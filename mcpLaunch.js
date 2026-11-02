"use strict";

/**
 * mcpLaunch.js — MCP stdio サーバーの「起動ルート」を決める（Lumen 実行コア）
 * ============================================================
 * 目的: Windows で `npx` 系（npx.cmd シム経由）や `uvx` の MCP サーバーが「接続中」のまま進まない／エージェントのツールに載らない問題への対処。
 *   原因候補はどれも「起動の仕方」と「プロトコル世代の選び方」にある。そこで起動方式を複数用意し、接続の再試行ごとに切り替える。
 *
 *   route A（直接起動）: npx / npm を cmd.exe・.cmd シムを介さず「node.exe + npx-cli.js」で直接起動する。
 *                        uvx / python / deno / bun なども PATH から絶対パスへ解決する。
 *                        filesystem（node を直接起動）が繋がるのと同じ経路なので、シム由来の問題を丸ごと避けられる。
 *                        npx-cli.js が見つからないとき・npx/npm 以外のシム（pnpm / yarn / corepack）は route B と同じ形になる。
 *   route B（従来）    : 元の command を SDK に渡す。ただし Windows の .cmd シム（npx / npm / pnpm / yarn / corepack）だけは、
 *                        SDK が shell:false 固定で spawn("npx") = ENOENT / spawn("npx.cmd") = EINVAL（CVE-2024-27980）になるため、
 *                        `cmd.exe /d /s /c "<コマンドライン>"` へ分解してから渡す（shell:true も生結合もしない）。
 *   どちらも、SDK 既定の最小環境では欠ける OS の必須環境変数（ComSpec / PATHEXT / ProgramData 等）を補い、
 *   PATH の先頭へ実行コア自身の node のあるフォルダ、末尾へ実在する既知の uv の場所を足す。
 *   実行コアの認証トークンなどアプリの秘密（LUMEN_TOKEN と、廃止した接頭辞の環境変数）は、ユーザー env に書いてあっても渡さない。
 *   route B が使えない引数（cmd.exe へ渡せない & | % など）のとき、その試行は route A（直接起動）で行う（fatal にして再試行ごと止めない）。
 *
 *   plan(cfg, attempt) -> { label, command, args, env, note, shell:false, diag }
 *       attempt 0,2,4… = route A / 1,3,5… = route B。attempt は「起動ルートの切替」専用。
 *       プロトコル世代の再試行は別のカウンタ（hub の protoStep）で持ち、ここへは混ぜない。
 *
 *   negotiationFor(cfg, protoStep) -> SDK の versionNegotiation（legacy / auto / pin）
 *       .mcp.json で protocol を省略したパッケージランナー（npx / uvx 等）の最初の接続は legacy。
 *       server/discover の兄弟プロセス・プローブは、ラッパー（npx / uvx）では内側が終わっても親がパイプを握り続けて時間切れになりやすく、
 *       2024-11-05 世代の initialize しか話さないサーバーも多いため。legacy が世代不一致で落ちたときだけ、次の 1 回を auto にする。
 *
 * 依存なし。単体でテストできるよう、環境・fs・platform は opts で差し替え可能。
 */

const fs = require("fs");
const nodePath = require("path");

const WIN_KEYS = ["APPDATA", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "PATH", "PATHEXT", "PROCESSOR_ARCHITECTURE", "SYSTEMDRIVE", "SYSTEMROOT",
  "TEMP", "TMP", "USERNAME", "USERPROFILE", "USERDOMAIN", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432", "PROGRAMDATA", "ALLUSERSPROFILE",
  "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)", "COMMONPROGRAMW6432", "COMSPEC", "WINDIR", "OS", "NUMBER_OF_PROCESSORS", "COMPUTERNAME",
  "PSMODULEPATH", "LANG", "LC_ALL"];
const POSIX_KEYS = ["HOME", "LOGNAME", "USER", "PATH", "SHELL", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
  "XDG_DATA_HOME", "XDG_RUNTIME_DIR", "NVM_DIR", "NVM_BIN", "VOLTA_HOME", "FNM_DIR", "FNM_MULTISHELL_PATH", "PNPM_HOME", "BUN_INSTALL", "DISPLAY", "WAYLAND_DISPLAY"];
/** プロキシ・社内CA・パッケージレジストリ関連。これが子に届かないと npx / uvx がパッケージを取得できず、接続中のまま進まない。 */
const NET_KEYS = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA", "NODE_TLS_REJECT_UNAUTHORIZED", "UV_NATIVE_TLS", "UV_SYSTEM_CERTS", "UV_CACHE_DIR", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "PIP_INDEX_URL", "PIP_CERT",
  "PYTHONUTF8", "PYTHONIOENCODING", "NPM_CONFIG_USERCONFIG", "NPM_CONFIG_CACHE", "NPM_CONFIG_REGISTRY", "NPM_CONFIG_CAFILE", "NPM_CONFIG_PREFIX", "NPM_CONFIG_GLOBALCONFIG"];
/** env を .mcp.json で明示したときでも、必ず子へ渡す最低限の環境変数（Windows の uv / pip / cmd.exe が、これらを欠くと起動に失敗する）。 */
const MIN_ENV_KEYS = ["PATH", "HOME", "USERPROFILE", "APPDATA", "TEMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "SystemRoot", "ComSpec", "PATHEXT"];
/** npx が対話待ちで止まらないように / 余計な通知で遅くならないようにする既定値（利用者の指定があればそちらを優先）。 */
const NPM_DEFAULTS = { npm_config_yes: "true", npm_config_update_notifier: "false", npm_config_fund: "false", npm_config_audit: "false" };
/** 直接起動（絶対パス解決）の対象。shell を要する .cmd シムではなく、実体を探す。 */
const RESOLVE_ABS = new Set(["uvx", "uv", "python", "python3", "py", "deno", "bun", "bunx", "node"]);

/** Windows で .cmd シムとして配布されるコマンド。Node の spawn は shell なしでは起動できない（mcpStdio.js もここを使う）。 */
const WIN_CMD_SHIMS = new Set(["npx", "npm", "pnpm", "yarn", "corepack"]);
/** パッケージランナー = 初回にパッケージを取得して起動するラッパー。上のシム + uvx。 */
const RUNNER_NAMES = new Set(["npx", "npm", "pnpm", "yarn", "corepack", "uvx"]);
/** cmd.exe に渡すコマンドラインへ入れてはいけない文字（改行・メタ文字・引用符・展開される % !）。 */
const UNSAFE_SHIM_CHARS = /[\r\n&|<>^%!"`]/;
/** 実行コアの認証トークンの環境変数名。子（MCP サーバー）へは決して渡さない。 */
const SECRET_ENV_KEYS = ["LUMEN_TOKEN"];
/** 廃止した旧接頭辞。この接頭辞の環境変数は使わない（旧トークンや旧設定が子へ漏れないよう、子には渡さず、起動時に警告する）。移行が済んだらこの安全弁ごと削除してよい。 */
const RETIRED_ENV_PREFIX = "NF_";
function retiredEnvKeys(env) { return Object.keys(env || {}).filter((k) => k.toUpperCase().indexOf(RETIRED_ENV_PREFIX) === 0); }
/** startupTimeoutMs を書いていないパッケージランナーの接続上限（初回ダウンロード + 世代の再試行が収まるように）。 */
const RUNNER_CONNECT_TIMEOUT_MS = 180000;

/** 起動引数が不正（400 相当）。ユーザーの引数を直せば解決するので、再試行しても無駄（fatal）。値は文言へ出さない。 */
class LaunchArgError extends Error {
  constructor(message) {
    super(message);
    this.name = "LaunchArgError";
    this.statusCode = 400;
    this.errorKind = "request";
    this.fatal = true;
  }
}

function ctx(opts) {
  opts = opts || {};
  const platform = opts.platform || process.platform;
  const win = platform === "win32";
  return {
    win,
    env: opts.env || process.env,
    P: win ? nodePath.win32 : nodePath.posix,
    exists: opts.exists || ((p) => { try { return fs.statSync(p).isFile(); } catch (_) { return false; } }),
    dirExists: opts.dirExists || ((p) => { try { return fs.statSync(p).isDirectory(); } catch (_) { return false; } }),
    realpath: opts.realpath || ((p) => { try { return fs.realpathSync(p); } catch (_) { return p; } }),
    execPath: opts.execPath || process.execPath,
  };
}

function envGet(env, name) {
  const k = Object.keys(env).find((x) => x.toUpperCase() === name.toUpperCase());
  return k === undefined ? undefined : env[k];
}

/** コマンド名の正規化（ディレクトリと .cmd/.bat/.exe/.com を落として小文字）。区切りは \ / どちらでも扱う。 */
function baseName(command) {
  return nodePath.win32.basename(String(command == null ? "" : command)).replace(/\.(cmd|bat|exe|com)$/i, "").toLowerCase();
}

/** cmd.exe の「/c を含む先頭のスイッチ列」の中で /c の位置。無ければ -1。（/d /s /c のように並んでいてもよい） */
function cSwitchIndex(args) {
  const a = Array.isArray(args) ? args : [];
  for (let i = 0; i < a.length; i++) {
    const t = String(a[i]);
    if (!/^\/[a-z]$/i.test(t)) return -1;
    if (/^\/c$/i.test(t)) return i;
  }
  return -1;
}

/** ユーザーが command: "cmd" / "cmd.exe" ＋ args が /c で始まる形で書いているか（二重に包まない）。 */
function isCmdCWrapped(command, args) {
  return baseName(command) === "cmd" && cSwitchIndex(args) >= 0;
}

/**
 * 起動コマンドがパッケージランナーなら、その名前（npx / npm / pnpm / yarn / corepack / uvx）。そうでなければ null。
 * 元のコマンド名で判定する。ユーザーが `cmd /c npx ...` と書いている場合は /c の後ろの先頭語で判定する。
 * （実行コアが cmd.exe へ分解したあとも、判定はこの関数に元の cfg を渡して行うので変わらない）
 */
function runnerName(command, args) {
  let name = baseName(command);
  if (name === "cmd") {
    const i = cSwitchIndex(args);
    if (i < 0) return null;
    const rest = (Array.isArray(args) ? args : []).slice(i + 1).map(String).join(" ").trim();
    const m = /^"([^"]*)"|^(\S+)/.exec(rest);
    name = m ? baseName(m[1] !== undefined ? m[1] : m[2]) : "";
  }
  return RUNNER_NAMES.has(name) ? name : null;
}
function isPackageRunner(command, args) { return runnerName(command, args) !== null; }

/** ComSpec が実在する絶対パスならそれ、なければ "cmd.exe"。 */
function comspecOf(c) {
  const v = envGet(c.env, "COMSPEC");
  if (typeof v === "string" && v && c.P.isAbsolute(v) && c.exists(v)) return v;
  return "cmd.exe";
}

/** 空・空白を含む引数は "..." で囲む。囲んだ中の末尾 \ は倍にする（mcpStdio.js 従来の規則）。 */
function quoteShimArg(a) {
  return a === "" || /\s/.test(a) ? '"' + a.replace(/\\+$/, (m) => m + m) + '"' : a;
}

/**
 * Windows の .cmd シム（npx / npm / pnpm / yarn / corepack）を cmd.exe へ分解する。該当しなければ null。
 *   - 非 Windows、node / uvx / python / deno / bun など他のコマンド、すでに `cmd /c ...` のものは null（改変しない）。
 *   - 引数に \r \n & | < > ^ % ! " ` が含まれていれば LaunchArgError（400 相当）。値は文言へ出さない。
 * 返す形:
 *   args         : ["/d","/s","/c","<1 本のコマンドライン>"]  … SDK の StdioClientTransport（shell:false 固定）へそのまま渡す。
 *                  Node がコマンドラインを自動で "..." に包む（/s が外側の "" を外す）。
 *   verbatimArgs : ["/d","/s","/c",'"<コマンドライン>"']      … Node の spawn を直接呼ぶ側（mcpStdio.js）が windowsVerbatimArguments:true と組み合わせて使う。
 *                  Node の shell:true が内部で作る形と同じ。
 */
function wrapWinShim(command, args, opts) {
  const c = ctx(opts);
  if (!c.win) return null;
  const shim = baseName(command);
  if (!WIN_CMD_SHIMS.has(shim)) return null;
  if (isCmdCWrapped(command, args)) return null;
  const list = (Array.isArray(args) ? args : []).map((a) => String(a));
  [String(command)].concat(list).forEach((a, i) => {
    if (UNSAFE_SHIM_CHARS.test(a)) {
      throw new LaunchArgError("Windows で " + shim + " に渡せない文字（& | < > ^ % ! \" ` と改行）が" + (i === 0 ? "コマンド" : "引数 " + i + " 番目") + "に含まれています。");
    }
  });
  const line = [String(command)].concat(list).map(quoteShimArg).join(" ");
  return { command: comspecOf(c), args: ["/d", "/s", "/c", line], verbatimArgs: ["/d", "/s", "/c", '"' + line + '"'], line, shim };
}

/* ------------------------------------------------------------
   環境変数
   ------------------------------------------------------------ */

/** OS が必須とする環境変数だけを、元の大文字小文字のまま取り出す（アプリの秘密は含めない）。 */
function systemEnv(opts) {
  const c = ctx(opts);
  const want = new Set((c.win ? WIN_KEYS : POSIX_KEYS).concat(NET_KEYS).map((k) => k.toUpperCase()));
  const out = {};
  Object.keys(c.env).forEach((k) => { if (want.has(k.toUpperCase()) && c.env[k] !== undefined && c.env[k] !== "") out[k] = c.env[k]; });
  // 実行コア自身を動かしている node のあるフォルダを PATH の先頭へ（子の `#!/usr/bin/env node` や npm の内部呼び出しが同じ node を見つけられるように）
  const pk = Object.keys(out).find((k) => k.toUpperCase() === "PATH") || "PATH";
  const dir = c.P.dirname(c.execPath);
  const cur = out[pk] || "";
  const sep = c.win ? ";" : ":";
  if (!cur.split(sep).some((d) => (c.win ? d.toLowerCase() === dir.toLowerCase() : d === dir))) out[pk] = dir + (cur ? sep + cur : "");
  return out;
}

/** base に over を重ねる。Windows は環境変数名の大文字小文字を区別しないので、同名の別綴りは消してから入れる。 */
function mergeEnv(base, over, c) {
  const out = Object.assign({}, base);
  Object.keys(over || {}).forEach((k) => {
    if (c.win) Object.keys(out).forEach((x) => { if (x !== k && x.toUpperCase() === k.toUpperCase()) delete out[x]; });
    out[k] = over[k];
  });
  return out;
}

function dropKey(env, name, c) {
  Object.keys(env).forEach((k) => { if (c.win ? k.toUpperCase() === name.toUpperCase() : k === name) delete env[k]; });
}

function normDir(c, d) {
  const s = String(d).trim().replace(/^"|"$/g, "").replace(/[\\/]+$/, "");
  return c.win ? s.toLowerCase() : s;
}

/** uv の実体がある既知のディレクトリ候補（存在確認は呼び出し側）。中身は起動しない。 */
function toolDirs(env, c) {
  const home = envGet(env, c.win ? "USERPROFILE" : "HOME");
  if (!home) return [];
  if (!c.win) return [c.P.join(home, ".local", "bin")];
  const local = envGet(env, "LOCALAPPDATA");
  return [
    c.P.join(home, ".local", "bin"),                                                                              // uv 公式インストーラ
    local ? c.P.join(local, "Microsoft", "WinGet", "Links") : c.P.join(home, "AppData", "Local", "Microsoft", "WinGet", "Links"), // winget
    c.P.join(home, ".cargo", "bin"),                                                                              // cargo install / 旧インストーラ
  ];
}

/** PATH の先頭へ実行コアの node のフォルダ、末尾へ実在する既知の uv の場所を足す。すでにあるものは重複させない。 */
function ensurePath(env, c) {
  const key = Object.keys(env).find((k) => k.toUpperCase() === "PATH") || "PATH";
  const sep = c.win ? ";" : ":";
  const parts = String(env[key] || "").split(sep).filter(Boolean);
  const have = new Set(parts.map((d) => normDir(c, d)));
  const front = [];
  const back = [];
  const nodeDir = c.P.dirname(c.execPath);
  if (!have.has(normDir(c, nodeDir))) { front.push(nodeDir); have.add(normDir(c, nodeDir)); }
  toolDirs(env, c).forEach((d) => {
    const n = normDir(c, d);
    if (!have.has(n) && c.dirExists(d)) { back.push(d); have.add(n); }
  });
  env[key] = front.concat(parts, back).join(sep);
}

/** c.env から MIN_ENV_KEYS だけを、元の大文字小文字のまま取り出す（Windows は名前の大文字小文字を区別しない）。 */
function minEnv(c) {
  const out = {};
  const keys = Object.keys(c.env);
  MIN_ENV_KEYS.forEach((want) => {
    const k = keys.find((x) => (c.win ? x.toUpperCase() === want.toUpperCase() : x === want));
    if (k !== undefined && typeof c.env[k] === "string" && c.env[k] !== "") out[k] = c.env[k];
  });
  return out;
}

function hasKey(env, name, c) {
  return Object.keys(env).some((k) => (c.win ? k.toUpperCase() === name.toUpperCase() : k === name));
}

/**
 * 子へ渡す env。
 *   cfg.env が未指定（undefined / null）: 実行コア自身の環境（process.env）をそのまま引き継ぐ。
 *     ※ SDK の StdioClientTransport は env を渡さないと PATH / HOME など一部の変数しか子へ渡さない（LANG・プロキシ・uv/pip の設定が届かない）。
 *       「SDK 既定 = process.env 相当」にはならないので、ここで明示的に process.env を渡す。
 *   cfg.env が指定されている: OS 必須 + ネットワーク系（systemEnv）+ MIN_ENV_KEYS の上に利用者の値を重ねる（利用者の env は最優先）。
 * どちらでも LUMEN_TOKEN（実行コアの認証トークン）と廃止した接頭辞の変数は必ず消す。npm 既定値は、すでに値があるものを上書きしない。
 */
function buildEnv(cfg, c, opts) {
  const user = cfg.env;
  let base;
  if (user === undefined || user === null) {
    base = {};
    Object.keys(c.env).forEach((k) => { if (typeof c.env[k] === "string" && c.env[k] !== "") base[k] = c.env[k]; });
  } else {
    base = Object.assign({}, systemEnv(opts), minEnv(c));
  }
  Object.keys(NPM_DEFAULTS).forEach((k) => { if (!hasKey(base, k, c)) base[k] = NPM_DEFAULTS[k]; });
  // 起動の高速化: キャッシュ済みのパッケージは、npx が毎回レジストリへ確認しに行かずそのまま使う（@latest も最後に取得した版で起動する）。
  // 常に最新版を取りたいときは LUMEN_NPM_FRESH=1 で起動する。利用者が .mcp.json の env で書いた値が優先される。
  if (!/^(1|true|on|yes)$/i.test(String(envGet(c.env, "LUMEN_NPM_FRESH") || "")) && !hasKey(base, "npm_config_prefer_offline", c)) base.npm_config_prefer_offline = "true";
  const env = mergeEnv(base, user || {}, c);
  SECRET_ENV_KEYS.forEach((k) => dropKey(env, k, c));   // 実行コアの認証トークンを子へ渡さない（値はログにもエラー文にも出さない）。
  retiredEnvKeys(env).forEach((k) => dropKey(env, k, c));
  ensurePath(env, c);
  return env;
}

/** プロセスの木ごと確実に落とす（npx / cmd.exe 経由だと子の子が残るため）。pid が無い・既に終了していれば何もしない。 */
function killTree(pid, opts) {
  const n = Number(pid);
  if (!Number.isInteger(n) || n <= 0) return;
  const cp = require("child_process");
  const win = (opts && opts.platform ? opts.platform : process.platform) === "win32";
  try {
    if (win) {
      const k = cp.spawn("taskkill", ["/pid", String(n), "/T", "/F"], { stdio: "ignore", windowsHide: true });
      k.on("error", () => { try { process.kill(n, "SIGKILL"); } catch (_) { /* 終了済み */ } });
    } else {
      try { process.kill(-n, "SIGKILL"); }   // detached で起動したときはプロセスグループごと
      catch (_) { process.kill(n, "SIGKILL"); }
    }
  } catch (_) { /* 既に終了している */ }
}

/* ------------------------------------------------------------
   実体の探索
   ------------------------------------------------------------ */

/** PATH（と Windows では PATHEXT）から command の実体ファイルを探す。見つからなければ null。 */
function findOnPath(command, opts) {
  const c = ctx(opts);
  if (!command || /[\\/]/.test(command)) return command && c.exists(command) ? command : null;
  const pathVar = envGet(c.env, "PATH") || "";
  const dirs = pathVar.split(c.win ? ";" : ":").filter(Boolean);
  const exts = c.win ? (envGet(c.env, "PATHEXT") || ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean) : [""];
  const hasExt = c.win && /\.[A-Za-z0-9]+$/.test(command);
  for (const d of [c.P.dirname(c.execPath)].concat(dirs)) {
    for (const e of hasExt ? [""] : exts) {
      const f = c.P.join(d, command + e);
      if (c.exists(f)) return f;
    }
  }
  return null;
}

/** npx / npm の JS 本体（npx-cli.js / npm-cli.js）を探す。見つかれば node で直接起動できる。 */
function findNpmCli(which, opts) {
  const c = ctx(opts);
  const file = which === "npm" ? "npm-cli.js" : "npx-cli.js";
  const cands = [];
  const nodeDir = c.P.dirname(c.execPath);
  cands.push(c.P.join(nodeDir, "node_modules", "npm", "bin", file));                    // Windows 標準 / nvm-windows
  cands.push(c.P.join(c.P.dirname(nodeDir), "lib", "node_modules", "npm", "bin", file)); // POSIX 標準（/usr/local/bin → /usr/local/lib/...）
  const shim = findOnPath(which, opts);
  if (shim) {
    const real = c.realpath(shim);
    if (/\.js$/i.test(real)) cands.push(real);
    const d = c.P.dirname(real);
    cands.push(c.P.join(d, "node_modules", "npm", "bin", file));
    cands.push(c.P.join(c.P.dirname(d), "lib", "node_modules", "npm", "bin", file));
  }
  return cands.find((f) => c.exists(f)) || null;
}

/* ------------------------------------------------------------
   起動ルート
   ------------------------------------------------------------ */

/**
 * cfg: { command, args, env, cwd }（hub の _cfg）。attempt: 接続の試行番号（起動ルートの切替だけに使う）。
 * 返す env は cfg.env を最優先（利用者が .mcp.json に書いた値は上書きされない。ただし LUMEN_TOKEN は除く）。
 * diag は失敗時のエラー文言用（どのランナーを、どこで探したか）。秘密は含めない。
 */
function plan(cfg, attempt, opts) {
  const c = ctx(opts);
  const env = buildEnv(cfg, c, opts);
  const ropts = Object.assign({}, opts, { env });   // 実体の探索は「子が実際に見る PATH」で行う
  const args = cfg.args || [];
  const runner = runnerName(cfg.command, args);
  const diag = { runner, nodeDir: c.P.dirname(c.execPath), viaCmd: false, direct: false, runnerFound: null, win: c.win, envMode: cfg.env === undefined || cfg.env === null ? "inherit" : "explicit" };
  if (runner && baseName(cfg.command) === runner) diag.runnerFound = !!findOnPath(String(cfg.command), ropts);
  const result = (label, command, a, note, extra) => Object.assign({ label, command, args: a, env, note: note || "", shell: false, diag }, extra || {});

  /** route B。Windows の .cmd シムだけ cmd.exe へ分解する（LaunchArgError は呼び出し側＝hub の接続失敗として扱われる）。 */
  const original = (label) => {
    const w = wrapWinShim(cfg.command, args, ropts);
    if (w) {
      diag.viaCmd = true;
      return result((label || "従来") + "(cmd /c " + w.shim + ")", w.command, w.args, "cmd.exe /d /s /c " + w.shim, { verbatimArgs: w.verbatimArgs });
    }
    return result(label || "従来", cfg.command, args, "");
  };

  /** route A。使えなければ null（route B へ回す）。 */
  const direct = () => {
    const name = baseName(cfg.command);
    if (name === "npx" || name === "npm") {
      const cli = findNpmCli(name, ropts);
      if (cli) { diag.direct = true; diag.runnerFound = true; return result("直接起動(node+" + c.P.basename(cli) + ")", c.execPath, [cli].concat(args), cli); }
      return null;
    }
    if (RESOLVE_ABS.has(name)) {
      const abs = name === "node" ? c.execPath : findOnPath(name, ropts);
      if (abs) { diag.direct = true; if (diag.runner) diag.runnerFound = true; return result("直接起動(" + name + ")", abs, args, abs); }
    }
    return null;
  };

  const useDirect = (Number(attempt) || 0) % 2 === 0;
  if (useDirect) {
    const d = direct();
    if (d) return d;
    const n = baseName(cfg.command);
    return original(n === "npx" || n === "npm" ? "従来(npm-cli未検出)" : "従来");
  }
  try {
    return original("従来");
  } catch (e) {
    // route B（cmd.exe 経由）は & | < > ^ % ! " ` と改行を含む引数を渡せない。以前はここで fatal になり、
    // 一時的な失敗（初回の npx ダウンロードの時間切れなど）の再試行ごと止まっていた。route A は cmd.exe を通らないので、その試行は A で行う。
    if (!(e instanceof LaunchArgError)) throw e;
    const d = direct();
    if (!d) throw e;
    diag.fellBackToDirect = true;
    d.note = "引数に cmd.exe へ渡せない文字があるため、この試行も直接起動で行います。";
    return d;
  }
}

/* ------------------------------------------------------------
   プロトコル世代の選択（hub が versionNegotiation に渡す）
   ------------------------------------------------------------ */

/**
 * cfg: { proto, protoImplicit, runner, type }（hub の compileSpec が作る）。protoStep: 0 = 最初の接続 / 1 = legacy が世代不一致で落ちた後の 1 回。
 *   - protocol をユーザーが書いた場合はその値だけ（"auto" 明示は auto、"legacy" と日付ピンも今どおり）。旧 HTTP+SSE の auto は従来どおり legacy。
 *   - 省略 + stdio + パッケージランナー（npx / uvx 等）: 最初は legacy（server/discover を打たない）。protoStep=1 のときだけ auto。
 *   - 省略 + node 直接起動 / HTTP など: 今までどおり auto。
 */
function negotiationFor(cfg, protoStep) {
  const proto = cfg.proto || "auto";
  if (proto === "legacy") return { mode: "legacy" };
  if (proto !== "auto") return { mode: { pin: proto } };
  if (cfg.type === "sse") return { mode: "legacy" };
  if (usesLegacyFirst(cfg) && !(Number(protoStep) >= 1)) return { mode: "legacy" };
  return { mode: "auto" };
}

/** protocol 省略のパッケージランナー（stdio）か。= 最初の接続を legacy にし、世代不一致なら auto へ 1 回だけ戻す対象。 */
function usesLegacyFirst(cfg) {
  return !!(cfg && cfg.type === "stdio" && cfg.protoImplicit === true && cfg.runner);
}

/**
 * 接続失敗が「プロトコル世代の不一致」か。ENOENT・引数不正・タイムアウト・認証失敗は false（auto へ切り替えない）。
 * SDK の細かいエラー型には依存せず、コード・名前・文面で判定する。
 */
function isProtocolMismatch(e) {
  if (!e) return false;
  if (e instanceof LaunchArgError) return false;
  const code = e.code == null ? "" : String(e.code);
  const name = String(e.name || "");
  const msg = String(e.message || "");
  if (/^(ENOENT|EINVAL|EACCES|EPERM|EPIPE|ECONN\w*)$/i.test(code)) return false;
  if (/timeout|timed.?out|abort|unauthorized|authentication/i.test(code + " " + name)) return false;
  if (/timed out|timeout|ENOENT|EINVAL|unauthorized|\b401\b/i.test(msg)) return false;
  return /unsupported protocol version|protocol version[^\n.]{0,80}(not supported|unsupported|mismatch|incompatible)|PROTOCOL_VERSION|VERSION_MISMATCH|UNSUPPORTED_PROTOCOL/i.test(code + " " + msg);
}

module.exports = {
  plan, systemEnv, findOnPath, findNpmCli, MIN_ENV_KEYS, killTree,
  wrapWinShim, runnerName, isPackageRunner, WIN_CMD_SHIMS, SECRET_ENV_KEYS, RETIRED_ENV_PREFIX, retiredEnvKeys, LaunchArgError,
  negotiationFor, usesLegacyFirst, isProtocolMismatch, RUNNER_CONNECT_TIMEOUT_MS,
};
