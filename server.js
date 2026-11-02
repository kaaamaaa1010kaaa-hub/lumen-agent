"use strict";

/**
 * server.js — Lumen 実行コア（Lumen Core）
 * ============================================================
 * ブラウザ（lumen.html）と MCP サーバー群のあいだの薄い中継。MCP の話は mcpHub.js（公式 SDK）が全部やる。
 * ここは「ローカルだけで安全に待ち受ける」「トークンで守る」「ツール一覧と呼び出し結果をそのまま渡す」だけ。
 *
 *   GET  /  および  GET /lumen.html   lumen.html を配信
 *   GET  /health              { ok, service, version, authRequired }（認証不要・秘密を含まない）
 *   GET  /api/state           サーバー接続状態（世代・プロトコル版・ツール数・エラー）
 *   GET  /api/tools           接続済みサーバーの tools/list 取得結果（名称は mcp__<server>__<tool>）。名前順・合成スキーマを平坦化済み。
 *                             ETag / If-None-Match 対応（変わっていなければ 304）。catalog に除外・警告の一覧
 *   GET  /api/commands        プロジェクトのコマンド（.lumen/commands と .claude/commands の *.md。Claude Code 互換。本文は展開するだけで、!コマンド や @ファイルは実行・展開しない）
 *   GET  /api/snapshot?toolsEtag=  状態 + ツール一覧を 1 回で返す（ツールが同じなら tools は null・toolsUnchanged:true）
 *   POST /api/tools/call      { name, arguments } → { result: CallToolResult, durationMs }（切断で上流の呼び出しも中断。
 *                             接続中・再接続待ち・error のサーバーのツールは、最大 LUMEN_CALL_WAIT_MS（既定 30 秒）だけ接続を待ってから呼ぶ。
 *                             error で再試行の予約待ちのサーバーは、予約を待たずその場で hub.reconnect(名前) をかける。
 *                             「サーバーへ送る前に断った」NOT_CONNECTED（セッション切れを含む）は、繋ぎ直しを待って 1 回だけやり直す。
 *                             通信の途中で切れた呼び出しは、副作用が起きたか分からないので自動では再送しない。
 *                             LUMEN_CALL_KEEPALIVE_MS（既定 20 秒）を超える呼び出しは、200 を先に返して空白を流し続ける（無音の長い接続を
 *                             ブラウザ・プロキシ・セキュリティソフトに切られないため）。その場合の失敗は 200 の本文 { error: { code, message, status } } で返る）
 *   POST /api/tools/discover  { query, maxServers? } → 能力マニフェストで候補化した lazy サーバーを接続し、サーバー状態だけ返す（schema本体は返さない）
 *   POST /api/reconnect       { server? , all? } 再接続。server 指定: そのサーバーだけ強制。指定なし: 接続できていないサーバーだけ（既定）。
 *                             all:true は全サーバーを強制で繋ぎ直す（hub.reconnect()。呼び出し中の workspace などの通信も切れるので、通常は使わない）
 *   GET  /api/config          .mcp.json の本文 / PUT /api/config { text } 検証して保存（JSON 全体の編集用）
 *   ── 複数の MCP サーバーを 1 件ずつ管理する（.mcp.json を原子的に書き換える。etag が違えば 409）──
 *   GET    /api/servers                        設定上の全サーバーと接続状態（秘密は伏字）+ etag
 *   POST   /api/servers/import/preview { text }   貼り付け（JSON / TOML / claude mcp add など）の解釈結果。何も書かない
 *   POST   /api/servers/import { text, choices?, etag? }   貼り付けを適用 → { results[] }
 *   PUT    /api/servers/:name { spec, mode?, etag? }       1 件の追加・更新（mode: "create" | "update"）
 *   DELETE /api/servers/:name                              1 件の削除
 *   POST   /api/servers/:name/enabled { enabled }          有効 / 無効の切り替え
 *   GET  /api/changes?since=N ロングポーリング（ツール・状態が変わったら revision を返す）
 *
 * 環境変数: LUMEN_PORT(3777) / LUMEN_WORKSPACE / LUMEN_TOKEN / LUMEN_AUTH=off / LUMEN_ALLOWED_ORIGINS=a,b
 *           LUMEN_CALL_WAIT_MS(30000, 0 で待たない) / LUMEN_CALL_KEEPALIVE_MS(20000, 0 で無効) / LUMEN_RECONNECT_COOLDOWN_MS(3000)
 *           LUMEN_CALL_IDLE_MS / LUMEN_RETRY_NETWORK_MAX / LUMEN_HTTP_LONG_FETCH=off / LUMEN_HTTP_HEADERS_TIMEOUT_MS / LUMEN_HTTP_BODY_TIMEOUT_MS（mcpPolicy.js / mcpHttp.js の項を参照）
 *           LUMEN_TOOL_DESC_MAX(4096) / LUMEN_TOOL_STRICT_PROPS=1（引数名が厳格な API の許容外のツールを外す）
 *           旧名 NF_PORT 等（NF_ + 同じ名前）も、LUMEN_ 側が未設定のときだけ読む（互換。非推奨）。
 */

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const hub = require("./mcpHub");
const catalogLib = require("./mcpCatalog");
const policy = require("./mcpPolicy");

const VERSION = require("./package.json").version;
const MAX_BODY = 8 * 1024 * 1024;
const APP_ROOT = __dirname;
const LUMEN_FILE = path.join(APP_ROOT, "lumen.html");

function log(msg) { console.log("[Lumen] " + msg); }

/** 環境変数 LUMEN_<name> を読む。未設定のときだけ旧名 NF_<name> を読む（旧名は互換のためで非推奨）。 */
function envOf(env, name) {
  const v = env["LUMEN_" + name];
  if (v !== undefined && String(v).trim() !== "") return v;
  return env["NF_" + name];
}

function loadToken(env) {
  if (String(envOf(env, "AUTH") || "").toLowerCase() === "off") return { required: false, token: "", file: null };
  const envToken = envOf(env, "TOKEN");
  if (envToken && String(envToken).trim()) return { required: true, token: String(envToken).trim(), file: null };
  const file = path.join(APP_ROOT, ".lumen-token");
  try {
    const t = fs.readFileSync(file, "utf8").trim();
    if (t.length >= 24) return { required: true, token: t, file };
  } catch (_) { /* 未作成 */ }
  // 旧名のトークンファイル（.nf-token）があれば同じトークンを引き継ぐ（画面に入力済みのトークンを変えない）。旧ファイルは消さない。
  let token = "";
  try {
    const t = fs.readFileSync(path.join(APP_ROOT, ".nf-token"), "utf8").trim();
    if (t.length >= 24) token = t;
  } catch (_) { /* 旧ファイルなし */ }
  if (!token) token = crypto.randomBytes(24).toString("hex");
  fs.writeFileSync(file, token + "\n", { mode: 0o600 });
  return { required: true, token, file };
}

/**
 * 実行コアが読み込む MCP SDK（@modelcontextprotocol/sdk）が「本物」かを調べる。
 * テスト用の偽 SDK（"fake SDK: HTTP transport only" を投げるもの）が残ったままだと、stdio のサーバーが全部
 * 「プロセス終了」に見えてしまう（コマンド自体は単体起動できるのに、接続だけが失敗する）。
 * 起動時に 1 回だけ、node_modules を探して package.json と一部のファイルを読む（秘密・パスは画面に出さない）。
 */
function inspectSdk(appRoot) {
  const info = { installed: false, ok: true, fake: false, version: "", problem: "", evidence: "", packages: [] };
  const PKGS = ["client", "sdk"];   // client = v2 系（実行コアが使う）/ sdk = v1 系（旧）。どちらに偽物が混ざっても気づけるよう両方見る
  const dirs = [];
  for (let d = appRoot; ; d = path.dirname(d)) { dirs.push(path.join(d, "node_modules")); if (path.dirname(d) === d) break; }
  // package.json の依存が file: / link: になっていれば、本物ではないパッケージを指している可能性が高い
  let deps = {};
  try { deps = JSON.parse(fs.readFileSync(path.join(appRoot, "package.json"), "utf8")).dependencies || {}; } catch (_) { /* 無い */ }
  for (const n of PKGS) {
    const spec = String(deps["@modelcontextprotocol/" + n] || "");
    if (/^(file|link|portal):/i.test(spec)) { info.fake = true; info.evidence = info.evidence || "package.json の @modelcontextprotocol/" + n + " が " + spec.slice(0, 60) + " になっています"; }
  }
  for (const n of PKGS) {
    let root = "";
    for (const nm of dirs) { const dir = path.join(nm, "@modelcontextprotocol", n); if (fs.existsSync(path.join(dir, "package.json"))) { root = dir; break; } }
    if (!root) continue;
    info.installed = true;
    let ver = "";
    try {
      const pj = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
      ver = String(pj.version || "").slice(0, 40);
      if (!info.version || n === "client") info.version = ver;
      if (/fake|stub|mock/i.test([pj.name, pj.description, (pj.keywords || []).join(" ")].join(" "))) { info.fake = true; info.evidence = info.evidence || "@modelcontextprotocol/" + n + " の package.json に fake / stub / mock と書かれています"; }
      if (ver === "0.0.0") { info.fake = true; info.evidence = info.evidence || "@modelcontextprotocol/" + n + " のバージョンが 0.0.0 です"; }
    } catch (_) { /* 読めなければ次の走査へ */ }
    info.packages.push({ name: "@modelcontextprotocol/" + n, version: ver });
    // ファイルの中身: 偽物が自分で名乗る文字列（件数・容量に上限をつけて走査）
    let files = 0, bytes = 0, hit = "";
    const walk = (dir, depth) => {
      if (hit || depth > 6 || files > 400 || bytes > 6e6) return;
      let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
      for (const e of ents) {
        if (hit || files > 400 || bytes > 6e6) return;
        const f = path.join(dir, e.name);
        if (e.isDirectory()) { if (e.name !== "node_modules") walk(f, depth + 1); continue; }
        if (!/\.(c?js|mjs)$/.test(e.name)) continue;
        let st; try { st = fs.statSync(f); } catch (_) { continue; }
        if (st.size > 262144) continue;
        files++; bytes += st.size;
        let t; try { t = fs.readFileSync(f, "utf8"); } catch (_) { continue; }
        if (/fake SDK/i.test(t)) { hit = path.relative(root, f).split(path.sep).slice(-3).join("/"); return; }
      }
    };
    walk(root, 0);
    if (hit) { info.fake = true; info.evidence = "@modelcontextprotocol/" + n + " の中に「fake SDK」と名乗るコードがあります（" + hit + "）"; }
  }
  if (info.fake) {
    info.ok = false;
    info.problem = "実行コアが読んでいる MCP SDK は、テスト用の偽物（HTTP だけ対応）です。stdio（npx / node で起動するサーバー）は、本物の SDK を入れるまで接続できません。";
  }
  return info;
}

const SDK_FIX_STEPS = [
  "実行コア（start.bat のウィンドウ）を閉じて止める",
  "server.js のあるフォルダで diag-sdk.bat を実行し、できた diag-sdk.txt の内容で原因（どの SDK を何版入れるべきか）を確認する",
  "start.bat で実行コアを起動し直す（SDK は起動時に 1 回だけ読み込まれるので、再起動が必要です）",
  "画面の MCP 設定で「すべて再接続」を押す",
];

/** プロジェクトのコマンド（Claude Code 互換）: <workspace>/.lumen/commands と <workspace>/.claude/commands の *.md を読み、
 *  名前（ファイル名）・説明・引数ヒント・本文を返す。実行はブラウザ側で「/名前 引数」を本文へ展開して送るだけで、
 *  本文中の !コマンド や @ファイル は実行・展開しない。読むのは通常のファイルだけ（シンボリックリンクと、ワークスペース外へ解決されるものは除外）。
 *  上限: 100 件・1 件 64KB・深さ 3。同名は .lumen/commands が優先。 */
function listProjectCommands(workspaceRoot) {
  const LIM = { files: 100, bytes: 64 * 1024, depth: 3 };
  const commands = [], warnings = [], seen = new Set();
  let rootReal;
  try { rootReal = fs.realpathSync(workspaceRoot); } catch (_) { return { commands, warnings }; }
  const norm = (n) => String(n || "").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
  const parse = (text) => {
    const t = String(text || "").replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n");
    const meta = {};
    let body = t;
    const m = /^---[ \t]*\n([\s\S]*?)\n---[ \t]*(?:\n|$)/.exec(t);
    if (m) {
      body = t.slice(m[0].length);
      const ls = m[1].split("\n");
      for (let i = 0; i < ls.length; i++) {
        const km = /^([A-Za-z][\w-]*):[ \t]*(.*)$/.exec(ls[i]);
        if (!km) continue;
        let v = km[2].trim();
        if (v === ">" || v === "|" || v === ">-" || v === "|-") {
          const acc = [];
          while (i + 1 < ls.length && (/^[ \t]+/.test(ls[i + 1]) || ls[i + 1] === "")) { acc.push(ls[++i].trim()); }
          v = acc.join(" ").trim();
        }
        meta[km[1].toLowerCase()] = v.replace(/^(["'])(.*)\1$/, "$2");
      }
    }
    return { description: meta.description || "", hint: meta["argument-hint"] || meta.argument_hint || "", body: body.trim() };
  };
  const clip = (x, n) => { x = String(x || "").replace(/\s+/g, " ").trim(); return x.length > n ? x.slice(0, n - 1) + "…" : x; };
  let truncated = false;
  const walk = (dir, rel, depth, source) => {
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
    ents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of ents) {
      if (commands.length >= LIM.files) { truncated = true; return; }
      if (e.isSymbolicLink()) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (depth < LIM.depth) walk(full, rel.concat(e.name), depth + 1, source); continue; }
      if (!e.isFile() || !/\.md$/i.test(e.name)) continue;
      let st, real;
      try { st = fs.statSync(full); real = fs.realpathSync(full); } catch (_) { continue; }
      if (real !== rootReal && !real.startsWith(rootReal + path.sep)) continue;
      if (st.size > LIM.bytes) { warnings.push(source + "/" + rel.concat(e.name).join("/") + " は 64KB を超えるため読み込みませんでした。"); continue; }
      const name = norm(e.name.replace(/\.md$/i, ""));
      if (!name) continue;
      if (seen.has(name)) { warnings.push("コマンド名「" + name + "」が重複しているため、" + source + "/" + rel.concat(e.name).join("/") + " は使いません。"); continue; }
      let text;
      try { text = fs.readFileSync(full, "utf8"); } catch (_) { continue; }
      const p = parse(text);
      if (!p.body) continue;
      seen.add(name);
      const firstLine = (p.body.split("\n").find((l) => l.trim()) || name);
      commands.push({ name, description: clip(p.description || firstLine, 200), hint: clip(p.hint, 60), body: p.body, source, path: source + "/" + rel.concat(e.name).join("/") });
    }
  };
  [[".lumen", "commands"], [".claude", "commands"]].forEach(([a, b]) => walk(path.join(workspaceRoot, a, b), [], 1, a + "/" + b));
  if (truncated) warnings.push("コマンドが " + LIM.files + " 件を超えたため、先頭の " + LIM.files + " 件だけ読み込みました。");
  return { commands, warnings: warnings.slice(0, 20) };
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/**
 * skills/<名前>/SKILL.md（Agent Skills 形式）を、ワークスペースの .lumen/skills/ へ置く。内容が違うものだけ書く。
 * lumen.html の常駐プロンプトは、これらを公式 filesystem MCP の読み取りツールで読むよう案内する（専用の取得ツールは無い）。
 * 名前は英小文字・数字・ハイフンだけを受け付ける（パスの組み立てに使うため）。置けなかったときは、ログに出して起動は続ける。
 */
function deploySkills(appRoot, workspaceRoot) {
  const srcRoot = path.join(appRoot, "skills");
  let names;
  try { names = fs.readdirSync(srcRoot, { withFileTypes: true }).filter((d) => d.isDirectory() && /^[a-z0-9][a-z0-9-]*$/.test(d.name)).map((d) => d.name); }
  catch (_) { return { copied: 0, total: 0 }; }   // skills/ が無い配置: スキルなしで動く
  const dstRoot = path.join(workspaceRoot, ".lumen", "skills");
  let copied = 0;
  for (const n of names) {
    let body; try { body = fs.readFileSync(path.join(srcRoot, n, "SKILL.md")); } catch (_) { continue; }
    const dst = path.join(dstRoot, n, "SKILL.md");
    let cur = null; try { cur = fs.readFileSync(dst); } catch (_) { /* 未配置 */ }
    if (cur && cur.equals(body)) continue;
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.writeFileSync(dst, body);
    copied++;
  }
  return { copied, total: names.length };
}

function start(options) {
  options = options || {};
  const env = options.env || process.env;
  const port = options.port !== undefined ? Number(options.port) : (Number(envOf(env, "PORT")) || 3777);   // 0 = OS 任せ（テスト用）
  const workspaceRoot = path.resolve(options.workspaceRoot || envOf(env, "WORKSPACE") || path.join(APP_ROOT, "workspace"));
  fs.mkdirSync(workspaceRoot, { recursive: true });
  try { const sk = deploySkills(APP_ROOT, workspaceRoot); if (sk.copied) log("スキル " + sk.copied + "/" + sk.total + " 件を " + path.join(workspaceRoot, ".lumen", "skills") + " へ配置しました。"); }
  catch (e) { log("スキルを配置できませんでした: " + String((e && e.message) || e).slice(0, 160)); }
  const auth = options.auth || loadToken(env);
  const extraOrigins = String(envOf(env, "ALLOWED_ORIGINS") || "").split(",").map((s) => s.trim()).filter(Boolean);
  const callWaitRaw = envOf(env, "CALL_WAIT_MS");
  const msOf = (name, dflt) => { const v = envOf(env, name); return v !== undefined && String(v).trim() !== "" ? Math.max(0, Number(v) || 0) : dflt; };
  const callWaitMs = callWaitRaw !== undefined && String(callWaitRaw).trim() !== "" ? Math.max(0, Number(callWaitRaw) || 0) : 30000;
  const keepAliveMs = msOf("CALL_KEEPALIVE_MS", 20000);
  const reconnectCooldownMs = msOf("RECONNECT_COOLDOWN_MS", 3000);
  const catalogOpts = { descMaxChars: Number(envOf(env, "TOOL_DESC_MAX")) || undefined, strictProps: String(envOf(env, "TOOL_STRICT_PROPS") || "") === "1" };

  /** 起動時に 1 回だけ SDK を調べる（読み込み済みのモジュールは入れ替えても変わらないので、結果は再起動まで同じ）。 */
  const sdkBase = (options.sdkInfo) || inspectSdk(APP_ROOT);
  /** 画面へ返す SDK の状態。静的な検査で見つからなくても、サーバーのエラー文に「fake SDK」があれば偽物と判断する（別の経路で差し込まれた場合）。 */
  const sdkNow = () => {
    const out = Object.assign({}, sdkBase, { fix: SDK_FIX_STEPS.slice() });
    if (!out.fake) {
      let hit = "";
      try { for (const x of (hub.getState().servers || [])) { const m = /fake SDK[^\n]*/i.exec(String((x && x.error) || "")); if (m) { hit = m[0].slice(0, 120); break; } } } catch (_) { /* 状態なし */ }
      if (hit) { out.fake = true; out.ok = false; out.evidence = "サーバーのエラーに「" + hit + "」が出ています"; out.problem = "実行コアが読んでいる MCP SDK は、テスト用の偽物（HTTP だけ対応）です。stdio（npx / node で起動するサーバー）は、本物の SDK を入れるまで接続できません。"; }
    }
    return out;
  };
  /** hub の状態に SDK の状態を足して返す（状態を使う API はすべてここを通す）。 */
  const stateOut = () => Object.assign({}, hub.getState(), { sdk: sdkNow() });
  if (sdkBase.fake) {
    log("警告: " + sdkBase.problem);
    log("  根拠: " + sdkBase.evidence);
    log("  直し方: " + SDK_FIX_STEPS.map((x, i) => (i + 1) + ") " + x).join(" / "));
  }

  /** ブラウザへ返すツール一覧（名前順・平坦化済み）。状態と同じ瞬間の値にそろえるため、同期で続けて取る。 */
  const buildCatalog = () => catalogLib.prepare(hub.getTools(), catalogOpts);
  const catalogReport = (cat) => ({ count: cat.summary.count, estTokens: cat.summary.estTokens, chars: cat.summary.chars, excluded: cat.excluded.slice(0, 50), warnings: cat.warnings.slice(0, 50) });

  /** ログ・エラー文に出す前に、アクセストークンと Bearer 値を伏せる。 */
  const scrub = (text) => {
    let t = String(text == null ? "" : text).replace(/(Bearer\s+)[A-Za-z0-9._~+\/=-]{8,}/gi, "$1***");
    if (auth.token && auth.token.length >= 8) t = t.split(auth.token).join("***");
    return t;
  };
  const slog = (msg) => log(scrub(msg));

  const SERVER_RE = /^mcp__([^_](?:[^_]|_(?!_))*)__/;
  const serverNameOf = (toolName) => { const m = SERVER_RE.exec(String(toolName || "")); return m ? m[1] : ""; };
  const serverEntry = (name) => (hub.getState().servers || []).find((x) => x && x.name === name);

  /* ------------------------------------------------------------
     サーバー 1 件の再接続（呼び出し時・手動のどちらもここを通る）
     ------------------------------------------------------------
     サーバー単位で 1 本にまとめ（並列の呼び出しが同じサーバーを何度も繋ぎ直さない）、直前の再接続から cooldown の間は重ねない。
     必ず「サーバー名つき」で hub.reconnect を呼ぶ。名前なしは全サーバーの強制再接続で、正常なサーバー（workspace など）の呼び出し中の通信まで切れる。 */
  const reconnecting = new Map();   // name -> Promise<boolean>
  const lastReconnect = new Map();  // name -> ms
  function reconnectServer(name, why, o) {
    o = o || {};
    const cur = reconnecting.get(name);
    if (cur) return cur;
    const now = Date.now();
    if (!o.force && now - (lastReconnect.get(name) || 0) < reconnectCooldownMs) return Promise.resolve(false);
    lastReconnect.set(name, now);
    slog("再接続: " + name + "（" + why + "）");
    const p = Promise.resolve().then(() => hub.reconnect(name)).then(
      () => true,
      (e) => {
        if (o.rethrow) throw e;
        slog("再接続に失敗: " + name + " — " + String((e && e.message) || e).slice(0, 200));
        return false;
      }
    ).finally(() => { reconnecting.delete(name); });
    reconnecting.set(name, p);
    return p;
  }

  /**
   * 呼び出し先のサーバーが使える状態になるまで、最大 callWaitMs 待つ。
   *   connected                         … すぐ返る
   *   connecting / timed_out / queued   … 接続中（初回の npx ダウンロード等）。進行中の接続を壊さないよう、繋ぎ直さずに待つ
   *   error（一時的な失敗）              … hub は 1 秒から倍々（最大 30 秒）で再試行するが、呼び出しが待っているので予約を待たず hub.reconnect(名前) を 1 回かける
   *   disabled / auth_required / 設定・起動失敗 … 待っても直らないので、すぐ hub に任せて理由を返させる
   */
  async function ensureServerReady(toolName, signal, o) {
    o = o || {};
    if (!callWaitMs) return;
    const name = serverNameOf(toolName);
    if (!name) return;
    const deadline = Date.now() + callWaitMs;
    let kickedAt = 0, kickDoneAt = 0;
    for (;;) {
      const st = hub.getState();
      const s = (st.servers || []).find((x) => x && x.name === name);
      if (!s) return;
      if (s.state === "connected") {
        // 繋ぎ直した直後は「接続済みだが tools/list がまだ」の時間がある（hub は接続のたびに tools を空にして取り直す）。ここで通すと UNKNOWN_TOOL（404）で
        // 断られるので、一覧が出る（または取得に失敗する）まで待つ。待ち時間は呼び出しの待ち上限（callWaitMs）に含まれる。
        const loading = (s.toolsStatus === "loading" || !s.toolsStatus) && !(s.toolCount > 0);
        if (!loading) return;
        const left0 = deadline - Date.now();
        if (left0 <= 0 || (signal && signal.aborted)) return;
        await hub.waitForChange(st.revision, Math.min(left0, 500));
        continue;
      }
      const d = policy.decideHeal(s, {}, Date.now(), { ignoreScheduled: true });
      if (d.action === "reset" || d.action === "giveup") return;   // 無効 / 待っても直らない
      if (d.action === "reconnect" && !kickedAt) {
        kickedAt = Date.now();
        reconnectServer(name, "呼び出し時に " + s.state, { force: !!o.force }).then(() => { kickDoneAt = Date.now(); });
      }
      // 再接続の呼び出しが終わったのに、まだ不調のままなら（繋ぎ直しても戻らなかった）、待ち続けずに hub に理由を返させる
      if (kickDoneAt && d.action === "reconnect" && Date.now() - kickDoneAt > 1500) return;
      const left = deadline - Date.now();
      if (left <= 0 || (signal && signal.aborted)) return;
      await hub.waitForChange(st.revision, Math.min(left, 1000));
    }
  }

  /** NOT_CONNECTED のあと、繋ぎ直しを待ってやり直す価値があるか。認証・設定の失敗や無効なサーバーは、待っても直らない。 */
  function worthRetrying(name) {
    const s = name ? serverEntry(name) : null;
    if (!s) return false;
    if (s.state === "connected") return true;   // 表示は接続済みなのに hub が断った = 状態が古かった
    const d = policy.decideHeal(s, {}, Date.now(), { ignoreScheduled: true });
    return d.action === "reconnect" || d.action === "skip" || d.action === "wait";
  }

  /* ------------------------------------------------------------
     呼び出しの失敗の記録
     ------------------------------------------------------------
     通信路が死んだ失敗（接続断・セッション切れ）は hub が state を error にして自分で再接続する（mcpHub.Upstream.callTool）。
     ここで足すのは、hub から見えない「固まったサーバー」だけ: 無音で 2 回続けて時間切れなら、そのサーバーを 1 件だけ繋ぎ直す。 */
  const suspect = new Map();   // name -> { timeouts }
  function noteCallOk(name) { if (name) suspect.delete(name); }
  function noteCallFailure(name, c) {
    if (!name || !c) return;
    const s = serverEntry(name);
    if (!s || s.state !== "connected") return;
    if (c.kind !== "timeout") { suspect.delete(name); return; }
    const r = suspect.get(name) || { timeouts: 0 };
    r.timeouts++;
    suspect.set(name, r);
    if (r.timeouts >= 2) { suspect.delete(name); reconnectServer(name, "呼び出しが 2 回続けて時間切れ（サーバーが固まっている可能性）"); }   // 遅いだけのサーバーを巻き込まないよう 1 回では繋ぎ直さない
  }

  /** hub の例外 → { code, status, kind, c, message }。message には「次にやること」を足す（モデルも画面もそれを読む）。 */
  function describeCallError(e, serverName) {
    const code = (e && e.hubCode) || "CALL_FAILED";
    const status = code === "UNKNOWN_TOOL" ? 404 : code === "NOT_CONNECTED" ? 503 : /TIMEOUT|TIMED_OUT/i.test(code) ? 504 : 502;
    const c = policy.classify(e);
    const srv = serverName ? serverEntry(serverName) : null;
    let message = scrub((e && e.message) || "呼び出しに失敗しました。");
    if (code !== "UNKNOWN_TOOL" && (c.kind !== "unknown" || code === "NOT_CONNECTED")) {
      const lost = policy.isSessionLost(e);
      const kind = lost ? "session_lost" : c.kind !== "unknown" ? c.kind : "network";
      message += "\n→ 次にやること: " + policy.nextActionFor({ kind, closed: c.closed, causeCode: c.causeCode, transport: policy.transportOf(srv), phase: "call", status: c.status });
    }
    // クライアント（lumen.html の gatewayOutcome）が再送してよいかを決める材料: not_sent = サーバーへ送る前に断った / rejected = 相手が答えて拒否した / unknown = 送信後に結果を受け取れなかった（実行済みかもしれない）。
    const outcome = /^(NOT_CONNECTED|UNKNOWN_TOOL|SERVER_DISABLED|BAD_REQUEST)$/.test(code) ? "not_sent" : code === "AUTH" ? "rejected" : "unknown";
    return { code, status, kind: c.kind, c, message, outcome };
  }

  const hostOk = (h) => {
    if (!h) return false;
    const m = /^(\[::1\]|127\.0\.0\.1|localhost)(?::(\d+))?$/i.exec(String(h));
    return !!m && (m[2] === undefined || Number(m[2]) === actualPort());
  };
  const originOk = (o) => {
    if (!o) return true;                       // 同一オリジン / curl
    if (o === "null") return true;             // file:// で開いた lumen.html
    if (extraOrigins.includes(o)) return true;
    return /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/i.test(o);
  };
  let boundPort = port;
  const actualPort = () => boundPort;

  const sendJson = (res, status, body, extra) => {
    const text = JSON.stringify(body);
    res.writeHead(status, Object.assign({ "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(text), "Cache-Control": "no-store" }, extra || {}));
    res.end(text);
  };
  const fail = (res, status, code, message) => sendJson(res, status, { error: { code, message } });

  const readJson = (req) => new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on("data", (c) => { n += c.length; if (n > MAX_BODY) { reject(Object.assign(new Error("リクエストが大きすぎます。"), { status: 413, code: "TOO_LARGE" })); req.destroy(); return; } chunks.push(c); });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw.trim()) { resolve({}); return; }
      try { resolve(JSON.parse(raw)); } catch (_) { reject(Object.assign(new Error("JSON として不正です。"), { status: 400, code: "BAD_JSON" })); }
    });
    req.on("error", reject);
  });

  async function route(req, res, url) {
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/lumen.html")) {
      // "/" も /lumen.html も lumen.html を配信する（同一オリジンで開けば CORS・file:// の Origin 問題を避けられる）。
      let html;
      try { html = fs.readFileSync(LUMEN_FILE); } catch (_) { /* 下で 404 */ }
      if (!html) { fail(res, 404, "NO_UI", path.basename(LUMEN_FILE) + " が見つかりません。"); return; }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
      res.end(html);
      return;
    }
    if (req.method === "GET" && url.pathname === "/health") {
      const sd = sdkNow();
      sendJson(res, 200, { ok: true, service: "lumen-core", version: VERSION, authRequired: auth.required, sdk: { ok: sd.ok, fake: sd.fake, version: sd.version } });
      return;
    }
    if (!url.pathname.startsWith("/api/")) { fail(res, 404, "NOT_FOUND", "存在しないパスです。"); return; }

    if (auth.required) {
      const m = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ""));
      if (!m || !safeEqual(m[1].trim(), auth.token)) { fail(res, 401, "UNAUTHORIZED", "アクセストークンが無効です。"); return; }
    }

    if (req.method === "GET" && url.pathname === "/api/state") { sendJson(res, 200, stateOut()); return; }
    if (req.method === "GET" && url.pathname === "/api/tools") {
      const st = hub.getState();
      const cat = buildCatalog();
      const tag = '"' + cat.etag + '"';
      if (String(req.headers["if-none-match"] || "").split(",").some((x) => x.trim().replace(/^W\//, "") === tag)) {
        res.writeHead(304, { ETag: tag, "Cache-Control": "no-cache" });
        res.end();
        return;
      }
      sendJson(res, 200, { revision: st.revision, tools: cat.tools, toolsEtag: cat.etag, catalog: catalogReport(cat) }, { ETag: tag, "Cache-Control": "no-cache" });
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/tools/discover") {
      const body = await readJson(req);
      if (typeof body.query !== "string" || !body.query.trim()) { fail(res, 400, "BAD_REQUEST", "query（ツール検索語）が必要です。"); return; }
      if (body.query.length > 500) { fail(res, 400, "BAD_REQUEST", "query は 500 文字以内にしてください。"); return; }
      try {
        const result = await hub.discoverTools(body.query, { maxServers: body.maxServers });
        sendJson(res, 200, Object.assign({ revision: hub.getState().revision }, result), { "Cache-Control": "no-store" });
      } catch (e) {
        const code = e.hubCode || "DISCOVERY_FAILED";
        const status = code === "BAD_REQUEST" ? 400 : code === "UNKNOWN_SERVER" ? 404 : 502;
        fail(res, status, code, String(e.message || e).slice(0, 500));
      }
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/commands") { sendJson(res, 200, listProjectCommands(workspaceRoot)); return; }
    if (req.method === "GET" && url.pathname === "/api/snapshot") {
      const st = hub.getState();
      const cat = buildCatalog();
      const known = url.searchParams.get("toolsEtag") || "";
      const same = known !== "" && known === cat.etag;
      sendJson(res, 200, { revision: st.revision, state: Object.assign({}, st, { sdk: sdkNow() }), toolsEtag: cat.etag, toolsUnchanged: same, tools: same ? null : cat.tools, catalog: catalogReport(cat) });
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/changes") {
      const since = Number(url.searchParams.get("since")) || 0;
      const rev = await hub.waitForChange(since, 25000);
      sendJson(res, 200, { revision: rev });
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/tools/call") {
      const body = await readJson(req);
      if (typeof body.name !== "string" || !body.name) { fail(res, 400, "BAD_REQUEST", "name（ツール名）が必要です。"); return; }
      const ac = new AbortController();
      res.on("close", () => { if (!res.writableEnded) ac.abort(); });
      const t0 = Date.now();
      const sname = serverNameOf(body.name);
      // 長い呼び出し: 無音のまま数分続くと、ブラウザ・プロキシ・セキュリティソフトが接続を切ることがある（Firefox の既定は 5 分）。
      // keepAliveMs を超えたら 200 を先に返し、空白を流し続ける（JSON は先頭の空白を許す）。短い呼び出しは今までどおり正しいステータスで返る。
      let streaming = false, beat = null, first = null;
      const stopBeat = () => { if (first) clearTimeout(first); if (beat) clearInterval(beat); first = beat = null; };
      const startStream = () => {
        if (streaming || res.destroyed || res.writableEnded) return;
        streaming = true;
        res.writeHead(200, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Accel-Buffering": "no" });
        res.write(" ");
        beat = setInterval(() => { if (!res.destroyed && !res.writableEnded) res.write(" "); }, keepAliveMs);
      };
      if (keepAliveMs) first = setTimeout(startStream, keepAliveMs);
      const finish = (status, payload, extra) => {
        stopBeat();
        if (res.writableEnded || res.destroyed) return;
        if (!streaming) { sendJson(res, status, payload, extra); return; }
        res.end(JSON.stringify(payload));   // 200 は送信済み。失敗は本文の { error } で伝える（クライアントは /api/tools/call の 200 + error を失敗として扱う）
      };
      const call = () => hub.callTool(body.name, body.arguments, { signal: ac.signal, timeoutMs: Number(body.timeoutMs) || undefined });
      try {
        await ensureServerReady(body.name, ac.signal);
        let result;
        try { result = await call(); }
        catch (e) {
          // NOT_CONNECTED は「サーバーへ送る前に断った」ことを表す（HTTP セッション切れもここに来る）。副作用が起きていないので、繋ぎ直しを待って 1 回だけやり直してよい。
          // （通信の途中で切れた呼び出しは、副作用が起きたか分からないので自動では再送しない）
          if (e && e.hubCode === "NOT_CONNECTED" && !ac.signal.aborted && worthRetrying(sname)) {
            await ensureServerReady(body.name, ac.signal, { force: true });
            result = await call();
          } else throw e;
        }
        noteCallOk(sname);
        const ms = Date.now() - t0;
        if (ms >= 10000) slog("呼び出し完了（長い）: " + body.name + " " + ms + "ms");
        finish(200, { result, durationMs: ms }, { "Server-Timing": "call;dur=" + ms });
      } catch (e) {
        if (res.writableEnded || res.destroyed || ac.signal.aborted) { stopBeat(); return; }
        const info = describeCallError(e, sname);
        noteCallFailure(sname, info.c);
        slog("呼び出し失敗: " + body.name + " " + (Date.now() - t0) + "ms code=" + info.code + " 種類=" + info.kind + (info.c.causeCode ? " cause=" + info.c.causeCode : "") + (info.c.closed ? " closed" : "") + " state=" + ((serverEntry(sname) || {}).state || "?"));
        finish(info.status, { error: { code: info.code, message: info.message, status: info.status, outcome: info.outcome } });
      }
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/reconnect") {
      const body = await readJson(req);
      const target = typeof body.server === "string" && body.server ? body.server : undefined;
      try {
        if (target) await reconnectServer(target, "手動", { force: true, rethrow: true });
        else if (body.all === true) await hub.reconnect(undefined);   // 全サーバーを強制で繋ぎ直す（呼び出し中の通信も切れる）
        else await hub.syncAllServers();                             // 既定: 接続できていないものだけ。正常なサーバー（workspace など）には触れない
        sendJson(res, 200, stateOut());
      } catch (e) { fail(res, e.hubCode === "UNKNOWN_SERVER" ? 404 : 500, e.hubCode || "ERROR", scrub(e.message)); }
      return;
    }
    // ---- 複数サーバーの管理（貼り付けインポート・1 件ずつの追加 / 更新 / 削除 / 有効無効） ----
    if (url.pathname === "/api/servers" || url.pathname.startsWith("/api/servers/")) {
      const mapErr = (e) => {
        const code = e.hubCode || "ERROR";
        const status = { INVALID_CONFIG: 400, INVALID_SERVER: 400, UNKNOWN_SERVER: 404, EXISTS: 409, CONFLICT: 409 }[code] || 500;
        fail(res, status, code, e.message);
      };
      const done = (result) => sendJson(res, 200, Object.assign({}, result, { state: stateOut() }));
      if (req.method === "GET" && url.pathname === "/api/servers") { sendJson(res, 200, stateOut()); return; }
      if (req.method === "POST" && url.pathname === "/api/servers/import/preview") {
        const body = await readJson(req);
        if (typeof body.text !== "string") { fail(res, 400, "BAD_REQUEST", "text（貼り付けた内容）が必要です。"); return; }
        sendJson(res, 200, hub.previewImport(body.text));
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/servers/import") {
        const body = await readJson(req);
        if (typeof body.text !== "string") { fail(res, 400, "BAD_REQUEST", "text（貼り付けた内容）が必要です。"); return; }
        try { done(hub.applyImport(body.text, body.choices, typeof body.etag === "string" ? body.etag : undefined)); } catch (e) { mapErr(e); }
        return;
      }
      const ms = /^\/api\/servers\/([^/]+)(?:\/(enabled|diagnose))?$/.exec(url.pathname);
      if (ms) {
        let name;
        try { name = decodeURIComponent(ms[1]); } catch (_) { fail(res, 400, "BAD_URL", "サーバー名が不正です。"); return; }
        if (req.method === "PUT" && !ms[2]) {
          const body = await readJson(req);
          if (!body.spec || typeof body.spec !== "object") { fail(res, 400, "BAD_REQUEST", "spec（サーバー定義）が必要です。"); return; }
          const mode = body.mode === "create" || body.mode === "update" ? body.mode : undefined;
          try { done(hub.putServer(name, body.spec, { mode, etag: typeof body.etag === "string" ? body.etag : undefined })); } catch (e) { mapErr(e); }
          return;
        }
        if (req.method === "DELETE" && !ms[2]) {
          try { done(hub.removeServer(name, url.searchParams.get("etag") || undefined)); } catch (e) { mapErr(e); }
          return;
        }
        if (req.method === "POST" && ms[2] === "diagnose") {
          try {
            const dg = await hub.diagnose(name);
            const sd = sdkNow();
            const out = Object.assign({}, dg, { sdk: { ok: sd.ok, fake: sd.fake, version: sd.version, evidence: sd.evidence } });
            if (sd.fake) {
              // コマンドは単体で起動できても、接続に使う SDK が偽物なので繋がらない。「起動したまま」の判定を、原因（SDK）の判定で上書きする。
              out.verdict = "原因は実行コア側です: 接続に使う MCP SDK がテスト用の偽物です（このサーバーのコマンドや設定の問題ではありません）。";
              out.errorKind = "sdk";
              out.nextAction = "画面上部の手順（fix-sdk.bat → start.bat で再起動）で本物の SDK を入れ直してください。";
              out.note = sd.evidence;
            }
            sendJson(res, 200, out);
          } catch (e) { mapErr(e); }
          return;
        }
        if (req.method === "POST" && ms[2] === "enabled") {
          const body = await readJson(req);
          if (typeof body.enabled !== "boolean") { fail(res, 400, "BAD_REQUEST", "enabled（true / false）が必要です。"); return; }
          try { done(hub.setServerDisabled(name, !body.enabled, typeof body.etag === "string" ? body.etag : undefined)); } catch (e) { mapErr(e); }
          return;
        }
      }
      fail(res, 404, "NOT_FOUND", "存在しない API です。");
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/config") { sendJson(res, 200, hub.readConfigText()); return; }
    if (req.method === "PUT" && url.pathname === "/api/config") {
      const body = await readJson(req);
      if (typeof body.text !== "string") { fail(res, 400, "BAD_REQUEST", "text（.mcp.json の本文）が必要です。"); return; }
      try { hub.writeConfigText(body.text); sendJson(res, 200, { ok: true, state: hub.getState() }); }
      catch (e) { fail(res, e.hubCode === "INVALID_CONFIG" ? 400 : 500, e.hubCode || "ERROR", e.message); }
      return;
    }
    fail(res, 404, "NOT_FOUND", "存在しない API です。");
  }

  const server = http.createServer((req, res) => {
    const origin = req.headers.origin;
    // DNS rebinding 対策: Host が自分自身（loopback）でなければ拒否
    if (!hostOk(req.headers.host)) { fail(res, 403, "BAD_HOST", "Host ヘッダーが許可されていません。"); return; }
    if (origin && !originOk(origin)) { fail(res, 403, "BAD_ORIGIN", "Origin が許可されていません。"); return; }
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, If-None-Match");
      res.setHeader("Access-Control-Expose-Headers", "ETag, Server-Timing");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    }
    if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }
    let url;
    try { url = new URL(req.url, "http://127.0.0.1"); } catch (_) { fail(res, 400, "BAD_URL", "URL が不正です。"); return; }
    route(req, res, url).catch((e) => {
      if (res.headersSent) { try { res.end(); } catch (_) { /* 切断済み */ } return; }
      fail(res, e.status || 500, e.code || "INTERNAL", e.status ? e.message : "内部エラー: " + String((e && e.message) || e).slice(0, 200));
    });
  });

  // 長いポーリング（/api/changes）と短い要求が同じ接続を使い回せるようにする（既定の 5 秒だと、ポーリングの合間に接続が切れる）。
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 70000;

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", async () => {
      boundPort = server.address().port;
      hub.init({ workspaceRoot, appRoot: APP_ROOT, version: VERSION, log });
      resolve({
        server, port: boundPort, token: auth.token, tokenFile: auth.file, workspaceRoot,
        async close() {
          await hub.shutdown();
          await new Promise((r) => {
            server.close(r);
            // keep-alive を長くしたぶん、待機中の接続が閉じるまで close が返らなくなるのを防ぐ（処理中のポーリングも 1 秒で打ち切る）
            if (typeof server.closeIdleConnections === "function") server.closeIdleConnections();
            const t = setTimeout(() => { if (typeof server.closeAllConnections === "function") server.closeAllConnections(); }, 1000);
            if (t.unref) t.unref();
          });
        },
      });
    });
  });
}

if (require.main === module) {
  start().then((s) => {
    log("core: http://127.0.0.1:" + s.port + "/   workspace: " + s.workspaceRoot);
    if (s.token) {
      log("アクセストークン" + (s.tokenFile ? "（" + s.tokenFile + "）" : "") + ": " + s.token);
      log("画面の 設定 → 実行コア にこのトークンを入力してください。");
    } else log("警告: LUMEN_AUTH=off のためトークン認証は無効です。");
    log("MCP サーバーは " + path.join(s.workspaceRoot, ".mcp.json") + " の mcpServers から接続します。");
    const stop = () => { s.close().finally(() => process.exit(0)); setTimeout(() => process.exit(0), 5000).unref(); };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
  }).catch((e) => { console.error("[Lumen] 起動できませんでした: " + e.message); process.exit(1); });
}

module.exports = { start, deploySkills, inspectSdk };
