"use strict";

/**
 * 【レガシー — 現在の経路では未使用】
 * server.js・mcpHub.js のどちらもこのファイルを require しない。stdio の MCP サーバーは mcpHub.js が SDK の StdioClientTransport で直接起動する（そちらが正）。
 * 下記の /mcp/stdio/rpc 契約を呼ぶブラウザ側の実装も、現行の lumen.html には無い（lumen.html は /api/tools/call 経由）。
 * mcpLaunch.js のコメントがこのファイルに触れているのは過去の経緯。新しい修正はここに入れない。
 */

/**
 * mcpStdio.js — MCP stdio 中継（Lumen 実行コア）
 * ============================================================
 * ブラウザ側 NFMcpTransports.stdio が呼ぶ契約を実装する。ブラウザは子プロセスを起動できないため、
 * 実行コアが MCP サーバー（子プロセス）を起動し、標準入出力の JSON-RPC を中継する。
 *
 *   POST /mcp/stdio/rpc     { server:{command,args,cwd}, message, timeoutMs } -> { message:{jsonrpc:"2.0", id, result|error} }
 *   POST /mcp/stdio/cancel  { requestId, server? } -> { ok:true, cancelled:boolean }（ベストエフォート）
 *                           server（rpc と同じ {command,args,cwd}）を付けると、そのサーバーのリクエストだけを取り消す。
 *                           省略時は全セッションから id 一致を探す（別サーバーが同じ id を使っていると巻き込むため、付けることを推奨）。
 *
 * ステータスの意味（クライアントの nfReason と対応）:
 *   200 成功 / 400 リクエスト不正 / 401 トークン不一致（server.js 側） / 403 許可リスト不一致・機能無効
 *   404・405 未実装（server.js のルーティング） / 429 同時セッション上限 / 502 子プロセスの起動失敗・異常終了 / 504 応答タイムアウト
 *
 * 設計:
 *   - 起動を許可するコマンドは「素のコマンド名」の許可リストだけ（パス区切りを含む指定は拒否）。/health の mcpStdioAllowed で宣言する。
 *   - 子プロセスは (command, args, cwd) ごとに 1 つ保持して再利用する（初回だけ initialize → notifications/initialized を実行コアが代行）。
 *     アイドルが LUMEN_MCP_STDIO_IDLE_MS（既定 10 分）続くと終了する。
 *   - 子プロセスには LUMEN_TOKEN を渡さない（実行コアの認証トークンが MCP サーバーへ漏れないように）。
 *
 * 環境変数:
 *   LUMEN_MCP_STDIO=off               この機能を無効にする
 *   LUMEN_MCP_STDIO_ALLOWED=a,b,c     許可するコマンド名（既定: npx,node,uvx,python,python3,deno,bun）。
 *                                  LUMEN_EXEC_MODE=whitelist のときは、これを明示した場合だけ有効になる。
 *   LUMEN_MCP_STDIO_IDLE_MS=600000    アイドル終了までの時間
 *   LUMEN_MCP_STDIO_HANDSHAKE=off     initialize の代行をしない（ステートレスで initialize を要しないサーバー向け）
 *   LUMEN_CONFINE_CWD=1               cwd をワークスペース配下に限定する（shellRunner と同じ設定）
 */

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const launch = require("./mcpLaunch");   // Windows の .cmd シム分解（WIN_CMD_SHIMS・危険文字判定・引用規則）は mcpHub と共有する単一の実装

const IS_WIN = process.platform === "win32";
const DEFAULT_ALLOWED = ["npx", "node", "uvx", "python", "python3", "deno", "bun"];
const INIT_PROTOCOL_VERSION = "2025-06-18";
const MAX_SESSIONS = 8;
const MAX_ARGS = 64;
const MAX_ARG_CHARS = 4096;
const MAX_LINE_BYTES = 16 * 1024 * 1024; // 1行（1 JSON-RPC メッセージ）の上限
const STDERR_TAIL_CHARS = 4000;
const DEFAULT_TIMEOUT_MS = 15000;
const INIT_TIMEOUT_MS = 120000;           // npx の初回ダウンロード等を見込んだ initialize の上限

class McpStdioError extends Error {
  constructor(statusCode, errorKind, message) {
    super(message);
    this.name = "McpStdioError";
    this.statusCode = statusCode;
    this.errorKind = errorKind;
  }
}

/* ------------------------------------------------------------
   設定
   ------------------------------------------------------------ */

let workspaceRoot = process.cwd();
let serviceVersion = "0";
let enabled = false;
let allowed = DEFAULT_ALLOWED.slice();
let confine = false;
let handshake = true;
let idleMs = 600000;

const COMMAND_NAME = /^[A-Za-z0-9._+-]+$/;

function init(opts) {
  opts = opts || {};
  const env = opts.env || process.env;
  workspaceRoot = path.resolve(opts.workspaceRoot || process.cwd());
  serviceVersion = String(opts.version || "0");
  // 廃止した接頭辞の環境変数は読まない。黙って無視すると、設定したつもりの制限（cwd の閉じ込め・許可コマンド）が効かなくなるので、見つけたら警告する。
  const _retired = launch.retiredEnvKeys(env);
  if (_retired.length) console.warn("[mcpStdio] 廃止した接頭辞の環境変数は無効です（LUMEN_ に改名してください）: " + _retired.join(", "));
  const raw = typeof env.LUMEN_MCP_STDIO_ALLOWED === "string" ? env.LUMEN_MCP_STDIO_ALLOWED.trim() : "";
  const explicit = raw !== "";
  allowed = explicit
    ? Array.from(new Set(raw.split(",").map((s) => s.trim()).filter((s) => s && COMMAND_NAME.test(s))))
    : DEFAULT_ALLOWED.slice();
  const off = String(env.LUMEN_MCP_STDIO || "").toLowerCase() === "off";
  // whitelist モード（任意コマンドを実行させない運用）では、許可コマンドを明示したときだけ有効にする。
  enabled = !off && allowed.length > 0 && (opts.execMode === "open" || explicit);
  confine = String(env.LUMEN_CONFINE_CWD || "") === "1";
  handshake = String(env.LUMEN_MCP_STDIO_HANDSHAKE || "").toLowerCase() !== "off";
  const idle = Number(env.LUMEN_MCP_STDIO_IDLE_MS);
  idleMs = Number.isFinite(idle) && idle >= 10000 ? idle : 600000;
}

function isEnabled() { return enabled; }
function getAllowedCommands() { return allowed.slice(); }

/* ------------------------------------------------------------
   入力検証
   ------------------------------------------------------------ */

function bad(message) { return new McpStdioError(400, "request", message); }

function commandAllowed(command) {
  if (IS_WIN) return allowed.some((a) => a.toLowerCase() === command.toLowerCase());
  return allowed.indexOf(command) >= 0;
}

function resolveCwd(cwd) {
  const rel = cwd == null || cwd === "" ? "." : String(cwd);
  if (rel.indexOf("\0") >= 0) throw bad("cwd が不正です。");
  const abs = path.resolve(workspaceRoot, rel);
  if (confine) {
    const r = path.relative(workspaceRoot, abs);
    if (r.startsWith("..") || path.isAbsolute(r)) throw new McpStdioError(403, "cwd", "cwd はワークスペース配下に限定されています（LUMEN_CONFINE_CWD=1）。");
  }
  let st;
  try { st = fs.statSync(abs); } catch (_) { throw bad("cwd が存在しません: " + rel); }
  if (!st.isDirectory()) throw bad("cwd がディレクトリではありません: " + rel);
  return abs;
}

function validateServer(server) {
  if (!server || typeof server !== "object") throw bad("server（command / args / cwd）が指定されていません。");
  const command = typeof server.command === "string" ? server.command.trim() : "";
  if (!command) throw bad("server.command が指定されていません。");
  if (!COMMAND_NAME.test(command) || command.length > 64) {
    throw new McpStdioError(403, "allow", "起動コマンドは許可リストにある素のコマンド名だけ指定できます（パスや空白を含む指定は不可）: " + command.slice(0, 40));
  }
  if (!commandAllowed(command)) {
    throw new McpStdioError(403, "allow", "起動コマンド「" + command + "」は mcpStdioAllowed に含まれていません（許可: " + allowed.join(", ") + "）。LUMEN_MCP_STDIO_ALLOWED で追加できます。");
  }
  const args = server.args == null ? [] : server.args;
  if (!Array.isArray(args) || args.length > MAX_ARGS) throw bad("server.args は " + MAX_ARGS + " 件以下の文字列配列にしてください。");
  const outArgs = args.map((a) => {
    const s = String(a);
    if (s.length > MAX_ARG_CHARS || s.indexOf("\0") >= 0) throw bad("server.args に不正な値があります。");
    return s;
  });
  const outEnv = {};
  if (server.env != null) {
    if (typeof server.env !== "object" || Array.isArray(server.env)) throw bad("server.env は文字列の連想配列にしてください。");
    const keys = Object.keys(server.env);
    if (keys.length > 64) throw bad("server.env は 64 件以下にしてください。");
    keys.forEach((k) => {
      if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(k) || k === "LUMEN_TOKEN") throw bad("server.env に使えないキーがあります: " + k.slice(0, 40));
      const v = String(server.env[k]);
      if (v.length > MAX_ARG_CHARS || v.indexOf("\0") >= 0) throw bad("server.env の値が不正です: " + k);
      outEnv[k] = v;
    });
  }
  return { command, args: outArgs, cwd: resolveCwd(server.cwd), env: outEnv };
}

function validateMessage(message) {
  if (!message || typeof message !== "object" || Array.isArray(message)) throw bad("message が JSON-RPC オブジェクトではありません。");
  if (message.jsonrpc !== "2.0") throw bad("message.jsonrpc は \"2.0\" である必要があります。");
  if (typeof message.method !== "string" || !message.method || message.method.length > 200) throw bad("message.method が不正です。");
  if (message.id !== undefined && typeof message.id !== "string" && typeof message.id !== "number") throw bad("message.id は文字列か数値にしてください。");
  return message;
}

/* ------------------------------------------------------------
   プロセス操作
   ------------------------------------------------------------ */

function killTree(child) {
  if (!child || !child.pid) return;
  try { if (child.stdin && !child.stdin.destroyed) child.stdin.end(); } catch (_) { /* 既に閉じている */ }
  try {
    if (IS_WIN) {
      // cmd.exe 経由で起動した孫プロセス（node など）まで止める。
      spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" }).on("error", () => {});
    } else {
      try { process.kill(-child.pid, "SIGTERM"); } catch (_) { child.kill("SIGTERM"); }
      setTimeout(() => { try { process.kill(-child.pid, "SIGKILL"); } catch (_) { /* 終了済み */ } }, 2000).unref();
    }
  } catch (_) { /* 終了済み */ }
}

/**
 * Windows の .cmd シム（npx / npm / pnpm / yarn / corepack）は、shell:true の生結合ではなく cmd.exe /d /s /c へ分解して起動する。
 * 規則（対象コマンド・引用・危険文字の拒否）は mcpLaunch.wrapWinShim が持つ。mcpHub（エージェント経路）と同じ実装。
 * ここは Node の spawn を直接呼ぶので、Node の shell:true と同じ形（外側の "" ＋ windowsVerbatimArguments）にする。
 */
function buildSpawn(command, args) {
  let w = null;
  try { w = launch.wrapWinShim(command, args); }
  catch (err) { if (err instanceof launch.LaunchArgError) throw bad(err.message); throw err; }
  if (w) return { cmd: w.command, args: w.verbatimArgs, verbatim: true };
  return { cmd: command, args, verbatim: false };
}

function childEnv(extra) {
  const env = Object.assign({}, process.env, extra || {});
  delete env.LUMEN_TOKEN; // 実行コアの認証トークンを子プロセスへ渡さない
  return env;
}

/* ------------------------------------------------------------
   セッション（子プロセス 1 つ）
   ------------------------------------------------------------ */

const sessions = new Map(); // key -> Session

class Session {
  constructor(key, def) {
    this.key = key;
    this.def = def;
    this.label = def.command + (def.args.length ? " " + def.args.join(" ") : "");
    this.child = null;
    this.buf = "";
    this.pending = new Map(); // JSON.stringify(id) -> { resolve, reject, timer, id }
    this.stderrTail = "";
    this.lastUsed = Date.now();
    this.closed = false;
    this.deadErr = null;
    this.initSeq = 0;
    this.ready = null;
  }

  start() {
    const sp = buildSpawn(this.def.command, this.def.args);
    let child;
    try {
      child = spawn(sp.cmd, sp.args, {
        cwd: this.def.cwd, env: childEnv(this.def.env), stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true, detached: !IS_WIN, shell: false, windowsVerbatimArguments: sp.verbatim,
      });
    } catch (err) {
      throw this._spawnError(err);
    }
    this.child = child;
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => this._onData(chunk));
    child.stderr.on("data", (chunk) => {
      this.stderrTail = (this.stderrTail + chunk).slice(-STDERR_TAIL_CHARS);
    });
    child.stdin.on("error", () => { /* EPIPE 等は exit/close 側で扱う */ });
    child.on("error", (err) => this._fail(this._spawnError(err)));
    child.on("close", (code, signal) => this._fail(this._exitError(code, signal)));
    this.ready = this._handshake().catch((err) => { this.kill(err); throw err; });
    this.ready.catch(() => { /* 呼び出し側が待つまでの unhandled rejection を防ぐ */ });
  }

  _tail() {
    const t = this.stderrTail.trim();
    return t ? "\nstderr（末尾）: " + t.slice(-600) : "";
  }
  _spawnError(err) {
    const code = err && err.code;
    if (code === "ENOENT") {
      return new McpStdioError(502, "spawn", "起動コマンド「" + this.def.command + "」が見つかりません。実行コアの PATH にインストールされているか確認してください。");
    }
    return new McpStdioError(502, "spawn", "MCP サーバーを起動できませんでした（" + (code || "error") + "）: " + String((err && err.message) || err).slice(0, 200));
  }
  _exitError(code, signal) {
    return new McpStdioError(502, "exit", "MCP stdio サーバー「" + this.label.slice(0, 120) + "」が終了しました（" + (signal ? "signal=" + signal : "code=" + code) + "）。起動コマンドや引数、依存の取得に失敗している可能性があります。" + this._tail());
  }

  _write(msg) {
    if (this.closed || !this.child || !this.child.stdin || this.child.stdin.destroyed || !this.child.stdin.writable) {
      throw this.deadErr || new McpStdioError(502, "exit", "MCP stdio サーバーは終了しています。");
    }
    this.child.stdin.write(JSON.stringify(msg) + "\n");
  }

  _onData(chunk) {
    this.buf += chunk;
    if (this.buf.length > MAX_LINE_BYTES) { this.kill(new McpStdioError(502, "exit", "MCP stdio サーバーの出力が大きすぎるため停止しました。")); return; }
    let i;
    while ((i = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, i).replace(/\r$/, "");
      this.buf = this.buf.slice(i + 1);
      if (line.trim()) this._onLine(line);
    }
  }

  _onLine(line) {
    let msg;
    try { msg = JSON.parse(line); } catch (_) {
      // JSON ではない行（ライブラリが stdout に出すログ等）は無視するが、原因調査用に stderr 側の末尾へ残す。
      this.stderrTail = (this.stderrTail + "[stdout] " + line.slice(0, 200) + "\n").slice(-STDERR_TAIL_CHARS);
      return;
    }
    if (!msg || typeof msg !== "object") return;
    if (typeof msg.method === "string") {
      // サーバー発のリクエスト（sampling / roots 等）は未対応。待たせず明示的に拒否する。通知は無視。
      if (msg.id !== undefined && msg.id !== null) {
        try {
          if (msg.method === "ping") this._write({ jsonrpc: "2.0", id: msg.id, result: {} });
          else this._write({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "Method not found" } });
        } catch (_) { /* 終了済み */ }
      }
      return;
    }
    if (msg.id !== undefined && (msg.result !== undefined || msg.error !== undefined)) {
      const p = this.pending.get(JSON.stringify(msg.id));
      if (p) { this.pending.delete(JSON.stringify(msg.id)); p.resolve(msg); }
    }
  }

  /** 異常終了・起動失敗: 待機中のリクエストをすべて失敗させ、プールから外す。 */
  _fail(err) {
    if (this.closed) return;
    this.closed = true;
    this.deadErr = err;
    if (sessions.get(this.key) === this) sessions.delete(this.key);
    Array.from(this.pending.values()).forEach((p) => p.reject(err));
    this.pending.clear();
  }

  kill(err) {
    this._fail(err || new McpStdioError(502, "exit", "MCP stdio サーバーを停止しました。"));
    killTree(this.child);
  }

  async _handshake() {
    if (!handshake) return;
    const deadline = Date.now() + INIT_TIMEOUT_MS;
    const id = "lumen-init-" + (++this.initSeq);
    let r;
    try {
      r = await this.request({
        jsonrpc: "2.0", id, method: "initialize",
        params: { protocolVersion: INIT_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "lumen-core", version: serviceVersion } },
      }, deadline);
    } catch (err) {
      if (err && err.errorKind === "timeout") {
        throw new McpStdioError(504, "timeout", "MCP stdio サーバーの initialize が " + Math.round(INIT_TIMEOUT_MS / 1000) + " 秒以内に完了しませんでした（初回の npx ダウンロード待ち、または initialize に応答しないサーバーです。後者は LUMEN_MCP_STDIO_HANDSHAKE=off を試してください）。" + this._tail());
      }
      throw err;
    }
    // initialize が JSON-RPC エラーで返ったサーバー（ステートレス等）は、そのまま通常のリクエストを受け付けるものとして続行する。
    if (!r.error) this._write({ jsonrpc: "2.0", method: "notifications/initialized" });
  }

  /** id 付きリクエストを送り、同じ id の応答を deadlineAt まで待つ。 */
  request(msg, deadlineAt) {
    return new Promise((resolve, reject) => {
      if (this.closed) { reject(this.deadErr || new McpStdioError(502, "exit", "MCP stdio サーバーは終了しています。")); return; }
      const key = JSON.stringify(msg.id);
      if (this.pending.has(key)) { reject(new McpStdioError(409, "conflict", "同じ id のリクエストが処理中です。")); return; }
      const remain = Math.max(1, deadlineAt - Date.now());
      const timer = setTimeout(() => {
        if (this.pending.get(key) === entry) this.pending.delete(key);
        reject(new McpStdioError(504, "timeout", "MCP stdio サーバーの応答がありませんでした（待ち時間の上限に達しました）。初回の npx ダウンロードなどで時間がかかる場合は「通信の待ち時間の上限」を延ばしてください。" + this._tail()));
      }, remain);
      const entry = {
        id: msg.id, timer,
        resolve: (m) => { clearTimeout(timer); resolve(m); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      };
      this.pending.set(key, entry);
      try { this._write(msg); } catch (e) { this.pending.delete(key); clearTimeout(timer); reject(e); }
    });
  }

  /** 待機中のリクエストを取り消し、サーバーへ notifications/cancelled を送る（ベストエフォート）。 */
  cancel(id, reason) {
    const key = JSON.stringify(id);
    const p = this.pending.get(key);
    if (!p) return false;
    this.pending.delete(key);
    try { this._write({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: id, reason: reason || "cancelled" } }); } catch (_) { /* 終了済み */ }
    p.reject(new McpStdioError(499, "cancelled", "取り消されました。"));
    return true;
  }
}

function sessionKey(def) {
  return crypto.createHash("sha1").update(JSON.stringify([def.command, def.args, def.cwd, def.env || {}])).digest("hex");
}

function getSession(def) {
  const key = sessionKey(def);
  let s = sessions.get(key);
  if (s && !s.closed) return s;
  if (sessions.size >= MAX_SESSIONS) {
    // 待機中のリクエストが無い最も古いセッションを退避する。全部使用中なら受け付けない。
    const idle = Array.from(sessions.values()).filter((x) => x.pending.size === 0).sort((a, b) => a.lastUsed - b.lastUsed)[0];
    if (!idle) throw new McpStdioError(429, "limit", "同時に起動できる MCP stdio サーバーの上限（" + MAX_SESSIONS + "）に達しています。");
    idle.kill(new McpStdioError(502, "exit", "上限のため停止しました。"));
  }
  s = new Session(key, def);
  sessions.set(key, s); // start() が同期で失敗した場合のため、先に登録してから起動し、失敗時は外す
  try { s.start(); } catch (err) { sessions.delete(key); throw err; }
  return s;
}

/** promise を deadlineAt で打ち切る（元の promise は止めない。initialize の完了待ちが次のリクエストに引き継がれるように）。 */
function untilDeadline(promise, deadlineAt, makeError) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(makeError()), Math.max(1, deadlineAt - Date.now()));
    promise.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

/* ------------------------------------------------------------
   公開API
   ------------------------------------------------------------ */

/** body: { server:{command,args,cwd}, message, timeoutMs } -> JSON-RPC 応答メッセージ（{jsonrpc,id,result|error}）。失敗は McpStdioError。 */
async function rpc(body) {
  if (!enabled) throw new McpStdioError(403, "mode", "MCP stdio 中継は無効です（LUMEN_MCP_STDIO=off、または whitelist モードで LUMEN_MCP_STDIO_ALLOWED が未設定）。");
  body = body || {};
  const def = validateServer(body.server);
  const msg = validateMessage(body.message);
  const ms = Math.min(300000, Math.max(1000, Number(body.timeoutMs) || DEFAULT_TIMEOUT_MS));
  const deadline = Date.now() + ms;
  const s = getSession(def);
  s.lastUsed = Date.now();
  const timeoutErr = () => new McpStdioError(504, "timeout", "MCP stdio サーバーの起動待ちが上限（" + Math.round(ms / 1000) + "秒）に達しました（初回の npx ダウンロード中かもしれません。続けて再試行すると引き継がれます）。" + s._tail());
  await untilDeadline(s.ready, deadline, timeoutErr);
  if (msg.id === undefined) { // 通知: 応答は無い
    s._write(msg);
    s.lastUsed = Date.now();
    return { jsonrpc: "2.0", result: {} };
  }
  const reply = await s.request(msg, deadline);
  s.lastUsed = Date.now();
  return reply;
}

/** 待機中のリクエストを id で取り消す。取り消した件数を返す。serverDef を渡すと、そのサーバー（command, args, cwd が同じセッション）だけが対象。 */
function cancelById(requestId, reason, serverDef) {
  if (requestId === undefined || requestId === null) return 0;
  let key = null;
  if (serverDef !== undefined && serverDef !== null) {
    try { key = sessionKey(validateServer(serverDef)); } catch (_) { return 0; } // 不正な定義のリクエストは実行されていない
  }
  let n = 0;
  sessions.forEach((s) => { if (key !== null && s.key !== key) return; if (s.cancel(requestId, reason)) n++; });
  return n;
}

function shutdownAll() {
  Array.from(sessions.values()).forEach((s) => s.kill(new McpStdioError(502, "exit", "実行コアを停止しました。")));
  sessions.clear();
}

function stats() {
  return Array.from(sessions.values()).map((s) => ({ command: s.def.command, pending: s.pending.size, idleMs: Date.now() - s.lastUsed }));
}

const sweeper = setInterval(() => {
  const now = Date.now();
  Array.from(sessions.values()).forEach((s) => {
    if (s.pending.size === 0 && now - s.lastUsed > idleMs) s.kill(new McpStdioError(502, "exit", "アイドルのため停止しました。"));
  });
}, 30000);
sweeper.unref();

module.exports = { init, isEnabled, getAllowedCommands, rpc, cancelById, shutdownAll, stats, McpStdioError };
