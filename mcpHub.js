"use strict";

/**
 * mcpHub.js — Lumen 実行コアの MCP 接続ハブ
 * ============================================================
 * 公式 MCP SDK v2（@modelcontextprotocol/client）で、ワークスペース直下 .mcp.json の mcpServers へ接続する。
 * 任意のトップレベル lumenCapabilities は Lumen 独自の明示的な遅延接続メタデータ。未指定・不正なサーバーは従来どおり eager 接続する。
 * 独自の JSON-RPC・initialize・セッション管理は持たない。プロトコル世代の交渉は SDK に任せる。
 *
 *   - 世代交渉   : versionNegotiation.mode = "auto"（server/discover を先に試し、2026-07-28 の modern 世代で接続。
 *                  古いサーバーは SDK が 2025 世代の initialize へ自動で落とす）。.mcp.json の "protocol" で固定も可。
 *                  ただし "protocol" を省略したパッケージランナー（npx / uvx 等）の stdio は、最初の接続を legacy にする
 *                  （ラッパー越しの server/discover プローブは時間切れになりやすく、古い SDK のサーバーは discover を話さない）。
 *                  legacy がプロトコル世代の不一致で落ちたときだけ、次の 1 回を auto にする（再試行カウンタは起動ルートの attempt と別の protoStep）。
 *   - transport  : stdio（StdioClientTransport）/ Streamable HTTP（StreamableHTTPClientTransport）/ 旧 HTTP+SSE（type: "sse"、SSEClientTransport。既定は legacy 世代）。
 *   - リモート接続: HTTP / SSE は、SDK を回す前に素の fetch で 1 回診断する（mcpHttp.probe: 到達・認証・応答形式）。到達できない / 認証が要る場合は、
 *                  原因（DNS・証明書・プロキシ・401 など）をそのまま出して止める。続行できるなら
 *                  「legacy（initialize）→ auto（server/discover）→ 最小クライアント」の順に、繋がるまで試す（protocol 省略時）。
 *                  /sse だけを話す旧サーバーは診断で見つけて SSE transport へ自動で切り替える。繋がった方式は route として覚え、再接続では先に試す。
 *   - 複数サーバー: mcpServers に何件でも書ける。追加・上書き・削除・有効/無効は 1 件ずつ原子的に書き換える（etag で他所の変更を検知）。
 *                  貼り付けインポート（mcpImport.js）は各種 MCP 設定（JSON / TOML / claude mcp add）を正規化して取り込む。
 *                  設定変更で再接続するのは、定義が変わった・新しいサーバーだけ（変わっていない接続は維持する）。
 *   - ツール取得 : Client.listTools()（ページングは SDK）。名称・説明・inputSchema・annotations は取得結果そのまま。
 *   - 遅延接続   : manifest で lazy=true と能力タグを明示したサーバーだけ、tool_search からの問い合わせで接続。tools/list 成功前はツールを公開しない。
 *   - 呼び出し   : Client.callTool()。結果は加工せずブラウザへ返す（isError も保持）。
 *   - 認証       : HTTP は静的ヘッダー / Bearer（${ENV} 展開）。OAuth が要求されたサーバーは state=auth_required を明示する。
 *   - 接続とツール取得は別の状態: client.connect() が成功した時点で state=connected。tools/list はその後ろでバックグラウンド取得し（失敗は 1s / 5s / 15s で再試行）、
 *                  3 回続けて失敗しても接続は生かして state=degraded にする（toolsStatus / toolsError に理由）。初期接続を tools/list で落とさない。
 *   - 失敗の見える化: サーバーごとに errorKind（spawn / protocol / auth / timeout / transport / tools / config / exit）と nextAction（次に何をすればよいか）を返す。
 *                  一過性の失敗は 1 秒から指数バックオフ（上限 30 秒）で自動再接続する。npx / uvx などのランナーは同時 2 本、それ以外は同時 6 本。
 *   - 失敗は閉じる: 接続できないサーバーのツールは 1 件も出さない。代替ツールは合成しない。
 *   - 秘密       : env / headers / bearer の値は、ログ・状態・エラー文から必ず伏字にする。
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const dns = require("dns");
const tls = require("tls");
const cp = require("child_process");
const { Client, StreamableHTTPClientTransport, SSEClientTransport, UnauthorizedError, SdkError } = require("@modelcontextprotocol/client");
const { StdioClientTransport } = require("@modelcontextprotocol/client/stdio");
const mcpLaunch = require("./mcpLaunch");   // 起動ルート（直接起動 / 従来）の切替と OS 必須環境変数の補完
const importer = require("./mcpImport");
const mcpHttp = require("./mcpHttp");       // HTTP / 旧 SSE の事前診断・原因の説明・最小クライアント（SDK が繋げなかったときの逃げ道）・長い呼び出し用の fetch
const policy = require("./mcpPolicy");      // 失敗の分類（通信路が死んだか / セッション切れか）。再接続の予約そのものは下の Upstream._scheduleRetry が持つ
const mcpCapabilities = require("./mcpCapabilities"); // trusted workspace manifest による opt-in lazy discovery

/* モデルに見せるツール名は "mcp__<server>__<tool>"。"mcp__" は MCP の名前空間を示す慣習で、独自ブランドではない。
   保存済みの権限ルール・フック・履歴がこの形式に依存し、組み込みツールとの衝突回避にもなるため維持する。
   呼び出し先は名前の文字列解析ではなく、登録時に記録した { server, upstreamName } で決める（toolOwners / findTool）。 */
const NAME_PREFIX = "mcp__";
const MAX_TOOL_NAME = 64;               // LLM API の関数名上限に合わせる
const SERVER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;
const CONNECT_TIMEOUT_MS = 120000;      // 既定の接続上限
const RUNNER_CONNECT_TIMEOUT_MS = mcpLaunch.RUNNER_CONNECT_TIMEOUT_MS;   // startupTimeoutMs を書いていない npx / uvx 等は 180 秒（初回ダウンロード + 世代の再試行を見込む）
const CALL_TIMEOUT_MS = 30 * 60 * 1000;
const RETRY_MIN_MS = 1000;              // 初回の再試行は 1 秒後。以降は 2 倍ずつ伸ばす
const RETRY_MAX_MS = 30000;
const STABLE_MS = 30000;                // 接続後この時間つながり続けたら、再試行カウンタ（と通知の重複判定）を戻す。接続→即死の繰り返しで 1 秒間隔に張り付かないため
const TEARDOWN_TIMEOUT_MS = 3000;       // client.close() のハング対策。超えたらプロセスを木ごと落とす
const TOOLS_RETRY_DELAYS = [1000, 5000, 15000];   // tools/list の再試行（接続後のバックグラウンド）。3 回失敗で degraded
const TOOLS_SLOW_RETRY_MS = 30000;      // degraded になった後の低頻度の再取得
const DEGRADED_KICK_AFTER = 4;          // degraded のまま低頻度の再取得を 4 回（約 2 分）続けても戻らなければ、接続ごと張り直す（セッションが壊れている場合に備える）
const DEGRADED_KICK_MAX = 3;            // その張り直しは、tools/list が取れるまでに最大 3 回（張り直しを無限に繰り返さない）
const CONNECT_GLOBAL_TIMEOUT_MS = 240000;   // 全サーバーの同期が終わらないときに timed_out を表示する上限（プロセスは止めない）
const PROGRESS_INTERVAL_MS = 5000;
const NOTICE_LIMIT = 50;
const STDERR_TAIL = 4000;
const WATCH_INTERVAL_MS = 1500;
const CONNECT_CONCURRENCY = 6;         // 同時に接続を始めるサーバー数（node 直起動・HTTP など、パッケージランナーではないもの）
const RUNNER_CONCURRENCY = Math.max(1, Math.min(8, Math.floor(Number(process.env.LUMEN_RUNNER_CONCURRENCY)) || 4));   // npx / uvx などパッケージランナーの同時起動数。既定 4（以前は 2）。キャッシュが空の初回に npx が詰まる（ENOTEMPTY 等）ときは LUMEN_RUNNER_CONCURRENCY=2 に戻す

let WORKSPACE_ROOT = process.cwd();
let APP_ROOT = process.cwd();
let VERSION = "0";
let CONFIG_PATH = path.join(WORKSPACE_ROOT, ".mcp.json");
let logger = (m) => console.log("[mcp-hub] " + m);

const upstreams = new Map();   // name -> Upstream
const toolOwners = new Map();  // 公開ツール名 -> { server, upstreamName }（切断中のサーバーのツール名も覚えておく）
let configError = null;        // null | { message, kind: "json" | "schema" | "import" }
let capabilityManifest = Object.create(null); // .mcp.json の lumenCapabilities。未宣言は従来どおり eager connect
let capabilityWarnings = [];
let revision = 1;
const waiters = new Set();
let watching = false;
let closing = false;

/* ------------------------------------------------------------
   共通
   ------------------------------------------------------------ */

function bump() {
  revision++;
  Array.from(waiters).forEach((w) => w());
}

/** since より新しい revision になるまで（最大 timeoutMs）待つ。ブラウザへの変更通知（ロングポーリング）用。 */
function waitForChange(since, timeoutMs) {
  if (revision !== since) return Promise.resolve(revision);
  return new Promise((resolve) => {
    const done = () => { clearTimeout(t); waiters.delete(done); resolve(revision); };
    const t = setTimeout(done, Math.max(1000, Math.min(timeoutMs || 25000, 60000)));
    t.unref();
    waiters.add(done);
  });
}

/* ------------------------------------------------------------
   通知（サーバーが error になったときの 1 回きりの知らせ）・同時実行の制限・全体の同期状態
   ------------------------------------------------------------ */

const KINDS = ["spawn", "protocol", "auth", "timeout", "transport", "tools", "config", "exit"];
const notices = [];
let noticeSeq = 0;

/** getState().notices へ積む。id は単調増加（ブラウザは最後に見た id より大きいものだけをトーストにする）。message は伏字済みのものだけを渡すこと。 */
function pushNotice(server, kind, message, nextAction) {
  notices.push({ id: ++noticeSeq, server, kind, message: String(message || "").slice(0, 300), nextAction: nextAction || "", at: new Date().toISOString() });
  if (notices.length > NOTICE_LIMIT) notices.splice(0, notices.length - NOTICE_LIMIT);
}

/** 同時実行を n 件までに絞るキュー（FIFO）。 */
class Pool {
  constructor(name, limit) { this.name = name; this.limit = limit; this.active = new Set(); this.q = []; this.maxActive = 0; this.started = 0; }
  run(label, fn) {
    return new Promise((resolve) => {
      const job = () => {
        this.active.add(label); this.started++;
        this.maxActive = Math.max(this.maxActive, this.active.size);
        Promise.resolve().then(fn).catch(() => false).then((r) => { this.active.delete(label); this._next(); resolve(r); });
      };
      if (this.active.size < this.limit) job(); else this.q.push(job);
    });
  }
  _next() { while (this.q.length && this.active.size < this.limit) this.q.shift()(); }
  stats() { return { limit: this.limit, active: this.active.size, activeNames: Array.from(this.active), queued: this.q.length, maxActive: this.maxActive, started: this.started }; }
}
const runnerPool = new Pool("runner", RUNNER_CONCURRENCY);
const plainPool = new Pool("plain", CONNECT_CONCURRENCY);

/** u を接続キューへ入れる。ランナー（npx / uvx 等）は専用キュー（同時 2）、それ以外は同時 6。force=false なら、順番が来た時点で接続済みなら何もしない。 */
function enqueue(u, force) {
  if (u._queued) return Promise.resolve(false);
  u._queued = true;
  const pool = u._cfg && u._cfg.runner ? runnerPool : plainPool;
  return pool.run(u.name, () => {
    u._queued = false;
    if (!force && (u.state === "connected" || u.state === "degraded")) return false;
    return u.connect().catch(() => false);
  });
}

const sync = { startedAt: 0, endedAt: 0, active: 0, timedOut: false, timer: null, progress: null };

function logProgress() {
  const list = Array.from(upstreams.values()).filter((u) => u.state !== "disabled" && u.state !== "deferred");
  const connecting = list.filter((u) => u.state === "connecting" || u.state === "timed_out");
  const queued = connecting.filter((u) => u._queued).length;
  logger("[MCP 進捗] " + list.filter((u) => u.state === "connected" || u.state === "degraded").length + "/" + list.length + " servers connected, " +
    (connecting.length - queued) + " running, " + queued + " queued" +
    (sync.timedOut ? "（全体の待ち " + Math.round(CONNECT_GLOBAL_TIMEOUT_MS / 1000) + " 秒を超過）" : ""));
}

function onGlobalTimeout() {
  sync.timedOut = true;
  let n = 0;
  upstreams.forEach((u) => { if (u.state === "connecting") { u._markTimedOut(); n++; } });
  logger("[MCP 全体タイムアウト] " + Math.round(CONNECT_GLOBAL_TIMEOUT_MS / 1000) + " 秒を超えても接続が終わらないサーバーが " + n + " 件あります。接続処理は止めず、順番待ち・試行中のまま続けます。");
  bump();
}

function beginSync() {
  sync.active++;
  if (sync.active !== 1) return;
  sync.startedAt = Date.now(); sync.endedAt = 0; sync.timedOut = false;
  clearTimeout(sync.timer); clearInterval(sync.progress);
  sync.timer = setTimeout(onGlobalTimeout, CONNECT_GLOBAL_TIMEOUT_MS); sync.timer.unref();
  sync.progress = setInterval(logProgress, PROGRESS_INTERVAL_MS); sync.progress.unref();
}

function endSync() {
  sync.active = Math.max(0, sync.active - 1);
  if (sync.active !== 0) return;
  sync.endedAt = Date.now();
  clearTimeout(sync.timer); clearInterval(sync.progress);
  logProgress();
  bump();
}

/** /api/state の syncStatus。経過秒・件数・全体タイムアウトの有無。 */
function syncStatusOf() {
  const list = Array.from(upstreams.values()).filter((u) => u.state !== "disabled" && u.state !== "deferred");
  const n = (f) => list.filter(f).length;
  const connecting = n((u) => u.state === "connecting");
  const timedOut = n((u) => u.state === "timed_out");
  const queued = n((u) => (u.state === "connecting" || u.state === "timed_out") && u._queued);
  const running = connecting + timedOut - queued;
  const elapsedMs = sync.startedAt ? (sync.endedAt || Date.now()) - sync.startedAt : 0;
  const phase = !sync.startedAt ? "idle" : sync.active > 0 ? (sync.timedOut ? "timed_out" : "syncing") : "done";
  return {
    phase, startedAt: sync.startedAt || null, elapsedSec: Math.round(elapsedMs / 1000), timeoutSec: Math.round(CONNECT_GLOBAL_TIMEOUT_MS / 1000),
    total: list.length, connected: n((u) => u.state === "connected"), degraded: n((u) => u.state === "degraded"),
    failed: n((u) => u.state === "error" || u.state === "auth_required"), timedOut, running, queued,
  };
}

/** 診断・テスト用: 同時実行キューと全体の同期状態。 */
function stats() { return { runner: runnerPool.stats(), plain: plainPool.stats(), sync: syncStatusOf() }; }

/** エラーの種類ごとの「次にやること」（1 行）。text に stderr などが含まれていれば、より具体的な案内に差し替える。 */
function nextActionFor(kind, text) {
  const t = String(text || "");
  if (/No module named ['"]?(pwd|fcntl|termios|resource|grp)\b/i.test(t)) {
    return "このサーバーは Unix 専用の Python モジュール（pwd / fcntl など）を使っており、Windows では起動できません。Windows 対応の別サーバー（例: windows-cli）を使うか、WSL 上で起動してください。";
  }
  // 必要な値（接続文字列・パスなど）を env ではなくコマンドライン引数で要求するサーバー。env に書いても読まれず、起動直後に終了する。
  if (/(?:provide|specify|pass|requires?|required|missing|expected|need)[^\n]{0,80}(?:command[- ]?line arg|as an? (?:cli |positional )?arg(?:ument)?|positional arg)|(?:unknown|unrecognized|missing required) (?:option|argument|arg)\b|^\s*usage:\s/im.test(t)) {
    return "このサーバーは必要な値（接続文字列・パスなど）を env ではなくコマンドライン引数（args）で受け取る可能性があります。stderr の案内を確認し、その値を args の末尾へ追加してください（env に書いても読まれません）。";
  }
  if (/ModuleNotFoundError|No module named|Cannot find module|ERR_MODULE_NOT_FOUND/i.test(t)) return "サーバーが依存パッケージを見つけられていません。パッケージの導入（npm install / uv sync）と、command・args のパスを確認してください。";
  if (/EBADENGINE|Unsupported engine|requires (?:a )?(?:node|python)/i.test(t)) return "サーバーが要求する Node / Python のバージョンと実行環境が合っていません。バージョンを確認してください。";
  if (kind === "exit" && /ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ECONNRESET|getaddrinfo|self[- ]signed|CERT_/i.test(t)) return "パッケージの取得で通信に失敗した可能性があります。プロキシ・社内 CA（NODE_EXTRA_CA_CERTS）・ネットワークを確認してください。";
  if (kind === "transport") {
    if (/session|セッション|\b(?:404|410)\b/i.test(t) && !/ENOTFOUND|ECONNREFUSED/i.test(t)) return "サーバー側のセッションが切れていた可能性があります（サーバーの再起動・有効期限）。自動で接続を張り直します。今すぐなら「再接続」を押してください。";
    if (/UND_ERR_(?:HEADERS|BODY)_TIMEOUT|Headers Timeout|Body Timeout|5 分/i.test(t)) return "サーバーから何も返らないまま長く経ち、Node の無応答の上限で切れました。長い呼び出しは longFetch（mcpHttp.js）で上限を外しています。LUMEN_HTTP_LONG_FETCH=off にしていないか確認してください。";
    if (/ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(t)) return "ホスト名を DNS で解決できません。URL のホスト名・VPN・社内 DNS・プロキシ（Node 22.21 / 24 以降は NODE_USE_ENV_PROXY=1）を確認してください。";
    if (/ECONNREFUSED/i.test(t)) return "接続を拒否されました。ポートとホスト、サーバーが起動しているかを確認してください（自動で再接続を続けます）。";
    if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS|DEPTH_ZERO/i.test(t)) return "TLS 証明書を検証できません。社内 CA を NODE_EXTRA_CA_CERTS（または NODE_USE_SYSTEM_CA=1）で渡して、実行コアを再起動してください。";
    if (/ECONNRESET|EPIPE|socket hang up|other side closed|terminated|Connection closed|切断/i.test(t)) return "接続を途中で切られました（サーバー側の制限・プロキシ・セキュリティソフトの可能性）。自動で再接続します。続く場合は「診断」を確認してください。";
    if (/\b429\b/.test(t)) return "レート制限（HTTP 429）です。少し待つと自動で再接続します。";
    if (/\b5\d\d\b/.test(t)) return "サーバー側の障害（HTTP 5xx）の可能性があります。自動で再接続を続けます。復旧しない場合はサーバーのログを確認してください。";
  }
  switch (kind) {
    case "spawn": return "コマンドが PATH にあるか、npx の場合は初回ダウンロードが完了しているかを確認してください。";
    case "protocol": return "サーバーの世代（legacy / 2025-06-18 / 2026-07-28）が合わない可能性があります。.mcp.json の protocol を試してください。";
    case "auth": return "headers / bearerToken に有効なトークンを設定してください（OAuth の対話認可は未対応です）。";
    case "timeout": return "初回のパッケージ取得などで時間がかかっている可能性があります。しばらく待つか、.mcp.json の startupTimeoutMs を延ばして「再接続」してください。";
    case "transport": return "URL・ネットワーク・プロキシ・証明書を確認してください。「診断」で DNS / TLS の状態を確認できます。";
    case "tools": return "接続はできていますが tools/list を取得できていません。サーバー側のログを確認して「再接続」を試してください（自動でも再取得を続けます）。";
    case "config": return ".mcp.json の定義（command / args / url / protocol など）を見直してください。";
    case "exit": return "サーバープロセスが終了しました。エラー欄の stderr（末尾）を確認し、「診断」でコマンドを単体実行して原因を確かめてください。";
    default: return "";
  }
}

const isTimeoutErr = (e) => !!e && (/timeout|timed.?out/i.test(String(e.code || "") + " " + String(e.name || "")) || /timed out|timeout/i.test(String(e.message || "")));
/** 通信路が死んだ失敗か（接続断・接続拒否・セッション切れ）。従来の文面判定（closed / ECONN / EPIPE / fetch failed / disconnected）に、mcpPolicy の分類を足したもの。 */
const isDeadTransportErr = (e) => !!e && (/closed|ECONN|EPIPE|fetch failed|disconnected/i.test(String(e.code || "") + " " + String(e.message || "")) || policy.isDeadTransport(e));
const isClosedErr = (e) => !!e && (e.code === -32000 || /^CONNECTION_CLOSED$/i.test(String(e.code || "")) || /connection closed|MCP error -32000/i.test(String(e.message || "")));

/** stdio の子プロセス（npx / uvx など）へ引き継ぐ、ネットワーク・証明書関連の環境変数。SDK は既定で最小限の環境しか渡さないため、
 *  プロキシや社内 CA の設定が届かずパッケージを取得できなくなる。アクセストークンなどアプリの秘密は含めない。 */
const INHERITED_ENV = [
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy",
  "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA",
  "UV_NATIVE_TLS", "UV_SYSTEM_CERTS", "UV_CACHE_DIR", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "PIP_INDEX_URL", "PIP_CERT",
  "PYTHONUTF8", "PYTHONIOENCODING", "NPM_CONFIG_USERCONFIG", "NPM_CONFIG_CACHE", "NPM_CONFIG_REGISTRY", "NPM_CONFIG_CAFILE", "npm_config_userconfig", "npm_config_cache", "npm_config_registry", "npm_config_cafile",
];
function inheritedEnv() {
  const o = {};
  INHERITED_ENV.forEach((k) => { if (process.env[k] !== undefined && process.env[k] !== "") o[k] = process.env[k]; });
  return o;
}

const expandVars = (s) => String(s).replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g, (_, k, d) =>
  (process.env[k] !== undefined ? process.env[k] : d !== undefined ? d : ""));
const expandMap = (m) => {
  const o = {};
  Object.keys(m || {}).forEach((k) => { o[k] = expandVars(m[k]); });
  return o;
};

function makeRedactor(secrets) {
  const list = Array.from(new Set(secrets.filter((s) => typeof s === "string" && s.length >= 6)));
  return (text) => {
    let t = String(text == null ? "" : text);
    list.forEach((s) => { t = t.split(s).join("***"); });
    return t.replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, "$1***");
  };
}

/** 公開名を決める。taken は「全サーバー横断」で使用済みの公開名（別サーバーの同名ツール・"__" を含むサーバー名との衝突を防ぐ）。
 *  衝突・長さ超過時は sha1(server\0tool) の先頭 6 桁を付ける（従来と同じ名前になる）。それでも衝突したら連番入りで再計算する。 */
function sanitizeToolName(server, tool, taken) {
  const clean = String(tool).replace(/[^A-Za-z0-9_-]/g, "_");
  let name = NAME_PREFIX + server + "__" + clean;
  if (name.length > MAX_TOOL_NAME || taken.has(name)) {
    const base = (NAME_PREFIX + server + "__" + clean).slice(0, MAX_TOOL_NAME - 7);
    for (let n = 0; ; n++) {
      const seed = n === 0 ? server + "\0" + tool : server + "\0" + tool + "\0" + n;
      name = base + "_" + crypto.createHash("sha1").update(seed).digest("hex").slice(0, 6);
      if (!taken.has(name)) break;
    }
  }
  return name;
}

/* ------------------------------------------------------------
   .mcp.json
   ------------------------------------------------------------ */

function defaultConfig() {
  // 公式リファレンスの filesystem サーバー（依存関係として同梱）を、ワークスペースに限定して起動する。
  return {
    mcpServers: {
      filesystem: {
        command: "node",
        args: ["${LUMEN_APP_ROOT}/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js", "${LUMEN_WORKSPACE_ROOT}"],
      },
    },
  };
}

function ensureConfigFile() {
  if (fs.existsSync(CONFIG_PATH)) return;
  try {
    fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(defaultConfig(), null, 2) + "\n", { flag: "wx" });
    logger("既定の .mcp.json（公式 filesystem サーバー）を作成しました。");
  } catch (e) { logger("既定の .mcp.json を作れませんでした: " + e.message); }
}

/** 設定オブジェクトの検証。{ servers, errors[] }。サーバー単位のエラーは errors に積み、他は生かす。 */
function validateConfig(obj) {
  const errors = [];
  const servers = {};
  if (obj == null || typeof obj !== "object" || Array.isArray(obj)) return { servers, errors: ["設定のルートが JSON オブジェクトではありません。"] };
  const s = obj.mcpServers;
  if (s == null) return { servers, errors };
  if (typeof s !== "object" || Array.isArray(s)) return { servers, errors: ["mcpServers がオブジェクトではありません。"] };
  Object.keys(s).forEach((name) => {
    if (!SERVER_NAME_RE.test(name) || name.includes("__")) {
      errors.push("サーバー名「" + name.slice(0, 40) + "」が不正です（英数字・_・- のみ、先頭は英数字、32 文字以内、__ は不可）。");
      return;
    }
    servers[name] = s[name];
  });
  return { servers, errors };
}

function readConfigFile() {
  let raw;
  try { raw = fs.readFileSync(CONFIG_PATH, "utf8"); }
  catch (e) { return { text: "", servers: {}, lumenCapabilities: null, errors: e.code === "ENOENT" ? [] : [".mcp.json を読めません: " + e.message], errorKind: "json" }; }
  if (!raw.trim()) return { text: raw, servers: {}, lumenCapabilities: null, errors: [] };
  let j;
  try { j = JSON.parse(raw); } catch (e) { return { text: raw, servers: {}, lumenCapabilities: null, errors: [".mcp.json が JSON として不正です: " + e.message], errorKind: "json" }; }
  const v = validateConfig(j);
  return { text: raw, servers: v.servers, lumenCapabilities: j && j.lumenCapabilities, errors: v.errors, errorKind: v.errors.length ? "schema" : undefined };
}

/* ------------------------------------------------------------
   サーバー定義 1 件の検証と正規化（Upstream と、貼り付け・保存時の事前検証が同じ関数を使う）
   ------------------------------------------------------------ */

/** 定義を検証して接続に必要な値へ展開する。不正なら Error。opts.validate=true なら disabled でも検証する。 */
function compileSpec(s, opts) {
  opts = opts || {};
  if (!s || typeof s !== "object" || Array.isArray(s)) throw new Error("定義がオブジェクトではありません。");
  const declared = s.type === undefined ? (s.command !== undefined ? "stdio" : s.url !== undefined ? "http" : null) : String(s.type).toLowerCase();
  if (s.disabled === true && !opts.validate) {
    return { type: declared === "sse" ? "sse" : (s.url !== undefined && s.command === undefined ? "http" : "stdio"), disabled: true, cfg: null, redact: (t) => String(t) };
  }
  // protocol を省略した事実は残す（ディスク上の JSON は変えない）。パッケージランナーの既定世代の選択に使う。
  const protoImplicit = s.protocol === undefined;
  const proto = protoImplicit ? "auto" : String(s.protocol);
  if (proto !== "auto" && proto !== "legacy" && !/^\d{4}-\d{2}-\d{2}$/.test(proto)) throw new Error('protocol は "auto" / "legacy" / 日付（例: 2026-07-28）のいずれかにしてください。');
  const explicitTimeout = Number.isFinite(Number(s.startupTimeoutMs)) && Number(s.startupTimeoutMs) >= 1000;
  let timeoutMs = explicitTimeout ? Number(s.startupTimeoutMs) : CONNECT_TIMEOUT_MS;
  if (declared === "stdio") {
    if (typeof s.command !== "string" || !s.command.trim()) throw new Error("command が指定されていません。");
    // env を書いていない（または空）なら undefined: 実行コアの環境（process.env）を子へそのまま引き継ぐ。書いてあれば、OS 必須の最低限 + 書いた値だけ（mcpLaunch.buildEnv）
    const userEnv = s.env && typeof s.env === "object" && !Array.isArray(s.env) && Object.keys(s.env).length ? expandMap(s.env) : undefined;
    const command = expandVars(s.command).trim();
    const args = Array.isArray(s.args) ? s.args.map((a) => expandVars(a)) : [];
    const runner = mcpLaunch.runnerName(command, args);   // npx / npm / pnpm / yarn / corepack / uvx（cmd /c npx ... と書かれていても元のコマンド名で判定）
    if (runner && !explicitTimeout) timeoutMs = RUNNER_CONNECT_TIMEOUT_MS;   // 書かれた startupTimeoutMs は尊重する
    return {
      type: "stdio", disabled: false, redact: makeRedactor(Object.values(userEnv || {})),
      cfg: {
        proto, protoImplicit, runner, timeoutMs,
        command,
        args,
        env: userEnv === undefined ? undefined : Object.assign(inheritedEnv(), userEnv),
        cwd: s.cwd ? path.resolve(WORKSPACE_ROOT, expandVars(s.cwd)) : WORKSPACE_ROOT,
      },
    };
  }
  if (declared === "http" || declared === "streamable-http" || declared === "streamablehttp" || declared === "sse") {
    if (typeof s.url !== "string" || !/^https?:\/\//i.test(expandVars(s.url))) throw new Error((declared === "sse" ? "sse" : "http") + " サーバーには http(s):// で始まる url が必要です。");
    const headers = expandMap(s.headers);
    const bearer = s.bearerToken !== undefined ? expandVars(s.bearerToken) : "";
    return {
      type: declared === "sse" ? "sse" : "http", disabled: false, redact: makeRedactor(Object.values(headers).concat([bearer])),
      cfg: { proto, protoImplicit, runner: null, timeoutMs, url: expandVars(s.url), headers, bearer },
    };
  }
  throw new Error('type は省略（command / url から判定）か "stdio" / "http" / "sse" にしてください' + (declared ? "（指定: " + declared + "）" : "") + "。");
}

/** 設定指紋。サーバー定義（command / args / env / url / headers など。値も含む）を正規化した JSON の SHA-256 先頭 32 桁。値そのものは返さない。
 *  クライアントの「信頼」はこの指紋とツール定義の指紋が両方一致する間だけ有効（同名ツールでも、接続先・コマンド・環境が変われば再承認）。
 *  有効/無効の切替と起動待ち時間は安全性に関係しないので含めない。 */
function specFingerprint(spec) {
  const canon = (v) => Array.isArray(v) ? v.map(canon)
    : (v && typeof v === "object") ? Object.keys(v).sort().reduce((o, k) => { o[k] = canon(v[k]); return o; }, {})
    : v;
  try {
    const o = spec && typeof spec === "object" && !Array.isArray(spec) ? Object.assign({}, spec) : spec;
    if (o && typeof o === "object") { delete o.disabled; delete o.startupTimeoutMs; }
    return crypto.createHash("sha256").update(JSON.stringify(canon(o === undefined ? null : o))).digest("hex").slice(0, 32);
  } catch (_e) { return ""; }
}

/** 画面・API へ返す定義。別名を正規形へそろえ、env / headers / bearerToken の値は伏字にする。 */
function displaySpec(spec) {
  if (!spec || typeof spec !== "object" || Array.isArray(spec)) return null;
  const n = importer.normalizeSpec(spec);
  return importer.maskSpec(n.spec || spec);
}

/* ------------------------------------------------------------
   上流サーバー 1 台（SDK Client 1 つ）
   ------------------------------------------------------------ */

class Upstream {
  constructor(name, spec, capability) {
    this.name = name;
    this.spec = spec;
    this.capability = capability || { lazy: false, capabilities: [], description: "", source: "default-eager" };
    this.lazy = this.capability.lazy === true;
    this._lazyConnectPromise = null;
    this.specKey = JSON.stringify(spec);
    this.type = null;
    this.state = "connecting";   // connecting | connected | degraded | error | auth_required | timed_out | disabled
    this.error = null;
    this.errorKind = null;       // spawn | protocol | auth | timeout | transport | tools | config | exit（error / auth_required / timed_out / degraded のとき）
    this.nextAction = null;      // 次に何をすればよいか（1 行）
    this.client = null;
    this.transport = null;
    this.tools = [];             // 取得結果（名称は名前空間付きに変換済み）
    this.toolsStatus = null;     // null（未接続） | "loading" | "ok" | "error"。transport の確立（state）とは独立
    this.toolsError = null;
    this.skipped = 0;
    this.era = null;
    this.protocolVersion = null;
    this.serverInfo = null;
    this.instructions = null;
    this.stderrTail = "";
    this.attempt = 0;            // 再試行の回数 = 起動ルート（mcpLaunch.plan）の切替と再試行間隔（バックオフ）用。プロトコル世代の再試行には使わない
    this._attemptCount = 0;      // 接続を試みた通算回数（attempts の各行に付ける。リセットしない）
    this.protoStep = 0;          // プロトコル世代の再試行段階。0 = 最初（パッケージランナーは legacy）/ 1 = legacy が世代不一致で落ちたので auto
    this._autoTrial = false;     // protoStep=1 への切替直後の 1 回（失敗したら 0 へ戻す。成功したら 1 のまま = そのサーバーは auto が要る）
    this._launch = null;         // 直近の起動ルートの diag（エラー文言用）
    this._negLabel = "auto";     // 直近の交渉モード（legacy / auto / pin）。タイムアウトの原因を取り違えないため
    this.attempts = [];          // 直近の接続試行の履歴（起動 / 診断 → 方式ごとの成否 / tools/list）。画面の診断表示用。秘密は含めない
    this.route = null;           // 繋がった方式（"legacy" / "auto" / "SSE(旧)" / "最小クライアント" など）
    this._goodRung = null;       // 前回繋がった方式（再接続で先頭にする）
    this.lastProbe = null;
    this.retryTimer = null;
    this.nextRetryAt = 0;
    this._stableTimer = null;
    this.connectedAt = 0;
    this._connectStartedAt = 0;  // 接続処理の開始時刻（処理中だけ非 0）
    this._queued = false;        // 接続キューで順番待ち
    this._noticeKey = "";        // 同じ失敗の連続で通知を重ねないための印
    this._toolsRun = null;
    this._toolsRerun = false;
    this._wake = null;
    this._degradedKicks = 0;     // degraded のまま接続ごと張り直した回数（tools/list が取れたら 0 に戻す）
    this.closed = false;
    this.started = false;        // 一度でも接続を試みたか（connectAll は未開始のものだけ始める）
    this._connecting = null;
    this._redact = (t) => String(t);
    this._cfg = null;
    try {
      this._configure();
      if (this.lazy && this.state !== "disabled") this.state = "deferred";
    } catch (e) {
      this.state = "error"; this.error = e.message; this.errorKind = "config"; this.nextAction = nextActionFor("config", e.message);
      pushNotice(this.name, "config", e.message, this.nextAction); this._noticeKey = "config|" + e.message;
    }
  }

  _configure() {
    const c = compileSpec(this.spec);
    this.type = c.type; this._cfg = c.cfg; this._redact = c.redact;
    if (c.disabled) this.state = "disabled";
  }

  _label() {
    return this.type === "stdio" ? this._cfg.command + (this._cfg.args.length ? " " + this._cfg.args.join(" ") : "")
      : this._cfg.url.replace(/([?&][^=&]*(?:key|token|secret|auth|pass|sig)[^=&]*=)[^&]+/gi, "$1***").replace(/\/\/[^/@]*@/, "//***@");
  }

  /** 試行の履歴へ 1 行足す（通算の試行番号と時刻つき）。後から ok / ms / note を書き換えられるよう、行そのものを返す。 */
  _pushAttempt(row) {
    const r = Object.assign({ attempt: this._attemptCount, at: new Date().toISOString() }, row);
    this.attempts.push(r);
    if (this.attempts.length > 30) this.attempts.splice(0, this.attempts.length - 30);
    return r;
  }

  /** 接続する。成功（= client.connect() の成功）で state=connected。tools/list は後ろでバックグラウンド取得する。同時呼び出しは 1 つにまとめる。 */
  connect() {
    if (this.state === "disabled" || !this._cfg || this.closed) return Promise.resolve(false);
    if (this._connecting) return this._connecting;
    this._connecting = this._doConnect().finally(() => { this._connecting = null; });
    return this._connecting;
  }

  _newClient(neg) {
    return new Client(
      { name: "lumen-core", version: VERSION },
      {
        capabilities: {},   // sampling / elicitation / roots は宣言しない（サーバーはクライアントへ要求しない）
        versionNegotiation: neg,
        listChanged: { tools: { onChanged: () => { this._startToolsLoad().catch(() => {}); } } },
      }
    );
  }

  _hookClient(client) {
    client.onclose = () => { if (this.client === client && !this.closed && (this.state === "connected" || this.state === "degraded")) this._fail(new Error("接続が切断されました。")); };
    client.onerror = (e) => { logger(this.name + ": " + this._redact((e && e.message) || e)); };
  }

  /**
   * client.connect() 成功の直後に呼ぶ。交渉結果を控えて state=connected にし、tools/list の取得を始める（待たない）。
   * ここで tools/list を待たない・失敗を投げないので、「接続→数秒後にエラー」にならない。route はリモートで繋がった方式の名前。
   */
  _loadAfterConnect(client, route) {
    try {
      this.era = client.getProtocolEra() || null;
      this.protocolVersion = client.getNegotiatedProtocolVersion() || null;
      this.serverInfo = client.getServerVersion() || null;
      this.instructions = client.getInstructions() || null;
    } catch (_) { /* 取れない項目は空のまま */ }
    if (route) this.route = route;
    this._markConnected();
    this._startToolsLoad().catch(() => {});
  }

  _markConnected() {
    this.state = "connected"; this.error = null; this.errorKind = null; this.nextAction = null; this.connectedAt = Date.now();
    this.toolsStatus = this.toolsStatus || "loading"; this.toolsError = null;
    clearTimeout(this._stableTimer);
    // すぐ落ちるサーバーで 1 秒間隔の再接続や通知の連発にならないよう、安定して繋がっていると分かってから戻す
    this._stableTimer = setTimeout(() => {
      if (this.state === "connected" || this.state === "degraded") { this.attempt = 0; this._noticeKey = ""; }
    }, STABLE_MS);
    this._stableTimer.unref();
    logger(this.name + ": 接続（" + this.era + " / " + this.protocolVersion + (this.route ? " / " + this.route : "") + "）— ツール一覧を取得します");
    bump();
  }

  async _doConnect(keepLog) {
    clearTimeout(this.retryTimer); this.nextRetryAt = 0;
    clearTimeout(this._stableTimer);
    this.started = true;
    await this._teardownSafe();
    this._attemptCount++;
    this._connectStartedAt = Date.now();
    this.state = "connecting"; this.error = null; this.errorKind = null; this.nextAction = null;
    this.tools = []; this.skipped = 0; this.toolsStatus = null; this.toolsError = null; this.route = null;
    if (!keepLog) this.attempts = [];
    bump();
    try { return this.type !== "stdio" ? await this._connectRemote() : await this._connectStdio(); }
    finally { this._connectStartedAt = 0; }
  }

  async _connectStdio() {
    const c = this._cfg;
    const neg = mcpLaunch.negotiationFor({ proto: c.proto, protoImplicit: c.protoImplicit, runner: c.runner, type: this.type }, this.protoStep);
    this._negLabel = typeof neg.mode === "string" ? neg.mode : neg.mode.mode || (neg.mode.pin ? "pin" : "auto");
    const client = this._newClient(neg);
    const t0 = Date.now();
    let transport, row = null;
    this.stderrTail = "";   // 前回の試行の stderr を今回の失敗理由に混ぜない
    try {
      const route = mcpLaunch.plan(c, this.attempt);   // attempt = 起動ルートの切替だけ（プロトコル世代の再試行は protoStep）
      this._launch = route.diag || null;
      row = this._pushAttempt({ step: "起動「" + route.label + "」/ 世代交渉 " + this._negLabel, ok: false, pending: true });
      logger(this.name + ": 起動ルート「" + route.label + "」 " + (route.note || route.command) + " / 世代交渉 " + this._negLabel + (this.protoStep ? "（legacy が世代不一致のため auto）" : "") + " / env " + ((route.diag && route.diag.envMode) || "?"));
      transport = new StdioClientTransport({ command: route.command, args: route.args, env: route.env, cwd: c.cwd, stderr: "pipe" });
      if (transport.stderr) {
        let shown = 0;   // 接続の失敗理由が見えるよう、最初の 20 行だけコンソールにも出す
        transport.stderr.on("data", (d) => {
          const t = String(d);
          this.stderrTail = (this.stderrTail + t).slice(-STDERR_TAIL);
          t.split(/\r?\n/).filter(Boolean).forEach((ln) => { if (shown < 20) { shown++; logger(this.name + " [stderr] " + this._redact(ln).slice(0, 240)); } });
        });
      }
      this._hookClient(client);
      this.client = client; this.transport = transport;
      await client.connect(transport, { timeout: c.timeoutMs });
      row.ok = true; row.pending = false; row.ms = Date.now() - t0;
      this._autoTrial = false;   // auto で繋がったなら protoStep=1 のまま（再接続でもまた legacy で落ちて auto へ戻る無駄をしない）
      this._loadAfterConnect(client);
      return true;
    } catch (e) {
      if (row) { row.ok = false; row.pending = false; row.ms = Date.now() - t0; row.note = this._redact(this._describe(e).text).split("\n")[0].slice(0, 300); }
      // legacy がプロトコル世代の不一致で落ちたときだけ、同じ起動ルートのまま次の 1 回を auto にする。
      // ENOENT・引数不正・タイムアウト・認証失敗では切り替えない（原因が世代ではないので auto にしても直らない）。
      if (!this.closed && !closing && this._canFallbackToAuto(e)) {
        this.protoStep = 1; this._autoTrial = true;
        logger(this.name + ": legacy がプロトコル世代の不一致で終了したため、次の 1 回を auto で接続します。");
        await this._teardownSafe();
        return this._doConnect(true);
      }
      if (this._autoTrial) { this._autoTrial = false; this.protoStep = 0; }   // auto でも駄目だった: 次の再試行は legacy から
      this._fail(e);
      return false;
    }
  }

  /** SDK で HTTP / 旧 SSE へ 1 回接続する（kind: "http" | "sse"）。成功で this.client が有効になる（state の更新と tools/list は呼び出し側）。失敗は例外。 */
  async _sdkRemote(kind, neg, timeoutMs) {
    const c = this._cfg;
    const hdrs = Object.assign({}, c.headers);
    if (c.bearer && !Object.keys(hdrs).some((k) => k.toLowerCase() === "authorization")) hdrs.Authorization = "Bearer " + c.bearer;   // 静的ヘッダーで確実に送る
    const client = this._newClient(neg);
    // 既定の fetch（undici）は、ヘッダー・本文のどちらも 5 分間何も届かないと切る。進捗を出さない長い tools/call や、通知の無い待機中のストリームが
    // 5 分ちょうどで「connection closed」になっていた。その上限だけを外した longFetch（mcpHttp.js）を、SDK の全リクエストに使う。
    const sendFetch = (url, init) => {
      const h = new Headers((init && init.headers) || {});
      Object.keys(hdrs).forEach((k) => h.set(k, hdrs[k]));   // 設定のヘッダーを全リクエストへ確実に付ける（従来の eventSourceInit.fetch と同じ）
      return mcpHttp.longFetch(url, Object.assign({}, init, { headers: h }));
    };
    let transport;
    if (kind === "sse") {
      transport = new SSEClientTransport(new URL(c.url), {
        requestInit: { headers: hdrs },   // メッセージ送信（POST）用
        eventSourceInit: { fetch: sendFetch },   // ストリーム開始（GET）用
        fetch: sendFetch,
      });
    } else {
      transport = new StreamableHTTPClientTransport(new URL(c.url), { requestInit: { headers: hdrs }, fetch: sendFetch });
    }
    this._hookClient(client);
    this.client = client; this.transport = transport;
    await client.connect(transport, { timeout: timeoutMs });
  }

  /** SDK がどの世代でも繋げなかったときの最後の手段。 */
  async _rawRemote(timeoutMs) {
    const c = this._cfg;
    const client = new mcpHttp.RawHttpClient({ url: c.url, headers: c.headers, bearer: c.bearer, clientInfo: { name: "lumen-core", version: VERSION } });
    this.client = client; this.transport = null;
    await client.connect(null, { timeout: timeoutMs });
  }

  /**
   * HTTP / 旧 SSE の接続。
   *   1. 素の fetch で診断。認証が要る（資格情報なし）・MCP の応答ではない → 原因をそのまま出して止める（SDK を回しても同じ失敗になるため）。
   *      到達できない（network）・HTTP エラーは一過性のこともあるので止めず、全方式（legacy → auto → 最小クライアント）を試す。
   *      資格情報があるのに 401/403 → 診断の拒否と SDK 側の判定を区別するため、SDK を 1 回だけ試す。
   *   2. 診断結果に合わせた順で、繋がるまで試す。旧 SSE と分かれば SSE transport。
   *   3. 全滅したら、診断結果と各方式の失敗理由を 1 つのエラーにまとめる。
   */
  async _connectRemote() {
    const c = this._cfg;
    const hasCred = !!(c.bearer || Object.keys(c.headers).some((k) => /auth|key|token/i.test(k)));
    const pr = await mcpHttp.probe(c.url, { headers: c.headers, bearer: c.bearer, timeoutMs: Math.min(c.timeoutMs, 20000), version: VERSION });
    this.lastProbe = pr;
    if (this.closed || closing) return false;
    const pnote = this._probeNote(pr);
    this._pushAttempt({ step: "診断", ok: pr.kind === "ok" || pr.kind === "sse" || pr.kind === "mcp-error", ms: pr.elapsedMs, note: pnote });
    const pf = mcpHttp.probeFailure(pr, { hasCredentials: hasCred });
    if (pr.kind === "not-mcp") { this._fail(pf); return false; }   // 2xx なのに MCP の応答ではない: URL が違う
    const authOnce = pr.kind === "auth";
    if (authOnce && !hasCred) { this._fail(pf); return false; }
    const soft = pr.kind === "network" || pr.kind === "http-error";   // 一過性かもしれない失敗: 全方式を試す

    const explicit = !c.protoImplicit;
    const rungs = [];
    const sdk = (label, kind, neg) => rungs.push({ label, run: (ms) => this._sdkRemote(kind, neg, ms) });
    const raw = () => rungs.push({ label: "最小クライアント", run: (ms) => this._rawRemote(ms) });
    if (this.type === "sse" || pr.kind === "sse") {
      sdk("SSE(旧)", "sse", { mode: "legacy" });
    } else if (explicit) {
      const neg = mcpLaunch.negotiationFor({ proto: c.proto, protoImplicit: false, runner: null, type: "http" }, 0);
      sdk("指定 protocol=" + c.proto, "http", neg);
      if (c.proto === "legacy" && (pr.initOk || soft)) raw();
    } else {
      const legacy = ["legacy", "http", { mode: "legacy" }], auto = ["auto", "http", { mode: "auto" }];
      (pr.kind === "mcp-error" ? [auto, legacy] : [legacy, auto]).forEach((r) => sdk(r[0], r[1], r[2]));
      if (pr.initOk || soft) raw();
    }
    const good = rungs.findIndex((r) => r.label === this._goodRung);
    if (good > 0) rungs.unshift(rungs.splice(good, 1)[0]);   // 前回繋がった方式を先に
    if (authOnce) rungs.length = Math.min(rungs.length, 1);

    let per = rungs.length > 1 ? Math.min(c.timeoutMs, 45000) : c.timeoutMs;
    if (pr.kind === "network") per = Math.min(per, 15000);   // 到達できなかった相手に、方式ごとに長く待たない
    if (authOnce) per = Math.min(per, 20000);
    for (const r of rungs) {
      if (this.closed || closing) return false;
      const t0 = Date.now();
      this._negLabel = r.label;
      try {
        await r.run(per);
        this._pushAttempt({ step: r.label, ok: true, ms: Date.now() - t0 });
        this._goodRung = r.label;
        this._loadAfterConnect(this.client, r.label);
        return true;
      } catch (e) {
        await this._teardownSafe();
        if (this.closed || closing) return false;
        const d = this._describe(e);
        this._pushAttempt({ step: r.label, ok: false, ms: Date.now() - t0, note: this._redact(d.text).split("\n")[0].slice(0, 300) });
        logger(this.name + ": 方式「" + r.label + "」で接続できません — " + this._redact(d.text).split("\n")[0].slice(0, 200));
        if (d.auth) { this._fail(authOnce && pf ? pf : e); return false; }
      }
    }
    if (authOnce && pf) { this._fail(pf); return false; }
    const lines = ["接続できませんでした — " + pnote]
      .concat(this.attempts.filter((x) => x.step !== "診断" && x.attempt === this._attemptCount).map((x) => "・" + x.step + ": " + (x.note || "失敗")));
    if ((soft || pr.kind === "not-mcp") && pf) lines.push(pf.message);
    let kind = "protocol";
    if (pr.kind === "network") kind = pr.causeCode === "ETIMEDOUT" ? "timeout" : "transport";
    else if (pr.kind === "http-error") kind = pr.status === 429 || pr.status >= 500 ? "transport" : pr.status === 404 || pr.status === 405 || pr.status === 410 ? "config" : "protocol";
    this._fail(new mcpHttp.ProbeError(lines.join("\n"), { kind: "connect", errorKind: kind, causeCode: pr.causeCode || "", status: pr.status }));
    return false;
  }

  /** probe の結果の 1 行（画面・ログ用。秘密は含まれない）。 */
  _probeNote(pr) {
    const lab = { ok: "initialize 成功", "mcp-error": "MCP エラー応答", auth: "認証が必要", network: "到達できません", "http-error": "HTTP エラー", "not-mcp": "MCP の応答ではない", sse: "旧 HTTP+SSE" }[pr.kind] || pr.kind;
    const bits = [lab];
    if (pr.status) bits.push("HTTP " + pr.status);
    if (pr.protocolVersion) bits.push("サーバー版 " + pr.protocolVersion);
    if (pr.kind === "network" && pr.network) bits.push(pr.network);
    else if (pr.note && pr.kind !== "sse") bits.push(pr.note);
    return this._redact(bits.join(" / ")).slice(0, 500) + "（" + pr.elapsedMs + "ms）";
  }

  /**
   * プロトコル世代の不一致らしい失敗か。mcpLaunch.isProtocolMismatch（文面の厳しい判定）に加えて、次のいずれかでも真:
   *   ・SDK のエラーで code / message に protocol・version・capabilit を含む
   *   ・HTTP 400 で message に version・protocol・era を含む
   *   ・接続を始めて 30 秒以内にプロセスが閉じ、stderr 末尾に protocol・unsupported・version を含む
   */
  _isLikelyProtocolMismatch(e) {
    if (!e) return false;
    if (e instanceof mcpLaunch.LaunchArgError) return false;
    const msg = String(e.message || "");
    if (e instanceof SdkError && /protocol|version|capabilit/i.test(String(e.code || "") + " " + msg) && !isTimeoutErr(e)) return true;
    if (Number(e.httpStatus || e.status || e.statusCode) === 400 && /version|protocol|\bera\b/i.test(msg)) return true;
    if (this.type === "stdio" && isClosedErr(e) && this._connectStartedAt && Date.now() - this._connectStartedAt < 30000 && /protocol|unsupported|version/i.test(this.stderrTail.slice(-1000))) return true;
    return !!mcpLaunch.isProtocolMismatch(e);
  }

  /** protocol 省略のパッケージランナーを legacy で接続して、世代の不一致で失敗したか。 */
  _canFallbackToAuto(e) {
    return this.type === "stdio" && this.protoStep === 0 && mcpLaunch.usesLegacyFirst(Object.assign({ type: this.type }, this._cfg)) && this._isLikelyProtocolMismatch(e);
  }

  /** 起動コマンドが見つからないときの 1 行（どこの PATH に無いのか・何をすればよいのか）。spawnFailed: spawn 自体が ENOENT だった。 */
  _missingText(spawnFailed, diag) {
    const dg = diag || this._launch || {};
    const cmd = this._cfg.command;
    // cmd.exe 経由（Windows のシム分解）で spawn が ENOENT なら、見つからないのは npx ではなく cmd.exe 側
    if (spawnFailed && dg.viaCmd) return "Windows のコマンドプロンプト（cmd.exe。ComSpec 環境変数）が見つかりません。ComSpec が実在する cmd.exe を指しているか確認してください。";
    if (dg.runner === "uvx") {
      return "起動コマンド「" + cmd + "」が見つかりません。実行コアを起動したプロセスの PATH に uvx がありません（対話シェルで uvx が動くことと、実行コアから見えることは別です。既知の uv の場所も探しました）。"
        + "uv を導入するか PATH へ追加し、実行コアを再起動してください。";
    }
    if (dg.runner) {
      const nd = dg.nodeDir ? "（" + dg.nodeDir + "）" : "";
      return "起動コマンド「" + dg.runner + "」が見つかりません。実行コア自身の Node のフォルダ" + nd + "を子の PATH の先頭へ足して起動しましたが、それでも見つかりませんでした。"
        + "Node.js（npm 同梱）の導入が必要です。導入後は実行コアを再起動してください。";
    }
    return "起動コマンド「" + cmd + "」が見つかりません（PATH を確認してください）。";
  }

  _describe(e) {
    if (e instanceof mcpHttp.ProbeError) return { auth: !!e.auth, fatal: !!e.fatal, text: e.message };   // 診断で原因が分かっているもの（文言はそのまま出す）
    const httpStatus = Number(e && (e.httpStatus || e.status || e.statusCode));
    if (e instanceof UnauthorizedError || (e && (e.name === "UnauthorizedError" || e.code === "CLIENT_HTTP_AUTHENTICATION")) || (this.type !== "stdio" && httpStatus === 401)) return { auth: true, text: "認証が必要です（401）。headers / bearerToken を設定してください（OAuth の対話認可は未対応）。" };
    let text = (e && e.message) || String(e);
    const dg = this._launch || {};
    const atConnect = !!this._connectStartedAt;   // 接続処理中の失敗だけ書き換える（callTool 中のタイムアウトや切断を「initialize 失敗」と言わない）
    const isLaunchArg = e instanceof mcpLaunch.LaunchArgError;
    const isTimeout = isTimeoutErr(e);
    const isClosed = isClosedErr(e);
    if (isLaunchArg) { /* 引数不正はそのまま（値は文言に含めない） */ }
    else if (e && e.code === "ENOENT" && this.type === "stdio") text = this._missingText(true);
    else if (this.type === "stdio" && atConnect && isTimeout) {
      const sec = Math.round(this._cfg.timeoutMs / 1000);
      if (this._negLabel === "auto") text = "接続の待ち時間（" + sec + " 秒）に達しました。世代交渉が auto のため server/discover のプローブ待ち、または初回のパッケージ取得の待ちです（サーバー自身の initialize 失敗とは限りません）。";
      else text = "initialize が " + sec + " 秒以内に完了しませんでした（世代交渉 " + this._negLabel + "。プローブは使っていません）。初回のパッケージ取得中、またはサーバー側が initialize を返せていません。";
    } else if (this.type === "stdio" && atConnect && isClosed) {
      text = "MCP サーバーのプロセスが initialize を終える前に終了しました（起動コマンド・引数・依存の取得の失敗の可能性）。";
    }
    // シム分解後も npx が子の PATH に無かった / uvx が見つからないことが分かっているなら、終了の理由としてまず示す
    if (this.type === "stdio" && atConnect && !isLaunchArg && dg.runnerFound === false && !(e && e.code === "ENOENT")) text = this._missingText() + "\n" + text;
    // リモートの「fetch failed」は、原因（DNS・証明書・プロキシ・接続拒否など）が cause に入っている。そこまでたどって示す。
    if (this.type !== "stdio" && e && !isTimeout && (e.cause || /^fetch failed$/i.test(String(e.message || "")))) text = mcpHttp.explainNetworkError(e);
    if (e instanceof SdkError || (e && e.name === "SdkError")) text = "[" + (e.code || "SdkError") + "] " + text;
    if (this.type === "http" && atConnect && /\b(404|405)\b/.test(String(e && e.status) + " " + text)) text += '\n旧 HTTP+SSE のサーバーの可能性があります。種類を SSE（type: "sse"）にして再接続してください。';
    const tail = this.stderrTail.trim();
    if (tail && this.type === "stdio") text += "\nstderr（末尾）: " + tail.slice(-500);
    return { auth: false, fatal: isLaunchArg, text };
  }

  /** 失敗の種類。spawn / protocol / auth / timeout / transport / tools / config / exit。 */
  _classify(e, d) {
    if (d.auth) return "auth";
    if (e && KINDS.includes(e.errorKind)) return e.errorKind;
    if (e instanceof mcpHttp.ProbeError) {
      if (e.kind === "network") return e.causeCode === "ETIMEDOUT" ? "timeout" : "transport";
      if (e.kind === "not-mcp") return "config";
      if (e.kind === "http") return e.status === 429 || e.status >= 500 ? "transport" : e.status === 404 || e.status === 405 || e.status === 410 ? "config" : "protocol";
      return "protocol";
    }
    if (e instanceof mcpLaunch.LaunchArgError) return "config";
    const stdio = this.type === "stdio";
    if (stdio && e && /^(ENOENT|EACCES|EPERM|EINVAL)$/.test(String(e.code || ""))) return "spawn";
    if (stdio && this._launch && this._launch.runnerFound === false) return "spawn";   // npx / uvx が子の PATH に無い
    if (this._isLikelyProtocolMismatch(e)) return "protocol";
    if (isTimeoutErr(e)) return "timeout";
    return stdio ? "exit" : "transport";
  }

  _fail(e) {
    if (this.closed || closing) return;
    const d = this._describe(e);
    const kind = this._classify(e, d);
    const first = this._redact(d.text).split("\n")[0].slice(0, 300);
    clearTimeout(this._stableTimer);
    this.state = d.auth ? "auth_required" : "error";
    this.error = this._redact(d.text).slice(0, 800);
    this.errorKind = kind;
    this.nextAction = nextActionFor(kind, d.text);
    this.tools = []; this.skipped = 0; this.toolsStatus = null; this.toolsError = null;
    logger(this.name + ": " + this.state + " [" + kind + "] — " + first);
    const key = kind + "|" + first;
    if (this._noticeKey !== key) { this._noticeKey = key; pushNotice(this.name, kind, first, this.nextAction); }   // 同じ失敗が続く間は 1 回だけ
    bump();
    const retry = !d.auth && !d.fatal;
    // teardown（最大 3 秒）が終わってから再試行を予約する。client.close() が戻らなくても進める
    this._teardownSafe().then(() => { if (retry && !this.closed && !closing && this.state === "error") this._scheduleRetry(); });
  }

  /** 全体の同期が CONNECT_GLOBAL_TIMEOUT_MS を超えたとき。接続処理は止めず（プロセスは落とさない）、表示だけ timed_out にする。 */
  _markTimedOut() {
    if (this.state !== "connecting") return;
    const sec = Math.round(CONNECT_GLOBAL_TIMEOUT_MS / 1000);
    this.state = "timed_out"; this.errorKind = "timeout";
    this.error = this._queued
      ? "全体の接続待ち（" + sec + " 秒）を超えました。接続の順番がまだ回ってきていません（npx / uvx は同時 " + RUNNER_CONCURRENCY + " 本まで）。順番が来れば自動で接続します。"
      : "全体の接続待ち（" + sec + " 秒）を超えました。接続処理は続けています（初回のパッケージ取得に時間がかかっている可能性があります）。完了または失敗すれば自動で更新され、失敗時は再試行します。";
    this.nextAction = nextActionFor("timeout", "");
    this._pushAttempt({ step: "全体タイムアウト", ok: false, ms: this._connectStartedAt ? Date.now() - this._connectStartedAt : undefined, note: this.error.slice(0, 200) });
    logger(this.name + ": timed_out [timeout] — " + this.error.split("。")[0]);
    pushNotice(this.name, "timeout", this.error.split("。")[0], this.nextAction);
    bump();
  }

  _scheduleRetry() {
    clearTimeout(this.retryTimer);
    if (this.closed || closing) return;
    const wait = Math.min(RETRY_MAX_MS, RETRY_MIN_MS * Math.pow(2, this.attempt++));
    this.nextRetryAt = Date.now() + wait;
    this.retryTimer = setTimeout(() => {
      this.nextRetryAt = 0;
      if (this.closed || closing) return;
      if (this.state === "connected" || this.state === "degraded" || this.state === "disabled" || this.state === "auth_required") return;
      if (this._connecting || this._queued) return;   // すでに接続中・順番待ち（全体タイムアウト後の再試行を二重に始めない）
      enqueue(this, true).catch(() => {});
    }, wait);
    this.retryTimer.unref();
  }

  async _teardown() {
    const client = this.client;
    this.client = null; this.transport = null; this._toolsRun = null; this._toolsRerun = false;
    if (this._wake) this._wake();   // 待っている tools/list のループを終わらせる（client が変わっているので何もせず抜ける）
    if (client) { client.onclose = undefined; try { await client.close(); } catch (_) { /* 既に閉じている */ } }
  }

  /** _teardown を最大 TEARDOWN_TIMEOUT_MS で打ち切る（client.close() がハングしても先へ進む）。打ち切ったら子プロセスを木ごと落とす。 */
  async _teardownSafe() {
    const pid = this.transport && this.transport.pid;
    let timer;
    const limit = new Promise((resolve) => { timer = setTimeout(() => resolve("timeout"), TEARDOWN_TIMEOUT_MS); timer.unref(); });
    const r = await Promise.race([this._teardown().then(() => "ok", () => "ok"), limit]);
    clearTimeout(timer);
    if (r === "timeout") {
      logger(this.name + ": 切断が " + Math.round(TEARDOWN_TIMEOUT_MS / 1000) + " 秒以内に終わらないため、プロセスを強制終了します。");
      if (pid) mcpLaunch.killTree(pid);
    }
  }

  /**
   * tools/list をバックグラウンドで取得する。同時に 1 本だけ（重複した要求は終わってからもう 1 回）。
   *   失敗しても state は connected のまま toolsStatus="error" / toolsError に記録し、1s / 5s / 15s で再試行。3 回続けて失敗したら state="degraded"（接続は生かす）、
   *   その後も 30 秒おきに再取得して、取れたら connected へ戻す。取得済みの一覧があるとき（listChanged の更新）は、一覧を保ったまま短く再試行するだけ。
   */
  _startToolsLoad() {
    const client = this.client;
    if (!client || this.closed || closing) return Promise.resolve(false);
    if (this._toolsRun) {
      if (this._wake) this._wake();   // 再試行の待ち時間中なら、待たずにすぐ取り直す（「再接続」や listChanged のとき）
      else this._toolsRerun = true;
      return this._toolsRun;
    }
    const keep = this.toolsStatus === "ok";
    if (!keep) { this.toolsStatus = "loading"; this.toolsError = null; bump(); }
    const run = this._toolsLoop(client, keep).catch(() => false);
    this._toolsRun = run;
    run.then(() => {
      if (this._toolsRun === run) this._toolsRun = null;
      if (this._toolsRerun) { this._toolsRerun = false; this._startToolsLoad().catch(() => {}); }
    });
    return run;
  }

  /** 起こせる待ち（_wake を呼ぶとすぐ戻る）。 */
  _wait(ms) {
    return new Promise((resolve) => {
      let t;
      const done = () => { clearTimeout(t); if (this._wake === done) this._wake = null; resolve(); };
      t = setTimeout(done, ms); t.unref();
      this._wake = done;
    });
  }

  async _toolsLoop(client, keep) {
    const stale = () => this.client !== client || this.closed || closing;
    for (let i = 0; ; i++) {
      const t0 = Date.now();
      try {
        const n = await this._fetchTools(client);
        if (stale()) return false;
        const wasDegraded = this.state === "degraded";
        this.toolsStatus = "ok"; this.toolsError = null; this._degradedKicks = 0;
        if (wasDegraded) { this.state = "connected"; this.error = null; this.errorKind = null; this.nextAction = null; }
        if (i > 0 || wasDegraded) this._pushAttempt({ step: "tools/list", ok: true, ms: Date.now() - t0, note: n + " 件" });
        logger(this.name + ": ツール " + n + " 件を取得" + (wasDegraded ? "（degraded から復帰）" : "") + (this.skipped ? "（登録不可 " + this.skipped + " 件）" : ""));
        bump();
        return true;
      } catch (e) {
        if (stale()) return false;
        const d = this._describe(e);
        if (d.auth) { this._fail(e); return false; }
        // 通信路が死んでいる（接続断・HTTP セッション切れ）なら、tools/list を同じ接続で繰り返しても戻らない。以前はここで degraded のまま固定されていた。
        // error にして、再接続（_scheduleRetry）へ回す。
        if (isDeadTransportErr(e)) { logger(this.name + ": tools/list の取得で通信路が使えないと分かったため、接続を張り直します。"); this._fail(e); return false; }
        const first = this._redact(d.text).split("\n")[0].slice(0, 300);
        this.toolsError = this._redact(d.text).slice(0, 400);
        this._pushAttempt({ step: "tools/list", ok: false, ms: Date.now() - t0, note: first });
        logger(this.name + ": tools/list の取得に失敗（" + (i + 1) + " 回目）— " + first);
        if (keep) {
          if (i >= TOOLS_RETRY_DELAYS.length) return false;   // 取得済みの一覧はそのまま使い続ける
        } else {
          this.toolsStatus = "error";
          if (i >= TOOLS_RETRY_DELAYS.length && this.state === "connected") {
            this.state = "degraded"; this.errorKind = "tools"; this.nextAction = nextActionFor("tools", d.text);
            this.error = "tools/list を " + (i + 1) + " 回続けて取得できませんでした（接続自体は維持しています）: " + first;
            logger(this.name + ": degraded [tools] — サーバーは接続したまま、ツール一覧の取得を " + Math.round(TOOLS_SLOW_RETRY_MS / 1000) + " 秒おきに続けます。");
            pushNotice(this.name, "tools", first, this.nextAction);
          }
          bump();
        }
        // degraded のまま低頻度の再取得を続けても戻らない: サーバー側のセッションが壊れている可能性があるので、接続ごと張り直す（最大 DEGRADED_KICK_MAX 回）
        if (!keep && this.state === "degraded" && i >= TOOLS_RETRY_DELAYS.length + DEGRADED_KICK_AFTER - 1 && this._degradedKicks < DEGRADED_KICK_MAX) {
          this._degradedKicks++;
          const kick = new Error("tools/list を取得できない状態が続いたため、接続を張り直します（" + this._degradedKicks + "/" + DEGRADED_KICK_MAX + " 回目）: " + first);
          kick.errorKind = "tools";
          this._fail(kick);
          return false;
        }
        await this._wait(i < TOOLS_RETRY_DELAYS.length ? TOOLS_RETRY_DELAYS[i] : TOOLS_SLOW_RETRY_MS);
        if (stale()) return false;
      }
    }
  }

  /** tools/list を 1 回取得して this.tools へ反映する。失敗は例外（呼び出し側が再試行を決める）。取得した件数を返す。 */
  async _fetchTools(client) {
    const raw = await client.listTools();   // ページングは SDK が集約する
    const tools = [];
    const taken = new Set();   // 他サーバーが公開中の名前も含める（サーバー間の公開名衝突を防ぐ）
    upstreams.forEach((u) => { if (u !== this) u.tools.forEach((x) => taken.add(x.name)); });
    let skipped = 0;
    for (const t of raw.tools || []) {
      const ok = t && typeof t.name === "string" && t.name && t.inputSchema && typeof t.inputSchema === "object" && !Array.isArray(t.inputSchema);
      if (!ok) { skipped++; continue; }
      const full = sanitizeToolName(this.name, t.name, taken);
      taken.add(full);
      tools.push({
        name: full, server: this.name, upstreamName: t.name,
        title: typeof t.title === "string" ? t.title : undefined,
        description: typeof t.description === "string" ? t.description : "",
        inputSchema: t.inputSchema,
        outputSchema: t.outputSchema && typeof t.outputSchema === "object" ? t.outputSchema : undefined,
        annotations: t.annotations && typeof t.annotations === "object" ? t.annotations : undefined,
      });
    }
    if (this.client !== client) return tools.length;   // 取得中に切断・再接続された: 古い結果は捨てる
    this.tools = tools; this.skipped = skipped;
    tools.forEach((x) => toolOwners.set(x.name, { server: x.server, upstreamName: x.upstreamName }));
    bump();
    return tools.length;
  }

  async callTool(upstreamName, args, opts) {
    if (this.state !== "connected" || !this.client) {
      const err = new Error("サーバー「" + this.name + "」は " + this.state + " です" + (this.error ? ": " + this.error.split("\n")[0] : "") + "。");
      err.hubCode = "NOT_CONNECTED";
      throw err;
    }
    try {
      return await this.client.callTool({ name: upstreamName, arguments: args || {} }, { signal: opts && opts.signal, timeout: (opts && opts.timeoutMs) || CALL_TIMEOUT_MS, resetTimeoutOnProgress: true });
    } catch (e) {
      if (e && e.name === "AbortError") throw e;
      const d = this._describe(e);
      const msg = this._redact(d.text);
      // 接続断・認証失敗・HTTP セッション切れは state に反映する（ツールの業務エラーは isError 結果として上流から返るのでここへは来ない）。
      // 以前は 404（セッション切れ）を見逃し、state が connected のまま以降の呼び出しも同じ 404 で失敗し続けた。
      const lost = this.type !== "stdio" && policy.isSessionLost(e);
      if (d.auth || lost || isDeadTransportErr(e)) this._fail(e);
      const err = new Error(msg);
      // セッション切れはサーバーで処理されていない要求なので、NOT_CONNECTED（= 送る前に断った）として返す。呼び出し側は繋ぎ直して 1 回やり直してよい。
      err.hubCode = d.auth ? "AUTH" : lost ? "NOT_CONNECTED" : isTimeoutErr(e) ? "CALL_TIMEOUT" : "CALL_FAILED";
      throw err;
    }
  }

  summary() {
    const kind = this.errorKind || (this.toolsStatus === "error" ? "tools" : null);
    const connecting = this.state === "connecting" && this._connectStartedAt;
    return {
      name: this.name, type: this.type, state: this.state, error: this.error,
      lazy: this.lazy, capabilities: (this.capability && Array.isArray(this.capability.capabilities) ? this.capability.capabilities : []).slice(0, 16),
      capabilityDescription: String((this.capability && this.capability.description) || "").slice(0, 240),
      errorKind: kind,
      nextAction: kind ? (this.nextAction || nextActionFor(kind, this.toolsError)) : null,
      toolsStatus: this.toolsStatus, toolsError: this.toolsError ? this._redact(this.toolsError) : null,
      connectingSince: connecting ? Date.now() - this._connectStartedAt : null,
      queued: !!this._queued,
      nextRetryAt: this.nextRetryAt || null,
      era: this.era, protocolVersion: this.protocolVersion,
      serverInfo: this.serverInfo ? { name: this.serverInfo.name, version: this.serverInfo.version } : null,
      toolCount: this.tools.length, skipped: this.skipped,
      target: this.type ? this._redact(this._cfg ? this._label() : "") : "",
      connectedAt: this.connectedAt || null,
      disabled: this.state === "disabled",
      route: this.route,
      attempts: this.attempts.slice(-8).map((a) => ({ step: a.step, ok: !!a.ok, pending: a.pending ? true : undefined, ms: a.ms, note: a.note ? this._redact(a.note) : undefined, attempt: a.attempt, at: a.at })),
      spec: displaySpec(this.spec),
      configFingerprint: specFingerprint(this.spec),
    };
  }

  async close() {
    this.closed = true;
    clearTimeout(this.retryTimer); clearTimeout(this._stableTimer);
    await this._teardownSafe();
  }
}

/* ------------------------------------------------------------
   公開 API
   ------------------------------------------------------------ */

function loadConfig() {
  const cfg = readConfigFile();
  const servers = cfg.servers || {};
  configError = cfg.errors && cfg.errors.length ? { message: cfg.errors.join("\n"), kind: cfg.errorKind || "schema" } : null;
  const normalizedCaps = mcpCapabilities.normalizeManifest(cfg.lumenCapabilities, Object.keys(servers));
  capabilityManifest = normalizedCaps.manifest;
  capabilityWarnings = normalizedCaps.warnings;
  const next = new Map();
  Object.keys(servers).forEach((name) => {
    const old = upstreams.get(name);
    const meta = capabilityManifest[name] || { lazy: false, capabilities: [], description: "", source: "default-eager" };
    if (old && !old.closed && old.specKey === JSON.stringify(servers[name])) {
      old.capability = meta;
      old.lazy = meta.lazy === true;
      // If only manifest metadata changed before this upstream had ever started, apply the new default.
      // Never interrupt an already connected server solely because its discoverability metadata changed.
      if (!old.started && old.state !== "disabled" && old.state !== "error") old.state = old.lazy ? "deferred" : "connecting";
      next.set(name, old);
      return;
    }
    next.set(name, new Upstream(name, servers[name], meta));
  });
  // 定義が消えた・変わった上流は閉じる
  upstreams.forEach((u, name) => { if (next.get(name) !== u) u.close().catch(() => {}); });
  upstreams.clear();
  next.forEach((u, k) => upstreams.set(k, u));
  bump();
}

/** list を接続する。ランナー（npx / uvx 等）は同時 RUNNER_CONCURRENCY 件、それ以外は同時 CONNECT_CONCURRENCY 件まで（モジュール全体で共有）。force=true は接続済みでもやり直す。 */
async function connectMany(list, force) {
  if (!list.length) return;
  beginSync();
  try { await Promise.all(list.map((u) => enqueue(u, !!force))); }
  finally { endSync(); }
}

/** まだ接続を試みていない（新規・定義が変わった）サーバーだけを始める。接続済み・再試行待ちのものには触らない。 */
function connectAll() {
  // Deferred connection is opt-in per-server. Servers without a valid explicit manifest remain eager.
  return connectMany(Array.from(upstreams.values()).filter((u) => !u.started && !u.lazy && u.state !== "disabled" && u.state !== "deferred"));
}

function watchConfig() {
  if (watching) return;
  watching = true;
  fs.watchFile(CONFIG_PATH, { interval: WATCH_INTERVAL_MS, persistent: false }, () => {
    logger(".mcp.json が変更されました。再読み込みします。");
    loadConfig();
    connectAll().catch(() => {});
  });
}

function init(opts) {
  opts = opts || {};
  WORKSPACE_ROOT = path.resolve(opts.workspaceRoot || process.cwd());
  APP_ROOT = path.resolve(opts.appRoot || process.cwd());
  VERSION = String(opts.version || "0");
  CONFIG_PATH = path.join(WORKSPACE_ROOT, ".mcp.json");
  if (typeof opts.log === "function") logger = opts.log;
  process.env.LUMEN_WORKSPACE_ROOT = WORKSPACE_ROOT;
  process.env.LUMEN_APP_ROOT = APP_ROOT;
  closing = false;
  sync.startedAt = 0; sync.endedAt = 0; sync.timedOut = false;
  ensureConfigFile();
  loadConfig();
  watchConfig();
  return connectAll();
}

function getState() {
  const servers = [];
  upstreams.forEach((u) => servers.push(u.summary()));
  return { revision, configPath: CONFIG_PATH, configError, capabilityWarnings: capabilityWarnings.slice(0, 50), etag: etagOf(readConfigFile().text), servers, syncStatus: syncStatusOf(), notices: notices.slice(), now: Date.now() };
}

function getTools() {
  const out = [];
  upstreams.forEach((u) => { if (u.state === "connected") out.push(...u.tools); });
  return out;
}


/** Connect one manifest-declared lazy server after bounded candidate ranking or explicit server selection. */
async function ensureServerConnected(name) {
  const u = upstreams.get(String(name || ""));
  if (!u) { const e = new Error("サーバー「" + String(name || "").slice(0, 40) + "」は定義されていません。"); e.hubCode = "UNKNOWN_SERVER"; throw e; }
  if (u.state === "disabled") { const e = new Error("サーバー「" + u.name + "」は無効です。"); e.hubCode = "SERVER_DISABLED"; throw e; }
  if (u._lazyConnectPromise) return u._lazyConnectPromise;
  u._lazyConnectPromise = (async () => {
    const startupMs = Number(u._cfg && u._cfg.timeoutMs) || (u.type === "stdio" && u._cfg && u._cfg.runner ? RUNNER_CONNECT_TIMEOUT_MS : CONNECT_TIMEOUT_MS);
    const deadline = Date.now() + Math.min(CONNECT_GLOBAL_TIMEOUT_MS + 10000, Math.max(45000, startupMs + 30000));
    while (u.state !== "connected" && u.state !== "degraded" && u.state !== "error" && u.state !== "auth_required" && u.state !== "disabled") {
      if (Date.now() >= deadline) {
        const e = new Error("サーバー「" + u.name + "」の接続待ちが上限に達しました。");
        e.hubCode = "CONNECT_WAIT_TIMEOUT";
        throw e;
      }
      if (u._connecting) {
        await Promise.race([u._connecting, waitForChange(revision, Math.min(2000, deadline - Date.now()))]);
      } else if (u._queued || u.state === "connecting" || u.state === "timed_out") {
        // Another request may already own the connection queue. Wait for its state transition
        // instead of interpreting enqueue()'s duplicate-suppression result as a failed connection.
        await waitForChange(revision, Math.min(2000, deadline - Date.now()));
        if (!u._connecting && !u._queued && (u.state === "connecting" || u.state === "timed_out")) {
          await connectMany([u], true);
        }
      } else {
        await connectMany([u], false);
      }
    }
    if ((u.state === "connected" || u.state === "degraded") && u.toolsStatus !== "ok") {
      await u._startToolsLoad();
    }
    if (u.state !== "connected" && u.state !== "degraded") {
      const e = new Error("サーバー「" + u.name + "」への接続に失敗しました: " + String(u.error || u.state).split("\n")[0]);
      e.hubCode = "NOT_CONNECTED";
      throw e;
    }
    if (u.toolsStatus !== "ok") {
      const e = new Error("サーバー「" + u.name + "」には接続しましたが、tools/list の確認が完了していません: " + String(u.toolsError || u.toolsStatus || "unknown").split("\n")[0]);
      e.hubCode = "TOOLS_DISCOVERY_FAILED";
      throw e;
    }
    return u.summary();
  })().finally(() => { u._lazyConnectPromise = null; });
  return u._lazyConnectPromise;
}

/** Discover lazy candidates using only explicit workspace metadata, connect a bounded subset, then return actual tools/list results. */
async function discoverTools(query, options) {
  options = options || {};
  const q = String(query || "").trim().slice(0, 500);
  if (!q) { const e = new Error("query が必要です。"); e.hubCode = "BAD_REQUEST"; throw e; }
  const states = {};
  upstreams.forEach((u, name) => { states[name] = { state: u.state }; });
  const candidates = mcpCapabilities.rankLazyServers(capabilityManifest, q, { maxServers: options.maxServers, states });
  const serverResults = await Promise.all(candidates.map(async (candidate) => {
    try {
      const server = await ensureServerConnected(candidate.name);
      return { name: candidate.name, state: server.state, connected: true, toolCount: server.toolCount, capabilities: server.capabilities };
    } catch (e) {
      const u = upstreams.get(candidate.name);
      return { name: candidate.name, state: u ? u.state : "error", connected: false, toolCount: u ? u.tools.length : 0, error: String(e && e.message || e).slice(0, 300), capabilities: candidate.capabilities || (u && u.capability.capabilities) || [] };
    }
  }));
  // The browser refreshes /api/tools after discovery. Never resend full schemas here as a second copy.
  return {
    query: q,
    candidates: candidates.map(c => ({ name: c.name, score: c.score, reason: c.reason })),
    servers: serverResults,
    warnings: capabilityWarnings.slice(0, 20)
  };
}

function getCapabilities() {
  return Object.keys(capabilityManifest).map(name => {
    const u = upstreams.get(name), c = capabilityManifest[name];
    return { name, lazy: !!c.lazy, capabilities: c.capabilities.slice(), description: c.description, state: u ? u.state : "unknown" };
  });
}

function findTool(name) {
  for (const u of upstreams.values()) {
    const t = u.tools.find((x) => x.name === name);
    if (t) return { upstream: u, tool: t };
  }
  return null;
}

async function callTool(name, args, opts) {
  const hit = findTool(String(name || ""));
  if (!hit) {
    // 接続されていないサーバーのツール名なら、その旨を明示する（成功を装わない）
    const owner = toolOwners.get(String(name || ""));   // 名前の文字列解析ではなく、登録時の記録で接続先を特定する
    const u = owner ? upstreams.get(owner.server) : null;
    const down = u && u.state !== "connected";
    const err = new Error(down ? "サーバー「" + u.name + "」は " + u.state + " のため、このツールは使えません。" : "不明なツールです（tools/list に存在しません）: " + String(name || "").slice(0, 120));
    err.hubCode = down ? "NOT_CONNECTED" : "UNKNOWN_TOOL";
    throw err;
  }
  return hit.upstream.callTool(hit.tool.upstreamName, args && typeof args === "object" && !Array.isArray(args) ? args : {}, opts);
}

/**
 * name 指定: そのサーバーだけ強制で繋ぎ直す（そのサーバーの呼び出し中の通信は切れる）。
 * name 省略: loadConfig() のうえで「全サーバー」を強制で繋ぎ直す。正常なサーバー（workspace など）の呼び出し中の通信も切れるので、
 *            server.js は通常これを使わず、接続できていないものだけをやり直す syncAllServers() を使う（POST /api/reconnect { all: true } のときだけここへ来る）。
 */
async function reconnect(name) {
  const targets = name ? [upstreams.get(name)].filter(Boolean) : Array.from(upstreams.values());
  if (name && !targets.length) { const e = new Error("サーバー「" + String(name).slice(0, 40) + "」は定義されていません。"); e.hubCode = "UNKNOWN_SERVER"; throw e; }
  if (!name) loadConfig();
  const list = name ? targets : Array.from(upstreams.values());
  list.forEach((u) => { u.attempt = 0; });
  await connectMany(list, true);
}

/**
 * 接続できていないサーバーだけをやり直す（定義の再読み込みはしない = Upstream を作り直さない）。再試行カウンタは全サーバーで 0 に戻す。
 * 接続済み・接続処理中・順番待ちのものには触らない。degraded（や tools/list の再試行待ち）は接続を保ったまま tools/list をすぐ取り直す。全体タイムアウト（timed_out）後の再試行にも使う。
 */
async function syncAllServers() {
  const list = Array.from(upstreams.values()).filter((u) => u.state !== "disabled" && !u.closed);
  list.forEach((u) => { u.attempt = 0; });
  list.filter((u) => u.state === "degraded" || (u.state === "connected" && u.toolsStatus === "error")).forEach((u) => { u._startToolsLoad().catch(() => {}); });
  const todo = list.filter((u) => (u.state === "error" || u.state === "timed_out" || u.state === "connecting") && !u._connecting && !u._queued);
  todo.forEach((u) => clearTimeout(u.retryTimer));   // 再試行待ちを前倒しする
  await connectMany(todo, true);
}

/** 子プロセスを spawn して stderr / stdout の先頭と終了コードを集める（3 秒だけ）。実際の Upstream には触れない。プロセスは必ず木ごと落とす。 */
function runStdioProbe(u, ms) {
  return new Promise((resolve) => {
    const c = u._cfg;
    const res = { route: "", command: "", cwd: c.cwd, envMode: "", spawned: false, exited: false, code: null, signal: null, ms: 0, stderrHead: "", stdoutHead: "", spawnError: null, message: "" };
    let route;
    try { route = mcpLaunch.plan(c, u.attempt); }
    catch (e) { res.spawnError = e.name || "Error"; res.message = u._redact(e.message).slice(0, 300); return resolve(res); }
    res.route = route.label; res.envMode = (route.diag && route.diag.envMode) || ""; res.diag = route.diag;
    res.command = u._redact(route.command + (route.args.length ? " " + route.args.join(" ") : "")).slice(0, 300);
    const t0 = Date.now();
    let child, timer, done = false;
    const finish = () => {
      if (done) return;
      done = true; clearTimeout(timer);
      res.ms = Date.now() - t0;
      if (child && child.pid && !res.exited) mcpLaunch.killTree(child.pid);
      res.stderrHead = u._redact(res.stderrHead); res.stdoutHead = u._redact(res.stdoutHead);
      resolve(res);
    };
    try {
      child = cp.spawn(route.command, route.args, { env: route.env, cwd: c.cwd, stdio: ["pipe", "pipe", "pipe"], windowsHide: true, shell: false, detached: process.platform !== "win32" });
    } catch (e) { res.spawnError = e.code || e.name || "Error"; res.message = u._redact(e.message).slice(0, 300); return finish(); }
    child.on("error", (e) => { res.spawnError = e.code || e.name || "Error"; res.message = u._redact(e.message).slice(0, 300); finish(); });
    child.on("spawn", () => { res.spawned = true; });
    child.stderr.on("data", (d) => { if (res.stderrHead.length < 500) res.stderrHead = (res.stderrHead + d).slice(0, 500); });
    child.stdout.on("data", (d) => { if (res.stdoutHead.length < 300) res.stdoutHead = (res.stdoutHead + d).slice(0, 300); });
    child.on("exit", (code, signal) => { res.exited = true; res.code = code; res.signal = signal; setTimeout(finish, 150); });   // stderr の残りを少し待つ
    timer = setTimeout(finish, ms);
    timer.unref();
  });
}

function stdioVerdict(u, r) {
  if (r.spawnError) {
    const ent = /ENOENT/.test(r.spawnError);
    return ent ? u._missingText(true, r.diag) : "起動に失敗しました（" + r.spawnError + "）: " + (r.message || "");
  }
  if (r.exited) {
    const how = r.code === 0 ? "すぐに正常終了しました（stdio の MCP サーバーは入力を待って動き続ける必要があります。引数が足りない可能性があります）。"
      : "起動して " + (r.ms / 1000).toFixed(1) + " 秒以内に終了しました（" + (r.code != null ? "終了コード " + r.code : "シグナル " + r.signal) + "）。";
    const act = nextActionFor("exit", r.stderrHead);
    return how + (r.stderrHead ? "\nstderr: " + r.stderrHead.replace(/\s+/g, " ").slice(0, 300) : "") + (act ? "\n" + act : "");
  }
  return "3 秒間は起動したままでした（プロセスは正常に立ち上がっています）。接続エラーが続くなら、初回のパッケージ取得に時間がかかっている、または initialize を返せていない（世代交渉・stdout への余計な出力）可能性があります。"
    + (r.stdoutHead ? "\nstdout の先頭（MCP 以外の出力が混ざると接続できません）: " + r.stdoutHead.replace(/\s+/g, " ").slice(0, 200) : "");
}

/** URL のホストについて DNS 解決と TLS ハンドシェイクを個別に確かめる（到達できなかった原因の切り分け用）。 */
async function networkDetailOf(urlStr) {
  const out = { dns: "error", tls: "error" };
  let url;
  try { url = new URL(urlStr); } catch (_) { return out; }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const within = (p, ms) => Promise.race([p, new Promise((_, rej) => { const t = setTimeout(() => rej(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })), ms); t.unref(); })]);
  try { await within(dns.promises.lookup(host), 5000); out.dns = "ok"; }
  catch (e) { out.dnsCode = e && e.code ? String(e.code) : ""; out.note = "DNS で名前解決できないため TLS は試していません。"; return out; }
  if (url.protocol !== "https:") { out.tls = "skipped"; out.note = "http:// のため TLS は使いません。"; return out; }
  await new Promise((resolve) => {
    const sock = tls.connect({ host, port: Number(url.port) || 443, servername: host });
    const end = (ok, code) => { out.tls = ok ? "ok" : "error"; if (code) out.tlsCode = String(code); try { sock.destroy(); } catch (_) { /* 終了済み */ } resolve(); };
    const t = setTimeout(() => end(false, "ETIMEDOUT"), 5000); t.unref();
    sock.once("secureConnect", () => { clearTimeout(t); end(true); });
    sock.once("error", (e) => { clearTimeout(t); end(false, e && e.code); });
  });
  return out;
}

/** 1 台の接続診断。HTTP / SSE は素の fetch で今すぐ叩いて到達・認証・応答形式を、到達できなければ DNS / TLS を個別に確かめる。stdio はコマンドを 3 秒だけ単体起動して stderr と終了コードを返す。履歴・errorKind・nextAction・checkedAt つき。 */
async function diagnose(name) {
  const u = upstreams.get(name);
  if (!u) { const e = new Error("サーバー「" + String(name).slice(0, 40) + "」は定義されていません。"); e.hubCode = "UNKNOWN_SERVER"; throw e; }
  const sm = u.summary();
  const out = {
    name, type: u.type, state: u.state, route: u.route, node: process.version,
    proxyEnv: ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY"].filter((k) => process.env[k] || process.env[k.toLowerCase()]),
    nodeEnvProxy: !!process.env.NODE_USE_ENV_PROXY,
    attempts: sm.attempts, errorKind: sm.errorKind, nextAction: sm.nextAction, toolsStatus: sm.toolsStatus, toolsError: sm.toolsError,
    checkedAt: new Date().toISOString(),
  };
  if (!u._cfg || u.state === "disabled") { out.note = "無効のサーバーは診断できません。"; return out; }
  if (u.type === "stdio") {
    const r = await runStdioProbe(u, 3000);
    out.verdict = u._redact(stdioVerdict(u, r));
    delete r.diag;
    out.stdio = r;
    out.checkedAt = new Date().toISOString();
    return out;
  }
  const c = u._cfg;
  const hasCred = !!(c.bearer || Object.keys(c.headers).some((k) => /auth|key|token/i.test(k)));
  const pr = await mcpHttp.probe(c.url, { headers: c.headers, bearer: c.bearer, timeoutMs: 20000, version: VERSION });
  const f = mcpHttp.probeFailure(pr, { hasCredentials: hasCred });
  out.url = u._redact(pr.url);
  out.probe = {
    kind: pr.kind, status: pr.status, contentType: pr.contentType, elapsedMs: pr.elapsedMs,
    protocolVersion: pr.protocolVersion, serverInfo: pr.serverInfo, wwwAuthenticate: u._redact(pr.wwwAuthenticate), body: u._redact(pr.body),
  };
  if (pr.kind === "network") {
    out.causeCode = pr.causeCode || "";
    try { out.networkDetail = await networkDetailOf(c.url); } catch (_) { out.networkDetail = { dns: "error", tls: "error" }; }
  }
  out.verdict = u._redact(f ? f.message : pr.kind === "ok" ? "到達でき、initialize にも成功しました。接続されていなければ「再接続」を押してください。" : pr.kind === "sse" ? pr.note : pr.note || "");
  out.checkedAt = new Date().toISOString();
  return out;
}

function readConfigText() {
  const r = readConfigFile();
  return { path: CONFIG_PATH, text: r.text, errors: r.errors };
}

/** 設定テキストを検証してから原子的に書き込む。サーバー単位のエラーがあれば保存しない。 */
function writeConfigText(text) {
  let j;
  try { j = JSON.parse(String(text)); } catch (e) { const err = new Error("JSON として不正です: " + e.message); err.hubCode = "INVALID_CONFIG"; throw err; }
  const v = validateConfig(j);
  if (v.errors.length) { const err = new Error(v.errors.join("\n")); err.hubCode = "INVALID_CONFIG"; throw err; }
  const tmp = CONFIG_PATH + ".tmp-" + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(j, null, 2) + "\n");
  fs.renameSync(tmp, CONFIG_PATH);
  loadConfig();
  connectAll().catch(() => {});
}

/* ------------------------------------------------------------
   複数サーバーの管理 API（貼り付けインポート・1 件ずつの追加 / 上書き / 削除 / 有効無効）
   すべて「読む → 変える → 検証 → 原子的に書く」を 1 回で行う。etag（ファイル内容のハッシュ）が違えば CONFLICT。
   ------------------------------------------------------------ */

function cfgErr(message, code) { const e = new Error(message); e.hubCode = code || "INVALID_CONFIG"; return e; }
const etagOf = (raw) => crypto.createHash("sha1").update(String(raw == null ? "" : raw)).digest("hex").slice(0, 12);
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const validName = (n) => typeof n === "string" && SERVER_NAME_RE.test(n) && !n.includes("__");

function uniqueName(base, taken) {
  let name = base;
  for (let k = 2; taken.has(name); k++) name = (base.slice(0, 29) + "-" + k).replace(/-{2,}/g, "-");
  return name;
}

/** 書き換え用に設定ファイルを読む。JSON として壊れていれば、勝手に上書きせずエラーにする。 */
function readEditable() {
  let raw = "";
  try { raw = fs.readFileSync(CONFIG_PATH, "utf8"); }
  catch (e) { if (e.code !== "ENOENT") throw cfgErr(".mcp.json を読めません: " + e.message, "ERROR"); }
  let obj = {};
  if (raw.trim()) {
    try { obj = JSON.parse(raw); }
    catch (e) { throw cfgErr(".mcp.json が JSON として不正なため、画面からは編集できません。先に「JSON 全体を編集」で直してください: " + e.message); }
  }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) throw cfgErr("設定のルートが JSON オブジェクトではありません。");
  if (obj.mcpServers == null) obj.mcpServers = {};
  else if (typeof obj.mcpServers !== "object" || Array.isArray(obj.mcpServers)) throw cfgErr("mcpServers がオブジェクトではありません。");
  return { raw, obj, etag: etagOf(raw) };
}

/** fn(servers, root) → { changed, value }。changed のときだけ書いて、再読み込みする。 */
function mutateConfig(fn, ifMatch) {
  const cur = readEditable();
  if (ifMatch && ifMatch !== cur.etag) throw cfgErr("設定が別の場所で変更されています。画面を更新してから、もう一度行ってください。", "CONFLICT");
  const r = fn(cur.obj.mcpServers, cur.obj);
  if (r && r.changed) {
    const text = JSON.stringify(cur.obj, null, 2) + "\n";
    fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
    const tmp = CONFIG_PATH + ".tmp-" + process.pid;
    fs.writeFileSync(tmp, text);
    fs.renameSync(tmp, CONFIG_PATH);
    loadConfig();
    connectAll().catch(() => {});
  }
  return Object.assign({ etag: etagOf(r && r.changed ? JSON.stringify(cur.obj, null, 2) + "\n" : cur.raw) }, r && r.value !== undefined ? { value: r.value } : {});
}

function currentServers() {
  try { const c = readEditable(); return { servers: c.obj.mcpServers, etag: c.etag, error: null }; }
  catch (e) { return { servers: {}, etag: etagOf(""), error: e.message }; }
}

/** 貼り付けのプレビュー（何も書かない）。各件の検証結果・既存との関係・注意を返す。秘密の値は伏字。 */
function previewImport(text) {
  const parsed = importer.parseImport(text);
  const cur = currentServers();
  const taken = new Set(Object.keys(cur.servers));
  parsed.entries.forEach((e) => taken.add(e.name));
  const entries = parsed.entries.map((e) => {
    let error = e.error;
    if (e.spec && !error) { try { compileSpec(e.spec, { validate: true }); } catch (x) { error = x.message; } }
    let existing = "none";
    if (hasOwn(cur.servers, e.name)) {
      const on = importer.normalizeSpec(cur.servers[e.name]);
      existing = e.spec && importer.canonicalKey(on.spec || cur.servers[e.name]) === importer.canonicalKey(e.spec) ? "same" : "different";
    }
    return {
      index: e.index, name: e.name, nameDerived: e.nameDerived,
      kind: importer.kindOf(e.spec), target: importer.describeTarget(e.spec), disabled: !!(e.spec && e.spec.disabled),
      warnings: e.warnings, error, existing,
      suggestedName: existing === "none" ? e.name : uniqueName(e.name, taken),
      spec: e.spec ? importer.maskSpec(e.spec) : null,
    };
  });
  return { entries, errors: parsed.errors.concat(cur.error ? [cur.error] : []), warnings: parsed.warnings, etag: cur.etag };
}

/**
 * 貼り付けを適用する。choices: [{ index, include?, name?, action? }]（index は previewImport の entries[].index）。
 *   action: 既存と同名のとき "replace"（上書き）/ "rename"（別名で追加）/ "skip"（既定）。choices を渡さなければ、エラーのない新規だけを追加する。
 * 戻り値: { results: [{ index, name, status: added|replaced|renamed|skipped|error, message?, from? }], etag }
 */
function applyImport(text, choices, ifMatch) {
  const parsed = importer.parseImport(text);
  if (!parsed.entries.length) throw cfgErr(parsed.errors.join("\n") || "取り込めるサーバーがありません。");
  const picks = new Map();
  (Array.isArray(choices) ? choices : []).forEach((c) => { if (c && Number.isInteger(c.index)) picks.set(c.index, c); });
  const r = mutateConfig((servers) => {
    const results = [];
    let changed = false;
    parsed.entries.forEach((e) => {
      const ch = picks.get(e.index);
      if (ch && ch.include === false) return;
      if (e.error || !e.spec) { results.push({ index: e.index, name: e.name, status: "error", message: e.error || "定義を読めません。" }); return; }
      const name = ch && typeof ch.name === "string" && ch.name.trim() ? ch.name.trim() : e.name;
      if (!validName(name)) { results.push({ index: e.index, name, status: "error", message: "名前が不正です（英数字・_・- のみ、先頭は英数字、32 文字以内、__ は不可）。" }); return; }
      try { compileSpec(e.spec, { validate: true }); } catch (x) { results.push({ index: e.index, name, status: "error", message: x.message }); return; }
      if (!hasOwn(servers, name)) { servers[name] = e.spec; changed = true; results.push({ index: e.index, name, status: "added" }); return; }
      const action = (ch && ch.action) || "skip";
      if (action === "replace") { servers[name] = e.spec; changed = true; results.push({ index: e.index, name, status: "replaced" }); }
      else if (action === "rename") { const n2 = uniqueName(name, new Set(Object.keys(servers))); servers[n2] = e.spec; changed = true; results.push({ index: e.index, name: n2, from: name, status: "renamed" }); }
      else results.push({ index: e.index, name, status: "skipped", message: "同名のサーバーが既にあるためスキップしました。" });
    });
    return { changed, value: results };
  }, ifMatch);
  return { results: r.value, etag: r.etag };
}

/** 1 件の追加・更新。mode: "create"（同名があれば EXISTS）/ "update"（無ければ UNKNOWN_SERVER）/ 省略（どちらでも）。 */
function putServer(name, specIn, opts) {
  opts = opts || {};
  if (!validName(name)) throw cfgErr("サーバー名が不正です（英数字・_・- のみ、先頭は英数字、32 文字以内、__ は不可）。", "INVALID_SERVER");
  const n = importer.normalizeSpec(specIn);
  if (n.error) throw cfgErr(n.error, "INVALID_SERVER");
  const r = mutateConfig((servers) => {
    const exists = hasOwn(servers, name);
    if (opts.mode === "create" && exists) throw cfgErr("同名のサーバー「" + name + "」が既にあります。", "EXISTS");
    if (opts.mode === "update" && !exists) throw cfgErr("サーバー「" + name + "」は定義されていません。", "UNKNOWN_SERVER");
    let prev = null;
    if (exists) { const on = importer.normalizeSpec(servers[name]); prev = on.spec || servers[name]; }
    const fixed = importer.restoreMasked(n.spec, prev);
    if (fixed.error) throw cfgErr(fixed.error, "INVALID_SERVER");
    try { compileSpec(fixed.spec, { validate: true }); } catch (e) { throw cfgErr(e.message, "INVALID_SERVER"); }
    servers[name] = fixed.spec;
    return { changed: true, value: { name, created: !exists, warnings: n.warnings } };
  }, opts.etag);
  return Object.assign({ etag: r.etag }, r.value);
}

function removeServer(name, ifMatch) {
  const r = mutateConfig((servers) => {
    if (!hasOwn(servers, name)) throw cfgErr("サーバー「" + String(name).slice(0, 40) + "」は定義されていません。", "UNKNOWN_SERVER");
    delete servers[name];
    return { changed: true, value: { name } };
  }, ifMatch);
  return { etag: r.etag, name: r.value.name };
}

function setServerDisabled(name, disabled, ifMatch) {
  const r = mutateConfig((servers) => {
    if (!hasOwn(servers, name)) throw cfgErr("サーバー「" + String(name).slice(0, 40) + "」は定義されていません。", "UNKNOWN_SERVER");
    const spec = servers[name];
    if (!spec || typeof spec !== "object" || Array.isArray(spec)) throw cfgErr("サーバー「" + name + "」の定義がオブジェクトではありません。", "INVALID_SERVER");
    if (disabled) spec.disabled = true; else delete spec.disabled;
    return { changed: true, value: { name, disabled: !!disabled } };
  }, ifMatch);
  return { etag: r.etag, name: r.value.name, disabled: r.value.disabled };
}

async function shutdown() {
  closing = true;
  clearTimeout(sync.timer); clearInterval(sync.progress); sync.active = 0;
  try { fs.unwatchFile(CONFIG_PATH); } catch (_) { /* 未登録 */ }
  watching = false;
  await Promise.all(Array.from(upstreams.values()).map((u) => u.close().catch(() => {})));
  upstreams.clear();
  Array.from(waiters).forEach((w) => w());
}

module.exports = {
  init, shutdown, getState, getTools, callTool, reconnect, readConfigText, writeConfigText, waitForChange, validateConfig, NAME_PREFIX, sanitizeToolName,
  previewImport, applyImport, putServer, removeServer, setServerDisabled, compileSpec, diagnose,
  syncAllServers, ensureServerConnected, discoverTools, getCapabilities, stats, nextActionFor,
};
