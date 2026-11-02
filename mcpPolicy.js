"use strict";

/**
 * mcpPolicy.js — MCP 接続経路の「いつ再試行するか・どれだけ待つか・何個同時に繋ぐか」を 1 か所で決める（Lumen 実行コア）
 * ============================================================
 * 純粋関数のみ（SDK・fs・hub には触れない。時計と乱数と sleep は差し替えられる）。
 * 接続・一覧取得・呼び出しの各所が別々の規則を持つと、直したつもりの場所だけが変わる。ここを唯一の根拠にする。
 *
 *   classify(err)                     … 失敗を種類に分ける（auth / not_found / rate_limited / server / network / timeout / aborted / client / exit / config / unknown）
 *   shouldRetry(phase, transport, err, retries, opts) -> { retry, delayMs, kind, reason }
 *   withRetry(fn, opts)               … 上の判断どおりに fn を再実行する（呼び出しごとの回数・待ち時間つき）
 *   createCallWatch(opts)             … 1 回の呼び出しの「全体の上限」と「無音の上限」を 1 つの AbortSignal にまとめる
 *   idleMsFor(transport)              … 無音の上限の既定値（リモート 5 分 / 子プロセス 30 分）
 *   mapLimit(items, limit, fn)        … 同時数を絞った並列実行（起動時にサーバーを一斉に繋ぐ用。結果は入力順・失敗は握りつぶさず settled で返す）
 *   decideHeal(server, rec, now)      … degraded / error のサーバーを、いま hub.reconnect してよいかの判断（server.js が呼び出し時に使う）
 *   isSessionLost(err)                … HTTP セッションが無くなった（404 / 410 / "session not found"）。SDK は自動では張り直さない。要求はサーバーで処理されていない
 *   isDeadTransport(err)              … 通信路が死んだ（接続断・接続拒否・セッション切れ）。hub が state を error にして再接続するかの判定
 *   nextActionFor(info)               … 失敗の種類 → 利用者向けの「次にやること」（hub の notices / server.js のエラー応答が使う。秘密は含めない）
 *
 * 段階（phase）ごとの規則:
 *   first-connect … リモート（http / sse）だけ。一時的な失敗（5xx / 429 / 接続拒否 / 切断 / 時間切れ）を最大 3 回再試行（1s → 2s → 4s）。
 *                   認証・見つからない（404 / 410）・その他の 4xx は、設定を直さない限り直らないので再試行しない。
 *   reconnect     … 接続済みのリモートが落ちたとき。最大 5 回、1s から倍々（1・2・4・8・16 秒）。子プロセス（stdio）は自動では繋ぎ直さない。
 *   discovery     … 接続後の tools/list など。一時的なネットワーク・サーバー失敗だけを最大 3 回、短い間隔で。認証・4xx・時間切れは再試行しない。
 *   background    … 対話のない実行で、落ちたリモートを裏で繋ぎ直し続ける（最大 30 分、間隔は 5s から倍々で 60s まで）。
 *   heal          … decideHeal の根拠。リモートは最大 30 分（5s 倍々 → 60s）、子プロセスは暴走を避けて最大 5 回。
 *                   認証・設定・起動失敗・プロトコル不一致・404 は対象外（直らないので）。
 *   ※ 実行コア（mcpHub）の再接続は hub 自身の _scheduleRetry（1s 倍々 → 30s、error の間は無制限・auth は再試行しない）が持つ。ここの phase は mcpHttp.RawHttpClient と decideHeal 用。
 *
 * 環境変数（どれも任意）:
 *   LUMEN_RETRY_NETWORK_MAX=3         first-connect / reconnect / discovery の再試行回数の上限（一時的なネットワーク・サーバー失敗）
 *   LUMEN_CALL_IDLE_MS                無音の上限（リモート・子プロセス共通。0 で無効）。LUMEN_CALL_IDLE_REMOTE_MS / LUMEN_CALL_IDLE_STDIO_MS で別々にも指定できる
 */

const DEFAULT_RNG = Math.random;
const REMOTE = new Set(["http", "sse", "ws"]);

function envInt(env, name, dflt, min) {
  const raw = (env || process.env)[name];
  if (raw === undefined || String(raw).trim() === "") return dflt;
  const n = Number(raw);
  return Number.isFinite(n) && n >= min ? Math.floor(n) : dflt;
}
/** 一時的なネットワーク・サーバー失敗の再試行回数の上限（既定 3）。その先は heal（server.js）が間隔を空けて繋ぎ直し続ける。 */
const NETWORK_MAX = envInt(process.env, "LUMEN_RETRY_NETWORK_MAX", 3, 0);

const PHASES = {
  "first-connect": { remoteOnly: true,  attempts: NETWORK_MAX, kinds: ["network", "server", "rate_limited", "timeout"], backoff: { baseMs: 1000, factor: 2, maxMs: 8000 } },
  "reconnect":     { remoteOnly: true,  attempts: NETWORK_MAX, kinds: ["network", "server", "rate_limited", "timeout"], backoff: { baseMs: 1000, factor: 2, maxMs: 16000 } },
  "discovery":     { remoteOnly: false, attempts: NETWORK_MAX, kinds: ["network", "server", "rate_limited"],            backoff: { baseMs: 200,  factor: 2, maxMs: 1000 } },
  "background":    { remoteOnly: true,  attempts: Infinity, windowMs: 30 * 60 * 1000, kinds: ["network", "server", "rate_limited", "timeout"], backoff: { baseMs: 5000, factor: 2, maxMs: 60000 } },
  "heal":          { remoteOnly: false, attempts: Infinity, stdioAttempts: 5, windowMs: 30 * 60 * 1000, kinds: ["network", "server", "rate_limited", "timeout", "exit"], backoff: { baseMs: 5000, factor: 2, maxMs: 60000 } },
};

/**
 * 無音の上限の既定。これは「安全網」であり、切断の主な検知ではない（切断は transport の close / 子プロセスの exit で分かる）。
 * リモートを 5 分にしていたため、進捗通知を出さないサーバーで 5 分を超える呼び出しが必ず切れていた（Node の fetch の既定 5 分と同じ壁）。
 */
const IDLE_MS = { remote: 30 * 60 * 1000, stdio: 30 * 60 * 1000 };

/* ------------------------------------------------------------
   失敗の分類
   ------------------------------------------------------------ */

function chainOf(e) {
  const out = [], seen = new Set();
  let x = e;
  for (let i = 0; x && typeof x === "object" && i < 6 && !seen.has(x); i++) {
    seen.add(x); out.push(x);
    x = x.cause || (Array.isArray(x.errors) && x.errors[0]) || null;
  }
  return out;
}

/** HTTP ステータス。SDK の StreamableHTTPError は数値の code に入れてくる。 */
function statusOf(e) {
  for (const x of chainOf(e)) {
    const cands = [x.httpStatus, x.status, x.statusCode, x.code];
    for (const c of cands) { const n = Number(c); if (Number.isInteger(n) && n >= 100 && n <= 599 && typeof c !== "boolean") return n; }
  }
  return 0;
}

/** 呼び出しの途中で transport が閉じた・未接続の文面（SDK の ConnectionClosed -32000 / "Not connected" / undici の "terminated" / 自前の「応答の途中で…」）。 */
const CLOSED_TEXT = /connection closed|not connected|transport (?:is )?closed|stream (?:closed|ended|disconnected)|\bterminated\b|接続が.{0,12}閉じられました|応答の途中で/i;
const NET_CODES = /^(ECONNREFUSED|ECONNRESET|ECONNABORTED|EPIPE|ETIMEDOUT|ENETUNREACH|EHOSTUNREACH|EAI_AGAIN|UND_ERR_(CONNECT_TIMEOUT|SOCKET|CLOSED|HEADERS_TIMEOUT|BODY_TIMEOUT))$/;
const CONFIG_CODES = /^(ENOTFOUND|ENOENT|EACCES|EINVAL|ERR_INVALID_URL|ERR_INVALID_ARG_VALUE|CERT_|DEPTH_ZERO|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS)/;

/** 失敗 → { kind, status, retryable, causeCode, closed? }。retryable は「一時的か」だけを示す（段階ごとの許可は shouldRetry が決める）。closed=true は「通信の途中で閉じた」。 */
function classify(err) {
  const e = err || {};
  const status = statusOf(e);
  const chain = chainOf(e);
  // causeCode は mcpHttp.ProbeError が持つ（fetch の cause の連鎖から取り出した ECONNREFUSED / ETIMEDOUT など）
  const codes = chain.reduce((acc, x) => { [x.code, x.causeCode].forEach((c) => { if (typeof c === "string" && c) acc.push(c); }); return acc; }, []);
  const names = chain.map((x) => String(x.name || "")).join(" ");
  const text = chain.map((x) => String(x.message || "")).join(" ");
  const causeCode = codes[0] || "";
  const done = (kind, retryable) => ({ kind, status, retryable, causeCode });
  const numCode = (n) => chain.some((x) => typeof x.code === "number" && x.code === n);

  if (e.auth === true || status === 401 || status === 403) return done("auth", false);
  if (/AbortError/.test(names) && !/Timeout/.test(names)) return done("aborted", false);
  if (e.fatal === true) return done(e.kind === "not-mcp" ? "config" : "client", false);
  if (status === 404 || status === 410) return done("not_found", false);
  if (status === 429) return done("rate_limited", true);
  if (status >= 500) return done("server", true);
  if (status >= 400) return done("client", false);
  if (codes.some((c) => CONFIG_CODES.test(c))) return done("config", false);
  if (/TimeoutError/.test(names) || numCode(-32001) || codes.some((c) => /^(ETIMEDOUT|UND_ERR_CONNECT_TIMEOUT)$/.test(c)) || /timed? ?out|時間切れ|返りませんでした/i.test(text)) return done("timeout", true);
  if (codes.some((c) => NET_CODES.test(c)) || /fetch failed|socket hang up|other side closed|ネットワーク|接続を途中で切られ/i.test(text)) return done("network", true);
  if (e.errorKind === "exit") return done("exit", false);
  // SDK の McpError -32000「Connection closed」・"Not connected"・SSE の途中切断。以前は unknown で、どの段階でも再試行されなかった。
  if (numCode(-32000) || chain.some((x) => x.streamEnded === true) || CLOSED_TEXT.test(text)) return Object.assign(done("network", true), { closed: true });
  if (/プロセス|exited|終了しました/.test(text)) return done("exit", false);
  return done("unknown", false);
}

// SDK が HTTP の状態を数値で持たず文面だけで返す場合（"Error POSTing to endpoint (HTTP 404)"）も拾う。
const SESSION_TEXT = /session (?:not found|expired|terminated|invalid|has (?:been )?(?:expired|terminated))|(?:unknown|invalid|missing|expired|no valid) session|セッション.{0,6}(?:切れ|無効|見つかりません)|\bHTTP\s*(?:status\s*)?(?:404|410)\b/i;

/**
 * HTTP セッションが無くなったか（サーバーの再起動・セッションの有効期限）。Streamable HTTP の SDK は 404 を受けても自動では initialize し直さない。
 * 以前は、この失敗が「接続済み」のまま固定され、以降の呼び出しも tools/list も同じ 404 で失敗し続けた。要求はサーバーで処理されていないので、繋ぎ直して再送してよい。
 */
function isSessionLost(err) {
  if (!err) return false;
  const st = statusOf(err);
  if (st === 404 || st === 410) return true;
  return SESSION_TEXT.test(chainOf(err).map((x) => String(x.message || "")).join(" "));
}

/** 通信路が死んだ失敗か（接続断・接続拒否・セッション切れ）。時間切れ・認証・ツールの業務エラーは含まない。 */
function isDeadTransport(err) {
  if (!err) return false;
  if (isSessionLost(err)) return true;
  const c = classify(err);
  return c.kind === "network";
}

/* ------------------------------------------------------------
   再試行の判断
   ------------------------------------------------------------ */

/** retries 回目（0 始まり）の再試行の前に待つ時間。jitter（±20%）つき。 */
function backoffDelay(phase, retries, rng) {
  const p = PHASES[phase];
  if (!p) return 0;
  const b = p.backoff;
  const base = Math.min(b.maxMs, b.baseMs * Math.pow(b.factor, Math.max(0, retries)));
  const r = (rng || DEFAULT_RNG)();
  return Math.max(0, Math.round(base * (0.8 + 0.4 * r)));
}

/**
 * phase: "first-connect" | "reconnect" | "discovery" | "background"
 * transport: "stdio" | "http" | "sse" | "ws"
 * retries: これまでに行った再試行の回数（最初の失敗の直後は 0）
 * opts: { rng, elapsedMs, headersHelper }
 *   headersHelper=true … 認証ヘッダーを実行のたびに作り直す設定。認証失敗も再試行する（新しい資格情報を拾える）。
 */
function shouldRetry(phase, transport, err, retries, opts) {
  return decideByKind(phase, transport, classify(err), retries, opts);
}

/** shouldRetry の本体。失敗の種類（classify の結果 { kind }）がすでに分かっているとき（hub の errorKind から来る heal など）はこちらを直接使う。 */
function decideByKind(phase, transport, c, retries, opts) {
  opts = opts || {};
  const p = PHASES[phase];
  const no = (reason, kind) => ({ retry: false, delayMs: 0, kind: kind || "", reason });
  if (!p) return no("未知の段階: " + phase);
  if (p.remoteOnly && !REMOTE.has(String(transport))) return no("ローカルの子プロセスは自動では繋ぎ直しません（再接続は手動）。", c.kind);
  if (c.kind === "aborted") return no("中断されました。", c.kind);
  const authOk = c.kind === "auth" && opts.headersHelper === true && phase !== "discovery";
  if (!authOk && p.kinds.indexOf(c.kind) < 0) return no(c.kind === "auth" ? "認証の失敗は設定を直すまで直りません。" : "この種類の失敗（" + c.kind + "）は再試行しません。", c.kind);
  if (retries >= p.attempts) return no("再試行の上限（" + p.attempts + " 回）に達しました。", c.kind);
  if (p.stdioAttempts && !REMOTE.has(String(transport)) && retries >= p.stdioAttempts) return no("子プロセスの自動再起動の上限（" + p.stdioAttempts + " 回）に達しました。", c.kind);
  if (p.windowMs && Number(opts.elapsedMs) >= p.windowMs) return no("裏での再試行の上限時間に達しました。", c.kind);
  return { retry: true, delayMs: backoffDelay(phase, retries, opts.rng), kind: c.kind, reason: "" };
}

function defaultSleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) { reject(abortError()); return; }
    const t = setTimeout(() => { if (signal) signal.removeEventListener("abort", onAbort); resolve(); }, ms);
    const onAbort = () => { clearTimeout(t); reject(abortError()); };
    if (signal) signal.addEventListener("abort", onAbort, { once: true });
  });
}
function abortError() { const e = new Error("中断されました。"); e.name = "AbortError"; return e; }

/**
 * fn(retries) を、shouldRetry の判断に従って再実行する。成功した値を返す。失敗は最後の例外（attempts / retryKind を足して）。
 * opts: { phase, transport, signal, sleep, rng, now, onRetry({retry, delayMs, kind, error}), headersHelper }
 */
async function withRetry(fn, opts) {
  opts = opts || {};
  const sleep = opts.sleep || defaultSleep;
  const now = opts.now || Date.now;
  const t0 = now();
  for (let retries = 0; ; retries++) {
    try {
      return await fn(retries);
    } catch (e) {
      if (opts.signal && opts.signal.aborted) throw e;
      const d = shouldRetry(opts.phase, opts.transport, e, retries, { rng: opts.rng, elapsedMs: now() - t0, headersHelper: opts.headersHelper });
      if (e && typeof e === "object") { try { e.attempts = retries + 1; e.retryKind = d.kind; } catch (_) { /* 凍結されたエラー */ } }
      if (!d.retry) throw e;
      if (typeof opts.onRetry === "function") { try { opts.onRetry({ retry: retries + 1, delayMs: d.delayMs, kind: d.kind, error: e }); } catch (_) { /* 通知側の例外で止めない */ } }
      await sleep(d.delayMs, opts.signal);
    }
  }
}

/* ------------------------------------------------------------
   呼び出しの待ち時間（全体の上限 + 無音の上限）
   ------------------------------------------------------------ */

function idleMsFor(transport, env) {
  const remote = REMOTE.has(String(transport));
  const e = env || process.env;
  const keys = [remote ? "LUMEN_CALL_IDLE_REMOTE_MS" : "LUMEN_CALL_IDLE_STDIO_MS", "LUMEN_CALL_IDLE_MS"];
  for (const k of keys) {
    if (e[k] !== undefined && String(e[k]).trim() !== "") { const n = Number(e[k]); if (Number.isFinite(n) && n >= 0) return n; }   // 0 = 無効
  }
  return remote ? IDLE_MS.remote : IDLE_MS.stdio;
}

/**
 * 1 回の tools/call の見張り。
 *   wallMs … 開始からの上限（進捗通知があっても延びない）。0 / 未指定で無効。
 *   idleMs … 最後の応答・進捗から何も来ない時間の上限。touch() のたびに数え直す。0 / 未指定で無効。
 *   signal … 親の AbortSignal（利用者の中止など）。
 * 返り値: { signal, touch(), done(), reason }。reason は { kind: "wall" | "idle" | "parent", message } か null。
 * wallMs が 1000 以上のとき、idleMs は wallMs より短くならない（長い呼び出しを無音だけで先に切らない）。
 */
function createCallWatch(opts) {
  opts = opts || {};
  const setT = opts.setTimeout || setTimeout, clearT = opts.clearTimeout || clearTimeout;
  const ac = new AbortController();
  let reason = null, wallTimer = null, idleTimer = null, finished = false;
  const wallMs = Number(opts.wallMs) > 0 ? Number(opts.wallMs) : 0;
  let idleMs = Number(opts.idleMs) > 0 ? Number(opts.idleMs) : 0;
  if (idleMs && wallMs >= 1000 && idleMs < wallMs) idleMs = wallMs;

  const stopTimers = () => { if (wallTimer) clearT(wallTimer); if (idleTimer) clearT(idleTimer); wallTimer = idleTimer = null; };
  const abort = (kind, message) => {
    if (finished || ac.signal.aborted) return;
    reason = { kind, message };
    stopTimers();
    const err = new Error(message); err.name = "TimeoutError"; err.watchKind = kind;
    ac.abort(err);
  };
  const armIdle = () => {
    if (!idleMs || finished) return;
    if (idleTimer) clearT(idleTimer);
    idleTimer = setT(() => abort("idle", "MCP サーバーから " + Math.round(idleMs / 1000) + " 秒間、応答も進捗もありませんでした。"), idleMs);
    if (idleTimer && typeof idleTimer.unref === "function") idleTimer.unref();
  };
  if (wallMs) {
    wallTimer = setT(() => abort("wall", "呼び出しが上限（" + Math.round(wallMs / 1000) + " 秒）を超えました。"), wallMs);
    if (wallTimer && typeof wallTimer.unref === "function") wallTimer.unref();
  }
  armIdle();

  let onParent = null;
  if (opts.signal) {
    if (opts.signal.aborted) { reason = { kind: "parent", message: "中断されました。" }; ac.abort(opts.signal.reason); }
    else { onParent = () => { reason = reason || { kind: "parent", message: "中断されました。" }; stopTimers(); ac.abort(opts.signal.reason); }; opts.signal.addEventListener("abort", onParent, { once: true }); }
  }
  return {
    signal: ac.signal,
    touch() { armIdle(); },
    done() { finished = true; stopTimers(); if (opts.signal && onParent) opts.signal.removeEventListener("abort", onParent); },
    get reason() { return reason; },
    get idleMs() { return idleMs; },   // 診断用（実際に張られた値。wallMs に引き上げられた後の値）
    get wallMs() { return wallMs; },
  };
}

/* ------------------------------------------------------------
   利用者向けの「次にやること」
   ------------------------------------------------------------ */

/** info: { kind, transport?, phase?, status?, causeCode?, closed? }（classify の結果にそのまま足せる）。値・URL・ヘッダーは扱わない（秘密が入らない固定文のみ）。 */
function nextActionFor(info) {
  info = info || {};
  const kind = String(info.kind || "");
  const remote = REMOTE.has(String(info.transport || ""));
  const code = String(info.causeCode || "");
  switch (kind) {
    case "auth": return "認証情報（bearerToken / headers / API キー）の値・有効期限・権限を確認し、設定を直してから「再接続」を押してください。認証の失敗は自動では再試行しません。";
    case "session_lost": return "サーバー側のセッションが切れていました（サーバーの再起動・有効期限）。実行コアが自動で接続を張り直します。この呼び出しはサーバーで処理されていないので、そのまま再実行できます。";
    case "not_found": return remote ? "URL のパスを確認してください（多くは /mcp、旧方式は /sse）。セッション切れの場合は「再接続」で張り直せます。" : "起動コマンドと引数を確認してください。";
    case "rate_limited": return "レート制限（HTTP 429）です。少し待つと自動で再接続します。続く場合は呼び出しの頻度を下げてください。";
    case "server": return "サーバー側の障害（HTTP 5xx）の可能性があります。実行コアが間隔を空けて自動で再接続を続けます（最大 30 分）。戻らない場合はサーバーのログを確認してください。";
    case "timeout": return info.phase === "call"
      ? "呼び出しが時間切れになりました。処理が長いだけなら LUMEN_CALL_IDLE_MS（無音の上限）と、呼び出しの timeoutMs を延ばしてください。サーバーが固まっている場合は「再接続」を押してください。"
      : "接続が時間切れです。ネットワーク・VPN・プロキシ（Node 22.21 / 24 以降なら NODE_USE_ENV_PROXY=1）を確認してください。初回の npx / uvx はダウンロードで時間がかかります。";
    case "network":
      if (info.closed) return "通信が呼び出しの途中で閉じられました。実行コアが自動で接続を張り直します（数秒）。結果が分からない呼び出しは、副作用が起きている可能性があるため、内容を確認してから再実行してください。";
      if (/^ECONNREFUSED$/.test(code)) return "接続を拒否されました。ポートとホスト、サーバーが起動しているかを確認してください。自動で再接続を続けます。";
      if (/^(ECONNRESET|EPIPE|UND_ERR_SOCKET)$/.test(code)) return "接続を途中で切られました（セキュリティソフト・プロキシ・サーバー側の制限の可能性）。自動で再接続します。";
      return "ネットワークの一時的な失敗です。自動で再接続します。続く場合は VPN・プロキシ・ファイアウォールを確認してください。";
    case "config": return "設定（URL・証明書・コマンドの場所）を直す必要があります。再試行しても直りません。証明書の場合は NODE_EXTRA_CA_CERTS を設定して実行コアを再起動してください。";
    case "exit": return "MCP サーバーのプロセスが終了しました。実行コアが自動で再起動を試みます（最大 5 回）。繰り返す場合は起動コマンド・依存の取得（npx / uvx）・stderr を確認してください。";
    case "aborted": return "中断されました。";
    case "client": return "リクエストが拒否されました（HTTP 4xx）。引数・URL・サーバーの仕様を確認してください。";
    default: return "「再接続」を試し、直らなければ診断（POST /api/servers/<名前>/diagnose）の結果を確認してください。";
  }
}

/* ------------------------------------------------------------
   degraded / error からの自動回復の判断（heal）
   ------------------------------------------------------------ */

/** hub が state に載せる errorKind → 再試行の種類。transport / tools は通信起因なので network 扱い。 */
const HUB_KIND = { transport: "network", network: "network", timeout: "timeout", exit: "exit", server: "server", rate_limited: "rate_limited", tools: "network" };
/** どれだけ繋ぎ直しても直らないもの。プロトコル世代の交渉（legacy / auto / pin）は hub が持つので、ここでは触らない。 */
const HEAL_NEVER = new Set(["auth", "config", "spawn", "protocol", "not_found", "client", "aborted"]);
const UNKNOWN_HEAL_ATTEMPTS = 3;

function transportOf(s) {
  const t = String((s && (s.type || s.transport)) || "stdio");
  return t === "http" || t === "sse" || t === "ws" ? t : "stdio";
}

/**
 * s: hub.getState().servers の 1 件 { name, state, type, errorKind, error, toolsStatus, queued, nextRetryAt }
 * rec: 呼び出し側（server.js）が持つ記録 { since, attempts, nextAt }（最初に不調を見た時刻 / これまでの再接続回数 / 次に許す時刻）
 * 戻り値: { action: "reset" | "skip" | "wait" | "reconnect" | "giveup", reason?, kind?, delayMs? }
 *   reset: 正常（記録を捨てる） / skip: 今は何もしない / wait: 間隔待ち / reconnect: いま hub.reconnect(name) を呼ぶ（delayMs = その次まで空ける時間） / giveup: 自動では直らない
 */
function decideHeal(s, rec, now, opts) {
  opts = opts || {};
  rec = rec || {};
  const skip = (reason) => ({ action: "skip", reason });
  if (!s || !s.name) return skip("サーバー情報がありません。");
  const st = String(s.state || "");
  const toolsBad = st === "connected" && s.toolsStatus === "error";
  if (st === "connected" && !toolsBad) return { action: "reset", reason: "接続済み" };
  if (st === "disabled") return { action: "reset", reason: "無効" };
  if (st === "auth_required") return { action: "giveup", kind: "auth", reason: "認証の失敗は設定を直すまで直りません。" };
  if (st === "deferred") return { action: "giveup", kind: "", reason: "遅延接続のサーバーです（tool_search 経由で接続します）。" };
  // connecting / timed_out は hub が接続を続けている最中（初回の npx ダウンロード等）。ここで繋ぎ直すと進行中の接続を壊す。
  if (st === "connecting" || st === "timed_out" || s.queued) return skip("接続処理中です。");
  if (!(st === "error" || st === "degraded" || toolsBad)) return skip("対象外の状態: " + st);
  if (!opts.ignoreScheduled && Number(s.nextRetryAt) > now) return skip("hub が再接続を予約済みです。");   // ignoreScheduled: 呼び出しが待っているときは、予約を待たずに今すぐ繋ぎ直す

  const raw = String(s.errorKind || "");
  let kind = HUB_KIND[raw] || (HEAL_NEVER.has(raw) ? raw : "");
  if (!kind) kind = classify({ message: String(s.error || s.toolsError || "") }).kind;
  const transport = transportOf(s);
  if (kind === "unknown") {
    // 理由が分からない degraded は、数回だけ繋ぎ直してみる（error のまま理由不明なものは設定ミスの可能性が高いので触らない）。
    if (!(st === "degraded" || toolsBad)) return { action: "giveup", kind, reason: "原因が不明な error は自動では繋ぎ直しません。" };
    if ((rec.attempts || 0) >= UNKNOWN_HEAL_ATTEMPTS) return { action: "giveup", kind, reason: "原因が不明なため、自動の再接続は " + UNKNOWN_HEAL_ATTEMPTS + " 回までです。" };
    kind = "network";
  }
  const d = decideByKind("heal", transport, { kind }, rec.attempts || 0, { rng: opts.rng, elapsedMs: now - (rec.since || now) });
  if (!d.retry) return { action: "giveup", kind, reason: d.reason };
  if ((rec.nextAt || 0) > now) return { action: "wait", kind, delayMs: rec.nextAt - now };
  return { action: "reconnect", kind, delayMs: d.delayMs };
}

/* ------------------------------------------------------------
   並列実行（同時数つき）
   ------------------------------------------------------------ */

/** items を最大 limit 個ずつ並列に fn(item, index) へ流す。戻り値は入力順の [{ status: "fulfilled", value } | { status: "rejected", reason }]。 */
async function mapLimit(items, limit, fn) {
  const list = Array.isArray(items) ? items : [];
  const n = Math.max(1, Math.min(Number(limit) || 1, list.length || 1));
  const out = new Array(list.length);
  let next = 0;
  async function worker() {
    for (;;) {
      const i = next++;
      if (i >= list.length) return;
      try { out[i] = { status: "fulfilled", value: await fn(list[i], i) }; }
      catch (reason) { out[i] = { status: "rejected", reason }; }
    }
  }
  await Promise.all(Array.from({ length: n }, worker));
  return out;
}

module.exports = { classify, statusOf, isSessionLost, isDeadTransport, shouldRetry, decideByKind, backoffDelay, withRetry, createCallWatch, idleMsFor, mapLimit, nextActionFor, decideHeal, transportOf, PHASES, IDLE_MS };
