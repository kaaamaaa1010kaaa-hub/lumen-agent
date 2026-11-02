"use strict";

/**
 * mcpHttp.js — リモート（HTTP / 旧 SSE）MCP サーバーの「事前診断」と「最後の逃げ道」（Lumen 実行コア）
 * ============================================================
 * 背景: HTTP サーバーが「エラー」のまま繋がらないとき、SDK の例外は "fetch failed" のように原因（DNS / 証明書 / プロキシ / 401 など）を
 *       隠しがちで、世代交渉（server/discover）の失敗とも区別がつかない。そこで SDK を呼ぶ前に素の fetch で 1 回だけ叩いて原因を特定する。
 *
 *   probe(url, opts)        … initialize を 1 回 POST し、到達性・認証・応答形式を分類する（何も接続は残さない）。
 *                             kind: ok | mcp-error | auth | network | http-error | not-mcp | sse
 *   explainNetworkError(e)  … fetch の例外から cause の連鎖をたどり、原因と対処を 1 文にする。
 *   RawHttpClient           … SDK がどの世代でも繋げなかったときだけ使う、最小の Streamable HTTP クライアント（initialize / tools/list / tools/call）。
 *                             probe が「initialize に成功する」と確認できたサーバーにだけ使う。SDK と同じメソッド名で hub から使える。
 *
 *   longFetch / longDispatcher … Node の fetch（undici）は既定で「ヘッダー 5 分・本文 5 分」何も届かないと切る（HeadersTimeoutError / BodyTimeoutError）。
 *                             tools/call は進捗を出さないまま 5 分を超えることがあるので、その上限だけを外した fetch。hub が SDK の transport に渡す fetch にも使える。
 *                             追加の依存は無い（Node 同梱の undici の Agent を、グローバル dispatcher の constructor から作る）。LUMEN_HTTP_LONG_FETCH=off で無効。
 *
 * 秘密（headers / bearer）は、ここで作る文言には含めない（hub がさらに伏字にする）。
 */

const policy = require("./mcpPolicy");   // 再試行の規則（段階ごとの回数・待ち時間・何を再試行しないか）は 1 か所に集約している

const ACCEPT = "application/json, text/event-stream";

/* ------------------------------------------------------------
   長い呼び出し用の fetch
   ------------------------------------------------------------ */

let _longDispatcher;   // undefined = 未作成 / null = 作れなかった
let _longWarned = false;

/**
 * headersTimeout / bodyTimeout を 0（無効）にした undici dispatcher。作れなければ undefined（= 既定の fetch のまま）。
 * グローバル dispatcher と同じ種類・同じ版の constructor で作るので、組み込みの fetch と必ず噛み合う。
 * NODE_USE_ENV_PROXY=1 のときのグローバル dispatcher は EnvHttpProxyAgent で、同じ種類で作るのでプロキシ経由のまま。
 * 呼び出しの上限は、呼び出し側の wall / idle タイマー（createCallWatch / withTimeout）が持つ。
 */
function longDispatcher() {
  if (_longDispatcher !== undefined) return _longDispatcher || undefined;
  _longDispatcher = null;
  if (String(process.env.LUMEN_HTTP_LONG_FETCH || "").toLowerCase() === "off") return undefined;
  try {
    fetch("data:,").catch(() => {});   // 呼ぶだけでグローバル dispatcher が作られる（接続はしない）
    const g = globalThis[Symbol.for("undici.globalDispatcher.1")];
    const C = g && g.constructor;
    // 既定は無制限（0）。上限を付けたいときだけ LUMEN_HTTP_HEADERS_TIMEOUT_MS / LUMEN_HTTP_BODY_TIMEOUT_MS（ミリ秒）を指定する。
    const ms = (k) => { const v = Number(process.env[k]); return Number.isFinite(v) && v > 0 ? Math.floor(v) : 0; };
    if (typeof C === "function" && (C.name === "Agent" || C.name === "EnvHttpProxyAgent")) _longDispatcher = new C({ headersTimeout: ms("LUMEN_HTTP_HEADERS_TIMEOUT_MS"), bodyTimeout: ms("LUMEN_HTTP_BODY_TIMEOUT_MS") });
  } catch (_) { /* 作れなければ既定の fetch */ }
  if (!_longDispatcher && !_longWarned) {
    _longWarned = true;
    console.warn("[Lumen] 警告: 長時間用の fetch を用意できません（Node 同梱の undici が見つからない、または別の dispatcher が設定済み）。無応答が 5 分を超える呼び出しは Node の既定で切れます。");
  }
  return _longDispatcher || undefined;
}

/** fetch と同じ形。init.dispatcher があればそれを優先する。 */
function longFetch(url, init) {
  const d = longDispatcher();
  return fetch(url, d ? Object.assign({ dispatcher: d }, init) : init);
}
const PROTO_LATEST = "2025-11-25";
const SNIPPET = 300;

class ProbeError extends Error {
  /** o: { auth?, fatal?, kind? } — auth=true は state=auth_required、fatal=true は自動再試行なし */
  constructor(message, o) {
    super(message);
    this.name = "ProbeError";
    Object.assign(this, o || {});
  }
}

/* ------------------------------------------------------------
   エラーの説明
   ------------------------------------------------------------ */

function chainOf(e) {
  const out = [];
  const seen = new Set();
  let x = e;
  for (let i = 0; x && typeof x === "object" && i < 6 && !seen.has(x); i++) {
    seen.add(x);
    out.push(x);
    x = x.cause || (Array.isArray(x.errors) && x.errors[0]) || null;   // AggregateError（IPv4 / IPv6 の両方で失敗したとき）
  }
  return out;
}

/** fetch の例外の cause の連鎖から、最初の文字列コード（ENOTFOUND / ECONNREFUSED / CERT_* / UND_ERR_* など）を返す。無ければ ""。 */
function causeCodeOf(e) {
  const codes = chainOf(e).map((x) => (typeof x.code === "string" ? x.code : "")).filter(Boolean);
  return codes[0] || "";
}

function proxyEnvNames() {
  return ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"].filter((k) => process.env[k]);
}

/** fetch の例外 → 原因と対処の 1〜2 文。 */
function explainNetworkError(e) {
  const chain = chainOf(e);
  const codes = chain.map((x) => (typeof x.code === "string" ? x.code : "")).filter(Boolean);
  const msgs = [];
  chain.forEach((x) => { const m = String(x.message || "").trim(); if (m && !msgs.includes(m)) msgs.push(m); });
  const all = codes.join(" ") + " " + msgs.join(" ");
  const raw = (msgs.filter((m) => !/^fetch failed$/i.test(m)).join(" ← ") || msgs.join(" ← ") || "不明なエラー") + (codes.length && !msgs.join(" ").includes(codes[0]) ? "（" + codes[0] + "）" : "");
  let why;
  if (/ENOTFOUND|EAI_AGAIN|EAI_NODATA|getaddrinfo/i.test(all)) why = "ホスト名を DNS で解決できません。URL のホスト名・ネットワーク・DNS（VPN や社内 DNS を含む）を確認してください。";
  else if (/ECONNREFUSED/i.test(all)) why = "接続を拒否されました。ポートやホストが違うか、サーバーが起動していません。";
  else if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS|SSL|DEPTH_ZERO|altnames/i.test(all)) why = "TLS 証明書を検証できません。社内プロキシ等の TLS 検査があるなら、その CA を NODE_EXTRA_CA_CERTS（または NODE_USE_SYSTEM_CA=1）で実行コアに渡して再起動してください。";
  else if (/UND_ERR_HEADERS_TIMEOUT|UND_ERR_BODY_TIMEOUT|Headers Timeout|Body Timeout/i.test(all)) why = "サーバーから何も返らないまま、Node の既定の上限（5 分）に達して切れました。長い呼び出しは、実行コアが longFetch（mcpHttp.js）で上限を外します。LUMEN_HTTP_LONG_FETCH=off になっていないか確認してください。";
  else if (/ETIMEDOUT|UND_ERR_CONNECT_TIMEOUT|ENETUNREACH|EHOSTUNREACH|timed? ?out/i.test(all)) why = "接続が時間切れ、または経路がありません。ファイアウォール・VPN・プロキシを確認してください。";
  else if (/ECONNRESET|EPIPE|UND_ERR_SOCKET|socket hang up|other side closed/i.test(all)) why = "接続を途中で切られました。セキュリティソフト・プロキシ・サーバー側の制限の可能性があります。";
  else why = "";
  const px = proxyEnvNames();
  const proxy = px.length && !process.env.NODE_USE_ENV_PROXY
    ? " ※ " + px[0] + " が設定されていますが、Node の fetch は既定でプロキシ環境変数を使いません。Node 22.21 / 24 以降なら NODE_USE_ENV_PROXY=1 を付けて実行コアを起動してください。"
    : "";
  return raw + (why ? " — " + why : "") + proxy;
}

/** WWW-Authenticate は値（URL・realm）を出さず、方式と項目名だけにする（伏字処理が誤って切らないように / 余計な情報を出さないように）。 */
function challengeSummary(h) {
  const m = /^\s*([A-Za-z][A-Za-z0-9_-]*)/.exec(String(h || ""));
  if (!m) return "";
  const names = Array.from(new Set(Array.from(String(h).matchAll(/([A-Za-z_][A-Za-z0-9_-]*)\s*=/g)).map((x) => x[1]))).slice(0, 6);
  return m[1] + (names.length ? "（" + names.join(", ") + "）" : "");
}

const redactUrl = (u) => String(u).replace(/([?&][^=&]*(?:key|token|secret|auth|pass|sig)[^=&]*=)[^&]+/gi, "$1***").replace(/\/\/[^/@]*@/, "//***@");

/* ------------------------------------------------------------
   応答の読み取り（JSON / SSE 両対応）
   ------------------------------------------------------------ */

function sseParser(onEvent) {
  let buf = "";
  let ev = { event: "message", data: [] };
  const flush = () => { if (ev.data.length) onEvent({ event: ev.event, data: ev.data.join("\n") }); ev = { event: "message", data: [] }; };
  const push = (chunk) => {
    buf += chunk;
    for (;;) {
      const m = /\r\n|\n|\r/.exec(buf);
      if (!m) break;
      if (m[0] === "\r" && m.index + 1 === buf.length) break;   // 末尾の \r は \r\n の前半かもしれない。続きを待つ
      const line = buf.slice(0, m.index);
      buf = buf.slice(m.index + m[0].length);
      if (line === "") { flush(); continue; }
      if (line[0] === ":") continue;
      const k = line.indexOf(":");
      const field = k < 0 ? line : line.slice(0, k);
      const val = k < 0 ? "" : line.slice(k + 1).replace(/^ /, "");
      if (field === "event") ev.event = val; else if (field === "data") ev.data.push(val);
    }
  };
  return { push, end() { if (buf) push("\n"); flush(); } };
}

/** Response から JSON-RPC の返答（id が一致する result / error）を取り出す。見つからなければ null。 */
async function readRpcResponse(res, id, onChunk) {
  const ct = String(res.headers.get("content-type") || "").toLowerCase();
  const matches = (m) => m && typeof m === "object" && !Array.isArray(m) && (m.result !== undefined || m.error !== undefined) && (id == null || m.id === id);
  if (ct.includes("text/event-stream")) {
    if (!res.body) return null;
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let found = null;
    const p = sseParser((e) => {
      if (found) return;
      let j; try { j = JSON.parse(e.data); } catch (_) { return; }
      (Array.isArray(j) ? j : [j]).forEach((m) => { if (!found && matches(m)) found = m; });
    });
    try {
      while (!found) {
        const r = await reader.read();
        if (r.done) { p.end(); break; }
        if (typeof onChunk === "function") { try { onChunk(); } catch (_) { /* 通知側の例外で止めない */ } }   // 進捗通知・ping も「生きている」印（createCallWatch.touch）
        p.push(dec.decode(r.value, { stream: true }));
      }
    } finally { try { await reader.cancel(); } catch (_) { /* 終了済み */ } }
    return found;
  }
  const text = await res.text();
  let j; try { j = JSON.parse(text); } catch (_) { const e = new Error("JSON として読めない応答です: " + text.slice(0, SNIPPET)); e.notJson = true; e.body = text.slice(0, SNIPPET); throw e; }
  return (Array.isArray(j) ? j : [j]).find(matches) || null;
}

function mergeHeaders(base, o) {
  const h = Object.assign({}, base);
  Object.keys((o && o.headers) || {}).forEach((k) => { h[k] = o.headers[k]; });
  if (o && o.bearer && !Object.keys(h).some((k) => k.toLowerCase() === "authorization")) h.Authorization = "Bearer " + o.bearer;
  return h;
}

function withTimeout(ms, outer) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(Object.assign(new Error("timeout"), { name: "TimeoutError" })), ms);
  let onAbort = null;
  if (outer) { if (outer.aborted) ac.abort(outer.reason); else { onAbort = () => ac.abort(outer.reason); outer.addEventListener("abort", onAbort, { once: true }); } }
  return { signal: ac.signal, done() { clearTimeout(timer); if (outer && onAbort) outer.removeEventListener("abort", onAbort); }, isTimeout: () => ac.signal.aborted && !(outer && outer.aborted) };
}

/* ------------------------------------------------------------
   probe
   ------------------------------------------------------------ */

/**
 * 到達性・認証・応答形式の診断。opts: { headers?, bearer?, timeoutMs?, version? }
 * 戻り値: { kind, url, status, contentType, elapsedMs, initOk, protocolVersion, serverInfo, wwwAuthenticate, session, note, body, network?, causeCode? }
 */
async function probe(url, opts) {
  opts = opts || {};
  const t0 = Date.now();
  const out = { kind: "network", url: redactUrl(url), status: 0, contentType: "", elapsedMs: 0, initOk: false, protocolVersion: null, serverInfo: null, wwwAuthenticate: "", session: false, note: "", body: "" };
  const finish = () => { out.elapsedMs = Date.now() - t0; return out; };
  const body = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: PROTO_LATEST, capabilities: {}, clientInfo: { name: "lumen-probe", version: String(opts.version || "0") } } };
  const t = withTimeout(opts.timeoutMs || 15000, opts.signal);
  let res;
  try {
    res = await fetch(url, { method: "POST", headers: mergeHeaders({ "Content-Type": "application/json", Accept: ACCEPT }, opts), body: JSON.stringify(body), signal: t.signal, redirect: "follow" });
  } catch (e) {
    t.done();
    out.kind = "network";
    out.network = t.isTimeout() ? "応答が " + Math.round((opts.timeoutMs || 15000) / 1000) + " 秒以内に返りませんでした。" : explainNetworkError(e);
    out.causeCode = t.isTimeout() ? "ETIMEDOUT" : causeCodeOf(e);
    out.note = out.network;
    return finish();
  }
  out.status = res.status;
  out.contentType = String(res.headers.get("content-type") || "");
  const challenge = String(res.headers.get("www-authenticate") || "").slice(0, 600);
  out.wwwAuthenticate = challengeSummary(challenge);
  out.oauthHint = /resource_metadata|authorization_uri|oauth/i.test(challenge);
  out.session = !!res.headers.get("mcp-session-id");
  let msg = null, text = "";
  try {
    if (res.status >= 200 && res.status < 300) msg = await readRpcResponse(res, 1);
    else {
      text = await res.text().catch(() => "");
      try { const j = JSON.parse(text); msg = (Array.isArray(j) ? j : [j]).find((m) => m && m.error !== undefined) || null; } catch (_) { /* JSON でない本文は msg なしのまま扱う */ }
    }
  } catch (e) {
    text = e.body || "";
    if (!e.notJson) { out.kind = "network"; out.network = t.isTimeout() ? "応答の途中で時間切れになりました。" : explainNetworkError(e); out.causeCode = t.isTimeout() ? "ETIMEDOUT" : causeCodeOf(e); out.note = out.network; t.done(); return finish(); }
  }
  t.done();
  out.body = String(text || "").replace(/\s+/g, " ").slice(0, SNIPPET);
  if (res.status === 401 || res.status === 403) { out.kind = "auth"; return finish(); }
  if (msg && msg.result && typeof msg.result === "object") {
    out.kind = "ok"; out.initOk = true;
    out.protocolVersion = msg.result.protocolVersion || null;
    out.serverInfo = msg.result.serverInfo ? { name: msg.result.serverInfo.name, version: msg.result.serverInfo.version } : null;
    // probe で作ったセッションは閉じておく（サーバー側に残さない）
    const sid = res.headers.get("mcp-session-id");
    if (sid) fetch(url, { method: "DELETE", headers: mergeHeaders({ "Mcp-Session-Id": sid }, opts), signal: AbortSignal.timeout(3000) }).catch(() => {});
    return finish();
  }
  if (msg && msg.error) { out.kind = "mcp-error"; out.note = "MCP エラー: " + String(msg.error.message || msg.error.code || "").slice(0, 160); return finish(); }
  if (res.status >= 200 && res.status < 300) { out.kind = "not-mcp"; out.note = "MCP の応答ではありません（Content-Type: " + (out.contentType || "なし") + "）。URL が MCP エンドポイント（/mcp など）か確認してください。"; return finish(); }
  out.kind = "http-error";
  // 404 / 405 / 400 などは、旧 HTTP+SSE（GET でストリームを張る形式）の可能性があるので GET でも確かめる
  if ([400, 404, 405, 406, 410, 415].includes(res.status)) {
    const s = await probeLegacySse(url, opts).catch(() => false);
    if (s) { out.kind = "sse"; out.note = "旧 HTTP+SSE（GET でイベントストリームを張る形式）のサーバーです。"; }
  }
  return finish();
}

async function probeLegacySse(url, opts) {
  const t = withTimeout(8000, opts && opts.signal);
  try {
    const res = await fetch(url, { method: "GET", headers: mergeHeaders({ Accept: "text/event-stream" }, opts), signal: t.signal });
    if (!(res.status >= 200 && res.status < 300) || !String(res.headers.get("content-type") || "").includes("text/event-stream") || !res.body) { try { await res.body.cancel(); } catch (_) { /* 無し */ } return false; }
    const reader = res.body.getReader(); const dec = new TextDecoder();
    let seen = false;
    const p = sseParser((e) => { if (e.event === "endpoint") seen = true; });
    try { while (!seen) { const r = await reader.read(); if (r.done) break; p.push(dec.decode(r.value, { stream: true })); } } finally { try { await reader.cancel(); } catch (_) { /* 終了済み */ } }
    return seen;
  } finally { t.done(); }
}

/** probe の結果が「SDK を試す前に止めるべき失敗」なら ProbeError を、続行してよければ null を返す。 */
function probeFailure(pr, o) {
  o = o || {};
  const hasCred = !!(o.hasCredentials);
  if (pr.kind === "network") return new ProbeError("サーバーに到達できません: " + pr.network, { kind: "network", causeCode: pr.causeCode || "" });
  if (pr.kind === "auth") {
    const oauth = !!pr.oauthHint;
    const base = "認証が必要です（HTTP " + pr.status + "）" + (hasCred ? "。設定済みの headers / bearerToken は拒否されました。値・有効期限・権限を確認してください。" : "。");
    const how = hasCred ? "" : oauth
      ? "このサーバーは OAuth（ブラウザでの認可）を案内しています。実行コアは OAuth の対話認可に未対応なので、API キー / トークンをヘッダーで受け付けるサーバーなら bearerToken（例: \"${API_KEY}\"）か headers に Authorization を設定してください。"
      : "API キー / トークンを bearerToken（例: \"${API_KEY}\"）か headers に設定してください。";
    return new ProbeError(base + how + (pr.wwwAuthenticate ? "\nWWW-Authenticate: " + pr.wwwAuthenticate : ""), { auth: true, kind: "auth" });
  }
  if (pr.kind === "not-mcp") return new ProbeError(pr.note, { fatal: true, kind: "not-mcp" });
  if (pr.kind === "http-error") {
    const s = pr.status;
    const hint = s === 404 ? "URL のパスが違う可能性があります（多くは /mcp。旧方式は /sse）。"
      : s === 429 ? "リクエスト過多（レート制限）です。しばらく待って再接続してください。"
      : s === 405 ? "このエンドポイントは POST を受け付けません。URL のパスが違うか、旧 SSE 専用のサーバーです（多くは /mcp が正しいパスです）。"
      : s === 410 ? "このサーバーは旧 SSE（/sse）を廃止しました。URL を /mcp（Streamable HTTP）に変更するか、.mcp.json の type を \"sse\" から外してください。"
      : s >= 500 ? "サーバー側の障害の可能性があります。時間をおいて再接続してください。"
      : "";
    return new ProbeError("サーバーが HTTP " + s + " を返しました。" + hint + (pr.body ? "\n応答: " + pr.body : ""), { kind: "http", status: s, fatal: s === 404 || s === 410 });
  }
  return null;
}

/* ------------------------------------------------------------
   RawHttpClient — 最小の Streamable HTTP クライアント（SDK が繋げなかったときの最後の手段）
   ------------------------------------------------------------ */

class RawHttpClient {
  constructor(o) {
    this.url = o.url;
    this.headers = o.headers || {};
    this.bearer = o.bearer || "";
    this.clientInfo = o.clientInfo || { name: "lumen-core", version: "0" };
    this.sessionId = null;
    this.protocolVersion = null;
    this.serverInfo = null;
    this.instructions = null;
    this._id = 1;
    this._reinit = null;
    this.closed = false;
    this.retry = o.retry || {};   // { sleep, rng } … テスト用。通常は未指定（実際の待ち時間・乱数を使う）
    this.fetch = o.fetch || longFetch;   // テストで差し替え可能。既定は 5 分の無応答上限を外した fetch
  }

  /** 接続・一覧取得の失敗のうち「一時的なもの」だけを、mcpPolicy の規則で再試行する。tools/call は副作用があるので、ここでは再送しない。 */
  _retrying(phase, signal, fn) {
    return policy.withRetry(fn, Object.assign({ phase, transport: "http", signal }, this.retry));
  }

  _hdr(extra) {
    const h = mergeHeaders({ "Content-Type": "application/json", Accept: ACCEPT }, { headers: this.headers, bearer: this.bearer });
    if (this.protocolVersion) h["MCP-Protocol-Version"] = this.protocolVersion;
    if (this.sessionId) h["Mcp-Session-Id"] = this.sessionId;
    return Object.assign(h, extra || {});
  }

  async _post(body, o) {
    const t = withTimeout(o.timeout || 60000, o.signal);
    try {
      const res = await this.fetch(this.url, { method: "POST", headers: this._hdr(), body: JSON.stringify(body), signal: t.signal, redirect: "follow" });
      return { res, t };
    } catch (e) {
      t.done();
      if (o.signal && o.signal.aborted) { const a = new Error("中断されました。"); a.name = "AbortError"; throw a; }
      throw Object.assign(new Error(t.isTimeout() ? "応答が時間切れです。" : explainNetworkError(e)), { cause: e });
    }
  }

  async _rpc(method, params, o) {
    o = o || {};
    const id = this._id++;
    const { res, t } = await this._post({ jsonrpc: "2.0", id, method, params }, o);
    try {
      if (res.status === 401 || res.status === 403) { const e = new Error("認証が必要です（HTTP " + res.status + "）。"); e.httpStatus = res.status; throw e; }
      if (res.status === 404 && this.sessionId && !o.retried) {
        // セッション切れ。1 回だけ initialize し直して送り直す
        try { await res.body.cancel(); } catch (_) { /* 無し */ }
        this.sessionId = null; this.protocolVersion = null;
        await this.connect(null, { timeout: o.timeout, signal: o.signal });
        return this._rpc(method, params, Object.assign({}, o, { retried: true }));
      }
      if (!res.ok) { const txt = await res.text().catch(() => ""); const e = new Error("HTTP " + res.status + (txt ? ": " + txt.replace(/\s+/g, " ").slice(0, 200) : "")); e.httpStatus = res.status; throw e; }
      const sid = res.headers.get("mcp-session-id");
      if (sid && method === "initialize") this.sessionId = sid;
      let msg;
      try { msg = await readRpcResponse(res, id, o.onActivity); }
      catch (e) { if (o.signal && o.signal.aborted) { const a = new Error("中断されました。"); a.name = "AbortError"; throw a; } throw e; }
      if (!msg) {
        // SSE が結果の前に終わった = 通信の途中切断（一時的）。JSON なのに結果が無い = サーバーの不具合（再試行しない）。
        const sse = String(res.headers.get("content-type") || "").toLowerCase().includes("text/event-stream");
        const err = new Error(sse ? "応答の途中で接続が閉じられました（" + method + " の結果が届く前にストリームが終わりました）。" : "応答に " + method + " の結果が含まれていません。");
        if (sse) err.streamEnded = true;
        throw err;
      }
      if (msg.error) { const e = new Error(String(msg.error.message || "MCP エラー")); e.code = msg.error.code; e.name = "McpError"; throw e; }
      return msg.result;
    } finally { t.done(); }
  }

  async _notify(method, params) {
    const { res, t } = await this._post({ jsonrpc: "2.0", method, params }, { timeout: 15000 });
    try { try { await res.body.cancel(); } catch (_) { /* 本文なし */ } } finally { t.done(); }
  }

  /** SDK の client.connect(transport, { timeout }) と同じ位置づけ（transport は使わない）。 */
  async connect(_transport, o) {
    o = o || {};
    const r = await this._retrying("first-connect", o.signal, () => this._rpc("initialize", { protocolVersion: PROTO_LATEST, capabilities: {}, clientInfo: this.clientInfo }, { timeout: o.timeout || 60000, signal: o.signal, retried: true }));
    this.protocolVersion = (r && r.protocolVersion) || PROTO_LATEST;
    this.serverInfo = (r && r.serverInfo) || null;
    this.instructions = (r && typeof r.instructions === "string") ? r.instructions : null;
    await this._notify("notifications/initialized").catch(() => { /* 通知の失敗は致命的でない */ });
  }

  async listTools() {
    const tools = [];
    let cursor;
    for (let i = 0; i < 50; i++) {
      const r = await this._retrying("discovery", undefined, () => this._rpc("tools/list", cursor ? { cursor } : {}, { timeout: 60000 }));
      (r && Array.isArray(r.tools) ? r.tools : []).forEach((x) => tools.push(x));
      cursor = r && r.nextCursor;
      if (!cursor) break;
    }
    return { tools };
  }

  /** o: { timeout, signal, onActivity } … onActivity は応答の chunk が届くたびに呼ぶ（createCallWatch の touch を渡す）。 */
  callTool(params, o) {
    o = o || {};
    return this._rpc("tools/call", { name: params.name, arguments: params.arguments || {} }, { timeout: o.timeout || 30 * 60 * 1000, signal: o.signal, onActivity: o.onActivity });
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    if (this.sessionId) {
      try { await fetch(this.url, { method: "DELETE", headers: this._hdr(), signal: AbortSignal.timeout(3000) }); } catch (_) { /* 切断済み */ }
    }
    this.sessionId = null;
  }

  getProtocolEra() { return "legacy"; }
  getNegotiatedProtocolVersion() { return this.protocolVersion; }
  getServerVersion() { return this.serverInfo; }
  getInstructions() { return this.instructions; }
}

module.exports = { challengeSummary, probe, probeFailure, explainNetworkError, causeCodeOf, RawHttpClient, ProbeError, redactUrl, readRpcResponse, sseParser, longFetch, longDispatcher, PROTO_LATEST };
