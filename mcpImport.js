"use strict";

/**
 * mcpImport.js — 貼り付けられた MCP 設定を、Lumen の .mcp.json 形式へ正規化する（純粋関数のみ。SDK にも fs にも触れない）
 * ============================================================
 * 受け付ける貼り付け:
 *   JSON      : { "mcpServers": {…} }（Claude Desktop / Claude Code / Cursor / Windsurf / Cline）
 *               { "servers": {…} }（VS Code .vscode/mcp.json）/ { "mcp": { "servers": {…} } }（VS Code settings.json）
 *               { "mcp": { "名前": { "type": "local" | "remote", … } } }（OpenCode）/ { "context_servers": {…} }（Zed）
 *               サーバー 1 件だけ { "command": … } / { "url": … }、"名前": {…} の断片、名前→定義のマップ、配列
 *               コメント・末尾カンマ・全角引用符・``` フェンス付きでも読む
 *   TOML      : [mcp_servers.名前] …（Codex の config.toml）
 *   コマンド  : claude mcp add / add-json、codex mcp add、gemini mcp add、npx … / uvx … / docker run … の 1 行、URL だけ
 * 出力の正規形:
 *   stdio : { command, args?, env?, cwd?, disabled?, protocol?, startupTimeoutMs? }
 *   http  : { type: "http", url, headers?, bearerToken?, … }     … Streamable HTTP
 *   sse   : { type: "sse",  url, headers?, bearerToken?, … }     … 旧 HTTP+SSE
 * 秘密（env / headers / bearerToken の値）は maskSpec() で伏字にして画面へ返す。伏字のまま保存された値は restoreMasked() が元の値へ戻す。
 */

const MASK = "••••••••";
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;
const ENV_REF_RE = /^\$\{[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?\}$/;
const SHELL_CMD_RE = /^(claude|codex|gemini|qwen|amp|opencode|cursor|code|vscode)(\s+|$)/i;
const LAUNCHERS = /^(npx|bunx|pnpx|uvx|uv|pipx|node|deno|bun|python3?|py|docker|podman|dotnet|java|cargo|go|ruby|php|cmd|powershell|pwsh|bash|sh)(\.exe|\.cmd)?$/i;

/* ------------------------------------------------------------
   字句・JSON まわり
   ------------------------------------------------------------ */

/** シェル風の分割（引用符・\ 区切りの継続行に対応。Windows のパスの \ は壊さない）。 */
function tokenize(str) {
  const s = String(str).replace(/\\\r?\n/g, " ");
  const out = [];
  let cur = "", has = false, q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === q) { q = null; continue; }
      if (q === '"' && c === "\\" && (s[i + 1] === '"' || s[i + 1] === "\\")) { cur += s[++i]; continue; }
      cur += c;
      continue;
    }
    if (c === '"' || c === "'") { q = c; has = true; continue; }
    if (c === "\\" && (s[i + 1] === " " || s[i + 1] === '"' || s[i + 1] === "'")) { cur += s[++i]; has = true; continue; }
    if (/\s/.test(c)) { if (has || cur) { out.push(cur); cur = ""; has = false; } continue; }
    cur += c; has = true;
  }
  if (q) throw new Error("引用符が閉じていません。");
  if (has || cur) out.push(cur);
  return out;
}

/** コメントと末尾カンマを取り除く（文字列の中は触らない）。 */
function stripJsonish(text) {
  let out = "", i = 0, inStr = false;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (inStr) {
      out += c;
      if (c === "\\") { out += text[i + 1] || ""; i += 2; continue; }
      if (c === '"') inStr = false;
      i++; continue;
    }
    if (c === '"') { inStr = true; out += c; i++; continue; }
    if (c === "/" && text[i + 1] === "/") { while (i < n && text[i] !== "\n") i++; continue; }
    if (c === "/" && text[i + 1] === "*") { i += 2; while (i < n && !(text[i] === "*" && text[i + 1] === "/")) i++; i += 2; continue; }
    out += c; i++;
  }
  // 末尾カンマ
  let res = "", j = 0, str = false;
  while (j < out.length) {
    const c = out[j];
    if (str) { res += c; if (c === "\\") { res += out[j + 1] || ""; j += 2; continue; } if (c === '"') str = false; j++; continue; }
    if (c === '"') { str = true; res += c; j++; continue; }
    if (c === ",") {
      let k = j + 1;
      while (k < out.length && /\s/.test(out[k])) k++;
      if (out[k] === "}" || out[k] === "]") { j++; continue; }
    }
    res += c; j++;
  }
  return res;
}

function tryParse(text) {
  const attempts = [
    (t) => t,
    (t) => stripJsonish(t),
    (t) => stripJsonish(t.replace(/[\u201C\u201D\u201E\u201F]/g, '"').replace(/[\u2018\u2019]/g, "'")),
  ];
  let lastErr = null;
  for (const f of attempts) {
    try { return { ok: true, value: JSON.parse(f(text)) }; } catch (e) { lastErr = e; }
  }
  return { ok: false, error: lastErr && lastErr.message };
}

/** 文字列を考慮して、トップレベルの {...} をそれぞれ切り出す。 */
function splitTopLevelObjects(text) {
  const out = [];
  let depth = 0, start = -1, str = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (str) { if (c === "\\") i++; else if (c === '"') str = false; continue; }
    if (c === '"') { str = true; continue; }
    if (c === "{") { if (depth === 0) start = i; depth++; }
    else if (c === "}") { if (depth > 0) { depth--; if (depth === 0 && start >= 0) { out.push(text.slice(start, i + 1)); start = -1; } } }
  }
  return out;
}

function chunksOf(text) {
  const t = String(text).replace(/^\uFEFF/, "");
  const fenced = Array.from(t.matchAll(/```[A-Za-z0-9_+-]*[ \t]*\r?\n([\s\S]*?)```/g)).map((m) => m[1]);
  return fenced.length ? fenced : [t];
}

/* ------------------------------------------------------------
   TOML（Codex の [mcp_servers.*] に必要な範囲だけ）
   ------------------------------------------------------------ */

function stripTomlComment(line) {
  let q = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === "\\" && q === '"') i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") { q = c; continue; }
    if (c === "#") return line.slice(0, i);
  }
  return line;
}

function bracketBalance(s) {
  let d = 0, q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === "\\" && q === '"') i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") { q = c; continue; }
    if (c === "[" || c === "{") d++;
    else if (c === "]" || c === "}") d--;
  }
  return d;
}

function parseTomlScalar(v) {
  v = v.trim();
  if (v[0] === '"') { try { return JSON.parse(v); } catch (_) { return v.slice(1, -1); } }
  if (v[0] === "'") return v.slice(1, -1);
  if (v === "true") return true;
  if (v === "false") return false;
  if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
  return v;
}

function splitTomlList(body) {
  const parts = [];
  let cur = "", d = 0, q = null;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (q) { cur += c; if (c === "\\" && q === '"') { cur += body[++i] || ""; continue; } if (c === q) q = null; continue; }
    if (c === '"' || c === "'") { q = c; cur += c; continue; }
    if (c === "[" || c === "{") d++;
    if (c === "]" || c === "}") d--;
    if (c === "," && d === 0) { parts.push(cur); cur = ""; continue; }
    cur += c;
  }
  if (cur.trim()) parts.push(cur);
  return parts.map((p) => p.trim()).filter(Boolean);
}

function parseTomlValue(v) {
  v = v.trim();
  if (v[0] === "[") return splitTomlList(v.replace(/^\[/, "").replace(/\]\s*$/, "")).map(parseTomlValue);
  if (v[0] === "{") {
    const o = {};
    splitTomlList(v.replace(/^\{/, "").replace(/\}\s*$/, "")).forEach((p) => {
      const m = /^("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_.-]+)\s*=\s*([\s\S]+)$/.exec(p);
      if (m) o[String(parseTomlScalar(m[1]))] = parseTomlValue(m[2]);
    });
    return o;
  }
  return parseTomlScalar(v);
}

function parseTomlServers(text) {
  const servers = {};
  let target = null;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    let ln = stripTomlComment(lines[i]).trim();
    if (!ln) continue;
    let m = /^\[\s*mcp_servers\.(?:"([^"]+)"|([A-Za-z0-9_-]+))(?:\.(env|http_headers|env_http_headers|headers))?\s*\]$/.exec(ln);
    if (m) {
      const name = m[1] || m[2];
      servers[name] = servers[name] || {};
      if (m[3]) { servers[name][m[3]] = servers[name][m[3]] || {}; target = servers[name][m[3]]; } else target = servers[name];
      continue;
    }
    if (/^\[/.test(ln)) { target = null; continue; }
    m = /^("(?:[^"\\]|\\.)*"|[A-Za-z0-9_.-]+)\s*=\s*([\s\S]*)$/.exec(ln);
    if (!m || !target) continue;
    let val = m[2];
    while (bracketBalance(val) > 0 && i + 1 < lines.length) val += "\n" + stripTomlComment(lines[++i]);
    target[String(parseTomlScalar(m[1]))] = parseTomlValue(val);
  }
  return servers;
}

/* ------------------------------------------------------------
   名前
   ------------------------------------------------------------ */

function sanitizeName(raw) {
  let s = String(raw == null ? "" : raw).trim();
  s = s.replace(/[^A-Za-z0-9_-]+/g, "-").replace(/_{2,}/g, "_").replace(/^[^A-Za-z0-9]+/, "").replace(/-{2,}/g, "-");
  s = s.slice(0, 32).replace(/[-_]+$/, "");
  return NAME_RE.test(s) && !s.includes("__") ? s : "";
}

function stripGeneric(base, scope) {
  let b = base;
  const tries = [/^mcp[-_]server[-_]/i, /^server[-_]/i, /^mcp[-_]/i, /[-_.]mcp[-_]server$/i, /[-_.]mcp$/i, /[-_]server$/i];
  tries.forEach((re) => { const n = b.replace(re, ""); if (n.length >= 2) b = n; });
  if (/^(mcp|server|mcp-server|mcp_server)$/i.test(b) && scope) b = scope;
  return b;
}

function nameFromPackage(p) {
  let s = String(p || "").trim();
  if (!s) return "";
  s = s.replace(/^[a-z+]+:\/\//i, "").replace(/[?#].*$/, "");
  let scope = "";
  const parts = s.split(/[\\/]/).filter(Boolean);
  let last = parts.pop() || "";
  if (parts.length && parts[parts.length - 1].startsWith("@")) scope = parts[parts.length - 1].slice(1);
  last = last.replace(/@[^@]*$/, (m, off) => (off > 0 ? "" : m)).replace(/:[A-Za-z0-9._-]+$/, "").replace(/\.(js|mjs|cjs|ts|py)$/i, "");
  if (/^(index|main|server|cli|app|run|__main__)$/i.test(last) && parts.length) last = parts[parts.length - 1].replace(/^@/, "");
  return stripGeneric(last, scope);
}

function deriveName(spec) {
  let base = "";
  try {
    if (spec.command !== undefined) {
      const cmd = String(spec.command).split(/[\\/]/).pop().replace(/\.(exe|cmd|bat)$/i, "");
      const args = Array.isArray(spec.args) ? spec.args : [];
      let cand = null;
      if (/^(npx|bunx|pnpx|uvx|pipx)$/i.test(cmd)) cand = args.find((a) => !/^-/.test(a));
      else if (/^(docker|podman)$/i.test(cmd)) {
        const skipNext = new Set(["-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "-w", "--workdir", "--network", "--env-file", "-u", "--user", "--entrypoint"]);
        const from = args.indexOf("run") + 1;
        for (let i = from; i < args.length; i++) {
          if (skipNext.has(args[i])) { i++; continue; }
          if (/^-/.test(args[i])) continue;
          cand = args[i]; break;
        }
      } else if (/^(npm|pnpm|yarn|bun)$/i.test(cmd) && /^(exec|dlx|x)$/.test(args[0] || "")) cand = args.slice(1).find((a) => !/^-/.test(a));
      else if (/^py(thon3?)?$/i.test(cmd) && args.indexOf("-m") >= 0) cand = args[args.indexOf("-m") + 1];
      else if (/^(node|deno|bun|python3?|py)$/i.test(cmd)) cand = args.find((a) => !/^-/.test(a) && a !== "run");
      else cand = cmd;
      base = nameFromPackage(cand || cmd);
    } else if (spec.url) {
      const u = new URL(String(spec.url).replace(/\$\{[^}]*\}/g, "x"));
      const generic = new Set(["www", "api", "mcp", "app", "apps", "server", "servers", "com", "net", "org", "io", "dev", "ai", "co", "cloud", "tech", "run", "xyz"]);
      const labels = u.hostname.split(".").filter((l) => l && !generic.has(l.toLowerCase()));
      base = labels.length ? labels[0] : u.hostname.replace(/\./g, "-");
      if (/^(localhost|127|0|\[?::1\]?)$/.test(base) || /^\d+$/.test(base)) base = "local" + (u.port ? u.port : "");
    }
  } catch (_) { /* 既定名へ */ }
  return sanitizeName(base) || "mcp-server";
}

/* ------------------------------------------------------------
   1 サーバー分の正規化
   ------------------------------------------------------------ */

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function toStringMap(v, label, warn) {
  const out = {};
  if (Array.isArray(v)) {
    v.forEach((item) => {
      const m = /^([^=:]+)[=:]\s*([\s\S]*)$/.exec(String(item));
      if (m) out[m[1].trim()] = m[2];
    });
    return out;
  }
  if (!isObj(v)) { warn(label + " がオブジェクトではないため無視しました。"); return out; }
  Object.keys(v).forEach((k) => {
    const x = v[k];
    if (typeof x === "string") out[k] = x;
    else if (typeof x === "number" || typeof x === "boolean") out[k] = String(x);
    else warn(label + "「" + k + "」の値が文字列ではないため無視しました。");
  });
  return out;
}

function normalizeSpec(raw) {
  const warnings = [];
  const warn = (m) => warnings.push(m);
  if (!isObj(raw)) return { error: "定義がオブジェクトではありません。", warnings };
  const used = new Set(["name", "$schema"]);
  const pick = (...keys) => {
    let v;
    keys.forEach((k) => { if (raw[k] !== undefined) { used.add(k); if (v === undefined) v = raw[k]; } });
    return v;
  };

  let t = pick("type", "transport", "transportType");
  t = t === undefined ? "" : String(t).toLowerCase().replace(/[\s_]+/g, "-");
  const cmdRaw = pick("command", "cmd");
  const urlRaw = pick("url", "serverUrl", "httpUrl", "endpoint");
  const onlyHttpUrl = raw.httpUrl !== undefined && raw.url === undefined && raw.serverUrl === undefined;

  let kind;
  if (["stdio", "local", "process"].includes(t)) kind = "stdio";
  else if (["sse", "sse-only"].includes(t)) kind = "sse";
  else if (["http", "streamable-http", "streamablehttp", "streamable", "remote"].includes(t)) kind = "http";
  else if (t === "") kind = cmdRaw !== undefined ? "stdio" : urlRaw !== undefined ? "url" : "";
  else return { error: "type「" + String(t).slice(0, 30) + "」は未対応です（stdio / http / sse のいずれか）。", warnings };
  if (!kind) return { error: "command（stdio）か url（HTTP / SSE）のどちらかが必要です。", warnings };

  const spec = {};
  if (kind === "stdio") {
    if (cmdRaw === undefined) return { error: "stdio には command が必要です。", warnings };
    let command, args = pick("args", "arguments");
    let envExtra = null;
    if (Array.isArray(cmdRaw)) {
      command = String(cmdRaw[0] == null ? "" : cmdRaw[0]);
      args = cmdRaw.slice(1).map(String).concat(Array.isArray(args) ? args : []);
      warn("command が配列だったため、command と args に分けました。");
    } else if (isObj(cmdRaw)) {
      command = String(cmdRaw.path || cmdRaw.command || "");
      args = Array.isArray(cmdRaw.args) ? cmdRaw.args : args;
      if (isObj(cmdRaw.env)) envExtra = cmdRaw.env;
    } else command = String(cmdRaw).trim();
    if (typeof args === "string") { try { args = tokenize(args); } catch (e) { return { error: "args を分割できません: " + e.message, warnings }; } warn("args が文字列だったため、空白で分割しました。"); }
    if (args !== undefined && !Array.isArray(args)) { warn("args が配列ではないため無視しました。"); args = undefined; }
    if (!command) return { error: "command が空です。", warnings };
    if ((!args || !args.length) && /\s/.test(command) && !/[\\/]/.test(command)) {
      try { const tk = tokenize(command); command = tk[0]; args = tk.slice(1); warn("command に引数が含まれていたため、command と args に分けました。"); } catch (e) { return { error: "command を分割できません: " + e.message, warnings }; }
    }
    spec.command = command;
    if (args && args.length) spec.args = args.map((a) => (typeof a === "string" ? a : (typeof a === "number" || typeof a === "boolean") ? String(a) : JSON.stringify(a)));
    const envV = pick("env", "environment");
    const env = Object.assign({}, envExtra ? toStringMap(envExtra, "env", warn) : {}, envV !== undefined ? toStringMap(envV, "env", warn) : {});
    if (Object.keys(env).length) spec.env = env;
    const cwd = pick("cwd", "workingDirectory");
    if (typeof cwd === "string" && cwd.trim()) spec.cwd = cwd;
    if (urlRaw !== undefined) warn("command と url の両方があるため、url は無視しました。");
  } else {
    let url = urlRaw;
    if (typeof url !== "string" || !url.trim()) return { error: "url が必要です。", warnings };
    url = url.trim();
    if (!/\$\{/.test(url) && !/^https?:\/\//i.test(url)) return { error: "url は http:// または https:// で始まる必要があります。", warnings };
    if (kind === "url") {
      let path = "";
      try { path = new URL(url.replace(/\$\{[^}]*\}/g, "x")).pathname; } catch (_) { /* hub 側で検証 */ }
      if (!onlyHttpUrl && /\/sse\/?$/i.test(path)) { kind = "sse"; warn("URL が /sse で終わるため、旧 HTTP+SSE（type: \"sse\"）として扱います。違う場合は種類を変えてください。"); }
      else kind = "http";
    }
    spec.type = kind;
    spec.url = url;
    const h = Object.assign({}, toStringMap(pick("headers") || {}, "headers", warn), toStringMap(pick("http_headers") || {}, "http_headers", warn));
    const eh = pick("env_http_headers");
    if (isObj(eh)) Object.keys(eh).forEach((k) => { if (typeof eh[k] === "string") h[k] = "${" + eh[k] + "}"; });
    if (Object.keys(h).length) spec.headers = h;
    let bearer = pick("bearerToken", "bearer_token", "authToken");
    const bearerEnv = pick("bearer_token_env_var");
    if (bearer === undefined && typeof bearerEnv === "string" && bearerEnv) bearer = "${" + bearerEnv + "}";
    if (typeof bearer === "string" && bearer) spec.bearerToken = bearer;
    ["command", "args", "env", "cwd"].forEach((k) => { if (raw[k] !== undefined) used.add(k); });
  }

  if (raw.disabled === true || raw.enabled === false || raw.isActive === false || raw.active === false) spec.disabled = true;
  ["disabled", "enabled", "isActive", "active"].forEach((k) => { if (raw[k] !== undefined) used.add(k); });
  const proto = pick("protocol");
  if (typeof proto === "string" && (proto === "auto" || proto === "legacy" || /^\d{4}-\d{2}-\d{2}$/.test(proto))) { if (proto !== "auto") spec.protocol = proto; }
  else if (proto !== undefined) warn("protocol の値が不正なため無視しました（auto / legacy / 日付）。");
  let to = pick("startupTimeoutMs", "startup_timeout_ms");
  const toSec = pick("startup_timeout_sec", "startupTimeoutSec");
  if (to === undefined && toSec !== undefined) to = Number(toSec) * 1000;
  if (to !== undefined) { if (Number.isFinite(Number(to)) && Number(to) >= 1000) spec.startupTimeoutMs = Number(to); else warn("起動待ち時間の値が不正なため無視しました。"); }

  const unknown = Object.keys(raw).filter((k) => !used.has(k));
  if (unknown.length) warn("未対応の項目は無視しました: " + unknown.slice(0, 8).join(", ") + (unknown.length > 8 ? " …" : ""));
  if (JSON.stringify(spec).includes("${input:")) warn("VS Code の ${input:…} は使えません。環境変数 ${NAME} に置き換えてください。");
  return { spec, warnings };
}

/* ------------------------------------------------------------
   貼り付け全体の解釈
   ------------------------------------------------------------ */

const LISTING_KEYS = ["mcpServers", "mcp_servers", "servers", "context_servers", "mcpservers"];

function looksLikeServer(o) {
  return isObj(o) && (o.command !== undefined || o.url !== undefined || o.serverUrl !== undefined || o.httpUrl !== undefined || (typeof o.type === "string" && /^(stdio|sse|http|streamable|local|remote)/i.test(o.type)));
}

/** 解析済み JSON から { name|null, raw } の配列を取り出す。 */
function entriesFromValue(v, out, errors, warnings) {
  if (Array.isArray(v)) {
    v.forEach((item) => {
      if (looksLikeServer(item)) out.push({ name: typeof item.name === "string" ? item.name : null, raw: item });
      else if (isObj(item)) entriesFromValue(item, out, errors, warnings);
    });
    return;
  }
  if (!isObj(v)) { errors.push("JSON のルートがオブジェクトではありません。"); return; }
  for (const k of LISTING_KEYS) {
    if (isObj(v[k])) {
      if (k === "servers" && Array.isArray(v.inputs) && v.inputs.length) warnings.push("VS Code の inputs は取り込みません（${input:…} は未対応）。");
      Object.keys(v[k]).forEach((name) => out.push({ name, raw: v[k][name] }));
      return;
    }
    if (Array.isArray(v[k])) { entriesFromValue(v[k], out, errors, warnings); return; }
  }
  if (isObj(v.mcp)) {
    if (isObj(v.mcp.servers)) { Object.keys(v.mcp.servers).forEach((name) => out.push({ name, raw: v.mcp.servers[name] })); return; }
    const vals = Object.keys(v.mcp).filter((k) => isObj(v.mcp[k]) && looksLikeServer(v.mcp[k]));
    if (vals.length) { vals.forEach((name) => out.push({ name, raw: v.mcp[name] })); return; }
  }
  if (looksLikeServer(v)) { out.push({ name: typeof v.name === "string" ? v.name : null, raw: v }); return; }
  const keys = Object.keys(v);
  const maybe = keys.filter((k) => isObj(v[k]) && looksLikeServer(v[k]));
  if (maybe.length) { maybe.forEach((name) => out.push({ name, raw: v[name] })); return; }
  errors.push("サーバー定義（command か url を持つオブジェクト）が見つかりませんでした。");
}

function parseJsonChunk(t, out, errors, warnings) {
  let r = tryParse(t);
  if (r.ok) { entriesFromValue(r.value, out, errors, warnings); return; }
  if (t[0] === '"') {
    const w = tryParse("{" + t.replace(/,\s*$/, "") + "}");
    if (w.ok) { entriesFromValue(w.value, out, errors, warnings); return; }
  }
  const pieces = splitTopLevelObjects(t);
  if (pieces.length > 1 || (pieces.length === 1 && pieces[0] !== t)) {
    let any = false;
    let rest = t;
    pieces.forEach((p) => {
      const pr = tryParse(p);
      if (pr.ok) { any = true; entriesFromValue(pr.value, out, errors, warnings); rest = rest.replace(p, "\n"); }
    });
    if (any) {
      // JSON の前後にコマンド行や URL が混ざっていれば、それも読む
      const extra = rest.split(/\r?\n/).filter((l) => l.trim() && !/^\s*(\/\/|#)/.test(l)).join("\n");
      if (extra.trim()) parseLines(extra, out, errors, warnings);
      return;
    }
  }
  errors.push("JSON として読めません: " + String(r.error || "").slice(0, 160));
}

/** `claude mcp add …` 系の 1 コマンド。 */
function parseAddCommand(tokens, out, errors, warnings) {
  const i = tokens.findIndex((x, k) => x === "mcp" && /^add(-json)?$/.test(tokens[k + 1] || ""));
  if (i < 0) { errors.push("未対応のコマンドです: " + tokens.slice(0, 3).join(" ")); return; }
  const sub = tokens[i + 1];
  const rest = tokens.slice(i + 2);
  if (sub === "add-json") {
    const name = rest.find((x) => !x.startsWith("-"));
    const js = rest.slice(rest.indexOf(name) + 1).join(" ");
    const r = tryParse(js);
    if (!name || !r.ok) { errors.push("add-json の引数を読めません。"); return; }
    out.push({ name, raw: r.value });
    return;
  }
  let transport = "", env = {}, headers = {}, name = null;
  const positional = [];
  let dashed = null;
  for (let k = 0; k < rest.length; k++) {
    const a = rest[k];
    if (dashed) { dashed.push(a); continue; }
    if (a === "--") { dashed = []; continue; }
    if (a === "-t" || a === "--transport") { transport = String(rest[++k] || "").toLowerCase(); continue; }
    if (a.startsWith("--transport=")) { transport = a.slice(12).toLowerCase(); continue; }
    if (a === "-s" || a === "--scope") { k++; continue; }
    if (a.startsWith("--scope=")) continue;
    if (a === "-e" || a === "--env") {
      while (k + 1 < rest.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(rest[k + 1])) { const m = /^([^=]+)=([\s\S]*)$/.exec(rest[++k]); env[m[1]] = m[2]; }
      continue;
    }
    if (a.startsWith("--env=")) { const m = /^([^=]+)=([\s\S]*)$/.exec(a.slice(6)); if (m) env[m[1]] = m[2]; continue; }
    if (a === "-H" || a === "--header") {
      const m = /^([^:]+):\s*([\s\S]*)$/.exec(rest[++k] || "");
      if (m) headers[m[1].trim()] = m[2];
      continue;
    }
    if (a.startsWith("--header=")) { const m = /^([^:]+):\s*([\s\S]*)$/.exec(a.slice(9)); if (m) headers[m[1].trim()] = m[2]; continue; }
    if (a.startsWith("-") && positional.length === 0) { warnings.push("未対応のオプションを無視しました: " + a); continue; }
    positional.push(a);
  }
  name = positional[0] || null;
  const tail = dashed || positional.slice(1);
  if (!tail.length) { errors.push("コマンドまたは URL がありません: " + tokens.slice(i, i + 5).join(" ")); return; }
  const first = tail[0];
  const isUrl = /^https?:\/\//i.test(first);
  if (isUrl || transport === "http" || transport === "sse") {
    const raw = { type: transport === "sse" ? "sse" : "http", url: first };
    if (Object.keys(headers).length) raw.headers = headers;
    out.push({ name, raw });
  } else {
    const raw = { command: first };
    if (tail.length > 1) raw.args = tail.slice(1);
    if (Object.keys(env).length) raw.env = env;
    out.push({ name, raw });
  }
}

function parseLines(t, out, errors, warnings) {
  const lines = t.replace(/\\\r?\n/g, " ").split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !/^(#|\/\/|\$ ?$)/.test(l));
  lines.forEach((line0) => {
    const line = line0.replace(/^\$\s+/, "").replace(/^>\s+/, "");
    let tokens;
    try { tokens = tokenize(line); } catch (e) { errors.push("コマンドを読めません: " + e.message); return; }
    if (!tokens.length) return;
    if (/^https?:\/\/\S+$/i.test(line)) { out.push({ name: null, raw: { url: line } }); return; }
    if (SHELL_CMD_RE.test(line) && tokens.includes("mcp")) { parseAddCommand(tokens, out, errors, warnings); return; }
    const exe = tokens[0].split(/[\\/]/).pop();
    if (LAUNCHERS.test(exe) || /^\.{0,2}[\\/]/.test(tokens[0]) || /^[A-Za-z]:\\/.test(tokens[0])) {
      out.push({ name: null, raw: tokens.length > 1 ? { command: tokens[0], args: tokens.slice(1) } : { command: tokens[0] } });
      return;
    }
    errors.push("認識できない行です: " + line.slice(0, 80));
  });
}

/**
 * 貼り付けテキスト全体を解釈する。
 * 戻り値: { entries: [{ index, name, nameDerived, spec, warnings[], error? }], errors[], warnings[] }
 * 名前は貼り付け内で一意にする（重複は -2, -3 …）。既存設定との衝突は呼び出し側（mcpHub）が判定する。
 */
function parseImport(text) {
  const out = [], errors = [], warnings = [];
  const src = String(text == null ? "" : text);
  if (!src.trim()) return { entries: [], errors: ["貼り付けるテキストが空です。"], warnings };
  if (src.length > 512 * 1024) return { entries: [], errors: ["テキストが大きすぎます（512KB まで）。"], warnings };
  chunksOf(src).forEach((chunk) => {
    let t = chunk.trim();
    if (!t) return;
    // 先頭のコメント行（// … や /* … */）は、形式の判定から外す
    t = t.replace(/^(?:\s*(?:\/\/[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/))+\s*/, "").trim();
    if (!t) return;
    if (/^\[\s*mcp_servers[.\]]/m.test(t) && !/^[{"]/.test(t)) {
      const servers = parseTomlServers(t);
      Object.keys(servers).forEach((name) => out.push({ name, raw: servers[name] }));
      if (!Object.keys(servers).length) errors.push("TOML に [mcp_servers.名前] が見つかりませんでした。");
    } else if (/^[{\["]/.test(t)) parseJsonChunk(t, out, errors, warnings);
    else parseLines(t, out, errors, warnings);
  });

  const entries = [];
  const taken = new Set();
  out.forEach((e) => {
    const n = normalizeSpec(e.raw);
    const ws = n.warnings.slice();
    let name = "", derived = false;
    if (typeof e.name === "string" && e.name.trim()) {
      name = sanitizeName(e.name);
      if (name !== e.name.trim()) ws.push("名前「" + e.name.trim().slice(0, 40) + "」は使えない文字を含むため「" + (name || "（自動）") + "」にしました（英数字・_・- のみ、32 文字以内）。");
    }
    if (!name) { name = n.spec ? deriveName(n.spec) : "mcp-server"; derived = true; }
    const base = name;
    for (let k = 2; taken.has(name); k++) { name = (base.slice(0, 29) + "-" + k).replace(/-{2,}/g, "-"); }
    if (name !== base) ws.push("同じ名前が貼り付け内にあったため「" + name + "」にしました。");
    taken.add(name);
    entries.push({ index: entries.length, name, nameDerived: derived, spec: n.spec || null, warnings: ws, error: n.error || null });
  });
  if (!entries.length && !errors.length) errors.push("サーバー定義が見つかりませんでした。");
  return { entries, errors, warnings };
}

/* ------------------------------------------------------------
   伏字
   ------------------------------------------------------------ */

const isEnvRef = (v) => typeof v === "string" && ENV_REF_RE.test(v.trim());

/** env / headers / bearerToken の値だけを伏字にしたコピー（${ENV} 参照はそのまま）。画面・API の応答用。 */
function maskSpec(spec) {
  if (!isObj(spec)) return null;
  const o = JSON.parse(JSON.stringify(spec));
  ["env", "headers"].forEach((k) => {
    if (isObj(o[k])) Object.keys(o[k]).forEach((key) => { if (!isEnvRef(o[k][key])) o[k][key] = MASK; });
  });
  if (typeof o.bearerToken === "string" && o.bearerToken && !isEnvRef(o.bearerToken)) o.bearerToken = MASK;
  return o;
}

/** 画面から戻ってきた spec の伏字（MASK）を、元の設定の値へ戻す。戻せない伏字があればエラー文字列を返す。 */
function restoreMasked(next, prev) {
  const fixed = JSON.parse(JSON.stringify(next));
  let bad = null;
  ["env", "headers"].forEach((k) => {
    if (!isObj(fixed[k])) return;
    Object.keys(fixed[k]).forEach((key) => {
      if (fixed[k][key] !== MASK) return;
      if (isObj(prev) && isObj(prev[k]) && typeof prev[k][key] === "string") fixed[k][key] = prev[k][key];
      else bad = bad || (k + "「" + key + "」の値が伏字のままです。値を入力してください。");
    });
  });
  if (fixed.bearerToken === MASK) {
    if (isObj(prev) && typeof prev.bearerToken === "string") fixed.bearerToken = prev.bearerToken;
    else bad = bad || "bearerToken が伏字のままです。値を入力してください。";
  }
  return { spec: fixed, error: bad };
}

function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (isObj(v)) { const o = {}; Object.keys(v).sort().forEach((k) => { o[k] = sortKeys(v[k]); }); return o; }
  return v;
}
/** 同じ設定かの比較用（キー順を無視）。 */
function canonicalKey(spec) { return JSON.stringify(sortKeys(spec)); }

/** 画面表示用の 1 行（秘密は含めない）。 */
function describeTarget(spec) {
  if (!isObj(spec)) return "";
  if (spec.command !== undefined) return [spec.command].concat(Array.isArray(spec.args) ? spec.args : []).join(" ");
  return String(spec.url || "").replace(/([?&][^=&]*(?:key|token|secret|auth|pass|sig)[^=&]*=)[^&]+/gi, "$1***").replace(/\/\/[^/@]*@/, "//***@");
}

function kindOf(spec) {
  if (!isObj(spec)) return "";
  if (spec.type === "sse") return "sse";
  if (spec.type === "http" || spec.type === "streamable-http" || (spec.command === undefined && spec.url !== undefined)) return "http";
  return "stdio";
}

module.exports = { parseImport, normalizeSpec, sanitizeName, deriveName, maskSpec, restoreMasked, canonicalKey, describeTarget, kindOf, tokenize, MASK, NAME_RE };
