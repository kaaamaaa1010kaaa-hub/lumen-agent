// テスト用: ツール一覧をそのまま返すだけの代用品（etag は内容のハッシュ）
const crypto = require("crypto");
module.exports = {
  prepare(tools) {
    const list = (tools || []).slice().sort((a, b) => a.name.localeCompare(b.name));
    const chars = JSON.stringify(list).length;
    return { tools: list, etag: crypto.createHash("sha1").update(JSON.stringify(list)).digest("hex").slice(0, 16), summary: { count: list.length, estTokens: Math.ceil(chars / 4), chars }, excluded: [], warnings: [] };
  },
};
