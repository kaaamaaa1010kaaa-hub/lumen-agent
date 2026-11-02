// テスト用: 能力宣言は使わない（全サーバー eager）
module.exports = {
  normalizeManifest() { return { manifest: Object.create(null), warnings: [] }; },
  rankLazyServers() { return []; },
};
