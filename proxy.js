const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
app.use(cors({ origin: '*', allowedHeaders: ['Content-Type', 'Authorization'] }));

app.use((req, res, next) => {
    console.log(`\n📨 ${req.method} ${req.url} from ${req.ip || req.connection.remoteAddress}`);
    console.log('  Authorization header exists?', !!req.headers.authorization);
    next();
});

const proxy = createProxyMiddleware({
    target: 'https://integrate.api.nvidia.com',
    changeOrigin: true,
    // 修正: 常に固定文字列 '/v1/chat/completions' を返していたため、
    // /v1/models（モデル一覧取得のGET）や /v1/embeddings 等、chat/completions以外への
    // リクエストもすべて誤って /v1/chat/completions 宛に書き換えられてNIMへ転送されていた。
    // NIM側はメソッド・パスの組み合わせを見て 501 (Not Implemented) を返していたと考えられる。
    // pathRewrite は「元のパスをそのまま使う」のが正しい既定動作なので、恒等関数にする。
    pathRewrite: (path) => path,
    proxyTimeout: 120000,          // プロキシ全体のタイムアウト (120秒)
    timeout: 120000,               // ソケットタイムアウト
    onProxyReq: (proxyReq, req, res) => {
        if (req.headers.authorization) {
            proxyReq.setHeader('Authorization', req.headers.authorization);
            console.log('  ✅ Authorization forwarded');
        } else {
            console.log('  ⚠️ No Authorization header');
        }
    },
    onError: (err, req, res) => {
        console.error('  ❌ Proxy error:', err.message);
        // 504 の代わりにリトライ可能なエラーとして返すことも可能
        res.status(504).json({ error: 'Gateway Timeout: ' + err.message });
    }
});

app.use(proxy);

const HOST = process.env.PROXY_HOST || '0.0.0.0';
const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, HOST, () => {
    // 修正: テンプレートリテラル内の変数展開が壊れており（${}が抜けてリテラル文字列
    // "HOST:{HOST}:HOST:{PORT}" がそのまま出力されていた）、起動ログのURLが読めなかった。
    console.log(`✅ NVIDIA API Proxy running on http://${HOST}:${PORT}`);
    console.log(`   Timeout set to 120 seconds`);
});

// 追加: ポート5000を静的ファイルサーバー（python -m http.server 等）と取り合うと、
// リクエストのたびにどちらが応答するか不定になり、「Unsupported method」「404」「501」等が
// 不規則に発生する（実際にこの問題で確認された）。EADDRINUSEを黙って握りつぶさず、
// 「他に何かがこのポートを使っている」ことを起動時点で分かりやすく知らせる。
server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`\n❌ ポート ${PORT} は既に他のプロセスが使用しています。`);
        console.error(`   静的ファイル配信（python -m http.server 等）と同じポートを共有していませんか？`);
        console.error(`   Windowsで確認する場合: netstat -ano | findstr :${PORT}`);
        console.error(`   このプロキシは常にポート5000専用、静的配信は別ポート（例: 8080）に分けてください。\n`);
        process.exit(1);
    } else {
        throw err;
    }
});
