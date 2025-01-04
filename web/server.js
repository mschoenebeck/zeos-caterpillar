const express = require('express');
const path = require('path');

const app = express();
const port = 3001;

// demonstrate single-threaded version of the library
app.get('/single-threaded', (req, res) => {
    res.sendFile(path.join(__dirname, 'st.html'));
});
app.get('/single-threaded/zeos_caterpillar.js', (req, res) => {
    res.sendFile(path.join(__dirname, '../wasm_pkg_st/zeos_caterpillar.js'));
});
app.get('/single-threaded/zeos_caterpillar_bg.wasm', (req, res) => {
    res.sendFile(path.join(__dirname, '../wasm_pkg_st/zeos_caterpillar_bg.wasm'));
});
app.get('/single-threaded/mint.params.b64', (req, res) => {
    res.sendFile(path.join(__dirname, '../mint.params.b64'));
});

// demonstrate multi-threaded version of the library (site must be served in cross-origin isolation)
app.use('/multi-threaded', (req, res, next) => {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    next();
});
app.get('/multi-threaded', (req, res) => {
    res.sendFile(path.join(__dirname, 'mt.html'));
});
app.get('/multi-threaded/worker.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'worker.js'));
});
app.get('/multi-threaded/zeos_caterpillar.js', (req, res) => {
    res.sendFile(path.join(__dirname, '../wasm_pkg_mt/zeos_caterpillar.js'));
});
app.get('/multi-threaded/zeos_caterpillar_bg.wasm', (req, res) => {
    res.sendFile(path.join(__dirname, '../wasm_pkg_mt/zeos_caterpillar_bg.wasm'));
});
app.get('/multi-threaded/snippets/wasm-bindgen-rayon-38edf6e439f6d70d/src/workerHelpers.no-bundler.js', (req, res) => {
    res.sendFile(path.join(__dirname, '../wasm_pkg_mt/snippets/wasm-bindgen-rayon-38edf6e439f6d70d/src/workerHelpers.no-bundler.js'));
});
app.get('/multi-threaded/mint.params.b64', (req, res) => {
    res.sendFile(path.join(__dirname, '../mint.params.b64'));
});

// start the server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});