import init, { initThreadPool, js_zsign_transfer_and_mint_transaction } from './zeos_caterpillar.js';
console.log("worker created...");

// init wasm module
await init();

// fetch and decode mint params
const fromB64String = (b64String) => Uint8Array.from(atob(b64String), c => c.charCodeAt(0))
let mint_params = await (await fetch("./mint.params.b64")).text();
let mint_params_bytes = fromB64String(mint_params);

// initialize thread pool with number of cores
console.log("thread num: " + navigator.hardwareConcurrency);
await initThreadPool(navigator.hardwareConcurrency);

// process and print dummy transaction (multi-threaded)
console.log(JSON.stringify(js_zsign_transfer_and_mint_transaction(
    `[{"to":"za1350j0ume40a06ww3fsplxfzwrlrwt0akk5tlu3wkdd5c8nxmswqr49yxgtultr8g3s66c7yqyzf","contract":"eosio.token","quantity":"10.0000 EOS","memo":"","from":"aliceaccount","publish_note":true}]`,
    "thezeosalias@public",
    "mschoenebeck@active",
    "zeos4privacy",
    "thezeosalias",
    `{"authenticate":"2.0000 ZEOS","begin":"5.0000 ZEOS","mint":"1.0000 ZEOS","output":"1.0000 ZEOS","publishnotes":"0.2000 ZEOS","spend":"1.0000 ZEOS","spendoutput":"2.0000 ZEOS","withdraw":"0.5000 ZEOS"}`,
    mint_params_bytes
), null, 2));
