# The ZEOS (Caterpillar) Shielded Protocol 🐛

The ZEOS Shielded Protocol is a full-fledged privacy solution designed for EOSIO/AntelopeIO blockchains. It enables Zcash-like shielded transactions for all assets of the underlying blockchain, including both fungible and non-fungible tokens (NFTs), ensuring that sender, receiver, amount, and asset type are private by default. Built inside a single smart contract fully on-chain, the protocol uses Groth16 zero-knowledge proofs for highly efficient, small, and fast verifiable transactions — ideal for single-threaded execution environments like (wasm) smart contracts where CPU is a scarce resource and thus a limitting factor.

## Key Features

- Full Privacy: Supports shielded transactions for all assets, including fungible tokens and NFTs, ensuring complete privacy for blockchain users.
- Easy Integration: Third-party smart contracts can seamlessly integrate with the ZEOS Shielded Protocol to enable privacy within decentralized applications (dApps).
- Highly Scalable: Built on the scalable EOSIO/AntelopeIO blockchain, the protocol offers high throughput with true block finality — ideal for DeFi applications.
- Zcash-like Privacy: Delivers privacy similar to Zcash, but supports all assets of the underlying blockchain and allows third-party application integration.
- Efficient Zero-Knowledge Proofs: Leverages Groth16 zero-knowledge proofs, which are compact and optimized for single-threaded smart contract execution, making the protocol fast and cost-efficient on-chain.

The ZEOS Shielded Protocol empowers developers to build privacy-preserving DeFi, GameFi, and other decentralized applications, enabling privacy in a space that traditionally lacks it, while maintaining full programmability and scalability.

## ZK-SNARK Parameter Generation

In order to generate the `params` files for the protocol please check out the [`zeos-caterpillar-mpc`](https://github.com/mschoenebeck/zeos-caterpillar-mpc) repository and follow the instructions there.

For simple testing only the `new` step (1) needs to be executed plus the subsequent `split_params` step (4):

```
git clone https://github.com/mschoenebeck/zeos-caterpillar-mpc
cd zeos-caterpillar-mpc
# download the phase 1 (Powers of Tau) parameter files using a torrent client of your choice:
# magnet:?xt=urn:btih:c3f316242ff3f4c2ec5f8cbfc27ae2ca2b599146&dn=powersoftau&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337%2Fannounce
cargo run --release --bin new --features="verification"             # creates a new set of params
cargo run --release --bin split_params --features="verification"    # splits the generated params into separate files
```

## Smart Contracts

The corresponding smart contracts of this protocol are not (yet) open-sourced.

## WASM build for Web Applications

In order to move assets from an EOSIO/AntelopeIO account into a ZEOS privacy wallet usually a web app is required to which EOSIO/AntelopeIO wallets can connect to and authorize transactions. For this purpose the `zeos-caterpillar` library can be compiled to WebAssembly (wasm) to be used inside a browser application. To speed up the CPU-intensive task of zero-knowledge proof generation multi-core support has been added. Note that multi-threading in wasm browser apps only works if the web application is executed in [cross-origin isolation](https://web.dev/articles/cross-origin-isolation-guide).

To demonstrate both, single-threaded and multi-threaded proof generation inside the browser, a simple demo web application is part of the repository. The library can be compiled to wasm using the `Makefile` which is located in the root folder:

```
make -j
```

This will build three targets:
```
wasm_pkg_st         # which is the single-threaded version of the library
wasm_pkg_mt         # which is the multi-threaded version of the library
mint.params.b64     # the mint params ecoded as base64 which is needed to
                    # create the necessary zero-knowledge proofs (depends
                    # on the mint.params file from above)
```

Once the library is built you can run the demo web application by:

```
cd web/
npm i
node server.js
```

This will spawn a server at `localhost:3001` which essentially provides two different web apps:

- [http://localhost:3001/single-threaded](http://localhost:3001/single-threaded)
- [http://localhost:3001/multi-threaded](http://localhost:3001/multi-threaded)

Open the Javascript console (`ctrl + shift + i`) and check out the performance difference!

## Special Thanks

A heartfelt thank you to the engineers at Electric Coin Company for their incredible work in developing the open-source codebase that powers zero-knowledge applications. Their pioneering efforts have made it possible for developers like us to create privacy-preserving solutions, such as the ZEOS Shielded Protocol, and bring privacy to programmable blockchains. We owe much of the foundation of this protocol to their vision and commitment to advancing cryptographic technologies.

Thank you for making the world of privacy-enhancing applications a reality.

## License

Licensed under either of

- Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.