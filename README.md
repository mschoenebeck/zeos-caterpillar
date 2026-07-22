# ZEOS Caterpillar Shielded Protocol

**Private transactions for fungible tokens, NFTs, and smart-contract applications on Antelope.**

ZEOS Caterpillar brings Sapling-style shielded transactions to Antelope smart contracts. Unlike a single-asset privacy coin, it works with tokens issued by different contracts, supports indivisible NFTs, and lets users authorize application actions through private auth tokens.

This repository contains the Rust side of the protocol: keys, addresses, notes, wallet state, transaction construction, encryption, circuits, and Groth16 proof generation. Its on-chain counterpart, `zeosprotocol`, verifies proofs and maintains the authoritative commitment and nullifier state.

The name is a nod to its lineage: **caterpillars thrive on saplings**.

> **Full technical architecture:**  
> [`docs/zeos-caterpillar.md`](docs/zeos-caterpillar.md)

## What Makes It Different

### Multiple assets, without losing issuer identity

On Antelope, a symbol alone does not identify a token. Two contracts can both issue a token called `USD`.

ZEOS Caterpillar binds each shielded asset to both its symbol and issuing contract. A transaction cannot spend one contract's token and create another contract's token simply because the numbers and symbols match.

### NFTs are not divisible values

A fungible note can be split and can produce change. An NFT identifier cannot.

The dedicated `spend_output` circuit keeps that distinction inside the proof system. A shielded NFT either remains shielded as one exact successor note or exits publicly as the same object. It cannot be split, duplicated, or turned into change.

### Private smart-contract authorization

Auth tokens reuse the shielded-note and proof system as private application capabilities.

Control of an auth-token secret can authorize an exact bundle of smart-contract actions without revealing the controlling public Antelope account. Applications can associate orders, positions, vaults, permissions, or other state with the token commitment instead.

### Small proofs, practical on-chain verification

Proof generation stays off-chain in the native or browser client. `zeosprotocol` only verifies the result and applies the state transition.

Groth16 fits this model well: proof size does not grow with circuit complexity—proofs use 384 bytes in this implementation's affine encoding—and verification grows mainly with the number of public inputs rather than the number of private constraints. More complex circuits make proving heavier for the client, but do not require validators to re-run the circuit.

## How It Fits Together

```text
Wallet / Browser / Application
            │
            ▼
     zeos-caterpillar
 keys · addresses · notes
 encryption · wallet state
 transaction construction · proving
            │
            │ proofs, commitments,
            │ nullifiers and action data
            ▼
       zeosprotocol
 proof verification · commitments
 nullifiers · public asset transitions
 auth-token action authorization
            │
            ▼
 Leap BLS12-381 host functions
```

Native proof generation uses Bellman with the `blstrs` pairing engine, backed by Supranational's optimized [`blst`](https://github.com/supranational/blst) implementation. Browser builds use the portable Rust/WASM proving path and can optionally use Web Workers for multicore proving.

On-chain verification uses [`bls12-381-cdt`](https://github.com/mschoenebeck/bls12-381-cdt) and the native BLS12-381 host functions contributed to Leap.

## What This Repository Contains

| Area | Responsibility |
|---|---|
| Circuits | Shared Mint/Auth, Spend, Output, and SpendOutput constraint systems |
| Keys and addresses | Spending, viewing, and diversified-address derivation |
| Notes | Fungible-token, NFT, and auth-token semantics |
| Encryption | Recipient note encryption and sender-side output recovery |
| Transactions | Note selection, witnesses, proofs, outputs, and Antelope action construction |
| Wallet | Synchronization, balances, notes, nullifiers, and encrypted persistence |
| Native integration | Rust library, C-compatible dynamic library, and static library |
| Browser integration | Single-threaded and multicore WebAssembly proving |

The implementation also handles contract-qualified asset commitments, confidential value conservation, Merkle witnesses, nullifier tracking, fungible change, exact NFT selection, and Antelope serialization.

## Build

### Requirements

- Rust 1.80 or newer
- `wasm-pack` for browser packages
- a nightly Rust toolchain for the multicore WASM package
- Node.js and npm for the browser demo
- the proving parameters required by the circuit being used

### Native library

```bash
cargo build --release
```

The crate builds as a Rust library, a C-compatible dynamic library, and a static library.

Native builds use `blstrs`/`blst` by default. A portable native build is available for environments that cannot use the architecture-specific backend:

```bash
cargo build --release --features blst-portable
```

The C interface is defined in [`include/zeos-caterpillar.h`](include/zeos-caterpillar.h).

### Browser packages

The root Makefile creates:

| Artifact | Purpose |
|---|---|
| `wasm_pkg_st/` | Single-threaded browser WASM package |
| `wasm_pkg_mt/` | Multicore browser WASM package |
| `mint.params.b64` | Browser-loadable Mint/Auth proving parameters |

It expects `mint.params` in the repository root.

```bash
make clean
make -j
```

The multicore package requires a cross-origin-isolated browser deployment.

### Browser mint-proof demo

The bundled demo covers the public-account-to-shielded-wallet flow. It loads the Mint/Auth proving parameters and lets you compare single-threaded and multicore browser proof generation.

```bash
cd web
npm install
node server.js
```

Open:

- `http://localhost:3001/single-threaded`
- `http://localhost:3001/multi-threaded`

The demo focuses on mint-proof generation. It is not a complete interface for every protocol circuit.

## Groth16 Parameters and Trusted Setup

The protocol currently uses four parameter sets:

- Mint/Auth
- Spend
- Output
- SpendOutput

Minting and authentication share one constraint system and therefore one setup.

Parameter generation, contributions, verification, beacon finalization, and final parameter splitting live in [`zeos-caterpillar-mpc`](https://github.com/mschoenebeck/zeos-caterpillar-mpc).

That tooling uses a customized [`phase2`](https://github.com/mschoenebeck/phase2) engine adapted to `blstrs`/`blst` for optimized native BLS12-381 arithmetic.

Locally generated parameters are useful for development and integration testing. Production deployments should document the exact circuit revisions, ceremony, parameter provenance, and active verifying keys.

## On-Chain Integration

`zeosprotocol` is the on-chain half of the system. It:

- verifies Mint/Auth, Spend, Output, and SpendOutput proofs;
- maintains the commitment tree;
- records and rejects reused nullifiers;
- checks confidential value balance;
- accepts public token and NFT deposits;
- executes public token and NFT exits;
- binds public recipients to the proven transaction;
- validates auth-token proofs and dispatches authorized actions.

The contract implementation is maintained separately from this Rust client and proving engine.

## Status and Security

ZEOS Caterpillar is working cryptographic infrastructure used with deployed Antelope contracts. That is not the same as an independent security audit.

Security depends on the whole stack: the circuits, Groth16 parameters, client implementation, note encryption, transaction encoding, `zeosprotocol`, `bls12-381-cdt`, and the underlying Leap host functions.

Public deposits and withdrawals reveal the information required by the underlying token or NFT contract. Auth tokens can hide the controlling account or wallet identity, but they do not make arbitrary application execution or public contract state confidential. Timing, network, and application metadata may still allow correlation.

See [Privacy, Security, and Limitations](docs/zeos-caterpillar.md#9-privacy-security-and-limitations) for the full discussion.

## Related Repositories

- [`zeos-caterpillar-mpc`](https://github.com/mschoenebeck/zeos-caterpillar-mpc) — Groth16 parameter generation and ceremony tooling
- [`phase2`](https://github.com/mschoenebeck/phase2) — phase-two implementation adapted to `blstrs`/`blst`
- [`bls12-381-cdt`](https://github.com/mschoenebeck/bls12-381-cdt) — BLS12-381 and Groth16 utilities for Antelope contracts
- [`bls12-381`](https://github.com/mschoenebeck/bls12-381) — native BLS12-381 implementation behind the corresponding Leap host-function work

[CLOAK](https://cloak.today) is an implementation of the ZEOS Caterpillar Shielded Protocol.

## License

Licensed under either:

- [Apache License 2.0](LICENSE-APACHE.txt)
- [MIT License](LICENSE-MIT.txt)

at your option.

Unless explicitly stated otherwise, contributions intentionally submitted for inclusion in this work are dual-licensed under the same terms.

## Author

Designed and implemented by [Matthias Schönebeck](https://github.com/mschoenebeck).

Blockchain and DeFi infrastructure engineer building deterministic trading systems, privacy protocols, lending infrastructure, and applied cryptography in C++ and Rust.
