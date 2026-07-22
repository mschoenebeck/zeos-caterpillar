# ZEOS Caterpillar Shielded Protocol

## 1. Overview

ZEOS Caterpillar is a shielded protocol for programmable Antelope blockchains. It takes the note-based privacy model pioneered by Zcash Sapling and extends it to an environment in which assets are issued by many independent smart contracts, may be fungible or non-fungible, and may need to interact with application state without exposing the controlling public account.

The protocol is split across two execution domains:

- **`zeos-caterpillar`**, the Rust cryptographic and client engine in this repository, manages keys, addresses, notes, wallet state, transaction construction, note encryption, circuit witnesses, and Groth16 proof generation.
- **`zeosprotocol`**, the on-chain Antelope contract, verifies proofs, maintains the authoritative commitment and nullifier state, accepts public deposits, executes public withdrawals, and mediates privacy-preserving application authorization.

This separation is fundamental. Private witnesses and proof generation remain off-chain in the client environment controlled by the user or integrating application. The blockchain receives the proofs, commitments, nullifiers, public transition data, and—when published through the protocol—encrypted note payloads required to validate and apply the transaction deterministically.

ZEOS Caterpillar is not a new privacy coin. It is a reusable privacy layer for an existing smart-contract asset ecosystem.

### What this repository contains

The Rust codebase provides the client-side machinery needed to participate in the protocol:

- deterministic key and shielded-address derivation;
- spending, viewing, and note-recovery capabilities;
- a unified note representation for fungible tokens, NFTs, and authentication tokens;
- note commitments, nullifiers, Merkle witnesses, and value commitments;
- recipient note encryption and sender-side output recovery;
- wallet synchronization and local note-state tracking;
- fungible-note selection, NFT selection, change construction, and transaction planning;
- Groth16 circuits and proof generation;
- Antelope action and data serialization;
- native Rust, C-compatible, static-library, dynamic-library, and browser WebAssembly targets.

The on-chain contract is intentionally outside this repository. The two components implement opposite sides of the same protocol boundary: the client constructs and proves; `zeosprotocol` verifies and enforces.

### Scope

This document describes the architecture and implemented protocol model. It is not:

- a formal cryptographic specification;
- a complete API reference;
- a step-by-step build guide;
- an audit report;
- product, token, or application documentation.

Exact build instructions belong in the repository README. Exact consensus behavior remains defined by the deployed `zeosprotocol` contract and the verifying keys configured for it.

---

## 2. Sapling Lineage and Protocol Generalization

### 2.1 Sapling foundations

ZEOS Caterpillar is directly inspired by the Zcash Sapling architecture. The name reflects that lineage: **caterpillars thrive on saplings**.

The protocol retains the central ideas that make a shielded note system work:

- privately owned notes rather than public account balances;
- diversified shielded addresses;
- note commitments recorded in a Merkle tree;
- encrypted note payloads discoverable by recipients;
- nullifiers that prevent double spending without revealing the consumed commitment;
- Groth16 proofs for compact on-chain verification;
- Pedersen commitments for confidential value conservation;
- separate spend-side and output-side proof statements.

In a conventional Sapling transaction, the asset being conserved is implicit: it is the chain’s native fungible currency. A spend proves ownership and membership of a ZEC note; an output creates a new ZEC note; transaction-level value commitments prove that ZEC was neither created nor destroyed.

That assumption does not hold on a general smart-contract chain.

### 2.2 Why a smart-contract ecosystem is different

An Antelope chain may host many token contracts. Each contract can issue one or more fungible assets, and two unrelated contracts may use the same token symbol. The chain may also host multiple NFT standards, application-specific digital objects, and contracts that require persistent user authorization.

A shielded protocol for that environment must solve several additional problems.

#### Asset identity is not implicit

A symbol such as `USD` is not globally unique. The complete identity of a fungible token includes both:

```text
token contract + symbol
```

A private transaction must not be able to spend one contract’s `USD` and create another contract’s `USD`, even when the quantities and symbol encodings match.

#### Not every asset is divisible

For a fungible token, a quantity can be divided:

```text
100 units → 40 units + 60 units
```

An NFT identifier is not a quantity. An NFT with identifier `100` cannot become identifiers `40` and `60` merely because the arithmetic balances.

#### Smart contracts expect authorization

A shielded note system proves private control of notes. An application contract normally expects an account, an authorization context, and a precise action request. Bridging those models without disclosing the user’s public account requires more than private payments.

#### Verification runs inside contract WASM

The proving system must ultimately be enforced by a deterministic smart contract operating under CPU and memory constraints. Proof generation is too expensive and too witness-sensitive to perform there, while pairing verification is impractical without native cryptographic acceleration.

### 2.3 Core extensions

ZEOS Caterpillar generalizes the Sapling model in five connected ways:

1. **Contract-qualified multi-asset notes**  
   Notes bind value to both a token symbol and its issuing contract.

2. **Confidential per-asset conservation**  
   Randomized asset commitments allow spend and output proofs to establish that they refer to the same contract-qualified asset without exposing that asset during a fully shielded sequence.

3. **First-class NFT semantics**  
   A dedicated `spend_output` circuit enforces indivisibility and exact input-to-destination continuity.

4. **Authentication tokens**  
   The note and proof system can represent private application capabilities, allowing control of a shielded secret to authorize an exact smart-contract action bundle.

5. **Client proving with contract-layer verification**  
   Native or browser clients construct witnesses and generate proofs; `zeosprotocol` verifies them inside blockchain WASM using BLS12-381 host functions.

The result is not simply “Sapling on another chain.” It is a shielded state machine adapted to a richer asset and application model.

### 2.4 Comparison boundaries

The closest architectural comparison is Zcash Sapling, not every later Zcash protocol.

| Dimension | Zcash Sapling | ZEOS Caterpillar |
|---|---|---|
| Execution model | Native consensus protocol | Client-side proving plus Antelope smart-contract verification |
| Asset model | Native fungible ZEC | Contract-qualified fungible tokens, NFTs, and auth-token capabilities |
| Core proof structure | Spend and Output descriptions | Shared Mint/Auth, Spend, Output, and SpendOutput circuits |
| Asset identity | Implicit in the protocol | Committed token contract and symbol |
| NFT semantics | Not part of deployed Sapling | Indivisibility enforced by `spend_output` |
| Application authorization | Outside the shielded payment model | Proof-bound auth-token interaction |

Zcash Orchard later combines input-side and output-side effects into a single Action abstraction. Zcash Shielded Assets also explore related multi-asset and NFT problems as protocol proposals. ZEOS Caterpillar should therefore not be described as the first system ever to consider shielded custom assets.

Its defining distinction is practical and architectural: it applies shielded-note semantics to assets issued by independent application contracts and connects private note ownership directly to smart-contract interaction.

---

## 3. Architecture and Execution Model

### 3.1 Client-side cryptographic engine

`zeos-caterpillar` operates where the private material exists: in the wallet, desktop application, service, or browser controlled by the user.

Its responsibilities include:

- deriving spending and viewing keys;
- generating diversified shielded addresses;
- scanning encrypted note payloads;
- reconstructing owned notes;
- maintaining a local view of the commitment tree;
- tracking unspent, spent, and outgoing notes;
- selecting fungible notes or an exact NFT;
- constructing change and recipient notes;
- deriving nullifiers and Merkle authentication paths;
- assembling circuit witnesses;
- generating Groth16 proofs;
- encrypting notes for recipients and for sender-side recovery;
- serializing the resulting Antelope actions.

The client must know the private witness, but the chain does not need it. The chain receives a proof that the witness satisfies the required statement.

### 3.2 On-chain `zeosprotocol`

`zeosprotocol` is the authoritative state machine.

It is responsible for:

- accepting supported public assets into the shielded domain;
- verifying the configured Groth16 proof types;
- maintaining commitment-tree state;
- maintaining the set of published nullifiers;
- rejecting reused nullifiers;
- checking value-commitment balance across transaction components;
- executing public token or NFT transfers on exit;
- binding unshielded recipients to the proven transaction;
- validating authentication proofs and dispatching authorized actions;
- publishing the protocol data required for wallet synchronization.

The contract does not know the private note plaintext, spending key, or Merkle witness. It applies the state transition only when the public inputs and proof verify.

### 3.3 Two WASM environments

ZEOS Caterpillar uses WebAssembly in two very different contexts.

#### Browser WebAssembly

The Rust client can be compiled to browser WASM. In this environment it handles private wallet operations and proof generation locally, without sending spending keys, note plaintexts, or circuit witnesses to a remote proving service.

The repository supports both single-threaded and multicore browser builds. Multicore proof generation depends on browser worker support and a cross-origin-isolated deployment.

#### Blockchain WebAssembly

`zeosprotocol` executes as deterministic Antelope contract WASM. It performs state validation and invokes native cryptographic host functions for expensive BLS12-381 operations.

The blockchain environment never performs general client-side proving. It verifies compact Groth16 proofs and updates consensus state.

### 3.4 Native cryptographic host layer

The on-chain verification stack is:

```text
zeosprotocol
    │
    ▼
bls12-381-cdt
    │
    ▼
Leap BLS12-381 host functions
    │
    ▼
native BLS12-381 implementation
```

`bls12-381-cdt` provides smart-contract-oriented curve and Groth16 utilities. The corresponding Leap host functions execute the heavy curve operations natively beneath the contract interface.

This division is what makes pairing-based verification practical within an Antelope contract. The contract remains deterministic and consensus-visible, while the most expensive arithmetic does not need to be reimplemented as ordinary WASM instructions.

Groth16 is particularly well suited to this execution split. Its proofs have constant size with respect to circuit complexity; in this implementation, each proof is serialized to 384 bytes. Verification consists of a small fixed pairing check plus a multi-scalar multiplication whose cost grows with the number of public inputs, not with the number of private constraints. Larger or more complex circuits therefore increase client-side proving work, but do not require every validator to re-execute the constraint system on-chain. The trade-off is the circuit-specific trusted setup described later in this document.

### 3.5 End-to-end flow

```text
Wallet / Browser / Application
            │
            ▼
     zeos-caterpillar
 keys · addresses · notes
 encryption · wallet state
 transaction construction · proving
            │
            │ Antelope action data,
            │ proofs and encrypted notes
            ▼
       zeosprotocol
 proof verification · commitments
 nullifiers · value balance
 public asset transitions · authentication
            │
            ▼
 Leap BLS12-381 host functions
```

A typical transaction therefore crosses three execution layers:

1. the client privately constructs the witness and proof;
2. the contract deterministically verifies the public statement;
3. native host functions execute the cryptographic primitives required by verification as part of each validating node’s consensus execution.

The host-function layer is an implementation boundary, not an external proving or trust service.

---

## 4. Unified Shielded Note Model

### 4.1 Keys and shielded addresses

The key hierarchy follows the familiar Sapling separation between spending authority and viewing capability.

A spending key controls note consumption and derives the proof-generation material needed by the circuits. A full viewing key derives incoming and outgoing viewing material. The incoming viewing key supports recipient-side note discovery; the outgoing viewing key supports recovery of notes created by the sender.

Diversified addresses allow a wallet to derive multiple shielded recipients without changing the underlying spending authority. The wallet can also operate in a read-only mode initialized from incoming viewing material, allowing synchronization and note discovery without spending capability.

### 4.2 Notes and commitments

A note is the protocol’s private ownership record. The implemented note representation includes:

- a header;
- a shielded recipient address;
- an Antelope account field whose meaning depends on the transition;
- an amount or object identifier;
- a token symbol;
- an issuing contract;
- note randomness;
- a memo payload.

The note commitment binds the privacy-relevant fields without revealing them. Conceptually, the commitment covers:

```text
account
value or object identifier
symbol
issuing contract
recipient address components
commitment randomness
```

Only the commitment is inserted into the public Merkle tree. The note plaintext remains encrypted for the intended recipient.

The account field carries operation-specific Antelope context. In the current active flows it identifies the public sender for minting, uses a neutral value for ordinary fully shielded transfer notes, and scopes an authentication token to its application contract. Public recipients in the current `SpendOutput` exit path are bound separately through the unshielded-output hash rather than through this note field.

### 4.3 Contract-qualified asset identity

The protocol treats token identity as the pair:

```text
(symbol, issuing contract)
```

This pair appears in the note commitment and in a separate randomized symbol commitment used by the spend and output circuits.

The name “symbol commitment” is historical shorthand. It commits not only the symbol but also the token contract. That distinction is essential: identical symbol values issued by different contracts remain separate assets.

The client wallet follows the same rule. Fungible note selection filters by both symbol and contract, and wallet balances are grouped by the same pair.

### 4.4 Semantic uses of the note model

The same note machinery represents three different categories of private state.

| Semantics | Amount field | Symbol convention | Contract/account role | Required behavior |
|---|---:|---|---|---|
| Fungible token | Token quantity | Non-zero token symbol | Issuing token contract | Divisible; multiple inputs and change are allowed |
| NFT | NFT identifier | Zero symbol | NFT contract identifies the asset domain | Indivisible; one exact object must remain shielded or exit publicly |
| Auth token | Zero | Zero symbol | Application contract defines the authorization scope | Proves private control of an application capability |

Auth tokens are not financial assets merely because they reuse the note representation. They are private capabilities carried by the same commitment, encryption, ownership, and proving infrastructure.

The zero-symbol convention makes NFTs and auth tokens distinguishable from fungible tokens. A zero-symbol note with a non-zero amount is treated as an NFT; a zero-symbol, zero-amount note is treated as an auth token.

### 4.5 Encrypted note payloads

A public commitment proves that a note exists, but it does not tell wallets who owns the note or what it contains.

The client produces a transmitted note ciphertext containing:

- an ephemeral public key;
- recipient-encrypted note plaintext;
- outgoing ciphertext for sender-side recovery.

A recipient wallet uses its prepared incoming viewing key to attempt decryption. The sender can recover outgoing notes using its outgoing viewing key. This allows both parties to reconstruct the transaction history relevant to them without placing the note plaintext on-chain.

Encrypted notes may be included with protocol actions or tracked for separate publication, depending on the transaction builder’s publication settings. The wallet maintains unpublished encrypted-note state so that ciphertext delivery can be coordinated without changing the commitment or proof semantics.

### 4.6 Merkle membership

Every accepted note commitment becomes a leaf in the protocol commitment tree.

To spend a note, the client supplies the circuit with:

- the note commitment preimage;
- the note commitment randomness;
- a Merkle authentication path;
- the leaf position;
- ownership key material.

The circuit recomputes the note commitment and follows the authentication path to a public anchor. This proves that the consumed note belongs to an accepted tree state without revealing which commitment in the tree is being spent.

The wallet maintains its own synchronized tree representation so it can produce authentication paths locally.

### 4.7 Nullifiers

A valid membership proof alone would allow the same note to be spent repeatedly. The nullifier solves that problem.

The nullifier is derived from private ownership material, the note commitment, and its position. It is deterministic for a given spendable note but does not directly reveal the corresponding commitment.

`zeosprotocol` publishes and stores nullifiers. A proof is rejected when its nullifier already exists, preventing double spending while preserving ambiguity about the consumed leaf.

### 4.8 Public and private fields

The protocol does not make every part of a transaction invisible.

During a fully shielded sequence, note contents and contract-qualified asset identity can remain committed rather than directly disclosed. The chain still sees commitments, nullifiers, proofs, timing, and the fact that a protocol action occurred.

Where value crosses the transparent boundary, the underlying asset contract and public transfer data must be available to `zeosprotocol`. Authenticated application actions are also visible to the target contract and to the chain.

Privacy is therefore operation-specific:

- shielded ownership and note contents remain private;
- transparent deposits and exits expose the information required by the underlying asset contract;
- auth tokens can hide the controlling wallet identity, but do not make arbitrary application execution confidential.

---

## 5. Protocol Actions and Circuit Architecture

Protocol operations and proving circuits do not have a one-to-one relationship.

A **protocol operation** describes what the user or application is doing. A **circuit statement** describes what must be proven privately. An **on-chain verification path** describes how `zeosprotocol` verifies the proof and applies the state transition.

Different operations may reuse one circuit when their private statements have the same structure. Minting and authentication are the important example.

### 5.1 Circuit set

The active transaction engine uses four circuit implementations:

- `Mint`, shared by public-to-shielded minting and auth-token authentication;
- `Spend`, for consuming a shielded note;
- `Output`, for creating a shielded output;
- `SpendOutput`, for atomically consuming a note while creating a successor note and/or releasing public value.

Each distinct constraint system has its own proving and verifying material. Mint and authentication deliberately share the same parameters because they reuse the same constraint system.

### 5.2 Shared mint/authentication circuit

The `Mint` circuit proves the correctness of a note commitment while exposing a compact public representation of the note’s context.

It commits to the note’s:

- account;
- value;
- symbol;
- contract;
- shielded address;
- commitment randomness.

It then exposes:

1. the resulting note commitment;
2. packed value, symbol, and contract data;
3. either a public account or an authentication hash.

The circuit recognizes an auth token through the note encoding:

```text
value == 0
symbol == 0
```

That signal selects the authentication form of the third public input.

#### Public-to-shielded mint

For an ordinary deposited asset, the proof binds a new shielded commitment to:

- the deposited amount or NFT identifier;
- the symbol convention;
- the issuing asset contract;
- the public account involved in the deposit.

`zeosprotocol` can therefore accept the public asset and insert the proven commitment without learning the note’s shielded owner from the commitment itself.

The word “mint” refers to minting a shielded note representation. It does not imply issuing new units of the underlying token.

#### Authentication

For an auth-token note, the same circuit is reused with different semantics.

The circuit additionally enforces that:

- the note’s application account and contract scope agree;
- the note recipient is derived from the proven key material;
- the public context is the authentication hash rather than a depositor account.

The authentication hash binds the proof to the exact action context constructed by the client and validated by `zeosprotocol`.

Reusing the circuit is not merely code reuse. It avoids creating a redundant constraint system and a separate trusted setup for a statement that is almost structurally identical.

### 5.3 Spend circuit

The `Spend` circuit proves that the prover may consume an existing note.

Its responsibilities include:

- deriving the note recipient from the proven key material;
- reconstructing the note commitment;
- proving membership under a public Merkle anchor;
- deriving the correct nullifier;
- committing to the note’s contract-qualified asset identity;
- producing a Pedersen commitment to the consumed value.

The public verifier learns the anchor, nullifier, randomized symbol commitment, and value commitment, but not the note plaintext or the consumed commitment’s position.

A spend proof alone does not create a recipient note. It contributes an input-side value commitment to a larger spend sequence.

### 5.4 Output circuit

The `Output` circuit proves the correctness of a newly created fully shielded note.

It binds:

- the output amount;
- symbol and issuing contract;
- shielded recipient;
- note randomness;
- resulting note commitment.

It also produces:

- the same form of randomized symbol commitment used by the input side;
- a Pedersen commitment to the output value.

For ordinary shielded outputs, the public account field is constrained to the neutral value. This prevents an internal transfer output from silently carrying transparent-boundary semantics.

Spend and Output proofs can therefore be combined while remaining independently provable: the symbol commitments establish asset consistency, and the value commitments establish conservation.

### 5.5 Confidential per-asset conservation

In a single-asset privacy protocol, balancing numerical values is enough because every value represents the same currency.

In a multi-asset protocol, this would be unsafe:

```text
spend:  100.0000 USD issued by contract A
output: 100.0000 USD issued by contract B
```

The numbers and symbols match, but the assets do not.

ZEOS Caterpillar computes a randomized symbol commitment over:

```text
symbol + issuing contract
```

Spend, Output, and SpendOutput components in the same asset sequence use a consistent commitment. This proves that their values refer to one contract-qualified asset without requiring that identity to be revealed during a fully shielded transfer.

Pedersen value commitments then provide confidential arithmetic:

```text
sum(input commitments)
=
sum(output commitments)
+ public value transition
```

`zeosprotocol` performs the corresponding group operations and rejects an unbalanced sequence.

The two mechanisms solve different problems:

- the symbol commitment proves **which asset class** is being conserved;
- the value commitment proves **how much of that asset** is conserved.

### 5.6 Why NFTs require different constraints

Fungible value commitments are additive. That property is useful for token quantities and dangerous for object identifiers.

Consider a zero-symbol note whose amount field contains NFT identifier `100`. Ordinary value balancing alone cannot distinguish that identifier from a fungible quantity. A malicious construction could satisfy arithmetic such as:

```text
100 = 40 + 60
```

while violating the actual asset semantics.

The transaction builder therefore selects NFTs by exact identifier rather than accumulating note values. The circuits must also enforce that the object cannot be divided.

### 5.7 The `spend_output` circuit

`SpendOutput` couples the input and destination semantics inside one proof.

It relates:

- **note A**, the consumed shielded note;
- **note B**, a successor shielded note;
- **value C**, value released to one or more public recipients.

For fungible assets, the circuit computes the net relationship:

```text
net value = A - (B + C)
```

and exposes a Pedersen commitment to the absolute net value together with public comparison flags indicating whether A is greater than or equal to the combined destination value. These outputs allow the contract to aggregate the net commitment with the rest of the transaction in the correct direction.

For NFTs, the circuit activates an additional indivisibility constraint:

```text
A = B XOR C
```

Here the expression is semantic rather than bitwise application logic: exactly one destination receives the complete object.

An NFT may therefore:

```text
remain shielded as one exact successor note
or
exit publicly as that exact NFT
```

It cannot be:

- divided between a shielded note and a public recipient;
- split across multiple successor values;
- converted into a fungible change amount;
- duplicated into both destinations.

This is why `spend_output` exists in addition to the separate `spend` and `output` circuits. It enforces continuity for an indivisible object at the point where independent additive proofs would be insufficient.

### 5.8 Binding public recipients

A public exit involves more than revealing an amount. The prover must not be able to prove one public value and then redirect it through different transfer data.

`SpendOutput` accepts a hash of the unshielded output description as a public input. `zeosprotocol` independently hashes the actual public recipients, amounts or NFT identifiers, accounts, and memo data and verifies that the result matches the proof input.

This binds the zero-knowledge statement to the precise public transfer list.

Fungible exits may be distributed across multiple public recipients as long as the total equals the proven public value. An NFT exit must resolve to one exact public object transfer.

### 5.9 Transaction assembly

A high-level shielded transaction may contain multiple proof components:

```text
spend sequence
    ├── zero or more SpendOutput proofs
    ├── zero or more Spend proofs
    └── zero or more Output proofs
```

The client:

1. selects the required notes;
2. constructs exact NFT or fungible destinations;
3. creates change where valid;
4. chooses shared asset-commitment randomness;
5. assigns value-commitment randomness so commitments balance;
6. generates the required proofs;
7. encrypts new notes;
8. serializes the complete Antelope action sequence.

`zeosprotocol` verifies all components and applies the public state changes atomically. Either the complete action succeeds or none of its commitments, nullifiers, or public transfers are accepted.

---

## 6. Auth Tokens and Smart-Contract Interaction

### 6.1 Bridging two state models

A shielded UTXO system and an account-based smart-contract platform express ownership differently.

The shielded protocol proves:

> The prover controls a private note that satisfies the circuit.

An Antelope application normally asks:

> Which account authorized these exact actions?

Requiring a normal Antelope account would reveal the user’s public identity and link the application interaction to their transparent history. Auth tokens provide a protocol-native bridge between the two models.

### 6.2 Auth tokens as private capabilities

An auth token is represented through the same note machinery as other shielded objects:

```text
amount = 0
symbol = 0
application contract defines the scope
```

Its commitment becomes a pseudonymous application handle. Control of the note’s private key material provides the capability to authenticate as that handle.

The application can associate orders, positions, vault state, game state, permissions, or other records with the commitment rather than with a public Antelope account.

This does not require the application to understand the user’s shielded wallet, spending key, or other notes.

### 6.3 Application scoping

The shared Mint/Auth circuit constrains the auth-token note so that its account and contract context agree. This binds the token to the intended application scope instead of creating a universal, context-free credential.

The on-chain authentication path further limits the actions that may be dispatched under that authorization. A token intended for one application cannot simply be repurposed as proof of control for an unrelated contract.

### 6.4 Proof-bound action authorization

The client constructs an authentication hash over the action context. The on-chain implementation binds this context to:

- the current replay-protection counter;
- the exact packed action bundle;
- the target application contract.

The auth-token proof exposes that hash through the shared Mint/Auth circuit.

`zeosprotocol` recomputes the hash, verifies the proof, checks the allowed action targets, and increments the authentication counter after success. A proof generated for one action bundle or counter value cannot be replayed for another.

The central property is:

> Control of a shielded auth-token secret authorizes an exact smart-contract action bundle without revealing the controlling public account.

### 6.5 Atomic token creation and substitution

The transaction builder can create new auth-token notes and make their commitments available to later application data in the same transaction-construction flow.

The implemented placeholder mechanism supports references such as:

```text
$AUTH0
$AUTH1
...
$AUTH9
```

The client replaces these placeholders with the corresponding newly created commitments. This allows a transaction to:

1. create a private application capability;
2. use its public commitment as an application identifier;
3. deposit or associate state with that identifier;

without requiring a separate manual round trip.

### 6.6 Privacy boundary

Auth tokens provide pseudonymous control, not universal confidential computation.

They can hide:

- the public account controlling the interaction;
- the shielded wallet from which the capability was derived;
- links between separately created application identities, subject to usage patterns.

They do not automatically hide:

- the target contract;
- the packed actions sent to that contract;
- public application state;
- timing and network metadata;
- consequences that the application deliberately records publicly.

An application must still design its own state and action model carefully. ZEOS Caterpillar supplies private authorization and value entry or exit; it cannot make arbitrary transparent contract logic secret.

---

## 7. Wallet and Client-Side Engine

### 7.1 Wallet initialization

A wallet may be created from either:

- seed material with spending capability; or
- incoming viewing material for read-only synchronization.

A spending wallet derives its full viewing key and default diversified address from the seed. A read-only wallet stores no spending seed and cannot construct valid spends.

Wallet metadata binds the local state to:

- chain ID;
- protocol contract;
- vault contract;
- alias authority;
- current block and leaf progress;
- current authentication counter.

### 7.2 Local note state

The wallet tracks separate note pools:

- unspent notes;
- spent notes;
- outgoing notes;
- unpublished encrypted notes.

It also maintains a local commitment-tree cache and the current leaf count needed to construct authentication paths.

The distinction between received and outgoing notes matters because note encryption supports both recipient decryption and sender-side output recovery. A sender can reconstruct the notes it created even when it cannot decrypt them through the recipient viewing key.

### 7.3 Ledger synchronization

Wallet synchronization consumes public chain data produced by the protocol:

- commitment leaves;
- encrypted note payloads;
- nullifiers;
- protocol action data;
- block numbers and timestamps;
- authentication events.

For each transmitted ciphertext, the wallet attempts recipient decryption. Successful decryption yields the private note fields, which can then be matched to a commitment in the synchronized tree.

The wallet also checks published nullifiers against locally owned notes. A match moves a note from the unspent set to the spent set.

### 7.4 Asset-specific views

The wallet exposes distinct views for:

- fungible tokens;
- non-fungible tokens;
- authentication tokens.

Fungible balances are grouped by both symbol and issuing contract. NFT queries select zero-symbol notes with non-zero identifiers. Auth-token queries select zero-symbol, zero-amount notes and can be filtered by application contract and spent state.

The separation exists at the semantic layer; all three still use the same note, encryption, commitment, and wallet infrastructure.

### 7.5 Note selection

Fungible and non-fungible selection use deliberately different algorithms.

#### Fungible tokens

The client filters notes by:

- issuing contract;
- symbol;
- non-NFT semantics.

It selects notes until their sum covers the requested quantity and computes fungible change when the selected value exceeds the destination value.

#### NFTs

The client searches for one exact note matching the requested NFT identifier. It does not accumulate or split zero-symbol values.

This client-side rule complements the circuit-level no-splitting constraint. Correct selection improves transaction construction; the circuit remains the authoritative proof that invalid splitting did not occur.

### 7.6 Transaction construction

The transaction engine accepts a high-level description of protocol actions and resolves it into contract-ready data.

Its responsibilities include:

- validating chain and contract context;
- resolving shielded recipients;
- selecting spendable notes;
- creating change notes;
- constructing public output descriptions;
- creating or selecting auth tokens;
- assigning value- and symbol-commitment randomness;
- creating Merkle witnesses;
- assembling circuit instances;
- generating proofs;
- encoding proofs and scalar values in the contract’s expected format;
- producing encrypted note ciphertexts;
- packing Antelope actions and transaction data.

This is more than a thin cryptographic library. It is the protocol-aware planner that converts user intent into a valid multi-proof state transition.

### 7.7 Proof generation

Groth16 proof generation runs entirely on the client.

The library loads the proving parameters corresponding to the required circuit and constructs the witness from private wallet state. The resulting proof is serialized in the affine little-endian format expected by the on-chain verifier.

The native target uses the Rust proving backend directly. Browser builds use the Rust/WASM-compatible backend and may enable multicore proving through Web Workers. This client-side proving path is separate from the C++/Leap host-function stack used for on-chain verification.

Proof generation is computationally heavier than verification. When performed locally, it requires no remote proving service and does not disclose the private witness outside the client environment.

### 7.8 Wallet persistence and encryption

The wallet supports binary and JSON serialization of its synchronized state, including note pools, chain metadata, Merkle leaves, and unpublished-note data.

The repository also includes wallet-encryption support so stored wallet material does not need to remain as unprotected plaintext. Application integrators remain responsible for secure password handling, backups, process isolation, and platform-specific secret storage.

### 7.9 Integration targets

The Cargo manifest builds the library as:

- a normal Rust library;
- a C-compatible dynamic library;
- a static library.

The public C header exposes the integration boundary for native non-Rust applications. The browser target exposes corresponding functionality through `wasm-bindgen`.

This allows the same protocol engine to serve:

- Rust applications;
- C or C++ desktop wallets;
- native service integrations;
- browser-based wallets and dApps.

---

## 8. Parameters and Trusted Setup

### 8.1 Circuit-specific parameters

Groth16 requires proving and verifying material tied to the exact constraint system.

The current active constraint systems are:

- Mint/Auth;
- Spend;
- Output;
- SpendOutput.

Minting and authentication share one parameter set because they share the Mint circuit.

Clients need the proving parameters to generate proofs. `zeosprotocol` needs the matching verifying keys to validate them. A proof generated against one circuit version or parameter set cannot be accepted under a different verifying key.

### 8.2 Development parameters

For local testing, developers may generate fresh parameters without a full production ceremony. Such parameters are useful for:

- circuit development;
- integration testing;
- local contract deployments;
- proof-format validation;
- performance testing.

They do not by themselves provide a credible production trusted setup.

### 8.3 Production ceremony

Groth16 security depends on the structured reference string being generated without retaining the secret setup material commonly called toxic waste.

A multiparty computation ceremony distributes that trust. The intended guarantee is that the final parameters remain secure if at least one honest participant destroys their secret contribution.

When a constraint system changes, new circuit-specific Groth16 parameters must be produced. In a phased setup, the reusable phase-one Powers of Tau material may remain valid, while the circuit-specific phase-two contribution must be repeated. Reusing the Mint circuit for authentication avoids an unnecessary additional constraint system and phase-two setup, but it does not remove the setup assumption for that shared circuit.

### 8.4 `zeos-caterpillar-mpc`

The [`zeos-caterpillar-mpc`](https://github.com/mschoenebeck/zeos-caterpillar-mpc) repository contains the parameter-generation and multiparty-ceremony tooling associated with the protocol circuits.

This main repository consumes the resulting proving material. It does not attempt to duplicate the full ceremony workflow.

Parameter provenance should always be documented by a deployment. Users should be able to determine:

- which circuit revision the parameters correspond to;
- how the ceremony was conducted;
- which transcript or contribution records exist;
- which verifying keys are active in `zeosprotocol`.

---

## 9. Privacy, Security, and Limitations

### 9.1 Intended privacy properties

The protocol is designed to protect, where the selected operation permits it:

- ownership of shielded notes;
- shielded recipient addresses;
- note values;
- contract-qualified asset identity during fully shielded transfer sequences;
- links between consumed commitments and published nullifiers;
- the public account or wallet controlling an auth-token interaction.

The proof reveals that the required statement is true, not the witness used to prove it.

### 9.2 Publicly observable information

The underlying blockchain remains public. Observers can see:

- that a protocol action occurred;
- the submitting transaction and authorizations used to submit it;
- Groth16 proofs and public inputs;
- note commitments;
- nullifiers;
- Merkle-tree updates;
- encrypted note ciphertexts when published on-chain;
- action timing and ordering;
- public deposit and withdrawal data;
- target contracts and packed application actions used with auth tokens.

A public deposit or withdrawal necessarily identifies the underlying token or NFT contract and the public side of the transfer.

### 9.3 Per-operation disclosure

Privacy varies by operation.

#### Fully shielded transfer

The owner, recipient, values, and contract-qualified asset identity are represented through commitments and encrypted notes. Commitments, nullifiers, proof data, and timing remain public.

#### Public-to-shielded deposit

The public sender, deposited asset, and public quantity or NFT identifier are visible at the transparent boundary. The resulting shielded recipient and later ownership remain private.

#### Shielded-to-public withdrawal

The public recipient, asset, and released quantity or NFT identifier are visible. The consumed note and its prior shielded history are not directly identified by the proof.

#### Authenticated application action

The target application and action bundle are visible. The auth-token commitment is pseudonymous, and the controlling wallet or public account need not be disclosed.

### 9.4 Cryptographic assumptions

Security depends on the correctness and security of:

- the circuit constraints;
- Groth16;
- BLS12-381 and Jubjub arithmetic;
- Pedersen commitments;
- Blake2-based hashes and personalizations;
- note encryption and key agreement;
- wallet key derivation;
- the trusted setup;
- serialization shared by client and contract;
- the on-chain verifier and native host functions.

A sound proof system cannot compensate for an incorrectly specified circuit statement. Circuit review is therefore as important as the underlying proving system.

### 9.5 Client responsibilities

The client controls the private keys and witnesses. A compromised client can:

- disclose spending or viewing keys;
- leak note plaintexts;
- reveal address linkage;
- construct privacy-damaging application patterns;
- lose access to funds through missing backups;
- expose metadata before the proof reaches the chain.

The library provides cryptographic primitives and wallet machinery, not a complete secure operating environment.

### 9.6 Metadata

ZEOS Caterpillar does not hide all metadata.

Potential correlation sources include:

- transaction timing;
- network origin;
- unique public amounts;
- uncommon asset transitions;
- immediate deposit-and-withdrawal patterns;
- repeated auth-token use;
- application-specific state;
- external wallet or browser telemetry.

Users and integrators must distinguish cryptographic note privacy from traffic-analysis resistance.

### 9.7 Asset and application support

The note and circuit model is generic across contract-qualified fungible assets and NFTs. Public deposits and withdrawals still depend on `zeosprotocol` understanding the relevant token or NFT transfer interface.

Supporting an additional NFT standard may therefore require an on-chain adapter even though the shielded note and proof semantics remain unchanged.

Similarly, auth tokens provide a private authorization primitive, but a target application must explicitly integrate the protocol model. Existing public contract state does not become private automatically.

### 9.8 State growth and availability

Commitments and nullifiers create persistent on-chain state. Wallets also need reliable access to the commitment leaves, encrypted note data, and protocol events required for synchronization.

Implementations must account for:

- long-term table growth;
- indexing and history availability;
- wallet resynchronization;
- parameter distribution;
- compatible contract and client versions;
- availability of the required BLS host functions.

### 9.9 Audit and status

This repository contains a working implementation rather than a design-only proposal, and its components have been exercised against deployed Antelope contracts.

That fact is not equivalent to an independent security audit.

Unless a specific audit report is published for the exact circuit, client, parameter, and contract versions in use, integrators should treat the system as unaudited cryptographic software and perform their own review before relying on it for material value.

No statement in this document guarantees:

- perfect anonymity;
- resistance to every linkage or metadata attack;
- correctness of an arbitrary deployment;
- safety of unreviewed parameters;
- compatibility with every Antelope chain or token standard.

---

## 10. Implementation Map and Related Work

### 10.1 Repository map

The implementation is organized by protocol responsibility rather than as one monolithic module.

```text
include/
    zeos-caterpillar.h       C-compatible integration interface

src/
    circuit/                 Groth16 circuit implementations and gadgets
    note/                    note commitment and nullifier components
    address.rs               diversified shielded addresses
    keys.rs                  spending and viewing key hierarchy
    note.rs                  unified note representation
    note_encryption.rs       recipient encryption and outgoing recovery
    transaction.rs           protocol-aware transaction construction
    wallet.rs                synchronized wallet and note-state engine
    wallet_encryption.rs     encrypted wallet persistence
    contract.rs              contract-facing data types and encodings
    eosio.rs                 Antelope names, assets, actions, and packing
    value.rs                 value commitments and trapdoors
    pedersen_hash.rs         Pedersen hash implementation
    blake2s7r.rs             Merkle hashing support
    engine.rs                proving-engine abstraction
    lib.rs                   Rust, native, and WASM exports

web/
    browser proof-generation demonstration
```

The transaction engine currently uses the Mint, Spend, Output, and SpendOutput circuits. Other circuit source files in the repository may reflect earlier development paths or supporting experiments and should not be assumed to define the active protocol without checking current call sites.

### 10.2 Related repositories

#### `zeosprotocol`

The on-chain Antelope counterpart. It verifies proofs, maintains commitment and nullifier state, executes public asset transitions, and dispatches authenticated application actions.

#### [`zeos-caterpillar-mpc`](https://github.com/mschoenebeck/zeos-caterpillar-mpc)

Parameter-generation and multiparty-ceremony tooling for the Groth16 circuits.

#### [`bls12-381-cdt`](https://github.com/mschoenebeck/bls12-381-cdt)

Header-oriented BLS12-381 and Groth16 utilities for Antelope smart contracts, backed by native host functions.

#### [`bls12-381`](https://github.com/mschoenebeck/bls12-381)

The native C++ BLS12-381 implementation underlying the corresponding Leap cryptographic host-function work.

### 10.3 Related implementation

[CLOAK](https://cloak.today) is an implementation of the ZEOS Caterpillar Shielded Protocol.

### 10.4 Licensing and acknowledgements

`zeos-caterpillar` is dual-licensed under:

- Apache License 2.0;
- MIT License.

The protocol and implementation build on the foundational work of the Zcash and Sapling engineering community, including the note, key, commitment, encryption, and proving-system designs from which ZEOS Caterpillar derives.

ZEOS Caterpillar extends that lineage into a different execution and application environment: a programmable smart-contract chain with independently issued fungible tokens, NFTs, and private application capabilities.
