# Parano1d ①

**Proof-native Layer 1 ordered by proof of work.**

Blockchains have a fundamental architectural flaw: the present does not prove
itself. Its validity is inherited from accumulated history. Bitcoin reconstructs
that validity by validating the chain from genesis. Other networks may shorten
bootstrap with snapshots or checkpoints, but those only move the dependency
forward: the current state still does not carry a proof of its own valid path
from genesis.

A new verifier must therefore reconstruct that path or rely on state produced
by prior historical validation.

This is not a temporary limitation. It is baked into the model.

Parano1d is designed to remove this requirement.

Validity is established once, where the complete information already exists.
The wallet proves authorization with its private witness. The miner proves the
public transaction logic and the exact State transition. The network verifies
those proofs instead of repeating the same execution.

Every accepted block carries a recursive `HistoryStep` that proves the block's
exact State transition, including its new UTXO root, and verifies the preceding
`HistoryStep` terminal. A new node can authenticate the current State and verify
the recent reorg suffix without
executing the chain from genesis.

Once the present State carries its own proof, spent records can be deleted and
their slots reused. Ownership no longer needs a public key or digital signature. State
growth can be priced directly. Proof of work can order transitions whose
validity is already established. The age of the network does not become a
hardware requirement.

## The fundamental shift

| | Conventional blockchain | Parano1d |
|---|---|---|
| Validation | Every full node re-executes | The witness holder proves; the network verifies |
| Bootstrap | Rebuild state from genesis | Authenticate current State and verify the recent suffix |
| Ownership | Public-key signature | Fresh ZK proof of a Poseidon2b preimage |
| State | Derived from accumulated history | Exact Live State is a consensus object |
| Spent outputs | Remain part of required history | Slots are cleared and safely reused |
| Proof of work | Orders an execution log | Orders proof-valid State transitions |
| Post-quantum migration | Replace the ownership scheme | No elliptic-curve transaction scheme to replace |

## One transition, proved once

When sending NOID, the wallet selects its UTXOs and creates one atomic
`PagedSpend`. It produces a freshly randomized, witness-hiding authorization
for `{logical_txid, input_owner}`. The 256-bit spending secret never leaves the
wallet.

The authorization is stateless: it contains no UTXO Merkle path and is not
tied to one State root. The miner holds the public State witness and proves
separately that every input exists, every output slot is empty, values balance,
fees are correct and the resulting State root is exact.

The mempool verifies a complete transaction intent before relaying it. The
miner combines accepted intents, the exact State transition and the preceding
terminal into the next `HistoryStep`. It proves the nonce-independent block
before searching for a PoW nonce.

Peers receive one atomic `{block, HistoryStep terminal}` bundle. They verify
the proof and nonce, then apply the proven slot writes to their local UTXO set.
They materialize the result without re-executing the transaction logic.

[See the complete proof and block flow →](architecture/overview.md)

## Mining requires State

**Hashpower alone cannot produce blocks. Mining requires State; nonce search
begins only after the proof is complete.**

An independent miner follows the canonical chain, holds the current State,
selects transactions and proves the exact next `HistoryStep`. Only after that
proof is complete can an internal or external worker search the immutable
Poseidon2b header nonce. A standalone hash engine cannot originate a block or
change the transition it is working on.

Mining infrastructure therefore doubles as network infrastructure: an
independent block producer is a proving full node backed by hashpower, not only
a nonce-search device.

[Understand mining and start a miner →](mining/index.md)

## A present that proves itself

Each `HistoryStep` proves the current block relation and verifies the previous
terminal inside the same relation. Proof size and verification work do not
increase with block height.

An active node keeps the exact Live State, compact headers for cumulative work
and the latest 18 canonical block bodies for competing miners and reorgs. A
joining node authenticates a finalized State with its matching terminal, then
verifies one recursive terminal at the recent suffix tip before applying the
linked bodies.

Parano1d is history-stateless, not state-free. `State` transfer scales with the
live UTXO set. What no longer scales with chain age is the execution required
to prove why that State is valid.

## Signatureless ownership

An address is the Poseidon2b image of a 256-bit spending secret. Ownership is a
zero-knowledge proof of knowledge of that preimage, bound to the complete
logical transaction. There is no public key or transaction signature on the
wire.

The authorization capsule is independently randomized on every spend,
including repeated use of the same address. Transaction consensus contains no
elliptic curves. The Ed25519 key used by libp2p identifies a peer only and has
no spending or consensus authority.

Parano1d is transparent, not a privacy chain. Values, owners and relayed
transactions are public. Zero knowledge protects the spending witness.
Protocol storage reduces routine transaction-body retention, but it cannot
prevent third parties from archiving public transactions.

## Live State

State is an exact sparse vector of indexed UTXOs. Spending clears a slot, and
the allocator reuses empty positions before opening new State capacity. Every output
has a fresh `creation_id`, so reusing an index can never revive an old
reference.

The vector is divided into `2^16`-slot segments. Empty segments are virtual and
a segment disappears when its last UTXO is spent. The slot domain begins at
`2^24` and can expand without copying State, migrating outputs or pausing the
network.

Fees distinguish ordinary I/O from net-new State. The State-growth component
rises with occupancy and is burned; consolidation pays no growth burn. The
block reward halves when the State domain expands, with a permanent 1 NOID
floor.

## One binary proof stack

Committed trace arithmetic uses the binary tower field `GF(2^128)`. The
production wide-challenge layer lifts Fiat–Shamir challenges, terminal claims
and recursive region authentication into `GF(2^256)`. Poseidon2b is the common
permutation for addresses, transactions, Merkle trees, State roots,
transcripts, block identifiers and proof of work.

[FROST-GKR](research/frost-gkr.md) packs Poseidon2b batches and Merkle paths into direct degree-seven
relations over shared Boolean hypercubes. Batched sumchecks, zerocheck,
lincheck and FRI-Binius close the binary R1CS relation without a trusted setup.
Wallet authorization, exact State transition and recursive chain verification
therefore compose inside one arithmetic system instead of separate proof
systems joined afterward.

## Soundness

| Security statement | Current production result |
|---|---:|
| Target FRI security | **128 bits** |
| Provable Block–Tiwari FS-FRI security | **127 bits** |
| Conjectured Block–Tiwari FS-FRI security | **127 bits** |
| Sequential ideal-QROM half-success boundary | **64.707407428576 bits** |
| NIST Post-Quantum Cryptography Category | **Category 1** |
| Dominant Category 1 gate-depth floor | **173.391078499301 bits** |
| Margin over the NIST `2^170` reference | **3.391078499301 bits** |
| Complete ideal bound at the Category 1 envelope | **0.049330348213215253** |

[Block and Tiwari](https://eprint.iacr.org/2024/1161) define concrete FS-FRI
security as the minimum expected classical random-oracle query work over every
positive integer query budget. Their definitions and whole-bit presentation
give 127 provable bits and 127 conjectured bits for the production B25 and B255
profiles. The complete calculation and published-system comparison are in the
[Block–Tiwari derivation](https://github.com/ignotusnemo/parano1d/blob/main/noid_soundness/docs/block-tiwari.md).

The separate end-to-end game asks whether one stateful quantum adversary can
make the production verifier accept an invalid terminal State whose recursive
ancestry starts at genesis. Under the fixed Poseidon2b delta and coherent
response-cost premises stated in the theorem, the result is provable end-to-end
post-quantum soundness for state validation from genesis at NIST PQC Category 1. See the
complete [QROM and Category 1 derivation](https://github.com/ignotusnemo/parano1d/blob/main/noid_soundness/docs/category-one.md)
and the [security model](protocol/security-model.md).

## Protocol profile

| Parameter | Value |
|---|---:|
| Mean block target | 20 seconds |
| Default miner class | B25, `m=22`, up to 25 effective page positions |
| Large miner class | B255, `m=24`, up to 255 effective page positions |
| Maximum logical transactions per block | 255 |
| Maximum one-page throughput | 12.75 TPS |
| Maximum inputs in one transaction | 1,020 |
| Maximum outputs in one transaction | 256 |
| Recent block and reorg suffix | 18 blocks |
| State domain | `2^24` to `2^32` slots |

## Start

- Install the native GUI wallet from the
  [latest release](https://github.com/ignotusnemo/parano1d/releases). It
  includes and supervises its own full node.
- Read the [architecture overview](architecture/overview.md) to follow a
  transaction from the wallet to accepted State.
- [Run an ordinary node on Linux](operate/node.md).
- [Run an internal or external miner](mining/index.md).
- Inspect or build the
  [source](https://github.com/ignotusnemo/parano1d) with the pinned Rust
  toolchain.

The source code is the canonical definition of consensus behavior. The
protocol specification documents those rules in a stable, implementation-
independent form.
