# ParanO(1)d

**Proof-Native transparent statechain (L1 PoW blockchain).**

Blockchains have a fundamental architectural flaw: to validate the present,
you must replay the past. Bitcoin, Ethereum, and nearly every major network
inherit this property. A new full node downloads the chain from genesis and
re-executes every transaction because the current state does not prove itself.
This is not a temporary limitation. It is baked into the model.

ParanO(1)d is designed to remove this requirement.

In ParanO(1)d, validity is established once, where the complete information
already exists. Authorization is proved locally by the party with the private
witness — the wallet owner. The miner proves the public transaction logic and
the exact state transition. The network verifies those proofs instead of
repeating the same execution.

Every accepted block carries a recursive `HistoryStep` that binds the block,
its new UTXO root, and the validity of the preceding statechain. A new node can
therefore authenticate the current state and verify the recent reorg suffix
without executing the chain from genesis.

Once the present state carries its own proof, a different architecture becomes
possible. Spent state can be deleted and reused. Ownership no longer needs a
public key or digital signature. State growth can be priced directly. Proof of
work can order transitions whose validity is already established. The result
is an L1 whose age does not become a hardware requirement. Years later, an
ordinary laptop can still hold the complete live state and independently
verify the network without replaying the chain's lifetime.

## The Fundamental Shift

| | Conventional blockchain | ParanO(1)d |
|---|---|---|
| Validation | Every full node re-executes | The witness holder proves; the network verifies |
| Bootstrap | Rebuild state from genesis | Authenticate current state and verify the recent suffix |
| Ownership | Public-key signature | Fresh ZK proof of a Poseidon2b preimage |
| State | Derived from accumulated history | Exact live UTXO state is a consensus object |
| Spent outputs | Remain part of required history | Slots are cleared and safely reused |
| Proof of work | Orders an execution log | Orders proof-valid state transitions |
| Post-quantum migration | Replace the ownership scheme | No elliptic-curve transaction scheme to replace |

ParanO(1)d is transparent, not a privacy chain. Current values and owners are
public, and transactions are visible when relayed. The protocol turns history
into proof: every node carries an authenticated present instead of an
ever-growing transaction graph. Anyone may build an external tracer, but it
must record the entire transaction stream for itself; the network does not
make every node carry that burden. Privacy here comes from non-retention, not
concealment. Zero knowledge protects the spending witness; proof-native
validation removes redundant execution.

## How It Works

### Execution Is Local

When sending NOID, the wallet selects its UTXOs and creates one atomic
`PagedSpend`. It then produces a freshly randomized, witness-hiding
authorization for `{logical_txid, input_owner}`. The spending secret never
leaves the wallet.

The authorization is stateless: it contains no UTXO Merkle path and is not
tied to one state root. The miner has the public state witness and proves
separately that every input exists, every output slot is empty, values balance,
fees are correct, and the resulting state root is exact.

Private authorization is proved by the wallet. Public execution is proved by
the miner. Neither task is repeated across the network.

### The Network Verifies, Not Executes

The mempool verifies the complete transaction intent before relaying it. A
miner selects available intents immediately.

The miner combines the selected transactions, exact state transition and
preceding terminal into the next `HistoryStep`. It completes this proof before
searching for a PoW nonce. Peers receive one atomic
`{block, HistoryStep terminal}` bundle and accept it only after verifying both
the proof and the nonce.

Peers then apply the proven slot writes to advance their local UTXO set,
materializing the proof's result without re-executing transaction logic.

### History Collapses Recursively

Each `HistoryStep` proves the current block relation and verifies the previous
terminal inside the same relation. Proof size and verification work do not
increase with block height.

An active node keeps the exact live state, compact headers for cumulative work,
and the latest 18 complete blocks for competing miners and reorgs. A joining
node authenticates a finalized current state with its matching terminal, then
verifies that recent suffix normally.

ParanO(1)d is history-stateless, not state-free. State transfer scales with the
live UTXO set. What no longer scales with chain age is the execution required
to prove why that state is valid.

## Architecture

### A Living UTXO State

The state is an exact sparse vector of indexed UTXOs. Spending clears a slot;
the allocator reuses empty positions before opening new state. Every new output
has a fresh `creation_id`, so reusing the same index can never revive an old
reference.

State is divided into `2^16`-slot segments. Empty segments are virtual and a
segment disappears again when its last UTXO is spent. The slot domain begins
at `2^24` and expands automatically at 75% occupancy by attaching a canonical
empty half to the existing root. No state copy, migration or network pause is
required.

Fees distinguish ordinary I/O from net-new state. The state-growth component
rises with occupancy and is burned; consolidation pays no growth burn. Block
reward halves when the state domain actually expands, with a permanent 1 NOID
floor.

### Signatureless Ownership

An address is the Poseidon2b image of a 256-bit spending secret. Ownership is a
zero-knowledge proof of knowledge of that preimage, bound to the complete
logical transaction. There is no public key or transaction signature on the
wire.

The capsule is independently randomized on every spend, including repeated use
of the same address. Transaction consensus contains no elliptic curves. The
Ed25519 key used by libp2p identifies a peer only and has no spending or
consensus authority.

### PagedSpend

The proof system uses fixed physical pages with eight input and two output
positions. `PagedSpend` joins up to 128 pages into one user transaction with
one txid, one fee, one ZK capsule and one receipt.

A single transaction may consume up to 1,020 UTXOs and create up to 256
outputs. Continuation pages are internal proof geometry: they remain one
indivisible transaction in the wallet, mempool, relay, block, receipt and reorg
paths.

### One Binary Proof Stack

The protocol is built over the binary tower field `GF(2^128)`. Poseidon2b is
the common permutation for addresses, transactions, Merkle trees, state roots,
transcripts, block identifiers and PoW.

For ParanO(1)d, we developed FROST-GKR (Frobenius Reduction Over Shifted
Tables). It packs entire Poseidon2b batches and Merkle paths into direct
degree-seven relations over shared Boolean hypercubes instead of running a
low-degree sumcheck chain for every permutation. In a like-for-like
59-permutation benchmark, this reduces median prover time by 10.69×, median
protocol-verifier time by 14.80× and raw algebraic proof bytes by 51.67×.
Batched sumchecks, zerocheck, lincheck and FRI-Binius close the GF(2) R1CS
relation without a trusted setup. The two authenticated launch matrices — B64
at `m=23` and B255 at `m=24` — are embedded in the official binary and can be
regenerated from source. The public [FROST-GKR research
artifact](https://github.com/ignotusnemo/frost-gkr) contains the paper's
reference implementation, comparison harness and complete measurement report.

This common arithmetic is what lets wallet authorization, exact state and
recursive chain verification compose as one protocol instead of independent
proof systems glued together afterward.

### Proof-Native PoW

PoW has one job: choose the order of valid transitions. Hash power cannot make
an invalid `HistoryStep` acceptable.

The miner proves the nonce-independent block first, then searches a fixed
Poseidon2b header with a 128-bit nonce. ASERT targets a 15-second mean interval,
and cumulative work selects the chain. An external miner receives an immutable,
single-use template and returns only a nonce; it cannot alter the transactions
or state root.

## Launch Profile

| Parameter | Value |
|---|---:|
| Mean block target | 15 seconds |
| Default miner class | B64, `m=23`, up to 64 user pages |
| Large miner class | B255, `m=24`, up to 255 user pages |
| Maximum logical transactions per block | 255 |
| Maximum one-page throughput | 17 TPS |
| Maximum inputs in one transaction | 1,020 |
| Maximum outputs in one transaction | 256 |
| Recent block / reorg suffix | 18 blocks |
| State domain | `2^24` to `2^32` slots |

B64 is the laptop-class mining floor, not the protocol ceiling. On the
reference 12-thread Intel Core i7-1365U, saturated B64 preparation measures
14.387 seconds at p95 and verification measures 0.720 seconds at p95. Faster
hardware may qualify B255; every node verifies both classes. Full measurements
are in the [two-class benchmark](research/two_class/results/2026-07-17-history-step-lto-20-sample.md).

## Network

ParanO(1)d uses libp2p GossipSub for blocks and transaction intents, typed
request-response protocols for synchronization, Kademlia and DNS seeds for
discovery, and mDNS for local networks. Persistent peers, connection limits,
and IPv4/IPv6 network-group diversity reduce simple eclipse and connection
flood attacks without adding a consensus round.

Finalized state transfer is authenticated by `HistoryStep`; short gaps use
ordinary recent-block sync. Finalized transaction bodies are not required by
active consensus. Exportable Merkle receipts preserve proof of inclusion after
a body leaves the recent suffix.

## Running ParanO(1)d

The first node of a new network creates genesis and starts mining:

```sh
paranoid --miner --genesis
```

`--genesis` is only for the first node. Join an existing network as a node or
miner:

```sh
paranoid --seed <host>:9400
paranoid --miner --seed <host>:9400
```

External nonce search keeps transaction selection and proving inside the node:

```sh
paranoid --extminer --mining-key <token>
noid-extminer --key <token>
```

Default ports are `9400` for P2P and `127.0.0.1:9401` for JSON-RPC. First start
creates `~/.paranoid/paranoid.toml`, the MDBX state and the built-in wallet
under `~/.paranoid/data/`.

The current `wallet.key` is not password-encrypted. It is created with
owner-only permissions; back it up and protect it.

### CLI

Addresses use bech32m and begin with `o1`. `1 NOID = 1,000,000 μNOID`.

```sh
noid-cli status
noid-cli peers
noid-cli state
noid-cli mining
noid-cli address
noid-cli address --new
noid-cli balance
noid-cli utxos
noid-cli send <o1-address> 10.5 --dry-run
noid-cli send <o1-address> 10.5
noid-cli mempool
noid-cli history
noid-cli receipt <txid> > receipt.hex
noid-cli verify "$(tr -d '\n' < receipt.hex)"
noid-cli stop
```

Run `paranoid --help`, `noid-cli help` or `noid-extminer --help` for the full
interface.

## Building from Source

The node and proof stack are continuously built on Linux x86-64, Linux ARM64,
macOS Apple Silicon, macOS Intel and Windows x86-64. A build requires the
pinned Rust toolchain, a native C/C++ toolchain, CMake, libclang and
`pkg-config` where the platform provides it.

Official Linux and Windows x86-64 builds use an x86-64-v3, PCLMULQDQ and
VPCLMULQDQ baseline. Intel macOS uses an x86-64-v3 and PCLMULQDQ baseline so
AVX2-era Macs remain supported. Each x86-64 binary selects wider
AVX2+VPCLMULQDQ or AVX-512 kernels at runtime when available. ARM64 builds use
NEON and PMULL. There is no separate legacy x86-64 release.

The canonical self-contained release command currently runs on Linux:

```sh
git clone https://github.com/ignotusnemo/paranoid.git
cd paranoid
./scripts/build_release.sh
```

The build regenerates and authenticates both HistoryStep matrices, runs the
release tests and produces `paranoid`, `noid-cli` and `noid-extminer`.

## Status

ParanO(1)d is version `0.1.0` and pre-genesis. No public network has launched.

Designed and developed by **Ignotus Nemo**. Licensed under the
[Apache License 2.0](LICENSE). Please report security issues according to the
[security policy](.github/SECURITY.md).

Contact: [ignotus.nemo@proton.me](mailto:ignotus.nemo@proton.me)
