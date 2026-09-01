# Parano1d ①

**Proof-native Layer 1 ordered by proof of work.**

[Website](https://parano1d.org) ·
[Documentation](https://docs.parano1d.org) ·
[Research](https://lab.parano1d.org) ·
[Releases](https://github.com/ignotusnemo/parano1d/releases)

Blockchains have a fundamental architectural flaw: the present does not prove
itself. Its validity is inherited from accumulated history. Bitcoin reconstructs
that validity by validating the chain from genesis. Other networks may shorten
bootstrap with snapshots or checkpoints, but those only move the dependency
forward: the current state still does not carry a proof of its own valid path
from genesis.

A new verifier must therefore reconstruct that path or rely on state produced
by prior historical validation.

This is not a temporary limitation. It is baked into the model.

Parano1d removes this requirement.

In Parano1d, validity is established once, where the complete information
already exists. Authorization is proved locally by the party with the private
witness — the wallet owner. The miner proves the public transaction logic and
the exact state transition. The network verifies those proofs instead of
repeating the same execution.

Every accepted block carries a recursive `HistoryStep` that proves the block's
exact state transition, including its new UTXO root, and verifies the preceding
`HistoryStep` terminal. A new node can therefore authenticate the current state
and verify the recent reorg suffix without executing the chain from genesis.

Once the present state carries its own proof, a different architecture becomes
possible. Spent state can be deleted and reused. Ownership no longer needs a
public key or digital signature. State growth can be priced directly. Proof of
work can order transitions whose validity is already established. The result
is an L1 whose age does not become a hardware requirement. Years later, an
ordinary laptop can still hold the complete live state and independently
verify the network without replaying the chain's lifetime.

## The Fundamental Shift

| | Conventional blockchain | Parano1d |
|---|---|---|
| Validation | Every full node re-executes | The witness holder proves; the network verifies |
| Bootstrap | Rebuild state from genesis | Authenticate current state and verify the recent suffix |
| Ownership | Public-key signature | Fresh ZK proof of a Poseidon2b preimage |
| State | Derived from accumulated history | Exact live UTXO state is a consensus object |
| Spent outputs | Remain part of required history | Slots are cleared and safely reused |
| Proof of work | Orders an execution log | Orders proof-valid state transitions |
| Post-quantum migration | Replace the ownership scheme | No elliptic-curve transaction scheme to replace |

Parano1d is transparent, not a privacy chain. Current values and owners are
public, and transactions are visible when relayed. The protocol turns history
into proof: every node carries an authenticated present instead of an
ever-growing transaction graph. Anyone may build an external tracer, but it
must record the entire transaction stream for itself; the network does not
make every node carry that burden. Privacy here comes from non-retention, not
concealment. Zero knowledge protects the spending witness; proof-native
validation removes redundant execution.

## Soundness

| Security statement | Current production result |
|---|---:|
| Target FRI security | **128 bits** |
| Provable Block–Tiwari FS-FRI security | **127 bits** |
| Conjectured Block–Tiwari FS-FRI security | **127 bits** |
| Sequential ideal-QROM half-success boundary | **64.707407428576 bits** |
| NIST Post-Quantum Cryptography Category | **Category 1** |
| Dominant Category 1 gate-depth floor | **173.273866314232 bits** |
| Margin over the NIST `2^170` reference | **3.273866314232 bits** |
| Complete ideal bound at the Category 1 envelope | **0.053364140323608411** |

### Block–Tiwari FS-FRI comparison

[Block and Tiwari](https://eprint.iacr.org/2024/1161) define concrete FS-FRI
security as the minimum expected classical random-oracle query work over every
positive integer query budget. Applying their definitions, 256-bit
random-oracle setting and whole-bit presentation to the production B25 and
B255 profiles gives 127 provable bits and 127 conjectured bits against a
128-bit target. Both expected-work values lie in the exact interval
`[127, 128)`. The complete substitutions, integer optimization and comparison
with the systems in their published table are given in the
[Block–Tiwari derivation](noid_soundness/docs/block-tiwari.md).

### End-to-end Category 1

The end-to-end security game asks whether one stateful quantum adversary can
make the production verifier accept an invalid terminal State whose recursive
ancestry starts at genesis. The reduction covers wallet authorization, the
block relation, parent links, the exact State transition, recursive
verification and the claimed ancestry under one adversarial resource budget.

`C1` is the source identifier for the production wide-challenge profile. It
uses 65 wallet queries, 133 History queries and algebraic challenges sampled
uniformly from a trace-one affine set of cardinality `2^255` in `GF(2^256)`.
The Category 1 assessment follows from the depth-aware resource theorem, which
evaluates the NIST Post-Quantum Cryptography Category 1 reference at every
specified `MAXDEPTH` point.

The fixed Poseidon2b production corollary requires
`Delta_P2b^C1 < 0.446635859676391589` and the coherent response-cost premise
stated by the resource theorem. Under these premises, the theorem gives
provable end-to-end post-quantum soundness for state validation from genesis at
NIST PQC Category 1: every adversary inside the Category 1 resource envelope
has success probability below one half in the from-genesis invalid-State game.
The complete theorem is in the
[end-to-end QROM and Category 1 derivation](noid_soundness/docs/category-one.md).

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
and the latest 18 canonical block bodies for competing miners and reorgs. A
joining node authenticates a finalized current state with its matching
terminal, then verifies one recursive terminal at the recent suffix tip before
applying the linked bodies.

Parano1d is history-stateless, not state-free. State transfer scales with the
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
at `2^24`. It expands after a strict majority of the complete 18-header
hard-finalized window records at least 75% occupancy, attaching a canonical
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

The committed trace arithmetic is built over the binary tower field
`GF(2^128)`. The production wide-challenge layer lifts Fiat–Shamir challenges,
terminal claims and recursive region authentication into `GF(2^256)`.
Poseidon2b is the common permutation for addresses, transactions, Merkle trees,
state roots, transcripts, block identifiers and PoW.

For Parano1d, we developed FROST-GKR (Frobenius Reduction Over Shifted
Tables). It packs entire Poseidon2b batches and Merkle paths into direct
degree-seven relations over shared Boolean hypercubes instead of running a
low-degree sumcheck chain for every permutation. In a like-for-like
59-permutation benchmark, this reduces median prover time by 10.69×, median
protocol-verifier time by 14.80× and raw algebraic proof bytes by 51.67×.
Batched sumchecks, zerocheck, lincheck and FRI-Binius close the GF(2) R1CS
relation without a trusted setup. One joint `GF(2^256)` transcript binds the
three Link and six Block recursive regions into the outer PCS batch. The two
authenticated production matrices, B25 at `m=22` and B255 at `m=24`, are embedded
in the official binary and can be regenerated from source. The Parano1d Lab
[FROST-GKR research article](https://lab.parano1d.org/research/frost-gkr-global-trace-protocol/)
links the paper, reference implementation, comparison harness and complete
measurement record.

This common arithmetic is what lets wallet authorization, exact state and
recursive chain verification compose as one protocol instead of independent
proof systems glued together afterward.

### Proof-Native PoW

**Hashpower alone cannot produce blocks. Mining is stateful and proof-gated.**
A producer must follow the canonical state and complete the nonce-independent
`HistoryStep` before its internal or external worker can search the fixed
header.

PoW has one job: choose the order of valid transitions. Hash power cannot make
an invalid `HistoryStep` acceptable.

The miner proves the nonce-independent block first, then searches a fixed
Poseidon2b header with a 128-bit nonce. ASERT targets the complete interval
between accepted blocks, including proof preparation, nonce search and
propagation, at a 20-second mean. Cumulative work selects the chain. An external
miner receives an immutable, single-use template and returns only a nonce; it
cannot alter the transactions or state root.

## Mainnet Profile

| Parameter | Value |
|---|---:|
| Genesis timestamp | 2026-08-21 16:00:00 UTC |
| Genesis block ID | `860e70453390bf815718e933aa4927167a13d098b0151391eefd722ee1add610` |
| Mean block target | 20 seconds |
| Default miner class | B25, `m=22`, up to 25 effective page positions |
| Large miner class | B255, `m=24`, up to 255 effective page positions |
| Maximum logical transactions per block | 255 |
| Maximum one-page throughput | 12.75 TPS |
| Maximum inputs in one transaction | 1,020 |
| Maximum outputs in one transaction | 256 |
| Recent block / reorg suffix | 18 blocks |
| State domain | `2^24` to `2^32` slots |

B25 is the laptop-class mining floor, not the protocol ceiling. The production
capacity selector measures complete preparation on each host and uses B255 only
when that host sustains the larger class within the block cadence. Every node
verifies both classes.

## Development Allocation

Parano1d has no premine. For blocks 1 through 6,307,200 — exactly three
365-day target-time years — each block reward is divided by consensus:

- 90% to the miner;
- 5% to the O(1) Network Fund;
- 5% to Parano1d Lab.

Transaction fees remain entirely miner-claimable after the existing
state-growth burn. Beginning with block 6,307,201, the development allocation
ends and 100% of every new block reward goes to miners.

The O(1) Network Fund finances operation, maintenance, security and adoption
of the live network. Parano1d Lab supports the founders, core developers,
researchers and contributors advancing the protocol. Both will publish
periodic reports covering funds received, major expenditures, completed work
and current priorities.

## Network

Parano1d uses libp2p GossipSub for blocks and transaction intents, typed
request-response protocols for synchronization, Kademlia and DNS seeds for
discovery, and mDNS for local networks. Persistent peers, connection limits,
and IPv4/IPv6 network-group diversity reduce simple eclipse and connection
flood attacks without adding a consensus round.

Finalized state transfer is authenticated by `HistoryStep`; short gaps use
ordinary recent-block sync. Finalized transaction bodies are not required by
active consensus. Exportable Merkle receipts preserve proof of inclusion after
a body leaves the recent suffix.

## Running Parano1d

Official binaries discover the public network through the built-in DNS seeds.
Run an ordinary node or an internal miner:

```sh
parano1d
parano1d --miner
```

An explicit seed may be supplied when diagnosing discovery or operating a
private entry point:

```sh
parano1d --seed <host>:9600
```

External nonce search keeps transaction selection and proving inside the node:

```sh
parano1d --extminer --mining-key-file ~/.parano1d/mining.key
parano1d-miner --key-file ~/.parano1d/mining.key
```

The legacy `--mining-key <token>` and `--key <token>` forms remain compatible. The credential authorizes only template retrieval and nonce submission.

Pools with a separate accounting/payout host can additionally configure an owner-only `--operator-key-file`. Its fixed RPC scope is documented in [`docs/reference/rpc.md`](docs/reference/rpc.md) and does not inherit mining or node-control authority.

Default ports are `9600` for P2P and `127.0.0.1:9601` for JSON-RPC. First start
creates `~/.parano1d/parano1d.toml`, the MDBX state and the built-in wallet
under `~/.parano1d/data/`.

The current `wallet.key` is not password-encrypted. It is created with
owner-only permissions; back it up and protect it.

### CLI

Addresses use bech32m and begin with `o1`. `1 NOID = 1,000,000 μNOID`.
`NOID` is the ticker; the wallet uses `①` as its interface symbol.

```sh
parano1d-cli status
parano1d-cli peers
parano1d-cli state
parano1d-cli mining
parano1d-cli address
parano1d-cli address --new
parano1d-cli balance
parano1d-cli utxos
parano1d-cli send <o1-address> 10.5 --dry-run
parano1d-cli send <o1-address> 10.5
parano1d-cli mempool
parano1d-cli history
parano1d-cli receipt <txid> > receipt.hex
parano1d-cli verify "$(tr -d '\n' < receipt.hex)"
parano1d-cli stop
```

Run `parano1d --help`, `parano1d-cli help` or `parano1d-miner --help` for the full
interface.

## Building from Source

The node and proof stack are continuously built on Linux x86-64, Linux ARM64,
macOS Apple Silicon, macOS Intel and Windows x86-64. A build requires the
pinned Rust toolchain, a native C/C++ toolchain, CMake, libclang and
`pkg-config` where the platform provides it.

Official binaries keep a portable process-wide baseline so they can inspect
the host before entering proof code. Production requires SSE4.1 and
PCLMULQDQ on x86-64, or NEON and PMULL on ARM64. Each binary then selects the
`pclmul`, `avx2+vpclmul`, `avx512bw+vpclmul` or `neon+pmull` backend at runtime. The
scalar implementation is a differential-test oracle and is never used by a
production node. Run `parano1d --check-hardware` before installation to see
the selected backend without creating configuration, wallet or chain data.

To reproduce a published release, check out the tag shown on its GitHub release
page. Then generate the HistoryStep matrices locally. This is the trustless
path: the machine derives and authenticates the pack instead of accepting
matrix bytes supplied by the project. Keep the pack outside the repository's
disposable `target/` tree:

```sh
git clone https://github.com/ignotusnemo/parano1d.git
cd parano1d

mkdir -p ../parano1d-artifacts
./scripts/generate_history_step_pack.sh \
  ../parano1d-artifacts/history-step-pack-v1
```

Generation is expensive but only needs to be performed once.

Build for the current machine. The script authenticates the pack, embeds it
into the node and produces two independent deliverables:

- a Core archive containing `parano1d`, `parano1d-cli` and `parano1d-miner`;
- a native GUI Wallet package containing `parano1d-gui` and its private,
  locally supervised `parano1d` node.

```sh
./scripts/build_release.sh \
  --pack ../parano1d-artifacts/history-step-pack-v1

cat target/release-builds/LAST_RELEASE
```

For a faster build, the corresponding GitHub release also carries the
authenticated `history-step-pack-v1.tar.gz`. Extract it and pass the contained
directory to the same build command:

```sh
mkdir -p ../release-pack
tar -xzf /path/to/history-step-pack-v1.tar.gz -C ../release-pack

./scripts/build_release.sh \
  --pack ../release-pack/history-step-pack-v1
```

To reproduce the production soundness calculation, see
[`noid_soundness`](noid_soundness/README.md) and run:

```sh
cargo run --release --locked -p noid_soundness
```

Designed and developed by **Ignotus Nemo**. Licensed under the
[Apache License 2.0](LICENSE). Please report security issues according to the
[security policy](.github/SECURITY.md).

Contact: [dev@parano1d.org](mailto:dev@parano1d.org)
