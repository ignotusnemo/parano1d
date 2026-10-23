# Parano1d ①

Parano1d is a live proof-native L1 where the present proves the past. Proofs
establish validity. PoW sets canonical order. Signatureless authorization,
execution and recursion share one transparent end-to-end post-quantum stack.

Proof-native contracts turn live value into **programmable live rights**.
Timelocked vaults, budgets, delegated spending and recurring payments share
the proof stack with token launches, bonding curves, a native DEX and an NFT
marketplace. Ownership, reserves and atomic transfers are enforced within
the recursive block proof.

Nodes verify State and rights from genesis without replay or trusted
checkpoints. Block bodies and transactions are pruned after retention.
Portable receipts remain verifiable. Mainnet is live.

[Website](https://parano1d.org) ·
[Documentation](https://docs.parano1d.org) ·
[Research](https://lab.parano1d.org) ·
[Releases](https://git.parano1d.org/ignotusnemo/parano1d/releases)

**Source:** [Forgejo](https://git.parano1d.org/ignotusnemo/parano1d) (canonical) ·
[GitHub](https://github.com/proof-native/parano1d) ·
[GitLab](https://gitlab.com/ignotusnemo/parano1d)

## From live value to live rights

Proof-native contracts extend that model to programmable rights. An ABI 3
contract output can commit
to a program, authorities, recipients, height conditions and persistent
counters. Spending it proves not only ownership of value but the right to take
a particular action: collect a payment, spend a budget, claim a due installment
or recover a remaining balance.

The authorized transition produces a new committed state or closes the right.
Its validity becomes part of the same block proof. Nodes do not need a growing
contract execution history to validate the present. Applications retain the
public terms and portable receipts they need to use and explain that present.

The shared integer core has 16 instructions, two persistent u64 counters, two
scratch registers, checked arithmetic, conditions and block-height access.
Users can create programs within this ABI without a new circuit or matrix per
application. It is a bounded core: scheduled actions require an authorized
call, and there are no loops or cross-contract calls.

The GUI, CLI and RPC expose six templates plus custom programs:

- refundable payments;
- timelocked vaults;
- delegated allowance wallets;
- budgets per height period;
- recurring payments;
- gradual release in fixed tranches.

This opens application space around prepaid services, delegated spending,
conditional access and staged payments while keeping consensus storage tied
to live rights. Each deposit is an independent instance. The
[concept](docs/concepts/proof-native-contracts.md),
[contract guide](docs/contracts/index.md), [API](docs/contracts/api.md) and
[GUI walkthrough](docs/contracts/gui.md) explain the mechanics and limits.

[Pruv](docs/contracts/pruv.md) compiles readable contract programs into the
existing native ABI. It checks types and resource limits, exports definitions
for the current CLI, and verifies declared postconditions with Z3.

## Native finance

Tokens, bonding curves, DEX pools and NFT listings are native proof-verified
contracts. Their ownership rules, reserves and atomic transfers are enforced
within the same recursive block proof.

- Launch a fixed-supply token from the wallet. The minimum is 100,000 tokens,
  each backed by 0.001 NOID. An optional creator purchase completes in the
  creation transaction.
- Buy and sell on the bonding curve, then trade the same asset on its permanent
  NOID DEX pool after automatic graduation. Holder backing stays separate from
  trading liquidity.
- Transfer tokens or burn them to redeem their share of backing. Each trade
  binds its minimum output, fee ceiling and expiry.
- Create individual NFTs or collections, mint batches and add items later.
  Transfer, burn, list, buy or remove an unsold listing from the NFT workspace.
- Use searchable token cards, collection grouping, MAX controls and filtered
  receipts. Optional images and price history use a bounded cache. External
  data starts Off.

Start with the [wallet guide](docs/wallet/index.md),
[tokens and trading](docs/wallet/tokens.md), [NFTs](docs/wallet/nfts.md),
[native rules](docs/protocol/native-finance.md).

## How a block is made

1. The wallet builds an atomic intent and proves knowledge of the required
   spending secret, bound to the complete logical transaction.
2. The mempool checks authorization, current spendability, limits and fees.
3. The miner proves the selected payments and contract calls, exact slot writes
   and recursive continuity with the parent.
4. Only then does an internal or external worker search the immutable
   Poseidon2b header's 128-bit nonce.
5. Peers verify the proof, PoW and chain rules, then apply the proven writes.

**Hashpower alone cannot originate a block.** A producer needs current State
and a completed proof. An external worker receives a single-use nonce template;
transaction selection and proving remain in the node.

## Verification without historical replay

Each `HistoryStep` proves the current block relation and verifies the previous
terminal inside the same relation. For a fixed network profile, proof size and
terminal verification work do not grow with chain height.

A joining node validates compact headers for cumulative work, authenticates a
finalized State with its matching proof, then verifies the recent block
suffix. Header validation scales with chain height; State transfer scales with
live outputs and rights. Historical transaction execution is covered by the
recursive proof.

An active node keeps the live State, permanent compact headers and a 42-block
body-serving window. The [synchronization guide](docs/architecture/synchronization.md)
describes the authenticated snapshot and recent-suffix paths.

## Network profile

| Parameter | Value |
| --- | --- |
| Mainnet genesis | 2026-08-21 16:00:00 UTC |
| Genesis block ID | `860e70453390bf815718e933aa4927167a13d098b0151391eefd722ee1add610` |
| Target block interval | 30 seconds |
| ASERT | 6-block reference epoch, 180-second half-life |
| Default Small | m23: 63 pages, 504 live inputs, 63 contract calls |
| Optional Large | m24: 206 pages, 504 live inputs, 63 contract calls |
| Automatic Native | m24: 63 pages, 504 live inputs, 63 contract calls, native finance |
| Hard finality / maximum reorg | 18 / 17 blocks |
| Local body retention | 42 blocks |
| State domain | 2^24 to 2^32 slots |
| Serialized terminal cap | 1,100,000 bytes |

Page, input and call limits apply together. Small fits 63 one-page payments or
63 calls; Large fits 206 one-page payments or 63 calls plus 143 payments,
within the input budget. A multi-page spend remains one logical transaction.
The primary coinbase is separate; an additional mandatory system page consumes
one effective page.

Large production is a server option, `--v2-large-blocks`, with no GUI switch.
The node considers Small and Native automatically. Large
adds an optional candidate for ordinary payments and ABI 3 calls. The node
selects the candidate with the greatest claimable fees and builds one proof.
Every node verifies all three classes. Ordinary one-page capacity ceilings at the target
interval are 2.1 and about 6.87 transactions/s; these are capacity calculations,
not measured sustained network throughput. See [parameters](docs/protocol/parameters.md)
and [measured proving and verification costs](docs/reference/performance.md).

## State and issuance

State is an exact sparse vector of indexed outputs. Spending clears a slot;
new outputs reuse empty positions with fresh `creation_id` values. Empty
2^16-slot segments need no materialized payload. Sustained finalized occupancy
can expand the domain without moving existing outputs.

Issuance follows an exact height schedule from H210537:
**16 → 11.30 → 8 → 5.65 → 4 → 2.83 → 2 → 1.41 → 1 NOID**,
one step every 1,051,200 blocks. The permanent 1 NOID tail means there is no
fixed maximum supply. State expansion does not change the reward.

Occupancy still increases the fee for net-new live slots. That growth component
is burned; consolidation frees slots and avoids growth fees. The
[network economics](docs/protocol/economics.md) explains the schedule, its
rationale and the distinction between gross subsidy and actual supply.

## Development allocation

Parano1d has no premine. For the original three 365-day target-time years from
genesis, the consensus subsidy allocation is:

- 90% to the miner;
- 5% to the O(1) Network Fund;
- 5% to Parano1d Lab.

The allocation ends at block 3,223,778. After that, 100% of new block subsidies
go to miners. Transaction fees remain entirely miner-claimable after the
state-growth burn. The [allocation schedule](docs/protocol/economics.md#existing-allocation-schedule)
details the daily payouts and accounting.

The O(1) Network Fund finances operation, maintenance, security and adoption
of the live network. Parano1d Lab supports the founders, core developers,
researchers and contributors advancing the protocol. Both will publish
periodic reports covering funds received, major expenditures, completed work
and current priorities.

## One proof stack

Committed traces use GF(2^128); C1 Fiat–Shamir challenges and recursive claims
use GF(2^256) with a trace-one support of size 2^255. Poseidon2b underlies
addresses, transactions, trees, transcripts and PoW. FROST-GKR batches its
permutations and Merkle paths; sumcheck, zerocheck, lincheck and FRI-Binius
close the relation without a trusted setup.

The [FROST-GKR research article](https://lab.parano1d.org/research/frost-gkr-global-trace-protocol/)
links the paper, reference implementation and reproducible comparison with
per-permutation reductions.

Ordinary ownership uses a freshly randomized proof of a 256-bit secret's
preimage, with no public-key transaction signature. Wallet authorization
contains no Live State Merkle path and is independent of the current State
root. The miner proves current input membership and exact State updates in
the block relation. Contract calls prove the active policy authority. The
libp2p Ed25519 identity identifies a peer only.
Public addresses, values and relayed transactions are observable. Third
parties can archive that relayed history.

The retained ancestry bank and matrix-retirement construction have
[source-linked soundness accounting](noid_soundness/docs/v2-retirement.md),
including legacy ancestry. Under the stated all-root composition, ideal
compiler, honest public preprocessing, fixed-Poseidon2b and resource-price
premises, the Category 1 assessment gives a dominant gate-depth floor with
log2 value **173.3897612554174** and an ideal success bound of about
**0.04937388373372754** at the Category 1 reference envelope. The premises and exact resource bounds are detailed in the
[security model](docs/protocol/security-model.md) and
[exact final-bank records](research/v2_feasibility/results/2026-09-25-common-input-budget/REPORT.md#accounting-for-the-final-banks).

Authenticated origin certificates bind the selected ancestry boundary under
independently pinned keys. Release builds embed the Small, Large and Native
matrices together with the retained ancestry bank and runtime metadata.
Synchronization selects the applicable relation from the block's consensus
schedule and carries its validity forward recursively.

## Network

The official wallet participates in the P2P mesh through its own node. DNS
seeds supply initial peer addresses. Kademlia, local mDNS and persisted peer
addresses support ongoing discovery. Once stable ordinary neighbours are
available, nodes replace their bootstrap seed connections.

libp2p GossipSub carries transaction intents and compact block announcements.
Nodes fetch State, block bodies and proofs from peers through bounded requests
and verify the data locally. See [networking](docs/architecture/networking.md)
for discovery, peer diversity and transport limits.

## Run a node or wallet

Official releases contain a Core archive and a native GUI wallet with its own
supervised node. The GUI supports Linux, Windows and macOS. See
[installation](docs/getting-started/wallet.md) and [Core](docs/getting-started/core.md).

```sh
parano1d --check-hardware
parano1d
```

For mining:

```sh
parano1d --miner
parano1d --miner --v2-large-blocks
```

External nonce search keeps proving in the node:

```sh
parano1d --extminer --mining-key-file ~/.parano1d/mining.key
parano1d-miner --key-file ~/.parano1d/mining.key
```

Use only the mining command appropriate to the host. Default ports are P2P
9600 and local JSON-RPC 127.0.0.1:9601. The built-in wallet key is not
password-encrypted; protect it and back up contract terms and receipts too.

```sh
parano1d-cli status
parano1d-cli balance
parano1d-cli contract protocol
parano1d-cli contract --help
```

Addresses use bech32m `o1…`; 1 NOID = 1,000,000 μNOID. F7 opens Contracts in
the GUI, and F8 opens Settings. See [RPC](docs/reference/rpc.md) for owner,
mining and operator access scopes.

### Keep your receipts

The wallet saves outgoing payment receipts locally while the confirmed block
data is available. Export a saved receipt for a payment to a different owner:

```sh
parano1d-cli receipt TXID > receipt.hex
parano1d-cli verify "$(tr -d '\n' < receipt.hex)"
```

For a retained contract-call receipt, use the saved contract terms and a
confirmed call ID. Replace `contract.json` and `CALL_TXID` with your file and
transaction ID; `--out` must name a new file:

```sh
parano1d-cli contract receipt contract.json CALL_TXID --out call.receipt
parano1d-cli contract verify call.receipt
```

Both receipt formats remain verifiable after the block body is pruned. Keep
public contract terms and receipts with your backups. A receipt establishes a
past payment or call; current spendability is checked against authenticated
State. See [payment receipts](docs/concepts/receipts.md) and
[contract receipts and recovery](docs/contracts/receipts-and-recovery.md).

## Build and verify

The workspace pins Rust 1.96.0. Native builds need a C/C++ toolchain, CMake,
libclang and platform packaging tools. Production x86-64 requires SSE4.1 and
PCLMULQDQ; ARM64 requires NEON and PMULL. Portable binaries select the available
PCLMUL, AVX2+VPCLMUL, AVX-512+VPCLMUL or NEON+PMULL backend at runtime.

A production build requires the authenticated three-class bank, reviewed pins
and ancestry verification material. The [build guide](docs/developers/build.md)
provides the material layout, authentication and packaging procedure. Contract
programs use this shared bank and do not generate new matrices.

```sh
./scripts/build_release.sh \
  --pack PATH_TO_LEGACY_PACK \
  --v2-pack PATH_TO_FROZEN_V2_PACK \
  --v2-pins PATH_TO_REVIEWED_PIN_FILE \
  --v21-pack PATH_TO_FROZEN_V21_PACK \
  --v21-pins PATH_TO_REVIEWED_V21_PIN_FILE \
  --retirement-keys PATH_TO_AUTHENTICATED_KEYS \
  --retired-history
```

Designed and developed by **Ignotus Nemo**. [Apache License 2.0](LICENSE).
Report security issues through the [security policy](.github/SECURITY.md).
Contact: [dev@parano1d.org](mailto:dev@parano1d.org).
