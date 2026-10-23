# Native objects and wire formats

This page describes the sequential native-finance profile. The integer
economic rules are in [Native finance](native-finance.md). Integrations can
use the [wallet RPC](../reference/native-rpc.md) to construct and review
operations against their own node's current State.

## Typed live objects

Each native opening has a kind, an immutable canonical byte encoding and a
domain-separated Poseidon2b commitment. That commitment is the State output's
owner/root field. The live slot also authenticates its amount and creation
incarnation. A dependency is accepted only when its committed root matches
the opening's required definition.

The sequential profile uses these live kinds:

| Kind | ID | 128-bit fields | Encoded bytes |
|---|---:|---:|---:|
| Fungible definition | 1 | 8 | 140 |
| Token balance | 2 | 6 | 108 |
| Token reserve | 3 | 6 | 108 |
| NFT collection | 4 | 8 | 140 |
| NFT item | 5 | 8 | 140 |
| Market definition | 32 | 8 | 140 |
| Market pool | 33 | 8 | 140 |
| Launch definition | 48 | 8 | 140 |
| Launch state | 49 | 8 | 140 |
| NFT listing definition | 64 | 8 | 140 |
| NFT listing | 65 | 8 | 140 |

An opening starts with eight bytes `NOIDAS21`, a little-endian `u16` wire
version of `1`, then a little-endian `u16` kind. Each following field is a
little-endian `u128`. The exact field count follows the kind; truncated,
oversized or trailing data rejects. The general decoder's opening bound is
204 bytes, including its 12-byte header. The selected sequential profile
accepts the kinds in the table above.

`noid_tx/src/native_assets.rs` defines the field order, numeric bounds,
commitment tags and canonical encoder. The individual launch, market and NFT
modules define the terms committed by their corresponding openings.

## Identity and incarnations

Asset and collection IDs are 32-byte identities. Creation binds the chain,
creator, exact funding slot and its creation ID together with the definition.
NFT identity additionally binds its collection and serial. An allocation's
amount and root must match the exact input incarnation before it is consumed.

Native creation IDs carry bit 62 and a sequence below `2^62`. Ordinary and
coinbase provenance use their respective dispatch rules. The native sequence
is checked when decoding a live State claim; a numeric slot alone cannot
identify the right being spent.

The fungible definition fixes issuance and metadata. Token balances commit
to asset, owner and base-unit quantity. The separate reserve commits to NOID
backing and outstanding supply. Curve/pool objects hold trading state.
Collection state keeps its maximum and issued serial count. Listing state
binds the item to its immutable seller, ask and expiry definition.

## Owner-authorized operations

The active native operation codes are:

| Code | Operation |
|---:|---|
| 2 | Transfer fungible tokens |
| 3 | Burn tokens and redeem backing |
| 5 | Create a collection |
| 6 | Mint an NFT |
| 7 | Transfer an NFT |
| 8 | Burn an NFT |
| 48 | Create a fixed-supply launch |
| 64 | Create an NFT listing |
| 65 | Purchase an NFT listing |
| 66 | Cancel an NFT listing |
| 80 | Execute the selected sequential trades |

Operation codes and opening-kind IDs are separate namespaces. The selected
block profile checks both. Native transitions bind all input/output slots,
amounts, creation IDs, typed openings, required definitions, authority and
fees. The relation checks the resulting State effects and authorization.

## Intent framing

A native spend uses `NOIDNT21` followed by little-endian wire version `1`,
`u16` page count and `u32` authorization byte count: a 16-byte prefix.
Canonical transaction page bodies follow. Each live input and output then
has a `u16` opening length and its opening bytes; zero length denotes an
ordinary NOID claim. Financial operations carry the bounded dependency list
specified by the header. The Owner capsule is the final byte region.

The encoder fixes the authorization offset before appending the capsule.
The parser checks framing, page/start/end markers, masks, counts, dependency
ordering and exact consumption of the message. Structural limits and the
admitting block's selected resource class both apply.

A funded trade policy uses `NOIDTO21`, little-endian version `1`, two zero
reserved bytes, a `u32` intent length and a `u32` authorization length. Its
20-byte prefix is followed by the canonical trade intent and Owner capsule.
The intent fixes the asset, exact principal funding incarnation, recipient,
input cap, minimum outcome, fee cap, epoch and validity interval.

The canonical encoders are in `noid_tx/src/native_assets/wire.rs` and
`noid_tx/src/native_assets/trade/wire.rs`. Use these encoders so the reviewed
intent and the authorization statement refer to identical bytes.

## Block data, snapshots and pruning

The block binds the actual selected funded policies, their deterministic
sequence, all intermediate transitions and final payouts. Policy receipts
identify each user's executed trade inside that committed group. The live
market update is ready for the next block.

State synchronization carries the live native openings and their required
definition closure. The `NSG1` native segment framing augments the sparse
State segment. Its decoder checks lengths before allocation, exact slot/root
and amount/incarnation correspondence, unique records and required
dependencies. Segment commitments bind the authenticated State view used
for installation.

Old bodies and their transaction data expire after retention. Live native
payloads remain available with current State; canonical headers support
saved receipt checks. Wallet descriptions and image files are distributed
separately using their [committed media hashes](../wallet/asset-media.md).
