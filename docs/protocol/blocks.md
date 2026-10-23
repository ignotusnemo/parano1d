# Blocks and headers

Direct block admission uses an atomic pair:

```text
{canonical block bytes, matching HistoryStep terminal}
```

The block contains a fixed header and up to 256 fixed transaction bodies.
The terminal proves the nonce-independent semantic header and complete State
transition.

## Block contents

Position zero is the primary reward. An additional mandatory system record,
when due, follows it. Contract calls form the prefix of user pages, followed
by ordinary atomic `PagedSpend` groups.

| Limit | Small / Large / Native |
| --- | ---: |
| Effective pages, excluding primary coinbase | 63 / 206 / 63 |
| User pages when an extra system record is due | 62 / 205 / 62 |
| Live user inputs | 504 / 504 / 504 |
| Contract calls | up to 63, within the available page budget |
| Distinct State segments | 256 |

The physical decoder retains its universal 256-body / 82,905-byte bound.
Active class budgets are checked in addition to that format bound before
acceptance. An ordinary logical spend can use multiple pages.

## Transaction root

The universal 256-leaf transaction tree commits to **logical transaction IDs**.
Each system record and each user group contributes one leaf; a multi-page
`PagedSpend` contributes one leaf for its complete logical ID. Unused positions
have a canonical empty value. The root also binds the exact logical count.

Receipts use an eight-level path at the logical transaction position. Their
transaction data reconstructs the complete group ID, including page count and
order. Physical page positions and logical leaf positions are distinct.

## Canonical header

The header has a fixed 212-byte little-endian encoding:

| Field | Size | Meaning |
|---|---:|---|
| `prev_block_hash` | 32 | Nonce-bearing parent block ID |
| `state_root` | 32 | Exact post-State UTXO root |
| `tx_root` | 32 | Count-bound transaction root |
| `timestamp` | 8 | Unix time in seconds |
| `height` | 8 | Child height |
| `miner_address` | 32 | Primary reward recipient |
| `nonce` | 16 | Poseidon2b PoW nonce |
| `difficulty_target` | 32 | Exact little-endian ASERT target |
| `log_slots` | 4 | Slot-domain exponent |
| `active_slot_count` | 8 | Post-State live UTXO count |
| `alloc_counter` | 8 | Post-State allocation counter |

Field order is consensus-locked. Future formats cannot reorder existing fields.

## Two header identifiers

The nonce-bearing block ID hashes every field under the `BLOCKHDR` domain. It
is used for parent links, transaction epoch anchors and canonical block
identity.

The semantic header ID hashes the same fields in the same order but skips the
nonce and uses the `SEMHDR__` domain. `HistoryStep` binds this projection so a
miner can vary the nonce without rebuilding the transition proof.

An accepting node requires the terminal and the native nonce-bearing header to
refer to one identical set of non-nonce fields.

## Primary reward

There is exactly one live primary reward output. Its `creation_id` uses a
disjoint height-tagged namespace:

```text
2^63 | block_height
```

Ordinary output allocation remains below `2^63`, so a reward record can never
collide with a user allocation identifier.

The primary reward may claim only the current miner subsidy and miner-claimable
fees. It cannot reclaim the burned State-growth component.

## Terminal representation

The terminal uses a canonical shared-path encoding. Merkle authentication
nodes shared by several openings are transmitted and stored once. Decoding
reconstructs the complete paths consumed by the recursive verifier; the
mathematical proof, query count and authenticated matrices are unchanged.

Consensus limits the serialized terminal to 1,100,000 bytes, counting the
compressed representation and its terminal metadata. Expansion is independently
bounded to 1,100,000 bytes. The block bytes have a separate 82,905-byte maximum;
block bodies and bundle framing do not consume the terminal limit. Malformed
or non-canonical encodings are rejected before expensive verification.

## Accepted bundle

The terminal includes metadata binding its version, height, semantic-header
hash and proof class. Bundle decoding checks lengths before allocating and
rejects trailing bytes, mismatched metadata or a terminal for another header.

Canonical block bodies are retained for 42 blocks. A directly admitted block
stores its complete bundle. During authenticated catch-up, one verified
terminal at the suffix tip authorizes the exact linked intermediate bodies;
the tip stores the complete bundle, while intermediate rows keep compact local
authorization for that verified suffix. Headers are permanent.

See [Proof of work](proof-of-work.md) for nonce validation and
[Receipts](../concepts/receipts.md) for durable transaction inclusion.

## Native body payload

During native execution, Native blocks include canonical typed openings and the
selected trade policies alongside the fixed page stream. The complete body
payload has a 713,689-byte ceiling. The fixed page stream retains its
82,905-byte decoder bound. Proof bytes have their separate 1,100,000-byte cap.

Native allocation identifiers carry bit 62 with a sequence below `2^62`.
The same State root binds NOID value and each typed object commitment.
The transaction root commits to native logical groups, including the selected
trade group policy commitment. Receipts identify individual executed policies
inside that group. See [native wire formats](native-wire.md).
