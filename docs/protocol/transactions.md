# Transaction protocol

An ordinary user transaction is one canonical logical `PagedSpend`. It consists
of one to 128 fixed `Tx8x2` pages and exactly one detached authorization capsule.

## Physical page

Each page has the fixed 323-byte body encoding:

| Field | Meaning |
|---|---|
| `epoch_anchor` | Current 144-block replay-protection anchor |
| `fee` | Logical fee on the first page; zero on continuations |
| `input_owner` | Owner shared by every live input |
| `inputs[8]` | Possible `{slot_index, amount, creation_id}` records |
| `outputs[2]` | Possible `{slot_index, amount, owner}` records |
| `validity_bitmap` | Live records and logical start/end markers |
| `is_coinbase` | False for every user page |

Bits 0–7 select inputs, 8–9 outputs, and 10–11 logical start/end.
Contract calls additionally use bit 12 (contract) and bit 13 (closing).
Ordinary payments leave these two bits zero; bits 14–15 are always zero.

A record whose live bit is zero must be the all-zero canonical dummy. This
removes alternate encodings of the same statement.

## Group validity

A valid `PagedSpend` satisfies all of these rules:

- page count is between one and 128;
- only page zero has the start marker;
- only the final page has the end marker;
- every page has the same `input_owner` and `epoch_anchor`;
- only the first page carries a non-zero fee;
- live inputs and outputs are packed densely in page order;
- the page count is minimal for those records;
- at least one input is live;
- no input appears twice;
- no output slot appears twice;
- an output slot is not also an input slot in the same spend;
- there are at most 504 inputs and 256 outputs, within the class page budget;
- total input value equals total output value plus the fee;
- the detached authorization is no larger than 256 KiB.

The maximum canonical intent encoding is 303,495 bytes.

Small permits 63 pages and Large 206 per block, with a shared 504-input
budget. A logical ordinary spend still has at most 128 pages and must fit in
one block. Wallet planning and both mempool admission checks enforce the
candidate height's limits. Format-only historical bounds are in the archive.

## Logical transaction ID

Page-local body hashes do not independently name the payment. The logical ID
is a domain-separated Poseidon2b sponge over:

```text
version || page_count || ordered_page_hashes
```

The launch version is `1`. Reordering, adding or removing a page changes the
ID. The authorization capsule proves knowledge of the preimage behind
`input_owner` for that exact logical ID.

## State checks

For each input, the current slot must be occupied by the declared owner,
amount and `creation_id`. For each output, the target slot must be empty and
inside the active slot domain.

Output `creation_id` values are not transaction fields. Consensus assigns them
from the post-State allocation sequence. A user cannot choose or reuse one.

The block transition enforces all State checks atomically for the complete
logical group.

## Fees

The minimum fee is:

```text
5,000
+ 100 × live_inputs
+ 700 × live_outputs
+ growth_price × max(0, live_outputs - live_inputs)
```

All amounts are in μNOID. `growth_price` begins at 2,500 μNOID per net-new
slot and is multiplied by 1, 2, 4 or 8 according to parent-State occupancy.

The State-growth component is burned. Any fee above the required minimum is a
miner-claimable tip. State-preserving and State-shrinking spends have no growth
burn.

## Epoch anchor

Every page uses the current transaction-epoch anchor. For child height `C`,
the anchor is the block ID at:

```text
floor((C - 1) / 144) × 144
```

for `C > 0`. Height 144 still consumes the height-zero anchor; height 145
begins using height 144. The mempool removes intents whose anchor is no longer
current.

## Authorization and State are separate

Wallet authorization proves ownership only. It does not prove current slot
membership and contains no Live State Merkle path.

The block `HistoryStep` proves current membership, emptiness, balance,
allocation and the post-State root. Both statements bind the same public
logical transaction.

## Contract calls

A call carries a 699-byte public opening and one canonical contract page.
It spends one exact `(slot_index, creation_id)` and checks the committed
program, selected authority and value policy. A continuing call creates an
updated commitment in output 0 and an optional payment in output 1. Closing
pays the branch recipient through output 0 and creates no successor.

All three classes support the same ABI and at most 63 calls. Calls share page and
input budgets with ordinary spends, forming the canonical user-page prefix.
The authorization proves the selected authority's secret; State ownership is
the opening's object commitment. See [contract core](../contracts/core.md)
and [lifecycle](../contracts/lifecycle.md) for the complete branch rules.

## System records

Primary reward and scheduled development payout records use the fixed physical
body type but are not user `PagedSpend` intents. Their shape, placement,
recipients and amounts are derived entirely from block context. They carry no
wallet authorization.

See [Transaction architecture](../architecture/transactions.md) for wallet and
mempool flow.

## Native intents

Native token, launchpad, DEX and NFT intents use typed openings and their
exact State incarnations. They are authorized and executed atomically inside
the Native block relation. Ordinary payments and ABI 3 calls can share that
block within its page and action budgets. See [Native finance](native-finance.md),
[native wire formats](native-wire.md) and [native RPC](../reference/native-rpc.md).
