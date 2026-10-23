# State transition

The consensus State is a sparse Merkle vector of UTXO records. Its active
domain contains `2^log_slots` leaves, where `log_slots` ranges from 24 to 32.
The header commits to the root, live count and allocation counter after every
block.

## Leaf states

A leaf is either canonical empty or contains:

```text
{amount: u64, creation_id: u64, owner: 32 bytes}
```

The commitment packs amount and creation identifier into one `GF(2^128)` lane
and hashes it with the owner under the UTXO-leaf domain.

## Transition order

Consensus derives one ordered transition from the block:

1. validate and allocate the primary reward;
2. validate and allocate the scheduled development payout when due;
3. process user groups in block order, including native groups;
4. clear every consumed input;
5. assign fresh creation identifiers and install outputs;
6. update segment roots, live count and allocation counter;
7. reconstruct the global State root.

Logical transaction atomicity is preserved even though its physical pages are
consecutive block records.

## Input rules

Ordinary input authority is its owner; a contract input instead proves the
active authority in its committed policy. The same proof verifies the program,
branch permissions, counters and exact successor or closing. Contract calls
precede ordinary user groups and obey the shared class budgets.

Every live user input must:

- be inside the parent State domain;
- identify a currently occupied slot;
- match the declared amount and owner commitment;
- match the current `creation_id`;
- appear only once in the block;
- be authorized by the group's wallet proof.

Reward and development records have no inputs and are validated through their
system schedule.

## Output rules

Every live user output must:

- be inside the child State domain;
- target an empty slot after accounting for earlier block actions;
- have a non-zero value for an ordinary NOID output;
- appear only once in the block.

The allocator chooses a fresh monotonic `creation_id`. Output slot hints are
only construction aids; a block remains responsible for proving that the slots
are empty against its exact parent.

## Value conservation

Within each logical user group:

```text
sum(inputs) = sum(outputs) + fee
```

Across the block, created value is limited to the protocol subsidy. The primary
reward ceiling includes the miner share plus claimable transaction fees. The
burned State-growth fee is omitted from that ceiling.

All aggregate monetary arithmetic uses a width that cannot silently saturate a
sum of valid `u64` fields.

## Segments

Leaves are grouped into `2^16`-slot segments. A block may touch no more than
256 distinct segments. This is a consensus availability bound checked before
the node hydrates segment data.

Empty segments use the canonical empty subtree root and need no raw MDBX
column. A segment whose last live UTXO is spent is removed.

## Expansion rule

For a candidate child of parent height `H`, use the 18 hard-finalized headers
ending at height `H - 18`. The first complete window is available for parent
height 35 and covers heights 0 through 17.

Count headers satisfying:

```text
active_slot_count × 4 >= 2^log_slots × 3
```

If at least 10 of 18 satisfy it and `log_slots < 32`, the child must set
`log_slots = parent.log_slots + 1`. Otherwise it must retain the parent value.

Expansion installs the previous root as the left child of a new root and the
canonical empty subtree as the right child. Existing slot indices and records
do not move.

## Reorganization data

Recent undo records preserve the previous form of every touched slot, segment
root and counter. They are retained for 36 blocks, while consensus permits at
most a 17-block rollback.

An undo is local recovery data, not an alternate consensus witness. The
replacement branch still needs valid headers, work and terminals.

## Native State objects

Native slots retain the same leaf format. The `amount` lane records NOID.
The `owner` lane commits to the typed opening. Token quantities, NFT identity,
creator rights and market terms are fields of that opening. A token or NFT
carrier can therefore have zero NOID while remaining a live occupied slot.
Reserves, curve cash, pool NOID and listing credit carry their exact NOID value.

Native conservation checks NOID, each token asset and each NFT identity
separately. Holder backing remains separate from trading reserves. The
recursive relation checks the complete typed transition and exact State writes.
Live openings and required definitions accompany authenticated snapshot
segments. See [native finance](native-finance.md) and [wire formats](native-wire.md).
