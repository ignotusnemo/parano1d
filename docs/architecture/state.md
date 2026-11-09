# Live State architecture

The canonical State is an exact sparse vector of UTXOs indexed by 32-bit slot
number. A header commits to both its Merkle root and the counters required to
interpret the vector:

- `state_root`;
- `log_slots`, the current slot-domain exponent;
- `active_slot_count`;
- `alloc_counter`, the next creation identifier.

State begins with `2^24` possible slots and can expand one level at a time
to `2^32`.

![Finalized-window State expansion](../assets/architecture/live-state-expansion.svg)

## Slot lifecycle

An occupied slot records an amount, an owner and a `creation_id`. Spending
clears the slot to the canonical empty value. Allocation prefers empty
positions, so a later output can reuse the same numerical index.

The creation identifier makes reuse safe. An input must match both
`slot_index` and `creation_id`; a reference to an earlier occupant cannot spend
the replacement.

```text
slot 9700063, creation 417  ── spend ──>  empty
empty slot 9700063          ─ allocate ─> slot 9700063, creation 894
```

The allocator counter is monotonic and committed in every header.

## Segmented storage

The vector is divided into segments of `2^16` slots. A segment is materialized
only when it contains a live UTXO. Empty segments are virtual, and clearing the
last live slot removes the segment from physical storage.

This gives the node two useful views:

- exact raw segment columns in MDBX for wallet queries and transition
  materialization;
- a compact tree of segment roots for State authentication.

At the initial `2^24` domain, only 256 segment roots are needed. Together with
their upper tree nodes, the compact exact-root cache is under roughly 17 KiB.
Raw segment data can be hydrated or evicted independently while the committed
root remains exact.

## Proving a transition

The miner gathers only the segments touched by the selected block. The public
block relation proves:

- each input record matches the current slot;
- each output target is empty;
- no slot is used inconsistently;
- values and fees balance;
- every resulting segment root is correct;
- untouched branches carry through unchanged;
- the reconstructed global root equals the header's `state_root`.

The accepted block exposes canonical writes. Other full nodes verify the
`HistoryStep` and apply those writes; they do not derive them by executing the
transactions again.

## Expansion

Expansion is based on an 18-header hard-finalized occupancy window. For a child
of parent height `H`, the window ends at `H - 18`. It is therefore unaffected
by the reorganizable suffix.

When at least 10 of the 18 finalized headers report occupancy at or above 75%,
the child increases `log_slots` by one. A 9/9 split does not expand.

The existing tree becomes the left child of a new root. An empty tree of equal
depth becomes the right child:

```text
new root
├── previous exact State root
└── canonical empty subtree
```

No UTXO moves, no segment is copied and slot numbers remain valid. Root update
work is independent of the number of occupied slots.

The [issuance schedule](../protocol/economics.md) advances by block height.
Expansion preserves existing values and slot indices. Occupancy-sensitive
State-growth fees continue to price net-new live outputs.

## State pressure and fees

Ordinary input and output work has a fixed fee component. Net-new live slots
also pay a State-growth component whose multiplier rises with occupancy.

| Occupancy | Growth multiplier |
|---:|---:|
| Below 50% | 1× |
| 50% to below 75% | 2× |
| 75% to below 90% | 4× |
| 90% and above | 8× |

The growth component is burned. The remainder of the fee is claimable by the
miner. A transaction that reduces or preserves the number of live slots pays
no growth burn.

This prices the scarce resource directly: persistent State, not historical
bytes that active consensus no longer needs.

## Restart and reorganization

MDBX stores State changes transactionally. For recent blocks, bounded undo
records contain the exact preimages and counters needed to roll State backward.
The node retains 36 blocks of undo data while consensus permits a maximum
18-block canonical reorganization.

Restart does not reconstruct State from genesis. The node opens the persisted
State, checks its canonical metadata and resumes from the current terminal.

See [State transition](../protocol/state.md) for normative rules and
[Synchronization](synchronization.md) for authenticated State transfer.

## Contract commitments

An output owner may be a contract commitment. Its live amount and incarnation
use the same State layout; public terms and counters are opened during the
call. Participants retain those terms and [receipts](../contracts/receipts-and-recovery.md).
