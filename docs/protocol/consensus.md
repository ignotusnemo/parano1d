# Consensus

Parano1d accepts only blocks that satisfy the native header rules, the
recursive `HistoryStep` relation and proof of work. Chain selection compares
cumulative work among valid candidates while preserving the hard-finalized
prefix.

The source code is the canonical consensus definition. This specification
describes the stable rule set and its boundaries.

## Candidate validity

For a child block to extend a parent, all of the following must hold:

1. `prev_block_hash` equals the parent's nonce-bearing block ID.
2. `height` is exactly `parent.height + 1`.
3. the timestamp is greater than the median of the preceding 11 headers and no
   more than 120 seconds ahead of local wall clock;
4. `difficulty_target` is the exact ASERT target derived from canonical
   history and is not easier than the protocol floor;
5. the Poseidon2b PoW digest is strictly less than the little-endian target;
6. the physical block encoding and all transaction groups are canonical;
7. the mandatory primary reward and any scheduled development payout are
   exact;
8. transaction-epoch anchors are current;
9. no input or output conflict exists inside the block;
10. fees, value conservation, allocation counters and slot writes are exact;
11. `log_slots` follows the finalized expansion rule;
12. the post-State counters and root equal the header commitments;
13. the supplied `HistoryStep` terminal verifies and binds the nonce-free
    semantic header.

Direct candidate admission accepts the block and matching terminal as one
bundle. Authenticated catch-up may first verify the terminal of an exact
descendant suffix tip and then import the linked bodies covered by that
recursion. Every body still satisfies the native rules above. No candidate is
accepted from block bytes and proof of work alone.

## Fork choice

Every valid header contributes work derived from its target. The canonical
chain is the candidate with the greatest cumulative work.

If two candidates have equal cumulative work, the chain with the
lexicographically smaller tip block hash wins. The tie-break is deterministic;
arrival order and peer identity have no role.

## Hard finality

The most recent 18-block window is the only reorganizable part of the chain.
A candidate that would change the finalized prefix is ineligible for fork
choice. Because rollback depth must be strictly less than 18, the maximum
accepted reorganization is 17 blocks.

Hard finality also separates State-expansion measurements from temporary
forks. The 18-header occupancy window used for expansion ends at the finalized
boundary, not at the tip.

This is a protocol rule, not a social checkpoint. All nodes derive the same
boundary from height and reject deeper alternatives.

## Difficulty

The target interval between accepted blocks is 30 seconds. Proof preparation,
nonce search and propagation share that interval. ASERT adjusts the target
using six-block reference epochs and a 180-second half-life. The target is
encoded as a 256-bit little-endian integer.

From v2 activation at height 210,537, validation derives the one exact target
from the canonical anchor and the parent header. Blocks with the same parent
have equal targets regardless of their own timestamps. Miners do not choose
among a range of acceptable difficulties.

## Transaction clock

User transactions bind to a block ID at the start of a 144-block transaction
epoch. The boundary block still accepts the preceding anchor; the new anchor
becomes active for the next child.

For child height `C > 0`, the anchor height is:

```text
floor((C - 1) / 144) × 144
```

This clock is independent of the six-block ASERT epoch. It limits replay and
stale mempool lifetime without tying wallet authorization to every new State
root.

## Local policy is not consensus

Nodes may choose which admissible transactions to relay or mine. The default
mempool uses minimum and dynamic fee policy, conflict reservations and bounded
resources. Those choices cannot make a transaction invalid once it appears in
a valid block, except where the same minimum fee formula is explicitly checked
by consensus.

Likewise, mining requires one authenticated peer in the official node. That
is an operational isolation guard, not a block-validity vote.

## Genesis and network identity

The public network has one compiled chain origin, network magic and protocol
identifier. A node does not negotiate consensus parameters with peers. Data
from another network fails parent, identity or proof checks before it can
become canonical State.

Continue with [Blocks and headers](blocks.md),
[Transaction protocol](transactions.md), [State transition](state.md), and the
[consensus invariant map](invariants.md).

## Height-selected rules

Mainnet v2 applies from H210537. Candidate height selects the proof bank,
resource budgets, 30-second timing and height-based subsidy together. The first
new proof binds to the selected predecessor; reorgs across that boundary must
replace the origin and undo orphaned contract transitions. ASERT sums ideal
intervals under each height's rules. Epoch, finality and retention counts stay
144, 18, 42 and 36 blocks respectively. Contract branches use inclusion height.

See [parameters](parameters.md), [economics](economics.md) and
[the authenticated fork boundary](security-model.md#fork-and-matrix-boundary).
