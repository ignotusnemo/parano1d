# Consensus invariants

These invariants describe what every accepted canonical tip means. They are a
review map for implementations and protocol changes, not a second source of
consensus constants. The executable rules remain authoritative.

## Chain continuity

Every non-origin header names the nonce-bearing block ID of its exact parent
and increments height by one. Its timestamp, target and proof of work satisfy
the deterministic rules derived from canonical history.

Fork choice compares accumulated work only among valid candidates that preserve
the hard-finalized prefix. Equal-work tips use the smaller block hash as the
deterministic tie-break.

## Proof-authorized validity

Direct block admission uses one accepted bundle containing the block and its
matching `HistoryStep` terminal. Authenticated catch-up may instead verify one
terminal at an exact descendant suffix tip before importing the linked bodies
covered by its recursion. Every body still passes the same native header, PoW,
transaction-epoch anchor, transaction and exact State-root checks.

No canonical block is admitted from body bytes and proof of work alone. It is
authorized either by its matching terminal or by a verified descendant
terminal whose exact recursive suffix includes it.

The terminal binds the nonce-free semantic header, including transaction and
post-State commitments. The nonce-bearing header is then checked separately
for proof of work and parent linkage.

## Canonical transaction grouping

Each physical `Tx8x2` body occupies one fixed 323-byte page. A logical
`PagedSpend` is one contiguous, canonically ordered group of 1 to 128 pages.
Group metadata, padding and commitment fields must agree across every page.

The logical transaction ID commits the entire ordered group. Page reordering,
insertion, removal or mutation changes the intent.

## Spending authority

Ordinary input authority is its owner; a contract input instead proves the
active authority in its committed policy. The same proof verifies the program,
branch permissions, counters and exact successor or closing. Contract calls
precede ordinary user groups and obey the shared class budgets.

Every ordinary user input is covered by a valid authorization capsule bound to the
logical transaction ID and input owner. Verification establishes knowledge of
the owner's 256-bit secret without placing that secret in the transaction.

Network peer keys, wallet labels and local address-discovery state have no
spending authority.

## Exact State transition

For every accepted logical transaction:

- each input slot is occupied in the parent State;
- its owner, value and `creation_id` match the referenced record;
- each input is consumed at most once;
- every output target is empty before allocation;
- no output target is allocated twice;
- value is conserved after the exact fee;
- resulting counters, segment roots and global root are exact.

Untouched State branches carry through unchanged. Nodes apply the canonical
writes exposed by the proven transition; they do not invent an alternative
execution result.

## Slot reuse safety

A numerical slot can be reused after it becomes empty. The monotonically
increasing `creation_id` distinguishes successive occupants. A reference to an
older occupant cannot spend a later replacement at the same slot index.

## Issuance and system records

The first body is the exact primary reward required for the block. On a
scheduled development boundary, the next body is the exact mandatory payout.
No user transaction can replace, omit or modify a required system record.

All other value enters and leaves user transactions through explicit inputs,
outputs and fees. The State-growth fee component is burned; it is not silently
redirected to a miner or fund.

## Recursive continuity

Each `HistoryStep` verifies the previous validity terminal and the complete
current public transition. A valid tip therefore carries recursive continuity
from the chain origin through its exact post-State.

Proof of work cannot make an invalid terminal acceptable. A valid terminal
cannot replace proof of work or cumulative-work fork choice.

## Hard-finalized decisions

Rollback depth is strictly less than 18 blocks. A candidate that changes the
deeper finalized prefix is ineligible.

State expansion reads only an 18-header window that is already hard-finalized.
At least 10 observations at or above 75% occupancy are required; a 9/9 split
does not expand. Temporary tip forks therefore cannot toggle capacity.

## Authenticated synchronization

A snapshot peer is only a source of bytes. Before installation, the joining
node checks that all of the following agree:

- validated permanent header at the finalized boundary;
- matching recursive terminal;
- manifest height, State root and counters;
- every segment identifier, length and root;
- the reconstructed exact global State root.

Candidate data is staged separately and becomes canonical in one transaction.
An interrupted or invalid transfer cannot leave a partially installed State.

The post-boundary suffix is admitted only after the terminal for its exact tip
has verified. Its linked bodies are then checked and materialized in order;
intermediate terminal transfer is unnecessary because validity is already
carried by the verified recursion.

## Policy boundary

Relay selection, dynamic fee floor, peer scoring, mining thread count and
ordinary transaction selection are local policy. They may determine what a node keeps or
mines, but cannot alter the validity of a block that satisfies consensus.

Changes to any invariant require the boundary tests described in
[Testing](../developers/testing.md). Constants and formulas are collected in
[Consensus parameters](parameters.md).

## Native financial invariants

A launch fixes token supply and deposits holder backing atomically. The
reserve remains separate from curve and pool liquidity. Burning pays the
holder's proportional backing and preserves backing per remaining unit.
Graduation preserves asset identity and creates permanently locked DEX liquidity.

Selected trades follow the sequence derived by consensus from parent State
and their committed policies. Each fill respects its owner, funding, minimum
output, fee ceiling and height bounds. An unfilled policy leaves inputs unspent.
Miners choose inclusion within these rules.

Minting consumes the creator's exact current collection and advances its serial
counter. A sale consumes one exact listing and delivers its NFT and payment
atomically. Competing purchases cannot deliver the same item twice.

The enclosing proof binds these rules, each State write and recursive ancestry.
The activation height selects the relation. See [native finance](native-finance.md).
