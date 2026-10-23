# A proof-native Layer 1

A conventional full node establishes the current state by replaying the chain.
The chain contains the historical inputs, and the node repeats every state
transition in order. Pruning can reduce disk use after validation, but it does
not remove the original dependency: the present is accepted because the node
reconstructed it from the past.

Parano1d changes what a block means. A block is not merely a collection of
operations that every peer must execute. It arrives with a recursive
`HistoryStep` proving that:

- the public block relation was satisfied;
- the resulting UTXO root is the exact post-State;
- the previous `HistoryStep` terminal was valid.

The terminal has a fixed shape. Verifying block 10,000 or block
10,000,000 does not require a proof whose size grows with height.

## Where execution goes

The work has not disappeared. It has moved to the participant that already has
the necessary witness.

The wallet knows the spending secret, so it proves authorization. The miner
has the Live State and the selected block contents, so it proves the State
transition. Peers verify both results. They do not reconstruct the wallet
witness or repeat the miner's public computation.

This division is deliberate:

| Participant | Private or expensive knowledge | Output |
|---|---|---|
| Wallet | 256-bit owner secret | Randomized authorization bound to one logical spend |
| Miner | Selected intents and exact Live State | Recursive proof of the complete block transition |
| Full node | No proving witness | Verification result and canonical slot writes |

The miner cannot manufacture wallet authority, and a valid wallet proof cannot
authorize a transition against nonexistent or already spent inputs. Both
proofs are required.

## What a full node stores

A current full node keeps:

- the exact Live State;
- permanent compact headers;
- the current `HistoryStep` terminal;
- the latest 42 canonical block bodies;
- bounded undo data for shallow reorganization.

Older transaction bodies are not part of the active validation requirement.
They can be discarded after their retention window. Headers remain because
proof of work and fork choice still need a permanent cumulative-work history.

This makes Parano1d **history-stateless**, not state-free. Joining still
requires the live UTXO set. The amount of State transfer follows current
usage, while validation no longer grows with the total number of transactions
the network has ever processed.

## Applying a proven block

After verification, a node materializes canonical slot writes into MDBX. It
does not re-run logical transaction execution to discover those writes. Each
input clears one exact `{slot_index, creation_id}` record; each output installs
one newly allocated record. The committed post-State root binds the result.

The distinction matters:

- **execution** derives and proves the transition;
- **verification** checks the proof;
- **materialization** writes the already-proven result to local storage.

Keeping those operations separate is what lets an ordinary node remain a full
consensus participant without becoming a prover.

## Joining without replay

For a gap of at most 18 blocks, a node downloads the retained block bodies and
one recursive terminal for the exact suffix tip. It verifies that terminal
before checking and materializing the linked bodies in order. For a deeper
gap, it downloads permanent headers, an authenticated snapshot at a finalized
boundary, the matching boundary terminal and the same compact recent suffix.

The snapshot is staged, its segment roots reconstruct the committed State root,
and its boundary is checked against the canonical header and recursive
terminal. Only then is it installed. The terminal at the recent suffix tip is
verified before any of its bodies are applied.

Snapshot transport does not introduce a trusted checkpoint. Peers supply data;
consensus proofs and proof of work decide whether that data is acceptable.

## What proof of work still does

Recursive validity does not choose a chain. Parano1d uses proof of work for
ordering and Sybil-resistant fork choice. A miner proves the nonce-independent
block first, then searches the 128-bit nonce of the fixed header.

Hash power can choose between valid competing transitions. It cannot turn an
invalid authorization, State root or recursive terminal into a valid block.

Continue with [System architecture](../architecture/overview.md) for the
component flow, or [Synchronization](../architecture/synchronization.md) for
the joining protocol.

## Live rights

Contracts apply this model: a live commitment binds spending policy
and counters, and its transition is proved inside the shared block relation.
Nodes retain the live result; participants retain public terms and receipts.
Read [From live value to live rights](proof-native-contracts.md).
