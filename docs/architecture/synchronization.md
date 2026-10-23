# Synchronization

Synchronization has two paths. A node close to the tip verifies a retained
block-body suffix and one recursive terminal at its tip. A node farther behind
first authenticates a finalized snapshot and then verifies the same form of
recent suffix. Neither path trusts a peer's claim about State.

![Authenticated snapshot synchronization](../assets/architecture/snapshot-sync.svg)

## Short gaps

Every full node retains the latest 42 canonical block bodies. If a joining
node is no more than 18 blocks behind, it authenticates the linked headers,
downloads the corresponding bodies and obtains one `HistoryStep` terminal for
the suffix tip. The terminal is verified before any suffix body is committed.
Its recursion covers the exact ancestry from the node's installed boundary to
that tip, so intermediate terminal bytes need not be transferred again.

The bodies are then processed in order. For each body the node checks:

- equality with the authenticated header, parent and height continuity;
- exact difficulty and timestamp rules;
- Poseidon2b proof of work;
- transaction and State commitments;
- the exact post-State root during materialization;
- fork-choice and hard-finality constraints.

Direct admission of a newly announced block still uses its ordinary atomic
`{block, HistoryStep terminal}` bundle. Compact suffix synchronization changes
only redundant proof transport, not the validity relation.

## Snapshot path

A gap of 19 blocks or more uses the snapshot protocol:

1. download and validate permanent headers;
2. choose the finalized snapshot boundary;
3. obtain the matching `HistoryStep` terminal;
4. download the State manifest;
5. download and verify the referenced State segments;
6. reconstruct the exact global State root;
7. install the staged State transactionally;
8. obtain and verify one terminal for the retained suffix tip, then apply its
   linked block bodies.

The manifest binds the boundary height, `state_root`, `log_slots`,
`active_slot_count`, `alloc_counter`, and the exact segment identifiers, roots
and lengths. Segment payloads are checked against those commitments.

The peer is only a data source. A forged, incomplete or boundary-shifted
snapshot fails before installation.

## Header chain

Headers are permanent and compact. The joining node validates them from its
known chain origin to the candidate tip, including parent links, height,
timestamps, exact ASERT targets and proof of work. It accumulates work and
applies the same deterministic fork-choice rule as an already-running node.

This phase is linear in header count. The recursive terminal then verifies
validity at the chosen boundary in constant proof-verification work.

The full cost profile is:

| Phase | Scales with |
|---|---|
| Header validation | Chain height |
| Boundary terminal verification | Constant |
| State transfer and installation | Live State |
| Recent suffix | At most 18 block bodies plus one tip terminal |

Parano1d removes historical execution replay; it does not pretend that proof
of work can be compared without reading headers or that current State can be
downloaded without transferring it.

## Transactional staging

Snapshot data is written to a scratch environment. The canonical database is
not changed while segments are arriving. Only a complete snapshot whose root,
counters, boundary header and terminal agree can replace the active State.

If the process exits during synchronization, the stale staging area is removed
at startup and synchronization begins from the last installed canonical State.
There is no partially installed snapshot to repair.

## Incremental service

An online node can continue serving its installed State while a newer snapshot
is staged. Network telemetry separates header validation, terminal checking,
State transfer and suffix application so operators can see whether progress is
CPU-, disk- or peer-bound.

Initial synchronization completes after the exact selected tip has been
verified and committed. Readiness does not depend on a redundant probe of
that same tip. New announcements continue through normal online processing.
Disconnected snapshot candidates are retired while verified exact-object
progress remains reusable through another source.

The 42-block local serving window is operational headroom, not a larger
authenticated suffix or a different snapshot boundary.

## Reorganizations

The finalized boundary is not reorganizable. Fork choice considers only
candidate chains that preserve it, and the accepted rollback depth must be
less than 18. The maximum canonical reorganization is therefore 17 blocks.

Recent undo data and block bodies cover this suffix. A deeper competing
history is rejected rather than reconstructed through a snapshot.

For the exact fork rule, see [Consensus](../protocol/consensus.md). Network
message boundaries are described in [Networking](networking.md).

## Authenticated origins

Header validation selects rules by authenticated height. The snapshot and
recent suffix bind the origin of the selected chain. The node checks origin
certificates under independently pinned preprocessing keys and uses the
applicable authenticated matrices. The retained bank and three-class financial
bank accompany the origin evidence. See [build inputs](../developers/build.md)
and [security model](../protocol/security-model.md).
