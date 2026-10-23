# Proof stack

Parano1d uses one binary arithmetic stack for ownership, State transitions,
Merkle relations, recursive continuity and proof of work commitments. The
committed trace field is the binary tower field `GF(2^128)`. The production
wide-challenge layer uses its quadratic extension `GF(2^256)`.

![Parano1d proof stack](../assets/architecture/proof-stack.svg)

## Poseidon2b

Poseidon2b is the common permutation:

| Parameter | Value |
|---|---:|
| State width | 4 field elements |
| S-box | `x^7` |
| Full rounds | 8 |
| Partial rounds | 58 |

Typed domain tags separate addresses, physical pages, logical transactions,
Merkle nodes, State commitments, block identifiers, PoW digests and proof
transcripts. Sharing a permutation does not mean sharing a hash domain.

## [FROST-GKR](../research/frost-gkr.md)

The protocol expresses batched Poseidon2b executions and Merkle paths as direct
degree-seven relations over shared Boolean hypercubes. It is the committed-
column reduction used by Parano1d, not a layer-by-layer replay of a circuit.

The reduction keeps the multilinear-extension and sumcheck machinery of GKR
while replacing recursive circuit-layer descent with global relations over
the execution trace. Shared columns let many permutations and paths be checked
without paying for an independent constraint sumcheck for every instance.

## Closing the relation

The downstream pipeline combines:

- batched sumcheck;
- zerocheck;
- lincheck;
- FRI-Binius/BaseFold over the binary field;
- one joint `GF(2^256)` transcript for the three Link and six Block recursive
  regions.

The transparent proof system uses an authenticated joint Small/Large/Native bank.
Its pins bind the interpreter, resource budgets and activation schedule.
Contract programs execute in this shared relation. Authenticated origin certificates carry the retained ancestry through the
same recursive relation. Verification uses independently pinned preprocessing keys.

## Wallet authorization

The wallet proves knowledge of the 256-bit preimage behind `input_owner`,
bound to the logical transaction ID. The proof is freshly randomized and
witness-hiding. It contains no State path.

The authorization wire format is bounded to 256 KiB. Its canonical decoder
checks framing and exact byte consumption before verification.

Contract inputs use the same secret-knowledge proof for the authority selected
by their committed policy; the State owner is the object commitment.

## HistoryStep

The block prover establishes the complete public transition and verifies the
previous terminal inside the new relation. The next terminal therefore binds:

```text
previous validity
        +
current block relation
        +
exact post-State
```

Proof size and terminal verification do not grow with chain height. Permanent
headers remain outside recursion for proof-of-work accumulation and fork
choice.

## Security accounting

C1 uses 65 wallet queries and 133 History queries. The ancestry calculation includes
old ancestry and both matrix-retirement reductions. Its exact inventory,
composition premises and Category 1 resource bounds are in the
[security model](../protocol/security-model.md). Contract programs add
deterministic constraints inside the shared relation.
