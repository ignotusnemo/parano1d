# Security model

Proof of work orders valid transitions. Recursive proofs establish validity;
they do not replace cumulative-work fork choice or the 18-block hard-finality
boundary. State transfer is checked against authenticated roots, not trusted
because a seed supplied it.

## What is proved

An accepted terminal covers exact input incarnations, empty output targets,
value conservation, fees, issuance, contract policy and integer-program
transitions, the post-State root and recursive ancestry. Ordinary inputs require
the owner's secret; a contract input requires the active authority selected by
its committed policy and inclusion height. Possession of an authority secret
does not bypass its program, branch permissions or amount limits.

The wallet proves secret knowledge bound to the logical transaction. The miner
proves the public relation and parent link. Peers verify and materialize the
result. A valid nonce cannot repair an invalid proof.

## Recursive ancestry accounting

The retained ancestry bank covered by this source-linked calculation is
`c2a6df736b0d0da22e285b6930b11cf44b520d65b52c7dfe78f44fe0cd48e76e`.
The source-linked ancestry calculation inventories wallet, ancestry, History and
two matrix-retirement reductions. It covers 20 typed failure events and does
not discard old error terms when old matrix bytes are removed.

| Quantity | Final-bank result |
| --- | ---: |
| Resource assessment | NIST PQC Category 1, conditional |
| log2 dominant half-success gate-depth floor | 173.3897612554174 |
| Ideal success bound at Category 1 reference envelope | approximately 0.04937388373372754 |

The table reports a resource floor and a success bound under the same
reference envelope. The dominant term is a query event in the ancestry
retirement reduction.

The assessment retains the **all-root composition, ideal compiler,
fixed-Poseidon2b delta, batch response-price and scalar gate-charge premises**.
It additionally requires **honest public preprocessing** of both old keys from
the authenticated canonical matrices. Attaching a matrix digest to arbitrary
commitment roots is insufficient. This is a mathematical resource assessment
under the explicit premises above.

The C1 profile uses 65 wallet queries and 133 History queries, with algebraic
challenges from a trace-one support of size 2^255 in GF(2^256). Trace arithmetic
is GF(2^128). Contract execution adds deterministic constraints, not a separate
Fiat–Shamir protocol per application. The shared ABI does not imply that every
custom policy is a correct implementation of its author's intent.

The [derivation and reproduction command](https://git.parano1d.org/ignotusnemo/parano1d/src/branch/v2/noid_soundness/docs/v2-retirement.md) and
[final-bank exact records](https://git.parano1d.org/ignotusnemo/parano1d/src/branch/v2/research/v2_feasibility/results/2026-09-25-common-input-budget/REPORT.md#accounting-for-the-final-banks)
identify assumptions, inputs and rational bounds. Source correspondence is
assessed alongside the fixed-hash instantiation and response-price premises.


## Cryptographic conditions

Each authorization attempt uses independent operating-system entropy and
consumes its private PCS state. Owner statements bind the exact intent.
The source-linked [cryptographic review](https://noid.network/security/october-2026)
describes the fixed-hash and proof-system assumptions.

## Authenticated ancestry

An origin proof binds the exact selected chain boundary. The verifier checks
its certificate under independently pinned preprocessing keys and preserves
that binding recursively. Reorganization updates the selected origin and
rolls back displaced outputs and receipts within the finality rule.

The node carries the retained verification bank, the three-class financial
bank, authenticated runtime metadata and origin evidence. Height selects the
applicable relation. Matrix bytes are retired through a verified certificate
under the corresponding pinned keys. See [build inputs](../developers/build.md).

## Wallet, evidence and network boundaries

Protect the 256-bit master secret. Anyone who learns it acquires the same
spending authority, subject to the same contract policy. Consensus cannot
distinguish the owner from an attacker holding the secret.

Contract terms and receipts are separate public data. The secret cannot
reconstruct a lost program or missed successor from a commitment hash. Ordinary
payment receipts preserve payment evidence; contract openings may also be
necessary to spend. See [contract recovery](../contracts/receipts-and-recovery.md).

Transactions, amounts, owners and public programs are transparent while
available. Third parties may archive them. Zero knowledge hides the spending
witness, not the public ledger statement.

Peer Ed25519 identities authenticate transport only. DNS seeds locate peers
but do not authorize transactions or define the chain. Connection diversity,
bounded messages and staged sync constrain resource use. Keep owner RPC local,
protect wallet data and use independent peers for infrastructure.
