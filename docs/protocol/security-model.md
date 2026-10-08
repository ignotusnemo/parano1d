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

## Final v2 accounting

The pinned mainnet bank is
`c2a6df736b0d0da22e285b6930b11cf44b520d65b52c7dfe78f44fe0cd48e76e`.
The source-linked calculation inventories wallet, old ancestry, v2 History and
two matrix-retirement reductions. It covers 20 typed failure events and does
not discard old error terms when old matrix bytes are removed.

| Quantity | Final-bank result |
| --- | ---: |
| Resource assessment | NIST PQC Category 1, conditional |
| log2 dominant half-success gate-depth floor | 173.3897612554174 |
| Ideal success bound at Category 1 reference envelope | approximately 0.04937388373372754 |

These are distinct resource/probability quantities, not interchangeable
“security bits”. The limiting event is a query event in the old-ancestry
retirement reduction. Its internal legacy class name does not designate an
active v2 mining class. Historical classical FS-FRI and ideal-QROM tables are
kept in the [archive](../archive/legacy-profiles.md).

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
identify assumptions, inputs and rational bounds. The default legacy soundness
calculator is not a substitute for the v2 tool. Performance and malformed-proof
tests complement this analysis; they do not prove its correspondence premises.

The [October 2026 correspondence work](../../noid_soundness/docs/v2-correspondence-2026-10.md) independently reconstructs both complete release retirement keys and gives source-linked arguments for complete request closure, the selected recursive parent and exact carried lanes, the conditional v2 all-root specialization and authenticated snapshot installation. It separates those deterministic obligations from fixed-hash instantiation and universal response-price assumptions. The numerical assessment above is unchanged, and the source-level scope is distinct from a proof-assistant verification of the whole implementation.

## Fork and matrix boundary

The first v2 proof binds to the selected last pre-v2 block. The authenticated
origin is specific to that boundary and chain, not a trusted checkpoint.
Reorganization must update the selected origin and roll back orphaned contract
outputs and receipts. The existing finality limit remains in force.

A transition release carries both historical verification material and the new
bank. A later retired-history build verifies the origin certificate using
independently pinned preprocessing keys and can omit old matrix bytes. It
still needs the two v2 matrices, authenticated metadata and origin evidence.
Omitting files without the corresponding verifier path is not retirement.

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
