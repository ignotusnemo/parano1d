# Security model

Parano1d combines proof of work, recursive validity, exact Live State and
signatureless wallet authorization. Each mechanism has a distinct job.

## What consensus establishes

An accepted canonical tip establishes that:

- its headers form the greatest-work eligible chain known to the node;
- every accepted block preserves the hard-finalized prefix;
- every wallet-authorized input belongs to a prover who knew the owner's
  256-bit secret;
- every input existed and every output target was empty in the exact parent
  State;
- values, fees, issuance and allocation followed consensus;
- the committed post-State is the exact result;
- recursive validity reaches the current terminal.

Proof of work orders valid transitions. It does not repair invalid proofs.
Recursive proofs establish validity. They do not replace fork choice.

## Production soundness

The production profile has two distinct security statements. Block–Tiwari
measures the classical random-oracle Fiat–Shamir compilation of FRI. The
end-to-end theorem measures acceptance of an invalid recursive State by a
quantum adversary.

| Security statement | Current production result |
|---|---:|
| Target FRI security | **128 bits** |
| Provable Block–Tiwari FS-FRI security | **127 bits** |
| Conjectured Block–Tiwari FS-FRI security | **127 bits** |
| Sequential ideal-QROM half-success boundary | **64.707407428576 bits** |
| NIST Post-Quantum Cryptography Category | **Category 1** |
| Dominant Category 1 gate-depth floor | **173.391078499301 bits** |
| Margin over the NIST `2^170` reference | **3.391078499301 bits** |
| Complete ideal bound at the Category 1 envelope | **0.049330348213215253** |

### Wallet analysis refinement

The W65 wallet uses a tighter Johnson-range analysis at radius `4/5`, with at
most 17 candidates at each Reed–Solomon layer. The resulting local bound is
`max(5^-65, 701202001931 / 2^255)`. The query term has a local exponent of
`150.925326167679` bits, not an end-to-end post-quantum security level.

This is an analysis-only improvement. Query counts, matrices, proof formats
and consensus are unchanged. The dominant resource term is now limited by
`history.query`. The classical FS-FRI result, sequential ideal-QROM boundary
and Category 1 classification remain unchanged. The
[wallet Johnson derivation](https://github.com/ignotusnemo/parano1d/blob/main/noid_soundness/docs/wallet-johnson.md)
gives the finite list bound, correlated-agreement argument and field-exception
ledger using existing theorems valid in characteristic two.

### Block–Tiwari FS-FRI

[Block and Tiwari](https://eprint.iacr.org/2024/1161) define concrete FS-FRI
security as

```text
log2(minimum expected classical random-oracle query work),
```

where the minimum ranges over every positive integer query budget. Applying
their definitions, 256-bit random-oracle setting and whole-bit presentation to
the production B25 and B255 profiles gives exact expected-work values in
`[127, 128)` for both the provable and conjectured RBR premises. Their equality
after integer presentation does not identify those premises.

The [Block–Tiwari derivation](https://github.com/ignotusnemo/parano1d/blob/main/noid_soundness/docs/block-tiwari.md) proves
the local RBR inputs for every production layer, solves both integer
optimizations and reproduces the comparison with the systems in their
published table.

### End-to-end Category 1

The security game asks whether one stateful quantum adversary can make the
production verifier accept an invalid terminal State whose recursive ancestry
starts at genesis. One resource budget covers wallet authorization, the block
relation, parent links, the exact State transition, recursive verification and
every adversarial ancestor on which the terminal depends.

`C1` is the source identifier for the production wide-challenge profile. It
uses 65 wallet queries, 133 History queries, a 256-bit transcript digest and
algebraic challenges sampled uniformly from a trace-one affine set of
cardinality `2^255` in `GF(2^256)`. Committed trace arithmetic and Poseidon2b
remain over `GF(2^128)`.

The depth-aware theorem evaluates all NIST Post-Quantum Cryptography Category 1
`MAXDEPTH` points against the AES-128 gate-depth reference `2^170`. The base-two
logarithm of its dominant half-success gate-depth floor is
`173.391078499301` bits, and its complete ideal success bound at the Category 1
envelope is at most `0.049330348213215253`.

The fixed Poseidon2b production corollary requires
`Delta_P2b^C1 < 0.450669651786784747`. It also assumes the minimum coherent
response cost stated by the resource theorem. Under these premises, the theorem
gives provable end-to-end post-quantum soundness for state validation from
genesis at NIST PQC Category 1: every adversary inside the Category 1 resource
envelope has success probability below one half in the from-genesis
invalid-State game.

The [end-to-end QROM derivation](https://github.com/ignotusnemo/parano1d/blob/main/noid_soundness/docs/category-one.md)
states the game, reductions, finite terms and assumptions. The
[`noid_soundness` certificate](https://github.com/ignotusnemo/parano1d/tree/main/noid_soundness) imports the
production constants and evaluates every normative inequality with exact
integer or rational arithmetic. This is a cryptographic Category 1 resource
assessment, not a claim of NIST review or certification.

## Trust boundaries

The protocol does not require:

- a trusted proving setup;
- a trusted snapshot publisher;
- historical transaction-body archives for validation;
- a public-key transaction signature scheme;
- permission from seed nodes or peers.

The released binary embeds authenticated proof matrices. Snapshot State is
checked against canonical headers and the matching terminal before
installation.

## Wallet boundary

The 256-bit master secret grants spending authority. Compromise of the device,
secret file or original photo-derived material compromises the wallet.
Consensus cannot distinguish the owner from an attacker who knows the same
secret.

Receipts are local records, not derived secrets. Losing them does not lose
funds, but can remove durable payment evidence after old block bodies are
pruned.

## Network boundary

Peer Ed25519 keys authenticate libp2p sessions only. They do not participate in
wallet or block authorization. DNS seeds help locate peers but cannot define
the canonical chain.

Connection diversity, message limits, staged synchronization and mempool
budgets bound common resource attacks. Operators should still keep RPC on
loopback, protect wallet files and use independent network paths for public
infrastructure.

## Transparency

Parano1d is not an anonymity system. Transaction owners, amounts, slots and
fees are transparent while bodies are available. Zero knowledge hides the
wallet secret and proves execution; it does not conceal the public ledger
statement.

## Finality assumption

Consensus refuses a reorganization that changes the prefix deeper than the
18-block finality boundary. Operators and applications may choose to wait for
additional confirmations inside the recent suffix, but no peer can present a
deeper branch as eligible under the same rules.

For operational protection, see
[Backup and recovery](../wallet/backup-recovery.md) and
[Configuration](../operate/configuration.md). Consensus checks are collected
in [Consensus invariants](invariants.md).
