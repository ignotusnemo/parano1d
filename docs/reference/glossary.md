# Glossary

This glossary defines protocol-specific language used throughout the
documentation. A capitalized term such as `State` or `HistoryStep` names a
particular Parano1d object; ordinary lowercase use keeps its general meaning.

## Accepted block bundle

The wire object used for direct block admission: canonical block bytes and the
matching `HistoryStep` terminal. The two are verified and relayed together.
Authenticated catch-up may omit redundant intermediate terminal bytes after a
recursive terminal for the exact suffix tip has verified.

## Active address

The derived wallet address currently selected for sends, change and the
default internal-mining payout. Other derived addresses remain valid, but the
wallet does not mix their UTXOs into a spend from the active address.

## Address

An ordinary owner address encodes the Poseidon2b image of a derived 256-bit
secret. A contract address instead encodes the object commitment. Both use
canonical bech32m `o1…` encoding.

## ASERT

The absolutely scheduled exponentially weighted target algorithm used to
derive the exact proof-of-work target at every height. Parano1d uses a
six-block reference epoch, a 180-second half-life and a 30-second target
interval.

## Authorization capsule

The detached, freshly randomized zero-knowledge proof attached to one logical
transaction. For an ordinary spend it proves the owner secret; for a contract call it
proves the selected policy authority. It binds that authority to the complete logical transaction ID.

<a id="small-large"></a>

## Small / Large / Native

The three proof classes. Small m23 has 63 pages, Large m24 has 206 and Native
m24 has 63 with native finance. Each shares its 504-input and 63-call budgets
with ordinary payments. Small and Native are considered automatically. `--v2-large-blocks` additionally permits Large. The producer selects
one candidate by claimable fees and builds one proof. Every node verifies all three.

## Block–Tiwari FS-FRI security

The concrete classical random-oracle expected-work metric defined by Block and
Tiwari for non-interactive FRI. Provable and conjectured values use different
RBR premises even when their whole-bit presentations coincide.

## BaseFold

The binary-field folding schedule used by the FRI-Binius polynomial commitment
layer. It reduces committed codewords through a fixed sequence of folds before
the final low-dimensional check.

## Block body

The ordered transaction records carried beside a fixed block header. A block
contains at most 256 fixed bodies, including primary reward and any scheduled
development-payout record.

## Block header

The fixed 212-byte consensus record binding the parent, post-State root,
transaction root, time, height, miner, nonce, target and State counters.
Headers are retained permanently.

## Block ID

The nonce-bearing, domain-separated Poseidon2b hash of the complete canonical
header. It is used for parent links and canonical block identity.

## Block template

One immutable candidate block whose transactions, payout, State transition,
proof and all non-nonce header fields have already been fixed. Mining changes
only its nonce.

## Body retention

The 42-block local serving window for complete block transaction data. This is
separate from the 18-block authenticated suffix and finality boundary.
Headers are permanent.

## Canonical chain and canonical tip

The eligible chain selected by deterministic fork choice, and its newest
accepted block. Only proof-valid chains that preserve the hard-finalized
prefix are eligible.

## Commitment and opening

A cryptographic commitment binds a prover to data without placing all of that
data in the verifier's initial view. An opening reveals or proves a requested
value at a point while checking consistency with the commitment.

## C1 profile

The source identifier for the production wide-challenge proof profile. Its
algebraic challenges are sampled from a trace-one affine support of size
`2^255` in `GF(2^256)`. Its resource assessment is derived separately in the
[security model](../protocol/security-model.md).

## Completeness

The property that an honestly generated proof of a true statement is accepted
by an honest verifier.

## Consensus

The deterministic rules by which nodes validate blocks and select one
canonical chain. Local relay policy, peer identity and arrival order are not
consensus.

## Creation ID

A fresh identifier assigned when a UTXO is installed in a slot. It prevents a
stale reference from spending a later occupant of the same numerical slot.

## DNS seed

A DNS name returning initial public P2P endpoints. A seed helps a new node find
peers; it does not define chain state or grant consensus authority.

## Domain separation

The use of distinct typed tags when the same hash or permutation serves
different protocol roles. It prevents, for example, an address hash from being
interpreted as a block ID or Merkle node.

## Epoch anchor

The block ID at the current 144-block transaction boundary. Every page of a
`PagedSpend` carries it, and the mempool removes an intent when its anchor is no
longer current.

## Fiat-Shamir transcript

The ordered record of public statements, commitments and derived challenges
used to compile an interactive proof into a non-interactive one. Parano1d
derives transcript challenges with domain-separated Poseidon2b.

## Fork choice

The deterministic rule selecting the eligible chain with greatest cumulative
proof of work. Equal-work candidates use the lexicographically smaller block
ID as a tie-break.

## FRI / FRI-Binius

FRI is an interactive-oracle proof of proximity to a low-degree codeword.
FRI-Binius is Parano1d's binary-field polynomial commitment layer built from
that family and a BaseFold schedule.

## [FROST-GKR](../research/frost-gkr.md)

The committed-column protocol that expresses batched Poseidon2b and Merkle
relations over shared Boolean hypercubes and reduces them through multilinear
sumchecks.

## Full node

A node that independently validates consensus, stores the current State and
permanent headers, and can serve synchronization data. It need not construct
proofs or mine.

## GF(2^128)

The 128-bit binary extension field used by Poseidon2b and committed trace
arithmetic. Field addition is bitwise XOR; field multiplication follows the
pinned binary tower representation.

## GF(2^256)

The quadratic extension of Parano1d's `GF(2^128)` field used for production C1
Fiat–Shamir challenges, terminal claims and recursive region authentication.

## GKR

The Goldwasser–Kalai–Rothblum family of interactive proofs based on multilinear
extensions and sumcheck. FROST-GKR retains that machinery but replaces
classical layer-by-layer circuit descent with global committed-column
relations.

## GossipSub

The libp2p publish-subscribe protocol used to relay transaction intents and
block announcements. Local validation still decides whether received data
enters the mempool or canonical State.

## Grinding

A required prover search for a transcript nonce satisfying a fixed predicate
before query challenges are derived. The exact work and any security credit
must remain attached to the metric in which they are analysed.

## Hard finality

The consensus rule that excludes candidate chains replacing the prefix deeper
than the most recent 18-block suffix. The maximum accepted reorganization is
17 blocks.

## History-stateless

Validation does not require historical transaction replay. A node still stores
and transfers permanent headers and the current Live State.

## HistoryStep

The recursive block relation proving current transition validity, the exact
post-State and continuity with the preceding terminal.

## Interactive oracle proof (IOP)

An interactive proof in which the prover supplies oracle-like committed
objects and the verifier checks a bounded set of derived locations. Sumcheck
and FRI-style proximity checks are analysed at this level before non-
interactive compilation.

## Kademlia

The distributed hash-table discovery mechanism used by libp2p to find ordinary
peers after initial bootstrap.

## Knowledge error

The probability bound associated with extracting a valid witness from a prover
that convinces the verifier. It is a stronger and more specific claim than
plain soundness and must be reported with its exact proof model.

## Lincheck

A protocol check that a claimed relation among committed multilinear objects
is linear and holds at the sampled point.

## Live State

The currently installed State required to validate and prove the next
transition: live UTXO records, segment commitments and consensus counters. It
is current State, not historical transaction replay.

## Logical transaction

One atomic `PagedSpend`, possibly made of several physical pages, with one ID
and one wallet authorization.

## Manifest

The bounded snapshot index binding a finalized height, State counters and the
identifiers, roots and lengths of every transferred State segment.

## Master secret

The wallet's 256-bit root secret. Indexed owner secrets and addresses are
derived from it; possession of it is sufficient to reconstruct spending
authority, but not locally stored receipts.

## Materialization

Writing already-proven canonical slot changes into a full node's exact local
State. It is distinct from deriving or proving the transition.

## Mempool

A node's bounded local set of validated, not-yet-mined transaction intents.
Admission and relay floors are local policy; block validity remains consensus.

## Merkle tree, root and path

A hash tree commits many indexed leaves to one root. An authentication path is
the sibling sequence needed to reconstruct that root for a selected leaf.

## Miner / proving node

A full node that selects a candidate transition, constructs its `HistoryStep`
and then searches for a valid nonce itself or through an external worker.

## Multilinear extension (MLE)

The unique multilinear polynomial agreeing with a table on the Boolean
hypercube. Sumcheck and GKR-style protocols use MLEs to reduce table-wide
relations to evaluations at sampled points.

## μNOID

The atomic currency unit. One NOID is 1,000,000 μNOID.

## Network identity

The public network identity fixed by genesis data, consensus parameters, the
proof-bank identity and the P2P protocol ID. It is distinct from an individual
node's peer identity and from a Git commit or build host.

## Network group

A coarse grouping of related IP address ranges used only for connection
diversity and resource limits. It has no role in consensus or wallet identity.

## NIST Post-Quantum Cryptography Category 1

The NIST resource target referenced to exhaustive key search against AES-128,
including the published `MAXDEPTH` limits. Parano1d evaluates this target for
the end-to-end from-genesis invalid-State game.

## Nonce

The 128-bit header field varied during proof-of-work search. A winning nonce
makes the Poseidon2b PoW digest numerically smaller than the exact target.

## PagedSpend

One to 128 ordered `Tx8x2` pages joined into one atomic wallet intent.

## Peer

Another node connected through the P2P protocol. Peers supply and relay data;
proof verification and fork choice determine whether that data is accepted.

## Peer identity

A persistent libp2p Ed25519 key used to authenticate network sessions and name
a peer. It has no spending or consensus authority.

## Polynomial commitment scheme (PCS)

A commitment system for polynomial or multilinear data that supports verified
openings without sending the complete committed object to the verifier.

## Poseidon2b

The width-four algebraic permutation over `GF(2^128)` used for addresses,
transactions, Merkle nodes, State commitments, transcripts, block identifiers
and proof of work. Typed domain separation keeps those roles distinct.

## Proof of work (PoW)

The nonce-search mechanism that assigns cumulative work and orders proof-valid
State transitions. PoW chooses among valid candidates; it cannot make an
invalid proof or transition valid.

## Proof-native

An architecture in which proofs of authorization and State transition are
consensus inputs. Verifiers check those proofs instead of re-executing the
complete computation that produced them.

## Prover, verifier and witness

The prover produces a proof from a statement and a witness; the verifier checks
the proof from public data. A witness is the private or expensive information
needed to establish the statement, such as a wallet secret or transition
trace.

## Rank-1 constraint system (R1CS)

An arithmetic representation of computation as multiplication constraints
between linear combinations. Parano1d uses a binary R1CS relation closed by
sumcheck, zerocheck, lincheck and FRI-Binius.

## Receipt

A self-contained transaction statement and eight-level Merkle path proving
inclusion under a claimed canonical header transaction root.

## Reorganization (reorg)

Replacement of recent canonical blocks by a different eligible branch with
greater cumulative work. Parano1d accepts at most a 17-block rollback.

## Round-by-round knowledge bound (RBR)

A bound obtained by accounting for the knowledge error contributed by each
verifier move of an interactive proof. It is not the same metric as a
Toy-Problem FRI score.

## Semantic header ID

The nonce-free header projection bound inside `HistoryStep`. It commits to
every other consensus-significant header field.

## Slot

One indexed position in the exact sparse UTXO vector.

## Snapshot

A segmented transport of Live State at a finalized boundary. Its manifest,
segment roots, canonical header and terminal are verified before installation.

## Soundness

The property that a verifier accepts a false statement only within the stated
error bound. A numerical soundness claim is meaningful only with its proof
model, assumptions and composition scope.

## State

The exact canonical UTXO object: its sparse indexed vector and the consensus
counters committed by the current block header. Capitalized `State` refers to
this protocol object, not to a user-interface or process status.

## State domain

The active slot index range `[0, 2^log_slots)`. It begins at `2^24` slots and
may expand up to `2^32` under the finalized occupancy rule.

## State expansion

The deterministic doubling of the active State domain after the required
hard-finalized occupancy window. Existing records and slot indices do not
move.

## State-growth burn

The fee component paid for a net increase in live UTXO slots. It scales with
occupancy, is removed from circulation and cannot be claimed by the miner.

## State segment

A fixed subtree containing `2^16` consecutive State slots. Empty segments are
virtual; snapshot transport and local storage materialize only non-empty ones.

## Proof-native Layer 1

An L1 network architecture in which proofs are mandatory consensus objects.
Every accepted block proves its exact State transition and verifies the
preceding `HistoryStep` terminal; proof of work orders only valid transitions.

## Sumcheck

An interactive reduction proving a claimed sum of a multivariate polynomial
over a Boolean hypercube by reducing it one variable at a time to a final
evaluation.

## System record

A consensus-derived transaction body used for the primary reward or scheduled
development payout. It has no wallet authorization and cannot be chosen or
omitted by a miner.

## Terminal

The fixed-shape recursive proof output for the current `HistoryStep`.

## Toy Problem metric

The conjectured FRI rate/query scoring convention published by Plonky2 and
used for like-for-like industry comparison. It is reported under its original
label and is not interchangeable with an RBR or end-to-end security claim.

## Trusted setup

A ceremony that creates secret public parameters whose compromise could
invalidate security. Parano1d's transparent proof stack requires no such
ceremony.

## Tx8x2

The fixed physical transaction body with eight possible inputs and two
possible outputs.

## Undo data

Bounded local records of the previous form of recently changed slots, segment
roots and counters. They support shallow reorganization but are not a
consensus witness.

## UTXO

An unspent transaction output: a Live State record containing an amount,
owner and fresh `creation_id` at one indexed slot.

## Zero-knowledge proof

A proof that establishes a statement without revealing the secret witness.
In Parano1d it hides wallet spending secrets; public owners, amounts, fees
and relayed transactions remain transparent.

## Zerocheck

A reduction proving that a constraint polynomial vanishes over its required
Boolean domain.

## Proof-native contract

A live output committing to a bounded integer program, authorization policy
and two counters. A call proves the permitted successor or closing inside
`HistoryStep`. See [contracts](../contracts/index.md).

## Contract opening

The 699-byte public encoding of a contract's immutable terms and current
counters. It reconstructs the State owner commitment; wallets retain and share it.

## Contract receipt

Portable evidence of a contract call, including original and optional successor
terms, inclusion and recursive proof evidence. It remains verifiable after body
pruning. Current spendability is checked separately in State.

## Contract instance

One funded `(slot_index, creation_id)` under a specific opening. Separate
deposits have independent balances and counters even when their terms match.
