# October 2026 v2 correspondence and composition

The v2.0.3 source obligations are separated here from the cryptographic assumptions of the certificate. The results below establish concrete release preprocessing, complete retirement request binding, selected recursive-parent binding and authenticated snapshot installation. They also give the deterministic v2 extension of the all-root worklist. None changes consensus parameters or the numerical soundness calculation.

Production and the integrated certificate are pinned to `50d6dac5a37b9f1be425b5e6cd823de48f843b50`. Reproduction code and regression tests are in audit commit `9c8136e4482cbba2a6fd5f469ac668c789ea1e01`. The arguments are source-level proofs in the stated model, supported by executable checks. They are not proof-assistant certificates or an assertion that every production function has been formally verified. The corresponding passive research submissions require semantic review before changing the accepted noid.network ledger.

## Results and remaining conditions

| Obligation | Result and scope |
| --- | --- |
| Honest release preprocessing | All seven static columns of each legacy class were reconstructed from the complete authenticated canonical matrix. Both 304-byte release keys matched exactly. |
| Retirement request and origin | Every live class, complete point/value, request context and dynamic root is preserved through the production origin verifier. |
| Recursive transcript and selected parent | The framed transcript has a unique operation encoding. Native and trace channels follow the same state machine. The authenticated boolean selector enables exactly one parent arm and carries the other matrix lane unchanged. |
| Authenticated State installation | The audited snapshot route verifies the exact terminal and origin, reauthenticates segment bytes and commits matching headers, proof and State in one MDBX transaction. |
| V2 ancestry worklist | Under the local extraction and typed-compiler hypotheses of the existing theorem, the extended graph terminates at genesis and retains all legacy obligations. The proof is below. |
| Fixed Poseidon2b instantiation | The event-specific fixed-hash deviation remains a cryptographic assumption. Transcript equivalence does not prove it. |
| Universal coherent response prices | The scalar charge and amortized batch prices remain resource assumptions. A constructed circuit gives an upper bound, not the required universal lower bound. |

The conditional mainnet v2 figures remain `173.3897612554174` for the descriptive dominant gate-depth floor and approximately `0.04937388373372754` for the ideal Category 1 envelope. The work adds correspondence evidence; it does not increase a bound or demonstrate an attack.

## Model and authority

The adversary controls peer proof bytes, contract data, public transaction data and candidate ancestors. The executable fork schedule, release bank, authenticated matrix artifacts, independent key pins and safe Rust verifier implementation are trusted. In-process capability forgery, a modified executable and storage hardware that violates its transaction guarantees are outside this source argument.

Equality of encodings and evaluated algebraic expressions is deterministic. When a digest is used as authority, the implication from equal digests to equal named objects is conditional on the certificate's binding game. When a probabilistic reduction is used, its local bad-response event remains in the accounting. These conditions are not replaced by regression tests.

## Canonical preprocessing lemma

Let the canonical legacy matrix have width `W = 2^k`. Enumerate all nonzero entries of A, then all nonzero entries of B with row addresses offset by W. Pad the list with zero coefficients to length `N = 2^n`. For entry i, set its immutable write tag to `N + i`, its previous row/column tag to the latest earlier write at that address or zero, and each final tag to the last write at that address or zero.

Since `0 <= i < N`, every write tag is distinct, nonzero and different from the initial tag zero. For each address, the previous-tag edges form a finite chain in increasing entry order, from its initial record to its final record. Padding participates in those chains; its coefficient zero prevents it from changing the matrix evaluation. The seven static columns therefore determine the actual canonical matrix coefficients and both complete access chains.

This is the construction implemented by [public preprocessing](../../noid_ivc_core/src/matrix_claim/sparse_c1/preprocess.rs). The independent audit derives its own entry traversal, columns and tags without calling the production table constructor or tag helpers, then uses the release PCS commitment function. It shares the canonical artifact decoder and PCS implementation; it is not an independent implementation of either primitive.

| Legacy class | Actual entries | Padded entries | Static roots compared |
| --- | ---: | ---: | ---: |
| 0 | 28,461,463 | 33,554,432 | 7 of 7 |
| 1 | 124,071,078 | 134,217,728 | 7 of 7 |

All 152,532,541 entries were covered. Matrix shape, structural digest, geometry and all seven roots matched every byte of both 304-byte keys. Their independent protocol pins are:

```text
class 0  0651ce507810b61213cbdc0e9f99436aec3a7922cc662bfba6128b466453c8b2
class 1  c301274d50dc02fd5c383f2e71629075729a954a768f5051388ec2040bce0267
```

Consequently honest preprocessing is checked for these concrete release instances, conditional on the canonical decoder and commitment binding. Attaching the correct matrix digest to arbitrary roots would not establish this lemma.

## Sparse evaluation lemma

Fix the honestly preprocessed static columns and one candidate tuple for the four dynamic columns. For a row or column address a, let `e(a)` be the public equality-table value at that address, and let `v(i)` be the committed lookup value of entry i. The read-only memory records are:

```text
initial(a) = (a, e(a), 0)
read(i)    = (address(i), v(i), previous_tag(i))
write(i)   = (address(i), v(i), N + i)
audit(a)   = (a, e(a), final_tag(a))
```

Suppose the multisets `initial + write` and `read + audit` are equal as tuples. If an address has no access, its initial and audit records cancel. Otherwise its unique initial tag forces the first read to equal `e(a)`. The first unique write tag then forces the second read to have that same value. Induction along the fixed finite chain forces every later read to equal `e(a)` and the final write to match the audit. Distinct write tags exclude an alternative permutation that jumps between accesses. Thus every lookup equals its prescribed equality-table value.

Encode each tuple by the monic factor

```text
offset + gamma^2 * address + gamma * value + tag.
```

The product ring `F[gamma, offset]` has unique factorization. Each factor is monic linear in offset. Two different tuple multisets therefore give different product polynomials: equality would require equality of their monic factors and hence of all three tuple coordinates. For a memory domain of r addresses, each side has `N + r` factors, and the difference has total degree at most `2(N + r)`. A wrong lookup assignment consequently has a nonzero polynomial identity to evade.

For independent challenges from the C1 support of size `Q = 2^255`, polynomial root counting bounds the identity exception by `2(N + r)/Q`. Applying this to both row and column memories, and using the larger row domain, gives `4(N + r_row)/Q`. This is a polynomial identity bound for fixed candidate tables. It is not by itself a Fiat-Shamir theorem.

The four dynamic commitments precede the inner-product and memory challenges. If the C1/BaseFold local extraction theorem gives at most L initial candidates per dynamic column, there are at most `L^4` candidate tuples. The seven static columns each have one fixed honest codeword. Unioning over the complete dynamic candidate set gives the documented `4(N + r_row)L^4/Q` envelope and permits later candidate switching. It does not assume a tuple selected before the challenges.

[The reduction verifier](../../noid_ivc_core/src/matrix_claim/sparse_c1.rs) reduces the coefficient/row-lookup/column-lookup cubic inner product and all eight memory products to explicit column evaluations. [The product-tree verifier](../../noid_ivc_core/src/matrix_claim/sparse_c1/sumcheck.rs) checks each layer's equality weight and reduces its two children by an independently sampled affine challenge. Outside its cubic sumcheck and affine-combination exceptions, backward induction identifies the terminal evaluation with the prescribed leaf table. The opening plan recombines a wide column as `lo(p) + X * hi(p)`; it does not split a field value evaluated at an extension point. Every resulting scalar or wide limb is then authenticated by the full PCS verifier.

Outside the local algebraic and PCS failure events, the memory lemma fixes both lookup vectors and the cubic inner product is exactly the stacked A/B matrix evaluation at the complete claimed point. These local events remain included in the certificate. The argument supplies the sparse semantic reduction, rather than treating successful decoding or rejected mutations as soundness.

## Retirement authority lemma

The production [retirement request constructor](../../noid_recursive/src/acceptance/history_step_bank/retirement.rs) is private to verified replay. It binds both banks, fork schedule, full boundary headers, ten boundary accumulator lanes, selected class, matrix identities and shapes, presence bits, all live point/value limbs and the complete fresh claim. Variable field vectors are length prefixed.

The reduction folds the fresh claim into the selected class and copies the other live class exactly. [Matrix closure](../../noid_recursive/src/acceptance/history_step_bank/retirement/evaluation.rs) requires one sparse evaluation for every remaining live lane, in canonical class order, with the correct shape and matrix digest. Its checked capability is constructed only after all evaluations pass. Each sparse transcript absorbs the pinned key digest, request context, complete point/value and all four dynamic roots before its challenges, and each of the eleven PCS openings names its column index and expected root.

The [origin entry point](../../noid_recursive/src/acceptance/history_step/v2/banked/retirement_codec.rs) verifies the parent boundary, derives that request through actual legacy replay, closes the reduction and evaluations, and passes the private capabilities to [the origin constructor](../../noid_recursive/src/acceptance/history_step/v2/banked/bank.rs). The latter checks the request, target, boundary, successor schedule/bank and both independent key pins. Therefore neither peer bytes nor the direct library route can grant origin authority by omitting a live class or using a key merely labeled with the right matrix digest, outside the retained binding and local proof failure events.

The origin digest identifies a common authenticated chain boundary and successor configuration. The retirement request digest identifies the exact proof obligations being discharged. They are different objects and need not have equal digests.

## Transcript equivalence lemma

Consider a finite sequence of legal operations of the production C1 channel. An operation header has `lo = op | kind << 8` and `hi = length`. The allowed op/kind pairs specify the number and kind of following lanes. Byte operations include their original byte length, so zero padding cannot make different byte strings share an encoding. Scalar and vector operations, base and extension values, domains and labels have distinct headers. Lengths are bounded by the production transport and geometry. Parsing the sequence from its first header therefore recovers exactly one operation sequence. This establishes encoding injectivity before hashing, not collision resistance of the sponge.

For the direct native/trace pair, use the invariant that the evaluated trace state, buffered lane, pending squeeze lane and permutation count equal the native channel's values after every operation. Initialization uses the same C1 IV and framed domain. An absorb discards the same pending lane and either buffers one lane or adds the same pair and permutes. An odd flush adds the same pad lane. A squeeze either returns the same pending lane or returns state lane zero, saves lane one and permutes. Both wide draws apply the same `F256::from_raw_challenge_lanes` map. Induction proves equality of every challenge and final state, conditional only on exact arithmetic and correctness of the permutation gadget.

The permutation gadget also has a deterministic arithmetic proof. The constant-one wire is pinned by the production class specification and lincheck. A multiplication allocation then constrains its output to the product of its two input expressions. The four allocations in `pow7` therefore force `x2=x*x`, `x4=x2*x2`, `x3=x2*x` and `x7=x4*x3`, hence exactly `x7=x^7`. Its affine MDS expressions and round constants import the same production tables, converted by the same field-basis isomorphism. Starting with the initial full MDS layer, induction over four full, fifty-eight partial and four full rounds gives the same mathematical permutation for every input, not only sampled inputs. This argument assumes the exact field operations and basis conversion underlying both implementations; it is not a formal verification of every hardware kernel.

For the wide challenge, the native map and its trace both compute `(lo, y^2+y+tau)`. The linear map `y -> y^2+y` over `GF(2^128)` has kernel `{0,1}` and image the trace-zero subspace. Since tau has trace one, uniform y maps two-to-one onto the trace-one affine subspace of size `2^127`. Together with the independent uniform 128-bit lo lane, the challenge is uniform on exactly `2^255` points. The trace enforces the square by a multiplication constraint and adds the same tau. This proves the stated support and native/trace equality under uniform raw lanes; it does not assert that a fixed public sponge is an ideal random oracle.

The native implementation is [FsLaneChallenger](../../noid_ivc_core/src/challenger.rs), and the direct trace is [FsChannelTrace](../../noid_ivc_core/src/field_circuit.rs). The selected-parent path uses [BaseSelectableParentRecorder](../../noid_recursive/src/acceptance/history_step/gated_recorder.rs): its numerical state follows the same recurrence, but challenge wires are initially allocated rather than hashed inline. Their authority comes from the recorded duplex walk and source bindings, not from their initial witness values. [Parent-region finalization](../../noid_recursive/src/acceptance/trace/r_pcs_region.rs) binds the selected recorded data/challenge cells and the PCS leaves, directions and roots to that walk. Under the existing sidecar extraction condition, the selected recording has the same transcript as native replay. The recorder alone grants no such guarantee.

## Selected parent and exact carry lemma

Let b be the current base flag and s the authenticated predecessor-class bit. The fixed relation constrains `b(b+1)=0` and `s(s+1)=0` over a field, so both belong to `{0,1}`. In characteristic two the nonbase gate is `g=1+b`, the small selector is `1+s`, and the large selector is s. The two arm gates are:

```text
g_small = (1 + b)(1 + s)
g_large = (1 + b)s
```

If b is zero, exactly one arm gate is one. If b is one, both are zero. For every rejection equation E, [scoped gating](../../noid_recursive/src/acceptance/trace/mod.rs) imposes `g_arm * E = 0`. Thus the selected nonbase arm retains every native rejection equation; disabling the unselected arm cannot disable the selected one. Nested source-binding gates multiply to the same authenticated selected-arm gate.

For each lane coordinate the [fixed assembly](../../noid_recursive/src/acceptance/history_step/v2/banked/assembly.rs) imposes

```text
out = previous + g_arm * (folded + previous).
```

For an active arm this is `out=folded`; for an inactive arm it is `out=previous`. The same rule changes the active lane's liveness bit to one and carries inactive liveness unchanged. At the base boundary every matrix lane is constrained to zero. Hence changing block class cannot reset a previously live lane, and the base arm cannot import an unchecked v2 matrix claim.

The ordered bank, matrix/post-commit identities and sealed origin prefix are copied from the same predecessor IO. The selected predecessor's semantic block ID and all ten start-accumulator lanes are bound to the current block's parent and start State; all end lanes are bound to the current public IO. On the base arm, those start lanes instead equal the independently verified legacy origin. Native [bank parsing](../../noid_recursive/src/acceptance/history_step/v2/banked/bank.rs) requires the pinned bank, both matrix/post identities, exact IO length, canonical booleans and dead lanes, and base status exactly at activation height. Together these constraints exclude an alternative parent-class route or an asserted origin as acceptance authority, under the local relation and binding conditions.

The [native matrix fold](../../noid_ivc_core/src/matrix_claim/c1.rs) and [its trace twin](../../noid_recursive/src/acceptance/trace/matrix_fold.rs) absorb the same complete fresh/incoming claims, perform the same two degree-two sumcheck phases and return the same point/value. Write `E_f` and `E_a` for the errors in the fresh and incoming evaluations. Before the first phase, an incorrect combined target has error `E_f + gamma * live * E_a`. If either required evaluation is false, this is a nonzero polynomial of degree at most one in gamma. The analogous second-phase combination uses delta after both intermediate values are observed. Outside those affine exceptions and the sumcheck exceptions, correctness of the authenticated outgoing evaluation propagates backwards to all live inputs. This is why copying the inactive lane and authenticating both final lanes are necessary; native replay without final matrix closure would be insufficient.

## Fixed relation lemma

The [bank identity](../../noid_recursive/src/acceptance/history_step/v2/banked/bank.rs) commits to the ordered configuration, IO specification, both matrix identities and PCS shapes, both block verifier-key digests, the parent verifier-key digest and both post-commit identities. [Runtime construction](../../noid_recursive/src/acceptance/history_step/v2/banked.rs) checks its parts against that bank, and every matrix load checks exact shape and structural digest. Native terminal replay binds matrix identity and commitment, complete public IO, then the post-commit sidecar identity before zerocheck, lincheck and PCS verification. The trace uses the same order and sources.

The sixteen-instruction [integer program](../../noid_tx/src/experimental_object/integer_program.rs) is witness data interpreted by [a fixed constraint gadget](../../noid_recursive/src/acceptance/trace/integer_program.rs). Instructions select among fixed, constrained operand/opcode/predicate tensors; they do not supply a verifier key, transcript implementation, class shape or new proving relation. Capacity limits and the fork schedule are bank configuration, not witness choices. This excludes relation substitution through contract data. It does not establish that every possible program inside that fixed relation is immune to concrete hash self-reference. That stronger conclusion belongs to the fixed-hash instantiation condition.

## Deterministic v2 all-root extension

Use the existing theorem's single measured compressed-oracle database D and typed, statement-keyed root representation. Its hypotheses are local round-by-round extraction, typed transcript/commitment binding and complete representation of every required noncertified child. They are stated here explicitly; the deterministic argument does not manufacture those hypotheses from framing or tests.

Define `BadAll(D)` over every represented accepting wallet, legacy History, v2 History and sparse root, before choosing a terminal ancestry. It holds when the relevant local extraction or deferred-obligation reduction fails. Define `MissRep` when a required noncertified child is absent and `BadTypedBind` when object/statement/namespace binding fails. The worklist uses only measured D and authenticated public material, with no fresh oracle query.

For a v2 terminal, authenticate its exact header/epoch boundary and independently verified origin. Native [terminal decision](../../noid_recursive/src/acceptance/history_step/v2/banked/decision.rs) replays the full proof and checks the fresh matrix evaluation and every live accumulated lane against authenticated v2 matrices. Its cache contains exact prior checked matrix claims, keyed by bank, class, shape and matrix identity; it contains no whole-terminal acceptance. The current fresh claim is always checked. A cache hit therefore supplies the same deterministic matrix fact as a repeat scan.

If `BadAll`, `MissRep` and `BadTypedBind` are all false, extraction supplies the exact current local relation. For a nonbase v2 witness the selected-parent lemma yields exactly one lower-height predecessor, the same origin and correct preservation/reduction of both matrix lanes. Push that predecessor and each required wallet/sidecar obligation. At the base witness, push the authenticated legacy boundary and its retirement obligations. The retirement lemma retains every legacy live lane; the sparse lemma closes them against the canonical legacy matrices. Continue with the existing legacy worklist to its deterministic genesis boundary.

History edges decrease authenticated integer block height. A retirement edge goes from the activation block to the height immediately before activation. Wallet, matrix evaluation and sidecar tasks introduce no same-height History edge; their protocol schedules have finite, decreasing remaining phases. A lexicographic rank consisting of History height and remaining nonrecursive protocol phase therefore decreases on every descent. Each extracted witness creates finitely many tasks, so the worklist terminates. Returning to a previously used class neither adds a rank cycle nor discards its carried obligation.

Apply the local State-transition implication in reverse topological order. Wallet obligations establish the required owner/authority evidence; the fixed block relation establishes the exact transition and parent link; matrix closure discharges deferred verifier claims; native consensus predicates bind the terminal to the selected valid header chain. Genesis is checked deterministically. The reconstructed ancestry is therefore a valid execution ending in the accepted terminal State. Taking the contrapositive proves

\[
\mathsf{BadState}_{v2}
\subseteq
\mathsf{BadAll}\cup\mathsf{MissRep}\cup\mathsf{BadTypedBind}.
\]

This proves the deterministic v2 specialization under the explicit local extraction, relation-semantic and compiler hypotheses of the existing certificate. In particular, the sparse reductions are additional authenticated obligations, not trusted checkpoints. The proof applies to the adversary's chosen finite ancestry, not just the archived test chain.

## Probability composition boundary

The current calculator retains all twenty event types:

```text
wallet.query                    wallet.field
history.query                   history.b25.proximity
history.b255.proximity           history.candidate-switching
history.joint-sidecar
v2.query                        v2.small.proximity
v2.large.proximity               v2.candidate-switching
v2.joint-sidecar
retirement.b25.query             retirement.b25.proximity
retirement.b25.pcs-scalar        retirement.b25.reduction
retirement.b255.query            retirement.b255.proximity
retirement.b255.pcs-scalar       retirement.b255.reduction
```

[The source-linked inventory](../src/v2.rs) starts with the seven legacy events, adds five v2 events without duplicating the unchanged wallet, and adds four events for each retired class. Old ancestry remains part of the from-genesis game even when old matrix bytes are removed.

Under the existing typed all-root compiler/lifting hypotheses, a response input identifies one previously fixed verifier move. Conditional on prefix/binding stability, that move's local escape density is at most `kappa_*`, the maximum over this complete inventory. A new response can also alter already represented prefixes; the existing database-instability and global binding terms cover that case. This uses the existential database-wide event before reachability is chosen. A union bound over the terminal's discovered ancestors is not substituted for the all-root estimate.

For the sequential theorem, the unchanged complete ideal envelope is

\[
\varepsilon_{ideal}(T)
=\min\{1,6T^2(\kappa_*+(2T+1)/2^{255})+6T^3/2^{256}\}.
\]

For the parallel resource theorem, let `rho=max_j(kappa_j/c_j)`. For each batch s, its assumed price inequality is `sum_j k_sj*c_j <= A_s*delta_s`; total charges satisfy `sum_s A_s <= G` and `sum_s delta_s <= D`. Then

\[
\sum_s\sqrt{10\sum_j\kappa_j k_{s,j}}
\le\sqrt{10\rho}\sum_s\sqrt{A_s\delta_s}
\le\sqrt{10\rho GD}.
\]

Squaring gives the existing main-event bound `10*rho*G*D`. Finite extraction and global collision terms are composed once, with output verification included in the same total budget. The deterministic extension introduces no new probability multiplier for chain height, wallet count or represented-root count. This conclusion depends on the stated database-wide lifting hypothesis; graph termination alone would not establish it.

The compressed-oracle tools are [Chiesa, Manohar and Spooner, Proposition 8.14](https://eprint.iacr.org/2019/834) and [Chung, Fehr, Huang and Liao](https://eprint.iacr.org/2020/1305). [Fractal, Section 2.5 and Theorem 11.5](https://eprint.iacr.org/2019/1076) explicitly distinguishes an ideal-oracle argument from recursive composition after hash instantiation. Theorem 11.5 is for constant-depth compliance predicates, where depth means the maximum compliant transcript depth, not merely the fixed depth of one verifier circuit. It is not used here as a direct theorem for an unbounded blockchain. Its secure concrete instantiation assumption is also not an unconditional theorem about the public production Poseidon2b permutation. Here the same boundary remains in the certificate's event-specific `Delta_P2b` condition and ideal-compiler hypotheses. The source lemmas above do not silently remove it or establish new lifting constants.

The [accepted Cipher review](https://git.parano1d.org/ignotusnemo/parano1d-soundness/pulls/10) identifies three compiler obligations: statement-exclusive one-cell database transitions, representation of every required extracted child in the same measured D, and accounting embedded-verifier oracle calls in the same total budget. Its observation changes the scope of a supporting result. The selected-parent and recording lemmas settle specific source bindings; they do not construct the complete typed database-game embedding. Graph termination settles the deterministic ancestry argument; it does not make `MissRep` false. Declaring a common budget settles the resource theorem's hypothesis; it does not demonstrate that all embedded calls have been charged. These obligations remain explicit. The document must not be promoted as a completed proof of the full adaptive all-root contract merely because its deterministic extension and regressions pass.

## Authenticated snapshot installation lemma

The audited route begins at `verify_terminal_against_validated_snapshot_headers`, calls the production `HistoryProtocolRuntime::verify_terminal`, mints `VerifiedSnapshotBoundary` only after successful verification, and ends at `install_finalized_snapshot_staging`. Native header staging checks the header chain and seals its descriptor, length and digest. The boundary checks exact tip/epoch metadata and the public prefix before calling the full runtime verifier. A peer-supplied header prefix is not terminal authority.

The writer receives both verified-boundary and sealed-header capabilities. It checks their exact tip identity and the current base/finality/work guards, including bounded rebase rules, before publication. For every segment it reauthenticates the staged file, copies the verified encoded bytes into an owned buffer and decodes those same bytes for State, indexes, counts and roots. A later file rewrite cannot change that buffer. It checks the complete resulting root and live count against the verified terminal boundary.

Headers, terminal proof, segment data, indexes and consensus metadata are updated inside one MDBX write transaction. An error before commit drops the transaction and publishes none of those writes. Success commits the transaction before the in-memory State is replaced. Thus this route either installs the exact authenticated snapshot atomically or preserves the earlier durable boundary, assuming MDBX transaction semantics and commitment binding.

The argument is for the snapshot route named above. It does not automatically certify ordinary block application, local production or every reorganization path. The genuine archived-v2 terminal regression and the separate late-file substitution storage regression test different layers: the storage test injects a private verified fixture and is not presented as a cryptographic verifier test.

## Executable evidence and reproduction

The completed runs passed fifty-four Rust tests: thirty-five snapshot tests, twelve focused v2 bank/origin/cache tests, one independent small-geometry preprocessing test, two complete release-key reconstruction tests and four existing permutation/channel/recording correspondence tests. The genuine isolated retirement certificate was accepted at parent height 9 and activation height 10 with both legacy lanes live, then rejected under the mainnet successor bank. Full-path mutations covered 188 point limbs, four value limbs, four key/context variants, eight dynamic roots and forty-four PCS leaf/path variants, plus missing, duplicate, reordered and substituted live obligations.

The genuine isolated v2 snapshot was verified at height 17 using fully authenticated artifact matrices and the production terminal dispatcher. Five header substitutions, an epoch substitution and a post-admission proof mutation failed. Restarting without the in-memory origin cache succeeded only after rechecking retained origin evidence. The storage regression changed a same-size finalized segment before install and checked that all durable header/proof/State boundaries rolled back.

The isolated fixtures share authenticated release legacy matrices and keys but use a different activation height and successor bank. These runs do not claim a mined mainnet v2 terminal before activation. Matrix-authentication and reconstruction timings are audit costs, not wallet synchronization measurements.

From the repository root:

```sh
cargo test --release --locked -p noid_chain snapshot -- --test-threads=1
cargo test --release --locked -p noid_recursive \
  acceptance::history_step::v2::banked:: -- --test-threads=1
NOID_CORRESPONDENCE_INPUTS=/path/to/authenticated-inputs \
RAYON_NUM_THREADS=3 cargo test --release --locked -p noid-ivc-core \
  independently_reproduce_pinned_release_key -- --ignored --nocapture --test-threads=1
```

The genuine fixtures are replayed by [the retirement harness](../../bench_prover/src/bin/noid_retirement_correspondence.rs) and [the snapshot harness](../../bench_prover/src/bin/noid_v2_snapshot_correspondence.rs), built with `--features noid_chain/isolated-v2-fork-testnet`. Detailed passive artifacts record every command, source/input digest and observation. The twenty-three-file reproduction input bundle has SHA-256 `25a0f1df8b90b71ff659b76a8e17b3d39f86e1d5bbd784aa4f8db919a7a9cbfa`. It must be made available with the research publication; its digest is an input receipt, not a substitute for obtaining its bytes.

The complete key reconstruction took 1,413.76 seconds with a maximum resident set of 11,919,456 KiB under a 16 GiB cgroup limit, three-CPU quota and no swap. It is intentionally opt-in. Repeating it is unnecessary for a documentation-only change unless its authenticated inputs, implementation or conclusions change.

## Accepted certificate updates

The new mathematical/source material belongs in the integrated certificate documentation and scoped research records. It supports release preprocessing and exact request closure, selected-parent/transcript source correspondence, conditional deterministic all-root specialization and the audited snapshot route. Semantic review must preserve those scopes. A green source-correspondence node means the named obligation has checked supporting evidence; it does not convert a dependent cryptographic assumption into an unconditional theorem.

Neither the fixed-hash deviation nor the declared universal scalar/batch response prices has been proved by this work. Their status and the numerical frontier stay unchanged. The ideal compiler/lifting hypotheses are also retained explicitly; this document proves their deterministic v2 specialization and selected source bindings, not a new general quantum Fiat-Shamir instantiation theorem.
