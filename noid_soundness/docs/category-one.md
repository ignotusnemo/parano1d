# End-to-end post-quantum soundness and Category 1

## Result

The security game asks whether a quantum adversary can make Parano1d accept an
invalid terminal State whose recursive ancestry starts at genesis.

For the current W65/H133 production profile, the executable theorem gives:

| Statement | Result |
|---|---:|
| Largest certified sequential ideal-QROM query budget | `30121082641781720121` |
| First uncovered sequential budget | `30121082641781720122` |
| Descriptive sequential boundary | **64.707407428576 bits** |
| Ideal success bound at `T=2^64` | **at most 0.187528937938435742** |
| Dominant Category 1 gate-depth floor | **173.391078499301 bits** |
| Margin over `2^170` | **3.391078499301 bits** |
| Complete ideal Category 1 envelope | **at most 0.049330348213215253** |

The fixed Poseidon2b corollaries hold under the sufficient conditions

\[
\Delta_{\rm P2b}(2^{64})
<0.312471062061564258
\tag{1}
\]

and

\[
\Delta_{\rm P2b}^{\rm C1}
<0.450669651786784747.
\tag{2}
\]

The Category 1 conclusion also uses the coherent response-cost premise stated
in [the resource section](#coherent-response-cost). Under those explicit
premises, the result is provable end-to-end post-quantum soundness for state
validation from genesis at NIST PQC Category 1.

This is a cryptographic resource assessment, not a claim that NIST reviewed or
certified Parano1d.

## The security game

The public instance is a terminal `HistoryStep` State. The adversary wins when
the production verifier accepts its terminal proof but no valid execution from
genesis ends in that State. Failure may occur in a wallet authorization, block
relation, parent link, exact State transition, recursive verification step or
the claimed ancestry itself.

The adversary is one stateful quantum algorithm. All oracle interactions used
to construct the terminal proof and every adversarial ancestor on which it
depends belong to the same resource budget. Genesis is checked
deterministically, so this game has no checkpoint-certification error term.

After the compressed-oracle database is measured, extraction and ancestry
walking are deterministic and make no new oracle queries.

## Production parameter correspondence

The certificate does not duplicate the parameters in a separate model file.
It imports and checks the following production definitions at build and run
time.

| Security input | Production source |
|---|---|
| Wallet query geometry and Johnson ledger | [`ZK_AUTH_CAPSULE_GEOMETRY`](../../noid_fri_binius/src/zk_capsule.rs) and [`conditional_selected_zk_auth_base_iop_ledger`](../../noid_gkr/src/zk_auth_qrom.rs) |
| C1 challenge support | [`C1_CHALLENGE_MIN_ENTROPY_BITS`](../../noid_ivc_core/src/field/gf2_256.rs) |
| History query count | [`HISTORY_STEP_FRI_QUERIES`](../../noid_recursive/src/acceptance/history_step_bank.rs) |
| Canonical B25 and B255 PCS profiles | [`canonical_history_step_pcs_params`](../../noid_recursive/src/acceptance/history_step_bank.rs) |
| BaseFold query count | [`BASEFOLD_RATE_QUARTER_C1_QUERIES`](../../noid_ivc_core/src/pcs/basefold.rs) |
| Sidecar transcript groups | [`JOINT_C1_GROUPS`](../../noid_recursive/src/region_sidecar.rs) |
| Poseidon2b profile | [`STATE_SIZE`, `SBOX_EXPONENT`, `F_ROUNDS`, `P_ROUNDS`](../../noid_poseidon2b/src/native/permutation.rs) and [`RATE`](../../noid_poseidon2b/src/native/compression.rs) |
| Poseidon2b linear layers and Merkle compression | [`MDS_FULL`, `MDS_PARTIAL`](../../noid_poseidon2b/src/native/permutation.rs) and [`compress_flat_feed_forward_with_tag`](../../noid_poseidon2b/src/native/compression.rs) |
| Digest width | the size of [`Digest`](../../noid_poseidon2b/src/primitives.rs) |

The current source definitions resolve to:

```text
wallet queries                 = 65
History queries                = 133
History queries = BaseFold queries
challenge support              = 2^255
digest width                   = 256 bits
B25 codeword                   = 2^19 at rate 1/4
B255 codeword                  = 2^21 at rate 1/4
Poseidon2b                     = t4, rate2, x^7, RF8, RP58
joint sidecar groups           = 3 + 6 = 9
```

The loader returns an error before printing a result if linked definitions
disagree, including the wallet ledger versus wallet geometry, History versus
BaseFold query counts, wallet versus C1 challenge support, or the two History
rates. Release tests separately pin every value in the displayed production
profile, so an intentional parameter change requires a reviewed new
certificate rather than silently retaining these numbers.

## Exact local theorem

The local theorem is stated for the de-Merkleized and de-grinded public-coin
IOP. Every production algebraic move remains in its original order, but each
Fiat–Shamir squeeze is replaced by its corresponding independent verifier
coin and authenticated arrays are exposed as ideal oracles. The final nonce
predicate is removed. Removing that predicate can only help a cheating prover,
so it supplies no security credit.

The C1 algebraic coins are elements of `GF(2^256)` sampled from the trace-one
affine support implemented by `F256::from_raw_challenge_lanes`. The support is
uniform and has exactly `2^255` elements. An exceptional set containing at
most `a` field elements is therefore hit with probability at most
`a/2^255`. The query-position move remains one atomic vector response. Its
positions are disjoint bit windows of uniform 128-bit lanes and are mutually
independent and uniform with replacement.

### Wallet

The wallet has two local bad-response terms:

\[
\kappa_{W,q}=\left(\frac{1}{5}\right)^{65},
\qquad
\kappa_{W,f}=\frac{701\,202\,001\,931}{2^{255}}.
\tag{3}
\]

Its generalized round-by-round bound is

\[
\kappa_W=\max\{\kappa_{W,q},\kappa_{W,f}\}.
\tag{4}
\]

The [wallet refinement derivation](wallet-johnson.md) certifies radius `4/5`
on all eight production RS layers, a list bound of seventeen, and the grouped
fold specialization. Its field numerator is the union of the eight proximity
envelopes plus `17^2 * (156 + 7)` algebraic roots. This explicitly accounts for
candidate switching and the upper-link multilinear across the 3+4 fold groups.
The query move is a different verifier move. Generalized round-by-round
knowledge error takes the largest conditional escape probability over
verifier moves, which explains the maximum in equation (4) rather than a sum
chosen after evaluation. Only analysis parameters change; the production
query count, transcript and matrices remain the same.

### History

For integral Johnson multiplicity `m >= 3`, define

\[
h=m+\frac12,
\qquad
\gamma=\frac{m-1}{2m},
\qquad
s_N=\frac{N-4}{2N}.
\tag{5}
\]

At a layer of length `N`, the production Reed–Solomon code has dimension
`N/4` and the degree convention of the list-correlated theorem gives reduced
rate

\[
\rho_N=\frac{N/4-1}{N}=\frac14-\frac1N.
\]

The rational value in equation (5) satisfies

\[
s_N^2<\rho_N,\qquad s_N<\sqrt{\rho_N}<\frac12.
\]

For

\[
\gamma_m=\frac{m-1}{2m}
\]

the multiplicity precondition of the list-correlated agreement theorem holds:

\[
\left\lceil
\frac{\sqrt{\rho_N}}{1-\sqrt{\rho_N}-\gamma_m}
\right\rceil\le m.
\]

Indeed, the denominator is strictly larger than `1/(2m)` and the numerator
is strictly smaller than `1/2`, so the ratio is strictly smaller than `m`.
This verifies the theorem range for every `m >= 3` and every production
layer, rather than extrapolating one asymptotic radius.

For every rate-one-quarter Reed–Solomon layer, the exact proximity envelope,
strict list bound and query escape term are

\[
A_N(m)=\left\lfloor
N\frac{2h^5+3h\gamma s_N^2}{3s_N^3}+\frac{h}{s_N}
\right\rfloor,
\tag{6}
\]

\[
L_N(m)=\left\lceil\frac{h}{s_N}\right\rceil-1,
\qquad
L_{\max}(m)=\max\{L_{2^{19}}(m),L_{2^{21}}(m)\},
\tag{7}
\]

\[
E_q(m)=\left(\frac{m+1}{2m}\right)^{133}.
\tag{8}
\]

Theorem 4.6 of Ben-Sasson, Carmon, Haböck, Kopparty and Saraf supplies
equation (6). Haböck's BaseFold analysis maps it to the fold schedule. Packing
the live lanes into one extension-field word gives one initial list. Later
algebraic identities explicitly union over that finite list, so candidate
switching is bounded rather than assumed away.

### Fold provenance and the single initial list

The initial commitment contains 32 interleaved `GF(2^128)` Reed–Solomon
rows. During the five row-batch moves, pack each live half into a fixed
extension of `GF(2^256)`. The production fold is an affine combination
`f_0 + r f_1`, up to an invertible coordinate-wise change of basis. Restricting
the exceptional set from the full field to the trace-one challenge support
cannot increase its cardinality.

For every nonexceptional challenge, the list-correlated agreement theorem says
that every close post-fold codeword selected by a later decoder has a
correlated pair of close pre-fold origins on the same weighted agreement set.
Applying this statement through all row-batch moves restores all 32 lanes on
one common set. For the position folds, production `fold_pair` first applies
an invertible additive-NTT butterfly and then the same affine combination.
Haböck's additive-FFT specialization gives the identical backward step.

Fixing a degree-32 extension and a basis identifies the 32-row initial oracle
with one Reed–Solomon word over that extension. Column Hamming distance is
preserved exactly. The strict integral list bound in equation (7) is therefore
the size of one packed list, not 32 independent lists. Every candidate that
survives a nonexceptional fold trace originates in that fixed initial list.
Agreement with the committed base-field rows holds on more than `N/2`
positions, while the degree is below `N/4`. Frobenius conjugation and
polynomial uniqueness therefore force every decomposed candidate row back
into the embedded `GF(2^128)` subfield.

The maximum algebraic identity has 127 roots per candidate. The joint sidecar
has nine groups across four Poseidon lanes, hence 36 roots per candidate. For
all B25 and B255 layers,

\[
\begin{aligned}
\kappa_H(m)=\max\{&E_q(m),
\max_N A_N(m)/2^{255},\\
&L_{\max}(m)\cdot127/2^{255},
L_{\max}(m)\cdot36/2^{255}\}.
\end{aligned}
\tag{9}
\]

The proximity maximum ranges over every folded layer. The list maximum uses
only the two initial committed codewords, because every later algebraic
continuation is unioned over that one fixed initial list.

The 127-root inventory covers public-input compression, zerocheck, lincheck,
PCS claim batching and BaseFold sumcheck identities. The joint sidecar uses
one batching polynomial with powers assigned to nine groups and four state
lanes, so its maximum degree is 36. For one verifier move, unioning the roots
over the complete fixed initial list gives exactly the last two finite terms
in equation (9). It permits the continuation to switch candidates; it never
assumes a candidate selected before the challenge.

| Algebraic verifier move | Maximum roots for one candidate |
|---|---:|
| public-input multilinear compression | 7 |
| sidecar initial multilinear point | 19 |
| sidecar relation, shift or carry identity | 4 |
| joint nine-group sidecar batch | 36 |
| ragged-walk sumcheck round | 8 |
| zerocheck coordinate compression | 18 |
| zerocheck interpolation challenge | 127 |
| zerocheck or lincheck sumcheck round | 2 |
| joint lincheck batching | 1 |
| deferred inner coordinate | 63 |
| all PCS opening claims jointly | 1 |
| BaseFold sumcheck round | 2 |

### Query move and extractor

Grouped Merkle epochs omit commitments to some intermediate folds, but not the
mathematical words. Each omitted word is a deterministic function of the
preceding oracle and scalar prefix. Expanding one production query into its
binary fold edges and then contracting deterministic skipped paths preserves
the set of accepting initial positions. If restoration to a
`(1-gamma_m)`-good initial candidate failed, the weighted backward graph
argument leaves an accepting fraction at most `1-gamma_m`. Consequently 133
independent positions miss the altered set with probability equation (8).

The straight-line extractor computes the packed initial list, decomposes each
candidate into 32 base-field rows, applies the inverse additive NTT and the
inverse structure-of-arrays map, and runs the exact History relation. It
returns a witness only when that deterministic relation accepts. Define a
prefix as doomed when no candidate yields a valid witness. Backward induction
over the exact verifier schedule shows that a doomed prefix can leave the
doomed set only through a proximity exception, an algebraic candidate root or
the final query miss. A complete doomed transcript rejects. Taking the maximum
of those conditional escape probabilities proves equation (9) as generalized
round-by-round knowledge error.

The unweighted optimum used by the sequential theorem is `m=861824`. The
resource-aware optimum used below is `m=318983`; it accounts for the fact that
a History query response needs twelve sequential Poseidon2b permutations.

## One all-root event

Every transcript family and statement is placed in a typed, statement-keyed
oracle namespace. Let `D` be the single measured compressed-oracle database.
Define `BadAll(D)` to mean that there exists any represented accepting wallet
or History root for which the deterministic extractor fails or returns an
invalid local witness.

Two boundary events are kept explicit:

```text
MissRep       a required noncertified child is absent from D
BadTypedBind  a collision, ambiguous encoding or domain confusion changes
              the typed semantic graph
```

The event `BadAll` quantifies over all represented roots before ancestry is
traversed. This ordering matters because inserting one database entry can make
an already present subgraph reachable. The probability theorem is applied to
the reachability-free all-root property; reachability is used only after the
database has become classical.

Once `D` is measured, a deterministic worklist starts at the accepted
terminal, validates the local relation, reconstructs its canonical nested
artifacts, follows the unique lower-height History parent and appends every
required wallet and joint-sidecar obligation. No step makes another oracle
query. The History rank decreases at each recursive edge, so the worklist
terminates at genesis.

The production semantic correspondence is the following deterministic
implication. A valid extracted class witness, the canonical parent and wallet
projection, [`ChainAccumulator::advance`](../../noid_recursive/src/accumulator.rs),
[`verify_history_step_terminal`](../../noid_recursive/src/acceptance/history_step/relation.rs),
the [native consensus predicates](../../noid_chain/src/consensus/validation.rs)
and
[`materialize_accepted_block_state`](../../noid_chain/src/block.rs) together
imply one exact valid State transition. Applying that implication in reverse
topological order gives a valid execution from genesis to the accepted State.
Therefore

\[
\mathsf{BadState}
\subseteq
\mathsf{BadAll}\cup\mathsf{MissRep}\cup\mathsf{BadTypedBind}.
\]

There is no certification term because this game starts at genesis. In the
closed-world typed ideal compiler, canonical nested artifacts are represented
in the same database, so `MissRep` is false. For the fixed production duplex,
both missing representation and typed binding deviation are included once in
the `P2B-Delta` game defined below.

Consequently chain height, wallet count and represented-root count affect
extraction time and the adversary's actual work, but introduce no additional
probability multiplier. They are already covered by the one existential
all-root event and the one total resource budget.

## Sequential ideal-QROM theorem

Let

\[
\kappa_*=\max\{\kappa_W,\kappa_H(861824)\}.
\tag{10}
\]

Specializing the compressed-oracle lifting argument of Chiesa, Manohar and
Spooner to the typed all-root property gives, for a total query cap `T`,

\[
I_{\rm all}(T)
\le\kappa_*+\frac{T+1}{2^{255}}.
\]

FRACTAL's statement-keyed lifting takes the maximum over typed instances, so
the number of adaptive statements and represented roots does not multiply
this instability. The typed transcript-collision instability is at most
`T/2^255`. Applying the explicit `6T^2` lifting factor to their sum, then
adding the one global 256-bit commitment collision term, gives

\[
\boxed{
\varepsilon_{\rm ideal}(T)=\min\left\{1,
6T^2\left(\kappa_*+\frac{2T+1}{2^{255}}\right)
+\frac{6T^3}{2^{256}}
\right\}.}
\tag{11}
\]

The terms in equation (11) are:

| Term | Meaning |
|---|---|
| `6T^2 kappa_*` | lifted local generalized RBR failure |
| `6T^2 (T+1)/2^255` | extraction instability |
| `6T^2 T/2^255` | typed transcript-collision instability |
| `6T^3/2^256` | one global commitment and binding collision event |

Exact integer binary search for
`epsilon_ideal(T) < 1/2` gives:

```text
largest certified T = 30121082641781720121
first uncovered T   = 30121082641781720122
log2(first uncovered T) = 64.707407428576...
```

The first uncovered value is where this upper bound reaches one half. It is not
an exhibited attack.

At `T=2^64`, directed rational evaluation gives

\[
\varepsilon_{\rm ideal}(2^{64})
\le 0.187528937938435742.
\tag{12}
\]

If the real fixed-permutation game differs from the ideal game by at most
`Delta_P2b(T)`, then

\[
\Pr[\mathsf{BadState}]_{\rm production}
\le\varepsilon_{\rm ideal}(T)+\Delta_{\rm P2b}(T).
\tag{13}
\]

Equations (12) and (13) prove equation (1).

## NIST Post-Quantum Cryptography Category 1 resource target

NIST defines Category 1 through attacks that require resources comparable to
or greater than AES-128 key search. Its preliminary depth-aware quantum
reference assigns AES-128

\[
G=2^{170}/D
\tag{14}
\]

logical gates at maximum circuit depth `D`. Equivalently, the reference
gate-depth product is

\[
GD=2^{170}.
\tag{15}
\]

NIST identifies `D` values `2^40`, `2^64` and `2^96`. The certificate
evaluates all three rather than selecting the most favorable point.

## Typed parallel-QROM resource theorem

For each typed bad-response event `j`, let:

```text
kappa_j  local bad-response density
g_j      logical gates needed for one coherent response
d_j      logical depth needed for one coherent response
```

The parallel compressed-oracle transition bound of Chung, Fehr, Huang and Liao
has constant 10. Specializing it to the typed all-root event and combining
query types by Cauchy–Schwarz gives

\[
\Pr[\mathsf{BadState}]_{\rm main}
\le 10GD\max_j\frac{\kappa_j}{g_jd_j}.
\tag{16}
\]

To see the resource step, let `k_sj` be the number of type-`j` queries in
parallel query round `s`, and let

\[
\delta_s=\max\{d_j:k_{s,j}>0\}
\tag{17}
\]

be the response depth of that round. The resource constraints are

\[
\sum_{s,j}g_jk_{s,j}\le G,
\qquad
\sum_s\delta_s\le D.
\tag{18}
\]

The compressed-oracle transition amplitude is at most

\[
\begin{aligned}
\sqrt{10}\sum_s\sqrt{\sum_j\kappa_jk_{s,j}}.
\end{aligned}
\tag{19}
\]

Weighted Cauchy–Schwarz, followed by `delta_s >= d_j` for every active type in
round `s`, gives

\[
\begin{aligned}
\Pr[\mathsf{BadState}]_{\rm main}
&\le10\left(\sum_s\delta_s\right)
\left(\sum_s\frac{\sum_j\kappa_jk_{s,j}}{\delta_s}\right)\\
&\le10D\sum_{s,j}\frac{\kappa_jk_{s,j}}{d_j}\\
&\le10D\max_j\frac{\kappa_j}{g_jd_j}
\sum_{s,j}g_jk_{s,j}\\
&\le10GD\max_j\frac{\kappa_j}{g_jd_j}.
\end{aligned}
\tag{20}
\]

This proves equation (16) even when one parallel round contains several
response types. Adaptively selected statements and recursive roots remain
inside the same all-root event and do not add a separate union factor.

## Coherent response cost

The resource model uses the following reversible `GF(2^128)` Karatsuba
multiplier schedule:

| Resource | Count |
|---|---:|
| CNOT | 29,340 |
| one-qubit Clifford | 4,374 |
| T | 15,309 |
| total logical gates | 49,023 |
| logical depth | 43 |

The fixed Poseidon2b permutation has 90 S-boxes:

\[
4\cdot8+58=90.
\tag{21}
\]

For `x^7`, squaring is linear and the nonlinear schedule uses two sequential
field multiplications. Coherent computation and uncomputation therefore use
four multiplications per S-box. Full-round S-boxes execute in parallel, so one
coherent permutation response has

\[
g_0=90\cdot4\cdot49\,023=17\,648\,280
\tag{22}
\]

logical gates and

\[
d_0=(8+58)\cdot4\cdot43=11\,352
\tag{23}
\]

logical depth. Thus

\[
g_0d_0=200\,343\,274\,560.
\tag{24}
\]

A wallet query response squeezes seven 128-bit lanes through a rate-two
duplex, requiring four sequential permutations. A History query response
needs twelve. Scalar responses use one permutation.

The Category 1 theorem assumes that an adversary obtaining the corresponding
coherent production response must pay at least these logical gate and depth
costs. Equations (22) and (23) are a concrete reversible schedule with positive
linear, routing and control work omitted. This omission is conservative for
that schedule, but a concrete construction alone is not a universal circuit
lower bound. The minimum coherent response-cost statement is therefore an
explicit premise of the production Category 1 conclusion.

## Category 1 calculation

The certificate evaluates these production event families:

```text
wallet.query
wallet.field
history.query
history.b25.proximity
history.b255.proximity
history.candidate-switching
history.joint-sidecar
```

For History, resource-aware minimization uses `m=318983`. The maximum ratio in
equation (16) is `history.query`. Solving the main term for half success gives

\[
GD_{1/2}^{\rm main}
=\frac{1}{20\max_j(\kappa_j/(g_jd_j))}.
\tag{25}
\]

The exact rational value in equation (25) has descriptive logarithm

\[
\log_2 GD_{1/2}^{\rm main}
=173.391078499301\ldots,
\tag{26}
\]

which is `3.391078499301` bits above the NIST reference in equation (15).

At `GD=2^170`, the main term is

\[
\varepsilon_{\rm main}
\le0.047659958340587260.
\tag{27}
\]

## Finite and collision terms

For each NIST depth point `D=2^d`, set

\[
G=2^{170-d},
\qquad
N=\left\lfloor\frac{G}{g_0}\right\rfloor,
\qquad
R=\left\lfloor\frac{D}{d_0}\right\rfloor.
\tag{28}
\]

Using the cheapest scalar response gives the conservative typed finite term.
Its two bad densities are `(N+1)/2^255` for extraction instability and
`N/2^255` for transcript-collision instability. Lifting them through equation
(16) yields a combined bound at the worst depth point of

\[
\varepsilon_{\rm typed}
\le0.000199022715317804.
\tag{29}
\]

For the one global 256-bit binding-collision event, Theorem 5.29 of Chung,
Fehr, Huang and Liao gives the amplitude bound

\[
2eN\sqrt{\frac{10R}{2^{256}}}
+\sqrt{\frac{2}{2^{256}}}.
\tag{30}
\]

The calculator squares the entire positive expression. It uses
`2719/1000 > e` and an integral ceiling square root, so no cross term is lost
and every rounding direction remains an upper bound. At the worst depth point,

\[
\varepsilon_{\rm collision}
\le0.001471367157310191.
\tag{31}
\]

The finite envelope is largest at `MAXDEPTH=2^40`; the calculator also checks
`2^64` and `2^96`. Combining equations (27), (29) and (31),

\[
\boxed{
\varepsilon_{\rm ideal}^{\rm C1}
\le0.049330348213215253<\frac12.}
\tag{32}
\]

The remaining half-success headroom proves equation (2).

## Current Poseidon2b cryptanalysis

Merz and Rodríguez García give improved algebraic attacks on Poseidon2 and
Poseidon2b in ePrint 2026/306. The executable audit pins the reviewed
2026-02-18 PDF with SHA-256
`8297df539a48859678ad2e4ba79d005a544e1a9686770a4f72a30ad358f76249`.
Their analysis distinguishes the CICO problem from the concrete compression
and sponge modes, so it must be matched to the mode used by production code
rather than cited only as permutation cryptanalysis.

The production instance is

```text
field       GF(2^128)
state       t = 4
rate        r = 2
capacity    c = 2
digest      d = 2 field elements
S-box       x^7
rounds      RF = 8, RP = 58
```

The main round skips in Sections 3 through 5 exploit the tensor structure of
wide non-MDS external matrices. Section 3.4 explicitly limits that attack
family to `t` in `{12, 16, 20, 24}`. The production `t=4` external layer is the
binary MDS matrix `M4` itself, so the paper's wide attack tables and the
headline `2^106` improvement do not apply to this instance. That improvement
is for the binary `(n,t,c,d)=(32,24,8,8)` sponge with `RP=15`.

Appendix A is relevant. It treats MDS two-to-one feed-forward compression. A
production flat Merkle node has input

\[
x=(a_0,a_1,b_0+\mathsf{IV}_0,b_1+\mathsf{IV}_1)
\]

and returns

\[
\operatorname{Tr}_2(P(x)+x).
\]

The capacity tag is a fixed affine shift and does not change the Appendix A
model. For `t=4` and `alpha=7`, its round skip is

\[
(1,[1]+[7]^{t/2-1})=(1,[1,7]).
\tag{33}
\]

Specializing Theorem 5.1 with `d=2`, `r_F=1` and `r_P=0` gives

\[
\begin{aligned}
d_I
&\le 7^{d(R_F-r_F)+(R_P-r_P)}\prod_i\delta_i \\
&=7^{2(8-1)+58}\cdot7 \\
&=7^{73}.
\end{aligned}
\tag{34}
\]

The exact integer is

\[
7^{73}=
49\,221\,735\,352\,184\,872\,959\,961\,855\,190\,338\,177\,606\,846\,542\,622\,561\,400\,857\,262\,407.
\tag{35}
\]

The paper models Gröbner-basis work as proportional to `d_I^omega` and uses
`omega=2` as its conservative projection. For this instance,

\[
\log_2(d_I^2)=146\log_2 7
=409.873818620410\ldots.
\tag{36}
\]

The formal scope of equation (36) is a classical attack-cost projection derived
from an upper bound on the ideal degree. The paper concludes that its attacks
do not reduce the claimed 128-bit security of the full-round recommended
instances. The event-specific fixed-Poseidon2b quantum condition is represented
separately by `Delta_P2b` below.

`poseidon2b_cryptanalysis::audit` imports the production tuple and checks both
linear matrices against the values used by this specialization before
evaluating equations (34) through (36). Any change to the field width, state
geometry, round schedule or matrices makes the executable certificate reject
the old audit.

### August 2026 nonlinear-subspace update

Li, Liu and Wang extend linear subspace trails to nonlinear constraints in
ePrint 2026/1792. Their compression-mode budget specializes to
`E_c=t-d=2`. With the production `s=1` partial layer, the linear trail covers
two partial rounds and the nonlinear trail covers four of the production 58.

The paper requires an instance-level rank check. For the exact production
internal matrix, its Appendix B.7 even-construction core reduces to

\[
N_e=BSC A^{-1}-1,\qquad S=D-CA^{-1}B.
\]

The executable audit evaluates this expression in `GF(2^128)` and obtains the
nonzero tower-basis value `0xbe32`. It then evaluates all four applicable
Macaulay models at every permitted trail placement. The smallest `omega=2`
projection is `1022.830074998558` bits. This is above the
`409.873818620410`-bit feed-forward projection in equation (36), so the new
paper does not change the strongest published dedicated-attack projection used
by this certificate. This is the paper's semi-regular attack-cost model
transferred to the production field, not a lower bound on all attacks.

The reviewed ePrint 2026/1792 archive version is `20260824:125701`, with
SHA-256
`006cf8bc3b47df053d662b6552aa82fd8add2a75a152e08f9c63db73a29564cb`.
The complete specialization, model caveats and the screening of the other
August Poseidon results are recorded in the
[August 2026 Poseidon2b review](poseidon2b-august-2026.md).

## Fixed Poseidon2b boundary

The production assumption is defined on compiler events, not on the desired
semantic conclusion. For a declared resource envelope `R`, let
`epsilon_ideal(R)` be the applicable complete typed ideal bound above and
define

\[
\mathsf{BadCompiler}
=\mathsf{BadAll}\cup\mathsf{MissRep}\cup\mathsf{BadTypedBind}.
\]

`Delta_P2b(R)` is any explicit upper bound satisfying

\[
\Delta_{\rm P2b}(R)\ge
\max\left\{0,
\Pr[\mathsf{BadCompiler}]_{\rm fixed\ P2b}
-\varepsilon_{\rm ideal}(R)
\right\}.
\]

The fixed experiment uses the exact `FsLaneChallenger` framing, public
Poseidon2b constants, typed commitment domains, canonical nested-artifact
recording, native verifier and recursive verifier gates. Because the
structural theorem already proves `BadState` is a subset of `BadCompiler`, the
definition does not assume the statement it is used to establish. It is added
once to the complete all-root bound:

\[
\Pr[\mathsf{BadState}]_{\rm production}
\le\varepsilon_{\rm ideal}+\Delta_{\rm P2b}.
\tag{37}
\]

It is not defined as a qPRP advantage between a public fixed permutation and a
secret random permutation. Direct evaluation would distinguish those games.
The Poseidon2b specification supplies the production parameters. The audit
above incorporates the current published classical cryptanalysis of the
permutation and its concrete modes. It does not evaluate `Delta_P2b`, because
the ideal-degree attack model neither bounds every fixed-permutation failure
event nor supplies the required coherent quantum statement. Equations (1) and
(2) state the additional event-specific quantum instantiation bounds
sufficient for the two production conclusions.

## Exact arithmetic and reproduction

All normative comparisons use `BigUint` rational arithmetic. Decimal
probability bounds are rounded upward. Sufficient `Delta` headroom values are
truncated downward. Logarithms are descriptive projections and never decide a
pass or fail result.

From the repository root:

```sh
cargo run --release --locked -p noid_soundness
cargo run --release --locked -p noid_soundness -- --exact
cargo test --release --locked -p noid_soundness
```

The exact mode prints every local density, response gate-depth product, NIST
finite term, global collision term, complete envelope and fixed-permutation
headroom as a reduced rational number.

## Sources

- NIST,
  [Post-Quantum Cryptography Standardization Evaluation Criteria, Section 4.A.5](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-%28evaluation-criteria%29),
  for the Category 1 AES-128 reference, `2^170/MAXDEPTH` gate estimate and
  depth points.
- Alessandro Chiesa, Peter Manohar and Nicholas Spooner,
  [*Succinct Arguments in the Quantum Random Oracle Model*](https://eprint.iacr.org/2019/834),
  Proposition 8.14 and the compressed-oracle lifting argument.
- Kai-Min Chung, Serge Fehr, Yu-Hsuan Huang and Tai-Ning Liao,
  [*On the Compressed-Oracle Technique, and Post-Quantum Security of Proofs of Sequential Work*](https://eprint.iacr.org/2020/1305),
  including Theorem 5.29 and the parallel transition bounds.
- Alessandro Chiesa, Dev Ojha and Nicholas Spooner,
  [*Fractal: Post-Quantum and Transparent Recursive Proofs from Holography*](https://eprint.iacr.org/2019/1076),
  for statement-keyed adaptive composition.
- Eli Ben-Sasson, Dan Carmon, Ulrich Haböck, Swastik Kopparty and Shubhangi
  Saraf,
  [*On Proximity Gaps for Reed-Solomon Codes*](https://eprint.iacr.org/2025/2055),
  Theorem 4.6.
- Ulrich Haböck,
  [*BaseFold in the List Decoding Regime*](https://eprint.iacr.org/2024/1571).
- Lorenzo Grassi, Dmitry Khovratovich, Katharina Koschatko, Christian
  Rechberger, Markus Schofnegger, Verena Schröppel and Zhuo Wu,
  [*Poseidon(2)b: Binary Field Versions of Poseidon/Poseidon2*](https://cic.iacr.org/p/2/4/15/pdf).
- Simon-Philipp Merz and Àlex Rodríguez García,
  [*Skipping Class: Algebraic Attacks exploiting weak matrices and operation modes of Poseidon2(b)*](https://eprint.iacr.org/2026/306),
  especially Section 3.4, Theorem 5.1, Section 6 and Appendix A.
- Enyan Li, Fukang Liu and Gaoli Wang,
  [*Beyond Linear Subspace Trails: Nonlinear Subspaces for Gröbner Basis Attacks on Poseidon/Poseidon2 and Neptune*](https://eprint.iacr.org/2026/1792),
  especially Sections 3.3, 4.1, 4.3 and Appendix B.7.
- Kyungbae Jang, Wonwoong Kim, Sejin Lim, Yeajun Kang, Yujin Yang, Hwajeong
  Seo and Ilsun You,
  [*Quantum Binary Field Multiplication with Optimized Toffoli Depth and Extension to Quantum Inversion*](https://pmc.ncbi.nlm.nih.gov/articles/PMC10055756/),
  for the reversible binary-field multiplier schedule used in the resource
  accounting.
