# Wallet Johnson refinement without a protocol change

The W65 wallet admits a tighter Johnson-range analysis at distance radius
`4/5`, with the same 65 queries and rate `1/32`. Its local query density becomes
`(1/5)^65`. This uses existing list-decoding and correlated-agreement results,
not a new beyond-Johnson theorem.

## Scope and dependencies

This note derives the finite list and field-exception bounds used by the
wallet local term of the [end-to-end certificate](category-one.md). It retains
that certificate's public-coin, typed compiler, coherent response-cost, and
fixed-Poseidon2b premises. It is not an unconditional quantum security claim.

The ingredients are Guruswami--Sudan interpolation,
[BCHKS, Theorem 4.6](https://eprint.iacr.org/2025/2055), and the additive-FFT
and skipped-commitment analysis in
[Haböck, Sections 5 and 6.2](https://eprint.iacr.org/2024/1571). They apply
in characteristic two. No prime-field capacity result is imported.

The reviewed PDFs have SHA-256 digests:

```text
BCHKS 2025/2055
8f6b42e6f75101698f0d7ff6f26d0d8776e27880b386c7932d3f8890c39df572

Haböck 2024/1571
8b851b4d8ef1c7681ddea663b06e3bc1af323db1c1610d230beec5e702d0d3cb
```

The extractor and decoder are mathematical operations, not node operations.
The supplied-candidate routines in `zk_auth_rbr.rs` remain checks, not decoder
implementations or machine-checked proofs of the source-relative knowledge
theorem. Their external-proof manifest is deliberately unchanged.

## The unchanged code family

Let `N_j = 65536 / 2^j`, `K_j = 2048 / 2^j`, and `k_j = K_j - 1`, for
`j = 0,...,7`. The additive-LCH quotient chain has eight Reed--Solomon layers
of dimension `K_j` and rate `1/32`.

The analysis works over the extension field containing the wide challenges.
At the initial source, both words and evaluation points belong to the embedded
`GF(2^128)`. A degree-`<K_j` polynomial agreeing with such a word on more than
`k_j` positions has coefficients in that subfield. Its coefficient-wise
Frobenius conjugate agrees with it on those positions, so polynomial uniqueness
makes them equal. Working over the larger field thus creates no additional
initial bank or companion candidates. Restricting to the actual affine
encoding constraints can only shorten the full Reed--Solomon list.

## At most seventeen candidates

For any received word on a layer of length `N`, put

\[
A=\left\lceil N/5\right\rceil,\qquad k=N/32-1,\qquad D=3A-1.
\]

Seek a nonzero bivariate `Q(X,Y)` with `Y` degree at most 17,
`(1,k)`-weighted degree at most `D`, and multiplicity at least three at every
received point. Multiplicity means the six Hasse coefficients of total order
less than three. Ordinary derivatives cannot replace these constraints in
characteristic two.

There are at most `6N` homogeneous linear constraints. All eighteen terms in
the following count are positive:

\[
U=\sum_{b=0}^{17}(D-kb+1)=54A-153k,
\qquad U-6N\ge\frac{3N}{160}+153>0.
\]

A nonzero interpolant exists for every received word, with no generic-rank
assumption. If `p` of degree at most `k` agrees in at least `A` positions,
`Q(X,p(X))` has degree at most `D` and at least `3A` zeros with multiplicity.
Since `D<3A`, it vanishes identically. Hence `Y-p(X)` divides `Q(X,Y)`.
Distinct candidates give distinct linear factors, so there are at most
seventeen candidates.

Linear algebra and finite-field polynomial factorization give the usual
extractor-side randomized polynomial-time interpolation-and-factorization
decoder. No exhaustive search through the field is required.

The exact production specialization is:

| Layer | N | K | Agreements | Unknowns | Constraints | Margin |
|---|---:|---:|---:|---:|---:|---:|
| 0 | 65536 | 2048 | 13108 | 394641 | 393216 | 1425 |
| 1 | 32768 | 1024 | 6554 | 197397 | 196608 | 789 |
| 2 | 16384 | 512 | 3277 | 98775 | 98304 | 471 |
| 3 | 8192 | 256 | 1639 | 49491 | 49152 | 339 |
| 4 | 4096 | 128 | 820 | 24849 | 24576 | 273 |
| 5 | 2048 | 64 | 410 | 12501 | 12288 | 213 |
| 6 | 1024 | 32 | 205 | 6327 | 6144 | 183 |
| 7 | 512 | 16 | 103 | 3267 | 3072 | 195 |

`selected_zk_auth_johnson_list_size_ledger` checks these integer dimensions.
The old multiplicity-one, seven-candidate certificate does not work at the
new radius and is not reused.

## Correlated agreement and grouped folds

Set `gamma=4/5` and `rho_j=k_j/N_j`. The Johnson condition holds since
`rho_j < 1/32 < (1/5)^2`. Proximity multiplicity `m=8` satisfies

\[
(m+1)\sqrt{\rho_j}\le m(1-\gamma),
\]

as certified by `25 * 81 * k_j <= 64 * N_j` on every layer. The proximity
multiplicity eight and list-interpolation multiplicity three serve different
arguments.

Theorem 4.6 bounds exceptions for all sufficiently large agreement sets and
all proximate outputs of an affine line, not just a candidate fixed in advance.
A weighted agreement set of mass at least `1/5`, with weights in `[0,1]`,
also has ordinary density at least `1/5`. The theorem preserves that same
set and its weight when tracing a nonexceptional fold backward.

The inverse additive-LCH butterfly gives two words on the child domain.
Correlated origins on the same child set reconstruct a parent polynomial
on its two-point fibers, preserving the pulled-back consistency weight.
At the source, write `(1-z)B + z C = B + z(B+C)` for the wide field challenge
`z` to apply the same affine-line theorem to bank and companion jointly.
This field challenge is distinct from the real-valued distance radius.

Expand the production 3+4 grouped folds into deterministic intermediate words.
No prover message is inserted between the scalar challenges of a group.
Conditioning on each scalar prefix and unioning its exceptional set covers
the atomic vector response. This is the skipped-commitment construction in
Haböck's Section 5.4, not an assumption that independently decoded layers
share a candidate.

For `h=m+1/2`, the degree-one exceptional-set envelope is

\[
E_j\le N_j\frac{2h^5+3h\gamma\rho_j}{3\rho_j^{3/2}}
+\frac{h}{\sqrt{\rho_j}}.
\]

Replace each square root in the denominators by a certified Q48 lower bound
and round upward:

| Affine line | Length | Exceptional field elements, at most |
|---|---:|---:|
| Source blend | 65536 | 351179818871 |
| Fold 0 | 32768 | 175718656177 |
| Fold 1 | 16384 | 87988311082 |
| Fold 2 | 8192 | 44123612929 |
| Fold 3 | 4096 | 22192220275 |
| Fold 4 | 2048 | 11228467832 |
| Fold 5 | 1024 | 5750607766 |
| Fold 6 | 512 | 3020259892 |
| Sum | | 701201954824 |

The sum is conservative for any individual verifier move. Restricting to
the trace-one challenge support preserves the exceptional-set cardinality,
so the probability denominator is `2^255`.

## Fixed origins and algebraic continuations

The bank and companion oracles are fixed together before Owner challenges.
Their initial lists contain at most seventeen candidates each. Every
continuation restored through nonexceptional folds originates in one of
these at most `17^2=289` pairs.

For a fixed initial pair and scalar prefix, the blended polynomial and all
folded descendants are determined. A consistent mid candidate is not an
independent choice. The algebraic union therefore uses initial pairs and
does not condition on a future decoder list.

The supplied-list checker can enumerate up to `17^3=4913` triples to locate
a consistent bank/companion/mid combination. This is extractor work, not a
probability multiplier for independent future candidates.

The existing scalar algebraic inventory contributes 156 roots per pair.
Also charge the first seven variables of the fixed upper-link multilinear
to the 3+4 fold groups. Partial substitution makes a nonzero multilinear
vanish identically only on a Schwartz--Zippel exceptional set, with conditional
density at most the number of substituted variables divided by `2^255`.
The eighth variable is already charged by `BetaTail`.

Unioning these continuations over all fixed initial pairs gives

\[
289(156+7)=47107.
\]

This allows choosing a surviving candidate after seeing a challenge.
Algebraic and proximity failures sharing a challenge are added, never
multiplied. The conservative field numerator is

\[
701201954824+47107=701202001931.
\]

## Query term and certificate

In the source-relative restoration argument, a prefix is bad when it has no
restorable Auth-valid witness satisfying its retained algebraic claims and
consistency measure. Backward propagation repairs such a prefix only through
a counted proximity exception or algebraic root. Selecting a restored bank
still requires exact Auth/address validation.

Outside those exceptions, a bad final transcript has accepting query positions
of density at most `1/5`. The 65 independent queries are still sampled with
replacement. Thus

\[
\kappa_{W,q}=5^{-65},\qquad
\kappa_{W,f}=\frac{701202001931}{2^{255}},\qquad
\kappa_W=\max\{\kappa_{W,q},\kappa_{W,f}\}.
\]

The maximum is the conservative generalized round-by-round bound over
distinct verifier moves. The lower-level conditional union diagnostic also
retains their sum. Neither diagnostic is an unconditional PQ bit count.

The query term dominates, with descriptive exponent improving from
`136.052111285446` to `150.925326167679`. The field term stays below `2^-215`.
No grinding credit is added.

The end-to-end effect is substantially smaller:

| Quantity | Previous analysis | Refined analysis |
|---|---:|---:|
| Classical FS-FRI whole bits | 127 | 127 |
| Sequential ideal-QROM boundary bits | 64.707407428576 | 64.707407428576 |
| Limiting Category 1 event | wallet.query | history.query |
| Main-term gate-depth bits | 173.273866314232 | 173.391078499301 |
| Complete ideal Category 1 envelope, upper bound | 0.053364140323608411 | 0.049330348213215253 |

History already determines the sequential bound and becomes the limiting
resource event. The main-term resource floor rises by approximately
`0.117212185069` bits, not by the wallet's approximately 14.87-bit local gain.
The assessment remains Category 1 under its existing premises.

Reducing the query count is a different task. It would change proof and
verifier geometry and is not implied by this analysis.

## Reproduction

```sh
cargo run --release --locked -p noid_soundness
cargo run --release --locked -p noid_soundness -- --exact
cargo test --release --locked -p noid_gkr -p noid_soundness
```

Tests pin all eight interpolation margins and exceptional counts, reject
multiplicity four at radius `4/5`, check the inclusive integer distance
boundary, and compare both certificates with identical production geometry
and compiler costs.
