# Scheduled v2 and matrix-retirement accounting

The default calculator remains the published legacy W65/H133 calculation.
The separate `noid_v2_soundness` tool reads a pinned joint-bank recipe and two
independently pinned legacy preprocessing keys. It inventories the actual PCS
instances and composes their local bounds with the legacy ancestry. It changes
neither a proof parameter nor consensus.

This is a conditional extension of the [existing all-root analysis](category-one.md).
It retains that document's ideal compiler, fixed-Poseidon2b delta, response-price
and scalar gate-charge premises. It also requires honest public preprocessing:
the release keys must be recomputed from the authenticated canonical matrices.
A matrix digest attached to arbitrary commitment roots does not meet this
requirement. The CLI checks both keys against the supplied legacy bank and
independent pins; artifact preparation performs the full matrix authentication.
The [October 2026 correspondence work](v2-correspondence-2026-10.md) independently
reconstructed both complete release keys and establishes the scoped request,
selected-parent and snapshot bindings, together with the deterministic v2
all-root specialization under the existing local and compiler hypotheses.

## Joint history relation

The source supplies each class's PCS geometry through `V2Config::pcs_params`.
The two current outer dimensions are 23 and 24, with position-codeword logs 20
and 21. Both use the same rate-one-quarter C1/BaseFold verifier and 133 queries.
The runtime recipe binds the contract interpreter, class resource limits and
fork schedule. These values are printed alongside the bank digest.

The integer interpreter contributes deterministic R1CS constraints. It does
not introduce an independent Fiat–Shamir protocol per contract. The existing
127-root scalar envelope still covers the block and parent proof protocols:
the public-I/O compression has eight coordinates; a carried matrix point has
at most 49 coordinates; zerocheck's interpolation bound remains 127. The
source-linked joint sidecar remains nine groups over four Poseidon lanes.
The candidate's two parent arms do not enlarge these scalar degrees: the
selected arm and exact inactive carry are constrained in the relation.

The calculator evaluates the source-derived joint geometries and keeps all
legacy wallet/History events. A new bank does not remove the ancestry's error
events from the from-genesis statement.

## Sparse evaluation reduction

The construction uses public preprocessing and read-only memory checks in the
style of [SPARK, section 7 of Spartan](https://iacr.org/archive/crypto2020/12171304/12171304.pdf).
That paper supplies the sparse-evaluation construction; the bounds below
specialize the repository's characteristic-two implementation and its explicit
initial-list accounting. The paper's complete zkSNARK security statement is
not substituted for the C1/BaseFold analysis.

Each preprocessing key authenticates seven fixed columns. Four additional
columns, committed before reduction challenges, hold the two limbs of the
row and column lookup values. The source exposes all eleven opening parameter
sets and the dynamic-column count. Accounting rejects a changed count or rate.

For an entry list padded to `n` and a row-address domain of size `r`, both
memory equations have at most `D = n + r` factors on either side; the column
address domain is no larger. A tuple fingerprint is

```text
offset + gamma^2 * address + gamma * value + tag.
```

The tags are authenticated unique bit strings describing fixed access chains.
They are not counters advanced by field addition. Correct multiset equalities
therefore force every lookup to equal the public equality-table value at its
address. The coefficient/lookup inner product is then the claimed matrix
evaluation.

For a fixed incorrect lookup assignment, unequal multisets yield a nonzero
polynomial in `gamma, offset`: monic linear factors in `offset` identify the
tuple polynomials. Its total degree is at most `2D`. Applying the root bound
over the challenge support of size `2^255`, and conservatively covering both
row and column equations, gives a `4D` root envelope. The same envelope
dominates the degree-three sumchecks and product-tree reductions.

The static columns are honestly preprocessed Reed–Solomon codewords. Their
initial proximity list contains only that fixed polynomial: a different
rate-one-quarter polynomial cannot agree with it on the required majority of
positions. The four prover-selected words can each have a list of size at
most `L`. Their candidate tuples must therefore be bounded by **`L^4`**, not
by `L`. Lists are fixed by initial commitments before the reduction challenges.
This permits candidate switching rather than assuming an early chosen tuple.

For every loaded key the executable computes:

```text
query term       = ((m + 1) / (2m))^133
proximity term   = maximum BCHKS layer envelope over all eleven columns
PCS scalar term  = 127 * L / 2^255
reduction term   = 4 * (n + r) * L^4 / 2^255
local RBR bound  = maximum of these four terms
```

`L` is the maximum initial-list envelope over the actual columns. The fixed
choice `m = 100000` is conservative; no optimality is claimed. All quantities
are exact integers or rationals. The field terms explicitly use the trace-one
C1 challenge support, not a uniform 256-bit field challenge.

Every returned leaf value is authenticated by a separately replayed C1 PCS
opening. The reduction channel binds the preprocessing-key digest, complete
matrix point/value, request context and four dynamic roots. Column labels,
indices and roots are observed before the respective opening. These bindings
prevent replacing a column, statement or request while retaining its proof.

## Composition and resource prices

The typed graph now contains wallet, legacy History, v2 History and sparse
evaluation roots. A v2 ancestry edge still decreases block height. At its
boundary, the authenticated origin reaches the legacy terminal and its matrix
evaluation obligations. Sparse roots have only finitely many nonrecursive
opening children. Under the same all-root extraction/binding premises, this
extends the terminating deterministic worklist to genesis; the certificate
does not introduce an authoritative checkpoint.

The sequential calculation uses the maximum local RBR bound over this entire
inventory and applies the existing exact ideal-QROM lifting once. The resource
calculation keeps each typed failure event and applies the existing batch
charge calculation to the largest density/price ratio. It does not multiply
the result by chain height or discard the old classes.

Different sparse columns have different position domains. Their query-response
cost is conservatively the **minimum** squeeze cost over the actual columns,
not the cost of the largest column. Scalar events use the existing scalar
price. Finite extraction and global collision terms are counted once under
the same total query/resource budget. Descriptive decimal logarithms do not
participate in the inequalities.

The [source-linked lemmas and conditional composition proof](v2-correspondence-2026-10.md)
make the current v2 correspondence obligations explicit. The local extraction,
typed ideal-compiler/lifting, fixed-Poseidon2b and response-price conditions
remain as stated. Performance tests, malformed-proof tests and the calculator
are complementary evidence; none replaces a mathematical argument.
The tool's output identifies the precise bank, keys, limits, geometries,
candidate counts, exact probabilities and declared prices it evaluates.

## Reproduce

```sh
cargo build --release --locked -p bench_prover --bin noid_v2_soundness
target/release/noid_v2_soundness \
  LEGACY_METADATA LEGACY_METADATA_PIN V2_METADATA V2_BANK_PIN \
  CLASS_0_KEY CLASS_0_KEY_PIN CLASS_1_KEY CLASS_1_KEY_PIN
```

Source: [inventory and composition](../src/v2.rs),
[sparse verifier](../../noid_ivc_core/src/matrix_claim/sparse_c1.rs),
[public preprocessing](../../noid_ivc_core/src/matrix_claim/sparse_c1/preprocess.rs),
[joint relation](../../noid_recursive/src/acceptance/history_step/v2/banked/assembly.rs).
