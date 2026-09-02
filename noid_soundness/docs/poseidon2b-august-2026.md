# August 2026 Poseidon cryptanalysis against production Poseidon2b

## Result

The August 2026 Poseidon papers were screened against the exact production
permutation and its one-permutation feed-forward compression. One new model
family can be instantiated from ePrint 2026/1792: the nonlinear subspace
construction of Li, Liu and Wang. The executable certificate now performs its
required rank check over the production `GF(2^128)` matrix and evaluates all
four relevant Macaulay models with the production round schedule.

The smallest projection reproduced from the paper's four-model comparison is

```text
log2(C_Macaulay^2) = 1022.830074998558
```

under the paper's `omega=2` semi-regular cost model. This is more expensive
than the existing `409.873818620410`-bit dedicated feed-forward projection from
ePrint 2026/306. No production parameter, certificate conclusion or security
frontier change is required.

These numbers are costs of specific published attack models. They are not
claims of 1022-bit or 409-bit security and they are not lower bounds on every
possible attack. The 2026/1792 calculation is a preimage-model projection for
the compression primitive, not a concrete collision or a valid-tree
reachability witness.

## Audited production target

The certificate imports the parameters and matrices directly from production
code:

```text
field                 GF(2^128)
state width           t = 4
rate                   r = 2
digest                 d = 2 field elements
S-box                  x^7
full rounds            RF = 8, split 4 + 4
partial rounds         RP = 58
partial-round S-boxes  s = 1
```

The relevant Merkle construction is

\[
H(a,b)=\operatorname{Tr}_2(P(a_0,a_1,b_0+IV_0,b_1+IV_1))+(a_0,a_1).
\]

The capacity tag is a fixed affine shift. The feed-forward term has degree one,
so it does not increase the highest degrees in the 2026/1792 models.

## ePrint 2026/1792

The reviewed PDF is archive version `20260824:125701`, SHA-256
`006cf8bc3b47df053d662b6552aa82fd8add2a75a152e08f9c63db73a29564cb`.

### Constraint budget and exact matrix check

Section 4.1 gives the compression-mode budget

\[
E_c=t-d=2.
\]

With one active S-box per partial round, the linear trail covers two rounds and
the nonlinear trail covers four rounds. The paper warns that generic
nonsingularity does not replace a check of the concrete internal matrix. The
certificate therefore evaluates the even-construction core from Appendix B.7.
For `E_c=2` it is the one-by-one matrix

\[
N_e=BSC A^{-1}-1,\qquad S=D-CA^{-1}B,
\]

where `A`, `B`, `C` and `D` are the blocks of the production internal matrix.
Evaluation in the production tower basis gives

```text
N_e = 0x0000000000000000000000000000be32
```

which is nonzero in `GF(2^128)`. The four-round nonlinear trail is therefore
available for this exact matrix. It covers only four of the 58 production
partial rounds. Production executes the permutation in an isomorphic flat
basis; the basis change preserves this rank result.

### Production cost projections

For each model the certificate applies the paper's finite-field degree cap,
searches every permitted trail position `tau`, constructs the exact Macaulay
matrix dimension and squares it for `omega=2`.

Let

\[
D(e)=\min(7^e,2^{128}-2).
\]

The four exact production expressions are

\[
\begin{aligned}
C_{\rm sub,lin}
&=\min_{0\le\tau\le56}
  \binom{1+4D(4+\tau)+2D(60-\tau)}{6}^{2},\\
C_{\rm sub,nonlin}
&=\min_{0\le\tau\le53}
  \binom{1+4D(4+\tau)+2D(58-\tau)+14}{8}^{2},\\
C_{\rm direct,lin}
&=\binom{1+2D(64)+2D(4)}{4}^{2},\\
C_{\rm direct,nonlin}
&=\binom{1+2D(62)+2D(5)}{4}^{2}.
\end{aligned}
\]

| Model | Best placement | Variables | `log2(C_Macaulay^2)` |
|---|---:|---:|---:|
| Forward, substitution, linear subspace | `tau=28` | 6 | 1090.060133886114 |
| Forward, substitution, nonlinear subspace | `tau=27` | 8 | 1403.209025315336 |
| Forward, no substitution, linear subspace | direct | 4 | 1022.830074998558 |
| Forward, no substitution, nonlinear subspace | direct | 4 | 1022.830074998558 |

For the width-four instance, the extra variables introduced by substitution
cost more than the longer nonlinear trail saves. The smallest attack-cost
projection in this family is therefore the no-substitution linear model, not
the new nonlinear model. All four remain weaker than the direct feed-forward
model from ePrint 2026/306.

The paper states its construction over `F_p` and reports experiments on
prime-field instances. The certificate does not copy those experimental rows.
It transfers only the algebraic construction, evaluates all field operations in
the actual `GF(2^128)`, verifies the concrete balancing rank and labels the
result as the same semi-regular Macaulay projection used by the paper.

## Other August Poseidon results

ePrint 2026/1579 constructs a constrained input family together with an MDS
matrix selected as a function of the round constants. Its own scope excludes a
fixed standardized instance. The production Poseidon2b matrices and round
constants are fixed independently in the pinned source, so the paper supplies
no witness or cost that can be transferred to this target. The reviewed PDF is
archive version `20260802:133135`, SHA-256
`5656b2df4d507397b8b2463179de5dcce36a9b235b3b738332b809f467a42f76`.

ePrint 2026/1692 introduces GSR for the ordinary Poseidon CICO-k model. A full
two-lane production output corresponds to the closest CICO-2 geometry. At
`t=4`, its new partial-round skip is `t-2k=0`. It also does not model the
production feed-forward output equations. It therefore supplies no new
production cost below the already instantiated Appendix A result of ePrint
2026/306 and is not added to the executable calculation. The reviewed PDF is
archive version `20260815:020031`, SHA-256
`d2d712449b7e179d04e44c7eb8da4bf32f37e54b8f323fb5eadcaf05807d6077`.

ePrint 2026/1760 requires an MDS matrix chosen after the round constants and a
prime field of odd characteristic. Production fixes both matrices and all round
constants together and uses characteristic two. That collision model does not
transfer to the production instance and is not part of the certificate. The
reviewed PDF is archive version `20260821:082229`, SHA-256
`2618dbf7d0af5cda7f8c12d3340f1f9fe389ef21f1892b1e5565ff2053910627`.

## Reproduce

From the repository root:

```sh
cargo run --release --locked -p noid_soundness
cargo run --release --locked -p noid_soundness -- --exact
cargo test --release --locked -p noid_soundness
```

The implementation is in
[`src/poseidon2b_cryptanalysis.rs`](../src/poseidon2b_cryptanalysis.rs). The
production field, round schedule, matrices and feed-forward mode are exercised
by release regression tests. Changing the audited profile makes the old
specialization fail.
