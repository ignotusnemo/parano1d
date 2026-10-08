// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2026 Paranoid Zero.

//! Experimental sparse matrix evaluation using the existing C1/BaseFold PCS.
//!
//! Public preprocessing binds row/column addresses, coefficients and immutable
//! access-chain tags to structurally authenticated [A; B] rows. An evaluation
//! proves the sparse inner product and two read-only memory checks. Product
//! trees reduce the memory checks to PCS openings; the verifier needs only
//! the small preprocessing key, the claim and the proof, never matrix rows.
//!
//! This is not a deployed protocol, a terminal codec or a fork certificate.
//! No mainnet preprocessing key is pinned. The sequential reference prover
//! has explicit resource admission and has not been qualified at release size.
//! The construction follows the public-preprocessing approach of SPARK:
//! <https://iacr.org/archive/crypto2020/12171304/12171304.pdf>, section 7.
//! Tags here are fixed unique bit strings, not counters incremented in a
//! characteristic-two field. Soundness/resource composition still needs review.

use crate::challenger::{Challenger, FsLaneChallenger};
use crate::field::{F128, F256};
use crate::matrix_claim::c1::C1MatrixAccClaim;
use crate::pcs::{
    self, C1BaseFoldProof, C1QuirkyDirectClaim, C1QuirkyDirectClaimRef, Commitment, PcsParams,
};
use crate::proof::FieldShape;
use crate::zerocheck::field_c1::build_eq_table;
use preprocess::{index_mle, raw, write_tag_mle};
use sumcheck::{
    CubicProof, ProductProof, eq, prove_cubic_from_fn, prove_product, verify_cubic, verify_product,
};

mod preprocess;
mod sumcheck;
mod wire;
mod workspace;
pub use preprocess::{
    SparseEvaluationBudget, SparseEvaluationGeometry, SparseMatrixEvaluationKey, SparseMatrixProver,
};
pub use wire::{MAX_SPARSE_EVALUATION_PROOF_BYTES, SPARSE_EVALUATION_KEY_BYTES};

const ROW: usize = 0;
const COL: usize = 1;
const VALUE: usize = 2;
const READ_ROW: usize = 3;
const READ_COL: usize = 4;
const FINAL_ROW: usize = 5;
const FINAL_COL: usize = 6;
const STATIC_COLUMNS: usize = 7;
const ALL_COLUMNS: usize = 11;
const INIT: usize = 0;
const READ: usize = 1;
const WRITE: usize = 2;
const AUDIT: usize = 3;
const EXTENSION: F256 = F256::new(F128::ZERO, F128::ONE);

#[derive(Clone, Debug, PartialEq, Eq)]
struct LookupProof {
    products: [F256; 4],
    trees: [ProductProof; 4],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Reduction {
    dynamic_roots: [[u8; 32]; 4],
    inner_product: CubicProof,
    lookups: [LookupProof; 2],
}

/// Opaque experimental proof with bounded canonical transport. Decoding alone
/// grants no verification capability or terminal conversion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMatrixEvaluationProof {
    reduction: Reduction,
    values: [Vec<F256>; ALL_COLUMNS],
    openings: [C1BaseFoldProof; ALL_COLUMNS],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Budget,
    MatrixIdentity,
    Claim,
    ProofShape,
    Wire,
    Workspace(String),
    Algebra,
    Opening(pcs::VerifyError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Shape => f.write_str("invalid sparse evaluation geometry"),
            Self::Budget => {
                f.write_str("sparse evaluation exceeds the caller's resource allowance")
            }
            Self::MatrixIdentity => f.write_str("sparse evaluation matrix identity mismatch"),
            Self::Claim => f.write_str("invalid sparse matrix claim"),
            Self::ProofShape => f.write_str("invalid sparse evaluation proof shape"),
            Self::Wire => f.write_str("invalid bounded sparse evaluation encoding"),
            Self::Workspace(error) => write!(f, "sparse prover workspace: {error}"),
            Self::Algebra => f.write_str("sparse evaluation algebraic check failed"),
            Self::Opening(error) => write!(f, "sparse evaluation PCS opening: {error:?}"),
        }
    }
}
impl std::error::Error for Error {}

fn params(log_len: usize) -> PcsParams {
    // The rate-1/4 UDR theorem requires at least eight position messages.
    // Tiny logical columns are zero-extended, with extra opening coords zero.
    let log_len = log_len.max(3);
    PcsParams {
        m: log_len + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 5.min(log_len - 3),
        profile: Default::default(),
    }
}

fn pad_column(values: &mut Vec<F128>) {
    values.resize(values.len().max(8), F128::ZERO);
}

fn channel(
    key: &SparseMatrixEvaluationKey,
    context: [u8; 32],
    claim: &C1MatrixAccClaim,
    roots: &[[u8; 32]; 4],
) -> FsLaneChallenger {
    let mut channel = FsLaneChallenger::new_c1(b"NOID/SPARSE-MATRIX-EVAL/C1/V1");
    channel.observe_bytes(&key.digest());
    channel.observe_bytes(&context);
    channel.observe_f256_slice(&claim.point);
    channel.observe_f256(claim.value);
    for root in roots {
        channel.observe_bytes(root);
    }
    channel
}

fn claim_shape(key: &SparseMatrixEvaluationKey, claim: &C1MatrixAccClaim) -> Result<(), Error> {
    if claim.point.len() != 2 * key.shape.k_log + 1 {
        return Err(Error::Claim);
    }
    Ok(())
}

fn base_evaluation(values: &[F128], point: &[F256]) -> F256 {
    assert_eq!(values.len(), 1usize << point.len());
    let weights = build_eq_table(point);
    values
        .iter()
        .zip(weights)
        .fold(F256::ZERO, |out, (&v, weight)| out + weight.scale_base(v))
}

fn dynamic_column(
    length: usize,
    lookup: &impl Fn(usize, usize) -> F256,
    column: usize,
) -> Vec<F128> {
    let index = column - STATIC_COLUMNS;
    (0..length)
        .map(|row| {
            let value = lookup(index / 2, row);
            if index % 2 == 0 { value.lo } else { value.hi }
        })
        .collect()
}

fn fingerprint(address: F256, value: F256, tag: F256, gamma: F256, offset: F256) -> F256 {
    offset + gamma.square() * address + gamma * value + tag
}

impl SparseMatrixProver {
    pub fn prove(
        &self,
        context: [u8; 32],
        claim: &C1MatrixAccClaim,
        budget: SparseEvaluationBudget,
    ) -> Result<SparseMatrixEvaluationProof, Error> {
        self.prove_with_workspace(context, claim, budget, None)
    }

    /// Use an anonymous disk-backed PCS codeword to reduce resident memory
    /// during openings. This does not change the proof, release key or wire
    /// format. Resource admission still applies; callers must separately allow
    /// disk space for one full codeword and bound the worker's memory usage.
    pub fn prove_with_disk_workspace(
        &self,
        context: [u8; 32],
        claim: &C1MatrixAccClaim,
        budget: SparseEvaluationBudget,
        directory: &std::path::Path,
    ) -> Result<SparseMatrixEvaluationProof, Error> {
        self.prove_with_workspace(context, claim, budget, Some(directory))
    }

    fn prove_with_workspace(
        &self,
        context: [u8; 32],
        claim: &C1MatrixAccClaim,
        budget: SparseEvaluationBudget,
        directory: Option<&std::path::Path>,
    ) -> Result<SparseMatrixEvaluationProof, Error> {
        claim_shape(&self.key, claim)?;
        self.key.geometry.admit(budget)?;
        if directory.is_some() {
            crate::scratch::clear();
        }
        // Repeated matrix addresses need repeated reads, not two additional
        // extension-valued vectors as long as the padded nonzero list.
        let equality = [
            build_eq_table(&claim.point[..self.key.shape.k_log + 1]),
            build_eq_table(&claim.point[self.key.shape.k_log + 1..]),
        ];
        self.prove_lookups(
            context,
            claim,
            budget,
            &|side, index| equality[side][self.indices[index][side] as usize],
            directory,
        )
    }

    fn prove_lookups(
        &self,
        context: [u8; 32],
        claim: &C1MatrixAccClaim,
        budget: SparseEvaluationBudget,
        lookup: &impl Fn(usize, usize) -> F256,
        directory: Option<&std::path::Path>,
    ) -> Result<SparseMatrixEvaluationProof, Error> {
        self.key.geometry.admit(budget)?;
        let actual =
            self.coefficients
                .iter()
                .enumerate()
                .fold(F256::ZERO, |out, (index, &coefficient)| {
                    out + (lookup(0, index) * lookup(1, index)).scale_base(coefficient)
                });
        if actual != claim.value {
            return Err(Error::Claim);
        }
        let dynamic_roots = std::array::from_fn(|index| {
            let mut values = dynamic_column(self.indices.len(), lookup, STATIC_COLUMNS + index);
            pad_column(&mut values);
            pcs::commit(&values, &params(self.key.geometry.entry_log()))
                .0
                .root
        });
        if directory.is_some() {
            crate::scratch::clear();
        }
        let mut transcript = channel(&self.key, context, claim, &dynamic_roots);
        let (inner_product, _) = prove_cubic_from_fn(
            self.indices.len(),
            |index| {
                [
                    F256::from_base(self.coefficients[index]),
                    lookup(0, index),
                    lookup(1, index),
                ]
            },
            claim.value,
            &mut transcript,
        );
        let gamma = transcript.sample_f256();
        let offset = transcript.sample_f256();
        let products: [[F256; 4]; 2] = std::array::from_fn(|side| {
            std::array::from_fn(|kind| {
                self.lookup_leaves(side, kind, claim, lookup, gamma, offset)
                    .into_iter()
                    .fold(F256::ONE, |out, item| out * item)
            })
        });
        for side in &products {
            transcript.observe_f256_slice(side);
        }
        let lookups = std::array::from_fn(|side| LookupProof {
            products: products[side],
            trees: std::array::from_fn(|kind| {
                let leaves = self.lookup_leaves(side, kind, claim, lookup, gamma, offset);
                prove_product(leaves, &mut transcript).0
            }),
        });
        let reduction = Reduction {
            dynamic_roots,
            inner_product,
            lookups,
        };
        // Replay to construct exactly the verifier's opening plan. This also
        // prevents an honest API call from packaging an inconsistent lookup.
        let (plan, mut replay) = reduce(&self.key, context, claim, &reduction)?;
        debug_assert_eq!(transcript.sample_f256(), replay.clone().sample_f256());
        let values = std::array::from_fn(|column| {
            let table = if column < STATIC_COLUMNS {
                self.static_column(column)
            } else {
                dynamic_column(self.indices.len(), lookup, column)
            };
            plan.points[column]
                .iter()
                .map(|point| base_evaluation(&table, point))
                .collect()
        });
        plan.check(&values)?;
        let mut openings = Vec::with_capacity(ALL_COLUMNS);
        for column in 0..ALL_COLUMNS {
            let mut table = if column < STATIC_COLUMNS {
                self.static_column(column)
            } else {
                dynamic_column(self.indices.len(), lookup, column)
            };
            pad_column(&mut table);
            let (commitment, mut data) = pcs::commit(&table, &params(self.key.column_log(column)));
            let expected_root = if column < STATIC_COLUMNS {
                self.key.roots[column]
            } else {
                dynamic_roots[column - STATIC_COLUMNS]
            };
            if commitment.root != expected_root {
                return Err(Error::MatrixIdentity);
            }
            let claims = plan.claims(column, &values);
            observe_opening_column(column, &commitment.root, &mut replay);
            openings.push(if let Some(directory) = directory {
                let codeword =
                    workspace::DiskCodeword::spill(std::mem::take(&mut data.codeword), directory)?;
                crate::scratch::clear();
                pcs::open_batch_quirky_direct_c1_slices(
                    &table,
                    codeword.values(),
                    &data.merkle_tree,
                    &commitment,
                    &claims,
                    &mut replay,
                )
            } else {
                pcs::open_batch_quirky_direct_c1(&table, &data, &commitment, &claims, &mut replay)
            });
        }
        Ok(SparseMatrixEvaluationProof {
            reduction,
            values,
            openings: openings.try_into().expect("fixed column count"),
        })
    }

    fn lookup_leaves(
        &self,
        side: usize,
        kind: usize,
        claim: &C1MatrixAccClaim,
        lookup: &impl Fn(usize, usize) -> F256,
        gamma: F256,
        offset: F256,
    ) -> Vec<F256> {
        if kind == READ || kind == WRITE {
            self.indices
                .iter()
                .enumerate()
                .map(|(index, entry)| {
                    let tag = if kind == READ {
                        entry[side + 2]
                    } else {
                        (self.key.geometry.padded_entries + index) as u32
                    };
                    fingerprint(
                        F256::from_base(raw(entry[side])),
                        lookup(side, index),
                        F256::from_base(raw(tag)),
                        gamma,
                        offset,
                    )
                })
                .collect()
        } else {
            let point = if side == ROW {
                &claim.point[..self.key.shape.k_log + 1]
            } else {
                &claim.point[self.key.shape.k_log + 1..]
            };
            build_eq_table(point)
                .into_iter()
                .enumerate()
                .map(|(address, value)| {
                    let tag = if kind == INIT {
                        0
                    } else {
                        self.final_tags[side][address]
                    };
                    fingerprint(
                        F256::from_base(raw(address as u32)),
                        value,
                        F256::from_base(raw(tag)),
                        gamma,
                        offset,
                    )
                })
                .collect()
        }
    }
}

impl SparseMatrixEvaluationKey {
    /// Verify an evaluation with this authenticated preprocessing key. The
    /// request context, complete point and value are bound before challenges.
    /// Success only proves this matrix evaluation, not a HistoryStep or fork.
    pub fn verify(
        &self,
        context: [u8; 32],
        claim: &C1MatrixAccClaim,
        proof: &SparseMatrixEvaluationProof,
    ) -> Result<(), Error> {
        let (plan, mut transcript) = reduce(self, context, claim, &proof.reduction)?;
        plan.check(&proof.values)?;
        for column in 0..ALL_COLUMNS {
            let commitment = Commitment {
                root: if column < STATIC_COLUMNS {
                    self.roots[column]
                } else {
                    proof.reduction.dynamic_roots[column - STATIC_COLUMNS]
                },
                params: params(self.column_log(column)),
            };
            let claims = plan.claims(column, &proof.values);
            let refs: Vec<_> = claims
                .iter()
                .map(|claim| C1QuirkyDirectClaimRef {
                    z_skip: claim.z_skip,
                    k_skip: claim.k_skip,
                    x_rest: &claim.x_rest,
                    value: claim.value,
                })
                .collect();
            observe_opening_column(column, &commitment.root, &mut transcript);
            pcs::verify_opening_batch_quirky_direct_c1(
                &commitment,
                &refs,
                &proof.openings[column],
                &mut transcript,
            )
            .map_err(Error::Opening)?;
        }
        Ok(())
    }
}

fn observe_opening_column(column: usize, root: &[u8; 32], transcript: &mut impl Challenger) {
    transcript.observe_label(b"sparse-c1-column-opening-v1");
    transcript.observe_bytes(&(column as u64).to_le_bytes());
    transcript.observe_bytes(root);
}

// Each term names one PCS evaluation and its linear coefficient. In
// particular, a wide polynomial evaluation is E_lo(p) + X * E_hi(p); it is
// NOT obtained by splitting the coordinates of the wide value at p.
struct Term {
    column: usize,
    opening: usize,
    coefficient: F256,
}
struct Equation {
    terms: Vec<Term>,
    expected: F256,
}
struct OpeningPlan {
    points: [Vec<Vec<F256>>; ALL_COLUMNS],
    equations: Vec<Equation>,
}

impl OpeningPlan {
    fn new() -> Self {
        Self {
            points: std::array::from_fn(|_| Vec::new()),
            equations: Vec::new(),
        }
    }
    fn term(&mut self, column: usize, point: &[F256], coefficient: F256) -> Term {
        let opening = self.points[column].len();
        self.points[column].push(point.to_vec());
        Term {
            column,
            opening,
            coefficient,
        }
    }
    fn wide_terms(&mut self, side: usize, point: &[F256], coefficient: F256) -> Vec<Term> {
        vec![
            self.term(STATIC_COLUMNS + 2 * side, point, coefficient),
            self.term(
                STATIC_COLUMNS + 2 * side + 1,
                point,
                coefficient * EXTENSION,
            ),
        ]
    }
    fn scalar(&mut self, column: usize, point: &[F256], expected: F256) {
        let term = self.term(column, point, F256::ONE);
        self.equations.push(Equation {
            terms: vec![term],
            expected,
        });
    }
    fn check(&self, values: &[Vec<F256>; ALL_COLUMNS]) -> Result<(), Error> {
        if self
            .points
            .iter()
            .zip(values)
            .any(|(points, column)| points.len() != column.len())
        {
            return Err(Error::ProofShape);
        }
        for equation in &self.equations {
            let actual = equation.terms.iter().fold(F256::ZERO, |out, term| {
                out + term.coefficient * values[term.column][term.opening]
            });
            if actual != equation.expected {
                return Err(Error::Algebra);
            }
        }
        Ok(())
    }
    fn claims(&self, column: usize, values: &[Vec<F256>; ALL_COLUMNS]) -> Vec<C1QuirkyDirectClaim> {
        self.points[column]
            .iter()
            .zip(&values[column])
            .map(|(point, &value)| {
                let mut point = point.clone();
                point.resize(point.len().max(3), F256::ZERO);
                C1QuirkyDirectClaim {
                    z_skip: F256::ZERO,
                    k_skip: 0,
                    x_rest: point,
                    value,
                }
            })
            .collect()
    }
}

fn reduce(
    key: &SparseMatrixEvaluationKey,
    context: [u8; 32],
    claim: &C1MatrixAccClaim,
    proof: &Reduction,
) -> Result<(OpeningPlan, FsLaneChallenger), Error> {
    claim_shape(key, claim)?;
    let mut transcript = channel(key, context, claim, &proof.dynamic_roots);
    let point = verify_cubic(
        key.geometry.entry_log(),
        claim.value,
        &proof.inner_product,
        &mut transcript,
    )?;
    let mut plan = OpeningPlan::new();
    plan.scalar(VALUE, &point, proof.inner_product.values[0]);
    for side in 0..2 {
        let terms = plan.wide_terms(side, &point, F256::ONE);
        plan.equations.push(Equation {
            terms,
            expected: proof.inner_product.values[side + 1],
        });
    }
    let gamma = transcript.sample_f256();
    let offset = transcript.sample_f256();
    for lookup in &proof.lookups {
        transcript.observe_f256_slice(&lookup.products);
        if lookup.products[INIT] * lookup.products[WRITE]
            != lookup.products[READ] * lookup.products[AUDIT]
        {
            return Err(Error::Algebra);
        }
    }
    for (side, lookup) in proof.lookups.iter().enumerate() {
        let query = if side == ROW {
            &claim.point[..key.shape.k_log + 1]
        } else {
            &claim.point[key.shape.k_log + 1..]
        };
        for kind in 0..4 {
            let log_len = if kind == INIT || kind == AUDIT {
                query.len()
            } else {
                key.geometry.entry_log()
            };
            let (point, value) = verify_product(
                log_len,
                lookup.products[kind],
                &lookup.trees[kind],
                &mut transcript,
            )?;
            if kind == INIT || kind == AUDIT {
                let transparent = fingerprint(
                    index_mle(&point),
                    eq(query, &point),
                    F256::ZERO,
                    gamma,
                    offset,
                );
                if kind == INIT {
                    if transparent != value {
                        return Err(Error::Algebra);
                    }
                } else {
                    plan.scalar(FINAL_ROW + side, &point, value + transparent);
                }
            } else {
                let mut terms = vec![plan.term(side, &point, gamma.square())];
                terms.extend(plan.wide_terms(side, &point, gamma));
                let mut expected = value + offset;
                if kind == READ {
                    terms.push(plan.term(READ_ROW + side, &point, F256::ONE));
                } else {
                    expected += write_tag_mle(&point);
                }
                plan.equations.push(Equation { terms, expected });
            }
        }
    }
    Ok((plan, transcript))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod correspondence_audit;
