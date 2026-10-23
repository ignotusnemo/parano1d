//! Genuine GF(2^256) prefix and suffix protocols for the fused History
//! sidecar.
//!
//! The fixed schedules and committed witness columns are unchanged. Only the
//! algebraic protocol is widened: challenges, relation coefficients,
//! sumcheck messages, walk groups, shift reductions, and terminal openings
//! are all extension-field values.

use noid_ivc_core::challenger::Challenger;
use noid_ivc_core::deep_chain::ff_merkle::FfMerkleFamilyRefs;
use noid_ivc_core::deep_chain::flat_mds;
use noid_ivc_core::deep_chain::relations::c1::{
    claimed_refs, prove_column_relation, prove_shift_discharge, prove_shift_discharge_pow2,
    verify_column_relation, verify_shift_discharge, verify_shift_discharge_pow2,
    C1ColumnRelationProof, C1RelationTerm, C1ShiftDischargeProof,
};
use noid_ivc_core::deep_chain::relations::{ColRef, FixedPattern, RelationColumns};
use noid_ivc_core::deep_chain::schedule::{DuplexFamilyRefs, MerkleFamilyRefs};
use noid_ivc_core::deep_chain::source_tree::SourceTreeRefs;
use noid_ivc_core::field::{F128, F256};
use noid_poseidon2b::native::permutation::STATE_SIZE;
use serde::{Deserialize, Serialize};

use super::paired_merkle_update::PairedMerkleUpdateRefs;
use super::region_source_binding::{
    DuplexUnionVerifyError, MerkleProtocolFamily, MerkleUnionVerifyError, SpineUnionSpec,
    SplitDuplexTailRefs, WalkAUnionVerifyError,
};
use noid_ivc_core::deep_chain::c1::C1LaneClaimGroup;

mod trace_impl;
pub(crate) use trace_impl::*;

fn c1_carry_selection_terms(columns: &[usize; STATE_SIZE], beta: F256) -> Vec<C1RelationTerm> {
    let mut terms = Vec::with_capacity(2 * STATE_SIZE);
    let mut power = F256::ONE;
    for lane in 0..STATE_SIZE {
        power *= beta;
        terms.push(C1RelationTerm {
            coeff: power,
            factors: vec![ColRef::Committed(columns[lane])],
        });
        terms.push(C1RelationTerm {
            coeff: power,
            factors: vec![ColRef::Internal(lane)],
        });
    }
    terms
}

fn c1_mds_weights(alpha: F256) -> [F256; STATE_SIZE] {
    let mut powers = [F256::ZERO; STATE_SIZE];
    let mut power = F256::ONE;
    for value in &mut powers {
        power *= alpha;
        *value = power;
    }
    let mds = flat_mds(true);
    std::array::from_fn(|column| {
        (0..STATE_SIZE).fold(F256::ZERO, |sum, row| {
            sum + powers[row].scale_base(mds[row][column])
        })
    })
}

fn push_terms(
    output: &mut Vec<C1RelationTerm>,
    coefficient: F256,
    factors: impl IntoIterator<Item = Vec<ColRef>>,
) {
    output.extend(factors.into_iter().map(|factors| C1RelationTerm {
        coeff: coefficient,
        factors,
    }));
}

fn c1_merkle_zero_terms(families: &[MerkleProtocolFamily], lambda: F256) -> Vec<C1RelationTerm> {
    let mut terms = Vec::new();
    for family in families {
        if let MerkleProtocolFamily::TwoPermutation { refs, .. } = family {
            push_terms(
                &mut terms,
                F256::ONE,
                [
                    vec![
                        ColRef::Fixed(refs.even),
                        ColRef::Committed(refs.d),
                        ColRef::Committed(refs.d),
                    ],
                    vec![ColRef::Fixed(refs.even), ColRef::Committed(refs.d)],
                ],
            );
        }
    }
    let weights = [lambda, lambda.square()];
    for family in families {
        if let MerkleProtocolFamily::FeedForward { refs, .. } = family {
            for (lane, &weight) in weights.iter().enumerate() {
                let nonstart = ColRef::Fixed(refs.nodens);
                let child = ColRef::Committed(refs.cr[lane]);
                let child_shift = ColRef::CommittedShift(refs.cr[lane]);
                let sibling_shift = ColRef::CommittedShift(refs.sib[lane]);
                let direction_shift = ColRef::CommittedShift(refs.d);
                let carry_shift = ColRef::CommittedShift(refs.c[lane]);
                push_terms(
                    &mut terms,
                    weight,
                    [
                        vec![nonstart, child],
                        vec![nonstart, carry_shift],
                        vec![nonstart, child_shift],
                        vec![nonstart, direction_shift, child_shift],
                        vec![nonstart, direction_shift, sibling_shift],
                    ],
                );
            }
        }
    }
    for family in families {
        if let MerkleProtocolFamily::PairedUpdate { refs, .. } = family {
            let mut weight = F256::ONE;
            for (left, right) in [
                (
                    vec![
                        ColRef::Fixed(refs.old_even),
                        ColRef::Committed(refs.d),
                        ColRef::Committed(refs.d),
                    ],
                    vec![ColRef::Fixed(refs.old_even), ColRef::Committed(refs.d)],
                ),
                (
                    vec![ColRef::Fixed(refs.bridge), ColRef::Committed(refs.e[0])],
                    vec![
                        ColRef::Fixed(refs.bridge),
                        ColRef::CommittedShift2(refs.c[0]),
                    ],
                ),
                (
                    vec![ColRef::Fixed(refs.bridge), ColRef::Committed(refs.e[1])],
                    vec![
                        ColRef::Fixed(refs.bridge),
                        ColRef::CommittedShift2(refs.c[1]),
                    ],
                ),
                (
                    vec![
                        ColRef::Fixed(refs.copy_step),
                        ColRef::Committed(refs.sib[0]),
                    ],
                    vec![
                        ColRef::Fixed(refs.copy_step),
                        ColRef::CommittedShift(refs.sib[0]),
                    ],
                ),
                (
                    vec![
                        ColRef::Fixed(refs.copy_step),
                        ColRef::Committed(refs.sib[1]),
                    ],
                    vec![
                        ColRef::Fixed(refs.copy_step),
                        ColRef::CommittedShift(refs.sib[1]),
                    ],
                ),
                (
                    vec![ColRef::Fixed(refs.copy_step), ColRef::Committed(refs.d)],
                    vec![
                        ColRef::Fixed(refs.copy_step),
                        ColRef::CommittedShift(refs.d),
                    ],
                ),
            ] {
                push_terms(&mut terms, weight, [left, right]);
                weight *= lambda;
            }
        }
    }
    terms
}

fn append_c1_ff_substitution(
    terms: &mut Vec<C1RelationTerm>,
    refs: &FfMerkleFamilyRefs,
    region: usize,
    weights: &[F256; STATE_SIZE],
) {
    for lane in 0..STATE_SIZE {
        terms.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![ColRef::Fixed(region), ColRef::CommittedShift(refs.c[lane])],
        });
    }
    let node = ColRef::Fixed(refs.node);
    for lane in 0..2 {
        let child = ColRef::Committed(refs.cr[lane]);
        let sibling = ColRef::Committed(refs.sib[lane]);
        let direction = ColRef::Committed(refs.d);
        let carry_shift = ColRef::CommittedShift(refs.c[lane]);
        push_terms(
            terms,
            weights[lane],
            [
                vec![node, carry_shift],
                vec![node, child],
                vec![node, direction, child],
                vec![node, direction, sibling],
            ],
        );
        let capacity_lane = 2 + lane;
        let capacity_shift = ColRef::CommittedShift(refs.c[capacity_lane]);
        push_terms(
            terms,
            weights[capacity_lane],
            [
                vec![node, capacity_shift],
                vec![node, sibling],
                vec![node, direction, child],
                vec![node, direction, sibling],
                vec![ColRef::Fixed(refs.iv[lane])],
            ],
        );
    }
}

fn append_c1_two_permutation_substitution(
    terms: &mut Vec<C1RelationTerm>,
    refs: &MerkleFamilyRefs,
    region: usize,
    weights: &[F256; STATE_SIZE],
) {
    let region = ColRef::Fixed(region);
    for lane in 0..2 {
        let carry_shift = ColRef::CommittedShift(refs.c[lane]);
        let carry_shift2 = ColRef::CommittedShift2(refs.c[lane]);
        let sibling = ColRef::Committed(refs.sib[lane]);
        let sibling_shift = ColRef::CommittedShift(refs.sib[lane]);
        let entry = ColRef::Committed(refs.e[lane]);
        let entry_shift = ColRef::CommittedShift(refs.e[lane]);
        let direction = ColRef::Committed(refs.d);
        let direction_shift = ColRef::CommittedShift(refs.d);
        push_terms(
            terms,
            weights[lane],
            [
                vec![region, carry_shift],
                vec![ColRef::Fixed(refs.evenstart), carry_shift],
                vec![ColRef::Fixed(refs.evenns), direction, carry_shift],
                vec![ColRef::Fixed(refs.even), direction, sibling],
                vec![ColRef::Fixed(refs.evenstart), entry],
                vec![ColRef::Fixed(refs.evenstart), direction, entry],
                vec![ColRef::Fixed(refs.odd), sibling_shift],
                vec![ColRef::Fixed(refs.odd), direction_shift, sibling_shift],
                vec![ColRef::Fixed(refs.oddns), direction_shift, carry_shift2],
                vec![ColRef::Fixed(refs.oddstart), direction_shift, entry_shift],
            ],
        );
    }
    for lane in 2..STATE_SIZE {
        let carry_shift = ColRef::CommittedShift(refs.c[lane]);
        push_terms(
            terms,
            weights[lane],
            [
                vec![region, carry_shift],
                vec![ColRef::Fixed(refs.even), carry_shift],
                vec![ColRef::Fixed(refs.iv[lane - 2])],
            ],
        );
    }
}

fn append_c1_paired_substitution(
    terms: &mut Vec<C1RelationTerm>,
    refs: &PairedMerkleUpdateRefs,
    region: usize,
    weights: &[F256; STATE_SIZE],
) {
    let mut push = |coefficient: F256, mut factors: Vec<ColRef>| {
        if !factors
            .iter()
            .any(|factor| matches!(factor, ColRef::Fixed(_)))
        {
            factors.insert(0, ColRef::Fixed(region));
        }
        terms.push(C1RelationTerm {
            coeff: coefficient,
            factors,
        });
    };
    for lane in 0..2 {
        let carry_shift = ColRef::CommittedShift(refs.c[lane]);
        let entry = ColRef::Committed(refs.e[lane]);
        let entry_shift = ColRef::CommittedShift(refs.e[lane]);
        let entry_shift2 = ColRef::CommittedShift2(refs.e[lane]);
        let sibling = ColRef::Committed(refs.sib[lane]);
        let sibling_shift = ColRef::CommittedShift(refs.sib[lane]);
        let direction = ColRef::Committed(refs.d);
        let direction_shift = ColRef::CommittedShift(refs.d);
        for factors in [
            vec![carry_shift],
            vec![ColRef::Fixed(refs.even), carry_shift],
            vec![ColRef::Fixed(refs.even_start), entry],
            vec![ColRef::Fixed(refs.even_start), direction, entry],
            vec![ColRef::Fixed(refs.even_nonstart), entry_shift],
            vec![ColRef::Fixed(refs.even_nonstart), direction, entry_shift],
            vec![ColRef::Fixed(refs.even), direction, sibling],
            vec![ColRef::Fixed(refs.odd), sibling_shift],
            vec![ColRef::Fixed(refs.odd), direction_shift, sibling_shift],
            vec![ColRef::Fixed(refs.odd_start), direction_shift, entry_shift],
            vec![
                ColRef::Fixed(refs.odd_nonstart),
                direction_shift,
                entry_shift2,
            ],
        ] {
            push(weights[lane], factors);
        }
    }
    for lane in 2..STATE_SIZE {
        let carry_shift = ColRef::CommittedShift(refs.c[lane]);
        for factors in [
            vec![carry_shift],
            vec![ColRef::Fixed(refs.even), carry_shift],
            vec![ColRef::Fixed(refs.iv[lane - 2])],
        ] {
            push(weights[lane], factors);
        }
    }
}

fn c1_merkle_substitution_terms(
    families: &[MerkleProtocolFamily],
    alpha: F256,
) -> Vec<C1RelationTerm> {
    let weights = c1_mds_weights(alpha);
    let mut terms = Vec::new();
    for family in families {
        if let MerkleProtocolFamily::FeedForward { refs, region } = family {
            append_c1_ff_substitution(&mut terms, refs, *region, &weights);
        }
    }
    for family in families {
        if let MerkleProtocolFamily::TwoPermutation { refs, region } = family {
            append_c1_two_permutation_substitution(&mut terms, refs, *region, &weights);
        }
    }
    for family in families {
        if let MerkleProtocolFamily::PairedUpdate { refs, region } = family {
            append_c1_paired_substitution(&mut terms, refs, *region, &weights);
        }
    }
    terms
}

fn append_c1_duplex_patterns(
    terms: &mut Vec<C1RelationTerm>,
    refs: &DuplexFamilyRefs,
    weights: &[F256; STATE_SIZE],
) {
    for lane in 0..STATE_SIZE {
        terms.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![
                ColRef::Fixed(refs.start),
                ColRef::CommittedShift(refs.c[lane]),
            ],
        });
        if lane < 2 {
            terms.push(C1RelationTerm {
                coeff: weights[lane],
                factors: vec![
                    ColRef::Fixed(refs.abs[lane]),
                    ColRef::Committed(refs.a[lane]),
                ],
            });
        }
        terms.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![ColRef::Fixed(refs.consts[lane])],
        });
    }
}

fn c1_duplex_terms(
    refs: &DuplexFamilyRefs,
    recording_refs: &[DuplexFamilyRefs],
    alpha: F256,
) -> Vec<C1RelationTerm> {
    let weights = c1_mds_weights(alpha);
    let mut sets = vec![*refs];
    sets.extend_from_slice(recording_refs);
    let mut terms = (0..STATE_SIZE)
        .map(|lane| C1RelationTerm {
            coeff: weights[lane],
            factors: vec![ColRef::CommittedShift(sets[0].c[lane])],
        })
        .collect::<Vec<_>>();
    for set in &sets {
        append_c1_duplex_patterns(&mut terms, set, &weights);
    }
    terms
}

pub(crate) fn c1_duplex_terms_selected(
    sets: &[DuplexFamilyRefs],
    selector: F128,
    alpha: F256,
) -> Vec<C1RelationTerm> {
    assert!(!sets.is_empty() && sets.len() % 2 == 0);
    let weights = c1_mds_weights(alpha);
    let selected = weights.map(|weight| weight.scale_base(selector));
    let mut terms = (0..STATE_SIZE)
        .map(|lane| C1RelationTerm {
            coeff: weights[lane],
            factors: vec![ColRef::CommittedShift(sets[0].c[lane])],
        })
        .collect::<Vec<_>>();
    for pair in sets.chunks_exact(2) {
        append_c1_duplex_patterns(&mut terms, &pair[0], &weights);
        append_c1_duplex_patterns(&mut terms, &pair[1], &selected);
    }
    terms
}

fn c1_sponge_leaf_terms(
    refs: &noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs,
    alpha: F256,
) -> Vec<C1RelationTerm> {
    let weights = c1_mds_weights(alpha);
    let mut terms = Vec::with_capacity(2 * STATE_SIZE);
    for lane in 0..2 {
        terms.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![ColRef::Committed(refs.in_[lane])],
        });
        terms.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![
                ColRef::Fixed(refs.odd),
                ColRef::CommittedShift(refs.c[lane]),
            ],
        });
    }
    for lane in 2..STATE_SIZE {
        terms.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![ColRef::Fixed(refs.iv[lane - 2])],
        });
        terms.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![
                ColRef::Fixed(refs.odd),
                ColRef::CommittedShift(refs.c[lane]),
            ],
        });
    }
    terms
}

fn append_c1_gated_sponge_terms(
    output: &mut Vec<C1RelationTerm>,
    refs: &noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs,
    region: usize,
    alpha: F256,
) {
    let mut terms = c1_sponge_leaf_terms(refs, alpha);
    for term in &mut terms {
        if !term
            .factors
            .iter()
            .any(|factor| matches!(factor, ColRef::Fixed(_)))
        {
            term.factors.insert(0, ColRef::Fixed(region));
        }
    }
    output.extend(terms);
}

fn append_c1_split_duplex_tail_terms(
    output: &mut Vec<C1RelationTerm>,
    refs: &SplitDuplexTailRefs,
    weights: &[F256; STATE_SIZE],
) {
    for lane in 0..2 {
        output.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![ColRef::Fixed(refs.region), ColRef::Committed(refs.a[lane])],
        });
        output.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![ColRef::Fixed(refs.consts[lane])],
        });
        output.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![
                ColRef::Fixed(refs.carry),
                ColRef::CommittedShift(refs.c[lane]),
            ],
        });
    }
    for lane in 2..STATE_SIZE {
        output.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![
                ColRef::Fixed(refs.first),
                ColRef::CommittedShift(refs.a[lane - 2]),
            ],
        });
        output.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![
                ColRef::Fixed(refs.carry),
                ColRef::CommittedShift(refs.c[lane]),
            ],
        });
    }
}

fn append_c1_source_tree_terms(
    output: &mut Vec<C1RelationTerm>,
    refs: &SourceTreeRefs,
    alpha: F256,
) {
    let weights = c1_mds_weights(alpha);
    for lane in 0..2 {
        let kid = ColRef::Committed(refs.kid[lane]);
        let carry = ColRef::CommittedShift(refs.c[lane]);
        let code = ColRef::Committed(refs.code[lane]);
        for factors in [
            vec![ColRef::Fixed(refs.even_int), kid],
            vec![ColRef::Fixed(refs.odd_int), kid],
            vec![ColRef::Fixed(refs.odd_int), carry],
            vec![ColRef::Fixed(refs.leafodd), code],
        ] {
            output.push(C1RelationTerm {
                coeff: weights[lane],
                factors,
            });
        }
    }
    for lane in 2..STATE_SIZE {
        output.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![ColRef::Fixed(refs.iv[lane - 2])],
        });
        output.push(C1RelationTerm {
            coeff: weights[lane],
            factors: vec![
                ColRef::Fixed(refs.odd_int),
                ColRef::CommittedShift(refs.c[lane]),
            ],
        });
    }
}

fn c1_walk_a_union_terms(
    leaf_refs: &[(noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs, usize)],
    split_tails: &[SplitDuplexTailRefs],
    es_sponge: Option<&(noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    alpha: F256,
) -> Vec<C1RelationTerm> {
    let weights = c1_mds_weights(alpha);
    let mut terms = Vec::new();
    for (refs, region) in leaf_refs {
        append_c1_gated_sponge_terms(&mut terms, refs, *region, alpha);
    }
    for refs in split_tails {
        append_c1_split_duplex_tail_terms(&mut terms, refs, &weights);
    }
    if let Some((refs, region)) = es_sponge {
        append_c1_gated_sponge_terms(&mut terms, refs, *region, alpha);
    }
    if let Some(spec) = spine {
        append_c1_source_tree_terms(&mut terms, &spec.tree_refs, alpha);
        append_c1_gated_sponge_terms(&mut terms, &spec.wrap_refs, spec.wrap_region, alpha);
    }
    terms
}

fn c1_spine_exposure_terms(gamma: F256) -> Vec<C1RelationTerm> {
    let mut terms = Vec::with_capacity(4);
    let mut power = F256::ONE;
    for lane in 0..2 {
        power *= gamma;
        terms.push(C1RelationTerm {
            coeff: power,
            factors: vec![ColRef::Fixed(0), ColRef::Committed(lane)],
        });
        terms.push(C1RelationTerm {
            coeff: power,
            factors: vec![
                ColRef::Fixed(0),
                ColRef::Window {
                    col: 2 + lane,
                    stride_log: 1,
                    offset: 1,
                },
            ],
        });
    }
    terms
}

fn c1_repoint_spine_kid(spec: &SpineUnionSpec, point: &[F256]) -> Vec<F256> {
    let (local, rest) = point.split_at(spec.local_log());
    let (instance, tx) = rest.split_at(spec.cap_log);
    let mut output = local.to_vec();
    output.push(F256::ZERO);
    output.extend_from_slice(instance);
    output.extend(spec.base_bits().into_iter().map(F256::from_base));
    output.extend_from_slice(tx);
    output.extend(spec.walk_high_bits.iter().copied().map(F256::from_base));
    output
}

fn c1_repoint_spine_c(spec: &SpineUnionSpec, point: &[F256]) -> Vec<F256> {
    let (local, rest) = point.split_at(spec.local_log());
    let (instance, tx) = rest.split_at(spec.cap_log);
    let mut output = vec![F256::ONE];
    output.extend_from_slice(local);
    output.extend_from_slice(instance);
    output.extend(spec.base_bits().into_iter().map(F256::from_base));
    output.extend_from_slice(tx);
    output.extend(spec.walk_high_bits.iter().copied().map(F256::from_base));
    output
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct C1WalkAUnionWalkDeferredProof {
    pub(crate) selection: C1ColumnRelationProof,
    pub(crate) substitution: C1ColumnRelationProof,
    pub(crate) shifts: Vec<C1ShiftDischargeProof>,
    pub(crate) spine_exposure: Option<C1ColumnRelationProof>,
}

#[derive(Clone, Copy)]
pub(crate) struct C1WalkAUnionWalkDeferredProofRef<'a> {
    pub(crate) selection: &'a C1ColumnRelationProof,
    pub(crate) substitution: &'a C1ColumnRelationProof,
    pub(crate) shifts: &'a [C1ShiftDischargeProof],
    pub(crate) spine_exposure: Option<&'a C1ColumnRelationProof>,
}

impl C1WalkAUnionWalkDeferredProof {
    pub(crate) fn as_ref(&self) -> C1WalkAUnionWalkDeferredProofRef<'_> {
        C1WalkAUnionWalkDeferredProofRef {
            selection: &self.selection,
            substitution: &self.substitution,
            shifts: &self.shifts,
            spine_exposure: self.spine_exposure.as_ref(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C1WalkAColumnClaim {
    pub(crate) column: usize,
    pub(crate) point: Vec<F256>,
    pub(crate) value: F256,
}

pub(crate) struct C1WalkAProverWalkPrefix {
    selection: C1ColumnRelationProof,
    pending: Vec<C1WalkAColumnClaim>,
    walk_group: C1LaneClaimGroup,
}

impl C1WalkAProverWalkPrefix {
    pub(crate) fn walk_group(&self) -> &C1LaneClaimGroup {
        &self.walk_group
    }
}

pub(crate) struct C1WalkAVerifierWalkPrefix<'a> {
    proof: C1WalkAUnionWalkDeferredProofRef<'a>,
    pending: Vec<C1WalkAColumnClaim>,
    walk_group: C1LaneClaimGroup,
}

impl C1WalkAVerifierWalkPrefix<'_> {
    pub(crate) fn walk_group(&self) -> &C1LaneClaimGroup {
        &self.walk_group
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_c1_walk_a_walk_prefix<C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    carry_columns: &[usize; STATE_SIZE],
    committed: &[&[F128]],
    s_out: &[Vec<F128>; STATE_SIZE],
    channel: &mut C,
) -> C1WalkAProverWalkPrefix {
    let width = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == width));
    assert!(s_out.iter().all(|column| column.len() == width));
    let beta = channel.sample_f256();
    let terms = c1_carry_selection_terms(carry_columns, beta);
    let rho = channel.sample_f256_vec(w_log);
    let internal = s_out.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let (selection, point, _) = prove_column_relation(
        F256::ZERO,
        &rho,
        &terms,
        &RelationColumns {
            committed,
            internal: &internal,
            fixed,
        },
        channel,
    );
    let mut pending = Vec::new();
    let mut values = [F256::ZERO; STATE_SIZE];
    for (&reference, &value) in claimed_refs(&terms).iter().zip(&selection.final_values) {
        match reference {
            ColRef::Committed(column) => pending.push(C1WalkAColumnClaim {
                column,
                point: point.clone(),
                value,
            }),
            ColRef::Internal(lane) => values[lane] = value,
            _ => unreachable!("C1 Walk-A selection claim kind"),
        }
    }
    C1WalkAProverWalkPrefix {
        selection,
        pending,
        walk_group: C1LaneClaimGroup { point, values },
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_c1_walk_a_walk_suffix<C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    leaf_refs: &[(noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs, usize)],
    split_tails: &[SplitDuplexTailRefs],
    es_sponge: Option<&(noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    committed: &[&[F128]],
    spine_exposure_columns: Option<&[&[F128]; 4]>,
    prefix: C1WalkAProverWalkPrefix,
    terminal: &C1LaneClaimGroup,
    channel: &mut C,
) -> (C1WalkAUnionWalkDeferredProof, Vec<C1WalkAColumnClaim>) {
    assert_eq!(spine.is_some(), spine_exposure_columns.is_some());
    let width = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == width));
    let C1WalkAProverWalkPrefix {
        selection,
        mut pending,
        walk_group: _,
    } = prefix;
    let alpha = channel.sample_f256();
    let terms = c1_walk_a_union_terms(leaf_refs, split_tails, es_sponge, spine, alpha);
    let mut power = F256::ONE;
    let target = terminal.values.iter().fold(F256::ZERO, |sum, &value| {
        power *= alpha;
        sum + power * value
    });
    let (substitution, point, _) = prove_column_relation(
        target,
        &terminal.point,
        &terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        channel,
    );
    let mut shifts = Vec::new();
    for (&reference, &value) in claimed_refs(&terms).iter().zip(&substitution.final_values) {
        match reference {
            ColRef::Committed(column) => pending.push(C1WalkAColumnClaim {
                column,
                point: point.clone(),
                value,
            }),
            ColRef::CommittedShift(column) | ColRef::CommittedShift2(column) => {
                let shift_log = usize::from(matches!(reference, ColRef::CommittedShift2(_)));
                let (shift, shifted_point) = prove_shift_discharge_pow2(
                    committed[column],
                    &point,
                    value,
                    shift_log,
                    channel,
                );
                pending.push(C1WalkAColumnClaim {
                    column,
                    point: shifted_point,
                    value: shift.final_value,
                });
                shifts.push(shift);
            }
            _ => unreachable!("C1 Walk-A substitution claim kind"),
        }
    }

    let spine_exposure = if let (Some(spec), Some(columns)) = (spine, spine_exposure_columns) {
        let gamma = channel.sample_f256();
        let terms = c1_spine_exposure_terms(gamma);
        let exposure_fixed = vec![spec.gate_pattern()];
        let rho = channel.sample_f256_vec(spec.expo_wlog());
        let (proof, point, _) = prove_column_relation(
            F256::ZERO,
            &rho,
            &terms,
            &RelationColumns {
                committed: columns,
                internal: &[],
                fixed: &exposure_fixed,
            },
            channel,
        );
        for (&reference, &value) in claimed_refs(&terms).iter().zip(&proof.final_values) {
            match reference {
                ColRef::Committed(local_column) => pending.push(C1WalkAColumnClaim {
                    column: spec.kid_meta[local_column],
                    point: c1_repoint_spine_kid(spec, &point),
                    value,
                }),
                ColRef::Window { col, .. } => pending.push(C1WalkAColumnClaim {
                    column: spec.c_meta[col - 2],
                    point: c1_repoint_spine_c(spec, &point),
                    value,
                }),
                _ => unreachable!("C1 Walk-A spine exposure claim kind"),
            }
        }
        Some(proof)
    } else {
        None
    };
    (
        C1WalkAUnionWalkDeferredProof {
            selection,
            substitution,
            shifts,
            spine_exposure,
        },
        pending,
    )
}

pub(crate) fn verify_c1_walk_a_walk_prefix<'a, C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    carry_columns: &[usize; STATE_SIZE],
    proof: C1WalkAUnionWalkDeferredProofRef<'a>,
    channel: &mut C,
) -> Result<C1WalkAVerifierWalkPrefix<'a>, WalkAUnionVerifyError> {
    let beta = channel.sample_f256();
    let terms = c1_carry_selection_terms(carry_columns, beta);
    let rho = channel.sample_f256_vec(w_log);
    let point = verify_column_relation(
        w_log,
        F256::ZERO,
        &rho,
        &terms,
        fixed,
        proof.selection,
        channel,
    )
    .map_err(WalkAUnionVerifyError::Selection)?;
    let mut pending = Vec::new();
    let mut values = [F256::ZERO; STATE_SIZE];
    for (&reference, &value) in claimed_refs(&terms)
        .iter()
        .zip(&proof.selection.final_values)
    {
        match reference {
            ColRef::Committed(column) => pending.push(C1WalkAColumnClaim {
                column,
                point: point.clone(),
                value,
            }),
            ColRef::Internal(lane) if lane < STATE_SIZE => values[lane] = value,
            _ => return Err(WalkAUnionVerifyError::Shape),
        }
    }
    Ok(C1WalkAVerifierWalkPrefix {
        proof,
        pending,
        walk_group: C1LaneClaimGroup { point, values },
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_c1_walk_a_walk_suffix<C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    leaf_refs: &[(noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs, usize)],
    split_tails: &[SplitDuplexTailRefs],
    es_sponge: Option<&(noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    prefix: C1WalkAVerifierWalkPrefix<'_>,
    terminal: &C1LaneClaimGroup,
    channel: &mut C,
) -> Result<Vec<C1WalkAColumnClaim>, WalkAUnionVerifyError> {
    let C1WalkAVerifierWalkPrefix {
        proof,
        mut pending,
        walk_group: _,
    } = prefix;
    let alpha = channel.sample_f256();
    let terms = c1_walk_a_union_terms(leaf_refs, split_tails, es_sponge, spine, alpha);
    let mut power = F256::ONE;
    let target = terminal.values.iter().fold(F256::ZERO, |sum, &value| {
        power *= alpha;
        sum + power * value
    });
    let point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &terms,
        fixed,
        proof.substitution,
        channel,
    )
    .map_err(WalkAUnionVerifyError::Substitution)?;
    let mut shift_cursor = 0usize;
    for (&reference, &value) in claimed_refs(&terms)
        .iter()
        .zip(&proof.substitution.final_values)
    {
        match reference {
            ColRef::Committed(column) => pending.push(C1WalkAColumnClaim {
                column,
                point: point.clone(),
                value,
            }),
            ColRef::CommittedShift(column) | ColRef::CommittedShift2(column) => {
                let shift = proof
                    .shifts
                    .get(shift_cursor)
                    .ok_or(WalkAUnionVerifyError::Shape)?;
                shift_cursor += 1;
                let shift_log = usize::from(matches!(reference, ColRef::CommittedShift2(_)));
                let shifted_point =
                    verify_shift_discharge_pow2(w_log, &point, value, shift_log, shift, channel)
                        .map_err(WalkAUnionVerifyError::Shift)?;
                pending.push(C1WalkAColumnClaim {
                    column,
                    point: shifted_point,
                    value: shift.final_value,
                });
            }
            _ => return Err(WalkAUnionVerifyError::Shape),
        }
    }
    if shift_cursor != proof.shifts.len() {
        return Err(WalkAUnionVerifyError::Shape);
    }
    match (spine, proof.spine_exposure) {
        (None, None) => {}
        (Some(spec), Some(exposure)) => {
            let gamma = channel.sample_f256();
            let terms = c1_spine_exposure_terms(gamma);
            let exposure_fixed = vec![spec.gate_pattern()];
            let rho = channel.sample_f256_vec(spec.expo_wlog());
            let point = verify_column_relation(
                spec.expo_wlog(),
                F256::ZERO,
                &rho,
                &terms,
                &exposure_fixed,
                exposure,
                channel,
            )
            .map_err(WalkAUnionVerifyError::SpineExposure)?;
            for (&reference, &value) in claimed_refs(&terms).iter().zip(&exposure.final_values) {
                match reference {
                    ColRef::Committed(local_column) if local_column < 2 => {
                        pending.push(C1WalkAColumnClaim {
                            column: spec.kid_meta[local_column],
                            point: c1_repoint_spine_kid(spec, &point),
                            value,
                        });
                    }
                    ColRef::Window {
                        col,
                        stride_log: 1,
                        offset: 1,
                    } if (2..4).contains(&col) => pending.push(C1WalkAColumnClaim {
                        column: spec.c_meta[col - 2],
                        point: c1_repoint_spine_c(spec, &point),
                        value,
                    }),
                    _ => return Err(WalkAUnionVerifyError::Shape),
                }
            }
        }
        _ => return Err(WalkAUnionVerifyError::Shape),
    }
    Ok(pending)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct C1MerkleUnionWalkDeferredProof {
    pub(crate) zero: C1ColumnRelationProof,
    pub(crate) zero_shifts: Vec<C1ShiftDischargeProof>,
    pub(crate) selection: C1ColumnRelationProof,
    pub(crate) substitution: C1ColumnRelationProof,
    pub(crate) shifts: Vec<C1ShiftDischargeProof>,
}

#[derive(Clone, Copy)]
pub(crate) struct C1MerkleUnionWalkDeferredProofRef<'a> {
    pub(crate) zero: &'a C1ColumnRelationProof,
    pub(crate) zero_shifts: &'a [C1ShiftDischargeProof],
    pub(crate) selection: &'a C1ColumnRelationProof,
    pub(crate) substitution: &'a C1ColumnRelationProof,
    pub(crate) shifts: &'a [C1ShiftDischargeProof],
}

impl C1MerkleUnionWalkDeferredProof {
    pub(crate) fn as_ref(&self) -> C1MerkleUnionWalkDeferredProofRef<'_> {
        C1MerkleUnionWalkDeferredProofRef {
            zero: &self.zero,
            zero_shifts: &self.zero_shifts,
            selection: &self.selection,
            substitution: &self.substitution,
            shifts: &self.shifts,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C1MerkleColumnClaim {
    pub(crate) column: usize,
    pub(crate) point: Vec<F256>,
    pub(crate) value: F256,
}

pub(crate) struct C1MerkleProverWalkPrefix {
    zero: C1ColumnRelationProof,
    zero_shifts: Vec<C1ShiftDischargeProof>,
    selection: C1ColumnRelationProof,
    pending: Vec<C1MerkleColumnClaim>,
    walk_group: C1LaneClaimGroup,
}

impl C1MerkleProverWalkPrefix {
    pub(crate) fn walk_group(&self) -> &C1LaneClaimGroup {
        &self.walk_group
    }
}

pub(crate) struct C1MerkleVerifierWalkPrefix<'a> {
    proof: C1MerkleUnionWalkDeferredProofRef<'a>,
    pending: Vec<C1MerkleColumnClaim>,
    walk_group: C1LaneClaimGroup,
}

impl C1MerkleVerifierWalkPrefix<'_> {
    pub(crate) fn walk_group(&self) -> &C1LaneClaimGroup {
        &self.walk_group
    }
}

fn prove_c1_merkle_claim_pass<C: Challenger>(
    committed: &[&[F128]],
    references: &[ColRef],
    values: &[F256],
    point: &[F256],
    channel: &mut C,
) -> (
    [F256; STATE_SIZE],
    Vec<C1MerkleColumnClaim>,
    Vec<C1ShiftDischargeProof>,
) {
    assert_eq!(references.len(), values.len(), "C1 Walk-B claim shape");
    let mut internal = [F256::ZERO; STATE_SIZE];
    let mut pending = Vec::new();
    let mut shifts = Vec::new();
    for (&reference, &value) in references.iter().zip(values) {
        match reference {
            ColRef::Committed(column) => pending.push(C1MerkleColumnClaim {
                column,
                point: point.to_vec(),
                value,
            }),
            ColRef::Internal(lane) => internal[lane] = value,
            ColRef::CommittedShift(column) => {
                let (shift, shifted_point) =
                    prove_shift_discharge(committed[column], point, value, channel);
                pending.push(C1MerkleColumnClaim {
                    column,
                    point: shifted_point,
                    value: shift.final_value,
                });
                shifts.push(shift);
            }
            ColRef::CommittedShift2(column) => {
                let (shift, shifted_point) =
                    prove_shift_discharge_pow2(committed[column], point, value, 1, channel);
                pending.push(C1MerkleColumnClaim {
                    column,
                    point: shifted_point,
                    value: shift.final_value,
                });
                shifts.push(shift);
            }
            _ => unreachable!("C1 Walk-B terminal claim kind"),
        }
    }
    (internal, pending, shifts)
}

fn verify_c1_merkle_claim_pass<C: Challenger>(
    w_log: usize,
    references: &[ColRef],
    values: &[F256],
    point: &[F256],
    proof_shifts: &[C1ShiftDischargeProof],
    channel: &mut C,
) -> Result<([F256; STATE_SIZE], Vec<C1MerkleColumnClaim>), MerkleUnionVerifyError> {
    if references.len() != values.len() {
        return Err(MerkleUnionVerifyError::Shape);
    }
    let mut internal = [F256::ZERO; STATE_SIZE];
    let mut pending = Vec::new();
    let mut shift_cursor = 0usize;
    for (&reference, &value) in references.iter().zip(values) {
        match reference {
            ColRef::Committed(column) => pending.push(C1MerkleColumnClaim {
                column,
                point: point.to_vec(),
                value,
            }),
            ColRef::Internal(lane) if lane < STATE_SIZE => internal[lane] = value,
            ColRef::CommittedShift(column) | ColRef::CommittedShift2(column) => {
                let shift = proof_shifts
                    .get(shift_cursor)
                    .ok_or(MerkleUnionVerifyError::Shape)?;
                shift_cursor += 1;
                let shifted_point = if matches!(reference, ColRef::CommittedShift(_)) {
                    verify_shift_discharge(w_log, point, value, shift, channel)
                } else {
                    verify_shift_discharge_pow2(w_log, point, value, 1, shift, channel)
                }
                .map_err(MerkleUnionVerifyError::Shift)?;
                pending.push(C1MerkleColumnClaim {
                    column,
                    point: shifted_point,
                    value: shift.final_value,
                });
            }
            _ => return Err(MerkleUnionVerifyError::Shape),
        }
    }
    if shift_cursor != proof_shifts.len() {
        return Err(MerkleUnionVerifyError::Shape);
    }
    Ok((internal, pending))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_c1_merkle_walk_prefix<C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    carry_columns: &[usize; STATE_SIZE],
    families: &[MerkleProtocolFamily],
    committed: &[&[F128]],
    s_out: &[Vec<F128>; STATE_SIZE],
    channel: &mut C,
) -> C1MerkleProverWalkPrefix {
    let width = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == width));
    assert!(s_out.iter().all(|column| column.len() == width));

    let lambda = channel.sample_f256();
    let zero_terms = c1_merkle_zero_terms(families, lambda);
    let zero_rho = channel.sample_f256_vec(w_log);
    let (zero, zero_point, _) = prove_column_relation(
        F256::ZERO,
        &zero_rho,
        &zero_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        channel,
    );
    let (_, mut pending, zero_shifts) = prove_c1_merkle_claim_pass(
        committed,
        &claimed_refs(&zero_terms),
        &zero.final_values,
        &zero_point,
        channel,
    );

    let beta = channel.sample_f256();
    let selection_terms = c1_carry_selection_terms(carry_columns, beta);
    let selection_rho = channel.sample_f256_vec(w_log);
    let internal = s_out.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let (selection, selection_point, _) = prove_column_relation(
        F256::ZERO,
        &selection_rho,
        &selection_terms,
        &RelationColumns {
            committed,
            internal: &internal,
            fixed,
        },
        channel,
    );
    let (output_values, selection_pending, selection_shifts) = prove_c1_merkle_claim_pass(
        committed,
        &claimed_refs(&selection_terms),
        &selection.final_values,
        &selection_point,
        channel,
    );
    assert!(selection_shifts.is_empty(), "C1 Walk-B selection shifts");
    pending.extend(selection_pending);
    C1MerkleProverWalkPrefix {
        zero,
        zero_shifts,
        selection,
        pending,
        walk_group: C1LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_c1_merkle_walk_suffix<C: Challenger>(
    _w_log: usize,
    fixed: &[FixedPattern],
    families: &[MerkleProtocolFamily],
    committed: &[&[F128]],
    prefix: C1MerkleProverWalkPrefix,
    terminal: &C1LaneClaimGroup,
    channel: &mut C,
) -> (C1MerkleUnionWalkDeferredProof, Vec<C1MerkleColumnClaim>) {
    let C1MerkleProverWalkPrefix {
        zero,
        zero_shifts,
        selection,
        mut pending,
        walk_group: _,
    } = prefix;
    let alpha = channel.sample_f256();
    let substitution_terms = c1_merkle_substitution_terms(families, alpha);
    let mut power = F256::ONE;
    let target = terminal.values.iter().fold(F256::ZERO, |sum, &value| {
        power *= alpha;
        sum + power * value
    });
    let (substitution, substitution_point, _) = prove_column_relation(
        target,
        &terminal.point,
        &substitution_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        channel,
    );
    let (_, substitution_pending, shifts) = prove_c1_merkle_claim_pass(
        committed,
        &claimed_refs(&substitution_terms),
        &substitution.final_values,
        &substitution_point,
        channel,
    );
    pending.extend(substitution_pending);
    (
        C1MerkleUnionWalkDeferredProof {
            zero,
            zero_shifts,
            selection,
            substitution,
            shifts,
        },
        pending,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_c1_merkle_walk_prefix<'a, C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    carry_columns: &[usize; STATE_SIZE],
    families: &[MerkleProtocolFamily],
    proof: C1MerkleUnionWalkDeferredProofRef<'a>,
    channel: &mut C,
) -> Result<C1MerkleVerifierWalkPrefix<'a>, MerkleUnionVerifyError> {
    let lambda = channel.sample_f256();
    let zero_terms = c1_merkle_zero_terms(families, lambda);
    let zero_rho = channel.sample_f256_vec(w_log);
    let zero_point = verify_column_relation(
        w_log,
        F256::ZERO,
        &zero_rho,
        &zero_terms,
        fixed,
        proof.zero,
        channel,
    )
    .map_err(MerkleUnionVerifyError::Zero)?;
    let (_, mut pending) = verify_c1_merkle_claim_pass(
        w_log,
        &claimed_refs(&zero_terms),
        &proof.zero.final_values,
        &zero_point,
        proof.zero_shifts,
        channel,
    )?;

    let beta = channel.sample_f256();
    let selection_terms = c1_carry_selection_terms(carry_columns, beta);
    let selection_rho = channel.sample_f256_vec(w_log);
    let selection_point = verify_column_relation(
        w_log,
        F256::ZERO,
        &selection_rho,
        &selection_terms,
        fixed,
        proof.selection,
        channel,
    )
    .map_err(MerkleUnionVerifyError::Selection)?;
    let (output_values, selection_pending) = verify_c1_merkle_claim_pass(
        w_log,
        &claimed_refs(&selection_terms),
        &proof.selection.final_values,
        &selection_point,
        &[],
        channel,
    )?;
    pending.extend(selection_pending);
    Ok(C1MerkleVerifierWalkPrefix {
        proof,
        pending,
        walk_group: C1LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    })
}

pub(crate) fn verify_c1_merkle_walk_suffix<C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    families: &[MerkleProtocolFamily],
    prefix: C1MerkleVerifierWalkPrefix<'_>,
    terminal: &C1LaneClaimGroup,
    channel: &mut C,
) -> Result<Vec<C1MerkleColumnClaim>, MerkleUnionVerifyError> {
    let C1MerkleVerifierWalkPrefix {
        proof,
        mut pending,
        walk_group: _,
    } = prefix;
    let alpha = channel.sample_f256();
    let substitution_terms = c1_merkle_substitution_terms(families, alpha);
    let mut power = F256::ONE;
    let target = terminal.values.iter().fold(F256::ZERO, |sum, &value| {
        power *= alpha;
        sum + power * value
    });
    let substitution_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &substitution_terms,
        fixed,
        proof.substitution,
        channel,
    )
    .map_err(MerkleUnionVerifyError::Substitution)?;
    let (_, substitution_pending) = verify_c1_merkle_claim_pass(
        w_log,
        &claimed_refs(&substitution_terms),
        &proof.substitution.final_values,
        &substitution_point,
        proof.shifts,
        channel,
    )?;
    pending.extend(substitution_pending);
    Ok(pending)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct C1DuplexUnionWalkDeferredProof {
    pub(crate) selection: C1ColumnRelationProof,
    pub(crate) substitution: C1ColumnRelationProof,
    pub(crate) shifts: Vec<C1ShiftDischargeProof>,
}

#[derive(Clone, Copy)]
pub(crate) struct C1DuplexUnionWalkDeferredProofRef<'a> {
    pub(crate) selection: &'a C1ColumnRelationProof,
    pub(crate) substitution: &'a C1ColumnRelationProof,
    pub(crate) shifts: &'a [C1ShiftDischargeProof],
}

impl C1DuplexUnionWalkDeferredProof {
    pub(crate) fn as_ref(&self) -> C1DuplexUnionWalkDeferredProofRef<'_> {
        C1DuplexUnionWalkDeferredProofRef {
            selection: &self.selection,
            substitution: &self.substitution,
            shifts: &self.shifts,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct C1DuplexColumnClaim {
    pub(crate) column: usize,
    pub(crate) point: Vec<F256>,
    pub(crate) value: F256,
}

pub(crate) struct C1DuplexProverWalkPrefix {
    selection: C1ColumnRelationProof,
    pending: Vec<C1DuplexColumnClaim>,
    walk_group: C1LaneClaimGroup,
}

impl C1DuplexProverWalkPrefix {
    pub(crate) fn walk_group(&self) -> &C1LaneClaimGroup {
        &self.walk_group
    }
}

pub(crate) struct C1DuplexVerifierWalkPrefix<'a> {
    proof: C1DuplexUnionWalkDeferredProofRef<'a>,
    pending: Vec<C1DuplexColumnClaim>,
    walk_group: C1LaneClaimGroup,
}

impl C1DuplexVerifierWalkPrefix<'_> {
    pub(crate) fn walk_group(&self) -> &C1LaneClaimGroup {
        &self.walk_group
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_c1_duplex_walk_prefix<C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    committed: &[&[F128]],
    s_out: &[Vec<F128>; STATE_SIZE],
    channel: &mut C,
) -> C1DuplexProverWalkPrefix {
    let width = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == width));
    assert!(s_out.iter().all(|column| column.len() == width));
    let beta = channel.sample_f256();
    let selection_terms = c1_carry_selection_terms(&refs.c, beta);
    let rho = channel.sample_f256_vec(w_log);
    let internal = s_out.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let (selection, selection_point, _) = prove_column_relation(
        F256::ZERO,
        &rho,
        &selection_terms,
        &RelationColumns {
            committed,
            internal: &internal,
            fixed,
        },
        channel,
    );
    let mut pending = Vec::new();
    let mut output_values = [F256::ZERO; STATE_SIZE];
    for (&reference, &value) in claimed_refs(&selection_terms)
        .iter()
        .zip(&selection.final_values)
    {
        match reference {
            ColRef::Committed(column) => pending.push(C1DuplexColumnClaim {
                column,
                point: selection_point.clone(),
                value,
            }),
            ColRef::Internal(lane) => output_values[lane] = value,
            _ => unreachable!("C1 duplex selection claim kind"),
        }
    }
    C1DuplexProverWalkPrefix {
        selection,
        pending,
        walk_group: C1LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn prove_c1_duplex_walk_suffix_batched<C: Challenger>(
    _w_log: usize,
    fixed: &[FixedPattern],
    committed: &[&[F128]],
    prefix: C1DuplexProverWalkPrefix,
    terminal: &C1LaneClaimGroup,
    alpha: F256,
    substitution_terms: Vec<C1RelationTerm>,
    channel: &mut C,
) -> (C1DuplexUnionWalkDeferredProof, Vec<C1DuplexColumnClaim>) {
    let C1DuplexProverWalkPrefix {
        selection,
        mut pending,
        walk_group: _,
    } = prefix;
    let mut power = F256::ONE;
    let target = terminal.values.iter().fold(F256::ZERO, |sum, &value| {
        power *= alpha;
        sum + power * value
    });
    let (substitution, substitution_point, _) = prove_column_relation(
        target,
        &terminal.point,
        &substitution_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        channel,
    );
    let mut shifts = Vec::new();
    for (&reference, &value) in claimed_refs(&substitution_terms)
        .iter()
        .zip(&substitution.final_values)
    {
        match reference {
            ColRef::Committed(column) => pending.push(C1DuplexColumnClaim {
                column,
                point: substitution_point.clone(),
                value,
            }),
            ColRef::CommittedShift(column) => {
                let (shift, point) =
                    prove_shift_discharge(committed[column], &substitution_point, value, channel);
                pending.push(C1DuplexColumnClaim {
                    column,
                    point,
                    value: shift.final_value,
                });
                shifts.push(shift);
            }
            _ => unreachable!("C1 duplex substitution claim kind"),
        }
    }
    (
        C1DuplexUnionWalkDeferredProof {
            selection,
            substitution,
            shifts,
        },
        pending,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_c1_duplex_walk_suffix<C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    recording_refs: &[DuplexFamilyRefs],
    committed: &[&[F128]],
    prefix: C1DuplexProverWalkPrefix,
    terminal: &C1LaneClaimGroup,
    channel: &mut C,
) -> (C1DuplexUnionWalkDeferredProof, Vec<C1DuplexColumnClaim>) {
    let alpha = channel.sample_f256();
    let terms = c1_duplex_terms(refs, recording_refs, alpha);
    prove_c1_duplex_walk_suffix_batched(
        w_log, fixed, committed, prefix, terminal, alpha, terms, channel,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_c1_duplex_walk_suffix_selected<C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    sets: &[DuplexFamilyRefs],
    selector: F128,
    committed: &[&[F128]],
    prefix: C1DuplexProverWalkPrefix,
    terminal: &C1LaneClaimGroup,
    channel: &mut C,
) -> (C1DuplexUnionWalkDeferredProof, Vec<C1DuplexColumnClaim>) {
    let alpha = channel.sample_f256();
    let terms = c1_duplex_terms_selected(sets, selector, alpha);
    prove_c1_duplex_walk_suffix_batched(
        w_log, fixed, committed, prefix, terminal, alpha, terms, channel,
    )
}

pub(crate) fn verify_c1_duplex_walk_prefix<'a, C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    proof: C1DuplexUnionWalkDeferredProofRef<'a>,
    channel: &mut C,
) -> Result<C1DuplexVerifierWalkPrefix<'a>, DuplexUnionVerifyError> {
    let beta = channel.sample_f256();
    let selection_terms = c1_carry_selection_terms(&refs.c, beta);
    let rho = channel.sample_f256_vec(w_log);
    let selection_point = verify_column_relation(
        w_log,
        F256::ZERO,
        &rho,
        &selection_terms,
        fixed,
        proof.selection,
        channel,
    )
    .map_err(DuplexUnionVerifyError::Selection)?;
    let mut pending = Vec::new();
    let mut output_values = [F256::ZERO; STATE_SIZE];
    for (&reference, &value) in claimed_refs(&selection_terms)
        .iter()
        .zip(&proof.selection.final_values)
    {
        match reference {
            ColRef::Committed(column) => pending.push(C1DuplexColumnClaim {
                column,
                point: selection_point.clone(),
                value,
            }),
            ColRef::Internal(lane) if lane < STATE_SIZE => output_values[lane] = value,
            _ => return Err(DuplexUnionVerifyError::Shape),
        }
    }
    Ok(C1DuplexVerifierWalkPrefix {
        proof,
        pending,
        walk_group: C1LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    })
}

fn verify_c1_duplex_walk_suffix_batched<C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    prefix: C1DuplexVerifierWalkPrefix<'_>,
    terminal: &C1LaneClaimGroup,
    alpha: F256,
    substitution_terms: Vec<C1RelationTerm>,
    channel: &mut C,
) -> Result<Vec<C1DuplexColumnClaim>, DuplexUnionVerifyError> {
    let C1DuplexVerifierWalkPrefix {
        proof,
        mut pending,
        walk_group: _,
    } = prefix;
    let mut power = F256::ONE;
    let target = terminal.values.iter().fold(F256::ZERO, |sum, &value| {
        power *= alpha;
        sum + power * value
    });
    let substitution_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &substitution_terms,
        fixed,
        proof.substitution,
        channel,
    )
    .map_err(DuplexUnionVerifyError::Substitution)?;
    let mut shift_cursor = 0usize;
    for (&reference, &value) in claimed_refs(&substitution_terms)
        .iter()
        .zip(&proof.substitution.final_values)
    {
        match reference {
            ColRef::Committed(column) => pending.push(C1DuplexColumnClaim {
                column,
                point: substitution_point.clone(),
                value,
            }),
            ColRef::CommittedShift(column) => {
                let shift = proof
                    .shifts
                    .get(shift_cursor)
                    .ok_or(DuplexUnionVerifyError::Shape)?;
                shift_cursor += 1;
                let point =
                    verify_shift_discharge(w_log, &substitution_point, value, shift, channel)
                        .map_err(DuplexUnionVerifyError::Shift)?;
                pending.push(C1DuplexColumnClaim {
                    column,
                    point,
                    value: shift.final_value,
                });
            }
            _ => return Err(DuplexUnionVerifyError::Shape),
        }
    }
    if shift_cursor != proof.shifts.len() {
        return Err(DuplexUnionVerifyError::Shape);
    }
    Ok(pending)
}

pub(crate) fn verify_c1_duplex_walk_suffix<C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    recording_refs: &[DuplexFamilyRefs],
    prefix: C1DuplexVerifierWalkPrefix<'_>,
    terminal: &C1LaneClaimGroup,
    channel: &mut C,
) -> Result<Vec<C1DuplexColumnClaim>, DuplexUnionVerifyError> {
    let alpha = channel.sample_f256();
    let terms = c1_duplex_terms(refs, recording_refs, alpha);
    verify_c1_duplex_walk_suffix_batched(w_log, fixed, prefix, terminal, alpha, terms, channel)
}

pub(crate) fn verify_c1_duplex_walk_suffix_selected<C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    sets: &[DuplexFamilyRefs],
    selector: F128,
    prefix: C1DuplexVerifierWalkPrefix<'_>,
    terminal: &C1LaneClaimGroup,
    channel: &mut C,
) -> Result<Vec<C1DuplexColumnClaim>, DuplexUnionVerifyError> {
    let alpha = channel.sample_f256();
    let terms = c1_duplex_terms_selected(sets, selector, alpha);
    verify_c1_duplex_walk_suffix_batched(w_log, fixed, prefix, terminal, alpha, terms, channel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
    use noid_ivc_core::deep_chain::c1::{
        prove_ragged_deep_chain_walk, verify_ragged_deep_chain_walk,
    };
    use noid_ivc_core::deep_chain::schedule::{
        carry_selection_terms, compile_duplex, duplex_family_refs, TranscriptOp,
    };

    use crate::acceptance::trace::region_source_binding::{
        build_duplex_union, duplex_substitution_terms_selected, duplex_substitution_terms_sets,
        merkle_protocol_substitution_terms, merkle_protocol_zero_terms,
    };

    fn assert_lifted(
        base: &[noid_ivc_core::deep_chain::relations::RelationTerm],
        wide: &[C1RelationTerm],
    ) {
        assert_eq!(base.len(), wide.len());
        for (base, wide) in base.iter().zip(wide) {
            assert_eq!(base.factors, wide.factors);
            assert_eq!(F256::from_base(base.coeff), wide.coeff);
        }
    }

    #[test]
    fn c1_term_builders_are_exact_extension_lifts_on_base_challenges() {
        let lambda = F128::new(0x1234, 0x5678);
        let alpha = F128::new(0x9abc, 0xdef0);
        let beta = F128::new(0x1357, 0x2468);
        let families = [
            MerkleProtocolFamily::feed_forward(0),
            MerkleProtocolFamily::two_permutation(5),
            MerkleProtocolFamily::paired_update(14),
        ];
        assert_lifted(
            &merkle_protocol_zero_terms(&families, lambda),
            &c1_merkle_zero_terms(&families, F256::from_base(lambda)),
        );
        assert_lifted(
            &merkle_protocol_substitution_terms(&families, alpha),
            &c1_merkle_substitution_terms(&families, F256::from_base(alpha)),
        );
        let carry = [0usize, 1, 2, 3];
        assert_lifted(
            &carry_selection_terms(&carry, beta),
            &c1_carry_selection_terms(&carry, F256::from_base(beta)),
        );

        let refs = duplex_family_refs(0, 0);
        let recording = [duplex_family_refs(0, 7)];
        assert_lifted(
            &duplex_substitution_terms_sets(&refs, &recording, alpha),
            &c1_duplex_terms(&refs, &recording, F256::from_base(alpha)),
        );
        let selected_sets = [duplex_family_refs(0, 0), duplex_family_refs(0, 7)];
        let selector = F128::ONE;
        assert_lifted(
            &duplex_substitution_terms_selected(&selected_sets, selector, alpha),
            &c1_duplex_terms_selected(&selected_sets, selector, F256::from_base(alpha)),
        );
    }

    #[test]
    fn c1_duplex_prefix_walk_suffix_roundtrip() {
        let layout = compile_duplex(&[
            TranscriptOp::Absorb(vec![None, None, None]),
            TranscriptOp::Squeeze(3),
        ]);
        let union = build_duplex_union(
            &layout,
            [F128::new(0x1111, 0x2222), F128::new(0x3333, 0x4444)],
            &[vec![F128::new(3, 0), F128::new(5, 0), F128::new(7, 0)]],
        );
        let committed = union
            .committed
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();

        let mut prover = FsLaneChallenger::new_c1(b"c1-duplex-prefix-walk-suffix");
        let prefix = prove_c1_duplex_walk_prefix(
            union.w_log,
            &union.fixed,
            &union.refs,
            &committed,
            &union.s_out,
            &mut prover,
        );
        let groups = vec![prefix.walk_group().clone()];
        let states = vec![&union.s0];
        let (walk, terminals) = prove_ragged_deep_chain_walk(&states, &groups, &mut prover);
        let (proof, prover_claims) = prove_c1_duplex_walk_suffix(
            union.w_log,
            &union.fixed,
            &union.refs,
            &[],
            &committed,
            prefix,
            &terminals[0],
            &mut prover,
        );

        let mut verifier = FsLaneChallenger::new_c1(b"c1-duplex-prefix-walk-suffix");
        let prefix = verify_c1_duplex_walk_prefix(
            union.w_log,
            &union.fixed,
            &union.refs,
            proof.as_ref(),
            &mut verifier,
        )
        .unwrap();
        let groups = vec![prefix.walk_group().clone()];
        let terminals =
            verify_ragged_deep_chain_walk(&[union.w_log], &groups, &walk, &mut verifier).unwrap();
        let verifier_claims = verify_c1_duplex_walk_suffix(
            union.w_log,
            &union.fixed,
            &union.refs,
            &[],
            prefix,
            &terminals[0],
            &mut verifier,
        )
        .unwrap();
        assert_eq!(prover_claims, verifier_claims);
        assert_eq!(prover.sample_f256(), verifier.sample_f256());
    }
}

pub(crate) fn c1_duplex_terms_selected_n(
    sets: &[DuplexFamilyRefs],
    arms: usize,
    selector: F128,
    alpha: F256,
) -> Vec<C1RelationTerm> {
    if arms == 2 {
        return c1_duplex_terms_selected(sets, selector, alpha);
    }
    assert_eq!(arms, 3);
    assert!(!sets.is_empty() && sets.len() % arms == 0);
    let weights = c1_mds_weights(alpha);
    let choices = super::region_source_binding::recording_choice_weights(arms, selector);
    let mut terms = (0..STATE_SIZE)
        .map(|lane| C1RelationTerm {
            coeff: weights[lane],
            factors: vec![ColRef::CommittedShift(sets[0].c[lane])],
        })
        .collect::<Vec<_>>();
    for group in sets.chunks_exact(arms) {
        for (choice, set) in choices.iter().zip(group) {
            append_c1_duplex_patterns(
                &mut terms,
                set,
                &weights.map(|weight| weight.scale_base(*choice)),
            );
        }
    }
    terms
}

pub(crate) fn prove_c1_duplex_walk_suffix_selected_n<C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    sets: &[DuplexFamilyRefs],
    arms: usize,
    selector: F128,
    committed: &[&[F128]],
    prefix: C1DuplexProverWalkPrefix,
    terminal: &C1LaneClaimGroup,
    channel: &mut C,
) -> (C1DuplexUnionWalkDeferredProof, Vec<C1DuplexColumnClaim>) {
    let alpha = channel.sample_f256();
    let terms = c1_duplex_terms_selected_n(sets, arms, selector, alpha);
    prove_c1_duplex_walk_suffix_batched(
        w_log, fixed, committed, prefix, terminal, alpha, terms, channel,
    )
}

pub(crate) fn verify_c1_duplex_walk_suffix_selected_n<C: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    sets: &[DuplexFamilyRefs],
    arms: usize,
    selector: F128,
    prefix: C1DuplexVerifierWalkPrefix<'_>,
    terminal: &C1LaneClaimGroup,
    channel: &mut C,
) -> Result<Vec<C1DuplexColumnClaim>, DuplexUnionVerifyError> {
    let alpha = channel.sample_f256();
    let terms = c1_duplex_terms_selected_n(sets, arms, selector, alpha);
    verify_c1_duplex_walk_suffix_batched(w_log, fixed, prefix, terminal, alpha, terms, channel)
}
