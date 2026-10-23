// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Recursive trace twins for the genuine `GF(2^256)` region protocols.

use noid_ivc_core::deep_chain::relations::c1::claimed_refs;
use noid_ivc_core::deep_chain::relations::ColRef;
use noid_ivc_core::field_circuit::FsChannelOps;
use noid_poseidon2b::native::permutation::STATE_SIZE;

use crate::acceptance::trace::deep_chain::{
    verify_c1_column_relation_trace, verify_c1_shift_discharge_trace, C1ColumnRelationProofTrace,
    C1LaneClaimGroupTrace, C1RelationTermTrace, C1ShiftDischargeProofTrace,
};
use crate::acceptance::trace::{mul_ext, ExtExpr, FieldR1csBuilder, LinExpr};
use crate::region_sidecar::RegionSidecarError;

use super::*;

fn c1_weights_trace(
    b: &mut FieldR1csBuilder,
    alpha: &ExtExpr,
) -> ([ExtExpr; STATE_SIZE], [ExtExpr; STATE_SIZE]) {
    let mut powers: [ExtExpr; STATE_SIZE] = std::array::from_fn(|_| ExtExpr::zero());
    let mut power = ExtExpr::one();
    for value in &mut powers {
        power = mul_ext(b, &power, alpha);
        *value = power.clone();
    }
    let mds = flat_mds(true);
    let weights = std::array::from_fn(|column| {
        (0..STATE_SIZE).fold(ExtExpr::zero(), |sum, row| {
            sum.add(&powers[row].scale_base(mds[row][column]))
        })
    });
    (weights, powers)
}

fn c1_selection_terms_trace(
    b: &mut FieldR1csBuilder,
    columns: &[usize; STATE_SIZE],
    beta: &ExtExpr,
) -> Vec<C1RelationTermTrace> {
    let mut terms = Vec::with_capacity(2 * STATE_SIZE);
    let mut power = ExtExpr::one();
    for lane in 0..STATE_SIZE {
        power = mul_ext(b, &power, beta);
        terms.push(C1RelationTermTrace {
            coeff: power.clone(),
            factors: vec![ColRef::Committed(columns[lane])],
        });
        terms.push(C1RelationTermTrace {
            coeff: power.clone(),
            factors: vec![ColRef::Internal(lane)],
        });
    }
    terms
}

fn c1_duplex_pattern_terms_trace(
    output: &mut Vec<C1RelationTermTrace>,
    refs: &DuplexFamilyRefs,
    weights: &[ExtExpr; STATE_SIZE],
) {
    for lane in 0..STATE_SIZE {
        output.push(C1RelationTermTrace {
            coeff: weights[lane].clone(),
            factors: vec![
                ColRef::Fixed(refs.start),
                ColRef::CommittedShift(refs.c[lane]),
            ],
        });
        if lane < 2 {
            output.push(C1RelationTermTrace {
                coeff: weights[lane].clone(),
                factors: vec![
                    ColRef::Fixed(refs.abs[lane]),
                    ColRef::Committed(refs.a[lane]),
                ],
            });
        }
        output.push(C1RelationTermTrace {
            coeff: weights[lane].clone(),
            factors: vec![ColRef::Fixed(refs.consts[lane])],
        });
    }
}

fn c1_duplex_terms_trace(
    b: &mut FieldR1csBuilder,
    refs: &DuplexFamilyRefs,
    recording_refs: &[DuplexFamilyRefs],
    alpha: &ExtExpr,
) -> (Vec<C1RelationTermTrace>, [ExtExpr; STATE_SIZE]) {
    let (weights, powers) = c1_weights_trace(b, alpha);
    let mut sets = vec![*refs];
    sets.extend_from_slice(recording_refs);
    let mut terms = (0..STATE_SIZE)
        .map(|lane| C1RelationTermTrace {
            coeff: weights[lane].clone(),
            factors: vec![ColRef::CommittedShift(sets[0].c[lane])],
        })
        .collect::<Vec<_>>();
    for set in &sets {
        c1_duplex_pattern_terms_trace(&mut terms, set, &weights);
    }
    (terms, powers)
}

fn c1_duplex_terms_selected_trace(
    b: &mut FieldR1csBuilder,
    sets: &[DuplexFamilyRefs],
    selector: &ExtExpr,
    alpha: &ExtExpr,
) -> (Vec<C1RelationTermTrace>, [ExtExpr; STATE_SIZE]) {
    assert!(!sets.is_empty() && sets.len() % 2 == 0);
    let (weights, powers) = c1_weights_trace(b, alpha);
    let selected: [ExtExpr; STATE_SIZE] =
        std::array::from_fn(|lane| mul_ext(b, &weights[lane], selector));
    let mut terms = (0..STATE_SIZE)
        .map(|lane| C1RelationTermTrace {
            coeff: weights[lane].clone(),
            factors: vec![ColRef::CommittedShift(sets[0].c[lane])],
        })
        .collect::<Vec<_>>();
    for pair in sets.chunks_exact(2) {
        c1_duplex_pattern_terms_trace(&mut terms, &pair[0], &weights);
        c1_duplex_pattern_terms_trace(&mut terms, &pair[1], &selected);
    }
    (terms, powers)
}

fn c1_shift_count(references: &[ColRef]) -> usize {
    references
        .iter()
        .filter(|reference| {
            matches!(
                reference,
                ColRef::CommittedShift(_) | ColRef::CommittedShift2(_)
            )
        })
        .count()
}

fn preflight_c1_relation(
    proof: &noid_ivc_core::deep_chain::relations::c1::C1ColumnRelationProof,
    w_log: usize,
    values: usize,
) -> bool {
    proof.rounds.len() == w_log && proof.final_values.len() == values
}

fn preflight_c1_shifts(
    proofs: &[noid_ivc_core::deep_chain::relations::c1::C1ShiftDischargeProof],
    count: usize,
    w_log: usize,
) -> bool {
    proofs.len() == count && proofs.iter().all(|proof| proof.rounds.len() == w_log)
}

pub(crate) struct C1DuplexColumnClaimTrace {
    pub(crate) column: usize,
    pub(crate) point: Vec<ExtExpr>,
    pub(crate) value: ExtExpr,
}

pub(crate) struct C1DuplexUnionTraceWalkPrefix<'a> {
    proof: C1DuplexUnionWalkDeferredProofRef<'a>,
    pending: Vec<C1DuplexColumnClaimTrace>,
    walk_group: C1LaneClaimGroupTrace,
}

impl C1DuplexUnionTraceWalkPrefix<'_> {
    pub(crate) fn walk_group(&self) -> &C1LaneClaimGroupTrace {
        &self.walk_group
    }
}

fn preflight_c1_duplex_deferred(
    w_log: usize,
    refs: &DuplexFamilyRefs,
    proof: C1DuplexUnionWalkDeferredProofRef<'_>,
) -> bool {
    let selection = c1_carry_selection_terms(&refs.c, F256::ONE);
    let substitution = c1_duplex_terms(refs, &[], F256::ONE);
    let selection_refs = claimed_refs(&selection);
    let substitution_refs = claimed_refs(&substitution);
    preflight_c1_relation(proof.selection, w_log, selection_refs.len())
        && preflight_c1_relation(proof.substitution, w_log, substitution_refs.len())
        && preflight_c1_shifts(proof.shifts, c1_shift_count(&substitution_refs), w_log)
}

pub(crate) fn verify_c1_duplex_walk_prefix_trace<'a, C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    channel: &mut C,
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    proof: C1DuplexUnionWalkDeferredProofRef<'a>,
) -> Result<C1DuplexUnionTraceWalkPrefix<'a>, RegionSidecarError> {
    if !preflight_c1_duplex_deferred(w_log, refs, proof) {
        return Err(RegionSidecarError::InvalidProof);
    }
    let beta = channel.sample_f256(b);
    let selection_terms = c1_selection_terms_trace(b, &refs.c, &beta);
    let selection_refs = claimed_refs(&c1_carry_selection_terms(&refs.c, F256::ONE));
    let rho = channel.sample_f256_vec(b, w_log);
    let selection =
        C1ColumnRelationProofTrace::alloc(b, proof.selection, w_log, selection_refs.len());
    let point = verify_c1_column_relation_trace(
        b,
        channel,
        w_log,
        &ExtExpr::zero(),
        &rho,
        &selection_terms,
        fixed,
        &selection,
    );
    let mut pending = Vec::new();
    let mut values: [ExtExpr; STATE_SIZE] = std::array::from_fn(|_| ExtExpr::zero());
    for (reference, value) in selection_refs.iter().zip(&selection.final_values) {
        match reference {
            ColRef::Committed(column) => pending.push(C1DuplexColumnClaimTrace {
                column: *column,
                point: point.clone(),
                value: value.clone(),
            }),
            ColRef::Internal(lane) if *lane < STATE_SIZE => values[*lane] = value.clone(),
            _ => return Err(RegionSidecarError::InvalidProof),
        }
    }
    Ok(C1DuplexUnionTraceWalkPrefix {
        proof,
        pending,
        walk_group: C1LaneClaimGroupTrace { point, values },
    })
}

fn verify_c1_duplex_walk_suffix_trace_inner<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    channel: &mut C,
    w_log: usize,
    fixed: &[FixedPattern],
    prefix: C1DuplexUnionTraceWalkPrefix<'_>,
    walk_terminal: &C1LaneClaimGroupTrace,
    concrete_terms: Vec<C1RelationTerm>,
    trace_terms: Vec<C1RelationTermTrace>,
    powers: [ExtExpr; STATE_SIZE],
) -> Result<Vec<C1DuplexColumnClaimTrace>, RegionSidecarError> {
    if walk_terminal.point.len() != w_log {
        return Err(RegionSidecarError::InvalidProof);
    }
    let C1DuplexUnionTraceWalkPrefix {
        proof,
        mut pending,
        walk_group: _,
    } = prefix;
    let references = claimed_refs(&concrete_terms);
    if trace_terms.len() != concrete_terms.len()
        || !trace_terms
            .iter()
            .zip(&concrete_terms)
            .all(|(trace, native)| trace.factors == native.factors)
        || !preflight_c1_relation(proof.substitution, w_log, references.len())
        || !preflight_c1_shifts(proof.shifts, c1_shift_count(&references), w_log)
    {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut target = ExtExpr::zero();
    for lane in 0..STATE_SIZE {
        target = target.add(&mul_ext(b, &powers[lane], &walk_terminal.values[lane]));
    }
    let substitution =
        C1ColumnRelationProofTrace::alloc(b, proof.substitution, w_log, references.len());
    let point = verify_c1_column_relation_trace(
        b,
        channel,
        w_log,
        &target,
        &walk_terminal.point,
        &trace_terms,
        fixed,
        &substitution,
    );
    let mut shift_cursor = 0usize;
    for (reference, value) in references.iter().zip(&substitution.final_values) {
        match reference {
            ColRef::Committed(column) => pending.push(C1DuplexColumnClaimTrace {
                column: *column,
                point: point.clone(),
                value: value.clone(),
            }),
            ColRef::CommittedShift(column) | ColRef::CommittedShift2(column) => {
                let native = proof
                    .shifts
                    .get(shift_cursor)
                    .ok_or(RegionSidecarError::InvalidProof)?;
                shift_cursor += 1;
                let shift = C1ShiftDischargeProofTrace::alloc(b, native, w_log);
                let shift_log = usize::from(matches!(reference, ColRef::CommittedShift2(_)));
                let shifted = verify_c1_shift_discharge_trace(
                    b, channel, w_log, &point, value, shift_log, &shift,
                );
                pending.push(C1DuplexColumnClaimTrace {
                    column: *column,
                    point: shifted,
                    value: shift.final_value,
                });
            }
            _ => return Err(RegionSidecarError::InvalidProof),
        }
    }
    if shift_cursor != proof.shifts.len() {
        return Err(RegionSidecarError::InvalidProof);
    }
    Ok(pending)
}

pub(crate) fn verify_c1_duplex_walk_suffix_trace<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    channel: &mut C,
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    recording_refs: &[DuplexFamilyRefs],
    prefix: C1DuplexUnionTraceWalkPrefix<'_>,
    walk_terminal: &C1LaneClaimGroupTrace,
) -> Result<Vec<C1DuplexColumnClaimTrace>, RegionSidecarError> {
    let alpha = channel.sample_f256(b);
    let concrete = c1_duplex_terms(refs, recording_refs, F256::ONE);
    let (trace, powers) = c1_duplex_terms_trace(b, refs, recording_refs, &alpha);
    verify_c1_duplex_walk_suffix_trace_inner(
        b,
        channel,
        w_log,
        fixed,
        prefix,
        walk_terminal,
        concrete,
        trace,
        powers,
    )
}

pub(crate) fn verify_c1_duplex_walk_suffix_selected_trace<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    channel: &mut C,
    w_log: usize,
    fixed: &[FixedPattern],
    sets: &[DuplexFamilyRefs],
    selector: &ExtExpr,
    prefix: C1DuplexUnionTraceWalkPrefix<'_>,
    walk_terminal: &C1LaneClaimGroupTrace,
) -> Result<Vec<C1DuplexColumnClaimTrace>, RegionSidecarError> {
    let alpha = channel.sample_f256(b);
    let concrete = c1_duplex_terms_selected(sets, F128::ZERO, F256::ONE);
    let (trace, powers) = c1_duplex_terms_selected_trace(b, sets, selector, &alpha);
    verify_c1_duplex_walk_suffix_trace_inner(
        b,
        channel,
        w_log,
        fixed,
        prefix,
        walk_terminal,
        concrete,
        trace,
        powers,
    )
}

pub(crate) struct C1WalkAColumnClaimTrace {
    pub(crate) column: usize,
    pub(crate) point: Vec<ExtExpr>,
    pub(crate) value: ExtExpr,
}

pub(crate) struct C1WalkAUnionTraceWalkPrefix<'a> {
    proof: C1WalkAUnionWalkDeferredProofRef<'a>,
    pending: Vec<C1WalkAColumnClaimTrace>,
    walk_group: C1LaneClaimGroupTrace,
}

impl C1WalkAUnionTraceWalkPrefix<'_> {
    pub(crate) fn walk_group(&self) -> &C1LaneClaimGroupTrace {
        &self.walk_group
    }
}

fn push_c1_trace_terms(
    output: &mut Vec<C1RelationTermTrace>,
    coefficient: &ExtExpr,
    factors: impl IntoIterator<Item = Vec<ColRef>>,
) {
    output.extend(factors.into_iter().map(|factors| C1RelationTermTrace {
        coeff: coefficient.clone(),
        factors,
    }));
}

fn append_c1_sponge_terms_trace(
    output: &mut Vec<C1RelationTermTrace>,
    refs: &noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs,
    region: usize,
    weights: &[ExtExpr; STATE_SIZE],
) {
    let mut push = |lane: usize, mut factors: Vec<ColRef>| {
        if !factors
            .iter()
            .any(|factor| matches!(factor, ColRef::Fixed(_)))
        {
            factors.insert(0, ColRef::Fixed(region));
        }
        output.push(C1RelationTermTrace {
            coeff: weights[lane].clone(),
            factors,
        });
    };
    for lane in 0..2 {
        push(lane, vec![ColRef::Committed(refs.in_[lane])]);
        push(
            lane,
            vec![
                ColRef::Fixed(refs.odd),
                ColRef::CommittedShift(refs.c[lane]),
            ],
        );
    }
    for lane in 2..STATE_SIZE {
        push(lane, vec![ColRef::Fixed(refs.iv[lane - 2])]);
        push(
            lane,
            vec![
                ColRef::Fixed(refs.odd),
                ColRef::CommittedShift(refs.c[lane]),
            ],
        );
    }
}

fn append_c1_split_tail_terms_trace(
    output: &mut Vec<C1RelationTermTrace>,
    refs: &SplitDuplexTailRefs,
    weights: &[ExtExpr; STATE_SIZE],
) {
    for lane in 0..2 {
        push_c1_trace_terms(
            output,
            &weights[lane],
            [
                vec![ColRef::Fixed(refs.region), ColRef::Committed(refs.a[lane])],
                vec![ColRef::Fixed(refs.consts[lane])],
                vec![
                    ColRef::Fixed(refs.carry),
                    ColRef::CommittedShift(refs.c[lane]),
                ],
            ],
        );
    }
    for lane in 2..STATE_SIZE {
        push_c1_trace_terms(
            output,
            &weights[lane],
            [
                vec![
                    ColRef::Fixed(refs.first),
                    ColRef::CommittedShift(refs.a[lane - 2]),
                ],
                vec![
                    ColRef::Fixed(refs.carry),
                    ColRef::CommittedShift(refs.c[lane]),
                ],
            ],
        );
    }
}

fn append_c1_source_tree_terms_trace(
    output: &mut Vec<C1RelationTermTrace>,
    refs: &SourceTreeRefs,
    weights: &[ExtExpr; STATE_SIZE],
) {
    for lane in 0..2 {
        let kid = ColRef::Committed(refs.kid[lane]);
        let carry = ColRef::CommittedShift(refs.c[lane]);
        let code = ColRef::Committed(refs.code[lane]);
        push_c1_trace_terms(
            output,
            &weights[lane],
            [
                vec![ColRef::Fixed(refs.even_int), kid],
                vec![ColRef::Fixed(refs.odd_int), kid],
                vec![ColRef::Fixed(refs.odd_int), carry],
                vec![ColRef::Fixed(refs.leafodd), code],
            ],
        );
    }
    for lane in 2..STATE_SIZE {
        push_c1_trace_terms(
            output,
            &weights[lane],
            [
                vec![ColRef::Fixed(refs.iv[lane - 2])],
                vec![
                    ColRef::Fixed(refs.odd_int),
                    ColRef::CommittedShift(refs.c[lane]),
                ],
            ],
        );
    }
}

fn c1_walk_a_terms_trace(
    b: &mut FieldR1csBuilder,
    leaf_refs: &[(noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs, usize)],
    split_tails: &[SplitDuplexTailRefs],
    es_sponge: Option<&(noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    alpha: &ExtExpr,
) -> (Vec<C1RelationTermTrace>, [ExtExpr; STATE_SIZE]) {
    let (weights, powers) = c1_weights_trace(b, alpha);
    let mut terms = Vec::new();
    for (refs, region) in leaf_refs {
        append_c1_sponge_terms_trace(&mut terms, refs, *region, &weights);
    }
    for refs in split_tails {
        append_c1_split_tail_terms_trace(&mut terms, refs, &weights);
    }
    if let Some((refs, region)) = es_sponge {
        append_c1_sponge_terms_trace(&mut terms, refs, *region, &weights);
    }
    if let Some(spec) = spine {
        append_c1_source_tree_terms_trace(&mut terms, &spec.tree_refs, &weights);
        append_c1_sponge_terms_trace(&mut terms, &spec.wrap_refs, spec.wrap_region, &weights);
    }
    (terms, powers)
}

fn repoint_c1_spine_trace(spec: &SpineUnionSpec, point: &[ExtExpr], carry: bool) -> Vec<ExtExpr> {
    let (local, rest) = point.split_at(spec.local_log());
    let (instance, tx) = rest.split_at(spec.cap_log);
    let mut output = Vec::new();
    if carry {
        output.push(ExtExpr::one());
        output.extend_from_slice(local);
    } else {
        output.extend_from_slice(local);
        output.push(ExtExpr::zero());
    }
    output.extend_from_slice(instance);
    output.extend(
        spec.base_bits()
            .into_iter()
            .map(|value| ExtExpr::constant(F256::from_base(value))),
    );
    output.extend_from_slice(tx);
    output.extend(
        spec.walk_high_bits
            .iter()
            .copied()
            .map(|value| ExtExpr::constant(F256::from_base(value))),
    );
    output
}

#[allow(clippy::too_many_arguments)]
fn preflight_c1_walk_a(
    w_log: usize,
    carry_columns: &[usize; STATE_SIZE],
    leaf_refs: &[(noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs, usize)],
    split_tails: &[SplitDuplexTailRefs],
    es_sponge: Option<&(noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    proof: C1WalkAUnionWalkDeferredProofRef<'_>,
) -> bool {
    let selection_refs = claimed_refs(&c1_carry_selection_terms(carry_columns, F256::ONE));
    let substitution_refs = claimed_refs(&c1_walk_a_union_terms(
        leaf_refs,
        split_tails,
        es_sponge,
        spine,
        F256::ONE,
    ));
    if !preflight_c1_relation(proof.selection, w_log, selection_refs.len())
        || !preflight_c1_relation(proof.substitution, w_log, substitution_refs.len())
        || !preflight_c1_shifts(proof.shifts, c1_shift_count(&substitution_refs), w_log)
    {
        return false;
    }
    match (spine, proof.spine_exposure) {
        (None, None) => true,
        (Some(spec), Some(exposure)) => {
            let refs = claimed_refs(&c1_spine_exposure_terms(F256::ONE));
            preflight_c1_relation(exposure, spec.expo_wlog(), refs.len())
        }
        _ => false,
    }
}

pub(crate) fn verify_c1_walk_a_walk_prefix_trace<'a, C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    channel: &mut C,
    w_log: usize,
    fixed: &[FixedPattern],
    carry_columns: &[usize; STATE_SIZE],
    proof: C1WalkAUnionWalkDeferredProofRef<'a>,
) -> Result<C1WalkAUnionTraceWalkPrefix<'a>, RegionSidecarError> {
    let selection_refs = claimed_refs(&c1_carry_selection_terms(carry_columns, F256::ONE));
    if !preflight_c1_relation(proof.selection, w_log, selection_refs.len()) {
        return Err(RegionSidecarError::InvalidProof);
    }
    let beta = channel.sample_f256(b);
    let terms = c1_selection_terms_trace(b, carry_columns, &beta);
    let rho = channel.sample_f256_vec(b, w_log);
    let selection =
        C1ColumnRelationProofTrace::alloc(b, proof.selection, w_log, selection_refs.len());
    let point = verify_c1_column_relation_trace(
        b,
        channel,
        w_log,
        &ExtExpr::zero(),
        &rho,
        &terms,
        fixed,
        &selection,
    );
    let mut pending = Vec::new();
    let mut values: [ExtExpr; STATE_SIZE] = std::array::from_fn(|_| ExtExpr::zero());
    for (reference, value) in selection_refs.iter().zip(&selection.final_values) {
        match reference {
            ColRef::Committed(column) => pending.push(C1WalkAColumnClaimTrace {
                column: *column,
                point: point.clone(),
                value: value.clone(),
            }),
            ColRef::Internal(lane) if *lane < STATE_SIZE => values[*lane] = value.clone(),
            _ => return Err(RegionSidecarError::InvalidProof),
        }
    }
    Ok(C1WalkAUnionTraceWalkPrefix {
        proof,
        pending,
        walk_group: C1LaneClaimGroupTrace { point, values },
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_c1_walk_a_walk_suffix_trace<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    channel: &mut C,
    w_log: usize,
    fixed: &[FixedPattern],
    carry_columns: &[usize; STATE_SIZE],
    leaf_refs: &[(noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs, usize)],
    split_tails: &[SplitDuplexTailRefs],
    es_sponge: Option<&(noid_ivc_core::deep_chain::leaf_hash::SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    prefix: C1WalkAUnionTraceWalkPrefix<'_>,
    walk_terminal: &C1LaneClaimGroupTrace,
) -> Result<Vec<C1WalkAColumnClaimTrace>, RegionSidecarError> {
    if walk_terminal.point.len() != w_log
        || !preflight_c1_walk_a(
            w_log,
            carry_columns,
            leaf_refs,
            split_tails,
            es_sponge,
            spine,
            prefix.proof,
        )
    {
        return Err(RegionSidecarError::InvalidProof);
    }
    let C1WalkAUnionTraceWalkPrefix {
        proof,
        mut pending,
        walk_group: _,
    } = prefix;
    let alpha = channel.sample_f256(b);
    let concrete = c1_walk_a_union_terms(leaf_refs, split_tails, es_sponge, spine, F256::ONE);
    let references = claimed_refs(&concrete);
    let (terms, powers) =
        c1_walk_a_terms_trace(b, leaf_refs, split_tails, es_sponge, spine, &alpha);
    if terms.len() != concrete.len()
        || !terms
            .iter()
            .zip(&concrete)
            .all(|(trace, native)| trace.factors == native.factors)
    {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut target = ExtExpr::zero();
    for lane in 0..STATE_SIZE {
        target = target.add(&mul_ext(b, &powers[lane], &walk_terminal.values[lane]));
    }
    let substitution =
        C1ColumnRelationProofTrace::alloc(b, proof.substitution, w_log, references.len());
    let point = verify_c1_column_relation_trace(
        b,
        channel,
        w_log,
        &target,
        &walk_terminal.point,
        &terms,
        fixed,
        &substitution,
    );
    let mut shift_cursor = 0usize;
    for (reference, value) in references.iter().zip(&substitution.final_values) {
        match reference {
            ColRef::Committed(column) => pending.push(C1WalkAColumnClaimTrace {
                column: *column,
                point: point.clone(),
                value: value.clone(),
            }),
            ColRef::CommittedShift(column) | ColRef::CommittedShift2(column) => {
                let native = proof
                    .shifts
                    .get(shift_cursor)
                    .ok_or(RegionSidecarError::InvalidProof)?;
                shift_cursor += 1;
                let shift = C1ShiftDischargeProofTrace::alloc(b, native, w_log);
                let shift_log = usize::from(matches!(reference, ColRef::CommittedShift2(_)));
                let shifted = verify_c1_shift_discharge_trace(
                    b, channel, w_log, &point, value, shift_log, &shift,
                );
                pending.push(C1WalkAColumnClaimTrace {
                    column: *column,
                    point: shifted,
                    value: shift.final_value,
                });
            }
            _ => return Err(RegionSidecarError::InvalidProof),
        }
    }
    if shift_cursor != proof.shifts.len() {
        return Err(RegionSidecarError::InvalidProof);
    }

    if let (Some(spec), Some(native)) = (spine, proof.spine_exposure) {
        let gamma = channel.sample_f256(b);
        let mut power = ExtExpr::one();
        let mut terms = Vec::with_capacity(4);
        for lane in 0..2 {
            power = mul_ext(b, &power, &gamma);
            terms.push(C1RelationTermTrace {
                coeff: power.clone(),
                factors: vec![ColRef::Fixed(0), ColRef::Committed(lane)],
            });
            terms.push(C1RelationTermTrace {
                coeff: power.clone(),
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
        let concrete = c1_spine_exposure_terms(F256::ONE);
        let references = claimed_refs(&concrete);
        let exposure_log = spec.expo_wlog();
        let rho = channel.sample_f256_vec(b, exposure_log);
        let proof_trace =
            C1ColumnRelationProofTrace::alloc(b, native, exposure_log, references.len());
        let exposure_point = verify_c1_column_relation_trace(
            b,
            channel,
            exposure_log,
            &ExtExpr::zero(),
            &rho,
            &terms,
            &[spec.gate_pattern()],
            &proof_trace,
        );
        for (reference, value) in references.iter().zip(&proof_trace.final_values) {
            let (column, point) = match reference {
                ColRef::Committed(local) if *local < 2 => (
                    spec.kid_meta[*local],
                    repoint_c1_spine_trace(spec, &exposure_point, false),
                ),
                ColRef::Window {
                    col,
                    stride_log: 1,
                    offset: 1,
                } if (2..4).contains(col) => (
                    spec.c_meta[*col - 2],
                    repoint_c1_spine_trace(spec, &exposure_point, true),
                ),
                _ => return Err(RegionSidecarError::InvalidProof),
            };
            if point.len() != w_log {
                return Err(RegionSidecarError::InvalidProof);
            }
            pending.push(C1WalkAColumnClaimTrace {
                column,
                point,
                value: value.clone(),
            });
        }
    }
    Ok(pending)
}

pub(crate) struct C1MerkleColumnClaimTrace {
    pub(crate) column: usize,
    pub(crate) point: Vec<ExtExpr>,
    pub(crate) value: ExtExpr,
}

pub(crate) struct C1MerkleUnionTraceWalkPrefix<'a> {
    proof: C1MerkleUnionWalkDeferredProofRef<'a>,
    pending: Vec<C1MerkleColumnClaimTrace>,
    walk_group: C1LaneClaimGroupTrace,
}

impl C1MerkleUnionTraceWalkPrefix<'_> {
    pub(crate) fn walk_group(&self) -> &C1LaneClaimGroupTrace {
        &self.walk_group
    }
}

fn c1_merkle_zero_terms_trace(
    b: &mut FieldR1csBuilder,
    families: &[MerkleProtocolFamily],
    lambda: &ExtExpr,
) -> Vec<C1RelationTermTrace> {
    let mut terms = Vec::new();
    for family in families {
        if let MerkleProtocolFamily::TwoPermutation { refs, .. } = family {
            push_c1_trace_terms(
                &mut terms,
                &ExtExpr::one(),
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
    let lambda_squared = mul_ext(b, lambda, lambda);
    for family in families {
        if let MerkleProtocolFamily::FeedForward { refs, .. } = family {
            for (lane, weight) in [lambda.clone(), lambda_squared.clone()]
                .into_iter()
                .enumerate()
            {
                let nonstart = ColRef::Fixed(refs.nodens);
                let child = ColRef::Committed(refs.cr[lane]);
                let child_shift = ColRef::CommittedShift(refs.cr[lane]);
                let sibling_shift = ColRef::CommittedShift(refs.sib[lane]);
                let direction_shift = ColRef::CommittedShift(refs.d);
                let carry_shift = ColRef::CommittedShift(refs.c[lane]);
                push_c1_trace_terms(
                    &mut terms,
                    &weight,
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
    let mut paired_weights = Vec::new();
    if families
        .iter()
        .any(|family| matches!(family, MerkleProtocolFamily::PairedUpdate { .. }))
    {
        paired_weights.push(ExtExpr::one());
        for _ in 1..6 {
            let next = mul_ext(b, paired_weights.last().expect("paired weight"), lambda);
            paired_weights.push(next);
        }
    }
    for family in families {
        if let MerkleProtocolFamily::PairedUpdate { refs, .. } = family {
            let equations = [
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
            ];
            for (weight, (left, right)) in paired_weights.iter().zip(equations) {
                push_c1_trace_terms(&mut terms, weight, [left, right]);
            }
        }
    }
    terms
}

fn append_c1_ff_terms_trace(
    terms: &mut Vec<C1RelationTermTrace>,
    refs: &FfMerkleFamilyRefs,
    region: usize,
    weights: &[ExtExpr; STATE_SIZE],
) {
    for lane in 0..STATE_SIZE {
        terms.push(C1RelationTermTrace {
            coeff: weights[lane].clone(),
            factors: vec![ColRef::Fixed(region), ColRef::CommittedShift(refs.c[lane])],
        });
    }
    let node = ColRef::Fixed(refs.node);
    for lane in 0..2 {
        let child = ColRef::Committed(refs.cr[lane]);
        let sibling = ColRef::Committed(refs.sib[lane]);
        let direction = ColRef::Committed(refs.d);
        let carry_shift = ColRef::CommittedShift(refs.c[lane]);
        push_c1_trace_terms(
            terms,
            &weights[lane],
            [
                vec![node, carry_shift],
                vec![node, child],
                vec![node, direction, child],
                vec![node, direction, sibling],
            ],
        );
        let capacity_lane = 2 + lane;
        let capacity_shift = ColRef::CommittedShift(refs.c[capacity_lane]);
        push_c1_trace_terms(
            terms,
            &weights[capacity_lane],
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

fn append_c1_two_permutation_terms_trace(
    terms: &mut Vec<C1RelationTermTrace>,
    refs: &MerkleFamilyRefs,
    region: usize,
    weights: &[ExtExpr; STATE_SIZE],
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
        push_c1_trace_terms(
            terms,
            &weights[lane],
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
        push_c1_trace_terms(
            terms,
            &weights[lane],
            [
                vec![region, carry_shift],
                vec![ColRef::Fixed(refs.even), carry_shift],
                vec![ColRef::Fixed(refs.iv[lane - 2])],
            ],
        );
    }
}

fn append_c1_paired_terms_trace(
    terms: &mut Vec<C1RelationTermTrace>,
    refs: &PairedMerkleUpdateRefs,
    region: usize,
    weights: &[ExtExpr; STATE_SIZE],
) {
    let mut push = |lane: usize, mut factors: Vec<ColRef>| {
        if !factors
            .iter()
            .any(|factor| matches!(factor, ColRef::Fixed(_)))
        {
            factors.insert(0, ColRef::Fixed(region));
        }
        terms.push(C1RelationTermTrace {
            coeff: weights[lane].clone(),
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
            push(lane, factors);
        }
    }
    for lane in 2..STATE_SIZE {
        let carry_shift = ColRef::CommittedShift(refs.c[lane]);
        for factors in [
            vec![carry_shift],
            vec![ColRef::Fixed(refs.even), carry_shift],
            vec![ColRef::Fixed(refs.iv[lane - 2])],
        ] {
            push(lane, factors);
        }
    }
}

fn c1_merkle_substitution_terms_trace(
    b: &mut FieldR1csBuilder,
    families: &[MerkleProtocolFamily],
    alpha: &ExtExpr,
) -> (Vec<C1RelationTermTrace>, [ExtExpr; STATE_SIZE]) {
    let (weights, powers) = c1_weights_trace(b, alpha);
    let mut terms = Vec::new();
    for family in families {
        if let MerkleProtocolFamily::FeedForward { refs, region } = family {
            append_c1_ff_terms_trace(&mut terms, refs, *region, &weights);
        }
    }
    for family in families {
        if let MerkleProtocolFamily::TwoPermutation { refs, region } = family {
            append_c1_two_permutation_terms_trace(&mut terms, refs, *region, &weights);
        }
    }
    for family in families {
        if let MerkleProtocolFamily::PairedUpdate { refs, region } = family {
            append_c1_paired_terms_trace(&mut terms, refs, *region, &weights);
        }
    }
    (terms, powers)
}

fn preflight_c1_merkle(
    w_log: usize,
    carry_columns: &[usize; STATE_SIZE],
    families: &[MerkleProtocolFamily],
    proof: C1MerkleUnionWalkDeferredProofRef<'_>,
) -> bool {
    let zero_refs = claimed_refs(&c1_merkle_zero_terms(families, F256::ONE));
    let selection_refs = claimed_refs(&c1_carry_selection_terms(carry_columns, F256::ONE));
    let substitution_refs = claimed_refs(&c1_merkle_substitution_terms(families, F256::ONE));
    preflight_c1_relation(proof.zero, w_log, zero_refs.len())
        && preflight_c1_shifts(proof.zero_shifts, c1_shift_count(&zero_refs), w_log)
        && preflight_c1_relation(proof.selection, w_log, selection_refs.len())
        && preflight_c1_relation(proof.substitution, w_log, substitution_refs.len())
        && preflight_c1_shifts(proof.shifts, c1_shift_count(&substitution_refs), w_log)
}

fn verify_c1_merkle_claim_pass_trace<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    channel: &mut C,
    w_log: usize,
    references: &[ColRef],
    values: &[ExtExpr],
    point: &[ExtExpr],
    native_shifts: &[noid_ivc_core::deep_chain::relations::c1::C1ShiftDischargeProof],
) -> Result<([ExtExpr; STATE_SIZE], Vec<C1MerkleColumnClaimTrace>), RegionSidecarError> {
    if references.len() != values.len() {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut internal: [ExtExpr; STATE_SIZE] = std::array::from_fn(|_| ExtExpr::zero());
    let mut pending = Vec::new();
    let mut shift_cursor = 0usize;
    for (reference, value) in references.iter().zip(values) {
        match reference {
            ColRef::Committed(column) => pending.push(C1MerkleColumnClaimTrace {
                column: *column,
                point: point.to_vec(),
                value: value.clone(),
            }),
            ColRef::Internal(lane) if *lane < STATE_SIZE => internal[*lane] = value.clone(),
            ColRef::CommittedShift(column) | ColRef::CommittedShift2(column) => {
                let native = native_shifts
                    .get(shift_cursor)
                    .ok_or(RegionSidecarError::InvalidProof)?;
                shift_cursor += 1;
                let shift = C1ShiftDischargeProofTrace::alloc(b, native, w_log);
                let shift_log = usize::from(matches!(reference, ColRef::CommittedShift2(_)));
                let shifted = verify_c1_shift_discharge_trace(
                    b, channel, w_log, point, value, shift_log, &shift,
                );
                pending.push(C1MerkleColumnClaimTrace {
                    column: *column,
                    point: shifted,
                    value: shift.final_value,
                });
            }
            _ => return Err(RegionSidecarError::InvalidProof),
        }
    }
    if shift_cursor != native_shifts.len() {
        return Err(RegionSidecarError::InvalidProof);
    }
    Ok((internal, pending))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_c1_merkle_walk_prefix_trace<'a, C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    channel: &mut C,
    w_log: usize,
    fixed: &[FixedPattern],
    carry_columns: &[usize; STATE_SIZE],
    families: &[MerkleProtocolFamily],
    proof: C1MerkleUnionWalkDeferredProofRef<'a>,
) -> Result<C1MerkleUnionTraceWalkPrefix<'a>, RegionSidecarError> {
    if !preflight_c1_merkle(w_log, carry_columns, families, proof) {
        return Err(RegionSidecarError::InvalidProof);
    }
    let lambda = channel.sample_f256(b);
    let zero_concrete = c1_merkle_zero_terms(families, F256::ONE);
    let zero_refs = claimed_refs(&zero_concrete);
    let zero_terms = c1_merkle_zero_terms_trace(b, families, &lambda);
    if zero_terms.len() != zero_concrete.len()
        || !zero_terms
            .iter()
            .zip(&zero_concrete)
            .all(|(trace, native)| trace.factors == native.factors)
    {
        return Err(RegionSidecarError::InvalidProof);
    }
    let rho = channel.sample_f256_vec(b, w_log);
    let zero = C1ColumnRelationProofTrace::alloc(b, proof.zero, w_log, zero_refs.len());
    let zero_point = verify_c1_column_relation_trace(
        b,
        channel,
        w_log,
        &ExtExpr::zero(),
        &rho,
        &zero_terms,
        fixed,
        &zero,
    );
    let (_, mut pending) = verify_c1_merkle_claim_pass_trace(
        b,
        channel,
        w_log,
        &zero_refs,
        &zero.final_values,
        &zero_point,
        proof.zero_shifts,
    )?;

    let beta = channel.sample_f256(b);
    let selection_concrete = c1_carry_selection_terms(carry_columns, F256::ONE);
    let selection_refs = claimed_refs(&selection_concrete);
    let selection_terms = c1_selection_terms_trace(b, carry_columns, &beta);
    let rho = channel.sample_f256_vec(b, w_log);
    let selection =
        C1ColumnRelationProofTrace::alloc(b, proof.selection, w_log, selection_refs.len());
    let selection_point = verify_c1_column_relation_trace(
        b,
        channel,
        w_log,
        &ExtExpr::zero(),
        &rho,
        &selection_terms,
        fixed,
        &selection,
    );
    let (values, claims) = verify_c1_merkle_claim_pass_trace(
        b,
        channel,
        w_log,
        &selection_refs,
        &selection.final_values,
        &selection_point,
        &[],
    )?;
    pending.extend(claims);
    Ok(C1MerkleUnionTraceWalkPrefix {
        proof,
        pending,
        walk_group: C1LaneClaimGroupTrace {
            point: selection_point,
            values,
        },
    })
}

pub(crate) fn verify_c1_merkle_walk_suffix_trace<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    channel: &mut C,
    w_log: usize,
    fixed: &[FixedPattern],
    families: &[MerkleProtocolFamily],
    prefix: C1MerkleUnionTraceWalkPrefix<'_>,
    walk_terminal: &C1LaneClaimGroupTrace,
) -> Result<Vec<C1MerkleColumnClaimTrace>, RegionSidecarError> {
    if walk_terminal.point.len() != w_log {
        return Err(RegionSidecarError::InvalidProof);
    }
    let C1MerkleUnionTraceWalkPrefix {
        proof,
        mut pending,
        walk_group: _,
    } = prefix;
    let alpha = channel.sample_f256(b);
    let concrete = c1_merkle_substitution_terms(families, F256::ONE);
    let references = claimed_refs(&concrete);
    let (terms, powers) = c1_merkle_substitution_terms_trace(b, families, &alpha);
    if terms.len() != concrete.len()
        || !terms
            .iter()
            .zip(&concrete)
            .all(|(trace, native)| trace.factors == native.factors)
    {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut target = ExtExpr::zero();
    for lane in 0..STATE_SIZE {
        target = target.add(&mul_ext(b, &powers[lane], &walk_terminal.values[lane]));
    }
    let substitution =
        C1ColumnRelationProofTrace::alloc(b, proof.substitution, w_log, references.len());
    let point = verify_c1_column_relation_trace(
        b,
        channel,
        w_log,
        &target,
        &walk_terminal.point,
        &terms,
        fixed,
        &substitution,
    );
    let (_, claims) = verify_c1_merkle_claim_pass_trace(
        b,
        channel,
        w_log,
        &references,
        &substitution.final_values,
        &point,
        proof.shifts,
    )?;
    pending.extend(claims);
    Ok(pending)
}

fn c1_duplex_terms_selected_trace_n(
    b: &mut FieldR1csBuilder,
    sets: &[DuplexFamilyRefs],
    arms: usize,
    selector: &ExtExpr,
    alpha: &ExtExpr,
) -> (Vec<C1RelationTermTrace>, [ExtExpr; STATE_SIZE]) {
    if arms == 2 {
        return c1_duplex_terms_selected_trace(b, sets, selector, alpha);
    }
    assert_eq!(arms, 3);
    assert!(!sets.is_empty() && sets.len() % arms == 0);
    let nodes = [
        F128::ZERO,
        F128::ONE,
        noid_ivc_core::field_circuit::f128_from_u128(2),
    ];
    let choices = nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let mut value = ExtExpr::one();
            for (j, other) in nodes.iter().enumerate() {
                if j != i {
                    let shifted = selector.add(&ExtExpr::from_base(LinExpr::constant(*other)));
                    value = mul_ext(b, &value, &shifted).scale_base((*node + *other).inv());
                }
            }
            value
        })
        .collect::<Vec<_>>();
    let (weights, powers) = c1_weights_trace(b, alpha);
    let weighted = choices
        .iter()
        .map(|choice| {
            std::array::from_fn::<_, STATE_SIZE, _>(|lane| mul_ext(b, &weights[lane], choice))
        })
        .collect::<Vec<_>>();
    let mut terms = (0..STATE_SIZE)
        .map(|lane| C1RelationTermTrace {
            coeff: weights[lane].clone(),
            factors: vec![ColRef::CommittedShift(sets[0].c[lane])],
        })
        .collect::<Vec<_>>();
    for group in sets.chunks_exact(arms) {
        for (set, weights) in group.iter().zip(&weighted) {
            c1_duplex_pattern_terms_trace(&mut terms, set, weights);
        }
    }
    (terms, powers)
}

pub(crate) fn verify_c1_duplex_walk_suffix_selected_trace_n<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    channel: &mut C,
    w_log: usize,
    fixed: &[FixedPattern],
    sets: &[DuplexFamilyRefs],
    arms: usize,
    selector: &ExtExpr,
    prefix: C1DuplexUnionTraceWalkPrefix<'_>,
    walk_terminal: &C1LaneClaimGroupTrace,
) -> Result<Vec<C1DuplexColumnClaimTrace>, RegionSidecarError> {
    let alpha = channel.sample_f256(b);
    let concrete = c1_duplex_terms_selected_n(sets, arms, F128::ZERO, F256::ONE);
    let (trace, powers) = c1_duplex_terms_selected_trace_n(b, sets, arms, selector, &alpha);
    verify_c1_duplex_walk_suffix_trace_inner(
        b,
        channel,
        w_log,
        fixed,
        prefix,
        walk_terminal,
        concrete,
        trace,
        powers,
    )
}
