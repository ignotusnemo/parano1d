use super::*;
use crate::acceptance::trace::{
    matrix_fold::C1FreshLincheckClaimTrace,
    self_verify::{
        finish_field_c1_deferred_prefix, prepare_field_c1_deferred_prefix,
        C1DeferredFieldPrefixTrace, C1QuirkyDirectClaimTrace, FlatDigestExpr,
    },
};
use noid_ivc_core::field_circuit::{FsChannelOps, RecordedChannel};

pub(super) struct ArmReplay {
    pub fresh: C1FreshLincheckClaimTrace,
    pub obligations: PcsWalkObligations,
    pub child: RecordedChannel,
    pub parent: RecordedChannel,
}

fn choose(b: &mut FieldR1csBuilder, selector: &LinExpr, zero: &LinExpr, one: &LinExpr) -> LinExpr {
    if zero == one {
        return zero.clone();
    }
    zero.add(&mul(b, selector, &zero.add(one)))
}

fn choose_ext(
    b: &mut FieldR1csBuilder,
    selector: &LinExpr,
    zero: &ExtExpr,
    one: &ExtExpr,
) -> ExtExpr {
    ExtExpr::new(
        choose(b, selector, &zero.lo, &one.lo),
        choose(b, selector, &zero.hi, &one.hi),
    )
}

fn select_claims(
    b: &mut FieldR1csBuilder,
    selector: &LinExpr,
    zero: C1DeferredFieldPrefixTrace,
    one: C1DeferredFieldPrefixTrace,
) -> Result<C1DeferredFieldPrefixTrace, V2Error> {
    if zero.claims.len() != one.claims.len() {
        return Err(V2Error::Layout);
    }
    let mut claims = Vec::with_capacity(zero.claims.len());
    for (zero, one) in zero.claims.into_iter().zip(one.claims) {
        if zero.k_skip != one.k_skip || zero.x_rest.len() != one.x_rest.len() {
            return Err(V2Error::Layout);
        }
        claims.push(C1QuirkyDirectClaimTrace {
            k_skip: zero.k_skip,
            z_skip: choose_ext(b, selector, &zero.z_skip, &one.z_skip),
            x_rest: zero
                .x_rest
                .iter()
                .zip(&one.x_rest)
                .map(|(zero, one)| choose_ext(b, selector, zero, one))
                .collect(),
            value: choose_ext(b, selector, &zero.value, &one.value),
        });
    }
    Ok(C1DeferredFieldPrefixTrace { claims })
}

pub(super) fn replay_shared(
    b: &mut FieldR1csBuilder,
    runtime: &Runtime,
    selected: Class,
    gate: &LinExpr,
    selectors: &[LinExpr; 3],
    prev: &[LinExpr],
    roots: &[FlatDigestExpr],
    envelopes: &[ParentEnvelope<'_>; 3],
) -> Result<[ArmReplay; 2], V2Error> {
    let config = runtime.bank.config();
    let large = config.class(Class::Large);
    let native = config.class(Class::Native);
    if large.shape() != native.shape()
        || pcs_params_statement_bytes(&large.pcs_params())
            != pcs_params_statement_bytes(&native.pcs_params())
        || runtime.parts.parent_layout(Class::Large) != runtime.parts.parent_layout(Class::Native)
    {
        return Err(V2Error::Layout);
    }
    let selector = &selectors[Class::Native.index()];
    let root = std::array::from_fn(|lane| choose(b, selector, &roots[1][lane], &roots[2][lane]));
    let proof_class = if selected == Class::Native {
        Class::Native
    } else {
        Class::Large
    };
    let proof = C1FieldR1csProofTrace::alloc_shape_mode(
        b,
        &envelopes[proof_class.index()].proof().field,
        &large.shape(),
        &large.pcs_params(),
        false,
    );
    let mut prefixes = Vec::new();
    let mut recorders = Vec::new();
    let mut children = Vec::new();
    for arm in [Class::Large, Class::Native] {
        let slot = arm.index();
        let arm_gate = mul(b, gate, &selectors[slot]);
        let mut recorder = BaseSelectableParentRecorder::new_c1(PROOF_DOMAIN);
        let mut child = None;
        let mut error = None;
        let prefix = with_pin_gate(&arm_gate, || {
            prepare_field_c1_deferred_prefix(
                b,
                &mut recorder,
                &large.shape(),
                &large.pcs_params(),
                &[
                    prev[MATRIX + 2 * slot].clone(),
                    prev[MATRIX + 2 * slot + 1].clone(),
                ],
                &root,
                &config.io_spec(),
                prev,
                &[
                    prev[POST + 2 * slot].clone(),
                    prev[POST + 2 * slot + 1].clone(),
                ],
                |builder, context| match verify_joint_c1_region_sidecar_trace_post_commit(
                    builder,
                    context,
                    &runtime.parts.parent_vk,
                    runtime.parts.block_vk(arm),
                    &envelopes[slot].proof().sidecar,
                ) {
                    Ok(recording) => child = Some(recording),
                    Err(e) => error = Some(e),
                },
            )
        });
        if let Some(error) = error {
            return Err(error.into());
        }
        prefixes.push(prefix);
        recorders.push(recorder);
        children.push(child.ok_or(V2Error::Layout)?);
    }
    let [zero, one]: [_; 2] = prefixes.try_into().map_err(|_| V2Error::Runtime)?;
    let prefix = select_claims(b, selector, zero, one)?;
    let [zero, one]: [_; 2] = recorders.try_into().map_err(|_| V2Error::Runtime)?;
    let mut recorder = BaseSelectableParentRecorder::select_prefix(b, selector, zero, one)
        .ok_or(V2Error::Layout)?;
    let shared_gate = mul(b, gate, &selectors[1].add(&selectors[2]));
    let mut obligations = PcsWalkObligations::default();
    let (_, fresh) = with_pin_gate(&shared_gate, || {
        finish_field_c1_deferred_prefix(
            b,
            &mut recorder,
            &large.shape(),
            &large.pcs_params(),
            &root,
            &proof,
            prefix,
            Some(&mut obligations),
        )
    });
    let parent = recorder.finish();
    let [large_child, native_child]: [_; 2] = children.try_into().map_err(|_| V2Error::Runtime)?;
    Ok([
        ArmReplay {
            fresh: fresh.clone(),
            obligations: obligations.clone(),
            child: large_child,
            parent: parent.clone(),
        },
        ArmReplay {
            fresh,
            obligations,
            child: native_child,
            parent,
        },
    ])
}
