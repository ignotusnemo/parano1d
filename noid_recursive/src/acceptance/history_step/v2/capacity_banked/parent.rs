// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use noid_ivc_core::challenger::Challenger;

pub(super) fn shape_only_arm(
    runtime: &Runtime,
    class: Class,
    io: Vec<F128>,
) -> Result<(V2Proof, Scratch), V2Error> {
    let mut envelope = shape_only_envelope(runtime, class, io)?;
    let scratch = scratch_replay(runtime, class, &envelope)?;
    crate::acceptance::trace::self_verify::patch_shape_only_query_positions_c1(
        &mut envelope.field,
        &runtime.bank.config().class(class).pcs_params(),
        &scratch.query_values,
    );
    Ok((envelope, scratch))
}

pub(super) struct PreparedParent<'a> {
    pub selected: Class,
    pub current: Class,
    pub envelopes: [ParentEnvelope<'a>; 3],
    pub scratch: [Scratch; 3],
    pub folds: [C1MatrixFoldProof; 3],
    pub io: Vec<F128>,
}

pub(super) fn prepare_parent<'a, const TIER: usize>(
    runtime: &Runtime,
    current_class: Class,
    origin: &Origin,
    parent: Option<&'a Terminal>,
    current: &HistoryStepBlockInput<TIER>,
) -> Result<PreparedParent<'a>, V2Error> {
    origin.check(&runtime.bank)?;
    if runtime.bank.config().class(current_class).pages() != TIER {
        return Err(V2Error::Runtime);
    }
    if current.sealed_header.height < origin.activation_height()? {
        return Err(V2Error::Boundary);
    }
    let mut folds = Class::ALL.map(|c| zero_fold_proof(runtime.bank.config().class(c).outer_m()));
    match parent {
        None => {
            if current.start_accumulator != origin.boundary
                || current.end_accumulator.height != origin.activation_height()?
                || noid_chain::hash_block_header(&current.parent_header) != origin.parent_id
            {
                return Err(V2Error::Boundary);
            }
            let prior_io = runtime
                .bank
                .initial_io(origin, Class::Small, &origin.boundary);
            let mut envelopes = Vec::new();
            let mut scratches = Vec::new();
            for arm in Class::ALL {
                let (ghost, scratch) = shape_only_arm(runtime, arm, prior_io.clone())?;
                envelopes.push(ParentEnvelope::Local(ghost));
                scratches.push(scratch);
            }
            Ok(PreparedParent {
                selected: Class::Small,
                current: current_class,
                envelopes: envelopes.try_into().map_err(|_| V2Error::Runtime)?,
                scratch: scratches.try_into().map_err(|_| V2Error::Runtime)?,
                folds,
                io: runtime
                    .bank
                    .initial_io(origin, current_class, &current.end_accumulator),
            })
        }
        Some(parent) => {
            let parsed = runtime.bank.parse(&parent.proof.io)?;
            if parsed.origin != *origin
                || parsed.accumulator != current.start_accumulator
                || parsed.class != parent.class
            {
                return Err(V2Error::Boundary);
            }
            let selected = parsed.class;
            let (fresh, scratch) = replay(runtime, selected, &parent.proof)?;
            let incoming = parsed.claims[selected.index()].clone().unwrap_or_else(|| {
                C1MatrixAccClaim::zero(runtime.bank.config().class(selected).outer_m())
            });
            let matrix = runtime.load_matrix(selected)?;
            let mut channel = FsLaneChallenger::new_c1(FOLD_DOMAIN);
            channel.observe_label(ROUTE_DOMAIN);
            channel.observe_bytes(&[selected.wire_id()]);
            let (fold, claim) = match &matrix {
                HistoryStepMatrixLease::Resident(m) => prove_matrix_claim_fold_c1(
                    m,
                    &fresh,
                    &incoming,
                    parsed.claims[selected.index()].is_some(),
                    &mut channel,
                ),
                HistoryStepMatrixLease::Compact(m) => prove_matrix_claim_fold_compact_c1(
                    m,
                    &fresh,
                    &incoming,
                    parsed.claims[selected.index()].is_some(),
                    &mut channel,
                ),
            };
            drop(matrix);
            folds[selected.index()] = fold;
            let mut io = parent.proof.io.clone();
            install_claim(selected, &mut io, &claim)?;
            io[TIP_CLASS] = f128_from_u128(current_class.wire_id() as u128);
            io[ACC..ACC + 10].copy_from_slice(&block_acc_lanes(&current.end_accumulator));
            runtime.bank.parse(&io)?;
            let mut envelopes = Vec::new();
            let mut scratches = Vec::new();
            let mut selected_scratch = Some(scratch);
            for arm in Class::ALL {
                if arm == selected {
                    envelopes.push(ParentEnvelope::Persisted(&parent.proof));
                    scratches.push(selected_scratch.take().ok_or(V2Error::Runtime)?);
                } else {
                    let (ghost, scratch) = shape_only_arm(runtime, arm, parent.proof.io.clone())?;
                    envelopes.push(ParentEnvelope::Local(ghost));
                    scratches.push(scratch);
                }
            }
            Ok(PreparedParent {
                selected,
                current: current_class,
                envelopes: envelopes.try_into().map_err(|_| V2Error::Runtime)?,
                scratch: scratches.try_into().map_err(|_| V2Error::Runtime)?,
                folds,
                io,
            })
        }
    }
}

fn shape_only_envelope(runtime: &Runtime, class: Class, io: Vec<F128>) -> Result<V2Proof, V2Error> {
    let (field, root) = shape_only_field_r1cs_proof_c1(
        &runtime.bank.config().class(class).shape(),
        &runtime.bank.config().class(class).pcs_params(),
    );
    Ok(V2Proof {
        field,
        commitment: Commitment {
            root,
            params: runtime.bank.config().class(class).pcs_params(),
        },
        io,
        sidecar: shape_only_joint_c1_region_sidecar_proof(
            &runtime.parts.parent_vk,
            runtime.parts.block_vk(class),
            runtime.bank.config().class(class).outer_m(),
        )?,
    })
}

fn scratch_replay(runtime: &Runtime, class: Class, envelope: &V2Proof) -> Result<Scratch, V2Error> {
    let mut builder = FieldR1csBuilder::new_witness_only();
    let statement = alloc_pinned_flat_digest(&mut builder, &runtime.bank.matrix_digest(class));
    let post = alloc_pinned_flat_digest(&mut builder, &runtime.bank.post_commit_digest(class));
    let root = alloc_flat_digest(&mut builder, &envelope.commitment.root);
    let io = envelope
        .io
        .iter()
        .map(|v| LinExpr::from_wire(builder.alloc_f128(*v)))
        .collect::<Vec<_>>();
    let proof = C1FieldR1csProofTrace::alloc_shape_mode(
        &mut builder,
        &envelope.field,
        &runtime.bank.config().class(class).shape(),
        &runtime.bank.config().class(class).pcs_params(),
        false,
    );
    let mut channel = FsChannelUnionRecorder::new_c1(PROOF_DOMAIN);
    let mut child = None;
    let mut error = None;
    verify_field_c1_trace_deferred_region_with_post_commit_context_expr(
        &mut builder,
        &mut channel,
        &runtime.bank.config().class(class).shape(),
        &runtime.bank.config().class(class).pcs_params(),
        &statement,
        &root,
        &proof,
        &runtime.bank.config().io_spec(),
        &io,
        &post,
        Some(&mut PcsWalkObligations::default()),
        |builder, context| match verify_joint_c1_region_sidecar_trace_post_commit(
            builder,
            context,
            &runtime.parts.parent_vk,
            runtime.parts.block_vk(class),
            &envelope.sidecar,
        ) {
            Ok(recording) => child = Some(recording),
            Err(e) => error = Some(e),
        },
    );
    if let Some(error) = error {
        return Err(error.into());
    }
    let parent = channel.finish();
    let start = parent
        .challenge_wires
        .len()
        .checked_sub(history_step_query_lane_count(
            &runtime.bank.config().class(class).pcs_params(),
        ))
        .ok_or(V2Error::Layout)?;
    Ok(Scratch {
        child: capture_scratch_recording(&child.ok_or(V2Error::Layout)?, &builder),
        query_values: parent.challenge_wires[start..]
            .iter()
            .map(|v| v.eval(builder.values()))
            .collect(),
        parent: capture_scratch_recording(&parent, &builder),
    })
}

pub(super) fn replay(
    runtime: &Runtime,
    class: Class,
    envelope: &V2Proof,
) -> Result<(C1FreshLincheckClaim, Scratch), V2Error> {
    if pcs_params_statement_bytes(&envelope.commitment.params)
        != pcs_params_statement_bytes(&runtime.bank.config().class(class).pcs_params())
    {
        return Err(V2Error::Runtime);
    }
    if runtime.bank.parse(&envelope.io)?.class != class {
        return Err(V2Error::Io);
    }
    let mut channel =
        LayoutRecordingChallenger::new_c1(PROOF_DOMAIN, runtime.parts.parent_layout(class).clone());
    let mut child = None;
    let (_, fresh) = verify_field_c1_deferred_matrix_with_post_commit_context(
        &runtime.bank.config().class(class).shape(),
        &runtime.bank.matrix_digest(class),
        &envelope.commitment,
        &envelope.field,
        &runtime.bank.config().io_spec(),
        &envelope.io,
        &runtime.bank.post_commit_digest(class),
        &envelope.sidecar,
        &mut channel,
        |sidecar, context| {
            child = Some(
                verify_joint_c1_region_sidecar_post_commit_layout_captured(
                    &runtime.parts.parent_vk,
                    runtime.parts.block_vk(class),
                    sidecar,
                    context,
                    runtime.parts.child_layout(class).clone(),
                )
                .map_err(|_| VerifyError::Auxiliary)?,
            );
            Ok(())
        },
    )?;
    Ok((
        fresh,
        Scratch {
            child: child.ok_or(V2Error::Layout)?,
            parent: channel.finish().map_err(|_| V2Error::Layout)?,
            query_values: Vec::new(),
        },
    ))
}
