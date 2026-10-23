// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use parent::{prepare_parent, PreparedParent};

pub struct Built {
    class: Class,
    matrix: HistoryStepMatrixLease,
    witness: Vec<F128>,
    io: Vec<F128>,
    preparations: Preparations,
}

struct Assembly {
    class: Class,
    builder: FieldR1csBuilder,
    block: SelectedZkBlockSlotsAssembly,
    parent: HistoryStepParentRegionPreparation,
    io_seal: DeferredHistoryStepIo,
    io: Vec<F128>,
    matrix: Option<HistoryStepMatrixLease>,
}

fn parent_selector(
    builder: &mut FieldR1csBuilder,
    authenticated: &LinExpr,
    class: Class,
) -> [LinExpr; 3] {
    let selectors = Class::ALL.map(|arm| LinExpr::from_wire(builder.alloc_bool(class == arm)));
    let mut total = LinExpr::zero();
    let mut code = LinExpr::zero();
    for (index, selector) in selectors.iter().enumerate() {
        total = total.add(selector);
        code = code.add(&selector.scale(f128_from_u128(index as u128)));
        for other in &selectors[..index] {
            let both = mul(builder, selector, other);
            pin_eq(builder, &both, &LinExpr::zero());
        }
    }
    pin_eq(builder, &total, &LinExpr::constant(F128::ONE));
    pin_eq(builder, authenticated, &code);
    selectors
}

/// Exact carry is part of the relation, including a previously used large
/// matrix after returning to small blocks. The inactive fold has no authority.
fn bind_lane(
    builder: &mut FieldR1csBuilder,
    cells: &[LinExpr],
    prev: &[LinExpr],
    lane: Lane,
    gate: &LinExpr,
    folded: &C1MatrixAccClaimTrace,
) {
    let outputs = folded
        .point
        .iter()
        .flat_map(|p| [&p.lo, &p.hi])
        .chain([&folded.value.lo, &folded.value.hi]);
    for (offset, value) in (lane.point..lane.live).zip(outputs) {
        let delta = mul(builder, gate, &value.add(&prev[offset]));
        pin_eq(builder, &cells[offset], &prev[offset].add(&delta));
    }
    let delta = mul(builder, gate, &prev[lane.live].add_const(F128::ONE));
    pin_eq(builder, &cells[lane.live], &prev[lane.live].add(&delta));
}

fn prepare_assembly<const TIER: usize>(
    runtime: &Runtime,
    prepared: PreparedParent<'_>,
    current: HistoryStepBlockInput<TIER>,
    frozen: bool,
    record_matrix_rows: bool,
) -> Result<Assembly, V2Error> {
    let PreparedParent {
        selected,
        current: class,
        envelopes,
        scratch,
        folds,
        io,
    } = prepared;
    let config = runtime.bank.config().class(class);
    if config.pages() != TIER {
        return Err(V2Error::Runtime);
    }
    let matrix = if frozen {
        None
    } else {
        Some(runtime.load_matrix(class)?)
    };
    let mut builder = if record_matrix_rows {
        FieldR1csBuilder::new()
    } else {
        FieldR1csBuilder::new_witness_only()
    };
    if std::env::var_os("NOID_PRODUCT_OBSERVATIONS").is_some() {
        builder.observe_symbolic_products(65536);
    }
    if runtime.bank.config().product_aliases() {
        builder.enable_symbolic_product_aliases();
    }
    if runtime.bank.config().reuses_linear_rows() {
        builder.enable_reused_linear_rows();
    }
    if runtime.bank.config().fused_pins() {
        builder.enable_fused_boolean_pins();
    }
    let mut row_ledger = 0;
    let (cells, io_seal) =
        allocate_deferred_history_step_io(&mut builder, &runtime.bank.config().io_spec(), &io, ACC);
    let gate = cells[BASE].add_const(F128::ONE);
    let boolean = mul(&mut builder, &cells[BASE], &gate);
    pin_eq(&mut builder, &boolean, &LinExpr::zero());
    pin_eq(
        &mut builder,
        &cells[TIP_CLASS],
        &LinExpr::constant(f128_from_u128(class.wire_id() as u128)),
    );
    let params = Class::ALL.map(|c| runtime.bank.config().class(c).pcs_params());
    let r_proofs = Class::ALL.map(|c| RPcsProof {
        native: &envelopes[c.index()].proof().field.pcs_open,
        params: &params[c.index()],
        commitment_root: flat_digest_lanes(&envelopes[c.index()].proof().commitment.root),
    });
    let (children, parents): (Vec<_>, Vec<_>) =
        scratch.into_iter().map(|s| (s.child, s.parent)).unzip();
    let mut columns = prepare_history_step_parent_columns(
        &mut builder,
        &r_proofs,
        selected.index(),
        &runtime.parts.geometry,
        children,
        parents,
    )?;
    crate::acceptance::row_ledger_mark(&builder, &mut row_ledger, "bank: IO and parent columns");
    let HistoryStepBlockInput {
        start_accumulator,
        end_accumulator,
        components,
        authorization,
        sealed_header,
        parent_header,
        ..
    } = current;
    let parent_seal = ParentSealTrace::alloc(&mut builder, &parent_header);
    let block = build_block_slots_selected_zk_prefix(
        &mut builder,
        &start_accumulator,
        &end_accumulator,
        &components,
        &sealed_header,
        TIER,
        authorization,
        &parent_header,
        &parent_seal.block_id,
        BlockRelationProfile::ScheduledV2(config),
    );
    pin_eq(
        &mut builder,
        &parent_seal.height,
        &block.slots().start_acc.height,
    );
    pin_eq(
        &mut builder,
        &cells[ORIGIN_ACC],
        &LinExpr::constant(flat_of(noid_core::Block128(
            (config.activation_height() - 1) as u128,
        ))),
    );
    crate::acceptance::row_ledger_mark(&builder, &mut row_ledger, "bank: complete block prefix");
    let roots = envelopes
        .iter()
        .map(|e| alloc_flat_digest(&mut builder, &e.proof().commitment.root))
        .collect::<Vec<_>>();
    let prev = envelopes[selected.index()]
        .proof()
        .io
        .iter()
        .map(|v| LinExpr::from_wire(builder.alloc_f128(*v)))
        .collect::<Vec<_>>();
    let selectors = parent_selector(&mut builder, &prev[TIP_CLASS], selected);
    // The entire ordered bank and sealed legacy boundary are inherited.
    for index in BANK..POINT {
        pin_eq(&mut builder, &cells[index], &prev[index]);
    }
    let mut obligations = Vec::new();
    let mut recorded_children = Vec::new();
    let mut recorded_parents = Vec::new();
    let mut shared = None;
    for arm in Class::ALL {
        let slot = arm.index();
        let entry = runtime.bank.config().class(arm);
        let envelope = envelopes[slot].proof();
        let arm_gate = mul(&mut builder, &gate, &selectors[slot]);
        let replay = if runtime.bank.config().shared_m24() && arm != Class::Small {
            if arm == Class::Large {
                shared = Some(
                    shared_parent::replay_shared(
                        &mut builder,
                        runtime,
                        selected,
                        &gate,
                        &selectors,
                        &prev,
                        &roots,
                        &envelopes,
                    )?
                    .map(Some),
                );
            }
            shared.as_mut().ok_or(V2Error::Runtime)?[slot - 1]
                .take()
                .ok_or(V2Error::Runtime)?
        } else {
            let proof = C1FieldR1csProofTrace::alloc_shape_mode(
                &mut builder,
                &envelope.field,
                &entry.shape(),
                &params[slot],
                false,
            );
            let mut arm_obligations = PcsWalkObligations::default();
            let mut recorder = BaseSelectableParentRecorder::new_c1(PROOF_DOMAIN);
            let mut child = None;
            let mut error = None;
            let (_, fresh) = with_pin_gate(&arm_gate, || {
                verify_field_c1_trace_deferred_region_with_post_commit_context_expr(
                    &mut builder,
                    &mut recorder,
                    &entry.shape(),
                    &params[slot],
                    &[
                        prev[MATRIX + 2 * slot].clone(),
                        prev[MATRIX + 2 * slot + 1].clone(),
                    ],
                    &roots[slot],
                    &proof,
                    &runtime.bank.config().io_spec(),
                    &prev,
                    &[
                        prev[POST + 2 * slot].clone(),
                        prev[POST + 2 * slot + 1].clone(),
                    ],
                    Some(&mut arm_obligations),
                    |builder, context| match verify_joint_c1_region_sidecar_trace_post_commit(
                        builder,
                        context,
                        &runtime.parts.parent_vk,
                        runtime.parts.block_vk(arm),
                        &envelope.sidecar,
                    ) {
                        Ok(recording) => child = Some(recording),
                        Err(e) => error = Some(e),
                    },
                )
            });
            if let Some(error) = error {
                return Err(error.into());
            }
            shared_parent::ArmReplay {
                fresh,
                obligations: arm_obligations,
                child: child.ok_or(V2Error::Layout)?,
                parent: recorder.finish(),
            }
        };
        let shared_parent::ArmReplay {
            fresh,
            obligations: arm_obligations,
            child,
            parent,
        } = replay;
        obligations.push(arm_obligations);
        recorded_children.push(child);
        recorded_parents.push(parent);
        let lane = Lane::for_class(arm);
        let incoming = C1MatrixAccClaimTrace {
            point: prev[lane.point..lane.value]
                .chunks_exact(2)
                .map(|x| ExtExpr::new(x[0].clone(), x[1].clone()))
                .collect(),
            value: ExtExpr::new(prev[lane.value].clone(), prev[lane.value + 1].clone()),
        };
        let fold = C1MatrixFoldProofTrace::alloc(&mut builder, &folds[slot], entry.outer_m());
        let mut channel = FsChannelTrace::new_c1(&mut builder, FOLD_DOMAIN);
        channel.observe_label(&mut builder, ROUTE_DOMAIN);
        channel.observe_lanes(&mut builder, 1, std::slice::from_ref(&prev[TIP_CLASS]));
        let outgoing = with_pin_gate(&arm_gate, || {
            verify_matrix_claim_fold_c1_trace(
                &mut builder,
                &mut channel,
                entry.shape().k_log,
                entry.shape().k_skip,
                &fresh,
                &incoming,
                &prev[lane.live],
                &fold,
            )
        });
        bind_lane(&mut builder, &cells, &prev, lane, &arm_gate, &outgoing);
        crate::acceptance::row_ledger_mark(
            &builder,
            &mut row_ledger,
            &format!("bank: parent verifier and fold {arm:?}"),
        );
        // A new origin cannot import an unchecked v2 matrix claim.
        with_pin_gate(&cells[BASE], || {
            for cell in &cells[lane.point..=lane.live] {
                pin_eq(&mut builder, cell, &LinExpr::zero());
            }
        });
    }
    if runtime.bank.config().shared_m24() {
        columns.align_shared_replay_hints(&builder, &recorded_children, &recorded_parents)?;
    }
    let finalize = if runtime.bank.config().shared_m24() {
        crate::acceptance::trace::r_pcs_region::finalize_shared_history_step_parent_region
    } else {
        finalize_history_step_parent_region
    };
    let parent = with_pin_gate(&gate, || {
        finalize(
            &mut builder,
            columns,
            &obligations,
            &selectors,
            &recorded_children,
            &recorded_parents,
        )
    })?;
    crate::acceptance::row_ledger_mark(
        &builder,
        &mut row_ledger,
        "bank: parent column finalization",
    );
    for lane in 0..2 {
        with_pin_gate(&gate, || {
            pin_eq(
                &mut builder,
                &parent_seal.semantic_id[lane],
                &prev[ACC + 1 + lane],
            )
        });
        with_pin_gate(&cells[BASE], || {
            pin_eq(
                &mut builder,
                &parent_seal.block_id[lane],
                &cells[ORIGIN_ID + lane],
            );
            pin_eq(
                &mut builder,
                &parent_seal.semantic_id[lane],
                &cells[ORIGIN_ACC + 1 + lane],
            );
        });
    }
    for (index, start) in block.slots().start_acc.ordered_lanes().iter().enumerate() {
        with_pin_gate(&gate, || pin_eq(&mut builder, start, &prev[ACC + index]));
        with_pin_gate(&cells[BASE], || {
            pin_eq(&mut builder, start, &cells[ORIGIN_ACC + index])
        });
    }
    for (index, end) in block.slots().end_acc.ordered_lanes().iter().enumerate() {
        pin_eq(&mut builder, end, &cells[ACC + index]);
    }
    Ok(Assembly {
        class,
        builder,
        block,
        parent,
        io_seal,
        io,
        matrix,
    })
}

enum AssemblyOutput {
    Frozen(FrozenV2),
    Built(Built),
}

fn finish_assembly(
    runtime: &Runtime,
    assembly: Assembly,
    header: &BlockHeader,
    end: &ChainAccumulator,
) -> Result<AssemblyOutput, V2Error> {
    let Assembly {
        class,
        mut builder,
        mut block,
        parent,
        io_seal,
        mut io,
        matrix,
    } = assembly;
    let config = runtime.bank.config().class(class);
    io_seal.seal(&mut builder, &mut io, ACC, end)?;
    block
        .seal_direct_tail(&mut builder, header, end)
        .map_err(|_| V2Error::Boundary)?;
    if let Some(stats) = builder.product_observation() {
        eprintln!("[products] class={class:?} products={} eligible={} repeated={} clears={} maximum_entries={} nested_bytes={}",stats.products,stats.eligible,stats.repeated,stats.clear_count,stats.maximum_entries,stats.nested_bytes);
        if builder.uses_fused_boolean_pins() {
            eprintln!(
                "[fused-pins] class={class:?} stats={:?}",
                builder.boolean_pin_observation()
            );
        }
        eprintln!(
            "[linear-pins] class={class:?} reused={}",
            builder.reused_linear_pins()
        );
        eprintln!(
            "[product-aliases] class={class:?} stats={:?}",
            builder.product_alias_observation()
        );
    }
    let used = builder.num_wires();
    let limit = 1usize << config.outer_m();
    if used > limit {
        return Err(V2Error::Shape { used, limit });
    }
    let block = finalize_selected_zk_block_region(block, config.outer_m())?;
    let preparations = Preparations { parent, block };
    match matrix {
        None => {
            let (matrix, witness) = builder.build();
            let (matrix, witness) =
                crate::acceptance::expand_empty_field_tail(matrix, witness, config.shape());
            Ok(AssemblyOutput::Frozen(FrozenV2 {
                matrix,
                witness,
                preparations,
            }))
        }
        Some(matrix) => {
            let (_, mut witness) = builder.build_witness_only();
            witness.resize(limit, F128::ZERO);
            if used != matrix.useful_rows()
                || preparations.parent.vk() != runtime.parts.parent_vk()
                || preparations.block.vk() != runtime.parts.block_vk(class)
            {
                return Err(V2Error::Runtime);
            }
            runtime.bank.parse(&io)?;
            Ok(AssemblyOutput::Built(Built {
                class,
                matrix,
                witness,
                io,
                preparations,
            }))
        }
    }
}

pub fn assemble_frozen<const TIER: usize>(
    runtime: &Runtime,
    class: Class,
    origin: &Origin,
    parent: Option<&Terminal>,
    current: HistoryStepBlockInput<TIER>,
) -> Result<FrozenV2, V2Error> {
    let prepared = prepare_parent(runtime, class, origin, parent, &current)?;
    let header = current.sealed_header;
    let end = current.end_accumulator.clone();
    let assembly = prepare_assembly(runtime, prepared, current, true, true)?;
    match finish_assembly(runtime, assembly, &header, &end)? {
        AssemblyOutput::Frozen(frozen) => Ok(frozen),
        _ => unreachable!("frozen assembly"),
    }
}

pub fn derive_assembled_block_vk<const TIER: usize>(
    runtime: &Runtime,
    class: Class,
    origin: &Origin,
    parent: Option<&Terminal>,
    current: HistoryStepBlockInput<TIER>,
) -> Result<(BlockRegionSidecarVk, usize), V2Error> {
    let prepared = prepare_parent(runtime, class, origin, parent, &current)?;
    let header = current.sealed_header;
    let end = current.end_accumulator.clone();
    let Assembly {
        mut builder,
        mut block,
        parent,
        io_seal,
        mut io,
        matrix,
        ..
    } = prepare_assembly(runtime, prepared, current, true, false)?;
    if matrix.is_some() || parent.vk() != runtime.parts.parent_vk() {
        return Err(V2Error::Runtime);
    }
    io_seal.seal(&mut builder, &mut io, ACC, &end)?;
    block
        .seal_direct_tail(&mut builder, &header, &end)
        .map_err(|_| V2Error::Boundary)?;
    let used = builder.num_wires();
    let limit = 1usize << runtime.bank.config().class(class).outer_m();
    if used > limit {
        return Err(V2Error::Shape { used, limit });
    }
    let block =
        finalize_selected_zk_block_region(block, runtime.bank.config().class(class).outer_m())?;
    let vk = block.vk().clone();
    let (count, _) = builder.build_witness_only();
    if count != used {
        return Err(V2Error::Runtime);
    }
    Ok((vk, used))
}

#[must_use = "dropping this value cancels the unsealed block attempt"]
pub struct PreparedForPow {
    assembly: Assembly,
    header: BlockHeader,
    parent_header: BlockHeader,
    start: ChainAccumulator,
}

pub fn prepare_for_pow<const TIER: usize>(
    runtime: &Runtime,
    class: Class,
    origin: &Origin,
    parent: Option<&Terminal>,
    current: HistoryStepBlockInput<TIER>,
) -> Result<PreparedForPow, V2Error> {
    if current.sealed_header.nonce != 0 {
        return Err(V2Error::Boundary);
    }
    let prepared = prepare_parent(runtime, class, origin, parent, &current)?;
    let header = current.sealed_header;
    let parent_header = current.parent_header;
    let start = current.start_accumulator.clone();
    Ok(PreparedForPow {
        assembly: prepare_assembly(runtime, prepared, current, false, false)?,
        header,
        parent_header,
        start,
    })
}
impl PreparedForPow {
    pub fn retained_witness_bytes(&self) -> usize {
        self.assembly.builder.retained_witness_bytes()
    }
    pub fn seal_nonce(mut self, runtime: &Runtime, nonce: u128) -> Result<Built, V2Error> {
        self.header.nonce = nonce;
        let end = self
            .start
            .advance(&self.parent_header, &self.header)
            .map_err(|_| V2Error::Boundary)?;
        match finish_assembly(runtime, self.assembly, &self.header, &end)? {
            AssemblyOutput::Built(built) => Ok(built),
            _ => unreachable!("witness assembly"),
        }
    }
}

pub fn prove_built(
    runtime: &Runtime,
    built: &Built,
    cancellation: &std::sync::atomic::AtomicBool,
) -> Result<Terminal, V2Error> {
    if cancellation.load(std::sync::atomic::Ordering::Acquire) {
        return Err(V2Error::Cancelled);
    }
    let class = built.class;
    let config = runtime.bank.config().class(class);
    runtime.bank.authenticate(class, &built.matrix)?;
    if runtime.bank.parse(&built.io)?.class != class {
        return Err(V2Error::Io);
    }
    if built.preparations.parent.vk() != runtime.parts.parent_vk()
        || built.preparations.block.vk() != runtime.parts.block_vk(class)
    {
        return Err(V2Error::Runtime);
    }
    let params = config.pcs_params();
    let spec = runtime.bank.config().io_spec();
    macro_rules! prove {
        ($function:path, $matrix:expr) => {{
            let parent = built.preparations.parent.certified_c1_prover_plan()?;
            let block = built.preparations.block.certified_c1_prover_plan()?;
            let mut channel = FsLaneChallenger::new_c1(PROOF_DOMAIN);
            $function(
                $matrix,
                &built.witness,
                &params,
                &spec,
                &built.io,
                &runtime.bank.post_commit_digest(class),
                cancellation,
                &mut channel,
                |context| -> Result<JointC1RegionSidecarProof, RegionSidecarError> {
                    let (proof, claims) = crate::region_sidecar::prove_joint_c1_region_sidecar(
                        &parent,
                        &block,
                        context.witness(),
                        context,
                    )?;
                    context.append_c1_claims(claims);
                    Ok(proof)
                },
            )
            .map_err(|_| V2Error::Cancelled)
        }};
    }
    let (field, sidecar, commitment, _) = match &built.matrix {
        HistoryStepMatrixLease::Resident(m) => prove!(
            prove_field_c1_with_public_io_and_post_commit_context_cancellable,
            m.as_ref()
        ),
        HistoryStepMatrixLease::Compact(m) => prove!(
            prove_field_compact_c1_with_public_io_and_post_commit_context_cancellable,
            m.as_ref()
        ),
    }?;
    if cancellation.load(std::sync::atomic::Ordering::Acquire) {
        return Err(V2Error::Cancelled);
    }
    Ok(Terminal {
        class,
        proof: V2Proof {
            field,
            commitment,
            io: built.io.clone(),
            sidecar: sidecar?,
        },
    })
}
