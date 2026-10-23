// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Scheduled single-class recursion. The first v2 block starts at an
//! authenticated legacy terminal, never at a replacement genesis. All later
//! blocks carry that origin unchanged. Acceptance requires an authenticated
//! legacy origin and the current proof's complete matrix obligations.

use super::gated_recorder::BaseSelectableParentRecorder;
use super::relation::{
    allocate_deferred_history_step_io, capture_scratch_recording, history_step_query_lane_count,
    placeholder_history_step_recording_layout, zero_fold_proof, DeferredHistoryStepIo,
};
use super::*;
use crate::acceptance::history_step_bank::block_acc_lanes;
use noid_ivc_core::field_circuit::ExtExpr;
use noid_ivc_core::matrix_claim::c1::{
    prove_matrix_claim_fold_c1, prove_matrix_claim_fold_compact_c1, C1MatrixAccClaim,
};

mod bank;
pub mod banked;
pub mod capacity_banked;
mod config;
mod wire;
use bank::*;
pub use bank::{V2Bank, V2Origin, VerifiedV2Origin};
pub use config::{NativeFinancialConfig, V2Config};
pub use wire::{decode_terminal, encode_terminal, terminal_max_bytes, V2_TERMINAL_VERSION};

const PROOF_DOMAIN: &[u8] = b"history-step-single-v2";

#[derive(Debug)]
pub enum V2Error {
    Legacy(HistoryStepError),
    Region(RegionSidecarError),
    Proof(VerifyError),
    Runtime,
    Matrix,
    Io,
    Boundary,
    Origin,
    Retirement(String),
    Layout,
    Shape { used: usize, limit: usize },
    Cancelled,
}
impl core::fmt::Display for V2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "v2 HistoryStep: {self:?}")
    }
}
impl std::error::Error for V2Error {}
impl From<HistoryStepError> for V2Error {
    fn from(e: HistoryStepError) -> Self {
        Self::Legacy(e)
    }
}
impl From<RegionSidecarError> for V2Error {
    fn from(e: RegionSidecarError) -> Self {
        Self::Region(e)
    }
}
impl From<VerifyError> for V2Error {
    fn from(e: VerifyError) -> Self {
        Self::Proof(e)
    }
}

#[derive(Clone, Debug)]
pub struct V2RuntimeParts {
    config: V2Config,
    parent_vk: LinkRegionSidecarVk,
    block_vk: BlockRegionSidecarVk,
    child_layout: DuplexLayout,
    parent_layout: DuplexLayout,
    geometry: HistoryStepParentGeometry,
}

impl V2RuntimeParts {
    pub fn new(
        config: V2Config,
        block_vk: BlockRegionSidecarVk,
        child_layout: DuplexLayout,
        parent_layout: DuplexLayout,
    ) -> Result<Self, V2Error> {
        if !block_vk.supports_objects()
            || block_vk.version() != crate::region_sidecar::BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION
        {
            return Err(V2Error::Runtime);
        }
        let expected = BlockRegionSidecarVk::from_object_registry_slices(
            config.block_geometry(),
            block_vk.selected_registry_slices()?,
        )?;
        if block_vk != expected {
            return Err(V2Error::Runtime);
        }
        let geometry = HistoryStepParentGeometry::single(
            &config.pcs_params(),
            child_layout.clone(),
            parent_layout.clone(),
        )?;
        let parent_vk = geometry.canonical_vk(&config.io_spec())?;
        Ok(Self {
            config,
            parent_vk,
            block_vk,
            child_layout,
            parent_layout,
            geometry,
        })
    }
    pub fn config(&self) -> V2Config {
        self.config
    }
    pub fn parent_vk(&self) -> &LinkRegionSidecarVk {
        &self.parent_vk
    }
    pub fn block_vk(&self) -> &BlockRegionSidecarVk {
        &self.block_vk
    }
    pub fn child_layout(&self) -> &DuplexLayout {
        &self.child_layout
    }
    pub fn parent_layout(&self) -> &DuplexLayout {
        &self.parent_layout
    }
}

pub trait V2MatrixSource: Send + Sync {
    fn load(&self) -> Result<HistoryStepMatrixLease, V2Error>;
}

pub struct V2Runtime {
    bank: V2Bank,
    parts: V2RuntimeParts,
    matrices: Box<dyn V2MatrixSource>,
}

impl V2Runtime {
    pub fn new(
        bank: V2Bank,
        parts: V2RuntimeParts,
        matrices: Box<dyn V2MatrixSource>,
    ) -> Result<Self, V2Error> {
        bank.check_parts(&parts)?;
        Ok(Self {
            bank,
            parts,
            matrices,
        })
    }
    pub fn bank(&self) -> &V2Bank {
        &self.bank
    }
    pub fn parts(&self) -> &V2RuntimeParts {
        &self.parts
    }
    fn load_matrix(&self) -> Result<HistoryStepMatrixLease, V2Error> {
        let matrix = self.matrices.load()?;
        self.bank.authenticate(&matrix)?;
        Ok(matrix)
    }
}

struct NoMatrix;
impl V2MatrixSource for NoMatrix {
    fn load(&self) -> Result<HistoryStepMatrixLease, V2Error> {
        Err(V2Error::Matrix)
    }
}

/// Intermediate freezer recipe. Absolute direct-block slices are replaced by
/// the integrated build before the final runtime is pinned.
pub fn derive_direct_block_vk<const TIER: usize>(
    config: V2Config,
    current: HistoryStepBlockInput<TIER>,
) -> Result<BlockRegionSidecarVk, V2Error> {
    if TIER != config.pages() || current.sealed_header.height < config.activation_height() {
        return Err(V2Error::Boundary);
    }
    let HistoryStepBlockInput {
        start_accumulator,
        end_accumulator,
        components,
        authorization,
        sealed_header,
        parent_header,
        ..
    } = current;
    let mut builder = FieldR1csBuilder::new_witness_only();
    let parent = ParentSealTrace::alloc(&mut builder, &parent_header);
    let assembly = build_block_slots_selected_zk(
        &mut builder,
        &start_accumulator,
        &end_accumulator,
        &components,
        &sealed_header,
        TIER,
        authorization,
        &parent_header,
        &parent.block_id,
        BlockRelationProfile::ScheduledV2(config),
    );
    Ok(assembly.region_vk().clone())
}

pub fn derive_runtime_parts(
    config: V2Config,
    block_vk: BlockRegionSidecarVk,
) -> Result<V2RuntimeParts, V2Error> {
    let mut child = placeholder_history_step_recording_layout(1 << 14);
    let mut parent = child.clone();
    for _ in 0..16 {
        let parts = V2RuntimeParts::new(config, block_vk.clone(), child.clone(), parent.clone())?;
        let runtime = V2Runtime::new(
            V2Bank::pin([0; 32], &parts),
            parts.clone(),
            Box::new(NoMatrix),
        )?;
        let envelope = shape_only_envelope(
            &runtime,
            vec![F128::ZERO; runtime.bank.config().layout().len],
        )?;
        let scratch = scratch_replay(&runtime, &envelope)?;
        if scratch.child.layout == child && scratch.parent.layout == parent {
            return Ok(parts);
        }
        child = scratch.child.layout;
        parent = scratch.parent.layout;
    }
    Err(V2Error::Layout)
}

struct V2Proof {
    field: C1FieldR1csProof,
    commitment: Commitment,
    io: Vec<F128>,
    sidecar: JointC1RegionSidecarProof,
}

/// Unverified persisted proof. Only `verify_terminal` returns block-application
/// authority, after checking the caller's authenticated origin.
pub struct V2Terminal {
    proof: V2Proof,
}

impl V2Terminal {
    /// The declared origin is an object-fetch key, not acceptance authority.
    /// The terminal still needs complete verification with VerifiedV2Origin.
    pub fn claimed_origin(&self, runtime: &V2Runtime) -> Result<V2Origin, V2Error> {
        let origin = runtime.bank.parse(&self.proof.io)?.origin;
        origin.check(runtime.bank())?;
        Ok(origin)
    }
}
impl V2Terminal {
    pub fn accumulator(&self, bank: &V2Bank) -> Result<ChainAccumulator, V2Error> {
        Ok(bank.parse(&self.proof.io)?.accumulator)
    }
}

#[must_use = "verified v2 authority must be consumed by block application"]
pub struct AcceptedV2Terminal {
    accumulator: ChainAccumulator,
    origin: V2Origin,
}
impl AcceptedV2Terminal {
    pub fn accumulator(&self) -> &ChainAccumulator {
        &self.accumulator
    }
    pub fn origin(&self) -> &V2Origin {
        &self.origin
    }
}

struct Scratch {
    child: LayoutRecordedChannel,
    parent: LayoutRecordedChannel,
    query_values: Vec<F128>,
}

fn shape_only_envelope(runtime: &V2Runtime, io: Vec<F128>) -> Result<V2Proof, V2Error> {
    let (field, root) = shape_only_field_r1cs_proof_c1(
        &runtime.bank.config().shape(),
        &runtime.bank.config().pcs_params(),
    );
    Ok(V2Proof {
        field,
        commitment: Commitment {
            root,
            params: runtime.bank.config().pcs_params(),
        },
        io,
        sidecar: shape_only_joint_c1_region_sidecar_proof(
            &runtime.parts.parent_vk,
            &runtime.parts.block_vk,
            runtime.bank.config().outer_m(),
        )?,
    })
}

fn scratch_replay(runtime: &V2Runtime, envelope: &V2Proof) -> Result<Scratch, V2Error> {
    let mut builder = FieldR1csBuilder::new_witness_only();
    let statement = alloc_pinned_flat_digest(&mut builder, &runtime.bank.matrix_digest());
    let post = alloc_pinned_flat_digest(&mut builder, &runtime.bank.post_commit_digest());
    let root = alloc_flat_digest(&mut builder, &envelope.commitment.root);
    let io = envelope
        .io
        .iter()
        .map(|v| LinExpr::from_wire(builder.alloc_f128(*v)))
        .collect::<Vec<_>>();
    let proof = C1FieldR1csProofTrace::alloc_shape_mode(
        &mut builder,
        &envelope.field,
        &runtime.bank.config().shape(),
        &runtime.bank.config().pcs_params(),
        false,
    );
    let mut channel = FsChannelUnionRecorder::new_c1(PROOF_DOMAIN);
    let mut child = None;
    let mut error = None;
    verify_field_c1_trace_deferred_region_with_post_commit_context_expr(
        &mut builder,
        &mut channel,
        &runtime.bank.config().shape(),
        &runtime.bank.config().pcs_params(),
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
            &runtime.parts.block_vk,
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
            &runtime.bank.config().pcs_params(),
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

fn replay(
    runtime: &V2Runtime,
    envelope: &V2Proof,
) -> Result<(C1FreshLincheckClaim, Scratch), V2Error> {
    if pcs_params_statement_bytes(&envelope.commitment.params)
        != pcs_params_statement_bytes(&runtime.bank.config().pcs_params())
    {
        return Err(V2Error::Runtime);
    }
    runtime.bank.parse(&envelope.io)?;
    let mut channel =
        LayoutRecordingChallenger::new_c1(PROOF_DOMAIN, runtime.parts.parent_layout.clone());
    let mut child = None;
    let (_, fresh) = verify_field_c1_deferred_matrix_with_post_commit_context(
        &runtime.bank.config().shape(),
        &runtime.bank.matrix_digest(),
        &envelope.commitment,
        &envelope.field,
        &runtime.bank.config().io_spec(),
        &envelope.io,
        &runtime.bank.post_commit_digest(),
        &envelope.sidecar,
        &mut channel,
        |sidecar, context| {
            child = Some(
                verify_joint_c1_region_sidecar_post_commit_layout_captured(
                    &runtime.parts.parent_vk,
                    &runtime.parts.block_vk,
                    sidecar,
                    context,
                    runtime.parts.child_layout.clone(),
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

struct PreparedParent<'a> {
    envelope: ParentEnvelope<'a>,
    scratch: Scratch,
    fold: C1MatrixFoldProof,
    io: Vec<F128>,
}

enum ParentEnvelope<'a> {
    Local(V2Proof),
    Persisted(&'a V2Proof),
}
impl ParentEnvelope<'_> {
    fn proof(&self) -> &V2Proof {
        match self {
            Self::Local(p) => p,
            Self::Persisted(p) => p,
        }
    }
}

fn prepare_parent<'a, const TIER: usize>(
    runtime: &V2Runtime,
    origin: &V2Origin,
    parent: Option<&'a V2Terminal>,
    current: &HistoryStepBlockInput<TIER>,
) -> Result<PreparedParent<'a>, V2Error> {
    origin.check(&runtime.bank)?;
    let activation = origin.activation_height()?;
    if TIER != runtime.bank.config().pages() || current.sealed_header.height < activation {
        return Err(V2Error::Boundary);
    }
    match parent {
        None => {
            if current.start_accumulator != origin.boundary
                || current.end_accumulator.height != activation
                || noid_chain::hash_block_header(&current.parent_header) != origin.parent_id
            {
                return Err(V2Error::Boundary);
            }
            let mut envelope =
                shape_only_envelope(runtime, runtime.bank.initial_io(origin, &origin.boundary))?;
            let scratch = scratch_replay(runtime, &envelope)?;
            crate::acceptance::trace::self_verify::patch_shape_only_query_positions_c1(
                &mut envelope.field,
                &runtime.bank.config().pcs_params(),
                &scratch.query_values,
            );
            Ok(PreparedParent {
                envelope: ParentEnvelope::Local(envelope),
                scratch,
                fold: zero_fold_proof(runtime.bank.config().outer_m()),
                io: runtime.bank.initial_io(origin, &current.end_accumulator),
            })
        }
        Some(parent) => {
            let parsed = runtime.bank.parse(&parent.proof.io)?;
            if parsed.origin != *origin || parsed.accumulator != current.start_accumulator {
                return Err(V2Error::Boundary);
            }
            let (fresh, scratch) = replay(runtime, &parent.proof)?;
            let incoming = parsed
                .claim
                .clone()
                .unwrap_or_else(|| C1MatrixAccClaim::zero(runtime.bank.config().outer_m()));
            let matrix = runtime.load_matrix()?;
            let mut channel = FsLaneChallenger::new_c1(FOLD_DOMAIN);
            let (fold, claim) = match &matrix {
                HistoryStepMatrixLease::Resident(m) => prove_matrix_claim_fold_c1(
                    m,
                    &fresh,
                    &incoming,
                    parsed.claim.is_some(),
                    &mut channel,
                ),
                HistoryStepMatrixLease::Compact(m) => prove_matrix_claim_fold_compact_c1(
                    m,
                    &fresh,
                    &incoming,
                    parsed.claim.is_some(),
                    &mut channel,
                ),
            };
            let mut io = parent.proof.io.clone();
            install_claim(runtime.bank.config(), &mut io, &claim)?;
            io[runtime.bank.config().layout().acc..runtime.bank.config().layout().acc + 10]
                .copy_from_slice(&block_acc_lanes(&current.end_accumulator));
            runtime.bank.parse(&io)?;
            Ok(PreparedParent {
                envelope: ParentEnvelope::Persisted(&parent.proof),
                scratch,
                fold,
                io,
            })
        }
    }
}

struct Preparations {
    parent: HistoryStepParentRegionPreparation,
    block: BlockRegionPreparation,
}

pub struct FrozenV2 {
    matrix: FieldR1cs,
    witness: Vec<F128>,
    preparations: Preparations,
}
impl FrozenV2 {
    pub fn matrix(&self) -> &FieldR1cs {
        &self.matrix
    }
    pub fn witness(&self) -> &[F128] {
        &self.witness
    }
    pub fn parent_vk(&self) -> &LinkRegionSidecarVk {
        self.preparations.parent.vk()
    }
    pub fn block_vk(&self) -> &BlockRegionSidecarVk {
        self.preparations.block.vk()
    }
    pub fn into_matrix(self) -> FieldR1cs {
        self.matrix
    }
}

pub struct BuiltV2 {
    matrix: HistoryStepMatrixLease,
    witness: Vec<F128>,
    io: Vec<F128>,
    preparations: Preparations,
}

struct Assembly {
    builder: FieldR1csBuilder,
    block: SelectedZkBlockSlotsAssembly,
    parent: HistoryStepParentRegionPreparation,
    io_seal: DeferredHistoryStepIo,
    io: Vec<F128>,
    matrix: Option<HistoryStepMatrixLease>,
}

fn prepare_assembly<const TIER: usize>(
    runtime: &V2Runtime,
    prepared: PreparedParent<'_>,
    current: HistoryStepBlockInput<TIER>,
    frozen: bool,
) -> Result<Assembly, V2Error> {
    let PreparedParent {
        envelope,
        scratch,
        fold,
        io,
    } = prepared;
    let envelope = envelope.proof();
    let matrix = if frozen {
        None
    } else {
        Some(runtime.load_matrix()?)
    };
    let mut builder = if frozen {
        FieldR1csBuilder::new()
    } else {
        FieldR1csBuilder::new_witness_only()
    };
    let (cells, io_seal) = allocate_deferred_history_step_io(
        &mut builder,
        &runtime.bank.config().io_spec(),
        &io,
        runtime.bank.config().layout().acc,
    );
    let gate = cells[BASE].add_const(F128::ONE);
    let boolean = mul(&mut builder, &cells[BASE], &gate);
    pin_eq(&mut builder, &boolean, &LinExpr::zero());
    let params = runtime.bank.config().pcs_params();
    let r_proof = RPcsProof {
        native: &envelope.field.pcs_open,
        params: &params,
        commitment_root: flat_digest_lanes(&envelope.commitment.root),
    };
    let columns = prepare_history_step_parent_columns(
        &mut builder,
        &[r_proof],
        0,
        &runtime.parts.geometry,
        vec![scratch.child],
        vec![scratch.parent],
    )?;
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
        BlockRelationProfile::ScheduledV2(runtime.bank.config()),
    );
    pin_eq(
        &mut builder,
        &parent_seal.height,
        &block.slots().start_acc.height,
    );
    // This is a separate relation for the configured scheduled fork. Its base
    // cannot start at an arbitrary height or be reset on a subsequent block.
    let height = runtime.bank.config().activation_height();
    pin_eq(
        &mut builder,
        &cells[ORIGIN_ACC],
        &LinExpr::constant(flat_of(noid_core::Block128((height - 1) as u128))),
    );

    let root = alloc_flat_digest(&mut builder, &envelope.commitment.root);
    let prev = envelope
        .io
        .iter()
        .map(|v| LinExpr::from_wire(builder.alloc_f128(*v)))
        .collect::<Vec<_>>();
    // The new matrix, sidecar identity and entire sealed legacy origin are
    // immutable along the chain, in both branches of the relation.
    for index in MATRIX..POINT {
        pin_eq(&mut builder, &cells[index], &prev[index]);
    }
    let proof = C1FieldR1csProofTrace::alloc_shape_mode(
        &mut builder,
        &envelope.field,
        &runtime.bank.config().shape(),
        &params,
        false,
    );
    let mut obligations = PcsWalkObligations::default();
    let mut recorder = BaseSelectableParentRecorder::new_c1(PROOF_DOMAIN);
    let mut recorded_child = None;
    let mut error = None;
    let (_, fresh) = with_pin_gate(&gate, || {
        verify_field_c1_trace_deferred_region_with_post_commit_context_expr(
            &mut builder,
            &mut recorder,
            &runtime.bank.config().shape(),
            &params,
            &[prev[MATRIX].clone(), prev[MATRIX + 1].clone()],
            &root,
            &proof,
            &runtime.bank.config().io_spec(),
            &prev,
            &[prev[POST].clone(), prev[POST + 1].clone()],
            Some(&mut obligations),
            |builder, context| match verify_joint_c1_region_sidecar_trace_post_commit(
                builder,
                context,
                &runtime.parts.parent_vk,
                &runtime.parts.block_vk,
                &envelope.sidecar,
            ) {
                Ok(recording) => recorded_child = Some(recording),
                Err(e) => error = Some(e),
            },
        )
    });
    if let Some(error) = error {
        return Err(error.into());
    }
    let incoming = C1MatrixAccClaimTrace {
        point: prev[POINT..runtime.bank.config().layout().value]
            .chunks_exact(2)
            .map(|x| ExtExpr::new(x[0].clone(), x[1].clone()))
            .collect(),
        value: ExtExpr::new(
            prev[runtime.bank.config().layout().value].clone(),
            prev[runtime.bank.config().layout().value + 1].clone(),
        ),
    };
    let fold = C1MatrixFoldProofTrace::alloc(&mut builder, &fold, runtime.bank.config().outer_m());
    let mut fold_channel = FsChannelTrace::new_c1(&mut builder, FOLD_DOMAIN);
    let outgoing = with_pin_gate(&gate, || {
        verify_matrix_claim_fold_c1_trace(
            &mut builder,
            &mut fold_channel,
            runtime.bank.config().shape().k_log,
            runtime.bank.config().shape().k_skip,
            &fresh,
            &incoming,
            &prev[runtime.bank.config().layout().live],
            &fold,
        )
    });
    let outputs = outgoing
        .point
        .iter()
        .flat_map(|p| [&p.lo, &p.hi])
        .chain([&outgoing.value.lo, &outgoing.value.hi]);
    for (cell, value) in cells[POINT..runtime.bank.config().layout().live]
        .iter()
        .zip(outputs)
    {
        let selected = mul(&mut builder, &gate, value);
        pin_eq(&mut builder, cell, &selected);
    }
    pin_eq(
        &mut builder,
        &cells[runtime.bank.config().layout().live],
        &gate,
    );
    let parent = with_pin_gate(&gate, || {
        finalize_history_step_parent_region(
            &mut builder,
            columns,
            &[obligations],
            &[LinExpr::constant(F128::ONE)],
            &[recorded_child.ok_or(V2Error::Layout)?],
            &[recorder.finish()],
        )
        .map_err(V2Error::from)
    })?;
    for lane in 0..2 {
        with_pin_gate(&gate, || {
            pin_eq(
                &mut builder,
                &parent_seal.semantic_id[lane],
                &prev[runtime.bank.config().layout().acc + 1 + lane],
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
        with_pin_gate(&gate, || {
            pin_eq(
                &mut builder,
                start,
                &prev[runtime.bank.config().layout().acc + index],
            )
        });
        with_pin_gate(&cells[BASE], || {
            pin_eq(&mut builder, start, &cells[ORIGIN_ACC + index])
        });
    }
    for (index, end) in block.slots().end_acc.ordered_lanes().iter().enumerate() {
        pin_eq(
            &mut builder,
            end,
            &cells[runtime.bank.config().layout().acc + index],
        );
    }
    Ok(Assembly {
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
    Built(BuiltV2),
}

fn finish_assembly(
    runtime: &V2Runtime,
    assembly: Assembly,
    header: &BlockHeader,
    end: &ChainAccumulator,
) -> Result<AssemblyOutput, V2Error> {
    let Assembly {
        mut builder,
        mut block,
        parent,
        io_seal,
        mut io,
        matrix,
    } = assembly;
    io_seal.seal(
        &mut builder,
        &mut io,
        runtime.bank.config().layout().acc,
        end,
    )?;
    block
        .seal_direct_tail(&mut builder, header, end)
        .map_err(|_| V2Error::Boundary)?;
    let used = builder.num_wires();
    let limit = 1usize << runtime.bank.config().outer_m();
    if used > limit {
        return Err(V2Error::Shape { used, limit });
    }
    let block = finalize_selected_zk_block_region(block, runtime.bank.config().outer_m())?;
    let preparations = Preparations { parent, block };
    match matrix {
        None => {
            let (matrix, witness) = builder.build();
            let (matrix, witness) = crate::acceptance::expand_empty_field_tail(
                matrix,
                witness,
                runtime.bank.config().shape(),
            );
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
                || preparations.block.vk() != runtime.parts.block_vk()
            {
                return Err(V2Error::Runtime);
            }
            runtime.bank.parse(&io)?;
            Ok(AssemblyOutput::Built(BuiltV2 {
                matrix,
                witness,
                io,
                preparations,
            }))
        }
    }
}

pub fn assemble_frozen<const TIER: usize>(
    runtime: &V2Runtime,
    origin: &V2Origin,
    parent: Option<&V2Terminal>,
    current: HistoryStepBlockInput<TIER>,
) -> Result<FrozenV2, V2Error> {
    let prepared = prepare_parent(runtime, origin, parent, &current)?;
    let header = current.sealed_header;
    let end = current.end_accumulator.clone();
    let assembly = prepare_assembly(runtime, prepared, current, true)?;
    match finish_assembly(runtime, assembly, &header, &end)? {
        AssemblyOutput::Frozen(frozen) => Ok(frozen),
        _ => unreachable!("frozen assembly"),
    }
}

#[must_use = "dropping this value cancels the unsealed block attempt"]
pub struct PreparedV2ForPow {
    assembly: Assembly,
    header: BlockHeader,
    parent_header: BlockHeader,
    start: ChainAccumulator,
}

pub fn prepare_for_pow<const TIER: usize>(
    runtime: &V2Runtime,
    origin: &V2Origin,
    parent: Option<&V2Terminal>,
    current: HistoryStepBlockInput<TIER>,
) -> Result<PreparedV2ForPow, V2Error> {
    if current.sealed_header.nonce != 0 {
        return Err(V2Error::Boundary);
    }
    let prepared = prepare_parent(runtime, origin, parent, &current)?;
    let header = current.sealed_header;
    let parent_header = current.parent_header;
    let start = current.start_accumulator.clone();
    Ok(PreparedV2ForPow {
        assembly: prepare_assembly(runtime, prepared, current, false)?,
        header,
        parent_header,
        start,
    })
}
impl PreparedV2ForPow {
    pub fn retained_witness_bytes(&self) -> usize {
        self.assembly.builder.retained_witness_bytes()
    }
    pub fn seal_nonce(mut self, runtime: &V2Runtime, nonce: u128) -> Result<BuiltV2, V2Error> {
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
    runtime: &V2Runtime,
    built: &BuiltV2,
    cancellation: &std::sync::atomic::AtomicBool,
) -> Result<V2Terminal, V2Error> {
    if cancellation.load(std::sync::atomic::Ordering::Acquire) {
        return Err(V2Error::Cancelled);
    }
    runtime.bank.authenticate(&built.matrix)?;
    runtime.bank.parse(&built.io)?;
    if built.preparations.parent.vk() != runtime.parts.parent_vk()
        || built.preparations.block.vk() != runtime.parts.block_vk()
    {
        return Err(V2Error::Runtime);
    }
    let params = runtime.bank.config().pcs_params();
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
                &runtime.bank.post_commit_digest(),
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
    Ok(V2Terminal {
        proof: V2Proof {
            field,
            commitment,
            io: built.io.clone(),
            sidecar: sidecar?,
        },
    })
}

pub fn verify_terminal(
    runtime: &V2Runtime,
    origin: &VerifiedV2Origin,
    terminal: &V2Terminal,
    header: &BlockHeader,
    epoch_header: &BlockHeader,
) -> Result<AcceptedV2Terminal, V2Error> {
    origin.0.check(&runtime.bank)?;
    let parsed = runtime.bank.parse(&terminal.proof.io)?;
    if parsed.origin != origin.0 {
        return Err(V2Error::Origin);
    }
    parsed
        .accumulator
        .validate_local_header_boundary(header, epoch_header)
        .map_err(|_| V2Error::Boundary)?;
    let (fresh, _) = replay(runtime, &terminal.proof)?;
    let matrix = runtime.load_matrix()?;
    check_claims(&matrix, &fresh, parsed.claim.as_ref())?;
    Ok(AcceptedV2Terminal {
        accumulator: parsed.accumulator,
        origin: parsed.origin,
    })
}
