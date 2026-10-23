// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Atomic proof-carrying block history.
//!
//! One HistoryStep proves the current block relation and, except at height one,
//! recursively verifies the persisted parent terminal. The network stores and
//! transports only the resulting terminal.

use noid_chain::block_header::BlockHeader;
use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::deep_chain::schedule::{compile_duplex, DuplexLayout};
use noid_ivc_core::field::{F128, F256};
use noid_ivc_core::field_circuit::{
    DeferredWitnessSlot, FieldR1csBuilder, FsChannelTrace, FsChannelUnionRecorder,
    LayoutRecordedChannel, LayoutRecordingChallenger, LinExpr, RecordedChannel,
};
use noid_ivc_core::field_r1cs::FieldR1cs;
use noid_ivc_core::matrix_claim::c1::{C1FreshLincheckClaim, C1MatrixFoldProof};
use noid_ivc_core::pcs::{Commitment, PcsParams};
use noid_ivc_core::proof::{pcs_params_statement_bytes, C1FieldR1csProof, FieldShape};
use noid_ivc_core::public_io::PublicIoSpec;
use noid_ivc_core::verifier::{
    verify_field_c1_deferred_matrix_with_post_commit_context, VerifyError,
};
use noid_ivc_prover::field_prover::{
    prove_field_c1_with_public_io_and_post_commit_context,
    prove_field_c1_with_public_io_and_post_commit_context_cancellable,
    prove_field_compact_c1_with_public_io_and_post_commit_context,
    prove_field_compact_c1_with_public_io_and_post_commit_context_cancellable,
};

use super::block_slots::{
    build_block_slots_selected_zk, build_block_slots_selected_zk_prefix,
    finalize_selected_zk_block_region, BlockRelationProfile, ParentSealTrace,
    SelectedZkBlockSlotsAssembly,
};
use super::trace::accepted_claim_batch::digest_lanes;
use super::trace::flat_of;
use super::trace::matrix_fold::{
    verify_matrix_claim_fold_c1_trace, C1MatrixAccClaimTrace, C1MatrixFoldProofTrace,
};
use super::trace::r_pcs_region::{
    finalize_history_step_parent_region, prepare_history_step_parent_columns,
    HistoryStepParentGeometry, HistoryStepParentRegionPreparation, RPcsProof,
};
use super::trace::self_verify::{
    alloc_flat_digest, flat_digest_lanes, shape_only_field_r1cs_proof_c1,
    verify_field_c1_trace_deferred_region_with_post_commit_context_expr, C1FieldR1csProofTrace,
    PcsWalkObligations,
};
use super::trace::zk_authorization_candidate::{
    prepare_selected_zk_authorizations, PreparedSelectedZkAuthorizations,
    PreparedSelectedZkGhostAuthorization,
};
use super::trace::{mul, pin_eq, with_pin_gate};
use crate::accumulator::{genesis_accumulator, ChainAccumulator};
use crate::region_sidecar::{
    shape_only_joint_c1_region_sidecar_proof, verify_joint_c1_region_sidecar_post_commit,
    verify_joint_c1_region_sidecar_post_commit_layout_captured,
    verify_joint_c1_region_sidecar_trace_post_commit, BlockRegionPreparation, BlockRegionSidecarVk,
    JointC1RegionSidecarProof, LinkRegionSidecarVk, RegionSidecarError,
};

mod freezer;
mod gated_recorder;
mod relation;
mod runtime_parts_codec;
pub mod v2;
mod wire;

pub use crate::acceptance::history_step_bank::HistoryStepMatrixLease;

/// Single Fiat-Shamir domain for a HistoryStep proof and every replay of that
/// persisted proof, including the recorded recursive verifier transcript.
pub(crate) const HISTORY_STEP_PROOF_DOMAIN: &[u8] = b"history-step-v1";

pub use freezer::{
    freeze_history_step_bank, FrozenHistoryStepBank, HistoryStepFreezeError,
    HistoryStepFreezeInput, HistoryStepFreezeInputProvider, HistoryStepFreezeMatrixStore,
    HistoryStepFreezeStage,
};
pub use relation::{
    assemble_frozen_direct_block_research, assemble_frozen_history_step_base,
    assemble_frozen_history_step_recursive, assemble_history_step_base,
    assemble_history_step_recursive, derive_history_step_direct_block_vk,
    derive_history_step_runtime_parts, pin_history_step_class_bank, prepare_history_step_for_pow,
    prepare_history_step_retirement, prove_built_history_step_terminal,
    prove_built_history_step_terminal_cancellable, prove_history_step,
    verify_history_step_terminal, AcceptedHistoryStepTerminal, BuiltHistoryStep,
    FrozenDirectBlockResearch, FrozenHistoryStep, HistoryStepError, HistoryStepMatrixSource,
    HistoryStepMatrixSourceError, HistoryStepParent, HistoryStepParentTranscriptLayout,
    HistoryStepRuntime, HistoryStepRuntimeParts, HistoryStepSidecarOperation, HistoryStepTerminal,
    PreparedHistoryStepForPow, HISTORY_STEP_WIRE_VERSION,
};
pub use runtime_parts_codec::{
    HISTORY_STEP_RUNTIME_PARTS_COMPACT_MAX_BYTES, HISTORY_STEP_RUNTIME_PARTS_COMPACT_VERSION,
};
pub use wire::{
    audit_history_step_terminal_encodings, decode_history_step_terminal,
    decode_verify_history_step_terminal, encode_history_step_terminal,
    history_step_terminal_max_wire_bytes, HistoryStepWireAudit,
};

/// Canonical authorization statement consumed by the direct block relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationComponentInput {
    pub block_index: usize,
    pub tx_index: usize,
    pub tx_body_hash: [noid_core::Block128; 2],
    pub public: noid_gkr::OwnerAuthPublicInputs,
}

pub const V2_CONTRACT_PROGRAM_STEPS: usize = noid_tx::experimental_object::PROGRAM_STEPS;
const _: () = assert!(
    V2_CONTRACT_PROGRAM_STEPS == noid_ivc_core::deep_chain::spine::SPINE_CONTRACT_PROGRAM_STEPS
);
pub const V2_CONTRACT_SLOTS: usize = 16;

/// Research-only contract opening associated with one physical user body.
/// It is deliberately not part of the v1 wire or consensus API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2ContractComponentInput {
    /// Index in `tx_body_inputs`, including coinbase and an optional payout.
    pub body_index: usize,
    pub live: bool,
    pub program: [[noid_core::Block128; 2]; V2_CONTRACT_PROGRAM_STEPS],
    pub current: noid_core::Block128,
    pub contexts: [noid_core::Block128; noid_tx::experimental_object::BODY_CONTEXT_FIELDS],
    pub next: noid_core::Block128,
    /// Claim authority used before the deadline.
    pub controller: [noid_core::Block128; 2],
    /// Recovery authority used at or after the deadline.
    pub refund_authority: [noid_core::Block128; 2],
    pub terminal: bool,
    pub deadline: u64,
    pub claim_recipient: [noid_core::Block128; 2],
    pub refund_recipient: [noid_core::Block128; 2],
    pub rules: noid_tx::experimental_object::ObjectRules,
}

/// Sibling-only exact-state carrier. Merkle topology is verifier-derived from
/// `touched_indices` and `active_depth`; no path directions are supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactStateStructuralFrontierInputs {
    pub touched_indices: Vec<u32>,
    pub active_depth: u32,
    pub old_slot_leaves: Vec<noid_gkr::SlotLeafInputs>,
    pub new_slot_leaves: Vec<noid_gkr::SlotLeafInputs>,
    pub live_sibling_digests: Vec<noid_chain::exact_state_hash::StateHash>,
    pub old_combine_digests: Vec<noid_chain::exact_state_hash::StateHash>,
    pub new_combine_digests: Vec<noid_chain::exact_state_hash::StateHash>,
    pub old_root: noid_chain::exact_state_hash::StateHash,
    pub new_root: noid_chain::exact_state_hash::StateHash,
}

/// Semantic inputs consumed by the direct block half of `HistoryStep`.
///
/// There is deliberately no accepted-claim digest, detached block proof,
/// certificate statement, or header-checkpoint proof here.  The outer
/// relation binds these values directly to the sealed header and proves the
/// body/root/state regions in its own post-commit sidecar.
#[derive(Debug, Clone)]
pub struct HistoryStepBlockComponents {
    /// Physical user PagedSpend pages in the canonical block suffix.
    pub user_page_count: usize,
    /// Whether the first body-suffix position is a development payout.
    pub has_development_payout: bool,
    /// Canonical block-order body spines: coinbase, optional payout, then
    /// physical user pages. The fixed recursive suffix multiplexes the
    /// payout against one user-capacity position.
    pub tx_body_inputs: Vec<noid_gkr::SpineInputs>,
    pub tx_body_hashes: Vec<[noid_core::Block128; 2]>,
    pub tx_root_inputs: Vec<noid_gkr::MerklePathInputs>,
    pub authorization_inputs: Vec<AuthorizationComponentInput>,
    /// Empty for v1. Contract witnesses use the selected class's physical
    /// body positions and are never serialized in the block body.
    pub v2_contract_inputs: Vec<V2ContractComponentInput>,
    /// Live object preimages for the fixed native action positions.
    /// Empty in earlier profiles.
    pub native_openings: Vec<noid_tx::native_assets::NativeOpening>,
    pub native_trade_batches: Vec<noid_tx::native_assets::trade::batch::TradeBatch>,
    /// Recent canonical ancestors, newest first, for registered financial rounds.
    pub financial_ancestors: Vec<BlockHeader>,
    pub exact_state: ExactStateStructuralFrontierInputs,
}

impl HistoryStepBlockComponents {
    /// Page count that selects the recursive block class.
    ///
    /// A scheduled payout consumes one physical block-capacity position.
    #[inline]
    pub const fn effective_page_count(&self) -> usize {
        self.user_page_count
            .saturating_add(self.has_development_payout as usize)
    }
}

/// Runtime-cached canonical ghost authorization, verified exactly once.
/// Fields are opaque and the capability has no wire representation.
#[derive(Clone)]
pub struct PreparedHistoryStepGhostAuthorization {
    pub(in crate::acceptance) inner: PreparedSelectedZkGhostAuthorization,
}

/// Nonce-independent live authorization authority. It is intentionally
/// non-cloneable and non-serializable and is consumed by one block attempt.
pub struct PreparedHistoryStepAuthorizations {
    pub(in crate::acceptance) inner: PreparedSelectedZkAuthorizations,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryStepAuthorizationError {
    NonCanonicalTier,
    ComponentShape,
    Verification,
}

impl core::fmt::Display for HistoryStepAuthorizationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonCanonicalTier => {
                formatter.write_str("HistoryStep authorization tier is not canonical")
            }
            Self::ComponentShape => {
                formatter.write_str("HistoryStep authorization statement shape is not canonical")
            }
            Self::Verification => {
                formatter.write_str("HistoryStep authorization proof verification failed")
            }
        }
    }
}

impl std::error::Error for HistoryStepAuthorizationError {}

pub fn prepare_history_step_ghost_authorization(
    proof: noid_gkr::zk_authorization::ZkAuthorizationProof,
) -> Result<PreparedHistoryStepGhostAuthorization, HistoryStepAuthorizationError> {
    prepare_history_step_ghost_authorization_for_version(
        proof,
        noid_tx::OwnerAuthorizationVersion::V4,
    )
}

pub fn prepare_history_step_ghost_authorization_for_version(
    proof: noid_gkr::zk_authorization::ZkAuthorizationProof,
    version: noid_tx::OwnerAuthorizationVersion,
) -> Result<PreparedHistoryStepGhostAuthorization, HistoryStepAuthorizationError> {
    Ok(PreparedHistoryStepGhostAuthorization {
        inner: super::trace::zk_authorization_candidate::prepare_selected_zk_ghost_authorization_for_version(proof, version)
            .map_err(|_| HistoryStepAuthorizationError::Verification)?,
    })
}

pub fn prepare_history_step_authorizations<const TIER: usize>(
    effective_page_count: usize,
    inputs: &[AuthorizationComponentInput],
    proofs: Vec<noid_gkr::zk_authorization::ZkAuthorizationProof>,
    ghost: &PreparedHistoryStepGhostAuthorization,
) -> Result<PreparedHistoryStepAuthorizations, HistoryStepAuthorizationError> {
    let actual_tier =
        noid_chain::consensus::paged_spend::BlockProofClass::for_page_count(effective_page_count)
            .map(|class| class.page_capacity());
    if crate::region_sidecar::selected_zk_block_geometry(TIER).is_none()
        || actual_tier != Some(TIER)
        || inputs.len() > TIER
    {
        return Err(HistoryStepAuthorizationError::NonCanonicalTier);
    }
    prepare_checked_authorizations(inputs, proofs, ghost)
}

/// Explicit research candidate capacity; ordinary nodes continue to select
/// only the two legacy classes through the entry point above.
pub fn prepare_candidate_authorizations(
    config: v2::V2Config,
    effective_page_count: usize,
    inputs: &[AuthorizationComponentInput],
    proofs: Vec<noid_gkr::zk_authorization::ZkAuthorizationProof>,
    ghost: &PreparedHistoryStepGhostAuthorization,
) -> Result<PreparedHistoryStepAuthorizations, HistoryStepAuthorizationError> {
    if effective_page_count > config.pages()
        || inputs.len()
            > if config.native_sequential_config().is_some() {
                config.pages()
            } else {
                effective_page_count
            }
        || proofs.len() != inputs.len()
    {
        return Err(HistoryStepAuthorizationError::ComponentShape);
    }
    prepare_checked_authorizations(inputs, proofs, ghost)
}

fn prepare_checked_authorizations(
    inputs: &[AuthorizationComponentInput],
    proofs: Vec<noid_gkr::zk_authorization::ZkAuthorizationProof>,
    ghost: &PreparedHistoryStepGhostAuthorization,
) -> Result<PreparedHistoryStepAuthorizations, HistoryStepAuthorizationError> {
    if inputs.iter().any(|input| {
        input.public.layout != noid_gkr::OwnerAuthLayout::FIXED
            || input.tx_body_hash != input.public.tx_body_hash
    }) {
        return Err(HistoryStepAuthorizationError::ComponentShape);
    }
    let statements = inputs
        .iter()
        .map(
            |input| noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement {
                tx_body_hash: input.public.tx_body_hash,
                address: input.public.expected_address,
            },
        )
        .collect::<Vec<_>>();
    Ok(PreparedHistoryStepAuthorizations {
        inner: prepare_selected_zk_authorizations(&statements, proofs, &ghost.inner)
            .map_err(|_| HistoryStepAuthorizationError::Verification)?,
    })
}

/// Consuming current-block input created at the post-native-accept,
/// pre-commit boundary.
#[must_use = "the accepted block input must be consumed by HistoryStep proving"]
pub struct HistoryStepBlockInput<const TIER: usize> {
    start_accumulator: ChainAccumulator,
    end_accumulator: ChainAccumulator,
    components: HistoryStepBlockComponents,
    authorization: PreparedSelectedZkAuthorizations,
    sealed_header: BlockHeader,
    parent_header: BlockHeader,
    semantic_id: [u8; 32],
}

impl<const TIER: usize> HistoryStepBlockInput<TIER> {
    pub fn try_new(
        start_accumulator: &ChainAccumulator,
        end_accumulator: &ChainAccumulator,
        components: HistoryStepBlockComponents,
        authorizations: PreparedHistoryStepAuthorizations,
        sealed_header: &BlockHeader,
        parent_header: &BlockHeader,
    ) -> Result<Self, HistoryStepInputError> {
        Self::try_new_inner(
            start_accumulator,
            end_accumulator,
            components,
            authorizations,
            sealed_header,
            parent_header,
            true,
        )
    }

    pub fn try_new_candidate(
        config: v2::V2Config,
        start_accumulator: &ChainAccumulator,
        end_accumulator: &ChainAccumulator,
        components: HistoryStepBlockComponents,
        authorizations: PreparedHistoryStepAuthorizations,
        sealed_header: &BlockHeader,
        parent_header: &BlockHeader,
    ) -> Result<Self, HistoryStepInputError> {
        if TIER != config.pages()
            || sealed_header.height < config.activation_height()
            || components.effective_page_count() > TIER
        {
            return Err(HistoryStepInputError::NonCanonicalTier { tier: TIER });
        }
        if components.v2_contract_inputs.len() > config.contract_slots() {
            return Err(HistoryStepInputError::ComponentShape);
        }
        match config.native_sequential_config() {
            Some(trade) => {
                if components.native_trade_batches.len() > trade.markets
                    || components
                        .native_trade_batches
                        .iter()
                        .map(|b| b.policies().len())
                        .sum::<usize>()
                        > trade.policies
                    || components
                        .native_trade_batches
                        .iter()
                        .flat_map(|b| b.policies())
                        .map(|p| p.funding.len())
                        .sum::<usize>()
                        > trade.funding
                    || components
                        .native_trade_batches
                        .iter()
                        .any(|b| b.validate_structure().is_err())
                {
                    return Err(HistoryStepInputError::ComponentShape);
                }
            }
            None if !components.native_trade_batches.is_empty() => {
                return Err(HistoryStepInputError::ComponentShape)
            }
            None => {}
        }
        Self::try_new_inner(
            start_accumulator,
            end_accumulator,
            components,
            authorizations,
            sealed_header,
            parent_header,
            false,
        )
    }

    fn try_new_inner(
        start_accumulator: &ChainAccumulator,
        end_accumulator: &ChainAccumulator,
        components: HistoryStepBlockComponents,
        authorizations: PreparedHistoryStepAuthorizations,
        sealed_header: &BlockHeader,
        parent_header: &BlockHeader,
        legacy_class: bool,
    ) -> Result<Self, HistoryStepInputError> {
        if crate::region_sidecar::selected_zk_block_geometry(TIER).is_none() {
            return Err(HistoryStepInputError::NonCanonicalTier { tier: TIER });
        }
        let live_authorizations = components.authorization_inputs.len();
        if authorizations.inner.live_count() != live_authorizations {
            return Err(HistoryStepInputError::AuthorizationProofCardinality {
                expected: live_authorizations,
                actual: authorizations.inner.live_count(),
            });
        }
        let user_page_count = components.user_page_count;
        let effective_page_count = components.effective_page_count();
        let actual_tier = noid_chain::consensus::paged_spend::BlockProofClass::for_page_count(
            effective_page_count,
        )
        .map(|class| class.page_capacity());
        if legacy_class && actual_tier != Some(TIER) {
            return Err(HistoryStepInputError::WrongTier {
                expected_tier: TIER,
                live_authorizations,
                actual_tier,
            });
        }
        if components.tx_body_inputs.len() != components.tx_body_hashes.len()
            || components.tx_body_inputs.len()
                != user_page_count
                    .saturating_add(1)
                    .saturating_add(components.has_development_payout as usize)
            || live_authorizations > if legacy_class { user_page_count } else { TIER }
            || components.tx_root_inputs.is_empty()
            || components.financial_ancestors.len() > 3
        {
            return Err(HistoryStepInputError::ComponentShape);
        }
        let semantic_id = noid_chain::block_header::semantic_header_id(sealed_header);
        // The complete parent glue: the end boundary must be the exact
        // parent-headed advance of the start boundary — this covers the
        // semantic tip, the chain link, the height successor and the shifted
        // epoch-anchor rule in one place.
        if start_accumulator
            .advance(parent_header, sealed_header)
            .ok()
            .as_ref()
            != Some(end_accumulator)
        {
            return Err(HistoryStepInputError::SealedHeaderMismatch);
        }
        if end_accumulator.tip_semantic_id != semantic_id {
            return Err(HistoryStepInputError::SealedHeaderMismatch);
        }
        Ok(Self {
            start_accumulator: start_accumulator.clone(),
            end_accumulator: end_accumulator.clone(),
            components,
            authorization: authorizations.inner,
            sealed_header: *sealed_header,
            parent_header: *parent_header,
            semantic_id,
        })
    }

    pub fn sealed_header(&self) -> &BlockHeader {
        &self.sealed_header
    }

    pub fn start_accumulator(&self) -> &ChainAccumulator {
        &self.start_accumulator
    }

    pub fn end_accumulator(&self) -> &ChainAccumulator {
        &self.end_accumulator
    }

    pub fn parent_header(&self) -> &BlockHeader {
        &self.parent_header
    }

    pub fn semantic_id(&self) -> [u8; 32] {
        self.semantic_id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryStepInputError {
    NonCanonicalTier {
        tier: usize,
    },
    AuthorizationProofCardinality {
        expected: usize,
        actual: usize,
    },
    WrongTier {
        expected_tier: usize,
        live_authorizations: usize,
        actual_tier: Option<usize>,
    },
    ComponentShape,
    SealedHeaderMismatch,
}

impl core::fmt::Display for HistoryStepInputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonCanonicalTier { tier } => {
                write!(f, "HistoryStep tier B{tier} is not canonical")
            }
            Self::AuthorizationProofCardinality { expected, actual } => write!(
                f,
                "HistoryStep authorization proof count {actual} does not match {expected} live inputs",
            ),
            Self::WrongTier {
                expected_tier,
                live_authorizations,
                actual_tier,
            } => write!(
                f,
                "HistoryStep B{expected_tier} has {live_authorizations} live authorizations (tier {actual_tier:?})",
            ),
            Self::ComponentShape => f.write_str("HistoryStep component shape is not canonical"),
            Self::SealedHeaderMismatch => {
                f.write_str("HistoryStep input is not bound to the exact sealed header")
            }
        }
    }
}

impl std::error::Error for HistoryStepInputError {}

pub(super) struct HistoryStepPreparations {
    recursion: HistoryStepParentRegionPreparation,
    direct_block: BlockRegionPreparation,
}

fn alloc_pinned_flat_digest(builder: &mut FieldR1csBuilder, digest: &[u8; 32]) -> [LinExpr; 2] {
    let lanes = flat_digest_lanes(digest);
    std::array::from_fn(|lane| {
        let expression = LinExpr::from_wire(builder.alloc_f128(lanes[lane]));
        pin_eq(builder, &expression, &LinExpr::constant(lanes[lane]));
        expression
    })
}
