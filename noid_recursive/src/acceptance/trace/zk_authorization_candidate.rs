// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Selected-ZK authorization trace and private selected-class bridge over
//! transcript and Wallet-B aliases.
//!
//! Its raw-slice tile adapter is private.  Shape-compatible [`WitnessSlice`]
//! values alone do not establish canonical sidecar provenance, and a
//! per-tile call cannot establish complete block coverage.  The private
//! production BlockSlots backend owns the
//! canonical statement aliases and consumes verifier-minted prepared
//! authorization through one canonical-statement binding -> raw
//! Owner/Main/Wallet -> common Meta allocator -> all-class-tiles bridge.  It
//! returns only an opaque bound region and paired handoff.  The
//! owning Block facade retains the sole builder through all Block and
//! public-IO rows, calls `build`/`build_witness_only`, and only then consumes
//! that binding through the sealed preparation finalizer.
//!
//! [`ZkAuthTranscriptCells`] is the sole source of serialized Owner/Main
//! fields and Fiat-Shamir challenges.  The caller supplies only cells already
//! authenticated by the Wallet-B/FF regions: path directions, source and mid
//! leaves, and final path-root expressions.  This adapter reshapes those
//! aliases and composes, in protocol order:
//!
//! 1. Owner AuthGKR, the transparent post-claim relation, and Phase A;
//! 2. the fixed low-16-bit post-nonce grind predicate; and
//! 3. all 65 Phase-B queries, upper/tail linkage, and both cap families.
//!
//! Prefix-to-suffix continuity for both transcripts and the four
//! Owner-closing-state -> Main-bridge pins are external to this disconnected
//! core and cost twelve rows in [`super::zk_split_bridge`]. The Main nonce is
//! range-bound here to the canonical `u64` wire language before its
//! post-nonce grind squeeze is checked.

use std::{collections::BTreeMap, sync::Arc};

use noid_fri_binius::interleaved_commit::SourceHash;
use noid_fri_binius::zk_capsule_algebra::{
    JOINT_SOURCE_LEAF_SYMBOLS, MID_STANDARD_FOLDS, SOURCE_QUERY_BITS,
};
use noid_gkr::zk_authorization::{
    verify_zk_authorization, ZkAuthorizationError, ZkAuthorizationProof, ZkAuthorizationVerified,
};
use noid_gkr::ZkAuthorizationWireEncodeError;
use noid_ivc_core::deep_chain::capsule_leaf::{
    C1_CAPSULE_LEAF_STRIDE, C1_CAPSULE_MID_DIGEST_SLOT, C1_CAPSULE_MID_SLOTS,
    C1_CAPSULE_SOURCE_DIGEST_SLOT, C1_CAPSULE_SOURCE_SLOTS,
};
use noid_ivc_core::deep_chain::schedule::DuplexLayout;
use noid_ivc_core::public_io::WitnessSlice;

use super::exact_state::ExactStateRegionData;
use super::region_source_binding::slot_cell;
use super::region_source_binding::{
    allocate_selected_zk_auth_pcs_region, PairedExactStateCells, SpineRegionData, TxRootRegionData,
};
use super::zk_auth_composition::{
    verify_zk_auth_composition_trace, ZkAuthCompositionTraceError, ZkAuthCompositionTraceInput,
    ZkAuthCompositionTraceOutput, ZK_AUTH_COMPOSITION_TRACE_ROWS,
};
use super::zk_auth_grind::{
    verify_zk_auth_grind_trace, ZkAuthGrindTraceError, ZkAuthGrindTraceOutput,
    ZK_AUTH_GRIND_TRACE_ROWS,
};
use super::zk_auth_nonce::{
    verify_zk_auth_nonce_trace, ZkAuthNonceTraceError, ZkAuthNonceTraceOutput,
    ZK_AUTH_NONCE_TRACE_ROWS,
};
use super::zk_auth_terminal::AuthCapsuleTerminalOperandClaimsTrace;
use super::zk_auth_transcript_cells::{
    view_zk_auth_raw_split_transcript_tile, view_zk_auth_split_transcript_tile,
    ZkAuthRawTranscriptTile, ZkAuthTranscriptCells, ZK_AUTH_MAIN_GAMMA_CHALLENGE_INDEX,
    ZK_AUTH_OWNER_ETA_CHALLENGE_INDEX, ZK_AUTH_OWNER_LAMBDA_CHALLENGE_INDEX,
    ZK_AUTH_OWNER_ROUND_CHALLENGE_START,
};
#[cfg(test)]
use super::zk_auth_transcript_cells::{
    ZK_AUTH_MAIN_BETA_CHALLENGE_START, ZK_AUTH_MAIN_GRIND_RAW_CHALLENGE_INDEX,
    ZK_AUTH_MAIN_PHASE_A_CHALLENGE_START, ZK_AUTH_MAIN_QUERY_SEED_RAW_CHALLENGE_START,
};
use super::zk_authorization_region::{
    build_selected_zk_authorization_region_draft, SelectedZkAuthorizationRegionDraft,
    SelectedZkAuthorizationRegionError,
};
use super::zk_mlecheck::ZkMleCheckRoundProofTrace;
use super::zk_phase_a::{ZkPhaseATraceRound, ZK_PHASE_A_ROUNDS};
use super::zk_phase_b_composition::{
    verify_zk_phase_b_composition_trace, ZkPhaseBCompositionTraceError,
    ZkPhaseBCompositionTraceInput, ZkPhaseBCompositionTraceOutput, ZK_PHASE_B_CAP_DIGEST_LANES,
    ZK_PHASE_B_COMPOSITION_TRACE_ROWS,
};
use super::zk_query_carriers::{
    ZK_MID_PATH_DIRECTION_BITS, ZK_QUERY_COUNT, ZK_SOURCE_PATH_DIRECTION_BITS,
};
use super::zk_split_bridge::{
    pin_zk_auth_c1_split_bridge_at, ZkAuthSplitBridgeCells, ZK_AUTH_SPLIT_BRIDGE_PIN_ROWS,
};
use super::{const_block, flat_of, mul, pin_eq, ExtExpr, FieldR1csBuilder, LinExpr, F128, F256};
use crate::acceptance::block_slots::SelectedBlockAssemblyFinalizationSeal;
use crate::acceptance::block_slots::{
    CanonicalSelectedZkAuthorizationCapability, CanonicalSelectedZkAuthorizationSlotKind,
};
use crate::acceptance::zk_auth_capsule_schedule::{
    ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES, ZK_AUTH_MAIN_TILE_LOG, ZK_AUTH_OWNER_SQUEEZES,
    ZK_AUTH_OWNER_TILE_LOG, ZK_AUTH_WALLET_A_MID_BASE, ZK_AUTH_WALLET_A_SOURCE_BASE,
};
#[cfg(test)]
use crate::acceptance::zk_auth_capsule_schedule::{
    ZK_AUTH_MAIN_DYNAMIC_LANES, ZK_AUTH_MAIN_RAW_CHALLENGE_LANES, ZK_AUTH_OWNER_DYNAMIC_LANES,
};
use crate::region_sidecar::SelectedZkBlockRegionDraft;
use crate::region_sidecar::{BlockRegionPreparation, RegionSidecarError};

/// Exact incremental ledger after all transcript and Wallet-B aliases exist.
/// The twelve split-bridge pins are intentionally not included.
pub const ZK_AUTHORIZATION_CANDIDATE_TRACE_ROWS: usize = ZK_AUTH_COMPOSITION_TRACE_ROWS
    + ZK_AUTH_NONCE_TRACE_ROWS
    + ZK_AUTH_GRIND_TRACE_ROWS
    + ZK_PHASE_B_COMPOSITION_TRACE_ROWS;
/// Required external Owner->Main bridge linkage, stated separately so callers
/// cannot accidentally fold it into the candidate's local ledger.
pub const ZK_AUTHORIZATION_CANDIDATE_EXTERNAL_BRIDGE_ROWS: usize = ZK_AUTH_SPLIT_BRIDGE_PIN_ROWS;

const _: () = assert!(ZK_AUTH_COMPOSITION_TRACE_ROWS == 1_852);
const _: () = assert!(ZK_AUTH_NONCE_TRACE_ROWS == 65);
const _: () = assert!(ZK_AUTH_GRIND_TRACE_ROWS == 113);
const _: () = assert!(ZK_PHASE_B_COMPOSITION_TRACE_ROWS == 13_926);
const _: () = assert!(ZK_AUTHORIZATION_CANDIDATE_TRACE_ROWS == 15_956);
const _: () = assert!(ZK_AUTHORIZATION_CANDIDATE_EXTERNAL_BRIDGE_ROWS == 12);
const _: () = assert!(ZK_PHASE_A_ROUNDS == 11);

pub const ZK_AUTH_WALLET_A_COLUMNS: usize = 6;
pub const ZK_AUTH_WALLET_B_COLUMNS: usize = 9;
pub const ZK_AUTH_META_A_COLUMNS: usize = 8;
pub const ZK_AUTH_META_B_COLUMNS: usize = 9;
pub const ZK_AUTH_WALLET_A_TILE_LOG: usize = 11;
pub const ZK_AUTH_WALLET_B_TILE_LOG: usize = 10;
pub const ZK_AUTH_WALLET_CORE_QUERY_COUNT: usize = 64;
pub const ZK_AUTH_WALLET_OVERFLOW_QUERY: usize = ZK_AUTH_WALLET_CORE_QUERY_COUNT;
pub const ZK_AUTH_WALLET_A_SOURCE_SLOTS: usize =
    ZK_AUTH_WALLET_CORE_QUERY_COUNT * C1_CAPSULE_SOURCE_SLOTS;
pub const ZK_AUTH_WALLET_A_MID_SLOTS: usize =
    ZK_AUTH_WALLET_CORE_QUERY_COUNT * C1_CAPSULE_MID_SLOTS;
pub const ZK_AUTH_WALLET_B_SOURCE_PATH_DEPTH: usize = ZK_SOURCE_PATH_DIRECTION_BITS;
pub const ZK_AUTH_WALLET_B_MID_PATH_DEPTH: usize = ZK_MID_PATH_DIRECTION_BITS;
pub const ZK_AUTH_WALLET_B_PATH_STRIDE: usize =
    ZK_AUTH_WALLET_B_SOURCE_PATH_DEPTH + ZK_AUTH_WALLET_B_MID_PATH_DEPTH;
pub const ZK_AUTH_WALLET_B_SOURCE_PATH_OFFSET: usize = 0;
pub const ZK_AUTH_WALLET_B_MID_PATH_OFFSET: usize = ZK_AUTH_WALLET_B_SOURCE_PATH_DEPTH;

pub(crate) const ZK_AUTH_RAW_SLICE_STATEMENT_PIN_ROWS: usize = 4;
/// One trace-one map row for every algebraic Owner/Main squeeze.
pub(crate) const ZK_AUTH_RAW_SLICE_C1_SAMPLER_ROWS: usize =
    ZK_AUTH_OWNER_SQUEEZES + ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES;
pub(crate) const ZK_AUTH_RAW_SLICE_DIGEST_BRIDGE_ROWS: usize =
    ZK_QUERY_COUNT * 2 /* families */ * 2 /* digest lanes */;
pub(crate) const ZK_AUTH_RAW_SLICE_COMPOSITE_ROOT_ROWS: usize =
    ZK_QUERY_COUNT * 2 /* families */ * 2 /* digest lanes */;
/// C1 fixed-shape tags and ordered Merkle paths bind leaf type, length and
/// position, so no leaf metadata cells or metadata pins exist.
pub(crate) const ZK_AUTH_RAW_SLICE_METADATA_PIN_ROWS: usize = 0;
/// Wrapper rows materialized before the core candidate derives bound queries.
pub(crate) const ZK_AUTH_RAW_SLICE_PRE_CORE_ROWS: usize = ZK_AUTH_RAW_SLICE_STATEMENT_PIN_ROWS
    + ZK_AUTH_RAW_SLICE_C1_SAMPLER_ROWS
    + ZK_AUTH_SPLIT_BRIDGE_PIN_ROWS
    + ZK_AUTH_RAW_SLICE_DIGEST_BRIDGE_ROWS
    + ZK_AUTH_RAW_SLICE_COMPOSITE_ROOT_ROWS;
pub(crate) const ZK_AUTH_RAW_SLICE_WRAPPER_ROWS: usize =
    ZK_AUTH_RAW_SLICE_PRE_CORE_ROWS + ZK_AUTH_RAW_SLICE_METADATA_PIN_ROWS;
pub(crate) const ZK_AUTH_RAW_SLICE_TILE_TRACE_ROWS: usize =
    ZK_AUTH_RAW_SLICE_WRAPPER_ROWS + ZK_AUTHORIZATION_CANDIDATE_TRACE_ROWS;

const _: () = assert!(C1_CAPSULE_LEAF_STRIDE == 16);
const _: () = assert!(SOURCE_QUERY_BITS == 13);
const _: () = assert!(ZK_QUERY_COUNT == ZK_AUTH_WALLET_CORE_QUERY_COUNT + 1);
const _: () = assert!(ZK_AUTH_WALLET_A_SOURCE_SLOTS == 768);
const _: () = assert!(ZK_AUTH_WALLET_A_MID_SLOTS == 1024);
const _: () = assert!(ZK_AUTH_WALLET_A_MID_BASE == ZK_AUTH_WALLET_A_SOURCE_SLOTS);
const _: () = assert!(ZK_AUTH_WALLET_B_SOURCE_PATH_DEPTH == 10);
const _: () = assert!(ZK_AUTH_WALLET_B_MID_PATH_DEPTH == 6);
const _: () = assert!(ZK_AUTH_WALLET_B_PATH_STRIDE == 16);
const _: () = assert!(
    ZK_AUTH_WALLET_CORE_QUERY_COUNT * ZK_AUTH_WALLET_B_PATH_STRIDE
        == 1 << ZK_AUTH_WALLET_B_TILE_LOG
);
const _: () = assert!(ZK_AUTH_RAW_SLICE_STATEMENT_PIN_ROWS == 4);
const _: () = assert!(ZK_AUTH_RAW_SLICE_DIGEST_BRIDGE_ROWS == 260);
const _: () = assert!(ZK_AUTH_RAW_SLICE_COMPOSITE_ROOT_ROWS == 260);
const _: () = assert!(ZK_AUTH_RAW_SLICE_METADATA_PIN_ROWS == 0);
const _: () = assert!(ZK_AUTH_RAW_SLICE_C1_SAMPLER_ROWS == 44);
const _: () = assert!(ZK_AUTH_RAW_SLICE_PRE_CORE_ROWS == 580);
const _: () = assert!(ZK_AUTH_RAW_SLICE_WRAPPER_ROWS == 580);
const _: () = assert!(ZK_AUTH_RAW_SLICE_TILE_TRACE_ROWS == 16_536);

/// Wallet-B and FF-Merkle expressions consumed by one fixed authorization.
/// No proof/transcript field is accepted here.
#[derive(Clone, Debug)]
pub(crate) struct ZkAuthorizationCandidateExternalAliases {
    /// Source FF directions `q0..q9`, `[query][depth]`.
    pub source_path_directions: [[LinExpr; ZK_SOURCE_PATH_DIRECTION_BITS]; ZK_QUERY_COUNT],
    /// Mid FF directions `q4..q9`, `[query][depth]`.
    pub mid_path_directions: [[LinExpr; ZK_MID_PATH_DIRECTION_BITS]; ZK_QUERY_COUNT],
    /// Authenticated adjacent source cells `[B0,C0,...,B7,C7]`.
    pub joint_source_leaves: [[LinExpr; JOINT_SOURCE_LEAF_SYMBOLS]; ZK_QUERY_COUNT],
    /// Authenticated contiguous sixteen-cell mid leaves.
    pub mid_leaves: [[ExtExpr; 1 << MID_STANDARD_FOLDS]; ZK_QUERY_COUNT],
    /// Final source FF expressions, `[query][digest_lane]`.
    pub source_path_roots: [[LinExpr; ZK_PHASE_B_CAP_DIGEST_LANES]; ZK_QUERY_COUNT],
    /// Final mid FF expressions, `[query][digest_lane]`.
    pub mid_path_roots: [[LinExpr; ZK_PHASE_B_CAP_DIGEST_LANES]; ZK_QUERY_COUNT],
}

/// Stable family labels for atomic input-preflight failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthorizationCandidateInput {
    OwnerPublicStatement,
    OwnerSourceCap,
    OwnerMaskMu,
    OwnerRoundCoefficient,
    OwnerMaskFinal,
    OwnerOperandClaim,
    OwnerRho,
    OwnerLambda,
    OwnerRoundChallenge,
    OwnerEta,
    MainBridge,
    MainSigma,
    MainPhaseARoundCoefficient,
    MainPhaseBValue,
    MainUpper,
    MainMidCap,
    MainTail,
    MainNonce,
    MainGamma,
    MainPhaseAChallenge,
    MainBeta,
    MainGrind,
    MainQuerySeed,
    SourcePathDirection,
    MidPathDirection,
    JointSourceLeaf,
    MidLeaf,
    SourcePathRoot,
    MidPathRoot,
    OuterTxBodyHash,
    OuterExpectedAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthorizationCandidateTraceError {
    /// A value expected to come directly from a committed transcript A/C cell
    /// was not a canonical one-wire alias in the current builder.
    MalformedTranscriptAlias {
        input: ZkAuthorizationCandidateInput,
        index: usize,
    },
    /// A Wallet-B/FF expression had no nonconstant witness support.
    ExternalAliasIsConstant {
        input: ZkAuthorizationCandidateInput,
        index: usize,
    },
    /// An external expression referenced a wire not allocated in this builder.
    ExternalAliasOutsideWitness {
        input: ZkAuthorizationCandidateInput,
        index: usize,
    },
    /// The affine blend would erase the companion oracle.
    GammaZero,
    /// The affine blend would erase the bank oracle.
    GammaOne,
    /// The characteristic-two MLE batching challenge must be invertible.
    LambdaZero,
    /// The post-claim RLC challenge must be invertible.
    EtaZero,
    /// The five terminal operand pads lose rank when `product_j r_j = 0`.
    TerminalBlindingWeightZero,
    Authorization(ZkAuthCompositionTraceError),
    Nonce(ZkAuthNonceTraceError),
    Grind(ZkAuthGrindTraceError),
    PhaseB(ZkPhaseBCompositionTraceError),
}

impl From<ZkAuthCompositionTraceError> for ZkAuthorizationCandidateTraceError {
    fn from(value: ZkAuthCompositionTraceError) -> Self {
        Self::Authorization(value)
    }
}

impl From<ZkAuthGrindTraceError> for ZkAuthorizationCandidateTraceError {
    fn from(value: ZkAuthGrindTraceError) -> Self {
        Self::Grind(value)
    }
}

impl From<ZkAuthNonceTraceError> for ZkAuthorizationCandidateTraceError {
    fn from(value: ZkAuthNonceTraceError) -> Self {
        Self::Nonce(value)
    }
}

impl From<ZkPhaseBCompositionTraceError> for ZkAuthorizationCandidateTraceError {
    fn from(value: ZkPhaseBCompositionTraceError) -> Self {
        Self::PhaseB(value)
    }
}

#[derive(Clone, Debug)]
pub struct ZkAuthorizationCandidateTraceOutput {
    pub authorization: ZkAuthCompositionTraceOutput,
    pub nonce: ZkAuthNonceTraceOutput,
    pub grind: ZkAuthGrindTraceOutput,
    pub phase_b: ZkPhaseBCompositionTraceOutput,
}

/// Exact selected authorization statement exposed by the Block relation.
/// It intentionally has no legacy layout tag, slot-live vector, or other
/// transitional owner-auth surface.
#[derive(Clone, Debug)]
struct SelectedZkAuthorizationStatementTrace {
    tx_body_hash: [LinExpr; 2],
    expected_address: [LinExpr; 2],
}

impl SelectedZkAuthorizationStatementTrace {
    #[cfg(test)]
    fn new(tx_body_hash: [LinExpr; 2], expected_address: [LinExpr; 2]) -> Self {
        Self {
            tx_body_hash,
            expected_address,
        }
    }
}

fn canonical_selected_zk_ghost_statement() -> noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement
{
    let body = noid_gkr::ghost_tx::ghost_tx_body();
    noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement {
        tx_body_hash: noid_gkr::ghost_tx::ghost_tx_body_hash(),
        address: body.input_owner.as_fields(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SelectedZkAuthorizationArtifactIdentity {
    proof_bytes: Vec<u8>,
    source_cap: Vec<SourceHash>,
}

fn selected_zk_authorization_artifact_identity(
    proof: &ZkAuthorizationProof,
) -> Result<SelectedZkAuthorizationArtifactIdentity, ZkAuthorizationWireEncodeError> {
    Ok(SelectedZkAuthorizationArtifactIdentity {
        proof_bytes: proof.to_bytes()?,
        source_cap: proof.source_commitment.cap.hashes.clone(),
    })
}

#[derive(Debug)]
pub(in crate::acceptance) enum HistoryStepAuthorizationPreparationError {
    LiveCount {
        expected: usize,
        actual: usize,
    },
    NativeVerification {
        index: usize,
        source: ZkAuthorizationError,
    },
    GhostVerification(ZkAuthorizationError),
    WireEncoding {
        index: usize,
        source: ZkAuthorizationWireEncodeError,
    },
    GhostWireEncoding(ZkAuthorizationWireEncodeError),
    DuplicateLiveProof {
        first: usize,
        second: usize,
    },
    DuplicateLiveSourceCommitment {
        first: usize,
        second: usize,
    },
    LiveGhostProofReuse {
        live: usize,
    },
    LiveGhostSourceCommitmentReuse {
        live: usize,
    },
}

impl std::fmt::Display for HistoryStepAuthorizationPreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LiveCount { expected, actual } => write!(
                f,
                "selected ZK authorization live-proof count mismatch: expected {expected}, got {actual}"
            ),
            Self::NativeVerification { index, source } => write!(
                f,
                "selected ZK authorization proof {index} failed native verification: {source:?}"
            ),
            Self::GhostVerification(source) => write!(
                f,
                "selected ZK authorization ghost proof failed native verification: {source:?}"
            ),
            Self::WireEncoding { index, source } => write!(
                f,
                "selected ZK authorization proof {index} failed canonical wire encoding: {source}"
            ),
            Self::GhostWireEncoding(source) => write!(
                f,
                "selected ZK authorization ghost proof failed canonical wire encoding: {source}"
            ),
            Self::DuplicateLiveProof { first, second } => write!(
                f,
                "selected ZK authorization proofs {first} and {second} reuse identical proof bytes"
            ),
            Self::DuplicateLiveSourceCommitment { first, second } => write!(
                f,
                "selected ZK authorization proofs {first} and {second} reuse an identical source commitment"
            ),
            Self::LiveGhostProofReuse { live } => write!(
                f,
                "selected ZK authorization proof {live} reuses the canonical ghost proof bytes"
            ),
            Self::LiveGhostSourceCommitmentReuse { live } => write!(
                f,
                "selected ZK authorization proof {live} reuses the canonical ghost source commitment"
            ),
        }
    }
}

impl std::error::Error for HistoryStepAuthorizationPreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WireEncoding { source, .. } | Self::GhostWireEncoding(source) => Some(source),
            _ => None,
        }
    }
}

fn validate_selected_zk_authorization_artifact_reuse(
    live: &[SelectedZkAuthorizationArtifactIdentity],
    ghost: &SelectedZkAuthorizationArtifactIdentity,
) -> Result<(), HistoryStepAuthorizationPreparationError> {
    let mut proof_bytes = BTreeMap::<&[u8], usize>::new();
    let mut source_caps = BTreeMap::<&[SourceHash], usize>::new();
    for (index, identity) in live.iter().enumerate() {
        if identity.proof_bytes == ghost.proof_bytes {
            return Err(
                HistoryStepAuthorizationPreparationError::LiveGhostProofReuse { live: index },
            );
        }
        if identity.source_cap == ghost.source_cap {
            return Err(
                HistoryStepAuthorizationPreparationError::LiveGhostSourceCommitmentReuse {
                    live: index,
                },
            );
        }
        if let Some(first) = proof_bytes.insert(identity.proof_bytes.as_slice(), index) {
            return Err(
                HistoryStepAuthorizationPreparationError::DuplicateLiveProof {
                    first,
                    second: index,
                },
            );
        }
        if let Some(first) = source_caps.insert(identity.source_cap.as_slice(), index) {
            return Err(
                HistoryStepAuthorizationPreparationError::DuplicateLiveSourceCommitment {
                    first,
                    second: index,
                },
            );
        }
    }
    Ok(())
}

pub(super) struct SelectedZkAuthorizationVerifiedEntry {
    statement: noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement,
    proof: ZkAuthorizationProof,
    verified: ZkAuthorizationVerified,
}

/// Runtime-prepared canonical ghost authorization. The expensive native
/// verification and transcript expansion happen once; block templates share
/// this immutable authority by `Arc`.
pub(in crate::acceptance) struct PreparedSelectedZkGhostAuthorization {
    entry: Arc<SelectedZkAuthorizationVerifiedEntry>,
    identity: SelectedZkAuthorizationArtifactIdentity,
}

impl Clone for PreparedSelectedZkGhostAuthorization {
    fn clone(&self) -> Self {
        Self {
            entry: Arc::clone(&self.entry),
            identity: self.identity.clone(),
        }
    }
}

/// Non-serializable, non-cloneable authorization authority prepared before
/// nonce search. It can only be minted by full native verification below.
pub(in crate::acceptance) struct PreparedSelectedZkAuthorizations {
    live_entries: Vec<SelectedZkAuthorizationVerifiedEntry>,
    ghost_entry: Arc<SelectedZkAuthorizationVerifiedEntry>,
}

impl PreparedSelectedZkAuthorizations {
    pub(in crate::acceptance) fn live_count(&self) -> usize {
        self.live_entries.len()
    }
}

pub(in crate::acceptance) fn prepare_selected_zk_ghost_authorization(
    proof: ZkAuthorizationProof,
) -> Result<PreparedSelectedZkGhostAuthorization, HistoryStepAuthorizationPreparationError> {
    let statement = canonical_selected_zk_ghost_statement();
    let verified = verify_zk_authorization(statement, &proof)
        .map_err(HistoryStepAuthorizationPreparationError::GhostVerification)?;
    let identity = selected_zk_authorization_artifact_identity(&proof)
        .map_err(HistoryStepAuthorizationPreparationError::GhostWireEncoding)?;
    Ok(PreparedSelectedZkGhostAuthorization {
        entry: Arc::new(SelectedZkAuthorizationVerifiedEntry {
            statement,
            proof,
            verified,
        }),
        identity,
    })
}

pub(in crate::acceptance) fn prepare_selected_zk_authorizations(
    statements: &[noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement],
    proofs: Vec<ZkAuthorizationProof>,
    ghost: &PreparedSelectedZkGhostAuthorization,
) -> Result<PreparedSelectedZkAuthorizations, HistoryStepAuthorizationPreparationError> {
    if proofs.len() != statements.len() {
        return Err(HistoryStepAuthorizationPreparationError::LiveCount {
            expected: statements.len(),
            actual: proofs.len(),
        });
    }
    let mut live_entries = Vec::with_capacity(proofs.len());
    let mut identities = Vec::with_capacity(proofs.len());
    for (index, (statement, proof)) in statements.iter().copied().zip(proofs).enumerate() {
        let verified = verify_zk_authorization(statement, &proof).map_err(|source| {
            HistoryStepAuthorizationPreparationError::NativeVerification { index, source }
        })?;
        identities.push(
            selected_zk_authorization_artifact_identity(&proof).map_err(|source| {
                HistoryStepAuthorizationPreparationError::WireEncoding { index, source }
            })?,
        );
        live_entries.push(SelectedZkAuthorizationVerifiedEntry {
            statement,
            proof,
            verified,
        });
    }
    validate_selected_zk_authorization_artifact_reuse(&identities, &ghost.identity)?;
    Ok(PreparedSelectedZkAuthorizations {
        live_entries,
        ghost_entry: Arc::clone(&ghost.entry),
    })
}

impl SelectedZkAuthorizationVerifiedEntry {
    pub(super) fn statement(&self) -> noid_gkr::zk_authorization::ZkAuthCapsuleOwnerStatement {
        self.statement
    }

    pub(super) fn proof(&self) -> &ZkAuthorizationProof {
        &self.proof
    }

    pub(super) fn verified(&self) -> &ZkAuthorizationVerified {
        &self.verified
    }
}

/// Verifier-minted native batch. One selected proof is supplied per live
/// canonical prefix slot and one proof for the canonical ghost statement.
/// The ghost artifact is verified and stored once; `entry_for_slot` maps every
/// Ghost/PAD slot to that immutable entry. Byte-identical repetition under the
/// identical statement adds no observation and must not force 255 fresh
/// empty-block proofs or 255 in-memory proof clones.
pub(super) struct SelectedZkAuthorizationProofBatch {
    canonical: CanonicalSelectedZkAuthorizationCapability,
    live_entries: Vec<SelectedZkAuthorizationVerifiedEntry>,
    ghost_entry: Arc<SelectedZkAuthorizationVerifiedEntry>,
}

impl SelectedZkAuthorizationProofBatch {
    pub(super) fn len(&self) -> usize {
        self.canonical.len()
    }

    pub(super) fn entry_for_slot(&self, index: usize) -> &SelectedZkAuthorizationVerifiedEntry {
        let slot = self.canonical.slot(index);
        match slot.kind() {
            CanonicalSelectedZkAuthorizationSlotKind::Live => {
                &self.live_entries[slot
                    .live_entry_index()
                    .expect("live selected authorization slot has a native proof index")]
            }
            CanonicalSelectedZkAuthorizationSlotKind::Ghost
            | CanonicalSelectedZkAuthorizationSlotKind::Pad => &self.ghost_entry,
        }
    }

    pub(super) fn ghost_entry(&self) -> &SelectedZkAuthorizationVerifiedEntry {
        &self.ghost_entry
    }

    /// Consume the only verifier-minted proof owner and derive the raw selected
    /// authorization columns before releasing the canonical statement
    /// capability. There is no API accepting a second statement/proof source,
    /// and the raw draft cannot be supplied independently to this handoff.
    fn into_canonical_and_raw_draft(
        self,
    ) -> Result<
        (
            CanonicalSelectedZkAuthorizationCapability,
            SelectedZkAuthorizationRegionDraft,
        ),
        SelectedZkAuthorizationRegionError,
    > {
        let raw = build_selected_zk_authorization_region_draft(&self)?;
        let Self { canonical, .. } = self;
        Ok((canonical, raw))
    }
}

/// Opaque result of the one private verified authorization ->
/// common authorization/Meta allocator -> all-tiles binding boundary.  The
/// draft never escapes this module; BlockSlots may only borrow the paired
/// exact-state cells needed by its common continuation.  The owning Block
/// facade carries this value through its IO pins and final builder build
/// before consuming `finalize_after_block_build`.
pub(in crate::acceptance) struct SelectedZkBlockRegionBinding {
    draft: SelectedZkBlockRegionDraft,
    paired: PairedExactStateCells,
}

impl SelectedZkBlockRegionBinding {
    pub(in crate::acceptance) fn paired(&self) -> &PairedExactStateCells {
        &self.paired
    }

    pub(in crate::acceptance) fn vk(&self) -> &crate::region_sidecar::BlockRegionSidecarVk {
        self.draft.vk()
    }

    /// Consume the opaque bound region only after the outer Block owner has
    /// finished building its matrix (or its witness-only replay).  The seal's
    /// constructor is private to the owning Block module, so this boundary
    /// cannot manufacture authority for an early finalization.
    pub(in crate::acceptance) fn finalize_after_block_build(
        self,
        seal: SelectedBlockAssemblyFinalizationSeal,
        total_vars: usize,
    ) -> Result<BlockRegionPreparation, RegionSidecarError> {
        BlockRegionPreparation::from_selected_zk_owned_assembly(self.draft, seal, total_vars)
    }
}

/// Consume every selected authorization input while the caller still borrows
/// the sole Block builder.  Capability verification, raw-column derivation,
/// common six-child allocation and all class statement bindings are atomic from
/// BlockSlots' point of view: no raw draft, canonical capability, transferable
/// finalization seal, or partially bound sidecar is returned.
pub(in crate::acceptance) fn bind_selected_zk_block_region(
    b: &mut FieldR1csBuilder,
    canonical: CanonicalSelectedZkAuthorizationCapability,
    prepared: PreparedSelectedZkAuthorizations,
    exact_state: &ExactStateRegionData,
    tx_root: &TxRootRegionData,
    spine: &SpineRegionData,
    geometry: crate::region_sidecar::SelectedZkBlockGeometry,
) -> SelectedZkBlockRegionBinding {
    assert_eq!(
        prepared.live_entries.len(),
        canonical.live_count(),
        "prepared HistoryStep authorization count drift"
    );
    for index in 0..canonical.len() {
        let slot = canonical.slot(index);
        let statement = match slot.kind() {
            CanonicalSelectedZkAuthorizationSlotKind::Live => prepared.live_entries[slot
                .live_entry_index()
                .expect("live selected authorization slot has a native proof index")]
            .statement(),
            CanonicalSelectedZkAuthorizationSlotKind::Ghost
            | CanonicalSelectedZkAuthorizationSlotKind::Pad => prepared.ghost_entry.statement(),
        };
        assert_eq!(
            statement,
            slot.native_statement(),
            "prepared HistoryStep authorization statement drift"
        );
    }
    let batch = SelectedZkAuthorizationProofBatch {
        canonical,
        live_entries: prepared.live_entries,
        ghost_entry: prepared.ghost_entry,
    };
    let (canonical, authorization) = batch
        .into_canonical_and_raw_draft()
        .expect("selected raw authorization draft");
    let allocation = allocate_selected_zk_auth_pcs_region(
        b,
        authorization,
        exact_state,
        tx_root,
        spine,
        geometry,
    )
    .expect("selected authorization/Meta allocation");
    bind_selected_zk_authorization_all_tiles_trace(b, allocation.draft(), &canonical, geometry)
        .expect("selected all-tiles binding");
    let (draft, paired) = allocation.into_parts();
    SelectedZkBlockRegionBinding { draft, paired }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ZkAuthorizationAllTilesTraceError {
    /// Every selected class has exactly its canonical dyadic authorization
    /// capacity, including every dead PAD above the physical page tier.
    StatementCount { expected: usize, actual: usize },
    Tile {
        index: usize,
        source: ZkAuthorizationCandidateTraceError,
    },
}

fn visit_all_selected_zk_authorization_tiles<T, E>(
    statements: &[T],
    expected: usize,
    mut visit: impl FnMut(usize, &T) -> Result<(), E>,
) -> Result<(), ZkAuthorizationBatchVisitError<E>> {
    if statements.len() != expected {
        return Err(ZkAuthorizationBatchVisitError::StatementCount {
            expected,
            actual: statements.len(),
        });
    }
    for (index, statement) in statements.iter().enumerate() {
        visit(index, statement)
            .map_err(|source| ZkAuthorizationBatchVisitError::Tile { index, source })?;
    }
    Ok(())
}

#[derive(Debug)]
enum ZkAuthorizationBatchVisitError<E> {
    StatementCount { expected: usize, actual: usize },
    Tile { index: usize, source: E },
}

fn preflight_then_visit_all_selected_zk_authorization_tiles<T, E, C>(
    context: &mut C,
    statements: &[T],
    expected: usize,
    mut preflight: impl FnMut(&C, usize, &T) -> Result<(), E>,
    mut visit: impl FnMut(&mut C, usize, &T),
) -> Result<(), ZkAuthorizationBatchVisitError<E>> {
    visit_all_selected_zk_authorization_tiles(statements, expected, |index, statement| {
        preflight(context, index, statement)
    })?;
    for (index, statement) in statements.iter().enumerate() {
        visit(context, index, statement);
    }
    Ok(())
}

fn materialize_selected_zk_statement_constant(
    b: &mut FieldR1csBuilder,
    value: noid_core::Block128,
) -> LinExpr {
    let constant = const_block(value);
    LinExpr::from_wire(b.materialize(&constant))
}

fn selected_zk_statement_from_body_aliases(
    tx_body_hash: &[LinExpr; 2],
    expected_address: &[LinExpr; 2],
) -> SelectedZkAuthorizationStatementTrace {
    SelectedZkAuthorizationStatementTrace {
        tx_body_hash: tx_body_hash.clone(),
        expected_address: expected_address.clone(),
    }
}

fn materialize_selected_zk_authorization_statements(
    b: &mut FieldR1csBuilder,
    canonical: &CanonicalSelectedZkAuthorizationCapability,
) -> Vec<SelectedZkAuthorizationStatementTrace> {
    (0..canonical.len())
        .map(|index| {
            let slot = canonical.slot(index);
            if let Some((tx_body_hash, expected_address)) = slot.body_aliases() {
                return selected_zk_statement_from_body_aliases(tx_body_hash, expected_address);
            }
            assert_eq!(slot.kind(), CanonicalSelectedZkAuthorizationSlotKind::Pad);
            let native = canonical_selected_zk_ghost_statement();
            assert_eq!(slot.native_statement(), native);
            SelectedZkAuthorizationStatementTrace {
                tx_body_hash: native
                    .tx_body_hash
                    .map(|value| materialize_selected_zk_statement_constant(b, value)),
                expected_address: native
                    .address
                    .map(|value| materialize_selected_zk_statement_constant(b, value)),
            }
        })
        .collect()
}

/// Bind all selected authorization tiles inside the private owning Block
/// assembly. The function is module-private, borrows the owner's builder and
/// accepts only the canonical Block capability — never an arbitrary statement
/// slice. It returns no token, draft or preparation.
fn bind_selected_zk_authorization_all_tiles_trace(
    b: &mut FieldR1csBuilder,
    draft: &SelectedZkBlockRegionDraft,
    canonical: &CanonicalSelectedZkAuthorizationCapability,
    geometry: crate::region_sidecar::SelectedZkBlockGeometry,
) -> Result<(), ZkAuthorizationAllTilesTraceError> {
    // Capacities and input budgets can share an authorization axis while
    // using different Meta offsets. Consume the owning allocator's geometry.
    if canonical.len() != geometry.auth_tiles {
        return Err(ZkAuthorizationAllTilesTraceError::StatementCount {
            expected: geometry.auth_tiles,
            actual: canonical.len(),
        });
    }
    let overflow = WalletOverflowLayout::for_geometry(geometry);
    let schedules =
        crate::acceptance::zk_auth_capsule_schedule::ZkAuthCapsuleDuplexSchedules::selected();
    let owner_layout = schedules.owner_layout();
    let main_layout = schedules.main_layout();
    let vk = draft.vk();

    let owner = *vk.owner_c().slices();
    let owner_a = [owner[0], owner[1]];
    let owner_c = [owner[2], owner[3], owner[4], owner[5]];
    let main = *vk.main_c().slices();
    let main_a = [main[0], main[1]];
    let main_c = [main[2], main[3], main[4], main[5]];
    let wallet_a: [WitnessSlice; ZK_AUTH_WALLET_A_COLUMNS] = vk
        .wallet_a()
        .slices()
        .try_into()
        .expect("selected wallet-A child has six committed slices");
    let wallet_b = *vk.wallet_b().slices();
    let meta_a: [WitnessSlice; ZK_AUTH_META_A_COLUMNS] = vk
        .meta_a()
        .slices()
        .try_into()
        .expect("selected Meta-A child has eight committed slices");
    let meta_b = *vk.meta_b().slices();

    let ghost_statement = canonical_selected_zk_ghost_statement();
    for index in 0..geometry.auth_tiles {
        if canonical.slot(index).kind() == CanonicalSelectedZkAuthorizationSlotKind::Pad {
            assert_eq!(canonical.slot(index).native_statement(), ghost_statement);
        }
    }
    let fallback = canonical
        .slot(0)
        .body_aliases()
        .expect("selected slot zero is body-backed");
    let preview = (0..canonical.len())
        .map(|index| {
            let slot = canonical.slot(index);
            let live = slot.liveness().eval(b.values());
            if let Some((tx_body_hash, expected_address)) = slot.body_aliases() {
                let native = slot.native_statement();
                for lane in 0..2 {
                    assert_eq!(
                        tx_body_hash[lane].eval(b.values()),
                        flat_of(native.tx_body_hash[lane]),
                        "canonical tx-body alias/native mismatch at slot {index} lane {lane}"
                    );
                    assert_eq!(
                        expected_address[lane].eval(b.values()),
                        flat_of(native.address[lane]),
                        "canonical owner alias/native mismatch at slot {index} lane {lane}"
                    );
                }
            }
            match slot.kind() {
                CanonicalSelectedZkAuthorizationSlotKind::Live => {
                    assert_eq!(live, F128::ONE);
                    assert!(slot.body_aliases().is_some());
                }
                CanonicalSelectedZkAuthorizationSlotKind::Ghost => {
                    assert_eq!(live, F128::ZERO);
                    assert!(slot.body_aliases().is_some());
                    assert_eq!(slot.native_statement(), ghost_statement);
                }
                CanonicalSelectedZkAuthorizationSlotKind::Pad => {
                    assert!(index < geometry.auth_tiles);
                    assert_eq!(live, F128::ZERO);
                    assert!(slot.body_aliases().is_none());
                    assert_eq!(slot.native_statement(), ghost_statement);
                }
            }
            let (tx_body_hash, expected_address) = slot.body_aliases().unwrap_or(fallback);
            selected_zk_statement_from_body_aliases(tx_body_hash, expected_address)
        })
        .collect::<Vec<_>>();

    // Batch-wide read-only pass before PAD materialization. A malformed
    // middle/last committed tile or body alias therefore appends zero rows.
    preflight_then_visit_all_selected_zk_authorization_tiles(
        b,
        &preview,
        geometry.auth_tiles,
        |b, tile_index, statement| {
            preflight_zk_authorization_raw_slice_tile_candidate_trace(
                b,
                &owner_layout,
                &owner_a,
                &owner_c,
                &main_layout,
                &main_a,
                &main_c,
                &wallet_a,
                &wallet_b,
                &meta_a,
                &meta_b,
                overflow,
                tile_index,
                statement,
            )
            .map(|_| ())
        },
        |_b, _tile_index, _statement| {},
    )
    .map_err(|error| match error {
        ZkAuthorizationBatchVisitError::StatementCount { expected, actual } => {
            ZkAuthorizationAllTilesTraceError::StatementCount { expected, actual }
        }
        ZkAuthorizationBatchVisitError::Tile { index, source } => {
            ZkAuthorizationAllTilesTraceError::Tile { index, source }
        }
    })?;

    // Exactly four constant-pinned PAD statement wires are now safe to add.
    let public = materialize_selected_zk_authorization_statements(b, canonical);
    for (tile_index, statement) in public.iter().enumerate() {
        // The append pass is infallible under the immutable inputs just
        // preflighted. PAD aliases differ only by four freshly
        // constant-materialized wires, checked by the same helper here.
        verify_zk_authorization_raw_slice_tile_candidate_trace(
            b,
            &owner_layout,
            &owner_a,
            &owner_c,
            &main_layout,
            &main_a,
            &main_c,
            &wallet_a,
            &wallet_b,
            &meta_a,
            &meta_b,
            overflow,
            tile_index,
            statement,
        )
        .expect("selected all-tiles append diverged from read-only preflight");
    }
    Ok(())
}

fn check_transcript_alias(
    b: &FieldR1csBuilder,
    expression: &LinExpr,
    input: ZkAuthorizationCandidateInput,
    index: usize,
) -> Result<(), ZkAuthorizationCandidateTraceError> {
    let canonical = expression.constant == F128::ZERO
        && expression.terms.len() == 1
        && expression.terms[0].1 == F128::ONE
        && expression.terms[0].0 != 0
        && (expression.terms[0].0 as usize) < b.num_wires();
    if canonical {
        Ok(())
    } else {
        Err(ZkAuthorizationCandidateTraceError::MalformedTranscriptAlias { input, index })
    }
}

#[cfg(test)]
fn check_transcript_ext_alias(
    b: &FieldR1csBuilder,
    expression: &ExtExpr,
    input: ZkAuthorizationCandidateInput,
    index: usize,
) -> Result<(), ZkAuthorizationCandidateTraceError> {
    check_transcript_alias(b, &expression.lo, input, 2 * index)?;
    check_transcript_alias(b, &expression.hi, input, 2 * index + 1)
}

fn check_external_alias(
    b: &FieldR1csBuilder,
    expression: &LinExpr,
    input: ZkAuthorizationCandidateInput,
    index: usize,
) -> Result<(), ZkAuthorizationCandidateTraceError> {
    if expression.is_const() || !expression.terms.iter().any(|&(wire, _)| wire != 0) {
        return Err(ZkAuthorizationCandidateTraceError::ExternalAliasIsConstant { input, index });
    }
    if expression
        .terms
        .iter()
        .any(|&(wire, _)| wire as usize >= b.num_wires())
    {
        return Err(
            ZkAuthorizationCandidateTraceError::ExternalAliasOutsideWitness { input, index },
        );
    }
    Ok(())
}

fn check_external_ext_alias(
    b: &FieldR1csBuilder,
    expression: &ExtExpr,
    input: ZkAuthorizationCandidateInput,
    index: usize,
) -> Result<(), ZkAuthorizationCandidateTraceError> {
    check_external_alias(b, &expression.lo, input, 2 * index)?;
    check_external_alias(b, &expression.hi, input, 2 * index + 1)
}

#[cfg(test)]
fn preflight_transcript_cells(
    b: &FieldR1csBuilder,
    cells: &ZkAuthTranscriptCells,
) -> Result<(), ZkAuthorizationCandidateTraceError> {
    let owner = &cells.owner;
    for (index, expression) in owner.public_statement.iter().enumerate() {
        check_transcript_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::OwnerPublicStatement,
            index,
        )?;
    }
    for (index, expression) in owner.source_cap.iter().enumerate() {
        check_transcript_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::OwnerSourceCap,
            index,
        )?;
    }
    check_transcript_ext_alias(
        b,
        &owner.mask_mu,
        ZkAuthorizationCandidateInput::OwnerMaskMu,
        0,
    )?;
    for round in 0..owner.round_coefficients.len() {
        for coefficient in 0..owner.round_coefficients[round].len() {
            check_transcript_ext_alias(
                b,
                &owner.round_coefficients[round][coefficient],
                ZkAuthorizationCandidateInput::OwnerRoundCoefficient,
                round * owner.round_coefficients[round].len() + coefficient,
            )?;
        }
    }
    check_transcript_ext_alias(
        b,
        &owner.mask_final,
        ZkAuthorizationCandidateInput::OwnerMaskFinal,
        0,
    )?;
    for (index, expression) in owner.operand_claims.iter().enumerate() {
        check_transcript_ext_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::OwnerOperandClaim,
            index,
        )?;
    }
    for (index, expression) in owner.rho.iter().enumerate() {
        check_transcript_ext_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::OwnerRho,
            index,
        )?;
    }
    check_transcript_ext_alias(
        b,
        &owner.lambda,
        ZkAuthorizationCandidateInput::OwnerLambda,
        0,
    )?;
    for (index, expression) in owner.round_challenges.iter().enumerate() {
        check_transcript_ext_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::OwnerRoundChallenge,
            index,
        )?;
    }
    check_transcript_ext_alias(b, &owner.eta, ZkAuthorizationCandidateInput::OwnerEta, 0)?;

    let main = &cells.main;
    for (index, expression) in main.bridge.iter().enumerate() {
        check_transcript_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::MainBridge,
            index,
        )?;
    }
    check_transcript_ext_alias(b, &main.sigma, ZkAuthorizationCandidateInput::MainSigma, 0)?;
    for round in 0..main.phase_a_round_coefficients.len() {
        for coefficient in 0..main.phase_a_round_coefficients[round].len() {
            check_transcript_ext_alias(
                b,
                &main.phase_a_round_coefficients[round][coefficient],
                ZkAuthorizationCandidateInput::MainPhaseARoundCoefficient,
                round * main.phase_a_round_coefficients[round].len() + coefficient,
            )?;
        }
    }
    check_transcript_ext_alias(
        b,
        &main.phase_b_value,
        ZkAuthorizationCandidateInput::MainPhaseBValue,
        0,
    )?;
    for (index, expression) in main.upper.iter().enumerate() {
        check_transcript_ext_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::MainUpper,
            index,
        )?;
    }
    for (index, expression) in main.mid_cap.iter().enumerate() {
        check_transcript_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::MainMidCap,
            index,
        )?;
    }
    for (index, expression) in main.tail.iter().enumerate() {
        check_transcript_ext_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::MainTail,
            index,
        )?;
    }
    check_transcript_alias(b, &main.nonce, ZkAuthorizationCandidateInput::MainNonce, 0)?;
    check_transcript_ext_alias(b, &main.gamma, ZkAuthorizationCandidateInput::MainGamma, 0)?;
    for (index, expression) in main.phase_a_challenges.iter().enumerate() {
        check_transcript_ext_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::MainPhaseAChallenge,
            index,
        )?;
    }
    for (index, expression) in main.beta.iter().enumerate() {
        check_transcript_ext_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::MainBeta,
            index,
        )?;
    }
    check_transcript_alias(b, &main.grind, ZkAuthorizationCandidateInput::MainGrind, 0)?;
    for (index, expression) in main.query_seeds.iter().enumerate() {
        check_transcript_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::MainQuerySeed,
            index,
        )?;
    }
    Ok(())
}

fn preflight_external_aliases(
    b: &FieldR1csBuilder,
    external: &ZkAuthorizationCandidateExternalAliases,
) -> Result<(), ZkAuthorizationCandidateTraceError> {
    for query in 0..ZK_QUERY_COUNT {
        for bit in 0..ZK_SOURCE_PATH_DIRECTION_BITS {
            check_external_alias(
                b,
                &external.source_path_directions[query][bit],
                ZkAuthorizationCandidateInput::SourcePathDirection,
                query * ZK_SOURCE_PATH_DIRECTION_BITS + bit,
            )?;
        }
        for bit in 0..ZK_MID_PATH_DIRECTION_BITS {
            check_external_alias(
                b,
                &external.mid_path_directions[query][bit],
                ZkAuthorizationCandidateInput::MidPathDirection,
                query * ZK_MID_PATH_DIRECTION_BITS + bit,
            )?;
        }
        for symbol in 0..JOINT_SOURCE_LEAF_SYMBOLS {
            check_external_alias(
                b,
                &external.joint_source_leaves[query][symbol],
                ZkAuthorizationCandidateInput::JointSourceLeaf,
                query * JOINT_SOURCE_LEAF_SYMBOLS + symbol,
            )?;
        }
        for symbol in 0..(1 << MID_STANDARD_FOLDS) {
            check_external_ext_alias(
                b,
                &external.mid_leaves[query][symbol],
                ZkAuthorizationCandidateInput::MidLeaf,
                query * (1 << MID_STANDARD_FOLDS) + symbol,
            )?;
        }
        for lane in 0..ZK_PHASE_B_CAP_DIGEST_LANES {
            check_external_alias(
                b,
                &external.source_path_roots[query][lane],
                ZkAuthorizationCandidateInput::SourcePathRoot,
                query * ZK_PHASE_B_CAP_DIGEST_LANES + lane,
            )?;
            check_external_alias(
                b,
                &external.mid_path_roots[query][lane],
                ZkAuthorizationCandidateInput::MidPathRoot,
                query * ZK_PHASE_B_CAP_DIGEST_LANES + lane,
            )?;
        }
    }
    Ok(())
}

fn raw_c1_value(b: &FieldR1csBuilder, raw_challenges: &[LinExpr], logical_index: usize) -> F256 {
    let start = 2 * logical_index;
    F256::from_raw_challenge_lanes(
        raw_challenges[start].eval(b.values()),
        raw_challenges[start + 1].eval(b.values()),
    )
}

/// Read-only batch preflight.  It checks every committed transcript cell and
/// all semantic challenge exclusions before the trace-one sampler allocates
/// its first row, preserving the all-tiles atomicity guarantee.
fn preflight_raw_transcript_tile(
    b: &FieldR1csBuilder,
    raw: &ZkAuthRawTranscriptTile,
) -> Result<(), ZkAuthorizationCandidateTraceError> {
    for (index, expression) in raw.owner_data.iter().enumerate() {
        check_transcript_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::OwnerPublicStatement,
            index,
        )?;
    }
    for (index, expression) in raw.owner_challenges.iter().enumerate() {
        check_transcript_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::OwnerRho,
            index,
        )?;
    }
    for (index, expression) in raw.main_data.iter().enumerate() {
        check_transcript_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::MainBridge,
            index,
        )?;
    }
    for (index, expression) in raw.main_challenges.iter().enumerate() {
        check_transcript_alias(
            b,
            expression,
            ZkAuthorizationCandidateInput::MainGamma,
            index,
        )?;
    }

    if raw_c1_value(
        b,
        &raw.owner_challenges,
        ZK_AUTH_OWNER_LAMBDA_CHALLENGE_INDEX,
    ) == F256::ZERO
    {
        return Err(ZkAuthorizationCandidateTraceError::LambdaZero);
    }
    if raw_c1_value(b, &raw.owner_challenges, ZK_AUTH_OWNER_ETA_CHALLENGE_INDEX) == F256::ZERO {
        return Err(ZkAuthorizationCandidateTraceError::EtaZero);
    }
    let terminal_blinding_weight = (0..ZK_PHASE_A_ROUNDS).fold(F256::ONE, |weight, round| {
        weight
            * raw_c1_value(
                b,
                &raw.owner_challenges,
                ZK_AUTH_OWNER_ROUND_CHALLENGE_START + round,
            )
    });
    if terminal_blinding_weight == F256::ZERO {
        return Err(ZkAuthorizationCandidateTraceError::TerminalBlindingWeightZero);
    }
    let gamma = raw_c1_value(b, &raw.main_challenges, ZK_AUTH_MAIN_GAMMA_CHALLENGE_INDEX);
    if gamma == F256::ZERO {
        return Err(ZkAuthorizationCandidateTraceError::GammaZero);
    }
    if gamma == F256::ONE {
        return Err(ZkAuthorizationCandidateTraceError::GammaOne);
    }
    Ok(())
}

#[cfg(test)]
fn preflight_candidate(
    b: &FieldR1csBuilder,
    cells: &ZkAuthTranscriptCells,
    external: &ZkAuthorizationCandidateExternalAliases,
) -> Result<(), ZkAuthorizationCandidateTraceError> {
    preflight_transcript_cells(b, cells)?;
    preflight_external_aliases(b, external)?;
    if cells.owner.lambda.eval(b.values()) == F256::ZERO {
        return Err(ZkAuthorizationCandidateTraceError::LambdaZero);
    }
    if cells.owner.eta.eval(b.values()) == F256::ZERO {
        return Err(ZkAuthorizationCandidateTraceError::EtaZero);
    }
    let terminal_blinding_weight = cells
        .owner
        .round_challenges
        .iter()
        .fold(F256::ONE, |weight, coordinate| {
            weight * coordinate.eval(b.values())
        });
    if terminal_blinding_weight == F256::ZERO {
        return Err(ZkAuthorizationCandidateTraceError::TerminalBlindingWeightZero);
    }
    let gamma = cells.main.gamma.eval(b.values());
    if gamma == F256::ZERO {
        return Err(ZkAuthorizationCandidateTraceError::GammaZero);
    }
    if gamma == F256::ONE {
        return Err(ZkAuthorizationCandidateTraceError::GammaOne);
    }
    Ok(())
}

/// Verify one complete disconnected authorization candidate.
///
/// All transcript cells and every external alias are preflighted before the
/// first row is appended.  On success the function adds exactly
/// [`ZK_AUTHORIZATION_CANDIDATE_TRACE_ROWS`] rows.  It assumes the caller has
/// separately applied the four split-bridge pins.
#[cfg(test)]
pub(crate) fn verify_zk_authorization_candidate_trace(
    b: &mut FieldR1csBuilder,
    cells: &ZkAuthTranscriptCells,
    external: &ZkAuthorizationCandidateExternalAliases,
) -> Result<ZkAuthorizationCandidateTraceOutput, ZkAuthorizationCandidateTraceError> {
    preflight_candidate(b, cells, external)?;
    verify_zk_authorization_candidate_trace_preflighted(b, cells, external)
}

/// Append the fixed candidate trace after its caller has authenticated and
/// preflighted every input. The raw-slice path uses this only after checking
/// all committed raw transcript lanes before materializing the C1 sampler.
fn verify_zk_authorization_candidate_trace_preflighted(
    b: &mut FieldR1csBuilder,
    cells: &ZkAuthTranscriptCells,
    external: &ZkAuthorizationCandidateExternalAliases,
) -> Result<ZkAuthorizationCandidateTraceOutput, ZkAuthorizationCandidateTraceError> {
    let trace_start = b.num_wires();

    let owner_rounds = std::array::from_fn(|round| ZkMleCheckRoundProofTrace {
        coeffs_without_constant: cells.owner.round_coefficients[round].clone(),
    });
    let terminal_operands = AuthCapsuleTerminalOperandClaimsTrace {
        increment: cells.owner.operand_claims[0].clone(),
        lane: std::array::from_fn(|lane| cells.owner.operand_claims[1 + lane].clone()),
    };
    let phase_a_rounds = std::array::from_fn(|round| ZkPhaseATraceRound {
        at_one: cells.main.phase_a_round_coefficients[round][0].clone(),
        at_infinity: cells.main.phase_a_round_coefficients[round][1].clone(),
    });
    let authorization_input = ZkAuthCompositionTraceInput {
        rho: cells.owner.rho.clone(),
        mask_mle_at_input: cells.owner.mask_mu.clone(),
        mask_final_at_terminal: cells.owner.mask_final.clone(),
        lambda: cells.owner.lambda.clone(),
        owner_rounds,
        owner_challenges_high_to_low: cells.owner.round_challenges.clone(),
        terminal_operands,
        expected_address: [
            cells.owner.public_statement[2].clone(),
            cells.owner.public_statement[3].clone(),
        ],
        eta: cells.owner.eta.clone(),
        companion_claim: cells.main.sigma.clone(),
        gamma: cells.main.gamma.clone(),
        phase_a_challenges_high_to_low: cells.main.phase_a_challenges.clone(),
        phase_a_rounds,
        terminal_oracle_value: cells.main.phase_b_value.clone(),
    };

    // Alias-only construction checks.  These are structural assertions over
    // LinExpr identities and allocate no rows.
    assert_eq!(authorization_input.rho, cells.owner.rho);
    assert_eq!(authorization_input.mask_mle_at_input, cells.owner.mask_mu);
    assert_eq!(
        authorization_input.mask_final_at_terminal,
        cells.owner.mask_final
    );
    assert_eq!(authorization_input.lambda, cells.owner.lambda);
    assert_eq!(
        authorization_input.owner_challenges_high_to_low,
        cells.owner.round_challenges
    );
    assert_eq!(
        authorization_input.expected_address,
        [
            cells.owner.public_statement[2].clone(),
            cells.owner.public_statement[3].clone(),
        ]
    );
    assert_eq!(authorization_input.eta, cells.owner.eta);
    assert_eq!(authorization_input.companion_claim, cells.main.sigma);
    assert_eq!(authorization_input.gamma, cells.main.gamma);
    assert_eq!(
        authorization_input.phase_a_challenges_high_to_low,
        cells.main.phase_a_challenges
    );
    assert_eq!(
        authorization_input.terminal_oracle_value,
        cells.main.phase_b_value
    );
    for round in 0..ZK_PHASE_A_ROUNDS {
        assert_eq!(
            authorization_input.owner_rounds[round].coeffs_without_constant,
            cells.owner.round_coefficients[round]
        );
        assert_eq!(
            authorization_input.phase_a_rounds[round].at_one,
            cells.main.phase_a_round_coefficients[round][0]
        );
        assert_eq!(
            authorization_input.phase_a_rounds[round].at_infinity,
            cells.main.phase_a_round_coefficients[round][1]
        );
    }

    let authorization = verify_zk_auth_composition_trace(b, &authorization_input)?;
    debug_assert_eq!(b.num_wires() - trace_start, ZK_AUTH_COMPOSITION_TRACE_ROWS);

    let nonce = verify_zk_auth_nonce_trace(b, &cells.main.nonce)?;
    debug_assert_eq!(
        b.num_wires() - trace_start,
        ZK_AUTH_COMPOSITION_TRACE_ROWS + ZK_AUTH_NONCE_TRACE_ROWS
    );

    let grind = verify_zk_auth_grind_trace(b, &cells.main.grind)?;
    debug_assert_eq!(
        b.num_wires() - trace_start,
        ZK_AUTH_COMPOSITION_TRACE_ROWS + ZK_AUTH_NONCE_TRACE_ROWS + ZK_AUTH_GRIND_TRACE_ROWS
    );

    let source_cap = cells.owner.source_cap_by_digest_lane();
    let mid_cap = cells.main.mid_cap_by_digest_lane();
    let phase_b_input = ZkPhaseBCompositionTraceInput {
        query_seeds: cells.main.query_seeds.clone(),
        source_path_directions: external.source_path_directions.clone(),
        mid_path_directions: external.mid_path_directions.clone(),
        joint_source_leaves: external.joint_source_leaves.clone(),
        mid_leaves: external.mid_leaves.clone(),
        source_cap,
        mid_cap,
        source_path_roots: external.source_path_roots.clone(),
        mid_path_roots: external.mid_path_roots.clone(),
        upper: cells.main.upper.clone(),
        phase_a_terminal_point: authorization.phase_a.terminal_point.clone(),
        beta: cells.main.beta.clone(),
        terminal_oracle_value: authorization.phase_a.terminal_oracle_value.clone(),
        tail: cells.main.tail.clone(),
        gamma: cells.main.gamma.clone(),
    };

    // Every cross-component hand-off is the exact expression returned by its
    // producer or read from the transcript view.  In particular no equality
    // copy is hidden between Phase A and Phase B.
    assert_eq!(phase_b_input.query_seeds, cells.main.query_seeds);
    assert_eq!(
        phase_b_input.source_cap,
        cells.owner.source_cap_by_digest_lane()
    );
    assert_eq!(phase_b_input.mid_cap, cells.main.mid_cap_by_digest_lane());
    assert_eq!(phase_b_input.upper, cells.main.upper);
    assert_eq!(phase_b_input.beta, cells.main.beta);
    assert_eq!(phase_b_input.tail, cells.main.tail);
    assert_eq!(phase_b_input.gamma, authorization_input.gamma);
    assert_eq!(phase_b_input.gamma, cells.main.gamma);
    assert_eq!(
        phase_b_input.phase_a_terminal_point,
        authorization.phase_a.terminal_point
    );
    assert_eq!(
        phase_b_input.terminal_oracle_value,
        authorization.phase_a.terminal_oracle_value
    );
    assert_eq!(
        phase_b_input.terminal_oracle_value,
        authorization_input.terminal_oracle_value
    );
    assert_eq!(
        phase_b_input.terminal_oracle_value,
        cells.main.phase_b_value
    );
    for low_variable in 0..ZK_PHASE_A_ROUNDS {
        assert_eq!(
            phase_b_input.phase_a_terminal_point[low_variable],
            cells.main.phase_a_challenges[ZK_PHASE_A_ROUNDS - 1 - low_variable]
        );
    }

    let phase_b = verify_zk_phase_b_composition_trace(b, &phase_b_input)?;
    debug_assert_eq!(
        b.num_wires() - trace_start,
        ZK_AUTHORIZATION_CANDIDATE_TRACE_ROWS
    );

    Ok(ZkAuthorizationCandidateTraceOutput {
        authorization,
        nonce,
        grind,
        phase_b,
    })
}

fn slice_range(slice: &WitnessSlice) -> std::ops::Range<usize> {
    let start = slice.start();
    let end = start
        .checked_add(slice.len())
        .expect("authorization committed-slice range overflow");
    start..end
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WalletOverflowLayout {
    tile_count: usize,
    meta_a_w_log: usize,
    meta_a_family_bases: [usize; 2],
    meta_b_w_log: usize,
    meta_b_block_log: usize,
    meta_b_family_bases: [usize; 2],
}

impl WalletOverflowLayout {
    fn for_geometry(geometry: crate::region_sidecar::SelectedZkBlockGeometry) -> Self {
        let tile_count = geometry.auth_tiles;
        let source_base = 1usize << geometry.exact_state_region_log;
        Self {
            tile_count,
            meta_a_w_log: geometry.meta_a_w_log,
            meta_a_family_bases: [
                source_base,
                source_base + tile_count * C1_CAPSULE_LEAF_STRIDE,
            ],
            meta_b_w_log: geometry.meta_b_w_log,
            meta_b_block_log: geometry.meta_b_block_log,
            meta_b_family_bases: geometry.wallet_overflow_bases,
        }
    }
}

#[cfg(test)]
fn raw_fixture_overflow_layout(tile_count: usize) -> WalletOverflowLayout {
    assert!(tile_count.is_power_of_two());
    // Private raw-slice fixtures use the minimal packed overflow domains.
    let meta_a_slots = tile_count * 2 * C1_CAPSULE_LEAF_STRIDE;
    let meta_b_slots = tile_count * ZK_AUTH_WALLET_B_PATH_STRIDE;
    WalletOverflowLayout {
        tile_count,
        meta_a_w_log: meta_a_slots.trailing_zeros() as usize,
        meta_a_family_bases: [0, tile_count * C1_CAPSULE_LEAF_STRIDE],
        meta_b_w_log: meta_b_slots.trailing_zeros() as usize,
        meta_b_block_log: 4,
        meta_b_family_bases: [
            ZK_AUTH_WALLET_B_SOURCE_PATH_OFFSET,
            ZK_AUTH_WALLET_B_MID_PATH_OFFSET,
        ],
    }
}

fn validate_raw_slice_tile_fixture(
    b: &FieldR1csBuilder,
    owner_a: &[WitnessSlice; 2],
    owner_c: &[WitnessSlice; 4],
    main_a: &[WitnessSlice; 2],
    main_c: &[WitnessSlice; 4],
    wallet_a: &[WitnessSlice; ZK_AUTH_WALLET_A_COLUMNS],
    wallet_b: &[WitnessSlice; ZK_AUTH_WALLET_B_COLUMNS],
    meta_a: &[WitnessSlice; ZK_AUTH_META_A_COLUMNS],
    meta_b: &[WitnessSlice; ZK_AUTH_META_B_COLUMNS],
    overflow: WalletOverflowLayout,
    tile_index: usize,
) -> usize {
    let owner = owner_a.iter().chain(owner_c).copied().collect::<Vec<_>>();
    let main = main_a.iter().chain(main_c).copied().collect::<Vec<_>>();
    let families: [(&str, &[WitnessSlice], usize); 4] = [
        ("Owner", &owner, ZK_AUTH_OWNER_TILE_LOG),
        ("Main", &main, ZK_AUTH_MAIN_TILE_LOG),
        ("Wallet-A", wallet_a, ZK_AUTH_WALLET_A_TILE_LOG),
        ("Wallet-B", wallet_b, ZK_AUTH_WALLET_B_TILE_LOG),
    ];
    let mut tile_counts = [0usize; 4];
    for (family, (name, slices, tile_log)) in families.iter().enumerate() {
        assert!(!slices.is_empty(), "{name} committed family is empty");
        assert!(
            slices.iter().all(|slice| slice.log2_len >= *tile_log),
            "{name} committed domain is below its selected tile"
        );
        assert!(
            slices
                .iter()
                .all(|slice| slice.log2_len == slices[0].log2_len),
            "{name} columns must share one tiled domain"
        );
        tile_counts[family] = 1usize << (slices[0].log2_len - tile_log);
    }
    assert!(
        tile_counts.iter().all(|&count| count == tile_counts[0]),
        "Owner/Main/Wallet-A/Wallet-B tile counts must agree"
    );
    assert!(
        tile_index < tile_counts[0],
        "authorization tile out of range"
    );
    assert_eq!(tile_counts[0], overflow.tile_count, "overflow tile count");
    assert!(meta_a
        .iter()
        .all(|slice| slice.log2_len == overflow.meta_a_w_log));
    assert!(meta_b
        .iter()
        .all(|slice| slice.log2_len == overflow.meta_b_w_log));

    let all = owner
        .iter()
        .chain(main.iter())
        .chain(wallet_a.iter())
        .chain(wallet_b.iter())
        .chain(meta_a.iter())
        .chain(meta_b.iter())
        .copied()
        .collect::<Vec<_>>();
    for (index, left) in all.iter().enumerate() {
        let left_range = slice_range(left);
        assert!(
            left_range.end <= b.num_wires(),
            "authorization committed slice is outside the current witness"
        );
        for right in &all[index + 1..] {
            let right_range = slice_range(right);
            assert!(
                left_range.end <= right_range.start || right_range.end <= left_range.start,
                "authorization committed columns must be pairwise disjoint"
            );
        }
    }
    tile_counts[0]
}

fn wallet_external_aliases(
    wallet_a: &[WitnessSlice; ZK_AUTH_WALLET_A_COLUMNS],
    wallet_b: &[WitnessSlice; ZK_AUTH_WALLET_B_COLUMNS],
    meta_a: &[WitnessSlice; ZK_AUTH_META_A_COLUMNS],
    meta_b: &[WitnessSlice; ZK_AUTH_META_B_COLUMNS],
    overflow: WalletOverflowLayout,
    tile_index: usize,
) -> ZkAuthorizationCandidateExternalAliases {
    let wallet_a_base = tile_index << ZK_AUTH_WALLET_A_TILE_LOG;
    let wallet_b_base = tile_index << ZK_AUTH_WALLET_B_TILE_LOG;
    let source_a_base = wallet_a_base;
    let mid_a_base = wallet_a_base + ZK_AUTH_WALLET_A_MID_BASE;

    let leaf = |family: usize, query: usize, symbol: usize| {
        if query < ZK_AUTH_WALLET_CORE_QUERY_COUNT {
            let family_base = if family == 0 {
                source_a_base
            } else {
                mid_a_base
            };
            let active_slots = if family == 0 {
                C1_CAPSULE_SOURCE_SLOTS
            } else {
                C1_CAPSULE_MID_SLOTS
            };
            let tile = family_base + query * active_slots;
            slot_cell(&wallet_a[symbol & 1], tile + symbol / 2)
        } else {
            debug_assert_eq!(query, ZK_AUTH_WALLET_OVERFLOW_QUERY);
            let tile = overflow.meta_a_family_bases[family] + tile_index * C1_CAPSULE_LEAF_STRIDE;
            slot_cell(&meta_a[2 + (symbol & 1)], tile + symbol / 2)
        }
    };
    let path_slot = |family: usize, query: usize, depth: usize| {
        if query < ZK_AUTH_WALLET_CORE_QUERY_COUNT {
            let family_offset = if family == 0 {
                ZK_AUTH_WALLET_B_SOURCE_PATH_OFFSET
            } else {
                ZK_AUTH_WALLET_B_MID_PATH_OFFSET
            };
            wallet_b_base + query * ZK_AUTH_WALLET_B_PATH_STRIDE + family_offset + depth
        } else {
            debug_assert_eq!(query, ZK_AUTH_WALLET_OVERFLOW_QUERY);
            (tile_index << overflow.meta_b_block_log) + overflow.meta_b_family_bases[family] + depth
        }
    };
    let direction = |family: usize, query: usize, depth: usize| {
        if query < ZK_AUTH_WALLET_CORE_QUERY_COUNT {
            slot_cell(&wallet_b[8], path_slot(family, query, depth))
        } else {
            slot_cell(&meta_b[8], path_slot(family, query, depth))
        }
    };
    // Before the composite-root multiplications exist, use the final C cells
    // as dynamic placeholders. The raw-slice helper replaces these aliases
    // before invoking Phase B; they only let the all-input atomic preflight
    // inspect every other Wallet-A/B family before any row is appended.
    let root_placeholder = |family: usize, query: usize, lane: usize| {
        let depth = if family == 0 {
            ZK_AUTH_WALLET_B_SOURCE_PATH_DEPTH
        } else {
            ZK_AUTH_WALLET_B_MID_PATH_DEPTH
        };
        let slot = path_slot(family, query, depth - 1);
        if query < ZK_AUTH_WALLET_CORE_QUERY_COUNT {
            slot_cell(&wallet_b[lane], slot)
        } else {
            slot_cell(&meta_b[lane], slot)
        }
    };

    ZkAuthorizationCandidateExternalAliases {
        source_path_directions: std::array::from_fn(|query| {
            std::array::from_fn(|depth| direction(0, query, depth))
        }),
        mid_path_directions: std::array::from_fn(|query| {
            std::array::from_fn(|depth| direction(1, query, depth))
        }),
        joint_source_leaves: std::array::from_fn(|query| {
            std::array::from_fn(|symbol| leaf(0, query, symbol))
        }),
        mid_leaves: std::array::from_fn(|query| {
            std::array::from_fn(|symbol| {
                ExtExpr::new(leaf(1, query, 2 * symbol), leaf(1, query, 2 * symbol + 1))
            })
        }),
        source_path_roots: std::array::from_fn(|query| {
            std::array::from_fn(|lane| root_placeholder(0, query, lane))
        }),
        mid_path_roots: std::array::from_fn(|query| {
            std::array::from_fn(|lane| root_placeholder(1, query, lane))
        }),
    }
}

fn assert_outer_statement_aliases(
    b: &FieldR1csBuilder,
    public: &SelectedZkAuthorizationStatementTrace,
    committed_slices: &[WitnessSlice],
) -> Result<(), ZkAuthorizationCandidateTraceError> {
    for lane in 0..2 {
        for (input, expression) in [
            (
                ZkAuthorizationCandidateInput::OuterTxBodyHash,
                &public.tx_body_hash[lane],
            ),
            (
                ZkAuthorizationCandidateInput::OuterExpectedAddress,
                &public.expected_address[lane],
            ),
        ] {
            check_transcript_alias(b, expression, input, lane)?;
            let wire = expression.terms[0].0 as usize;
            assert!(
                committed_slices
                    .iter()
                    .all(|slice| !slice_range(slice).contains(&wire)),
                "outer owner statement must not alias a self-selected committed transcript cell"
            );
        }
    }
    Ok(())
}

fn composite_wallet_roots(
    b: &mut FieldR1csBuilder,
    wallet_b: &[WitnessSlice; ZK_AUTH_WALLET_B_COLUMNS],
    meta_b: &[WitnessSlice; ZK_AUTH_META_B_COLUMNS],
    overflow: WalletOverflowLayout,
    tile_index: usize,
    family: usize,
) -> [[LinExpr; ZK_PHASE_B_CAP_DIGEST_LANES]; ZK_QUERY_COUNT] {
    let wallet_b_base = tile_index << ZK_AUTH_WALLET_B_TILE_LOG;
    let family_offset = if family == 0 {
        ZK_AUTH_WALLET_B_SOURCE_PATH_OFFSET
    } else {
        ZK_AUTH_WALLET_B_MID_PATH_OFFSET
    };
    let path_depth = if family == 0 {
        ZK_AUTH_WALLET_B_SOURCE_PATH_DEPTH
    } else {
        ZK_AUTH_WALLET_B_MID_PATH_DEPTH
    };
    std::array::from_fn(|query| {
        let (columns, last) = if query < ZK_AUTH_WALLET_CORE_QUERY_COUNT {
            (
                wallet_b,
                wallet_b_base + query * ZK_AUTH_WALLET_B_PATH_STRIDE + family_offset + path_depth
                    - 1,
            )
        } else {
            debug_assert_eq!(query, ZK_AUTH_WALLET_OVERFLOW_QUERY);
            (
                meta_b,
                (tile_index << overflow.meta_b_block_log)
                    + overflow.meta_b_family_bases[family]
                    + path_depth
                    - 1,
            )
        };
        let direction = slot_cell(&columns[8], last);
        std::array::from_fn(|lane| {
            let carry = slot_cell(&columns[4 + lane], last);
            let sibling = slot_cell(&columns[6 + lane], last);
            let selected_delta = mul(b, &direction, &carry.add(&sibling));
            slot_cell(&columns[lane], last)
                .add(&carry)
                .add(&selected_delta)
        })
    })
}

/// Exercise one authorization tile over caller-supplied committed-slice
/// geometry.
///
/// This is deliberately private: it proves the candidate algebra for the
/// supplied cells, but raw slices carry no evidence that the canonical
/// post-commit Owner/Main/Wallet sidecars authenticate those exact columns.
/// It also checks only `tile_index`, not all tiles in the family.  Production
/// code can reach it only through the owning all-tiles batch above; direct
/// calls remain local fixture coverage.
#[allow(clippy::too_many_arguments)]
fn preflight_zk_authorization_raw_slice_tile_candidate_trace(
    b: &FieldR1csBuilder,
    owner_layout: &DuplexLayout,
    owner_a: &[WitnessSlice; 2],
    owner_c: &[WitnessSlice; 4],
    main_layout: &DuplexLayout,
    main_a: &[WitnessSlice; 2],
    main_c: &[WitnessSlice; 4],
    wallet_a: &[WitnessSlice; ZK_AUTH_WALLET_A_COLUMNS],
    wallet_b: &[WitnessSlice; ZK_AUTH_WALLET_B_COLUMNS],
    meta_a: &[WitnessSlice; ZK_AUTH_META_A_COLUMNS],
    meta_b: &[WitnessSlice; ZK_AUTH_META_B_COLUMNS],
    overflow: WalletOverflowLayout,
    tile_index: usize,
    public: &SelectedZkAuthorizationStatementTrace,
) -> Result<ZkAuthorizationCandidateExternalAliases, ZkAuthorizationCandidateTraceError> {
    validate_raw_slice_tile_fixture(
        b, owner_a, owner_c, main_a, main_c, wallet_a, wallet_b, meta_a, meta_b, overflow,
        tile_index,
    );
    let raw = view_zk_auth_raw_split_transcript_tile(
        owner_layout,
        owner_a,
        owner_c,
        main_layout,
        main_a,
        main_c,
        wallet_a,
        tile_index,
    );
    let external =
        wallet_external_aliases(wallet_a, wallet_b, meta_a, meta_b, overflow, tile_index);
    preflight_raw_transcript_tile(b, &raw)?;
    preflight_external_aliases(b, &external)?;
    let committed_slices = owner_a
        .iter()
        .chain(owner_c)
        .chain(main_a)
        .chain(main_c)
        .chain(wallet_a)
        .chain(wallet_b)
        .chain(meta_a)
        .chain(meta_b)
        .copied()
        .collect::<Vec<_>>();
    assert_outer_statement_aliases(b, public, &committed_slices)?;
    Ok(external)
}

#[allow(clippy::too_many_arguments)]
fn verify_zk_authorization_raw_slice_tile_candidate_trace(
    b: &mut FieldR1csBuilder,
    owner_layout: &DuplexLayout,
    owner_a: &[WitnessSlice; 2],
    owner_c: &[WitnessSlice; 4],
    main_layout: &DuplexLayout,
    main_a: &[WitnessSlice; 2],
    main_c: &[WitnessSlice; 4],
    wallet_a: &[WitnessSlice; ZK_AUTH_WALLET_A_COLUMNS],
    wallet_b: &[WitnessSlice; ZK_AUTH_WALLET_B_COLUMNS],
    meta_a: &[WitnessSlice; ZK_AUTH_META_A_COLUMNS],
    meta_b: &[WitnessSlice; ZK_AUTH_META_B_COLUMNS],
    overflow: WalletOverflowLayout,
    tile_index: usize,
    public: &SelectedZkAuthorizationStatementTrace,
) -> Result<
    (ZkAuthSplitBridgeCells, ZkAuthorizationCandidateTraceOutput),
    ZkAuthorizationCandidateTraceError,
> {
    let mut external = preflight_zk_authorization_raw_slice_tile_candidate_trace(
        b,
        owner_layout,
        owner_a,
        owner_c,
        main_layout,
        main_a,
        main_c,
        wallet_a,
        wallet_b,
        meta_a,
        meta_b,
        overflow,
        tile_index,
        public,
    )?;

    let wrapper_start = b.num_wires();
    let cells = view_zk_auth_split_transcript_tile(
        b,
        owner_layout,
        owner_a,
        owner_c,
        main_layout,
        main_a,
        main_c,
        wallet_a,
        tile_index,
    );
    debug_assert_eq!(
        b.num_wires() - wrapper_start,
        ZK_AUTH_RAW_SLICE_C1_SAMPLER_ROWS
    );
    for lane in 0..2 {
        pin_eq(
            b,
            &cells.owner.public_statement[lane],
            &public.tx_body_hash[lane],
        );
        pin_eq(
            b,
            &cells.owner.public_statement[2 + lane],
            &public.expected_address[lane],
        );
    }
    debug_assert_eq!(
        b.num_wires() - wrapper_start,
        ZK_AUTH_RAW_SLICE_C1_SAMPLER_ROWS + ZK_AUTH_RAW_SLICE_STATEMENT_PIN_ROWS
    );

    let bridge = pin_zk_auth_c1_split_bridge_at(b, owner_c, main_a, main_c, wallet_a, tile_index);
    assert_eq!(bridge.main_absorb, cells.main.bridge);
    assert_eq!(bridge.sigma, cells.main.sigma);
    debug_assert_eq!(
        b.num_wires() - wrapper_start,
        ZK_AUTH_RAW_SLICE_C1_SAMPLER_ROWS
            + ZK_AUTH_RAW_SLICE_STATEMENT_PIN_ROWS
            + ZK_AUTH_SPLIT_BRIDGE_PIN_ROWS
    );

    let wallet_a_base = tile_index << ZK_AUTH_WALLET_A_TILE_LOG;
    let wallet_b_base = tile_index << ZK_AUTH_WALLET_B_TILE_LOG;
    for query in 0..ZK_QUERY_COUNT {
        for family in 0..2 {
            let (a_columns, leaf_tile, b_columns, path_start) =
                if query < ZK_AUTH_WALLET_CORE_QUERY_COUNT {
                    (
                        wallet_a.as_slice(),
                        wallet_a_base
                            + if family == 0 {
                                ZK_AUTH_WALLET_A_SOURCE_BASE + query * C1_CAPSULE_SOURCE_SLOTS
                            } else {
                                ZK_AUTH_WALLET_A_MID_BASE + query * C1_CAPSULE_MID_SLOTS
                            },
                        wallet_b.as_slice(),
                        wallet_b_base
                            + query * ZK_AUTH_WALLET_B_PATH_STRIDE
                            + if family == 0 {
                                ZK_AUTH_WALLET_B_SOURCE_PATH_OFFSET
                            } else {
                                ZK_AUTH_WALLET_B_MID_PATH_OFFSET
                            },
                    )
                } else {
                    debug_assert_eq!(query, ZK_AUTH_WALLET_OVERFLOW_QUERY);
                    (
                        meta_a.as_slice(),
                        overflow.meta_a_family_bases[family] + tile_index * C1_CAPSULE_LEAF_STRIDE,
                        meta_b.as_slice(),
                        (tile_index << overflow.meta_b_block_log)
                            + overflow.meta_b_family_bases[family],
                    )
                };
            for lane in 0..2 {
                let a_digest_column = if query < ZK_AUTH_WALLET_CORE_QUERY_COUNT {
                    2 + lane
                } else {
                    4 + lane
                };
                pin_eq(
                    b,
                    &slot_cell(
                        &a_columns[a_digest_column],
                        leaf_tile
                            + if family == 0 {
                                C1_CAPSULE_SOURCE_DIGEST_SLOT
                            } else {
                                C1_CAPSULE_MID_DIGEST_SLOT
                            },
                    ),
                    &slot_cell(&b_columns[4 + lane], path_start),
                );
            }
        }
    }
    debug_assert_eq!(
        b.num_wires() - wrapper_start,
        ZK_AUTH_RAW_SLICE_C1_SAMPLER_ROWS
            + ZK_AUTH_RAW_SLICE_STATEMENT_PIN_ROWS
            + ZK_AUTH_SPLIT_BRIDGE_PIN_ROWS
            + ZK_AUTH_RAW_SLICE_DIGEST_BRIDGE_ROWS
    );

    external.source_path_roots =
        composite_wallet_roots(b, wallet_b, meta_b, overflow, tile_index, 0);
    external.mid_path_roots = composite_wallet_roots(b, wallet_b, meta_b, overflow, tile_index, 1);
    debug_assert_eq!(
        b.num_wires() - wrapper_start,
        ZK_AUTH_RAW_SLICE_PRE_CORE_ROWS
    );

    let candidate = verify_zk_authorization_candidate_trace_preflighted(b, &cells, &external)?;
    debug_assert_eq!(
        b.num_wires() - wrapper_start,
        ZK_AUTH_RAW_SLICE_PRE_CORE_ROWS + ZK_AUTHORIZATION_CANDIDATE_TRACE_ROWS
    );

    debug_assert_eq!(
        b.num_wires() - wrapper_start,
        ZK_AUTH_RAW_SLICE_TILE_TRACE_ROWS
    );
    Ok((bridge, candidate))
}

#[cfg(test)]
mod tests {
    const SELECTED_ZK_AUTH_TILE_COUNT: usize = 256;

    use noid_core::mle::evaluate::evaluate_slice;
    use noid_core::mle::fold::fold_variable_inplace;
    use noid_core::{Block128, Block256, TowerField};
    use noid_fri_binius::capsule::capsule_query_bit_location;
    use noid_fri_binius::zk_affine_code::{ZkAffineLchCode, AFFINE_CODE_MESSAGE_LEN};
    use noid_fri_binius::zk_capsule_algebra::{
        build_fold_normal_joint_source_leaf, build_fold_normal_mid_leaf,
        contract_high3_for_each_low8, evaluate_upper_at_low8, OWNER_BANK_POINT_VARS,
        PHASE_B_HIGH_VARS, PHASE_B_LOW_VARS, SOURCE_QUERY_BITS, SOURCE_STANDARD_FOLDS,
        TAIL_SYMBOLS, UPPER_SYMBOLS,
    };
    use noid_fri_binius::zk_phase_a::{
        prove_phase_a, verify_phase_a, ZkPhaseARoundProof, PHASE_A_ORACLE_LEN,
    };
    use noid_gkr::layers::evaluate_permutation;
    use noid_gkr::zk_auth_capsule::{
        build_explicit_mlecheck_carrier, build_post_claim_relation, state_cell_index,
        AuthCapsuleBoundaryPublic, AuthCapsuleTerminalOperandClaims, ZkAuthCapsuleBankView,
        ZK_AUTH_CAPSULE_BANK_LEN, ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET,
        ZK_AUTH_CAPSULE_PCS_COINS_OFFSET, ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET,
    };
    use noid_gkr::zk_mlecheck::ZkMleCheckRoundProof;
    use noid_ivc_core::deep_chain::capsule_leaf::{flat_c1_capsule_leaf_hash, C1CapsuleLeafKind};
    use noid_ivc_core::deep_chain::schedule::LaneSource;
    use noid_ivc_core::field_r1cs::FieldR1cs;
    use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRFIX};

    use super::super::region_source_binding::{alloc_boolean_column_slice, alloc_column_slice};
    use super::super::zk_auth_transcript_cells::{
        ZkAuthMainTranscriptCells, ZkAuthOwnerTranscriptCells,
    };
    use super::super::zk_phase_b_composition::{
        ZK_PHASE_B_MID_CAP_NODES, ZK_PHASE_B_SOURCE_CAP_NODES,
    };
    use super::super::{alloc_block, alloc_block256, const_block256, flat_of_ext};
    use super::*;
    use crate::acceptance::block_slots::canonical_selected_zk_authorization_fixture;
    use crate::acceptance::zk_auth_capsule_schedule::ZkAuthCapsuleDuplexSchedules;

    #[derive(Clone)]
    struct NativeCandidate {
        public_statement: [Block128; 4],
        source_cap: [[Block128; ZK_PHASE_B_SOURCE_CAP_NODES]; ZK_PHASE_B_CAP_DIGEST_LANES],
        rho: [Block256; OWNER_BANK_POINT_VARS],
        mask_mu: Block256,
        mask_final: Block256,
        lambda: Block256,
        owner_rounds: [ZkMleCheckRoundProof<Block256>; OWNER_BANK_POINT_VARS],
        owner_challenges: [Block256; OWNER_BANK_POINT_VARS],
        terminal_operands: AuthCapsuleTerminalOperandClaims<Block256>,
        eta: Block256,
        sigma: Block256,
        gamma: Block256,
        phase_a_challenges: [Block256; ZK_PHASE_A_ROUNDS],
        phase_a_rounds: [ZkPhaseARoundProof<Block256>; ZK_PHASE_A_ROUNDS],
        terminal_oracle_value: Block256,
        upper: [Block256; UPPER_SYMBOLS],
        beta: [Block256; PHASE_B_LOW_VARS],
        mid_cap: [[Block128; ZK_PHASE_B_MID_CAP_NODES]; ZK_PHASE_B_CAP_DIGEST_LANES],
        tail: [Block256; TAIL_SYMBOLS],
        grind: Block128,
        query_seeds: [Block128; 7],
        owner_raw_challenges: [Block128; 2 * ZK_AUTH_OWNER_SQUEEZES],
        main_raw_challenges: [Block128; ZK_AUTH_MAIN_RAW_CHALLENGE_LANES],
        queries: [usize; ZK_QUERY_COUNT],
        joint_source_leaves: [[Block128; JOINT_SOURCE_LEAF_SYMBOLS]; ZK_QUERY_COUNT],
        mid_leaves: [[Block256; 1 << MID_STANDARD_FOLDS]; ZK_QUERY_COUNT],
        source_path_roots: [[Block128; ZK_PHASE_B_CAP_DIGEST_LANES]; ZK_QUERY_COUNT],
        mid_path_roots: [[Block128; ZK_PHASE_B_CAP_DIGEST_LANES]; ZK_QUERY_COUNT],
    }

    fn alloc_selected_statement(
        b: &mut FieldR1csBuilder,
        native: &NativeCandidate,
    ) -> SelectedZkAuthorizationStatementTrace {
        SelectedZkAuthorizationStatementTrace::new(
            [
                alloc_block(b, native.public_statement[0]),
                alloc_block(b, native.public_statement[1]),
            ],
            [
                alloc_block(b, native.public_statement[2]),
                alloc_block(b, native.public_statement[3]),
            ],
        )
    }

    fn elem(index: usize, domain: u128, salt: u128) -> Block128 {
        let mut value = Block128::from(
            domain
                .wrapping_mul(index as u128 + 1)
                .rotate_left(((19 * index + 7) % 127) as u32)
                ^ salt.rotate_left(((11 * index + 3) % 127) as u32)
                ^ (index as u128 + 5).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        );
        if value == Block128::ZERO || value == Block128::ONE {
            value += Block128::from(2u128);
        }
        value
    }

    fn raw_challenges<const N: usize>(domain: u128, salt: u128) -> [Block128; N] {
        std::array::from_fn(|index| elem(index + 29, domain, salt))
    }

    fn mapped_challenge(raw: &[Block128], index: usize) -> Block256 {
        Block256::from_raw_challenge_lanes(raw[2 * index], raw[2 * index + 1])
    }

    fn packed_queries(seeds: &[Block128; 7]) -> [usize; ZK_QUERY_COUNT] {
        std::array::from_fn(|query| {
            (0..SOURCE_QUERY_BITS).fold(0usize, |index, query_bit| {
                let (seed, bit) = capsule_query_bit_location(query, query_bit, SOURCE_QUERY_BITS);
                index | ((((seeds[seed].0 >> bit) & 1) as usize) << query_bit)
            })
        })
    }

    fn native_candidate(salt: u128) -> NativeCandidate {
        let iv = capacity_iv(TAG_ADDRFIX);
        let permutation = evaluate_permutation([
            elem(0, 0x5EC2_E7, salt),
            elem(1, 0x5EC2_E7, salt ^ 0x10),
            iv[0],
            iv[1],
        ]);
        let expected_address = [permutation.final_state()[0], permutation.final_state()[1]];
        let mut bank = vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN];
        for (round, row) in permutation.state.iter().enumerate() {
            for (lane, value) in row.iter().copied().enumerate() {
                bank[state_cell_index(round, lane).unwrap()] = value;
            }
        }
        for (index, cell) in bank
            .iter_mut()
            .enumerate()
            .take(ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET)
            .skip(ZK_AUTH_CAPSULE_PCS_COINS_OFFSET)
        {
            *cell = elem(index, 0xC01A_5, salt ^ 0x20);
        }
        for (index, cell) in bank
            .iter_mut()
            .enumerate()
            .take(ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET)
            .skip(ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET)
        {
            *cell = elem(index, 0x11B2_A, salt ^ 0x30);
        }
        for (index, cell) in bank
            .iter_mut()
            .enumerate()
            .skip(ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET)
        {
            *cell = elem(index, 0xA771_A6, salt ^ 0x40);
        }
        let bank_view = ZkAuthCapsuleBankView::checked(&bank).expect("bank shape");

        let owner_raw_challenges =
            raw_challenges::<{ 2 * ZK_AUTH_OWNER_SQUEEZES }>(0x1A90_7, salt ^ 0x50);
        let rho = std::array::from_fn(|index| mapped_challenge(&owner_raw_challenges, index));
        let lambda = mapped_challenge(&owner_raw_challenges, ZK_AUTH_OWNER_LAMBDA_CHALLENGE_INDEX);
        let owner_challenges = std::array::from_fn(|index| {
            mapped_challenge(
                &owner_raw_challenges,
                ZK_AUTH_OWNER_ROUND_CHALLENGE_START + index,
            )
        });
        let carrier = build_explicit_mlecheck_carrier(bank_view, rho, lambda, owner_challenges)
            .expect("real explicit Owner carrier");
        let eta = mapped_challenge(&owner_raw_challenges, ZK_AUTH_OWNER_ETA_CHALLENGE_INDEX);
        let relation = build_post_claim_relation(
            &rho,
            &carrier.terminal_point,
            AuthCapsuleBoundaryPublic::canonical(expected_address),
            carrier.post_claims(),
            eta,
        )
        .expect("native post-claim relation");
        assert!(relation.verify(bank_view));

        let companion: Vec<Block256> = (0..PHASE_A_ORACLE_LEN)
            .map(|index| {
                Block256::new(
                    elem(index, 0xC09A_91, salt ^ 0x90),
                    elem(index + 113, 0xC125_6, salt ^ 0x91),
                )
            })
            .collect();
        assert!(
            companion
                .iter()
                .zip(&bank)
                .any(|(&companion, &bank)| companion != Block256::from(bank)),
            "companion must remain independent"
        );
        let mut main_raw_challenges =
            raw_challenges::<ZK_AUTH_MAIN_RAW_CHALLENGE_LANES>(0x5A11_CE, salt ^ 0xA0);
        let gamma = mapped_challenge(&main_raw_challenges, ZK_AUTH_MAIN_GAMMA_CHALLENGE_INDEX);
        let phase_a_challenges = std::array::from_fn(|index| {
            mapped_challenge(
                &main_raw_challenges,
                ZK_AUTH_MAIN_PHASE_A_CHALLENGE_START + index,
            )
        });
        let phase_a = prove_phase_a(
            &bank,
            &companion,
            &relation.weights,
            gamma,
            &phase_a_challenges,
        )
        .expect("native Phase A");
        let verified_phase_a = verify_phase_a(
            &phase_a.proof,
            phase_a.relation_claims,
            &relation.weights,
            gamma,
            &phase_a_challenges,
            phase_a.terminal_oracle_value,
        )
        .expect("native Phase A verifies");
        assert_eq!(
            verified_phase_a.terminal_relation_value,
            evaluate_slice(&relation.weights, &phase_a.terminal_point)
        );

        let bank: [Block128; AFFINE_CODE_MESSAGE_LEN] = bank
            .try_into()
            .unwrap_or_else(|_| unreachable!("Auth bank is the affine message"));
        let companion: [Block256; AFFINE_CODE_MESSAGE_LEN] = companion
            .try_into()
            .unwrap_or_else(|_| unreachable!("companion is the affine message"));
        let virtual_bank: [Block256; AFFINE_CODE_MESSAGE_LEN] = std::array::from_fn(|index| {
            let bank = Block256::from(bank[index]);
            bank + gamma * (bank + companion[index])
        });
        let beta: [Block256; PHASE_B_LOW_VARS] = std::array::from_fn(|index| {
            mapped_challenge(
                &main_raw_challenges,
                ZK_AUTH_MAIN_BETA_CHALLENGE_START + index,
            )
        });
        let grind = Block128::from(elem(97, 0x6A1D, salt ^ 0x101).0 & !0xFFFFu128);
        main_raw_challenges[ZK_AUTH_MAIN_GRIND_RAW_CHALLENGE_INDEX] = grind;
        let query_seeds: [Block128; 7] = std::array::from_fn(|index| {
            let seed = elem(index + 71, 0x5EED, salt ^ 0xD0);
            main_raw_challenges[ZK_AUTH_MAIN_QUERY_SEED_RAW_CHALLENGE_START + index] = seed;
            seed
        });
        let queries = packed_queries(&query_seeds);

        let code = ZkAffineLchCode::selected().expect("selected affine code");
        let bank_code = code.encode(&bank).expect("bank codeword");
        let companion_code = code
            .encode_extension_after_low_folds(&companion, 0)
            .expect("companion codeword");
        let mut mid_code = code
            .encode_extension_after_low_folds(&virtual_bank, 0)
            .expect("virtual codeword");
        for round in 0..SOURCE_STANDARD_FOLDS {
            mid_code = code
                .fold_codeword_once_extension(&mid_code, round, beta[round])
                .expect("source fold");
        }
        let joint_source_leaves = std::array::from_fn(|query| {
            build_fold_normal_joint_source_leaf(&code, &bank_code, &companion_code, queries[query])
                .expect("fold-normal joint source leaf")
        });
        let mid_leaves = std::array::from_fn(|query| {
            build_fold_normal_mid_leaf(&code, &mid_code, queries[query] >> MID_STANDARD_FOLDS)
                .expect("fold-normal mid leaf")
        });
        for round in 0..MID_STANDARD_FOLDS {
            mid_code = code
                .fold_codeword_once_extension(
                    &mid_code,
                    SOURCE_STANDARD_FOLDS + round,
                    beta[SOURCE_STANDARD_FOLDS + round],
                )
                .expect("mid fold");
        }
        let mut tail_vec = virtual_bank.to_vec();
        for challenge in &beta[..SOURCE_STANDARD_FOLDS + MID_STANDARD_FOLDS] {
            fold_variable_inplace(&mut tail_vec, *challenge, 0);
        }
        let tail: [Block256; TAIL_SYMBOLS] =
            tail_vec.try_into().expect("seven folds leave sixteen");
        assert_eq!(
            code.encode_extension_after_low_folds(
                &tail,
                SOURCE_STANDARD_FOLDS + MID_STANDARD_FOLDS,
            )
            .expect("tail codeword"),
            mid_code
        );

        let high_point: &[Block256; PHASE_B_HIGH_VARS] = phase_a.terminal_point[PHASE_B_LOW_VARS..]
            .try_into()
            .expect("three high coordinates");
        let low_point: &[Block256; PHASE_B_LOW_VARS] = phase_a.terminal_point[..PHASE_B_LOW_VARS]
            .try_into()
            .expect("eight low coordinates");
        let upper = contract_high3_for_each_low8(&virtual_bank, high_point);
        let terminal_oracle_value = evaluate_upper_at_low8(&upper, low_point);
        assert_eq!(terminal_oracle_value, phase_a.terminal_oracle_value);

        let source_cap = std::array::from_fn(|lane| {
            std::array::from_fn(|node| elem(node + 101 * lane, 0x5CA9, salt ^ 0xE0))
        });
        let mid_cap = std::array::from_fn(|lane| {
            std::array::from_fn(|node| elem(node + 13 * lane, 0x1DC4, salt ^ 0xF0))
        });
        let source_path_roots = std::array::from_fn(|query| {
            let cap_index = queries[query] >> ZK_AUTH_WALLET_B_SOURCE_PATH_DEPTH;
            std::array::from_fn(|lane| source_cap[lane][cap_index])
        });
        let mid_path_roots = std::array::from_fn(|query| {
            let cap_index =
                (queries[query] >> MID_STANDARD_FOLDS) >> ZK_AUTH_WALLET_B_MID_PATH_DEPTH;
            std::array::from_fn(|lane| mid_cap[lane][cap_index])
        });

        NativeCandidate {
            public_statement: [
                elem(101, 0x57A7E, salt),
                elem(102, 0x57A7E, salt),
                expected_address[0],
                expected_address[1],
            ],
            source_cap,
            rho,
            mask_mu: carrier.mask_mle_at_input,
            mask_final: carrier.mask_final_at_terminal,
            lambda,
            owner_rounds: carrier
                .round_proofs
                .try_into()
                .expect("eleven Owner rounds"),
            owner_challenges,
            terminal_operands: carrier.terminal_operands,
            eta,
            sigma: phase_a.relation_claims.companion,
            gamma,
            phase_a_challenges,
            phase_a_rounds: phase_a.proof.rounds,
            terminal_oracle_value,
            upper,
            beta,
            mid_cap,
            tail,
            grind,
            query_seeds,
            owner_raw_challenges,
            main_raw_challenges,
            queries,
            joint_source_leaves,
            mid_leaves,
            source_path_roots,
            mid_path_roots,
        }
    }

    fn alloc_cells(b: &mut FieldR1csBuilder, native: &NativeCandidate) -> ZkAuthTranscriptCells {
        let owner = ZkAuthOwnerTranscriptCells {
            public_statement: std::array::from_fn(|index| {
                alloc_block(b, native.public_statement[index])
            }),
            source_cap: std::array::from_fn(|index| {
                alloc_block(b, native.source_cap[index & 1][index >> 1])
            }),
            mask_mu: alloc_block256(b, native.mask_mu),
            round_coefficients: std::array::from_fn(|round| {
                std::array::from_fn(|coefficient| {
                    alloc_block256(
                        b,
                        native.owner_rounds[round].coeffs_without_constant[coefficient],
                    )
                })
            }),
            mask_final: alloc_block256(b, native.mask_final),
            operand_claims: [
                alloc_block256(b, native.terminal_operands.increment),
                alloc_block256(b, native.terminal_operands.lane[0]),
                alloc_block256(b, native.terminal_operands.lane[1]),
                alloc_block256(b, native.terminal_operands.lane[2]),
                alloc_block256(b, native.terminal_operands.lane[3]),
            ],
            rho: std::array::from_fn(|index| alloc_block256(b, native.rho[index])),
            lambda: alloc_block256(b, native.lambda),
            round_challenges: std::array::from_fn(|index| {
                alloc_block256(b, native.owner_challenges[index])
            }),
            eta: alloc_block256(b, native.eta),
        };
        let main = ZkAuthMainTranscriptCells {
            bridge: std::array::from_fn(|index| {
                alloc_block(b, elem(index + 211, 0xB21D6E, native.grind.0))
            }),
            sigma: alloc_block256(b, native.sigma),
            phase_a_round_coefficients: std::array::from_fn(|round| {
                [
                    alloc_block256(b, native.phase_a_rounds[round].at_one),
                    alloc_block256(b, native.phase_a_rounds[round].at_infinity),
                ]
            }),
            phase_b_value: alloc_block256(b, native.terminal_oracle_value),
            upper: std::array::from_fn(|index| alloc_block256(b, native.upper[index])),
            mid_cap: std::array::from_fn(|index| {
                alloc_block(b, native.mid_cap[index & 1][index >> 1])
            }),
            tail: std::array::from_fn(|index| alloc_block256(b, native.tail[index])),
            nonce: alloc_block(b, Block128::from(17u128)),
            gamma: alloc_block256(b, native.gamma),
            phase_a_challenges: std::array::from_fn(|index| {
                alloc_block256(b, native.phase_a_challenges[index])
            }),
            beta: std::array::from_fn(|index| alloc_block256(b, native.beta[index])),
            grind: alloc_block(b, native.grind),
            query_seeds: std::array::from_fn(|index| alloc_block(b, native.query_seeds[index])),
        };
        ZkAuthTranscriptCells { owner, main }
    }

    fn alloc_external(
        b: &mut FieldR1csBuilder,
        native: &NativeCandidate,
    ) -> ZkAuthorizationCandidateExternalAliases {
        ZkAuthorizationCandidateExternalAliases {
            source_path_directions: std::array::from_fn(|query| {
                std::array::from_fn(|bit| {
                    LinExpr::from_wire(b.alloc_bool((native.queries[query] >> bit) & 1 == 1))
                })
            }),
            mid_path_directions: std::array::from_fn(|query| {
                std::array::from_fn(|bit| {
                    LinExpr::from_wire(b.alloc_bool((native.queries[query] >> (4 + bit)) & 1 == 1))
                })
            }),
            joint_source_leaves: std::array::from_fn(|query| {
                std::array::from_fn(|symbol| {
                    alloc_block(b, native.joint_source_leaves[query][symbol])
                })
            }),
            mid_leaves: std::array::from_fn(|query| {
                std::array::from_fn(|symbol| alloc_block256(b, native.mid_leaves[query][symbol]))
            }),
            source_path_roots: std::array::from_fn(|query| {
                std::array::from_fn(|lane| alloc_block(b, native.source_path_roots[query][lane]))
            }),
            mid_path_roots: std::array::from_fn(|query| {
                std::array::from_fn(|lane| alloc_block(b, native.mid_path_roots[query][lane]))
            }),
        }
    }

    fn duplex_data_positions(layout: &DuplexLayout) -> Vec<(usize, usize)> {
        let mut positions = vec![None; layout.n_data];
        for (slot, descriptor) in layout.slots.iter().enumerate() {
            for (lane, source) in descriptor.lanes.iter().enumerate() {
                if let Some(LaneSource::Data(index)) = source {
                    assert!(positions[*index].replace((slot, lane)).is_none());
                }
            }
        }
        positions
            .into_iter()
            .map(|position| position.expect("complete duplex data map"))
            .collect()
    }

    fn push_wide(data: &mut Vec<Block128>, value: Block256) {
        data.push(value.lo);
        data.push(value.hi);
    }

    fn owner_stream(native: &NativeCandidate) -> (Vec<Block128>, Vec<Block128>) {
        let mut data = Vec::with_capacity(ZK_AUTH_OWNER_DYNAMIC_LANES);
        data.extend(native.public_statement);
        for node in 0..ZK_PHASE_B_SOURCE_CAP_NODES {
            for lane in 0..ZK_PHASE_B_CAP_DIGEST_LANES {
                data.push(native.source_cap[lane][node]);
            }
        }
        push_wide(&mut data, native.mask_mu);
        for round in &native.owner_rounds {
            for coefficient in round.coeffs_without_constant {
                push_wide(&mut data, coefficient);
            }
        }
        push_wide(&mut data, native.mask_final);
        push_wide(&mut data, native.terminal_operands.increment);
        for operand in native.terminal_operands.lane {
            push_wide(&mut data, operand);
        }

        assert_eq!(data.len(), ZK_AUTH_OWNER_DYNAMIC_LANES);
        (data, native.owner_raw_challenges.to_vec())
    }

    fn main_stream(
        native: &NativeCandidate,
        bridge: [Block128; 4],
    ) -> (Vec<Block128>, Vec<Block128>) {
        let mut data = Vec::with_capacity(ZK_AUTH_MAIN_DYNAMIC_LANES);
        data.extend(bridge);
        push_wide(&mut data, native.sigma);
        for round in &native.phase_a_rounds {
            push_wide(&mut data, round.at_one);
            push_wide(&mut data, round.at_infinity);
        }
        push_wide(&mut data, native.terminal_oracle_value);
        for value in native.upper {
            push_wide(&mut data, value);
        }
        for node in 0..ZK_PHASE_B_MID_CAP_NODES {
            for lane in 0..ZK_PHASE_B_CAP_DIGEST_LANES {
                data.push(native.mid_cap[lane][node]);
            }
        }
        for value in native.tail {
            push_wide(&mut data, value);
        }
        data.push(Block128::from(17u128));

        assert_eq!(data.len(), ZK_AUTH_MAIN_DYNAMIC_LANES);
        (data, native.main_raw_challenges.to_vec())
    }

    fn duplex_columns_from_stream(
        layout: &DuplexLayout,
        data: &[Block128],
        challenges: &[Block128],
    ) -> ([Vec<F128>; 2], [Vec<F128>; 4]) {
        let len = layout.slots.len().next_power_of_two();
        let mut a = std::array::from_fn(|_| vec![F128::ZERO; len]);
        let mut c = std::array::from_fn(|_| vec![F128::ZERO; len]);
        assert_eq!(data.len(), layout.n_data);
        assert_eq!(challenges.len(), layout.challenges.len());
        for (index, (slot, lane)) in duplex_data_positions(layout).into_iter().enumerate() {
            a[lane][slot] = flat_of(data[index]);
        }
        for (index, &(slot, lane)) in layout.challenges.iter().enumerate() {
            c[lane][slot] = flat_of(challenges[index]);
        }
        (a, c)
    }

    struct RawSliceTileFixtureSlices {
        owner_a: [WitnessSlice; 2],
        owner_c: [WitnessSlice; 4],
        main_a: [WitnessSlice; 2],
        main_c: [WitnessSlice; 4],
        wallet_a: [WitnessSlice; ZK_AUTH_WALLET_A_COLUMNS],
        wallet_b: [WitnessSlice; ZK_AUTH_WALLET_B_COLUMNS],
        meta_a: [WitnessSlice; ZK_AUTH_META_A_COLUMNS],
        meta_b: [WitnessSlice; ZK_AUTH_META_B_COLUMNS],
        statement_wire: usize,
        bridge_wire: usize,
        digest_wire: usize,
        root_wire: usize,
    }

    fn alloc_raw_slice_tile_fixture_slices(
        b: &mut FieldR1csBuilder,
        native: &NativeCandidate,
        owner_layout: &DuplexLayout,
        main_layout: &DuplexLayout,
    ) -> RawSliceTileFixtureSlices {
        let bridge: [Block128; 4] =
            std::array::from_fn(|lane| elem(lane + 401, 0xB21D_6E, native.grind.0));
        let (owner_data, owner_challenges) = owner_stream(native);
        let (main_data, main_challenges) = main_stream(native, bridge);
        let (owner_full_a, mut owner_full_c) =
            duplex_columns_from_stream(owner_layout, &owner_data, &owner_challenges);
        let (main_full_a, main_full_c) =
            duplex_columns_from_stream(main_layout, &main_data, &main_challenges);
        for lane in 0..4 {
            owner_full_c[lane][owner_layout.slots.len() - 1] = flat_of(bridge[lane]);
        }

        let owner_prefix_slots = 1 << ZK_AUTH_OWNER_TILE_LOG;
        let main_prefix_slots = 1 << ZK_AUTH_MAIN_TILE_LOG;
        let owner_a_cols: [Vec<F128>; 2] =
            std::array::from_fn(|lane| owner_full_a[lane][..owner_prefix_slots].to_vec());
        let owner_c_cols: [Vec<F128>; 4] =
            std::array::from_fn(|lane| owner_full_c[lane][..owner_prefix_slots].to_vec());
        let main_a_cols: [Vec<F128>; 2] =
            std::array::from_fn(|lane| main_full_a[lane][..main_prefix_slots].to_vec());
        let main_c_cols: [Vec<F128>; 4] =
            std::array::from_fn(|lane| main_full_c[lane][..main_prefix_slots].to_vec());

        let mut wallet_a_cols: [Vec<F128>; ZK_AUTH_WALLET_A_COLUMNS] =
            std::array::from_fn(|_| vec![F128::ZERO; 1 << ZK_AUTH_WALLET_A_TILE_LOG]);
        let mut wallet_b_cols: [Vec<F128>; ZK_AUTH_WALLET_B_COLUMNS] =
            std::array::from_fn(|_| vec![F128::ZERO; 1 << ZK_AUTH_WALLET_B_TILE_LOG]);
        let mut meta_a_cols: [Vec<F128>; ZK_AUTH_META_A_COLUMNS] =
            std::array::from_fn(|_| vec![F128::ZERO; 1 << 5]);
        let mut meta_b_cols: [Vec<F128>; ZK_AUTH_META_B_COLUMNS] =
            std::array::from_fn(|_| vec![F128::ZERO; 1 << 4]);

        for (full_a, full_c, prefix_slots, tail_base, bridge_slot, data_slot, full_slots) in [
            (
                &owner_full_a,
                &owner_full_c,
                owner_prefix_slots,
                crate::acceptance::zk_auth_capsule_schedule::ZK_AUTH_WALLET_A_OWNER_TAIL_BASE,
                crate::acceptance::zk_auth_capsule_schedule::ZK_AUTH_WALLET_A_OWNER_BRIDGE_SLOT,
                crate::acceptance::zk_auth_capsule_schedule::ZK_AUTH_WALLET_A_OWNER_DATA_SLOT,
                owner_layout.slots.len(),
            ),
            (
                &main_full_a,
                &main_full_c,
                main_prefix_slots,
                crate::acceptance::zk_auth_capsule_schedule::ZK_AUTH_WALLET_A_MAIN_TAIL_BASE,
                crate::acceptance::zk_auth_capsule_schedule::ZK_AUTH_WALLET_A_MAIN_BRIDGE_SLOT,
                crate::acceptance::zk_auth_capsule_schedule::ZK_AUTH_WALLET_A_MAIN_DATA_SLOT,
                main_layout.slots.len(),
            ),
        ] {
            let tail_slots = full_slots - prefix_slots;
            wallet_a_cols[0][bridge_slot] = full_c[2][prefix_slots - 1];
            wallet_a_cols[1][bridge_slot] = full_c[3][prefix_slots - 1];
            for lane in 0..2 {
                wallet_a_cols[lane][data_slot] = full_a[lane][prefix_slots];
                wallet_a_cols[lane][tail_base..tail_base + tail_slots]
                    .copy_from_slice(&full_a[lane][prefix_slots..full_slots]);
                wallet_a_cols[lane][tail_base] += full_c[lane][prefix_slots - 1];
            }
            for lane in 0..4 {
                wallet_a_cols[2 + lane][tail_base..tail_base + tail_slots]
                    .copy_from_slice(&full_c[lane][prefix_slots..full_slots]);
            }
        }

        for query in 0..ZK_QUERY_COUNT {
            let source_lanes = native.joint_source_leaves[query]
                .iter()
                .copied()
                .map(flat_of)
                .collect::<Vec<_>>();
            let mid_lanes = native.mid_leaves[query]
                .iter()
                .flat_map(|&value| {
                    let value = flat_of_ext(value);
                    [value.lo, value.hi]
                })
                .collect::<Vec<_>>();
            for (family, kind, lanes, root) in [
                (
                    0usize,
                    C1CapsuleLeafKind::MixedSource,
                    source_lanes.as_slice(),
                    &native.source_path_roots[query],
                ),
                (
                    1usize,
                    C1CapsuleLeafKind::WideMid,
                    mid_lanes.as_slice(),
                    &native.mid_path_roots[query],
                ),
            ] {
                let core = query < ZK_AUTH_WALLET_CORE_QUERY_COUNT;
                let leaf = if core {
                    if family == 0 {
                        ZK_AUTH_WALLET_A_SOURCE_BASE + query * C1_CAPSULE_SOURCE_SLOTS
                    } else {
                        ZK_AUTH_WALLET_A_MID_BASE + query * C1_CAPSULE_MID_SLOTS
                    }
                } else {
                    family * C1_CAPSULE_LEAF_STRIDE
                };
                let path = if core {
                    query * ZK_AUTH_WALLET_B_PATH_STRIDE
                        + if family == 0 {
                            ZK_AUTH_WALLET_B_SOURCE_PATH_OFFSET
                        } else {
                            ZK_AUTH_WALLET_B_MID_PATH_OFFSET
                        }
                } else {
                    if family == 0 {
                        ZK_AUTH_WALLET_B_SOURCE_PATH_OFFSET
                    } else {
                        ZK_AUTH_WALLET_B_MID_PATH_OFFSET
                    }
                };
                let a_in0 = if core { 0 } else { 2 };
                let a_c0 = if core { 2 } else { 4 };
                let a_columns = if core {
                    wallet_a_cols.as_mut_slice()
                } else {
                    meta_a_cols.as_mut_slice()
                };
                let b_columns = if core {
                    wallet_b_cols.as_mut_slice()
                } else {
                    meta_b_cols.as_mut_slice()
                };
                for (lane, &value) in lanes.iter().enumerate() {
                    a_columns[a_in0 + (lane & 1)][leaf + lane / 2] = value;
                }
                let digest = flat_c1_capsule_leaf_hash(kind, lanes);
                let digest_slot = if family == 0 {
                    C1_CAPSULE_SOURCE_DIGEST_SLOT
                } else {
                    C1_CAPSULE_MID_DIGEST_SLOT
                };
                let path_depth = if family == 0 {
                    ZK_AUTH_WALLET_B_SOURCE_PATH_DEPTH
                } else {
                    ZK_AUTH_WALLET_B_MID_PATH_DEPTH
                };
                for lane in 0..2 {
                    a_columns[a_c0 + lane][leaf + digest_slot] = digest[lane];
                    b_columns[4 + lane][path] = digest[lane];
                    b_columns[lane][path + path_depth - 1] = flat_of(root[lane]);
                }
                for depth in 0..path_depth {
                    let query_bit = if family == 0 { depth } else { 4 + depth };
                    b_columns[8][path + depth] = if (native.queries[query] >> query_bit) & 1 == 1 {
                        F128::ONE
                    } else {
                        F128::ZERO
                    };
                }
            }
        }

        let owner_a = std::array::from_fn(|lane| {
            alloc_column_slice(b, &owner_a_cols[lane], ZK_AUTH_OWNER_TILE_LOG).0
        });
        let owner_c = std::array::from_fn(|lane| {
            alloc_column_slice(b, &owner_c_cols[lane], ZK_AUTH_OWNER_TILE_LOG).0
        });
        let main_a = std::array::from_fn(|lane| {
            alloc_column_slice(b, &main_a_cols[lane], ZK_AUTH_MAIN_TILE_LOG).0
        });
        let main_c = std::array::from_fn(|lane| {
            alloc_column_slice(b, &main_c_cols[lane], ZK_AUTH_MAIN_TILE_LOG).0
        });
        let wallet_a = std::array::from_fn(|column| {
            alloc_column_slice(b, &wallet_a_cols[column], ZK_AUTH_WALLET_A_TILE_LOG).0
        });
        let wallet_b = std::array::from_fn(|column| {
            if column == 8 {
                alloc_boolean_column_slice(b, &wallet_b_cols[column], ZK_AUTH_WALLET_B_TILE_LOG).0
            } else {
                alloc_column_slice(b, &wallet_b_cols[column], ZK_AUTH_WALLET_B_TILE_LOG).0
            }
        });
        let meta_a = std::array::from_fn(|column| alloc_column_slice(b, &meta_a_cols[column], 5).0);
        let meta_b = std::array::from_fn(|column| {
            if column == 8 {
                alloc_boolean_column_slice(b, &meta_b_cols[column], 4).0
            } else {
                alloc_column_slice(b, &meta_b_cols[column], 4).0
            }
        });

        let statement_position = duplex_data_positions(owner_layout)[0];
        let bridge_position = duplex_data_positions(main_layout)[0];
        RawSliceTileFixtureSlices {
            statement_wire: owner_a[statement_position.1].start() + statement_position.0,
            bridge_wire: main_a[bridge_position.1].start() + bridge_position.0,
            digest_wire: wallet_a[2].start() + C1_CAPSULE_SOURCE_DIGEST_SLOT,
            root_wire: wallet_b[0].start() + ZK_AUTH_WALLET_B_SOURCE_PATH_DEPTH - 1,
            owner_a,
            owner_c,
            main_a,
            main_c,
            wallet_a,
            wallet_b,
            meta_a,
            meta_b,
        }
    }

    fn input_wire(expression: &LinExpr) -> usize {
        assert_eq!(expression.terms.len(), 1);
        assert_eq!(expression.terms[0].1, F128::ONE);
        assert_eq!(expression.constant, F128::ZERO);
        expression.terms[0].0 as usize
    }

    struct BuiltCandidate {
        r1cs: FieldR1cs,
        witness: Vec<F128>,
        trace_rows: usize,
        tamper_wires: Vec<(&'static str, usize)>,
        digest: [u8; 32],
    }

    fn build_candidate(salt: u128) -> BuiltCandidate {
        let native = native_candidate(salt);
        let mut b = FieldR1csBuilder::new();
        let cells = alloc_cells(&mut b, &native);
        let external = alloc_external(&mut b, &native);
        let tamper_wires = vec![
            (
                "Owner round",
                input_wire(&cells.owner.round_coefficients[3][4].lo),
            ),
            (
                "Owner operand claim",
                input_wire(&cells.owner.operand_claims[2].lo),
            ),
            ("sigma", input_wire(&cells.main.sigma.lo)),
            (
                "Phase-A round",
                input_wire(&cells.main.phase_a_round_coefficients[5][1].lo),
            ),
            (
                "Phase-A terminal point",
                input_wire(&cells.main.phase_a_challenges[6].lo),
            ),
            (
                "Phase-A/Phase-B v",
                input_wire(&cells.main.phase_b_value.lo),
            ),
            ("upper", input_wire(&cells.main.upper[37].lo)),
            ("tail", input_wire(&cells.main.tail[9].lo)),
            ("nonce", input_wire(&cells.main.nonce)),
            ("grind", input_wire(&cells.main.grind)),
            ("query seed", input_wire(&cells.main.query_seeds[2])),
            (
                "source direction",
                input_wire(&external.source_path_directions[7][3]),
            ),
            (
                "joint source leaf",
                input_wire(&external.joint_source_leaves[11][5]),
            ),
            ("mid leaf", input_wire(&external.mid_leaves[13][7].lo)),
            (
                "source path root",
                input_wire(&external.source_path_roots[17][1]),
            ),
            ("source cap", input_wire(&cells.owner.source_cap[15])),
            ("mid cap", input_wire(&cells.main.mid_cap[3])),
        ];

        let before = b.num_wires();
        let output = verify_zk_authorization_candidate_trace(&mut b, &cells, &external)
            .expect("native candidate trace");
        let trace_rows = b.num_wires() - before;
        assert_eq!(
            output.authorization.phase_a.terminal_oracle_value,
            cells.main.phase_b_value
        );
        for low in 0..ZK_PHASE_A_ROUNDS {
            assert_eq!(
                output.authorization.phase_a.terminal_point[low],
                cells.main.phase_a_challenges[ZK_PHASE_A_ROUNDS - 1 - low]
            );
        }
        assert_eq!(
            output.phase_b.upper_link.beta, cells.main.beta,
            "Phase-B output retained exact beta aliases"
        );
        let (r1cs, witness) = b.build();
        let digest = r1cs.structural_statement_digest();
        BuiltCandidate {
            r1cs,
            witness,
            trace_rows,
            tamper_wires,
            digest,
        }
    }

    #[test]
    fn native_end_to_end_candidate_is_satisfied_with_exact_alias_ledger() {
        assert_eq!(ZK_AUTHORIZATION_CANDIDATE_TRACE_ROWS, 15_956);
        assert_eq!(ZK_AUTHORIZATION_CANDIDATE_EXTERNAL_BRIDGE_ROWS, 12);
        let built = build_candidate(0xCAAD_1DA7E);
        assert_eq!(built.trace_rows, ZK_AUTHORIZATION_CANDIDATE_TRACE_ROWS);
        assert!(built.r1cs.satisfies(&built.witness));
    }

    #[test]
    fn representative_owner_main_phase_b_and_grind_tampering_rejects() {
        let built = build_candidate(0x7A9E_E001);
        assert!(built.r1cs.satisfies(&built.witness));
        for &(label, wire) in &built.tamper_wires {
            let mut bad = built.witness.clone();
            bad[wire] += F128::ONE;
            assert!(!built.r1cs.satisfies(&bad), "{label} tamper survived");
        }
        let direction_wire = built
            .tamper_wires
            .iter()
            .find_map(|(label, wire)| (*label == "source direction").then_some(*wire))
            .expect("source direction tamper wire");
        let mut non_boolean = built.witness.clone();
        non_boolean[direction_wire] += F128 { lo: 2, hi: 0 };
        assert!(
            !built.r1cs.satisfies(&non_boolean),
            "fabricated non-Boolean Wallet-B D cell survived"
        );
    }

    #[test]
    fn top_level_preflight_rejects_atomically_before_authorization_rows() {
        let native = native_candidate(0xA701_1C00);
        let mut b = FieldR1csBuilder::new();
        let cells = alloc_cells(&mut b, &native);
        let external = alloc_external(&mut b, &native);

        let mut bad_cells = cells.clone();
        bad_cells.main.tail[3] = const_block256(native.tail[3]);
        let before = b.num_wires();
        assert!(matches!(
            verify_zk_authorization_candidate_trace(&mut b, &bad_cells, &external),
            Err(
                ZkAuthorizationCandidateTraceError::MalformedTranscriptAlias {
                    input: ZkAuthorizationCandidateInput::MainTail,
                    index: 6,
                }
            )
        ));
        assert_eq!(b.num_wires(), before);

        let mut bad_external = external.clone();
        bad_external.joint_source_leaves[9][4] =
            LinExpr::constant(flat_of(native.joint_source_leaves[9][4]));
        let before = b.num_wires();
        assert!(matches!(
            verify_zk_authorization_candidate_trace(&mut b, &cells, &bad_external),
            Err(ZkAuthorizationCandidateTraceError::ExternalAliasIsConstant {
                input: ZkAuthorizationCandidateInput::JointSourceLeaf,
                index,
            }) if index == 9 * JOINT_SOURCE_LEAF_SYMBOLS + 4
        ));
        assert_eq!(b.num_wires(), before);

        let mut zero_gamma = cells.clone();
        zero_gamma.main.gamma = alloc_block256(&mut b, Block256::ZERO);
        let before = b.num_wires();
        assert_eq!(
            verify_zk_authorization_candidate_trace(&mut b, &zero_gamma, &external).unwrap_err(),
            ZkAuthorizationCandidateTraceError::GammaZero
        );
        assert_eq!(b.num_wires(), before);

        let mut zero_terminal_weight = cells.clone();
        zero_terminal_weight.owner.round_challenges[4] = alloc_block256(&mut b, Block256::ZERO);
        let before = b.num_wires();
        assert_eq!(
            verify_zk_authorization_candidate_trace(&mut b, &zero_terminal_weight, &external,)
                .unwrap_err(),
            ZkAuthorizationCandidateTraceError::TerminalBlindingWeightZero
        );
        assert_eq!(b.num_wires(), before);
    }

    #[test]
    fn candidate_matrix_is_native_content_invariant() {
        let left = build_candidate(0x1111_2222);
        let right = build_candidate(0xAAAA_BBBB);
        assert!(left.r1cs.satisfies(&left.witness));
        assert!(right.r1cs.satisfies(&right.witness));
        assert_eq!(left.trace_rows, right.trace_rows);
        assert_eq!(left.r1cs.useful_rows, right.r1cs.useful_rows);
        assert_eq!(left.digest, right.digest);
    }

    struct BuiltRawSliceTileFixture {
        r1cs: FieldR1cs,
        witness: Vec<F128>,
        trace_rows: usize,
        tamper_wires: Vec<(&'static str, usize)>,
        digest: [u8; 32],
        k2_ranges: Option<K2Ranges>,
    }

    #[derive(Clone)]
    struct K2Ranges {
        wallet_a: [WitnessSlice; ZK_AUTH_WALLET_A_COLUMNS],
        wallet_b: [WitnessSlice; ZK_AUTH_WALLET_B_COLUMNS],
        main_a: [WitnessSlice; 2],
    }

    fn build_raw_slice_tile_fixture(salt: u128) -> BuiltRawSliceTileFixture {
        let native = native_candidate(salt);
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        let owner_layout = schedules.owner_layout();
        let main_layout = schedules.main_layout();
        let mut b = FieldR1csBuilder::new();
        let public = alloc_selected_statement(&mut b, &native);
        let public_wire = input_wire(&public.expected_address[0]);
        let slices =
            alloc_raw_slice_tile_fixture_slices(&mut b, &native, &owner_layout, &main_layout);
        let before = b.num_wires();
        let (bridge, candidate) = verify_zk_authorization_raw_slice_tile_candidate_trace(
            &mut b,
            &owner_layout,
            &slices.owner_a,
            &slices.owner_c,
            &main_layout,
            &slices.main_a,
            &slices.main_c,
            &slices.wallet_a,
            &slices.wallet_b,
            &slices.meta_a,
            &slices.meta_b,
            raw_fixture_overflow_layout(1),
            0,
            &public,
        )
        .expect("raw-slice tile candidate");
        let trace_rows = b.num_wires() - before;
        let mapped = view_zk_auth_split_transcript_tile(
            &mut b,
            &owner_layout,
            &slices.owner_a,
            &slices.owner_c,
            &main_layout,
            &slices.main_a,
            &slices.main_c,
            &slices.wallet_a,
            0,
        );
        assert_eq!(bridge.main_absorb, mapped.main.bridge);
        assert_eq!(
            candidate
                .authorization
                .phase_a
                .terminal_oracle_value
                .eval(b.values()),
            flat_of_ext(native.terminal_oracle_value)
        );
        let tamper_wires = vec![
            ("outer statement", public_wire),
            ("Owner statement absorb", slices.statement_wire),
            ("split bridge", slices.bridge_wire),
            ("source leaf lane 0", slices.wallet_a[0].start()),
            ("source leaf lane 1", slices.wallet_a[1].start()),
            (
                "mid leaf high coordinate",
                slices.wallet_a[1].start() + ZK_AUTH_WALLET_A_MID_BASE,
            ),
            ("wallet digest bridge", slices.digest_wire),
            ("source-path composite root", slices.root_wire),
            ("overflow source leaf lane", slices.meta_a[2].start()),
            (
                "overflow mid leaf high coordinate",
                slices.meta_a[3].start() + C1_CAPSULE_LEAF_STRIDE,
            ),
            (
                "overflow digest bridge",
                slices.meta_a[4].start() + C1_CAPSULE_SOURCE_DIGEST_SLOT,
            ),
            ("overflow source direction", slices.meta_b[8].start()),
            (
                "overflow source-path composite root",
                slices.meta_b[0].start() + ZK_AUTH_WALLET_B_SOURCE_PATH_DEPTH - 1,
            ),
        ];
        let (r1cs, witness) = b.build();
        let digest = r1cs.structural_statement_digest();
        BuiltRawSliceTileFixture {
            r1cs,
            witness,
            trace_rows,
            tamper_wires,
            digest,
            k2_ranges: None,
        }
    }

    fn concatenate_slices(
        b: &mut FieldR1csBuilder,
        left: WitnessSlice,
        right: WitnessSlice,
    ) -> WitnessSlice {
        assert_eq!(left.log2_len, right.log2_len);
        let mut values = b.values()[slice_range(&left)].to_vec();
        values.extend_from_slice(&b.values()[slice_range(&right)]);
        alloc_column_slice(b, &values, left.log2_len + 1).0
    }

    fn concatenate_boolean_slices(
        b: &mut FieldR1csBuilder,
        left: WitnessSlice,
        right: WitnessSlice,
    ) -> WitnessSlice {
        assert_eq!(left.log2_len, right.log2_len);
        let mut values = b.values()[slice_range(&left)].to_vec();
        values.extend_from_slice(&b.values()[slice_range(&right)]);
        alloc_boolean_column_slice(b, &values, left.log2_len + 1).0
    }

    fn concatenate_meta_a_slices(
        b: &mut FieldR1csBuilder,
        left: WitnessSlice,
        right: WitnessSlice,
    ) -> WitnessSlice {
        assert_eq!(left.log2_len, 5);
        assert_eq!(right.log2_len, 5);
        let left_values = b.values()[slice_range(&left)].to_vec();
        let right_values = b.values()[slice_range(&right)].to_vec();
        let mut values = Vec::with_capacity(64);
        values.extend_from_slice(&left_values[..16]);
        values.extend_from_slice(&right_values[..16]);
        values.extend_from_slice(&left_values[16..]);
        values.extend_from_slice(&right_values[16..]);
        alloc_column_slice(b, &values, 6).0
    }

    fn build_k2_raw_slice_tile_fixture() -> BuiltRawSliceTileFixture {
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        let owner_layout = schedules.owner_layout();
        let main_layout = schedules.main_layout();
        let mut b = FieldR1csBuilder::new();
        // Each native fixture is deliberately large. Keep only one on the
        // test-thread stack at a time; the allocated witness slices outlive it.
        let (public, left) = {
            let native = native_candidate(0x2A11_0000);
            let public = alloc_selected_statement(&mut b, &native);
            let slices =
                alloc_raw_slice_tile_fixture_slices(&mut b, &native, &owner_layout, &main_layout);
            (public, slices)
        };
        let right = {
            let native = native_candidate(0x2A11_0001);
            alloc_raw_slice_tile_fixture_slices(&mut b, &native, &owner_layout, &main_layout)
        };

        let owner_a = std::array::from_fn(|lane| {
            concatenate_slices(&mut b, left.owner_a[lane], right.owner_a[lane])
        });
        let owner_c = std::array::from_fn(|lane| {
            concatenate_slices(&mut b, left.owner_c[lane], right.owner_c[lane])
        });
        let main_a = std::array::from_fn(|lane| {
            concatenate_slices(&mut b, left.main_a[lane], right.main_a[lane])
        });
        let main_c = std::array::from_fn(|lane| {
            concatenate_slices(&mut b, left.main_c[lane], right.main_c[lane])
        });
        let wallet_a = std::array::from_fn(|column| {
            concatenate_slices(&mut b, left.wallet_a[column], right.wallet_a[column])
        });
        let wallet_b = std::array::from_fn(|column| {
            if column == 8 {
                concatenate_boolean_slices(&mut b, left.wallet_b[column], right.wallet_b[column])
            } else {
                concatenate_slices(&mut b, left.wallet_b[column], right.wallet_b[column])
            }
        });
        let meta_a = std::array::from_fn(|column| {
            concatenate_meta_a_slices(&mut b, left.meta_a[column], right.meta_a[column])
        });
        let meta_b = std::array::from_fn(|column| {
            if column == 8 {
                concatenate_boolean_slices(&mut b, left.meta_b[column], right.meta_b[column])
            } else {
                concatenate_slices(&mut b, left.meta_b[column], right.meta_b[column])
            }
        });

        let before = b.num_wires();
        // Intentionally exercise only tile zero.  This fixture demonstrates
        // why the private raw-slice helper is not a production all-tiles API.
        let _ = verify_zk_authorization_raw_slice_tile_candidate_trace(
            &mut b,
            &owner_layout,
            &owner_a,
            &owner_c,
            &main_layout,
            &main_a,
            &main_c,
            &wallet_a,
            &wallet_b,
            &meta_a,
            &meta_b,
            raw_fixture_overflow_layout(2),
            0,
            &public,
        )
        .expect("fixed-shape K2 raw-slice tile candidate");
        let trace_rows = b.num_wires() - before;
        let (r1cs, witness) = b.build();
        let digest = r1cs.structural_statement_digest();
        BuiltRawSliceTileFixture {
            r1cs,
            witness,
            trace_rows,
            tamper_wires: Vec::new(),
            digest,
            k2_ranges: Some(K2Ranges {
                wallet_a,
                wallet_b,
                main_a,
            }),
        }
    }

    fn run_in_large_stack<F: FnOnce() + Send + 'static>(name: &str, f: F) {
        std::thread::Builder::new()
            .name(name.to_owned())
            .stack_size(64 * 1024 * 1024)
            .spawn(f)
            .expect("spawn large stack test")
            .join()
            .expect("test panicked");
    }

    #[test]
    fn raw_slice_tile_helper_has_exact_wrapper_ledger_and_is_satisfied() {
        run_in_large_stack("zk-auth-raw-slice-helper", || {
            assert_eq!(ZK_AUTH_RAW_SLICE_PRE_CORE_ROWS, 580);
            assert_eq!(ZK_AUTH_RAW_SLICE_METADATA_PIN_ROWS, 0);
            assert_eq!(ZK_AUTH_RAW_SLICE_WRAPPER_ROWS, 580);
            assert_eq!(ZK_AUTH_RAW_SLICE_TILE_TRACE_ROWS, 16_536);
            let built = build_raw_slice_tile_fixture(0x5200_A11A5);
            assert_eq!(built.trace_rows, ZK_AUTH_RAW_SLICE_TILE_TRACE_ROWS);
            assert!(built.r1cs.satisfies(&built.witness));
        });
    }

    #[test]
    fn raw_c1_sampler_excludes_zero_terminal_weight_and_gamma_endpoints() {
        let native = native_candidate(0xB11D_0000);
        assert!(native
            .owner_challenges
            .iter()
            .all(|&challenge| challenge != Block256::ZERO));
        assert_ne!(
            native
                .owner_challenges
                .iter()
                .copied()
                .fold(Block256::ONE, |product, challenge| product * challenge),
            Block256::ZERO
        );
        assert!(native.gamma != Block256::ZERO && native.gamma != Block256::ONE);
    }

    #[test]
    fn raw_slice_tile_statement_bridge_leaf_digest_and_root_tampering_rejects() {
        run_in_large_stack("zk-auth-raw-slice-tamper", || {
            let built = build_raw_slice_tile_fixture(0xB21D_6E57);
            assert!(built.r1cs.satisfies(&built.witness));
            for &(label, wire) in &built.tamper_wires {
                let mut bad = built.witness.clone();
                bad[wire] += F128::ONE;
                assert!(!built.r1cs.satisfies(&bad), "{label} tamper survived");
            }
        });
    }

    #[test]
    fn raw_slice_tile_matrix_is_native_content_invariant() {
        run_in_large_stack("zk-auth-raw-slice-invariant", || {
            let left = build_raw_slice_tile_fixture(0x5107_0001);
            let right = build_raw_slice_tile_fixture(0x5107_0002);
            assert!(left.r1cs.satisfies(&left.witness));
            assert!(right.r1cs.satisfies(&right.witness));
            assert_eq!(left.trace_rows, right.trace_rows);
            assert_eq!(left.r1cs.useful_rows, right.r1cs.useful_rows);
            assert_eq!(left.digest, right.digest);
        });
    }

    #[test]
    fn k2_private_per_tile_fixture_checks_only_one_tile_and_rejects_cross_tile_splices() {
        // This test deliberately materializes a synthetic two-tile witness and
        // two full tampered copies at once.  The fixture is test-only, but it is
        // larger than libtest's default worker stack in debug builds.
        std::thread::Builder::new()
            .name("zk-auth-k2-fixture".to_owned())
            .stack_size(64 * 1024 * 1024)
            .spawn(run_k2_private_per_tile_fixture_checks)
            .expect("spawn K2 fixture test")
            .join()
            .expect("K2 fixture test panicked");
    }

    fn run_k2_private_per_tile_fixture_checks() {
        let honest = build_k2_raw_slice_tile_fixture();
        assert_eq!(honest.trace_rows, ZK_AUTH_RAW_SLICE_TILE_TRACE_ROWS);
        assert_ne!(
            honest.trace_rows,
            2 * ZK_AUTH_RAW_SLICE_TILE_TRACE_ROWS,
            "the local K2 fixture must remain an explicit one-tile primitive"
        );
        assert!(honest.r1cs.satisfies(&honest.witness));
        let ranges = honest.k2_ranges.as_ref().expect("K2 splice ranges");

        let mut wallet_splice = honest.witness.clone();
        for (slices, tile_len) in [
            (&ranges.wallet_a[..], 1usize << ZK_AUTH_WALLET_A_TILE_LOG),
            (&ranges.wallet_b[..], 1usize << ZK_AUTH_WALLET_B_TILE_LOG),
        ] {
            for slice in slices {
                let start = slice.start();
                for offset in 0..tile_len {
                    wallet_splice[start + offset] = honest.witness[start + tile_len + offset];
                }
            }
        }
        assert!(
            !honest.r1cs.satisfies(&wallet_splice),
            "cross-tile Wallet-A/B splice survived"
        );

        let mut foreign_main = honest.witness.clone();
        for slice in &ranges.main_a {
            let start = slice.start();
            let tile_len = 1usize << ZK_AUTH_MAIN_TILE_LOG;
            for offset in 0..tile_len {
                foreign_main[start + offset] = honest.witness[start + tile_len + offset];
            }
        }
        assert!(
            !honest.r1cs.satisfies(&foreign_main),
            "foreign Main A/C pairing survived"
        );
    }

    #[test]
    fn selected_batch_driver_has_no_range_or_omission_surface() {
        let statements = (0..SELECTED_ZK_AUTH_TILE_COUNT).collect::<Vec<_>>();
        let mut visited = Vec::new();
        preflight_then_visit_all_selected_zk_authorization_tiles(
            &mut visited,
            &statements,
            SELECTED_ZK_AUTH_TILE_COUNT,
            |_visited, index, statement| {
                assert_eq!(index, *statement);
                Ok::<(), ()>(())
            },
            |visited, index, statement| {
                assert_eq!(index, *statement);
                visited.push(index);
            },
        )
        .expect("exact selected batch");
        assert_eq!(visited, statements);

        let mut omitted = Vec::new();
        let error = preflight_then_visit_all_selected_zk_authorization_tiles(
            &mut omitted,
            &statements[..SELECTED_ZK_AUTH_TILE_COUNT - 1],
            SELECTED_ZK_AUTH_TILE_COUNT,
            |_visited, _, _| Ok::<(), ()>(()),
            |visited, index, _| visited.push(index),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ZkAuthorizationBatchVisitError::StatementCount {
                expected,
                actual,
            } if expected == SELECTED_ZK_AUTH_TILE_COUNT
                && actual == SELECTED_ZK_AUTH_TILE_COUNT - 1
        ));
        assert!(omitted.is_empty(), "short batch appended a partial range");
    }

    #[test]
    fn selected_two_class_all_tiles_row_ledger_is_exact() {
        for (tier, expected_rows) in [(25, 529_152), (255, 4_233_216)] {
            let geometry = crate::region_sidecar::selected_zk_block_geometry(tier).unwrap();
            assert_eq!(
                geometry.auth_tiles * ZK_AUTH_RAW_SLICE_TILE_TRACE_ROWS,
                expected_rows,
                "B{tier} selected all-tiles rows"
            );
        }
    }

    #[test]
    fn overflow_aliases_distinguish_capacities_with_the_same_tile_count() {
        fn slices<const N: usize>(log2_len: usize) -> [WitnessSlice; N] {
            std::array::from_fn(|index| WitnessSlice {
                log2_len,
                index: index + 1,
            })
        }
        // 64/96/127 all pad to 128 tiles; 128/255 both pad to 256.
        // Their final query must still read its own Meta paths and leaves.
        for (tier, leaf_base, path_base, path_stride) in [
            (25, 1_024, 1_152, 2_048),
            (63, 4_096, 960, 1_024),
            (64, 4_096, 544, 1_024),
            (96, 4_096, 672, 1_024),
            (127, 8_192, 800, 1_024),
            (128, 8_192, 400, 512),
            (255, 8_192, 464, 512),
        ] {
            let geometry = crate::region_sidecar::selected_zk_block_geometry(tier).unwrap();
            let wallet_a = slices(geometry.wallet_a_w_log);
            let wallet_b = slices(geometry.wallet_b_w_log);
            let meta_a = slices(geometry.meta_a_w_log);
            let meta_b = slices(geometry.meta_b_w_log);
            for tile in [0, geometry.auth_tiles - 1] {
                let aliases = wallet_external_aliases(
                    &wallet_a,
                    &wallet_b,
                    &meta_a,
                    &meta_b,
                    WalletOverflowLayout::for_geometry(geometry),
                    tile,
                );
                assert_eq!(
                    input_wire(&aliases.source_path_directions[64][0]),
                    meta_b[8].start() + tile * path_stride + path_base,
                    "capacity {tier}, tile {tile}: source path"
                );
                assert_eq!(
                    input_wire(&aliases.mid_path_directions[64][0]),
                    meta_b[8].start() + tile * path_stride + path_base + 10,
                    "capacity {tier}, tile {tile}: mid path"
                );
                assert_eq!(
                    input_wire(&aliases.joint_source_leaves[64][0]),
                    meta_a[2].start() + leaf_base + tile * C1_CAPSULE_LEAF_STRIDE,
                    "capacity {tier}, tile {tile}: source leaf"
                );
            }
        }
    }

    #[test]
    fn bad_middle_and_last_statement_fail_atomically_before_append() {
        let statements = (0..SELECTED_ZK_AUTH_TILE_COUNT).collect::<Vec<_>>();
        for bad_index in [
            SELECTED_ZK_AUTH_TILE_COUNT / 2,
            SELECTED_ZK_AUTH_TILE_COUNT - 1,
        ] {
            let mut appended = 0usize;
            let error = preflight_then_visit_all_selected_zk_authorization_tiles(
                &mut appended,
                &statements,
                SELECTED_ZK_AUTH_TILE_COUNT,
                |_appended, index, _| (index != bad_index).then_some(()).ok_or(index),
                |appended, _, _| *appended += 1,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                ZkAuthorizationBatchVisitError::Tile { index, source }
                    if index == bad_index && source == bad_index
            ));
            assert_eq!(
                appended, 0,
                "tile {bad_index} failed after a partial append pass"
            );
        }
    }

    fn fake_artifact(proof_tag: usize, cap_tag: usize) -> SelectedZkAuthorizationArtifactIdentity {
        let mut cap = [0u8; 32];
        cap[..8].copy_from_slice(&(cap_tag as u64).to_le_bytes());
        SelectedZkAuthorizationArtifactIdentity {
            proof_bytes: proof_tag.to_le_bytes().to_vec(),
            source_cap: vec![cap],
        }
    }

    #[test]
    fn proof_reuse_policy_is_live_unique_but_allows_one_ghost_for_every_dead_slot() {
        let ghost = fake_artifact(usize::MAX, usize::MAX - 1);
        for live_count in [0usize, 1, 2, 7, 8, 255] {
            let live = (0..live_count)
                .map(|index| fake_artifact(index, index + 1))
                .collect::<Vec<_>>();
            validate_selected_zk_authorization_artifact_reuse(&live, &ghost)
                .expect("unique live artifacts and distinct ghost");
            let expanded_dead = vec![ghost.clone(); 256 - live_count];
            assert!(expanded_dead.iter().all(|identity| identity == &ghost));
        }

        let duplicate_proof = [fake_artifact(1, 1), fake_artifact(1, 2)];
        assert!(matches!(
            validate_selected_zk_authorization_artifact_reuse(&duplicate_proof, &ghost),
            Err(
                HistoryStepAuthorizationPreparationError::DuplicateLiveProof {
                    first: 0,
                    second: 1
                }
            )
        ));
        let duplicate_cap = [fake_artifact(1, 7), fake_artifact(2, 7)];
        assert!(matches!(
            validate_selected_zk_authorization_artifact_reuse(&duplicate_cap, &ghost),
            Err(
                HistoryStepAuthorizationPreparationError::DuplicateLiveSourceCommitment {
                    first: 0,
                    second: 1
                }
            )
        ));
        assert!(matches!(
            validate_selected_zk_authorization_artifact_reuse(
                &[fake_artifact(usize::MAX, 1)],
                &ghost
            ),
            Err(HistoryStepAuthorizationPreparationError::LiveGhostProofReuse { live: 0 })
        ));
        assert!(matches!(
            validate_selected_zk_authorization_artifact_reuse(
                &[fake_artifact(1, usize::MAX - 1)],
                &ghost
            ),
            Err(
                HistoryStepAuthorizationPreparationError::LiveGhostSourceCommitmentReuse {
                    live: 0
                }
            )
        ));
    }

    #[test]
    fn pad255_hash_and_address_are_four_constant_materialized_wires() {
        let (mut b, capability) = canonical_selected_zk_authorization_fixture(0);
        let before = b.num_wires();
        let statements = materialize_selected_zk_authorization_statements(&mut b, &capability);
        assert_eq!(statements.len(), 256);
        assert_eq!(b.num_wires() - before, 4);

        let pad = &statements[255];
        let native = capability.slot(255).native_statement();
        let expressions = pad
            .tx_body_hash
            .iter()
            .chain(pad.expected_address.iter())
            .collect::<Vec<_>>();
        let expected = native
            .tx_body_hash
            .iter()
            .chain(native.address.iter())
            .copied()
            .collect::<Vec<_>>();
        let wires = expressions
            .iter()
            .zip(expected.iter())
            .map(|(expression, expected)| {
                check_transcript_alias(
                    &b,
                    expression,
                    ZkAuthorizationCandidateInput::OuterExpectedAddress,
                    0,
                )
                .expect("PAD constant has a dedicated wire");
                assert_eq!(expression.eval(b.values()), flat_of(*expected));
                expression.terms[0].0 as usize
            })
            .collect::<Vec<_>>();
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
        for wire in wires {
            let mut bad = witness.clone();
            bad[wire] += F128::ONE;
            assert!(!r1cs.satisfies(&bad), "PAD constant wire {wire} floated");
        }
    }

    #[test]
    fn pad_materialization_and_policy_metadata_are_live_count_shape_invariant() {
        let build = |live_count| {
            let (mut b, capability) = canonical_selected_zk_authorization_fixture(live_count);
            let before = b.num_wires();
            let _ = materialize_selected_zk_authorization_statements(&mut b, &capability);
            assert_eq!(b.num_wires() - before, 4);
            let (r1cs, witness) = b.build();
            assert!(r1cs.satisfies(&witness));
            (r1cs.structural_statement_digest(), r1cs.useful_rows)
        };
        assert_eq!(build(0), build(1));
        assert_eq!(build(1), build(127));
        assert_eq!(build(127), build(255));
    }

    #[test]
    fn selected_block_bridge_consumes_prepared_authority_raw_allocator_and_all_tiles_in_order() {
        let source = include_str!("zk_authorization_candidate.rs");
        let production = source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production candidate source");
        let bridge = production
            .split("fn bind_selected_zk_block_region")
            .nth(1)
            .expect("private selected Block bridge");
        let cardinality = bridge
            .find("prepared.live_entries.len()")
            .expect("prepared authorization cardinality binding");
        let statement_binding = bridge
            .find("slot.native_statement()")
            .expect("prepared authorization canonical statement binding");
        let batch = bridge
            .find("let batch = SelectedZkAuthorizationProofBatch")
            .expect("prepared authorization batch ownership");
        let raw = bridge
            .find("into_canonical_and_raw_draft")
            .expect("raw authorization derivation");
        let allocation = bridge
            .find("allocate_selected_zk_auth_pcs_region")
            .expect("common six-child allocation");
        let all_tiles = bridge
            .find("bind_selected_zk_authorization_all_tiles_trace")
            .expect("all-tiles binding");
        let opaque_return = bridge
            .find("SelectedZkBlockRegionBinding { draft, paired }")
            .expect("opaque bound return");
        assert!(cardinality < statement_binding && statement_binding < batch && batch < raw);
        assert!(raw < allocation && allocation < all_tiles);
        assert!(all_tiles < opaque_return);

        let binding = production
            .split("struct SelectedZkBlockRegionBinding")
            .nth(1)
            .expect("opaque binding declaration")
            .split('}')
            .next()
            .expect("opaque binding fields");
        assert!(
            !binding.contains("pub "),
            "draft/paired became public fields"
        );
    }
}
