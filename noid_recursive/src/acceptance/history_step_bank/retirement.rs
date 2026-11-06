// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Unfrozen reduction of legacy matrix obligations at a scheduled fork.
//!
//! This is a reduction, not a matrix-evaluation proof or an accepted handoff.
//! Replaying it needs no matrix. Its output still requires an authenticated
//! evaluation of every returned claim before any old matrix can be retired.
//! No type in this module grants terminal or State-application authority.

use super::{
    CanonicalHistoryStepClassId, HistoryStepBankError, HistoryStepMatrixLease, MatrixRequirement,
    PendingBankLane, PendingHistoryStepBankDecision, PinnedHistoryStepClassBank,
    HISTORY_STEP_CLASS_COUNT,
};
use crate::accumulator::ChainAccumulator;
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::forks::ForkSchedule;
use noid_core::Block128;
use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::field::F256;
use noid_ivc_core::matrix_claim::c1::{
    prove_matrix_claim_fold_c1, prove_matrix_claim_fold_compact_c1, verify_matrix_claim_fold_c1,
    C1FreshLincheckClaim, C1MatrixAccClaim, C1MatrixFoldProof,
};
use noid_ivc_core::matrix_claim::MatrixFoldError;
use noid_ivc_core::proof::FieldShape;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

const REQUEST_DOMAIN: &[u8] = b"NOID/HISTORY-STEP/RETIREMENT-REQUEST/V1";
const FOLD_DOMAIN: &[u8] = b"NOID/HISTORY-STEP/RETIREMENT-FOLD/C1/V1";
const REDUCTION_MAGIC: &[u8; 8] = b"O1MRED01";
const REDUCTION_HEADER_BYTES: usize = 8 + 1 + 32;

mod evaluation;
pub mod trace;
pub use evaluation::{
    CheckedHistoryStepRetirementMatrices, HistoryStepRetirementEvaluation,
    RetirementEvaluationError,
};

/// Verifier-supplied fork policy. The next bank digest is an opaque binding
/// until the separate v2 bank exists; this constructor does not certify it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryStepRetirementTarget {
    schedule: ForkSchedule,
    legacy_bank_digest: [u8; 32],
    next_bank_digest: [u8; 32],
    activation_height: u64,
}

impl HistoryStepRetirementTarget {
    pub(crate) fn for_authorization(
        schedule: ForkSchedule,
        previous_bank: [u8; 32],
        next_bank: [u8; 32],
        activation_height: u64,
    ) -> Result<Self, HistoryStepRetirementError> {
        if schedule
            .v2()
            .is_none_or(|v| v.height() >= activation_height)
            || previous_bank == [0; 32]
            || next_bank == [0; 32]
            || previous_bank == next_bank
        {
            return Err(HistoryStepRetirementError::Schedule);
        }
        Ok(Self {
            schedule,
            legacy_bank_digest: previous_bank,
            next_bank_digest: next_bank,
            activation_height,
        })
    }

    pub fn new(
        schedule: ForkSchedule,
        legacy_bank: &PinnedHistoryStepClassBank,
        next_bank_digest: [u8; 32],
    ) -> Result<Self, HistoryStepRetirementError> {
        let activation_height = schedule
            .v2()
            .map(|activation| activation.height())
            .filter(|height| *height > 1)
            .ok_or(HistoryStepRetirementError::Schedule)?;
        if next_bank_digest == [0; 32] || next_bank_digest == legacy_bank.digest() {
            return Err(HistoryStepRetirementError::BankIdentity);
        }
        Ok(Self {
            schedule,
            legacy_bank_digest: legacy_bank.digest(),
            next_bank_digest,
            activation_height,
        })
    }

    pub const fn activation_height(&self) -> u64 {
        self.activation_height
    }

    pub const fn next_bank_digest(&self) -> [u8; 32] {
        self.next_bank_digest
    }

    pub const fn legacy_bank_digest(&self) -> [u8; 32] {
        self.legacy_bank_digest
    }

    pub const fn schedule(&self) -> ForkSchedule {
        self.schedule
    }

    pub(crate) fn check_parent_height(
        &self,
        height: u64,
    ) -> Result<(), HistoryStepRetirementError> {
        if height.checked_add(1) != Some(self.activation_height) {
            return Err(HistoryStepRetirementError::Boundary);
        }
        Ok(())
    }

    pub(crate) fn check_legacy_bank(
        &self,
        digest: [u8; 32],
    ) -> Result<(), HistoryStepRetirementError> {
        if self.legacy_bank_digest != digest {
            return Err(HistoryStepRetirementError::BankIdentity);
        }
        Ok(())
    }
}

/// Exact outstanding obligations from a replayed legacy terminal. Only the
/// verifier can construct this request. It cannot be decoded from peer data.
#[must_use = "a retirement request still contains unchecked matrix obligations"]
pub struct HistoryStepRetirementRequest {
    target: HistoryStepRetirementTarget,
    parent_header: BlockHeader,
    epoch_anchor_header: BlockHeader,
    boundary: ChainAccumulator,
    tip_class: CanonicalHistoryStepClassId,
    requirements: [MatrixRequirement; HISTORY_STEP_CLASS_COUNT],
    fresh: C1FreshLincheckClaim,
    lanes: [Option<C1MatrixAccClaim>; HISTORY_STEP_CLASS_COUNT],
    binding: [u8; 32],
    predecessor_origin: Option<[u8; 32]>,
}

impl HistoryStepRetirementRequest {
    pub(crate) fn from_pending(
        pending: PendingHistoryStepBankDecision,
        target: HistoryStepRetirementTarget,
        parent_header: &BlockHeader,
        epoch_anchor_header: &BlockHeader,
    ) -> Result<Self, HistoryStepRetirementError> {
        target.check_parent_height(parent_header.height)?;
        if target.legacy_bank_digest != pending.bank_digest {
            return Err(HistoryStepRetirementError::BankIdentity);
        }
        // A previous local matrix scan is not transferable evidence. Require
        // the untouched replay, so no checked lane can silently disappear.
        if pending.tip_fresh.is_none()
            || pending
                .lanes
                .iter()
                .any(|lane| matches!(lane, PendingBankLane::Checked))
        {
            return Err(HistoryStepRetirementError::AlreadyDischarged);
        }
        let boundary = ChainAccumulator::from_lanes(pending.block_accumulator.map(|lane| {
            let flat = lane.lo as u128 | ((lane.hi as u128) << 64);
            Block128::from(noid_core::hardware::flat_to_tower_u128(flat))
        }))
        .map_err(|_| HistoryStepRetirementError::Boundary)?;
        boundary
            .validate_local_header_boundary(parent_header, epoch_anchor_header)
            .map_err(|_| HistoryStepRetirementError::Boundary)?;
        if pending.base != (boundary.height == 1) {
            return Err(HistoryStepRetirementError::Boundary);
        }
        let mut request = Self {
            target,
            parent_header: *parent_header,
            epoch_anchor_header: *epoch_anchor_header,
            boundary,
            tip_class: pending.tip_class,
            requirements: pending.requirements,
            fresh: pending.tip_fresh.expect("checked above"),
            lanes: pending.lanes.map(|lane| match lane {
                PendingBankLane::Pending(claim) => Some(claim),
                PendingBankLane::Dead => None,
                PendingBankLane::Checked => unreachable!("checked above"),
            }),
            binding: [0; 32],
            predecessor_origin: None,
        };
        request.binding = request.compute_binding();
        Ok(request)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_banked_replay(
        target: HistoryStepRetirementTarget,
        predecessor_origin: [u8; 32],
        parent_header: &BlockHeader,
        epoch_header: &BlockHeader,
        boundary: ChainAccumulator,
        tip_class: CanonicalHistoryStepClassId,
        matrices: [(FieldShape, [u8; 32]); HISTORY_STEP_CLASS_COUNT],
        fresh: C1FreshLincheckClaim,
        lanes: [Option<C1MatrixAccClaim>; HISTORY_STEP_CLASS_COUNT],
    ) -> Result<Self, HistoryStepRetirementError> {
        target.check_parent_height(parent_header.height)?;
        boundary
            .validate_local_header_boundary(parent_header, epoch_header)
            .map_err(|_| HistoryStepRetirementError::Boundary)?;
        let mut request = Self {
            target,
            parent_header: *parent_header,
            epoch_anchor_header: *epoch_header,
            boundary,
            tip_class,
            requirements: matrices.map(|(shape, digest)| MatrixRequirement { shape, digest }),
            fresh,
            lanes,
            binding: [0; 32],
            predecessor_origin: Some(predecessor_origin),
        };
        request.binding = request.compute_binding();
        Ok(request)
    }

    pub const fn predecessor_origin_binding(&self) -> Option<[u8; 32]> {
        self.predecessor_origin
    }

    pub const fn binding(&self) -> [u8; 32] {
        self.binding
    }

    pub fn boundary(&self) -> &ChainAccumulator {
        &self.boundary
    }

    pub fn parent_header(&self) -> &BlockHeader {
        &self.parent_header
    }

    pub fn epoch_anchor_header(&self) -> &BlockHeader {
        &self.epoch_anchor_header
    }

    pub const fn target(&self) -> &HistoryStepRetirementTarget {
        &self.target
    }

    pub const fn tip_class(&self) -> CanonicalHistoryStepClassId {
        self.tip_class
    }

    fn shape(&self) -> FieldShape {
        self.requirements[self.tip_class.index()].shape
    }

    fn compute_binding(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.target.legacy_bank_digest);
        bytes.extend_from_slice(&self.target.next_bank_digest);
        // A scheduled v2 always has a v1.1 activation; encode both heights.
        bytes.extend_from_slice(
            &self
                .target
                .schedule
                .v1_1_height()
                .expect("valid schedule")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.target.activation_height.to_le_bytes());
        bytes.extend_from_slice(
            &self
                .target
                .schedule
                .v2()
                .expect("checked retirement target")
                .block_time()
                .to_le_bytes(),
        );
        self.parent_header.encode(&mut bytes);
        self.epoch_anchor_header.encode(&mut bytes);
        for lane in self.boundary.to_lanes() {
            bytes.extend_from_slice(&lane.to_u128().to_le_bytes());
        }
        bytes.push(self.tip_class.wire_id());
        for (index, (requirement, claim)) in self.requirements.iter().zip(&self.lanes).enumerate() {
            bytes.push(index as u8);
            bytes.extend_from_slice(&requirement.digest);
            for value in [
                requirement.shape.m,
                requirement.shape.k_log,
                requirement.shape.k_skip,
            ] {
                bytes.extend_from_slice(&(value as u64).to_le_bytes());
            }
            bytes.extend_from_slice(
                &requirement
                    .shape
                    .const_pin
                    .map_or(0, |pin| pin as u64 + 1)
                    .to_le_bytes(),
            );
            bytes.push(u8::from(claim.is_some()));
            if let Some(claim) = claim {
                push_fields(&mut bytes, &claim.point);
                bytes.extend_from_slice(&claim.value.to_le_bytes());
            }
        }
        bytes.extend_from_slice(&self.fresh.alpha.to_le_bytes());
        bytes.extend_from_slice(&self.fresh.z_skip.to_le_bytes());
        push_fields(&mut bytes, &self.fresh.x_inner_rest);
        push_fields(&mut bytes, &self.fresh.r_inner_rest);
        push_fields(&mut bytes, &self.fresh.z_partial);
        bytes.extend_from_slice(&self.fresh.value.to_le_bytes());
        if let Some(predecessor) = self.predecessor_origin {
            bytes.extend_from_slice(b"NOID/BANKED-AUTHORIZATION-RETIREMENT/V1");
            bytes.extend_from_slice(&predecessor);
            bytes.extend_from_slice(
                &self
                    .target
                    .schedule
                    .v2()
                    .expect("checked schedule")
                    .height()
                    .to_le_bytes(),
            );
        }
        poseidon2b_hash_byte_slices(REQUEST_DOMAIN, &[&bytes])
    }

    fn channel(&self) -> FsLaneChallenger {
        let mut channel = FsLaneChallenger::new_c1(FOLD_DOMAIN);
        channel.observe_bytes(&self.binding);
        channel
    }

    fn incoming(&self) -> C1MatrixAccClaim {
        self.lanes[self.tip_class.index()]
            .clone()
            .unwrap_or_else(|| C1MatrixAccClaim::zero(self.shape().k_log))
    }

    /// Prove only the fresh-tip reduction using its authenticated old matrix.
    /// Non-selected live lanes are retained unchanged by the verifier.
    pub fn prove_reduction(
        &self,
        matrix: &HistoryStepMatrixLease,
    ) -> Result<HistoryStepRetirementReduction, HistoryStepRetirementError> {
        let requirement = self.requirements[self.tip_class.index()];
        if matrix.field_shape() != requirement.shape {
            return Err(HistoryStepRetirementError::Matrix(
                HistoryStepBankError::MatrixShape(self.tip_class),
            ));
        }
        if matrix.statement_digest() != requirement.digest {
            return Err(HistoryStepRetirementError::Matrix(
                HistoryStepBankError::MatrixDigest(self.tip_class),
            ));
        }
        let incoming = self.incoming();
        let live = self.lanes[self.tip_class.index()].is_some();
        let mut channel = self.channel();
        let (fold, _) = match matrix {
            HistoryStepMatrixLease::Resident(matrix) => {
                prove_matrix_claim_fold_c1(matrix, &self.fresh, &incoming, live, &mut channel)
            }
            HistoryStepMatrixLease::Compact(matrix) => prove_matrix_claim_fold_compact_c1(
                matrix,
                &self.fresh,
                &incoming,
                live,
                &mut channel,
            ),
        };
        Ok(HistoryStepRetirementReduction {
            class_id: self.tip_class,
            request_binding: self.binding,
            fold,
        })
    }

    /// Verify without loading a matrix. Success is still pending: every
    /// remaining MLE claim must be closed by a separate evaluation proof.
    pub fn verify_reduction(
        &self,
        proof: &HistoryStepRetirementReduction,
    ) -> Result<PendingHistoryStepRetirement, HistoryStepRetirementError> {
        proof.check_binding(self)?;
        let outgoing = verify_matrix_claim_fold_c1(
            self.shape().k_log,
            self.shape().k_skip,
            &self.fresh,
            &self.incoming(),
            if self.lanes[self.tip_class.index()].is_some() {
                F256::ONE
            } else {
                F256::ZERO
            },
            &proof.fold,
            &mut self.channel(),
        )
        .map_err(HistoryStepRetirementError::Fold)?;
        let mut claims = self.lanes.clone();
        claims[self.tip_class.index()] = Some(outgoing);
        Ok(PendingHistoryStepRetirement {
            request_binding: self.binding,
            target: self.target,
            boundary: self.boundary.clone(),
            obligations: std::array::from_fn(|index| {
                claims[index].take().map(|claim| PendingRetiredMatrixClaim {
                    class_id: CanonicalHistoryStepClassId::from_index(index)
                        .expect("fixed legacy bank"),
                    shape: self.requirements[index].shape,
                    matrix_digest: self.requirements[index].digest,
                    claim,
                })
            }),
        })
    }

    fn reduction_wire_bytes(&self) -> usize {
        REDUCTION_HEADER_BYTES + (4 * self.shape().k_log + 5) * 32
    }
}

fn push_fields(bytes: &mut Vec<u8>, values: &[F256]) {
    bytes.extend_from_slice(&(values.len() as u64).to_le_bytes());
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
}

/// Bounded reduction proof. Its codec is experimental and is not a node
/// terminal encoding. It cannot encode a matrix, an omitted lane or a target
/// chosen by a peer; these all come from the verifier's request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryStepRetirementReduction {
    class_id: CanonicalHistoryStepClassId,
    request_binding: [u8; 32],
    fold: C1MatrixFoldProof,
}

impl HistoryStepRetirementReduction {
    fn check_binding(
        &self,
        request: &HistoryStepRetirementRequest,
    ) -> Result<(), HistoryStepRetirementError> {
        if self.class_id != request.tip_class || self.request_binding != request.binding {
            return Err(HistoryStepRetirementError::Binding);
        }
        let k_log = request.shape().k_log;
        if self.fold.phase1_rounds.len() != k_log + 1 || self.fold.phase2_rounds.len() != k_log {
            return Err(HistoryStepRetirementError::Wire);
        }
        Ok(())
    }

    pub fn encode_for(
        &self,
        request: &HistoryStepRetirementRequest,
    ) -> Result<Vec<u8>, HistoryStepRetirementError> {
        self.check_binding(request)?;
        let mut bytes = Vec::with_capacity(request.reduction_wire_bytes());
        bytes.extend_from_slice(REDUCTION_MAGIC);
        bytes.push(self.class_id.wire_id());
        bytes.extend_from_slice(&self.request_binding);
        for round in &self.fold.phase1_rounds {
            for value in round {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        for value in [self.fold.g_v, self.fold.g_e] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for round in &self.fold.phase2_rounds {
            for value in round {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        bytes.extend_from_slice(&self.fold.final_matrix_eval.to_le_bytes());
        debug_assert_eq!(bytes.len(), request.reduction_wire_bytes());
        Ok(bytes)
    }

    /// Check exact length, version and context before allocating any rounds.
    pub fn decode_for(
        request: &HistoryStepRetirementRequest,
        bytes: &[u8],
    ) -> Result<Self, HistoryStepRetirementError> {
        if bytes.len() != request.reduction_wire_bytes() || &bytes[..8] != REDUCTION_MAGIC {
            return Err(HistoryStepRetirementError::Wire);
        }
        if bytes[8] != request.tip_class.wire_id() || bytes[9..41] != request.binding {
            return Err(HistoryStepRetirementError::Binding);
        }
        let mut fields = bytes[REDUCTION_HEADER_BYTES..].chunks_exact(32);
        let mut next = || {
            F256::from_le_bytes(
                fields
                    .next()
                    .expect("exact length checked")
                    .try_into()
                    .expect("field width"),
            )
        };
        let phase1_rounds = (0..request.shape().k_log + 1)
            .map(|_| [next(), next()])
            .collect();
        let g_v = next();
        let g_e = next();
        let phase2_rounds = (0..request.shape().k_log)
            .map(|_| [next(), next()])
            .collect();
        let final_matrix_eval = next();
        Ok(Self {
            class_id: request.tip_class,
            request_binding: request.binding,
            fold: C1MatrixFoldProof {
                phase1_rounds,
                g_v,
                g_e,
                phase2_rounds,
                final_matrix_eval,
            },
        })
    }
}

/// One still-unchecked legacy MLE. No public constructor or mutation surface.
pub struct PendingRetiredMatrixClaim {
    class_id: CanonicalHistoryStepClassId,
    shape: FieldShape,
    matrix_digest: [u8; 32],
    claim: C1MatrixAccClaim,
}

impl PendingRetiredMatrixClaim {
    pub const fn class_id(&self) -> CanonicalHistoryStepClassId {
        self.class_id
    }
    pub const fn shape(&self) -> FieldShape {
        self.shape
    }
    pub const fn matrix_digest(&self) -> [u8; 32] {
        self.matrix_digest
    }
    pub fn claim(&self) -> &C1MatrixAccClaim {
        &self.claim
    }
}

/// A verified reduction with unresolved matrix evaluations. Experimental
/// evaluation proofs can close these; there is no accepted-terminal conversion
/// or matrix-retirement capability.
#[must_use = "every legacy matrix evaluation remains to be proved"]
pub struct PendingHistoryStepRetirement {
    request_binding: [u8; 32],
    target: HistoryStepRetirementTarget,
    boundary: ChainAccumulator,
    obligations: [Option<PendingRetiredMatrixClaim>; HISTORY_STEP_CLASS_COUNT],
}

impl PendingHistoryStepRetirement {
    pub const fn request_binding(&self) -> [u8; 32] {
        self.request_binding
    }
    pub const fn target(&self) -> &HistoryStepRetirementTarget {
        &self.target
    }
    pub fn boundary(&self) -> &ChainAccumulator {
        &self.boundary
    }
    pub fn obligations(&self) -> impl Iterator<Item = &PendingRetiredMatrixClaim> {
        self.obligations.iter().filter_map(Option::as_ref)
    }
}

#[derive(Debug)]
pub enum HistoryStepRetirementError {
    Schedule,
    BankIdentity,
    Boundary,
    AlreadyDischarged,
    Binding,
    Wire,
    Matrix(HistoryStepBankError),
    Fold(MatrixFoldError),
    Replay(crate::acceptance::history_step::HistoryStepError),
}

impl core::fmt::Display for HistoryStepRetirementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Schedule => {
                f.write_str("retirement requires a scheduled v2 with a legacy terminal")
            }
            Self::BankIdentity => f.write_str("retirement bank identity mismatch"),
            Self::Boundary => {
                f.write_str("retirement must consume the exact pre-fork chain boundary")
            }
            Self::AlreadyDischarged => {
                f.write_str("a local matrix check cannot replace a retirement obligation")
            }
            Self::Binding => f.write_str("retirement reduction request mismatch"),
            Self::Wire => f.write_str("invalid retirement reduction encoding or shape"),
            Self::Matrix(error) => write!(f, "retirement matrix: {error}"),
            Self::Fold(error) => write!(f, "retirement reduction: {error}"),
            Self::Replay(error) => write!(f, "retirement terminal replay: {error}"),
        }
    }
}

impl std::error::Error for HistoryStepRetirementError {}

#[cfg(test)]
mod tests;
