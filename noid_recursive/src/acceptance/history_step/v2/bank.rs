// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! One v2 matrix, one accumulated claim, and an immutable authenticated fork
//! origin. No legacy matrix claim is silently reset by this layout.

use super::*;
use crate::acceptance::history_step_bank::block_acc_lanes;
use noid_core::Block128;
use noid_ivc_core::field_circuit::f128_to_u128;
use noid_ivc_core::matrix_claim::c1::{
    fresh_claim_value_c1, stacked_matrix_mle_eval_c1, C1MatrixAccClaim,
};
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

pub(super) const FOLD_DOMAIN: &[u8] = b"history-step-single-fold-v2";

pub(super) const BASE: usize = 0;
pub(super) const MATRIX: usize = 1;
pub(super) const POST: usize = MATRIX + 2;
pub(super) const BANK: usize = POST + 2;
pub(super) const ORIGIN: usize = BANK + 2;
pub(super) const ORIGIN_ID: usize = ORIGIN + 2;
pub(super) const ORIGIN_ACC: usize = ORIGIN_ID + 2;
pub(super) const POINT: usize = ORIGIN_ACC + 10;
/// Fixed public identity of the one-class runtime. Construction authenticates
/// composition; release pin selection remains the verifier's responsibility.
#[derive(Clone, Debug)]
pub struct V2Bank {
    config: V2Config,
    matrix_digest: [u8; 32],
    post_commit_digest: [u8; 32],
    digest: [u8; 32],
    parent_digest: [u8; 32],
    block_digest: [u8; 32],
}

impl V2Bank {
    pub fn pin(matrix_digest: [u8; 32], parts: &V2RuntimeParts) -> Self {
        let parent_digest = parts.parent_vk.transcript_digest();
        let block_digest = parts.block_vk.transcript_digest();
        let config = parts.config;
        let identity = config.identity_bytes();
        let spec: Vec<u8> = config
            .io_spec()
            .transcript_lanes()
            .iter()
            .flat_map(|lane| [lane.lo.to_le_bytes(), lane.hi.to_le_bytes()].concat())
            .collect();
        let pcs = pcs_params_statement_bytes(&config.pcs_params());
        let s = config.shape();
        let shape_bytes: Vec<u8> = [s.m, s.k_log, s.k_skip, s.const_pin.unwrap() + 1]
            .into_iter()
            .flat_map(|x| (x as u64).to_le_bytes())
            .collect();
        let post_commit_digest = poseidon2b_hash_byte_slices(
            b"NOID/HISTORY-STEP/SINGLE-POST-COMMIT/V2",
            &[
                &identity,
                &matrix_digest,
                &shape_bytes,
                &spec,
                &pcs,
                &parent_digest,
                &block_digest,
            ],
        );
        let digest = poseidon2b_hash_byte_slices(
            b"NOID/HISTORY-STEP/SINGLE-BANK/V2",
            &[
                &identity,
                &matrix_digest,
                &post_commit_digest,
                &shape_bytes,
                &spec,
                &pcs,
                &parent_digest,
                &block_digest,
            ],
        );
        Self {
            config,
            matrix_digest,
            post_commit_digest,
            digest,
            parent_digest,
            block_digest,
        }
    }
    pub fn config(&self) -> V2Config {
        self.config
    }
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub const fn matrix_digest(&self) -> [u8; 32] {
        self.matrix_digest
    }
    pub const fn post_commit_digest(&self) -> [u8; 32] {
        self.post_commit_digest
    }
    pub(super) fn check_parts(&self, parts: &V2RuntimeParts) -> Result<(), V2Error> {
        if self.config != parts.config
            || self.parent_digest != parts.parent_vk.transcript_digest()
            || self.block_digest != parts.block_vk.transcript_digest()
        {
            return Err(V2Error::Runtime);
        }
        Ok(())
    }
    pub(super) fn authenticate(&self, matrix: &HistoryStepMatrixLease) -> Result<(), V2Error> {
        if matrix.field_shape() != self.config.shape()
            || matrix.statement_digest() != self.matrix_digest
        {
            return Err(V2Error::Matrix);
        }
        Ok(())
    }
    pub(super) fn initial_io(&self, origin: &V2Origin, end: &ChainAccumulator) -> Vec<F128> {
        let layout = self.config.layout();
        let mut io = vec![F128::ZERO; layout.len];
        io[BASE] = F128::ONE;
        for (offset, digest) in [
            (MATRIX, self.matrix_digest),
            (POST, self.post_commit_digest),
            (BANK, self.digest),
            (ORIGIN, origin.request_binding),
        ] {
            io[offset..offset + 2].copy_from_slice(&flat_digest_lanes(&digest));
        }
        io[ORIGIN_ID..ORIGIN_ID + 2].copy_from_slice(&digest_lanes(&origin.parent_id).map(flat_of));
        io[ORIGIN_ACC..ORIGIN_ACC + 10].copy_from_slice(&block_acc_lanes(&origin.boundary));
        io[layout.acc..layout.acc + 10].copy_from_slice(&block_acc_lanes(end));
        io
    }
    pub(super) fn parse(&self, io: &[F128]) -> Result<ParsedIo, V2Error> {
        let layout = self.config.layout();
        if io.len() != layout.len {
            return Err(V2Error::Io);
        }
        for (offset, digest) in [
            (MATRIX, self.matrix_digest),
            (POST, self.post_commit_digest),
            (BANK, self.digest),
        ] {
            if io[offset..offset + 2] != flat_digest_lanes(&digest) {
                return Err(V2Error::Io);
            }
        }
        let base = match io[BASE] {
            F128::ZERO => false,
            F128::ONE => true,
            _ => return Err(V2Error::Io),
        };
        let claim = match io[layout.live] {
            F128::ZERO if io[POINT..layout.live].iter().all(|x| *x == F128::ZERO) => None,
            F128::ONE => Some(C1MatrixAccClaim {
                point: io[POINT..layout.value]
                    .chunks_exact(2)
                    .map(|x| F256::new(x[0], x[1]))
                    .collect(),
                value: F256::new(io[layout.value], io[layout.value + 1]),
            }),
            _ => return Err(V2Error::Io),
        };
        if base == claim.is_some() {
            return Err(V2Error::Io);
        }
        let origin = V2Origin {
            request_binding: digest_from_flat(&io[ORIGIN..ORIGIN + 2]),
            parent_id: digest_from_state_lanes(&io[ORIGIN_ID..ORIGIN_ID + 2]),
            boundary: accumulator_from_flat(&io[ORIGIN_ACC..ORIGIN_ACC + 10])?,
            next_bank: self.digest,
        };
        let accumulator = accumulator_from_flat(&io[layout.acc..layout.acc + 10])?;
        let activation = origin.activation_height()?;
        if accumulator.height < activation || base != (accumulator.height == activation) {
            return Err(V2Error::Boundary);
        }
        Ok(ParsedIo {
            claim,
            origin,
            accumulator,
        })
    }
}

fn accumulator_from_flat(lanes: &[F128]) -> Result<ChainAccumulator, V2Error> {
    let lanes: [Block128; 10] = lanes
        .iter()
        .map(|lane| Block128(noid_core::hardware::flat_to_tower_u128(f128_to_u128(*lane))))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| V2Error::Io)?;
    ChainAccumulator::from_lanes(lanes).map_err(|_| V2Error::Io)
}

fn digest_from_flat(lanes: &[F128]) -> [u8; 32] {
    // Digest lanes use flat bytes directly, not the tower encoding of State.
    let mut digest = [0u8; 32];
    for (chunk, lane) in digest.chunks_exact_mut(16).zip(lanes) {
        chunk.copy_from_slice(&f128_to_u128(*lane).to_le_bytes());
    }
    digest
}

fn digest_from_state_lanes(lanes: &[F128]) -> [u8; 32] {
    let mut digest = [0; 32];
    for (chunk, lane) in digest.chunks_exact_mut(16).zip(lanes) {
        chunk.copy_from_slice(
            &noid_core::hardware::flat_to_tower_u128(f128_to_u128(*lane)).to_le_bytes(),
        );
    }
    digest
}

pub(super) struct ParsedIo {
    pub claim: Option<C1MatrixAccClaim>,
    pub origin: V2Origin,
    pub accumulator: ChainAccumulator,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (V2Bank, V2Origin, ChainAccumulator) {
        let config = V2Config::new(
            23,
            64,
            noid_chain::consensus::forks::ForkSchedule::new(
                Some(5),
                noid_chain::consensus::forks::V2Activation::new(10, 30),
            )
            .unwrap(),
        )
        .unwrap();
        let bank = V2Bank {
            config,
            matrix_digest: [11; 32],
            post_commit_digest: [12; 32],
            digest: [13; 32],
            parent_digest: [14; 32],
            block_digest: [15; 32],
        };
        let mut boundary = genesis_accumulator();
        boundary.height = 9;
        boundary.tip_semantic_id = [23; 32];
        boundary.state_root = [31; 32];
        let origin = V2Origin {
            request_binding: [21; 32],
            parent_id: [22; 32],
            boundary: boundary.clone(),
            next_bank: bank.digest(),
        };
        let mut end = boundary;
        end.height = 10;
        end.tip_semantic_id = [24; 32];
        (bank, origin, end)
    }

    #[test]
    fn origin_encoding_preserves_full_header_and_state_field_domains() {
        let (bank, origin, end) = fixture();
        let io = bank.initial_io(&origin, &end);
        let parsed = bank.parse(&io).unwrap();
        assert_eq!(parsed.origin, origin);
        assert_eq!(parsed.accumulator, end);
        assert!(parsed.claim.is_none());
        assert_eq!(
            io[ORIGIN_ID..ORIGIN_ID + 2],
            digest_lanes(&origin.parent_id).map(flat_of)
        );
        assert_ne!(
            io[ORIGIN_ID..ORIGIN_ID + 2],
            flat_digest_lanes(&origin.parent_id)
        );
    }

    #[test]
    fn single_lane_cannot_be_dropped_reset_or_rebound_to_a_different_bank() {
        let (bank, origin, end) = fixture();
        let layout = bank.config.layout();
        let io = bank.initial_io(&origin, &end);
        for index in [
            MATRIX,
            MATRIX + 1,
            POST,
            POST + 1,
            BANK,
            BANK + 1,
            POINT,
            layout.value,
            layout.live,
        ] {
            let mut invalid = io.clone();
            invalid[index] += F128::ONE;
            assert!(bank.parse(&invalid).is_err(), "tampered base IO at {index}");
        }
        let mut recursive = io;
        let mut next = end.clone();
        next.height += 1;
        recursive[layout.acc..layout.acc + 10].copy_from_slice(&block_acc_lanes(&next));
        assert!(
            bank.parse(&recursive).is_err(),
            "base flag reset at a later height"
        );
        let claim = C1MatrixAccClaim {
            point: vec![F256::ONE; layout.point_len],
            value: F256::ONE,
        };
        install_claim(bank.config, &mut recursive, &claim).unwrap();
        let parsed = bank.parse(&recursive).unwrap();
        assert_eq!(parsed.origin, origin);
        assert_eq!(parsed.claim.unwrap().point, claim.point);
        let mut invalid = recursive.clone();
        invalid[layout.live] = F128::ZERO;
        assert!(bank.parse(&invalid).is_err());
        invalid[POINT..layout.live].fill(F128::ZERO);
        assert!(
            bank.parse(&invalid).is_err(),
            "recursive history cannot drop its lane"
        );
        recursive[BASE] = F128::ONE;
        assert!(bank.parse(&recursive).is_err());
    }
}

/// Witness of the immutable fork boundary. This carries no acceptance
/// authority: every terminal verifier also requires `VerifiedV2Origin`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2Origin {
    pub(super) request_binding: [u8; 32],
    pub(super) parent_id: [u8; 32],
    pub(super) boundary: ChainAccumulator,
    next_bank: [u8; 32],
}

impl V2Origin {
    /// Build the boundary statement used for deterministic matrix generation.
    /// Terminal acceptance uses an independently verified origin capability.
    pub fn for_matrix_freezing(
        legacy_bank: [u8; 32],
        next: &V2Bank,
        parent: &BlockHeader,
        epoch: &BlockHeader,
        boundary: &ChainAccumulator,
    ) -> Result<Self, V2Error> {
        if parent.height.checked_add(1) != Some(next.config.activation_height()) {
            return Err(V2Error::Boundary);
        }
        boundary
            .validate_local_header_boundary(parent, epoch)
            .map_err(|_| V2Error::Boundary)?;
        let mut boundary_bytes = Vec::new();
        parent.encode(&mut boundary_bytes);
        epoch.encode(&mut boundary_bytes);
        for lane in boundary.to_lanes() {
            boundary_bytes.extend_from_slice(&lane.0.to_le_bytes());
        }
        let request_binding = poseidon2b_hash_byte_slices(
            b"NOID/HISTORY-STEP/VERIFIED-ORIGIN/V2",
            &[
                &legacy_bank,
                &next.digest(),
                &next.config.identity_bytes(),
                &boundary_bytes,
            ],
        );
        let origin = Self {
            request_binding,
            parent_id: noid_chain::hash_block_header(parent),
            boundary: boundary.clone(),
            next_bank: next.digest(),
        };
        origin.check(next)?;
        Ok(origin)
    }

    pub fn boundary(&self) -> &ChainAccumulator {
        &self.boundary
    }
    pub const fn parent_id(&self) -> [u8; 32] {
        self.parent_id
    }
    pub const fn request_binding(&self) -> [u8; 32] {
        self.request_binding
    }
    pub const fn next_bank(&self) -> [u8; 32] {
        self.next_bank
    }
    pub fn activation_height(&self) -> Result<u64, V2Error> {
        self.boundary
            .height
            .checked_add(1)
            .filter(|h| *h > 1)
            .ok_or(V2Error::Boundary)
    }
    pub(super) fn check(&self, bank: &V2Bank) -> Result<(), V2Error> {
        if self.next_bank != bank.digest()
            || self.activation_height()? != bank.config.activation_height()
        {
            return Err(V2Error::Boundary);
        }
        Ok(())
    }
}

/// All legacy obligations have been checked for this exact sealed boundary,
/// schedule and new bank. It cannot be constructed from a peer's raw fields.
/// A later certificate verifier must mint this same authority only after
/// authenticating the complete legacy proof and every matrix obligation.
pub struct VerifiedV2Origin(pub(super) V2Origin);

impl VerifiedV2Origin {
    pub fn origin(&self) -> &V2Origin {
        &self.0
    }

    /// Transition releases may verify with locally authenticated old rows.
    pub fn from_legacy(
        legacy: &HistoryStepRuntime,
        terminal: &HistoryStepTerminal,
        parent_header: &BlockHeader,
        epoch_header: &BlockHeader,
        next: &V2Bank,
    ) -> Result<Self, V2Error> {
        noid_chain::consensus::pow::validate_pow(parent_header).map_err(|_| V2Error::Origin)?;
        if next.config.authorization_activation().is_some()
            || parent_header.height.checked_add(1) != Some(next.config.activation_height())
        {
            return Err(V2Error::Boundary);
        }
        // Full terminal verification discharges every live legacy lane.
        let accepted = verify_history_step_terminal(legacy, terminal, parent_header, epoch_header)?;
        let mut boundary_bytes = Vec::new();
        parent_header.encode(&mut boundary_bytes);
        epoch_header.encode(&mut boundary_bytes);
        for lane in accepted.accumulator().to_lanes() {
            boundary_bytes.extend_from_slice(&lane.0.to_le_bytes());
        }
        let request_binding = poseidon2b_hash_byte_slices(
            b"NOID/HISTORY-STEP/VERIFIED-ORIGIN/V2",
            &[
                &legacy.bank().digest(),
                &next.digest(),
                &next.config.identity_bytes(),
                &boundary_bytes,
            ],
        );
        let origin = V2Origin {
            request_binding,
            parent_id: noid_chain::hash_block_header(parent_header),
            boundary: accepted.accumulator().clone(),
            next_bank: next.digest(),
        };
        origin.check(next)?;
        Ok(Self(origin))
    }
}

pub(super) fn install_claim(
    config: V2Config,
    io: &mut [F128],
    claim: &C1MatrixAccClaim,
) -> Result<(), V2Error> {
    let layout = config.layout();
    if io.len() != layout.len || claim.point.len() != layout.point_len {
        return Err(V2Error::Io);
    }
    for (lanes, point) in io[POINT..layout.value]
        .chunks_exact_mut(2)
        .zip(&claim.point)
    {
        lanes.copy_from_slice(&[point.lo, point.hi]);
    }
    io[layout.value] = claim.value.lo;
    io[layout.value + 1] = claim.value.hi;
    io[layout.live] = F128::ONE;
    io[BASE] = F128::ZERO;
    Ok(())
}

pub(super) fn check_claims(
    matrix: &HistoryStepMatrixLease,
    fresh: &C1FreshLincheckClaim,
    accumulated: Option<&C1MatrixAccClaim>,
) -> Result<(), V2Error> {
    let (fv, av) = match matrix {
        HistoryStepMatrixLease::Resident(matrix) => (
            fresh_claim_value_c1(matrix, fresh),
            accumulated.map(|claim| stacked_matrix_mle_eval_c1(matrix, claim)),
        ),
        HistoryStepMatrixLease::Compact(matrix) => {
            let evaluated = matrix
                .evaluate_matrix_claims_c1_authenticated(Some(fresh), accumulated)
                .map_err(|_| V2Error::Matrix)?;
            if !evaluated.is_bound_to(Some(fresh), accumulated) {
                return Err(V2Error::Matrix);
            }
            (
                evaluated.fresh_value().ok_or(V2Error::Matrix)?,
                evaluated.accumulated_value(),
            )
        }
    };
    if fv != fresh.value || av != accumulated.map(|c| c.value) {
        return Err(V2Error::Matrix);
    }
    Ok(())
}
