// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical selected Owner transcript for the witness-hiding authorization
//! capsule.
//!
//! This is the sole native implementation of the Owner half of the split
//! transcript.  The prover borrows a caller-owned, already length-checked
//! bank.  A higher PCS typestate owns one-shot freshness; this algebraic
//! layer does not.  The transcript-only verifier consumes only the canonical
//! public statement, flattened 16-lane source cap, and 117-field proof
//! payload; it reconstructs the transparent post-claim relation which
//! Main/PCS must discharge.  It never receives the private bank.
//!
//! The transcript follows the constants in this module exactly:
//!
//! 1. fixed Owner prefix, public statement, and source cap;
//! 2. `rho[11]`, then `mu = g_MLE(rho)` and nonzero `lambda`;
//! 3. eleven adaptive HIGH-to-LOW degree-ten MLE-check rounds;
//! 4. `g(r)` and five ZK-padded terminal operand claims, then nonzero `eta`;
//! 5. one post-claim relation and an exact four-lane consuming bridge.
//!
//! Only prover-owned dynamic absorb values are serialized.  Fiat--Shamir
//! challenges and the bridge are always replayed and derived.  This bounded
//! cut does not yet authenticate the source cap against the bank: that is the
//! Main/PCS path obligation.
//!
//! The Owner algebra creates no randomness.  The complete public prover later
//! in this module owns the OS-CSPRNG boundary which fills the bank's PCS coins,
//! Libra buffer, terminal pads, and companion oracle.
//! [`verify_zk_auth_capsule_owner_witness_reference`] is an optional
//! differential helper which checks the reconstructed relation against a
//! supplied bank; it is not needed by transcript verification.
//!
//! [`ZkAuthorizationProof::preflight_shape`] is the native in-memory shape
//! gate.  The canonical allocation-bounded proof codec lives in
//! `zk_authorization_wire`; switching the outer wallet/consensus envelope to
//! that codec remains a separate wire hard cut.

use crate::authorization_profile::{AuthorizationLayout, OwnerAuthorizationVersion};
use crate::zk_auth_capsule::{
    auth_main_round_polynomial, compute_terminal_operand_claims,
    evaluate_auth_main_terminal_from_claims, validate_auth_main_relation, validate_sparse_boundary,
    AuthCapsuleBoundaryPublic, AuthCapsulePostClaimRelation, AuthCapsulePostClaims,
    AuthCapsuleTerminalOperandClaims, ZkAuthCapsuleBankView, ZkAuthCapsuleError,
    ZkAuthCapsuleStateTable, ZK_AUTH_CAPSULE_BANK_VARS, ZK_AUTH_CAPSULE_LIBRA_MASK_LEN,
    ZK_AUTH_CAPSULE_PCS_COINS_LEN, ZK_AUTH_CAPSULE_STATE_LEN,
    ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS,
};
use crate::zk_auth_hiding::{
    certify_zk_auth_conditioned_companion_hyperplane, certify_zk_auth_joint_hiding_rank,
    ZkAuthConditionedCompanionHyperplaneCertificate, ZkAuthHidingRankError,
    ZkAuthJointHidingRankCertificate,
};
use crate::zk_mlecheck::{
    combine_main_and_mask_round, mlecheck_endpoint_claim, ZkMleCheckError, ZkMleCheckRoundProof,
    ZkMleCheckVerifierState, ZK_MLECHECK_N_VARS, ZK_MLECHECK_ROUND_PROOF_COEFFS,
};
use noid_core::mle::evaluate::evaluate_slice;
use noid_core::sumcheck::RoundPolynomial;
use noid_core::{Block128, Block256, TowerField};
use noid_fri_binius::capsule::capsule_query_bit_location;
use noid_fri_binius::zk_affine_code::AFFINE_CODE_LOG_RATE;
use noid_fri_binius::zk_capsule::ZK_AUTH_CAPSULE_GEOMETRY;
use noid_fri_binius::zk_capsule_algebra::{
    evaluate_upper_at_low8, tail16_local_fold, FINAL_H_SYMBOLS, MID_STANDARD_FOLDS,
    PHASE_B_HIGH_VARS, PHASE_B_LOW_VARS, SOURCE_QUERY_BITS, SOURCE_STANDARD_FOLDS, TAIL_SYMBOLS,
    UPPER_SYMBOLS,
};
use noid_fri_binius::zk_capsule_pcs::{
    zk_capsule_pcs_bind_owner, zk_capsule_pcs_bind_phase_a, zk_capsule_pcs_commit_fresh,
    zk_capsule_pcs_commit_mid, zk_capsule_pcs_link_phase_b, zk_capsule_pcs_open,
    zk_capsule_pcs_prove_phase_a, zk_capsule_pcs_reveal_tail, zk_capsule_pcs_verify,
    ZkCapsulePcsError, ZkCapsulePcsMidCommitment, ZkCapsulePcsOpening,
    ZkCapsulePcsSourceCommitment, ZkCapsulePcsTailReveal, ZK_CAPSULE_PCS_MID_COMMITMENT_BYTES,
    ZK_CAPSULE_PCS_MID_SYMBOLS, ZK_CAPSULE_PCS_QUERY_COUNT, ZK_CAPSULE_PCS_SOURCE_COMMITMENT_BYTES,
    ZK_CAPSULE_PCS_SOURCE_SYMBOLS, ZK_CAPSULE_PCS_TAIL_BYTES, ZK_CAPSULE_PCS_WORST_MID_SIBLINGS,
    ZK_CAPSULE_PCS_WORST_OPENING_BYTES, ZK_CAPSULE_PCS_WORST_SOURCE_SIBLINGS,
    ZK_CAPSULE_PCS_WORST_TOTAL_BYTES,
};
use noid_fri_binius::zk_phase_a::{
    verify_phase_a, ZkPhaseAError, ZkPhaseAProof, ZkPhaseARelationClaims,
    PHASE_A_SERIALIZED_FIELDS_PER_ROUND, PHASE_A_VARS,
};
use noid_poseidon2b::channel::Poseidon2bWideChannel;
use rand_core::{CryptoRng, OsRng, RngCore};
use rayon::prelude::*;
use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub const ZK_AUTH_OWNER_PROTOCOL_TAG: u128 = 0x5A4B_A017_0000_0001;
pub const ZK_AUTH_OWNER_TO_MAIN_CLOSE_TAG: u128 = 0x5A4B_BA1D_0000_0001;
pub const ZK_AUTH_MAIN_FROM_OWNER_TAG: u128 = 0x5A4B_AA10_0000_0001;
pub const ZK_AUTH_PHASE_B_TAG: u128 = 0x5A4B_BA5E_0000_0001;
pub const ZK_AUTH_MID_CAP_TAG: u128 = 0x5A4B_A1DC_0000_0001;
pub const ZK_AUTH_TAIL_TAG: u128 = 0x5A4B_7A11_0000_0001;
pub const ZK_AUTH_GRIND_TAG: u128 = 0x5A4B_6A1D_0000_0001;

/// Construction identity of the selected authorization transcript.
pub const ZK_AUTH_OWNER_CONSTRUCTION_VERSION: u128 = 4;

pub const ZK_AUTH_OWNER_DYNAMIC_LANES: usize = 254;
pub const ZK_AUTH_OWNER_CONSTANT_LANES: usize = 11;
pub const ZK_AUTH_OWNER_SQUEEZES: usize = 24;
pub const ZK_AUTH_OWNER_RAW_CHALLENGE_LANES: usize = 2 * ZK_AUTH_OWNER_SQUEEZES;
pub const ZK_AUTH_OWNER_COMPILED_SLOTS: usize = 157;
pub const ZK_AUTH_OWNER_BRIDGE_SLOT: usize = ZK_AUTH_OWNER_COMPILED_SLOTS - 1;

pub const ZK_AUTH_MAIN_DYNAMIC_LANES: usize = 613;
pub const ZK_AUTH_MAIN_CONSTANT_LANES: usize = 5;
pub const ZK_AUTH_MAIN_SQUEEZES: usize = 28;
pub const ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES: usize = 1 + PHASE_A_VARS + PHASE_B_LOW_VARS;
pub const ZK_AUTH_MAIN_RAW_CHALLENGE_LANES: usize =
    2 * ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES + (ZK_AUTH_MAIN_SQUEEZES - ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES);
pub const ZK_AUTH_MAIN_COMPILED_SLOTS: usize = 335;

pub const ZK_AUTH_REJECTED_SINGLE_CHANNEL_SLOTS: usize = 489;
pub const ZK_AUTH_OWNER_TILE_LOG: usize = 7;
pub const ZK_AUTH_MAIN_TILE_LOG: usize = 8;

pub const ZK_AUTH_BRIDGE_LANES: usize = 4;
pub const ZK_AUTH_SOURCE_CAP_HASHES: usize = 8;
pub const ZK_AUTH_SOURCE_CAP_LANES: usize = 2 * ZK_AUTH_SOURCE_CAP_HASHES;
pub const ZK_AUTH_MLECHECK_VARS: usize = 11;
pub const ZK_AUTH_MLECHECK_ROUND_FIELDS: usize = 10;
pub const ZK_AUTH_TERMINAL_FIELDS: usize = 6;
pub const ZK_AUTH_PHASE_A_ROUND_FIELDS: usize = 2;
pub const ZK_AUTH_UPPER_FIELDS: usize = 256;
pub const ZK_AUTH_BETA_FIELDS: usize = 8;
pub const ZK_AUTH_MID_CAP_LANES: usize = 16;
pub const ZK_AUTH_TAIL_FIELDS: usize = 16;
pub const ZK_AUTH_QUERY_SEEDS: usize = 7;

/// Selected authorization query count.  This lifetime parameter is fixed by
/// the current protocol version and remains independent of debug assertions.
pub const ZK_AUTH_QUERY_COUNT: usize = ZK_CAPSULE_PCS_QUERY_COUNT;
pub const ZK_AUTH_QUERY_WIDTH_BITS: usize = SOURCE_QUERY_BITS;
pub const ZK_AUTH_GRIND_BITS: u32 = 16;

pub const ZK_AUTH_PHASE_A_PROOF_BYTES: usize =
    PHASE_A_VARS * PHASE_A_SERIALIZED_FIELDS_PER_ROUND * 32;
pub const ZK_AUTH_UPPER_BYTES: usize = UPPER_SYMBOLS * 32;
pub const ZK_AUTH_SIGMA_BYTES: usize = 32;
pub const ZK_AUTH_PHASE_B_VALUE_BYTES: usize = 32;
pub const ZK_AUTH_GRIND_NONCE_BYTES: usize = 8;
pub const ZK_AUTH_FIXED_NON_PCS_PROOF_BYTES: usize = ZK_AUTH_OWNER_PROOF_BYTES
    + ZK_AUTH_SIGMA_BYTES
    + ZK_AUTH_PHASE_A_PROOF_BYTES
    + ZK_AUTH_PHASE_B_VALUE_BYTES
    + ZK_AUTH_UPPER_BYTES
    + ZK_AUTH_GRIND_NONCE_BYTES;
/// Exact content-byte ceiling at worst canonical multiproof sibling counts.
pub const ZK_AUTHORIZATION_WORST_MODELED_BYTES: usize =
    ZK_CAPSULE_PCS_WORST_TOTAL_BYTES + ZK_AUTH_FIXED_NON_PCS_PROOF_BYTES;
/// Bincode adds one `u64` length to each of the six bounded PCS vectors.
pub const ZK_AUTHORIZATION_BINCODE_LENGTH_OVERHEAD: usize = 6 * 8;
pub const ZK_AUTHORIZATION_WORST_SERIALIZED_BYTES: usize =
    ZK_AUTHORIZATION_WORST_MODELED_BYTES + ZK_AUTHORIZATION_BINCODE_LENGTH_OVERHEAD;
/// Conservative fixed decoder roofline for the selected C1 Wallet proof.
pub const ZK_AUTHORIZATION_PAYLOAD_ROOFLINE_BYTES: usize = 96 * 1_024;

// Main dynamic-data indices. Bridge cells are derived from Owner C0..C3 and
// are not proof payload; every subsequent index is proof-carried.
pub const ZK_AUTH_MAIN_BRIDGE_DATA_START: usize = 0;
pub const ZK_AUTH_MAIN_SIGMA_DATA_INDEX: usize = 4;
pub const ZK_AUTH_MAIN_PHASE_A_DATA_START: usize = 6;
pub const ZK_AUTH_MAIN_PHASE_B_VALUE_DATA_INDEX: usize = 50;
pub const ZK_AUTH_MAIN_UPPER_DATA_START: usize = 52;
pub const ZK_AUTH_MAIN_MID_CAP_DATA_START: usize = 564;
pub const ZK_AUTH_MAIN_TAIL_DATA_START: usize = 580;
pub const ZK_AUTH_MAIN_NONCE_DATA_INDEX: usize = 612;

pub const ZK_AUTH_OWNER_PUBLIC_STATEMENT_FIELDS: usize = 4;
pub const ZK_AUTH_OWNER_PROOF_ROUNDS: usize = ZK_AUTH_MLECHECK_VARS;
pub const ZK_AUTH_OWNER_PROOF_DYNAMIC_FIELDS: usize =
    1 + ZK_AUTH_OWNER_PROOF_ROUNDS * ZK_AUTH_MLECHECK_ROUND_FIELDS + ZK_AUTH_TERMINAL_FIELDS;
pub const ZK_AUTH_OWNER_PROOF_BYTES: usize = ZK_AUTH_OWNER_PROOF_DYNAMIC_FIELDS * 32;

/// Fixed prefix absorbed before the canonical public statement and source
/// cap.  Its values are derived from the selected bank/code geometry except
/// for the construction version inside this provisional tag family.
pub const ZK_AUTH_OWNER_PREFIX_CONSTANTS: [u128; 9] = [
    ZK_AUTH_OWNER_PROTOCOL_TAG,
    ZK_AUTH_OWNER_CONSTRUCTION_VERSION,
    ZK_AUTH_CAPSULE_BANK_VARS as u128,
    ZK_AUTH_CAPSULE_STATE_LEN as u128,
    ZK_AUTH_CAPSULE_PCS_COINS_LEN as u128,
    ZK_AUTH_CAPSULE_LIBRA_MASK_LEN as u128,
    AFFINE_CODE_LOG_RATE as u128,
    ZK_AUTH_CAPSULE_GEOMETRY.source_cap_depth as u128,
    ZK_AUTH_CAPSULE_GEOMETRY.query_count as u128,
];

pub const fn zk_auth_owner_prefix_constants(version: OwnerAuthorizationVersion) -> [u128; 9] {
    let mut values = ZK_AUTH_OWNER_PREFIX_CONSTANTS;
    values[1] = version.construction_version();
    values[5] = AuthorizationLayout::for_version(version).libra_len as u128;
    values
}

const _: () = assert!(ZK_AUTH_MLECHECK_VARS == ZK_MLECHECK_N_VARS);
const _: () = assert!(ZK_AUTH_MLECHECK_ROUND_FIELDS == ZK_MLECHECK_ROUND_PROOF_COEFFS);
const _: () = assert!(ZK_AUTH_OWNER_PROOF_DYNAMIC_FIELDS == 117);
const _: () = assert!(ZK_AUTH_OWNER_PROOF_BYTES == 3_744);
const _: () = assert!(
    ZK_AUTH_OWNER_PUBLIC_STATEMENT_FIELDS
        + ZK_AUTH_SOURCE_CAP_LANES
        + 2 * ZK_AUTH_OWNER_PROOF_DYNAMIC_FIELDS
        == ZK_AUTH_OWNER_DYNAMIC_LANES
);
const _: () = assert!(ZK_AUTH_OWNER_SQUEEZES == 24);
const _: () = assert!(ZK_AUTH_OWNER_RAW_CHALLENGE_LANES == 48);
const _: () = assert!(ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES == 20);
const _: () = assert!(ZK_AUTH_MAIN_RAW_CHALLENGE_LANES == 48);
const _: () = assert!(ZK_AUTH_UPPER_FIELDS == 1 << 8);
const _: () = assert!(ZK_AUTH_QUERY_SEEDS * 128 >= 65 * 13);
const _: () = assert!(1 << ZK_AUTH_OWNER_TILE_LOG == 128);
const _: () = assert!(1 << ZK_AUTH_MAIN_TILE_LOG == 256);
const _: () = assert!(ZK_AUTH_QUERY_COUNT == 65);
const _: () = assert!(ZK_AUTH_QUERY_WIDTH_BITS == 13);
const _: () = assert!(ZK_AUTH_QUERY_SEEDS * 128 >= ZK_AUTH_QUERY_COUNT * ZK_AUTH_QUERY_WIDTH_BITS);
const _: () = assert!(ZK_AUTH_PHASE_A_PROOF_BYTES == 704);
const _: () = assert!(ZK_AUTH_UPPER_BYTES == 8_192);
const _: () = assert!(ZK_AUTH_FIXED_NON_PCS_PROOF_BYTES == 12_712);
const _: () = assert!(
    ZK_CAPSULE_PCS_SOURCE_COMMITMENT_BYTES
        + ZK_CAPSULE_PCS_MID_COMMITMENT_BYTES
        + ZK_CAPSULE_PCS_TAIL_BYTES
        + ZK_CAPSULE_PCS_WORST_OPENING_BYTES
        == ZK_CAPSULE_PCS_WORST_TOTAL_BYTES
);
const _: () = assert!(ZK_AUTHORIZATION_WORST_MODELED_BYTES == 92_648);
const _: () = assert!(ZK_AUTHORIZATION_WORST_SERIALIZED_BYTES == 92_696);
const _: () =
    assert!(ZK_AUTHORIZATION_WORST_SERIALIZED_BYTES <= ZK_AUTHORIZATION_PAYLOAD_ROOFLINE_BYTES);

/// The affine blend is `(1-gamma)B + gamma C`. Both endpoints erase one of
/// the two required oracles and are rejected before Phase A.
pub fn affine_blend_gamma_is_admissible(gamma: Block256) -> bool {
    gamma != Block256::ZERO && gamma != Block256::ONE && !gamma.is_in_base_subfield()
}

/// Canonical Owner public statement.  Body-hash lanes bind the
/// noninteractive proof to this transaction; address lanes additionally
/// enter the sparse bank boundary relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ZkAuthCapsuleOwnerStatement {
    pub tx_body_hash: [Block128; 2],
    pub address: [Block128; 2],
}

impl ZkAuthCapsuleOwnerStatement {
    pub const fn flattened(self) -> [Block128; ZK_AUTH_OWNER_PUBLIC_STATEMENT_FIELDS] {
        [
            self.tx_body_hash[0],
            self.tx_body_hash[1],
            self.address[0],
            self.address[1],
        ]
    }

    pub fn boundary(self) -> AuthCapsuleBoundaryPublic {
        AuthCapsuleBoundaryPublic::canonical(self.address)
    }
}

/// Serialized Owner proof payload.  Public statement/source-cap lanes are
/// supplied to verification separately and are not duplicated here.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ZkAuthCapsuleOwnerProof {
    pub mask_mu: Block256,
    pub rounds: [ZkMleCheckRoundProof<Block256>; ZK_AUTH_OWNER_PROOF_ROUNDS],
    /// `g(r)` in the schedule's terminal absorb.
    pub mask_final: Block256,
    /// Five ZK-padded operand evaluations in increment-then-lane order.
    pub terminal_operand_claims: [Block256; ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS],
}

impl ZkAuthCapsuleOwnerProof {
    /// Prover-owned dynamic absorbs in exact Owner schedule order.
    pub fn absorbed_values(&self) -> Vec<Block256> {
        let mut values = Vec::with_capacity(ZK_AUTH_OWNER_PROOF_DYNAMIC_FIELDS);
        values.push(self.mask_mu);
        for round in &self.rounds {
            values.extend_from_slice(&round.coeffs_without_constant);
        }
        values.push(self.mask_final);
        values.extend_from_slice(&self.terminal_operand_claims);
        debug_assert_eq!(values.len(), ZK_AUTH_OWNER_PROOF_DYNAMIC_FIELDS);
        values
    }

    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("fixed Owner proof length fits u64") as usize
    }

    fn terminal_operands(&self) -> AuthCapsuleTerminalOperandClaims<Block256> {
        AuthCapsuleTerminalOperandClaims {
            increment: self.terminal_operand_claims[0],
            lane: std::array::from_fn(|lane| self.terminal_operand_claims[1 + lane]),
        }
    }
}

/// Every value replayed or derived by successful Owner verification and
/// needed by the later Main/PCS side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAuthCapsuleOwnerDerived {
    pub version: OwnerAuthorizationVersion,
    pub rho: [Block256; ZK_AUTH_MLECHECK_VARS],
    pub lambda: Block256,
    pub round_challenges_high_to_low: [Block256; ZK_AUTH_MLECHECK_VARS],
    pub terminal_point: [Block256; ZK_AUTH_MLECHECK_VARS],
    pub terminal_operands: AuthCapsuleTerminalOperandClaims<Block256>,
    pub mask_mu: Block256,
    pub mask_final: Block256,
    pub main_final: Block256,
    pub eta: Block256,
    /// The transparent relation `t`; its expected inner product is Phase A's
    /// bank claim and its weights are committed/opened by Main/PCS.
    pub post_claim_relation: AuthCapsulePostClaimRelation<Block256>,
    pub bridge: [Block128; 4],
}

impl ZkAuthCapsuleOwnerDerived {
    /// All Owner squeezes in exact compiled-layout order.
    pub fn transcript_challenges(&self) -> [Block256; ZK_AUTH_OWNER_SQUEEZES] {
        let mut challenges = [Block256::ZERO; ZK_AUTH_OWNER_SQUEEZES];
        challenges[..ZK_AUTH_MLECHECK_VARS].copy_from_slice(&self.rho);
        challenges[ZK_AUTH_MLECHECK_VARS] = self.lambda;
        let rounds_start = ZK_AUTH_MLECHECK_VARS + 1;
        challenges[rounds_start..rounds_start + ZK_AUTH_MLECHECK_VARS]
            .copy_from_slice(&self.round_challenges_high_to_low);
        challenges[ZK_AUTH_OWNER_SQUEEZES - 1] = self.eta;
        challenges
    }

    pub const fn bank_claim(&self) -> Block256 {
        self.post_claim_relation.expected_inner_product
    }

    pub const fn post_claims(&self) -> AuthCapsulePostClaims<Block256> {
        AuthCapsulePostClaims {
            terminal_operands: self.terminal_operands,
            mask_mle_at_input: self.mask_mu,
            mask_final_at_terminal: self.mask_final,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAuthCapsuleOwnerProverOutput {
    pub proof: ZkAuthCapsuleOwnerProof,
    pub derived: ZkAuthCapsuleOwnerDerived,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthCapsuleOwnerError {
    AuthCapsule(ZkAuthCapsuleError),
    LambdaZero,
    EtaZero,
    PostClaimRelationMismatch,
}

impl From<ZkAuthCapsuleError> for ZkAuthCapsuleOwnerError {
    fn from(value: ZkAuthCapsuleError) -> Self {
        Self::AuthCapsule(value)
    }
}

impl From<ZkMleCheckError> for ZkAuthCapsuleOwnerError {
    fn from(value: ZkMleCheckError) -> Self {
        Self::AuthCapsule(ZkAuthCapsuleError::ZkMleCheck(value))
    }
}

#[cfg(test)]
pub(crate) fn absorb_owner_prefix(
    channel: &mut Poseidon2bWideChannel,
    statement: ZkAuthCapsuleOwnerStatement,
    source_cap: &[Block128; ZK_AUTH_SOURCE_CAP_LANES],
) {
    absorb_owner_prefix_for_version(
        channel,
        statement,
        source_cap,
        OwnerAuthorizationVersion::V4,
    );
}

fn absorb_owner_prefix_for_version(
    channel: &mut Poseidon2bWideChannel,
    statement: ZkAuthCapsuleOwnerStatement,
    source_cap: &[Block128; ZK_AUTH_SOURCE_CAP_LANES],
    version: OwnerAuthorizationVersion,
) {
    for &constant in &zk_auth_owner_prefix_constants(version) {
        channel.absorb_base(Block128::from(constant));
    }
    for value in statement.flattened() {
        channel.absorb_base(value);
    }
    for &value in source_cap {
        channel.absorb_base(value);
    }
}

pub(crate) fn squeeze_wide_array<const N: usize>(
    channel: &mut Poseidon2bWideChannel,
) -> [Block256; N] {
    std::array::from_fn(|_| channel.squeeze_wide())
}

pub(crate) fn absorb_round(
    channel: &mut Poseidon2bWideChannel,
    round: &ZkMleCheckRoundProof<Block256>,
) {
    for &coefficient in &round.coeffs_without_constant {
        channel.absorb_wide(coefficient);
    }
}

pub(crate) fn absorb_terminal(
    channel: &mut Poseidon2bWideChannel,
    mask_final: Block256,
    terminal_operand_claims: &[Block256; ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS],
) {
    channel.absorb_wide(mask_final);
    for &claim in terminal_operand_claims {
        channel.absorb_wide(claim);
    }
}

fn require_lambda_nonzero(lambda: Block256) -> Result<(), ZkAuthCapsuleOwnerError> {
    if lambda == Block256::ZERO {
        Err(ZkAuthCapsuleOwnerError::LambdaZero)
    } else {
        Ok(())
    }
}

fn require_eta_nonzero(eta: Block256) -> Result<(), ZkAuthCapsuleOwnerError> {
    if eta == Block256::ZERO {
        Err(ZkAuthCapsuleOwnerError::EtaZero)
    } else {
        Ok(())
    }
}

fn endpoint_matches(
    round: &RoundPolynomial<Block256>,
    input_coordinate: Block256,
    running_claim: Block256,
) -> bool {
    mlecheck_endpoint_claim(&round.coeffs, input_coordinate) == running_claim
}

/// Full Owner dynamic-data stream in the exact order consumed by the
/// compiled duplex layout.  This is an adapter helper, not an alternative
/// serialization format.
pub fn zk_auth_capsule_owner_dynamic_data(
    statement: ZkAuthCapsuleOwnerStatement,
    source_cap: &[Block128; ZK_AUTH_SOURCE_CAP_LANES],
    proof: &ZkAuthCapsuleOwnerProof,
) -> Vec<Block128> {
    let mut values = Vec::with_capacity(ZK_AUTH_OWNER_DYNAMIC_LANES);
    values.extend_from_slice(&statement.flattened());
    values.extend_from_slice(source_cap);
    for value in proof.absorbed_values() {
        values.push(value.lo);
        values.push(value.hi);
    }
    debug_assert_eq!(values.len(), ZK_AUTH_OWNER_DYNAMIC_LANES);
    values
}

/// Deterministically construct the selected Owner proof from a caller-owned
/// fresh bank.  No bank cell or proof randomness is generated here.
pub(crate) fn prove_zk_auth_capsule_owner(
    bank: ZkAuthCapsuleBankView<'_>,
    statement: ZkAuthCapsuleOwnerStatement,
    source_cap: &[Block128; ZK_AUTH_SOURCE_CAP_LANES],
) -> Result<ZkAuthCapsuleOwnerProverOutput, ZkAuthCapsuleOwnerError> {
    // Exact native preflight prevents an honest caller from spending work on
    // a known-invalid bank.  Verification below still follows the actual
    // MLE-check and post-claim argument rather than trusting this preflight.
    validate_auth_main_relation(bank)?;
    validate_sparse_boundary(bank, statement.boundary())?;

    let mask = bank.libra_mask_view()?;
    let mut channel = Poseidon2bWideChannel::new();
    absorb_owner_prefix_for_version(&mut channel, statement, source_cap, bank.version());
    let rho = squeeze_wide_array::<ZK_AUTH_MLECHECK_VARS>(&mut channel);

    let mask_mu = mask.evaluate_mle(&rho);
    channel.absorb_wide(mask_mu);
    let lambda = channel.squeeze_wide();
    require_lambda_nonzero(lambda)?;

    let mut prior_challenges = Vec::with_capacity(ZK_AUTH_MLECHECK_VARS);
    let mut round_proofs = Vec::with_capacity(ZK_AUTH_OWNER_PROOF_ROUNDS);
    let mut main_running_claim = Block256::ZERO;
    for round_index in 0..ZK_AUTH_OWNER_PROOF_ROUNDS {
        let variable = ZK_AUTH_MLECHECK_VARS - 1 - round_index;
        let main_round = auth_main_round_polynomial(bank, &rho, &prior_challenges)?;
        if !endpoint_matches(&main_round, rho[variable], main_running_claim) {
            return Err(
                ZkAuthCapsuleError::MainRoundEndpointMismatch { round: round_index }.into(),
            );
        }
        let mask_round = mask.round_coefficients(&rho, &prior_challenges)?;
        let combined = combine_main_and_mask_round(&main_round, &mask_round, lambda)?;
        let round_proof = ZkMleCheckRoundProof::truncate(&combined)?;
        absorb_round(&mut channel, &round_proof);
        let challenge = channel.squeeze_wide();
        main_running_claim = main_round.evaluate(challenge);
        prior_challenges.push(challenge);
        round_proofs.push(round_proof);
    }

    let round_challenges_high_to_low: [Block256; ZK_AUTH_MLECHECK_VARS] = prior_challenges
        .try_into()
        .unwrap_or_else(|_| unreachable!("exactly eleven adaptive Owner rounds"));
    let terminal_point = std::array::from_fn(|variable| {
        round_challenges_high_to_low[ZK_AUTH_MLECHECK_VARS - 1 - variable]
    });
    crate::zk_auth_capsule::certify_terminal_blinding_rank_for_version(
        &terminal_point,
        bank.version(),
    )?;
    let terminal_operands = compute_terminal_operand_claims(bank, &terminal_point);
    let main_final = evaluate_auth_main_terminal_from_claims(&terminal_point, terminal_operands)?;
    if main_running_claim != main_final {
        return Err(ZkAuthCapsuleError::MainTerminalMismatch.into());
    }
    let mask_final = mask.evaluate_final(&terminal_point);
    let terminal_operand_claims = terminal_operands.ordered();
    absorb_terminal(&mut channel, mask_final, &terminal_operand_claims);
    let eta = channel.squeeze_wide();
    require_eta_nonzero(eta)?;

    let post_claims = AuthCapsulePostClaims {
        terminal_operands,
        mask_mle_at_input: mask_mu,
        mask_final_at_terminal: mask_final,
    };
    let post_claim_relation = crate::zk_auth_capsule::build_post_claim_relation_for_version(
        &rho,
        &terminal_point,
        statement.boundary(),
        post_claims,
        eta,
        bank.version(),
    )?;
    if !post_claim_relation.verify(bank) {
        return Err(ZkAuthCapsuleOwnerError::PostClaimRelationMismatch);
    }
    let bridge = channel.close_into_bridge(Block128::from(ZK_AUTH_OWNER_TO_MAIN_CLOSE_TAG));

    let proof = ZkAuthCapsuleOwnerProof {
        mask_mu,
        rounds: round_proofs
            .try_into()
            .unwrap_or_else(|_| unreachable!("exactly eleven Owner round proofs")),
        mask_final,
        terminal_operand_claims,
    };
    let derived = ZkAuthCapsuleOwnerDerived {
        version: bank.version(),
        rho,
        lambda,
        round_challenges_high_to_low,
        terminal_point,
        terminal_operands,
        mask_mu,
        mask_final,
        main_final,
        eta,
        post_claim_relation,
        bridge,
    };

    // Keep prover and transcript-only verifier implementations locked
    // together.  The relation was checked against the prover bank above;
    // verification itself never needs that witness.
    let replayed =
        verify_zk_auth_capsule_owner_for_version(statement, source_cap, &proof, bank.version())?;
    debug_assert_eq!(replayed, derived);
    Ok(ZkAuthCapsuleOwnerProverOutput { proof, derived })
}

/// Replay the selected Owner transcript and verify its MLE-check reduction,
/// returning the transparent claim which Main/PCS must discharge.
///
/// Neither challenges, terminal point, bank claim, nor bridge are accepted
/// from the proof payload.  This verifier intentionally has no bank argument
/// and does not call [`AuthCapsulePostClaimRelation::verify`].  Acceptance is
/// complete only after Main/PCS proves the returned relation against the
/// committed bank.
pub fn verify_zk_auth_capsule_owner(
    statement: ZkAuthCapsuleOwnerStatement,
    source_cap: &[Block128; ZK_AUTH_SOURCE_CAP_LANES],
    proof: &ZkAuthCapsuleOwnerProof,
) -> Result<ZkAuthCapsuleOwnerDerived, ZkAuthCapsuleOwnerError> {
    verify_zk_auth_capsule_owner_for_version(
        statement,
        source_cap,
        proof,
        OwnerAuthorizationVersion::V4,
    )
}

pub fn verify_zk_auth_capsule_owner_for_version(
    statement: ZkAuthCapsuleOwnerStatement,
    source_cap: &[Block128; ZK_AUTH_SOURCE_CAP_LANES],
    proof: &ZkAuthCapsuleOwnerProof,
    version: OwnerAuthorizationVersion,
) -> Result<ZkAuthCapsuleOwnerDerived, ZkAuthCapsuleOwnerError> {
    let mut channel = Poseidon2bWideChannel::new();
    absorb_owner_prefix_for_version(&mut channel, statement, source_cap, version);
    let rho = squeeze_wide_array::<ZK_AUTH_MLECHECK_VARS>(&mut channel);

    channel.absorb_wide(proof.mask_mu);
    let lambda = channel.squeeze_wide();
    require_lambda_nonzero(lambda)?;
    let mut verifier = ZkMleCheckVerifierState::new(rho, Block256::ZERO, proof.mask_mu, lambda);
    let mut round_challenges_high_to_low = [Block256::ZERO; ZK_AUTH_MLECHECK_VARS];
    for (round_index, round) in proof.rounds.iter().enumerate() {
        absorb_round(&mut channel, round);
        let challenge = channel.squeeze_wide();
        round_challenges_high_to_low[round_index] = challenge;
        verifier.transition(round, challenge)?;
    }

    let terminal_point = std::array::from_fn(|variable| {
        round_challenges_high_to_low[ZK_AUTH_MLECHECK_VARS - 1 - variable]
    });
    crate::zk_auth_capsule::certify_terminal_blinding_rank_for_version(&terminal_point, version)?;
    let terminal_operands = proof.terminal_operands();
    let main_final = evaluate_auth_main_terminal_from_claims(&terminal_point, terminal_operands)?;
    verifier.finish_checked(proof.mask_final, main_final)?;

    absorb_terminal(
        &mut channel,
        proof.mask_final,
        &proof.terminal_operand_claims,
    );
    let eta = channel.squeeze_wide();
    require_eta_nonzero(eta)?;

    let post_claims = AuthCapsulePostClaims {
        terminal_operands,
        mask_mle_at_input: proof.mask_mu,
        mask_final_at_terminal: proof.mask_final,
    };
    let post_claim_relation = crate::zk_auth_capsule::build_post_claim_relation_for_version(
        &rho,
        &terminal_point,
        statement.boundary(),
        post_claims,
        eta,
        version,
    )?;
    let bridge = channel.close_into_bridge(Block128::from(ZK_AUTH_OWNER_TO_MAIN_CLOSE_TAG));

    Ok(ZkAuthCapsuleOwnerDerived {
        version,
        rho,
        lambda,
        round_challenges_high_to_low,
        terminal_point,
        terminal_operands,
        mask_mu: proof.mask_mu,
        mask_final: proof.mask_final,
        main_final,
        eta,
        post_claim_relation,
        bridge,
    })
}

/// Optional native differential helper which additionally evaluates the
/// transcript-derived post-claim relation on a supplied bank.  Production
/// verification uses Main/PCS instead of receiving this private witness.
pub fn verify_zk_auth_capsule_owner_witness_reference(
    bank: ZkAuthCapsuleBankView<'_>,
    statement: ZkAuthCapsuleOwnerStatement,
    source_cap: &[Block128; ZK_AUTH_SOURCE_CAP_LANES],
    proof: &ZkAuthCapsuleOwnerProof,
) -> Result<ZkAuthCapsuleOwnerDerived, ZkAuthCapsuleOwnerError> {
    let derived =
        verify_zk_auth_capsule_owner_for_version(statement, source_cap, proof, bank.version())?;
    if !derived.post_claim_relation.verify(bank) {
        return Err(ZkAuthCapsuleOwnerError::PostClaimRelationMismatch);
    }
    Ok(derived)
}

/// Strict fixed-width carrier for the public Phase-B contraction table.
///
/// The custom tuple serialization has no attacker-controlled length prefix:
/// decoding reads exactly 256 field elements or fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAuthorizationUpper([Block256; UPPER_SYMBOLS]);

impl ZkAuthorizationUpper {
    pub const fn new(values: [Block256; UPPER_SYMBOLS]) -> Self {
        Self(values)
    }

    pub const fn as_array(&self) -> &[Block256; UPPER_SYMBOLS] {
        &self.0
    }

    pub const fn into_array(self) -> [Block256; UPPER_SYMBOLS] {
        self.0
    }
}

impl Serialize for ZkAuthorizationUpper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(UPPER_SYMBOLS)?;
        for value in &self.0 {
            tuple.serialize_element(value)?;
        }
        tuple.end()
    }
}

struct ZkAuthorizationUpperVisitor;

impl<'de> Visitor<'de> for ZkAuthorizationUpperVisitor {
    type Value = ZkAuthorizationUpper;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "exactly {UPPER_SYMBOLS} authorization upper fields"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = [Block256::ZERO; UPPER_SYMBOLS];
        for (index, value) in values.iter_mut().enumerate() {
            *value = sequence
                .next_element()?
                .ok_or_else(|| A::Error::invalid_length(index, &self))?;
        }
        Ok(ZkAuthorizationUpper(values))
    }
}

impl<'de> Deserialize<'de> for ZkAuthorizationUpper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_tuple(UPPER_SYMBOLS, ZkAuthorizationUpperVisitor)
    }
}

/// Complete selected authorization proof.  Transcript challenges, bridge,
/// query seeds, and derived queries are deliberately absent from the wire.
///
/// Raw serde deserialization is intentionally unavailable: network-facing
/// code must enter through the allocation-bounded
/// [`ZkAuthorizationProof::from_bytes`] scanner.
///
/// ```compile_fail
/// use noid_gkr::zk_authorization::ZkAuthorizationProof;
///
/// fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// require_deserialize::<ZkAuthorizationProof>();
/// ```
#[derive(Clone, Debug, Serialize)]
pub struct ZkAuthorizationProof {
    pub source_commitment: ZkCapsulePcsSourceCommitment,
    pub owner: ZkAuthCapsuleOwnerProof,
    pub sigma: Block256,
    pub phase_a: ZkPhaseAProof<Block256>,
    pub phase_b_value: Block256,
    pub upper: ZkAuthorizationUpper,
    pub mid_commitment: ZkCapsulePcsMidCommitment,
    pub tail: ZkCapsulePcsTailReveal,
    pub grind_nonce: u64,
    pub opening: ZkCapsulePcsOpening,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthorizationProofComponent {
    SourceCap,
    MidCap,
    SourceSymbols,
    MidSymbols,
    SourceSiblings,
    MidSiblings,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkAuthorizationError {
    ProofShape {
        component: ZkAuthorizationProofComponent,
        expected: usize,
        actual: usize,
        is_maximum: bool,
    },
    Owner(ZkAuthCapsuleOwnerError),
    Pcs(ZkCapsulePcsError),
    PhaseA(ZkPhaseAError),
    Hiding(ZkAuthHidingRankError),
    GammaEndpoint,
    PhaseABindingMismatch,
    PhaseBTerminalValueMismatch,
    PhaseBUpperTailMismatch,
    GrindRejected,
    GrindExhausted,
}

impl From<ZkAuthCapsuleOwnerError> for ZkAuthorizationError {
    fn from(value: ZkAuthCapsuleOwnerError) -> Self {
        Self::Owner(value)
    }
}

impl From<ZkCapsulePcsError> for ZkAuthorizationError {
    fn from(value: ZkCapsulePcsError) -> Self {
        Self::Pcs(value)
    }
}

impl From<ZkPhaseAError> for ZkAuthorizationError {
    fn from(value: ZkPhaseAError) -> Self {
        Self::PhaseA(value)
    }
}

impl From<ZkAuthHidingRankError> for ZkAuthorizationError {
    fn from(value: ZkAuthHidingRankError) -> Self {
        Self::Hiding(value)
    }
}

impl ZkAuthorizationProof {
    /// Reject every variable-length component after object decoding and
    /// before transcript replay, affine encoding, or Merkle verification.
    pub fn preflight_shape(&self) -> Result<(), ZkAuthorizationError> {
        fn exact(
            component: ZkAuthorizationProofComponent,
            expected: usize,
            actual: usize,
        ) -> Result<(), ZkAuthorizationError> {
            if actual == expected {
                Ok(())
            } else {
                Err(ZkAuthorizationError::ProofShape {
                    component,
                    expected,
                    actual,
                    is_maximum: false,
                })
            }
        }

        fn at_most(
            component: ZkAuthorizationProofComponent,
            maximum: usize,
            actual: usize,
        ) -> Result<(), ZkAuthorizationError> {
            if actual <= maximum {
                Ok(())
            } else {
                Err(ZkAuthorizationError::ProofShape {
                    component,
                    expected: maximum,
                    actual,
                    is_maximum: true,
                })
            }
        }

        exact(
            ZkAuthorizationProofComponent::SourceCap,
            ZK_CAPSULE_PCS_SOURCE_COMMITMENT_BYTES / 32,
            self.source_commitment.cap.hashes.len(),
        )?;
        exact(
            ZkAuthorizationProofComponent::MidCap,
            ZK_CAPSULE_PCS_MID_COMMITMENT_BYTES / 32,
            self.mid_commitment.cap.hashes.len(),
        )?;
        exact(
            ZkAuthorizationProofComponent::SourceSymbols,
            ZK_CAPSULE_PCS_SOURCE_SYMBOLS,
            self.opening.source_joint_symbols.len(),
        )?;
        exact(
            ZkAuthorizationProofComponent::MidSymbols,
            ZK_CAPSULE_PCS_MID_SYMBOLS,
            self.opening.mid_symbols.len(),
        )?;
        at_most(
            ZkAuthorizationProofComponent::SourceSiblings,
            ZK_CAPSULE_PCS_WORST_SOURCE_SIBLINGS,
            self.opening.source_batch.siblings.len(),
        )?;
        at_most(
            ZkAuthorizationProofComponent::MidSiblings,
            ZK_CAPSULE_PCS_WORST_MID_SIBLINGS,
            self.opening.mid_batch.siblings.len(),
        )
    }

    /// Exact proof content bytes, excluding the six bincode vector lengths.
    pub fn modeled_byte_len(&self) -> usize {
        self.source_commitment.byte_len()
            + self.owner.byte_len()
            + ZK_AUTH_SIGMA_BYTES
            + ZK_AUTH_PHASE_A_PROOF_BYTES
            + ZK_AUTH_PHASE_B_VALUE_BYTES
            + ZK_AUTH_UPPER_BYTES
            + self.mid_commitment.byte_len()
            + self.tail.byte_len()
            + ZK_AUTH_GRIND_NONCE_BYTES
            + self.opening.byte_len()
    }

    pub fn serialized_byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("bounded authorization proof length fits u64")
            as usize
    }
}

/// All non-serialized values reconstructed by complete native verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAuthorizationVerified {
    pub owner: ZkAuthCapsuleOwnerDerived,
    pub gamma: Block256,
    pub phase_a_challenges_high_to_low: [Block256; PHASE_A_VARS],
    pub beta: [Block256; PHASE_B_LOW_VARS],
    pub grind: Block128,
    pub query_seeds: [Block128; ZK_AUTH_QUERY_SEEDS],
    pub queries: [usize; ZK_AUTH_QUERY_COUNT],
    pub conditioned_sigma: ZkAuthConditionedCompanionHyperplaneCertificate,
    pub hiding: Option<ZkAuthJointHidingRankCertificate>,
}

impl ZkAuthorizationVerified {
    /// All Main squeezes in exact compiled-layout order.
    pub fn main_algebraic_challenges(&self) -> [Block256; 1 + PHASE_A_VARS + PHASE_B_LOW_VARS] {
        let mut challenges = [Block256::ZERO; 1 + PHASE_A_VARS + PHASE_B_LOW_VARS];
        challenges[0] = self.gamma;
        challenges[1..1 + PHASE_A_VARS].copy_from_slice(&self.phase_a_challenges_high_to_low);
        challenges[1 + PHASE_A_VARS..].copy_from_slice(&self.beta);
        challenges
    }
}

fn require_main_gamma(gamma: Block256) -> Result<(), ZkAuthorizationError> {
    if affine_blend_gamma_is_admissible(gamma) {
        Ok(())
    } else {
        Err(ZkAuthorizationError::GammaEndpoint)
    }
}

pub(crate) fn init_main_channel(
    owner: &ZkAuthCapsuleOwnerDerived,
    sigma: Block256,
) -> Poseidon2bWideChannel {
    let mut channel = Poseidon2bWideChannel::new();
    channel.absorb_base(Block128::from(ZK_AUTH_MAIN_FROM_OWNER_TAG));
    channel.absorb_base_slice(&owner.bridge);
    channel.absorb_wide(sigma);
    channel
}

pub(crate) fn absorb_phase_a_round(
    channel: &mut Poseidon2bWideChannel,
    round: &noid_fri_binius::ZkPhaseARoundProof<Block256>,
) {
    channel.absorb_wide(round.at_one);
    channel.absorb_wide(round.at_infinity);
}

pub(crate) fn absorb_phase_b_prefix(
    channel: &mut Poseidon2bWideChannel,
    phase_b_value: Block256,
    upper: &ZkAuthorizationUpper,
) {
    channel.absorb_base(Block128::from(ZK_AUTH_PHASE_B_TAG));
    channel.absorb_wide(phase_b_value);
    for &value in upper.as_array() {
        channel.absorb_wide(value);
    }
}

pub(crate) fn absorb_mid_commitment(
    channel: &mut Poseidon2bWideChannel,
    mid: &ZkCapsulePcsMidCommitment,
) -> Result<(), ZkAuthorizationError> {
    channel.absorb_base(Block128::from(ZK_AUTH_MID_CAP_TAG));
    channel.absorb_base_slice(&mid.transcript_lanes()?);
    Ok(())
}

pub(crate) fn absorb_tail(channel: &mut Poseidon2bWideChannel, tail: &ZkCapsulePcsTailReveal) {
    channel.absorb_base(Block128::from(ZK_AUTH_TAIL_TAG));
    for &value in &tail.coefficients {
        channel.absorb_wide(value);
    }
}

pub(crate) fn verify_phase_b_upper_tail_link(
    upper: &[Block256; UPPER_SYMBOLS],
    phase_a_terminal_point: &[Block256; PHASE_A_VARS],
    phase_b_value: Block256,
    beta: &[Block256; PHASE_B_LOW_VARS],
    tail: &[Block256; TAIL_SYMBOLS],
) -> Result<(), ZkAuthorizationError> {
    if evaluate_upper_at_low8(
        upper,
        &phase_a_terminal_point[..PHASE_B_LOW_VARS]
            .try_into()
            .unwrap(),
    ) != phase_b_value
    {
        return Err(ZkAuthorizationError::PhaseBTerminalValueMismatch);
    }
    let upper_at_beta = evaluate_upper_at_low8(upper, beta);
    let h: [Block256; FINAL_H_SYMBOLS] = tail16_local_fold(tail, beta[PHASE_B_LOW_VARS - 1]);
    let high: &[Block256; PHASE_B_HIGH_VARS] = phase_a_terminal_point[PHASE_B_LOW_VARS..]
        .try_into()
        .unwrap_or_else(|_| unreachable!("11-variable point splits as 8+3"));
    if upper_at_beta != evaluate_slice(&h, high) {
        return Err(ZkAuthorizationError::PhaseBUpperTailMismatch);
    }
    Ok(())
}

#[inline]
pub const fn zk_authorization_grind_is_valid(grind: Block128) -> bool {
    grind.0 & ((1u128 << ZK_AUTH_GRIND_BITS) - 1) == 0
}

fn grind_mask(bits: u32) -> u128 {
    debug_assert!(bits > 0 && bits < 64);
    (1u128 << bits) - 1
}

fn probe_grind(channel: &Poseidon2bWideChannel, nonce: u64) -> Block128 {
    let mut probe = channel.clone();
    probe.absorb_base(Block128::from(nonce as u128));
    probe.squeeze_base()
}

fn grind_main_channel_with_bits(
    channel: &mut Poseidon2bWideChannel,
    bits: u32,
) -> Result<(u64, Block128), ZkAuthorizationError> {
    channel.absorb_base(Block128::from(ZK_AUTH_GRIND_TAG));
    let mask = grind_mask(bits);
    let block = 1u64 << (bits + 1);
    let mut start = 0u64;
    let nonce = loop {
        let end = start.saturating_add(block);
        if let Some(found) = (start..end)
            .into_par_iter()
            .find_first(|&nonce| probe_grind(channel, nonce).0 & mask == 0)
        {
            break found;
        }
        if end == u64::MAX {
            if probe_grind(channel, u64::MAX).0 & mask == 0 {
                break u64::MAX;
            }
            return Err(ZkAuthorizationError::GrindExhausted);
        }
        start = end;
    };
    let expected = probe_grind(channel, nonce);
    channel.absorb_base(Block128::from(nonce as u128));
    let grind = channel.squeeze_base();
    debug_assert_eq!(grind, expected);
    if grind.0 & mask != 0 {
        return Err(ZkAuthorizationError::GrindRejected);
    }
    Ok((nonce, grind))
}

fn replay_grind(
    channel: &mut Poseidon2bWideChannel,
    nonce: u64,
) -> Result<Block128, ZkAuthorizationError> {
    channel.absorb_base(Block128::from(ZK_AUTH_GRIND_TAG));
    channel.absorb_base(Block128::from(nonce as u128));
    let grind = channel.squeeze_base();
    if !zk_authorization_grind_is_valid(grind) {
        return Err(ZkAuthorizationError::GrindRejected);
    }
    Ok(grind)
}

/// Decode the fixed seven transcript seeds into 65 independent 13-bit query
/// indices using the protocol's LSB-first packed bit stream.
pub fn zk_authorization_queries_from_seeds(
    seeds: &[Block128; ZK_AUTH_QUERY_SEEDS],
) -> [usize; ZK_AUTH_QUERY_COUNT] {
    std::array::from_fn(|query| {
        (0..ZK_AUTH_QUERY_WIDTH_BITS).fold(0usize, |index, query_bit| {
            let (seed, bit) =
                capsule_query_bit_location(query, query_bit, ZK_AUTH_QUERY_WIDTH_BITS);
            index | ((((seeds[seed].0 >> bit) & 1) as usize) << query_bit)
        })
    })
}

/// Exact 601-lane Main dynamic stream consumed by the recursive duplex
/// columns.  Derived challenges and query seeds are not part of this adapter.
pub fn zk_authorization_main_dynamic_data(
    owner: &ZkAuthCapsuleOwnerDerived,
    proof: &ZkAuthorizationProof,
) -> Result<[Block128; ZK_AUTH_MAIN_DYNAMIC_LANES], ZkAuthorizationError> {
    proof.preflight_shape()?;
    let mut values = Vec::with_capacity(ZK_AUTH_MAIN_DYNAMIC_LANES);
    values.extend_from_slice(&owner.bridge);
    values.extend_from_slice(&[proof.sigma.lo, proof.sigma.hi]);
    for round in &proof.phase_a.rounds {
        values.extend_from_slice(&[round.at_one.lo, round.at_one.hi]);
        values.extend_from_slice(&[round.at_infinity.lo, round.at_infinity.hi]);
    }
    values.extend_from_slice(&[proof.phase_b_value.lo, proof.phase_b_value.hi]);
    for &value in proof.upper.as_array() {
        values.extend_from_slice(&[value.lo, value.hi]);
    }
    values.extend_from_slice(&proof.mid_commitment.transcript_lanes()?);
    for &value in &proof.tail.coefficients {
        values.extend_from_slice(&[value.lo, value.hi]);
    }
    values.push(Block128::from(proof.grind_nonce as u128));
    Ok(values
        .try_into()
        .unwrap_or_else(|_| unreachable!("Main dynamic stream has exact selected length")))
}

/// Construct one complete authorization proof from the exact 512-cell
/// Poseidon state table.
///
/// Every PCS transition consumes its predecessor.  In particular Owner is
/// proved inside the one-shot source-state callback; no reusable bank borrow
/// or partial Owner proof escapes if any later endpoint or link check fails.
///
/// Each invocation obtains fresh entropy directly from the operating-system
/// CSPRNG.  Authorization hiding therefore assumes that the OS CSPRNG supplies
/// independent entropy to every attempt.  If the OS entropy source fails,
/// `OsRng` fails closed by panicking rather than emitting a proof; this is an
/// availability tradeoff.  This boundary does not provide durable protection
/// against whole-system or VM rollback that also rolls back the OS RNG state.
pub(crate) fn prove_zk_authorization_from_state(
    state: &[Block128],
    statement: ZkAuthCapsuleOwnerStatement,
) -> Result<ZkAuthorizationProof, ZkAuthorizationError> {
    let mut rng = OsRng;
    prove_zk_authorization_from_state_with_rng(state, statement, &mut rng)
}

/// Construct one complete authorization proof from an opaque, zeroizing
/// address-permutation state owner.
///
/// This is the public low-level prover seam. Unlike the retired raw-slice
/// entry point, it does not let callers borrow, format, clone, serialize, or
/// persist any state cell.
pub fn prove_zk_authorization_from_state_table(
    state: &ZkAuthCapsuleStateTable,
    statement: ZkAuthCapsuleOwnerStatement,
) -> Result<ZkAuthorizationProof, ZkAuthorizationError> {
    prove_zk_authorization_from_state(state.cells(), statement)
}

pub fn prove_zk_authorization_from_state_table_for_version(
    state: &ZkAuthCapsuleStateTable,
    statement: ZkAuthCapsuleOwnerStatement,
    version: OwnerAuthorizationVersion,
) -> Result<ZkAuthorizationProof, ZkAuthorizationError> {
    let mut rng = OsRng;
    prove_zk_authorization_from_state_with_rng_for_version(
        state.cells(),
        statement,
        &mut rng,
        version,
    )
}

/// Internal deterministic seam used to exercise the entropy boundary.
///
/// Keeping this helper private prevents production callers from reusing or
/// cloning an attempt RNG and thereby reproducing the PCS hiding randomness.
fn prove_zk_authorization_from_state_with_rng(
    state: &[Block128],
    statement: ZkAuthCapsuleOwnerStatement,
    rng: &mut (impl CryptoRng + RngCore + ?Sized),
) -> Result<ZkAuthorizationProof, ZkAuthorizationError> {
    prove_zk_authorization_from_state_with_rng_for_version(
        state,
        statement,
        rng,
        OwnerAuthorizationVersion::V4,
    )
}

fn prove_zk_authorization_from_state_with_rng_for_version(
    state: &[Block128],
    statement: ZkAuthCapsuleOwnerStatement,
    rng: &mut (impl CryptoRng + RngCore + ?Sized),
    version: OwnerAuthorizationVersion,
) -> Result<ZkAuthorizationProof, ZkAuthorizationError> {
    let (source_commitment, source_state) = zk_capsule_pcs_commit_fresh(state, rng)?;
    let source_cap = source_commitment.transcript_lanes()?;
    let (owner_output, owner_bound) = zk_capsule_pcs_bind_owner(source_state, |bank| {
        let bank = ZkAuthCapsuleBankView::checked_for_version(bank, version)?;
        prove_zk_auth_capsule_owner(bank, statement, &source_cap)
    })?;

    let (phase_a_binding, phase_a_bound) = zk_capsule_pcs_bind_phase_a(
        owner_bound,
        &owner_output.derived.post_claim_relation.weights,
        owner_output.derived.bank_claim(),
    )?;
    let sigma = phase_a_binding.companion_claim;
    let mut channel = init_main_channel(&owner_output.derived, sigma);
    let gamma = channel.squeeze_wide();
    require_main_gamma(gamma)?;

    let (phase_a_output, phase_a_complete) =
        zk_capsule_pcs_prove_phase_a(phase_a_bound, gamma, |_round, round_proof| {
            absorb_phase_a_round(&mut channel, &round_proof);
            channel.squeeze_wide()
        })?;
    if phase_a_output.relation_claims.bank != owner_output.derived.bank_claim()
        || phase_a_output.relation_claims.companion != sigma
    {
        return Err(ZkAuthorizationError::PhaseABindingMismatch);
    }

    let phase_b_value = phase_a_output.terminal_oracle_value;
    let (phase_b_link, phase_b_ready) =
        zk_capsule_pcs_link_phase_b(phase_a_complete, phase_b_value)?;
    let upper = ZkAuthorizationUpper::new(phase_b_link.upper);
    absorb_phase_b_prefix(&mut channel, phase_b_value, &upper);
    let beta_source: [Block256; SOURCE_STANDARD_FOLDS] =
        std::array::from_fn(|_| channel.squeeze_wide());

    let (mid_commitment, mid_state) = zk_capsule_pcs_commit_mid(phase_b_ready, beta_source)?;
    absorb_mid_commitment(&mut channel, &mid_commitment)?;
    let beta_mid: [Block256; MID_STANDARD_FOLDS] = std::array::from_fn(|_| channel.squeeze_wide());

    let tail_state = zk_capsule_pcs_reveal_tail(mid_state, beta_mid)?;
    let tail = tail_state.tail.clone();
    absorb_tail(&mut channel, &tail);
    let beta_tail = channel.squeeze_wide();
    let mut beta = [Block256::ZERO; PHASE_B_LOW_VARS];
    beta[..SOURCE_STANDARD_FOLDS].copy_from_slice(&beta_source);
    beta[SOURCE_STANDARD_FOLDS..SOURCE_STANDARD_FOLDS + MID_STANDARD_FOLDS]
        .copy_from_slice(&beta_mid);
    beta[PHASE_B_LOW_VARS - 1] = beta_tail;
    verify_phase_b_upper_tail_link(
        upper.as_array(),
        &phase_a_output.terminal_point,
        phase_b_value,
        &beta,
        &tail.coefficients,
    )?;

    let (grind_nonce, _grind) = grind_main_channel_with_bits(&mut channel, ZK_AUTH_GRIND_BITS)?;
    let query_seeds: [Block128; ZK_AUTH_QUERY_SEEDS] =
        std::array::from_fn(|_| channel.squeeze_base());
    let queries = zk_authorization_queries_from_seeds(&query_seeds);
    let opening = zk_capsule_pcs_open(tail_state, &queries)?;

    let proof = ZkAuthorizationProof {
        source_commitment,
        owner: owner_output.proof,
        sigma,
        phase_a: phase_a_output.proof,
        phase_b_value,
        upper,
        mid_commitment,
        tail,
        grind_nonce,
        opening,
    };
    proof.preflight_shape()?;
    let _ = verify_zk_authorization_for_version(statement, &proof, version)?;
    Ok(proof)
}

/// Complete network/native verification.  It receives no bank, companion,
/// spend secret, transcript challenge, bridge, seed, or query index.
pub fn verify_zk_authorization(
    statement: ZkAuthCapsuleOwnerStatement,
    proof: &ZkAuthorizationProof,
) -> Result<ZkAuthorizationVerified, ZkAuthorizationError> {
    verify_zk_authorization_for_version(statement, proof, OwnerAuthorizationVersion::V4)
}

pub fn verify_zk_authorization_for_version(
    statement: ZkAuthCapsuleOwnerStatement,
    proof: &ZkAuthorizationProof,
    version: OwnerAuthorizationVersion,
) -> Result<ZkAuthorizationVerified, ZkAuthorizationError> {
    proof.preflight_shape()?;

    let source_cap = proof.source_commitment.transcript_lanes()?;
    let owner =
        verify_zk_auth_capsule_owner_for_version(statement, &source_cap, &proof.owner, version)?;

    let mut channel = init_main_channel(&owner, proof.sigma);
    let gamma = channel.squeeze_wide();
    require_main_gamma(gamma)?;

    let mut phase_a_challenges_high_to_low = [Block256::ZERO; PHASE_A_VARS];
    for (index, round) in proof.phase_a.rounds.iter().enumerate() {
        absorb_phase_a_round(&mut channel, round);
        phase_a_challenges_high_to_low[index] = channel.squeeze_wide();
    }
    let phase_a = verify_phase_a(
        &proof.phase_a,
        ZkPhaseARelationClaims {
            bank: owner.bank_claim(),
            companion: proof.sigma,
        },
        &owner.post_claim_relation.weights,
        gamma,
        &phase_a_challenges_high_to_low,
        proof.phase_b_value,
    )?;

    absorb_phase_b_prefix(&mut channel, proof.phase_b_value, &proof.upper);
    let beta_source: [Block256; SOURCE_STANDARD_FOLDS] =
        std::array::from_fn(|_| channel.squeeze_wide());

    absorb_mid_commitment(&mut channel, &proof.mid_commitment)?;
    let beta_mid: [Block256; MID_STANDARD_FOLDS] = std::array::from_fn(|_| channel.squeeze_wide());

    absorb_tail(&mut channel, &proof.tail);
    let beta_tail = channel.squeeze_wide();
    let mut beta = [Block256::ZERO; PHASE_B_LOW_VARS];
    beta[..SOURCE_STANDARD_FOLDS].copy_from_slice(&beta_source);
    beta[SOURCE_STANDARD_FOLDS..SOURCE_STANDARD_FOLDS + beta_mid.len()].copy_from_slice(&beta_mid);
    beta[PHASE_B_LOW_VARS - 1] = beta_tail;
    verify_phase_b_upper_tail_link(
        proof.upper.as_array(),
        &phase_a.terminal_point,
        proof.phase_b_value,
        &beta,
        &proof.tail.coefficients,
    )?;

    let grind = replay_grind(&mut channel, proof.grind_nonce)?;
    let query_seeds = std::array::from_fn(|_| channel.squeeze_base());
    let queries = zk_authorization_queries_from_seeds(&query_seeds);
    let pcs = zk_capsule_pcs_verify(
        &proof.source_commitment,
        &proof.mid_commitment,
        &proof.tail,
        gamma,
        beta_source,
        beta_mid,
        &queries,
        &proof.opening,
    )?;
    let hiding = if version == OwnerAuthorizationVersion::V4 {
        Some(certify_zk_auth_joint_hiding_rank(
            pcs.source_hiding_rank,
            &owner.terminal_point,
            owner.lambda,
            gamma,
        )?)
    } else {
        crate::zk_auth_hiding::validate_v3_authorization_parameters(
            &pcs.source_hiding_rank,
            &owner.terminal_point,
            owner.lambda,
            gamma,
        )?;
        None
    };
    let conditioned_sigma = certify_zk_auth_conditioned_companion_hyperplane(
        &owner.post_claim_relation.weights,
        owner.bank_claim(),
        proof.sigma,
        gamma,
    )?;

    Ok(ZkAuthorizationVerified {
        owner,
        gamma,
        phase_a_challenges_high_to_low,
        beta,
        grind,
        query_seeds,
        queries,
        conditioned_sigma,
        hiding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{evaluate_permutation, zk_auth_capsule::ZkAuthCapsuleStateTable};
    use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRFIX};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::sync::OnceLock;

    fn elem(index: usize, domain: u128, salt: u128) -> Block128 {
        Block128::from(
            domain
                .wrapping_mul(index as u128 + 1)
                .rotate_left(((17 * index + 5) % 127) as u32)
                ^ salt.rotate_left(((11 * index + 3) % 127) as u32)
                ^ (index as u128 + 7).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        )
    }

    struct Fixture {
        bank: Vec<Block128>,
        statement: ZkAuthCapsuleOwnerStatement,
        source_cap: [Block128; ZK_AUTH_SOURCE_CAP_LANES],
    }

    fn fixture(salt: u128) -> Fixture {
        let iv = capacity_iv(TAG_ADDRFIX);
        let secret = [elem(1, 0x5EC2_E7, salt), elem(2, 0x5EC2_E7, salt)];
        let witness = evaluate_permutation([secret[0], secret[1], iv[0], iv[1]]);
        let address = [witness.final_state()[0], witness.final_state()[1]];
        let state = ZkAuthCapsuleStateTable::from_permutation_witness(&witness)
            .expect("valid Poseidon state table");
        let mut bank = vec![Block128::ZERO; crate::zk_auth_capsule::ZK_AUTH_CAPSULE_BANK_LEN];
        bank[..ZK_AUTH_CAPSULE_STATE_LEN].copy_from_slice(state.cells());
        for (index, cell) in bank.iter_mut().enumerate().skip(ZK_AUTH_CAPSULE_STATE_LEN) {
            *cell = elem(index, 0xB4A9_C01A_5A11, salt ^ 0xA5A5);
        }
        let statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [elem(3, 0x7A_B0D1, salt), elem(4, 0x7A_B0D1, salt)],
            address,
        };
        let source_cap = std::array::from_fn(|index| elem(index + 71, 0xCA95_0005, salt ^ 0x5A5A));
        Fixture {
            bank,
            statement,
            source_cap,
        }
    }

    fn prove_fixture(fixture: &Fixture) -> ZkAuthCapsuleOwnerProverOutput {
        prove_zk_auth_capsule_owner(
            ZkAuthCapsuleBankView::checked(&fixture.bank).expect("checked fixture bank"),
            fixture.statement,
            &fixture.source_cap,
        )
        .expect("honest Owner proof")
    }

    struct FullFixture {
        state: [Block128; ZK_AUTH_CAPSULE_STATE_LEN],
        statement: ZkAuthCapsuleOwnerStatement,
        proof: ZkAuthorizationProof,
        verified: ZkAuthorizationVerified,
    }

    fn full_fixture() -> &'static FullFixture {
        static FIXTURE: OnceLock<FullFixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let owner = fixture(0xA11C_E100);
            let state: [Block128; ZK_AUTH_CAPSULE_STATE_LEN] = owner.bank
                [..ZK_AUTH_CAPSULE_STATE_LEN]
                .try_into()
                .expect("exact state fixture");
            let mut rng = StdRng::seed_from_u64(0xA11C_E100);
            let proof =
                prove_zk_authorization_from_state_with_rng(&state, owner.statement, &mut rng)
                    .expect("complete authorization proof");
            let verified = verify_zk_authorization(owner.statement, &proof)
                .expect("complete authorization verification");
            FullFixture {
                state,
                statement: owner.statement,
                proof,
                verified,
            }
        })
    }

    #[test]
    fn owner_prove_verify_roundtrip_is_deterministic_and_payload_is_exact() {
        assert_eq!(ZK_AUTH_OWNER_PREFIX_CONSTANTS[1], 4);
        let fixture = fixture(0xA11C_E001);
        let first = prove_fixture(&fixture);
        let second = prove_fixture(&fixture);
        assert_eq!(
            first, second,
            "fixed bank must produce one deterministic proof"
        );
        assert_eq!(first.proof.absorbed_values().len(), 117);
        assert_eq!(first.proof.byte_len(), ZK_AUTH_OWNER_PROOF_BYTES);
        let encoded = bincode::serialize(&first.proof).expect("Owner proof serialization");
        assert_eq!(encoded.len(), ZK_AUTH_OWNER_PROOF_BYTES);
        let decoded: ZkAuthCapsuleOwnerProof =
            bincode::deserialize(&encoded).expect("Owner proof decoding");
        assert_eq!(decoded, first.proof);
        assert_ne!(first.derived.lambda, Block256::ZERO);
        assert_ne!(first.derived.eta, Block256::ZERO);
        for variable in 0..ZK_AUTH_MLECHECK_VARS {
            assert_eq!(
                first.derived.terminal_point[variable],
                first.derived.round_challenges_high_to_low[ZK_AUTH_MLECHECK_VARS - 1 - variable]
            );
        }
        assert!(first
            .derived
            .post_claim_relation
            .verify(ZkAuthCapsuleBankView::checked(&fixture.bank).unwrap()));

        let transcript_only =
            verify_zk_auth_capsule_owner(fixture.statement, &fixture.source_cap, &first.proof)
                .expect("honest transcript-only Owner replay");
        let witness_reference = verify_zk_auth_capsule_owner_witness_reference(
            ZkAuthCapsuleBankView::checked(&fixture.bank).unwrap(),
            fixture.statement,
            &fixture.source_cap,
            &first.proof,
        )
        .expect("honest witness-reference Owner replay");
        assert_eq!(transcript_only, first.derived);
        assert_eq!(witness_reference, transcript_only);
    }

    fn assert_rejected(fixture: &Fixture, proof: &ZkAuthCapsuleOwnerProof, name: &str) {
        assert!(
            verify_zk_auth_capsule_owner(fixture.statement, &fixture.source_cap, proof,).is_err(),
            "accepted {name} tamper"
        );
    }

    #[test]
    fn owner_tamper_matrix_rejects_statement_cap_round_terminal_and_bank_changes() {
        let fixture = fixture(0xA11C_E003);
        let output = prove_fixture(&fixture);

        let mut changed_statement = Fixture {
            bank: fixture.bank.clone(),
            statement: fixture.statement,
            source_cap: fixture.source_cap,
        };
        changed_statement.statement.tx_body_hash[0] += Block128::ONE;
        assert!(verify_zk_auth_capsule_owner(
            changed_statement.statement,
            &changed_statement.source_cap,
            &output.proof,
        )
        .is_err());

        let mut changed_address = fixture.statement;
        changed_address.address[1] += Block128::ONE;
        assert!(
            verify_zk_auth_capsule_owner(changed_address, &fixture.source_cap, &output.proof,)
                .is_err()
        );

        let mut changed_cap = fixture.source_cap;
        changed_cap[13] += Block128::ONE;
        assert!(
            verify_zk_auth_capsule_owner(fixture.statement, &changed_cap, &output.proof,).is_err()
        );

        let mut proof = output.proof.clone();
        proof.mask_mu += Block256::ONE;
        assert_rejected(&fixture, &proof, "mask mu");

        let mut proof = output.proof.clone();
        proof.rounds[0].coeffs_without_constant[0] += Block256::ONE;
        assert_rejected(&fixture, &proof, "first round coefficient");

        let mut proof = output.proof.clone();
        proof.rounds[10].coeffs_without_constant[9] += Block256::ONE;
        assert_rejected(&fixture, &proof, "last round coefficient");

        let mut proof = output.proof.clone();
        proof.mask_final += Block256::ONE;
        assert_rejected(&fixture, &proof, "terminal mask");

        for claim in 0..ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS {
            let mut proof = output.proof.clone();
            proof.terminal_operand_claims[claim] += Block256::ONE;
            assert_rejected(&fixture, &proof, &format!("terminal operand claim {claim}"));
        }

        let mut changed_bank = fixture.bank.clone();
        changed_bank[17] += Block128::ONE;
        assert!(verify_zk_auth_capsule_owner_witness_reference(
            ZkAuthCapsuleBankView::checked(&changed_bank).unwrap(),
            fixture.statement,
            &fixture.source_cap,
            &output.proof,
        )
        .is_err());
    }

    #[test]
    fn complete_authorization_roundtrip_queries_hiding_and_main_stream_are_exact() {
        let fixture = full_fixture();
        let replayed = verify_zk_authorization(fixture.statement, &fixture.proof)
            .expect("complete proof replay");
        assert_eq!(replayed, fixture.verified);
        let challenge_tape = crate::zk_auth_qrom::ZkAuthChallengeTape::from_verified(&replayed);
        assert!(challenge_tape.has_admissible_base_challenges());
        assert!(challenge_tape.compiled_grind_is_valid());
        for move_ in crate::zk_auth_qrom::zk_auth_iop_moves() {
            if move_ == crate::zk_auth_qrom::ZkAuthIopMove::QuerySeeds {
                assert_eq!(replayed.query_seeds.len(), move_.challenge_fields());
                continue;
            }
            assert_eq!(
                challenge_tape
                    .algebraic_challenge_group(move_)
                    .expect("manifest emits only bounded rounds")
                    .len(),
                move_.challenge_fields()
            );
        }
        assert!(challenge_tape
            .algebraic_challenge_group(crate::zk_auth_qrom::ZkAuthIopMove::OwnerMleCheckRound(
                ZK_AUTH_MLECHECK_VARS,
            ))
            .is_none());
        assert!(challenge_tape
            .algebraic_challenge_group(crate::zk_auth_qrom::ZkAuthIopMove::PhaseARound(
                PHASE_A_VARS,
            ))
            .is_none());
        assert!(challenge_tape
            .algebraic_challenge_group(crate::zk_auth_qrom::ZkAuthIopMove::QuerySeeds)
            .is_none());
        assert_eq!(challenge_tape.query_seeds, replayed.query_seeds);
        assert_eq!(challenge_tape.compiled_grind, replayed.grind);
        assert_eq!(replayed.queries.len(), ZK_AUTH_QUERY_COUNT);
        assert!(replayed
            .queries
            .iter()
            .all(|&query| query < 1 << ZK_AUTH_QUERY_WIDTH_BITS));
        let hiding = replayed.hiding.as_ref().unwrap();
        assert_eq!(hiding.intended_relations, 2);
        assert_eq!(
            hiding.certified_joint_rank + hiding.intended_relations,
            hiding.public_conditioning_fields
        );
        replayed
            .conditioned_sigma
            .validate(&replayed.owner.post_claim_relation.weights)
            .expect("conditioned sigma hyperplane certificate");
        assert_eq!(
            zk_authorization_main_dynamic_data(&replayed.owner, &fixture.proof)
                .expect("bounded Main stream")
                .len(),
            ZK_AUTH_MAIN_DYNAMIC_LANES
        );
    }

    #[test]
    fn cloned_deterministic_rng_streams_reproduce_the_source_commitment() {
        let fixture = full_fixture();
        let rng = StdRng::seed_from_u64(0xA11C_E101);
        let mut first_rng = rng.clone();
        let mut second_rng = rng;
        let first = prove_zk_authorization_from_state_with_rng(
            &fixture.state,
            fixture.statement,
            &mut first_rng,
        )
        .expect("first deterministic authorization attempt");
        let second = prove_zk_authorization_from_state_with_rng(
            &fixture.state,
            fixture.statement,
            &mut second_rng,
        )
        .expect("cloned deterministic authorization attempt");
        assert_eq!(
            first.source_commitment, second.source_commitment,
            "cloned RNG streams reproduce hiding randomness, so this helper must stay private"
        );
    }

    #[test]
    fn public_production_attempts_on_same_state_have_distinct_commitments() {
        let fixture = full_fixture();
        let first = prove_zk_authorization_from_state(&fixture.state, fixture.statement)
            .expect("first production authorization attempt");
        let second = prove_zk_authorization_from_state(&fixture.state, fixture.statement)
            .expect("second production authorization attempt");
        verify_zk_authorization(fixture.statement, &first).expect("first proof verifies");
        verify_zk_authorization(fixture.statement, &second).expect("second proof verifies");
        assert_ne!(
            first.source_commitment, second.source_commitment,
            "independent OS-CSPRNG attempts must change the source commitment"
        );
        assert_ne!(first.owner, second.owner);
    }

    #[test]
    fn complete_authorization_serialized_and_modeled_byte_ledgers_are_exact() {
        let fixture = full_fixture();
        let proof = &fixture.proof;
        proof.preflight_shape().expect("honest bounded shape");
        let encoded = proof.to_bytes().expect("complete proof serialization");
        assert_eq!(encoded.len(), proof.serialized_byte_len());
        assert_eq!(
            proof.serialized_byte_len() - proof.modeled_byte_len(),
            ZK_AUTHORIZATION_BINCODE_LENGTH_OVERHEAD
        );
        assert!(proof.modeled_byte_len() <= ZK_AUTHORIZATION_WORST_MODELED_BYTES);
        assert!(proof.serialized_byte_len() <= ZK_AUTHORIZATION_WORST_SERIALIZED_BYTES);
        assert!(ZK_AUTHORIZATION_WORST_SERIALIZED_BYTES <= ZK_AUTHORIZATION_PAYLOAD_ROOFLINE_BYTES);
        let decoded =
            ZkAuthorizationProof::from_bytes(&encoded).expect("complete proof roundtrip decoding");
        assert_eq!(decoded.upper, proof.upper);
        assert_eq!(decoded.serialized_byte_len(), encoded.len());
        verify_zk_authorization(fixture.statement, &decoded).expect("decoded proof verifies");

        let upper_bytes = bincode::serialize(&proof.upper).expect("upper serialization");
        assert_eq!(upper_bytes.len(), ZK_AUTH_UPPER_BYTES);
        let decoded_upper: ZkAuthorizationUpper =
            bincode::deserialize(&upper_bytes).expect("fixed upper decoding");
        assert_eq!(decoded_upper, proof.upper);
    }

    fn assert_full_rejected(proof: &ZkAuthorizationProof, family: &str) {
        assert!(
            verify_zk_authorization(full_fixture().statement, proof).is_err(),
            "accepted {family} tamper"
        );
    }

    #[test]
    fn complete_authorization_tamper_matrix_and_shape_preflight_reject() {
        let fixture = full_fixture();

        let mut changed = fixture.proof.clone();
        changed.source_commitment.cap.hashes[0][0] ^= 1;
        assert_full_rejected(&changed, "source commitment");

        let mut changed = fixture.proof.clone();
        changed.owner.mask_mu += Block256::ONE;
        assert_full_rejected(&changed, "Owner proof");

        let mut changed = fixture.proof.clone();
        changed.sigma += Block256::ONE;
        assert_full_rejected(&changed, "sigma");

        let mut changed = fixture.proof.clone();
        changed.phase_a.rounds[3].at_infinity += Block256::ONE;
        assert_full_rejected(&changed, "Phase-A proof");

        let mut changed = fixture.proof.clone();
        changed.phase_b_value += Block256::ONE;
        assert_full_rejected(&changed, "Phase-B value");

        let mut changed = fixture.proof.clone();
        changed.upper.0[91] += Block256::ONE;
        assert_full_rejected(&changed, "upper table");

        let mut changed = fixture.proof.clone();
        changed.mid_commitment.cap.hashes[0][7] ^= 1;
        assert_full_rejected(&changed, "mid commitment");

        let mut changed = fixture.proof.clone();
        changed.tail.coefficients[5] += Block256::ONE;
        assert_full_rejected(&changed, "tail reveal");

        let mut changed = fixture.proof.clone();
        let mut found_invalid_nonce = false;
        for delta in 1..=128u64 {
            changed.grind_nonce = fixture.proof.grind_nonce.wrapping_add(delta);
            if matches!(
                verify_zk_authorization(fixture.statement, &changed),
                Err(ZkAuthorizationError::GrindRejected)
            ) {
                found_invalid_nonce = true;
                break;
            }
        }
        assert!(
            found_invalid_nonce,
            "failed to find an invalid nonce tamper"
        );

        let mut changed = fixture.proof.clone();
        changed.opening.source_joint_symbols[17] += Block128::ONE;
        assert_full_rejected(&changed, "PCS opening");

        let mut malformed = fixture.proof.clone();
        malformed.source_commitment.cap.hashes.pop();
        assert!(matches!(
            malformed.preflight_shape(),
            Err(ZkAuthorizationError::ProofShape {
                component: ZkAuthorizationProofComponent::SourceCap,
                ..
            })
        ));

        let mut malformed = fixture.proof.clone();
        malformed.opening.mid_symbols.pop();
        assert!(matches!(
            verify_zk_authorization(fixture.statement, &malformed),
            Err(ZkAuthorizationError::ProofShape {
                component: ZkAuthorizationProofComponent::MidSymbols,
                ..
            })
        ));

        let mut malformed = fixture.proof.clone();
        malformed
            .opening
            .source_batch
            .siblings
            .resize(ZK_CAPSULE_PCS_WORST_SOURCE_SIBLINGS + 1, [0u8; 32]);
        assert!(matches!(
            verify_zk_authorization(fixture.statement, &malformed),
            Err(ZkAuthorizationError::ProofShape {
                component: ZkAuthorizationProofComponent::SourceSiblings,
                is_maximum: true,
                ..
            })
        ));
    }

    #[test]
    fn fixed_query_derivation_is_lsb_first_across_seed_boundaries() {
        let expected: [usize; ZK_AUTH_QUERY_COUNT] =
            std::array::from_fn(|query| (query * 197 + 83) & ((1 << 13) - 1));
        let mut seeds = [Block128::ZERO; ZK_AUTH_QUERY_SEEDS];
        for (query, &value) in expected.iter().enumerate() {
            for bit in 0..ZK_AUTH_QUERY_WIDTH_BITS {
                if (value >> bit) & 1 == 1 {
                    let stream_bit = query * ZK_AUTH_QUERY_WIDTH_BITS + bit;
                    seeds[stream_bit / 128].0 |= 1u128 << (stream_bit % 128);
                }
            }
        }
        assert_eq!(zk_authorization_queries_from_seeds(&seeds), expected);
        assert_eq!(
            zk_authorization_queries_from_seeds(&[Block128::ZERO; 7]),
            [0; 65]
        );
        assert_eq!(
            zk_authorization_queries_from_seeds(&[Block128::from(u128::MAX); 7]),
            [(1 << 13) - 1; 65]
        );
    }

    #[test]
    fn parallel_grind_is_smallest_and_low16_predicate_is_exact() {
        let mut channel = Poseidon2bWideChannel::new();
        channel.absorb_base(Block128::from(0xA11C_E170u128));
        channel.absorb_base(Block128::from(0xA11C_E171u128));
        let mut sequential_base = channel.clone();
        sequential_base.absorb_base(Block128::from(ZK_AUTH_GRIND_TAG));
        let small_bits = 6;
        let mask = grind_mask(small_bits);
        let sequential = (0u64..)
            .find(|&nonce| probe_grind(&sequential_base, nonce).0 & mask == 0)
            .expect("small grind has a solution");
        let (parallel, grind) =
            grind_main_channel_with_bits(&mut channel, small_bits).expect("parallel small grind");
        assert_eq!(parallel, sequential);
        assert_eq!(grind.0 & mask, 0);

        assert!(zk_authorization_grind_is_valid(Block128::ZERO));
        assert!(zk_authorization_grind_is_valid(Block128::from(1u128 << 16)));
        for bit in 0..ZK_AUTH_GRIND_BITS {
            assert!(!zk_authorization_grind_is_valid(Block128::from(
                1u128 << bit
            )));
        }
    }

    #[test]
    fn gamma_and_phase_b_link_endpoint_guards_are_explicit() {
        assert_eq!(
            require_main_gamma(Block256::ZERO),
            Err(ZkAuthorizationError::GammaEndpoint)
        );
        assert_eq!(
            require_main_gamma(Block256::ONE),
            Err(ZkAuthorizationError::GammaEndpoint)
        );
        assert!(require_main_gamma(Block256::new(Block128::from(2u128), Block128::ONE)).is_ok());

        let fixture = full_fixture();
        assert!(verify_phase_b_upper_tail_link(
            fixture.proof.upper.as_array(),
            &fixture
                .verified
                .phase_a_challenges_high_to_low
                .map(|_| Block256::ZERO),
            fixture.proof.phase_b_value,
            &fixture.verified.beta,
            &fixture.proof.tail.coefficients,
        )
        .is_err());
    }

    #[test]
    fn zero_lambda_and_eta_guards_are_explicit() {
        assert_eq!(
            require_lambda_nonzero(Block256::ZERO),
            Err(ZkAuthCapsuleOwnerError::LambdaZero)
        );
        assert_eq!(
            require_eta_nonzero(Block256::ZERO),
            Err(ZkAuthCapsuleOwnerError::EtaZero)
        );
        assert!(require_lambda_nonzero(Block256::ONE).is_ok());
        assert!(require_eta_nonzero(Block256::ONE).is_ok());
        assert_eq!(
            crate::zk_auth_capsule::certify_terminal_blinding_rank(
                &[Block256::ZERO; ZK_AUTH_MLECHECK_VARS]
            ),
            Err(ZkAuthCapsuleError::ZeroTerminalBlindingWeight)
        );
    }
}
