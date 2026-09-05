// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Executable parameter ledger for the selected authorization transcript.
//!
//! It locks the prover-message/challenge geometry and checks the conservative
//! engineering soundness targets used by the implementation. It is not part
//! of live proving or verification.

use crate::zk_auth_capsule::{
    ZK_AUTH_CAPSULE_MAIN_DEGREE, ZK_AUTH_CAPSULE_POST_CLAIMS,
    ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS,
};

#[cfg(test)]
use crate::zk_auth_capsule::{
    evaluate_auth_main_terminal_from_claims, AuthCapsuleTerminalOperandClaims,
};
#[cfg(test)]
use crate::zk_auth_hiding::{
    certify_zk_auth_conditioned_companion_hyperplane, certify_zk_auth_joint_hiding_rank,
    ZkAuthConditionedCompanionHyperplaneCertificate, ZkAuthJointHidingRankCertificate,
};
#[cfg(test)]
use crate::zk_authorization::affine_blend_gamma_is_admissible;
#[cfg(test)]
use crate::zk_authorization::{
    absorb_mid_commitment, absorb_owner_prefix, absorb_phase_a_round, absorb_phase_b_prefix,
    absorb_round, absorb_tail, absorb_terminal, init_main_channel, squeeze_wide_array,
    verify_phase_b_upper_tail_link, verify_zk_auth_capsule_owner,
    zk_authorization_queries_from_seeds, ZkAuthCapsuleOwnerError, ZkAuthCapsuleOwnerProof,
    ZkAuthCapsuleOwnerProverOutput, ZkAuthCapsuleOwnerStatement, ZkAuthorizationError,
    ZkAuthorizationUpper, ZK_AUTH_OWNER_PROOF_ROUNDS, ZK_AUTH_OWNER_TO_MAIN_CLOSE_TAG,
    ZK_AUTH_SOURCE_CAP_LANES,
};
use crate::zk_authorization::{
    zk_authorization_grind_is_valid, ZkAuthorizationVerified, ZK_AUTH_GRIND_BITS,
    ZK_AUTH_MAIN_SQUEEZES, ZK_AUTH_MLECHECK_VARS, ZK_AUTH_OWNER_CONSTRUCTION_VERSION,
    ZK_AUTH_OWNER_SQUEEZES, ZK_AUTH_QUERY_COUNT, ZK_AUTH_QUERY_SEEDS, ZK_AUTH_QUERY_WIDTH_BITS,
};
use crate::zk_mlecheck::ZK_MLECHECK_MASK_DEGREE;
#[cfg(test)]
use crate::zk_mlecheck::{ZkMleCheckRoundProof, ZkMleCheckVerifierState};
use noid_core::{Block128, Block256, TowerField};
#[cfg(test)]
use noid_fri::hasher::CryptographicHasher;
#[cfg(test)]
use noid_fri_binius::capsule::{capsule_leaf_hash_wide, CapsuleNodeHasher};
#[cfg(test)]
use noid_fri_binius::interleaved_commit::{
    canonical_source_batched_merkle_sibling_positions, MerkleCap, SourceHash,
    SourceMerkleSiblingPosition,
};
#[cfg(test)]
use noid_fri_binius::zk_affine_code::{AffineHighPaddingRankCertificate, ZkAffineLchCode};
use noid_fri_binius::zk_capsule::ZK_AUTH_CAPSULE_GEOMETRY;
#[cfg(test)]
use noid_fri_binius::zk_capsule_algebra::{
    build_fold_normal_mid_leaf, certify_source_query_hiding_rank, contract_high3_for_each_low8,
    fold_normal_joint_source_leaf, fold_normal_mid_leaf, fold_normal_mid_raw_member,
    interleave_joint_source_leaf, joint_source_leaf_positions, map_source_query_leaf,
    JOINT_SOURCE_BANK_SYMBOLS, JOINT_SOURCE_LEAF_SYMBOLS, PHASE_B_HIGH_VARS,
};
use noid_fri_binius::zk_capsule_algebra::{
    MID_STANDARD_FOLDS, PHASE_B_LOW_VARS, SOURCE_STANDARD_FOLDS, TAIL_SYMBOLS, UPPER_SYMBOLS,
};
#[cfg(test)]
use noid_fri_binius::zk_capsule_pcs::{
    tower_lanes_to_flat_digest, ZkCapsulePcsError, ZkCapsulePcsMidCommitment,
    ZkCapsulePcsSourceCommitment, ZkCapsulePcsTailReveal, ZK_CAPSULE_PCS_MID_CAP_DEPTH,
    ZK_CAPSULE_PCS_MID_CAP_HASHES, ZK_CAPSULE_PCS_MID_LEAF_COUNT, ZK_CAPSULE_PCS_MID_SYMBOLS,
    ZK_CAPSULE_PCS_MID_TREE_DEPTH, ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH, ZK_CAPSULE_PCS_SOURCE_SYMBOLS,
    ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH, ZK_CAPSULE_PCS_WORST_MID_SIBLINGS,
    ZK_CAPSULE_PCS_WORST_SOURCE_SIBLINGS,
};
use noid_fri_binius::zk_capsule_pcs::{
    ZK_CAPSULE_PCS_MID_CODE_LEN, ZK_CAPSULE_PCS_MID_LEAF_HASH_LOG,
    ZK_CAPSULE_PCS_SOURCE_CAP_HASHES, ZK_CAPSULE_PCS_SOURCE_LEAF_COUNT,
    ZK_CAPSULE_PCS_SOURCE_LEAF_HASH_LOG, ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
};
#[cfg(test)]
use noid_fri_binius::zk_phase_a::{
    prove_phase_a_from_virtual_oracle_adaptive, verify_phase_a, ZkPhaseAProof,
    ZkPhaseARelationClaims,
};
use noid_fri_binius::zk_phase_a::{PHASE_A_ROUND_DEGREE, PHASE_A_VARS};
#[cfg(test)]
use noid_poseidon2b::channel::Poseidon2bWideChannel;
#[cfg(test)]
use rand_core::{CryptoRng, RngCore};

pub const WALLET_BASE_IOP_BITS: u32 = 150;
pub const WALLET_QROM_TARGET_BITS: u32 = 103;
pub const HISTORY_STEP_CLASSICAL_BITS: u32 = 100;
/// `min(100 - 2*8, 128 - 3*8) - 1` under the shared QROM budget.
pub const HISTORY_STEP_QROM_BITS: u32 = 83;
pub const HASH_PREIMAGE_PQ_BITS: u32 = 128;
pub const HASH_COLLISION_PQ_BITS: u32 = 85;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoundnessLedger {
    pub wallet_base_iop_bits: u32,
    pub wallet_qrom_target_bits: u32,
    pub history_step_classical_bits: u32,
    pub history_step_qrom_bits: u32,
    pub hash_preimage_pq_bits: u32,
    pub hash_collision_pq_bits: u32,
}

impl SoundnessLedger {
    pub const fn post_quantum_floor_bits(self) -> u32 {
        let mut minimum = self.wallet_qrom_target_bits;
        if self.history_step_qrom_bits < minimum {
            minimum = self.history_step_qrom_bits;
        }
        if self.hash_preimage_pq_bits < minimum {
            minimum = self.hash_preimage_pq_bits;
        }
        if self.hash_collision_pq_bits < minimum {
            minimum = self.hash_collision_pq_bits;
        }
        minimum
    }
}

pub const SOUNDNESS_LEDGER: SoundnessLedger = SoundnessLedger {
    wallet_base_iop_bits: WALLET_BASE_IOP_BITS,
    wallet_qrom_target_bits: WALLET_QROM_TARGET_BITS,
    history_step_classical_bits: HISTORY_STEP_CLASSICAL_BITS,
    history_step_qrom_bits: HISTORY_STEP_QROM_BITS,
    hash_preimage_pq_bits: HASH_PREIMAGE_PQ_BITS,
    hash_collision_pq_bits: HASH_COLLISION_PQ_BITS,
};

/// Exact min-entropy of the trace-one GF(2^256) challenge sampler.
pub const ZK_AUTH_EFFECTIVE_CHALLENGE_BITS: u32 = 255;
/// CAPSLEAF/CAPSNODE commitments expose 256-bit digests.
pub const ZK_AUTH_MERKLE_DIGEST_BITS: u32 = 256;
/// Grinding is an accepted-output predicate, not unconditional soundness.
/// Its effect must be charged through the adversary's QRO query budget.
pub const ZK_AUTH_QROM_FIXED_GRIND_SOUNDNESS_CREDIT_BITS: u32 = 0;
/// Generic Grover search over a `g`-bit predicate needs only about 2^(g/2)
/// quantum queries.  This is a work exponent, not a theorem-level credit.
pub const ZK_AUTH_GENERIC_QUANTUM_GRIND_WORK_BITS: u32 = ZK_AUTH_GRIND_BITS / 2;

/// Structural cap on ideal-oracle programming points in one source opening:
/// one leaf point per query and one node point per path level. Shared paths
/// only reduce the realized count.
pub const ZK_AUTH_QROM_MAX_PROGRAMMED_SOURCE_LEAVES: usize = ZK_AUTH_QUERY_COUNT;
pub const ZK_AUTH_QROM_MAX_PROGRAMMED_SOURCE_NODES: usize =
    ZK_AUTH_QUERY_COUNT * ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH;
pub const ZK_AUTH_QROM_MAX_PROGRAMMING_POINTS: usize =
    ZK_AUTH_QROM_MAX_PROGRAMMED_SOURCE_LEAVES + ZK_AUTH_QROM_MAX_PROGRAMMED_SOURCE_NODES;
/// The first transcript message carries eight fresh 256-bit ideal cap values.
/// Turning this structural width into conditional min-entropy is deliberately
/// left to the adaptive multi-proof QROM argument.
pub const ZK_AUTH_SOURCE_CAP_STRUCTURAL_BITS: usize =
    ZK_CAPSULE_PCS_SOURCE_CAP_HASHES * ZK_AUTH_MERKLE_DIGEST_BITS as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthQromProgrammingBudget {
    pub max_source_leaf_programs: usize,
    pub max_source_node_programs: usize,
    pub max_total_programs: usize,
    pub source_cap_structural_bits: usize,
    pub dedicated_session_salt_bits: usize,
}

pub const ZK_AUTH_QROM_PROGRAMMING_BUDGET: ZkAuthQromProgrammingBudget =
    ZkAuthQromProgrammingBudget {
        max_source_leaf_programs: ZK_AUTH_QROM_MAX_PROGRAMMED_SOURCE_LEAVES,
        max_source_node_programs: ZK_AUTH_QROM_MAX_PROGRAMMED_SOURCE_NODES,
        max_total_programs: ZK_AUTH_QROM_MAX_PROGRAMMING_POINTS,
        source_cap_structural_bits: ZK_AUTH_SOURCE_CAP_STRUCTURAL_BITS,
        dedicated_session_salt_bits: 0,
    };

/// Inputs to the finite-length proximity-gap calculation.  The seven binary
/// folds are executed as grouped 3+4 transitions in the selected prover.  For
/// one parent fold, BCHKS Corollary 1.4 applies to the two split words and the
/// folded word over the child domain, whose length is half the parent length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthPcsProximityParameters {
    pub field_bits: u32,
    pub inverse_rate: usize,
    pub source_domain_len: usize,
    pub source_folds: usize,
    pub mid_domain_len: usize,
    pub mid_folds: usize,
    pub tail_domain_len: usize,
    pub query_count: usize,
    pub queries_with_replacement: bool,
    pub fixed_grind_credit_bits: u32,
}

pub const ZK_AUTH_SELECTED_PCS_PROXIMITY_PARAMETERS: ZkAuthPcsProximityParameters =
    ZkAuthPcsProximityParameters {
        field_bits: ZK_AUTH_EFFECTIVE_CHALLENGE_BITS,
        inverse_rate: ZK_AUTH_CAPSULE_GEOMETRY.rate,
        source_domain_len: ZK_AUTH_CAPSULE_GEOMETRY.source_domain_len,
        source_folds: SOURCE_STANDARD_FOLDS,
        mid_domain_len: ZK_AUTH_CAPSULE_GEOMETRY.mid_leaf_count
            * ZK_AUTH_CAPSULE_GEOMETRY.mid_leaf_symbols,
        mid_folds: MID_STANDARD_FOLDS,
        tail_domain_len: ZK_AUTH_CAPSULE_GEOMETRY.tail_len * ZK_AUTH_CAPSULE_GEOMETRY.rate,
        query_count: ZK_AUTH_QUERY_COUNT,
        queries_with_replacement: true,
        fixed_grind_credit_bits: ZK_AUTH_QROM_FIXED_GRIND_SOUNDNESS_CREDIT_BITS,
    };

pub const ZK_AUTH_AFFINE_PROXIMITY_FOLD_ROUNDS: usize = SOURCE_STANDARD_FOLDS + MID_STANDARD_FOLDS;
pub const ZK_AUTH_AFFINE_RS_LAYER_COUNT: usize = ZK_AUTH_AFFINE_PROXIMITY_FOLD_ROUNDS + 1;

/// One Reed--Solomon layer in the selected additive-LCH quotient chain.
/// `folds_done=j` represents `EncodeAfterLowFolds(j)`; all eight layers keep
/// rate 1/32 while both message and code lengths halve together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthAffineRsLayer {
    pub folds_done: usize,
    pub message_len: usize,
    pub code_len: usize,
    pub inverse_rate: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthFoldCoin {
    BetaSource(usize),
    BetaMid(usize),
}

/// Exact coordinate object for one conceptual binary proximity fold.
///
/// The inverse-butterfly components and their challenge combination are
/// words in `after`, so `cat_line_len` is the child code length.  Source and
/// mid prover messages group these as 3+4 atomic vector-coin moves; this
/// scalar inventory does not claim that seven independent RBR lemmas compose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthAffineFoldRound {
    pub round: usize,
    pub logical_variable: usize,
    pub coin: ZkAuthFoldCoin,
    pub before: ZkAuthAffineRsLayer,
    pub after: ZkAuthAffineRsLayer,
    pub cat_line_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthGammaProximityLine {
    pub source_code_len: usize,
    pub committed_word_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthTailLocalEquality {
    pub logical_variable: usize,
    pub coefficients_before: usize,
    pub coefficients_after: usize,
    pub is_pcs_proximity_fold: bool,
}

pub const fn zk_auth_affine_rs_layers() -> [ZkAuthAffineRsLayer; ZK_AUTH_AFFINE_RS_LAYER_COUNT] {
    let mut layers = [ZkAuthAffineRsLayer {
        folds_done: 0,
        message_len: ZK_AUTH_CAPSULE_GEOMETRY.bank_len,
        code_len: ZK_AUTH_CAPSULE_GEOMETRY.source_domain_len,
        inverse_rate: ZK_AUTH_CAPSULE_GEOMETRY.rate,
    }; ZK_AUTH_AFFINE_RS_LAYER_COUNT];
    let mut round = 0;
    while round < ZK_AUTH_AFFINE_RS_LAYER_COUNT {
        layers[round] = ZkAuthAffineRsLayer {
            folds_done: round,
            message_len: ZK_AUTH_CAPSULE_GEOMETRY.bank_len >> round,
            code_len: ZK_AUTH_CAPSULE_GEOMETRY.source_domain_len >> round,
            inverse_rate: ZK_AUTH_CAPSULE_GEOMETRY.rate,
        };
        round += 1;
    }
    layers
}

pub const fn zk_auth_affine_fold_rounds(
) -> [ZkAuthAffineFoldRound; ZK_AUTH_AFFINE_PROXIMITY_FOLD_ROUNDS] {
    let layers = zk_auth_affine_rs_layers();
    let placeholder = ZkAuthAffineFoldRound {
        round: 0,
        logical_variable: 0,
        coin: ZkAuthFoldCoin::BetaSource(0),
        before: layers[0],
        after: layers[1],
        cat_line_len: layers[1].code_len,
    };
    let mut rounds = [placeholder; ZK_AUTH_AFFINE_PROXIMITY_FOLD_ROUNDS];
    let mut round = 0;
    while round < ZK_AUTH_AFFINE_PROXIMITY_FOLD_ROUNDS {
        rounds[round] = ZkAuthAffineFoldRound {
            round,
            logical_variable: round,
            coin: if round < SOURCE_STANDARD_FOLDS {
                ZkAuthFoldCoin::BetaSource(round)
            } else {
                ZkAuthFoldCoin::BetaMid(round - SOURCE_STANDARD_FOLDS)
            },
            before: layers[round],
            after: layers[round + 1],
            cat_line_len: layers[round + 1].code_len,
        };
        round += 1;
    }
    rounds
}

pub const ZK_AUTH_GAMMA_PROXIMITY_LINE: ZkAuthGammaProximityLine = ZkAuthGammaProximityLine {
    source_code_len: ZK_AUTH_CAPSULE_GEOMETRY.source_domain_len,
    committed_word_count: 2,
};

/// Beta seven folds the already revealed 16 coefficients to eight local
/// values for the upper/tail equality.  It is not an eighth PCS proximity
/// transition and therefore cannot enter the seven-round bad-coin ledger.
pub const ZK_AUTH_TAIL_LOCAL_EQUALITY: ZkAuthTailLocalEquality = ZkAuthTailLocalEquality {
    logical_variable: SOURCE_STANDARD_FOLDS + MID_STANDARD_FOLDS,
    coefficients_before: TAIL_SYMBOLS,
    coefficients_after: TAIL_SYMBOLS / 2,
    is_pcs_proximity_fold: false,
};

const _: () = assert!(ZK_AUTH_AFFINE_PROXIMITY_FOLD_ROUNDS == 7);
const _: () = assert!(ZK_AUTH_AFFINE_RS_LAYER_COUNT == 8);
const _: () = assert!(ZK_AUTH_TAIL_LOCAL_EQUALITY.logical_variable == 7);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthPcsProximityConfigError {
    InvalidFieldSize,
    InvalidInverseRate,
    InvalidSourceDomain,
    InvalidMidDomain,
    InvalidTailDomain,
    InvalidFoldCount,
    InvalidQueryCount,
    SamplingMustBeWithReplacement,
    GrindCreditMustBeZero,
    NonPositiveConservativeGap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthPcsTargetStatus {
    BelowEightyBits,
    AtLeastEightyBits,
}

/// Exact rational ledger for the conservative finite-length candidate
///
/// `delta = 1 - rate`,
/// `gap = delta/2 - 3/(delta*n_min)`,
/// `Pr[all q queries miss] = (1-gap)^q`.
///
/// It deliberately does not turn that candidate into `epsilon_RBR`: the
/// grouped affine-fold/common-agreement lemma and doomed-state restoration
/// proof remain external obligations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthConditionalPcsProximityLedger {
    pub parameters: ZkAuthPcsProximityParameters,
    pub fold_child_domain_lengths: [usize; 7],
    pub shortest_fold_child_domain_len: usize,
    pub relative_distance_numerator: u128,
    pub relative_distance_denominator: u128,
    pub conservative_gap_numerator: u128,
    pub conservative_gap_denominator: u128,
    pub single_query_miss_numerator: u128,
    pub single_query_miss_denominator: u128,
    pub query_term_exponent: usize,
    pub fold_bad_coin_counts: [u128; 7],
    pub fold_bad_coin_total: u128,
    pub gamma_line_bad_coin_count: u128,
    pub all_bad_coin_total: u128,
    pub bad_coin_denominator_bits: u32,
    pub query_term_target_status: ZkAuthPcsTargetStatus,
}

impl ZkAuthConditionalPcsProximityLedger {
    /// Diagnostic only; the exact security object is the rational power in
    /// the fields above.
    pub fn diagnostic_query_term_bits(self) -> f64 {
        let miss =
            self.single_query_miss_numerator as f64 / self.single_query_miss_denominator as f64;
        -(self.query_term_exponent as f64) * miss.log2()
    }

    pub fn diagnostic_bad_coin_term_bits(self) -> f64 {
        self.bad_coin_denominator_bits as f64 - (self.all_bad_coin_total as f64).log2()
    }

    pub fn diagnostic_conditional_union_bits(self) -> f64 {
        let query = 2f64.powf(-self.diagnostic_query_term_bits());
        let bad_coins =
            (self.all_bad_coin_total as f64) * 2f64.powi(-(self.bad_coin_denominator_bits as i32));
        -(query + bad_coins).log2()
    }

    pub fn diagnostic_min_queries_for_query_term_bits(self, target_bits: u32) -> usize {
        let per_query = -((self.single_query_miss_numerator as f64)
            / (self.single_query_miss_denominator as f64))
            .log2();
        (target_bits as f64 / per_query).ceil() as usize
    }
}

const fn gcd_u128(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

pub fn conditional_zk_auth_pcs_proximity_ledger(
    parameters: ZkAuthPcsProximityParameters,
) -> Result<ZkAuthConditionalPcsProximityLedger, ZkAuthPcsProximityConfigError> {
    if parameters.field_bits != ZK_AUTH_EFFECTIVE_CHALLENGE_BITS {
        return Err(ZkAuthPcsProximityConfigError::InvalidFieldSize);
    }
    if parameters.inverse_rate < 2 {
        return Err(ZkAuthPcsProximityConfigError::InvalidInverseRate);
    }
    if parameters.source_domain_len == 0 || !parameters.source_domain_len.is_power_of_two() {
        return Err(ZkAuthPcsProximityConfigError::InvalidSourceDomain);
    }
    if parameters.source_folds != 3 || parameters.mid_folds != 4 {
        return Err(ZkAuthPcsProximityConfigError::InvalidFoldCount);
    }
    if parameters.mid_domain_len == 0
        || !parameters.mid_domain_len.is_power_of_two()
        || parameters.source_domain_len >> parameters.source_folds != parameters.mid_domain_len
    {
        return Err(ZkAuthPcsProximityConfigError::InvalidMidDomain);
    }
    if parameters.tail_domain_len == 0
        || !parameters.tail_domain_len.is_power_of_two()
        || parameters.mid_domain_len >> parameters.mid_folds != parameters.tail_domain_len
    {
        return Err(ZkAuthPcsProximityConfigError::InvalidTailDomain);
    }
    if parameters.query_count == 0 {
        return Err(ZkAuthPcsProximityConfigError::InvalidQueryCount);
    }
    if !parameters.queries_with_replacement {
        return Err(ZkAuthPcsProximityConfigError::SamplingMustBeWithReplacement);
    }
    if parameters.fixed_grind_credit_bits != 0 {
        return Err(ZkAuthPcsProximityConfigError::GrindCreditMustBeZero);
    }

    // At each conceptual binary fold, the proximity-gap line consists of the
    // two inverse-butterfly components and their random combination on the
    // child code/domain.  Using the parent length here would make the finite
    // correction 3/(delta*n) optimistically small by one fold.
    let fold_child_domain_lengths = [
        parameters.source_domain_len >> 1,
        parameters.source_domain_len >> 2,
        parameters.source_domain_len >> 3,
        parameters.mid_domain_len >> 1,
        parameters.mid_domain_len >> 2,
        parameters.mid_domain_len >> 3,
        parameters.mid_domain_len >> 4,
    ];
    let shortest_fold_child_domain_len = fold_child_domain_lengths[6];
    if shortest_fold_child_domain_len < parameters.inverse_rate
        || shortest_fold_child_domain_len % parameters.inverse_rate != 0
    {
        return Err(ZkAuthPcsProximityConfigError::InvalidFoldCount);
    }
    let distance_numerator = (parameters.inverse_rate - 1) as u128;
    let distance_denominator = parameters.inverse_rate as u128;
    let n_min = shortest_fold_child_domain_len as u128;

    // For delta=a/b, delta/2 - 3/(delta*n)
    // = (a^2*n - 6*b^2) / (2*a*b*n).
    let positive = distance_numerator * distance_numerator * n_min;
    let correction = 6 * distance_denominator * distance_denominator;
    if positive <= correction {
        return Err(ZkAuthPcsProximityConfigError::NonPositiveConservativeGap);
    }
    let raw_gap_numerator = positive - correction;
    let raw_gap_denominator = 2 * distance_numerator * distance_denominator * n_min;
    let divisor = gcd_u128(raw_gap_numerator, raw_gap_denominator);
    let gap_numerator = raw_gap_numerator / divisor;
    let gap_denominator = raw_gap_denominator / divisor;
    if gap_numerator >= gap_denominator {
        return Err(ZkAuthPcsProximityConfigError::NonPositiveConservativeGap);
    }

    // BCHKS Cor. 1.4 preconditions, checked exactly at every child-domain
    // length: delta^2*n >= 18, delta/3 <= gap, and
    // gap <= delta/2 - 3/(delta*n).
    for &domain_len in &fold_child_domain_lengths {
        let n = domain_len as u128;
        if distance_numerator * distance_numerator * n
            < 18 * distance_denominator * distance_denominator
            || gap_numerator * 3 * distance_denominator < distance_numerator * gap_denominator
        {
            return Err(ZkAuthPcsProximityConfigError::NonPositiveConservativeGap);
        }
        let per_length_positive = distance_numerator * distance_numerator * n;
        if per_length_positive <= correction {
            return Err(ZkAuthPcsProximityConfigError::NonPositiveConservativeGap);
        }
        let per_length_upper_numerator = per_length_positive - correction;
        let per_length_upper_denominator = 2 * distance_numerator * distance_denominator * n;
        if gap_numerator * per_length_upper_denominator
            > per_length_upper_numerator * gap_denominator
        {
            return Err(ZkAuthPcsProximityConfigError::NonPositiveConservativeGap);
        }
    }

    let fold_bad_coin_counts = fold_child_domain_lengths
        .map(|domain_len| (gap_numerator * domain_len as u128 + gap_denominator) / gap_denominator);
    let fold_bad_coin_total = fold_bad_coin_counts.iter().copied().sum();
    // Gamma batches the two complete source words before any binary fold, so
    // its line lives on the full source domain rather than the first child.
    let gamma_line_bad_coin_count =
        (gap_numerator * parameters.source_domain_len as u128 + gap_denominator) / gap_denominator;
    let all_bad_coin_total = fold_bad_coin_total + gamma_line_bad_coin_count;
    let miss_numerator = gap_denominator - gap_numerator;
    let diagnostic_query_bits = -(parameters.query_count as f64)
        * ((miss_numerator as f64) / (gap_denominator as f64)).log2();

    Ok(ZkAuthConditionalPcsProximityLedger {
        parameters,
        fold_child_domain_lengths,
        shortest_fold_child_domain_len,
        relative_distance_numerator: distance_numerator,
        relative_distance_denominator: distance_denominator,
        conservative_gap_numerator: gap_numerator,
        conservative_gap_denominator: gap_denominator,
        single_query_miss_numerator: miss_numerator,
        single_query_miss_denominator: gap_denominator,
        query_term_exponent: parameters.query_count,
        fold_bad_coin_counts,
        fold_bad_coin_total,
        gamma_line_bad_coin_count,
        all_bad_coin_total,
        bad_coin_denominator_bits: parameters.field_bits,
        query_term_target_status: if diagnostic_query_bits >= 80.0 {
            ZkAuthPcsTargetStatus::AtLeastEightyBits
        } else {
            ZkAuthPcsTargetStatus::BelowEightyBits
        },
    })
}

/// Conditional Johnson/list-correlated-agreement screen for the selected
/// q=65 geometry. The analysis radius 4/5 gives a per-query miss fraction of
/// 1/5; BCHKS Theorem 4.2/4.6 uses multiplicity eight on every selected RS
/// layer. Neither this radius nor the interpolation multiplicities below
/// enter production proving, verification, transcripts, or circuit matrices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthJohnsonPcsParameters {
    pub field_bits: u32,
    pub radius_numerator: u128,
    pub radius_denominator: u128,
    pub multiplicity: u128,
    pub query_count: usize,
    pub fixed_grind_credit_bits: u32,
}

pub const ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS: ZkAuthJohnsonPcsParameters =
    ZkAuthJohnsonPcsParameters {
        field_bits: ZK_AUTH_EFFECTIVE_CHALLENGE_BITS,
        radius_numerator: 4,
        radius_denominator: 5,
        multiplicity: 8,
        query_count: ZK_AUTH_QUERY_COUNT,
        fixed_grind_credit_bits: ZK_AUTH_QROM_FIXED_GRIND_SOUNDNESS_CREDIT_BITS,
    };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthJohnsonPcsConfigError {
    InvalidFieldSize,
    InvalidRadius,
    InvalidMultiplicity,
    InvalidQueryCount,
    GrindCreditMustBeZero,
    JohnsonRadiusPrecondition,
    SelectedMultiplicityPrecondition,
    ArithmeticOverflow,
    InvalidSquareRootBound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthJohnsonLineKind {
    Gamma,
    Fold(usize),
}

/// One exact integer upper bound for the exceptional challenge set in the
/// conditional Johnson screen.  `paper_degree` is `K-1` for a selected
/// degree-`<K` RS word, matching the theorem's dimension-`k+1` convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthJohnsonLineLedger {
    pub kind: ZkAuthJohnsonLineKind,
    pub code_len: usize,
    pub message_len: usize,
    pub paper_degree: usize,
    pub rho_numerator: u128,
    pub rho_denominator: u128,
    pub sqrt_rho_lower_numerator: u128,
    pub sqrt_rho_lower_denominator: u128,
    pub multiplicity: usize,
    pub bad_coin_upper_bound: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthConditionalJohnsonPcsLedger {
    pub parameters: ZkAuthJohnsonPcsParameters,
    pub lines: [ZkAuthJohnsonLineLedger; 8],
    pub single_query_miss_numerator: u128,
    pub single_query_miss_denominator: u128,
    pub query_term_exponent: usize,
    pub all_bad_coin_upper_bound: u128,
    pub bad_coin_denominator_bits: u32,
}

/// Extractor-side Guruswami--Sudan interpolation parameters. Multiplicity
/// three means six Hasse constraints at each point, also in characteristic
/// two. This multiplicity is distinct from the proximity-gap multiplicity.
pub const ZK_AUTH_JOHNSON_LIST_INTERPOLATION_MULTIPLICITY: usize = 3;
pub const ZK_AUTH_JOHNSON_LIST_INTERPOLATION_Y_DEGREE: usize = 17;

/// Exact interpolation dimension certificate for a bounded Johnson
/// candidate list at the selected 4/5 distance radius.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthJohnsonListSizeLineLedger {
    pub code_len: usize,
    pub message_len: usize,
    pub paper_degree: usize,
    pub required_agreements: usize,
    pub interpolation_multiplicity: usize,
    pub interpolation_weighted_degree: usize,
    pub interpolation_y_degree: usize,
    pub monomials_by_y_degree: [usize; ZK_AUTH_JOHNSON_LIST_INTERPOLATION_Y_DEGREE + 1],
    pub interpolation_unknowns: usize,
    pub interpolation_constraints: usize,
    pub interpolation_dimension_margin: usize,
    pub max_candidate_list_size: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthJohnsonListSizeLedger {
    pub distance_radius_numerator: usize,
    pub distance_radius_denominator: usize,
    pub agreement_numerator: usize,
    pub agreement_denominator: usize,
    pub lines: [ZkAuthJohnsonListSizeLineLedger; 8],
    pub global_max_candidate_list_size: usize,
    pub polynomial_time_decoder_implemented: bool,
}

const fn selected_johnson_list_size_line(
    layer: ZkAuthAffineRsLayer,
) -> ZkAuthJohnsonListSizeLineLedger {
    let radius_numerator = ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS.radius_numerator as usize;
    let radius_denominator = ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS.radius_denominator as usize;
    let agreement_numerator = radius_denominator - radius_numerator;
    let required_agreements = (agreement_numerator * layer.code_len).div_ceil(radius_denominator);
    let interpolation_multiplicity = ZK_AUTH_JOHNSON_LIST_INTERPOLATION_MULTIPLICITY;
    let interpolation_y_degree = ZK_AUTH_JOHNSON_LIST_INTERPOLATION_Y_DEGREE;
    let interpolation_weighted_degree = interpolation_multiplicity * required_agreements - 1;
    let paper_degree = layer.message_len - 1;
    let mut monomials_by_y_degree = [0usize; ZK_AUTH_JOHNSON_LIST_INTERPOLATION_Y_DEGREE + 1];
    let mut interpolation_unknowns = 0;
    let mut y_degree = 0;
    while y_degree <= interpolation_y_degree {
        let weight = paper_degree * y_degree;
        if weight <= interpolation_weighted_degree {
            monomials_by_y_degree[y_degree] = interpolation_weighted_degree - weight + 1;
        }
        interpolation_unknowns += monomials_by_y_degree[y_degree];
        y_degree += 1;
    }
    let interpolation_constraints =
        layer.code_len * interpolation_multiplicity * (interpolation_multiplicity + 1) / 2;
    assert!(interpolation_unknowns > interpolation_constraints);
    ZkAuthJohnsonListSizeLineLedger {
        code_len: layer.code_len,
        message_len: layer.message_len,
        paper_degree,
        required_agreements,
        interpolation_multiplicity,
        interpolation_weighted_degree,
        interpolation_y_degree,
        monomials_by_y_degree,
        interpolation_unknowns,
        interpolation_constraints,
        interpolation_dimension_margin: interpolation_unknowns - interpolation_constraints,
        max_candidate_list_size: interpolation_y_degree,
    }
}

pub const fn selected_zk_auth_johnson_list_size_ledger() -> ZkAuthJohnsonListSizeLedger {
    let layers = zk_auth_affine_rs_layers();
    let mut lines = [selected_johnson_list_size_line(layers[0]); 8];
    let mut layer = 0;
    while layer < lines.len() {
        lines[layer] = selected_johnson_list_size_line(layers[layer]);
        layer += 1;
    }
    ZkAuthJohnsonListSizeLedger {
        distance_radius_numerator: ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS.radius_numerator
            as usize,
        distance_radius_denominator: ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS.radius_denominator
            as usize,
        agreement_numerator: (ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS.radius_denominator
            - ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS.radius_numerator)
            as usize,
        agreement_denominator: ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS.radius_denominator as usize,
        lines,
        global_max_candidate_list_size: ZK_AUTH_JOHNSON_LIST_INTERPOLATION_Y_DEGREE,
        polynomial_time_decoder_implemented: false,
    }
}

impl ZkAuthConditionalJohnsonPcsLedger {
    pub fn diagnostic_query_term_bits(self) -> f64 {
        let miss =
            self.single_query_miss_numerator as f64 / self.single_query_miss_denominator as f64;
        -(self.query_term_exponent as f64) * miss.log2()
    }

    pub fn diagnostic_bad_coin_term_bits(self) -> f64 {
        self.bad_coin_denominator_bits as f64 - (self.all_bad_coin_upper_bound as f64).log2()
    }

    pub fn diagnostic_conditional_union_bits(self) -> f64 {
        let query = 2f64.powf(-self.diagnostic_query_term_bits());
        let bad_coins = (self.all_bad_coin_upper_bound as f64)
            * 2f64.powi(-(self.bad_coin_denominator_bits as i32));
        -(query + bad_coins).log2()
    }
}

const ZK_AUTH_JOHNSON_SQRT_SCALE: u128 = 1u128 << 48;

fn floor_sqrt_u128(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    let shift = (u128::BITS - value.leading_zeros()).div_ceil(2);
    let mut current = 1u128 << shift;
    loop {
        let next = (current + value / current) / 2;
        if next >= current {
            return current;
        }
        current = next;
    }
}

fn conditional_johnson_line_ledger(
    kind: ZkAuthJohnsonLineKind,
    layer: ZkAuthAffineRsLayer,
    parameters: ZkAuthJohnsonPcsParameters,
) -> Result<ZkAuthJohnsonLineLedger, ZkAuthJohnsonPcsConfigError> {
    let radius_numerator = parameters.radius_numerator;
    let radius_denominator = parameters.radius_denominator;
    let radius_complement = radius_denominator - radius_numerator;
    let rho_numerator = layer
        .message_len
        .checked_sub(1)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)? as u128;
    let rho_denominator = layer.code_len as u128;

    let square = |value: u128| {
        value
            .checked_mul(value)
            .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)
    };
    let radius_denominator_squared = square(radius_denominator)?;
    let radius_complement_squared = square(radius_complement)?;

    // gamma < 1-sqrt(rho), checked without floating point.
    if rho_numerator
        .checked_mul(radius_denominator_squared)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?
        >= rho_denominator
            .checked_mul(radius_complement_squared)
            .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?
    {
        return Err(ZkAuthJohnsonPcsConfigError::JohnsonRadiusPrecondition);
    }

    // ceil(sqrt(rho)/(1-sqrt(rho)-gamma)) <= m is equivalent to
    // (m+1)*sqrt(rho) <= m*(1-gamma). This pins one multiplicity uniformly
    // over all eight layers.
    let multiplicity = parameters.multiplicity;
    let multiplicity_plus_one = multiplicity
        .checked_add(1)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;
    let multiplicity_plus_one_squared = multiplicity_plus_one
        .checked_mul(multiplicity_plus_one)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;
    let multiplicity_squared = multiplicity
        .checked_mul(multiplicity)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;
    if multiplicity_plus_one_squared
        .checked_mul(rho_numerator)
        .and_then(|value| value.checked_mul(radius_denominator_squared))
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?
        > multiplicity_squared
            .checked_mul(rho_denominator)
            .and_then(|value| value.checked_mul(radius_complement_squared))
            .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?
    {
        return Err(ZkAuthJohnsonPcsConfigError::SelectedMultiplicityPrecondition);
    }
    let h_numerator = multiplicity
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;
    let h_numerator_squared = h_numerator
        .checked_mul(h_numerator)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;
    let h_numerator_fourth = h_numerator_squared
        .checked_mul(h_numerator_squared)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;
    let h_numerator_fifth = h_numerator_fourth
        .checked_mul(h_numerator)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;

    let sqrt_scale_squared = ZK_AUTH_JOHNSON_SQRT_SCALE
        .checked_mul(ZK_AUTH_JOHNSON_SQRT_SCALE)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;
    let scaled_square = rho_numerator
        .checked_mul(sqrt_scale_squared)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?
        / rho_denominator;
    let sqrt_rho_lower_numerator = floor_sqrt_u128(scaled_square);
    if sqrt_rho_lower_numerator == 0
        || sqrt_rho_lower_numerator
            .checked_mul(sqrt_rho_lower_numerator)
            .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?
            > scaled_square
        || sqrt_rho_lower_numerator
            .checked_add(1)
            .and_then(|value| value.checked_mul(value))
            .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?
            <= scaled_square
    {
        return Err(ZkAuthJohnsonPcsConfigError::InvalidSquareRootBound);
    }

    // For selected m and h=m+1/2, Theorem 4.2/4.6 bounds one degree-one
    // exceptional set by
    //
    // n * (2h^5 + 3h*gamma*rho)/(3*rho^(3/2)) + h/sqrt(rho).
    //
    // Replacing sqrt(rho) in the denominators with the certified Q48 lower
    // bound gives a rational upper bound.  The expression below is that
    // rational with common denominator.  Ceiling division deliberately keeps
    // the integer exceptional-set ledger conservative as well.
    // Clearing the h denominator gives the common numerator
    // h_num^5*rden*rhoden + 24*h_num*rnum*rhonum.
    let curve_term = h_numerator_fifth
        .checked_mul(radius_denominator)
        .and_then(|value| value.checked_mul(rho_denominator))
        .and_then(|value| {
            24u128
                .checked_mul(h_numerator)
                .and_then(|second| second.checked_mul(radius_numerator))
                .and_then(|second| second.checked_mul(rho_numerator))
                .and_then(|second| value.checked_add(second))
        })
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;
    let upper_numerator = (layer.code_len as u128)
        .checked_mul(curve_term)
        .and_then(|value| {
            24u128
                .checked_mul(h_numerator)
                .and_then(|second| second.checked_mul(radius_denominator))
                .and_then(|second| second.checked_mul(rho_numerator))
                .and_then(|second| value.checked_add(second))
        })
        .and_then(|value| value.checked_mul(ZK_AUTH_JOHNSON_SQRT_SCALE))
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;
    let upper_denominator = 48u128
        .checked_mul(radius_denominator)
        .and_then(|value| value.checked_mul(rho_numerator))
        .and_then(|value| value.checked_mul(sqrt_rho_lower_numerator))
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;
    if upper_denominator == 0 {
        return Err(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow);
    }
    let bad_coin_upper_bound = upper_numerator
        .checked_add(upper_denominator - 1)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?
        / upper_denominator;

    Ok(ZkAuthJohnsonLineLedger {
        kind,
        code_len: layer.code_len,
        message_len: layer.message_len,
        paper_degree: layer.message_len - 1,
        rho_numerator,
        rho_denominator,
        sqrt_rho_lower_numerator,
        sqrt_rho_lower_denominator: ZK_AUTH_JOHNSON_SQRT_SCALE,
        multiplicity: multiplicity as usize,
        bad_coin_upper_bound,
    })
}

pub fn conditional_selected_zk_auth_johnson_pcs_ledger(
    parameters: ZkAuthJohnsonPcsParameters,
) -> Result<ZkAuthConditionalJohnsonPcsLedger, ZkAuthJohnsonPcsConfigError> {
    if parameters.field_bits != ZK_AUTH_EFFECTIVE_CHALLENGE_BITS {
        return Err(ZkAuthJohnsonPcsConfigError::InvalidFieldSize);
    }
    if parameters.radius_denominator == 0
        || parameters.radius_numerator == 0
        || parameters.radius_numerator >= parameters.radius_denominator
    {
        return Err(ZkAuthJohnsonPcsConfigError::InvalidRadius);
    }
    if parameters.query_count == 0 {
        return Err(ZkAuthJohnsonPcsConfigError::InvalidQueryCount);
    }
    if parameters.multiplicity < 3 {
        return Err(ZkAuthJohnsonPcsConfigError::InvalidMultiplicity);
    }
    if parameters.fixed_grind_credit_bits != 0 {
        return Err(ZkAuthJohnsonPcsConfigError::GrindCreditMustBeZero);
    }

    let layers = zk_auth_affine_rs_layers();
    let placeholder =
        conditional_johnson_line_ledger(ZkAuthJohnsonLineKind::Gamma, layers[0], parameters)?;
    let mut lines = [placeholder; 8];
    lines[0] = placeholder;
    let mut round = 0;
    while round < ZK_AUTH_AFFINE_PROXIMITY_FOLD_ROUNDS {
        lines[round + 1] = conditional_johnson_line_ledger(
            ZkAuthJohnsonLineKind::Fold(round),
            layers[round + 1],
            parameters,
        )?;
        round += 1;
    }
    let all_bad_coin_upper_bound = lines.iter().try_fold(0u128, |sum, line| {
        sum.checked_add(line.bad_coin_upper_bound)
            .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)
    })?;

    Ok(ZkAuthConditionalJohnsonPcsLedger {
        parameters,
        lines,
        single_query_miss_numerator: parameters.radius_denominator - parameters.radius_numerator,
        single_query_miss_denominator: parameters.radius_denominator,
        query_term_exponent: parameters.query_count,
        all_bad_coin_upper_bound,
        bad_coin_denominator_bits: parameters.field_bits,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthTranscriptPhase {
    Owner,
    Main,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthProverMessageKind {
    SourceCommitmentAndStatement,
    OwnerMaskEvaluation,
    OwnerMleCheckRound,
    OwnerTerminalClaims,
    OwnerBridgeAndCompanionClaim,
    PhaseARound,
    PhaseBValueAndUpper,
    MidCommitment,
    TailReveal,
    GrindNonce,
}

/// One grouped public-coin edge in the interactive transcript view.
///
/// Vector challenges (`rho[11]`, beta groups, query seeds) count as one
/// verifier move.  Adaptive sumcheck rounds repeat the same edge and therefore
/// set `repetitions > 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthPublicCoinStage {
    pub phase: ZkAuthTranscriptPhase,
    pub prover_message: ZkAuthProverMessageKind,
    pub repetitions: usize,
    pub challenge_fields_per_repetition: usize,
    /// Number of low bits of the first response lane conditioned by an
    /// accepted-output predicate.  Only the nonce stage is conditioned.
    pub conditioned_low_bits: u32,
}

impl ZkAuthPublicCoinStage {
    pub const fn verifier_moves(self) -> usize {
        self.repetitions
    }

    pub const fn challenge_fields(self) -> usize {
        self.repetitions * self.challenge_fields_per_repetition
    }
}

/// Exact grouped transcript DAG of the selected construction.
///
/// The final stage returns the grind lane followed by seven packed query-seed
/// lanes.  In the concrete duplex the first query seed is the second lane of
/// the same 256-bit permutation response as the grind value.  The verifier
/// checks only the low-bit predicate, not nonce minimality, so a malicious
/// prover may choose any satisfying nonce.
pub const ZK_AUTH_PUBLIC_COIN_STAGES: [ZkAuthPublicCoinStage; 10] = [
    ZkAuthPublicCoinStage {
        phase: ZkAuthTranscriptPhase::Owner,
        prover_message: ZkAuthProverMessageKind::SourceCommitmentAndStatement,
        repetitions: 1,
        challenge_fields_per_repetition: ZK_AUTH_MLECHECK_VARS,
        conditioned_low_bits: 0,
    },
    ZkAuthPublicCoinStage {
        phase: ZkAuthTranscriptPhase::Owner,
        prover_message: ZkAuthProverMessageKind::OwnerMaskEvaluation,
        repetitions: 1,
        challenge_fields_per_repetition: 1,
        conditioned_low_bits: 0,
    },
    ZkAuthPublicCoinStage {
        phase: ZkAuthTranscriptPhase::Owner,
        prover_message: ZkAuthProverMessageKind::OwnerMleCheckRound,
        repetitions: ZK_AUTH_MLECHECK_VARS,
        challenge_fields_per_repetition: 1,
        conditioned_low_bits: 0,
    },
    ZkAuthPublicCoinStage {
        phase: ZkAuthTranscriptPhase::Owner,
        prover_message: ZkAuthProverMessageKind::OwnerTerminalClaims,
        repetitions: 1,
        challenge_fields_per_repetition: 1,
        conditioned_low_bits: 0,
    },
    ZkAuthPublicCoinStage {
        phase: ZkAuthTranscriptPhase::Main,
        prover_message: ZkAuthProverMessageKind::OwnerBridgeAndCompanionClaim,
        repetitions: 1,
        challenge_fields_per_repetition: 1,
        conditioned_low_bits: 0,
    },
    ZkAuthPublicCoinStage {
        phase: ZkAuthTranscriptPhase::Main,
        prover_message: ZkAuthProverMessageKind::PhaseARound,
        repetitions: PHASE_A_VARS,
        challenge_fields_per_repetition: 1,
        conditioned_low_bits: 0,
    },
    ZkAuthPublicCoinStage {
        phase: ZkAuthTranscriptPhase::Main,
        prover_message: ZkAuthProverMessageKind::PhaseBValueAndUpper,
        repetitions: 1,
        challenge_fields_per_repetition: SOURCE_STANDARD_FOLDS,
        conditioned_low_bits: 0,
    },
    ZkAuthPublicCoinStage {
        phase: ZkAuthTranscriptPhase::Main,
        prover_message: ZkAuthProverMessageKind::MidCommitment,
        repetitions: 1,
        challenge_fields_per_repetition: MID_STANDARD_FOLDS,
        conditioned_low_bits: 0,
    },
    ZkAuthPublicCoinStage {
        phase: ZkAuthTranscriptPhase::Main,
        prover_message: ZkAuthProverMessageKind::TailReveal,
        repetitions: 1,
        challenge_fields_per_repetition: PHASE_B_LOW_VARS
            - SOURCE_STANDARD_FOLDS
            - MID_STANDARD_FOLDS,
        conditioned_low_bits: 0,
    },
    ZkAuthPublicCoinStage {
        phase: ZkAuthTranscriptPhase::Main,
        prover_message: ZkAuthProverMessageKind::GrindNonce,
        repetitions: 1,
        challenge_fields_per_repetition: 1 + ZK_AUTH_QUERY_SEEDS,
        conditioned_low_bits: ZK_AUTH_GRIND_BITS,
    },
];

pub const ZK_AUTH_OWNER_VERIFIER_MOVES: usize = 1 + 1 + ZK_AUTH_MLECHECK_VARS + 1;
pub const ZK_AUTH_MAIN_VERIFIER_MOVES: usize = 1 + PHASE_A_VARS + 1 + 1 + 1 + 1;
pub const ZK_AUTH_TOTAL_VERIFIER_MOVES: usize =
    ZK_AUTH_OWNER_VERIFIER_MOVES + ZK_AUTH_MAIN_VERIFIER_MOVES;

/// One verifier move in the base interactive IOP underlying the BCS
/// transform.  The accepted-output grind is deliberately absent: it is a
/// transform-level QRO wrapper around the final query-seed move, not an
/// independent uniformly random coin of the base IOP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthIopMove {
    OwnerRho,
    OwnerLambda,
    OwnerMleCheckRound(usize),
    OwnerEta,
    MainGamma,
    PhaseARound(usize),
    BetaSource,
    BetaMid,
    BetaTail,
    QuerySeeds,
}

impl ZkAuthIopMove {
    pub const fn challenge_fields(self) -> usize {
        match self {
            Self::OwnerRho => ZK_AUTH_MLECHECK_VARS,
            Self::OwnerLambda
            | Self::OwnerMleCheckRound(_)
            | Self::OwnerEta
            | Self::MainGamma
            | Self::PhaseARound(_)
            | Self::BetaTail => 1,
            Self::BetaSource => SOURCE_STANDARD_FOLDS,
            Self::BetaMid => MID_STANDARD_FOLDS,
            Self::QuerySeeds => ZK_AUTH_QUERY_SEEDS,
        }
    }
}

pub const fn zk_auth_iop_moves() -> [ZkAuthIopMove; ZK_AUTH_TOTAL_VERIFIER_MOVES] {
    let mut moves = [ZkAuthIopMove::OwnerRho; ZK_AUTH_TOTAL_VERIFIER_MOVES];
    moves[0] = ZkAuthIopMove::OwnerRho;
    moves[1] = ZkAuthIopMove::OwnerLambda;
    let mut cursor = 2;
    let mut round = 0;
    while round < ZK_AUTH_MLECHECK_VARS {
        moves[cursor] = ZkAuthIopMove::OwnerMleCheckRound(round);
        cursor += 1;
        round += 1;
    }
    moves[cursor] = ZkAuthIopMove::OwnerEta;
    cursor += 1;
    moves[cursor] = ZkAuthIopMove::MainGamma;
    cursor += 1;
    round = 0;
    while round < PHASE_A_VARS {
        moves[cursor] = ZkAuthIopMove::PhaseARound(round);
        cursor += 1;
        round += 1;
    }
    moves[cursor] = ZkAuthIopMove::BetaSource;
    cursor += 1;
    moves[cursor] = ZkAuthIopMove::BetaMid;
    cursor += 1;
    moves[cursor] = ZkAuthIopMove::BetaTail;
    cursor += 1;
    moves[cursor] = ZkAuthIopMove::QuerySeeds;
    moves
}

pub const ZK_AUTH_BASE_IOP_CHALLENGE_FIELDS: usize =
    ZK_AUTH_OWNER_SQUEEZES + ZK_AUTH_MAIN_SQUEEZES - 1;
pub const ZK_AUTH_COMPILED_CONDITIONED_GRIND_FIELDS: usize = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthIopFinalResponseKind {
    /// Logical oracle answers only. Merkle caps and authentication siblings
    /// belong to the BCS wrapper, not to epsilon_RBR of the base IOP.
    SourceAndMidQueryAnswers,
}

/// Exact boundary between the RBR object and the noninteractive wrapper.
/// No numeric proximity/RBR error is asserted here; that remains a separate
/// proof obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthRbrIopProfile {
    pub verifier_moves: usize,
    pub public_coin_fields: usize,
    pub owner_degree_ten_rounds: usize,
    pub owner_round_degree: usize,
    pub post_claim_rlc_claims: usize,
    pub post_claim_bad_polynomial_degree: usize,
    pub phase_a_degree_two_rounds: usize,
    pub phase_a_round_degree: usize,
    pub final_query_seed_fields: usize,
    pub query_salt_fields: usize,
    pub query_salt_domain_bits: usize,
    pub final_response: ZkAuthIopFinalResponseKind,
    pub final_query_answer_fields: usize,
    pub merkle_wrapper_fields_included: bool,
    pub compiled_conditioned_grind_fields: usize,
}

pub const ZK_AUTH_RBR_IOP_PROFILE: ZkAuthRbrIopProfile = ZkAuthRbrIopProfile {
    verifier_moves: ZK_AUTH_TOTAL_VERIFIER_MOVES,
    public_coin_fields: ZK_AUTH_BASE_IOP_CHALLENGE_FIELDS,
    owner_degree_ten_rounds: ZK_AUTH_MLECHECK_VARS,
    owner_round_degree: ZK_MLECHECK_MASK_DEGREE,
    post_claim_rlc_claims: ZK_AUTH_CAPSULE_POST_CLAIMS,
    post_claim_bad_polynomial_degree: ZK_AUTH_CAPSULE_POST_CLAIMS - 1,
    phase_a_degree_two_rounds: PHASE_A_VARS,
    phase_a_round_degree: PHASE_A_ROUND_DEGREE,
    final_query_seed_fields: ZK_AUTH_QUERY_SEEDS,
    query_salt_fields: 1,
    query_salt_domain_bits: u64::BITS as usize,
    final_response: ZkAuthIopFinalResponseKind::SourceAndMidQueryAnswers,
    final_query_answer_fields: ZK_AUTH_BASE_FINAL_QUERY_ANSWER_FIELDS,
    merkle_wrapper_fields_included: false,
    compiled_conditioned_grind_fields: ZK_AUTH_COMPILED_CONDITIONED_GRIND_FIELDS,
};

pub const ZK_AUTH_BASE_SOURCE_ORACLE_FIELDS: usize = ZK_CAPSULE_PCS_SOURCE_LEAF_COUNT * 16;
pub const ZK_AUTH_BASE_MID_ORACLE_FIELDS: usize = ZK_CAPSULE_PCS_MID_CODE_LEN;
pub const ZK_AUTH_BASE_FINAL_QUERY_ANSWER_FIELDS: usize = ZK_AUTH_QUERY_COUNT
    * (ZK_AUTH_CAPSULE_GEOMETRY.source_leaf_symbols + (1 << MID_STANDARD_FOLDS));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthBaseIopProverMessageKind {
    SourceOracle,
    OwnerMaskEvaluation,
    OwnerMleCheckRound(usize),
    OwnerTerminalClaims,
    CompanionClaim,
    PhaseARound(usize),
    PhaseBValueAndUpper,
    MidOracle,
    TailReveal,
    /// The compiled proof serializes this as the grind nonce. In the base IOP
    /// it is unconstrained within the canonical 64-bit salt alphabet and
    /// receives no soundness credit.
    QuerySaltNonce,
}

impl ZkAuthBaseIopProverMessageKind {
    pub const fn logical_fields(self) -> usize {
        match self {
            Self::SourceOracle => ZK_AUTH_BASE_SOURCE_ORACLE_FIELDS,
            Self::OwnerMaskEvaluation => 1,
            Self::OwnerMleCheckRound(_) => ZK_MLECHECK_MASK_DEGREE,
            Self::OwnerTerminalClaims => 1 + ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS,
            Self::CompanionClaim => 1,
            Self::PhaseARound(_) => PHASE_A_ROUND_DEGREE,
            Self::PhaseBValueAndUpper => 1 + UPPER_SYMBOLS,
            Self::MidOracle => ZK_AUTH_BASE_MID_ORACLE_FIELDS,
            Self::TailReveal => TAIL_SYMBOLS,
            Self::QuerySaltNonce => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthRbrPrecoinCheckpoint {
    SourceOracleFixed,
    OwnerMaskEvaluationFixed,
    OwnerRoundMessageFixed { round: usize },
    OwnerTerminalClaimsFixed,
    CompanionClaimFixed,
    PhaseARoundMessageFixed { round: usize },
    PhaseBValueAndUpperFixed,
    MidOracleFixed,
    TailFixed,
    QuerySaltFixed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthRbrPostcoinState {
    OwnerZeroCheckPointFixed,
    OwnerMaskBatchInitialized,
    OwnerTelescope { completed_rounds: usize },
    OwnerPostClaimRelationFixed,
    PhaseABatchInitialized,
    PhaseATelescope { completed_rounds: usize },
    SourceFoldPointFixed,
    MidFoldPointFixed,
    UpperTailLinkClosed,
    QueriesDerived,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthRbrBoundClass {
    MultilinearZeroCheck {
        variables: usize,
        individual_degree: usize,
        total_degree: usize,
    },
    AffineBatch {
        bad_degree: usize,
        rejected_points: usize,
    },
    Sumcheck {
        max_degree: usize,
    },
    RandomLinearCombination {
        claims: usize,
        bad_degree: usize,
        rejected_points: usize,
    },
    AffineFoldProximity {
        folds: usize,
    },
    AffineEquality {
        bad_degree: usize,
    },
    OracleSampling {
        seed_fields: usize,
        used_bits: usize,
        queries: usize,
        index_bits: usize,
        with_replacement: bool,
    },
}

/// One row of the exact base-IOP move/checkpoint inventory. Caps, Merkle
/// siblings and the conditioned grind lane cannot appear here. This inventory
/// does not itself supply restoration maps, a doomed set, or per-move lemmas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthRbrMoveProfile {
    pub index: usize,
    pub move_: ZkAuthIopMove,
    pub prover_message_before_coin: ZkAuthBaseIopProverMessageKind,
    pub atomic_challenge_fields: usize,
    pub precoin_checkpoint: ZkAuthRbrPrecoinCheckpoint,
    pub postcoin_state: ZkAuthRbrPostcoinState,
    pub bound_class: ZkAuthRbrBoundClass,
}

pub const fn zk_auth_rbr_move_profiles() -> [ZkAuthRbrMoveProfile; ZK_AUTH_TOTAL_VERIFIER_MOVES] {
    let placeholder = ZkAuthRbrMoveProfile {
        index: 0,
        move_: ZkAuthIopMove::OwnerRho,
        prover_message_before_coin: ZkAuthBaseIopProverMessageKind::SourceOracle,
        atomic_challenge_fields: ZK_AUTH_MLECHECK_VARS,
        precoin_checkpoint: ZkAuthRbrPrecoinCheckpoint::SourceOracleFixed,
        postcoin_state: ZkAuthRbrPostcoinState::OwnerZeroCheckPointFixed,
        bound_class: ZkAuthRbrBoundClass::MultilinearZeroCheck {
            variables: ZK_AUTH_MLECHECK_VARS,
            individual_degree: 1,
            total_degree: ZK_AUTH_MLECHECK_VARS,
        },
    };
    let mut profiles = [placeholder; ZK_AUTH_TOTAL_VERIFIER_MOVES];
    profiles[0] = placeholder;
    profiles[1] = ZkAuthRbrMoveProfile {
        index: 1,
        move_: ZkAuthIopMove::OwnerLambda,
        prover_message_before_coin: ZkAuthBaseIopProverMessageKind::OwnerMaskEvaluation,
        atomic_challenge_fields: 1,
        precoin_checkpoint: ZkAuthRbrPrecoinCheckpoint::OwnerMaskEvaluationFixed,
        postcoin_state: ZkAuthRbrPostcoinState::OwnerMaskBatchInitialized,
        bound_class: ZkAuthRbrBoundClass::AffineBatch {
            bad_degree: 1,
            rejected_points: 1,
        },
    };
    let mut cursor = 2;
    let mut round = 0;
    while round < ZK_AUTH_MLECHECK_VARS {
        profiles[cursor] = ZkAuthRbrMoveProfile {
            index: cursor,
            move_: ZkAuthIopMove::OwnerMleCheckRound(round),
            prover_message_before_coin: ZkAuthBaseIopProverMessageKind::OwnerMleCheckRound(round),
            atomic_challenge_fields: 1,
            precoin_checkpoint: ZkAuthRbrPrecoinCheckpoint::OwnerRoundMessageFixed { round },
            postcoin_state: ZkAuthRbrPostcoinState::OwnerTelescope {
                completed_rounds: round + 1,
            },
            bound_class: ZkAuthRbrBoundClass::Sumcheck {
                max_degree: ZK_MLECHECK_MASK_DEGREE,
            },
        };
        cursor += 1;
        round += 1;
    }
    profiles[cursor] = ZkAuthRbrMoveProfile {
        index: cursor,
        move_: ZkAuthIopMove::OwnerEta,
        prover_message_before_coin: ZkAuthBaseIopProverMessageKind::OwnerTerminalClaims,
        atomic_challenge_fields: 1,
        precoin_checkpoint: ZkAuthRbrPrecoinCheckpoint::OwnerTerminalClaimsFixed,
        postcoin_state: ZkAuthRbrPostcoinState::OwnerPostClaimRelationFixed,
        bound_class: ZkAuthRbrBoundClass::RandomLinearCombination {
            claims: ZK_AUTH_CAPSULE_POST_CLAIMS,
            bad_degree: ZK_AUTH_CAPSULE_POST_CLAIMS - 1,
            rejected_points: 1,
        },
    };
    cursor += 1;
    profiles[cursor] = ZkAuthRbrMoveProfile {
        index: cursor,
        move_: ZkAuthIopMove::MainGamma,
        prover_message_before_coin: ZkAuthBaseIopProverMessageKind::CompanionClaim,
        atomic_challenge_fields: 1,
        precoin_checkpoint: ZkAuthRbrPrecoinCheckpoint::CompanionClaimFixed,
        postcoin_state: ZkAuthRbrPostcoinState::PhaseABatchInitialized,
        bound_class: ZkAuthRbrBoundClass::AffineBatch {
            bad_degree: 1,
            rejected_points: 2,
        },
    };
    cursor += 1;
    round = 0;
    while round < PHASE_A_VARS {
        profiles[cursor] = ZkAuthRbrMoveProfile {
            index: cursor,
            move_: ZkAuthIopMove::PhaseARound(round),
            prover_message_before_coin: ZkAuthBaseIopProverMessageKind::PhaseARound(round),
            atomic_challenge_fields: 1,
            precoin_checkpoint: ZkAuthRbrPrecoinCheckpoint::PhaseARoundMessageFixed { round },
            postcoin_state: ZkAuthRbrPostcoinState::PhaseATelescope {
                completed_rounds: round + 1,
            },
            bound_class: ZkAuthRbrBoundClass::Sumcheck {
                max_degree: PHASE_A_ROUND_DEGREE,
            },
        };
        cursor += 1;
        round += 1;
    }
    profiles[cursor] = ZkAuthRbrMoveProfile {
        index: cursor,
        move_: ZkAuthIopMove::BetaSource,
        prover_message_before_coin: ZkAuthBaseIopProverMessageKind::PhaseBValueAndUpper,
        atomic_challenge_fields: SOURCE_STANDARD_FOLDS,
        precoin_checkpoint: ZkAuthRbrPrecoinCheckpoint::PhaseBValueAndUpperFixed,
        postcoin_state: ZkAuthRbrPostcoinState::SourceFoldPointFixed,
        bound_class: ZkAuthRbrBoundClass::AffineFoldProximity {
            folds: SOURCE_STANDARD_FOLDS,
        },
    };
    cursor += 1;
    profiles[cursor] = ZkAuthRbrMoveProfile {
        index: cursor,
        move_: ZkAuthIopMove::BetaMid,
        prover_message_before_coin: ZkAuthBaseIopProverMessageKind::MidOracle,
        atomic_challenge_fields: MID_STANDARD_FOLDS,
        precoin_checkpoint: ZkAuthRbrPrecoinCheckpoint::MidOracleFixed,
        postcoin_state: ZkAuthRbrPostcoinState::MidFoldPointFixed,
        bound_class: ZkAuthRbrBoundClass::AffineFoldProximity {
            folds: MID_STANDARD_FOLDS,
        },
    };
    cursor += 1;
    profiles[cursor] = ZkAuthRbrMoveProfile {
        index: cursor,
        move_: ZkAuthIopMove::BetaTail,
        prover_message_before_coin: ZkAuthBaseIopProverMessageKind::TailReveal,
        atomic_challenge_fields: 1,
        precoin_checkpoint: ZkAuthRbrPrecoinCheckpoint::TailFixed,
        postcoin_state: ZkAuthRbrPostcoinState::UpperTailLinkClosed,
        bound_class: ZkAuthRbrBoundClass::AffineEquality { bad_degree: 1 },
    };
    cursor += 1;
    profiles[cursor] = ZkAuthRbrMoveProfile {
        index: cursor,
        move_: ZkAuthIopMove::QuerySeeds,
        prover_message_before_coin: ZkAuthBaseIopProverMessageKind::QuerySaltNonce,
        atomic_challenge_fields: ZK_AUTH_QUERY_SEEDS,
        precoin_checkpoint: ZkAuthRbrPrecoinCheckpoint::QuerySaltFixed,
        postcoin_state: ZkAuthRbrPostcoinState::QueriesDerived,
        bound_class: ZkAuthRbrBoundClass::OracleSampling {
            seed_fields: ZK_AUTH_QUERY_SEEDS,
            used_bits: ZK_AUTH_QUERY_COUNT * ZK_AUTH_QUERY_WIDTH_BITS,
            queries: ZK_AUTH_QUERY_COUNT,
            index_bits: ZK_AUTH_QUERY_WIDTH_BITS,
            with_replacement: true,
        },
    };
    profiles
}

/// Exact Schwartz--Zippel/root-count inventory outside the affine PCS
/// proximity and final query-sampling terms.  Rejected challenge endpoints
/// make the verifier reject and therefore do not count as accepting bad
/// coins in the unconditional base-IOP experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthConditionalAlgebraicBadCoinLedger {
    pub owner_zero_check: u128,
    pub owner_lambda_batch: u128,
    pub owner_sumchecks: u128,
    pub owner_eta_rlc: u128,
    pub main_gamma_batch: u128,
    pub phase_a_sumchecks: u128,
    pub beta_tail_equality: u128,
    pub rejected_endpoints_not_counted: u128,
    pub total_bad_coin_upper_bound: u128,
    pub denominator_bits: u32,
}

pub const fn conditional_zk_auth_algebraic_bad_coin_ledger(
) -> ZkAuthConditionalAlgebraicBadCoinLedger {
    let profiles = zk_auth_rbr_move_profiles();
    let mut ledger = ZkAuthConditionalAlgebraicBadCoinLedger {
        owner_zero_check: 0,
        owner_lambda_batch: 0,
        owner_sumchecks: 0,
        owner_eta_rlc: 0,
        main_gamma_batch: 0,
        phase_a_sumchecks: 0,
        beta_tail_equality: 0,
        rejected_endpoints_not_counted: 0,
        total_bad_coin_upper_bound: 0,
        denominator_bits: ZK_AUTH_EFFECTIVE_CHALLENGE_BITS,
    };
    let mut index = 0;
    while index < profiles.len() {
        let profile = profiles[index];
        let bad = match profile.bound_class {
            ZkAuthRbrBoundClass::MultilinearZeroCheck { total_degree, .. } => total_degree as u128,
            ZkAuthRbrBoundClass::AffineBatch {
                bad_degree,
                rejected_points,
            } => {
                ledger.rejected_endpoints_not_counted += rejected_points as u128;
                bad_degree as u128
            }
            ZkAuthRbrBoundClass::Sumcheck { max_degree } => max_degree as u128,
            ZkAuthRbrBoundClass::RandomLinearCombination {
                bad_degree,
                rejected_points,
                ..
            } => {
                ledger.rejected_endpoints_not_counted += rejected_points as u128;
                bad_degree as u128
            }
            ZkAuthRbrBoundClass::AffineEquality { bad_degree } => bad_degree as u128,
            ZkAuthRbrBoundClass::AffineFoldProximity { .. }
            | ZkAuthRbrBoundClass::OracleSampling { .. } => 0,
        };
        match profile.move_ {
            ZkAuthIopMove::OwnerRho => ledger.owner_zero_check += bad,
            ZkAuthIopMove::OwnerLambda => ledger.owner_lambda_batch += bad,
            ZkAuthIopMove::OwnerMleCheckRound(_) => ledger.owner_sumchecks += bad,
            ZkAuthIopMove::OwnerEta => ledger.owner_eta_rlc += bad,
            ZkAuthIopMove::MainGamma => ledger.main_gamma_batch += bad,
            ZkAuthIopMove::PhaseARound(_) => ledger.phase_a_sumchecks += bad,
            ZkAuthIopMove::BetaTail => ledger.beta_tail_equality += bad,
            ZkAuthIopMove::BetaSource | ZkAuthIopMove::BetaMid | ZkAuthIopMove::QuerySeeds => {}
        }
        ledger.total_bad_coin_upper_bound += bad;
        index += 1;
    }
    ledger
}

/// Fail-closed scalar union for the selected q=65 base IOP before the BCS
/// compiler.  The Main gamma algebraic root and gamma proximity exception use
/// the same coin and are therefore added, never multiplied. Algebraic roots
/// are unioned over the fixed initial bank/companion candidate pairs; a later
/// continuation need not choose its candidate before seeing the challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthConditionalBaseIopLedger {
    pub johnson: ZkAuthConditionalJohnsonPcsLedger,
    pub algebraic: ZkAuthConditionalAlgebraicBadCoinLedger,
    pub max_initial_candidate_pairs: usize,
    /// The first seven variables of the fixed upper-link multilinear are
    /// substituted in the 3+4 grouped fold moves. BetaTail already contributes
    /// the eighth variable in the scalar algebraic inventory.
    pub grouped_upper_link_bad_coin_upper_bound: u128,
    pub candidate_algebraic_bad_coin_upper_bound: u128,
    pub all_field_bad_coin_upper_bound: u128,
    pub field_denominator_bits: u32,
    pub single_query_miss_numerator: u128,
    pub single_query_miss_denominator: u128,
    pub query_term_exponent: usize,
    pub shared_gamma_events_are_unioned: bool,
}

impl ZkAuthConditionalBaseIopLedger {
    pub fn diagnostic_query_term_bits(self) -> f64 {
        let miss =
            self.single_query_miss_numerator as f64 / self.single_query_miss_denominator as f64;
        -(self.query_term_exponent as f64) * miss.log2()
    }

    pub fn diagnostic_field_bad_coin_bits(self) -> f64 {
        self.field_denominator_bits as f64 - (self.all_field_bad_coin_upper_bound as f64).log2()
    }

    pub fn diagnostic_conditional_union_bits(self) -> f64 {
        let query = 2f64.powf(-self.diagnostic_query_term_bits());
        let field = (self.all_field_bad_coin_upper_bound as f64)
            * 2f64.powi(-(self.field_denominator_bits as i32));
        -(query + field).log2()
    }
}

pub fn conditional_selected_zk_auth_base_iop_ledger(
) -> Result<ZkAuthConditionalBaseIopLedger, ZkAuthJohnsonPcsConfigError> {
    let johnson =
        conditional_selected_zk_auth_johnson_pcs_ledger(ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS)?;
    let algebraic = conditional_zk_auth_algebraic_bad_coin_ledger();
    let max_candidates = selected_zk_auth_johnson_list_size_ledger().global_max_candidate_list_size;
    let max_initial_candidate_pairs = max_candidates
        .checked_mul(max_candidates)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;
    let grouped_upper_link_bad_coin_upper_bound =
        (SOURCE_STANDARD_FOLDS + MID_STANDARD_FOLDS) as u128;
    let candidate_algebraic_bad_coin_upper_bound = algebraic
        .total_bad_coin_upper_bound
        .checked_add(grouped_upper_link_bad_coin_upper_bound)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?
        .checked_mul(max_initial_candidate_pairs as u128)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;
    let all_field_bad_coin_upper_bound = johnson
        .all_bad_coin_upper_bound
        .checked_add(candidate_algebraic_bad_coin_upper_bound)
        .ok_or(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)?;
    Ok(ZkAuthConditionalBaseIopLedger {
        johnson,
        algebraic,
        max_initial_candidate_pairs,
        grouped_upper_link_bad_coin_upper_bound,
        candidate_algebraic_bad_coin_upper_bound,
        all_field_bad_coin_upper_bound,
        field_denominator_bits: ZK_AUTH_EFFECTIVE_CHALLENGE_BITS,
        single_query_miss_numerator: johnson.single_query_miss_numerator,
        single_query_miss_denominator: johnson.single_query_miss_denominator,
        query_term_exponent: johnson.query_term_exponent,
        shared_gamma_events_are_unioned: true,
    })
}

/// Exact public-coin tape reconstructed from one accepted noninteractive
/// proof.  Keeping this separate from Poseidon transcript mechanics gives the
/// RBR/HVZK arguments a concrete interactive object to reason about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAuthChallengeTape {
    pub owner_rho: [Block256; ZK_AUTH_MLECHECK_VARS],
    pub owner_lambda: Block256,
    pub owner_rounds_high_to_low: [Block256; ZK_AUTH_MLECHECK_VARS],
    pub owner_eta: Block256,
    pub main_gamma: Block256,
    pub phase_a_high_to_low: [Block256; PHASE_A_VARS],
    pub beta_source: [Block256; SOURCE_STANDARD_FOLDS],
    pub beta_mid: [Block256; MID_STANDARD_FOLDS],
    pub beta_tail: Block256,
    /// Transform-level accepted-output lane. It is not returned through
    /// [`Self::challenge_group`] because it is not a base-IOP public coin.
    pub compiled_grind: Block128,
    pub query_seeds: [Block128; ZK_AUTH_QUERY_SEEDS],
}

impl ZkAuthChallengeTape {
    pub fn from_verified(verified: &ZkAuthorizationVerified) -> Self {
        Self {
            owner_rho: verified.owner.rho,
            owner_lambda: verified.owner.lambda,
            owner_rounds_high_to_low: verified.owner.round_challenges_high_to_low,
            owner_eta: verified.owner.eta,
            main_gamma: verified.gamma,
            phase_a_high_to_low: verified.phase_a_challenges_high_to_low,
            beta_source: verified.beta[..SOURCE_STANDARD_FOLDS]
                .try_into()
                .expect("selected beta source width"),
            beta_mid: verified.beta[SOURCE_STANDARD_FOLDS..PHASE_B_LOW_VARS - 1]
                .try_into()
                .expect("selected beta mid width"),
            beta_tail: verified.beta[PHASE_B_LOW_VARS - 1],
            compiled_grind: verified.grind,
            query_seeds: verified.query_seeds,
        }
    }

    pub fn algebraic_challenge_group(&self, move_: ZkAuthIopMove) -> Option<&[Block256]> {
        Some(match move_ {
            ZkAuthIopMove::OwnerRho => &self.owner_rho,
            ZkAuthIopMove::OwnerLambda => std::slice::from_ref(&self.owner_lambda),
            ZkAuthIopMove::OwnerMleCheckRound(round) => {
                std::slice::from_ref(self.owner_rounds_high_to_low.get(round)?)
            }
            ZkAuthIopMove::OwnerEta => std::slice::from_ref(&self.owner_eta),
            ZkAuthIopMove::MainGamma => std::slice::from_ref(&self.main_gamma),
            ZkAuthIopMove::PhaseARound(round) => {
                std::slice::from_ref(self.phase_a_high_to_low.get(round)?)
            }
            ZkAuthIopMove::BetaSource => &self.beta_source,
            ZkAuthIopMove::BetaMid => &self.beta_mid,
            ZkAuthIopMove::BetaTail => std::slice::from_ref(&self.beta_tail),
            ZkAuthIopMove::QuerySeeds => return None,
        })
    }

    pub fn has_admissible_base_challenges(&self) -> bool {
        self.owner_lambda != Block256::ZERO
            && self.owner_eta != Block256::ZERO
            && self.main_gamma != Block256::ZERO
            && self.main_gamma != Block256::ONE
    }

    pub fn compiled_grind_is_valid(&self) -> bool {
        zk_authorization_grind_is_valid(self.compiled_grind)
    }
}

/// Concrete exponent terms before the hidden constant in the CMS/BCS bound.
///
/// If `epsilon_rbr <= 2^-base_soundness_bits` and a quantum adversary makes
/// at most `t <= 2^oracle_query_budget_bits` oracle queries, the two displayed
/// terms have the exponents below.  Their sum loses at least one more bit.
/// This function does not turn the theorem's big-O constant into evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BcsQromExponentLedger {
    pub rbr_term_bits: i32,
    pub oracle_term_bits: i32,
    pub preconstant_union_floor_bits: i32,
}

pub const fn bcs_qrom_exponent_ledger(
    base_soundness_bits: u32,
    oracle_query_budget_bits: u32,
    oracle_output_bits: u32,
) -> BcsQromExponentLedger {
    let rbr_term_bits = base_soundness_bits as i32 - 2 * oracle_query_budget_bits as i32;
    let oracle_term_bits = oracle_output_bits as i32 - 3 * oracle_query_budget_bits as i32;
    let minimum = if rbr_term_bits < oracle_term_bits {
        rbr_term_bits
    } else {
        oracle_term_bits
    };
    BcsQromExponentLedger {
        rbr_term_bits,
        oracle_term_bits,
        preconstant_union_floor_bits: minimum - 1,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthQromFeasibilityError {
    ConditionalBaseIop(ZkAuthJohnsonPcsConfigError),
    ArithmeticOverflow,
}

/// Sufficient per-term bit budgets obtained by allocating half of the target
/// error to each of the two displayed CMS/BCS terms.
///
/// For target `s`, at most `2^L` lifetime targets and at most `2^q` QRO
/// queries, this requires base-IOP bits `>= s + L + 2q + 1` and oracle-output
/// bits `>= s + L + 3q + 1`.  It is only a generic arithmetic prerequisite;
/// it does not account for the theorem's hidden constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthQromRequiredTermBudgets {
    pub target_bits: u32,
    pub oracle_query_budget_exponent: u32,
    pub lifetime_union_exponent: u32,
    pub one_bit_term_split: u32,
    pub required_base_iop_bits: u32,
    pub required_oracle_output_bits: u32,
}

pub fn zk_auth_qrom_required_term_budgets(
    target_bits: u32,
    oracle_query_budget_exponent: u32,
    lifetime_union_exponent: u32,
) -> Result<ZkAuthQromRequiredTermBudgets, ZkAuthQromFeasibilityError> {
    let twice_query_budget = oracle_query_budget_exponent
        .checked_mul(2)
        .ok_or(ZkAuthQromFeasibilityError::ArithmeticOverflow)?;
    let thrice_query_budget = oracle_query_budget_exponent
        .checked_mul(3)
        .ok_or(ZkAuthQromFeasibilityError::ArithmeticOverflow)?;
    let target_and_lifetime = target_bits
        .checked_add(lifetime_union_exponent)
        .ok_or(ZkAuthQromFeasibilityError::ArithmeticOverflow)?;
    let required_base_iop_bits = target_and_lifetime
        .checked_add(twice_query_budget)
        .and_then(|bits| bits.checked_add(1))
        .ok_or(ZkAuthQromFeasibilityError::ArithmeticOverflow)?;
    let required_oracle_output_bits = target_and_lifetime
        .checked_add(thrice_query_budget)
        .and_then(|bits| bits.checked_add(1))
        .ok_or(ZkAuthQromFeasibilityError::ArithmeticOverflow)?;
    Ok(ZkAuthQromRequiredTermBudgets {
        target_bits,
        oracle_query_budget_exponent,
        lifetime_union_exponent,
        one_bit_term_split: 1,
        required_base_iop_bits,
        required_oracle_output_bits,
    })
}

/// Fail-closed feasibility screen for the selected q=65 base IOP under the
/// pre-hidden-constant CMS/BCS expression.
///
/// The exact symbolic bound represented here is
///
/// ```text
/// 2^L * (2^(2q) * (A / 2^255 + (1 / 5)^65) + 2^(3q-lambda)),
/// ```
///
/// where `A` and the other base-IOP parameters come directly from
/// [`conditional_selected_zk_auth_base_iop_ledger`].  Floating-point methods
/// below are display diagnostics computed from that exact representation;
/// they are never promoted into claimed security bits.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ZkAuthConditionalQromFeasibilityLedger {
    pub base_iop: ZkAuthConditionalBaseIopLedger,
    pub target_bits: u32,
    pub oracle_query_budget_exponent: u32,
    pub lifetime_union_exponent: u32,
    pub oracle_output_bits: u32,
    pub rbr_total_multiplier_exponent: u32,
    pub oracle_total_numerator_exponent: u32,
    pub required_term_budgets: ZkAuthQromRequiredTermBudgets,
}

impl ZkAuthConditionalQromFeasibilityLedger {
    /// Diagnostic bits of `2^(L+2q) * epsilon_RBR`.
    pub fn diagnostic_scaled_rbr_term_bits(self) -> f64 {
        self.base_iop.diagnostic_conditional_union_bits()
            - self.rbr_total_multiplier_exponent as f64
    }

    /// Diagnostic bits of `2^(L+3q-lambda)`.
    pub fn diagnostic_oracle_term_bits(self) -> f64 {
        self.oracle_output_bits as f64 - self.oracle_total_numerator_exponent as f64
    }

    /// Diagnostic bits of the sum of the two displayed CMS/BCS terms after
    /// lifetime union, but before its hidden multiplicative constant.
    pub fn diagnostic_preconstant_lifetime_union_bits(self) -> f64 {
        let rbr_bits = self.diagnostic_scaled_rbr_term_bits();
        let oracle_bits = self.diagnostic_oracle_term_bits();
        let minimum = rbr_bits.min(oracle_bits);
        let maximum = rbr_bits.max(oracle_bits);
        minimum - (1.0 + 2f64.powf(minimum - maximum)).log2()
    }

    pub fn meets_target(self) -> bool {
        self.diagnostic_preconstant_lifetime_union_bits() >= self.target_bits as f64
    }
}

pub fn conditional_selected_zk_auth_qrom_feasibility_ledger(
    target_bits: u32,
    oracle_query_budget_exponent: u32,
    lifetime_union_exponent: u32,
    oracle_output_bits: u32,
) -> Result<ZkAuthConditionalQromFeasibilityLedger, ZkAuthQromFeasibilityError> {
    let base_iop = conditional_selected_zk_auth_base_iop_ledger()
        .map_err(ZkAuthQromFeasibilityError::ConditionalBaseIop)?;
    let twice_query_budget = oracle_query_budget_exponent
        .checked_mul(2)
        .ok_or(ZkAuthQromFeasibilityError::ArithmeticOverflow)?;
    let thrice_query_budget = oracle_query_budget_exponent
        .checked_mul(3)
        .ok_or(ZkAuthQromFeasibilityError::ArithmeticOverflow)?;
    let rbr_total_multiplier_exponent = lifetime_union_exponent
        .checked_add(twice_query_budget)
        .ok_or(ZkAuthQromFeasibilityError::ArithmeticOverflow)?;
    let oracle_total_numerator_exponent = lifetime_union_exponent
        .checked_add(thrice_query_budget)
        .ok_or(ZkAuthQromFeasibilityError::ArithmeticOverflow)?;
    let required_term_budgets = zk_auth_qrom_required_term_budgets(
        target_bits,
        oracle_query_budget_exponent,
        lifetime_union_exponent,
    )?;
    Ok(ZkAuthConditionalQromFeasibilityLedger {
        base_iop,
        target_bits,
        oracle_query_budget_exponent,
        lifetime_union_exponent,
        oracle_output_bits,
        rbr_total_multiplier_exponent,
        oracle_total_numerator_exponent,
        required_term_budgets,
    })
}

pub const ZK_AUTH_SELECTED_QROM_DIAGNOSTIC_TARGET_BITS: u32 = WALLET_QROM_TARGET_BITS;
pub const ZK_AUTH_SELECTED_QROM_DIAGNOSTIC_QUERY_BUDGET_EXPONENT: u32 = 8;
pub const ZK_AUTH_SELECTED_QROM_DIAGNOSTIC_LIFETIME_EXPONENT: u32 = 0;
pub const ZK_AUTH_SELECTED_QROM_DIAGNOSTIC_ORACLE_OUTPUT_BITS: u32 = HASH_PREIMAGE_PQ_BITS;

/// The selected executable arithmetic gate for the q65/rate-1/32 capsule.
///
/// It changes no capsule/PCS geometry.
pub fn conditional_selected_zk_auth_qrom_diagnostic(
) -> Result<ZkAuthConditionalQromFeasibilityLedger, ZkAuthQromFeasibilityError> {
    conditional_selected_zk_auth_qrom_feasibility_ledger(
        ZK_AUTH_SELECTED_QROM_DIAGNOSTIC_TARGET_BITS,
        ZK_AUTH_SELECTED_QROM_DIAGNOSTIC_QUERY_BUDGET_EXPONENT,
        ZK_AUTH_SELECTED_QROM_DIAGNOSTIC_LIFETIME_EXPONENT,
        ZK_AUTH_SELECTED_QROM_DIAGNOSTIC_ORACLE_OUTPUT_BITS,
    )
}

#[inline]
#[cfg(test)]
fn draw_simulator_base_field(rng: &mut (impl CryptoRng + RngCore + ?Sized)) -> Block128 {
    Block128::from(((rng.next_u64() as u128) << 64) | rng.next_u64() as u128)
}

#[inline]
#[cfg(test)]
fn draw_simulator_field(rng: &mut (impl CryptoRng + RngCore + ?Sized)) -> Block256 {
    Block256::new(
        draw_simulator_base_field(rng),
        draw_simulator_base_field(rng),
    )
}

/// Construct one accepting Owner transcript view without a bank, state table,
/// or spend secret.
///
/// This is the first executable honest-verifier-ZK sufficiency step.  It
/// samples the 111 independent Libra observations (`mask_mu` plus ten
/// nonconstant coefficients in each of eleven rounds), replays every adaptive
/// challenge, samples the five independently padded terminal operands, and
/// solves the sole intended telescope relation for `mask_final`.  The ordinary
/// transcript-only verifier then reconstructs the post-claim relation and
/// bridge.
///
/// This does not simulate the source/Merkle commitment or discharge the
/// returned bank relation.  It is therefore not an authorization forgery and
/// not yet a full ROM/QROM simulator.  A zero lambda, eta, or terminal
/// blinding weight aborts this attempt; a caller modeling an honest retry must
/// use a new independently fresh source commitment rather than resampling
/// against the same cap.
#[cfg(test)]
fn simulate_zk_auth_capsule_owner_view(
    statement: ZkAuthCapsuleOwnerStatement,
    source_cap: &[Block128; ZK_AUTH_SOURCE_CAP_LANES],
    rng: &mut (impl CryptoRng + RngCore + ?Sized),
) -> Result<ZkAuthCapsuleOwnerProverOutput, ZkAuthCapsuleOwnerError> {
    let mut channel = Poseidon2bWideChannel::new();
    absorb_owner_prefix(&mut channel, statement, source_cap);
    let rho = squeeze_wide_array::<ZK_AUTH_MLECHECK_VARS>(&mut channel);

    let mask_mu = draw_simulator_field(rng);
    channel.absorb_wide(mask_mu);
    let lambda = channel.squeeze_wide();
    if lambda == Block256::ZERO {
        return Err(ZkAuthCapsuleOwnerError::LambdaZero);
    }

    let mut verifier = ZkMleCheckVerifierState::new(rho, Block256::ZERO, mask_mu, lambda);
    let mut round_challenges_high_to_low = [Block256::ZERO; ZK_AUTH_MLECHECK_VARS];
    let mut rounds = Vec::with_capacity(ZK_AUTH_OWNER_PROOF_ROUNDS);
    for (round_index, challenge_slot) in round_challenges_high_to_low.iter_mut().enumerate() {
        let round = ZkMleCheckRoundProof {
            coeffs_without_constant: std::array::from_fn(|_| draw_simulator_field(rng)),
        };
        absorb_round(&mut channel, &round);
        let challenge = channel.squeeze_wide();
        *challenge_slot = challenge;
        verifier.transition(&round, challenge)?;
        debug_assert_eq!(round_index + 1, verifier.completed_rounds());
        rounds.push(round);
    }

    let terminal_point = std::array::from_fn(|variable| {
        round_challenges_high_to_low[ZK_AUTH_MLECHECK_VARS - 1 - variable]
    });
    let terminal_operands = AuthCapsuleTerminalOperandClaims {
        increment: draw_simulator_field(rng),
        lane: std::array::from_fn(|_| draw_simulator_field(rng)),
    };
    let main_final = evaluate_auth_main_terminal_from_claims(&terminal_point, terminal_operands)?;
    let mask_final = (verifier.running_claim() - main_final) * lambda.invert();
    let terminal_operand_claims = terminal_operands.ordered();
    debug_assert_eq!(
        terminal_operand_claims.len(),
        ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS
    );
    absorb_terminal(&mut channel, mask_final, &terminal_operand_claims);
    let eta = channel.squeeze_wide();
    if eta == Block256::ZERO {
        return Err(ZkAuthCapsuleOwnerError::EtaZero);
    }
    let expected_bridge =
        channel.close_into_bridge(Block128::from(ZK_AUTH_OWNER_TO_MAIN_CLOSE_TAG));

    let proof = ZkAuthCapsuleOwnerProof {
        mask_mu,
        rounds: rounds
            .try_into()
            .unwrap_or_else(|_| unreachable!("simulator emits exactly eleven Owner rounds")),
        mask_final,
        terminal_operand_claims,
    };
    let derived = verify_zk_auth_capsule_owner(statement, source_cap, &proof)?;
    debug_assert_eq!(derived.rho, rho);
    debug_assert_eq!(derived.lambda, lambda);
    debug_assert_eq!(
        derived.round_challenges_high_to_low,
        round_challenges_high_to_low
    );
    debug_assert_eq!(derived.terminal_point, terminal_point);
    debug_assert_eq!(derived.terminal_operands, terminal_operands);
    debug_assert_eq!(derived.main_final, main_final);
    debug_assert_eq!(derived.eta, eta);
    debug_assert_eq!(derived.bridge, expected_bridge);
    Ok(ZkAuthCapsuleOwnerProverOutput { proof, derived })
}

#[cfg(test)]
fn random_merkle_digest(rng: &mut (impl CryptoRng + RngCore + ?Sized)) -> [u8; 32] {
    tower_lanes_to_flat_digest([
        draw_simulator_base_field(rng),
        draw_simulator_base_field(rng),
    ])
}

#[cfg(test)]
fn sample_uniform_affine_fiber(
    weights: &[Block256],
    claim: Block256,
    rng: &mut (impl CryptoRng + RngCore + ?Sized),
) -> Result<Vec<Block256>, ZkAuthorizationError> {
    let pivot = weights
        .iter()
        .position(|&coefficient| coefficient != Block256::ZERO);
    let mut values = (0..weights.len())
        .map(|_| draw_simulator_field(rng))
        .collect::<Vec<_>>();
    match pivot {
        Some(pivot) => {
            values[pivot] = Block256::ZERO;
            let fixed = weights
                .iter()
                .zip(&values)
                .fold(Block256::ZERO, |sum, (&weight, &value)| {
                    sum + weight * value
                });
            values[pivot] = (claim - fixed) * weights[pivot].invert();
        }
        None if claim == Block256::ZERO => {}
        None => return Err(ZkAuthorizationError::PhaseABindingMismatch),
    }
    debug_assert_eq!(
        weights
            .iter()
            .zip(&values)
            .fold(Block256::ZERO, |sum, (&weight, &value)| {
                sum + weight * value
            }),
        claim
    );
    Ok(values)
}

#[cfg(test)]
fn fold_lowest_in_place(values: &mut Vec<Block256>, challenge: Block256) {
    assert!(values.len().is_power_of_two() && values.len() >= 2);
    let folded_len = values.len() / 2;
    for index in 0..folded_len {
        let at_zero = values[2 * index];
        let at_one = values[2 * index + 1];
        values[index] = at_zero + challenge * (at_zero + at_one);
    }
    values.truncate(folded_len);
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct ZkAuthHonestMerkleTree {
    /// Bottom-up: leaves first, root last.
    levels: Vec<Vec<SourceHash>>,
}

#[cfg(test)]
impl ZkAuthHonestMerkleTree {
    fn new(mut current: Vec<SourceHash>) -> Self {
        assert!(current.len().is_power_of_two());
        let mut levels = Vec::with_capacity(current.len().trailing_zeros() as usize + 1);
        levels.push(current.clone());
        while current.len() > 1 {
            let next = current
                .chunks_exact(2)
                .map(|pair| CapsuleNodeHasher.compress(&pair[0], &pair[1]))
                .collect::<Vec<_>>();
            levels.push(next.clone());
            current = next;
        }
        Self { levels }
    }

    fn tree_depth(&self) -> usize {
        self.levels.len() - 1
    }

    fn cap_at_depth(&self, cap_depth: usize) -> Vec<SourceHash> {
        assert!(cap_depth <= self.tree_depth());
        self.levels[self.tree_depth() - cap_depth].clone()
    }

    fn queried_nodes(&self) -> Vec<ZkAuthProgrammedNode> {
        let mut nodes = Vec::with_capacity(self.levels[0].len() - 1);
        for layer in 0..self.tree_depth() {
            for (parent, pair) in self.levels[layer].chunks_exact(2).enumerate() {
                nodes.push(ZkAuthProgrammedNode {
                    left: pair[0],
                    right: pair[1],
                    output: self.levels[layer + 1][parent],
                });
            }
        }
        nodes
    }
}

#[cfg(test)]
fn build_honest_mid_tree(
    mid_codeword: &[Block256],
) -> Result<ZkAuthHonestMerkleTree, ZkAuthorizationError> {
    let code = ZkAffineLchCode::selected().map_err(authorization_pcs_error)?;
    let mut leaf_hashes = Vec::with_capacity(ZK_CAPSULE_PCS_MID_LEAF_COUNT);
    for leaf_index in 0..ZK_CAPSULE_PCS_MID_LEAF_COUNT {
        let leaf = build_fold_normal_mid_leaf(&code, mid_codeword, leaf_index)
            .map_err(authorization_pcs_error)?;
        leaf_hashes.push(capsule_leaf_hash_wide(&leaf));
    }
    Ok(ZkAuthHonestMerkleTree::new(leaf_hashes))
}

/// Witness-free public field view through the final Phase-B challenge.  The
/// source and mid roots are ideal programmable-commitment placeholders; raw
/// leaves, authentication paths, grind and query openings are deliberately
/// outside this algebraic boundary.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ZkAuthMerkleProgrammingStatus {
    Unprogrammed,
    Honest,
    ProgrammedIdeal,
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct ZkAuthPreopeningAlgebraicView {
    source_commitment: ZkCapsulePcsSourceCommitment,
    source_merkle: ZkAuthMerkleProgrammingStatus,
    owner: ZkAuthCapsuleOwnerProverOutput,
    sigma: Block256,
    gamma: Block256,
    phase_a: ZkPhaseAProof<Block256>,
    phase_a_challenges_high_to_low: [Block256; PHASE_A_VARS],
    phase_b_value: Block256,
    upper: ZkAuthorizationUpper,
    mid_commitment: ZkCapsulePcsMidCommitment,
    mid_merkle: ZkAuthMerkleProgrammingStatus,
    mid_codeword: Vec<Block256>,
    mid_tree: ZkAuthHonestMerkleTree,
    tail: ZkCapsulePcsTailReveal,
    beta: [Block256; PHASE_B_LOW_VARS],
    virtual_oracle: Vec<Block256>,
}

#[cfg(test)]
fn simulate_zk_auth_preopening_algebraic_view(
    statement: ZkAuthCapsuleOwnerStatement,
    rng: &mut (impl CryptoRng + RngCore + ?Sized),
) -> Result<ZkAuthPreopeningAlgebraicView, ZkAuthorizationError> {
    let source_commitment = ZkCapsulePcsSourceCommitment {
        cap: MerkleCap {
            hashes: (0..ZK_CAPSULE_PCS_SOURCE_CAP_HASHES)
                .map(|_| random_merkle_digest(rng))
                .collect(),
        },
    };
    let source_cap = source_commitment.transcript_lanes()?;
    let owner = simulate_zk_auth_capsule_owner_view(statement, &source_cap, rng)?;
    let relation = &owner.derived.post_claim_relation.weights;
    let bank_claim = owner.derived.bank_claim();
    let relation_is_zero = relation
        .iter()
        .all(|&coefficient| coefficient == Block256::ZERO);
    if relation_is_zero && bank_claim != Block256::ZERO {
        return Err(ZkAuthorizationError::PhaseABindingMismatch);
    }
    let sigma = if relation_is_zero {
        Block256::ZERO
    } else {
        draw_simulator_field(rng)
    };
    let mut channel = init_main_channel(&owner.derived, sigma);
    let gamma = channel.squeeze_wide();
    if !affine_blend_gamma_is_admissible(gamma) {
        return Err(ZkAuthorizationError::GammaEndpoint);
    }

    let relation_claims = ZkPhaseARelationClaims {
        bank: bank_claim,
        companion: sigma,
    };
    let virtual_claim = bank_claim + gamma * (bank_claim + sigma);
    let virtual_oracle = sample_uniform_affine_fiber(relation, virtual_claim, rng)?;
    let mut phase_a_challenges_high_to_low = [Block256::ZERO; PHASE_A_VARS];
    let phase_a = prove_phase_a_from_virtual_oracle_adaptive(
        &virtual_oracle,
        relation,
        relation_claims,
        gamma,
        |round, round_proof| {
            absorb_phase_a_round(&mut channel, &round_proof);
            let challenge = channel.squeeze_wide();
            phase_a_challenges_high_to_low[round] = challenge;
            challenge
        },
    )?;
    let phase_b_value = phase_a.terminal_oracle_value;
    let virtual_oracle_array: &[Block256; 1 << PHASE_A_VARS] = virtual_oracle
        .as_slice()
        .try_into()
        .expect("selected virtual oracle length");
    let high_point: &[Block256; PHASE_B_HIGH_VARS] = phase_a.terminal_point[PHASE_B_LOW_VARS..]
        .try_into()
        .expect("selected Phase-A point splits 8+3");
    let upper = ZkAuthorizationUpper::new(contract_high3_for_each_low8(
        virtual_oracle_array,
        high_point,
    ));
    absorb_phase_b_prefix(&mut channel, phase_b_value, &upper);
    let beta_source: [Block256; SOURCE_STANDARD_FOLDS] =
        std::array::from_fn(|_| channel.squeeze_wide());

    let mut folded = virtual_oracle.clone();
    for challenge in beta_source {
        fold_lowest_in_place(&mut folded, challenge);
    }
    let code = ZkAffineLchCode::selected().map_err(authorization_pcs_error)?;
    let mid_codeword = code
        .encode_extension_after_low_folds(&folded, SOURCE_STANDARD_FOLDS)
        .map_err(authorization_pcs_error)?;
    let mid_tree = build_honest_mid_tree(&mid_codeword)?;
    debug_assert_eq!(mid_tree.tree_depth(), ZK_CAPSULE_PCS_MID_TREE_DEPTH);
    let mid_commitment = ZkCapsulePcsMidCommitment {
        cap: MerkleCap {
            hashes: mid_tree.cap_at_depth(ZK_CAPSULE_PCS_MID_CAP_DEPTH),
        },
    };
    debug_assert_eq!(
        mid_commitment.cap.hashes.len(),
        ZK_CAPSULE_PCS_MID_CAP_HASHES
    );
    absorb_mid_commitment(&mut channel, &mid_commitment)?;
    let beta_mid: [Block256; MID_STANDARD_FOLDS] = std::array::from_fn(|_| channel.squeeze_wide());
    for challenge in beta_mid {
        fold_lowest_in_place(&mut folded, challenge);
    }
    let tail = ZkCapsulePcsTailReveal {
        coefficients: folded
            .as_slice()
            .try_into()
            .expect("seven low folds leave tail16"),
    };
    debug_assert_eq!(tail.coefficients.len(), TAIL_SYMBOLS);
    absorb_tail(&mut channel, &tail);
    let beta_tail = channel.squeeze_wide();
    let mut beta = [Block256::ZERO; PHASE_B_LOW_VARS];
    beta[..SOURCE_STANDARD_FOLDS].copy_from_slice(&beta_source);
    beta[SOURCE_STANDARD_FOLDS..PHASE_B_LOW_VARS - 1].copy_from_slice(&beta_mid);
    beta[PHASE_B_LOW_VARS - 1] = beta_tail;

    verify_phase_a(
        &phase_a.proof,
        relation_claims,
        relation,
        gamma,
        &phase_a_challenges_high_to_low,
        phase_b_value,
    )?;
    verify_phase_b_upper_tail_link(
        upper.as_array(),
        &phase_a.terminal_point,
        phase_b_value,
        &beta,
        &tail.coefficients,
    )?;

    Ok(ZkAuthPreopeningAlgebraicView {
        source_commitment,
        source_merkle: ZkAuthMerkleProgrammingStatus::Unprogrammed,
        owner,
        sigma,
        gamma,
        phase_a: phase_a.proof,
        phase_a_challenges_high_to_low,
        phase_b_value,
        upper,
        mid_commitment,
        mid_merkle: ZkAuthMerkleProgrammingStatus::Honest,
        mid_codeword,
        mid_tree,
        tail,
        beta,
        virtual_oracle,
    })
}

#[cfg(test)]
fn authorization_pcs_error(error: impl Into<ZkCapsulePcsError>) -> ZkAuthorizationError {
    ZkAuthorizationError::Pcs(error.into())
}

/// Replay exactly the algebraic portion of the selected PCS verifier, ending
/// before either Merkle multipath.  This helper deliberately accepts raw
/// query-major symbols rather than `ZkCapsulePcsOpening`, whose type would
/// falsely imply that authentication siblings are present.
#[cfg(test)]
fn verify_zk_auth_algebraic_opening_links(
    gamma: Block256,
    beta_source: [Block256; SOURCE_STANDARD_FOLDS],
    beta_mid: [Block256; MID_STANDARD_FOLDS],
    tail: &ZkCapsulePcsTailReveal,
    queries: &[usize],
    source_joint_symbols: &[Block128],
    mid_symbols: &[Block256],
) -> Result<AffineHighPaddingRankCertificate, ZkAuthorizationError> {
    if queries.len() != ZK_AUTH_QUERY_COUNT {
        return Err(authorization_pcs_error(ZkCapsulePcsError::QueryCount {
            expected: ZK_AUTH_QUERY_COUNT,
            actual: queries.len(),
        }));
    }
    for (query_index, &value) in queries.iter().enumerate() {
        if value >= 1 << ZK_AUTH_QUERY_WIDTH_BITS {
            return Err(authorization_pcs_error(
                ZkCapsulePcsError::QueryOutOfRange { query_index, value },
            ));
        }
    }
    if source_joint_symbols.len() != ZK_CAPSULE_PCS_SOURCE_SYMBOLS {
        return Err(authorization_pcs_error(
            ZkCapsulePcsError::SourceSymbolCount {
                expected: ZK_CAPSULE_PCS_SOURCE_SYMBOLS,
                actual: source_joint_symbols.len(),
            },
        ));
    }
    if mid_symbols.len() != ZK_CAPSULE_PCS_MID_SYMBOLS {
        return Err(authorization_pcs_error(ZkCapsulePcsError::MidSymbolCount {
            expected: ZK_CAPSULE_PCS_MID_SYMBOLS,
            actual: mid_symbols.len(),
        }));
    }
    if !affine_blend_gamma_is_admissible(gamma) {
        return Err(ZkAuthorizationError::GammaEndpoint);
    }

    let code = ZkAffineLchCode::selected().map_err(authorization_pcs_error)?;
    let source_hiding_rank =
        certify_source_query_hiding_rank(&code, queries).map_err(authorization_pcs_error)?;
    let tail_codeword = code
        .encode_extension_after_low_folds(
            &tail.coefficients,
            SOURCE_STANDARD_FOLDS + MID_STANDARD_FOLDS,
        )
        .map_err(authorization_pcs_error)?;
    let mut distinct_source_leaves =
        std::collections::BTreeMap::<usize, [Block128; JOINT_SOURCE_LEAF_SYMBOLS]>::new();
    let mut distinct_mid_leaves =
        std::collections::BTreeMap::<usize, [Block256; 1 << MID_STANDARD_FOLDS]>::new();

    for (query_index, &query) in queries.iter().enumerate() {
        let mapping = map_source_query_leaf(query).map_err(authorization_pcs_error)?;
        let source_start = query_index * JOINT_SOURCE_LEAF_SYMBOLS;
        let source_leaf: &[Block128; JOINT_SOURCE_LEAF_SYMBOLS] = source_joint_symbols
            [source_start..source_start + JOINT_SOURCE_LEAF_SYMBOLS]
            .try_into()
            .expect("source symbol count preflighted");
        if let Some(previous) = distinct_source_leaves.insert(query, *source_leaf) {
            if previous != *source_leaf {
                return Err(authorization_pcs_error(ZkCapsulePcsError::SourceMerkle(
                    format!("inconsistent simulated source leaf {query}"),
                )));
            }
        }
        let source_folded = fold_normal_joint_source_leaf(source_leaf, gamma, &beta_source);

        let mid_start = query_index * (1 << MID_STANDARD_FOLDS);
        let mid_leaf: &[Block256; 1 << MID_STANDARD_FOLDS] = mid_symbols
            [mid_start..mid_start + (1 << MID_STANDARD_FOLDS)]
            .try_into()
            .expect("mid symbol count preflighted");
        if let Some(previous) = distinct_mid_leaves.insert(mapping.mid_leaf_index, *mid_leaf) {
            if previous != *mid_leaf {
                return Err(authorization_pcs_error(ZkCapsulePcsError::MidMerkle(
                    format!("inconsistent simulated mid leaf {}", mapping.mid_leaf_index),
                )));
            }
        }
        let raw_mid_member = fold_normal_mid_raw_member(
            &code,
            mid_leaf,
            mapping.mid_leaf_index,
            mapping.mid_member_index,
        )
        .map_err(authorization_pcs_error)?;
        if raw_mid_member != source_folded {
            return Err(authorization_pcs_error(
                ZkCapsulePcsError::SourceToMidMismatch { query_index },
            ));
        }
        let mid_folded = fold_normal_mid_leaf(mid_leaf, &beta_mid);
        if tail_codeword[mapping.mid_leaf_index] != mid_folded {
            return Err(authorization_pcs_error(
                ZkCapsulePcsError::MidToTailMismatch { query_index },
            ));
        }
    }

    Ok(source_hiding_rank)
}

/// Witness-free base-IOP field view through the final source/mid response.
/// Query seeds are verifier public coins of the base IOP; no grind credit is
/// present.  Source bank symbols are sampled only after those queries, and
/// companion symbols are solved from the sampled virtual oracle.  The view
/// intentionally contains no Merkle siblings and cannot be converted into a
/// network `ZkAuthorizationProof`.
#[cfg(test)]
#[derive(Clone, Debug)]
struct ZkAuthAlgebraicOpeningView {
    preopening: ZkAuthPreopeningAlgebraicView,
    query_seeds: [Block128; ZK_AUTH_QUERY_SEEDS],
    queries: [usize; ZK_AUTH_QUERY_COUNT],
    source_joint_symbols: Vec<Block128>,
    mid_symbols: Vec<Block256>,
    joint_hiding: ZkAuthJointHidingRankCertificate,
    conditioned_sigma: ZkAuthConditionedCompanionHyperplaneCertificate,
}

#[cfg(test)]
fn simulate_zk_auth_algebraic_opening_view(
    statement: ZkAuthCapsuleOwnerStatement,
    query_seeds: [Block128; ZK_AUTH_QUERY_SEEDS],
    rng: &mut (impl CryptoRng + RngCore + ?Sized),
) -> Result<ZkAuthAlgebraicOpeningView, ZkAuthorizationError> {
    let preopening = simulate_zk_auth_preopening_algebraic_view(statement, rng)?;
    let queries = zk_authorization_queries_from_seeds(&query_seeds);
    let code = ZkAffineLchCode::selected().map_err(authorization_pcs_error)?;
    let virtual_codeword = code
        .encode_extension_after_low_folds(&preopening.virtual_oracle, 0)
        .map_err(authorization_pcs_error)?;

    let beta_source: [Block256; SOURCE_STANDARD_FOLDS] = preopening.beta[..SOURCE_STANDARD_FOLDS]
        .try_into()
        .expect("selected beta source width");
    let beta_mid: [Block256; MID_STANDARD_FOLDS] = preopening.beta
        [SOURCE_STANDARD_FOLDS..PHASE_B_LOW_VARS - 1]
        .try_into()
        .expect("selected beta mid width");

    let inverse_gamma = preopening.gamma.invert();
    let bank_coefficient = Block256::ONE + preopening.gamma;
    let mut sampled_bank_leaves =
        std::collections::BTreeMap::<usize, [Block128; JOINT_SOURCE_BANK_SYMBOLS]>::new();
    let mut source_joint_symbols = Vec::with_capacity(ZK_CAPSULE_PCS_SOURCE_SYMBOLS);
    let mut mid_symbols = Vec::with_capacity(ZK_CAPSULE_PCS_MID_SYMBOLS);
    for &query in &queries {
        let mapping = map_source_query_leaf(query).map_err(authorization_pcs_error)?;
        let bank_leaf = sampled_bank_leaves
            .entry(query)
            .or_insert_with(|| std::array::from_fn(|_| draw_simulator_base_field(rng)));
        let positions = joint_source_leaf_positions(query).map_err(authorization_pcs_error)?;
        let companion_leaf: [Block256; JOINT_SOURCE_BANK_SYMBOLS] = std::array::from_fn(|member| {
            inverse_gamma
                * (virtual_codeword[positions[member]]
                    + bank_coefficient * Block256::from(bank_leaf[member]))
        });
        let normalized_bank = code
            .fold_normalize_coset(bank_leaf, 0, query)
            .map_err(authorization_pcs_error)?;
        let normalized_companion = code
            .fold_normalize_coset(&companion_leaf, 0, query)
            .map_err(authorization_pcs_error)?;
        let normalized_bank: [Block128; JOINT_SOURCE_BANK_SYMBOLS] = normalized_bank
            .try_into()
            .unwrap_or_else(|_| unreachable!("source normalization preserves leaf size"));
        let normalized_companion: [Block256; JOINT_SOURCE_BANK_SYMBOLS] = normalized_companion
            .try_into()
            .unwrap_or_else(|_| unreachable!("source normalization preserves leaf size"));
        source_joint_symbols.extend_from_slice(&interleave_joint_source_leaf(
            &normalized_bank,
            &normalized_companion,
        ));
        mid_symbols.extend_from_slice(
            &build_fold_normal_mid_leaf(&code, &preopening.mid_codeword, mapping.mid_leaf_index)
                .map_err(authorization_pcs_error)?,
        );
    }

    let source_hiding_rank = verify_zk_auth_algebraic_opening_links(
        preopening.gamma,
        beta_source,
        beta_mid,
        &preopening.tail,
        &queries,
        &source_joint_symbols,
        &mid_symbols,
    )?;
    let joint_hiding = certify_zk_auth_joint_hiding_rank(
        source_hiding_rank,
        &preopening.owner.derived.terminal_point,
        preopening.owner.derived.lambda,
        preopening.gamma,
    )?;
    let conditioned_sigma = certify_zk_auth_conditioned_companion_hyperplane(
        &preopening.owner.derived.post_claim_relation.weights,
        preopening.owner.derived.bank_claim(),
        preopening.sigma,
        preopening.gamma,
    )?;
    let simulated_virtual_claim = preopening
        .owner
        .derived
        .post_claim_relation
        .weights
        .iter()
        .zip(&preopening.virtual_oracle)
        .fold(Block256::ZERO, |sum, (&weight, &value)| {
            sum + weight * value
        });
    if simulated_virtual_claim != conditioned_sigma.expected_blend_claim {
        return Err(ZkAuthorizationError::PhaseABindingMismatch);
    }

    Ok(ZkAuthAlgebraicOpeningView {
        preopening,
        query_seeds,
        queries,
        source_joint_symbols,
        mid_symbols,
        joint_hiding,
        conditioned_sigma,
    })
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum ZkAuthMerkleSimulationError {
    Authorization(ZkAuthorizationError),
    Shape(&'static str),
    InconsistentLeaf { leaf_index: usize },
    MissingLeafProgram { leaf_index: usize },
    ConflictingNodeProgram,
    MissingNodeProgram,
    UnusedProgram,
    SiblingUnderflow,
    SiblingOverflow,
    CapMismatch { cap_index: usize },
}

#[cfg(test)]
impl From<ZkAuthorizationError> for ZkAuthMerkleSimulationError {
    fn from(value: ZkAuthorizationError) -> Self {
        Self::Authorization(value)
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ZkAuthProgrammedLeaf {
    message_log: usize,
    leaf_index: usize,
    symbols: [Block128; JOINT_SOURCE_LEAF_SYMBOLS],
    output: SourceHash,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ZkAuthProgrammedNode {
    left: SourceHash,
    right: SourceHash,
    output: SourceHash,
}

/// Ideal random-oracle programming needed only for the source tree.  This is
/// not a concrete Poseidon proof and cannot be serialized as one.
#[cfg(test)]
#[derive(Clone, Debug)]
struct ZkAuthProgrammedSourceMerkleOpening {
    leaf_programs: Vec<ZkAuthProgrammedLeaf>,
    sibling_positions: Vec<SourceMerkleSiblingPosition>,
    siblings: Vec<SourceHash>,
    node_programs: Vec<ZkAuthProgrammedNode>,
}

#[cfg(test)]
fn sorted_unique_parents(indices: impl Iterator<Item = usize>) -> Vec<usize> {
    indices
        .map(|index| index >> 1)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
fn register_programmed_node(
    programs: &mut Vec<ZkAuthProgrammedNode>,
    candidate: ZkAuthProgrammedNode,
) -> Result<(), ZkAuthMerkleSimulationError> {
    if let Some(existing) = programs
        .iter()
        .find(|entry| entry.left == candidate.left && entry.right == candidate.right)
    {
        if existing.output != candidate.output {
            return Err(ZkAuthMerkleSimulationError::ConflictingNodeProgram);
        }
    } else {
        programs.push(candidate);
    }
    Ok(())
}

/// CAPSNODE is shared by source and mid trees. Treat every honestly evaluated
/// mid node as a prior oracle-table entry and refuse inconsistent source
/// programming at the same input pair.
#[cfg(test)]
fn ensure_source_programs_are_consistent_with_honest_mid(
    source: &ZkAuthProgrammedSourceMerkleOpening,
    mid_tree: &ZkAuthHonestMerkleTree,
) -> Result<(), ZkAuthMerkleSimulationError> {
    let mid_queries = mid_tree.queried_nodes();
    for source_program in &source.node_programs {
        if let Some(mid_program) = mid_queries.iter().find(|mid_program| {
            mid_program.left == source_program.left && mid_program.right == source_program.right
        }) {
            if mid_program.output != source_program.output {
                return Err(ZkAuthMerkleSimulationError::ConflictingNodeProgram);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn program_source_merkle_to_committed_cap(
    cap: &[SourceHash],
    queries: &[usize; ZK_AUTH_QUERY_COUNT],
    source_joint_symbols: &[Block128],
    rng: &mut (impl CryptoRng + RngCore + ?Sized),
) -> Result<ZkAuthProgrammedSourceMerkleOpening, ZkAuthMerkleSimulationError> {
    if cap.len() != 1 << ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH
        || source_joint_symbols.len() != ZK_CAPSULE_PCS_SOURCE_SYMBOLS
    {
        return Err(ZkAuthMerkleSimulationError::Shape(
            "source programmable Merkle shape",
        ));
    }
    let mut distinct_symbols =
        std::collections::BTreeMap::<usize, [Block128; JOINT_SOURCE_LEAF_SYMBOLS]>::new();
    for (&query, symbols) in queries
        .iter()
        .zip(source_joint_symbols.chunks_exact(JOINT_SOURCE_LEAF_SYMBOLS))
    {
        let symbols: [Block128; JOINT_SOURCE_LEAF_SYMBOLS] = symbols.try_into().unwrap();
        if let Some(previous) = distinct_symbols.insert(query, symbols) {
            if previous != symbols {
                return Err(ZkAuthMerkleSimulationError::InconsistentLeaf { leaf_index: query });
            }
        }
    }

    let mut leaf_programs = Vec::with_capacity(distinct_symbols.len());
    let mut known = std::collections::BTreeMap::<usize, SourceHash>::new();
    for (&leaf_index, &symbols) in &distinct_symbols {
        let output = random_merkle_digest(rng);
        leaf_programs.push(ZkAuthProgrammedLeaf {
            message_log: ZK_CAPSULE_PCS_SOURCE_LEAF_HASH_LOG,
            leaf_index,
            symbols,
            output,
        });
        known.insert(leaf_index, output);
    }
    let sibling_positions = canonical_source_batched_merkle_sibling_positions(
        ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH,
        ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH,
        queries,
    )
    .map_err(|_| ZkAuthMerkleSimulationError::Shape("canonical source sibling schedule"))?;

    let path_depth = ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH - ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH;
    let mut siblings = Vec::new();
    let mut node_programs = Vec::new();
    for layer in 0..path_depth {
        let parents = sorted_unique_parents(known.keys().copied());
        let mut next = std::collections::BTreeMap::new();
        for parent in parents {
            let left_index = parent << 1;
            let right_index = left_index + 1;
            let left = match known.get(&left_index).copied() {
                Some(value) => value,
                None => {
                    let actual_position = SourceMerkleSiblingPosition {
                        depth_from_root: ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH - layer,
                        index: left_index,
                    };
                    if sibling_positions.get(siblings.len()) != Some(&actual_position) {
                        return Err(ZkAuthMerkleSimulationError::Shape(
                            "source left sibling schedule drift",
                        ));
                    }
                    let value = random_merkle_digest(rng);
                    siblings.push(value);
                    value
                }
            };
            let right = match known.get(&right_index).copied() {
                Some(value) => value,
                None => {
                    let actual_position = SourceMerkleSiblingPosition {
                        depth_from_root: ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH - layer,
                        index: right_index,
                    };
                    if sibling_positions.get(siblings.len()) != Some(&actual_position) {
                        return Err(ZkAuthMerkleSimulationError::Shape(
                            "source right sibling schedule drift",
                        ));
                    }
                    let value = random_merkle_digest(rng);
                    siblings.push(value);
                    value
                }
            };
            let output = if layer + 1 == path_depth {
                *cap.get(parent)
                    .ok_or(ZkAuthMerkleSimulationError::Shape("source cap index"))?
            } else {
                random_merkle_digest(rng)
            };
            register_programmed_node(
                &mut node_programs,
                ZkAuthProgrammedNode {
                    left,
                    right,
                    output,
                },
            )?;
            next.insert(parent, output);
        }
        known = next;
    }
    if siblings.len() != sibling_positions.len() {
        return Err(ZkAuthMerkleSimulationError::Shape(
            "source sibling schedule length drift",
        ));
    }
    for (&cap_index, hash) in &known {
        if cap.get(cap_index) != Some(hash) {
            return Err(ZkAuthMerkleSimulationError::CapMismatch { cap_index });
        }
    }

    Ok(ZkAuthProgrammedSourceMerkleOpening {
        leaf_programs,
        sibling_positions,
        siblings,
        node_programs,
    })
}

#[cfg(test)]
fn verify_programmed_source_merkle(
    cap: &[SourceHash],
    queries: &[usize; ZK_AUTH_QUERY_COUNT],
    source_joint_symbols: &[Block128],
    opening: &ZkAuthProgrammedSourceMerkleOpening,
) -> Result<(), ZkAuthMerkleSimulationError> {
    if cap.len() != 1 << ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH
        || source_joint_symbols.len() != ZK_CAPSULE_PCS_SOURCE_SYMBOLS
    {
        return Err(ZkAuthMerkleSimulationError::Shape(
            "source programmable Merkle verification shape",
        ));
    }
    let mut distinct_symbols =
        std::collections::BTreeMap::<usize, [Block128; JOINT_SOURCE_LEAF_SYMBOLS]>::new();
    for (&query, symbols) in queries
        .iter()
        .zip(source_joint_symbols.chunks_exact(JOINT_SOURCE_LEAF_SYMBOLS))
    {
        let symbols: [Block128; JOINT_SOURCE_LEAF_SYMBOLS] = symbols.try_into().unwrap();
        if let Some(previous) = distinct_symbols.insert(query, symbols) {
            if previous != symbols {
                return Err(ZkAuthMerkleSimulationError::InconsistentLeaf { leaf_index: query });
            }
        }
    }
    if opening.leaf_programs.len() != distinct_symbols.len() {
        return Err(ZkAuthMerkleSimulationError::UnusedProgram);
    }
    let expected_positions = canonical_source_batched_merkle_sibling_positions(
        ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH,
        ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH,
        queries,
    )
    .map_err(|_| ZkAuthMerkleSimulationError::Shape("canonical source sibling schedule"))?;
    if opening.sibling_positions != expected_positions
        || opening.siblings.len() != opening.sibling_positions.len()
    {
        return Err(ZkAuthMerkleSimulationError::Shape(
            "source sibling schedule mismatch",
        ));
    }

    let mut known = std::collections::BTreeMap::<usize, SourceHash>::new();
    for (&leaf_index, &symbols) in &distinct_symbols {
        let programmed = opening
            .leaf_programs
            .iter()
            .find(|entry| {
                entry.message_log == ZK_CAPSULE_PCS_SOURCE_LEAF_HASH_LOG
                    && entry.leaf_index == leaf_index
                    && entry.symbols == symbols
            })
            .ok_or(ZkAuthMerkleSimulationError::MissingLeafProgram { leaf_index })?;
        known.insert(leaf_index, programmed.output);
    }

    let path_depth = ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH - ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH;
    let mut sibling_cursor = 0usize;
    let mut used_nodes = vec![false; opening.node_programs.len()];
    for _layer in 0..path_depth {
        let parents = sorted_unique_parents(known.keys().copied());
        let mut next = std::collections::BTreeMap::new();
        for parent in parents {
            let left_index = parent << 1;
            let right_index = left_index + 1;
            let left = match known.get(&left_index).copied() {
                Some(value) => value,
                None => {
                    let value = opening
                        .siblings
                        .get(sibling_cursor)
                        .copied()
                        .ok_or(ZkAuthMerkleSimulationError::SiblingUnderflow)?;
                    sibling_cursor += 1;
                    value
                }
            };
            let right = match known.get(&right_index).copied() {
                Some(value) => value,
                None => {
                    let value = opening
                        .siblings
                        .get(sibling_cursor)
                        .copied()
                        .ok_or(ZkAuthMerkleSimulationError::SiblingUnderflow)?;
                    sibling_cursor += 1;
                    value
                }
            };
            let (program_index, programmed) = opening
                .node_programs
                .iter()
                .enumerate()
                .find(|(_, entry)| entry.left == left && entry.right == right)
                .ok_or(ZkAuthMerkleSimulationError::MissingNodeProgram)?;
            used_nodes[program_index] = true;
            next.insert(parent, programmed.output);
        }
        known = next;
    }
    if sibling_cursor != opening.siblings.len() {
        return Err(ZkAuthMerkleSimulationError::SiblingOverflow);
    }
    if used_nodes.iter().any(|used| !used) {
        return Err(ZkAuthMerkleSimulationError::UnusedProgram);
    }
    for (&cap_index, hash) in &known {
        if cap.get(cap_index) != Some(hash) {
            return Err(ZkAuthMerkleSimulationError::CapMismatch { cap_index });
        }
    }
    Ok(())
}

#[cfg(test)]
fn build_honest_merkle_siblings(
    tree: &ZkAuthHonestMerkleTree,
    leaf_indices: &[usize],
    cap_depth: usize,
) -> Result<Vec<SourceHash>, ZkAuthMerkleSimulationError> {
    if cap_depth > tree.tree_depth()
        || leaf_indices
            .iter()
            .any(|&index| index >= tree.levels[0].len())
    {
        return Err(ZkAuthMerkleSimulationError::Shape(
            "honest Merkle opening shape",
        ));
    }
    canonical_source_batched_merkle_sibling_positions(tree.tree_depth(), cap_depth, leaf_indices)
        .map_err(|_| ZkAuthMerkleSimulationError::Shape("canonical honest sibling schedule"))?
        .into_iter()
        .map(|position| {
            let bottom_up_layer = tree.tree_depth() - position.depth_from_root;
            tree.levels
                .get(bottom_up_layer)
                .and_then(|layer| layer.get(position.index))
                .copied()
                .ok_or(ZkAuthMerkleSimulationError::Shape(
                    "honest sibling position",
                ))
        })
        .collect()
}

#[cfg(test)]
fn verify_honest_mid_merkle(
    cap: &[SourceHash],
    queries: &[usize; ZK_AUTH_QUERY_COUNT],
    mid_symbols: &[Block256],
    siblings: &[SourceHash],
) -> Result<(), ZkAuthMerkleSimulationError> {
    if cap.len() != 1 << ZK_CAPSULE_PCS_MID_CAP_DEPTH
        || mid_symbols.len() != ZK_CAPSULE_PCS_MID_SYMBOLS
    {
        return Err(ZkAuthMerkleSimulationError::Shape(
            "honest mid Merkle verification shape",
        ));
    }
    let mut known = std::collections::BTreeMap::<usize, SourceHash>::new();
    let mut distinct_symbols =
        std::collections::BTreeMap::<usize, [Block256; 1 << MID_STANDARD_FOLDS]>::new();
    for (&query, symbols) in queries
        .iter()
        .zip(mid_symbols.chunks_exact(1 << MID_STANDARD_FOLDS))
    {
        let mapping = map_source_query_leaf(query)
            .map_err(authorization_pcs_error)
            .map_err(ZkAuthMerkleSimulationError::from)?;
        let symbols: [Block256; 1 << MID_STANDARD_FOLDS] = symbols.try_into().unwrap();
        if let Some(previous) = distinct_symbols.insert(mapping.mid_leaf_index, symbols) {
            if previous != symbols {
                return Err(ZkAuthMerkleSimulationError::InconsistentLeaf {
                    leaf_index: mapping.mid_leaf_index,
                });
            }
        }
    }
    for (&leaf_index, symbols) in &distinct_symbols {
        known.insert(leaf_index, capsule_leaf_hash_wide(symbols));
    }

    let mut sibling_cursor = 0usize;
    for _layer in 0..(ZK_CAPSULE_PCS_MID_TREE_DEPTH - ZK_CAPSULE_PCS_MID_CAP_DEPTH) {
        let parents = sorted_unique_parents(known.keys().copied());
        let mut next = std::collections::BTreeMap::new();
        for parent in parents {
            let left_index = parent << 1;
            let right_index = left_index + 1;
            let left = match known.get(&left_index).copied() {
                Some(value) => value,
                None => {
                    let value = siblings
                        .get(sibling_cursor)
                        .copied()
                        .ok_or(ZkAuthMerkleSimulationError::SiblingUnderflow)?;
                    sibling_cursor += 1;
                    value
                }
            };
            let right = match known.get(&right_index).copied() {
                Some(value) => value,
                None => {
                    let value = siblings
                        .get(sibling_cursor)
                        .copied()
                        .ok_or(ZkAuthMerkleSimulationError::SiblingUnderflow)?;
                    sibling_cursor += 1;
                    value
                }
            };
            next.insert(parent, CapsuleNodeHasher.compress(&left, &right));
        }
        known = next;
    }
    if sibling_cursor != siblings.len() {
        return Err(ZkAuthMerkleSimulationError::SiblingOverflow);
    }
    for (&cap_index, hash) in &known {
        if cap.get(cap_index) != Some(hash) {
            return Err(ZkAuthMerkleSimulationError::CapMismatch { cap_index });
        }
    }
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct ZkAuthMerkleOpeningView {
    algebraic: ZkAuthAlgebraicOpeningView,
    source_merkle: ZkAuthMerkleProgrammingStatus,
    source_opening: ZkAuthProgrammedSourceMerkleOpening,
    mid_merkle: ZkAuthMerkleProgrammingStatus,
    mid_siblings: Vec<SourceHash>,
}

#[cfg(test)]
fn simulate_zk_auth_merkle_opening_view(
    statement: ZkAuthCapsuleOwnerStatement,
    query_seeds: [Block128; ZK_AUTH_QUERY_SEEDS],
    rng: &mut (impl CryptoRng + RngCore + ?Sized),
) -> Result<ZkAuthMerkleOpeningView, ZkAuthMerkleSimulationError> {
    let algebraic = simulate_zk_auth_algebraic_opening_view(statement, query_seeds, rng)?;
    let source_opening = program_source_merkle_to_committed_cap(
        &algebraic.preopening.source_commitment.cap.hashes,
        &algebraic.queries,
        &algebraic.source_joint_symbols,
        rng,
    )?;
    ensure_source_programs_are_consistent_with_honest_mid(
        &source_opening,
        &algebraic.preopening.mid_tree,
    )?;
    verify_programmed_source_merkle(
        &algebraic.preopening.source_commitment.cap.hashes,
        &algebraic.queries,
        &algebraic.source_joint_symbols,
        &source_opening,
    )?;

    let mid_leaf_indices = algebraic
        .queries
        .iter()
        .map(|&query| {
            map_source_query_leaf(query)
                .map(|mapping| mapping.mid_leaf_index)
                .map_err(authorization_pcs_error)
                .map_err(ZkAuthMerkleSimulationError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mid_siblings = build_honest_merkle_siblings(
        &algebraic.preopening.mid_tree,
        &mid_leaf_indices,
        ZK_CAPSULE_PCS_MID_CAP_DEPTH,
    )?;
    verify_honest_mid_merkle(
        &algebraic.preopening.mid_commitment.cap.hashes,
        &algebraic.queries,
        &algebraic.mid_symbols,
        &mid_siblings,
    )?;

    Ok(ZkAuthMerkleOpeningView {
        algebraic,
        source_merkle: ZkAuthMerkleProgrammingStatus::ProgrammedIdeal,
        source_opening,
        mid_merkle: ZkAuthMerkleProgrammingStatus::Honest,
        mid_siblings,
    })
}

const _: () = assert!(ZK_AUTH_OWNER_CONSTRUCTION_VERSION == 3);
const _: () = assert!(ZK_AUTH_OWNER_SQUEEZES == 24);
const _: () = assert!(ZK_AUTH_MAIN_SQUEEZES == 28);
const _: () = assert!(ZK_AUTH_TOTAL_VERIFIER_MOVES == 30);
const _: () = assert!(ZK_AUTH_BASE_IOP_CHALLENGE_FIELDS == 51);
const _: () = assert!(ZK_AUTH_CAPSULE_MAIN_DEGREE == ZK_MLECHECK_MASK_DEGREE);
const _: () = assert!(ZK_AUTH_QROM_MAX_PROGRAMMED_SOURCE_NODES == 650);
const _: () = assert!(ZK_AUTH_QROM_MAX_PROGRAMMING_POINTS == 715);
const _: () = assert!(ZK_AUTH_SOURCE_CAP_STRUCTURAL_BITS == 2_048);
const _: () = assert!(ZK_CAPSULE_PCS_SOURCE_LEAF_HASH_LOG != ZK_CAPSULE_PCS_MID_LEAF_HASH_LOG);
const _: () = assert!(ZK_AUTH_BASE_SOURCE_ORACLE_FIELDS == 131_072);
const _: () = assert!(ZK_AUTH_BASE_MID_ORACLE_FIELDS == 8_192);
const _: () = assert!(ZK_AUTH_BASE_FINAL_QUERY_ANSWER_FIELDS == 2_080);
const _: () = assert!(ZK_AUTH_GENERIC_QUANTUM_GRIND_WORK_BITS == 8);
const _: () = assert!(ZK_AUTH_QROM_FIXED_GRIND_SOUNDNESS_CREDIT_BITS == 0);

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn grouped_dag_matches_every_owner_and_main_squeeze() {
        let owner_fields: usize = ZK_AUTH_PUBLIC_COIN_STAGES
            .iter()
            .filter(|stage| stage.phase == ZkAuthTranscriptPhase::Owner)
            .map(|stage| stage.challenge_fields())
            .sum();
        let main_fields: usize = ZK_AUTH_PUBLIC_COIN_STAGES
            .iter()
            .filter(|stage| stage.phase == ZkAuthTranscriptPhase::Main)
            .map(|stage| stage.challenge_fields())
            .sum();
        let owner_moves: usize = ZK_AUTH_PUBLIC_COIN_STAGES
            .iter()
            .filter(|stage| stage.phase == ZkAuthTranscriptPhase::Owner)
            .map(|stage| stage.verifier_moves())
            .sum();
        let main_moves: usize = ZK_AUTH_PUBLIC_COIN_STAGES
            .iter()
            .filter(|stage| stage.phase == ZkAuthTranscriptPhase::Main)
            .map(|stage| stage.verifier_moves())
            .sum();
        assert_eq!(owner_fields, ZK_AUTH_OWNER_SQUEEZES);
        assert_eq!(main_fields, ZK_AUTH_MAIN_SQUEEZES);
        assert_eq!(owner_moves, ZK_AUTH_OWNER_VERIFIER_MOVES);
        assert_eq!(main_moves, ZK_AUTH_MAIN_VERIFIER_MOVES);
        assert_eq!(owner_moves + main_moves, 30);
        let moves = zk_auth_iop_moves();
        assert_eq!(moves.len(), ZK_AUTH_TOTAL_VERIFIER_MOVES);
        assert_eq!(
            moves
                .iter()
                .map(|move_| move_.challenge_fields())
                .sum::<usize>(),
            ZK_AUTH_BASE_IOP_CHALLENGE_FIELDS
        );
        assert_eq!(moves[0], ZkAuthIopMove::OwnerRho);
        assert_eq!(moves[13], ZkAuthIopMove::OwnerEta);
        assert_eq!(moves[14], ZkAuthIopMove::MainGamma);
        assert_eq!(moves[29], ZkAuthIopMove::QuerySeeds);
        assert_eq!(
            ZK_AUTH_BASE_IOP_CHALLENGE_FIELDS + ZK_AUTH_COMPILED_CONDITIONED_GRIND_FIELDS,
            ZK_AUTH_OWNER_SQUEEZES + ZK_AUTH_MAIN_SQUEEZES
        );
    }

    #[test]
    fn rbr_profile_excludes_the_transform_level_grind_lane() {
        assert_eq!(ZK_AUTH_RBR_IOP_PROFILE.verifier_moves, 30);
        assert_eq!(ZK_AUTH_RBR_IOP_PROFILE.public_coin_fields, 51);
        assert_eq!(ZK_AUTH_RBR_IOP_PROFILE.owner_degree_ten_rounds, 11);
        assert_eq!(ZK_AUTH_RBR_IOP_PROFILE.owner_round_degree, 10);
        assert_eq!(ZK_AUTH_RBR_IOP_PROFILE.post_claim_rlc_claims, 11);
        assert_eq!(ZK_AUTH_RBR_IOP_PROFILE.post_claim_bad_polynomial_degree, 10);
        assert_eq!(ZK_AUTH_RBR_IOP_PROFILE.phase_a_degree_two_rounds, 11);
        assert_eq!(ZK_AUTH_RBR_IOP_PROFILE.phase_a_round_degree, 2);
        assert_eq!(ZK_AUTH_RBR_IOP_PROFILE.final_query_seed_fields, 7);
        assert_eq!(ZK_AUTH_RBR_IOP_PROFILE.query_salt_fields, 1);
        assert_eq!(ZK_AUTH_RBR_IOP_PROFILE.query_salt_domain_bits, 64);
        assert_eq!(
            ZK_AUTH_RBR_IOP_PROFILE.final_response,
            ZkAuthIopFinalResponseKind::SourceAndMidQueryAnswers
        );
        assert_eq!(ZK_AUTH_RBR_IOP_PROFILE.final_query_answer_fields, 2_080);
        assert!(!ZK_AUTH_RBR_IOP_PROFILE.merkle_wrapper_fields_included);
        assert_eq!(ZK_AUTH_RBR_IOP_PROFILE.compiled_conditioned_grind_fields, 1);
    }

    #[test]
    fn rbr_move_profile_is_exact_atomic_and_uses_wide_algebraic_coins() {
        let profiles = zk_auth_rbr_move_profiles();
        let moves = zk_auth_iop_moves();
        assert_eq!(profiles.len(), 30);
        assert_eq!(
            profiles
                .iter()
                .map(|profile| profile.atomic_challenge_fields)
                .sum::<usize>(),
            51
        );
        for (index, (profile, move_)) in profiles.iter().zip(moves).enumerate() {
            assert_eq!(profile.index, index);
            assert_eq!(profile.move_, move_);
            assert_eq!(profile.atomic_challenge_fields, move_.challenge_fields());
        }

        assert_eq!(
            profiles[0].prover_message_before_coin,
            ZkAuthBaseIopProverMessageKind::SourceOracle
        );
        assert_eq!(
            profiles[0].prover_message_before_coin.logical_fields(),
            131_072
        );
        assert_eq!(
            profiles[13].bound_class,
            ZkAuthRbrBoundClass::RandomLinearCombination {
                claims: 11,
                bad_degree: 10,
                rejected_points: 1,
            }
        );
        assert_eq!(
            profiles[14].bound_class,
            ZkAuthRbrBoundClass::AffineBatch {
                bad_degree: 1,
                rejected_points: 2,
            }
        );
        assert_eq!(
            profiles[27].prover_message_before_coin,
            ZkAuthBaseIopProverMessageKind::MidOracle
        );
        assert_eq!(
            profiles[27].prover_message_before_coin.logical_fields(),
            8_192
        );
        assert_eq!(
            profiles[29].prover_message_before_coin,
            ZkAuthBaseIopProverMessageKind::QuerySaltNonce
        );
        assert_eq!(profiles[29].move_, ZkAuthIopMove::QuerySeeds);
        assert_eq!(
            profiles[29].bound_class,
            ZkAuthRbrBoundClass::OracleSampling {
                seed_fields: 7,
                used_bits: 845,
                queries: 65,
                index_bits: 13,
                with_replacement: true,
            }
        );

        let degree_ten_sumchecks = profiles
            .iter()
            .filter(|profile| {
                profile.bound_class == (ZkAuthRbrBoundClass::Sumcheck { max_degree: 10 })
            })
            .count();
        let degree_two_sumchecks = profiles
            .iter()
            .filter(|profile| {
                profile.bound_class == (ZkAuthRbrBoundClass::Sumcheck { max_degree: 2 })
            })
            .count();
        assert_eq!(degree_ten_sumchecks, 11);
        assert_eq!(degree_two_sumchecks, 11);
        assert_eq!(
            ZK_AUTH_RBR_IOP_PROFILE.final_query_answer_fields,
            ZK_AUTH_BASE_FINAL_QUERY_ANSWER_FIELDS
        );
        assert!(!ZK_AUTH_RBR_IOP_PROFILE.merkle_wrapper_fields_included);
    }

    #[test]
    fn non_pcs_algebraic_bad_coin_inventory_is_exact_and_excludes_rejections() {
        let ledger = conditional_zk_auth_algebraic_bad_coin_ledger();
        assert_eq!(ledger.owner_zero_check, 11);
        assert_eq!(ledger.owner_lambda_batch, 1);
        assert_eq!(ledger.owner_sumchecks, 110);
        assert_eq!(ledger.owner_eta_rlc, 10);
        assert_eq!(ledger.main_gamma_batch, 1);
        assert_eq!(ledger.phase_a_sumchecks, 22);
        assert_eq!(ledger.beta_tail_equality, 1);
        assert_eq!(ledger.rejected_endpoints_not_counted, 4);
        assert_eq!(ledger.total_bad_coin_upper_bound, 156);
        assert_eq!(ledger.denominator_bits, 255);

        let proximity_or_query_rows = zk_auth_rbr_move_profiles()
            .into_iter()
            .filter(|profile| {
                matches!(
                    profile.bound_class,
                    ZkAuthRbrBoundClass::AffineFoldProximity { .. }
                        | ZkAuthRbrBoundClass::OracleSampling { .. }
                )
            })
            .count();
        assert_eq!(proximity_or_query_rows, 3);
    }

    #[test]
    fn conditional_base_iop_union_adds_shared_gamma_events_and_claims_no_rbr() {
        let ledger = conditional_selected_zk_auth_base_iop_ledger()
            .expect("selected conditional base-IOP ledger");
        assert_eq!(ledger.johnson.all_bad_coin_upper_bound, 701_201_954_824);
        assert_eq!(ledger.algebraic.total_bad_coin_upper_bound, 156);
        assert_eq!(ledger.max_initial_candidate_pairs, 17 * 17);
        assert_eq!(ledger.grouped_upper_link_bad_coin_upper_bound, 7);
        assert_eq!(ledger.candidate_algebraic_bad_coin_upper_bound, 47_107);
        assert_eq!(ledger.all_field_bad_coin_upper_bound, 701_202_001_931);
        assert_eq!(ledger.field_denominator_bits, 255);
        assert_eq!(ledger.single_query_miss_numerator, 1);
        assert_eq!(ledger.single_query_miss_denominator, 5);
        assert_eq!(ledger.query_term_exponent, 65);
        assert!(ledger.shared_gamma_events_are_unioned);
        assert!((ledger.diagnostic_query_term_bits() - 150.925_326_2).abs() < 1e-7);
        assert!((ledger.diagnostic_field_bad_coin_bits() - 215.648_960_8).abs() < 1e-7);
        assert!((ledger.diagnostic_conditional_union_bits() - 150.925_326_2).abs() < 1e-7);
        assert_eq!(
            ledger.diagnostic_conditional_union_bits().floor() as u32,
            WALLET_BASE_IOP_BITS
        );
    }

    #[test]
    fn conditional_affine_pcs_bound_is_finite_length_and_has_no_grind_credit() {
        let ledger =
            conditional_zk_auth_pcs_proximity_ledger(ZK_AUTH_SELECTED_PCS_PROXIMITY_PARAMETERS)
                .expect("selected finite-length proximity parameters");
        assert_eq!(ledger.parameters.field_bits, 255);
        assert_eq!(ledger.parameters.inverse_rate, 32);
        assert_eq!(ledger.parameters.source_domain_len, 65_536);
        assert_eq!(ledger.parameters.source_folds, 3);
        assert_eq!(ledger.parameters.mid_domain_len, 8_192);
        assert_eq!(ledger.parameters.mid_folds, 4);
        assert_eq!(ledger.parameters.tail_domain_len, 512);
        assert_eq!(ledger.parameters.query_count, 65);
        assert!(ledger.parameters.queries_with_replacement);
        assert_eq!(ledger.parameters.fixed_grind_credit_bits, 0);
        assert_eq!(
            ledger.fold_child_domain_lengths,
            [32_768, 16_384, 8_192, 4_096, 2_048, 1_024, 512]
        );
        assert_eq!(ledger.shortest_fold_child_domain_len, 512);
        assert_eq!(
            (
                ledger.relative_distance_numerator,
                ledger.relative_distance_denominator,
            ),
            (31, 32)
        );
        assert_eq!(
            (
                ledger.conservative_gap_numerator,
                ledger.conservative_gap_denominator,
            ),
            (949, 1_984)
        );
        assert_eq!(
            (
                ledger.single_query_miss_numerator,
                ledger.single_query_miss_denominator,
            ),
            (1_035, 1_984)
        );
        assert_eq!(ledger.query_term_exponent, 65);
        assert_eq!(
            ledger.fold_bad_coin_counts,
            [15_674, 7_837, 3_919, 1_960, 980, 490, 245]
        );
        assert_eq!(ledger.fold_bad_coin_total, 31_105);
        assert_eq!(ledger.gamma_line_bad_coin_count, 31_348);
        assert_eq!(ledger.all_bad_coin_total, 62_453);
        assert_eq!(ledger.bad_coin_denominator_bits, 255);
        assert_eq!(
            ledger.query_term_target_status,
            ZkAuthPcsTargetStatus::BelowEightyBits
        );
        assert!((ledger.diagnostic_query_term_bits() - 61.020_781_8).abs() < 1e-7);
        assert!((ledger.diagnostic_bad_coin_term_bits() - 239.069_516_7).abs() < 1e-7);
        assert!((ledger.diagnostic_conditional_union_bits() - 61.020_781_8).abs() < 1e-7);
        assert_eq!(ledger.diagnostic_min_queries_for_query_term_bits(80), 86);
        assert_eq!(ledger.diagnostic_min_queries_for_query_term_bits(128), 137);
    }

    #[test]
    fn affine_fold_manifest_uses_child_lines_and_keeps_gamma_and_beta_seven_separate() {
        let layers = zk_auth_affine_rs_layers();
        assert_eq!(
            layers.map(|layer| layer.folds_done),
            [0, 1, 2, 3, 4, 5, 6, 7]
        );
        assert_eq!(
            layers.map(|layer| layer.message_len),
            [2_048, 1_024, 512, 256, 128, 64, 32, 16]
        );
        assert_eq!(
            layers.map(|layer| layer.code_len),
            [65_536, 32_768, 16_384, 8_192, 4_096, 2_048, 1_024, 512]
        );
        assert!(layers
            .iter()
            .all(|layer| layer.code_len == layer.message_len * layer.inverse_rate));

        let rounds = zk_auth_affine_fold_rounds();
        assert_eq!(
            rounds.map(|round| round.coin),
            [
                ZkAuthFoldCoin::BetaSource(0),
                ZkAuthFoldCoin::BetaSource(1),
                ZkAuthFoldCoin::BetaSource(2),
                ZkAuthFoldCoin::BetaMid(0),
                ZkAuthFoldCoin::BetaMid(1),
                ZkAuthFoldCoin::BetaMid(2),
                ZkAuthFoldCoin::BetaMid(3),
            ]
        );
        assert_eq!(
            rounds.map(|round| round.cat_line_len),
            [32_768, 16_384, 8_192, 4_096, 2_048, 1_024, 512]
        );
        for round in rounds {
            assert_eq!(round.logical_variable, round.round);
            assert_eq!(round.before.folds_done + 1, round.after.folds_done);
            assert_eq!(round.before.code_len / 2, round.after.code_len);
            assert_eq!(round.cat_line_len, round.after.code_len);
        }

        let ledger =
            conditional_zk_auth_pcs_proximity_ledger(ZK_AUTH_SELECTED_PCS_PROXIMITY_PARAMETERS)
                .expect("selected finite-length proximity parameters");
        assert_eq!(
            ledger.fold_child_domain_lengths,
            rounds.map(|round| round.cat_line_len)
        );
        assert_eq!(
            ZK_AUTH_GAMMA_PROXIMITY_LINE.source_code_len,
            layers[0].code_len
        );
        assert_eq!(ZK_AUTH_GAMMA_PROXIMITY_LINE.committed_word_count, 2);
        assert_eq!(ZK_AUTH_TAIL_LOCAL_EQUALITY.logical_variable, 7);
        assert_eq!(ZK_AUTH_TAIL_LOCAL_EQUALITY.coefficients_before, 16);
        assert_eq!(ZK_AUTH_TAIL_LOCAL_EQUALITY.coefficients_after, 8);
        assert!(!ZK_AUTH_TAIL_LOCAL_EQUALITY.is_pcs_proximity_fold);
    }

    #[test]
    fn selected_lch_quotient_certificate_matches_every_qrom_rs_layer() {
        let qrom_layers = zk_auth_affine_rs_layers();
        let code = ZkAffineLchCode::selected().expect("selected affine LCH code");
        let certificate = code
            .certify_selected_rs_manifest()
            .expect("selected quotient-domain RS manifest");

        for (expected, checked) in qrom_layers.iter().zip(&certificate.layers) {
            assert_eq!(checked.folds_done, expected.folds_done);
            assert_eq!(checked.domain_len, expected.code_len);
            assert_eq!(checked.message_len, expected.message_len);
            assert_eq!(checked.paper_degree, expected.message_len - 1);
            assert_eq!(
                checked.algebraic_rs_min_distance,
                expected.code_len - expected.message_len + 1
            );
            assert_eq!(checked.rho_numerator, (expected.message_len - 1) as u128);
            assert_eq!(checked.rho_denominator, expected.code_len as u128);
            assert_eq!(checked.inverse_rate, expected.inverse_rate);
            assert_eq!(checked.projected_basis_rank, 16 - expected.folds_done);
            assert!(checked.projected_beta_outside_basis_span);
            assert_eq!(checked.checked_coordinate_count, expected.code_len);
            assert_eq!(checked.distinct_projected_point_count, expected.code_len);
        }
    }

    #[test]
    fn conditional_johnson_screen_certifies_selected_q65_geometry() {
        let ledger = conditional_selected_zk_auth_johnson_pcs_ledger(
            ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS,
        )
        .expect("selected conditional Johnson parameters");
        assert_eq!(ledger.parameters.radius_numerator, 4);
        assert_eq!(ledger.parameters.radius_denominator, 5);
        assert_eq!(ledger.parameters.multiplicity, 8);
        assert_eq!(ledger.parameters.query_count, 65);
        assert_eq!(ledger.single_query_miss_numerator, 1);
        assert_eq!(ledger.single_query_miss_denominator, 5);
        assert_eq!(ledger.query_term_exponent, 65);
        assert_eq!(
            ledger.lines.map(|line| line.kind),
            [
                ZkAuthJohnsonLineKind::Gamma,
                ZkAuthJohnsonLineKind::Fold(0),
                ZkAuthJohnsonLineKind::Fold(1),
                ZkAuthJohnsonLineKind::Fold(2),
                ZkAuthJohnsonLineKind::Fold(3),
                ZkAuthJohnsonLineKind::Fold(4),
                ZkAuthJohnsonLineKind::Fold(5),
                ZkAuthJohnsonLineKind::Fold(6),
            ]
        );
        assert_eq!(
            ledger.lines.map(|line| line.code_len),
            [65_536, 32_768, 16_384, 8_192, 4_096, 2_048, 1_024, 512]
        );
        assert_eq!(
            ledger.lines.map(|line| line.message_len),
            [2_048, 1_024, 512, 256, 128, 64, 32, 16]
        );
        assert_eq!(
            ledger.lines.map(|line| line.bad_coin_upper_bound),
            [
                351_179_818_871,
                175_718_656_177,
                87_988_311_082,
                44_123_612_929,
                22_192_220_275,
                11_228_467_832,
                5_750_607_766,
                3_020_259_892,
            ]
        );
        assert_eq!(ledger.all_bad_coin_upper_bound, 701_201_954_824);
        assert_eq!(ledger.bad_coin_denominator_bits, 255);
        assert!(ledger.lines.iter().all(|line| line.multiplicity == 8));
        for line in ledger.lines {
            assert_eq!(line.paper_degree + 1, line.message_len);
            assert_eq!(line.rho_numerator, line.paper_degree as u128);
            assert_eq!(line.rho_denominator, line.code_len as u128);
            let scale_squared = line.sqrt_rho_lower_denominator * line.sqrt_rho_lower_denominator;
            let lower = line.sqrt_rho_lower_numerator;
            assert!(lower * lower * line.rho_denominator <= line.rho_numerator * scale_squared);
            assert!(
                (lower + 1) * (lower + 1) * line.rho_denominator
                    > line.rho_numerator * scale_squared
            );
        }
        assert!((ledger.diagnostic_query_term_bits() - 150.925_326_2).abs() < 1e-7);
        assert!((ledger.diagnostic_bad_coin_term_bits() - 215.648_960_9).abs() < 1e-7);
        assert!((ledger.diagnostic_conditional_union_bits() - 150.925_326_2).abs() < 1e-7);
    }

    #[test]
    fn johnson_guruswami_sudan_certificate_bounds_every_candidate_list_by_seventeen() {
        let ledger = selected_zk_auth_johnson_list_size_ledger();
        assert_eq!(ledger.distance_radius_numerator, 4);
        assert_eq!(ledger.distance_radius_denominator, 5);
        assert_eq!(ledger.agreement_numerator, 1);
        assert_eq!(ledger.agreement_denominator, 5);
        assert_eq!(ledger.global_max_candidate_list_size, 17);
        assert!(!ledger.polynomial_time_decoder_implemented);
        assert_eq!(
            ledger.lines.map(|line| line.required_agreements),
            [13_108, 6_554, 3_277, 1_639, 820, 410, 205, 103]
        );
        assert_eq!(
            ledger.lines.map(|line| line.interpolation_unknowns),
            [394_641, 197_397, 98_775, 49_491, 24_849, 12_501, 6_327, 3_267]
        );
        assert_eq!(
            ledger.lines.map(|line| line.interpolation_dimension_margin),
            [1_425, 789, 471, 339, 273, 213, 183, 195]
        );
        for line in ledger.lines {
            assert_eq!(line.paper_degree + 1, line.message_len);
            assert_eq!(line.interpolation_multiplicity, 3);
            assert_eq!(
                line.interpolation_weighted_degree + 1,
                3 * line.required_agreements
            );
            assert_eq!(line.interpolation_y_degree, 17);
            assert_eq!(line.interpolation_constraints, 6 * line.code_len);
            for (y, &monomials) in line.monomials_by_y_degree.iter().enumerate() {
                assert_eq!(
                    monomials,
                    (line.interpolation_weighted_degree + 1).saturating_sub(y * line.paper_degree)
                );
            }
            assert_eq!(
                line.monomials_by_y_degree.iter().sum::<usize>(),
                line.interpolation_unknowns
            );
            assert!(line.interpolation_unknowns > line.interpolation_constraints);
            assert_eq!(line.max_candidate_list_size, 17);
        }
    }

    #[test]
    fn old_seven_candidate_interpolant_does_not_certify_the_new_radius() {
        let layer = zk_auth_affine_rs_layers()[0];
        let agreements = layer.code_len.div_ceil(5);
        let old_unknowns: usize = (0..=7)
            .map(|y| agreements.saturating_sub(y * (layer.message_len - 1)))
            .sum();
        assert!(old_unknowns <= layer.code_len);
    }

    #[test]
    fn previous_johnson_radius_remains_a_valid_more_conservative_screen() {
        let previous =
            conditional_selected_zk_auth_johnson_pcs_ledger(ZkAuthJohnsonPcsParameters {
                radius_numerator: 49,
                radius_denominator: 64,
                multiplicity: 4,
                ..ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS
            })
            .expect("previous analysis parameters");
        assert_eq!(previous.all_bad_coin_upper_bound, 29_163_918_732);
        assert_eq!(previous.query_term_exponent, ZK_AUTH_QUERY_COUNT);
        assert!((previous.diagnostic_query_term_bits() - 136.052_111_3).abs() < 1e-7);
    }

    #[test]
    fn conditional_johnson_screen_rejects_shortcuts_and_unproved_radius_changes() {
        let selected = ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS;
        assert_eq!(
            conditional_selected_zk_auth_johnson_pcs_ledger(ZkAuthJohnsonPcsParameters {
                field_bits: 127,
                ..selected
            }),
            Err(ZkAuthJohnsonPcsConfigError::InvalidFieldSize)
        );
        assert_eq!(
            conditional_selected_zk_auth_johnson_pcs_ledger(ZkAuthJohnsonPcsParameters {
                radius_numerator: 0,
                ..selected
            }),
            Err(ZkAuthJohnsonPcsConfigError::InvalidRadius)
        );
        assert_eq!(
            conditional_selected_zk_auth_johnson_pcs_ledger(ZkAuthJohnsonPcsParameters {
                query_count: 0,
                ..selected
            }),
            Err(ZkAuthJohnsonPcsConfigError::InvalidQueryCount)
        );
        assert_eq!(
            conditional_selected_zk_auth_johnson_pcs_ledger(ZkAuthJohnsonPcsParameters {
                fixed_grind_credit_bits: 16,
                ..selected
            }),
            Err(ZkAuthJohnsonPcsConfigError::GrindCreditMustBeZero)
        );
        assert_eq!(
            conditional_selected_zk_auth_johnson_pcs_ledger(ZkAuthJohnsonPcsParameters {
                multiplicity: 4,
                ..selected
            }),
            Err(ZkAuthJohnsonPcsConfigError::SelectedMultiplicityPrecondition)
        );
        assert_eq!(
            conditional_selected_zk_auth_johnson_pcs_ledger(ZkAuthJohnsonPcsParameters {
                multiplicity: 2,
                ..selected
            }),
            Err(ZkAuthJohnsonPcsConfigError::InvalidMultiplicity)
        );
        assert_eq!(
            conditional_selected_zk_auth_johnson_pcs_ledger(ZkAuthJohnsonPcsParameters {
                multiplicity: u128::MAX,
                ..selected
            }),
            Err(ZkAuthJohnsonPcsConfigError::ArithmeticOverflow)
        );
        assert_eq!(
            conditional_selected_zk_auth_johnson_pcs_ledger(ZkAuthJohnsonPcsParameters {
                radius_numerator: 9,
                radius_denominator: 10,
                ..selected
            }),
            Err(ZkAuthJohnsonPcsConfigError::JohnsonRadiusPrecondition)
        );
    }

    #[test]
    fn conditional_affine_pcs_checker_rejects_shape_and_grind_shortcuts() {
        let selected = ZK_AUTH_SELECTED_PCS_PROXIMITY_PARAMETERS;
        assert_eq!(
            conditional_zk_auth_pcs_proximity_ledger(ZkAuthPcsProximityParameters {
                queries_with_replacement: false,
                ..selected
            }),
            Err(ZkAuthPcsProximityConfigError::SamplingMustBeWithReplacement)
        );
        assert_eq!(
            conditional_zk_auth_pcs_proximity_ledger(ZkAuthPcsProximityParameters {
                fixed_grind_credit_bits: 16,
                ..selected
            }),
            Err(ZkAuthPcsProximityConfigError::GrindCreditMustBeZero)
        );
        assert_eq!(
            conditional_zk_auth_pcs_proximity_ledger(ZkAuthPcsProximityParameters {
                mid_domain_len: selected.mid_domain_len / 2,
                ..selected
            }),
            Err(ZkAuthPcsProximityConfigError::InvalidMidDomain)
        );
        assert_eq!(
            conditional_zk_auth_pcs_proximity_ledger(ZkAuthPcsProximityParameters {
                tail_domain_len: selected.tail_domain_len / 2,
                ..selected
            }),
            Err(ZkAuthPcsProximityConfigError::InvalidTailDomain)
        );
    }

    #[test]
    fn only_final_nonce_edge_is_conditioned_and_it_has_no_fixed_qrom_credit() {
        let conditioned = ZK_AUTH_PUBLIC_COIN_STAGES
            .iter()
            .filter(|stage| stage.conditioned_low_bits != 0)
            .collect::<Vec<_>>();
        assert_eq!(conditioned.len(), 1);
        assert_eq!(
            conditioned[0].prover_message,
            ZkAuthProverMessageKind::GrindNonce
        );
        assert_eq!(conditioned[0].conditioned_low_bits, 16);
        assert_eq!(conditioned[0].challenge_fields_per_repetition, 8);
        assert_eq!(ZK_AUTH_QROM_FIXED_GRIND_SOUNDNESS_CREDIT_BITS, 0);
        assert_eq!(ZK_AUTH_GENERIC_QUANTUM_GRIND_WORK_BITS, 8);
    }

    #[test]
    fn bcs_ledger_keeps_query_budget_and_big_o_loss_visible() {
        let ledger = bcs_qrom_exponent_ledger(128, 16, 128);
        assert_eq!(ledger.rbr_term_bits, 96);
        assert_eq!(ledger.oracle_term_bits, 80);
        assert_eq!(ledger.preconstant_union_floor_bits, 79);
        assert_eq!(ZK_AUTH_QROM_PROGRAMMING_BUDGET.max_total_programs, 715);
        assert_eq!(
            ZK_AUTH_QROM_PROGRAMMING_BUDGET.max_total_programs,
            ZK_AUTH_QROM_MAX_PROGRAMMING_POINTS
        );
        assert_eq!(
            ZK_AUTH_QROM_PROGRAMMING_BUDGET.source_cap_structural_bits,
            2_048
        );
        assert_eq!(
            ZK_AUTH_QROM_PROGRAMMING_BUDGET.source_cap_structural_bits,
            ZK_AUTH_SOURCE_CAP_STRUCTURAL_BITS
        );
    }

    #[test]
    fn soundness_ledger_is_pinned_to_selected_parameters() {
        assert_eq!(
            SOUNDNESS_LEDGER,
            SoundnessLedger {
                wallet_base_iop_bits: 150,
                wallet_qrom_target_bits: 103,
                history_step_classical_bits: 100,
                history_step_qrom_bits: 83,
                hash_preimage_pq_bits: 128,
                hash_collision_pq_bits: 85,
            }
        );
        let history_step = bcs_qrom_exponent_ledger(
            HISTORY_STEP_CLASSICAL_BITS,
            ZK_AUTH_SELECTED_QROM_DIAGNOSTIC_QUERY_BUDGET_EXPONENT,
            HASH_PREIMAGE_PQ_BITS,
        );
        assert_eq!(history_step.rbr_term_bits, 84);
        assert_eq!(history_step.oracle_term_bits, 104);
        assert_eq!(
            history_step.preconstant_union_floor_bits,
            HISTORY_STEP_QROM_BITS as i32
        );
        assert_eq!(SOUNDNESS_LEDGER.post_quantum_floor_bits(), 83);
    }

    #[test]
    fn selected_qrom_calculation_meets_the_wallet_target() {
        let ledger = conditional_selected_zk_auth_qrom_diagnostic()
            .expect("selected conditional QROM diagnostic");
        assert_eq!(ledger.target_bits, WALLET_QROM_TARGET_BITS);
        assert_eq!(ledger.oracle_query_budget_exponent, 8);
        assert_eq!(ledger.lifetime_union_exponent, 0);
        assert_eq!(ledger.oracle_output_bits, HASH_PREIMAGE_PQ_BITS);
        assert_eq!(ledger.rbr_total_multiplier_exponent, 16);
        assert_eq!(ledger.oracle_total_numerator_exponent, 24);

        // These fields preserve A/2^255 + (1/5)^65 instead of first
        // rounding the conditional base error down to an integer bit count.
        assert_eq!(
            ledger.base_iop.all_field_bad_coin_upper_bound,
            701_202_001_931
        );
        assert_eq!(ledger.base_iop.field_denominator_bits, 255);
        assert_eq!(ledger.base_iop.single_query_miss_numerator, 1);
        assert_eq!(ledger.base_iop.single_query_miss_denominator, 5);
        assert_eq!(ledger.base_iop.query_term_exponent, ZK_AUTH_QUERY_COUNT);

        assert!((ledger.diagnostic_scaled_rbr_term_bits() - 134.925_326_2).abs() < 1e-7);
        assert!((ledger.diagnostic_oracle_term_bits() - 104.0).abs() < f64::EPSILON);
        assert!((ledger.diagnostic_preconstant_lifetime_union_bits() - 104.0).abs() < 1e-7);
        assert!(ledger.meets_target());
    }

    #[test]
    fn seven_bit_qro_budget_screen_retains_the_wide_profile_margin() {
        let ledger = conditional_selected_zk_auth_qrom_feasibility_ledger(80, 7, 0, 128)
            .expect("conditional q=7 arithmetic screen");
        assert!((ledger.diagnostic_preconstant_lifetime_union_bits() - 107.0).abs() < 1e-7);
        assert!(ledger.meets_target());
        assert_eq!(ledger.required_term_budgets.required_base_iop_bits, 95);
        assert_eq!(
            ledger.required_term_budgets.required_oracle_output_bits,
            102
        );
    }

    #[test]
    fn qrom_term_budgets_include_lifetime_and_reject_overflow() {
        let requirements =
            zk_auth_qrom_required_term_budgets(80, 8, 5).expect("finite term budgets");
        assert_eq!(requirements.one_bit_term_split, 1);
        assert_eq!(requirements.required_base_iop_bits, 102);
        assert_eq!(requirements.required_oracle_output_bits, 110);

        let lifetime = conditional_selected_zk_auth_qrom_feasibility_ledger(80, 7, 5, 128)
            .expect("finite lifetime-union diagnostic");
        assert_eq!(lifetime.rbr_total_multiplier_exponent, 19);
        assert_eq!(lifetime.oracle_total_numerator_exponent, 26);
        assert!((lifetime.diagnostic_preconstant_lifetime_union_bits() - 102.0).abs() < 1e-7);
        assert!(lifetime.meets_target());

        assert_eq!(
            zk_auth_qrom_required_term_budgets(80, u32::MAX, 0),
            Err(ZkAuthQromFeasibilityError::ArithmeticOverflow)
        );
        assert_eq!(
            zk_auth_qrom_required_term_budgets(u32::MAX, 0, 1),
            Err(ZkAuthQromFeasibilityError::ArithmeticOverflow)
        );
        assert_eq!(
            conditional_selected_zk_auth_qrom_feasibility_ledger(80, u32::MAX, 0, 128),
            Err(ZkAuthQromFeasibilityError::ArithmeticOverflow)
        );
    }

    fn field(index: usize, domain: u128) -> Block128 {
        Block128::from(
            domain.rotate_left((index % 127) as u32)
                ^ (index as u128 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15_D1B5_4A32_D192_ED03),
        )
    }

    #[test]
    fn witness_free_owner_views_are_distinct_and_accept_the_real_verifier() {
        let statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [field(1, 0xB0D1), field(2, 0xB0D1)],
            address: [field(3, 0xADD2), field(4, 0xADD2)],
        };
        let source_cap = std::array::from_fn(|index| field(index + 11, 0xCA95));
        let mut first_rng = StdRng::seed_from_u64(0x51A1_0001);
        let mut second_rng = StdRng::seed_from_u64(0x51A1_0002);
        let first = simulate_zk_auth_capsule_owner_view(statement, &source_cap, &mut first_rng)
            .expect("first witness-free Owner view");
        let second = simulate_zk_auth_capsule_owner_view(statement, &source_cap, &mut second_rng)
            .expect("second witness-free Owner view");

        assert_ne!(first.proof, second.proof);
        assert_eq!(
            verify_zk_auth_capsule_owner(statement, &source_cap, &first.proof)
                .expect("first simulated view verifies"),
            first.derived
        );
        assert_eq!(
            verify_zk_auth_capsule_owner(statement, &source_cap, &second.proof)
                .expect("second simulated view verifies"),
            second.derived
        );
        assert_eq!(first.derived.post_claim_relation.weights.len(), 1 << 11);
        assert_eq!(second.derived.post_claim_relation.weights.len(), 1 << 11);
    }

    #[test]
    fn simulated_owner_view_remains_bound_to_statement_and_source_cap() {
        let statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [field(21, 0xB0D1), field(22, 0xB0D1)],
            address: [field(23, 0xADD2), field(24, 0xADD2)],
        };
        let source_cap = std::array::from_fn(|index| field(index + 31, 0xCA95));
        let mut rng = StdRng::seed_from_u64(0x51A1_0003);
        let simulated = simulate_zk_auth_capsule_owner_view(statement, &source_cap, &mut rng)
            .expect("witness-free Owner view");

        let mut changed_statement = statement;
        changed_statement.address[0] += Block128::ONE;
        assert!(
            verify_zk_auth_capsule_owner(changed_statement, &source_cap, &simulated.proof,)
                .is_err()
        );
        let mut changed_cap = source_cap;
        changed_cap[7] += Block128::ONE;
        assert!(verify_zk_auth_capsule_owner(statement, &changed_cap, &simulated.proof).is_err());
    }

    #[test]
    fn witness_free_preopening_view_closes_phase_a_and_upper_tail() {
        let statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [field(41, 0xB0D1), field(42, 0xB0D1)],
            address: [field(43, 0xADD2), field(44, 0xADD2)],
        };
        let mut first_rng = StdRng::seed_from_u64(0x51A1_1001);
        let mut second_rng = StdRng::seed_from_u64(0x51A1_1002);
        let first = simulate_zk_auth_preopening_algebraic_view(statement, &mut first_rng)
            .expect("first witness-free preopening view");
        let second = simulate_zk_auth_preopening_algebraic_view(statement, &mut second_rng)
            .expect("second witness-free preopening view");

        assert_ne!(first.source_commitment, second.source_commitment);
        assert_ne!(first.owner.proof, second.owner.proof);
        assert_ne!(first.mid_commitment, second.mid_commitment);
        assert_eq!(
            first.source_merkle,
            ZkAuthMerkleProgrammingStatus::Unprogrammed
        );
        assert_eq!(first.mid_merkle, ZkAuthMerkleProgrammingStatus::Honest);
        assert_eq!(first.mid_tree.tree_depth(), ZK_CAPSULE_PCS_MID_TREE_DEPTH);
        assert_eq!(
            first.mid_tree.cap_at_depth(ZK_CAPSULE_PCS_MID_CAP_DEPTH),
            first.mid_commitment.cap.hashes
        );
        assert_eq!(
            first.source_commitment.cap.hashes.len(),
            ZK_CAPSULE_PCS_SOURCE_CAP_HASHES
        );
        assert_eq!(
            first.mid_commitment.cap.hashes.len(),
            ZK_CAPSULE_PCS_MID_CAP_HASHES
        );

        let source_cap = first
            .source_commitment
            .transcript_lanes()
            .expect("simulator emits the exact source cap");
        assert_eq!(
            verify_zk_auth_capsule_owner(statement, &source_cap, &first.owner.proof)
                .expect("simulated Owner view verifies"),
            first.owner.derived
        );

        let relation_claims = ZkPhaseARelationClaims {
            bank: first.owner.derived.bank_claim(),
            companion: first.sigma,
        };
        let verified_phase_a = verify_phase_a(
            &first.phase_a,
            relation_claims,
            &first.owner.derived.post_claim_relation.weights,
            first.gamma,
            &first.phase_a_challenges_high_to_low,
            first.phase_b_value,
        )
        .expect("simulated Phase A verifies");
        assert_eq!(verified_phase_a.terminal_oracle_value, first.phase_b_value);
        verify_phase_b_upper_tail_link(
            first.upper.as_array(),
            &verified_phase_a.terminal_point,
            first.phase_b_value,
            &first.beta,
            &first.tail.coefficients,
        )
        .expect("simulated upper/tail link verifies");

        let mut channel = init_main_channel(&first.owner.derived, first.sigma);
        assert_eq!(channel.squeeze_wide(), first.gamma);
        for (round, &expected_challenge) in first
            .phase_a
            .rounds
            .iter()
            .zip(&first.phase_a_challenges_high_to_low)
        {
            absorb_phase_a_round(&mut channel, round);
            assert_eq!(channel.squeeze_wide(), expected_challenge);
        }
        absorb_phase_b_prefix(&mut channel, first.phase_b_value, &first.upper);
        for &expected_challenge in &first.beta[..SOURCE_STANDARD_FOLDS] {
            assert_eq!(channel.squeeze_wide(), expected_challenge);
        }
        absorb_mid_commitment(&mut channel, &first.mid_commitment)
            .expect("simulator emits the exact mid cap");
        for &expected_challenge in &first.beta[SOURCE_STANDARD_FOLDS..PHASE_B_LOW_VARS - 1] {
            assert_eq!(channel.squeeze_wide(), expected_challenge);
        }
        absorb_tail(&mut channel, &first.tail);
        assert_eq!(channel.squeeze_wide(), first.beta[PHASE_B_LOW_VARS - 1]);
    }

    #[test]
    fn preopening_view_tampering_fails_the_real_algebraic_verifiers() {
        let statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [field(51, 0xB0D1), field(52, 0xB0D1)],
            address: [field(53, 0xADD2), field(54, 0xADD2)],
        };
        let mut rng = StdRng::seed_from_u64(0x51A1_1003);
        let view = simulate_zk_auth_preopening_algebraic_view(statement, &mut rng)
            .expect("witness-free preopening view");
        let relation_claims = ZkPhaseARelationClaims {
            bank: view.owner.derived.bank_claim(),
            companion: view.sigma,
        };
        let verified_phase_a = verify_phase_a(
            &view.phase_a,
            relation_claims,
            &view.owner.derived.post_claim_relation.weights,
            view.gamma,
            &view.phase_a_challenges_high_to_low,
            view.phase_b_value,
        )
        .expect("untampered simulated Phase A verifies");

        let mut bad_phase_a = view.phase_a.clone();
        bad_phase_a.rounds[4].at_one += Block256::ONE;
        assert!(verify_phase_a(
            &bad_phase_a,
            relation_claims,
            &view.owner.derived.post_claim_relation.weights,
            view.gamma,
            &view.phase_a_challenges_high_to_low,
            view.phase_b_value,
        )
        .is_err());

        let shifted_upper = ZkAuthorizationUpper::new(std::array::from_fn(|index| {
            view.upper.as_array()[index] + Block256::ONE
        }));
        assert_eq!(
            verify_phase_b_upper_tail_link(
                shifted_upper.as_array(),
                &verified_phase_a.terminal_point,
                view.phase_b_value + Block256::ONE,
                &view.beta,
                &view.tail.coefficients,
            ),
            Err(ZkAuthorizationError::PhaseBUpperTailMismatch)
        );
    }

    fn query_seeds_for(queries: [usize; ZK_AUTH_QUERY_COUNT]) -> [Block128; ZK_AUTH_QUERY_SEEDS] {
        let mut packed = [0u128; ZK_AUTH_QUERY_SEEDS];
        for (query_index, query) in queries.into_iter().enumerate() {
            assert!(query < 1 << ZK_AUTH_QUERY_WIDTH_BITS);
            for query_bit in 0..ZK_AUTH_QUERY_WIDTH_BITS {
                let stream_bit = query_index * ZK_AUTH_QUERY_WIDTH_BITS + query_bit;
                packed[stream_bit / 128] |=
                    (((query >> query_bit) & 1) as u128) << (stream_bit % 128);
            }
        }
        packed.map(Block128::from)
    }

    #[test]
    fn witness_free_algebraic_openings_close_the_maximum_rank_view() {
        let statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [field(61, 0xB0D1), field(62, 0xB0D1)],
            address: [field(63, 0xADD2), field(64, 0xADD2)],
        };
        let expected_queries = std::array::from_fn(|index| index);
        let query_seeds = query_seeds_for(expected_queries);
        let mut rng = StdRng::seed_from_u64(0x51A1_2001);
        let view = simulate_zk_auth_algebraic_opening_view(statement, query_seeds, &mut rng)
            .expect("witness-free algebraic opening view");

        assert_eq!(view.query_seeds, query_seeds);
        assert_eq!(view.queries, expected_queries);
        assert_eq!(
            view.preopening.source_merkle,
            ZkAuthMerkleProgrammingStatus::Unprogrammed
        );
        assert_eq!(
            view.preopening.mid_merkle,
            ZkAuthMerkleProgrammingStatus::Honest
        );
        assert_eq!(
            view.source_joint_symbols.len(),
            ZK_CAPSULE_PCS_SOURCE_SYMBOLS
        );
        assert_eq!(view.mid_symbols.len(), ZK_CAPSULE_PCS_MID_SYMBOLS);
        assert_eq!(view.joint_hiding.source_rank, 520);
        assert_eq!(view.joint_hiding.source.distinct_query_count, 520);
        assert_eq!(view.joint_hiding.certified_joint_rank, 636);
        assert_eq!(view.joint_hiding.public_conditioning_fields, 637);
        assert_eq!(view.joint_hiding.intended_relations, 1);
        view.conditioned_sigma
            .validate(&view.preopening.owner.derived.post_claim_relation.weights)
            .expect("conditioned companion fiber certificate");

        let beta_source = view.preopening.beta[..SOURCE_STANDARD_FOLDS]
            .try_into()
            .unwrap();
        let beta_mid = view.preopening.beta[SOURCE_STANDARD_FOLDS..PHASE_B_LOW_VARS - 1]
            .try_into()
            .unwrap();
        assert_eq!(
            verify_zk_auth_algebraic_opening_links(
                view.preopening.gamma,
                beta_source,
                beta_mid,
                &view.preopening.tail,
                &view.queries,
                &view.source_joint_symbols,
                &view.mid_symbols,
            )
            .expect("ordinary algebraic opening checks"),
            view.joint_hiding.source
        );
    }

    #[test]
    fn repeated_queries_share_symbols_and_algebraic_tampering_is_rejected() {
        let statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [field(71, 0xB0D1), field(72, 0xB0D1)],
            address: [field(73, 0xADD2), field(74, 0xADD2)],
        };
        let query_seeds = [Block128::ZERO; ZK_AUTH_QUERY_SEEDS];
        let mut first_rng = StdRng::seed_from_u64(0x51A1_2002);
        let mut second_rng = StdRng::seed_from_u64(0x51A1_2003);
        let view = simulate_zk_auth_algebraic_opening_view(statement, query_seeds, &mut first_rng)
            .expect("repeated-query algebraic view");
        let second =
            simulate_zk_auth_algebraic_opening_view(statement, query_seeds, &mut second_rng)
                .expect("independent repeated-query algebraic view");

        assert!(view.queries.iter().all(|&query| query == 0));
        assert_eq!(view.joint_hiding.source_rank, 8);
        let first_source = &view.source_joint_symbols[..JOINT_SOURCE_LEAF_SYMBOLS];
        assert!(view
            .source_joint_symbols
            .chunks_exact(JOINT_SOURCE_LEAF_SYMBOLS)
            .all(|leaf| leaf == first_source));
        let first_mid = &view.mid_symbols[..1 << MID_STANDARD_FOLDS];
        assert!(view
            .mid_symbols
            .chunks_exact(1 << MID_STANDARD_FOLDS)
            .all(|leaf| leaf == first_mid));
        assert_ne!(view.source_joint_symbols, second.source_joint_symbols);

        let beta_source: [Block256; SOURCE_STANDARD_FOLDS] = view.preopening.beta
            [..SOURCE_STANDARD_FOLDS]
            .try_into()
            .unwrap();
        let beta_mid: [Block256; MID_STANDARD_FOLDS] = view.preopening.beta
            [SOURCE_STANDARD_FOLDS..PHASE_B_LOW_VARS - 1]
            .try_into()
            .unwrap();
        let verify = |source: &[Block128], mid: &[Block256]| {
            verify_zk_auth_algebraic_opening_links(
                view.preopening.gamma,
                beta_source,
                beta_mid,
                &view.preopening.tail,
                &view.queries,
                source,
                mid,
            )
        };

        let mut inconsistent_duplicate = view.source_joint_symbols.clone();
        inconsistent_duplicate[0] += Block128::ONE;
        assert!(verify(&inconsistent_duplicate, &view.mid_symbols).is_err());

        let mut shifted_source = view.source_joint_symbols.clone();
        for value in &mut shifted_source {
            *value += Block128::ONE;
        }
        assert_eq!(
            verify(&shifted_source, &view.mid_symbols),
            Err(authorization_pcs_error(
                ZkCapsulePcsError::SourceToMidMismatch { query_index: 0 }
            ))
        );

        let code = ZkAffineLchCode::selected().unwrap();
        let shifted_source_leaf: &[Block128; JOINT_SOURCE_LEAF_SYMBOLS] = shifted_source
            [..JOINT_SOURCE_LEAF_SYMBOLS]
            .try_into()
            .unwrap();
        let shifted_source_fold =
            fold_normal_joint_source_leaf(shifted_source_leaf, view.preopening.gamma, &beta_source);
        let normalized_mid: &[Block256; 1 << MID_STANDARD_FOLDS] = view.mid_symbols
            [..1 << MID_STANDARD_FOLDS]
            .try_into()
            .unwrap();
        let mut raw_mid = code
            .fold_denormalize_coset(normalized_mid, SOURCE_STANDARD_FOLDS, 0)
            .unwrap();
        raw_mid[0] = shifted_source_fold;
        let normalized_mid = code
            .fold_normalize_coset(&raw_mid, SOURCE_STANDARD_FOLDS, 0)
            .unwrap();
        let mut shifted_mid = view.mid_symbols.clone();
        for leaf in shifted_mid.chunks_exact_mut(1 << MID_STANDARD_FOLDS) {
            leaf.copy_from_slice(&normalized_mid);
        }
        assert_eq!(
            verify(&shifted_source, &shifted_mid),
            Err(authorization_pcs_error(
                ZkCapsulePcsError::MidToTailMismatch { query_index: 0 }
            ))
        );
    }

    #[test]
    fn ideal_source_programming_and_honest_mid_paths_close_the_merkle_view() {
        let statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [field(81, 0xB0D1), field(82, 0xB0D1)],
            address: [field(83, 0xADD2), field(84, 0xADD2)],
        };
        let expected_queries = std::array::from_fn(|index| index);
        let query_seeds = query_seeds_for(expected_queries);
        let mut rng = StdRng::seed_from_u64(0x51A1_3001);
        let view = simulate_zk_auth_merkle_opening_view(statement, query_seeds, &mut rng)
            .expect("witness-free Merkle opening view");

        assert_eq!(view.algebraic.queries, expected_queries);
        assert_eq!(
            view.algebraic.preopening.source_merkle,
            ZkAuthMerkleProgrammingStatus::Unprogrammed
        );
        assert_eq!(
            view.source_merkle,
            ZkAuthMerkleProgrammingStatus::ProgrammedIdeal
        );
        assert_eq!(view.mid_merkle, ZkAuthMerkleProgrammingStatus::Honest);
        assert_eq!(view.source_opening.leaf_programs.len(), 65);
        assert!(!view.source_opening.node_programs.is_empty());
        assert!(
            view.source_opening.leaf_programs.len() + view.source_opening.node_programs.len()
                <= ZK_AUTH_QROM_PROGRAMMING_BUDGET.max_total_programs
        );
        assert!(view.source_opening.siblings.len() <= ZK_CAPSULE_PCS_WORST_SOURCE_SIBLINGS);
        assert!(view.mid_siblings.len() <= ZK_CAPSULE_PCS_WORST_MID_SIBLINGS);
        verify_programmed_source_merkle(
            &view.algebraic.preopening.source_commitment.cap.hashes,
            &view.algebraic.queries,
            &view.algebraic.source_joint_symbols,
            &view.source_opening,
        )
        .expect("programmed source multipath");
        verify_honest_mid_merkle(
            &view.algebraic.preopening.mid_commitment.cap.hashes,
            &view.algebraic.queries,
            &view.algebraic.mid_symbols,
            &view.mid_siblings,
        )
        .expect("honest mid multipath");
    }

    #[test]
    fn programmed_and_honest_merkle_views_reject_leaf_path_and_cap_tampering() {
        let statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [field(91, 0xB0D1), field(92, 0xB0D1)],
            address: [field(93, 0xADD2), field(94, 0xADD2)],
        };
        let query_seeds = [Block128::ZERO; ZK_AUTH_QUERY_SEEDS];
        let mut rng = StdRng::seed_from_u64(0x51A1_3002);
        let view = simulate_zk_auth_merkle_opening_view(statement, query_seeds, &mut rng)
            .expect("repeated-query Merkle opening view");
        assert_eq!(view.source_opening.leaf_programs.len(), 1);
        assert_eq!(
            view.source_opening.siblings.len(),
            ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH
        );
        assert_eq!(
            view.source_opening.node_programs.len(),
            ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH
        );
        assert_eq!(
            view.mid_siblings.len(),
            ZK_CAPSULE_PCS_MID_TREE_DEPTH - ZK_CAPSULE_PCS_MID_CAP_DEPTH
        );

        let mut cross_tree_conflict = view.source_opening.clone();
        let honest_mid_node = view.algebraic.preopening.mid_tree.queried_nodes()[0];
        cross_tree_conflict.node_programs[0] = honest_mid_node;
        cross_tree_conflict.node_programs[0].output[0] ^= 1;
        assert_eq!(
            ensure_source_programs_are_consistent_with_honest_mid(
                &cross_tree_conflict,
                &view.algebraic.preopening.mid_tree,
            ),
            Err(ZkAuthMerkleSimulationError::ConflictingNodeProgram)
        );

        let source_cap = &view.algebraic.preopening.source_commitment.cap.hashes;
        let verify_source = |cap: &[SourceHash], symbols: &[Block128], opening| {
            verify_programmed_source_merkle(cap, &view.algebraic.queries, symbols, opening)
        };
        let mut changed_source_symbols = view.algebraic.source_joint_symbols.clone();
        for leaf in changed_source_symbols.chunks_exact_mut(JOINT_SOURCE_LEAF_SYMBOLS) {
            leaf[0] += Block128::ONE;
        }
        assert_eq!(
            verify_source(source_cap, &changed_source_symbols, &view.source_opening),
            Err(ZkAuthMerkleSimulationError::MissingLeafProgram { leaf_index: 0 })
        );

        let mut changed_source_path = view.source_opening.clone();
        changed_source_path.siblings[0][0] ^= 1;
        let beta_source = view.algebraic.preopening.beta[..SOURCE_STANDARD_FOLDS]
            .try_into()
            .unwrap();
        let beta_mid = view.algebraic.preopening.beta[SOURCE_STANDARD_FOLDS..PHASE_B_LOW_VARS - 1]
            .try_into()
            .unwrap();
        verify_zk_auth_algebraic_opening_links(
            view.algebraic.preopening.gamma,
            beta_source,
            beta_mid,
            &view.algebraic.preopening.tail,
            &view.algebraic.queries,
            &view.algebraic.source_joint_symbols,
            &view.algebraic.mid_symbols,
        )
        .expect("BCS sibling mutation is outside the base IOP");
        assert_eq!(
            verify_source(
                source_cap,
                &view.algebraic.source_joint_symbols,
                &changed_source_path,
            ),
            Err(ZkAuthMerkleSimulationError::MissingNodeProgram)
        );
        let mut changed_source_cap = source_cap.clone();
        changed_source_cap[0][0] ^= 1;
        assert_eq!(
            verify_source(
                &changed_source_cap,
                &view.algebraic.source_joint_symbols,
                &view.source_opening,
            ),
            Err(ZkAuthMerkleSimulationError::CapMismatch { cap_index: 0 })
        );

        let mid_cap = &view.algebraic.preopening.mid_commitment.cap.hashes;
        let verify_mid = |cap: &[SourceHash], symbols: &[Block256], siblings: &[SourceHash]| {
            verify_honest_mid_merkle(cap, &view.algebraic.queries, symbols, siblings)
        };
        let mut changed_mid_symbols = view.algebraic.mid_symbols.clone();
        for leaf in changed_mid_symbols.chunks_exact_mut(1 << MID_STANDARD_FOLDS) {
            leaf[0] += Block256::ONE;
        }
        assert!(verify_mid(mid_cap, &changed_mid_symbols, &view.mid_siblings).is_err());
        let mut changed_mid_path = view.mid_siblings.clone();
        changed_mid_path[0][0] ^= 1;
        assert!(verify_mid(mid_cap, &view.algebraic.mid_symbols, &changed_mid_path).is_err());
        let mut changed_mid_cap = mid_cap.clone();
        changed_mid_cap[0][0] ^= 1;
        assert_eq!(
            verify_mid(
                &changed_mid_cap,
                &view.algebraic.mid_symbols,
                &view.mid_siblings,
            ),
            Err(ZkAuthMerkleSimulationError::CapMismatch { cap_index: 0 })
        );
    }

    #[test]
    fn adaptive_two_body_same_owner_simulated_views_use_independent_attempts() {
        let address = [field(101, 0xADD2), field(102, 0xADD2)];
        let first_statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [field(103, 0xB0D1), field(104, 0xB0D1)],
            address,
        };
        let first_queries = std::array::from_fn(|index| index);
        let mut rng = StdRng::seed_from_u64(0x51A1_4001);
        let first = simulate_zk_auth_merkle_opening_view(
            first_statement,
            query_seeds_for(first_queries),
            &mut rng,
        )
        .expect("first same-owner simulated view");

        let first_cap_lanes = first
            .algebraic
            .preopening
            .source_commitment
            .transcript_lanes()
            .unwrap();
        let second_statement = ZkAuthCapsuleOwnerStatement {
            // Model an adaptively chosen second body using only the first
            // public view; the owner address remains identical.
            tx_body_hash: [first_cap_lanes[0], first_cap_lanes[1]],
            address,
        };
        let second_query_seeds = std::array::from_fn(|index| first_cap_lanes[index + 2]);
        let second =
            simulate_zk_auth_merkle_opening_view(second_statement, second_query_seeds, &mut rng)
                .expect("adaptive second same-owner simulated view");

        assert_eq!(first_statement.address, second_statement.address);
        assert_ne!(
            first.algebraic.preopening.source_commitment,
            second.algebraic.preopening.source_commitment
        );
        assert_ne!(
            first.algebraic.preopening.owner.proof,
            second.algebraic.preopening.owner.proof
        );
        assert_ne!(
            first.algebraic.source_joint_symbols,
            second.algebraic.source_joint_symbols
        );
        assert_ne!(
            first.algebraic.preopening.mid_commitment,
            second.algebraic.preopening.mid_commitment
        );
        verify_programmed_source_merkle(
            &second.algebraic.preopening.source_commitment.cap.hashes,
            &second.algebraic.queries,
            &second.algebraic.source_joint_symbols,
            &second.source_opening,
        )
        .expect("adaptive second programmed source path");
        verify_honest_mid_merkle(
            &second.algebraic.preopening.mid_commitment.cap.hashes,
            &second.algebraic.queries,
            &second.algebraic.mid_symbols,
            &second.mid_siblings,
        )
        .expect("adaptive second honest mid path");
    }

    fn assert_markers_in_order(source: &str, markers: &[&str]) {
        let mut cursor = 0usize;
        for marker in markers {
            let relative = source[cursor..]
                .find(marker)
                .unwrap_or_else(|| panic!("missing ordered transcript marker {marker}"));
            cursor += relative + marker.len();
        }
    }

    #[test]
    fn public_prover_keeps_every_commit_reveal_before_its_challenge() {
        let source = include_str!("zk_authorization.rs");
        let prover = source
            .split("fn prove_zk_authorization_from_state_with_rng")
            .nth(1)
            .expect("complete selected prover")
            .split("/// Complete network/native verification")
            .next()
            .expect("bounded complete selected prover");
        assert_markers_in_order(
            prover,
            &[
                "zk_capsule_pcs_commit_fresh",
                "zk_capsule_pcs_bind_owner",
                "zk_capsule_pcs_bind_phase_a",
                "init_main_channel",
                "let gamma = channel.squeeze_wide()",
                "zk_capsule_pcs_prove_phase_a",
                "absorb_phase_b_prefix",
                "let beta_source",
                "zk_capsule_pcs_commit_mid",
                "absorb_mid_commitment",
                "let beta_mid",
                "zk_capsule_pcs_reveal_tail",
                "absorb_tail",
                "let beta_tail = channel.squeeze_wide()",
                "grind_main_channel_with_bits",
                "let query_seeds",
                "zk_capsule_pcs_open",
            ],
        );
    }

    #[test]
    fn verifier_replays_the_same_staged_commitment_order() {
        let source = include_str!("zk_authorization.rs");
        let verifier = source
            .split("pub fn verify_zk_authorization(")
            .nth(1)
            .expect("complete selected verifier")
            .split("#[cfg(test)]")
            .next()
            .expect("bounded complete selected verifier");
        assert_markers_in_order(
            verifier,
            &[
                "source_commitment.transcript_lanes",
                "verify_zk_auth_capsule_owner",
                "init_main_channel",
                "let gamma = channel.squeeze_wide()",
                "absorb_phase_a_round",
                "verify_phase_a",
                "absorb_phase_b_prefix",
                "let beta_source",
                "absorb_mid_commitment",
                "let beta_mid",
                "absorb_tail",
                "let beta_tail = channel.squeeze_wide()",
                "replay_grind",
                "let query_seeds",
                "zk_capsule_pcs_verify",
            ],
        );
    }
}
