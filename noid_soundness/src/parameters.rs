// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Read-only projection of the parameters used by production proving code.

use noid_gkr::zk_auth_qrom::{
    ZK_AUTH_EFFECTIVE_CHALLENGE_BITS, conditional_selected_zk_auth_base_iop_ledger,
};
use noid_ivc_core::{
    field::gf2_256::C1_CHALLENGE_MIN_ENTROPY_BITS,
    pcs::{BASEFOLD_RATE_QUARTER_C1_QUERIES, fri_commit_layout},
};
use noid_poseidon2b::{
    Digest,
    native::{
        compression::RATE,
        permutation::{F_ROUNDS, P_ROUNDS, SBOX_EXPONENT, STATE_SIZE},
    },
};
use noid_recursive::acceptance::history_step_bank::HISTORY_STEP_FRI_QUERIES;
use noid_recursive::{canonical_history_step_class_id, canonical_history_step_pcs_params};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryClassParameters {
    pub tier: usize,
    pub message_log2: usize,
    pub codeword_log2: usize,
    pub codeword_len: u64,
    pub inverse_rate: u64,
    pub plaintext_tail_len: u64,
    pub fri_arities: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionParameters {
    pub challenge_min_entropy_bits: u32,
    pub digest_bits: u32,
    pub wallet_inverse_rate: u64,
    pub wallet_queries: u32,
    pub wallet_radius_numerator: u64,
    pub wallet_radius_denominator: u64,
    pub wallet_field_bad_numerator: u128,
    pub wallet_query_seed_lanes: usize,
    pub history_inverse_rate: u64,
    pub history_queries: u32,
    pub history_classes: [HistoryClassParameters; 2],
    pub poseidon_state_width: usize,
    pub poseidon_rate_lanes: usize,
    pub poseidon_sbox_exponent: usize,
    pub poseidon_full_rounds: usize,
    pub poseidon_partial_rounds: usize,
}

impl ProductionParameters {
    pub fn load() -> Result<Self, String> {
        let wallet = conditional_selected_zk_auth_base_iop_ledger()
            .map_err(|error| format!("wallet soundness ledger rejected production: {error:?}"))?;
        let geometry = noid_fri_binius::ZK_AUTH_CAPSULE_GEOMETRY;

        let history_class = |tier: usize| -> Result<HistoryClassParameters, String> {
            let class_id = canonical_history_step_class_id(tier)
                .ok_or_else(|| format!("missing production History class B{tier}"))?;
            let pcs = canonical_history_step_pcs_params(class_id);
            let fri_arities = pcs.fri_arities();
            let (_, tail) = fri_commit_layout(pcs.k_code(), &fri_arities);
            let (plaintext_tail_len, _) = tail
                .ok_or_else(|| format!("production History class B{tier} has no plaintext tail"))?;
            Ok(HistoryClassParameters {
                tier,
                message_log2: pcs.log_dim(),
                codeword_log2: pcs.k_code(),
                codeword_len: u64::try_from(pcs.n_positions())
                    .map_err(|_| format!("B{tier} codeword length does not fit u64"))?,
                inverse_rate: 1u64
                    .checked_shl(
                        u32::try_from(pcs.log_inv_rate)
                            .map_err(|_| format!("B{tier} inverse-rate log does not fit u32"))?,
                    )
                    .ok_or_else(|| format!("B{tier} inverse rate does not fit u64"))?,
                plaintext_tail_len: u64::try_from(plaintext_tail_len)
                    .map_err(|_| format!("B{tier} plaintext tail does not fit u64"))?,
                fri_arities,
            })
        };

        let history_classes = [history_class(25)?, history_class(255)?];
        if history_classes[0].inverse_rate != history_classes[1].inverse_rate {
            return Err("production History classes use different rates".to_string());
        }

        if HISTORY_STEP_FRI_QUERIES != BASEFOLD_RATE_QUARTER_C1_QUERIES {
            return Err("HistoryStep and BaseFold query counts diverged".to_string());
        }
        if wallet.query_term_exponent != geometry.query_count {
            return Err("wallet ledger and capsule query counts diverged".to_string());
        }
        if wallet.field_denominator_bits != ZK_AUTH_EFFECTIVE_CHALLENGE_BITS {
            return Err("wallet challenge entropy ledger diverged".to_string());
        }
        if wallet.field_denominator_bits != C1_CHALLENGE_MIN_ENTROPY_BITS {
            return Err("wallet and C1 challenge supports diverged".to_string());
        }

        Ok(Self {
            challenge_min_entropy_bits: C1_CHALLENGE_MIN_ENTROPY_BITS,
            digest_bits: u32::try_from(std::mem::size_of::<Digest>() * u8::BITS as usize)
                .expect("digest width fits u32"),
            wallet_inverse_rate: u64::try_from(geometry.rate)
                .map_err(|_| "wallet inverse rate does not fit u64")?,
            wallet_queries: u32::try_from(wallet.query_term_exponent)
                .map_err(|_| "wallet query count does not fit u32")?,
            wallet_radius_numerator: u64::try_from(wallet.johnson.parameters.radius_numerator)
                .map_err(|_| "wallet radius numerator does not fit u64")?,
            wallet_radius_denominator: u64::try_from(wallet.johnson.parameters.radius_denominator)
                .map_err(|_| "wallet radius denominator does not fit u64")?,
            wallet_field_bad_numerator: wallet.all_field_bad_coin_upper_bound,
            wallet_query_seed_lanes: geometry.query_seed_count,
            history_inverse_rate: history_classes[0].inverse_rate,
            history_queries: u32::try_from(HISTORY_STEP_FRI_QUERIES)
                .map_err(|_| "History query count does not fit u32")?,
            history_classes,
            poseidon_state_width: STATE_SIZE,
            poseidon_rate_lanes: RATE,
            poseidon_sbox_exponent: SBOX_EXPONENT,
            poseidon_full_rounds: F_ROUNDS,
            poseidon_partial_rounds: P_ROUNDS,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_profile_is_w65_h133() {
        let parameters = ProductionParameters::load().unwrap();
        assert_eq!(parameters.challenge_min_entropy_bits, 255);
        assert_eq!(parameters.digest_bits, 256);
        assert_eq!(parameters.wallet_inverse_rate, 32);
        assert_eq!(parameters.wallet_queries, 65);
        assert_eq!(
            (
                parameters.wallet_radius_numerator,
                parameters.wallet_radius_denominator,
            ),
            (4, 5)
        );
        assert_eq!(parameters.wallet_field_bad_numerator, 701_202_001_931);
        assert_eq!(parameters.wallet_query_seed_lanes, 7);
        assert_eq!(parameters.history_inverse_rate, 4);
        assert_eq!(parameters.history_queries, 133);
    }

    #[test]
    fn both_recursive_history_classes_are_covered() {
        let classes = ProductionParameters::load().unwrap().history_classes;
        assert_eq!(classes[0].tier, 25);
        assert_eq!(classes[0].message_log2, 17);
        assert_eq!(classes[0].codeword_log2, 19);
        assert_eq!(classes[0].codeword_len, 1 << 19);
        assert_eq!(classes[0].inverse_rate, 4);
        assert_eq!(classes[0].plaintext_tail_len, 128);
        assert_eq!(classes[0].fri_arities, [4, 4, 4, 4, 1]);
        assert_eq!(classes[1].tier, 255);
        assert_eq!(classes[1].message_log2, 19);
        assert_eq!(classes[1].codeword_log2, 21);
        assert_eq!(classes[1].codeword_len, 1 << 21);
        assert_eq!(classes[1].inverse_rate, 4);
        assert_eq!(classes[1].plaintext_tail_len, 512);
        assert_eq!(classes[1].fri_arities, [4, 4, 4, 4, 3]);
    }

    #[test]
    fn fixed_poseidon2b_profile_is_source_linked() {
        let parameters = ProductionParameters::load().unwrap();
        assert_eq!(parameters.poseidon_state_width, 4);
        assert_eq!(parameters.poseidon_rate_lanes, 2);
        assert_eq!(parameters.poseidon_sbox_exponent, 7);
        assert_eq!(parameters.poseidon_full_rounds, 8);
        assert_eq!(parameters.poseidon_partial_rounds, 58);
    }
}
