// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Checked geometry for the witness-hiding authorization capsule.
//!
//! This module is a parameter contract, not a protocol implementation.  In
//! particular, importing it does not alter the active capsule proof, wire
//! format, transcript, or verifier. It makes the selected natural-order affine
//! bank-and-companion geometry executable so the masking protocol and recursive
//! row ledger can be built against one checked source of truth.

/// Input parameters for the interleaved bank-and-companion capsule geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkCapsuleParameters {
    pub bank_log: usize,
    pub companion_bank_log: usize,
    pub state_len: usize,
    /// Dedicated, independently uniform PCS coins immediately after `state`.
    pub pcs_coin_len: usize,
    pub mask_main_degree: usize,
    pub mask_extra_dof: usize,
    pub mask_main_len: usize,
    pub log_rate: usize,
    pub source_bank_symbols_per_leaf: usize,
    pub source_companion_symbols_per_leaf: usize,
    pub source_inner_gamma_folds: usize,
    pub source_standard_fold_log: usize,
    pub source_cap_depth: usize,
    pub mid_cap_depth: usize,
    pub second_wide_fold_log: usize,
    pub tail_local_fold_log: usize,
    pub query_count: usize,
    pub query_seed_bits: usize,
    pub query_bits_with_existing_carriers: usize,
    pub wallet_b_legs: usize,
    pub wallet_b_stride: usize,
    pub digest_field_lanes: usize,
    /// Active-capsule source cap used only to state the transcript delta.
    pub baseline_source_cap_depth: usize,
    /// The active mid commitment is one root, i.e. cap depth zero.
    pub baseline_mid_cap_depth: usize,
    /// The active owner capsule reveals a two-element final `h`.
    pub baseline_tail_len: usize,
}

/// A completely derived, internally consistent authorization-capsule shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkCapsuleGeometry {
    pub bank_log: usize,
    pub bank_len: usize,
    pub companion_bank_len: usize,
    pub state_len: usize,
    pub state_vars: usize,
    pub fundamental_high_vars: usize,
    pub pcs_coin_start: usize,
    pub pcs_coin_len: usize,
    pub mask_sumcheck_vars: usize,
    pub mask_main_degree: usize,
    pub mask_extra_dof: usize,
    pub mask_main_start: usize,
    pub mask_main_len: usize,
    pub trailing_padding_start: usize,
    pub trailing_padding_len: usize,
    pub total_fresh_padding_len: usize,
    pub raw_source_observation_bound: usize,

    pub log_rate: usize,
    pub rate: usize,
    pub source_domain_log: usize,
    pub source_domain_len: usize,
    pub source_bank_symbols_per_leaf: usize,
    pub source_companion_symbols_per_leaf: usize,
    pub source_leaf_symbols: usize,
    pub source_inner_gamma_folds: usize,
    pub source_standard_fold_log: usize,
    pub source_leaf_count: usize,
    pub source_tree_depth: usize,
    pub source_cap_depth: usize,
    pub source_path_depth: usize,

    pub mid_log: usize,
    pub mid_domain_log: usize,
    pub mid_leaf_symbols: usize,
    pub mid_leaf_count: usize,
    pub mid_tree_depth: usize,
    pub mid_cap_depth: usize,
    pub mid_path_depth: usize,
    pub second_wide_fold_log: usize,

    pub tail_log: usize,
    pub tail_len: usize,
    pub tail_local_fold_log: usize,
    pub final_h_log: usize,
    pub final_h_len: usize,

    pub query_width_bits: usize,
    pub query_count: usize,
    pub query_seed_bits: usize,
    pub query_seed_count: usize,
    pub query_bits_with_existing_carriers: usize,
    pub query_bits_requiring_aux_carrier: usize,
    pub wallet_a_symbols_per_auth: usize,
    pub wallet_b_legs: usize,
    pub wallet_b_stride: usize,
    pub source_uses_root_copy_tail: bool,
    pub mid_uses_root_copy_tail: bool,
    pub wallet_b_slots_per_auth: usize,

    pub source_transcript_delta_lanes: isize,
    pub mid_transcript_delta_lanes: isize,
    pub tail_transcript_delta_lanes: isize,
}

/// Why a candidate parameter set does not describe this capsule construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkCapsuleGeometryError {
    LogTooLarge,
    ArithmeticOverflow,
    CompanionBankMismatch,
    StateNotPowerOfTwo,
    UnsupportedFundamentalHighVars,
    PcsCoinZoneMismatch,
    MaskOpeningDofTooSmall,
    MaskZoneLengthMismatch,
    ZonesExceedBank,
    InsufficientIndependentPcsCoins,
    EmptyLeaf,
    SourceLeafHalvesMismatch,
    SourceLeafNotPowerOfTwo,
    UnsupportedInnerGammaFoldCount,
    SourceFoldDoesNotConsumeLeaf,
    FoldExceedsMessage,
    CapExceedsTree,
    EmptyQuery,
    EmptyQuerySeed,
    QueryCarrierExceedsWidth,
    WalletBShapeMismatch,
    TranscriptBaselineExceedsSelected,
}

impl ZkCapsuleGeometry {
    /// Derive and validate every tree, fold, transcript, and row-ledger size.
    pub const fn checked(p: ZkCapsuleParameters) -> Result<Self, ZkCapsuleGeometryError> {
        let bank_len = match pow2(p.bank_log) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::LogTooLarge),
        };
        let companion_bank_len = match pow2(p.companion_bank_log) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::LogTooLarge),
        };
        if companion_bank_len != bank_len {
            return Err(ZkCapsuleGeometryError::CompanionBankMismatch);
        }

        if p.state_len == 0 || !p.state_len.is_power_of_two() {
            return Err(ZkCapsuleGeometryError::StateNotPowerOfTwo);
        }
        if p.mask_extra_dof < p.query_count {
            return Err(ZkCapsuleGeometryError::MaskOpeningDofTooSmall);
        }
        let state_vars = p.state_len.trailing_zeros() as usize;
        let fundamental_high_vars = match p.bank_log.checked_sub(state_vars) {
            Some(2) => 2,
            _ => return Err(ZkCapsuleGeometryError::UnsupportedFundamentalHighVars),
        };
        // The dedicated PCS-coin zone is one complete dyadic block at the end
        // of the bank. Natural novel-basis order then gives
        // X_{s+j} = W_log2(s) * X_j for s <= j < 2s, while the earlier state,
        // Libra mask, and terminal pads can be conditioned independently.
        if p.pcs_coin_len == 0 || !p.pcs_coin_len.is_power_of_two() {
            return Err(ZkCapsuleGeometryError::PcsCoinZoneMismatch);
        }
        let pcs_coin_start = match bank_len.checked_sub(p.pcs_coin_len) {
            Some(value) if value == p.pcs_coin_len => value,
            _ => return Err(ZkCapsuleGeometryError::PcsCoinZoneMismatch),
        };
        // Every authorization relation is extended over the whole bank. A
        // selector restricts semantic support to the fundamental state slice,
        // while the two high variables randomize terminal evaluations. Using
        // `state_vars` here would silently restore the raw nine-variable
        // terminal claims the ZK construction is meant to remove.
        let mask_sumcheck_vars = p.bank_log;
        let expected_mask_main_len =
            match zk_mask_buffer_len(mask_sumcheck_vars, p.mask_main_degree, p.mask_extra_dof) {
                Some(value) => value,
                None => return Err(ZkCapsuleGeometryError::ArithmeticOverflow),
            };
        if p.mask_main_len != expected_mask_main_len {
            return Err(ZkCapsuleGeometryError::MaskZoneLengthMismatch);
        }

        let mask_main_start = p.state_len;
        let occupied = match mask_main_start.checked_add(p.mask_main_len) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::ArithmeticOverflow),
        };
        if occupied > pcs_coin_start {
            return Err(ZkCapsuleGeometryError::ZonesExceedBank);
        }
        let trailing_padding_start = occupied;
        let trailing_padding_len = pcs_coin_start - occupied;
        let total_fresh_padding_len = match p.pcs_coin_len.checked_add(trailing_padding_len) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::ArithmeticOverflow),
        };

        let rate = match pow2(p.log_rate) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::LogTooLarge),
        };
        if p.source_bank_symbols_per_leaf == 0 || p.source_companion_symbols_per_leaf == 0 {
            return Err(ZkCapsuleGeometryError::EmptyLeaf);
        }
        if p.source_bank_symbols_per_leaf != p.source_companion_symbols_per_leaf {
            return Err(ZkCapsuleGeometryError::SourceLeafHalvesMismatch);
        }
        if !p.source_bank_symbols_per_leaf.is_power_of_two() {
            return Err(ZkCapsuleGeometryError::SourceLeafNotPowerOfTwo);
        }
        if p.source_inner_gamma_folds != 1 {
            return Err(ZkCapsuleGeometryError::UnsupportedInnerGammaFoldCount);
        }
        let source_leaf_symbols = match p
            .source_bank_symbols_per_leaf
            .checked_add(p.source_companion_symbols_per_leaf)
        {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::ArithmeticOverflow),
        };
        let expected_bank_leaf_symbols = match pow2(p.source_standard_fold_log) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::LogTooLarge),
        };
        if p.source_bank_symbols_per_leaf != expected_bank_leaf_symbols {
            return Err(ZkCapsuleGeometryError::SourceFoldDoesNotConsumeLeaf);
        }
        if p.source_standard_fold_log > p.bank_log {
            return Err(ZkCapsuleGeometryError::FoldExceedsMessage);
        }

        let source_domain_log = match p.bank_log.checked_add(p.log_rate) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::ArithmeticOverflow),
        };
        let source_domain_len = match pow2(source_domain_log) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::LogTooLarge),
        };
        let source_leaf_count = source_domain_len / p.source_bank_symbols_per_leaf;
        let source_tree_depth = source_domain_log - p.source_standard_fold_log;
        if p.source_cap_depth > source_tree_depth {
            return Err(ZkCapsuleGeometryError::CapExceedsTree);
        }
        let source_path_depth = source_tree_depth - p.source_cap_depth;

        let mid_log = p.bank_log - p.source_standard_fold_log;
        let mid_domain_log = match mid_log.checked_add(p.log_rate) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::ArithmeticOverflow),
        };
        if p.second_wide_fold_log > mid_log {
            return Err(ZkCapsuleGeometryError::FoldExceedsMessage);
        }
        let mid_leaf_symbols = match pow2(p.second_wide_fold_log) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::LogTooLarge),
        };
        let mid_tree_depth = mid_domain_log - p.second_wide_fold_log;
        let mid_leaf_count = match pow2(mid_tree_depth) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::LogTooLarge),
        };
        if p.mid_cap_depth > mid_tree_depth {
            return Err(ZkCapsuleGeometryError::CapExceedsTree);
        }
        let mid_path_depth = mid_tree_depth - p.mid_cap_depth;

        let tail_log = mid_log - p.second_wide_fold_log;
        let tail_len = match pow2(tail_log) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::LogTooLarge),
        };
        if p.tail_local_fold_log > tail_log {
            return Err(ZkCapsuleGeometryError::FoldExceedsMessage);
        }
        let final_h_log = tail_log - p.tail_local_fold_log;
        let final_h_len = match pow2(final_h_log) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::LogTooLarge),
        };

        if p.query_count == 0 {
            return Err(ZkCapsuleGeometryError::EmptyQuery);
        }
        if p.query_seed_bits == 0 {
            return Err(ZkCapsuleGeometryError::EmptyQuerySeed);
        }
        // Sample a uniform joint source leaf, not a member-codeword
        // position. Every opening already carries all 8 + 8 leaf symbols,
        // so member-position bits would be sampled and then ignored.
        let query_width_bits = source_tree_depth;
        let query_bits = match p.query_count.checked_mul(query_width_bits) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::ArithmeticOverflow),
        };
        let query_seed_count = div_ceil(query_bits, p.query_seed_bits);
        if p.query_bits_with_existing_carriers > query_width_bits {
            return Err(ZkCapsuleGeometryError::QueryCarrierExceedsWidth);
        }
        let query_bits_requiring_aux_carrier =
            query_width_bits - p.query_bits_with_existing_carriers;

        // A wide source query reveals every bank symbol in its leaf. The
        // dedicated, unconditioned PCS-coin zone must therefore supply at
        // least one independent random degree of freedom per worst-case raw
        // observation. This cardinality check is paired with the affine
        // encoder's executable W_n/Vandermonde rank certificate.
        let raw_source_observation_bound =
            match p.query_count.checked_mul(p.source_bank_symbols_per_leaf) {
                Some(value) => value,
                None => return Err(ZkCapsuleGeometryError::ArithmeticOverflow),
            };
        if p.pcs_coin_len < raw_source_observation_bound {
            return Err(ZkCapsuleGeometryError::InsufficientIndependentPcsCoins);
        }

        if p.wallet_b_legs != 2 || p.wallet_b_stride < source_path_depth + mid_path_depth {
            return Err(ZkCapsuleGeometryError::WalletBShapeMismatch);
        }
        // C1 packs the two path families densely inside one per-query tile.
        // There is no family-local dyadic tail: both roots are exposed from
        // their final feed-forward node expressions.
        let source_uses_root_copy_tail = false;
        let mid_uses_root_copy_tail = false;
        let wallet_a_symbols_per_query = match source_leaf_symbols.checked_add(mid_leaf_symbols) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::ArithmeticOverflow),
        };
        let wallet_a_symbols_per_auth = match p.query_count.checked_mul(wallet_a_symbols_per_query)
        {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::ArithmeticOverflow),
        };

        let wallet_b_slots_per_auth = match p.query_count.checked_mul(p.wallet_b_stride) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::ArithmeticOverflow),
        };

        let selected_source_cap_nodes = match pow2(p.source_cap_depth) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::LogTooLarge),
        };
        let baseline_source_cap_nodes = match pow2(p.baseline_source_cap_depth) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::LogTooLarge),
        };
        let selected_mid_cap_nodes = match pow2(p.mid_cap_depth) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::LogTooLarge),
        };
        let baseline_mid_cap_nodes = match pow2(p.baseline_mid_cap_depth) {
            Some(value) => value,
            None => return Err(ZkCapsuleGeometryError::LogTooLarge),
        };
        let source_transcript_delta_lanes = (selected_source_cap_nodes as isize
            - baseline_source_cap_nodes as isize)
            * p.digest_field_lanes as isize;
        let mid_transcript_delta_lanes = (selected_mid_cap_nodes as isize
            - baseline_mid_cap_nodes as isize)
            * p.digest_field_lanes as isize;
        let tail_transcript_delta_lanes = tail_len as isize - p.baseline_tail_len as isize;

        Ok(Self {
            bank_log: p.bank_log,
            bank_len,
            companion_bank_len,
            state_len: p.state_len,
            state_vars,
            fundamental_high_vars,
            pcs_coin_start,
            pcs_coin_len: p.pcs_coin_len,
            mask_sumcheck_vars,
            mask_main_degree: p.mask_main_degree,
            mask_extra_dof: p.mask_extra_dof,
            mask_main_start,
            mask_main_len: p.mask_main_len,
            trailing_padding_start,
            trailing_padding_len,
            total_fresh_padding_len,
            raw_source_observation_bound,
            log_rate: p.log_rate,
            rate,
            source_domain_log,
            source_domain_len,
            source_bank_symbols_per_leaf: p.source_bank_symbols_per_leaf,
            source_companion_symbols_per_leaf: p.source_companion_symbols_per_leaf,
            source_leaf_symbols,
            source_inner_gamma_folds: p.source_inner_gamma_folds,
            source_standard_fold_log: p.source_standard_fold_log,
            source_leaf_count,
            source_tree_depth,
            source_cap_depth: p.source_cap_depth,
            source_path_depth,
            mid_log,
            mid_domain_log,
            mid_leaf_symbols,
            mid_leaf_count,
            mid_tree_depth,
            mid_cap_depth: p.mid_cap_depth,
            mid_path_depth,
            second_wide_fold_log: p.second_wide_fold_log,
            tail_log,
            tail_len,
            tail_local_fold_log: p.tail_local_fold_log,
            final_h_log,
            final_h_len,
            query_width_bits,
            query_count: p.query_count,
            query_seed_bits: p.query_seed_bits,
            query_seed_count,
            query_bits_with_existing_carriers: p.query_bits_with_existing_carriers,
            query_bits_requiring_aux_carrier,
            wallet_a_symbols_per_auth,
            wallet_b_legs: p.wallet_b_legs,
            wallet_b_stride: p.wallet_b_stride,
            source_uses_root_copy_tail,
            mid_uses_root_copy_tail,
            wallet_b_slots_per_auth,
            source_transcript_delta_lanes,
            mid_transcript_delta_lanes,
            tail_transcript_delta_lanes,
        })
    }

    #[inline]
    pub const fn query_count(&self) -> usize {
        self.query_count
    }

    #[inline]
    pub const fn query_seed_count(&self) -> usize {
        self.query_seed_count
    }

    #[inline]
    pub const fn wallet_a_symbols_per_auth(&self) -> usize {
        self.wallet_a_symbols_per_auth
    }

    #[inline]
    pub const fn wallet_b_slots_per_auth(&self) -> usize {
        self.wallet_b_slots_per_auth
    }

    #[inline]
    pub const fn source_transcript_delta_lanes(&self) -> isize {
        self.source_transcript_delta_lanes
    }

    #[inline]
    pub const fn mid_transcript_delta_lanes(&self) -> isize {
        self.mid_transcript_delta_lanes
    }

    #[inline]
    pub const fn tail_transcript_delta_lanes(&self) -> isize {
        self.tail_transcript_delta_lanes
    }
}

const fn pow2(log: usize) -> Option<usize> {
    if log >= usize::BITS as usize {
        None
    } else {
        Some(1usize << log)
    }
}

const fn div_ceil(value: usize, divisor: usize) -> usize {
    value / divisor + if value.is_multiple_of(divisor) { 0 } else { 1 }
}

/// Buffer length used by the characteristic-two ZK MLE-check mask.
///
/// This is the executable form of the official dimension rule: enough rows
/// for all variables and enough total coefficients for `n*d + 1` masking
/// constraints plus the opening degrees of freedom.
const fn zk_mask_buffer_len(n_vars: usize, degree: usize, n_extra_dof: usize) -> Option<usize> {
    let degree_plus_one = match degree.checked_add(1) {
        Some(value) => value,
        None => return None,
    };
    let row_len = match ceil_pow2(degree_plus_one) {
        Some(value) => value,
        None => return None,
    };
    let rows_for_vars = match ceil_pow2(n_vars) {
        Some(value) => value,
        None => return None,
    };
    let constrained = match n_vars.checked_mul(degree) {
        Some(value) => value,
        None => return None,
    };
    let constrained_plus_one = match constrained.checked_add(1) {
        Some(value) => value,
        None => return None,
    };
    let min_size = match constrained_plus_one.checked_add(n_extra_dof) {
        Some(value) => value,
        None => return None,
    };
    let padded_size = match ceil_pow2(min_size) {
        Some(value) => value,
        None => return None,
    };
    let rows_for_size = div_ceil(padded_size, row_len);
    let rows = if rows_for_vars > rows_for_size {
        rows_for_vars
    } else {
        rows_for_size
    };
    let low_coordinate_len = match rows.checked_mul(row_len) {
        Some(value) => value,
        None => return None,
    };
    let high_coordinate_len = match n_vars.checked_mul(row_len) {
        Some(value) => value,
        None => return None,
    };
    low_coordinate_len.checked_add(high_coordinate_len)
}

const fn ceil_pow2(value: usize) -> Option<usize> {
    if value <= 1 {
        return Some(1);
    }
    let mut out = 1usize;
    while out < value {
        out = match out.checked_mul(2) {
            Some(next) => next,
            None => return None,
        };
    }
    Some(out)
}

/// Selected authorization ZK-capsule parameters.
pub const ZK_AUTH_CAPSULE_PARAMETERS: ZkCapsuleParameters = ZkCapsuleParameters {
    bank_log: 11,
    companion_bank_log: 11,
    state_len: 512,
    pcs_coin_len: 1_024,
    mask_main_degree: 10,
    mask_extra_dof: 65,
    mask_main_len: 432,
    log_rate: 5,
    source_bank_symbols_per_leaf: 8,
    source_companion_symbols_per_leaf: 8,
    source_inner_gamma_folds: 1,
    source_standard_fold_log: 3,
    source_cap_depth: 3,
    mid_cap_depth: 3,
    second_wide_fold_log: 4,
    tail_local_fold_log: 1,
    query_count: 65,
    query_seed_bits: u128::BITS as usize,
    query_bits_with_existing_carriers: 10,
    wallet_b_legs: 2,
    wallet_b_stride: 16,
    digest_field_lanes: 2,
    baseline_source_cap_depth: 5,
    baseline_mid_cap_depth: 0,
    baseline_tail_len: 2,
};

/// Checked selected geometry.  A bad edit to the parameter contract fails at
/// compile time instead of drifting into a benchmark or proof implementation.
pub const ZK_AUTH_CAPSULE_GEOMETRY: ZkCapsuleGeometry =
    match ZkCapsuleGeometry::checked(ZK_AUTH_CAPSULE_PARAMETERS) {
        Ok(geometry) => geometry,
        Err(_) => panic!("invalid authorization ZK-capsule geometry"),
    };

/// Source and mid path directions carry query bits `q0..q11`; one explicit
/// auxiliary cell carries `q12`, which selects both the source and mid cap.
pub const QUERY_BITS_REQUIRING_AUX_CARRIER: usize =
    ZK_AUTH_CAPSULE_GEOMETRY.query_bits_requiring_aux_carrier;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk_affine_code::{
        AFFINE_CODE_LEN, AFFINE_CODE_LOG_LEN, AFFINE_CODE_LOG_RATE, AFFINE_CODE_MESSAGE_LEN,
        AFFINE_CODE_MESSAGE_LOG, AFFINE_FRESH_PADDING_LEN, AFFINE_FRESH_PADDING_START,
        AFFINE_LIBRA_MASK_LEN, AFFINE_LIBRA_MASK_START, AFFINE_PCS_COINS_LEN,
        AFFINE_PCS_COINS_START,
    };

    #[test]
    fn selected_interleaved_geometry_is_derived_exactly() {
        let g = ZK_AUTH_CAPSULE_GEOMETRY;

        assert_eq!(g.bank_log, 11);
        assert_eq!(g.bank_len, 1 << g.bank_log);
        assert_eq!(g.companion_bank_len, g.bank_len);
        assert_eq!(g.state_len, 512);
        assert_eq!(g.state_vars, 9);
        assert_eq!(g.fundamental_high_vars, 2);
        assert_eq!(g.pcs_coin_start, 1_024);
        assert_eq!(g.pcs_coin_len, 1_024);
        assert_eq!(g.mask_sumcheck_vars, g.bank_log);
        assert_eq!(g.mask_sumcheck_vars, 11);
        assert_eq!(g.mask_main_degree, 10);
        assert_eq!(g.mask_extra_dof, g.query_count);
        assert_eq!(g.mask_main_start, 512);
        assert_eq!(g.mask_main_len, 432);
        assert_eq!(g.trailing_padding_start, 944);
        assert_eq!(g.trailing_padding_len, 80);
        assert_eq!(g.total_fresh_padding_len, 1_104);
        assert_eq!(g.raw_source_observation_bound, 8 * g.query_count);
        assert_eq!(g.raw_source_observation_bound, 520);
        assert!(g.pcs_coin_len >= g.raw_source_observation_bound);

        assert_eq!(g.log_rate, 5);
        assert_eq!(g.rate, 1 << g.log_rate);
        assert_eq!(g.source_domain_log, g.bank_log + g.log_rate);
        assert_eq!(g.source_domain_log, 16);
        assert_eq!(g.source_domain_len, 1 << g.source_domain_log);
        assert_eq!(g.source_bank_symbols_per_leaf, 8);
        assert_eq!(g.source_companion_symbols_per_leaf, 8);
        assert_eq!(
            g.source_leaf_symbols,
            g.source_bank_symbols_per_leaf + g.source_companion_symbols_per_leaf
        );
        assert_eq!(g.source_leaf_symbols, 16);
        assert_eq!(g.source_inner_gamma_folds, 1);
        assert_eq!(g.source_standard_fold_log, 3);
        assert_eq!(
            g.source_leaf_count,
            g.source_domain_len / g.source_bank_symbols_per_leaf
        );
        assert_eq!(g.source_tree_depth, g.source_leaf_count.ilog2() as usize);
        assert_eq!(g.source_tree_depth, 13);
        assert_eq!(g.source_cap_depth, 3);
        assert_eq!(
            g.source_path_depth,
            g.source_tree_depth - g.source_cap_depth
        );
        assert_eq!(g.source_path_depth, 10);

        assert_eq!(g.mid_log, g.bank_log - g.source_standard_fold_log);
        assert_eq!(g.mid_log, 8);
        assert_eq!(g.mid_domain_log, g.mid_log + g.log_rate);
        assert_eq!(g.mid_leaf_symbols, 1 << g.second_wide_fold_log);
        assert_eq!(g.second_wide_fold_log, 4);
        assert_eq!(g.mid_tree_depth, g.mid_domain_log - g.second_wide_fold_log);
        assert_eq!(g.mid_tree_depth, 9);
        assert_eq!(g.mid_leaf_count, 1 << g.mid_tree_depth);
        assert_eq!(g.mid_cap_depth, 3);
        assert_eq!(g.mid_path_depth, g.mid_tree_depth - g.mid_cap_depth);
        assert_eq!(g.mid_path_depth, 6);

        assert_eq!(g.tail_log, g.mid_log - g.second_wide_fold_log);
        assert_eq!(g.tail_len, 1 << g.tail_log);
        assert_eq!(g.tail_len, 16);
        assert_eq!(g.tail_local_fold_log, 1);
        assert_eq!(g.final_h_log, g.tail_log - g.tail_local_fold_log);
        assert_eq!(g.final_h_len, 1 << g.final_h_log);
        assert_eq!(g.final_h_len, 8);

        // Geometry and the only accepted affine encoder must remain one
        // compile-and-test-time contract. The old window encoder is not a
        // selectable implementation of this shape.
        assert_eq!(g.bank_log, AFFINE_CODE_MESSAGE_LOG);
        assert_eq!(g.bank_len, AFFINE_CODE_MESSAGE_LEN);
        assert_eq!(g.log_rate, AFFINE_CODE_LOG_RATE);
        assert_eq!(g.source_domain_log, AFFINE_CODE_LOG_LEN);
        assert_eq!(g.source_domain_len, AFFINE_CODE_LEN);
        assert_eq!(g.pcs_coin_start, AFFINE_PCS_COINS_START);
        assert_eq!(g.pcs_coin_len, AFFINE_PCS_COINS_LEN);
        assert_eq!(g.mask_main_start, AFFINE_LIBRA_MASK_START);
        assert_eq!(g.mask_main_len, AFFINE_LIBRA_MASK_LEN);
        assert_eq!(g.trailing_padding_start, AFFINE_FRESH_PADDING_START);
        assert_eq!(g.trailing_padding_len, AFFINE_FRESH_PADDING_LEN);
    }

    #[test]
    fn query_and_recursive_wallet_ledgers_are_derived() {
        let g = ZK_AUTH_CAPSULE_GEOMETRY;

        assert_eq!(g.query_width_bits, g.source_tree_depth);
        assert_eq!(g.query_width_bits, 13);
        assert_eq!(g.query_count(), 65);
        assert_eq!(
            g.query_seed_count(),
            (g.query_count * g.query_width_bits).div_ceil(g.query_seed_bits)
        );
        assert_eq!(g.query_seed_count(), 7);
        assert_eq!(g.query_bits_with_existing_carriers, 10);
        assert_eq!(g.query_bits_requiring_aux_carrier, 3);
        assert_eq!(QUERY_BITS_REQUIRING_AUX_CARRIER, 3);
        assert_eq!(
            g.wallet_a_symbols_per_auth(),
            g.query_count * (g.source_leaf_symbols + g.mid_leaf_symbols)
        );
        assert_eq!(g.wallet_a_symbols_per_auth(), 2_080);
        assert_eq!(g.wallet_b_legs, 2);
        assert_eq!(g.wallet_b_stride, 16);
        assert!(!g.source_uses_root_copy_tail);
        assert!(!g.mid_uses_root_copy_tail);
        assert_eq!(
            g.wallet_b_slots_per_auth(),
            g.query_count * g.wallet_b_stride
        );
        assert_eq!(g.wallet_b_slots_per_auth(), 1_040);
    }

    #[test]
    fn transcript_deltas_are_cap_and_tail_differences() {
        let p = ZK_AUTH_CAPSULE_PARAMETERS;
        let g = ZK_AUTH_CAPSULE_GEOMETRY;

        assert_eq!(
            g.source_transcript_delta_lanes(),
            ((1 << g.source_cap_depth) as isize - (1 << p.baseline_source_cap_depth) as isize)
                * p.digest_field_lanes as isize
        );
        assert_eq!(g.source_transcript_delta_lanes(), -48);
        assert_eq!(
            g.mid_transcript_delta_lanes(),
            ((1 << g.mid_cap_depth) as isize - (1 << p.baseline_mid_cap_depth) as isize)
                * p.digest_field_lanes as isize
        );
        assert_eq!(g.mid_transcript_delta_lanes(), 14);
        assert_eq!(
            g.tail_transcript_delta_lanes(),
            g.tail_len as isize - p.baseline_tail_len as isize
        );
        assert_eq!(g.tail_transcript_delta_lanes(), 14);
    }

    #[test]
    fn checked_constructor_rejects_invalid_shapes() {
        let mut p = ZK_AUTH_CAPSULE_PARAMETERS;
        p.companion_bank_log = p.bank_log - 1;
        assert_eq!(
            ZkCapsuleGeometry::checked(p),
            Err(ZkCapsuleGeometryError::CompanionBankMismatch)
        );

        let mut p = ZK_AUTH_CAPSULE_PARAMETERS;
        p.mask_main_len = p.bank_len_for_test() - p.state_len + 1;
        assert_eq!(
            ZkCapsuleGeometry::checked(p),
            Err(ZkCapsuleGeometryError::MaskZoneLengthMismatch)
        );

        let mut p = ZK_AUTH_CAPSULE_PARAMETERS;
        p.mask_extra_dof = p.query_count - 1;
        assert_eq!(
            ZkCapsuleGeometry::checked(p),
            Err(ZkCapsuleGeometryError::MaskOpeningDofTooSmall)
        );

        let mut p = ZK_AUTH_CAPSULE_PARAMETERS;
        p.bank_log -= 1;
        p.companion_bank_log -= 1;
        assert_eq!(
            ZkCapsuleGeometry::checked(p),
            Err(ZkCapsuleGeometryError::UnsupportedFundamentalHighVars)
        );

        let mut p = ZK_AUTH_CAPSULE_PARAMETERS;
        p.pcs_coin_len /= 2;
        assert_eq!(
            ZkCapsuleGeometry::checked(p),
            Err(ZkCapsuleGeometryError::PcsCoinZoneMismatch)
        );

        let mut p = ZK_AUTH_CAPSULE_PARAMETERS;
        p.mask_extra_dof = 2_048;
        p.mask_main_len = zk_mask_buffer_len(p.bank_log, p.mask_main_degree, p.mask_extra_dof)
            .expect("test main mask geometry");
        assert_eq!(
            ZkCapsuleGeometry::checked(p),
            Err(ZkCapsuleGeometryError::ZonesExceedBank)
        );

        let mut p = ZK_AUTH_CAPSULE_PARAMETERS;
        p.source_companion_symbols_per_leaf /= 2;
        assert_eq!(
            ZkCapsuleGeometry::checked(p),
            Err(ZkCapsuleGeometryError::SourceLeafHalvesMismatch)
        );

        let mut p = ZK_AUTH_CAPSULE_PARAMETERS;
        p.source_standard_fold_log -= 1;
        assert_eq!(
            ZkCapsuleGeometry::checked(p),
            Err(ZkCapsuleGeometryError::SourceFoldDoesNotConsumeLeaf)
        );

        let mut p = ZK_AUTH_CAPSULE_PARAMETERS;
        p.source_cap_depth = usize::BITS as usize - 1;
        assert_eq!(
            ZkCapsuleGeometry::checked(p),
            Err(ZkCapsuleGeometryError::CapExceedsTree)
        );

        let mut p = ZK_AUTH_CAPSULE_PARAMETERS;
        p.query_seed_bits = 0;
        assert_eq!(
            ZkCapsuleGeometry::checked(p),
            Err(ZkCapsuleGeometryError::EmptyQuerySeed)
        );

        let mut p = ZK_AUTH_CAPSULE_PARAMETERS;
        p.query_bits_with_existing_carriers = ZK_AUTH_CAPSULE_GEOMETRY.query_width_bits + 1;
        assert_eq!(
            ZkCapsuleGeometry::checked(p),
            Err(ZkCapsuleGeometryError::QueryCarrierExceedsWidth)
        );

        let mut p = ZK_AUTH_CAPSULE_PARAMETERS;
        p.wallet_b_stride = ZK_AUTH_CAPSULE_GEOMETRY.source_path_depth - 1;
        assert_eq!(
            ZkCapsuleGeometry::checked(p),
            Err(ZkCapsuleGeometryError::WalletBShapeMismatch)
        );
    }

    impl ZkCapsuleParameters {
        fn bank_len_for_test(self) -> usize {
            1usize << self.bank_log
        }
    }
}
