// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Selected affine LCH additive Reed–Solomon code for the production ZK
//! authorization capsule.
//!
//! This is one rate-1/32 code over the single affine domain
//! `beta + span{b_0, ..., b_15}`. The production capsule PCS uses this code for
//! its source, mid, and tail oracles and applies the selected low-to-high
//! binary BaseFold schedule between its arity-16 commitment stages.
//!
//! The committed bank is already the coefficient/oracle vector in natural
//! LCH novel-basis order. It is zero-padded without a permutation. Therefore
//! inverse-butterfly FRI folds of adjacent codeword pairs eliminate MLE
//! variables from lowest to highest. The authorization challenge/point order
//! must mirror that convention.

use noid_core::hardware::{clmul_gcm, flat_to_tower_u128, tower_to_flat_u128};
use noid_core::{Block128, TowerField};

pub const AFFINE_CODE_MESSAGE_LOG: usize = 11;
pub const AFFINE_CODE_LOG_RATE: usize = 5;
pub const AFFINE_CODE_LOG_LEN: usize = AFFINE_CODE_MESSAGE_LOG + AFFINE_CODE_LOG_RATE;
pub const AFFINE_CODE_MESSAGE_LEN: usize = 1 << AFFINE_CODE_MESSAGE_LOG;
pub const AFFINE_CODE_LEN: usize = 1 << AFFINE_CODE_LOG_LEN;
/// The selected BCHKS chain consists of the source layer plus the seven
/// post-fold child layers.
pub const AFFINE_SELECTED_RS_LAYER_COUNT: usize = 8;
pub const AFFINE_FUNDAMENTAL_LOG: usize = 9;
pub const AFFINE_FUNDAMENTAL_LEN: usize = 1 << AFFINE_FUNDAMENTAL_LOG;
pub const AFFINE_STATE_LEN: usize = 512;
pub const AFFINE_LIBRA_MASK_START: usize = AFFINE_STATE_LEN;
pub const AFFINE_LIBRA_MASK_LEN: usize = 432;
pub const AFFINE_FRESH_PADDING_START: usize = AFFINE_LIBRA_MASK_START + AFFINE_LIBRA_MASK_LEN;
pub const AFFINE_PCS_COINS_LEN: usize = 1 << 10;
pub const AFFINE_PCS_COINS_START: usize = AFFINE_CODE_MESSAGE_LEN - AFFINE_PCS_COINS_LEN;
pub const AFFINE_FRESH_PADDING_LEN: usize = AFFINE_PCS_COINS_START - AFFINE_FRESH_PADDING_START;
pub const AFFINE_RANK_RANDOM_BLOCK_START: usize = AFFINE_PCS_COINS_START;
pub const AFFINE_RANK_RANDOM_BLOCK_LEN: usize = AFFINE_PCS_COINS_LEN;
pub const AFFINE_RANK_MAX_QUERIES: usize = AFFINE_RANK_RANDOM_BLOCK_LEN;
pub const AFFINE_RANK_FACTOR_LEVEL: usize =
    AFFINE_RANK_RANDOM_BLOCK_START.trailing_zeros() as usize;

const _: () = assert!(AFFINE_CODE_LOG_LEN == 16);
const _: () = assert!(AFFINE_CODE_MESSAGE_LEN == 2_048);
const _: () = assert!(AFFINE_CODE_LEN == 65_536);
const _: () = assert!(AFFINE_SELECTED_RS_LAYER_COUNT == 8);
const _: () = assert!(AFFINE_SELECTED_RS_LAYER_COUNT <= AFFINE_CODE_MESSAGE_LOG + 1);
const _: () = assert!(AFFINE_LIBRA_MASK_START == 512);
const _: () = assert!(AFFINE_FRESH_PADDING_START == 944);
const _: () = assert!(AFFINE_FRESH_PADDING_LEN == 80);
const _: () = assert!(AFFINE_PCS_COINS_START == 1_024);
const _: () = assert!(AFFINE_PCS_COINS_LEN == 1_024);
const _: () = assert!(AFFINE_RANK_FACTOR_LEVEL == 10);
const _: () = assert!(
    AFFINE_RANK_RANDOM_BLOCK_START + AFFINE_RANK_RANDOM_BLOCK_LEN <= AFFINE_CODE_MESSAGE_LEN
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAffineCodeError {
    BasisRank {
        expected: usize,
        actual: usize,
    },
    BetaInCodeSpan,
    BetaInFundamentalSpan,
    ZeroSubspaceNormalizer,
    MessageLength {
        expected: usize,
        actual: usize,
    },
    FoldCountOutOfRange,
    CodewordLength {
        expected: usize,
        actual: usize,
    },
    DomainIndexOutOfRange,
    LayerOutOfRange,
    BlockOutOfRange,
    CosetLength {
        expected: usize,
        actual: usize,
    },
    CosetIndexOutOfRange,
    ProjectedBasisRank {
        layer: usize,
        expected: usize,
        actual: usize,
    },
    ProjectedBetaInBasisSpan {
        layer: usize,
    },
    ProjectedDomainCoordinateMismatch {
        layer: usize,
        index: usize,
    },
    ProjectedDomainCollision {
        layer: usize,
        expected: usize,
        actual: usize,
    },
    TooManyDistinctQueries {
        max: usize,
        actual: usize,
    },
    RankFactorVanished,
}

/// Checked implementation manifest for one selected additive-LCH quotient
/// layer.
///
/// The finite checks represented here establish the projected affine-domain
/// coordinates, their rank and distinctness, and their correspondence with
/// the implementation's normalized subspace polynomial.  The fields
/// `paper_degree`, `algebraic_rs_min_distance`, and `rho_*` are the standard
/// algebraic consequences once the LCH basis is identified with all
/// degree-`<K` polynomials on those distinct points.  They are deliberately
/// not described as conclusions proved by finite testing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffineSelectedRsLayerCertificate {
    /// Number of already eliminated low variables, `j`.
    pub folds_done: usize,
    /// RS block length `N = 2^(16-j)`.
    pub domain_len: usize,
    /// RS dimension `K = 2^(11-j)`.
    pub message_len: usize,
    /// BCHKS degree convention `k = K-1`.
    pub paper_degree: usize,
    /// Standard RS algebraic distance `d = N-K+1`.
    pub algebraic_rs_min_distance: usize,
    /// Slightly reduced BCHKS rate `rho = (K-1)/N = 1-d/N`.
    pub rho_numerator: u128,
    pub rho_denominator: u128,
    pub inverse_rate: usize,
    /// `pi_j(beta)` for the normalized subspace polynomial `pi_j`.
    pub projected_beta: Block128,
    /// Ordered basis `pi_j(b_j), ..., pi_j(b_15)` of the quotient domain.
    pub projected_basis: Vec<Block128>,
    pub projected_basis_rank: usize,
    pub projected_beta_outside_basis_span: bool,
    /// Number of coordinates checked against
    /// `pi_j(domain_point(index << j))`.
    pub checked_coordinate_count: usize,
    pub distinct_projected_point_count: usize,
}

impl AffineSelectedRsLayerCertificate {
    /// Evaluate the checked affine coordinate formula
    /// `pi_j(beta) + sum index_r*pi_j(b_{j+r})`.
    pub fn projected_domain_point(&self, index: usize) -> Result<Block128, ZkAffineCodeError> {
        if index >= self.domain_len {
            return Err(ZkAffineCodeError::DomainIndexOutOfRange);
        }
        let mut point = to_flat(self.projected_beta);
        for (bit, &basis) in self.projected_basis.iter().enumerate() {
            if (index >> bit) & 1 == 1 {
                point ^= to_flat(basis);
            }
        }
        Ok(from_flat(point))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffineSelectedRsManifest {
    pub layers: [AffineSelectedRsLayerCertificate; AFFINE_SELECTED_RS_LAYER_COUNT],
}

/// Structural row-rank certificate for opened affine positions.
///
/// The certificate assumes logical novel coefficients `1024..2048` are
/// independently uniform and are not later conditioned by another claim.
/// Since `X_{1024+j} = W_10 * X_j`, `W_10` is nonzero on the affine domain,
/// and `{X_j}_{j<1024}` spans all degree-`<1024` polynomials, observations at
/// `q <= 1024` distinct points have row rank exactly `q`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffineHighPaddingRankCertificate {
    pub distinct_query_count: usize,
    pub certified_rank: usize,
    pub independent_coeff_start: usize,
    pub independent_coeff_len: usize,
    pub nonzero_factor_level: usize,
}

/// Checked affine LCH domain and its complete neighbors-last twiddle table.
#[derive(Clone)]
pub struct ZkAffineLchCode {
    basis_flat: [u128; AFFINE_CODE_LOG_LEN],
    beta_flat: u128,
    normalizers_flat: [u128; AFFINE_CODE_LOG_LEN],
    normalizer_inverses_flat: [u128; AFFINE_CODE_LOG_LEN],
    /// `twiddles[layer][block]`, including the affine beta contribution.
    twiddles_flat: Vec<Vec<u128>>,
}

impl ZkAffineLchCode {
    /// Selected flat-polynomial basis `b_i = x^i` and `beta = x^16`.
    /// The affine coset is therefore disjoint from both `H_16` and the
    /// fundamental `H_9` subset.
    pub fn selected() -> Result<Self, ZkAffineCodeError> {
        let basis = std::array::from_fn(|i| from_flat(1u128 << i));
        let beta = from_flat(1u128 << AFFINE_CODE_LOG_LEN);
        Self::checked(basis, beta)
    }

    pub fn checked(
        basis: [Block128; AFFINE_CODE_LOG_LEN],
        beta: Block128,
    ) -> Result<Self, ZkAffineCodeError> {
        let basis_flat = basis.map(to_flat);
        let beta_flat = to_flat(beta);

        let rank = binary_rank(&basis_flat);
        if rank != AFFINE_CODE_LOG_LEN {
            return Err(ZkAffineCodeError::BasisRank {
                expected: AFFINE_CODE_LOG_LEN,
                actual: rank,
            });
        }
        if binary_span_contains(&basis_flat, beta_flat) {
            return Err(ZkAffineCodeError::BetaInCodeSpan);
        }
        if binary_span_contains(&basis_flat[..AFFINE_FUNDAMENTAL_LOG], beta_flat) {
            return Err(ZkAffineCodeError::BetaInFundamentalSpan);
        }

        let mut raw_rows = Vec::with_capacity(AFFINE_CODE_LOG_LEN);
        raw_rows.push(basis_flat.to_vec());
        for level in 1..AFFINE_CODE_LOG_LEN {
            let previous = &raw_rows[level - 1];
            let root = previous[0];
            let mut row = Vec::with_capacity(AFFINE_CODE_LOG_LEN - level);
            for &value in &previous[1..] {
                row.push(flat_mul(value, value ^ root));
            }
            raw_rows.push(row);
        }

        let mut normalizers_flat = [0u128; AFFINE_CODE_LOG_LEN];
        let mut normalizer_inverses_flat = [0u128; AFFINE_CODE_LOG_LEN];
        for level in 0..AFFINE_CODE_LOG_LEN {
            let normalizer = raw_rows[level][0];
            if normalizer == 0 {
                return Err(ZkAffineCodeError::ZeroSubspaceNormalizer);
            }
            normalizers_flat[level] = normalizer;
            normalizer_inverses_flat[level] = flat_inverse(normalizer);
        }

        let mut beta_raw = [0u128; AFFINE_CODE_LOG_LEN];
        beta_raw[0] = beta_flat;
        for level in 1..AFFINE_CODE_LOG_LEN {
            let previous = beta_raw[level - 1];
            beta_raw[level] = flat_mul(previous, previous ^ normalizers_flat[level - 1]);
        }

        let normalized_rows: Vec<Vec<u128>> = raw_rows
            .iter()
            .enumerate()
            .map(|(level, row)| {
                row.iter()
                    .map(|&value| flat_mul(value, normalizer_inverses_flat[level]))
                    .collect()
            })
            .collect();
        let beta_normalized: [u128; AFFINE_CODE_LOG_LEN] =
            std::array::from_fn(|level| flat_mul(beta_raw[level], normalizer_inverses_flat[level]));

        let mut twiddles_flat = Vec::with_capacity(AFFINE_CODE_LOG_LEN);
        for layer in 0..AFFINE_CODE_LOG_LEN {
            let subspace_level = AFFINE_CODE_LOG_LEN - layer - 1;
            let higher_basis_evals = &normalized_rows[subspace_level][1..];
            let mut layer_twiddles = Vec::with_capacity(1usize << layer);
            for block in 0..1usize << layer {
                let mut twiddle = beta_normalized[subspace_level];
                for (bit, &value) in higher_basis_evals.iter().enumerate() {
                    if (block >> bit) & 1 == 1 {
                        twiddle ^= value;
                    }
                }
                layer_twiddles.push(twiddle);
            }
            twiddles_flat.push(layer_twiddles);
        }

        Ok(Self {
            basis_flat,
            beta_flat,
            normalizers_flat,
            normalizer_inverses_flat,
            twiddles_flat,
        })
    }

    pub fn basis(&self) -> [Block128; AFFINE_CODE_LOG_LEN] {
        self.basis_flat.map(from_flat)
    }

    pub fn beta(&self) -> Block128 {
        from_flat(self.beta_flat)
    }

    /// Enumerate `beta + sum_i index_i*b_i` in natural LSB-first order.
    pub fn domain_point(&self, index: usize) -> Result<Block128, ZkAffineCodeError> {
        if index >= AFFINE_CODE_LEN {
            return Err(ZkAffineCodeError::DomainIndexOutOfRange);
        }
        Ok(from_flat(self.domain_point_flat(index)))
    }

    /// Check one of the eight selected quotient layers used by the BCHKS
    /// arithmetic manifest.
    ///
    /// For `j = folds_done`, this constructs the normalized subspace map
    /// `pi_j`, checks that its projected basis has rank `16-j`, checks that
    /// `pi_j(beta)` is outside that span, and exhaustively compares all
    /// ordered projected coordinates with
    /// `pi_j(domain_point(index << j))`.  The returned degree and distance
    /// fields record the standard algebraic RS consequences of those LCH
    /// identities; enumeration is not presented as a proof of the RS
    /// root/distance theorem.
    pub fn certify_selected_rs_layer(
        &self,
        folds_done: usize,
    ) -> Result<AffineSelectedRsLayerCertificate, ZkAffineCodeError> {
        if folds_done >= AFFINE_SELECTED_RS_LAYER_COUNT {
            return Err(ZkAffineCodeError::LayerOutOfRange);
        }

        let domain_len = AFFINE_CODE_LEN >> folds_done;
        let message_len = AFFINE_CODE_MESSAGE_LEN >> folds_done;
        let paper_degree = message_len - 1;
        let algebraic_rs_min_distance = domain_len - message_len + 1;
        let projected_beta_flat = self.normalized_subspace_eval_flat(folds_done, self.beta_flat);
        let projected_basis_flat = self.basis_flat[folds_done..]
            .iter()
            .map(|&basis| self.normalized_subspace_eval_flat(folds_done, basis))
            .collect::<Vec<_>>();

        let projected_basis_rank = binary_rank(&projected_basis_flat);
        let expected_rank = AFFINE_CODE_LOG_LEN - folds_done;
        if projected_basis_rank != expected_rank {
            return Err(ZkAffineCodeError::ProjectedBasisRank {
                layer: folds_done,
                expected: expected_rank,
                actual: projected_basis_rank,
            });
        }
        let projected_beta_outside_basis_span =
            !binary_span_contains(&projected_basis_flat, projected_beta_flat);
        if !projected_beta_outside_basis_span {
            return Err(ZkAffineCodeError::ProjectedBetaInBasisSpan { layer: folds_done });
        }

        let mut distinct = std::collections::HashSet::with_capacity(domain_len);
        for index in 0..domain_len {
            let mut projected_from_basis = projected_beta_flat;
            for (bit, &basis) in projected_basis_flat.iter().enumerate() {
                if (index >> bit) & 1 == 1 {
                    projected_from_basis ^= basis;
                }
            }
            let representative = self.domain_point_flat(index << folds_done);
            let projected_from_source =
                self.normalized_subspace_eval_flat(folds_done, representative);
            if projected_from_basis != projected_from_source {
                return Err(ZkAffineCodeError::ProjectedDomainCoordinateMismatch {
                    layer: folds_done,
                    index,
                });
            }
            distinct.insert(projected_from_basis);
        }
        if distinct.len() != domain_len {
            return Err(ZkAffineCodeError::ProjectedDomainCollision {
                layer: folds_done,
                expected: domain_len,
                actual: distinct.len(),
            });
        }

        Ok(AffineSelectedRsLayerCertificate {
            folds_done,
            domain_len,
            message_len,
            paper_degree,
            algebraic_rs_min_distance,
            rho_numerator: paper_degree as u128,
            rho_denominator: domain_len as u128,
            inverse_rate: domain_len / message_len,
            projected_beta: from_flat(projected_beta_flat),
            projected_basis: projected_basis_flat.into_iter().map(from_flat).collect(),
            projected_basis_rank,
            projected_beta_outside_basis_span,
            checked_coordinate_count: domain_len,
            distinct_projected_point_count: distinct.len(),
        })
    }

    pub fn certify_selected_rs_manifest(
        &self,
    ) -> Result<AffineSelectedRsManifest, ZkAffineCodeError> {
        Ok(AffineSelectedRsManifest {
            layers: [
                self.certify_selected_rs_layer(0)?,
                self.certify_selected_rs_layer(1)?,
                self.certify_selected_rs_layer(2)?,
                self.certify_selected_rs_layer(3)?,
                self.certify_selected_rs_layer(4)?,
                self.certify_selected_rs_layer(5)?,
                self.certify_selected_rs_layer(6)?,
                self.certify_selected_rs_layer(7)?,
            ],
        })
    }

    /// Certify the observation rank contributed by the dedicated independent
    /// random coefficient block `1024..2048` after deduplicating query
    /// positions. Randomness/conditioning is a caller-side precondition; this
    /// helper certifies only the affine-domain algebra.
    pub fn certify_high_padding_rank(
        &self,
        query_positions: &[usize],
    ) -> Result<AffineHighPaddingRankCertificate, ZkAffineCodeError> {
        let mut distinct = std::collections::BTreeSet::new();
        for &position in query_positions {
            if position >= AFFINE_CODE_LEN {
                return Err(ZkAffineCodeError::DomainIndexOutOfRange);
            }
            distinct.insert(position);
        }
        if distinct.len() > AFFINE_RANK_MAX_QUERIES {
            return Err(ZkAffineCodeError::TooManyDistinctQueries {
                max: AFFINE_RANK_MAX_QUERIES,
                actual: distinct.len(),
            });
        }

        // X_{1024+j} = W_10 * X_j. beta is outside V_16, hence outside
        // V_10, so W_10 never vanishes on beta + V_16.
        let factor_level = AFFINE_RANK_FACTOR_LEVEL;
        for position in distinct.iter().copied() {
            if self.normalized_subspace_eval_flat(factor_level, self.domain_point_flat(position))
                == 0
            {
                return Err(ZkAffineCodeError::RankFactorVanished);
            }
        }

        Ok(AffineHighPaddingRankCertificate {
            distinct_query_count: distinct.len(),
            certified_rank: distinct.len(),
            independent_coeff_start: AFFINE_RANK_RANDOM_BLOCK_START,
            independent_coeff_len: AFFINE_RANK_RANDOM_BLOCK_LEN,
            nonzero_factor_level: factor_level,
        })
    }

    pub fn twiddle(&self, layer: usize, block: usize) -> Result<Block128, ZkAffineCodeError> {
        if layer >= AFFINE_CODE_LOG_LEN {
            return Err(ZkAffineCodeError::LayerOutOfRange);
        }
        let Some(&twiddle) = self.twiddles_flat[layer].get(block) else {
            return Err(ZkAffineCodeError::BlockOutOfRange);
        };
        Ok(from_flat(twiddle))
    }

    /// Encode one 2^11-element bank at rate 1/32.
    pub fn encode(&self, message: &[Block128]) -> Result<Vec<Block128>, ZkAffineCodeError> {
        self.encode_after_low_folds(message, 0)
    }

    /// Encode a message after `folds_done` lowest MLE variables have already
    /// been folded. The output uses the surviving prefix of the original LCH
    /// butterfly schedule, exactly matching FRI inverse-butterfly reduction.
    pub fn encode_after_low_folds(
        &self,
        message: &[Block128],
        folds_done: usize,
    ) -> Result<Vec<Block128>, ZkAffineCodeError> {
        if folds_done > AFFINE_CODE_MESSAGE_LOG {
            return Err(ZkAffineCodeError::FoldCountOutOfRange);
        }
        let message_log = AFFINE_CODE_MESSAGE_LOG - folds_done;
        let expected_message_len = 1usize << message_log;
        if message.len() != expected_message_len {
            return Err(ZkAffineCodeError::MessageLength {
                expected: expected_message_len,
                actual: message.len(),
            });
        }
        let code_log = AFFINE_CODE_LOG_LEN - folds_done;
        let mut data = vec![0u128; 1usize << code_log];
        for (raw_index, &value) in message.iter().enumerate() {
            data[raw_index] = to_flat(value);
        }
        self.forward_flat(&mut data, code_log);
        Ok(data.into_iter().map(from_flat).collect())
    }

    /// Encode extension-field coefficients with the same frozen affine LCH
    /// butterfly schedule. Twiddles remain in the embedded GF(2^128)
    /// subfield; only the message and all derived symbols live in `F`.
    pub fn encode_extension_after_low_folds<F>(
        &self,
        message: &[F],
        folds_done: usize,
    ) -> Result<Vec<F>, ZkAffineCodeError>
    where
        F: TowerField + From<Block128>,
    {
        if folds_done > AFFINE_CODE_MESSAGE_LOG {
            return Err(ZkAffineCodeError::FoldCountOutOfRange);
        }
        let message_log = AFFINE_CODE_MESSAGE_LOG - folds_done;
        let expected_message_len = 1usize << message_log;
        if message.len() != expected_message_len {
            return Err(ZkAffineCodeError::MessageLength {
                expected: expected_message_len,
                actual: message.len(),
            });
        }
        let code_log = AFFINE_CODE_LOG_LEN - folds_done;
        let mut data = vec![F::ZERO; 1usize << code_log];
        data[..message.len()].copy_from_slice(message);
        self.forward_extension(&mut data, code_log);
        Ok(data)
    }

    /// Exact inverse of one forward butterfly.
    pub fn inverse_butterfly(
        &self,
        layer: usize,
        block: usize,
        left: Block128,
        right: Block128,
    ) -> Result<(Block128, Block128), ZkAffineCodeError> {
        let twiddle = to_flat(self.twiddle(layer, block)?);
        let u_out = to_flat(left);
        let v_coeff = to_flat(right) ^ u_out;
        let u_coeff = u_out ^ flat_mul(v_coeff, twiddle);
        Ok((from_flat(u_coeff), from_flat(v_coeff)))
    }

    /// Split one current affine-code word into the two child endpoint words
    /// obtained by applying the exact inverse butterfly to every adjacent
    /// pair.
    ///
    /// For challenge `r`, [`Self::fold_codeword_once`] evaluates the child
    /// line as `at_zero + r * (at_zero + at_one)`.  This helper fixes that
    /// algebra and coordinate order only; it makes no proximity, agreement, or
    /// decoding claim about arbitrary input words.
    pub fn split_affine_fold_children(
        &self,
        parent: &[Block128],
        folds_done: usize,
    ) -> Result<(Vec<Block128>, Vec<Block128>), ZkAffineCodeError> {
        if folds_done >= AFFINE_CODE_LOG_LEN {
            return Err(ZkAffineCodeError::FoldCountOutOfRange);
        }
        let expected = 1usize << (AFFINE_CODE_LOG_LEN - folds_done);
        if parent.len() != expected {
            return Err(ZkAffineCodeError::CodewordLength {
                expected,
                actual: parent.len(),
            });
        }

        let child_len = expected / 2;
        let layer = AFFINE_CODE_LOG_LEN - folds_done - 1;
        let mut at_zero = Vec::with_capacity(child_len);
        let mut at_one = Vec::with_capacity(child_len);
        for (pair_index, pair) in parent.chunks_exact(2).enumerate() {
            let (zero, one) = self.inverse_butterfly(layer, pair_index, pair[0], pair[1])?;
            at_zero.push(zero);
            at_one.push(one);
        }
        Ok((at_zero, at_one))
    }

    /// Restore one parent word from two inverse-butterfly child endpoint
    /// words in the exact natural adjacent-pair order.
    ///
    /// This is the algebraic inverse of [`Self::split_affine_fold_children`]
    /// for every correctly shaped pair of field vectors.  Membership in any
    /// code, common agreement, and proximity preservation are deliberately
    /// outside this API.
    pub fn restore_affine_fold_parent(
        &self,
        at_zero: &[Block128],
        at_one: &[Block128],
        folds_done: usize,
    ) -> Result<Vec<Block128>, ZkAffineCodeError> {
        if folds_done >= AFFINE_CODE_LOG_LEN {
            return Err(ZkAffineCodeError::FoldCountOutOfRange);
        }
        let expected_child_len = 1usize << (AFFINE_CODE_LOG_LEN - folds_done - 1);
        for child in [at_zero, at_one] {
            if child.len() != expected_child_len {
                return Err(ZkAffineCodeError::CodewordLength {
                    expected: expected_child_len,
                    actual: child.len(),
                });
            }
        }

        let layer = AFFINE_CODE_LOG_LEN - folds_done - 1;
        let mut parent = Vec::with_capacity(2 * expected_child_len);
        for (block, (&zero, &one)) in at_zero.iter().zip(at_one).enumerate() {
            let left = zero + one * self.twiddle(layer, block)?;
            parent.push(left);
            parent.push(one + left);
        }
        Ok(parent)
    }

    /// DP24 inverse-butterfly FRI fold for one adjacent pair in the current
    /// codeword. `pair_index` is the output position after this fold.
    pub fn fold_pair(
        &self,
        folds_done: usize,
        pair_index: usize,
        left: Block128,
        right: Block128,
        challenge: Block128,
    ) -> Result<Block128, ZkAffineCodeError> {
        if folds_done >= AFFINE_CODE_LOG_LEN {
            return Err(ZkAffineCodeError::FoldCountOutOfRange);
        }
        let layer = AFFINE_CODE_LOG_LEN - folds_done - 1;
        if pair_index >= 1usize << layer {
            return Err(ZkAffineCodeError::BlockOutOfRange);
        }
        let (u, v) = self.inverse_butterfly(layer, pair_index, left, right)?;
        Ok(u + challenge * (u + v))
    }

    /// Extension-field form of [`Self::fold_pair`]. The inverse-butterfly
    /// twiddle is embedded from the base field before the wide fold.
    pub fn fold_pair_extension<F>(
        &self,
        folds_done: usize,
        pair_index: usize,
        left: F,
        right: F,
        challenge: F,
    ) -> Result<F, ZkAffineCodeError>
    where
        F: TowerField + From<Block128>,
    {
        if folds_done >= AFFINE_CODE_LOG_LEN {
            return Err(ZkAffineCodeError::FoldCountOutOfRange);
        }
        let layer = AFFINE_CODE_LOG_LEN - folds_done - 1;
        if pair_index >= 1usize << layer {
            return Err(ZkAffineCodeError::BlockOutOfRange);
        }
        let twiddle = F::from(self.twiddle(layer, pair_index)?);
        let v = right + left;
        let u = left + v * twiddle;
        Ok(u + challenge * (u + v))
    }

    pub fn fold_codeword_once(
        &self,
        codeword: &[Block128],
        folds_done: usize,
        challenge: Block128,
    ) -> Result<Vec<Block128>, ZkAffineCodeError> {
        if folds_done >= AFFINE_CODE_LOG_LEN {
            return Err(ZkAffineCodeError::FoldCountOutOfRange);
        }
        let expected = 1usize << (AFFINE_CODE_LOG_LEN - folds_done);
        if codeword.len() != expected {
            return Err(ZkAffineCodeError::CodewordLength {
                expected,
                actual: codeword.len(),
            });
        }
        codeword
            .chunks_exact(2)
            .enumerate()
            .map(|(pair_index, pair)| {
                self.fold_pair(folds_done, pair_index, pair[0], pair[1], challenge)
            })
            .collect()
    }

    /// Extension-field form of [`Self::fold_codeword_once`].
    pub fn fold_codeword_once_extension<F>(
        &self,
        codeword: &[F],
        folds_done: usize,
        challenge: F,
    ) -> Result<Vec<F>, ZkAffineCodeError>
    where
        F: TowerField + From<Block128>,
    {
        if folds_done >= AFFINE_CODE_LOG_LEN {
            return Err(ZkAffineCodeError::FoldCountOutOfRange);
        }
        let expected = 1usize << (AFFINE_CODE_LOG_LEN - folds_done);
        if codeword.len() != expected {
            return Err(ZkAffineCodeError::CodewordLength {
                expected,
                actual: codeword.len(),
            });
        }
        codeword
            .chunks_exact(2)
            .enumerate()
            .map(|(pair_index, pair)| {
                self.fold_pair_extension(folds_done, pair_index, pair[0], pair[1], challenge)
            })
            .collect()
    }

    /// Fold one contiguous `2^a` codeword coset, using its index in the
    /// current codeword and the exact global twiddles at every inner step.
    pub fn fold_contiguous_coset(
        &self,
        coset: &[Block128],
        folds_done: usize,
        coset_index: usize,
        challenges: &[Block128],
    ) -> Result<Block128, ZkAffineCodeError> {
        if folds_done + challenges.len() > AFFINE_CODE_LOG_LEN {
            return Err(ZkAffineCodeError::FoldCountOutOfRange);
        }
        let expected_coset_len = 1usize << challenges.len();
        if coset.len() != expected_coset_len {
            return Err(ZkAffineCodeError::CosetLength {
                expected: expected_coset_len,
                actual: coset.len(),
            });
        }
        let current_code_len = 1usize << (AFFINE_CODE_LOG_LEN - folds_done);
        if coset_index >= current_code_len / expected_coset_len {
            return Err(ZkAffineCodeError::CosetIndexOutOfRange);
        }

        let mut current = coset.to_vec();
        for (inner_fold, &challenge) in challenges.iter().enumerate() {
            let next_len = current.len() / 2;
            let mut next = Vec::with_capacity(next_len);
            for pair in 0..next_len {
                let global_pair_index = coset_index * next_len + pair;
                next.push(self.fold_pair(
                    folds_done + inner_fold,
                    global_pair_index,
                    current[2 * pair],
                    current[2 * pair + 1],
                    challenge,
                )?);
            }
            current = next;
        }
        Ok(current[0])
    }

    /// Extension-field form of [`Self::fold_contiguous_coset`].
    pub fn fold_contiguous_coset_extension<F>(
        &self,
        coset: &[F],
        folds_done: usize,
        coset_index: usize,
        challenges: &[F],
    ) -> Result<F, ZkAffineCodeError>
    where
        F: TowerField + From<Block128>,
    {
        if folds_done + challenges.len() > AFFINE_CODE_LOG_LEN {
            return Err(ZkAffineCodeError::FoldCountOutOfRange);
        }
        let expected_coset_len = 1usize << challenges.len();
        if coset.len() != expected_coset_len {
            return Err(ZkAffineCodeError::CosetLength {
                expected: expected_coset_len,
                actual: coset.len(),
            });
        }
        let current_code_len = 1usize << (AFFINE_CODE_LOG_LEN - folds_done);
        if coset_index >= current_code_len / expected_coset_len {
            return Err(ZkAffineCodeError::CosetIndexOutOfRange);
        }

        let mut current = coset.to_vec();
        for (inner_fold, &challenge) in challenges.iter().enumerate() {
            let next_len = current.len() / 2;
            let mut next = Vec::with_capacity(next_len);
            for pair in 0..next_len {
                let global_pair_index = coset_index * next_len + pair;
                next.push(self.fold_pair_extension(
                    folds_done + inner_fold,
                    global_pair_index,
                    current[2 * pair],
                    current[2 * pair + 1],
                    challenge,
                )?);
            }
            current = next;
        }
        Ok(current[0])
    }

    /// Convert one opened affine-code coset to its local fold-normal table.
    ///
    /// Entry `i` of the returned table is the result of applying the exact
    /// inverse LCH butterflies with every local fold challenge fixed to the
    /// bits of `i` (lowest challenge in the least-significant bit).  Hence a
    /// plain multilinear evaluation of the returned table at arbitrary
    /// challenges is exactly [`Self::fold_contiguous_coset_extension`] on the
    /// original coset.  The transform is invertible and never mixes distinct
    /// committed leaves.
    pub fn fold_normalize_coset<F>(
        &self,
        coset: &[F],
        folds_done: usize,
        coset_index: usize,
    ) -> Result<Vec<F>, ZkAffineCodeError>
    where
        F: TowerField + From<Block128>,
    {
        if coset.is_empty() || !coset.len().is_power_of_two() {
            return Err(ZkAffineCodeError::CosetLength {
                expected: coset.len().max(1).next_power_of_two(),
                actual: coset.len(),
            });
        }
        let local_folds = coset.len().trailing_zeros() as usize;
        if folds_done + local_folds > AFFINE_CODE_LOG_LEN {
            return Err(ZkAffineCodeError::FoldCountOutOfRange);
        }
        let current_code_len = 1usize << (AFFINE_CODE_LOG_LEN - folds_done);
        if coset_index >= current_code_len / coset.len() {
            return Err(ZkAffineCodeError::CosetIndexOutOfRange);
        }

        // After round r, the low r+1 table bits are the Boolean values of
        // challenges 0..=r.  Coefficients for those bits remain adjacent,
        // while the next inverse butterfly joins neighboring coefficient
        // blocks of size 2^r.
        let mut table = coset.to_vec();
        for inner_fold in 0..local_folds {
            let coefficient_count = 1usize << inner_fold;
            let next_len = coset.len() >> (inner_fold + 1);
            let layer = AFFINE_CODE_LOG_LEN - folds_done - inner_fold - 1;
            for pair in 0..next_len {
                let global_pair_index = coset_index * next_len + pair;
                let twiddle = F::from(self.twiddle(layer, global_pair_index)?);
                let base = 2 * pair * coefficient_count;
                for coefficient in 0..coefficient_count {
                    let left_index = base + coefficient;
                    let right_index = left_index + coefficient_count;
                    let left = table[left_index];
                    let right = table[right_index];
                    let v = right + left;
                    let u = left + v * twiddle;
                    table[left_index] = u;
                    table[right_index] = v;
                }
            }
        }
        Ok(table)
    }

    /// Restore the raw coset from [`Self::fold_normalize_coset`].
    pub fn fold_denormalize_coset<F>(
        &self,
        table: &[F],
        folds_done: usize,
        coset_index: usize,
    ) -> Result<Vec<F>, ZkAffineCodeError>
    where
        F: TowerField + From<Block128>,
    {
        if table.is_empty() || !table.len().is_power_of_two() {
            return Err(ZkAffineCodeError::CosetLength {
                expected: table.len().max(1).next_power_of_two(),
                actual: table.len(),
            });
        }
        let local_folds = table.len().trailing_zeros() as usize;
        if folds_done + local_folds > AFFINE_CODE_LOG_LEN {
            return Err(ZkAffineCodeError::FoldCountOutOfRange);
        }
        let current_code_len = 1usize << (AFFINE_CODE_LOG_LEN - folds_done);
        if coset_index >= current_code_len / table.len() {
            return Err(ZkAffineCodeError::CosetIndexOutOfRange);
        }

        let mut coset = table.to_vec();
        for inner_fold in (0..local_folds).rev() {
            let coefficient_count = 1usize << inner_fold;
            let next_len = table.len() >> (inner_fold + 1);
            let layer = AFFINE_CODE_LOG_LEN - folds_done - inner_fold - 1;
            for pair in 0..next_len {
                let global_pair_index = coset_index * next_len + pair;
                let twiddle = F::from(self.twiddle(layer, global_pair_index)?);
                let base = 2 * pair * coefficient_count;
                for coefficient in 0..coefficient_count {
                    let left_index = base + coefficient;
                    let right_index = left_index + coefficient_count;
                    let u = coset[left_index];
                    let v = coset[right_index];
                    let left = u + v * twiddle;
                    coset[left_index] = left;
                    coset[right_index] = v + left;
                }
            }
        }
        Ok(coset)
    }

    fn forward_extension<F>(&self, data: &mut [F], code_log: usize)
    where
        F: TowerField + From<Block128>,
    {
        debug_assert_eq!(data.len(), 1usize << code_log);
        for layer in 0..code_log {
            let block_size = 1usize << (code_log - layer);
            let half = block_size / 2;
            for block in 0..1usize << layer {
                let twiddle = F::from(from_flat(self.twiddles_flat[layer][block]));
                let start = block * block_size;
                for offset in 0..half {
                    let left = start + offset;
                    let right = left + half;
                    let v = data[right];
                    let new_u = data[left] + v * twiddle;
                    data[left] = new_u;
                    data[right] = v + new_u;
                }
            }
        }
    }

    fn forward_flat(&self, data: &mut [u128], code_log: usize) {
        debug_assert_eq!(data.len(), 1usize << code_log);
        for layer in 0..code_log {
            let block_size = 1usize << (code_log - layer);
            let half = block_size / 2;
            for block in 0..1usize << layer {
                let twiddle = self.twiddles_flat[layer][block];
                let start = block * block_size;
                for offset in 0..half {
                    let left = start + offset;
                    let right = left + half;
                    let v = data[right];
                    let new_u = data[left] ^ flat_mul(v, twiddle);
                    data[left] = new_u;
                    data[right] = v ^ new_u;
                }
            }
        }
    }

    #[inline]
    fn domain_point_flat(&self, index: usize) -> u128 {
        let mut point = self.beta_flat;
        for (bit, &basis) in self.basis_flat.iter().enumerate() {
            if (index >> bit) & 1 == 1 {
                point ^= basis;
            }
        }
        point
    }

    fn normalized_subspace_eval_flat(&self, level: usize, point: u128) -> u128 {
        let mut value = point;
        for previous_level in 0..level {
            value = flat_mul(value, value ^ self.normalizers_flat[previous_level]);
        }
        flat_mul(value, self.normalizer_inverses_flat[level])
    }
}

#[inline]
fn to_flat(value: Block128) -> u128 {
    tower_to_flat_u128(value.0)
}

#[inline]
fn from_flat(value: u128) -> Block128 {
    Block128::from(flat_to_tower_u128(value))
}

#[inline]
fn flat_mul(left: u128, right: u128) -> u128 {
    clmul_gcm(left, right)
}

fn flat_inverse(value: u128) -> u128 {
    debug_assert_ne!(value, 0);
    to_flat(from_flat(value).invert())
}

fn binary_rank(values: &[u128]) -> usize {
    let mut basis = [0u128; 128];
    let mut rank = 0usize;
    for &input in values {
        let mut value = input;
        while value != 0 {
            let pivot = value.ilog2() as usize;
            if basis[pivot] == 0 {
                basis[pivot] = value;
                rank += 1;
                break;
            }
            value ^= basis[pivot];
        }
    }
    rank
}

fn binary_span_contains(basis: &[u128], value: u128) -> bool {
    let mut extended = basis.to_vec();
    let original_rank = binary_rank(&extended);
    extended.push(value);
    binary_rank(&extended) == original_rank
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use noid_core::mle::evaluate::evaluate_slice;
    use noid_core::mle::fold::fold_variable_inplace;
    use noid_core::Block256;

    use super::*;

    fn elem(index: usize, domain: u128) -> Block128 {
        Block128::from(
            domain
                .wrapping_mul(index as u128 + 1)
                .rotate_left((index % 127) as u32)
                ^ (index as u128 * 0x9E37_79B9_7F4A_7C15),
        )
    }

    fn message() -> Vec<Block128> {
        (0..AFFINE_CODE_MESSAGE_LEN)
            .map(|index| elem(index, 0xAFF1CE))
            .collect()
    }

    fn fold_message_low(mut message: Vec<Block128>, challenges: &[Block128]) -> Vec<Block128> {
        for &challenge in challenges {
            fold_variable_inplace(&mut message, challenge, 0);
        }
        message
    }

    #[test]
    fn fold_normal_cosets_are_invertible_and_match_wide_affine_folds() {
        let code = ZkAffineLchCode::selected().unwrap();
        for (case, folds_done, local_folds, coset_index) in [
            (0usize, 0usize, 3usize, 0usize),
            (1, 0, 3, (1usize << 13) - 1),
            (2, 3, 4, 0),
            (3, 3, 4, (1usize << 9) - 1),
        ] {
            let raw = (0..1usize << local_folds)
                .map(|index| {
                    Block256::new(
                        elem(case * 100 + index + 1, 0xF01D_0001),
                        elem(case * 100 + index + 41, 0xF01D_0002),
                    )
                })
                .collect::<Vec<_>>();
            let challenges = (0..local_folds)
                .map(|index| {
                    Block256::new(
                        elem(case * 100 + index + 81, 0xF01D_0003),
                        elem(case * 100 + index + 121, 0xF01D_0004),
                    )
                })
                .collect::<Vec<_>>();

            let normalized = code
                .fold_normalize_coset(&raw, folds_done, coset_index)
                .unwrap();
            let restored = code
                .fold_denormalize_coset(&normalized, folds_done, coset_index)
                .unwrap();
            assert_eq!(restored, raw, "fold-normal inverse, case {case}");

            let expected = code
                .fold_contiguous_coset_extension(&raw, folds_done, coset_index, &challenges)
                .unwrap();
            let actual = evaluate_slice(&normalized, &challenges);
            assert_eq!(actual, expected, "fold-normal evaluation, case {case}");
        }
    }

    fn direct_novel_eval(
        code: &ZkAffineLchCode,
        message: &[Block128],
        domain_index: usize,
    ) -> Block128 {
        direct_projected_novel_eval(code, message, 0, domain_index)
    }

    /// Independently evaluate the projected novel basis for layer `j` via
    /// the composition identity L_{j,r}(pi_j(X)) = pi_{j+r}(X).
    fn direct_projected_novel_eval(
        code: &ZkAffineLchCode,
        message: &[Block128],
        folds_done: usize,
        domain_index: usize,
    ) -> Block128 {
        let expected_message_len = AFFINE_CODE_MESSAGE_LEN >> folds_done;
        let domain_len = AFFINE_CODE_LEN >> folds_done;
        assert_eq!(message.len(), expected_message_len);
        assert!(domain_index < domain_len);

        let representative = code.domain_point_flat(domain_index << folds_done);
        let message_log = AFFINE_CODE_MESSAGE_LOG - folds_done;
        let normalized = (0..message_log)
            .map(|offset| code.normalized_subspace_eval_flat(folds_done + offset, representative))
            .collect::<Vec<_>>();

        let mut novel_values = vec![0u128; expected_message_len];
        novel_values[0] = 1;
        for coefficient_index in 1..expected_message_len {
            let bit = coefficient_index.trailing_zeros() as usize;
            novel_values[coefficient_index] = flat_mul(
                novel_values[coefficient_index ^ (1usize << bit)],
                normalized[bit],
            );
        }

        let mut value = 0u128;
        for (raw_index, &coefficient) in message.iter().enumerate() {
            value ^= flat_mul(to_flat(coefficient), novel_values[raw_index]);
        }
        from_flat(value)
    }

    fn novel_basis_eval_flat(code: &ZkAffineLchCode, basis_index: usize, point: u128) -> u128 {
        let mut value = 1u128;
        for level in 0..AFFINE_CODE_MESSAGE_LOG {
            if (basis_index >> level) & 1 == 1 {
                value = flat_mul(value, code.normalized_subspace_eval_flat(level, point));
            }
        }
        value
    }

    #[test]
    fn selected_affine_domain_is_injective_and_disjoint_from_h9() {
        let code = ZkAffineLchCode::selected().unwrap();
        let points: HashSet<u128> = (0..AFFINE_CODE_LEN)
            .map(|index| to_flat(code.domain_point(index).unwrap()))
            .collect();
        assert_eq!(points.len(), AFFINE_CODE_LEN);

        let h9: HashSet<u128> = (0..AFFINE_FUNDAMENTAL_LEN)
            .map(|index| {
                let mut point = 0u128;
                for (bit, &basis) in code.basis_flat[..AFFINE_FUNDAMENTAL_LOG].iter().enumerate() {
                    if (index >> bit) & 1 == 1 {
                        point ^= basis;
                    }
                }
                point
            })
            .collect();
        assert!(points.is_disjoint(&h9));
        assert_eq!(
            code.domain_point(AFFINE_CODE_LEN),
            Err(ZkAffineCodeError::DomainIndexOutOfRange)
        );
    }

    #[test]
    fn selected_rs_manifest_checks_all_eight_projected_domains() {
        let code = ZkAffineLchCode::selected().unwrap();
        let manifest = code.certify_selected_rs_manifest().unwrap();
        let expected_n = [65_536, 32_768, 16_384, 8_192, 4_096, 2_048, 1_024, 512];
        let expected_k = [2_048, 1_024, 512, 256, 128, 64, 32, 16];
        let expected_degree = [2_047, 1_023, 511, 255, 127, 63, 31, 15];
        let expected_distance = [63_489, 31_745, 15_873, 7_937, 3_969, 1_985, 993, 497];

        for (folds_done, certificate) in manifest.layers.iter().enumerate() {
            assert_eq!(certificate.folds_done, folds_done);
            assert_eq!(certificate.domain_len, expected_n[folds_done]);
            assert_eq!(certificate.message_len, expected_k[folds_done]);
            assert_eq!(certificate.paper_degree, expected_degree[folds_done]);
            assert_eq!(
                certificate.algebraic_rs_min_distance,
                expected_distance[folds_done]
            );
            assert_eq!(
                certificate.rho_numerator,
                expected_degree[folds_done] as u128
            );
            assert_eq!(certificate.rho_denominator, expected_n[folds_done] as u128);
            assert_eq!(
                certificate.paper_degree + certificate.algebraic_rs_min_distance,
                certificate.domain_len
            );
            assert_eq!(certificate.inverse_rate, 32);
            assert_eq!(
                certificate.projected_basis.len(),
                AFFINE_CODE_LOG_LEN - folds_done
            );
            assert_eq!(
                certificate.projected_basis_rank,
                AFFINE_CODE_LOG_LEN - folds_done
            );
            assert_eq!(certificate.projected_basis[0], Block128::ONE);
            assert!(certificate.projected_beta_outside_basis_span);
            assert_eq!(certificate.checked_coordinate_count, certificate.domain_len);
            assert_eq!(
                certificate.distinct_projected_point_count,
                certificate.domain_len
            );
            assert_eq!(
                certificate.projected_domain_point(certificate.domain_len),
                Err(ZkAffineCodeError::DomainIndexOutOfRange)
            );
        }
        assert_eq!(
            code.certify_selected_rs_layer(AFFINE_SELECTED_RS_LAYER_COUNT),
            Err(ZkAffineCodeError::LayerOutOfRange)
        );
    }

    #[test]
    fn selected_rs_twiddles_and_two_point_quotient_fibers_are_exact() {
        let code = ZkAffineLchCode::selected().unwrap();
        let manifest = code.certify_selected_rs_manifest().unwrap();

        // Every twiddle used by every selected projected FFT is the
        // corresponding normalized quotient-domain coordinate.  Repetition
        // across projected layers is intentional: local level r composes to
        // original level j+r.
        for folds_done in 0..AFFINE_SELECTED_RS_LAYER_COUNT {
            let code_log = AFFINE_CODE_LOG_LEN - folds_done;
            for fft_layer in 0..code_log {
                let quotient_level = AFFINE_CODE_LOG_LEN - fft_layer - 1;
                for block in 0..1usize << fft_layer {
                    let representative_index = block << (quotient_level + 1);
                    let expected = from_flat(code.normalized_subspace_eval_flat(
                        quotient_level,
                        code.domain_point_flat(representative_index),
                    ));
                    assert_eq!(
                        code.twiddle(fft_layer, block).unwrap(),
                        expected,
                        "twiddle drift at projected layer {folds_done}, FFT layer {fft_layer}, block {block}"
                    );
                }
            }
        }

        // D_j is paired by y -> y+1 and both points project to the same
        // coordinate of D_{j+1}.  The even representative is exactly the
        // inverse-butterfly twiddle for that pair.
        for folds_done in 0..AFFINE_SELECTED_RS_LAYER_COUNT - 1 {
            let parent = &manifest.layers[folds_done];
            let child = &manifest.layers[folds_done + 1];
            for pair_index in 0..child.domain_len {
                let even = parent.projected_domain_point(2 * pair_index).unwrap();
                let odd = parent.projected_domain_point(2 * pair_index + 1).unwrap();
                assert_eq!(odd, even + Block128::ONE);
                assert_eq!(
                    code.twiddle(AFFINE_CODE_LOG_LEN - folds_done - 1, pair_index)
                        .unwrap(),
                    even
                );

                let even_representative = code.domain_point_flat((2 * pair_index) << folds_done);
                let odd_representative = code.domain_point_flat((2 * pair_index + 1) << folds_done);
                let projected_even = from_flat(
                    code.normalized_subspace_eval_flat(folds_done + 1, even_representative),
                );
                let projected_odd = from_flat(
                    code.normalized_subspace_eval_flat(folds_done + 1, odd_representative),
                );
                let child_point = child.projected_domain_point(pair_index).unwrap();
                assert_eq!(projected_even, child_point);
                assert_eq!(projected_odd, child_point);
            }
        }
    }

    #[test]
    fn independent_pcs_coin_block_certifies_rank_1024() {
        let code = ZkAffineLchCode::selected().unwrap();
        assert_eq!(AFFINE_LIBRA_MASK_START, 512);
        assert_eq!(AFFINE_LIBRA_MASK_LEN, 432);
        assert_eq!(AFFINE_FRESH_PADDING_START, 944);
        assert_eq!(AFFINE_FRESH_PADDING_LEN, 80);
        assert_eq!(AFFINE_PCS_COINS_START, 1_024);
        assert_eq!(AFFINE_PCS_COINS_LEN, 1_024);
        assert_eq!(AFFINE_RANK_RANDOM_BLOCK_START, 1_024);
        assert_eq!(AFFINE_RANK_RANDOM_BLOCK_LEN, 1_024);

        // The unit coefficient X_1024 is exactly the nonvanishing W_10
        // factor shared by the certified 1024-coefficient random block.
        let mut unit = vec![Block128::ZERO; AFFINE_CODE_MESSAGE_LEN];
        unit[AFFINE_RANK_RANDOM_BLOCK_START] = Block128::ONE;
        let encoded_unit = code.encode(&unit).unwrap();
        for position in 0..AFFINE_CODE_LEN {
            let point = code.domain_point_flat(position);
            let factor = code.normalized_subspace_eval_flat(10, point);
            assert_ne!(factor, 0, "W_10 vanished at domain position {position}");
            assert_eq!(to_flat(encoded_unit[position]), factor);
        }

        // X_{1024+j} = W_10 * X_j pins the structural Vandermonde
        // factorization independently of the encoder implementation.
        for position in [0, 1, 255, 4_097, AFFINE_CODE_LEN - 1] {
            let point = code.domain_point_flat(position);
            let factor = novel_basis_eval_flat(&code, AFFINE_RANK_RANDOM_BLOCK_START, point);
            for j in 0..AFFINE_RANK_RANDOM_BLOCK_LEN {
                assert_eq!(
                    novel_basis_eval_flat(&code, AFFINE_RANK_RANDOM_BLOCK_START + j, point),
                    flat_mul(factor, novel_basis_eval_flat(&code, j, point))
                );
            }
        }

        let mut queries: Vec<usize> = (0..AFFINE_RANK_MAX_QUERIES)
            .map(|index| (index * 127 + 19) & (AFFINE_CODE_LEN - 1))
            .collect();
        queries.extend_from_slice(&queries[..16].to_vec());
        let certificate = code.certify_high_padding_rank(&queries).unwrap();
        assert_eq!(certificate.distinct_query_count, 1_024);
        assert_eq!(certificate.certified_rank, 1_024);
        assert_eq!(certificate.independent_coeff_start, 1_024);
        assert_eq!(certificate.independent_coeff_len, 1_024);
        assert_eq!(certificate.nonzero_factor_level, 10);

        let too_many: Vec<usize> = (0..=AFFINE_RANK_MAX_QUERIES).collect();
        assert_eq!(
            code.certify_high_padding_rank(&too_many),
            Err(ZkAffineCodeError::TooManyDistinctQueries {
                max: 1_024,
                actual: 1_025,
            })
        );
    }

    #[test]
    fn affine_ntt_matches_independent_novel_basis_evaluation() {
        let code = ZkAffineLchCode::selected().unwrap();
        let message = message();
        let encoded = code.encode(&message).unwrap();
        for index in [0, 1, 2, 7, 255, 256, 4_097, 32_768, AFFINE_CODE_LEN - 1] {
            assert_eq!(
                encoded[index],
                direct_novel_eval(&code, &message, index),
                "domain index {index}"
            );
        }
    }

    #[test]
    fn selected_projected_encoders_match_sampled_direct_degree_basis_evaluations() {
        let code = ZkAffineLchCode::selected().unwrap();

        for folds_done in 0..AFFINE_SELECTED_RS_LAYER_COUNT {
            let message_len = AFFINE_CODE_MESSAGE_LEN >> folds_done;
            let domain_len = AFFINE_CODE_LEN >> folds_done;
            let layer_message = (0..message_len)
                .map(|index| elem(index, 0xD1EC_7000 ^ folds_done as u128))
                .collect::<Vec<_>>();
            let encoded = code
                .encode_after_low_folds(&layer_message, folds_done)
                .unwrap();

            let mut sampled = vec![
                0,
                1,
                2,
                7,
                domain_len / 3,
                domain_len / 2,
                domain_len - 2,
                domain_len - 1,
            ];
            sampled.sort_unstable();
            sampled.dedup();
            for domain_index in sampled {
                assert_eq!(
                    encoded[domain_index],
                    direct_projected_novel_eval(&code, &layer_message, folds_done, domain_index,),
                    "direct projected evaluation drift at layer {folds_done}, coordinate {domain_index}"
                );
            }
        }
    }

    #[test]
    fn three_then_four_contiguous_folds_match_low_folded_encodings() {
        let code = ZkAffineLchCode::selected().unwrap();
        let message = message();
        let source_challenges: [Block128; 3] = std::array::from_fn(|index| elem(index, 0x503CE));
        let mid_challenges: [Block128; 4] = std::array::from_fn(|index| elem(index, 0xA11D));

        let source_code = code.encode(&message).unwrap();
        let mut folded_source_code = source_code.clone();
        for (folds_done, &challenge) in source_challenges.iter().enumerate() {
            folded_source_code = code
                .fold_codeword_once(&folded_source_code, folds_done, challenge)
                .unwrap();
        }
        let source_folded_message = fold_message_low(message.clone(), &source_challenges);
        let expected_mid_code = code
            .encode_after_low_folds(&source_folded_message, source_challenges.len())
            .unwrap();
        assert_eq!(folded_source_code, expected_mid_code);
        assert_eq!(folded_source_code.len(), 1 << 13);

        for source_leaf in 0..folded_source_code.len() {
            let coset = &source_code[source_leaf * 8..source_leaf * 8 + 8];
            assert_eq!(
                code.fold_contiguous_coset(coset, 0, source_leaf, &source_challenges)
                    .unwrap(),
                folded_source_code[source_leaf]
            );
        }

        let mut folded_mid_code = folded_source_code.clone();
        for (inner, &challenge) in mid_challenges.iter().enumerate() {
            folded_mid_code = code
                .fold_codeword_once(&folded_mid_code, source_challenges.len() + inner, challenge)
                .unwrap();
        }
        let tail_message = fold_message_low(source_folded_message, &mid_challenges);
        assert_eq!(tail_message.len(), 16);
        let expected_tail_code = code
            .encode_after_low_folds(
                &tail_message,
                source_challenges.len() + mid_challenges.len(),
            )
            .unwrap();
        assert_eq!(folded_mid_code, expected_tail_code);
        assert_eq!(folded_mid_code.len(), 1 << 9);

        for mid_leaf in 0..folded_mid_code.len() {
            let coset = &folded_source_code[mid_leaf * 16..mid_leaf * 16 + 16];
            assert_eq!(
                code.fold_contiguous_coset(
                    coset,
                    source_challenges.len(),
                    mid_leaf,
                    &mid_challenges,
                )
                .unwrap(),
                folded_mid_code[mid_leaf]
            );
        }
    }

    #[test]
    fn selected_seven_layers_split_and_restore_arbitrary_received_words() {
        let code = ZkAffineLchCode::selected().unwrap();

        for folds_done in 0..7 {
            let parent_len = AFFINE_CODE_LEN >> folds_done;
            let parent = (0..parent_len)
                .map(|index| elem(index, 0xA2B1_7000 ^ folds_done as u128))
                .collect::<Vec<_>>();
            let (at_zero, at_one) = code
                .split_affine_fold_children(&parent, folds_done)
                .unwrap();
            assert_eq!(at_zero.len(), parent_len / 2);
            assert_eq!(at_one.len(), parent_len / 2);
            assert_eq!(
                code.restore_affine_fold_parent(&at_zero, &at_one, folds_done)
                    .unwrap(),
                parent,
                "inverse-butterfly restoration drift at selected layer {folds_done}"
            );

            let challenge = elem(folds_done + 19, 0xB37A_0000 ^ folds_done as u128);
            let folded = code
                .fold_codeword_once(&parent, folds_done, challenge)
                .unwrap();
            let from_children = at_zero
                .iter()
                .zip(&at_one)
                .map(|(&zero, &one)| zero + challenge * (zero + one))
                .collect::<Vec<_>>();
            assert_eq!(
                folded, from_children,
                "child line evaluation drift at selected layer {folds_done}"
            );
        }
    }

    #[test]
    fn selected_grouped_cosets_match_sequential_folds_for_arbitrary_received_words() {
        let code = ZkAffineLchCode::selected().unwrap();

        for (folds_done, group_width, domain) in
            [(0usize, 3usize, 0x503C_EA11u128), (3, 4, 0xA11D_EA11)]
        {
            let parent_len = AFFINE_CODE_LEN >> folds_done;
            let parent = (0..parent_len)
                .map(|index| elem(index, domain))
                .collect::<Vec<_>>();
            let challenges = (0..group_width)
                .map(|inner| elem(folds_done + inner + 41, domain ^ 0xC011_A11E))
                .collect::<Vec<_>>();

            let mut sequential = parent.clone();
            for (inner, &challenge) in challenges.iter().enumerate() {
                sequential = code
                    .fold_codeword_once(&sequential, folds_done + inner, challenge)
                    .unwrap();
            }

            let coset_len = 1usize << group_width;
            assert_eq!(sequential.len(), parent.len() / coset_len);
            for (coset_index, &expected) in sequential.iter().enumerate() {
                let start = coset_index << group_width;
                let actual = code
                    .fold_contiguous_coset(
                        &parent[start..start + coset_len],
                        folds_done,
                        coset_index,
                        &challenges,
                    )
                    .unwrap();
                assert_eq!(
                    actual, expected,
                    "grouped arbitrary-word fold drift at layer {folds_done}, coset {coset_index}"
                );
            }
        }
    }

    #[test]
    fn selected_honest_parent_splits_to_direct_even_and_odd_child_encodings() {
        let code = ZkAffineLchCode::selected().unwrap();

        for folds_done in 0..AFFINE_SELECTED_RS_LAYER_COUNT - 1 {
            let parent_message_len = AFFINE_CODE_MESSAGE_LEN >> folds_done;
            let parent_message = (0..parent_message_len)
                .map(|index| elem(index, 0x5A11_7000 ^ folds_done as u128))
                .collect::<Vec<_>>();
            let parent = code
                .encode_after_low_folds(&parent_message, folds_done)
                .unwrap();
            let (actual_even, actual_odd) = code
                .split_affine_fold_children(&parent, folds_done)
                .unwrap();

            let even_message = parent_message
                .iter()
                .step_by(2)
                .copied()
                .collect::<Vec<_>>();
            let odd_message = parent_message
                .iter()
                .skip(1)
                .step_by(2)
                .copied()
                .collect::<Vec<_>>();
            let expected_even = code
                .encode_after_low_folds(&even_message, folds_done + 1)
                .unwrap();
            let expected_odd = code
                .encode_after_low_folds(&odd_message, folds_done + 1)
                .unwrap();
            assert_eq!(
                actual_even, expected_even,
                "even child-code drift at selected layer {folds_done}"
            );
            assert_eq!(
                actual_odd, expected_odd,
                "odd child-code drift at selected layer {folds_done}"
            );
        }
    }

    #[test]
    fn selected_seven_layers_restore_honest_children_to_direct_parent_encoding() {
        let code = ZkAffineLchCode::selected().unwrap();

        for folds_done in 0..7 {
            let child_message_len = AFFINE_CODE_MESSAGE_LEN >> (folds_done + 1);
            let at_zero_message = (0..child_message_len)
                .map(|index| elem(index, 0xC0DE_0000 ^ folds_done as u128))
                .collect::<Vec<_>>();
            let at_one_message = (0..child_message_len)
                .map(|index| elem(index, 0xC1DE_0000 ^ folds_done as u128))
                .collect::<Vec<_>>();
            let at_zero = code
                .encode_after_low_folds(&at_zero_message, folds_done + 1)
                .unwrap();
            let at_one = code
                .encode_after_low_folds(&at_one_message, folds_done + 1)
                .unwrap();

            let restored = code
                .restore_affine_fold_parent(&at_zero, &at_one, folds_done)
                .unwrap();
            let parent_message = at_zero_message
                .iter()
                .zip(&at_one_message)
                .flat_map(|(&zero, &one)| [zero, one])
                .collect::<Vec<_>>();
            let direct = code
                .encode_after_low_folds(&parent_message, folds_done)
                .unwrap();
            assert_eq!(
                restored, direct,
                "honest child restoration drift at selected layer {folds_done}"
            );
        }
    }

    #[test]
    fn affine_fold_split_and_restore_reject_wrong_shapes() {
        let code = ZkAffineLchCode::selected().unwrap();
        assert_eq!(
            code.split_affine_fold_children(&[Block128::ZERO; 2], 0),
            Err(ZkAffineCodeError::CodewordLength {
                expected: AFFINE_CODE_LEN,
                actual: 2,
            })
        );
        assert_eq!(
            code.split_affine_fold_children(&[], AFFINE_CODE_LOG_LEN),
            Err(ZkAffineCodeError::FoldCountOutOfRange)
        );
        assert_eq!(
            code.restore_affine_fold_parent(&[Block128::ZERO], &[], 6),
            Err(ZkAffineCodeError::CodewordLength {
                expected: AFFINE_CODE_LEN >> 7,
                actual: 1,
            })
        );
        assert_eq!(
            code.restore_affine_fold_parent(&[], &[], AFFINE_CODE_LOG_LEN),
            Err(ZkAffineCodeError::FoldCountOutOfRange)
        );
    }

    #[test]
    fn inverse_butterfly_and_coset_mapping_reject_tamper() {
        let code = ZkAffineLchCode::selected().unwrap();
        let message = message();
        let encoded = code.encode(&message).unwrap();
        let challenge = elem(3, 0xF01D);
        let pair_index = 127usize;
        let left = encoded[2 * pair_index];
        let right = encoded[2 * pair_index + 1];
        let (u, v) = code
            .inverse_butterfly(AFFINE_CODE_LOG_LEN - 1, pair_index, left, right)
            .unwrap();
        let twiddle = code.twiddle(AFFINE_CODE_LOG_LEN - 1, pair_index).unwrap();
        assert_eq!(left, u + v * twiddle);
        assert_eq!(right, v + left);

        let honest = code
            .fold_pair(0, pair_index, left, right, challenge)
            .unwrap();
        assert_ne!(
            code.fold_pair(0, pair_index, left + Block128::ONE, right, challenge)
                .unwrap(),
            honest
        );
        assert_ne!(
            code.fold_pair(0, pair_index + 1, left, right, challenge)
                .unwrap(),
            honest
        );
        assert_eq!(
            code.fold_contiguous_coset(&encoded[..7], 0, 0, &[challenge; 3]),
            Err(ZkAffineCodeError::CosetLength {
                expected: 8,
                actual: 7,
            })
        );
    }

    #[test]
    fn rejected_bitreverse_layout_exposes_two_state_only_modes_per_leaf8() {
        let code = ZkAffineLchCode::selected().unwrap();
        let reverse_11 =
            |value: usize| value.reverse_bits() >> (usize::BITS as usize - AFFINE_CODE_MESSAGE_LOG);

        // Rejected layout: bit-reversing logical state[0..512) fills every
        // internal coefficient whose low two bits are 00. All other three
        // H2 modes are changed independently between the two witnesses.
        let mut left_message = vec![Block128::ZERO; AFFINE_CODE_MESSAGE_LEN];
        let mut right_message = vec![Block128::ZERO; AFFINE_CODE_MESSAGE_LEN];
        for logical_state in 0..AFFINE_STATE_LEN {
            let internal = reverse_11(logical_state);
            assert_eq!(internal & 3, 0);
            let value = elem(logical_state, 0x57A7E);
            left_message[internal] = value;
            right_message[internal] = value;
        }
        for internal in 0..AFFINE_CODE_MESSAGE_LEN {
            if internal & 3 != 0 {
                left_message[internal] = elem(internal, 0x1E57);
                right_message[internal] = elem(internal, 0xBAD5EED);
            }
        }

        let left_code = code.encode(&left_message).unwrap();
        let right_code = code.encode(&right_message).unwrap();

        let recover_h2_constant = |codeword: &[Block128], fiber: usize| {
            let base = fiber * 4;
            let (a0, a1) = code
                .inverse_butterfly(15, 2 * fiber, codeword[base], codeword[base + 1])
                .unwrap();
            let (b0, b1) = code
                .inverse_butterfly(15, 2 * fiber + 1, codeword[base + 2], codeword[base + 3])
                .unwrap();
            let (constant_mode, _) = code.inverse_butterfly(14, fiber, a0, b0).unwrap();
            let _ = code.inverse_butterfly(14, fiber, a1, b1).unwrap();
            constant_mode
        };

        for leaf8 in [0, 1, 127, 4_097, (AFFINE_CODE_LEN / 8) - 1] {
            let base = leaf8 * 8;
            assert_ne!(
                &left_code[base..base + 8],
                &right_code[base..base + 8],
                "nonstate modes must actually differ"
            );
            for fiber in [2 * leaf8, 2 * leaf8 + 1] {
                assert_eq!(
                    recover_h2_constant(&left_code, fiber),
                    recover_h2_constant(&right_code, fiber),
                    "bit-reversed leaf {leaf8} leaks one state-only mode per H2 fiber"
                );
            }
        }
    }
}
