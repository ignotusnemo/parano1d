// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Characteristic-two Libra plumbing for the future ZK MLE-check.
//!
//! The formulas mirror the audited Binius `mlecheck.rs` and
//! `sumcheck/zk_mlecheck.rs`: a separable mask
//! `g(X) = sum_i g_i(X_i)` is batched with the main round polynomial, not
//! with the equality polynomial. This distinction is required for hiding in
//! characteristic two.
//!
//! This module owns no randomness and is disconnected from `owner_auth`, its
//! proof types, wire format, and transcripts. Every one of the 432 mask-buffer
//! cells is supplied by the caller and retained verbatim; padded cells are not
//! synthesized or silently zeroed.

use crate::authorization_profile::{AuthorizationLayout, OwnerAuthorizationVersion};
use noid_core::sumcheck::RoundPolynomial;
use noid_core::{Block128, TowerField};

pub const ZK_MLECHECK_N_VARS: usize = 11;
pub const ZK_MLECHECK_MASK_DEGREE: usize = 10;
pub const ZK_MLECHECK_MASK_COEFFS: usize = ZK_MLECHECK_MASK_DEGREE + 1;
pub const ZK_MLECHECK_MASK_ROW_STRIDE: usize = ZK_MLECHECK_MASK_COEFFS.next_power_of_two();
pub const ZK_MLECHECK_MASK_ROWS: usize = ZK_MLECHECK_N_VARS.next_power_of_two();
pub const ZK_MLECHECK_WIDE_LIMB_LEN: usize = ZK_MLECHECK_MASK_ROWS * ZK_MLECHECK_MASK_ROW_STRIDE;
pub const ZK_MLECHECK_MASK_LEN: usize =
    ZK_MLECHECK_WIDE_LIMB_LEN + ZK_MLECHECK_N_VARS * ZK_MLECHECK_MASK_ROW_STRIDE;
pub const ZK_MLECHECK_ROUND_PROOF_COEFFS: usize = ZK_MLECHECK_MASK_DEGREE;
pub const ZK_MLECHECK_ACTIVE_MASK_COEFFS: usize = ZK_MLECHECK_N_VARS * ZK_MLECHECK_MASK_COEFFS;
pub const ZK_MLECHECK_MASKED_ROUND_FIELDS: usize =
    ZK_MLECHECK_N_VARS * ZK_MLECHECK_ROUND_PROOF_COEFFS;
pub const ZK_MLECHECK_PUBLIC_MASK_FIELDS: usize = ZK_MLECHECK_MASKED_ROUND_FIELDS + 2;
pub const ZK_MLECHECK_MASK_OBSERVATION_RANK: usize =
    ZK_MLECHECK_N_VARS * ZK_MLECHECK_MASK_DEGREE + 1;

const _: () = assert!(ZK_MLECHECK_MASK_ROW_STRIDE == 16);
const _: () = assert!(ZK_MLECHECK_MASK_ROWS == 16);
const _: () = assert!(ZK_MLECHECK_MASK_LEN == 432);
const _: () =
    assert!(ZK_MLECHECK_N_VARS * ZK_MLECHECK_MASK_ROW_STRIDE <= ZK_MLECHECK_WIDE_LIMB_LEN);
const _: () = assert!(ZK_MLECHECK_ACTIVE_MASK_COEFFS == 121);
const _: () = assert!(ZK_MLECHECK_MASKED_ROUND_FIELDS == 110);
const _: () = assert!(ZK_MLECHECK_PUBLIC_MASK_FIELDS == 112);
const _: () = assert!(ZK_MLECHECK_MASK_OBSERVATION_RANK == 111);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkMleCheckError {
    MaskBufferLength { expected: usize, actual: usize },
    VariableOutOfRange,
    TooManyPriorChallenges,
    MainRoundEmpty,
    MainRoundDegreeTooHigh { max: usize, actual: usize },
    CombinedRoundCoefficientCount { expected: usize, actual: usize },
    RoundExhausted,
    RoundsIncomplete { completed: usize },
    MainFinalMismatch,
    ZeroMaskBatchChallenge,
}

/// Structural rank of the characteristic-two Libra masking transcript.
///
/// The 110 nonconstant round coefficients have a diagonal nonzero-mask block.
/// The sum of the eleven constant coefficients independently masks `g_MLE`.
/// `g(r)` adds the single intended telescope relation rather than another
/// independent observation, so 112 public mask-dependent fields have exact
/// rank 111 over the 121 active coefficients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkMleCheckMaskRankCertificate {
    pub active_mask_coefficients: usize,
    pub public_mask_dependent_fields: usize,
    pub certified_rank: usize,
    pub intended_terminal_relations: usize,
    pub remaining_active_degrees_of_freedom: usize,
}

pub fn certify_zk_mlecheck_mask_rank<F: TowerField>(
    mask_batch_challenge: F,
) -> Result<ZkMleCheckMaskRankCertificate, ZkMleCheckError> {
    if mask_batch_challenge == F::ZERO {
        return Err(ZkMleCheckError::ZeroMaskBatchChallenge);
    }
    Ok(ZkMleCheckMaskRankCertificate {
        active_mask_coefficients: ZK_MLECHECK_ACTIVE_MASK_COEFFS,
        public_mask_dependent_fields: ZK_MLECHECK_PUBLIC_MASK_FIELDS,
        certified_rank: ZK_MLECHECK_MASK_OBSERVATION_RANK,
        intended_terminal_relations: ZK_MLECHECK_PUBLIC_MASK_FIELDS
            - ZK_MLECHECK_MASK_OBSERVATION_RANK,
        remaining_active_degrees_of_freedom: ZK_MLECHECK_ACTIVE_MASK_COEFFS
            - ZK_MLECHECK_MASK_OBSERVATION_RANK,
    })
}

/// Bank coordinates of one authorization-mask coefficient.
pub fn zk_mlecheck_mask_coefficient_weights<F: TowerField>(
    variable: usize,
    power: usize,
) -> [(usize, F); 2] {
    zk_mlecheck_mask_coefficient_weights_for_version(variable, power, OwnerAuthorizationVersion::V4)
}

pub fn zk_mlecheck_mask_coefficient_weights_for_version<F: TowerField>(
    variable: usize,
    power: usize,
    version: OwnerAuthorizationVersion,
) -> [(usize, F); 2] {
    debug_assert!(variable < ZK_MLECHECK_N_VARS);
    debug_assert!(power <= ZK_MLECHECK_MASK_DEGREE);
    if F::BITS == 128 || version == OwnerAuthorizationVersion::V3 {
        let index = variable * ZK_MLECHECK_MASK_ROW_STRIDE + power;
        return [(index, F::ONE), (index, F::ZERO)];
    }
    assert_eq!(F::BITS, 256);
    let index = variable * ZK_MLECHECK_MASK_ROW_STRIDE + power;
    let mut basis = [0u8; 32];
    basis[16] = 1;
    [
        (index, F::ONE),
        (
            ZK_MLECHECK_WIDE_LIMB_LEN + index,
            F::from_uniform_bytes(&basis),
        ),
    ]
}

/// Borrowed, length-checked view of the complete 432-cell mask buffer.
#[derive(Clone, Copy)]
pub struct ZkMleCheckMaskView<'a> {
    cells: &'a [Block128],
    version: OwnerAuthorizationVersion,
}

impl<'a> ZkMleCheckMaskView<'a> {
    pub fn checked(cells: &'a [Block128]) -> Result<Self, ZkMleCheckError> {
        Self::checked_for_version(cells, OwnerAuthorizationVersion::V4)
    }

    pub fn checked_for_version(
        cells: &'a [Block128],
        version: OwnerAuthorizationVersion,
    ) -> Result<Self, ZkMleCheckError> {
        let expected = AuthorizationLayout::for_version(version).libra_len;
        if cells.len() != expected {
            return Err(ZkMleCheckError::MaskBufferLength {
                expected,
                actual: cells.len(),
            });
        }
        Ok(Self { cells, version })
    }

    /// All active and padded cells exactly as supplied by the caller.
    pub fn cells(&self) -> &'a [Block128] {
        self.cells
    }

    /// Low-coordinate coefficient for base-field reference calculations.
    pub fn coefficient(&self, var_index: usize, power: usize) -> Option<Block128> {
        if var_index >= ZK_MLECHECK_N_VARS || power > ZK_MLECHECK_MASK_DEGREE {
            return None;
        }
        Some(self.cells[var_index * ZK_MLECHECK_MASK_ROW_STRIDE + power])
    }

    /// Low-coordinate coefficients for base-field reference calculations.
    pub fn coefficients_for_var(
        &self,
        var_index: usize,
    ) -> Option<[Block128; ZK_MLECHECK_MASK_COEFFS]> {
        if var_index >= ZK_MLECHECK_N_VARS {
            return None;
        }
        let base = var_index * ZK_MLECHECK_MASK_ROW_STRIDE;
        Some(std::array::from_fn(|power| self.cells[base + power]))
    }

    /// Assemble coefficients in the selected authorization field.
    pub fn coefficients_for_field<F>(
        &self,
        var_index: usize,
    ) -> Option<[F; ZK_MLECHECK_MASK_COEFFS]>
    where
        F: TowerField + From<Block128>,
    {
        if var_index >= ZK_MLECHECK_N_VARS {
            return None;
        }
        Some(std::array::from_fn(|power| {
            zk_mlecheck_mask_coefficient_weights_for_version::<F>(var_index, power, self.version)
                .into_iter()
                .fold(F::ZERO, |value, (index, coefficient)| {
                    value + F::from(self.cells[index]) * coefficient
                })
        }))
    }

    /// Evaluate one `g_i(x)` in monomial basis using Horner's rule.
    pub fn evaluate_univariate<F>(&self, var_index: usize, x: F) -> Result<F, ZkMleCheckError>
    where
        F: TowerField + From<Block128>,
    {
        let coeffs = self
            .coefficients_for_field::<F>(var_index)
            .ok_or(ZkMleCheckError::VariableOutOfRange)?;
        Ok(evaluate_coefficients(&coeffs, x))
    }

    /// Evaluate the multilinear extension of `g` at the input claim point.
    ///
    /// Although each `g_i` has degree ten, its Boolean-table MLE contribution
    /// is the endpoint line `(1-z_i)g_i(0) + z_i g_i(1)`.
    pub fn evaluate_mle<F>(&self, input_point: &[F; ZK_MLECHECK_N_VARS]) -> F
    where
        F: TowerField + From<Block128>,
    {
        let mut value = F::ZERO;
        for (var_index, &z_i) in input_point.iter().enumerate() {
            value += self.endpoint_line(var_index, z_i);
        }
        value
    }

    /// Evaluate the separable degree-ten mask at the final arbitrary point:
    /// `g(r) = sum_i g_i(r_i)`.
    pub fn evaluate_final<F>(&self, terminal_point: &[F; ZK_MLECHECK_N_VARS]) -> F
    where
        F: TowerField + From<Block128>,
    {
        terminal_point
            .iter()
            .enumerate()
            .fold(F::ZERO, |acc, (var_index, &r_i)| {
                acc + self.evaluate_univariate_unchecked(var_index, r_i)
            })
    }

    /// Build the current separable mask round in high-to-low variable order.
    /// `prior_challenges[0]` belongs to variable ten, then variable nine, etc.
    pub fn round_coefficients<F>(
        &self,
        input_point: &[F; ZK_MLECHECK_N_VARS],
        prior_challenges: &[F],
    ) -> Result<LibraMaskRoundCoefficients<F>, ZkMleCheckError>
    where
        F: TowerField + From<Block128>,
    {
        if prior_challenges.len() >= ZK_MLECHECK_N_VARS {
            return Err(ZkMleCheckError::TooManyPriorChallenges);
        }

        let var_index = ZK_MLECHECK_N_VARS - 1 - prior_challenges.len();
        let mut constant_offset = F::ZERO;

        // Already-bound high variables contribute g_j(r_j).
        for (round, &challenge) in prior_challenges.iter().enumerate() {
            let processed_var = ZK_MLECHECK_N_VARS - 1 - round;
            constant_offset += self.evaluate_univariate_unchecked(processed_var, challenge);
        }

        // Unbound lower variables retain their input-point MLE contribution.
        for (lower_var, &z_i) in input_point.iter().enumerate().take(var_index) {
            constant_offset += self.endpoint_line(lower_var, z_i);
        }

        let base_coeffs = self
            .coefficients_for_field::<F>(var_index)
            .expect("var_index is derived in range");
        let mut coeffs = base_coeffs;
        coeffs[0] += constant_offset;
        Ok(LibraMaskRoundCoefficients { coeffs })
    }

    #[inline]
    fn evaluate_univariate_unchecked<F>(&self, var_index: usize, x: F) -> F
    where
        F: TowerField + From<Block128>,
    {
        evaluate_coefficients(
            &self
                .coefficients_for_field::<F>(var_index)
                .expect("internal variable index in range"),
            x,
        )
    }

    #[inline]
    fn endpoint_line<F>(&self, var_index: usize, z_i: F) -> F
    where
        F: TowerField + From<Block128>,
    {
        let coeffs = self
            .coefficients_for_field::<F>(var_index)
            .expect("internal variable index in range");
        let at_zero = coeffs[0];
        let at_one = coeffs
            .iter()
            .copied()
            .fold(F::ZERO, |acc, coeff| acc + coeff);
        // `at_one - at_zero == at_one + at_zero` in characteristic two.
        at_zero + z_i * (at_one - at_zero)
    }
}

/// Owned mask buffer. The complete caller-supplied buffer is wiped on drop.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct OwnedZkMleCheckMask {
    cells: Box<[Block128; ZK_MLECHECK_MASK_LEN]>,
}

impl OwnedZkMleCheckMask {
    pub fn from_cells(cells: [Block128; ZK_MLECHECK_MASK_LEN]) -> Self {
        Self {
            cells: Box::new(cells),
        }
    }

    pub fn checked_copy_from_slice(cells: &[Block128]) -> Result<Self, ZkMleCheckError> {
        ZkMleCheckMaskView::checked(cells)?;
        let mut owned = Box::new([Block128::ZERO; ZK_MLECHECK_MASK_LEN]);
        owned.copy_from_slice(cells);
        Ok(Self { cells: owned })
    }

    pub fn as_view(&self) -> ZkMleCheckMaskView<'_> {
        ZkMleCheckMaskView {
            cells: self.cells.as_slice(),
            version: OwnerAuthorizationVersion::V4,
        }
    }
}

/// One full degree-ten mask round in monomial coefficient order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraMaskRoundCoefficients<F = Block128> {
    pub coeffs: [F; ZK_MLECHECK_MASK_COEFFS],
}

impl<F: TowerField> LibraMaskRoundCoefficients<F> {
    pub fn evaluate(&self, x: F) -> F {
        evaluate_coefficients(&self.coeffs, x)
    }

    pub fn endpoint_claim(&self, alpha: F) -> F {
        mlecheck_endpoint_claim(&self.coeffs, alpha)
    }

    pub fn as_round_polynomial(&self) -> RoundPolynomial<F> {
        RoundPolynomial::from_coeffs(self.coeffs.to_vec())
    }
}

/// MLE-check round proof with the constant coefficient omitted.
///
/// This is intentionally different from [`noid_core::sumcheck::CompressedRoundPolynomial`],
/// which omits the linear coefficient for a standard characteristic-two
/// sumcheck. Here the MLE-check endpoint identity makes `a_0` redundant.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ZkMleCheckRoundProof<F = Block128> {
    /// `[a_1, ..., a_10]`; the constant `a_0` is recovered from the claim.
    pub coeffs_without_constant: [F; ZK_MLECHECK_ROUND_PROOF_COEFFS],
}

impl<F: TowerField> ZkMleCheckRoundProof<F> {
    pub fn truncate(full: &RoundPolynomial<F>) -> Result<Self, ZkMleCheckError> {
        if full.coeffs.len() != ZK_MLECHECK_MASK_COEFFS {
            return Err(ZkMleCheckError::CombinedRoundCoefficientCount {
                expected: ZK_MLECHECK_MASK_COEFFS,
                actual: full.coeffs.len(),
            });
        }
        Ok(Self {
            coeffs_without_constant: std::array::from_fn(|index| full.coeffs[index + 1]),
        })
    }

    /// Recover `a_0 = claim - alpha * sum(a_1, ..., a_d)` exactly as in
    /// the MLE-check endpoint relation.
    pub fn recover(&self, claim: F, alpha: F) -> RoundPolynomial<F> {
        let nonconstant_sum = self
            .coeffs_without_constant
            .iter()
            .copied()
            .fold(F::ZERO, |acc, coeff| acc + coeff);
        let constant = claim - alpha * nonconstant_sum;
        let mut coeffs = Vec::with_capacity(ZK_MLECHECK_MASK_COEFFS);
        coeffs.push(constant);
        coeffs.extend_from_slice(&self.coeffs_without_constant);
        RoundPolynomial::from_coeffs(coeffs)
    }

    pub const fn byte_len(&self) -> usize {
        ZK_MLECHECK_ROUND_PROOF_COEFFS * (F::BITS / 8)
    }
}

/// Pad a main round through degree ten and add `lambda * mask_round`.
pub fn combine_main_and_mask_round<F: TowerField>(
    main_round: &RoundPolynomial<F>,
    mask_round: &LibraMaskRoundCoefficients<F>,
    lambda: F,
) -> Result<RoundPolynomial<F>, ZkMleCheckError> {
    certify_zk_mlecheck_mask_rank(lambda)?;
    if main_round.coeffs.is_empty() {
        return Err(ZkMleCheckError::MainRoundEmpty);
    }
    if main_round.coeffs.len() > ZK_MLECHECK_MASK_COEFFS {
        return Err(ZkMleCheckError::MainRoundDegreeTooHigh {
            max: ZK_MLECHECK_MASK_DEGREE,
            actual: main_round.coeffs.len() - 1,
        });
    }

    let mut combined = mask_round.coeffs.map(|coeff| lambda * coeff);
    for (combined_coeff, &main_coeff) in combined.iter_mut().zip(&main_round.coeffs) {
        *combined_coeff += main_coeff;
    }
    Ok(RoundPolynomial::from_coeffs(combined.to_vec()))
}

/// `(1-alpha)R(0) + alpha R(1)` for monomial coefficients in
/// characteristic two.
pub fn mlecheck_endpoint_claim<F: TowerField>(coeffs: &[F], alpha: F) -> F {
    let Some((&constant, nonconstant)) = coeffs.split_first() else {
        return F::ZERO;
    };
    let nonconstant_sum = nonconstant
        .iter()
        .copied()
        .fold(F::ZERO, |acc, coeff| acc + coeff);
    // R(1) - R(0) is exactly the sum of nonconstant coefficients.
    constant + alpha * nonconstant_sum
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkMleCheckVerifierOutput<F = Block128> {
    /// Unbatched main-polynomial evaluation at `terminal_point`.
    pub main_eval: F,
    /// Caller-supplied final mask evaluation at the same point.
    pub mask_eval: F,
    /// Variable order is low-to-high, despite rounds running high-to-low.
    pub terminal_point: [F; ZK_MLECHECK_N_VARS],
}

/// Native verifier telescope. Fiat-Shamir absorption/sampling is deliberately
/// left to the future protocol wrapper; this state consumes explicit caller
/// challenges and creates none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkMleCheckVerifierState<F = Block128> {
    input_point: [F; ZK_MLECHECK_N_VARS],
    lambda: F,
    running_claim: F,
    completed_rounds: usize,
    terminal_point: [F; ZK_MLECHECK_N_VARS],
}

impl<F: TowerField> ZkMleCheckVerifierState<F> {
    pub fn new(
        input_point: [F; ZK_MLECHECK_N_VARS],
        main_claim: F,
        mask_mle_eval: F,
        lambda: F,
    ) -> Self {
        Self {
            input_point,
            lambda,
            running_claim: main_claim + lambda * mask_mle_eval,
            completed_rounds: 0,
            terminal_point: [F::ZERO; ZK_MLECHECK_N_VARS],
        }
    }

    pub const fn running_claim(&self) -> F {
        self.running_claim
    }

    pub const fn completed_rounds(&self) -> usize {
        self.completed_rounds
    }

    pub const fn current_var_index(&self) -> Option<usize> {
        if self.completed_rounds == ZK_MLECHECK_N_VARS {
            None
        } else {
            Some(ZK_MLECHECK_N_VARS - 1 - self.completed_rounds)
        }
    }

    /// Recover the full round, evaluate it at the caller-supplied challenge,
    /// and advance the high-to-low telescope by one variable.
    pub fn transition(
        &mut self,
        round: &ZkMleCheckRoundProof<F>,
        challenge: F,
    ) -> Result<RoundPolynomial<F>, ZkMleCheckError> {
        let var_index = self
            .current_var_index()
            .ok_or(ZkMleCheckError::RoundExhausted)?;
        let alpha = self.input_point[var_index];
        let recovered = round.recover(self.running_claim, alpha);
        debug_assert_eq!(
            mlecheck_endpoint_claim(&recovered.coeffs, alpha),
            self.running_claim
        );
        self.running_claim = recovered.evaluate(challenge);
        self.terminal_point[var_index] = challenge;
        self.completed_rounds += 1;
        Ok(recovered)
    }

    /// Unbatch the final mask evaluation after exactly eleven transitions.
    pub fn finish(
        self,
        mask_final_eval: F,
    ) -> Result<ZkMleCheckVerifierOutput<F>, ZkMleCheckError> {
        if self.completed_rounds != ZK_MLECHECK_N_VARS {
            return Err(ZkMleCheckError::RoundsIncomplete {
                completed: self.completed_rounds,
            });
        }
        Ok(ZkMleCheckVerifierOutput {
            main_eval: self.running_claim - self.lambda * mask_final_eval,
            mask_eval: mask_final_eval,
            terminal_point: self.terminal_point,
        })
    }

    /// Test/integration gate that also binds the unbatched result to the
    /// caller's independently computed main terminal evaluation.
    pub fn finish_checked(
        self,
        mask_final_eval: F,
        expected_main_final: F,
    ) -> Result<ZkMleCheckVerifierOutput<F>, ZkMleCheckError> {
        let output = self.finish(mask_final_eval)?;
        if output.main_eval != expected_main_final {
            return Err(ZkMleCheckError::MainFinalMismatch);
        }
        Ok(output)
    }
}

fn evaluate_coefficients<F: TowerField>(coeffs: &[F], x: F) -> F {
    coeffs
        .iter()
        .rev()
        .fold(F::ZERO, |acc, &coeff| acc * x + coeff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::mle::evaluate::evaluate_slice;

    fn elem(index: usize, domain: u128) -> Block128 {
        Block128::from(
            domain
                .wrapping_mul(index as u128 + 1)
                .rotate_left((index % 127) as u32)
                ^ (index as u128 * 0x9E37_79B9_7F4A_7C15),
        )
    }

    fn cells(domain: u128) -> [Block128; ZK_MLECHECK_MASK_LEN] {
        std::array::from_fn(|index| elem(index, domain))
    }

    fn point(domain: u128) -> [Block128; ZK_MLECHECK_N_VARS] {
        std::array::from_fn(|index| elem(index + 31, domain))
    }

    fn direct_univariate(mask: ZkMleCheckMaskView<'_>, var_index: usize, x: Block128) -> Block128 {
        let coeffs = mask.coefficients_for_var(var_index).unwrap();
        let mut power = Block128::ONE;
        let mut value = Block128::ZERO;
        for coeff in coeffs {
            value += coeff * power;
            power *= x;
        }
        value
    }

    #[test]
    fn checked_view_and_owned_buffer_preserve_every_caller_cell() {
        let supplied = cells(0xB0FFE2);
        let view = ZkMleCheckMaskView::checked(&supplied).unwrap();
        assert_eq!(view.cells(), supplied.as_slice());

        let owned = OwnedZkMleCheckMask::checked_copy_from_slice(&supplied).unwrap();
        assert_eq!(owned.as_view().cells(), supplied.as_slice());

        assert!(matches!(
            ZkMleCheckMaskView::checked(&supplied[..ZK_MLECHECK_MASK_LEN - 1]),
            Err(ZkMleCheckError::MaskBufferLength { .. })
        ));
        assert!(matches!(
            OwnedZkMleCheckMask::checked_copy_from_slice(&supplied[..17]),
            Err(ZkMleCheckError::MaskBufferLength { .. })
        ));
    }

    #[test]
    fn mask_mle_and_final_eval_match_direct_polynomials() {
        let supplied = cells(0x6A5C);
        let mask = ZkMleCheckMaskView::checked(&supplied).unwrap();
        let input_point = point(0x1A907);

        let mut boolean_table = vec![Block128::ZERO; 1 << ZK_MLECHECK_N_VARS];
        for (vertex, value) in boolean_table.iter_mut().enumerate() {
            for var_index in 0..ZK_MLECHECK_N_VARS {
                let bit = Block128::from(((vertex >> var_index) & 1) as u128);
                *value += direct_univariate(mask, var_index, bit);
            }
        }
        assert_eq!(
            mask.evaluate_mle(&input_point),
            evaluate_slice(&boolean_table, &input_point)
        );

        let terminal_point = point(0x7E2A11);
        let direct_final = terminal_point
            .iter()
            .enumerate()
            .fold(Block128::ZERO, |acc, (var_index, &r_i)| {
                acc + direct_univariate(mask, var_index, r_i)
            });
        assert_eq!(mask.evaluate_final(&terminal_point), direct_final);
    }

    #[test]
    fn separable_rounds_match_direct_high_to_low_restriction() {
        let supplied = cells(0xC0EFF);
        let mask = ZkMleCheckMaskView::checked(&supplied).unwrap();
        let input_point = point(0x1A907);
        let challenges = point(0xC4A11);

        let mut current_claim = mask.evaluate_mle(&input_point);
        for round_index in 0..ZK_MLECHECK_N_VARS {
            let var_index = ZK_MLECHECK_N_VARS - 1 - round_index;
            let round = mask
                .round_coefficients(&input_point, &challenges[..round_index])
                .unwrap();
            assert_eq!(round.endpoint_claim(input_point[var_index]), current_claim);

            for x in [Block128::ZERO, Block128::ONE, elem(round_index, 0xA11CE)] {
                let mut direct = direct_univariate(mask, var_index, x);
                for (prior_round, &challenge) in challenges[..round_index].iter().enumerate() {
                    let processed_var = ZK_MLECHECK_N_VARS - 1 - prior_round;
                    direct += direct_univariate(mask, processed_var, challenge);
                }
                for lower_var in 0..var_index {
                    let at_zero = direct_univariate(mask, lower_var, Block128::ZERO);
                    let at_one = direct_univariate(mask, lower_var, Block128::ONE);
                    direct += at_zero + input_point[lower_var] * (at_one - at_zero);
                }
                assert_eq!(round.evaluate(x), direct);
            }

            current_claim = round.evaluate(challenges[round_index]);
        }

        let terminal_point =
            std::array::from_fn(|var_index| challenges[ZK_MLECHECK_N_VARS - 1 - var_index]);
        assert_eq!(current_claim, mask.evaluate_final(&terminal_point));
    }

    #[test]
    fn constant_truncation_and_recovery_use_characteristic_two_ordering() {
        let coeffs: Vec<Block128> = (0..ZK_MLECHECK_MASK_COEFFS)
            .map(|index| elem(index, 0xC0EFF))
            .collect();
        let full = RoundPolynomial::from_coeffs(coeffs.clone());
        let alpha = elem(21, 0xA1FA);
        let claim = mlecheck_endpoint_claim(&coeffs, alpha);
        let proof = ZkMleCheckRoundProof::truncate(&full).unwrap();

        assert_eq!(proof.coeffs_without_constant[0], coeffs[1]);
        assert_eq!(proof.coeffs_without_constant[9], coeffs[10]);
        let nonconstant_sum = coeffs[1..]
            .iter()
            .copied()
            .fold(Block128::ZERO, |acc, coeff| acc + coeff);
        assert_eq!(coeffs[0], claim - alpha * nonconstant_sum);
        assert_eq!(proof.recover(claim, alpha), full);

        let at_zero = full.evaluate(Block128::ZERO);
        let at_one = full.evaluate(Block128::ONE);
        assert_eq!(claim, at_zero + alpha * (at_one - at_zero));
    }

    fn matrix_rank(mut matrix: Vec<Vec<Block128>>) -> usize {
        let columns = matrix.first().map_or(0, Vec::len);
        let mut rank = 0;
        for column in 0..columns {
            let Some(pivot) =
                (rank..matrix.len()).find(|&row| matrix[row][column] != Block128::ZERO)
            else {
                continue;
            };
            matrix.swap(rank, pivot);
            let inverse = matrix[rank][column].invert();
            for entry in &mut matrix[rank][column..] {
                *entry *= inverse;
            }
            let pivot_row = matrix[rank].clone();
            for (row_index, row) in matrix.iter_mut().enumerate() {
                if row_index == rank {
                    continue;
                }
                let factor = row[column];
                if factor == Block128::ZERO {
                    continue;
                }
                for (entry, &pivot_entry) in row[column..].iter_mut().zip(&pivot_row[column..]) {
                    *entry += factor * pivot_entry;
                }
            }
            rank += 1;
            if rank == matrix.len() {
                break;
            }
        }
        rank
    }

    #[test]
    fn libra_public_observation_matrix_has_exact_rank_111() {
        let input = point(0x1A907);
        let terminal = point(0x7E2A11);
        let lambda = elem(77, 0x1A4BDA);
        assert_ne!(lambda, Block128::ZERO);

        let mut matrix = vec![
            vec![Block128::ZERO; ZK_MLECHECK_ACTIVE_MASK_COEFFS];
            ZK_MLECHECK_PUBLIC_MASK_FIELDS
        ];

        // mu = sum_j c[j,0] + rho[j] * sum_{k=1}^{10} c[j,k].
        for variable in 0..ZK_MLECHECK_N_VARS {
            let base = variable * ZK_MLECHECK_MASK_COEFFS;
            matrix[0][base] = Block128::ONE;
            for power in 1..=ZK_MLECHECK_MASK_DEGREE {
                matrix[0][base + power] = input[variable];
                let round_row = 1 + variable * ZK_MLECHECK_MASK_DEGREE + power - 1;
                matrix[round_row][base + power] = lambda;
            }
        }

        // g(r) = sum_{j,k} c[j,k] * r[j]^k.
        let final_row = ZK_MLECHECK_PUBLIC_MASK_FIELDS - 1;
        for variable in 0..ZK_MLECHECK_N_VARS {
            let base = variable * ZK_MLECHECK_MASK_COEFFS;
            let mut power_value = Block128::ONE;
            for power in 0..=ZK_MLECHECK_MASK_DEGREE {
                matrix[final_row][base + power] = power_value;
                power_value *= terminal[variable];
            }
        }

        assert_eq!(matrix_rank(matrix), ZK_MLECHECK_MASK_OBSERVATION_RANK);
        assert_eq!(
            certify_zk_mlecheck_mask_rank(lambda).unwrap(),
            ZkMleCheckMaskRankCertificate {
                active_mask_coefficients: 121,
                public_mask_dependent_fields: 112,
                certified_rank: 111,
                intended_terminal_relations: 1,
                remaining_active_degrees_of_freedom: 10,
            }
        );
        assert_eq!(
            certify_zk_mlecheck_mask_rank(Block128::ZERO),
            Err(ZkMleCheckError::ZeroMaskBatchChallenge)
        );
    }

    fn honest_proof_fixture() -> (
        [Block128; ZK_MLECHECK_N_VARS],
        Block128,
        Block128,
        Block128,
        [Block128; ZK_MLECHECK_N_VARS],
        Vec<ZkMleCheckRoundProof>,
        Block128,
        Block128,
    ) {
        let main_cells = cells(0xA11CE);
        let mask_cells = cells(0x6A5C);
        let main = ZkMleCheckMaskView::checked(&main_cells).unwrap();
        let mask = ZkMleCheckMaskView::checked(&mask_cells).unwrap();
        let input_point = point(0x1A907);
        let lambda = elem(77, 0x1A4BDA);
        let challenges = point(0xC4A11);
        let main_claim = main.evaluate_mle(&input_point);
        let mask_claim = mask.evaluate_mle(&input_point);

        let mut proofs = Vec::with_capacity(ZK_MLECHECK_N_VARS);
        for round_index in 0..ZK_MLECHECK_N_VARS {
            let main_round = main
                .round_coefficients(&input_point, &challenges[..round_index])
                .unwrap();
            let mask_round = mask
                .round_coefficients(&input_point, &challenges[..round_index])
                .unwrap();
            let combined =
                combine_main_and_mask_round(&main_round.as_round_polynomial(), &mask_round, lambda)
                    .unwrap();
            proofs.push(ZkMleCheckRoundProof::truncate(&combined).unwrap());
        }

        let terminal_point =
            std::array::from_fn(|var_index| challenges[ZK_MLECHECK_N_VARS - 1 - var_index]);
        let main_final = main.evaluate_final(&terminal_point);
        let mask_final = mask.evaluate_final(&terminal_point);
        (
            input_point,
            main_claim,
            mask_claim,
            lambda,
            challenges,
            proofs,
            main_final,
            mask_final,
        )
    }

    #[test]
    fn honest_combined_roundtrip_and_verifier_transition() {
        let (
            input_point,
            main_claim,
            mask_claim,
            lambda,
            challenges,
            proofs,
            main_final,
            mask_final,
        ) = honest_proof_fixture();
        let mut verifier =
            ZkMleCheckVerifierState::new(input_point, main_claim, mask_claim, lambda);

        for (round_index, (proof, &challenge)) in proofs.iter().zip(&challenges).enumerate() {
            assert_eq!(
                verifier.current_var_index(),
                Some(ZK_MLECHECK_N_VARS - 1 - round_index)
            );
            verifier.transition(proof, challenge).unwrap();
        }
        assert_eq!(verifier.current_var_index(), None);
        let output = verifier.finish_checked(mask_final, main_final).unwrap();
        assert_eq!(output.main_eval, main_final);
        assert_eq!(output.mask_eval, mask_final);
        for var_index in 0..ZK_MLECHECK_N_VARS {
            assert_eq!(
                output.terminal_point[var_index],
                challenges[ZK_MLECHECK_N_VARS - 1 - var_index]
            );
        }
    }

    #[test]
    fn tampered_round_or_mask_final_is_rejected_by_terminal_binding() {
        let (
            input_point,
            main_claim,
            mask_claim,
            lambda,
            challenges,
            mut proofs,
            main_final,
            mask_final,
        ) = honest_proof_fixture();

        // Last round processes variable zero. Changing a_1 changes R(r) by
        // delta*(r-alpha), while recovered a_0 still enforces the endpoint
        // identity. The independent terminal main evaluation must reject it.
        proofs[ZK_MLECHECK_N_VARS - 1].coeffs_without_constant[0] += Block128::ONE;
        let mut verifier =
            ZkMleCheckVerifierState::new(input_point, main_claim, mask_claim, lambda);
        for (proof, &challenge) in proofs.iter().zip(&challenges) {
            verifier.transition(proof, challenge).unwrap();
        }
        assert_eq!(
            verifier.finish_checked(mask_final, main_final),
            Err(ZkMleCheckError::MainFinalMismatch)
        );

        let (
            input_point,
            main_claim,
            mask_claim,
            lambda,
            challenges,
            proofs,
            main_final,
            mask_final,
        ) = honest_proof_fixture();
        let mut verifier =
            ZkMleCheckVerifierState::new(input_point, main_claim, mask_claim, lambda);
        for (proof, &challenge) in proofs.iter().zip(&challenges) {
            verifier.transition(proof, challenge).unwrap();
        }
        assert_eq!(
            verifier.finish_checked(mask_final + Block128::ONE, main_final),
            Err(ZkMleCheckError::MainFinalMismatch)
        );
    }
}
