// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Production correspondence for published Poseidon2b algebraic attacks.
//!
//! This module records the classical attack-cost projections that can be
//! instantiated for the fixed Parano1d profile. The production QROM delta
//! remains a separate premise of the end-to-end theorem.

use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::{MDS_FULL, MDS_PARTIAL};
use num_bigint::BigUint;
use num_traits::One;

use crate::{exact::descriptive_log2_integer, parameters::ProductionParameters};

pub const SKIPPING_CLASS_EPRINT: &str = "2026/306";
pub const SKIPPING_CLASS_REVIEWED_VERSION: &str = "2026-02-18";
pub const SKIPPING_CLASS_PDF_SHA256: &str =
    "8297df539a48859678ad2e4ba79d005a544e1a9686770a4f72a30ad358f76249";
pub const NONLINEAR_SUBSPACES_EPRINT: &str = "2026/1792";
pub const NONLINEAR_SUBSPACES_REVIEWED_VERSION: &str = "20260824:125701";
pub const NONLINEAR_SUBSPACES_PDF_SHA256: &str =
    "006cf8bc3b47df053d662b6552aa82fd8add2a75a152e08f9c63db73a29564cb";

// Production baseline to which the paper's generic results are specialized.
// These are correspondence pins, not parameter claims made by the paper.
const AUDITED_FIELD_BITS: u32 = 128;
const AUDITED_STATE_WIDTH: usize = 4;
const AUDITED_RATE_LANES: usize = 2;
const AUDITED_DIGEST_LANES: usize = 2;
const AUDITED_SBOX_EXPONENT: usize = 7;
const AUDITED_FULL_ROUNDS: usize = 8;
const AUDITED_PARTIAL_ROUNDS: usize = 58;
const AUDITED_PARTIAL_SBOXES: usize = 1;

// Binary M4 from the Poseidon2b specification and Section 2.2 of ePrint
// 2026/306. For t=4 this is the complete external matrix, rather than one
// block in the wide non-MDS tensor construction attacked in the main tables.
const AUDITED_BINARY_M4: [[u128; 4]; 4] = [
    [0x5, 0x7, 0x1, 0x3],
    [0x4, 0x6, 0x1, 0x1],
    [0x1, 0x3, 0x5, 0x7],
    [0x1, 0x1, 0x4, 0x6],
];

const AUDITED_INTERNAL_MATRIX: [[u128; 4]; 4] = [
    [0x20, 0x1, 0x1, 0x1],
    [0x1, 0x2000, 0x1, 0x1],
    [0x1, 0x1, 0x200, 0x1],
    [0x1, 0x1, 0x1, 0x800],
];

/// One exact `omega=2` Macaulay-matrix projection from ePrint 2026/1792.
///
/// These are attack-cost projections under the paper's semi-regular model,
/// not lower bounds on all possible attacks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacaulayProjection {
    pub model: &'static str,
    pub partial_rounds_before_trail: Option<usize>,
    pub variables: usize,
    pub macaulay_matrix_dimension: BigUint,
    pub quadratic_work_projection: BigUint,
}

impl MacaulayProjection {
    pub fn descriptive_quadratic_projection_bits(&self) -> f64 {
        descriptive_log2_integer(&self.quadratic_work_projection)
    }
}

/// Exact production specialization of the subspace models in ePrint 2026/1792.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonlinearSubspaceAudit {
    /// Compression mode has no fixed input-capacity coordinates, so Section
    /// 4.1 gives `E_c = t - d`.
    pub extra_constraint_budget: usize,
    pub partial_sboxes_per_round: usize,
    pub linear_trail_rounds: usize,
    pub nonlinear_trail_rounds: usize,
    /// The one-by-one `N_e` core for the production t=4, s=1, E_c=2 even
    /// construction, encoded in the production tower basis.
    pub even_balancing_core: u128,
    pub projections: Vec<MacaulayProjection>,
    pub lowest_cost_projection_index: usize,
}

impl NonlinearSubspaceAudit {
    pub fn lowest_cost_projection(&self) -> &MacaulayProjection {
        &self.projections[self.lowest_cost_projection_index]
    }
}

/// Exact specialization of the published classical attack models.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poseidon2bCryptanalysisAudit {
    pub field_bits: u32,
    pub state_width: usize,
    pub rate_lanes: usize,
    pub capacity_lanes: usize,
    pub digest_lanes: usize,
    pub sbox_exponent: usize,
    pub full_rounds: usize,
    pub partial_rounds: usize,
    /// Section 3.4 limits the paper's wide tensor round skips to widths
    /// 12, 16, 20 and 24. The production width is four.
    pub wide_tensor_round_skips_apply: bool,
    /// Appendix A applies to the production one-permutation, feed-forward,
    /// two-to-one compression used for Merkle nodes.
    pub appendix_a_compression_applies: bool,
    pub skipped_full_rounds: usize,
    pub skipped_partial_rounds: usize,
    pub parameter_degrees: Vec<usize>,
    pub ideal_degree_base: usize,
    pub ideal_degree_exponent: u32,
    pub ideal_degree_upper_bound: BigUint,
    /// The paper models algebraic solving work as proportional to d_I^omega
    /// and uses omega=2 as its conservative projection.
    pub quadratic_work_projection: BigUint,
    pub nonlinear_subspaces: NonlinearSubspaceAudit,
}

impl Poseidon2bCryptanalysisAudit {
    pub fn descriptive_ideal_degree_bits(&self) -> f64 {
        descriptive_log2_integer(&self.ideal_degree_upper_bound)
    }

    pub fn descriptive_quadratic_projection_bits(&self) -> f64 {
        descriptive_log2_integer(&self.quadratic_work_projection)
    }
}

/// Match the production instance to ePrint 2026/306 and instantiate the one
/// attack from that paper which applies to the t=4 construction.
pub fn audit(parameters: &ProductionParameters) -> Result<Poseidon2bCryptanalysisAudit, String> {
    let field_bits = u128::BITS;
    let capacity_lanes = parameters
        .poseidon_state_width
        .checked_sub(parameters.poseidon_rate_lanes)
        .ok_or_else(|| "Poseidon2b rate exceeds its state width".to_string())?;
    if !parameters.digest_bits.is_multiple_of(field_bits) {
        return Err("Poseidon2b digest width is not a whole number of field lanes".to_string());
    }
    let digest_lanes = usize::try_from(parameters.digest_bits / field_bits)
        .map_err(|_| "Poseidon2b digest lane count does not fit usize".to_string())?;

    let tuple = (
        field_bits,
        parameters.poseidon_state_width,
        parameters.poseidon_rate_lanes,
        digest_lanes,
        parameters.poseidon_sbox_exponent,
        parameters.poseidon_full_rounds,
        parameters.poseidon_partial_rounds,
    );
    let audited_tuple = (
        AUDITED_FIELD_BITS,
        AUDITED_STATE_WIDTH,
        AUDITED_RATE_LANES,
        AUDITED_DIGEST_LANES,
        AUDITED_SBOX_EXPONENT,
        AUDITED_FULL_ROUNDS,
        AUDITED_PARTIAL_ROUNDS,
    );
    if tuple != audited_tuple {
        return Err("Poseidon2b profile changed from the audited cryptanalysis target".to_string());
    }
    if MDS_FULL != AUDITED_BINARY_M4 || MDS_PARTIAL != AUDITED_INTERNAL_MATRIX {
        return Err(
            "Poseidon2b matrices changed from the audited cryptanalysis target".to_string(),
        );
    }
    if gcd_u128(parameters.poseidon_sbox_exponent as u128, u128::MAX) != 1 {
        return Err("Poseidon2b S-box is not a permutation of GF(2^128)".to_string());
    }

    // Appendix A gives a (1, [1] + [alpha]^(t/2-1)) round skip for MDS
    // two-to-one feed-forward compression. Here t=4, d=t/2=2 and alpha=7,
    // hence (1, [1, 7]). Theorem 5.1 gives
    //
    //   d_I <= alpha^(d(R_F-r_F) + (R_P-r_P)) * product(delta_i)
    //       = 7^(2(8-1) + 58) * 7
    //       = 7^73.
    let skipped_full_rounds = 1usize;
    let skipped_partial_rounds = 0usize;
    let parameter_degrees = vec![1, parameters.poseidon_sbox_exponent];
    let product_degree_exponent = u32::try_from(digest_lanes - 1)
        .map_err(|_| "Appendix A degree exponent does not fit u32".to_string())?;
    let remaining_full_degree = digest_lanes
        .checked_mul(parameters.poseidon_full_rounds - skipped_full_rounds)
        .ok_or_else(|| "Appendix A full-round exponent overflow".to_string())?;
    let remaining_partial_degree = parameters.poseidon_partial_rounds - skipped_partial_rounds;
    let ideal_degree_exponent = u32::try_from(remaining_full_degree + remaining_partial_degree)
        .map_err(|_| "Appendix A ideal-degree exponent does not fit u32".to_string())?
        .checked_add(product_degree_exponent)
        .ok_or_else(|| "Appendix A ideal-degree exponent overflow".to_string())?;
    let ideal_degree_base = parameters.poseidon_sbox_exponent;
    let ideal_degree_upper_bound = BigUint::from(ideal_degree_base).pow(ideal_degree_exponent);
    let quadratic_work_projection = ideal_degree_upper_bound.pow(2);
    let wide_tensor_round_skips_apply = [12, 16, 20, 24].contains(&parameters.poseidon_state_width);
    let appendix_a_compression_applies =
        digest_lanes * 2 == parameters.poseidon_state_width && MDS_FULL == AUDITED_BINARY_M4;
    let nonlinear_subspaces = nonlinear_subspace_audit(parameters, digest_lanes, field_bits)?;

    Ok(Poseidon2bCryptanalysisAudit {
        field_bits,
        state_width: parameters.poseidon_state_width,
        rate_lanes: parameters.poseidon_rate_lanes,
        capacity_lanes,
        digest_lanes,
        sbox_exponent: parameters.poseidon_sbox_exponent,
        full_rounds: parameters.poseidon_full_rounds,
        partial_rounds: parameters.poseidon_partial_rounds,
        wide_tensor_round_skips_apply,
        appendix_a_compression_applies,
        skipped_full_rounds,
        skipped_partial_rounds,
        parameter_degrees,
        ideal_degree_base,
        ideal_degree_exponent,
        ideal_degree_upper_bound,
        quadratic_work_projection,
        nonlinear_subspaces,
    })
}

fn nonlinear_subspace_audit(
    parameters: &ProductionParameters,
    digest_lanes: usize,
    field_bits: u32,
) -> Result<NonlinearSubspaceAudit, String> {
    let extra_constraint_budget = parameters
        .poseidon_state_width
        .checked_sub(digest_lanes)
        .ok_or_else(|| "Poseidon2b digest exceeds the compression state width".to_string())?;
    let linear_trail_rounds = extra_constraint_budget / AUDITED_PARTIAL_SBOXES;
    let nonlinear_trail_rounds = linear_trail_rounds
        .checked_mul(2)
        .ok_or_else(|| "nonlinear subspace trail length overflow".to_string())?;
    if nonlinear_trail_rounds >= parameters.poseidon_partial_rounds {
        return Err(format!(
            "ePrint {NONLINEAR_SUBSPACES_EPRINT} trail consumes the complete production partial layer"
        ));
    }

    // Section B.7 reduces the even construction to N_e. For t=4, s=1 and
    // E_c=2, N_e is one-by-one:
    //
    //   N_e = B S C A^-1 - 1,
    //   S   = D - C A^-1 B.
    //
    // Evaluate it in the exact GF(2^128) tower basis used by the scalar
    // production reference path. A nonzero value is the required instance-
    // level rank check; generic nonsingularity alone is not enough.
    let even_balancing_core = production_even_balancing_core()?;
    if even_balancing_core == Block128::ZERO {
        return Err(format!(
            "production Poseidon2b internal matrix fails the ePrint {NONLINEAR_SUBSPACES_EPRINT} balancing-rank check"
        ));
    }

    let full_rounds_before = parameters.poseidon_full_rounds / 2;
    let full_rounds_after = parameters
        .poseidon_full_rounds
        .checked_sub(full_rounds_before)
        .ok_or_else(|| "Poseidon2b full-round split underflow".to_string())?;
    let alpha = parameters.poseidon_sbox_exponent;
    let t = parameters.poseidon_state_width;
    let d = digest_lanes;
    let c = 0usize;
    let r = t - c;

    let linear_max_tau = parameters
        .poseidon_partial_rounds
        .checked_sub(linear_trail_rounds)
        .ok_or_else(|| "linear subspace trail exceeds the partial layer".to_string())?;
    let nonlinear_max_tau = parameters
        .poseidon_partial_rounds
        .checked_sub(
            nonlinear_trail_rounds
                .checked_add(1)
                .ok_or_else(|| "nonlinear subspace placement overflow".to_string())?,
        )
        .ok_or_else(|| {
            "nonlinear subspace trail cannot be placed in the partial layer".to_string()
        })?;

    let linear_substitution = minimizing_substitution_projection(
        "forward + substitution + linear subspace",
        0..=linear_max_tau,
        t + d,
        |tau| {
            let left = capped_power(alpha, full_rounds_before + tau, field_bits);
            let right = capped_power(
                alpha,
                full_rounds_after + parameters.poseidon_partial_rounds - tau - linear_trail_rounds,
                field_bits,
            );
            BigUint::one() + BigUint::from(t) * left + BigUint::from(d) * right
        },
    );
    let nonlinear_substitution = minimizing_substitution_projection(
        "forward + substitution + nonlinear subspace",
        0..=nonlinear_max_tau,
        2 * t - c,
        |tau| {
            let left = capped_power(alpha, full_rounds_before + tau, field_bits);
            let right = capped_power(
                alpha,
                full_rounds_after + parameters.poseidon_partial_rounds
                    - tau
                    - nonlinear_trail_rounds,
                field_bits,
            );
            BigUint::one()
                + BigUint::from(t) * left
                + BigUint::from(d) * right
                + BigUint::from(extra_constraint_budget) * BigUint::from(alpha)
        },
    );

    let linear_nonsubstitution_sum = BigUint::one()
        + BigUint::from(d)
            * capped_power(
                alpha,
                parameters.poseidon_full_rounds + parameters.poseidon_partial_rounds
                    - linear_trail_rounds,
                field_bits,
            )
        + BigUint::from(extra_constraint_budget)
            * capped_power(alpha, full_rounds_before, field_bits);
    let linear_nonsubstitution = projection_from_degree_sum(
        "forward + no substitution + linear subspace",
        None,
        r,
        linear_nonsubstitution_sum,
    );

    let nonlinear_nonsubstitution_sum = BigUint::one()
        + BigUint::from(d)
            * capped_power(
                alpha,
                parameters.poseidon_full_rounds + parameters.poseidon_partial_rounds
                    - nonlinear_trail_rounds,
                field_bits,
            )
        + BigUint::from(extra_constraint_budget)
            * capped_power(alpha, full_rounds_before + 1, field_bits);
    let nonlinear_nonsubstitution = projection_from_degree_sum(
        "forward + no substitution + nonlinear subspace",
        None,
        r,
        nonlinear_nonsubstitution_sum,
    );

    let projections = vec![
        linear_substitution,
        nonlinear_substitution,
        linear_nonsubstitution,
        nonlinear_nonsubstitution,
    ];
    let lowest_cost_projection_index = projections
        .iter()
        .enumerate()
        .min_by(|(_, left), (_, right)| {
            left.quadratic_work_projection
                .cmp(&right.quadratic_work_projection)
        })
        .map(|(index, _)| index)
        .ok_or_else(|| "missing nonlinear-subspace projections".to_string())?;

    Ok(NonlinearSubspaceAudit {
        extra_constraint_budget,
        partial_sboxes_per_round: AUDITED_PARTIAL_SBOXES,
        linear_trail_rounds,
        nonlinear_trail_rounds,
        even_balancing_core: even_balancing_core.to_u128(),
        projections,
        lowest_cost_projection_index,
    })
}

fn production_even_balancing_core() -> Result<Block128, String> {
    let field = |value: u128| Block128::from(value);
    let a = field(MDS_PARTIAL[0][0]);
    if a == Block128::ZERO {
        return Err("Poseidon2b internal active-coordinate block is singular".to_string());
    }
    let a_inverse = a.invert();
    let b = [
        field(MDS_PARTIAL[0][1]),
        field(MDS_PARTIAL[0][2]),
        field(MDS_PARTIAL[0][3]),
    ];
    let c = [
        field(MDS_PARTIAL[1][0]),
        field(MDS_PARTIAL[2][0]),
        field(MDS_PARTIAL[3][0]),
    ];
    let mut schur = [[Block128::ZERO; 3]; 3];
    for row in 0..3 {
        for column in 0..3 {
            schur[row][column] =
                field(MDS_PARTIAL[row + 1][column + 1]) - c[row] * a_inverse * b[column];
        }
    }
    let mut schur_times_c = [Block128::ZERO; 3];
    for row in 0..3 {
        for (column, c_entry) in c.iter().enumerate() {
            schur_times_c[row] += schur[row][column] * *c_entry;
        }
    }
    let mut b_schur_c = Block128::ZERO;
    for row in 0..3 {
        b_schur_c += b[row] * schur_times_c[row];
    }
    Ok(b_schur_c * a_inverse - Block128::ONE)
}

fn minimizing_substitution_projection(
    model: &'static str,
    tau_range: std::ops::RangeInclusive<usize>,
    variables: usize,
    degree_sum: impl Fn(usize) -> BigUint,
) -> MacaulayProjection {
    tau_range
        .map(|tau| projection_from_degree_sum(model, Some(tau), variables, degree_sum(tau)))
        .min_by(|left, right| {
            left.quadratic_work_projection
                .cmp(&right.quadratic_work_projection)
        })
        .expect("a nonempty partial-round placement range")
}

fn projection_from_degree_sum(
    model: &'static str,
    partial_rounds_before_trail: Option<usize>,
    variables: usize,
    degree_sum: BigUint,
) -> MacaulayProjection {
    let macaulay_matrix_dimension = binomial(&degree_sum, variables);
    let quadratic_work_projection = macaulay_matrix_dimension.pow(2);
    MacaulayProjection {
        model,
        partial_rounds_before_trail,
        variables,
        macaulay_matrix_dimension,
        quadratic_work_projection,
    }
}

fn capped_power(base: usize, exponent: usize, field_bits: u32) -> BigUint {
    let exponent = u32::try_from(exponent).expect("Poseidon2b exponent fits u32");
    let degree = BigUint::from(base).pow(exponent);
    let field_polynomial_degree_cap = (BigUint::one() << field_bits) - 2u32;
    degree.min(field_polynomial_degree_cap)
}

fn binomial(top: &BigUint, bottom: usize) -> BigUint {
    if bottom == 0 {
        return BigUint::one();
    }
    let mut result = BigUint::one();
    for index in 0..bottom {
        let factor = top - BigUint::from(index);
        result *= factor;
        result /= BigUint::from(index + 1);
    }
    result
}

fn gcd_u128(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::native::{
        DomainTag, capacity_iv_flat, compress_flat_feed_forward_with_tag, permute_flat_u128,
    };

    #[test]
    fn production_profile_instantiates_the_appendix_a_bound_exactly() {
        let parameters = ProductionParameters::load().unwrap();
        let result = audit(&parameters).unwrap();

        assert_eq!(result.field_bits, 128);
        assert_eq!(result.state_width, 4);
        assert_eq!(result.rate_lanes, 2);
        assert_eq!(result.capacity_lanes, 2);
        assert_eq!(result.digest_lanes, 2);
        assert!(!result.wide_tensor_round_skips_apply);
        assert!(result.appendix_a_compression_applies);
        assert_eq!(result.parameter_degrees, [1, 7]);
        assert_eq!(result.ideal_degree_exponent, 73);
        assert_eq!(
            result.ideal_degree_upper_bound.to_string(),
            "49221735352184872959961855190338177606846542622561400857262407"
        );
        assert_eq!(
            result.quadratic_work_projection.to_string(),
            "2422779231080526099722000834398871788804606268104681604592905959020265247411227403401328491417830386450157273478434455433649"
        );
    }

    #[test]
    fn production_profile_instantiates_the_nonlinear_subspace_models() {
        let parameters = ProductionParameters::load().unwrap();
        let result = audit(&parameters).unwrap();
        let nonlinear = &result.nonlinear_subspaces;

        assert_eq!(nonlinear.extra_constraint_budget, 2);
        assert_eq!(nonlinear.partial_sboxes_per_round, 1);
        assert_eq!(nonlinear.linear_trail_rounds, 2);
        assert_eq!(nonlinear.nonlinear_trail_rounds, 4);
        assert_eq!(nonlinear.even_balancing_core, 0xbe32);
        assert_eq!(nonlinear.projections.len(), 4);
        assert_eq!(
            nonlinear.projections[0].partial_rounds_before_trail,
            Some(28)
        );
        assert_eq!(
            nonlinear.projections[1].partial_rounds_before_trail,
            Some(27)
        );
        assert_eq!(nonlinear.lowest_cost_projection_index, 2);
        let expected_projection_bits = [
            1090.060133886114,
            1403.209025315336,
            1022.830074998558,
            1022.830074998558,
        ];
        for (projection, expected_bits) in
            nonlinear.projections.iter().zip(expected_projection_bits)
        {
            assert!(
                (projection.descriptive_quadratic_projection_bits() - expected_bits).abs() < 1e-9
            );
        }
        assert!(
            nonlinear.projections[2].quadratic_work_projection
                < nonlinear.projections[3].quadratic_work_projection
        );
        assert_eq!(
            nonlinear
                .lowest_cost_projection()
                .partial_rounds_before_trail,
            None
        );
        assert!(
            nonlinear
                .lowest_cost_projection()
                .descriptive_quadratic_projection_bits()
                > result.descriptive_quadratic_projection_bits()
        );
    }

    #[test]
    fn unaudited_round_schedule_is_rejected() {
        let mut parameters = ProductionParameters::load().unwrap();
        parameters.poseidon_partial_rounds += 1;
        assert!(audit(&parameters).is_err());
    }

    #[test]
    fn exact_helpers_match_small_reference_values() {
        assert_eq!(binomial(&BigUint::from(10u32), 4), BigUint::from(210u32));
        assert_eq!(gcd_u128(7, u128::MAX), 1);
    }

    #[test]
    fn production_merkle_compression_is_the_appendix_a_feed_forward_map() {
        let tag = DomainTag::new(b"SC26AUD_");
        let left = [0x35u8; 32];
        let right = [0xA6u8; 32];
        let a0 = u128::from_le_bytes(left[..16].try_into().unwrap());
        let a1 = u128::from_le_bytes(left[16..].try_into().unwrap());
        let b0 = u128::from_le_bytes(right[..16].try_into().unwrap());
        let b1 = u128::from_le_bytes(right[16..].try_into().unwrap());
        let [iv0, iv1] = capacity_iv_flat(tag);
        let mut state = [a0, a1, b0 ^ iv0, b1 ^ iv1];
        permute_flat_u128(&mut state);

        let mut expected = [0u8; 32];
        expected[..16].copy_from_slice(&(state[0] ^ a0).to_le_bytes());
        expected[16..].copy_from_slice(&(state[1] ^ a1).to_le_bytes());

        assert_eq!(
            compress_flat_feed_forward_with_tag(tag, &left, &right),
            expected
        );
    }
}
