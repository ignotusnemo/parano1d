// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact local generalized round-by-round soundness terms.

use noid_poseidon2b::native::permutation::STATE_SIZE;
use noid_recursive::region_sidecar::JOINT_C1_GROUPS;
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::{
    exact::ExactProbability,
    parameters::{HistoryClassParameters, ProductionParameters},
};

/// Largest degree in the current History algebraic identity inventory.
pub const HISTORY_MAX_ALGEBRAIC_ROOTS: u32 = (1u32 << (noid_ivc_core::zerocheck::K_SKIP + 1)) - 1;
/// Joint sidecar groups, each occupying one alpha power per Poseidon state lane.
pub const HISTORY_JOINT_SIDECAR_ROOTS: u32 = (JOINT_C1_GROUPS * STATE_SIZE) as u32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletLocalCertificate {
    pub query_escape: ExactProbability,
    pub field_exception: ExactProbability,
    pub local_rbr: ExactProbability,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryClassCertificate {
    pub tier: usize,
    pub proximity_exception: ExactProbability,
    pub initial_list_size_bound: BigUint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryLocalCertificate {
    pub multiplicity: u32,
    pub query_escape: ExactProbability,
    pub classes: [HistoryClassCertificate; 2],
    pub maximum_proximity_exception: ExactProbability,
    pub maximum_initial_list_size_bound: BigUint,
    pub candidate_switching_exception: ExactProbability,
    pub joint_sidecar_exception: ExactProbability,
    pub local_rbr: ExactProbability,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistorySelection {
    pub certificate: HistoryLocalCertificate,
    /// The selected objective with the common Poseidon response cost removed.
    pub normalized_objective: ExactProbability,
}

pub fn wallet_local_certificate(parameters: &ProductionParameters) -> WalletLocalCertificate {
    let miss_numerator = parameters.wallet_radius_denominator - parameters.wallet_radius_numerator;
    let query_escape = ExactProbability::new(miss_numerator, parameters.wallet_radius_denominator)
        .pow(parameters.wallet_queries);
    let field_exception = ExactProbability::dyadic(
        parameters.wallet_field_bad_numerator,
        parameters.challenge_min_entropy_bits,
    );
    let local_rbr = query_escape.clone().max(field_exception.clone());
    WalletLocalCertificate {
        query_escape,
        field_exception,
        local_rbr,
    }
}

pub fn history_query_escape(queries: u32, multiplicity: u32) -> ExactProbability {
    assert!(multiplicity >= 3);
    ExactProbability::new(multiplicity + 1, 2 * multiplicity).pow(queries)
}

fn reciprocal(value: &ExactProbability) -> ExactProbability {
    assert!(!value.numerator().is_zero());
    ExactProbability::new(value.denominator().clone(), value.numerator().clone())
}

/// BCHKS Theorem 4.6 integer envelope at one rate-one-quarter RS layer.
fn history_proximity_at_domain(
    challenge_bits: u32,
    domain: u64,
    multiplicity: u32,
) -> ExactProbability {
    assert!(domain > 4);
    let h = ExactProbability::new(2 * multiplicity + 1, 2u32);
    let gamma = ExactProbability::new(multiplicity - 1, 2 * multiplicity);
    let sqrt_rho_lower = ExactProbability::new(domain - 4, 2 * domain);
    let curve_numerator = h.pow(5).scale_integer(2u32).add(
        &h.multiply(&gamma)
            .multiply(&sqrt_rho_lower.pow(2))
            .scale_integer(3u32),
    );
    let curve_denominator = sqrt_rho_lower.pow(3).scale_integer(3u32);
    let exceptional_upper = curve_numerator
        .multiply(&reciprocal(&curve_denominator))
        .scale_integer(domain)
        .add(&h.multiply(&reciprocal(&sqrt_rho_lower)));
    // The exceptional set has integral cardinality and is at most the real
    // BCHKS expression, so its cardinality is at most the floor.
    let exceptional_integer = exceptional_upper.numerator() / exceptional_upper.denominator();
    ExactProbability::dyadic(exceptional_integer, challenge_bits)
}

fn maximum_layer_proximity(
    challenge_bits: u32,
    class: &HistoryClassParameters,
    multiplicity: u32,
) -> ExactProbability {
    assert!(class.plaintext_tail_len.is_power_of_two());
    assert!(class.codeword_len.is_power_of_two());
    let mut domain = class.plaintext_tail_len;
    let mut maximum = ExactProbability::zero();
    loop {
        maximum = maximum.max(history_proximity_at_domain(
            challenge_bits,
            domain,
            multiplicity,
        ));
        if domain == class.codeword_len {
            return maximum;
        }
        domain = domain
            .checked_mul(2)
            .expect("History layer domain must fit u64");
        assert!(domain <= class.codeword_len);
    }
}

/// Integer list bound `ceil((m+1/2)/s_N)-1`, where
/// `s_N=1/2-2/N<sqrt((N/4-1)/N)`.
fn initial_list_size_bound(class: &HistoryClassParameters, multiplicity: u32) -> BigUint {
    let numerator = BigUint::from(2 * multiplicity + 1) * class.codeword_len;
    let denominator = BigUint::from(class.codeword_len - 4);
    assert!(!denominator.is_zero());
    // Largest integer strictly below the rational upper envelope.
    (&numerator - BigUint::one()) / denominator
}

pub fn history_local_certificate(
    parameters: &ProductionParameters,
    multiplicity: u32,
) -> HistoryLocalCertificate {
    assert!(multiplicity >= 3);
    let query_escape = history_query_escape(parameters.history_queries, multiplicity);
    let class_certificate = |class: &HistoryClassParameters| HistoryClassCertificate {
        tier: class.tier,
        proximity_exception: maximum_layer_proximity(
            parameters.challenge_min_entropy_bits,
            class,
            multiplicity,
        ),
        initial_list_size_bound: initial_list_size_bound(class, multiplicity),
    };
    let classes = [
        class_certificate(&parameters.history_classes[0]),
        class_certificate(&parameters.history_classes[1]),
    ];
    let maximum_proximity_exception = classes[0]
        .proximity_exception
        .clone()
        .max(classes[1].proximity_exception.clone());
    let maximum_initial_list_size_bound = classes[0]
        .initial_list_size_bound
        .clone()
        .max(classes[1].initial_list_size_bound.clone());
    let candidate_switching_exception = ExactProbability::dyadic(
        &maximum_initial_list_size_bound * HISTORY_MAX_ALGEBRAIC_ROOTS,
        parameters.challenge_min_entropy_bits,
    );
    let joint_sidecar_exception = ExactProbability::dyadic(
        &maximum_initial_list_size_bound * HISTORY_JOINT_SIDECAR_ROOTS,
        parameters.challenge_min_entropy_bits,
    );
    let local_rbr = [
        query_escape.clone(),
        maximum_proximity_exception.clone(),
        candidate_switching_exception.clone(),
        joint_sidecar_exception.clone(),
    ]
    .into_iter()
    .max()
    .expect("History has local soundness terms");
    HistoryLocalCertificate {
        multiplicity,
        query_escape,
        classes,
        maximum_proximity_exception,
        maximum_initial_list_size_bound,
        candidate_switching_exception,
        joint_sidecar_exception,
        local_rbr,
    }
}

fn increasing_history_terms(certificate: &HistoryLocalCertificate) -> ExactProbability {
    [
        certificate.maximum_proximity_exception.clone(),
        certificate.candidate_switching_exception.clone(),
        certificate.joint_sidecar_exception.clone(),
    ]
    .into_iter()
    .max()
    .expect("History has increasing finite terms")
}

fn first_increasing_term_crossing(
    parameters: &ProductionParameters,
    query_response_product_factor: u32,
) -> u32 {
    let crossed = |multiplicity: u32| {
        let certificate = history_local_certificate(parameters, multiplicity);
        increasing_history_terms(&certificate)
            >= certificate
                .query_escape
                .divide_integer(query_response_product_factor)
    };
    if crossed(3) {
        return 3;
    }
    let mut low = 3u32;
    let mut high = 4u32;
    while !crossed(high) {
        low = high;
        high = high
            .checked_mul(2)
            .expect("History multiplicity search exceeds u32");
    }
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if crossed(middle) {
            high = middle;
        } else {
            low = middle;
        }
    }
    high
}

fn select_with_query_response_factor(
    parameters: &ProductionParameters,
    query_response_product_factor: u32,
) -> HistorySelection {
    assert!(query_response_product_factor > 0);
    let crossing = first_increasing_term_crossing(parameters, query_response_product_factor);
    let previous = crossing.saturating_sub(1).max(3);
    [previous, crossing]
        .into_iter()
        .map(|multiplicity| {
            let certificate = history_local_certificate(parameters, multiplicity);
            let normalized_objective = certificate
                .query_escape
                .divide_integer(query_response_product_factor)
                .max(increasing_history_terms(&certificate));
            HistorySelection {
                certificate,
                normalized_objective,
            }
        })
        .min_by(|left, right| {
            left.normalized_objective
                .cmp(&right.normalized_objective)
                .then_with(|| {
                    left.certificate
                        .multiplicity
                        .cmp(&right.certificate.multiplicity)
                })
        })
        .expect("History candidate window is nonempty")
}

/// Best local theorem without response-cost weighting.
pub fn select_unweighted_history(parameters: &ProductionParameters) -> HistorySelection {
    select_with_query_response_factor(parameters, 1)
}

/// Best History event for a query response made from `s` sequential
/// permutations versus one permutation for a scalar challenge. Gate count and
/// depth both scale by `s`, hence the `s^2` product factor.
pub fn select_resource_history(
    parameters: &ProductionParameters,
    query_squeeze_permutations: u32,
) -> HistorySelection {
    select_with_query_response_factor(
        parameters,
        query_squeeze_permutations
            .checked_pow(2)
            .expect("query response product factor fits u32"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_terms_are_imported_exactly() {
        let parameters = ProductionParameters::load().unwrap();
        let certificate = wallet_local_certificate(&parameters);
        assert_eq!(
            certificate.query_escape,
            ExactProbability::new(1u32, 5u32).pow(65)
        );
        assert_eq!(
            certificate.field_exception,
            ExactProbability::dyadic(701_202_001_931u64, 255)
        );
        assert_eq!(certificate.local_rbr, certificate.query_escape);
    }

    #[test]
    fn history_certificate_covers_b25_and_b255() {
        let parameters = ProductionParameters::load().unwrap();
        let certificate = history_local_certificate(&parameters, 5);
        assert_eq!(
            [certificate.classes[0].tier, certificate.classes[1].tier],
            [25, 255]
        );
        assert!(
            certificate.classes[1].proximity_exception > certificate.classes[0].proximity_exception
        );
        assert_eq!(
            certificate.maximum_initial_list_size_bound,
            BigUint::from(11u32)
        );
    }

    #[test]
    fn algebraic_root_bounds_follow_production_shapes() {
        assert_eq!(HISTORY_MAX_ALGEBRAIC_ROOTS, 127);
        assert_eq!(HISTORY_JOINT_SIDECAR_ROOTS, 36);
    }

    #[test]
    fn exact_optimizers_include_the_larger_history_class() {
        let parameters = ProductionParameters::load().unwrap();
        let unweighted = select_unweighted_history(&parameters);
        let resource = select_resource_history(&parameters, 12);
        assert_eq!(unweighted.certificate.multiplicity, 861_824);
        assert_eq!(resource.certificate.multiplicity, 318_983);
        assert_eq!(
            unweighted.certificate.local_rbr,
            unweighted.certificate.query_escape
        );
    }
}
