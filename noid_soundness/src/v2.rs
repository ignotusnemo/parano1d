// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Parameterized v2 inventory, including the legacy ancestry and sparse
//! retirement argument. The local reduction and composition premises are
//! documented in docs/v2-retirement.md; this is not a change to proof code.

use noid_ivc_core::matrix_claim::sparse_c1::SparseMatrixEvaluationKey;
use noid_recursive::acceptance::history_step::v2::banked::{Class, RuntimeParts};
use num_bigint::BigUint;

use crate::{
    exact::ExactProbability,
    local::{
        history_query_escape, initial_list_size_bound, maximum_layer_proximity,
        select_unweighted_history,
    },
    parameters::{history_class_parameters, HistoryClassParameters, ProductionParameters},
    qrom::{ideal_breakdown, maximum_query_cap_below_half},
    resource::{self, CategoryOneCertificate},
};

// A conservative fixed choice, not a claim of an optimal list multiplicity.
// Its exact proximity and algebraic terms are evaluated for every loaded key.
pub const RETIREMENT_MULTIPLICITY: u32 = 100_000;

#[derive(Clone, Debug)]
pub struct RetirementLocalCertificate {
    pub matrix_digest: [u8; 32],
    pub key_digest: [u8; 32],
    pub columns: Vec<HistoryClassParameters>,
    pub dynamic_commitments: usize,
    pub maximum_initial_list_size: BigUint,
    pub candidate_tuples: BigUint,
    pub memory_polynomial_roots: u64,
    pub query_escape: ExactProbability,
    pub maximum_proximity_exception: ExactProbability,
    pub pcs_scalar_exception: ExactProbability,
    pub reduction_exception: ExactProbability,
    pub local_rbr: ExactProbability,
    pub minimum_query_permutations: u32,
}

#[derive(Clone, Debug)]
pub struct V2Certificate {
    pub joint_classes: [HistoryClassParameters; 2],
    pub retirement: [RetirementLocalCertificate; 2],
    pub sequential_local_rbr: ExactProbability,
    pub sequential_largest_query_cap: BigUint,
    pub sequential_at_two_to_64: crate::qrom::IdealQromBreakdown,
    pub category_one: CategoryOneCertificate,
}

fn query_permutations(parameters: &ProductionParameters, class: &HistoryClassParameters) -> u32 {
    let per_lane = 128 / class.codeword_log2;
    let seed_lanes = (parameters.history_queries as usize).div_ceil(per_lane);
    seed_lanes.div_ceil(parameters.poseidon_rate_lanes) as u32
}

fn retirement_certificate(
    parameters: &ProductionParameters,
    key: &SparseMatrixEvaluationKey,
) -> Result<RetirementLocalCertificate, String> {
    let columns = key
        .opening_parameters()
        .enumerate()
        .map(|(column, pcs)| history_class_parameters(column, &pcs))
        .collect::<Result<Vec<_>, _>>()?;
    let dynamic_commitments = key.dynamic_commitment_count();
    if dynamic_commitments != 4
        || columns.len() != 11
        || columns
            .iter()
            .any(|column| column.inverse_rate != 4 || column.codeword_log2 > 32)
    {
        return Err(
            "sparse opening inventory differs from the audited four-column reduction".into(),
        );
    }
    let maximum_initial_list_size = columns
        .iter()
        .map(|column| initial_list_size_bound(column, RETIREMENT_MULTIPLICITY))
        .max()
        .ok_or("missing sparse columns")?;
    // Seven static columns are authenticated codewords fixed by the release
    // key. Only the four prover-selected initial words contribute alternatives.
    let candidate_tuples = maximum_initial_list_size.pow(dynamic_commitments as u32);
    let geometry = key.geometry();
    // Both memory checks use D <= padded_entries + row_addresses factors on
    // either side. Each fingerprint has total degree two. The extra factor
    // two conservatively unions row and column checks at the same challenge.
    let memory_polynomial_roots = u64::try_from(geometry.padded_entries)
        .ok()
        .and_then(|entries| entries.checked_add(geometry.row_addresses as u64))
        .and_then(|factors| factors.checked_mul(4))
        .ok_or("sparse memory degree overflow")?;
    let query_escape = history_query_escape(parameters.history_queries, RETIREMENT_MULTIPLICITY);
    let maximum_proximity_exception = columns
        .iter()
        .map(|column| {
            maximum_layer_proximity(
                parameters.challenge_min_entropy_bits,
                column,
                RETIREMENT_MULTIPLICITY,
            )
        })
        .max()
        .ok_or("missing sparse proximity instance")?;
    let pcs_scalar_exception = ExactProbability::dyadic(
        &maximum_initial_list_size * crate::local::HISTORY_MAX_ALGEBRAIC_ROOTS,
        parameters.challenge_min_entropy_bits,
    );
    let reduction_exception = ExactProbability::dyadic(
        &candidate_tuples * memory_polynomial_roots.max(3),
        parameters.challenge_min_entropy_bits,
    );
    let local_rbr = query_escape
        .clone()
        .max(maximum_proximity_exception.clone())
        .max(pcs_scalar_exception.clone())
        .max(reduction_exception.clone());
    // Use the cheapest actual column response, not the longest codeword's
    // larger squeeze cost. A failed opening need not be in the largest column.
    let minimum_query_permutations = columns
        .iter()
        .map(|column| query_permutations(parameters, column))
        .min()
        .ok_or("missing sparse query response")?;
    Ok(RetirementLocalCertificate {
        matrix_digest: key.matrix_digest(),
        key_digest: key.digest(),
        columns,
        dynamic_commitments,
        maximum_initial_list_size,
        candidate_tuples,
        memory_polynomial_roots,
        query_escape,
        maximum_proximity_exception,
        pcs_scalar_exception,
        reduction_exception,
        local_rbr,
        minimum_query_permutations,
    })
}

/// Local inventory for a release-authenticated sparse key at a later handoff.
/// Its columns and memory degrees come from the key's actual geometry.
pub fn calculate_retirement_key(
    key: &SparseMatrixEvaluationKey,
) -> Result<RetirementLocalCertificate, String> {
    retirement_certificate(&ProductionParameters::load()?, key)
}

/// The caller authenticates the bank and both preprocessing keys against
/// independently supplied release pins before calling this read-only audit.
pub fn calculate(
    parts: &RuntimeParts,
    keys: &[SparseMatrixEvaluationKey; 2],
) -> Result<V2Certificate, String> {
    let legacy = ProductionParameters::load()?;
    let mut joint_profile = legacy.clone();
    joint_profile.history_classes = [Class::Small, Class::Large]
        .map(|class| {
            let config = parts.config().class(class);
            history_class_parameters(config.pages(), &config.pcs_params())
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "joint class count")?;
    if joint_profile
        .history_classes
        .iter()
        .any(|class| class.inverse_rate != 4)
    {
        return Err("v2 PCS inverse rate changed".into());
    }
    let legacy_category = resource::certificate(&legacy);
    let joint_category = resource::certificate(&joint_profile);
    let retirement = [
        retirement_certificate(&legacy, &keys[0])?,
        retirement_certificate(&legacy, &keys[1])?,
    ];
    let mut events = legacy_category.events.clone();
    for mut event in joint_category.events {
        event.id = match event.id {
            "wallet.query" | "wallet.field" => continue,
            "history.query" => "v2.query",
            "history.b25.proximity" => "v2.small.proximity",
            "history.b255.proximity" => "v2.large.proximity",
            "history.candidate-switching" => "v2.candidate-switching",
            "history.joint-sidecar" => "v2.joint-sidecar",
            _ => return Err("unaccounted joint resource event".into()),
        };
        events.push(event);
    }
    let scalar = legacy_category.poseidon_response_cost.clone();
    for (index, proof) in retirement.iter().enumerate() {
        let names = if index == 0 {
            [
                "retirement.b25.query",
                "retirement.b25.proximity",
                "retirement.b25.pcs-scalar",
                "retirement.b25.reduction",
            ]
        } else {
            [
                "retirement.b255.query",
                "retirement.b255.proximity",
                "retirement.b255.pcs-scalar",
                "retirement.b255.reduction",
            ]
        };
        let densities = [
            &proof.query_escape,
            &proof.maximum_proximity_exception,
            &proof.pcs_scalar_exception,
            &proof.reduction_exception,
        ];
        for (kind, density) in densities.into_iter().enumerate() {
            let cost = if kind == 0 {
                scalar.sequential_permutations(proof.minimum_query_permutations)
            } else {
                scalar.clone()
            };
            events.push(resource::resource_event(names[kind], density.clone(), cost));
        }
    }
    let category_one = resource::compose_events(
        &legacy,
        legacy_category.wallet,
        legacy_category.history,
        events,
    );
    let mut sequential_local_rbr = crate::local::wallet_local_certificate(&legacy)
        .local_rbr
        .max(select_unweighted_history(&legacy).certificate.local_rbr)
        .max(
            select_unweighted_history(&joint_profile)
                .certificate
                .local_rbr,
        );
    for proof in &retirement {
        sequential_local_rbr = sequential_local_rbr.max(proof.local_rbr.clone());
    }
    let sequential_largest_query_cap = maximum_query_cap_below_half(
        legacy.challenge_min_entropy_bits,
        legacy.digest_bits,
        &sequential_local_rbr,
    );
    let sequential_at_two_to_64 = ideal_breakdown(
        BigUint::from(1u32) << 64usize,
        legacy.challenge_min_entropy_bits,
        legacy.digest_bits,
        &sequential_local_rbr,
    );
    Ok(V2Certificate {
        joint_classes: joint_profile.history_classes,
        retirement,
        sequential_local_rbr,
        sequential_largest_query_cap,
        sequential_at_two_to_64,
        category_one,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adding_a_larger_failure_density_cannot_improve_the_bound() {
        let parameters = ProductionParameters::load().unwrap();
        let old = resource::certificate(&parameters);
        let mut events = old.events.clone();
        let worst = &events[0];
        let mut added = worst.clone();
        added.id = "test.additional";
        added.bad_density = added.bad_density.scale_integer(2u32);
        added.bad_density_per_gate_depth = added.bad_density_per_gate_depth.scale_integer(2u32);
        events.push(added);
        let new = resource::compose_events(&parameters, old.wallet, old.history, events);
        assert_eq!(new.limiting_event, "test.additional");
        assert_eq!(
            new.maximum_bad_density_per_gate_depth,
            old.maximum_bad_density_per_gate_depth.scale_integer(2u32)
        );
        assert!(new.ideal_envelope > old.ideal_envelope);
    }
}
