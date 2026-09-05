// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Executable soundness certificates for the production Parano1d protocol.

pub mod block_tiwari;
pub mod exact;
pub mod local;
pub mod parameters;
pub mod poseidon2b_cryptanalysis;
pub mod qrom;
pub mod resource;

use block_tiwari::BlockTiwariCertificate;
use parameters::ProductionParameters;
use poseidon2b_cryptanalysis::Poseidon2bCryptanalysisAudit;
use qrom::IdealQromCertificate;
use resource::CategoryOneCertificate;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoundnessCertificate {
    pub parameters: ProductionParameters,
    pub block_tiwari: BlockTiwariCertificate,
    pub poseidon2b_cryptanalysis: Poseidon2bCryptanalysisAudit,
    pub ideal_qrom: IdealQromCertificate,
    pub category_one: CategoryOneCertificate,
}

pub fn calculate() -> Result<SoundnessCertificate, String> {
    let parameters = ProductionParameters::load()?;
    let block_tiwari = block_tiwari::certificate(&parameters);
    let poseidon2b_cryptanalysis = poseidon2b_cryptanalysis::audit(&parameters)?;
    let ideal_qrom = qrom::certificate(&parameters);
    let category_one = resource::certificate(&parameters);
    Ok(SoundnessCertificate {
        parameters,
        block_tiwari,
        poseidon2b_cryptanalysis,
        ideal_qrom,
        category_one,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_certificate_is_reproducible() {
        assert_eq!(calculate().unwrap(), calculate().unwrap());
    }

    #[test]
    fn wallet_analysis_refinement_preserves_protocol_and_compiler_parameters() {
        let current = calculate().unwrap();
        // Reproduce the previously published numerical profile. Only the
        // analytical radius and field exception change, never the protocol.
        let mut previous_parameters = current.parameters.clone();
        previous_parameters.wallet_radius_numerator = 49;
        previous_parameters.wallet_radius_denominator = 64;
        previous_parameters.wallet_field_bad_numerator = 29_163_918_888;
        let previous_qrom = qrom::certificate(&previous_parameters);
        let previous_resource = resource::certificate(&previous_parameters);

        assert_eq!(current.parameters.wallet_queries, 65);
        assert_eq!(current.parameters.wallet_query_seed_lanes, 7);
        assert_eq!(current.parameters.history_queries, 133);
        assert!(current.ideal_qrom.wallet.local_rbr < previous_qrom.wallet.local_rbr);
        assert_eq!(current.ideal_qrom.local_rbr, previous_qrom.local_rbr);
        assert_eq!(
            current.ideal_qrom.largest_certified_integer_work,
            previous_qrom.largest_certified_integer_work
        );
        assert_eq!(current.ideal_qrom.at_two_to_64, previous_qrom.at_two_to_64);
        assert_eq!(
            current.block_tiwari,
            block_tiwari::certificate(&previous_parameters)
        );
        assert_eq!(previous_resource.limiting_event, "wallet.query");
        assert_eq!(current.category_one.limiting_event, "history.query");
        assert!(current.category_one.ideal_envelope < previous_resource.ideal_envelope);
        assert_eq!(
            current.category_one.typed_finite,
            previous_resource.typed_finite
        );
        assert_eq!(
            current.category_one.global_collision_term,
            previous_resource.global_collision_term
        );
        assert_eq!(
            current.category_one.poseidon_response_cost,
            previous_resource.poseidon_response_cost
        );
        assert_eq!(
            previous_resource.ideal_envelope.decimal_ceiling(18),
            "0.053364140323608411"
        );
        assert_eq!(
            current.category_one.ideal_envelope.decimal_ceiling(18),
            "0.049330348213215253"
        );
    }
}
