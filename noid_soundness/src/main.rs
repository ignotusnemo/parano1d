// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use noid_soundness::calculate;

fn main() -> Result<(), String> {
    let mut exact = false;
    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--exact" => exact = true,
            "-h" | "--help" => {
                println!("Usage: noid_soundness [--exact]");
                println!("  --exact  print the reduced rational certificates");
                return Ok(());
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }

    let certificate = calculate()?;
    let parameters = &certificate.parameters;
    let block_tiwari = &certificate.block_tiwari;
    let poseidon2b_cryptanalysis = &certificate.poseidon2b_cryptanalysis;
    let ideal = &certificate.ideal_qrom;
    let category_one = &certificate.category_one;

    println!("PARANO1D SOUNDNESS CERTIFICATE");
    println!("production parameter correspondence: PASS");
    println!(
        "profile: W{}/H{}, challenge support=2^{}, digest={} bits",
        parameters.wallet_queries,
        parameters.history_queries,
        parameters.challenge_min_entropy_bits,
        parameters.digest_bits
    );
    println!(
        "History classes: B{} N=2^{}, B{} N=2^{}\n",
        parameters.history_classes[0].tier,
        parameters.history_classes[0].codeword_log2,
        parameters.history_classes[1].tier,
        parameters.history_classes[1].codeword_log2,
    );

    println!("WALLET LOCAL ANALYSIS, UNCHANGED PROTOCOL");
    println!(
        "analysis radius: {}/{}; query count remains {}",
        parameters.wallet_radius_numerator,
        parameters.wallet_radius_denominator,
        parameters.wallet_queries,
    );
    println!(
        "local query density: ({}/{})^{}",
        parameters.wallet_radius_denominator - parameters.wallet_radius_numerator,
        parameters.wallet_radius_denominator,
        parameters.wallet_queries,
    );
    println!(
        "local field density: {}/2^{}\n",
        parameters.wallet_field_bad_numerator, parameters.challenge_min_entropy_bits,
    );

    println!("BLOCK AND TIWARI FS-FRI, CLASSICAL ROM");
    println!("Target FRI security      {}", block_tiwari.target_fri_bits);
    println!(
        "Provable FS-FRI security {}",
        block_tiwari.provable.displayed_whole_bits()
    );
    println!(
        "Conjectured FS-FRI security {}",
        block_tiwari.conjectured.displayed_whole_bits()
    );
    println!(
        "provable RBR multiplicity: {}",
        block_tiwari.provable_history.certificate.multiplicity
    );
    if exact {
        println!(
            "provable minimizing queries: {}",
            block_tiwari.provable.minimizing_queries
        );
        println!(
            "provable first capped queries: {}",
            block_tiwari.provable.first_capped_queries
        );
        println!(
            "provable RBR exact: {}",
            block_tiwari.provable_rbr.exact_fraction()
        );
        println!(
            "provable minimum expected work exact: {}",
            block_tiwari.provable.exact_minimum_expected_work()
        );
    }
    println!(
        "provable descriptive log2(work): {:.12}",
        block_tiwari.provable.descriptive_bits()
    );
    if exact {
        println!(
            "conjectured RBR exact: {}",
            block_tiwari.conjectured_rbr.exact_fraction()
        );
        println!(
            "conjectured minimizing queries: {}",
            block_tiwari.conjectured.minimizing_queries
        );
        println!(
            "conjectured first capped queries: {}",
            block_tiwari.conjectured.first_capped_queries
        );
        println!(
            "conjectured minimum expected work exact: {}",
            block_tiwari.conjectured.exact_minimum_expected_work()
        );
    }
    println!(
        "conjectured descriptive log2(work): {:.12}\n",
        block_tiwari.conjectured.descriptive_bits()
    );

    println!("POSEIDON2B PUBLISHED CLASSICAL CRYPTANALYSIS");
    println!("source: https://eprint.iacr.org/2026/306");
    if exact {
        println!(
            "reviewed PDF: version={} sha256={}",
            noid_soundness::poseidon2b_cryptanalysis::SKIPPING_CLASS_REVIEWED_VERSION,
            noid_soundness::poseidon2b_cryptanalysis::SKIPPING_CLASS_PDF_SHA256
        );
    }
    println!(
        "production tuple: GF(2^{}), t={}, rate={}, capacity={}, digest={} lanes, x^{}, RF={}, RP={}",
        poseidon2b_cryptanalysis.field_bits,
        poseidon2b_cryptanalysis.state_width,
        poseidon2b_cryptanalysis.rate_lanes,
        poseidon2b_cryptanalysis.capacity_lanes,
        poseidon2b_cryptanalysis.digest_lanes,
        poseidon2b_cryptanalysis.sbox_exponent,
        poseidon2b_cryptanalysis.full_rounds,
        poseidon2b_cryptanalysis.partial_rounds,
    );
    println!(
        "ePrint 2026/306 wide tensor scope: t in {{12,16,20,24}}; production t={} {} scope",
        poseidon2b_cryptanalysis.state_width,
        if poseidon2b_cryptanalysis.wide_tensor_round_skips_apply {
            "inside"
        } else {
            "outside"
        }
    );
    println!(
        "Appendix A MDS two-to-one compression model: {}",
        if poseidon2b_cryptanalysis.appendix_a_compression_applies {
            "applicable"
        } else {
            "not applicable"
        }
    );
    println!(
        "round skip: ({}, [1, {}])",
        poseidon2b_cryptanalysis.skipped_full_rounds, poseidon2b_cryptanalysis.sbox_exponent
    );
    println!(
        "ideal-degree upper bound: {}^{}",
        poseidon2b_cryptanalysis.ideal_degree_base, poseidon2b_cryptanalysis.ideal_degree_exponent
    );
    println!(
        "descriptive log2(d_I): {:.12}",
        poseidon2b_cryptanalysis.descriptive_ideal_degree_bits()
    );
    println!(
        "descriptive log2(d_I^2) dedicated algebraic projection: {:.12}",
        poseidon2b_cryptanalysis.descriptive_quadratic_projection_bits()
    );
    if exact {
        println!(
            "ideal-degree upper bound exact: {}",
            poseidon2b_cryptanalysis.ideal_degree_upper_bound
        );
        println!(
            "quadratic dedicated algebraic projection exact: {}",
            poseidon2b_cryptanalysis.quadratic_work_projection
        );
    }
    println!("scope: classical dedicated-attack projection from an ideal-degree upper bound\n");

    let nonlinear = &poseidon2b_cryptanalysis.nonlinear_subspaces;
    println!("POSEIDON2B NONLINEAR SUBSPACE REVIEW");
    println!("source: https://eprint.iacr.org/2026/1792");
    if exact {
        println!(
            "reviewed PDF: version={} sha256={}",
            noid_soundness::poseidon2b_cryptanalysis::NONLINEAR_SUBSPACES_REVIEWED_VERSION,
            noid_soundness::poseidon2b_cryptanalysis::NONLINEAR_SUBSPACES_PDF_SHA256
        );
    }
    println!(
        "compression constraint budget: E_c={} with s={} active S-box per partial round",
        nonlinear.extra_constraint_budget, nonlinear.partial_sboxes_per_round
    );
    println!(
        "partial-round trails: linear={} nonlinear={} of production RP={}",
        nonlinear.linear_trail_rounds,
        nonlinear.nonlinear_trail_rounds,
        poseidon2b_cryptanalysis.partial_rounds
    );
    println!(
        "production even-construction rank core: 0x{:032x} nonzero",
        nonlinear.even_balancing_core
    );
    for projection in &nonlinear.projections {
        let placement = projection
            .partial_rounds_before_trail
            .map_or_else(|| "direct".to_string(), |tau| format!("tau={tau}"));
        println!(
            "{} ({placement}, variables={}): log2(C_Macaulay^2)={:.12}",
            projection.model,
            projection.variables,
            projection.descriptive_quadratic_projection_bits()
        );
        if exact {
            println!(
                "  Macaulay matrix dimension exact: {}",
                projection.macaulay_matrix_dimension
            );
            println!(
                "  quadratic projection exact: {}",
                projection.quadratic_work_projection
            );
        }
    }
    println!(
        "lowest-cost ePrint 2026/1792 production projection: {} at {:.12} bits",
        nonlinear.lowest_cost_projection().model,
        nonlinear
            .lowest_cost_projection()
            .descriptive_quadratic_projection_bits()
    );
    println!(
        "scope: omega=2 semi-regular Macaulay attack-cost projection; the ePrint 2026/306 feed-forward projection remains stronger\n"
    );

    println!("END TO END IDEAL QROM, FROM GENESIS INVALID STATE GAME");
    println!(
        "optimal local History multiplicity: {}",
        ideal.history.certificate.multiplicity
    );
    if exact {
        println!("local RBR exact: {}", ideal.local_rbr.exact_fraction());
        println!(
            "History query escape exact: {}",
            ideal.history.certificate.query_escape.exact_fraction()
        );
        println!(
            "History maximum proximity exact: {}",
            ideal
                .history
                .certificate
                .maximum_proximity_exception
                .exact_fraction()
        );
        println!(
            "History candidate switching exact: {}",
            ideal
                .history
                .certificate
                .candidate_switching_exception
                .exact_fraction()
        );
        println!(
            "History joint sidecar exact: {}",
            ideal
                .history
                .certificate
                .joint_sidecar_exception
                .exact_fraction()
        );
    }
    println!(
        "largest certified integer query work: {}",
        ideal.largest_certified_integer_work
    );
    println!(
        "first uncovered integer query work: {}",
        ideal.first_uncovered_integer_work
    );
    println!(
        "descriptive boundary bits: {:.12}",
        ideal.descriptive_boundary_bits()
    );
    println!(
        "epsilon_ideal(2^64) <= {}",
        ideal.at_two_to_64.total.decimal_ceiling(18)
    );
    println!(
        "sufficient fixed Poseidon2b condition at 2^64: Delta < {}\n",
        ideal.half_success_headroom_at_two_to_64.decimal_prefix(18)
    );
    if exact {
        println!(
            "epsilon RBR term at 2^64 exact: {}",
            ideal.at_two_to_64.transcript_rbr_term.exact_fraction()
        );
        println!(
            "epsilon finite term at 2^64 exact: {}",
            ideal.at_two_to_64.transcript_finite_term.exact_fraction()
        );
        println!(
            "epsilon binding term at 2^64 exact: {}",
            ideal.at_two_to_64.binding_collision_term.exact_fraction()
        );
        println!(
            "epsilon total at 2^64 exact: {}",
            ideal.at_two_to_64.total.exact_fraction()
        );
        println!(
            "fixed Poseidon2b headroom at 2^64 exact: {}\n",
            ideal.half_success_headroom_at_two_to_64.exact_fraction()
        );
    }

    println!("NIST POST-QUANTUM CRYPTOGRAPHY CATEGORY 1 RESOURCE ASSESSMENT");
    println!("security game: invalid terminal State accepted from genesis");
    println!("limiting typed event: {}", category_one.limiting_event);
    println!(
        "resource-aware History multiplicity: {}",
        category_one.history.certificate.multiplicity
    );
    println!(
        "coherent Poseidon2b response: gates={} depth={} gate-depth={}",
        category_one.poseidon_response_cost.logical_gates,
        category_one.poseidon_response_cost.logical_depth,
        category_one.poseidon_response_cost.gate_depth_product()
    );
    if exact {
        println!(
            "dominant-term half-success gate-depth floor exact: {}",
            category_one
                .dominant_half_success_gate_depth_floor
                .exact_fraction()
        );
        for event in &category_one.events {
            println!(
                "event {}: bad-density={} response-gd={} density-per-gd={}",
                event.id,
                event.bad_density.exact_fraction(),
                event.response_cost.gate_depth_product(),
                event.bad_density_per_gate_depth.exact_fraction()
            );
        }
    }
    println!(
        "dominant-term descriptive gate-depth bits: {:.12}",
        category_one
            .dominant_half_success_gate_depth_floor
            .descriptive_bits()
    );
    println!(
        "dominant-term margin over 2^170: {:.12} bits",
        category_one
            .dominant_half_success_gate_depth_floor
            .descriptive_bits()
            - 170.0
    );
    println!(
        "evaluated NIST MAXDEPTH points: 2^{}, 2^{}, 2^{}",
        category_one.evaluated_max_depth_bits[0],
        category_one.evaluated_max_depth_bits[1],
        category_one.evaluated_max_depth_bits[2]
    );
    println!(
        "largest finite envelope occurs at MAXDEPTH=2^{}",
        category_one.worst_case_max_depth_bits
    );
    println!(
        "ideal main term at the Category 1 envelope <= {}",
        category_one.category_one_main_term.decimal_ceiling(18)
    );
    if exact {
        println!(
            "ideal main term exact: {}",
            category_one.category_one_main_term.exact_fraction()
        );
    }
    println!(
        "typed finite term at the Category 1 envelope <= {}",
        category_one.typed_finite.total.decimal_ceiling(18)
    );
    if exact {
        println!(
            "typed database query cap: {}",
            category_one.typed_finite.database_query_cap
        );
        println!(
            "typed extraction instability exact: {}",
            category_one
                .typed_finite
                .extraction_instability
                .exact_fraction()
        );
        println!(
            "typed transcript collision instability exact: {}",
            category_one
                .typed_finite
                .transcript_collision_instability
                .exact_fraction()
        );
        println!(
            "typed finite term exact: {}",
            category_one.typed_finite.total.exact_fraction()
        );
    }
    println!(
        "global collision upper bound <= {}",
        category_one.global_collision_term.decimal_ceiling(18)
    );
    if exact {
        println!(
            "global collision exact: {}",
            category_one.global_collision_term.exact_fraction()
        );
    }
    println!(
        "complete ideal envelope <= {}",
        category_one.ideal_envelope.decimal_ceiling(18)
    );
    if exact {
        println!(
            "complete ideal envelope exact: {}",
            category_one.ideal_envelope.exact_fraction()
        );
    }
    println!(
        "sufficient fixed Poseidon2b delta bound: Delta < {}",
        category_one
            .fixed_poseidon2b_delta_headroom
            .decimal_prefix(18)
    );
    if exact {
        println!(
            "fixed Poseidon2b delta headroom exact: {}",
            category_one
                .fixed_poseidon2b_delta_headroom
                .exact_fraction()
        );
    }
    println!(
        "assessment: PASS under the typed parallel-QROM, coherent response-cost, and fixed-Poseidon2b delta premises"
    );

    Ok(())
}
