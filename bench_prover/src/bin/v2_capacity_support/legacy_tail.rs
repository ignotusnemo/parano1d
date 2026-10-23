//! Measure the carried-matrix mechanism with real legacy proofs. This is a
//! control experiment, not a two-class v2 implementation or capacity result.
use super::*;

pub fn measure(args: &[String], verify_only: bool) -> Result<()> {
    if args.len() != 5 || noid_chain::consensus::params::V1_1_ACTIVATION_HEIGHT != Some(5) {
        return Err("usage: noid_v2_capacity legacy-tail[-verify] PACK PIN LEGACY_FIXTURES TAIL_OUTPUT COUNT (isolated-v1-1-testnet required)".into());
    }
    let pin = hex::decode(&args[1])
        .map_err(err)?
        .try_into()
        .map_err(|_| "pin length")?;
    let count: usize = args[4].parse().map_err(err)?;
    if !(1..=20).contains(&count) {
        return Err("count must be 1..=20".into());
    }
    let output = PathBuf::from(&args[3]);
    if !verify_only {
        std::fs::create_dir(&output).map_err(err)?;
    }
    let factory = proof::legacy_runtime_factory(Path::new(&args[0]), pin)?;
    let runtime = factory.runtime()?;
    // Reuse only the pre-H10 fixture loader. Every generated block below uses
    // ACTIVE_SCHEDULE, which has v1.1 at H5 and no v2 activation.
    let config = v2::V2Config::new(
        23,
        112,
        ForkSchedule::new(
            Some(5),
            noid_chain::consensus::forks::V2Activation::new(10, 30),
        )
        .unwrap(),
    )
    .map_err(err)?;
    let settings = Settings {
        pack: PathBuf::from(&args[0]),
        pin,
        fixtures: PathBuf::from(&args[2]),
        output: output.clone(),
        config,
        samples: count,
        freeze_only: false,
        transition_only: false,
        payments_only: false,
    };
    let start = Instant::now();
    let (mut chain, mut previous) = Chain::load(&settings, &runtime)?;
    let parent_class = previous.class_id().index();
    let receiver = factory.runtime()?;
    println!(
        "{}",
        json!({"phase":"legacy_tail_setup", "parent_class":parent_class,
        "setup_ms":elapsed(start),"rayon_threads":rayon::current_num_threads(),
        "cpu_backend":noid_core::cpu::selected_backend().to_string(),"memory":memory()})
    );
    let ghost = if verify_only {
        None
    } else {
        Some(
            noid_recursive::prepare_history_step_ghost_authorization_for_version(
                noid_gkr::ghost_tx::prove_selected_ghost_authorization_for_version(
                    noid_tx::OwnerAuthorizationVersion::V3,
                )
                .map_err(err)?,
                noid_tx::OwnerAuthorizationVersion::V3,
            )
            .map_err(err)?,
        )
    };
    let schedule = noid_chain::consensus::forks::ACTIVE_SCHEDULE;
    for index in 0..count {
        let height = chain.parent().height + 1;
        let (block, bytes) = if verify_only {
            (
                Block::from_bytes(&proof::bounded(
                    &output.join(format!("h{height:06}.block")),
                    16 * 1024 * 1024,
                )?)
                .map_err(err)?,
                proof::bounded(
                    &output.join(format!("h{height:06}.terminal")),
                    legacy::history_step_terminal_max_wire_bytes(&runtime).map_err(err)?,
                )?,
            )
        } else {
            let (mut block, construction_state) = chain.build(&[], schedule)?;
            drop(construction_state);
            let start = Instant::now();
            let input = chain.legacy_empty_input(block.clone(), ghost.as_ref().unwrap())?;
            let input_ms = elapsed(start);
            let start = Instant::now();
            let prepared = legacy::prepare_history_step_for_pow(&runtime, Some(&previous), input)
                .map_err(err)?;
            let assembly_ms = elapsed(start);
            block.header.nonce = mine(&block.header);
            let built = prepared
                .seal_nonce(&runtime, block.header.nonce)
                .map_err(err)?;
            let start = Instant::now();
            let terminal =
                legacy::prove_built_history_step_terminal(&runtime, &built).map_err(err)?;
            let prove_ms = elapsed(start);
            drop(built);
            let bytes = legacy::encode_history_step_terminal(&runtime, &terminal).map_err(err)?;
            std::fs::write(output.join(format!("h{height:06}.block")), block.to_bytes())
                .map_err(err)?;
            std::fs::write(output.join(format!("h{height:06}.terminal")), &bytes).map_err(err)?;
            println!(
                "{}",
                json!({"phase":"legacy_tail_prove","height":height,"parent_class":previous.class_id().index(),
                "input_ms":input_ms,"assembly_ms":assembly_ms,"prove_ms":prove_ms,"terminal_bytes":bytes.len(),"memory":memory()})
            );
            (block, bytes)
        };
        chain.check_native(&block, schedule)?;
        let terminal = legacy::decode_history_step_terminal(&runtime, &bytes).map_err(err)?;
        let start = Instant::now();
        let accepted = legacy::verify_history_step_terminal(
            &receiver,
            &terminal,
            &block.header,
            &chain.epoch(),
        )
        .map_err(err)?;
        let first_verify_ms = elapsed(start);
        let end = chain
            .accumulator
            .advance(chain.parent(), &block.header)
            .map_err(err)?;
        if accepted.accumulator() != &end {
            return Err("tail boundary mismatch".into());
        }
        println!(
            "{}",
            json!({"phase":"legacy_tail_first_verify","height":height,"first_after_restart":index==0,
            "verify_ms":first_verify_ms,"terminal_bytes":bytes.len(),"memory":memory()})
        );
        for sample in 0..3 {
            // A fresh runtime has an empty checked-claim cache. Both runtimes
            // share the same authenticated matrices; neither reload is timed.
            let cold_claims = factory.runtime()?;
            let order = if sample % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            };
            for cached in order {
                let verifier = if cached { &receiver } else { &cold_claims };
                let start = Instant::now();
                let decoded =
                    legacy::decode_history_step_terminal(verifier, &bytes).map_err(err)?;
                let checked = legacy::verify_history_step_terminal(
                    verifier,
                    &decoded,
                    &block.header,
                    &chain.epoch(),
                )
                .map_err(err)?;
                if checked.accumulator() != &end {
                    return Err("tail A/B boundary mismatch".into());
                }
                println!(
                    "{}",
                    json!({"phase":"legacy_tail_verify","height":height,"sample":sample,
                    "cached":cached,"verify_ms":elapsed(start),"memory":memory()})
                );
            }
        }
        noid_chain::materialize_accepted_block_state(&mut chain.state, &block).map_err(err)?;
        chain.accept(block, end);
        previous = terminal;
    }
    println!(
        "{}",
        json!({"complete":true,"mode":"legacy_tail","original_parent_class":parent_class,
        "tip":chain.parent().height,"memory":memory()})
    );
    Ok(())
}
