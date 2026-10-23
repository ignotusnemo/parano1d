// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Freeze the source-scheduled bank without inventing a verified fork origin.
//! The real predecessor cannot exist before activation. Hypothetical witnesses
//! establish matrix geometry only and are never emitted as acceptance evidence.

use super::*;
use noid_miner::{history_step_artifacts as old_pack, v2_artifacts as pack};

pub fn freeze_mainnet(args: &[String]) -> Result<()> {
    if !(8..=9).contains(&args.len()) {
        return Err("usage: noid_v2_capacity joint-freeze-mainnet LEGACY_PACK LEGACY_PIN NEW_OUTPUT SMALL_PAGES SMALL_INPUTS SMALL_CALLS LARGE_INPUTS LARGE_CALLS [--large-pages=206|207|209|210|211|223|255] (mainnet build required)".into());
    }
    let schedule = noid_chain::consensus::forks::ACTIVE_SCHEDULE;
    if noid_chain::consensus::params::ISOLATED_V1_1_TESTNET
        || noid_chain::consensus::params::ISOLATED_V2_FORK_TESTNET
        || schedule.v2().map(|activation| activation.height())
            != Some(noid_chain::consensus::params::MAINNET_V2_ACTIVATION_HEIGHT)
    {
        return Err("mainnet matrix freezing requires the source-pinned mainnet profile".into());
    }
    let number = |i: usize| args[i].parse::<usize>().map_err(err);
    let (large_pages, freeze_only) = joint_options(&args[8..])?;
    if freeze_only {
        return Err("mainnet freezing does not accept --freeze-only".into());
    }
    let config = joint::Config::new(
        v2::V2Config::with_limits(23, number(3)?, number(4)?, number(5)?, schedule).map_err(err)?,
        v2::V2Config::with_limits(24, large_pages, number(6)?, number(7)?, schedule)
            .map_err(err)?,
    )
    .map_err(err)?;
    let legacy_pin = digest(&args[1])?;
    let legacy_path = Path::new(&args[0])
        .join(old_pack::HISTORY_STEP_PACK_VERSION_DIRECTORY)
        .join(old_pack::HISTORY_STEP_RUNTIME_METADATA_FILE);
    let legacy = old_pack::decode_history_step_runtime_metadata_pinned(
        &proof::bounded(
            &legacy_path,
            old_pack::HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES,
        )?,
        legacy_pin,
    )
    .map_err(err)?;
    let output = Path::new(&args[2]);
    std::fs::create_dir(output).map_err(|e| format!("new output directory required: {e}"))?;
    match (config.class(Class::Small).pages(), large_pages) {
        (63, 206) => freeze::<63, 206>(config, legacy.bank().digest(), legacy_pin, output),
        (63, 207) => freeze::<63, 207>(config, legacy.bank().digest(), legacy_pin, output),
        (63, 209) => freeze::<63, 209>(config, legacy.bank().digest(), legacy_pin, output),
        (63, 210) => freeze::<63, 210>(config, legacy.bank().digest(), legacy_pin, output),
        (63, 211) => freeze::<63, 211>(config, legacy.bank().digest(), legacy_pin, output),
        (63, 223) => freeze::<63, 223>(config, legacy.bank().digest(), legacy_pin, output),
        (25, 255) => freeze::<25, 255>(config, legacy.bank().digest(), legacy_pin, output),
        (63, 255) => freeze::<63, 255>(config, legacy.bank().digest(), legacy_pin, output),
        (64, 255) => freeze::<64, 255>(config, legacy.bank().digest(), legacy_pin, output),
        (96, 255) => freeze::<96, 255>(config, legacy.bank().digest(), legacy_pin, output),
        (112, 255) => freeze::<112, 255>(config, legacy.bank().digest(), legacy_pin, output),
        (120, 255) => freeze::<120, 255>(config, legacy.bank().digest(), legacy_pin, output),
        (127, 255) => freeze::<127, 255>(config, legacy.bank().digest(), legacy_pin, output),
        _ => Err("unsupported joint mainnet capacity".into()),
    }
}

fn freeze<const SMALL: usize, const LARGE: usize>(
    config: joint::Config,
    legacy_bank: [u8; 32],
    legacy_pin: [u8; 32],
    output: &Path,
) -> Result<()> {
    let started = Instant::now();
    let (chain, epoch) = Chain::for_matrix_freezing(config.class(Class::Small), 0)?;
    let ghost = noid_recursive::prepare_history_step_ghost_authorization_for_version(
        noid_gkr::ghost_tx::prove_selected_ghost_authorization_for_version(
            config.class(Class::Small).authorization_version(),
        )
        .map_err(err)?,
        config.class(Class::Small).authorization_version(),
    )
    .map_err(err)?;
    let (first, _) = chain.build(&[], config.schedule())?;
    let blocks = [
        v2::derive_direct_block_vk(
            config.class(Class::Small),
            chain.input::<SMALL>(
                &first,
                &Batch::default(),
                &ghost,
                config.class(Class::Small),
            )?,
        )
        .map_err(err)?,
        v2::derive_direct_block_vk(
            config.class(Class::Large),
            chain.input::<LARGE>(
                &first,
                &Batch::default(),
                &ghost,
                config.class(Class::Large),
            )?,
        )
        .map_err(err)?,
    ];
    let mut parts = joint::derive_runtime_parts(config, blocks).map_err(err)?;
    let mut converged = None;
    for pass in 0..4 {
        let bank = joint::Bank::pin([[0; 32]; 2], &parts);
        let runtime =
            joint::Runtime::new(bank, parts.clone(), Box::new(RejectSource)).map_err(err)?;
        // This type has no conversion into VerifiedOrigin. No terminal is
        // accepted from this statement during generation or artifact loading.
        let origin = joint::Origin::for_matrix_freezing(
            legacy_bank,
            runtime.bank(),
            chain.parent(),
            &epoch,
            &chain.accumulator,
        )
        .map_err(err)?;
        let mut blocks = Class::ALL.map(|class| parts.block_vk(class).clone());
        let mut digests = [[0; 32]; 2];
        let mut rows = [0; 2];
        let paths = Class::ALL.map(|class| {
            output.join(format!(
                "pass{pass}-class{}.field-r1cs.zst",
                class.wire_id()
            ))
        });
        for class in Class::ALL {
            let phase = Instant::now();
            let frozen = match class {
                Class::Small => {
                    freeze_class::<SMALL>(&runtime, &origin, &chain, &first, &ghost, class)?
                }
                Class::Large => {
                    freeze_class::<LARGE>(&runtime, &origin, &chain, &first, &ghost, class)?
                }
            };
            blocks[class.index()] = frozen.block_vk().clone();
            digests[class.index()] = frozen.matrix().statement_digest();
            rows[class.index()] = frozen.matrix().useful_rows;
            proof::write_matrix(&paths[class.index()], frozen.matrix())?;
            println!(
                "{}",
                json!({"phase":"mainnet_joint_freeze","pass":pass,
                "class":class.wire_id(),"rows":rows[class.index()],"satisfied":true,
                "matrix":hex::encode(digests[class.index()]),"ms":elapsed(phase),"memory":memory()})
            );
        }
        if Class::ALL
            .into_iter()
            .all(|class| &blocks[class.index()] == parts.block_vk(class))
        {
            converged = Some((digests, rows, paths));
            break;
        }
        parts = joint::derive_runtime_parts(config, blocks).map_err(err)?;
    }
    let (digests, rows, paths) = converged.ok_or("mainnet joint geometry did not converge")?;
    let bank = joint::Bank::pin(digests, &parts);
    let runtime = joint::Runtime::new(bank, parts.clone(), Box::new(RejectSource)).map_err(err)?;
    // Reassemble under the final pins using two different hypothetical origins.
    // Matrix identity must not depend on the boundary witness or provisional pin.
    for variant in 0..=1 {
        let (chain, epoch) = Chain::for_matrix_freezing(config.class(Class::Small), variant)?;
        let (block, _) = chain.build(&[], config.schedule())?;
        let origin = joint::Origin::for_matrix_freezing(
            legacy_bank,
            runtime.bank(),
            chain.parent(),
            &epoch,
            &chain.accumulator,
        )
        .map_err(err)?;
        for class in Class::ALL {
            let frozen = match class {
                Class::Small => {
                    freeze_class::<SMALL>(&runtime, &origin, &chain, &block, &ghost, class)?
                }
                Class::Large => {
                    freeze_class::<LARGE>(&runtime, &origin, &chain, &block, &ghost, class)?
                }
            };
            if frozen.matrix().statement_digest() != digests[class.index()]
                || frozen.block_vk() != parts.block_vk(class)
            {
                return Err("mainnet matrix changed with final pin or origin witness".into());
            }
            println!(
                "{}",
                json!({"phase":"mainnet_witness_invariance","variant":variant,
                "class":class.wire_id(),"satisfied":true,"memory":memory()})
            );
        }
    }
    let compact = parts.encode_compact().map_err(err)?;
    let decoded = joint::RuntimeParts::decode_compact(&compact).map_err(err)?;
    if decoded.encode_compact().map_err(err)? != compact
        || joint::Bank::pin(digests, &decoded).digest() != runtime.bank().digest()
    {
        return Err("mainnet recipe round trip changed its bank".into());
    }
    let encoded = pack::encode_v2_runtime_metadata(runtime.bank(), &parts)?;
    let metadata = pack::decode_v2_runtime_metadata_pinned(&encoded, runtime.bank().digest())?;
    if metadata.bank().config().schedule() != noid_chain::consensus::forks::ACTIVE_SCHEDULE {
        return Err("staged metadata lost its source-pinned schedule".into());
    }
    let mut entries = Vec::new();
    for class in Class::ALL {
        let compressed = proof::bounded(&paths[class.index()], pack::V2_MATRIX_MAX_BYTES)?;
        metadata.preflight_build_matrix(class, &compressed)?;
        let terminal_bound = joint::terminal_max_bytes(&runtime, class).map_err(err)?;
        if terminal_bound
            > noid_chain::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES
        {
            return Err("scheduled class exceeds the terminal transport limit".into());
        }
        let name = pack::v2_matrix_file_name(class);
        std::fs::write(output.join(name), &compressed).map_err(err)?;
        let limits = config.class(class);
        entries.push(json!({"class":class.wire_id(),"m":limits.outer_m(),"pages":limits.pages(),
            "inputs":limits.max_live_inputs(),"calls":limits.contract_slots(),"rows":rows[class.index()],
            "matrix":hex::encode(digests[class.index()]),"file":paths[class.index()].file_name().unwrap().to_str().unwrap(),
            "matrix_zstd_bytes":compressed.len(),"terminal_bound":terminal_bound}));
    }
    std::fs::write(output.join(pack::V2_METADATA_FILE), encoded).map_err(err)?;
    std::fs::write(output.join("joint.parts"), compact).map_err(err)?;
    let report = json!({"status":"source-scheduled matrix pack; no verified origin",
        "bank":hex::encode(runtime.bank().digest()),"entries":entries,"legacy_metadata":hex::encode(legacy_pin),
        "v1_1_height":config.schedule().v1_1_height(),"v2_height":config.activation_height(),
        "block_seconds":config.schedule().block_time(config.activation_height()),
        "hypothetical_boundary_variants":2,"verified_origin_created":false,"terminal_produced":false,
        "elapsed_ms":elapsed(started),"memory":memory(),"rayon_threads":rayon::current_num_threads(),
        "cpu_backend":noid_core::cpu::selected_backend().to_string()});
    std::fs::write(
        output.join("joint.pins.json"),
        serde_json::to_vec_pretty(&report).map_err(err)?,
    )
    .map_err(err)?;
    println!("{report}");
    Ok(())
}
