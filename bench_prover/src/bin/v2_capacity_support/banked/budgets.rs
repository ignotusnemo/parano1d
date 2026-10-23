// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Spend the full input envelope across State segments under an existing bank.
//! A replayed fixture supplies State; its accumulator must match a terminal
//! verified from the authenticated legacy origin before new blocks are built.

use super::super::boundaries::{payment, spread_sources};
use super::*;

pub fn measure_budgets(args: &[String]) -> Result<()> {
    if args.len() != 7 || noid_chain::consensus::params::V1_1_ACTIVATION_HEIGHT != Some(5) {
        return Err("usage: noid_v2_capacity joint-budgets PACK PIN LEGACY_FIXTURES CANDIDATE BANK_PIN NEW_OUTPUT TIP (isolated-v1-1-testnet required)".into());
    }
    let started = Instant::now();
    let candidate = PathBuf::from(&args[3]);
    let output = PathBuf::from(&args[5]);
    if output.exists() {
        return Err("new budget measurement directory required".into());
    }
    let tip: u64 = args[6].parse().map_err(err)?;
    let (parts, bank, paths) = read_candidate(&candidate, digest(&args[4])?)?;
    let config = bank.config();
    if config.activation_height() != 10 || !(10..=10_000).contains(&tip) {
        return Err("isolated H10 bank and bounded post-fork tip required".into());
    }
    let settings = Settings {
        pack: PathBuf::from(&args[0]),
        pin: digest(&args[1])?,
        fixtures: PathBuf::from(&args[2]),
        output: output.clone(),
        config: config.class(Class::Small),
        samples: 1,
        freeze_only: false,
        transition_only: false,
        payments_only: false,
    };
    let legacy = proof::legacy_runtime(&settings.pack, settings.pin)?;
    let (legacy_chain, legacy_tip) = Chain::load(&settings, &legacy)?;
    let origin = joint::VerifiedOrigin::from_legacy(
        &legacy,
        &legacy_tip,
        legacy_chain.parent(),
        &legacy_chain.epoch(),
        &bank,
    )
    .map_err(err)?;
    drop(legacy_tip);
    drop(legacy_chain);
    drop(legacy);
    let runtime = joint::Runtime::new(
        bank.clone(),
        parts,
        Box::new(Source {
            paths: paths.clone(),
            config,
            digests: Class::ALL.map(|class| bank.matrix_digest(class)),
            cache: Mutex::new([None, None]),
        }),
    )
    .map_err(err)?;
    for class in Class::ALL {
        runtime.prepare_matrix_cache(class).map_err(err)?;
    }
    let mut chain =
        Chain::replay_for_receiver(&settings.fixtures, &candidate, settings.config, tip)?;
    let terminal = joint::decode_terminal(
        &runtime,
        &proof::bounded(
            &candidate.join(format!("h{tip:06}.terminal")),
            2 * 1024 * 1024,
        )?,
    )
    .map_err(err)?;
    let epoch_height = (tip - 1) / noid_chain::consensus::params::TX_EPOCH_BLOCKS
        * noid_chain::consensus::params::TX_EPOCH_BLOCKS;
    let epoch = if epoch_height == 0 {
        noid_chain::consensus::genesis_header()
    } else {
        let directory = if epoch_height < config.activation_height() {
            &settings.fixtures
        } else {
            &candidate
        };
        Block::from_bytes(&proof::bounded(
            &directory.join(format!("h{epoch_height:06}.block")),
            16 * 1024 * 1024,
        )?)
        .map_err(err)?
        .header
    };
    let accepted = joint::verify_terminal(&runtime, &origin, &terminal, chain.parent(), &epoch)
        .map_err(err)?;
    if accepted.accumulator() != &chain.accumulator {
        return Err("budget fixture replay differs from its verified accumulator".into());
    }
    // Retain a self-contained fixture for the existing independent receiver.
    std::fs::create_dir(&output).map_err(err)?;
    for name in ["joint.parts", "joint.pins.json"] {
        std::fs::copy(candidate.join(name), output.join(name)).map_err(err)?;
    }
    for path in paths {
        std::fs::copy(
            &path,
            output.join(path.file_name().ok_or("matrix filename")?),
        )
        .map_err(err)?;
    }
    for height in config.activation_height()..=tip {
        for extension in ["block", "terminal"] {
            let name = format!("h{height:06}.{extension}");
            std::fs::copy(candidate.join(&name), output.join(name)).map_err(err)?;
        }
    }
    let ghost = noid_recursive::prepare_history_step_ghost_authorization_for_version(
        noid_gkr::ghost_tx::prove_selected_ghost_authorization_for_version(
            config.class(Class::Small).authorization_version(),
        )
        .map_err(err)?,
        config.class(Class::Small).authorization_version(),
    )
    .map_err(err)?;
    println!(
        "{}",
        json!({"phase":"joint_budget_setup", "bank":hex::encode(bank.digest()),
        "source_tip":tip,"ms":elapsed(started),"memory":memory()})
    );
    let mut run = JointRun {
        runtime,
        origin,
        previous: Some(terminal),
        ghost,
        output,
        audited_transitions: [false; 5],
        audited_full_calls: [false; 2],
    };
    chain.distribute_outputs();
    match config.class(Class::Small).pages() {
        25 => class_budget::<25>(&mut run, &mut chain, Class::Small)?,
        63 => class_budget::<63>(&mut run, &mut chain, Class::Small)?,
        64 => class_budget::<64>(&mut run, &mut chain, Class::Small)?,
        96 => class_budget::<96>(&mut run, &mut chain, Class::Small)?,
        112 => class_budget::<112>(&mut run, &mut chain, Class::Small)?,
        120 => class_budget::<120>(&mut run, &mut chain, Class::Small)?,
        127 => class_budget::<127>(&mut run, &mut chain, Class::Small)?,
        _ => return Err("unsupported small budget capacity".into()),
    }
    match config.class(Class::Large).pages() {
        206 => class_budget::<206>(&mut run, &mut chain, Class::Large)?,
        207 => class_budget::<207>(&mut run, &mut chain, Class::Large)?,
        209 => class_budget::<209>(&mut run, &mut chain, Class::Large)?,
        210 => class_budget::<210>(&mut run, &mut chain, Class::Large)?,
        211 => class_budget::<211>(&mut run, &mut chain, Class::Large)?,
        223 => class_budget::<223>(&mut run, &mut chain, Class::Large)?,
        255 => class_budget::<255>(&mut run, &mut chain, Class::Large)?,
        _ => return Err("unsupported large budget capacity".into()),
    }
    println!(
        "{}",
        json!({"complete":true,"mode":"joint-input-budgets",
        "tip":chain.parent().height,"memory":memory()})
    );
    Ok(())
}

fn class_budget<const PAGES: usize>(
    run: &mut JointRun,
    chain: &mut Chain,
    class: Class,
) -> Result<()> {
    let config = run.runtime.bank().config().class(class);
    let limit = config.max_live_inputs();
    let original_limit = noid_chain::consensus::params::block_class_spend_capacity(PAGES);
    let mut negative_checked = false;
    for inputs_per_page in [4, 8, 0] {
        let full_pages = inputs_per_page == 0;
        if full_pages
            && (limit < PAGES || [4, 8].iter().any(|width| limit.div_ceil(*width) == PAGES))
        {
            continue;
        }
        if !full_pages && limit.div_ceil(inputs_per_page) > PAGES {
            continue;
        }
        fund::<PAGES>(
            run,
            chain,
            class,
            limit + usize::from(limit < original_limit),
        )?;
        let sources = spread_sources(chain);
        if !negative_checked && limit < original_limit {
            reject_over_budget::<PAGES>(run, chain, class, &sources[..limit + 1])?;
            negative_checked = true;
        }
        let segments = sources[..limit]
            .iter()
            .map(|slot| slot >> 16)
            .collect::<BTreeSet<_>>()
            .len();
        if segments != limit.min(256) {
            return Err("full input case did not span the expected State segments".into());
        }
        let mut batch = Batch::default();
        let mut consumed = 0;
        while consumed < limit {
            let width = if full_pages {
                (limit - consumed - (PAGES - batch.pages.len() - 1)).min(TX_INPUTS)
            } else {
                inputs_per_page.min(limit - consumed)
            };
            payment(&mut batch, chain, &sources[consumed..consumed + width], 2)?;
            consumed += width;
        }
        let layout = if full_pages {
            "full_pages".to_owned()
        } else {
            format!("per_page_{inputs_per_page}")
        };
        let height = chain.parent().height + 1;
        let pages = batch.pages.len();
        // Also rebuild and check the exact frozen relation for this maximum
        // input witness, even when this class transition has been seen before.
        run.audited_transitions = [false; 5];
        run.block::<PAGES>(
            chain,
            class,
            &format!("joint_class_{}_inputs_{limit}_{layout}", class.wire_id()),
            batch,
        )?;
        println!(
            "{}",
            json!({"phase":"joint_input_boundary", "height":height,
            "class":class.wire_id(),"inputs":limit,"layout":layout,
            "pages":pages,"outputs":2*pages,"input_segments":segments})
        );
    }
    run.block::<PAGES>(
        chain,
        class,
        "joint_budget_empty_successor",
        Batch::default(),
    )
}

fn fund<const PAGES: usize>(
    run: &mut JointRun,
    chain: &mut Chain,
    class: Class,
    target: usize,
) -> Result<()> {
    loop {
        let sources = chain.ordinary_slots();
        let segments = sources
            .iter()
            .map(|slot| slot >> 16)
            .collect::<BTreeSet<_>>()
            .len();
        if sources.len() >= target && segments >= target.min(256) {
            return Ok(());
        }
        let count = sources.len().min(PAGES).min(if sources.len() < target {
            target - sources.len()
        } else {
            PAGES
        });
        if count == 0 {
            return Err("joint budget funding exhausted".into());
        }
        let mut batch = Batch::default();
        for source in &sources[..count] {
            payment(&mut batch, chain, &[*source], 2)?;
        }
        run.block::<PAGES>(chain, class, "joint_budget_funding", batch)?;
    }
}

fn reject_over_budget<const PAGES: usize>(
    run: &JointRun,
    chain: &mut Chain,
    class: Class,
    sources: &[u32],
) -> Result<()> {
    let config = run.runtime.bank().config().class(class);
    let mut batch = Batch::default();
    for sources in sources.chunks(TX_INPUTS) {
        payment(&mut batch, chain, sources, 1)?;
    }
    let (block, state) = chain.build(&batch.pages, config.schedule())?;
    drop(state);
    match chain.input::<PAGES>(&block, &batch, &run.ghost, config) {
        Err(error) if error.contains("BlockInputLimit") => (),
        _ => return Err("over-budget inputs escaped native candidate validation".into()),
    }
    batch.prove_authorizations(block.header.height)?;
    let wider = v2::V2Config::new(config.outer_m(), PAGES, config.schedule()).map_err(err)?;
    let frozen = joint::assemble_frozen(
        &run.runtime,
        run.origin.origin(),
        run.previous.as_ref(),
        chain.input::<PAGES>(&block, &batch, &run.ghost, wider)?,
    )
    .map_err(err)?;
    if frozen.matrix().statement_digest() != run.runtime.bank().matrix_digest(class)
        || frozen.matrix().satisfies(frozen.witness())
    {
        return Err("joint input overflow failed its frozen-matrix negative control".into());
    }
    println!(
        "{}",
        json!({"phase":"joint_input_budget_adversarial_check",
        "class":class.wire_id(),"inputs":sources.len(),"native_rejected":true,
        "same_matrix":true,"r1cs_satisfied":false})
    );
    Ok(())
}
