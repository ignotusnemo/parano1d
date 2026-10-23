// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete joint-bank qualification. Both matrices come from the same
//! predecessor geometry and pinned bank; separately frozen single classes
//! cannot be substituted for this construction.

use super::*;
use joint::Class;
use noid_ivc_core::field_r1cs::CompactFieldR1cs;
use noid_recursive::acceptance::history_step::v2::banked as joint;
use noid_recursive::HistoryStepMatrixLease;
use std::sync::{Arc, Mutex};

mod budgets;
mod release;
pub use budgets::measure_budgets;
pub use release::freeze_mainnet;

struct Source {
    paths: [PathBuf; 2],
    config: joint::Config,
    digests: [[u8; 32]; 2],
    cache: Mutex<[Option<Arc<CompactFieldR1cs>>; 2]>,
}
impl joint::MatrixSource for Source {
    fn load(&self, class: Class) -> std::result::Result<HistoryStepMatrixLease, v2::V2Error> {
        let mut cache = self.cache.lock().map_err(|_| v2::V2Error::Matrix)?;
        let slot = class.index();
        if cache[slot].is_none() {
            cache[slot] = Some(
                proof::open_matrix(
                    &self.paths[slot],
                    self.config.class(class).shape(),
                    self.digests[slot],
                )
                .map_err(|_| v2::V2Error::Matrix)?,
            );
        }
        Ok(HistoryStepMatrixLease::Compact(Arc::clone(
            cache[slot].as_ref().unwrap(),
        )))
    }
}
struct RejectSource;
impl joint::MatrixSource for RejectSource {
    fn load(&self, _: Class) -> std::result::Result<HistoryStepMatrixLease, v2::V2Error> {
        Err(v2::V2Error::Matrix)
    }
}

struct SharedSource(Arc<Source>);
impl joint::MatrixSource for SharedSource {
    fn load(&self, class: Class) -> std::result::Result<HistoryStepMatrixLease, v2::V2Error> {
        joint::MatrixSource::load(self.0.as_ref(), class)
    }
}

fn digest(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)
        .map_err(err)?
        .try_into()
        .map_err(|_| "pin length".into())
}

fn read_candidate(
    output: &Path,
    supplied_pin: [u8; 32],
) -> Result<(joint::RuntimeParts, joint::Bank, [PathBuf; 2])> {
    let parts = joint::RuntimeParts::decode_compact(&proof::bounded(
        &output.join("joint.parts"),
        noid_recursive::HISTORY_STEP_RUNTIME_PARTS_COMPACT_MAX_BYTES,
    )?)
    .map_err(err)?;
    let pins: serde_json::Value =
        serde_json::from_slice(&proof::bounded(&output.join("joint.pins.json"), 64 * 1024)?)
            .map_err(err)?;
    if pins["entries"].as_array().map(Vec::len) != Some(2) {
        return Err("joint bank requires exactly two entries".into());
    }
    let mut digests = [[0; 32]; 2];
    let mut paths = [PathBuf::new(), PathBuf::new()];
    for class in Class::ALL {
        let entry = &pins["entries"][class.index()];
        if entry["class"].as_u64() != Some(class.wire_id() as u64) {
            return Err("entry class".into());
        }
        digests[class.index()] = digest(entry["matrix"].as_str().ok_or("matrix pin")?)?;
        let name = entry["file"].as_str().ok_or("matrix filename")?;
        if Path::new(name).components().count() != 1
            || !name.ends_with(".field-r1cs.zst")
            || name.contains(['/', '\\'])
        {
            return Err("matrix filename must be a local artifact name".into());
        }
        paths[class.index()] = output.join(name);
    }
    let bank = joint::Bank::pin(digests, &parts);
    if bank.digest() != supplied_pin {
        return Err("joint bank differs from supplied pin".into());
    }
    Ok((parts, bank, paths))
}

/// Independent verification contexts share authenticated immutable matrices,
/// never their successful-claim caches or accepted origins.
pub(super) fn runtime_pair(output: &Path, pin: [u8; 32]) -> Result<[Arc<joint::Runtime>; 2]> {
    let (parts, bank, paths) = read_candidate(output, pin)?;
    let source = Arc::new(Source {
        paths,
        config: parts.config(),
        digests: Class::ALL.map(|class| bank.matrix_digest(class)),
        cache: Mutex::new([None, None]),
    });
    let make = || {
        joint::Runtime::new(
            bank.clone(),
            parts.clone(),
            Box::new(SharedSource(Arc::clone(&source))),
        )
        .map(Arc::new)
        .map_err(err)
    };
    Ok([make()?, make()?])
}

/// Run separately under the receiver CPU/memory envelope. Matrix decoding
/// and authentication are setup; cold means an empty checked-claim cache.
pub fn verify_saved(args: &[String]) -> Result<()> {
    if args.len() != 7 || noid_chain::consensus::params::V1_1_ACTIVATION_HEIGHT != Some(5) {
        return Err("usage: noid_v2_capacity joint-verify PACK PIN LEGACY_FIXTURES CANDIDATE BANK_PIN HEIGHT[,HEIGHT...] REPEATS (isolated-v1-1-testnet required)".into());
    }
    let output = PathBuf::from(&args[3]);
    let setup = Instant::now();
    let (parts, bank, paths) = read_candidate(&output, digest(&args[4])?)?;
    let config = parts.config();
    let digests = Class::ALL.map(|class| bank.matrix_digest(class));
    let source = Arc::new(Source {
        paths,
        config,
        digests,
        cache: Mutex::new([None, None]),
    });
    // Ensure that filesystem reads, decompression and artifact authentication
    // do not get mistaken for steady-state terminal verification.
    for class in Class::ALL {
        drop(joint::MatrixSource::load(source.as_ref(), class).map_err(err)?);
    }
    let make_runtime = || {
        joint::Runtime::new(
            bank.clone(),
            parts.clone(),
            Box::new(SharedSource(Arc::clone(&source))),
        )
        .map_err(err)
    };
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
    drop(legacy_chain);
    drop(legacy_tip);
    drop(legacy);
    println!(
        "{}",
        json!({"phase":"joint_receiver_setup","ms":elapsed(setup),"memory":memory(),"threads":rayon::current_num_threads(),"bank":hex::encode(bank.digest())})
    );
    let repeats: usize = args[6].parse().map_err(err)?;
    if repeats == 0 || repeats > 20 {
        return Err("repeats must be 1..20".into());
    }
    for h in args[5].split(',') {
        let height: u64 = h.parse().map_err(err)?;
        let header = Block::from_bytes(&proof::bounded(
            &output.join(format!("h{height:06}.block")),
            16 * 1024 * 1024,
        )?)
        .map_err(err)?
        .header;
        if header.height != height {
            return Err("fixture height".into());
        }
        let epoch_height = height.checked_sub(1).ok_or("terminal before fork")?
            / noid_chain::consensus::params::TX_EPOCH_BLOCKS
            * noid_chain::consensus::params::TX_EPOCH_BLOCKS;
        let epoch = if epoch_height == 0 {
            noid_chain::consensus::genesis_header()
        } else {
            let root = if epoch_height < config.activation_height() {
                &settings.fixtures
            } else {
                &output
            };
            Block::from_bytes(&proof::bounded(
                &root.join(format!("h{epoch_height:06}.block")),
                16 * 1024 * 1024,
            )?)
            .map_err(err)?
            .header
        };
        let bytes = proof::bounded(
            &output.join(format!("h{height:06}.terminal")),
            2 * 1024 * 1024,
        )?;
        for sample in 0..repeats {
            let runtime = make_runtime()?;
            for warm in [false, true] {
                let start = Instant::now();
                let terminal = joint::decode_terminal(&runtime, &bytes).map_err(err)?;
                let accepted =
                    joint::verify_terminal(&runtime, &origin, &terminal, &header, &epoch)
                        .map_err(err)?;
                println!(
                    "{}",
                    json!({"phase":"joint_receiver_verify","height":height,"class":accepted.class().wire_id(),
                    "sample":sample,"checked_claim_cache_warm":warm,"ms":elapsed(start),"memory":memory(),"terminal_bytes":bytes.len()})
                );
            }
        }
        // This is fixture qualification, outside the receiver timing. The
        // production proof verifier does not require replaying old bodies.
        let replay_start = Instant::now();
        let replayed = Chain::replay_for_receiver(
            &settings.fixtures,
            &output,
            config.class(Class::Small),
            height,
        )?;
        let runtime = make_runtime()?;
        let terminal = joint::decode_terminal(&runtime, &bytes).map_err(err)?;
        if terminal.accumulator(&bank).map_err(err)? != replayed.accumulator {
            return Err("joint fixture replay differs from its verified accumulator".into());
        }
        println!(
            "{}",
            json!({"phase":"joint_fixture_native_replay","height":height,"ms":elapsed(replay_start),"memory":memory()})
        );
        audit_terminal(&runtime, &origin, &bytes, &header, &epoch)?;
    }
    Ok(())
}

/// Exercise the production artifact loader against an already proved isolated
/// candidate, then stage a NEW pack for local node integration.
pub fn stage_saved(args: &[String]) -> Result<()> {
    use noid_miner::v2_artifacts as pack;
    if args.len() != 7 || noid_chain::consensus::params::V1_1_ACTIVATION_HEIGHT != Some(5) {
        return Err("usage: noid_v2_capacity joint-stage PACK PIN LEGACY_FIXTURES CANDIDATE BANK_PIN NEW_PACK HEIGHT (isolated-v1-1-testnet required)".into());
    }
    let candidate = PathBuf::from(&args[3]);
    let output = PathBuf::from(&args[5]);
    if output.exists() {
        return Err("a new staging directory is required".into());
    }
    let bank_pin = digest(&args[4])?;
    let (parts, bank, paths) = read_candidate(&candidate, bank_pin)?;
    let config = bank.config();
    let encoded = pack::encode_v2_runtime_metadata(&bank, &parts)?;
    let metadata = pack::decode_v2_runtime_metadata_pinned(&encoded, bank_pin)?;
    if metadata.bank().config() != config {
        return Err("production metadata changed the joint limits".into());
    }
    let mut wrong_pin = bank_pin;
    wrong_pin[0] ^= 1;
    if pack::decode_v2_runtime_metadata_pinned(&encoded, wrong_pin).is_ok() {
        return Err("production metadata accepted an unpinned bank".into());
    }
    for cut in [0, 8, 75, encoded.len() - 1] {
        if pack::decode_v2_runtime_metadata_pinned(&encoded[..cut], bank_pin).is_ok() {
            return Err("truncated production metadata accepted".into());
        }
    }
    let compressed = [
        proof::bounded(&paths[0], pack::V2_MATRIX_MAX_BYTES)?,
        proof::bounded(&paths[1], pack::V2_MATRIX_MAX_BYTES)?,
    ];
    for class in Class::ALL {
        if metadata
            .preflight_build_matrix(class, &compressed[1 - class.index()])
            .is_ok()
        {
            return Err("production loader accepted swapped matrix classes".into());
        }
    }
    let preflight = |class: Class| -> Result<_> {
        let start = Instant::now();
        let seal = metadata.preflight_build_matrix(class, &compressed[class.index()])?;
        println!(
            "{}",
            json!({"phase":"production_matrix_preflight","class":class.wire_id(),"ms":elapsed(start),"memory":memory()})
        );
        Ok(seal)
    };
    let seals = [preflight(Class::Small)?, preflight(Class::Large)?];
    // This process models executable embedding. The exact preflighted bytes
    // become immutable for its lifetime, without reopening either source file.
    let embedded: [&'static [u8]; 2] =
        compressed.map(|bytes| &*Box::leak(bytes.into_boxed_slice()));
    let runtime = unsafe {
        // SAFETY: each immutable slice above is the exact blob authenticated
        // by the matching class's seal immediately above.
        metadata.into_embedded_runtime(embedded, seals)?
    };
    let start = Instant::now();
    for class in Class::ALL {
        runtime.prepare_matrix_cache(class).map_err(err)?;
    }
    println!(
        "{}",
        json!({"phase":"production_embedded_matrix_load","ms":elapsed(start),"memory":memory()})
    );
    let settings = Settings {
        pack: PathBuf::from(&args[0]),
        pin: digest(&args[1])?,
        fixtures: PathBuf::from(&args[2]),
        output: candidate.clone(),
        config: config.class(Class::Small),
        samples: 1,
        freeze_only: false,
        transition_only: false,
        payments_only: false,
    };
    let old_runtime = proof::legacy_runtime(&settings.pack, settings.pin)?;
    let (old_chain, old_tip) = Chain::load(&settings, &old_runtime)?;
    let certificate = joint::LegacyOriginCertificate::new(
        *old_chain.parent(),
        old_chain.epoch(),
        legacy::encode_history_step_terminal(&old_runtime, &old_tip).map_err(err)?,
    )
    .map_err(err)?;
    let origin = certificate
        .verify(&old_runtime, runtime.bank())
        .map_err(err)?;
    drop(old_tip);
    drop(old_chain);
    drop(old_runtime);
    let height: u64 = args[6].parse().map_err(err)?;
    if height < config.activation_height() {
        return Err("staged endpoint must belong to v2".into());
    }
    let mut parent = Chain::replay_for_receiver(
        &settings.fixtures,
        &candidate,
        config.class(Class::Small),
        height - 1,
    )?;
    let block = Block::from_bytes(&proof::bounded(
        &candidate.join(format!("h{height:06}.block")),
        16 * 1024 * 1024,
    )?)
    .map_err(err)?;
    let bytes = proof::bounded(&candidate.join(format!("h{height:06}.terminal")), 1_100_000)?;
    let terminal = joint::decode_terminal(&runtime, &bytes).map_err(err)?;
    let accepted =
        joint::verify_terminal(&runtime, &origin, &terminal, &block.header, &parent.epoch())
            .map_err(err)?;
    parent.check_native(&block, config.schedule())?;
    if accepted.accumulator()
        != &parent
            .accumulator
            .advance(parent.parent(), &block.header)
            .map_err(err)?
    {
        return Err("production artifact verifier differs from native replay".into());
    }
    noid_chain::materialize_accepted_block_state(&mut parent.state, &block).map_err(err)?;
    std::fs::create_dir(&output).map_err(err)?;
    std::fs::write(output.join(pack::V2_METADATA_FILE), &encoded).map_err(err)?;
    for class in Class::ALL {
        std::fs::write(
            output.join(pack::v2_matrix_file_name(class)),
            embedded[class.index()],
        )
        .map_err(err)?;
    }
    std::fs::write(output.join("legacy-v2-origin.bin"), certificate.to_bytes()).map_err(err)?;
    let report = json!({"status":"local candidate staged and verified","bank":hex::encode(bank_pin),
        "origin_binding":hex::encode(origin.origin().request_binding()),"height":height,"memory":memory(),
        "mainnet_release":false,"metadata_negative_checks":5,"swapped_class_rejections":2});
    std::fs::write(
        output.join("stage.json"),
        serde_json::to_vec_pretty(&report).map_err(err)?,
    )
    .map_err(err)?;
    println!("{report}");
    Ok(())
}

pub fn run(args: &[String]) -> Result<()> {
    if args.len() < 9 {
        return Err("usage: noid_v2_capacity joint PACK PIN LEGACY_FIXTURES NEW_OUTPUT SMALL_PAGES SMALL_INPUTS SMALL_CALLS LARGE_INPUTS LARGE_CALLS [--freeze-only] [--large-pages=206|207|209|210|211|223|255]".into());
    }
    if noid_chain::consensus::params::V1_1_ACTIVATION_HEIGHT != Some(5) {
        return Err("isolated-v1-1-testnet feature required".into());
    }
    let schedule = ForkSchedule::new(
        Some(5),
        noid_chain::consensus::forks::V2Activation::new(10, 30),
    )
    .ok_or("schedule")?;
    let number = |i: usize| args[i].parse::<usize>().map_err(err);
    let (large_pages, freeze_only) = joint_options(&args[9..])?;
    let small =
        v2::V2Config::with_limits(23, number(4)?, number(5)?, number(6)?, schedule).map_err(err)?;
    let large = v2::V2Config::with_limits(24, large_pages, number(7)?, number(8)?, schedule)
        .map_err(err)?;
    let config = joint::Config::new(small, large).map_err(err)?;
    let output = PathBuf::from(&args[3]);
    std::fs::create_dir(&output).map_err(|e| format!("new output directory required: {e}"))?;
    let settings = Settings {
        pack: PathBuf::from(&args[0]),
        pin: hex::decode(&args[1])
            .map_err(err)?
            .try_into()
            .map_err(|_| "pin length")?,
        fixtures: PathBuf::from(&args[2]),
        output,
        config: small,
        samples: 1,
        freeze_only,
        transition_only: false,
        payments_only: false,
    };
    match (small.pages(), large.pages()) {
        (63, 206) => measure::<63, 206>(settings, config),
        (63, 207) => measure::<63, 207>(settings, config),
        (63, 209) => measure::<63, 209>(settings, config),
        (63, 210) => measure::<63, 210>(settings, config),
        (63, 211) => measure::<63, 211>(settings, config),
        (63, 223) => measure::<63, 223>(settings, config),
        (25, 255) => measure::<25, 255>(settings, config),
        (63, 255) => measure::<63, 255>(settings, config),
        (64, 255) => measure::<64, 255>(settings, config),
        (96, 255) => measure::<96, 255>(settings, config),
        (112, 255) => measure::<112, 255>(settings, config),
        (120, 255) => measure::<120, 255>(settings, config),
        (127, 255) => measure::<127, 255>(settings, config),
        _ => Err("unsupported joint probe capacity".into()),
    }
}

fn joint_options(options: &[String]) -> Result<(usize, bool)> {
    let mut large_pages = None;
    let mut freeze_only = false;
    for option in options {
        if option == "--freeze-only" && !freeze_only {
            freeze_only = true;
        } else if let Some(value) = option.strip_prefix("--large-pages=") {
            if large_pages.is_some() {
                return Err("duplicate large page limit".into());
            }
            let pages: usize = value.parse().map_err(err)?;
            if !matches!(pages, 206 | 207 | 209 | 210 | 211 | 223 | 255) {
                return Err("unsupported large page limit".into());
            }
            large_pages = Some(pages);
        } else {
            return Err(format!("unsupported joint option: {option}"));
        }
    }
    Ok((large_pages.unwrap_or(255), freeze_only))
}

fn freeze_class<const PAGES: usize>(
    runtime: &joint::Runtime,
    origin: &joint::Origin,
    chain: &Chain,
    block: &Block,
    ghost: &PreparedHistoryStepGhostAuthorization,
    class: Class,
) -> Result<legacy::v2::FrozenV2> {
    let input = chain.input::<PAGES>(
        block,
        &Batch::default(),
        ghost,
        runtime.bank().config().class(class),
    )?;
    let frozen = joint::assemble_frozen(runtime, origin, None, input).map_err(err)?;
    if !frozen.matrix().satisfies(frozen.witness()) {
        return Err("joint matrix witness unsatisfied".into());
    }
    if frozen.parent_vk() != runtime.parts().parent_vk() {
        return Err("joint parent geometry changed".into());
    }
    Ok(frozen)
}

fn measure<const SMALL: usize, const LARGE: usize>(
    settings: Settings,
    config: joint::Config,
) -> Result<()> {
    let legacy_runtime = proof::legacy_runtime(&settings.pack, settings.pin)?;
    let (mut chain, legacy_tip) = Chain::load(&settings, &legacy_runtime)?;
    let ghost = noid_recursive::prepare_history_step_ghost_authorization_for_version(
        noid_gkr::ghost_tx::prove_selected_ghost_authorization_for_version(
            config.class(Class::Small).authorization_version(),
        )
        .map_err(err)?,
        config.class(Class::Small).authorization_version(),
    )
    .map_err(err)?;
    let start = Instant::now();
    let (first, _) = chain.build(&[], config.schedule())?;
    let block_vks = [
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
    let mut parts = joint::derive_runtime_parts(config, block_vks).map_err(err)?;
    let mut result = None;
    for pass in 0..4 {
        let bank = joint::Bank::pin([[0; 32]; 2], &parts);
        let runtime =
            joint::Runtime::new(bank, parts.clone(), Box::new(RejectSource)).map_err(err)?;
        let origin = joint::VerifiedOrigin::from_legacy(
            &legacy_runtime,
            &legacy_tip,
            chain.parent(),
            &chain.epoch(),
            runtime.bank(),
        )
        .map_err(err)?;
        let mut blocks = Class::ALL.map(|c| parts.block_vk(c).clone());
        let mut digests = [[0; 32]; 2];
        let mut rows = [0; 2];
        let paths = Class::ALL.map(|c| {
            settings
                .output
                .join(format!("pass{pass}-class{}.field-r1cs.zst", c.wire_id()))
        });
        for class in Class::ALL {
            let scan = Instant::now();
            let frozen = match class {
                Class::Small => {
                    freeze_class::<SMALL>(&runtime, origin.origin(), &chain, &first, &ghost, class)?
                }
                Class::Large => {
                    freeze_class::<LARGE>(&runtime, origin.origin(), &chain, &first, &ghost, class)?
                }
            };
            blocks[class.index()] = frozen.block_vk().clone();
            digests[class.index()] = frozen.matrix().statement_digest();
            rows[class.index()] = frozen.matrix().useful_rows;
            println!(
                "{}",
                json!({"phase":"joint_freeze", "pass":pass,"class":class.wire_id(),
                "pages":config.class(class).pages(),"calls":config.class(class).contract_slots(),
                "inputs":config.class(class).max_live_inputs(),"rows":rows[class.index()],
                "matrix":hex::encode(digests[class.index()]),"satisfied":true,"scan_ms":elapsed(scan),"memory":memory()})
            );
            proof::write_matrix(&paths[class.index()], frozen.matrix())?;
        }
        if Class::ALL
            .into_iter()
            .all(|c| &blocks[c.index()] == parts.block_vk(c))
        {
            result = Some((digests, rows, paths));
            break;
        }
        parts = joint::derive_runtime_parts(config, blocks).map_err(err)?;
    }
    let (digests, rows, paths) = result.ok_or("joint integrated geometry did not converge")?;
    let bank = joint::Bank::pin(digests, &parts);
    let runtime = joint::Runtime::new(
        bank,
        parts.clone(),
        Box::new(Source {
            paths: paths.clone(),
            config,
            digests,
            cache: Mutex::new([None, None]),
        }),
    )
    .map_err(err)?;
    let origin = joint::VerifiedOrigin::from_legacy(
        &legacy_runtime,
        &legacy_tip,
        chain.parent(),
        &chain.epoch(),
        runtime.bank(),
    )
    .map_err(err)?;
    for class in Class::ALL {
        let frozen = match class {
            Class::Small => {
                freeze_class::<SMALL>(&runtime, origin.origin(), &chain, &first, &ghost, class)?
            }
            Class::Large => {
                freeze_class::<LARGE>(&runtime, origin.origin(), &chain, &first, &ghost, class)?
            }
        };
        if frozen.matrix().statement_digest() != digests[class.index()]
            || frozen.block_vk() != parts.block_vk(class)
        {
            return Err("pinning the full bank changed its matrix".into());
        }
    }
    let encoded = parts.encode_compact().map_err(err)?;
    let decoded = joint::RuntimeParts::decode_compact(&encoded).map_err(err)?;
    if joint::Bank::pin(digests, &decoded).digest() != runtime.bank().digest()
        || decoded.encode_compact().map_err(err)? != encoded
    {
        return Err("joint recipe round trip".into());
    }
    for (offset, value) in [
        (0, 0u64),
        (8, 2),
        (16, 24),
        (64, 0),
        (64, 1),
        (64, u64::MAX),
    ] {
        let mut changed = encoded.clone();
        changed[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        if let Ok(other) = joint::RuntimeParts::decode_compact(&changed) {
            if joint::Bank::pin(digests, &other).digest() == runtime.bank().digest() {
                return Err("joint recipe substitution retained pin".into());
            }
        }
    }
    std::fs::write(settings.output.join("joint.parts"), encoded).map_err(err)?;
    let entries = Class::ALL.into_iter().map(|class| -> Result<_> {
        Ok(json!({"class":class.wire_id(),"m":config.class(class).outer_m(),"pages":config.class(class).pages(),
            "inputs":config.class(class).max_live_inputs(),"calls":config.class(class).contract_slots(),"rows":rows[class.index()],
            "matrix":hex::encode(digests[class.index()]),"file":paths[class.index()].file_name().unwrap().to_str().unwrap(),
            "matrix_zstd_bytes":std::fs::metadata(&paths[class.index()]).map_err(err)?.len(),
            "terminal_bound":joint::terminal_max_bytes(&runtime,class).map_err(err)?}))
    }).collect::<Result<Vec<_>>>()?;
    let manifest = json!({"status":"research joint bank; no release capacity selected", "bank":hex::encode(runtime.bank().digest()),
        "entries":entries,"setup_ms":elapsed(start),"memory":memory(),"rayon_threads":rayon::current_num_threads(),
        "cpu_backend":noid_core::cpu::selected_backend().to_string(),"legacy_metadata":hex::encode(settings.pin),
        "legacy_fixture_directory":settings.fixtures});
    std::fs::write(
        settings.output.join("joint.pins.json"),
        serde_json::to_vec_pretty(&manifest).map_err(err)?,
    )
    .map_err(err)?;
    println!("{manifest}");
    drop(legacy_tip);
    drop(legacy_runtime);
    if settings.freeze_only {
        return Ok(());
    }
    let matrix_setup = Instant::now();
    for class in Class::ALL {
        runtime.prepare_matrix_cache(class).map_err(err)?;
    }
    println!(
        "{}",
        json!({"phase":"joint_matrix_authentication","ms":elapsed(matrix_setup),"memory":memory()})
    );
    let mut run = JointRun {
        runtime,
        origin,
        previous: None,
        ghost,
        output: settings.output,
        audited_transitions: [false; 5],
        audited_full_calls: [false; 2],
    };
    // Exercise every predecessor/current pair and a longer small tail after
    // a large parent. A separate cold receiver checks carried lanes again.
    for (step, class) in [
        Class::Small,
        Class::Small,
        Class::Large,
        Class::Large,
        Class::Small,
        Class::Small,
        Class::Small,
        Class::Small,
    ]
    .into_iter()
    .enumerate()
    {
        let label = format!("joint_transition_{step}");
        match class {
            Class::Small => run.block::<SMALL>(&mut chain, class, &label, Batch::default())?,
            Class::Large => run.block::<LARGE>(&mut chain, class, &label, Batch::default())?,
        }
    }
    applications::<SMALL, LARGE>(&mut run, &mut chain)?;
    println!(
        "{}",
        json!({"complete":true,"mode":"joint-transition-and-applications","tip":chain.parent().height,"memory":memory()})
    );
    Ok(())
}

struct JointRun {
    runtime: joint::Runtime,
    origin: joint::VerifiedOrigin,
    previous: Option<joint::Terminal>,
    ghost: PreparedHistoryStepGhostAuthorization,
    output: PathBuf,
    audited_transitions: [bool; 5],
    audited_full_calls: [bool; 2],
}
impl JointRun {
    fn block<const PAGES: usize>(
        &mut self,
        chain: &mut Chain,
        class: Class,
        label: &str,
        mut batch: Batch,
    ) -> Result<()> {
        let config = self.runtime.bank().config().class(class);
        batch.prove_authorizations(chain.parent().height + 1)?;
        let (mut block, _) = chain.build(&batch.pages, config.schedule())?;
        // Rebuild and scan every parent-class case during qualification. Its
        // cost is separate from the actual witness-only mining measurements.
        let transition = self
            .previous
            .as_ref()
            .map(|p| 2 * p.class().index() + class.index())
            .unwrap_or(4);
        let full_calls = batch.openings.len() == config.contract_slots();
        if !self.audited_transitions[transition]
            || (full_calls && !self.audited_full_calls[class.index()])
        {
            let scan = Instant::now();
            let frozen = joint::assemble_frozen(
                &self.runtime,
                self.origin.origin(),
                self.previous.as_ref(),
                chain.input::<PAGES>(&block, &batch, &self.ghost, config)?,
            )
            .map_err(err)?;
            if frozen.matrix().statement_digest() != self.runtime.bank().matrix_digest(class)
                || frozen.parent_vk() != self.runtime.parts().parent_vk()
                || frozen.block_vk() != self.runtime.parts().block_vk(class)
                || !frozen.matrix().satisfies(frozen.witness())
            {
                return Err(
                    "recursive class switch changed the matrix or failed its constraints".into(),
                );
            }
            println!(
                "{}",
                json!({"phase":"joint_recursive_matrix_audit","height":block.header.height,"class":class.wire_id(),"ms":elapsed(scan),"satisfied":true})
            );
            drop(frozen);
            self.audited_transitions[transition] = true;
            self.audited_full_calls[class.index()] |= full_calls;
        }
        let start = Instant::now();
        let input = chain.input::<PAGES>(&block, &batch, &self.ghost, config)?;
        let input_ms = elapsed(start);
        let start = Instant::now();
        let prepared = joint::prepare_for_pow(
            &self.runtime,
            self.origin.origin(),
            self.previous.as_ref(),
            input,
        )
        .map_err(err)?;
        let assembly_ms = elapsed(start);
        let start = Instant::now();
        block.header.nonce = mine(&block.header);
        let pow_ms = elapsed(start);
        let built = prepared
            .seal_nonce(&self.runtime, block.header.nonce)
            .map_err(err)?;
        let start = Instant::now();
        let terminal = joint::prove_built(
            &self.runtime,
            &built,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .map_err(err)?;
        let prove_ms = elapsed(start);
        drop(built);
        let bytes = joint::encode_terminal(&self.runtime, &terminal).map_err(err)?;
        drop(terminal);
        let start = Instant::now();
        let terminal = joint::decode_terminal(&self.runtime, &bytes).map_err(err)?;
        let accepted = joint::verify_terminal(
            &self.runtime,
            &self.origin,
            &terminal,
            &block.header,
            &chain.epoch(),
        )
        .map_err(err)?;
        let verify_ms = elapsed(start);
        let expected = chain
            .accumulator
            .advance(chain.parent(), &block.header)
            .map_err(err)?;
        if accepted.accumulator() != &expected {
            return Err("joint accepted boundary mismatch".into());
        }
        chain.check_native(&block, config.schedule())?;
        noid_chain::materialize_accepted_block_state(&mut chain.state, &block).map_err(err)?;
        let record = json!({"label":label,"height":block.header.height,"class":class.wire_id(),"pages":batch.pages.len(),
            "calls":batch.openings.len(),"input_ms":input_ms,"assembly_ms":assembly_ms,"prove_ms":prove_ms,"pow_ms":pow_ms,
            "verify_ms":verify_ms,"terminal_bytes":bytes.len(),"terminal_bound":joint::terminal_max_bytes(&self.runtime,class).map_err(err)?,
            "memory":memory()});
        println!("{record}");
        let stem = format!("h{:06}", block.header.height);
        std::fs::write(self.output.join(format!("{stem}.block")), block.to_bytes()).map_err(err)?;
        std::fs::write(self.output.join(format!("{stem}.terminal")), &bytes).map_err(err)?;
        std::fs::write(
            self.output.join(format!("{stem}.json")),
            serde_json::to_vec_pretty(&record).map_err(err)?,
        )
        .map_err(err)?;
        if label.starts_with("joint_transition_") || full_calls {
            audit_terminal(
                &self.runtime,
                &self.origin,
                &bytes,
                &block.header,
                &chain.epoch(),
            )?;
        }
        self.previous = Some(terminal);
        chain.accept(block, expected);
        Ok(())
    }
}

fn applications<const SMALL: usize, const LARGE: usize>(
    run: &mut JointRun,
    chain: &mut Chain,
) -> Result<()> {
    let config = run.runtime.bank().config();
    let calls = Class::ALL
        .into_iter()
        .map(|c| config.class(c).contract_slots())
        .max()
        .unwrap();
    let opening = integer_probe_opening();
    let mut ordinary = chain.ordinary_slots();
    while ordinary.len() < LARGE + calls {
        let count = ordinary
            .len()
            .min(SMALL)
            .min(LARGE + calls - ordinary.len());
        if count == 0 {
            return Err("no funding notes".into());
        }
        let sources: Vec<_> = ordinary.drain(..count).collect();
        let mut batch = Batch::default();
        for source in sources {
            let amount = chain
                .input_slot(source)?
                .amount
                .checked_sub(chain.fee(2))
                .ok_or("split balance")?;
            let slots = chain.empty_slots::<2>()?;
            batch.ordinary(
                chain,
                source,
                [
                    TxOutput {
                        slot_index: slots[0],
                        amount: amount / 2,
                        owner: address(1),
                    },
                    TxOutput {
                        slot_index: slots[1],
                        amount: amount - amount / 2,
                        owner: address(1),
                    },
                ],
                true,
            )?;
            ordinary.extend(slots);
        }
        run.block::<SMALL>(chain, Class::Small, "joint_fund_payments", batch)?;
    }
    let mut objects = Vec::new();
    while objects.len() < calls {
        let mut batch = Batch::default();
        for source in ordinary
            .drain(..SMALL.min(calls - objects.len()))
            .collect::<Vec<_>>()
        {
            let [slot] = chain.empty_slots()?;
            let amount = chain
                .input_slot(source)?
                .amount
                .checked_sub(chain.fee(1))
                .ok_or("object balance")?;
            batch.ordinary(
                chain,
                source,
                [
                    TxOutput {
                        slot_index: slot,
                        amount,
                        owner: opening.root(),
                    },
                    TxOutput::dummy(),
                ],
                false,
            )?;
            objects.push((slot, opening.clone()));
        }
        run.block::<SMALL>(chain, Class::Small, "joint_fund_objects", batch)?;
    }
    for (class, pages, count) in [
        (Class::Small, 0, 0),
        (Class::Small, 4, 0),
        (Class::Small, SMALL, 0),
        (Class::Small, SMALL, 1),
        (Class::Small, SMALL, 4),
        (
            Class::Small,
            SMALL,
            config.class(Class::Small).contract_slots(),
        ),
        (Class::Large, LARGE, 0),
        (
            Class::Large,
            LARGE,
            config.class(Class::Large).contract_slots(),
        ),
        (
            Class::Small,
            SMALL,
            config.class(Class::Small).contract_slots(),
        ),
        (Class::Small, 0, 0),
        (Class::Small, 0, 0),
        (Class::Small, 0, 0),
    ] {
        let mut batch = Batch::default();
        for object in objects.iter_mut().take(count) {
            let [slot] = chain.empty_slots()?;
            let next = batch.object(chain, object.0, slot, &object.1)?;
            *object = (slot, next);
        }
        for source in ordinary.iter_mut().take(pages - count) {
            let [slot] = chain.empty_slots()?;
            let amount = chain
                .input_slot(*source)?
                .amount
                .checked_sub(chain.fee(1))
                .ok_or("payment balance")?;
            batch.ordinary(
                chain,
                *source,
                [
                    TxOutput {
                        slot_index: slot,
                        amount,
                        owner: address(1),
                    },
                    TxOutput::dummy(),
                ],
                false,
            )?;
            *source = slot;
        }
        let label = format!(
            "joint_class_{}_pages_{pages}_calls_{count}",
            class.wire_id()
        );
        match class {
            Class::Small => run.block::<SMALL>(chain, class, &label, batch)?,
            Class::Large => run.block::<LARGE>(chain, class, &label, batch)?,
        }
    }
    Ok(())
}

fn audit_terminal(
    runtime: &joint::Runtime,
    origin: &joint::VerifiedOrigin,
    bytes: &[u8],
    header: &BlockHeader,
    epoch: &BlockHeader,
) -> Result<()> {
    let rejects = |b: &[u8]| match joint::decode_terminal(runtime, b) {
        Err(_) => true,
        Ok(t) => joint::verify_terminal(runtime, origin, &t, header, epoch).is_err(),
    };
    for length in [0, 41, bytes.len() - 1] {
        if !rejects(&bytes[..length]) {
            return Err("truncation accepted".into());
        }
    }
    let mut changed = bytes.to_vec();
    changed.push(0);
    if !rejects(&changed) {
        return Err("trailing byte accepted".into());
    }
    for lane in 0..runtime.bank().config().io_spec().io_len {
        let mut changed = bytes.to_vec();
        changed[74 + 16 * lane] ^= 1;
        if !rejects(&changed) {
            return Err(format!("altered joint IO lane {lane} accepted"));
        }
    }
    for (offset, value) in [(0, 6), (41, 2), (41, 1 - bytes[41])] {
        let mut changed = bytes.to_vec();
        changed[offset] = value;
        if !rejects(&changed) {
            return Err("altered class/version accepted".into());
        }
    }
    let mut rejected = runtime.bank().config().io_spec().io_len + 7;
    let mut changed = bytes.to_vec();
    changed[41] ^= 1;
    changed[74 + 16] ^= 1;
    if !rejects(&changed) {
        return Err("wire and authenticated class substituted together".into());
    }
    rejected += 1;
    // Clear the coordinates and live bit together: the erased lane has a
    // canonical encoding and must still fail full proof verification.
    for (start, end) in [(26, 123), (123, 224)] {
        let range = 74 + 16 * start..74 + 16 * end;
        if bytes[range.clone()].iter().any(|b| *b != 0) {
            let mut changed = bytes.to_vec();
            changed[range].fill(0);
            if !rejects(&changed) {
                return Err("live accumulated lane erased canonically".into());
            }
            rejected += 1;
        }
    }
    let terminal = joint::decode_terminal(runtime, bytes).map_err(err)?;
    let mut wrong_header = *header;
    wrong_header.tx_root[0] ^= 1;
    if joint::verify_terminal(runtime, origin, &terminal, &wrong_header, epoch).is_ok() {
        return Err("joint terminal accepted a different header".into());
    }
    rejected += 1;
    println!(
        "{}",
        json!({"phase":"joint_terminal_adversarial_checks","height":header.height,"rejected":rejected})
    );
    Ok(())
}
