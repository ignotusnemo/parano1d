// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Build-time authentication and embedding of history release material.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use noid_ivc_core::proof::FieldShape;
use noid_miner::history_step_artifacts::{
    decode_history_step_runtime_metadata_pinned, history_step_matrix_file_name,
    HISTORY_STEP_PACK_LEAF_COUNT, HISTORY_STEP_PACK_VERSION_DIRECTORY,
    HISTORY_STEP_RUNTIME_METADATA_FILE, HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES,
};
use noid_recursive::acceptance::history_step_bank::CanonicalHistoryStepClassId;

mod matrix_checks;

const PACK_DIRECTORY_ENV: &str = "NOID_HISTORY_STEP_PACK_DIR";
const METADATA_DIGEST_ENV: &str = "NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST";
const V2_PACK_ENV: &str = "NOID_V2_PACK_DIR";
const V2_BANK_ENV: &str = "NOID_V2_RELEASE_BANK";
const V21_PACK_ENV: &str = "NOID_V21_PACK_DIR";
const V21_BANK_ENV: &str = "NOID_V21_RELEASE_BANK";
const AUTHORIZATION_PACK_ENV: &str = "NOID_AUTHORIZATION_PACK_DIR";
const AUTHORIZATION_BANK_ENV: &str = "NOID_AUTHORIZATION_RELEASE_BANK";
const RETIREMENT_KEYS_ENV: &str = "NOID_RETIREMENT_KEYS_DIR";
const RETIREMENT_PIN0_ENV: &str = "NOID_RETIREMENT_KEY_0_PIN";
const RETIREMENT_PIN1_ENV: &str = "NOID_RETIREMENT_KEY_1_PIN";

const GENERATED_FILE: &str = "history_step_pack.rs";
const STAGED_DIRECTORY: &str = "embedded-history-step";
const MAX_COMPRESSED_LEAF_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CANONICAL_LEAF_BYTES: usize = 1024 * 1024 * 1024;
const ZSTD_WINDOW_LOG_MAX: u32 = 27;

#[derive(Clone, Copy)]
struct EmbeddedLeafSeal {
    shape: FieldShape,
    statement_digest: [u8; 32],
    canonical_bytes: usize,
}

struct EmbeddedLeaf {
    seal: EmbeddedLeafSeal,
}

fn main() {
    for variable in [
        PACK_DIRECTORY_ENV,
        METADATA_DIGEST_ENV,
        V2_PACK_ENV,
        V2_BANK_ENV,
        V21_PACK_ENV,
        V21_BANK_ENV,
        AUTHORIZATION_PACK_ENV,
        AUTHORIZATION_BANK_ENV,
        RETIREMENT_KEYS_ENV,
        RETIREMENT_PIN0_ENV,
        RETIREMENT_PIN1_ENV,
        "NOID_PRECHECKED_MATRIX_PACKS",
        "NOID_V2_MATRIX_CHECKS_SHA256",
        "NOID_V21_MATRIX_CHECKS_SHA256",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }

    let pack_directory = env::var_os(PACK_DIRECTORY_ENV);
    let metadata_digest = env::var_os(METADATA_DIGEST_ENV);
    let out_directory = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    let generated_path = out_directory.join(GENERATED_FILE);
    if env::var("PROFILE").as_deref() == Ok("release")
        && noid_chain::consensus::params::V2_ACTIVATION_HEIGHT.is_some()
    {
        assert!([RETIREMENT_KEYS_ENV, RETIREMENT_PIN0_ENV, RETIREMENT_PIN1_ENV]
            .into_iter().all(|name| env::var_os(name).is_some()),
            "scheduled v2 releases require independently pinned retirement keys for origin-format interoperability");
    }
    write_if_changed(
        &out_directory.join("retirement_keys.rs"),
        b"static GENERATED_RETIREMENT_KEYS: Option<EmbeddedRetirementKeys> = None;\n",
    );
    if env::var_os("CARGO_FEATURE_RETIRED_HISTORY").is_some() {
        assert!(
            env::var_os(V2_PACK_ENV).is_some()
                && env::var_os(RETIREMENT_KEYS_ENV).is_some()
                && pack_directory.is_some(),
            "retired-history requires pinned legacy metadata, the v2 pack and retirement keys"
        );
        // Runtime construction additionally rejects an unscheduled v2 pack.
    }

    match (pack_directory, metadata_digest) {
        (None, None) => {
            assert_ne!(
                env::var("PROFILE").as_deref(),
                Ok("release"),
                "release node builds require {PACK_DIRECTORY_ENV} and {METADATA_DIGEST_ENV}"
            );
            write_if_changed(
                &generated_path,
                b"static GENERATED_HISTORY_STEP_PACK: Option<EmbeddedHistoryStepPack> = None;\n",
            );
        }
        (Some(pack_directory), Some(metadata_digest)) => {
            let metadata_digest = parse_hex_digest(
                &metadata_digest
                    .into_string()
                    .unwrap_or_else(|_| panic!("{METADATA_DIGEST_ENV} is not UTF-8")),
                METADATA_DIGEST_ENV,
            );
            embed_release_pack(
                &PathBuf::from(pack_directory),
                metadata_digest,
                &out_directory,
                &generated_path,
            );
        }
        _ => panic!("{PACK_DIRECTORY_ENV} and {METADATA_DIGEST_ENV} must be set together"),
    }
    let release = env::var("PROFILE").as_deref() == Ok("release");
    embed_v2_pack(
        &out_directory,
        V2_PACK_ENV,
        V2_BANK_ENV,
        "v2",
        "GENERATED_V2_PACK",
        None,
        release && noid_chain::consensus::params::V2_ACTIVATION_HEIGHT.is_some(),
    );
    let activation = noid_chain::consensus::params::OWNER_AUTHORIZATION_ACTIVATION_HEIGHT;
    let finance_requested =
        env::var_os(V21_PACK_ENV).is_some() || env::var_os(V21_BANK_ENV).is_some();
    let authorization_requested = env::var_os(AUTHORIZATION_PACK_ENV).is_some()
        || env::var_os(AUTHORIZATION_BANK_ENV).is_some();
    assert!(
        !(finance_requested && authorization_requested),
        "configure one post-activation proof bank"
    );
    embed_v21_pack(&out_directory, release && activation.is_some());
    embed_v2_pack(
        &out_directory,
        AUTHORIZATION_PACK_ENV,
        AUTHORIZATION_BANK_ENV,
        "authorization",
        "GENERATED_AUTHORIZATION_PACK",
        activation,
        false,
    );
}

fn embed_v21_pack(out_directory: &Path, required: bool) {
    use noid_miner::v21_artifacts::*;
    use noid_recursive::acceptance::history_step::v2::capacity_banked::Class;
    let generated = out_directory.join("v21_pack.rs");
    match (env::var_os(V21_PACK_ENV), env::var_os(V21_BANK_ENV)) {
        (None, None) => {
            assert!(
                !required,
                "scheduled v2.1 release builds require {V21_PACK_ENV} and {V21_BANK_ENV}"
            );
            write_if_changed(
                &generated,
                b"static GENERATED_V21_PACK: Option<EmbeddedV21Pack> = None;\n",
            );
        }
        (Some(directory), Some(pin)) => {
            let bank = parse_hex_digest(&pin.into_string().expect("UTF-8 v2.1 bank"), V21_BANK_ENV);
            let directory = PathBuf::from(directory);
            let metadata_path = directory.join(V21_METADATA_FILE);
            let metadata = read_bounded(&metadata_path, V21_METADATA_MAX_BYTES as u64);
            let runtime_metadata = decode_v21_runtime_metadata_pinned(&metadata, bank)
                .expect("pinned v2.1 runtime metadata");
            assert_eq!(
                runtime_metadata.bank().config().schedule(),
                noid_chain::consensus::forks::ACTIVE_SCHEDULE,
                "v2.1 artifact schedule differs from the executable profile"
            );
            let activation = noid_chain::consensus::params::V2_1_ACTIVATION_HEIGHT;
            assert!(
                activation.is_some(),
                "v2.1 artifacts require a scheduled activation"
            );
            for class in Class::ALL {
                assert_eq!(
                    runtime_metadata
                        .bank()
                        .config()
                        .class(class)
                        .authorization_activation(),
                    activation,
                    "v2.1 artifact activation differs from the executable profile"
                );
            }
            println!("cargo:rerun-if-changed={}", metadata_path.display());
            let staged = out_directory.join("embedded-v21");
            fs::create_dir_all(&staged).expect("v2.1 staging directory");
            write_if_changed(&staged.join(V21_METADATA_FILE), &metadata);
            let mut sources = Vec::new();
            let mut seals = Vec::new();
            let mut checks = matrix_checks::PackChecks::new(&directory, "v21", bank, &metadata, Class::ALL.len());
            for class in Class::ALL {
                let name = v21_matrix_file_name(class);
                let path = directory.join(name);
                let compressed = read_bounded(&path, V21_MATRIX_MAX_BYTES as u64);
                let seal = checks.authenticate(name, &compressed,
                    runtime_metadata.bank().config().class(class).shape(),
                    runtime_metadata.bank().matrix_digest(class), || {
                        runtime_metadata.preflight_build_matrix(class, &compressed)
                            .expect("v2.1 matrix semantic authentication before embedding")
                    });
                println!("cargo:rerun-if-changed={}", path.display());
                write_if_changed(&staged.join(name), &compressed);
                sources.push(format!(
                    "include_bytes!(concat!(env!(\"OUT_DIR\"), \"/embedded-v21/{name}\"))"
                ));
                seals.push(format!(
                    "unsafe {{ noid_ivc_core::field_r1cs::BuildAuthenticatedFieldR1csSeal::from_release_build(noid_ivc_core::proof::FieldShape {{ m: {}, k_log: {}, k_skip: {}, const_pin: {} }}, {}, {}) }}",
                    seal.shape().m, seal.shape().k_log, seal.shape().k_skip,
                    render_const_pin(seal.shape().const_pin), render_digest(seal.statement_digest()), seal.canonical_bytes(),
                ));
            }
            checks.write(&staged);
            write_if_changed(&generated, format!(
                "static GENERATED_V21_PACK: Option<EmbeddedV21Pack> = Some(EmbeddedV21Pack {{\n\
                metadata: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/embedded-v21/{V21_METADATA_FILE}\")),\n\
                compressed_matrices: [{}],\n\
                release_bank: {},\n\
                build_seals: [{}],\n}});\n", sources.join(", "), render_digest(bank), seals.join(", ")
            ).as_bytes());
        }
        _ => panic!("{V21_PACK_ENV} and {V21_BANK_ENV} must be set together"),
    }
}

fn embed_v2_pack(
    out_directory: &Path,
    pack_env: &str,
    bank_env: &str,
    label: &str,
    static_name: &str,
    activation: Option<u64>,
    required: bool,
) {
    use noid_miner::v2_artifacts::*;
    let generated = out_directory.join(format!("{label}_pack.rs"));
    match (env::var_os(pack_env), env::var_os(bank_env)) {
        (None, None) => {
            assert!(
                !required,
                "scheduled v2 release builds require {pack_env} and {bank_env}"
            );
            write_if_changed(
                &generated,
                format!("static {static_name}: Option<EmbeddedV2Pack> = None;\n").as_bytes(),
            );
        }
        (Some(directory), Some(pin)) => {
            let bank = parse_hex_digest(&pin.into_string().expect("UTF-8 v2 bank"), bank_env);
            let directory = PathBuf::from(directory);
            let metadata_path = directory.join(V2_METADATA_FILE);
            let metadata = read_bounded(&metadata_path, V2_METADATA_MAX_BYTES as u64);
            let runtime_metadata = decode_v2_runtime_metadata_pinned(&metadata, bank)
                .expect("pinned v2 runtime metadata");
            assert_eq!(
                runtime_metadata.bank().config().schedule(),
                noid_chain::consensus::forks::ACTIVE_SCHEDULE,
                "v2 artifact schedule differs from the executable profile",
            );
            assert_eq!(
                runtime_metadata
                    .bank()
                    .config()
                    .class(noid_recursive::acceptance::history_step::v2::banked::Class::Small)
                    .authorization_activation(),
                activation,
                "authorization artifact activation differs from the executable profile"
            );
            println!("cargo:rerun-if-changed={}", metadata_path.display());
            let staged = out_directory.join(format!("embedded-{label}"));
            fs::create_dir_all(&staged).expect("v2 staging directory");
            write_if_changed(&staged.join(V2_METADATA_FILE), &metadata);
            let mut sources = Vec::new();
            let mut seals = Vec::new();
            let mut checks = matrix_checks::PackChecks::new(&directory, label, bank, &metadata,
                noid_recursive::acceptance::history_step::v2::banked::Class::ALL.len());
            for class in noid_recursive::acceptance::history_step::v2::banked::Class::ALL {
                let name = v2_matrix_file_name(class);
                let path = directory.join(name);
                let compressed = read_bounded(&path, V2_MATRIX_MAX_BYTES as u64);
                let seal = checks.authenticate(name, &compressed,
                    runtime_metadata.bank().config().class(class).shape(),
                    runtime_metadata.bank().matrix_digest(class), || {
                        runtime_metadata.preflight_build_matrix(class, &compressed)
                            .expect("v2 matrix semantic authentication before embedding")
                    });
                println!("cargo:rerun-if-changed={}", path.display());
                write_if_changed(&staged.join(name), &compressed);
                sources.push(format!(
                    "include_bytes!(concat!(env!(\"OUT_DIR\"), \"/embedded-{label}/{name}\"))"
                ));
                seals.push(format!(
                    "unsafe {{ noid_ivc_core::field_r1cs::BuildAuthenticatedFieldR1csSeal::from_release_build(noid_ivc_core::proof::FieldShape {{ m: {}, k_log: {}, k_skip: {}, const_pin: {} }}, {}, {}) }}",
                    seal.shape().m, seal.shape().k_log, seal.shape().k_skip,
                    render_const_pin(seal.shape().const_pin), render_digest(seal.statement_digest()),
                    seal.canonical_bytes(),
                ));
            }
            checks.write(&staged);
            write_if_changed(&generated, format!(
                "static {static_name}: Option<EmbeddedV2Pack> = Some(EmbeddedV2Pack {{\n\
                metadata: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/embedded-{label}/{V2_METADATA_FILE}\")),\n\
                compressed_matrices: [{}],\n\
                release_bank: {},\n\
                build_seals: [{}],\n}});\n",
                sources.join(", "), render_digest(bank), seals.join(", ")).as_bytes());
        }
        _ => panic!("{pack_env} and {bank_env} must be set together"),
    }
}

fn embed_release_pack(
    pack_root: &Path,
    metadata_digest: [u8; 32],
    out_directory: &Path,
    generated_path: &Path,
) {
    let version_directory = pack_root.join(HISTORY_STEP_PACK_VERSION_DIRECTORY);
    let metadata_path = version_directory.join(HISTORY_STEP_RUNTIME_METADATA_FILE);
    let metadata = read_bounded(
        &metadata_path,
        HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES as u64,
    );
    let runtime_metadata = decode_history_step_runtime_metadata_pinned(&metadata, metadata_digest)
        .unwrap_or_else(|error| {
            panic!(
                "validate pinned HistoryStep runtime metadata {}: {error}",
                metadata_path.display()
            )
        });
    println!("cargo:rerun-if-changed={}", metadata_path.display());

    let staged_directory = out_directory.join(STAGED_DIRECTORY);
    fs::create_dir_all(&staged_directory).unwrap_or_else(|error| {
        panic!(
            "create embedded HistoryStep staging directory {}: {error}",
            staged_directory.display()
        )
    });
    write_if_changed(
        &staged_directory.join(HISTORY_STEP_RUNTIME_METADATA_FILE),
        &metadata,
    );

    embed_retirement_keys(out_directory, runtime_metadata.bank());
    if env::var_os("CARGO_FEATURE_RETIRED_HISTORY").is_some() {
        write_if_changed(generated_path, format!(
            "static GENERATED_HISTORY_STEP_PACK: Option<EmbeddedHistoryStepPack> = Some(EmbeddedHistoryStepPack {{\n\
            runtime_metadata: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{STAGED_DIRECTORY}/{HISTORY_STEP_RUNTIME_METADATA_FILE}\")),\n\
            runtime_metadata_digest: {}, leaves: None,\n}});\n", render_digest(metadata_digest)).as_bytes());
        return;
    }

    let mut build_leaves = Vec::with_capacity(HISTORY_STEP_PACK_LEAF_COUNT);
    for index in 0..HISTORY_STEP_PACK_LEAF_COUNT {
        let class = CanonicalHistoryStepClassId::from_index(index).expect("canonical class");
        let leaf_path = version_directory.join(history_step_matrix_file_name(class));
        let compressed = read_bounded(&leaf_path, MAX_COMPRESSED_LEAF_BYTES);
        let entry = runtime_metadata.bank().entry(class);
        // Pack generation/preflight authenticates the relation once. Building
        // an executable only stages those approved bytes and records the
        // decoded-size bound required by runtime decompression.
        let leaf = stage_leaf(
            &compressed,
            entry.shape(),
            entry.matrix_digest(),
            &leaf_path,
        );
        write_if_changed(
            &staged_directory.join(history_step_matrix_file_name(class)),
            &compressed,
        );
        build_leaves.push(leaf);
        println!("cargo:rerun-if-changed={}", leaf_path.display());
    }
    let build_leaves: [EmbeddedLeaf; HISTORY_STEP_PACK_LEAF_COUNT] = build_leaves
        .try_into()
        .unwrap_or_else(|_| unreachable!("one build result per HistoryStep class"));
    let generated = render_generated_pack(metadata_digest, &build_leaves);
    write_if_changed(generated_path, generated.as_bytes());
}

fn embed_retirement_keys(
    out: &Path,
    bank: &noid_recursive::acceptance::history_step_bank::PinnedHistoryStepClassBank,
) {
    match (env::var_os(RETIREMENT_KEYS_ENV), env::var_os(RETIREMENT_PIN0_ENV), env::var_os(RETIREMENT_PIN1_ENV)) {
        (None, None, None) => {},
        (Some(directory), Some(first), Some(second)) => {
            let directory = PathBuf::from(directory);
            let pins = [parse_hex_digest(&first.into_string().expect("UTF-8 retirement pin"), RETIREMENT_PIN0_ENV), parse_hex_digest(&second.into_string().expect("UTF-8 retirement pin"), RETIREMENT_PIN1_ENV)];
            let keys: [Vec<u8>; 2] = std::array::from_fn(|index| {
                let path = directory.join(format!("class-{index}.key"));
                println!("cargo:rerun-if-changed={}", path.display());
                read_bounded(&path, noid_ivc_core::matrix_claim::sparse_c1::SPARSE_EVALUATION_KEY_BYTES as u64)
            });
            noid_recursive::acceptance::history_step::v2::banked::PinnedRetirementKeys::from_release(bank, [&keys[0], &keys[1]], pins).expect("release-pinned retirement preprocessing keys");
            for (index, bytes) in keys.iter().enumerate() { write_if_changed(&out.join(format!("retirement-{index}.key")), bytes); }
            write_if_changed(&out.join("retirement_keys.rs"), format!(
                "static GENERATED_RETIREMENT_KEYS: Option<EmbeddedRetirementKeys> = Some(EmbeddedRetirementKeys {{\n\
                encoded: [include_bytes!(concat!(env!(\"OUT_DIR\"), \"/retirement-0.key\")), include_bytes!(concat!(env!(\"OUT_DIR\"), \"/retirement-1.key\"))],\n\
                release_pins: [{}, {}],\n}});\n", render_digest(pins[0]), render_digest(pins[1])).as_bytes());
        },
        _ => panic!("{RETIREMENT_KEYS_ENV}, {RETIREMENT_PIN0_ENV}, {RETIREMENT_PIN1_ENV} must be set together"),
    }
}

fn stage_leaf(
    compressed: &[u8],
    shape: FieldShape,
    statement_digest: [u8; 32],
    path: &Path,
) -> EmbeddedLeaf {
    let mut decoder = zstd::stream::read::Decoder::new(compressed)
        .unwrap_or_else(|error| panic!("open compressed matrix {}: {error}", path.display()));
    decoder
        .window_log_max(ZSTD_WINDOW_LOG_MAX)
        .unwrap_or_else(|error| panic!("bound zstd window for {}: {error}", path.display()));
    let canonical_bytes = std::io::copy(
        &mut decoder.take(MAX_CANONICAL_LEAF_BYTES as u64 + 1),
        &mut std::io::sink(),
    )
    .unwrap_or_else(|error| panic!("measure decoded matrix {}: {error}", path.display()));
    assert!(
        canonical_bytes <= MAX_CANONICAL_LEAF_BYTES as u64,
        "HistoryStep matrix {} exceeds the canonical size bound",
        path.display()
    );
    EmbeddedLeaf {
        seal: EmbeddedLeafSeal {
            shape,
            statement_digest,
            canonical_bytes: usize::try_from(canonical_bytes)
                .expect("bounded canonical matrix length fits usize"),
        },
    }
}

fn read_bounded(path: &Path, max_bytes: u64) -> Vec<u8> {
    let metadata = fs::metadata(path)
        .unwrap_or_else(|error| panic!("inspect release artifact {}: {error}", path.display()));
    assert!(
        metadata.is_file() && metadata.len() <= max_bytes,
        "release artifact {} is not a bounded regular file",
        path.display()
    );
    fs::read(path)
        .unwrap_or_else(|error| panic!("read release artifact {}: {error}", path.display()))
}

fn parse_hex_digest(encoded: &str, variable: &str) -> [u8; 32] {
    assert_eq!(
        encoded.len(),
        64,
        "{variable} must be exactly 64 lowercase hexadecimal characters"
    );
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let high = decode_lower_hex(encoded.as_bytes()[index * 2])
            .unwrap_or_else(|| panic!("{variable} is not lowercase hexadecimal"));
        let low = decode_lower_hex(encoded.as_bytes()[index * 2 + 1])
            .unwrap_or_else(|| panic!("{variable} is not lowercase hexadecimal"));
        *byte = (high << 4) | low;
    }
    digest
}

const fn decode_lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn render_generated_pack(
    metadata_digest: [u8; 32],
    leaves: &[EmbeddedLeaf; HISTORY_STEP_PACK_LEAF_COUNT],
) -> String {
    let mut generated = String::from(
        "static GENERATED_HISTORY_STEP_PACK: Option<EmbeddedHistoryStepPack> =\n\
         Some(EmbeddedHistoryStepPack {\n",
    );
    writeln!(
        &mut generated,
        "    runtime_metadata: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{STAGED_DIRECTORY}/{HISTORY_STEP_RUNTIME_METADATA_FILE}\")),"
    )
    .expect("writing to String cannot fail");
    writeln!(
        &mut generated,
        "    runtime_metadata_digest: {},",
        render_digest(metadata_digest)
    )
    .expect("writing to String cannot fail");
    generated.push_str("    leaves: Some([\n");
    for (index, leaf) in leaves.iter().enumerate() {
        let class = CanonicalHistoryStepClassId::from_index(index).expect("canonical class");
        let seal = leaf.seal;
        writeln!(
            &mut generated,
            "        unsafe {{ noid_miner::EmbeddedHistoryStepMatrixLeaf::from_release_build(\n            noid_recursive::acceptance::history_step_bank::CanonicalHistoryStepClassId::from_index({index}).unwrap(),\n            include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{STAGED_DIRECTORY}/{}\")),\n            noid_ivc_core::field_r1cs::BuildAuthenticatedFieldR1csSeal::from_release_build(\n                noid_ivc_core::proof::FieldShape {{ m: {}, k_log: {}, k_skip: {}, const_pin: {} }},\n                {},\n                {},\n            ),\n        ) }},",
            history_step_matrix_file_name(class),
            seal.shape.m,
            seal.shape.k_log,
            seal.shape.k_skip,
            render_const_pin(seal.shape.const_pin),
            render_digest(seal.statement_digest),
            seal.canonical_bytes,
        )
        .expect("writing to String cannot fail");
    }
    generated.push_str("    ]),\n});\n");
    generated
}

fn render_const_pin(pin: Option<usize>) -> String {
    pin.map_or_else(|| "None".to_owned(), |column| format!("Some({column})"))
}

fn render_digest(digest: [u8; 32]) -> String {
    let mut rendered = String::from("[");
    for (index, byte) in digest.iter().enumerate() {
        if index != 0 {
            rendered.push_str(", ");
        }
        write!(&mut rendered, "0x{byte:02x}").expect("writing to String cannot fail");
    }
    rendered.push(']');
    rendered
}

fn write_if_changed(path: &Path, bytes: &[u8]) {
    if matches!(fs::read(path), Ok(existing) if existing == bytes) {
        return;
    }
    fs::write(path, bytes)
        .unwrap_or_else(|error| panic!("write generated artifact {}: {error}", path.display()));
}
