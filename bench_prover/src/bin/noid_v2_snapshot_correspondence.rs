// SPDX-License-Identifier: Apache-2.0

//! Offline check of the genuine v2 terminal-to-snapshot admission boundary.
//! The archived isolated activation is never promoted to mainnet authority.

use noid_chain::{storage::MdbxChainContext, Block};
use noid_miner::{history_step_artifacts::*, v2_artifacts::*, HistoryProtocolRuntime};
use noid_recursive::{
    acceptance::history_step::v2::banked as v2, CanonicalHistoryStepClassId,
    HistoryStepMatrixLease, HistoryStepMatrixSource, HistoryStepMatrixSourceError,
    HistoryStepRuntime,
};
use serde_json::json;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

static ROW_LOADS: AtomicUsize = AtomicUsize::new(0);
struct NoLegacyRows;
impl HistoryStepMatrixSource for NoLegacyRows {
    fn load(
        &self,
        _: CanonicalHistoryStepClassId,
    ) -> Result<HistoryStepMatrixLease, HistoryStepMatrixSourceError> {
        ROW_LOADS.fetch_add(1, Ordering::Relaxed);
        Err(HistoryStepMatrixSourceError)
    }
}

fn pin(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}
fn read(path: &Path, cap: usize) -> Vec<u8> {
    assert!(std::fs::metadata(path).unwrap().len() <= cap as u64);
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() <= cap);
    bytes
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(args.len(), 8, "legacy metadata, isolated v2 metadata, release keys directory, retired origin, v2 block, v2 terminal, isolated matrix pack, output JSON required");
    let started = Instant::now();
    let metadata = decode_history_step_runtime_metadata_pinned(
        &read(Path::new(&args[0]), HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES),
        pin("ad463bd76e27df3c0f414f4fd7640cfb5c45cc7f3a09e44a2f7bc7a8b869485b"),
    )
    .unwrap();
    let (bank, parts) = metadata.into_parts();
    let legacy = Arc::new(HistoryStepRuntime::new(bank, Box::new(NoLegacyRows), parts).unwrap());
    let metadata = decode_v2_runtime_metadata_pinned(
        &read(Path::new(&args[1]), V2_METADATA_MAX_BYTES),
        pin("be82f3bec102f03c63715dac9bb4a939cb9aa5b21d013e38402b321fd8a41fa9"),
    )
    .unwrap();
    let compressed = v2::Class::ALL.map(|class| {
        Arc::from(read(
            &Path::new(&args[6]).join(v2_matrix_file_name(class)),
            V2_MATRIX_MAX_BYTES,
        ))
    });
    // File-based loading performs the complete semantic matrix scan. No
    // embedded build seal or caller-supplied pre-authentication bypass is used.
    let current = Arc::new(metadata.into_runtime(compressed).unwrap());
    let encoded =
        [0, 1].map(|index| read(&Path::new(&args[2]).join(format!("class-{index}.key")), 304));
    let release_pins = [
        pin("0651ce507810b61213cbdc0e9f99436aec3a7922cc662bfba6128b466453c8b2"),
        pin("c301274d50dc02fd5c383f2e71629075729a954a768f5051388ec2040bce0267"),
    ];
    let origin_bytes = read(Path::new(&args[3]), v2::MAX_RETIREMENT_ORIGIN_BYTES);
    let certificate = v2::RetirementOriginCertificate::from_bytes(&origin_bytes).unwrap();
    let epoch = *certificate.legacy_certificate().epoch_header();
    let block = Block::from_bytes(&read(
        Path::new(&args[4]),
        noid_chain::consensus::wire_limits::MAX_BLOCK_BYTES,
    ))
    .unwrap();
    let header = block.header;
    assert!(header.height >= current.bank().config().activation_height());
    let terminal = read(
        Path::new(&args[5]),
        noid_chain::consensus::wire_limits::history_step_terminal_bytes_limit(header.height),
    );
    let scratch = tempfile::tempdir().unwrap();
    let origin_directory = scratch.path().join("origins");
    let runtime = || {
        HistoryProtocolRuntime::new(
            Some(legacy.clone()),
            Some(current.clone()),
            origin_directory.clone(),
        )
        .unwrap()
        .with_retirement_keys(
            v2::PinnedRetirementKeys::from_release(
                legacy.bank(),
                [&encoded[0], &encoded[1]],
                release_pins,
            )
            .unwrap(),
        )
        .unwrap()
    };
    let dispatcher = runtime();
    dispatcher.install_origin_bytes(&origin_bytes).unwrap();
    let context = MdbxChainContext::open_or_create(&scratch.path().join("state")).unwrap();
    let admit = |dispatcher: &HistoryProtocolRuntime, header, epoch, bytes| {
        context.verify_snapshot_boundary(header, epoch, bytes, |claim| {
            dispatcher.verify_terminal(
                claim.terminal_bytes,
                &claim.header,
                &claim.epoch_anchor_header,
            )
        })
    };
    let baseline = admit(&dispatcher, header, epoch, terminal.clone()).unwrap();
    assert_eq!(baseline.header(), &header);
    assert_eq!(baseline.history_step_terminal_bytes(), terminal);
    let mut observations = vec![json!({"check":"valid_v2_snapshot_boundary",
        "accepted":true,"height":header.height,"activation_height":current.bank().config().activation_height(),"bank":hex::encode(current.bank().digest()),
        "state_root":hex::encode(header.state_root),"terminal_bytes":terminal.len(),
        "terminal_callback":"HistoryProtocolRuntime::verify_terminal"})];
    for field in [
        "state_root",
        "live_count",
        "alloc_cursor",
        "height",
        "previous_hash",
    ] {
        let mut changed = header;
        match field {
            "state_root" => changed.state_root[0] ^= 1,
            "live_count" => changed.active_slot_count ^= 1,
            "alloc_cursor" => changed.alloc_counter ^= 1,
            "height" => changed.height += 1,
            _ => changed.prev_block_hash[0] ^= 1,
        }
        let error = admit(&dispatcher, changed, epoch, terminal.clone()).unwrap_err();
        observations.push(json!({"check":"header_substitution", "field":field,
            "rejected":true,"error":error.to_string()}));
    }
    let mut changed_epoch = epoch;
    changed_epoch.state_root[0] ^= 1;
    let error = admit(&dispatcher, header, changed_epoch, terminal.clone()).unwrap_err();
    observations.push(
        json!({"check":"epoch_substitution_same_height", "rejected":true,
        "error":error.to_string()}),
    );
    // Mutate the proof tail, leaving the authentic public prefix intact. The
    // already populated carried-claim cache must not grant terminal acceptance.
    let mut changed = terminal.clone();
    *changed.last_mut().unwrap() ^= 1;
    let error = admit(&dispatcher, header, epoch, changed).unwrap_err();
    observations.push(
        json!({"check":"proof_tail_substitution_after_valid_admission",
        "rejected":true,"error":error.to_string()}),
    );
    drop(dispatcher);
    // A new dispatcher has no verified-origin cache. It must reconstruct the
    // capability from the retained certificate before admitting the terminal.
    let restarted = runtime();
    let replay = admit(&restarted, header, epoch, terminal).unwrap();
    assert_eq!(replay.header(), &header);
    observations.push(json!({"check":"origin_cache_restart", "accepted":true,
        "explicit_origin_reinstallation":false}));
    assert_eq!(ROW_LOADS.load(Ordering::Relaxed), 0);
    assert_eq!(
        context.tip_height(),
        0,
        "verification alone cannot install canonical State"
    );
    observations.push(
        json!({"check":"authority_boundary", "legacy_row_load_attempts":0,
        "canonical_tip_after_all_admissions":0}),
    );
    let report = json!({"productionCommit":"50d6dac5a37b9f1be425b5e6cd823de48f843b50",
        "scope":"genuine isolated v2 terminal through production dispatcher and snapshot capability constructor; sealed header validation and durable State installation checked separately",
        "elapsed_ms":started.elapsed().as_millis(),"observations":observations});
    std::fs::write(&args[7], serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{report}");
}
