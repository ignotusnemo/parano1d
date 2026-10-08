// SPDX-License-Identifier: Apache-2.0

//! Offline audit of archived, genuinely verified retirement requests. This
//! tool changes no verifier, key, bank or network parameter. An isolated bank
//! remains isolated; passing these checks does not establish QROM soundness.

use noid_ivc_core::{matrix_claim::sparse_c1::*, pcs};
use noid_miner::{history_step_artifacts::*, v2_artifacts::*};
use noid_recursive::{
    acceptance::history_step::{self as history, v2::banked as v2},
    acceptance::history_step_bank::retirement::*,
    CanonicalHistoryStepClassId, HistoryStepMatrixLease, HistoryStepMatrixSource,
    HistoryStepMatrixSourceError, HistoryStepRuntime,
};
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
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

fn pin(text: &str) -> [u8; 32] {
    hex::decode(text).unwrap().try_into().unwrap()
}

fn read(path: &Path, cap: usize) -> Vec<u8> {
    assert!(std::fs::metadata(path).unwrap().len() <= cap as u64);
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() <= cap);
    bytes
}

fn cubic_bytes(log: usize) -> usize {
    // Each round transmits three non-constant coefficients. The constant is
    // reconstructed from the current claim; the three final values follow.
    32 * (3 * log + 3)
}
fn product_bytes(log: usize) -> usize {
    (0..log).map(cubic_bytes).sum()
}

/// Compute byte spans from public PCS geometry, independently of the sparse
/// decoder. Only the first authenticated initial leaf/path of each column is
/// touched. The original valid reduction and all request bytes remain intact.
fn opening_spans(key: &SparseMatrixEvaluationKey, bytes: &[u8]) -> Vec<(usize, usize, usize)> {
    let k = key.shape().k_log;
    let log = key.geometry().padded_entries.trailing_zeros() as usize;
    let mut offset = 8 + 32 + 32 + 32 * (2 * k + 2);
    offset += 4 * 32 + cubic_bytes(log);
    for query_log in [k + 1, k] {
        offset += 4 * 32 + 2 * product_bytes(query_log) + 2 * product_bytes(log);
    }
    let points = [2, 2, 1, 1, 1, 1, 1, 3, 3, 3, 3];
    let mut spans = Vec::new();
    for (column, (parameters, point_count)) in key.opening_parameters().zip(points).enumerate() {
        offset += 32 * point_count;
        let rounds = parameters.m - pcs::LOG_PACKING;
        let arities = pcs::compute_fri_arities(parameters.log_dim());
        let (commits, tail) = pcs::fri_commit_layout(parameters.k_code(), &arities);
        let tail_len = tail.map_or(0, |(length, _)| length);
        let header =
            64 * rounds + 32 * (1 + commits + 2 + (1 << parameters.log_inv_rate) + tail_len) + 8;
        let leaf_len = 1usize << parameters.log_batch_size;
        let path_len = parameters.k_code();
        let row_leaf = 1usize << arities[0];
        let row_path = parameters.k_code() - arities[0];
        let mut consumed = arities[0];
        let epoch_bytes: usize = arities
            .iter()
            .skip(1)
            .take(commits)
            .map(|arity| {
                consumed += arity;
                32 * ((1usize << arity) + parameters.k_code() - consumed)
            })
            .sum();
        let query_bytes = 8 + 16 * leaf_len + 32 * (path_len + row_leaf + row_path) + epoch_bytes;
        let leaf_offset = offset + header + 8;
        let path_offset = leaf_offset + 16 * leaf_len;
        assert!(path_len > 0 && path_offset + 32 <= bytes.len());
        spans.push((column, leaf_offset, path_offset));
        offset += header
            + pcs::default_fri_queries(parameters.log_dim(), parameters.log_inv_rate) * query_bytes;
    }
    assert_eq!(
        offset,
        bytes.len(),
        "independent sparse wire inventory must reach exact EOF"
    );
    spans
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(args.len(), 5, "legacy runtime, isolated v2 metadata, mainnet v2 metadata, archived certificate directory, output JSON required");
    let started = Instant::now();
    let directory = Path::new(&args[3]);
    let metadata = decode_history_step_runtime_metadata_pinned(
        &read(Path::new(&args[0]), HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES),
        pin("ad463bd76e27df3c0f414f4fd7640cfb5c45cc7f3a09e44a2f7bc7a8b869485b"),
    )
    .unwrap();
    let (bank, parts) = metadata.into_parts();
    let legacy = HistoryStepRuntime::new(bank, Box::new(NoLegacyRows), parts).unwrap();
    let next = decode_v2_runtime_metadata_pinned(
        &read(Path::new(&args[1]), V2_METADATA_MAX_BYTES),
        pin("be82f3bec102f03c63715dac9bb4a939cb9aa5b21d013e38402b321fd8a41fa9"),
    )
    .unwrap();
    let mainnet = decode_v2_runtime_metadata_pinned(
        &read(Path::new(&args[2]), V2_METADATA_MAX_BYTES),
        pin("c2a6df736b0d0da22e285b6930b11cf44b520d65b52c7dfe78f44fe0cd48e76e"),
    )
    .unwrap();
    let key_bytes = [0, 1].map(|index| {
        read(
            &directory.join(format!("class-{index}.key")),
            SPARSE_EVALUATION_KEY_BYTES,
        )
    });
    let key_pins = [
        pin("0651ce507810b61213cbdc0e9f99436aec3a7922cc662bfba6128b466453c8b2"),
        pin("c301274d50dc02fd5c383f2e71629075729a954a768f5051388ec2040bce0267"),
    ];
    let keys = v2::PinnedRetirementKeys::from_release(
        legacy.bank(),
        [&key_bytes[0], &key_bytes[1]],
        key_pins,
    )
    .unwrap();
    let wire = read(
        &directory.join("retired-v2-origin.bin"),
        v2::MAX_RETIREMENT_ORIGIN_BYTES,
    );
    let certificate = v2::RetirementOriginCertificate::from_bytes(&wire).unwrap();
    let verified = certificate.verify(&legacy, next.bank(), &keys).unwrap();
    assert!(
        certificate.verify(&legacy, mainnet.bank(), &keys).is_err(),
        "isolated activation cannot authenticate a mainnet origin"
    );
    let source = certificate.legacy_certificate();
    let terminal = history::decode_history_step_terminal(&legacy, source.terminal_bytes()).unwrap();
    let target = HistoryStepRetirementTarget::new(
        next.bank().config().schedule(),
        legacy.bank(),
        next.bank().digest(),
    )
    .unwrap();
    let request = history::prepare_history_step_retirement(
        &legacy,
        &terminal,
        source.parent_header(),
        source.epoch_header(),
        target,
    )
    .unwrap();
    let reduction_bytes = read(&directory.join("reduction.bin"), 8192);
    let reduction = HistoryStepRetirementReduction::decode_for(&request, &reduction_bytes).unwrap();
    let pending = request.verify_reduction(&reduction).unwrap();
    let classes: Vec<_> = pending
        .obligations()
        .map(|obligation| obligation.class_id())
        .collect();
    assert_eq!(
        classes.len(),
        2,
        "archived full origin must contain the nonselected live class"
    );
    let proofs: Vec<_> = classes
        .iter()
        .map(|class| {
            (
                *class,
                read(
                    &directory.join(format!("class-{}.proof", class.index())),
                    MAX_SPARSE_EVALUATION_PROOF_BYTES,
                ),
            )
        })
        .collect();
    let mut observations: Vec<Value> = Vec::new();
    observations.push(json!({"check":"valid_full_origin", "accepted":true, "parent_height":source.parent_header().height, "isolated_activation":next.bank().config().activation_height(), "isolated_bank":hex::encode(next.bank().digest()), "mainnet_activation":mainnet.bank().config().activation_height(), "mainnet_bank":hex::encode(mainnet.bank().digest()), "isolated_origin_rejected_by_mainnet_bank":true, "live_classes":[0,1], "tip_class":request.tip_class().index(), "request":hex::encode(request.binding()), "origin":hex::encode(verified.origin().request_binding())}));
    for (obligation, (_, encoded)) in pending.obligations().zip(&proofs) {
        let class = obligation.class_id().index();
        let key = SparseMatrixEvaluationKey::from_bytes_pinned(&key_bytes[class], key_pins[class])
            .unwrap();
        let proof = SparseMatrixEvaluationProof::from_bytes(
            &key,
            request.binding(),
            obligation.claim(),
            encoded,
        )
        .unwrap();
        key.verify(request.binding(), obligation.claim(), &proof)
            .unwrap();
        let mut point_rejections = 0;
        for coordinate in 0..obligation.claim().point.len() {
            for limb in [0, 16] {
                let mut changed = encoded.clone();
                changed[72 + 32 * coordinate + limb] ^= 1;
                assert!(SparseMatrixEvaluationProof::from_bytes(
                    &key,
                    request.binding(),
                    obligation.claim(),
                    &changed
                )
                .is_err());
                point_rejections += 1;
            }
        }
        for limb in [0, 16] {
            let mut changed = encoded.clone();
            changed[72 + 32 * obligation.claim().point.len() + limb] ^= 1;
            assert!(SparseMatrixEvaluationProof::from_bytes(
                &key,
                request.binding(),
                obligation.claim(),
                &changed
            )
            .is_err());
        }
        for header_offset in [8, 40] {
            let mut changed = encoded.clone();
            changed[header_offset] ^= 1;
            assert!(SparseMatrixEvaluationProof::from_bytes(
                &key,
                request.binding(),
                obligation.claim(),
                &changed
            )
            .is_err());
        }
        let dynamic_start = 72 + 32 * (obligation.claim().point.len() + 1);
        for column in 0..4 {
            let mut changed = encoded.clone();
            changed[dynamic_start + 32 * column] ^= 1;
            assert!(SparseMatrixEvaluationProof::from_bytes(
                &key,
                request.binding(),
                obligation.claim(),
                &changed
            )
            .is_err());
            let mut evaluations = proofs.clone();
            evaluations[class].1 = changed;
            assert!(v2::RetirementOriginCertificate::new(
                source.clone(),
                reduction_bytes.clone(),
                evaluations
            )
            .unwrap()
            .verify(&legacy, next.bank(), &keys)
            .is_err());
        }
        let spans = opening_spans(&key, encoded);
        for &(column, leaf, path) in &spans {
            for (kind, offset) in [("initial_leaf", leaf), ("initial_merkle_path", path)] {
                let mut changed = encoded.clone();
                changed[offset] ^= 1;
                let decoded = SparseMatrixEvaluationProof::from_bytes(
                    &key,
                    request.binding(),
                    obligation.claim(),
                    &changed,
                )
                .unwrap();
                assert!(
                    matches!(
                        key.verify(request.binding(), obligation.claim(), &decoded),
                        Err(noid_ivc_core::matrix_claim::sparse_c1::Error::Opening(_))
                    ),
                    "column {column} {kind} must be rejected by PCS authentication"
                );
            }
        }
        observations.push(json!({"check":"request_and_opening_mutations", "class":class, "point_coordinates":obligation.claim().point.len(), "point_limb_changes_rejected":point_rejections, "value_limb_changes_rejected":2, "key_or_context_changes_rejected":2, "dynamic_root_changes_rejected_at_full_origin_entry":4, "independent_pcs_columns":spans.len(), "pcs_leaf_or_path_changes_rejected":2*spans.len(), "wire_bytes":encoded.len()}));
    }
    for omitted in 0..2 {
        let evaluations = proofs
            .iter()
            .filter(|(class, _)| class.index() != omitted)
            .cloned()
            .collect();
        assert!(v2::RetirementOriginCertificate::new(
            source.clone(),
            reduction_bytes.clone(),
            evaluations
        )
        .unwrap()
        .verify(&legacy, next.bank(), &keys)
        .is_err());
    }
    let duplicate = vec![proofs[0].clone(), proofs[0].clone()];
    assert!(v2::RetirementOriginCertificate::new(
        source.clone(),
        reduction_bytes.clone(),
        duplicate
    )
    .is_err());
    let mut reordered = proofs.clone();
    reordered.reverse();
    assert!(v2::RetirementOriginCertificate::new(
        source.clone(),
        reduction_bytes.clone(),
        reordered
    )
    .is_err());
    let mut wrong_request = reduction_bytes.clone();
    wrong_request[9] ^= 1;
    assert!(
        v2::RetirementOriginCertificate::new(source.clone(), wrong_request, proofs.clone())
            .unwrap()
            .verify(&legacy, next.bank(), &keys)
            .is_err()
    );
    let mut wrong_class = proofs.clone();
    wrong_class[0].0 = CanonicalHistoryStepClassId::new(1).unwrap();
    assert!(v2::RetirementOriginCertificate::new(
        source.clone(),
        reduction_bytes.clone(),
        wrong_class
    )
    .is_err());
    assert_eq!(
        ROW_LOADS.load(Ordering::Relaxed),
        0,
        "verification must never try to load retired rows"
    );
    observations.push(json!({"check":"coverage_and_authority", "both_single_lane_omissions_rejected":true, "duplicates_rejected":true, "reordering_rejected":true, "reduction_request_substitution_rejected":true, "class_substitution_rejected":true, "legacy_row_load_attempts":0, "origin_boundary_preserved":verified.origin().boundary()==request.boundary()}));
    let report = json!({"productionCommit":"50d6dac5a37b9f1be425b5e6cd823de48f843b50", "scope":"archived valid isolated-network request, release legacy matrices and preprocessing keys, pinned production verifier code; not a mainnet origin or a QROM proof", "elapsed_ms":started.elapsed().as_millis(), "observations":observations});
    std::fs::write(&args[4], serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{report}");
}
