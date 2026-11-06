// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Offline preparation and row-free verification of the v2.1 handoff.

use noid_ivc_core::{field_r1cs::CompactFieldR1cs, matrix_claim::sparse_c1::*};
use noid_miner::{history_step_artifacts::*, v21_artifacts::*, v2_artifacts::*};
use noid_recursive::acceptance::history_step::v2::{banked as v2, capacity_banked as v21};
use noid_recursive::{
    HistoryStepMatrixLease, HistoryStepMatrixSource, HistoryStepMatrixSourceError,
    HistoryStepRuntime,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn pin(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)
        .map_err(err)?
        .try_into()
        .map_err(|_| "32-byte pin required".into())
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(err)?;
    if !meta.is_file() || meta.len() > limit as u64 {
        return Err("artifact file bound".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(err)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    if bytes.len() > limit {
        return Err("artifact grew".into());
    }
    Ok(bytes)
}
fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    if path.exists() {
        if read(path, bytes.len())? == bytes {
            return Ok(());
        }
        return Err(format!("existing artifact differs: {}", path.display()));
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(err)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(err)
}

#[derive(Deserialize)]
struct Inputs {
    legacy_metadata: PathBuf,
    legacy_pin: String,
    v2_pack: PathBuf,
    v2_pin: String,
    v21_metadata: PathBuf,
    v21_pin: String,
    legacy_keys: [PathBuf; 2],
    legacy_key_pins: [String; 2],
    v2_key_pins: Option<[String; 2]>,
    authorization_origin: PathBuf,
}
impl Inputs {
    fn previous_metadata(&self) -> Result<V2RuntimeMetadata> {
        decode_v2_runtime_metadata_pinned(
            &read(&self.v2_pack.join(V2_METADATA_FILE), V2_METADATA_MAX_BYTES)?,
            pin(&self.v2_pin)?,
        )
    }
    fn next_metadata(&self) -> Result<V21RuntimeMetadata> {
        decode_v21_runtime_metadata_pinned(
            &read(&self.v21_metadata, V21_METADATA_MAX_BYTES)?,
            pin(&self.v21_pin)?,
        )
    }
    fn predecessor(&self, bank: &v2::Bank, bytes: &[u8]) -> Result<v2::VerifiedOrigin> {
        struct NoRows;
        impl HistoryStepMatrixSource for NoRows {
            fn load(
                &self,
                _: noid_recursive::CanonicalHistoryStepClassId,
            ) -> std::result::Result<HistoryStepMatrixLease, HistoryStepMatrixSourceError>
            {
                Err(HistoryStepMatrixSourceError)
            }
        }
        let metadata = decode_history_step_runtime_metadata_pinned(
            &read(
                &self.legacy_metadata,
                HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES,
            )?,
            pin(&self.legacy_pin)?,
        )
        .map_err(err)?;
        let (old_bank, parts) = metadata.into_parts();
        let runtime = HistoryStepRuntime::new(old_bank, Box::new(NoRows), parts).map_err(err)?;
        let encoded = self
            .legacy_keys
            .each_ref()
            .map(|p| read(p, SPARSE_EVALUATION_KEY_BYTES));
        let first = encoded[0].as_ref().map_err(err)?;
        let second = encoded[1].as_ref().map_err(err)?;
        let keys = v2::PinnedRetirementKeys::from_release(
            runtime.bank(),
            [first, second],
            [
                pin(&self.legacy_key_pins[0])?,
                pin(&self.legacy_key_pins[1])?,
            ],
        )
        .map_err(err)?;
        v2::RetirementOriginCertificate::from_bytes(bytes)
            .map_err(err)?
            .verify(&runtime, bank, &keys)
            .map_err(err)
    }
    fn matrix(&self, class: v2::Class) -> Result<Arc<CompactFieldR1cs>> {
        let metadata = self.previous_metadata()?;
        let compressed = read(
            &self.v2_pack.join(v2_matrix_file_name(class)),
            V2_MATRIX_MAX_BYTES,
        )?;
        let mut decoder = zstd::stream::read::Decoder::new(compressed.as_slice()).map_err(err)?;
        decoder.window_log_max(27).map_err(err)?;
        let mut bytes = Vec::new();
        decoder
            .take(V2_MATRIX_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        if bytes.len() > V2_MATRIX_MAX_BYTES {
            return Err("canonical matrix bound".into());
        }
        CompactFieldR1cs::open(
            bytes.into_boxed_slice(),
            metadata.bank().config().class(class).shape(),
            metadata.bank().matrix_digest(class),
        )
        .map(Arc::new)
        .map_err(err)
    }
}

fn budget(gib: &str) -> Result<SparseEvaluationBudget> {
    let n: u64 = gib.parse().map_err(err)?;
    if !(1..=128).contains(&n) {
        return Err("planning allowance must be 1..128 GiB".into());
    }
    Ok(SparseEvaluationBudget {
        max_padded_entries: 1 << 30,
        max_planned_bytes: n << 30,
    })
}

fn prepare(input: &Inputs, output: &Path, allowance: SparseEvaluationBudget) -> Result<()> {
    fs::create_dir_all(output).map_err(err)?;
    let workspace = output.join("workspace");
    fs::create_dir_all(&workspace).map_err(err)?;
    let next = input.next_metadata()?;
    let runtime = input.previous_metadata()?.into_metadata_only_runtime()?;
    let encoded = read(
        &input.authorization_origin,
        v21::MAX_AUTHORIZATION_ORIGIN_BYTES,
    )?;
    let authorization = v21::AuthorizationOriginCertificate::from_bytes(&encoded).map_err(err)?;
    let predecessor = input.predecessor(runtime.bank(), authorization.previous_origin_bytes())?;
    let terminal = v2::decode_terminal(&runtime, authorization.terminal_bytes()).map_err(err)?;
    let request = v2::prepare_authorization_retirement(
        &runtime,
        &predecessor,
        &terminal,
        authorization.parent_header(),
        authorization.epoch_header(),
        next.bank(),
    )
    .map_err(err)?;
    let selected = v2::Class::from_wire(request.tip_class().wire_id()).map_err(err)?;
    let selected_matrix = input.matrix(selected)?;
    let reduction = request
        .prove_reduction(&HistoryStepMatrixLease::Compact(selected_matrix))
        .map_err(err)?;
    let reduction_bytes = reduction.encode_for(&request).map_err(err)?;
    let pending = request.verify_reduction(&reduction).map_err(err)?;
    let mut evaluations = Vec::new();
    let mut keys = Vec::new();
    let started = Instant::now();
    for class in v2::Class::ALL {
        println!(
            "{}",
            json!({"phase":"preprocessing","class":class.wire_id()})
        );
        let matrix = input.matrix(class)?;
        let prover = SparseMatrixProver::from_compact(
            &matrix,
            runtime.bank().matrix_digest(class),
            allowance,
        )
        .map_err(err)?;
        drop(matrix);
        let key = prover.key().clone();
        save(
            &output.join(format!("class-{}.key", class.wire_id())),
            &key.to_bytes(),
        )?;
        if let Some(claim) = pending
            .obligations()
            .find(|c| c.class_id().wire_id() == class.wire_id())
        {
            println!("{}", json!({"phase":"proving","class":class.wire_id()}));
            let proof = prover
                .prove_with_disk_workspace(request.binding(), claim.claim(), allowance, &workspace)
                .map_err(err)?;
            key.verify(request.binding(), claim.claim(), &proof)
                .map_err(err)?;
            let bytes = proof
                .to_shared_bytes(&key, request.binding(), claim.claim())
                .map_err(err)?;
            save(
                &output.join(format!("class-{}.proof", class.wire_id())),
                &bytes,
            )?;
            evaluations.push((class.wire_id(), bytes));
        }
        println!(
            "{}",
            json!({"phase":"class_complete","class":class.wire_id(),"key_pin":hex::encode(key.digest()),"elapsed_ms":started.elapsed().as_millis()})
        );
        keys.push(key);
        drop(prover);
        noid_ivc_core::scratch::clear();
    }
    let certificate = v21::UnifiedOriginCertificate::new(
        &authorization,
        &request,
        next.bank(),
        &reduction_bytes,
        &evaluations,
    )
    .map_err(err)?;
    let encoded_keys = keys.iter().map(|k| k.to_bytes()).collect::<Vec<_>>();
    let pins = [keys[0].digest(), keys[1].digest()];
    let keys = v2::PinnedRetirementKeys::from_banked_release(
        runtime.bank(),
        [&encoded_keys[0], &encoded_keys[1]],
        pins,
    )
    .map_err(err)?;
    let checked = certificate
        .verify(&runtime, &predecessor, next.bank(), &keys)
        .map_err(err)?;
    let bytes = certificate.to_bytes().map_err(err)?;
    save(&output.join("unified.origin"), &bytes)?;
    let report = json!({"status":"verified","certificate_bytes":bytes.len(),"origin_binding":hex::encode(checked.origin().request_binding()),
        "verification_without_v1_or_v2_rows":true,"v2_bank":input.v2_pin,"v21_bank":input.v21_pin,
        "key_pins":pins.map(hex::encode),"elapsed_ms":started.elapsed().as_millis()});
    save(
        &output.join("retirement-release.json"),
        &serde_json::to_vec_pretty(&report).map_err(err)?,
    )?;
    println!("{report}");
    Ok(())
}

fn verify(input: &Inputs, directory: &Path) -> Result<()> {
    let pins = input
        .v2_key_pins
        .as_ref()
        .ok_or("verification requires independently supplied v2_key_pins in INPUTS.json")?;
    let runtime = input.previous_metadata()?.into_metadata_only_runtime()?;
    let next = input.next_metadata()?;
    let bytes = read(
        &directory.join("unified.origin"),
        v21::MAX_AUTHORIZATION_ORIGIN_BYTES,
    )?;
    let certificate = v21::UnifiedOriginCertificate::from_bytes(&bytes).map_err(err)?;
    let predecessor = input.predecessor(runtime.bank(), certificate.predecessor_bytes())?;
    let first = read(&directory.join("class-0.key"), SPARSE_EVALUATION_KEY_BYTES)?;
    let second = read(&directory.join("class-1.key"), SPARSE_EVALUATION_KEY_BYTES)?;
    let keys = v2::PinnedRetirementKeys::from_banked_release(
        runtime.bank(),
        [&first, &second],
        [pin(&pins[0])?, pin(&pins[1])?],
    )
    .map_err(err)?;
    let started = Instant::now();
    let origin = certificate
        .verify(&runtime, &predecessor, next.bank(), &keys)
        .map_err(err)?;
    println!(
        "{}",
        json!({"status":"verified","origin_binding":hex::encode(origin.origin().request_binding()),"verification_without_v1_or_v2_rows":true,"verify_ms":started.elapsed().as_millis()})
    );
    Ok(())
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = (|| {
        if args.len() < 3 {
            return Err("usage: noid_retire_authorization prepare|verify INPUTS.json OUTPUT_DIRECTORY [PLANNED_GIB]".into());
        }
        let inputs: Inputs =
            serde_json::from_slice(&read(Path::new(&args[1]), 65536)?).map_err(err)?;
        match args[0].as_str() {
            "prepare" if args.len() == 4 => {
                prepare(&inputs, Path::new(&args[2]), budget(&args[3])?)
            }
            "verify" if args.len() == 3 => verify(&inputs, Path::new(&args[2])),
            _ => Err("invalid command or argument count".into()),
        }
    })();
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
