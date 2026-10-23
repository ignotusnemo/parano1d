use std::{env, fs, path::Path};

use noid_ivc_core::{field_r1cs::BuildAuthenticatedFieldR1csSeal, proof::FieldShape};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const FILE: &str = "matrix-checks.json";
const MAX_CANONICAL_BYTES: usize = 1024 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Shape {
    m: usize,
    k_log: usize,
    k_skip: usize,
    const_pin: Option<usize>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MatrixCheck {
    file: String,
    compressed_sha256: String,
    statement_digest: String,
    canonical_bytes: usize,
    shape: Shape,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u8,
    bank: String,
    metadata_sha256: String,
    matrices: Vec<MatrixCheck>,
}

pub struct PackChecks {
    checked: Option<Manifest>,
    result: Manifest,
    classes: usize,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

impl PackChecks {
    pub fn new(
        directory: &Path,
        label: &str,
        bank: [u8; 32],
        metadata: &[u8],
        classes: usize,
    ) -> Self {
        let result = Manifest {
            schema: 1,
            bank: hex(&bank),
            metadata_sha256: sha256(metadata),
            matrices: Vec::new(),
        };
        let checked = match env::var("NOID_PRECHECKED_MATRIX_PACKS").as_deref() {
            Err(env::VarError::NotPresent) => None,
            Ok("1") => {
                let pin_name = match label {
                    "v2" => "NOID_V2_MATRIX_CHECKS_SHA256",
                    "v21" => "NOID_V21_MATRIX_CHECKS_SHA256",
                    _ => panic!("unsupported prechecked matrix pack"),
                };
                let pin = env::var(pin_name).expect("prechecked matrix manifest pin");
                assert!(
                    pin.len() == 64
                        && pin
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "matrix manifest pin format"
                );
                let path = directory.join(FILE);
                let bytes = crate::read_bounded(&path, 64 * 1024);
                assert_eq!(
                    sha256(&bytes),
                    pin,
                    "matrix manifest differs from the approved release archive"
                );
                let manifest: Manifest =
                    serde_json::from_slice(&bytes).expect("matrix check manifest");
                assert_eq!(manifest.schema, result.schema, "matrix check schema");
                assert_eq!(manifest.bank, result.bank, "matrix check bank");
                assert_eq!(
                    manifest.metadata_sha256, result.metadata_sha256,
                    "matrix check runtime metadata"
                );
                assert_eq!(manifest.matrices.len(), classes, "matrix check class count");
                println!("cargo:rerun-if-changed={}", path.display());
                Some(manifest)
            }
            _ => panic!("NOID_PRECHECKED_MATRIX_PACKS must be unset or 1"),
        };
        Self {
            checked,
            result,
            classes,
        }
    }

    pub fn authenticate(
        &mut self,
        file: &str,
        compressed: &[u8],
        shape: FieldShape,
        statement_digest: [u8; 32],
        full_check: impl FnOnce() -> BuildAuthenticatedFieldR1csSeal,
    ) -> BuildAuthenticatedFieldR1csSeal {
        let compressed_sha256 = sha256(compressed);
        let digest = hex(&statement_digest);
        let seal = if let Some(checked) = &self.checked {
            let entry = &checked.matrices[self.result.matrices.len()];
            assert_eq!(entry.file, file, "matrix check class order");
            assert_eq!(
                entry.compressed_sha256, compressed_sha256,
                "matrix differs from its local preflight"
            );
            assert_eq!(
                entry.statement_digest, digest,
                "matrix check statement digest"
            );
            assert_eq!(entry.shape.m, shape.m as usize, "matrix check shape m");
            assert_eq!(
                entry.shape.k_log, shape.k_log as usize,
                "matrix check shape k_log"
            );
            assert_eq!(
                entry.shape.k_skip, shape.k_skip as usize,
                "matrix check shape k_skip"
            );
            assert_eq!(
                entry.shape.const_pin, shape.const_pin,
                "matrix check constant pin"
            );
            assert!(
                (1..=MAX_CANONICAL_BYTES).contains(&entry.canonical_bytes),
                "matrix check canonical length"
            );
            // SAFETY: the independently approved archive binds this local
            // full-preflight result to the exact compressed payload, pinned
            // bank, class shape and statement digest checked above.
            unsafe {
                BuildAuthenticatedFieldR1csSeal::from_release_build(
                    shape,
                    statement_digest,
                    entry.canonical_bytes,
                )
            }
        } else {
            full_check()
        };
        self.result.matrices.push(MatrixCheck {
            file: file.to_owned(),
            compressed_sha256,
            statement_digest: digest,
            canonical_bytes: seal.canonical_bytes(),
            shape: Shape {
                m: shape.m as usize,
                k_log: shape.k_log as usize,
                k_skip: shape.k_skip as usize,
                const_pin: shape.const_pin,
            },
        });
        seal
    }

    pub fn write(&self, directory: &Path) {
        assert_eq!(
            self.result.matrices.len(),
            self.classes,
            "complete matrix preflight"
        );
        let bytes = serde_json::to_vec_pretty(&self.result).expect("serialize matrix checks");
        fs::write(directory.join(FILE), bytes).expect("write matrix checks");
    }
}
