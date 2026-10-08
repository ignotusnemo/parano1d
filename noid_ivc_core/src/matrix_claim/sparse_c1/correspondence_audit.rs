// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Offline correspondence checks. The release test is deliberately opt-in:
//! it authenticates complete canonical matrices and recomputes all seven
//! static commitments. It neither changes protocol code nor proves PCS soundness.

use super::*;
use crate::field_r1cs::{CompactFieldR1cs, FieldR1csArtifactMatrix, synthetic_satisfiable};
use serde_json::json;
use std::{path::Path, time::Instant};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_pin(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
}

/// Visit entries directly from the authenticated compact artifact. This audit
/// does not use SparseMatrixProver's entry table, push, complete, static_column
/// or tag helpers. Padded entries participate in the access chain as in the
/// published construction, including the final access to address zero.
fn entries(
    matrix: &CompactFieldR1cs,
    padded: usize,
    mut visit: impl FnMut(usize, usize, F128, usize),
) -> usize {
    let width = 1usize << matrix.shape().k_log;
    let mut index = 0;
    for (side_index, side) in [FieldR1csArtifactMatrix::A, FieldR1csArtifactMatrix::B]
        .into_iter()
        .enumerate()
    {
        for group in 0..matrix.matrix_group_count(side) {
            assert!(
                matrix.for_each_matrix_group_entry(side, group, |row, column, coefficient| {
                    visit(
                        row + side_index * width,
                        column as usize,
                        coefficient,
                        index,
                    );
                    index += 1;
                })
            );
        }
    }
    let actual = index;
    assert!(actual <= padded);
    while index < padded {
        visit(0, 0, F128::ZERO, index);
        index += 1;
    }
    actual
}

fn independent_column(
    matrix: &CompactFieldR1cs,
    column: usize,
    padded: usize,
    actual: usize,
) -> Vec<F128> {
    let width = 1usize << matrix.shape().k_log;
    let length = match column {
        5 => 2 * width,
        6 => width,
        _ => padded,
    };
    let mut values = vec![F128::ZERO; length.max(8)];
    let mut previous = match column {
        3 => vec![0u32; 2 * width],
        4 => vec![0u32; width],
        _ => Vec::new(),
    };
    let visited = entries(matrix, padded, |row, col, coefficient, index| {
        let tag = u32::try_from(padded | index).unwrap();
        assert_ne!(tag, 0);
        match column {
            0 => values[index] = F128::new(row as u64, 0),
            1 => values[index] = F128::new(col as u64, 0),
            2 => values[index] = coefficient,
            3 | 4 => {
                let address = if column == 3 { row } else { col };
                values[index] = F128::new(u64::from(previous[address]), 0);
                previous[address] = tag;
            }
            5 | 6 => {
                let address = if column == 5 { row } else { col };
                values[address] = F128::new(u64::from(tag), 0);
            }
            _ => panic!("static column index"),
        }
    });
    assert_eq!(visited, actual);
    values
}

fn independent_key(
    matrix: &CompactFieldR1cs,
    expected: &SparseMatrixEvaluationKey,
    verbose: bool,
) -> [u8; SPARSE_EVALUATION_KEY_BYTES] {
    assert_eq!(matrix.shape(), expected.shape());
    assert_eq!(matrix.statement_digest(), expected.matrix_digest());
    let geometry = expected.geometry();
    let mut out = Vec::from(&b"N1SPKEY1"[..]);
    let shape = matrix.shape();
    for value in [
        shape.m,
        shape.k_log,
        shape.k_skip,
        shape.const_pin.map_or(0, |pin| pin + 1),
        geometry.entries,
    ] {
        out.extend_from_slice(&(value as u64).to_le_bytes());
    }
    out.extend_from_slice(&matrix.statement_digest());
    for column in 0..7 {
        crate::scratch::clear();
        let started = Instant::now();
        let values = independent_column(matrix, column, geometry.padded_entries, geometry.entries);
        let log_len = values.len().trailing_zeros() as usize;
        let parameters = PcsParams {
            m: log_len + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: (log_len - 3).min(5),
            profile: Default::default(),
        };
        let (commitment, data) = pcs::commit(&values, &parameters);
        let root = commitment.root;
        drop(data);
        drop(values);
        crate::scratch::clear();
        out.extend_from_slice(&root);
        if verbose {
            println!(
                "{}",
                json!({"stage":"independent_static_column", "k_log":shape.k_log, "column":column, "root":hex(&root), "milliseconds":started.elapsed().as_millis()})
            );
        }
    }
    out.try_into().unwrap()
}

#[test]
fn independent_sparse_columns_match_resident_and_compact_preprocessing() {
    for (k, seed) in [(7, 19), (8, 271), (9, 12345)] {
        let matrix = synthetic_satisfiable(k, k, seed).0;
        let digest = matrix.structural_statement_digest();
        let mut bytes = Vec::new();
        matrix.write_artifact(&mut bytes).unwrap();
        let compact =
            CompactFieldR1cs::open(bytes.into_boxed_slice(), FieldShape::of(&matrix), digest)
                .unwrap();
        let allowance = SparseEvaluationBudget {
            max_padded_entries: 1 << 16,
            max_planned_bytes: 64 << 20,
        };
        let resident_key = SparseMatrixProver::from_resident(&matrix, digest, allowance)
            .unwrap()
            .key()
            .clone();
        let compact_key = SparseMatrixProver::from_compact(&compact, digest, allowance)
            .unwrap()
            .key()
            .clone();
        let independently_computed = independent_key(&compact, &resident_key, false);
        assert_eq!(independently_computed, resident_key.to_bytes());
        assert_eq!(independently_computed, compact_key.to_bytes());
    }
}

fn release_class(class: usize, pin: &str) {
    let inputs = std::env::var("NOID_CORRESPONDENCE_INPUTS")
        .expect("authenticated decompressed release inputs required");
    let path = Path::new(&inputs);
    let key_bytes = std::fs::read(path.join(format!("class-{class}.key"))).unwrap();
    let expected =
        SparseMatrixEvaluationKey::from_bytes_pinned(&key_bytes, parse_pin(pin)).unwrap();
    let canonical_path = path.join(format!("history-step-c{class:02}.field-r1cs"));
    assert!(std::fs::metadata(&canonical_path).unwrap().len() <= 1 << 30);
    let canonical = std::fs::read(canonical_path).unwrap();
    let canonical_bytes = canonical.len();
    let started = Instant::now();
    // Full semantic authentication, with no build seal or seeded digest.
    let matrix = CompactFieldR1cs::open(
        canonical.into_boxed_slice(),
        expected.shape(),
        expected.matrix_digest(),
    )
    .unwrap();
    let authentication_ms = started.elapsed().as_millis();
    let rebuilt = independent_key(&matrix, &expected, true);
    assert_eq!(rebuilt.as_slice(), key_bytes.as_slice());
    let checked = SparseMatrixEvaluationKey::from_bytes_pinned(&rebuilt, parse_pin(pin)).unwrap();
    println!(
        "{}",
        json!({"stage":"independent_release_key", "class":class, "k_log":matrix.shape().k_log, "entries":checked.geometry().entries, "padded_entries":checked.geometry().padded_entries, "canonical_bytes":canonical_bytes, "authentication_ms":authentication_ms, "elapsed_ms":started.elapsed().as_millis(), "key_digest":hex(&checked.digest()), "all_304_bytes_match":true, "method":"independent column reconstruction from fully authenticated canonical rows; shared release PCS commitment"})
    );
}

#[test]
#[ignore = "full release matrices and several GiB of memory required"]
fn independently_reproduce_pinned_release_key_class_0() {
    release_class(
        0,
        "0651ce507810b61213cbdc0e9f99436aec3a7922cc662bfba6128b466453c8b2",
    );
}

#[test]
#[ignore = "full release matrices and several GiB of memory required"]
fn independently_reproduce_pinned_release_key_class_1() {
    release_class(
        1,
        "c301274d50dc02fd5c383f2e71629075729a954a768f5051388ec2040bce0267",
    );
}
