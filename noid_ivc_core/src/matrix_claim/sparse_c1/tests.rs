use super::sumcheck::prove_cubic;
use super::*;
use crate::field_r1cs::{CompactFieldR1cs, FieldR1cs, SparseFieldMatrix};
use crate::matrix_claim::c1::stacked_matrix_mle_eval_c1;
use std::sync::OnceLock;
use std::time::Instant;

fn wide(seed: u64) -> F256 {
    F256::new(
        F128::new(seed.wrapping_mul(7919), seed.rotate_left(17)),
        F128::new(seed ^ 0xC1, !seed),
    )
}
fn budget() -> SparseEvaluationBudget {
    SparseEvaluationBudget {
        max_padded_entries: 1 << 16,
        max_planned_bytes: 64 << 20,
    }
}

fn matrix(k: usize) -> FieldR1cs {
    let width = 1usize << k;
    let rows = |side: usize| {
        (0..width)
            .map(|row| {
                if row % 3 == 1 {
                    Vec::new()
                } else {
                    // Repeated addresses, different coefficient values and real
                    // extension-valued query coordinates exercise both lookup chains.
                    (0..1 + (row + side) % 4)
                        .map(|j| {
                            (
                                ((row * 5 + j * 3 + side) % width) as u32,
                                F128::new((row + j + 1) as u64, (side + j) as u64),
                            )
                        })
                        .collect()
                }
            })
            .collect()
    };
    FieldR1cs {
        m: k,
        k_log: k,
        k_skip: k.min(2),
        useful_rows: width,
        a_0: SparseFieldMatrix::from_rows(width, rows(0)),
        b_0: SparseFieldMatrix::from_rows(width, rows(1)),
        const_pin: Some(0),
        digest_cache: OnceLock::new(),
        csc_cache: OnceLock::new(),
    }
}

fn claim(matrix: &FieldR1cs) -> C1MatrixAccClaim {
    let point: Vec<_> = (0..2 * matrix.k_log + 1)
        .map(|i| wide(30 + i as u64))
        .collect();
    let mut claim = C1MatrixAccClaim {
        value: F256::ZERO,
        point,
    };
    claim.value = stacked_matrix_mle_eval_c1(matrix, &claim);
    claim
}

struct Fixture {
    prover: SparseMatrixProver,
    claim: C1MatrixAccClaim,
    proof: SparseMatrixEvaluationProof,
}
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let matrix = matrix(3);
        let claim = claim(&matrix);
        let prover = SparseMatrixProver::from_resident(
            &matrix,
            matrix.structural_statement_digest(),
            budget(),
        )
        .unwrap();
        let proof = prover.prove([7; 32], &claim, budget()).unwrap();
        Fixture {
            prover,
            claim,
            proof,
        }
    })
}
fn rejects(proof: &SparseMatrixEvaluationProof) {
    let f = fixture();
    assert!(f.prover.key().verify([7; 32], &f.claim, proof).is_err());
}

#[test]
fn pinned_sparse_key_and_canonical_proof_round_trip_without_rows() {
    let f = fixture();
    let key_bytes = f.prover.key().to_bytes();
    let key =
        SparseMatrixEvaluationKey::from_bytes_pinned(&key_bytes, f.prover.key().digest()).unwrap();
    assert_eq!(&key, f.prover.key());
    let bytes = f.proof.to_bytes(&key, [7; 32], &f.claim).unwrap();
    assert!(bytes.len() < MAX_SPARSE_EVALUATION_PROOF_BYTES);
    let proof = SparseMatrixEvaluationProof::from_bytes(&key, [7; 32], &f.claim, &bytes).unwrap();
    assert_eq!(proof, f.proof);
    assert_eq!(proof.to_bytes(&key, [7; 32], &f.claim).unwrap(), bytes);
    key.verify([7; 32], &f.claim, &proof).unwrap();
}

#[test]
fn shared_sparse_paths_preserve_the_verified_proof_and_reject_malformed_transport() {
    let f = fixture();
    let key = f.prover.key();
    let full = f.proof.to_bytes(key, [7; 32], &f.claim).unwrap();
    let shared = f.proof.to_shared_bytes(key, [7; 32], &f.claim).unwrap();
    assert!(shared.len() < full.len());
    let restored =
        SparseMatrixEvaluationProof::from_bytes(key, [7; 32], &f.claim, &shared).unwrap();
    assert_eq!(restored, f.proof);
    assert_eq!(restored.to_bytes(key, [7; 32], &f.claim).unwrap(), full);
    key.verify([7; 32], &f.claim, &restored).unwrap();
    assert_eq!(
        restored.to_shared_bytes(key, [7; 32], &f.claim).unwrap(),
        shared
    );
    for cut in [0, 7, 71, shared.len() / 2, shared.len() - 1] {
        assert!(
            SparseMatrixEvaluationProof::from_bytes(key, [7; 32], &f.claim, &shared[..cut])
                .is_err()
        );
    }
    let mut extra = shared.clone();
    extra.push(0);
    assert!(SparseMatrixEvaluationProof::from_bytes(key, [7; 32], &f.claim, &extra).is_err());
    let mut changed = shared;
    *changed.last_mut().unwrap() ^= 1;
    if let Ok(proof) = SparseMatrixEvaluationProof::from_bytes(key, [7; 32], &f.claim, &changed) {
        assert!(key.verify([7; 32], &f.claim, &proof).is_err());
    }
    let mut conflict = f.proof.clone();
    let opening = &mut conflict.openings[0];
    opening.queries[1] = opening.queries[0].clone();
    opening.queries[1].initial_path[0][0] ^= 1;
    assert!(conflict.to_shared_bytes(key, [7; 32], &f.claim).is_err());
}

#[test]
fn disk_workspace_preserves_the_complete_proof_and_removes_temporary_files() {
    let f = fixture();
    let directory = tempfile::tempdir().unwrap();
    let proof = f
        .prover
        .prove_with_disk_workspace([7; 32], &f.claim, budget(), directory.path())
        .unwrap();
    assert_eq!(proof, f.proof);
    f.prover.key().verify([7; 32], &f.claim, &proof).unwrap();
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    let absent = directory.path().join("absent");
    assert!(matches!(
        f.prover
            .prove_with_disk_workspace([7; 32], &f.claim, budget(), &absent),
        Err(Error::Workspace(_))
    ));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn sparse_wire_rejects_wrong_pins_requests_shapes_and_trailing_data() {
    let f = fixture();
    let key = f.prover.key();
    let key_bytes = key.to_bytes();
    assert!(SparseMatrixEvaluationKey::from_bytes_pinned(&key_bytes, [0; 32]).is_err());
    for index in 0..key_bytes.len() {
        let mut changed = key_bytes;
        changed[index] ^= 1;
        assert!(SparseMatrixEvaluationKey::from_bytes_pinned(&changed, key.digest()).is_err());
        assert!(
            SparseMatrixEvaluationKey::from_bytes_pinned(&key_bytes[..index], key.digest())
                .is_err()
        );
    }
    let bytes = f.proof.to_bytes(key, [7; 32], &f.claim).unwrap();
    assert!(SparseMatrixEvaluationProof::from_bytes(key, [8; 32], &f.claim, &bytes).is_err());
    let mut claim = f.claim.clone();
    claim.value += F256::ONE;
    assert!(SparseMatrixEvaluationProof::from_bytes(key, [7; 32], &claim, &bytes).is_err());
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(SparseMatrixEvaluationProof::from_bytes(key, [7; 32], &f.claim, &extra).is_err());
    for cut in [0, 7, 8, 39, 71, 103, bytes.len() / 2, bytes.len() - 1] {
        assert!(
            SparseMatrixEvaluationProof::from_bytes(key, [7; 32], &f.claim, &bytes[..cut]).is_err()
        );
    }
    let mut modified = bytes.clone();
    *modified.last_mut().unwrap() ^= 1;
    match SparseMatrixEvaluationProof::from_bytes(key, [7; 32], &f.claim, &modified) {
        Err(_) => {}
        Ok(proof) => assert!(key.verify([7; 32], &f.claim, &proof).is_err()),
    }
    let mut oversized = vec![0; MAX_SPARSE_EVALUATION_PROOF_BYTES + 1];
    oversized[..8].copy_from_slice(b"N1SPEVL1");
    assert!(SparseMatrixEvaluationProof::from_bytes(key, [7; 32], &f.claim, &oversized).is_err());
}

#[test]
fn cubic_and_product_reductions_match_independent_evaluations() {
    for log_len in 0..7 {
        let tables: [Vec<F256>; 3] = std::array::from_fn(|j| {
            (0..1usize << log_len)
                .map(|i| wide((1 + 100 * j + i) as u64))
                .collect()
        });
        let target = (0..tables[0].len()).fold(F256::ZERO, |out, i| {
            out + tables[0][i] * tables[1][i] * tables[2][i]
        });
        let mut prover = FsLaneChallenger::new_c1(b"sparse-cubic-test");
        let (proof, point) = prove_cubic(tables.clone(), target, &mut prover);
        let mut streaming = FsLaneChallenger::new_c1(b"sparse-cubic-test");
        let streamed = prove_cubic_from_fn(
            tables[0].len(),
            |index| std::array::from_fn(|j| tables[j][index]),
            target,
            &mut streaming,
        );
        assert_eq!(streamed, (proof.clone(), point.clone()));
        assert_eq!(streaming.sample_f256(), prover.clone().sample_f256());
        let mut verifier = FsLaneChallenger::new_c1(b"sparse-cubic-test");
        assert_eq!(
            point,
            verify_cubic(log_len, target, &proof, &mut verifier).unwrap()
        );
        for j in 0..3 {
            assert_eq!(
                proof.values[j],
                sumcheck::evaluate(tables[j].clone(), &point)
            );
        }
        assert_eq!(prover.sample_f256(), verifier.sample_f256());
        let root = tables[0]
            .iter()
            .copied()
            .fold(F256::ONE, |out, value| out * value);
        let mut prover = FsLaneChallenger::new_c1(b"sparse-product-test");
        let (proof, point, value) = prove_product(tables[0].clone(), &mut prover);
        let mut verifier = FsLaneChallenger::new_c1(b"sparse-product-test");
        assert_eq!(
            (point.clone(), value),
            verify_product(log_len, root, &proof, &mut verifier).unwrap()
        );
        assert_eq!(value, sumcheck::evaluate(tables[0].clone(), &point));
        assert_eq!(prover.sample_f256(), verifier.sample_f256());
    }
}

#[test]
fn nonzero_sparse_proof_verifies_after_dropping_rows_and_prover() {
    let matrix = matrix(4);
    let claim = claim(&matrix);
    let started = Instant::now();
    let prover =
        SparseMatrixProver::from_resident(&matrix, matrix.structural_statement_digest(), budget())
            .unwrap();
    let preprocessing = started.elapsed();
    let started = Instant::now();
    let proof = prover.prove([0xA5; 32], &claim, budget()).unwrap();
    let proving = started.elapsed();
    let key = prover.key().clone();
    drop(prover);
    drop(matrix);
    let started = Instant::now();
    key.verify([0xA5; 32], &claim, &proof).unwrap();
    eprintln!(
        "sparse-c1 fixture k={} nnz={} padded={} preprocess_us={} prove_us={} verify_us={}",
        key.shape.k_log,
        key.geometry.entries,
        key.geometry.padded_entries,
        preprocessing.as_micros(),
        proving.as_micros(),
        started.elapsed().as_micros()
    );
}

#[test]
fn resident_and_compact_preprocessing_are_identical() {
    let matrix = matrix(3);
    let digest = matrix.structural_statement_digest();
    let resident = SparseMatrixProver::from_resident(&matrix, digest, budget()).unwrap();
    let mut bytes = Vec::new();
    matrix.write_artifact(&mut bytes).unwrap();
    let compact =
        CompactFieldR1cs::open(bytes.into_boxed_slice(), FieldShape::of(&matrix), digest).unwrap();
    let compact = SparseMatrixProver::from_compact(&compact, digest, budget()).unwrap();
    assert_eq!(resident.key(), compact.key());
    assert_eq!(resident.indices, compact.indices);
    assert_eq!(resident.coefficients, compact.coefficients);
    assert_eq!(resident.final_tags, compact.final_tags);
    assert_eq!(
        compact.prove([7; 32], &claim(&matrix), budget()).unwrap(),
        fixture().proof
    );
}

#[test]
fn immutable_tags_cover_repeated_reads_and_padding_without_field_increment() {
    let prover = &fixture().prover;
    let n = prover.key.geometry.padded_entries;
    let mut tags = [
        vec![0; prover.key.geometry.row_addresses],
        vec![0; prover.key.geometry.column_addresses],
    ];
    for (index, entry) in prover.indices.iter().enumerate() {
        let point: Vec<_> = (0..prover.key.geometry.entry_log())
            .map(|bit| F256::from_base(raw(((index >> bit) & 1) as u32)))
            .collect();
        assert_eq!(
            write_tag_mle(&point),
            F256::from_base(raw((n + index) as u32))
        );
        for side in 0..2 {
            assert_eq!(entry[side + 2], tags[side][entry[side] as usize]);
            tags[side][entry[side] as usize] = (n + index) as u32;
        }
        if index >= prover.key.geometry.entries {
            assert_eq!(entry[..2], [0, 0]);
            assert_eq!(prover.coefficients[index], F128::ZERO);
        }
    }
    assert_eq!(tags, prover.final_tags);
    assert_ne!(raw((n + 2) as u32), raw(n as u32) + F128::ONE + F128::ONE);
}

#[test]
fn proof_binds_context_point_value_and_all_preprocessing_roots() {
    let f = fixture();
    assert!(f.prover.key.verify([8; 32], &f.claim, &f.proof).is_err());
    for index in 0..f.claim.point.len() {
        let mut claim = f.claim.clone();
        claim.point[index] += F256::ONE;
        assert!(f.prover.key.verify([7; 32], &claim, &f.proof).is_err());
    }
    let mut claim = f.claim.clone();
    claim.value += F256::ONE;
    assert!(f.prover.key.verify([7; 32], &claim, &f.proof).is_err());
    for column in 0..STATIC_COLUMNS {
        let mut key = f.prover.key.clone();
        key.roots[column][0] ^= 1;
        assert!(key.verify([7; 32], &f.claim, &f.proof).is_err());
    }
    let mut key = f.prover.key.clone();
    key.matrix_digest[0] ^= 1;
    assert!(key.verify([7; 32], &f.claim, &f.proof).is_err());
    let mut key = f.prover.key.clone();
    key.shape.const_pin = None;
    assert!(key.verify([7; 32], &f.claim, &f.proof).is_err());
}

#[test]
fn every_inner_product_coefficient_and_terminal_value_is_checked() {
    let f = fixture();
    for round in 0..f.proof.reduction.inner_product.rounds.len() {
        for coordinate in 0..3 {
            let mut proof = f.proof.clone();
            proof.reduction.inner_product.rounds[round][coordinate] += F256::ONE;
            rejects(&proof);
        }
    }
    for coordinate in 0..3 {
        let mut proof = f.proof.clone();
        proof.reduction.inner_product.values[coordinate] += F256::ONE;
        rejects(&proof);
    }
}

#[test]
fn every_product_tree_message_and_product_is_checked() {
    let f = fixture();
    for side in 0..2 {
        for kind in 0..4 {
            let mut proof = f.proof.clone();
            proof.reduction.lookups[side].products[kind] += F256::ONE;
            rejects(&proof);
            for layer in 0..f.proof.reduction.lookups[side].trees[kind].layers.len() {
                for round in 0..layer {
                    for coordinate in 0..3 {
                        let mut proof = f.proof.clone();
                        proof.reduction.lookups[side].trees[kind].layers[layer].rounds[round]
                            [coordinate] += F256::ONE;
                        rejects(&proof);
                    }
                }
                for coordinate in 0..3 {
                    let mut proof = f.proof.clone();
                    proof.reduction.lookups[side].trees[kind].layers[layer].values[coordinate] +=
                        F256::ONE;
                    rejects(&proof);
                }
            }
        }
    }
}

#[test]
fn every_pcs_value_root_and_opening_is_checked() {
    let f = fixture();
    for column in 0..ALL_COLUMNS {
        for index in 0..f.proof.values[column].len() {
            for delta in [F256::ONE, EXTENSION] {
                let mut proof = f.proof.clone();
                proof.values[column][index] += delta;
                rejects(&proof);
            }
        }
        let mut proof = f.proof.clone();
        proof.openings[column].final_b += F256::ONE;
        rejects(&proof);
        let mut proof = f.proof.clone();
        proof.openings[column].queries.clear();
        rejects(&proof);
    }
    for column in 0..4 {
        let mut proof = f.proof.clone();
        proof.reduction.dynamic_roots[column][0] ^= 1;
        rejects(&proof);
    }
}

#[test]
fn malformed_shapes_reject_without_panicking() {
    let f = fixture();
    let mut claim = f.claim.clone();
    claim.point.pop();
    assert_eq!(
        f.prover.key.verify([7; 32], &claim, &f.proof),
        Err(Error::Claim)
    );
    let mut proof = f.proof.clone();
    proof.reduction.inner_product.rounds.pop();
    rejects(&proof);
    for side in 0..2 {
        for kind in 0..4 {
            let mut proof = f.proof.clone();
            proof.reduction.lookups[side].trees[kind].layers.pop();
            rejects(&proof);
            let mut proof = f.proof.clone();
            proof.reduction.lookups[side].trees[kind].layers[0]
                .rounds
                .push([F256::ZERO; 3]);
            rejects(&proof);
        }
    }
    for column in 0..ALL_COLUMNS {
        let mut proof = f.proof.clone();
        proof.values[column].clear();
        rejects(&proof);
        let mut proof = f.proof.clone();
        proof.values[column].push(F256::ZERO);
        rejects(&proof);
    }
}

#[test]
fn wrong_values_and_seeded_matrix_substitutions_reject() {
    let f = fixture();
    let mut claim = f.claim.clone();
    claim.value += F256::ONE;
    assert!(matches!(
        f.prover.prove([7; 32], &claim, budget()),
        Err(Error::Claim)
    ));
    let honest = matrix(3);
    let digest = honest.structural_statement_digest();
    let mut substituted = matrix(3);
    substituted.a_0.value_table[0] += F128::ONE;
    substituted.seed_statement_digest(digest);
    assert!(matches!(
        SparseMatrixProver::from_resident(&substituted, digest, budget()),
        Err(Error::MatrixIdentity)
    ));
}

#[test]
fn budget_admission_precedes_large_allocations_and_hashing() {
    let mut invalid = matrix(3);
    invalid.a_0.value_indices[0] = u32::MAX;
    let no_space = SparseEvaluationBudget {
        max_padded_entries: 0,
        max_planned_bytes: 0,
    };
    assert!(matches!(
        SparseMatrixProver::from_resident(&invalid, [0; 32], no_space),
        Err(Error::Budget)
    ));
    assert!(matches!(
        SparseMatrixProver::from_resident(&invalid, [0; 32], budget()),
        Err(Error::Shape)
    ));
    let mut invalid = matrix(3);
    invalid.a_0.col_indices.pop();
    assert!(matches!(
        SparseMatrixProver::from_resident(&invalid, [0; 32], budget()),
        Err(Error::Shape)
    ));
    assert_eq!(SparseEvaluationGeometry::new(31, 0), Err(Error::Shape));
    assert_eq!(
        SparseEvaluationGeometry::new(1, usize::MAX),
        Err(Error::Shape)
    );
    for (k, entries) in [(22, 28_461_463), (24, 124_071_078)] {
        let geometry = SparseEvaluationGeometry::new(k, entries).unwrap();
        assert_eq!(geometry.admit(budget()), Err(Error::Budget));
        eprintln!(
            "sparse-c1 planning k={k} nnz={entries} padded={} planned_bytes={}",
            geometry.padded_entries, geometry.planned_bytes
        );
    }
}

#[test]
fn coordinated_wide_opening_changes_preserve_algebra_but_fail_pcs() {
    let f = fixture();
    let (plan, _) = reduce(&f.prover.key, [7; 32], &f.claim, &f.proof.reduction).unwrap();
    for side in 0..2 {
        let low = STATIC_COLUMNS + 2 * side;
        for index in 0..f.proof.values[low].len() {
            let mut proof = f.proof.clone();
            proof.values[low][index] += EXTENSION;
            proof.values[low + 1][index] += F256::ONE;
            // The wide recombination is unchanged; only the PCS authenticates
            // the separately committed base-field coordinate polynomials.
            plan.check(&proof.values).unwrap();
            assert!(matches!(
                f.prover.key.verify([7; 32], &f.claim, &proof),
                Err(Error::Opening(_))
            ));
        }
    }
}

#[test]
fn repeated_bad_reads_do_not_cancel_in_characteristic_two() {
    let f = fixture();
    let row_eq = build_eq_table(&f.claim.point[..f.prover.key.shape.k_log + 1]);
    let col_eq = build_eq_table(&f.claim.point[f.prover.key.shape.k_log + 1..]);
    let mut vectors: [Vec<_>; 2] = [
        f.prover
            .indices
            .iter()
            .map(|entry| row_eq[entry[0] as usize])
            .collect(),
        f.prover
            .indices
            .iter()
            .map(|entry| col_eq[entry[1] as usize])
            .collect(),
    ];
    // Two reads of the same row carry the same wrong value. A parity-only
    // multiset sum would cancel these changes; the unique-tag product does not.
    let first = 0;
    let second = f
        .prover
        .indices
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, entry)| entry[0] == f.prover.indices[first][0])
        .unwrap()
        .0;
    vectors[0][first] += F256::ONE;
    vectors[0][second] += F256::ONE;
    let gamma = wide(444);
    let offset = wide(999);
    let products: [F256; 4] = std::array::from_fn(|kind| {
        f.prover
            .lookup_leaves(
                0,
                kind,
                &f.claim,
                &|side, index| vectors[side][index],
                gamma,
                offset,
            )
            .into_iter()
            .fold(F256::ONE, |out, value| out * value)
    });
    assert_ne!(
        products[INIT] * products[WRITE],
        products[READ] * products[AUDIT]
    );
}

#[test]
fn zero_matrix_and_boolean_edge_points_have_valid_proofs() {
    for empty in [false, true] {
        let mut matrix = matrix(1);
        if empty {
            matrix.a_0 = SparseFieldMatrix::zero(2);
            matrix.b_0 = SparseFieldMatrix::zero(2);
        }
        let mut claim = C1MatrixAccClaim {
            point: vec![F256::ONE, F256::ZERO, F256::ONE],
            value: F256::ZERO,
        };
        claim.value = stacked_matrix_mle_eval_c1(&matrix, &claim);
        let prover = SparseMatrixProver::from_resident(
            &matrix,
            matrix.structural_statement_digest(),
            budget(),
        )
        .unwrap();
        let proof = prover.prove([1; 32], &claim, budget()).unwrap();
        prover.key.verify([1; 32], &claim, &proof).unwrap();
    }
}

#[test]
#[ignore = "bounded standalone resource probe; run explicitly"]
fn measure_sparse_evaluation() {
    let k = std::env::var("NOID_SPARSE_PROBE_K")
        .map(|s| s.parse::<usize>().expect("integer probe width"))
        .unwrap_or(10);
    assert!(
        (3..=12).contains(&k),
        "probe is deliberately bounded to small fixtures"
    );
    let matrix = matrix(k);
    let claim = claim(&matrix);
    let digest = matrix.structural_statement_digest();
    let started = Instant::now();
    let prover = SparseMatrixProver::from_resident(&matrix, digest, budget()).unwrap();
    let preprocessing = started.elapsed();
    let started = Instant::now();
    let proof = prover.prove([0x50; 32], &claim, budget()).unwrap();
    let proving = started.elapsed();
    let key = prover.key.clone();
    drop(prover);
    drop(matrix);
    let started = Instant::now();
    key.verify([0x50; 32], &claim, &proof).unwrap();
    let verifying = started.elapsed();
    let cubic_bytes = |proof: &CubicProof| (3 * proof.rounds.len() + 3) * 32;
    let reduction_bytes = 4 * 32
        + cubic_bytes(&proof.reduction.inner_product)
        + proof
            .reduction
            .lookups
            .iter()
            .map(|lookup| {
                4 * 32
                    + lookup
                        .trees
                        .iter()
                        .map(|tree| tree.layers.iter().map(cubic_bytes).sum::<usize>())
                        .sum::<usize>()
            })
            .sum::<usize>();
    let opening_bytes = proof
        .openings
        .iter()
        .map(|opening| bincode::serialized_size(opening).unwrap())
        .sum::<u64>();
    let value_bytes = proof
        .values
        .iter()
        .map(|values| values.len() * 32)
        .sum::<usize>();
    eprintln!(
        "SPARSE_EVAL_MEASUREMENT {{\"k_log\":{k},\"entries\":{},\"padded_entries\":{},\"planned_bytes\":{},\"preprocessing_us\":{},\"proving_us\":{},\"verification_us\":{},\"reduction_payload_bytes\":{reduction_bytes},\"pcs_bincode_bytes\":{opening_bytes},\"opening_value_bytes\":{value_bytes}}}",
        key.geometry.entries,
        key.geometry.padded_entries,
        key.geometry.planned_bytes,
        preprocessing.as_micros(),
        proving.as_micros(),
        verifying.as_micros()
    );
}
