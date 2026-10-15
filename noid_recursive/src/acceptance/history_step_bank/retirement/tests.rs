use super::*;
use crate::acceptance::history_step_bank::{
    canonical_history_step_pcs_params, canonical_history_step_shape,
    history_step_bank_base_output_io, history_step_bank_io_spec,
    history_step_bank_post_commit_digest, install_folded_lane, HistoryStepBankEntryPins,
};
use noid_chain::block_header::{hash_block_header, semantic_header_id};
use noid_chain::consensus::forks::V2Activation;
use noid_chain::consensus::genesis_header;
use noid_ivc_core::field::F128;
use noid_ivc_core::field_r1cs::{synthetic_satisfiable, CompactFieldR1cs, FieldR1cs};
use noid_ivc_core::matrix_claim::c1::{fresh_claim_value_c1, stacked_matrix_mle_eval_c1};
use noid_ivc_core::matrix_claim::sparse_c1::{
    SparseEvaluationBudget, SparseMatrixEvaluationKey, SparseMatrixEvaluationProof,
    SparseMatrixProver,
};

fn value(seed: u64) -> F256 {
    F256::new(
        F128::new(seed, seed.rotate_left(7)),
        F128::new(!seed, seed ^ 0xC1),
    )
}

fn class(index: usize) -> CanonicalHistoryStepClassId {
    CanonicalHistoryStepClassId::from_index(index).unwrap()
}

fn local_schedule() -> ForkSchedule {
    ForkSchedule::new(Some(5), V2Activation::new(10, 30)).unwrap()
}

fn bank() -> PinnedHistoryStepClassBank {
    let pins = std::array::from_fn(|index| {
        let class_id = class(index);
        let pcs_params = canonical_history_step_pcs_params(class_id);
        let matrix_digest = [index as u8 + 1; 32];
        let parent_recursion_vk_digest = [0x21; 32];
        let direct_block_vk_digest = [index as u8 + 0x41; 32];
        HistoryStepBankEntryPins {
            class_id,
            shape: canonical_history_step_shape(class_id),
            matrix_digest,
            parent_recursion_vk_digest,
            direct_block_vk_digest,
            post_commit_digest: history_step_bank_post_commit_digest(
                class_id,
                &matrix_digest,
                &history_step_bank_io_spec(),
                &pcs_params,
                parent_recursion_vk_digest,
                direct_block_vk_digest,
            ),
            pcs_params,
        }
    });
    PinnedHistoryStepClassBank::validate(pins).unwrap()
}

fn fresh(shape: FieldShape) -> C1FreshLincheckClaim {
    C1FreshLincheckClaim {
        alpha: value(1),
        z_skip: value(2),
        x_inner_rest: (0..shape.k_log - shape.k_skip)
            .map(|i| value(10 + i as u64))
            .collect(),
        r_inner_rest: (0..shape.k_log - shape.k_skip)
            .map(|i| value(30 + i as u64))
            .collect(),
        z_partial: (0..1usize << shape.k_skip)
            .map(|i| value(50 + i as u64))
            .collect(),
        value: value(100),
    }
}

fn lane(shape: FieldShape, salt: u64) -> C1MatrixAccClaim {
    C1MatrixAccClaim {
        point: (0..2 * shape.k_log + 1)
            .map(|i| value(salt + i as u64))
            .collect(),
        value: value(salt + 100),
    }
}

// This tests the request boundary, not a terminal proof. Only this module's
// tests can mint the private replay capability without invoking the verifier.
fn pending_fixture(
    selected: usize,
    live_mask: usize,
) -> (
    PendingHistoryStepBankDecision,
    HistoryStepRetirementTarget,
    BlockHeader,
    BlockHeader,
) {
    let bank = bank();
    let epoch = genesis_header();
    let mut parent = epoch;
    parent.height = 9;
    parent.timestamp += 9 * 20;
    parent.state_root = [0x71; 32];
    let boundary = ChainAccumulator {
        height: parent.height,
        tip_semantic_id: semantic_header_id(&parent),
        state_root: parent.state_root,
        log_slots: parent.log_slots,
        active_slot_count: parent.active_slot_count,
        alloc_counter: parent.alloc_counter,
        epoch_anchor_id: hash_block_header(&epoch),
    };
    let target = HistoryStepRetirementTarget::new(local_schedule(), &bank, [0xAA; 32]).unwrap();
    let selected_class = class(selected);
    let mut io = history_step_bank_base_output_io(&bank, selected_class, &boundary).unwrap();
    io[bank.layout().base] = F128::ZERO;
    for index in 0..HISTORY_STEP_CLASS_COUNT {
        if live_mask & (1 << index) != 0 {
            install_folded_lane(
                &bank,
                &mut io,
                class(index),
                &lane(bank.entry(class(index)).shape(), 300 + index as u64),
            )
            .unwrap();
        }
    }
    let entry = bank.entry(selected_class);
    let replay = bank
        .bind_verified_tip_replay(
            selected_class,
            entry.matrix_digest(),
            entry.post_commit_digest(),
            fresh(entry.shape()),
        )
        .unwrap();
    (
        PendingHistoryStepBankDecision::begin(&bank, &io, replay).unwrap(),
        target,
        parent,
        epoch,
    )
}

fn canonical_request(selected: usize, live_mask: usize) -> HistoryStepRetirementRequest {
    let (pending, target, parent, epoch) = pending_fixture(selected, live_mask);
    HistoryStepRetirementRequest::from_pending(pending, target, &parent, &epoch).unwrap()
}

// Small nonzero matrices exercise the real C1 fold without allocating m22/m24
// tables per mutation. Production requests retain canonical bank dimensions.
fn algebra_fixture(
    selected: usize,
    live_mask: usize,
) -> (HistoryStepRetirementRequest, [FieldR1cs; 2]) {
    let matrices = std::array::from_fn(|index| {
        synthetic_satisfiable(7 + index, 7 + index, 900 + index as u64).0
    });
    let mut request = canonical_request(selected, live_mask);
    request.requirements = std::array::from_fn(|index| MatrixRequirement {
        shape: FieldShape::of(&matrices[index]),
        digest: matrices[index].structural_statement_digest(),
    });
    request.fresh = fresh(request.shape());
    request.fresh.value = fresh_claim_value_c1(&matrices[selected], &request.fresh);
    request.lanes = std::array::from_fn(|index| {
        (live_mask & (1 << index) != 0).then(|| {
            let mut claim = lane(request.requirements[index].shape, 300 + index as u64);
            claim.value = stacked_matrix_mle_eval_c1(&matrices[index], &claim);
            claim
        })
    });
    request.binding = request.compute_binding();
    (request, matrices)
}

struct EvaluationFixture {
    request: HistoryStepRetirementRequest,
    reduction: HistoryStepRetirementReduction,
    keys: Vec<SparseMatrixEvaluationKey>,
    proofs: Vec<SparseMatrixEvaluationProof>,
    classes: Vec<CanonicalHistoryStepClassId>,
}

impl EvaluationFixture {
    fn new(selected: usize, mask: usize) -> Self {
        // As with algebra_fixture, this checks the matrix-closure component,
        // not a real terminal or the full cross-bank transition relation.
        let (request, matrices) = algebra_fixture(selected, mask);
        let reduction = request
            .prove_reduction(&HistoryStepMatrixLease::resident(
                matrices[selected].clone(),
            ))
            .unwrap();
        let pending = request.verify_reduction(&reduction).unwrap();
        let budget = SparseEvaluationBudget {
            max_padded_entries: 1 << 16,
            max_planned_bytes: 64 << 20,
        };
        let mut keys = Vec::new();
        let mut proofs = Vec::new();
        let mut classes = Vec::new();
        for obligation in pending.obligations() {
            let index = obligation.class_id().index();
            let prover = SparseMatrixProver::from_resident(
                &matrices[index],
                obligation.matrix_digest(),
                budget,
            )
            .unwrap();
            proofs.push(
                prover
                    .prove(pending.request_binding(), obligation.claim(), budget)
                    .unwrap(),
            );
            keys.push(prover.key().clone());
            classes.push(obligation.class_id());
        }
        // Matrix rows and all preprocessing/prover data are dropped before
        // any consumer test below verifies these evaluations.
        Self {
            request,
            reduction,
            keys,
            proofs,
            classes,
        }
    }

    fn evaluations(&self) -> Vec<HistoryStepRetirementEvaluation<'_>> {
        self.classes
            .iter()
            .enumerate()
            .map(|(index, &class_id)| HistoryStepRetirementEvaluation {
                class_id,
                key: &self.keys[index],
                proof: &self.proofs[index],
            })
            .collect()
    }
    fn pending(&self) -> PendingHistoryStepRetirement {
        self.request.verify_reduction(&self.reduction).unwrap()
    }
}

fn evaluation_fixture() -> &'static EvaluationFixture {
    static FIXTURE: std::sync::OnceLock<EvaluationFixture> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| EvaluationFixture::new(0, 3))
}

#[test]
fn sparse_evaluations_close_both_live_lanes_without_matrix_rows() {
    let fixture = evaluation_fixture();
    let checked = fixture
        .pending()
        .verify_matrix_evaluations(&fixture.evaluations())
        .unwrap();
    assert_eq!(checked.request_binding(), fixture.request.binding());
    assert_eq!(checked.boundary(), fixture.request.boundary());
    assert_eq!(checked.target(), fixture.request.target());
    assert_eq!(
        checked.evaluation_key_digests(),
        &[
            Some(fixture.keys[0].digest()),
            Some(fixture.keys[1].digest()),
        ]
    );
}

#[test]
fn sparse_evaluations_reject_missing_duplicate_reordered_and_wrong_keys() {
    let fixture = evaluation_fixture();
    let mut evaluations = fixture.evaluations();
    for count in 0..2 {
        assert!(matches!(
            fixture
                .pending()
                .verify_matrix_evaluations(&evaluations[..count]),
            Err(RetirementEvaluationError::Coverage)
        ));
    }
    evaluations.swap(0, 1);
    assert!(matches!(
        fixture.pending().verify_matrix_evaluations(&evaluations),
        Err(RetirementEvaluationError::Identity)
    ));
    evaluations.swap(0, 1);
    evaluations[1].class_id = evaluations[0].class_id;
    assert!(matches!(
        fixture.pending().verify_matrix_evaluations(&evaluations),
        Err(RetirementEvaluationError::Identity)
    ));
    let mut evaluations = fixture.evaluations();
    evaluations[0].key = evaluations[1].key;
    assert!(matches!(
        fixture.pending().verify_matrix_evaluations(&evaluations),
        Err(RetirementEvaluationError::Identity)
    ));
    let mut evaluations = fixture.evaluations();
    evaluations[1].proof = evaluations[0].proof;
    assert!(matches!(
        fixture.pending().verify_matrix_evaluations(&evaluations),
        Err(RetirementEvaluationError::Proof(_))
    ));
    let mut evaluations = fixture.evaluations();
    evaluations.push(HistoryStepRetirementEvaluation {
        class_id: class(0),
        key: &fixture.keys[0],
        proof: &fixture.proofs[0],
    });
    assert!(matches!(
        fixture.pending().verify_matrix_evaluations(&evaluations),
        Err(RetirementEvaluationError::Coverage)
    ));
}

#[test]
fn sparse_evaluations_bind_request_and_nonselected_lane() {
    let fixture = evaluation_fixture();
    let mut pending = fixture.pending();
    pending.request_binding[0] ^= 1;
    assert!(matches!(
        pending.verify_matrix_evaluations(&fixture.evaluations()),
        Err(RetirementEvaluationError::Proof(_))
    ));
    for index in 0..2 {
        let mut pending = fixture.pending();
        pending.obligations[index].as_mut().unwrap().claim.value += F256::ONE;
        assert!(matches!(
            pending.verify_matrix_evaluations(&fixture.evaluations()),
            Err(RetirementEvaluationError::Proof(_))
        ));
        let mut pending = fixture.pending();
        pending.obligations[index].as_mut().unwrap().claim.point[0] += F256::ONE;
        assert!(matches!(
            pending.verify_matrix_evaluations(&fixture.evaluations()),
            Err(RetirementEvaluationError::Proof(_))
        ));
    }
}

#[test]
fn sparse_evaluations_close_the_other_selected_class_with_no_old_live_lane() {
    let fixture = EvaluationFixture::new(1, 0);
    let checked = fixture
        .pending()
        .verify_matrix_evaluations(&fixture.evaluations())
        .unwrap();
    assert_eq!(checked.evaluation_key_digests()[0], None);
    assert_eq!(
        checked.evaluation_key_digests()[1],
        Some(fixture.keys[0].digest())
    );
}

#[test]
fn target_requires_a_scheduled_fork_and_distinct_bank() {
    let bank = bank();
    for schedule in [
        ForkSchedule::new(Some(5), None).unwrap(),
        ForkSchedule::new(Some(0), V2Activation::new(1, 30)).unwrap(),
    ] {
        assert!(matches!(
            HistoryStepRetirementTarget::new(schedule, &bank, [0xAA; 32]),
            Err(HistoryStepRetirementError::Schedule)
        ));
    }
    for digest in [[0; 32], bank.digest()] {
        assert!(matches!(
            HistoryStepRetirementTarget::new(local_schedule(), &bank, digest),
            Err(HistoryStepRetirementError::BankIdentity)
        ));
    }
    let target = HistoryStepRetirementTarget::new(
        ForkSchedule::new(Some(5), V2Activation::new(u64::MAX, 30)).unwrap(),
        &bank,
        [0xAA; 32],
    )
    .unwrap();
    assert!(target.check_parent_height(u64::MAX - 1).is_ok());
    assert!(target.check_parent_height(u64::MAX).is_err());
    assert!(target.check_parent_height(0).is_err());
}

#[test]
fn request_requires_exact_boundary_and_keeps_all_lanes() {
    for selected in 0..2 {
        let request = canonical_request(selected, 3);
        assert_eq!(request.boundary().height, 9);
        assert_eq!(request.target().activation_height(), 10);
        assert_eq!(request.tip_class, class(selected));
        assert!(request.lanes.iter().all(Option::is_some));
    }
    for height in [0, 8, 10, u64::MAX] {
        let (pending, target, mut parent, epoch) = pending_fixture(0, 3);
        parent.height = height;
        assert!(matches!(
            HistoryStepRetirementRequest::from_pending(pending, target, &parent, &epoch),
            Err(HistoryStepRetirementError::Boundary)
        ));
    }
    for index in 0..super::super::ACC_LANES {
        let (mut pending, target, parent, epoch) = pending_fixture(0, 3);
        pending.block_accumulator[index] += F128::ONE;
        assert!(
            matches!(
                HistoryStepRetirementRequest::from_pending(pending, target, &parent, &epoch),
                Err(HistoryStepRetirementError::Boundary)
            ),
            "boundary lane {index}"
        );
    }
    let (pending, target, parent, mut epoch) = pending_fixture(0, 3);
    epoch.nonce ^= 1;
    assert!(matches!(
        HistoryStepRetirementRequest::from_pending(pending, target, &parent, &epoch),
        Err(HistoryStepRetirementError::Boundary)
    ));
    let (mut pending, target, parent, epoch) = pending_fixture(0, 3);
    pending.bank_digest[0] ^= 1;
    assert!(matches!(
        HistoryStepRetirementRequest::from_pending(pending, target, &parent, &epoch),
        Err(HistoryStepRetirementError::BankIdentity)
    ));
}

#[test]
fn locally_checked_obligations_cannot_be_omitted_from_a_certificate() {
    for checked in 0..3 {
        let (mut pending, target, parent, epoch) = pending_fixture(0, 3);
        if checked == 2 {
            pending.tip_fresh = None;
        } else {
            pending.lanes[checked] = PendingBankLane::Checked;
        }
        assert!(matches!(
            HistoryStepRetirementRequest::from_pending(pending, target, &parent, &epoch),
            Err(HistoryStepRetirementError::AlreadyDischarged)
        ));
    }
}

#[test]
fn reduction_replays_without_matrices_and_preserves_nonselected_claims() {
    for selected in 0..2 {
        for live_mask in 0..4 {
            let (request, matrices) = algebra_fixture(selected, live_mask);
            let matrix = HistoryStepMatrixLease::resident(matrices[selected].clone());
            let proof = request.prove_reduction(&matrix).unwrap();
            let encoded = proof.encode_for(&request).unwrap();
            let decoded = HistoryStepRetirementReduction::decode_for(&request, &encoded).unwrap();
            assert_eq!(decoded, proof);
            let checked = request.verify_reduction(&decoded).unwrap();
            let expected: Vec<_> = checked
                .obligations()
                .map(|item| {
                    assert_eq!(
                        item.claim().value,
                        stacked_matrix_mle_eval_c1(
                            &matrices[item.class_id().index()],
                            item.claim()
                        )
                    );
                    (
                        item.class_id(),
                        item.shape(),
                        item.matrix_digest(),
                        item.claim().clone(),
                    )
                })
                .collect();
            drop(checked);
            drop(matrix);
            drop(matrices);
            let pending = request.verify_reduction(&decoded).unwrap();
            assert_eq!(pending.request_binding(), request.binding());
            assert_eq!(pending.target(), request.target());
            assert_eq!(pending.boundary(), request.boundary());
            assert_eq!(
                pending.obligations().count(),
                1 + usize::from(live_mask & (1 << (1 - selected)) != 0)
            );
            for (item, expected) in pending.obligations().zip(expected) {
                assert_eq!(
                    (
                        item.class_id(),
                        item.shape(),
                        item.matrix_digest(),
                        item.claim()
                    ),
                    (expected.0, expected.1, expected.2, &expected.3)
                );
                if item.class_id().index() != selected {
                    assert_eq!(
                        Some(item.claim()),
                        request.lanes[item.class_id().index()].as_ref()
                    );
                }
            }
        }
    }
}

#[test]
fn every_fold_field_is_checked() {
    let (request, matrices) = algebra_fixture(1, 3);
    let proof = request
        .prove_reduction(&HistoryStepMatrixLease::resident(matrices[1].clone()))
        .unwrap();
    let bytes = proof.encode_for(&request).unwrap();
    for offset in (REDUCTION_HEADER_BYTES..bytes.len()).step_by(16) {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        let decoded = HistoryStepRetirementReduction::decode_for(&request, &bad).unwrap();
        assert!(
            request.verify_reduction(&decoded).is_err(),
            "unchecked field half at {offset}"
        );
    }
}

#[test]
fn changed_context_cannot_relabel_an_existing_fold() {
    let (original, matrices) = algebra_fixture(0, 3);
    let proof = original
        .prove_reduction(&HistoryStepMatrixLease::resident(matrices[0].clone()))
        .unwrap();
    for mutation in 0..16 {
        let (mut request, _) = algebra_fixture(0, 3);
        match mutation {
            0 => request.target.activation_height += 1,
            1 => request.target.next_bank_digest[0] ^= 1,
            2 => request.target.legacy_bank_digest[0] ^= 1,
            3 => {
                request.target.schedule =
                    ForkSchedule::new(Some(4), V2Activation::new(10, 30)).unwrap()
            }
            4 => request.parent_header.nonce ^= 1,
            5 => request.parent_header.timestamp += 1,
            6 => request.boundary.state_root[0] ^= 1,
            7 => request.boundary.alloc_counter += 1,
            8 => request.epoch_anchor_header.nonce ^= 1,
            9 => request.lanes[1].as_mut().unwrap().value += F256::ONE,
            10 => request.lanes[1].as_mut().unwrap().point[0] += F256::ONE,
            11 => request.lanes[1] = None,
            12 => request.fresh.value += F256::ONE,
            13 => request.requirements[1].digest[0] ^= 1,
            14 => request.requirements[1].shape.const_pin = None,
            15 => {
                request.target.schedule =
                    ForkSchedule::new(Some(5), V2Activation::new(10, 40)).unwrap()
            }
            _ => unreachable!(),
        }
        request.binding = request.compute_binding();
        assert_ne!(
            request.binding(),
            original.binding(),
            "unbound context {mutation}"
        );
        assert!(request.verify_reduction(&proof).is_err());
        let mut relabeled = proof.clone();
        relabeled.request_binding = request.binding();
        assert!(
            request.verify_reduction(&relabeled).is_err(),
            "transcript ignored context {mutation}"
        );
    }
}

#[test]
fn sealed_parent_nonce_changes_request_even_with_identical_semantic_tip() {
    let (pending, target, parent, epoch) = pending_fixture(0, 3);
    let original =
        HistoryStepRetirementRequest::from_pending(pending, target, &parent, &epoch).unwrap();
    let (pending, target, mut parent, epoch) = pending_fixture(0, 3);
    parent.nonce ^= 1;
    let changed =
        HistoryStepRetirementRequest::from_pending(pending, target, &parent, &epoch).unwrap();
    assert_eq!(original.boundary(), changed.boundary());
    assert_ne!(original.binding(), changed.binding());
}

#[test]
fn codec_rejects_truncation_extensions_versions_and_wrong_requests() {
    let (request, matrices) = algebra_fixture(0, 3);
    let proof = request
        .prove_reduction(&HistoryStepMatrixLease::resident(matrices[0].clone()))
        .unwrap();
    let bytes = proof.encode_for(&request).unwrap();
    for length in 0..bytes.len() {
        assert!(HistoryStepRetirementReduction::decode_for(&request, &bytes[..length]).is_err());
    }
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(HistoryStepRetirementReduction::decode_for(&request, &extended).is_err());
    for offset in 0..REDUCTION_HEADER_BYTES {
        let mut bad = bytes.clone();
        bad[offset] ^= 0xFF;
        assert!(
            HistoryStepRetirementReduction::decode_for(&request, &bad).is_err(),
            "header byte {offset}"
        );
    }
    let mut wrong_shape = proof;
    wrong_shape.fold.phase1_rounds.push([F256::ZERO; 2]);
    assert!(wrong_shape.encode_for(&request).is_err());
    assert!(request.verify_reduction(&wrong_shape).is_err());
    for (index, expected) in [(0, 3017), (1, 3273)] {
        let request = canonical_request(index, 3);
        assert_eq!(request.reduction_wire_bytes(), expected);
    }
}

#[test]
fn prover_rejects_substituted_matrix_even_with_seeded_identity() {
    let (request, _) = algebra_fixture(0, 3);
    let wrong = synthetic_satisfiable(7, 7, 123456).0;
    wrong.seed_statement_digest(request.requirements[0].digest);
    assert!(matches!(
        request.prove_reduction(&HistoryStepMatrixLease::resident(wrong)),
        Err(HistoryStepRetirementError::Matrix(
            HistoryStepBankError::MatrixDigest(_)
        ))
    ));
    let wrong_shape = synthetic_satisfiable(8, 8, 900).0;
    assert!(matches!(
        request.prove_reduction(&HistoryStepMatrixLease::resident(wrong_shape)),
        Err(HistoryStepRetirementError::Matrix(
            HistoryStepBankError::MatrixShape(_)
        ))
    ));
}

#[test]
fn wrong_fresh_or_selected_accumulated_values_do_not_reduce_honestly() {
    let (honest_request, matrices) = algebra_fixture(1, 3);
    let proof = honest_request
        .prove_reduction(&HistoryStepMatrixLease::resident(matrices[1].clone()))
        .unwrap();
    for which in 0..2 {
        let (mut bad_request, _) = algebra_fixture(1, 3);
        if which == 0 {
            bad_request.fresh.value += F256::ONE;
        } else {
            bad_request.lanes[1].as_mut().unwrap().value += F256::ONE;
        }
        bad_request.binding = bad_request.compute_binding();
        let mut bad_proof = proof.clone();
        bad_proof.request_binding = bad_request.binding;
        assert!(bad_request.verify_reduction(&bad_proof).is_err());
    }
}

#[test]
fn compact_and_resident_matrices_produce_the_same_reduction() {
    let (request, matrices) = algebra_fixture(1, 3);
    let mut artifact = Vec::new();
    matrices[1].write_artifact(&mut artifact).unwrap();
    let compact = CompactFieldR1cs::open(
        artifact.into_boxed_slice(),
        request.shape(),
        request.requirements[1].digest,
    )
    .unwrap();
    let resident = request
        .prove_reduction(&HistoryStepMatrixLease::resident(matrices[1].clone()))
        .unwrap();
    let compact = request
        .prove_reduction(&HistoryStepMatrixLease::compact(compact))
        .unwrap();
    assert_eq!(resident, compact);
}

fn trace_reduction(
    request: &HistoryStepRetirementRequest,
    proof: &HistoryStepRetirementReduction,
    live_override: Option<F128>,
    incoming_override: Option<C1MatrixAccClaim>,
) -> (FieldR1cs, Vec<F128>, std::ops::Range<usize>) {
    use crate::acceptance::trace::matrix_fold::{
        C1FreshLincheckClaimTrace, C1MatrixAccClaimTrace, C1MatrixFoldProofTrace,
    };
    use crate::acceptance::trace::pin_eq_ext;
    use noid_ivc_core::challenger::fs_pack_bytes_lanes;
    use noid_ivc_core::field_circuit::{ExtExpr, FieldR1csBuilder, LinExpr};

    fn alloc_ext(b: &mut FieldR1csBuilder, value: F256) -> ExtExpr {
        ExtExpr::new(
            LinExpr::from_wire(b.alloc_f128(value.lo)),
            LinExpr::from_wire(b.alloc_f128(value.hi)),
        )
    }
    let native = request.verify_reduction(proof).unwrap();
    let expected = native
        .obligations()
        .find(|item| item.class_id() == request.tip_class())
        .unwrap()
        .claim();
    let mut builder = FieldR1csBuilder::new();
    let mutation_start = builder.num_wires();
    let packed = fs_pack_bytes_lanes(&request.binding());
    let digest = std::array::from_fn(|index| LinExpr::from_wire(builder.alloc_f128(packed[index])));
    let fresh = &request.fresh;
    let fresh_trace = C1FreshLincheckClaimTrace {
        alpha: alloc_ext(&mut builder, fresh.alpha),
        z_skip: alloc_ext(&mut builder, fresh.z_skip),
        x_inner_rest: fresh
            .x_inner_rest
            .iter()
            .map(|&value| alloc_ext(&mut builder, value))
            .collect(),
        r_inner_rest: fresh
            .r_inner_rest
            .iter()
            .map(|&value| alloc_ext(&mut builder, value))
            .collect(),
        z_partial: fresh
            .z_partial
            .iter()
            .map(|&value| alloc_ext(&mut builder, value))
            .collect(),
        value: alloc_ext(&mut builder, fresh.value),
    };
    let incoming = incoming_override.unwrap_or_else(|| request.incoming());
    let incoming_trace = C1MatrixAccClaimTrace::alloc(&mut builder, &incoming);
    let live = live_override.unwrap_or(if request.lanes[request.tip_class.index()].is_some() {
        F128::ONE
    } else {
        F128::ZERO
    });
    let live = LinExpr::from_wire(builder.alloc_f128(live));
    let proof_trace =
        C1MatrixFoldProofTrace::alloc(&mut builder, &proof.fold, request.shape().k_log);
    let mutation_end = builder.num_wires();
    let output = super::trace::verify_retirement_fold_trace(
        &mut builder,
        request.shape().k_log,
        request.shape().k_skip,
        &digest,
        &fresh_trace,
        &incoming_trace,
        &live,
        &proof_trace,
    );
    for (actual, expected) in output.point.iter().zip(&expected.point) {
        pin_eq_ext(&mut builder, actual, &ExtExpr::constant(*expected));
    }
    pin_eq_ext(
        &mut builder,
        &output.value,
        &ExtExpr::constant(expected.value),
    );
    let (relation, witness) = builder.build();
    (relation, witness, mutation_start..mutation_end)
}

#[test]
fn retirement_trace_matches_native_and_constrains_every_input_and_proof_wire() {
    for selected in 0..2 {
        for mask in [0, 3] {
            let (request, matrices) = algebra_fixture(selected, mask);
            let proof = request
                .prove_reduction(&HistoryStepMatrixLease::resident(
                    matrices[selected].clone(),
                ))
                .unwrap();
            let (relation, witness, mutations) = trace_reduction(&request, &proof, None, None);
            assert!(relation.satisfies(&witness));
            let survivors = relation.flip_battery(&witness).survivors(mutations);
            assert!(
                survivors.is_empty(),
                "unconstrained retirement wires: {survivors:?}"
            );
        }
    }
}

#[test]
fn retirement_trace_rejects_nonboolean_liveness_and_noncanonical_dead_claims() {
    let (request, matrices) = algebra_fixture(0, 0);
    let proof = request
        .prove_reduction(&HistoryStepMatrixLease::resident(matrices[0].clone()))
        .unwrap();
    let (relation, witness, _) = trace_reduction(&request, &proof, Some(F128::new(2, 0)), None);
    assert!(!relation.satisfies(&witness));
    let mut incoming = request.incoming();
    incoming.point[0] = F256::ONE;
    let (relation, witness, _) = trace_reduction(&request, &proof, None, Some(incoming));
    assert!(!relation.satisfies(&witness));
}

#[test]
fn canonical_retirement_fold_trace_geometry() {
    // Shape-only zero polynomial witnesses measure the reduction gadget at
    // both real widths. They are not claims about the release matrices.
    for selected in 0..2 {
        let mut request = canonical_request(selected, 3);
        request.fresh.value = F256::ZERO;
        for claim in request.lanes.iter_mut().flatten() {
            claim.value = F256::ZERO;
        }
        request.binding = request.compute_binding();
        let k_log = request.shape().k_log;
        let proof = HistoryStepRetirementReduction {
            class_id: request.tip_class,
            request_binding: request.binding(),
            fold: C1MatrixFoldProof {
                phase1_rounds: vec![[F256::ZERO; 2]; k_log + 1],
                g_v: F256::ZERO,
                g_e: F256::ZERO,
                phase2_rounds: vec![[F256::ZERO; 2]; k_log],
                final_matrix_eval: F256::ZERO,
            },
        };
        let (relation, witness, _) = trace_reduction(&request, &proof, None, None);
        assert!(relation.satisfies(&witness));
        eprintln!(
            "retirement reduction only: class=B{} k_log={} useful_rows={} domain={} proof_bytes={}",
            request.tip_class.current_tier(),
            k_log,
            relation.useful_rows,
            relation.m,
            proof.encode_for(&request).unwrap().len()
        );
    }
}
