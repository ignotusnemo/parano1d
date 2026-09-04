//! [G] item 5b step 3 — the wallet-PCS SOURCE-LEAF family discharged IN-TRACE
//! through the real outer PCS.
//!
//! This replays the production authorization source-leaf hash through the
//! `region_merkle_slot_e2e` discharge pattern. The source-leaf family's
//! committed columns (IN0,IN1,C0..C3) live
//! as witness slices; its claim DAG (carry-selection → walk → distance-2
//! compress substitution → shift/shift2 discharges) is replayed by the
//! in-trace verifier twins; every terminal claim AND the leaf digest (C0/C1 at
//! the digest slot) are pinned to the IO slice, and `prove/verify_field_with_
//! public_io` turns them into opening claims against the committed witness.
//! A flipped committed lane breaks its opening claim → the BaseFold layer
//! rejects. This is the in-trace source-leaf digest the SB6 composition wires
//! into the Merkle path family's entry.

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::flat_mds;
use noid_ivc_core::deep_chain::leaf_hash::{
    build_source_leaf_columns, source_leaf_fixed_patterns, source_leaf_refs, SourceLeafChain,
    SourceLeafColumns,
};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, prove_shift_discharge_pow2,
    verify_column_relation, verify_shift_discharge, verify_shift_discharge_pow2, ColRef,
    ColumnRelationProof, RelationColumns, RelationTerm, ShiftDischargeProof,
};
use noid_ivc_core::deep_chain::schedule::carry_selection_terms;
use noid_ivc_core::deep_chain::source_tree::compress_iv_flat;
use noid_ivc_core::deep_chain::{
    prove_deep_chain_walk, verify_deep_chain_walk, DeepChainWalkProof, LaneClaimGroup,
};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, FsChannelTrace, LinExpr};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec, WitnessSlice};
use noid_poseidon2b::native::permutation::STATE_SIZE;
use noid_recursive::acceptance::trace::deep_chain::{
    verify_column_relation_trace, verify_deep_chain_walk_trace, verify_shift_discharge_trace,
    ColumnRelationProofTrace, DeepChainWalkProofTrace, LaneClaimGroupTrace, RelationTermTrace,
    ShiftDischargeProofTrace,
};
use noid_recursive::acceptance::trace::{mul, pin_eq};

const DOMAIN: &[u8] = b"source-leaf-family-dag";
const OUTER_DOMAIN: &[u8] = b"region-source-leaf-slot-e2e";

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn f128(&mut self) -> F128 {
        F128 {
            lo: self.next_u64(),
            hi: self.next_u64(),
        }
    }
}

struct NativePending {
    point: Vec<F128>,
    value: F128,
}

struct NativeArtifacts {
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pending: Vec<NativePending>,
}

/// Run the native source-leaf region DAG (prover + verifier channels in
/// lockstep, mirroring `source_leaf_region_dag_roundtrip_and_negatives`),
/// returning every proof and the verifier-derived pending claims — including
/// the two digest pins (C0/C1 at the digest slot).
fn run_source_leaf_native(
    chain: &SourceLeafChain,
    cols: &SourceLeafColumns,
    w_log: usize,
) -> NativeArtifacts {
    let iv = compress_iv_flat();
    let fixed = source_leaf_fixed_patterns(chain, iv);
    let refs = source_leaf_refs(0, 0);
    let committed: Vec<&[F128]> = vec![
        &cols.in_[0],
        &cols.in_[1],
        &cols.c[0],
        &cols.c[1],
        &cols.c[2],
        &cols.c[3],
    ];
    let internal: Vec<&[F128]> = cols.s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(DOMAIN);
    let mut ch_v = FsLaneChallenger::new(DOMAIN);
    let mut pending: Vec<NativePending> = Vec::new();

    // Carry-selection → walk group.
    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&refs.c, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &sel_terms,
        &RelationColumns {
            committed: &committed,
            internal: &internal,
            fixed: &fixed,
        },
        &mut ch_p,
    );
    let sel_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho,
        &sel_terms,
        &fixed,
        &sel_proof,
        &mut ch_v,
    )
    .expect("native selection");
    let mut group_values = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms)
        .iter()
        .zip(sel_proof.final_values.iter())
    {
        match r {
            ColRef::Committed(_) => pending.push(NativePending {
                point: sel_point.clone(),
                value: *v,
            }),
            ColRef::Internal(j) => group_values[*j] = *v,
            _ => unreachable!(),
        }
    }

    let groups = vec![LaneClaimGroup {
        point: sel_point.clone(),
        values: group_values,
    }];
    let (walk_proof, _) = prove_deep_chain_walk(&cols.s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native walk");

    // Substitution.
    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = source_leaf_substitution_terms_native(&refs, alpha);
    let mut target = F128::ZERO;
    let mut p = F128::ONE;
    for e in 0..STATE_SIZE {
        p = p * alpha;
        target += p * terminal.values[e];
    }
    let (sub_proof, _, _) = prove_column_relation(
        target,
        &terminal.point,
        &sub_terms,
        &RelationColumns {
            committed: &committed,
            internal: &[],
            fixed: &fixed,
        },
        &mut ch_p,
    );
    let sub_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &sub_terms,
        &fixed,
        &sub_proof,
        &mut ch_v,
    )
    .expect("native substitution");

    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms)
        .iter()
        .zip(sub_proof.final_values.iter())
    {
        match r {
            ColRef::Committed(_) => pending.push(NativePending {
                point: sub_point.clone(),
                value: *v,
            }),
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                let pt =
                    verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).expect("shift");
                pending.push(NativePending {
                    point: pt,
                    value: pr.final_value,
                });
                shifts.push((0usize, *c, pr));
            }
            ColRef::CommittedShift2(c) => {
                let (pr, _) =
                    prove_shift_discharge_pow2(committed[*c], &sub_point, *v, 1, &mut ch_p);
                let pt = verify_shift_discharge_pow2(w_log, &sub_point, *v, 1, &pr, &mut ch_v)
                    .expect("shift2");
                pending.push(NativePending {
                    point: pt,
                    value: pr.final_value,
                });
                shifts.push((1usize, *c, pr));
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "native lockstep");

    NativeArtifacts {
        sel_proof,
        walk_proof,
        sub_proof,
        shifts,
        pending,
    }
}

/// The native source-leaf substitution terms (α-batched), reproduced here to
/// keep the claimed-ref shape aligned with the trace twin below.
fn source_leaf_substitution_terms_native(
    refs: &noid_ivc_core::deep_chain::leaf_hash::SourceLeafRefs,
    alpha: F128,
) -> Vec<RelationTerm> {
    noid_ivc_core::deep_chain::leaf_hash::source_leaf_substitution_terms(refs, alpha)
}

fn alloc_column_slice(
    b: &mut FieldR1csBuilder,
    col: &[F128],
    log2_len: usize,
) -> (WitnessSlice, Vec<LinExpr>) {
    let block = 1usize << log2_len;
    while b.num_wires() % block != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let index = b.num_wires() / block;
    let wires: Vec<LinExpr> = col
        .iter()
        .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
        .collect();
    for _ in col.len()..block {
        b.alloc_f128(F128::ZERO);
    }
    (WitnessSlice { log2_len, index }, wires)
}

/// Trace twin of `source_leaf_substitution_terms`: α-power coefficients as
/// LinExpr (m[j] = Σ_e α^{e+1}·flat(MDS_FULL[e][j])), factor lists a
/// line-by-line shadow. Returns the terms and the α-power wires.
fn source_leaf_substitution_terms_trace(
    b: &mut FieldR1csBuilder,
    refs: &noid_ivc_core::deep_chain::leaf_hash::SourceLeafRefs,
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let mds = flat_mds(true);
    let mut alpha_pows = Vec::with_capacity(STATE_SIZE);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..STATE_SIZE {
        acc = mul(b, &acc, alpha);
        alpha_pows.push(acc.clone());
    }
    let m: Vec<LinExpr> = (0..STATE_SIZE)
        .map(|j| {
            let mut a = LinExpr::zero();
            for e in 0..STATE_SIZE {
                a = a.add(&alpha_pows[e].scale(mds[e][j]));
            }
            a
        })
        .collect();
    let mut terms = Vec::new();
    for i in 0..2 {
        let in_col = ColRef::Committed(refs.in_[i]);
        let c_sh = ColRef::CommittedShift(refs.c[i]);
        let c_sh2 = ColRef::CommittedShift2(refs.c[i]);
        for factors in [
            vec![ColRef::Fixed(refs.hp), in_col],
            vec![ColRef::Fixed(refs.even), c_sh2],
            vec![ColRef::Fixed(refs.odd), c_sh],
            vec![ColRef::Fixed(refs.odd), c_sh2],
        ] {
            terms.push(RelationTermTrace {
                coeff: m[i].clone(),
                factors,
            });
        }
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(refs.iv[j - 2])],
        });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(refs.odd), ColRef::CommittedShift(refs.c[j])],
        });
    }
    (terms, alpha_pows)
}

struct PendingClaimTrace {
    col: usize,
    point: Vec<LinExpr>,
    value: LinExpr,
}

#[test]
fn region_source_leaf_slot_end_to_end() {
    let n_cols = 3usize;
    let chain = SourceLeafChain { n_cols };
    let w_log = chain.stride().trailing_zeros() as usize;
    let (log_rows, leaf_index) = (6usize, 5usize);

    let mut rng = Rng(0x50EAF_C0DE);
    let symbols: Vec<F128> = (0..n_cols * 2).map(|_| rng.f128()).collect();
    let cols = build_source_leaf_columns(&chain, log_rows, leaf_index, &symbols, w_log);

    let native = run_source_leaf_native(&chain, &cols, w_log);
    let iv = compress_iv_flat();
    let fixed = source_leaf_fixed_patterns(&chain, iv);
    let refs = source_leaf_refs(0, 0);

    // ---- Trace circuit: committed columns as slices, then the DAG twins.
    let mut b = FieldR1csBuilder::new();
    let column_data: [&[F128]; 6] = [
        &cols.in_[0],
        &cols.in_[1],
        &cols.c[0],
        &cols.c[1],
        &cols.c[2],
        &cols.c[3],
    ];
    let mut slices = Vec::new();
    for col in column_data.iter() {
        slices.push(alloc_column_slice(&mut b, col, w_log));
    }

    let mut ch = FsChannelTrace::new(&mut b, DOMAIN);
    let mut pending: Vec<PendingClaimTrace> = Vec::new();
    let zero = LinExpr::zero();

    // Carry-selection → walk group (β-power coefficients).
    let beta = ch.sample_f128(&mut b);
    let mut beta_pow = LinExpr::constant(F128::ONE);
    let mut sel_terms_e: Vec<RelationTermTrace> = Vec::new();
    for j in 0..STATE_SIZE {
        beta_pow = mul(&mut b, &beta_pow, &beta);
        sel_terms_e.push(RelationTermTrace {
            coeff: beta_pow.clone(),
            factors: vec![ColRef::Committed(refs.c[j])],
        });
        sel_terms_e.push(RelationTermTrace {
            coeff: beta_pow.clone(),
            factors: vec![ColRef::Internal(j)],
        });
    }
    let rho = ch.sample_f128_vec(&mut b, w_log);
    let sel_e = ColumnRelationProofTrace::alloc(&mut b, &native.sel_proof, w_log, 2 * STATE_SIZE);
    let sel_point = verify_column_relation_trace(
        &mut b,
        &mut ch,
        w_log,
        &zero,
        &rho,
        &sel_terms_e,
        &fixed,
        &sel_e,
    );
    let sel_claimed = claimed_refs(&carry_selection_terms(&refs.c, F128::ONE));
    let mut group_values: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    for (r, v) in sel_claimed.iter().zip(sel_e.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push(PendingClaimTrace {
                col: *c,
                point: sel_point.clone(),
                value: v.clone(),
            }),
            ColRef::Internal(j) => group_values[*j] = v.clone(),
            _ => unreachable!(),
        }
    }

    let groups_e = vec![LaneClaimGroupTrace {
        point: sel_point.clone(),
        values: group_values,
    }];
    let walk_e = DeepChainWalkProofTrace::alloc(&mut b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(&mut b, &mut ch, w_log, &groups_e, &walk_e);

    // Substitution (α-power coefficients, distance-2 wiring).
    let alpha = ch.sample_f128(&mut b);
    let sub_terms_native = source_leaf_substitution_terms_native(&refs, F128::ONE);
    let (sub_terms_e, alpha_pows) = source_leaf_substitution_terms_trace(&mut b, &refs, &alpha);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(&mut b, &alpha_pows[e], &terminal.values[e]));
    }
    let n_sub_claims = claimed_refs(&sub_terms_native).len();
    let sub_e = ColumnRelationProofTrace::alloc(&mut b, &native.sub_proof, w_log, n_sub_claims);
    let sub_point = verify_column_relation_trace(
        &mut b,
        &mut ch,
        w_log,
        &target,
        &terminal.point,
        &sub_terms_e,
        &fixed,
        &sub_e,
    );

    let sub_claimed = claimed_refs(&sub_terms_native);
    let mut shift_cursor = 0usize;
    for (r, v) in sub_claimed.iter().zip(sub_e.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push(PendingClaimTrace {
                col: *c,
                point: sub_point.clone(),
                value: v.clone(),
            }),
            ColRef::CommittedShift(_) | ColRef::CommittedShift2(_) => {
                let (shift_log, col, native_shift) = &native.shifts[shift_cursor];
                shift_cursor += 1;
                let shift_e = ShiftDischargeProofTrace::alloc(&mut b, native_shift, w_log);
                let pt = verify_shift_discharge_trace(
                    &mut b, &mut ch, w_log, &sub_point, v, *shift_log, &shift_e,
                );
                pending.push(PendingClaimTrace {
                    col: *col,
                    point: pt,
                    value: shift_e.final_value.clone(),
                });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(
        shift_cursor,
        native.shifts.len(),
        "all shift proofs consumed"
    );

    // The leaf digest (C0/C1 at the digest slot) as two opening claims — the
    // value SB6 wires into the Merkle-path family's entry.
    let d = chain.digest_slot();
    let digest_point: Vec<LinExpr> = (0..w_log)
        .map(|bb| {
            LinExpr::constant(if (d >> bb) & 1 == 1 {
                F128::ONE
            } else {
                F128::ZERO
            })
        })
        .collect();
    for lane in 0..2 {
        let value = LinExpr::from_wire(b.alloc_f128(cols.digest[lane]));
        pending.push(PendingClaimTrace {
            col: 2 + lane,
            point: digest_point.clone(),
            value,
        });
    }

    // ---- IO slice + public-IO discharge.
    let mut native_pending = native.pending;
    for lane in 0..2 {
        let digest_pt: Vec<F128> = (0..w_log)
            .map(|bb| {
                if (d >> bb) & 1 == 1 {
                    F128::ONE
                } else {
                    F128::ZERO
                }
            })
            .collect();
        native_pending.push(NativePending {
            point: digest_pt,
            value: cols.digest[lane],
        });
    }
    assert_eq!(pending.len(), native_pending.len(), "claim count lockstep");
    let lanes_per_claim = w_log + 1;
    let io_len = pending.len() * lanes_per_claim;
    let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
    let mut io_values = Vec::with_capacity(io_len);
    for nc in &native_pending {
        assert_eq!(nc.point.len(), w_log);
        io_values.extend_from_slice(&nc.point);
        io_values.push(nc.value);
    }
    let (io_slice, io_wires) = alloc_column_slice(&mut b, &io_values, io_log);
    for (ci, claim) in pending.iter().enumerate() {
        let base = ci * lanes_per_claim;
        for (k, p) in claim.point.iter().enumerate() {
            pin_eq(&mut b, p, &io_wires[base + k]);
        }
        pin_eq(&mut b, &claim.value, &io_wires[base + w_log]);
    }
    let spec = PublicIoSpec {
        io_slice,
        io_len,
        claims: pending
            .iter()
            .enumerate()
            .map(|(ci, claim)| IoClaimSpec {
                slice: slices[claim.col].0,
                point: ci * lanes_per_claim..ci * lanes_per_claim + w_log,
                value: ci * lanes_per_claim + w_log,
            })
            .collect(),
    };

    let (r1cs, z) = b.build();
    assert!(r1cs.satisfies(&z), "honest source-leaf trace unsatisfiable");
    let params = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    };
    let mut ch_p = FsLaneChallenger::new(OUTER_DOMAIN);
    let (proof, commitment, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
        &r1cs, &z, &params, &spec, &io_values, &mut ch_p,
    );
    let mut ch_v = FsLaneChallenger::new(OUTER_DOMAIN);
    noid_ivc_core::verifier::verify_field_with_public_io(
        &r1cs,
        &commitment,
        &proof,
        &spec,
        &io_values,
        &mut ch_v,
    )
    .expect("the region source-leaf slot proof verifies");

    eprintln!(
        "[region-source-leaf-slot] rows = {} (m = {}), opening claims = {}",
        z.len(),
        r1cs.m,
        spec.claims.len()
    );

    // Money negative: flip a committed C0 lane; the trace stays satisfiable but
    // the opening claim against the flipped column is now false → PCS rejects.
    let mut bad_z = z.clone();
    let carry_slice = slices[2].0; // C0
    bad_z[carry_slice.start() + 4] += F128::ONE;
    assert!(r1cs.satisfies(&bad_z), "columns are free wires");
    let mut ch_p = FsLaneChallenger::new(OUTER_DOMAIN);
    let (bad_proof, bad_commitment, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
        &r1cs, &bad_z, &params, &spec, &io_values, &mut ch_p,
    );
    let mut ch_v = FsLaneChallenger::new(OUTER_DOMAIN);
    assert!(
        noid_ivc_core::verifier::verify_field_with_public_io(
            &r1cs,
            &bad_commitment,
            &bad_proof,
            &spec,
            &io_values,
            &mut ch_v
        )
        .is_err(),
        "a flipped committed column lane must break its opening claim"
    );
}
