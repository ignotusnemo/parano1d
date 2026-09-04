//! [G] step 4 Stage 1 — the load-bearing multi-tx flatness mechanism, proven
//! NATIVELY (fast; no heavy prove).
//!
//! The selected region design lays all K transactions' families into ONE
//! walk at a `[tx_hi | schedule_lo]` tiling so the walk/relation cost is
//! logarithmic in the domain (the `FixedPattern` MLE reads only the low
//! `schedule_lo` bits; the high `tx_hi` coordinates integrate out).
//!
//! Two mechanisms make this work and are the ones the memory note flags as
//! UNPROVEN ("the gated homogeneous tiling does NOT prove it"):
//!
//!   1. **Common-period patterns, no bleed.** Multiple independent source-leaf
//!      query families share ONE walk. A naive per-family-stride pattern is
//!      periodic and would fire inside the OTHER family's slots; instead every
//!      family's patterns are rebuilt at ONE COMMON per-tx period `B` with the
//!      family's stride-pattern only at its offset, zero elsewhere
//!      (`low_log = log B`). Periodic over `B` ⇒ ONE pattern covers all K txs,
//!      and the eq tensor stays `O(B)` (flat in K) — NOT the `O(2^w_log)`
//!      landmine of a full-domain table.
//!
//!   2. **Flat walk.** ONE carry-selection + ONE deep-chain walk + ONE unioned
//!      substitution discharge every tile of every tx; the walk transcript is
//!      `O(w_log)` rounds, so growing K adds only `log K` rounds.
//!
//! Gate: 2 families × K txs × nq tiles into ONE walk. Honest native verify;
//! corrupting one tx's tile is caught by the single relation set; and the walk
//! proof size is measured at K = 1 / 2 / 4 to show it is flat (logarithmic).

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::leaf_hash::{
    build_source_leaf_columns, source_leaf_fixed_patterns, source_leaf_refs,
    source_leaf_substitution_terms, SourceLeafChain, SourceLeafRefs,
};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, prove_shift_discharge_pow2,
    verify_column_relation, verify_shift_discharge, verify_shift_discharge_pow2, ColRef,
    FixedPattern, RelationColumns, RelationTerm,
};
use noid_ivc_core::deep_chain::schedule::{carry_selection_terms, flat_of_tower_u128};
use noid_ivc_core::deep_chain::{prove_deep_chain_walk, verify_deep_chain_walk, LaneClaimGroup};
use noid_ivc_core::field::F128;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_COMPRESS};
use noid_poseidon2b::native::permutation::STATE_SIZE;

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

fn iv_flat() -> [F128; 2] {
    let iv = capacity_iv(TAG_COMPRESS);
    [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
}

/// Rebuild a family's per-stride pattern as a COMMON-PERIOD table of length
/// `2^block_log`: the stride-pattern placed `nq` times starting at
/// `within_block_offset`, zero elsewhere; `low_log = block_log` so the pattern
/// is periodic over the per-tx block and covers every tx for free.
fn common_period(
    stride_table: &[F128],
    within_block_offset: usize,
    nq: usize,
    block_log: usize,
) -> FixedPattern {
    let block = 1usize << block_log;
    let stride = stride_table.len();
    let mut t = vec![F128::ZERO; block];
    for q in 0..nq {
        let off = within_block_offset + q * stride;
        t[off..off + stride].copy_from_slice(stride_table);
    }
    FixedPattern::new(block_log, t)
}

/// One walk-A-leaves discharge over `k_tx × n_fam × nq` tiles laid at a
/// `[tx_hi | family | query | schedule_lo]` tiling; returns the walk-proof round
/// count (the flatness witness) after a full honest native verify.
struct LeafUnion {
    committed: Vec<Vec<F128>>,
    s0: [Vec<F128>; STATE_SIZE],
    s_out: [Vec<F128>; STATE_SIZE],
    fixed: Vec<FixedPattern>,
    leaf_refs: Vec<SourceLeafRefs>,
    w_log: usize,
}

/// Column layout (shared across every family / tx / query, tiled):
///   IN0=0, IN1=1, C0=2..C3=5.
/// Fixed patterns: family f at `[6-nothing]`; refs use fixed_base = f*5.
fn build_leaf_union(k_tx: usize, nq: usize, seed: u64) -> LeafUnion {
    let mut rng = Rng(seed);
    let src_chain = SourceLeafChain { n_cols: 1 };
    let stride = src_chain.stride();
    let stride_log = stride.trailing_zeros() as usize;

    let n_fam = 2usize;
    let per_tx_block = n_fam * nq * stride;
    let block_log = per_tx_block.trailing_zeros() as usize;
    assert_eq!(
        1usize << block_log,
        per_tx_block,
        "per-tx block must be a power of two"
    );
    let total = k_tx * per_tx_block;
    let w_log = total.trailing_zeros() as usize;
    assert_eq!(1usize << w_log, total, "domain must be a power of two");
    let p = 1usize << w_log;

    // Ghost-fill every slot with perm([0;4]) so untouched slots are chain-valid.
    let (ghost0, ghost_out) =
        noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
    let mut committed: Vec<Vec<F128>> = (0..6).map(|_| vec![F128::ZERO; p]).collect();
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    for slot in 0..p {
        for j in 0..STATE_SIZE {
            s0[j][slot] = ghost0[j];
            s_out[j][slot] = ghost_out[j];
            committed[2 + j][slot] = ghost_out[j];
        }
    }

    // Tile: family 0 at within-block offset 0, family 1 at nq*stride.
    let fam_offset = |f: usize| f * nq * stride;
    let tile_slot = |t: usize, f: usize, q: usize| t * per_tx_block + fam_offset(f) + q * stride;
    for t in 0..k_tx {
        for q in 0..nq {
            // Family 0: source-leaf (n_cols = 1) — 2 column-hash symbols.
            let syms: Vec<F128> = (0..2).map(|_| rng.f128()).collect();
            let tile = build_source_leaf_columns(&src_chain, 9, 3 * q + 1, &syms, stride_log);
            let off = tile_slot(t, 0, q);
            for j in 0..2 {
                committed[j][off..off + stride].copy_from_slice(&tile.in_[j]);
            }
            for j in 0..STATE_SIZE {
                committed[2 + j][off..off + stride].copy_from_slice(&tile.c[j]);
                s0[j][off..off + stride].copy_from_slice(&tile.s0[j]);
                s_out[j][off..off + stride].copy_from_slice(&tile.s_out[j]);
            }
            // Family 1: an independent source-leaf query.
            let syms: Vec<F128> = (0..2).map(|_| rng.f128()).collect();
            let tile = build_source_leaf_columns(&src_chain, 12, 2 * q + 1, &syms, stride_log);
            let off = tile_slot(t, 1, q);
            for j in 0..2 {
                committed[j][off..off + stride].copy_from_slice(&tile.in_[j]);
            }
            for j in 0..STATE_SIZE {
                committed[2 + j][off..off + stride].copy_from_slice(&tile.c[j]);
                s0[j][off..off + stride].copy_from_slice(&tile.s0[j]);
                s_out[j][off..off + stride].copy_from_slice(&tile.s_out[j]);
            }
        }
    }

    // COMMON-PERIOD patterns: family f at within-block offset f*nq*stride,
    // low_log = block_log (periodic per tx block; covers every tx). The five
    // Source-leaf patterns are hp, even, odd, iv0, iv1. Each independent
    // family gets the same five patterns at its own offset so they never fire
    // in another family's slots.
    let iv = iv_flat();
    let base_patterns = source_leaf_fixed_patterns(&src_chain, iv);
    let mut fixed: Vec<FixedPattern> = Vec::new();
    let mut leaf_refs: Vec<SourceLeafRefs> = Vec::new();
    for f in 0..n_fam {
        let fixed_base = fixed.len();
        for pat in &base_patterns {
            fixed.push(common_period(&pat.table, fam_offset(f), nq, block_log));
        }
        // in_ = [0,1], c = [2..5]; fixed_base points at this family's 5 patterns.
        leaf_refs.push(source_leaf_refs(0, fixed_base));
    }

    LeafUnion {
        committed,
        s0,
        s_out,
        fixed,
        leaf_refs,
        w_log,
    }
}

fn union_sub_terms(leaf_refs: &[SourceLeafRefs], alpha: F128) -> Vec<RelationTerm> {
    let mut terms = Vec::new();
    for lr in leaf_refs {
        terms.extend(source_leaf_substitution_terms(lr, alpha));
    }
    terms
}

/// Full native discharge; returns the walk's per-layer sumcheck round count
/// (= `w_log`, the flatness witness). ONE walk covers every tx, so this is the
/// LOG of the domain — doubling K adds exactly one round, not a K-fold walk.
fn run_leaf_union(u: &LeafUnion) -> usize {
    let committed: Vec<&[F128]> = u.committed.iter().map(|c| c.as_slice()).collect();
    let internal: Vec<&[F128]> = u.s_out.iter().map(|c| c.as_slice()).collect();
    let c_refs: [usize; STATE_SIZE] = std::array::from_fn(|i| 2 + i);
    let w_log = u.w_log;

    let mut ch_p = FsLaneChallenger::new(b"leaf-union");
    let mut ch_v = FsLaneChallenger::new(b"leaf-union");

    // ONE carry-selection over the shared C carries.
    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&c_refs, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &sel_terms,
        &RelationColumns {
            committed: &committed,
            internal: &internal,
            fixed: &u.fixed,
        },
        &mut ch_p,
    );
    let sel_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho,
        &sel_terms,
        &u.fixed,
        &sel_proof,
        &mut ch_v,
    )
    .expect("native selection");
    let mut gv = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms)
        .iter()
        .zip(sel_proof.final_values.iter())
    {
        match r {
            ColRef::Committed(_) => {}
            ColRef::Internal(j) => gv[*j] = *v,
            _ => unreachable!(),
        }
    }

    // ONE deep-chain walk over the shared s0.
    let groups = vec![LaneClaimGroup {
        point: sel_point,
        values: gv,
    }];
    let (walk_proof, _) = prove_deep_chain_walk(&u.s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native walk");

    // ONE unioned substitution over EVERY family.
    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = union_sub_terms(&u.leaf_refs, alpha);
    let mut target = F128::ZERO;
    let mut pw = F128::ONE;
    for e in 0..STATE_SIZE {
        pw = pw * alpha;
        target += pw * terminal.values[e];
    }
    let (sub_proof, _, _) = prove_column_relation(
        target,
        &terminal.point,
        &sub_terms,
        &RelationColumns {
            committed: &committed,
            internal: &[],
            fixed: &u.fixed,
        },
        &mut ch_p,
    );
    let sub_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &sub_terms,
        &u.fixed,
        &sub_proof,
        &mut ch_v,
    )
    .expect("native substitution");
    // Discharge the shift claims (the distance-2 carry reads).
    for (r, v) in claimed_refs(&sub_terms)
        .iter()
        .zip(sub_proof.final_values.iter())
    {
        match r {
            ColRef::Committed(_) => {}
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).expect("shift");
            }
            ColRef::CommittedShift2(c) => {
                let (pr, _) =
                    prove_shift_discharge_pow2(committed[*c], &sub_point, *v, 1, &mut ch_p);
                verify_shift_discharge_pow2(w_log, &sub_point, *v, 1, &pr, &mut ch_v)
                    .expect("shift2");
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(
        ch_p.sample_f128(),
        ch_v.sample_f128(),
        "native leaf-union lockstep"
    );
    walk_proof
        .layers
        .first()
        .map_or(0, |l| l.round_coeffs.len())
}

/// Honest multi-tx leaf union verifies; corrupting one tx's tile is caught by
/// the single relation set (no bleed, no missed tile).
#[test]
fn common_period_multitx_leaf_union_native() {
    let nq = 2usize;
    // Honest K = 2.
    let u = build_leaf_union(2, nq, 0xC0FFEE);
    let _ = run_leaf_union(&u);

    // Negative: flip one committed lane of tx 1, family 1, query 0's first
    // input symbol. The single relation set must reject (a broken tile changes
    // its column's MLE at the substitution point).
    let mut bad = u;
    let stride = SourceLeafChain { n_cols: 1 }.stride();
    let per_tx_block = 2 * nq * stride;
    // tx 1, family 1 (offset nq*stride), query 0, IN0 (column 0), slot 0 of the tile.
    let bad_slot = 1 * per_tx_block + nq * stride + 0 * stride;
    let before = bad.committed[0][bad_slot];
    bad.committed[0][bad_slot] += F128::ONE;
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_leaf_union(&bad)));
    assert!(
        caught.is_err(),
        "corrupted tx-1 tile accepted by the shared relation set"
    );
    bad.committed[0][bad_slot] = before; // restore (unused, clarity)
}

/// The walk cost is FLAT in tx count: doubling K adds only ~1 walk round
/// (`log K`), not a K-fold blowup. This is the tx-independence property.
#[test]
fn common_period_multitx_walk_is_flat() {
    let nq = 2usize;
    let r1 = run_leaf_union(&build_leaf_union(1, nq, 0xA1));
    let r2 = run_leaf_union(&build_leaf_union(2, nq, 0xA2));
    let r4 = run_leaf_union(&build_leaf_union(4, nq, 0xA4));
    let r8 = run_leaf_union(&build_leaf_union(8, nq, 0xA8));
    eprintln!("[common-period-flat] walk rounds: K=1 {r1}, K=2 {r2}, K=4 {r4}, K=8 {r8}");
    // Doubling K raises the domain by one bit ⇒ the walk gains exactly one round
    // per doubling. Linear-in-K would be r(8) ≈ 8·r(1); here it is r(1)+3.
    assert_eq!(r2, r1 + 1, "K:1->2 adds exactly one walk round");
    assert_eq!(r4, r1 + 2, "K:1->4 adds exactly two walk rounds");
    assert_eq!(r8, r1 + 3, "K:1->8 adds exactly three walk rounds");
}
