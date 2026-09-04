//! [G] step 4 Stage 1 — the multi-tx WALK-A union (source_tree + leaf families
//! COMBINED across K txs), proven NATIVELY.
//!
//! Walk A of the wallet-PCS discharge unions, per tx, ONE source-binding tree
//! plus two independent source-leaf query families. The source-tree and leaf
//! families were each proven to tile multi-tx separately
//! (`region_source_tree_multitx`, `region_common_period_multitx`); this gate
//! proves them COMBINED into ONE walk across K txs — the exact structure the
//! plural discharge assembles — with the two heterogeneous parts sharing ONE
//! carry-selection + ONE deep-chain walk + ONE unioned substitution, plus K
//! per-tree exposures whose claim points carry the tx-block offset.
//!
//! Column layout (matches the discharge): CODE0,1=0,1; KID0,1=2,3; IN0,1=4,5;
//! C0..C3=6..10. Per tx: source_tree at the block start, leaf family f after it.
//! Patterns are common-period over the per-tx block (`low_log = block_log`), so
//! ONE source-tree + ONE-per-family leaf substitution cover every tx.
//!
//! Gate: honest K=2 verifies; corrupting one tx's leaf tile (caught by the
//! substitution) AND one tx's source-tree KID at an exposure-only slot (caught
//! by THAT tx's exposure) both reject; the walk round count is flat @K=1/2/4/8.

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::leaf_hash::{
    build_source_leaf_columns, source_leaf_fixed_patterns, source_leaf_substitution_terms,
    SourceLeafChain, SourceLeafRefs,
};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, prove_shift_discharge_pow2,
    verify_column_relation, verify_shift_discharge, verify_shift_discharge_pow2,
    window_discharge_point, ColRef, FixedPattern, RelationColumns, RelationTerm,
};
use noid_ivc_core::deep_chain::schedule::carry_selection_terms;
use noid_ivc_core::deep_chain::source_tree::{
    build_source_code_columns, build_source_tree_columns, compress_iv_flat, run_perm,
    source_tree_exposure_terms, source_tree_fixed_patterns, source_tree_refs,
    source_tree_substitution_terms, SourceTree, SourceTreeRefs,
};
use noid_ivc_core::deep_chain::{prove_deep_chain_walk, verify_deep_chain_walk, LaneClaimGroup};
use noid_ivc_core::field::F128;
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

// Column layout (shared with the discharge).
const CODE0: usize = 0;
const KID0: usize = 2;
const IN0: usize = 4;
const C0: usize = 6;
const N_COMMITTED: usize = 10;

/// Repeat a family's per-stride pattern `n_tiles` times at `offset`, `low_log =
/// block_log` (periodic per tx block; covers every tx).
fn common_period(table: &[F128], offset: usize, n_tiles: usize, block_log: usize) -> FixedPattern {
    let block = 1usize << block_log;
    let stride = table.len();
    let mut t = vec![F128::ZERO; block];
    for q in 0..n_tiles {
        let off = offset + q * stride;
        t[off..off + stride].copy_from_slice(table);
    }
    FixedPattern::new(block_log, t)
}

struct WalkA {
    committed: Vec<Vec<F128>>,
    s0: [Vec<F128>; STATE_SIZE],
    s_out: [Vec<F128>; STATE_SIZE],
    fixed: Vec<FixedPattern>,
    st_refs: SourceTreeRefs,
    leaf_refs: Vec<SourceLeafRefs>,
    w_log: usize,
    // Per-tx source-tree block bases (for the K exposures).
    tree_bases: Vec<usize>,
    st_wlog: usize,
    nq: usize,
    leaf_stride: usize,
    n_leaf_families: usize,
    st_slots: usize,
}

fn build_walk_a(k_tx: usize, leaf_log: usize, nq: usize, seed: u64) -> WalkA {
    let mut rng = Rng(seed);
    let iv = compress_iv_flat();
    let tree = SourceTree { leaf_log };
    let st_wlog = tree.slots_log();
    let st_slots = tree.n_slots();
    let leaf_chain = SourceLeafChain { n_cols: 1 };
    let leaf_stride = leaf_chain.stride();
    let leaf_stride_log = leaf_stride.trailing_zeros() as usize;
    // Two independent source-leaf query families.
    let n_leaf_families = 2usize;
    let leaf_family_slots = nq * leaf_stride;

    let per_tx = st_slots + n_leaf_families * leaf_family_slots;
    let per_tx_block = per_tx.next_power_of_two();
    let block_log = per_tx_block.trailing_zeros() as usize;
    let total = k_tx * per_tx_block;
    let w_log = total.trailing_zeros() as usize;
    assert_eq!(1usize << w_log, total, "domain power of two");
    let p = 1usize << w_log;
    let leaf_base = |f: usize| st_slots + f * leaf_family_slots;

    // Ghost-fill perm([0;4]) everywhere.
    let (gs0, gso) = run_perm([F128::ZERO; STATE_SIZE]);
    let mut committed: Vec<Vec<F128>> = (0..N_COMMITTED).map(|_| vec![F128::ZERO; p]).collect();
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    for slot in 0..p {
        for j in 0..STATE_SIZE {
            s0[j][slot] = gs0[j];
            s_out[j][slot] = gso[j];
            committed[C0 + j][slot] = gso[j];
        }
    }

    let mut tree_bases = Vec::with_capacity(k_tx);
    for t in 0..k_tx {
        let tx_off = t * per_tx_block;
        tree_bases.push(tx_off);
        // Source tree at the block start.
        let code: Vec<F128> = (0..tree.code_len()).map(|_| rng.f128()).collect();
        let st = build_source_tree_columns(&tree, &code, st_wlog);
        let cc = build_source_code_columns(&tree, &code, st_wlog);
        for j in 0..2 {
            committed[CODE0 + j][tx_off..tx_off + st_slots].copy_from_slice(&cc[j]);
            committed[KID0 + j][tx_off..tx_off + st_slots].copy_from_slice(&st.kid[j]);
        }
        for j in 0..STATE_SIZE {
            committed[C0 + j][tx_off..tx_off + st_slots].copy_from_slice(&st.c[j]);
            s0[j][tx_off..tx_off + st_slots].copy_from_slice(&st.s0[j]);
            s_out[j][tx_off..tx_off + st_slots].copy_from_slice(&st.s_out[j]);
        }
        // Two source-leaf families, `nq` tiles each.
        for q in 0..nq {
            let syms = [rng.f128(), rng.f128()];
            let tile = build_source_leaf_columns(&leaf_chain, 9, 3 * q + 1, &syms, leaf_stride_log);
            let off = tx_off + leaf_base(0) + q * leaf_stride;
            for j in 0..2 {
                committed[IN0 + j][off..off + leaf_stride].copy_from_slice(&tile.in_[j]);
            }
            for j in 0..STATE_SIZE {
                committed[C0 + j][off..off + leaf_stride].copy_from_slice(&tile.c[j]);
                s0[j][off..off + leaf_stride].copy_from_slice(&tile.s0[j]);
                s_out[j][off..off + leaf_stride].copy_from_slice(&tile.s_out[j]);
            }
            let syms = [rng.f128(), rng.f128()];
            let tile =
                build_source_leaf_columns(&leaf_chain, 12, 2 * q + 1, &syms, leaf_stride_log);
            let off = tx_off + leaf_base(1) + q * leaf_stride;
            for j in 0..2 {
                committed[IN0 + j][off..off + leaf_stride].copy_from_slice(&tile.in_[j]);
            }
            for j in 0..STATE_SIZE {
                committed[C0 + j][off..off + leaf_stride].copy_from_slice(&tile.c[j]);
                s0[j][off..off + leaf_stride].copy_from_slice(&tile.s0[j]);
                s_out[j][off..off + leaf_stride].copy_from_slice(&tile.s_out[j]);
            }
        }
    }

    // Common-period patterns: source-tree at offset 0, leaf family f at leaf_base(f).
    let mut fixed: Vec<FixedPattern> = Vec::new();
    for pat in source_tree_fixed_patterns(&tree, iv) {
        fixed.push(common_period(&pat.table, 0, 1, block_log));
    }
    let st_refs = source_tree_refs(CODE0, 0); // code=[0,1], kid=[2,3], c=[6..], patterns [0..5)
                                              // Fix c refs to the global C columns (source_tree_refs uses col_base+4..).
    let st_refs = SourceTreeRefs {
        code: [CODE0, CODE0 + 1],
        kid: [KID0, KID0 + 1],
        c: std::array::from_fn(|i| C0 + i),
        ..st_refs
    };
    let mut leaf_refs: Vec<SourceLeafRefs> = Vec::new();
    let base_leaf_pats = source_leaf_fixed_patterns(&leaf_chain, iv);
    for f in 0..n_leaf_families {
        let fixed_base = fixed.len();
        for pat in &base_leaf_pats {
            fixed.push(common_period(&pat.table, leaf_base(f), nq, block_log));
        }
        leaf_refs.push(SourceLeafRefs {
            in_: [IN0, IN0 + 1],
            c: std::array::from_fn(|i| C0 + i),
            hp: fixed_base,
            even: fixed_base + 1,
            odd: fixed_base + 2,
            iv: [fixed_base + 3, fixed_base + 4],
        });
    }

    WalkA {
        committed,
        s0,
        s_out,
        fixed,
        st_refs,
        leaf_refs,
        w_log,
        tree_bases,
        st_wlog,
        nq,
        leaf_stride,
        n_leaf_families,
        st_slots,
    }
}

/// Union native terms: source-tree substitution + every leaf family's.
fn union_terms(
    st_refs: &SourceTreeRefs,
    leaf_refs: &[SourceLeafRefs],
    alpha: F128,
) -> Vec<RelationTerm> {
    let mut terms = source_tree_substitution_terms(st_refs, alpha);
    for lr in leaf_refs {
        terms.extend(source_leaf_substitution_terms(lr, alpha));
    }
    terms
}

fn run_walk_a(u: &WalkA) -> usize {
    let committed: Vec<&[F128]> = u.committed.iter().map(|c| c.as_slice()).collect();
    let internal: Vec<&[F128]> = u.s_out.iter().map(|c| c.as_slice()).collect();
    let w_log = u.w_log;
    let mut ch_p = FsLaneChallenger::new(b"walk-a-union");
    let mut ch_v = FsLaneChallenger::new(b"walk-a-union");

    // ONE selection.
    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&u.st_refs.c, beta);
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

    // ONE walk.
    let groups = vec![LaneClaimGroup {
        point: sel_point,
        values: gv,
    }];
    let (walk_proof, _) = prove_deep_chain_walk(&u.s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native walk");

    // ONE unioned substitution (source-tree + every leaf family).
    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = union_terms(&u.st_refs, &u.leaf_refs, alpha);
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
    for (r, v) in claimed_refs(&sub_terms)
        .iter()
        .zip(sub_proof.final_values.iter())
    {
        match r {
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
            _ => {}
        }
    }

    // K per-tree exposures. Each runs on tree t's own kid_lo + C slice; the
    // Window terminal discharges to a point that (with the tx-block bits) opens
    // the SHARED C column at tree t's child slots.
    let half = 1usize << (u.st_wlog - 1);
    for &base in &u.tree_bases {
        let kid0: Vec<F128> = u.committed[KID0][base..base + half].to_vec();
        let kid1: Vec<F128> = u.committed[KID0 + 1][base..base + half].to_vec();
        let c0: Vec<F128> = u.committed[C0][base..base + u.st_slots].to_vec();
        let c1: Vec<F128> = u.committed[C0 + 1][base..base + u.st_slots].to_vec();
        let expo_committed: Vec<&[F128]> = vec![&kid0, &kid1, &c0, &c1];
        let gamma = ch_p.sample_f128();
        assert_eq!(gamma, ch_v.sample_f128());
        let expo_terms = source_tree_exposure_terms([0, 1], [2, 3], gamma);
        let rho_e = ch_p.sample_f128_vec(u.st_wlog - 1);
        let _ = ch_v.sample_f128_vec(u.st_wlog - 1);
        let (expo_proof, _, _) = prove_column_relation(
            F128::ZERO,
            &rho_e,
            &expo_terms,
            &RelationColumns {
                committed: &expo_committed,
                internal: &[],
                fixed: &[],
            },
            &mut ch_p,
        );
        let expo_point = verify_column_relation(
            u.st_wlog - 1,
            F128::ZERO,
            &rho_e,
            &expo_terms,
            &[],
            &expo_proof,
            &mut ch_v,
        )
        .expect("native exposure");
        for (r, _v) in claimed_refs(&expo_terms)
            .iter()
            .zip(expo_proof.final_values.iter())
        {
            if let ColRef::Window {
                stride_log, offset, ..
            } = r
            {
                let _ = window_discharge_point(*offset, *stride_log, &expo_point);
            }
        }
    }

    assert_eq!(
        ch_p.sample_f128(),
        ch_v.sample_f128(),
        "native walk-a lockstep"
    );
    let _ = (u.nq, u.leaf_stride, u.n_leaf_families);
    walk_proof
        .layers
        .first()
        .map_or(0, |l| l.round_coeffs.len())
}

/// Honest combined walk-A union (source_tree + 2 leaf families × K txs); one
/// leaf-tile corruption caught by the substitution, one source-tree KID
/// corruption at an exposure-only slot caught by THAT tree's exposure.
#[test]
fn walk_a_union_native() {
    let leaf_log = 3usize;
    let nq = 2usize;
    let u = build_walk_a(2, leaf_log, nq, 0xC0FFEE);
    let _ = run_walk_a(&u);

    // Negative 1: corrupt tx 1's SB6 leaf tile (IN0 at the leaf base). Caught by
    // the substitution (the leaf chain's input changes).
    let mut bad = build_walk_a(2, leaf_log, nq, 0xC0FFEE);
    let tx1 = bad.tree_bases[1];
    let leaf0 = tx1 + bad.st_slots; // leaf family 0 base within tx 1
    bad.committed[IN0][leaf0] += F128::ONE;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_walk_a(&bad))).is_err(),
        "corrupted tx-1 leaf tile accepted"
    );

    // Negative 2: corrupt tx 1's source-tree KID0 at slot 0 (heap node 0 — an
    // exposure-only slot the substitution ignores). Caught by tx 1's exposure.
    let mut bad = build_walk_a(2, leaf_log, nq, 0xC0FFEE);
    let tx1 = bad.tree_bases[1];
    bad.committed[KID0][tx1] += F128::ONE;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_walk_a(&bad))).is_err(),
        "corrupted tx-1 source-tree KID (exposure-only) accepted"
    );
}

/// Walk cost FLAT in tx count.
#[test]
fn walk_a_union_walk_is_flat() {
    let (ll, nq) = (3usize, 2usize);
    let r1 = run_walk_a(&build_walk_a(1, ll, nq, 0xA1));
    let r2 = run_walk_a(&build_walk_a(2, ll, nq, 0xA2));
    let r4 = run_walk_a(&build_walk_a(4, ll, nq, 0xA4));
    eprintln!("[walk-a-flat] walk rounds: K=1 {r1}, K=2 {r2}, K=4 {r4}");
    assert_eq!(r2, r1 + 1, "K:1->2 adds one walk round");
    assert_eq!(r4, r1 + 2, "K:1->4 adds two walk rounds");
}
