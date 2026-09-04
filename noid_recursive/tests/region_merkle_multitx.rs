//! [G] step 4 Stage 1 — the multi-tx MERKLE-union flatness mechanism, proven
//! NATIVELY (fast; no heavy prove).
//!
//! The wallet-PCS discharge authenticates several Merkle legs per transaction,
//! including source and intermediate commitment paths. Each is a
//! `MerklePathFamily` of a DIFFERENT depth. `region_common_period_multitx.rs`
//! proves common-period tiling for leaf families of the same stride. This gate
//! proves the harder case where Merkle legs
//! of DIFFERENT depths (hence different strides) share ONE data-parallel walk
//! via a common per-tx PERIOD (not a per-stride period), so K transactions add
//! only `log K` walk rounds instead of a K-fold walk.
//!
//! Mechanism (identical to the leaf union, generalized to mixed strides):
//!   - per-tx block `B = Σ_leg nq·stride(leg)`, padded to a power of two;
//!   - leg `f` placed at within-block offset `o_f`; its 8 merkle patterns + a
//!     region selector rebuilt at `low_log = log B` (periodic per tx block,
//!     covers every tx for free, eq tensor stays `O(B)` — flat in K);
//!   - ONE booleanity + ONE carry-selection + ONE deep-chain walk + ONE unioned
//!     substitution discharge every leg of every tx.
//!
//! Gate: honest K = 2 verifies; corrupting one tx's leg tile is caught by the
//! single relation set; and the walk round count is measured at K = 1/2/4/8 to
//! show it is flat (logarithmic in K).

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, prove_shift_discharge_pow2,
    verify_column_relation, verify_shift_discharge, verify_shift_discharge_pow2, ColRef,
    FixedPattern, RelationColumns, RelationTerm,
};
use noid_ivc_core::deep_chain::schedule::{
    build_merkle_path_columns, carry_selection_terms, flat_of_tower_u128, merkle_booleanity_terms,
    merkle_fixed_patterns, merkle_substitution_terms, MerkleFamilyRefs, MerklePathFamily,
    MerklePathWitness,
};
use noid_ivc_core::deep_chain::source_tree::run_perm;
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
    fn bit(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

fn iv_flat() -> [F128; 2] {
    let iv = capacity_iv(TAG_COMPRESS);
    [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
}

/// Rebuild a leg's per-stride pattern as a COMMON-PERIOD table of length
/// `2^block_log`: the single-path stride pattern placed `nq` times starting at
/// `offset`, zero elsewhere; `low_log = block_log` so the pattern is periodic
/// over the per-tx block and covers every tx for free.
fn common_period(
    stride_table: &[F128],
    offset: usize,
    nq: usize,
    block_log: usize,
) -> FixedPattern {
    let block = 1usize << block_log;
    let stride = stride_table.len();
    let mut t = vec![F128::ZERO; block];
    for q in 0..nq {
        let off = offset + q * stride;
        t[off..off + stride].copy_from_slice(stride_table);
    }
    FixedPattern::new(block_log, t)
}

/// A leg-type's refs over caller-managed tables: global carries `c_refs`,
/// per-leg `E/SIB/D` at `col_base`, its 8 merkle patterns at `fixed_base`.
fn refs_for(col_base: usize, fixed_base: usize, c_refs: [usize; STATE_SIZE]) -> MerkleFamilyRefs {
    MerkleFamilyRefs {
        e: [col_base, col_base + 1],
        sib: [col_base + 2, col_base + 3],
        d: col_base + 4,
        c: c_refs,
        even: fixed_base,
        evenns: fixed_base + 1,
        evenstart: fixed_base + 2,
        odd: fixed_base + 3,
        oddns: fixed_base + 4,
        oddstart: fixed_base + 5,
        iv: [fixed_base + 6, fixed_base + 7],
    }
}

/// K txs × L legs (different depths) tiled into ONE walk at a common per-tx
/// period. Column layout: global carries `C0..C3` at columns `0..4`; leg `f`'s
/// `E0,E1,SIB0,SIB1,D` at `4 + 5·f`. Patterns: leg `f`'s 8 merkle patterns +
/// region selector at `9·f`.
struct MerkleUnion {
    committed: Vec<Vec<F128>>,
    s0: [Vec<F128>; STATE_SIZE],
    s_out: [Vec<F128>; STATE_SIZE],
    fixed: Vec<FixedPattern>,
    refs: Vec<MerkleFamilyRefs>,
    regions: Vec<usize>,
    c_refs: [usize; STATE_SIZE],
    w_log: usize,
}

fn build_merkle_union(k_tx: usize, leg_depths: &[usize], nq: usize, seed: u64) -> MerkleUnion {
    let mut rng = Rng(seed);
    let iv = iv_flat();
    let l = leg_depths.len();
    let c_refs: [usize; STATE_SIZE] = std::array::from_fn(|i| i);

    // Per-tx block: legs packed contiguously, block padded to a power of two.
    let strides: Vec<usize> = leg_depths
        .iter()
        .map(|&d| (2 * d).next_power_of_two())
        .collect();
    let leg_slots: Vec<usize> = strides.iter().map(|&s| nq * s).collect();
    let offsets: Vec<usize> = {
        let mut o = Vec::with_capacity(l);
        let mut acc = 0usize;
        for &n in &leg_slots {
            o.push(acc);
            acc += n;
        }
        o
    };
    let total_slots: usize = leg_slots.iter().sum();
    let per_tx_block = total_slots.next_power_of_two();
    let block_log = per_tx_block.trailing_zeros() as usize;
    let total = k_tx * per_tx_block;
    let w_log = total.trailing_zeros() as usize;
    assert_eq!(1usize << w_log, total, "domain must be a power of two");
    let p = 1usize << w_log;

    // Ghost-fill every slot with perm([0;4]) so untouched slots are chain-valid
    // (walk: s_out = perm(s0); selection: C == s_out).
    let (gs0, gso) = run_perm([F128::ZERO; STATE_SIZE]);
    let mut committed: Vec<Vec<F128>> = (0..4 + 5 * l).map(|_| vec![F128::ZERO; p]).collect();
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    for slot in 0..p {
        for j in 0..STATE_SIZE {
            s0[j][slot] = gs0[j];
            s_out[j][slot] = gso[j];
            committed[j][slot] = gso[j]; // C0..C3 == s_out
        }
    }

    // Tile every tx's every leg.
    for t in 0..k_tx {
        for f in 0..l {
            let family = MerklePathFamily {
                depth: leg_depths[f],
                n_paths: nq,
            };
            let stride = strides[f];
            let fam_wlog = leg_slots[f].trailing_zeros() as usize;
            assert_eq!(1usize << fam_wlog, leg_slots[f], "leg block power of two");
            let witnesses: Vec<MerklePathWitness> = (0..nq)
                .map(|_| MerklePathWitness {
                    entry: [rng.f128(), rng.f128()],
                    siblings: (0..family.depth)
                        .map(|_| [rng.f128(), rng.f128()])
                        .collect(),
                    directions: (0..family.depth).map(|_| rng.bit()).collect(),
                })
                .collect();
            let mcols = build_merkle_path_columns(&family, iv, &witnesses, fam_wlog);
            let off = t * per_tx_block + offsets[f];
            let col_base = 4 + 5 * f;
            let n = leg_slots[f];
            for j in 0..2 {
                committed[col_base + j][off..off + n].copy_from_slice(&mcols.e[j][0..n]);
                committed[col_base + 2 + j][off..off + n].copy_from_slice(&mcols.sib[j][0..n]);
            }
            committed[col_base + 4][off..off + n].copy_from_slice(&mcols.d[0..n]);
            for j in 0..STATE_SIZE {
                committed[j][off..off + n].copy_from_slice(&mcols.c[j][0..n]);
                s0[j][off..off + n].copy_from_slice(&mcols.s0[j][0..n]);
                s_out[j][off..off + n].copy_from_slice(&mcols.s_out[j][0..n]);
            }
            let _ = stride;
        }
    }

    // COMMON-PERIOD patterns: leg f's 8 merkle patterns tiled nq times at its
    // within-block offset, plus a region selector over its slots; all at
    // low_log = block_log (periodic per tx block; fire in every tx, never in
    // another leg's slots).
    let mut fixed: Vec<FixedPattern> = Vec::new();
    let mut refs: Vec<MerkleFamilyRefs> = Vec::new();
    let mut regions: Vec<usize> = Vec::new();
    for f in 0..l {
        let family = MerklePathFamily {
            depth: leg_depths[f],
            n_paths: nq,
        };
        let fixed_base = fixed.len();
        for pat in merkle_fixed_patterns(&family, iv) {
            fixed.push(common_period(&pat.table, offsets[f], nq, block_log));
        }
        refs.push(refs_for(4 + 5 * f, fixed_base, c_refs));
        // Region selector: 1 over the whole leg's slots within each tx block.
        let mut t = vec![F128::ZERO; per_tx_block];
        for s in offsets[f]..offsets[f] + leg_slots[f] {
            t[s] = F128::ONE;
        }
        regions.push(fixed.len());
        fixed.push(FixedPattern::new(block_log, t));
    }

    MerkleUnion {
        committed,
        s0,
        s_out,
        fixed,
        refs,
        regions,
        c_refs,
        w_log,
    }
}

/// Union the legs' booleanity terms (each already gated by its own `even`
/// pattern, which is zero outside the leg).
fn union_bool(refs: &[MerkleFamilyRefs]) -> Vec<RelationTerm> {
    let mut t = Vec::new();
    for r in refs {
        t.extend(merkle_booleanity_terms(r));
    }
    t
}

/// Union the legs' substitution terms; the bare-continuity terms (no Fixed
/// factor) get their leg's region prepended so they fire only in that leg.
fn union_sub(refs: &[MerkleFamilyRefs], regions: &[usize], alpha: F128) -> Vec<RelationTerm> {
    let mut terms = Vec::new();
    for (r, &region) in refs.iter().zip(regions.iter()) {
        let mut m = merkle_substitution_terms(r, alpha);
        for t in m.iter_mut() {
            if !t.factors.iter().any(|f| matches!(f, ColRef::Fixed(_))) {
                t.factors.insert(0, ColRef::Fixed(region));
            }
        }
        terms.extend(m);
    }
    terms
}

/// Full native discharge over every tx's every leg in ONE walk; returns the
/// walk's per-layer sumcheck round count (= `w_log`, the flatness witness).
fn run_merkle_union(u: &MerkleUnion) -> usize {
    let committed: Vec<&[F128]> = u.committed.iter().map(|c| c.as_slice()).collect();
    let internal: Vec<&[F128]> = u.s_out.iter().map(|c| c.as_slice()).collect();
    let w_log = u.w_log;
    let mut ch_p = FsLaneChallenger::new(b"merkle-union");
    let mut ch_v = FsLaneChallenger::new(b"merkle-union");

    // ONE booleanity relation over the union of every leg's direction bits.
    let bool_terms = union_bool(&u.refs);
    let rho_b = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (bool_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho_b,
        &bool_terms,
        &RelationColumns {
            committed: &committed,
            internal: &[],
            fixed: &u.fixed,
        },
        &mut ch_p,
    );
    verify_column_relation(
        w_log,
        F128::ZERO,
        &rho_b,
        &bool_terms,
        &u.fixed,
        &bool_proof,
        &mut ch_v,
    )
    .expect("native merkle-union booleanity");

    // ONE carry-selection over the shared C carries.
    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&u.c_refs, beta);
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
    .expect("native merkle-union selection");
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
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native merkle walk");

    // ONE unioned substitution over EVERY leg.
    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = union_sub(&u.refs, &u.regions, alpha);
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
    .expect("native merkle-union substitution");

    // Discharge the shift claims (the distance-1 / distance-2 carry reads).
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
        "native merkle-union lockstep"
    );
    walk_proof
        .layers
        .first()
        .map_or(0, |l| l.round_coeffs.len())
}

/// Honest multi-tx Merkle union (legs of depths 3/5/2 — mixed strides 8/16/4)
/// verifies; corrupting one tx's leg tile is caught by the single relation set.
#[test]
fn common_period_multitx_merkle_union_native() {
    let depths = [3usize, 5, 2];
    let nq = 2usize;
    let u = build_merkle_union(2, &depths, nq, 0xC0FFEE);
    let _ = run_merkle_union(&u);

    // Negative: flip one sibling lane of tx 1, leg 1 (depth 5), path 0, level 0.
    let mut bad = build_merkle_union(2, &depths, nq, 0xC0FFEE);
    let strides: Vec<usize> = depths
        .iter()
        .map(|&d| (2 * d).next_power_of_two())
        .collect();
    let leg_slots: Vec<usize> = strides.iter().map(|&s| nq * s).collect();
    let per_tx_block: usize = leg_slots.iter().sum::<usize>().next_power_of_two();
    let leg1_off: usize = leg_slots[0]; // leg 1 begins after leg 0
                                        // tx 1, leg 1, path 0, level 0 sibling = column (4 + 5·1 + 2) = SIB0 of leg 1.
    let slot = per_tx_block + leg1_off;
    let sib_col = 4 + 5 * 1 + 2;
    bad.committed[sib_col][slot] += F128::ONE;
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_merkle_union(&bad)));
    assert!(
        caught.is_err(),
        "corrupted tx-1 leg tile accepted by the shared relation set"
    );
}

/// The walk cost is FLAT in tx count: doubling K adds only ~1 walk round
/// (`log K`), not a K-fold blowup — the tx-independence property for Merkle.
#[test]
fn common_period_multitx_merkle_walk_is_flat() {
    let depths = [3usize, 5, 2];
    let nq = 2usize;
    let r1 = run_merkle_union(&build_merkle_union(1, &depths, nq, 0xA1));
    let r2 = run_merkle_union(&build_merkle_union(2, &depths, nq, 0xA2));
    let r4 = run_merkle_union(&build_merkle_union(4, &depths, nq, 0xA4));
    let r8 = run_merkle_union(&build_merkle_union(8, &depths, nq, 0xA8));
    eprintln!("[merkle-flat] walk rounds: K=1 {r1}, K=2 {r2}, K=4 {r4}, K=8 {r8}");
    assert_eq!(r2, r1 + 1, "K:1->2 adds exactly one walk round");
    assert_eq!(r4, r1 + 2, "K:1->4 adds exactly two walk rounds");
    assert_eq!(r8, r1 + 3, "K:1->8 adds exactly three walk rounds");
}
