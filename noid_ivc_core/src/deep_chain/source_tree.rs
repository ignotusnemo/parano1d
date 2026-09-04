//! Source-binding Merkle tree rebuild for the wallet capsule in the
//! deep-chain region.
//!
//! The source-binding reduction recomputes the encoded-source tree and checks
//! its root against the committed source root: `2^d` leaf hashes over the
//! `Code(H·eq_right)` symbols, then `d` levels of two-permutation `compress`
//! up to the root. Replaying every `compress` inline is the ~1.7M-rows/tx
//! cost the region layer exists to fold away; here the internal tree is a
//! fan-in-2 chain of `compress` nodes whose per-node permutations are
//! verified data-parallel by the deep-chain walk, and whose node-to-child
//! wiring is a single [`ColRef::Window`] read.
//!
//! # Basis
//!
//! The wallet capsule hashes in the TOWER basis (`Poseidon2bPermutation`),
//! but the walk anchors on `permute_flat_u128` and the region columns carry
//! flat lanes. Because `permute_mut = flat→tower ∘ permute_flat ∘
//! tower→flat` and the basis change φ is F2-linear (so `φ(a+b) = φ(a)+φ(b)`
//! and XOR feed-forwards commute with it), the WHOLE tree runs in the flat
//! basis with φ applied only at the two boundaries — the leaf code symbols
//! coming in and the committed source root going out. This is the
//! same single-basis convention the proof-core PCS trees adopted; here it
//! keeps every digest lane a plain flat wire.
//!
//! # Slot layout (heap order, two permutations per node)
//!
//! Node `h` (1-indexed binary heap: root `h = 1`, children `2h`/`2h+1`)
//! occupies the slot pair `(2h, 2h+1)` — an EVEN slot (the first `compress`
//! permutation on `[left, IV]`) and an ODD slot (the second, feeding the
//! even output forward and absorbing `right`). The node's output digest
//! lands on lanes `C0/C1` of its ODD slot `2h+1`. A parent at slot `w` then
//! reads a child's digest with the SAME window on both of its slots:
//!
//! ```text
//!   Window(C_i, stride_log = 1, offset = 1)(w) = C_i(2w + 1)
//!     w = 2h   (parent even) → C_i(4h+1) = digest of child 2h  (left)
//!     w = 2h+1 (parent odd)  → C_i(4h+3) = digest of child 2h+1 (right)
//! ```
//!
//! because `2h`'s output slot is `2·(2h)+1 = 4h+1` and `2h+1`'s is `4h+3` —
//! one window ref supplies both children, no direction bit.
//!
//! For the INTERNAL tree built here the leaf digests are given (committed at
//! the leaf nodes' odd slots `2h+1`, `h ∈ [L, 2L)`), and the internal nodes
//! `h ∈ [1, L)` are the permutation-active slots. Leaf slots and the ghost
//! node 0 carry state forward.

use crate::deep_chain::relations::{ColRef, FixedPattern, RelationTerm};
use crate::deep_chain::schedule::flat_of_tower_u128;
use crate::deep_chain::{apply_round, initial_mds};
use crate::field::F128;
use noid_poseidon2b::native::domain::{TAG_COMPRESS, capacity_iv_flat};
use noid_poseidon2b::native::permutation::{MDS_FULL, N_ROUNDS, STATE_SIZE};

/// The flat-basis `compress` capacity IV (`TAG_COMPRESS`), as F128 lanes.
pub fn compress_iv_flat() -> [F128; 2] {
    let iv = capacity_iv_flat(TAG_COMPRESS);
    [
        F128 {
            lo: iv[0] as u64,
            hi: (iv[0] >> 64) as u64,
        },
        F128 {
            lo: iv[1] as u64,
            hi: (iv[1] >> 64) as u64,
        },
    ]
}

/// One Poseidon2b permutation in the flat basis, expressed as the walk
/// models it: `initial_mds` then the `N_ROUNDS` round schedule. Equal to
/// `permute_flat_u128` on the lane bit patterns (`F128{lo,hi}` IS the flat
/// u128), which is the structural anchor of the deep-chain walk.
pub fn permute_flat_state(raw: [F128; STATE_SIZE]) -> [F128; STATE_SIZE] {
    let mut state = initial_mds(raw);
    for q in 0..N_ROUNDS {
        state = apply_round(q, state);
    }
    state
}

/// Flat-basis one-permutation `hash_pair(a, b)`: `permute([a, b, 0, 0])`,
/// output lanes `(0, 1)`. Mirrors `noid_poseidon2b`'s tower `hash_pair`
/// lane-for-lane under φ (zero capacity is basis-invariant).
pub fn flat_hash_pair(a: F128, b: F128) -> [F128; 2] {
    let s = permute_flat_state([a, b, F128::ZERO, F128::ZERO]);
    [s[0], s[1]]
}

/// Flat-basis two-permutation `compress(a, b)` with capacity IV `iv`:
///
/// ```text
///   s = permute([a0, a1, iv0, iv1]); s0 += b0; s1 += b1; s = permute(s)
///   digest = (s0, s1)
/// ```
///
/// Mirrors `noid_poseidon2b::native::compress` lane-for-lane under φ.
pub fn flat_compress(iv: [F128; 2], a: [F128; 2], b: [F128; 2]) -> [F128; 2] {
    let mut s = permute_flat_state([a[0], a[1], iv[0], iv[1]]);
    s[0] += b[0];
    s[1] += b[1];
    let s = permute_flat_state(s);
    [s[0], s[1]]
}

/// Flat lane of a tower `u128` bit pattern (leaf code symbols and the root
/// constant cross the region boundary through this linear map).
pub fn flat_lane(v: u128) -> F128 {
    flat_of_tower_u128(v)
}

/// One source-binding tree instance: `2^leaf_log` leaves over a length
/// `2^(leaf_log+1)` codeword. The heap slot domain is `2^(leaf_log+2)` (two
/// permutation slots per heap node), so the region needs `w_log ≥
/// leaf_log + 2`.
#[derive(Clone, Copy, Debug)]
pub struct SourceTree {
    pub leaf_log: usize,
}

impl SourceTree {
    pub fn leaf_count(&self) -> usize {
        1usize << self.leaf_log
    }
    pub fn code_len(&self) -> usize {
        1usize << (self.leaf_log + 1)
    }
    /// Heap node count (index 0 unused; root = 1; leaves `[L, 2L)`).
    pub fn heap_len(&self) -> usize {
        1usize << (self.leaf_log + 1)
    }
    pub fn n_slots(&self) -> usize {
        1usize << (self.leaf_log + 2)
    }
    pub fn slots_log(&self) -> usize {
        self.leaf_log + 2
    }
}

/// The flat-basis region columns of one source tree: every heap node's two
/// permutation slots. `c[j][slot]` is the permutation output state (the node
/// digest lives on lanes `C0/C1` of its ODD slot); `s0` is the walk's
/// post-`initial_mds` input; `s_out == c`.
///
/// Node roles by slot (`h = slot / 2`, `local = slot & 1`):
/// - leaf odd slot (`h ∈ [L, 2L)`, `local == 1`): `hash_pair(code[2i],
///   code[2i+1])`, one permutation on `[code0, code1, 0, 0]`, `i = h − L`;
/// - internal even slot (`h ∈ [1, L)`, `local == 0`): first `compress`
///   permutation on `[left, left, IV, IV]`, `left = C(2h+1)` via the window;
/// - internal odd slot (`h ∈ [1, L)`, `local == 1`): second `compress`
///   permutation on `[even_out + right, even_out_cap]`, `right = C(2h+1)`;
/// - leaf even slots and node 0: ghost permutations carrying state forward.
pub struct SourceTreeColumns {
    pub c: [Vec<F128>; STATE_SIZE],
    pub s0: [Vec<F128>; STATE_SIZE],
    pub s_out: [Vec<F128>; STATE_SIZE],
    /// The child digest absorbed at each internal slot: `KID_i[w] =
    /// C_i(2w+1)` over the low half `w ∈ [0, 2L)`, zero above. The
    /// substitution reads these plainly at slot `w`; the exposure relation
    /// proves them against `C` via a window over the half domain.
    pub kid: [Vec<F128>; 2],
    /// The recomputed root digest: `C0/C1` at heap node 1's odd slot (3).
    pub root: [F128; 2],
}

/// Run one permutation from its raw pre-MDS input, returning the walk's
/// `s0` (post-`initial_mds`) and the output state (`s_out == c`).
pub fn run_perm(raw: [F128; STATE_SIZE]) -> ([F128; STATE_SIZE], [F128; STATE_SIZE]) {
    let s0 = initial_mds(raw);
    let mut state = s0;
    for q in 0..N_ROUNDS {
        state = apply_round(q, state);
    }
    (s0, state)
}

/// The two code lanes a leaf reads at its odd slot (`CODE0/CODE1` committed
/// columns): `CODE0[2h+1] = code[2i]`, `CODE1[2h+1] = code[2i+1]`.
pub fn build_source_code_columns(tree: &SourceTree, code: &[F128], w_log: usize) -> [Vec<F128>; 2] {
    let w = 1usize << w_log;
    assert!(w_log >= tree.slots_log(), "slot domain below the tree");
    assert_eq!(code.len(), tree.code_len(), "code length");
    let l = tree.leaf_count();
    let mut code0 = vec![F128::ZERO; w];
    let mut code1 = vec![F128::ZERO; w];
    for i in 0..l {
        let h = l + i;
        let odd = 2 * h + 1;
        code0[odd] = code[2 * i];
        code1[odd] = code[2 * i + 1];
    }
    [code0, code1]
}

/// Replay the whole tree in the flat basis and fill the region columns.
///
/// Children are filled before parents (leaves first, then heap indices
/// descending), so a parent's window read of `C(2h+1)` is already the child
/// digest. The recomputed `root` matches the native capsule tree root under
/// φ (`compute_leaf_hashes` + `MerkleTree::new_parallel`).
pub fn build_source_tree_columns(
    tree: &SourceTree,
    code: &[F128],
    w_log: usize,
) -> SourceTreeColumns {
    let w = 1usize << w_log;
    assert!(w_log >= tree.slots_log(), "slot domain below the tree");
    assert_eq!(code.len(), tree.code_len(), "code length");
    let l = tree.leaf_count();
    let iv = compress_iv_flat();

    let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);

    let mut store = |slot: usize,
                     s0v: [F128; STATE_SIZE],
                     outv: [F128; STATE_SIZE],
                     c: &mut [Vec<F128>; STATE_SIZE]| {
        for j in 0..STATE_SIZE {
            s0[j][slot] = s0v[j];
            s_out[j][slot] = outv[j];
            c[j][slot] = outv[j];
        }
    };

    // Ghost default: every slot runs the permutation on raw = 0 (leaf even
    // slots, node 0, padding past the tree). The wiring relation gates all
    // selectors off at these slots, so `raw = 0` there and the walk stays
    // consistent. Overwritten below for the perm-active slots.
    let (ghost_s0, ghost_out) = run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..w {
        store(slot, ghost_s0, ghost_out, &mut c);
    }

    // Leaves: hash_pair(code0, code1) at the odd slot; even slot ghost.
    for i in 0..l {
        let h = l + i;
        let raw = [code[2 * i], code[2 * i + 1], F128::ZERO, F128::ZERO];
        let (s0v, outv) = run_perm(raw);
        store(2 * h + 1, s0v, outv, &mut c);
    }

    // Internal nodes, heap indices descending (children already filled).
    for h in (1..l).rev() {
        let left = [c[0][2 * (2 * h) + 1], c[1][2 * (2 * h) + 1]];
        let right = [c[0][2 * (2 * h + 1) + 1], c[1][2 * (2 * h + 1) + 1]];
        // Even slot: first compress permutation on [left, IV].
        let even_raw = [left[0], left[1], iv[0], iv[1]];
        let (even_s0, even_out) = run_perm(even_raw);
        store(2 * h, even_s0, even_out, &mut c);
        // Odd slot: second permutation, even output fed forward, right absorbed.
        let odd_raw = [
            even_out[0] + right[0],
            even_out[1] + right[1],
            even_out[2],
            even_out[3],
        ];
        let (odd_s0, odd_out) = run_perm(odd_raw);
        store(2 * h + 1, odd_s0, odd_out, &mut c);
    }

    // Child-digest column: KID_i[w] = C_i(2w+1) over the low half (every
    // internal slot's absorbed child), read plainly by the substitution.
    let mut kid: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let half = 1usize << (tree.slots_log() - 1);
    for slot in 0..half {
        kid[0][slot] = c[0][2 * slot + 1];
        kid[1][slot] = c[1][2 * slot + 1];
    }

    let root = [c[0][3], c[1][3]];
    SourceTreeColumns {
        c,
        s0,
        s_out,
        kid,
        root,
    }
}

// ---------------------------------------------------------------------------
// Region wiring: fixed patterns, substitution and exposure terms
// ---------------------------------------------------------------------------

/// Column/pattern indices of one source-tree family. Committed column order
/// `CODE0, CODE1, KID0, KID1, C0..C3`; pattern order `EVEN_INT, ODD_INT,
/// LEAFODD, IV0, IV1`.
#[derive(Clone, Copy, Debug)]
pub struct SourceTreeRefs {
    pub code: [usize; 2],
    pub kid: [usize; 2],
    pub c: [usize; STATE_SIZE],
    pub even_int: usize,
    pub odd_int: usize,
    pub leafodd: usize,
    pub iv: [usize; 2],
}

pub fn source_tree_refs(col_base: usize, fixed_base: usize) -> SourceTreeRefs {
    SourceTreeRefs {
        code: [col_base, col_base + 1],
        kid: [col_base + 2, col_base + 3],
        c: std::array::from_fn(|i| col_base + 4 + i),
        even_int: fixed_base,
        odd_int: fixed_base + 1,
        leafodd: fixed_base + 2,
        iv: [fixed_base + 3, fixed_base + 4],
    }
}

/// The tree-structure patterns over one `n_slots` period (heap slot layout).
/// `EVEN_INT`/`ODD_INT` mark internal nodes' first/second permutation slots,
/// `LEAFODD` the leaf permutation slots, and `IV0/IV1` carry the compress
/// capacity IV at internal even slots. Node 0 and leaf even slots stay
/// ghost (all patterns zero). One period tiles per transaction, so the
/// verifier's pattern cost is transaction-count independent.
pub fn source_tree_fixed_patterns(tree: &SourceTree, iv_flat: [F128; 2]) -> Vec<FixedPattern> {
    let low_log = tree.slots_log();
    let period = tree.n_slots();
    let l = tree.leaf_count();
    let mut even_int = vec![F128::ZERO; period];
    let mut odd_int = vec![F128::ZERO; period];
    let mut leafodd = vec![F128::ZERO; period];
    let mut iv0 = vec![F128::ZERO; period];
    let mut iv1 = vec![F128::ZERO; period];
    for slot in 0..period {
        let h = slot / 2;
        let odd = slot & 1 == 1;
        if !odd && (1..l).contains(&h) {
            even_int[slot] = F128::ONE;
            iv0[slot] = iv_flat[0];
            iv1[slot] = iv_flat[1];
        } else if odd && (1..l).contains(&h) {
            odd_int[slot] = F128::ONE;
        } else if odd && (l..2 * l).contains(&h) {
            leafodd[slot] = F128::ONE;
        }
    }
    vec![
        FixedPattern::new(low_log, even_int),
        FixedPattern::new(low_log, odd_int),
        FixedPattern::new(low_log, leafodd),
        FixedPattern::new(low_log, iv0),
        FixedPattern::new(low_log, iv1),
    ]
}

/// Per-lane `m_j = Σ_e α^{e+1}·MDS_FULL[e][j]` (flat basis) — the walk's
/// α-batched `initial_mds` weights, shared by every family's substitution.
pub fn mds_weights_pub(alpha: F128) -> [F128; STATE_SIZE] {
    mds_weights(alpha)
}

fn mds_weights(alpha: F128) -> [F128; STATE_SIZE] {
    let mut alphas = [F128::ZERO; STATE_SIZE];
    let mut p = F128::ONE;
    for a in alphas.iter_mut() {
        p = p * alpha;
        *a = p;
    }
    std::array::from_fn(|j| {
        let mut acc = F128::ZERO;
        for e in 0..STATE_SIZE {
            acc += alphas[e] * flat_of_tower_u128(MDS_FULL[e][j]);
        }
        acc
    })
}

/// Wiring substitution for the α-batched walk terminal `Σ_j m_j·raw_j(w)`.
/// Per the heap layout, at slot `w` the absorbed child digest is `KID_i(w)`
/// (the child node equals the slot number), read plainly:
///
/// ```text
///   raw_0 = INT·KID0 + ODD_INT·C0(w−1) + LEAFODD·CODE0
///   raw_1 = INT·KID1 + ODD_INT·C1(w−1) + LEAFODD·CODE1
///   raw_2 = IV0_pat  + ODD_INT·C2(w−1)
///   raw_3 = IV1_pat  + ODD_INT·C3(w−1)
/// ```
///
/// (`INT = EVEN_INT + ODD_INT`; the even slot absorbs the left child on a
/// fresh IV, the odd slot the even output fed forward plus the right child;
/// leaf odd slots run `hash_pair(CODE0, CODE1)` with zero capacity.)
pub fn source_tree_substitution_terms(refs: &SourceTreeRefs, alpha: F128) -> Vec<RelationTerm> {
    let m = mds_weights(alpha);
    let mut terms = Vec::new();
    for i in 0..2 {
        let kid = ColRef::Committed(refs.kid[i]);
        let c_sh = ColRef::CommittedShift(refs.c[i]);
        let code = ColRef::Committed(refs.code[i]);
        for factors in [
            vec![ColRef::Fixed(refs.even_int), kid],
            vec![ColRef::Fixed(refs.odd_int), kid],
            vec![ColRef::Fixed(refs.odd_int), c_sh],
            vec![ColRef::Fixed(refs.leafodd), code],
        ] {
            terms.push(RelationTerm {
                coeff: m[i],
                factors,
            });
        }
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTerm {
            coeff: m[j],
            factors: vec![ColRef::Fixed(refs.iv[j - 2])],
        });
        terms.push(RelationTerm {
            coeff: m[j],
            factors: vec![
                ColRef::Fixed(refs.odd_int),
                ColRef::CommittedShift(refs.c[j]),
            ],
        });
    }
    terms
}

/// Exposure terms proving `KID_i(w) = C_i(2w+1)` over the HALF domain
/// `w ∈ [0, 2L)`: `0 = Σ_w eq·Σ_i γ^{i+1}·[KID_i^{lo}(w) + C_i(2w+1)]`, with
/// `C_i(2w+1)` a [`ColRef::Window`] (child length `4L = 2L·2`, in range) and
/// `KID_i^{lo}` the committed low slice. The window terminal discharges as a
/// plain `C_i` opening at [`window_discharge_point`]`(1, 1, ·)`.
pub fn source_tree_exposure_terms(
    kid_lo: [usize; 2],
    c: [usize; 2],
    gamma: F128,
) -> Vec<RelationTerm> {
    let mut terms = Vec::new();
    let mut p = F128::ONE;
    for i in 0..2 {
        p = p * gamma;
        terms.push(RelationTerm {
            coeff: p,
            factors: vec![ColRef::Committed(kid_lo[i])],
        });
        terms.push(RelationTerm {
            coeff: p,
            factors: vec![ColRef::Window {
                col: c[i],
                stride_log: 1,
                offset: 1,
            }],
        });
    }
    terms
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::{Block128, CanonicalSerialize, TowerField};

    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        fn block(&mut self) -> Block128 {
            Block128::from(((self.next_u64() as u128) << 64) | self.next_u64() as u128)
        }
    }

    fn mle_eval(col: &[F128], point: &[F128]) -> F128 {
        use crate::lincheck::build_eq_table;
        let eq = build_eq_table(point);
        let mut acc = F128::ZERO;
        for (v, e) in col.iter().zip(eq.iter()) {
            acc += *v * *e;
        }
        acc
    }

    fn digest_bytes(a0: Block128, a1: Block128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&a0.to_bytes());
        out[16..].copy_from_slice(&a1.to_bytes());
        out
    }

    fn tower_flat(b: Block128) -> F128 {
        let f = noid_core::hardware::tower_to_flat_u128(b.0);
        F128 {
            lo: f as u64,
            hi: (f >> 64) as u64,
        }
    }

    fn ref_leaf(a: Block128, b: Block128) -> [Block128; 2] {
        use noid_poseidon2b::native::permutation::Poseidon2bPermutation;
        let mut st = [a, b, Block128::ZERO, Block128::ZERO];
        Poseidon2bPermutation.permute_mut(&mut st);
        [st[0], st[1]]
    }

    fn ref_compress(l: [Block128; 2], r: [Block128; 2]) -> [Block128; 2] {
        let out =
            noid_poseidon2b::native::compress(&digest_bytes(l[0], l[1]), &digest_bytes(r[0], r[1]));
        [
            Block128::from(u128::from_le_bytes(out[..16].try_into().unwrap())),
            Block128::from(u128::from_le_bytes(out[16..].try_into().unwrap())),
        ]
    }

    /// Independent native tower reference for the whole capsule tree: leaves
    /// = `hash_pair(code[2i], code[2i+1])`, then heap-order `compress` to the
    /// root — exactly `compute_leaf_hashes` + `MerkleTree::new_parallel`.
    fn reference_root(code: &[Block128]) -> [Block128; 2] {
        let l = code.len() / 2;
        let mut dig = vec![[Block128::ZERO; 2]; 2 * l];
        for i in 0..l {
            dig[l + i] = ref_leaf(code[2 * i], code[2 * i + 1]);
        }
        for h in (1..l).rev() {
            dig[h] = ref_compress(dig[2 * h], dig[2 * h + 1]);
        }
        dig[1]
    }

    /// The flat-basis heap replay reproduces the native capsule tree root
    /// (leaf `hash_pair` + internal `compress`, heap-order) under φ, at
    /// several leaf counts and with slack `w_log`.
    #[test]
    fn source_tree_root_matches_native_capsule_tree() {
        for (leaf_log, seed, slack) in [(1usize, 0xA11u64, 0), (3, 0xB22, 0), (3, 0xC33, 1)] {
            let tree = SourceTree { leaf_log };
            let mut rng = Rng(seed);
            let code_tower: Vec<Block128> = (0..tree.code_len()).map(|_| rng.block()).collect();
            let code_flat: Vec<F128> = code_tower.iter().map(|b| tower_flat(*b)).collect();
            let w_log = tree.slots_log() + slack;

            let cols = build_source_tree_columns(&tree, &code_flat, w_log);
            let want = reference_root(&code_tower);
            assert_eq!(
                cols.root[0],
                tower_flat(want[0]),
                "root lane 0 (leaf_log={leaf_log})"
            );
            assert_eq!(
                cols.root[1],
                tower_flat(want[1]),
                "root lane 1 (leaf_log={leaf_log})"
            );
        }
    }

    /// The full region DAG for one source tree: carry-selection seeds the
    /// walk from the committed digests, the walk verifies every node's
    /// permutation, the substitution ties the walk input to the heap wiring
    /// (child digests read plainly from KID), the exposure proves KID against
    /// C through the half-domain window, and the root pins to C0/C1 at slot
    /// 3. Honest run discharges every claim true against the columns; a
    /// corrupted digest / child / code lane is caught.
    #[test]
    fn source_tree_region_dag_roundtrip_and_negatives() {
        use crate::challenger::{Challenger, FsLaneChallenger};
        use crate::deep_chain::relations::{
            RelationColumns, claimed_refs, prove_column_relation, prove_shift_discharge,
            verify_column_relation, verify_shift_discharge, window_discharge_point,
        };
        use crate::deep_chain::schedule::carry_selection_terms;
        use crate::deep_chain::{LaneClaimGroup, prove_deep_chain_walk, verify_deep_chain_walk};

        let leaf_log = 3usize;
        let tree = SourceTree { leaf_log };
        let w_log = tree.slots_log();
        let half = 1usize << (w_log - 1);
        let iv = compress_iv_flat();

        let mut rng = Rng(0x7EE);
        let code: Vec<F128> = (0..tree.code_len())
            .map(|_| tower_flat(rng.block()))
            .collect();
        let cols = build_source_tree_columns(&tree, &code, w_log);
        let code_cols = build_source_code_columns(&tree, &code, w_log);
        let fixed = source_tree_fixed_patterns(&tree, iv);
        let refs = source_tree_refs(0, 0);

        // Boolean point for the root at heap node 1's odd slot (index 3).
        let root_point: Vec<F128> = (0..w_log)
            .map(|b| {
                if (3usize >> b) & 1 == 1 {
                    F128::ONE
                } else {
                    F128::ZERO
                }
            })
            .collect();

        // committed column order matches source_tree_refs: CODE0/1, KID0/1, C0..3.
        let run = |code0: &[F128],
                   code1: &[F128],
                   kid0: &[F128],
                   kid1: &[F128],
                   c: &[Vec<F128>; STATE_SIZE]|
         -> Result<(), String> {
            let committed: Vec<&[F128]> =
                vec![code0, code1, kid0, kid1, &c[0], &c[1], &c[2], &c[3]];
            let internal: Vec<&[F128]> = cols.s_out.iter().map(|c| c.as_slice()).collect();
            let mut ch_p = FsLaneChallenger::new(b"source-tree-dag");
            let mut ch_v = FsLaneChallenger::new(b"source-tree-dag");
            let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();

            // ---- Carry selection: C ↔ walk output group.
            let beta = ch_p.sample_f128();
            assert_eq!(beta, ch_v.sample_f128());
            let sel_terms = carry_selection_terms(&refs.c, beta);
            let rho: Vec<F128> = ch_p.sample_f128_vec(w_log);
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
            .map_err(|e| format!("selection: {e}"))?;
            let sel_claimed = claimed_refs(&sel_terms);
            let mut group_values = [F128::ZERO; STATE_SIZE];
            for (r, v) in sel_claimed.iter().zip(sel_proof.final_values.iter()) {
                match r {
                    ColRef::Committed(cc) => pending.push((*cc, sel_point.clone(), *v)),
                    ColRef::Internal(j) => group_values[*j] = *v,
                    _ => unreachable!(),
                }
            }

            // ---- Walk over every node's permutation.
            let groups = vec![LaneClaimGroup {
                point: sel_point.clone(),
                values: group_values,
            }];
            let (walk_proof, _) = prove_deep_chain_walk(&cols.s0, &groups, &mut ch_p);
            let terminal = verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v)
                .map_err(|e| format!("walk: {e}"))?;

            // ---- Substitution: walk input ↔ heap wiring.
            let alpha = ch_p.sample_f128();
            assert_eq!(alpha, ch_v.sample_f128());
            let sub_terms = source_tree_substitution_terms(&refs, alpha);
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
            .map_err(|e| format!("substitution: {e}"))?;
            let sub_claimed = claimed_refs(&sub_terms);
            for (r, v) in sub_claimed.iter().zip(sub_proof.final_values.iter()) {
                match r {
                    ColRef::Committed(cc) => pending.push((*cc, sub_point.clone(), *v)),
                    ColRef::CommittedShift(cc) => {
                        let (pr, _) =
                            prove_shift_discharge(committed[*cc], &sub_point, *v, &mut ch_p);
                        let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v)
                            .map_err(|e| format!("shift: {e}"))?;
                        pending.push((*cc, pt, pr.final_value));
                    }
                    _ => unreachable!(),
                }
            }

            // ---- Exposure: KID_i(w) = C_i(2w+1) over the half domain.
            let kid_lo0 = &kid0[..half];
            let kid_lo1 = &kid1[..half];
            let expo_committed: Vec<&[F128]> = vec![kid_lo0, kid_lo1, &c[0], &c[1]];
            let gamma = ch_p.sample_f128();
            assert_eq!(gamma, ch_v.sample_f128());
            let expo_terms = source_tree_exposure_terms([0, 1], [2, 3], gamma);
            let rho_e: Vec<F128> = ch_p.sample_f128_vec(w_log - 1);
            let _ = ch_v.sample_f128_vec(w_log - 1);
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
                w_log - 1,
                F128::ZERO,
                &rho_e,
                &expo_terms,
                &[],
                &expo_proof,
                &mut ch_v,
            )
            .map_err(|e| format!("exposure: {e}"))?;
            for (r, v) in claimed_refs(&expo_terms)
                .iter()
                .zip(expo_proof.final_values.iter())
            {
                match r {
                    // KID low-slice claims: check against the low half.
                    ColRef::Committed(0) => {
                        if mle_eval(kid_lo0, &expo_point) != *v {
                            return Err("kid0 low claim false".into());
                        }
                    }
                    ColRef::Committed(1) => {
                        if mle_eval(kid_lo1, &expo_point) != *v {
                            return Err("kid1 low claim false".into());
                        }
                    }
                    // Window(C_i,1,1) → plain C_i opening at [1, expo_point].
                    ColRef::Window {
                        col,
                        stride_log,
                        offset,
                    } => {
                        let pt = window_discharge_point(*offset, *stride_log, &expo_point);
                        let idx = if *col == 2 { 0 } else { 1 };
                        if mle_eval(&c[idx], &pt) != *v {
                            return Err(format!("window C{idx} claim false"));
                        }
                    }
                    _ => unreachable!(),
                }
            }

            assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "lockstep");

            // ---- Discharge every pending PCS claim against the columns.
            for (cc, pt, v) in &pending {
                if mle_eval(committed[*cc], pt) != *v {
                    return Err(format!("claim on column {cc} is false"));
                }
            }

            // ---- Root pin: C0/C1 at slot 3 are the recomputed root.
            if mle_eval(&c[0], &root_point) != cols.root[0]
                || mle_eval(&c[1], &root_point) != cols.root[1]
            {
                return Err("root pin mismatch".into());
            }
            Ok(())
        };

        run(
            &code_cols[0],
            &code_cols[1],
            &cols.kid[0],
            &cols.kid[1],
            &cols.c,
        )
        .expect("honest source tree DAG verifies");

        // A corrupted child digest (KID lane) breaks the exposure or the
        // substitution claim.
        {
            let mut bad = cols.kid[0].clone();
            bad[3] += F128::ONE;
            assert!(
                crate::dishonest_fixture_rejected(|| {
                    run(&code_cols[0], &code_cols[1], &bad, &cols.kid[1], &cols.c)
                }),
                "corrupted KID lane accepted"
            );
        }
        // A corrupted output digest (C lane) breaks the walk/exposure/root.
        {
            let mut bad = cols.c.clone();
            bad[0][5] += F128::ONE;
            assert!(
                crate::dishonest_fixture_rejected(|| {
                    run(
                        &code_cols[0],
                        &code_cols[1],
                        &cols.kid[0],
                        &cols.kid[1],
                        &bad,
                    )
                }),
                "corrupted C lane accepted"
            );
        }
        // A corrupted leaf code lane breaks the substitution claim.
        {
            let mut bad = code_cols[0].clone();
            let leaf_slot = 2 * (tree.leaf_count()) + 1; // first leaf odd slot
            bad[leaf_slot] += F128::ONE;
            assert!(
                crate::dishonest_fixture_rejected(|| {
                    run(&bad, &code_cols[1], &cols.kid[0], &cols.kid[1], &cols.c)
                }),
                "corrupted CODE lane accepted"
            );
        }
    }

    /// The atomic correctness fact: the flat-basis `flat_compress` equals the
    /// native tower-basis `compress` lane-for-lane after φ. Everything the
    /// tree family builds rests on this.
    #[test]
    fn flat_compress_matches_native_tower_compress() {
        let mut rng = Rng(0xC0FFEE);
        let iv = compress_iv_flat();
        for _ in 0..16 {
            let a0 = rng.block();
            let a1 = rng.block();
            let b0 = rng.block();
            let b1 = rng.block();

            let native =
                noid_poseidon2b::native::compress(&digest_bytes(a0, a1), &digest_bytes(b0, b1));
            let n0 = Block128::from(u128::from_le_bytes(native[..16].try_into().unwrap()));
            let n1 = Block128::from(u128::from_le_bytes(native[16..].try_into().unwrap()));

            let got = flat_compress(
                iv,
                [tower_flat(a0), tower_flat(a1)],
                [tower_flat(b0), tower_flat(b1)],
            );
            assert_eq!(got[0], tower_flat(n0), "compress lane 0 diverges under phi");
            assert_eq!(got[1], tower_flat(n1), "compress lane 1 diverges under phi");
        }
    }
}
