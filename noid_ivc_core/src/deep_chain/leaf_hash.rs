//! Flat-basis replays of the production query-leaf hash schedules.
//!
//! Each encoded-source query opens a leaf whose hash is a fixed chain of
//! `hash_pair`/`compress` over the queried symbols plus class-constant
//! metadata (domain tag, `log_rows`, `n_cols`, leaf index). The region layer
//! proves these chains with a deep-chain family (the item-3 clone of
//! `MerklePathFamily`); this module is the native flat-basis replay the
//! family and its gate are built against — the same single-basis convention
//! as [`super::source_tree`] (φ only at the symbol/digest boundary, every
//! interior lane a plain flat wire).

use crate::deep_chain::schedule::flat_of_tower_u128;
use crate::deep_chain::source_tree::{
    compress_iv_flat, flat_compress, flat_hash_pair, permute_flat_state, run_perm,
};
use crate::field::F128;
use noid_poseidon2b::native::domain::{TAG_EXSTSLT, capacity_iv_flat};
use noid_poseidon2b::native::permutation::STATE_SIZE;

/// Domain tag for encoded-source leaf hashes — the flat image of
/// `noid_fri_binius::interleaved_commit::SOURCE_LEAF_DOMAIN`. Kept in sync
/// with the native constant; a mismatch only yields honest-rejected proofs.
pub const SOURCE_LEAF_DOMAIN: u128 = 0xF21B_1D50_0000_0001u128;

/// Flat lane of a tower `u128` bit pattern (class-constant metadata and
/// queried symbols cross the region boundary through this linear map).
#[inline]
pub fn flat_lane(v: u128) -> F128 {
    flat_of_tower_u128(v)
}

/// Flat-basis replay of `source_leaf_hash(log_rows, n_cols, leaf_index,
/// symbols)`:
///
/// ```text
///   acc  = hash_pair(DOMAIN, log_rows)
///   meta = hash_pair(n_cols, leaf_index)
///   acc  = compress(acc, meta)
///   for k in 0..n_cols:  acc = compress(acc, hash_pair(sym[2k], sym[2k+1]))
/// ```
///
/// `symbols` are the `2·n_cols` queried codeword lanes already in the flat
/// basis. `log_rows`, `n_cols`, `leaf_index` are class/query metadata (their
/// flat images are formed here). Matches the native tower `source_leaf_hash`
/// under φ. Returns the leaf digest's two flat lanes.
pub fn flat_source_leaf_hash(
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    symbols: &[F128],
) -> [F128; 2] {
    assert_eq!(symbols.len(), n_cols * 2, "source leaf symbol count");
    let iv = compress_iv_flat();

    let acc = flat_hash_pair(flat_lane(SOURCE_LEAF_DOMAIN), flat_lane(log_rows as u128));
    let meta = flat_hash_pair(flat_lane(n_cols as u128), flat_lane(leaf_index as u128));
    let mut acc = flat_compress(iv, acc, meta);
    for k in 0..n_cols {
        let ph = flat_hash_pair(symbols[2 * k], symbols[2 * k + 1]);
        acc = flat_compress(iv, acc, ph);
    }
    acc
}

/// One source-leaf chain family instance. `n_cols` queried column pairs; the
/// per-leaf schedule occupies `4 + 3·n_cols` permutation slots (2 initial
/// `hash_pair`s + 1 two-slot `compress`, then per column a `hash_pair` + a
/// two-slot `compress`).
#[derive(Clone, Copy, Debug)]
pub struct SourceLeafChain {
    pub n_cols: usize,
}

impl SourceLeafChain {
    pub fn slots(&self) -> usize {
        4 + 3 * self.n_cols
    }
    pub fn stride(&self) -> usize {
        self.slots().next_power_of_two()
    }
    /// The slot holding the final accumulator (the leaf digest, `C0/C1`).
    pub fn digest_slot(&self) -> usize {
        3 + 3 * self.n_cols
    }
}

/// Flat-basis region columns of one source-leaf chain: every schedule slot's
/// permutation. `c[j][slot]` is the output state; the leaf digest is
/// `C0/C1` at [`SourceLeafChain::digest_slot`].
///
/// Slot roles (uniform distance-2 carry, matching the tree's `compress`
/// convention): `0` = `hash_pair(DOMAIN, log_rows)`, `1` =
/// `hash_pair(n_cols, leaf_index)`, `2/3` = the first `compress` (even
/// absorbs `acc0 = C(w−2)` on a fresh IV, odd feeds the even output forward
/// and absorbs `meta = C(w−2)`); then per column `k`: slot `4+3k` =
/// `hash_pair(sym[2k], sym[2k+1])`, `5+3k`/`6+3k` = the `compress` (even
/// absorbs the running `acc = C(w−2)`, odd absorbs `ph_k = C(w−2)`). Both
/// the acc-into-even and the hash-into-odd reads are exactly two slots back.
pub struct SourceLeafColumns {
    pub c: [Vec<F128>; STATE_SIZE],
    pub s0: [Vec<F128>; STATE_SIZE],
    pub s_out: [Vec<F128>; STATE_SIZE],
    /// The two `hash_pair` input lanes at each hash-pair slot (0 elsewhere) —
    /// the committed `IN0/IN1` columns the substitution reads.
    pub in_: [Vec<F128>; 2],
    pub digest: [F128; 2],
}

/// Replay one source-leaf chain in the flat basis and fill the region
/// columns. `symbols` are the `2·n_cols` queried flat lanes. The recomputed
/// digest matches [`flat_source_leaf_hash`] (hence native `source_leaf_hash`
/// under φ).
pub fn build_source_leaf_columns(
    chain: &SourceLeafChain,
    log_rows: usize,
    leaf_index: usize,
    symbols: &[F128],
    w_log: usize,
) -> SourceLeafColumns {
    let w = 1usize << w_log;
    assert!(w >= chain.slots(), "slot domain below the chain");
    assert_eq!(symbols.len(), chain.n_cols * 2, "source leaf symbol count");
    let iv = compress_iv_flat();

    let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);

    // Copy-only store: the permutation is run by the caller, so the ghost
    // fill runs `perm([0;4])` ONCE (not per slot) and active slots are permed
    // exactly once each (single-pass, matching `source_tree`).
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

    // Ghost default so the walk stays consistent on unused slots (raw = 0):
    // one perm, broadcast to every slot; active slots overwritten below.
    let (ghost_s0, ghost_out) = run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..w {
        store(slot, ghost_s0, ghost_out, &mut c);
    }

    // Initial block.
    let (a, b) = run_perm([
        flat_lane(SOURCE_LEAF_DOMAIN),
        flat_lane(log_rows as u128),
        F128::ZERO,
        F128::ZERO,
    ]);
    store(0, a, b, &mut c);
    let (a, b) = run_perm([
        flat_lane(chain.n_cols as u128),
        flat_lane(leaf_index as u128),
        F128::ZERO,
        F128::ZERO,
    ]);
    store(1, a, b, &mut c);
    // compress(acc0 = C(0), meta = C(1)).
    let acc0 = [c[0][0], c[1][0]];
    let (a, b) = run_perm([acc0[0], acc0[1], iv[0], iv[1]]);
    store(2, a, b, &mut c);
    let even_out: [F128; STATE_SIZE] = std::array::from_fn(|j| c[j][2]);
    let meta = [c[0][1], c[1][1]];
    let (a, b) = run_perm([
        even_out[0] + meta[0],
        even_out[1] + meta[1],
        even_out[2],
        even_out[3],
    ]);
    store(3, a, b, &mut c);

    // Per-column steps.
    for k in 0..chain.n_cols {
        let hp = 4 + 3 * k;
        let ev = 5 + 3 * k;
        let od = 6 + 3 * k;
        let (a, b) = run_perm([symbols[2 * k], symbols[2 * k + 1], F128::ZERO, F128::ZERO]);
        store(hp, a, b, &mut c);
        let acc = [c[0][ev - 2], c[1][ev - 2]]; // running acc, two slots back
        let (a, b) = run_perm([acc[0], acc[1], iv[0], iv[1]]);
        store(ev, a, b, &mut c);
        let even_out: [F128; STATE_SIZE] = std::array::from_fn(|j| c[j][ev]);
        let ph = [c[0][od - 2], c[1][od - 2]]; // ph_k = the hash_pair output, two slots back
        let (a, b) = run_perm([
            even_out[0] + ph[0],
            even_out[1] + ph[1],
            even_out[2],
            even_out[3],
        ]);
        store(od, a, b, &mut c);
    }

    // The committed hash_pair input columns (0 outside hash-pair slots).
    let mut in_: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    in_[0][0] = flat_lane(SOURCE_LEAF_DOMAIN);
    in_[1][0] = flat_lane(log_rows as u128);
    in_[0][1] = flat_lane(chain.n_cols as u128);
    in_[1][1] = flat_lane(leaf_index as u128);
    for k in 0..chain.n_cols {
        let hp = 4 + 3 * k;
        in_[0][hp] = symbols[2 * k];
        in_[1][hp] = symbols[2 * k + 1];
    }

    let d = chain.digest_slot();
    let digest = [c[0][d], c[1][d]];
    SourceLeafColumns {
        c,
        s0,
        s_out,
        in_,
        digest,
    }
}

// ---------------------------------------------------------------------------
// Region wiring: refs, fixed patterns, substitution terms
// ---------------------------------------------------------------------------

use crate::deep_chain::relations::{ColRef, FixedPattern, RelationTerm};
use crate::deep_chain::source_tree::mds_weights_pub;

/// Column/pattern indices of one source-leaf chain. Committed column order
/// `IN0, IN1, C0..C3`; pattern order `HP, EVEN, ODD, IV0, IV1`.
#[derive(Clone, Copy, Debug)]
pub struct SourceLeafRefs {
    pub in_: [usize; 2],
    pub c: [usize; STATE_SIZE],
    pub hp: usize,
    pub even: usize,
    pub odd: usize,
    pub iv: [usize; 2],
}

pub fn source_leaf_refs(col_base: usize, fixed_base: usize) -> SourceLeafRefs {
    SourceLeafRefs {
        in_: [col_base, col_base + 1],
        c: std::array::from_fn(|i| col_base + 2 + i),
        hp: fixed_base,
        even: fixed_base + 1,
        odd: fixed_base + 2,
        iv: [fixed_base + 3, fixed_base + 4],
    }
}

/// Role of a slot in the per-leaf schedule.
fn slot_role(chain: &SourceLeafChain, slot: usize) -> u8 {
    // 0 = hash_pair, 1 = compress even, 2 = compress odd, 3 = ghost.
    if slot < 2 {
        0
    } else if slot == 2 {
        1
    } else if slot == 3 {
        2
    } else if slot < chain.slots() {
        match (slot - 4) % 3 {
            0 => 0,
            1 => 1,
            _ => 2,
        }
    } else {
        3
    }
}

/// The schedule selector/constant patterns over one `stride` period. `HP`,
/// `EVEN`, `ODD` mark the slot roles; `IV0/IV1` carry the compress capacity
/// IV at even slots. One period tiles per leaf, so the verifier's pattern
/// cost is leaf-count independent.
pub fn source_leaf_fixed_patterns(
    chain: &SourceLeafChain,
    iv_flat: [F128; 2],
) -> Vec<FixedPattern> {
    let period = chain.stride();
    let low_log = period.trailing_zeros() as usize;
    let mut hp = vec![F128::ZERO; period];
    let mut even = vec![F128::ZERO; period];
    let mut odd = vec![F128::ZERO; period];
    let mut iv0 = vec![F128::ZERO; period];
    let mut iv1 = vec![F128::ZERO; period];
    for slot in 0..period {
        match slot_role(chain, slot) {
            0 => hp[slot] = F128::ONE,
            1 => {
                even[slot] = F128::ONE;
                iv0[slot] = iv_flat[0];
                iv1[slot] = iv_flat[1];
            }
            2 => odd[slot] = F128::ONE,
            _ => {}
        }
    }
    vec![
        FixedPattern::new(low_log, hp),
        FixedPattern::new(low_log, even),
        FixedPattern::new(low_log, odd),
        FixedPattern::new(low_log, iv0),
        FixedPattern::new(low_log, iv1),
    ]
}

/// Wiring substitution `Σ_j m_j·raw_j(w)` for the α-batched walk terminal.
/// The carry is uniformly two slots back (see [`build_source_leaf_columns`]):
///
/// ```text
///   raw_0 = HP·IN0 + EVEN·C0(w−2) + ODD·[C0(w−1) + C0(w−2)]
///   raw_1 = HP·IN1 + EVEN·C1(w−2) + ODD·[C1(w−1) + C1(w−2)]
///   raw_2 = IV0_pat + ODD·C2(w−1)
///   raw_3 = IV1_pat + ODD·C3(w−1)
/// ```
///
/// (`hash_pair` absorbs `IN0/IN1` on zero capacity; the compress even slot
/// absorbs the running acc `C(w−2)` on a fresh IV; the odd slot feeds the
/// even output `C(w−1)` forward and absorbs `C(w−2)` — the meta / column
/// hash.)
pub fn source_leaf_substitution_terms(refs: &SourceLeafRefs, alpha: F128) -> Vec<RelationTerm> {
    let m = mds_weights_pub(alpha);
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
            factors: vec![ColRef::Fixed(refs.odd), ColRef::CommittedShift(refs.c[j])],
        });
    }
    terms
}

// ---------------------------------------------------------------------------
// The exact-state slot-leaf sponge family ([D] migration)
// ---------------------------------------------------------------------------
//
// The exact-state UTXO commitment hashes each slot leaf with a rate-2
// Poseidon2b sponge on `capacity_iv(TAG_EXSTSLT)`, absorbing the slot's public
// statement data over TWO permutations (the native `slot_leaf_hash` in
// `noid_chain::exact_state_hash`, whose per-permutation form is
// `noid_gkr::state_leaf_killshot::evaluate_slot_leaf`):
//
// ```text
//   state = [0, 0, iv_hi, iv_lo]                    // iv = capacity_iv(TAG_EXSTSLT)
//   perm0: state[0] += amount;  state[1] += owner_hi;  state = permute(state)
//   perm1: state[0] += owner_lo; state[1] += PAD;      state = permute(state)
//   leaf  = state[0..2]
// ```
//
// where `PAD = pad_after_one_field()` is the sponge padding after three
// absorbed fields (`0x80` at byte 0, `0x01` at byte 15). Block0 = `[amount,
// owner_hi]`, block1 = `[owner_lo, PAD]`; two permutations, digest = two output
// lanes.
//
// This is a STRICT SIMPLIFICATION of the source-leaf family: no `hash_pair`
// sub-structure and a DISTANCE-1 carry (perm1 feeds directly off perm0's full
// output state one slot back), where the source leaf's two-permutation
// `compress` nodes carry two slots back. Only the SLOT-LEAF hash is a new
// schedule; everything else in the [D] migration reuses `MerklePathFamily`.
//
// # Basis
//
// Same single-basis convention as [`super::source_tree`] / the other leaf
// families: `permute_mut = flat→tower ∘ permute_flat ∘ tower→flat` and φ is
// F2-linear, so the whole sponge runs in the flat basis with φ applied only at
// the input/output boundary — every absorbed lane and digest lane a plain flat
// wire. The absorbed data is public UTXO-slot statement (amount / owner); no
// wallet secret ever enters these columns.

/// Permutation slots per sponge leaf (perm0 = even slot, perm1 = odd slot).
pub const SPONGE_LEAF_SLOTS: usize = 2;
/// The slot holding a leaf's digest (perm1's output `C0/C1`), relative to the
/// leaf's tile base.
pub const SPONGE_LEAF_DIGEST_SLOT: usize = 1;

/// The flat-basis capacity IV for the exact-state slot leaf (`TAG_EXSTSLT`),
/// as F128 lanes. Lane 0 = φ(iv_hi), lane 1 = φ(iv_lo), matching
/// `capacity_iv(TAG_EXSTSLT) = [iv_hi, iv_lo]` placed in capacity lanes 2/3.
pub fn slot_leaf_iv_flat() -> [F128; 2] {
    let iv = capacity_iv_flat(TAG_EXSTSLT);
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

/// The flat lane of the sponge padding `pad_after_one_field` (`0x80` at byte
/// 0, `0x01` at byte 15) — the final block's second rate lane. Constructed
/// byte-for-byte from the native padding, then mapped through φ.
pub fn slot_leaf_pad_flat() -> F128 {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x80;
    bytes[15] = 0x01;
    flat_lane(u128::from_le_bytes(bytes))
}

/// Flat-basis replay of the native `slot_leaf_hash(amount, owner_hi,
/// owner_lo)`: the rate-2 `TAG_EXSTSLT` sponge over two permutations.
///
/// ```text
///   s = permute([amount, owner_hi, iv0, iv1])       // absorb block0
///   s = permute([s0 + owner_lo, s1 + PAD, s2, s3])  // absorb block1
///   digest = (s0, s1)
/// ```
///
/// `amount`, `owner_hi`, `owner_lo` are the slot's public statement lanes
/// already in the flat basis (`amount = φ(Block128::from(u64))`). Matches the
/// native tower slot-leaf hash under φ. Returns the leaf digest's two flat
/// lanes.
pub fn flat_sponge_leaf_hash(amount: F128, owner_hi: F128, owner_lo: F128) -> [F128; 2] {
    let iv = slot_leaf_iv_flat();
    let pad = slot_leaf_pad_flat();
    // perm0: absorb block0 = [amount, owner_hi] on the IV capacity.
    let s = permute_flat_state([amount, owner_hi, iv[0], iv[1]]);
    // perm1: feed the full perm0 output forward, absorb block1 = [owner_lo, PAD].
    let s = permute_flat_state([s[0] + owner_lo, s[1] + pad, s[2], s[3]]);
    [s[0], s[1]]
}

/// Fill the region columns for `leaves.len()` slot-leaf sponge chains tiled at
/// stride [`SPONGE_LEAF_SLOTS`] (leaf `t` at slots `2t`/`2t+1`). `leaves[t] =
/// (amount, owner_hi, owner_lo)` in the flat basis. `w_log` must cover the
/// tiles (`2^w_log` a multiple of the stride, `≥ 2·leaves.len()`); any tile
/// past `leaves.len()` is a CANONICAL GHOST sponge leaf (`amount = owner_hi =
/// owner_lo = 0`, still absorbing the same PAD) — NOT a `perm([0;4])` slot,
/// because the periodic fixed patterns fire at every even/odd slot and must be
/// satisfied by a real sponge run. Every slot in the domain is thus perm-active
/// (even or odd of some tile), so `IN0/IN1` are read PLAINLY by the
/// substitution (no absorb selector). Returns the columns and each REAL leaf's
/// digest (`C0/C1` at its odd slot `2t+1`); leaf `t`'s digest matches
/// [`flat_sponge_leaf_hash`] (hence native `slot_leaf_hash` under φ).
///
/// Reuses the [`SourceLeafColumns`] layout: `IN0/IN1` are the two rate-absorb
/// lanes at each slot (`[amount, owner_hi]` at the even slot, `[owner_lo, PAD]`
/// at the odd slot); `c/s0/s_out` are every slot's permutation.
pub fn build_sponge_leaf_columns(
    leaves: &[(F128, F128, F128)],
    w_log: usize,
) -> (SourceLeafColumns, Vec<[F128; 2]>) {
    let w = 1usize << w_log;
    assert_eq!(
        w % SPONGE_LEAF_SLOTS,
        0,
        "domain not a multiple of the tile"
    );
    let num_tiles = w / SPONGE_LEAF_SLOTS;
    assert!(leaves.len() <= num_tiles, "more leaves than tiles");
    let iv = slot_leaf_iv_flat();
    let pad = slot_leaf_pad_flat();

    let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut in_: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; w]);

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

    // Every slot is active; a tile past `leaves.len()` is the canonical ghost
    // sponge leaf (0, 0, 0) — a real two-permutation run, so the periodic
    // even/odd patterns stay satisfied.
    let mut digests = Vec::with_capacity(leaves.len());
    for t in 0..num_tiles {
        let (amount, owner_hi, owner_lo) = if t < leaves.len() {
            leaves[t]
        } else {
            (F128::ZERO, F128::ZERO, F128::ZERO)
        };
        let even = SPONGE_LEAF_SLOTS * t;
        let odd = even + 1;
        // perm0: absorb block0 = [amount, owner_hi] on the IV capacity.
        let (a, b) = run_perm([amount, owner_hi, iv[0], iv[1]]);
        store(even, a, b, &mut c);
        // perm1: feed the full perm0 output forward, absorb block1 = [owner_lo, PAD].
        let p0: [F128; STATE_SIZE] = std::array::from_fn(|j| c[j][even]);
        let (a, b) = run_perm([p0[0] + owner_lo, p0[1] + pad, p0[2], p0[3]]);
        store(odd, a, b, &mut c);
        // Committed absorb (rate) lanes at each slot.
        in_[0][even] = amount;
        in_[1][even] = owner_hi;
        in_[0][odd] = owner_lo;
        in_[1][odd] = pad;
        if t < leaves.len() {
            digests.push([c[0][odd], c[1][odd]]);
        }
    }

    let digest = digests.first().copied().unwrap_or([F128::ZERO; 2]);
    (
        SourceLeafColumns {
            c,
            s0,
            s_out,
            in_,
            digest,
        },
        digests,
    )
}

/// Column/pattern indices of one slot-leaf sponge family. Committed column
/// order `IN0, IN1, C0..C3`; pattern order `ODD, IV0, IV1`.
#[derive(Clone, Copy, Debug)]
pub struct SpongeLeafRefs {
    pub in_: [usize; 2],
    pub c: [usize; STATE_SIZE],
    pub odd: usize,
    pub iv: [usize; 2],
}

pub fn sponge_leaf_refs(col_base: usize, fixed_base: usize) -> SpongeLeafRefs {
    SpongeLeafRefs {
        in_: [col_base, col_base + 1],
        c: std::array::from_fn(|i| col_base + 2 + i),
        odd: fixed_base,
        iv: [fixed_base + 1, fixed_base + 2],
    }
}

/// The schedule patterns over one [`SPONGE_LEAF_SLOTS`]-slot period. `ODD`
/// marks the perm1 (odd) slot; `IV0/IV1` carry the sponge capacity IV at the
/// perm0 (even) slot (zero at the odd slot). No `EVEN`/absorb selector is
/// needed: every slot absorbs a rate block, so `IN0/IN1` are read plainly, and
/// the `IV0/IV1` patterns are themselves even-gated by construction. One period
/// tiles per leaf, so the verifier's pattern cost is leaf-count independent.
pub fn sponge_leaf_fixed_patterns(iv_flat: [F128; 2]) -> Vec<FixedPattern> {
    let low_log = SPONGE_LEAF_SLOTS.trailing_zeros() as usize;
    // slot 0 = perm0 (even), slot 1 = perm1 (odd).
    let odd = vec![F128::ZERO, F128::ONE];
    let iv0 = vec![iv_flat[0], F128::ZERO];
    let iv1 = vec![iv_flat[1], F128::ZERO];
    vec![
        FixedPattern::new(low_log, odd),
        FixedPattern::new(low_log, iv0),
        FixedPattern::new(low_log, iv1),
    ]
}

/// Wiring substitution `Σ_j m_j·raw_j(w)` for the α-batched walk terminal. The
/// carry is uniformly one slot back (perm1 feeds off perm0's full output):
///
/// ```text
///   raw_0 = IN0      + ODD·C0(w−1)
///   raw_1 = IN1      + ODD·C1(w−1)
///   raw_2 = IV0_pat  + ODD·C2(w−1)
///   raw_3 = IV1_pat  + ODD·C3(w−1)
/// ```
///
/// At the even slot `ODD = 0`: `raw = [amount, owner_hi, iv0, iv1]` (the fresh
/// sponge absorb on the IV capacity). At the odd slot `ODD = 1` and the
/// `IV_pat` are zero: `raw = [owner_lo + C0(w−1), PAD + C1(w−1), C2(w−1),
/// C3(w−1)]` (the full perm0 output fed forward, block1 absorbed into the
/// rate). `IN0/IN1` read plainly because every slot absorbs a rate block.
pub fn sponge_leaf_substitution_terms(refs: &SpongeLeafRefs, alpha: F128) -> Vec<RelationTerm> {
    let m = mds_weights_pub(alpha);
    let mut terms = Vec::new();
    // Rate lanes 0/1: the absorbed block read plainly + the odd-gated carry.
    for i in 0..2 {
        terms.push(RelationTerm {
            coeff: m[i],
            factors: vec![ColRef::Committed(refs.in_[i])],
        });
        terms.push(RelationTerm {
            coeff: m[i],
            factors: vec![ColRef::Fixed(refs.odd), ColRef::CommittedShift(refs.c[i])],
        });
    }
    // Capacity lanes 2/3: the even-gated IV pattern + the odd-gated carry.
    for j in 2..STATE_SIZE {
        terms.push(RelationTerm {
            coeff: m[j],
            factors: vec![ColRef::Fixed(refs.iv[j - 2])],
        });
        terms.push(RelationTerm {
            coeff: m[j],
            factors: vec![ColRef::Fixed(refs.odd), ColRef::CommittedShift(refs.c[j])],
        });
    }
    terms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::{Challenger, FsLaneChallenger};
    use crate::deep_chain::relations::{
        ColRef, RelationColumns, claimed_refs, prove_column_relation, prove_shift_discharge,
        prove_shift_discharge_pow2, verify_column_relation, verify_shift_discharge,
        verify_shift_discharge_pow2,
    };
    use crate::deep_chain::schedule::carry_selection_terms;
    use crate::deep_chain::source_tree::compress_iv_flat;
    use crate::deep_chain::{LaneClaimGroup, prove_deep_chain_walk, verify_deep_chain_walk};
    use crate::lincheck::build_eq_table;

    fn mle(col: &[F128], point: &[F128]) -> F128 {
        let eq = build_eq_table(point);
        let mut acc = F128::ZERO;
        for (v, e) in col.iter().zip(eq.iter()) {
            acc += *v * *e;
        }
        acc
    }

    /// Run the full region DAG for one or more tiled source-leaf chains over
    /// the supplied global column data. ONE carry-selection, ONE walk and ONE
    /// substitution cover every tile; `pins` gives each tile's
    /// `(global digest slot, honest digest)` — pass the honest digest so a
    /// corrupted `c` column is caught by the pin. The fixed patterns are
    /// periodic with period = one tile's stride, so the verifier cost is
    /// tile-count independent (the `[tx_hi | schedule_lo]` flatness property).
    fn run_leaf_dag(
        chain: &SourceLeafChain,
        in0: &[F128],
        in1: &[F128],
        c: &[Vec<F128>; STATE_SIZE],
        s0: &[Vec<F128>; STATE_SIZE],
        s_out: &[Vec<F128>; STATE_SIZE],
        pins: &[(usize, [F128; 2])],
        w_log: usize,
    ) -> Result<(), String> {
        let iv = compress_iv_flat();
        let fixed = source_leaf_fixed_patterns(chain, iv);
        let refs = source_leaf_refs(0, 0);

        let committed: Vec<&[F128]> = vec![in0, in1, &c[0], &c[1], &c[2], &c[3]];
        let internal: Vec<&[F128]> = s_out.iter().map(|c| c.as_slice()).collect();
        let mut ch_p = FsLaneChallenger::new(b"leaf-dag");
        let mut ch_v = FsLaneChallenger::new(b"leaf-dag");
        let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();

        // carry selection → walk group.
        let beta = ch_p.sample_f128();
        assert_eq!(beta, ch_v.sample_f128());
        let sel_terms = carry_selection_terms(&refs.c, beta);
        let rho: Vec<F128> = ch_p.sample_f128_vec(w_log);
        let _ = ch_v.sample_f128_vec(w_log);
        let (sp, _, _) = prove_column_relation(
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
        let sel_point =
            verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, &fixed, &sp, &mut ch_v)
                .map_err(|e| format!("selection: {e}"))?;
        let mut group_values = [F128::ZERO; STATE_SIZE];
        for (r, v) in claimed_refs(&sel_terms).iter().zip(sp.final_values.iter()) {
            match r {
                ColRef::Committed(cc) => pending.push((*cc, sel_point.clone(), *v)),
                ColRef::Internal(j) => group_values[*j] = *v,
                _ => unreachable!(),
            }
        }

        // walk.
        let groups = vec![LaneClaimGroup {
            point: sel_point.clone(),
            values: group_values,
        }];
        let (wp, _) = prove_deep_chain_walk(s0, &groups, &mut ch_p);
        let terminal = verify_deep_chain_walk(w_log, &groups, &wp, &mut ch_v)
            .map_err(|e| format!("walk: {e}"))?;

        // substitution.
        let alpha = ch_p.sample_f128();
        assert_eq!(alpha, ch_v.sample_f128());
        let sub_terms = source_leaf_substitution_terms(&refs, alpha);
        let mut target = F128::ZERO;
        let mut p = F128::ONE;
        for e in 0..STATE_SIZE {
            p = p * alpha;
            target += p * terminal.values[e];
        }
        let (subp, _, _) = prove_column_relation(
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
            &subp,
            &mut ch_v,
        )
        .map_err(|e| format!("substitution: {e}"))?;
        for (r, v) in claimed_refs(&sub_terms)
            .iter()
            .zip(subp.final_values.iter())
        {
            match r {
                ColRef::Committed(cc) => pending.push((*cc, sub_point.clone(), *v)),
                ColRef::CommittedShift(cc) => {
                    let (pr, _) = prove_shift_discharge(committed[*cc], &sub_point, *v, &mut ch_p);
                    let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v)
                        .map_err(|e| format!("shift: {e}"))?;
                    pending.push((*cc, pt, pr.final_value));
                }
                ColRef::CommittedShift2(cc) => {
                    let (pr, _) =
                        prove_shift_discharge_pow2(committed[*cc], &sub_point, *v, 1, &mut ch_p);
                    let pt = verify_shift_discharge_pow2(w_log, &sub_point, *v, 1, &pr, &mut ch_v)
                        .map_err(|e| format!("shift2: {e}"))?;
                    pending.push((*cc, pt, pr.final_value));
                }
                _ => unreachable!(),
            }
        }

        assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "lockstep");

        for (cc, pt, v) in &pending {
            if mle(committed[*cc], pt) != *v {
                return Err(format!("claim on column {cc} is false"));
            }
        }
        // Per-tile digest pins.
        for (slot, dig) in pins {
            let digest_point: Vec<F128> = (0..w_log)
                .map(|bb| {
                    if (slot >> bb) & 1 == 1 {
                        F128::ONE
                    } else {
                        F128::ZERO
                    }
                })
                .collect();
            if mle(&c[0], &digest_point) != dig[0] || mle(&c[1], &digest_point) != dig[1] {
                return Err(format!("digest pin mismatch at slot {slot}"));
            }
        }
        Ok(())
    }

    /// Tile `tiles` independent source-leaf chains into one global column set
    /// at `[tx_hi | schedule_lo]` stride (tile t at slots `[t·stride,
    /// (t+1)·stride)`). The per-tile distance-2 carry stays within its tile
    /// (slots 0/1 are hash-pairs that read no carry; the compresses read at
    /// most two slots back, within the tile), so the tiles compose into one
    /// walk with no cross-tile coupling. `tiles.len()` must be a power of two
    /// and exactly fill the domain. Returns the global columns and each
    /// tile's digest.
    fn build_tiled_source_leaf(
        chain: &SourceLeafChain,
        tiles: &[(usize, usize, Vec<F128>)],
        global_w_log: usize,
    ) -> (SourceLeafColumns, Vec<[F128; 2]>) {
        let stride = chain.stride();
        let stride_log = stride.trailing_zeros() as usize;
        let w = 1usize << global_w_log;
        assert_eq!(
            tiles.len() * stride,
            w,
            "tiles must exactly fill the domain"
        );
        let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
        let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
        let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
        let mut in_: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; w]);
        let mut digests = Vec::with_capacity(tiles.len());
        for (t, (log_rows, leaf_index, symbols)) in tiles.iter().enumerate() {
            let tile =
                build_source_leaf_columns(chain, *log_rows, *leaf_index, symbols, stride_log);
            let off = t * stride;
            for j in 0..STATE_SIZE {
                c[j][off..off + stride].copy_from_slice(&tile.c[j]);
                s0[j][off..off + stride].copy_from_slice(&tile.s0[j]);
                s_out[j][off..off + stride].copy_from_slice(&tile.s_out[j]);
            }
            for j in 0..2 {
                in_[j][off..off + stride].copy_from_slice(&tile.in_[j]);
            }
            digests.push(tile.digest);
        }
        let digest = digests[0];
        (
            SourceLeafColumns {
                c,
                s0,
                s_out,
                in_,
                digest,
            },
            digests,
        )
    }

    /// The `[tx_hi | schedule_lo]` tiling: K source-leaf chains (distinct
    /// shapes/symbols) tiled into ONE column set, discharged by ONE
    /// carry-selection + ONE walk + ONE substitution with the per-tile fixed
    /// patterns (period = one tile's stride). Every tile's digest is pinned;
    /// honest run verifies, and corrupting one tile's symbol is caught — the
    /// single relation set covers all tiles, and its verifier cost does not
    /// grow with tile count (the flatness property [G] is built on).
    #[test]
    fn tiled_source_leaf_one_walk_one_relation() {
        let n_cols = 3usize;
        let chain = SourceLeafChain { n_cols };
        let stride_log = chain.stride().trailing_zeros() as usize;
        let num_tiles = 4usize; // power of two
        let global_w_log = stride_log + num_tiles.trailing_zeros() as usize;
        let stride = chain.stride();

        let mut seed = 0x71_1E_u64;
        let mut next = || {
            seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z ^= z >> 31;
            F128 {
                lo: z,
                hi: z.rotate_left(23),
            }
        };
        // Distinct (log_rows, leaf_index, symbols) per tile — the schedule is
        // the same, only the witness contents differ across txs.
        let tiles: Vec<(usize, usize, Vec<F128>)> = (0..num_tiles)
            .map(|t| {
                let symbols: Vec<F128> = (0..n_cols * 2).map(|_| next()).collect();
                (4 + t, 3 * t + 1, symbols)
            })
            .collect();
        let (cols, digests) = build_tiled_source_leaf(&chain, &tiles, global_w_log);

        let pins: Vec<(usize, [F128; 2])> = digests
            .iter()
            .enumerate()
            .map(|(t, &d)| (t * stride + chain.digest_slot(), d))
            .collect();

        run_leaf_dag(
            &chain,
            &cols.in_[0],
            &cols.in_[1],
            &cols.c,
            &cols.s0,
            &cols.s_out,
            &pins,
            global_w_log,
        )
        .expect("tiled source-leaf DAG verifies with one walk + one relation set");

        // Corrupt tile 2's first column-hash symbol: exactly that tile's
        // wiring claim (and digest) breaks; the single relation set catches it.
        {
            let mut bad = cols.in_[0].clone();
            bad[2 * stride + 4] += F128::ONE;
            assert!(
                crate::dishonest_fixture_rejected(|| run_leaf_dag(
                    &chain,
                    &bad,
                    &cols.in_[1],
                    &cols.c,
                    &cols.s0,
                    &cols.s_out,
                    &pins,
                    global_w_log,
                )),
                "corrupted tile symbol accepted"
            );
        }
    }

    /// The chain column replay's recomputed digest (from the distance-2
    /// carry slot layout) equals the direct `flat_source_leaf_hash` (hence
    /// native `source_leaf_hash` under φ) across shapes, and `c == s_out`
    /// (the digest columns are the walk outputs). This validates the slot
    /// layout the region DAG will wire.
    #[test]
    fn source_leaf_columns_digest_matches() {
        let mut seed = 0x5EEDu64;
        let mut next = || {
            seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^= z >> 31;
            F128 {
                lo: z,
                hi: z.rotate_left(17),
            }
        };
        for (n_cols, log_rows, leaf_index) in [(1usize, 4usize, 0usize), (3, 6, 5), (4, 8, 37)] {
            let chain = SourceLeafChain { n_cols };
            let w_log = chain.stride().trailing_zeros() as usize;
            let symbols: Vec<F128> = (0..n_cols * 2).map(|_| next()).collect();
            let cols = build_source_leaf_columns(&chain, log_rows, leaf_index, &symbols, w_log);

            let direct = flat_source_leaf_hash(log_rows, n_cols, leaf_index, &symbols);
            assert_eq!(cols.digest, direct, "chain digest != flat_source_leaf_hash");
            for slot in 0..(1usize << w_log) {
                for j in 0..STATE_SIZE {
                    assert_eq!(cols.c[j][slot], cols.s_out[j][slot]);
                }
            }
        }
    }

    /// The full region DAG for one source-leaf chain: carry-selection seeds
    /// the walk from the committed digests, the walk verifies every slot's
    /// permutation, the substitution ties the walk input to the distance-2
    /// chain wiring (hash-pair inputs read plainly, acc and column-hash read
    /// two slots back, feed-forward one slot back), and the digest pins to
    /// C0/C1 at the final slot. Honest run discharges every claim true; a
    /// corrupted input / output lane is caught.
    #[test]
    fn source_leaf_region_dag_roundtrip_and_negatives() {
        let n_cols = 3usize;
        let chain = SourceLeafChain { n_cols };
        let w_log = chain.stride().trailing_zeros() as usize;
        let (log_rows, leaf_index) = (6usize, 5usize);

        let mut seed = 0xA5A5u64;
        let mut next = || {
            seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z ^= z >> 31;
            F128 {
                lo: z,
                hi: z.rotate_left(29),
            }
        };
        let symbols: Vec<F128> = (0..n_cols * 2).map(|_| next()).collect();
        let cols = build_source_leaf_columns(&chain, log_rows, leaf_index, &symbols, w_log);

        run_leaf_dag(
            &chain,
            &cols.in_[0],
            &cols.in_[1],
            &cols.c,
            &cols.s0,
            &cols.s_out,
            &[(chain.digest_slot(), cols.digest)],
            w_log,
        )
        .expect("honest source leaf DAG verifies");

        // A corrupted symbol input breaks a claim.
        {
            let mut bad = cols.in_[0].clone();
            bad[4] += F128::ONE; // first column hash_pair input
            assert!(
                crate::dishonest_fixture_rejected(|| run_leaf_dag(
                    &chain,
                    &bad,
                    &cols.in_[1],
                    &cols.c,
                    &cols.s0,
                    &cols.s_out,
                    &[(chain.digest_slot(), cols.digest)],
                    w_log,
                )),
                "corrupted IN accepted"
            );
        }
        // A corrupted output digest lane breaks the walk/digest.
        {
            let mut bad = cols.c.clone();
            bad[0][chain.digest_slot()] += F128::ONE;
            assert!(
                crate::dishonest_fixture_rejected(|| run_leaf_dag(
                    &chain,
                    &cols.in_[0],
                    &cols.in_[1],
                    &bad,
                    &cols.s0,
                    &cols.s_out,
                    &[(chain.digest_slot(), cols.digest)],
                    w_log,
                )),
                "corrupted C accepted"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Exact-state slot-leaf sponge family gates
    // -----------------------------------------------------------------------

    /// The φ anchor: the flat-basis [`flat_sponge_leaf_hash`] reproduces the
    /// native tower `slot_leaf_hash` (rate-2 `TAG_EXSTSLT` sponge —
    /// `noid_chain::exact_state_hash::slot_leaf_hash` /
    /// `state_leaf_killshot::evaluate_slot_leaf`) under φ, across random
    /// (amount, owner_hi, owner_lo). Gated FIRST, before the region DAG.
    #[test]
    fn sponge_leaf_digest_matches_native_slot_leaf_hash() {
        use noid_core::Block128;
        use noid_poseidon2b::native::compression::Poseidon2bSponge;
        use noid_poseidon2b::native::domain::{TAG_EXSTSLT, capacity_iv};

        // φ: tower Block128 → flat F128 lane (per 16-byte lane).
        let tower_flat = |b: Block128| -> F128 {
            let f = noid_core::hardware::tower_to_flat_u128(b.0);
            F128 {
                lo: f as u64,
                hi: (f >> 64) as u64,
            }
        };

        // The native tower slot-leaf hash, exactly `slot_leaf_hash`: a rate-2
        // TAG_EXSTSLT sponge absorbing amount then the owner pair.
        let native_leaf = |amount: u64, owner_hi: Block128, owner_lo: Block128| -> [Block128; 2] {
            let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_EXSTSLT));
            s.absorb(Block128::from(amount));
            s.absorb_pair(owner_hi, owner_lo);
            let hash = s.finalize();
            let mut lo = [0u8; 16];
            let mut hi = [0u8; 16];
            lo.copy_from_slice(&hash[..16]);
            hi.copy_from_slice(&hash[16..]);
            [
                Block128::from(u128::from_le_bytes(lo)),
                Block128::from(u128::from_le_bytes(hi)),
            ]
        };

        let mut seed = 0x513Eu64;
        let mut next = || {
            seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        };
        for _ in 0..16 {
            let amount = next();
            let owner_hi = Block128::from(((next() as u128) << 64) | next() as u128);
            let owner_lo = Block128::from(((next() as u128) << 64) | next() as u128);

            let want = native_leaf(amount, owner_hi, owner_lo);
            let got = flat_sponge_leaf_hash(
                tower_flat(Block128::from(amount)),
                tower_flat(owner_hi),
                tower_flat(owner_lo),
            );
            assert_eq!(
                got[0],
                tower_flat(want[0]),
                "slot-leaf digest lane 0 diverges under phi"
            );
            assert_eq!(
                got[1],
                tower_flat(want[1]),
                "slot-leaf digest lane 1 diverges under phi"
            );
        }
    }

    /// The chain column replay's recomputed digest (from the distance-1 carry
    /// slot layout) equals the direct [`flat_sponge_leaf_hash`] (hence native
    /// `slot_leaf_hash` under φ) for every tiled leaf, and `c == s_out` (the
    /// digest columns are the walk outputs). Validates the slot layout the
    /// region DAG wires.
    #[test]
    fn sponge_leaf_columns_digest_matches() {
        let mut seed = 0x5107u64;
        let mut next = || {
            seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^= z >> 31;
            F128 {
                lo: z,
                hi: z.rotate_left(13),
            }
        };
        let k = 4usize; // power of two, exact fill
        let w_log = SPONGE_LEAF_SLOTS.trailing_zeros() as usize + k.trailing_zeros() as usize;
        let leaves: Vec<(F128, F128, F128)> = (0..k).map(|_| (next(), next(), next())).collect();
        let (cols, digests) = build_sponge_leaf_columns(&leaves, w_log);

        for (t, &(amount, owner_hi, owner_lo)) in leaves.iter().enumerate() {
            let direct = flat_sponge_leaf_hash(amount, owner_hi, owner_lo);
            assert_eq!(
                digests[t], direct,
                "chain digest {t} != flat_sponge_leaf_hash"
            );
            let odd = SPONGE_LEAF_SLOTS * t + SPONGE_LEAF_DIGEST_SLOT;
            assert_eq!(
                [cols.c[0][odd], cols.c[1][odd]],
                direct,
                "column digest {t}"
            );
        }
        for slot in 0..(1usize << w_log) {
            for j in 0..STATE_SIZE {
                assert_eq!(cols.c[j][slot], cols.s_out[j][slot]);
            }
        }
    }

    /// Run the full region DAG for the tiled slot-leaf sponge chains:
    /// carry-selection seeds the walk from the committed digests, the walk
    /// verifies every slot's permutation, the substitution ties the walk input
    /// to the distance-1 sponge wiring (`IN0/IN1` read plainly, capacity IV
    /// even-gated, perm0 output fed forward one slot at the odd slot), and each
    /// tile's digest pins to `C0/C1` at its odd slot. ONE carry-selection, ONE
    /// walk and ONE substitution cover every tile.
    fn run_sponge_leaf_dag(
        in0: &[F128],
        in1: &[F128],
        c: &[Vec<F128>; STATE_SIZE],
        s0: &[Vec<F128>; STATE_SIZE],
        s_out: &[Vec<F128>; STATE_SIZE],
        pins: &[(usize, [F128; 2])],
        w_log: usize,
    ) -> Result<(), String> {
        let iv = slot_leaf_iv_flat();
        let fixed = sponge_leaf_fixed_patterns(iv);
        let refs = sponge_leaf_refs(0, 0);

        let committed: Vec<&[F128]> = vec![in0, in1, &c[0], &c[1], &c[2], &c[3]];
        let internal: Vec<&[F128]> = s_out.iter().map(|c| c.as_slice()).collect();
        let mut ch_p = FsLaneChallenger::new(b"sponge-leaf-dag");
        let mut ch_v = FsLaneChallenger::new(b"sponge-leaf-dag");
        let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();

        // carry selection → walk group.
        let beta = ch_p.sample_f128();
        assert_eq!(beta, ch_v.sample_f128());
        let sel_terms = carry_selection_terms(&refs.c, beta);
        let rho: Vec<F128> = ch_p.sample_f128_vec(w_log);
        let _ = ch_v.sample_f128_vec(w_log);
        let (sp, _, _) = prove_column_relation(
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
        let sel_point =
            verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, &fixed, &sp, &mut ch_v)
                .map_err(|e| format!("selection: {e}"))?;
        let mut group_values = [F128::ZERO; STATE_SIZE];
        for (r, v) in claimed_refs(&sel_terms).iter().zip(sp.final_values.iter()) {
            match r {
                ColRef::Committed(cc) => pending.push((*cc, sel_point.clone(), *v)),
                ColRef::Internal(j) => group_values[*j] = *v,
                _ => unreachable!(),
            }
        }

        // walk.
        let groups = vec![LaneClaimGroup {
            point: sel_point.clone(),
            values: group_values,
        }];
        let (wp, _) = prove_deep_chain_walk(s0, &groups, &mut ch_p);
        let terminal = verify_deep_chain_walk(w_log, &groups, &wp, &mut ch_v)
            .map_err(|e| format!("walk: {e}"))?;

        // substitution.
        let alpha = ch_p.sample_f128();
        assert_eq!(alpha, ch_v.sample_f128());
        let sub_terms = sponge_leaf_substitution_terms(&refs, alpha);
        let mut target = F128::ZERO;
        let mut p = F128::ONE;
        for e in 0..STATE_SIZE {
            p = p * alpha;
            target += p * terminal.values[e];
        }
        let (subp, _, _) = prove_column_relation(
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
            &subp,
            &mut ch_v,
        )
        .map_err(|e| format!("substitution: {e}"))?;
        for (r, v) in claimed_refs(&sub_terms)
            .iter()
            .zip(subp.final_values.iter())
        {
            match r {
                ColRef::Committed(cc) => pending.push((*cc, sub_point.clone(), *v)),
                ColRef::CommittedShift(cc) => {
                    let (pr, _) = prove_shift_discharge(committed[*cc], &sub_point, *v, &mut ch_p);
                    let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v)
                        .map_err(|e| format!("shift: {e}"))?;
                    pending.push((*cc, pt, pr.final_value));
                }
                _ => unreachable!(),
            }
        }

        assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "lockstep");

        for (cc, pt, v) in &pending {
            if mle(committed[*cc], pt) != *v {
                return Err(format!("claim on column {cc} is false"));
            }
        }
        // Per-tile digest pins.
        for (slot, dig) in pins {
            let digest_point: Vec<F128> = (0..w_log)
                .map(|bb| {
                    if (slot >> bb) & 1 == 1 {
                        F128::ONE
                    } else {
                        F128::ZERO
                    }
                })
                .collect();
            if mle(&c[0], &digest_point) != dig[0] || mle(&c[1], &digest_point) != dig[1] {
                return Err(format!("digest pin mismatch at slot {slot}"));
            }
        }
        Ok(())
    }

    /// The slot-leaf sponge region DAG over tiled leaves: honest run discharges
    /// every claim true, and each of a corrupted absorb input (amount, owner)
    /// and a corrupted output digest breaks the DAG (relation terminal false /
    /// digest pin mismatch).
    #[test]
    fn sponge_leaf_region_dag_roundtrip_and_negatives() {
        let k = 4usize; // power of two, exact fill
        let w_log = SPONGE_LEAF_SLOTS.trailing_zeros() as usize + k.trailing_zeros() as usize;

        let mut seed = 0x5A17u64;
        let mut next = || {
            seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z ^= z >> 31;
            F128 {
                lo: z,
                hi: z.rotate_left(29),
            }
        };
        let leaves: Vec<(F128, F128, F128)> = (0..k).map(|_| (next(), next(), next())).collect();
        let (cols, digests) = build_sponge_leaf_columns(&leaves, w_log);
        let pins: Vec<(usize, [F128; 2])> = digests
            .iter()
            .enumerate()
            .map(|(t, &d)| (SPONGE_LEAF_SLOTS * t + SPONGE_LEAF_DIGEST_SLOT, d))
            .collect();

        run_sponge_leaf_dag(
            &cols.in_[0],
            &cols.in_[1],
            &cols.c,
            &cols.s0,
            &cols.s_out,
            &pins,
            w_log,
        )
        .expect("honest sponge-leaf DAG verifies");

        // Corrupt leaf 2's absorbed amount (IN0 at its even slot).
        {
            let mut bad = cols.in_[0].clone();
            bad[SPONGE_LEAF_SLOTS * 2] += F128::ONE;
            assert!(
                crate::dishonest_fixture_rejected(|| run_sponge_leaf_dag(
                    &bad,
                    &cols.in_[1],
                    &cols.c,
                    &cols.s0,
                    &cols.s_out,
                    &pins,
                    w_log,
                )),
                "corrupted amount accepted"
            );
        }
        // Corrupt leaf 1's absorbed owner_hi (IN1 at its even slot).
        {
            let mut bad = cols.in_[1].clone();
            bad[SPONGE_LEAF_SLOTS * 1] += F128::ONE;
            assert!(
                crate::dishonest_fixture_rejected(|| run_sponge_leaf_dag(
                    &cols.in_[0],
                    &bad,
                    &cols.c,
                    &cols.s0,
                    &cols.s_out,
                    &pins,
                    w_log,
                )),
                "corrupted owner accepted"
            );
        }
        // Corrupt leaf 3's output digest lane (C0 at its odd slot).
        {
            let mut bad = cols.c.clone();
            bad[0][SPONGE_LEAF_SLOTS * 3 + SPONGE_LEAF_DIGEST_SLOT] += F128::ONE;
            assert!(
                crate::dishonest_fixture_rejected(|| run_sponge_leaf_dag(
                    &cols.in_[0],
                    &cols.in_[1],
                    &bad,
                    &cols.s0,
                    &cols.s_out,
                    &pins,
                    w_log,
                )),
                "corrupted digest accepted"
            );
        }
    }
}
