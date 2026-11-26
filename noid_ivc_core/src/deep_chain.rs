//! Deep-chain layer walk: a data-parallel GKR over the Poseidon2b round
//! structure.
//!
//! The prover holds `W = 2^w_log` permutation executions as four state
//! COLUMNS per layer (one F128 lane per column per slot) and proves, layer
//! by layer, that every slot's output is the Poseidon2b permutation of its
//! input — with the verifier paying only sumcheck rounds, never hashing.
//!
//! Layer structure mirrors `noid_poseidon2b::native::permutation`
//! exactly: the caller applies the initial `MDS_FULL` when building the
//! layer-0 columns (it is linear, so input-wiring relations absorb it for
//! free), then layer `ℓ ∈ 1..=66` applies round `ℓ−1`:
//!
//! - full round (`q ∉ [F/2, F/2 + P)`): every lane gets the round constant,
//!   the x^7 S-box, then `MDS_FULL`;
//! - partial round: lane 0 only, then `MDS_PARTIAL`.
//!
//! The WALK reduces evaluation claims on the layer-66 (output) columns to a
//! claim on the layer-0 (input) columns: per layer, the batched claim
//! `Σ_{g,i} α^{4g+i+1} · S_ℓ,i~(ρ_g)` equals
//!
//! ```text
//!   Σ_w Σ_j E_j(w) · term_j(S_{ℓ−1}(w))      E_j(w) = Σ_g c_{g,j}·eq(ρ_g, w)
//! ```
//!
//! with `c_{g,j} = Σ_i α^{4g+i+1}·MDS[i][j]` verifier-computable constants
//! and `term_j` the S-box (degree 7) or identity per the round type — one
//! degree-8 sumcheck over the `w_log` slot variables. Its final claim is
//! the four `S_{ℓ−1}` lane evaluations at the derived point, which seed the
//! next layer. Intermediate layers are bound by this chain alone: nothing
//! per-slot is ever absorbed or committed, and the walk's terminal claim
//! lands on the layer-0 columns, which the caller discharges against
//! committed data (witness slices via the public-IO opening claims).
//!
//! Round polynomials travel in the compressed wire form `[c_0, c_2..c_8]`
//! (the linear coefficient is reconstructed from the running claim, so
//! `p(0) + p(1) = claim` holds by construction).

pub mod c1;
pub mod capsule_leaf;
pub mod encode_kernel;
pub mod family;
pub mod ff_merkle;
pub mod leaf_hash;
pub mod proof_node_path;
pub mod relations;
pub mod schedule;
pub mod source_tree;
pub mod spine;

use crate::challenger::Challenger;
use crate::field::{F128, F256Unreduced};
use crate::lincheck::build_eq_table;
use noid_core::hardware::tower_to_flat_u128;
use noid_poseidon2b::native::permutation::{
    F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};
use rayon::prelude::*;

/// Degree of a walk round polynomial: `eq` (1) × S-box on a multilinear (7).
pub const WALK_DEGREE: usize = 8;

/// Checkpoint spacing for the prover's layer-column rebuilds.
const CHECKPOINT_SPACING: usize = 8;

#[inline]
fn f128_of_u128(v: u128) -> F128 {
    F128 {
        lo: v as u64,
        hi: (v >> 64) as u64,
    }
}

/// x^7 over the flat basis: `x · x² · x⁴`.
#[inline]
pub fn sbox7(x: F128) -> F128 {
    let x2 = x * x;
    let x4 = x2 * x2;
    x * x2 * x4
}

#[inline]
fn sbox7_lanes(x: [F128; STATE_SIZE]) -> [F128; STATE_SIZE] {
    let [x20, x21] = mul_pair(x[0], x[0], x[1], x[1]);
    let [x22, x23] = mul_pair(x[2], x[2], x[3], x[3]);
    let [x40, x41] = mul_pair(x20, x20, x21, x21);
    let [x42, x43] = mul_pair(x22, x22, x23, x23);
    let [x30, x31] = mul_pair(x[0], x20, x[1], x21);
    let [x32, x33] = mul_pair(x[2], x22, x[3], x23);
    let [y0, y1] = mul_pair(x30, x40, x31, x41);
    let [y2, y3] = mul_pair(x32, x42, x33, x43);
    [y0, y1, y2, y3]
}

/// Round schedule in the flat basis (converted once from the tower-basis
/// protocol constants, exactly as the native permutation does internally).
struct FlatSchedule {
    rc: [[F128; N_ROUNDS]; STATE_SIZE],
    mds_full: [[F128; STATE_SIZE]; STATE_SIZE],
    mds_partial: [[F128; STATE_SIZE]; STATE_SIZE],
}

fn schedule() -> &'static FlatSchedule {
    static S: std::sync::OnceLock<FlatSchedule> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        let mut rc = [[F128::ZERO; N_ROUNDS]; STATE_SIZE];
        let mut mds_full = [[F128::ZERO; STATE_SIZE]; STATE_SIZE];
        let mut mds_partial = [[F128::ZERO; STATE_SIZE]; STATE_SIZE];
        for i in 0..STATE_SIZE {
            for q in 0..N_ROUNDS {
                rc[i][q] = f128_of_u128(tower_to_flat_u128(ROUND_CONSTANTS[i][q]));
            }
            for j in 0..STATE_SIZE {
                mds_full[i][j] = f128_of_u128(tower_to_flat_u128(MDS_FULL[i][j]));
                mds_partial[i][j] = f128_of_u128(tower_to_flat_u128(MDS_PARTIAL[i][j]));
            }
        }
        // The hot MDS kernels below elide exactly these protocol-fixed
        // identity products.  Validate the sparse layout once in every build
        // (not merely under debug assertions), so any future constant drift
        // fails before a proof can be authored with the wrong linear layer.
        for (row, column) in [(0, 2), (1, 2), (1, 3), (2, 0), (3, 0), (3, 1)] {
            assert_eq!(
                mds_full[row][column],
                F128::ONE,
                "full MDS identity layout drift at ({row}, {column})"
            );
        }
        for (row, coefficients) in mds_partial.iter().enumerate() {
            for (column, &coefficient) in coefficients.iter().enumerate() {
                if row != column {
                    assert_eq!(
                        coefficient,
                        F128::ONE,
                        "partial MDS identity layout drift at ({row}, {column})"
                    );
                }
            }
        }
        FlatSchedule {
            rc,
            mds_full,
            mds_partial,
        }
    })
}

/// Whether round `q ∈ 0..N_ROUNDS` is a full round.
#[inline]
pub fn is_full_round(q: usize) -> bool {
    !(F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&q)
}

/// Flat-basis round constant of `lane` at round `q` (a protocol constant —
/// verifier twins fold it into affine expressions).
pub fn flat_round_constant(lane: usize, q: usize) -> F128 {
    schedule().rc[lane][q]
}

/// Flat-basis MDS matrix (full or partial) — protocol constants.
pub fn flat_mds(full: bool) -> &'static [[F128; STATE_SIZE]; STATE_SIZE] {
    if full {
        &schedule().mds_full
    } else {
        &schedule().mds_partial
    }
}

/// The initial `MDS_FULL` the permutation applies before round 0 — callers
/// fold it into the layer-0 columns (it is linear, so chain-wiring
/// relations compose with it for free).
pub fn initial_mds(raw: [F128; STATE_SIZE]) -> [F128; STATE_SIZE] {
    mds_apply_full(&schedule().mds_full, raw)
}

/// Apply the frozen full-round MDS while eliding its six identity
/// coefficients.  Products stay unreduced until the four row sums, exactly
/// like the dense kernel; reduction is linear, so replacing `1 * x` by `x`
/// cannot change a field value (and therefore cannot change a proof byte).
#[inline]
fn mds_apply_full(
    mds: &[[F128; STATE_SIZE]; STATE_SIZE],
    input: [F128; STATE_SIZE],
) -> [F128; STATE_SIZE] {
    let [p00, p10] = mul_unreduced_pair(mds[0][0], input[0], mds[1][0], input[0]);
    let [p01, p11] = mul_unreduced_pair(mds[0][1], input[1], mds[1][1], input[1]);
    let [p03, p21] = mul_unreduced_pair(mds[0][3], input[3], mds[2][1], input[1]);
    let [p22, p32] = mul_unreduced_pair(mds[2][2], input[2], mds[3][2], input[2]);
    let [p23, p33] = mul_unreduced_pair(mds[2][3], input[3], mds[3][3], input[3]);
    [
        (p00 ^ p01 ^ p03).reduce() + input[2],
        (p10 ^ p11).reduce() + input[2] + input[3],
        (p21 ^ p22 ^ p23).reduce() + input[0],
        (p32 ^ p33).reduce() + input[0] + input[1],
    ]
}

/// The partial-round matrix has four non-trivial diagonal coefficients and
/// twelve identity coefficients.  With `sum = x0 + x1 + x2 + x3`, row `i`
/// is `diag_i * x_i + sum + x_i`; this is the exact dense 4x4 product in
/// characteristic two, using four multiplications instead of sixteen.
#[inline]
fn mds_apply_partial(
    mds: &[[F128; STATE_SIZE]; STATE_SIZE],
    input: [F128; STATE_SIZE],
) -> [F128; STATE_SIZE] {
    let sum = input[0] + input[1] + input[2] + input[3];
    let [p0, p1] = mul_pair(mds[0][0], input[0], mds[1][1], input[1]);
    let [p2, p3] = mul_pair(mds[2][2], input[2], mds[3][3], input[3]);
    [
        p0 + sum + input[0],
        p1 + sum + input[1],
        p2 + sum + input[2],
        p3 + sum + input[3],
    ]
}

/// Apply round `q` to one slot's state (mirrors the native round order).
pub fn apply_round(q: usize, state: [F128; STATE_SIZE]) -> [F128; STATE_SIZE] {
    let sch = schedule();
    if is_full_round(q) {
        let boxed = sbox7_lanes(std::array::from_fn(|i| state[i] + sch.rc[i][q]));
        mds_apply_full(&sch.mds_full, boxed)
    } else {
        let mut boxed = state;
        boxed[0] = sbox7(state[0] + sch.rc[0][q]);
        mds_apply_partial(&sch.mds_partial, boxed)
    }
}

/// A group of four per-lane evaluation claims at one point:
/// `column_i~(point) = values[i]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneClaimGroup {
    pub point: Vec<F128>,
    pub values: [F128; STATE_SIZE],
}

/// One layer's wire data: `w_log` compressed degree-8 round polynomials
/// plus the four next-layer lane evaluations at the derived point.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WalkLayerProof {
    /// Per sumcheck round: `[c_0, c_2..c_8]` (8 coefficients).
    pub round_coeffs: Vec<[F128; WALK_DEGREE]>,
    pub next_values: [F128; STATE_SIZE],
}

/// The full walk: layer 66 first, down to layer 1.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeepChainWalkProof {
    pub layers: Vec<WalkLayerProof>,
}

/// One layer of a multi-instance walk.
///
/// All instances share the aggregate degree-8 sumcheck messages and therefore
/// the derived aggregate slot point. Their four layer-`l - 1` evaluations stay
/// independent: the verifier checks one Fiat–Shamir random-linear aggregate of
/// all instance transition terms before carrying one claim group per instance
/// into the next layer.  V1 uses equal domains; the ragged V2 protocol reuses
/// this wire shape with one round message per coordinate of the largest
/// instance.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MultiWalkLayerProof {
    /// Per aggregate sumcheck round: `[c_0, c_2..c_8]`.
    pub round_coeffs: Vec<[F128; WALK_DEGREE]>,
    /// Four next-layer values in canonical instance order.
    pub next_values: Vec<[F128; STATE_SIZE]>,
}

/// Proof container for several independent Poseidon deep-chain instances.
///
/// The transcript label and verifier entry point select either the equal-domain
/// V1 protocol or the ragged-domain V2 protocol.  In both cases the surrounding
/// selection/substitution protocols remain independent and the proof returns
/// one authenticated layer-0 claim per instance.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MultiDeepChainWalkProof {
    pub layers: Vec<MultiWalkLayerProof>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkError {
    /// Proof shape disagrees with (w_log, N_ROUNDS).
    Shape,
    /// A layer's final check failed (claim vs reassembled relation).
    LayerMismatch(usize),
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalkError::Shape => write!(f, "walk proof shape mismatch"),
            WalkError::LayerMismatch(l) => write!(f, "walk layer {l} claim mismatch"),
        }
    }
}

// ---------------------------------------------------------------------------
// Interpolation constants (evaluations at 0..=8 → monomial coefficients)
// ---------------------------------------------------------------------------

pub(crate) fn f128_inv_pub(x: F128) -> F128 {
    // Fermat: x^(2^128 − 2).
    let exp: u128 = u128::MAX - 1;
    let mut result = F128::ONE;
    let mut base = x;
    for bit in 0..128 {
        if (exp >> bit) & 1 == 1 {
            result = result * base;
        }
        base = base * base;
    }
    result
}

/// Lagrange basis in coefficient form for nodes `t_i = i`, `i ∈ 0..=8`:
/// `coeffs = Σ_i evals[i] · basis[i]`.
fn interpolation_basis() -> &'static [[F128; WALK_DEGREE + 1]; WALK_DEGREE + 1] {
    static B: std::sync::OnceLock<[[F128; WALK_DEGREE + 1]; WALK_DEGREE + 1]> =
        std::sync::OnceLock::new();
    B.get_or_init(|| {
        let nodes: Vec<F128> = (0..=WALK_DEGREE as u128).map(f128_of_u128).collect();
        std::array::from_fn(|i| {
            // Numerator Π_{j≠i} (X + t_j), char-2.
            let mut poly = [F128::ZERO; WALK_DEGREE + 1];
            poly[0] = F128::ONE;
            let mut deg = 0usize;
            let mut denom = F128::ONE;
            for (j, &t_j) in nodes.iter().enumerate() {
                if j == i {
                    continue;
                }
                denom = denom * (nodes[i] + t_j);
                // poly *= (X + t_j)
                let mut next = [F128::ZERO; WALK_DEGREE + 1];
                for d in 0..=deg {
                    next[d + 1] += poly[d];
                    next[d] += poly[d] * t_j;
                }
                deg += 1;
                poly = next;
            }
            let inv = f128_inv_pub(denom);
            std::array::from_fn(|d| poly[d] * inv)
        })
    })
}

fn interpolate(evals: &[F128; WALK_DEGREE + 1]) -> [F128; WALK_DEGREE + 1] {
    let basis = interpolation_basis();
    let mut coeffs = [F128::ZERO; WALK_DEGREE + 1];
    for (i, &e) in evals.iter().enumerate() {
        if e == F128::ZERO {
            continue;
        }
        for d in 0..=WALK_DEGREE {
            coeffs[d] += e * basis[i][d];
        }
    }
    coeffs
}

#[inline]
fn horner(coeffs: &[F128; WALK_DEGREE + 1], x: F128) -> F128 {
    let mut acc = coeffs[WALK_DEGREE];
    for d in (0..WALK_DEGREE).rev() {
        acc = acc * x + coeffs[d];
    }
    acc
}

/// Reconstruct the full coefficient vector from the wire form: the linear
/// coefficient is `claim + Σ_{i≥2} c_i` (char 2), making `p(0) + p(1) =
/// claim` hold by construction.
fn reconstruct(wire: &[F128; WALK_DEGREE], claim: F128) -> [F128; WALK_DEGREE + 1] {
    let mut c1 = claim;
    for &c in &wire[1..] {
        c1 += c;
    }
    let mut full = [F128::ZERO; WALK_DEGREE + 1];
    full[0] = wire[0];
    full[1] = c1;
    full[2..].copy_from_slice(&wire[1..]);
    full
}

fn compress(full: &[F128; WALK_DEGREE + 1]) -> [F128; WALK_DEGREE] {
    let mut wire = [F128::ZERO; WALK_DEGREE];
    wire[0] = full[0];
    wire[1..].copy_from_slice(&full[2..]);
    wire
}

// ---------------------------------------------------------------------------
// Shared transcript pieces
// ---------------------------------------------------------------------------

/// `c_{g,j} = Σ_i w_{g,i} · MDS[i][j]` for one group's lane weights.
fn column_weights(q: usize, lane_weights: &[F128; STATE_SIZE]) -> [F128; STATE_SIZE] {
    let sch = schedule();
    let mds = if is_full_round(q) {
        &sch.mds_full
    } else {
        &sch.mds_partial
    };
    std::array::from_fn(|j| {
        let [p0, p1] = mul_unreduced_pair(lane_weights[0], mds[0][j], lane_weights[1], mds[1][j]);
        let [p2, p3] = mul_unreduced_pair(lane_weights[2], mds[2][j], lane_weights[3], mds[3][j]);
        (p0 ^ p1 ^ p2 ^ p3).reduce()
    })
}

/// Accumulate `columns[j] · eq[i]` into all four lane tables in one fused
/// pass over the eq table. The per-lane form walked the eq table once per
/// nonzero lane (up to five memory sweeps per group); the fused sweep reads
/// each eq entry once and updates every lane while it is hot. Pure XOR
/// accumulation of the same terms — bit-identical.
fn accumulate_lane_tables(
    tables: &mut [Vec<F128>; STATE_SIZE],
    eq: &[F128],
    columns: &[F128; STATE_SIZE],
) {
    use rayon::prelude::*;
    const CHUNK: usize = 4096;
    let [t0, t1, t2, t3] = tables;
    t0.par_chunks_mut(CHUNK)
        .zip(t1.par_chunks_mut(CHUNK))
        .zip(t2.par_chunks_mut(CHUNK))
        .zip(t3.par_chunks_mut(CHUNK))
        .zip(eq.par_chunks(CHUNK))
        .for_each(|((((c0, c1), c2), c3), eq_chunk)| {
            for (i, &e) in eq_chunk.iter().enumerate() {
                if columns[0] != F128::ZERO {
                    c0[i] += columns[0] * e;
                }
                if columns[1] != F128::ZERO {
                    c1[i] += columns[1] * e;
                }
                if columns[2] != F128::ZERO {
                    c2[i] += columns[2] * e;
                }
                if columns[3] != F128::ZERO {
                    c3[i] += columns[3] * e;
                }
            }
        });
}

/// Row-major twin of [`accumulate_lane_tables`] for the ragged Link walk.
/// Keeping all four lanes adjacent lets both field products and subsequent
/// folds use the two-lane VPCLMUL path without transposing every round.
fn accumulate_lane_rows(
    rows: &mut [[F128; STATE_SIZE]],
    eq: &[F128],
    columns: &[F128; STATE_SIZE],
) {
    const CHUNK: usize = 4096;
    rows.par_chunks_mut(CHUNK)
        .zip(eq.par_chunks(CHUNK))
        .for_each(|(row_chunk, eq_chunk)| {
            for (row, &e) in row_chunk.iter_mut().zip(eq_chunk) {
                let [p0, p1] = mul_pair(columns[0], e, columns[1], e);
                let [p2, p3] = mul_pair(columns[2], e, columns[3], e);
                row[0] += p0;
                row[1] += p1;
                row[2] += p2;
                row[3] += p3;
            }
        });
}

/// `term_j` of the layer relation applied to next-layer lane values.
fn layer_terms(q: usize, u: &[F128; STATE_SIZE]) -> [F128; STATE_SIZE] {
    let sch = schedule();
    if is_full_round(q) {
        sbox7_lanes(std::array::from_fn(|j| u[j] + sch.rc[j][q]))
    } else {
        let mut t = *u;
        t[0] = sbox7(u[0] + sch.rc[0][q]);
        t
    }
}

/// Two independent unreduced GF(2^128) products. On the production x86
/// target VPCLMULQDQ executes both 128-bit lanes per instruction; the scalar
/// fallback preserves portability and the exact unreduced bit layout.
#[inline]
#[allow(unreachable_code)]
fn mul_unreduced_pair(a0: F128, b0: F128, a1: F128, b1: F128) -> [F256Unreduced; 2] {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        target_feature = "vpclmulqdq"
    ))]
    {
        // SAFETY: both instructions are part of the static build target.
        return unsafe { mul_unreduced_pair_vpclmul(a0, b0, a1, b1) };
    }
    #[cfg(all(
        target_arch = "x86_64",
        not(all(target_feature = "avx2", target_feature = "vpclmulqdq"))
    ))]
    {
        if noid_core::cpu::avx2_vpclmul_available() {
            // SAFETY: AVX2 and VPCLMULQDQ were detected before selection.
            return unsafe { mul_unreduced_pair_vpclmul(a0, b0, a1, b1) };
        }
    }
    [a0.mul_unreduced(b0), a1.mul_unreduced(b1)]
}

#[inline]
fn mul_pair(a0: F128, b0: F128, a1: F128, b1: F128) -> [F128; 2] {
    mul_unreduced_pair(a0, b0, a1, b1).map(F256Unreduced::reduce)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2", enable = "vpclmulqdq")]
unsafe fn mul_unreduced_pair_vpclmul(a0: F128, b0: F128, a1: F128, b1: F128) -> [F256Unreduced; 2] {
    use core::arch::x86_64::*;

    #[inline]
    unsafe fn lane(v: __m256i, high: bool) -> __m128i {
        if high {
            // SAFETY: inherited AVX2 target feature.
            unsafe { _mm256_extracti128_si256::<1>(v) }
        } else {
            // SAFETY: inherited AVX2 target feature.
            unsafe { _mm256_castsi256_si128(v) }
        }
    }

    #[inline]
    unsafe fn unpack(ll: __m128i, cross: __m128i, hh: __m128i) -> F256Unreduced {
        // SAFETY: inherited SSE4.1 support from AVX2.
        unsafe {
            F256Unreduced {
                r0: _mm_extract_epi64::<0>(ll) as u64,
                r1: (_mm_extract_epi64::<1>(ll) as u64) ^ (_mm_extract_epi64::<0>(cross) as u64),
                r2: (_mm_extract_epi64::<0>(hh) as u64) ^ (_mm_extract_epi64::<1>(cross) as u64),
                r3: _mm_extract_epi64::<1>(hh) as u64,
            }
        }
    }

    // SAFETY: function carries AVX2 + VPCLMULQDQ and all values are plain
    // integer vectors. Lane 0 is product 0; lane 1 is product 1.
    unsafe {
        let va0 = _mm_set_epi64x(a0.hi as i64, a0.lo as i64);
        let va1 = _mm_set_epi64x(a1.hi as i64, a1.lo as i64);
        let vb0 = _mm_set_epi64x(b0.hi as i64, b0.lo as i64);
        let vb1 = _mm_set_epi64x(b1.hi as i64, b1.lo as i64);
        let va = _mm256_set_m128i(va1, va0);
        let vb = _mm256_set_m128i(vb1, vb0);
        let va_cross = _mm256_set_m128i(
            _mm_set_epi64x(0, (a1.lo ^ a1.hi) as i64),
            _mm_set_epi64x(0, (a0.lo ^ a0.hi) as i64),
        );
        let vb_cross = _mm256_set_m128i(
            _mm_set_epi64x(0, (b1.lo ^ b1.hi) as i64),
            _mm_set_epi64x(0, (b0.lo ^ b0.hi) as i64),
        );
        let ll = _mm256_clmulepi64_epi128::<0x00>(va, vb);
        let hh = _mm256_clmulepi64_epi128::<0x11>(va, vb);
        let middle = _mm256_clmulepi64_epi128::<0x00>(va_cross, vb_cross);
        let cross = _mm256_xor_si256(_mm256_xor_si256(middle, ll), hh);
        [
            unpack(lane(ll, false), lane(cross, false), lane(hh, false)),
            unpack(lane(ll, true), lane(cross, true), lane(hh, true)),
        ]
    }
}

/// Monomial coefficients of `Σ_j E_j(t)·term_j(S(t))` for one Boolean pair,
/// accumulated into `acc`. `E_j(t) = e_base_j + t·e_delta_j`,
/// `S_j(t) = s_base_j + t·s_delta_j`, `term_j` as in [`layer_terms`].
///
/// In characteristic 2 squaring is linear, so with `x = a + t·b`
/// `sbox7(x) = x⁴·x²·x = (a⁴ + t⁴b⁴)(a² + t²b²)(a + t·b)` expands into
/// eight monomials costing 12 multiplications plus four squarings, and the
/// affine `E` factor is a 2×8 convolution — 44 multiplications per partial
/// round pair against 144 for evaluating the degree-8 product at all nine
/// wire points. The round message previously interpolated from those nine
/// evaluations is the same polynomial, so by coefficient uniqueness every
/// wire byte is unchanged. An exhausted ragged instance arrives here as
/// `e_delta = e_base`, `s_delta = 0` and degenerates to the constant-`S`
/// alignment gate `E·(1 + t)·term(S)`.
#[inline]
fn accumulate_pair_round_coeffs(
    q: usize,
    e_base: &[F128; STATE_SIZE],
    e_delta: &[F128; STATE_SIZE],
    s_base: &[F128; STATE_SIZE],
    s_delta: &[F128; STATE_SIZE],
    acc: &mut [F256Unreduced; WALK_DEGREE + 1],
) {
    let sch = schedule();
    let full_round = is_full_round(q);
    for j in 0..STATE_SIZE {
        let eb = e_base[j];
        let ed = e_delta[j];
        if full_round || j == 0 {
            // T(t) = sbox7((s_base + rc) + t·s_delta), degree 7.
            let a = s_base[j] + sch.rc[j][q];
            let b = s_delta[j];
            let t_coeffs = sbox7_affine_coeffs(a, b);
            for (d, &tc) in t_coeffs.iter().enumerate() {
                if tc == F128::ZERO {
                    continue;
                }
                let [base_product, delta_product] = mul_unreduced_pair(eb, tc, ed, tc);
                acc[d] ^= base_product;
                acc[d + 1] ^= delta_product;
            }
        } else {
            // Passthrough lane: T(t) = s_base + t·s_delta, degree 1.
            let sb = s_base[j];
            let sd = s_delta[j];
            let [constant, quadratic] = mul_unreduced_pair(eb, sb, ed, sd);
            let [linear_a, linear_b] = mul_unreduced_pair(eb, sd, ed, sb);
            acc[0] ^= constant;
            acc[1] ^= linear_a;
            acc[1] ^= linear_b;
            acc[2] ^= quadratic;
        }
    }
}

/// Coefficients of `(a + t·b)^7` in characteristic two.  Keeping this as
/// one shared kernel lets the ordinary dense-E path and the single-group
/// ragged specialization use exactly the same polynomial expansion.
#[inline]
fn sbox7_affine_coeffs(a: F128, b: F128) -> [F128; WALK_DEGREE] {
    let [a2, b2] = mul_pair(a, a, b, b);
    let [a4, b4] = mul_pair(a2, a2, b2, b2);
    let [a4a2, b4b2] = mul_pair(a4, a2, b4, b2);
    let [a4b2, b4a2] = mul_pair(a4, b2, b4, a2);
    let [c0, c1] = mul_pair(a4a2, a, a4a2, b);
    let [c2, c3] = mul_pair(a4b2, a, a4b2, b);
    let [c4, c5] = mul_pair(b4a2, a, b4a2, b);
    let [c6, c7] = mul_pair(b4b2, a, b4b2, b);
    [c0, c1, c2, c3, c4, c5, c6, c7]
}

/// Single-claim-group specialization of [`accumulate_pair_round_coeffs`].
///
/// For one group all four E lanes share the same equality polynomial:
/// `E_j(t) = column_j · (eq_base + t·eq_delta)`.  Factor that common
/// affine term out, first form `R(t) = Σ_j column_j·term_j(S_j(t))`, then
/// convolve `R` with eq.  This is the same field polynomial as materializing
/// and folding four E columns, but removes those large columns from the hot
/// Block-sidecar walk and reduces its per-pair product count.
#[inline]
fn accumulate_single_group_pair_round_coeffs(
    q: usize,
    eq_base: F128,
    eq_delta: F128,
    columns: &[F128; STATE_SIZE],
    s_base: &[F128; STATE_SIZE],
    s_delta: &[F128; STATE_SIZE],
    acc: &mut [F256Unreduced; WALK_DEGREE + 1],
) {
    let sch = schedule();
    let full_round = is_full_round(q);
    let mut relation = [F256Unreduced::ZERO; WALK_DEGREE];
    for lane in 0..STATE_SIZE {
        let column = columns[lane];
        if column == F128::ZERO {
            continue;
        }
        if full_round || lane == 0 {
            let coefficients = sbox7_affine_coeffs(s_base[lane] + sch.rc[lane][q], s_delta[lane]);
            for degree in (0..WALK_DEGREE).step_by(2) {
                let [lo, hi] = mul_unreduced_pair(
                    column,
                    coefficients[degree],
                    column,
                    coefficients[degree + 1],
                );
                relation[degree] ^= lo;
                relation[degree + 1] ^= hi;
            }
        } else {
            let [constant, linear] =
                mul_unreduced_pair(column, s_base[lane], column, s_delta[lane]);
            relation[0] ^= constant;
            relation[1] ^= linear;
        }
    }

    for (degree, coefficient) in relation.map(F256Unreduced::reduce).into_iter().enumerate() {
        let [base, delta] = mul_unreduced_pair(eq_base, coefficient, eq_delta, coefficient);
        acc[degree] ^= base;
        acc[degree + 1] ^= delta;
    }
}

#[inline]
fn reduce_round_coeffs(deferred: [F256Unreduced; WALK_DEGREE + 1]) -> [F128; WALK_DEGREE + 1] {
    deferred.map(F256Unreduced::reduce)
}

#[inline]
fn xor_round_coeffs(
    mut left: [F256Unreduced; WALK_DEGREE + 1],
    right: [F256Unreduced; WALK_DEGREE + 1],
) -> [F256Unreduced; WALK_DEGREE + 1] {
    for (left, right) in left.iter_mut().zip(right) {
        *left ^= right;
    }
    left
}

/// Per-group lane weights from one squeezed α: group g lane i gets
/// `α^{4g+i+1}`.
fn lane_weight_table(alpha: F128, groups: usize) -> Vec<[F128; STATE_SIZE]> {
    let mut power = F128::ONE;
    (0..groups)
        .map(|_| {
            std::array::from_fn(|_| {
                power = power * alpha;
                power
            })
        })
        .collect()
}

fn absorb_groups<Ch: Challenger>(challenger: &mut Ch, groups: &[LaneClaimGroup]) {
    challenger.observe_label(b"history-deep-chain-walk-v0");
    for g in groups {
        challenger.observe_f128_slice(&g.point);
        challenger.observe_f128_slice(&g.values);
    }
}

/// Bind the complete ordered multi-instance claim shape before the first
/// batching challenge.  Explicit instance/group counts prevent repartitioning
/// one flat claim list into a different authority topology.
fn absorb_multi_groups<Ch: Challenger>(challenger: &mut Ch, groups: &[Vec<LaneClaimGroup>]) {
    challenger.observe_label(b"history-deep-chain-multi-walk-v1");
    challenger.observe_f128(f128_of_u128(groups.len() as u128));
    for instance in groups {
        challenger.observe_f128(f128_of_u128(instance.len() as u128));
        for group in instance {
            challenger.observe_f128_slice(&group.point);
            challenger.observe_f128_slice(&group.values);
        }
    }
}

/// V2 transcript prefix for a ragged multi-walk.  Domain widths are protocol
/// constants supplied by the caller (and derived from the native columns by
/// the prover), not proof fields.  Binding them in instance-major order before
/// the first batching challenge prevents either a width reassignment or a
/// repartitioning of the flat claim list.
fn absorb_ragged_multi_groups<Ch: Challenger>(
    challenger: &mut Ch,
    w_logs: &[usize],
    groups: &[Vec<LaneClaimGroup>],
) {
    debug_assert_eq!(w_logs.len(), groups.len());
    challenger.observe_label(b"history-deep-chain-ragged-multi-walk-v2");
    challenger.observe_f128(f128_of_u128(groups.len() as u128));
    for (&w_log, instance) in w_logs.iter().zip(groups) {
        challenger.observe_f128(f128_of_u128(w_log as u128));
        challenger.observe_f128(f128_of_u128(instance.len() as u128));
        for group in instance {
            challenger.observe_f128_slice(&group.point);
            challenger.observe_f128_slice(&group.values);
        }
    }
}

/// eq(a, b) for equal-length points.
pub(crate) fn eq_eval_pub(a: &[F128], b: &[F128]) -> F128 {
    eq_eval(a, b)
}

fn eq_eval(a: &[F128], b: &[F128]) -> F128 {
    debug_assert_eq!(a.len(), b.len());
    let mut acc = F128::ONE;
    for (x, y) in a.iter().zip(b.iter()) {
        acc = acc * (*x * *y + (F128::ONE + *x) * (F128::ONE + *y));
    }
    acc
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

/// Prover representation of the ragged walk's four E lanes.  Production
/// sidecars carry exactly one claim group per child, so all four lanes are a
/// fixed column-weight vector times one equality table.  Retain that factored
/// form instead of allocating four full-width columns.  The dense variant
/// preserves the public multi-group API without changing its transcript.
enum RaggedETable {
    Single {
        eq: Vec<F128>,
        columns: [F128; STATE_SIZE],
    },
    Dense(Vec<[F128; STATE_SIZE]>),
}

impl RaggedETable {
    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::Single { eq, .. } => eq.len(),
            Self::Dense(rows) => rows.len(),
        }
    }
}

fn ragged_instance_round_contribution(
    q: usize,
    native_coordinate: bool,
    e_table: &RaggedETable,
    s_table: &[[F128; STATE_SIZE]],
) -> [F128; WALK_DEGREE + 1] {
    let deferred = match (e_table, native_coordinate) {
        (RaggedETable::Single { eq, columns }, true) => (0..eq.len() / 2)
            .into_par_iter()
            .fold(
                || [F256Unreduced::ZERO; WALK_DEGREE + 1],
                |mut acc, p| {
                    let eq_base = eq[2 * p];
                    let eq_delta = eq_base + eq[2 * p + 1];
                    let s_base = s_table[2 * p];
                    let s_next = s_table[2 * p + 1];
                    let s_delta = std::array::from_fn(|lane| s_base[lane] + s_next[lane]);
                    accumulate_single_group_pair_round_coeffs(
                        q, eq_base, eq_delta, columns, &s_base, &s_delta, &mut acc,
                    );
                    acc
                },
            )
            .reduce(|| [F256Unreduced::ZERO; WALK_DEGREE + 1], xor_round_coeffs),
        (RaggedETable::Dense(rows), true) => (0..rows.len() / 2)
            .into_par_iter()
            .fold(
                || [F256Unreduced::ZERO; WALK_DEGREE + 1],
                |mut acc, p| {
                    let e_base = rows[2 * p];
                    let e_next = rows[2 * p + 1];
                    let e_delta = std::array::from_fn(|lane| e_base[lane] + e_next[lane]);
                    let s_base = s_table[2 * p];
                    let s_next = s_table[2 * p + 1];
                    let s_delta = std::array::from_fn(|lane| s_base[lane] + s_next[lane]);
                    accumulate_pair_round_coeffs(q, &e_base, &e_delta, &s_base, &s_delta, &mut acc);
                    acc
                },
            )
            .reduce(|| [F256Unreduced::ZERO; WALK_DEGREE + 1], xor_round_coeffs),
        (RaggedETable::Single { eq, columns }, false) => {
            debug_assert_eq!(eq.len(), 1);
            debug_assert_eq!(s_table.len(), 1);
            let mut acc = [F256Unreduced::ZERO; WALK_DEGREE + 1];
            let s_delta = [F128::ZERO; STATE_SIZE];
            // The high-coordinate gate is `(1 + t)`, hence the factored
            // equality polynomial has delta == base.
            accumulate_single_group_pair_round_coeffs(
                q,
                eq[0],
                eq[0],
                columns,
                &s_table[0],
                &s_delta,
                &mut acc,
            );
            acc
        }
        (RaggedETable::Dense(rows), false) => {
            debug_assert_eq!(rows.len(), 1);
            debug_assert_eq!(s_table.len(), 1);
            let mut acc = [F256Unreduced::ZERO; WALK_DEGREE + 1];
            let e_base = rows[0];
            let s_delta = [F128::ZERO; STATE_SIZE];
            // e * (1 + t) = e + t*e in characteristic two.
            accumulate_pair_round_coeffs(q, &e_base, &e_base, &s_table[0], &s_delta, &mut acc);
            acc
        }
    };
    reduce_round_coeffs(deferred)
}

#[allow(clippy::too_many_arguments)]
fn fold_ragged_instance_tables(
    native_coordinate: bool,
    challenge: F128,
    e_table: &mut RaggedETable,
    s_table: &mut Vec<[F128; STATE_SIZE]>,
    e_single_scratch: &mut Vec<F128>,
    e_dense_scratch: &mut Vec<[F128; STATE_SIZE]>,
    s_scratch: &mut Vec<[F128; STATE_SIZE]>,
) {
    if native_coordinate {
        rayon::join(
            || match e_table {
                RaggedETable::Single { eq, .. } => {
                    fold_table_reusing(eq, e_single_scratch, challenge)
                }
                RaggedETable::Dense(rows) => fold_rows_reusing(rows, e_dense_scratch, challenge),
            },
            || fold_rows_reusing(s_table, s_scratch, challenge),
        );
    } else {
        let gate = F128::ONE + challenge;
        match e_table {
            RaggedETable::Single { eq, .. } => eq[0] = eq[0] * gate,
            RaggedETable::Dense(rows) => {
                let row = &mut rows[0];
                let [v0, v1] = mul_pair(row[0], gate, row[1], gate);
                let [v2, v3] = mul_pair(row[2], gate, row[3], gate);
                *row = [v0, v1, v2, v3];
            }
        }
    }
}

/// Prove the walk from claims on the layer-66 output columns down to a
/// claim on the layer-0 input columns (returned). `s0` holds the four
/// layer-0 columns, each of length `2^w_log`; every claim group's point has
/// `w_log` coordinates and its values must be true output-column MLE
/// evaluations (the caller's selection relations produce them).
pub fn prove_deep_chain_walk<Ch: Challenger>(
    s0: &[Vec<F128>; STATE_SIZE],
    out_groups: &[LaneClaimGroup],
    challenger: &mut Ch,
) -> (DeepChainWalkProof, LaneClaimGroup) {
    let w = s0[0].len();
    assert!(w.is_power_of_two(), "column length must be a power of two");
    let w_log = w.trailing_zeros() as usize;
    assert!(s0.iter().all(|c| c.len() == w));
    assert!(!out_groups.is_empty());
    for g in out_groups {
        assert_eq!(g.point.len(), w_log, "claim point arity");
    }

    // Layer checkpoints S_0, S_8, … served backward one window at a time.
    let mut layer_states = DescendingLayerStates::new(s0);

    absorb_groups(challenger, out_groups);

    let mut groups: Vec<LaneClaimGroup> = out_groups.to_vec();
    let mut layers = Vec::with_capacity(N_ROUNDS);
    for layer in (1..=N_ROUNDS).rev() {
        let q = layer - 1;
        let alpha = challenger.sample_f128();
        let weights = lane_weight_table(alpha, groups.len());

        // Running claim and the E_j tables.
        let mut claim = F128::ZERO;
        for (g, w_g) in groups.iter().zip(weights.iter()) {
            for i in 0..STATE_SIZE {
                claim += w_g[i] * g.values[i];
            }
        }
        let mut e_tables: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
        for (g, w_g) in groups.iter().zip(weights.iter()) {
            let c = column_weights(q, w_g);
            let eq = build_eq_table(&g.point);
            accumulate_lane_tables(&mut e_tables, &eq, &c);
        }
        let mut s_tables = layer_states.state(q);

        let mut round_coeffs = Vec::with_capacity(w_log);
        let mut point = Vec::with_capacity(w_log);
        for _round in 0..w_log {
            let half = e_tables[0].len() / 2;
            let full = (0..half)
                .into_par_iter()
                .fold(
                    || [F256Unreduced::ZERO; WALK_DEGREE + 1],
                    |mut acc, p| {
                        let mut e_base = [F128::ZERO; STATE_SIZE];
                        let mut e_delta = [F128::ZERO; STATE_SIZE];
                        let mut s_base = [F128::ZERO; STATE_SIZE];
                        let mut s_delta = [F128::ZERO; STATE_SIZE];
                        for j in 0..STATE_SIZE {
                            e_base[j] = e_tables[j][2 * p];
                            e_delta[j] = e_tables[j][2 * p] + e_tables[j][2 * p + 1];
                            s_base[j] = s_tables[j][2 * p];
                            s_delta[j] = s_tables[j][2 * p] + s_tables[j][2 * p + 1];
                        }
                        accumulate_pair_round_coeffs(
                            q, &e_base, &e_delta, &s_base, &s_delta, &mut acc,
                        );
                        acc
                    },
                )
                .reduce(
                    || [F256Unreduced::ZERO; WALK_DEGREE + 1],
                    |mut a, b| {
                        for (x, y) in a.iter_mut().zip(b.iter()) {
                            *x ^= *y;
                        }
                        a
                    },
                );
            let full = reduce_round_coeffs(full);
            debug_assert_eq!(
                full[0] + horner(&full, F128::ONE),
                claim,
                "walk prover-side round mismatch at layer {layer}"
            );
            let wire = compress(&full);
            challenger.observe_f128_slice(&wire);
            let r = challenger.sample_f128();
            claim = horner(&full, r);
            point.push(r);
            round_coeffs.push(wire);
            for j in 0..STATE_SIZE {
                fold_in_place(&mut e_tables[j], r);
                fold_in_place(&mut s_tables[j], r);
            }
        }

        let next_values: [F128; STATE_SIZE] = std::array::from_fn(|j| s_tables[j][0]);
        challenger.observe_f128_slice(&next_values);
        debug_assert_eq!(
            {
                let terms = layer_terms(q, &next_values);
                let mut acc = F128::ZERO;
                for j in 0..STATE_SIZE {
                    acc += e_tables[j][0] * terms[j];
                }
                acc
            },
            claim,
            "layer {layer} prover-side final mismatch"
        );

        layers.push(WalkLayerProof {
            round_coeffs,
            next_values,
        });
        groups = vec![LaneClaimGroup {
            point: point.clone(),
            values: next_values,
        }];
    }

    (
        DeepChainWalkProof { layers },
        groups.pop().expect("one terminal group"),
    )
}

/// Prove several independent walks of the same dyadic width with one aggregate
/// sumcheck per Poseidon layer.
///
/// `s0_instances[a]` is instance `a`'s four layer-0 columns and
/// `out_groups[a]` its non-empty set of layer-66 claims.  The transcript binds
/// both nesting dimensions before sampling the weights.  One global power
/// ladder random-linearly combines every `(instance, group, lane)` claim; the
/// shared sumcheck point is then checked against each instance's own next-layer
/// values.  The returned vector contains one true layer-0 claim per instance.
pub fn prove_multi_deep_chain_walk<Ch: Challenger>(
    s0_instances: &[&[Vec<F128>; STATE_SIZE]],
    out_groups: &[Vec<LaneClaimGroup>],
    challenger: &mut Ch,
) -> (MultiDeepChainWalkProof, Vec<LaneClaimGroup>) {
    assert!(!s0_instances.is_empty(), "at least one walk instance");
    assert_eq!(
        s0_instances.len(),
        out_groups.len(),
        "one claim-group list per walk instance"
    );
    let w = s0_instances[0][0].len();
    assert!(w.is_power_of_two(), "column length must be a power of two");
    let w_log = w.trailing_zeros() as usize;
    for (instance, groups) in s0_instances.iter().zip(out_groups) {
        assert!(instance.iter().all(|column| column.len() == w));
        assert!(!groups.is_empty(), "every instance needs an output claim");
        assert!(
            groups.iter().all(|group| group.point.len() == w_log),
            "claim point arity"
        );
    }

    // Retain the same bounded-rebuild discipline as the single-instance
    // prover. Checkpoints are independent; only their sumcheck messages are
    // aggregated. The retained payload is
    // `instances * 10 * 4 * 2^w_log * sizeof(F128)` at 66 rounds / spacing 8
    // (20 MiB for the planned two-instance w_log=14 small-class group). A future wider
    // ladder should stream/rebuild instances if that product becomes material.
    let mut layer_states: Vec<DescendingLayerStates> = s0_instances
        .iter()
        .map(|&s0| DescendingLayerStates::new(s0))
        .collect();

    absorb_multi_groups(challenger, out_groups);

    let mut groups = out_groups.to_vec();
    let mut layers = Vec::with_capacity(N_ROUNDS);
    for layer in (1..=N_ROUNDS).rev() {
        let q = layer - 1;
        let alpha = challenger.sample_f128();
        let total_groups = groups.iter().map(Vec::len).sum();
        let flat_weights = lane_weight_table(alpha, total_groups);
        let mut weight_cursor = 0usize;
        let weights: Vec<Vec<[F128; STATE_SIZE]>> = groups
            .iter()
            .map(|instance| {
                let end = weight_cursor + instance.len();
                let instance_weights = flat_weights[weight_cursor..end].to_vec();
                weight_cursor = end;
                instance_weights
            })
            .collect();
        debug_assert_eq!(weight_cursor, flat_weights.len());

        let mut claim = F128::ZERO;
        let mut e_tables: Vec<[Vec<F128>; STATE_SIZE]> = groups
            .iter()
            .map(|_| std::array::from_fn(|_| vec![F128::ZERO; w]))
            .collect();
        for ((instance_groups, instance_weights), instance_e) in
            groups.iter().zip(&weights).zip(&mut e_tables)
        {
            for (group, lane_weights) in instance_groups.iter().zip(instance_weights) {
                for lane in 0..STATE_SIZE {
                    claim += lane_weights[lane] * group.values[lane];
                }
                let columns = column_weights(q, lane_weights);
                let eq = build_eq_table(&group.point);
                accumulate_lane_tables(instance_e, &eq, &columns);
            }
        }

        let mut s_tables: Vec<[Vec<F128>; STATE_SIZE]> = layer_states
            .iter_mut()
            .map(|instance_states| instance_states.state(q))
            .collect();
        let mut round_coeffs = Vec::with_capacity(w_log);
        let mut point = Vec::with_capacity(w_log);
        for _round in 0..w_log {
            let half = e_tables[0][0].len() / 2;
            let work = half * s0_instances.len();
            let evals = (0..work)
                .into_par_iter()
                .fold(
                    || [F256Unreduced::ZERO; WALK_DEGREE + 1],
                    |mut acc, work_index| {
                        let instance = work_index / half;
                        let p = work_index % half;
                        let mut e_base = [F128::ZERO; STATE_SIZE];
                        let mut e_delta = [F128::ZERO; STATE_SIZE];
                        let mut s_base = [F128::ZERO; STATE_SIZE];
                        let mut s_delta = [F128::ZERO; STATE_SIZE];
                        for lane in 0..STATE_SIZE {
                            e_base[lane] = e_tables[instance][lane][2 * p];
                            e_delta[lane] = e_tables[instance][lane][2 * p]
                                + e_tables[instance][lane][2 * p + 1];
                            s_base[lane] = s_tables[instance][lane][2 * p];
                            s_delta[lane] = s_tables[instance][lane][2 * p]
                                + s_tables[instance][lane][2 * p + 1];
                        }
                        accumulate_pair_round_coeffs(
                            q, &e_base, &e_delta, &s_base, &s_delta, &mut acc,
                        );
                        acc
                    },
                )
                .reduce(
                    || [F256Unreduced::ZERO; WALK_DEGREE + 1],
                    |mut left, right| {
                        for (left, right) in left.iter_mut().zip(right) {
                            *left ^= right;
                        }
                        left
                    },
                );
            let full = reduce_round_coeffs(evals);
            debug_assert_eq!(full[0] + horner(&full, F128::ONE), claim);
            let wire = compress(&full);
            challenger.observe_f128_slice(&wire);
            let challenge = challenger.sample_f128();
            claim = horner(&full, challenge);
            point.push(challenge);
            round_coeffs.push(wire);
            for instance in 0..s0_instances.len() {
                for lane in 0..STATE_SIZE {
                    fold_in_place(&mut e_tables[instance][lane], challenge);
                    fold_in_place(&mut s_tables[instance][lane], challenge);
                }
            }
        }

        let next_values: Vec<[F128; STATE_SIZE]> = s_tables
            .iter()
            .map(|instance| std::array::from_fn(|lane| instance[lane][0]))
            .collect();
        let flat_next = next_values
            .iter()
            .flat_map(|values| values.iter().copied())
            .collect::<Vec<_>>();
        challenger.observe_f128_slice(&flat_next);

        let mut expected = F128::ZERO;
        for (((instance_groups, instance_weights), instance_e), instance_next) in
            groups.iter().zip(&weights).zip(&e_tables).zip(&next_values)
        {
            let terms = layer_terms(q, instance_next);
            for (group, lane_weights) in instance_groups.iter().zip(instance_weights) {
                let columns = column_weights(q, lane_weights);
                let eq = eq_eval(&group.point, &point);
                let mut dot = F128::ZERO;
                for lane in 0..STATE_SIZE {
                    dot += columns[lane] * terms[lane];
                }
                expected += eq * dot;
            }
            debug_assert!(instance_e.iter().all(|table| table.len() == 1));
        }
        debug_assert_eq!(expected, claim, "layer {layer} prover-side final mismatch");

        layers.push(MultiWalkLayerProof {
            round_coeffs,
            next_values: next_values.clone(),
        });
        groups = next_values
            .into_iter()
            .map(|values| {
                vec![LaneClaimGroup {
                    point: point.clone(),
                    values,
                }]
            })
            .collect();
    }

    let terminals = groups
        .into_iter()
        .map(|mut instance| instance.pop().expect("one terminal group per instance"))
        .collect();
    (MultiDeepChainWalkProof { layers }, terminals)
}

/// Prove independent walks with different dyadic widths using one aggregate
/// sumcheck per Poseidon layer (ragged multi-walk V2).
///
/// Let instance `a` have width `w_a` and let `W = max_a w_a`.  Its transition
/// relation is embedded into the `W`-variate aggregate as
///
/// ```text
/// E_a(x_0..x_{w_a-1})
///   * ∏_{j=w_a}^{W-1} (1 + x_j)
///   * T(S_a(x_0..x_{w_a-1})).
/// ```
///
/// Thus the original Boolean sum appears exactly once, at an all-zero high
/// suffix.  `S_a` ignores (equivalently, repeats across) the high coordinates,
/// but its four columns are never physically padded.  The degree bound remains
/// `WALK_DEGREE = 8`: on a real coordinate, `E_a` is affine and the Poseidon
/// transition has degree at most seven; on a high coordinate only the affine
/// gate depends on that variable.  Summing instances cannot increase degree.
///
/// The proof has `W` round messages and one four-lane next value per instance.
/// Returned terminal points are truncated back to their native `w_a`, so each
/// one discharges directly against its original committed columns.
pub fn prove_ragged_multi_deep_chain_walk<Ch: Challenger>(
    s0_instances: &[&[Vec<F128>; STATE_SIZE]],
    out_groups: &[Vec<LaneClaimGroup>],
    challenger: &mut Ch,
) -> (MultiDeepChainWalkProof, Vec<LaneClaimGroup>) {
    let total_started = std::time::Instant::now();
    let timing_enabled = std::env::var_os("NOIDH_DEEP_CHAIN_TIMING").is_some();
    assert!(!s0_instances.is_empty(), "at least one walk instance");
    assert_eq!(
        s0_instances.len(),
        out_groups.len(),
        "one claim-group list per walk instance"
    );

    let w_logs = s0_instances
        .iter()
        .map(|instance| {
            let w = instance[0].len();
            assert!(w.is_power_of_two(), "column length must be a power of two");
            assert!(instance.iter().all(|column| column.len() == w));
            w.trailing_zeros() as usize
        })
        .collect::<Vec<_>>();
    let max_w_log = *w_logs.iter().max().expect("one walk instance");
    for (&w_log, groups) in w_logs.iter().zip(out_groups) {
        assert!(!groups.is_empty(), "every instance needs an output claim");
        assert!(
            groups.iter().all(|group| group.point.len() == w_log),
            "claim point arity"
        );
    }
    // Layer states retain each native width.  In particular, a smaller state
    // is not cloned into a 2^W outer witness merely to share sumcheck rounds.
    let state_init_started = std::time::Instant::now();
    let mut layer_states: Vec<RaggedDescendingLayerStates> = s0_instances
        .par_iter()
        .map(|&s0| RaggedDescendingLayerStates::new(s0))
        .collect();
    let state_init_elapsed = state_init_started.elapsed();

    absorb_ragged_multi_groups(challenger, &w_logs, out_groups);

    let mut groups = out_groups.to_vec();
    let mut layers = Vec::with_capacity(N_ROUNDS);
    let mut setup_elapsed = std::time::Duration::ZERO;
    let mut state_fetch_elapsed = std::time::Duration::ZERO;
    let mut sumcheck_elapsed = std::time::Duration::ZERO;
    let mut finish_elapsed = std::time::Duration::ZERO;
    for layer in (1..=N_ROUNDS).rev() {
        let setup_started = std::time::Instant::now();
        let q = layer - 1;
        let alpha = challenger.sample_f128();
        let total_groups = groups.iter().map(Vec::len).sum();
        let flat_weights = lane_weight_table(alpha, total_groups);
        let mut weight_cursor = 0usize;
        let weights: Vec<Vec<[F128; STATE_SIZE]>> = groups
            .iter()
            .map(|instance| {
                let end = weight_cursor + instance.len();
                let instance_weights = flat_weights[weight_cursor..end].to_vec();
                weight_cursor = end;
                instance_weights
            })
            .collect();
        debug_assert_eq!(weight_cursor, flat_weights.len());

        let mut claim = F128::ZERO;
        let mut e_tables = Vec::with_capacity(w_logs.len());
        for ((instance_groups, instance_weights), &w_log) in
            groups.iter().zip(&weights).zip(&w_logs)
        {
            for (group, lane_weights) in instance_groups.iter().zip(instance_weights) {
                for lane in 0..STATE_SIZE {
                    claim += lane_weights[lane] * group.values[lane];
                }
            }
            if instance_groups.len() == 1 {
                let group = &instance_groups[0];
                let lane_weights = &instance_weights[0];
                e_tables.push(RaggedETable::Single {
                    eq: build_eq_table(&group.point),
                    columns: column_weights(q, lane_weights),
                });
            } else {
                let mut rows = vec![[F128::ZERO; STATE_SIZE]; 1usize << w_log];
                for (group, lane_weights) in instance_groups.iter().zip(instance_weights) {
                    let columns = column_weights(q, lane_weights);
                    let eq = build_eq_table(&group.point);
                    accumulate_lane_rows(&mut rows, &eq, &columns);
                }
                e_tables.push(RaggedETable::Dense(rows));
            }
        }
        setup_elapsed += setup_started.elapsed();

        let state_fetch_started = std::time::Instant::now();
        let mut s_tables: Vec<Vec<[F128; STATE_SIZE]>> = layer_states
            .par_iter_mut()
            .map(|instance_states| instance_states.state(q))
            .collect();
        state_fetch_elapsed += state_fetch_started.elapsed();

        let mut e_single_fold_scratch: Vec<Vec<F128>> =
            (0..w_logs.len()).map(|_| Vec::new()).collect();
        let mut e_dense_fold_scratch: Vec<Vec<[F128; STATE_SIZE]>> =
            (0..w_logs.len()).map(|_| Vec::new()).collect();
        let mut s_fold_scratch: Vec<Vec<[F128; STATE_SIZE]>> =
            (0..w_logs.len()).map(|_| Vec::new()).collect();

        let mut round_coeffs = Vec::with_capacity(max_w_log);
        let mut point = Vec::with_capacity(max_w_log);
        let sumcheck_started = std::time::Instant::now();
        for round in 0..max_w_log {
            // A native coordinate contributes one work item per Boolean
            // pair; an exhausted instance contributes one analytical item
            // for its `(1 + x_round)` alignment gate while S stays constant.
            // Instances run as separate parallel folds — the coefficient
            // sums are XOR-accumulated, so regrouping by instance is
            // bit-identical to the earlier flat work list and drops the
            // per-pair offset search from the hot loop.
            let contributions = (0..w_logs.len())
                .into_par_iter()
                .map(|instance| {
                    ragged_instance_round_contribution(
                        q,
                        round < w_logs[instance],
                        &e_tables[instance],
                        &s_tables[instance],
                    )
                })
                .collect::<Vec<_>>();
            let mut full = [F128::ZERO; WALK_DEGREE + 1];
            for contribution in contributions {
                for (slot, value) in full.iter_mut().zip(&contribution) {
                    *slot += *value;
                }
            }
            debug_assert_eq!(
                full[0] + horner(&full, F128::ONE),
                claim,
                "ragged layer {layer}, coordinate {round} Boolean sum"
            );
            let wire = compress(&full);
            challenger.observe_f128_slice(&wire);
            let challenge = challenger.sample_f128();
            claim = horner(&full, challenge);
            point.push(challenge);
            round_coeffs.push(wire);
            e_tables
                .par_iter_mut()
                .zip(s_tables.par_iter_mut())
                .zip(e_single_fold_scratch.par_iter_mut())
                .zip(e_dense_fold_scratch.par_iter_mut())
                .zip(s_fold_scratch.par_iter_mut())
                .zip(w_logs.par_iter())
                .for_each(
                    |(
                        ((((e_table, s_table), e_single_scratch), e_dense_scratch), s_scratch),
                        &w_log,
                    )| {
                        fold_ragged_instance_tables(
                            round < w_log,
                            challenge,
                            e_table,
                            s_table,
                            e_single_scratch,
                            e_dense_scratch,
                            s_scratch,
                        );
                    },
                );
        }
        sumcheck_elapsed += sumcheck_started.elapsed();

        let finish_started = std::time::Instant::now();
        let next_values: Vec<[F128; STATE_SIZE]> =
            s_tables.iter().map(|instance| instance[0]).collect();
        let flat_next = next_values
            .iter()
            .flat_map(|values| values.iter().copied())
            .collect::<Vec<_>>();
        challenger.observe_f128_slice(&flat_next);

        let mut expected = F128::ZERO;
        for (instance, ((instance_groups, instance_weights), instance_next)) in
            groups.iter().zip(&weights).zip(&next_values).enumerate()
        {
            let terms = layer_terms(q, instance_next);
            let w_log = w_logs[instance];
            let mut high_gate = F128::ONE;
            for &coordinate in &point[w_log..] {
                high_gate *= F128::ONE + coordinate;
            }
            for (group, lane_weights) in instance_groups.iter().zip(instance_weights) {
                let columns = column_weights(q, lane_weights);
                let aligned_eq = eq_eval(&group.point, &point[..w_log]) * high_gate;
                let mut dot = F128::ZERO;
                for lane in 0..STATE_SIZE {
                    dot += columns[lane] * terms[lane];
                }
                expected += aligned_eq * dot;
            }
            debug_assert_eq!(e_tables[instance].len(), 1);
        }
        debug_assert_eq!(
            expected, claim,
            "ragged layer {layer} prover-side final mismatch"
        );

        layers.push(MultiWalkLayerProof {
            round_coeffs,
            next_values: next_values.clone(),
        });
        groups = next_values
            .into_iter()
            .enumerate()
            .map(|(instance, values)| {
                vec![LaneClaimGroup {
                    point: point[..w_logs[instance]].to_vec(),
                    values,
                }]
            })
            .collect();
        finish_elapsed += finish_started.elapsed();
    }

    let terminals = groups
        .into_iter()
        .map(|mut instance| instance.pop().expect("one terminal group per instance"))
        .collect();
    if timing_enabled {
        eprintln!(
            "NOIDH deep-chain-ragged widths={w_logs:?} state_init_ms={} setup_ms={} state_fetch_ms={} sumcheck_ms={} finish_ms={} total_ms={}",
            state_init_elapsed.as_millis(),
            setup_elapsed.as_millis(),
            state_fetch_elapsed.as_millis(),
            sumcheck_elapsed.as_millis(),
            finish_elapsed.as_millis(),
            total_started.elapsed().as_millis(),
        );
    }
    (MultiDeepChainWalkProof { layers }, terminals)
}

fn apply_round_columns(q: usize, cols: &mut [Vec<F128>; STATE_SIZE]) {
    let w = cols[0].len();
    let chunk = 1usize.max(w / (rayon::current_num_threads().max(1) * 4));
    // One `apply_round` per position into a position-major buffer, then a
    // memory-bound scatter back to lane-major columns. The earlier form
    // recomputed the full round once per output lane (STATE_SIZE× the
    // multiplications) to avoid the transpose; the round function dominates,
    // so paying the scatter is the cheaper side. Values and their in-lane
    // order are bit-identical.
    let mut rows: Vec<[F128; STATE_SIZE]> = vec![[F128::ZERO; STATE_SIZE]; w];
    rows.par_chunks_mut(chunk)
        .enumerate()
        .for_each(|(c, slots)| {
            let base = c * chunk;
            for (dw, slot) in slots.iter_mut().enumerate() {
                let widx = base + dw;
                let state: [F128; STATE_SIZE] = std::array::from_fn(|j| cols[j][widx]);
                *slot = apply_round(q, state);
            }
        });
    for (lane, col) in cols.iter_mut().enumerate() {
        col.par_chunks_mut(chunk)
            .enumerate()
            .for_each(|(c, slots)| {
                let base = c * chunk;
                for (dw, slot) in slots.iter_mut().enumerate() {
                    *slot = rows[base + dw][lane];
                }
            });
    }
}

fn columns_to_rows(columns: &[Vec<F128>; STATE_SIZE]) -> Vec<[F128; STATE_SIZE]> {
    let w = columns[0].len();
    (0..w)
        .into_par_iter()
        .map(|slot| std::array::from_fn(|lane| columns[lane][slot]))
        .collect()
}

/// Apply a consecutive round span while each four-lane slot stays hot in the
/// worker.  This is exactly the repeated [`apply_round`] map, but one Rayon
/// pass replaces one full-memory pass and barrier per round.
fn apply_round_span_rows(first_round: usize, round_count: usize, rows: &mut [[F128; STATE_SIZE]]) {
    assert!(
        first_round + round_count <= N_ROUNDS,
        "round span outside schedule"
    );
    let chunk = 1usize.max(rows.len() / (rayon::current_num_threads().max(1) * 4));
    rows.par_chunks_mut(chunk).for_each(|slots| {
        for slot in slots {
            let mut state = *slot;
            for q in first_round..first_round + round_count {
                state = apply_round(q, state);
            }
            *slot = state;
        }
    });
}

/// Materialize one descending-server checkpoint window in a single slot-wise
/// pass.  Every intermediate state remains independently owned and in the
/// same layer-major order as the former clone-then-transform loop; MultiZip
/// merely lets one worker carry `S_base[slot]` through all seven rounds before
/// moving to another slot.
fn replay_round_window(
    checkpoint: Vec<[F128; STATE_SIZE]>,
    base: usize,
    len: usize,
) -> Vec<Vec<[F128; STATE_SIZE]>> {
    assert!(
        len > 0 && len <= CHECKPOINT_SPACING,
        "checkpoint window length"
    );
    assert!(base + len <= N_ROUNDS, "checkpoint window outside schedule");
    if len == 1 {
        return vec![checkpoint];
    }

    let width = checkpoint.len();
    match len {
        // The terminal S_64/S_65 window for the frozen 66-round schedule.
        2 => {
            let mut s1 = vec![[F128::ZERO; STATE_SIZE]; width];
            (checkpoint.as_slice(), s1.as_mut_slice())
                .into_par_iter()
                .for_each(|(&s0, s1)| *s1 = apply_round(base, s0));
            vec![checkpoint, s1]
        }
        // Every complete checkpoint window.  Each output vector is disjoint,
        // so the tuple iterator is safe and preserves slot order exactly.
        CHECKPOINT_SPACING => {
            const _: () = assert!(CHECKPOINT_SPACING == 8);
            let mut s1 = vec![[F128::ZERO; STATE_SIZE]; width];
            let mut s2 = vec![[F128::ZERO; STATE_SIZE]; width];
            let mut s3 = vec![[F128::ZERO; STATE_SIZE]; width];
            let mut s4 = vec![[F128::ZERO; STATE_SIZE]; width];
            let mut s5 = vec![[F128::ZERO; STATE_SIZE]; width];
            let mut s6 = vec![[F128::ZERO; STATE_SIZE]; width];
            let mut s7 = vec![[F128::ZERO; STATE_SIZE]; width];
            (
                checkpoint.as_slice(),
                s1.as_mut_slice(),
                s2.as_mut_slice(),
                s3.as_mut_slice(),
                s4.as_mut_slice(),
                s5.as_mut_slice(),
                s6.as_mut_slice(),
                s7.as_mut_slice(),
            )
                .into_par_iter()
                .for_each(|(&s0, s1, s2, s3, s4, s5, s6, s7)| {
                    *s1 = apply_round(base, s0);
                    *s2 = apply_round(base + 1, *s1);
                    *s3 = apply_round(base + 2, *s2);
                    *s4 = apply_round(base + 3, *s3);
                    *s5 = apply_round(base + 4, *s4);
                    *s6 = apply_round(base + 5, *s5);
                    *s7 = apply_round(base + 6, *s6);
                });
            vec![checkpoint, s1, s2, s3, s4, s5, s6, s7]
        }
        // Kept for a future round-count change.  It is not selected by the
        // frozen 66/8 geometry and retains the exact reference construction.
        _ => {
            let mut window = Vec::with_capacity(len);
            window.push(checkpoint);
            for i in 1..len {
                let mut next = window[i - 1].clone();
                apply_round_span_rows(base + i - 1, 1, &mut next);
                window.push(next);
            }
            window
        }
    }
}

/// Row-major checkpoint server used by the ragged Link walk. The round
/// function naturally consumes one four-lane state, so retaining this layout
/// removes the position-major scratch allocation and four lane scatters from
/// every forward/replayed Poseidon round.
struct RaggedDescendingLayerStates {
    checkpoints: Vec<Vec<[F128; STATE_SIZE]>>,
    window: Vec<Vec<[F128; STATE_SIZE]>>,
    window_base: usize,
}

impl RaggedDescendingLayerStates {
    fn new(s0: &[Vec<F128>; STATE_SIZE]) -> Self {
        Self::from_rows(columns_to_rows(s0))
    }

    fn from_rows(mut current: Vec<[F128; STATE_SIZE]>) -> Self {
        let mut checkpoints = vec![current.clone()];
        let last_checkpoint = ((N_ROUNDS - 1) / CHECKPOINT_SPACING) * CHECKPOINT_SPACING;
        let mut q = 0usize;
        while q < last_checkpoint {
            let step = CHECKPOINT_SPACING.min(last_checkpoint - q);
            apply_round_span_rows(q, step, &mut current);
            q += step;
            checkpoints.push(current.clone());
        }
        Self {
            checkpoints,
            window: Vec::new(),
            window_base: usize::MAX,
        }
    }

    fn state(&mut self, q: usize) -> Vec<[F128; STATE_SIZE]> {
        let base = (q / CHECKPOINT_SPACING) * CHECKPOINT_SPACING;
        if self.window_base != base {
            let len = CHECKPOINT_SPACING.min(N_ROUNDS - base);
            let checkpoint = std::mem::take(&mut self.checkpoints[base / CHECKPOINT_SPACING]);
            assert!(!checkpoint.is_empty(), "checkpoint requested twice");
            self.window = replay_round_window(checkpoint, base, len);
            self.window_base = base;
        }
        let slot = &mut self.window[q - self.window_base];
        assert!(!slot.is_empty(), "layer state S_{q} requested twice");
        std::mem::take(slot)
    }
}

/// Backward layer-state server for the walk provers.
///
/// The walk consumes `S_q` for `q = N_ROUNDS-1 .. 0` while states are only
/// computable forward, so some replay is unavoidable. The former per-layer
/// rebuild replayed up to `CHECKPOINT_SPACING-1` rounds for every layer
/// (~3.5·N_ROUNDS extra applies); this server materializes one checkpoint
/// window at a time and hands each state out exactly once, bounding total
/// work to one forward pass plus one window replay (~2·N_ROUNDS applies)
/// and extra memory to `CHECKPOINT_SPACING` column sets. Values are
/// bit-identical to the per-layer rebuild.
struct DescendingLayerStates {
    checkpoints: Vec<[Vec<F128>; STATE_SIZE]>,
    /// `window[i]` is `S_{window_base + i}`; slots are taken (emptied) as the
    /// walk consumes them.
    window: Vec<[Vec<F128>; STATE_SIZE]>,
    window_base: usize,
}

impl DescendingLayerStates {
    fn new(s0: &[Vec<F128>; STATE_SIZE]) -> Self {
        let mut checkpoints = vec![s0.clone()];
        let mut current = s0.clone();
        let mut q = 0usize;
        // The highest state consumed by the backward walk is S_{N_ROUNDS-1}.
        // Stop at its checkpoint base: the former final S_66 checkpoint cost
        // two full column rounds and was never requested.
        let last_checkpoint = ((N_ROUNDS - 1) / CHECKPOINT_SPACING) * CHECKPOINT_SPACING;
        while q < last_checkpoint {
            let step = CHECKPOINT_SPACING.min(last_checkpoint - q);
            for dq in 0..step {
                apply_round_columns(q + dq, &mut current);
            }
            q += step;
            checkpoints.push(current.clone());
        }
        Self {
            checkpoints,
            window: Vec::new(),
            window_base: usize::MAX,
        }
    }

    /// Owned columns of `S_q` (the state after `q` rounds). Each `q` may be
    /// requested once per walk; requests must not revisit a window that a
    /// smaller `q` has already replaced.
    fn state(&mut self, q: usize) -> [Vec<F128>; STATE_SIZE] {
        let base = (q / CHECKPOINT_SPACING) * CHECKPOINT_SPACING;
        if self.window_base != base {
            let len = CHECKPOINT_SPACING.min(N_ROUNDS - base);
            let mut window = Vec::with_capacity(len);
            // Windows are visited in strictly descending order. Move their
            // checkpoint into the window instead of cloning it; neither this
            // checkpoint nor any higher one can be requested again. Besides
            // removing a full-column copy, retained checkpoint memory now
            // falls as the proof descends.
            let checkpoint = std::mem::take(&mut self.checkpoints[base / CHECKPOINT_SPACING]);
            assert!(!checkpoint[0].is_empty(), "checkpoint requested twice");
            window.push(checkpoint);
            for i in 1..len {
                let mut next = window[i - 1].clone();
                apply_round_columns(base + i - 1, &mut next);
                window.push(next);
            }
            self.window = window;
            self.window_base = base;
        }
        let slot = &mut self.window[q - self.window_base];
        assert!(!slot[0].is_empty(), "layer state S_{q} requested twice");
        std::mem::take(slot)
    }
}

#[inline]
fn fold_in_place(table: &mut Vec<F128>, r: F128) {
    let half = table.len() / 2;
    let folded: Vec<F128> = (0..half)
        .into_par_iter()
        .map(|p| {
            let a = table[2 * p];
            let b = table[2 * p + 1];
            a + r * (a + b)
        })
        .collect();
    *table = folded;
}

#[inline]
fn fold_rows_reusing(
    table: &mut Vec<[F128; STATE_SIZE]>,
    scratch: &mut Vec<[F128; STATE_SIZE]>,
    r: F128,
) {
    let half = table.len() / 2;
    (0..half)
        .into_par_iter()
        .map(|p| {
            let a = table[2 * p];
            let b = table[2 * p + 1];
            let [d0, d1] = mul_pair(r, a[0] + b[0], r, a[1] + b[1]);
            let [d2, d3] = mul_pair(r, a[2] + b[2], r, a[3] + b[3]);
            [a[0] + d0, a[1] + d1, a[2] + d2, a[3] + d3]
        })
        .collect_into_vec(scratch);
    std::mem::swap(table, scratch);
}

#[inline]
fn fold_table_reusing(table: &mut Vec<F128>, scratch: &mut Vec<F128>, r: F128) {
    let half = table.len() / 2;
    scratch.clear();
    scratch.par_extend((0..half).into_par_iter().map(|p| {
        let a = table[2 * p];
        let b = table[2 * p + 1];
        a + r * (a + b)
    }));
    std::mem::swap(table, scratch);
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verify the walk; returns the terminal layer-0 claim the caller must
/// discharge against committed input columns.
pub fn verify_deep_chain_walk<Ch: Challenger>(
    w_log: usize,
    out_groups: &[LaneClaimGroup],
    proof: &DeepChainWalkProof,
    challenger: &mut Ch,
) -> Result<LaneClaimGroup, WalkError> {
    if out_groups.is_empty()
        || out_groups.iter().any(|g| g.point.len() != w_log)
        || proof.layers.len() != N_ROUNDS
        || proof.layers.iter().any(|l| l.round_coeffs.len() != w_log)
    {
        return Err(WalkError::Shape);
    }

    absorb_groups(challenger, out_groups);

    let mut groups: Vec<LaneClaimGroup> = out_groups.to_vec();
    for (li, layer_proof) in proof.layers.iter().enumerate() {
        let layer = N_ROUNDS - li;
        let q = layer - 1;
        let alpha = challenger.sample_f128();
        let weights = lane_weight_table(alpha, groups.len());

        let mut claim = F128::ZERO;
        for (g, w_g) in groups.iter().zip(weights.iter()) {
            for i in 0..STATE_SIZE {
                claim += w_g[i] * g.values[i];
            }
        }

        let mut point = Vec::with_capacity(w_log);
        for wire in &layer_proof.round_coeffs {
            challenger.observe_f128_slice(wire);
            let full = reconstruct(wire, claim);
            let r = challenger.sample_f128();
            claim = horner(&full, r);
            point.push(r);
        }
        challenger.observe_f128_slice(&layer_proof.next_values);

        // E_j(point) = Σ_g c_{g,j} · eq(ρ_g, point), then reassemble.
        let mut expected = F128::ZERO;
        let terms = layer_terms(q, &layer_proof.next_values);
        for (g, w_g) in groups.iter().zip(weights.iter()) {
            let c = column_weights(q, w_g);
            let eq = eq_eval(&g.point, &point);
            let mut dot = F128::ZERO;
            for j in 0..STATE_SIZE {
                dot += c[j] * terms[j];
            }
            expected += eq * dot;
        }
        if expected != claim {
            return Err(WalkError::LayerMismatch(layer));
        }

        groups = vec![LaneClaimGroup {
            point,
            values: layer_proof.next_values,
        }];
    }

    Ok(groups.pop().expect("one terminal group"))
}

/// Verify an equal-`w_log` V1 multi-instance walk and return one terminal
/// layer-0 claim per instance.
pub fn verify_multi_deep_chain_walk<Ch: Challenger>(
    w_log: usize,
    out_groups: &[Vec<LaneClaimGroup>],
    proof: &MultiDeepChainWalkProof,
    challenger: &mut Ch,
) -> Result<Vec<LaneClaimGroup>, WalkError> {
    let instances = out_groups.len();
    if instances == 0
        || out_groups.iter().any(|groups| {
            groups.is_empty() || groups.iter().any(|group| group.point.len() != w_log)
        })
        || proof.layers.len() != N_ROUNDS
        || proof
            .layers
            .iter()
            .any(|layer| layer.round_coeffs.len() != w_log || layer.next_values.len() != instances)
    {
        return Err(WalkError::Shape);
    }

    absorb_multi_groups(challenger, out_groups);

    let mut groups = out_groups.to_vec();
    for (layer_index, layer_proof) in proof.layers.iter().enumerate() {
        let layer = N_ROUNDS - layer_index;
        let q = layer - 1;
        let alpha = challenger.sample_f128();
        let total_groups = groups.iter().map(Vec::len).sum();
        let flat_weights = lane_weight_table(alpha, total_groups);
        let mut weight_cursor = 0usize;
        let weights: Vec<Vec<[F128; STATE_SIZE]>> = groups
            .iter()
            .map(|instance| {
                let end = weight_cursor + instance.len();
                let instance_weights = flat_weights[weight_cursor..end].to_vec();
                weight_cursor = end;
                instance_weights
            })
            .collect();
        debug_assert_eq!(weight_cursor, flat_weights.len());

        let mut claim = F128::ZERO;
        for (instance_groups, instance_weights) in groups.iter().zip(&weights) {
            for (group, lane_weights) in instance_groups.iter().zip(instance_weights) {
                for lane in 0..STATE_SIZE {
                    claim += lane_weights[lane] * group.values[lane];
                }
            }
        }

        let mut point = Vec::with_capacity(w_log);
        for wire in &layer_proof.round_coeffs {
            challenger.observe_f128_slice(wire);
            let full = reconstruct(wire, claim);
            let challenge = challenger.sample_f128();
            claim = horner(&full, challenge);
            point.push(challenge);
        }
        let flat_next = layer_proof
            .next_values
            .iter()
            .flat_map(|values| values.iter().copied())
            .collect::<Vec<_>>();
        challenger.observe_f128_slice(&flat_next);

        let mut expected = F128::ZERO;
        for ((instance_groups, instance_weights), instance_next) in
            groups.iter().zip(&weights).zip(&layer_proof.next_values)
        {
            let terms = layer_terms(q, instance_next);
            for (group, lane_weights) in instance_groups.iter().zip(instance_weights) {
                let columns = column_weights(q, lane_weights);
                let eq = eq_eval(&group.point, &point);
                let mut dot = F128::ZERO;
                for lane in 0..STATE_SIZE {
                    dot += columns[lane] * terms[lane];
                }
                expected += eq * dot;
            }
        }
        if expected != claim {
            return Err(WalkError::LayerMismatch(layer));
        }

        groups = layer_proof
            .next_values
            .iter()
            .map(|values| {
                vec![LaneClaimGroup {
                    point: point.clone(),
                    values: *values,
                }]
            })
            .collect();
    }

    Ok(groups
        .into_iter()
        .map(|mut instance| instance.pop().expect("one terminal group per instance"))
        .collect())
}

/// Verify a ragged-domain V2 multi-instance walk.
///
/// `w_logs[a]` is instance `a`'s committed-column width.  The verifier
/// derives `W = max(w_logs)`, checks exactly `W` aggregate rounds, and aligns
/// every smaller relation with an all-zero high-coordinate suffix.  See
/// [`prove_ragged_multi_deep_chain_walk`] for the embedded relation and degree
/// argument.
pub fn verify_ragged_multi_deep_chain_walk<Ch: Challenger>(
    w_logs: &[usize],
    out_groups: &[Vec<LaneClaimGroup>],
    proof: &MultiDeepChainWalkProof,
    challenger: &mut Ch,
) -> Result<Vec<LaneClaimGroup>, WalkError> {
    let instances = out_groups.len();
    if instances == 0 || w_logs.len() != instances {
        return Err(WalkError::Shape);
    }
    let max_w_log = *w_logs.iter().max().ok_or(WalkError::Shape)?;
    if out_groups.iter().zip(w_logs).any(|(groups, &w_log)| {
        groups.is_empty() || groups.iter().any(|group| group.point.len() != w_log)
    }) || proof.layers.len() != N_ROUNDS
        || proof.layers.iter().any(|layer| {
            layer.round_coeffs.len() != max_w_log || layer.next_values.len() != instances
        })
    {
        return Err(WalkError::Shape);
    }

    absorb_ragged_multi_groups(challenger, w_logs, out_groups);

    let mut groups = out_groups.to_vec();
    for (layer_index, layer_proof) in proof.layers.iter().enumerate() {
        let layer = N_ROUNDS - layer_index;
        let q = layer - 1;
        let alpha = challenger.sample_f128();
        let total_groups = groups.iter().map(Vec::len).sum();
        let flat_weights = lane_weight_table(alpha, total_groups);
        let mut weight_cursor = 0usize;
        let weights: Vec<Vec<[F128; STATE_SIZE]>> = groups
            .iter()
            .map(|instance| {
                let end = weight_cursor + instance.len();
                let instance_weights = flat_weights[weight_cursor..end].to_vec();
                weight_cursor = end;
                instance_weights
            })
            .collect();
        debug_assert_eq!(weight_cursor, flat_weights.len());

        let mut claim = F128::ZERO;
        for (instance_groups, instance_weights) in groups.iter().zip(&weights) {
            for (group, lane_weights) in instance_groups.iter().zip(instance_weights) {
                for lane in 0..STATE_SIZE {
                    claim += lane_weights[lane] * group.values[lane];
                }
            }
        }

        let mut point = Vec::with_capacity(max_w_log);
        for wire in &layer_proof.round_coeffs {
            challenger.observe_f128_slice(wire);
            let full = reconstruct(wire, claim);
            let challenge = challenger.sample_f128();
            claim = horner(&full, challenge);
            point.push(challenge);
        }
        let flat_next = layer_proof
            .next_values
            .iter()
            .flat_map(|values| values.iter().copied())
            .collect::<Vec<_>>();
        challenger.observe_f128_slice(&flat_next);

        let mut expected = F128::ZERO;
        for (instance, ((instance_groups, instance_weights), instance_next)) in groups
            .iter()
            .zip(&weights)
            .zip(&layer_proof.next_values)
            .enumerate()
        {
            let terms = layer_terms(q, instance_next);
            let w_log = w_logs[instance];
            let mut high_gate = F128::ONE;
            for &coordinate in &point[w_log..] {
                high_gate *= F128::ONE + coordinate;
            }
            for (group, lane_weights) in instance_groups.iter().zip(instance_weights) {
                let columns = column_weights(q, lane_weights);
                let aligned_eq = eq_eval(&group.point, &point[..w_log]) * high_gate;
                let mut dot = F128::ZERO;
                for lane in 0..STATE_SIZE {
                    dot += columns[lane] * terms[lane];
                }
                expected += aligned_eq * dot;
            }
        }
        if expected != claim {
            return Err(WalkError::LayerMismatch(layer));
        }

        groups = layer_proof
            .next_values
            .iter()
            .enumerate()
            .map(|(instance, values)| {
                vec![LaneClaimGroup {
                    point: point[..w_logs[instance]].to_vec(),
                    values: *values,
                }]
            })
            .collect();
    }

    Ok(groups
        .into_iter()
        .map(|mut instance| instance.pop().expect("one terminal group per instance"))
        .collect())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::FsLaneChallenger;

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

    fn mle_eval(col: &[F128], point: &[F128]) -> F128 {
        let eq = build_eq_table(point);
        let mut acc = F128::ZERO;
        for (v, e) in col.iter().zip(eq.iter()) {
            acc += *v * *e;
        }
        acc
    }

    fn random_columns(w_log: usize, seed: u64) -> [Vec<F128>; STATE_SIZE] {
        let mut rng = Rng(seed);
        std::array::from_fn(|_| (0..1usize << w_log).map(|_| rng.f128()).collect())
    }

    fn output_columns(s0: &[Vec<F128>; STATE_SIZE]) -> [Vec<F128>; STATE_SIZE] {
        let w = s0[0].len();
        let mut out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
        for widx in 0..w {
            let mut state: [F128; STATE_SIZE] = std::array::from_fn(|j| s0[j][widx]);
            for q in 0..N_ROUNDS {
                state = apply_round(q, state);
            }
            for j in 0..STATE_SIZE {
                out[j][widx] = state[j];
            }
        }
        out
    }

    fn multi_walk_fixture(
        w_log: usize,
    ) -> (Vec<[Vec<F128>; STATE_SIZE]>, Vec<Vec<LaneClaimGroup>>) {
        let instances = vec![
            random_columns(w_log, 0xB471_0001),
            random_columns(w_log, 0xB471_0002),
        ];
        let outputs = instances.iter().map(output_columns).collect::<Vec<_>>();
        let mut rng = Rng(0xB471_F5);
        let groups = outputs
            .iter()
            .enumerate()
            .map(|(instance, output)| {
                (0..=instance)
                    .map(|_| {
                        let point = (0..w_log).map(|_| rng.f128()).collect::<Vec<_>>();
                        let values = std::array::from_fn(|lane| mle_eval(&output[lane], &point));
                        LaneClaimGroup { point, values }
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        (instances, groups)
    }

    fn ragged_multi_walk_fixture(
        w_logs: &[usize],
    ) -> (Vec<[Vec<F128>; STATE_SIZE]>, Vec<Vec<LaneClaimGroup>>) {
        let instances = w_logs
            .iter()
            .enumerate()
            .map(|(instance, &w_log)| random_columns(w_log, 0xA11D_0000 + instance as u64))
            .collect::<Vec<_>>();
        let outputs = instances.iter().map(output_columns).collect::<Vec<_>>();
        let mut rng = Rng(0xA11D_F5);
        let groups = outputs
            .iter()
            .zip(w_logs)
            .enumerate()
            .map(|(instance, (output, &w_log))| {
                (0..=instance % 2)
                    .map(|_| {
                        let point = (0..w_log).map(|_| rng.f128()).collect::<Vec<_>>();
                        let values = std::array::from_fn(|lane| mle_eval(&output[lane], &point));
                        LaneClaimGroup { point, values }
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        (instances, groups)
    }

    #[test]
    fn single_group_factoring_matches_dense_e_polynomial() {
        let mut rng = Rng(0xE51D_E17A);
        // Exercise both schedule branches and enough independent field
        // values to lock the factored kernel to the dense E-lane equation.
        for q in [0usize, F_ROUNDS / 2] {
            assert_eq!(is_full_round(q), q == 0);
            for _ in 0..32 {
                let eq_base = rng.f128();
                let eq_delta = rng.f128();
                let columns = std::array::from_fn(|_| rng.f128());
                let s_base = std::array::from_fn(|_| rng.f128());
                let s_delta = std::array::from_fn(|_| rng.f128());
                let e_base = std::array::from_fn(|lane| columns[lane] * eq_base);
                let e_delta = std::array::from_fn(|lane| columns[lane] * eq_delta);

                let mut dense = [F256Unreduced::ZERO; WALK_DEGREE + 1];
                accumulate_pair_round_coeffs(q, &e_base, &e_delta, &s_base, &s_delta, &mut dense);
                let mut factored = [F256Unreduced::ZERO; WALK_DEGREE + 1];
                accumulate_single_group_pair_round_coeffs(
                    q,
                    eq_base,
                    eq_delta,
                    &columns,
                    &s_base,
                    &s_delta,
                    &mut factored,
                );
                assert_eq!(
                    reduce_round_coeffs(factored),
                    reduce_round_coeffs(dense),
                    "factored E polynomial drift at round {q}",
                );
            }
        }
    }

    fn multi_walk_terminals_are_honest(
        w_log: usize,
        instances: &[[Vec<F128>; STATE_SIZE]],
        groups: &[Vec<LaneClaimGroup>],
        proof: &MultiDeepChainWalkProof,
    ) -> bool {
        let mut challenger = FsLaneChallenger::new(b"deep-chain-multi-test");
        let Ok(terminals) = verify_multi_deep_chain_walk(w_log, groups, proof, &mut challenger)
        else {
            return false;
        };
        terminals.len() == instances.len()
            && terminals.iter().zip(instances).all(|(terminal, s0)| {
                (0..STATE_SIZE)
                    .all(|lane| mle_eval(&s0[lane], &terminal.point) == terminal.values[lane])
            })
    }

    /// The layer schedule composed with `initial_mds` IS the production
    /// permutation, slot by slot — the structural anchor of the whole walk.
    #[test]
    fn rounds_compose_to_the_native_permutation() {
        use noid_poseidon2b::native::permutation::permute_flat_u128;
        let mut rng = Rng(0xD5E9);
        for _ in 0..8 {
            let raw: [F128; STATE_SIZE] = std::array::from_fn(|_| rng.f128());
            let mut state = initial_mds(raw);
            for q in 0..N_ROUNDS {
                state = apply_round(q, state);
            }
            let mut flat: [u128; STATE_SIZE] =
                std::array::from_fn(|i| (raw[i].lo as u128) | ((raw[i].hi as u128) << 64));
            permute_flat_u128(&mut flat);
            let expected: [F128; STATE_SIZE] = std::array::from_fn(|i| F128 {
                lo: flat[i] as u64,
                hi: (flat[i] >> 64) as u64,
            });
            assert_eq!(state, expected, "walk rounds diverge from permute_flat");
        }
    }

    /// The sparse MDS kernels are an implementation-only optimization.  Keep
    /// an independent dense 4x4 oracle so every output lane remains exactly
    /// equal for both frozen matrices, including the identity-elision path.
    #[test]
    fn sparse_mds_kernels_match_dense_field_product_oracle() {
        fn dense(
            matrix: &[[F128; STATE_SIZE]; STATE_SIZE],
            input: [F128; STATE_SIZE],
        ) -> [F128; STATE_SIZE] {
            std::array::from_fn(|row| {
                let mut value = F128::ZERO;
                for (coefficient, input) in matrix[row].iter().zip(input) {
                    value += *coefficient * input;
                }
                value
            })
        }

        let schedule = schedule();
        let mut rng = Rng(0x5A25_E1D5);
        for _ in 0..256 {
            let input = std::array::from_fn(|_| rng.f128());
            assert_eq!(
                mds_apply_full(&schedule.mds_full, input),
                dense(&schedule.mds_full, input),
                "full MDS"
            );
            assert_eq!(
                mds_apply_partial(&schedule.mds_partial, input),
                dense(&schedule.mds_partial, input),
                "partial MDS"
            );
        }
    }

    #[test]
    fn interpolation_roundtrips() {
        let mut rng = Rng(0x1E77);
        let coeffs: [F128; WALK_DEGREE + 1] = std::array::from_fn(|_| rng.f128());
        let evals: [F128; WALK_DEGREE + 1] =
            std::array::from_fn(|t| horner(&coeffs, f128_of_u128(t as u128)));
        assert_eq!(interpolate(&evals), coeffs);
    }

    /// Deferred reduction must be a wire-preserving arithmetic change: XORing
    /// the 256-bit products and reducing once has to match reducing every
    /// product before it enters the coefficient accumulator.
    #[test]
    fn deferred_round_coeff_accumulation_matches_reduced_reference() {
        fn reduced_reference(
            q: usize,
            e_base: &[F128; STATE_SIZE],
            e_delta: &[F128; STATE_SIZE],
            s_base: &[F128; STATE_SIZE],
            s_delta: &[F128; STATE_SIZE],
        ) -> [F128; WALK_DEGREE + 1] {
            let sch = schedule();
            let full_round = is_full_round(q);
            let mut acc = [F128::ZERO; WALK_DEGREE + 1];
            for j in 0..STATE_SIZE {
                let eb = e_base[j];
                let ed = e_delta[j];
                if full_round || j == 0 {
                    let a = s_base[j] + sch.rc[j][q];
                    let b = s_delta[j];
                    let a2 = a * a;
                    let b2 = b * b;
                    let a4 = a2 * a2;
                    let b4 = b2 * b2;
                    let a4a2 = a4 * a2;
                    let a4b2 = a4 * b2;
                    let b4a2 = b4 * a2;
                    let b4b2 = b4 * b2;
                    let terms = [
                        a4a2 * a,
                        a4a2 * b,
                        a4b2 * a,
                        a4b2 * b,
                        b4a2 * a,
                        b4a2 * b,
                        b4b2 * a,
                        b4b2 * b,
                    ];
                    for (d, &term) in terms.iter().enumerate() {
                        acc[d] += eb * term;
                        acc[d + 1] += ed * term;
                    }
                } else {
                    let sb = s_base[j];
                    let sd = s_delta[j];
                    acc[0] += eb * sb;
                    acc[1] += eb * sd + ed * sb;
                    acc[2] += ed * sd;
                }
            }
            acc
        }

        let mut rng = Rng(0xDEF3_22ED);
        for q in 0..N_ROUNDS {
            for _ in 0..4 {
                let e_base = std::array::from_fn(|_| rng.f128());
                let e_delta = std::array::from_fn(|_| rng.f128());
                let s_base = std::array::from_fn(|_| rng.f128());
                let s_delta = std::array::from_fn(|_| rng.f128());
                let mut deferred = [F256Unreduced::ZERO; WALK_DEGREE + 1];
                accumulate_pair_round_coeffs(
                    q,
                    &e_base,
                    &e_delta,
                    &s_base,
                    &s_delta,
                    &mut deferred,
                );
                assert_eq!(
                    reduce_round_coeffs(deferred),
                    reduced_reference(q, &e_base, &e_delta, &s_base, &s_delta),
                    "round {q}"
                );
            }
        }
    }

    #[test]
    fn paired_unreduced_products_match_scalar_layout() {
        let mut rng = Rng(0x2A1E_DF00);
        for _ in 0..256 {
            let a0 = rng.f128();
            let b0 = rng.f128();
            let a1 = rng.f128();
            let b1 = rng.f128();
            assert_eq!(
                mul_unreduced_pair(a0, b0, a1, b1),
                [a0.mul_unreduced(b0), a1.mul_unreduced(b1)]
            );
        }
    }

    fn apply_round_span_rows_scalar(
        first_round: usize,
        round_count: usize,
        rows: &mut [[F128; STATE_SIZE]],
    ) {
        for q in first_round..first_round + round_count {
            for row in rows.iter_mut() {
                *row = apply_round(q, *row);
            }
        }
    }

    fn replay_round_window_scalar(
        checkpoint: Vec<[F128; STATE_SIZE]>,
        base: usize,
        len: usize,
    ) -> Vec<Vec<[F128; STATE_SIZE]>> {
        let mut window = Vec::with_capacity(len);
        window.push(checkpoint);
        for i in 1..len {
            let mut next = window[i - 1].clone();
            apply_round_span_rows_scalar(base + i - 1, 1, &mut next);
            window.push(next);
        }
        window
    }

    #[test]
    fn fused_round_spans_match_scalar_round_order() {
        let mut rng = Rng(0x5A4E_5F00);
        let rows = (0..257)
            .map(|_| std::array::from_fn(|_| rng.f128()))
            .collect::<Vec<_>>();
        for (first_round, round_count) in [
            (0, CHECKPOINT_SPACING),
            (F_ROUNDS / 2, CHECKPOINT_SPACING),
            (N_ROUNDS - CHECKPOINT_SPACING, CHECKPOINT_SPACING),
            (N_ROUNDS - 2, 2),
        ] {
            let mut reference = rows.clone();
            apply_round_span_rows_scalar(first_round, round_count, &mut reference);
            let mut fused = rows.clone();
            apply_round_span_rows(first_round, round_count, &mut fused);
            assert_eq!(fused, reference, "round span {first_round}+{round_count}");
        }
    }

    #[test]
    fn fused_round_windows_match_scalar_intermediate_layers() {
        let mut rng = Rng(0x71D0_5F00);
        let checkpoint = (0..257)
            .map(|_| std::array::from_fn(|_| rng.f128()))
            .collect::<Vec<_>>();
        for (base, len) in [
            (0, CHECKPOINT_SPACING),
            (F_ROUNDS / 2, CHECKPOINT_SPACING),
            (N_ROUNDS - 2, 2),
        ] {
            let reference = replay_round_window_scalar(checkpoint.clone(), base, len);
            let fused = replay_round_window(checkpoint.clone(), base, len);
            assert_eq!(fused, reference, "round window {base}+{len}");
        }
    }

    #[test]
    fn ragged_row_major_state_server_matches_column_reference() {
        let s0 = random_columns(5, 0x57A7_E5);
        let mut column_server = DescendingLayerStates::new(&s0);
        let mut row_server = RaggedDescendingLayerStates::new(&s0);
        for q in (0..N_ROUNDS).rev() {
            let columns = column_server.state(q);
            let rows = row_server.state(q);
            assert_eq!(rows.len(), columns[0].len());
            for (slot, row) in rows.iter().enumerate() {
                for lane in 0..STATE_SIZE {
                    assert_eq!(row[lane], columns[lane][slot], "S_{q}[{slot}][{lane}]");
                }
            }
        }
    }

    #[test]
    fn ragged_row_kernels_match_column_references() {
        let mut rng = Rng(0xB17E_A11E);
        for q in [0, F_ROUNDS / 2, N_ROUNDS - 1] {
            let weights = std::array::from_fn(|_| rng.f128());
            let mds = flat_mds(is_full_round(q));
            let reference = std::array::from_fn(|column| {
                let mut value = F128::ZERO;
                for lane in 0..STATE_SIZE {
                    value += weights[lane] * mds[lane][column];
                }
                value
            });
            assert_eq!(column_weights(q, &weights), reference);
        }

        let eq = (0..32).map(|_| rng.f128()).collect::<Vec<_>>();
        let columns = std::array::from_fn(|_| rng.f128());
        let mut lane_tables = std::array::from_fn(|_| vec![F128::ZERO; eq.len()]);
        let mut rows = vec![[F128::ZERO; STATE_SIZE]; eq.len()];
        accumulate_lane_tables(&mut lane_tables, &eq, &columns);
        accumulate_lane_rows(&mut rows, &eq, &columns);
        for (slot, row) in rows.iter().enumerate() {
            for lane in 0..STATE_SIZE {
                assert_eq!(row[lane], lane_tables[lane][slot]);
            }
        }

        let challenge = rng.f128();
        let mut row_scratch = Vec::new();
        let mut folded_rows = rows.clone();
        fold_rows_reusing(&mut folded_rows, &mut row_scratch, challenge);
        for lane in 0..STATE_SIZE {
            fold_in_place(&mut lane_tables[lane], challenge);
        }
        for (slot, row) in folded_rows.iter().enumerate() {
            for lane in 0..STATE_SIZE {
                assert_eq!(row[lane], lane_tables[lane][slot]);
            }
        }
    }

    #[test]
    fn walk_roundtrip_single_and_multi_group() {
        for (w_log, n_groups, seed) in [(0usize, 1usize, 11u64), (4, 1, 12), (5, 2, 13)] {
            let s0 = random_columns(w_log, seed);
            let out = output_columns(&s0);
            let mut rng = Rng(seed ^ 0xFF);
            let groups: Vec<LaneClaimGroup> = (0..n_groups)
                .map(|_| {
                    let point: Vec<F128> = (0..w_log).map(|_| rng.f128()).collect();
                    let values: [F128; STATE_SIZE] =
                        std::array::from_fn(|j| mle_eval(&out[j], &point));
                    LaneClaimGroup { point, values }
                })
                .collect();

            let mut ch_p = FsLaneChallenger::new(b"deep-chain-test");
            let (proof, s0_claim_p) = prove_deep_chain_walk(&s0, &groups, &mut ch_p);

            let mut ch_v = FsLaneChallenger::new(b"deep-chain-test");
            let s0_claim_v = verify_deep_chain_walk(w_log, &groups, &proof, &mut ch_v)
                .unwrap_or_else(|e| panic!("honest walk rejected (w_log={w_log}): {e}"));
            assert_eq!(s0_claim_p, s0_claim_v);
            assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "lockstep");

            // The terminal claim is TRUE against the layer-0 columns.
            for j in 0..STATE_SIZE {
                assert_eq!(
                    mle_eval(&s0[j], &s0_claim_v.point),
                    s0_claim_v.values[j],
                    "terminal claim lane {j}"
                );
            }
        }
    }

    #[test]
    fn multi_instance_walk_roundtrip_and_transcript_lockstep() {
        let w_log = 3;
        let (instances, groups) = multi_walk_fixture(w_log);
        let instance_refs = instances.iter().collect::<Vec<_>>();
        let mut prover_channel = FsLaneChallenger::new(b"deep-chain-multi-test");
        let (proof, prover_terminals) =
            prove_multi_deep_chain_walk(&instance_refs, &groups, &mut prover_channel);

        assert_eq!(proof.layers.len(), N_ROUNDS);
        assert!(proof.layers.iter().all(|layer| {
            layer.round_coeffs.len() == w_log && layer.next_values.len() == instances.len()
        }));
        let mut verifier_channel = FsLaneChallenger::new(b"deep-chain-multi-test");
        let verifier_terminals =
            verify_multi_deep_chain_walk(w_log, &groups, &proof, &mut verifier_channel)
                .expect("honest multi-instance walk");
        assert_eq!(prover_terminals, verifier_terminals);
        assert_eq!(
            prover_channel.sample_f128(),
            verifier_channel.sample_f128(),
            "multi-walk transcript lockstep"
        );
        assert!(multi_walk_terminals_are_honest(
            w_log, &instances, &groups, &proof
        ));
    }

    #[test]
    fn multi_instance_walk_rejects_mutation_swap_and_shape_drift() {
        let w_log = 2;
        let (instances, groups) = multi_walk_fixture(w_log);
        let instance_refs = instances.iter().collect::<Vec<_>>();
        let mut prover_channel = FsLaneChallenger::new(b"deep-chain-multi-test");
        let (proof, _) = prove_multi_deep_chain_walk(&instance_refs, &groups, &mut prover_channel);

        let mut bad_coeff = proof.clone();
        bad_coeff.layers[N_ROUNDS / 2].round_coeffs[1][3] += F128::ONE;
        assert!(!multi_walk_terminals_are_honest(
            w_log, &instances, &groups, &bad_coeff
        ));

        let mut bad_instance = proof.clone();
        bad_instance.layers[1].next_values[1][2] += F128::ONE;
        assert!(!multi_walk_terminals_are_honest(
            w_log,
            &instances,
            &groups,
            &bad_instance
        ));

        let mut swapped = proof.clone();
        swapped.layers[N_ROUNDS / 3].next_values.swap(0, 1);
        assert!(!multi_walk_terminals_are_honest(
            w_log, &instances, &groups, &swapped
        ));

        let mut malformed = proof.clone();
        malformed.layers[0].next_values.pop();
        let mut verifier_channel = FsLaneChallenger::new(b"deep-chain-multi-test");
        assert_eq!(
            verify_multi_deep_chain_walk(w_log, &groups, &malformed, &mut verifier_channel),
            Err(WalkError::Shape)
        );
    }

    #[test]
    fn multi_instance_transcript_binds_group_boundaries() {
        let w_log = 2;
        let (_, groups) = multi_walk_fixture(w_log);
        assert_eq!(groups.iter().map(Vec::len).collect::<Vec<_>>(), [1, 2]);
        let flat = groups.iter().flatten().cloned().collect::<Vec<_>>();
        let repartitioned = vec![flat[..2].to_vec(), flat[2..].to_vec()];

        let mut canonical = FsLaneChallenger::new(b"deep-chain-multi-test");
        absorb_multi_groups(&mut canonical, &groups);
        let canonical_challenge = canonical.sample_f128();
        let mut drifted = FsLaneChallenger::new(b"deep-chain-multi-test");
        absorb_multi_groups(&mut drifted, &repartitioned);
        let drifted_challenge = drifted.sample_f128();
        assert_ne!(
            canonical_challenge, drifted_challenge,
            "instance/group boundary repartition left transcript unchanged"
        );
    }

    #[test]
    fn ragged_multi_instance_roundtrip_lockstep_and_individual_differential() {
        let w_logs = [1usize, 3, 2];
        let max_w_log = *w_logs.iter().max().unwrap();
        let (instances, groups) = ragged_multi_walk_fixture(&w_logs);
        let instance_refs = instances.iter().collect::<Vec<_>>();

        let mut prover_channel = FsLaneChallenger::new(b"deep-chain-ragged-multi-test");
        let (proof, prover_terminals) =
            prove_ragged_multi_deep_chain_walk(&instance_refs, &groups, &mut prover_channel);
        assert!(proof.layers.iter().all(|layer| {
            layer.round_coeffs.len() == max_w_log && layer.next_values.len() == instances.len()
        }));

        let mut verifier_channel = FsLaneChallenger::new(b"deep-chain-ragged-multi-test");
        let verifier_terminals =
            verify_ragged_multi_deep_chain_walk(&w_logs, &groups, &proof, &mut verifier_channel)
                .expect("honest ragged multi-instance walk");
        assert_eq!(prover_terminals, verifier_terminals);
        assert_eq!(
            prover_channel.sample_f128(),
            verifier_channel.sample_f128(),
            "ragged multi-walk transcript lockstep"
        );

        // Differential baseline: each exact same output claim also survives
        // its ordinary native-width walk, and both protocols return claims
        // that discharge against the same unpadded input columns.
        for (instance, (((s0, instance_groups), &w_log), ragged_terminal)) in instances
            .iter()
            .zip(&groups)
            .zip(&w_logs)
            .zip(&verifier_terminals)
            .enumerate()
        {
            assert_eq!(ragged_terminal.point.len(), w_log);
            for lane in 0..STATE_SIZE {
                assert_eq!(
                    mle_eval(&s0[lane], &ragged_terminal.point),
                    ragged_terminal.values[lane],
                    "ragged terminal {instance}, lane {lane}"
                );
            }

            let mut individual_prover = FsLaneChallenger::new(b"deep-chain-ragged-individual-test");
            let (individual_proof, individual_terminal_p) =
                prove_deep_chain_walk(s0, instance_groups, &mut individual_prover);
            let mut individual_verifier =
                FsLaneChallenger::new(b"deep-chain-ragged-individual-test");
            let individual_terminal_v = verify_deep_chain_walk(
                w_log,
                instance_groups,
                &individual_proof,
                &mut individual_verifier,
            )
            .expect("individual differential walk");
            assert_eq!(individual_terminal_p, individual_terminal_v);
            for lane in 0..STATE_SIZE {
                assert_eq!(
                    mle_eval(&s0[lane], &individual_terminal_v.point),
                    individual_terminal_v.values[lane],
                    "individual terminal {instance}, lane {lane}"
                );
            }
        }
    }

    /// Production-shape micro profile for the Link three-child multi-walk.
    /// Claims need not be honest for measuring the prover kernel in a release
    /// build; the regular round-trip tests above cover the authenticated path.
    #[test]
    #[ignore = "production-width performance benchmark"]
    fn ragged_m22_three_child_micro_profile() {
        let w_logs = [14usize, 15, 17];
        let instances = w_logs
            .iter()
            .enumerate()
            .map(|(instance, &w_log)| random_columns(w_log, 0xC011_0000 + instance as u64))
            .collect::<Vec<_>>();
        let mut rng = Rng(0xC011_F5);
        let groups = w_logs
            .iter()
            .map(|&w_log| {
                vec![LaneClaimGroup {
                    point: (0..w_log).map(|_| rng.f128()).collect(),
                    values: std::array::from_fn(|_| rng.f128()),
                }]
            })
            .collect::<Vec<_>>();
        let instance_refs = instances.iter().collect::<Vec<_>>();
        let started = std::time::Instant::now();
        let mut challenger = FsLaneChallenger::new(b"deep-chain-ragged-m22-micro");
        let (proof, terminals) =
            prove_ragged_multi_deep_chain_walk(&instance_refs, &groups, &mut challenger);
        eprintln!(
            "NOIDH deep-chain-ragged-m22-micro elapsed_ms={} layers={} terminals={}",
            started.elapsed().as_millis(),
            proof.layers.len(),
            terminals.len(),
        );
        assert_eq!(proof.layers.len(), N_ROUNDS);
        assert_eq!(terminals.len(), w_logs.len());
    }

    #[test]
    fn ragged_multi_instance_rejects_mutation_swap_and_shape_drift() {
        let w_logs = [1usize, 3];
        let (instances, groups) = ragged_multi_walk_fixture(&w_logs);
        let instance_refs = instances.iter().collect::<Vec<_>>();
        let mut prover_channel = FsLaneChallenger::new(b"deep-chain-ragged-multi-test");
        let (proof, _) =
            prove_ragged_multi_deep_chain_walk(&instance_refs, &groups, &mut prover_channel);

        let honest_terminals = |candidate: &MultiDeepChainWalkProof| {
            let mut verifier = FsLaneChallenger::new(b"deep-chain-ragged-multi-test");
            let Ok(terminals) =
                verify_ragged_multi_deep_chain_walk(&w_logs, &groups, candidate, &mut verifier)
            else {
                return false;
            };
            terminals.iter().zip(&instances).all(|(terminal, s0)| {
                (0..STATE_SIZE)
                    .all(|lane| mle_eval(&s0[lane], &terminal.point) == terminal.values[lane])
            })
        };
        assert!(honest_terminals(&proof));

        let mut bad_coeff = proof.clone();
        bad_coeff.layers[N_ROUNDS / 2].round_coeffs[2][3] += F128::ONE;
        assert!(!honest_terminals(&bad_coeff));

        let mut bad_instance = proof.clone();
        bad_instance.layers[1].next_values[0][2] += F128::ONE;
        assert!(!honest_terminals(&bad_instance));

        let mut swapped = proof.clone();
        swapped.layers[N_ROUNDS / 3].next_values.swap(0, 1);
        assert!(!honest_terminals(&swapped));

        let mut malformed = proof.clone();
        malformed.layers[0].round_coeffs.pop();
        let mut malformed_channel = FsLaneChallenger::new(b"deep-chain-ragged-multi-test");
        assert_eq!(
            verify_ragged_multi_deep_chain_walk(
                &w_logs,
                &groups,
                &malformed,
                &mut malformed_channel,
            ),
            Err(WalkError::Shape)
        );

        // Swapping complete instance metadata is still a different ordered
        // authority.  The original proof cannot be replayed under it.
        let swapped_w_logs = [w_logs[1], w_logs[0]];
        let swapped_groups = vec![groups[1].clone(), groups[0].clone()];
        let mut swapped_channel = FsLaneChallenger::new(b"deep-chain-ragged-multi-test");
        assert!(
            verify_ragged_multi_deep_chain_walk(
                &swapped_w_logs,
                &swapped_groups,
                &proof,
                &mut swapped_channel,
            )
            .is_err()
        );
    }

    #[test]
    fn ragged_multi_transcript_binds_ordered_widths_and_group_counts() {
        let w_logs = [1usize, 3];
        let (_, groups) = ragged_multi_walk_fixture(&w_logs);

        let mut canonical = FsLaneChallenger::new(b"deep-chain-ragged-multi-test");
        absorb_ragged_multi_groups(&mut canonical, &w_logs, &groups);
        let canonical_challenge = canonical.sample_f128();

        let mut width_drift = FsLaneChallenger::new(b"deep-chain-ragged-multi-test");
        absorb_ragged_multi_groups(&mut width_drift, &[3, 1], &groups);
        assert_ne!(canonical_challenge, width_drift.sample_f128());

        let flat = groups.iter().flatten().cloned().collect::<Vec<_>>();
        let repartitioned = vec![flat[..2].to_vec(), flat[2..].to_vec()];
        let mut group_drift = FsLaneChallenger::new(b"deep-chain-ragged-multi-test");
        absorb_ragged_multi_groups(&mut group_drift, &w_logs, &repartitioned);
        assert_ne!(canonical_challenge, group_drift.sample_f128());
    }

    #[test]
    fn ragged_alignment_preserves_degree_eight_bound() {
        let mut rng = Rng(0xDE6E_E8);
        for q in [0usize, N_ROUNDS / 2] {
            let e_base: [F128; STATE_SIZE] = std::array::from_fn(|_| rng.f128());
            let e_delta: [F128; STATE_SIZE] = std::array::from_fn(|_| rng.f128());
            let s_base: [F128; STATE_SIZE] = std::array::from_fn(|_| rng.f128());
            let s_delta: [F128; STATE_SIZE] = std::array::from_fn(|_| rng.f128());
            let native_eval = |t: usize| {
                let t = f128_of_u128(t as u128);
                let e: [F128; STATE_SIZE] =
                    std::array::from_fn(|lane| e_base[lane] + t * e_delta[lane]);
                let s: [F128; STATE_SIZE] =
                    std::array::from_fn(|lane| s_base[lane] + t * s_delta[lane]);
                let terms = layer_terms(q, &s);
                (0..STATE_SIZE).fold(F128::ZERO, |acc, lane| acc + e[lane] * terms[lane])
            };
            let evals = std::array::from_fn(native_eval);
            let coeffs = interpolate(&evals);
            for t in [9usize, 10] {
                assert_eq!(
                    horner(&coeffs, f128_of_u128(t as u128)),
                    native_eval(t),
                    "native-coordinate transition exceeded degree eight"
                );
            }

            let state: [F128; STATE_SIZE] = std::array::from_fn(|_| rng.f128());
            let high_e: [F128; STATE_SIZE] = std::array::from_fn(|_| rng.f128());
            let terms = layer_terms(q, &state);
            let high_evals = std::array::from_fn(|t| {
                let gate = F128::ONE + f128_of_u128(t as u128);
                (0..STATE_SIZE).fold(F128::ZERO, |acc, lane| {
                    acc + high_e[lane] * gate * terms[lane]
                })
            });
            let high_coeffs = interpolate(&high_evals);
            assert!(
                high_coeffs[2..]
                    .iter()
                    .all(|coefficient| *coefficient == F128::ZERO),
                "alignment-only coordinate exceeded affine degree"
            );
        }
    }

    #[test]
    fn ragged_implicit_alignment_matches_explicit_tables() {
        let w_log = 2usize;
        let max_w_log = 4usize;
        let w = 1usize << w_log;
        let max_w = 1usize << max_w_log;
        let mut rng = Rng(0xE7A1_16E0);
        let state = (0..w).map(|_| rng.f128()).collect::<Vec<_>>();
        let claim_point = (0..w_log).map(|_| rng.f128()).collect::<Vec<_>>();
        let aggregate_point = (0..max_w_log).map(|_| rng.f128()).collect::<Vec<_>>();

        // S repeats across every high-bit block; no padded copy is used by
        // the actual prover, but this materialized reference locks the exact
        // coordinate convention down.
        let explicit_state = (0..max_w)
            .map(|index| state[index & (w - 1)])
            .collect::<Vec<_>>();
        assert_eq!(
            mle_eval(&explicit_state, &aggregate_point),
            mle_eval(&state, &aggregate_point[..w_log]),
            "implicit state high-coordinate ignore != explicit repetition"
        );

        // E occupies only the first (all-zero high suffix) block.  Its MLE is
        // exactly low-equality times the product of zero-selecting high gates.
        let low_eq_table = build_eq_table(&claim_point);
        let mut explicit_e = vec![F128::ZERO; max_w];
        explicit_e[..w].copy_from_slice(&low_eq_table);
        let mut high_gate = F128::ONE;
        for &coordinate in &aggregate_point[w_log..] {
            high_gate *= F128::ONE + coordinate;
        }
        assert_eq!(
            mle_eval(&explicit_e, &aggregate_point),
            eq_eval(&claim_point, &aggregate_point[..w_log]) * high_gate,
            "implicit E high gate != explicit first-block zero extension"
        );
    }

    /// A forged output claim yields a walk whose terminal claim is FALSE
    /// against the true input columns — the discharge (committed-column
    /// opening) is what catches it, exactly as designed.
    #[test]
    fn forged_output_claim_shifts_the_terminal_claim() {
        let w_log = 4;
        let s0 = random_columns(w_log, 21);
        let out = output_columns(&s0);
        let mut rng = Rng(0x21FF);
        let point: Vec<F128> = (0..w_log).map(|_| rng.f128()).collect();
        let mut values: [F128; STATE_SIZE] = std::array::from_fn(|j| mle_eval(&out[j], &point));
        values[2] += F128::ONE;
        let groups = [LaneClaimGroup { point, values }];

        let mut ch_p = FsLaneChallenger::new(b"deep-chain-test");
        let Some((proof, _)) = crate::catch_expected_prover_rejection(|| {
            prove_deep_chain_walk(&s0, &groups, &mut ch_p)
        }) else {
            return;
        };
        let mut ch_v = FsLaneChallenger::new(b"deep-chain-test");
        match verify_deep_chain_walk(w_log, &groups, &proof, &mut ch_v) {
            // The layer chain catches the forged batched claim directly...
            Err(_) => {}
            // ...or the surviving terminal claim must be FALSE against the
            // true input columns, so the committed-column discharge kills it.
            Ok(claim) => {
                let honest =
                    (0..STATE_SIZE).all(|j| mle_eval(&s0[j], &claim.point) == claim.values[j]);
                assert!(
                    !honest,
                    "forged output claim survived to an honest terminal"
                );
            }
        }
    }

    /// Wire-level mutations: flipping any round coefficient or next-value
    /// lane in any layer must be rejected (or shift the terminal claim off
    /// the true columns — either way the proof chain cannot survive).
    #[test]
    fn walk_rejects_wire_mutations() {
        let w_log = 3;
        let s0 = random_columns(w_log, 31);
        let out = output_columns(&s0);
        let mut rng = Rng(0x31AA);
        let point: Vec<F128> = (0..w_log).map(|_| rng.f128()).collect();
        let values: [F128; STATE_SIZE] = std::array::from_fn(|j| mle_eval(&out[j], &point));
        let groups = [LaneClaimGroup { point, values }];

        let mut ch_p = FsLaneChallenger::new(b"deep-chain-test");
        let (proof, _) = prove_deep_chain_walk(&s0, &groups, &mut ch_p);

        let mut survivors = Vec::new();
        for li in [0usize, 1, N_ROUNDS / 2, N_ROUNDS - 1] {
            for round in 0..w_log {
                for coeff in 0..WALK_DEGREE {
                    let mut bad = proof.clone();
                    bad.layers[li].round_coeffs[round][coeff] += F128::ONE;
                    let mut ch = FsLaneChallenger::new(b"deep-chain-test");
                    match verify_deep_chain_walk(w_log, &groups, &bad, &mut ch) {
                        Err(_) => {}
                        Ok(claim) => {
                            let honest = (0..STATE_SIZE)
                                .all(|j| mle_eval(&s0[j], &claim.point) == claim.values[j]);
                            if honest {
                                survivors.push((li, round, coeff));
                            }
                        }
                    }
                }
            }
            for lane in 0..STATE_SIZE {
                let mut bad = proof.clone();
                bad.layers[li].next_values[lane] += F128::ONE;
                let mut ch = FsLaneChallenger::new(b"deep-chain-test");
                match verify_deep_chain_walk(w_log, &groups, &bad, &mut ch) {
                    Err(_) => {}
                    Ok(claim) => {
                        let honest = (0..STATE_SIZE)
                            .all(|j| mle_eval(&s0[j], &claim.point) == claim.values[j]);
                        if honest {
                            survivors.push((li, 99, lane));
                        }
                    }
                }
            }
        }
        assert!(
            survivors.is_empty(),
            "walk mutation survivors: {survivors:?}"
        );
    }

    #[test]
    fn walk_rejects_shape_mismatches() {
        let w_log = 3;
        let s0 = random_columns(w_log, 41);
        let out = output_columns(&s0);
        let mut rng = Rng(0x41BB);
        let point: Vec<F128> = (0..w_log).map(|_| rng.f128()).collect();
        let values: [F128; STATE_SIZE] = std::array::from_fn(|j| mle_eval(&out[j], &point));
        let groups = [LaneClaimGroup { point, values }];
        let mut ch_p = FsLaneChallenger::new(b"deep-chain-test");
        let (proof, _) = prove_deep_chain_walk(&s0, &groups, &mut ch_p);

        let mut short = proof.clone();
        short.layers.pop();
        let mut ch = FsLaneChallenger::new(b"deep-chain-test");
        assert_eq!(
            verify_deep_chain_walk(w_log, &groups, &short, &mut ch),
            Err(WalkError::Shape)
        );

        let mut ch = FsLaneChallenger::new(b"deep-chain-test");
        assert_eq!(
            verify_deep_chain_walk(w_log + 1, &groups, &proof, &mut ch),
            Err(WalkError::Shape)
        );
    }
}
