// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Killshot verifiers as arithmetic F128 traces — the verifier-replay and
//! discharge slots of the recursive acceptance proof.
//!
//! Every `*_trace` function in this tree is a **line-by-line transliteration**
//! of its native `verify_*` / `discharge_*_native` reference (hard rule):
//! same absorb/squeeze order on the raw killshot channel
//! ([`RawChannelTrace`] — the in-circuit mirror of
//! `noid_poseidon2b::channel::Poseidon2bChannel`), same checks, no
//! reorderings. Any edit to a native verifier MUST change its trace twin (and
//! `tier1_shape_stats.rs`) in the same commit.
//!
//! ## How native control flow maps into the trace
//!
//! - **Shape checks** (`proof.rounds.len() != n`, degree bounds, claim
//!   counts): the trace has a FIXED shape (fixed-shape invariant) — a proof of the
//!   wrong shape is unrepresentable; the `alloc` constructors assert. Value
//!   mutations inside an honest shape are what the auto-mutator exercises.
//! - **Value checks** (`return None` on a mismatched field equation): a
//!   [`pin_zero`] row — the trace becomes unsatisfiable exactly where native
//!   rejects (replay-completeness invariant).
//! - **Basis**: circuit wires carry flat (GCM) images of tower values
//!   (`φ = tower_to_flat_u128`); XOR commutes with φ and every tower mul is
//!   an F128 mul of the flat images, so replayed verifier algebra is
//!   value-for-value the native algebra. Public tower constants enter via
//!   [`flat_of`] / `flat_const`.
//! - **Association of products**: where a native helper evaluates a public
//!   polynomial by a different-but-equal strategy (eq tensors instead of
//!   per-index products), the trace may share partial products — field
//!   algebra is associative, the VALUE is bit-identical and the FS schedule
//!   is untouched. The FS schedule itself is never restructured.

pub mod accepted_claim_batch;
pub mod accepted_claim_hash;
pub mod action_compaction;
pub mod action_surface;
pub mod batch_eval;
pub mod block_spine;
pub mod deep_chain;
pub mod development_allocation;
pub mod exact_state;
pub mod fee_arithmetic;
pub mod fri_pcs;
pub mod integer_program;
pub mod matrix_fold;
pub mod merkle_path;
pub mod native_assets;
pub mod paged_spend;
pub mod paired_merkle_update;
pub mod permutation_network;
pub mod public_arithmetic;
pub mod r_pcs_region;
pub mod region_source_binding;
pub mod region_source_binding_c1;
pub mod segment_compaction;
pub mod self_verify;
pub mod tx_body_spine;
pub mod tx_epoch;
pub mod zk_affine_fold;
pub mod zk_affine_tail;
pub mod zk_auth_composition;
pub mod zk_auth_grind;
pub mod zk_auth_nonce;
pub mod zk_auth_terminal;
pub mod zk_auth_transcript_cells;
pub mod zk_authorization_candidate;
mod zk_authorization_region;
pub mod zk_mlecheck;
pub mod zk_owner_verifier;
pub mod zk_phase_a;
pub mod zk_phase_b_composition;
pub mod zk_phase_b_query;
pub mod zk_phase_b_upper_link;
pub mod zk_post_claim_relation;
pub mod zk_query_carriers;
pub mod zk_split_bridge;

use std::cell::RefCell;
use std::collections::HashMap;

use noid_core::{Block128, Block256};

pub use noid_ivc_core::field::{F128, F256};
pub use noid_ivc_core::field_circuit::{
    flat_const, poseidon2b_permute, ExtExpr, FieldR1csBuilder, LinExpr, RawChannelTrace, Wire,
};

/// φ-map a tower value into the circuit (flat) basis.
#[inline]
pub fn flat_of(v: Block128) -> F128 {
    flat_const(v.0)
}

/// Allocate a witness wire carrying the flat image of a tower value.
#[inline]
pub fn alloc_block(b: &mut FieldR1csBuilder, v: Block128) -> LinExpr {
    LinExpr::from_wire(b.alloc_f128(flat_of(v)))
}

/// Allocate a witness wire per element.
pub fn alloc_blocks(b: &mut FieldR1csBuilder, vs: &[Block128]) -> Vec<LinExpr> {
    vs.iter().map(|&v| alloc_block(b, v)).collect()
}

#[inline]
pub fn flat_of_ext(v: Block256) -> F256 {
    F256::from_tower(v)
}

#[inline]
pub fn alloc_block256(b: &mut FieldR1csBuilder, v: Block256) -> ExtExpr {
    let value = flat_of_ext(v);
    ExtExpr::new(
        LinExpr::from_wire(b.alloc_f128(value.lo)),
        LinExpr::from_wire(b.alloc_f128(value.hi)),
    )
}

pub fn alloc_blocks256(b: &mut FieldR1csBuilder, values: &[Block256]) -> Vec<ExtExpr> {
    values
        .iter()
        .map(|&value| alloc_block256(b, value))
        .collect()
}

#[inline]
pub fn const_block256(v: Block256) -> ExtExpr {
    ExtExpr::constant(flat_of_ext(v))
}

/// Constant (public, build-time) tower value as an expression.
#[inline]
pub fn const_block(v: Block128) -> LinExpr {
    LinExpr::constant(flat_of(v))
}

/// Assert `expr == 0` (1 wire). The trace twin of a native
/// `if lhs != rhs { return None; }` check, called with `lhs + rhs`
/// (subtraction == addition in char 2).
#[inline]
pub fn pin_zero(b: &mut FieldR1csBuilder, expr: &LinExpr) {
    PIN_GATES.with(|gates| {
        let gates = gates.borrow();
        if b.uses_fused_boolean_pins() {
            if let Some(index) = gates.iter().position(|gate| !gate.is_const()) {
                let mut remaining = expr.clone();
                for (other, gate) in gates.iter().enumerate() {
                    if other != index {
                        remaining = mul(b, gate, &remaining);
                    }
                }
                if remaining.is_const() && remaining.constant == F128::ZERO {
                    b.pin_f128(&remaining, F128::ZERO);
                } else {
                    b.pin_boolean_gated_zero(&gates[index], &remaining);
                }
                return;
            }
        }
        let mut gated = expr.clone();
        for gate in gates.iter() {
            gated = mul(b, gate, &gated);
        }
        b.pin_f128(&gated, F128::ZERO);
    });
}

thread_local! {
    /// Composition-only conditional relation scope.  The primitive verifier
    /// twins remain unchanged: every native rejection still reaches
    /// [`pin_zero`], while a recursive relation may select its exact base arm
    /// by multiplying those rejection equations by one authenticated boolean.
    /// The scope is thread-local because matrix builders run in parallel.
    static PIN_GATES: RefCell<Vec<LinExpr>> = const { RefCell::new(Vec::new()) };
}

struct PinGateGuard;

impl Drop for PinGateGuard {
    fn drop(&mut self) {
        PIN_GATES.with(|gates| {
            let removed = gates.borrow_mut().pop();
            debug_assert!(removed.is_some(), "pin-gate stack underflow");
        });
    }
}

/// Run one verifier-composition arm under `gate`.  This does not alter any
/// transcript or primitive parameter: it only turns each native rejection
/// equation `e = 0` into `gate * e = 0`.  Callers must separately constrain
/// `gate` to a boolean and bind the complementary base relation.
pub(crate) fn with_pin_gate<R>(gate: &LinExpr, f: impl FnOnce() -> R) -> R {
    PIN_GATES.with(|gates| gates.borrow_mut().push(gate.clone()));
    let _guard = PinGateGuard;
    f()
}

/// Assert two expressions are equal.
#[inline]
pub fn pin_eq(b: &mut FieldR1csBuilder, lhs: &LinExpr, rhs: &LinExpr) {
    pin_zero(b, &lhs.add(rhs));
}

#[inline]
pub fn pin_zero_ext(b: &mut FieldR1csBuilder, expr: &ExtExpr) {
    pin_zero(b, &expr.lo);
    pin_zero(b, &expr.hi);
}

#[inline]
pub fn pin_eq_ext(b: &mut FieldR1csBuilder, lhs: &ExtExpr, rhs: &ExtExpr) {
    pin_zero_ext(b, &lhs.add(rhs));
}

/// Allocate a GF(2^256) inverse witness and constrain `value * inverse = 1`.
///
/// The extension element occupies two base-field wires, its Karatsuba
/// product occupies three, and the two coordinate pins occupy two more.
/// Callers must reject zero before invoking this helper.
#[inline]
pub fn constrain_nonzero_ext(b: &mut FieldR1csBuilder, value: &ExtExpr) {
    let inverse_value = value.eval(b.values()).inv();
    let inverse = ExtExpr::new(
        LinExpr::from_wire(b.alloc_f128(inverse_value.lo)),
        LinExpr::from_wire(b.alloc_f128(inverse_value.hi)),
    );
    let product = mul_ext(b, value, &inverse);
    pin_eq_ext(b, &product, &ExtExpr::one());
}

/// One multiplication, returned as an expression. Constant operands fold:
/// multiplying by a build-time constant is F128-linear (`scale`), and two
/// constants multiply at build time — zero constraint rows either way, with
/// a value bit-identical to the allocated product (the association-of-
/// products allowance), so transcripts and replays are unaffected.
#[inline]
pub fn mul(b: &mut FieldR1csBuilder, x: &LinExpr, y: &LinExpr) -> LinExpr {
    if y.is_const() {
        return x.scale(y.constant);
    }
    if x.is_const() {
        return y.scale(x.constant);
    }
    LinExpr::from_wire(b.mul(x, y))
}

#[inline]
pub fn mul_ext(b: &mut FieldR1csBuilder, x: &ExtExpr, y: &ExtExpr) -> ExtExpr {
    if let Some(value) = y.constant_value() {
        return x.scale_ext(value);
    }
    if let Some(value) = x.constant_value() {
        return y.scale_ext(value);
    }
    if y.hi.is_const() && y.hi.constant == F128::ZERO {
        return mul_ext_base(b, x, &y.lo);
    }
    if x.hi.is_const() && x.hi.constant == F128::ZERO {
        return mul_ext_base(b, y, &x.lo);
    }
    if x == y {
        return b.square_f256(x);
    }
    b.mul_f256(x, y)
}

#[inline]
pub fn mul_ext_base(b: &mut FieldR1csBuilder, value: &ExtExpr, scalar: &LinExpr) -> ExtExpr {
    if scalar.is_const() {
        return value.scale_base(scalar.constant);
    }
    ExtExpr::new(mul(b, &value.lo, scalar), mul(b, &value.hi, scalar))
}

/// Four-multiplication addition-chain for `x^7` over GF(2^256).
#[inline]
pub fn pow7_ext(b: &mut FieldR1csBuilder, value: &ExtExpr) -> ExtExpr {
    let square = mul_ext(b, value, value);
    let cube = mul_ext(b, &square, value);
    let sixth = mul_ext(b, &cube, &cube);
    mul_ext(b, &sixth, value)
}

/// Extension-field equality tensor in little-endian Boolean-index order.
/// Every split after the first materializes two GF(2^256) products; the
/// first split is linear because the initial tensor entry is one.
pub fn eq_ind_partial_eval_ext_trace(b: &mut FieldR1csBuilder, point: &[ExtExpr]) -> Vec<ExtExpr> {
    let mut result = vec![ExtExpr::one()];
    for r_i in point {
        let len = result.len();
        for j in 0..len {
            let prod = mul_ext(b, &result[j], r_i);
            result[j] = result[j].add(&prod);
            result.push(prod);
        }
    }
    result
}

pub fn evaluate_slice_ext_trace(
    b: &mut FieldR1csBuilder,
    table: &[ExtExpr],
    point: &[ExtExpr],
) -> ExtExpr {
    assert_eq!(table.len(), 1usize << point.len());
    let mut scratch = table.to_vec();
    for challenge in point.iter().rev() {
        let half = scratch.len() / 2;
        for index in 0..half {
            let delta = scratch[index].add(&scratch[index + half]);
            scratch[index] = scratch[index].add(&mul_ext(b, challenge, &delta));
        }
        scratch.truncate(half);
    }
    scratch.pop().expect("nonempty extension MLE table")
}

/// Trace twin of `noid_core::mle::eq::eq_ind` for two expression points:
/// `Π (1 + x_i + y_i)` (the char-2 form of `x·y + (1−x)(1−y)`).
pub fn eq_ind_trace(b: &mut FieldR1csBuilder, x: &[LinExpr], y: &[LinExpr]) -> LinExpr {
    b.eq_eval_trace(x, y)
}

/// Trace twin of `noid_core::mle::eq::eq_ind_partial_eval`: the tensor
/// `(1−r_0, r_0) ⊗ … ⊗ (1−r_{n−1}, r_{n−1})` of length `2^n`, bit `i` of the
/// index ↔ `point[i]`. Costs `2^n − 1` multiplications.
pub fn eq_ind_partial_eval_trace(b: &mut FieldR1csBuilder, point: &[LinExpr]) -> Vec<LinExpr> {
    let mut result = vec![LinExpr::constant(F128::ONE)];
    for r_i in point {
        let len = result.len();
        for j in 0..len {
            let prod = mul(b, &result[j], r_i);
            result[j] = result[j].add(&prod); // val − val·r == val + val·r
            result.push(prod);
        }
    }
    result
}

/// Trace twin of `noid_core::mle::evaluate::evaluate_slice` for an
/// expression table at an expression point: `Σ_x tab[x] · eq(x, r)` via the
/// eq tensor (same value as the native highest-var fold).
pub fn evaluate_slice_trace(
    b: &mut FieldR1csBuilder,
    tab: &[LinExpr],
    point: &[LinExpr],
) -> LinExpr {
    assert_eq!(tab.len(), 1usize << point.len());
    let eq = eq_ind_partial_eval_trace(b, point);
    let mut acc = LinExpr::zero();
    for (t, e) in tab.iter().zip(eq.iter()) {
        acc = acc.add(&mul(b, t, e));
    }
    acc
}

/// Memoized `eq(boolean-index, r)` products over one challenge point `r` —
/// the trace twin of `batch_eval::eq_at_boolean_index`. Native multiplies the
/// per-bit factors `r_b` / `1 + r_b` left to right; the cache shares prefix
/// products across indices (associativity — same value), which is what makes
/// large public linear relations (spine chain claims, Merkle path chains)
/// affordable in-trace.
pub struct BooleanPointEqCache {
    r: Vec<LinExpr>,
    /// (depth, index & ((1<<depth)−1)) → product of the first `depth` factors.
    memo: HashMap<(usize, usize), LinExpr>,
}

impl BooleanPointEqCache {
    pub fn new(r: &[LinExpr]) -> Self {
        Self {
            r: r.to_vec(),
            memo: HashMap::new(),
        }
    }

    fn factor(&self, bit: usize, set: bool) -> LinExpr {
        if set {
            self.r[bit].clone()
        } else {
            self.r[bit].add_const(F128::ONE)
        }
    }

    /// `eq` at the boolean point whose bit `b` is `(index >> b) & 1`, over
    /// all `n = r.len()` variables.
    pub fn eq_at_index(&mut self, b: &mut FieldR1csBuilder, index: usize) -> LinExpr {
        let n = self.r.len();
        assert!(n >= 1);
        assert!(index < (1usize << n));
        self.prefix(b, index, n)
    }

    fn prefix(&mut self, b: &mut FieldR1csBuilder, index: usize, depth: usize) -> LinExpr {
        let key = (depth, index & ((1usize << depth) - 1));
        if let Some(e) = self.memo.get(&key) {
            return e.clone();
        }
        let expr = if depth == 1 {
            self.factor(0, index & 1 == 1)
        } else {
            let below = self.prefix(b, index, depth - 1);
            let f = self.factor(depth - 1, (index >> (depth - 1)) & 1 == 1);
            mul(b, &below, &f)
        };
        self.memo.insert(key, expr.clone());
        expr
    }
}

/// Enforce that `expr` (the flat image `φ(v)` of a tower value `v`) carries
/// a value whose TOWER bit pattern fits in `n_bits` integer bits. Because φ
/// is F2-linear, `φ(v) = Σ_i bit_i(v) · φ(2^i)` — so allocating the tower
/// bits as booleans and pinning the φ-mapped power sum against the wire
/// forces every tower bit above `n_bits − 1` to zero. Used to make native
/// implicit type bounds (u64 amounts, u32 slots) explicit in-trace.
/// Returns the bit wires (LSB-first, tower bit order).
pub fn range_check_bits(b: &mut FieldR1csBuilder, expr: &LinExpr, n_bits: usize) -> Vec<Wire> {
    use noid_core::hardware::flat_to_tower_u128;
    assert!(n_bits <= 128);
    let flat = expr.eval(b.values());
    let tower = flat_to_tower_u128((flat.lo as u128) | ((flat.hi as u128) << 64));
    let bits: Vec<Wire> = (0..n_bits)
        .map(|i| b.alloc_bool((tower >> i) & 1 == 1))
        .collect();
    let mut sum = LinExpr::zero();
    for (i, bit) in bits.iter().enumerate() {
        sum = sum.add(&LinExpr::from_wire(*bit).scale(flat_const(1u128 << i)));
    }
    pin_zero(b, &sum.add(expr));
    bits
}

/// `a + c` as an unsigned INTEGER over `n_bits` tower bits.
///
/// Both operands are range-checked and a ripple-carry full adder reconstructs
/// the sum. The final carry is pinned to zero, so this is integer addition with
/// no overflow rather than F128/XOR addition.
pub fn integer_add_no_overflow(
    b: &mut FieldR1csBuilder,
    a: &LinExpr,
    c: &LinExpr,
    n_bits: usize,
) -> LinExpr {
    assert!((1..=128).contains(&n_bits));
    let a_bits = range_check_bits(b, a, n_bits);
    let c_bits = range_check_bits(b, c, n_bits);
    let mut carry = LinExpr::zero();
    let mut terms: Vec<LinExpr> = Vec::with_capacity(n_bits);
    for i in 0..n_bits {
        let ai = LinExpr::from_wire(a_bits[i]);
        let ci = LinExpr::from_wire(c_bits[i]);
        // sum_i = a_i XOR c_i XOR carry_i.
        let sum_i = ai.add(&ci).add(&carry);
        terms.push(sum_i.scale(flat_const(1u128 << i)));
        // carry_{i+1} = a_i*c_i + carry_i*(a_i XOR c_i). The two products
        // cannot both be one, so addition in characteristic two is the OR.
        let ai_ci = mul(b, &ai, &ci);
        let carry_axc = mul(b, &carry, &ai.add(&ci));
        carry = ai_ci.add(&carry_axc);
    }
    pin_zero(b, &carry);
    terms
        .into_iter()
        .fold(LinExpr::zero(), |sum, term| sum.add(&term))
}

/// Strict unsigned `a < b` over two already range-checked bit
/// decompositions (LSB-first, same width) as a boolean-valued expression:
/// MSB-first borrow fold. ~3 multiplications per bit.
pub fn lt_strict_expr(b: &mut FieldR1csBuilder, a_bits: &[Wire], b_bits: &[Wire]) -> LinExpr {
    assert_eq!(a_bits.len(), b_bits.len());
    assert!(!a_bits.is_empty());
    let mut acc_lt = LinExpr::zero();
    let mut acc_eq = LinExpr::constant(F128::ONE);
    for (a, bb) in a_bits.iter().rev().zip(b_bits.iter().rev()) {
        let a_e = LinExpr::from_wire(*a);
        let b_e = LinExpr::from_wire(*bb);
        // (¬a_i)·b_i — this bit decides if all higher bits are equal.
        let not_a_and_b = mul(b, &a_e.add_const(F128::ONE), &b_e);
        acc_lt = acc_lt.add(&mul(b, &acc_eq, &not_a_and_b));
        // eq_i = 1 + a_i + b_i (char-2 bit equality).
        acc_eq = mul(b, &acc_eq, &a_e.add(&b_e).add_const(F128::ONE));
    }
    acc_lt
}

/// Enforce strict unsigned `a < b`: pin the less-than accumulator to 1.
pub fn pin_lt_strict(b: &mut FieldR1csBuilder, a_bits: &[Wire], b_bits: &[Wire]) {
    let acc_lt = lt_strict_expr(b, a_bits, b_bits);
    pin_zero(b, &acc_lt.add_const(F128::ONE));
}

/// A univariate round polynomial in transcript form, allocated from a native
/// `CompressedRoundPolynomial<Block128>` (`noid_core::sumcheck`): the linear
/// coefficient is omitted on the wire and reconstructed from the running
/// sumcheck claim. The coefficient count is part of the trace shape:
/// native's degree check becomes an alloc-time assertion (an off-shape
/// proof is unrepresentable).
pub struct RoundPolyTrace {
    /// Wire coefficients `[c_0, c_2, …, c_d]`.
    pub coeffs_no_linear: Vec<LinExpr>,
}

impl RoundPolyTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &noid_core::sumcheck::CompressedRoundPolynomial<Block128>,
        expected_degree: usize,
    ) -> Self {
        assert_eq!(
            native.coeffs_no_linear.len(),
            expected_degree,
            "round polynomial off the frozen trace shape"
        );
        Self {
            coeffs_no_linear: alloc_blocks(b, &native.coeffs_no_linear),
        }
    }

    /// Trace twin of `CompressedRoundPolynomial::reconstruct` followed by
    /// `RoundPolynomial::evaluate`: `c_1 = claim + Σ_{i≥2} c_i` is affine
    /// (free), so the round identity `p(0) + p(1) = claim` holds by
    /// construction; Horner still spends `degree` multiplications.
    pub fn evaluate_reconstructed(
        &self,
        b: &mut FieldR1csBuilder,
        claim: &LinExpr,
        x: &LinExpr,
    ) -> LinExpr {
        let mut c1 = claim.clone();
        for c in &self.coeffs_no_linear[1..] {
            c1 = c1.add(c);
        }
        let mut coeffs = Vec::with_capacity(self.coeffs_no_linear.len() + 1);
        coeffs.push(self.coeffs_no_linear[0].clone());
        coeffs.push(c1);
        coeffs.extend_from_slice(&self.coeffs_no_linear[1..]);
        b.horner_eval(&coeffs, x)
    }

    /// Absorb the wire coefficients in native order
    /// (`for &c in &wire.coeffs_no_linear`).
    pub fn absorb_coeffs(&self, b: &mut FieldR1csBuilder, ch: &mut RawChannelTrace) {
        for c in &self.coeffs_no_linear {
            ch.absorb(b, c);
        }
    }
}

/// Reduced claim `(point, value)` as expressions — the trace twin of
/// `noid_gkr::batch_eval::BatchEvalReduction`.
#[derive(Clone)]
pub struct BatchEvalReductionTrace {
    pub point: Vec<LinExpr>,
    pub value: LinExpr,
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Evaluate an expression against a builder's current witness and map
    /// back to the tower basis for comparison with native values.
    pub fn tower_value(b: &FieldR1csBuilder, e: &LinExpr) -> Block128 {
        use noid_core::hardware::flat_to_tower_u128;
        let f = e.eval(b.values());
        let flat = (f.lo as u128) | ((f.hi as u128) << 64);
        Block128(flat_to_tower_u128(flat))
    }

    pub fn assert_expr_is(b: &FieldR1csBuilder, e: &LinExpr, native: Block128, what: &str) {
        assert_eq!(tower_value(b, e), native, "{what} diverged from native");
    }

    /// Evaluate a symbolic C1 challenge-field expression and map both
    /// coordinates back to the native tower basis.
    pub fn tower_value_ext(b: &FieldR1csBuilder, e: &ExtExpr) -> Block256 {
        e.eval(b.values()).to_tower()
    }

    pub fn assert_ext_expr_is(b: &FieldR1csBuilder, e: &ExtExpr, native: Block256, what: &str) {
        assert_eq!(tower_value_ext(b, e), native, "{what} diverged from native");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::mle::eq::{eq_ind, eq_ind_partial_eval};
    use noid_core::TowerField;

    fn rand_blocks(seed: u64, n: usize) -> Vec<Block128> {
        let mut s = seed as u128;
        (0..n)
            .map(|_| {
                s = s
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(0xDEAD_BEEF);
                Block128::from(s)
            })
            .collect()
    }

    #[test]
    fn eq_partial_eval_trace_matches_native() {
        for n in [1usize, 3, 6] {
            let point = rand_blocks(7 + n as u64, n);
            let mut b = FieldR1csBuilder::new();
            let exprs = alloc_blocks(&mut b, &point);
            let tensor = eq_ind_partial_eval_trace(&mut b, &exprs);
            let native = eq_ind_partial_eval::<Block128>(&point);
            assert_eq!(tensor.len(), native.len());
            for (e, nv) in tensor.iter().zip(native.iter()) {
                test_support::assert_expr_is(&b, e, *nv, "eq tensor entry");
            }
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }
    }

    #[test]
    fn boolean_point_eq_cache_matches_native() {
        let n = 9usize;
        let r = rand_blocks(99, n);
        let mut b = FieldR1csBuilder::new();
        let r_exprs = alloc_blocks(&mut b, &r);
        let mut cache = BooleanPointEqCache::new(&r_exprs);
        for index in [0usize, 1, 2, 5, 63, 200, 511, 300, 5, 200] {
            let e = cache.eq_at_index(&mut b, index);
            let point: Vec<Block128> = (0..n)
                .map(|bit| {
                    if (index >> bit) & 1 == 1 {
                        Block128::ONE
                    } else {
                        Block128::ZERO
                    }
                })
                .collect();
            let native = eq_ind(&point, &r);
            test_support::assert_expr_is(&b, &e, native, "boolean eq");
        }
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
    }

    #[test]
    fn evaluate_slice_trace_matches_native() {
        let n = 5usize;
        let tab = rand_blocks(3, 1 << n);
        let point = rand_blocks(4, n);
        let mut b = FieldR1csBuilder::new();
        let tab_e = alloc_blocks(&mut b, &tab);
        let point_e = alloc_blocks(&mut b, &point);
        let got = evaluate_slice_trace(&mut b, &tab_e, &point_e);
        let native = noid_core::mle::evaluate::evaluate_slice(&tab, &point);
        test_support::assert_expr_is(&b, &got, native, "evaluate_slice");
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
    }

    fn gated_equality_matrix(active: bool) -> (noid_ivc_core::field_r1cs::FieldR1cs, Vec<F128>) {
        let mut b = FieldR1csBuilder::new();
        let gate = LinExpr::from_wire(b.alloc_bool(active));
        let wrong = LinExpr::from_wire(b.alloc_f128(F128::ONE));
        with_pin_gate(&gate, || pin_eq(&mut b, &wrong, &LinExpr::zero()));
        b.build()
    }

    #[test]
    fn composition_pin_gate_is_matrix_fixed_and_fail_closed_when_live() {
        let (inactive_matrix, inactive_witness) = gated_equality_matrix(false);
        let (active_matrix, active_witness) = gated_equality_matrix(true);
        assert_eq!(
            inactive_matrix.structural_statement_digest(),
            active_matrix.structural_statement_digest(),
            "selector value must not change the relation matrix",
        );
        assert!(inactive_matrix.satisfies(&inactive_witness));
        assert!(!active_matrix.satisfies(&active_witness));
    }
}

pub(crate) mod scheduled_allocation;
