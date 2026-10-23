//! `FieldR1csBuilder` and the base in-circuit gadgets of the acceptance-
//! proof trace (the arithmetic F128 replay of the block verifiers).
//!
//! The builder emits a satisfiable [`FieldR1cs`] (option A: F128 coefficients
//! in the sparse matrices, `C = I`) together with its witness. Linear
//! combinations are **symbolic** ([`LinExpr`]) — they live in the matrix rows
//! of the multiplication constraints that consume them and cost no
//! constraints of their own. Only multiplications (and explicit pins /
//! allocations) materialize witness wires.
//!
//! ## Basis convention (load-bearing)
//!
//! Circuit wires carry values in the **flat (GCM) basis** of GF(2^128), which
//! is bit-for-bit the `noid_ivc_core` [`F128`] field (`clmul_gcm` ==
//! `F128::mul` on the same u128 layout — pinned by test). Native reference
//! objects (Poseidon2b states, killshot transcripts) live in the **tower
//! basis** (`Block128`); they map into the circuit through the F2-linear
//! isomorphism `noid_core::hardware::tower_to_flat_u128` and back via
//! `flat_to_tower_u128`. Addition (XOR) commutes with the map; every tower
//! multiplication corresponds to an F128 multiplication of the flat images.
//! The Poseidon2b round constants and MDS coefficients are φ-mapped once into
//! static tables. This matches the native permutation itself, which already
//! evaluates in the flat basis internally (`noid_poseidon2b`'s
//! `permute_mut`).
//!
//! ## Gadget inventory (constraints, option A)
//!
//! - [`FieldR1csBuilder::pow7`] — 4
//! - [`poseidon2b_permute`] — 360 (8 full rounds × 4 lanes + 58 partial, ×4
//!   muls per S-box; all MDS/RC layers symbolic)
//! - [`FieldR1csBuilder::horner_eval`] — deg
//! - [`FieldR1csBuilder::eq_eval_trace`] — n − 1 (n ≥ 1)
//! - [`FsChannelTrace`] — 360 per sponge permutation; the op schedule is the
//!   [`crate::challenger::FsLaneChallenger`] lane protocol, one lane-affine
//!   absorb per element, no byte splitting.
//! - [`FsChannelTrace::verify_pow_trace`] — grind-by-squeeze: 2 transcript
//!   permutations (absorb pair + squeeze flush) + (128 − bits) boolean
//!   wires + 1 pin.

use crate::challenger::{
    fs_c1_lane_iv_flat, fs_lane_iv_flat, fs_op_lane, fs_pack_bytes_lanes, fs_pad_lane_flat,
    Challenger, FsLaneChallenger, FS_KIND_SCALAR, FS_KIND_SLICE, FS_KIND_WIDE_SCALAR,
    FS_KIND_WIDE_SLICE, FS_OP_BYTES, FS_OP_DOMAIN, FS_OP_LABEL, FS_OP_OBSERVE, FS_OP_POW,
    FS_OP_SQUEEZE,
};
use crate::deep_chain::schedule::{flat_of_tower_u128, DuplexLayout, LaneSource};
use crate::field::{F128, F256};
use crate::field_r1cs::{FieldR1cs, SparseFieldMatrix};
use noid_core::hardware::tower_to_flat_u128;
use noid_poseidon2b::native::permutation::{
    F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};
use std::sync::atomic::{AtomicU64, Ordering};

#[inline]
pub fn f128_from_u128(v: u128) -> F128 {
    F128 {
        lo: v as u64,
        hi: (v >> 64) as u64,
    }
}

#[inline]
pub fn f128_to_u128(v: F128) -> u128 {
    (v.lo as u128) | ((v.hi as u128) << 64)
}

/// φ-map a tower-basis constant into the circuit (flat) basis.
#[inline]
pub fn flat_const(tower: u128) -> F128 {
    f128_from_u128(tower_to_flat_u128(tower))
}

// ---------------------------------------------------------------------------
// Wires and symbolic linear expressions
// ---------------------------------------------------------------------------

/// Index of a materialized witness element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wire(pub u32);

/// Linear authority to replace one explicitly deferred free witness value.
///
/// The slot is deliberately neither `Clone` nor serializable.  It is branded
/// to the builder that allocated it, can be consumed only once, and cannot be
/// constructed for an already-existing wire.  This keeps staged witness
/// assembly from growing an arbitrary witness-mutation API.
#[must_use = "a deferred witness slot must be sealed before the builder can finish"]
pub struct DeferredWitnessSlot {
    builder_brand: u64,
    wire: Wire,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeferredWitnessSlotError {
    WrongBuilder,
    AlreadySealed,
}

/// Linear authority to replace one reserved free-input row after the staged
/// relation has allocated all wires referenced by its final constraint.
///
/// The wire value and index never change. Only its original tautology row is
/// replaced, exactly once, by `wire = left * right`. This lets a committed
/// column be allocated before a self-recursive replay while still using that
/// already-budgeted row for the replay's final source binding.
#[must_use = "a deferred constraint row must be sealed before the builder can finish"]
pub struct DeferredConstraintSlot {
    builder_brand: u64,
    wire: Wire,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeferredConstraintSlotError {
    WrongBuilder,
    AlreadySealed,
    PendingWitness,
    Unsatisfied,
}

const PENDING_WITNESS_VALUE: u8 = 1;
const PENDING_CONSTRAINT_ROW: u8 = 2;
const ELIGIBLE_LINEAR_ROW: u8 = 4;
const CONSTRAINED_ZERO: u8 = 8;
const CONSTRAINED_ONE: u8 = 16;

static NEXT_BUILDER_BRAND: AtomicU64 = AtomicU64::new(1);

fn next_builder_brand() -> u64 {
    let brand = NEXT_BUILDER_BRAND.fetch_add(1, Ordering::Relaxed);
    assert_ne!(brand, 0, "FieldR1csBuilder brand space exhausted");
    brand
}

/// Symbolic affine combination `Σ coeff·wire + constant`. Terms are kept
/// sorted by wire index and consolidated on every combination, so expression
/// size is bounded by the support (set of distinct wires), not by the number
/// of operations that produced it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinExpr {
    /// Sorted by wire index; no duplicates; no zero coefficients.
    pub terms: Vec<(u32, F128)>,
    pub constant: F128,
}

impl LinExpr {
    pub fn constant(c: F128) -> Self {
        Self {
            terms: Vec::new(),
            constant: c,
        }
    }

    pub fn zero() -> Self {
        Self::constant(F128::ZERO)
    }

    pub fn from_wire(w: Wire) -> Self {
        Self {
            terms: vec![(w.0, F128::ONE)],
            constant: F128::ZERO,
        }
    }

    pub fn is_const(&self) -> bool {
        self.terms.is_empty()
    }

    /// `self + other` with sorted-merge consolidation.
    pub fn add(&self, other: &Self) -> Self {
        let mut terms = Vec::with_capacity(self.terms.len() + other.terms.len());
        let (mut i, mut j) = (0usize, 0usize);
        while i < self.terms.len() && j < other.terms.len() {
            let (wa, ca) = self.terms[i];
            let (wb, cb) = other.terms[j];
            match wa.cmp(&wb) {
                std::cmp::Ordering::Less => {
                    terms.push((wa, ca));
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    terms.push((wb, cb));
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    let c = ca + cb;
                    if c != F128::ZERO {
                        terms.push((wa, c));
                    }
                    i += 1;
                    j += 1;
                }
            }
        }
        terms.extend_from_slice(&self.terms[i..]);
        terms.extend_from_slice(&other.terms[j..]);
        Self {
            terms,
            constant: self.constant + other.constant,
        }
    }

    /// `self · scalar` (F128-linear).
    pub fn scale(&self, scalar: F128) -> Self {
        if scalar == F128::ZERO {
            return Self::zero();
        }
        if scalar == F128::ONE {
            return self.clone();
        }
        Self {
            terms: self.terms.iter().map(|&(w, c)| (w, c * scalar)).collect(),
            constant: self.constant * scalar,
        }
    }

    pub fn add_const(&self, c: F128) -> Self {
        Self {
            terms: self.terms.clone(),
            constant: self.constant + c,
        }
    }

    /// Evaluate against a witness.
    pub fn eval(&self, values: &[F128]) -> F128 {
        let mut acc = self.constant;
        for &(w, c) in &self.terms {
            let value = values[w as usize];
            acc += if c == F128::ONE { value } else { c * value };
        }
        acc
    }
}

/// Symbolic element of the C1 challenge field GF(2^256), represented by two
/// flat-basis GF(2^128) expressions.  The committed recursive witness remains
/// over F128; every extension operation is lowered to base-field constraints.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtExpr {
    pub lo: LinExpr,
    pub hi: LinExpr,
}

impl ExtExpr {
    pub fn new(lo: LinExpr, hi: LinExpr) -> Self {
        Self { lo, hi }
    }

    pub fn zero() -> Self {
        Self::constant(F256::ZERO)
    }

    pub fn one() -> Self {
        Self::constant(F256::ONE)
    }

    pub fn constant(value: F256) -> Self {
        Self {
            lo: LinExpr::constant(value.lo),
            hi: LinExpr::constant(value.hi),
        }
    }

    pub fn from_base(value: LinExpr) -> Self {
        Self {
            lo: value,
            hi: LinExpr::zero(),
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        Self {
            lo: self.lo.add(&other.lo),
            hi: self.hi.add(&other.hi),
        }
    }

    pub fn add_const(&self, value: F256) -> Self {
        Self {
            lo: self.lo.add_const(value.lo),
            hi: self.hi.add_const(value.hi),
        }
    }

    pub fn scale_base(&self, scalar: F128) -> Self {
        Self {
            lo: self.lo.scale(scalar),
            hi: self.hi.scale(scalar),
        }
    }

    /// Multiply by a build-time GF(2^256) constant using only F128-linear
    /// recombination. No multiplication constraint is required.
    pub fn scale_ext(&self, scalar: F256) -> Self {
        let v0 = self.lo.scale(scalar.lo);
        let v1 = self.hi.scale(scalar.hi);
        let v_sum = self.lo.add(&self.hi).scale(scalar.lo + scalar.hi);
        Self {
            lo: v0.add(&v1.scale(F256::EXTENSION_TAU)),
            hi: v0.add(&v_sum),
        }
    }

    pub fn eval(&self, values: &[F128]) -> F256 {
        F256::new(self.lo.eval(values), self.hi.eval(values))
    }

    pub fn is_const(&self) -> bool {
        self.lo.is_const() && self.hi.is_const()
    }

    pub fn constant_value(&self) -> Option<F256> {
        self.is_const()
            .then_some(F256::new(self.lo.constant, self.hi.constant))
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builds a satisfiable single-block [`FieldR1cs`] (`m = k_log`, `n_outer =
/// 1`) plus its witness. Wire 0 is the constant-one wire (row `z_0 = z_0²`,
/// `const_pin = Some(0)` — the lincheck β-pin proves the committed column is
/// all-ones, excluding the `z_0 = 0` root).
pub struct FieldR1csBuilder {
    values: Vec<F128>,
    /// A/B constraint matrices in dictionary-encoded CSR-under-construction
    /// form. Ordinary allocations append exactly one row in wire order, never
    /// a `Vec<Vec>` of per-row heap allocations. Coefficients are interned into
    /// `value_table` on the fly (the matrix is a protocol constant with a few
    /// hundred distinct values), so the builder holds a `u32` index, not a
    /// 16-byte `F128`, per nonzero. A small explicitly deferred subset is
    /// replaced in one ordered CSR pass at `build`; every other row moves
    /// directly into `SparseFieldMatrix`.
    a_cols: Vec<u32>,
    a_value_indices: Vec<u32>,
    a_offsets: Vec<usize>,
    b_cols: Vec<u32>,
    b_value_indices: Vec<u32>,
    b_offsets: Vec<usize>,
    value_table: Vec<F128>,
    value_map: std::collections::HashMap<u128, u32>,
    /// `(wire, value)` pairs registered through [`Self::alloc_public_f128`].
    publics: Vec<(u32, F128)>,
    /// When false (witness-only mode, [`Self::new_witness_only`]), constraint
    /// rows are not accumulated: [`Self::commit_wire`] stores only the wire
    /// VALUE. Witness values are computed by the gadget callers before the
    /// commit, so skipping the row pushes cannot change the witness — the
    /// mode rebuilds the witness of a CLASS-FIXED matrix (identical across
    /// builds by I1, enforced by the fixity gates) without materializing a
    /// second matrix copy. Finish with [`Self::build_witness_only`].
    record_rows: bool,
    /// Identity and exact per-wire pending flags for the small set of free
    /// inputs deliberately left open by a staged relation. One byte per wire
    /// makes release-mode dependency checks a direct indexed load and also
    /// catches manually reconstructed [`LinExpr`] values.
    builder_brand: u64,
    deferred_witness_slots: Vec<u8>,
    pending_deferred_witness_slots: usize,
    pending_deferred_constraint_slots: usize,
    deferred_constraint_patches: Vec<DeferredConstraintPatch>,
    deferred_patch_a_cols: Vec<u32>,
    deferred_patch_a_value_indices: Vec<u32>,
    deferred_patch_b_cols: Vec<u32>,
    deferred_patch_b_value_indices: Vec<u32>,
    tower_bit_wires: std::collections::HashMap<TowerBitKey, Vec<Wire>>,
    tower_bit_nested_bytes: usize,
    product_observer: Option<SymbolicProductObserver>,
    fused_boolean_pins: bool,
    reuse_linear_rows: bool,
    reused_linear_pins: usize,
    symbolic_product_aliases: bool,
    constant_product_wires: std::collections::HashMap<u128, Wire>,
    product_alias_stats: ProductAliasObservation,
    checked_boolean_gates: std::collections::HashSet<SymbolicProductOperand>,
    checked_boolean_gate_bytes: usize,
    boolean_pin_stats: BooleanPinObservation,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProductAliasObservation {
    pub identity_reuses: usize,
    pub constant_reuses: usize,
    pub constant_rows: usize,
    pub constant_clears: usize,
    pub maximum_constants: usize,
    pub constrained_bits: usize,
    pub reduced_operands: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProductObservation {
    pub products: usize,
    pub eligible: usize,
    pub repeated: usize,
    pub clear_count: usize,
    pub maximum_entries: usize,
    pub nested_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BooleanPinObservation {
    pub fused_assertions: usize,
    pub boolean_checks: usize,
    pub constant_assertions_removed: usize,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SymbolicProductOperand {
    constant: u128,
    terms: Vec<(u32, u128)>,
}

impl SymbolicProductOperand {
    fn from_expression(expression: &LinExpr) -> Self {
        let scalar = |value: F128| (u128::from(value.hi) << 64) | u128::from(value.lo);
        Self {
            constant: scalar(expression.constant),
            terms: expression
                .terms
                .iter()
                .map(|&(wire, value)| (wire, scalar(value)))
                .collect(),
        }
    }
}

struct SymbolicProductObserver {
    entries: std::collections::HashSet<(SymbolicProductOperand, SymbolicProductOperand)>,
    limit: usize,
    stats: ProductObservation,
}

impl SymbolicProductObserver {
    fn observe(&mut self, x: &LinExpr, y: &LinExpr) {
        self.stats.products += 1;
        if x.is_const() || y.is_const() || x.terms.len() > 4 || y.terms.len() > 4 {
            return;
        }
        self.stats.eligible += 1;
        let mut left = SymbolicProductOperand::from_expression(x);
        let mut right = SymbolicProductOperand::from_expression(y);
        if left > right {
            std::mem::swap(&mut left, &mut right);
        }
        let key = (left, right);
        if self.entries.contains(&key) {
            self.stats.repeated += 1;
            return;
        }
        if self.entries.len() == self.limit {
            self.entries.clear();
            self.stats.nested_bytes = 0;
            self.stats.clear_count += 1;
        }
        self.stats.nested_bytes +=
            (key.0.terms.capacity() + key.1.terms.capacity()) * core::mem::size_of::<(u32, u128)>();
        self.entries.insert(key);
        self.stats.maximum_entries = self.stats.maximum_entries.max(self.entries.len());
    }

    fn retained_bytes(&self) -> usize {
        self.entries
            .capacity()
            .saturating_mul(2)
            .saturating_mul(
                core::mem::size_of::<(SymbolicProductOperand, SymbolicProductOperand)>() + 1,
            )
            .saturating_add(self.stats.nested_bytes)
    }
}

#[derive(PartialEq, Eq, Hash)]
struct TowerBitKey {
    width: usize,
    constant: u128,
    terms: Vec<(u32, u128)>,
}

struct DeferredConstraintPatch {
    wire: u32,
    a_start: usize,
    a_end: usize,
    b_start: usize,
    b_end: usize,
}

impl Default for FieldR1csBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldR1csBuilder {
    pub fn new() -> Self {
        let mut b = Self {
            values: Vec::new(),
            a_cols: Vec::new(),
            a_value_indices: Vec::new(),
            a_offsets: vec![0],
            b_cols: Vec::new(),
            b_value_indices: Vec::new(),
            b_offsets: vec![0],
            value_table: Vec::new(),
            value_map: std::collections::HashMap::new(),
            publics: Vec::new(),
            record_rows: true,
            builder_brand: next_builder_brand(),
            deferred_witness_slots: Vec::new(),
            pending_deferred_witness_slots: 0,
            pending_deferred_constraint_slots: 0,
            deferred_constraint_patches: Vec::new(),
            deferred_patch_a_cols: Vec::new(),
            deferred_patch_a_value_indices: Vec::new(),
            deferred_patch_b_cols: Vec::new(),
            deferred_patch_b_value_indices: Vec::new(),
            tower_bit_wires: std::collections::HashMap::new(),
            tower_bit_nested_bytes: 0,
            product_observer: None,
            fused_boolean_pins: false,
            reuse_linear_rows: false,
            reused_linear_pins: 0,
            symbolic_product_aliases: false,
            constant_product_wires: std::collections::HashMap::new(),
            product_alias_stats: ProductAliasObservation::default(),
            checked_boolean_gates: std::collections::HashSet::new(),
            checked_boolean_gate_bytes: 0,
            boolean_pin_stats: BooleanPinObservation::default(),
        };
        // Wire 0: the constant-one wire, z_0 = z_0 · z_0.
        let w = b.commit_wire(F128::ONE, &[(0, F128::ONE)], &[(0, F128::ONE)]);
        debug_assert_eq!(w.0, 0);
        b
    }

    /// A witness-only builder: identical wire numbering and witness values,
    /// no constraint-row accumulation (see `record_rows`). Finish with
    /// [`Self::build_witness_only`]; [`Self::build`] would produce an empty
    /// matrix and is forbidden.
    pub fn new_witness_only() -> Self {
        let mut b = Self::new();
        b.record_rows = false;
        // Drop wire 0's already-recorded row: witness-only builds never read
        // the row arrays, keep them empty for the `build` guard.
        b.a_cols.clear();
        b.a_value_indices.clear();
        b.a_offsets.truncate(1);
        b.b_cols.clear();
        b.b_value_indices.clear();
        b.b_offsets.truncate(1);
        b
    }

    pub fn enable_symbolic_product_aliases(&mut self) {
        assert!(!self.symbolic_product_aliases);
        self.symbolic_product_aliases = true;
        self.constant_product_wires
            .insert(f128_to_u128(F128::ONE), Wire(0));
        self.product_alias_stats.maximum_constants = 1;
        self.record_constrained_bit(Wire(0), F128::ONE);
    }

    pub fn product_alias_observation(&self) -> ProductAliasObservation {
        self.product_alias_stats
    }

    fn record_constrained_bit(&mut self, wire: Wire, value: F128) {
        let bit = if value == F128::ZERO {
            CONSTRAINED_ZERO
        } else if value == F128::ONE {
            CONSTRAINED_ONE
        } else {
            return;
        };
        let flags = &mut self.deferred_witness_slots[wire.0 as usize];
        if *flags & (CONSTRAINED_ZERO | CONSTRAINED_ONE) == 0 {
            *flags |= bit;
            self.product_alias_stats.constrained_bits += 1;
        }
    }

    fn record_pinned_bit(&mut self, expression: &LinExpr, expected: F128) {
        if let &[(wire, coefficient)] = expression.terms.as_slice() {
            if coefficient != F128::ZERO {
                let value = if coefficient == F128::ONE {
                    expression.constant + expected
                } else {
                    (expression.constant + expected) * coefficient.inv()
                };
                self.record_constrained_bit(Wire(wire), value);
            }
        }
    }

    fn reduce_constrained_bits(&mut self, expression: &LinExpr) -> Option<LinExpr> {
        if !expression.terms.iter().any(|&(wire, _)| {
            self.deferred_witness_slots
                .get(wire as usize)
                .is_some_and(|flags| flags & (CONSTRAINED_ZERO | CONSTRAINED_ONE) != 0)
        }) {
            return None;
        }
        let mut reduced = LinExpr {
            terms: Vec::with_capacity(expression.terms.len()),
            constant: expression.constant,
        };
        for &(wire, coefficient) in &expression.terms {
            let flags = self.deferred_witness_slots[wire as usize];
            if flags & CONSTRAINED_ONE != 0 {
                reduced.constant += coefficient;
            } else if flags & CONSTRAINED_ZERO == 0 {
                reduced.terms.push((wire, coefficient));
            }
        }
        self.product_alias_stats.reduced_operands += 1;
        Some(reduced)
    }

    fn symbolic_product_alias(&mut self, left: &LinExpr, right: &LinExpr) -> Option<Wire> {
        let constant = if left.is_const() && right.is_const() {
            Some(left.constant * right.constant)
        } else if left.is_const() && left.constant == F128::ZERO
            || right.is_const() && right.constant == F128::ZERO
        {
            Some(F128::ZERO)
        } else {
            None
        };
        let identity = if left.is_const() {
            (right.terms.len() == 1
                && right.constant == F128::ZERO
                && right.terms[0].1 * left.constant == F128::ONE)
                .then(|| Wire(right.terms[0].0))
        } else if right.is_const() {
            (left.terms.len() == 1
                && left.constant == F128::ZERO
                && left.terms[0].1 * right.constant == F128::ONE)
                .then(|| Wire(left.terms[0].0))
        } else {
            None
        };
        if constant.is_none() && identity.is_none() {
            return None;
        }
        assert!(
            left.terms
                .iter()
                .chain(right.terms.iter())
                .all(|&(wire, _)| (wire as usize) < self.values.len()),
            "cannot alias a product with an unallocated input"
        );
        if let Some(wire) = identity {
            self.product_alias_stats.identity_reuses += 1;
            return Some(wire);
        }
        let value = constant.unwrap();
        let key = f128_to_u128(value);
        if let Some(&wire) = self.constant_product_wires.get(&key) {
            self.product_alias_stats.constant_reuses += 1;
            return Some(wire);
        }
        if self.constant_product_wires.len() == 4096 {
            self.constant_product_wires.clear();
            self.constant_product_wires
                .insert(f128_to_u128(F128::ONE), Wire(0));
            self.product_alias_stats.constant_clears += 1;
        }
        let wire = if self.record_rows {
            let row = if value == F128::ZERO {
                Vec::new()
            } else {
                vec![(0, value)]
            };
            self.commit_wire(value, &row, &[(0, F128::ONE)])
        } else {
            self.commit_wire(value, &[], &[])
        };
        self.record_constrained_bit(wire, value);
        self.constant_product_wires.insert(key, wire);
        self.product_alias_stats.constant_rows += 1;
        self.product_alias_stats.maximum_constants = self
            .product_alias_stats
            .maximum_constants
            .max(self.constant_product_wires.len());
        Some(wire)
    }

    pub fn enable_reused_linear_rows(&mut self) {
        assert!(!self.reuse_linear_rows);
        self.reuse_linear_rows = true;
    }

    pub fn reused_linear_pins(&self) -> usize {
        self.reused_linear_pins
    }

    fn bind_linear_pin_in_free_row(&mut self, expression: &LinExpr, expected: F128) -> bool {
        let candidate = expression
            .terms
            .iter()
            .rev()
            .find(|&&(wire, coefficient)| {
                coefficient != F128::ZERO
                    && self
                        .deferred_witness_slots
                        .get(wire as usize)
                        .is_some_and(|flags| flags & ELIGIBLE_LINEAR_ROW != 0)
                    && expression
                        .terms
                        .iter()
                        .filter(|&&(other, _)| other == wire)
                        .count()
                        == 1
            })
            .copied();
        let Some((wire, coefficient)) = candidate else {
            return false;
        };
        self.deferred_witness_slots[wire as usize] &= !ELIGIBLE_LINEAR_ROW;
        if self.record_rows {
            let inverse = if coefficient == F128::ONE {
                F128::ONE
            } else {
                coefficient.inv()
            };
            let solved = LinExpr {
                terms: expression
                    .terms
                    .iter()
                    .filter(|&&(other, _)| other != wire)
                    .map(|&(other, value)| (other, value * inverse))
                    .collect(),
                constant: (expression.constant + expected) * inverse,
            };
            let a_start = self.deferred_patch_a_cols.len();
            for (column, value) in Self::expr_to_row(&solved) {
                let value_index = self.intern_value(value);
                self.deferred_patch_a_cols.push(column);
                self.deferred_patch_a_value_indices.push(value_index);
            }
            let a_end = self.deferred_patch_a_cols.len();
            let b_start = self.deferred_patch_b_cols.len();
            let one = self.intern_value(F128::ONE);
            self.deferred_patch_b_cols.push(0);
            self.deferred_patch_b_value_indices.push(one);
            let b_end = self.deferred_patch_b_cols.len();
            self.deferred_constraint_patches
                .push(DeferredConstraintPatch {
                    wire,
                    a_start,
                    a_end,
                    b_start,
                    b_end,
                });
        }
        self.reused_linear_pins += 1;
        true
    }

    pub fn enable_fused_boolean_pins(&mut self) {
        assert!(!self.fused_boolean_pins);
        self.fused_boolean_pins = true;
    }

    pub fn uses_fused_boolean_pins(&self) -> bool {
        self.fused_boolean_pins
    }

    pub fn boolean_pin_observation(&self) -> BooleanPinObservation {
        self.boolean_pin_stats
    }

    /// Enforce a checked boolean implication using one self-referential row.
    /// For boolean g, w = g * (e + w) is equivalent to g * e = 0.
    pub fn pin_boolean_gated_zero(&mut self, gate: &LinExpr, expression: &LinExpr) {
        assert!(self.fused_boolean_pins);
        assert!(
            !self.expression_contains_pending_deferred(gate)
                && !self.expression_contains_pending_deferred(expression),
            "cannot pin a conditional expression from an unsealed witness slot"
        );
        let key = (gate.terms.len() <= 16).then(|| SymbolicProductOperand::from_expression(gate));
        let known_boolean = key
            .as_ref()
            .is_some_and(|key| self.checked_boolean_gates.contains(key));
        if !known_boolean {
            let product = self.mul(gate, &gate.add_const(F128::ONE));
            self.pin_f128(&LinExpr::from_wire(product), F128::ZERO);
            self.boolean_pin_stats.boolean_checks += 1;
            if let Some(key) = key {
                if self.checked_boolean_gates.len() == 4096 {
                    self.checked_boolean_gates.clear();
                    self.checked_boolean_gate_bytes = 0;
                }
                self.checked_boolean_gate_bytes +=
                    key.terms.capacity() * core::mem::size_of::<(u32, u128)>();
                self.checked_boolean_gates.insert(key);
            }
        }
        let wire = self.next_wire();
        if self.record_rows {
            let a_row = Self::expr_to_row(gate);
            let b_row = Self::expr_to_row(&expression.add(&LinExpr::from_wire(Wire(wire))));
            self.commit_wire(F128::ZERO, &a_row, &b_row);
        } else {
            self.commit_wire(F128::ZERO, &[], &[]);
        }
        self.boolean_pin_stats.fused_assertions += 1;
    }

    pub fn observe_symbolic_products(&mut self, limit: usize) {
        assert!((1..=65536).contains(&limit));
        assert!(self.product_observer.is_none());
        self.product_observer = Some(SymbolicProductObserver {
            entries: std::collections::HashSet::new(),
            limit,
            stats: ProductObservation::default(),
        });
    }

    pub fn product_observation(&self) -> Option<ProductObservation> {
        self.product_observer
            .as_ref()
            .map(|observer| observer.stats)
    }

    /// The constant-one wire as an expression.
    pub fn one(&self) -> LinExpr {
        LinExpr::from_wire(Wire(0))
    }

    pub fn num_wires(&self) -> usize {
        self.values.len()
    }

    /// Allocated witness buffers and conservative retained bit-cache storage.
    /// Staged proving owners use this for admission accounting.
    pub fn retained_witness_bytes(&self) -> usize {
        // The pinned std table has at most twice its reported capacity in
        // buckets here. Include bucket payloads, control bytes and alignment.
        let table = if self.tower_bit_wires.capacity() == 0 {
            0
        } else {
            self.tower_bit_wires
                .capacity()
                .saturating_mul(2)
                .saturating_mul(core::mem::size_of::<(TowerBitKey, Vec<Wire>)>() + 1)
                .saturating_add(128)
        };
        self.values
            .capacity()
            .saturating_mul(core::mem::size_of::<F128>())
            .saturating_add(self.deferred_witness_slots.capacity())
            .saturating_add(self.tower_bit_nested_bytes)
            .saturating_add(table)
            .saturating_add(
                self.product_observer
                    .as_ref()
                    .map_or(0, SymbolicProductObserver::retained_bytes),
            )
            .saturating_add(if self.constant_product_wires.capacity() == 0 {
                0
            } else {
                self.constant_product_wires
                    .capacity()
                    .saturating_mul(2)
                    .saturating_mul(core::mem::size_of::<(u128, Wire)>() + 1)
                    .saturating_add(128)
            })
            .saturating_add(self.checked_boolean_gate_bytes)
            .saturating_add(
                self.checked_boolean_gates
                    .capacity()
                    .saturating_mul(2)
                    .saturating_mul(core::mem::size_of::<SymbolicProductOperand>() + 1),
            )
    }

    fn release_tower_bit_cache(&mut self) {
        self.tower_bit_wires = std::collections::HashMap::new();
        self.tower_bit_nested_bytes = 0;
        self.product_observer = None;
        self.constant_product_wires = std::collections::HashMap::new();
        self.checked_boolean_gates = std::collections::HashSet::new();
        self.checked_boolean_gate_bytes = 0;
    }

    /// Index the next allocation will assign.
    #[inline]
    fn next_wire(&self) -> u32 {
        self.values.len() as u32
    }

    /// Intern a coefficient into the value table, returning its index.
    #[inline]
    fn intern_value(&mut self, v: F128) -> u32 {
        let key = ((v.hi as u128) << 64) | v.lo as u128;
        let table = &mut self.value_table;
        *self.value_map.entry(key).or_insert_with(|| {
            let idx = table.len() as u32;
            table.push(v);
            idx
        })
    }

    /// Append one wire: its witness value and its A/B matrix rows (entries in
    /// the order they were built — the per-row order every consumer and the
    /// statement digest depend on). Coefficients are interned into the value
    /// table.
    fn commit_wire(&mut self, value: F128, a_row: &[(u32, F128)], b_row: &[(u32, F128)]) -> Wire {
        let idx = self.values.len();
        assert!(idx < u32::MAX as usize);
        self.values.push(value);
        self.deferred_witness_slots.push(0);
        if self.record_rows {
            for &(c, v) in a_row {
                self.a_cols.push(c);
                let vi = self.intern_value(v);
                self.a_value_indices.push(vi);
            }
            self.a_offsets.push(self.a_cols.len());
            for &(c, v) in b_row {
                self.b_cols.push(c);
                let vi = self.intern_value(v);
                self.b_value_indices.push(vi);
            }
            self.b_offsets.push(self.b_cols.len());
        }
        Wire(idx as u32)
    }

    /// Convert an expression into a sparse matrix row: terms + the constant
    /// folded onto the constant-one column.
    fn expr_to_row(expr: &LinExpr) -> Vec<(u32, F128)> {
        let mut row = Vec::with_capacity(expr.terms.len() + 1);
        let mut const_coeff = expr.constant;
        for &(w, c) in &expr.terms {
            if w == 0 {
                const_coeff += c;
            } else {
                row.push((w, c));
            }
        }
        if const_coeff != F128::ZERO {
            // Keep the row sorted: column 0 first.
            row.insert(0, (0, const_coeff));
        }
        row
    }

    /// Free (unconstrained) input wire: tautology row `z_i = z_i · 1`.
    pub fn alloc_f128(&mut self, value: F128) -> Wire {
        let w = self.next_wire();
        let wire = self.commit_wire(value, &[(w, F128::ONE)], &[(0, F128::ONE)]);
        if self.reuse_linear_rows {
            self.deferred_witness_slots[wire.0 as usize] |= ELIGIBLE_LINEAR_ROW;
        }
        wire
    }

    /// Allocate one free input whose value may be replaced exactly once by
    /// consuming the returned builder-branded capability.
    ///
    /// Its constraint row is byte-for-byte the ordinary [`Self::alloc_f128`]
    /// row, so sealing changes witness data only and never relation shape.
    #[doc(hidden)]
    pub fn alloc_deferred_f128(&mut self, initial: F128) -> (Wire, DeferredWitnessSlot) {
        let wire = self.alloc_f128(initial);
        let pending = &mut self.deferred_witness_slots[wire.0 as usize];
        assert_eq!(
            *pending & (PENDING_WITNESS_VALUE | PENDING_CONSTRAINT_ROW),
            0,
            "fresh deferred witness wire was already pending"
        );
        *pending = PENDING_WITNESS_VALUE;
        self.pending_deferred_witness_slots += 1;
        (
            wire,
            DeferredWitnessSlot {
                builder_brand: self.builder_brand,
                wire,
            },
        )
    }

    /// Seal one explicitly deferred free input.  There is intentionally no
    /// API for mutating an ordinary or already-sealed witness wire.
    #[doc(hidden)]
    pub fn seal_deferred_f128(
        &mut self,
        slot: DeferredWitnessSlot,
        value: F128,
    ) -> Result<(), DeferredWitnessSlotError> {
        if slot.builder_brand != self.builder_brand {
            return Err(DeferredWitnessSlotError::WrongBuilder);
        }
        let Some(pending) = self.deferred_witness_slots.get_mut(slot.wire.0 as usize) else {
            return Err(DeferredWitnessSlotError::AlreadySealed);
        };
        if *pending & PENDING_WITNESS_VALUE == 0 {
            return Err(DeferredWitnessSlotError::AlreadySealed);
        }
        *pending &= !PENDING_WITNESS_VALUE;
        self.pending_deferred_witness_slots -= 1;
        self.values[slot.wire.0 as usize] = value;
        Ok(())
    }

    /// Reserve one ordinary free-input row whose final constraint references
    /// wires allocated later in the staged relation. The returned capability
    /// is linear, builder-branded, and must be consumed exactly once.
    pub fn alloc_deferred_constraint_f128(
        &mut self,
        value: F128,
    ) -> (Wire, DeferredConstraintSlot) {
        let wire = self.alloc_f128(value);
        let pending = &mut self.deferred_witness_slots[wire.0 as usize];
        assert_eq!(
            *pending & (PENDING_WITNESS_VALUE | PENDING_CONSTRAINT_ROW),
            0,
            "fresh deferred constraint row was pending"
        );
        *pending = PENDING_CONSTRAINT_ROW;
        self.pending_deferred_constraint_slots += 1;
        (
            wire,
            DeferredConstraintSlot {
                builder_brand: self.builder_brand,
                wire,
            },
        )
    }

    /// Replace a reserved tautology by `slot.wire = left * right` without
    /// allocating another row. Future-wire references are accepted because
    /// matrix columns are validated only after the complete witness exists.
    pub fn seal_deferred_constraint(
        &mut self,
        slot: DeferredConstraintSlot,
        left: &LinExpr,
        right: &LinExpr,
    ) -> Result<(), DeferredConstraintSlotError> {
        if slot.builder_brand != self.builder_brand {
            return Err(DeferredConstraintSlotError::WrongBuilder);
        }
        let Some(&pending) = self.deferred_witness_slots.get(slot.wire.0 as usize) else {
            return Err(DeferredConstraintSlotError::AlreadySealed);
        };
        if pending & PENDING_CONSTRAINT_ROW == 0 {
            return Err(DeferredConstraintSlotError::AlreadySealed);
        }
        if self.expression_contains_pending_deferred(left)
            || self.expression_contains_pending_deferred(right)
        {
            return Err(DeferredConstraintSlotError::PendingWitness);
        }
        if left.eval(&self.values) * right.eval(&self.values) != self.values[slot.wire.0 as usize] {
            return Err(DeferredConstraintSlotError::Unsatisfied);
        }

        if self.record_rows {
            let a_start = self.deferred_patch_a_cols.len();
            for (column, value) in Self::expr_to_row(left) {
                let value_index = self.intern_value(value);
                self.deferred_patch_a_cols.push(column);
                self.deferred_patch_a_value_indices.push(value_index);
            }
            let a_end = self.deferred_patch_a_cols.len();
            let b_start = self.deferred_patch_b_cols.len();
            for (column, value) in Self::expr_to_row(right) {
                let value_index = self.intern_value(value);
                self.deferred_patch_b_cols.push(column);
                self.deferred_patch_b_value_indices.push(value_index);
            }
            let b_end = self.deferred_patch_b_cols.len();
            self.deferred_constraint_patches
                .push(DeferredConstraintPatch {
                    wire: slot.wire.0,
                    a_start,
                    a_end,
                    b_start,
                    b_end,
                });
        }
        self.deferred_witness_slots[slot.wire.0 as usize] &= !PENDING_CONSTRAINT_ROW;
        self.pending_deferred_constraint_slots -= 1;
        Ok(())
    }

    /// Public-input wire: row forces `z_i = value` (`A_i = value·col_0`,
    /// `B_i = col_0`), and the pair is recorded in the public-input list.
    /// The pinned value is part of the statement (it lives in the matrix,
    /// which the statement digest covers).
    pub fn alloc_public_f128(&mut self, value: F128) -> Wire {
        let w = self.next_wire();
        let a_row: Vec<(u32, F128)> = if value != F128::ZERO {
            vec![(0, value)]
        } else {
            Vec::new()
        };
        let wire = self.commit_wire(value, &a_row, &[(0, F128::ONE)]);
        self.publics.push((w, value));
        if self.symbolic_product_aliases {
            self.record_constrained_bit(wire, value);
        }
        wire
    }

    /// Boolean wire: row `z_i = z_i · z_i` ⇒ `z_i ∈ {0, 1}` (the only
    /// idempotents of a field). Zero multiplication cost beyond the row.
    pub fn alloc_bool(&mut self, bit: bool) -> Wire {
        let w = self.next_wire();
        let v = if bit { F128::ONE } else { F128::ZERO };
        self.commit_wire(v, &[(w, F128::ONE)], &[(w, F128::ONE)])
    }

    /// One multiplication constraint: new wire `w = x · y`.
    pub fn mul(&mut self, x: &LinExpr, y: &LinExpr) -> Wire {
        assert!(
            !self.expression_contains_pending_deferred(x)
                && !self.expression_contains_pending_deferred(y),
            "cannot evaluate a multiplication from an unsealed deferred witness slot"
        );
        let reduced_x = if self.symbolic_product_aliases {
            self.reduce_constrained_bits(x)
        } else {
            None
        };
        let reduced_y = if self.symbolic_product_aliases {
            self.reduce_constrained_bits(y)
        } else {
            None
        };
        let x = reduced_x.as_ref().unwrap_or(x);
        let y = reduced_y.as_ref().unwrap_or(y);
        if self.symbolic_product_aliases {
            if let Some(wire) = self.symbolic_product_alias(x, y) {
                return wire;
            }
        }
        if let Some(observer) = &mut self.product_observer {
            observer.observe(x, y);
        }
        let value = x.eval(&self.values) * y.eval(&self.values);
        if !self.record_rows {
            return self.commit_wire(value, &[], &[]);
        }
        let a_row = Self::expr_to_row(x);
        let b_row = Self::expr_to_row(y);
        self.commit_wire(value, &a_row, &b_row)
    }

    /// Three base-field multiplication constraints for one GF(2^256)
    /// Karatsuba product. Linear recombination by the extension constant is
    /// symbolic and adds no rows.
    pub fn mul_f256(&mut self, x: &ExtExpr, y: &ExtExpr) -> ExtExpr {
        let v0 = LinExpr::from_wire(self.mul(&x.lo, &y.lo));
        let v1 = LinExpr::from_wire(self.mul(&x.hi, &y.hi));
        let x_sum = x.lo.add(&x.hi);
        let y_sum = y.lo.add(&y.hi);
        let v_sum = LinExpr::from_wire(self.mul(&x_sum, &y_sum));
        ExtExpr {
            lo: v0.add(&v1.scale(F256::EXTENSION_TAU)),
            hi: v0.add(&v_sum),
        }
    }

    /// Two base-field multiplication constraints for one GF(2^256) square.
    /// In the quadratic tower, `(a + bu)^2 = a^2 + tau*b^2 + b^2*u`, so the
    /// cross product used by a general Karatsuba multiplication is absent.
    pub fn square_f256(&mut self, value: &ExtExpr) -> ExtExpr {
        let lo_square = LinExpr::from_wire(self.mul(&value.lo, &value.lo));
        let hi_square = LinExpr::from_wire(self.mul(&value.hi, &value.hi));
        ExtExpr {
            lo: lo_square.add(&hi_square.scale(F256::EXTENSION_TAU)),
            hi: hi_square,
        }
    }

    /// One base-field multiplication for the C1 trace-one challenge map
    /// `(lo, y) -> (lo, y^2+y+tau)`.
    pub fn c1_challenge_from_raw(&mut self, lo: LinExpr, raw_hi: LinExpr) -> ExtExpr {
        let square = LinExpr::from_wire(self.mul(&raw_hi, &raw_hi));
        ExtExpr {
            lo,
            hi: square.add(&raw_hi).add_const(F256::EXTENSION_TAU),
        }
    }

    #[inline]
    fn expression_contains_pending_deferred(&self, expression: &LinExpr) -> bool {
        self.pending_deferred_witness_slots != 0
            && expression.terms.iter().any(|(wire, _)| {
                self.deferred_witness_slots[*wire as usize] & PENDING_WITNESS_VALUE != 0
            })
    }

    /// Materialize an expression into a single wire (`w = expr · 1`).
    pub fn materialize(&mut self, expr: &LinExpr) -> Wire {
        self.mul(expr, &self.one())
    }

    pub fn materialize_f256(&mut self, expr: &ExtExpr) -> (Wire, Wire) {
        (self.materialize(&expr.lo), self.materialize(&expr.hi))
    }

    /// Assert `expr == expected` (one wire, self-cancelling row:
    /// `z_w = (z_w + expr + expected) · 1` ⇒ `expr + expected = 0`).
    pub fn pin_f128(&mut self, expr: &LinExpr, expected: F128) {
        if self.symbolic_product_aliases {
            self.record_pinned_bit(expr, expected);
        }
        if self.fused_boolean_pins && expr.is_const() && expr.constant == expected {
            self.boolean_pin_stats.constant_assertions_removed += 1;
            return;
        }
        if self.reuse_linear_rows && self.bind_linear_pin_in_free_row(expr, expected) {
            return;
        }
        if !self.record_rows {
            self.commit_wire(F128::ZERO, &[], &[]);
            return;
        }
        let w = self.next_wire();
        let full = expr.add(&LinExpr::from_wire(Wire(w))).add_const(expected);
        let a_row = Self::expr_to_row(&full);
        self.commit_wire(F128::ZERO, &a_row, &[(0, F128::ONE)]);
    }

    pub fn pin_f256(&mut self, expr: &ExtExpr, expected: F256) {
        self.pin_f128(&expr.lo, expected.lo);
        self.pin_f128(&expr.hi, expected.hi);
    }

    fn apply_deferred_constraint_patches(&mut self) {
        assert_eq!(
            self.pending_deferred_constraint_slots, 0,
            "cannot build with unsealed deferred constraint rows"
        );
        if !self.record_rows {
            assert!(self.deferred_constraint_patches.is_empty());
            return;
        }
        if self.deferred_constraint_patches.is_empty() {
            return;
        }

        self.deferred_constraint_patches
            .sort_unstable_by_key(|patch| patch.wire);
        assert!(
            self.deferred_constraint_patches
                .windows(2)
                .all(|pair| pair[0].wire != pair[1].wire),
            "deferred constraint row patched twice"
        );

        let old_a_cols = std::mem::take(&mut self.a_cols);
        let old_a_values = std::mem::take(&mut self.a_value_indices);
        let old_a_offsets = std::mem::take(&mut self.a_offsets);
        let old_b_cols = std::mem::take(&mut self.b_cols);
        let old_b_values = std::mem::take(&mut self.b_value_indices);
        let old_b_offsets = std::mem::take(&mut self.b_offsets);
        let patch_a_cols = std::mem::take(&mut self.deferred_patch_a_cols);
        let patch_a_values = std::mem::take(&mut self.deferred_patch_a_value_indices);
        let patch_b_cols = std::mem::take(&mut self.deferred_patch_b_cols);
        let patch_b_values = std::mem::take(&mut self.deferred_patch_b_value_indices);

        let mut new_a_cols = Vec::with_capacity(
            old_a_cols.len() + patch_a_cols.len() - self.deferred_constraint_patches.len(),
        );
        let mut new_a_values = Vec::with_capacity(new_a_cols.capacity());
        let mut new_a_offsets = Vec::with_capacity(self.values.len() + 1);
        let mut new_b_cols = Vec::with_capacity(
            old_b_cols.len() + patch_b_cols.len() - self.deferred_constraint_patches.len(),
        );
        let mut new_b_values = Vec::with_capacity(new_b_cols.capacity());
        let mut new_b_offsets = Vec::with_capacity(self.values.len() + 1);
        new_a_offsets.push(0);
        new_b_offsets.push(0);

        let mut patch_index = 0usize;
        for row in 0..self.values.len() {
            let patch = self
                .deferred_constraint_patches
                .get(patch_index)
                .filter(|patch| patch.wire as usize == row);
            if let Some(patch) = patch {
                let old_a = old_a_offsets[row]..old_a_offsets[row + 1];
                let old_b = old_b_offsets[row]..old_b_offsets[row + 1];
                assert_eq!(&old_a_cols[old_a.clone()], &[row as u32]);
                assert_eq!(old_a.len(), 1);
                assert_eq!(
                    self.value_table[old_a_values[old_a.start] as usize],
                    F128::ONE
                );
                assert_eq!(&old_b_cols[old_b.clone()], &[0]);
                assert_eq!(old_b.len(), 1);
                assert_eq!(
                    self.value_table[old_b_values[old_b.start] as usize],
                    F128::ONE
                );
                new_a_cols.extend_from_slice(&patch_a_cols[patch.a_start..patch.a_end]);
                new_a_values.extend_from_slice(&patch_a_values[patch.a_start..patch.a_end]);
                new_b_cols.extend_from_slice(&patch_b_cols[patch.b_start..patch.b_end]);
                new_b_values.extend_from_slice(&patch_b_values[patch.b_start..patch.b_end]);
                patch_index += 1;
            } else {
                let a = old_a_offsets[row]..old_a_offsets[row + 1];
                let b = old_b_offsets[row]..old_b_offsets[row + 1];
                new_a_cols.extend_from_slice(&old_a_cols[a.clone()]);
                new_a_values.extend_from_slice(&old_a_values[a]);
                new_b_cols.extend_from_slice(&old_b_cols[b.clone()]);
                new_b_values.extend_from_slice(&old_b_values[b]);
            }
            new_a_offsets.push(new_a_cols.len());
            new_b_offsets.push(new_b_cols.len());
        }
        assert_eq!(patch_index, self.deferred_constraint_patches.len());
        self.a_cols = new_a_cols;
        self.a_value_indices = new_a_values;
        self.a_offsets = new_a_offsets;
        self.b_cols = new_b_cols;
        self.b_value_indices = new_b_values;
        self.b_offsets = new_b_offsets;
        self.deferred_constraint_patches.clear();
    }

    /// Finish: pad to the next power of two (≥ 2^7 — the zerocheck needs
    /// `m ≥ K_SKIP + 1` and the lincheck `k_skip ≤ k_log`), emit a
    /// single-block `FieldR1cs` (`m = k_log`, `n_outer = 1`) and the witness.
    /// Finish a witness-only builder: the real wire count plus the witness
    /// padded to the dyadic size [`Self::build`] would have used. The caller
    /// pairs it with an existing instance of the same class-fixed matrix.
    pub fn build_witness_only(mut self) -> (usize, Vec<F128>) {
        assert!(!self.record_rows, "use build() on a row-recording builder");
        assert!(
            self.pending_deferred_witness_slots == 0,
            "cannot build with unsealed deferred witness slots"
        );
        assert_eq!(
            self.pending_deferred_constraint_slots, 0,
            "cannot build with unsealed deferred constraint rows"
        );
        self.release_tower_bit_cache();
        let n_wires = self.values.len();
        let k_log = n_wires.next_power_of_two().trailing_zeros().max(7) as usize;
        let mut values = self.values;
        values.resize(1 << k_log, F128::ZERO);
        (n_wires, values)
    }

    pub fn build(mut self) -> (FieldR1cs, Vec<F128>) {
        assert!(
            self.record_rows,
            "build() on a witness-only builder would emit an empty matrix; \
             use build_witness_only()"
        );
        assert!(
            self.pending_deferred_witness_slots == 0,
            "cannot build with unsealed deferred witness slots"
        );
        self.apply_deferred_constraint_patches();
        self.release_tower_bit_cache();
        let n_wires = self.values.len();
        let k_log = n_wires.next_power_of_two().trailing_zeros().max(7) as usize;
        let k = 1usize << k_log;

        // Pad to k rows: the extra rows are empty, so their offset just repeats
        // the current entry count (row r spans [offsets[r], offsets[r+1])).
        let a_cols = self.a_cols;
        let a_value_indices = self.a_value_indices;
        let mut a_offsets = self.a_offsets;
        a_offsets.resize(k + 1, a_cols.len());
        let b_cols = self.b_cols;
        let b_value_indices = self.b_value_indices;
        let mut b_offsets = self.b_offsets;
        b_offsets.resize(k + 1, b_cols.len());
        let mut values = self.values;
        values.resize(k, F128::ZERO);
        // A and B interned into ONE table (a few hundred entries); each matrix
        // takes its own copy — negligible bytes, and keeps them independent.
        let value_table = self.value_table;

        let r1cs = FieldR1cs {
            m: k_log,
            k_log,
            k_skip: crate::zerocheck::K_SKIP,
            useful_rows: n_wires,
            a_0: SparseFieldMatrix::from_dict(
                k,
                a_cols,
                a_value_indices,
                value_table.clone(),
                a_offsets,
            ),
            b_0: SparseFieldMatrix::from_dict(k, b_cols, b_value_indices, value_table, b_offsets),
            const_pin: Some(0),
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        };
        r1cs.validate_shape();
        (r1cs, values)
    }

    /// Registered public inputs (wire, value).
    pub fn public_inputs(&self) -> &[(u32, F128)] {
        &self.publics
    }

    /// Current witness snapshot (for tests / expression evaluation).
    pub fn values(&self) -> &[F128] {
        &self.values
    }

    // -----------------------------------------------------------------------
    // Base gadgets
    // -----------------------------------------------------------------------

    /// `x^7` — 4 multiplications (x², x⁴, x³, x⁷), the Poseidon2b S-box.
    pub fn pow7(&mut self, x: &LinExpr) -> LinExpr {
        let x2 = LinExpr::from_wire(self.mul(x, x));
        let x4 = LinExpr::from_wire(self.mul(&x2, &x2));
        let x3 = LinExpr::from_wire(self.mul(&x2, x));
        LinExpr::from_wire(self.mul(&x4, &x3))
    }

    /// Horner evaluation of `Σ coeffs[i]·x^i` (coeffs LSB-first, degree =
    /// `coeffs.len() − 1`): `deg` multiplications.
    pub fn horner_eval(&mut self, coeffs: &[LinExpr], x: &LinExpr) -> LinExpr {
        assert!(!coeffs.is_empty());
        let mut acc = coeffs[coeffs.len() - 1].clone();
        for c in coeffs.iter().rev().skip(1) {
            let prod = LinExpr::from_wire(self.mul(&acc, x));
            acc = prod.add(c);
        }
        acc
    }

    /// `eq(r, x) = Π_i (1 + r_i + x_i)` — `n − 1` multiplications (`n ≥ 1`).
    pub fn eq_eval_trace(&mut self, r: &[LinExpr], x: &[LinExpr]) -> LinExpr {
        assert_eq!(r.len(), x.len());
        assert!(!r.is_empty());
        let factor = |i: usize| -> LinExpr { r[i].add(&x[i]).add_const(F128::ONE) };
        let mut acc = factor(0);
        for i in 1..r.len() {
            acc = LinExpr::from_wire(self.mul(&acc, &factor(i)));
        }
        acc
    }

    /// Allocate or reuse Boolean tower-coordinate bits for this exact
    /// expression and width. Each caller binds their reconstruction in its
    /// own conditional scope. The Boolean constraints are unconditional.
    pub fn alloc_tower_bits_cached(&mut self, expr: &LinExpr, n_bits: usize) -> Vec<Wire> {
        assert!(n_bits <= 128);
        assert!(
            !self.expression_contains_pending_deferred(expr),
            "cannot decompose an unsealed deferred witness slot"
        );
        let key = TowerBitKey {
            width: n_bits,
            constant: f128_to_u128(expr.constant),
            terms: expr
                .terms
                .iter()
                .map(|(wire, coefficient)| (*wire, f128_to_u128(*coefficient)))
                .collect(),
        };
        if let Some(bits) = self.tower_bit_wires.get(&key) {
            return bits.clone();
        }
        let value = noid_core::hardware::flat_to_tower_u128(f128_to_u128(expr.eval(&self.values)));
        let bits: Vec<Wire> = (0..n_bits)
            .map(|i| self.alloc_bool((value >> i) & 1 == 1))
            .collect();
        let retained_bits = bits.clone();
        self.tower_bit_nested_bytes = self
            .tower_bit_nested_bytes
            .saturating_add(
                key.terms
                    .capacity()
                    .saturating_mul(core::mem::size_of::<(u32, u128)>()),
            )
            .saturating_add(
                retained_bits
                    .capacity()
                    .saturating_mul(core::mem::size_of::<Wire>()),
            );
        self.tower_bit_wires.insert(key, retained_bits);
        bits
    }

    /// Bit-decompose `expr` into `n_bits` boolean wires (LSB-first) and
    /// enforce `expr = Σ b_i·x^i`. Because only `n_bits` bit wires exist,
    /// this simultaneously proves that `expr`'s bits above `n_bits − 1` are
    /// all zero. Returns the bit wires. Cost: `n_bits` boolean rows + 1 pin.
    pub fn decompose_bits_le(&mut self, expr: &LinExpr, n_bits: usize) -> Vec<Wire> {
        assert!(n_bits <= 128);
        assert!(
            !self.expression_contains_pending_deferred(expr),
            "cannot decompose an unsealed deferred witness slot"
        );
        let value = f128_to_u128(expr.eval(&self.values));
        let bits: Vec<Wire> = (0..n_bits)
            .map(|i| self.alloc_bool((value >> i) & 1 == 1))
            .collect();
        let mut sum = LinExpr::zero();
        for (i, b) in bits.iter().enumerate() {
            sum = sum.add(&LinExpr::from_wire(*b).scale(f128_from_u128(1u128 << i)));
        }
        self.pin_f128(&sum.add(expr), F128::ZERO);
        bits
    }
}

// ---------------------------------------------------------------------------
// Poseidon2b permutation gadget
// ---------------------------------------------------------------------------

struct PoseidonFlatTables {
    rc: [[F128; N_ROUNDS]; STATE_SIZE],
    mds_full: [[F128; STATE_SIZE]; STATE_SIZE],
    mds_partial: [[F128; STATE_SIZE]; STATE_SIZE],
}

fn poseidon_flat_tables() -> &'static PoseidonFlatTables {
    static TABLES: std::sync::OnceLock<PoseidonFlatTables> = std::sync::OnceLock::new();
    TABLES.get_or_init(|| {
        let mut rc = [[F128::ZERO; N_ROUNDS]; STATE_SIZE];
        for i in 0..STATE_SIZE {
            for r in 0..N_ROUNDS {
                rc[i][r] = flat_const(ROUND_CONSTANTS[i][r]);
            }
        }
        let mut mds_full = [[F128::ZERO; STATE_SIZE]; STATE_SIZE];
        let mut mds_partial = [[F128::ZERO; STATE_SIZE]; STATE_SIZE];
        for i in 0..STATE_SIZE {
            for j in 0..STATE_SIZE {
                mds_full[i][j] = flat_const(MDS_FULL[i][j]);
                mds_partial[i][j] = flat_const(MDS_PARTIAL[i][j]);
            }
        }
        PoseidonFlatTables {
            rc,
            mds_full,
            mds_partial,
        }
    })
}

fn apply_mds_symbolic(
    state: &[LinExpr; STATE_SIZE],
    mds: &[[F128; STATE_SIZE]; STATE_SIZE],
) -> [LinExpr; STATE_SIZE] {
    std::array::from_fn(|i| {
        let mut acc = LinExpr::zero();
        for j in 0..STATE_SIZE {
            acc = acc.add(&state[j].scale(mds[i][j]));
        }
        acc
    })
}

/// In-circuit Poseidon2b permutation over flat-basis state lanes.
/// Line-by-line shadow of `Poseidon2bPermutation::permute_mut` (which itself
/// runs in the flat basis): initial MDS_FULL, then 4 full / 58 partial / 4
/// full rounds. 360 multiplication constraints; every linear layer is
/// symbolic.
pub fn poseidon2b_permute(
    b: &mut FieldR1csBuilder,
    state: [LinExpr; STATE_SIZE],
) -> [LinExpr; STATE_SIZE] {
    let t = poseidon_flat_tables();
    let mut state = apply_mds_symbolic(&state, &t.mds_full);
    for r in 0..N_ROUNDS {
        if !(F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&r) {
            for (i, lane) in state.iter_mut().enumerate() {
                let x = lane.add_const(t.rc[i][r]);
                *lane = b.pow7(&x);
            }
            state = apply_mds_symbolic(&state, &t.mds_full);
        } else {
            let x = state[0].add_const(t.rc[0][r]);
            state[0] = b.pow7(&x);
            state = apply_mds_symbolic(&state, &t.mds_partial);
        }
    }
    state
}

/// Multiplication constraints per permutation (S-boxes only; MDS/RC are
/// symbolic): 8 full rounds × 4 lanes × 4 + 58 partial × 4 = **360**.
pub const POSEIDON2B_PERMUTE_CONSTRAINTS: usize = (F_ROUNDS * STATE_SIZE + P_ROUNDS) * 4;

// ---------------------------------------------------------------------------
// Fiat-Shamir channel trace gadget
// ---------------------------------------------------------------------------

/// In-circuit replay of the [`crate::challenger::FsLaneChallenger`] duplex
/// sponge — the LaneExpr pattern of `noid_recursive::fs_transcript`, lifted
/// to symbolic expressions. State lanes, buffering, padding and the pending
/// squeeze lane mirror the native challenger op for op; the op-header lanes
/// are the shared constants from `crate::challenger`.
///
/// Every observed value enters as a [`LinExpr`] (witness data or a public
/// constant); every squeeze returns the state-lane expression, which the
/// caller's replayed verifier algebra then consumes — the transcript
/// invariant of the recursion: the in-circuit channel matches the native
/// challenger bit-for-bit (permutation, IV, padding, absorb/squeeze order).
pub struct FsChannelTrace {
    state: [LinExpr; STATE_SIZE],
    buffered: Option<LinExpr>,
    pending: Option<LinExpr>,
    perms: usize,
    c1: bool,
}

impl FsChannelTrace {
    /// Mirror of `FsLaneChallenger::new(domain)`.
    pub fn new(b: &mut FieldR1csBuilder, domain: &[u8]) -> Self {
        Self::with_profile(b, domain, fs_lane_iv_flat(), false)
    }

    /// Mirror of `FsLaneChallenger::new_c1(domain)`.
    pub fn new_c1(b: &mut FieldR1csBuilder, domain: &[u8]) -> Self {
        Self::with_profile(b, domain, fs_c1_lane_iv_flat(), true)
    }

    fn with_profile(
        b: &mut FieldR1csBuilder,
        domain: &[u8],
        [iv0, iv1]: [F128; 2],
        c1: bool,
    ) -> Self {
        let mut t = Self {
            state: [
                LinExpr::zero(),
                LinExpr::zero(),
                LinExpr::constant(iv0),
                LinExpr::constant(iv1),
            ],
            buffered: None,
            pending: None,
            perms: 0,
            c1,
        };
        t.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_DOMAIN, 0, domain.len() as u64)),
        );
        for lane in fs_pack_bytes_lanes(domain) {
            t.absorb_lane(b, LinExpr::constant(lane));
        }
        t
    }

    /// Number of permutations executed so far (must match the native
    /// challenger's count in lockstep tests).
    pub fn perms(&self) -> usize {
        self.perms
    }

    fn permute(&mut self, b: &mut FieldR1csBuilder) {
        self.state = poseidon2b_permute(b, std::mem::take(&mut self.state));
        self.perms += 1;
    }

    /// Rate-2 absorb with pair buffering (mirror of the sponge byte buffer,
    /// which at the lane level always holds 0 or 1 whole lanes).
    fn absorb_lane(&mut self, b: &mut FieldR1csBuilder, lane: LinExpr) {
        self.pending = None;
        if let Some(first) = self.buffered.take() {
            self.state[0] = self.state[0].add(&first);
            self.state[1] = self.state[1].add(&lane);
            self.permute(b);
        } else {
            self.buffered = Some(lane);
        }
    }

    /// Commit a buffered odd lane with the sponge pad block.
    fn flush(&mut self, b: &mut FieldR1csBuilder) {
        if let Some(first) = self.buffered.take() {
            self.state[0] = self.state[0].add(&first);
            self.state[1] = self.state[1].add_const(fs_pad_lane_flat());
            self.permute(b);
        }
    }

    fn squeeze_lane(&mut self, b: &mut FieldR1csBuilder) -> LinExpr {
        if let Some(p) = self.pending.take() {
            return p;
        }
        self.flush(b);
        let out = self.state[0].clone();
        self.pending = Some(self.state[1].clone());
        self.permute(b);
        out
    }

    // ---- Challenger-op mirrors (same order and lane encoding as
    //      FsLaneChallenger) ------------------------------------------------

    pub fn observe_label(&mut self, b: &mut FieldR1csBuilder, label: &[u8]) {
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_LABEL, 0, label.len() as u64)),
        );
        for lane in fs_pack_bytes_lanes(label) {
            self.absorb_lane(b, LinExpr::constant(lane));
        }
    }

    pub fn observe_f128(&mut self, b: &mut FieldR1csBuilder, value: &LinExpr) {
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_OBSERVE, FS_KIND_SCALAR, 0)),
        );
        self.absorb_lane(b, value.clone());
    }

    pub fn observe_f128_slice(&mut self, b: &mut FieldR1csBuilder, values: &[LinExpr]) {
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(
                FS_OP_OBSERVE,
                FS_KIND_SLICE,
                values.len() as u64,
            )),
        );
        for v in values {
            self.absorb_lane(b, v.clone());
        }
    }

    pub fn observe_f256(&mut self, b: &mut FieldR1csBuilder, value: &ExtExpr) {
        assert!(
            self.c1,
            "wide transcript operation requires FsChannelTrace::new_c1"
        );
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_OBSERVE, FS_KIND_WIDE_SCALAR, 0)),
        );
        self.absorb_lane(b, value.lo.clone());
        self.absorb_lane(b, value.hi.clone());
    }

    pub fn observe_f256_slice(&mut self, b: &mut FieldR1csBuilder, values: &[ExtExpr]) {
        assert!(
            self.c1,
            "wide transcript operation requires FsChannelTrace::new_c1"
        );
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(
                FS_OP_OBSERVE,
                FS_KIND_WIDE_SLICE,
                values.len() as u64,
            )),
        );
        for value in values {
            self.absorb_lane(b, value.lo.clone());
            self.absorb_lane(b, value.hi.clone());
        }
    }

    /// Constant byte observation (statement digests, roots known at build
    /// time). Witness-carried byte data must be observed as lane expressions
    /// via [`Self::observe_lanes`] with the same header.
    pub fn observe_bytes_const(&mut self, b: &mut FieldR1csBuilder, bytes: &[u8]) {
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_BYTES, 0, bytes.len() as u64)),
        );
        for lane in fs_pack_bytes_lanes(bytes) {
            self.absorb_lane(b, LinExpr::constant(lane));
        }
    }

    /// Witness-carried byte observation: the caller supplies the packed
    /// lanes as expressions plus the true byte length for the header.
    pub fn observe_lanes(&mut self, b: &mut FieldR1csBuilder, byte_len: u64, lanes: &[LinExpr]) {
        assert_eq!(lanes.len() as u64, byte_len.div_ceil(16));
        self.absorb_lane(b, LinExpr::constant(fs_op_lane(FS_OP_BYTES, 0, byte_len)));
        for lane in lanes {
            self.absorb_lane(b, lane.clone());
        }
    }

    pub fn sample_f128(&mut self, b: &mut FieldR1csBuilder) -> LinExpr {
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SCALAR, 0)),
        );
        self.squeeze_lane(b)
    }

    pub fn sample_f128_vec(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<LinExpr> {
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SLICE, n as u64)),
        );
        (0..n).map(|_| self.squeeze_lane(b)).collect()
    }

    pub fn sample_f256(&mut self, b: &mut FieldR1csBuilder) -> ExtExpr {
        assert!(
            self.c1,
            "wide transcript operation requires FsChannelTrace::new_c1"
        );
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_WIDE_SCALAR, 0)),
        );
        let lo = self.squeeze_lane(b);
        let raw_hi = self.squeeze_lane(b);
        b.c1_challenge_from_raw(lo, raw_hi)
    }

    pub fn sample_f256_vec(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<ExtExpr> {
        assert!(
            self.c1,
            "wide transcript operation requires FsChannelTrace::new_c1"
        );
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_WIDE_SLICE, n as u64)),
        );
        (0..n)
            .map(|_| {
                let lo = self.squeeze_lane(b);
                let raw_hi = self.squeeze_lane(b);
                b.c1_challenge_from_raw(lo, raw_hi)
            })
            .collect()
    }

    /// In-trace mirror of `FsLaneChallenger::verify_pow` (GRIND-BY-SQUEEZE):
    /// absorb the `[FS_OP_POW header, nonce]` pair with the ordinary lane
    /// discipline, sample one scalar challenge and prove its top `bits`
    /// flat bits are zero (via a `128 − bits`-bit decomposition — the
    /// missing top wires force the zeros). The pow rides the transcript
    /// sponge itself — no separate PoW instance, no state peek — so a
    /// union recording carries it as plain schedule lanes.
    pub fn verify_pow_trace(&mut self, b: &mut FieldR1csBuilder, nonce: &LinExpr, bits: u32) {
        assert!(bits <= 64, "leading-zero window limited to the top limb");
        self.absorb_lane(b, LinExpr::constant(fs_op_lane(FS_OP_POW, 0, bits as u64)));
        self.absorb_lane(b, nonce.clone());
        let pt = self.sample_f128(b);
        if bits > 0 {
            // pt must satisfy: top `bits` bits zero ⇔ pt = Σ_{i<128−bits} b_i·x^i.
            b.decompose_bits_le(&pt, 128 - bits as usize);
        } else {
            // Zero-bit site: the canonical nonce is 0 (the native verifier's
            // non-malleability rule) — a zero-length decomposition pins it.
            b.decompose_bits_le(nonce, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// Channel abstraction: inline permutation replay vs union recording
// ---------------------------------------------------------------------------

/// The channel interface the deep-chain verifier twins consume, so one twin
/// body runs against either the inline permutation replay
/// ([`FsChannelTrace`]) or the union recorder ([`FsChannelUnionRecorder`])
/// that discharges the same transcript through a committed duplex-union
/// walk instead of in-trace permutations.
pub trait FsChannelOps {
    fn observe_label(&mut self, b: &mut FieldR1csBuilder, label: &[u8]);
    fn observe_f128(&mut self, b: &mut FieldR1csBuilder, value: &LinExpr);
    fn observe_f128_slice(&mut self, b: &mut FieldR1csBuilder, values: &[LinExpr]);
    fn observe_f256(&mut self, b: &mut FieldR1csBuilder, value: &ExtExpr) {
        self.observe_f128(b, &value.lo);
        self.observe_f128(b, &value.hi);
    }
    fn observe_f256_slice(&mut self, b: &mut FieldR1csBuilder, values: &[ExtExpr]) {
        for value in values {
            self.observe_f256(b, value);
        }
    }
    fn sample_f128(&mut self, b: &mut FieldR1csBuilder) -> LinExpr;
    /// One SLICE-kind squeeze header followed by `n` challenge reads — the
    /// native `sample_f128_vec` discipline (NOT `n` scalar samples, whose
    /// per-sample headers would diverge from the native transcript).
    fn sample_f128_vec(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<LinExpr>;
    fn sample_f256(&mut self, b: &mut FieldR1csBuilder) -> ExtExpr {
        let lanes = self.sample_f128_vec(b, 2);
        b.c1_challenge_from_raw(lanes[0].clone(), lanes[1].clone())
    }
    fn sample_f256_vec(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<ExtExpr> {
        (0..n).map(|_| self.sample_f256(b)).collect()
    }
    /// Grind-by-squeeze pow mirror: absorb the `[FS_OP_POW header, nonce]`
    /// pair, sample one scalar challenge and pin its top `bits` flat bits
    /// to zero (`FsLaneChallenger::verify_pow` lockstep).
    fn verify_pow(&mut self, b: &mut FieldR1csBuilder, nonce: &LinExpr, bits: u32);
    /// Constant byte observation (`FsLaneChallenger::observe_bytes` mirror
    /// for build-time constants: statement digests, baked roots).
    fn observe_bytes_const(&mut self, b: &mut FieldR1csBuilder, bytes: &[u8]);
    /// Witness-carried byte observation: packed lanes as expressions plus
    /// the true byte length for the header.
    fn observe_lanes(&mut self, b: &mut FieldR1csBuilder, byte_len: u64, lanes: &[LinExpr]);
}

impl<C: FsChannelOps + ?Sized> FsChannelOps for &mut C {
    fn observe_label(&mut self, b: &mut FieldR1csBuilder, label: &[u8]) {
        (**self).observe_label(b, label);
    }
    fn observe_f128(&mut self, b: &mut FieldR1csBuilder, value: &LinExpr) {
        (**self).observe_f128(b, value);
    }
    fn observe_f128_slice(&mut self, b: &mut FieldR1csBuilder, values: &[LinExpr]) {
        (**self).observe_f128_slice(b, values);
    }
    fn observe_f256(&mut self, b: &mut FieldR1csBuilder, value: &ExtExpr) {
        (**self).observe_f256(b, value);
    }
    fn observe_f256_slice(&mut self, b: &mut FieldR1csBuilder, values: &[ExtExpr]) {
        (**self).observe_f256_slice(b, values);
    }
    fn sample_f128(&mut self, b: &mut FieldR1csBuilder) -> LinExpr {
        (**self).sample_f128(b)
    }
    fn sample_f128_vec(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<LinExpr> {
        (**self).sample_f128_vec(b, n)
    }
    fn sample_f256(&mut self, b: &mut FieldR1csBuilder) -> ExtExpr {
        (**self).sample_f256(b)
    }
    fn sample_f256_vec(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<ExtExpr> {
        (**self).sample_f256_vec(b, n)
    }
    fn verify_pow(&mut self, b: &mut FieldR1csBuilder, nonce: &LinExpr, bits: u32) {
        (**self).verify_pow(b, nonce, bits);
    }
    fn observe_bytes_const(&mut self, b: &mut FieldR1csBuilder, bytes: &[u8]) {
        (**self).observe_bytes_const(b, bytes);
    }
    fn observe_lanes(&mut self, b: &mut FieldR1csBuilder, byte_len: u64, lanes: &[LinExpr]) {
        (**self).observe_lanes(b, byte_len, lanes);
    }
}

impl FsChannelOps for FsChannelTrace {
    fn observe_label(&mut self, b: &mut FieldR1csBuilder, label: &[u8]) {
        FsChannelTrace::observe_label(self, b, label);
    }
    fn observe_f128(&mut self, b: &mut FieldR1csBuilder, value: &LinExpr) {
        FsChannelTrace::observe_f128(self, b, value);
    }
    fn observe_f128_slice(&mut self, b: &mut FieldR1csBuilder, values: &[LinExpr]) {
        FsChannelTrace::observe_f128_slice(self, b, values);
    }
    fn observe_f256(&mut self, b: &mut FieldR1csBuilder, value: &ExtExpr) {
        FsChannelTrace::observe_f256(self, b, value);
    }
    fn observe_f256_slice(&mut self, b: &mut FieldR1csBuilder, values: &[ExtExpr]) {
        FsChannelTrace::observe_f256_slice(self, b, values);
    }
    fn sample_f128(&mut self, b: &mut FieldR1csBuilder) -> LinExpr {
        FsChannelTrace::sample_f128(self, b)
    }
    fn sample_f128_vec(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<LinExpr> {
        FsChannelTrace::sample_f128_vec(self, b, n)
    }
    fn sample_f256(&mut self, b: &mut FieldR1csBuilder) -> ExtExpr {
        FsChannelTrace::sample_f256(self, b)
    }
    fn sample_f256_vec(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<ExtExpr> {
        FsChannelTrace::sample_f256_vec(self, b, n)
    }
    fn verify_pow(&mut self, b: &mut FieldR1csBuilder, nonce: &LinExpr, bits: u32) {
        FsChannelTrace::verify_pow_trace(self, b, nonce, bits);
    }
    fn observe_bytes_const(&mut self, b: &mut FieldR1csBuilder, bytes: &[u8]) {
        FsChannelTrace::observe_bytes_const(self, b, bytes);
    }
    fn observe_lanes(&mut self, b: &mut FieldR1csBuilder, byte_len: u64, lanes: &[LinExpr]) {
        FsChannelTrace::observe_lanes(self, b, byte_len, lanes);
    }
}

/// A finished union recording: the class-fixed transcript schedule plus this
/// instance's witness lanes and challenge wires, ready for the duplex-union
/// discharge (`compile_duplex(&ops)` → committed columns; data cells pin to
/// `data_wires`, challenge carry cells pin to `challenge_wires`).
#[derive(Clone)]
pub struct RecordedChannel {
    pub ops: Vec<crate::deep_chain::schedule::TranscriptOp>,
    pub data_wires: Vec<LinExpr>,
    pub data_flat: Vec<F128>,
    pub challenge_wires: Vec<LinExpr>,
    /// Native post-transcript state lanes (flat) — the lockstep differential
    /// value gates compare against an inline replay.
    pub post_state: [F128; STATE_SIZE],
    /// Native transcript permutations executed (pad flushes included).
    pub perms: usize,
}

/// Value-only recording captured while the sound native verifier is already
/// replaying a proof.
///
/// The immutable [`DuplexLayout`] is the class-authenticated schedule.  A
/// [`LayoutRecordingChallenger`] accepts a native transcript lane only when
/// the corresponding layout cell has the same constant or is the next data
/// cell.  It therefore harvests exactly the data stream needed to prefill a
/// recording union without the former throwaway witness-only trace replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayoutRecordedChannel {
    pub layout: DuplexLayout,
    pub data_flat: Vec<F128>,
    /// Native challenge values when the ordinary Challenger API exposes
    /// them. PoW verification intentionally returns only a boolean, so those
    /// entries are `None`; the later trace-to-column pins remain authoritative
    /// for every challenge cell.
    pub challenges: Vec<Option<F128>>,
    pub post_state: [F128; STATE_SIZE],
    pub perms: usize,
}

/// Production Fiat-Shamir challenger plus a fail-closed, class-layout-checked
/// value recorder.
///
/// Challenges come from an ordinary [`FsLaneChallenger`], so native proof
/// verification is unchanged.  The recorder merely classifies each absorbed
/// lane through the frozen layout: constants must match exactly and only
/// `LaneSource::Data` cells are retained.  Any schedule mismatch is remembered
/// and reported by [`Self::finish`].
pub struct LayoutRecordingChallenger {
    inner: FsLaneChallenger,
    layout: DuplexLayout,
    data_flat: Vec<F128>,
    challenges: Vec<Option<F128>>,
    slot: usize,
    filled: usize,
    pending_challenge: Option<(usize, usize)>,
    valid: bool,
}

impl LayoutRecordingChallenger {
    pub fn new(domain: &[u8], layout: DuplexLayout) -> Self {
        Self::with_inner(domain, layout, FsLaneChallenger::new(domain))
    }

    pub fn new_c1(domain: &[u8], layout: DuplexLayout) -> Self {
        Self::with_inner(domain, layout, FsLaneChallenger::new_c1(domain))
    }

    fn with_inner(domain: &[u8], layout: DuplexLayout, inner: FsLaneChallenger) -> Self {
        let mut recorder = Self {
            inner,
            data_flat: Vec::with_capacity(layout.n_data),
            challenges: Vec::with_capacity(layout.challenges.len()),
            layout,
            slot: 0,
            filled: 0,
            pending_challenge: None,
            valid: true,
        };
        recorder.record_absorb(fs_op_lane(FS_OP_DOMAIN, 0, domain.len() as u64));
        for lane in fs_pack_bytes_lanes(domain) {
            recorder.record_absorb(lane);
        }
        recorder
    }

    #[inline]
    fn invalidate(&mut self) {
        self.valid = false;
    }

    fn record_absorb(&mut self, value: F128) {
        // Native lane semantics discard a buffered second squeeze as soon as
        // a new absorb begins. The eager empty permutation was already
        // consumed by record_squeeze, exactly as in compile_duplex.
        self.pending_challenge = None;
        let source = self
            .layout
            .slots
            .get(self.slot)
            .and_then(|slot| slot.lanes.get(self.filled))
            .copied()
            .flatten();
        match source {
            Some(LaneSource::Data(index)) => {
                if index != self.data_flat.len() {
                    self.invalidate();
                } else {
                    self.data_flat.push(value);
                }
            }
            Some(LaneSource::Const(expected)) => {
                if value != flat_of_tower_u128(expected) {
                    self.invalidate();
                }
            }
            None => self.invalidate(),
        }
        self.filled += 1;
        if self.filled == 2 {
            self.filled = 0;
            self.slot += 1;
        }
    }

    fn record_squeeze(&mut self, value: Option<F128>) {
        if self.filled == 1 {
            let expected_pad = self
                .layout
                .slots
                .get(self.slot)
                .and_then(|slot| slot.lanes[1]);
            let pad_tower =
                noid_core::hardware::flat_to_tower_u128(f128_to_u128(fs_pad_lane_flat()));
            if expected_pad != Some(LaneSource::Const(pad_tower)) {
                self.invalidate();
            }
            self.filled = 0;
            self.slot += 1;
        }

        let location = if let Some(pending) = self.pending_challenge.take() {
            pending
        } else if self.slot == 0 {
            self.invalidate();
            (0, 0)
        } else {
            let read_slot = self.slot - 1;
            let empty = self
                .layout
                .slots
                .get(self.slot)
                .is_some_and(|slot| slot.lanes == [None, None]);
            if !empty {
                self.invalidate();
            }
            self.slot += 1;
            self.pending_challenge = Some((read_slot, 1));
            (read_slot, 0)
        };
        if self.layout.challenges.get(self.challenges.len()) != Some(&location) {
            self.invalidate();
        }
        self.challenges.push(value);
    }

    fn record_scalar_sample_header(&mut self) {
        self.record_absorb(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SCALAR, 0));
    }

    /// Finish only if the native call stream consumed the complete frozen
    /// schedule and every data cell exactly once.
    pub fn finish(mut self) -> Result<LayoutRecordedChannel, &'static str> {
        // compile_duplex gives a trailing unpermuted odd absorb its own
        // partial slot so the data cell exists in the committed union.
        if self.filled == 1 {
            let trailing_none = self
                .layout
                .slots
                .get(self.slot)
                .is_some_and(|slot| slot.lanes[1].is_none());
            if !trailing_none {
                self.invalidate();
            }
            self.filled = 0;
            self.slot += 1;
        }
        if !self.valid
            || self.slot != self.layout.slots.len()
            || self.data_flat.len() != self.layout.n_data
            || self.challenges.len() != self.layout.challenges.len()
        {
            return Err(
                "native Fiat-Shamir call stream does not match the frozen recording layout",
            );
        }
        Ok(LayoutRecordedChannel {
            layout: self.layout,
            data_flat: self.data_flat,
            challenges: self.challenges,
            post_state: self.inner.post_state(),
            perms: self.inner.perms(),
        })
    }
}

impl Challenger for LayoutRecordingChallenger {
    fn observe_label(&mut self, label: &[u8]) {
        self.record_absorb(fs_op_lane(FS_OP_LABEL, 0, label.len() as u64));
        for lane in fs_pack_bytes_lanes(label) {
            self.record_absorb(lane);
        }
        self.inner.observe_label(label);
    }

    fn observe_f128(&mut self, value: F128) {
        self.record_absorb(fs_op_lane(FS_OP_OBSERVE, FS_KIND_SCALAR, 0));
        self.record_absorb(value);
        self.inner.observe_f128(value);
    }

    fn observe_f128_slice(&mut self, values: &[F128]) {
        self.record_absorb(fs_op_lane(
            FS_OP_OBSERVE,
            FS_KIND_SLICE,
            values.len() as u64,
        ));
        for &value in values {
            self.record_absorb(value);
        }
        self.inner.observe_f128_slice(values);
    }

    fn observe_f256(&mut self, value: F256) {
        self.record_absorb(fs_op_lane(FS_OP_OBSERVE, FS_KIND_WIDE_SCALAR, 0));
        self.record_absorb(value.lo);
        self.record_absorb(value.hi);
        self.inner.observe_f256(value);
    }

    fn observe_f256_slice(&mut self, values: &[F256]) {
        self.record_absorb(fs_op_lane(
            FS_OP_OBSERVE,
            FS_KIND_WIDE_SLICE,
            values.len() as u64,
        ));
        for value in values {
            self.record_absorb(value.lo);
            self.record_absorb(value.hi);
        }
        self.inner.observe_f256_slice(values);
    }

    fn observe_bytes(&mut self, bytes: &[u8]) {
        self.record_absorb(fs_op_lane(FS_OP_BYTES, 0, bytes.len() as u64));
        for lane in fs_pack_bytes_lanes(bytes) {
            self.record_absorb(lane);
        }
        self.inner.observe_bytes(bytes);
    }

    fn sample_f128(&mut self) -> F128 {
        self.record_scalar_sample_header();
        let value = self.inner.sample_f128();
        self.record_squeeze(Some(value));
        value
    }

    fn sample_f128_vec(&mut self, n: usize) -> Vec<F128> {
        self.record_absorb(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SLICE, n as u64));
        let values = self.inner.sample_f128_vec(n);
        for &value in &values {
            self.record_squeeze(Some(value));
        }
        values
    }

    fn sample_f256(&mut self) -> F256 {
        self.record_absorb(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_WIDE_SCALAR, 0));
        let (challenge, raw) = self.inner.sample_f256_with_raw();
        self.record_squeeze(Some(raw[0]));
        self.record_squeeze(Some(raw[1]));
        challenge
    }

    fn sample_f256_vec(&mut self, n: usize) -> Vec<F256> {
        self.record_absorb(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_WIDE_SLICE, n as u64));
        let draws = self.inner.sample_f256_vec_with_raw(n);
        draws
            .into_iter()
            .map(|(challenge, raw)| {
                self.record_squeeze(Some(raw[0]));
                self.record_squeeze(Some(raw[1]));
                challenge
            })
            .collect()
    }

    fn grind_pow(&mut self, bits: u32) -> u64 {
        let nonce = self.inner.grind_pow(bits);
        self.record_absorb(fs_op_lane(FS_OP_POW, 0, bits as u64));
        self.record_absorb(F128 { lo: nonce, hi: 0 });
        self.record_scalar_sample_header();
        self.record_squeeze(None);
        nonce
    }

    fn verify_pow(&mut self, nonce: u64, bits: u32) -> bool {
        self.record_absorb(fs_op_lane(FS_OP_POW, 0, bits as u64));
        self.record_absorb(F128 { lo: nonce, hi: 0 });
        self.record_scalar_sample_header();
        let accepted = self.inner.verify_pow(nonce, bits);
        self.record_squeeze(None);
        accepted
    }
}

/// Union-mode twin channel: RECORDS the transcript instead of replaying its
/// permutations in-trace.
///
/// Drop-in for [`FsChannelTrace`] behind [`FsChannelOps`]: the twin's
/// verifier algebra runs unchanged, but every absorb lane lands in a
/// [`crate::deep_chain::schedule::TranscriptOp`] schedule — protocol
/// constants as `Some(tower pattern)`, witness lanes as `None` plus the
/// lane's expression and native value — and every sampled challenge returns
/// a FRESH witness wire carrying the native challenge value. The schedule is
/// class-fixed because the twin's control flow is (op counts derive from
/// class parameters); constant-vs-data is decided by the expression form,
/// which is deterministic per call site.
///
/// The lane discipline (rate-2 pair buffering, pad lane on an odd flush,
/// pending second squeeze lane, absorb-after-squeeze reset) mirrors
/// [`FsChannelTrace`] exactly, and `compile_duplex` implements the same
/// discipline slot-for-slot — the pad lane is therefore NOT emitted into
/// the schedule (the compiler inserts the same constant itself). The native
/// state runs alongside so sampled values are real; the post-state
/// differential against an inline replay is the lockstep gate.
pub struct FsChannelUnionRecorder {
    state: [F128; STATE_SIZE],
    buffered: Option<F128>,
    pending: Option<F128>,
    /// Absorb lanes accumulated since the last emitted op.
    cur_absorb: Vec<Option<u128>>,
    ops: Vec<crate::deep_chain::schedule::TranscriptOp>,
    data_wires: Vec<LinExpr>,
    data_flat: Vec<F128>,
    challenge_wires: Vec<LinExpr>,
    perms: usize,
    c1: bool,
}

impl FsChannelUnionRecorder {
    /// Mirror of `FsChannelTrace::new(domain)`: LANECHAL capacity IV, then
    /// the domain-op header and label lanes (all protocol constants).
    pub fn new(domain: &[u8]) -> Self {
        Self::with_profile(domain, fs_lane_iv_flat(), false)
    }

    /// C1 recorder using the wide transcript capacity domain and canonical
    /// extension-field frames.
    pub fn new_c1(domain: &[u8]) -> Self {
        Self::with_profile(domain, fs_c1_lane_iv_flat(), true)
    }

    fn with_profile(domain: &[u8], [iv0, iv1]: [F128; 2], c1: bool) -> Self {
        let mut t = Self {
            state: [F128::ZERO, F128::ZERO, iv0, iv1],
            buffered: None,
            pending: None,
            cur_absorb: Vec::new(),
            ops: Vec::new(),
            data_wires: Vec::new(),
            data_flat: Vec::new(),
            challenge_wires: Vec::new(),
            perms: 0,
            c1,
        };
        t.absorb_const(fs_op_lane(FS_OP_DOMAIN, 0, domain.len() as u64));
        for lane in fs_pack_bytes_lanes(domain) {
            t.absorb_const(lane);
        }
        t
    }

    /// The capacity IV the discharge seeds the duplex columns with.
    pub fn capacity_iv_flat() -> [F128; 2] {
        fs_lane_iv_flat()
    }

    pub fn capacity_iv_flat_c1() -> [F128; 2] {
        fs_c1_lane_iv_flat()
    }

    fn flat_bits(v: F128) -> u128 {
        (v.lo as u128) | ((v.hi as u128) << 64)
    }

    fn permute(&mut self) {
        let mut lanes: [u128; STATE_SIZE] = std::array::from_fn(|i| Self::flat_bits(self.state[i]));
        noid_poseidon2b::native::permutation::permute_flat_u128(&mut lanes);
        self.state = std::array::from_fn(|i| F128 {
            lo: lanes[i] as u64,
            hi: (lanes[i] >> 64) as u64,
        });
        self.perms += 1;
    }

    fn absorb_native(&mut self, v: F128) {
        self.pending = None;
        if let Some(first) = self.buffered.take() {
            self.state[0] += first;
            self.state[1] += v;
            self.permute();
        } else {
            self.buffered = Some(v);
        }
    }

    fn absorb_const(&mut self, c: F128) {
        self.cur_absorb
            .push(Some(noid_core::hardware::flat_to_tower_u128(
                Self::flat_bits(c),
            )));
        self.absorb_native(c);
    }

    fn absorb_expr(&mut self, b: &FieldR1csBuilder, e: &LinExpr) {
        if e.is_const() {
            self.absorb_const(e.constant);
        } else {
            let v = e.eval(b.values());
            self.cur_absorb.push(None);
            self.data_wires.push(e.clone());
            self.data_flat.push(v);
            self.absorb_native(v);
        }
    }

    fn close_absorb(&mut self) {
        if !self.cur_absorb.is_empty() {
            self.ops
                .push(crate::deep_chain::schedule::TranscriptOp::Absorb(
                    std::mem::take(&mut self.cur_absorb),
                ));
        }
    }

    fn squeeze_native(&mut self) -> F128 {
        if let Some(p) = self.pending.take() {
            return p;
        }
        if let Some(first) = self.buffered.take() {
            self.state[0] += first;
            self.state[1] += fs_pad_lane_flat();
            self.permute();
        }
        let out = self.state[0];
        self.pending = Some(self.state[1]);
        self.permute();
        out
    }

    /// Finish: emit any trailing absorb op and return the recording.
    pub fn finish(mut self) -> RecordedChannel {
        self.close_absorb();
        RecordedChannel {
            ops: self.ops,
            data_wires: self.data_wires,
            data_flat: self.data_flat,
            challenge_wires: self.challenge_wires,
            post_state: self.state,
            perms: self.perms,
        }
    }
}

impl FsChannelOps for FsChannelUnionRecorder {
    fn observe_label(&mut self, _b: &mut FieldR1csBuilder, label: &[u8]) {
        self.absorb_const(fs_op_lane(FS_OP_LABEL, 0, label.len() as u64));
        for lane in fs_pack_bytes_lanes(label) {
            self.absorb_const(lane);
        }
    }

    fn observe_f128(&mut self, b: &mut FieldR1csBuilder, value: &LinExpr) {
        self.absorb_const(fs_op_lane(FS_OP_OBSERVE, FS_KIND_SCALAR, 0));
        self.absorb_expr(b, value);
    }

    fn observe_f128_slice(&mut self, b: &mut FieldR1csBuilder, values: &[LinExpr]) {
        self.absorb_const(fs_op_lane(
            FS_OP_OBSERVE,
            FS_KIND_SLICE,
            values.len() as u64,
        ));
        for v in values {
            self.absorb_expr(b, v);
        }
    }

    fn observe_f256(&mut self, b: &mut FieldR1csBuilder, value: &ExtExpr) {
        assert!(self.c1, "wide transcript operation requires new_c1");
        self.absorb_const(fs_op_lane(FS_OP_OBSERVE, FS_KIND_WIDE_SCALAR, 0));
        self.absorb_expr(b, &value.lo);
        self.absorb_expr(b, &value.hi);
    }

    fn observe_f256_slice(&mut self, b: &mut FieldR1csBuilder, values: &[ExtExpr]) {
        assert!(self.c1, "wide transcript operation requires new_c1");
        self.absorb_const(fs_op_lane(
            FS_OP_OBSERVE,
            FS_KIND_WIDE_SLICE,
            values.len() as u64,
        ));
        for value in values {
            self.absorb_expr(b, &value.lo);
            self.absorb_expr(b, &value.hi);
        }
    }

    fn sample_f128(&mut self, b: &mut FieldR1csBuilder) -> LinExpr {
        self.absorb_const(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SCALAR, 0));
        self.close_absorb();
        self.ops
            .push(crate::deep_chain::schedule::TranscriptOp::Squeeze(1));
        let v = self.squeeze_native();
        let w = LinExpr::from_wire(b.alloc_f128(v));
        self.challenge_wires.push(w.clone());
        w
    }

    fn sample_f128_vec(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<LinExpr> {
        self.absorb_const(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SLICE, n as u64));
        self.close_absorb();
        self.ops
            .push(crate::deep_chain::schedule::TranscriptOp::Squeeze(n));
        (0..n)
            .map(|_| {
                let v = self.squeeze_native();
                let w = LinExpr::from_wire(b.alloc_f128(v));
                self.challenge_wires.push(w.clone());
                w
            })
            .collect()
    }

    fn sample_f256(&mut self, b: &mut FieldR1csBuilder) -> ExtExpr {
        assert!(self.c1, "wide transcript operation requires new_c1");
        self.absorb_const(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_WIDE_SCALAR, 0));
        self.close_absorb();
        self.ops
            .push(crate::deep_chain::schedule::TranscriptOp::Squeeze(2));
        let lo = LinExpr::from_wire(b.alloc_f128(self.squeeze_native()));
        let raw_hi = LinExpr::from_wire(b.alloc_f128(self.squeeze_native()));
        self.challenge_wires.push(lo.clone());
        self.challenge_wires.push(raw_hi.clone());
        b.c1_challenge_from_raw(lo, raw_hi)
    }

    fn sample_f256_vec(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<ExtExpr> {
        assert!(self.c1, "wide transcript operation requires new_c1");
        self.absorb_const(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_WIDE_SLICE, n as u64));
        self.close_absorb();
        self.ops
            .push(crate::deep_chain::schedule::TranscriptOp::Squeeze(2 * n));
        (0..n)
            .map(|_| {
                let lo = LinExpr::from_wire(b.alloc_f128(self.squeeze_native()));
                let raw_hi = LinExpr::from_wire(b.alloc_f128(self.squeeze_native()));
                self.challenge_wires.push(lo.clone());
                self.challenge_wires.push(raw_hi.clone());
                b.c1_challenge_from_raw(lo, raw_hi)
            })
            .collect()
    }

    fn verify_pow(&mut self, b: &mut FieldR1csBuilder, nonce: &LinExpr, bits: u32) {
        assert!(bits <= 64, "leading-zero window limited to the top limb");
        self.absorb_const(fs_op_lane(FS_OP_POW, 0, bits as u64));
        self.absorb_expr(b, nonce);
        self.absorb_const(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SCALAR, 0));
        self.close_absorb();
        self.ops
            .push(crate::deep_chain::schedule::TranscriptOp::Squeeze(1));
        let v = self.squeeze_native();
        let pt = LinExpr::from_wire(b.alloc_f128(v));
        self.challenge_wires.push(pt.clone());
        if bits > 0 {
            // pt's top `bits` flat bits must be zero (same pin as the inline
            // twin; the challenge cell binds pt to the recorded transcript).
            b.decompose_bits_le(&pt, 128 - bits as usize);
        } else {
            // Zero-bit site: canonical nonce 0 (non-malleability rule).
            b.decompose_bits_le(nonce, 0);
        }
    }

    fn observe_bytes_const(&mut self, _b: &mut FieldR1csBuilder, bytes: &[u8]) {
        self.absorb_const(fs_op_lane(FS_OP_BYTES, 0, bytes.len() as u64));
        for lane in fs_pack_bytes_lanes(bytes) {
            self.absorb_const(lane);
        }
    }

    fn observe_lanes(&mut self, b: &mut FieldR1csBuilder, byte_len: u64, lanes: &[LinExpr]) {
        assert_eq!(lanes.len() as u64, byte_len.div_ceil(16));
        self.absorb_const(fs_op_lane(FS_OP_BYTES, 0, byte_len));
        for lane in lanes {
            self.absorb_expr(b, lane);
        }
    }
}

// ---------------------------------------------------------------------------
// Raw Fiat-Shamir channel trace gadget
// ---------------------------------------------------------------------------

/// In-circuit replay of the production killshot channel
/// (`noid_poseidon2b::channel::Poseidon2bChannel` — the `FiatShamir<Block128>`
/// implementation every `noid_gkr` verifier runs on). Unlike
/// [`FsChannelTrace`], the raw channel has NO op-header lanes and NO domain
/// absorb: it is a bare rate-2 duplex seeded with the `KSCHANNL` capacity IV,
/// where every absorbed `Block128` is one whole lane and every squeeze emits
/// `state[0]` / holds `state[1]` pending.
///
/// Basis: absorbed tower values enter as their flat (GCM) images
/// (`flat_const` for constants, φ-mapped witness wires otherwise); squeezed
/// expressions evaluate to the flat images of the native channel's tower
/// challenges. XOR commutes with φ and the permutation gadget shadows the
/// native permutation on flat images, so the trace state is φ(native state)
/// lane-for-lane (the transcript-lockstep invariant).
pub struct RawChannelTrace {
    state: [LinExpr; STATE_SIZE],
    buffered: Option<LinExpr>,
    pending: Option<LinExpr>,
    perms: usize,
}

impl RawChannelTrace {
    /// Mirror of `Poseidon2bChannel::new()`: zero rate lanes, `KSCHANNL`
    /// capacity IV, empty buffer, no pending challenge.
    pub fn new() -> Self {
        let [iv0, iv1] = crate::challenger::ks_channel_iv_flat();
        Self {
            state: [
                LinExpr::zero(),
                LinExpr::zero(),
                LinExpr::constant(iv0),
                LinExpr::constant(iv1),
            ],
            buffered: None,
            pending: None,
            perms: 0,
        }
    }

    /// Transcript permutations executed so far (lockstep pin).
    pub fn perms(&self) -> usize {
        self.perms
    }

    fn permute(&mut self, b: &mut FieldR1csBuilder) {
        self.state = poseidon2b_permute(b, std::mem::take(&mut self.state));
        self.perms += 1;
    }

    /// Mirror of `FiatShamir::absorb`: one whole lane, rate-2 pair buffering
    /// (`Poseidon2bSponge::update` with 16-byte writes keeps 0 or 1 whole
    /// lanes buffered). Absorbing invalidates any pending challenge.
    pub fn absorb(&mut self, b: &mut FieldR1csBuilder, lane: &LinExpr) {
        self.pending = None;
        if let Some(first) = self.buffered.take() {
            self.state[0] = self.state[0].add(&first);
            self.state[1] = self.state[1].add(lane);
            self.permute(b);
        } else {
            self.buffered = Some(lane.clone());
        }
    }

    /// Absorb a build-time constant (tower basis), φ-mapped.
    pub fn absorb_const_tower(&mut self, b: &mut FieldR1csBuilder, tower: u128) {
        self.absorb(b, &LinExpr::constant(flat_const(tower)));
    }

    /// Mirror of `Poseidon2bSponge::flush_to_squeeze`: commit a buffered odd
    /// lane with the sponge pad block (`0x80 … 0x01`).
    fn flush(&mut self, b: &mut FieldR1csBuilder) {
        if let Some(first) = self.buffered.take() {
            self.state[0] = self.state[0].add(&first);
            self.state[1] = self.state[1].add_const(crate::challenger::fs_pad_lane_flat());
            self.permute(b);
        }
    }

    /// Mirror of `Poseidon2bChannel::squeeze`: pending lane if buffered from
    /// the previous squeeze, else flush + emit `state[0]`, hold `state[1]`
    /// pending, advance the sponge.
    pub fn squeeze(&mut self, b: &mut FieldR1csBuilder) -> LinExpr {
        if let Some(p) = self.pending.take() {
            return p;
        }
        self.flush(b);
        let out = self.state[0].clone();
        self.pending = Some(self.state[1].clone());
        self.permute(b);
        out
    }

    /// Mirror of `FiatShamir::squeeze_n`.
    pub fn squeeze_n(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<LinExpr> {
        (0..n).map(|_| self.squeeze(b)).collect()
    }
}

impl Default for RawChannelTrace {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::{Challenger, FsLaneChallenger};
    use noid_core::hardware::clmul_gcm;
    use noid_core::{Block128, TowerField};
    use noid_poseidon2b::native::permutation::Poseidon2bPermutation;

    #[test]
    fn deferred_witness_slot_is_builder_branded_and_single_use() {
        let initial = F128 { lo: 7, hi: 11 };
        let sealed = F128 { lo: 13, hi: 17 };
        let mut owner = FieldR1csBuilder::new_witness_only();
        let (wire, slot) = owner.alloc_deferred_f128(initial);
        let mut other = FieldR1csBuilder::new_witness_only();
        assert_eq!(
            other.seal_deferred_f128(slot, sealed),
            Err(DeferredWitnessSlotError::WrongBuilder)
        );

        // A wrong-builder attempt consumes the linear token; the owner can no
        // longer finish, rather than gaining a retryable arbitrary patch.
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.build_witness_only()
        }))
        .is_err());
        assert_eq!(wire.0, 1);
    }

    #[test]
    fn deferred_witness_seal_preserves_the_ordinary_free_row_shape() {
        let initial = F128 { lo: 19, hi: 23 };
        let sealed = F128 { lo: 29, hi: 31 };

        let mut deferred = FieldR1csBuilder::new();
        let (wire, slot) = deferred.alloc_deferred_f128(initial);
        deferred
            .seal_deferred_f128(slot, sealed)
            .expect("owner seals its exact slot");
        let (deferred_matrix, deferred_witness) = deferred.build();

        let mut ordinary = FieldR1csBuilder::new();
        let ordinary_wire = ordinary.alloc_f128(sealed);
        let (ordinary_matrix, ordinary_witness) = ordinary.build();

        assert_eq!(wire, ordinary_wire);
        assert_eq!(
            deferred_matrix.statement_digest(),
            ordinary_matrix.statement_digest()
        );
        assert_eq!(deferred_witness, ordinary_witness);
        assert!(deferred_matrix.satisfies(&deferred_witness));
    }

    #[test]
    fn deferred_witness_cannot_feed_computed_rows_before_seal() {
        let mut builder = FieldR1csBuilder::new_witness_only();
        let (wire, slot) = builder.alloc_deferred_f128(F128::ZERO);
        let expression = LinExpr::from_wire(wire);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            builder.mul(&expression, &LinExpr::constant(F128::ONE));
        }))
        .is_err());
        builder
            .seal_deferred_f128(slot, F128::ONE)
            .expect("deferred owner remains sealable after dependency rejection");
        builder.mul(&expression, &LinExpr::constant(F128::ONE));
        let (_, witness) = builder.build_witness_only();
        assert_eq!(witness[wire.0 as usize], F128::ONE);
    }

    #[test]
    fn deferred_witness_cannot_feed_bit_decomposition_before_seal() {
        let mut builder = FieldR1csBuilder::new_witness_only();
        let (wire, slot) = builder.alloc_deferred_f128(F128::ZERO);
        let expression = LinExpr::from_wire(wire);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            builder.decompose_bits_le(&expression, 1);
        }))
        .is_err());
        builder
            .seal_deferred_f128(slot, F128::ONE)
            .expect("deferred owner remains sealable after dependency rejection");
        builder.decompose_bits_le(&expression, 1);
        let (_, witness) = builder.build_witness_only();
        assert_eq!(witness[wire.0 as usize], F128::ONE);
    }

    #[test]
    fn deferred_constraint_reuses_reserved_row_with_future_wires() {
        let arm0_value = F128 { lo: 7, hi: 11 };
        let arm1_value = F128 { lo: 13, hi: 17 };

        let mut builder = FieldR1csBuilder::new();
        let (cell_wire, slot) = builder.alloc_deferred_constraint_f128(arm1_value);
        let arm0 = LinExpr::from_wire(builder.alloc_f128(arm0_value));
        let arm1 = LinExpr::from_wire(builder.alloc_f128(arm1_value));
        let selector = LinExpr::from_wire(builder.alloc_bool(true));
        let product = LinExpr::from_wire(builder.mul(&selector, &arm0.add(&arm1)));
        let one = builder.one();
        builder
            .seal_deferred_constraint(slot, &arm0.add(&product), &one)
            .expect("selected future-wire equality seals reserved row");
        let useful_rows = builder.num_wires();
        let (matrix, witness) = builder.build();
        assert_eq!(useful_rows, 6, "row reuse allocated an extra pin");
        assert!(matrix.satisfies(&witness));

        let mut bad_cell = witness.clone();
        bad_cell[cell_wire.0 as usize] += F128::ONE;
        assert!(!matrix.satisfies(&bad_cell));
        let mut bad_arm = witness.clone();
        bad_arm[arm1.terms[0].0 as usize] += F128::ONE;
        assert!(!matrix.satisfies(&bad_arm));
    }

    #[test]
    fn deferred_constraint_gates_a_unique_source_in_one_new_row() {
        let value = F128 { lo: 19, hi: 23 };
        let mut builder = FieldR1csBuilder::new();
        let (cell_wire, slot) = builder.alloc_deferred_constraint_f128(value);
        let cell = LinExpr::from_wire(cell_wire);
        let source = LinExpr::from_wire(builder.alloc_f128(value));
        let gate = LinExpr::from_wire(builder.alloc_bool(true));
        let product = LinExpr::from_wire(builder.mul(&gate, &source.add(&cell)));
        let one = builder.one();
        builder
            .seal_deferred_constraint(slot, &cell.add(&product), &one)
            .expect("gated source equality seals reserved row");
        let useful_rows = builder.num_wires();
        let (matrix, witness) = builder.build();
        assert_eq!(useful_rows, 5, "unique binding allocated an extra pin");
        assert!(matrix.satisfies(&witness));

        let mut bad_source = witness.clone();
        bad_source[source.terms[0].0 as usize] += F128::ONE;
        assert!(!matrix.satisfies(&bad_source));
    }

    fn drive_mixed_gadgets(b: &mut FieldR1csBuilder) {
        let mut rng = Rng::new(0xF00D);
        let xs: Vec<LinExpr> = (0..8)
            .map(|_| LinExpr::from_wire(b.alloc_f128(rng.f128())))
            .collect();
        let _p = b.alloc_public_f128(F128 { lo: 5, hi: 9 });
        let _bit = b.alloc_bool(true);
        let prod = LinExpr::from_wire(b.mul(&xs[0], &xs[1]));
        let combo = prod
            .add(&xs[2])
            .scale(F128 { lo: 3, hi: 1 })
            .add_const(F128::ONE);
        let m = LinExpr::from_wire(b.materialize(&combo));
        let mv = m.eval(b.values());
        b.pin_f128(&m, mv);
        let mut ch = FsChannelTrace::new(b, b"witness-only-parity");
        ch.observe_f128_slice(b, &xs);
        let c = ch.sample_f128(b);
        let s = b.mul(&c, &xs[3]);
        let sv = LinExpr::from_wire(s).eval(b.values());
        b.pin_f128(&LinExpr::from_wire(s), sv);
    }

    /// Witness-only builder parity: identical wire numbering and witness
    /// values with the row accumulation skipped, and the witness satisfies
    /// the FULL build's matrix — the steady-state link rebuild (which adopts
    /// the class-fixed matrix of a previous instance) rests on exactly this.
    #[test]
    fn witness_only_builder_matches_full_build() {
        let mut full = FieldR1csBuilder::new();
        drive_mixed_gadgets(&mut full);
        let (r1cs, w_full) = full.build();

        let mut wo = FieldR1csBuilder::new_witness_only();
        drive_mixed_gadgets(&mut wo);
        let (n_wires, w_wo) = wo.build_witness_only();

        assert_eq!(n_wires, r1cs.useful_rows, "wire count parity");
        assert_eq!(w_full, w_wo, "witness parity");
        assert!(
            r1cs.satisfies(&w_wo),
            "witness-only witness on the full matrix"
        );
    }

    /// The union recorder must be bit-lockstep with the inline channel twin
    /// (same challenges, same permutation count), and its recorded schedule
    /// must reproduce the same challenges when compiled and run through the
    /// duplex-column builder — the exact machinery the region discharge
    /// pins against.
    #[test]
    fn union_recorder_locksteps_inline_channel_and_duplex_columns() {
        use crate::deep_chain::schedule::{build_duplex_columns, compile_duplex};

        fn drive<C: FsChannelOps>(
            ch: &mut C,
            b: &mut FieldR1csBuilder,
            wires: &[LinExpr],
        ) -> Vec<LinExpr> {
            let mut chals = Vec::new();
            ch.observe_label(b, b"stage-1");
            ch.observe_f128(b, &LinExpr::constant(F128 { lo: 42, hi: 7 }));
            ch.observe_f128(b, &wires[0]);
            chals.push(ch.sample_f128(b));
            ch.observe_f128_slice(b, &wires[1..4]);
            chals.push(ch.sample_f128(b));
            chals.push(ch.sample_f128(b)); // back-to-back squeezes
            chals.extend(ch.sample_f128_vec(b, 3)); // SLICE-header vec draw
            ch.observe_f128_slice(b, &wires[4..7]);
            ch.observe_label(b, b"stage-2");
            chals.push(ch.sample_f128(b));
            // Odd-parity tail after the last squeeze: the final data lane
            // lands in a trailing partial-absorb slot that `compile_duplex`
            // must flush into the layout.
            ch.observe_f128_slice(b, &wires[..2]);
            chals
        }

        let mut b = FieldR1csBuilder::new();
        let mut rng = Rng::new(0xD00D);
        let data: Vec<F128> = (0..7).map(|_| rng.f128()).collect();
        let wires: Vec<LinExpr> = data
            .iter()
            .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
            .collect();

        let mut inline = FsChannelTrace::new(&mut b, b"union-recorder-lockstep");
        let chal_inline = drive(&mut inline, &mut b, &wires);
        let mut rec = FsChannelUnionRecorder::new(b"union-recorder-lockstep");
        let chal_rec = drive(&mut rec, &mut b, &wires);
        let rc = rec.finish();

        let vals = b.values().to_vec();
        assert_eq!(chal_inline.len(), chal_rec.len());
        for (k, (ci, cr)) in chal_inline.iter().zip(chal_rec.iter()).enumerate() {
            assert_eq!(ci.eval(&vals), cr.eval(&vals), "challenge {k} diverges");
        }
        assert_eq!(inline.perms(), rc.perms, "permutation count diverges");
        assert_eq!(rc.data_flat.len(), 9, "exactly the witness lanes are data");
        for (dw, df) in rc.data_wires.iter().zip(rc.data_flat.iter()) {
            assert_eq!(dw.eval(&vals), *df, "data wire/value mismatch");
        }

        // Compile the recorded schedule and rebuild the columns natively:
        // the challenge carry cells must reproduce the sampled values.
        let layout = compile_duplex(&rc.ops);
        assert_eq!(layout.n_data, rc.data_flat.len(), "data lane count");
        let block_log = layout.slots.len().next_power_of_two().trailing_zeros() as usize;
        let cols = build_duplex_columns(
            &layout,
            FsChannelUnionRecorder::capacity_iv_flat(),
            &rc.data_flat,
            block_log,
        );
        assert_eq!(cols.challenges.len(), rc.challenge_wires.len());
        for (k, cw) in rc.challenge_wires.iter().enumerate() {
            assert_eq!(
                cols.challenges[k],
                cw.eval(&vals),
                "duplex column challenge {k} diverges from the recording"
            );
        }
    }

    /// A sound native verifier can harvest the recording values through the
    /// frozen layout while producing the exact same challenges as the normal
    /// lane challenger. This is the differential lock for removing a second,
    /// throwaway trace replay from production Link assembly.
    #[test]
    fn layout_recording_challenger_matches_union_recorder() {
        use crate::challenger::Challenger;
        use crate::deep_chain::schedule::compile_duplex;

        let mut b = FieldR1csBuilder::new_witness_only();
        let values = (0..7)
            .map(|i| F128 {
                lo: 0xA500 + i,
                hi: 0x5A00 + 3 * i,
            })
            .collect::<Vec<_>>();
        let wires = values
            .iter()
            .map(|&value| LinExpr::from_wire(b.alloc_f128(value)))
            .collect::<Vec<_>>();
        let constant = F128 { lo: 42, hi: 7 };

        let mut trace = FsChannelUnionRecorder::new(b"layout-native-lockstep");
        trace.observe_label(&mut b, b"stage-1");
        trace.observe_f128(&mut b, &LinExpr::constant(constant));
        trace.observe_f128(&mut b, &wires[0]);
        let mut trace_challenges = vec![trace.sample_f128(&mut b)];
        trace.observe_f128_slice(&mut b, &wires[1..4]);
        trace_challenges.extend(trace.sample_f128_vec(&mut b, 3));
        trace.observe_f128_slice(&mut b, &wires[4..7]);
        trace.observe_label(&mut b, b"stage-2");
        trace_challenges.push(trace.sample_f128(&mut b));
        // Exercise the special Challenger::verify_pow call stream too. Its
        // challenge is deliberately opaque in the native API.
        trace.verify_pow(&mut b, &LinExpr::constant(F128::ZERO), 0);
        trace.observe_f128_slice(&mut b, &wires[..2]);
        let recorded = trace.finish();
        let layout = compile_duplex(&recorded.ops);

        let mut native = LayoutRecordingChallenger::new(b"layout-native-lockstep", layout.clone());
        native.observe_label(b"stage-1");
        native.observe_f128(constant);
        native.observe_f128(values[0]);
        let mut native_challenges = vec![native.sample_f128()];
        native.observe_f128_slice(&values[1..4]);
        native_challenges.extend(native.sample_f128_vec(3));
        native.observe_f128_slice(&values[4..7]);
        native.observe_label(b"stage-2");
        native_challenges.push(native.sample_f128());
        assert!(native.verify_pow(0, 0));
        native.observe_f128_slice(&values[..2]);
        let captured = native
            .finish()
            .expect("frozen layout matches native replay");

        assert_eq!(captured.layout, layout);
        assert_eq!(captured.data_flat, recorded.data_flat);
        assert_eq!(captured.post_state, recorded.post_state);
        assert_eq!(captured.perms, recorded.perms);
        assert_eq!(native_challenges.len(), trace_challenges.len());
        for (native, trace) in native_challenges.iter().zip(&trace_challenges) {
            assert_eq!(*native, trace.eval(b.values()));
        }
        let exposed = captured
            .challenges
            .iter()
            .filter_map(|value| *value)
            .collect::<Vec<_>>();
        // All ordinary samples are exposed; only the PoW sample is opaque.
        assert_eq!(exposed, native_challenges);
    }

    #[test]
    fn c1_layout_and_union_recorders_bind_raw_wide_sponge_lanes() {
        use crate::deep_chain::schedule::{build_duplex_columns, compile_duplex};

        let domain = b"c1-layout-native-lockstep";
        let values = [
            F256::new(F128::new(0x11, 0x12), F128::new(0x13, 0x14)),
            F256::new(F128::new(0x21, 0x22), F128::new(0x23, 0x24)),
            F256::new(F128::new(0x31, 0x32), F128::new(0x33, 0x34)),
        ];
        let mut b = FieldR1csBuilder::new();
        let expressions = values.map(|value| {
            ExtExpr::new(
                LinExpr::from_wire(b.alloc_f128(value.lo)),
                LinExpr::from_wire(b.alloc_f128(value.hi)),
            )
        });

        let mut trace = FsChannelUnionRecorder::new_c1(domain);
        trace.observe_label(&mut b, b"wide-stage");
        trace.observe_f256(&mut b, &expressions[0]);
        trace.observe_f256_slice(&mut b, &expressions[1..]);
        let trace_scalar = trace.sample_f256(&mut b);
        let trace_wide = trace.sample_f256_vec(&mut b, 4);
        let trace_raw = trace.sample_f128_vec(&mut b, 3);
        let recorded = trace.finish();
        let layout = compile_duplex(&recorded.ops);

        let mut native = LayoutRecordingChallenger::new_c1(domain, layout.clone());
        native.observe_label(b"wide-stage");
        native.observe_f256(values[0]);
        native.observe_f256_slice(&values[1..]);
        let native_scalar = native.sample_f256();
        let native_wide = native.sample_f256_vec(4);
        let native_raw = native.sample_f128_vec(3);
        let captured = native
            .finish()
            .expect("C1 native call stream matches its frozen wide layout");

        assert_eq!(trace_scalar.eval(b.values()), native_scalar);
        assert!(!native_scalar.is_in_base_subfield());
        for (trace_value, native_value) in trace_wide.iter().zip(&native_wide) {
            assert_eq!(trace_value.eval(b.values()), *native_value);
            assert!(!native_value.is_in_base_subfield());
        }
        for (trace_value, native_value) in trace_raw.iter().zip(&native_raw) {
            assert_eq!(trace_value.eval(b.values()), *native_value);
        }
        assert_eq!(captured.layout, layout);
        assert_eq!(captured.data_flat, recorded.data_flat);
        assert_eq!(captured.post_state, recorded.post_state);
        assert_eq!(captured.perms, recorded.perms);

        // The committed duplex carries the raw low/high sponge lanes. The
        // trace-one map is constrained after those lanes are bound, so no
        // transformed extension coordinate is mistaken for a sponge output.
        assert_eq!(captured.challenges.len(), recorded.challenge_wires.len());
        for (captured_value, trace_wire) in
            captured.challenges.iter().zip(&recorded.challenge_wires)
        {
            assert_eq!(*captured_value, Some(trace_wire.eval(b.values())));
        }
        let block_log = layout.slots.len().next_power_of_two().trailing_zeros() as usize;
        let columns = build_duplex_columns(
            &layout,
            FsChannelUnionRecorder::capacity_iv_flat_c1(),
            &recorded.data_flat,
            block_log,
        );
        for (column_value, trace_wire) in columns.challenges.iter().zip(&recorded.challenge_wires) {
            assert_eq!(*column_value, trace_wire.eval(b.values()));
        }

        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
    }

    #[test]
    fn layout_recording_challenger_rejects_layout_drift() {
        use crate::challenger::Challenger;
        use crate::deep_chain::schedule::compile_duplex;

        let value = F128 { lo: 9, hi: 11 };
        let mut b = FieldR1csBuilder::new_witness_only();
        let wire = LinExpr::from_wire(b.alloc_f128(value));
        let mut trace = FsChannelUnionRecorder::new(b"layout-drift");
        trace.observe_f128(&mut b, &wire);
        let _ = trace.sample_f128(&mut b);
        let mut layout = compile_duplex(&trace.finish().ops);
        layout.n_data += 1;

        let mut native = LayoutRecordingChallenger::new(b"layout-drift", layout);
        native.observe_f128(value);
        let _ = native.sample_f128();
        assert!(
            native.finish().is_err(),
            "drifted class layout must fail closed"
        );
    }

    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
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
        fn u128v(&mut self) -> u128 {
            ((self.next_u64() as u128) << 64) | self.next_u64() as u128
        }
    }

    /// The load-bearing basis fact: the flat (GCM) basis multiplication IS
    /// the noid_ivc F128 multiplication on the same u128 bit layout, and the
    /// tower↔flat conversion is its inverse pair.
    #[test]
    fn flat_basis_is_ivc_f128() {
        use noid_core::hardware::flat_to_tower_u128;
        let mut rng = Rng::new(0xBA515);
        for _ in 0..2000 {
            let a = rng.u128v();
            let b = rng.u128v();
            let fa = f128_from_u128(a);
            let fb = f128_from_u128(b);
            assert_eq!(f128_to_u128(fa * fb), clmul_gcm(a, b));
            assert_eq!(flat_to_tower_u128(tower_to_flat_u128(a)), a);
        }
    }

    /// Builder smoke: mul/lin/pin produce a satisfiable instance; a broken
    /// pin is caught by `satisfies`.
    #[test]
    fn builder_basic_satisfiability() {
        let mut rng = Rng::new(1);
        let mut b = FieldR1csBuilder::new();
        let x = LinExpr::from_wire(b.alloc_f128(rng.f128()));
        let y = LinExpr::from_wire(b.alloc_f128(rng.f128()));
        let xv = x.eval(b.values());
        let yv = y.eval(b.values());
        let prod = LinExpr::from_wire(b.mul(&x, &y));
        let combo = prod
            .scale(F128 { lo: 3, hi: 0 })
            .add(&x)
            .add_const(F128::ONE);
        b.pin_f128(&combo, F128 { lo: 3, hi: 0 } * (xv * yv) + xv + F128::ONE);
        let pub_w = b.alloc_public_f128(F128 { lo: 42, hi: 7 });
        let pub_e = LinExpr::from_wire(pub_w);
        b.pin_f128(&pub_e, F128 { lo: 42, hi: 7 });

        let (r1cs, mut z) = b.build();
        assert!(r1cs.satisfies(&z));

        // Corrupt the public wire → unsat.
        z[pub_w.0 as usize] += F128::ONE;
        assert!(!r1cs.satisfies(&z));
    }

    #[test]
    fn f256_gadget_matches_native_and_costs_three_constraints() {
        let mut rng = Rng::new(0xC1_F256);
        for _ in 0..32 {
            let x = F256::new(rng.f128(), rng.f128());
            let y = F256::new(rng.f128(), rng.f128());
            let mut b = FieldR1csBuilder::new();
            let x_expr = ExtExpr::new(
                LinExpr::from_wire(b.alloc_f128(x.lo)),
                LinExpr::from_wire(b.alloc_f128(x.hi)),
            );
            let y_expr = ExtExpr::new(
                LinExpr::from_wire(b.alloc_f128(y.lo)),
                LinExpr::from_wire(b.alloc_f128(y.hi)),
            );

            let before = b.num_wires();
            let product = b.mul_f256(&x_expr, &y_expr);
            assert_eq!(
                b.num_wires() - before,
                3,
                "one extension product must use exactly three base products"
            );
            assert_eq!(product.eval(b.values()), x * y);
            b.pin_f256(&product, x * y);

            let (r1cs, witness) = b.build();
            assert!(r1cs.satisfies(&witness));
        }
    }

    #[test]
    fn f256_square_matches_native_and_costs_two_constraints() {
        let mut rng = Rng::new(0xC1_5A_E);
        for _ in 0..32 {
            let value = F256::new(rng.f128(), rng.f128());
            let mut b = FieldR1csBuilder::new();
            let expression = ExtExpr::new(
                LinExpr::from_wire(b.alloc_f128(value.lo)),
                LinExpr::from_wire(b.alloc_f128(value.hi)),
            );

            let before = b.num_wires();
            let square = b.square_f256(&expression);
            assert_eq!(b.num_wires() - before, 2);
            assert_eq!(square.eval(b.values()), value * value);
            b.pin_f256(&square, value * value);

            let (r1cs, witness) = b.build();
            assert!(r1cs.satisfies(&witness));
        }
    }

    #[test]
    fn c1_channel_trace_locksteps_native_wide_operations() {
        let domain = b"c1-trace-lockstep";
        let values = [
            F256::new(F128::new(1, 2), F128::new(3, 4)),
            F256::new(F128::new(5, 6), F128::new(7, 8)),
            F256::new(F128::new(9, 10), F128::new(11, 12)),
        ];

        let mut b = FieldR1csBuilder::new();
        let expressions = values.map(|value| {
            ExtExpr::new(
                LinExpr::from_wire(b.alloc_f128(value.lo)),
                LinExpr::from_wire(b.alloc_f128(value.hi)),
            )
        });
        let mut trace = FsChannelTrace::new_c1(&mut b, domain);
        let mut native = FsLaneChallenger::new_c1(domain);

        trace.observe_label(&mut b, b"wide-algebra");
        native.observe_label(b"wide-algebra");
        trace.observe_f256(&mut b, &expressions[0]);
        native.observe_f256(values[0]);
        trace.observe_f256_slice(&mut b, &expressions[1..]);
        native.observe_f256_slice(&values[1..]);

        let trace_scalar = trace.sample_f256(&mut b);
        let native_scalar = native.sample_f256();
        assert_eq!(trace_scalar.eval(b.values()), native_scalar);
        assert!(!native_scalar.is_in_base_subfield());

        let trace_wide = trace.sample_f256_vec(&mut b, 7);
        let native_wide = native.sample_f256_vec(7);
        for (trace_value, native_value) in trace_wide.iter().zip(&native_wide) {
            assert_eq!(trace_value.eval(b.values()), *native_value);
            assert!(!native_value.is_in_base_subfield());
        }

        // Raw base-field draws remain part of the C1 transcript for query
        // indices and grinding. They must stay in the same sponge schedule.
        let trace_raw = trace.sample_f128_vec(&mut b, 23);
        let native_raw = native.sample_f128_vec(23);
        for (trace_value, native_value) in trace_raw.iter().zip(&native_raw) {
            assert_eq!(trace_value.eval(b.values()), *native_value);
        }
        assert_eq!(trace.perms(), native.perms());

        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
    }

    /// pow7 == native S-box through the φ map, and costs exactly 4 wires.
    #[test]
    fn pow7_matches_native_sbox() {
        use noid_poseidon2b::native::permutation::sbox_x7;
        let mut rng = Rng::new(2);
        for _ in 0..32 {
            let tower = rng.u128v();
            let mut b = FieldR1csBuilder::new();
            let x = LinExpr::from_wire(b.alloc_f128(flat_const(tower)));
            let before = b.num_wires();
            let out = b.pow7(&x);
            assert_eq!(b.num_wires() - before, 4, "pow7 must cost 4 constraints");
            let expected = flat_const(sbox_x7(Block128(tower)).0);
            assert_eq!(out.eval(b.values()), expected);
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }
    }

    /// The permutation gadget matches `Poseidon2bPermutation::permute_mut`
    /// through φ on random states (all 66 rounds, MDS full/partial), is
    /// satisfiable, and costs ≤ 400 constraints (exactly 360).
    #[test]
    fn poseidon2b_permute_matches_native() {
        let perm = Poseidon2bPermutation;
        let mut rng = Rng::new(3);
        for case in 0..16 {
            let tower_state: [Block128; STATE_SIZE] = std::array::from_fn(|_| {
                if case == 0 {
                    Block128::ZERO
                } else {
                    Block128(rng.u128v())
                }
            });
            let mut expected = tower_state;
            perm.permute_mut(&mut expected);

            let mut b = FieldR1csBuilder::new();
            let state: [LinExpr; STATE_SIZE] = std::array::from_fn(|i| {
                LinExpr::from_wire(b.alloc_f128(flat_const(tower_state[i].0)))
            });
            let before = b.num_wires();
            let out = poseidon2b_permute(&mut b, state);
            let cost = b.num_wires() - before;
            assert_eq!(cost, POSEIDON2B_PERMUTE_CONSTRAINTS);
            assert!(cost <= 400, "permutation gadget budget: ≤ 400 constraints");

            for i in 0..STATE_SIZE {
                assert_eq!(
                    out[i].eval(b.values()),
                    flat_const(expected[i].0),
                    "lane {i} mismatch (case {case})"
                );
            }
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }
    }

    /// horner_eval == native Horner; eq_eval_trace == multilinear::eq_eval.
    #[test]
    fn horner_and_eq_eval_match_native() {
        let mut rng = Rng::new(4);
        for deg in [1usize, 3, 9] {
            let mut b = FieldR1csBuilder::new();
            let coeffs_v: Vec<F128> = (0..=deg).map(|_| rng.f128()).collect();
            let x_v = rng.f128();
            let coeffs: Vec<LinExpr> = coeffs_v
                .iter()
                .map(|&c| LinExpr::from_wire(b.alloc_f128(c)))
                .collect();
            let x = LinExpr::from_wire(b.alloc_f128(x_v));
            let before = b.num_wires();
            let out = b.horner_eval(&coeffs, &x);
            assert_eq!(b.num_wires() - before, deg);
            let mut expected = F128::ZERO;
            for &c in coeffs_v.iter().rev() {
                expected = expected * x_v + c;
            }
            assert_eq!(out.eval(b.values()), expected);
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }

        for n in [1usize, 4, 11] {
            let mut b = FieldR1csBuilder::new();
            let r_v: Vec<F128> = (0..n).map(|_| rng.f128()).collect();
            let x_v: Vec<F128> = (0..n).map(|_| rng.f128()).collect();
            let r: Vec<LinExpr> = r_v
                .iter()
                .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                .collect();
            let x: Vec<LinExpr> = x_v
                .iter()
                .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                .collect();
            let before = b.num_wires();
            let out = b.eq_eval_trace(&r, &x);
            assert_eq!(b.num_wires() - before, n - 1);
            assert_eq!(
                out.eval(b.values()),
                crate::zerocheck::multilinear::eq_eval(&r_v, &x_v)
            );
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }
    }

    /// decompose_bits_le proves the value fits in n bits: honest witness
    /// satisfies; a value with a higher bit set has NO satisfying assignment
    /// of the bit wires (checked via the builder's own dishonest witness).
    #[test]
    fn decompose_bits_forces_range() {
        let mut b = FieldR1csBuilder::new();
        let v = F128 { lo: 0xAB47, hi: 0 };
        let x = LinExpr::from_wire(b.alloc_f128(v));
        b.decompose_bits_le(&x, 16);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));

        // Out-of-range: bit 16 set. The builder still produces SOME witness
        // (its debug_assert would fire in dev; here we hand-corrupt): flip
        // the input value in the finished witness — the pin row must break.
        let mut bad = z.clone();
        bad[1] += F128 { lo: 1 << 16, hi: 0 };
        assert!(!r1cs.satisfies(&bad));
    }

    /// THE lockstep gate: 1000 random op schedules; the trace gadget
    /// mirrors `FsLaneChallenger` exactly — same permutation count, squeezed
    /// expressions evaluate to the native challenges, and the built R1CS is
    /// satisfiable. Covers labels, scalar/slice observes, byte observes,
    /// scalar/vec samples, sponge padding (odd/even lane parity) and PoW
    /// grind/verify.
    #[test]
    fn fs_channel_trace_lockstep_1000_random_traces() {
        let mut rng = Rng::new(0x10C_57E9);
        for trace_idx in 0..1000 {
            let domain = format!("lockstep-{}", trace_idx % 7);
            let mut native = FsLaneChallenger::new(domain.as_bytes());
            let mut b = FieldR1csBuilder::new();
            let mut trace = FsChannelTrace::new(&mut b, domain.as_bytes());

            let n_ops = 1 + (rng.next_u64() % 8) as usize;
            for _ in 0..n_ops {
                match rng.next_u64() % 7 {
                    0 => {
                        let label = format!("phase-{}", rng.next_u64() % 5);
                        native.observe_label(label.as_bytes());
                        trace.observe_label(&mut b, label.as_bytes());
                    }
                    1 => {
                        let v = rng.f128();
                        native.observe_f128(v);
                        let w = LinExpr::from_wire(b.alloc_f128(v));
                        trace.observe_f128(&mut b, &w);
                    }
                    2 => {
                        let n = (rng.next_u64() % 4) as usize;
                        let vals: Vec<F128> = (0..n).map(|_| rng.f128()).collect();
                        native.observe_f128_slice(&vals);
                        let exprs: Vec<LinExpr> = vals
                            .iter()
                            .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                            .collect();
                        trace.observe_f128_slice(&mut b, &exprs);
                    }
                    3 => {
                        let len = (rng.next_u64() % 40) as usize;
                        let bytes: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
                        native.observe_bytes(&bytes);
                        trace.observe_bytes_const(&mut b, &bytes);
                    }
                    4 => {
                        let c = native.sample_f128();
                        let e = trace.sample_f128(&mut b);
                        assert_eq!(e.eval(b.values()), c, "scalar sample diverged");
                    }
                    5 => {
                        let n = 1 + (rng.next_u64() % 3) as usize;
                        let cs = native.sample_f128_vec(n);
                        let es = trace.sample_f128_vec(&mut b, n);
                        for (e, c) in es.iter().zip(cs.iter()) {
                            assert_eq!(e.eval(b.values()), *c, "vec sample diverged");
                        }
                    }
                    _ => {
                        let bits = (rng.next_u64() % 5) as u32; // 0..=4
                        let nonce = native.grind_pow(bits);
                        let nonce_expr =
                            LinExpr::from_wire(b.alloc_f128(F128 { lo: nonce, hi: 0 }));
                        trace.verify_pow_trace(&mut b, &nonce_expr, bits);
                    }
                }
            }
            // Final divergence check: one more challenge each.
            let c = native.sample_f128();
            let e = trace.sample_f128(&mut b);
            assert_eq!(e.eval(b.values()), c, "trailing sample diverged");
            assert_eq!(trace.perms(), native.perms(), "permutation count diverged");

            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z), "trace {trace_idx} unsatisfiable");
        }
    }

    /// THE raw-channel lockstep gate: 1000 random absorb/squeeze schedules; the raw
    /// channel trace mirrors the production `Poseidon2bChannel` exactly —
    /// every squeezed expression evaluates to the flat image of the native
    /// tower challenge, and the built R1CS is satisfiable. Covers pair
    /// buffering (odd/even absorb parity), the pad-flush on odd squeezes,
    /// pending-lane reuse and pending invalidation by interleaved absorbs.
    #[test]
    fn raw_channel_trace_lockstep_1000_random_schedules() {
        use noid_core::transcript::FiatShamir;
        use noid_poseidon2b::channel::Poseidon2bChannel;

        let mut rng = Rng::new(0x0A0B_CDEF_1234_5678);
        for schedule_idx in 0..1000 {
            let mut native = Poseidon2bChannel::new();
            let mut b = FieldR1csBuilder::new();
            let mut trace = RawChannelTrace::new();

            let n_ops = 1 + (rng.next_u64() % 12) as usize;
            for _ in 0..n_ops {
                match rng.next_u64() % 3 {
                    0 => {
                        // Witness-carried absorb (tower value → flat wire).
                        let tower = rng.u128v();
                        native.absorb(Block128(tower));
                        let w = LinExpr::from_wire(b.alloc_f128(flat_const(tower)));
                        trace.absorb(&mut b, &w);
                    }
                    1 => {
                        // Constant absorb (public statement data).
                        let tower = rng.next_u64() as u128;
                        native.absorb(Block128(tower));
                        trace.absorb_const_tower(&mut b, tower);
                    }
                    _ => {
                        let c = native.squeeze();
                        let e = trace.squeeze(&mut b);
                        assert_eq!(
                            e.eval(b.values()),
                            flat_const(c.0),
                            "squeeze diverged (schedule {schedule_idx})"
                        );
                    }
                }
            }
            // Trailing divergence check: two more challenges (exercises the
            // pending lane and the no-buffer squeeze path).
            for _ in 0..2 {
                let c = native.squeeze();
                let e = trace.squeeze(&mut b);
                assert_eq!(
                    e.eval(b.values()),
                    flat_const(c.0),
                    "trailing squeeze diverged (schedule {schedule_idx})"
                );
            }

            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z), "schedule {schedule_idx} unsatisfiable");
        }
    }

    /// A tampered PoW nonce makes the trace unsatisfiable — the PoW
    /// permutation rows were built for the honest nonce, and the
    /// leading-zero decomposition pins the honest output. Negative twin of
    /// the lockstep grind coverage.
    #[test]
    fn verify_pow_trace_rejects_wrong_nonce() {
        let mut native = FsLaneChallenger::new(b"pow-neg");
        native.observe_bytes(b"root");
        let bits = 8u32;
        let nonce = native.grind_pow(bits);

        // Honest trace, then corrupt the nonce wire in the finished witness.
        let mut b = FieldR1csBuilder::new();
        let mut trace = FsChannelTrace::new(&mut b, b"pow-neg");
        trace.observe_bytes_const(&mut b, b"root");
        let nonce_wire = b.alloc_f128(F128 { lo: nonce, hi: 0 });
        trace.verify_pow_trace(&mut b, &LinExpr::from_wire(nonce_wire), bits);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest nonce trace must satisfy");

        let mut bad = z.clone();
        bad[nonce_wire.0 as usize] += F128::ONE;
        assert!(
            !r1cs.satisfies(&bad),
            "tampered nonce produced a satisfiable trace"
        );
    }
}
