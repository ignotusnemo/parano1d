// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-shape action compaction and slot uniqueness.
//!
//! Candidates enter in canonical body order: the primary coinbase mint, two
//! schedule-gated development-payout mints, then every user input and output
//! bitmap position. Semantic lanes are selected to zero when dead. The
//! allocator first packs each mint's body-order creation id into its value
//! lane. One witness-routed Beneš network then permutes the six-lane physical
//! source directly into a `(live first, slot ascending)` target. Output constraints,
//! not the host routing witness, prove the ordering and strict slot uniqueness.
//! This avoids materializing two `O(N log^2 N)` sorting networks.

use noid_ivc_core::field_circuit::Wire;

use super::action_surface::ActionRowTrace;
use super::permutation_network::route_permutation_network;
use super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};

/// Slot-sorted live-prefix handoff to allocator/exact-state recombination.
pub struct CompactedActionTrace {
    pub rows: Vec<ActionRowTrace>,
    /// The already-constrained 32-bit little-endian decomposition of each
    /// returned row's `slot_index`, aligned one-for-one with `rows`.
    ///
    /// Exact-state routing reuses these wires directly; exposing them must not
    /// allocate a second range check.
    pub slot_bits: Vec<Vec<Wire>>,
    /// For each adjacent returned row, a 32-entry one-hot vector whose set bit
    /// is `msb(slot[i] XOR slot[i+1])`. Equal/dead-zero pairs are all zero.
    /// These expressions reuse the strict-order comparator's existing
    /// equal-prefix products and therefore add no rows.
    pub adjacent_msb_one_hot: Vec<Vec<LinExpr>>,
    /// Existing `live[i] * live[i+1]` comparator gates, aligned with
    /// `adjacent_msb_one_hot`; reused by segment-boundary derivation.
    pub adjacent_both_live: Vec<LinExpr>,
    pub source_rows: usize,
    pub sort_rows: usize,
}

/// Compact bitmap-selected body-order candidates, prove the class live cap,
/// and return one strictly slot-sorted unique live prefix.
///
/// The network itself unconditionally proves a permutation: every switch is a
/// boolean-constrained identity/transposition over all six semantic lanes.
/// The deterministic native routing is only a satisfying-witness generator.
pub fn compact_action_rows(
    b: &mut FieldR1csBuilder,
    candidates: &[ActionRowTrace],
    live_capacity: usize,
) -> CompactedActionTrace {
    assert!(!candidates.is_empty(), "coinbase supplies one action row");
    assert!(
        (1..=candidates.len()).contains(&live_capacity),
        "invalid action live capacity"
    );
    let source_rows = candidates.len();
    let sort_rows = source_rows.next_power_of_two();

    let mut source = Vec::with_capacity(sort_rows);
    for action in candidates.iter().cloned() {
        constrain_source_row(b, &action);
        source.push(action);
    }
    source.resize_with(sort_rows, zero_action);

    // Honest witness routing. Soundness does not trust this sort: arbitrary
    // switch bits still describe a permutation, while the constraints below
    // require its output to be a live-prefix strict slot order.
    let mut output_inputs: Vec<usize> = (0..sort_rows).collect();
    output_inputs.sort_by_key(|&input| {
        let action = &source[input];
        let live = native_bool(&action.live, b);
        let slot = if live {
            native_tower_u128(&action.slot_index, b)
        } else {
            0
        };
        (u8::from(!live), slot, input)
    });
    let mut permutation = vec![usize::MAX; sort_rows];
    for (output, input) in output_inputs.into_iter().enumerate() {
        permutation[input] = output;
    }

    let routed_lanes = route_permutation_network(
        b,
        source.into_iter().map(action_lanes).collect(),
        &permutation,
    );
    let routed: Vec<_> = routed_lanes.into_iter().map(action_from_lanes).collect();

    // The class cap is algebraic: no switch witness can move a live action
    // beyond this boundary.
    for action in &routed[live_capacity..] {
        pin_zero(b, &action.live);
    }
    // Live rows must be a prefix. This also prevents a dead row with slot zero
    // from being interleaved before a later live row.
    for pair in routed.windows(2) {
        let dead_then_live = mul(b, &pair[1].live, &pair[0].live.add_const(F128::ONE));
        pin_zero(b, &dead_then_live);
    }

    let slot_bits: Vec<Vec<Wire>> = routed[..live_capacity]
        .iter()
        .map(|action| super::range_check_bits(b, &action.slot_index, 32))
        .collect();
    let mut adjacent_msb_one_hot = Vec::with_capacity(live_capacity.saturating_sub(1));
    let mut adjacent_both_live = Vec::with_capacity(live_capacity.saturating_sub(1));
    for (actions, bits) in routed[..live_capacity].windows(2).zip(slot_bits.windows(2)) {
        let both_live = mul(b, &actions[0].live, &actions[1].live);
        let (strictly_less, msb_one_hot) = strict_less_bits(b, &bits[0], &bits[1]);
        let live_order_violation = mul(b, &both_live, &strictly_less.add_const(F128::ONE));
        pin_zero(b, &live_order_violation);
        adjacent_msb_one_hot.push(msb_one_hot);
        adjacent_both_live.push(both_live);
    }

    CompactedActionTrace {
        rows: routed.into_iter().take(live_capacity).collect(),
        slot_bits,
        adjacent_msb_one_hot,
        adjacent_both_live,
        source_rows,
        sort_rows,
    }
}

fn constrain_source_row(b: &mut FieldR1csBuilder, row: &ActionRowTrace) {
    let live_sq = mul(b, &row.live, &row.live);
    pin_eq(b, &live_sq, &row.live);
    let mint_sq = mul(b, &row.is_mint, &row.is_mint);
    pin_eq(b, &mint_sq, &row.is_mint);
    let mint_when_dead = mul(b, &row.is_mint, &row.live.add_const(F128::ONE));
    pin_zero(b, &mint_when_dead);

    let dead = row.live.add_const(F128::ONE);
    for lane in [&row.slot_index, &row.value, &row.owner[0], &row.owner[1]] {
        let dead_lane = mul(b, &dead, lane);
        pin_zero(b, &dead_lane);
    }
}

fn zero_action() -> ActionRowTrace {
    ActionRowTrace {
        live: LinExpr::zero(),
        slot_index: LinExpr::zero(),
        value: LinExpr::zero(),
        owner: [LinExpr::zero(), LinExpr::zero()],
        is_mint: LinExpr::zero(),
    }
}

fn action_lanes(action: ActionRowTrace) -> Vec<LinExpr> {
    vec![
        action.live,
        action.slot_index,
        action.value,
        action.owner[0].clone(),
        action.owner[1].clone(),
        action.is_mint,
    ]
}

fn action_from_lanes(mut lanes: Vec<LinExpr>) -> ActionRowTrace {
    assert_eq!(lanes.len(), 6);
    let is_mint = lanes.pop().unwrap();
    let owner1 = lanes.pop().unwrap();
    let owner0 = lanes.pop().unwrap();
    let value = lanes.pop().unwrap();
    let slot_index = lanes.pop().unwrap();
    let live = lanes.pop().unwrap();
    ActionRowTrace {
        live,
        slot_index,
        value,
        owner: [owner0, owner1],
        is_mint,
    }
}

/// Pack every live mint's creation id in canonical body order.
///
/// This MUST run before slot sorting: consensus increments the allocator as
/// coinbase/user outputs appear in the block, not in destination-slot order.
/// The high-half packing is built directly from the already-constrained
/// counter bits, so it needs no post-sort decomposition. The packed value
/// subsequently travels through the same permutation as the rest of the
/// action. Conditional ripple increments reject u64 overflow and the final
/// counter is pinned to the child accumulator/header value. Callers must have
/// proved every mint amount is u64 before this pass.
///
/// Exact twin of the `state_delta` mint branch (height-tagged coinbase
/// identity): EVERY mint consumes one allocator increment and the incremented
/// counter must never enter the tagged coinbase namespace (bit 63), but the
/// SINGLE mandatory coinbase output — canonical body order fixes it as
/// `actions[0]` — stores `COINBASE_CREATION_TAG | block_height` instead of
/// the allocator id.
pub fn bind_mint_packed_values_body_order(
    b: &mut FieldR1csBuilder,
    actions: &mut [ActionRowTrace],
    parent_alloc_counter: &LinExpr,
    child_alloc_counter: &LinExpr,
    block_height: &LinExpr,
) {
    bind_mint_packed_values_inner(
        b,
        actions,
        parent_alloc_counter,
        child_alloc_counter,
        block_height,
        None,
    );
}

/// Updated allocation namespace: a native mint sets bit 62 while every
/// allocator sequence remains below it. The mandatory coinbase retains its
/// independent height tag. The operation bank supplies every native selector.
pub fn bind_native_mint_packed_values_body_order(
    b: &mut FieldR1csBuilder,
    actions: &mut [ActionRowTrace],
    parent_alloc_counter: &LinExpr,
    child_alloc_counter: &LinExpr,
    block_height: &LinExpr,
    native_mints: &[LinExpr],
) {
    assert_eq!(native_mints.len(), actions.len());
    bind_mint_packed_values_inner(
        b,
        actions,
        parent_alloc_counter,
        child_alloc_counter,
        block_height,
        Some(native_mints),
    );
}

fn bind_mint_packed_values_inner(
    b: &mut FieldR1csBuilder,
    actions: &mut [ActionRowTrace],
    parent_alloc_counter: &LinExpr,
    child_alloc_counter: &LinExpr,
    block_height: &LinExpr,
    native_mints: Option<&[LinExpr]>,
) {
    const BITS: usize = 64;
    let mut counter_bits: Vec<LinExpr> = super::range_check_bits(b, parent_alloc_counter, BITS)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect();
    if native_mints.is_some() {
        pin_zero(b, &counter_bits[62]);
        pin_zero(b, &counter_bits[63]);
    }

    // `coinbase_creation_id(height) = (1 << 63) | height`: the OR forces id
    // bit 63 to one and passes the height's low 63 bits through, matching the
    // native constant for every u64 height. The bits come from the header
    // height lane's constrained u64 decomposition.
    let height_bits = super::range_check_bits(b, block_height, BITS);
    let coinbase_creation_high = height_bits[..BITS - 1].iter().enumerate().fold(
        LinExpr::constant(flat_const(1u128 << 127)),
        |sum, (bit, &value)| {
            sum.add(&LinExpr::from_wire(value).scale(flat_const(1u128 << (64 + bit))))
        },
    );

    for (index, action) in actions.iter_mut().enumerate() {
        let mut carry = action.is_mint.clone();
        let mut next_bits = Vec::with_capacity(BITS);
        for bit in &counter_bits {
            next_bits.push(bit.add(&carry));
            carry = mul(b, bit, &carry);
        }
        pin_zero(b, &carry);
        // Twin of the native tagged-namespace guard: a mint whose incremented
        // allocator id sets bit 63 fails closed (`is_coinbase_creation_id`
        // rejection in the mint branch), keeping the two id spaces disjoint.
        let tagged_allocation = mul(b, &action.is_mint, &next_bits[BITS - 1]);
        pin_zero(b, &tagged_allocation);
        if let Some(native) = native_mints {
            let tagged_allocation = mul(b, &action.is_mint, &next_bits[62]);
            pin_zero(b, &tagged_allocation);
            let not_boolean = mul(b, &native[index], &native[index].add_const(F128::ONE));
            pin_zero(b, &not_boolean);
            let not_mint = mul(b, &native[index], &action.is_mint.add_const(F128::ONE));
            pin_zero(b, &not_mint);
            if index == 0 {
                pin_zero(b, &native[index]);
            }
        }
        let creation_high = if index == 0 {
            coinbase_creation_high.clone()
        } else {
            next_bits
                .iter()
                .enumerate()
                .fold(LinExpr::zero(), |sum, (bit, value)| {
                    sum.add(&value.scale(flat_const(1u128 << (64 + bit))))
                })
        };
        let selected_creation_high = mul(b, &action.is_mint, &creation_high);
        action.value = action.value.add(&selected_creation_high);
        if let Some(native) = native_mints {
            action.value = action
                .value
                .add(&native[index].scale(flat_const(1u128 << 126)));
        }
        counter_bits = next_bits;
    }

    let final_counter = counter_bits
        .iter()
        .enumerate()
        .fold(LinExpr::zero(), |sum, (bit, value)| {
            sum.add(&value.scale(flat_const(1u128 << bit)))
        });
    pin_eq(b, &final_counter, child_alloc_counter);
}

fn native_bool(expr: &LinExpr, b: &FieldR1csBuilder) -> bool {
    match expr.eval(b.values()) {
        F128::ZERO => false,
        F128::ONE => true,
        value => panic!("non-boolean action selector in native witness: {value:?}"),
    }
}

fn native_tower_u128(expr: &LinExpr, b: &FieldR1csBuilder) -> u128 {
    let flat = expr.eval(b.values());
    let raw = u128::from(flat.lo) | (u128::from(flat.hi) << 64);
    noid_core::hardware::flat_to_tower_u128(raw)
}

/// Boolean expression for the unsigned strict relation `left < right`.
pub(super) fn strict_less_bits(
    b: &mut FieldR1csBuilder,
    left: &[Wire],
    right: &[Wire],
) -> (LinExpr, Vec<LinExpr>) {
    assert_eq!(left.len(), right.len());
    let mut equal_higher = LinExpr::constant(F128::ONE);
    let mut less = LinExpr::zero();
    let mut highest_difference = vec![LinExpr::zero(); left.len()];
    for bit in (0..left.len()).rev() {
        let a = LinExpr::from_wire(left[bit]);
        let c = LinExpr::from_wire(right[bit]);
        let left_zero_right_one = mul(b, &a.add_const(F128::ONE), &c);
        less = less.add(&mul(b, &equal_higher, &left_zero_right_one));
        let equal_bit = a.add(&c).add_const(F128::ONE);
        let equal_through = mul(b, &equal_higher, &equal_bit);
        highest_difference[bit] = equal_higher.add(&equal_through);
        equal_higher = equal_through;
    }
    (less, highest_difference)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::Block128;

    fn candidate(
        b: &mut FieldR1csBuilder,
        ordinal: usize,
        live: bool,
        mint: bool,
    ) -> ActionRowTrace {
        let live_w = super::super::alloc_block(b, Block128::from(if live { 1u128 } else { 0u128 }));
        let selected = |b: &mut FieldR1csBuilder, value: u128| {
            super::super::alloc_block(b, Block128::from(if live { value } else { 0 }))
        };
        ActionRowTrace {
            live: live_w.clone(),
            slot_index: selected(b, ordinal as u128 + 100),
            value: selected(b, ordinal as u128 + 1_000),
            owner: [
                selected(b, ordinal as u128 + 2_000),
                selected(b, ordinal as u128 + 3_000),
            ],
            is_mint: if mint { live_w } else { LinExpr::zero() },
        }
    }

    fn build(
        pattern: &[bool],
        capacity: usize,
    ) -> (noid_ivc_core::field_r1cs::FieldR1cs, Vec<F128>, Vec<F128>) {
        let mut b = FieldR1csBuilder::new();
        let rows: Vec<_> = pattern
            .iter()
            .enumerate()
            .map(|(ordinal, &live)| candidate(&mut b, ordinal, live, ordinal % 2 == 0))
            .collect();
        let compact = compact_action_rows(&mut b, &rows, capacity);
        let slots = compact
            .rows
            .iter()
            .map(|action| action.slot_index.eval(b.values()))
            .collect();
        let (r1cs, witness) = b.build();
        (r1cs, witness, slots)
    }

    fn slot_case(
        slots: &[(u128, bool, bool)],
    ) -> (noid_ivc_core::field_r1cs::FieldR1cs, Vec<F128>, Vec<F128>) {
        let mut b = FieldR1csBuilder::new();
        let rows = slot_rows(&mut b, slots);
        let compact = compact_action_rows(&mut b, &rows, rows.len());
        let slot_values = compact
            .rows
            .iter()
            .map(|row| row.slot_index.eval(b.values()))
            .collect();
        let (r1cs, witness) = b.build();
        (r1cs, witness, slot_values)
    }

    fn slot_case_with_bits(
        slots: &[(u128, bool, bool)],
    ) -> (
        noid_ivc_core::field_r1cs::FieldR1cs,
        Vec<F128>,
        Vec<F128>,
        Vec<Vec<F128>>,
    ) {
        let mut b = FieldR1csBuilder::new();
        let rows = slot_rows(&mut b, slots);
        let compact = compact_action_rows(&mut b, &rows, rows.len());
        let slot_values = compact
            .rows
            .iter()
            .map(|row| row.slot_index.eval(b.values()))
            .collect();
        let slot_bit_values = compact
            .slot_bits
            .iter()
            .map(|bits| {
                bits.iter()
                    .map(|&bit| LinExpr::from_wire(bit).eval(b.values()))
                    .collect()
            })
            .collect();
        let (r1cs, witness) = b.build();
        (r1cs, witness, slot_values, slot_bit_values)
    }

    fn slot_rows(b: &mut FieldR1csBuilder, slots: &[(u128, bool, bool)]) -> Vec<ActionRowTrace> {
        slots
            .iter()
            .enumerate()
            .map(|(ordinal, &(slot, live, mint))| {
                let mut row = candidate(b, ordinal, live, mint);
                row.slot_index =
                    super::super::alloc_block(b, Block128::from(if live { slot } else { 0 }));
                row
            })
            .collect()
    }

    fn bits_as_u32(bits: &[F128]) -> u32 {
        assert_eq!(bits.len(), 32);
        bits.iter().enumerate().fold(0u32, |value, (bit, &v)| {
            assert!(v == F128::ZERO || v == F128::ONE);
            value | (u32::from(v == F128::ONE) << bit)
        })
    }

    const TEST_BLOCK_HEIGHT: u128 = 6;
    const COINBASE_TEST_ID: u128 = (1u128 << 63) | TEST_BLOCK_HEIGHT;

    fn allocator_case(
        slots: &[(u128, bool, bool)],
        parent: u128,
        child: u128,
    ) -> (
        noid_ivc_core::field_r1cs::FieldR1cs,
        Vec<F128>,
        Vec<(u128, u128)>,
    ) {
        let mut b = FieldR1csBuilder::new();
        let mut rows = slot_rows(&mut b, slots);
        let parent_w = super::super::alloc_block(&mut b, Block128::from(parent));
        let child_w = super::super::alloc_block(&mut b, Block128::from(child));
        let height_w = super::super::alloc_block(&mut b, Block128::from(TEST_BLOCK_HEIGHT));
        bind_mint_packed_values_body_order(&mut b, &mut rows, &parent_w, &child_w, &height_w);
        let compact = compact_action_rows(&mut b, &rows, rows.len());
        let routed = compact
            .rows
            .iter()
            .map(|row| {
                (
                    native_tower_u128(&row.slot_index, &b),
                    native_tower_u128(&row.value, &b) >> 64,
                )
            })
            .collect();
        let (r1cs, witness) = b.build();
        (r1cs, witness, routed)
    }

    #[test]
    fn sparse_high_positions_compact_to_slot_sorted_zero_suffix() {
        let pattern = [false, true, false, false, true, false, true, false, true];
        let (r1cs, witness, slots) = build(&pattern, 6);
        assert!(r1cs.satisfies(&witness));
        assert_eq!(
            slots,
            [
                super::super::flat_const(101),
                super::super::flat_const(104),
                super::super::flat_const(106),
                super::super::flat_const(108),
                F128::ZERO,
                F128::ZERO,
            ]
        );
    }

    #[test]
    fn body_order_creation_ids_survive_slot_sorting() {
        // Index 0 is the mandatory coinbase mint: it stores the tagged height
        // id while still consuming allocator increment 8; the user mints then
        // take 9 and 10 in body order.
        let (r1cs, witness, routed) = allocator_case(
            &[
                (90, true, true),
                (5, true, false),
                (20, true, true),
                (1, true, true),
                (0, false, false),
            ],
            7,
            10,
        );
        assert!(r1cs.satisfies(&witness));
        assert_eq!(
            routed,
            [(1, 10), (5, 0), (20, 9), (90, COINBASE_TEST_ID), (0, 0)]
        );
    }

    #[test]
    fn allocator_rejects_user_mint_entering_coinbase_namespace() {
        // The coinbase increment reaches (1<<63)-1 (untagged, valid); the
        // user mint's increment would set bit 63 and must fail closed — the
        // twin of the native `is_coinbase_creation_id(next_alloc)` rejection.
        let parent = (1u128 << 63) - 2;
        let (r1cs, witness, _) =
            allocator_case(&[(9, true, true), (12, true, true)], parent, parent + 2);
        assert!(!r1cs.satisfies(&witness));

        // One increment below the namespace boundary stays satisfiable.
        let (ok, ok_witness, _) = allocator_case(&[(9, true, true)], parent, parent + 1);
        assert!(ok.satisfies(&ok_witness));
    }

    #[test]
    fn allocator_and_packed_value_lane_are_slot_topology_invariant() {
        let (left, left_witness, _) = allocator_case(
            &[
                (90, true, true),
                (5, true, false),
                (20, true, true),
                (0, false, false),
            ],
            7,
            9,
        );
        let (right, right_witness, _) = allocator_case(
            &[
                (1, true, true),
                (95, true, false),
                (70, true, true),
                (0, false, false),
            ],
            70,
            72,
        );
        assert!(left.satisfies(&left_witness));
        assert!(right.satisfies(&right_witness));
        assert_eq!(left.useful_rows, right.useful_rows);
        assert_eq!(left.statement_digest(), right.statement_digest());
    }

    #[test]
    fn production_mint_roles_are_occupancy_shape_invariant() {
        // The third tuple component is the physical role, not live content:
        // coinbase/output positions always carry the dynamic mint selector;
        // input positions always carry structural zero.
        let (left, left_witness, _) = allocator_case(
            &[
                (90, true, true),
                (5, true, false),
                (0, false, false),
                (20, true, true),
                (0, false, false),
                (0, false, true),
            ],
            7,
            9,
        );
        let (right, right_witness, _) = allocator_case(
            &[
                (90, true, true),
                (0, false, false),
                (35, true, false),
                (0, false, true),
                (70, true, false),
                (60, true, true),
            ],
            70,
            72,
        );
        assert!(left.satisfies(&left_witness));
        assert!(right.satisfies(&right_witness));
        assert_eq!(left.useful_rows, right.useful_rows);
        assert_eq!(left.statement_digest(), right.statement_digest());
    }

    #[test]
    fn allocator_rejects_wrong_child_counter_and_overflow() {
        let (wrong, wrong_witness, _) = allocator_case(&[(9, true, true)], 7, 9);
        assert!(!wrong.satisfies(&wrong_witness));

        let (overflow, overflow_witness, _) =
            allocator_case(&[(9, true, true)], u64::MAX as u128, 0);
        assert!(!overflow.satisfies(&overflow_witness));
    }

    #[test]
    fn all_six_row_bitmaps_preserve_live_body_order_when_slots_do() {
        const N: usize = 6;
        for bitmap in 0u8..(1 << N) {
            let pattern: Vec<_> = (0..N).map(|bit| bitmap >> bit & 1 == 1).collect();
            let (r1cs, witness, slots) = build(&pattern, N);
            assert!(r1cs.satisfies(&witness), "bitmap {bitmap:#08b}");
            let mut expected: Vec<_> = pattern
                .iter()
                .enumerate()
                .filter(|(_, live)| **live)
                .map(|(ordinal, _)| super::super::flat_const(ordinal as u128 + 100))
                .collect();
            expected.resize(N, F128::ZERO);
            assert_eq!(slots, expected, "bitmap {bitmap:#08b}");
        }
    }

    #[test]
    fn occupancy_does_not_change_the_compactor_matrix() {
        let (sparse, sparse_witness, _) =
            build(&[true, false, false, true, false, false, false, false], 6);
        let (dense, dense_witness, _) =
            build(&[true, true, true, true, true, true, false, false], 6);
        assert!(sparse.satisfies(&sparse_witness));
        assert!(dense.satisfies(&dense_witness));
        assert_eq!(sparse.statement_digest(), dense.statement_digest());
        assert_eq!(sparse.useful_rows, dense.useful_rows);
    }

    #[test]
    fn class_live_capacity_is_a_constraint() {
        let (r1cs, witness, _) = build(&[true, true, true, true], 3);
        assert!(!r1cs.satisfies(&witness));
    }

    #[test]
    fn dead_nonzero_semantic_row_is_rejected() {
        let mut b = FieldR1csBuilder::new();
        let mut row = candidate(&mut b, 0, false, false);
        row.slot_index = super::super::alloc_block(&mut b, Block128::from(1u128));
        let _ = compact_action_rows(&mut b, &[row], 1);
        let (r1cs, witness) = b.build();
        assert!(!r1cs.satisfies(&witness));
    }

    #[test]
    fn routes_directly_to_unique_slot_order_with_dead_suffix() {
        let (r1cs, witness, slots) = slot_case(&[
            (91, true, false),
            (0, false, false),
            (7, true, true),
            (42, true, false),
            (0, false, true),
        ]);
        assert!(r1cs.satisfies(&witness));
        assert_eq!(
            slots,
            [
                super::super::flat_const(7),
                super::super::flat_const(42),
                super::super::flat_const(91),
                F128::ZERO,
                F128::ZERO,
            ]
        );
    }

    #[test]
    fn exposed_slot_bits_match_routed_slot_indices() {
        let (r1cs, witness, slots, slot_bits) = slot_case_with_bits(&[
            (91, true, false),
            (0, false, false),
            (7, true, true),
            (42, true, false),
            (0, false, true),
        ]);
        assert!(r1cs.satisfies(&witness));
        assert_eq!(slot_bits.len(), slots.len());
        assert_eq!(
            slot_bits
                .iter()
                .map(|bits| bits_as_u32(bits))
                .collect::<Vec<_>>(),
            [7, 42, 91, 0, 0]
        );
        for (slot, bits) in slots.iter().zip(&slot_bits) {
            let raw = u128::from(slot.lo) | (u128::from(slot.hi) << 64);
            assert_eq!(
                u128::from(bits_as_u32(bits)),
                noid_core::hardware::flat_to_tower_u128(raw)
            );
        }
    }

    #[test]
    fn exposed_slot_bits_have_a_zero_dead_suffix() {
        let (r1cs, witness, _, slot_bits) = slot_case_with_bits(&[
            (91, true, false),
            (0, false, false),
            (7, true, true),
            (42, true, false),
            (0, false, false),
        ]);
        assert!(r1cs.satisfies(&witness));
        assert!(slot_bits[3..]
            .iter()
            .flatten()
            .all(|&bit| bit == F128::ZERO));
    }

    #[test]
    fn comparator_exposes_highest_difference_without_an_extra_range_pass() {
        let mut b = FieldR1csBuilder::new();
        let rows = slot_rows(
            &mut b,
            &[
                (91, true, false),
                (0, false, false),
                (7, true, true),
                (42, true, false),
                (0, false, false),
            ],
        );
        let compact = compact_action_rows(&mut b, &rows, rows.len());
        let highest: Vec<_> = compact
            .adjacent_msb_one_hot
            .iter()
            .map(|one_hot| {
                let set: Vec<_> = one_hot
                    .iter()
                    .enumerate()
                    .filter(|(_, bit)| bit.eval(b.values()) == F128::ONE)
                    .map(|(position, _)| position)
                    .collect();
                set
            })
            .collect();
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
        assert_eq!(highest, [vec![5], vec![6], vec![6], vec![]]);
    }

    #[test]
    fn exposing_slot_bits_adds_no_rows_or_matrix_changes() {
        let slots = [
            (91, true, false),
            (0, false, false),
            (7, true, true),
            (42, true, false),
            (0, false, false),
        ];
        // Local projection of the former API: consume only the compacted rows.
        let (baseline, baseline_witness, _) = slot_case(&slots);
        let (exposed, exposed_witness, _, slot_bits) = slot_case_with_bits(&slots);
        assert!(baseline.satisfies(&baseline_witness));
        assert!(exposed.satisfies(&exposed_witness));
        assert_eq!(slot_bits.len(), slots.len());
        assert_eq!(baseline.useful_rows, exposed.useful_rows);
        assert_eq!(baseline.statement_digest(), exposed.statement_digest());
    }

    #[test]
    fn repeated_spend_or_mint_slot_is_rejected() {
        for rows in [
            [(17, true, false), (17, true, false)],
            [(17, true, false), (17, true, true)],
            [(17, true, true), (17, true, true)],
        ] {
            let (r1cs, witness, _) = slot_case(&rows);
            assert!(!r1cs.satisfies(&witness));
        }
    }

    #[test]
    fn slot_values_do_not_change_the_routing_matrix() {
        let (left, left_witness, _) =
            slot_case(&[(9, true, false), (2, true, true), (0, false, false)]);
        let (right, right_witness, _) =
            slot_case(&[(90, true, false), (20, true, true), (0, false, false)]);
        assert!(left.satisfies(&left_witness));
        assert!(right.satisfies(&right_witness));
        assert_eq!(left.statement_digest(), right.statement_digest());
        assert_eq!(left.useful_rows, right.useful_rows);
    }

    #[test]
    fn slot_index_must_fit_u32() {
        let (r1cs, witness, _) = slot_case(&[(1u128 << 32, true, false)]);
        assert!(!r1cs.satisfies(&witness));
    }
}
