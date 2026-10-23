// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-shape public arithmetic for one physical PagedSpend page.
//!
//! The body spine commits input value lanes as
//! `amount | (creation_id << 64)`, while balance is ordinary unsigned integer
//! arithmetic rather than addition in `F_{2^128}`.  This module splits every
//! packed input exactly in the tower basis, range-checks all monetary lanes,
//! Page-local arithmetic proves every amount range, packed input split,
//! bitmap count and selected sum. Conservation is deliberately not asserted
//! here: the PagedSpend scanner proves it once over the complete START..END
//! group.
//! Values come from the raw rows already committed by the spine and the
//! selectors produced by [`ActionSurfaceTrace`]. That surface proves every
//! bitmap-dead raw record is zero and every selected selector is
//! `page_live * raw_selector`. We therefore mux each page's checked sums once
//! and feed those exact expressions into the group accumulator.
//!
//! There is no witness-value branch: all eight input positions and both output
//! positions instantiate the same constraints even when their bitmap bits or
//! the outer transaction-liveness bit are zero.  The raw packed components are
//! split at every physical position, while a tier-padding ghost returns zero
//! selected sums and fee for later block arithmetic.
//!
//! The selected bitmap popcounts are derived once here and reused by the group
//! scanner; no downstream consumer allocates a divergent page counter.

use noid_core::{hardware::flat_to_tower_u128, Block128};

use super::action_surface::{
    ActionSurfaceTrace, INPUT_SELECTORS, LEAF_FEE, LEAF_INPUT_BASE, LEAF_OUTPUT0_DATA,
    OUTPUT_SELECTORS,
};
use super::tx_body_spine::SpineInputsTrace;
use super::{
    alloc_block, flat_const, mul, pin_eq, pin_zero, range_check_bits, FieldR1csBuilder, LinExpr,
    Wire,
};

const U64_BITS: usize = 64;
const INPUT_SUM_BITS: usize = U64_BITS + 3; // eight u64 inputs fit in 67 bits
const OUTPUT_PLUS_FEE_BITS: usize = U64_BITS + 2; // two outputs plus one fee fit in 66 bits

/// One expression proven to carry an unsigned 64-bit tower-basis value.
#[derive(Clone)]
pub struct U64Trace {
    pub value: LinExpr,
    /// Little-endian tower bits.  Exposing these lets later arithmetic reuse
    /// this decomposition instead of allocating a second range check.
    pub bits: [Wire; U64_BITS],
}

/// Exact split of an input body's packed value lane.
#[derive(Clone)]
pub struct PackedInputValueTrace {
    pub amount: U64Trace,
    pub creation_id: U64Trace,
}

/// Public-arithmetic outputs for one physical user-transaction slot.
pub struct UserPublicArithmeticTrace {
    /// The exact outer liveness wire and the already-proven selected bitmap
    /// bits.  Block fee arithmetic reuses these expressions to derive `ni`
    /// and `no`; it must not allocate a second, potentially divergent bitmap
    /// decomposition.
    pub tx_live: LinExpr,
    pub selected_input_live: [LinExpr; INPUT_SELECTORS],
    pub selected_output_live: [LinExpr; OUTPUT_SELECTORS],
    pub live_input_count_bits: [LinExpr; 4],
    pub live_output_count_bits: [LinExpr; 2],
    pub live_input_count: LinExpr,
    pub live_output_count: LinExpr,
    /// Exact raw-body packed splits at all eight physical input positions.
    pub inputs: [PackedInputValueTrace; INPUT_SELECTORS],
    /// Raw-body output amount ranges at both physical output positions.
    pub outputs: [U64Trace; OUTPUT_SELECTORS],
    pub fee: U64Trace,
    /// Tx-live and bitmap-selected amount lanes, recovered from the exact
    /// action rows without another bitmap decomposition.
    pub selected_inputs: [LinExpr; INPUT_SELECTORS],
    pub selected_outputs: [LinExpr; OUTPUT_SELECTORS],
    /// Fee contribution to block totals.  A canonical capacity-padding ghost
    /// has a valid raw body but contributes zero through `tx_live`.
    pub paid_fee: LinExpr,
    /// Raw checked u128-native sums, represented in tight proven widths.
    pub raw_input_sum: LinExpr,
    pub raw_output_sum: LinExpr,
    pub raw_output_plus_fee: LinExpr,
    /// The raw checked sums muxed once by `tx_live`.  These are zero for every
    /// capacity ghost and equal the raw sums for every live user transaction.
    pub input_sum: LinExpr,
    pub output_sum: LinExpr,
    pub output_plus_fee: LinExpr,
}

fn bind_u64(b: &mut FieldR1csBuilder, value: &LinExpr) -> U64Trace {
    let bits = range_check_bits(b, value, U64_BITS);
    U64Trace {
        value: value.clone(),
        bits: std::array::from_fn(|i| bits[i]),
    }
}

fn reconstruct_bits(bits: &[LinExpr]) -> LinExpr {
    assert!(bits.len() <= 128);
    bits.iter()
        .enumerate()
        .fold(LinExpr::zero(), |sum, (i, bit)| {
            sum.add(&bit.scale(flat_const(1u128 << i)))
        })
}

/// Exact popcount of already-boolean selector expressions. The incrementer
/// stays fixed-shape and rejects overflow at the declared width.
fn selector_count_bits<const WIDTH: usize>(
    b: &mut FieldR1csBuilder,
    selectors: &[LinExpr],
) -> [LinExpr; WIDTH] {
    let mut count: [LinExpr; WIDTH] = std::array::from_fn(|_| LinExpr::zero());
    for selector in selectors {
        let mut carry = selector.clone();
        for bit in &mut count {
            let previous = bit.clone();
            *bit = previous.add(&carry);
            carry = mul(b, &previous, &carry);
        }
        pin_zero(b, &carry);
    }
    count
}

fn tower_value(expr: &LinExpr, b: &FieldR1csBuilder) -> u128 {
    let flat = expr.eval(b.values());
    flat_to_tower_u128((flat.lo as u128) | ((flat.hi as u128) << 64))
}

fn creation_id_high(creation_id: &U64Trace) -> LinExpr {
    creation_id
        .bits
        .iter()
        .enumerate()
        .fold(LinExpr::zero(), |sum, (i, &bit)| {
            sum.add(&LinExpr::from_wire(bit).scale(flat_const(1u128 << (U64_BITS + i))))
        })
}

/// Range-check caller-provided components and bind their exact packed lane.
///
/// The high half is reconstructed bit-by-bit with tower-basis constants.
/// Field multiplication by `2^64` would not be a sound substitute for this
/// concatenation in an arbitrary extension-field basis.
pub fn bind_packed_input_components(
    b: &mut FieldR1csBuilder,
    packed: &LinExpr,
    amount: &LinExpr,
    creation_id: &LinExpr,
) -> PackedInputValueTrace {
    let amount = bind_u64(b, amount);
    let creation_id = bind_u64(b, creation_id);
    let creation_high = creation_id_high(&creation_id);
    pin_eq(b, packed, &amount.value.add(&creation_high));
    PackedInputValueTrace {
        amount,
        creation_id,
    }
}

/// Allocate the canonical `(amount:u64, creation_id:u64)` witness split of a
/// packed input lane, then constrain the split with
/// [`bind_packed_input_components`].
pub fn split_packed_input_value(
    b: &mut FieldR1csBuilder,
    packed: &LinExpr,
) -> PackedInputValueTrace {
    let packed_native = Block128(tower_value(packed, b));
    let (amount, creation_id) = noid_tx::unpack_amount_creation_id(packed_native);
    let amount = alloc_block(b, Block128::from(amount as u128));
    let creation_id = alloc_block(b, Block128::from(creation_id as u128));
    bind_packed_input_components(b, packed, &amount, &creation_id)
}

fn widen_u64_bits(value: &U64Trace, width: usize) -> Vec<LinExpr> {
    assert!((U64_BITS..=128).contains(&width));
    (0..width)
        .map(|i| {
            if i < U64_BITS {
                LinExpr::from_wire(value.bits[i])
            } else {
                LinExpr::zero()
            }
        })
        .collect()
}

/// Ripple-carry unsigned addition over already boolean bit expressions.
/// The final carry is pinned to zero, making overflow unsatisfiable.
fn checked_add_bits(b: &mut FieldR1csBuilder, a: &[LinExpr], c: &[LinExpr]) -> Vec<LinExpr> {
    assert_eq!(a.len(), c.len());
    assert!(!a.is_empty());
    let mut carry = LinExpr::zero();
    let mut sum = Vec::with_capacity(a.len());
    for (ai, ci) in a.iter().zip(c) {
        sum.push(ai.add(ci).add(&carry));
        // carry' = ai*ci + carry*(ai XOR ci).  For boolean operands the
        // products are mutually exclusive, so characteristic-two addition
        // is their exact OR.
        let ai_ci = mul(b, ai, ci);
        let carry_axc = mul(b, &carry, &ai.add(ci));
        carry = ai_ci.add(&carry_axc);
    }
    pin_zero(b, &carry);
    sum
}

fn checked_sum_u64<const N: usize>(
    b: &mut FieldR1csBuilder,
    terms: &[U64Trace; N],
    width: usize,
) -> (Vec<LinExpr>, LinExpr) {
    assert!(N > 0);
    let mut acc = widen_u64_bits(&terms[0], width);
    for term in &terms[1..] {
        let term = widen_u64_bits(term, width);
        acc = checked_add_bits(b, &acc, &term);
    }
    let value = reconstruct_bits(&acc);
    (acc, value)
}

/// Bind one physical page's ranges and selected sums to the exact body spine
/// and action-selector surface. Group conservation is bound by PagedSpend.
///
/// The exact outer liveness expression comes from `surface.tx_live`; it is the
/// same wire that `bind_user_action_surface` proved boolean and used for every
/// selected selector.  The selected amount expressions come from those
/// tx-live-and-bitmap-selected rows.
/// The checked adder trees consume the raw amount decompositions once; the
/// surface's dead-zero relation and common boolean `tx_live` make a single mux
/// of the final sums exactly equivalent to re-running those trees over the
/// selected rows.  No constraint shape depends on selector or witness values.
pub fn bind_user_public_arithmetic(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    surface: &ActionSurfaceTrace,
) -> UserPublicArithmeticTrace {
    bind_user_public_arithmetic_inner(b, spine, surface, false)
}

/// Native metadata headers keep their committed mask words and pay the
/// logical fee, while their zero action bitmap contributes no State amounts.
pub fn bind_user_public_arithmetic_v2_1(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    surface: &ActionSurfaceTrace,
) -> UserPublicArithmeticTrace {
    bind_user_public_arithmetic_inner(b, spine, surface, true)
}

fn bind_user_public_arithmetic_inner(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    surface: &ActionSurfaceTrace,
    native_pages: bool,
) -> UserPublicArithmeticTrace {
    let inputs: [PackedInputValueTrace; INPUT_SELECTORS] =
        std::array::from_fn(|i| split_packed_input_value(b, &spine.leaves[LEAF_INPUT_BASE + i][1]));
    let outputs: [U64Trace; OUTPUT_SELECTORS] = std::array::from_fn(|i| {
        let data_leaf = LEAF_OUTPUT0_DATA + 2 * i;
        bind_u64(b, &spine.leaves[data_leaf][1])
    });
    let fee = bind_u64(b, &spine.leaves[LEAF_FEE][0]);
    pin_zero(b, &spine.leaves[LEAF_FEE][1]);

    // Consume the SAME selected action rows instead of decomposing the bitmap
    // again.  An input row carries selected*(amount + creation_high).  Remove
    // its selected high component in characteristic two to recover the exact
    // selected amount.  Output rows already carry the selected raw amount.
    let selected_inputs: [LinExpr; INPUT_SELECTORS] = std::array::from_fn(|i| {
        assert_eq!(surface.input_rows[i].live, surface.selected_inputs[i]);
        let selected_creation_high = mul(
            b,
            &surface.selected_inputs[i],
            &creation_id_high(&inputs[i].creation_id),
        );
        surface.input_rows[i].value.add(&selected_creation_high)
    });
    let selected_outputs: [LinExpr; OUTPUT_SELECTORS] = std::array::from_fn(|i| {
        assert_eq!(surface.output_rows[i].live, surface.selected_outputs[i]);
        surface.output_rows[i].value.clone()
    });
    let live_input_count_bits = selector_count_bits::<4>(b, &surface.selected_inputs);
    let live_output_count_bits = selector_count_bits::<2>(b, &surface.selected_outputs);
    let live_input_count = reconstruct_bits(&live_input_count_bits);
    let live_output_count = reconstruct_bits(&live_output_count_bits);

    let input_amounts = inputs.clone().map(|input| input.amount);
    let (_, raw_input_sum) = checked_sum_u64(b, &input_amounts, INPUT_SUM_BITS);
    let (output_bits, raw_output_sum) = checked_sum_u64(b, &outputs, OUTPUT_PLUS_FEE_BITS);
    let fee_bits = widen_u64_bits(&fee, OUTPUT_PLUS_FEE_BITS);
    let output_plus_fee_bits = checked_add_bits(b, &output_bits, &fee_bits);
    let raw_output_plus_fee = reconstruct_bits(&output_plus_fee_bits);

    // One common boolean mux is exact selected semantics: action_surface has
    // already established selected_i = tx_live*raw_i and raw dead-zero.
    let data_live = if native_pages {
        mul(
            b,
            &surface.tx_live,
            &surface.native_header.add_const(super::F128::ONE),
        )
    } else {
        surface.tx_live.clone()
    };
    let input_sum = mul(b, &data_live, &raw_input_sum);
    let output_sum = mul(b, &data_live, &raw_output_sum);
    let mut output_plus_fee = mul(b, &data_live, &raw_output_plus_fee);
    if native_pages {
        let header_live = mul(b, &surface.tx_live, &surface.native_header);
        output_plus_fee = output_plus_fee.add(&mul(b, &header_live, &fee.value));
    }
    let paid_fee = mul(b, &surface.tx_live, &fee.value);

    UserPublicArithmeticTrace {
        tx_live: surface.tx_live.clone(),
        selected_input_live: surface.selected_inputs.clone(),
        selected_output_live: surface.selected_outputs.clone(),
        live_input_count_bits,
        live_output_count_bits,
        live_input_count,
        live_output_count,
        inputs,
        outputs,
        fee,
        selected_inputs,
        selected_outputs,
        paid_fee,
        raw_input_sum,
        raw_output_sum,
        raw_output_plus_fee,
        input_sum,
        output_sum,
        output_plus_fee,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acceptance::trace::action_surface::bind_user_action_surface;
    use crate::acceptance::trace::{alloc_block, F128};
    use noid_core::TowerField;
    use noid_gkr::{spine_statement::spine_inputs_from_body, SpineInputs};
    use noid_ivc_core::field_r1cs::FieldR1cs;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, pack_amount_creation_id, validate_public_tx_logic, TxBody, TxInput,
        TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    fn sparse_body() -> TxBody {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 7,
            amount: 10,
            creation_id: 3,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 19,
            amount: 9,
            owner: Address([0x77; 32]),
        };
        TxBody {
            epoch_anchor: [0x42; 32],
            fee: 1,
            input_owner: Address([0x33; 32]),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        }
    }

    fn wide_sum_body() -> TxBody {
        let mut body = sparse_body();
        body.inputs[0].amount = u64::MAX;
        body.inputs[0].creation_id = u64::MAX;
        body.inputs[1] = TxInput {
            slot_index: 8,
            amount: 10,
            creation_id: 4,
        };
        body.outputs[0].amount = u64::MAX;
        body.outputs[1] = TxOutput {
            slot_index: 20,
            amount: 9,
            owner: Address([0x88; 32]),
        };
        body.validity_bitmap = 0b11 | output_bitmap_bit(0) | output_bitmap_bit(1);
        body
    }

    fn dense_body() -> TxBody {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        for (i, input) in inputs.iter_mut().enumerate() {
            *input = TxInput {
                slot_index: 100 + i as u32,
                amount: 10,
                creation_id: 1_000 + i as u64,
            };
        }
        let outputs = [
            TxOutput {
                slot_index: 200,
                amount: 50,
                owner: Address([0x81; 32]),
            },
            TxOutput {
                slot_index: 201,
                amount: 27,
                owner: Address([0x82; 32]),
            },
        ];
        TxBody {
            epoch_anchor: [0x52; 32],
            fee: 3,
            input_owner: Address([0x43; 32]),
            inputs,
            outputs,
            validity_bitmap: ((1u16 << TX_INPUTS) - 1)
                | output_bitmap_bit(0)
                | output_bitmap_bit(1),
            is_coinbase: false,
        }
    }

    fn build_relation(
        native: &SpineInputs,
        tx_live: Block128,
    ) -> (FieldR1cs, Vec<F128>, UserPublicArithmeticTrace) {
        let mut b = FieldR1csBuilder::new();
        let spine = SpineInputsTrace::alloc(&mut b, native);
        let tx_live = alloc_block(&mut b, tx_live);
        let surface = bind_user_action_surface(&mut b, &spine, &tx_live);
        let arithmetic = bind_user_public_arithmetic(&mut b, &spine, &surface);
        let (r1cs, witness) = b.build();
        (r1cs, witness, arithmetic)
    }

    fn relation_satisfies(native: &SpineInputs, tx_live: Block128) -> bool {
        let (r1cs, witness, _) = build_relation(native, tx_live);
        r1cs.satisfies(&witness)
    }

    fn expr_tower_value(witness: &[F128], expr: &LinExpr) -> u128 {
        let flat = expr.eval(witness);
        flat_to_tower_u128((flat.lo as u128) | ((flat.hi as u128) << 64))
    }

    fn component_relation_satisfies(
        packed: Block128,
        amount: Block128,
        creation_id: Block128,
    ) -> bool {
        let mut b = FieldR1csBuilder::new();
        let packed = alloc_block(&mut b, packed);
        let amount = alloc_block(&mut b, amount);
        let creation_id = alloc_block(&mut b, creation_id);
        let _ = bind_packed_input_components(&mut b, &packed, &amount, &creation_id);
        let (r1cs, witness) = b.build();
        r1cs.satisfies(&witness)
    }

    #[test]
    fn honest_wide_integer_sum_and_exact_components_match_native() {
        let body = wide_sum_body();
        let facts = validate_public_tx_logic(&body).expect("native public arithmetic");
        assert!(facts.input_sum > u64::MAX as u128);
        let native = spine_inputs_from_body(&body);
        let (r1cs, witness, arithmetic) = build_relation(&native, Block128::ONE);
        assert!(r1cs.satisfies(&witness));
        assert_eq!(
            expr_tower_value(&witness, &arithmetic.inputs[0].amount.value),
            u64::MAX as u128
        );
        assert_eq!(
            expr_tower_value(&witness, &arithmetic.inputs[0].creation_id.value),
            u64::MAX as u128
        );
        assert_eq!(
            expr_tower_value(&witness, &arithmetic.inputs[1].creation_id.value),
            4
        );
        assert_eq!(
            expr_tower_value(&witness, &arithmetic.selected_inputs[0]),
            u64::MAX as u128
        );
        assert_eq!(
            expr_tower_value(&witness, &arithmetic.selected_outputs[1]),
            9
        );
        assert_eq!(
            expr_tower_value(&witness, &arithmetic.input_sum),
            facts.input_sum
        );
        assert_eq!(
            expr_tower_value(&witness, &arithmetic.output_sum),
            facts.output_sum
        );
        assert_eq!(
            expr_tower_value(&witness, &arithmetic.output_plus_fee),
            facts.output_sum + facts.fee_u64 as u128
        );
        assert_eq!(
            expr_tower_value(&witness, &arithmetic.paid_fee),
            facts.fee_u64 as u128
        );
    }

    #[test]
    fn canonical_ghost_raw_body_maps_to_zero_selected_arithmetic() {
        let body = noid_gkr::ghost_tx::ghost_tx_body();
        let facts = validate_public_tx_logic(&body).expect("canonical ghost public logic");
        let native = spine_inputs_from_body(&body);
        let (r1cs, witness, arithmetic) = build_relation(&native, Block128::ZERO);
        assert!(r1cs.satisfies(&witness));
        assert_eq!(facts.input_sum, 1);
        assert_eq!(facts.output_sum, 1);
        assert_eq!(expr_tower_value(&witness, &arithmetic.raw_input_sum), 1);
        assert_eq!(expr_tower_value(&witness, &arithmetic.raw_output_sum), 1);
        assert_eq!(expr_tower_value(&witness, &arithmetic.input_sum), 0);
        assert_eq!(expr_tower_value(&witness, &arithmetic.output_sum), 0);
        assert_eq!(facts.input_sum, facts.output_sum);
        assert_eq!(expr_tower_value(&witness, &arithmetic.paid_fee), 0);
    }

    #[test]
    fn inactive_slot_zeroes_selected_amounts_and_nonzero_raw_fee() {
        let native = spine_inputs_from_body(&sparse_body());
        let (r1cs, witness, arithmetic) = build_relation(&native, Block128::ZERO);
        assert!(r1cs.satisfies(&witness));
        assert_eq!(expr_tower_value(&witness, &arithmetic.fee.value), 1);
        assert_eq!(expr_tower_value(&witness, &arithmetic.input_sum), 0);
        assert_eq!(expr_tower_value(&witness, &arithmetic.output_sum), 0);
        assert_eq!(expr_tower_value(&witness, &arithmetic.paid_fee), 0);
        assert!(arithmetic
            .selected_inputs
            .iter()
            .all(|input| expr_tower_value(&witness, input) == 0));
        assert!(arithmetic
            .selected_outputs
            .iter()
            .all(|output| expr_tower_value(&witness, output) == 0));
    }

    #[test]
    fn matrix_is_invariant_across_sparse_dense_and_ghost_content() {
        let sparse = spine_inputs_from_body(&sparse_body());
        let dense = spine_inputs_from_body(&dense_body());
        let ghost = spine_inputs_from_body(&noid_gkr::ghost_tx::ghost_tx_body());
        let (sparse_r1cs, sparse_witness, _) = build_relation(&sparse, Block128::ONE);
        let (dense_r1cs, dense_witness, _) = build_relation(&dense, Block128::ONE);
        let (ghost_r1cs, ghost_witness, _) = build_relation(&ghost, Block128::ZERO);
        assert!(sparse_r1cs.satisfies(&sparse_witness));
        assert!(dense_r1cs.satisfies(&dense_witness));
        assert!(ghost_r1cs.satisfies(&ghost_witness));
        assert_eq!(sparse_r1cs.useful_rows, dense_r1cs.useful_rows);
        assert_eq!(sparse_r1cs.useful_rows, ghost_r1cs.useful_rows);
        assert_eq!(sparse_r1cs.a_0, dense_r1cs.a_0);
        assert_eq!(sparse_r1cs.a_0, ghost_r1cs.a_0);
        assert_eq!(sparse_r1cs.b_0, dense_r1cs.b_0);
        assert_eq!(sparse_r1cs.b_0, ghost_r1cs.b_0);
        assert_eq!(
            sparse_r1cs.statement_digest(),
            dense_r1cs.statement_digest()
        );
        assert_eq!(
            sparse_r1cs.statement_digest(),
            ghost_r1cs.statement_digest()
        );
    }

    #[test]
    fn page_arithmetic_defers_balance_and_fee_to_group_scanner() {
        let mut inflation = sparse_body();
        inflation.outputs[0].amount += 1;
        assert!(validate_public_tx_logic(&inflation).is_err());
        assert!(relation_satisfies(
            &spine_inputs_from_body(&inflation),
            Block128::ONE
        ));

        let mut wrong_fee = sparse_body();
        wrong_fee.fee += 1;
        assert!(validate_public_tx_logic(&wrong_fee).is_err());
        assert!(relation_satisfies(
            &spine_inputs_from_body(&wrong_fee),
            Block128::ONE
        ));
    }

    #[test]
    fn oversize_output_fee_and_component_witnesses_are_unsatisfied() {
        let body = sparse_body();
        let mut output = spine_inputs_from_body(&body);
        output.leaves[LEAF_OUTPUT0_DATA][1] = Block128::from((1u128 << 64) | 9);
        assert!(!relation_satisfies(&output, Block128::ONE));

        let mut fee = spine_inputs_from_body(&body);
        fee.leaves[LEAF_FEE][0] = Block128::from((1u128 << 64) | 1);
        assert!(!relation_satisfies(&fee, Block128::ONE));

        let packed = pack_amount_creation_id(17, 9);
        assert!(!component_relation_satisfies(
            packed,
            Block128::from(1u128 << 64),
            Block128::from(9u128)
        ));
        assert!(!component_relation_satisfies(
            packed,
            Block128::from(17u128),
            Block128::from(1u128 << 64)
        ));
    }

    #[test]
    fn nonzero_fee_unused_lane_is_unsatisfied() {
        let mut native = spine_inputs_from_body(&sparse_body());
        native.leaves[LEAF_FEE][1] = Block128::ONE;
        assert!(!relation_satisfies(&native, Block128::ONE));
    }

    #[test]
    fn packed_component_recombination_rejects_low_or_high_mixups() {
        let packed = pack_amount_creation_id(17, 9);
        assert!(component_relation_satisfies(
            packed,
            Block128::from(17u128),
            Block128::from(9u128)
        ));
        assert!(!component_relation_satisfies(
            packed,
            Block128::from(18u128),
            Block128::from(9u128)
        ));
        assert!(!component_relation_satisfies(
            packed,
            Block128::from(17u128),
            Block128::from(10u128)
        ));
        assert!(!component_relation_satisfies(
            packed,
            Block128::from(9u128),
            Block128::from(17u128)
        ));
    }

    #[test]
    fn every_range_valid_page_shape_reaches_group_arithmetic() {
        let mut no_outputs = sparse_body();
        no_outputs.outputs = [TxOutput::dummy(); TX_OUTPUTS];
        no_outputs.inputs[0].amount = 7;
        no_outputs.fee = 7;
        no_outputs.validity_bitmap = 1;

        let mut inflation = sparse_body();
        inflation.outputs[0].amount = 10;
        let mut wrong_fee = sparse_body();
        wrong_fee.fee = 2;
        let cases = [
            sparse_body(),
            wide_sum_body(),
            dense_body(),
            no_outputs,
            inflation,
            wrong_fee,
        ];
        for (case, body) in cases.iter().enumerate() {
            let trace_accepts = relation_satisfies(&spine_inputs_from_body(body), Block128::ONE);
            assert!(trace_accepts, "page arithmetic rejected case {case}");
        }
    }
}
