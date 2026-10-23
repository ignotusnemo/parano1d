// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native fungible transfer, proportional redemption and reserve top-up.

use super::super::{mul, pin_eq, pin_zero, range_check_bits, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::{checked_add, checked_subtract, extend, less_than, multiply, pack};
use super::validation::{bits, nonzero_pair, require_nonzero, NativeOpeningTrace};

pub struct FungibleTransitionTrace {
    pub live: LinExpr,
    pub redemption_live: LinExpr,
    pub input_units: Vec<LinExpr>,
    pub output_units: Vec<LinExpr>,
    pub burned_units: Vec<LinExpr>,
    pub payout_micronoid: Vec<LinExpr>,
    pub contribution_micronoid: Vec<LinExpr>,
}

pub struct FungibleInventoryTrace {
    pub units: Vec<LinExpr>,
    pub reserve: Vec<LinExpr>,
    pub supply: Vec<LinExpr>,
    pub initial: LinExpr,
    pub definition_root: [LinExpr; 2],
}

fn operation_selectors(b: &mut FieldR1csBuilder, operation: &LinExpr) -> [LinExpr; 8] {
    let op_bits = range_check_bits(b, operation, 3);
    let mut tensor = vec![LinExpr::constant(F128::ONE)];
    for bit in op_bits {
        let bit = LinExpr::from_wire(bit);
        let len = tensor.len();
        let mut next = vec![LinExpr::zero(); 2 * len];
        for (index, value) in tensor.iter().enumerate() {
            let one = mul(b, value, &bit);
            next[index] = value.add(&one);
            next[index + len] = one;
        }
        tensor = next;
    }
    for index in [1, 5, 6, 7] {
        pin_zero(b, &tensor[index]);
    }
    tensor.try_into().unwrap()
}

fn inventory(
    b: &mut FieldR1csBuilder,
    openings: &[NativeOpeningTrace],
    asset: &[LinExpr; 2],
    balances_allowed: &LinExpr,
    reserve_required: &LinExpr,
) -> FungibleInventoryTrace {
    let mut units = vec![LinExpr::zero(); 64];
    let mut reserve = vec![LinExpr::zero(); 64];
    let mut supply = vec![LinExpr::zero(); 64];
    let mut initial = LinExpr::zero();
    let mut definition_root = [LinExpr::zero(), LinExpr::zero()];
    let mut seen_reserve = LinExpr::zero();
    for opening in openings {
        let selected = &opening.commitment.selectors;
        let allowed_balance = mul(b, &selected[2], balances_allowed);
        let allowed_reserve = mul(b, &selected[3], reserve_required);
        pin_zero(b, &opening.live.add(&allowed_balance).add(&allowed_reserve));
        for (actual, expected) in opening.identifier.iter().zip(asset) {
            let different = mul(b, &opening.live, &actual.add(expected));
            pin_zero(b, &different);
        }
        let repeated_reserve = mul(b, &seen_reserve, &selected[3]);
        pin_zero(b, &repeated_reserve);
        seen_reserve = seen_reserve.add(&selected[3]);
        // In allowed inventories only balances have nonzero primary units;
        // reserve projections are already zero for every other kind.
        units = checked_add(b, &units, &bits(&opening.primary));
        for i in 0..64 {
            reserve[i] = reserve[i].add(&LinExpr::from_wire(opening.reserve_micronoid.bits[i]));
            supply[i] = supply[i].add(&LinExpr::from_wire(opening.outstanding_units.bits[i]));
        }
        initial = initial.add(&opening.initial_supply.value);
        for (total, value) in definition_root.iter_mut().zip(&opening.definition_root) {
            *total = total.add(value);
        }
    }
    pin_eq(b, &seen_reserve, reserve_required);
    FungibleInventoryTrace {
        units,
        reserve,
        supply,
        initial,
        definition_root,
    }
}

fn gated_bits(b: &mut FieldR1csBuilder, when: &LinExpr, bits: &[LinExpr]) -> Vec<LinExpr> {
    bits.iter().map(|bit| mul(b, when, bit)).collect()
}

/// Operation codes match the native header: zero padding, two transfer,
/// three redemption and four top-up. The complete native inventories are
/// routed from authenticated body/State actions by the enclosing block.
/// Its shared NOID conservation binds the returned payout/contribution to
/// ordinary payments and fees. `remainder` is an untrusted u64 witness.
pub fn bind_fungible_transition(
    b: &mut FieldR1csBuilder,
    operation: &LinExpr,
    asset: &[LinExpr; 2],
    inputs: &[NativeOpeningTrace],
    outputs: &[NativeOpeningTrace],
    remainder: &LinExpr,
) -> FungibleTransitionTrace {
    let op = operation_selectors(b, operation);
    let live = op[0].add_const(F128::ONE);
    let transfer = &op[2];
    let redemption = &op[3];
    let top_up = &op[4];
    nonzero_pair(b, asset, &live);
    for lane in asset {
        let inactive = mul(b, &op[0], lane);
        pin_zero(b, &inactive);
    }
    let balances_allowed = transfer.add(redemption);
    let reserve_required = redemption.add(top_up);
    let before = inventory(b, inputs, asset, &balances_allowed, &reserve_required);
    let after = inventory(b, outputs, asset, &balances_allowed, &reserve_required);
    finish_fungible_transition(b, op, before, after, remainder)
}

/// Bind already aggregated, exact complete native inventories. The caller
/// enforces allowed kinds, unique reserves and per-asset membership while
/// deriving these u64 summaries from the actual State actions.
pub fn bind_fungible_inventory_transition(
    b: &mut FieldR1csBuilder,
    operation: &LinExpr,
    asset: &[LinExpr; 2],
    before: FungibleInventoryTrace,
    after: FungibleInventoryTrace,
    remainder: &LinExpr,
) -> FungibleTransitionTrace {
    let op = operation_selectors(b, operation);
    let live = op[0].add_const(F128::ONE);
    nonzero_pair(b, asset, &live);
    for lane in asset {
        let inactive = mul(b, &op[0], lane);
        pin_zero(b, &inactive);
    }
    finish_fungible_transition(b, op, before, after, remainder)
}

fn finish_fungible_transition(
    b: &mut FieldR1csBuilder,
    op: [LinExpr; 8],
    before: FungibleInventoryTrace,
    after: FungibleInventoryTrace,
    remainder: &LinExpr,
) -> FungibleTransitionTrace {
    let live = op[0].add_const(F128::ONE);
    let transfer = &op[2];
    let redemption = &op[3];
    let top_up = &op[4];
    let balances_allowed = transfer.add(redemption);
    let reserve_required = redemption.add(top_up);
    require_nonzero(b, &pack(&before.units), &balances_allowed);
    require_nonzero(b, &pack(&after.units), transfer);

    let burned = checked_subtract(b, &before.units, &after.units);
    let burned_value = pack(&burned);
    require_nonzero(b, &burned_value, redemption);
    let no_redemption_burn = mul(b, &redemption.add_const(F128::ONE), &burned_value);
    pin_zero(b, &no_redemption_burn);
    let restored_supply = checked_add(b, &after.supply, &burned);
    pin_eq(b, &pack(&restored_supply), &pack(&before.supply));
    pin_eq(b, &before.initial, &after.initial);
    for (old, next) in before.definition_root.iter().zip(&after.definition_root) {
        pin_eq(b, old, next);
    }

    let redemption_old = gated_bits(b, redemption, &before.reserve);
    let redemption_next = gated_bits(b, redemption, &after.reserve);
    let payout = checked_subtract(b, &redemption_old, &redemption_next);
    let top_up_old = gated_bits(b, top_up, &before.reserve);
    let top_up_next = gated_bits(b, top_up, &after.reserve);
    let contribution = checked_subtract(b, &top_up_next, &top_up_old);
    require_nonzero(b, &pack(&contribution), top_up);
    require_nonzero(b, &pack(&before.supply), &reserve_required);

    let remainder_bits: Vec<_> = range_check_bits(b, remainder, 64)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect();
    let unused_remainder = mul(b, &redemption.add_const(F128::ONE), remainder);
    pin_zero(b, &unused_remainder);
    let proper_remainder = less_than(b, &remainder_bits, &before.supply);
    let invalid_remainder = mul(b, redemption, &proper_remainder.add_const(F128::ONE));
    pin_zero(b, &invalid_remainder);
    let numerator = multiply(b, &before.reserve, &burned);
    let quotient_product = multiply(b, &before.supply, &payout);
    let reconstructed = checked_add(b, &quotient_product, &extend(&remainder_bits, 128));
    pin_eq(b, &pack(&numerator), &pack(&reconstructed));

    FungibleTransitionTrace {
        live,
        redemption_live: redemption.clone(),
        input_units: before.units,
        output_units: after.units,
        burned_units: burned,
        payout_micronoid: payout,
        contribution_micronoid: contribution,
    }
}
