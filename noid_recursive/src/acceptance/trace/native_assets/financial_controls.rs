// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded shared product checks for pool and launch controls.

use noid_core::hardware::flat_to_tower_u128;
use noid_tx::native_assets::{
    launch::{LAUNCH_MAX_SUPPLY, LAUNCH_PROFILE},
    NativeKind,
};

use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::actions::route_sorted;
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, extend, less_than, multiply};
use super::financial_actions::FinancialActionTrace;
use super::financial_definitions::{constant_bits, scale_bits, FinancialDefinitionsTrace};
use super::validation::require_nonzero;

pub struct FinancialControlArithmeticTrace {
    pub pool: LinExpr,
    pub launch: LinExpr,
    pub remainder: Vec<LinExpr>,
    pub sold_units: Vec<LinExpr>,
}

fn bits(b: &mut FieldR1csBuilder, packed: &LinExpr) -> (Vec<LinExpr>, Vec<LinExpr>) {
    let t = split_packed_input_value(b, packed);
    (
        t.amount
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect(),
        t.creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect(),
    )
}

/// Pool controls require shares^2 <= base*quote. Launch controls require
/// cash = ceil(((3*S+5*sold)*sold)/(900*S)) and inventory above the fixed
/// DEX allocation. Both relations share two exact unsigned products.
/// The enclosing relation supplies canonical carrier fields and a validated,
/// root-linked launch definition whose supply is a positive whole-token count.
pub fn bind_financial_control_arithmetic(
    b: &mut FieldR1csBuilder,
    pool: &LinExpr,
    launch: &LinExpr,
    fields: &[LinExpr; 12],
    definition_supply: &LinExpr,
) -> FinancialControlArithmeticTrace {
    for flag in [pool, launch] {
        let invalid = mul(b, flag, &flag.add_const(F128::ONE));
        pin_zero(b, &invalid);
    }
    let overlap = mul(b, pool, launch);
    pin_zero(b, &overlap);
    let active = pool.add(launch);
    let state = mul(b, &active, &fields[2]);
    let (low, high) = bits(b, &state);
    let shares = mul(b, pool, &fields[3]);
    let (shares, _) = bits(b, &shares);
    let supply = mul(b, launch, definition_supply);
    let supply = split_packed_input_value(b, &supply);
    pin_eq(
        b,
        &supply.creation_id.value,
        &launch.scale(flat_const(u128::from(LAUNCH_PROFILE))),
    );
    require_nonzero(b, &supply.amount.value, launch);
    let supply = supply
        .amount
        .bits
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let beyond_max = less_than(
        b,
        &constant_bits(u128::from(LAUNCH_MAX_SUPPLY), 64),
        &supply,
    );
    pin_zero(b, &beyond_max);
    let inventory = low
        .iter()
        .map(|bit| mul(b, launch, bit))
        .collect::<Vec<_>>();
    let sold_units = checked_subtract(b, &supply, &inventory);
    let five_inventory = scale_bits(b, &inventory, 5, 64);
    let twice_supply = scale_bits(b, &supply, 2, 64);
    let above_dex = less_than(b, &twice_supply, &five_inventory);
    let bad_inventory = mul(b, launch, &above_dex.add_const(F128::ONE));
    pin_zero(b, &bad_inventory);
    let denominator = scale_bits(b, &supply, 900, 64);
    let three_supply = scale_bits(b, &supply, 3, 64);
    let five_sold = scale_bits(b, &sold_units, 5, 64);
    let numerator_factor = checked_add(b, &three_supply, &five_sold);
    let left_a = (0..64)
        .map(|i| {
            let a = mul(b, pool, &low[i]);
            a.add(&mul(b, launch, &high[i]))
        })
        .collect::<Vec<_>>();
    let left_b = (0..64)
        .map(|i| mul(b, pool, &high[i]).add(&denominator[i]))
        .collect::<Vec<_>>();
    let right_a = (0..64)
        .map(|i| shares[i].add(&numerator_factor[i]))
        .collect::<Vec<_>>();
    let right_b = (0..64)
        .map(|i| shares[i].add(&sold_units[i]))
        .collect::<Vec<_>>();
    for operand in [&left_a, &left_b, &right_a, &right_b] {
        pin_zero(b, &operand[63]);
    }
    let left_product = multiply(b, &left_a[..63], &left_b[..63]);
    let right_product = multiply(b, &right_a[..63], &right_b[..63]);
    let remainder = checked_subtract(b, &left_product, &right_product);
    let proper = less_than(b, &remainder, &extend(&denominator, 126));
    let wrong_cash = mul(b, launch, &proper.add_const(F128::ONE));
    pin_zero(b, &wrong_cash);
    FinancialControlArithmeticTrace {
        pool: pool.clone(),
        launch: launch.clone(),
        remainder,
        sold_units,
    }
}

fn tower(b: &FieldR1csBuilder, value: &LinExpr) -> u128 {
    let x = value.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}

/// Route every pool/launch control before applying the shared arithmetic.
/// The bound is a fixed profile capacity; no live source row may be dropped.
pub fn bind_financial_controls(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    capacity: usize,
) -> Vec<FinancialControlArithmeticTrace> {
    assert_eq!(actions.len(), definitions.actions.len());
    assert!(capacity > 0 && capacity <= actions.len().max(1).next_power_of_two());
    let candidates = actions
        .iter()
        .zip(&definitions.actions)
        .map(|(action, definition)| {
            let pool = action.opening.commitment.selector(NativeKind::MarketPool);
            let launch = action.opening.commitment.selector(NativeKind::LaunchState);
            let live = pool.add(launch);
            let mut row = vec![
                live.clone(),
                pool.clone(),
                launch.clone(),
                mul(b, &live, &action.header_page),
                mul(b, &live, &action.is_output),
                mul(b, &live, &action.ordinal),
            ];
            row.extend(
                action
                    .opening
                    .fields
                    .iter()
                    .map(|field| mul(b, &live, field)),
            );
            row.push(mul(b, launch, &definition.fields[4]));
            row
        })
        .collect();
    let rows = route_sorted(b, candidates, 19, |b, row| {
        vec![tower(b, &row[3]), tower(b, &row[4]), tower(b, &row[5])]
    });
    for row in &rows[capacity..] {
        pin_zero(b, &row[0]);
    }
    let mut previous = LinExpr::constant(F128::ONE);
    rows.into_iter()
        .take(capacity)
        .map(|row| {
            let hole = mul(b, &row[0], &previous.add_const(F128::ONE));
            pin_zero(b, &hole);
            previous = row[0].clone();
            let fields: [LinExpr; 12] = std::array::from_fn(|i| row[6 + i].clone());
            bind_financial_control_arithmetic(b, &row[1], &row[2], &fields, &row[18])
        })
        .collect()
}
