// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical launch price and cap checks from complete global summaries.

use super::super::{
    alloc_block, flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::{checked_add, checked_subtract, less_than, multiply, pack};
use super::financial_clearing_summaries::FinancialClearingSummaryTrace;
use super::validation::{is_zero, require_nonzero};
use noid_core::{hardware::flat_to_tower_u128, Block128};

pub struct FinancialLaunchContextTrace {
    pub marginal_totals: [LinExpr; 2],
    pub partial: [LinExpr; 3],
    pub fraction_numerator: LinExpr,
    pub fraction_denominator: LinExpr,
    pub at_cap: LinExpr,
}
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn boolean(b: &mut FieldR1csBuilder, x: &LinExpr) {
    let bad = mul(b, x, &x.add_const(F128::ONE));
    pin_zero(b, &bad);
}
fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}
fn scale(b: &mut FieldR1csBuilder, x: &[LinExpr], c: u64, width: usize) -> Vec<LinExpr> {
    let mut sum = vec![LinExpr::zero(); width];
    for shift in 0..64 {
        if c & (1u64 << shift) == 0 {
            continue;
        }
        let mut row = vec![LinExpr::zero(); width];
        for (i, v) in x.iter().enumerate() {
            if i + shift < width {
                row[i + shift] = v.clone();
            } else {
                pin_zero(b, v);
            }
        }
        sum = checked_add(b, &sum, &row);
    }
    sum
}
fn gated(b: &mut FieldR1csBuilder, flag: &LinExpr, x: &[LinExpr]) -> Vec<LinExpr> {
    x.iter().map(|v| mul(b, flag, v)).collect()
}
fn five_product(b: &mut FieldR1csBuilder, x: &[LinExpr], y: &[LinExpr]) -> Vec<LinExpr> {
    let product = multiply(b, x, y);
    scale(b, &product, 5, 128)
}
fn equal_when(b: &mut FieldR1csBuilder, flag: &LinExpr, x: &LinExpr, y: &LinExpr) {
    let bad = mul(b, flag, &x.add(y));
    pin_zero(b, &bad);
}

/// Validated fixed supply, current sold quantity and exact active-row totals
/// supply the complete native continuous problem. The cap and first-equal
/// boundary retain their native precedence and raw coordinate representation.
pub fn bind_financial_launch_context(
    b: &mut FieldR1csBuilder,
    live: &LinExpr,
    supply: &LinExpr,
    sold: &LinExpr,
    price: &[LinExpr; 2],
    at_cap: &LinExpr,
    summary: &FinancialClearingSummaryTrace,
) -> FinancialLaunchContextTrace {
    boolean(b, live);
    boolean(b, at_cap);
    let outside = mul(b, at_cap, &live.add_const(F128::ONE));
    pin_zero(b, &outside);
    let capped = at_cap.clone();
    let uncapped = live.add(&capped);
    let supply = mul(b, live, supply);
    let sold = mul(b, live, sold);
    let sb = bits(b, &supply, 64);
    let qb = bits(b, &sold, 64);
    require_nonzero(b, &supply, live);
    let sv = tower(b, &supply);
    let sale = alloc_block(b, Block128(sv / 5 * 3));
    let sale_bits = bits(b, &sale, 64);
    let three_supply = scale(b, &sb, 3, 64);
    let five_sale = scale(b, &sale_bits, 5, 64);
    pin_eq(b, &pack(&five_sale), &pack(&three_supply));
    let remaining = checked_subtract(b, &sale_bits, &qb);
    require_nonzero(b, &pack(&remaining), live);
    let curve_denominator = scale(b, &sb, 900, 64);
    pin_zero(b, &curve_denominator[63]);
    let five_sold = scale(b, &qb, 5, 64);
    let ten_sold = scale(b, &qb, 10, 64);
    let center = checked_add(b, &three_supply, &ten_sold);
    let offset = checked_add(b, &three_supply, &five_sold);
    let n = mul(b, live, &price[0]);
    let d = mul(b, live, &price[1]);
    let nb = bits(b, &n, 64);
    let db = bits(b, &d, 64);
    require_nonzero(b, &n, live);
    require_nonzero(b, &d, live);

    boolean(b, &summary.nonempty);
    boolean(b, &summary.boundary);
    let outside = mul(b, &summary.nonempty, &live.add_const(F128::ONE));
    pin_zero(b, &outside);
    let outside = mul(b, &summary.boundary, &summary.nonempty.add_const(F128::ONE));
    pin_zero(b, &outside);
    let full_totals: [Vec<LinExpr>; 2] = std::array::from_fn(|j| bits(b, &summary.full[j], 64));
    let marginal_totals: [Vec<LinExpr>; 2] =
        std::array::from_fn(|j| bits(b, &summary.marginal[j], 64));
    for x in full_totals.iter().chain(&marginal_totals) {
        pin_zero(b, &x[63]);
    }
    let boundary = summary.boundary.clone();
    let boundary_price = summary.boundary_price.clone();
    let interior = mul(b, &uncapped, &boundary.add_const(F128::ONE));
    let boundary_flag = mul(b, &uncapped, &boundary);
    let fives_buys = scale(b, &full_totals[0], 5, 64);
    let fives_sells = scale(b, &full_totals[1], 5, 64);
    let gross_center = checked_add(b, &center, &fives_buys);
    let interior_numerator = checked_subtract(b, &gross_center, &fives_sells);
    let cap_term = checked_add(b, &qb, &sale_bits);
    let cap_term = scale(b, &cap_term, 5, 64);
    let cap_numerator = checked_add(b, &three_supply, &cap_term);
    let expected_n = mul(b, &interior, &pack(&interior_numerator))
        .add(&mul(b, &boundary_flag, &boundary_price[0]))
        .add(&mul(b, &capped, &pack(&cap_numerator)));
    let expected_d = mul(b, &interior, &pack(&curve_denominator))
        .add(&mul(b, &boundary_flag, &boundary_price[1]))
        .add(&mul(b, &capped, &pack(&curve_denominator)));
    pin_eq(b, &n, &expected_n);
    pin_eq(b, &d, &expected_d);
    let n_un = gated(b, &uncapped, &nb);
    let d_un = gated(b, &uncapped, &db);
    let curve = gated(b, &uncapped, &curve_denominator);
    let offset = gated(b, &uncapped, &offset);
    let target_left = multiply(b, &curve, &n_un);
    let target_right = multiply(b, &offset, &d_un);
    let target = checked_subtract(b, &target_left, &target_right);
    let cap_target = five_product(b, &d_un, &sale_bits);
    let below_cap = less_than(b, &target, &cap_target);
    equal_when(b, &uncapped, &below_cap, &LinExpr::constant(F128::ONE));
    let fbuy = gated(b, &uncapped, &full_totals[0]);
    let fsell = gated(b, &uncapped, &full_totals[1]);
    let mbuy = gated(b, &uncapped, &marginal_totals[0]);
    let msell = gated(b, &uncapped, &marginal_totals[1]);
    let start = gated(b, &uncapped, &qb);
    let start_buy = checked_add(b, &start, &fbuy);
    let r = five_product(b, &start_buy, &d_un);
    let sell_product = five_product(b, &fsell, &d_un);
    let l = checked_add(b, &target, &sell_product);
    let max_buy = five_product(b, &mbuy, &d_un);
    let max_sell = five_product(b, &msell, &d_un);
    let r_buy = checked_add(b, &r, &max_buy);
    let l_sell = checked_add(b, &l, &max_sell);
    let buy_numerator = checked_subtract(b, &l_sell, &r);
    let sell_numerator = checked_subtract(b, &r_buy, &l);
    let choose_buy = less_than(b, &l_sell, &r_buy);
    let choose_buy = mul(b, &uncapped, &choose_buy);
    let choose_sell = uncapped.add(&choose_buy);
    let num = (0..128)
        .map(|i| {
            mul(b, &choose_buy, &buy_numerator[i]).add(&mul(b, &choose_sell, &sell_numerator[i]))
        })
        .collect::<Vec<_>>();
    let den = (0..128)
        .map(|i| mul(b, &choose_buy, &max_buy[i]).add(&mul(b, &choose_sell, &max_sell[i])))
        .collect::<Vec<_>>();
    let empty = is_zero(b, &pack(&den));
    let fallback = mul(b, &uncapped, &empty);
    let invalid = mul(b, &fallback, &pack(&num));
    pin_zero(b, &invalid);
    let partial_buy = mul(b, &choose_buy, &empty.add_const(F128::ONE));
    let partial_sell = mul(b, &choose_sell, &empty.add_const(F128::ONE));
    let cap_buys = checked_add(b, &full_totals[0], &marginal_totals[0]);
    let cap_sells = checked_add(b, &full_totals[1], &marginal_totals[1]);
    let needed = checked_add(b, &remaining, &cap_sells);
    let too_small = less_than(b, &cap_buys, &needed);
    let bad = mul(b, &capped, &too_small);
    pin_zero(b, &bad);
    require_nonzero(b, &pack(&cap_buys), &capped);
    let numerator = pack(&num).add(&mul(b, &capped, &pack(&needed)));
    let denominator = pack(&den)
        .add(&fallback)
        .add(&mul(b, &capped, &pack(&cap_buys)));
    let numerator_bits = bits(b, &numerator, 128);
    let denominator_bits = bits(b, &denominator, 128);
    let over = less_than(b, &denominator_bits, &numerator_bits);
    pin_zero(b, &over);
    let cap_marginal = mul(b, &capped, &pack(&cap_buys));
    let result_totals = [
        mul(b, &uncapped, &pack(&marginal_totals[0])).add(&cap_marginal),
        mul(b, &uncapped, &pack(&marginal_totals[1])),
    ];
    let partial = [partial_buy.add(&capped), partial_sell, fallback];
    pin_eq(
        b,
        &partial.iter().fold(LinExpr::zero(), |s, x| s.add(x)),
        live,
    );
    FinancialLaunchContextTrace {
        marginal_totals: result_totals,
        partial,
        fraction_numerator: numerator,
        fraction_denominator: denominator,
        at_cap: capped,
    }
}
