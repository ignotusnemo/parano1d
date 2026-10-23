// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact launch request execution at one complete-set clearing price.

use super::super::{alloc_block, mul, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::{checked_subtract, less_than, pack};
use super::financial_ratio::bind_financial_ratio;
use super::validation::{is_zero, require_nonzero};
use noid_core::{hardware::flat_to_tower_u128, Block128};
pub struct FinancialLaunchExecutionInputTrace {
    pub live: LinExpr,
    pub sell: LinExpr,
    pub requested: LinExpr,
    pub limit: LinExpr,
    pub quantity: LinExpr,
    pub price: [LinExpr; 2],
}
pub struct FinancialLaunchExecutionTrace {
    pub buy: LinExpr,
    pub sell: LinExpr,
    pub bought: LinExpr,
    pub sold: LinExpr,
    pub cost: LinExpr,
    pub proceeds: LinExpr,
    pub refund: LinExpr,
    pub output: LinExpr,
}
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}
fn a(b: &mut FieldR1csBuilder, x: u128) -> LinExpr {
    alloc_block(b, Block128(x))
}
/// Complete-set clearing and the exact typed request provide the price, final
/// quantity, original quantity and limit. Integer costs use ceil for buys and
/// floor for sells, with exact proportional limits and native dust rejection.
pub fn bind_financial_launch_execution(
    b: &mut FieldR1csBuilder,
    input: &FinancialLaunchExecutionInputTrace,
) -> FinancialLaunchExecutionTrace {
    let member = &input.live;
    let sell = &input.sell;
    for flag in [member, sell] {
        let bad = mul(b, flag, &flag.add_const(F128::ONE));
        pin_zero(b, &bad);
    }
    let outside = mul(b, sell, &member.add_const(F128::ONE));
    pin_zero(b, &outside);
    let buy = member.add(sell);
    let requested = mul(b, member, &input.requested);
    let limit = mul(b, member, &input.limit);
    let q = mul(b, member, &input.quantity);
    let outside = mul(b, &member.add_const(F128::ONE), &input.quantity);
    pin_zero(b, &outside);
    let price = &input.price;
    let qb = bits(b, &q, 63);
    let request_bits = bits(b, &requested, 63);
    let over = less_than(b, &request_bits, &qb);
    pin_zero(b, &over);
    require_nonzero(b, &requested, member);
    let numerator = mul(b, member, &price[0]);
    let denominator = mul(b, member, &price[1]);
    let qv = tower(b, &q);
    let nv = tower(b, &numerator);
    let dv = tower(b, &denominator);
    let paying = tower(b, &buy) != 0;
    let amount = a(
        b,
        if dv == 0 {
            0
        } else if paying {
            qv.saturating_mul(nv).div_ceil(dv)
        } else {
            qv.saturating_mul(nv) / dv
        },
    );
    let amount_bits = bits(b, &amount, 63);
    let _ = bind_financial_ratio(b, member, &buy, &q, &numerator, &denominator, &amount, 64);
    let rv = tower(b, &requested);
    let lv = tower(b, &limit);
    let bound = a(
        b,
        if rv == 0 {
            0
        } else if paying {
            lv.saturating_mul(qv).div_ceil(rv)
        } else {
            lv.saturating_mul(qv) / rv
        },
    );
    let bound_bits = bits(b, &bound, 63);
    let _ = bind_financial_ratio(b, member, &buy, &limit, &q, &requested, &bound, 64);
    let low = less_than(b, &amount_bits, &bound_bits);
    let high = less_than(b, &bound_bits, &amount_bits);
    let bad = mul(b, sell, &low).add(&mul(b, &buy, &high));
    pin_zero(b, &bad);
    let budget = bits(b, &limit, 63);
    let over = less_than(b, &budget, &amount_bits);
    let bad = mul(b, &buy, &over);
    pin_zero(b, &bad);
    let positive = is_zero(b, &q).add_const(F128::ONE);
    let empty = is_zero(b, &amount);
    let bad = mul(b, sell, &positive);
    let bad = mul(b, &bad, &empty);
    pin_zero(b, &bad);
    let cost = mul(b, &buy, &amount);
    let received = mul(b, sell, &amount);

    let bought = mul(b, &buy, &q);
    let sold = mul(b, sell, &q);
    let principal = mul(b, &buy, &limit).add(&mul(b, sell, &requested));
    let spent = cost.add(&sold);
    let principal = bits(b, &principal, 64);
    let spent = bits(b, &spent, 64);
    let refund = pack(&checked_subtract(b, &principal, &spent));
    let output = bought.add(&received);
    FinancialLaunchExecutionTrace {
        buy,
        sell: sell.clone(),
        bought,
        sold,
        cost,
        proceeds: received,
        refund,
        output,
    }
}
