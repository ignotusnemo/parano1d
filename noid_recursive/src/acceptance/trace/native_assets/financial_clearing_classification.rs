// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared complete active-row classification for AMM and launch clearing.

use super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::{extend, less_than, multiply, pack};
use super::validation::require_nonzero;

pub struct FinancialClearingClassificationInputTrace {
    pub live: LinExpr,
    pub market: LinExpr,
    pub launch: LinExpr,
    pub side: LinExpr,
    pub quantity: LinExpr,
    pub limit: LinExpr,
    pub price: [LinExpr; 2],
    pub at_cap: LinExpr,
}
pub struct FinancialClearingClassificationTrace {
    pub full: LinExpr,
    pub marginal: LinExpr,
    pub raw_full: LinExpr,
    pub raw_marginal: LinExpr,
    pub limit_price: [LinExpr; 2],
    pub quantity_bits: Vec<LinExpr>,
    pub price_bits: [Vec<LinExpr>; 2],
}
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn boolean(b: &mut FieldR1csBuilder, x: &LinExpr) {
    let bad = mul(b, x, &x.add_const(F128::ONE));
    pin_zero(b, &bad);
}

/// The complete active-row route binds exact source fields, immutable native
/// family, current step price and launch cap branch. Market quantity means
/// after-fee capacity; launch quantity means the requested token quantity.
/// Side is quote-to-base for markets and sell for launches.
pub fn bind_financial_clearing_classification(
    b: &mut FieldR1csBuilder,
    input: &FinancialClearingClassificationInputTrace,
) -> FinancialClearingClassificationTrace {
    for flag in [
        &input.live,
        &input.market,
        &input.launch,
        &input.side,
        &input.at_cap,
    ] {
        boolean(b, flag);
    }
    pin_eq(b, &input.market.add(&input.launch), &input.live);
    let both = mul(b, &input.market, &input.launch);
    pin_zero(b, &both);
    let outside = mul(b, &input.at_cap, &input.launch.add_const(F128::ONE));
    pin_zero(b, &outside);
    let quantity = mul(b, &input.live, &input.quantity);
    let limit = mul(b, &input.live, &input.limit);
    let quantity_bits = bits(b, &quantity, 63);
    let limit_bits = bits(b, &limit, 63);
    require_nonzero(b, &quantity, &input.live);
    let buy = mul(b, &input.launch, &input.side.add_const(F128::ONE));
    let positive_limit = input.market.add(&buy);
    require_nonzero(b, &limit, &positive_limit);
    let n = mul(b, &input.live, &input.price[0]);
    let d = mul(b, &input.live, &input.price[1]);
    let n_bits = bits(b, &n, 64);
    let d_bits = bits(b, &d, 64);
    require_nonzero(b, &n, &input.live);
    require_nonzero(b, &d, &input.live);
    let swap = mul(b, &input.market, &input.side);
    let mut limit_n = Vec::with_capacity(63);
    let mut limit_d = Vec::with_capacity(63);
    for i in 0..63 {
        let delta = mul(b, &swap, &quantity_bits[i].add(&limit_bits[i]));
        limit_n.push(limit_bits[i].add(&delta));
        limit_d.push(quantity_bits[i].add(&delta));
    }
    let left = multiply(b, &n_bits, &extend(&limit_d, 64));
    let right = multiply(b, &d_bits, &extend(&limit_n, 64));
    let low = less_than(b, &left, &right);
    let high = less_than(b, &right, &left);
    let equal = low.add(&high).add_const(F128::ONE);
    let raw_marginal = mul(b, &input.live, &equal);
    let direction = mul(b, &input.side, &low.add(&high));
    let ordinary_full = high.add(&direction);
    let launch_delta = mul(b, &input.launch, &high.add(&low));
    let ordinary_full = ordinary_full.add(&launch_delta);
    let raw_full = mul(b, &input.live, &ordinary_full);
    let included = raw_full.add(&raw_marginal);
    let cap_full = mul(b, &input.side, &included);
    let cap_marginal = mul(b, &input.side.add_const(F128::ONE), &included);
    let full = raw_full.add(&mul(b, &input.at_cap, &raw_full.add(&cap_full)));
    let marginal = raw_marginal.add(&mul(b, &input.at_cap, &raw_marginal.add(&cap_marginal)));
    FinancialClearingClassificationTrace {
        full,
        marginal,
        raw_full,
        raw_marginal,
        limit_price: [pack(&limit_n), pack(&limit_d)],
        quantity_bits,
        price_bits: [n_bits, d_bits],
    }
}
