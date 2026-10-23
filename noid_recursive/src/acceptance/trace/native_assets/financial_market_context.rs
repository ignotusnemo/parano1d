// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical AMM price and fraction checks from complete global summaries.

use super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::{checked_add, checked_subtract, less_than, multiply, pack};
use super::financial_clearing_summaries::FinancialClearingSummaryTrace;
use super::validation::{is_zero, require_nonzero};

pub struct FinancialMarketContextTrace {
    pub full_totals: [LinExpr; 2],
    pub marginal_totals: [LinExpr; 2],
    pub partial: [LinExpr; 3],
    pub fraction_numerator: LinExpr,
    pub fraction_denominator: LinExpr,
}
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn boolean(b: &mut FieldR1csBuilder, x: &LinExpr) {
    let bad = mul(b, x, &x.add_const(F128::ONE));
    pin_zero(b, &bad);
}
fn twice_plus(b: &mut FieldR1csBuilder, reference: &[LinExpr], sum: &[LinExpr]) -> Vec<LinExpr> {
    assert_eq!(reference.len(), 64);
    assert_eq!(sum.len(), 64);
    pin_zero(b, &sum[63]);
    let mut twice = vec![LinExpr::zero()];
    twice.extend(sum[..63].iter().cloned());
    checked_add(b, reference, &twice)
}

/// Complete exact active-row summaries supply side totals and the first
/// equal-price source. Positive immutable reserves and native admission
/// bounds compose with this exact canonical price and partial-side relation.
pub fn bind_financial_market_context(
    b: &mut FieldR1csBuilder,
    live: &LinExpr,
    reference: &[LinExpr; 2],
    price: &[LinExpr; 2],
    summary: &FinancialClearingSummaryTrace,
) -> FinancialMarketContextTrace {
    boolean(b, live);
    boolean(b, &summary.nonempty);
    boolean(b, &summary.boundary);
    let outside = mul(b, &summary.nonempty, &live.add_const(F128::ONE));
    pin_zero(b, &outside);
    let outside = mul(b, &summary.boundary, &summary.nonempty.add_const(F128::ONE));
    pin_zero(b, &outside);
    let base = mul(b, live, &reference[0]);
    let quote = mul(b, live, &reference[1]);
    let base_bits = bits(b, &base, 64);
    let quote_bits = bits(b, &quote, 64);
    pin_zero(b, &base_bits[63]);
    pin_zero(b, &quote_bits[63]);
    require_nonzero(b, &base, live);
    require_nonzero(b, &quote, live);
    let n = mul(b, live, &price[0]);
    let d = mul(b, live, &price[1]);
    let n_bits = bits(b, &n, 64);
    let d_bits = bits(b, &d, 64);
    require_nonzero(b, &n, live);
    require_nonzero(b, &d, live);
    let full_totals: [Vec<LinExpr>; 2] = std::array::from_fn(|j| bits(b, &summary.full[j], 64));
    let marginal_totals: [Vec<LinExpr>; 2] =
        std::array::from_fn(|j| bits(b, &summary.marginal[j], 64));
    for x in full_totals.iter().chain(&marginal_totals) {
        pin_zero(b, &x[63]);
    }
    let boundary = summary.boundary.clone();
    let boundary_price = summary.boundary_price.clone();
    let interior = mul(b, live, &boundary.add_const(F128::ONE));
    let a = twice_plus(b, &base_bits, &full_totals[0]);
    let c = twice_plus(b, &quote_bits, &full_totals[1]);
    let expected_n = mul(b, &interior, &pack(&c)).add(&boundary_price[0]);
    let expected_d = mul(b, &interior, &pack(&a)).add(&boundary_price[1]);
    pin_eq(b, &n, &expected_n);
    pin_eq(b, &d, &expected_d);
    let combined_base = checked_add(b, &full_totals[0], &marginal_totals[0]);
    let combined_quote = checked_add(b, &full_totals[1], &marginal_totals[1]);
    let amax = twice_plus(b, &base_bits, &combined_base);
    let cmax = twice_plus(b, &quote_bits, &combined_quote);
    let left = multiply(b, &n_bits, &a);
    let right = multiply(b, &d_bits, &c);
    let left_max = multiply(b, &n_bits, &amax);
    let right_max = multiply(b, &d_bits, &cmax);
    let masked = |b: &mut FieldR1csBuilder, v: &[LinExpr]| {
        v.iter().map(|x| mul(b, &boundary, x)).collect::<Vec<_>>()
    };
    let left = masked(b, &left);
    let right = masked(b, &right);
    let left_max = masked(b, &left_max);
    let right_max = masked(b, &right_max);
    let base_numerator = checked_subtract(b, &right_max, &left);
    let quote_numerator = checked_subtract(b, &left_max, &right);
    let quote_partial = less_than(b, &left_max, &right_max);
    let base_partial = quote_partial.add_const(F128::ONE);
    let base_partial = mul(b, &boundary, &base_partial);
    let quote_partial = mul(b, &boundary, &quote_partial);
    let base_product = multiply(b, &n_bits, &marginal_totals[0]);
    let quote_product = multiply(b, &d_bits, &marginal_totals[1]);
    pin_zero(b, &base_product[127]);
    pin_zero(b, &quote_product[127]);
    let mut base_denominator = vec![LinExpr::zero()];
    base_denominator.extend(base_product[..127].iter().cloned());
    let mut quote_denominator = vec![LinExpr::zero()];
    quote_denominator.extend(quote_product[..127].iter().cloned());
    let numerator = (0..128)
        .map(|i| {
            mul(b, &base_partial, &base_numerator[i]).add(&mul(
                b,
                &quote_partial,
                &quote_numerator[i],
            ))
        })
        .collect::<Vec<_>>();
    let mut denominator = (0..128)
        .map(|i| {
            mul(b, &base_partial, &base_denominator[i]).add(&mul(
                b,
                &quote_partial,
                &quote_denominator[i],
            ))
        })
        .collect::<Vec<_>>();
    let zero = is_zero(b, &pack(&denominator));
    let fallback = mul(b, &boundary, &zero);
    let bad = mul(b, &fallback, &pack(&numerator));
    pin_zero(b, &bad);
    let none = interior.add(&fallback);
    denominator[0] = denominator[0].add(&none);
    let base_partial = mul(b, &base_partial, &zero.add_const(F128::ONE));
    let quote_partial = mul(b, &quote_partial, &zero.add_const(F128::ONE));
    pin_eq(b, &base_partial.add(&quote_partial).add(&none), live);
    let over = less_than(b, &denominator, &numerator);
    pin_zero(b, &over);
    FinancialMarketContextTrace {
        full_totals: full_totals.each_ref().map(|v| pack(v)),
        marginal_totals: marginal_totals.each_ref().map(|v| pack(v)),
        partial: [base_partial, quote_partial, none],
        fraction_numerator: pack(&numerator),
        fraction_denominator: pack(&denominator),
    }
}
