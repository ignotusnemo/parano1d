// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact fees, partial spending, limit floors and swap entitlements.

use super::super::{alloc_block, flat_const, mul, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::{checked_subtract, less_than, pack};
use super::financial_ratio::bind_financial_ratio;
use super::validation::{is_zero, require_nonzero};
use noid_core::{hardware::flat_to_tower_u128, Block128};
use noid_tx::native_assets::market::MARKET_FEE_BPS;

pub struct FinancialSwapExecutionInputTrace {
    pub live: LinExpr,
    pub quote_to_base: LinExpr,
    pub gross_input: LinExpr,
    pub minimum_output: LinExpr,
    pub effective_input: LinExpr,
    pub price: [LinExpr; 2],
}
pub struct FinancialSwapExecutionTrace {
    pub capacity: LinExpr,
    pub spent_input: LinExpr,
    pub refund_input: LinExpr,
    pub output: LinExpr,
    pub scaled_minimum: LinExpr,
}
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}
fn number(x: u128) -> LinExpr {
    LinExpr::constant(flat_const(x))
}
fn witness(b: &mut FieldR1csBuilder, x: u128) -> LinExpr {
    alloc_block(b, Block128(x))
}

/// Exact authenticated request fields and the common clearing price/allocation
/// are supplied by the complete-set relation. All products retain128 bits.
/// Gross, effective, minimum and resulting native quantities fit63 bits;
/// positive price numerator and denominator retain their full64-bit domain.
pub fn bind_financial_swap_execution(
    b: &mut FieldR1csBuilder,
    input: &FinancialSwapExecutionInputTrace,
) -> FinancialSwapExecutionTrace {
    for f in [&input.live, &input.quote_to_base] {
        let bad = mul(b, f, &f.add_const(F128::ONE));
        pin_zero(b, &bad);
    }
    let live = &input.live;
    let gross = mul(b, live, &input.gross_input);
    let minimum = mul(b, live, &input.minimum_output);
    let effective = mul(b, live, &input.effective_input);
    let gross_bits = bits(b, &gross, 63);
    bits(b, &minimum, 63);
    let effective_bits = bits(b, &effective, 63);
    require_nonzero(b, &minimum, live);
    let after_fee = u128::from(10_000 - MARKET_FEE_BPS);
    let g = tower(b, &gross);
    let e = tower(b, &effective);
    let capacity = witness(b, g.saturating_mul(after_fee) / 10_000);
    let capacity_bits = bits(b, &capacity, 63);
    require_nonzero(b, &capacity, live);
    let _ = bind_financial_ratio(
        b,
        live,
        &LinExpr::zero(),
        &gross,
        &number(after_fee),
        &number(10_000),
        &capacity,
        64,
    );
    let over = less_than(b, &capacity_bits, &effective_bits);
    pin_zero(b, &over);
    let partial = witness(b, e.saturating_mul(10_000).div_ceil(after_fee));
    bits(b, &partial, 63);
    let _ = bind_financial_ratio(
        b,
        live,
        &number(1),
        &effective,
        &number(10_000),
        &number(after_fee),
        &partial,
        64,
    );
    let full = is_zero(b, &effective.add(&capacity));
    let full = mul(b, live, &full);
    let spent = mul(b, &full, &gross).add(&mul(b, &live.add(&full), &partial));
    let spent_bits = bits(b, &spent, 63);
    let refund = pack(&checked_subtract(b, &gross_bits, &spent_bits));
    let numerator = mul(b, live, &input.price[0]);
    let denominator = mul(b, live, &input.price[1]);
    bits(b, &numerator, 64);
    bits(b, &denominator, 64);
    require_nonzero(b, &numerator, live);
    require_nonzero(b, &denominator, live);
    let n = numerator.add(&mul(b, &input.quote_to_base, &numerator.add(&denominator)));
    let d = denominator.add(&mul(b, &input.quote_to_base, &numerator.add(&denominator)));
    let nv = tower(b, &n);
    let dv = tower(b, &d);
    let output = witness(
        b,
        if dv == 0 {
            0
        } else {
            e.saturating_mul(nv) / dv
        },
    );
    let output_bits = bits(b, &output, 63);
    let _ = bind_financial_ratio(b, live, &LinExpr::zero(), &effective, &n, &d, &output, 64);
    let c = tower(b, &capacity);
    let m = tower(b, &minimum);
    let scaled = witness(b, if c == 0 { 0 } else { m.saturating_mul(e) / c });
    let scaled_bits = bits(b, &scaled, 63);
    let _ = bind_financial_ratio(
        b,
        live,
        &LinExpr::zero(),
        &minimum,
        &effective,
        &capacity,
        &scaled,
        64,
    );
    let low = less_than(b, &output_bits, &scaled_bits);
    pin_zero(b, &low);
    let zero_spent = is_zero(b, &spent);
    let zero_output = is_zero(b, &output);
    let bad = mul(b, &zero_spent.add_const(F128::ONE), &zero_output);
    let bad = mul(b, live, &bad);
    pin_zero(b, &bad);
    FinancialSwapExecutionTrace {
        capacity,
        spent_input: spent,
        refund_input: refund,
        output,
        scaled_minimum: scaled,
    }
}
