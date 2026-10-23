// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-reference liquidity execution and exact conditional entitlements.

use super::super::{alloc_block, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::{less_than, multiply};
use super::financial_ratio::bind_financial_ratio;
use super::validation::is_zero;
use noid_core::{hardware::flat_to_tower_u128, Block128};

pub struct FinancialLiquidityInputTrace {
    pub live: LinExpr,
    pub kinds: [LinExpr; 3],
    pub max_base: LinExpr,
    pub max_quote: LinExpr,
    pub minimum_shares: LinExpr,
    pub shares: LinExpr,
    pub minimum_base: LinExpr,
    pub minimum_quote: LinExpr,
}
pub struct FinancialLiquidityExecutionTrace {
    pub used_base: LinExpr,
    pub used_quote: LinExpr,
    pub paid_base: LinExpr,
    pub paid_quote: LinExpr,
    pub minted_shares: LinExpr,
    pub burned_shares: LinExpr,
    pub returned_shares: LinExpr,
    pub locked_shares: LinExpr,
}
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}
fn boolean(b: &mut FieldR1csBuilder, x: &LinExpr) {
    let bad = mul(b, x, &x.add_const(F128::ONE));
    pin_zero(b, &bad);
}
fn witness(b: &mut FieldR1csBuilder, x: u128) -> LinExpr {
    alloc_block(b, Block128(x))
}

/// Reference reserves and shares are positive validated63-bit pool quantities.
/// The complete round supplies deposit-capacity and consumed-share bounds,
/// exact typed request fields and the common post-swap reference for every row.
/// These bounds ensure the limiting deposit quotient fits the native domain.
pub fn bind_financial_liquidity_step(
    b: &mut FieldR1csBuilder,
    reference: &[LinExpr; 3],
    input: &FinancialLiquidityInputTrace,
) -> FinancialLiquidityExecutionTrace {
    boolean(b, &input.live);
    for f in &input.kinds {
        boolean(b, f);
    }
    for i in 0..3 {
        for j in i + 1..3 {
            let bad = mul(b, &input.kinds[i], &input.kinds[j]);
            pin_zero(b, &bad);
        }
    }
    let [deposit, withdraw, burn] = &input.kinds;
    pin_eq(b, &input.live, &deposit.add(withdraw).add(burn));
    let [base, quote, total] = reference;
    let base_bits = bits(b, base, 63);
    let quote_bits = bits(b, quote, 63);
    let _total_bits = bits(b, total, 63);
    for x in [base, quote, total] {
        let zero = is_zero(b, x);
        let bad = mul(b, &input.live, &zero);
        pin_zero(b, &bad);
    }
    for (flag, value) in [
        (deposit, &input.max_base),
        (deposit, &input.max_quote),
        (deposit, &input.minimum_shares),
        (&withdraw.add(burn), &input.shares),
    ] {
        let empty = is_zero(b, value);
        let bad = mul(b, flag, &empty);
        pin_zero(b, &bad);
    }
    let max_base = mul(b, deposit, &input.max_base);
    let max_quote = mul(b, deposit, &input.max_quote);
    let maximum_base = bits(b, &max_base, 63);
    let maximum_quote = bits(b, &max_quote, 63);
    let cross_base = multiply(b, &maximum_base, &quote_bits);
    let cross_quote = multiply(b, &maximum_quote, &base_bits);
    let quote_limited = less_than(b, &cross_quote, &cross_base);
    let base_limited = quote_limited.add_const(F128::ONE);
    let numerator = mul(b, &base_limited, &max_base).add(&mul(b, &quote_limited, &max_quote));
    let denominator = mul(b, &base_limited, base).add(&mul(b, &quote_limited, quote));
    let nv = tower(b, &numerator);
    let dv = tower(b, &denominator);
    let lv = tower(b, total);
    let candidate = witness(
        b,
        if dv == 0 {
            0
        } else {
            nv.saturating_mul(lv) / dv
        },
    );
    let candidate_bits = bits(b, &candidate, 63);
    let _ = bind_financial_ratio(
        b,
        deposit,
        &LinExpr::zero(),
        &numerator,
        total,
        &denominator,
        &candidate,
        64,
    );
    let minimum = mul(b, deposit, &input.minimum_shares);
    let minimum_bits = bits(b, &minimum, 63);
    let too_small = less_than(b, &candidate_bits, &minimum_bits);
    let execute_deposit = mul(b, deposit, &too_small.add_const(F128::ONE));
    let minted = mul(b, &execute_deposit, &candidate);
    let shares = mul(b, &withdraw.add(burn), &input.shares);
    bits(b, &shares, 63);
    let withdrawal = mul(b, withdraw, &shares);
    let quantity = minted.add(&withdrawal);
    let active = deposit.add(withdraw);
    let q = tower(b, &quantity);
    let xv = tower(b, base);
    let yv = tower(b, quote);
    let up = tower(b, deposit) == 1;
    let value = |r: u128| {
        if lv == 0 {
            0
        } else if up {
            q.saturating_mul(r).div_ceil(lv)
        } else {
            q.saturating_mul(r) / lv
        }
    };
    let base_value = value(xv);
    let quote_value = value(yv);
    let proposed_base = witness(b, base_value);
    let proposed_quote = witness(b, quote_value);
    let proposed_base_bits = bits(b, &proposed_base, 63);
    let proposed_quote_bits = bits(b, &proposed_quote, 63);
    let _ = bind_financial_ratio(
        b,
        &active,
        deposit,
        &quantity,
        base,
        total,
        &proposed_base,
        64,
    );
    let _ = bind_financial_ratio(
        b,
        &active,
        deposit,
        &quantity,
        quote,
        total,
        &proposed_quote,
        64,
    );
    let minimum_base = mul(b, withdraw, &input.minimum_base);
    let minimum_quote = mul(b, withdraw, &input.minimum_quote);
    let minimum_base_bits = bits(b, &minimum_base, 63);
    let minimum_quote_bits = bits(b, &minimum_quote, 63);
    let base_low = less_than(b, &proposed_base_bits, &minimum_base_bits);
    let quote_low = less_than(b, &proposed_quote_bits, &minimum_quote_bits);
    let enough = mul(
        b,
        &base_low.add_const(F128::ONE),
        &quote_low.add_const(F128::ONE),
    );
    let empty_base = is_zero(b, &proposed_base);
    let empty_quote = is_zero(b, &proposed_quote);
    let empty = mul(b, &empty_base, &empty_quote);
    let execute_withdraw = mul(b, &enough, &empty.add_const(F128::ONE));
    let execute_withdraw = mul(b, withdraw, &execute_withdraw);
    FinancialLiquidityExecutionTrace {
        used_base: mul(b, deposit, &proposed_base),
        used_quote: mul(b, deposit, &proposed_quote),
        paid_base: mul(b, &execute_withdraw, &proposed_base),
        paid_quote: mul(b, &execute_withdraw, &proposed_quote),
        minted_shares: minted,
        burned_shares: mul(b, &execute_withdraw, &shares),
        returned_shares: mul(b, &withdraw.add(&execute_withdraw), &shares),
        locked_shares: mul(b, burn, &shares),
    }
}
