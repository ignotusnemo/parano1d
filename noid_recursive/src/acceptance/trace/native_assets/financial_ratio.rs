// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact bounded floor and ceiling ratios with complete product widths.

use super::super::{mul, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::{checked_subtract, extend, less_than, multiply};
use super::validation::require_nonzero;
use noid_core::hardware::flat_to_tower_u128;

pub struct FinancialRatioTrace {
    pub numerator: Vec<LinExpr>,
    pub denominator: Vec<LinExpr>,
    pub quotient: Vec<LinExpr>,
    pub remainder: Vec<LinExpr>,
}
fn bits(b: &mut FieldR1csBuilder, value: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, value, n)
}

/// Static scalar constants have exact boolean masked bits without a second
/// decomposition. An out-of-domain static constant forces inactive mode.
fn masked_bits(
    b: &mut FieldR1csBuilder,
    active: &LinExpr,
    value: &LinExpr,
    width: usize,
) -> Vec<LinExpr> {
    if value.is_const() {
        let f = value.constant;
        let n = flat_to_tower_u128(u128::from(f.lo) | (u128::from(f.hi) << 64));
        if width < 128 && n >> width != 0 {
            pin_zero(b, active);
        }
        return (0..width)
            .map(|i| {
                if (n >> i) & 1 != 0 {
                    active.clone()
                } else {
                    LinExpr::zero()
                }
            })
            .collect();
    }
    let value = mul(b, active, value);
    bits(b, &value, width)
}

/// The active integer operands and quotient have the owning relation's fixed
/// width, at most128 bits. Both products retain their full double width.
/// A nonzero denominator and a remainder strictly below it uniquely establish
/// floor(left*right/denominator), or ceiling when rounding_up is one.
/// The caller binds every operand to its exact authenticated transition value.
pub fn bind_financial_ratio(
    b: &mut FieldR1csBuilder,
    active: &LinExpr,
    rounding_up: &LinExpr,
    left: &LinExpr,
    right: &LinExpr,
    denominator: &LinExpr,
    quotient: &LinExpr,
    width: usize,
) -> FinancialRatioTrace {
    assert!(width > 0 && width <= 128);
    for flag in [active, rounding_up] {
        let bad = mul(b, flag, &flag.add_const(F128::ONE));
        pin_zero(b, &bad);
    }
    let selected = mul(b, active, rounding_up);
    let left = masked_bits(b, active, left, width);
    let right = masked_bits(b, active, right, width);
    let denominator_value = mul(b, active, denominator);
    require_nonzero(b, &denominator_value, active);
    let denominator = masked_bits(b, active, denominator, width);
    let quotient = masked_bits(b, active, quotient, width);
    let numerator = multiply(b, &left, &right);
    let product = multiply(b, &quotient, &denominator);
    let top = numerator
        .iter()
        .zip(&product)
        .map(|(a, c)| a.add(&mul(b, &selected, &a.add(c))))
        .collect::<Vec<_>>();
    let bottom = product
        .iter()
        .zip(&numerator)
        .map(|(a, c)| a.add(&mul(b, &selected, &a.add(c))))
        .collect::<Vec<_>>();
    let remainder = checked_subtract(b, &top, &bottom);
    let proper = less_than(b, &remainder, &extend(&denominator, 2 * width));
    let bad = mul(b, active, &proper.add_const(F128::ONE));
    pin_zero(b, &bad);
    FinancialRatioTrace {
        numerator,
        denominator,
        quotient,
        remainder,
    }
}
