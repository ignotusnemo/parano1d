// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact marginal totals with a cancelled common integer factor.

use super::super::{alloc_block, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::{checked_add, checked_subtract, extend, less_than, multiply, pack};
use super::financial_global_allocation::{
    FinancialAllocationStepInputTrace, FinancialAllocationStepTrace,
};
use super::validation::{is_zero, require_nonzero};
use noid_core::{hardware::flat_to_tower_u128, Block128};
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}
fn boolean(b: &mut FieldR1csBuilder, x: &LinExpr) {
    let invalid = mul(b, x, &x.add_const(F128::ONE));
    pin_zero(b, &invalid);
}
/// For an active marginal side, the native fraction denominator is M*U:
/// U=2*price_axis for AMM, 5*price_denominator for launch, and 1 at the cap.
/// M is positive and cancels from floor(N*M/(M*U)). The exact identity is
/// constrained here before floor(N/U), retaining both products' full width.
pub fn bind_financial_allocation_budgets(
    b: &mut FieldR1csBuilder,
    input: &[FinancialAllocationStepInputTrace],
) -> Vec<FinancialAllocationStepTrace> {
    input
        .iter()
        .map(|s| {
            for flag in [
                &s.live,
                &s.launch,
                &s.at_cap,
                &s.partial[0],
                &s.partial[1],
                &s.partial[2],
            ] {
                boolean(b, flag);
            }
            pin_eq(
                b,
                &s.partial.iter().fold(LinExpr::zero(), |a, x| a.add(x)),
                &s.live,
            );
            for i in 0..3 {
                for j in i + 1..3 {
                    let both = mul(b, &s.partial[i], &s.partial[j]);
                    pin_zero(b, &both);
                }
            }
            let outside = mul(b, &s.launch, &s.live.add_const(F128::ONE));
            pin_zero(b, &outside);
            let outside = mul(b, &s.at_cap, &s.launch.add_const(F128::ONE));
            pin_zero(b, &outside);
            let outside = mul(b, &s.at_cap, &s.partial[0].add_const(F128::ONE));
            pin_zero(b, &outside);
            let partial = s.partial[0].add(&s.partial[1]);
            let total = mul(b, &s.partial[0], &s.marginal_totals[0]).add(&mul(
                b,
                &s.partial[1],
                &s.marginal_totals[1],
            ));
            let total_bits = bits(b, &total, 63);
            require_nonzero(b, &total, &partial);
            let axis = mul(b, &s.partial[0], &s.price[0]).add(&mul(b, &s.partial[1], &s.price[1]));
            let axis = bits(b, &axis, 64);
            let mut twice = vec![LinExpr::zero()];
            twice.extend(axis);
            twice.resize(67, LinExpr::zero());
            let launch_regular = mul(b, &s.launch, &s.at_cap.add_const(F128::ONE));
            let launch_regular = mul(b, &launch_regular, &partial);
            let d = mul(b, &launch_regular, &s.price[1]);
            let d = bits(b, &d, 64);
            let mut shifted = vec![LinExpr::zero(); 2];
            shifted.extend(d.iter().cloned());
            shifted.resize(67, LinExpr::zero());
            let five = checked_add(b, &extend(&d, 67), &shifted);
            let market = s.live.add(&s.launch);
            let unit = mul(b, &market, &pack(&twice))
                .add(&pack(&five))
                .add(&s.at_cap)
                .add(&s.partial[2]);
            let unit_bits = bits(b, &unit, 67);
            require_nonzero(b, &unit, &s.live);
            let numerator = mul(b, &s.live, &s.fraction_numerator);
            let numerator_bits = bits(b, &numerator, 128);
            let denominator = mul(b, &s.live, &s.fraction_denominator);
            bits(b, &denominator, 128);
            let expected = multiply(b, &extend(&total_bits, 67), &unit_bits);
            for high in &expected[128..] {
                pin_zero(b, high);
            }
            pin_eq(b, &denominator, &pack(&expected[..128]).add(&s.partial[2]));
            let nv = tower(b, &numerator);
            let uv = tower(b, &unit);
            let partial_total = alloc_block(b, Block128(if uv == 0 { 0 } else { nv / uv }));
            let partial_bits = bits(b, &partial_total, 63);
            let product = multiply(b, &extend(&partial_bits, 67), &unit_bits);
            let remainder = checked_subtract(b, &extend(&numerator_bits, 134), &product);
            let proper = less_than(b, &remainder, &extend(&unit_bits, 134));
            let bad = mul(b, &s.live, &proper.add_const(F128::ONE));
            pin_zero(b, &bad);
            let over = less_than(b, &total_bits, &partial_bits);
            pin_zero(b, &over);
            let positive = is_zero(b, &numerator).add_const(F128::ONE);
            let positive = mul(b, &s.live, &positive);
            FinancialAllocationStepTrace {
                live: s.live.clone(),
                launch: s.launch.clone(),
                at_cap: s.at_cap.clone(),
                price: s.price.clone(),
                partial: s.partial.clone(),
                marginal_total: total,
                partial_total,
                positive_fraction: positive,
            }
        })
        .collect()
}
