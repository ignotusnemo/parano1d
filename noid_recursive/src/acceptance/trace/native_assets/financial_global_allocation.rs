// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Globally routed exact partial totals, allocation prefixes and dust.

use super::super::{alloc_block, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::{
    checked_add, checked_subtract, extend, less_than, multiply, pack, shifted,
};
use super::financial_clearing_summaries::FinancialSortedClearingRowTrace;
use super::financial_ratio::bind_financial_ratio;
use super::validation::is_zero;
use noid_core::{hardware::flat_to_tower_u128, Block128};

pub struct FinancialAllocationStepInputTrace {
    pub live: LinExpr,
    pub launch: LinExpr,
    pub at_cap: LinExpr,
    pub price: [LinExpr; 2],
    pub partial: [LinExpr; 3],
    pub marginal_totals: [LinExpr; 2],
    pub fraction_numerator: LinExpr,
    pub fraction_denominator: LinExpr,
}
pub struct FinancialAllocationStepTrace {
    pub live: LinExpr,
    pub launch: LinExpr,
    pub at_cap: LinExpr,
    pub price: [LinExpr; 2],
    pub partial: [LinExpr; 3],
    pub marginal_total: LinExpr,
    pub partial_total: LinExpr,
    pub positive_fraction: LinExpr,
}
pub struct FinancialGlobalAllocationRowTrace {
    pub live: LinExpr,
    pub step_index: LinExpr,
    pub source_index: LinExpr,
    pub effective: LinExpr,
    pub dust: LinExpr,
}
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn boolean(b: &mut FieldR1csBuilder, x: &LinExpr) {
    let bad = mul(b, x, &x.add_const(F128::ONE));
    pin_zero(b, &bad);
}
fn eq_when(b: &mut FieldR1csBuilder, f: &LinExpr, x: &LinExpr, y: &LinExpr) {
    let bad = mul(b, f, &x.add(y));
    pin_zero(b, &bad);
}
fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}
fn wide_product(a: u128, b: u64) -> [u64; 3] {
    let low = u128::from(a as u64) * u128::from(b);
    let high = (a >> 64) * u128::from(b) + (low >> 64);
    [low as u64, high as u64, (high >> 64) as u64]
}
fn wide_floor(a: u128, b: u64, d: u128) -> u64 {
    if d == 0 {
        return 0;
    }
    let target = wide_product(a, b);
    let (mut lo, mut hi) = (0u64, b);
    while lo < hi {
        let mid = ((u128::from(lo) + u128::from(hi) + 1) / 2) as u64;
        let candidate = wide_product(d, mid);
        if candidate.iter().rev().cmp(target.iter().rev()).is_le() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// The exact per-step market/launch context certificate supplies family,
/// cap, marginal side and fraction. One full-width ratio fixes the total
/// allocated quantity before exact canonical source prefixes distribute it.
pub fn bind_financial_allocation_steps(
    b: &mut FieldR1csBuilder,
    input: &[FinancialAllocationStepInputTrace],
) -> Vec<FinancialAllocationStepTrace> {
    input
        .iter()
        .map(|s| {
            for f in [
                &s.live,
                &s.launch,
                &s.at_cap,
                &s.partial[0],
                &s.partial[1],
                &s.partial[2],
            ] {
                boolean(b, f);
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
            let total = mul(b, &s.partial[0], &s.marginal_totals[0]).add(&mul(
                b,
                &s.partial[1],
                &s.marginal_totals[1],
            ));
            let tb = bits(b, &total, 63);
            let value = wide_floor(
                tower(b, &s.fraction_numerator),
                tower(b, &total) as u64,
                tower(b, &s.fraction_denominator),
            );
            let partial_total = alloc_block(b, Block128(u128::from(value)));
            let pb = bits(b, &partial_total, 63);
            let _ = bind_financial_ratio(
                b,
                &s.live,
                &LinExpr::zero(),
                &s.fraction_numerator,
                &total,
                &s.fraction_denominator,
                &partial_total,
                128,
            );
            let over = less_than(b, &tb, &pb);
            pin_zero(b, &over);
            let positive = is_zero(b, &s.fraction_numerator).add_const(F128::ONE);
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

/// Complete sorted active rows and exact four-channel prefixes come from
/// the global summary relation. Every dust result is equality-bound to the
/// original lineage row, and terminal quantities feed exact native effects.
pub fn bind_financial_global_allocation(
    b: &mut FieldR1csBuilder,
    rows: &[FinancialSortedClearingRowTrace],
    steps: &[FinancialAllocationStepTrace],
) -> Vec<FinancialGlobalAllocationRowTrace> {
    let mut result = Vec::with_capacity(rows.len());
    let mut old_live = LinExpr::zero();
    let mut old_step = LinExpr::zero();
    let mut cumulative = vec![LinExpr::zero(); 64];
    for (i, r) in rows.iter().enumerate() {
        let mut found = LinExpr::zero();
        let (mut launch, mut cap, mut total, mut allocated, mut positive) = (
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
        );
        let mut partial: [LinExpr; 3] = std::array::from_fn(|_| LinExpr::zero());
        let mut price = [LinExpr::zero(), LinExpr::zero()];
        for (j, s) in steps.iter().enumerate() {
            let same = is_zero(
                b,
                &r.step_index.add_const(super::super::flat_const(j as u128)),
            );
            let selected = mul(b, &r.live, &same);
            let selected = mul(b, &selected, &s.live);
            found = found.add(&selected);
            for (output, input) in [
                (&mut launch, &s.launch),
                (&mut cap, &s.at_cap),
                (&mut total, &s.marginal_total),
                (&mut allocated, &s.partial_total),
                (&mut positive, &s.positive_fraction),
            ] {
                *output = output.add(&mul(b, &selected, input));
            }
            for k in 0..3 {
                partial[k] = partial[k].add(&mul(b, &selected, &s.partial[k]));
            }
            for k in 0..2 {
                price[k] = price[k].add(&mul(b, &selected, &s.price[k]));
            }
        }
        pin_eq(b, &found, &r.live);
        let base = r.side.add_const(F128::ONE);
        let chosen = mul(b, &partial[0], &base).add(&mul(b, &partial[1], &r.side));
        let selected = mul(b, &r.marginal, &chosen);
        let full_buy = bits(b, &r.prefixes[0], 64);
        let marginal_buy = bits(b, &r.prefixes[2], 64);
        let combined = checked_add(b, &full_buy, &marginal_buy);
        let buy =
            pack(&marginal_buy).add(&mul(b, &cap, &pack(&marginal_buy).add(&pack(&combined))));
        let prefix = mul(b, &partial[0], &buy).add(&mul(b, &partial[1], &r.prefixes[3]));
        bits(b, &prefix, 63);
        let tv = tower(b, &total);
        let pv = tower(b, &prefix);
        let av = tower(b, &allocated);
        let next = alloc_block(
            b,
            Block128(if tv == 0 {
                0
            } else {
                av.saturating_mul(pv) / tv
            }),
        );
        bits(b, &next, 63);
        let _ = bind_financial_ratio(
            b,
            &selected,
            &LinExpr::zero(),
            &allocated,
            &prefix,
            &total,
            &next,
            64,
        );
        let same = is_zero(b, &r.step_index.add(&old_step));
        let cont = mul(b, &same, &old_live);
        let cont = mul(b, &cont, &r.live);
        let before = cumulative
            .iter()
            .map(|v| mul(b, &cont, v))
            .collect::<Vec<_>>();
        let old = pack(&before);
        let value = old.add(&mul(b, &selected, &old.add(&next)));
        let current = bits(b, &value, 64);
        pin_zero(b, &current[63]);
        let amount = pack(&checked_subtract(b, &current, &before));
        cumulative = current;
        let complete = r.full.add(&r.marginal).add(&selected);
        let effective = amount.add(&mul(b, &complete, &r.quantity));
        let effective_bits = bits(b, &effective, 63);
        let capacity = bits(b, &r.quantity, 63);
        let over = less_than(b, &capacity, &effective_bits);
        pin_zero(b, &over);
        let n = bits(b, &price[0], 64);
        let d = bits(b, &price[1], 64);
        let mut numerator = Vec::with_capacity(64);
        let mut divisor = Vec::with_capacity(64);
        for j in 0..64 {
            let market_n = n[j].add(&mul(b, &r.side, &n[j].add(&d[j])));
            let market_d = d[j].add(&mul(b, &r.side, &n[j].add(&d[j])));
            let one = if j == 0 {
                LinExpr::constant(F128::ONE)
            } else {
                LinExpr::zero()
            };
            let launch_n = one.add(&mul(b, &r.side, &one.add(&n[j])));
            let launch_d = one.add(&mul(b, &r.side, &one.add(&d[j])));
            numerator.push(market_n.add(&mul(b, &launch, &market_n.add(&launch_n))));
            divisor.push(market_d.add(&mul(b, &launch, &market_d.add(&launch_d))));
        }
        let product = multiply(b, &extend(&effective_bits, 64), &numerator);
        let empty = less_than(b, &product, &extend(&divisor, 128));
        let fits = less_than(b, &product, &shifted(&divisor, 64, 128));
        let bad = mul(b, &r.live, &fits.add_const(F128::ONE));
        pin_zero(b, &bad);
        let positive_target = complete.add(&mul(b, &selected, &positive));
        let dust = mul(b, &positive_target, &empty);
        let next_same = if let Some(next) = rows.get(i + 1) {
            let same = is_zero(b, &r.step_index.add(&next.step_index));
            mul(b, &next.live, &same)
        } else {
            LinExpr::zero()
        };
        let end = mul(b, &r.live, &next_same.add_const(F128::ONE));
        eq_when(b, &end, &pack(&cumulative), &allocated);
        eq_when(b, &end, &prefix, &total);
        result.push(FinancialGlobalAllocationRowTrace {
            live: r.live.clone(),
            step_index: r.step_index.clone(),
            source_index: r.source_index.clone(),
            effective,
            dust,
        });
        old_live = r.live.clone();
        old_step = r.step_index.clone();
    }
    result
}
