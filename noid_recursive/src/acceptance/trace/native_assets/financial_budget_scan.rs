// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete grouped admission budgets with checked unsigned accumulation.

use super::super::{flat_const, mul, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::actions::route_sorted;
use super::arithmetic::{checked_add, less_than};
use super::validation::{is_zero, require_nonzero};
use noid_core::hardware::flat_to_tower_u128;

pub struct FinancialBudgetRowTrace {
    pub live: LinExpr,
    pub control_index: LinExpr,
    pub request: LinExpr,
    pub request_index: LinExpr,
    pub amounts: [LinExpr; 3],
    pub limits: [LinExpr; 2],
}
pub struct FinancialBudgetStepTrace {
    pub live: LinExpr,
    pub control_index: LinExpr,
    pub sums: [Vec<LinExpr>; 3],
    pub limits: [Vec<LinExpr>; 2],
}
fn tower(b: &FieldR1csBuilder, v: &LinExpr) -> u128 {
    let f = v.eval(b.values());
    flat_to_tower_u128(u128::from(f.lo) | (u128::from(f.hi) << 64))
}
fn bits(b: &mut FieldR1csBuilder, v: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, v, n)
}
/// Anchors carry the three starting sums and two exact group limits. Each
/// request carries its three nonnegative contributions. The enclosing native
/// relation binds every anchor/request to its complete actual source set.
/// The first sum is bounded by QMAX; the other sums also obey group limits.
pub fn bind_financial_budget_scan(
    b: &mut FieldR1csBuilder,
    sources: &[FinancialBudgetRowTrace],
    control_capacity: usize,
    request_capacity: usize,
) -> Vec<FinancialBudgetStepTrace> {
    assert!(control_capacity > 0 && request_capacity > 0);
    let group_width = (control_capacity + 1)
        .next_power_of_two()
        .trailing_zeros()
        .max(1) as usize;
    let request_width = (request_capacity + 1)
        .next_power_of_two()
        .trailing_zeros()
        .max(1) as usize;
    assert!(!sources.is_empty());
    let mut request_count = vec![LinExpr::zero(); request_width];
    for source in sources {
        for flag in [&source.live, &source.request] {
            let bad = mul(b, flag, &flag.add_const(F128::ONE));
            pin_zero(b, &bad);
        }
        let outside = mul(b, &source.request, &source.live.add_const(F128::ONE));
        pin_zero(b, &outside);
        for field in [
            &source.control_index,
            &source.request,
            &source.request_index,
        ]
        .into_iter()
        .chain(source.amounts.iter())
        .chain(source.limits.iter())
        {
            let dead = mul(b, &source.live.add_const(F128::ONE), field);
            pin_zero(b, &dead);
        }
        let mut delta = vec![LinExpr::zero(); request_width];
        delta[0] = source.request.clone();
        request_count = checked_add(b, &request_count, &delta);
    }
    let maximum = (0..request_width)
        .map(|i| LinExpr::constant(flat_const(((request_capacity as u128) >> i) & 1)))
        .collect::<Vec<_>>();
    let excess = less_than(b, &maximum, &request_count);
    pin_zero(b, &excess);
    let capacity = sources.len().max(1).next_power_of_two();
    let mut rows = sources
        .iter()
        .map(|s| {
            let mut row = vec![
                s.live.clone(),
                s.control_index.clone(),
                s.request.clone(),
                s.request_index.clone(),
            ];
            row.extend(s.amounts.iter().cloned());
            row.extend(s.limits.iter().cloned());
            row
        })
        .collect::<Vec<_>>();
    rows.resize_with(capacity, || vec![LinExpr::zero(); 9]);
    let rows = route_sorted(b, rows, 9, |b, row| {
        vec![tower(b, &row[1]), tower(b, &row[2]), tower(b, &row[3])]
    });
    for row in &rows[sources.len()..] {
        pin_zero(b, &row[0]);
    }
    let mut previous_live = LinExpr::constant(F128::ONE);
    let mut previous_group = LinExpr::zero();
    let mut previous_key: Option<Vec<LinExpr>> = None;
    let mut sums: [Vec<LinExpr>; 3] = std::array::from_fn(|_| vec![LinExpr::zero(); 63]);
    let mut limits: [Vec<LinExpr>; 2] = std::array::from_fn(|_| vec![LinExpr::zero(); 63]);
    let mut steps = Vec::new();
    for row in rows.into_iter().take(sources.len()) {
        let live = &row[0];
        let request = &row[2];
        let hole = mul(b, live, &previous_live.add_const(F128::ONE));
        pin_zero(b, &hole);
        previous_live = live.clone();
        let group = bits(b, &row[1], group_width);
        let index = bits(b, &row[3], request_width);
        require_nonzero(b, &row[1], live);
        require_nonzero(b, &row[3], request);
        let anchor = live.add(request);
        let anchor_index = mul(b, &anchor, &row[3]);
        pin_zero(b, &anchor_index);
        let maximum = (0..group_width)
            .map(|i| LinExpr::constant(flat_const(((control_capacity as u128) >> i) & 1)))
            .collect::<Vec<_>>();
        let too_large = less_than(b, &maximum, &group);
        pin_zero(b, &too_large);
        let maximum = (0..request_width)
            .map(|i| LinExpr::constant(flat_const(((request_capacity as u128) >> i) & 1)))
            .collect::<Vec<_>>();
        let too_large = less_than(b, &maximum, &index);
        pin_zero(b, &too_large);
        let mut key = index;
        key.push(request.clone());
        key.extend(group);
        if let Some(old) = previous_key {
            let strict = less_than(b, &old, &key);
            let bad = mul(b, live, &strict.add_const(F128::ONE));
            pin_zero(b, &bad);
        }
        previous_key = Some(key);
        let same = is_zero(b, &row[1].add(&previous_group));
        let orphan = mul(b, request, &same.add_const(F128::ONE));
        pin_zero(b, &orphan);
        let duplicate_anchor = mul(b, &anchor, &same);
        pin_zero(b, &duplicate_anchor);
        previous_group = row[1].clone();
        for axis in 0..3 {
            let delta = bits(b, &row[4 + axis], 63);
            let carried = sums[axis]
                .iter()
                .map(|v| mul(b, request, v))
                .collect::<Vec<_>>();
            sums[axis] = checked_add(b, &carried, &delta);
        }
        for axis in 0..2 {
            let local = bits(b, &row[7 + axis], 63);
            let request_limit = mul(b, request, &row[7 + axis]);
            pin_zero(b, &request_limit);
            limits[axis] = local
                .iter()
                .zip(&limits[axis])
                .map(|(local, previous)| local.add(&mul(b, request, previous)))
                .collect();
            let exceeded = less_than(b, &limits[axis], &sums[axis + 1]);
            pin_zero(b, &exceeded);
        }
        steps.push(FinancialBudgetStepTrace {
            live: live.clone(),
            control_index: row[1].clone(),
            sums: sums.clone(),
            limits: limits.clone(),
        });
    }
    steps
}
