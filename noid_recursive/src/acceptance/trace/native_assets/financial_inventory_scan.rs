// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete grouped inventories, distinct slots and one request payload.

use super::super::permutation_network::route_permutation_network;
use super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::{checked_add, less_than, pack};
use super::validation::is_zero;
use noid_core::hardware::flat_to_tower_u128;

pub struct FinancialInventoryRowTrace {
    pub live: LinExpr,
    pub group: LinExpr,
    pub slot: LinExpr,
    pub amounts: [LinExpr; 6],
    pub singleton: LinExpr,
    pub payload: [LinExpr; 12],
}
pub struct FinancialInventorySummaryTrace {
    pub live: LinExpr,
    pub group: LinExpr,
    pub amounts: [LinExpr; 6],
    pub singleton: LinExpr,
    pub payload: [LinExpr; 12],
}
pub struct FinancialInventoryScanTrace {
    pub groups: Vec<FinancialInventorySummaryTrace>,
    pub sum_width: usize,
}
fn bits(b: &mut FieldR1csBuilder, v: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, v, n)
}
fn tower(b: &FieldR1csBuilder, v: &LinExpr) -> u128 {
    let f = v.eval(b.values());
    flat_to_tower_u128(u128::from(f.lo) | (u128::from(f.hi) << 64))
}
fn route(b: &mut FieldR1csBuilder, rows: Vec<Vec<LinExpr>>, keys: &[usize]) -> Vec<Vec<LinExpr>> {
    let mut order = (0..rows.len()).collect::<Vec<_>>();
    order.sort_by_key(|&i| {
        (
            tower(b, &rows[i][0]) == 0,
            keys.iter()
                .map(|&k| tower(b, &rows[i][k]))
                .collect::<Vec<_>>(),
            i,
        )
    });
    let mut permutation = vec![0; rows.len()];
    for (target, source) in order.into_iter().enumerate() {
        permutation[source] = target;
    }
    route_permutation_network(b, rows, &permutation)
}
fn boolean(b: &mut FieldR1csBuilder, v: &LinExpr) {
    let bad = mul(b, v, &v.add_const(F128::ONE));
    pin_zero(b, &bad);
}

/// The caller binds every selected physical action to one complete source row.
/// All six nonnegative u64 channels are accumulated exactly per group. Routing
/// covers every row and proves strict (group, slot) order, so no slot repeats
/// within a group. At most one row supplies its twelve-field request payload.
/// Summary routing covers the complete group-end set within the given capacity.
pub fn bind_financial_inventory_scan(
    b: &mut FieldR1csBuilder,
    sources: &[FinancialInventoryRowTrace],
    group_capacity: usize,
) -> FinancialInventoryScanTrace {
    assert!(!sources.is_empty());
    let capacity = sources.len().next_power_of_two();
    assert!(group_capacity > 0 && group_capacity <= capacity);
    let sum_width = 64 + capacity.trailing_zeros() as usize;
    assert!(sum_width <= 128);
    let mut rows = Vec::with_capacity(capacity);
    for s in sources {
        boolean(b, &s.live);
        boolean(b, &s.singleton);
        let outside = mul(b, &s.singleton, &s.live.add_const(F128::ONE));
        pin_zero(b, &outside);
        for v in [&s.group, &s.slot]
            .into_iter()
            .chain(s.amounts.iter())
            .chain(std::iter::once(&s.singleton))
            .chain(s.payload.iter())
        {
            let dead = mul(b, &s.live.add_const(F128::ONE), v);
            pin_zero(b, &dead);
        }
        for v in &s.payload {
            let unused = mul(b, &s.singleton.add_const(F128::ONE), v);
            pin_zero(b, &unused);
        }
        let mut row = vec![s.live.clone(), s.group.clone(), s.slot.clone()];
        row.extend(s.amounts.iter().cloned());
        row.push(s.singleton.clone());
        row.extend(s.payload.iter().cloned());
        rows.push(row);
    }
    rows.resize_with(capacity, || vec![LinExpr::zero(); 22]);
    let rows = route(b, rows, &[1, 2]);
    let mut previous_key: Option<(LinExpr, Vec<LinExpr>)> = None;
    let mut previous_live = LinExpr::zero();
    let mut previous_group = LinExpr::zero();
    let mut sums: [Vec<LinExpr>; 6] = std::array::from_fn(|_| vec![LinExpr::zero(); sum_width]);
    let mut seen = LinExpr::zero();
    let mut payload: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
    let mut ends = Vec::with_capacity(capacity);
    for (i, row) in rows.iter().enumerate() {
        let mut key = bits(b, &row[2], 32);
        key.extend(bits(b, &row[1], 32));
        if let Some((live, old)) = previous_key {
            let hole = mul(b, &row[0], &live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let strict = less_than(b, &old, &key);
            let bad = mul(b, &row[0], &strict.add_const(F128::ONE));
            pin_zero(b, &bad);
        }
        previous_key = Some((row[0].clone(), key));
        let same = is_zero(b, &row[1].add(&previous_group));
        let cont = mul(b, &same, &previous_live);
        let cont = mul(b, &cont, &row[0]);
        for k in 0..6 {
            let previous = sums[k].iter().map(|v| mul(b, &cont, v)).collect::<Vec<_>>();
            let mut amount = bits(b, &row[3 + k], 64);
            amount.resize(sum_width, LinExpr::zero());
            sums[k] = checked_add(b, &previous, &amount);
        }
        let previous = mul(b, &cont, &seen);
        let overlap = mul(b, &previous, &row[9]);
        pin_zero(b, &overlap);
        seen = previous.add(&row[9]);
        for j in 0..12 {
            payload[j] = mul(b, &cont, &payload[j]).add(&row[10 + j]);
        }
        let continuation = if let Some(next) = rows.get(i + 1) {
            let same = is_zero(b, &row[1].add(&next[1]));
            mul(b, &same, &next[0])
        } else {
            LinExpr::zero()
        };
        let end = mul(b, &row[0], &continuation.add_const(F128::ONE));
        let mut summary = vec![end.clone(), mul(b, &end, &row[1])];
        summary.extend(sums.iter().map(|v| mul(b, &end, &pack(v))));
        summary.push(mul(b, &end, &seen));
        summary.extend(payload.iter().map(|v| mul(b, &end, v)));
        ends.push(summary);
        previous_live = row[0].clone();
        previous_group = row[1].clone();
    }
    let ends = route(b, ends, &[1]);
    for row in &ends[group_capacity..] {
        pin_zero(b, &row[0]);
    }
    let mut previous: Option<(LinExpr, Vec<LinExpr>)> = None;
    let mut groups = Vec::with_capacity(group_capacity);
    for row in ends.into_iter().take(group_capacity) {
        let key = bits(b, &row[1], 32);
        if let Some((live, old)) = previous {
            let hole = mul(b, &row[0], &live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let strict = less_than(b, &old, &key);
            let bad = mul(b, &row[0], &strict.add_const(F128::ONE));
            pin_zero(b, &bad);
        }
        previous = Some((row[0].clone(), key));
        groups.push(FinancialInventorySummaryTrace {
            live: row[0].clone(),
            group: row[1].clone(),
            amounts: std::array::from_fn(|j| row[2 + j].clone()),
            singleton: row[8].clone(),
            payload: std::array::from_fn(|j| row[9 + j].clone()),
        });
    }
    FinancialInventoryScanTrace { groups, sum_width }
}
