// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact global active-row totals, canonical boundary and allocation prefixes.

use super::super::permutation_network::route_permutation_network;
use super::super::{
    alloc_block, flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::{checked_add, extend, less_than, pack};
use super::financial_active_clearing_route::FinancialActiveClearingRowTrace;
use super::financial_clearing_classification::FinancialClearingClassificationTrace;
use super::validation::is_zero;
use noid_core::{hardware::flat_to_tower_u128, Block128};

pub struct FinancialClearingSummaryTrace {
    pub nonempty: LinExpr,
    pub count: LinExpr,
    pub full: [LinExpr; 2],
    pub marginal: [LinExpr; 2],
    pub boundary: LinExpr,
    pub boundary_price: [LinExpr; 2],
}
pub struct FinancialSortedClearingRowTrace {
    pub live: LinExpr,
    pub step_index: LinExpr,
    pub source_index: LinExpr,
    pub side: LinExpr,
    pub quantity: LinExpr,
    pub full: LinExpr,
    pub marginal: LinExpr,
    pub raw_full: LinExpr,
    pub raw_marginal: LinExpr,
    pub limit_price: [LinExpr; 2],
    pub prefixes: [LinExpr; 4],
}
pub struct FinancialClearingSummariesTrace {
    pub steps: Vec<FinancialClearingSummaryTrace>,
    pub rows: Vec<FinancialSortedClearingRowTrace>,
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
fn eq_when(b: &mut FieldR1csBuilder, f: &LinExpr, x: &LinExpr, y: &LinExpr) {
    let bad = mul(b, f, &x.add(y));
    pin_zero(b, &bad);
}
fn routed_sort(
    b: &mut FieldR1csBuilder,
    mut rows: Vec<Vec<LinExpr>>,
    last: usize,
) -> Vec<Vec<LinExpr>> {
    let useful = rows.len();
    assert!(useful > 0);
    let width = rows[0].len();
    rows.resize_with(useful.next_power_of_two(), || vec![LinExpr::zero(); width]);
    let mut order = (0..rows.len()).collect::<Vec<_>>();
    order.sort_by_key(|&i| {
        (
            tower(b, &rows[i][0]) == 0,
            tower(b, &rows[i][1]),
            if last > 1 { tower(b, &rows[i][2]) } else { 0 },
            i,
        )
    });
    let mut permutation = vec![0; rows.len()];
    for (target, source) in order.into_iter().enumerate() {
        permutation[source] = target;
    }
    let mut result = route_permutation_network(b, rows, &permutation);
    for row in &result[useful..] {
        pin_zero(b, &row[0]);
    }
    result.truncate(useful);
    result
}

/// Exact active lineage and classification bind every input field. Source
/// indices retain funded-key order within each native group. The complete
/// permutation proves each step's totals and first equal-price boundary;
/// four exact prefixes support both ordinary marginal and launch-cap fills.
pub fn bind_financial_clearing_summaries(
    b: &mut FieldR1csBuilder,
    rows: &[FinancialActiveClearingRowTrace],
    classes: &[FinancialClearingClassificationTrace],
    step_count: usize,
) -> FinancialClearingSummariesTrace {
    assert_eq!(rows.len(), classes.len());
    assert!(!rows.is_empty() && step_count > 0 && step_count <= rows.len());
    let candidates = rows
        .iter()
        .zip(classes)
        .map(|(r, c)| {
            let mut v = vec![r.live.clone()];
            for x in [
                &r.step_index,
                &r.source_index,
                &r.side,
                &r.quantity,
                &c.raw_full,
                &c.raw_marginal,
                &c.limit_price[0],
                &c.limit_price[1],
                &c.full,
                &c.marginal,
            ] {
                v.push(mul(b, &r.live, x));
            }
            v
        })
        .collect::<Vec<_>>();
    let sorted = routed_sort(b, candidates, 2);
    let mut previous_key: Option<(LinExpr, Vec<LinExpr>)> = None;
    let mut old_live = LinExpr::zero();
    let mut old_step = LinExpr::zero();
    let mut totals: [Vec<LinExpr>; 4] = std::array::from_fn(|_| vec![LinExpr::zero(); 64]);
    let mut count = vec![LinExpr::zero(); 8];
    let mut seen = LinExpr::zero();
    let mut boundary_price = [LinExpr::zero(), LinExpr::zero()];
    let mut ends = Vec::with_capacity(rows.len());
    let mut result = Vec::with_capacity(rows.len());
    for (i, row) in sorted.iter().enumerate() {
        let live = &row[0];
        for flag in [&row[0], &row[3], &row[5], &row[6], &row[9], &row[10]] {
            boolean(b, flag);
        }
        let step = &row[1];
        let source = &row[2];
        let mut key = bits(b, source, 8);
        key.extend(bits(b, step, 8));
        if let Some((previous_live, previous)) = previous_key {
            let hole = mul(b, live, &previous_live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let strict = less_than(b, &previous, &key);
            eq_when(b, live, &strict, &LinExpr::constant(F128::ONE));
        }
        previous_key = Some((live.clone(), key));
        let same = is_zero(b, &step.add(&old_step));
        let cont = mul(b, &same, &old_live);
        let cont = mul(b, &cont, live);
        let quantity = bits(b, &row[4], 63);
        let sides = [row[3].add_const(F128::ONE), row[3].clone()];
        for j in 0..4 {
            let selected = mul(b, &sides[j % 2], &row[if j < 2 { 5 } else { 6 }]);
            let contribution = quantity
                .iter()
                .map(|v| mul(b, &selected, v))
                .collect::<Vec<_>>();
            let previous = totals[j]
                .iter()
                .map(|v| mul(b, &cont, v))
                .collect::<Vec<_>>();
            totals[j] = checked_add(b, &previous, &extend(&contribution, 64));
            pin_zero(b, &totals[j][63]);
        }
        let old_count = count.iter().map(|v| mul(b, &cont, v)).collect::<Vec<_>>();
        let mut delta = vec![LinExpr::zero(); 8];
        delta[0] = live.clone();
        count = checked_add(b, &old_count, &delta);
        let maximum = (0..8)
            .map(|i| LinExpr::constant(flat_const((16u128 >> i) & 1)))
            .collect::<Vec<_>>();
        let over = less_than(b, &maximum, &count);
        pin_zero(b, &over);
        let continued_seen = mul(b, &cont, &seen);
        let first = mul(b, &row[6], &continued_seen.add_const(F128::ONE));
        seen = continued_seen.add(&first);
        for j in 0..2 {
            boundary_price[j] = mul(b, &cont, &boundary_price[j]).add(&mul(b, &first, &row[7 + j]));
        }
        let next_same = if let Some(next) = sorted.get(i + 1) {
            let same = is_zero(b, &step.add(&next[1]));
            mul(b, &next[0], &same)
        } else {
            LinExpr::zero()
        };
        let end = mul(b, live, &next_same.add_const(F128::ONE));
        let mut token = vec![end.clone(), mul(b, &end, step), mul(b, &end, &pack(&count))];
        for v in &totals {
            token.push(mul(b, &end, &pack(v)));
        }
        token.push(mul(b, &end, &seen));
        for v in &boundary_price {
            token.push(mul(b, &end, v));
        }
        assert_eq!(token.len(), 10);
        ends.push(token);
        result.push(FinancialSortedClearingRowTrace {
            live: live.clone(),
            step_index: step.clone(),
            source_index: source.clone(),
            side: row[3].clone(),
            quantity: row[4].clone(),
            full: row[9].clone(),
            marginal: row[10].clone(),
            raw_full: row[5].clone(),
            raw_marginal: row[6].clone(),
            limit_price: [row[7].clone(), row[8].clone()],
            prefixes: std::array::from_fn(|j| pack(&totals[j])),
        });
        old_live = live.clone();
        old_step = step.clone();
    }
    let mut queries = Vec::with_capacity(rows.len());
    let mut summaries = Vec::with_capacity(step_count);
    for step in 0..step_count {
        let source = ends
            .iter()
            .find(|r| tower(b, &r[0]) != 0 && tower(b, &r[1]) == step as u128);
        let live = LinExpr::from_wire(b.alloc_bool(source.is_some()));
        let mut row = vec![live.clone(), live.scale(flat_const(step as u128))];
        for j in 2..10 {
            row.push(alloc_block(
                b,
                Block128(source.map_or(0, |r| tower(b, &r[j]))),
            ));
        }
        summaries.push(FinancialClearingSummaryTrace {
            nonempty: live,
            count: row[2].clone(),
            full: [row[3].clone(), row[4].clone()],
            marginal: [row[5].clone(), row[6].clone()],
            boundary: row[7].clone(),
            boundary_price: [row[8].clone(), row[9].clone()],
        });
        queries.push(row);
    }
    queries.resize_with(rows.len(), || vec![LinExpr::zero(); 10]);
    let left = routed_sort(b, ends, 1);
    let right = routed_sort(b, queries, 1);
    for (a, c) in left.iter().zip(&right) {
        for j in 0..10 {
            pin_eq(b, &a[j], &c[j]);
        }
    }
    FinancialClearingSummariesTrace {
        steps: summaries,
        rows: result,
    }
}
