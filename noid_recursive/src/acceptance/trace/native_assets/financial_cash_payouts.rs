// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete beneficiary aggregation and canonical ordinary payouts.

use super::super::permutation_network::route_permutation_network;
use super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::{checked_add, less_than, pack};
use super::validation::is_zero;
use noid_core::hardware::flat_to_tower_u128;

pub struct FinancialCashContributionTrace {
    pub live: LinExpr,
    pub group: LinExpr,
    pub owner: [LinExpr; 2],
    pub amount: LinExpr,
}
pub struct FinancialCashOutputTrace {
    pub live: LinExpr,
    pub group: LinExpr,
    pub owner: [LinExpr; 2],
    pub amount: LinExpr,
    pub ordinal: LinExpr,
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
fn order_bits(b: &mut FieldR1csBuilder, row: &[LinExpr]) -> Vec<LinExpr> {
    let raw = [bits(b, &row[2], 128), bits(b, &row[3], 128)].concat();
    let mut key = (0..32)
        .rev()
        .flat_map(|byte| raw[8 * byte..8 * byte + 8].iter().cloned())
        .collect::<Vec<_>>();
    key.extend(bits(b, &row[1], 32));
    key
}
fn route(
    b: &mut FieldR1csBuilder,
    mut rows: Vec<Vec<LinExpr>>,
    width: usize,
    capacity: usize,
) -> Vec<Vec<LinExpr>> {
    rows.resize_with(capacity, || vec![LinExpr::zero(); width]);
    let mut order = (0..rows.len()).collect::<Vec<_>>();
    order.sort_by_key(|&i| {
        (
            tower(b, &rows[i][0]) == 0,
            tower(b, &rows[i][1]),
            tower(b, &rows[i][2]).swap_bytes(),
            tower(b, &rows[i][3]).swap_bytes(),
            i,
        )
    });
    let mut permutation = vec![0; rows.len()];
    for (target, source) in order.into_iter().enumerate() {
        permutation[source] = target;
    }
    route_permutation_network(b, rows, &permutation)
}
fn framed(b: &mut FieldR1csBuilder, row: &[LinExpr]) {
    boolean(b, &row[0]);
    for x in &row[1..] {
        let bad = mul(b, &row[0].add_const(F128::ONE), x);
        pin_zero(b, &bad);
    }
    let lo = is_zero(b, &row[2]);
    let hi = is_zero(b, &row[3]);
    let empty = mul(b, &lo, &hi);
    let bad = mul(b, &row[0], &empty);
    pin_zero(b, &bad);
}

/// Contributions and outputs are complete projections of authenticated actions
/// and transition arithmetic. Equal beneficiary addresses are summed with exact
/// wide carries. Zero aggregates are omitted, and every remaining amount must
/// fit u64. Outputs have increasing byte-ordered owners and zero-based ordinals
/// within each group. The enclosing relation binds the actual output set.
pub fn bind_financial_cash_payouts(
    b: &mut FieldR1csBuilder,
    contributions: &[FinancialCashContributionTrace],
    outputs: &[FinancialCashOutputTrace],
) {
    assert!(!contributions.is_empty() && !outputs.is_empty());
    let capacity = contributions.len().max(outputs.len()).next_power_of_two();
    let sum_width = 64 + capacity.trailing_zeros() as usize;
    assert!(sum_width <= 128);
    let rows = contributions
        .iter()
        .map(|s| {
            vec![
                s.live.clone(),
                s.group.clone(),
                s.owner[0].clone(),
                s.owner[1].clone(),
                s.amount.clone(),
            ]
        })
        .collect::<Vec<_>>();
    for row in &rows {
        framed(b, row);
    }
    let rows = route(b, rows, 5, capacity);
    let mut previous: Option<(LinExpr, Vec<LinExpr>)> = None;
    let mut old_group = LinExpr::zero();
    let mut old_owner = [LinExpr::zero(), LinExpr::zero()];
    let mut old_live = LinExpr::zero();
    let mut sum = vec![LinExpr::zero(); sum_width];
    let mut ends = Vec::with_capacity(capacity);
    for (i, row) in rows.iter().enumerate() {
        let key = order_bits(b, row);
        if let Some((live, old)) = previous {
            let hole = mul(b, &row[0], &live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let descending = less_than(b, &key, &old);
            let bad = mul(b, &row[0], &descending);
            pin_zero(b, &bad);
        }
        previous = Some((row[0].clone(), key));
        let mut same = is_zero(b, &row[1].add(&old_group));
        for j in 0..2 {
            let eq = is_zero(b, &row[2 + j].add(&old_owner[j]));
            same = mul(b, &same, &eq);
        }
        let cont = mul(b, &same, &old_live);
        let cont = mul(b, &cont, &row[0]);
        let previous = sum.iter().map(|x| mul(b, &cont, x)).collect::<Vec<_>>();
        let mut amount = bits(b, &row[4], 64);
        amount.resize(sum_width, LinExpr::zero());
        sum = checked_add(b, &previous, &amount);
        let continuation = if let Some(next) = rows.get(i + 1) {
            let mut eq = is_zero(b, &row[1].add(&next[1]));
            for j in 0..2 {
                let owner = is_zero(b, &row[2 + j].add(&next[2 + j]));
                eq = mul(b, &eq, &owner);
            }
            mul(b, &eq, &next[0])
        } else {
            LinExpr::zero()
        };
        let end = mul(b, &row[0], &continuation.add_const(F128::ONE));
        let empty = is_zero(b, &pack(&sum));
        let live = mul(b, &end, &empty.add_const(F128::ONE));
        for high in &sum[64..] {
            let bad = mul(b, &end, high);
            pin_zero(b, &bad);
        }
        ends.push(vec![
            live.clone(),
            mul(b, &live, &row[1]),
            mul(b, &live, &row[2]),
            mul(b, &live, &row[3]),
            mul(b, &live, &pack(&sum)),
        ]);
        old_group = row[1].clone();
        old_owner = [row[2].clone(), row[3].clone()];
        old_live = row[0].clone();
    }
    let expected = route(b, ends, 5, capacity);
    let actual = outputs
        .iter()
        .map(|s| {
            vec![
                s.live.clone(),
                s.group.clone(),
                s.owner[0].clone(),
                s.owner[1].clone(),
                s.amount.clone(),
                s.ordinal.clone(),
            ]
        })
        .collect::<Vec<_>>();
    for row in &actual {
        framed(b, row);
        let zero = is_zero(b, &row[4]);
        let bad = mul(b, &row[0], &zero);
        pin_zero(b, &bad);
        bits(b, &row[4], 64);
    }
    let actual = route(b, actual, 6, capacity);
    let count_width = (capacity + 1).next_power_of_two().trailing_zeros() as usize;
    let mut rank = vec![LinExpr::zero(); count_width];
    let mut previous_group = LinExpr::zero();
    let mut previous_live = LinExpr::zero();
    let mut previous_key: Option<Vec<LinExpr>> = None;
    for (row, want) in actual.iter().zip(&expected) {
        for j in 0..5 {
            pin_eq(b, &row[j], &want[j]);
        }
        let key = order_bits(b, row);
        let hole = mul(b, &row[0], &previous_live.add_const(F128::ONE));
        if previous_key.is_some() {
            pin_zero(b, &hole);
        }
        if let Some(old) = previous_key {
            let strict = less_than(b, &old, &key);
            let bad = mul(b, &row[0], &strict.add_const(F128::ONE));
            pin_zero(b, &bad);
        }
        previous_key = Some(key);
        let same = is_zero(b, &row[1].add(&previous_group));
        let cont = mul(b, &same, &previous_live);
        let cont = mul(b, &cont, &row[0]);
        let old = rank.iter().map(|x| mul(b, &cont, x)).collect::<Vec<_>>();
        let mut delta = vec![LinExpr::zero(); count_width];
        delta[0] = cont;
        rank = checked_add(b, &old, &delta);
        pin_eq(b, &row[5], &pack(&rank));
        previous_group = row[1].clone();
        previous_live = row[0].clone();
    }
}
