// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete active-order lineage for compact native clearing arithmetic.

use super::super::permutation_network::route_permutation_network;
use super::super::{
    alloc_block, flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::{checked_add, less_than, pack};
use super::validation::is_zero;
use noid_core::{hardware::flat_to_tower_u128, Block128};

pub struct FinancialClearingSourceTrace {
    pub live: LinExpr,
    pub group: LinExpr,
    pub side: LinExpr,
    pub quantity: LinExpr,
    pub limit: LinExpr,
}
pub struct FinancialClearingStepTrace {
    pub live: LinExpr,
    pub group: LinExpr,
    pub rank: LinExpr,
    pub terminal: LinExpr,
    pub price: [LinExpr; 2],
    pub at_cap: LinExpr,
}
#[derive(Clone, Copy)]
pub struct FinancialActiveRouteWitness {
    pub source: usize,
    pub step: usize,
    pub dust: bool,
}
pub struct FinancialActiveClearingRowTrace {
    pub live: LinExpr,
    pub source_index: LinExpr,
    pub step_index: LinExpr,
    pub group: LinExpr,
    pub rank: LinExpr,
    pub side: LinExpr,
    pub quantity: LinExpr,
    pub limit: LinExpr,
    pub price: [LinExpr; 2],
    pub at_cap: LinExpr,
    pub terminal: LinExpr,
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
fn zero_padding(b: &mut FieldR1csBuilder, live: &LinExpr, x: &LinExpr) {
    let bad = mul(b, &live.add_const(F128::ONE), x);
    pin_zero(b, &bad);
}
fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}
fn sorted_tokens(
    b: &mut FieldR1csBuilder,
    mut rows: Vec<Vec<LinExpr>>,
    capacity: usize,
) -> Vec<Vec<LinExpr>> {
    assert!(rows.len() <= capacity && capacity.is_power_of_two());
    rows.resize_with(capacity, || vec![LinExpr::zero(); 7]);
    let mut order = (0..capacity).collect::<Vec<_>>();
    order.sort_by_key(|&i| {
        (
            tower(b, &rows[i][0]) == 0,
            tower(b, &rows[i][1]),
            tower(b, &rows[i][2]),
            tower(b, &rows[i][3]),
            i,
        )
    });
    let mut permutation = vec![0; capacity];
    for (target, source) in order.into_iter().enumerate() {
        permutation[source] = target;
    }
    route_permutation_network(b, rows, &permutation)
}
/// Complete source rows are the original funded-key-ordered swap or launch
/// projection. The caller binds each returned dust bit to its exact price and
/// allocation calculation, and binds final terminal rows to every execution.
/// Every active order is consumed once per step. Only non-dust nonterminal
/// rows produce a successor, so an omitted or reintroduced order is rejected.
pub fn bind_financial_active_clearing_route(
    b: &mut FieldR1csBuilder,
    sources: &[FinancialClearingSourceTrace],
    steps: &[FinancialClearingStepTrace],
    row_capacity: usize,
    witness: &[FinancialActiveRouteWitness],
) -> Vec<FinancialActiveClearingRowTrace> {
    assert!(!sources.is_empty() && !steps.is_empty() && witness.len() <= row_capacity);
    let mut producers = Vec::with_capacity(sources.len() + row_capacity);
    for (i, s) in sources.iter().enumerate() {
        boolean(b, &s.live);
        boolean(b, &s.side);
        bits(b, &s.group, 32);
        for x in [&s.group, &s.side, &s.quantity, &s.limit] {
            zero_padding(b, &s.live, x);
        }
        let source = LinExpr::constant(flat_const(i as u128));
        let id = mul(b, &s.live, &source);
        producers.push(vec![
            s.live.clone(),
            s.group.clone(),
            LinExpr::zero(),
            id,
            s.side.clone(),
            s.quantity.clone(),
            s.limit.clone(),
        ]);
    }
    let mut old_live = LinExpr::zero();
    let mut old_group = LinExpr::zero();
    let mut old_rank = vec![LinExpr::zero(); 8];
    let mut old_terminal = LinExpr::zero();
    for (index, step) in steps.iter().enumerate() {
        for x in [&step.live, &step.terminal, &step.at_cap] {
            boolean(b, x);
        }
        for x in [
            &step.group,
            &step.rank,
            &step.terminal,
            &step.price[0],
            &step.price[1],
            &step.at_cap,
        ] {
            zero_padding(b, &step.live, x);
        }
        let group = bits(b, &step.group, 32);
        let rank = bits(b, &step.rank, 8);
        if index > 0 {
            let hole = mul(b, &step.live, &old_live.add_const(F128::ONE));
            pin_zero(b, &hole);
        }
        let same = is_zero(b, &step.group.add(&old_group));
        let continued = mul(b, &same, &old_live);
        let continued = mul(b, &continued, &step.live);
        let initial = step.live.add(&continued);
        let ended = old_live.add(&continued);
        eq_when(b, &ended, &old_terminal, &LinExpr::constant(F128::ONE));
        eq_when(b, &continued, &old_terminal, &LinExpr::zero());
        let mut one = vec![LinExpr::zero(); 8];
        one[0] = old_live.clone();
        let next = checked_add(b, &old_rank, &one);
        eq_when(b, &continued, &step.rank, &pack(&next));
        eq_when(b, &initial, &step.rank, &LinExpr::zero());
        let old_group_bits = bits(b, &old_group, 32);
        let greater = less_than(b, &old_group_bits, &group);
        let between = mul(b, &initial, &old_live);
        eq_when(b, &between, &greater, &LinExpr::constant(F128::ONE));
        let mut known = LinExpr::zero();
        for source in sources {
            let same = is_zero(b, &source.group.add(&step.group));
            let present = mul(b, &same, &source.live);
            let next = mul(b, &present, &known.add_const(F128::ONE));
            known = known.add(&next);
        }
        eq_when(b, &step.live, &known, &LinExpr::constant(F128::ONE));
        old_live = step.live.clone();
        old_group = step.group.clone();
        old_rank = rank;
        old_terminal = step.terminal.clone();
    }
    eq_when(b, &old_live, &old_terminal, &LinExpr::constant(F128::ONE));
    let mut result = Vec::with_capacity(row_capacity);
    let mut consumers = Vec::with_capacity(row_capacity);
    let mut dust_by_step = vec![LinExpr::zero(); steps.len()];
    for i in 0..row_capacity {
        let hint = witness.get(i);
        let live = LinExpr::from_wire(b.alloc_bool(hint.is_some()));
        let source_index = alloc_block(b, Block128(hint.map_or(0, |r| r.source as u128)));
        let step_index = alloc_block(b, Block128(hint.map_or(0, |r| r.step as u128)));
        let dust = LinExpr::from_wire(b.alloc_bool(hint.is_some_and(|r| r.dust)));
        for x in [&source_index, &step_index, &dust] {
            zero_padding(b, &live, x);
        }
        let mut found = LinExpr::zero();
        let mut source_group = LinExpr::zero();
        let mut payload = [LinExpr::zero(), LinExpr::zero(), LinExpr::zero()];
        for (j, s) in sources.iter().enumerate() {
            let same = is_zero(b, &source_index.add_const(flat_const(j as u128)));
            let selected = mul(b, &live, &same);
            let selected = mul(b, &selected, &s.live);
            found = found.add(&selected);
            source_group = source_group.add(&mul(b, &selected, &s.group));
            for (k, x) in [&s.side, &s.quantity, &s.limit].iter().enumerate() {
                payload[k] = payload[k].add(&mul(b, &selected, x));
            }
        }
        pin_eq(b, &found, &live);
        let mut found = LinExpr::zero();
        let mut group = LinExpr::zero();
        let mut rank = LinExpr::zero();
        let mut terminal = LinExpr::zero();
        let mut price = [LinExpr::zero(), LinExpr::zero()];
        let mut at_cap = LinExpr::zero();
        for (j, s) in steps.iter().enumerate() {
            let same = is_zero(b, &step_index.add_const(flat_const(j as u128)));
            let selected = mul(b, &live, &same);
            let selected = mul(b, &selected, &s.live);
            found = found.add(&selected);
            group = group.add(&mul(b, &selected, &s.group));
            rank = rank.add(&mul(b, &selected, &s.rank));
            terminal = terminal.add(&mul(b, &selected, &s.terminal));
            at_cap = at_cap.add(&mul(b, &selected, &s.at_cap));
            for k in 0..2 {
                price[k] = price[k].add(&mul(b, &selected, &s.price[k]));
            }
            let removed = mul(b, &selected, &dust);
            let next = mul(b, &removed, &dust_by_step[j].add_const(F128::ONE));
            dust_by_step[j] = dust_by_step[j].add(&next);
        }
        pin_eq(b, &found, &live);
        pin_eq(b, &group, &source_group);
        let survives = mul(b, &live, &dust.add_const(F128::ONE));
        let survives = mul(b, &survives, &terminal.add_const(F128::ONE));
        let rank_bits = bits(b, &rank, 8);
        let mut one = vec![LinExpr::zero(); 8];
        one[0] = survives.clone();
        let successor = pack(&checked_add(b, &rank_bits, &one));
        let id = mul(b, &live, &source_index);
        let consumer = vec![
            live.clone(),
            group.clone(),
            rank.clone(),
            id.clone(),
            payload[0].clone(),
            payload[1].clone(),
            payload[2].clone(),
        ];
        let producer = vec![
            survives.clone(),
            mul(b, &survives, &group),
            mul(b, &survives, &successor),
            mul(b, &survives, &id),
            mul(b, &survives, &payload[0]),
            mul(b, &survives, &payload[1]),
            mul(b, &survives, &payload[2]),
        ];
        consumers.push(consumer);
        producers.push(producer);
        result.push(FinancialActiveClearingRowTrace {
            live,
            source_index,
            step_index,
            group,
            rank,
            side: payload[0].clone(),
            quantity: payload[1].clone(),
            limit: payload[2].clone(),
            price,
            at_cap,
            terminal,
            dust,
        });
    }
    for (step, dust) in steps.iter().zip(&dust_by_step) {
        let expected = mul(b, &step.live, &step.terminal.add_const(F128::ONE));
        pin_eq(b, dust, &expected);
    }
    let capacity = (sources.len() + row_capacity).next_power_of_two();
    let producers = sorted_tokens(b, producers, capacity);
    let consumers = sorted_tokens(b, consumers, capacity);
    let mut previous: Option<(LinExpr, Vec<LinExpr>)> = None;
    for (a, c) in producers.iter().zip(&consumers) {
        for j in 0..7 {
            pin_eq(b, &a[j], &c[j]);
        }
        let mut key = bits(b, &c[3], 8);
        key.extend(bits(b, &c[2], 8));
        key.extend(bits(b, &c[1], 32));
        if let Some((old_live, old_key)) = previous {
            let hole = mul(b, &c[0], &old_live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let strict = less_than(b, &old_key, &key);
            eq_when(b, &c[0], &strict, &LinExpr::constant(F128::ONE));
        }
        previous = Some((c[0].clone(), key));
    }
    result
}
