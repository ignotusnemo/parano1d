// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete frozen-set projection and globally routed clearing.

use super::super::permutation_network::route_permutation_network;
use super::super::{
    alloc_block, flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, extend, less_than, pack};
use super::financial_active_clearing_route::{
    bind_financial_active_clearing_route, FinancialActiveRouteWitness,
    FinancialClearingSourceTrace, FinancialClearingStepTrace,
};
use super::financial_allocation_budget::bind_financial_allocation_budgets as bind_financial_allocation_steps;
use super::financial_clearing_classification::{
    bind_financial_clearing_classification, FinancialClearingClassificationInputTrace,
};
use super::financial_clearing_summaries::{
    bind_financial_clearing_summaries, FinancialClearingSummaryTrace,
};
use super::financial_global_allocation::{
    bind_financial_global_allocation, FinancialAllocationStepInputTrace,
};
use super::financial_launch_context::bind_financial_launch_context;
use super::financial_market_context::bind_financial_market_context;
use super::financial_ratio::bind_financial_ratio;
use super::financial_settlement_sets::FinancialSettlementSetTrace;
use super::validation::{is_zero, require_nonzero};
use noid_core::{hardware::flat_to_tower_u128, Block128};
use noid_tx::native_assets::market::{queue::MAX_ROUND_REQUESTS, MARKET_FEE_BPS};

#[derive(Clone, Copy)]
pub struct FinancialClearingStepWitness {
    pub group: u32,
    pub rank: u8,
    pub terminal: bool,
    pub price: [u64; 2],
    pub at_cap: bool,
}
pub struct FinancialGlobalClearingWitness {
    pub steps: Vec<FinancialClearingStepWitness>,
    pub active: Vec<FinancialActiveRouteWitness>,
}
pub struct FinancialSettlementClearingTrace {
    pub price: [LinExpr; 2],
    pub effective: Vec<LinExpr>,
}
struct Control {
    live: LinExpr,
    group: LinExpr,
    launch: LinExpr,
    reference: [LinExpr; 2],
    supply: LinExpr,
    sold: LinExpr,
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
fn a(b: &mut FieldR1csBuilder, x: u128) -> LinExpr {
    alloc_block(b, Block128(x))
}
fn pair_equal(b: &mut FieldR1csBuilder, x: &[LinExpr], y: &[LinExpr]) -> LinExpr {
    let p = is_zero(b, &x[0].add(&y[0]));
    let q = is_zero(b, &x[1].add(&y[1]));
    mul(b, &p, &q)
}
fn or(b: &mut FieldR1csBuilder, old: &LinExpr, next: &LinExpr) -> LinExpr {
    old.add(&mul(b, next, &old.add_const(F128::ONE)))
}
fn sort(b: &mut FieldR1csBuilder, mut rows: Vec<Vec<LinExpr>>, width: usize) -> Vec<Vec<LinExpr>> {
    let capacity = rows.len().next_power_of_two();
    rows.resize_with(capacity, || vec![LinExpr::zero(); width]);
    let mut order = (0..capacity).collect::<Vec<_>>();
    order.sort_by_key(|&i| {
        (
            tower(b, &rows[i][0]) == 0,
            tower(b, &rows[i][1]),
            tower(b, &rows[i][2]),
            i,
        )
    });
    let mut permutation = vec![0; capacity];
    for (target, source) in order.into_iter().enumerate() {
        permutation[source] = target;
    }
    route_permutation_network(b, rows, &permutation)
}
fn gate_summary(
    b: &mut FieldR1csBuilder,
    flag: &LinExpr,
    s: &FinancialClearingSummaryTrace,
) -> FinancialClearingSummaryTrace {
    FinancialClearingSummaryTrace {
        nonempty: mul(b, flag, &s.nonempty),
        count: mul(b, flag, &s.count),
        full: std::array::from_fn(|i| mul(b, flag, &s.full[i])),
        marginal: std::array::from_fn(|i| mul(b, flag, &s.marginal[i])),
        boundary: mul(b, flag, &s.boundary),
        boundary_price: std::array::from_fn(|i| mul(b, flag, &s.boundary_price[i])),
    }
}
/// Every complete settlement consumes and produces its control and all claims.
/// The fixed physical action capacity bounds both original requests and steps.
/// Removing at least one order at every nonterminal step bounds active pairs.
pub fn financial_clearing_capacities(action_capacity: usize) -> (usize, usize) {
    assert!(action_capacity >= 4 && action_capacity <= 128 && action_capacity % 2 == 0);
    let budget = action_capacity / 2;
    let mut maximum = vec![0usize; budget + 1];
    for n in 1..=budget {
        for m in 1..=MAX_ROUND_REQUESTS.min(n.saturating_sub(1)) {
            maximum[n] = maximum[n].max(maximum[n - m - 1] + m * (m + 1) / 2);
        }
    }
    (budget, maximum[budget].max(1))
}
/// Typed canonical actions, exact native definitions, frozen queues and aggregate
/// admission supply the sets. All prices, sources, contexts, fractions, integer
/// fills, dust transitions and terminal executions are checked together here.
/// Operation-specific claims, pool/custody and fee effects bind these outputs.
pub fn bind_financial_global_clearing(
    b: &mut FieldR1csBuilder,
    sets: &[FinancialSettlementSetTrace],
    action_capacity: usize,
    witness: &FinancialGlobalClearingWitness,
) -> Vec<FinancialSettlementClearingTrace> {
    assert!(!sets.is_empty());
    let (capacity, row_capacity) = financial_clearing_capacities(action_capacity);
    let source_capacity = capacity * MAX_ROUND_REQUESTS / (MAX_ROUND_REQUESTS + 1);
    assert!(witness.steps.len() <= capacity && witness.active.len() <= row_capacity);
    let mut candidates = Vec::with_capacity(sets.len() * MAX_ROUND_REQUESTS);
    let mut controls = Vec::with_capacity(sets.len());
    let mut source_presence = Vec::with_capacity(sets.len());
    let mut input_budget = vec![LinExpr::zero(); 16];
    for set in sets {
        assert_eq!(set.requests.len(), MAX_ROUND_REQUESTS);
        let state = split_packed_input_value(b, &set.frozen[2]);
        let supply_word = mul(b, &set.family[1], &set.definition[4]);
        let supply = split_packed_input_value(b, &supply_word);
        let inventory = mul(b, &set.family[1], &state.amount.value);
        let inventory = bits(b, &inventory, 64);
        let supply_bits = bits(b, &supply.amount.value, 64);
        let sold = pack(&checked_subtract(b, &supply_bits, &inventory));
        controls.push(Control {
            live: set.live.clone(),
            group: set.header_page.clone(),
            launch: set.family[1].clone(),
            reference: [
                mul(b, &set.family[0], &state.amount.value),
                mul(b, &set.family[0], &state.creation_id.value),
            ],
            supply: supply.amount.value,
            sold,
        });
        let count = bits(b, &set.count, 5);
        input_budget = checked_add(b, &input_budget, &extend(&count, 16));
        input_budget = checked_add(b, &input_budget, &extend(&[set.live.clone()], 16));
        let mut presence = LinExpr::zero();
        for (i, r) in set.requests.iter().enumerate() {
            let market = mul(b, &set.family[0], &r.kinds[0]);
            let launch = mul(b, &set.family[1], &r.kinds[4]);
            let live = market.add(&launch);
            presence = or(b, &presence, &live);
            let swap = split_packed_input_value(b, &r.fields[10]);
            let request = split_packed_input_value(b, &r.fields[8]);
            let time = split_packed_input_value(b, &r.fields[9]);
            let quote = pair_equal(b, &r.fields[2..4], &set.definition[4..6]);
            let side = mul(b, &market, &quote).add(&mul(b, &launch, &time.creation_id.value));
            let quantity =
                mul(b, &market, &swap.amount.value).add(&mul(b, &launch, &request.amount.value));
            let limit = mul(b, &market, &swap.creation_id.value).add(&mul(
                b,
                &launch,
                &request.creation_id.value,
            ));
            candidates.push(vec![
                live.clone(),
                mul(b, &live, &set.header_page),
                live.scale(flat_const(i as u128)),
                side,
                quantity,
                limit,
                launch,
            ]);
        }
        source_presence.push(presence);
    }
    let maximum_budget = bits(b, &number(capacity as u128), 16);
    let over = less_than(b, &maximum_budget, &input_budget);
    pin_zero(b, &over);
    for (i, left) in controls.iter().enumerate() {
        for right in &controls[i + 1..] {
            let same = is_zero(b, &left.group.add(&right.group));
            let both = mul(b, &left.live, &right.live);
            let duplicate = mul(b, &both, &same);
            pin_zero(b, &duplicate);
        }
    }
    candidates.resize_with(candidates.len().max(capacity).next_power_of_two(), || {
        vec![LinExpr::zero(); 7]
    });
    let mut projection = sort(b, candidates, 7);
    for row in &projection[source_capacity..] {
        pin_zero(b, &row[0]);
    }
    projection.truncate(source_capacity);
    let mut previous: Option<(LinExpr, Vec<LinExpr>)> = None;
    let mut sources = Vec::with_capacity(source_capacity);
    for row in &projection {
        let mut key = bits(b, &row[2], 4);
        key.extend(bits(b, &row[1], 32));
        if let Some((live, old)) = previous {
            let hole = mul(b, &row[0], &live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let strict = less_than(b, &old, &key);
            let bad = mul(b, &row[0], &strict.add_const(F128::ONE));
            pin_zero(b, &bad);
        }
        previous = Some((row[0].clone(), key));
        let market = row[0].add(&row[6]);
        let gross = mul(b, &market, &row[4]);
        let value = tower(b, &gross) * u128::from(10_000 - MARKET_FEE_BPS) / 10_000;
        let after_fee = a(b, value);
        bits(b, &after_fee, 63);
        let _ = bind_financial_ratio(
            b,
            &market,
            &LinExpr::zero(),
            &gross,
            &number(u128::from(10_000 - MARKET_FEE_BPS)),
            &number(10_000),
            &after_fee,
            64,
        );
        let quantity = after_fee.add(&mul(b, &row[6], &row[4]));
        require_nonzero(b, &quantity, &row[0]);
        sources.push(FinancialClearingSourceTrace {
            live: row[0].clone(),
            group: row[1].clone(),
            side: row[3].clone(),
            quantity,
            limit: row[5].clone(),
        });
    }
    let steps = (0..capacity)
        .map(|i| {
            let w = witness.steps.get(i);
            FinancialClearingStepTrace {
                live: a(b, u128::from(w.is_some())),
                group: a(b, w.map_or(0, |s| u128::from(s.group))),
                rank: a(b, w.map_or(0, |s| u128::from(s.rank))),
                terminal: a(b, u128::from(w.is_some_and(|s| s.terminal))),
                price: std::array::from_fn(|j| a(b, w.map_or(0, |s| u128::from(s.price[j])))),
                at_cap: a(b, u128::from(w.is_some_and(|s| s.at_cap))),
            }
        })
        .collect::<Vec<_>>();
    let mut families = Vec::with_capacity(capacity);
    let mut references = Vec::with_capacity(capacity);
    let mut supplies = Vec::with_capacity(capacity);
    let mut solds = Vec::with_capacity(capacity);
    for step in &steps {
        let mut found = LinExpr::zero();
        let mut launch = LinExpr::zero();
        let mut reference = [LinExpr::zero(), LinExpr::zero()];
        let mut supply = LinExpr::zero();
        let mut sold = LinExpr::zero();
        for c in &controls {
            let same = is_zero(b, &c.group.add(&step.group));
            let selected = mul(b, &same, &step.live);
            let selected = mul(b, &selected, &c.live);
            found = found.add(&selected);
            launch = launch.add(&mul(b, &selected, &c.launch));
            for j in 0..2 {
                reference[j] = reference[j].add(&mul(b, &selected, &c.reference[j]));
            }
            supply = supply.add(&mul(b, &selected, &c.supply));
            sold = sold.add(&mul(b, &selected, &c.sold));
        }
        pin_eq(b, &found, &step.live);
        families.push(launch);
        references.push(reference);
        supplies.push(supply);
        solds.push(sold);
    }
    let active =
        bind_financial_active_clearing_route(b, &sources, &steps, row_capacity, &witness.active);
    let mut classes = Vec::with_capacity(row_capacity);
    for r in &active {
        let mut launch = LinExpr::zero();
        for (i, f) in families.iter().enumerate() {
            let same = is_zero(b, &r.step_index.add_const(flat_const(i as u128)));
            let selected = mul(b, &r.live, &same);
            launch = launch.add(&mul(b, &selected, f));
        }
        let market = r.live.add(&launch);
        classes.push(bind_financial_clearing_classification(
            b,
            &FinancialClearingClassificationInputTrace {
                live: r.live.clone(),
                market,
                launch,
                side: r.side.clone(),
                quantity: r.quantity.clone(),
                limit: r.limit.clone(),
                price: r.price.clone(),
                at_cap: r.at_cap.clone(),
            },
        ));
    }
    let summaries = bind_financial_clearing_summaries(b, &active, &classes, capacity);
    let mut allocation_input = Vec::with_capacity(capacity);
    for i in 0..capacity {
        let step = &steps[i];
        let launch = &families[i];
        let market = step.live.add(launch);
        let market_summary = gate_summary(b, &market, &summaries.steps[i]);
        let launch_summary = gate_summary(b, launch, &summaries.steps[i]);
        let m =
            bind_financial_market_context(b, &market, &references[i], &step.price, &market_summary);
        let l = bind_financial_launch_context(
            b,
            launch,
            &supplies[i],
            &solds[i],
            &step.price,
            &step.at_cap,
            &launch_summary,
        );
        allocation_input.push(FinancialAllocationStepInputTrace {
            live: step.live.clone(),
            launch: launch.clone(),
            at_cap: step.at_cap.clone(),
            price: step.price.clone(),
            partial: std::array::from_fn(|j| m.partial[j].add(&l.partial[j])),
            marginal_totals: std::array::from_fn(|j| {
                m.marginal_totals[j].add(&l.marginal_totals[j])
            }),
            fraction_numerator: m.fraction_numerator.add(&l.fraction_numerator),
            fraction_denominator: m.fraction_denominator.add(&l.fraction_denominator),
        });
    }
    let allocation_steps = bind_financial_allocation_steps(b, &allocation_input);
    let execution = bind_financial_global_allocation(b, &summaries.rows, &allocation_steps);
    let wanted = sort(
        b,
        active
            .iter()
            .map(|r| {
                vec![
                    r.live.clone(),
                    r.step_index.clone(),
                    r.source_index.clone(),
                    r.dust.clone(),
                ]
            })
            .collect(),
        4,
    );
    let actual = sort(
        b,
        execution
            .iter()
            .map(|r| {
                vec![
                    r.live.clone(),
                    r.step_index.clone(),
                    r.source_index.clone(),
                    r.dust.clone(),
                ]
            })
            .collect(),
        4,
    );
    for (left, right) in wanted.iter().zip(&actual) {
        for j in 0..4 {
            pin_eq(b, &left[j], &right[j]);
        }
    }
    let mut terminal_quantities = Vec::with_capacity(row_capacity);
    for r in &execution {
        let mut terminal = LinExpr::zero();
        for (i, s) in steps.iter().enumerate() {
            let same = is_zero(b, &r.step_index.add_const(flat_const(i as u128)));
            let selected = mul(b, &same, &r.live);
            terminal = terminal.add(&mul(b, &selected, &s.terminal));
        }
        terminal_quantities.push(mul(b, &terminal, &r.effective));
    }
    let mut final_quantities = Vec::with_capacity(source_capacity);
    for i in 0..source_capacity {
        let mut amount = LinExpr::zero();
        for (r, q) in execution.iter().zip(&terminal_quantities) {
            let same = is_zero(b, &r.source_index.add_const(flat_const(i as u128)));
            amount = amount.add(&mul(b, &same, q));
        }
        final_quantities.push(amount);
    }
    let mut result = Vec::with_capacity(sets.len());
    for (set, present) in sets.iter().zip(&source_presence) {
        let mut price = [LinExpr::zero(), LinExpr::zero()];
        let mut found = LinExpr::zero();
        for step in &steps {
            let same = is_zero(b, &set.header_page.add(&step.group));
            let selected = mul(b, &same, &step.live);
            let selected = mul(b, &selected, &step.terminal);
            let selected = mul(b, &selected, &set.live);
            found = found.add(&selected);
            for j in 0..2 {
                price[j] = price[j].add(&mul(b, &selected, &step.price[j]));
            }
        }
        pin_eq(b, &found, present);
        let no_swaps = mul(b, &set.family[0], &present.add_const(F128::ONE));
        let state = split_packed_input_value(b, &set.frozen[2]);
        price[0] = price[0].add(&mul(b, &no_swaps, &state.creation_id.value));
        price[1] = price[1].add(&mul(b, &no_swaps, &state.amount.value));
        let effective = (0..MAX_ROUND_REQUESTS)
            .map(|i| {
                let mut amount = LinExpr::zero();
                for (row, q) in projection.iter().zip(&final_quantities) {
                    let same = is_zero(b, &row[1].add(&set.header_page));
                    let ordinal = is_zero(b, &row[2].add_const(flat_const(i as u128)));
                    let selected = mul(b, &same, &ordinal);
                    let selected = mul(b, &selected, &row[0]);
                    let selected = mul(b, &selected, &set.live);
                    amount = amount.add(&mul(b, &selected, q));
                }
                amount
            })
            .collect();
        result.push(FinancialSettlementClearingTrace { price, effective });
    }
    result
}
