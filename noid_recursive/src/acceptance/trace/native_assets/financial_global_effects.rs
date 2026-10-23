// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete request compaction and shared swap execution.

use super::super::permutation_network::route_permutation_network;
use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, extend, less_than};
use super::financial_market_effects_shared::{
    bind_financial_market_finish, bind_financial_market_swap_totals, FinancialMarketEffectsTrace,
};
use super::financial_settlement_sets::FinancialSettlementSetTrace;
use super::financial_swap_execution::{
    bind_financial_swap_execution, FinancialSwapExecutionInputTrace, FinancialSwapExecutionTrace,
};
use super::validation::is_zero;
use noid_core::hardware::flat_to_tower_u128;
use noid_tx::native_assets::market::queue::MAX_ROUND_REQUESTS;

pub struct FinancialEffectRequestTrace {
    pub live: LinExpr,
    pub group: LinExpr,
    pub ordinal: LinExpr,
    pub market: LinExpr,
    pub launch: LinExpr,
    pub price: [LinExpr; 2],
    pub quote: [LinExpr; 2],
    pub effective: LinExpr,
    pub kinds: [LinExpr; 5],
    pub fields: [LinExpr; 12],
}

fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}

fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, width: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, width)
}

fn equal_pair(b: &mut FieldR1csBuilder, x: &[LinExpr], y: &[LinExpr]) -> LinExpr {
    let first = is_zero(b, &x[0].add(&y[0]));
    let second = is_zero(b, &x[1].add(&y[1]));
    mul(b, &first, &second)
}

/// Validated frozen sets supply boolean family/request selectors, exact typed
/// fields and clearing results. Every request is routed once. Strict order and
/// a zero dropped suffix establish a complete, unique bounded projection.
pub fn bind_financial_effect_requests(
    b: &mut FieldR1csBuilder,
    sets: &[FinancialSettlementSetTrace],
    prices: &[[LinExpr; 2]],
    effective: &[Vec<LinExpr>],
    action_capacity: usize,
) -> Vec<FinancialEffectRequestTrace> {
    assert!(!sets.is_empty());
    assert_eq!(sets.len(), prices.len());
    assert_eq!(sets.len(), effective.len());
    assert!(action_capacity >= 4 && action_capacity <= 128 && action_capacity % 2 == 0);
    // q <= 16*g and q+g <= B imply q <= floor(16*B/17).
    let request_capacity = (action_capacity / 2) * MAX_ROUND_REQUESTS / (MAX_ROUND_REQUESTS + 1);
    let mut input_budget = vec![LinExpr::zero(); 16];
    const WIDTH: usize = 27;
    let mut source = Vec::with_capacity(sets.len() * MAX_ROUND_REQUESTS);
    for (i, set) in sets.iter().enumerate() {
        assert_eq!(set.requests.len(), MAX_ROUND_REQUESTS);
        assert_eq!(effective[i].len(), MAX_ROUND_REQUESTS);
        let count = bits(b, &set.count, 5);
        input_budget = checked_add(b, &input_budget, &extend(&count, 16));
        input_budget = checked_add(b, &input_budget, &extend(&[set.live.clone()], 16));
        for other in &sets[..i] {
            let same = is_zero(b, &set.header_page.add(&other.header_page));
            let both = mul(b, &set.live, &other.live);
            let duplicate = mul(b, &same, &both);
            pin_zero(b, &duplicate);
        }
        for (ordinal, request) in set.requests.iter().enumerate() {
            let live = mul(b, &set.live, &request.live);
            let mut row = vec![
                live.clone(),
                mul(b, &live, &set.header_page),
                live.scale(flat_const(ordinal as u128)),
                mul(b, &live, &set.family[0]),
                mul(b, &live, &set.family[1]),
            ];
            row.extend(prices[i].iter().map(|x| mul(b, &live, x)));
            row.extend(set.definition[4..6].iter().map(|x| mul(b, &live, x)));
            row.push(mul(b, &live, &effective[i][ordinal]));
            row.extend(request.kinds.iter().map(|x| mul(b, &live, x)));
            row.extend(request.fields.iter().map(|x| mul(b, &live, x)));
            assert_eq!(row.len(), WIDTH);
            source.push(row);
        }
    }
    let maximum = bits(
        b,
        &LinExpr::constant(flat_const((action_capacity / 2) as u128)),
        16,
    );
    let over = less_than(b, &maximum, &input_budget);
    pin_zero(b, &over);
    let capacity = source.len().max(request_capacity).next_power_of_two();
    source.resize_with(capacity, || vec![LinExpr::zero(); WIDTH]);
    let mut order = (0..capacity).collect::<Vec<_>>();
    order.sort_by_key(|&i| {
        (
            tower(b, &source[i][0]) == 0,
            tower(b, &source[i][1]),
            tower(b, &source[i][2]),
            i,
        )
    });
    let mut permutation = vec![0; capacity];
    for (target, index) in order.into_iter().enumerate() {
        permutation[index] = target;
    }
    let routed = route_permutation_network(b, source, &permutation);
    let mut result = Vec::with_capacity(request_capacity);
    let mut previous_live = LinExpr::constant(F128::ONE);
    let mut previous_key = vec![LinExpr::zero(); 36];
    for (i, row) in routed.into_iter().enumerate() {
        if i >= request_capacity {
            pin_zero(b, &row[0]);
            continue;
        }
        let live = &row[0];
        let invalid_live = mul(b, live, &live.add_const(F128::ONE));
        pin_zero(b, &invalid_live);
        let gap = mul(b, live, &previous_live.add_const(F128::ONE));
        pin_zero(b, &gap);
        let group = bits(b, &row[1], 32);
        let mut key = bits(b, &row[2], 4);
        key.extend(group);
        if i > 0 {
            let increasing = less_than(b, &previous_key, &key);
            let bad = mul(b, live, &increasing.add_const(F128::ONE));
            pin_zero(b, &bad);
        }
        previous_key = key;
        previous_live = live.clone();
        result.push(FinancialEffectRequestTrace {
            live: live.clone(),
            group: row[1].clone(),
            ordinal: row[2].clone(),
            market: row[3].clone(),
            launch: row[4].clone(),
            price: std::array::from_fn(|j| row[5 + j].clone()),
            quote: std::array::from_fn(|j| row[7 + j].clone()),
            effective: row[9].clone(),
            kinds: std::array::from_fn(|j| row[10 + j].clone()),
            fields: std::array::from_fn(|j| row[15 + j].clone()),
        });
    }
    result
}

fn select_executions<const WIDTH: usize>(
    b: &mut FieldR1csBuilder,
    set: &FinancialSettlementSetTrace,
    rows: &[FinancialEffectRequestTrace],
    values: &[[LinExpr; WIDTH]],
) -> Vec<[LinExpr; WIDTH]> {
    assert_eq!(rows.len(), values.len());
    set.requests
        .iter()
        .enumerate()
        .map(|(ordinal, request)| {
            let mut found = LinExpr::zero();
            let mut output = std::array::from_fn(|_| LinExpr::zero());
            for (row, values) in rows.iter().zip(values) {
                let group = is_zero(b, &row.group.add(&set.header_page));
                let rank = is_zero(b, &row.ordinal.add_const(flat_const(ordinal as u128)));
                let hit = mul(b, &group, &rank);
                let hit = mul(b, &hit, &row.market);
                let hit = mul(b, &hit, &set.family[0]);
                found = found.add(&hit);
                for j in 0..WIDTH {
                    output[j] = output[j].add(&mul(b, &hit, &values[j]));
                }
            }
            let expected = mul(b, &set.family[0], &request.live);
            pin_eq(b, &found, &expected);
            output
        })
        .collect()
}

/// Nonlinear swap calculations are allocated once per global
/// request. Exact group/ordinal queries return those constrained results to
/// complete set accounting and its physical output binding.
pub fn bind_financial_global_market_effects_from_requests(
    b: &mut FieldR1csBuilder,
    sets: &[FinancialSettlementSetTrace],
    prices: &[[LinExpr; 2]],
    fees: &[LinExpr],
    rows: &[FinancialEffectRequestTrace],
) -> Vec<FinancialMarketEffectsTrace> {
    assert_eq!(sets.len(), prices.len());
    assert_eq!(sets.len(), fees.len());
    let mut swaps = Vec::with_capacity(rows.len());
    for row in rows {
        let swap = mul(b, &row.market, &row.kinds[0]);
        let non_swap = row.market.add(&swap);
        let outside = mul(b, &non_swap, &row.effective);
        pin_zero(b, &outside);
        let side = equal_pair(b, &row.fields[2..4], &row.quote);
        let side = mul(b, &swap, &side);
        let principal = split_packed_input_value(b, &row.fields[10]);
        let effective_input = mul(b, &swap, &row.effective);
        let execution = bind_financial_swap_execution(
            b,
            &FinancialSwapExecutionInputTrace {
                live: swap.clone(),
                quote_to_base: side,
                gross_input: principal.amount.value,
                minimum_output: principal.creation_id.value,
                effective_input,
                price: row.price.clone(),
            },
        );
        swaps.push([
            execution.capacity,
            execution.spent_input,
            execution.refund_input,
            execution.output,
            execution.scaled_minimum,
        ]);
    }
    let selected_swaps = sets
        .iter()
        .map(|set| {
            select_executions(b, set, rows, &swaps)
                .into_iter()
                .map(
                    |[capacity, spent_input, refund_input, output, scaled_minimum]| {
                        FinancialSwapExecutionTrace {
                            capacity,
                            spent_input,
                            refund_input,
                            output,
                            scaled_minimum,
                        }
                    },
                )
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let totals = sets
        .iter()
        .zip(prices)
        .zip(&selected_swaps)
        .map(|((set, price), swaps)| bind_financial_market_swap_totals(b, set, price, swaps))
        .collect::<Vec<_>>();
    sets.iter()
        .enumerate()
        .map(|(i, set)| {
            bind_financial_market_finish(b, set, &totals[i], &selected_swaps[i], &fees[i])
        })
        .collect()
}

pub fn bind_financial_global_market_effects(
    b: &mut FieldR1csBuilder,
    sets: &[FinancialSettlementSetTrace],
    prices: &[[LinExpr; 2]],
    effective: &[Vec<LinExpr>],
    fees: &[LinExpr],
    action_capacity: usize,
) -> Vec<FinancialMarketEffectsTrace> {
    let rows = bind_financial_effect_requests(b, sets, prices, effective, action_capacity);
    bind_financial_global_market_effects_from_requests(b, sets, prices, fees, &rows)
}
