// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact swap claims and permanent-pool accounting.

use super::super::{
    alloc_block, flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, extend, less_than, multiply, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_settlement_sets::FinancialSettlementSetTrace;
use super::financial_swap_execution::FinancialSwapExecutionTrace;
use super::validation::{is_zero, require_nonzero};
use noid_core::{hardware::flat_to_tower_u128, Block128};
use noid_tx::native_assets::{
    market::{
        clearing::MAX_SETTLEMENT_FEE_PER_REQUEST, queue::MAX_ROUND_REQUESTS,
        MARKET_REQUEST_FEE_CREDIT,
    },
    NativeKind,
};

pub struct FinancialMarketEffectsTrace {
    pub live: LinExpr,
    pub post_swap: [LinExpr; 3],
    pub pool: [LinExpr; 12],
    pub claims: Vec<[LinExpr; 12]>,
    pub capacities: Vec<LinExpr>,
}
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn constant(x: u128, n: usize) -> Vec<LinExpr> {
    (0..n)
        .map(|i| LinExpr::constant(flat_const((x >> i) & 1)))
        .collect()
}
fn eq_when(b: &mut FieldR1csBuilder, f: &LinExpr, x: &LinExpr, y: &LinExpr) {
    let bad = mul(b, f, &x.add(y));
    pin_zero(b, &bad);
}
fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}
fn pair_equal(b: &mut FieldR1csBuilder, x: &[LinExpr], y: &[LinExpr]) -> LinExpr {
    let a = is_zero(b, &x[0].add(&y[0]));
    let c = is_zero(b, &x[1].add(&y[1]));
    mul(b, &a, &c)
}
fn add_sum(b: &mut FieldR1csBuilder, sum: &mut Vec<LinExpr>, x: &LinExpr) {
    let value = bits(b, x, 64);
    *sum = checked_add(b, sum, &extend(&value, 68));
}
fn quantity(b: &mut FieldR1csBuilder, x: &[LinExpr], live: &LinExpr) -> LinExpr {
    let x = pack(x);
    bits(b, &x, 63);
    require_nonzero(b, &x, live);
    x
}

pub struct FinancialMarketSwapTotalsTrace {
    pub live: LinExpr,
    pub post_swap: [LinExpr; 3],
    pub total: LinExpr,
    pub locked: LinExpr,
    pub capacities: Vec<LinExpr>,
}

/// The complete global request relation binds each prepared execution to its
/// exact request, immutable pool context, clearing price and effective input.
pub fn bind_financial_market_swap_totals(
    b: &mut FieldR1csBuilder,
    set: &FinancialSettlementSetTrace,
    price: &[LinExpr; 2],
    swaps: &[FinancialSwapExecutionTrace],
) -> FinancialMarketSwapTotalsTrace {
    assert_eq!(set.requests.len(), MAX_ROUND_REQUESTS);
    assert_eq!(swaps.len(), MAX_ROUND_REQUESTS);
    let live = &set.family[0];
    let state = split_packed_input_value(b, &set.frozen[2]);
    let shares = split_packed_input_value(b, &set.frozen[3]);
    let before_base = mul(b, live, &state.amount.value);
    let before_quote = mul(b, live, &state.creation_id.value);
    let total = mul(b, live, &shares.amount.value);
    let locked = mul(b, live, &shares.creation_id.value);
    let before = [before_base.clone(), before_quote.clone(), total.clone()];
    let mut present = LinExpr::zero();
    let mut capacities = Vec::with_capacity(MAX_ROUND_REQUESTS);
    let mut spent: [Vec<LinExpr>; 2] = std::array::from_fn(|_| vec![LinExpr::zero(); 68]);
    let mut paid = spent.clone();
    for (r, execution) in set.requests.iter().zip(swaps) {
        let swap = mul(b, live, &r.kinds[0]);
        let next = mul(b, &swap, &present.add_const(F128::ONE));
        present = present.add(&next);
        let side = pair_equal(b, &r.fields[2..4], &set.definition[4..6]);
        let side = mul(b, &swap, &side);
        let base = swap.add(&side);
        let flow = [(base.clone(), side.clone()), (side, base)];
        for j in 0..2 {
            let x = mul(b, &flow[j].0, &execution.spent_input);
            add_sum(b, &mut spent[j], &x);
            let x = mul(b, &flow[j].1, &execution.output);
            add_sum(b, &mut paid[j], &x);
        }
        capacities.push(execution.capacity.clone());
    }
    let no_swaps = mul(b, live, &present.add_const(F128::ONE));
    eq_when(b, &no_swaps, &price[0], &before_quote);
    eq_when(b, &no_swaps, &price[1], &before_base);
    let mut post = [LinExpr::zero(), LinExpr::zero(), total.clone()];
    for j in 0..2 {
        let initial = bits(b, &before[j], 68);
        let incoming = checked_add(b, &initial, &spent[j]);
        let result = checked_subtract(b, &incoming, &paid[j]);
        post[j] = quantity(b, &result, live);
    }
    let old_base = bits(b, &before_base, 63);
    let old_quote = bits(b, &before_quote, 63);
    let post_base = bits(b, &post[0], 63);
    let post_quote = bits(b, &post[1], 63);
    let old_product = multiply(b, &old_base, &old_quote);
    let new_product = multiply(b, &post_base, &post_quote);
    let lower = less_than(b, &new_product, &old_product);
    pin_zero(b, &lower);

    FinancialMarketSwapTotalsTrace {
        live: live.clone(),
        post_swap: post,
        total,
        locked,
        capacities,
    }
}

/// All market requests are swaps against a permanent-liquidity pool.
/// The exact frozen set and shared executions supply every claim.
pub fn bind_financial_market_finish(
    b: &mut FieldR1csBuilder,
    set: &FinancialSettlementSetTrace,
    totals: &FinancialMarketSwapTotalsTrace,
    swaps: &[FinancialSwapExecutionTrace],
    fee: &LinExpr,
) -> FinancialMarketEffectsTrace {
    assert_eq!(swaps.len(), MAX_ROUND_REQUESTS);
    let live = &set.family[0];
    let count = mul(b, live, &set.count);
    let fee = mul(b, live, fee);
    pin_eq(b, &totals.total, &totals.locked);
    for request in &set.requests {
        let expected = mul(b, live, &request.live);
        let actual = mul(b, live, &request.kinds[0]);
        pin_eq(b, &actual, &expected);
    }
    let temporal = split_packed_input_value(b, &set.frozen[6]);
    let generation = mul(b, live, &temporal.amount.value);
    let generation = bits(b, &generation, 64);
    let mut one = vec![LinExpr::zero(); 64];
    one[0] = live.clone();
    let generation = checked_add(b, &generation, &one);
    let mut pool: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
    for lane in 0..2 {
        pool[lane] = mul(b, live, &set.frozen[lane]);
    }
    pool[2] = totals.post_swap[0].add(&totals.post_swap[1].scale(flat_const(1u128 << 64)));
    pool[3] = totals
        .total
        .add(&totals.total.scale(flat_const(1u128 << 64)));
    pool[6] = pack(&generation);
    pool[7] = mul(b, live, &set.base_is_noid).scale(flat_const(1u128 << 88));
    let n = tower(b, &count);
    let f = tower(b, &fee);
    let quotient = alloc_block(b, Block128(if n == 0 { 0 } else { f / n }));
    let remainder = alloc_block(b, Block128(if n == 0 { 0 } else { f % n }));
    let qb = bits(b, &quotient, 16);
    let rb = bits(b, &remainder, 5);
    let nb = bits(b, &count, 5);
    let valid = less_than(b, &rb, &nb);
    eq_when(b, live, &valid, &LinExpr::constant(F128::ONE));
    let product = multiply(b, &qb, &extend(&nb, 16));
    let combined = checked_add(b, &product, &extend(&rb, 32));
    pin_eq(b, &pack(&combined), &fee);
    let cap = multiply(
        b,
        &extend(&nb, 16),
        &constant(u128::from(MAX_SETTLEMENT_FEE_PER_REQUEST), 16),
    );
    let over = less_than(b, &cap, &combined);
    pin_zero(b, &over);
    let mut claims = Vec::with_capacity(MAX_ROUND_REQUESTS);
    for (i, (request, execution)) in set.requests.iter().zip(swaps).enumerate() {
        let member = mul(b, live, &request.live);
        let extra = less_than(b, &constant(i as u128, 5), &rb);
        let charge = checked_add(b, &extend(&qb, 64), &extend(&[extra], 64));
        let credit = checked_subtract(
            b,
            &constant(u128::from(MARKET_REQUEST_FEE_CREDIT), 64),
            &charge,
        );
        let mut claim: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        for lane in 0..2 {
            claim[lane] = mul(b, &member, &request.key[lane]);
            for start in [2, 4, 6, 8] {
                claim[start + lane] = mul(b, &member, &request.fields[start + lane]);
            }
        }
        claim[10] = execution
            .refund_input
            .add(&execution.output.scale(flat_const(1u128 << 64)));
        claim[11] = mul(b, &member, &pack(&credit));
        claims.push(claim);
    }
    FinancialMarketEffectsTrace {
        live: live.clone(),
        post_swap: totals.post_swap.clone(),
        pool,
        claims,
        capacities: totals.capacities.clone(),
    }
}

/// Exact output ordinals are pool first, followed by the complete funded-key
/// ordered claims. Carrier validation binds all selected fields to their roots.
pub fn bind_financial_market_effect_outputs(
    b: &mut FieldR1csBuilder,
    set: &FinancialSettlementSetTrace,
    effects: &FinancialMarketEffectsTrace,
    actions: &[FinancialActionTrace],
) {
    let mut found = vec![LinExpr::zero(); MAX_ROUND_REQUESTS + 1];
    for a in actions {
        let same = is_zero(b, &a.header_page.add(&set.header_page));
        let selected = mul(b, &same, &a.live);
        let selected = mul(b, &selected, &a.is_output);
        let selected = mul(b, &selected, &effects.live);
        eq_when(b, &selected, &a.native, &LinExpr::constant(F128::ONE));
        let mut permitted = LinExpr::zero();
        for i in 0..=MAX_ROUND_REQUESTS {
            let ordinal = is_zero(b, &a.ordinal.add_const(flat_const(i as u128)));
            let hit = mul(b, &selected, &ordinal);
            let member = if i == 0 {
                effects.live.clone()
            } else {
                let r = &set.requests[i - 1];
                mul(b, &effects.live, &r.live)
            };
            eq_when(b, &hit, &member, &LinExpr::constant(F128::ONE));
            let repeated = mul(b, &found[i], &hit);
            pin_zero(b, &repeated);
            found[i] = found[i].add(&hit);
            permitted = permitted.add(&hit);
            let fields = if i == 0 {
                &effects.pool
            } else {
                &effects.claims[i - 1]
            };
            for j in 0..12 {
                eq_when(b, &hit, &a.opening.fields[j], &fields[j]);
            }
            let expected = if i == 0 {
                a.opening
                    .commitment
                    .selector(NativeKind::MarketPool)
                    .clone()
            } else {
                a.opening
                    .commitment
                    .selector(NativeKind::MarketClaim)
                    .clone()
            };
            eq_when(b, &hit, &expected, &LinExpr::constant(F128::ONE));
        }
        pin_eq(b, &permitted, &selected);
    }
    pin_eq(b, &found[0], &effects.live);
    for i in 0..MAX_ROUND_REQUESTS {
        let expected = mul(b, &effects.live, &set.requests[i].live);
        pin_eq(b, &found[i + 1], &expected);
    }
}
