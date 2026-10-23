// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! One bounded execution table shared by every selected native market.

use super::super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::super::arithmetic::{bits, checked_add, less_than, multiply, pack};
use super::super::validation::{is_zero, nonzero_pair, require_nonzero};
use super::group::{price, SequentialPolicyTrace};
use super::launch::{
    bind_sequential_trade_step_with_curve, CheckedCurveState, SequentialTradeInputTrace,
    SequentialTradeStepTrace,
};
use super::{boolean, digest_bytes_bits, hash_fields, number, select};
use noid_poseidon2b::native::DomainTag;
use noid_tx::native_assets::market::sequential::MAX_SEQUENTIAL_TRADES;

#[derive(Clone)]
pub struct TradeMarketTrace {
    pub live: LinExpr,
    pub asset: [LinExpr; 2],
    pub curve: LinExpr,
    pub supply: LinExpr,
    pub base_reserve: LinExpr,
    pub quote_reserve: LinExpr,
}

pub struct MarketPolicyTrace {
    pub market_index: LinExpr,
    pub policy: SequentialPolicyTrace,
}

pub struct GlobalTradeStepTrace {
    pub live: LinExpr,
    pub market_index: LinExpr,
    pub policy_index: LinExpr,
    pub market_end: LinExpr,
    pub quote: SequentialTradeStepTrace,
}

pub struct FinalTradeMarketTrace {
    pub curve: LinExpr,
    pub base_reserve: LinExpr,
    pub quote_reserve: LinExpr,
}

pub struct GlobalTradeExecutionTrace {
    pub priorities: Vec<[LinExpr; 2]>,
    pub steps: Vec<GlobalTradeStepTrace>,
    pub markets: Vec<FinalTradeMarketTrace>,
}

fn increment(b: &mut FieldR1csBuilder, count: &[LinExpr], flag: &LinExpr) -> Vec<LinExpr> {
    let mut delta = vec![LinExpr::zero(); count.len()];
    delta[0] = flag.clone();
    checked_add(b, count, &delta)
}

fn lookup_market(
    b: &mut FieldR1csBuilder,
    live: &LinExpr,
    index: &LinExpr,
    markets: &[TradeMarketTrace],
) -> (TradeMarketTrace, Vec<LinExpr>) {
    let mut result = TradeMarketTrace {
        live: LinExpr::zero(),
        asset: [LinExpr::zero(), LinExpr::zero()],
        curve: LinExpr::zero(),
        supply: LinExpr::zero(),
        base_reserve: LinExpr::zero(),
        quote_reserve: LinExpr::zero(),
    };
    let mut selectors = Vec::with_capacity(markets.len());
    for (position, market) in markets.iter().enumerate() {
        let matches = is_zero(b, &index.add(&number(position as u128)));
        let selected = mul(b, live, &matches);
        let selected = mul(b, &selected, &market.live);
        result.live = result.live.add(&selected);
        for lane in 0..2 {
            result.asset[lane] = result.asset[lane].add(&mul(b, &selected, &market.asset[lane]));
        }
        result.curve = result.curve.add(&mul(b, &selected, &market.curve));
        result.supply = result.supply.add(&mul(b, &selected, &market.supply));
        result.base_reserve = result
            .base_reserve
            .add(&mul(b, &selected, &market.base_reserve));
        result.quote_reserve = result
            .quote_reserve
            .add(&mul(b, &selected, &market.quote_reserve));
        selectors.push(selected);
    }
    pin_eq(b, &result.live, live);
    (result, selectors)
}

/// Policies form a strict (market ordinal, funded priority) live prefix. Their
/// complete source set and anchors come from the canonical funding relation.
/// One quote relation is instantiated per global policy position, with market
/// State reset only when the preceding market has consumed all its policies.
pub fn bind_global_trade_execution(
    b: &mut FieldR1csBuilder,
    parent_id: &[LinExpr; 2],
    markets: &[TradeMarketTrace],
    policies: &[MarketPolicyTrace],
    execution_order: &[LinExpr],
) -> GlobalTradeExecutionTrace {
    let capacity = policies.len();
    assert!((1..=MAX_SEQUENTIAL_TRADES).contains(&capacity));
    assert!(!markets.is_empty() && markets.len() <= capacity);
    assert_eq!(capacity, execution_order.len());
    let market_width = markets.len().next_power_of_two().trailing_zeros().max(1) as usize;
    let policy_width = capacity.next_power_of_two().trailing_zeros().max(1) as usize;
    let count_width = (capacity + 1).next_power_of_two().trailing_zeros() as usize;
    let mut previous_live = LinExpr::constant(F128::ONE);
    for market in markets {
        boolean(b, &market.live);
        boolean(b, &market.curve);
        let gap = mul(b, &market.live, &previous_live.add_const(F128::ONE));
        pin_zero(b, &gap);
        previous_live = market.live.clone();
        for field in [
            &market.curve,
            &market.supply,
            &market.base_reserve,
            &market.quote_reserve,
        ]
        .into_iter()
        .chain(&market.asset)
        {
            let padding = mul(b, &market.live.add_const(F128::ONE), field);
            pin_zero(b, &padding);
        }
        let unused = mul(b, &market.curve.add_const(F128::ONE), &market.supply);
        pin_zero(b, &unused);
        nonzero_pair(b, &market.asset, &market.live);
        bits(b, &market.supply, 54);
        bits(b, &market.base_reserve, 63);
        bits(b, &market.quote_reserve, 63);
    }
    let mut market_counts = vec![vec![LinExpr::zero(); count_width]; markets.len()];
    let mut previous_live = LinExpr::constant(F128::ONE);
    let mut previous_key: Option<Vec<LinExpr>> = None;
    let mut priorities = Vec::with_capacity(capacity);
    for item in policies {
        let row = &item.policy;
        boolean(b, &row.live);
        boolean(b, &row.sell);
        let gap = mul(b, &row.live, &previous_live.add_const(F128::ONE));
        pin_zero(b, &gap);
        previous_live = row.live.clone();
        for field in [
            &item.market_index,
            &row.sell,
            &row.gross_input,
            &row.minimum_output,
            &row.anchor_creation_id,
            &row.anchor_slot,
        ] {
            let padding = mul(b, &row.live.add_const(F128::ONE), field);
            pin_zero(b, &padding);
        }
        let market_index = bits(b, &item.market_index, market_width);
        bits(b, &row.gross_input, 63);
        bits(b, &row.minimum_output, 63);
        require_nonzero(b, &row.gross_input, &row.live);
        require_nonzero(b, &row.minimum_output, &row.live);
        let creation = bits(b, &row.anchor_creation_id, 64);
        let native = mul(b, &creation[62], &creation[63].add_const(F128::ONE));
        pin_eq(b, &native, &row.sell);
        require_nonzero(b, &row.anchor_creation_id, &row.live);
        let slot = bits(b, &row.anchor_slot, 32);
        let (market, selected) = lookup_market(b, &row.live, &item.market_index, markets);
        for (count, selected) in market_counts.iter_mut().zip(selected) {
            *count = increment(b, count, &selected);
        }
        nonzero_pair(b, parent_id, &row.live);
        let key = hash_fields(
            b,
            DomainTag::new(b"TRORD_21"),
            &[
                parent_id[0].clone(),
                parent_id[1].clone(),
                market.asset[0].clone(),
                market.asset[1].clone(),
                row.anchor_creation_id.clone(),
                row.anchor_slot.clone(),
            ],
        );
        let key = key.map(|lane| mul(b, &row.live, &lane));
        let mut ordered = slot;
        ordered.extend(creation);
        ordered.extend(digest_bytes_bits(b, &key));
        ordered.extend(market_index);
        if let Some(previous) = previous_key {
            let ordered = less_than(b, &previous, &ordered);
            let invalid = mul(b, &row.live, &ordered.add_const(F128::ONE));
            pin_zero(b, &invalid);
        }
        previous_key = Some(ordered);
        priorities.push(key);
    }
    for (market, count) in markets.iter().zip(&market_counts) {
        require_nonzero(b, &pack(count), &market.live);
    }
    let mut consumed = vec![LinExpr::zero(); capacity];
    let mut end_counts = vec![vec![LinExpr::zero(); count_width]; markets.len()];
    let mut final_markets = markets
        .iter()
        .map(|_| FinalTradeMarketTrace {
            curve: LinExpr::zero(),
            base_reserve: LinExpr::zero(),
            quote_reserve: LinExpr::zero(),
        })
        .collect::<Vec<_>>();
    let mut carried_curve = LinExpr::zero();
    let mut carried_base = LinExpr::zero();
    let mut carried_quote = LinExpr::zero();
    let mut carried_curve_state = CheckedCurveState::zero();
    let mut previous_market = LinExpr::zero();
    let mut previous_step_live = LinExpr::zero();
    let mut steps = Vec::with_capacity(capacity);
    let initial_prices = markets
        .iter()
        .map(|market| {
            let price = price(
                b,
                &market.live,
                &market.curve,
                &market.supply,
                &market.base_reserve,
                &market.quote_reserve,
            );
            price.map(|bits| LinExpr::from_wire(b.materialize(&pack(&bits))))
        })
        .collect::<Vec<_>>();
    let initial_curves = markets
        .iter()
        .map(|market| {
            CheckedCurveState::initial(
                b,
                &market.live,
                &market.curve,
                &market.supply,
                &market.base_reserve,
                &market.quote_reserve,
            )
        })
        .collect::<Vec<_>>();
    for (step_index, chosen_index) in execution_order.iter().enumerate() {
        let live = &policies[step_index].policy.live;
        bits(b, chosen_index, policy_width);
        let padding = mul(b, &live.add_const(F128::ONE), chosen_index);
        pin_zero(b, &padding);
        let mut first_remaining = LinExpr::zero();
        let mut market_index = LinExpr::zero();
        for (item, seen) in policies.iter().zip(&consumed) {
            let available = mul(b, &item.policy.live, &seen.add_const(F128::ONE));
            let first = mul(b, &available, &first_remaining.add_const(F128::ONE));
            first_remaining = first_remaining.add(&first);
            market_index = market_index.add(&mul(b, &first, &item.market_index));
        }
        pin_eq(b, &first_remaining, live);
        let (market, market_selectors) = lookup_market(b, live, &market_index, markets);
        let same_market = is_zero(b, &market_index.add(&previous_market));
        let continued = mul(b, &previous_step_live, &same_market);
        let continued = mul(b, live, &continued);
        let curve = select(b, &continued, &market.curve, &carried_curve);
        let base = select(b, &continued, &market.base_reserve, &carried_base);
        let quote = select(b, &continued, &market.quote_reserve, &carried_quote);
        let initial_curve = market_selectors
            .iter()
            .zip(&initial_curves)
            .fold(CheckedCurveState::zero(), |state, (selected, initial)| {
                CheckedCurveState::select(b, selected, &state, initial)
            });
        let curve_state =
            CheckedCurveState::select(b, &continued, &initial_curve, &carried_curve_state);
        let initial: [Vec<LinExpr>; 2] = std::array::from_fn(|lane| {
            let value = market_selectors
                .iter()
                .zip(&initial_prices)
                .fold(LinExpr::zero(), |sum, (selected, price)| {
                    sum.add(&mul(b, selected, &price[lane]))
                });
            bits(b, &value, 64)
        });
        let current = price(b, live, &curve, &market.supply, &base, &quote);
        let left = multiply(b, &current[0], &initial[1]);
        let right = multiply(b, &initial[0], &current[1]);
        let preferred_sell = less_than(b, &right, &left);
        let mut first_preferred = Vec::with_capacity(capacity);
        let mut first_any = Vec::with_capacity(capacity);
        let mut found_preferred = LinExpr::zero();
        let mut found_any = LinExpr::zero();
        for (item, seen) in policies.iter().zip(&consumed) {
            let same = is_zero(b, &item.market_index.add(&market_index));
            let available = mul(b, &item.policy.live, &seen.add_const(F128::ONE));
            let available = mul(b, &available, &same);
            let preferred = mul(
                b,
                &available,
                &item.policy.sell.add(&preferred_sell).add_const(F128::ONE),
            );
            let preferred = mul(b, &preferred, &found_preferred.add_const(F128::ONE));
            let any = mul(b, &available, &found_any.add_const(F128::ONE));
            found_preferred = found_preferred.add(&preferred);
            found_any = found_any.add(&any);
            first_preferred.push(preferred);
            first_any.push(any);
        }
        let mut sell = LinExpr::zero();
        let mut gross = LinExpr::zero();
        let mut minimum = LinExpr::zero();
        let mut chosen_count = LinExpr::zero();
        for (index, item) in policies.iter().enumerate() {
            let matching = is_zero(b, &chosen_index.add(&number(index as u128)));
            let selected = mul(b, live, &matching);
            let expected = select(
                b,
                &found_preferred,
                &first_any[index],
                &first_preferred[index],
            );
            pin_eq(b, &selected, &expected);
            let repeated = mul(b, &selected, &consumed[index]);
            pin_zero(b, &repeated);
            consumed[index] = consumed[index].add(&selected);
            chosen_count = chosen_count.add(&selected);
            sell = sell.add(&mul(b, &selected, &item.policy.sell));
            gross = gross.add(&mul(b, &selected, &item.policy.gross_input));
            minimum = minimum.add(&mul(b, &selected, &item.policy.minimum_output));
        }
        pin_eq(b, &chosen_count, live);
        let (result, successor_curve_state) = bind_sequential_trade_step_with_curve(
            b,
            &SequentialTradeInputTrace {
                live: live.clone(),
                curve,
                sell,
                supply: market.supply,
                base_reserve: base,
                quote_reserve: quote,
                gross_input: gross,
                minimum_output: minimum,
            },
            &curve_state,
        );
        let mut remains = LinExpr::zero();
        for (item, seen) in policies.iter().zip(&consumed) {
            let same = is_zero(b, &item.market_index.add(&market_index));
            let available = mul(b, &item.policy.live, &seen.add_const(F128::ONE));
            let available = mul(b, &available, &same);
            let first = mul(b, &available, &remains.add_const(F128::ONE));
            remains = remains.add(&first);
        }
        let market_end = mul(b, live, &remains.add_const(F128::ONE));
        for ((final_market, end_count), selected) in final_markets
            .iter_mut()
            .zip(&mut end_counts)
            .zip(market_selectors)
        {
            let end = mul(b, &market_end, &selected);
            *end_count = increment(b, end_count, &end);
            final_market.curve = final_market.curve.add(&mul(b, &end, &result.after_curve));
            final_market.base_reserve =
                final_market
                    .base_reserve
                    .add(&mul(b, &end, &result.after_base));
            final_market.quote_reserve =
                final_market
                    .quote_reserve
                    .add(&mul(b, &end, &result.after_quote));
        }
        carried_curve = result.after_curve.clone();
        carried_base = result.after_base.clone();
        carried_quote = result.after_quote.clone();
        carried_curve_state = successor_curve_state;
        previous_market = market_index.clone();
        previous_step_live = live.clone();
        steps.push(GlobalTradeStepTrace {
            live: live.clone(),
            market_index,
            policy_index: chosen_index.clone(),
            market_end,
            quote: result,
        });
    }
    for (item, consumed) in policies.iter().zip(consumed) {
        pin_eq(b, &item.policy.live, &consumed);
    }
    for (market, count) in markets.iter().zip(end_counts) {
        pin_eq(b, &pack(&count), &market.live);
    }
    GlobalTradeExecutionTrace {
        priorities,
        steps,
        markets: final_markets,
    }
}
