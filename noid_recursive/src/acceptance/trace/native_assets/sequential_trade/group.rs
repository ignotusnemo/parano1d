// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete funded-priority order and sequential market State carries.

use super::super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::super::arithmetic::{bits, checked_add, checked_subtract, less_than, multiply, pack};
use super::super::validation::{is_zero, nonzero_pair, require_nonzero};
use super::launch::{
    bind_sequential_trade_step, scaled, SequentialTradeInputTrace, SequentialTradeStepTrace,
};
use super::{boolean, digest_bytes_bits, hash_fields, number, select};
use noid_poseidon2b::native::DomainTag;
use noid_tx::native_assets::market::sequential::MAX_SEQUENTIAL_TRADES;

pub struct SequentialPolicyTrace {
    pub live: LinExpr,
    pub sell: LinExpr,
    pub gross_input: LinExpr,
    pub minimum_output: LinExpr,
    pub anchor_creation_id: LinExpr,
    pub anchor_slot: LinExpr,
}

pub struct SequentialGroupInputTrace<'a> {
    pub live: LinExpr,
    pub parent_id: [LinExpr; 2],
    pub asset: [LinExpr; 2],
    pub curve: LinExpr,
    pub supply: LinExpr,
    pub base_reserve: LinExpr,
    pub quote_reserve: LinExpr,
    pub policies: &'a [SequentialPolicyTrace],
    pub execution_order: &'a [LinExpr],
}

pub struct SequentialGroupStepTrace {
    pub live: LinExpr,
    pub policy_index: LinExpr,
    pub sell: LinExpr,
    pub gross_input: LinExpr,
    pub minimum_output: LinExpr,
    pub quote: SequentialTradeStepTrace,
}

pub struct SequentialGroupTrace {
    pub count: LinExpr,
    pub priorities: Vec<[LinExpr; 2]>,
    pub steps: Vec<SequentialGroupStepTrace>,
    pub after_curve: LinExpr,
    pub after_base: LinExpr,
    pub after_quote: LinExpr,
}

pub(super) fn price(
    b: &mut FieldR1csBuilder,
    live: &LinExpr,
    curve: &LinExpr,
    supply: &LinExpr,
    base: &LinExpr,
    quote: &LinExpr,
) -> [Vec<LinExpr>; 2] {
    let s = mul(b, curve, supply);
    let inventory = mul(b, curve, quote);
    let s_bits = bits(b, &s, 54);
    let inventory_bits = bits(b, &inventory, 54);
    let sold = checked_subtract(b, &s_bits, &inventory_bits);
    let three_s = scaled(b, &s_bits, 3, 64);
    let ten_sold = scaled(b, &sold, 10, 64);
    let curve_numerator = pack(&checked_add(b, &three_s, &ten_sold));
    let curve_denominator = pack(&scaled(b, &s_bits, 900, 64));
    let market = live.add(curve);
    let numerator = curve_numerator.add(&mul(b, &market, base));
    let denominator = curve_denominator.add(&mul(b, &market, quote));
    require_nonzero(b, &numerator, live);
    require_nonzero(b, &denominator, live);
    [bits(b, &numerator, 64), bits(b, &denominator, 64)]
}

/// Rows are the exact selected policies in strict funded-priority order. The
/// enclosing relation binds each row to its Owner statement and largest exact
/// principal input. Each supplied execution index is checked against the full
/// remaining set and the current price, then used once for the State carry.
pub fn bind_sequential_group(
    b: &mut FieldR1csBuilder,
    input: &SequentialGroupInputTrace<'_>,
) -> SequentialGroupTrace {
    let capacity = input.policies.len();
    let count_width = (capacity + 1).next_power_of_two().trailing_zeros() as usize;
    assert!((1..=MAX_SEQUENTIAL_TRADES).contains(&capacity));
    assert_eq!(capacity, input.execution_order.len());
    boolean(b, &input.live);
    boolean(b, &input.curve);
    nonzero_pair(b, &input.parent_id, &input.live);
    nonzero_pair(b, &input.asset, &input.live);
    let mut previous_live = input.live.clone();
    let mut previous_key: Option<Vec<LinExpr>> = None;
    let mut count = vec![LinExpr::zero(); count_width];
    let mut priorities = Vec::with_capacity(capacity);
    for row in input.policies {
        boolean(b, &row.live);
        boolean(b, &row.sell);
        let hole = mul(b, &row.live, &previous_live.add_const(F128::ONE));
        pin_zero(b, &hole);
        previous_live = row.live.clone();
        for field in [
            &row.sell,
            &row.gross_input,
            &row.minimum_output,
            &row.anchor_creation_id,
            &row.anchor_slot,
        ] {
            let padding = mul(b, &row.live.add_const(F128::ONE), field);
            pin_zero(b, &padding);
        }
        bits(b, &row.gross_input, 63);
        bits(b, &row.minimum_output, 63);
        require_nonzero(b, &row.gross_input, &row.live);
        require_nonzero(b, &row.minimum_output, &row.live);
        let creation = bits(b, &row.anchor_creation_id, 64);
        let native_anchor = mul(b, &creation[62], &creation[63].add_const(F128::ONE));
        pin_eq(b, &native_anchor, &row.sell);
        require_nonzero(b, &row.anchor_creation_id, &row.live);
        let slot = bits(b, &row.anchor_slot, 32);
        let fields = [
            input.parent_id[0].clone(),
            input.parent_id[1].clone(),
            input.asset[0].clone(),
            input.asset[1].clone(),
            row.anchor_creation_id.clone(),
            row.anchor_slot.clone(),
        ];
        let key = hash_fields(b, DomainTag::new(b"TRORD_21"), &fields);
        let key = key.map(|lane| mul(b, &row.live, &lane));
        let mut ordered = slot;
        ordered.extend(creation);
        ordered.extend(digest_bytes_bits(b, &key));
        if let Some(previous) = previous_key {
            let strict = less_than(b, &previous, &ordered);
            let invalid = mul(b, &row.live, &strict.add_const(F128::ONE));
            pin_zero(b, &invalid);
        }
        previous_key = Some(ordered);
        priorities.push(key);
        let mut increment = vec![LinExpr::zero(); count_width];
        increment[0] = row.live.clone();
        count = checked_add(b, &count, &increment);
    }
    let count = pack(&count);
    require_nonzero(b, &count, &input.live);
    let mut curve = mul(b, &input.live, &input.curve);
    let supply = mul(b, &curve, &input.supply);
    let mut base = mul(b, &input.live, &input.base_reserve);
    let mut quote = mul(b, &input.live, &input.quote_reserve);
    let initial_price = price(b, &input.live, &curve, &supply, &base, &quote);
    let mut consumed = vec![LinExpr::zero(); capacity];
    let mut steps = Vec::with_capacity(capacity);
    let index_width = capacity.next_power_of_two().trailing_zeros().max(1) as usize;
    for (step_index, index) in input.execution_order.iter().enumerate() {
        let live = &input.policies[step_index].live;
        bits(b, index, index_width);
        let padding = mul(b, &live.add_const(F128::ONE), index);
        pin_zero(b, &padding);
        let current_price = price(b, &input.live, &curve, &supply, &base, &quote);
        let left = multiply(b, &current_price[0], &initial_price[1]);
        let right = multiply(b, &initial_price[0], &current_price[1]);
        let preferred_sell = less_than(b, &right, &left);
        let mut first_preferred = Vec::with_capacity(capacity);
        let mut first_any = Vec::with_capacity(capacity);
        let mut found_preferred = LinExpr::zero();
        let mut found_any = LinExpr::zero();
        for (row, consumed) in input.policies.iter().zip(&consumed) {
            let available = mul(b, &row.live, &consumed.add_const(F128::ONE));
            let matches_side = row.sell.add(&preferred_sell).add_const(F128::ONE);
            let preferred = mul(b, &available, &matches_side);
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
        let mut selected_count = LinExpr::zero();
        for (policy_index, row) in input.policies.iter().enumerate() {
            let matches_index = is_zero(b, &index.add(&number(policy_index as u128)));
            let selected = mul(b, live, &matches_index);
            let expected = select(
                b,
                &found_preferred,
                &first_any[policy_index],
                &first_preferred[policy_index],
            );
            pin_eq(b, &selected, &expected);
            let repeated = mul(b, &selected, &consumed[policy_index]);
            pin_zero(b, &repeated);
            consumed[policy_index] = consumed[policy_index].add(&selected);
            selected_count = selected_count.add(&selected);
            sell = sell.add(&mul(b, &selected, &row.sell));
            gross = gross.add(&mul(b, &selected, &row.gross_input));
            minimum = minimum.add(&mul(b, &selected, &row.minimum_output));
        }
        pin_eq(b, &selected_count, live);
        let quote_input = SequentialTradeInputTrace {
            live: live.clone(),
            curve: curve.clone(),
            sell: sell.clone(),
            supply: supply.clone(),
            base_reserve: base.clone(),
            quote_reserve: quote.clone(),
            gross_input: gross.clone(),
            minimum_output: minimum.clone(),
        };
        let result = bind_sequential_trade_step(b, &quote_input);
        curve = select(b, live, &curve, &result.after_curve);
        base = select(b, live, &base, &result.after_base);
        quote = select(b, live, &quote, &result.after_quote);
        steps.push(SequentialGroupStepTrace {
            live: live.clone(),
            policy_index: index.clone(),
            sell,
            gross_input: gross,
            minimum_output: minimum,
            quote: result,
        });
    }
    for (row, consumed) in input.policies.iter().zip(consumed) {
        pin_eq(b, &row.live, &consumed);
    }
    SequentialGroupTrace {
        count,
        priorities,
        steps,
        after_curve: curve,
        after_base: base,
        after_quote: quote,
    }
}
