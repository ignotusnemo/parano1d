// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact first-input market boundaries and final raw control actions.

use super::super::super::super::{pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::super::super::arithmetic::{checked_subtract, extend, multiply};
use super::super::super::financial_controls::bind_financial_control_arithmetic;
use super::super::global_execution::{FinalTradeMarketTrace, TradeMarketTrace};
use super::super::{bind_same, witness};
use super::*;

pub(super) struct MarketRow {
    pub market: TradeMarketTrace,
    pub header_page: LinExpr,
    pub input_count: LinExpr,
    pub output_count: LinExpr,
    pub last_output: LinExpr,
    pub fee: LinExpr,
    pub commitment: [LinExpr; 2],
    pub source_root: [LinExpr; 2],
    pub source_slot: LinExpr,
    pub source_creation_id: LinExpr,
    pub definition_root: [LinExpr; 2],
    pub definition_fields: [LinExpr; 8],
    pub next_generation: LinExpr,
    pub shares: LinExpr,
}

fn unique(b: &mut FieldR1csBuilder, seen: &LinExpr, next: &LinExpr) -> LinExpr {
    let overlap = mul(b, seen, next);
    pin_zero(b, &overlap);
    seen.add(next)
}

pub(super) fn extract(
    b: &mut FieldR1csBuilder,
    capacity: usize,
    headers: &[FinancialNativeHeaderTrace],
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    context: &TradeKernelContext<'_>,
) -> Vec<MarketRow> {
    assert_eq!(actions.len(), definitions.actions.len());
    let mut rows = headers
        .iter()
        .map(|h| {
            let trade = is_zero(b, &h.header.operation.add(&number(80)));
            let live = mul(b, &h.header.live, &trade);
            vec![
                live.clone(),
                mul(b, &live, &h.header.header_page),
                mul(b, &live, &h.header.input_count),
                mul(b, &live, &h.header.output_count),
                mul(b, &live, &h.header.fee),
                mul(b, &live, &h.metadata.trade_root[0]),
                mul(b, &live, &h.metadata.trade_root[1]),
            ]
        })
        .collect::<Vec<_>>();
    rows.resize_with(rows.len().max(capacity).next_power_of_two(), || {
        vec![LinExpr::zero(); 7]
    });
    let rows = route_sorted(b, rows, 7, |b, row| vec![value(b, &row[1])]);
    for row in &rows[capacity..] {
        pin_zero(b, &row[0]);
    }
    let mut previous_live = LinExpr::constant(F128::ONE);
    let mut previous_page = vec![LinExpr::zero(); 16];
    rows.into_iter()
        .take(capacity)
        .enumerate()
        .map(|(index, row)| {
            let live = row[0].clone();
            let page = bits(b, &row[1], 16);
            let hole = mul(b, &live, &previous_live.add_const(F128::ONE));
            pin_zero(b, &hole);
            if index != 0 {
                let strict = less_than(b, &previous_page, &page);
                let wrong = mul(b, &live, &strict.add_const(F128::ONE));
                pin_zero(b, &wrong);
            }
            previous_page = page;
            previous_live = live.clone();
            let mut seen = LinExpr::zero();
            let mut pool = LinExpr::zero();
            let mut curve = LinExpr::zero();
            let mut source_root: [LinExpr; 2] = std::array::from_fn(|_| LinExpr::zero());
            let mut source_slot = LinExpr::zero();
            let mut source_creation_id = LinExpr::zero();
            let mut definition_root = source_root.clone();
            let mut definition_fields: [LinExpr; 8] = std::array::from_fn(|_| LinExpr::zero());
            let mut fields: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
            for (action, definition) in actions.iter().zip(&definitions.actions) {
                let same = is_zero(b, &action.header_page.add(&row[1]));
                let selected = mul(b, &same, &live);
                let selected = mul(b, &selected, &action.live);
                let selected = mul(b, &selected, &action.is_output.add_const(F128::ONE));
                let first = is_zero(b, &action.ordinal);
                let selected = mul(b, &selected, &first);
                seen = unique(b, &seen, &selected);
                let native = mul(b, &selected, &action.native);
                pin_eq(b, &native, &selected);
                let p = mul(
                    b,
                    &selected,
                    action.opening.commitment.selector(NativeKind::MarketPool),
                );
                let c = mul(
                    b,
                    &selected,
                    action.opening.commitment.selector(NativeKind::LaunchState),
                );
                pin_eq(b, &p.add(&c), &selected);
                let dp = mul(b, &selected, &definition.market);
                let dc = mul(b, &selected, &definition.launch);
                pin_eq(b, &dp, &p);
                pin_eq(b, &dc, &c);
                pool = pool.add(&p);
                curve = curve.add(&c);
                let packed = split_packed_input_value(b, &action.packed_value);
                source_slot = source_slot.add(&mul(b, &selected, &action.slot));
                source_creation_id =
                    source_creation_id.add(&mul(b, &selected, &packed.creation_id.value));
                for lane in 0..2 {
                    source_root[lane] =
                        source_root[lane].add(&mul(b, &selected, &action.root[lane]));
                    definition_root[lane] =
                        definition_root[lane].add(&mul(b, &selected, &definition.root[lane]));
                }
                for i in 0..8 {
                    definition_fields[i] =
                        definition_fields[i].add(&mul(b, &selected, &definition.fields[i]));
                }
                for i in 0..12 {
                    fields[i] = fields[i].add(&mul(b, &selected, &action.opening.fields[i]));
                }
            }
            pin_eq(b, &seen, &live);
            for lane in 0..2 {
                pin_eq(b, &fields[lane], &definition_root[lane]);
                pin_zero(b, &fields[4 + lane]);
            }
            let cid = bits(b, &source_creation_id, 64);
            pin_eq(b, &cid[62], &live);
            pin_zero(b, &cid[63]);
            let counter = bits(b, context.parent_alloc_counter, 62);
            let future = less_than(b, &counter, &cid[..62]);
            pin_zero(b, &future);
            let source_state = split_packed_input_value(b, &fields[2]);
            let base = select(
                b,
                &curve,
                &source_state.amount.value,
                &source_state.creation_id.value,
            );
            let quote = select(
                b,
                &curve,
                &source_state.creation_id.value,
                &source_state.amount.value,
            );
            let supply_packed = mul(b, &curve, &definition_fields[4]);
            let supply = split_packed_input_value(b, &supply_packed);
            let asset = std::array::from_fn(|lane| {
                mul(b, &curve, &definition_fields[lane]).add(&mul(
                    b,
                    &pool,
                    &definition_fields[4 + lane],
                ))
            });
            let generation = mul(b, &curve, &fields[3]).add(&mul(b, &pool, &fields[6]));
            let generation = split_packed_input_value(b, &generation);
            pin_zero(b, &generation.creation_id.value);
            let mut one = vec![LinExpr::zero(); 64];
            one[0] = live.clone();
            let generation_bits = generation.amount.bits.map(LinExpr::from_wire);
            let next_generation = pack(&checked_add(b, &generation_bits, &one));
            let pool_shares = mul(b, &pool, &fields[3]);
            let shares = split_packed_input_value(b, &pool_shares);
            pin_eq(b, &shares.amount.value, &shares.creation_id.value);
            let shares_bits = bits(b, &shares.amount.value, 63);
            let minimum = bits(
                b,
                &number(noid_tx::native_assets::market::MARKET_MIN_LOCKED_SHARES as u128),
                63,
            );
            let too_small = less_than(b, &shares_bits, &minimum);
            let bad = mul(b, &pool, &too_small);
            pin_zero(b, &bad);
            let curve_tail = mul(b, &curve, &fields[6]);
            pin_zero(b, &curve_tail);
            pin_eq(b, &fields[7], &pool.scale(flat_const(1 << 88)));
            bind_financial_control_arithmetic(b, &pool, &curve, &fields, &supply_packed);
            let output = bits(b, &row[3], 11);
            let mut one = vec![LinExpr::zero(); 11];
            one[0] = live.clone();
            let last_output = pack(&checked_subtract(b, &output, &one));
            MarketRow {
                market: TradeMarketTrace {
                    live,
                    asset,
                    curve,
                    supply: supply.amount.value,
                    base_reserve: base,
                    quote_reserve: quote,
                },
                header_page: row[1].clone(),
                input_count: row[2].clone(),
                output_count: row[3].clone(),
                last_output,
                fee: row[4].clone(),
                commitment: [row[5].clone(), row[6].clone()],
                source_root,
                source_slot,
                source_creation_id,
                definition_root,
                definition_fields,
                next_generation,
                shares: shares.amount.value,
            }
        })
        .collect()
}

/// Bootstrap shares are the exact integer square root of the fixed graduation
/// reserves. All of those shares remain permanently locked in the pool.
fn bootstrap_shares(b: &mut FieldR1csBuilder, graduated: &LinExpr, supply: &LinExpr) -> LinExpr {
    let supply = mul(b, graduated, supply);
    let s = bits(b, &supply, 54);
    let sv = value(b, &supply);
    let cash = witness(b, sv / 250);
    let inventory = witness(b, sv / 5 * 2);
    let cash_bits = bits(b, &cash, 63);
    let inventory_bits = bits(b, &inventory, 54);
    let cash_factor = bits(b, &number(250), 63);
    let cash_product = multiply(b, &cash_bits, &cash_factor);
    bind_same(b, &cash_product, &extend(&s, 126));
    let five = bits(b, &number(5), 54);
    let two = bits(b, &number(2), 54);
    let left = multiply(b, &inventory_bits, &five);
    let right = multiply(b, &s, &two);
    bind_same(b, &left, &right);
    let product = multiply(b, &cash_bits, &extend(&inventory_bits, 63));
    let shares = witness(b, ((sv / 250) * (sv / 5 * 2)).isqrt());
    let shares_bits = bits(b, &shares, 63);
    let square = multiply(b, &shares_bits, &shares_bits);
    let product = extend(&product, 126);
    checked_subtract(b, &product, &square);
    let mut one = vec![LinExpr::zero(); 63];
    one[0] = LinExpr::constant(F128::ONE);
    let next = checked_add(b, &shares_bits, &one);
    let next_square = multiply(b, &next, &next);
    let upper = less_than(b, &product, &next_square);
    pin_eq(b, &upper, &LinExpr::constant(F128::ONE));
    shares
}

pub(super) fn bind_final_controls(
    b: &mut FieldR1csBuilder,
    markets: &[MarketRow],
    finals: &[FinalTradeMarketTrace],
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
) {
    assert_eq!(markets.len(), finals.len());
    for (market, final_state) in markets.iter().zip(finals) {
        let live = &market.market.live;
        let before_curve = &market.market.curve;
        let after_curve = &final_state.curve;
        let graduated = before_curve.add(after_curve);
        let pool = live.add(after_curve);
        let old_pool = live.add(before_curve);
        let shares = bootstrap_shares(b, &graduated, &market.market.supply);
        let shares = shares.add(&mul(b, &old_pool, &market.shares));
        let pool_generation = mul(b, &old_pool, &market.next_generation);
        let curve_generation = mul(b, after_curve, &market.next_generation);
        let mut seen = LinExpr::zero();
        for (action, definition) in actions.iter().zip(&definitions.actions) {
            let same = is_zero(b, &action.header_page.add(&market.header_page));
            let selected = mul(b, &same, live);
            let selected = mul(b, &selected, &action.live);
            let selected = mul(b, &selected, &action.is_output);
            let last = is_zero(b, &action.ordinal.add(&market.last_output));
            let selected = mul(b, &selected, &last);
            seen = unique(b, &seen, &selected);
            let native = mul(b, &selected, &action.native);
            pin_eq(b, &native, &selected);
            let output_curve = mul(
                b,
                &selected,
                action.opening.commitment.selector(NativeKind::LaunchState),
            );
            let output_pool = mul(
                b,
                &selected,
                action.opening.commitment.selector(NativeKind::MarketPool),
            );
            let wanted_curve = mul(b, &selected, after_curve);
            let wanted_pool = mul(b, &selected, &pool);
            pin_eq(b, &output_curve, &wanted_curve);
            pin_eq(b, &output_pool, &wanted_pool);
            for (actual, wanted) in [
                (&definition.launch, &output_curve),
                (&definition.market, &output_pool),
            ] {
                let selected_actual = mul(b, &selected, actual);
                pin_eq(b, &selected_actual, wanted);
            }
            let retained = mul(b, &selected, &graduated.add_const(F128::ONE));
            for lane in 0..2 {
                let wrong = mul(
                    b,
                    &retained,
                    &definition.root[lane].add(&market.definition_root[lane]),
                );
                pin_zero(b, &wrong);
            }
            let graduated_output = mul(b, &selected, &graduated);
            let expected_definition = [
                market.definition_fields[2].clone(),
                market.definition_fields[3].clone(),
                LinExpr::zero(),
                LinExpr::zero(),
                market.market.asset[0].clone(),
                market.market.asset[1].clone(),
                number(noid_tx::native_assets::market::MARKET_PROFILE as u128),
                LinExpr::zero(),
            ];
            for i in 0..8 {
                let wrong = mul(
                    b,
                    &graduated_output,
                    &definition.fields[i].add(&expected_definition[i]),
                );
                pin_zero(b, &wrong);
            }
            let mut expected: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
            expected[..2].clone_from_slice(&definition.root);
            let low = select(
                b,
                after_curve,
                &final_state.base_reserve,
                &final_state.quote_reserve,
            );
            let high = select(
                b,
                after_curve,
                &final_state.quote_reserve,
                &final_state.base_reserve,
            );
            expected[2] = super::super::policy::packed(&low, &high);
            expected[3] = curve_generation.add(&super::super::policy::packed(&shares, &shares));
            expected[6] = pool_generation.clone();
            expected[7] = pool.scale(flat_const(1 << 88));
            for i in 0..12 {
                let wrong = mul(b, &selected, &action.opening.fields[i].add(&expected[i]));
                pin_zero(b, &wrong);
            }
        }
        pin_eq(b, &seen, live);
    }
}
