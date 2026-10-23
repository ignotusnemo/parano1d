// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete frozen pool and launch request sets and admission bounds.

use super::super::permutation_network::route_permutation_network;
use super::super::{
    flat_const, flat_of, mul, pin_eq, pin_zero, poseidon2b_permute, FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, extend, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_definitions::{FinancialDefinitionsTrace, SelectedFinancialDefinitionTrace};
use super::financial_inventory_scan::{bind_financial_inventory_scan, FinancialInventoryRowTrace};
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::financial_queue::{
    bind_financial_queue, bind_financial_round, funded_request_key_trace,
};
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_core::hardware::flat_to_tower_u128;
use noid_poseidon2b::native::capacity_iv;
use noid_tx::native_assets::{market::queue::MAX_ROUND_REQUESTS, NativeKind};

pub struct FinancialSettlementRequestTrace {
    pub live: LinExpr,
    pub key: [LinExpr; 2],
    pub root: [LinExpr; 2],
    pub kinds: [LinExpr; 5],
    pub fields: [LinExpr; 12],
}
pub struct FinancialSettlementSetTrace {
    pub live: LinExpr,
    pub family: [LinExpr; 2],
    pub header_page: LinExpr,
    pub frozen: [LinExpr; 12],
    pub idle: [LinExpr; 12],
    pub definition: [LinExpr; 8],
    pub base_is_noid: LinExpr,
    pub round: [LinExpr; 2],
    pub count: LinExpr,
    pub requests: Vec<FinancialSettlementRequestTrace>,
}
/// Selected settlement metadata paired with its physical input count.
pub struct FinancialSettlementHeaderTrace {
    pub family: [LinExpr; 2],
    pub header_page: LinExpr,
    pub input_count: LinExpr,
}
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn eq_when(b: &mut FieldR1csBuilder, f: &LinExpr, a: &LinExpr, c: &LinExpr) {
    let bad = mul(b, f, &a.add(c));
    pin_zero(b, &bad);
}
fn pair_equal(b: &mut FieldR1csBuilder, a: &[LinExpr; 2], c: &[LinExpr; 2]) -> LinExpr {
    let x = is_zero(b, &a[0].add(&c[0]));
    let y = is_zero(b, &a[1].add(&c[1]));
    mul(b, &x, &y)
}
fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}
fn sort_requests(b: &mut FieldR1csBuilder, mut rows: Vec<Vec<LinExpr>>) -> Vec<Vec<LinExpr>> {
    rows.resize_with(
        rows.len().max(MAX_ROUND_REQUESTS).next_power_of_two(),
        || vec![LinExpr::zero(); 22],
    );
    let mut order = (0..rows.len()).collect::<Vec<_>>();
    order.sort_by_key(|&i| {
        (
            tower(b, &rows[i][0]) == 0,
            tower(b, &rows[i][1]).swap_bytes(),
            tower(b, &rows[i][2]).swap_bytes(),
            i,
        )
    });
    let mut p = vec![0; rows.len()];
    for (target, source) in order.into_iter().enumerate() {
        p[source] = target;
    }
    let rows = route_permutation_network(b, rows, &p);
    for row in &rows[MAX_ROUND_REQUESTS..] {
        pin_zero(b, &row[0]);
    }
    rows.into_iter().take(MAX_ROUND_REQUESTS).collect()
}
fn idle_root(
    b: &mut FieldR1csBuilder,
    family: &[LinExpr; 2],
    fields: &[LinExpr; 12],
) -> [LinExpr; 2] {
    let mut iv = [LinExpr::zero(), LinExpr::zero()];
    for (f, k) in family
        .iter()
        .zip([NativeKind::MarketPool, NativeKind::LaunchState])
    {
        let tag = capacity_iv(k.tag());
        for j in 0..2 {
            iv[j] = iv[j].add(&f.scale(flat_of(tag[j])));
        }
    }
    let mut state = [
        LinExpr::zero(),
        LinExpr::zero(),
        iv[0].clone(),
        iv[1].clone(),
    ];
    for pair in fields[..8].chunks_exact(2) {
        state[0] = state[0].add(&pair[0]);
        state[1] = state[1].add(&pair[1]);
        state = poseidon2b_permute(b, state);
    }
    let live = family[0].add(&family[1]);
    std::array::from_fn(|j| mul(b, &live, &state[j]))
}

/// Complete physical actions, typed validation, definition links and shared
/// control arithmetic are bound by the enclosing relation. Every consumed
/// frozen control is reconstructed from its exact idle form and full funded
/// set. The returned canonical rows feed the exact clearing/effect predicates.
pub fn bind_financial_settlement_sets_for_headers(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialSettlementHeaderTrace],
    height: &LinExpr,
) -> Vec<FinancialSettlementSetTrace> {
    assert_eq!(actions.len(), definitions.actions.len());
    let current = bits(b, height, 64);
    let mut result = Vec::with_capacity(headers.len());
    let families = headers.iter().map(|h| h.family.clone()).collect::<Vec<_>>();
    let keys = actions
        .iter()
        .map(|a| funded_request_key_trace(b, &a.root, &a.slot, &a.opening.creation_id.value))
        .collect::<Vec<_>>();
    let inventory = actions
        .iter()
        .map(|a| {
            let mut flag = LinExpr::zero();
            for (h, f) in headers.iter().zip(&families) {
                let same = is_zero(b, &a.header_page.add(&h.header_page));
                flag = flag.add(&mul(b, &same, &f[0].add(&f[1])));
            }
            let live = mul(b, &flag, &a.live);
            FinancialInventoryRowTrace {
                live: live.clone(),
                group: mul(b, &live, &a.header_page),
                slot: mul(b, &live, &a.slot),
                amounts: std::array::from_fn(|_| LinExpr::zero()),
                singleton: LinExpr::zero(),
                payload: std::array::from_fn(|_| LinExpr::zero()),
            }
        })
        .collect::<Vec<_>>();
    let _ = bind_financial_inventory_scan(b, &inventory, headers.len());
    for (h, family) in headers.iter().zip(&families) {
        let live = family[0].add(&family[1]);
        let mut seen = LinExpr::zero();
        let mut frozen: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        let mut d = SelectedFinancialDefinitionTrace {
            market: LinExpr::zero(),
            launch: LinExpr::zero(),
            listing: LinExpr::zero(),
            fields: std::array::from_fn(|_| LinExpr::zero()),
            root: std::array::from_fn(|_| LinExpr::zero()),
            base_is_noid: LinExpr::zero(),
        };
        let mut candidates = Vec::with_capacity(actions.len());
        for ((a, key), definition) in actions.iter().zip(&keys).zip(&definitions.actions) {
            let same = is_zero(b, &a.header_page.add(&h.header_page));
            let input = mul(b, &same, &a.live);
            let input = mul(b, &input, &a.is_output.add_const(F128::ONE));
            let input = mul(b, &input, &live);
            eq_when(b, &input, &a.native, &LinExpr::constant(F128::ONE));
            let pool = mul(
                b,
                &family[0],
                a.opening.commitment.selector(NativeKind::MarketPool),
            );
            let launch = mul(
                b,
                &family[1],
                a.opening.commitment.selector(NativeKind::LaunchState),
            );
            let control = mul(b, &input, &pool.add(&launch));
            let overlap = mul(b, &seen, &control);
            pin_zero(b, &overlap);
            seen = seen.add(&control);
            let kinds = [
                NativeKind::MarketRequest,
                NativeKind::MarketLiquidityDeposit,
                NativeKind::MarketLiquidityWithdrawal,
                NativeKind::MarketLiquidityBurn,
                NativeKind::LaunchRequest,
            ]
            .iter()
            .enumerate()
            .map(|(i, &k)| {
                let flag = mul(
                    b,
                    if i == 4 { &family[1] } else { &family[0] },
                    a.opening.commitment.selector(k),
                );
                mul(b, &input, &flag)
            })
            .collect::<Vec<_>>();
            let request = kinds.iter().fold(LinExpr::zero(), |s, x| s.add(x));
            pin_eq(b, &input, &control.add(&request));
            for j in 0..12 {
                frozen[j] = frozen[j].add(&mul(b, &control, &a.opening.fields[j]));
            }
            for j in 0..8 {
                d.fields[j] = d.fields[j].add(&mul(b, &control, &definition.fields[j]));
            }
            for j in 0..2 {
                d.root[j] = d.root[j].add(&mul(b, &control, &definition.root[j]));
            }
            d.base_is_noid = d
                .base_is_noid
                .add(&mul(b, &control, &definition.base_is_noid));
            d.market = d.market.add(&mul(b, &control, &definition.market));
            d.launch = d.launch.add(&mul(b, &control, &definition.launch));
            let mut row = vec![request.clone()];
            row.extend(key.iter().map(|v| mul(b, &request, v)));
            row.extend(a.root.iter().map(|v| mul(b, &request, v)));
            row.extend(kinds);
            row.extend(a.opening.fields.iter().map(|v| mul(b, &request, v)));
            assert_eq!(row.len(), 22);
            candidates.push(row);
        }
        pin_eq(b, &seen, &live);
        pin_eq(b, &d.market, &family[0]);
        pin_eq(b, &d.launch, &family[1]);
        for j in 0..2 {
            eq_when(b, &live, &frozen[j], &d.root[j]);
        }
        let temporal = mul(b, &family[0], &frozen[6]).add(&mul(b, &family[1], &frozen[3]));
        let temporal = split_packed_input_value(b, &temporal);
        let exhausted = is_zero(
            b,
            &temporal
                .amount
                .value
                .add_const(flat_const(u128::from(u64::MAX))),
        );
        let bad = mul(b, &live, &exhausted);
        pin_zero(b, &bad);
        let registered = temporal.creation_id.value;
        let meta = mul(b, &family[0], &frozen[7]).add(&mul(b, &family[1], &frozen[6]));
        let meta = bits(b, &meta, 128);
        let count = pack(&meta[64..80]);
        pin_eq(b, &pack(&meta[80..88]), &live);
        pin_eq(b, &meta[88], &d.base_is_noid);
        for high in &meta[89..] {
            pin_zero(b, high);
        }
        let start = bits(b, &registered, 64);
        let mut four = vec![LinExpr::zero(); 64];
        four[2] = live.clone();
        let timeout = checked_add(b, &start, &four);
        pin_eq(b, &pack(&meta[..64]), &pack(&timeout));
        let after = less_than(b, &start, &current);
        eq_when(b, &live, &after, &LinExpr::constant(F128::ONE));
        let before = less_than(b, &current, &timeout);
        eq_when(b, &live, &before, &LinExpr::constant(F128::ONE));
        let mut idle = frozen.clone();
        idle[3] = mul(b, &family[0], &frozen[3]).add(&mul(b, &family[1], &temporal.amount.value));
        idle[4] = LinExpr::zero();
        idle[5] = LinExpr::zero();
        idle[6] = mul(b, &family[0], &temporal.amount.value);
        idle[7] = d.base_is_noid.scale(flat_const(1u128 << 88));
        let root = idle_root(b, family, &idle);
        let round = bind_financial_round(
            b,
            &[family[0].clone(), family[1].clone(), LinExpr::zero()],
            &[frozen[0].clone(), frozen[1].clone()],
            &root,
            &registered,
            &[LinExpr::zero(), LinExpr::zero()],
            &LinExpr::zero(),
        );
        let rows = sort_requests(b, candidates);
        let members = std::array::from_fn(|i| rows[i][0].clone());
        let queue_keys = std::array::from_fn(|i| [rows[i][1].clone(), rows[i][2].clone()]);
        let queue = bind_financial_queue(b, &live, &round, &queue_keys, &members);
        pin_eq(b, &queue.count, &count);
        for j in 0..2 {
            eq_when(b, &live, &queue.root[j], &frozen[4 + j]);
        }
        let count_bits = bits(b, &queue.count, 16);
        let mut one = vec![LinExpr::zero(); 16];
        one[0] = live.clone();
        let input_count = checked_add(b, &count_bits, &one);
        eq_when(b, &live, &h.input_count, &pack(&input_count));
        let state = split_packed_input_value(b, &frozen[2]);
        let shares_word = mul(b, &family[0], &frozen[3]);
        let shares = split_packed_input_value(b, &shares_word);
        let total = bits(b, &shares.amount.value, 64);
        let locked = bits(b, &shares.creation_id.value, 64);
        let available = checked_subtract(b, &total, &locked);
        let supply_word = mul(b, &family[1], &d.fields[4]);
        let supply = split_packed_input_value(b, &supply_word);
        let inventory = mul(b, &family[1], &state.amount.value);
        let inventory = bits(b, &inventory, 64);
        let supply_bits = bits(b, &supply.amount.value, 64);
        let sold = checked_subtract(b, &supply_bits, &inventory);
        let initial0 = mul(b, &family[0], &state.amount.value).add(&mul(
            b,
            &family[1],
            &state.creation_id.value,
        ));
        let initial1 = mul(b, &family[0], &state.creation_id.value);
        let mut sums = [
            bits(b, &initial0, 68),
            bits(b, &initial1, 68),
            vec![LinExpr::zero(); 68],
        ];
        for row in &rows {
            let member = &row[0];
            let flags = &row[5..10];
            let f = &row[10..22];
            let first = flags[0].add(&flags[4]);
            let lp = flags[1].add(&flags[2]).add(&flags[3]);
            for j in 0..2 {
                let actual = mul(b, &first, &f[j]).add(&mul(b, &lp, &f[2 + j]));
                let expected = mul(b, member, &round[j]);
                pin_eq(b, &actual, &expected);
                eq_when(b, &lp, &f[j], &frozen[j]);
                eq_when(b, &flags[4], &f[2 + j], &d.fields[j]);
            }
            let direction = pair_equal(
                b,
                &[f[2].clone(), f[3].clone()],
                &[d.fields[2].clone(), d.fields[3].clone()],
            );
            let base = mul(b, &flags[0], &direction);
            let quote = flags[0].add(&base);
            for j in 0..2 {
                let expected_in =
                    mul(b, &base, &d.fields[2 + j]).add(&mul(b, &quote, &d.fields[4 + j]));
                let expected_out =
                    mul(b, &base, &d.fields[4 + j]).add(&mul(b, &quote, &d.fields[2 + j]));
                eq_when(b, &flags[0], &f[2 + j], &expected_in);
                eq_when(b, &flags[0], &f[4 + j], &expected_out);
            }
            let swap = split_packed_input_value(b, &f[10]);
            let time = split_packed_input_value(b, &f[11]);
            let liquidity = split_packed_input_value(b, &f[6]);
            let deposit = split_packed_input_value(b, &f[7]);
            let launch = split_packed_input_value(b, &f[8]);
            let side = split_packed_input_value(b, &f[9]);
            let registered_actual = mul(b, &flags[0], &time.amount.value)
                .add(&mul(b, &flags[1], &deposit.creation_id.value))
                .add(&mul(
                    b,
                    &flags[2].add(&flags[3]),
                    &liquidity.creation_id.value,
                ))
                .add(&mul(b, &flags[4], &side.amount.value));
            eq_when(b, member, &registered_actual, &registered);
            eq_when(
                b,
                &flags[1],
                &LinExpr::from_wire(deposit.amount.bits[63]),
                &d.base_is_noid,
            );
            let quantity = mul(b, &flags[4], &launch.amount.value);
            let quantity = bits(b, &quantity, 64);
            let maximum = supply
                .amount
                .bits
                .iter()
                .copied()
                .map(LinExpr::from_wire)
                .collect::<Vec<_>>();
            let over = less_than(b, &maximum, &quantity);
            let bad = mul(b, &flags[4], &over);
            pin_zero(b, &bad);
            let sell = mul(b, &flags[4], &side.creation_id.value);
            let buy = flags[4].add(&sell);
            let principal0 = mul(b, &base, &swap.amount.value)
                .add(&mul(b, &flags[1], &liquidity.amount.value))
                .add(&mul(b, &buy, &launch.creation_id.value));
            let principal1 = mul(b, &quote, &swap.amount.value)
                .add(&mul(b, &flags[1], &liquidity.creation_id.value))
                .add(&mul(b, &sell, &launch.amount.value));
            let consumed = mul(b, &flags[2].add(&flags[3]), &liquidity.amount.value);
            for (j, x) in [principal0, principal1, consumed].iter().enumerate() {
                let value = bits(b, x, 64);
                sums[j] = checked_add(b, &sums[j], &extend(&value, 68));
            }
        }
        for sum in &sums {
            bits(b, &pack(sum), 63);
        }
        let limit1 = family[0]
            .scale(flat_const((1u128 << 63) - 1))
            .add(&pack(&sold));
        let limit1 = bits(b, &limit1, 68);
        let over = less_than(b, &limit1, &sums[1]);
        pin_zero(b, &over);
        let limit2 = extend(&available, 68);
        let over = less_than(b, &limit2, &sums[2]);
        pin_zero(b, &over);
        let requests = rows
            .into_iter()
            .map(|row| FinancialSettlementRequestTrace {
                live: row[0].clone(),
                key: [row[1].clone(), row[2].clone()],
                root: [row[3].clone(), row[4].clone()],
                kinds: std::array::from_fn(|j| row[5 + j].clone()),
                fields: std::array::from_fn(|j| row[10 + j].clone()),
            })
            .collect::<Vec<_>>();
        result.push(FinancialSettlementSetTrace {
            live,
            family: family.clone(),
            header_page: h.header_page.clone(),
            frozen,
            idle,
            definition: d.fields,
            base_is_noid: d.base_is_noid,
            round,
            count: queue.count,
            requests,
        });
    }
    result
}

/// Retain the complete header view for callers with an existing fixed layout.
pub fn bind_financial_settlement_sets(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialNativeHeaderTrace],
    height: &LinExpr,
) -> Vec<FinancialSettlementSetTrace> {
    let selected = headers
        .iter()
        .map(|header| FinancialSettlementHeaderTrace {
            family: [39, 51].map(|code| {
                header.metadata.financial[FINANCIAL_OPERATION_CODES
                    .iter()
                    .position(|&c| c == code)
                    .unwrap()]
                .clone()
            }),
            header_page: header.header.header_page.clone(),
            input_count: header.header.input_count.clone(),
        })
        .collect::<Vec<_>>();
    bind_financial_settlement_sets_for_headers(b, actions, definitions, &selected, height)
}
