// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete key-ordered market and launch timeout refunds.

use super::super::permutation_network::route_permutation_network;
use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_definitions::FinancialDefinitionsTrace;
use super::financial_inventory_scan::{bind_financial_inventory_scan, FinancialInventoryRowTrace};
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::financial_queue::funded_request_key_trace;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_chain::consensus::params::{FEE_PER_INPUT, FEE_PER_OUTPUT, MIN_FEE_BASE};
use noid_core::hardware::flat_to_tower_u128;
use noid_tx::native_assets::{
    market::{queue::MAX_ROUND_REQUESTS, MARKET_REQUEST_FEE_CREDIT, MARKET_SETTLEMENT_WINDOW},
    NativeKind,
};

fn bits(b: &mut FieldR1csBuilder, v: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, v, n)
}
fn constant(v: u128, n: usize) -> Vec<LinExpr> {
    (0..n)
        .map(|i| LinExpr::constant(flat_const((v >> i) & 1)))
        .collect()
}
fn when_eq(b: &mut FieldR1csBuilder, f: &LinExpr, x: &LinExpr, y: &LinExpr) {
    let bad = mul(b, f, &x.add(y));
    pin_zero(b, &bad);
}
fn tower(b: &FieldR1csBuilder, v: &LinExpr) -> u128 {
    let f = v.eval(b.values());
    flat_to_tower_u128(u128::from(f.lo) | (u128::from(f.hi) << 64))
}
fn sort_requests(b: &mut FieldR1csBuilder, mut rows: Vec<Vec<LinExpr>>) -> Vec<Vec<LinExpr>> {
    rows.resize_with(rows.len().next_power_of_two(), || vec![LinExpr::zero(); 25]);
    let mut order = (0..rows.len()).collect::<Vec<_>>();
    order.sort_by_key(|&i| {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&tower(b, &rows[i][2]).to_le_bytes());
        key[16..].copy_from_slice(&tower(b, &rows[i][3]).to_le_bytes());
        (tower(b, &rows[i][0]) == 0, tower(b, &rows[i][1]), key, i)
    });
    let mut permutation = vec![0; rows.len()];
    for (target, source) in order.into_iter().enumerate() {
        permutation[source] = target;
    }
    route_permutation_network(b, rows, &permutation)
}

/// Complete canonical actions, validated carriers and exact linked definitions
/// compose with the enclosing State/context relation. Each selected input is
/// refunded once, in strict funded-key order, to its original rights. The
/// fixed I=O fee is split by native rank with exact integer rounding.
pub fn bind_financial_timeout_refunds(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialNativeHeaderTrace],
    height: &LinExpr,
) {
    assert!(!actions.is_empty() && !headers.is_empty());
    assert_eq!(headers.len(), definitions.headers.len());
    let height = bits(b, height, 64);
    let mut contexts = Vec::with_capacity(headers.len());
    for (i, h) in headers.iter().enumerate() {
        let flags = [40, 52].map(|code| {
            h.metadata.financial[FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&x| x == code)
                .unwrap()]
            .clone()
        });
        let live = flags[0].add(&flags[1]);
        when_eq(
            b,
            &flags[0],
            &definitions.headers[i].market,
            &LinExpr::constant(F128::ONE),
        );
        when_eq(b, &live, &h.header.input_count, &h.header.output_count);
        let mut found = LinExpr::zero();
        let mut fee = LinExpr::zero();
        let mut quotient = LinExpr::zero();
        let mut remainder = LinExpr::zero();
        for n in 1..=MAX_ROUND_REQUESTS {
            let count = is_zero(b, &h.header.input_count.add_const(flat_const(n as u128)));
            let selected = mul(b, &live, &count);
            found = found.add(&selected);
            let total = MIN_FEE_BASE + n as u64 * (FEE_PER_INPUT + FEE_PER_OUTPUT);
            fee = fee.add(&selected.scale(flat_const(u128::from(total))));
            quotient = quotient.add(&selected.scale(flat_const(u128::from(total / n as u64))));
            remainder = remainder.add(&selected.scale(flat_const(u128::from(total % n as u64))));
        }
        pin_eq(b, &found, &live);
        when_eq(b, &live, &h.header.fee, &fee);
        contexts.push((flags, quotient, remainder));
    }
    let mut inputs = Vec::with_capacity(actions.len());
    let mut inventory = Vec::with_capacity(actions.len());
    let mut outputs = Vec::with_capacity(actions.len());
    for a in actions {
        let mut market = LinExpr::zero();
        let mut launch = LinExpr::zero();
        let mut base_noid = LinExpr::zero();
        let mut quotient = LinExpr::zero();
        let mut remainder = LinExpr::zero();
        let mut count = LinExpr::zero();
        let mut root = [LinExpr::zero(), LinExpr::zero()];
        for (i, (h, c)) in headers.iter().zip(&contexts).enumerate() {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let same = mul(b, &a.live, &same);
            let m = mul(b, &same, &c.0[0]);
            let l = mul(b, &same, &c.0[1]);
            let active = m.add(&l);
            market = market.add(&m);
            launch = launch.add(&l);
            base_noid = base_noid.add(&mul(b, &m, &definitions.headers[i].base_is_noid));
            quotient = quotient.add(&mul(b, &same, &c.1));
            remainder = remainder.add(&mul(b, &same, &c.2));
            count = count.add(&mul(b, &active, &h.header.input_count));
            for j in 0..2 {
                root[j] = root[j].add(&mul(b, &m, &definitions.headers[i].root[j]));
            }
        }
        let live = market.add(&launch);
        when_eq(b, &live, &a.native, &LinExpr::constant(F128::ONE));
        let input = mul(b, &live, &a.is_output.add_const(F128::ONE));
        let output = mul(b, &live, &a.is_output);
        let kinds = [
            NativeKind::MarketRequest,
            NativeKind::MarketLiquidityDeposit,
            NativeKind::MarketLiquidityWithdrawal,
            NativeKind::MarketLiquidityBurn,
            NativeKind::LaunchRequest,
        ];
        let flags: [LinExpr; 5] = std::array::from_fn(|i| {
            let allowed = mul(
                b,
                if i == 4 { &launch } else { &market },
                a.opening.commitment.selector(kinds[i]),
            );
            mul(b, &input, &allowed)
        });
        pin_eq(
            b,
            &flags.iter().fold(LinExpr::zero(), |s, x| s.add(x)),
            &input,
        );
        let lp = flags[1].add(&flags[2]).add(&flags[3]);
        for j in 0..2 {
            when_eq(b, &lp, &a.opening.fields[j], &root[j]);
        }
        let deposit_word = split_packed_input_value(b, &a.opening.fields[7]);
        when_eq(
            b,
            &flags[1],
            &LinExpr::from_wire(deposit_word.amount.bits[63]),
            &base_noid,
        );
        let key = funded_request_key_trace(b, &a.root, &a.slot, &a.opening.creation_id.value);
        let mut row = vec![input.clone(), mul(b, &input, &a.header_page)];
        row.extend(key.iter().map(|v| mul(b, &input, v)));
        row.extend(flags);
        row.extend(a.opening.fields.iter().map(|v| mul(b, &input, v)));
        for v in [&base_noid, &quotient, &remainder, &count] {
            row.push(mul(b, &input, v));
        }
        assert_eq!(row.len(), 25);
        inputs.push(row);
        inventory.push(FinancialInventoryRowTrace {
            live: live.clone(),
            group: mul(b, &live, &a.header_page),
            slot: mul(b, &live, &a.slot),
            amounts: [
                input,
                output.clone(),
                LinExpr::zero(),
                LinExpr::zero(),
                LinExpr::zero(),
                LinExpr::zero(),
            ],
            singleton: LinExpr::zero(),
            payload: std::array::from_fn(|_| LinExpr::zero()),
        });
        outputs.push(output);
    }
    let inventory = bind_financial_inventory_scan(b, &inventory, headers.len());
    for (h, c) in headers.iter().zip(&contexts) {
        let live = c.0[0].add(&c.0[1]);
        let mut found = LinExpr::zero();
        for summary in &inventory.groups {
            let same = is_zero(b, &summary.group.add(&h.header.header_page));
            let selected = mul(b, &summary.live, &same);
            let selected = mul(b, &live, &selected);
            found = found.add(&selected);
            when_eq(b, &selected, &summary.amounts[0], &h.header.input_count);
            when_eq(b, &selected, &summary.amounts[1], &h.header.output_count);
        }
        pin_eq(b, &found, &live);
    }
    let inputs = sort_requests(b, inputs);
    let mut previous: Option<(LinExpr, Vec<LinExpr>)> = None;
    let mut old_group = LinExpr::zero();
    let mut old_live = LinExpr::zero();
    let mut rank = vec![LinExpr::zero(); 5];
    for row in &inputs {
        let live = &row[0];
        let f = &row[4..9];
        let s = &row[9..21];
        let raw = [bits(b, &row[2], 128), bits(b, &row[3], 128)].concat();
        let mut key = (0..32)
            .rev()
            .flat_map(|byte| raw[8 * byte..8 * byte + 8].iter().cloned())
            .collect::<Vec<_>>();
        key.extend(bits(b, &row[1], 32));
        if let Some((last_live, old)) = previous {
            let hole = mul(b, live, &last_live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let strict = less_than(b, &old, &key);
            let bad = mul(b, live, &strict.add_const(F128::ONE));
            pin_zero(b, &bad);
        }
        previous = Some((live.clone(), key));
        let same = is_zero(b, &row[1].add(&old_group));
        let cont = mul(b, &same, &old_live);
        let cont = mul(b, live, &cont);
        let next = checked_add(b, &rank, &constant(1, 5));
        rank = next.iter().map(|v| mul(b, &cont, v)).collect();
        let rem = bits(b, &row[23], 5);
        let extra = less_than(b, &rank, &rem);
        let mut delta = vec![LinExpr::zero(); 64];
        delta[0] = extra;
        let quotient = bits(b, &row[22], 64);
        let charge = checked_add(b, &quotient, &delta);
        let credit_bits = (0..64)
            .map(|i| live.scale(flat_const((u128::from(MARKET_REQUEST_FEE_CREDIT) >> i) & 1)))
            .collect::<Vec<_>>();
        let credit = pack(&checked_subtract(b, &credit_bits, &charge));
        let lp = f[1].add(&f[2]).add(&f[3]);
        let swap = f[0].add(&f[4]);
        let swap_time = split_packed_input_value(b, &s[11]);
        let deposit_time = split_packed_input_value(b, &s[7]);
        let withdrawal_time = split_packed_input_value(b, &s[6]);
        let launch_time = split_packed_input_value(b, &s[9]);
        let temporal = mul(b, &f[0], &swap_time.amount.value)
            .add(&mul(b, &f[1], &deposit_time.creation_id.value))
            .add(&mul(
                b,
                &f[2].add(&f[3]),
                &withdrawal_time.creation_id.value,
            ))
            .add(&mul(b, &f[4], &launch_time.amount.value));
        let t = bits(b, &temporal, 64);
        let delta = (0..64)
            .map(|i| live.scale(flat_const((u128::from(MARKET_SETTLEMENT_WINDOW) >> i) & 1)))
            .collect::<Vec<_>>();
        let deadline = checked_add(b, &t, &delta);
        let early = less_than(b, &height, &deadline);
        let bad = mul(b, live, &early);
        pin_zero(b, &bad);
        let side = mul(b, &f[4], &launch_time.creation_id.value);
        let buy = f[4].add(&side);
        let launch_units = split_packed_input_value(b, &s[8]);
        let gross = split_packed_input_value(b, &s[10]);
        let refund = mul(b, &f[0], &gross.amount.value)
            .add(&mul(b, &buy, &launch_units.creation_id.value))
            .add(&mul(b, &side, &launch_units.amount.value));
        let mut expected: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        expected[0] = row[2].clone();
        expected[1] = row[3].clone();
        for j in 0..2 {
            expected[2 + j] = mul(b, &f[0], &s[2 + j])
                .add(&mul(b, &side, &s[2 + j]))
                .add(&mul(b, &lp, &s[j]));
            expected[4 + j] = mul(b, &f[0], &s[4 + j])
                .add(&mul(b, &buy, &s[2 + j]))
                .add(&mul(b, &lp, &s[4 + j]));
            expected[6 + j] = mul(b, &f[0], &s[6 + j]).add(&mul(b, &f[4], &s[4 + j]));
            expected[8 + j] = mul(b, &f[0], &s[8 + j]).add(&mul(b, &f[4], &s[6 + j]));
        }
        expected[6] = expected[6].add(&mul(b, &f[1], &s[6]));
        let shares = mul(b, &f[2].add(&f[3]), &withdrawal_time.amount.value);
        let lp_credit = mul(b, &lp, &credit).scale(flat_const(1u128 << 64));
        expected[7] = expected[7]
            .add(&shares)
            .add(&lp_credit)
            .add(&mul(b, &lp, &row[21]).scale(flat_const(1u128 << 127)));
        expected[10] = refund;
        expected[11] = mul(b, &swap, &credit);
        let mut found = LinExpr::zero();
        for (a, output) in actions.iter().zip(&outputs) {
            let group = is_zero(b, &a.header_page.add(&row[1]));
            let ordinal = is_zero(b, &a.ordinal.add(&pack(&rank)));
            let selected = mul(b, output, &group);
            let selected = mul(b, &selected, &ordinal);
            let selected = mul(b, live, &selected);
            found = found.add(&selected);
            when_eq(
                b,
                &selected,
                a.opening.commitment.selector(NativeKind::MarketClaim),
                &swap,
            );
            when_eq(
                b,
                &selected,
                a.opening
                    .commitment
                    .selector(NativeKind::MarketLiquidityClaim),
                &lp,
            );
            for j in 0..12 {
                when_eq(b, &selected, &a.opening.fields[j], &expected[j]);
            }
        }
        pin_eq(b, &found, live);
        old_group = row[1].clone();
        old_live = live.clone();
    }
}
