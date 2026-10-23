// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact launch and NFT purchase request funding.

use super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_definitions::FinancialDefinitionsTrace;
use super::financial_inventory_scan::{bind_financial_inventory_scan, FinancialInventoryRowTrace};
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::financial_reads::FinancialParentReadTrace;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_tx::native_assets::NativeKind;
fn bits(b: &mut FieldR1csBuilder, v: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, v, n)
}
fn when_eq(b: &mut FieldR1csBuilder, f: &LinExpr, x: &LinExpr, y: &LinExpr) {
    let bad = mul(b, f, &x.add(y));
    pin_zero(b, &bad);
}

/// The enclosing bank authenticates the complete physical actions, authority,
/// current height/parent counter, read controls, carrier values and definitions.
/// Admission binds the exact round, time, generation and registration suffix.
/// Ordinary NOID conservation and fees fund the same request and owner change.
pub fn bind_financial_owner_requests(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialNativeHeaderTrace],
    reads: &[FinancialParentReadTrace],
    height: &LinExpr,
    parent_counter: &LinExpr,
) {
    assert_eq!(headers.len(), definitions.reads.len());
    assert_eq!(headers.len(), reads.len());
    let height_bits = bits(b, height, 64);
    let parent_bits = bits(b, parent_counter, 64);
    let flags = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let launch = h.metadata.financial[FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&x| x == 49)
                .unwrap()]
            .clone();
            let f = [launch, LinExpr::zero()];
            let launch = mul(b, &f[0], &definitions.reads[i].launch);
            pin_eq(b, &launch, &f[0]);
            let listing = mul(b, &f[1], &definitions.reads[i].listing);
            pin_eq(b, &listing, &f[1]);
            f
        })
        .collect::<Vec<_>>();
    let mut rows = Vec::with_capacity(actions.len());
    for a in actions {
        let mut launch = LinExpr::zero();
        let mut nft = LinExpr::zero();
        let mut asset = [LinExpr::zero(), LinExpr::zero()];
        let mut listing = asset.clone();
        for (i, h) in headers.iter().enumerate() {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let same = mul(b, &a.live, &same);
            let l = mul(b, &same, &flags[i][0]);
            let n = mul(b, &same, &flags[i][1]);
            launch = launch.add(&l);
            nft = nft.add(&n);
            for j in 0..2 {
                asset[j] = asset[j].add(&mul(b, &l, &definitions.reads[i].fields[j]));
                listing[j] = listing[j].add(&mul(b, &n, &reads[i].fields[j]));
            }
        }
        let live = launch.add(&nft);
        let input = mul(b, &live, &a.is_output.add_const(F128::ONE));
        let output = mul(b, &live, &a.is_output);
        let ordinary = mul(b, &live, &a.native.add_const(F128::ONE));
        for j in 0..2 {
            when_eq(b, &ordinary, &a.root[j], &a.authority[j]);
        }
        let token = mul(
            b,
            &launch,
            a.opening.commitment.selector(NativeKind::TokenBalance),
        );
        let ti = mul(b, &input, &token);
        let to = mul(b, &output, &token);
        let native_in = mul(b, &input, &a.native);
        pin_eq(b, &native_in, &ti);
        let lr = mul(
            b,
            &launch,
            a.opening.commitment.selector(NativeKind::LaunchRequest),
        );
        let nr = mul(
            b,
            &nft,
            a.opening.commitment.selector(NativeKind::NftPurchase),
        );
        let request = mul(b, &output, &lr.add(&nr));
        let native_out = mul(b, &output, &a.native);
        pin_eq(b, &native_out, &to.add(&request));
        let token = ti.add(&to);
        for j in 0..2 {
            when_eq(b, &token, &a.opening.fields[j], &asset[j]);
            when_eq(b, &token, &a.opening.fields[2 + j], &a.authority[j]);
            when_eq(b, &request, &a.opening.fields[4 + j], &a.authority[j]);
            when_eq(b, &nr, &a.opening.fields[j], &listing[j]);
            when_eq(b, &lr, &a.opening.fields[2 + j], &asset[j]);
        }
        let value = split_packed_input_value(b, &a.opening.fields[4]);
        let unlock = value
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let early = less_than(b, &height_bits, &unlock);
        let bad = mul(b, &ti, &early);
        pin_zero(b, &bad);
        let ordinary_input = mul(b, &input, &nft);
        let packed = split_packed_input_value(b, &a.packed_value);
        let raw = packed
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let reward = raw[63].clone();
        let maturity = pack(&raw[..63]);
        let maturity = bits(b, &maturity, 64);
        let mature = less_than(b, &maturity, &height_bits);
        let bad = mul(b, &ordinary_input, &reward);
        let bad = mul(b, &bad, &mature.add_const(F128::ONE));
        pin_zero(b, &bad);
        let normal = mul(b, &ordinary_input, &reward.add_const(F128::ONE));
        let future = less_than(b, &parent_bits, &raw);
        let bad = mul(b, &normal, &future);
        pin_zero(b, &bad);
        rows.push(FinancialInventoryRowTrace {
            live: live.clone(),
            group: mul(b, &live, &a.header_page),
            slot: mul(b, &live, &a.slot),
            amounts: [
                mul(b, &ti, &value.amount.value),
                mul(b, &to, &value.amount.value),
                LinExpr::zero(),
                LinExpr::zero(),
                LinExpr::zero(),
                LinExpr::zero(),
            ],
            singleton: request.clone(),
            payload: std::array::from_fn(|j| mul(b, &request, &a.opening.fields[j])),
        });
    }
    let inventory = bind_financial_inventory_scan(b, &rows, headers.len());
    for (i, h) in headers.iter().enumerate() {
        let live = flags[i][0].add(&flags[i][1]);
        let mut found = LinExpr::zero();
        for s in &inventory.groups {
            let same = is_zero(b, &s.group.add(&h.header.header_page));
            let selected = mul(b, &live, &s.live);
            let selected = mul(b, &selected, &same);
            found = found.add(&selected);
            when_eq(b, &selected, &s.singleton, &LinExpr::constant(F128::ONE));
            let packed = split_packed_input_value(b, &s.payload[8]);
            let side = split_packed_input_value(b, &s.payload[9]);
            let launch = mul(b, &selected, &flags[i][0]);
            let nft = mul(b, &selected, &flags[i][1]);
            let sell = mul(b, &launch, &side.creation_id.value);
            let buy = launch.add(&sell);
            let incoming = bits(b, &s.amounts[0], inventory.sum_width);
            let outgoing = bits(b, &s.amounts[1], inventory.sum_width);
            let amount = mul(b, &sell, &packed.amount.value);
            let amount = bits(b, &amount, inventory.sum_width);
            let total = checked_add(b, &outgoing, &amount);
            when_eq(b, &selected, &pack(&incoming), &pack(&total));
            let bad = mul(b, &buy, &s.amounts[0]);
            pin_zero(b, &bad);
            let supply_word = mul(b, &launch, &definitions.reads[i].fields[4]);
            let supply = split_packed_input_value(b, &supply_word);
            let q = mul(b, &launch, &packed.amount.value);
            let q = bits(b, &q, 64);
            let supply = supply
                .amount
                .bits
                .iter()
                .copied()
                .map(LinExpr::from_wire)
                .collect::<Vec<_>>();
            let over = less_than(b, &supply, &q);
            pin_zero(b, &over);
            let ask_word = mul(b, &nft, &definitions.reads[i].fields[7]);
            let ask = split_packed_input_value(b, &ask_word);
            let ask = ask
                .amount
                .bits
                .iter()
                .copied()
                .map(LinExpr::from_wire)
                .collect::<Vec<_>>();
            let budget = mul(b, &nft, &packed.amount.value);
            let budget = bits(b, &budget, 64);
            let low = less_than(b, &budget, &ask);
            pin_zero(b, &low);
        }
        pin_eq(b, &found, &live);
    }
}
