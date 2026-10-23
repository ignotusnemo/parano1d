// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact Owner market funding and LP movement over one grouped inventory.

use super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_definitions::FinancialDefinitionsTrace;
use super::financial_inventory_scan::{bind_financial_inventory_scan, FinancialInventoryRowTrace};
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_tx::native_assets::NativeKind;
fn bits(b: &mut FieldR1csBuilder, v: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, v, n)
}
fn eq_when(b: &mut FieldR1csBuilder, flag: &LinExpr, a: &LinExpr, c: &LinExpr) {
    let bad = mul(b, flag, &a.add(c));
    pin_zero(b, &bad);
}
fn same_pair(b: &mut FieldR1csBuilder, a: &[LinExpr; 2], c: &[LinExpr; 2]) -> LinExpr {
    let lo = is_zero(b, &a[0].add(&c[0]));
    let hi = is_zero(b, &a[1].add(&c[1]));
    mul(b, &lo, &hi)
}
fn unique(b: &mut FieldR1csBuilder, seen: &LinExpr, flag: &LinExpr) -> LinExpr {
    let repeated = mul(b, seen, flag);
    pin_zero(b, &repeated);
    seen.add(flag)
}
struct Context {
    flags: [LinExpr; 5],
    root: [LinExpr; 2],
    base: [LinExpr; 2],
    quote: [LinExpr; 2],
}

/// Complete canonical actions, validated carrier values, linked parent/header
/// definitions, admission/registration and ordinary fee/NOID rules compose in
/// the bank. One complete inventory scan binds token and LP conservation and
/// distinct source/output slots for swaps, deposits, withdrawals, burns and LP
/// transfers. The enclosing Owner statement authenticates the exact authority.
pub fn bind_financial_market_owner(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialNativeHeaderTrace],
    height: &LinExpr,
) {
    assert_eq!(headers.len(), definitions.headers.len());
    assert_eq!(headers.len(), definitions.reads.len());
    let height = bits(b, height, 64);
    let mut contexts = Vec::with_capacity(headers.len());
    for (i, h) in headers.iter().enumerate() {
        let flags = [33, 34, 35, 36, 37].map(|code| {
            h.metadata.financial[FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&c| c == code)
                .unwrap()]
            .clone()
        });
        let transfer = &flags[4];
        let read = flags[..4].iter().fold(LinExpr::zero(), |s, v| s.add(v));
        let live = read.add(transfer);
        let hd = &definitions.headers[i];
        let rd = &definitions.reads[i];
        let market = mul(b, transfer, &hd.market).add(&mul(b, &read, &rd.market));
        pin_eq(b, &market, &live);
        let mut root = [LinExpr::zero(), LinExpr::zero()];
        let mut base = root.clone();
        let mut quote = root.clone();
        for j in 0..2 {
            root[j] = mul(b, transfer, &hd.root[j]).add(&mul(b, &read, &rd.root[j]));
            base[j] = mul(b, transfer, &hd.fields[2 + j]).add(&mul(b, &read, &rd.fields[2 + j]));
            quote[j] = mul(b, transfer, &hd.fields[4 + j]).add(&mul(b, &read, &rd.fields[4 + j]));
        }
        contexts.push(Context {
            flags,
            root,
            base,
            quote,
        });
    }
    let mut rows = Vec::with_capacity(actions.len());
    for a in actions {
        let mut flags: [LinExpr; 5] = std::array::from_fn(|_| LinExpr::zero());
        let mut root = [LinExpr::zero(), LinExpr::zero()];
        let mut base = root.clone();
        let mut quote = root.clone();
        for (h, c) in headers.iter().zip(&contexts) {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let same = mul(b, &same, &a.live);
            for k in 0..5 {
                flags[k] = flags[k].add(&mul(b, &same, &c.flags[k]));
            }
            for j in 0..2 {
                root[j] = root[j].add(&mul(b, &same, &c.root[j]));
                base[j] = base[j].add(&mul(b, &same, &c.base[j]));
                quote[j] = quote[j].add(&mul(b, &same, &c.quote[j]));
            }
        }
        let live = flags.iter().fold(LinExpr::zero(), |s, v| s.add(v));
        let input = mul(b, &live, &a.is_output.add_const(F128::ONE));
        let output = mul(b, &live, &a.is_output);
        let native_in = mul(b, &input, &a.native);
        let native_out = mul(b, &output, &a.native);
        let ordinary = mul(b, &live, &a.native.add_const(F128::ONE));
        for j in 0..2 {
            eq_when(b, &ordinary, &a.root[j], &a.authority[j]);
        }
        let tokens = flags[0].add(&flags[1]);
        let positions = flags[2].add(&flags[3]).add(&flags[4]);
        let ti = mul(
            b,
            &native_in,
            a.opening.commitment.selector(NativeKind::TokenBalance),
        );
        let ti = mul(b, &ti, &tokens);
        let to = mul(
            b,
            &native_out,
            a.opening.commitment.selector(NativeKind::TokenBalance),
        );
        let to = mul(b, &to, &tokens);
        let pi = mul(
            b,
            &native_in,
            a.opening.commitment.selector(NativeKind::MarketLiquidity),
        );
        let pi = mul(b, &pi, &positions);
        let po = mul(
            b,
            &native_out,
            a.opening.commitment.selector(NativeKind::MarketLiquidity),
        );
        let po = mul(b, &po, &positions);
        pin_eq(b, &ti.add(&pi), &native_in);
        let mut request = LinExpr::zero();
        for (k, kind) in [
            NativeKind::MarketRequest,
            NativeKind::MarketLiquidityDeposit,
            NativeKind::MarketLiquidityWithdrawal,
            NativeKind::MarketLiquidityBurn,
        ]
        .into_iter()
        .enumerate()
        {
            let selected = mul(b, &native_out, a.opening.commitment.selector(kind));
            let selected = mul(b, &selected, &flags[k]);
            request = request.add(&selected);
            let owner_index = if k == 0 { 6 } else { 4 };
            for j in 0..2 {
                eq_when(
                    b,
                    &selected,
                    &a.opening.fields[owner_index + j],
                    &a.authority[j],
                );
            }
        }
        pin_eq(b, &to.add(&po).add(&request), &native_out);
        let token = ti.add(&to);
        let position = pi.add(&po);
        let asset = [a.opening.fields[0].clone(), a.opening.fields[1].clone()];
        let is_base = same_pair(b, &asset, &base);
        let is_quote = same_pair(b, &asset, &quote);
        eq_when(
            b,
            &token,
            &is_base.add(&is_quote),
            &LinExpr::constant(F128::ONE),
        );
        let output_owner = mul(b, &po, &flags[4].add_const(F128::ONE));
        let owned = token.add(&pi).add(&output_owner);
        for j in 0..2 {
            eq_when(b, &owned, &a.opening.fields[2 + j], &a.authority[j]);
            eq_when(b, &position, &asset[j], &root[j]);
        }
        let quantity = split_packed_input_value(b, &a.opening.fields[4]);
        let unlock = quantity
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let locked = less_than(b, &height, &unlock);
        let source = ti.add(&pi);
        let locked = mul(b, &source, &locked);
        pin_zero(b, &locked);
        let input_base = mul(b, &ti, &is_base);
        let input_quote = mul(b, &ti, &is_quote);
        let output_base = mul(b, &to, &is_base);
        let output_quote = mul(b, &to, &is_quote);
        let amounts = [input_base, input_quote, pi, output_base, output_quote, po]
            .map(|flag| mul(b, &flag, &quantity.amount.value));
        rows.push(FinancialInventoryRowTrace {
            live: live.clone(),
            group: mul(b, &live, &a.header_page),
            slot: mul(b, &live, &a.slot),
            amounts,
            singleton: request.clone(),
            payload: std::array::from_fn(|j| mul(b, &request, &a.opening.fields[j])),
        });
    }
    let scan = bind_financial_inventory_scan(b, &rows, headers.len());
    let mut matches = vec![LinExpr::zero(); scan.groups.len()];
    for (h, c) in headers.iter().zip(&contexts) {
        let live = c.flags.iter().fold(LinExpr::zero(), |s, v| s.add(v));
        let mut found = LinExpr::zero();
        let mut amounts: [LinExpr; 6] = std::array::from_fn(|_| LinExpr::zero());
        let mut payload: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        let mut requests = LinExpr::zero();
        for (i, s) in scan.groups.iter().enumerate() {
            let same = is_zero(b, &s.group.add(&h.header.header_page));
            let selected = mul(b, &same, &s.live);
            let selected = mul(b, &selected, &live);
            found = unique(b, &found, &selected);
            matches[i] = unique(b, &matches[i], &selected);
            for k in 0..6 {
                amounts[k] = amounts[k].add(&mul(b, &selected, &s.amounts[k]));
            }
            for j in 0..12 {
                payload[j] = payload[j].add(&mul(b, &selected, &s.payload[j]));
            }
            requests = requests.add(&mul(b, &selected, &s.singleton));
        }
        pin_eq(b, &found, &live);
        let needs_request = c.flags[..4].iter().fold(LinExpr::zero(), |s, v| s.add(v));
        pin_eq(b, &requests, &needs_request);
        let swap_amount = split_packed_input_value(b, &payload[10]);
        let liquidity = split_packed_input_value(b, &payload[6]);
        let input_asset = [payload[2].clone(), payload[3].clone()];
        let input_base = same_pair(b, &input_asset, &c.base);
        let input_quote = same_pair(b, &input_asset, &c.quote);
        eq_when(
            b,
            &c.flags[0],
            &input_base.add(&input_quote),
            &LinExpr::constant(F128::ONE),
        );
        let buy_base = mul(b, &c.flags[0], &input_base);
        let buy_quote = mul(b, &c.flags[0], &input_quote);
        let principal_base = mul(b, &buy_base, &swap_amount.amount.value).add(&mul(
            b,
            &c.flags[1],
            &liquidity.amount.value,
        ));
        let principal_quote = mul(b, &buy_quote, &swap_amount.amount.value).add(&mul(
            b,
            &c.flags[1],
            &liquidity.creation_id.value,
        ));
        let base_noid = same_pair(b, &c.base, &[LinExpr::zero(), LinExpr::zero()]);
        let quote_noid = same_pair(b, &c.quote, &[LinExpr::zero(), LinExpr::zero()]);
        let principal_base = mul(b, &principal_base, &base_noid.add_const(F128::ONE));
        let principal_quote = mul(b, &principal_quote, &quote_noid.add_const(F128::ONE));
        let lp_request = c.flags[2].add(&c.flags[3]);
        let lp_request = mul(b, &lp_request, &liquidity.amount.value);
        for (input, output, delta) in [
            (&amounts[0], &amounts[3], &principal_base),
            (&amounts[1], &amounts[4], &principal_quote),
            (&amounts[2], &amounts[5], &lp_request),
        ] {
            let input = bits(b, input, 128);
            let output = bits(b, output, 128);
            let delta = bits(b, delta, 128);
            let sum = checked_add(b, &output, &delta);
            pin_eq(b, &pack(&input), &pack(&sum));
        }
        let transfer_empty = is_zero(b, &amounts[2]);
        let empty = mul(b, &c.flags[4], &transfer_empty);
        pin_zero(b, &empty);
    }
    for (s, matched) in scan.groups.iter().zip(&matches) {
        pin_eq(b, matched, &s.live);
    }
}
