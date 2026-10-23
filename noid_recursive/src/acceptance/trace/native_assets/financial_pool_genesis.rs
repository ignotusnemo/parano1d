// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact funded market genesis and initial LP rights.

use super::super::{
    const_block, flat_const, mul, pin_eq, pin_zero, poseidon2b_permute, FieldR1csBuilder, LinExpr,
    F128,
};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_bootstrap_root::bind_bootstrap_share_root;
use super::financial_control_rows::FinancialControlRowTrace;
use super::financial_definitions::FinancialDefinitionsTrace;
use super::financial_inventory_scan::{bind_financial_inventory_scan, FinancialInventoryRowTrace};
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_poseidon2b::native::{capacity_iv, DomainTag};
use noid_tx::native_assets::{market::MARKET_MIN_LOCKED_SHARES, NativeKind};
fn bits(b: &mut FieldR1csBuilder, v: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, v, n)
}
fn when_eq(b: &mut FieldR1csBuilder, f: &LinExpr, x: &LinExpr, y: &LinExpr) {
    let bad = mul(b, f, &x.add(y));
    pin_zero(b, &bad);
}
fn same_pair(b: &mut FieldR1csBuilder, x: &[LinExpr; 2], y: &[LinExpr; 2]) -> LinExpr {
    let lo = is_zero(b, &x[0].add(&y[0]));
    let hi = is_zero(b, &x[1].add(&y[1]));
    mul(b, &lo, &hi)
}
fn unique(b: &mut FieldR1csBuilder, seen: &LinExpr, f: &LinExpr) -> LinExpr {
    let repeated = mul(b, seen, f);
    pin_zero(b, &repeated);
    seen.add(f)
}
fn seed(b: &mut FieldR1csBuilder, fields: &[LinExpr; 10]) -> [LinExpr; 2] {
    let iv = capacity_iv(DomainTag::new(b"MKSEED21"));
    let mut s = [
        LinExpr::zero(),
        LinExpr::zero(),
        const_block(iv[0]),
        const_block(iv[1]),
    ];
    for p in fields.chunks_exact(2) {
        s[0] = s[0].add(&p[0]);
        s[1] = s[1].add(&p[1]);
        s = poseidon2b_permute(b, s);
    }
    [s[0].clone(), s[1].clone()]
}

/// Shared complete physical actions, validated carriers/definitions, exact
/// designated funding flags and control arithmetic compose in the bank.
/// The enclosing Owner, State and fee relations authenticate this same group.
pub fn bind_financial_pool_genesis(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialNativeHeaderTrace],
    controls: &[FinancialControlRowTrace],
    height: &LinExpr,
) {
    assert_eq!(headers.len(), definitions.headers.len());
    let height_bits = bits(b, height, 64);
    let flags = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let flag = h.metadata.financial[FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&x| x == 32)
                .unwrap()]
            .clone();
            when_eq(
                b,
                &flag,
                &definitions.headers[i].market,
                &LinExpr::constant(F128::ONE),
            );
            flag
        })
        .collect::<Vec<_>>();
    let mut rows = Vec::with_capacity(actions.len());
    for a in actions {
        let mut live = LinExpr::zero();
        let mut root = [LinExpr::zero(), LinExpr::zero()];
        let mut base = root.clone();
        let mut quote = root.clone();
        for (i, h) in headers.iter().enumerate() {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let selected = mul(b, &a.live, &same);
            let selected = mul(b, &selected, &flags[i]);
            live = live.add(&selected);
            for j in 0..2 {
                root[j] = root[j].add(&mul(b, &selected, &definitions.headers[i].root[j]));
                base[j] = base[j].add(&mul(b, &selected, &definitions.headers[i].fields[2 + j]));
                quote[j] = quote[j].add(&mul(b, &selected, &definitions.headers[i].fields[4 + j]));
            }
        }
        let input = mul(b, &live, &a.is_output.add_const(F128::ONE));
        let output = mul(b, &live, &a.is_output);
        let ordinary = mul(b, &live, &a.native.add_const(F128::ONE));
        for j in 0..2 {
            when_eq(b, &ordinary, &a.root[j], &a.authority[j]);
        }
        let token = mul(
            b,
            &live,
            a.opening.commitment.selector(NativeKind::TokenBalance),
        );
        let ti = mul(b, &input, &token);
        let to = mul(b, &output, &token);
        let lp = mul(
            b,
            &output,
            a.opening.commitment.selector(NativeKind::MarketLiquidity),
        );
        let pool = mul(
            b,
            &output,
            a.opening.commitment.selector(NativeKind::MarketPool),
        );
        let ni = mul(b, &input, &a.native);
        let no = mul(b, &output, &a.native);
        pin_eq(b, &ni, &ti);
        pin_eq(b, &no, &to.add(&lp).add(&pool));
        let asset = [a.opening.fields[0].clone(), a.opening.fields[1].clone()];
        let is_base = same_pair(b, &asset, &base);
        let is_quote = same_pair(b, &asset, &quote);
        let allowed = mul(b, &token, &is_base.add(&is_quote));
        pin_eq(b, &allowed, &token);
        for j in 0..2 {
            when_eq(
                b,
                &token.add(&lp),
                &a.opening.fields[2 + j],
                &a.authority[j],
            );
            when_eq(b, &lp.add(&pool), &a.opening.fields[j], &root[j]);
        }
        let value = split_packed_input_value(b, &a.opening.fields[4]);
        let unlock = value
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let early = super::arithmetic::less_than(b, &height_bits, &unlock);
        let bad = mul(b, &ti, &early);
        pin_zero(b, &bad);
        let ti_base = mul(b, &ti, &is_base);
        let ti_quote = mul(b, &ti, &is_quote);
        let to_base = mul(b, &to, &is_base);
        let to_quote = mul(b, &to, &is_quote);
        rows.push(FinancialInventoryRowTrace {
            live: live.clone(),
            group: mul(b, &live, &a.header_page),
            slot: mul(b, &live, &a.slot),
            amounts: [
                mul(b, &ti_base, &value.amount.value),
                mul(b, &ti_quote, &value.amount.value),
                mul(b, &lp, &value.amount.value),
                mul(b, &to_base, &value.amount.value),
                mul(b, &to_quote, &value.amount.value),
                LinExpr::zero(),
            ],
            singleton: pool.clone(),
            payload: std::array::from_fn(|j| mul(b, &pool, &a.opening.fields[j])),
        });
    }
    let inventory = bind_financial_inventory_scan(b, &rows, headers.len());
    for (i, h) in headers.iter().enumerate() {
        let live = &flags[i];
        let d = &definitions.headers[i];
        let mut funding = LinExpr::zero();
        let mut funding_slot = LinExpr::zero();
        let mut funding_value = LinExpr::zero();
        let mut funding_root = [LinExpr::zero(), LinExpr::zero()];
        for a in actions {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let selected = mul(b, live, &same);
            let selected = mul(b, &selected, &a.live);
            let selected = mul(b, &selected, &a.funding);
            funding = unique(b, &funding, &selected);
            when_eq(b, &selected, &a.is_output, &LinExpr::zero());
            when_eq(b, &selected, &a.native, &LinExpr::zero());
            funding_slot = funding_slot.add(&mul(b, &selected, &a.slot));
            funding_value = funding_value.add(&mul(b, &selected, &a.packed_value));
            for j in 0..2 {
                funding_root[j] = funding_root[j].add(&mul(b, &selected, &a.root[j]));
            }
        }
        pin_eq(b, &funding, live);
        let packed = split_packed_input_value(b, &funding_value);
        for value in [&packed.amount.value, &packed.creation_id.value] {
            let zero = is_zero(b, value);
            let bad = mul(b, live, &zero);
            pin_zero(b, &bad);
        }
        let reserved = mul(
            b,
            &LinExpr::from_wire(packed.creation_id.bits[62]),
            &LinExpr::from_wire(packed.creation_id.bits[63]).add_const(F128::ONE),
        );
        pin_zero(b, &reserved);
        let mut anchor: [LinExpr; 10] = std::array::from_fn(|_| LinExpr::zero());
        for j in 0..2 {
            when_eq(b, live, &funding_root[j], &h.header.authority[j]);
            anchor[j] = mul(b, live, &h.header.chain[j]);
            anchor[2 + j] = mul(b, live, &h.header.authority[j]);
            anchor[6 + j] = mul(b, live, &d.fields[2 + j]);
            anchor[8 + j] = mul(b, live, &d.fields[4 + j]);
        }
        anchor[4] = funding_value;
        anchor[5] = funding_slot;
        let id = seed(b, &anchor);
        for j in 0..2 {
            when_eq(b, live, &id[j], &d.fields[j]);
        }
        let mut found = LinExpr::zero();
        for s in &inventory.groups {
            let same = is_zero(b, &s.group.add(&h.header.header_page));
            let selected = mul(b, live, &same);
            let selected = mul(b, &selected, &s.live);
            found = found.add(&selected);
            when_eq(b, &selected, &s.singleton, &LinExpr::constant(F128::ONE));
            let p = &s.payload;
            let reserves = split_packed_input_value(b, &p[2]);
            let shares = split_packed_input_value(b, &p[3]);
            when_eq(
                b,
                &selected,
                &shares.creation_id.value,
                &LinExpr::constant(flat_const(u128::from(MARKET_MIN_LOCKED_SHARES))),
            );
            for j in 4..=6 {
                when_eq(b, &selected, &p[j], &LinExpr::zero());
            }
            let expected_flag = mul(b, &selected, &d.base_is_noid).scale(flat_const(1u128 << 88));
            when_eq(b, &selected, &p[7], &expected_flag);
            let base_principal = mul(
                b,
                &d.base_is_noid.add_const(F128::ONE),
                &reserves.amount.value,
            );
            let principals = [base_principal, reserves.creation_id.value.clone()];
            for k in 0..2 {
                let incoming = bits(b, &s.amounts[k], inventory.sum_width);
                let outgoing = bits(b, &s.amounts[3 + k], inventory.sum_width);
                let principal = mul(b, &selected, &principals[k]);
                let principal = bits(b, &principal, inventory.sum_width);
                let total = checked_add(b, &outgoing, &principal);
                when_eq(b, &selected, &pack(&incoming), &pack(&total));
            }
            let total = bits(b, &shares.amount.value, 64);
            let locked = (0..64)
                .map(|j| {
                    selected.scale(flat_const((u128::from(MARKET_MIN_LOCKED_SHARES) >> j) & 1))
                })
                .collect::<Vec<_>>();
            let selected_total = total
                .iter()
                .map(|v| mul(b, &selected, v))
                .collect::<Vec<_>>();
            let owned = pack(&checked_subtract(b, &selected_total, &locked));
            let actual = mul(b, &selected, &s.amounts[2]);
            pin_eq(b, &actual, &owned);
        }
        pin_eq(b, &found, live);
    }
    for c in controls {
        let mut selected = LinExpr::zero();
        for (i, h) in headers.iter().enumerate() {
            let same = is_zero(b, &c.header_page.add(&h.header.header_page));
            selected = selected.add(&mul(b, &same, &flags[i]));
        }
        let selected = mul(b, &selected, &c.is_output);
        let selected = mul(b, &selected, &c.arithmetic.pool);
        let packed = split_packed_input_value(b, &c.fields[3]);
        let shares = packed.amount.bits[..63]
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        bind_bootstrap_share_root(b, &selected, &shares, &c.arithmetic.remainder);
    }
}
