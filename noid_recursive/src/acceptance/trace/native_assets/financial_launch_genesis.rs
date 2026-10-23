// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact fixed-supply launch genesis and prefunded holder reserves.

use super::super::{
    const_block, flat_const, mul, pin_eq, pin_zero, poseidon2b_permute, FieldR1csBuilder, LinExpr,
    F128,
};
use super::arithmetic::range_check_bits;
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_controls::bind_financial_control_arithmetic;
use super::financial_definitions::{scale_bits, FinancialDefinitionsTrace};
use super::financial_inventory_scan::{bind_financial_inventory_scan, FinancialInventoryRowTrace};
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_poseidon2b::native::{capacity_iv, DomainTag};
use noid_tx::native_assets::NativeKind;
fn when_eq(b: &mut FieldR1csBuilder, f: &LinExpr, x: &LinExpr, y: &LinExpr) {
    let bad = mul(b, f, &x.add(y));
    pin_zero(b, &bad);
}
fn unique(b: &mut FieldR1csBuilder, seen: &LinExpr, f: &LinExpr) -> LinExpr {
    let bad = mul(b, seen, f);
    pin_zero(b, &bad);
    seen.add(f)
}
fn hash(b: &mut FieldR1csBuilder, tag: DomainTag, fields: &[LinExpr]) -> [LinExpr; 2] {
    assert!(fields.len().is_multiple_of(2));
    let iv = capacity_iv(tag);
    let mut s = [
        LinExpr::zero(),
        LinExpr::zero(),
        const_block(iv[0]),
        const_block(iv[1]),
    ];
    for pair in fields.chunks_exact(2) {
        s[0] = s[0].add(&pair[0]);
        s[1] = s[1].add(&pair[1]);
        s = poseidon2b_permute(b, s);
    }
    [s[0].clone(), s[1].clone()]
}
fn scale_1000(b: &mut FieldR1csBuilder, value: &[LinExpr]) -> Vec<LinExpr> {
    assert_eq!(value.len(), 64);
    let mut total = vec![LinExpr::zero(); 64];
    for shift in 0..10 {
        if (1000 >> shift) & 1 == 0 {
            continue;
        }
        let mut term = vec![LinExpr::zero(); 64];
        for (i, v) in value.iter().enumerate() {
            if i + shift < 64 {
                term[i + shift] = v.clone();
            } else {
                pin_zero(b, v);
            }
        }
        total = checked_add(b, &total, &term);
    }
    total
}

/// Complete physical actions and validated carriers/header definitions compose
/// with the authenticated Owner, funding ordinal, State and NOID fee relation.
/// A launch has one token definition, minimum reserve and market custody,
/// plus its optional initial creator purchase. The supply stays fixed.
pub fn bind_financial_launch_genesis(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialNativeHeaderTrace],
) {
    assert_eq!(headers.len(), definitions.headers.len());
    assert!(!headers.is_empty() && !actions.is_empty());
    let flags = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let f = h.metadata.financial[FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&x| x == 48)
                .unwrap()]
            .clone();
            when_eq(
                b,
                &f,
                &definitions.headers[i].launch,
                &LinExpr::constant(F128::ONE),
            );
            f
        })
        .collect::<Vec<_>>();
    let mut slots = Vec::with_capacity(actions.len());
    for a in actions {
        let mut live = LinExpr::zero();
        for (i, h) in headers.iter().enumerate() {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let selected = mul(b, &same, &flags[i]);
            live = live.add(&mul(b, &selected, &a.live));
        }
        slots.push(FinancialInventoryRowTrace {
            live: live.clone(),
            group: mul(b, &live, &a.header_page),
            slot: mul(b, &live, &a.slot),
            amounts: std::array::from_fn(|_| LinExpr::zero()),
            singleton: LinExpr::zero(),
            payload: std::array::from_fn(|_| LinExpr::zero()),
        });
    }
    let _ = bind_financial_inventory_scan(b, &slots, headers.len());
    for (i, h) in headers.iter().enumerate() {
        let live = &flags[i];
        let d = &definitions.headers[i];
        let mut seen: [LinExpr; 5] = std::array::from_fn(|_| LinExpr::zero());
        let mut f: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        let mut r = f.clone();
        let mut s = f.clone();
        let mut p = f.clone();
        let mut purchase = f.clone();
        let mut launch = LinExpr::zero();
        let mut pool = LinExpr::zero();
        let mut froot = [LinExpr::zero(), LinExpr::zero()];
        let mut funding_slot = LinExpr::zero();
        let mut funding_value = LinExpr::zero();
        let mut funding_root = froot.clone();
        for (action_index, a) in actions.iter().enumerate() {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let group = mul(b, &same, &a.live);
            let group = mul(b, &group, live);
            let input = mul(b, &group, &a.is_output.add_const(F128::ONE));
            let output = mul(b, &group, &a.is_output);
            let native_input = mul(b, &input, &a.native);
            pin_zero(b, &native_input);
            let ordinary = mul(b, &group, &a.native.add_const(F128::ONE));
            for j in 0..2 {
                when_eq(b, &ordinary, &a.root[j], &a.authority[j]);
            }
            let selectors = [
                NativeKind::FungibleDefinition,
                NativeKind::TokenReserve,
                NativeKind::LaunchState,
                NativeKind::MarketPool,
                NativeKind::TokenBalance,
            ]
            .map(|kind| mul(b, &output, a.opening.commitment.selector(kind)));
            let native_output = mul(b, &output, &a.native);
            pin_eq(
                b,
                &native_output,
                &selectors.iter().fold(LinExpr::zero(), |sum, x| sum.add(x)),
            );
            seen[0] = unique(b, &seen[0], &selectors[0]);
            seen[1] = unique(b, &seen[1], &selectors[1]);
            seen[2] = unique(b, &seen[2], &selectors[2].add(&selectors[3]));
            seen[3] = unique(b, &seen[3], &selectors[4]);
            launch = launch.add(&selectors[2]);
            pool = pool.add(&selectors[3]);
            for j in 0..12 {
                f[j] = f[j].add(&mul(b, &selectors[0], &a.opening.fields[j]));
                r[j] = r[j].add(&mul(b, &selectors[1], &a.opening.fields[j]));
                s[j] = s[j].add(&mul(b, &selectors[2], &a.opening.fields[j]));
                p[j] = p[j].add(&mul(b, &selectors[3], &a.opening.fields[j]));
                purchase[j] = purchase[j].add(&mul(b, &selectors[4], &a.opening.fields[j]));
            }
            for j in 0..2 {
                froot[j] = froot[j].add(&mul(b, &selectors[0], &a.root[j]));
            }
            let funding = mul(b, &group, &a.funding);
            seen[4] = unique(b, &seen[4], &funding);
            when_eq(b, &funding, &a.is_output, &LinExpr::zero());
            when_eq(b, &funding, &a.native, &LinExpr::zero());
            funding_slot = funding_slot.add(&mul(b, &funding, &a.slot));
            funding_value = funding_value.add(&mul(b, &funding, &a.packed_value));
            for j in 0..2 {
                funding_root[j] = funding_root[j].add(&mul(b, &funding, &a.root[j]));
            }
            let market = &definitions.actions[action_index];
            when_eq(
                b,
                &selectors[3],
                &market.market,
                &LinExpr::constant(F128::ONE),
            );
            for j in 0..2 {
                when_eq(b, &selectors[3], &market.fields[j], &d.fields[2 + j]);
                when_eq(b, &selectors[3], &market.fields[2 + j], &LinExpr::zero());
                when_eq(b, &selectors[3], &market.fields[4 + j], &d.fields[j]);
            }
        }
        for k in [0, 1, 2, 4] {
            pin_eq(b, &seen[k], live);
        }
        let supply = split_packed_input_value(b, &f[4]);
        pin_eq(b, &supply.creation_id.value, live);
        let definition_word = mul(b, live, &d.fields[4]);
        let definition_supply = split_packed_input_value(b, &definition_word);
        pin_eq(b, &supply.amount.value, &definition_supply.amount.value);
        let reserve = split_packed_input_value(b, &r[2]);
        pin_eq(b, &reserve.creation_id.value, &supply.amount.value);
        pin_eq(b, &r[3], &supply.amount.value);
        let reserve_bits = reserve
            .amount
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let backed_supply = pack(&scale_1000(b, &reserve_bits));
        pin_eq(b, &backed_supply, &supply.amount.value);
        for j in 0..2 {
            let actor = mul(b, live, &h.header.authority[j]);
            pin_eq(b, &f[2 + j], &actor);
            pin_eq(b, &funding_root[j], &actor);
            pin_eq(b, &r[j], &f[j]);
            let asset = mul(b, live, &d.fields[j]);
            pin_eq(b, &f[j], &asset);
            let definition_root = mul(b, live, &d.fields[5 + j]);
            pin_eq(b, &froot[j], &definition_root);
            pin_eq(b, &r[4 + j], &froot[j]);
            let launch_root = mul(b, &launch, &d.root[j]);
            pin_eq(b, &s[j], &launch_root);
            when_eq(b, &seen[3], &purchase[j], &f[j]);
            when_eq(b, &seen[3], &purchase[2 + j], &f[2 + j]);
        }
        let bought = split_packed_input_value(b, &purchase[4]);
        pin_zero(b, &bought.creation_id.value);
        let no_purchase = is_zero(b, &bought.amount.value);
        let expected_purchase = mul(b, live, &no_purchase.add_const(F128::ONE));
        pin_eq(b, &seen[3], &expected_purchase);
        let arithmetic =
            bind_financial_control_arithmetic(b, &LinExpr::zero(), &launch, &s, &d.fields[4]);
        when_eq(
            b,
            &launch,
            &bought.amount.value,
            &pack(&arithmetic.sold_units),
        );
        for value in &s[3..] {
            pin_zero(b, value);
        }
        let pool_state = split_packed_input_value(b, &p[2]);
        let pool_shares = split_packed_input_value(b, &p[3]);
        let pool_supply = mul(b, &pool, &supply.amount.value);
        let quantity_bits = |wires: &[noid_ivc_core::field_circuit::Wire]| {
            wires
                .iter()
                .copied()
                .map(LinExpr::from_wire)
                .collect::<Vec<_>>()
        };
        let cash_bits = quantity_bits(&pool_state.amount.bits);
        let inventory_bits = quantity_bits(&pool_state.creation_id.bits);
        let shares_bits = quantity_bits(&pool_shares.amount.bits);
        let scaled_cash = pack(&scale_bits(b, &cash_bits, 250, 64));
        pin_eq(b, &scaled_cash, &pool_supply);
        let pool_supply_bits = supply
            .amount
            .bits
            .iter()
            .copied()
            .map(|wire| mul(b, &pool, &LinExpr::from_wire(wire)))
            .collect::<Vec<_>>();
        let scaled_inventory = pack(&scale_bits(b, &inventory_bits, 5, 64));
        let twice_supply = pack(&scale_bits(b, &pool_supply_bits, 2, 64));
        pin_eq(b, &scaled_inventory, &twice_supply);
        let scaled_shares = pack(&scale_bits(b, &shares_bits, 25, 64));
        pin_eq(b, &scaled_shares, &pool_supply);
        pin_eq(b, &pool_shares.amount.value, &pool_shares.creation_id.value);
        let pool_purchase_bits = bought
            .amount
            .bits
            .iter()
            .copied()
            .map(|wire| mul(b, &pool, &LinExpr::from_wire(wire)))
            .collect::<Vec<_>>();
        let scaled_purchase = pack(&scale_bits(b, &pool_purchase_bits, 5, 64));
        let three_supply = pack(&scale_bits(b, &pool_supply_bits, 3, 64));
        pin_eq(b, &scaled_purchase, &three_supply);
        for value in &p[4..7] {
            pin_zero(b, value);
        }
        pin_eq(b, &p[7], &pool.scale(flat_const(1u128 << 88)));
        let funding = split_packed_input_value(b, &funding_value);
        for value in [&funding.amount.value, &funding.creation_id.value] {
            let zero = is_zero(b, value);
            let bad = mul(b, live, &zero);
            pin_zero(b, &bad);
        }
        let reserved = mul(
            b,
            &LinExpr::from_wire(funding.creation_id.bits[62]),
            &LinExpr::from_wire(funding.creation_id.bits[63]).add_const(F128::ONE),
        );
        pin_zero(b, &reserved);
        let slot_bits = range_check_bits(b, &funding_slot, 32)
            .into_iter()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let kind_and_slot = pack(&slot_bits).add(&live.scale(flat_const(1u128 << 32)));
        let mut identity: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        for j in 0..2 {
            identity[j] = mul(b, live, &h.header.chain[j]);
            identity[2 + j] = mul(b, live, &h.header.authority[j]);
            identity[6 + j] = f[2 + j].clone();
        }
        identity[4] = funding_value.clone();
        identity[5] = kind_and_slot;
        identity[8] = f[4].clone();
        identity[9] = f[5].clone();
        identity[10] = f[6].clone();
        let id = hash(b, DomainTag::new(b"NATID_21"), &identity);
        for j in 0..2 {
            let expected = mul(b, live, &id[j]);
            pin_eq(b, &f[j], &expected);
        }
        let market_fields = [
            identity[0].clone(),
            identity[1].clone(),
            identity[2].clone(),
            identity[3].clone(),
            funding_value,
            funding_slot,
            LinExpr::zero(),
            LinExpr::zero(),
            f[0].clone(),
            f[1].clone(),
        ];
        let market = hash(b, DomainTag::new(b"MKSEED21"), &market_fields);
        for j in 0..2 {
            when_eq(b, live, &d.fields[2 + j], &market[j]);
        }
    }
}
