// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical liquidity claim asset payouts and returned LP rights.

use super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_definitions::FinancialDefinitionsTrace;
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_tx::native_assets::NativeKind;
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn eq_when(b: &mut FieldR1csBuilder, flag: &LinExpr, a: &LinExpr, c: &LinExpr) {
    let bad = mul(b, flag, &a.add(c));
    pin_zero(b, &bad);
}
fn unique(b: &mut FieldR1csBuilder, seen: &LinExpr, flag: &LinExpr) -> LinExpr {
    let repeated = mul(b, seen, flag);
    pin_zero(b, &repeated);
    seen.add(flag)
}

struct Candidate {
    kind: NativeKind,
    live: LinExpr,
    noid: LinExpr,
    asset: [LinExpr; 2],
    owner: [LinExpr; 2],
    amount: LinExpr,
    rank: LinExpr,
}

/// Complete canonical actions, validated claim values, exact linked market
/// definitions and immutable-parent required fees compose in the financial
/// bank. Asset payouts follow the definition's canonical order, with NOID fee
/// change merged into a NOID base payout. Unlocked LP rights follow all assets.
pub fn bind_financial_liquidity_claims(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialNativeHeaderTrace],
    required_fees: &[LinExpr],
) {
    assert_eq!(headers.len(), required_fees.len());
    assert_eq!(headers.len(), definitions.headers.len());
    for ((h, required), definition) in headers.iter().zip(required_fees).zip(&definitions.headers) {
        let live = h.metadata.financial[FINANCIAL_OPERATION_CODES
            .iter()
            .position(|&c| c == 42)
            .unwrap()]
        .clone();
        eq_when(
            b,
            &live,
            &h.header.input_count,
            &LinExpr::constant(F128::ONE),
        );
        eq_when(b, &live, &h.header.fee, required);
        let mut fields: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        let (mut inputs, mut input_slot) = (LinExpr::zero(), LinExpr::zero());
        let mut outputs = Vec::new();
        for a in actions {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let group = mul(b, &same, &a.live);
            let group = mul(b, &group, &live);
            let input = mul(b, &group, &a.is_output.add_const(F128::ONE));
            let output = mul(b, &group, &a.is_output);
            inputs = unique(b, &inputs, &input);
            input_slot = input_slot.add(&mul(b, &input, &a.slot));
            eq_when(b, &input, &a.native, &LinExpr::constant(F128::ONE));
            eq_when(
                b,
                &input,
                a.opening
                    .commitment
                    .selector(NativeKind::MarketLiquidityClaim),
                &LinExpr::constant(F128::ONE),
            );
            for j in 0..12 {
                fields[j] = fields[j].add(&mul(b, &input, &a.opening.fields[j]));
            }
            outputs.push(output);
        }
        pin_eq(b, &inputs, &live);

        eq_when(b, &live, &definition.market, &LinExpr::constant(F128::ONE));
        for lane in 0..2 {
            eq_when(b, &live, &fields[2 + lane], &definition.root[lane]);
        }
        let quantities = split_packed_input_value(b, &fields[6]);
        let base = quantities
            .amount
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let quote = quantities
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let rights = split_packed_input_value(b, &fields[7]);
        let shares = rights.amount.value;
        let mut credit = rights.creation_id.bits[..63]
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        credit.push(LinExpr::zero());
        let base_noid = LinExpr::from_wire(rights.creation_id.bits[63]);
        let expected_noid = mul(b, &live, &definition.base_is_noid);
        pin_eq(b, &base_noid, &expected_noid);
        let fee = mul(b, &live, &h.header.fee);
        let fee = bits(b, &fee, 64);
        let affordable = less_than(b, &fee, &credit);
        eq_when(b, &live, &affordable, &LinExpr::constant(F128::ONE));
        let change = checked_subtract(b, &credit, &fee);
        let extra = change
            .iter()
            .map(|v| mul(b, &base_noid, v))
            .collect::<Vec<_>>();
        let amount_a = pack(&checked_add(b, &base, &extra));
        let amount_b = pack(&quote);
        let amount_c = pack(
            &change
                .iter()
                .map(|v| mul(b, &live.add(&base_noid), v))
                .collect::<Vec<_>>(),
        );
        let a_live = is_zero(b, &amount_a).add_const(F128::ONE);
        let b_live = is_zero(b, &amount_b).add_const(F128::ONE);
        let c_live = is_zero(b, &amount_c).add_const(F128::ONE);
        let lp_live = is_zero(b, &shares).add_const(F128::ONE);
        let b_rank_bits = checked_add(
            b,
            &[a_live.clone(), LinExpr::zero()],
            &[c_live.clone(), LinExpr::zero()],
        );
        let b_rank = pack(&b_rank_bits);
        let lp_rank = pack(&checked_add(
            b,
            &b_rank_bits,
            &[b_live.clone(), LinExpr::zero()],
        ));
        let owner = [fields[4].clone(), fields[5].clone()];
        let candidates = [
            Candidate {
                kind: NativeKind::TokenBalance,
                live: a_live,
                noid: base_noid,
                asset: [definition.fields[2].clone(), definition.fields[3].clone()],
                owner: owner.clone(),
                amount: amount_a,
                rank: c_live.clone(),
            },
            Candidate {
                kind: NativeKind::TokenBalance,
                live: b_live,
                noid: LinExpr::zero(),
                asset: [definition.fields[4].clone(), definition.fields[5].clone()],
                owner: owner.clone(),
                amount: amount_b,
                rank: b_rank,
            },
            Candidate {
                kind: NativeKind::TokenBalance,
                live: c_live,
                noid: LinExpr::constant(F128::ONE),
                asset: [LinExpr::zero(), LinExpr::zero()],
                owner: owner.clone(),
                amount: amount_c,
                rank: LinExpr::zero(),
            },
            Candidate {
                kind: NativeKind::MarketLiquidity,
                live: lp_live,
                noid: LinExpr::zero(),
                asset: [fields[2].clone(), fields[3].clone()],
                owner,
                amount: shares,
                rank: lp_rank,
            },
        ];
        let mut count = vec![LinExpr::zero(); 3];
        for c in &candidates {
            count = checked_add(
                b,
                &count,
                &[c.live.clone(), LinExpr::zero(), LinExpr::zero()],
            );
        }
        eq_when(b, &live, &h.header.output_count, &pack(&count));
        let mut covered = vec![LinExpr::zero(); actions.len()];
        let mut slots = Vec::new();
        for c in &candidates {
            let token = mul(b, &c.live, &c.noid.add_const(F128::ONE));
            let ordinary = mul(b, &c.live, &c.noid);
            let (mut found, mut packed, mut native, mut kind, mut slot) = (
                LinExpr::zero(),
                LinExpr::zero(),
                LinExpr::zero(),
                LinExpr::zero(),
                LinExpr::zero(),
            );
            let mut actual: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
            let mut root = [LinExpr::zero(), LinExpr::zero()];
            for (i, (a, output)) in actions.iter().zip(&outputs).enumerate() {
                let ordinal = is_zero(b, &a.ordinal.add(&c.rank));
                let hit = mul(b, &ordinal, output);
                let hit = mul(b, &hit, &c.live);
                found = unique(b, &found, &hit);
                covered[i] = unique(b, &covered[i], &hit);
                packed = packed.add(&mul(b, &hit, &a.packed_value));
                native = native.add(&mul(b, &hit, &a.native));
                kind = kind.add(&mul(b, &hit, a.opening.commitment.selector(c.kind)));
                slot = slot.add(&mul(b, &hit, &a.slot));
                for j in 0..12 {
                    actual[j] = actual[j].add(&mul(b, &hit, &a.opening.fields[j]));
                }
                for j in 0..2 {
                    root[j] = root[j].add(&mul(b, &hit, &a.root[j]));
                }
            }
            pin_eq(b, &found, &c.live);
            pin_eq(b, &native, &token);
            pin_eq(b, &kind, &token);
            let value = split_packed_input_value(b, &packed);
            let expected_amount = mul(b, &ordinary, &c.amount);
            pin_eq(b, &value.amount.value, &expected_amount);
            for j in 0..2 {
                eq_when(b, &ordinary, &root[j], &c.owner[j]);
                let asset = mul(b, &token, &c.asset[j]);
                pin_eq(b, &actual[j], &asset);
                let owner = mul(b, &token, &c.owner[j]);
                pin_eq(b, &actual[2 + j], &owner);
            }
            let units = mul(b, &token, &c.amount);
            pin_eq(b, &actual[4], &units);
            for tail in &actual[5..] {
                pin_zero(b, tail);
            }
            let same_input = is_zero(b, &slot.add(&input_slot));
            let repeated = mul(b, &c.live, &same_input);
            pin_zero(b, &repeated);
            slots.push(slot);
        }
        for (i, slot) in slots.iter().enumerate() {
            for j in 0..i {
                let same = is_zero(b, &slot.add(&slots[j]));
                let both = mul(b, &candidates[i].live, &candidates[j].live);
                let repeated = mul(b, &both, &same);
                pin_zero(b, &repeated);
            }
        }
        for (seen, output) in covered.iter().zip(outputs) {
            pin_eq(b, seen, &output);
        }
    }
}
