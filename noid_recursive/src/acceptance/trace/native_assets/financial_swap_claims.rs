// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical swap claim payouts and exact beneficiary aggregation.

use super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, less_than, pack};
use super::financial_actions::FinancialActionTrace;
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
fn pair_zero(b: &mut FieldR1csBuilder, pair: &[LinExpr; 2]) -> LinExpr {
    let a = is_zero(b, &pair[0]);
    let c = is_zero(b, &pair[1]);
    mul(b, &a, &c)
}
fn digest_order(b: &mut FieldR1csBuilder, pair: &[LinExpr; 2]) -> Vec<LinExpr> {
    let raw = pair
        .iter()
        .flat_map(|x| bits(b, x, 128))
        .collect::<Vec<_>>();
    (0..32)
        .rev()
        .flat_map(|byte| raw[byte * 8..byte * 8 + 8].iter().cloned())
        .collect()
}
fn add_count(b: &mut FieldR1csBuilder, a: &LinExpr, c: &LinExpr) -> LinExpr {
    pack(&checked_add(
        b,
        &[a.clone(), LinExpr::zero()],
        &[c.clone(), LinExpr::zero()],
    ))
}
struct Candidate {
    live: LinExpr,
    noid: LinExpr,
    asset: [LinExpr; 2],
    owner: [LinExpr; 2],
    amount: LinExpr,
    rank: LinExpr,
}

/// The shared financial bank supplies complete canonical actions, validated
/// claim values and exact required fees from the immutable parent context.
/// Each payout follows bytewise (asset, owner) order, merges matching NOID
/// recipients and creates only unlocked token balances or ordinary NOID.
pub fn bind_financial_swap_claims(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    headers: &[FinancialNativeHeaderTrace],
    required_fees: &[LinExpr],
) {
    assert_eq!(headers.len(), required_fees.len());
    for (h, required) in headers.iter().zip(required_fees) {
        let live = h.metadata.financial[FINANCIAL_OPERATION_CODES
            .iter()
            .position(|&c| c == 43)
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
                a.opening.commitment.selector(NativeKind::MarketClaim),
                &LinExpr::constant(F128::ONE),
            );
            for j in 0..12 {
                fields[j] = fields[j].add(&mul(b, &input, &a.opening.fields[j]));
            }
            outputs.push(output);
        }
        pin_eq(b, &inputs, &live);
        let quantities = split_packed_input_value(b, &fields[10]);
        let refunds = quantities
            .amount
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let paid = quantities
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let credit = bits(b, &fields[11], 64);
        let fee = mul(b, &live, &h.header.fee);
        let fee = bits(b, &fee, 64);
        let affordable = less_than(b, &fee, &credit);
        eq_when(b, &live, &affordable, &LinExpr::constant(F128::ONE));
        let change = checked_subtract(b, &credit, &fee);
        let input_asset = [fields[2].clone(), fields[3].clone()];
        let output_asset = [fields[4].clone(), fields[5].clone()];
        let payer = [fields[6].clone(), fields[7].clone()];
        let recipient = [fields[8].clone(), fields[9].clone()];
        let input_noid = pair_zero(b, &input_asset);
        let output_noid = pair_zero(b, &output_asset);
        let owner_delta = [payer[0].add(&recipient[0]), payer[1].add(&recipient[1])];
        let same_owner = pair_zero(b, &owner_delta);
        let merge_refund = mul(b, &live, &input_noid);
        let merge_payment = mul(b, &output_noid, &same_owner);
        let merge_payment = mul(b, &live, &merge_payment);
        let separate = live.add(&merge_refund).add(&merge_payment);
        let extra_a = change
            .iter()
            .map(|v| mul(b, &merge_refund, v))
            .collect::<Vec<_>>();
        let amount_a = pack(&checked_add(b, &refunds, &extra_a));
        let extra_b = change
            .iter()
            .map(|v| mul(b, &merge_payment, v))
            .collect::<Vec<_>>();
        let amount_b = pack(&checked_add(b, &paid, &extra_b));
        let amount_c = pack(
            &change
                .iter()
                .map(|v| mul(b, &separate, v))
                .collect::<Vec<_>>(),
        );
        let a_live = is_zero(b, &amount_a).add_const(F128::ONE);
        let b_live = is_zero(b, &amount_b).add_const(F128::ONE);
        let c_live = is_zero(b, &amount_c).add_const(F128::ONE);
        let a_key = digest_order(b, &input_asset);
        let b_key = digest_order(b, &output_asset);
        let asset_less = less_than(b, &a_key, &b_key);
        let payer_key = digest_order(b, &payer);
        let recipient_key = digest_order(b, &recipient);
        let owner_less = less_than(b, &payer_key, &recipient_key);
        // A separate fee-credit payout has the zero NOID asset. It precedes
        // every non-NOID asset; the only remaining tie is the NOID recipient.
        let c_before_b = output_noid
            .add_const(F128::ONE)
            .add(&mul(b, &output_noid, &owner_less));
        let b_before_c = mul(b, &output_noid, &owner_less.add_const(F128::ONE));
        let a_rank_left = mul(b, &b_live, &asset_less.add_const(F128::ONE));
        let a_rank = add_count(b, &a_rank_left, &c_live);
        let b_rank_left = mul(b, &a_live, &asset_less);
        let b_rank_right = mul(b, &c_live, &c_before_b);
        let b_rank = add_count(b, &b_rank_left, &b_rank_right);
        let c_rank = mul(b, &b_live, &b_before_c);
        let candidates = [
            Candidate {
                live: a_live,
                noid: input_noid,
                asset: input_asset,
                owner: payer.clone(),
                amount: amount_a,
                rank: a_rank,
            },
            Candidate {
                live: b_live,
                noid: output_noid,
                asset: output_asset,
                owner: recipient,
                amount: amount_b,
                rank: b_rank,
            },
            Candidate {
                live: c_live,
                noid: LinExpr::constant(F128::ONE),
                asset: [LinExpr::zero(), LinExpr::zero()],
                owner: payer,
                amount: amount_c,
                rank: c_rank,
            },
        ];
        let mut count = vec![LinExpr::zero(); 2];
        for c in &candidates {
            count = checked_add(b, &count, &[c.live.clone(), LinExpr::zero()]);
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
                kind = kind.add(&mul(
                    b,
                    &hit,
                    a.opening.commitment.selector(NativeKind::TokenBalance),
                ));
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
