// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact Owner-authorized NFT offer acceptance and cancellation.

use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_tx::native_assets::{nft_market::NFT_FEE_CREDIT, NativeKind};

fn bits(b: &mut FieldR1csBuilder, value: &LinExpr, width: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, value, width)
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
fn same_owner(b: &mut FieldR1csBuilder, a: &[LinExpr; 2], c: &[LinExpr; 2]) -> LinExpr {
    let lo = is_zero(b, &a[0].add(&c[0]));
    let hi = is_zero(b, &a[1].add(&c[1]));
    mul(b, &lo, &hi)
}

/// Complete canonical actions and validated carrier values compose in the
/// financial bank. The enclosing Owner statement authenticates authority and
/// the exact operation. The fee bank supplies the ordinary minimum fee floor.
/// Payout matching preserves the native Owner path's unordered output set.
pub fn bind_financial_nft_offers(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    headers: &[FinancialNativeHeaderTrace],
    height: &LinExpr,
) {
    let height = bits(b, height, 64);
    for h in headers {
        let flag = |code| {
            h.metadata.financial[FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&c| c == code)
                .unwrap()]
            .clone()
        };
        let accept = flag(68);
        let cancel = flag(69);
        let live = accept.add(&cancel);
        let input_count = cancel.add(&accept.scale(flat_const(2)));
        eq_when(b, &live, &h.header.input_count, &input_count);
        let mut offer: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        let mut item = offer.clone();
        let (mut offers, mut items, mut offer_slot, mut item_slot) = (
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
        );
        let mut outputs = Vec::new();
        for a in actions {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let group = mul(b, &same, &a.live);
            let group = mul(b, &group, &live);
            let input = mul(b, &group, &a.is_output.add_const(F128::ONE));
            let output = mul(b, &group, &a.is_output);
            outputs.push(output);
            let oi = mul(
                b,
                &input,
                a.opening.commitment.selector(NativeKind::NftOffer),
            );
            let ni = mul(
                b,
                &input,
                a.opening.commitment.selector(NativeKind::NftItem),
            );
            let ni = mul(b, &ni, &accept);
            pin_eq(b, &oi.add(&ni), &input);
            eq_when(b, &input, &a.native, &LinExpr::constant(F128::ONE));
            offers = unique(b, &offers, &oi);
            items = unique(b, &items, &ni);
            offer_slot = offer_slot.add(&mul(b, &oi, &a.slot));
            item_slot = item_slot.add(&mul(b, &ni, &a.slot));
            for j in 0..12 {
                offer[j] = offer[j].add(&mul(b, &oi, &a.opening.fields[j]));
                item[j] = item[j].add(&mul(b, &ni, &a.opening.fields[j]));
            }
        }
        pin_eq(b, &offers, &live);
        pin_eq(b, &items, &accept);
        let payer = [offer[2].clone(), offer[3].clone()];
        let seller = [item[2].clone(), item[3].clone()];
        let same = same_owner(b, &payer, &seller);
        for j in 0..2 {
            eq_when(b, &cancel, &h.header.authority[j], &payer[j]);
            eq_when(b, &accept, &h.header.authority[j], &seller[j]);
            eq_when(b, &accept, &offer[j], &item[j]);
        }
        let identity = split_packed_input_value(b, &offer[6]);
        let item_identity = split_packed_input_value(b, &item[6]);
        let any = is_zero(b, &identity.amount.value);
        let exact = mul(b, &accept, &any.add_const(F128::ONE));
        eq_when(
            b,
            &exact,
            &identity.amount.value,
            &item_identity.amount.value,
        );
        let expiry = identity
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let before = less_than(b, &height, &expiry);
        eq_when(b, &accept, &before, &LinExpr::constant(F128::ONE));
        let unlock = item_identity
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let locked = less_than(b, &height, &unlock);
        let locked = mul(b, &accept, &locked);
        pin_zero(b, &locked);
        let terms = split_packed_input_value(b, &offer[7]);
        let price = terms
            .amount
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let credit = (0..64)
            .map(|i| live.scale(flat_const((u128::from(NFT_FEE_CREDIT) >> i) & 1)))
            .collect::<Vec<_>>();
        let fee = mul(b, &live, &h.header.fee);
        let fee = bits(b, &fee, 64);
        let affordable = less_than(b, &fee, &credit);
        eq_when(b, &live, &affordable, &LinExpr::constant(F128::ONE));
        let refund = checked_subtract(b, &credit, &fee);
        let merged = mul(b, &accept, &same);
        let include_price = cancel.add(&merged);
        let extra = price
            .iter()
            .map(|v| mul(b, &include_price, v))
            .collect::<Vec<_>>();
        let amount_a = pack(&checked_add(b, &refund, &extra));
        let b_live = mul(b, &accept, &same.add_const(F128::ONE));
        let amount_b = pack(&price.iter().map(|v| mul(b, &b_live, v)).collect::<Vec<_>>());
        let count = checked_add(
            b,
            &[live.clone(), LinExpr::zero()],
            &[b_live.clone(), LinExpr::zero()],
        );
        let count = pack(&checked_add(b, &count, &[accept.clone(), LinExpr::zero()]));
        eq_when(b, &live, &h.header.output_count, &count);
        let (mut seen_a, mut seen_b, mut seen_nft) =
            (LinExpr::zero(), LinExpr::zero(), LinExpr::zero());
        let (mut slot_a, mut slot_b, mut slot_nft, mut value_a, mut value_b) = (
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
        );
        let mut next: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        for (a, output) in actions.iter().zip(&outputs) {
            let ordinary = mul(b, output, &a.native.add_const(F128::ONE));
            let pa = same_owner(b, &a.root, &payer);
            let pb = same_owner(b, &a.root, &seller);
            let pa = mul(b, &ordinary, &pa);
            let pb = mul(b, &ordinary, &pb);
            let pb = mul(b, &pb, &b_live);
            let nft = mul(b, output, &a.native);
            let nft = mul(b, &nft, &accept);
            pin_eq(b, &pa.add(&pb).add(&nft), output);
            eq_when(
                b,
                &nft,
                a.opening.commitment.selector(NativeKind::NftItem),
                &LinExpr::constant(F128::ONE),
            );
            seen_a = unique(b, &seen_a, &pa);
            seen_b = unique(b, &seen_b, &pb);
            seen_nft = unique(b, &seen_nft, &nft);
            slot_a = slot_a.add(&mul(b, &pa, &a.slot));
            slot_b = slot_b.add(&mul(b, &pb, &a.slot));
            slot_nft = slot_nft.add(&mul(b, &nft, &a.slot));
            value_a = value_a.add(&mul(b, &pa, &a.packed_value));
            value_b = value_b.add(&mul(b, &pb, &a.packed_value));
            for j in 0..12 {
                next[j] = next[j].add(&mul(b, &nft, &a.opening.fields[j]));
            }
        }
        pin_eq(b, &seen_a, &live);
        pin_eq(b, &seen_b, &b_live);
        pin_eq(b, &seen_nft, &accept);
        let value_a = split_packed_input_value(b, &value_a);
        let value_b = split_packed_input_value(b, &value_b);
        pin_eq(b, &value_a.amount.value, &amount_a);
        pin_eq(b, &value_b.amount.value, &amount_b);
        let slots = [
            (&live, &offer_slot),
            (&accept, &item_slot),
            (&live, &slot_a),
            (&b_live, &slot_b),
            (&accept, &slot_nft),
        ];
        for i in 0..slots.len() {
            for j in i + 1..slots.len() {
                let both = mul(b, slots[i].0, slots[j].0);
                let same = is_zero(b, &slots[i].1.add(slots[j].1));
                let duplicate = mul(b, &both, &same);
                pin_zero(b, &duplicate);
            }
        }
        let mut expected: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        for j in 0..2 {
            expected[j] = item[j].clone();
            expected[2 + j] = mul(b, &accept, &offer[4 + j]);
            expected[4 + j] = item[4 + j].clone();
        }
        expected[6] = item_identity.amount.value;
        for j in 0..12 {
            pin_eq(b, &next[j], &expected[j]);
        }
    }
}
