// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Owner funding of native NFT listings and fixed-beneficiary offers.

use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, less_than};
use super::financial_actions::FinancialActionTrace;
use super::financial_definitions::FinancialDefinitionsTrace;
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
fn unique(b: &mut FieldR1csBuilder, seen: &LinExpr, flag: &LinExpr) -> LinExpr {
    let repeated = mul(b, seen, flag);
    pin_zero(b, &repeated);
    seen.add(flag)
}

/// The enclosing bank supplies complete canonical actions, validated carrier
/// values, exact linked definitions, authenticated Owner statements, NOID
/// conservation and minimum fees. Listing identity derives from the actual
/// NFT incarnation. Offer funding binds the designated ordinary input's id.
pub fn bind_financial_nft_funding(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialNativeHeaderTrace],
    height: &LinExpr,
) {
    assert_eq!(definitions.headers.len(), headers.len());
    let height = bits(b, height, 64);
    for (h, d) in headers.iter().zip(&definitions.headers) {
        let flag = |code| {
            h.metadata.financial[FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&c| c == code)
                .unwrap()]
            .clone()
        };
        let listing = flag(64);
        let offer = flag(67);
        let live = listing.add(&offer);
        eq_when(b, &listing, &d.listing, &LinExpr::constant(F128::ONE));
        let (mut item_count, mut carrier_count, mut funding_count) =
            (LinExpr::zero(), LinExpr::zero(), LinExpr::zero());
        let mut item: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        let mut carrier = item.clone();
        let (mut item_value, mut funding_value) = (LinExpr::zero(), LinExpr::zero());
        let mut groups = Vec::new();
        for a in actions {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let group = mul(b, &same, &a.live);
            let group = mul(b, &group, &live);
            groups.push(group.clone());
            let input = mul(b, &group, &a.is_output.add_const(F128::ONE));
            let output = mul(b, &group, &a.is_output);
            let ordinary = mul(b, &group, &a.native.add_const(F128::ONE));
            for j in 0..2 {
                eq_when(b, &ordinary, &a.root[j], &h.header.authority[j]);
            }
            let native_input = mul(b, &input, &a.native);
            let allowed = mul(
                b,
                &listing,
                a.opening.commitment.selector(NativeKind::NftItem),
            );
            eq_when(b, &native_input, &allowed, &LinExpr::constant(F128::ONE));
            item_count = unique(b, &item_count, &native_input);
            item_value = item_value.add(&mul(b, &native_input, &a.packed_value));
            let native_output = mul(b, &output, &a.native);
            let listing_output = mul(
                b,
                &listing,
                a.opening.commitment.selector(NativeKind::NftListing),
            );
            let offer_output = mul(
                b,
                &offer,
                a.opening.commitment.selector(NativeKind::NftOffer),
            );
            eq_when(
                b,
                &native_output,
                &listing_output.add(&offer_output),
                &LinExpr::constant(F128::ONE),
            );
            carrier_count = unique(b, &carrier_count, &native_output);
            for j in 0..12 {
                item[j] = item[j].add(&mul(b, &native_input, &a.opening.fields[j]));
                carrier[j] = carrier[j].add(&mul(b, &native_output, &a.opening.fields[j]));
            }
            let designated = mul(b, &input, &a.funding);
            let designated = mul(b, &designated, &offer);
            funding_count = unique(b, &funding_count, &designated);
            eq_when(b, &designated, &a.native, &LinExpr::zero());
            funding_value = funding_value.add(&mul(b, &designated, &a.packed_value));
        }
        pin_eq(b, &item_count, &listing);
        pin_eq(b, &carrier_count, &live);
        pin_eq(b, &funding_count, &offer);
        for i in 0..actions.len() {
            for j in i + 1..actions.len() {
                let both = mul(b, &groups[i], &groups[j]);
                let same = is_zero(b, &actions[i].slot.add(&actions[j].slot));
                let duplicate = mul(b, &both, &same);
                pin_zero(b, &duplicate);
            }
        }
        let source = split_packed_input_value(b, &item_value);
        let identity = split_packed_input_value(b, &item[6]);
        let definition_identity = split_packed_input_value(b, &d.fields[6]);
        let terms = split_packed_input_value(b, &d.fields[7]);
        for j in 0..6 {
            eq_when(b, &listing, &item[j], &d.fields[j]);
        }
        for j in 0..2 {
            eq_when(b, &listing, &item[2 + j], &h.header.authority[j]);
        }
        eq_when(
            b,
            &listing,
            &identity.amount.value,
            &definition_identity.amount.value,
        );
        eq_when(
            b,
            &listing,
            &source.creation_id.value,
            &definition_identity.creation_id.value,
        );
        let unlock = identity
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let early = less_than(b, &height, &unlock);
        let early = mul(b, &listing, &early);
        pin_zero(b, &early);
        let selected_height = height
            .iter()
            .map(|v| mul(b, &listing, v))
            .collect::<Vec<_>>();
        let mut delta = vec![LinExpr::zero(); 64];
        delta[0] = listing.clone();
        let next = checked_add(b, &selected_height, &delta);
        let expiry = terms
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let valid = less_than(b, &next, &expiry);
        eq_when(b, &listing, &valid, &LinExpr::constant(F128::ONE));
        let mut expected: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        for j in 0..2 {
            expected[j] = mul(b, &listing, &d.root[j]);
            expected[2 + j] = mul(b, &listing, &d.fields[j]);
        }
        expected[4] = mul(b, &listing, &definition_identity.amount.value);
        for j in 0..12 {
            eq_when(b, &listing, &carrier[j], &expected[j]);
        }
        for j in 0..2 {
            eq_when(b, &offer, &carrier[2 + j], &h.header.authority[j]);
        }
        let offer_identity = split_packed_input_value(b, &carrier[6]);
        let offer_terms = split_packed_input_value(b, &carrier[7]);
        let funding = split_packed_input_value(b, &funding_value);
        eq_when(
            b,
            &offer,
            &offer_terms.creation_id.value,
            &funding.creation_id.value,
        );
        let expiry = offer_identity
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let valid = less_than(b, &height, &expiry);
        eq_when(b, &offer, &valid, &LinExpr::constant(F128::ONE));
    }
}
