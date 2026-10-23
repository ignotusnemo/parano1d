// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Atomic fixed-price NFT purchases over exact listing incarnations.

use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::range_check_bits;
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_definitions::FinancialDefinitionsTrace;
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_tx::native_assets::{nft_market::NFT_FEE_CREDIT, NativeKind};

fn eq_when(b: &mut FieldR1csBuilder, live: &LinExpr, a: &LinExpr, c: &LinExpr) {
    let bad = mul(b, live, &a.add(c));
    pin_zero(b, &bad);
}

fn unique(b: &mut FieldR1csBuilder, seen: &LinExpr, next: &LinExpr) -> LinExpr {
    let repeated = mul(b, seen, next);
    pin_zero(b, &repeated);
    seen.add(next)
}

/// The enclosing relation supplies complete body actions, exact definitions,
/// State consumption, buyer Owner authorization, NOID conservation and fees.
/// Output ordinals are seller payment, NFT and optional buyer change.
pub fn bind_financial_listing_purchase(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialNativeHeaderTrace],
    height: &LinExpr,
) {
    assert_eq!(actions.len(), definitions.actions.len());
    let height_bits = range_check_bits(b, height, 64)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    for header in headers {
        let live = &header.metadata.financial[FINANCIAL_OPERATION_CODES
            .iter()
            .position(|&code| code == 65)
            .unwrap()];
        let mut seen = std::array::from_fn::<_, 4, _>(|_| LinExpr::zero());
        let mut source: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        let mut item = source.clone();
        let mut definition: [LinExpr; 8] = std::array::from_fn(|_| LinExpr::zero());
        let mut definition_root = [LinExpr::zero(), LinExpr::zero()];
        let mut seller_root = definition_root.clone();
        let mut seller_value = LinExpr::zero();
        for (action, selected_definition) in actions.iter().zip(&definitions.actions) {
            let same = is_zero(b, &action.header_page.add(&header.header.header_page));
            let group = mul(b, &same, &action.live);
            let group = mul(b, &group, live);
            let input = mul(b, &group, &action.is_output.add_const(F128::ONE));
            let output = mul(b, &group, &action.is_output);
            let listing = mul(b, &input, &action.native);
            seen[0] = unique(b, &seen[0], &listing);
            eq_when(
                b,
                &listing,
                action.opening.commitment.selector(NativeKind::NftListing),
                &LinExpr::constant(F128::ONE),
            );
            eq_when(
                b,
                &listing,
                &selected_definition.listing,
                &LinExpr::constant(F128::ONE),
            );
            eq_when(b, &listing, &action.slot, &header.metadata.read_slot);
            let value = split_packed_input_value(b, &action.packed_value);
            eq_when(
                b,
                &listing,
                &value.creation_id.value,
                &header.metadata.read_creation_id,
            );
            for lane in 0..2 {
                eq_when(
                    b,
                    &listing,
                    &action.root[lane],
                    &header.metadata.read_root[lane],
                );
                let ordinary = mul(b, &input, &action.native.add_const(F128::ONE));
                eq_when(
                    b,
                    &ordinary,
                    &action.root[lane],
                    &header.header.authority[lane],
                );
                definition_root[lane] =
                    definition_root[lane].add(&mul(b, &listing, &selected_definition.root[lane]));
            }
            for i in 0..12 {
                source[i] = source[i].add(&mul(b, &listing, &action.opening.fields[i]));
            }
            for i in 0..8 {
                definition[i] =
                    definition[i].add(&mul(b, &listing, &selected_definition.fields[i]));
            }
            let positions =
                [0u128, 1, 2].map(|i| is_zero(b, &action.ordinal.add_const(flat_const(i))));
            let seller = mul(b, &output, &positions[0]);
            let nft = mul(b, &output, &positions[1]);
            let change = mul(b, &output, &positions[2]);
            pin_eq(b, &output, &seller.add(&nft).add(&change));
            let native_output = mul(b, &output, &action.native);
            pin_eq(b, &native_output, &nft);
            seen[1] = unique(b, &seen[1], &seller);
            seen[2] = unique(b, &seen[2], &nft);
            seen[3] = unique(b, &seen[3], &change);
            eq_when(
                b,
                &nft,
                action.opening.commitment.selector(NativeKind::NftItem),
                &LinExpr::constant(F128::ONE),
            );
            seller_value = seller_value.add(&mul(b, &seller, &value.amount.value));
            for lane in 0..2 {
                seller_root[lane] = seller_root[lane].add(&mul(b, &seller, &action.root[lane]));
                eq_when(
                    b,
                    &change,
                    &action.root[lane],
                    &header.header.authority[lane],
                );
            }
            for i in 0..12 {
                item[i] = item[i].add(&mul(b, &nft, &action.opening.fields[i]));
            }
        }
        for count in &seen[..3] {
            pin_eq(b, count, live);
        }
        let serial = split_packed_input_value(b, &definition[6]);
        let terms = split_packed_input_value(b, &definition[7]);
        let mut expected_source: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        expected_source[..2].clone_from_slice(&definition_root);
        expected_source[2..4].clone_from_slice(&definition[..2]);
        expected_source[4] = serial.amount.value.clone();
        let mut expected_item: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        expected_item[..2].clone_from_slice(&definition[..2]);
        for lane in 0..2 {
            expected_item[2 + lane] = mul(b, live, &header.header.authority[lane]);
            pin_eq(b, &seller_root[lane], &definition[2 + lane]);
        }
        expected_item[4..6].clone_from_slice(&definition[4..6]);
        expected_item[6] = serial.amount.value;
        for i in 0..12 {
            pin_eq(b, &source[i], &expected_source[i]);
            pin_eq(b, &item[i], &expected_item[i]);
        }
        let ask = terms.amount.bits.map(LinExpr::from_wire);
        let credit = (0..64)
            .map(|i| live.scale(flat_const((u128::from(NFT_FEE_CREDIT) >> i) & 1)))
            .collect::<Vec<_>>();
        let payment = pack(&checked_add(b, &ask, &credit));
        pin_eq(b, &seller_value, &payment);
        let expiry = terms.creation_id.bits.map(LinExpr::from_wire);
        let timely = less_than(b, &height_bits, &expiry);
        eq_when(b, live, &timely, &LinExpr::constant(F128::ONE));
    }
}
