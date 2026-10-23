// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact listing cancellation and expired item recovery.

use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_definitions::FinancialDefinitionsTrace;
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::financial_values::FinancialCarrierValuesTrace;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_tx::native_assets::{
    market::MARKET_SETTLEMENT_WINDOW, nft_market::NFT_FEE_CREDIT, NativeKind,
};
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

/// Shared validated listing definitions bind item identity, seller and metadata.
/// Owner cancellation requires an idle listing and its exact seller authority.
/// Public recovery requires expiry and, for a frozen listing, its timeout.
/// The enclosing financial bank authenticates height, exact required fees,
/// complete actions and the Owner statement for cancellation.
pub fn bind_financial_listing_returns(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    values: &[FinancialCarrierValuesTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialNativeHeaderTrace],
    height: &LinExpr,
    required_fees: &[LinExpr],
) {
    assert_eq!(headers.len(), required_fees.len());
    assert_eq!(actions.len(), values.len());
    assert_eq!(actions.len(), definitions.actions.len());
    let height = bits(b, height, 64);
    for (h, required) in headers.iter().zip(required_fees) {
        let flag = |code| {
            h.metadata.financial[FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&c| c == code)
                .unwrap()]
            .clone()
        };
        let cancel = flag(66);
        let recover = flag(73);
        let live = cancel.add(&recover);
        eq_when(
            b,
            &live,
            &h.header.input_count,
            &LinExpr::constant(F128::ONE),
        );
        eq_when(
            b,
            &live,
            &h.header.output_count,
            &LinExpr::constant(flat_const(2)),
        );
        eq_when(b, &recover, &h.header.fee, required);
        let (mut inputs, mut noid_count, mut nft_count) =
            (LinExpr::zero(), LinExpr::zero(), LinExpr::zero());
        let mut fields: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        let mut definition: [LinExpr; 8] = std::array::from_fn(|_| LinExpr::zero());
        let mut definition_root = [LinExpr::zero(), LinExpr::zero()];
        let (
            mut frozen,
            mut registered,
            mut input_slot,
            mut noid_slot,
            mut nft_slot,
            mut noid_value,
        ) = (
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
        );
        let mut owner = [LinExpr::zero(), LinExpr::zero()];
        let mut item: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        for (i, a) in actions.iter().enumerate() {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let group = mul(b, &same, &a.live);
            let group = mul(b, &group, &live);
            let input = mul(b, &group, &a.is_output.add_const(F128::ONE));
            let output = mul(b, &group, &a.is_output);
            inputs = unique(b, &inputs, &input);
            eq_when(b, &input, &a.native, &LinExpr::constant(F128::ONE));
            eq_when(
                b,
                &input,
                a.opening.commitment.selector(NativeKind::NftListing),
                &LinExpr::constant(F128::ONE),
            );
            eq_when(
                b,
                &input,
                &definitions.actions[i].listing,
                &LinExpr::constant(F128::ONE),
            );
            for j in 0..12 {
                fields[j] = fields[j].add(&mul(b, &input, &a.opening.fields[j]));
            }
            for j in 0..8 {
                definition[j] =
                    definition[j].add(&mul(b, &input, &definitions.actions[i].fields[j]));
            }
            for j in 0..2 {
                definition_root[j] =
                    definition_root[j].add(&mul(b, &input, &definitions.actions[i].root[j]));
            }
            frozen = frozen.add(&mul(b, &input, &values[i].frozen));
            registered = registered.add(&mul(b, &input, &values[i].registered_height));
            input_slot = input_slot.add(&mul(b, &input, &a.slot));
            let zero = is_zero(b, &a.ordinal);
            let one = is_zero(b, &a.ordinal.add_const(F128::ONE));
            let noid = mul(b, &output, &a.native.add_const(F128::ONE));
            let nft = mul(b, &output, &a.native);
            let outside = mul(b, &output, &zero.add(&one).add_const(F128::ONE));
            pin_zero(b, &outside);
            let public_noid = mul(b, &recover, &noid);
            let public_nft = mul(b, &recover, &nft);
            eq_when(b, &public_noid, &a.ordinal, &LinExpr::zero());
            eq_when(b, &public_nft, &a.ordinal, &LinExpr::constant(F128::ONE));
            noid_count = unique(b, &noid_count, &noid);
            nft_count = unique(b, &nft_count, &nft);
            eq_when(
                b,
                &nft,
                a.opening.commitment.selector(NativeKind::NftItem),
                &LinExpr::constant(F128::ONE),
            );
            noid_slot = noid_slot.add(&mul(b, &noid, &a.slot));
            nft_slot = nft_slot.add(&mul(b, &nft, &a.slot));
            noid_value = noid_value.add(&mul(b, &noid, &a.packed_value));
            for j in 0..2 {
                owner[j] = owner[j].add(&mul(b, &noid, &a.root[j]));
            }
            for j in 0..12 {
                item[j] = item[j].add(&mul(b, &nft, &a.opening.fields[j]));
            }
        }
        for count in [&inputs, &noid_count, &nft_count] {
            pin_eq(b, count, &live);
        }
        for (a, c) in [
            (&input_slot, &noid_slot),
            (&input_slot, &nft_slot),
            (&noid_slot, &nft_slot),
        ] {
            let same = is_zero(b, &a.add(c));
            let repeated = mul(b, &live, &same);
            pin_zero(b, &repeated);
        }
        for j in 0..2 {
            pin_eq(b, &fields[j], &definition_root[j]);
            pin_eq(b, &fields[2 + j], &definition[j]);
            pin_eq(b, &owner[j], &definition[2 + j]);
            eq_when(b, &cancel, &h.header.authority[j], &definition[2 + j]);
        }
        let source_serial = split_packed_input_value(b, &fields[4]);
        let serial = split_packed_input_value(b, &definition[6]);
        pin_eq(b, &source_serial.amount.value, &serial.amount.value);
        let expiry = split_packed_input_value(b, &definition[7]);
        let expiry = expiry
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let early = less_than(b, &height, &expiry);
        let early = mul(b, &recover, &early);
        pin_zero(b, &early);
        let registered = bits(b, &registered, 64);
        let delta = (0..64)
            .map(|i| frozen.scale(flat_const((u128::from(MARKET_SETTLEMENT_WINDOW) >> i) & 1)))
            .collect::<Vec<_>>();
        let deadline = checked_add(b, &registered, &delta);
        let early = less_than(b, &height, &deadline);
        let early = mul(b, &recover, &early);
        pin_zero(b, &early);
        let nonidle = mul(b, &cancel, &frozen);
        pin_zero(b, &nonidle);
        let credit = (0..64)
            .map(|i| live.scale(flat_const((u128::from(NFT_FEE_CREDIT) >> i) & 1)))
            .collect::<Vec<_>>();
        let fee = mul(b, &live, &h.header.fee);
        let fee = bits(b, &fee, 64);
        let affordable = less_than(b, &fee, &credit);
        eq_when(b, &live, &affordable, &LinExpr::constant(F128::ONE));
        let refund = pack(&checked_subtract(b, &credit, &fee));
        let actual = split_packed_input_value(b, &noid_value);
        pin_eq(b, &actual.amount.value, &refund);
        let mut expected: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        expected[0] = definition[0].clone();
        expected[1] = definition[1].clone();
        expected[2] = definition[2].clone();
        expected[3] = definition[3].clone();
        expected[4] = definition[4].clone();
        expected[5] = definition[5].clone();
        expected[6] = serial.amount.value;
        for j in 0..12 {
            pin_eq(b, &item[j], &expected[j]);
        }
    }
}
