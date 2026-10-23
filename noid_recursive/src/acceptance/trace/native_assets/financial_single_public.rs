// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared exact one-input/one-output public financial transitions.

use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_definitions::FinancialDefinitionsTrace;
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::financial_values::FinancialCarrierValuesTrace;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_chain::consensus::params::{FEE_PER_INPUT, FEE_PER_OUTPUT, MIN_FEE_BASE};
use noid_tx::native_assets::{
    market::MARKET_SETTLEMENT_WINDOW, nft_market::NFT_FEE_CREDIT, NativeKind,
};
const ONE_TO_ONE_FEE: u64 = MIN_FEE_BASE + FEE_PER_INPUT + FEE_PER_OUTPUT;
const _: () = assert!(ONE_TO_ONE_FEE < NFT_FEE_CREDIT);
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn when_eq(b: &mut FieldR1csBuilder, flag: &LinExpr, a: &LinExpr, c: &LinExpr) {
    let bad = mul(b, flag, &a.add(c));
    pin_zero(b, &bad);
}
/// The incoming flags are Boolean. Rejecting every overlap makes the XOR
/// accumulator an exact at-most-one count before its final equality to live.
fn unique(b: &mut FieldR1csBuilder, seen: &LinExpr, flag: &LinExpr) -> LinExpr {
    let duplicate = mul(b, seen, flag);
    pin_zero(b, &duplicate);
    seen.add(flag)
}

/// Canonical complete actions, validated carrier values and exact linked
/// definitions are shared with the financial bank. Resets preserve economics
/// and ownership while advancing generation. Refunds pay only the source payer.
/// The enclosing context authenticates the current height.
pub fn bind_financial_single_public(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    values: &[FinancialCarrierValuesTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialNativeHeaderTrace],
    height: &LinExpr,
) {
    assert_eq!(actions.len(), values.len());
    assert_eq!(actions.len(), definitions.actions.len());
    let height = bits(b, height, 64);
    for h in headers {
        let flags = [41, 53, 72, 74, 75].map(|code| {
            h.metadata.financial[FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&v| v == code)
                .unwrap()]
            .clone()
        });
        let reset = flags[..3].iter().fold(LinExpr::zero(), |s, v| s.add(v));
        let refund = flags[3].add(&flags[4]);
        let live = reset.add(&refund);
        for count in [&h.header.input_count, &h.header.output_count] {
            when_eq(b, &live, count, &LinExpr::constant(F128::ONE));
        }
        when_eq(
            b,
            &live,
            &h.header.fee,
            &refund.scale(flat_const(u128::from(ONE_TO_ONE_FEE))),
        );
        let (mut inputs, mut outputs) = (LinExpr::zero(), LinExpr::zero());
        let mut source: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        let mut successor = source.clone();
        let (
            mut frozen,
            mut temporal,
            mut base_noid,
            mut source_slot,
            mut output_slot,
            mut amount,
            mut output_value,
        ) = (
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
        );
        let mut recipient = [LinExpr::zero(), LinExpr::zero()];
        for (i, a) in actions.iter().enumerate() {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let group = mul(b, &same, &a.live);
            let group = mul(b, &group, &live);
            let input = mul(b, &group, &a.is_output.add_const(F128::ONE));
            let output = mul(b, &group, &a.is_output);
            inputs = unique(b, &inputs, &input);
            outputs = unique(b, &outputs, &output);
            let kinds = [
                NativeKind::MarketPool,
                NativeKind::LaunchState,
                NativeKind::NftListing,
                NativeKind::NftPurchase,
                NativeKind::NftOffer,
            ];
            let allowed = kinds
                .iter()
                .enumerate()
                .fold(LinExpr::zero(), |sum, (k, kind)| {
                    sum.add(&mul(b, &flags[k], a.opening.commitment.selector(*kind)))
                });
            when_eq(b, &input, &allowed, &LinExpr::constant(F128::ONE));
            when_eq(b, &input, &a.native, &LinExpr::constant(F128::ONE));
            let allowed_output = kinds[..3]
                .iter()
                .enumerate()
                .fold(LinExpr::zero(), |sum, (k, kind)| {
                    sum.add(&mul(b, &flags[k], a.opening.commitment.selector(*kind)))
                });
            when_eq(b, &output, &allowed_output, &reset);
            when_eq(b, &output, &a.native, &reset);
            for j in 0..12 {
                source[j] = source[j].add(&mul(b, &input, &a.opening.fields[j]));
                successor[j] = successor[j].add(&mul(b, &output, &a.opening.fields[j]));
            }
            frozen = frozen.add(&mul(b, &input, &values[i].frozen));
            let time = values[i]
                .registered_height
                .add(&mul(b, &flags[3], &values[i].primary.creation_id.value))
                .add(&mul(b, &flags[4], &values[i].secondary.creation_id.value));
            temporal = temporal.add(&mul(b, &input, &time));
            base_noid = base_noid.add(&mul(b, &input, &definitions.actions[i].base_is_noid));
            source_slot = source_slot.add(&mul(b, &input, &a.slot));
            output_slot = output_slot.add(&mul(b, &output, &a.slot));
            amount = amount.add(&mul(b, &input, &a.opening.amount));
            output_value = output_value.add(&mul(b, &output, &a.packed_value));
            for lane in 0..2 {
                recipient[lane] = recipient[lane].add(&mul(b, &output, &a.root[lane]));
            }
        }
        pin_eq(b, &inputs, &live);
        pin_eq(b, &outputs, &live);
        pin_eq(b, &frozen, &reset);
        let same_slot = is_zero(b, &source_slot.add(&output_slot));
        let duplicate = mul(b, &live, &same_slot);
        pin_zero(b, &duplicate);
        let temporal = bits(b, &temporal, 64);
        let has_window = reset.add(&flags[3]);
        let delta = (0..64)
            .map(|i| has_window.scale(flat_const((u128::from(MARKET_SETTLEMENT_WINDOW) >> i) & 1)))
            .collect::<Vec<_>>();
        let deadline = checked_add(b, &temporal, &delta);
        let early = less_than(b, &height, &deadline);
        let early = mul(b, &live, &early);
        pin_zero(b, &early);
        let raw = mul(b, &flags[0], &source[6])
            .add(&mul(b, &flags[1], &source[3]))
            .add(&mul(b, &flags[2], &source[4]));
        let packed = split_packed_input_value(b, &raw);
        let low = packed
            .amount
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let high = packed
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let ordinary = flags[0].add(&flags[1]);
        let generation = (0..64)
            .map(|i| mul(b, &ordinary, &low[i]).add(&mul(b, &flags[2], &high[i])))
            .collect::<Vec<_>>();
        let mut one = vec![LinExpr::zero(); 64];
        one[0] = reset.clone();
        let next = checked_add(b, &generation, &one);
        let next_word = pack(&next);
        let mut expected: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        for j in 0..3 {
            expected[j] = mul(b, &reset, &source[j]);
        }
        expected[3] =
            mul(b, &flags[0].add(&flags[2]), &source[3]).add(&mul(b, &flags[1], &next_word));
        let mut nft = low.iter().map(|v| mul(b, &flags[2], v)).collect::<Vec<_>>();
        nft.extend(next.iter().map(|v| mul(b, &flags[2], v)));
        expected[4] = pack(&nft);
        expected[6] = mul(b, &flags[0], &next_word);
        expected[7] = mul(b, &flags[0], &base_noid).scale(flat_const(1u128 << 88));
        for j in 0..12 {
            pin_eq(b, &successor[j], &expected[j]);
        }
        let amount = mul(b, &refund, &amount);
        let amount = bits(b, &amount, 64);
        let fee = (0..64)
            .map(|i| refund.scale(flat_const((u128::from(ONE_TO_ONE_FEE) >> i) & 1)))
            .collect::<Vec<_>>();
        let paid = pack(&checked_subtract(b, &amount, &fee));
        let output_value = mul(b, &refund, &output_value);
        let output_value = split_packed_input_value(b, &output_value);
        pin_eq(b, &output_value.amount.value, &paid);
        for lane in 0..2 {
            let actual = mul(b, &refund, &recipient[lane]);
            let payer =
                mul(b, &flags[3], &source[4 + lane]).add(&mul(b, &flags[4], &source[2 + lane]));
            pin_eq(b, &actual, &payer);
        }
    }
}
