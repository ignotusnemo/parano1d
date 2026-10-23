// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-beneficiary NFT refunds with exact one-input/one-output fees.

use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_chain::consensus::params::{FEE_PER_INPUT, FEE_PER_OUTPUT, MIN_FEE_BASE};
use noid_tx::native_assets::{nft_market::NFT_FEE_CREDIT, NativeKind};

const ONE_TO_ONE_FEE: u64 = MIN_FEE_BASE + FEE_PER_INPUT + FEE_PER_OUTPUT;
const _: () = assert!(ONE_TO_ONE_FEE < NFT_FEE_CREDIT);
fn bits(b: &mut FieldR1csBuilder, value: &LinExpr, width: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, value, width)
}
fn increment(b: &mut FieldR1csBuilder, value: &[LinExpr], flag: &LinExpr) -> Vec<LinExpr> {
    let mut delta = vec![LinExpr::zero(); value.len()];
    delta[0] = flag.clone();
    checked_add(b, value, &delta)
}
fn equals_when(b: &mut FieldR1csBuilder, when: &LinExpr, a: &LinExpr, c: &LinExpr) {
    let bad = mul(b, when, &a.add(c));
    pin_zero(b, &bad);
}
/// The complete action table and headers bind the actual input/output roles.
/// For one input and one output there is no State growth, so the required
/// fee is the fixed base plus input/output charges at every parent occupancy.
/// The enclosing financial context authenticates the current height.
pub fn bind_financial_nft_refunds(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    headers: &[FinancialNativeHeaderTrace],
    height: &LinExpr,
) {
    let height = bits(b, height, 64);
    let width = (actions.len() + 1)
        .next_power_of_two()
        .trailing_zeros()
        .max(1) as usize;
    for header in headers {
        let selected = |code| {
            header.metadata.financial[FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&v| v == code)
                .unwrap()]
            .clone()
        };
        let purchase = selected(74);
        let offer = selected(75);
        let live = purchase.add(&offer);
        equals_when(
            b,
            &live,
            &header.header.input_count,
            &LinExpr::constant(F128::ONE),
        );
        equals_when(
            b,
            &live,
            &header.header.output_count,
            &LinExpr::constant(F128::ONE),
        );
        equals_when(
            b,
            &live,
            &header.header.fee,
            &LinExpr::constant(flat_const(u128::from(ONE_TO_ONE_FEE))),
        );
        let mut inputs = vec![LinExpr::zero(); width];
        let mut outputs = vec![LinExpr::zero(); width];
        let mut fields: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        let mut amount = LinExpr::zero();
        let mut input_slot = LinExpr::zero();
        let mut output_slot = LinExpr::zero();
        let mut packed_output = LinExpr::zero();
        let mut recipient = [LinExpr::zero(), LinExpr::zero()];
        for action in actions {
            let same = is_zero(b, &action.header_page.add(&header.header.header_page));
            let group = mul(b, &same, &action.live);
            let group = mul(b, &group, &live);
            let input = mul(b, &group, &action.is_output.add_const(F128::ONE));
            let output = mul(b, &group, &action.is_output);
            inputs = increment(b, &inputs, &input);
            outputs = increment(b, &outputs, &output);
            let allowed = mul(
                b,
                &purchase,
                action.opening.commitment.selector(NativeKind::NftPurchase),
            )
            .add(&mul(
                b,
                &offer,
                action.opening.commitment.selector(NativeKind::NftOffer),
            ));
            equals_when(b, &input, &allowed, &LinExpr::constant(F128::ONE));
            equals_when(b, &input, &action.native, &LinExpr::constant(F128::ONE));
            let native_output = mul(b, &output, &action.native);
            pin_zero(b, &native_output);
            input_slot = input_slot.add(&mul(b, &input, &action.slot));
            output_slot = output_slot.add(&mul(b, &output, &action.slot));
            amount = amount.add(&mul(b, &input, &action.opening.amount));
            for i in 0..12 {
                fields[i] = fields[i].add(&mul(b, &input, &action.opening.fields[i]));
            }
            packed_output = packed_output.add(&mul(b, &output, &action.packed_value));
            for lane in 0..2 {
                recipient[lane] = recipient[lane].add(&mul(b, &output, &action.root[lane]));
            }
        }
        pin_eq(b, &pack(&inputs), &live);
        pin_eq(b, &pack(&outputs), &live);
        let same_slot = is_zero(b, &input_slot.add(&output_slot));
        let duplicate = mul(b, &live, &same_slot);
        pin_zero(b, &duplicate);
        let amount = bits(b, &amount, 64);
        let fee = (0..64)
            .map(|i| live.scale(flat_const((u128::from(ONE_TO_ONE_FEE) >> i) & 1)))
            .collect::<Vec<_>>();
        let refund = pack(&checked_subtract(b, &amount, &fee));
        let output = split_packed_input_value(b, &packed_output);
        pin_eq(b, &output.amount.value, &refund);
        for lane in 0..2 {
            let expected =
                mul(b, &purchase, &fields[4 + lane]).add(&mul(b, &offer, &fields[2 + lane]));
            pin_eq(b, &recipient[lane], &expected);
        }
        let temporal = mul(b, &purchase, &fields[8]).add(&mul(b, &offer, &fields[6]));
        let temporal = split_packed_input_value(b, &temporal);
        let registered_or_expiry = temporal
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let delta = (0..64)
            .map(|i| {
                if i == 2 {
                    purchase.clone()
                } else {
                    LinExpr::zero()
                }
            })
            .collect::<Vec<_>>();
        let deadline = checked_add(b, &registered_or_expiry, &delta);
        let premature = less_than(b, &height, &deadline);
        let premature = mul(b, &live, &premature);
        pin_zero(b, &premature);
    }
}
