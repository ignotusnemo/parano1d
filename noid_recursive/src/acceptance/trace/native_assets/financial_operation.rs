// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-shape canonical metadata for base and financial native operations.

use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::range_check_bits;
use super::arithmetic::{less_than, pack};
use super::validation::{is_zero, nonzero_pair, require_nonzero};

pub const FINANCIAL_OPERATION_CODES: [u16; 31] = [
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 48, 49, 50, 51, 52, 53, 64, 65, 66, 67, 68, 69,
    70, 71, 72, 73, 74, 75, 80,
];

pub struct NativeOperationMetadataTrace {
    pub inactive: LinExpr,
    pub base: [LinExpr; 9],
    pub financial: [LinExpr; 31],
    pub trade_root: [LinExpr; 2],
    pub owner_required: LinExpr,
    pub read_required: LinExpr,
    pub registration_required: LinExpr,
    pub definition_required: LinExpr,
    pub funding_required: LinExpr,
    pub read_slot: LinExpr,
    pub read_creation_id: LinExpr,
    pub read_sequence: LinExpr,
    pub read_root: [LinExpr; 2],
    pub definition_root: [LinExpr; 2],
    pub asset: [LinExpr; 2],
    pub funding_input: LinExpr,
}

fn selected(base: &[LinExpr; 9], financial: &[LinExpr; 31], codes: &[u16]) -> LinExpr {
    codes.iter().fold(LinExpr::zero(), |sum, &code| {
        let value = if code <= 8 {
            &base[usize::from(code)]
        } else {
            &financial[FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&c| c == code)
                .expect("finite financial code")]
        };
        sum.add(value)
    })
}

/// Bind fields taken from one authenticated native header and its exact END.
/// The enclosing group relation supplies the State, ancestry, fee and operation
/// predicates, and links every Owner-required header to its V4 statement.
pub fn bind_native_operation_metadata(
    b: &mut FieldR1csBuilder,
    live: &LinExpr,
    operation: &LinExpr,
    operand_slot: &LinExpr,
    operand_amount: &LinExpr,
    operand_root: &[LinExpr; 2],
    authority: &[LinExpr; 2],
    input_count: &LinExpr,
) -> NativeOperationMetadataTrace {
    let invalid_live = mul(b, live, &live.add_const(F128::ONE));
    pin_zero(b, &invalid_live);
    range_check_bits(b, operation, 7);
    let base = std::array::from_fn(|code| {
        if code == 0 || noid_tx::native_assets::profile::operation_enabled(code as u16) {
            is_zero(b, &operation.add_const(flat_const(code as u128)))
        } else {
            LinExpr::zero()
        }
    });
    let financial = FINANCIAL_OPERATION_CODES.map(|code| {
        if noid_tx::native_assets::profile::operation_enabled(code) {
            is_zero(b, &operation.add_const(flat_const(u128::from(code))))
        } else {
            LinExpr::zero()
        }
    });
    let inactive = base[0].clone();
    pin_eq(b, &inactive, &live.add_const(F128::ONE));
    let recognized = base
        .iter()
        .chain(&financial)
        .fold(LinExpr::zero(), |sum, v| sum.add(v));
    pin_eq(b, &recognized, &LinExpr::constant(F128::ONE));
    let owner_required = selected(
        &base,
        &financial,
        &[
            1, 2, 3, 4, 5, 6, 7, 8, 32, 33, 34, 35, 36, 37, 48, 49, 64, 65, 66, 67, 68, 69,
        ],
    );
    let read_required = selected(&base, &financial, &[33, 34, 35, 36, 49, 65]);
    let registration_required = selected(&base, &financial, &[33, 49]);
    let definition_required = selected(&base, &financial, &[32, 37, 40, 42, 48, 64]);
    let funding_required = selected(&base, &financial, &[1, 5, 32, 48, 67]);
    let asset_required = selected(&base, &financial, &[2, 3, 4]);
    nonzero_pair(b, authority, &owner_required);
    for lane in authority {
        let unused = mul(b, &owner_required.add_const(F128::ONE), lane);
        pin_zero(b, &unused);
    }
    let trade = selected(&base, &financial, &[80]);
    let root_required = read_required
        .add(&definition_required)
        .add(&asset_required)
        .add(&trade);
    nonzero_pair(b, operand_root, &root_required);
    for lane in operand_root {
        let unused = mul(b, &root_required.add_const(F128::ONE), lane);
        pin_zero(b, &unused);
    }
    range_check_bits(b, operand_slot, 32);
    let operand_bits: Vec<_> = range_check_bits(b, operand_amount, 64)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect();
    let unused_slot = mul(b, &read_required.add_const(F128::ONE), operand_slot);
    pin_zero(b, &unused_slot);
    let argument_required = read_required.add(&funding_required);
    let unused_amount = mul(b, &argument_required.add_const(F128::ONE), operand_amount);
    pin_zero(b, &unused_amount);
    let read_slot = mul(b, &read_required, operand_slot);
    let read_creation_id = mul(b, &read_required, operand_amount);
    let read_tag = mul(b, &read_required, &operand_bits[62]);
    pin_eq(b, &read_tag, &read_required);
    let read_high = mul(b, &read_required, &operand_bits[63]);
    pin_zero(b, &read_high);
    let read_sequence = mul(b, &read_required, &pack(&operand_bits[..62]));
    require_nonzero(b, &read_sequence, &read_required);
    let read_root = std::array::from_fn(|i| mul(b, &read_required, &operand_root[i]));
    let definition_root = std::array::from_fn(|i| mul(b, &definition_required, &operand_root[i]));
    let asset = std::array::from_fn(|i| mul(b, &asset_required, &operand_root[i]));
    let funding_input = mul(b, &funding_required, operand_amount);
    let funding_bits: Vec<_> = range_check_bits(b, &funding_input, 11)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect();
    let count_bits: Vec<_> = range_check_bits(b, input_count, 11)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect();
    let dead_count = mul(b, &inactive, input_count);
    pin_zero(b, &dead_count);
    require_nonzero(b, input_count, live);
    let maximum = noid_tx::MAX_PAGED_SPEND_INPUTS as u128 + 1;
    let maximum: Vec<_> = (0..11)
        .map(|i| LinExpr::constant(flat_const((maximum >> i) & 1)))
        .collect();
    let count_in_range = less_than(b, &count_bits, &maximum);
    pin_eq(b, &count_in_range, &LinExpr::constant(F128::ONE));
    let valid_funding = less_than(b, &funding_bits, &count_bits);
    let bad_funding = mul(b, &funding_required, &valid_funding.add_const(F128::ONE));
    pin_zero(b, &bad_funding);
    NativeOperationMetadataTrace {
        inactive,
        base,
        financial,
        trade_root: std::array::from_fn(|lane| mul(b, &trade, &operand_root[lane])),
        owner_required,
        read_required,
        registration_required,
        definition_required,
        funding_required,
        read_slot,
        read_creation_id,
        read_sequence,
        read_root,
        definition_root,
        asset,
        funding_input,
    }
}
