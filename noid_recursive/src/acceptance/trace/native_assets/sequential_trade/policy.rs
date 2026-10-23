// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact Owner policy framing and admitting-context bounds.

use super::super::super::{flat_const, mul, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::super::arithmetic::{bits, less_than};
use super::super::validation::{nonzero_pair, require_nonzero};
use super::{boolean, hash_fields};
use noid_poseidon2b::native::DomainTag;

#[derive(Clone)]
pub struct TradePolicyContextTrace {
    pub chain: [LinExpr; 2],
    pub epoch_anchor: [LinExpr; 2],
    pub asset: [LinExpr; 2],
    pub height: LinExpr,
    pub parent_alloc_counter: LinExpr,
}

#[derive(Clone)]
pub struct TradePolicyInputTrace {
    pub live: LinExpr,
    pub chain: [LinExpr; 2],
    pub epoch_anchor: [LinExpr; 2],
    pub owner: [LinExpr; 2],
    pub asset: [LinExpr; 2],
    pub recipient: [LinExpr; 2],
    pub sell: LinExpr,
    pub gross_input: LinExpr,
    pub minimum_output: LinExpr,
    pub fee_limit: LinExpr,
    pub valid_from: LinExpr,
    pub valid_until: LinExpr,
}

#[derive(Clone)]
pub struct TradePolicyTrace {
    pub input: TradePolicyInputTrace,
    pub root: [LinExpr; 2],
}

pub(crate) fn gated_equal(
    b: &mut FieldR1csBuilder,
    when: &LinExpr,
    actual: &LinExpr,
    expected: &LinExpr,
) {
    let invalid = mul(b, when, &actual.add(expected));
    pin_zero(b, &invalid);
}

pub(crate) fn packed(low: &LinExpr, high: &LinExpr) -> LinExpr {
    low.add(&high.scale(flat_const(1u128 << 64)))
}

pub fn bind_trade_policy(
    b: &mut FieldR1csBuilder,
    context: &TradePolicyContextTrace,
    input: &TradePolicyInputTrace,
) -> TradePolicyTrace {
    boolean(b, &input.live);
    boolean(b, &input.sell);
    for field in input
        .chain
        .iter()
        .chain(&input.epoch_anchor)
        .chain(&input.owner)
        .chain(&input.asset)
        .chain(&input.recipient)
        .chain([
            &input.sell,
            &input.gross_input,
            &input.minimum_output,
            &input.fee_limit,
            &input.valid_from,
            &input.valid_until,
        ])
    {
        let padding = mul(b, &input.live.add_const(F128::ONE), field);
        pin_zero(b, &padding);
    }
    for (actual, expected) in [
        (&input.chain, &context.chain),
        (&input.epoch_anchor, &context.epoch_anchor),
        (&input.asset, &context.asset),
    ] {
        for lane in 0..2 {
            gated_equal(b, &input.live, &actual[lane], &expected[lane]);
        }
        nonzero_pair(b, actual, &input.live);
    }
    nonzero_pair(b, &input.owner, &input.live);
    nonzero_pair(b, &input.recipient, &input.live);
    for quantity in [&input.gross_input, &input.minimum_output, &input.fee_limit] {
        bits(b, quantity, 63);
        require_nonzero(b, quantity, &input.live);
    }
    let from = bits(b, &input.valid_from, 64);
    let until = bits(b, &input.valid_until, 64);
    let height = bits(b, &context.height, 64);
    let before = less_than(b, &height, &from);
    let after = less_than(b, &until, &height);
    let invalid_before = mul(b, &input.live, &before);
    let invalid_after = mul(b, &input.live, &after);
    pin_zero(b, &invalid_before);
    pin_zero(b, &invalid_after);
    let fields = [
        input.live.clone(),
        input.sell.clone(),
        input.chain[0].clone(),
        input.chain[1].clone(),
        input.epoch_anchor[0].clone(),
        input.epoch_anchor[1].clone(),
        input.owner[0].clone(),
        input.owner[1].clone(),
        input.asset[0].clone(),
        input.asset[1].clone(),
        input.recipient[0].clone(),
        input.recipient[1].clone(),
        packed(&input.gross_input, &input.minimum_output),
        packed(&input.valid_from, &input.valid_until),
        input.fee_limit.clone(),
        LinExpr::zero(),
    ];
    let root = hash_fields(b, DomainTag::new(b"TRPOL_21"), &fields);
    TradePolicyTrace {
        input: input.clone(),
        root: root.map(|lane| mul(b, &input.live, &lane)),
    }
}
