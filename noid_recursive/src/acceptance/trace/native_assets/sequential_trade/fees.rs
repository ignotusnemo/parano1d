// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical per-policy quotes from the immutable parent fee context.

use super::super::super::{mul, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::super::arithmetic::{
    bits, checked_add, checked_subtract, extend, less_than, multiply, pack,
};
use super::super::validation::require_nonzero;
use super::{boolean, number};
use noid_chain::consensus::params::{FEE_PER_INPUT, FEE_PER_OUTPUT, MIN_FEE_BASE};

#[derive(Clone)]
pub struct TradeFeeQuoteTrace {
    quotes: [LinExpr; 3],
}
impl TradeFeeQuoteTrace {
    pub fn quotes(&self) -> &[LinExpr; 3] {
        &self.quotes
    }
}

pub fn bind_trade_growth_price(b: &mut FieldR1csBuilder, pressure_multiplier: &LinExpr) -> LinExpr {
    let pressure = bits(b, pressure_multiplier, 4);
    let unit = bits(
        b,
        &number(u128::from(
            noid_chain::consensus::params::STATE_GROWTH_FEE_BASE,
        )),
        16,
    );
    let product = multiply(b, &extend(&pressure, 16), &unit);
    for bit in &product[15..] {
        pin_zero(b, bit);
    }
    pack(&product[..15])
}

/// The parent fee relation binds growth_per_slot to its proven occupancy and
/// depth. Each quote includes the shared market input and final control.
pub fn bind_trade_fee_quotes(
    b: &mut FieldR1csBuilder,
    live: &LinExpr,
    funding_count: &LinExpr,
    growth_per_slot: &LinExpr,
) -> TradeFeeQuoteTrace {
    boolean(b, live);
    let funding = bits(b, funding_count, 11);
    let maximum = bits(b, &number(noid_tx::MAX_PAGED_SPEND_INPUTS as u128 + 1), 11);
    let valid = less_than(b, &funding, &maximum);
    let invalid = mul(b, live, &valid.add_const(F128::ONE));
    pin_zero(b, &invalid);
    require_nonzero(b, funding_count, live);
    let padding = mul(b, &live.add_const(F128::ONE), funding_count);
    pin_zero(b, &padding);
    let mut one = vec![LinExpr::zero(); 11];
    one[0] = live.clone();
    let input_count = checked_add(b, &funding, &one);
    let input_unit = bits(b, &number(u128::from(FEE_PER_INPUT)), 16);
    let input_fee = multiply(b, &extend(&input_count, 16), &input_unit);
    let growth = bits(b, growth_per_slot, 15);
    let base = bits(b, &number(u128::from(MIN_FEE_BASE)), 32)
        .iter()
        .map(|bit| mul(b, live, bit))
        .collect::<Vec<_>>();
    let quotes = std::array::from_fn(|index| {
        let count = index + 1;
        let payout_count = bits(b, &number(count as u128), 11)
            .iter()
            .map(|bit| mul(b, live, bit))
            .collect::<Vec<_>>();
        let grows = less_than(b, &funding, &payout_count);
        let larger = payout_count
            .iter()
            .map(|bit| mul(b, &grows, bit))
            .collect::<Vec<_>>();
        let smaller = funding
            .iter()
            .map(|bit| mul(b, &grows, bit))
            .collect::<Vec<_>>();
        let net = checked_subtract(b, &larger, &smaller);
        let burn = multiply(b, &extend(&net, 16), &extend(&growth, 16));
        let out_fee = bits(
            b,
            &number((count as u128 + 1) * u128::from(FEE_PER_OUTPUT)),
            32,
        )
        .iter()
        .map(|bit| mul(b, live, bit))
        .collect::<Vec<_>>();
        let base_inputs = checked_add(b, &base, &input_fee);
        let io = checked_add(b, &base_inputs, &out_fee);
        pack(&checked_add(b, &io, &burn))
    });
    TradeFeeQuoteTrace { quotes }
}
