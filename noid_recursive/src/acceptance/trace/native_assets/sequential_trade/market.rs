// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Sequential exact-input constant-product prices and retained pool fees.

use super::super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::super::arithmetic::{
    bits, checked_add, checked_subtract, extend, less_than, multiply, pack,
};
use super::super::validation::{is_zero, require_nonzero};
use super::{bind_quotient, boolean, number, select, value, witness};
use noid_tx::native_assets::market::MARKET_FEE_BPS;

pub struct SequentialMarketInputTrace {
    pub live: LinExpr,
    pub sell: LinExpr,
    pub base_reserve: LinExpr,
    pub quote_reserve: LinExpr,
    pub gross_input: LinExpr,
    pub minimum_output: LinExpr,
}

pub struct SequentialMarketStepTrace {
    pub executed: LinExpr,
    pub spent_input: LinExpr,
    pub effective_input: LinExpr,
    pub fee: LinExpr,
    pub output: LinExpr,
    pub after_base: LinExpr,
    pub after_quote: LinExpr,
}

pub fn bind_sequential_market_step(
    b: &mut FieldR1csBuilder,
    input: &SequentialMarketInputTrace,
) -> SequentialMarketStepTrace {
    let minimum = mul(b, &input.live, &input.minimum_output);
    let minimum_bits = bits(b, &minimum, 63);
    require_nonzero(b, &minimum, &input.live);
    let gross = mul(b, &input.live, &input.gross_input);
    require_nonzero(b, &gross, &input.live);
    let step = bind_sequential_market_candidate(b, input);
    pin_eq(b, &step.executed, &input.live);
    let output_bits = bits(b, &step.output, 63);
    let too_small = less_than(b, &output_bits, &minimum_bits);
    pin_zero(b, &too_small);
    step
}

/// Zero-effective-input or zero-output curve dust keeps the parent pool intact.
/// Positive effective input still obeys the native reserve-capacity bound.
pub(crate) fn bind_sequential_market_candidate(
    b: &mut FieldR1csBuilder,
    input: &SequentialMarketInputTrace,
) -> SequentialMarketStepTrace {
    boolean(b, &input.live);
    boolean(b, &input.sell);
    let live = &input.live;
    let base = mul(b, live, &input.base_reserve);
    let quote = mul(b, live, &input.quote_reserve);
    let gross = mul(b, live, &input.gross_input);
    let gross_bits = bits(b, &gross, 63);
    bits(b, &base, 63);
    bits(b, &quote, 63);
    require_nonzero(b, &base, live);
    require_nonzero(b, &quote, live);
    let rin = select(b, &input.sell, &base, &quote);
    let rout = select(b, &input.sell, &quote, &base);
    let rin_bits = bits(b, &rin, 63);
    let rout_bits = bits(b, &rout, 63);
    let retained = u128::from(10_000 - MARKET_FEE_BPS);
    let g = value(b, &gross);
    let effective = witness(b, g.saturating_mul(retained) / 10_000);
    let effective_bits = bits(b, &effective, 63);
    let retained_bits = bits(b, &number(retained), 63);
    let numerator = multiply(b, &gross_bits, &retained_bits);
    let denominator = bits(b, &number(10_000), 63);
    bind_quotient(b, live, &numerator, &denominator, &effective_bits, false);
    let fee = pack(&checked_subtract(b, &gross_bits, &effective_bits));
    let capacity = checked_add(b, &extend(&rin_bits, 64), &extend(&gross_bits, 64));
    let nonzero_effective = is_zero(b, &effective).add_const(F128::ONE);
    let check_capacity = mul(b, live, &nonzero_effective);
    let overflow = mul(b, &check_capacity, &capacity[63]);
    pin_zero(b, &overflow);
    let denominator = checked_add(b, &extend(&rin_bits, 64), &extend(&effective_bits, 64));
    let rin_value = value(b, &rin);
    let rout_value = value(b, &rout);
    let e = value(b, &effective);
    let divisor = rin_value.saturating_add(e);
    let output = witness(
        b,
        if divisor == 0 {
            0
        } else {
            rout_value.saturating_mul(e) / divisor
        },
    );
    let output_bits = bits(b, &output, 63);
    let numerator = multiply(b, &rout_bits, &effective_bits);
    bind_quotient(b, live, &numerator, &denominator, &output_bits, false);
    let after_output = pack(&checked_subtract(b, &rout_bits, &output_bits));
    require_nonzero(b, &after_output, live);
    let output_nonzero = is_zero(b, &output).add_const(F128::ONE);
    let executed = mul(b, live, &output_nonzero);
    let after_input = select(b, &executed, &rin, &pack(&capacity));
    let after_output = select(b, &executed, &rout, &after_output);
    let after_base = select(b, &input.sell, &after_input, &after_output);
    let after_quote = select(b, &input.sell, &after_output, &after_input);
    bits(b, &after_base, 63);
    bits(b, &after_quote, 63);
    SequentialMarketStepTrace {
        spent_input: mul(b, &executed, &gross),
        effective_input: mul(b, &executed, &effective),
        fee: mul(b, &executed, &fee),
        output: mul(b, &executed, &output),
        executed,
        after_base,
        after_quote,
    }
}
