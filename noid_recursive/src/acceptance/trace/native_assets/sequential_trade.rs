// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact sequential curve and permanent-market execution predicates.

pub mod authorization;
pub mod fees;
pub mod flat_funding;
pub mod funding;
pub mod global_execution;
pub mod group;
pub mod kernel;
pub mod launch;
pub mod market;
pub mod payouts;
pub mod policy;

use super::super::{
    alloc_block, flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::{checked_subtract, extend, less_than, multiply};
use super::validation::require_nonzero;
use noid_core::{hardware::flat_to_tower_u128, Block128};
use noid_poseidon2b::native::{capacity_iv, DomainTag};

pub(crate) fn number(value: u128) -> LinExpr {
    LinExpr::constant(flat_const(value))
}
pub(crate) fn value(b: &FieldR1csBuilder, expression: &LinExpr) -> u128 {
    let value = expression.eval(b.values());
    flat_to_tower_u128(u128::from(value.lo) | (u128::from(value.hi) << 64))
}
pub(crate) fn witness(b: &mut FieldR1csBuilder, value: u128) -> LinExpr {
    alloc_block(b, Block128(value))
}
pub(crate) fn boolean(b: &mut FieldR1csBuilder, expression: &LinExpr) {
    let invalid = mul(b, expression, &expression.add_const(F128::ONE));
    pin_zero(b, &invalid);
}
pub(crate) fn select(
    b: &mut FieldR1csBuilder,
    flag: &LinExpr,
    when_zero: &LinExpr,
    when_one: &LinExpr,
) -> LinExpr {
    when_zero.add(&mul(b, flag, &when_zero.add(when_one)))
}

/// Exact bounded quotient: all supplied coordinates are Boolean unsigned bits.
/// The complete product and a remainder below the positive denominator fix the
/// requested floor or ceiling, including zero numerators.
pub(crate) fn bind_quotient(
    b: &mut FieldR1csBuilder,
    active: &LinExpr,
    numerator: &[LinExpr],
    denominator: &[LinExpr],
    quotient: &[LinExpr],
    round_up: bool,
) {
    let width = denominator.len().max(quotient.len());
    let product = multiply(b, &extend(denominator, width), &extend(quotient, width));
    let full_width = product.len().max(numerator.len());
    let product = extend(&product, full_width);
    let numerator = extend(numerator, full_width);
    let (top, bottom) = if round_up {
        (&product, &numerator)
    } else {
        (&numerator, &product)
    };
    let remainder = checked_subtract(b, top, bottom);
    let proper = less_than(b, &remainder, &extend(denominator, full_width));
    let invalid = mul(b, active, &proper.add_const(F128::ONE));
    pin_zero(b, &invalid);
    require_nonzero(b, &super::arithmetic::pack(denominator), active);
}

pub(crate) fn bind_same(b: &mut FieldR1csBuilder, a: &[LinExpr], c: &[LinExpr]) {
    assert_eq!(a.len(), c.len());
    for (a, c) in a.chunks(128).zip(c.chunks(128)) {
        pin_eq(b, &super::arithmetic::pack(a), &super::arithmetic::pack(c));
    }
}

pub(crate) fn hash_fields(
    b: &mut FieldR1csBuilder,
    tag: DomainTag,
    fields: &[LinExpr],
) -> [LinExpr; 2] {
    let state = hash_state(b, tag, fields);
    [state[0].clone(), state[1].clone()]
}

pub(crate) fn hash_state(
    b: &mut FieldR1csBuilder,
    tag: DomainTag,
    fields: &[LinExpr],
) -> [LinExpr; 4] {
    assert!(fields.len().is_multiple_of(2));
    let iv = capacity_iv(tag);
    let mut state = [
        LinExpr::zero(),
        LinExpr::zero(),
        LinExpr::constant(super::super::flat_of(iv[0])),
        LinExpr::constant(super::super::flat_of(iv[1])),
    ];
    for pair in fields.chunks_exact(2) {
        state[0] = state[0].add(&pair[0]);
        state[1] = state[1].add(&pair[1]);
        state = super::super::poseidon2b_permute(b, state);
    }
    state
}

pub(crate) fn digest_bytes_bits(b: &mut FieldR1csBuilder, digest: &[LinExpr; 2]) -> Vec<LinExpr> {
    let raw = digest
        .iter()
        .flat_map(|lane| super::arithmetic::bits(b, lane, 128))
        .collect::<Vec<_>>();
    (0..32)
        .rev()
        .flat_map(|byte| raw[8 * byte..8 * byte + 8].iter().cloned())
        .collect()
}
