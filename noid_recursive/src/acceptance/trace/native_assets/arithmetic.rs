// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact unsigned arithmetic over proven little-endian bit expressions.

use super::super::public_arithmetic::{PackedInputValueTrace, U64Trace};
use super::super::{flat_const, mul, pin_zero, FieldR1csBuilder, LinExpr, F128};
use noid_ivc_core::field_circuit::Wire;

/// Exact unsigned bits, retaining compile-time literals as constant expressions.
pub fn bits(b: &mut FieldR1csBuilder, expr: &LinExpr, n_bits: usize) -> Vec<LinExpr> {
    assert!(n_bits <= 128);
    if !expr.is_const() {
        return range_check_bits(b, expr, n_bits)
            .into_iter()
            .map(LinExpr::from_wire)
            .collect();
    }
    let c = expr.constant;
    let value =
        noid_core::hardware::flat_to_tower_u128(u128::from(c.lo) | (u128::from(c.hi) << 64));
    if n_bits < 128 && value >> n_bits != 0 {
        pin_zero(b, &LinExpr::constant(F128::ONE));
    }
    (0..n_bits)
        .map(|i| {
            LinExpr::constant(if (value >> i) & 1 == 0 {
                F128::ZERO
            } else {
                F128::ONE
            })
        })
        .collect()
}

/// Reuse Boolean coordinates while binding each reconstruction in its owning scope.
pub fn range_check_bits(b: &mut FieldR1csBuilder, expr: &LinExpr, n_bits: usize) -> Vec<Wire> {
    let bits = b.alloc_tower_bits_cached(expr, n_bits);
    let sum = bits
        .iter()
        .enumerate()
        .fold(LinExpr::zero(), |sum, (i, bit)| {
            sum.add(&LinExpr::from_wire(*bit).scale(flat_const(1u128 << i)))
        });
    pin_zero(b, &sum.add(expr));
    bits
}
/// Recover both unsigned halves from one exact packed decomposition.
pub fn split_packed_input_value(
    b: &mut FieldR1csBuilder,
    packed: &LinExpr,
) -> PackedInputValueTrace {
    let bits = range_check_bits(b, packed, 128);
    let mut half = |offset: usize| {
        let bits: [Wire; 64] = std::array::from_fn(|i| bits[offset + i]);
        let value = bits
            .iter()
            .enumerate()
            .fold(LinExpr::zero(), |sum, (i, bit)| {
                sum.add(&LinExpr::from_wire(*bit).scale(flat_const(1u128 << i)))
            });
        let value = LinExpr::from_wire(b.materialize(&value));
        U64Trace { value, bits }
    };
    PackedInputValueTrace {
        amount: half(0),
        creation_id: half(64),
    }
}

pub fn pack(bits: &[LinExpr]) -> LinExpr {
    assert!(bits.len() <= 128);
    bits.iter()
        .enumerate()
        .fold(LinExpr::zero(), |sum, (i, bit)| {
            sum.add(&bit.scale(flat_const(1u128 << i)))
        })
}

pub fn extend(bits: &[LinExpr], width: usize) -> Vec<LinExpr> {
    assert!(bits.len() <= width);
    let mut result = bits.to_vec();
    result.resize(width, LinExpr::zero());
    result
}

pub fn shifted(bits: &[LinExpr], shift: usize, width: usize) -> Vec<LinExpr> {
    assert!(shift + bits.len() <= width);
    let mut result = vec![LinExpr::zero(); width];
    result[shift..shift + bits.len()].clone_from_slice(bits);
    result
}

fn majority(b: &mut FieldR1csBuilder, a: &LinExpr, c: &LinExpr, carry: &LinExpr) -> LinExpr {
    let (x, y, z) = if a.terms.len() <= c.terms.len() && a.terms.len() <= carry.terms.len() {
        (c, carry, a)
    } else if c.terms.len() <= carry.terms.len() {
        (a, carry, c)
    } else {
        (a, c, carry)
    };
    mul(b, &x.add(z), &y.add(z)).add(z)
}

/// Inputs are boolean expressions; the full-adder identities preserve that
/// property in both output bits and carries. The final carry is zero.
pub fn checked_add(b: &mut FieldR1csBuilder, a: &[LinExpr], c: &[LinExpr]) -> Vec<LinExpr> {
    assert_eq!(a.len(), c.len());
    assert!(!a.is_empty());
    let mut carry = LinExpr::zero();
    let mut result = Vec::with_capacity(a.len());
    for (ai, ci) in a.iter().zip(c) {
        result.push(ai.add(ci).add(&carry));
        carry = majority(b, ai, ci, &carry);
    }
    pin_zero(b, &carry);
    result
}

/// Exact subtraction with final borrow zero. Boolean inputs are required.
pub fn checked_subtract(b: &mut FieldR1csBuilder, a: &[LinExpr], c: &[LinExpr]) -> Vec<LinExpr> {
    assert_eq!(a.len(), c.len());
    assert!(!a.is_empty());
    let mut borrow = LinExpr::zero();
    let mut result = Vec::with_capacity(a.len());
    for (ai, ci) in a.iter().zip(c) {
        result.push(ai.add(ci).add(&borrow));
        borrow = majority(b, &ai.add_const(F128::ONE), ci, &borrow);
    }
    pin_zero(b, &borrow);
    result
}

/// Strict unsigned comparison; output is a boolean expression.
pub fn less_than(b: &mut FieldR1csBuilder, a: &[LinExpr], c: &[LinExpr]) -> LinExpr {
    assert_eq!(a.len(), c.len());
    assert!(!a.is_empty());
    let mut less = LinExpr::zero();
    for (ai, ci) in a.iter().zip(c) {
        less = mul(b, &ai.add(ci).add_const(F128::ONE), &less.add(ci)).add(ci);
    }
    less
}

fn static_zero(x: &LinExpr) -> bool {
    x.is_const() && x.constant == F128::ZERO
}

fn schoolbook(b: &mut FieldR1csBuilder, a: &[LinExpr], c: &[LinExpr]) -> Vec<LinExpr> {
    let width = a.len() + c.len();
    let mut columns = vec![Vec::<LinExpr>::new(); width + 1];
    for (i, ai) in a.iter().enumerate() {
        for (j, ci) in c.iter().enumerate() {
            columns[i + j].push(mul(b, ai, ci));
        }
    }
    let mut output = Vec::with_capacity(width);
    for i in 0..width {
        while columns[i].len() > 2 {
            let z = columns[i].pop().unwrap();
            let y = columns[i].pop().unwrap();
            let x = columns[i].pop().unwrap();
            columns[i].push(x.add(&y).add(&z));
            let carry = majority(b, &x, &y, &z);
            columns[i + 1].push(carry);
        }
        let bit = match columns[i].as_slice() {
            [] => LinExpr::zero(),
            [one] => one.clone(),
            [x, y] => {
                let result = x.add(y);
                let carry = mul(b, x, y);
                columns[i + 1].push(carry);
                result
            }
            _ => unreachable!(),
        };
        output.push(bit);
    }
    for extra in &columns[width] {
        pin_zero(b, extra);
    }
    output
}

fn sparse(b: &mut FieldR1csBuilder, bits: Vec<LinExpr>) -> Vec<LinExpr> {
    bits.into_iter()
        .map(|bit| {
            if bit.terms.len() <= 1 {
                bit
            } else {
                LinExpr::from_wire(b.materialize(&bit))
            }
        })
        .collect()
}

/// The checked subtraction fixes the half order. Equal halves give zero
/// for either selector, and every resulting bit remains boolean.
fn absolute_difference(
    b: &mut FieldR1csBuilder,
    a: &[LinExpr],
    c: &[LinExpr],
) -> (Vec<LinExpr>, LinExpr) {
    assert_eq!(a.len(), c.len());
    if a.iter().all(static_zero) {
        return (c.to_vec(), LinExpr::constant(F128::ONE));
    }
    if c.iter().all(static_zero) {
        return (a.to_vec(), LinExpr::zero());
    }
    if a == c {
        return (vec![LinExpr::zero(); a.len()], LinExpr::zero());
    }
    let exchange = a
        .iter()
        .zip(c)
        .rev()
        .find_map(|(a, c)| {
            let a = a.eval(b.values());
            let c = c.eval(b.values());
            (a != c).then_some(a == F128::ZERO && c == F128::ONE)
        })
        .unwrap_or(false);
    let exchange = LinExpr::from_wire(b.alloc_bool(exchange));
    let delta = a
        .iter()
        .zip(c)
        .map(|(a, c)| mul(b, &exchange, &a.add(c)))
        .collect::<Vec<_>>();
    let larger = a
        .iter()
        .zip(&delta)
        .map(|(a, d)| a.add(d))
        .collect::<Vec<_>>();
    let smaller = c
        .iter()
        .zip(&delta)
        .map(|(c, d)| c.add(d))
        .collect::<Vec<_>>();
    let difference = checked_subtract(b, &larger, &smaller);
    (sparse(b, difference), exchange)
}

/// One full adder performs either unsigned addition or subtraction. The
/// final carry establishes zero overflow or zero borrow for the selected mode.
fn checked_signed_add(
    b: &mut FieldR1csBuilder,
    a: &[LinExpr],
    c: &[LinExpr],
    subtract: &LinExpr,
) -> Vec<LinExpr> {
    assert_eq!(a.len(), c.len());
    let mut carry = subtract.clone();
    let mut result = Vec::with_capacity(a.len());
    for (a, c) in a.iter().zip(c) {
        let c = c.add(subtract);
        result.push(a.add(&c).add(&carry));
        carry = majority(b, a, &c, &carry);
    }
    let invalid = carry.add(subtract);
    pin_zero(b, &invalid);
    result
}

/// Difference-form integer Karatsuba with exact carries and full output width.
/// Static high zeros select the exact narrower product. Operand bits are
/// boolean and widths are fixed by the owning relation.
pub fn multiply(b: &mut FieldR1csBuilder, a: &[LinExpr], c: &[LinExpr]) -> Vec<LinExpr> {
    assert_eq!(a.len(), c.len());
    assert!(!a.is_empty());
    let width = a.len() + c.len();
    let used_a = a.iter().rposition(|x| !static_zero(x)).map_or(0, |i| i + 1);
    let used_c = c.iter().rposition(|x| !static_zero(x)).map_or(0, |i| i + 1);
    if used_a == 0 || used_c == 0 {
        return vec![LinExpr::zero(); width];
    }
    if used_a.min(used_c) <= 16 {
        return extend(&schoolbook(b, &a[..used_a], &c[..used_c]), width);
    }
    let used = used_a.max(used_c);
    if used < a.len() {
        return extend(&multiply(b, &a[..used], &c[..used]), width);
    }
    let half = a.len().div_ceil(2);
    let (al, ah) = a.split_at(half);
    let (cl, ch) = c.split_at(half);
    let low = multiply(b, al, cl);
    let high = multiply(b, ah, ch);
    let (difference_a, order_a) = absolute_difference(b, al, &extend(ah, half));
    let (difference_c, order_c) = absolute_difference(b, cl, &extend(ch, half));
    let difference = multiply(b, &difference_a, &difference_c);
    let cross_width = 2 * half + 1;
    let sum = checked_add(b, &extend(&low, cross_width), &extend(&high, cross_width));
    let subtract = order_a.add(&order_c).add_const(F128::ONE);
    let cross = checked_signed_add(b, &sum, &extend(&difference, cross_width), &subtract);
    let used_cross_width = a.len() + 1;
    for bit in &cross[used_cross_width..] {
        pin_zero(b, bit);
    }
    let mut disjoint = low;
    disjoint.extend(high);
    assert_eq!(disjoint.len(), width);
    checked_add(
        b,
        &disjoint,
        &shifted(&cross[..used_cross_width], half, width),
    )
}
