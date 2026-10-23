// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact bootstrap shares from the shared pool product remainder.

use super::super::{flat_const, mul, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::{extend, less_than};
use noid_tx::native_assets::market::MARKET_MIN_LOCKED_SHARES;

/// The caller binds Boolean share bits and the exact nonnegative remainder
/// base*quote - shares^2 through the shared control arithmetic. This upper
/// bound completes the integer square root without another multiplication.
pub fn bind_bootstrap_share_root(
    b: &mut FieldR1csBuilder,
    live: &LinExpr,
    shares: &[LinExpr],
    remainder: &[LinExpr],
) {
    assert_eq!(shares.len(), 63);
    assert_eq!(remainder.len(), 126);
    let bad = mul(b, live, &live.add_const(F128::ONE));
    pin_zero(b, &bad);
    let minimum = (0..63)
        .map(|i| LinExpr::constant(flat_const((u128::from(MARKET_MIN_LOCKED_SHARES) >> i) & 1)))
        .collect::<Vec<_>>();
    let large = less_than(b, &minimum, shares);
    let bad = mul(b, live, &large.add_const(F128::ONE));
    pin_zero(b, &bad);
    let mut bound = vec![LinExpr::constant(F128::ONE)];
    bound.extend(shares.iter().cloned());
    let proper = less_than(b, remainder, &extend(&bound, 126));
    let bad = mul(b, live, &proper.add_const(F128::ONE));
    pin_zero(b, &bad);
}
