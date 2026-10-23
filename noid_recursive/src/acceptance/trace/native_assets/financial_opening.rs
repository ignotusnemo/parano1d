// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical opening commitments for the complete native financial schema.

use noid_poseidon2b::native::capacity_iv;
use noid_tx::native_assets::{NativeKind, MAX_NATIVE_OPENING_FIELDS};

use super::super::{
    flat_const, flat_of, mul, pin_eq, pin_zero, poseidon2b_permute, FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::range_check_bits;
use super::validation::is_zero;

pub struct FinancialOpeningRootTrace {
    pub inactive: LinExpr,
    /// Entries follow the stable NativeKind::ALL order.
    pub selectors: [LinExpr; NativeKind::ALL.len()],
    pub root: [LinExpr; 2],
}
impl FinancialOpeningRootTrace {
    pub fn selector(&self, kind: NativeKind) -> &LinExpr {
        let index = NativeKind::ALL
            .iter()
            .position(|&k| k == kind)
            .expect("native kind");
        &self.selectors[index]
    }
}

/// Fix the domain, absorption length and zero tails independently of the
/// witness kind. The operation relation binds typed values and State actions.
pub fn financial_opening_root_trace(
    b: &mut FieldR1csBuilder,
    kind: &LinExpr,
    fields: &[LinExpr; MAX_NATIVE_OPENING_FIELDS],
) -> FinancialOpeningRootTrace {
    opening_root_trace(
        b,
        kind,
        fields,
        noid_tx::native_assets::profile::kind_enabled,
    )
}

/// Use the carrier schema of the sequential financial profile.
pub fn sequential_financial_opening_root_trace(
    b: &mut FieldR1csBuilder,
    kind: &LinExpr,
    fields: &[LinExpr; MAX_NATIVE_OPENING_FIELDS],
) -> FinancialOpeningRootTrace {
    opening_root_trace(
        b,
        kind,
        fields,
        noid_tx::native_assets::profile::sequential_kind_enabled,
    )
}

fn opening_root_trace(
    b: &mut FieldR1csBuilder,
    kind: &LinExpr,
    fields: &[LinExpr; MAX_NATIVE_OPENING_FIELDS],
    enabled: fn(NativeKind) -> bool,
) -> FinancialOpeningRootTrace {
    const _: () = assert!(MAX_NATIVE_OPENING_FIELDS == 12);
    range_check_bits(b, kind, 7);
    let inactive = is_zero(b, kind);
    let selectors = NativeKind::ALL.map(|k| {
        if enabled(k) {
            is_zero(b, &kind.add_const(flat_const(k as u128)))
        } else {
            LinExpr::zero()
        }
    });
    let selected = selectors.iter().fold(inactive.clone(), |sum, s| sum.add(s));
    pin_eq(b, &selected, &LinExpr::constant(F128::ONE));

    for (index, field) in fields.iter().enumerate() {
        let unused = NativeKind::ALL
            .iter()
            .zip(&selectors)
            .filter(|(k, _)| index >= k.field_count())
            .fold(inactive.clone(), |sum, (_, s)| sum.add(s));
        let nonzero_tail = mul(b, &unused, field);
        pin_zero(b, &nonzero_tail);
    }
    let mut iv = [LinExpr::zero(), LinExpr::zero()];
    let mut lengths: [LinExpr; 3] = std::array::from_fn(|_| LinExpr::zero());
    for (&k, selector) in NativeKind::ALL.iter().zip(&selectors) {
        let constants = capacity_iv(k.tag());
        for lane in 0..2 {
            iv[lane] = iv[lane].add(&selector.scale(flat_of(constants[lane])));
        }
        let length = match k.field_count() {
            6 => 0,
            8 => 1,
            12 => 2,
            _ => unreachable!("native width"),
        };
        lengths[length] = lengths[length].add(selector);
    }
    let mut state = [
        LinExpr::zero(),
        LinExpr::zero(),
        iv[0].clone(),
        iv[1].clone(),
    ];
    let mut root = [LinExpr::zero(), LinExpr::zero()];
    let max_fields = NativeKind::ALL
        .iter()
        .copied()
        .filter(|&kind| enabled(kind))
        .map(NativeKind::field_count)
        .max()
        .expect("nonempty native schema");
    for (index, pair) in fields[..max_fields].chunks_exact(2).enumerate() {
        state[0] = state[0].add(&pair[0]);
        state[1] = state[1].add(&pair[1]);
        state = poseidon2b_permute(b, state);
        let length = match index {
            2 => Some(0),
            3 => Some(1),
            5 => Some(2),
            _ => None,
        };
        if let Some(length) = length {
            for lane in 0..2 {
                root[lane] = root[lane].add(&mul(b, &lengths[length], &state[lane]));
            }
        }
    }
    FinancialOpeningRootTrace {
        inactive,
        selectors,
        root,
    }
}

/// Bind reserved lanes and truncated integer fields to canonical codec form.
pub fn bind_financial_opening_frame(
    b: &mut FieldR1csBuilder,
    opening: &FinancialOpeningRootTrace,
    fields: &[LinExpr; MAX_NATIVE_OPENING_FIELDS],
) {
    use NativeKind::*;
    for (k, field) in [
        (FungibleDefinition, 7),
        (TokenBalance, 5),
        (NftCollection, 7),
        (NftItem, 7),
        (MarketDefinition, 7),
        (MarketLiquidity, 5),
        (MarketLiquidityBurn, 7),
        (LaunchDefinition, 7),
        (LaunchState, 7),
        (LaunchRequest, 11),
        (NftPurchase, 10),
        (NftPurchase, 11),
    ] {
        let padding = mul(b, opening.selector(k), &fields[field]);
        pin_zero(b, &padding);
    }
    for (k, field, width) in [
        (TokenReserve, 3, 64),
        (MarketDefinition, 6, 64),
        (MarketClaim, 11, 64),
        (LaunchRequest, 9, 65),
        (LaunchRequest, 10, 64),
        (NftPurchase, 9, 64),
        (MarketPool, 7, 89),
        (LaunchState, 6, 81),
        (NftListing, 7, 81),
    ] {
        let selected = mul(b, opening.selector(k), &fields[field]);
        let bits = range_check_bits(b, &selected, width);
        if k == MarketPool {
            for &bit in &bits[81..88] {
                pin_zero(b, &LinExpr::from_wire(bit));
            }
        }
    }
}
