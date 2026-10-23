// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Typed carrier values shared by the complete financial operation relation.

use noid_tx::native_assets::{
    launch::{LAUNCH_MAX_SUPPLY, LAUNCH_PROFILE},
    market::{
        queue::MAX_ROUND_REQUESTS, MARKET_FEE_BPS, MARKET_MIN_LOCKED_SHARES, MARKET_PROFILE,
        MARKET_QUANTITY_MAX, MARKET_REQUEST_FEE_CREDIT, MARKET_SETTLEMENT_WINDOW,
    },
    nft_market::{NFT_FEE_CREDIT, NFT_MARKET_PROFILE},
    NativeKind,
};

use super::super::public_arithmetic::PackedInputValueTrace;
use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, less_than, pack};
use super::financial_definitions::{constant_bits, value_bits};
use super::financial_slot::FinancialSlotTrace;
use super::validation::{
    bind_native_opening_values, is_zero, nonzero_pair, require_nonzero, NativeOpeningTrace,
};
use super::NativeOpeningRootTrace;

pub struct FinancialCarrierValuesTrace {
    pub base: NativeOpeningTrace,
    pub primary: PackedInputValueTrace,
    pub secondary: PackedInputValueTrace,
    pub frozen: LinExpr,
    pub registered_height: LinExpr,
    pub queue_root: [LinExpr; 2],
}

fn pair_nonzero(b: &mut FieldR1csBuilder, pair: &[LinExpr; 2], when: &LinExpr) {
    nonzero_pair(b, pair, when);
}

fn pair_zero(b: &mut FieldR1csBuilder, pair: &[LinExpr; 2]) -> LinExpr {
    let a = is_zero(b, &pair[0]);
    let c = is_zero(b, &pair[1]);
    mul(b, &a, &c)
}

fn no_more_than(b: &mut FieldR1csBuilder, bits: &[LinExpr], limit: u64, when: &LinExpr) {
    let exceeded = less_than(b, &constant_bits(u128::from(limit), bits.len()), bits);
    let invalid = mul(b, when, &exceeded);
    pin_zero(b, &invalid);
}

fn base_values(b: &mut FieldR1csBuilder, slot: &FinancialSlotTrace) -> NativeOpeningTrace {
    let kinds = [
        NativeKind::FungibleDefinition,
        NativeKind::TokenBalance,
        NativeKind::TokenReserve,
        NativeKind::NftCollection,
        NativeKind::NftItem,
    ];
    let active = kinds.iter().fold(LinExpr::zero(), |sum, &kind| {
        sum.add(slot.commitment.selector(kind))
    });
    let selectors = std::array::from_fn(|i| {
        if i == 0 {
            active.add_const(F128::ONE)
        } else {
            slot.commitment.selector(kinds[i - 1]).clone()
        }
    });
    let root = [
        mul(b, &active, &slot.commitment.root[0]),
        mul(b, &active, &slot.commitment.root[1]),
    ];
    let fields: [LinExpr; 8] = std::array::from_fn(|i| mul(b, &active, &slot.fields[i]));
    bind_native_opening_values(b, NativeOpeningRootTrace { selectors, root }, &fields)
}

/// Validate every carrier's identifiers, owners, quantities and control
/// phase frame. Pool product bounds and launch-definition cash/inventory
/// relations consume these same fields in the bounded control relation.
pub fn bind_financial_carrier_values(
    b: &mut FieldR1csBuilder,
    slot: &FinancialSlotTrace,
) -> FinancialCarrierValuesTrace {
    use NativeKind::*;
    let base = base_values(b, slot);
    let s = |kind| slot.commitment.selector(kind).clone();
    let financial = slot.live.add(&base.live);
    pair_nonzero(
        b,
        &[slot.fields[0].clone(), slot.fields[1].clone()],
        &financial,
    );
    let second = s(MarketLiquidity)
        .add(&s(MarketLiquidityDeposit))
        .add(&s(MarketLiquidityWithdrawal))
        .add(&s(MarketLiquidityClaim))
        .add(&s(MarketLiquidityBurn))
        .add(&s(LaunchRequest))
        .add(&s(NftListing))
        .add(&s(NftPurchase))
        .add(&s(NftOffer));
    pair_nonzero(
        b,
        &[slot.fields[2].clone(), slot.fields[3].clone()],
        &second,
    );
    let third = s(MarketLiquidityDeposit)
        .add(&s(MarketLiquidityWithdrawal))
        .add(&s(MarketLiquidityClaim))
        .add(&s(MarketLiquidityBurn))
        .add(&s(LaunchRequest))
        .add(&s(NftPurchase))
        .add(&s(NftOffer));
    pair_nonzero(b, &[slot.fields[4].clone(), slot.fields[5].clone()], &third);
    let fourth = s(MarketRequest)
        .add(&s(MarketClaim))
        .add(&s(LaunchRequest))
        .add(&s(NftPurchase));
    pair_nonzero(
        b,
        &[slot.fields[6].clone(), slot.fields[7].clone()],
        &fourth,
    );
    let fifth = s(MarketRequest).add(&s(MarketClaim));
    pair_nonzero(b, &[slot.fields[8].clone(), slot.fields[9].clone()], &fifth);
    let equal_assets = pair_zero(
        b,
        &[
            slot.fields[2].add(&slot.fields[4]),
            slot.fields[3].add(&slot.fields[5]),
        ],
    );
    let same_asset = mul(b, &fifth, &equal_assets);
    pin_zero(b, &same_asset);

    let mut primary = LinExpr::zero();
    for (kind, field) in [
        (MarketPool, 2),
        (MarketRequest, 10),
        (MarketClaim, 10),
        (MarketLiquidity, 4),
        (MarketLiquidityDeposit, 6),
        (MarketLiquidityWithdrawal, 6),
        (MarketLiquidityClaim, 6),
        (MarketLiquidityBurn, 6),
        (LaunchState, 2),
        (LaunchRequest, 8),
        (NftListing, 4),
        (NftPurchase, 8),
        (NftOffer, 7),
    ] {
        primary = primary.add(&mul(b, &s(kind), &slot.fields[field]));
    }
    let primary = split_packed_input_value(b, &primary);
    let low = primary
        .amount
        .bits
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let high = primary
        .creation_id
        .bits
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let positive_low = financial.add(&s(MarketClaim)).add(&s(MarketLiquidityClaim));
    require_nonzero(b, &primary.amount.value, &positive_low);
    let narrow_low = financial.add(&s(NftListing));
    let large_low = mul(b, &narrow_low, &low[63]);
    pin_zero(b, &large_low);
    let narrow_high = s(MarketPool)
        .add(&s(MarketRequest))
        .add(&s(MarketClaim))
        .add(&s(MarketLiquidityDeposit))
        .add(&s(MarketLiquidityClaim))
        .add(&s(LaunchState))
        .add(&s(LaunchRequest));
    let large_high = mul(b, &narrow_high, &high[63]);
    pin_zero(b, &large_high);
    let positive_high = s(MarketPool)
        .add(&s(MarketRequest))
        .add(&s(MarketLiquidityDeposit))
        .add(&s(NftOffer));
    require_nonzero(b, &primary.creation_id.value, &positive_high);
    let output_zero = is_zero(b, &primary.amount.value);
    let other_zero = is_zero(b, &primary.creation_id.value);
    let both_zero = mul(b, &output_zero, &other_zero);
    let empty_claim = mul(b, &s(MarketClaim), &both_zero);
    pin_zero(b, &empty_claim);
    // For the fixed positive fee below one half, effective input is positive
    // exactly when gross input is at least two.
    const _: () = assert!(MARKET_FEE_BPS > 0 && MARKET_FEE_BPS <= 5_000);
    let unit = is_zero(b, &primary.amount.value.add_const(F128::ONE));
    let ineffective = mul(b, &s(MarketRequest), &unit);
    pin_zero(b, &ineffective);
    no_more_than(
        b,
        &low,
        LAUNCH_MAX_SUPPLY,
        &s(LaunchState).add(&s(LaunchRequest)),
    );
    no_more_than(
        b,
        &low,
        MARKET_QUANTITY_MAX - 2 * NFT_FEE_CREDIT,
        &s(NftPurchase),
    );
    no_more_than(b, &low, MARKET_QUANTITY_MAX - NFT_FEE_CREDIT, &s(NftOffer));

    let mut secondary = LinExpr::zero();
    for (kind, field) in [
        (MarketPool, 3),
        (MarketRequest, 11),
        (MarketClaim, 11),
        (MarketLiquidityDeposit, 7),
        (MarketLiquidityWithdrawal, 7),
        (MarketLiquidityClaim, 7),
        (LaunchRequest, 9),
        (NftPurchase, 9),
        (NftOffer, 6),
    ] {
        secondary = secondary.add(&mul(b, &s(kind), &slot.fields[field]));
    }
    let secondary = split_packed_input_value(b, &secondary);
    let low2 = secondary
        .amount
        .bits
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let high2 = secondary
        .creation_id
        .bits
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let narrow2_low = s(MarketPool)
        .add(&s(MarketLiquidityWithdrawal))
        .add(&s(MarketLiquidityClaim));
    let too_big = mul(b, &narrow2_low, &low2[63]);
    pin_zero(b, &too_big);
    let too_big = mul(b, &s(MarketLiquidityWithdrawal), &high2[63]);
    pin_zero(b, &too_big);
    require_nonzero(b, &secondary.amount.value, &s(MarketPool));
    let low_locked = less_than(
        b,
        &high2,
        &constant_bits(u128::from(MARKET_MIN_LOCKED_SHARES), 64),
    );
    let invalid_locked = mul(b, &s(MarketPool), &low_locked);
    pin_zero(b, &invalid_locked);
    let unlocked = secondary.amount.value.add(&secondary.creation_id.value);
    let invalid_locked = mul(b, &s(MarketPool), &unlocked);
    pin_zero(b, &invalid_locked);
    require_nonzero(b, &pack(&low2[..63]), &s(MarketLiquidityDeposit));
    require_nonzero(b, &secondary.creation_id.value, &s(NftOffer));
    let bad_profile = mul(
        b,
        &s(MarketRequest),
        &secondary
            .creation_id
            .value
            .add_const(flat_const(u128::from(MARKET_PROFILE))),
    );
    pin_zero(b, &bad_profile);
    let bad_profile = mul(
        b,
        &s(LaunchRequest),
        &slot.fields[10].add_const(flat_const(u128::from(LAUNCH_PROFILE))),
    );
    pin_zero(b, &bad_profile);
    let bad_profile = mul(
        b,
        &s(NftPurchase),
        &secondary
            .amount
            .value
            .add_const(flat_const(u128::from(NFT_MARKET_PROFILE))),
    );
    pin_zero(b, &bad_profile);
    let buy = mul(
        b,
        &s(LaunchRequest),
        &secondary.creation_id.value.add_const(F128::ONE),
    );
    require_nonzero(b, &primary.creation_id.value, &buy);
    let credit = (0..64)
        .map(|i| {
            let a = mul(b, &s(MarketClaim), &low2[i]);
            if i == 63 {
                a
            } else {
                a.add(&mul(b, &s(MarketLiquidityClaim), &high2[i]))
            }
        })
        .collect::<Vec<_>>();
    no_more_than(
        b,
        &credit,
        MARKET_REQUEST_FEE_CREDIT,
        &LinExpr::constant(F128::ONE),
    );
    let empty_shares = is_zero(b, &secondary.amount.value);
    let no_credit = is_zero(b, &pack(&credit));
    let empty_lp = mul(b, &both_zero, &empty_shares);
    let empty_lp = mul(b, &empty_lp, &no_credit);
    let invalid_lp = mul(b, &s(MarketLiquidityClaim), &empty_lp);
    pin_zero(b, &invalid_lp);

    let control = s(MarketPool).add(&s(LaunchState)).add(&s(NftListing));
    let mut meta = mul(b, &s(MarketPool).add(&s(NftListing)), &slot.fields[7]);
    meta = meta.add(&mul(b, &s(LaunchState), &slot.fields[6]));
    let meta = value_bits(b, &meta, 89);
    let frozen = meta[80].clone();
    let idle = control.add(&frozen);
    let count = pack(&meta[64..80]);
    require_nonzero(b, &count, &frozen);
    no_more_than(
        b,
        &meta[64..80],
        MAX_ROUND_REQUESTS as u64,
        &LinExpr::constant(F128::ONE),
    );
    let idle_count = mul(b, &idle, &count);
    pin_zero(b, &idle_count);
    let mut temporal = mul(b, &s(MarketPool), &slot.fields[6]);
    temporal = temporal.add(&mul(b, &s(LaunchState), &slot.fields[3]));
    let temporal = split_packed_input_value(b, &temporal);
    let registered = (0..64)
        .map(|i| {
            LinExpr::from_wire(temporal.creation_id.bits[i]).add(&mul(b, &s(NftListing), &meta[i]))
        })
        .collect::<Vec<_>>();
    let registered_height = pack(&registered);
    require_nonzero(b, &registered_height, &frozen);
    let idle_height = mul(b, &idle, &registered_height);
    pin_zero(b, &idle_height);
    let timeout_delta = constant_bits(u128::from(MARKET_SETTLEMENT_WINDOW), 64)
        .iter()
        .map(|bit| mul(b, &frozen, bit))
        .collect::<Vec<_>>();
    let timeout = checked_add(b, &registered, &timeout_delta);
    let stored = s(MarketPool).add(&s(LaunchState));
    let actual = mul(b, &stored, &pack(&meta[..64]));
    let expected = mul(b, &stored, &pack(&timeout));
    pin_eq(b, &actual, &expected);
    let queue_root = std::array::from_fn(|i| {
        let a = mul(b, &s(MarketPool).add(&s(LaunchState)), &slot.fields[4 + i]);
        a.add(&mul(b, &s(NftListing), &slot.fields[5 + i]))
    });
    pair_nonzero(b, &queue_root, &frozen);
    for lane in &queue_root {
        let invalid = mul(b, &idle, lane);
        pin_zero(b, &invalid);
    }
    let request_height = (0..64)
        .map(|i| {
            let a = mul(b, &s(MarketRequest).add(&s(LaunchRequest)), &low2[i]);
            let c = mul(b, &s(MarketLiquidityDeposit), &high2[i]);
            a.add(&c).add(&mul(
                b,
                &s(MarketLiquidityWithdrawal)
                    .add(&s(MarketLiquidityBurn))
                    .add(&s(NftPurchase)),
                &high[i],
            ))
        })
        .collect::<Vec<_>>();
    let request = s(MarketRequest)
        .add(&s(LaunchRequest))
        .add(&s(MarketLiquidityDeposit))
        .add(&s(MarketLiquidityWithdrawal))
        .add(&s(MarketLiquidityBurn))
        .add(&s(NftPurchase));
    require_nonzero(b, &pack(&request_height), &request);
    let delta = constant_bits(u128::from(MARKET_SETTLEMENT_WINDOW), 64)
        .iter()
        .map(|bit| mul(b, &request, bit))
        .collect::<Vec<_>>();
    checked_add(b, &request_height, &delta);
    FinancialCarrierValuesTrace {
        base,
        primary,
        secondary,
        frozen,
        registered_height,
        queue_root,
    }
}
