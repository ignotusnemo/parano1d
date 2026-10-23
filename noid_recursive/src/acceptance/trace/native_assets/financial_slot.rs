// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete native carrier framing and exact NOID-value binding.

use noid_tx::native_assets::{
    market::MARKET_REQUEST_FEE_CREDIT, nft_market::NFT_FEE_CREDIT, NativeKind,
    MAX_NATIVE_OPENING_FIELDS,
};

use super::super::public_arithmetic::{PackedInputValueTrace, U64Trace};
use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::range_check_bits;
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, pack};
use super::financial_opening::{
    bind_financial_opening_frame, financial_opening_root_trace,
    sequential_financial_opening_root_trace, FinancialOpeningRootTrace,
};
use super::validation::{is_zero, require_nonzero};

pub struct FinancialSlotTrace {
    pub commitment: FinancialOpeningRootTrace,
    pub fields: [LinExpr; MAX_NATIVE_OPENING_FIELDS],
    pub live: LinExpr,
    pub amount: LinExpr,
    pub amount_bits: Vec<LinExpr>,
    pub creation_id: U64Trace,
}

fn zero_pair(b: &mut FieldR1csBuilder, pair: &[LinExpr]) -> LinExpr {
    let first = is_zero(b, &pair[0]);
    let second = is_zero(b, &pair[1]);
    mul(b, &first, &second)
}

/// Select the raw carrier's NOID value from the same committed schema fields.
/// Integer sums have a zero final carry, including fee-credit escrow.
fn amount_from_fields(
    b: &mut FieldR1csBuilder,
    root: &FinancialOpeningRootTrace,
    fields: &[LinExpr; MAX_NATIVE_OPENING_FIELDS],
) -> (LinExpr, Vec<LinExpr>) {
    use NativeKind::*;
    let s = |kind| root.selector(kind).clone();
    let mut main = LinExpr::zero();
    for (kind, field) in [
        (TokenReserve, 2),
        (MarketPool, 2),
        (MarketRequest, 10),
        (MarketClaim, 10),
        (MarketLiquidityDeposit, 6),
        (MarketLiquidityClaim, 6),
        (LaunchState, 2),
        (LaunchRequest, 8),
        (NftPurchase, 8),
        (NftOffer, 7),
    ] {
        main = main.add(&mul(b, &s(kind), &fields[field]));
    }
    let main = split_packed_input_value(b, &main);
    let flag_kinds = s(MarketPool)
        .add(&s(MarketLiquidityDeposit))
        .add(&s(MarketLiquidityClaim));
    let flags = mul(b, &flag_kinds, &fields[7]);
    let flags = range_check_bits(b, &flags, 128)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let pool_noid = mul(b, &s(MarketPool), &flags[88]);
    let deposit_noid = mul(b, &s(MarketLiquidityDeposit), &flags[63]);
    let claim_noid = mul(b, &s(MarketLiquidityClaim), &flags[127]);
    let input_zero = zero_pair(b, &fields[2..4]);
    let output_zero = zero_pair(b, &fields[4..6]);
    let request_noid = mul(b, &s(MarketRequest), &input_zero);
    let refund_noid = mul(b, &s(MarketClaim), &input_zero);
    let output_only = mul(b, &input_zero.add_const(F128::ONE), &output_zero);
    let output_noid = mul(b, &s(MarketClaim), &output_only);
    let launch_side = mul(b, &s(LaunchRequest), &fields[9]);
    let launch_side = range_check_bits(b, &launch_side, 65);
    let launch_buy = mul(
        b,
        &s(LaunchRequest),
        &LinExpr::from_wire(launch_side[64]).add_const(F128::ONE),
    );
    let low = s(TokenReserve)
        .add(&pool_noid)
        .add(&request_noid)
        .add(&refund_noid)
        .add(&deposit_noid)
        .add(&claim_noid)
        .add(&s(NftPurchase))
        .add(&s(NftOffer));
    let high = s(LaunchState).add(&launch_buy).add(&output_noid);
    let cash = (0..64)
        .map(|index| {
            let lo = mul(b, &low, &LinExpr::from_wire(main.amount.bits[index]));
            lo.add(&mul(
                b,
                &high,
                &LinExpr::from_wire(main.creation_id.bits[index]),
            ))
        })
        .collect::<Vec<_>>();
    let ordinary_credit = s(MarketRequest)
        .add(&s(MarketLiquidityDeposit))
        .add(&s(MarketLiquidityWithdrawal))
        .add(&s(MarketLiquidityBurn))
        .add(&s(LaunchRequest));
    let nft_credit = s(NftListing).add(&s(NftPurchase)).add(&s(NftOffer));
    let mut credit = ordinary_credit
        .scale(flat_const(u128::from(MARKET_REQUEST_FEE_CREDIT)))
        .add(&nft_credit.scale(flat_const(u128::from(NFT_FEE_CREDIT))));
    credit = credit.add(&mul(b, &s(MarketClaim), &fields[11]));
    credit = credit.add(&mul(b, &s(MarketLiquidityClaim), &pack(&flags[64..127])));
    let credit = range_check_bits(b, &credit, 64)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let bits = checked_add(b, &cash, &credit);
    (pack(&bits), bits)
}

fn sequential_amount_from_fields(
    b: &mut FieldR1csBuilder,
    root: &FinancialOpeningRootTrace,
    fields: &[LinExpr; MAX_NATIVE_OPENING_FIELDS],
) -> (LinExpr, Vec<LinExpr>) {
    let reserve = root.selector(NativeKind::TokenReserve);
    let pool = root.selector(NativeKind::MarketPool);
    let launch = root.selector(NativeKind::LaunchState);
    let listing = root.selector(NativeKind::NftListing);
    let carrier = reserve.add(pool).add(launch);
    let main = mul(b, &carrier, &fields[2]);
    let main = split_packed_input_value(b, &main);
    let flags = mul(b, pool, &fields[7]);
    let flags = range_check_bits(b, &flags, 89);
    let low = reserve.add(&LinExpr::from_wire(flags[88]));
    let amount_bits = (0..64)
        .map(|index| {
            let low = mul(b, &low, &LinExpr::from_wire(main.amount.bits[index]));
            let high = mul(b, launch, &LinExpr::from_wire(main.creation_id.bits[index]));
            let mut bit = low.add(&high);
            // Each amount source belongs to a distinct one-hot carrier kind.
            if (NFT_FEE_CREDIT >> index) & 1 != 0 {
                bit = bit.add(listing);
            }
            bit
        })
        .collect::<Vec<_>>();
    (pack(&amount_bits), amount_bits)
}

/// Bind one native carrier after the shared body-order allocator. Typed
/// ownership, time bounds and operation-specific transitions consume the
/// returned fields and the exact header in the financial operation relation.
pub fn bind_financial_slot(
    b: &mut FieldR1csBuilder,
    kind: &LinExpr,
    fields: &[LinExpr; MAX_NATIVE_OPENING_FIELDS],
    slot: &LinExpr,
    packed: &PackedInputValueTrace,
    root: &[LinExpr; 2],
) -> FinancialSlotTrace {
    let commitment = financial_opening_root_trace(b, kind, fields);
    bind_slot(b, commitment, fields, slot, packed, root, false)
}

pub fn bind_sequential_financial_slot(
    b: &mut FieldR1csBuilder,
    kind: &LinExpr,
    fields: &[LinExpr; MAX_NATIVE_OPENING_FIELDS],
    slot: &LinExpr,
    packed: &PackedInputValueTrace,
    root: &[LinExpr; 2],
) -> FinancialSlotTrace {
    let commitment = sequential_financial_opening_root_trace(b, kind, fields);
    bind_slot(b, commitment, fields, slot, packed, root, true)
}

fn bind_slot(
    b: &mut FieldR1csBuilder,
    commitment: FinancialOpeningRootTrace,
    fields: &[LinExpr; MAX_NATIVE_OPENING_FIELDS],
    slot: &LinExpr,
    packed: &PackedInputValueTrace,
    root: &[LinExpr; 2],
    sequential: bool,
) -> FinancialSlotTrace {
    bind_financial_opening_frame(b, &commitment, fields);
    let live = commitment.inactive.add_const(F128::ONE);
    let auxiliary = commitment
        .selector(NativeKind::MarketDefinition)
        .add(commitment.selector(NativeKind::LaunchDefinition))
        .add(commitment.selector(NativeKind::NftListingDefinition));
    pin_zero(b, &auxiliary);
    range_check_bits(b, slot, 32);
    let inactive_slot = mul(b, &commitment.inactive, slot);
    pin_zero(b, &inactive_slot);
    for lane in 0..2 {
        pin_eq(b, &root[lane], &commitment.root[lane]);
    }
    pin_zero(b, &LinExpr::from_wire(packed.creation_id.bits[63]));
    pin_eq(b, &LinExpr::from_wire(packed.creation_id.bits[62]), &live);
    let sequence = packed.creation_id.bits[..62]
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    require_nonzero(b, &pack(&sequence), &live);
    let inactive_id = mul(b, &commitment.inactive, &packed.creation_id.value);
    pin_zero(b, &inactive_id);
    let (amount, amount_bits) = if sequential {
        sequential_amount_from_fields(b, &commitment, fields)
    } else {
        amount_from_fields(b, &commitment, fields)
    };
    pin_eq(b, &packed.amount.value, &amount);
    FinancialSlotTrace {
        commitment,
        fields: fields.clone(),
        live,
        amount,
        amount_bits,
        creation_id: packed.creation_id.clone(),
    }
}
