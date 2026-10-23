// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical typed quantities, authority and exact native slot bindings.

use noid_tx::asset_backing::MIN_BACKING_MICRONOID_PER_TOKEN;
use noid_tx::native_assets::{
    COMPACT_NATIVE_OPENING_FIELDS as MAX_NATIVE_OPENING_FIELDS, TOKEN_UNITS,
};

use super::super::public_arithmetic::{split_packed_input_value, PackedInputValueTrace, U64Trace};
use super::super::{
    flat_const, mul, pin_eq, pin_zero, range_check_bits, FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::{checked_add, extend, less_than, pack, shifted};
use super::{native_opening_root_trace, NativeOpeningRootTrace};

pub struct NativeOpeningTrace {
    pub commitment: NativeOpeningRootTrace,
    pub fields: [LinExpr; MAX_NATIVE_OPENING_FIELDS],
    pub live: LinExpr,
    pub identifier: [LinExpr; 2],
    pub owner: [LinExpr; 2],
    /// Supply, balance units, collection cap or item serial, by kind.
    pub primary: U64Trace,
    /// Route, unlock height, issued count or item unlock height, by kind.
    pub secondary: U64Trace,
    pub reserve_micronoid: U64Trace,
    pub outstanding_units: U64Trace,
    pub initial_supply: U64Trace,
    pub definition_root: [LinExpr; 2],
    pub metadata: [LinExpr; 2],
}

pub struct NativeContextTrace {
    pub live: LinExpr,
    pub authority: [LinExpr; 2],
    pub height: U64Trace,
}

pub(super) fn bits(value: &U64Trace) -> Vec<LinExpr> {
    value.bits.iter().copied().map(LinExpr::from_wire).collect()
}

fn u64_value(b: &mut FieldR1csBuilder, value: LinExpr) -> U64Trace {
    let bits = range_check_bits(b, &value, 64).try_into().unwrap();
    U64Trace { value, bits }
}

/// The inverse is a witness only. These two equations fix the result to one
/// exactly when the input field element is zero.
pub fn is_zero(b: &mut FieldR1csBuilder, value: &LinExpr) -> LinExpr {
    let x = value.eval(b.values());
    let zero = LinExpr::from_wire(b.alloc_f128(if x == F128::ZERO {
        F128::ONE
    } else {
        F128::ZERO
    }));
    let inverse =
        LinExpr::from_wire(b.alloc_f128(if x == F128::ZERO { F128::ZERO } else { x.inv() }));
    let check = mul(b, value, &inverse).add(&zero);
    pin_eq(b, &check, &LinExpr::constant(F128::ONE));
    let check = mul(b, value, &zero);
    pin_zero(b, &check);
    zero
}

pub fn require_nonzero(b: &mut FieldR1csBuilder, value: &LinExpr, when: &LinExpr) {
    let zero = is_zero(b, value);
    let invalid = mul(b, when, &zero);
    pin_zero(b, &invalid);
}

pub(super) fn nonzero_pair(b: &mut FieldR1csBuilder, value: &[LinExpr; 2], when: &LinExpr) {
    let first = is_zero(b, &value[0]);
    let second = is_zero(b, &value[1]);
    let both = mul(b, &first, &second);
    let invalid = mul(b, when, &both);
    pin_zero(b, &invalid);
}

pub fn bind_native_context(
    b: &mut FieldR1csBuilder,
    live: &LinExpr,
    authority: &[LinExpr; 2],
    height: &LinExpr,
) -> NativeContextTrace {
    let invalid = mul(b, live, &live.add_const(F128::ONE));
    pin_zero(b, &invalid);
    nonzero_pair(b, authority, live);
    NativeContextTrace {
        live: live.clone(),
        authority: authority.clone(),
        height: u64_value(b, height.clone()),
    }
}

/// Validate every native kind with one matrix shape. Kind zero is a zero
/// padding record. The enclosing operation binds the complete routed set of
/// these openings to the raw body and exact State actions.
pub fn bind_native_opening(
    b: &mut FieldR1csBuilder,
    kind: &LinExpr,
    fields: &[LinExpr; MAX_NATIVE_OPENING_FIELDS],
) -> NativeOpeningTrace {
    let commitment = native_opening_root_trace(b, kind, fields);
    bind_native_opening_values(b, commitment, fields)
}

/// Validate fields whose canonical kind, framing and commitment are already
/// bound by the enclosing native schema relation.
pub(super) fn bind_native_opening_values(
    b: &mut FieldR1csBuilder,
    commitment: NativeOpeningRootTrace,
    fields: &[LinExpr; MAX_NATIVE_OPENING_FIELDS],
) -> NativeOpeningTrace {
    let selector = &commitment.selectors;
    let live = selector[0].add_const(F128::ONE);
    let identifier = [fields[0].clone(), fields[1].clone()];
    nonzero_pair(b, &identifier, &live);

    let owned = selector[1]
        .add(&selector[2])
        .add(&selector[4])
        .add(&selector[5]);
    let owner = std::array::from_fn(|i| mul(b, &owned, &fields[2 + i]));
    nonzero_pair(b, &owner, &owned);
    let quantity_kind = selector[1].add(&selector[2]).add(&selector[4]);
    let short = mul(b, &quantity_kind, &fields[4]);
    let item = mul(b, &selector[5], &fields[6]);
    let quantity = split_packed_input_value(b, &short.add(&item));
    require_nonzero(b, &quantity.amount.value, &owned);
    let primary = quantity.amount;
    let secondary = quantity.creation_id;
    let invalid_route = mul(b, &selector[1], &secondary.value.add_const(F128::ONE));
    pin_zero(b, &invalid_route);
    let launch_units = mul(b, &selector[1], &primary.value);
    let launch_bits = primary
        .bits
        .iter()
        .map(|&wire| mul(b, &selector[1], &LinExpr::from_wire(wire)))
        .collect::<Vec<_>>();
    super::financial_definitions::bind_launch_supply(b, &selector[1], &launch_units, &launch_bits);
    let issued_exceeds_cap = less_than(b, &bits(&primary), &bits(&secondary));
    let invalid_cap = mul(b, &selector[4], &issued_exceeds_cap);
    pin_zero(b, &invalid_cap);

    let reserve_pair = mul(b, &selector[3], &fields[2]);
    let reserve = split_packed_input_value(b, &reserve_pair);
    let reserve_micronoid = reserve.amount;
    let outstanding_units = reserve.creation_id;
    let initial = mul(b, &selector[3], &fields[3]);
    let initial_supply = u64_value(b, initial);
    require_nonzero(b, &initial_supply.value, &selector[3]);
    let invalid_supply = less_than(b, &bits(&initial_supply), &bits(&outstanding_units));
    pin_zero(b, &invalid_supply);
    let no_supply = is_zero(b, &outstanding_units.value);
    let residual_reserve = mul(b, &no_supply, &reserve_micronoid.value);
    pin_zero(b, &residual_reserve);

    // With the standard precision, S <= 1000*R is exactly
    // S + 16*R + 8*R <= 1024*R. Reuse the existing u64 decompositions.
    const _: () = assert!(TOKEN_UNITS == 1000 * MIN_BACKING_MICRONOID_PER_TOKEN);
    let r = bits(&reserve_micronoid);
    let s = bits(&outstanding_units);
    let width = 74;
    let rhs = checked_add(b, &extend(&s, width), &shifted(&r, 4, width));
    let rhs = checked_add(b, &rhs, &shifted(&r, 3, width));
    let invalid_backing = less_than(b, &shifted(&r, 10, width), &rhs);
    pin_zero(b, &invalid_backing);

    let definition_root = std::array::from_fn(|i| mul(b, &selector[3], &fields[4 + i]));
    nonzero_pair(b, &definition_root, &selector[3]);
    let definition_or_collection = selector[1].add(&selector[4]);
    let metadata = std::array::from_fn(|i| {
        let standard = mul(b, &definition_or_collection, &fields[5 + i]);
        let item = mul(b, &selector[5], &fields[4 + i]);
        standard.add(&item)
    });
    NativeOpeningTrace {
        commitment,
        fields: fields.clone(),
        live,
        identifier,
        owner,
        primary,
        secondary,
        reserve_micronoid,
        outstanding_units,
        initial_supply,
        definition_root,
        metadata,
    }
}

fn bind_slot_position(
    b: &mut FieldR1csBuilder,
    opening: &NativeOpeningTrace,
    slot: &LinExpr,
    root: &[LinExpr; 2],
    context: &NativeContextTrace,
) {
    range_check_bits(b, slot, 32);
    let inactive_slot = mul(b, &opening.commitment.selectors[0], slot);
    pin_zero(b, &inactive_slot);
    for (actual, expected) in root.iter().zip(&opening.commitment.root) {
        pin_eq(b, actual, expected);
    }
    let unregistered = mul(b, &opening.live, &context.live.add_const(F128::ONE));
    pin_zero(b, &unregistered);
}

/// Bind one compacted native input to the exact packed body/State value.
/// `packed` is the already constrained split shared with the raw action.
pub fn bind_native_input_slot(
    b: &mut FieldR1csBuilder,
    opening: &NativeOpeningTrace,
    slot: &LinExpr,
    packed: &PackedInputValueTrace,
    root: &[LinExpr; 2],
    context: &NativeContextTrace,
) {
    bind_slot_position(b, opening, slot, root, context);
    pin_eq(b, &packed.amount.value, &opening.reserve_micronoid.value);
    pin_zero(b, &LinExpr::from_wire(packed.creation_id.bits[63]));
    pin_eq(
        b,
        &LinExpr::from_wire(packed.creation_id.bits[62]),
        &opening.live,
    );
    let sequence: Vec<_> = packed.creation_id.bits[..62]
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect();
    require_nonzero(b, &pack(&sequence), &opening.live);
    let inactive_id = mul(
        b,
        &opening.commitment.selectors[0],
        &packed.creation_id.value,
    );
    pin_zero(b, &inactive_id);
    let selector = &opening.commitment.selectors;
    let owned = selector[2].add(&selector[4]).add(&selector[5]);
    for i in 0..2 {
        let different = mul(b, &owned, &opening.owner[i].add(&context.authority[i]));
        pin_zero(b, &different);
    }
    let timed = selector[2].add(&selector[5]);
    let too_early = less_than(b, &bits(&context.height), &bits(&opening.secondary));
    let invalid_time = mul(b, &timed, &too_early);
    pin_zero(b, &invalid_time);
}

/// Bind a compacted native output to its consensus-assigned allocator
/// sequence and exact post-State packed value, including the native tag.
pub fn bind_native_output_slot(
    b: &mut FieldR1csBuilder,
    opening: &NativeOpeningTrace,
    slot: &LinExpr,
    allocated_sequence: &U64Trace,
    packed_post: &LinExpr,
    root: &[LinExpr; 2],
    context: &NativeContextTrace,
) {
    bind_slot_position(b, opening, slot, root, context);
    for &bit in &allocated_sequence.bits[62..] {
        pin_zero(b, &LinExpr::from_wire(bit));
    }
    require_nonzero(b, &allocated_sequence.value, &opening.live);
    let inactive_id = mul(
        b,
        &opening.commitment.selectors[0],
        &allocated_sequence.value,
    );
    pin_zero(b, &inactive_id);
    let high = allocated_sequence.bits[..62]
        .iter()
        .enumerate()
        .fold(LinExpr::zero(), |sum, (i, &bit)| {
            sum.add(&LinExpr::from_wire(bit).scale(flat_const(1u128 << (64 + i))))
        });
    let tagged = high.add(&opening.live.scale(flat_const(1u128 << 126)));
    pin_eq(
        b,
        packed_post,
        &opening.reserve_micronoid.value.add(&tagged),
    );
}

/// Shared validation for a native action already packed by the block's
/// body-order allocator. Output ownership and future unlock heights are
/// commitments; input ownership and the current unlock boundary are enforced.
pub fn bind_native_action_slot(
    b: &mut FieldR1csBuilder,
    opening: &NativeOpeningTrace,
    slot: &LinExpr,
    packed: &PackedInputValueTrace,
    root: &[LinExpr; 2],
    is_output: &LinExpr,
    context: &NativeContextTrace,
) {
    bind_slot_position(b, opening, slot, root, context);
    let invalid_output = mul(b, is_output, &is_output.add_const(F128::ONE));
    pin_zero(b, &invalid_output);
    let inactive_output = mul(b, is_output, &opening.live.add_const(F128::ONE));
    pin_zero(b, &inactive_output);
    pin_eq(b, &packed.amount.value, &opening.reserve_micronoid.value);
    pin_zero(b, &LinExpr::from_wire(packed.creation_id.bits[63]));
    pin_eq(
        b,
        &LinExpr::from_wire(packed.creation_id.bits[62]),
        &opening.live,
    );
    let sequence: Vec<_> = packed.creation_id.bits[..62]
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect();
    require_nonzero(b, &pack(&sequence), &opening.live);
    let inactive_id = mul(
        b,
        &opening.commitment.selectors[0],
        &packed.creation_id.value,
    );
    pin_zero(b, &inactive_id);
    let owned = opening.commitment.selectors[2]
        .add(&opening.commitment.selectors[4])
        .add(&opening.commitment.selectors[5]);
    let owned_input = mul(b, &owned, &is_output.add_const(F128::ONE));
    for lane in 0..2 {
        let mismatch = mul(
            b,
            &owned_input,
            &opening.owner[lane].add(&context.authority[lane]),
        );
        pin_zero(b, &mismatch);
    }
    let timed = opening.commitment.selectors[2].add(&opening.commitment.selectors[5]);
    let timed_input = mul(b, &timed, &is_output.add_const(F128::ONE));
    let too_early = less_than(b, &bits(&context.height), &bits(&opening.secondary));
    let invalid_time = mul(b, &timed_input, &too_early);
    pin_zero(b, &invalid_time);
}
