// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-supply asset and collection genesis from exact ordinary funding.

use noid_poseidon2b::native::{capacity_iv, DomainTag};

use super::super::public_arithmetic::split_packed_input_value;
use super::super::{
    const_block, flat_const, mul, pin_eq, pin_zero, poseidon2b_permute, range_check_bits,
    FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::{checked_add, pack};
use super::validation::{
    bits, nonzero_pair, require_nonzero, NativeContextTrace, NativeOpeningTrace,
};

pub struct NativeGenesisFundingTrace {
    pub slot: LinExpr,
    pub packed_value: LinExpr,
    pub root: [LinExpr; 2],
}

pub struct NativeGenesisTrace {
    pub live: LinExpr,
    pub identifier: [LinExpr; 2],
    pub reserve_contribution_micronoid: LinExpr,
}

fn unique_fields(
    b: &mut FieldR1csBuilder,
    outputs: &[NativeOpeningTrace],
    kind: usize,
    required: &LinExpr,
) -> [LinExpr; 8] {
    let mut seen = LinExpr::zero();
    let mut result: [LinExpr; 8] = std::array::from_fn(|_| LinExpr::zero());
    for output in outputs {
        let selected = &output.commitment.selectors[kind];
        let repeated = mul(b, &seen, selected);
        pin_zero(b, &repeated);
        seen = seen.add(selected);
        for (total, field) in result.iter_mut().zip(&output.fields) {
            *total = total.add(&mul(b, selected, field));
        }
    }
    pin_eq(b, &seen, required);
    result
}

/// Header operation one creates a standalone token; five creates a collection.
/// Zero is padding. The enclosing block routes the exact selected funding
/// input, proves its ordinary provenance and membership, and binds the complete
/// native output set and the common NOID conservation equation.
pub fn bind_native_genesis(
    b: &mut FieldR1csBuilder,
    operation: &LinExpr,
    chain: &[LinExpr; 2],
    context: &NativeContextTrace,
    funding: &NativeGenesisFundingTrace,
    native_inputs: &[NativeOpeningTrace],
    outputs: &[NativeOpeningTrace],
) -> NativeGenesisTrace {
    let op = range_check_bits(b, operation, 3);
    pin_zero(b, &LinExpr::from_wire(op[1]));
    let live = LinExpr::from_wire(op[0]);
    let collection = LinExpr::from_wire(op[2]);
    let invalid_collection = mul(b, &collection, &live.add_const(F128::ONE));
    pin_zero(b, &invalid_collection);
    let token = live.add(&collection);
    pin_eq(b, &context.live, &live);
    nonzero_pair(b, chain, &live);
    for input in native_inputs {
        pin_zero(b, &input.live);
    }
    for output in outputs {
        let selector = &output.commitment.selectors;
        let allowed_token = mul(b, &token, &selector[1].add(&selector[2]).add(&selector[3]));
        let allowed_collection = mul(b, &collection, &selector[4]);
        pin_zero(b, &output.live.add(&allowed_token).add(&allowed_collection));
    }
    let definition = unique_fields(b, outputs, 1, &token);
    let reserve = unique_fields(b, outputs, 3, &token);
    let nft_collection = unique_fields(b, outputs, 4, &collection);
    let combined: [LinExpr; 8] = std::array::from_fn(|i| definition[i].add(&nft_collection[i]));
    let identifier =
        bind_native_genesis_identity(b, &token, &collection, chain, context, funding, &combined);
    for i in 0..2 {
        pin_eq(b, &combined[i], &identifier[i]);
    }
    let mut units = vec![LinExpr::zero(); 64];
    let mut reserve_amount = LinExpr::zero();
    let mut definition_root = [LinExpr::zero(), LinExpr::zero()];
    for output in outputs {
        for i in 0..2 {
            let different = mul(b, &output.live, &output.identifier[i].add(&identifier[i]));
            pin_zero(b, &different);
            let selected_definition = mul(
                b,
                &output.commitment.selectors[1],
                &output.commitment.root[i],
            );
            definition_root[i] = definition_root[i].add(&selected_definition);
        }
        let selected_units: Vec<_> = bits(&output.primary)
            .iter()
            .map(|bit| mul(b, &output.commitment.selectors[2], bit))
            .collect();
        units = checked_add(b, &units, &selected_units);
        reserve_amount = reserve_amount.add(&output.reserve_micronoid.value);
    }
    let initial = split_packed_input_value(b, &definition[4]);
    pin_eq(b, &pack(&units), &initial.amount.value);
    let reserve_quantities = split_packed_input_value(b, &reserve[2]);
    pin_eq(
        b,
        &reserve_quantities.creation_id.value,
        &initial.amount.value,
    );
    pin_eq(b, &reserve[3], &initial.amount.value);
    for i in 0..2 {
        pin_eq(b, &reserve[4 + i], &definition_root[i]);
    }
    NativeGenesisTrace {
        live,
        identifier,
        reserve_contribution_micronoid: reserve_amount,
    }
}

/// Genesis identity and exact ordinary anchor shared by complete inventories.
pub(super) fn bind_native_genesis_identity(
    b: &mut FieldR1csBuilder,
    token: &LinExpr,
    collection: &LinExpr,
    chain: &[LinExpr; 2],
    context: &NativeContextTrace,
    funding: &NativeGenesisFundingTrace,
    combined: &[LinExpr; 8],
) -> [LinExpr; 2] {
    let live = token.add(collection);
    for i in 0..2 {
        let invalid_owner = mul(b, &live, &combined[2 + i].add(&context.authority[i]));
        pin_zero(b, &invalid_owner);
    }
    // These words are supply/route and cap/issued respectively. Pinning the
    // high half to zero fixes standalone issuance and an empty collection.
    let quantity = split_packed_input_value(b, &combined[4]);
    pin_zero(b, &quantity.creation_id.value);

    let funding_value = split_packed_input_value(b, &funding.packed_value);
    require_nonzero(b, &funding_value.amount.value, &live);
    require_nonzero(b, &funding_value.creation_id.value, &live);
    let native_funding = mul(
        b,
        &LinExpr::from_wire(funding_value.creation_id.bits[62]),
        &LinExpr::from_wire(funding_value.creation_id.bits[63]).add_const(F128::ONE),
    );
    let invalid_funding = mul(b, &live, &native_funding);
    pin_zero(b, &invalid_funding);
    let inactive = live.add_const(F128::ONE);
    let dead_funding = mul(b, &inactive, &funding.packed_value);
    pin_zero(b, &dead_funding);
    let slot_bits: Vec<_> = range_check_bits(b, &funding.slot, 32)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect();
    let dead_slot = mul(b, &inactive, &funding.slot);
    pin_zero(b, &dead_slot);
    for i in 0..2 {
        let mismatch = mul(b, &live, &funding.root[i].add(&context.authority[i]));
        pin_zero(b, &mismatch);
        let dead_root = mul(b, &inactive, &funding.root[i]);
        pin_zero(b, &dead_root);
    }
    let kind_and_slot = pack(&slot_bits)
        .add(&token.scale(flat_const(1u128 << 32)))
        .add(&collection.scale(flat_const(4u128 << 32)));
    let iv = capacity_iv(DomainTag::new(b"NATID_21"));
    let mut state = [
        LinExpr::zero(),
        LinExpr::zero(),
        const_block(iv[0]),
        const_block(iv[1]),
    ];
    for pair in [
        chain.clone(),
        context.authority.clone(),
        [funding.packed_value.clone(), kind_and_slot],
        [combined[2].clone(), combined[3].clone()],
        [combined[4].clone(), combined[5].clone()],
        [combined[6].clone(), LinExpr::zero()],
    ] {
        state[0] = state[0].add(&pair[0]);
        state[1] = state[1].add(&pair[1]);
        state = poseidon2b_permute(b, state);
    }
    let identifier: [LinExpr; 2] = std::array::from_fn(|i| mul(b, &live, &state[i]));
    identifier
}
