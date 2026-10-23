// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native collection issuance and exact NFT inventory transitions.

use noid_core::hardware::flat_to_tower_u128;

use super::super::permutation_network::route_permutation_network;
use super::super::{mul, pin_eq, pin_zero, range_check_bits, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::{checked_add, less_than, pack};
use super::validation::{bits, NativeOpeningTrace};

pub struct NftTransitionTrace {
    pub live: LinExpr,
    pub mint_live: LinExpr,
    pub transfer_live: LinExpr,
    pub burn_live: LinExpr,
}

fn selectors(b: &mut FieldR1csBuilder, operation: &LinExpr) -> [LinExpr; 16] {
    let op = range_check_bits(b, operation, 4);
    let mut tensor = vec![LinExpr::constant(F128::ONE)];
    for bit in op {
        let bit = LinExpr::from_wire(bit);
        let len = tensor.len();
        let mut next = vec![LinExpr::zero(); 2 * len];
        for (i, value) in tensor.iter().enumerate() {
            let one = mul(b, value, &bit);
            next[i] = value.add(&one);
            next[i + len] = one;
        }
        tensor = next;
    }
    for (i, selector) in tensor.iter().enumerate() {
        if ![0, 6, 7, 8].contains(&i) {
            pin_zero(b, selector);
        }
    }
    tensor.try_into().unwrap()
}

struct Collection {
    fields: [LinExpr; 8],
    issued: Vec<LinExpr>,
    any_item: LinExpr,
}

fn collection(
    b: &mut FieldR1csBuilder,
    openings: &[NativeOpeningTrace],
    required: &LinExpr,
    items_allowed: &LinExpr,
) -> Collection {
    let mut seen = LinExpr::zero();
    let mut fields: [LinExpr; 8] = std::array::from_fn(|_| LinExpr::zero());
    let mut issued = vec![LinExpr::zero(); 64];
    let mut any_item = LinExpr::zero();
    for opening in openings {
        let c = &opening.commitment.selectors[4];
        let item = &opening.commitment.selectors[5];
        let allowed_collection = mul(b, c, required);
        let allowed_item = mul(b, item, items_allowed);
        pin_zero(b, &opening.live.add(&allowed_collection).add(&allowed_item));
        let repeated = mul(b, &seen, c);
        pin_zero(b, &repeated);
        seen = seen.add(c);
        let overlap = mul(b, &any_item, item);
        any_item = any_item.add(item).add(&overlap);
        for (field, value) in fields.iter_mut().zip(&opening.fields) {
            *field = field.add(&mul(b, c, value));
        }
        for (bit, value) in issued.iter_mut().zip(bits(&opening.secondary)) {
            *bit = bit.add(&mul(b, c, &value));
        }
    }
    pin_eq(b, &seen, required);
    Collection {
        fields,
        issued,
        any_item,
    }
}

fn tower(b: &FieldR1csBuilder, value: &LinExpr) -> u128 {
    let flat = value.eval(b.values());
    flat_to_tower_u128(u128::from(flat.lo) | (u128::from(flat.hi) << 64))
}

fn sorted_inventory(
    b: &mut FieldR1csBuilder,
    openings: &[NativeOpeningTrace],
    selected: &LinExpr,
    capacity: usize,
) -> Vec<Vec<LinExpr>> {
    let mut rows: Vec<_> = openings
        .iter()
        .map(|opening| {
            let live = mul(b, selected, &opening.commitment.selectors[5]);
            let mut row = vec![live.clone()];
            for value in [
                &opening.identifier[0],
                &opening.identifier[1],
                &opening.primary.value,
                &opening.metadata[0],
                &opening.metadata[1],
            ] {
                row.push(mul(b, &live, value));
            }
            row
        })
        .collect();
    rows.resize_with(capacity, || vec![LinExpr::zero(); 6]);
    let mut order: Vec<_> = (0..capacity).collect();
    order.sort_by_key(|&i| {
        (
            tower(b, &rows[i][0]) == 0,
            tower(b, &rows[i][1]),
            tower(b, &rows[i][2]),
            tower(b, &rows[i][3]),
            i,
        )
    });
    let mut permutation = vec![0; capacity];
    for (target, source) in order.into_iter().enumerate() {
        permutation[source] = target;
    }
    route_permutation_network(b, rows, &permutation)
}

/// Codes six/seven/eight are mint/transfer/burn; zero is padding.
/// The enclosing block supplies complete native inventories in body order
/// and binds their exact State incarnations and input authorities.
pub fn bind_nft_transition(
    b: &mut FieldR1csBuilder,
    operation: &LinExpr,
    inputs: &[NativeOpeningTrace],
    outputs: &[NativeOpeningTrace],
) -> NftTransitionTrace {
    let op = selectors(b, operation);
    let mint = &op[6];
    let transfer = &op[7];
    let burn = &op[8];
    let transfer_or_burn = transfer.add(burn);
    let before = collection(b, inputs, mint, &transfer_or_burn);
    let after = collection(b, outputs, mint, &mint.add(transfer));
    let no_minted_items = mul(b, mint, &after.any_item.add_const(F128::ONE));
    pin_zero(b, &no_minted_items);
    let no_input_items = mul(b, &transfer_or_burn, &before.any_item.add_const(F128::ONE));
    pin_zero(b, &no_input_items);
    for i in [0, 1, 2, 3, 5, 6, 7] {
        pin_eq(b, &before.fields[i], &after.fields[i]);
    }
    // The low collection half is the immutable cap. Only the issued counter
    // advances, once per item in exact physical native-output order.
    let old_limits =
        super::super::public_arithmetic::split_packed_input_value(b, &before.fields[4]);
    let new_limits = super::super::public_arithmetic::split_packed_input_value(b, &after.fields[4]);
    pin_eq(b, &old_limits.amount.value, &new_limits.amount.value);
    let mut issued = before.issued;
    for output in outputs {
        let item = &output.commitment.selectors[5];
        let minted = mul(b, mint, item);
        let mut increment = vec![LinExpr::zero(); 64];
        increment[0] = minted.clone();
        issued = checked_add(b, &issued, &increment);
        let wrong_serial = mul(b, &minted, &output.primary.value.add(&pack(&issued)));
        pin_zero(b, &wrong_serial);
        for i in 0..2 {
            let wrong_collection = mul(b, &minted, &output.identifier[i].add(&before.fields[i]));
            pin_zero(b, &wrong_collection);
        }
    }
    pin_eq(b, &pack(&issued), &pack(&after.issued));

    // Sorted deterministic permutation checks compare collection, serial and
    // artwork exactly. Strict keys reject repeated NFTs, including on burn.
    let capacity = inputs.len().max(outputs.len()).max(1).next_power_of_two();
    let old_inventory = sorted_inventory(b, inputs, &transfer_or_burn, capacity);
    let new_inventory = sorted_inventory(b, outputs, transfer, capacity);
    let mut previous: Option<(LinExpr, Vec<LinExpr>)> = None;
    for (old, next) in old_inventory.iter().zip(&new_inventory) {
        for (a, c) in old.iter().zip(next) {
            let changed = mul(b, transfer, &a.add(c));
            pin_zero(b, &changed);
        }
        let mut key: Vec<_> = range_check_bits(b, &old[3], 64)
            .into_iter()
            .map(LinExpr::from_wire)
            .collect();
        for lane in [2, 1] {
            key.extend(
                range_check_bits(b, &old[lane], 128)
                    .into_iter()
                    .map(LinExpr::from_wire),
            );
        }
        if let Some((live, before_key)) = previous {
            let hole = mul(b, &old[0], &live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let strict = less_than(b, &before_key, &key);
            let duplicate_or_unordered = mul(b, &old[0], &strict.add_const(F128::ONE));
            pin_zero(b, &duplicate_or_unordered);
        }
        previous = Some((old[0].clone(), key));
    }
    NftTransitionTrace {
        live: op[0].add_const(F128::ONE),
        mint_live: mint.clone(),
        transfer_live: transfer.clone(),
        burn_live: burn.clone(),
    }
}
