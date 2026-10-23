// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete native-operation groups over the shared authenticated action set.

use noid_core::{hardware::flat_to_tower_u128, Block128};

use super::super::permutation_network::route_permutation_network;
use super::super::public_arithmetic::split_packed_input_value;
use super::super::{
    alloc_block, flat_const, mul, pin_eq, pin_zero, range_check_bits, FieldR1csBuilder, LinExpr,
    F128,
};
use super::actions::NativeActionTrace;
use super::arithmetic::{checked_add, less_than, pack};
use super::fungible::{bind_fungible_inventory_transition, FungibleInventoryTrace};
use super::genesis::{bind_native_genesis_identity, NativeGenesisFundingTrace};
use super::header::NativeHeaderTrace;
use super::validation::{bind_native_context, bits, is_zero, require_nonzero};

const SUMMARY_WIDTH: usize = 64;
const FIELDS: usize = 22;
const DEFINITION: usize = 0;
const RESERVE_IN: usize = 1;
const RESERVE_OUT: usize = 2;
const COLLECTION_IN: usize = 3;
const COLLECTION_OUT: usize = 4;

fn tower(b: &FieldR1csBuilder, value: &LinExpr) -> u128 {
    let flat = value.eval(b.values());
    flat_to_tower_u128(u128::from(flat.lo) | (u128::from(flat.hi) << 64))
}

fn gated(b: &mut FieldR1csBuilder, flag: &LinExpr, values: &[LinExpr]) -> Vec<LinExpr> {
    values.iter().map(|value| mul(b, flag, value)).collect()
}

fn reset(b: &mut FieldR1csBuilder, start: &LinExpr, values: &[LinExpr]) -> Vec<LinExpr> {
    gated(b, &start.add_const(F128::ONE), values)
}

fn add_selected(
    b: &mut FieldR1csBuilder,
    previous: &[LinExpr],
    when: &LinExpr,
    current: &[LinExpr],
) -> Vec<LinExpr> {
    let selected = gated(b, when, current);
    checked_add(b, previous, &selected)
}

fn increment(b: &mut FieldR1csBuilder, value: &[LinExpr], when: &LinExpr) -> Vec<LinExpr> {
    let mut delta = vec![LinExpr::zero(); value.len()];
    delta[0] = when.clone();
    checked_add(b, value, &delta)
}

fn op_selectors(b: &mut FieldR1csBuilder, value: &LinExpr) -> [LinExpr; 9] {
    let bits = range_check_bits(b, value, 4);
    let mut result = vec![LinExpr::constant(F128::ONE)];
    for bit in bits {
        let bit = LinExpr::from_wire(bit);
        let size = result.len();
        let mut next = vec![LinExpr::zero(); 2 * size];
        for (i, value) in result.iter().enumerate() {
            let one = mul(b, value, &bit);
            next[i] = value.add(&one);
            next[i + size] = one;
        }
        result = next;
    }
    for invalid in &result[9..] {
        pin_zero(b, invalid);
    }
    std::array::from_fn(|i| result[i].clone())
}

fn route(
    b: &mut FieldR1csBuilder,
    mut rows: Vec<Vec<LinExpr>>,
    width: usize,
    key: impl Fn(&FieldR1csBuilder, &[LinExpr]) -> Vec<u128>,
) -> Vec<Vec<LinExpr>> {
    let size = rows.len().max(1).next_power_of_two();
    rows.resize_with(size, || vec![LinExpr::zero(); width]);
    let mut order: Vec<_> = (0..size).collect();
    order.sort_by_key(|&i| (tower(b, &rows[i][0]) == 0, key(b, &rows[i]), i));
    let mut permutation = vec![0; size];
    for (target, source) in order.into_iter().enumerate() {
        permutation[source] = target;
    }
    route_permutation_network(b, rows, &permutation)
}

fn complete_group_summaries(
    b: &mut FieldR1csBuilder,
    actions: &[NativeActionTrace],
    limit: usize,
) -> Vec<Vec<LinExpr>> {
    let mut previous_header = LinExpr::zero();
    let mut previous_operation = LinExpr::zero();
    let mut previous_authority = [LinExpr::zero(), LinExpr::zero()];
    let mut seen: [LinExpr; 6] = std::array::from_fn(|_| LinExpr::zero());
    let mut fields: [[LinExpr; 8]; 5] =
        std::array::from_fn(|_| std::array::from_fn(|_| LinExpr::zero()));
    let mut funding: [LinExpr; 4] = std::array::from_fn(|_| LinExpr::zero());
    let mut definition_root = [LinExpr::zero(), LinExpr::zero()];
    let mut identifier = [LinExpr::zero(), LinExpr::zero()];
    let mut any_native = LinExpr::zero();
    let mut units = [vec![LinExpr::zero(); 64], vec![LinExpr::zero(); 64]];
    let mut items = [vec![LinExpr::zero(); 11], vec![LinExpr::zero(); 11]];
    let mut issued = vec![LinExpr::zero(); 64];
    let mut ends = Vec::with_capacity(actions.len());
    for (index, action) in actions.iter().enumerate() {
        let same_header = is_zero(b, &action.header_page.add(&previous_header));
        let continuation = mul(b, &action.live, &same_header);
        let start = action.live.add(&continuation);
        for (current, previous) in std::iter::once((&action.operation, &previous_operation))
            .chain(action.authority.iter().zip(&previous_authority))
        {
            let changed = mul(b, &continuation, &current.add(previous));
            pin_zero(b, &changed);
        }
        let op = op_selectors(b, &action.operation);
        let kind = &action.opening.commitment.selectors;
        let output = &action.is_output;
        let input = output.add_const(F128::ONE);
        let genesis_output = mul(b, &op[1], output);
        let collection_genesis_output = mul(b, &op[5], output);
        let mint_output = mul(b, &op[6], output);
        let burn_input = mul(b, &op[8], &input);
        let mut allowed = mul(b, &kind[1], &genesis_output);
        allowed = allowed.add(&mul(b, &kind[2], &genesis_output.add(&op[2]).add(&op[3])));
        allowed = allowed.add(&mul(b, &kind[3], &genesis_output.add(&op[3]).add(&op[4])));
        allowed = allowed.add(&mul(b, &kind[4], &collection_genesis_output.add(&op[6])));
        allowed = allowed.add(&mul(b, &kind[5], &mint_output.add(&op[7]).add(&burn_input)));
        pin_eq(b, &action.native, &allowed);
        let genesis = op[1].add(&op[5]);
        let foreign_funding = mul(b, &action.funding, &genesis.add_const(F128::ONE));
        pin_zero(b, &foreign_funding);

        any_native = mul(b, &start.add_const(F128::ONE), &any_native);
        identifier =
            std::array::from_fn(|lane| mul(b, &start.add_const(F128::ONE), &identifier[lane]));
        let first_native = mul(b, &action.native, &any_native.add_const(F128::ONE));
        for lane in 0..2 {
            identifier[lane] = identifier[lane].add(&mul(
                b,
                &first_native,
                &action.opening.identifier[lane].add(&identifier[lane]),
            ));
        }
        let overlap = mul(b, &any_native, &action.native);
        any_native = any_native.add(&action.native).add(&overlap);
        let one_asset_op = op[1]
            .add(&op[2])
            .add(&op[3])
            .add(&op[4])
            .add(&op[5])
            .add(&op[6]);
        let one_asset = mul(b, &action.native, &one_asset_op);
        for lane in 0..2 {
            let mismatch = mul(
                b,
                &one_asset,
                &action.opening.identifier[lane].add(&identifier[lane]),
            );
            pin_zero(b, &mismatch);
        }

        let selectors = [
            action.funding.clone(),
            mul(b, &kind[1], output),
            mul(b, &kind[3], &input),
            mul(b, &kind[3], output),
            mul(b, &kind[4], &input),
            mul(b, &kind[4], output),
        ];
        for i in 0..6 {
            seen[i] = mul(b, &start.add_const(F128::ONE), &seen[i]);
            let repeated = mul(b, &seen[i], &selectors[i]);
            pin_zero(b, &repeated);
            seen[i] = seen[i].add(&selectors[i]);
        }
        for (target, value) in funding.iter_mut().zip([
            &action.slot,
            &action.packed_value,
            &action.root[0],
            &action.root[1],
        ]) {
            *target =
                mul(b, &start.add_const(F128::ONE), target).add(&mul(b, &action.funding, value));
        }
        for lane in 0..2 {
            definition_root[lane] = mul(b, &start.add_const(F128::ONE), &definition_root[lane])
                .add(&mul(
                    b,
                    &selectors[1],
                    &action.opening.commitment.root[lane],
                ));
        }
        for i in 0..5 {
            for lane in 0..8 {
                fields[i][lane] = mul(b, &start.add_const(F128::ONE), &fields[i][lane]).add(&mul(
                    b,
                    &selectors[1 + i],
                    &action.opening.fields[lane],
                ));
            }
        }
        let balance_in = mul(b, &kind[2], &input);
        let balance_out = mul(b, &kind[2], output);
        let item_in = mul(b, &kind[5], &input);
        let item_out = mul(b, &kind[5], output);
        let primary = bits(&action.opening.primary);
        for (side, flag) in [balance_in, balance_out].iter().enumerate() {
            units[side] = reset(b, &start, &units[side]);
            units[side] = add_selected(b, &units[side], flag, &primary);
        }
        for (side, flag) in [item_in, item_out.clone()].iter().enumerate() {
            items[side] = reset(b, &start, &items[side]);
            items[side] = increment(b, &items[side], flag);
        }
        issued = reset(b, &start, &issued);
        issued = add_selected(b, &issued, &selectors[4], &bits(&action.opening.secondary));
        let minted_item = mul(b, &item_out, &op[6]);
        issued = increment(b, &issued, &minted_item);
        let wrong_serial = mul(
            b,
            &minted_item,
            &action.opening.primary.value.add(&pack(&issued)),
        );
        pin_zero(b, &wrong_serial);
        let next_header = actions
            .get(index + 1)
            .map(|a| a.header_page.clone())
            .unwrap_or_else(LinExpr::zero);
        let same_next = is_zero(b, &action.header_page.add(&next_header));
        let end = mul(b, &action.live, &same_next.add_const(F128::ONE));
        let mut row = vec![
            end.clone(),
            action.header_page.clone(),
            action.operation.clone(),
            action.authority[0].clone(),
            action.authority[1].clone(),
            identifier[0].clone(),
            identifier[1].clone(),
            seen[0].clone(),
            funding[0].clone(),
            funding[1].clone(),
            funding[2].clone(),
            funding[3].clone(),
            seen[1].clone(),
            seen[2].clone(),
            seen[3].clone(),
            seen[4].clone(),
            seen[5].clone(),
            pack(&units[0]),
            pack(&units[1]),
            pack(&items[0]),
            pack(&items[1]),
            pack(&issued),
        ];
        row.extend(fields.iter().flat_map(|f| f.iter().cloned()));
        row.extend(definition_root.iter().cloned());
        assert_eq!(row.len(), SUMMARY_WIDTH);
        for value in &mut row[1..] {
            *value = mul(b, &end, value);
        }
        ends.push(row);
        previous_header = action.header_page.clone();
        previous_operation = action.operation.clone();
        previous_authority = action.authority.clone();
    }
    ends.resize_with(actions.len().max(limit), || {
        vec![LinExpr::zero(); SUMMARY_WIDTH]
    });
    let rows = route(b, ends, SUMMARY_WIDTH, |b, row| vec![tower(b, &row[1])]);
    for row in &rows[limit..] {
        pin_zero(b, &row[0]);
    }
    rows.into_iter().take(limit).collect()
}

fn u64_bits(b: &mut FieldR1csBuilder, value: &LinExpr) -> Vec<LinExpr> {
    range_check_bits(b, value, 64)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect()
}

fn inventory(
    b: &mut FieldR1csBuilder,
    live: &LinExpr,
    units: &LinExpr,
    fields: &[LinExpr; 8],
) -> FungibleInventoryTrace {
    let selected_units = mul(b, live, units);
    let packed = mul(b, live, &fields[2]);
    let reserve = split_packed_input_value(b, &packed);
    FungibleInventoryTrace {
        units: u64_bits(b, &selected_units),
        reserve: bits(&reserve.amount),
        supply: bits(&reserve.creation_id),
        initial: mul(b, live, &fields[3]),
        definition_root: std::array::from_fn(|i| mul(b, live, &fields[4 + i])),
    }
}

/// Bind every header to exactly one complete operation summary. All native
/// records, ordinary genesis anchors and per-asset totals come from the same
/// sorted body action set used by the exact State transition.
pub fn bind_native_kernel(
    b: &mut FieldR1csBuilder,
    headers: &[NativeHeaderTrace],
    actions: &[NativeActionTrace],
    height: &LinExpr,
) {
    let summaries = complete_group_summaries(b, actions, headers.len());
    for (header, row) in headers.iter().zip(summaries) {
        pin_eq(b, &header.live, &row[0]);
        pin_eq(b, &header.header_page, &row[1]);
        pin_eq(b, &header.operation, &row[2]);
        for lane in 0..2 {
            pin_eq(b, &header.authority[lane], &row[3 + lane]);
        }
        let op = &header.selectors;
        let required = [
            op[1].add(&op[5]),
            op[1].clone(),
            op[3].add(&op[4]),
            op[1].add(&op[3]).add(&op[4]),
            op[6].clone(),
            op[5].add(&op[6]),
        ];
        for (count, want) in [&row[7], &row[12], &row[13], &row[14], &row[15], &row[16]]
            .into_iter()
            .zip(&required)
        {
            pin_eq(b, count, want);
        }
        let fields: [[LinExpr; 8]; 5] =
            std::array::from_fn(|i| std::array::from_fn(|j| row[FIELDS + 8 * i + j].clone()));
        let definition = &fields[DEFINITION];
        let reserve_in = &fields[RESERVE_IN];
        let reserve_out = &fields[RESERVE_OUT];
        let collection_in = &fields[COLLECTION_IN];
        let collection_out = &fields[COLLECTION_OUT];
        let genesis = op[1].add(&op[5]);
        let authority = std::array::from_fn(|i| mul(b, &genesis, &header.authority[i]));
        let context = bind_native_context(b, &genesis, &authority, height);
        let chain = std::array::from_fn(|i| mul(b, &genesis, &header.chain[i]));
        let combined: [LinExpr; 8] = std::array::from_fn(|i| {
            let token = mul(b, &op[1], &definition[i]);
            let collection = mul(b, &op[5], &collection_out[i]);
            token.add(&collection)
        });
        let funding = NativeGenesisFundingTrace {
            slot: row[8].clone(),
            packed_value: row[9].clone(),
            root: [row[10].clone(), row[11].clone()],
        };
        let id =
            bind_native_genesis_identity(b, &op[1], &op[5], &chain, &context, &funding, &combined);
        for lane in 0..2 {
            pin_eq(b, &id[lane], &combined[lane]);
        }
        let initial = split_packed_input_value(b, &combined[4]);
        let issued_units = mul(b, &op[1], &row[18]);
        let token_initial = mul(b, &op[1], &initial.amount.value);
        pin_eq(b, &issued_units, &token_initial);
        let genesis_reserve = mul(b, &op[1], &reserve_out[2]);
        let genesis_reserve = split_packed_input_value(b, &genesis_reserve);
        pin_eq(b, &genesis_reserve.creation_id.value, &token_initial);
        let reserve_initial = mul(b, &op[1], &reserve_out[3]);
        pin_eq(b, &reserve_initial, &token_initial);
        for lane in 0..2 {
            let root = mul(b, &op[1], &reserve_out[4 + lane]);
            pin_eq(b, &root, &row[62 + lane]);
        }
        let ft = op[2].add(&op[3]).add(&op[4]);
        for lane in 0..2 {
            let mismatch = mul(b, &ft, &row[5 + lane].add(&header.asset[lane]));
            pin_zero(b, &mismatch);
        }
        let before = inventory(b, &ft, &row[17], reserve_in);
        let after = inventory(b, &ft, &row[18], reserve_out);
        let old_r = tower(b, &pack(&before.reserve));
        let old_s = tower(b, &pack(&before.supply));
        let burned = tower(b, &pack(&before.units)).saturating_sub(tower(b, &pack(&after.units)));
        let remainder = if tower(b, &op[3]) != 0 && old_s != 0 {
            (old_r * burned) % old_s
        } else {
            0
        };
        let remainder = alloc_block(b, Block128(remainder));
        let operation = op[2]
            .scale(flat_const(2))
            .add(&op[3].scale(flat_const(3)))
            .add(&op[4].scale(flat_const(4)));
        let _fungible = bind_fungible_inventory_transition(
            b,
            &operation,
            &header.asset,
            before,
            after,
            &remainder,
        );
        let mint = &op[6];
        for lane in [0, 1, 2, 3, 5, 6, 7] {
            let mismatch = mul(b, mint, &collection_in[lane].add(&collection_out[lane]));
            pin_zero(b, &mismatch);
        }
        let old = split_packed_input_value(b, &collection_in[4]);
        let next = split_packed_input_value(b, &collection_out[4]);
        let cap = mul(b, mint, &old.amount.value.add(&next.amount.value));
        pin_zero(b, &cap);
        let issued = mul(b, mint, &next.creation_id.value.add(&row[21]));
        pin_zero(b, &issued);
        require_nonzero(b, &row[20], mint);
        require_nonzero(b, &row[19], &op[7].add(&op[8]));
    }
    bind_nft_inventory(b, actions);
}

fn bind_nft_inventory(b: &mut FieldR1csBuilder, actions: &[NativeActionTrace]) {
    let mut rows = Vec::with_capacity(actions.len());
    for action in actions {
        let op = op_selectors(b, &action.operation);
        let live = mul(
            b,
            &op[7].add(&op[8]),
            &action.opening.commitment.selectors[5],
        );
        let mut row = vec![
            live.clone(),
            action.header_page.clone(),
            action.is_output.clone(),
            op[7].clone(),
            action.opening.identifier[0].clone(),
            action.opening.identifier[1].clone(),
            action.opening.primary.value.clone(),
            action.opening.metadata[0].clone(),
            action.opening.metadata[1].clone(),
        ];
        for value in &mut row[1..] {
            *value = mul(b, &live, value);
        }
        rows.push(row);
    }
    let rows = route(b, rows, 9, |b, row| {
        vec![
            tower(b, &row[1]),
            tower(b, &row[4]),
            tower(b, &row[5]),
            tower(b, &row[6]),
            tower(b, &row[2]),
        ]
    });
    let mut previous: Option<(LinExpr, Vec<LinExpr>)> = None;
    for (index, row) in rows.iter().enumerate() {
        let mut key = vec![row[2].clone()];
        key.extend(
            range_check_bits(b, &row[6], 64)
                .into_iter()
                .map(LinExpr::from_wire),
        );
        for lane in [5, 4] {
            key.extend(
                range_check_bits(b, &row[lane], 128)
                    .into_iter()
                    .map(LinExpr::from_wire),
            );
        }
        key.extend(
            range_check_bits(b, &row[1], 16)
                .into_iter()
                .map(LinExpr::from_wire),
        );
        if let Some((live, old)) = previous {
            let hole = mul(b, &row[0], &live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let strict = less_than(b, &old, &key);
            let invalid = mul(b, &row[0], &strict.add_const(F128::ONE));
            pin_zero(b, &invalid);
        }
        previous = Some((row[0].clone(), key));
        let transfer_input = mul(b, &row[3], &row[2].add_const(F128::ONE));
        let transfer_output = mul(b, &row[3], &row[2]);
        for (when, neighbor, want_output) in [
            (&transfer_input, rows.get(index + 1), true),
            (
                &transfer_output,
                index.checked_sub(1).and_then(|i| rows.get(i)),
                false,
            ),
        ] {
            let zero = vec![LinExpr::zero(); 9];
            let other = neighbor.unwrap_or(&zero);
            for lane in [0, 1, 3, 4, 5, 6, 7, 8] {
                let mismatch = mul(b, when, &row[lane].add(&other[lane]));
                pin_zero(b, &mismatch);
            }
            let wanted = if want_output {
                LinExpr::constant(F128::ONE)
            } else {
                LinExpr::zero()
            };
            let wrong_role = mul(b, when, &other[2].add(&wanted));
            pin_zero(b, &wrong_role);
        }
    }
}
