// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete native action extraction and exact header bitmap binding.

use std::collections::BTreeMap;

use noid_core::{hardware::flat_to_tower_u128, Block128};
use noid_poseidon2b::primitives::Address;
use noid_tx::native_assets::NativeOpening;

use super::super::action_surface::{ActionRowTrace, ActionSurfaceTrace};
use super::super::paged_spend::NativePageContextTrace;
use super::super::permutation_network::route_permutation_network;
use super::super::public_arithmetic::{split_packed_input_value, UserPublicArithmeticTrace};
use super::super::{
    alloc_block, flat_const, integer_add_no_overflow, mul, pin_eq, pin_zero, range_check_bits,
    FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::{less_than, pack};
use super::header::{FinancialNativeHeaderTrace, NativeHeaderTrace};
use super::validation::{
    bind_native_action_slot, bind_native_context, bind_native_opening, is_zero, require_nonzero,
    NativeOpeningTrace,
};

pub struct NativeActionSelectors {
    /// One entry for every raw user action in physical body order.
    pub native: Vec<LinExpr>,
    pub funding: Vec<LinExpr>,
    pub ordinal: Vec<LinExpr>,
}

pub struct NativeActionTrace {
    pub live: LinExpr,
    pub native: LinExpr,
    pub funding: LinExpr,
    pub header_page: LinExpr,
    pub ordinal: LinExpr,
    pub is_output: LinExpr,
    pub slot: LinExpr,
    pub packed_value: LinExpr,
    pub root: [LinExpr; 2],
    pub authority: [LinExpr; 2],
    pub operation: LinExpr,
    pub opening: NativeOpeningTrace,
}

fn tower(b: &FieldR1csBuilder, value: &LinExpr) -> u128 {
    let flat = value.eval(b.values());
    flat_to_tower_u128(u128::from(flat.lo) | (u128::from(flat.hi) << 64))
}

fn select(b: &mut FieldR1csBuilder, when: &LinExpr, yes: &LinExpr, no: &LinExpr) -> LinExpr {
    no.add(&mul(b, when, &yes.add(no)))
}

/// Ordinary-only classes preserve typed entries and cannot consume them as NOID.
pub fn bind_ordinary_native_namespace(
    b: &mut FieldR1csBuilder,
    surface: &ActionSurfaceTrace,
    arithmetic: &UserPublicArithmeticTrace,
) {
    for index in 0..noid_tx::TX_INPUTS {
        let creation = &arithmetic.inputs[index].creation_id;
        let tag = mul(
            b,
            &LinExpr::from_wire(creation.bits[62]),
            &LinExpr::from_wire(creation.bits[63]).add_const(F128::ONE),
        );
        let invalid = mul(b, &tag, &surface.selected_inputs[index]);
        pin_zero(b, &invalid);
    }
}

/// Input provenance follows the exact packed incarnation. Output provenance
/// is witness advice whose complete set is checked against the header below.
/// Ordinary funding inside a native operation uses the same header authority
/// as the selected Owner statement.
pub fn bind_native_action_selectors(
    b: &mut FieldR1csBuilder,
    surfaces: &[ActionSurfaceTrace],
    arithmetic: &[UserPublicArithmeticTrace],
    pages: &[NativePageContextTrace],
    headers: &[NativeHeaderTrace],
) -> NativeActionSelectors {
    let headers = headers.iter().collect::<Vec<_>>();
    bind_native_action_selectors_inner(b, surfaces, arithmetic, pages, &headers, false)
}

pub fn bind_financial_action_selectors(
    b: &mut FieldR1csBuilder,
    surfaces: &[ActionSurfaceTrace],
    arithmetic: &[UserPublicArithmeticTrace],
    pages: &[NativePageContextTrace],
    headers: &[FinancialNativeHeaderTrace],
) -> NativeActionSelectors {
    let headers = headers.iter().map(|h| &h.header).collect::<Vec<_>>();
    bind_native_action_selectors_inner(b, surfaces, arithmetic, pages, &headers, true)
}

fn bind_native_action_selectors_inner(
    b: &mut FieldR1csBuilder,
    surfaces: &[ActionSurfaceTrace],
    arithmetic: &[UserPublicArithmeticTrace],
    pages: &[NativePageContextTrace],
    headers: &[&NativeHeaderTrace],
    financial: bool,
) -> NativeActionSelectors {
    assert_eq!(surfaces.len(), arithmetic.len());
    assert_eq!(surfaces.len(), pages.len());
    let output_masks: BTreeMap<_, _> = headers
        .iter()
        .filter(|header| tower(b, &header.live) != 0)
        .map(|header| {
            (
                tower(b, &header.header_page),
                header
                    .output_types
                    .iter()
                    .map(|bit| tower(b, bit) != 0)
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let mut result = NativeActionSelectors {
        native: Vec::with_capacity(10 * surfaces.len()),
        funding: Vec::with_capacity(10 * surfaces.len()),
        ordinal: Vec::with_capacity(10 * surfaces.len()),
    };
    for ((surface, arithmetic), page) in surfaces.iter().zip(arithmetic).zip(pages) {
        let trade = if financial {
            is_zero(b, &page.operation.add_const(flat_const(80)))
        } else {
            LinExpr::zero()
        };
        let token_genesis = is_zero(b, &page.operation.add_const(flat_const(1)));
        let collection_genesis = is_zero(b, &page.operation.add_const(flat_const(5)));
        let mut genesis = token_genesis.add(&collection_genesis);
        if financial {
            for code in [32, 48, 67] {
                let funding = is_zero(b, &page.operation.add_const(flat_const(code)));
                genesis = genesis.add(&funding);
            }
        }
        for index in 0..noid_tx::TX_INPUTS {
            let live = &surface.selected_inputs[index];
            let input = &arithmetic.inputs[index];
            let native_tag = mul(
                b,
                &LinExpr::from_wire(input.creation_id.bits[62]),
                &LinExpr::from_wire(input.creation_id.bits[63]).add_const(F128::ONE),
            );
            let native = mul(b, live, &native_tag);
            let outside_native = mul(b, &native, &page.live.add_const(F128::ONE));
            pin_zero(b, &outside_native);
            let ordinary_group_input = mul(b, live, &page.live);
            let ordinary = ordinary_group_input.add(&native);
            require_nonzero(b, &input.creation_id.value, &ordinary);
            let owner_checked = mul(b, &ordinary, &trade.add_const(F128::ONE));
            for lane in 0..2 {
                let different = mul(
                    b,
                    &owner_checked,
                    &surface.input_rows[index].owner[lane].add(&page.authority[lane]),
                );
                pin_zero(b, &different);
            }
            let raw_ordinal = integer_add_no_overflow(
                b,
                &page.input_offset,
                &LinExpr::constant(flat_const(index as u128)),
                11,
            );
            let ordinal = mul(b, &ordinary_group_input, &raw_ordinal);
            let selected_funding = is_zero(b, &raw_ordinal.add(&page.funding_input));
            let selected_funding = mul(b, &selected_funding, &genesis);
            let funding = mul(b, &ordinary_group_input, &selected_funding);
            let native_funding = mul(b, &native, &funding);
            pin_zero(b, &native_funding);
            result.native.push(native);
            result.funding.push(funding);
            result.ordinal.push(ordinal);
        }
        for index in 0..noid_tx::TX_OUTPUTS {
            let live = &surface.selected_outputs[index];
            let ordinal = integer_add_no_overflow(
                b,
                &page.output_offset,
                &LinExpr::constant(flat_const(index as u128)),
                9,
            );
            let mask_bit = output_masks
                .get(&tower(b, &page.header_page))
                .and_then(|mask| mask.get(tower(b, &ordinal) as usize))
                .copied()
                .unwrap_or(false);
            let native = alloc_block(
                b,
                Block128::from(u128::from(mask_bit && tower(b, live) != 0)),
            );
            let invalid = mul(b, &native, &native.add_const(F128::ONE));
            pin_zero(b, &invalid);
            for required in [live, &page.live] {
                let outside = mul(b, &native, &required.add_const(F128::ONE));
                pin_zero(b, &outside);
            }
            let selected = mul(b, live, &page.live);
            result.ordinal.push(mul(b, &selected, &ordinal));
            result.native.push(native);
            result.funding.push(LinExpr::zero());
        }
    }
    result
}

pub(super) fn route_sorted(
    b: &mut FieldR1csBuilder,
    mut rows: Vec<Vec<LinExpr>>,
    width: usize,
    keys: impl Fn(&FieldR1csBuilder, &[LinExpr]) -> Vec<u128>,
) -> Vec<Vec<LinExpr>> {
    let capacity = rows.len().max(1).next_power_of_two();
    rows.resize_with(capacity, || vec![LinExpr::zero(); width]);
    let mut order: Vec<_> = (0..capacity).collect();
    order.sort_by_key(|&i| (tower(b, &rows[i][0]) == 0, keys(b, &rows[i]), i));
    let mut permutation = vec![0; capacity];
    for (target, source) in order.into_iter().enumerate() {
        permutation[source] = target;
    }
    route_permutation_network(b, rows, &permutation)
}

/// Route the complete selected action set after allocator packing. Every
/// returned preimage is bound to its actual body root and exact State value.
/// Funding anchors remain ordinary records, distinguished from typed objects.
pub fn bind_native_actions(
    b: &mut FieldR1csBuilder,
    actions: &[ActionRowTrace],
    selectors: &NativeActionSelectors,
    pages: &[NativePageContextTrace],
    headers: &[NativeHeaderTrace],
    height: &LinExpr,
    capacity: usize,
    mut opening_for_root: impl FnMut(Address) -> Option<NativeOpening>,
) -> Vec<NativeActionTrace> {
    assert_eq!(actions.len(), 10 * pages.len());
    assert_eq!(actions.len(), selectors.native.len());
    assert_eq!(actions.len(), selectors.funding.len());
    assert_eq!(actions.len(), selectors.ordinal.len());
    assert!(capacity > 0 && capacity <= actions.len().next_power_of_two());
    let rows = actions
        .iter()
        .enumerate()
        .map(|(index, action)| {
            let page = &pages[index / 10];
            let native = &selectors.native[index];
            let live = native.add(&selectors.funding[index]);
            let input = mul(b, native, &action.is_mint.add_const(F128::ONE));
            let output = mul(b, native, &action.is_mint);
            let class = input.add(&output.scale(flat_const(2)));
            vec![
                live.clone(),
                class,
                mul(b, &live, &page.header_page),
                mul(b, &live, &selectors.ordinal[index]),
                mul(b, &live, &action.slot_index),
                mul(b, &live, &action.value),
                mul(b, &live, &action.owner[0]),
                mul(b, &live, &action.owner[1]),
            ]
        })
        .collect();
    let rows = route_sorted(b, rows, 8, |b, row| {
        vec![tower(b, &row[2]), tower(b, &row[1]), tower(b, &row[3])]
    });
    for row in &rows[capacity..] {
        pin_zero(b, &row[0]);
    }
    let mut previous: Option<(LinExpr, Vec<LinExpr>)> = None;
    let mut result = Vec::with_capacity(capacity);
    for row in rows.into_iter().take(capacity) {
        let class: Vec<_> = range_check_bits(b, &row[1], 2)
            .into_iter()
            .map(LinExpr::from_wire)
            .collect();
        let invalid_class = mul(b, &class[0], &class[1]);
        pin_zero(b, &invalid_class);
        let native = class[0].add(&class[1]);
        let unselected = mul(b, &native, &row[0].add_const(F128::ONE));
        pin_zero(b, &unselected);
        let funding = row[0].add(&native);
        let output = class[1].clone();
        let header_bits: Vec<_> = range_check_bits(b, &row[2], 16)
            .into_iter()
            .map(LinExpr::from_wire)
            .collect();
        let mut key: Vec<_> = range_check_bits(b, &row[3], 11)
            .into_iter()
            .map(LinExpr::from_wire)
            .collect();
        key.extend(class);
        key.extend(header_bits);
        if let Some((live, old_key)) = previous {
            let hole = mul(b, &row[0], &live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let strict = less_than(b, &old_key, &key);
            let duplicate = mul(b, &row[0], &strict.add_const(F128::ONE));
            pin_zero(b, &duplicate);
        }
        previous = Some((row[0].clone(), key));
        // Resolve the shared header only after bounded compaction. Its keys
        // are already unique, so this disjoint lookup selects exactly one.
        let mut found = LinExpr::zero();
        let mut operation = LinExpr::zero();
        let mut authority = [LinExpr::zero(), LinExpr::zero()];
        for header in headers {
            let equal = is_zero(b, &row[2].add(&header.header_page));
            let selected = mul(b, &equal, &header.live);
            let selected = mul(b, &selected, &row[0]);
            found = found.add(&selected);
            operation = operation.add(&mul(b, &selected, &header.operation));
            for lane in 0..2 {
                authority[lane] = authority[lane].add(&mul(b, &selected, &header.authority[lane]));
            }
        }
        pin_eq(b, &found, &row[0]);
        let mut root_bytes = [0u8; 32];
        root_bytes[..16].copy_from_slice(&tower(b, &row[6]).to_le_bytes());
        root_bytes[16..].copy_from_slice(&tower(b, &row[7]).to_le_bytes());
        let witness = if tower(b, &native) != 0 {
            opening_for_root(Address(root_bytes))
        } else {
            None
        };
        let kind = alloc_block(
            b,
            Block128(witness.as_ref().map_or(0, |value| value.kind() as u128)),
        );
        let fields = witness
            .as_ref()
            .and_then(NativeOpening::compact_fields)
            .unwrap_or([Block128(0); 8])
            .map(|field| alloc_block(b, field));
        let opening = bind_native_opening(b, &kind, &fields);
        pin_eq(b, &opening.live, &native);
        let slot = mul(b, &native, &row[4]);
        let value = mul(b, &native, &row[5]);
        let root = std::array::from_fn(|i| mul(b, &native, &row[6 + i]));
        let native_authority = std::array::from_fn(|i| mul(b, &native, &authority[i]));
        let context = bind_native_context(b, &native, &native_authority, height);
        let packed = split_packed_input_value(b, &value);
        bind_native_action_slot(b, &opening, &slot, &packed, &root, &output, &context);
        result.push(NativeActionTrace {
            live: row[0].clone(),
            native,
            funding,
            header_page: row[2].clone(),
            ordinal: row[3].clone(),
            is_output: output,
            slot: row[4].clone(),
            packed_value: row[5].clone(),
            root: [row[6].clone(), row[7].clone()],
            authority,
            operation,
            opening,
        });
    }
    bind_type_bitmaps(b, headers, &result);
    result
}

fn bit_unit(b: &mut FieldR1csBuilder, bits: &[LinExpr]) -> LinExpr {
    assert_eq!(bits.len(), 7);
    let mut values: Vec<_> = (0..128)
        .map(|bit| LinExpr::constant(flat_const(1u128 << bit)))
        .collect();
    for bit in bits {
        values = values
            .chunks_exact(2)
            .map(|pair| select(b, bit, &pair[1], &pair[0]))
            .collect();
    }
    values.pop().expect("one bit-unit value")
}

/// Each bucket occurs exactly once in the header source. Native action
/// ordinals are unique, so their XOR of single-bit units reconstructs the
/// exact bitmap. A permutation and bucket equality bind every bit, including
/// positions beyond the logical input/output counts, without a chosen subset.
pub(super) struct NativeTypeBitmapRow<'a> {
    pub native: &'a LinExpr,
    pub ordinal: &'a LinExpr,
    pub is_output: &'a LinExpr,
    pub header_page: &'a LinExpr,
}

fn bind_type_bitmaps(
    b: &mut FieldR1csBuilder,
    headers: &[NativeHeaderTrace],
    actions: &[NativeActionTrace],
) {
    let headers = headers.iter().collect::<Vec<_>>();
    let actions = actions
        .iter()
        .map(|a| NativeTypeBitmapRow {
            native: &a.native,
            ordinal: &a.ordinal,
            is_output: &a.is_output,
            header_page: &a.header_page,
        })
        .collect::<Vec<_>>();
    bind_native_type_bitmaps(b, &headers, &actions);
}

pub(super) fn bind_native_type_bitmaps(
    b: &mut FieldR1csBuilder,
    headers: &[&NativeHeaderTrace],
    actions: &[NativeTypeBitmapRow<'_>],
) {
    let mut rows = Vec::with_capacity(10 * headers.len() + actions.len());
    for header in headers {
        let header_bits: Vec<_> = range_check_bits(b, &header.header_page, 16)
            .into_iter()
            .map(LinExpr::from_wire)
            .collect();
        let high = header_bits
            .iter()
            .enumerate()
            .fold(LinExpr::zero(), |sum, (i, bit)| {
                sum.add(&bit.scale(flat_const(1u128 << (4 + i))))
            });
        for (chunk, mask) in header
            .input_types
            .chunks_exact(128)
            .chain(header.output_types.chunks_exact(128))
            .enumerate()
        {
            let key = high.add(&header.live.scale(flat_const(chunk as u128)));
            rows.push(vec![
                header.live.clone(),
                key,
                header.live.clone(),
                LinExpr::zero(),
                pack(mask),
            ]);
        }
    }
    for action in actions {
        let live = action.native;
        let ordinal: Vec<_> = range_check_bits(b, &action.ordinal, 11)
            .into_iter()
            .map(LinExpr::from_wire)
            .collect();
        let out_of_input_mask = mul(b, live, &ordinal[10]);
        pin_zero(b, &out_of_input_mask);
        for bit in &ordinal[8..10] {
            let out_of_output_mask = mul(b, &action.is_output, bit);
            pin_zero(b, &out_of_output_mask);
        }
        let header: Vec<_> = range_check_bits(b, &action.header_page, 16)
            .into_iter()
            .map(LinExpr::from_wire)
            .collect();
        let mut key = pack(&ordinal[7..10]);
        key = key.add(&action.is_output.scale(flat_const(8)));
        for (i, bit) in header.iter().enumerate() {
            key = key.add(&bit.scale(flat_const(1u128 << (4 + i))));
        }
        let key = mul(b, live, &key);
        let unit = bit_unit(b, &ordinal[..7]);
        let unit = mul(b, live, &unit);
        rows.push(vec![
            live.clone(),
            key,
            LinExpr::zero(),
            unit,
            LinExpr::zero(),
        ]);
    }
    let rows = route_sorted(b, rows, 5, |b, row| {
        vec![tower(b, &row[1]), u128::from(tower(b, &row[2]) == 0)]
    });
    let mut current_key = LinExpr::zero();
    let mut expected = LinExpr::zero();
    let mut actual = LinExpr::zero();
    let mut previous_live = LinExpr::constant(F128::ONE);
    for row in rows {
        let hole = mul(b, &row[0], &previous_live.add_const(F128::ONE));
        pin_zero(b, &hole);
        previous_live = row[0].clone();
        let flush = mul(b, &row[2], &expected.add(&actual));
        pin_zero(b, &flush);
        current_key = select(b, &row[2], &row[1], &current_key);
        expected = select(b, &row[2], &row[4], &expected);
        actual = mul(b, &row[2].add_const(F128::ONE), &actual).add(&row[3]);
        let unit_live = row[0].add(&row[2]);
        let wrong_bucket = mul(b, &unit_live, &row[1].add(&current_key));
        pin_zero(b, &wrong_bucket);
    }
    pin_eq(b, &expected, &actual);
}
