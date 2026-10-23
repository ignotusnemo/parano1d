// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete native-financial action routing over the shared State table.

use noid_core::{hardware::flat_to_tower_u128, Block128};
use noid_poseidon2b::primitives::Address;
use noid_tx::native_assets::{NativeOpening, MAX_NATIVE_OPENING_FIELDS};

use super::super::action_surface::ActionRowTrace;
use super::super::paged_spend::NativePageContextTrace;
use super::super::{alloc_block, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::actions::{
    bind_native_type_bitmaps, route_sorted, NativeActionSelectors, NativeTypeBitmapRow,
};
use super::arithmetic::less_than;
use super::arithmetic::range_check_bits;
use super::arithmetic::split_packed_input_value;
use super::financial_slot::{
    bind_financial_slot, bind_sequential_financial_slot, FinancialSlotTrace,
};
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;

pub struct FinancialActionTrace {
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
    pub opening: FinancialSlotTrace,
}

fn tower(b: &FieldR1csBuilder, value: &LinExpr) -> u128 {
    let flat = value.eval(b.values());
    flat_to_tower_u128(u128::from(flat.lo) | (u128::from(flat.hi) << 64))
}

/// Route every input and output of every native group, including ordinary
/// NOID funding, change and fixed beneficiary payments. The caller supplies
/// the already packed shared allocator rows in exact physical body order.
pub fn bind_financial_actions(
    b: &mut FieldR1csBuilder,
    actions: &[ActionRowTrace],
    selectors: &NativeActionSelectors,
    pages: &[NativePageContextTrace],
    headers: &[FinancialNativeHeaderTrace],
    capacity: usize,
    opening_for_root: impl FnMut(Address) -> Option<NativeOpening>,
) -> Vec<FinancialActionTrace> {
    bind_actions(
        b,
        actions,
        selectors,
        pages,
        headers,
        capacity,
        opening_for_root,
        false,
    )
}

pub fn bind_sequential_financial_actions(
    b: &mut FieldR1csBuilder,
    actions: &[ActionRowTrace],
    selectors: &NativeActionSelectors,
    pages: &[NativePageContextTrace],
    headers: &[FinancialNativeHeaderTrace],
    capacity: usize,
    opening_for_root: impl FnMut(Address) -> Option<NativeOpening>,
) -> Vec<FinancialActionTrace> {
    bind_actions(
        b,
        actions,
        selectors,
        pages,
        headers,
        capacity,
        opening_for_root,
        true,
    )
}

fn bind_actions(
    b: &mut FieldR1csBuilder,
    actions: &[ActionRowTrace],
    selectors: &NativeActionSelectors,
    pages: &[NativePageContextTrace],
    headers: &[FinancialNativeHeaderTrace],
    capacity: usize,
    mut opening_for_root: impl FnMut(Address) -> Option<NativeOpening>,
    sequential: bool,
) -> Vec<FinancialActionTrace> {
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
            let live = mul(b, &page.live, &action.live);
            vec![
                live.clone(),
                mul(b, &live, &page.header_page),
                mul(b, &live, &action.is_mint),
                mul(b, &live, &selectors.ordinal[index]),
                selectors.native[index].clone(),
                selectors.funding[index].clone(),
                mul(b, &live, &action.slot_index),
                mul(b, &live, &action.value),
                mul(b, &live, &action.owner[0]),
                mul(b, &live, &action.owner[1]),
            ]
        })
        .collect();
    let rows = route_sorted(b, rows, 10, |b, row| {
        vec![tower(b, &row[1]), tower(b, &row[2]), tower(b, &row[3])]
    });
    for row in &rows[capacity..] {
        pin_zero(b, &row[0]);
    }
    let mut result = Vec::with_capacity(capacity);
    let mut previous: Option<(LinExpr, Vec<LinExpr>)> = None;
    for row in rows.into_iter().take(capacity) {
        let mut key = range_check_bits(b, &row[3], 11)
            .into_iter()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        key.push(row[2].clone());
        key.extend(
            range_check_bits(b, &row[1], 16)
                .into_iter()
                .map(LinExpr::from_wire),
        );
        if let Some((live, old)) = previous {
            let hole = mul(b, &row[0], &live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let strict = less_than(b, &old, &key);
            let duplicate = mul(b, &row[0], &strict.add_const(F128::ONE));
            pin_zero(b, &duplicate);
        }
        previous = Some((row[0].clone(), key));
        let mut found = LinExpr::zero();
        let mut operation = LinExpr::zero();
        let mut authority = [LinExpr::zero(), LinExpr::zero()];
        for header in headers {
            let same = is_zero(b, &row[1].add(&header.header.header_page));
            let selected = mul(b, &same, &header.header.live);
            let selected = mul(b, &selected, &row[0]);
            found = found.add(&selected);
            operation = operation.add(&mul(b, &selected, &header.header.operation));
            for lane in 0..2 {
                authority[lane] =
                    authority[lane].add(&mul(b, &selected, &header.header.authority[lane]));
            }
        }
        pin_eq(b, &found, &row[0]);
        let mut root = [0u8; 32];
        root[..16].copy_from_slice(&tower(b, &row[8]).to_le_bytes());
        root[16..].copy_from_slice(&tower(b, &row[9]).to_le_bytes());
        let witness = if tower(b, &row[4]) != 0 {
            opening_for_root(Address(root))
        } else {
            None
        };
        let kind = alloc_block(
            b,
            Block128(witness.as_ref().map_or(0, |v| v.kind() as u128)),
        );
        let fields = witness
            .as_ref()
            .map(NativeOpening::fields)
            .unwrap_or([Block128(0); MAX_NATIVE_OPENING_FIELDS])
            .map(|v| alloc_block(b, v));
        let slot = mul(b, &row[4], &row[6]);
        let packed = mul(b, &row[4], &row[7]);
        let packed = split_packed_input_value(b, &packed);
        let root = [mul(b, &row[4], &row[8]), mul(b, &row[4], &row[9])];
        let opening = if sequential {
            bind_sequential_financial_slot(b, &kind, &fields, &slot, &packed, &root)
        } else {
            bind_financial_slot(b, &kind, &fields, &slot, &packed, &root)
        };
        pin_eq(b, &opening.live, &row[4]);
        result.push(FinancialActionTrace {
            live: row[0].clone(),
            native: row[4].clone(),
            funding: row[5].clone(),
            header_page: row[1].clone(),
            ordinal: row[3].clone(),
            is_output: row[2].clone(),
            slot: row[6].clone(),
            packed_value: row[7].clone(),
            root: [row[8].clone(), row[9].clone()],
            authority,
            operation,
            opening,
        });
    }
    let headers = headers.iter().map(|h| &h.header).collect::<Vec<_>>();
    let bitmaps = result
        .iter()
        .map(|a| NativeTypeBitmapRow {
            native: &a.native,
            ordinal: &a.ordinal,
            is_output: &a.is_output,
            header_page: &a.header_page,
        })
        .collect::<Vec<_>>();
    bind_native_type_bitmaps(b, &headers, &bitmaps);
    result
}
