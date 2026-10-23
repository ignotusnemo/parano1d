// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Base operation semantics over the complete shared financial action table.

use super::super::permutation_network::route_permutation_network;
use super::super::public_arithmetic::U64Trace;
use super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::actions::NativeActionTrace;
use super::arithmetic::less_than;
use super::arithmetic::range_check_bits;
use super::arithmetic::split_packed_input_value;
use super::financial_actions::FinancialActionTrace;
use super::financial_values::FinancialCarrierValuesTrace;
use super::header::{FinancialNativeHeaderTrace, NativeHeaderTrace};
use super::kernel::bind_native_kernel;
use super::validation::{
    bind_native_action_slot, bind_native_context, is_zero, NativeOpeningTrace,
};
use super::NativeOpeningRootTrace;
use noid_core::hardware::flat_to_tower_u128;

fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}

fn selected_u64(b: &mut FieldR1csBuilder, flag: &LinExpr, x: &U64Trace) -> U64Trace {
    let value = mul(b, flag, &x.value);
    let bits = range_check_bits(b, &value, 64).try_into().unwrap();
    U64Trace { value, bits }
}

fn selected_opening(
    b: &mut FieldR1csBuilder,
    flag: &LinExpr,
    x: &NativeOpeningTrace,
) -> NativeOpeningTrace {
    let live = mul(b, flag, &x.live);
    let selectors = std::array::from_fn(|i| {
        if i == 0 {
            live.add_const(F128::ONE)
        } else {
            mul(b, flag, &x.commitment.selectors[i])
        }
    });
    let root = std::array::from_fn(|i| mul(b, flag, &x.commitment.root[i]));
    NativeOpeningTrace {
        commitment: NativeOpeningRootTrace { selectors, root },
        fields: std::array::from_fn(|i| mul(b, flag, &x.fields[i])),
        live,
        identifier: std::array::from_fn(|i| mul(b, flag, &x.identifier[i])),
        owner: std::array::from_fn(|i| mul(b, flag, &x.owner[i])),
        primary: selected_u64(b, flag, &x.primary),
        secondary: selected_u64(b, flag, &x.secondary),
        reserve_micronoid: selected_u64(b, flag, &x.reserve_micronoid),
        outstanding_units: selected_u64(b, flag, &x.outstanding_units),
        initial_supply: selected_u64(b, flag, &x.initial_supply),
        definition_root: std::array::from_fn(|i| mul(b, flag, &x.definition_root[i])),
        metadata: std::array::from_fn(|i| mul(b, flag, &x.metadata[i])),
    }
}

fn base_headers(
    b: &mut FieldR1csBuilder,
    source: &[FinancialNativeHeaderTrace],
) -> Vec<NativeHeaderTrace> {
    assert!(!source.is_empty());
    let input_width = source[0].header.input_types.len();
    let output_width = source[0].header.output_types.len();
    let width = 23 + input_width + output_width;
    let mut rows = Vec::with_capacity(source.len());
    for header in source {
        let h = &header.header;
        assert_eq!(h.input_types.len(), input_width);
        assert_eq!(h.output_types.len(), output_width);
        let live = header.metadata.base[1..]
            .iter()
            .fold(LinExpr::zero(), |sum, x| sum.add(x));
        let mut row = vec![live.clone()];
        for x in [&h.header_page, &h.operation]
            .into_iter()
            .chain(h.chain.iter())
            .chain(h.authority.iter())
            .chain(h.asset.iter())
            .chain(std::iter::once(&h.funding_input))
            .chain(h.logical_txid.iter())
            .chain([&h.input_count, &h.output_count, &h.fee])
            .chain(header.metadata.base[1..].iter())
            .chain(h.input_types.iter())
            .chain(h.output_types.iter())
        {
            row.push(mul(b, &live, x));
        }
        assert_eq!(row.len(), width);
        rows.push(row);
    }
    let capacity = rows.len().next_power_of_two();
    rows.resize_with(capacity, || vec![LinExpr::zero(); width]);
    let mut order = (0..capacity).collect::<Vec<_>>();
    order.sort_by_key(|&i| (tower(b, &rows[i][0]) == 0, tower(b, &rows[i][1]), i));
    let mut permutation = vec![0; capacity];
    for (target, original) in order.into_iter().enumerate() {
        permutation[original] = target;
    }
    let rows = route_permutation_network(b, rows, &permutation);
    for row in &rows[source.len()..] {
        pin_zero(b, &row[0]);
    }
    let mut previous: Option<(LinExpr, Vec<LinExpr>)> = None;
    rows.into_iter()
        .take(source.len())
        .map(|row| {
            let key = range_check_bits(b, &row[1], 16)
                .into_iter()
                .map(LinExpr::from_wire)
                .collect::<Vec<_>>();
            if let Some((old_live, old)) = previous.take() {
                let gap = mul(b, &row[0], &old_live.add_const(F128::ONE));
                pin_zero(b, &gap);
                let strict = less_than(b, &old, &key);
                let invalid = mul(b, &row[0], &strict.add_const(F128::ONE));
                pin_zero(b, &invalid);
            }
            previous = Some((row[0].clone(), key));
            NativeHeaderTrace {
                live: row[0].clone(),
                header_page: row[1].clone(),
                operation: row[2].clone(),
                selectors: std::array::from_fn(|i| {
                    if i == 0 {
                        row[0].add_const(F128::ONE)
                    } else {
                        row[14 + i].clone()
                    }
                }),
                chain: std::array::from_fn(|i| row[3 + i].clone()),
                authority: std::array::from_fn(|i| row[5 + i].clone()),
                asset: std::array::from_fn(|i| row[7 + i].clone()),
                funding_input: row[9].clone(),
                logical_txid: std::array::from_fn(|i| row[10 + i].clone()),
                input_count: row[12].clone(),
                output_count: row[13].clone(),
                fee: row[14].clone(),
                input_types: row[23..23 + input_width].to_vec(),
                output_types: row[23 + input_width..].to_vec(),
            }
        })
        .collect()
}

/// The enclosing relation binds complete shared actions, typed values and
/// native headers. Exact base-family selection reuses their commitments and
/// supplies each complete base group, including ordinary NOID carriers, to
/// the established base operation kernel.
pub fn bind_financial_base_operations(
    b: &mut FieldR1csBuilder,
    headers: &[FinancialNativeHeaderTrace],
    actions: &[FinancialActionTrace],
    values: &[FinancialCarrierValuesTrace],
    height: &LinExpr,
) {
    assert_eq!(actions.len(), values.len());
    let projected_headers = base_headers(b, headers);
    let mut projected = Vec::with_capacity(actions.len());
    for (action, values) in actions.iter().zip(values) {
        let mut found = LinExpr::zero();
        let mut base = LinExpr::zero();
        for header in headers {
            let same = is_zero(b, &action.header_page.add(&header.header.header_page));
            let hit = mul(b, &same, &header.header.live);
            let hit = mul(b, &hit, &action.live);
            found = found.add(&hit);
            let family = header.metadata.base[1..]
                .iter()
                .fold(LinExpr::zero(), |sum, x| sum.add(x));
            base = base.add(&mul(b, &hit, &family));
        }
        pin_eq(b, &found, &action.live);
        let overlap = mul(b, &action.native, &action.funding);
        pin_zero(b, &overlap);
        let selected = base;
        let native = mul(b, &selected, &action.native);
        let funding = mul(b, &selected, &action.funding);
        let opening = selected_opening(b, &selected, &values.base);
        pin_eq(b, &opening.live, &native);
        let authority = std::array::from_fn(|i| mul(b, &selected, &action.authority[i]));
        let native_authority = std::array::from_fn(|i| mul(b, &native, &authority[i]));
        let context = bind_native_context(b, &native, &native_authority, height);
        let slot = mul(b, &native, &action.slot);
        let packed = mul(b, &native, &action.packed_value);
        let packed = split_packed_input_value(b, &packed);
        let root = std::array::from_fn(|i| mul(b, &native, &action.root[i]));
        let output = mul(b, &native, &action.is_output);
        bind_native_action_slot(b, &opening, &slot, &packed, &root, &output, &context);
        projected.push(NativeActionTrace {
            live: selected.clone(),
            native,
            funding,
            header_page: mul(b, &selected, &action.header_page),
            ordinal: mul(b, &selected, &action.ordinal),
            is_output: mul(b, &selected, &action.is_output),
            slot: mul(b, &selected, &action.slot),
            packed_value: mul(b, &selected, &action.packed_value),
            root: std::array::from_fn(|i| mul(b, &selected, &action.root[i])),
            authority,
            operation: mul(b, &selected, &action.operation),
            opening,
        });
    }
    bind_native_kernel(b, &projected_headers, &projected, height);
}
