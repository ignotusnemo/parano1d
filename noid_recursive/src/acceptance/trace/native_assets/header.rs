// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete native headers paired with their exact logical END records.

use super::super::action_surface::{
    ActionSurfaceTrace, LEAF_EPOCH_ANCHOR, LEAF_FEE, LEAF_FLAGS, LEAF_INPUT_BASE, LEAF_INPUT_OWNER,
    LEAF_OUTPUT0_DATA, LEAF_OUTPUT0_OWNER, LEAF_OUTPUT1_DATA, LEAF_OUTPUT1_OWNER,
};
use super::super::paged_spend::NativePageContextTrace;
use super::super::permutation_network::route_permutation_network;
use super::super::tx_body_spine::SpineInputsTrace;
use super::super::{
    flat_const, mul, pin_eq, pin_zero, range_check_bits, FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::less_than;
use super::financial_operation::{bind_native_operation_metadata, NativeOperationMetadataTrace};
use super::validation::{is_zero, nonzero_pair};

pub struct NativeHeaderTrace {
    pub live: LinExpr,
    pub header_page: LinExpr,
    pub operation: LinExpr,
    pub selectors: [LinExpr; 9],
    pub chain: [LinExpr; 2],
    pub authority: [LinExpr; 2],
    pub asset: [LinExpr; 2],
    pub funding_input: LinExpr,
    pub input_types: Vec<LinExpr>,
    pub output_types: Vec<LinExpr>,
    pub logical_txid: [LinExpr; 2],
    pub input_count: LinExpr,
    pub output_count: LinExpr,
    pub fee: LinExpr,
}

/// Complete native header and its selected financial operand/authority rules.
pub struct FinancialNativeHeaderTrace {
    pub header: NativeHeaderTrace,
    pub metadata: NativeOperationMetadataTrace,
}

fn tower(b: &FieldR1csBuilder, value: &LinExpr) -> u128 {
    let value = value.eval(b.values());
    noid_core::hardware::flat_to_tower_u128(u128::from(value.lo) | (u128::from(value.hi) << 64))
}

fn compact(
    b: &mut FieldR1csBuilder,
    mut rows: Vec<Vec<LinExpr>>,
    width: usize,
    limit: usize,
) -> Vec<Vec<LinExpr>> {
    let capacity = rows.len().max(1).next_power_of_two();
    assert!(limit > 0 && limit <= capacity);
    rows.resize_with(capacity, || vec![LinExpr::zero(); width]);
    let mut order: Vec<_> = (0..capacity).collect();
    order.sort_by_key(|&i| (tower(b, &rows[i][0]) == 0, tower(b, &rows[i][1]), i));
    let mut permutation = vec![0; capacity];
    for (target, source) in order.into_iter().enumerate() {
        permutation[source] = target;
    }
    let rows = route_permutation_network(b, rows, &permutation);
    for row in &rows[limit..] {
        pin_zero(b, &row[0]);
    }
    let mut previous: Option<(LinExpr, Vec<LinExpr>)> = None;
    for row in &rows[..limit] {
        let key: Vec<_> = range_check_bits(b, &row[1], 16)
            .into_iter()
            .map(LinExpr::from_wire)
            .collect();
        if let Some((live, previous_key)) = previous {
            let hole = mul(b, &row[0], &live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let strict = less_than(b, &previous_key, &key);
            let unordered = mul(b, &row[0], &strict.add_const(F128::ONE));
            pin_zero(b, &unordered);
        }
        previous = Some((row[0].clone(), key));
    }
    rows.into_iter().take(limit).collect()
}

/// The routes prove complete extraction of every native header and END.
/// Scalar fields and bitmap words come from the same body-hash leaves as the
/// action surface. The operation bank binds every set type bit to its exact
/// native action and therefore also rejects unused bitmap positions.
pub fn bind_native_headers(
    b: &mut FieldR1csBuilder,
    spines: &[SpineInputsTrace],
    surfaces: &[ActionSurfaceTrace],
    pages: &[NativePageContextTrace],
    limit: usize,
    expected_chain: &[LinExpr; 2],
) -> Vec<NativeHeaderTrace> {
    bind_native_headers_inner(b, spines, surfaces, pages, limit, expected_chain, false)
        .into_iter()
        .map(|(header, _)| header)
        .collect()
}

pub fn bind_financial_native_headers(
    b: &mut FieldR1csBuilder,
    spines: &[SpineInputsTrace],
    surfaces: &[ActionSurfaceTrace],
    pages: &[NativePageContextTrace],
    limit: usize,
    expected_chain: &[LinExpr; 2],
) -> Vec<FinancialNativeHeaderTrace> {
    bind_native_headers_inner(b, spines, surfaces, pages, limit, expected_chain, true)
        .into_iter()
        .map(|(header, metadata)| FinancialNativeHeaderTrace {
            header,
            metadata: metadata.expect("financial header metadata"),
        })
        .collect()
}

fn bind_native_headers_inner(
    b: &mut FieldR1csBuilder,
    spines: &[SpineInputsTrace],
    surfaces: &[ActionSurfaceTrace],
    pages: &[NativePageContextTrace],
    limit: usize,
    expected_chain: &[LinExpr; 2],
    financial: bool,
) -> Vec<(NativeHeaderTrace, Option<NativeOperationMetadataTrace>)> {
    assert_eq!(spines.len(), surfaces.len());
    assert_eq!(spines.len(), pages.len());
    let mut headers = Vec::with_capacity(spines.len());
    let mut ends = Vec::with_capacity(spines.len());
    for (index, ((spine, surface), page)) in spines.iter().zip(surfaces).zip(pages).enumerate() {
        let live = mul(b, &surface.tx_live, &surface.native_header);
        let mut row = vec![live.clone(), live.scale(flat_const((index + 1) as u128))];
        for (index, leaf) in spine.leaves.iter().enumerate() {
            if index == LEAF_EPOCH_ANCHOR || index == LEAF_FEE {
                continue;
            }
            for lane in leaf {
                row.push(mul(b, &live, lane));
            }
        }
        headers.push(row);
        let mut end = vec![
            page.end_live.clone(),
            mul(b, &page.end_live, &page.header_page),
            page.logical_txid[0].clone(),
            page.logical_txid[1].clone(),
            page.input_count.clone(),
            page.output_count.clone(),
            page.fee.clone(),
            mul(b, &page.end_live, &page.authority[0]),
            mul(b, &page.end_live, &page.authority[1]),
        ];
        if financial {
            for field in page
                .chain
                .iter()
                .chain([&page.operation, &page.funding_input])
                .chain(&page.asset)
            {
                end.push(mul(b, &page.end_live, field));
            }
        }
        ends.push(end);
    }
    let headers = compact(b, headers, 30, limit);
    let ends = compact(b, ends, if financial { 15 } else { 9 }, limit);
    let mut result = Vec::with_capacity(limit);
    for (row, end) in headers.into_iter().zip(ends) {
        pin_eq(b, &row[0], &end[0]);
        pin_eq(b, &row[1], &end[1]);
        let live = row[0].clone();
        let header_page = row[1].clone();
        let mut values = row[2..].chunks_exact(2);
        let leaves: [[LinExpr; 2]; 16] = std::array::from_fn(|index| {
            if index == LEAF_EPOCH_ANCHOR || index == LEAF_FEE {
                [LinExpr::zero(), LinExpr::zero()]
            } else {
                let pair = values.next().expect("retained header leaf");
                [pair[0].clone(), pair[1].clone()]
            }
        });
        let flags = u128::from(
            noid_tx::PAGED_SPEND_START_BIT
                | noid_tx::native_assets::wire::NATIVE_PAGE_BIT
                | noid_tx::native_assets::wire::NATIVE_HEADER_BIT,
        );
        pin_eq(b, &leaves[LEAF_FLAGS][0], &live.scale(flat_const(flags)));
        pin_zero(b, &leaves[LEAF_FLAGS][1]);
        pin_eq(
            b,
            &leaves[LEAF_OUTPUT0_DATA][0],
            &live.scale(flat_const(u128::from(
                noid_tx::native_assets::wire::NATIVE_SPEND_VERSION,
            ))),
        );
        if !financial {
            pin_zero(b, &leaves[LEAF_OUTPUT1_DATA][0]);
        }
        let authority = leaves[LEAF_INPUT_OWNER].clone();
        if !financial {
            nonzero_pair(b, &authority, &live);
        }
        for lane in 0..2 {
            pin_eq(b, &authority[lane], &end[7 + lane]);
        }
        let chain = leaves[LEAF_OUTPUT0_OWNER].clone();
        for lane in 0..2 {
            let expected = mul(b, &live, &expected_chain[lane]);
            pin_eq(b, &chain[lane], &expected);
        }
        let operation = leaves[LEAF_OUTPUT0_DATA][1].clone();
        let (selectors, asset, funding_input, metadata) = if financial {
            for lane in 0..2 {
                pin_eq(b, &chain[lane], &end[9 + lane]);
                pin_eq(b, &leaves[LEAF_OUTPUT1_OWNER][lane], &end[13 + lane]);
            }
            pin_eq(b, &operation, &end[11]);
            pin_eq(b, &leaves[LEAF_OUTPUT1_DATA][1], &end[12]);
            let metadata = bind_native_operation_metadata(
                b,
                &live,
                &operation,
                &leaves[LEAF_OUTPUT1_DATA][0],
                &leaves[LEAF_OUTPUT1_DATA][1],
                &leaves[LEAF_OUTPUT1_OWNER],
                &authority,
                &end[4],
            );
            (
                metadata.base.clone(),
                metadata.asset.clone(),
                metadata.funding_input.clone(),
                Some(metadata),
            )
        } else {
            let op_bits = range_check_bits(b, &operation, 4);
            let mut tensor = vec![LinExpr::constant(F128::ONE)];
            for bit in op_bits {
                let bit = LinExpr::from_wire(bit);
                let n = tensor.len();
                let mut next = vec![LinExpr::zero(); 2 * n];
                for (i, value) in tensor.iter().enumerate() {
                    let one = mul(b, value, &bit);
                    next[i] = value.add(&one);
                    next[i + n] = one;
                }
                tensor = next;
            }
            for invalid in &tensor[9..] {
                pin_zero(b, invalid);
            }
            for code in [1, 4] {
                pin_zero(b, &tensor[code]);
            }
            pin_eq(b, &tensor[0], &live.add_const(F128::ONE));
            let selectors: [LinExpr; 9] = std::array::from_fn(|i| {
                if i == 0 || noid_tx::native_assets::profile::operation_enabled(i as u16) {
                    tensor[i].clone()
                } else {
                    LinExpr::zero()
                }
            });
            let asset_required = selectors[2].add(&selectors[3]).add(&selectors[4]);
            let asset = leaves[LEAF_OUTPUT1_OWNER].clone();
            nonzero_pair(b, &asset, &asset_required);
            for lane in &asset {
                let extra = mul(b, &asset_required.add_const(F128::ONE), lane);
                pin_zero(b, &extra);
            }
            let funding_required = selectors[1].add(&selectors[5]);
            let funding_input = leaves[LEAF_OUTPUT1_DATA][1].clone();
            let argument_bits: Vec<_> = range_check_bits(b, &funding_input, 11)
                .into_iter()
                .map(LinExpr::from_wire)
                .collect();
            let unused_argument = mul(b, &funding_required.add_const(F128::ONE), &funding_input);
            pin_zero(b, &unused_argument);
            let count_bits: Vec<_> = range_check_bits(b, &end[4], 11)
                .into_iter()
                .map(LinExpr::from_wire)
                .collect();
            let valid_funding = less_than(b, &argument_bits, &count_bits);
            let bad_funding = mul(b, &funding_required, &valid_funding.add_const(F128::ONE));
            pin_zero(b, &bad_funding);
            (selectors, asset, funding_input, None)
        };
        let mut bitmap = Vec::with_capacity(1280);
        for leaf in &leaves[LEAF_INPUT_BASE..LEAF_INPUT_BASE + noid_tx::TX_INPUTS] {
            bitmap.extend(
                range_check_bits(b, &leaf[0], 32)
                    .into_iter()
                    .map(LinExpr::from_wire),
            );
            bitmap.extend(
                range_check_bits(b, &leaf[1], 128)
                    .into_iter()
                    .map(LinExpr::from_wire),
            );
        }
        let output_types = bitmap.split_off(1024);
        let input_types = bitmap;
        for bit in &input_types[1020..] {
            pin_zero(b, bit);
        }
        let count_zero = is_zero(b, &end[4]);
        let empty = mul(b, &live, &count_zero);
        pin_zero(b, &empty);
        // The scanner's counts and fee are part of the same END record as
        // the derived logical id, rather than independent caller assertions.
        result.push((
            NativeHeaderTrace {
                live,
                header_page,
                operation,
                selectors,
                chain,
                authority,
                asset,
                funding_input,
                input_types,
                output_types,
                logical_txid: [end[2].clone(), end[3].clone()],
                input_count: end[4].clone(),
                output_count: end[5].clone(),
                fee: end[6].clone(),
            },
            metadata,
        ));
    }
    result
}
