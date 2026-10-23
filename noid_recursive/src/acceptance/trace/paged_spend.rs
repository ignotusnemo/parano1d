// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-class PagedSpend scanner.
//!
//! Physical Tx8x2 pages stay in body/action order. This relation proves the
//! START..END partition, group continuity, dense/minimal packing, one checked
//! balance and one logical hash per group. END records are then stably
//! compacted into the authorization/fee/transaction-root prefix.

use noid_core::{hardware::flat_to_tower_u128, Block128};
use noid_poseidon2b::native::domain::{capacity_iv, DomainTag};

use super::action_compaction::strict_less_bits;
use super::action_surface::{ActionSurfaceTrace, LEAF_EPOCH_ANCHOR, LEAF_INPUT_OWNER};
use super::native_assets::validation::is_zero;
use super::permutation_network::route_permutation_network;
use super::public_arithmetic::UserPublicArithmeticTrace;
use super::tx_body_spine::SpineInputsTrace;
use super::{
    alloc_block, const_block, flat_const, integer_add_no_overflow, mul, pin_eq, pin_lt_strict,
    pin_zero, poseidon2b_permute, range_check_bits, FieldR1csBuilder, LinExpr, Wire, F128,
};

const TAG_PAGED_SPEND: DomainTag = DomainTag::new(b"PAGEDTX_");
const COUNT_BITS: usize = 11;
const OUTPUT_COUNT_BITS: usize = 9;
const MONEY_BITS: usize = 74;
const PAGE_COUNT_BITS: usize = 8;

/// One compacted logical group. A dead suffix record is exactly zero.
#[derive(Clone)]
pub struct PagedSpendGroupTrace {
    pub live: LinExpr,
    pub logical_txid: [LinExpr; 2],
    pub input_owner: [LinExpr; 2],
    pub fee: LinExpr,
    pub live_input_count: LinExpr,
    pub live_output_count: LinExpr,
    pub end_page: LinExpr,
}

/// Page scan result shared by capsule, tx-root and fee arithmetic.
pub struct PagedSpendBlockTrace {
    /// Power-of-two authorization-tile width for the selected proof class.
    /// Slots above the physical page tier are permanently dead dyadic pads.
    pub groups: Vec<PagedSpendGroupTrace>,
    pub logical_count: LinExpr,
    /// Empty in earlier profiles. Each context is derived from a native
    /// header and carried across its exact committed data-page group.
    pub native_pages: Vec<NativePageContextTrace>,
    pub native_group_count: LinExpr,
}

/// All logical operations plus the exact Owner-required authorization prefix.
pub struct FinancialPagedSpendBlockTrace {
    pub stream: PagedSpendBlockTrace,
    pub native_groups: Vec<LinExpr>,
    pub authorizations: Vec<PagedSpendGroupTrace>,
    pub authorization_count: LinExpr,
}

pub struct NativePageContextTrace {
    pub live: LinExpr,
    pub header_page: LinExpr,
    pub authority: [LinExpr; 2],
    pub chain: [LinExpr; 2],
    pub operation: LinExpr,
    pub funding_input: LinExpr,
    pub asset: [LinExpr; 2],
    pub input_offset: LinExpr,
    pub output_offset: LinExpr,
    pub end_live: LinExpr,
    pub logical_txid: [LinExpr; 2],
    pub input_count: LinExpr,
    pub output_count: LinExpr,
    pub fee: LinExpr,
}

fn tower_value(b: &FieldR1csBuilder, expression: &LinExpr) -> u128 {
    let flat = expression.eval(b.values());
    flat_to_tower_u128(u128::from(flat.lo) | (u128::from(flat.hi) << 64))
}

fn native_bool(b: &FieldR1csBuilder, expression: &LinExpr) -> bool {
    match expression.eval(b.values()) {
        F128::ZERO => false,
        F128::ONE => true,
        value => panic!("PagedSpend selector is not boolean: {value:?}"),
    }
}

fn mux(
    b: &mut FieldR1csBuilder,
    selector: &LinExpr,
    when_one: &LinExpr,
    when_zero: &LinExpr,
) -> LinExpr {
    when_zero.add(&mul(b, selector, &when_one.add(when_zero)))
}

fn increment_from_bits(b: &mut FieldR1csBuilder, bits: &[Wire]) -> LinExpr {
    let mut carry = LinExpr::constant(F128::ONE);
    let mut result = LinExpr::zero();
    for (bit, wire) in bits.iter().copied().enumerate() {
        let value = LinExpr::from_wire(wire);
        let next = value.add(&carry);
        result = result.add(&next.scale(flat_const(1u128 << bit)));
        carry = mul(b, &value, &carry);
    }
    pin_zero(b, &carry);
    result
}

fn rolling_sum(
    b: &mut FieldR1csBuilder,
    previous: &LinExpr,
    current: &LinExpr,
    start: &LinExpr,
    live: &LinExpr,
    width: usize,
) -> LinExpr {
    let continued = integer_add_no_overflow(b, previous, current, width);
    let grouped = mux(b, start, current, &continued);
    mul(b, live, &grouped)
}

fn prefix_bits(b: &mut FieldR1csBuilder, bits: &[LinExpr]) {
    for pair in bits.windows(2) {
        let sparse = mul(b, &pair[1], &pair[0].add_const(F128::ONE));
        pin_zero(b, &sparse);
    }
}

fn nonzero_when(b: &mut FieldR1csBuilder, selector: &LinExpr, bits: &[Wire]) {
    let all_zero = bits
        .iter()
        .copied()
        .fold(LinExpr::constant(F128::ONE), |product, bit| {
            mul(b, &product, &LinExpr::from_wire(bit).add_const(F128::ONE))
        });
    let violation = mul(b, selector, &all_zero);
    pin_zero(b, &violation);
}

fn selected_index(live: &LinExpr, one_based_index: usize) -> LinExpr {
    live.scale(flat_const(one_based_index as u128))
}

fn zero_group() -> PagedSpendGroupTrace {
    PagedSpendGroupTrace {
        live: LinExpr::zero(),
        logical_txid: [LinExpr::zero(), LinExpr::zero()],
        input_owner: [LinExpr::zero(), LinExpr::zero()],
        fee: LinExpr::zero(),
        live_input_count: LinExpr::zero(),
        live_output_count: LinExpr::zero(),
        end_page: LinExpr::zero(),
    }
}

fn group_lanes(group: PagedSpendGroupTrace) -> Vec<LinExpr> {
    vec![
        group.live,
        group.logical_txid[0].clone(),
        group.logical_txid[1].clone(),
        group.input_owner[0].clone(),
        group.input_owner[1].clone(),
        group.fee,
        group.live_input_count,
        group.live_output_count,
        group.end_page,
    ]
}

fn group_from_lanes(mut lanes: Vec<LinExpr>) -> PagedSpendGroupTrace {
    assert_eq!(lanes.len(), 9);
    let end_page = lanes.pop().unwrap();
    let live_output_count = lanes.pop().unwrap();
    let live_input_count = lanes.pop().unwrap();
    let fee = lanes.pop().unwrap();
    let owner_1 = lanes.pop().unwrap();
    let owner_0 = lanes.pop().unwrap();
    let hash_1 = lanes.pop().unwrap();
    let hash_0 = lanes.pop().unwrap();
    let live = lanes.pop().unwrap();
    PagedSpendGroupTrace {
        live,
        logical_txid: [hash_0, hash_1],
        input_owner: [owner_0, owner_1],
        fee,
        live_input_count,
        live_output_count,
        end_page,
    }
}

fn compact_end_records(
    b: &mut FieldR1csBuilder,
    candidates: Vec<PagedSpendGroupTrace>,
) -> Vec<PagedSpendGroupTrace> {
    compact_tagged_end_records(b, candidates, None).0
}

fn compact_tagged_end_records(
    b: &mut FieldR1csBuilder,
    mut candidates: Vec<PagedSpendGroupTrace>,
    tags: Option<Vec<LinExpr>>,
) -> (Vec<PagedSpendGroupTrace>, Option<Vec<LinExpr>>) {
    let physical_pages = candidates.len();
    // The shared body/authentication axis also carries primary coinbase.
    // This is unchanged for legacy 25/255 and gives power-of-two candidate
    // capacities a canonical all-zero authorization suffix.
    let route_rows = (physical_pages + 1).next_power_of_two();
    candidates.resize_with(route_rows, zero_group);

    let mut output_inputs: Vec<usize> = (0..route_rows).collect();
    output_inputs.sort_by_key(|&input| {
        let group = &candidates[input];
        let live = native_bool(b, &group.live);
        let end_page = if live {
            tower_value(b, &group.end_page)
        } else {
            0
        };
        (u8::from(!live), end_page, input)
    });
    let mut permutation = vec![usize::MAX; route_rows];
    for (output, input) in output_inputs.into_iter().enumerate() {
        permutation[input] = output;
    }

    let tagged = tags.is_some();
    let mut rows: Vec<_> = candidates.into_iter().map(group_lanes).collect();
    if let Some(mut tags) = tags {
        assert_eq!(tags.len(), physical_pages);
        tags.resize(route_rows, LinExpr::zero());
        for (row, tag) in rows.iter_mut().zip(tags) {
            row.push(tag);
        }
    }
    let mut output_tags = tagged.then(Vec::new);
    let routed = route_permutation_network(b, rows, &permutation)
        .into_iter()
        .map(|mut row| {
            if let Some(tags) = &mut output_tags {
                tags.push(row.pop().expect("routed native group tag"));
            }
            group_from_lanes(row)
        })
        .collect::<Vec<_>>();

    for pair in routed.windows(2) {
        let dead_then_live = mul(b, &pair[1].live, &pair[0].live.add_const(F128::ONE));
        pin_zero(b, &dead_then_live);
    }
    let end_bits = routed
        .iter()
        .map(|group| range_check_bits(b, &group.end_page, 32))
        .collect::<Vec<_>>();
    for (groups, bits) in routed.windows(2).zip(end_bits.windows(2)) {
        let both_live = mul(b, &groups[0].live, &groups[1].live);
        let (less, _) = strict_less_bits(b, &bits[0], &bits[1]);
        let violation = mul(b, &both_live, &less.add_const(F128::ONE));
        pin_zero(b, &violation);
    }
    (routed, output_tags)
}

fn sum_live_prefix(b: &mut FieldR1csBuilder, groups: &[PagedSpendGroupTrace]) -> LinExpr {
    groups.iter().fold(LinExpr::zero(), |sum, group| {
        integer_add_no_overflow(b, &sum, &group.live, 9)
    })
}

fn native_remaining_counts(
    b: &FieldR1csBuilder,
    surfaces: &[ActionSurfaceTrace],
    page_live: &[LinExpr],
) -> Vec<u8> {
    let mut remaining = vec![0u8; surfaces.len()];
    let mut cursor = 0usize;
    while cursor < surfaces.len() && native_bool(b, &page_live[cursor]) {
        assert!(native_bool(b, &surfaces[cursor].start));
        let end = (cursor..surfaces.len())
            .find(|&index| native_bool(b, &surfaces[index].end))
            .expect("native-validated PagedSpend group has END");
        let count = end - cursor + 1;
        assert!(count <= noid_tx::MAX_PAGED_SPEND_PAGES);
        for index in cursor..=end {
            remaining[index] = u8::try_from(end - index + 1).unwrap();
        }
        cursor = end + 1;
    }
    remaining
}

/// Prove and compact one class-sized physical page stream.
pub fn bind_paged_spend_stream(
    b: &mut FieldR1csBuilder,
    spines: &[SpineInputsTrace],
    page_hashes: &[[LinExpr; 2]],
    page_live: &[LinExpr],
    surfaces: &[ActionSurfaceTrace],
    arithmetic: &[UserPublicArithmeticTrace],
) -> PagedSpendBlockTrace {
    bind_paged_spend_stream_inner(
        b,
        spines,
        page_hashes,
        page_live,
        surfaces,
        arithmetic,
        false,
        false,
    )
    .0
}

pub fn bind_paged_spend_stream_v2_1(
    b: &mut FieldR1csBuilder,
    spines: &[SpineInputsTrace],
    page_hashes: &[[LinExpr; 2]],
    page_live: &[LinExpr],
    surfaces: &[ActionSurfaceTrace],
    arithmetic: &[UserPublicArithmeticTrace],
) -> PagedSpendBlockTrace {
    bind_paged_spend_stream_inner(
        b,
        spines,
        page_hashes,
        page_live,
        surfaces,
        arithmetic,
        true,
        false,
    )
    .0
}

/// Preserve every logical operation in the transaction/fee stream and retain
/// ordinary and existing contract groups in the authorization layout.
/// Public native groups are selected by their exact type tag and zero authority;
/// the complete financial header relation binds the finite operation roles.
pub fn bind_financial_paged_spend_stream(
    b: &mut FieldR1csBuilder,
    spines: &[SpineInputsTrace],
    page_hashes: &[[LinExpr; 2]],
    page_live: &[LinExpr],
    surfaces: &[ActionSurfaceTrace],
    arithmetic: &[UserPublicArithmeticTrace],
) -> FinancialPagedSpendBlockTrace {
    let (stream, native_groups) = bind_paged_spend_stream_inner(
        b,
        spines,
        page_hashes,
        page_live,
        surfaces,
        arithmetic,
        true,
        true,
    );
    let native_groups = native_groups.expect("financial native group tags");
    let candidates = stream
        .groups
        .iter()
        .take(spines.len())
        .zip(&native_groups)
        .map(|(group, native)| {
            let zero_0 = is_zero(b, &group.input_owner[0]);
            let zero_1 = is_zero(b, &group.input_owner[1]);
            let zero = mul(b, &zero_0, &zero_1);
            let public_native = mul(b, native, &zero);
            let live = mul(b, &group.live, &public_native.add_const(F128::ONE));
            let mut lanes = vec![live.clone()];
            lanes.extend(
                group_lanes(group.clone())
                    .into_iter()
                    .skip(1)
                    .map(|v| mul(b, &live, &v)),
            );
            group_from_lanes(lanes)
        })
        .collect();
    let authorizations = compact_end_records(b, candidates);
    let authorization_count = sum_live_prefix(b, &authorizations[..spines.len()]);
    FinancialPagedSpendBlockTrace {
        stream,
        native_groups,
        authorizations,
        authorization_count,
    }
}

fn bind_paged_spend_stream_inner(
    b: &mut FieldR1csBuilder,
    spines: &[SpineInputsTrace],
    page_hashes: &[[LinExpr; 2]],
    page_live: &[LinExpr],
    surfaces: &[ActionSurfaceTrace],
    arithmetic: &[UserPublicArithmeticTrace],
    native_pages: bool,
    financial: bool,
) -> (PagedSpendBlockTrace, Option<Vec<LinExpr>>) {
    let tier = spines.len();
    assert!(crate::region_sidecar::selected_zk_block_geometry(tier).is_some());
    assert_eq!(page_hashes.len(), tier);
    assert_eq!(page_live.len(), tier);
    assert_eq!(surfaces.len(), tier);
    assert_eq!(arithmetic.len(), tier);

    let remaining_native = native_remaining_counts(b, surfaces, page_live);
    let cap = const_block(Block128::from((noid_tx::MAX_PAGED_SPEND_PAGES + 1) as u128));
    let cap_bits = range_check_bits(b, &cap, PAGE_COUNT_BITS);

    let [iv0, iv1] = capacity_iv(TAG_PAGED_SPEND);
    let version = const_block(Block128::from(noid_tx::PAGED_SPEND_VERSION as u128));
    let pad = [
        const_block(Block128::from(0x80u128)),
        const_block(Block128::from(1u128 << 120)),
    ];

    let mut previous_remaining = LinExpr::zero();
    let mut previous_state = [
        LinExpr::zero(),
        LinExpr::zero(),
        LinExpr::zero(),
        LinExpr::zero(),
    ];
    let mut previous_owner = [LinExpr::zero(), LinExpr::zero()];
    let mut previous_epoch = [LinExpr::zero(), LinExpr::zero()];
    let mut previous_input_count = LinExpr::zero();
    let mut previous_output_count = LinExpr::zero();
    let mut previous_input_sum = LinExpr::zero();
    let mut previous_output_sum = LinExpr::zero();
    let mut previous_fee = LinExpr::zero();
    let mut candidates = Vec::with_capacity(tier);
    let mut previous_native = LinExpr::zero();
    let mut previous_header_page = LinExpr::zero();
    let mut previous_native_fields: [LinExpr; 6] = std::array::from_fn(|_| LinExpr::zero());
    let mut native_contexts = Vec::new();
    let mut native_group_count = LinExpr::zero();
    let mut native_end_tags = Vec::new();

    for index in 0..tier {
        let live = &page_live[index];
        let surface = &surfaces[index];
        let page = &arithmetic[index];
        let remaining = alloc_block(b, Block128::from(remaining_native[index] as u128));
        let remaining_bits = range_check_bits(b, &remaining, PAGE_COUNT_BITS);
        pin_lt_strict(b, &remaining_bits, &cap_bits);
        let dead_remaining = mul(b, &live.add_const(F128::ONE), &remaining);
        pin_zero(b, &dead_remaining);

        let expected_start = if index == 0 {
            live.clone()
        } else {
            mul(b, live, &surfaces[index - 1].end)
        };
        pin_eq(b, &surface.start, &expected_start);
        let next_live = page_live
            .get(index + 1)
            .cloned()
            .unwrap_or_else(LinExpr::zero);
        let last_live = mul(b, live, &next_live.add_const(F128::ONE));
        let missing_end = mul(b, &last_live, &surface.end.add_const(F128::ONE));
        pin_zero(b, &missing_end);
        let end_remaining = mul(b, &surface.end, &remaining.add_const(F128::ONE));
        pin_zero(b, &end_remaining);

        let continuation = mul(b, live, &surface.start.add_const(F128::ONE));
        let incremented = increment_from_bits(b, &remaining_bits);
        let bad_countdown = mul(b, &continuation, &previous_remaining.add(&incremented));
        pin_zero(b, &bad_countdown);
        let ordinary_continuation = if native_pages {
            let wrong_type = mul(b, &continuation, &surface.native.add(&previous_native));
            pin_zero(b, &wrong_type);
            mul(b, &continuation, &surface.native.add_const(F128::ONE))
        } else {
            continuation.clone()
        };
        for lane in 0..2 {
            let owner_delta =
                spines[index].leaves[LEAF_INPUT_OWNER][lane].add(&previous_owner[lane]);
            let bad_owner = mul(b, &ordinary_continuation, &owner_delta);
            pin_zero(b, &bad_owner);
            let epoch_delta =
                spines[index].leaves[LEAF_EPOCH_ANCHOR][lane].add(&previous_epoch[lane]);
            let bad_epoch = mul(b, &continuation, &epoch_delta);
            pin_zero(b, &bad_epoch);
        }
        let continuation_fee = mul(b, &continuation, &page.fee.value);
        pin_zero(b, &continuation_fee);

        prefix_bits(b, &surface.raw_inputs);
        prefix_bits(b, &surface.raw_outputs);
        if index != 0 {
            let crosses_input_gap = mul(
                b,
                &surface.raw_inputs[0],
                &surfaces[index - 1].raw_inputs[noid_tx::TX_INPUTS - 1].add_const(F128::ONE),
            );
            let sparse_input = mul(b, &ordinary_continuation, &crosses_input_gap);
            pin_zero(b, &sparse_input);
            let crosses_output_gap = mul(
                b,
                &surface.raw_outputs[0],
                &surfaces[index - 1].raw_outputs[noid_tx::TX_OUTPUTS - 1].add_const(F128::ONE),
            );
            let output_continuation = if native_pages {
                mul(
                    b,
                    &continuation,
                    &surfaces[index - 1].native_header.add_const(F128::ONE),
                )
            } else {
                continuation.clone()
            };
            let sparse_output = mul(b, &output_continuation, &crosses_output_gap);
            pin_zero(b, &sparse_output);
            if native_pages {
                let continues_native_data = mul(b, &output_continuation, &surface.native);
                let previous_input_empty = surfaces[index - 1].raw_inputs[0].add_const(F128::ONE);
                let crosses_empty_input = mul(b, &surface.raw_inputs[0], &previous_input_empty);
                let sparse_native_input = mul(b, &continues_native_data, &crosses_empty_input);
                pin_zero(b, &sparse_native_input);
            }
        }
        let needs_next = mul(b, live, &surface.end.add_const(F128::ONE));
        let no_full_input = surface.raw_inputs[noid_tx::TX_INPUTS - 1].add_const(F128::ONE);
        let no_full_output = surface.raw_outputs[noid_tx::TX_OUTPUTS - 1].add_const(F128::ONE);
        let neither_dimension_full = mul(b, &no_full_input, &no_full_output);
        let ordinary_needs_next = if native_pages {
            mul(b, &needs_next, &surface.native.add_const(F128::ONE))
        } else {
            needs_next.clone()
        };
        let redundant_page = mul(b, &ordinary_needs_next, &neither_dimension_full);
        pin_zero(b, &redundant_page);

        let mut logical_owner = spines[index].leaves[LEAF_INPUT_OWNER].clone();
        if native_pages {
            let native_live = mul(b, live, &surface.native);
            let header_live = mul(b, live, &surface.native_header);
            let native_data = mul(b, live, &surface.native.add(&surface.native_header));
            let no_inputs = surface.raw_inputs[0].add_const(F128::ONE);
            let no_outputs = surface.raw_outputs[0].add_const(F128::ONE);
            let empty = mul(b, &no_inputs, &no_outputs);
            let empty_data = mul(b, &native_data, &empty);
            pin_zero(b, &empty_data);
            let zero_owner_0 = is_zero(b, &logical_owner[0]);
            let zero_owner_1 = is_zero(b, &logical_owner[1]);
            let zero_owner = mul(b, &zero_owner_0, &zero_owner_1);
            if !financial {
                let bad_header_owner = mul(b, &header_live, &zero_owner);
                pin_zero(b, &bad_header_owner);
            }
            let wrong_data_owner = mul(b, &native_data, &zero_owner.add(&no_inputs));
            pin_zero(b, &wrong_data_owner);
            logical_owner = std::array::from_fn(|lane| {
                let carried = mux(
                    b,
                    &surface.start,
                    &logical_owner[lane],
                    &previous_owner[lane],
                );
                mul(b, live, &carried)
            });
            let header_page = mux(
                b,
                &surface.start,
                &selected_index(&header_live, index + 1),
                &previous_header_page,
            );
            let header_page = mul(b, &native_live, &header_page);
            let raw = [
                spines[index].leaves[super::action_surface::LEAF_OUTPUT0_OWNER][0].clone(),
                spines[index].leaves[super::action_surface::LEAF_OUTPUT0_OWNER][1].clone(),
                spines[index].leaves[super::action_surface::LEAF_OUTPUT0_DATA][1].clone(),
                spines[index].leaves[super::action_surface::LEAF_OUTPUT1_DATA][1].clone(),
                spines[index].leaves[super::action_surface::LEAF_OUTPUT1_OWNER][0].clone(),
                spines[index].leaves[super::action_surface::LEAF_OUTPUT1_OWNER][1].clone(),
            ];
            let carried: [LinExpr; 6] = std::array::from_fn(|lane| {
                let raw = mul(b, &surface.native_header, &raw[lane]);
                let value = mux(b, &surface.start, &raw, &previous_native_fields[lane]);
                mul(b, &native_live, &value)
            });
            native_contexts.push(NativePageContextTrace {
                live: native_live.clone(),
                header_page: header_page.clone(),
                authority: std::array::from_fn(|lane| mul(b, &native_live, &logical_owner[lane])),
                chain: [carried[0].clone(), carried[1].clone()],
                operation: carried[2].clone(),
                funding_input: carried[3].clone(),
                asset: [carried[4].clone(), carried[5].clone()],
                input_offset: {
                    let continued = mul(
                        b,
                        &surface.start.add_const(F128::ONE),
                        &previous_input_count,
                    );
                    mul(b, &native_live, &continued)
                },
                output_offset: {
                    let continued = mul(
                        b,
                        &surface.start.add_const(F128::ONE),
                        &previous_output_count,
                    );
                    mul(b, &native_live, &continued)
                },
                end_live: LinExpr::zero(),
                logical_txid: [LinExpr::zero(), LinExpr::zero()],
                input_count: LinExpr::zero(),
                output_count: LinExpr::zero(),
                fee: LinExpr::zero(),
            });
            native_group_count = integer_add_no_overflow(b, &native_group_count, &header_live, 9);
            previous_header_page = header_page;
            previous_native_fields = carried;
            previous_native = native_live;
        }

        let input_count = rolling_sum(
            b,
            &previous_input_count,
            &page.live_input_count,
            &surface.start,
            live,
            COUNT_BITS,
        );
        let output_count = rolling_sum(
            b,
            &previous_output_count,
            &page.live_output_count,
            &surface.start,
            live,
            OUTPUT_COUNT_BITS,
        );
        let input_sum = rolling_sum(
            b,
            &previous_input_sum,
            &page.input_sum,
            &surface.start,
            live,
            MONEY_BITS,
        );
        let output_sum = rolling_sum(
            b,
            &previous_output_sum,
            &page.output_sum,
            &surface.start,
            live,
            MONEY_BITS,
        );
        let grouped_fee = mux(b, &surface.start, &page.paid_fee, &previous_fee);
        let fee = mul(b, live, &grouped_fee);
        let input_count_bits = range_check_bits(b, &input_count, COUNT_BITS);
        nonzero_when(b, &surface.end, &input_count_bits);
        let output_plus_fee = integer_add_no_overflow(b, &output_sum, &fee, MONEY_BITS);
        let bad_balance = mul(b, &surface.end, &input_sum.add(&output_plus_fee));
        pin_zero(b, &bad_balance);

        let mut initial = [
            version.clone(),
            remaining.clone(),
            const_block(iv0),
            const_block(iv1),
        ];
        initial = poseidon2b_permute(b, initial);
        let mut state: [LinExpr; 4] = std::array::from_fn(|lane| {
            mux(b, &surface.start, &initial[lane], &previous_state[lane])
        });
        state[0] = state[0].add(&page_hashes[index][0]);
        state[1] = state[1].add(&page_hashes[index][1]);
        state = poseidon2b_permute(b, state);
        state = std::array::from_fn(|lane| mul(b, live, &state[lane]));
        let mut finalized = state.clone();
        finalized[0] = finalized[0].add(&pad[0]);
        finalized[1] = finalized[1].add(&pad[1]);
        finalized = poseidon2b_permute(b, finalized);

        let end_live = mul(b, live, &surface.end);
        if native_pages {
            let context = native_contexts.last_mut().expect("native page context");
            context.end_live = mul(b, &context.live, &surface.end);
            context.logical_txid =
                std::array::from_fn(|lane| mul(b, &context.end_live, &finalized[lane]));
            context.input_count = mul(b, &context.end_live, &input_count);
            context.output_count = mul(b, &context.end_live, &output_count);
            context.fee = mul(b, &context.end_live, &fee);
            if financial {
                native_end_tags.push(context.end_live.clone());
            }
        }
        candidates.push(PagedSpendGroupTrace {
            live: end_live.clone(),
            logical_txid: std::array::from_fn(|lane| mul(b, &end_live, &finalized[lane])),
            input_owner: std::array::from_fn(|lane| mul(b, &end_live, &logical_owner[lane])),
            fee: mul(b, &end_live, &fee),
            live_input_count: mul(b, &end_live, &input_count),
            live_output_count: mul(b, &end_live, &output_count),
            end_page: selected_index(&end_live, index + 1),
        });

        previous_remaining = remaining;
        previous_state = state;
        previous_owner = logical_owner;
        previous_epoch = spines[index].leaves[LEAF_EPOCH_ANCHOR].clone();
        previous_input_count = input_count;
        previous_output_count = output_count;
        previous_input_sum = input_sum;
        previous_output_sum = output_sum;
        previous_fee = fee;
    }

    let (groups, native_groups) = if financial {
        compact_tagged_end_records(b, candidates, Some(native_end_tags))
    } else {
        (compact_end_records(b, candidates), None)
    };
    assert_eq!(groups.len(), (tier + 1).next_power_of_two());
    for group in &groups[tier..] {
        pin_zero(b, &group.live);
    }
    let logical_count = sum_live_prefix(b, &groups[..tier]);
    (
        PagedSpendBlockTrace {
            groups,
            logical_count,
            native_pages: native_contexts,
            native_group_count,
        },
        native_groups,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_ivc_core::field_r1cs::FieldR1cs;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        hash_paged_spend, output_bitmap_bit, TxBody, TxInput, TxOutput, TxPage,
        PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT, TX_INPUTS, TX_OUTPUTS,
    };

    fn pages() -> Vec<TxPage> {
        let owner = Address([0x33; 32]);
        let mut first_inputs = [TxInput::dummy(); TX_INPUTS];
        for (index, input) in first_inputs.iter_mut().enumerate() {
            *input = TxInput {
                slot_index: index as u32 + 1,
                amount: 100,
                creation_id: index as u64 + 10,
            };
        }
        let mut first_outputs = [TxOutput::dummy(); TX_OUTPUTS];
        first_outputs[0] = TxOutput {
            slot_index: 100,
            amount: 893,
            owner: Address([0x55; 32]),
        };
        let first = TxPage {
            body: TxBody {
                epoch_anchor: [0x44; 32],
                fee: 7,
                input_owner: owner,
                inputs: first_inputs,
                outputs: first_outputs,
                validity_bitmap: 0x00ff | output_bitmap_bit(0) | PAGED_SPEND_START_BIT,
                is_coinbase: false,
            },
        };
        let mut second_inputs = [TxInput::dummy(); TX_INPUTS];
        second_inputs[0] = TxInput {
            slot_index: 9,
            amount: 100,
            creation_id: 18,
        };
        let second = TxPage {
            body: TxBody {
                epoch_anchor: [0x44; 32],
                fee: 0,
                input_owner: owner,
                inputs: second_inputs,
                outputs: [TxOutput::dummy(); TX_OUTPUTS],
                validity_bitmap: 1 | PAGED_SPEND_END_BIT,
                is_coinbase: false,
            },
        };
        vec![first, second]
    }

    fn one_page() -> TxPage {
        let mut page = pages().remove(0);
        page.body.outputs[0].amount = 793;
        page.body.validity_bitmap |= PAGED_SPEND_END_BIT;
        page
    }

    fn build(
        pages: &[TxPage],
    ) -> (
        FieldR1cs,
        Vec<F128>,
        PagedSpendBlockTrace,
        Vec<ActionSurfaceTrace>,
    ) {
        let tier = 25usize;
        let ghost = noid_gkr::ghost_tx::ghost_tx_body();
        let mut bodies = pages
            .iter()
            .map(|page| page.body.clone())
            .collect::<Vec<_>>();
        bodies.resize(tier, ghost);
        let mut b = FieldR1csBuilder::new();
        let spines = bodies
            .iter()
            .map(|body| {
                SpineInputsTrace::alloc(
                    &mut b,
                    &noid_gkr::spine_statement::spine_inputs_from_body(body),
                )
            })
            .collect::<Vec<_>>();
        let hashes = bodies
            .iter()
            .map(|body| {
                body.txid()
                    .as_fields()
                    .map(|lane| alloc_block(&mut b, lane))
            })
            .collect::<Vec<_>>();
        let live = (0..tier)
            .map(|index| LinExpr::from_wire(b.alloc_bool(index < pages.len())))
            .collect::<Vec<_>>();
        let mut surfaces = Vec::with_capacity(tier);
        let mut arithmetic = Vec::with_capacity(tier);
        for index in 0..tier {
            let surface = super::super::action_surface::bind_user_action_surface(
                &mut b,
                &spines[index],
                &live[index],
            );
            let page = super::super::public_arithmetic::bind_user_public_arithmetic(
                &mut b,
                &spines[index],
                &surface,
            );
            surfaces.push(surface);
            arithmetic.push(page);
        }
        let trace =
            bind_paged_spend_stream(&mut b, &spines, &hashes, &live, &surfaces, &arithmetic);
        let (matrix, witness) = b.build();
        (matrix, witness, trace, surfaces)
    }

    fn digest_from_trace(witness: &[F128], digest: &[LinExpr; 2]) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for lane in 0..2 {
            let value = tower_value_from_witness(witness, &digest[lane]);
            bytes[lane * 16..(lane + 1) * 16].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    fn tower_value_from_witness(witness: &[F128], expression: &LinExpr) -> u128 {
        let flat = expression.eval(witness);
        flat_to_tower_u128(u128::from(flat.lo) | (u128::from(flat.hi) << 64))
    }

    #[test]
    fn two_pages_compact_to_one_native_logical_hash() {
        let pages = pages();
        let expected = hash_paged_spend(&pages).unwrap().0;
        let (matrix, witness, trace, _) = build(&pages);
        assert!(matrix.satisfies(&witness));
        assert_eq!(tower_value_from_witness(&witness, &trace.logical_count), 1);
        assert_eq!(
            digest_from_trace(&witness, &trace.groups[0].logical_txid),
            expected
        );
        assert_eq!(
            tower_value_from_witness(&witness, &trace.groups[0].live_input_count),
            9
        );
        assert_eq!(
            tower_value_from_witness(&witness, &trace.groups[0].live_output_count),
            1
        );
        assert!(trace.groups[1..]
            .iter()
            .all(|group| group.live.eval(&witness) == F128::ZERO));
    }

    #[test]
    fn group_owner_fee_and_balance_tampering_are_unsatisfied() {
        let honest = pages();
        let (matrix, witness, _, _) = build(&honest);
        assert!(matrix.satisfies(&witness));

        let mut owner = honest.clone();
        owner[1].body.input_owner = Address([0x99; 32]);
        let (owner_matrix, owner_witness, _, _) = build(&owner);
        assert!(!owner_matrix.satisfies(&owner_witness));

        let mut epoch = honest.clone();
        epoch[1].body.epoch_anchor = [0x98; 32];
        let (epoch_matrix, epoch_witness, _, _) = build(&epoch);
        assert!(!epoch_matrix.satisfies(&epoch_witness));

        let mut fee = honest.clone();
        fee[1].body.fee = 1;
        let (fee_matrix, fee_witness, _, _) = build(&fee);
        assert!(!fee_matrix.satisfies(&fee_witness));

        let mut inflation = honest;
        inflation[0].body.outputs[0].amount += 1;
        let (inflation_matrix, inflation_witness, _, _) = build(&inflation);
        assert!(!inflation_matrix.satisfies(&inflation_witness));
    }

    #[test]
    fn marker_mutation_and_redundant_page_are_unsatisfied() {
        let honest = pages();
        let (matrix, witness, _, surfaces) = build(&honest);
        assert!(matrix.satisfies(&witness));
        let start_wire = surfaces[0].start.terms[0].0 as usize;
        let mut missing_start = witness;
        missing_start[start_wire] += F128::ONE;
        assert!(!matrix.satisfies(&missing_start));

        let mut redundant = pages();
        redundant[1].body.validity_bitmap &= !PAGED_SPEND_END_BIT;
        let mut third = redundant[1].clone();
        third.body.inputs = [TxInput::dummy(); TX_INPUTS];
        third.body.validity_bitmap = PAGED_SPEND_END_BIT;
        redundant.push(third);
        let (redundant_matrix, redundant_witness, _, _) = build(&redundant);
        assert!(!redundant_matrix.satisfies(&redundant_witness));
    }

    #[test]
    fn matrix_is_invariant_across_group_partition_and_values() {
        let one = one_page();
        let mut second = one.clone();
        second.body.epoch_anchor = [0x66; 32];
        second.body.inputs[0].slot_index = 777;
        second.body.outputs[0].slot_index = 888;

        let (one_group, one_witness, one_trace, _) = build(&pages());
        let (two_groups, two_witness, two_trace, _) = build(&[one, second]);
        assert!(one_group.satisfies(&one_witness));
        assert!(two_groups.satisfies(&two_witness));
        assert_eq!(
            tower_value_from_witness(&one_witness, &one_trace.logical_count),
            1
        );
        assert_eq!(
            tower_value_from_witness(&two_witness, &two_trace.logical_count),
            2
        );
        assert_eq!(one_group.useful_rows, two_groups.useful_rows);
        assert_eq!(one_group.statement_digest(), two_groups.statement_digest());
    }
}
