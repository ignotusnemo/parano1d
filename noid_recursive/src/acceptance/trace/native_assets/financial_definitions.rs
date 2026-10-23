// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared content-addressed definitions for native financial transitions.

use noid_core::{hardware::flat_to_tower_u128, Block128};
use noid_poseidon2b::native::capacity_iv;
use noid_tx::native_assets::{
    launch::{LAUNCH_MAX_SUPPLY, LAUNCH_MIN_WHOLE_TOKENS, LAUNCH_PROFILE},
    market::{MARKET_PROFILE, MARKET_QUANTITY_MAX},
    nft_market::NFT_FEE_CREDIT,
    NativeKind, NativeOpening, TOKEN_UNITS,
};

use super::super::{
    alloc_block, flat_const, flat_of, mul, pin_eq, pin_zero, poseidon2b_permute, FieldR1csBuilder,
    LinExpr, F128,
};
use super::arithmetic::range_check_bits;
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_reads::FinancialParentReadTrace;
use super::header::FinancialNativeHeaderTrace;
use super::validation::{is_zero, nonzero_pair, require_nonzero};

pub struct FinancialDefinitionTrace {
    pub live: LinExpr,
    pub market: LinExpr,
    pub launch: LinExpr,
    pub listing: LinExpr,
    pub fields: [LinExpr; 8],
    pub root: [LinExpr; 2],
    pub base_is_noid: LinExpr,
}

pub struct FinancialDefinitionQueryTrace {
    pub market: LinExpr,
    pub launch: LinExpr,
    pub listing: LinExpr,
    pub root: [LinExpr; 2],
}

pub struct SelectedFinancialDefinitionTrace {
    pub market: LinExpr,
    pub launch: LinExpr,
    pub listing: LinExpr,
    pub root: [LinExpr; 2],
    pub fields: [LinExpr; 8],
    pub base_is_noid: LinExpr,
}

pub struct FinancialDefinitionsTrace {
    pub table: Vec<FinancialDefinitionTrace>,
    pub headers: Vec<SelectedFinancialDefinitionTrace>,
    pub reads: Vec<SelectedFinancialDefinitionTrace>,
    pub actions: Vec<SelectedFinancialDefinitionTrace>,
}

fn tower(b: &FieldR1csBuilder, value: &LinExpr) -> u128 {
    let v = value.eval(b.values());
    flat_to_tower_u128(u128::from(v.lo) | (u128::from(v.hi) << 64))
}

pub(super) fn constant_bits(value: u128, width: usize) -> Vec<LinExpr> {
    (0..width)
        .map(|i| LinExpr::constant(flat_const((value >> i) & 1)))
        .collect()
}

pub(super) fn value_bits(b: &mut FieldR1csBuilder, value: &LinExpr, width: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, value, width)
}

/// Fixed integer multiplication by a public constant, with zero overflow.
pub(super) fn scale_bits(
    b: &mut FieldR1csBuilder,
    bits: &[LinExpr],
    factor: u64,
    width: usize,
) -> Vec<LinExpr> {
    let mut result = vec![LinExpr::zero(); width];
    for shift in 0..64 {
        if (factor >> shift) & 1 == 0 {
            continue;
        }
        let mut term = vec![LinExpr::zero(); width];
        for (index, bit) in bits.iter().enumerate() {
            if index + shift < width {
                term[index + shift] = bit.clone();
            } else {
                pin_zero(b, bit);
            }
        }
        result = checked_add(b, &result, &term);
    }
    result
}

/// Native identifiers compare as byte strings. Little-endian integer bit
/// comparisons therefore visit the last byte first, preserving bit order
/// inside each byte.
fn digest_order_bits(b: &mut FieldR1csBuilder, pair: &[LinExpr; 2]) -> Vec<LinExpr> {
    let raw = pair
        .iter()
        .flat_map(|v| value_bits(b, v, 128))
        .collect::<Vec<_>>();
    (0..32)
        .rev()
        .flat_map(|byte| raw[8 * byte..8 * byte + 8].iter().cloned())
        .collect()
}

/// Fixed whole-token launch supply shared by definitions and typed carriers.
pub(super) fn bind_launch_supply(
    b: &mut FieldR1csBuilder,
    live: &LinExpr,
    units: &LinExpr,
    unit_bits: &[LinExpr],
) {
    assert_eq!(unit_bits.len(), 64);
    let too_large = less_than(
        b,
        &constant_bits(u128::from(LAUNCH_MAX_SUPPLY), 64),
        unit_bits,
    );
    pin_zero(b, &too_large);
    let quotient = alloc_block(b, Block128(tower(b, units) / u128::from(TOKEN_UNITS)));
    let quotient = value_bits(b, &quotient, 34);
    let below_minimum = less_than(
        b,
        &quotient,
        &constant_bits(u128::from(LAUNCH_MIN_WHOLE_TOKENS), 34),
    );
    let invalid = mul(b, live, &below_minimum);
    pin_zero(b, &invalid);
    let exact = scale_bits(b, &quotient, TOKEN_UNITS, 64);
    pin_eq(b, &pack(&exact), units);
}

/// All three definitions use exactly eight fields and four sponge rounds.
/// Their native validation is fixed by the selected definition kind.
pub fn bind_financial_definition(
    b: &mut FieldR1csBuilder,
    kind: &LinExpr,
    fields: &[LinExpr; 8],
) -> FinancialDefinitionTrace {
    range_check_bits(b, kind, 7);
    let inactive = is_zero(b, kind);
    let market = is_zero(
        b,
        &kind.add_const(flat_const(NativeKind::MarketDefinition as u128)),
    );
    let launch = is_zero(
        b,
        &kind.add_const(flat_const(NativeKind::LaunchDefinition as u128)),
    );
    let listing = is_zero(
        b,
        &kind.add_const(flat_const(NativeKind::NftListingDefinition as u128)),
    );
    let live = market.add(&launch).add(&listing);
    pin_eq(b, &inactive.add(&live), &LinExpr::constant(F128::ONE));
    for field in fields {
        let padding = mul(b, &inactive, field);
        pin_zero(b, &padding);
    }
    nonzero_pair(b, &[fields[0].clone(), fields[1].clone()], &live);
    nonzero_pair(
        b,
        &[fields[2].clone(), fields[3].clone()],
        &launch.add(&listing),
    );
    nonzero_pair(b, &[fields[5].clone(), fields[6].clone()], &launch);
    let padding = mul(b, &market.add(&launch), &fields[7]);
    pin_zero(b, &padding);
    let bad_profile = mul(
        b,
        &market,
        &fields[6].add_const(flat_const(u128::from(MARKET_PROFILE))),
    );
    pin_zero(b, &bad_profile);
    let base = [mul(b, &market, &fields[2]), mul(b, &market, &fields[3])];
    let quote = [mul(b, &market, &fields[4]), mul(b, &market, &fields[5])];
    pin_zero(b, &base[0]);
    pin_zero(b, &base[1]);
    nonzero_pair(b, &quote, &market);
    let base_is_noid = market.clone();

    let supply = mul(b, &launch, &fields[4]);
    let supply = split_packed_input_value(b, &supply);
    pin_eq(
        b,
        &supply.creation_id.value,
        &launch.scale(flat_const(u128::from(LAUNCH_PROFILE))),
    );
    let supply_bits = supply
        .amount
        .bits
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    bind_launch_supply(b, &launch, &supply.amount.value, &supply_bits);

    let serial = mul(b, &listing, &fields[6]);
    let serial = split_packed_input_value(b, &serial);
    require_nonzero(b, &serial.amount.value, &listing);
    pin_eq(
        b,
        &LinExpr::from_wire(serial.creation_id.bits[62]),
        &listing,
    );
    pin_zero(b, &LinExpr::from_wire(serial.creation_id.bits[63]));
    let sequence = serial.creation_id.bits[..62]
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    require_nonzero(b, &pack(&sequence), &listing);
    let price = mul(b, &listing, &fields[7]);
    let price = split_packed_input_value(b, &price);
    require_nonzero(b, &price.amount.value, &listing);
    require_nonzero(b, &price.creation_id.value, &listing);
    let ask = price
        .amount
        .bits
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let max_ask = MARKET_QUANTITY_MAX - 2 * NFT_FEE_CREDIT;
    let too_expensive = less_than(b, &constant_bits(u128::from(max_ask), 64), &ask);
    pin_zero(b, &too_expensive);

    let mut iv = [LinExpr::zero(), LinExpr::zero()];
    for (kind, selected) in [
        (NativeKind::MarketDefinition, &market),
        (NativeKind::LaunchDefinition, &launch),
        (NativeKind::NftListingDefinition, &listing),
    ] {
        let constants = capacity_iv(kind.tag());
        for lane in 0..2 {
            iv[lane] = iv[lane].add(&selected.scale(flat_of(constants[lane])));
        }
    }
    let mut state = [
        LinExpr::zero(),
        LinExpr::zero(),
        iv[0].clone(),
        iv[1].clone(),
    ];
    for pair in fields.chunks_exact(2) {
        state[0] = state[0].add(&pair[0]);
        state[1] = state[1].add(&pair[1]);
        state = poseidon2b_permute(b, state);
    }
    let root = [mul(b, &live, &state[0]), mul(b, &live, &state[1])];
    FinancialDefinitionTrace {
        live,
        market,
        launch,
        listing,
        fields: fields.clone(),
        root,
        base_is_noid,
    }
}

/// Bind a unique, root-sorted live prefix of shared auxiliary definitions.
pub fn bind_financial_definition_table(
    b: &mut FieldR1csBuilder,
    capacity: usize,
    witness: &[NativeOpening],
) -> Vec<FinancialDefinitionTrace> {
    assert!(capacity > 0 && witness.len() <= capacity);
    let mut result = Vec::with_capacity(capacity);
    let mut previous: Option<(LinExpr, Vec<LinExpr>)> = None;
    for index in 0..capacity {
        let value = witness.get(index);
        let kind = alloc_block(b, Block128(value.map_or(0, |v| v.kind() as u128)));
        let fields: [LinExpr; 8] =
            std::array::from_fn(|i| alloc_block(b, value.map_or(Block128(0), |v| v.fields()[i])));
        let definition = bind_financial_definition(b, &kind, &fields);
        let key = digest_order_bits(b, &definition.root);
        if let Some((live, old_key)) = previous {
            let hole = mul(b, &definition.live, &live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let strict = less_than(b, &old_key, &key);
            let unordered = mul(b, &definition.live, &strict.add_const(F128::ONE));
            pin_zero(b, &unordered);
        }
        previous = Some((definition.live.clone(), key));
        result.push(definition);
    }
    result
}

/// Each query selects one exact definition. Every live table entry must be
/// referenced; inactive queries have zero roots and zero selected fields.
pub fn bind_financial_definition_queries(
    b: &mut FieldR1csBuilder,
    table: &[FinancialDefinitionTrace],
    queries: &[FinancialDefinitionQueryTrace],
) -> Vec<SelectedFinancialDefinitionTrace> {
    let mut used = vec![LinExpr::zero(); table.len()];
    let mut result = Vec::with_capacity(queries.len());
    for query in queries {
        let flags = [&query.market, &query.launch, &query.listing];
        for flag in flags {
            let invalid = mul(b, flag, &flag.add_const(F128::ONE));
            pin_zero(b, &invalid);
        }
        for first in 0..3 {
            for second in first + 1..3 {
                let overlap = mul(b, flags[first], flags[second]);
                pin_zero(b, &overlap);
            }
        }
        let required = query.market.add(&query.launch).add(&query.listing);
        nonzero_pair(b, &query.root, &required);
        for lane in &query.root {
            let inactive = mul(b, &required.add_const(F128::ONE), lane);
            pin_zero(b, &inactive);
        }
        let mut found = LinExpr::zero();
        let mut market = LinExpr::zero();
        let mut launch = LinExpr::zero();
        let mut listing = LinExpr::zero();
        let mut fields: [LinExpr; 8] = std::array::from_fn(|_| LinExpr::zero());
        let mut base_is_noid = LinExpr::zero();
        for (index, definition) in table.iter().enumerate() {
            let zero0 = is_zero(b, &query.root[0].add(&definition.root[0]));
            let zero1 = is_zero(b, &query.root[1].add(&definition.root[1]));
            let selected = mul(b, &zero0, &zero1);
            let selected = mul(b, &selected, &definition.live);
            let selected = mul(b, &selected, &required);
            found = found.add(&selected);
            let overlap = mul(b, &used[index], &selected);
            used[index] = used[index].add(&selected).add(&overlap);
            market = market.add(&mul(b, &selected, &definition.market));
            launch = launch.add(&mul(b, &selected, &definition.launch));
            listing = listing.add(&mul(b, &selected, &definition.listing));
            base_is_noid = base_is_noid.add(&mul(b, &selected, &definition.base_is_noid));
            for i in 0..8 {
                fields[i] = fields[i].add(&mul(b, &selected, &definition.fields[i]));
            }
        }
        pin_eq(b, &found, &required);
        pin_eq(b, &market, &query.market);
        pin_eq(b, &launch, &query.launch);
        pin_eq(b, &listing, &query.listing);
        result.push(SelectedFinancialDefinitionTrace {
            market,
            launch,
            listing,
            root: query.root.clone(),
            fields,
            base_is_noid,
        });
    }
    for (definition, used) in table.iter().zip(used) {
        pin_eq(b, &definition.live, &used);
    }
    result
}

fn action_query(
    b: &mut FieldR1csBuilder,
    action: &FinancialActionTrace,
) -> FinancialDefinitionQueryTrace {
    use NativeKind::*;
    let s = |kind| action.opening.commitment.selector(kind).clone();
    let market_first = s(MarketPool)
        .add(&s(MarketLiquidity))
        .add(&s(MarketLiquidityDeposit))
        .add(&s(MarketLiquidityWithdrawal))
        .add(&s(MarketLiquidityBurn));
    let market_second = s(MarketLiquidityClaim);
    let launch = s(LaunchState);
    let listing = s(NftListing);
    let first = market_first.add(&launch).add(&listing);
    let root = std::array::from_fn(|i| {
        let a = mul(b, &first, &action.opening.fields[i]);
        a.add(&mul(b, &market_second, &action.opening.fields[2 + i]))
    });
    FinancialDefinitionQueryTrace {
        market: market_first.add(&market_second),
        launch,
        listing,
        root,
    }
}

/// Match every header definition operand and every carrier dependency to the
/// same shared table. Per-operation and per-control relations consume the
/// selected fields for exact ownership, phase and financial transitions.
pub fn bind_financial_definitions(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    headers: &[FinancialNativeHeaderTrace],
    reads: &[FinancialParentReadTrace],
    capacity: usize,
    witness: &[NativeOpening],
) -> FinancialDefinitionsTrace {
    let table = bind_financial_definition_table(b, capacity, witness);
    let mut queries = headers
        .iter()
        .map(|header| {
            let selected = |code| {
                &header.metadata.financial[super::financial_operation::FINANCIAL_OPERATION_CODES
                    .iter()
                    .position(|&c| c == code)
                    .expect("financial code")]
            };
            FinancialDefinitionQueryTrace {
                market: selected(32)
                    .add(selected(37))
                    .add(selected(40))
                    .add(selected(42)),
                launch: selected(48).clone(),
                listing: selected(64).clone(),
                root: header.metadata.definition_root.clone(),
            }
        })
        .collect::<Vec<_>>();
    queries.extend(reads.iter().map(|read| FinancialDefinitionQueryTrace {
        market: read.market.clone(),
        launch: read.launch.clone(),
        listing: read.listing.clone(),
        root: [read.fields[0].clone(), read.fields[1].clone()],
    }));
    queries.extend(actions.iter().map(|action| action_query(b, action)));
    let mut selected = bind_financial_definition_queries(b, &table, &queries);
    let mut selected_reads = selected.split_off(headers.len());
    let selected_actions = selected_reads.split_off(reads.len());
    for (action, definition) in actions.iter().zip(&selected_actions) {
        bind_definition_link_fields(b, action, definition);
    }
    FinancialDefinitionsTrace {
        table,
        headers: selected,
        reads: selected_reads,
        actions: selected_actions,
    }
}

fn bind_definition_link_fields(
    b: &mut FieldR1csBuilder,
    action: &FinancialActionTrace,
    definition: &SelectedFinancialDefinitionTrace,
) {
    use NativeKind::*;
    let s = |kind| action.opening.commitment.selector(kind).clone();
    let flag_kinds = s(MarketPool)
        .add(&s(MarketLiquidityDeposit))
        .add(&s(MarketLiquidityClaim));
    let flags = mul(b, &flag_kinds, &action.opening.fields[7]);
    let flags = value_bits(b, &flags, 128);
    let pool = mul(b, &s(MarketPool), &flags[88]);
    let deposit = mul(b, &s(MarketLiquidityDeposit), &flags[63]);
    let claim = mul(b, &s(MarketLiquidityClaim), &flags[127]);
    let has_flag = s(MarketPool)
        .add(&s(MarketLiquidityDeposit))
        .add(&s(MarketLiquidityClaim));
    let expected_flag = mul(b, &has_flag, &definition.base_is_noid);
    pin_eq(b, &pool.add(&deposit).add(&claim), &expected_flag);
    let listing = s(NftListing);
    for lane in 0..2 {
        let different = mul(
            b,
            &listing,
            &action.opening.fields[2 + lane].add(&definition.fields[lane]),
        );
        pin_zero(b, &different);
    }
    let serial = mul(b, &listing, &action.opening.fields[4]);
    let serial = split_packed_input_value(b, &serial);
    let definition_serial = mul(b, &listing, &definition.fields[6]);
    let definition_serial = split_packed_input_value(b, &definition_serial);
    pin_eq(b, &serial.amount.value, &definition_serial.amount.value);
    let listing_meta = mul(b, &listing, &action.opening.fields[7]);
    let listing_meta = value_bits(b, &listing_meta, 81);
    let frozen = &listing_meta[80];
    let registered = listing_meta[..64]
        .iter()
        .map(|bit| mul(b, frozen, bit))
        .collect::<Vec<_>>();
    let mut increment = vec![LinExpr::zero(); 64];
    increment[0] = frozen.clone();
    let next_height = checked_add(b, &registered, &increment);
    let expiry = mul(b, &listing, &definition.fields[7]);
    let expiry = split_packed_input_value(b, &expiry);
    let expiry = expiry
        .creation_id
        .bits
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let before_expiry = less_than(b, &next_height, &expiry);
    let too_late = mul(b, frozen, &before_expiry.add_const(F128::ONE));
    pin_zero(b, &too_late);
}
