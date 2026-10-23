// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical Owner statements across physical groups and trade policies.

use super::super::super::paged_spend::PagedSpendGroupTrace;
use super::super::super::{
    alloc_block, flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128,
};
use super::super::actions::route_sorted;
use super::super::arithmetic::{bits, checked_add, less_than, pack};
use super::super::header::FinancialNativeHeaderTrace;
use super::super::validation::is_zero;
use super::kernel::TradeOwnerStatementTrace;
use super::{boolean, number, value};
use noid_core::Block128;
use noid_poseidon2b::primitives::Address;
use noid_tx::native_assets::trade::batch::TradeBatch;

pub struct TradeOwnerAdviceTrace {
    pub statements: Vec<TradeOwnerStatementTrace>,
}

fn pair_bytes(b: &FieldR1csBuilder, pair: &[LinExpr; 2]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for lane in 0..2 {
        bytes[16 * lane..16 * lane + 16].copy_from_slice(&value(b, &pair[lane]).to_le_bytes());
    }
    bytes
}

/// Allocate the early statement wires needed by the selected proof region.
/// The exact late native execution relation binds every returned field.
pub fn allocate_trade_owner_advice(
    b: &mut FieldR1csBuilder,
    capacity: usize,
    headers: &[FinancialNativeHeaderTrace],
    batches: &[TradeBatch],
) -> TradeOwnerAdviceTrace {
    assert!(
        (1..=noid_tx::native_assets::market::sequential::MAX_SEQUENTIAL_TRADES).contains(&capacity)
    );
    let mut hints = Vec::new();
    for header in headers {
        if value(b, &header.header.live) == 0 || value(b, &header.header.operation) != 80 {
            continue;
        }
        let root = Address(pair_bytes(b, &header.metadata.trade_root));
        if let Some(batch) = batches.iter().find(|batch| batch.root().ok() == Some(root)) {
            hints.extend(
                batch
                    .policies()
                    .iter()
                    .map(|p| (value(b, &header.header.header_page), p)),
            );
        }
    }
    let statements = (0..capacity)
        .map(|i| {
            let hint = hints.get(i);
            let live = alloc_block(b, Block128(u128::from(hint.is_some())));
            boolean(b, &live);
            let page = alloc_block(b, Block128(hint.map_or(0, |(page, _)| *page)));
            let index = alloc_block(b, Block128(hint.map_or(0, |_| i as u128)));
            let id = hint
                .and_then(|(_, p)| p.authorization_id().ok())
                .map_or(Address([0; 32]), |id| Address(id.0));
            let id = id.as_fields().map(|v| alloc_block(b, v));
            let owner = hint
                .map_or(Address([0; 32]), |(_, p)| p.policy.owner)
                .as_fields()
                .map(|v| alloc_block(b, v));
            for field in [&page, &index].into_iter().chain(&id).chain(&owner) {
                let unused = mul(b, &live.add_const(F128::ONE), field);
                pin_zero(b, &unused);
            }
            TradeOwnerStatementTrace {
                live,
                header_page: page,
                policy_index: index,
                authorization_id: id,
                owner,
            }
        })
        .collect();
    TradeOwnerAdviceTrace { statements }
}

pub fn bind_trade_owner_advice(
    b: &mut FieldR1csBuilder,
    advice: &TradeOwnerAdviceTrace,
    actual: &[TradeOwnerStatementTrace],
) {
    assert_eq!(advice.statements.len(), actual.len());
    for (a, c) in advice.statements.iter().zip(actual) {
        for (a, c) in [
            (&a.live, &c.live),
            (&a.header_page, &c.header_page),
            (&a.policy_index, &c.policy_index),
        ] {
            pin_eq(b, a, c);
        }
        for lane in 0..2 {
            pin_eq(b, &a.authorization_id[lane], &c.authorization_id[lane]);
            pin_eq(b, &a.owner[lane], &c.owner[lane]);
        }
    }
}

pub struct TradeAuthorizationPrefixTrace {
    pub groups: Vec<PagedSpendGroupTrace>,
    pub count: LinExpr,
}

/// Contract authority is selected through the group's exact physical END.
/// Compaction and native multi-page groups do not change that coordinate.
fn contract_authority(
    b: &mut FieldR1csBuilder,
    group: &PagedSpendGroupTrace,
    contract_flags: &[LinExpr],
    authorities: &[[LinExpr; 2]],
) -> [LinExpr; 2] {
    assert!(authorities.len() <= contract_flags.len());
    let mut result = group.input_owner.clone();
    for (i, authority) in authorities.iter().enumerate() {
        let same = is_zero(b, &group.end_page.add(&number(i as u128 + 1)));
        let selected = mul(b, &same, &group.live);
        let selected = mul(b, &selected, &contract_flags[i]);
        for lane in 0..2 {
            result[lane] = result[lane].add(&mul(
                b,
                &selected,
                &authority[lane].add(&group.input_owner[lane]),
            ));
        }
    }
    result
}

/// Merge exact non-public group statements and the bounded trade advice into
/// the existing dyadic Owner capacity. Sorting coordinates are physical group
/// order and canonical policy ordinal. Every early trade field is bound late.
pub fn merge_trade_authorizations(
    b: &mut FieldR1csBuilder,
    groups: &[PagedSpendGroupTrace],
    contract_flags: &[LinExpr],
    contract_authorities: &[[LinExpr; 2]],
    trades: &TradeOwnerAdviceTrace,
) -> TradeAuthorizationPrefixTrace {
    let capacity = groups.len();
    assert!(capacity.is_power_of_two() && contract_flags.len() < capacity);
    for flag in contract_flags {
        boolean(b, flag);
    }
    let mut rows = Vec::with_capacity(capacity + trades.statements.len());
    for group in groups {
        let owner = contract_authority(b, group, contract_flags, contract_authorities);
        rows.push(vec![
            group.live.clone(),
            group.end_page.clone(),
            LinExpr::zero(),
            group.logical_txid[0].clone(),
            group.logical_txid[1].clone(),
            owner[0].clone(),
            owner[1].clone(),
            group.fee.clone(),
            group.live_input_count.clone(),
            group.live_output_count.clone(),
        ]);
    }
    for (i, t) in trades.statements.iter().enumerate() {
        rows.push(vec![
            t.live.clone(),
            t.header_page.clone(),
            t.live.scale(flat_const(i as u128 + 1)),
            t.authorization_id[0].clone(),
            t.authorization_id[1].clone(),
            t.owner[0].clone(),
            t.owner[1].clone(),
            LinExpr::zero(),
            LinExpr::zero(),
            LinExpr::zero(),
        ]);
    }
    let rows = route_sorted(b, rows, 10, |b, row| {
        vec![value(b, &row[1]), value(b, &row[2])]
    });
    for row in &rows[contract_flags.len()..] {
        pin_zero(b, &row[0]);
    }
    let mut previous_live = LinExpr::constant(F128::ONE);
    let mut previous_key: Option<Vec<LinExpr>> = None;
    let mut count = vec![LinExpr::zero(); 11];
    let groups = rows
        .into_iter()
        .take(capacity)
        .map(|row| {
            boolean(b, &row[0]);
            for field in &row[1..] {
                let unused = mul(b, &row[0].add_const(F128::ONE), field);
                pin_zero(b, &unused);
            }
            let hole = mul(b, &row[0], &previous_live.add_const(F128::ONE));
            pin_zero(b, &hole);
            previous_live = row[0].clone();
            let coordinate = bits(b, &row[1], 16);
            let limit = bits(b, &number(contract_flags.len() as u128 + 1), 16);
            let valid = less_than(b, &coordinate, &limit);
            let outside = mul(b, &row[0], &valid.add_const(F128::ONE));
            pin_zero(b, &outside);
            let zero_coordinate = is_zero(b, &row[1]);
            let missing_position = mul(b, &row[0], &zero_coordinate);
            pin_zero(b, &missing_position);
            let mut key = bits(b, &row[2], 8);
            key.extend(coordinate);
            if let Some(old) = previous_key.take() {
                let strict = less_than(b, &old, &key);
                let wrong = mul(b, &row[0], &strict.add_const(F128::ONE));
                pin_zero(b, &wrong);
            }
            previous_key = Some(key);
            let mut one = vec![LinExpr::zero(); 11];
            one[0] = row[0].clone();
            count = checked_add(b, &count, &one);
            PagedSpendGroupTrace {
                live: row[0].clone(),
                end_page: row[1].clone(),
                logical_txid: [row[3].clone(), row[4].clone()],
                input_owner: [row[5].clone(), row[6].clone()],
                fee: row[7].clone(),
                live_input_count: row[8].clone(),
                live_output_count: row[9].clone(),
            }
        })
        .collect();
    TradeAuthorizationPrefixTrace {
        groups,
        count: pack(&count),
    }
}
