// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete settlement-header routing within the physical action budget.

use super::super::permutation_network::route_permutation_network;
use super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::less_than;
use super::arithmetic::range_check_bits;
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::financial_settlement_sets::FinancialSettlementHeaderTrace;
use super::header::FinancialNativeHeaderTrace;
use noid_core::hardware::flat_to_tower_u128;

pub struct FinancialSettlementHeadersTrace {
    pub headers: Vec<FinancialSettlementHeaderTrace>,
    pub fees: Vec<LinExpr>,
    pub required_fees: Vec<LinExpr>,
}

fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}

pub fn bind_financial_settlement_headers(
    b: &mut FieldR1csBuilder,
    headers: &[FinancialNativeHeaderTrace],
    required_fees: &[LinExpr],
    action_capacity: usize,
) -> FinancialSettlementHeadersTrace {
    assert!(!headers.is_empty());
    assert_eq!(headers.len(), required_fees.len());
    assert!(action_capacity >= 4 && action_capacity % 2 == 0);
    let limit = headers.len().min(action_capacity / 4);
    let width = 7;
    let mut rows = headers
        .iter()
        .zip(required_fees)
        .map(|(h, fee)| {
            let family = [39, 51].map(|code| {
                h.metadata.financial[FINANCIAL_OPERATION_CODES
                    .iter()
                    .position(|&c| c == code)
                    .unwrap()]
                .clone()
            });
            let live = family[0].add(&family[1]);
            vec![
                live.clone(),
                mul(b, &live, &h.header.header_page),
                mul(b, &live, &h.header.input_count),
                mul(b, &live, &h.header.fee),
                mul(b, &live, fee),
                family[0].clone(),
                family[1].clone(),
            ]
        })
        .collect::<Vec<_>>();
    rows.resize_with(rows.len().next_power_of_two(), || {
        vec![LinExpr::zero(); width]
    });
    let mut order = (0..rows.len()).collect::<Vec<_>>();
    order.sort_by_key(|&i| (tower(b, &rows[i][0]) == 0, tower(b, &rows[i][1]), i));
    let mut permutation = vec![0; rows.len()];
    for (target, source) in order.into_iter().enumerate() {
        permutation[source] = target;
    }
    let rows = route_permutation_network(b, rows, &permutation);
    for row in &rows[limit..] {
        pin_zero(b, &row[0]);
    }
    let mut previous: Option<(&LinExpr, Vec<LinExpr>)> = None;
    let mut selected = Vec::with_capacity(limit);
    let mut fees = Vec::with_capacity(limit);
    let mut required = Vec::with_capacity(limit);
    for row in rows.iter().take(limit) {
        let invalid = mul(b, &row[0], &row[0].add_const(F128::ONE));
        pin_zero(b, &invalid);
        pin_eq(b, &row[0], &row[5].add(&row[6]));
        let page = range_check_bits(b, &row[1], 32)
            .into_iter()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        if let Some((prior_live, prior_page)) = &previous {
            let gap = mul(b, &row[0], &prior_live.add_const(F128::ONE));
            pin_zero(b, &gap);
            let ordered = less_than(b, prior_page, &page);
            let invalid = mul(b, &row[0], &ordered.add_const(F128::ONE));
            pin_zero(b, &invalid);
        }
        previous = Some((&row[0], page));
        selected.push(FinancialSettlementHeaderTrace {
            family: [row[5].clone(), row[6].clone()],
            header_page: row[1].clone(),
            input_count: row[2].clone(),
        });
        fees.push(row[3].clone());
        required.push(row[4].clone());
    }
    FinancialSettlementHeadersTrace {
        headers: selected,
        fees,
        required_fees: required,
    }
}
