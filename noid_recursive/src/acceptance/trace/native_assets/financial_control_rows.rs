// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete control coordinates and shared integer product remainders.

use super::super::permutation_network::route_permutation_network;
use super::super::{mul, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::less_than;
use super::financial_actions::FinancialActionTrace;
use super::financial_controls::{
    bind_financial_control_arithmetic, FinancialControlArithmeticTrace,
};
use super::financial_definitions::FinancialDefinitionsTrace;
use noid_core::hardware::flat_to_tower_u128;
use noid_tx::native_assets::NativeKind;
pub struct FinancialControlRowTrace {
    pub live: LinExpr,
    pub header_page: LinExpr,
    pub is_output: LinExpr,
    pub ordinal: LinExpr,
    pub root: [LinExpr; 2],
    pub fields: [LinExpr; 12],
    pub arithmetic: FinancialControlArithmeticTrace,
}
fn tower(b: &FieldR1csBuilder, v: &LinExpr) -> u128 {
    let f = v.eval(b.values());
    flat_to_tower_u128(u128::from(f.lo) | (u128::from(f.hi) << 64))
}
fn bits(b: &mut FieldR1csBuilder, v: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, v, n)
}
/// All physical control rows pass through one complete constrained permutation.
/// Coordinates and roots accompany the same fields and arithmetic result, so
/// later transition predicates can reuse each exact product remainder.
pub fn bind_financial_control_rows(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    capacity: usize,
) -> Vec<FinancialControlRowTrace> {
    assert_eq!(actions.len(), definitions.actions.len());
    assert!(!actions.is_empty() && capacity > 0 && capacity <= actions.len().next_power_of_two());
    let mut rows = actions
        .iter()
        .zip(&definitions.actions)
        .map(|(a, d)| {
            let pool = a.opening.commitment.selector(NativeKind::MarketPool);
            let launch = a.opening.commitment.selector(NativeKind::LaunchState);
            let live = pool.add(launch);
            let mut row = vec![
                live.clone(),
                pool.clone(),
                launch.clone(),
                mul(b, &live, &a.header_page),
                mul(b, &live, &a.is_output),
                mul(b, &live, &a.ordinal),
            ];
            row.extend(a.opening.fields.iter().map(|v| mul(b, &live, v)));
            row.push(mul(b, launch, &d.fields[4]));
            row.extend(a.root.iter().map(|v| mul(b, &live, v)));
            row
        })
        .collect::<Vec<_>>();
    rows.resize_with(rows.len().next_power_of_two(), || vec![LinExpr::zero(); 21]);
    let mut order = (0..rows.len()).collect::<Vec<_>>();
    order.sort_by_key(|&i| {
        (
            tower(b, &rows[i][0]) == 0,
            tower(b, &rows[i][3]),
            tower(b, &rows[i][4]),
            tower(b, &rows[i][5]),
            i,
        )
    });
    let mut permutation = vec![0; rows.len()];
    for (target, source) in order.into_iter().enumerate() {
        permutation[source] = target;
    }
    let rows = route_permutation_network(b, rows, &permutation);
    for row in &rows[capacity..] {
        pin_zero(b, &row[0]);
    }
    let mut previous: Option<(LinExpr, Vec<LinExpr>)> = None;
    rows.into_iter()
        .take(capacity)
        .map(|row| {
            let mut key = bits(b, &row[5], 11);
            key.push(row[4].clone());
            key.extend(bits(b, &row[3], 16));
            if let Some((live, old)) = previous.take() {
                let hole = mul(b, &row[0], &live.add_const(F128::ONE));
                pin_zero(b, &hole);
                let strict = less_than(b, &old, &key);
                let bad = mul(b, &row[0], &strict.add_const(F128::ONE));
                pin_zero(b, &bad);
            }
            previous = Some((row[0].clone(), key));
            let fields: [LinExpr; 12] = std::array::from_fn(|i| row[6 + i].clone());
            let arithmetic =
                bind_financial_control_arithmetic(b, &row[1], &row[2], &fields, &row[18]);
            FinancialControlRowTrace {
                live: row[0].clone(),
                header_page: row[3].clone(),
                is_output: row[4].clone(),
                ordinal: row[5].clone(),
                root: [row[19].clone(), row[20].clone()],
                fields,
                arithmetic,
            }
        })
        .collect()
}
