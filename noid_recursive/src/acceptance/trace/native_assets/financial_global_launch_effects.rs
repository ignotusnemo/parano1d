// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared launch request execution and exact complete-set effects.

use super::super::{flat_const, mul, pin_eq, FieldR1csBuilder, LinExpr};
use super::arithmetic::split_packed_input_value;
use super::financial_control_rows::FinancialControlRowTrace;
use super::financial_global_effects::FinancialEffectRequestTrace;
use super::financial_launch_effects_shared::{
    bind_financial_launch_effects_prepared, FinancialLaunchEffectsTrace,
};
use super::financial_launch_execution::{
    bind_financial_launch_execution, FinancialLaunchExecutionInputTrace,
    FinancialLaunchExecutionTrace,
};
use super::financial_settlement_sets::FinancialSettlementSetTrace;
use super::validation::is_zero;

/// The common complete request projection binds every launch source, clearing
/// price and final quantity. Exact family/group/ordinal lookups supply all
/// per-set inventory, cash, fee, claim and graduation accounting.
pub fn bind_financial_global_launch_effects_from_requests(
    b: &mut FieldR1csBuilder,
    sets: &[FinancialSettlementSetTrace],
    fees: &[LinExpr],
    controls: &[FinancialControlRowTrace],
    rows: &[FinancialEffectRequestTrace],
) -> Vec<FinancialLaunchEffectsTrace> {
    assert_eq!(sets.len(), fees.len());
    assert_eq!(sets.len(), controls.len());
    let executions = rows
        .iter()
        .map(|row| {
            let live = mul(b, &row.launch, &row.kinds[4]);
            let time = split_packed_input_value(b, &row.fields[9]);
            let sell = mul(b, &live, &time.creation_id.value);
            let terms = split_packed_input_value(b, &row.fields[8]);
            let quantity = mul(b, &live, &row.effective);
            let execution = bind_financial_launch_execution(
                b,
                &FinancialLaunchExecutionInputTrace {
                    live,
                    sell,
                    requested: terms.amount.value,
                    limit: terms.creation_id.value,
                    quantity,
                    price: row.price.clone(),
                },
            );
            [
                execution.buy,
                execution.sell,
                execution.bought,
                execution.sold,
                execution.cost,
                execution.proceeds,
                execution.refund,
                execution.output,
            ]
        })
        .collect::<Vec<_>>();
    sets.iter()
        .enumerate()
        .map(|(group_index, set)| {
            let selected = set
                .requests
                .iter()
                .enumerate()
                .map(|(ordinal, request)| {
                    let mut found = LinExpr::zero();
                    let mut values: [LinExpr; 8] = std::array::from_fn(|_| LinExpr::zero());
                    for (row, execution) in rows.iter().zip(&executions) {
                        let same_group = is_zero(b, &row.group.add(&set.header_page));
                        let same_ordinal =
                            is_zero(b, &row.ordinal.add_const(flat_const(ordinal as u128)));
                        let hit = mul(b, &same_group, &same_ordinal);
                        let hit = mul(b, &hit, &row.launch);
                        let hit = mul(b, &hit, &set.family[1]);
                        found = found.add(&hit);
                        for j in 0..8 {
                            values[j] = values[j].add(&mul(b, &hit, &execution[j]));
                        }
                    }
                    let expected = mul(b, &set.family[1], &request.live);
                    pin_eq(b, &found, &expected);
                    let [buy, sell, bought, sold, cost, proceeds, refund, output] = values;
                    FinancialLaunchExecutionTrace {
                        buy,
                        sell,
                        bought,
                        sold,
                        cost,
                        proceeds,
                        refund,
                        output,
                    }
                })
                .collect::<Vec<_>>();
            bind_financial_launch_effects_prepared(
                b,
                set,
                &selected,
                &fees[group_index],
                &controls[group_index],
            )
        })
        .collect()
}
