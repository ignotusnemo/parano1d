// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Parent-bound admission rounds shared by native financial requests.

use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr};
use super::arithmetic::split_packed_input_value;
use super::financial_actions::FinancialActionTrace;
use super::financial_definitions::FinancialDefinitionsTrace;
use super::financial_queue::bind_financial_round;
use super::financial_reads::FinancialParentReadTrace;
use super::financial_registration::FinancialRegistrationsTrace;
use super::financial_values::FinancialCarrierValuesTrace;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_tx::native_assets::NativeKind;

fn require_equal(b: &mut FieldR1csBuilder, when: &LinExpr, a: &LinExpr, c: &LinExpr) {
    let invalid = mul(b, when, &a.add(c));
    pin_zero(b, &invalid);
}
/// Market and launch requests bind their exact registration round. Direct
/// fixed-price NFT purchases consume their listing without creating a round.
/// The caller authenticates the parent id, allocation counter and height.
pub fn bind_financial_registration_rounds(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    values: &[FinancialCarrierValuesTrace],
    headers: &[FinancialNativeHeaderTrace],
    reads: &[FinancialParentReadTrace],
    definitions: &FinancialDefinitionsTrace,
    registrations: &FinancialRegistrationsTrace,
    height: &LinExpr,
    parent_id: &[LinExpr; 2],
    parent_counter: &LinExpr,
) -> Vec<[LinExpr; 2]> {
    assert_eq!(headers.len(), reads.len());
    assert_eq!(headers.len(), definitions.reads.len());
    assert_eq!(actions.len(), values.len());
    assert_eq!(actions.len(), registrations.requests.len());
    let rounds = reads
        .iter()
        .zip(&definitions.reads)
        .map(|(read, definition)| {
            require_equal(
                b,
                &read.market,
                &read.fields[7],
                &definition.base_is_noid.scale(flat_const(1u128 << 88)),
            );
            let launch_idle = mul(b, &read.launch, &read.fields[6]);
            pin_zero(b, &launch_idle);
            let mut temporal = mul(b, &read.market, &read.fields[6]);
            temporal = temporal.add(&mul(b, &read.launch, &read.fields[3]));
            let temporal = split_packed_input_value(b, &temporal);
            let required = read.market.add(&read.launch);
            let generation = mul(b, &required, &temporal.amount.value);
            let exhausted = is_zero(b, &generation.add_const(flat_const(u128::from(u64::MAX))));
            let invalid = mul(b, &required, &exhausted);
            pin_zero(b, &invalid);
            let selected_height = mul(b, &required, height);
            bind_financial_round(
                b,
                &[read.market.clone(), read.launch.clone(), LinExpr::zero()],
                &[read.fields[0].clone(), read.fields[1].clone()],
                &read.root,
                &selected_height,
                parent_id,
                parent_counter,
            )
        })
        .collect::<Vec<_>>();
    for ((request, action), value) in registrations.requests.iter().zip(actions).zip(values) {
        let swap = mul(
            b,
            &request.live,
            action
                .opening
                .commitment
                .selector(NativeKind::MarketRequest),
        );
        let deposit = mul(
            b,
            &request.live,
            action
                .opening
                .commitment
                .selector(NativeKind::MarketLiquidityDeposit),
        );
        let first_pair = swap.add(&request.family[1]);
        let second_pair = request.live.add(&first_pair);
        let actual: [LinExpr; 2] = std::array::from_fn(|lane| {
            mul(b, &first_pair, &action.opening.fields[lane]).add(&mul(
                b,
                &second_pair,
                &action.opening.fields[lane + 2],
            ))
        });
        let mut expected: [LinExpr; 2] = std::array::from_fn(|_| LinExpr::zero());
        for (header, round) in headers.iter().zip(&rounds) {
            let same = is_zero(b, &request.header_page.add(&header.header.header_page));
            let selected = mul(b, &same, &request.live);
            for lane in 0..2 {
                expected[lane] = expected[lane].add(&mul(b, &selected, &round[lane]));
            }
        }
        for lane in 0..2 {
            pin_eq(b, &actual[lane], &expected[lane]);
        }
        let later = request.live.add(&first_pair).add(&deposit);
        let registered = mul(b, &first_pair, &value.secondary.amount.value)
            .add(&mul(b, &deposit, &value.secondary.creation_id.value))
            .add(&mul(b, &later, &value.primary.creation_id.value));
        let expected = mul(b, &request.live, height);
        pin_eq(b, &registered, &expected);
    }
    rounds
}
