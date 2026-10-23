// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact native-control reads from registration and purchase inputs.

use noid_tx::native_assets::NativeKind;

use super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::range_check_bits;
use super::arithmetic::{checked_add, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;

pub struct FinancialParentReadTrace {
    pub required: LinExpr,
    pub market: LinExpr,
    pub launch: LinExpr,
    pub listing: LinExpr,
    pub root: [LinExpr; 2],
    pub fields: [LinExpr; 12],
}

/// Funded requests read their registration family's control. A fixed-price
/// purchase reads the listing consumed by that same purchase. Exact State
/// consumption and the parent counter bind each control's incarnation.
pub fn bind_financial_parent_reads(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    headers: &[FinancialNativeHeaderTrace],
    parent_alloc_counter: &LinExpr,
) -> Vec<FinancialParentReadTrace> {
    let counter = range_check_bits(b, parent_alloc_counter, 64);
    pin_zero(b, &LinExpr::from_wire(counter[62]));
    pin_zero(b, &LinExpr::from_wire(counter[63]));
    let counter = counter[..62]
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let sources = actions
        .iter()
        .map(|action| {
            [
                (38, NativeKind::MarketPool),
                (50, NativeKind::LaunchState),
                (65, NativeKind::NftListing),
            ]
            .map(|(code, kind)| {
                let operation = is_zero(
                    b,
                    &action.operation.add_const(super::super::flat_const(code)),
                );
                let selected = mul(b, &operation, action.opening.commitment.selector(kind));
                mul(b, &selected, &action.is_output.add_const(F128::ONE))
            })
        })
        .collect::<Vec<_>>();
    let count_width = (actions.len() + 1)
        .next_power_of_two()
        .trailing_zeros()
        .max(1) as usize;
    headers
        .iter()
        .map(|header| {
            let op = |code| {
                &header.metadata.financial[FINANCIAL_OPERATION_CODES
                    .iter()
                    .position(|&c| c == code)
                    .expect("financial code")]
            };
            let market = op(33).add(op(34)).add(op(35)).add(op(36));
            let launch = op(49).clone();
            let listing = op(65).clone();
            let required = market.add(&launch).add(&listing);
            pin_eq(b, &required, &header.metadata.read_required);
            let sequence = range_check_bits(b, &header.metadata.read_sequence, 62)
                .into_iter()
                .map(LinExpr::from_wire)
                .collect::<Vec<_>>();
            let after_parent = less_than(b, &counter, &sequence);
            pin_zero(b, &after_parent);
            let mut count = vec![LinExpr::zero(); count_width];
            let mut fields: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
            for (action, source) in actions.iter().zip(&sources) {
                let mut family = mul(b, &market, &source[0]);
                family = family.add(&mul(b, &launch, &source[1]));
                family = family.add(&mul(b, &listing, &source[2]));
                let slot = is_zero(b, &action.slot.add(&header.metadata.read_slot));
                let incarnation = is_zero(
                    b,
                    &action
                        .opening
                        .creation_id
                        .value
                        .add(&header.metadata.read_creation_id),
                );
                let root0 = is_zero(b, &action.root[0].add(&header.metadata.read_root[0]));
                let root1 = is_zero(b, &action.root[1].add(&header.metadata.read_root[1]));
                let mut selected = mul(b, &family, &slot);
                selected = mul(b, &selected, &incarnation);
                selected = mul(b, &selected, &root0);
                selected = mul(b, &selected, &root1);
                let mut delta = vec![LinExpr::zero(); count_width];
                delta[0] = selected.clone();
                count = checked_add(b, &count, &delta);
                for index in 0..12 {
                    fields[index] =
                        fields[index].add(&mul(b, &selected, &action.opening.fields[index]));
                }
            }
            pin_eq(b, &pack(&count), &required);
            FinancialParentReadTrace {
                required,
                market,
                launch,
                listing,
                root: header.metadata.read_root.clone(),
                fields,
            }
        })
        .collect()
}
