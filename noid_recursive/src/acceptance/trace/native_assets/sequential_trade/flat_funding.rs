// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! One canonical source table shared by all selected trade policies.

use super::super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::super::actions::route_sorted;
use super::super::arithmetic::{bits, checked_add, pack};
use super::super::validation::is_zero;
use super::funding::{
    append_trade_funding, begin_trade_funding, finish_trade_funding_at, TradeFundingInputTrace,
    TradeFundingResultTrace, TradeFundingStateTrace,
};
use super::policy::{TradePolicyContextTrace, TradePolicyInputTrace, TradePolicyTrace};
use super::{boolean, number, value};
use noid_tx::native_assets::market::sequential::MAX_SEQUENTIAL_TRADES;
use noid_tx::MAX_PAGED_SPEND_INPUTS;

pub struct FlatTradePolicyTrace {
    pub policy: TradePolicyTrace,
    pub funding_count: LinExpr,
}

pub struct FlatTradeFundingRowTrace {
    pub policy_index: LinExpr,
    pub input: TradeFundingInputTrace,
}

fn selected_policy(
    b: &mut FieldR1csBuilder,
    selectors: &[LinExpr],
    policies: &[FlatTradePolicyTrace],
) -> TradePolicyTrace {
    let mut field = |get: fn(&TradePolicyTrace) -> &LinExpr| {
        selectors
            .iter()
            .zip(policies)
            .fold(LinExpr::zero(), |sum, (selected, p)| {
                sum.add(&mul(b, selected, get(&p.policy)))
            })
    };
    TradePolicyTrace {
        input: TradePolicyInputTrace {
            live: field(|p| &p.input.live),
            chain: [field(|p| &p.input.chain[0]), field(|p| &p.input.chain[1])],
            epoch_anchor: [
                field(|p| &p.input.epoch_anchor[0]),
                field(|p| &p.input.epoch_anchor[1]),
            ],
            owner: [field(|p| &p.input.owner[0]), field(|p| &p.input.owner[1])],
            asset: [field(|p| &p.input.asset[0]), field(|p| &p.input.asset[1])],
            recipient: [
                field(|p| &p.input.recipient[0]),
                field(|p| &p.input.recipient[1]),
            ],
            sell: field(|p| &p.input.sell),
            gross_input: field(|p| &p.input.gross_input),
            minimum_output: field(|p| &p.input.minimum_output),
            fee_limit: field(|p| &p.input.fee_limit),
            valid_from: field(|p| &p.input.valid_from),
            valid_until: field(|p| &p.input.valid_until),
        },
        root: [field(|p| &p.root[0]), field(|p| &p.root[1])],
    }
}

/// Policy rows are the canonical group/authorization-id prefix. Source rows
/// project the exact raw funding inputs in policy order and strict slot order.
/// The enclosing body binds those rows and each already-checked policy root.
pub fn bind_flat_trade_funding(
    b: &mut FieldR1csBuilder,
    context: &TradePolicyContextTrace,
    policies: &[FlatTradePolicyTrace],
    sources: &[FlatTradeFundingRowTrace],
) -> Vec<TradeFundingResultTrace> {
    assert!((1..=MAX_SEQUENTIAL_TRADES).contains(&policies.len()));
    assert!(!sources.is_empty() && sources.len() <= MAX_PAGED_SPEND_INPUTS);
    let width = policies.len().next_power_of_two().trailing_zeros().max(1) as usize;
    let mut previous_policy_live = LinExpr::constant(F128::ONE);
    let initial = policies
        .iter()
        .map(|p| {
            boolean(b, &p.policy.input.live);
            let hole = mul(
                b,
                &p.policy.input.live,
                &previous_policy_live.add_const(F128::ONE),
            );
            pin_zero(b, &hole);
            previous_policy_live = p.policy.input.live.clone();
            begin_trade_funding(b, &p.policy, &p.funding_count)
        })
        .collect::<Vec<_>>();
    let mut carried = TradeFundingStateTrace::zero();
    let mut previous_live = LinExpr::constant(F128::ONE);
    let mut previous_index = vec![LinExpr::zero(); width];
    let mut completed = Vec::with_capacity(sources.len());
    for (position, source) in sources.iter().enumerate() {
        let live = &source.input.live;
        boolean(b, live);
        let hole = mul(b, live, &previous_live.add_const(F128::ONE));
        pin_zero(b, &hole);
        let index = bits(b, &source.policy_index, width);
        let dead = mul(b, &live.add_const(F128::ONE), &source.policy_index);
        pin_zero(b, &dead);
        let same = is_zero(b, &pack(&previous_index).add(&source.policy_index));
        let start = if position == 0 {
            live.clone()
        } else {
            mul(b, live, &same.add_const(F128::ONE))
        };
        if position == 0 {
            pin_zero(b, &source.policy_index);
        } else {
            let mut delta = vec![LinExpr::zero(); width];
            delta[0] = start.clone();
            let expected = pack(&checked_add(b, &previous_index, &delta));
            let wrong = mul(b, live, &expected.add(&source.policy_index));
            pin_zero(b, &wrong);
        }
        let selectors = (0..policies.len())
            .map(|i| {
                let same = is_zero(b, &source.policy_index.add(&number(i as u128)));
                mul(b, live, &same)
            })
            .collect::<Vec<_>>();
        let policy = selected_policy(b, &selectors, policies);
        pin_eq(b, &policy.input.live, live);
        let seeds = selectors.iter().zip(&initial).collect::<Vec<_>>();
        let seed = TradeFundingStateTrace::weighted_sum(b, &seeds);
        let state = TradeFundingStateTrace::select(b, &start, &carried, &seed);
        let state =
            TradeFundingStateTrace::select(b, live, &TradeFundingStateTrace::zero(), &state);
        carried = append_trade_funding(b, context, &policy, &state, &source.input);
        let continuation = if let Some(next) = sources.get(position + 1) {
            let same = is_zero(b, &source.policy_index.add(&next.policy_index));
            mul(b, &next.input.live, &same)
        } else {
            LinExpr::zero()
        };
        let end = mul(b, live, &continuation.add_const(F128::ONE));
        let finished = finish_trade_funding_at(b, &end, &policy, &carried);
        completed.push(vec![
            end.clone(),
            mul(b, &end, &source.policy_index),
            finished.authorization_id[0].clone(),
            finished.authorization_id[1].clone(),
            finished.count,
            pack(&finished.noid),
            pack(&finished.tokens),
            finished.anchor_quantity,
            finished.anchor_creation_id,
            finished.anchor_slot,
        ]);
        previous_live = live.clone();
        previous_index = index;
    }
    let completed = route_sorted(b, completed, 10, |b, row| vec![value(b, &row[1])]);
    for row in &completed[policies.len().min(completed.len())..] {
        pin_zero(b, &row[0]);
    }
    policies
        .iter()
        .enumerate()
        .map(|(i, policy)| {
            let zero = vec![LinExpr::zero(); 10];
            let row = completed.get(i).unwrap_or(&zero);
            pin_eq(b, &row[0], &policy.policy.input.live);
            pin_eq(
                b,
                &row[1],
                &policy
                    .policy
                    .input
                    .live
                    .scale(super::super::super::flat_const(i as u128)),
            );
            TradeFundingResultTrace {
                authorization_id: [row[2].clone(), row[3].clone()],
                count: row[4].clone(),
                noid: bits(b, &row[5], 74),
                tokens: bits(b, &row[6], 74),
                anchor_quantity: row[7].clone(),
                anchor_creation_id: row[8].clone(),
                anchor_slot: row[9].clone(),
            }
        })
        .collect()
}
