// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native witness construction for the constrained complete-set clearing trace.

use super::super::{FieldR1csBuilder, LinExpr};
use noid_core::{hardware::flat_to_tower_u128, Block128};
use noid_poseidon2b::primitives::Address;
use noid_tx::native_assets::NativeOpening;

fn value(v: &LinExpr, b: &FieldR1csBuilder) -> u128 {
    let x = v.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}

fn decode_financial_fields(
    b: &FieldR1csBuilder,
    kind: noid_tx::native_assets::NativeKind,
    fields: &[LinExpr],
) -> NativeOpening {
    let fields = fields
        .iter()
        .take(kind.field_count())
        .map(|x| Block128(value(x, b)))
        .collect::<Vec<_>>();
    NativeOpening::from_fields(kind, &fields).unwrap()
}
fn trace_address(b: &FieldR1csBuilder, fields: &[LinExpr; 2]) -> Address {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&value(&fields[0], b).to_le_bytes());
    bytes[16..].copy_from_slice(&value(&fields[1], b).to_le_bytes());
    Address(bytes)
}
fn funded_coordinates(
    b: &FieldR1csBuilder,
    group: u128,
    key: &[LinExpr; 2],
    actions: &[super::financial_actions::FinancialActionTrace],
) -> (u32, u64) {
    let key = trace_address(b, key).0;
    let found = actions
        .iter()
        .filter(|a| {
            value(&a.live, b) == 1
                && value(&a.is_output, b) == 0
                && value(&a.header_page, b) == group
        })
        .filter_map(|a| {
            let slot = value(&a.slot, b) as u32;
            let cid = (value(&a.packed_value, b) >> 64) as u64;
            (noid_tx::native_assets::market::queue::funded_request_key(
                trace_address(b, &a.root),
                slot,
                cid,
            ) == key)
                .then_some((slot, cid))
        })
        .collect::<Vec<_>>();
    assert_eq!(found.len(), 1);
    found[0]
}
pub fn financial_clearing_witness(
    b: &FieldR1csBuilder,
    sets: &[super::financial_settlement_sets::FinancialSettlementSetTrace],
    actions: &[super::financial_actions::FinancialActionTrace],
) -> super::financial_global_clearing::FinancialGlobalClearingWitness {
    use super::{
        financial_active_clearing_route::FinancialActiveRouteWitness,
        financial_global_clearing::{FinancialClearingStepWitness, FinancialGlobalClearingWitness},
    };
    use noid_tx::native_assets::{
        launch::{
            self,
            queue::{LaunchRegisteredBatch, LaunchRequestRef},
            LaunchOpening,
        },
        market::{
            self,
            queue::{MarketRequestRef, MixedRegisteredBatch},
            request::MarketRequest,
            MarketOpening,
        },
        NativeKind,
    };
    let mut steps = vec![];
    let mut active = vec![];
    let mut source_offset = 0;
    for set in sets {
        let group = value(&set.header_page, b);
        let step_offset = steps.len();
        if value(&set.family[0], b) == 1 {
            let NativeOpening::Market(MarketOpening::Definition(def)) =
                decode_financial_fields(b, NativeKind::MarketDefinition, &set.definition)
            else {
                panic!()
            };
            let NativeOpening::Market(MarketOpening::Pool(pool)) =
                decode_financial_fields(b, NativeKind::MarketPool, &set.frozen)
            else {
                panic!()
            };
            let requests = set
                .requests
                .iter()
                .filter(|r| value(&r.live, b) == 1)
                .map(|r| {
                    let which = (0..4).find(|&i| value(&r.kinds[i], b) == 1).unwrap();
                    let kind = [
                        NativeKind::MarketRequest,
                        NativeKind::MarketLiquidityDeposit,
                        NativeKind::MarketLiquidityWithdrawal,
                        NativeKind::MarketLiquidityBurn,
                    ][which];
                    let NativeOpening::Market(opening) =
                        decode_financial_fields(b, kind, &r.fields)
                    else {
                        panic!()
                    };
                    let request = match opening {
                        MarketOpening::Request(x) => MarketRequest::Swap(x),
                        MarketOpening::LiquidityDeposit(x) => MarketRequest::Deposit(x),
                        MarketOpening::LiquidityWithdrawal(x) => MarketRequest::Withdraw(x),
                        MarketOpening::LiquidityBurn(x) => MarketRequest::Burn(x),
                        _ => panic!(),
                    };
                    let (slot_index, creation_id) = funded_coordinates(b, group, &r.key, actions);
                    MarketRequestRef {
                        slot_index,
                        creation_id,
                        request,
                    }
                })
                .collect::<Vec<_>>();
            let batch = MixedRegisteredBatch::from_frozen(def, pool, &requests).unwrap();
            let settlement = market::mixed::MixedBatchSettlement::calculate(
                def,
                &batch,
                pool.registered_height + 1,
                0,
            )
            .unwrap();
            let Some(solution) = settlement.swaps() else {
                continue;
            };
            for (i, s) in solution.steps().iter().enumerate() {
                steps.push(FinancialClearingStepWitness {
                    group: group as u32,
                    rank: i as u8,
                    terminal: i + 1 == solution.steps().len(),
                    price: [s.price.numerator, s.price.denominator],
                    at_cap: false,
                });
                for j in 0..solution.execution().len() {
                    if s.active_mask & (1 << j) != 0 {
                        active.push(FinancialActiveRouteWitness {
                            source: source_offset + j,
                            step: step_offset + i,
                            dust: s.dust_mask & (1 << j) != 0,
                        });
                    }
                }
            }
            source_offset += solution.execution().len();
        } else if value(&set.family[1], b) == 1 {
            let NativeOpening::Launch(LaunchOpening::Definition(def)) =
                decode_financial_fields(b, NativeKind::LaunchDefinition, &set.definition)
            else {
                panic!()
            };
            let NativeOpening::Launch(LaunchOpening::State(pool)) =
                decode_financial_fields(b, NativeKind::LaunchState, &set.frozen)
            else {
                panic!()
            };
            let requests = set
                .requests
                .iter()
                .filter(|r| value(&r.live, b) == 1)
                .map(|r| {
                    let NativeOpening::Launch(LaunchOpening::Request(request)) =
                        decode_financial_fields(b, NativeKind::LaunchRequest, &r.fields)
                    else {
                        panic!()
                    };
                    let (slot_index, creation_id) = funded_coordinates(b, group, &r.key, actions);
                    LaunchRequestRef {
                        slot_index,
                        creation_id,
                        request,
                    }
                })
                .collect::<Vec<_>>();
            let batch = LaunchRegisteredBatch::from_frozen(def, pool, &requests).unwrap();
            let solution = launch::clearing::solve(def, &batch).unwrap();
            for (i, s) in solution.steps.iter().enumerate() {
                steps.push(FinancialClearingStepWitness {
                    group: group as u32,
                    rank: i as u8,
                    terminal: i + 1 == solution.steps.len(),
                    price: [s.price.numerator, s.price.denominator],
                    at_cap: s.at_cap,
                });
                for j in 0..batch.requests().len() {
                    if s.active_mask & (1 << j) != 0 {
                        active.push(FinancialActiveRouteWitness {
                            source: source_offset + j,
                            step: step_offset + i,
                            dust: s.dust_mask & (1 << j) != 0,
                        });
                    }
                }
            }
            source_offset += batch.requests().len();
        }
    }
    FinancialGlobalClearingWitness { steps, active }
}
