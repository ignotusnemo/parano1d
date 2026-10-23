// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete sequential trade projections over authenticated financial actions.

mod markets;

use super::super::super::{
    alloc_block, flat_const, mul, pin_eq, pin_zero, poseidon2b_permute, FieldR1csBuilder, LinExpr,
    F128,
};
use super::super::actions::route_sorted;
use super::super::arithmetic::{bits, checked_add, less_than, pack, split_packed_input_value};
use super::super::financial_actions::FinancialActionTrace;
use super::super::financial_definitions::FinancialDefinitionsTrace;
use super::super::header::FinancialNativeHeaderTrace;
use super::super::validation::is_zero;
use super::fees::bind_trade_fee_quotes;
use super::flat_funding::{
    bind_flat_trade_funding, FlatTradeFundingRowTrace, FlatTradePolicyTrace,
};
use super::funding::{TradeFundingInputTrace, TradeFundingResultTrace};
use super::global_execution::{bind_global_trade_execution, MarketPolicyTrace};
use super::group::SequentialPolicyTrace;
use super::payouts::{bind_trade_payouts, TradePayoutsTrace};
use super::policy::{bind_trade_policy, TradePolicyContextTrace, TradePolicyInputTrace};
use super::{digest_bytes_bits, hash_fields, hash_state, number, select, value};
use noid_core::Block128;
use noid_poseidon2b::{native::DomainTag, primitives::Address};
use noid_tx::native_assets::{
    launch::LaunchSide,
    market::sequential::MAX_SEQUENTIAL_TRADES,
    trade::{batch::TradeBatch, sequencing::TradeBoundary},
    NativeKind,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TradeKernelConfig {
    pub markets: usize,
    pub policies: usize,
    pub funding: usize,
}

pub struct TradeKernelContext<'a> {
    pub chain: &'a [LinExpr; 2],
    pub epoch_anchor: &'a [LinExpr; 2],
    pub parent_id: &'a [LinExpr; 2],
    pub height: &'a LinExpr,
    pub parent_alloc_counter: &'a LinExpr,
    pub growth_per_slot: &'a LinExpr,
}

pub struct TradeOwnerStatementTrace {
    pub live: LinExpr,
    pub header_page: LinExpr,
    pub policy_index: LinExpr,
    pub authorization_id: [LinExpr; 2],
    pub owner: [LinExpr; 2],
}

pub struct TradeKernelTrace {
    pub authorizations: Vec<TradeOwnerStatementTrace>,
    pub batch_roots: Vec<[LinExpr; 2]>,
}

fn pair_bytes(b: &FieldR1csBuilder, pair: &[LinExpr; 2]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for lane in 0..2 {
        bytes[lane * 16..lane * 16 + 16].copy_from_slice(&value(b, &pair[lane]).to_le_bytes());
    }
    bytes
}
fn allocate(b: &mut FieldR1csBuilder, n: u128) -> LinExpr {
    alloc_block(b, Block128(n))
}
fn allocate_address(b: &mut FieldR1csBuilder, address: Address) -> [LinExpr; 2] {
    address.as_fields().map(|v| alloc_block(b, v))
}

fn weighted(
    b: &mut FieldR1csBuilder,
    selectors: &[LinExpr],
    values: impl IntoIterator<Item = LinExpr>,
) -> LinExpr {
    selectors
        .iter()
        .zip(values)
        .fold(LinExpr::zero(), |sum, (s, v)| sum.add(&mul(b, s, &v)))
}

/// The shared action table binds all roots, types, body ordinals and State
/// incarnations. This relation supplies complete policy funding, execution,
/// payout and controller predicates and returns the exact Owner statements.
pub fn bind_trade_kernel(
    b: &mut FieldR1csBuilder,
    config: TradeKernelConfig,
    context: &TradeKernelContext<'_>,
    headers: &[FinancialNativeHeaderTrace],
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    batches: &[TradeBatch],
) -> TradeKernelTrace {
    let mut ledger = b.num_wires();
    assert!((1..=MAX_SEQUENTIAL_TRADES).contains(&config.policies));
    assert!((1..=config.policies).contains(&config.markets));
    assert!((config.policies..=noid_tx::MAX_PAGED_SPEND_INPUTS).contains(&config.funding));
    let markets = markets::extract(b, config.markets, headers, actions, definitions, context);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "trade: market projection");
    let boundary = TradeBoundary {
        chain: pair_bytes(b, context.chain),
        epoch_anchor: pair_bytes(b, context.epoch_anchor),
        parent_id: pair_bytes(b, context.parent_id),
        height: value(b, context.height) as u64,
    };
    let mut hints = Vec::new();
    let mut execution_hints = Vec::new();
    for (market_index, market) in markets.iter().enumerate() {
        if value(b, &market.market.live) == 0 {
            continue;
        }
        let root = Address(pair_bytes(b, &market.commitment));
        if let Some(batch) = batches.iter().find(|batch| batch.root().ok() == Some(root)) {
            let offset = hints.len();
            if let Ok(plan) = batch.checked(boundary) {
                execution_hints.extend(plan.fills().iter().map(|fill| offset + fill.source_index));
            }
            hints.extend(batch.policies().iter().map(|p| (market_index, p)));
        }
    }
    let market_width = config.markets.next_power_of_two().trailing_zeros().max(1) as usize;
    let mut policies = Vec::with_capacity(config.policies);
    let mut market_indices = Vec::with_capacity(config.policies);
    let mut policy_selectors = Vec::with_capacity(config.policies);
    let mut policy_pages = Vec::with_capacity(config.policies);
    let mut starts = Vec::with_capacity(config.policies);
    let mut ends = Vec::with_capacity(config.policies);
    let mut previous_end = vec![LinExpr::zero(); 11];
    let mut previous_market = LinExpr::zero();
    for i in 0..config.policies {
        let hint = hints.get(i);
        let p = hint.map(|(_, p)| p.policy);
        let input = TradePolicyInputTrace {
            live: allocate(b, u128::from(p.is_some())),
            chain: allocate_address(b, Address(p.map_or([0; 32], |p| p.chain))),
            epoch_anchor: allocate_address(b, Address(p.map_or([0; 32], |p| p.epoch_anchor))),
            owner: allocate_address(b, p.map_or(Address([0; 32]), |p| p.owner)),
            asset: allocate_address(b, Address(p.map_or([0; 32], |p| p.asset.0))),
            recipient: allocate_address(b, p.map_or(Address([0; 32]), |p| p.recipient)),
            sell: allocate(b, p.map_or(0, |p| u128::from(p.side == LaunchSide::Sell))),
            gross_input: allocate(b, p.map_or(0, |p| u128::from(p.gross_input))),
            minimum_output: allocate(b, p.map_or(0, |p| u128::from(p.minimum_output))),
            fee_limit: allocate(b, p.map_or(0, |p| u128::from(p.fee_limit))),
            valid_from: allocate(b, p.map_or(0, |p| u128::from(p.valid_from))),
            valid_until: allocate(b, p.map_or(0, |p| u128::from(p.valid_until))),
        };
        let index = allocate(b, hint.map_or(0, |(m, _)| *m as u128));
        bits(b, &index, market_width);
        let unused = mul(b, &input.live.add_const(F128::ONE), &index);
        pin_zero(b, &unused);
        let selectors = markets
            .iter()
            .enumerate()
            .map(|(position, m)| {
                let same = is_zero(b, &index.add(&number(position as u128)));
                let selected = mul(b, &input.live, &same);
                mul(b, &selected, &m.market.live)
            })
            .collect::<Vec<_>>();
        let found = selectors.iter().fold(LinExpr::zero(), |sum, s| sum.add(s));
        pin_eq(b, &found, &input.live);
        let asset = std::array::from_fn(|lane| {
            weighted(
                b,
                &selectors,
                markets.iter().map(|m| m.market.asset[lane].clone()),
            )
        });
        let page = weighted(b, &selectors, markets.iter().map(|m| m.header_page.clone()));
        let admitting = TradePolicyContextTrace {
            chain: context.chain.clone(),
            epoch_anchor: context.epoch_anchor.clone(),
            asset,
            height: context.height.clone(),
            parent_alloc_counter: context.parent_alloc_counter.clone(),
        };
        let policy = bind_trade_policy(b, &admitting, &input);
        let count = allocate(b, hint.map_or(0, |(_, p)| p.funding.len() as u128));
        let same = is_zero(b, &index.add(&previous_market));
        let continuation = if i == 0 {
            LinExpr::zero()
        } else {
            mul(b, &input.live, &same)
        };
        let initial = mul(b, &input.live, &number(1));
        let start = select(b, &continuation, &initial, &pack(&previous_end));
        let start = mul(b, &input.live, &start);
        let start_bits = bits(b, &start, 11);
        let count_bits = bits(b, &count, 11);
        let end = checked_add(b, &start_bits, &count_bits);
        starts.push(start_bits);
        ends.push(end.clone());
        previous_end = end;
        previous_market = index.clone();
        policy_pages.push(page);
        policy_selectors.push(selectors);
        market_indices.push(index);
        policies.push(FlatTradePolicyTrace {
            policy,
            funding_count: count,
        });
    }
    for i in 0..config.policies {
        let live = &policies[i].policy.input.live;
        let continued = if i + 1 < config.policies {
            let same = is_zero(b, &market_indices[i].add(&market_indices[i + 1]));
            mul(b, &same, &policies[i + 1].policy.input.live)
        } else {
            LinExpr::zero()
        };
        let end = mul(b, live, &continued.add_const(F128::ONE));
        let expected = weighted(
            b,
            &policy_selectors[i],
            markets.iter().map(|m| m.input_count.clone()),
        );
        let wrong = mul(b, &end, &pack(&ends[i]).add(&expected));
        pin_zero(b, &wrong);
    }
    crate::acceptance::row_ledger_mark(b, &mut ledger, "trade: canonical policies");
    let sources = project_funding(
        b,
        config.funding,
        actions,
        &markets,
        &policies,
        &policy_pages,
        &starts,
        &ends,
    );
    let funding_context = TradePolicyContextTrace {
        chain: context.chain.clone(),
        epoch_anchor: context.epoch_anchor.clone(),
        asset: [LinExpr::zero(), LinExpr::zero()],
        height: context.height.clone(),
        parent_alloc_counter: context.parent_alloc_counter.clone(),
    };
    let funding = bind_flat_trade_funding(b, &funding_context, &policies, &sources);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "trade: source projection and funding");
    let batch_roots = bind_batch_roots(
        b,
        &markets,
        &policies,
        &funding,
        &market_indices,
        &policy_selectors,
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "trade: batch roots");
    let mut routed = Vec::with_capacity(config.policies);
    let mut previous_key: Option<Vec<LinExpr>> = None;
    for i in 0..config.policies {
        let p = &policies[i].policy.input;
        let mut key = digest_bytes_bits(b, &funding[i].authorization_id);
        key.extend(bits(b, &market_indices[i], market_width));
        if let Some(old) = previous_key {
            let strict = less_than(b, &old, &key);
            let bad = mul(b, &p.live, &strict.add_const(F128::ONE));
            pin_zero(b, &bad);
        }
        previous_key = Some(key);
        let priority = hash_fields(
            b,
            DomainTag::new(b"TRORD_21"),
            &[
                context.parent_id[0].clone(),
                context.parent_id[1].clone(),
                p.asset[0].clone(),
                p.asset[1].clone(),
                funding[i].anchor_creation_id.clone(),
                funding[i].anchor_slot.clone(),
            ],
        );
        routed.push(vec![
            p.live.clone(),
            market_indices[i].clone(),
            p.live.scale(flat_const(i as u128)),
            p.sell.clone(),
            p.gross_input.clone(),
            p.minimum_output.clone(),
            funding[i].anchor_creation_id.clone(),
            funding[i].anchor_slot.clone(),
            mul(b, &p.live, &priority[0]),
            mul(b, &p.live, &priority[1]),
        ]);
    }
    let routed = route_sorted(b, routed, 10, |b, row| {
        let mut key = vec![value(b, &row[1])];
        for lane in &row[8..10] {
            key.extend(value(b, lane).to_le_bytes().into_iter().map(u128::from));
        }
        key.extend([value(b, &row[6]), value(b, &row[7])]);
        key
    });
    let routed = &routed[..config.policies];
    let mut order = Vec::with_capacity(config.policies);
    for i in 0..config.policies {
        let source = execution_hints
            .get(i)
            .and_then(|&canonical| {
                routed.iter().position(|row| {
                    value(b, &row[0]) != 0 && value(b, &row[2]) == canonical as u128
                })
            })
            .unwrap_or(0);
        order.push(allocate(b, source as u128));
    }
    let execution_policies = routed
        .iter()
        .map(|row| MarketPolicyTrace {
            market_index: row[1].clone(),
            policy: SequentialPolicyTrace {
                live: row[0].clone(),
                sell: row[3].clone(),
                gross_input: row[4].clone(),
                minimum_output: row[5].clone(),
                anchor_creation_id: row[6].clone(),
                anchor_slot: row[7].clone(),
            },
        })
        .collect::<Vec<_>>();
    let descriptors = markets.iter().map(|m| m.market.clone()).collect::<Vec<_>>();
    crate::acceptance::row_ledger_mark(b, &mut ledger, "trade: funded ordering");
    let executed = bind_global_trade_execution(
        b,
        context.parent_id,
        &descriptors,
        &execution_policies,
        &order,
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "trade: execution");
    for (row, priority) in routed.iter().zip(&executed.priorities) {
        for lane in 0..2 {
            pin_eq(b, &row[8 + lane], &priority[lane]);
        }
    }
    let outcomes = executed
        .steps
        .iter()
        .map(|step| {
            let selectors = (0..config.policies)
                .map(|i| {
                    let same = is_zero(b, &step.policy_index.add(&number(i as u128)));
                    mul(b, &step.live, &same)
                })
                .collect::<Vec<_>>();
            vec![
                step.live.clone(),
                weighted(b, &selectors, routed.iter().map(|row| row[2].clone())),
                step.quote.spent_input.clone(),
                step.quote.output.clone(),
            ]
        })
        .collect();
    let outcomes = route_sorted(b, outcomes, 4, |b, row| vec![value(b, &row[1])]);
    let payouts = (0..config.policies)
        .map(|i| {
            let p = &policies[i].policy;
            let row = &outcomes[i];
            pin_eq(b, &row[0], &p.input.live);
            pin_eq(b, &row[1], &p.input.live.scale(flat_const(i as u128)));
            let quotes =
                bind_trade_fee_quotes(b, &p.input.live, &funding[i].count, context.growth_per_slot);
            bind_trade_payouts(b, p, &funding[i], &row[2], &row[3], &quotes)
        })
        .collect::<Vec<_>>();
    bind_payout_actions(
        b,
        actions,
        &markets,
        &policies,
        &policy_pages,
        &policy_selectors,
        &payouts,
    );
    markets::bind_final_controls(b, &markets, &executed.markets, actions, definitions);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "trade: exact payouts and final markets");
    let authorizations = (0..config.policies)
        .map(|i| TradeOwnerStatementTrace {
            live: policies[i].policy.input.live.clone(),
            header_page: policy_pages[i].clone(),
            policy_index: policies[i].policy.input.live.scale(flat_const(i as u128)),
            authorization_id: funding[i].authorization_id.clone(),
            owner: policies[i].policy.input.owner.clone(),
        })
        .collect();
    TradeKernelTrace {
        authorizations,
        batch_roots,
    }
}

fn project_funding(
    b: &mut FieldR1csBuilder,
    capacity: usize,
    actions: &[FinancialActionTrace],
    markets: &[markets::MarketRow],
    policies: &[FlatTradePolicyTrace],
    pages: &[LinExpr],
    starts: &[Vec<LinExpr>],
    ends: &[Vec<LinExpr>],
) -> Vec<FlatTradeFundingRowTrace> {
    let mut rows = Vec::with_capacity(actions.len().max(capacity));
    for action in actions {
        let trade = is_zero(b, &action.operation.add(&number(80)));
        let input = mul(b, &action.live, &action.is_output.add_const(F128::ONE));
        let ordinal_zero = is_zero(b, &action.ordinal);
        let live = mul(b, &input, &ordinal_zero.add_const(F128::ONE));
        let live = mul(b, &live, &trade);
        let ordinal = bits(b, &action.ordinal, 11);
        let mut selected = LinExpr::zero();
        let mut policy_index = LinExpr::zero();
        for (i, policy) in policies.iter().enumerate() {
            let same = is_zero(b, &action.header_page.add(&pages[i]));
            let active = mul(b, &live, &same);
            let active = mul(b, &active, &policy.policy.input.live);
            let before = less_than(b, &ordinal, &starts[i]);
            let until = less_than(b, &ordinal, &ends[i]);
            let in_range = mul(b, &before.add_const(F128::ONE), &until);
            let hit = mul(b, &active, &in_range);
            let duplicate = mul(b, &selected, &hit);
            pin_zero(b, &duplicate);
            selected = selected.add(&hit);
            policy_index = policy_index.add(&hit.scale(flat_const(i as u128)));
        }
        pin_eq(b, &selected, &live);
        let packed = split_packed_input_value(b, &action.packed_value);
        let token = mul(b, &live, &action.native);
        let kind = mul(
            b,
            &live,
            action.opening.commitment.selector(NativeKind::TokenBalance),
        );
        pin_eq(b, &kind, &token);
        let token_amount = mul(b, &token, &action.opening.fields[4]);
        let token_amount = split_packed_input_value(b, &token_amount);
        let mut row = vec![
            live.clone(),
            policy_index,
            mul(b, &live, &action.ordinal),
            mul(b, &live, &action.slot),
            mul(b, &live, &packed.amount.value),
            mul(b, &live, &packed.creation_id.value),
            mul(b, &live, &action.root[0]),
            mul(b, &live, &action.root[1]),
            token.clone(),
        ];
        for field in &action.opening.fields[..4] {
            row.push(mul(b, &token, field));
        }
        row.extend([token_amount.amount.value, token_amount.creation_id.value]);
        rows.push(row);
    }
    rows.resize_with(rows.len().max(capacity).next_power_of_two(), || {
        vec![LinExpr::zero(); 15]
    });
    let rows = route_sorted(b, rows, 15, |b, row| {
        vec![value(b, &row[1]), value(b, &row[2])]
    });
    for row in &rows[capacity..] {
        pin_zero(b, &row[0]);
    }
    let _ = markets;
    rows.into_iter()
        .take(capacity)
        .map(|row| FlatTradeFundingRowTrace {
            policy_index: row[1].clone(),
            input: TradeFundingInputTrace {
                live: row[0].clone(),
                slot: row[3].clone(),
                amount: row[4].clone(),
                creation_id: row[5].clone(),
                root: [row[6].clone(), row[7].clone()],
                native: row[8].clone(),
                token_asset: [row[9].clone(), row[10].clone()],
                token_owner: [row[11].clone(), row[12].clone()],
                token_units: row[13].clone(),
                unlock_height: row[14].clone(),
            },
        })
        .collect()
}

fn bind_batch_roots(
    b: &mut FieldR1csBuilder,
    markets: &[markets::MarketRow],
    policies: &[FlatTradePolicyTrace],
    funding: &[TradeFundingResultTrace],
    indices: &[LinExpr],
    selectors: &[Vec<LinExpr>],
) -> Vec<[LinExpr; 2]> {
    let count_width = (policies.len() + 1).next_power_of_two().trailing_zeros() as usize;
    let mut states = Vec::with_capacity(markets.len());
    for (i, m) in markets.iter().enumerate() {
        let mut count = vec![LinExpr::zero(); count_width];
        for selected in selectors {
            let mut delta = vec![LinExpr::zero(); count_width];
            delta[0] = selected[i].clone();
            count = checked_add(b, &count, &delta);
        }
        let frame = m
            .market
            .live
            .scale(flat_const(
                noid_tx::native_assets::trade::batch::TRADE_BATCH_VERSION as u128,
            ))
            .add(&m.market.curve.scale(flat_const(1 << 16)));
        states.push(hash_state(
            b,
            DomainTag::new(b"TRBCH_21"),
            &[
                m.source_root[0].clone(),
                m.source_root[1].clone(),
                m.source_creation_id.clone(),
                m.source_slot.clone(),
                m.market.asset[0].clone(),
                m.market.asset[1].clone(),
                pack(&count),
                frame,
            ],
        ));
    }
    for (i, p) in policies.iter().enumerate() {
        let selected: [LinExpr; 4] = std::array::from_fn(|lane| {
            weighted(b, &selectors[i], states.iter().map(|s| s[lane].clone()))
        });
        let mut next = selected;
        next[0] = next[0].add(&funding[i].authorization_id[0]);
        next[1] = next[1].add(&funding[i].authorization_id[1]);
        let next = poseidon2b_permute(b, next);
        for (j, state) in states.iter_mut().enumerate() {
            for lane in 0..4 {
                state[lane] = select(b, &selectors[i][j], &state[lane], &next[lane]);
            }
        }
        let _ = (p, &indices[i]);
    }
    markets
        .iter()
        .zip(states)
        .map(|(m, state)| {
            let root = std::array::from_fn(|lane| mul(b, &m.market.live, &state[lane]));
            for lane in 0..2 {
                pin_eq(b, &root[lane], &m.commitment[lane]);
            }
            root
        })
        .collect()
}

fn bind_payout_actions(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    markets: &[markets::MarketRow],
    policies: &[FlatTradePolicyTrace],
    pages: &[LinExpr],
    selectors: &[Vec<LinExpr>],
    payouts: &[TradePayoutsTrace],
) {
    let capacity = (3 * policies.len()).next_power_of_two();
    let mut expected = Vec::with_capacity(capacity);
    for (i, payout) in payouts.iter().enumerate() {
        for (rank, p) in payout.payouts.iter().enumerate() {
            let live = &p.live;
            let token = &p.token;
            let mut row = vec![
                live.clone(),
                mul(b, live, &pages[i]),
                live.scale(flat_const((3 * i + rank) as u128)),
                token.clone(),
            ];
            row.extend(p.owner.iter().cloned());
            row.extend(
                policies[i]
                    .policy
                    .input
                    .asset
                    .iter()
                    .map(|v| mul(b, token, v)),
            );
            row.push(p.units.clone());
            expected.push(row);
        }
    }
    expected.resize_with(capacity, || vec![LinExpr::zero(); 9]);
    let mut expected = route_sorted(b, expected, 9, |b, row| {
        vec![value(b, &row[1]), value(b, &row[2])]
    });
    let mut count = vec![LinExpr::zero(); 11];
    let mut previous_page = LinExpr::zero();
    for row in &mut expected {
        let same = is_zero(b, &row[1].add(&previous_page));
        let continued = mul(b, &same, &row[0]);
        let ordinal = count
            .iter()
            .map(|bit| mul(b, &continued, bit))
            .collect::<Vec<_>>();
        row[2] = pack(&ordinal);
        let mut one = vec![LinExpr::zero(); 11];
        one[0] = row[0].clone();
        count = checked_add(b, &ordinal, &one);
        previous_page = row[1].clone();
    }
    let mut actual = Vec::with_capacity(actions.len().max(capacity));
    for action in actions {
        let mut live = LinExpr::zero();
        for m in markets {
            let same = is_zero(b, &action.header_page.add(&m.header_page));
            let selected = mul(b, &same, &m.market.live);
            let selected = mul(b, &selected, &action.live);
            let output = mul(b, &selected, &action.is_output);
            let end = is_zero(b, &action.ordinal.add(&m.last_output));
            let payout = mul(b, &output, &end.add_const(F128::ONE));
            live = live.add(&payout);
        }
        let token = mul(b, &live, &action.native);
        let kind = mul(
            b,
            &live,
            action.opening.commitment.selector(NativeKind::TokenBalance),
        );
        pin_eq(b, &kind, &token);
        let ordinary = live.add(&token);
        let packed = split_packed_input_value(b, &action.packed_value);
        let amount = mul(b, &token, &action.opening.fields[4]);
        let amount = split_packed_input_value(b, &amount);
        pin_zero(b, &amount.creation_id.value);
        let owner = std::array::from_fn::<_, 2, _>(|lane| {
            mul(b, &ordinary, &action.root[lane]).add(&mul(
                b,
                &token,
                &action.opening.fields[2 + lane],
            ))
        });
        let units = mul(b, &ordinary, &packed.amount.value).add(&amount.amount.value);
        actual.push(vec![
            live.clone(),
            mul(b, &live, &action.header_page),
            mul(b, &live, &action.ordinal),
            token.clone(),
            owner[0].clone(),
            owner[1].clone(),
            mul(b, &token, &action.opening.fields[0]),
            mul(b, &token, &action.opening.fields[1]),
            units,
        ]);
    }
    actual.resize_with(actual.len().max(capacity).next_power_of_two(), || {
        vec![LinExpr::zero(); 9]
    });
    let actual = route_sorted(b, actual, 9, |b, row| {
        vec![value(b, &row[1]), value(b, &row[2])]
    });
    for row in &actual[capacity..] {
        pin_zero(b, &row[0]);
    }
    for (a, c) in actual.iter().take(capacity).zip(&expected) {
        for lane in 0..9 {
            pin_eq(b, &a[lane], &c[lane]);
        }
    }
    for (i, m) in markets.iter().enumerate() {
        let mut fee = vec![LinExpr::zero(); 64];
        let mut count = vec![LinExpr::zero(); 11];
        for (j, p) in payouts.iter().enumerate() {
            let f = mul(b, &selectors[j][i], &p.fee);
            let n = mul(b, &selectors[j][i], &p.output_count);
            let f = bits(b, &f, 64);
            let n = bits(b, &n, 11);
            fee = checked_add(b, &fee, &f);
            count = checked_add(b, &count, &n);
        }
        pin_eq(b, &pack(&fee), &m.fee);
        let mut one = vec![LinExpr::zero(); 11];
        one[0] = m.market.live.clone();
        let count = checked_add(b, &count, &one);
        pin_eq(b, &pack(&count), &m.output_count);
    }
}
