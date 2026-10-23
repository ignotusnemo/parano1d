// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Selected native markets, exact payouts and shared class resources.

use super::*;
use noid_chain::mempool::{BlockSelectionBudget, NativeResourceUsage};
use noid_chain::state::native_assets::{
    market::liquidity::MarketFeeContext, trade::quote_trade_charge,
};
use noid_mempool::V2MiningReservation;
use noid_tx::native_assets::{
    trade::{
        batch::{TradeBatch, TradeParent},
        execution::{TradeExecution, TradeFeeQuotes, TradeOutputSlots},
        sequencing::{SequencingPlan, TradeBoundary},
        TradeIntent,
    },
    wire::NativeIntent,
    AssetId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub(super) struct Assembly {
    pub reservation: V2MiningReservation,
    pub intents: Vec<NativeIntent>,
    pub batches: Vec<TradeBatch>,
}

pub(super) struct Selection {
    pub candidate_index: usize,
    pub entries: Vec<noid_mempool::SelectedMempoolEntry>,
    pub pending_outputs: HashSet<u32>,
    pub intents: Vec<NativeIntent>,
    pub batches: Vec<TradeBatch>,
    pub authorizations: Vec<(noid_poseidon2b::primitives::TxBodyHash, Vec<u8>)>,
}

pub(super) async fn select(
    builder: &TemplateBuilder,
    snapshot: &TemplateChainSnapshot,
    small: BlockSelectionBudget,
    large: Option<BlockSelectionBudget>,
    epoch_anchor: [u8; 32],
) -> Result<Selection, String> {
    let height = snapshot
        .parent
        .height
        .checked_add(1)
        .ok_or("height exhausted")?;
    if std::iter::once(small).chain(large).all(|budget| {
        budget
            .financial
            .is_none_or(|financial| financial.policies == 0)
    }) {
        return builder
            .mempool
            .select_for_v2_mining(small, large, height, epoch_anchor)
            .await
            .map(|mempool| Selection {
                candidate_index: usize::from(mempool.large_class),
                entries: mempool.entries,
                pending_outputs: mempool.pending_outputs,
                intents: Vec::new(),
                batches: Vec::new(),
                authorizations: Vec::new(),
            })
            .map_err(|error| error.to_string());
    }
    let budgets: Vec<_> = std::iter::once(small).chain(large).collect();
    select_candidates(builder, snapshot, &budgets, epoch_anchor).await
}

pub(super) async fn select_candidates(
    builder: &TemplateBuilder,
    snapshot: &TemplateChainSnapshot,
    budgets: &[BlockSelectionBudget],
    epoch_anchor: [u8; 32],
) -> Result<Selection, String> {
    if !(1..=3).contains(&budgets.len()) {
        return Err("mining class candidate count".into());
    }
    let height = snapshot
        .parent
        .height
        .checked_add(1)
        .ok_or("height exhausted")?;
    let parent_id = block_id(&snapshot.parent);
    let policies = builder
        .mempool
        .trade_mining_snapshot(snapshot.parent.height, parent_id, epoch_anchor)
        .await
        .map_err(|error| error.to_string())?;
    let boundary = TradeBoundary {
        chain: noid_chain::state::native_assets::native_chain_id(),
        parent_id,
        epoch_anchor,
        height,
    };
    let placement = placement(snapshot, !policies.intents.is_empty())?;
    let prepare = |budget| {
        install_history_step_phase_cpu(|| {
            assemble(
                snapshot,
                &placement,
                &policies.intents,
                budget,
                &policies.pending_outputs,
                boundary,
            )
        })
        .map_err(|error| error.to_string())?
    };
    let mut reservations = Vec::with_capacity(budgets.len());
    let mut payloads = Vec::with_capacity(budgets.len());
    for budget in budgets {
        let Assembly {
            reservation,
            intents,
            batches,
        } = prepare(*budget)?;
        reservations.push(reservation);
        payloads.push((intents, batches));
    }
    let selected = builder
        .mempool
        .select_for_mining_candidates(
            snapshot.parent.height,
            parent_id,
            epoch_anchor,
            reservations,
        )
        .await
        .map_err(|error| error.to_string())?;
    let payload = payloads
        .get_mut(selected.candidate_index)
        .ok_or("selected class payload unavailable")?;
    let (intents, batches) = std::mem::take(payload);
    Ok(Selection {
        candidate_index: selected.candidate_index,
        entries: selected.entries,
        pending_outputs: selected.pending_outputs,
        intents,
        batches,
        authorizations: selected.trade_authorizations,
    })
}

fn placement(snapshot: &TemplateChainSnapshot, active: bool) -> Result<ChainState, String> {
    let mut placement = snapshot.state.clone();
    if active {
        snapshot
            .hydrate_coinbase_reuse_segment(&mut placement)
            .map_err(|error| error.to_string())?;
        let log_slots = noid_chain::consensus::expected_child_log_slots(
            snapshot.parent.height,
            snapshot.parent.log_slots,
            &snapshot.finalized_active_counts,
        );
        if log_slots > snapshot.parent.log_slots {
            placement.expand_one();
        }
    }
    Ok(placement)
}

#[derive(Debug, Clone)]
pub struct TradeProjection {
    pub pending_policies: usize,
    pub selected_policies: usize,
    pub selected_markets: usize,
    pub position: Option<usize>,
    pub outcome: Option<noid_tx::native_assets::trade::sequencing::TradeOutcome>,
    pub fee: Option<u64>,
    pub selected_ids: Vec<noid_poseidon2b::primitives::TxBodyHash>,
}

/// Assemble a checked wallet policy with the parent's authenticated pool view.
pub fn project_trade(
    snapshot: &TemplateChainSnapshot,
    pending: &noid_mempool::TradeMiningSnapshot,
    candidate: &TradeIntent,
    budget: BlockSelectionBudget,
) -> Result<TradeProjection, String> {
    let boundary = TradeBoundary {
        chain: noid_chain::state::native_assets::native_chain_id(),
        parent_id: block_id(&snapshot.parent),
        epoch_anchor: block_id(&snapshot.child_tx_epoch_anchor_header),
        height: snapshot
            .parent
            .height
            .checked_add(1)
            .ok_or("height exhausted")?,
    };
    candidate
        .checked(boundary.chain, boundary.epoch_anchor, boundary.height)
        .map_err(|e| e.to_string())?;
    let id = candidate.authorization_id().map_err(|e| e.to_string())?;
    let mut policies = pending.intents.clone();
    if policies
        .iter()
        .any(|policy| policy.authorization_id().ok() == Some(id))
    {
        return Err("wallet policy is already pending".into());
    }
    policies.push(Arc::new(candidate.clone()));
    let placement = placement(snapshot, true)?;
    let assembled = assemble(
        snapshot,
        &placement,
        &policies,
        budget,
        &pending.pending_outputs,
        boundary,
    )?;
    let mut projection = TradeProjection {
        pending_policies: pending.intents.len(),
        selected_policies: assembled.reservation.trade_ids.len(),
        selected_markets: assembled.batches.len(),
        position: None,
        outcome: None,
        fee: None,
        selected_ids: assembled.reservation.trade_ids,
    };
    for batch in &assembled.batches {
        if !batch
            .policies()
            .iter()
            .any(|p| p.authorization_id().ok() == Some(id))
        {
            continue;
        }
        let plan = batch.checked(boundary).map_err(|e| e.to_string())?;
        for (position, fill) in plan.fills().iter().enumerate() {
            if fill.authorization_id == id {
                let charge = quote_trade_charge(
                    candidate,
                    boundary,
                    fill.outcome,
                    MarketFeeContext::from_state(&snapshot.state),
                )
                .map_err(|e| e.to_string())?;
                projection.position = Some(position);
                projection.outcome = Some(fill.outcome);
                projection.fee = Some(charge.fee);
            }
        }
    }
    Ok(projection)
}

struct Group {
    batch: TradeBatch,
    intent: NativeIntent,
    resources: NativeResourceUsage,
    definitions: BTreeSet<[u8; 32]>,
    claimable_fees: u128,
}

fn stable_policies(
    parent: TradeParent,
    boundary: TradeBoundary,
    mut policies: Vec<TradeIntent>,
    fees: MarketFeeContext,
) -> Result<Vec<TradeIntent>, String> {
    while !policies.is_empty() {
        let plan = SequencingPlan::execute(parent.market, boundary, &policies)
            .map_err(|error| error.to_string())?;
        let mut accepted = vec![false; policies.len()];
        for fill in plan.fills() {
            accepted[fill.source_index] =
                quote_trade_charge(&policies[fill.source_index], boundary, fill.outcome, fees)
                    .is_ok();
        }
        if accepted.iter().all(|accepted| *accepted) {
            return Ok(policies);
        }
        policies = policies
            .into_iter()
            .zip(accepted)
            .filter_map(|(policy, accepted)| accepted.then_some(policy))
            .collect();
    }
    Ok(policies)
}

fn build_group(
    snapshot: &TemplateChainSnapshot,
    placement: &ChainState,
    boundary: TradeBoundary,
    parent: TradeParent,
    policies: Vec<TradeIntent>,
    reserved_outputs: &HashSet<u32>,
    existing_definitions: &BTreeSet<[u8; 32]>,
) -> Result<Option<Group>, String> {
    let batch = TradeBatch::new(parent, policies).map_err(|error| error.to_string())?;
    let plan = batch.checked(boundary).map_err(|error| error.to_string())?;
    let fees = MarketFeeContext::from_state(&snapshot.state);
    let mut payout_counts = vec![0; batch.policies().len()];
    for fill in plan.fills() {
        payout_counts[fill.source_index] = quote_trade_charge(
            &batch.policies()[fill.source_index],
            boundary,
            fill.outcome,
            fees,
        )
        .map_err(|error| error.to_string())?
        .payouts
        .len();
    }
    let count = payout_counts.iter().sum::<usize>() + 1;
    let Some(slots) = noid_chain::consensus::template::select_template_output_slots(
        placement,
        snapshot.parent.alloc_counter,
        count,
        reserved_outputs,
    ) else {
        return Ok(None);
    };
    let mut offset = 0;
    let payouts = payout_counts
        .into_iter()
        .map(|count| {
            let result = slots[offset..offset + count].to_vec();
            offset += count;
            result
        })
        .collect();
    let slots = TradeOutputSlots {
        payouts,
        market: *slots.last().expect("market successor slot"),
    };
    let fee_quotes = batch
        .policies()
        .iter()
        .map(|intent| {
            let mut quotes = [0; 3];
            for (index, quote) in quotes.iter_mut().enumerate() {
                *quote = fees
                    .required(intent.funding.len() + 1, index + 2)
                    .map_err(|error| error.to_string())?;
            }
            Ok(TradeFeeQuotes(quotes))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let execution = TradeExecution::new(&batch, boundary, &fee_quotes, &slots)
        .map_err(|error| error.to_string())?;
    let intent = NativeIntent::from_trade_execution(&execution, |root| {
        snapshot
            .store
            .native_payload(root.0)
            .ok()
            .flatten()
            .map(|record| record.opening)
    })
    .map_err(|error| error.to_string())?;
    let facts = intent
        .validate_structure()
        .map_err(|error| error.to_string())?;
    let definitions: BTreeSet<_> = intent
        .dependencies
        .iter()
        .filter(|opening| opening.is_auxiliary())
        .map(|opening| opening.root().0)
        .collect();
    let resources = NativeResourceUsage {
        headers: 1,
        records: intent.input_openings.iter().filter(|o| o.is_some()).count()
            + intent
                .output_openings
                .iter()
                .filter(|o| o.is_some())
                .count()
            + intent.dependencies.len(),
        actions: facts.live_inputs + facts.live_outputs,
        definitions: definitions.difference(existing_definitions).count(),
        markets: 1,
        policies: batch.policies().len(),
        funding: batch
            .policies()
            .iter()
            .map(|intent| intent.funding.len())
            .sum(),
        authorizations: batch.policies().len(),
        financial: true,
    };
    let burned = noid_chain::consensus::fee_breakdown(
        facts.live_inputs as u64,
        facts.live_outputs as u64,
        snapshot.parent.active_slot_count,
        snapshot.parent.log_slots,
    )
    .burned;
    Ok(Some(Group {
        batch,
        intent,
        resources,
        definitions,
        claimable_fees: u128::from(execution.fee().saturating_sub(burned)),
    }))
}

pub(super) fn assemble(
    snapshot: &TemplateChainSnapshot,
    placement: &ChainState,
    intents: &[Arc<TradeIntent>],
    budget: BlockSelectionBudget,
    pending_outputs: &HashSet<u32>,
    boundary: TradeBoundary,
) -> Result<Assembly, String> {
    let mut result = Assembly {
        reservation: V2MiningReservation::empty(budget),
        intents: Vec::new(),
        batches: Vec::new(),
    };
    if budget
        .financial
        .is_none_or(|financial| financial.policies == 0)
        || budget.native_headers == 0
    {
        return Ok(result);
    }
    let mut ranked = intents
        .iter()
        .filter_map(|intent| {
            intent
                .funding_priority(boundary.parent_id)
                .ok()
                .map(|priority| (priority, intent))
        })
        .collect::<Vec<_>>();
    ranked.sort_unstable_by_key(|(priority, _)| *priority);
    let mut assets = Vec::new();
    let mut grouped: BTreeMap<AssetId, Vec<_>> = BTreeMap::new();
    for (_, intent) in ranked {
        let group = grouped.entry(intent.policy.asset).or_insert_with(|| {
            assets.push(intent.policy.asset);
            Vec::new()
        });
        group.push(intent);
    }
    let fees = MarketFeeContext::from_state(&snapshot.state);
    for asset in assets {
        let remaining = result.reservation.remaining;
        let financial = remaining.financial.expect("financial class");
        if remaining.native_headers == 0
            || financial.markets == 0
            || financial.policies == 0
            || remaining.owner_authorizations == 0
        {
            break;
        }
        let Some(parent) = snapshot
            .store
            .native_trade_parent_at(asset, snapshot.parent.height, boundary.parent_id)
            .map_err(|error| error.to_string())?
        else {
            continue;
        };
        let mut outputs = pending_outputs.clone();
        outputs.extend(&result.reservation.occupied.outputs);
        let mut accepted: Vec<TradeIntent> = Vec::new();
        let mut selected = None;
        for intent in grouped.remove(&asset).expect("ranked market group") {
            if accepted.len() >= financial.policies.min(remaining.owner_authorizations) {
                break;
            }
            let funding =
                accepted.iter().map(|p| p.funding.len()).sum::<usize>() + intent.funding.len();
            if funding > financial.funding || funding + 1 > remaining.live_inputs {
                continue;
            }
            let mut trial = accepted.clone();
            trial.push((**intent).clone());
            let trial = stable_policies(parent, boundary, trial, fees)?;
            if trial.is_empty() || trial == accepted {
                continue;
            }
            let Some(group) = build_group(
                snapshot,
                placement,
                boundary,
                parent,
                trial.clone(),
                &outputs,
                &result.reservation.occupied.definitions,
            )?
            else {
                continue;
            };
            let facts = group
                .intent
                .resource_facts()
                .map_err(|error| error.to_string())?;
            let mut available = remaining;
            if available.try_consume(
                group.intent.pages.len(),
                usize::from(facts.live_inputs),
                0,
                group.resources,
            ) {
                accepted = trial;
                selected = Some((group, available));
            }
        }
        let Some((group, available)) = selected else {
            continue;
        };
        result.reservation.remaining = available;
        result.reservation.claimable_fees += group.claimable_fees;
        for policy in group.batch.policies() {
            result.reservation.trade_ids.push(
                policy
                    .authorization_id()
                    .map_err(|error| error.to_string())?,
            );
        }
        result.reservation.occupied.inputs.extend(
            group
                .batch
                .inputs()
                .map_err(|error| error.to_string())?
                .iter()
                .map(|claim| claim.input.slot_index),
        );
        result.reservation.occupied.outputs.extend(
            group
                .intent
                .pages
                .iter()
                .flat_map(|page| page.body.live_outputs())
                .map(|(_, output)| output.slot_index),
        );
        result
            .reservation
            .occupied
            .definitions
            .extend(group.definitions);
        result.intents.push(group.intent);
        result.batches.push(group.batch);
    }
    Ok(result)
}
