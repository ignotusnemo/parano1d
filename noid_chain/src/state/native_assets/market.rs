// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact State application for block-derived market registration plans.

use crate::{ChainState, SlotValue};
use noid_poseidon2b::primitives::{Address, Digest};
use noid_tx::native_assets::{
    market::{
        clearing::BatchSettlement,
        queue::{FundedRequestRef, RegisteredBatch, MAX_ROUND_REQUESTS},
        request::RequestValue,
        MarketDefinition, MarketError, MarketPayout, PoolId, PoolState, SwapClaim, NOID_ASSET,
    },
    native_creation_id, native_sequence, NATIVE_SEQUENCE_MAX,
};
use std::collections::{BTreeMap, BTreeSet};

pub mod liquidity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentPool {
    pub slot_index: u32,
    pub creation_id: u64,
    pub definition: MarketDefinition,
    pub pool: PoolState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationEffects<T = noid_tx::native_assets::market::SwapRequest> {
    pub state_root: Digest,
    pub batches: Vec<RegisteredBatch<T>>,
    pub controls: Vec<(u32, u64, PoolState)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundedClaimRef {
    pub slot_index: u32,
    pub creation_id: u64,
    pub claim: SwapClaim,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementEffects {
    pub state_root: Digest,
    pub settlement: BatchSettlement,
    pub control: (u32, u64, PoolState),
    pub claims: Vec<(u32, u64, SwapClaim)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefundEffects {
    pub state_root: Digest,
    pub fee: u64,
    pub claims: Vec<(u32, u64, SwapClaim)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutEffects {
    pub state_root: Digest,
    pub fee: u64,
    pub payouts: Vec<(u32, u64, MarketPayout)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketApplyError {
    Inactive,
    Semantic(MarketError),
    Bounds,
    State,
    Input,
    Output,
    Allocator,
    Supply,
}
impl core::fmt::Display for MarketApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "market State: {self:?}")
    }
}
impl std::error::Error for MarketApplyError {}
impl From<MarketError> for MarketApplyError {
    fn from(e: MarketError) -> Self {
        Self::Semantic(e)
    }
}

/// The block adapter supplies every admitted request and its parent control.
/// A single atomic plan fixes one successor for each touched pool.
pub fn apply_block_registrations<T: RequestValue>(
    state: &mut ChainState,
    height: u64,
    pools: &[ParentPool],
    requests: &[FundedRequestRef<T>],
    output_slots: &[u32],
) -> Result<RegistrationEffects<T>, MarketApplyError> {
    if !crate::consensus::params::v2_1_active(height) {
        return Err(MarketApplyError::Inactive);
    }
    if pools.is_empty()
        || pools.len() > MAX_ROUND_REQUESTS
        || requests.is_empty()
        || requests.len() > MAX_ROUND_REQUESTS
        || output_slots.len() != pools.len()
    {
        return Err(MarketApplyError::Bounds);
    }
    let mut parent_slots = BTreeSet::new();
    let mut ids = BTreeSet::<PoolId>::new();
    let mut by_round = BTreeMap::new();
    for pool in pools {
        pool.pool.check_definition(pool.definition)?;
        let sequence = native_sequence(pool.creation_id).map_err(|_| MarketApplyError::Input)?;
        if sequence > state.alloc_counter {
            return Err(MarketApplyError::Input);
        }
        if !parent_slots.insert(pool.slot_index) || !ids.insert(pool.pool.pool) {
            return Err(MarketApplyError::Input);
        }
        require_slot(
            state,
            pool.slot_index,
            SlotValue::with_owner_fields(
                pool.pool.noid_value(),
                pool.creation_id,
                pool.pool.root().as_fields(),
            ),
        )?;
        let round = pool.pool.round_id(height)?;
        if by_round.insert(round, (pool, Vec::new())).is_some() {
            return Err(MarketApplyError::Input);
        }
    }
    let mut request_slots = BTreeSet::new();
    for request in requests {
        request.validate()?;
        if native_sequence(request.creation_id).map_err(|_| MarketApplyError::Input)?
            > state.alloc_counter
        {
            return Err(MarketApplyError::Input);
        }
        if parent_slots.contains(&request.slot_index) || !request_slots.insert(request.slot_index) {
            return Err(MarketApplyError::Input);
        }
        let (pool, list) = by_round
            .get_mut(&request.request.round())
            .ok_or(MarketError::Generation)?;
        request
            .request
            .check_round(pool.definition, pool.pool, height)?;
        require_slot(
            state,
            request.slot_index,
            SlotValue::with_owner_fields(
                request.request.noid_value()?,
                request.creation_id,
                request.root().as_fields(),
            ),
        )?;
        list.push(*request);
    }
    let mut grouped = by_round.into_values().collect::<Vec<_>>();
    grouped.sort_by_key(|(p, _)| p.pool.pool);
    let mut batches = Vec::with_capacity(pools.len());
    for (pool, list) in &grouped {
        batches.push(RegisteredBatch::register(
            pool.definition,
            pool.pool,
            height,
            list,
        )?);
    }
    let mut used = BTreeSet::new();
    for &slot in output_slots {
        if parent_slots.contains(&slot) || request_slots.contains(&slot) || !used.insert(slot) {
            return Err(MarketApplyError::Output);
        }
        require_slot(state, slot, SlotValue::EMPTY).map_err(|_| MarketApplyError::Output)?;
    }
    let allocator = state
        .alloc_counter
        .checked_add(pools.len() as u64)
        .filter(|n| *n <= NATIVE_SEQUENCE_MAX)
        .ok_or(MarketApplyError::Allocator)?;
    let mut delta = Vec::with_capacity(2 * pools.len());
    let mut controls = Vec::with_capacity(pools.len());
    for (index, ((parent, _), batch)) in grouped.iter().zip(&batches).enumerate() {
        let creation = native_creation_id(state.alloc_counter + index as u64 + 1)
            .map_err(|_| MarketApplyError::Allocator)?;
        let next = batch.after();
        let slot = output_slots[index];
        delta.push((parent.slot_index, SlotValue::EMPTY));
        delta.push((
            slot,
            SlotValue::with_owner_fields(next.noid_value(), creation, next.root().as_fields()),
        ));
        controls.push((slot, creation, next));
    }
    let mut next = state.clone();
    let supply = next
        .supply_after_slot_updates(&delta)
        .ok_or(MarketApplyError::Supply)?;
    if supply != next.circulating_supply_micronoid {
        return Err(MarketApplyError::Supply);
    }
    next.state
        .apply_delta_unrooted(&delta)
        .map_err(|_| MarketApplyError::State)?;
    next.alloc_counter = allocator;
    let state_root = next.try_state_root().map_err(|_| MarketApplyError::State)?;
    *state = next;
    Ok(RegistrationEffects {
        state_root,
        batches,
        controls,
    })
}

/// Consume the frozen control and its complete funded set in one State update.
pub fn apply_batch_settlement(
    state: &mut ChainState,
    height: u64,
    parent: ParentPool,
    requests: &[FundedRequestRef],
    output_slots: &[u32],
) -> Result<SettlementEffects, MarketApplyError> {
    require_active(height)?;
    if output_slots.len() != requests.len() + 1 {
        return Err(MarketApplyError::Bounds);
    }
    let batch = RegisteredBatch::from_frozen(parent.definition, parent.pool, requests)?;
    let fee = protocol_fee(state, requests.len() + 1, output_slots.len());
    let settlement = BatchSettlement::calculate(parent.definition, &batch, height, fee)?;
    let mut inputs = vec![pool_input(parent)];
    inputs.extend(
        batch
            .requests()
            .iter()
            .map(|r| {
                Ok((
                    r.slot_index,
                    native_slot(r.creation_id, r.request.noid_value()?, r.root()),
                ))
            })
            .collect::<Result<Vec<_>, MarketError>>()?,
    );
    let after = settlement.after();
    let mut outputs = vec![ExactOutput {
        slot: output_slots[0],
        amount: after.noid_value(),
        root: after.root(),
        native: true,
    }];
    for (&slot, claim) in output_slots[1..].iter().zip(settlement.claims()) {
        outputs.push(ExactOutput {
            slot,
            amount: claim.noid_value()?,
            root: claim.root(),
            native: true,
        });
    }
    let (state_root, incarnations) = apply_exact_updates(state, &inputs, &outputs, fee)?;
    let control = (output_slots[0], incarnations[0], after);
    let claims = output_slots[1..]
        .iter()
        .zip(&incarnations[1..])
        .zip(settlement.claims())
        .map(|((&slot, &id), &claim)| (slot, id, claim))
        .collect();
    Ok(SettlementEffects {
        state_root,
        settlement,
        control,
        claims,
    })
}

/// Open the next pool generation after the refund boundary. Old funded
/// requests retain independent principal and fee-credit refund rights.
pub fn apply_pool_timeout_reset(
    state: &mut ChainState,
    height: u64,
    parent: ParentPool,
    output_slot: u32,
) -> Result<(Digest, u64, PoolState), MarketApplyError> {
    require_active(height)?;
    parent.pool.check_definition(parent.definition)?;
    let after = parent.pool.reset_after_timeout(height)?;
    let output = ExactOutput {
        slot: output_slot,
        amount: after.noid_value(),
        root: after.root(),
        native: true,
    };
    let (root, incarnations) = apply_exact_updates(state, &[pool_input(parent)], &[output], 0)?;
    Ok((root, incarnations[0], after))
}

/// Expired requests release their own escrow without requiring an old control.
pub fn apply_timed_out_requests(
    state: &mut ChainState,
    height: u64,
    requests: &[FundedRequestRef],
    output_slots: &[u32],
) -> Result<RefundEffects, MarketApplyError> {
    require_active(height)?;
    if requests.is_empty()
        || requests.len() > MAX_ROUND_REQUESTS
        || output_slots.len() != requests.len()
    {
        return Err(MarketApplyError::Bounds);
    }
    let mut ordered = requests.to_vec();
    ordered.sort_by_cached_key(|r| r.key());
    let mut keys = BTreeSet::new();
    let fee = protocol_fee(state, requests.len(), output_slots.len());
    let count = requests.len() as u64;
    let mut claims = Vec::with_capacity(requests.len());
    let mut inputs = Vec::with_capacity(requests.len());
    let mut outputs = Vec::with_capacity(requests.len());
    for (index, (&slot, r)) in output_slots.iter().zip(&ordered).enumerate() {
        if !keys.insert(r.key()) {
            return Err(MarketError::Duplicate.into());
        }
        let charged = fee / count + u64::from((index as u64) < fee % count);
        let claim = SwapClaim::timeout_refund(*r, height, charged)?;
        inputs.push((
            r.slot_index,
            native_slot(r.creation_id, r.request.noid_value()?, r.root()),
        ));
        outputs.push(ExactOutput {
            slot,
            amount: claim.noid_value()?,
            root: claim.root(),
            native: true,
        });
        claims.push(claim);
    }
    let (state_root, incarnations) = apply_exact_updates(state, &inputs, &outputs, fee)?;
    let claims = output_slots
        .iter()
        .zip(incarnations)
        .zip(claims)
        .map(|((&slot, id), claim)| (slot, id, claim))
        .collect();
    Ok(RefundEffects {
        state_root,
        fee,
        claims,
    })
}

/// Materialize the fixed beneficiaries of a claim; the caller chooses only
/// empty destination slots. The current occupancy fixes the protocol fee.
pub fn apply_claim_payout(
    state: &mut ChainState,
    height: u64,
    funded: FundedClaimRef,
    output_slots: &[u32],
) -> Result<PayoutEffects, MarketApplyError> {
    require_active(height)?;
    let preliminary = funded.claim.payouts(0)?;
    let fee = protocol_fee(state, 1, preliminary.len());
    let payouts = funded.claim.payouts(fee)?;
    if payouts.len() != preliminary.len() || output_slots.len() != payouts.len() {
        return Err(MarketApplyError::Bounds);
    }
    let mut outputs = Vec::with_capacity(payouts.len());
    for (&slot, payout) in output_slots.iter().zip(&payouts) {
        let root = if payout.asset == NOID_ASSET {
            payout.owner
        } else {
            let opening = noid_tx::native_assets::NativeOpening::TokenBalance(
                noid_tx::native_assets::TokenBalance {
                    asset: payout.asset,
                    owner: payout.owner,
                    units: payout.units,
                    unlock_height: 0,
                },
            );
            opening.validate().map_err(|_| MarketApplyError::Output)?;
            opening.root()
        };
        outputs.push(ExactOutput {
            slot,
            amount: if payout.asset == NOID_ASSET {
                payout.units
            } else {
                0
            },
            root,
            native: payout.asset != NOID_ASSET,
        });
    }
    let input = (
        funded.slot_index,
        native_slot(
            funded.creation_id,
            funded.claim.noid_value()?,
            funded.claim.root(),
        ),
    );
    let (state_root, incarnations) = apply_exact_updates(state, &[input], &outputs, fee)?;
    let payouts = output_slots
        .iter()
        .zip(incarnations)
        .zip(payouts)
        .map(|((&slot, id), payout)| (slot, id, payout))
        .collect();
    Ok(PayoutEffects {
        state_root,
        fee,
        payouts,
    })
}

#[derive(Clone, Copy)]
pub(super) struct ExactOutput {
    pub(super) slot: u32,
    pub(super) amount: u64,
    pub(super) root: Address,
    pub(super) native: bool,
}

fn require_active(height: u64) -> Result<(), MarketApplyError> {
    if crate::consensus::params::v2_1_active(height) {
        Ok(())
    } else {
        Err(MarketApplyError::Inactive)
    }
}

fn protocol_fee(state: &ChainState, inputs: usize, outputs: usize) -> u64 {
    crate::consensus::fees::fee_breakdown(
        inputs as u64,
        outputs as u64,
        state.active_slot_count,
        state.state.log_slots() as u32,
    )
    .required_total
}

pub(super) fn native_slot(creation: u64, amount: u64, root: Address) -> SlotValue {
    SlotValue::with_owner_fields(amount, creation, root.as_fields())
}

fn pool_input(parent: ParentPool) -> (u32, SlotValue) {
    (
        parent.slot_index,
        native_slot(
            parent.creation_id,
            parent.pool.noid_value(),
            parent.pool.root(),
        ),
    )
}

pub(super) fn apply_exact_updates(
    state: &mut ChainState,
    inputs: &[(u32, SlotValue)],
    outputs: &[ExactOutput],
    fee: u64,
) -> Result<(Digest, Vec<u64>), MarketApplyError> {
    let kinds = vec![true; inputs.len()];
    apply_updates_with_input_kinds(state, None, inputs, outputs, fee, &kinds)
}

pub(super) fn apply_updates_with_input_kinds(
    state: &mut ChainState,
    height: Option<u64>,
    inputs: &[(u32, SlotValue)],
    outputs: &[ExactOutput],
    fee: u64,
    kinds: &[bool],
) -> Result<(Digest, Vec<u64>), MarketApplyError> {
    if kinds.len() != inputs.len() {
        return Err(MarketApplyError::Input);
    }
    let allocator = state
        .alloc_counter
        .checked_add(outputs.len() as u64)
        .filter(|&n| n <= NATIVE_SEQUENCE_MAX)
        .ok_or(MarketApplyError::Allocator)?;
    let active = state
        .active_slot_count
        .checked_sub(inputs.len() as u64)
        .and_then(|n| n.checked_add(outputs.len() as u64))
        .filter(|&n| n <= state.num_slots())
        .ok_or(MarketApplyError::Bounds)?;
    let mut occupied = BTreeSet::new();
    let mut delta = Vec::with_capacity(inputs.len() + outputs.len());
    for (&(slot, expected), &native) in inputs.iter().zip(kinds) {
        let valid = if native {
            native_sequence(expected.creation_id()).is_ok_and(|n| n <= state.alloc_counter)
        } else {
            native_sequence(expected.creation_id()).is_err()
                && height.is_some_and(|h| {
                    crate::consensus::params::creation_id_within_boundary(
                        expected.creation_id(),
                        state.alloc_counter,
                        h,
                    )
                })
        };
        if !valid || !occupied.insert(slot) {
            return Err(MarketApplyError::Input);
        }
        require_slot(state, slot, expected)?;
        delta.push((slot, SlotValue::EMPTY));
    }
    let mut incarnations = Vec::with_capacity(outputs.len());
    for (index, output) in outputs.iter().enumerate() {
        if !occupied.insert(output.slot) {
            return Err(MarketApplyError::Output);
        }
        require_slot(state, output.slot, SlotValue::EMPTY).map_err(|_| MarketApplyError::Output)?;
        let sequence = state.alloc_counter + index as u64 + 1;
        let creation = if output.native {
            native_creation_id(sequence).map_err(|_| MarketApplyError::Allocator)?
        } else {
            sequence
        };
        incarnations.push(creation);
        delta.push((
            output.slot,
            native_slot(creation, output.amount, output.root),
        ));
    }
    let mut next = state.clone();
    let supply = next
        .supply_after_slot_updates(&delta)
        .ok_or(MarketApplyError::Supply)?;
    if Some(supply)
        != next
            .circulating_supply_micronoid
            .checked_sub(u128::from(fee))
    {
        return Err(MarketApplyError::Supply);
    }
    next.state
        .apply_delta_unrooted(&delta)
        .map_err(|_| MarketApplyError::State)?;
    next.alloc_counter = allocator;
    next.active_slot_count = active;
    next.circulating_supply_micronoid = supply;
    let root = next.try_state_root().map_err(|_| MarketApplyError::State)?;
    *state = next;
    Ok((root, incarnations))
}

pub(super) fn require_slot(
    state: &ChainState,
    slot: u32,
    expected: SlotValue,
) -> Result<(), MarketApplyError> {
    if u64::from(slot) >= state.num_slots() {
        return Err(MarketApplyError::Bounds);
    }
    let segment = (slot >> state.state.effective_log_segment_size()) as u16;
    if state.state.is_evicted(segment) {
        return Err(MarketApplyError::State);
    }
    if state.state.slot(slot) != expected {
        return Err(MarketApplyError::Input);
    }
    Ok(())
}
