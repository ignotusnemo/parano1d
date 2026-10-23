// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Atomic launch funding, complete-set rounds and same-asset graduation.

use super::market::{
    apply_exact_updates, apply_updates_with_input_kinds, liquidity::MarketFeeContext, native_slot,
    require_slot, ExactOutput, MarketApplyError, RefundEffects,
};
use crate::ChainState;
use noid_poseidon2b::primitives::Digest;
use noid_tx::native_assets::{
    launch::{
        clearing::{LaunchOutcome, LaunchSettlement},
        owner::{check_launch_creation, check_launch_request},
        queue::{timeout_reset, LaunchRegisteredBatch, LaunchRequestRef},
        LaunchDefinition, LaunchError, LaunchId, LaunchOpening, LaunchState,
    },
    market::{queue::MAX_ROUND_REQUESTS, MarketOpening, SwapClaim},
    native_sequence,
    transition::{NativeContext, NativeInputClaim, NativeOutputClaim},
    FungibleDefinition, NativeOpening,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchApplyError {
    Inactive,
    Context,
    Bounds,
    Input,
    Fee,
    Semantic(LaunchError),
    State(MarketApplyError),
}
impl core::fmt::Display for LaunchApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "launch State: {self:?}")
    }
}
impl std::error::Error for LaunchApplyError {}
impl From<LaunchError> for LaunchApplyError {
    fn from(e: LaunchError) -> Self {
        Self::Semantic(e)
    }
}
impl From<MarketApplyError> for LaunchApplyError {
    fn from(e: MarketApplyError) -> Self {
        Self::State(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentLaunch {
    pub slot_index: u32,
    pub creation_id: u64,
    pub definition: LaunchDefinition,
    pub launch: LaunchState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchStateOutputs {
    pub state_root: Digest,
    pub outputs: Vec<(u32, u64, NativeOutputClaim)>,
    pub auxiliary: Vec<NativeOpening>,
}

fn require_active(height: u64) -> Result<(), LaunchApplyError> {
    if crate::consensus::params::v2_1_active(height) {
        Ok(())
    } else {
        Err(LaunchApplyError::Inactive)
    }
}

fn check_context(
    context: &NativeContext,
    inputs: usize,
    outputs: usize,
    fees: MarketFeeContext,
) -> Result<(), LaunchApplyError> {
    require_active(context.height)?;
    if context.chain != super::native_chain_id() {
        return Err(LaunchApplyError::Context);
    }
    if context.fee != fees.required(inputs, outputs)? {
        return Err(LaunchApplyError::Fee);
    }
    Ok(())
}

fn parent_input(parent: ParentLaunch) -> (u32, crate::SlotValue) {
    (
        parent.slot_index,
        native_slot(
            parent.creation_id,
            parent.launch.market_noid,
            parent.launch.root(),
        ),
    )
}

fn check_parent(state: &ChainState, parent: ParentLaunch) -> Result<(), LaunchApplyError> {
    parent.launch.check_definition(parent.definition)?;
    let sequence = native_sequence(parent.creation_id).map_err(|_| LaunchApplyError::Input)?;
    if sequence > state.alloc_counter {
        return Err(LaunchApplyError::Input);
    }
    let (slot, expected) = parent_input(parent);
    require_slot(state, slot, expected)?;
    Ok(())
}

fn apply_owner_claims(
    state: &mut ChainState,
    context: &NativeContext,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    auxiliary: Vec<NativeOpening>,
) -> Result<LaunchStateOutputs, LaunchApplyError> {
    let raw_inputs: Vec<_> = inputs
        .iter()
        .map(|c| {
            (
                c.input.slot_index,
                native_slot(c.input.creation_id, c.input.amount, c.root),
            )
        })
        .collect();
    let kinds: Vec<_> = inputs.iter().map(|c| c.opening.is_some()).collect();
    let raw_outputs: Vec<_> = outputs
        .iter()
        .map(|c| ExactOutput {
            slot: c.output.slot_index,
            amount: c.output.amount,
            root: c.output.owner,
            native: c.opening.is_some(),
        })
        .collect();
    let (state_root, ids) = apply_updates_with_input_kinds(
        state,
        Some(context.height),
        &raw_inputs,
        &raw_outputs,
        context.fee,
        &kinds,
    )?;
    Ok(LaunchStateOutputs {
        state_root,
        outputs: outputs
            .iter()
            .copied()
            .zip(ids)
            .map(|(c, id)| (c.output.slot_index, id, c))
            .collect(),
        auxiliary,
    })
}

/// The admitting block binds the exact Owner statement before committing
/// these outputs and the immutable auxiliary launch definition.
pub fn apply_owned_launch_creation(
    state: &mut ChainState,
    context: &NativeContext,
    token: FungibleDefinition,
    definition: LaunchDefinition,
    funding_input: u16,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    fees: MarketFeeContext,
) -> Result<LaunchStateOutputs, LaunchApplyError> {
    check_context(context, inputs.len(), outputs.len(), fees)?;
    check_launch_creation(context, token, definition, funding_input, inputs, outputs)?;
    apply_owner_claims(
        state,
        context,
        inputs,
        outputs,
        vec![NativeOpening::Launch(LaunchOpening::Definition(definition))],
    )
}

pub fn apply_owned_launch_request(
    state: &mut ChainState,
    context: &NativeContext,
    parent: ParentLaunch,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    fees: MarketFeeContext,
) -> Result<LaunchStateOutputs, LaunchApplyError> {
    check_context(context, inputs.len(), outputs.len(), fees)?;
    check_parent(state, parent)?;
    check_launch_request(context, parent.definition, parent.launch, inputs, outputs)?;
    apply_owner_claims(state, context, inputs, outputs, Vec::new())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRegistrationEffects {
    pub state_root: Digest,
    pub batches: Vec<LaunchRegisteredBatch>,
    pub controls: Vec<(u32, u64, LaunchState)>,
}

/// Every admitted request is supplied by the complete block extraction.
pub fn apply_block_launch_registrations(
    state: &mut ChainState,
    height: u64,
    parents: &[ParentLaunch],
    requests: &[LaunchRequestRef],
    output_slots: &[u32],
) -> Result<LaunchRegistrationEffects, LaunchApplyError> {
    require_active(height)?;
    if parents.is_empty()
        || parents.len() > MAX_ROUND_REQUESTS
        || requests.is_empty()
        || requests.len() > MAX_ROUND_REQUESTS
        || output_slots.len() != parents.len()
    {
        return Err(LaunchApplyError::Bounds);
    }
    let mut ids = BTreeSet::<LaunchId>::new();
    let mut occupied = BTreeSet::new();
    let mut groups = BTreeMap::new();
    for &parent in parents {
        check_parent(state, parent)?;
        if !ids.insert(parent.launch.launch) || !occupied.insert(parent.slot_index) {
            return Err(LaunchApplyError::Input);
        }
        let round = parent.launch.round_id(height)?;
        if groups.insert(round, (parent, Vec::new())).is_some() {
            return Err(LaunchApplyError::Input);
        }
    }
    for &r in requests {
        r.validate()?;
        if !occupied.insert(r.slot_index)
            || native_sequence(r.creation_id).map_err(|_| LaunchApplyError::Input)?
                > state.alloc_counter
        {
            return Err(LaunchApplyError::Input);
        }
        let (parent, list) = groups.get_mut(&r.request.round).ok_or(LaunchError::Round)?;
        r.request
            .check_round(parent.definition, parent.launch, height)?;
        require_slot(
            state,
            r.slot_index,
            native_slot(r.creation_id, r.request.noid_value()?, r.root()),
        )?;
        list.push(r);
    }
    let mut groups: Vec<_> = groups.into_values().collect();
    groups.sort_by_key(|(p, _)| p.launch.launch);
    let mut batches = Vec::with_capacity(groups.len());
    let mut inputs = Vec::with_capacity(groups.len());
    let mut outputs = Vec::with_capacity(groups.len());
    for ((parent, list), &slot) in groups.iter().zip(output_slots) {
        let batch =
            LaunchRegisteredBatch::register(parent.definition, parent.launch, height, list)?;
        inputs.push(parent_input(*parent));
        outputs.push(ExactOutput {
            slot,
            amount: batch.after().market_noid,
            root: batch.after().root(),
            native: true,
        });
        batches.push(batch);
    }
    let (state_root, ids) = apply_exact_updates(state, &inputs, &outputs, 0)?;
    let controls = output_slots
        .iter()
        .zip(ids)
        .zip(&batches)
        .map(|((&slot, id), b)| (slot, id, b.after()))
        .collect();
    Ok(LaunchRegistrationEffects {
        state_root,
        batches,
        controls,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSettlementEffects {
    pub state_root: Digest,
    pub settlement: LaunchSettlement,
    pub control: (u32, u64, NativeOpening),
    pub claims: Vec<(u32, u64, SwapClaim)>,
    pub auxiliary: Vec<NativeOpening>,
}

pub fn apply_launch_settlement(
    state: &mut ChainState,
    height: u64,
    parent: ParentLaunch,
    requests: &[LaunchRequestRef],
    output_slots: &[u32],
    fees: MarketFeeContext,
) -> Result<LaunchSettlementEffects, LaunchApplyError> {
    require_active(height)?;
    check_parent(state, parent)?;
    if output_slots.len() != requests.len() + 1 {
        return Err(LaunchApplyError::Bounds);
    }
    let batch = LaunchRegisteredBatch::from_frozen(parent.definition, parent.launch, requests)?;
    let fee = fees.required(requests.len() + 1, output_slots.len())?;
    let settlement = LaunchSettlement::calculate(parent.definition, &batch, height, fee)?;
    let mut inputs = vec![parent_input(parent)];
    for r in batch.requests() {
        inputs.push((
            r.slot_index,
            native_slot(r.creation_id, r.request.noid_value()?, r.root()),
        ));
    }
    let (control, auxiliary) = match settlement.outcome() {
        LaunchOutcome::Continue(s) => (NativeOpening::Launch(LaunchOpening::State(s)), Vec::new()),
        LaunchOutcome::Graduate(p) => (
            NativeOpening::Market(MarketOpening::Pool(p)),
            vec![NativeOpening::Market(MarketOpening::Definition(
                parent.definition.market_definition(),
            ))],
        ),
    };
    let mut outputs = vec![ExactOutput {
        slot: output_slots[0],
        amount: control.amount_micronoid(),
        root: control.root(),
        native: true,
    }];
    for (&slot, claim) in output_slots[1..].iter().zip(settlement.claims()) {
        outputs.push(ExactOutput {
            slot,
            amount: claim.noid_value().map_err(|_| LaunchError::Conservation)?,
            root: claim.root(),
            native: true,
        });
    }
    let (state_root, ids) = apply_exact_updates(state, &inputs, &outputs, settlement.fee())?;
    let claims = output_slots[1..]
        .iter()
        .zip(&ids[1..])
        .zip(settlement.claims())
        .map(|((&slot, &id), &claim)| (slot, id, claim))
        .collect();
    Ok(LaunchSettlementEffects {
        state_root,
        settlement,
        control: (output_slots[0], ids[0], control),
        claims,
        auxiliary,
    })
}

pub fn apply_launch_timeout_reset(
    state: &mut ChainState,
    height: u64,
    parent: ParentLaunch,
    output_slot: u32,
) -> Result<(Digest, u64, LaunchState), LaunchApplyError> {
    require_active(height)?;
    check_parent(state, parent)?;
    let after = timeout_reset(parent.definition, parent.launch, height)?;
    let output = ExactOutput {
        slot: output_slot,
        amount: after.market_noid,
        root: after.root(),
        native: true,
    };
    let (root, ids) = apply_exact_updates(state, &[parent_input(parent)], &[output], 0)?;
    Ok((root, ids[0], after))
}

pub fn apply_launch_timeout_refunds(
    state: &mut ChainState,
    height: u64,
    requests: &[LaunchRequestRef],
    output_slots: &[u32],
    fees: MarketFeeContext,
) -> Result<RefundEffects, LaunchApplyError> {
    require_active(height)?;
    if requests.is_empty()
        || requests.len() > MAX_ROUND_REQUESTS
        || output_slots.len() != requests.len()
    {
        return Err(LaunchApplyError::Bounds);
    }
    let mut requests = requests.to_vec();
    requests.sort_by_cached_key(|r| r.key());
    let fee = fees.required(requests.len(), output_slots.len())?;
    let count = requests.len() as u64;
    let mut inputs = Vec::with_capacity(requests.len());
    let mut outputs = Vec::with_capacity(requests.len());
    let mut claims = Vec::with_capacity(requests.len());
    for (index, (r, &slot)) in requests.iter().zip(output_slots).enumerate() {
        r.validate()?;
        let charged = fee / count + u64::from((index as u64) < fee % count);
        let claim = r.request.timeout_claim(r.key(), height, charged)?;
        inputs.push((
            r.slot_index,
            native_slot(r.creation_id, r.request.noid_value()?, r.root()),
        ));
        outputs.push(ExactOutput {
            slot,
            amount: claim.noid_value().map_err(|_| LaunchError::Conservation)?,
            root: claim.root(),
            native: true,
        });
        claims.push(claim);
    }
    let (state_root, ids) = apply_exact_updates(state, &inputs, &outputs, fee)?;
    Ok(RefundEffects {
        state_root,
        fee,
        claims: output_slots
            .iter()
            .zip(ids)
            .zip(claims)
            .map(|((&slot, id), claim)| (slot, id, claim))
            .collect(),
    })
}
