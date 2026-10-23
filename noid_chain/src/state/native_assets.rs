// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Atomic native asset updates of the exact raw State.

use super::ChainState;
use crate::fri_state::SlotValue;
use noid_poseidon2b::primitives::{Address, Digest};
use noid_tx::native_assets::{
    native_creation_id,
    transition::{
        check_native_transition, NativeContext, NativeInputClaim, NativeOperation,
        NativeOutputClaim, NativeTransitionError, NativeTransitionFacts,
    },
    NativeOpening, NATIVE_SEQUENCE_MAX,
};
use std::sync::OnceLock;

pub mod launch;
pub mod market;
pub mod nft_market;
pub mod trade;

pub fn native_chain_id() -> Digest {
    static ID: OnceLock<Digest> = OnceLock::new();
    *ID.get_or_init(|| crate::hash_block_header(&crate::consensus::genesis_header()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeCreatedOpening {
    pub slot_index: u32,
    pub creation_id: u64,
    pub opening: NativeOpening,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeConsumedOpening {
    pub slot_index: u32,
    pub creation_id: u64,
    pub root: Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeStateTransition {
    pub new_state_root: Digest,
    pub facts: NativeTransitionFacts,
    pub created_openings: Vec<NativeCreatedOpening>,
    pub consumed_openings: Vec<NativeConsumedOpening>,
}

pub(crate) struct DeferredNativeStateEffects {
    pub facts: NativeTransitionFacts,
    pub created_openings: Vec<NativeCreatedOpening>,
    pub consumed_openings: Vec<NativeConsumedOpening>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeApplyError {
    Inactive,
    ChainContext,
    Semantic(NativeTransitionError),
    SlotOutOfRange,
    ExactStateUnavailable,
    UnknownOrSpentInput,
    OutputSlotNotEmpty,
    AllocCounterOverflow,
    ActiveSlotCount,
    CirculatingSupply,
}

impl core::fmt::Display for NativeApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "native State: {self:?}")
    }
}
impl std::error::Error for NativeApplyError {}

/// Apply an operation atomically and return its live-payload storage changes.
/// The admitting block binds the claims to its body, Owner authorization and
/// recursive transition before committing the returned State and payloads.
pub fn apply_native_transition(
    state: &mut ChainState,
    context: &NativeContext,
    operation: NativeOperation,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<NativeStateTransition, NativeApplyError> {
    let mut snapshot = state.clone();
    let effects = apply_native_deferred_root(&mut snapshot, context, operation, inputs, outputs)?;
    let new_state_root = snapshot
        .try_state_root()
        .map_err(|_| NativeApplyError::ExactStateUnavailable)?;
    *state = snapshot;
    Ok(NativeStateTransition {
        new_state_root,
        facts: effects.facts,
        created_openings: effects.created_openings,
        consumed_openings: effects.consumed_openings,
    })
}

pub(crate) fn apply_native_deferred_root(
    state: &mut ChainState,
    context: &NativeContext,
    operation: NativeOperation,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<DeferredNativeStateEffects, NativeApplyError> {
    if !crate::consensus::params::v2_1_active(context.height) {
        return Err(NativeApplyError::Inactive);
    }
    if context.chain != native_chain_id() {
        return Err(NativeApplyError::ChainContext);
    }
    let facts = check_native_transition(context, operation, inputs, outputs)
        .map_err(NativeApplyError::Semantic)?;
    apply_checked_native_deferred_root(state, context, inputs, outputs, facts)
}

/// Shared raw allocator after the selected typed predicate has succeeded.
pub(crate) fn apply_checked_native_deferred_root(
    state: &mut ChainState,
    context: &NativeContext,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    facts: NativeTransitionFacts,
) -> Result<DeferredNativeStateEffects, NativeApplyError> {
    if !crate::consensus::params::v2_1_active(context.height) {
        return Err(NativeApplyError::Inactive);
    }
    if context.chain != native_chain_id() {
        return Err(NativeApplyError::ChainContext);
    }
    if facts.output_is_native.len() != outputs.len()
        || facts
            .output_is_native
            .iter()
            .zip(outputs)
            .any(|(&native, c)| native != c.opening.is_some())
        || facts.native_inputs != inputs.iter().filter(|c| c.opening.is_some()).count()
        || facts.native_outputs != outputs.iter().filter(|c| c.opening.is_some()).count()
    {
        return Err(NativeApplyError::Semantic(NativeTransitionError::Shape));
    }
    let log = state.state.effective_log_segment_size();
    let num_slots = state.state.num_slots();
    let mut delta = Vec::with_capacity(inputs.len() + outputs.len());
    let mut consumed_openings = Vec::with_capacity(facts.native_inputs);
    for claim in inputs {
        if u64::from(claim.input.slot_index) >= num_slots {
            return Err(NativeApplyError::SlotOutOfRange);
        }
        if state
            .state
            .is_evicted((claim.input.slot_index >> log) as u16)
        {
            return Err(NativeApplyError::ExactStateUnavailable);
        }
        let expected = SlotValue::with_owner_fields(
            claim.input.amount,
            claim.input.creation_id,
            claim.root.as_fields(),
        );
        if state.state.slot(claim.input.slot_index) != expected {
            return Err(NativeApplyError::UnknownOrSpentInput);
        }
        delta.push((claim.input.slot_index, SlotValue::EMPTY));
        if claim.opening.is_some() {
            consumed_openings.push(NativeConsumedOpening {
                slot_index: claim.input.slot_index,
                creation_id: claim.input.creation_id,
                root: claim.root,
            });
        }
    }
    let active_after = state
        .active_slot_count
        .checked_sub(inputs.len() as u64)
        .and_then(|n| n.checked_add(outputs.len() as u64))
        .ok_or(NativeApplyError::ActiveSlotCount)?;
    let final_allocator = state
        .alloc_counter
        .checked_add(outputs.len() as u64)
        .filter(|&n| n <= NATIVE_SEQUENCE_MAX)
        .ok_or(NativeApplyError::AllocCounterOverflow)?;
    let mut allocator = state.alloc_counter;
    let mut created_openings = Vec::with_capacity(facts.native_outputs);
    for (claim, &native) in outputs.iter().zip(&facts.output_is_native) {
        if u64::from(claim.output.slot_index) >= num_slots {
            return Err(NativeApplyError::SlotOutOfRange);
        }
        if state
            .state
            .is_evicted((claim.output.slot_index >> log) as u16)
        {
            return Err(NativeApplyError::ExactStateUnavailable);
        }
        if state.state.slot(claim.output.slot_index) != SlotValue::EMPTY {
            return Err(NativeApplyError::OutputSlotNotEmpty);
        }
        allocator += 1;
        let creation_id = if native {
            native_creation_id(allocator).map_err(|_| NativeApplyError::AllocCounterOverflow)?
        } else {
            allocator
        };
        delta.push((
            claim.output.slot_index,
            SlotValue::with_owner_fields(
                claim.output.amount,
                creation_id,
                claim.output.owner.as_fields(),
            ),
        ));
        if let Some(opening) = claim.opening {
            created_openings.push(NativeCreatedOpening {
                slot_index: claim.output.slot_index,
                creation_id,
                opening,
            });
        }
    }
    let supply = state
        .supply_after_slot_updates(&delta)
        .ok_or(NativeApplyError::CirculatingSupply)?;
    state
        .state
        .apply_delta_unrooted(&delta)
        .expect("native slot updates were preflighted");
    state.active_slot_count = active_after;
    state.alloc_counter = final_allocator;
    state.circulating_supply_micronoid = supply;
    Ok(DeferredNativeStateEffects {
        facts,
        created_openings,
        consumed_openings,
    })
}
