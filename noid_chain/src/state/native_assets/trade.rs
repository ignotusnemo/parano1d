// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Authorized sequential market groups and atomic State materialization.

use noid_poseidon2b::primitives::Address;
use noid_tx::native_assets::{
    trade::{
        batch::{BatchError, TradeBatch},
        execution::{quote_charge, TradeExecution, TradeExecutionError, TradeFeeQuotes},
        sequencing::{SequencingPlan, TradeBoundary, TradeOutcome},
        TradeError, TradeIntent,
    },
    transition::{NativeContext, NativeInputClaim, NativeOutputClaim},
    NativeOpening,
};

pub use noid_tx::native_assets::trade::execution::{TradeCharge, TradeOutputSlots};

use super::market::liquidity::MarketFeeContext;
use super::{
    apply_checked_native_deferred_root, native_chain_id, NativeApplyError, NativeStateTransition,
};
use crate::{ChainState, SlotValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TradeStateError {
    Inactive,
    Context,
    Batch(BatchError),
    Policy(TradeError),
    Fee,
    Inputs,
    Outputs,
    Conservation,
    Wire(noid_tx::native_assets::wire::NativeWireError),
    State(NativeApplyError),
}
impl core::fmt::Display for TradeStateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "trade State: {self:?}")
    }
}
impl std::error::Error for TradeStateError {}
impl From<BatchError> for TradeStateError {
    fn from(value: BatchError) -> Self {
        Self::Batch(value)
    }
}
impl From<TradeError> for TradeStateError {
    fn from(value: TradeError) -> Self {
        Self::Policy(value)
    }
}
impl From<NativeApplyError> for TradeStateError {
    fn from(value: NativeApplyError) -> Self {
        Self::State(value)
    }
}
impl From<TradeExecutionError> for TradeStateError {
    fn from(value: TradeExecutionError) -> Self {
        match value {
            TradeExecutionError::Context => Self::Context,
            TradeExecutionError::Batch(error) => Self::Batch(error),
            TradeExecutionError::Policy(error) => Self::Policy(error),
            TradeExecutionError::Fee => Self::Fee,
            TradeExecutionError::Inputs => Self::Inputs,
            TradeExecutionError::Outputs => Self::Outputs,
            TradeExecutionError::Conservation => Self::Conservation,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreparedTradeBatch {
    execution: TradeExecution,
    parent_log_slots: u32,
    child_log_slots: u32,
}
impl PreparedTradeBatch {
    pub fn boundary(&self) -> TradeBoundary {
        self.execution.boundary()
    }
    pub fn commitment(&self) -> Address {
        self.execution.commitment()
    }
    pub fn inputs(&self) -> &[NativeInputClaim] {
        self.execution.inputs()
    }
    pub fn outputs(&self) -> &[NativeOutputClaim] {
        self.execution.outputs()
    }
    pub fn charges(&self) -> &[TradeCharge] {
        self.execution.charges()
    }
    pub fn fee(&self) -> u64 {
        self.execution.fee()
    }
    pub fn plan(&self) -> &SequencingPlan {
        self.execution.plan()
    }
    pub fn auxiliary(&self) -> &[NativeOpening] {
        self.execution.auxiliary()
    }
    pub fn execution(&self) -> &TradeExecution {
        &self.execution
    }
    pub fn child_log_slots(&self) -> u32 {
        self.child_log_slots
    }
}

/// The admitting block verifies every Owner capsule against this complete set.
pub fn prepare_trade_batch(
    parent_state: &ChainState,
    boundary: TradeBoundary,
    batch: &TradeBatch,
    slots: &TradeOutputSlots,
) -> Result<PreparedTradeBatch, TradeStateError> {
    prepare_trade_batch_at_log_slots(
        parent_state,
        boundary,
        parent_state.state.log_slots() as u32,
        batch,
        slots,
    )
}

/// Child geometry and immutable-parent fee occupancy are distinct contexts.
/// Header acceptance establishes the canonical expansion trigger.
pub fn prepare_trade_batch_at_log_slots(
    parent_state: &ChainState,
    boundary: TradeBoundary,
    child_log_slots: u32,
    batch: &TradeBatch,
    slots: &TradeOutputSlots,
) -> Result<PreparedTradeBatch, TradeStateError> {
    preflight(parent_state, boundary, child_log_slots, batch)?;
    let quotes = trade_fee_quotes(parent_state, batch)?;
    let execution = TradeExecution::new(batch, boundary, &quotes, slots)?;
    finish_preparation(parent_state, child_log_slots, execution)
}

pub fn prepare_trade_batch_from_claims(
    parent_state: &ChainState,
    boundary: TradeBoundary,
    child_log_slots: u32,
    batch: &TradeBatch,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<PreparedTradeBatch, TradeStateError> {
    preflight(parent_state, boundary, child_log_slots, batch)?;
    let quotes = trade_fee_quotes(parent_state, batch)?;
    let execution = TradeExecution::from_claims(batch, boundary, &quotes, inputs, outputs)?;
    finish_preparation(parent_state, child_log_slots, execution)
}

pub fn prepare_trade_batch_from_intent(
    parent_state: &ChainState,
    boundary: TradeBoundary,
    child_log_slots: u32,
    batch: &TradeBatch,
    intent: &noid_tx::native_assets::wire::NativeIntent,
) -> Result<PreparedTradeBatch, TradeStateError> {
    preflight(parent_state, boundary, child_log_slots, batch)?;
    let quotes = trade_fee_quotes(parent_state, batch)?;
    let execution = intent
        .checked_trade(boundary, batch, &quotes)
        .map_err(TradeStateError::Wire)?;
    finish_preparation(parent_state, child_log_slots, execution)
}

pub fn trade_fee_quotes(
    parent_state: &ChainState,
    batch: &TradeBatch,
) -> Result<Vec<TradeFeeQuotes>, TradeStateError> {
    let fees = MarketFeeContext::from_state(parent_state);
    batch
        .policies()
        .iter()
        .map(|intent| fee_quotes(intent, fees))
        .collect()
}

fn fee_quotes(
    intent: &TradeIntent,
    fees: MarketFeeContext,
) -> Result<TradeFeeQuotes, TradeStateError> {
    let mut quotes = [0; 3];
    for (index, quote) in quotes.iter_mut().enumerate() {
        *quote = fees
            .required(intent.funding.len() + 1, index + 2)
            .map_err(|_| TradeStateError::Fee)?;
    }
    Ok(TradeFeeQuotes(quotes))
}

pub fn quote_trade_charge(
    intent: &TradeIntent,
    boundary: TradeBoundary,
    outcome: TradeOutcome,
    fees: MarketFeeContext,
) -> Result<TradeCharge, TradeStateError> {
    quote_charge(intent, boundary, outcome, fee_quotes(intent, fees)?).map_err(Into::into)
}

fn preflight(
    parent_state: &ChainState,
    boundary: TradeBoundary,
    child_log_slots: u32,
    batch: &TradeBatch,
) -> Result<(), TradeStateError> {
    if !crate::consensus::params::v2_1_active(boundary.height) {
        return Err(TradeStateError::Inactive);
    }
    let parent_log = parent_state.state.log_slots() as u32;
    if boundary.chain != native_chain_id()
        || boundary.height == 0
        || boundary.parent_id == [0; 32]
        || child_log_slots > 32
        || (child_log_slots != parent_log && child_log_slots != parent_log + 1)
    {
        return Err(TradeStateError::Context);
    }
    for input in batch.inputs()? {
        require_input(parent_state, boundary, &input)?;
    }
    Ok(())
}

fn finish_preparation(
    parent_state: &ChainState,
    child_log_slots: u32,
    execution: TradeExecution,
) -> Result<PreparedTradeBatch, TradeStateError> {
    for output in execution.outputs() {
        let slot = output.output.slot_index;
        if u64::from(slot) >= 1u64 << child_log_slots {
            return Err(TradeStateError::Outputs);
        }
        if u64::from(slot) < parent_state.num_slots() {
            require_value(parent_state, slot, SlotValue::EMPTY)
                .map_err(|_| TradeStateError::Outputs)?;
        }
    }
    let required = MarketFeeContext::from_state(parent_state)
        .required(execution.inputs().len(), execution.outputs().len())
        .map_err(|_| TradeStateError::Fee)?;
    if execution.fee() < required {
        return Err(TradeStateError::Fee);
    }
    Ok(PreparedTradeBatch {
        execution,
        parent_log_slots: parent_state.state.log_slots() as u32,
        child_log_slots,
    })
}

pub fn apply_prepared_trade_batch(
    state: &mut ChainState,
    prepared: &PreparedTradeBatch,
) -> Result<NativeStateTransition, TradeStateError> {
    let mut next = state.clone();
    let log_slots = next.state.log_slots() as u32;
    if log_slots != prepared.parent_log_slots && log_slots != prepared.child_log_slots {
        return Err(TradeStateError::Context);
    }
    if log_slots < prepared.child_log_slots {
        next.expand_one();
    }
    let boundary = prepared.boundary();
    let context = NativeContext {
        chain: boundary.chain,
        height: boundary.height,
        authority: Address([0; 32]),
        fee: prepared.fee(),
    };
    let effects = apply_checked_native_deferred_root(
        &mut next,
        &context,
        prepared.inputs(),
        prepared.outputs(),
        prepared.execution.facts().clone(),
    )?;
    let new_state_root = next
        .try_state_root()
        .map_err(|_| TradeStateError::State(NativeApplyError::ExactStateUnavailable))?;
    *state = next;
    Ok(NativeStateTransition {
        new_state_root,
        facts: effects.facts,
        created_openings: effects.created_openings,
        consumed_openings: effects.consumed_openings,
    })
}

fn require_input(
    state: &ChainState,
    boundary: TradeBoundary,
    claim: &NativeInputClaim,
) -> Result<(), TradeStateError> {
    if !crate::consensus::params::creation_id_within_boundary(
        claim.input.creation_id,
        state.alloc_counter,
        boundary.height - 1,
    ) {
        return Err(TradeStateError::Inputs);
    }
    let expected = SlotValue::with_owner_fields(
        claim.input.amount,
        claim.input.creation_id,
        claim.root.as_fields(),
    );
    require_value(state, claim.input.slot_index, expected).map_err(|_| TradeStateError::Inputs)
}
fn require_value(
    state: &ChainState,
    slot: u32,
    expected: SlotValue,
) -> Result<(), TradeStateError> {
    if u64::from(slot) >= state.num_slots()
        || state
            .state
            .is_evicted((slot >> state.state.effective_log_segment_size()) as u16)
        || state.state.slot(slot) != expected
    {
        return Err(TradeStateError::Inputs);
    }
    Ok(())
}
