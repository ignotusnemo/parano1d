// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical grouped trade payouts and exact raw claims.

use std::collections::BTreeSet;

use noid_poseidon2b::primitives::{Address, TxBodyHash};

use super::{
    batch::{BatchError, TradeBatch},
    sequencing::{MarketStart, SequencingPlan, TradeBoundary, TradeOutcome},
    TradeError, TradeIntent, TradePayout,
};
use crate::native_assets::{
    launch::{sequential::TradeState, LaunchOpening},
    market::{MarketOpening, NOID_ASSET},
    transition::{NativeInputClaim, NativeOutputClaim, NativeTransitionFacts},
    AssetId, NativeOpening, TokenBalance,
};
use crate::{TxOutput, MAX_PAGED_SPEND_OUTPUTS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeOutputSlots {
    pub payouts: Vec<Vec<u32>>,
    pub market: u32,
}

/// The admitting block supplies the exact parent-State fee for one, two and
/// three user payouts, including the shared market input and successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TradeFeeQuotes(pub [u64; 3]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeCharge {
    pub authorization_id: TxBodyHash,
    pub fee: u64,
    pub payouts: Vec<TradePayout>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TradeExecutionError {
    Context,
    Batch(BatchError),
    Policy(TradeError),
    Fee,
    Inputs,
    Outputs,
    Conservation,
}
impl core::fmt::Display for TradeExecutionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "trade execution: {self:?}")
    }
}
impl std::error::Error for TradeExecutionError {}
impl From<BatchError> for TradeExecutionError {
    fn from(value: BatchError) -> Self {
        Self::Batch(value)
    }
}
impl From<TradeError> for TradeExecutionError {
    fn from(value: TradeError) -> Self {
        Self::Policy(value)
    }
}

#[derive(Debug, Clone)]
pub struct TradeExecution {
    boundary: TradeBoundary,
    commitment: Address,
    inputs: Vec<NativeInputClaim>,
    outputs: Vec<NativeOutputClaim>,
    charges: Vec<TradeCharge>,
    fee: u64,
    facts: NativeTransitionFacts,
    plan: SequencingPlan,
    auxiliary: Vec<NativeOpening>,
}

impl TradeExecution {
    pub fn boundary(&self) -> TradeBoundary {
        self.boundary
    }
    pub fn commitment(&self) -> Address {
        self.commitment
    }
    pub fn inputs(&self) -> &[NativeInputClaim] {
        &self.inputs
    }
    pub fn outputs(&self) -> &[NativeOutputClaim] {
        &self.outputs
    }
    pub fn charges(&self) -> &[TradeCharge] {
        &self.charges
    }
    pub fn fee(&self) -> u64 {
        self.fee
    }
    pub fn facts(&self) -> &NativeTransitionFacts {
        &self.facts
    }
    pub fn plan(&self) -> &SequencingPlan {
        &self.plan
    }
    pub fn auxiliary(&self) -> &[NativeOpening] {
        &self.auxiliary
    }

    pub fn new(
        batch: &TradeBatch,
        boundary: TradeBoundary,
        fees: &[TradeFeeQuotes],
        slots: &TradeOutputSlots,
    ) -> Result<Self, TradeExecutionError> {
        let (plan, charges) = prepare(batch, boundary, fees)?;
        Self::materialize(batch, boundary, plan, charges, slots)
    }

    /// Preserve canonical policy/funding order in the exact raw input stream.
    /// The admitting block authenticates all claims against parent State and
    /// binds each supplied fee quotation to that same immutable boundary.
    pub fn from_claims(
        batch: &TradeBatch,
        boundary: TradeBoundary,
        fees: &[TradeFeeQuotes],
        inputs: &[NativeInputClaim],
        outputs: &[NativeOutputClaim],
    ) -> Result<Self, TradeExecutionError> {
        let (plan, charges) = prepare(batch, boundary, fees)?;
        let payout_count: usize = charges.iter().map(|c| c.payouts.len()).sum();
        if outputs.len() != payout_count + 1 {
            return Err(TradeExecutionError::Outputs);
        }
        let mut offset = 0;
        let payouts = charges
            .iter()
            .map(|charge| {
                let end = offset + charge.payouts.len();
                let slots = outputs[offset..end]
                    .iter()
                    .map(|c| c.output.slot_index)
                    .collect();
                offset = end;
                slots
            })
            .collect();
        let slots = TradeOutputSlots {
            payouts,
            market: outputs[payout_count].output.slot_index,
        };
        let execution = Self::materialize(batch, boundary, plan, charges, &slots)?;
        if execution.inputs != inputs {
            return Err(TradeExecutionError::Inputs);
        }
        if execution.outputs != outputs {
            return Err(TradeExecutionError::Outputs);
        }
        Ok(execution)
    }

    fn materialize(
        batch: &TradeBatch,
        boundary: TradeBoundary,
        plan: SequencingPlan,
        charges: Vec<TradeCharge>,
        slots: &TradeOutputSlots,
    ) -> Result<Self, TradeExecutionError> {
        if slots.payouts.len() != charges.len() {
            return Err(TradeExecutionError::Outputs);
        }
        let inputs = batch.inputs()?;
        let mut outputs = Vec::new();
        let mut fee = 0u64;
        for (charge, slots) in charges.iter().zip(&slots.payouts) {
            if charge.payouts.len() != slots.len() {
                return Err(TradeExecutionError::Outputs);
            }
            for (&payout, &slot) in charge.payouts.iter().zip(slots) {
                outputs.push(payout_claim(payout, slot)?);
            }
            fee = fee
                .checked_add(charge.fee)
                .ok_or(TradeExecutionError::Fee)?;
        }
        let final_state = plan.after().ok_or(TradeExecutionError::Conservation)?;
        let market = match final_state {
            TradeState::Curve(state) => NativeOpening::Launch(LaunchOpening::State(state)),
            TradeState::Market(pool) => NativeOpening::Market(MarketOpening::Pool(pool)),
        };
        outputs.push(native_output(market, slots.market));
        if outputs.len() > MAX_PAGED_SPEND_OUTPUTS {
            return Err(TradeExecutionError::Outputs);
        }
        let mut occupied: BTreeSet<_> = inputs.iter().map(|c| c.input.slot_index).collect();
        for output in &outputs {
            if !occupied.insert(output.output.slot_index) {
                return Err(TradeExecutionError::Outputs);
            }
            if let Some(opening) = output.opening {
                opening
                    .check_output(&output.output)
                    .map_err(|_| TradeExecutionError::Outputs)?;
            }
        }
        let noid_in: u128 = inputs.iter().map(|c| u128::from(c.input.amount)).sum();
        let noid_out: u128 = outputs.iter().map(|c| u128::from(c.output.amount)).sum();
        let tokens_in: u128 = inputs
            .iter()
            .map(|c| token_units(c.opening, batch.parent().asset()))
            .sum();
        let tokens_out: u128 = outputs
            .iter()
            .map(|c| token_units(c.opening, batch.parent().asset()))
            .sum();
        if noid_in != noid_out + u128::from(fee) || tokens_in != tokens_out {
            return Err(TradeExecutionError::Conservation);
        }
        let mut auxiliary = vec![batch.parent().definition()];
        if let MarketStart::Curve { definition, .. } = batch.parent().market {
            if matches!(final_state, TradeState::Market(_)) {
                auxiliary.push(NativeOpening::Market(MarketOpening::Definition(
                    definition.market_definition(),
                )));
            }
        }
        let facts = NativeTransitionFacts {
            native_inputs: inputs.iter().filter(|c| c.opening.is_some()).count(),
            native_outputs: outputs.iter().filter(|c| c.opening.is_some()).count(),
            output_is_native: outputs.iter().map(|c| c.opening.is_some()).collect(),
            redeemed_units: 0,
            redemption_micronoid: 0,
            reserve_contribution_micronoid: 0,
            nft_items: 0,
        };
        Ok(Self {
            boundary,
            commitment: batch.root()?,
            inputs,
            outputs,
            charges,
            fee,
            facts,
            plan,
            auxiliary,
        })
    }
}

fn prepare(
    batch: &TradeBatch,
    boundary: TradeBoundary,
    fees: &[TradeFeeQuotes],
) -> Result<(SequencingPlan, Vec<TradeCharge>), TradeExecutionError> {
    if boundary.chain == [0; 32]
        || boundary.epoch_anchor == [0; 32]
        || boundary.parent_id == [0; 32]
        || boundary.height == 0
    {
        return Err(TradeExecutionError::Context);
    }
    if fees.len() != batch.policies().len() {
        return Err(TradeExecutionError::Fee);
    }
    let plan = batch.checked(boundary)?;
    let mut outcomes = vec![None; batch.policies().len()];
    for fill in plan.fills() {
        outcomes[fill.source_index] = Some(fill.outcome);
    }
    let charges = batch
        .policies()
        .iter()
        .zip(fees)
        .enumerate()
        .map(|(index, (intent, fee))| {
            quote_charge(
                intent,
                boundary,
                outcomes[index].ok_or(TradeExecutionError::Conservation)?,
                *fee,
            )
        })
        .collect::<Result<_, _>>()?;
    Ok((plan, charges))
}

/// Select the first bounded quotation whose canonical payouts fit its count.
pub fn quote_charge(
    intent: &TradeIntent,
    boundary: TradeBoundary,
    outcome: TradeOutcome,
    fees: TradeFeeQuotes,
) -> Result<TradeCharge, TradeExecutionError> {
    if fees.0[0] == 0 || fees.0.windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(TradeExecutionError::Fee);
    }
    for (index, fee) in fees.0.into_iter().enumerate() {
        if fee > intent.policy.fee_limit {
            continue;
        }
        let payouts = match intent.payouts(
            boundary.chain,
            boundary.epoch_anchor,
            boundary.height,
            outcome.spent_input,
            outcome.output,
            fee,
        ) {
            Ok(payouts) => payouts,
            Err(TradeError::Arithmetic) => continue,
            Err(error) => return Err(error.into()),
        };
        if payouts.len() <= index + 1 {
            return Ok(TradeCharge {
                authorization_id: intent.authorization_id()?,
                fee,
                payouts,
            });
        }
    }
    Err(TradeExecutionError::Fee)
}

fn payout_claim(payout: TradePayout, slot: u32) -> Result<NativeOutputClaim, TradeExecutionError> {
    if payout.asset == NOID_ASSET {
        Ok(NativeOutputClaim {
            output: TxOutput {
                slot_index: slot,
                amount: payout.units,
                owner: payout.owner,
            },
            opening: None,
        })
    } else {
        let opening = NativeOpening::TokenBalance(TokenBalance {
            asset: payout.asset,
            owner: payout.owner,
            units: payout.units,
            unlock_height: 0,
        });
        opening
            .validate()
            .map_err(|_| TradeExecutionError::Outputs)?;
        Ok(native_output(opening, slot))
    }
}
fn native_output(opening: NativeOpening, slot: u32) -> NativeOutputClaim {
    NativeOutputClaim {
        output: TxOutput {
            slot_index: slot,
            amount: opening.amount_micronoid(),
            owner: opening.root(),
        },
        opening: Some(opening),
    }
}
fn token_units(opening: Option<NativeOpening>, asset: AssetId) -> u128 {
    match opening {
        Some(NativeOpening::TokenBalance(balance)) if balance.asset == asset => {
            u128::from(balance.units)
        }
        Some(NativeOpening::Launch(LaunchOpening::State(state))) => {
            u128::from(state.inventory_units)
        }
        Some(NativeOpening::Market(MarketOpening::Pool(pool))) => u128::from(pool.quote_reserve),
        _ => 0,
    }
}
