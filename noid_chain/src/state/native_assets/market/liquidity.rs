// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Atomic funded liquidity requests, settlement and payout application.

use super::*;
use noid_tx::native_assets::{
    market::{
        mixed::{timeout_claim, MixedBatchSettlement},
        owner::{check_owned_market_operation, MarketOwnerOperation},
        queue::{MarketRequestRef, MixedRegisteredBatch},
        LiquidityClaim, MarketOpening,
    },
    transition::{NativeContext, NativeInputClaim, NativeOutputClaim},
    NativeOpening, TokenBalance,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarketFeeContext {
    pub active_slots: u64,
    pub log_slots: u32,
}
impl MarketFeeContext {
    pub fn from_parent(parent: &crate::BlockHeader) -> Self {
        Self {
            active_slots: parent.active_slot_count,
            log_slots: parent.log_slots,
        }
    }
    pub fn from_state(state: &ChainState) -> Self {
        Self {
            active_slots: state.active_slot_count,
            log_slots: state.state.log_slots() as u32,
        }
    }
    pub fn required(self, inputs: usize, outputs: usize) -> Result<u64, MarketApplyError> {
        if self.log_slots > 32 || self.log_slots == 0 || self.active_slots > 1u64 << self.log_slots
        {
            return Err(MarketApplyError::Bounds);
        }
        Ok(crate::consensus::fees::fee_breakdown(
            inputs as u64,
            outputs as u64,
            self.active_slots,
            self.log_slots,
        )
        .required_total)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketStateOutputs {
    pub state_root: Digest,
    pub outputs: Vec<(u32, u64, NativeOutputClaim)>,
}

/// The admitting block binds the exact Owner statement and auxiliary
/// definition before committing these checked raw State changes.
pub fn apply_owned_market_operation(
    state: &mut ChainState,
    context: &NativeContext,
    definition: MarketDefinition,
    parent: Option<ParentPool>,
    operation: MarketOwnerOperation,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    fees: MarketFeeContext,
) -> Result<MarketStateOutputs, MarketApplyError> {
    require_active(context.height)?;
    if context.chain != crate::state::native_assets::native_chain_id() {
        return Err(MarketError::Anchor.into());
    }
    if context.fee != fees.required(inputs.len(), outputs.len())? {
        return Err(MarketError::Fee.into());
    }
    if let Some(parent) = parent {
        if parent.definition != definition {
            return Err(MarketError::Pool.into());
        }
        let sequence = native_sequence(parent.creation_id).map_err(|_| MarketApplyError::Input)?;
        if sequence > state.alloc_counter {
            return Err(MarketApplyError::Input);
        }
        let (slot, value) = pool_input(parent);
        require_slot(state, slot, value)?;
    }
    check_owned_market_operation(
        context,
        definition,
        parent.map(|p| p.pool),
        operation,
        inputs,
        outputs,
    )?;
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
    Ok(MarketStateOutputs {
        state_root,
        outputs: outputs
            .iter()
            .copied()
            .zip(ids)
            .map(|(c, id)| (c.output.slot_index, id, c))
            .collect(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixedSettlementEffects {
    pub state_root: Digest,
    pub settlement: MixedBatchSettlement,
    pub control: (u32, u64, PoolState),
    pub claims: Vec<(u32, u64, MarketOpening)>,
}

pub fn apply_mixed_batch_settlement(
    state: &mut ChainState,
    height: u64,
    parent: ParentPool,
    requests: &[MarketRequestRef],
    output_slots: &[u32],
    fees: MarketFeeContext,
) -> Result<MixedSettlementEffects, MarketApplyError> {
    require_active(height)?;
    if output_slots.len() != requests.len() + 1 {
        return Err(MarketApplyError::Bounds);
    }
    let batch = MixedRegisteredBatch::from_frozen(parent.definition, parent.pool, requests)?;
    let fee = fees.required(requests.len() + 1, output_slots.len())?;
    let settlement = MixedBatchSettlement::calculate(parent.definition, &batch, height, fee)?;
    let mut inputs = vec![pool_input(parent)];
    for r in batch.requests() {
        inputs.push((
            r.slot_index,
            native_slot(r.creation_id, r.request.noid_value()?, r.root()),
        ));
    }
    let after = settlement.after();
    let mut outputs = vec![ExactOutput {
        slot: output_slots[0],
        amount: after.noid_value(),
        root: after.root(),
        native: true,
    }];
    for (&slot, c) in output_slots[1..].iter().zip(settlement.claims()) {
        outputs.push(ExactOutput {
            slot,
            amount: c.noid_value()?,
            root: c.root(),
            native: true,
        });
    }
    let (state_root, ids) = apply_exact_updates(state, &inputs, &outputs, fee)?;
    let control = (output_slots[0], ids[0], after);
    let claims = output_slots[1..]
        .iter()
        .zip(&ids[1..])
        .zip(settlement.claims())
        .map(|((&slot, &id), &c)| (slot, id, c))
        .collect();
    Ok(MixedSettlementEffects {
        state_root,
        settlement,
        control,
        claims,
    })
}

pub fn apply_mixed_timeout_refunds(
    state: &mut ChainState,
    height: u64,
    definition: MarketDefinition,
    requests: &[MarketRequestRef],
    output_slots: &[u32],
    fees: MarketFeeContext,
) -> Result<(Digest, Vec<(u32, u64, MarketOpening)>), MarketApplyError> {
    require_active(height)?;
    if requests.is_empty()
        || requests.len() > MAX_ROUND_REQUESTS
        || output_slots.len() != requests.len()
    {
        return Err(MarketApplyError::Bounds);
    }
    let mut requests = requests.to_vec();
    requests.sort_by_cached_key(|r| r.key());
    let count = requests.len() as u64;
    let fee = fees.required(requests.len(), output_slots.len())?;
    let mut inputs = Vec::with_capacity(requests.len());
    let mut outputs = Vec::with_capacity(requests.len());
    let mut claims = Vec::with_capacity(requests.len());
    for (i, (r, &slot)) in requests.iter().zip(output_slots).enumerate() {
        let charged = fee / count + u64::from((i as u64) < fee % count);
        let claim = timeout_claim(definition, *r, height, charged)?;
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
    let (root, ids) = apply_exact_updates(state, &inputs, &outputs, fee)?;
    Ok((
        root,
        output_slots
            .iter()
            .zip(ids)
            .zip(claims)
            .map(|((&slot, id), c)| (slot, id, c))
            .collect(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundedLiquidityClaim {
    pub slot_index: u32,
    pub creation_id: u64,
    pub claim: LiquidityClaim,
}

pub fn apply_liquidity_claim_payout(
    state: &mut ChainState,
    height: u64,
    definition: MarketDefinition,
    funded: FundedLiquidityClaim,
    output_slots: &[u32],
    fees: MarketFeeContext,
) -> Result<MarketStateOutputs, MarketApplyError> {
    require_active(height)?;
    let preliminary = funded.claim.payouts(definition, 0)?;
    let fee = fees.required(1, preliminary.len())?;
    let payouts = funded.claim.payouts(definition, fee)?;
    if output_slots.len() != payouts.len() || preliminary.len() != payouts.len() {
        return Err(MarketApplyError::Bounds);
    }
    let input = (
        funded.slot_index,
        native_slot(
            funded.creation_id,
            funded.claim.noid_value()?,
            MarketOpening::LiquidityClaim(funded.claim).root(),
        ),
    );
    let outputs: Vec<_> = output_slots
        .iter()
        .zip(&payouts)
        .map(|(&slot, (amount, root, opening))| ExactOutput {
            slot,
            amount: *amount,
            root: *root,
            native: opening.is_some(),
        })
        .collect();
    let (state_root, ids) = apply_exact_updates(state, &[input], &outputs, fee)?;
    let outputs = output_slots
        .iter()
        .zip(ids)
        .zip(payouts)
        .map(|((&slot, id), (amount, owner, opening))| {
            (
                slot,
                id,
                NativeOutputClaim {
                    output: noid_tx::TxOutput {
                        slot_index: slot,
                        amount,
                        owner,
                    },
                    opening,
                },
            )
        })
        .collect();
    Ok(MarketStateOutputs {
        state_root,
        outputs,
    })
}

pub fn apply_swap_claim_payout(
    state: &mut ChainState,
    height: u64,
    funded: FundedClaimRef,
    output_slots: &[u32],
    fees: MarketFeeContext,
) -> Result<MarketStateOutputs, MarketApplyError> {
    require_active(height)?;
    let count = funded.claim.payouts(0)?.len();
    let fee = fees.required(1, count)?;
    let payouts = funded.claim.payouts(fee)?;
    if count != payouts.len() || output_slots.len() != count {
        return Err(MarketApplyError::Bounds);
    }
    let mut claims = Vec::with_capacity(count);
    for (&slot, payout) in output_slots.iter().zip(payouts) {
        let (amount, owner, opening) = if payout.asset == NOID_ASSET {
            (payout.units, payout.owner, None)
        } else {
            let opening = NativeOpening::TokenBalance(TokenBalance {
                asset: payout.asset,
                owner: payout.owner,
                units: payout.units,
                unlock_height: 0,
            });
            opening.validate().map_err(|_| MarketApplyError::Output)?;
            (0, opening.root(), Some(opening))
        };
        claims.push(NativeOutputClaim {
            output: noid_tx::TxOutput {
                slot_index: slot,
                amount,
                owner,
            },
            opening,
        });
    }
    let outputs: Vec<_> = claims
        .iter()
        .map(|c| ExactOutput {
            slot: c.output.slot_index,
            amount: c.output.amount,
            root: c.output.owner,
            native: c.opening.is_some(),
        })
        .collect();
    let input = (
        funded.slot_index,
        native_slot(
            funded.creation_id,
            funded.claim.noid_value()?,
            funded.claim.root(),
        ),
    );
    let (state_root, ids) = apply_exact_updates(state, &[input], &outputs, fee)?;
    Ok(MarketStateOutputs {
        state_root,
        outputs: claims
            .into_iter()
            .zip(ids)
            .map(|(claim, id)| (claim.output.slot_index, id, claim))
            .collect(),
    })
}
