// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact NFT escrow, complete purchase settlement and funded offer State.

use super::market::{
    apply_exact_updates, apply_updates_with_input_kinds, liquidity::MarketFeeContext, native_slot,
    require_slot, ExactOutput, MarketApplyError,
};
use crate::ChainState;
use noid_poseidon2b::primitives::Digest;
use noid_tx::native_assets::{
    native_sequence,
    nft_market::{owner::*, queue::*, settlement::*, *},
    transition::{NativeContext, NativeInputClaim, NativeOutputClaim},
    NativeOpening,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftMarketApplyError {
    Inactive,
    Context,
    Bounds,
    Input,
    Fee,
    Semantic(NftMarketError),
    State(MarketApplyError),
}
impl core::fmt::Display for NftMarketApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NFT market State: {self:?}")
    }
}
impl std::error::Error for NftMarketApplyError {}
impl From<NftMarketError> for NftMarketApplyError {
    fn from(e: NftMarketError) -> Self {
        Self::Semantic(e)
    }
}
impl From<MarketApplyError> for NftMarketApplyError {
    fn from(e: MarketApplyError) -> Self {
        Self::State(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentListing {
    pub slot_index: u32,
    pub creation_id: u64,
    pub definition: ListingDefinition,
    pub listing: ListingState,
}

/// Canonical parent header for one original purchase-admission height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftRoundAnchor {
    context: NftRoundContext,
    parent: crate::BlockHeader,
}
impl NftRoundAnchor {
    pub fn from_parent_header(
        height: u64,
        expected_parent_id: Digest,
        parent: crate::BlockHeader,
    ) -> Result<Self, NftMarketApplyError> {
        if parent.height.checked_add(1) != Some(height)
            || crate::block_id(&parent) != expected_parent_id
        {
            return Err(NftMarketApplyError::Context);
        }
        let context = NftRoundContext::new(height, expected_parent_id, parent.alloc_counter)?;
        Ok(Self { context, parent })
    }
    pub const fn context(&self) -> NftRoundContext {
        self.context
    }
    pub const fn parent_header(&self) -> &crate::BlockHeader {
        &self.parent
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundedOffer {
    pub slot_index: u32,
    pub creation_id: u64,
    pub offer: NftOffer,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftMarketStateOutputs {
    pub state_root: Digest,
    pub outputs: Vec<(u32, u64, NativeOutputClaim)>,
    pub auxiliary: Vec<NativeOpening>,
}

fn active(height: u64) -> Result<(), NftMarketApplyError> {
    if crate::consensus::params::v2_1_active(height) {
        Ok(())
    } else {
        Err(NftMarketApplyError::Inactive)
    }
}
fn context(
    c: &NativeContext,
    n: usize,
    m: usize,
    fees: MarketFeeContext,
) -> Result<(), NftMarketApplyError> {
    active(c.height)?;
    if c.chain != super::native_chain_id() {
        return Err(NftMarketApplyError::Context);
    }
    if c.fee != fees.required(n, m)? {
        return Err(NftMarketApplyError::Fee);
    }
    Ok(())
}
fn parent_input(p: ParentListing) -> (u32, crate::SlotValue) {
    (
        p.slot_index,
        native_slot(p.creation_id, NFT_FEE_CREDIT, p.listing.root()),
    )
}
fn parent(state: &ChainState, p: ParentListing) -> Result<(), NftMarketApplyError> {
    p.listing.check_definition(p.definition)?;
    if native_sequence(p.creation_id).map_err(|_| NftMarketApplyError::Input)? > state.alloc_counter
    {
        return Err(NftMarketApplyError::Input);
    }
    let (slot, v) = parent_input(p);
    require_slot(state, slot, v)?;
    Ok(())
}
fn owner_updates(
    state: &mut ChainState,
    c: &NativeContext,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    auxiliary: Vec<NativeOpening>,
) -> Result<NftMarketStateOutputs, NftMarketApplyError> {
    let raw: Vec<_> = inputs
        .iter()
        .map(|i| {
            (
                i.input.slot_index,
                native_slot(i.input.creation_id, i.input.amount, i.root),
            )
        })
        .collect();
    let kinds: Vec<_> = inputs.iter().map(|i| i.opening.is_some()).collect();
    let out: Vec<_> = outputs
        .iter()
        .map(|o| ExactOutput {
            slot: o.output.slot_index,
            amount: o.output.amount,
            root: o.output.owner,
            native: o.opening.is_some(),
        })
        .collect();
    let (state_root, ids) =
        apply_updates_with_input_kinds(state, Some(c.height), &raw, &out, c.fee, &kinds)?;
    Ok(NftMarketStateOutputs {
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

pub fn apply_owned_listing_creation(
    state: &mut ChainState,
    c: &NativeContext,
    d: ListingDefinition,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    fees: MarketFeeContext,
) -> Result<NftMarketStateOutputs, NftMarketApplyError> {
    context(c, inputs.len(), outputs.len(), fees)?;
    check_listing_creation(c, d, inputs, outputs)?;
    owner_updates(
        state,
        c,
        inputs,
        outputs,
        vec![NativeOpening::NftMarket(NftMarketOpening::Definition(d))],
    )
}
pub fn apply_owned_purchase_funding(
    state: &mut ChainState,
    c: &NativeContext,
    p: ParentListing,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    anchor: &NftRoundAnchor,
) -> Result<NftMarketStateOutputs, NftMarketApplyError> {
    let round = anchor.context();
    if c.height != round.height() || round.parent_alloc_counter() > state.alloc_counter {
        return Err(NftMarketApplyError::Context);
    }
    let fees = MarketFeeContext::from_parent(anchor.parent_header());
    context(c, inputs.len(), outputs.len(), fees)?;
    parent(state, p)?;
    check_purchase_funding(c, round, p.definition, p.listing, inputs, outputs)?;
    owner_updates(state, c, inputs, outputs, Vec::new())
}
pub fn apply_owned_listing_cancellation(
    state: &mut ChainState,
    c: &NativeContext,
    p: ParentListing,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    fees: MarketFeeContext,
) -> Result<NftMarketStateOutputs, NftMarketApplyError> {
    context(c, inputs.len(), outputs.len(), fees)?;
    parent(state, p)?;
    if inputs.len() != 1
        || inputs[0].input.slot_index != p.slot_index
        || inputs[0].input.creation_id != p.creation_id
    {
        return Err(NftMarketApplyError::Input);
    }
    check_listing_cancellation(c, p.definition, inputs, outputs)?;
    owner_updates(state, c, inputs, outputs, Vec::new())
}

pub fn apply_owned_listing_purchase(
    state: &mut ChainState,
    c: &NativeContext,
    p: ParentListing,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    fees: MarketFeeContext,
) -> Result<NftMarketStateOutputs, NftMarketApplyError> {
    context(c, inputs.len(), outputs.len(), fees)?;
    parent(state, p)?;
    let matching = inputs.iter().filter(|input| {
        input.input.slot_index == p.slot_index && input.input.creation_id == p.creation_id
    });
    if matching.count() != 1 {
        return Err(NftMarketApplyError::Input);
    }
    check_listing_purchase(c, p.definition, p.listing, inputs, outputs)?;
    owner_updates(state, c, inputs, outputs, Vec::new())
}
pub fn apply_owned_offer_funding(
    state: &mut ChainState,
    c: &NativeContext,
    funding_input: u16,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    fees: MarketFeeContext,
) -> Result<NftMarketStateOutputs, NftMarketApplyError> {
    context(c, inputs.len(), outputs.len(), fees)?;
    check_offer_funding(c, funding_input, inputs, outputs)?;
    owner_updates(state, c, inputs, outputs, Vec::new())
}
pub fn apply_owned_offer_acceptance(
    state: &mut ChainState,
    c: &NativeContext,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    fees: MarketFeeContext,
) -> Result<NftMarketStateOutputs, NftMarketApplyError> {
    context(c, inputs.len(), outputs.len(), fees)?;
    check_offer_acceptance(c, inputs, outputs)?;
    owner_updates(state, c, inputs, outputs, Vec::new())
}
pub fn apply_owned_offer_cancellation(
    state: &mut ChainState,
    c: &NativeContext,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    fees: MarketFeeContext,
) -> Result<NftMarketStateOutputs, NftMarketApplyError> {
    context(c, inputs.len(), outputs.len(), fees)?;
    check_offer_cancellation(c, inputs, outputs)?;
    owner_updates(state, c, inputs, outputs, Vec::new())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingRegistrationEffects {
    pub state_root: Digest,
    pub batches: Vec<ListingBatch>,
    pub controls: Vec<(u32, u64, ListingState)>,
}

pub fn apply_block_listing_registrations(
    state: &mut ChainState,
    anchor: &NftRoundAnchor,
    parents: &[ParentListing],
    requests: &[FundedPurchaseRef],
    output_slots: &[u32],
) -> Result<ListingRegistrationEffects, NftMarketApplyError> {
    let round = anchor.context();
    let height = round.height();
    if round.parent_alloc_counter() > state.alloc_counter {
        return Err(NftMarketApplyError::Context);
    }
    active(height)?;
    let max = noid_tx::native_assets::market::queue::MAX_ROUND_REQUESTS;
    if parents.is_empty()
        || parents.len() > max
        || requests.is_empty()
        || requests.len() > max
        || output_slots.len() != parents.len()
    {
        return Err(NftMarketApplyError::Bounds);
    }
    let mut ids = BTreeSet::new();
    let mut occupied = BTreeSet::new();
    let mut groups = BTreeMap::new();
    for &p in parents {
        parent(state, p)?;
        if !ids.insert(p.listing.listing) || !occupied.insert(p.slot_index) {
            return Err(NftMarketApplyError::Input);
        }
        let id = p.listing.round_id(round)?;
        if groups.insert(id, (p, Vec::new())).is_some() {
            return Err(NftMarketApplyError::Input);
        }
    }
    for &r in requests {
        r.validate()?;
        if !occupied.insert(r.slot_index)
            || native_sequence(r.creation_id).map_err(|_| NftMarketApplyError::Input)?
                > state.alloc_counter
        {
            return Err(NftMarketApplyError::Input);
        }
        let (p, list) = groups
            .get_mut(&r.request.round)
            .ok_or(NftMarketError::Queue)?;
        r.request.check_round(p.definition, p.listing, round)?;
        require_slot(
            state,
            r.slot_index,
            native_slot(r.creation_id, r.request.noid_value()?, r.request.root()),
        )?;
        list.push(r);
    }
    let mut groups: Vec<_> = groups.into_values().collect();
    groups.sort_by_key(|(p, _)| p.listing.listing);
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut batches = Vec::new();
    for ((p, r), &slot) in groups.iter().zip(output_slots) {
        let batch = ListingBatch::register(p.definition, p.listing, round, r)?;
        inputs.push(parent_input(*p));
        outputs.push(ExactOutput {
            slot,
            amount: NFT_FEE_CREDIT,
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
    Ok(ListingRegistrationEffects {
        state_root,
        batches,
        controls,
    })
}

fn payout_claim(slot: u32, p: NftPayout) -> NativeOutputClaim {
    NativeOutputClaim {
        output: noid_tx::TxOutput {
            slot_index: slot,
            amount: p.noid,
            owner: p.root(),
        },
        opening: p.opening(),
    }
}
fn system_payouts(
    state: &mut ChainState,
    inputs: &[(u32, crate::SlotValue)],
    payouts: &[NftPayout],
    slots: &[u32],
    fee: u64,
) -> Result<NftMarketStateOutputs, NftMarketApplyError> {
    if payouts.len() != slots.len() {
        return Err(NftMarketApplyError::Bounds);
    }
    let claims: Vec<_> = slots
        .iter()
        .zip(payouts)
        .map(|(&s, &p)| payout_claim(s, p))
        .collect();
    let outputs: Vec<_> = claims
        .iter()
        .map(|c| ExactOutput {
            slot: c.output.slot_index,
            amount: c.output.amount,
            root: c.output.owner,
            native: c.opening.is_some(),
        })
        .collect();
    let (state_root, ids) = apply_exact_updates(state, inputs, &outputs, fee)?;
    Ok(NftMarketStateOutputs {
        state_root,
        outputs: claims
            .into_iter()
            .zip(ids)
            .map(|(c, id)| (c.output.slot_index, id, c))
            .collect(),
        auxiliary: Vec::new(),
    })
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingSettlementEffects {
    pub settlement: ListingSettlement,
    pub state: NftMarketStateOutputs,
}
pub fn apply_listing_settlement(
    state: &mut ChainState,
    height: u64,
    p: ParentListing,
    requests: &[FundedPurchaseRef],
    slots: &[u32],
    fees: MarketFeeContext,
    registration: &NftRoundAnchor,
) -> Result<ListingSettlementEffects, NftMarketApplyError> {
    active(height)?;
    parent(state, p)?;
    let batch =
        ListingBatch::from_frozen(p.definition, p.listing, requests, registration.context())?;
    let preliminary = ListingSettlement::calculate(&batch, height, 0)?;
    let fee = fees.required(requests.len() + 1, preliminary.payouts().len())?;
    let settlement = ListingSettlement::calculate(&batch, height, fee)?;
    if preliminary.payouts().len() != settlement.payouts().len() {
        return Err(NftMarketApplyError::Bounds);
    }
    let mut inputs = vec![parent_input(p)];
    for r in batch.requests() {
        inputs.push((
            r.slot_index,
            native_slot(r.creation_id, r.request.noid_value()?, r.request.root()),
        ));
    }
    let out = system_payouts(state, &inputs, settlement.payouts(), slots, fee)?;
    Ok(ListingSettlementEffects {
        settlement,
        state: out,
    })
}
pub fn apply_listing_timeout_reset(
    state: &mut ChainState,
    height: u64,
    p: ParentListing,
    slot: u32,
) -> Result<(Digest, u64, ListingState), NftMarketApplyError> {
    active(height)?;
    parent(state, p)?;
    let next = timeout_reset(p.definition, p.listing, height)?;
    let (root, ids) = apply_exact_updates(
        state,
        &[parent_input(p)],
        &[ExactOutput {
            slot,
            amount: NFT_FEE_CREDIT,
            root: next.root(),
            native: true,
        }],
        0,
    )?;
    Ok((root, ids[0], next))
}
pub fn apply_expired_listing_recovery(
    state: &mut ChainState,
    height: u64,
    p: ParentListing,
    slots: &[u32],
    fees: MarketFeeContext,
) -> Result<NftMarketStateOutputs, NftMarketApplyError> {
    active(height)?;
    parent(state, p)?;
    p.listing.expired_recovery(p.definition, height)?;
    let preliminary = listing_return(p.definition, 0)?;
    let fee = fees.required(1, preliminary.len())?;
    let payouts = listing_return(p.definition, fee)?;
    if preliminary.len() != payouts.len() {
        return Err(NftMarketApplyError::Bounds);
    }
    system_payouts(state, &[parent_input(p)], &payouts, slots, fee)
}
pub fn apply_expired_purchase_refund(
    state: &mut ChainState,
    height: u64,
    r: FundedPurchaseRef,
    slot: u32,
    fees: MarketFeeContext,
) -> Result<NftMarketStateOutputs, NftMarketApplyError> {
    active(height)?;
    r.validate()?;
    let fee = fees.required(1, 1)?;
    let payout = purchase_refund(r.request, height, fee)?;
    system_payouts(
        state,
        &[(
            r.slot_index,
            native_slot(r.creation_id, r.request.noid_value()?, r.request.root()),
        )],
        &[payout],
        &[slot],
        fee,
    )
}
pub fn apply_expired_offer_refund(
    state: &mut ChainState,
    height: u64,
    o: FundedOffer,
    slot: u32,
    fees: MarketFeeContext,
) -> Result<NftMarketStateOutputs, NftMarketApplyError> {
    active(height)?;
    o.offer.validate()?;
    if height < o.offer.expiry_height {
        return Err(NftMarketError::Phase.into());
    }
    let fee = fees.required(1, 1)?;
    let payout = offer_refund(o.offer, fee)?;
    system_payouts(
        state,
        &[(
            o.slot_index,
            native_slot(o.creation_id, o.offer.noid_value()?, o.offer.root()),
        )],
        &[payout],
        &[slot],
        fee,
    )
}
