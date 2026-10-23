// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Owner authorization for NFT escrow, cancellation and funded offer acceptance.

use super::{settlement::*, *};
use crate::native_assets::{
    transition::{NativeContext, NativeInputClaim, NativeOutputClaim},
    NATIVE_CREATION_TAG,
};
use std::collections::BTreeSet;

fn claims(
    context: &NativeContext,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<(), NftMarketError> {
    if context.chain == [0; 32] || context.authority == Address([0; 32]) || context.height == 0 {
        return Err(NftMarketError::Owner);
    }
    if inputs.is_empty()
        || inputs.len() > crate::MAX_PAGED_SPEND_INPUTS
        || outputs.is_empty()
        || outputs.len() > crate::MAX_PAGED_SPEND_OUTPUTS
    {
        return Err(NftMarketError::Capacity);
    }
    let mut slots = BTreeSet::new();
    let mut incoming = 0u128;
    let mut outgoing = u128::from(context.fee);
    for c in inputs {
        if !slots.insert(c.input.slot_index) {
            return Err(NftMarketError::Duplicate);
        }
        if let Some(o) = c.opening {
            o.check_input(&c.input, c.root, context.height)
                .map_err(|_| NftMarketError::Funding)?;
        } else if c.input.amount == 0
            || c.input.creation_id == 0
            || (c.input.creation_id >= NATIVE_CREATION_TAG && c.input.creation_id & (1 << 63) == 0)
            || c.root != context.authority
        {
            return Err(NftMarketError::Funding);
        }
        incoming += u128::from(c.input.amount);
    }
    for c in outputs {
        if !slots.insert(c.output.slot_index) {
            return Err(NftMarketError::Duplicate);
        }
        if let Some(o) = c.opening {
            o.check_output(&c.output)
                .map_err(|_| NftMarketError::Funding)?;
        } else if c.output.amount == 0 || c.output.owner == Address([0; 32]) {
            return Err(NftMarketError::Funding);
        }
        outgoing += u128::from(c.output.amount);
    }
    if incoming != outgoing {
        return Err(NftMarketError::Conservation);
    }
    Ok(())
}
fn ordinary_change(context: &NativeContext, c: &NativeOutputClaim) -> Result<(), NftMarketError> {
    if c.output.owner != context.authority {
        return Err(NftMarketError::Owner);
    }
    Ok(())
}
fn exact_payouts(
    expected: &[NftPayout],
    outputs: &[NativeOutputClaim],
) -> Result<(), NftMarketError> {
    let mut a: Vec<_> = expected
        .iter()
        .map(|p| (p.noid, p.root(), p.opening()))
        .collect();
    let mut b: Vec<_> = outputs
        .iter()
        .map(|c| (c.output.amount, c.output.owner, c.opening))
        .collect();
    a.sort_by_key(|p| (p.0, p.1 .0));
    b.sort_by_key(|p| (p.0, p.1 .0));
    if a != b {
        return Err(NftMarketError::Conservation);
    }
    Ok(())
}

pub fn check_listing_creation(
    context: &NativeContext,
    d: ListingDefinition,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<(), NftMarketError> {
    claims(context, inputs, outputs)?;
    let mut item = None;
    for c in inputs {
        if let Some(o) = c.opening {
            match o {
                NativeOpening::NftItem(n) if n.owner == context.authority && item.is_none() => {
                    item = Some((n, c.input.creation_id))
                }
                _ => return Err(NftMarketError::Owner),
            }
        }
    }
    let (n, id) = item.ok_or(NftMarketError::Funding)?;
    if ListingDefinition::from_item(n, id, d.ask, d.expiry_height, context.height)? != d {
        return Err(NftMarketError::Definition);
    }
    let initial = ListingState::initial(d)?;
    let mut seen = false;
    for c in outputs {
        match c.opening {
            None => ordinary_change(context, c)?,
            Some(NativeOpening::NftMarket(NftMarketOpening::Listing(s)))
                if s == initial && !seen =>
            {
                seen = true
            }
            _ => return Err(NftMarketError::Funding),
        }
    }
    if !seen {
        return Err(NftMarketError::Funding);
    }
    Ok(())
}
pub fn check_purchase_funding(
    context: &NativeContext,
    round: NftRoundContext,
    d: ListingDefinition,
    parent: ListingState,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<PurchaseRequest, NftMarketError> {
    claims(context, inputs, outputs)?;
    round.validate()?;
    if context.height != round.height() {
        return Err(NftMarketError::Height);
    }
    if inputs.iter().any(|c| c.opening.is_some()) {
        return Err(NftMarketError::Funding);
    }
    if inputs
        .iter()
        .any(|c| !round.contains_current_input(&c.input))
    {
        return Err(NftMarketError::Funding);
    }
    let mut request = None;
    for c in outputs {
        match c.opening {
            None => ordinary_change(context, c)?,
            Some(NativeOpening::NftMarket(NftMarketOpening::Purchase(r)))
                if r.payer == context.authority && request.is_none() =>
            {
                r.check_round(d, parent, round)?;
                request = Some(r);
            }
            _ => return Err(NftMarketError::Funding),
        }
    }
    request.ok_or(NftMarketError::Funding)
}

/// Consume one idle listing and pay its seller while delivering the NFT.
/// Output order is seller payment, NFT, then optional buyer change.
pub fn check_listing_purchase(
    context: &NativeContext,
    definition: ListingDefinition,
    parent: ListingState,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<(), NftMarketError> {
    claims(context, inputs, outputs)?;
    if inputs.len() < 2 || !(2..=3).contains(&outputs.len()) {
        return Err(NftMarketError::Capacity);
    }
    if parent != ListingState::initial(definition)? {
        return Err(NftMarketError::Phase);
    }
    if context.height >= definition.expiry_height {
        return Err(NftMarketError::Expired);
    }
    let mut listing = false;
    for input in inputs {
        match input.opening {
            None => {}
            Some(NativeOpening::NftMarket(NftMarketOpening::Listing(value)))
                if value == parent && !listing =>
            {
                listing = true;
            }
            _ => return Err(NftMarketError::Funding),
        }
    }
    if !listing {
        return Err(NftMarketError::Funding);
    }
    let payment = definition
        .ask
        .checked_add(NFT_FEE_CREDIT)
        .ok_or(NftMarketError::Price)?;
    if outputs[0].opening.is_some()
        || outputs[0].output.owner != definition.seller
        || outputs[0].output.amount != payment
        || outputs[1].opening != Some(NativeOpening::NftItem(definition.item(context.authority)?))
    {
        return Err(NftMarketError::Conservation);
    }
    if let Some(change) = outputs.get(2) {
        if change.opening.is_some() {
            return Err(NftMarketError::Funding);
        }
        ordinary_change(context, change)?;
    }
    Ok(())
}
pub fn check_offer_funding(
    context: &NativeContext,
    funding_input: u16,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<NftOffer, NftMarketError> {
    claims(context, inputs, outputs)?;
    if inputs.iter().any(|c| c.opening.is_some()) {
        return Err(NftMarketError::Funding);
    }
    let nonce = inputs
        .get(usize::from(funding_input))
        .ok_or(NftMarketError::Funding)?
        .input
        .creation_id;
    let mut offer = None;
    for c in outputs {
        match c.opening {
            None => ordinary_change(context, c)?,
            Some(NativeOpening::NftMarket(NftMarketOpening::Offer(o)))
                if o.payer == context.authority
                    && offer.is_none()
                    && o.funding_creation_id == nonce
                    && o.expiry_height > context.height =>
            {
                offer = Some(o);
            }
            _ => return Err(NftMarketError::Funding),
        }
    }
    offer.ok_or(NftMarketError::Funding)
}
pub fn check_offer_acceptance(
    context: &NativeContext,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<(), NftMarketError> {
    claims(context, inputs, outputs)?;
    if inputs.len() != 2 {
        return Err(NftMarketError::Capacity);
    }
    let mut item = None;
    let mut offer = None;
    for c in inputs {
        match c.opening {
            Some(NativeOpening::NftItem(n)) if n.owner == context.authority && item.is_none() => {
                item = Some(n)
            }
            Some(NativeOpening::NftMarket(NftMarketOpening::Offer(o))) if offer.is_none() => {
                offer = Some(o)
            }
            _ => return Err(NftMarketError::Owner),
        }
    }
    exact_payouts(
        &offer_acceptance(
            offer.ok_or(NftMarketError::Funding)?,
            item.ok_or(NftMarketError::Funding)?,
            context.height,
            context.fee,
        )?,
        outputs,
    )
}
pub fn check_listing_cancellation(
    context: &NativeContext,
    d: ListingDefinition,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<(), NftMarketError> {
    claims(context, inputs, outputs)?;
    if inputs.len() != 1 || context.authority != d.seller {
        return Err(NftMarketError::Owner);
    }
    let Some(NativeOpening::NftMarket(NftMarketOpening::Listing(s))) = inputs[0].opening else {
        return Err(NftMarketError::Funding);
    };
    s.check_definition(d)?;
    if s.phase != PoolPhase::Idle {
        return Err(NftMarketError::Phase);
    }
    exact_payouts(&listing_return(d, context.fee)?, outputs)
}
pub fn check_offer_cancellation(
    context: &NativeContext,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<(), NftMarketError> {
    claims(context, inputs, outputs)?;
    if inputs.len() != 1 {
        return Err(NftMarketError::Capacity);
    }
    let Some(NativeOpening::NftMarket(NftMarketOpening::Offer(o))) = inputs[0].opening else {
        return Err(NftMarketError::Funding);
    };
    if o.payer != context.authority {
        return Err(NftMarketError::Owner);
    }
    exact_payouts(&[offer_refund(o, context.fee)?], outputs)
}
