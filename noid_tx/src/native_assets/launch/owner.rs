// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact owner funding for fixed-supply launches and curve requests.

use super::*;
use crate::native_assets::{
    transition::{NativeContext, NativeInputClaim, NativeOutputClaim},
    TokenReserve, NATIVE_CREATION_TAG, TOKEN_DECIMALS,
};
use std::collections::BTreeSet;

fn check_claims(
    context: &NativeContext,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<(), LaunchError> {
    if context.chain == [0; 32] || context.authority == Address([0; 32]) {
        return Err(LaunchError::Identity);
    }
    if inputs.is_empty()
        || inputs.len() > crate::MAX_PAGED_SPEND_INPUTS
        || outputs.is_empty()
        || outputs.len() > crate::MAX_PAGED_SPEND_OUTPUTS
    {
        return Err(LaunchError::Capacity);
    }
    let mut slots = BTreeSet::new();
    let mut incoming = 0u128;
    let mut outgoing = u128::from(context.fee);
    for claim in inputs {
        if !slots.insert(claim.input.slot_index) {
            return Err(LaunchError::Duplicate);
        }
        if let Some(opening) = claim.opening {
            opening
                .check_input(&claim.input, claim.root, context.height)
                .map_err(|_| LaunchError::Funding)?;
        } else {
            let id = claim.input.creation_id;
            if id == 0
                || (id >= NATIVE_CREATION_TAG && id & (1 << 63) == 0)
                || claim.input.amount == 0
                || claim.root != context.authority
            {
                return Err(LaunchError::Funding);
            }
        }
        incoming += u128::from(claim.input.amount);
    }
    for claim in outputs {
        if !slots.insert(claim.output.slot_index) {
            return Err(LaunchError::Duplicate);
        }
        if let Some(opening) = claim.opening {
            opening
                .check_output(&claim.output)
                .map_err(|_| LaunchError::Funding)?;
        } else if claim.output.amount == 0 || claim.output.owner != context.authority {
            return Err(LaunchError::Funding);
        }
        outgoing += u128::from(claim.output.amount);
    }
    if incoming != outgoing {
        return Err(LaunchError::Conservation);
    }
    Ok(())
}

pub fn check_launch_creation(
    context: &NativeContext,
    token: FungibleDefinition,
    definition: LaunchDefinition,
    funding_input: u16,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<(), LaunchError> {
    check_claims(context, inputs, outputs)?;
    if inputs.iter().any(|c| c.opening.is_some()) {
        return Err(LaunchError::Funding);
    }
    let funding = inputs
        .get(usize::from(funding_input))
        .ok_or(LaunchError::Funding)?;
    let anchor = GenesisAnchor {
        chain: context.chain,
        owner: context.authority,
        input: funding.input,
    };
    if LaunchDefinition::from_genesis(&anchor, token)? != definition {
        return Err(LaunchError::Definition);
    }
    let minimum = crate::asset_backing::TokenDenomination::new(TOKEN_DECIMALS)
        .and_then(|d| d.minimum_backing(token.initial_supply))
        .map_err(|_| LaunchError::Funding)?;
    let reserve =
        TokenReserve::from_definition(&token, minimum).map_err(|_| LaunchError::Funding)?;
    let mut purchased = None;
    for claim in outputs {
        if let Some(NativeOpening::TokenBalance(balance)) = claim.opening {
            if balance.asset != token.asset
                || balance.owner != context.authority
                || balance.unlock_height != 0
                || purchased.replace(balance.units).is_some()
            {
                return Err(LaunchError::Funding);
            }
        }
    }
    let initial = definition.after_initial_purchase(purchased.unwrap_or(0))?;
    let mut seen = [false; 3];
    for claim in outputs {
        let index = match claim.opening {
            None => continue,
            Some(NativeOpening::FungibleDefinition(d)) if d == token => 0,
            Some(NativeOpening::TokenReserve(r)) if r == reserve => 1,
            Some(NativeOpening::Launch(LaunchOpening::State(s)))
                if initial == sequential::TradeState::Curve(s) =>
            {
                2
            }
            Some(NativeOpening::Market(super::super::market::MarketOpening::Pool(s)))
                if initial == sequential::TradeState::Market(s) =>
            {
                2
            }
            Some(NativeOpening::TokenBalance(_)) => continue,
            _ => return Err(LaunchError::Funding),
        };
        if core::mem::replace(&mut seen[index], true) {
            return Err(LaunchError::Duplicate);
        }
    }
    if seen != [true; 3] {
        return Err(LaunchError::Funding);
    }
    Ok(())
}

pub fn check_launch_request(
    context: &NativeContext,
    definition: LaunchDefinition,
    parent: LaunchState,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<LaunchRequest, LaunchError> {
    check_claims(context, inputs, outputs)?;
    parent.check_definition(definition)?;
    let mut incoming = 0u128;
    let mut outgoing = 0u128;
    for claim in inputs {
        if let Some(opening) = claim.opening {
            match opening {
                NativeOpening::TokenBalance(b)
                    if b.asset == definition.asset && b.owner == context.authority =>
                {
                    incoming += u128::from(b.units);
                }
                _ => return Err(LaunchError::Funding),
            }
        }
    }
    let mut request = None;
    for claim in outputs {
        match claim.opening {
            None => (),
            Some(NativeOpening::TokenBalance(b))
                if b.asset == definition.asset && b.owner == context.authority =>
            {
                outgoing += u128::from(b.units);
            }
            Some(NativeOpening::Launch(LaunchOpening::Request(r)))
                if r.owner == context.authority && request.is_none() =>
            {
                r.check_round(definition, parent, context.height)?;
                request = Some(r);
            }
            _ => return Err(LaunchError::Funding),
        }
    }
    let request = request.ok_or(LaunchError::Funding)?;
    if request.side == LaunchSide::Sell {
        outgoing += u128::from(request.quantity);
    } else if incoming != 0 {
        return Err(LaunchError::Funding);
    }
    if incoming != outgoing {
        return Err(LaunchError::Conservation);
    }
    Ok(request)
}
