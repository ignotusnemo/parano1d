// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact Owner-authorized financial operations and their read dependencies.

use super::{FinancialOperation, FinancialOperationError, NativeParentRef};
use crate::native_assets::{
    launch::{owner::*, LaunchDefinition, LaunchOpening, LaunchState},
    market::{owner::*, MarketDefinition, MarketError, MarketOpening, PoolState},
    nft_market::{
        owner::*, ListingDefinition, ListingState, NftMarketError, NftMarketOpening,
        NftRoundContext,
    },
    transition::{NativeContext, NativeInputClaim, NativeOutputClaim, NativeTransitionFacts},
    FungibleDefinition, NativeOpening,
};
use noid_poseidon2b::primitives::Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinancialOwnerError {
    Context,
    Operation,
    Dependency,
    Operand(FinancialOperationError),
    Market(MarketError),
    Launch(crate::native_assets::launch::LaunchError),
    Nft(NftMarketError),
}
impl core::fmt::Display for FinancialOwnerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "financial Owner: {self:?}")
    }
}
impl std::error::Error for FinancialOwnerError {}
impl From<FinancialOperationError> for FinancialOwnerError {
    fn from(v: FinancialOperationError) -> Self {
        Self::Operand(v)
    }
}
impl From<MarketError> for FinancialOwnerError {
    fn from(v: MarketError) -> Self {
        Self::Market(v)
    }
}
impl From<crate::native_assets::launch::LaunchError> for FinancialOwnerError {
    fn from(v: crate::native_assets::launch::LaunchError) -> Self {
        Self::Launch(v)
    }
}
impl From<NftMarketError> for FinancialOwnerError {
    fn from(v: NftMarketError) -> Self {
        Self::Nft(v)
    }
}

fn one<T>(items: impl IntoIterator<Item = T>) -> Result<T, FinancialOwnerError> {
    let mut iter = items.into_iter();
    let value = iter.next().ok_or(FinancialOwnerError::Dependency)?;
    if iter.next().is_some() {
        return Err(FinancialOwnerError::Dependency);
    }
    Ok(value)
}
fn read(
    root: Address,
    resolve: &mut impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<NativeOpening, FinancialOwnerError> {
    let value = resolve(root).ok_or(FinancialOwnerError::Dependency)?;
    if value.root() != root || value.validate().is_err() {
        return Err(FinancialOwnerError::Dependency);
    }
    Ok(value)
}
pub(super) fn market_definition(
    root: Address,
    resolve: &mut impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<MarketDefinition, FinancialOwnerError> {
    let NativeOpening::Market(MarketOpening::Definition(d)) = read(root, resolve)? else {
        return Err(FinancialOwnerError::Dependency);
    };
    Ok(d)
}
pub(super) fn launch_definition(
    root: Address,
    resolve: &mut impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<LaunchDefinition, FinancialOwnerError> {
    let NativeOpening::Launch(LaunchOpening::Definition(d)) = read(root, resolve)? else {
        return Err(FinancialOwnerError::Dependency);
    };
    Ok(d)
}
pub(super) fn listing_definition(
    root: Address,
    resolve: &mut impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<ListingDefinition, FinancialOwnerError> {
    let NativeOpening::NftMarket(NftMarketOpening::Definition(d)) = read(root, resolve)? else {
        return Err(FinancialOwnerError::Dependency);
    };
    Ok(d)
}
fn market_parent(
    p: NativeParentRef,
    round: NftRoundContext,
    resolve: &mut impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<(MarketDefinition, PoolState), FinancialOwnerError> {
    p.check_boundary(round.parent_alloc_counter())?;
    let NativeOpening::Market(MarketOpening::Pool(pool)) = read(p.root, resolve)? else {
        return Err(FinancialOwnerError::Dependency);
    };
    let d = market_definition(Address(pool.pool.0), resolve)?;
    pool.check_definition(d)?;
    Ok((d, pool))
}
fn launch_parent(
    p: NativeParentRef,
    round: NftRoundContext,
    resolve: &mut impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<(LaunchDefinition, LaunchState), FinancialOwnerError> {
    p.check_boundary(round.parent_alloc_counter())?;
    let NativeOpening::Launch(LaunchOpening::State(state)) = read(p.root, resolve)? else {
        return Err(FinancialOwnerError::Dependency);
    };
    let d = launch_definition(Address(state.launch.0), resolve)?;
    state.check_definition(d)?;
    Ok((d, state))
}
fn listing_parent(
    p: NativeParentRef,
    round: NftRoundContext,
    resolve: &mut impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<(ListingDefinition, ListingState), FinancialOwnerError> {
    p.check_boundary(round.parent_alloc_counter())?;
    let NativeOpening::NftMarket(NftMarketOpening::Listing(state)) = read(p.root, resolve)? else {
        return Err(FinancialOwnerError::Dependency);
    };
    let d = listing_definition(Address(state.listing.0), resolve)?;
    state.check_definition(d)?;
    Ok((d, state))
}

/// The admitting chain authenticates the exact read-parent slot and canonical
/// header context. Every dependency is resolved by its committed content key.
pub fn check_financial_owner(
    context: &NativeContext,
    round: NftRoundContext,
    operation: FinancialOperation,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    mut resolve: impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<NativeTransitionFacts, FinancialOwnerError> {
    round.validate()?;
    operation.operand()?;
    if context.chain == [0; 32]
        || context.authority == Address([0; 32])
        || round.height() != context.height
    {
        return Err(FinancialOwnerError::Context);
    }
    use FinancialOperation::*;
    match operation {
        BootstrapPool {
            funding_input,
            definition,
        } => {
            let d = market_definition(definition, &mut resolve)?;
            let pool = one(outputs.iter().filter_map(|o| match o.opening {
                Some(NativeOpening::Market(MarketOpening::Pool(p))) => Some(p),
                _ => None,
            }))?;
            check_owned_market_operation(
                context,
                d,
                None,
                MarketOwnerOperation::Bootstrap {
                    funding_input,
                    base: pool.base_reserve,
                    quote: pool.quote_reserve,
                },
                inputs,
                outputs,
            )?;
        }
        Swap { parent }
        | DepositLiquidity { parent }
        | WithdrawLiquidity { parent }
        | BurnLiquidity { parent } => {
            let (d, pool) = market_parent(parent, round, &mut resolve)?;
            let op = match operation {
                Swap { .. } => MarketOwnerOperation::Swap,
                DepositLiquidity { .. } => MarketOwnerOperation::Deposit,
                WithdrawLiquidity { .. } => MarketOwnerOperation::Withdraw,
                BurnLiquidity { .. } => MarketOwnerOperation::Burn,
                _ => unreachable!(),
            };
            check_owned_market_operation(context, d, Some(pool), op, inputs, outputs)?;
        }
        TransferLiquidity { definition } => {
            let d = market_definition(definition, &mut resolve)?;
            check_owned_market_operation(
                context,
                d,
                None,
                MarketOwnerOperation::Transfer,
                inputs,
                outputs,
            )?;
        }
        CreateLaunch {
            funding_input,
            definition,
        } => {
            let d = launch_definition(definition, &mut resolve)?;
            let token: FungibleDefinition = one(outputs.iter().filter_map(|o| match o.opening {
                Some(NativeOpening::FungibleDefinition(d)) => Some(d),
                _ => None,
            }))?;
            check_launch_creation(context, token, d, funding_input, inputs, outputs)?;
        }
        LaunchRequest { parent } => {
            let (d, s) = launch_parent(parent, round, &mut resolve)?;
            check_launch_request(context, d, s, inputs, outputs)?;
        }
        CreateListing { definition } => check_listing_creation(
            context,
            listing_definition(definition, &mut resolve)?,
            inputs,
            outputs,
        )?,
        Purchase { parent } => {
            let (d, s) = listing_parent(parent, round, &mut resolve)?;
            let listing = one(inputs.iter().filter(|claim| claim.opening.is_some()))?;
            if listing.input.slot_index != parent.slot_index
                || listing.input.creation_id != parent.creation_id
                || listing.root != parent.root
            {
                return Err(FinancialOwnerError::Dependency);
            }
            check_listing_purchase(context, d, s, inputs, outputs)?;
        }
        CancelListing => {
            let state = one(inputs.iter().filter_map(|o| match o.opening {
                Some(NativeOpening::NftMarket(NftMarketOpening::Listing(s))) => Some(s),
                _ => None,
            }))?;
            check_listing_cancellation(
                context,
                listing_definition(Address(state.listing.0), &mut resolve)?,
                inputs,
                outputs,
            )?;
        }
        CreateOffer { funding_input } => {
            check_offer_funding(context, funding_input, inputs, outputs)?;
        }
        AcceptOffer => check_offer_acceptance(context, inputs, outputs)?,
        CancelOffer => check_offer_cancellation(context, inputs, outputs)?,
        _ => return Err(FinancialOwnerError::Operation),
    }
    Ok(NativeTransitionFacts {
        native_inputs: inputs.iter().filter(|c| c.opening.is_some()).count(),
        native_outputs: outputs.iter().filter(|c| c.opening.is_some()).count(),
        output_is_native: outputs.iter().map(|c| c.opening.is_some()).collect(),
        redeemed_units: 0,
        redemption_micronoid: 0,
        reserve_contribution_micronoid: if matches!(operation, CreateLaunch { .. }) {
            outputs
                .iter()
                .find_map(|o| match o.opening {
                    Some(NativeOpening::TokenReserve(r)) => Some(r.reserve_micronoid),
                    _ => None,
                })
                .unwrap_or(0)
        } else {
            0
        },
        nft_items: outputs
            .iter()
            .filter(|c| matches!(c.opening, Some(NativeOpening::NftItem(_))))
            .count(),
    })
}
