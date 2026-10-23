// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Deterministic public financial transitions over exact funded claims.

use super::{owner::*, FinancialOperation, NativeParentRef};
use crate::native_assets::{
    launch::{
        clearing::{LaunchOutcome, LaunchSettlement},
        queue::{timeout_reset as reset_launch, LaunchRegisteredBatch, LaunchRequestRef},
        LaunchError, LaunchOpening,
    },
    market::{
        mixed::{timeout_claim, MixedBatchSettlement},
        queue::{MarketRequestRef, MixedRegisteredBatch, MAX_ROUND_REQUESTS},
        request::MarketRequest,
        MarketError, MarketOpening, NOID_ASSET,
    },
    nft_market::{
        queue::{timeout_reset as reset_listing, FundedPurchaseRef, ListingBatch},
        settlement::{listing_return, offer_refund, purchase_refund, ListingSettlement, NftPayout},
        NftMarketError, NftMarketOpening, NftRoundContext,
    },
    transition::{NativeContext, NativeInputClaim, NativeOutputClaim, NativeTransitionFacts},
    NativeOpening, TokenBalance,
};
use noid_poseidon2b::primitives::{Address, Digest};
use std::collections::{BTreeMap, BTreeSet};

/// The block derives these records from successful Owner funding groups and
/// their assigned output incarnations. Each family consumes the complete set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinancialRegistration {
    Market {
        parent: NativeParentRef,
        request: MarketRequestRef,
    },
    Launch {
        parent: NativeParentRef,
        request: LaunchRequestRef,
    },
    Listing {
        parent: NativeParentRef,
        request: FundedPurchaseRef,
    },
}

impl FinancialRegistration {
    pub fn parent(self) -> NativeParentRef {
        match self {
            Self::Market { parent, .. }
            | Self::Launch { parent, .. }
            | Self::Listing { parent, .. } => parent,
        }
    }
    pub fn slot(self) -> u32 {
        match self {
            Self::Market { request, .. } => request.slot_index,
            Self::Launch { request, .. } => request.slot_index,
            Self::Listing { request, .. } => request.slot_index,
        }
    }
    pub fn creation_id(self) -> u64 {
        match self {
            Self::Market { request, .. } => request.creation_id,
            Self::Launch { request, .. } => request.creation_id,
            Self::Listing { request, .. } => request.creation_id,
        }
    }
    pub fn registration_operation(self) -> FinancialOperation {
        match self {
            Self::Market { .. } => FinancialOperation::RegisterPools,
            Self::Launch { .. } => FinancialOperation::RegisterLaunches,
            Self::Listing { .. } => FinancialOperation::RegisterListings,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FinancialPublicContext<'a> {
    pub round: NftRoundContext,
    /// Required I/O fee computed from the immutable parent State boundary.
    pub required_fee: u64,
    /// Original registration context, authenticated by the linked header window.
    pub listing_round: Option<NftRoundContext>,
    pub registrations: &'a [FinancialRegistration],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinancialPublicFacts {
    pub transition: NativeTransitionFacts,
    pub auxiliary: Vec<NativeOpening>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinancialPublicError {
    Context,
    Operation,
    Shape,
    Input,
    Output,
    Conservation,
    Fee,
    Registration,
    Dependency(FinancialOwnerError),
    Market(MarketError),
    Launch(LaunchError),
    Nft(NftMarketError),
}
impl core::fmt::Display for FinancialPublicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "financial public: {self:?}")
    }
}
impl std::error::Error for FinancialPublicError {}
impl From<FinancialOwnerError> for FinancialPublicError {
    fn from(e: FinancialOwnerError) -> Self {
        Self::Dependency(e)
    }
}
impl From<MarketError> for FinancialPublicError {
    fn from(e: MarketError) -> Self {
        Self::Market(e)
    }
}
impl From<LaunchError> for FinancialPublicError {
    fn from(e: LaunchError) -> Self {
        Self::Launch(e)
    }
}
impl From<NftMarketError> for FinancialPublicError {
    fn from(e: NftMarketError) -> Self {
        Self::Nft(e)
    }
}

type ExpectedOutput = (u64, Address, Option<NativeOpening>);

fn native(value: NativeOpening) -> ExpectedOutput {
    (value.amount_micronoid(), value.root(), Some(value))
}
fn nft(value: NftPayout) -> ExpectedOutput {
    (value.noid, value.root(), value.opening())
}
fn exact_outputs(
    actual: &[NativeOutputClaim],
    expected: &[ExpectedOutput],
) -> Result<(), FinancialPublicError> {
    if actual.len() != expected.len()
        || actual
            .iter()
            .zip(expected)
            .any(|(a, &(amount, root, opening))| {
                a.output.amount != amount || a.output.owner != root || a.opening != opening
            })
    {
        return Err(FinancialPublicError::Output);
    }
    Ok(())
}
fn parent_ref(claim: &NativeInputClaim) -> NativeParentRef {
    NativeParentRef {
        slot_index: claim.input.slot_index,
        creation_id: claim.input.creation_id,
        root: claim.root,
    }
}
fn market_request(claim: &NativeInputClaim) -> Result<MarketRequestRef, FinancialPublicError> {
    let request = match claim.opening {
        Some(NativeOpening::Market(MarketOpening::Request(r))) => MarketRequest::Swap(r),
        Some(NativeOpening::Market(MarketOpening::LiquidityDeposit(r))) => {
            MarketRequest::Deposit(r)
        }
        Some(NativeOpening::Market(MarketOpening::LiquidityWithdrawal(r))) => {
            MarketRequest::Withdraw(r)
        }
        Some(NativeOpening::Market(MarketOpening::LiquidityBurn(r))) => MarketRequest::Burn(r),
        _ => return Err(FinancialPublicError::Input),
    };
    Ok(MarketRequestRef {
        slot_index: claim.input.slot_index,
        creation_id: claim.input.creation_id,
        request,
    })
}
fn launch_request(claim: &NativeInputClaim) -> Result<LaunchRequestRef, FinancialPublicError> {
    let Some(NativeOpening::Launch(LaunchOpening::Request(request))) = claim.opening else {
        return Err(FinancialPublicError::Input);
    };
    Ok(LaunchRequestRef {
        slot_index: claim.input.slot_index,
        creation_id: claim.input.creation_id,
        request,
    })
}
fn purchase(claim: &NativeInputClaim) -> Result<FundedPurchaseRef, FinancialPublicError> {
    let Some(NativeOpening::NftMarket(NftMarketOpening::Purchase(request))) = claim.opening else {
        return Err(FinancialPublicError::Input);
    };
    Ok(FundedPurchaseRef {
        slot_index: claim.input.slot_index,
        creation_id: claim.input.creation_id,
        request,
    })
}
fn one_input(inputs: &[NativeInputClaim]) -> Result<&NativeInputClaim, FinancialPublicError> {
    if inputs.len() != 1 {
        return Err(FinancialPublicError::Shape);
    }
    Ok(&inputs[0])
}
fn unique_control(
    inputs: &[NativeInputClaim],
    is_control: impl Fn(NativeOpening) -> bool,
) -> Result<usize, FinancialPublicError> {
    let mut matches = inputs
        .iter()
        .enumerate()
        .filter(|(_, c)| c.opening.is_some_and(&is_control));
    let index = matches.next().ok_or(FinancialPublicError::Input)?.0;
    if matches.next().is_some() {
        return Err(FinancialPublicError::Input);
    }
    Ok(index)
}

fn registration_outputs(
    operation: FinancialOperation,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    public: &FinancialPublicContext<'_>,
    resolve: &mut impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<Vec<ExpectedOutput>, FinancialPublicError> {
    let registrations = public.registrations;
    if registrations.is_empty()
        || registrations.len() > MAX_ROUND_REQUESTS
        || inputs.len() > MAX_ROUND_REQUESTS
        || inputs.len() != outputs.len()
    {
        return Err(FinancialPublicError::Registration);
    }
    let mut occupied: BTreeSet<_> = inputs
        .iter()
        .map(|c| c.input.slot_index)
        .chain(outputs.iter().map(|c| c.output.slot_index))
        .collect();
    for &r in registrations {
        r.parent()
            .check_boundary(public.round.parent_alloc_counter())
            .map_err(|_| FinancialPublicError::Registration)?;
        if r.registration_operation() != operation
            || !occupied.insert(r.slot())
            || crate::native_assets::native_sequence(r.creation_id())
                .map_err(|_| FinancialPublicError::Registration)?
                <= public.round.parent_alloc_counter()
            || !inputs.iter().any(|c| parent_ref(c) == r.parent())
        {
            return Err(FinancialPublicError::Registration);
        }
    }
    let mut expected = BTreeMap::<Digest, ExpectedOutput>::new();
    for c in inputs {
        let p = parent_ref(c);
        let out = match (operation, c.opening) {
            (
                FinancialOperation::RegisterPools,
                Some(NativeOpening::Market(MarketOpening::Pool(pool))),
            ) => {
                let d = market_definition(Address(pool.pool.0), resolve)?;
                let requests: Vec<_> = registrations
                    .iter()
                    .filter_map(|r| match *r {
                        FinancialRegistration::Market { parent, request } if parent == p => {
                            Some(request)
                        }
                        _ => None,
                    })
                    .collect();
                let b = MixedRegisteredBatch::register(d, pool, public.round.height(), &requests)?;
                (
                    pool.pool.0,
                    native(NativeOpening::Market(MarketOpening::Pool(b.after()))),
                )
            }
            (
                FinancialOperation::RegisterLaunches,
                Some(NativeOpening::Launch(LaunchOpening::State(state))),
            ) => {
                let d = launch_definition(Address(state.launch.0), resolve)?;
                let requests: Vec<_> = registrations
                    .iter()
                    .filter_map(|r| match *r {
                        FinancialRegistration::Launch { parent, request } if parent == p => {
                            Some(request)
                        }
                        _ => None,
                    })
                    .collect();
                let b =
                    LaunchRegisteredBatch::register(d, state, public.round.height(), &requests)?;
                (
                    state.launch.0,
                    native(NativeOpening::Launch(LaunchOpening::State(b.after()))),
                )
            }
            (
                FinancialOperation::RegisterListings,
                Some(NativeOpening::NftMarket(NftMarketOpening::Listing(state))),
            ) => {
                let d = listing_definition(Address(state.listing.0), resolve)?;
                let requests: Vec<_> = registrations
                    .iter()
                    .filter_map(|r| match *r {
                        FinancialRegistration::Listing { parent, request } if parent == p => {
                            Some(request)
                        }
                        _ => None,
                    })
                    .collect();
                let b = ListingBatch::register(d, state, public.round, &requests)?;
                (
                    state.listing.0,
                    native(NativeOpening::NftMarket(NftMarketOpening::Listing(
                        b.after(),
                    ))),
                )
            }
            _ => return Err(FinancialPublicError::Input),
        };
        if expected.insert(out.0, out.1).is_some() {
            return Err(FinancialPublicError::Registration);
        }
    }
    Ok(expected.into_values().collect())
}

/// The admitting block authenticates the header contexts, the fixed parent
/// fee, every exact input slot and the complete registration extraction.
pub fn check_financial_public(
    context: &NativeContext,
    operation: FinancialOperation,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
    public: &FinancialPublicContext<'_>,
    mut resolve: impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<FinancialPublicFacts, FinancialPublicError> {
    public.round.validate()?;
    if context.chain == [0; 32]
        || context.authority != Address([0; 32])
        || context.height != public.round.height()
    {
        return Err(FinancialPublicError::Context);
    }
    if operation.requires_owner() || !super::super::profile::operation_enabled(operation.code()) {
        return Err(FinancialPublicError::Operation);
    }
    use FinancialOperation::*;
    let registration = matches!(
        operation,
        RegisterPools | RegisterLaunches | RegisterListings
    );
    if !registration && !public.registrations.is_empty()
        || operation != SettleListing && public.listing_round.is_some()
    {
        return Err(FinancialPublicError::Context);
    }
    let zero_fee = operation.has_zero_fee();
    if zero_fee && context.fee != 0
        || !zero_fee && operation != SettleLaunch && context.fee != public.required_fee
    {
        return Err(FinancialPublicError::Fee);
    }
    if inputs.is_empty()
        || inputs.len() > crate::MAX_PAGED_SPEND_INPUTS
        || outputs.is_empty()
        || outputs.len() > crate::MAX_PAGED_SPEND_OUTPUTS
    {
        return Err(FinancialPublicError::Shape);
    }
    let mut occupied = BTreeSet::new();
    let mut noid_in = 0u128;
    let mut noid_out = u128::from(context.fee);
    for c in inputs {
        if !occupied.insert(c.input.slot_index) {
            return Err(FinancialPublicError::Input);
        }
        c.opening
            .ok_or(FinancialPublicError::Input)?
            .check_input(&c.input, c.root, context.height)
            .map_err(|_| FinancialPublicError::Input)?;
        noid_in += u128::from(c.input.amount);
    }
    for c in outputs {
        if !occupied.insert(c.output.slot_index) {
            return Err(FinancialPublicError::Output);
        }
        if let Some(o) = c.opening {
            o.check_output(&c.output)
                .map_err(|_| FinancialPublicError::Output)?;
        } else if c.output.amount == 0 || c.output.owner == Address([0; 32]) {
            return Err(FinancialPublicError::Output);
        }
        noid_out += u128::from(c.output.amount);
    }
    if noid_in != noid_out {
        return Err(FinancialPublicError::Conservation);
    }
    let mut auxiliary = Vec::new();
    let expected = match operation {
        RegisterPools | RegisterLaunches | RegisterListings => {
            registration_outputs(operation, inputs, outputs, public, &mut resolve)?
        }
        SettlePool => {
            let index = unique_control(inputs, |o| {
                matches!(o, NativeOpening::Market(MarketOpening::Pool(_)))
            })?;
            let Some(NativeOpening::Market(MarketOpening::Pool(pool))) = inputs[index].opening
            else {
                unreachable!()
            };
            let d = market_definition(Address(pool.pool.0), &mut resolve)?;
            let requests: Vec<_> = inputs
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != index)
                .map(|(_, c)| market_request(c))
                .collect::<Result<_, _>>()?;
            let b = MixedRegisteredBatch::from_frozen(d, pool, &requests)?;
            let s = MixedBatchSettlement::calculate(d, &b, context.height, public.required_fee)?;
            let mut expected = vec![native(NativeOpening::Market(MarketOpening::Pool(
                s.after(),
            )))];
            expected.extend(s.claims().iter().map(|&o| native(NativeOpening::Market(o))));
            expected
        }
        RefundMarket { definition } => {
            if inputs.len() > MAX_ROUND_REQUESTS {
                return Err(FinancialPublicError::Shape);
            }
            let d = market_definition(definition, &mut resolve)?;
            let mut requests: Vec<_> = inputs
                .iter()
                .map(market_request)
                .collect::<Result<_, _>>()?;
            requests.sort_by_cached_key(|r| r.key());
            let count = requests.len() as u64;
            requests
                .into_iter()
                .enumerate()
                .map(|(i, r)| {
                    let fee = context.fee / count + u64::from((i as u64) < context.fee % count);
                    Ok(native(NativeOpening::Market(timeout_claim(
                        d,
                        r,
                        context.height,
                        fee,
                    )?)))
                })
                .collect::<Result<_, FinancialPublicError>>()?
        }
        ResetPool => {
            let Some(NativeOpening::Market(MarketOpening::Pool(p))) = one_input(inputs)?.opening
            else {
                return Err(FinancialPublicError::Input);
            };
            p.check_definition(market_definition(Address(p.pool.0), &mut resolve)?)?;
            vec![native(NativeOpening::Market(MarketOpening::Pool(
                p.reset_after_timeout(context.height)?,
            )))]
        }
        ClaimLiquidity { definition } => {
            let Some(NativeOpening::Market(MarketOpening::LiquidityClaim(c))) =
                one_input(inputs)?.opening
            else {
                return Err(FinancialPublicError::Input);
            };
            let d = market_definition(definition, &mut resolve)?;
            c.payouts(d, context.fee)?
        }
        ClaimSwap => {
            let Some(NativeOpening::Market(MarketOpening::Claim(c))) = one_input(inputs)?.opening
            else {
                return Err(FinancialPublicError::Input);
            };
            c.payouts(context.fee)?
                .into_iter()
                .map(|p| {
                    if p.asset == NOID_ASSET {
                        (p.units, p.owner, None)
                    } else {
                        native(NativeOpening::TokenBalance(TokenBalance {
                            asset: p.asset,
                            owner: p.owner,
                            units: p.units,
                            unlock_height: 0,
                        }))
                    }
                })
                .collect()
        }
        SettleLaunch => {
            let index = unique_control(inputs, |o| {
                matches!(o, NativeOpening::Launch(LaunchOpening::State(_)))
            })?;
            let Some(NativeOpening::Launch(LaunchOpening::State(state))) = inputs[index].opening
            else {
                unreachable!()
            };
            let d = launch_definition(Address(state.launch.0), &mut resolve)?;
            let requests: Vec<_> = inputs
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != index)
                .map(|(_, c)| launch_request(c))
                .collect::<Result<_, _>>()?;
            let b = LaunchRegisteredBatch::from_frozen(d, state, &requests)?;
            let s = LaunchSettlement::calculate(d, &b, context.height, public.required_fee)?;
            if context.fee != s.fee() {
                return Err(FinancialPublicError::Fee);
            }
            let control = match s.outcome() {
                LaunchOutcome::Continue(s) => NativeOpening::Launch(LaunchOpening::State(s)),
                LaunchOutcome::Graduate(p) => {
                    auxiliary.push(NativeOpening::Market(MarketOpening::Definition(
                        d.market_definition(),
                    )));
                    NativeOpening::Market(MarketOpening::Pool(p))
                }
            };
            let mut expected = vec![native(control)];
            expected.extend(
                s.claims()
                    .iter()
                    .map(|&c| native(NativeOpening::Market(MarketOpening::Claim(c)))),
            );
            expected
        }
        RefundLaunch => {
            if inputs.len() > MAX_ROUND_REQUESTS {
                return Err(FinancialPublicError::Shape);
            }
            let mut requests: Vec<_> = inputs
                .iter()
                .map(launch_request)
                .collect::<Result<_, _>>()?;
            requests.sort_by_cached_key(|r| r.key());
            let count = requests.len() as u64;
            requests
                .into_iter()
                .enumerate()
                .map(|(i, r)| {
                    let fee = context.fee / count + u64::from((i as u64) < context.fee % count);
                    Ok(native(NativeOpening::Market(MarketOpening::Claim(
                        r.request.timeout_claim(r.key(), context.height, fee)?,
                    ))))
                })
                .collect::<Result<_, FinancialPublicError>>()?
        }
        ResetLaunch => {
            let Some(NativeOpening::Launch(LaunchOpening::State(s))) = one_input(inputs)?.opening
            else {
                return Err(FinancialPublicError::Input);
            };
            let d = launch_definition(Address(s.launch.0), &mut resolve)?;
            vec![native(NativeOpening::Launch(LaunchOpening::State(
                reset_launch(d, s, context.height)?,
            )))]
        }
        SettleListing => {
            let index = unique_control(inputs, |o| {
                matches!(o, NativeOpening::NftMarket(NftMarketOpening::Listing(_)))
            })?;
            let Some(NativeOpening::NftMarket(NftMarketOpening::Listing(s))) =
                inputs[index].opening
            else {
                unreachable!()
            };
            let d = listing_definition(Address(s.listing.0), &mut resolve)?;
            let round = public.listing_round.ok_or(FinancialPublicError::Context)?;
            let requests: Vec<_> = inputs
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != index)
                .map(|(_, c)| purchase(c))
                .collect::<Result<_, _>>()?;
            let b = ListingBatch::from_frozen(d, s, &requests, round)?;
            let s = ListingSettlement::calculate(&b, context.height, context.fee)?;
            s.payouts().iter().copied().map(nft).collect()
        }
        ResetListing | RecoverListing => {
            let Some(NativeOpening::NftMarket(NftMarketOpening::Listing(s))) =
                one_input(inputs)?.opening
            else {
                return Err(FinancialPublicError::Input);
            };
            let d = listing_definition(Address(s.listing.0), &mut resolve)?;
            if operation == ResetListing {
                vec![native(NativeOpening::NftMarket(NftMarketOpening::Listing(
                    reset_listing(d, s, context.height)?,
                )))]
            } else {
                s.expired_recovery(d, context.height)?;
                listing_return(d, context.fee)?
                    .into_iter()
                    .map(nft)
                    .collect()
            }
        }
        RefundPurchase => {
            let r = purchase(one_input(inputs)?)?;
            vec![nft(purchase_refund(
                r.request,
                context.height,
                context.fee,
            )?)]
        }
        RefundOffer => {
            let Some(NativeOpening::NftMarket(NftMarketOpening::Offer(o))) =
                one_input(inputs)?.opening
            else {
                return Err(FinancialPublicError::Input);
            };
            if context.height < o.expiry_height {
                return Err(FinancialPublicError::Nft(NftMarketError::Phase));
            }
            vec![nft(offer_refund(o, context.fee)?)]
        }
        _ => return Err(FinancialPublicError::Operation),
    };
    exact_outputs(outputs, &expected)?;
    Ok(FinancialPublicFacts {
        transition: NativeTransitionFacts {
            native_inputs: inputs.len(),
            native_outputs: outputs.iter().filter(|c| c.opening.is_some()).count(),
            output_is_native: outputs.iter().map(|c| c.opening.is_some()).collect(),
            redeemed_units: 0,
            redemption_micronoid: 0,
            reserve_contribution_micronoid: 0,
            nft_items: outputs
                .iter()
                .filter(|c| matches!(c.opening, Some(NativeOpening::NftItem(_))))
                .count(),
        },
        auxiliary,
    })
}
