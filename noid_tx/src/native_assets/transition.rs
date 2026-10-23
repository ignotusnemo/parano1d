// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Atomic native-operation semantics over authenticated input/output claims.

use std::collections::{BTreeMap, BTreeSet};

use noid_poseidon2b::primitives::{Address, Digest};

use super::{
    financial::FinancialOperation, AssetId, FungibleDefinition, GenesisAnchor, IssuanceRoute,
    NativeAssetError, NativeOpening, NftCollection, TokenReserve, NATIVE_CREATION_TAG,
};
use crate::{TxInput, TxOutput, MAX_PAGED_SPEND_INPUTS, MAX_PAGED_SPEND_OUTPUTS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeInputClaim {
    pub input: TxInput,
    pub root: Address,
    pub opening: Option<NativeOpening>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeOutputClaim {
    pub output: TxOutput,
    pub opening: Option<NativeOpening>,
}

/// Context supplied by the admitting block and its Owner statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeContext {
    pub chain: Digest,
    pub height: u64,
    pub authority: Address,
    pub fee: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeOperation {
    CreateToken { funding_input: u16 },
    TransferToken { asset: AssetId },
    RedeemToken { asset: AssetId },
    TopUpReserve { asset: AssetId },
    CreateCollection { funding_input: u16 },
    MintNft,
    TransferNft,
    BurnNft,
    Financial(FinancialOperation),
}

impl NativeOperation {
    pub fn enabled(self) -> bool {
        match self {
            Self::CreateToken { .. } | Self::TopUpReserve { .. } => false,
            Self::Financial(operation) => super::profile::operation_enabled(operation.code()),
            _ => true,
        }
    }

    pub fn requires_owner(self) -> bool {
        match self {
            Self::Financial(operation) => operation.requires_owner(),
            _ => true,
        }
    }

    pub fn funding_input(self) -> Option<u16> {
        match self {
            Self::CreateToken { funding_input } | Self::CreateCollection { funding_input } => {
                Some(funding_input)
            }
            Self::Financial(operation) => operation.funding_input(),
            _ => None,
        }
    }

    pub fn with_funding_input(self, funding_input: u16) -> Result<Self, NativeTransitionError> {
        Ok(match self {
            Self::CreateToken { .. } => Self::CreateToken { funding_input },
            Self::CreateCollection { .. } => Self::CreateCollection { funding_input },
            Self::Financial(operation) => Self::Financial(
                operation
                    .with_funding_input(funding_input)
                    .map_err(|_| NativeTransitionError::Operation)?,
            ),
            _ => return Err(NativeTransitionError::Operation),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTransitionFacts {
    pub native_inputs: usize,
    pub native_outputs: usize,
    /// Each true entry is allocated in the native incarnation namespace.
    pub output_is_native: Vec<bool>,
    pub redeemed_units: u64,
    pub redemption_micronoid: u64,
    pub reserve_contribution_micronoid: u64,
    pub nft_items: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeTransitionError {
    Context,
    Shape,
    InputSlot,
    OutputSlot,
    Authority,
    NoidConservation,
    Operation,
    Asset,
    TokenConservation,
    Reserve,
    NftConservation,
    Supply,
    Opening(NativeAssetError),
}

impl core::fmt::Display for NativeTransitionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "native transition: {self:?}")
    }
}

impl std::error::Error for NativeTransitionError {}

impl From<NativeAssetError> for NativeTransitionError {
    fn from(error: NativeAssetError) -> Self {
        Self::Opening(error)
    }
}

/// Check one complete logical operation before applying its slot delta.
/// The caller binds every claim to the transaction body and exact State,
/// verifies the Owner statement, and enforces the shared activation schedule.
pub fn check_native_transition(
    context: &NativeContext,
    operation: NativeOperation,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<NativeTransitionFacts, NativeTransitionError> {
    if !operation.enabled() {
        return Err(NativeTransitionError::Operation);
    }
    if context.chain == [0; 32] || context.authority == Address([0; 32]) {
        return Err(NativeTransitionError::Context);
    }
    if inputs.is_empty()
        || inputs.len() > MAX_PAGED_SPEND_INPUTS
        || outputs.len() > MAX_PAGED_SPEND_OUTPUTS
    {
        return Err(NativeTransitionError::Shape);
    }
    let mut input_slots = BTreeSet::new();
    let mut output_slots = BTreeSet::new();
    let mut noid_input = 0u128;
    let mut noid_output = u128::from(context.fee);
    for claim in inputs {
        if !input_slots.insert(claim.input.slot_index) {
            return Err(NativeTransitionError::InputSlot);
        }
        if let Some(opening) = &claim.opening {
            opening.check_input(&claim.input, claim.root, context.height)?;
            let authority = match opening {
                NativeOpening::TokenBalance(balance) => Some(balance.owner),
                NativeOpening::NftCollection(collection) => Some(collection.creator),
                NativeOpening::NftItem(item) => Some(item.owner),
                NativeOpening::TokenReserve(_) | NativeOpening::FungibleDefinition(_) => None,
                NativeOpening::Market(_)
                | NativeOpening::Launch(_)
                | NativeOpening::NftMarket(_) => return Err(NativeTransitionError::Shape),
            };
            if authority.is_some_and(|owner| owner != context.authority) {
                return Err(NativeTransitionError::Authority);
            }
        } else {
            let creation = claim.input.creation_id;
            if creation == 0 || (creation >= NATIVE_CREATION_TAG && creation & (1 << 63) == 0) {
                return Err(NativeAssetError::Provenance.into());
            }
            if claim.root != context.authority {
                return Err(NativeTransitionError::Authority);
            }
        }
        noid_input += u128::from(claim.input.amount);
    }
    let mut output_is_native = Vec::with_capacity(outputs.len());
    for claim in outputs {
        if input_slots.contains(&claim.output.slot_index)
            || !output_slots.insert(claim.output.slot_index)
        {
            return Err(NativeTransitionError::OutputSlot);
        }
        if let Some(opening) = &claim.opening {
            if matches!(
                opening,
                NativeOpening::Market(_) | NativeOpening::Launch(_) | NativeOpening::NftMarket(_)
            ) {
                return Err(NativeTransitionError::Shape);
            }
            opening.check_output(&claim.output)?;
        }
        output_is_native.push(claim.opening.is_some());
        noid_output += u128::from(claim.output.amount);
    }
    if noid_input != noid_output {
        return Err(NativeTransitionError::NoidConservation);
    }
    let before: Vec<_> = inputs.iter().filter_map(|c| c.opening.as_ref()).collect();
    let after: Vec<_> = outputs.iter().filter_map(|c| c.opening.as_ref()).collect();
    let mut facts = NativeTransitionFacts {
        native_inputs: before.len(),
        native_outputs: after.len(),
        output_is_native,
        redeemed_units: 0,
        redemption_micronoid: 0,
        reserve_contribution_micronoid: 0,
        nft_items: 0,
    };
    match operation {
        NativeOperation::Financial(_) => return Err(NativeTransitionError::Operation),
        NativeOperation::CreateToken { funding_input } => {
            if !before.is_empty() {
                return Err(NativeTransitionError::Operation);
            }
            let anchor = funding_anchor(context, inputs, funding_input)?;
            create_token(&anchor, &after)?;
        }
        NativeOperation::TransferToken { asset } => {
            let (input_units, _) = token_balances(&before, asset, true)?;
            let (output_units, _) = token_balances(&after, asset, true)?;
            if input_units != output_units {
                return Err(NativeTransitionError::TokenConservation);
            }
        }
        NativeOperation::RedeemToken { asset } => {
            let (old, old_balances) = separate_reserve(&before, asset)?;
            let (next, new_balances) = separate_reserve(&after, asset)?;
            let (input_units, _) = token_balances(&old_balances, asset, true)?;
            let (output_units, _) = token_balances(&new_balances, asset, false)?;
            let burned = input_units
                .checked_sub(output_units)
                .filter(|&n| n != 0)
                .ok_or(NativeTransitionError::TokenConservation)?;
            let (expected, payout) = old.redeem(burned)?;
            if next != expected {
                return Err(NativeTransitionError::Reserve);
            }
            facts.redeemed_units = burned;
            facts.redemption_micronoid = payout;
        }
        NativeOperation::TopUpReserve { asset } => {
            let (old, old_balances) = separate_reserve(&before, asset)?;
            let (next, new_balances) = separate_reserve(&after, asset)?;
            if !old_balances.is_empty() || !new_balances.is_empty() {
                return Err(NativeTransitionError::Operation);
            }
            let contribution = next
                .reserve_micronoid
                .checked_sub(old.reserve_micronoid)
                .filter(|&n| n != 0)
                .ok_or(NativeTransitionError::Reserve)?;
            if old.top_up(contribution)? != next {
                return Err(NativeTransitionError::Reserve);
            }
            facts.reserve_contribution_micronoid = contribution;
        }
        NativeOperation::CreateCollection { funding_input } => {
            if !before.is_empty() || after.len() != 1 {
                return Err(NativeTransitionError::Operation);
            }
            let NativeOpening::NftCollection(collection) = *after[0] else {
                return Err(NativeTransitionError::Operation);
            };
            let anchor = funding_anchor(context, inputs, funding_input)?;
            if collection
                != NftCollection::from_genesis(
                    &anchor,
                    collection.maximum_items,
                    collection.metadata,
                )?
            {
                return Err(NativeTransitionError::Supply);
            }
        }
        NativeOperation::MintNft => {
            facts.nft_items = mint_nft(&before, &after)?;
        }
        NativeOperation::TransferNft => {
            let old = nft_inventory(&before)?;
            let next = nft_inventory(&after)?;
            if old.is_empty() || old != next {
                return Err(NativeTransitionError::NftConservation);
            }
            facts.nft_items = old.len();
        }
        NativeOperation::BurnNft => {
            let old = nft_inventory(&before)?;
            if old.is_empty() || !after.is_empty() {
                return Err(NativeTransitionError::NftConservation);
            }
            facts.nft_items = old.len();
        }
    }
    Ok(facts)
}

fn funding_anchor(
    context: &NativeContext,
    inputs: &[NativeInputClaim],
    index: u16,
) -> Result<GenesisAnchor, NativeTransitionError> {
    let funding = inputs
        .get(usize::from(index))
        .ok_or(NativeTransitionError::InputSlot)?;
    if funding.opening.is_some() {
        return Err(NativeTransitionError::Operation);
    }
    let anchor = GenesisAnchor {
        chain: context.chain,
        owner: context.authority,
        input: funding.input,
    };
    anchor.validate()?;
    Ok(anchor)
}

fn create_token(
    anchor: &GenesisAnchor,
    after: &[&NativeOpening],
) -> Result<(), NativeTransitionError> {
    let mut definition = None;
    let mut reserve = None;
    let mut balances = Vec::new();
    for opening in after {
        match opening {
            NativeOpening::FungibleDefinition(d) if definition.is_none() => definition = Some(*d),
            NativeOpening::TokenReserve(r) if reserve.is_none() => reserve = Some(*r),
            NativeOpening::TokenBalance(_) => balances.push(*opening),
            _ => return Err(NativeTransitionError::Operation),
        }
    }
    let definition = definition.ok_or(NativeTransitionError::Operation)?;
    let reserve = reserve.ok_or(NativeTransitionError::Operation)?;
    if definition.route != IssuanceRoute::Standalone
        || definition
            != FungibleDefinition::from_genesis(
                anchor,
                definition.initial_supply,
                definition.route,
                definition.metadata,
            )?
    {
        return Err(NativeTransitionError::Asset);
    }
    if reserve != TokenReserve::from_definition(&definition, reserve.reserve_micronoid)? {
        return Err(NativeTransitionError::Reserve);
    }
    let (units, _) = token_balances(&balances, definition.asset, true)?;
    if units != definition.initial_supply {
        return Err(NativeTransitionError::TokenConservation);
    }
    Ok(())
}

fn token_balances(
    openings: &[&NativeOpening],
    asset: AssetId,
    require_nonempty: bool,
) -> Result<(u64, usize), NativeTransitionError> {
    if require_nonempty && openings.is_empty() {
        return Err(NativeTransitionError::Operation);
    }
    let mut units = 0u64;
    for opening in openings {
        let NativeOpening::TokenBalance(balance) = opening else {
            return Err(NativeTransitionError::Operation);
        };
        if balance.asset != asset {
            return Err(NativeTransitionError::Asset);
        }
        units = units
            .checked_add(balance.units)
            .ok_or(NativeTransitionError::TokenConservation)?;
    }
    Ok((units, openings.len()))
}

fn separate_reserve<'a>(
    openings: &[&'a NativeOpening],
    asset: AssetId,
) -> Result<(TokenReserve, Vec<&'a NativeOpening>), NativeTransitionError> {
    let mut reserve = None;
    let mut balances = Vec::new();
    for &opening in openings {
        match opening {
            NativeOpening::TokenReserve(r) if reserve.is_none() => {
                if r.asset != asset {
                    return Err(NativeTransitionError::Asset);
                }
                reserve = Some(*r);
            }
            NativeOpening::TokenBalance(_) => balances.push(opening),
            _ => return Err(NativeTransitionError::Operation),
        }
    }
    Ok((reserve.ok_or(NativeTransitionError::Reserve)?, balances))
}

fn mint_nft(
    before: &[&NativeOpening],
    after: &[&NativeOpening],
) -> Result<usize, NativeTransitionError> {
    if before.len() != 1 || after.len() < 2 {
        return Err(NativeTransitionError::Operation);
    }
    let NativeOpening::NftCollection(old) = *before[0] else {
        return Err(NativeTransitionError::Operation);
    };
    let mut successor = None;
    let mut next_serial = old.issued_items;
    let mut count = 0;
    for opening in after {
        match opening {
            NativeOpening::NftCollection(c) if successor.is_none() => successor = Some(*c),
            NativeOpening::NftItem(item) => {
                next_serial = next_serial
                    .checked_add(1)
                    .ok_or(NativeTransitionError::Supply)?;
                if item.collection != old.collection || item.serial != next_serial {
                    return Err(NativeTransitionError::NftConservation);
                }
                count += 1;
            }
            _ => return Err(NativeTransitionError::Operation),
        }
    }
    let expected = NftCollection {
        issued_items: next_serial,
        ..old
    };
    if count == 0 || next_serial > old.maximum_items || successor != Some(expected) {
        return Err(NativeTransitionError::Supply);
    }
    Ok(count)
}

fn nft_inventory(
    openings: &[&NativeOpening],
) -> Result<BTreeMap<(super::CollectionId, u64), Digest>, NativeTransitionError> {
    let mut items = BTreeMap::new();
    for opening in openings {
        let NativeOpening::NftItem(item) = opening else {
            return Err(NativeTransitionError::Operation);
        };
        if items
            .insert((item.collection, item.serial), item.metadata)
            .is_some()
        {
            return Err(NativeTransitionError::NftConservation);
        }
    }
    Ok(items)
}
