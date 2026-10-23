// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete funded purchase sets with exact listing and round identities.

use super::*;
use crate::native_assets::market::queue::{
    committed_queue_root, funded_request_key, MAX_ROUND_REQUESTS,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundedPurchaseRef {
    pub slot_index: u32,
    pub creation_id: u64,
    pub request: PurchaseRequest,
}
impl FundedPurchaseRef {
    pub fn validate(self) -> Result<(), NftMarketError> {
        native_sequence(self.creation_id).map_err(|_| NftMarketError::Incarnation)?;
        self.request.validate()
    }
    pub fn key(self) -> Digest {
        funded_request_key(self.request.root(), self.slot_index, self.creation_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingBatch {
    context: NftRoundContext,
    definition: ListingDefinition,
    before: ListingState,
    after: ListingState,
    requests: Vec<FundedPurchaseRef>,
}
impl ListingBatch {
    pub fn register(
        definition: ListingDefinition,
        before: ListingState,
        context: NftRoundContext,
        requests: &[FundedPurchaseRef],
    ) -> Result<Self, NftMarketError> {
        before.check_definition(definition)?;
        context.validate()?;
        let height = context.height();
        if requests.is_empty() || requests.len() > MAX_ROUND_REQUESTS {
            return Err(NftMarketError::Capacity);
        }
        let round = before.round_id(context)?;
        if height
            .checked_add(1)
            .is_none_or(|h| h >= definition.expiry_height)
        {
            return Err(NftMarketError::Expired);
        }
        let mut slots = BTreeSet::new();
        let mut keyed = Vec::with_capacity(requests.len());
        let mut noid = u128::from(NFT_FEE_CREDIT);
        for &r in requests {
            r.validate()?;
            if r.request.listing != before.listing
                || r.request.round != round
                || r.request.registered_height != height
                || r.request.budget < definition.ask
            {
                return Err(NftMarketError::Funding);
            }
            if !slots.insert(r.slot_index) {
                return Err(NftMarketError::Duplicate);
            }
            noid += u128::from(r.request.noid_value()?);
            keyed.push((r.key(), r));
        }
        if noid > u128::from(MARKET_QUANTITY_MAX) {
            return Err(NftMarketError::Capacity);
        }
        keyed.sort_unstable_by_key(|(k, _)| *k);
        if keyed.windows(2).any(|p| p[0].0 == p[1].0) {
            return Err(NftMarketError::Duplicate);
        }
        let keys: Vec<_> = keyed.iter().map(|(k, _)| *k).collect();
        let after = ListingState {
            queue_root: committed_queue_root(round, &keys).map_err(|_| NftMarketError::Queue)?,
            registered_height: height,
            request_count: requests.len() as u16,
            phase: PoolPhase::Frozen,
            ..before
        };
        after.check_definition(definition)?;
        Ok(Self {
            context,
            definition,
            before,
            after,
            requests: keyed.into_iter().map(|(_, r)| r).collect(),
        })
    }
    pub fn from_frozen(
        d: ListingDefinition,
        s: ListingState,
        requests: &[FundedPurchaseRef],
        context: NftRoundContext,
    ) -> Result<Self, NftMarketError> {
        if s.phase != PoolPhase::Frozen || context.height() != s.registered_height {
            return Err(NftMarketError::Phase);
        }
        let b = Self::register(d, s.idle_view(), context, requests)?;
        if b.after != s {
            return Err(NftMarketError::Queue);
        }
        Ok(b)
    }
    pub fn definition(&self) -> ListingDefinition {
        self.definition
    }
    pub fn context(&self) -> NftRoundContext {
        self.context
    }
    pub fn before(&self) -> ListingState {
        self.before
    }
    pub fn after(&self) -> ListingState {
        self.after
    }
    pub fn requests(&self) -> &[FundedPurchaseRef] {
        &self.requests
    }
    pub fn settlement_allowed(&self, height: u64) -> Result<(), NftMarketError> {
        if height >= self.definition.expiry_height {
            return Err(NftMarketError::Expired);
        }
        if self.after.phase_at(height)? != RoundPhase::Settlement {
            return Err(NftMarketError::Phase);
        }
        Ok(())
    }
}

pub fn timeout_reset(
    d: ListingDefinition,
    s: ListingState,
    height: u64,
) -> Result<ListingState, NftMarketError> {
    s.check_definition(d)?;
    if s.phase_at(height)? != RoundPhase::Refund {
        return Err(NftMarketError::Phase);
    }
    let next = ListingState {
        generation: s.generation.checked_add(1).ok_or(NftMarketError::Height)?,
        ..s.idle_view()
    };
    next.check_definition(d)?;
    Ok(next)
}
