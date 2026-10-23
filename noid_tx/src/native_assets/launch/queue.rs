// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete funded launch rounds with immutable membership and deadlines.

use super::*;
use crate::native_assets::market::queue::{
    committed_queue_root, funded_request_key, MAX_ROUND_REQUESTS,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchRequestRef {
    pub slot_index: u32,
    pub creation_id: u64,
    pub request: LaunchRequest,
}
impl LaunchRequestRef {
    pub fn validate(self) -> Result<(), LaunchError> {
        validate_funded_request(self.creation_id, self.request)
    }
    pub fn key(self) -> Digest {
        funded_request_key(self.request.root(), self.slot_index, self.creation_id)
    }
    pub fn root(self) -> Address {
        self.request.root()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRegisteredBatch {
    before: LaunchState,
    after: LaunchState,
    round: Digest,
    requests: Vec<LaunchRequestRef>,
}
impl LaunchRegisteredBatch {
    pub fn register(
        definition: LaunchDefinition,
        before: LaunchState,
        height: u64,
        requests: &[LaunchRequestRef],
    ) -> Result<Self, LaunchError> {
        before.check_definition(definition)?;
        if requests.is_empty() || requests.len() > MAX_ROUND_REQUESTS {
            return Err(LaunchError::Capacity);
        }
        let round = before.round_id(height)?;
        let mut slots = BTreeSet::new();
        let mut keyed = Vec::with_capacity(requests.len());
        let mut buys = u128::from(before.market_noid);
        let mut sells = 0u128;
        for r in requests {
            r.validate()?;
            r.request.check_round(definition, before, height)?;
            if !slots.insert(r.slot_index) {
                return Err(LaunchError::Duplicate);
            }
            match r.request.side {
                LaunchSide::Buy => buys += u128::from(r.request.noid_limit),
                LaunchSide::Sell => sells += u128::from(r.request.quantity),
            }
            keyed.push((r.key(), *r));
        }
        if buys > u128::from(MARKET_QUANTITY_MAX)
            || sells > u128::from(definition.initial_supply - before.inventory_units)
        {
            return Err(LaunchError::Capacity);
        }
        keyed.sort_unstable_by_key(|(key, _)| *key);
        if keyed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(LaunchError::Duplicate);
        }
        let keys: Vec<_> = keyed.iter().map(|(key, _)| *key).collect();
        let after = LaunchState {
            queue_root: committed_queue_root(round, &keys).map_err(|_| LaunchError::Queue)?,
            registered_height: height,
            timeout_height: expiry(height)?,
            request_count: requests.len() as u16,
            phase: PoolPhase::Frozen,
            ..before
        };
        after.check_definition(definition)?;
        Ok(Self {
            before,
            after,
            round,
            requests: keyed.into_iter().map(|(_, r)| r).collect(),
        })
    }
    pub fn from_frozen(
        definition: LaunchDefinition,
        frozen: LaunchState,
        requests: &[LaunchRequestRef],
    ) -> Result<Self, LaunchError> {
        if frozen.phase != PoolPhase::Frozen {
            return Err(LaunchError::Phase);
        }
        let batch = Self::register(
            definition,
            frozen.idle_view(),
            frozen.registered_height,
            requests,
        )?;
        if batch.after != frozen {
            return Err(LaunchError::Queue);
        }
        Ok(batch)
    }
    pub fn before(&self) -> LaunchState {
        self.before
    }
    pub fn after(&self) -> LaunchState {
        self.after
    }
    pub fn round(&self) -> Digest {
        self.round
    }
    pub fn requests(&self) -> &[LaunchRequestRef] {
        &self.requests
    }
    pub fn settlement_allowed(&self, height: u64) -> Result<(), LaunchError> {
        if self.after.phase_at(height)? == RoundPhase::Settlement {
            Ok(())
        } else {
            Err(LaunchError::Phase)
        }
    }
}

pub fn timeout_reset(
    definition: LaunchDefinition,
    before: LaunchState,
    height: u64,
) -> Result<LaunchState, LaunchError> {
    before.check_definition(definition)?;
    if before.phase_at(height)? != RoundPhase::Refund {
        return Err(LaunchError::Phase);
    }
    let next = LaunchState {
        generation: before
            .generation
            .checked_add(1)
            .ok_or(LaunchError::Arithmetic)?,
        ..before.idle_view()
    };
    next.check_definition(definition)?;
    Ok(next)
}
