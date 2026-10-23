// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Count-bound complete funded-request queues and round transitions.

use super::{
    hash_fields,
    request::{MarketRequest, RequestValue},
    MarketDefinition, MarketError, PoolPhase, PoolState, RoundPhase, SwapRequest,
    MARKET_QUANTITY_MAX,
};
use crate::native_assets::native_sequence;
use noid_core::Block128;
use noid_poseidon2b::{
    native::{compress_with_tag, DomainTag},
    primitives::{Address, Digest},
};
use std::collections::BTreeSet;

pub const MAX_ROUND_REQUESTS: usize = 16;
pub const QUEUE_LEAF_CAPACITY: usize = MAX_ROUND_REQUESTS.next_power_of_two();
pub type MarketRequestRef = FundedRequestRef<MarketRequest>;
pub type MixedRegisteredBatch = RegisteredBatch<MarketRequest>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundedRequestRef<T = SwapRequest> {
    pub slot_index: u32,
    pub creation_id: u64,
    pub request: T,
}
impl<T: RequestValue> FundedRequestRef<T> {
    pub fn validate(self) -> Result<(), MarketError> {
        native_sequence(self.creation_id).map_err(|_| MarketError::Funding)?;
        self.request.validate()
    }
    pub fn key(self) -> Digest {
        funded_request_key(self.request.root(), self.slot_index, self.creation_id)
    }
    pub fn root(self) -> Address {
        self.request.root()
    }
}

pub fn funded_request_key(root: Address, slot_index: u32, creation_id: u64) -> Digest {
    let r = root.as_fields();
    hash_fields(
        DomainTag::new(b"MKREQID1"),
        &[
            r[0],
            r[1],
            Block128(u128::from(slot_index)),
            Block128(u128::from(creation_id)),
        ],
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredBatch<T = SwapRequest> {
    before: PoolState,
    after: PoolState,
    round: Digest,
    requests: Vec<FundedRequestRef<T>>,
}
impl<T: RequestValue> RegisteredBatch<T> {
    pub fn register(
        definition: MarketDefinition,
        before: PoolState,
        height: u64,
        requests: &[FundedRequestRef<T>],
    ) -> Result<Self, MarketError> {
        before.check_definition(definition)?;
        if before.phase != PoolPhase::Idle {
            return Err(MarketError::Phase);
        }
        let round = before.round_id(height)?;
        let keyed = canonical_requests(requests)?;
        let mut principal = [
            u128::from(before.base_reserve),
            u128::from(before.quote_reserve),
        ];
        let mut shares = 0u128;
        for (_, r) in &keyed {
            r.request.check_round(definition, before, height)?;
            let amount = r.request.principal(definition)?;
            for side in 0..2 {
                principal[side] += u128::from(amount[side]);
            }
            shares += u128::from(r.request.consumed_lp_shares());
        }
        if principal
            .iter()
            .any(|&n| n > u128::from(MARKET_QUANTITY_MAX))
            || shares > u128::from(before.total_shares - before.locked_shares)
        {
            return Err(MarketError::Capacity);
        }
        let after = PoolState {
            queue_root: queue_root_from_keys(round, &keyed)?,
            registered_height: height,
            timeout_height: height
                .checked_add(super::MARKET_SETTLEMENT_WINDOW)
                .ok_or(MarketError::Arithmetic)?,
            request_count: keyed.len() as u16,
            phase: PoolPhase::Frozen,
            ..before
        };
        after.validate()?;
        Ok(Self {
            before,
            after,
            round,
            requests: keyed.into_iter().map(|(_, request)| request).collect(),
        })
    }
    pub fn from_frozen(
        definition: MarketDefinition,
        pool: PoolState,
        requests: &[FundedRequestRef<T>],
    ) -> Result<Self, MarketError> {
        pool.check_definition(definition)?;
        if pool.phase != PoolPhase::Frozen {
            return Err(MarketError::Phase);
        }
        let batch = Self::register(
            definition,
            pool.idle_view(),
            pool.registered_height,
            requests,
        )?;
        if batch.after != pool {
            return Err(MarketError::Queue);
        }
        Ok(batch)
    }
    pub fn before(&self) -> PoolState {
        self.before
    }
    pub fn after(&self) -> PoolState {
        self.after
    }
    pub fn round(&self) -> Digest {
        self.round
    }
    pub fn requests(&self) -> &[FundedRequestRef<T>] {
        &self.requests
    }
    pub fn settlement_allowed(&self, height: u64) -> Result<(), MarketError> {
        if self.after.phase_at(height)? == RoundPhase::Settlement {
            Ok(())
        } else {
            Err(MarketError::Phase)
        }
    }
}

fn canonical_requests<T: RequestValue>(
    requests: &[FundedRequestRef<T>],
) -> Result<Vec<(Digest, FundedRequestRef<T>)>, MarketError> {
    if requests.is_empty() || requests.len() > MAX_ROUND_REQUESTS {
        return Err(MarketError::Capacity);
    }
    let mut slots = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut keyed = Vec::with_capacity(requests.len());
    for r in requests {
        r.validate()?;
        let key = r.key();
        if !slots.insert(r.slot_index) || !keys.insert(key) {
            return Err(MarketError::Duplicate);
        }
        keyed.push((key, *r));
    }
    keyed.sort_unstable_by_key(|(key, _)| *key);
    Ok(keyed)
}

pub fn queue_root<T: RequestValue>(
    round: Digest,
    requests: &[FundedRequestRef<T>],
) -> Result<Digest, MarketError> {
    queue_root_from_keys(round, &canonical_requests(requests)?)
}

fn queue_root_from_keys<T: RequestValue>(
    round: Digest,
    requests: &[(Digest, FundedRequestRef<T>)],
) -> Result<Digest, MarketError> {
    committed_queue_root(
        round,
        &requests.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
    )
}

pub fn committed_queue_root(round: Digest, keys: &[Digest]) -> Result<Digest, MarketError> {
    if round == [0; 32] {
        return Err(MarketError::Identifier);
    }
    if keys.is_empty() || keys.len() > MAX_ROUND_REQUESTS {
        return Err(MarketError::Capacity);
    }
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(MarketError::Duplicate);
    }
    let mut layer = [[0; 32]; QUEUE_LEAF_CAPACITY];
    for (i, key) in keys.iter().enumerate() {
        layer[i] = *key
    }
    let mut n = QUEUE_LEAF_CAPACITY;
    while n > 1 {
        for i in 0..n / 2 {
            layer[i] = compress_with_tag(
                DomainTag::new(b"MKQNOD21"),
                &layer[2 * i],
                &layer[2 * i + 1],
            )
        }
        n /= 2;
    }
    let root = Address(layer[0]).as_fields();
    let round = Address(round).as_fields();
    Ok(hash_fields(
        DomainTag::new(b"MKQROOT1"),
        &[
            root[0],
            root[1],
            round[0],
            round[1],
            Block128(keys.len() as u128),
            Block128(0),
        ],
    ))
}

impl RegisteredBatch<MarketRequest> {
    /// Project every swap member from an already validated complete mixed set.
    pub(super) fn swap_projection(&self) -> RegisteredBatch<SwapRequest> {
        RegisteredBatch {
            before: self.before,
            after: self.after,
            round: self.round,
            requests: self
                .requests
                .iter()
                .filter_map(|r| match r.request {
                    MarketRequest::Swap(request) => Some(FundedRequestRef {
                        slot_index: r.slot_index,
                        creation_id: r.creation_id,
                        request,
                    }),
                    _ => None,
                })
                .collect(),
        }
    }
}
