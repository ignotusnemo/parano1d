// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Count-bound trade policy sets and their authenticated market parent.

use std::collections::BTreeSet;

use noid_core::Block128;
use noid_poseidon2b::{native::DomainTag, primitives::Address};

use super::{
    sequencing::{MarketStart, SequencingPlan, TradeBoundary},
    take, TradeError, TradeIntent, MAX_TRADE_INTENT_BYTES, TRADE_INTENT_FIXED_BYTES,
};
use crate::native_assets::{
    launch::{sequential::SequentialLaunch, LaunchOpening},
    market::{
        hash_fields,
        sequential::{SequentialMarket, MAX_SEQUENTIAL_TRADES},
        MarketOpening,
    },
    transition::NativeInputClaim,
    AssetId, NativeOpening, MAX_NATIVE_OPENING_BYTES,
};
use crate::{TxInput, MAX_PAGED_SPEND_INPUTS};

pub const TRADE_BATCH_MAGIC: &[u8; 8] = b"NOIDBT21";
pub const TRADE_BATCH_VERSION: u16 = 1;
pub const MAX_TRADE_BATCH_BYTES: usize = 16
    + 12
    + 4
    + 2 * MAX_NATIVE_OPENING_BYTES
    + MAX_TRADE_INTENT_BYTES
    + MAX_SEQUENTIAL_TRADES * 4
    + (MAX_SEQUENTIAL_TRADES - 1) * TRADE_INTENT_FIXED_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchError {
    Encoding,
    Bounds,
    Parent,
    Policy(TradeError),
    Sequence,
    Unfilled,
}

impl From<TradeError> for BatchError {
    fn from(value: TradeError) -> Self {
        Self::Policy(value)
    }
}
impl core::fmt::Display for BatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "trade batch: {self:?}")
    }
}
impl std::error::Error for BatchError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TradeParent {
    pub slot_index: u32,
    pub creation_id: u64,
    pub market: MarketStart,
}

impl TradeParent {
    pub fn asset(self) -> AssetId {
        match self.market {
            MarketStart::Curve { definition, .. } => definition.asset,
            MarketStart::Market { definition, .. } => definition.quote,
        }
    }

    pub fn definition(self) -> NativeOpening {
        match self.market {
            MarketStart::Curve { definition, .. } => {
                NativeOpening::Launch(LaunchOpening::Definition(definition))
            }
            MarketStart::Market { definition, .. } => {
                NativeOpening::Market(MarketOpening::Definition(definition))
            }
        }
    }

    pub fn opening(self) -> NativeOpening {
        match self.market {
            MarketStart::Curve { state, .. } => NativeOpening::Launch(LaunchOpening::State(state)),
            MarketStart::Market { state, .. } => NativeOpening::Market(MarketOpening::Pool(state)),
        }
    }

    pub fn claim(self) -> Result<NativeInputClaim, BatchError> {
        match self.market {
            MarketStart::Curve { definition, state } => {
                SequentialLaunch::new(definition, state).map_err(|_| BatchError::Parent)?;
            }
            MarketStart::Market { definition, state } => {
                SequentialMarket::new(definition, state).map_err(|_| BatchError::Parent)?;
            }
        }
        let opening = self.opening();
        let claim = NativeInputClaim {
            input: TxInput {
                slot_index: self.slot_index,
                amount: opening.amount_micronoid(),
                creation_id: self.creation_id,
            },
            root: opening.root(),
            opening: Some(opening),
        };
        opening
            .check_input_binding(&claim.input, claim.root)
            .map_err(|_| BatchError::Parent)?;
        Ok(claim)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeBatch {
    parent: TradeParent,
    policies: Vec<TradeIntent>,
}

impl TradeBatch {
    pub fn new(parent: TradeParent, policies: Vec<TradeIntent>) -> Result<Self, BatchError> {
        if policies.is_empty() || policies.len() > MAX_SEQUENTIAL_TRADES {
            return Err(BatchError::Bounds);
        }
        let mut keyed = policies
            .into_iter()
            .map(|intent| Ok((intent.authorization_id()?.0, intent)))
            .collect::<Result<Vec<_>, TradeError>>()?;
        keyed.sort_unstable_by_key(|(key, _)| *key);
        let batch = Self {
            parent,
            policies: keyed.into_iter().map(|(_, intent)| intent).collect(),
        };
        batch.validate_structure()?;
        Ok(batch)
    }

    pub fn parent(&self) -> TradeParent {
        self.parent
    }
    pub fn policies(&self) -> &[TradeIntent] {
        &self.policies
    }

    pub fn validate_structure(&self) -> Result<(), BatchError> {
        self.parent.claim()?;
        if self.policies.is_empty() || self.policies.len() > MAX_SEQUENTIAL_TRADES {
            return Err(BatchError::Bounds);
        }
        let mut slots = BTreeSet::from([self.parent.slot_index]);
        let mut previous = None;
        for policy in &self.policies {
            if policy.policy.asset != self.parent.asset() {
                return Err(BatchError::Parent);
            }
            let key = policy.authorization_id()?.0;
            if previous.is_some_and(|old| old >= key) {
                return Err(BatchError::Encoding);
            }
            previous = Some(key);
            for input in &policy.funding {
                if !slots.insert(input.input.slot_index) {
                    return Err(BatchError::Policy(TradeError::Funding));
                }
            }
        }
        if slots.len() > MAX_PAGED_SPEND_INPUTS {
            return Err(BatchError::Bounds);
        }
        Ok(())
    }

    pub fn checked(&self, boundary: TradeBoundary) -> Result<SequencingPlan, BatchError> {
        self.validate_structure()?;
        let plan = SequencingPlan::execute(self.parent.market, boundary, &self.policies)
            .map_err(|_| BatchError::Sequence)?;
        if !plan.unfilled().is_empty() || plan.fills().len() != self.policies.len() {
            return Err(BatchError::Unfilled);
        }
        Ok(plan)
    }

    pub fn root(&self) -> Result<Address, BatchError> {
        self.validate_structure()?;
        let mut fields = Vec::with_capacity(8 + 2 * self.policies.len());
        fields.extend_from_slice(&self.parent.opening().root().as_fields());
        fields.push(Block128(u128::from(self.parent.creation_id)));
        fields.push(Block128(u128::from(self.parent.slot_index)));
        fields.extend_from_slice(&Address(self.parent.asset().0).as_fields());
        fields.push(Block128(self.policies.len() as u128));
        fields.push(Block128(
            u128::from(TRADE_BATCH_VERSION)
                | ((matches!(self.parent.market, MarketStart::Curve { .. }) as u128) << 16),
        ));
        for policy in &self.policies {
            fields.extend_from_slice(&policy.authorization_id()?.as_fields());
        }
        Ok(Address(hash_fields(DomainTag::new(b"TRBCH_21"), &fields)))
    }

    pub fn inputs(&self) -> Result<Vec<NativeInputClaim>, BatchError> {
        self.validate_structure()?;
        let mut inputs = vec![self.parent.claim()?];
        inputs.extend(self.policies.iter().flat_map(|p| p.funding.iter().copied()));
        Ok(inputs)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, BatchError> {
        self.validate_structure()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(TRADE_BATCH_MAGIC);
        bytes.extend_from_slice(&TRADE_BATCH_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(self.policies.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&self.parent.slot_index.to_le_bytes());
        bytes.extend_from_slice(&self.parent.creation_id.to_le_bytes());
        for opening in [self.parent.definition(), self.parent.opening()] {
            let raw = opening.to_bytes().map_err(|_| BatchError::Parent)?;
            bytes.extend_from_slice(&(raw.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&raw);
        }
        for policy in &self.policies {
            let raw = policy.to_bytes()?;
            bytes.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&raw);
        }
        if bytes.len() > MAX_TRADE_BATCH_BYTES {
            return Err(BatchError::Bounds);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BatchError> {
        if bytes.len() > MAX_TRADE_BATCH_BYTES {
            return Err(BatchError::Bounds);
        }
        let mut cursor = bytes;
        if &take::<8>(&mut cursor)? != TRADE_BATCH_MAGIC
            || u16::from_le_bytes(take(&mut cursor)?) != TRADE_BATCH_VERSION
        {
            return Err(BatchError::Encoding);
        }
        let count = usize::from(u16::from_le_bytes(take(&mut cursor)?));
        if !(1..=MAX_SEQUENTIAL_TRADES).contains(&count) || take::<4>(&mut cursor)? != [0; 4] {
            return Err(BatchError::Bounds);
        }
        let slot_index = u32::from_le_bytes(take(&mut cursor)?);
        let creation_id = u64::from_le_bytes(take(&mut cursor)?);
        let definition = read_opening(&mut cursor)?;
        let opening = read_opening(&mut cursor)?;
        let market = match (definition, opening) {
            (
                NativeOpening::Launch(LaunchOpening::Definition(definition)),
                NativeOpening::Launch(LaunchOpening::State(state)),
            ) => MarketStart::Curve { definition, state },
            (
                NativeOpening::Market(MarketOpening::Definition(definition)),
                NativeOpening::Market(MarketOpening::Pool(state)),
            ) => MarketStart::Market { definition, state },
            _ => return Err(BatchError::Parent),
        };
        let mut policies = Vec::with_capacity(count);
        for _ in 0..count {
            let size = u32::from_le_bytes(take(&mut cursor)?) as usize;
            if size > MAX_TRADE_INTENT_BYTES || size > cursor.len() {
                return Err(BatchError::Bounds);
            }
            policies.push(TradeIntent::from_bytes(&cursor[..size])?);
            cursor = &cursor[size..];
        }
        if !cursor.is_empty() {
            return Err(BatchError::Encoding);
        }
        let batch = Self {
            parent: TradeParent {
                slot_index,
                creation_id,
                market,
            },
            policies,
        };
        batch.validate_structure()?;
        Ok(batch)
    }
}

fn read_opening(cursor: &mut &[u8]) -> Result<NativeOpening, BatchError> {
    let size = usize::from(u16::from_le_bytes(take(cursor)?));
    if size == 0 || size > MAX_NATIVE_OPENING_BYTES || size > cursor.len() {
        return Err(BatchError::Bounds);
    }
    let opening = NativeOpening::from_bytes(&cursor[..size]).map_err(|_| BatchError::Parent)?;
    *cursor = &cursor[size..];
    Ok(opening)
}
