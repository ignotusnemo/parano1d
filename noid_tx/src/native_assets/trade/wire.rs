// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded transport for one funded policy and its detached Owner capsule.

use super::{TradeError, TradeIntent, MAX_TRADE_INTENT_BYTES, TRADE_INTENT_FIXED_BYTES};
use crate::{MAX_PAGED_SPEND_INTENT_BYTES, MAX_TX_AUTHORIZATION_BYTES};

pub const TRADE_OWNER_INTENT_MAGIC: &[u8; 8] = b"NOIDTO21";
pub const TRADE_OWNER_INTENT_VERSION: u16 = 1;
pub const TRADE_OWNER_INTENT_PREFIX_BYTES: usize = 20;
pub const MAX_TRADE_OWNER_INTENT_BYTES: usize = MAX_PAGED_SPEND_INTENT_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeOwnerIntent {
    pub intent: TradeIntent,
    pub authorization_bytes: Vec<u8>,
}

impl TradeOwnerIntent {
    pub fn authorization_wire_offset(&self) -> Result<usize, TradeError> {
        TRADE_OWNER_INTENT_PREFIX_BYTES
            .checked_add(self.intent.to_bytes()?.len())
            .ok_or(TradeError::Bounds)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, TradeError> {
        let intent = self.intent.to_bytes()?;
        if self.authorization_bytes.len() > MAX_TX_AUTHORIZATION_BYTES {
            return Err(TradeError::Bounds);
        }
        let total = TRADE_OWNER_INTENT_PREFIX_BYTES
            .checked_add(intent.len())
            .and_then(|count| count.checked_add(self.authorization_bytes.len()))
            .filter(|&count| count <= MAX_TRADE_OWNER_INTENT_BYTES)
            .ok_or(TradeError::Bounds)?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(TRADE_OWNER_INTENT_MAGIC);
        bytes.extend_from_slice(&TRADE_OWNER_INTENT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(intent.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.authorization_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&intent);
        bytes.extend_from_slice(&self.authorization_bytes);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TradeError> {
        if bytes.len() < TRADE_OWNER_INTENT_PREFIX_BYTES + TRADE_INTENT_FIXED_BYTES
            || bytes.len() > MAX_TRADE_OWNER_INTENT_BYTES
            || &bytes[..8] != TRADE_OWNER_INTENT_MAGIC
            || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != TRADE_OWNER_INTENT_VERSION
            || bytes[10..12] != [0; 2]
        {
            return Err(TradeError::Encoding);
        }
        let intent_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
        let authorization_len = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        if !(TRADE_INTENT_FIXED_BYTES..=MAX_TRADE_INTENT_BYTES).contains(&intent_len)
            || authorization_len > MAX_TX_AUTHORIZATION_BYTES
        {
            return Err(TradeError::Bounds);
        }
        let offset = TRADE_OWNER_INTENT_PREFIX_BYTES
            .checked_add(intent_len)
            .ok_or(TradeError::Bounds)?;
        if offset.checked_add(authorization_len) != Some(bytes.len()) {
            return Err(TradeError::Encoding);
        }
        Ok(Self {
            intent: TradeIntent::from_bytes(&bytes[TRADE_OWNER_INTENT_PREFIX_BYTES..offset])?,
            authorization_bytes: bytes[offset..].to_vec(),
        })
    }
}
