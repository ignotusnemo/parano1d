// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Owner trade policies, exact funding commitments and canonical payouts.

pub mod batch;
pub mod execution;
pub mod sequencing;
pub mod wire;

use std::collections::BTreeMap;

use noid_core::Block128;
use noid_poseidon2b::{
    native::DomainTag,
    primitives::{Address, Digest, TxBodyHash},
};

use super::{
    launch::LaunchSide,
    market::{hash_fields, MARKET_QUANTITY_MAX, NOID_ASSET},
    transition::NativeInputClaim,
    AssetId, NativeOpening, MAX_NATIVE_OPENING_BYTES, NATIVE_CREATION_TAG,
};
use crate::{CanonicalOwnerAuth, MAX_PAGED_SPEND_INPUTS};

pub const TRADE_INTENT_MAGIC: &[u8; 8] = b"NOIDTR21";
pub const TRADE_INTENT_VERSION: u16 = 1;
const PREFIX_BYTES: usize = 16;
const POLICY_BYTES: usize = 208;
pub const TRADE_INTENT_FIXED_BYTES: usize = PREFIX_BYTES + POLICY_BYTES;
const FUNDING_BYTES: usize = 4 + 8 + 8 + 32 + 2;
pub const MAX_TRADE_INTENT_BYTES: usize = PREFIX_BYTES
    + POLICY_BYTES
    + MAX_PAGED_SPEND_INPUTS * (FUNDING_BYTES + MAX_NATIVE_OPENING_BYTES);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TradeError {
    Encoding,
    Version,
    Bounds,
    Context,
    Policy,
    Funding,
    Expiry,
    Minimum,
    Fee,
    Arithmetic,
}

impl core::fmt::Display for TradeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "trade intent: {self:?}")
    }
}

impl std::error::Error for TradeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TradePolicy {
    pub chain: Digest,
    pub epoch_anchor: Digest,
    pub owner: Address,
    pub asset: AssetId,
    pub recipient: Address,
    pub side: LaunchSide,
    pub gross_input: u64,
    pub minimum_output: u64,
    pub fee_limit: u64,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl TradePolicy {
    pub fn validate(self) -> Result<(), TradeError> {
        if self.chain == [0; 32]
            || self.epoch_anchor == [0; 32]
            || self.owner == Address([0; 32])
            || self.asset == NOID_ASSET
            || self.recipient == Address([0; 32])
            || ![self.gross_input, self.minimum_output, self.fee_limit]
                .iter()
                .all(|&n| n != 0 && n <= MARKET_QUANTITY_MAX)
            || self.valid_from > self.valid_until
        {
            return Err(TradeError::Policy);
        }
        Ok(())
    }

    pub fn check_context(
        self,
        chain: Digest,
        epoch_anchor: Digest,
        height: u64,
    ) -> Result<(), TradeError> {
        self.validate()?;
        if self.chain != chain || self.epoch_anchor != epoch_anchor {
            return Err(TradeError::Context);
        }
        if height < self.valid_from || height > self.valid_until {
            return Err(TradeError::Expiry);
        }
        Ok(())
    }

    pub fn root(self) -> Result<Address, TradeError> {
        self.validate()?;
        let mut fields = Vec::with_capacity(16);
        fields.push(Block128(u128::from(TRADE_INTENT_VERSION)));
        fields.push(Block128(self.side as u128));
        fields.extend_from_slice(&Address(self.chain).as_fields());
        fields.extend_from_slice(&Address(self.epoch_anchor).as_fields());
        fields.extend_from_slice(&self.owner.as_fields());
        fields.extend_from_slice(&Address(self.asset.0).as_fields());
        fields.extend_from_slice(&self.recipient.as_fields());
        fields.push(pack(self.gross_input, self.minimum_output));
        fields.push(pack(self.valid_from, self.valid_until));
        fields.push(Block128(u128::from(self.fee_limit)));
        fields.push(Block128(0));
        Ok(Address(hash_fields(DomainTag::new(b"TRPOL_21"), &fields)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundingTotals {
    pub noid: u128,
    pub tokens: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeIntent {
    pub policy: TradePolicy,
    pub funding: Vec<NativeInputClaim>,
}

impl TradeIntent {
    pub fn validate_structure(&self) -> Result<FundingTotals, TradeError> {
        self.validate_funding(None)
    }

    fn validate_funding(&self, height: Option<u64>) -> Result<FundingTotals, TradeError> {
        self.policy.validate()?;
        if self.funding.is_empty() || self.funding.len() > MAX_PAGED_SPEND_INPUTS {
            return Err(TradeError::Bounds);
        }
        let mut previous = None;
        let mut totals = FundingTotals { noid: 0, tokens: 0 };
        for claim in &self.funding {
            if previous.is_some_and(|slot| slot >= claim.input.slot_index) {
                return Err(TradeError::Funding);
            }
            previous = Some(claim.input.slot_index);
            match claim.opening {
                Some(opening @ NativeOpening::TokenBalance(balance)) => {
                    opening
                        .check_input_binding(&claim.input, claim.root)
                        .map_err(|_| TradeError::Funding)?;
                    if self.policy.side != LaunchSide::Sell
                        || balance.asset != self.policy.asset
                        || balance.owner != self.policy.owner
                        || height.is_some_and(|h| h < balance.unlock_height)
                    {
                        return Err(TradeError::Funding);
                    }
                    totals.tokens += u128::from(balance.units);
                }
                Some(_) => return Err(TradeError::Funding),
                None => {
                    let id = claim.input.creation_id;
                    if id == 0
                        || (id >= NATIVE_CREATION_TAG && id & (1 << 63) == 0)
                        || claim.input.amount == 0
                        || claim.root != self.policy.owner
                    {
                        return Err(TradeError::Funding);
                    }
                }
            }
            totals.noid += u128::from(claim.input.amount);
        }
        let noid_principal = if self.policy.side == LaunchSide::Buy {
            u128::from(self.policy.gross_input)
        } else {
            0
        };
        if totals.noid < noid_principal + u128::from(self.policy.fee_limit)
            || (self.policy.side == LaunchSide::Sell
                && totals.tokens < u128::from(self.policy.gross_input))
        {
            return Err(TradeError::Funding);
        }
        Ok(totals)
    }

    pub fn checked(
        &self,
        chain: Digest,
        epoch_anchor: Digest,
        height: u64,
    ) -> Result<FundingTotals, TradeError> {
        self.policy.check_context(chain, epoch_anchor, height)?;
        self.validate_funding(Some(height))
    }

    pub fn authorization_id(&self) -> Result<TxBodyHash, TradeError> {
        self.validate_structure()?;
        let mut fields = Vec::with_capacity(4 + 4 * self.funding.len());
        fields.extend_from_slice(&self.policy.root()?.as_fields());
        fields.push(Block128(self.funding.len() as u128));
        fields.push(Block128(u128::from(TRADE_INTENT_VERSION)));
        for claim in &self.funding {
            fields.push(Block128(u128::from(claim.input.slot_index)));
            fields.push(pack(claim.input.amount, claim.input.creation_id));
            fields.extend_from_slice(&claim.root.as_fields());
        }
        Ok(TxBodyHash(hash_fields(
            DomainTag::new(b"TRINT_21"),
            &fields,
        )))
    }

    pub fn canonical_auth(&self) -> Result<CanonicalOwnerAuth, TradeError> {
        Ok(CanonicalOwnerAuth {
            tx_body_hash: self.authorization_id()?,
            input_owner: self.policy.owner,
        })
    }

    /// Priority uses an immutable principal input and the admitting parent.
    pub fn funding_priority(&self, parent_id: Digest) -> Result<FundingPriority, TradeError> {
        self.validate_structure()?;
        if parent_id == [0; 32] {
            return Err(TradeError::Context);
        }
        let (_, anchor) = self
            .funding
            .iter()
            .filter_map(|claim| match (self.policy.side, claim.opening) {
                (LaunchSide::Buy, None) => Some((claim.input.amount, claim)),
                (LaunchSide::Sell, Some(NativeOpening::TokenBalance(balance))) => {
                    Some((balance.units, claim))
                }
                _ => None,
            })
            .min_by_key(|(units, claim)| {
                (
                    std::cmp::Reverse(*units),
                    claim.input.creation_id,
                    claim.input.slot_index,
                )
            })
            .ok_or(TradeError::Funding)?;
        let mut fields = Vec::with_capacity(6);
        fields.extend_from_slice(&Address(parent_id).as_fields());
        fields.extend_from_slice(&Address(self.policy.asset.0).as_fields());
        fields.push(Block128(u128::from(anchor.input.creation_id)));
        fields.push(Block128(u128::from(anchor.input.slot_index)));
        Ok(FundingPriority {
            digest: hash_fields(DomainTag::new(b"TRORD_21"), &fields),
            creation_id: anchor.input.creation_id,
            slot_index: anchor.input.slot_index,
        })
    }

    pub fn payouts(
        &self,
        chain: Digest,
        epoch_anchor: Digest,
        height: u64,
        spent_input: u64,
        output: u64,
        protocol_fee: u64,
    ) -> Result<Vec<TradePayout>, TradeError> {
        let totals = self.checked(chain, epoch_anchor, height)?;
        if output > MARKET_QUANTITY_MAX {
            return Err(TradeError::Bounds);
        }
        if spent_input > self.policy.gross_input || output < self.policy.minimum_output {
            return Err(TradeError::Minimum);
        }
        if protocol_fee > self.policy.fee_limit {
            return Err(TradeError::Fee);
        }
        let (noid_spent, token_spent, output_asset) = match self.policy.side {
            LaunchSide::Buy => (u128::from(spent_input), 0, self.policy.asset),
            LaunchSide::Sell => (0, u128::from(spent_input), NOID_ASSET),
        };
        let refund_noid = totals
            .noid
            .checked_sub(noid_spent + u128::from(protocol_fee))
            .ok_or(TradeError::Arithmetic)?;
        let refund_tokens = totals
            .tokens
            .checked_sub(token_spent)
            .ok_or(TradeError::Arithmetic)?;
        let mut values = BTreeMap::new();
        for (asset, owner, units) in [
            (NOID_ASSET, self.policy.owner, refund_noid),
            (self.policy.asset, self.policy.owner, refund_tokens),
            (output_asset, self.policy.recipient, u128::from(output)),
        ] {
            if units != 0 {
                *values.entry((asset, owner.0)).or_insert(0u128) += units;
            }
        }
        values
            .into_iter()
            .map(|((asset, owner), units)| {
                Ok(TradePayout {
                    asset,
                    owner: Address(owner),
                    units: u64::try_from(units).map_err(|_| TradeError::Arithmetic)?,
                })
            })
            .collect()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, TradeError> {
        self.validate_structure()?;
        let mut bytes = encode_policy_header(self.policy, self.funding.len())?.to_vec();
        for claim in &self.funding {
            bytes.extend_from_slice(&claim.input.slot_index.to_le_bytes());
            bytes.extend_from_slice(&claim.input.amount.to_le_bytes());
            bytes.extend_from_slice(&claim.input.creation_id.to_le_bytes());
            bytes.extend_from_slice(&claim.root.0);
            let opening = claim
                .opening
                .map(|opening| opening.to_bytes())
                .transpose()
                .map_err(|_| TradeError::Funding)?
                .unwrap_or_default();
            bytes.extend_from_slice(&(opening.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&opening);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TradeError> {
        if bytes.len() > MAX_TRADE_INTENT_BYTES {
            return Err(TradeError::Bounds);
        }
        let header = bytes
            .get(..TRADE_INTENT_FIXED_BYTES)
            .ok_or(TradeError::Encoding)?;
        let (policy, count) = decode_policy_header(header)?;
        let mut cursor = &bytes[TRADE_INTENT_FIXED_BYTES..];
        if cursor.len() < count * FUNDING_BYTES {
            return Err(TradeError::Encoding);
        }
        let mut funding = Vec::with_capacity(count);
        for _ in 0..count {
            let input = crate::TxInput {
                slot_index: u32::from_le_bytes(take(&mut cursor)?),
                amount: u64::from_le_bytes(take(&mut cursor)?),
                creation_id: u64::from_le_bytes(take(&mut cursor)?),
            };
            let root = Address(take(&mut cursor)?);
            let size = usize::from(u16::from_le_bytes(take(&mut cursor)?));
            if size > MAX_NATIVE_OPENING_BYTES || size > cursor.len() {
                return Err(TradeError::Bounds);
            }
            let opening = if size == 0 {
                None
            } else {
                Some(NativeOpening::from_bytes(&cursor[..size]).map_err(|_| TradeError::Funding)?)
            };
            cursor = &cursor[size..];
            funding.push(NativeInputClaim {
                input,
                root,
                opening,
            });
        }
        if !cursor.is_empty() {
            return Err(TradeError::Encoding);
        }
        let intent = Self { policy, funding };
        intent.validate_structure()?;
        Ok(intent)
    }
}

/// Fixed policy and source count; source claims remain in the canonical body.
pub fn encode_policy_header(
    policy: TradePolicy,
    funding_count: usize,
) -> Result<[u8; TRADE_INTENT_FIXED_BYTES], TradeError> {
    policy.validate()?;
    if !(1..=MAX_PAGED_SPEND_INPUTS).contains(&funding_count) {
        return Err(TradeError::Bounds);
    }
    let mut bytes = [0; TRADE_INTENT_FIXED_BYTES];
    bytes[..8].copy_from_slice(TRADE_INTENT_MAGIC);
    bytes[8..10].copy_from_slice(&TRADE_INTENT_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&(funding_count as u16).to_le_bytes());
    bytes[PREFIX_BYTES] = policy.side as u8;
    let mut offset = PREFIX_BYTES + 8;
    for digest in [
        policy.chain,
        policy.epoch_anchor,
        policy.owner.0,
        policy.asset.0,
        policy.recipient.0,
    ] {
        bytes[offset..offset + 32].copy_from_slice(&digest);
        offset += 32;
    }
    for value in [
        policy.gross_input,
        policy.minimum_output,
        policy.fee_limit,
        policy.valid_from,
        policy.valid_until,
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        offset += 8;
    }
    Ok(bytes)
}

pub fn decode_policy_header(bytes: &[u8]) -> Result<(TradePolicy, usize), TradeError> {
    if bytes.len() != TRADE_INTENT_FIXED_BYTES {
        return Err(TradeError::Encoding);
    }
    let mut cursor = bytes;
    if &take::<8>(&mut cursor)? != TRADE_INTENT_MAGIC {
        return Err(TradeError::Encoding);
    }
    if u16::from_le_bytes(take(&mut cursor)?) != TRADE_INTENT_VERSION {
        return Err(TradeError::Version);
    }
    let count = usize::from(u16::from_le_bytes(take(&mut cursor)?));
    if !(1..=MAX_PAGED_SPEND_INPUTS).contains(&count) || take::<4>(&mut cursor)? != [0; 4] {
        return Err(TradeError::Bounds);
    }
    let side = match take::<1>(&mut cursor)?[0] {
        0 => LaunchSide::Buy,
        1 => LaunchSide::Sell,
        _ => return Err(TradeError::Policy),
    };
    if take::<7>(&mut cursor)? != [0; 7] {
        return Err(TradeError::Encoding);
    }
    let policy = TradePolicy {
        side,
        chain: take(&mut cursor)?,
        epoch_anchor: take(&mut cursor)?,
        owner: Address(take(&mut cursor)?),
        asset: AssetId(take(&mut cursor)?),
        recipient: Address(take(&mut cursor)?),
        gross_input: u64::from_le_bytes(take(&mut cursor)?),
        minimum_output: u64::from_le_bytes(take(&mut cursor)?),
        fee_limit: u64::from_le_bytes(take(&mut cursor)?),
        valid_from: u64::from_le_bytes(take(&mut cursor)?),
        valid_until: u64::from_le_bytes(take(&mut cursor)?),
    };
    policy.validate()?;
    Ok((policy, count))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TradePayout {
    pub asset: AssetId,
    pub owner: Address,
    pub units: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FundingPriority {
    pub digest: Digest,
    pub creation_id: u64,
    pub slot_index: u32,
}

fn pack(low: u64, high: u64) -> Block128 {
    Block128(u128::from(low) | (u128::from(high) << 64))
}

fn take<const N: usize>(cursor: &mut &[u8]) -> Result<[u8; N], TradeError> {
    let bytes = cursor.get(..N).ok_or(TradeError::Encoding)?;
    let mut value = [0; N];
    value.copy_from_slice(bytes);
    *cursor = &cursor[N..];
    Ok(value)
}
