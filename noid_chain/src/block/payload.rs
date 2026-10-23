// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical block-body transport with complete committed native records.

use std::borrow::Cow;

use noid_tx::native_assets::{trade::batch::TradeBatch, NativeOpening, MAX_NATIVE_OPENING_BYTES};

mod trades;
pub use trades::{canonical_trade_batches, confirmed_intent_ids, MAX_BLOCK_TRADE_POLICIES};
use trades::{decode_trade_batches, encode_trade_batches, encoded_trade_bytes};

use super::{native_assets::validate_scheduled_block_page_stream, Block};
use crate::consensus::{params::BLOCK_MAX_ACTIONS, wire_limits::MAX_BLOCK_BYTES};

pub const NATIVE_BODY_MAGIC: &[u8; 4] = b"NBD1";
pub const NATIVE_BODY_HEADER_BYTES: usize = 12;
pub const TRADE_BODY_MAGIC: &[u8; 4] = b"NBD2";
pub const TRADE_BODY_HEADER_BYTES: usize = 16;
pub const MAX_BLOCK_NATIVE_OPENINGS: usize = 2 * BLOCK_MAX_ACTIONS;
pub const MAX_BLOCK_BODY_PAYLOAD_BYTES: usize = MAX_BLOCK_BYTES
    + NATIVE_BODY_HEADER_BYTES
    + MAX_BLOCK_NATIVE_OPENINGS * (2 + MAX_NATIVE_OPENING_BYTES);

pub const fn block_body_payload_bytes_limit(height: u64) -> usize {
    if crate::consensus::params::v2_1_active(height) {
        MAX_BLOCK_BODY_PAYLOAD_BYTES
    } else {
        MAX_BLOCK_BYTES
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockBodyPayloadError {
    Bounds,
    Encoding,
    Trade,
    MissingOpening(noid_poseidon2b::primitives::Address),
    Block(noid_tx::wire::WireError),
    Native(String),
}

impl core::fmt::Display for BlockBodyPayloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "block body payload: {self:?}")
    }
}
impl std::error::Error for BlockBodyPayloadError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockBodyPayload {
    block: Block,
    native_openings: Vec<NativeOpening>,
    trade_batches: Vec<TradeBatch>,
}

impl BlockBodyPayload {
    pub fn new(block: Block, openings: Vec<NativeOpening>) -> Result<Self, BlockBodyPayloadError> {
        Self::new_with_native_data(block, openings, Vec::new())
    }

    pub fn new_with_native_data(
        block: Block,
        openings: Vec<NativeOpening>,
        batches: Vec<TradeBatch>,
    ) -> Result<Self, BlockBodyPayloadError> {
        let body_len = block
            .canonical_wire_len()
            .map_err(BlockBodyPayloadError::Block)?;
        if body_len > MAX_BLOCK_BYTES {
            return Err(BlockBodyPayloadError::Bounds);
        }
        let payloads = canonical_opening_map(&block, openings)?;
        let trade_batches = canonical_trade_batches(&block, &payloads, batches)?;
        let native_openings: Vec<_> = payloads.into_values().collect();
        if encoded_body_len(body_len, &native_openings, &trade_batches)?
            > MAX_BLOCK_BODY_PAYLOAD_BYTES
        {
            return Err(BlockBodyPayloadError::Bounds);
        }
        Ok(Self {
            block,
            native_openings,
            trade_batches,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BlockBodyPayloadError> {
        if bytes.is_empty() || bytes.len() > MAX_BLOCK_BODY_PAYLOAD_BYTES {
            return Err(BlockBodyPayloadError::Bounds);
        }
        let has_trades = bytes.starts_with(TRADE_BODY_MAGIC);
        if !has_trades && !bytes.starts_with(NATIVE_BODY_MAGIC) {
            if bytes.len() > MAX_BLOCK_BYTES {
                return Err(BlockBodyPayloadError::Bounds);
            }
            let block = Block::from_bytes(bytes).map_err(BlockBodyPayloadError::Block)?;
            return Self::new(block, Vec::new());
        }
        let header_len = if has_trades {
            TRADE_BODY_HEADER_BYTES
        } else {
            NATIVE_BODY_HEADER_BYTES
        };
        if bytes.len() < header_len {
            return Err(BlockBodyPayloadError::Encoding);
        }
        let body_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        if body_len == 0
            || body_len > MAX_BLOCK_BYTES
            || count == 0
            || count > MAX_BLOCK_NATIVE_OPENINGS
        {
            return Err(BlockBodyPayloadError::Bounds);
        }
        let batch_count = if has_trades {
            let count = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
            if count == 0 || count > MAX_BLOCK_TRADE_POLICIES {
                return Err(BlockBodyPayloadError::Bounds);
            }
            count
        } else {
            0
        };
        let body_end = header_len
            .checked_add(body_len)
            .ok_or(BlockBodyPayloadError::Bounds)?;
        let minimum = count
            .checked_mul(2)
            .and_then(|n| body_end.checked_add(n))
            .ok_or(BlockBodyPayloadError::Bounds)?;
        if minimum > bytes.len() {
            return Err(BlockBodyPayloadError::Encoding);
        }
        let block = Block::from_bytes(&bytes[header_len..body_end])
            .map_err(BlockBodyPayloadError::Block)?;
        if !crate::consensus::params::v2_1_active(block.header.height) {
            return Err(BlockBodyPayloadError::Encoding);
        }
        let mut cursor = body_end;
        let mut openings = Vec::with_capacity(count);
        let mut previous = None;
        for _ in 0..count {
            let size_end = cursor.checked_add(2).ok_or(BlockBodyPayloadError::Bounds)?;
            let size = bytes
                .get(cursor..size_end)
                .ok_or(BlockBodyPayloadError::Encoding)?;
            let size = usize::from(u16::from_le_bytes(size.try_into().unwrap()));
            if size == 0 || size > MAX_NATIVE_OPENING_BYTES {
                return Err(BlockBodyPayloadError::Bounds);
            }
            cursor = size_end;
            let end = cursor
                .checked_add(size)
                .ok_or(BlockBodyPayloadError::Bounds)?;
            let raw = bytes
                .get(cursor..end)
                .ok_or(BlockBodyPayloadError::Encoding)?;
            let opening = NativeOpening::from_bytes(raw)
                .map_err(|error| BlockBodyPayloadError::Native(error.to_string()))?;
            let root = opening.root().0;
            if previous.is_some_and(|previous| previous >= root) {
                return Err(BlockBodyPayloadError::Encoding);
            }
            previous = Some(root);
            openings.push(opening);
            cursor = end;
        }
        let payloads = canonical_opening_map(&block, openings)?;
        let mut remainder = &bytes[cursor..];
        let trade_batches = if has_trades {
            decode_trade_batches(&block, &payloads, batch_count, &mut remainder)?
        } else {
            Vec::new()
        };
        if !remainder.is_empty() {
            return Err(BlockBodyPayloadError::Encoding);
        }
        Self::new_with_native_data(block, payloads.into_values().collect(), trade_batches)
    }

    pub fn block(&self) -> &Block {
        &self.block
    }
    pub fn native_openings(&self) -> &[NativeOpening] {
        &self.native_openings
    }
    pub fn trade_batches(&self) -> &[TradeBatch] {
        &self.trade_batches
    }
    pub fn into_parts(self) -> (Block, Vec<NativeOpening>, Vec<TradeBatch>) {
        (self.block, self.native_openings, self.trade_batches)
    }
    pub fn into_block(self) -> Block {
        self.block
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_body_with_trades(
            &self.block.to_bytes(),
            &self.native_openings,
            &self.trade_batches,
        )
        .into_owned()
    }
}

/// Validate and order the exact primary and dependency records of this body.
pub fn canonical_openings(
    block: &Block,
    openings: Vec<NativeOpening>,
) -> Result<Vec<NativeOpening>, BlockBodyPayloadError> {
    Ok(canonical_opening_map(block, openings)?
        .into_values()
        .collect())
}

pub fn canonical_opening_map(
    block: &Block,
    openings: Vec<NativeOpening>,
) -> Result<
    std::collections::BTreeMap<noid_poseidon2b::primitives::Digest, NativeOpening>,
    BlockBodyPayloadError,
> {
    if openings.len() > MAX_BLOCK_NATIVE_OPENINGS {
        return Err(BlockBodyPayloadError::Bounds);
    }
    let flags = noid_tx::native_assets::wire::NATIVE_PAGE_BIT
        | noid_tx::native_assets::wire::NATIVE_HEADER_BIT;
    if !block
        .transactions
        .iter()
        .any(|tx| tx.body.validity_bitmap & flags != 0)
    {
        return if openings.is_empty() {
            Ok(std::collections::BTreeMap::new())
        } else {
            Err(BlockBodyPayloadError::Native(
                "extraneous native records".into(),
            ))
        };
    }
    let stream = validate_scheduled_block_page_stream(&block.transactions, block.header.height)
        .map_err(|error| BlockBodyPayloadError::Native(error.to_string()))?;
    let required = stream.required_native_opening_roots(&block.transactions);
    let operands = stream.required_native_operand_roots();
    let closure = noid_tx::native_assets::closure::canonical_native_closure(
        &required,
        &operands,
        &openings,
        MAX_BLOCK_NATIVE_OPENINGS,
    )
    .map_err(|error| match error {
        noid_tx::native_assets::closure::NativeClosureError::Missing(root) => {
            BlockBodyPayloadError::MissingOpening(root)
        }
        error => BlockBodyPayloadError::Native(error.to_string()),
    })?;
    let keyed = closure
        .into_iter()
        .map(|opening| (opening.root().0, opening))
        .collect();
    Ok(keyed)
}

pub(crate) fn encoded_body_len(
    body_len: usize,
    openings: &[NativeOpening],
    batches: &[TradeBatch],
) -> Result<usize, BlockBodyPayloadError> {
    if openings.is_empty() && batches.is_empty() {
        return Ok(body_len);
    }
    let header = if batches.is_empty() {
        NATIVE_BODY_HEADER_BYTES
    } else {
        TRADE_BODY_HEADER_BYTES
    };
    let mut length = body_len
        .checked_add(header)
        .ok_or(BlockBodyPayloadError::Bounds)?;
    for opening in openings {
        let record = opening
            .to_bytes()
            .map_err(|error| BlockBodyPayloadError::Native(error.to_string()))?;
        length = length
            .checked_add(2 + record.len())
            .ok_or(BlockBodyPayloadError::Bounds)?;
    }
    length
        .checked_add(encoded_trade_bytes(batches))
        .ok_or(BlockBodyPayloadError::Bounds)
}

pub(crate) fn encode_body<'a>(block_bytes: &'a [u8], openings: &[NativeOpening]) -> Cow<'a, [u8]> {
    encode_body_with_trades(block_bytes, openings, &[])
}

pub(crate) fn encode_body_with_trades<'a>(
    block_bytes: &'a [u8],
    openings: &[NativeOpening],
    batches: &[TradeBatch],
) -> Cow<'a, [u8]> {
    if openings.is_empty() && batches.is_empty() {
        return Cow::Borrowed(block_bytes);
    }
    let length = encoded_body_len(block_bytes.len(), openings, batches)
        .expect("validated native body length");
    let mut encoded = Vec::with_capacity(length);
    encoded.extend_from_slice(if batches.is_empty() {
        NATIVE_BODY_MAGIC
    } else {
        TRADE_BODY_MAGIC
    });
    encoded.extend_from_slice(&(block_bytes.len() as u32).to_le_bytes());
    encoded.extend_from_slice(&(openings.len() as u32).to_le_bytes());
    if !batches.is_empty() {
        encoded.extend_from_slice(&(batches.len() as u32).to_le_bytes());
    }
    encoded.extend_from_slice(block_bytes);
    for opening in openings {
        let bytes = opening.to_bytes().expect("validated native record");
        encoded.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&bytes);
    }
    encode_trade_batches(&mut encoded, batches);
    Cow::Owned(encoded)
}
