// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Compact policies bound to the controller and sources already in the body.

use std::collections::BTreeMap;

use noid_poseidon2b::primitives::Digest;
use noid_tx::native_assets::{
    financial::FinancialOperation,
    launch::LaunchOpening,
    market::{sequential::MAX_SEQUENTIAL_TRADES, MarketOpening},
    trade::{
        batch::{TradeBatch, TradeParent},
        decode_policy_header, encode_policy_header,
        sequencing::MarketStart,
        TradeIntent, TRADE_INTENT_FIXED_BYTES,
    },
    transition::{NativeInputClaim, NativeOperation},
    NativeOpening,
};

use super::{Block, BlockBodyPayloadError};
use crate::block::native_assets::{validate_scheduled_block_page_stream, ScheduledSpendKind};

pub const MAX_BLOCK_TRADE_POLICIES: usize = MAX_SEQUENTIAL_TRADES;
const BATCH_PREFIX_BYTES: usize = 36;

type OpeningMap = BTreeMap<Digest, NativeOpening>;
type SourceMap = BTreeMap<Digest, Vec<NativeInputClaim>>;

/// Confirmation events include each committed Owner policy while logical
/// transaction-root leaves retain their original group identities.
pub fn confirmed_intent_ids(
    block: &Block,
    batches: &[TradeBatch],
) -> Result<Vec<noid_poseidon2b::primitives::TxBodyHash>, BlockBodyPayloadError> {
    use std::collections::BTreeSet;
    let stream = validate_scheduled_block_page_stream(&block.transactions, block.header.height)
        .map_err(|error| BlockBodyPayloadError::Native(error.to_string()))?;
    let mut expected = BTreeSet::new();
    for group in stream.groups() {
        if let ScheduledSpendKind::Native(facts) = group.kind {
            if let NativeOperation::Financial(FinancialOperation::ExecuteTrades { commitment }) =
                facts.operation
            {
                if !expected.insert(commitment.0) {
                    return Err(BlockBodyPayloadError::Trade);
                }
            }
        }
    }
    if batches.len() != expected.len() || batches.len() > MAX_BLOCK_TRADE_POLICIES {
        return Err(BlockBodyPayloadError::Trade);
    }
    let mut ids = stream.logical_txids(&block.transactions);
    let mut unique: BTreeSet<_> = ids.iter().map(|id| id.0).collect();
    let mut policies = 0usize;
    for batch in batches {
        let root = batch.root().map_err(|_| BlockBodyPayloadError::Trade)?.0;
        if !expected.remove(&root) {
            return Err(BlockBodyPayloadError::Trade);
        }
        policies += batch.policies().len();
        if policies > MAX_BLOCK_TRADE_POLICIES {
            return Err(BlockBodyPayloadError::Bounds);
        }
        for policy in batch.policies() {
            let id = policy
                .authorization_id()
                .map_err(|_| BlockBodyPayloadError::Trade)?;
            if !unique.insert(id.0) {
                return Err(BlockBodyPayloadError::Trade);
            }
            ids.push(id);
        }
    }
    Ok(ids)
}

pub fn canonical_trade_batches(
    block: &Block,
    openings: &OpeningMap,
    batches: Vec<TradeBatch>,
) -> Result<Vec<TradeBatch>, BlockBodyPayloadError> {
    let sources = trade_sources(block, openings)?;
    if sources.len() != batches.len() || batches.len() > MAX_BLOCK_TRADE_POLICIES {
        return Err(BlockBodyPayloadError::Trade);
    }
    let mut keyed = BTreeMap::new();
    let mut count = 0usize;
    for batch in batches {
        count += batch.policies().len();
        if count > MAX_BLOCK_TRADE_POLICIES {
            return Err(BlockBodyPayloadError::Bounds);
        }
        let root = batch.root().map_err(|_| BlockBodyPayloadError::Trade)?.0;
        let claims = sources.get(&root).ok_or(BlockBodyPayloadError::Trade)?;
        if batch.inputs().map_err(|_| BlockBodyPayloadError::Trade)? != *claims
            || batch.parent() != trade_parent(claims, openings)?
            || keyed.insert(root, batch).is_some()
        {
            return Err(BlockBodyPayloadError::Trade);
        }
    }
    Ok(keyed.into_values().collect())
}

pub(super) fn decode_trade_batches(
    block: &Block,
    openings: &OpeningMap,
    batch_count: usize,
    cursor: &mut &[u8],
) -> Result<Vec<TradeBatch>, BlockBodyPayloadError> {
    if batch_count == 0 || batch_count > MAX_BLOCK_TRADE_POLICIES {
        return Err(BlockBodyPayloadError::Bounds);
    }
    if cursor.len() < batch_count * (BATCH_PREFIX_BYTES + TRADE_INTENT_FIXED_BYTES) {
        return Err(BlockBodyPayloadError::Encoding);
    }
    let sources = trade_sources(block, openings)?;
    if sources.len() != batch_count {
        return Err(BlockBodyPayloadError::Trade);
    }
    let mut batches = Vec::with_capacity(batch_count);
    let mut previous = None;
    let mut total = 0usize;
    for _ in 0..batch_count {
        let root = take::<32>(cursor)?;
        let count = usize::from(u16::from_le_bytes(take(cursor)?));
        if count == 0 || count > MAX_BLOCK_TRADE_POLICIES - total {
            return Err(BlockBodyPayloadError::Bounds);
        }
        total += count;
        if take::<2>(cursor)? != [0; 2]
            || previous.is_some_and(|old| old >= root)
            || cursor.len() < count * TRADE_INTENT_FIXED_BYTES
        {
            return Err(BlockBodyPayloadError::Encoding);
        }
        previous = Some(root);
        let claims = sources.get(&root).ok_or(BlockBodyPayloadError::Trade)?;
        let parent = trade_parent(claims, openings)?;
        let mut offset = 1usize;
        let mut policies = Vec::with_capacity(count);
        let mut previous_policy = None;
        for _ in 0..count {
            let (policy, funding_count) = decode_policy_header(&cursor[..TRADE_INTENT_FIXED_BYTES])
                .map_err(|_| BlockBodyPayloadError::Trade)?;
            *cursor = &cursor[TRADE_INTENT_FIXED_BYTES..];
            let end = offset
                .checked_add(funding_count)
                .filter(|end| *end <= claims.len())
                .ok_or(BlockBodyPayloadError::Trade)?;
            let intent = TradeIntent {
                policy,
                funding: claims[offset..end].to_vec(),
            };
            let id = intent
                .authorization_id()
                .map_err(|_| BlockBodyPayloadError::Trade)?
                .0;
            if previous_policy.is_some_and(|old| old >= id) {
                return Err(BlockBodyPayloadError::Encoding);
            }
            previous_policy = Some(id);
            offset = end;
            policies.push(intent);
        }
        if offset != claims.len() {
            return Err(BlockBodyPayloadError::Trade);
        }
        let batch = TradeBatch::new(parent, policies).map_err(|_| BlockBodyPayloadError::Trade)?;
        if batch.root().map_err(|_| BlockBodyPayloadError::Trade)?.0 != root {
            return Err(BlockBodyPayloadError::Trade);
        }
        batches.push(batch);
    }
    Ok(batches)
}

pub(super) fn encoded_trade_bytes(batches: &[TradeBatch]) -> usize {
    batches
        .iter()
        .map(|batch| BATCH_PREFIX_BYTES + batch.policies().len() * TRADE_INTENT_FIXED_BYTES)
        .sum()
}

pub(super) fn encode_trade_batches(bytes: &mut Vec<u8>, batches: &[TradeBatch]) {
    for batch in batches {
        bytes.extend_from_slice(&batch.root().expect("validated trade batch").0);
        bytes.extend_from_slice(&(batch.policies().len() as u16).to_le_bytes());
        bytes.extend_from_slice(&[0; 2]);
        for intent in batch.policies() {
            bytes.extend_from_slice(
                &encode_policy_header(intent.policy, intent.funding.len())
                    .expect("validated trade policy"),
            );
        }
    }
}

fn trade_sources(block: &Block, openings: &OpeningMap) -> Result<SourceMap, BlockBodyPayloadError> {
    let native_flags = noid_tx::native_assets::wire::NATIVE_PAGE_BIT
        | noid_tx::native_assets::wire::NATIVE_HEADER_BIT;
    if !block
        .transactions
        .iter()
        .any(|tx| tx.body.validity_bitmap & native_flags != 0)
    {
        return Ok(SourceMap::new());
    }
    let stream = validate_scheduled_block_page_stream(&block.transactions, block.header.height)
        .map_err(|error| BlockBodyPayloadError::Native(error.to_string()))?;
    let mut sources = SourceMap::new();
    let mut total = 0usize;
    for group in stream.groups() {
        let ScheduledSpendKind::Native(facts) = group.kind else {
            continue;
        };
        let NativeOperation::Financial(FinancialOperation::ExecuteTrades { commitment }) =
            facts.operation
        else {
            continue;
        };
        if sources.len() >= MAX_BLOCK_TRADE_POLICIES {
            return Err(BlockBodyPayloadError::Bounds);
        }
        total = total
            .checked_add(facts.live_inputs)
            .ok_or(BlockBodyPayloadError::Bounds)?;
        if total > noid_tx::MAX_PAGED_SPEND_INPUTS {
            return Err(BlockBodyPayloadError::Bounds);
        }
        let data = &block.transactions[group.body_start + 1..group.body_start + group.page_count];
        let inputs = data
            .iter()
            .flat_map(|tx| {
                tx.body
                    .live_inputs()
                    .map(|(_, input)| (*input, tx.body.input_owner))
            })
            .enumerate()
            .map(|(i, (input, root))| {
                Ok(NativeInputClaim {
                    input,
                    root,
                    opening: if facts.input_is_native(i) {
                        Some(
                            *openings
                                .get(&root.0)
                                .ok_or(BlockBodyPayloadError::MissingOpening(root))?,
                        )
                    } else {
                        None
                    },
                })
            })
            .collect::<Result<Vec<_>, BlockBodyPayloadError>>()?;
        if sources.insert(commitment.0, inputs).is_some() {
            return Err(BlockBodyPayloadError::Trade);
        }
    }
    Ok(sources)
}

fn trade_parent(
    claims: &[NativeInputClaim],
    openings: &OpeningMap,
) -> Result<TradeParent, BlockBodyPayloadError> {
    let claim = claims.first().ok_or(BlockBodyPayloadError::Trade)?;
    let market = match claim.opening {
        Some(NativeOpening::Launch(LaunchOpening::State(state))) => {
            let Some(NativeOpening::Launch(LaunchOpening::Definition(definition))) =
                openings.get(&state.launch.0)
            else {
                return Err(BlockBodyPayloadError::Trade);
            };
            MarketStart::Curve {
                definition: *definition,
                state,
            }
        }
        Some(NativeOpening::Market(MarketOpening::Pool(state))) => {
            let Some(NativeOpening::Market(MarketOpening::Definition(definition))) =
                openings.get(&state.pool.0)
            else {
                return Err(BlockBodyPayloadError::Trade);
            };
            MarketStart::Market {
                definition: *definition,
                state,
            }
        }
        _ => return Err(BlockBodyPayloadError::Trade),
    };
    let parent = TradeParent {
        slot_index: claim.input.slot_index,
        creation_id: claim.input.creation_id,
        market,
    };
    if parent.claim().map_err(|_| BlockBodyPayloadError::Trade)? != *claim {
        return Err(BlockBodyPayloadError::Trade);
    }
    Ok(parent)
}

fn take<const N: usize>(cursor: &mut &[u8]) -> Result<[u8; N], BlockBodyPayloadError> {
    let raw = cursor.get(..N).ok_or(BlockBodyPayloadError::Encoding)?;
    let value = raw
        .try_into()
        .map_err(|_| BlockBodyPayloadError::Encoding)?;
    *cursor = &cursor[N..];
    Ok(value)
}
