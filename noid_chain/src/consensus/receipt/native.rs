// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native action receipts with their committed public openings.

use std::collections::BTreeSet;

use noid_poseidon2b::primitives::Address;
use noid_tx::{
    native_assets::{
        nft_market::NftRoundContext,
        transition::{NativeInputClaim, NativeOperation, NativeOutputClaim},
        wire::NativeIntent,
        NativeOpening,
    },
    TxPage,
};

use super::{summary_from_pages, ParanoidReceipt, RECEIPT_CONSTRUCTION_MARKER};
use crate::{
    block::{native_assets::ScheduledSpendKind, payload::BlockBodyPayload},
    consensus::wire_limits::MAX_RPC_RECEIPT_BYTES,
    wire::BLOCK_HEADER_WIRE_SIZE,
    BlockHeader,
};

pub(super) const MAGIC: &[u8; 4] = b"NAR1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeReceiptDetails {
    pub operation: NativeOperation,
    pub authority: Address,
    pub inputs: Vec<NativeInputClaim>,
    pub outputs: Vec<NativeOutputClaim>,
    pub dependencies: Vec<NativeOpening>,
}

impl NativeReceiptDetails {
    pub fn participants(&self) -> Vec<Address> {
        let mut addresses = BTreeSet::from([self.authority.0]);
        for (owner, opening) in self
            .inputs
            .iter()
            .map(|claim| (claim.root, claim.opening))
            .chain(
                self.outputs
                    .iter()
                    .map(|claim| (claim.output.owner, claim.opening)),
            )
        {
            if let Some(opening) = opening {
                let dependency = opening.dependency_root().and_then(|root| {
                    self.dependencies
                        .iter()
                        .find(|value| value.root() == root)
                        .copied()
                });
                for owner in opening
                    .owners_with_dependency(dependency)
                    .unwrap_or_default()
                {
                    addresses.insert(owner.0);
                }
            } else {
                addresses.insert(owner.0);
            }
        }
        addresses.into_iter().map(Address).collect()
    }
}

pub fn native_receipt_details(receipt: &ParanoidReceipt) -> Option<NativeReceiptDetails> {
    let (header, intent) = check_receipt(receipt)?;
    let facts = intent.validate_structure().ok()?;
    let inputs = intent
        .pages
        .iter()
        .skip(1)
        .flat_map(|page| {
            page.body
                .live_inputs()
                .map(|(_, input)| (*input, page.body.input_owner))
        })
        .zip(&intent.input_openings)
        .map(|((input, root), opening)| NativeInputClaim {
            input,
            root,
            opening: *opening,
        })
        .collect();
    let outputs = intent
        .pages
        .iter()
        .skip(1)
        .flat_map(|page| page.body.live_outputs().map(|(_, output)| *output))
        .zip(&intent.output_openings)
        .map(|(output, opening)| NativeOutputClaim {
            output,
            opening: *opening,
        })
        .collect();
    debug_assert_eq!(header.height, receipt.claimed_height);
    Some(NativeReceiptDetails {
        operation: facts.operation,
        authority: facts.authority,
        inputs,
        outputs,
        dependencies: intent.dependencies,
    })
}

pub fn native_receipt_for_group(
    payload: &BlockBodyPayload,
    parent: &BlockHeader,
    id: &[u8; 32],
) -> Result<Option<ParanoidReceipt>, String> {
    let block = payload.block();
    let stream = crate::block::native_assets::validate_scheduled_block_page_stream(
        &block.transactions,
        block.header.height,
    )
    .map_err(|e| e.to_string())?;
    let hashes: Vec<_> = crate::block::native_assets::try_compute_logical_txids_at(
        &block.transactions,
        block.header.height,
    )
    .map_err(|e| e.to_string())?
    .into_iter()
    .map(|id| id.0)
    .collect();
    for (index, group) in stream.groups().enumerate() {
        if group.logical_txid().0 != *id {
            continue;
        }
        let ScheduledSpendKind::Native(facts) = group.kind else {
            return Ok(None);
        };
        if matches!(
            facts.operation,
            NativeOperation::Financial(
                noid_tx::native_assets::financial::FinancialOperation::ExecuteTrades { .. }
            )
        ) {
            return Ok(None);
        }
        let pages = block.transactions[group.body_start..group.body_start + group.page_count]
            .iter()
            .map(|tx| TxPage {
                body: tx.body.clone(),
            })
            .collect();
        let intent = NativeIntent::from_pages_with_openings(pages, |root| {
            payload
                .native_openings()
                .iter()
                .find(|opening| opening.root() == root)
                .copied()
        })
        .map_err(|e| e.to_string())?;
        let mut encoded = MAGIC.to_vec();
        encoded.extend_from_slice(&block.header.to_bytes());
        encoded.extend_from_slice(&parent.to_bytes());
        encoded.extend_from_slice(&intent.to_bytes().map_err(|e| e.to_string())?);
        let logical_index = stream.user_start_index() + index;
        let receipt = ParanoidReceipt {
            construction_marker: RECEIPT_CONSTRUCTION_MARKER,
            paged_spend: encoded,
            tx_index: u16::try_from(logical_index).map_err(|_| "native receipt position")?,
            tx_count: u16::try_from(hashes.len()).map_err(|_| "native receipt count")?,
            merkle_path: crate::tx_tree::path_from_hashes(&hashes, logical_index),
            claimed_root: block.header.tx_root,
            claimed_height: block.header.height,
            summary: summary_from_pages(&intent.pages, block.header.height, block.header.timestamp),
        };
        if receipt.to_bytes().len() > MAX_RPC_RECEIPT_BYTES || check_receipt(&receipt).is_none() {
            return Err("invalid native action receipt".into());
        }
        return Ok(Some(receipt));
    }
    Ok(None)
}

pub(super) fn claimed_header(bytes: &[u8]) -> Result<BlockHeader, String> {
    if !bytes.starts_with(MAGIC) || bytes.len() > MAX_RPC_RECEIPT_BYTES {
        return Err("native receipt framing".into());
    }
    let header = bytes
        .get(MAGIC.len()..MAGIC.len() + BLOCK_HEADER_WIRE_SIZE)
        .ok_or("native receipt header")?;
    BlockHeader::from_bytes(header.try_into().map_err(|_| "native receipt header")?)
        .map_err(|e| format!("native receipt header: {e:?}"))
}

pub(super) fn check_receipt(receipt: &ParanoidReceipt) -> Option<(BlockHeader, NativeIntent)> {
    if receipt.construction_marker != RECEIPT_CONSTRUCTION_MARKER
        || receipt.paged_spend.len() > MAX_RPC_RECEIPT_BYTES
    {
        return None;
    }
    let header = claimed_header(&receipt.paged_spend).ok()?;
    let parent_start = MAGIC.len() + BLOCK_HEADER_WIRE_SIZE;
    let intent_start = parent_start + BLOCK_HEADER_WIRE_SIZE;
    let parent = BlockHeader::from_bytes(
        receipt
            .paged_spend
            .get(parent_start..intent_start)?
            .try_into()
            .ok()?,
    )
    .ok()?;
    if parent.height.checked_add(1) != Some(header.height)
        || crate::block_id(&parent) != header.prev_block_hash
        || !crate::consensus::params::v2_1_active(header.height)
        || !super::verify_against_header(receipt, &header)
    {
        return None;
    }
    let intent = NativeIntent::from_bytes(receipt.paged_spend.get(intent_start..)?).ok()?;
    if !intent.authorization_bytes.is_empty() {
        return None;
    }
    let facts = intent.validate_structure().ok()?;
    let chain = crate::state::native_assets::native_chain_id();
    match facts.operation {
        NativeOperation::Financial(operation) => {
            if !operation.requires_owner() {
                return None;
            }
            let round =
                NftRoundContext::new(header.height, header.prev_block_hash, parent.alloc_counter)
                    .ok()?;
            intent.checked_financial_owner(chain, round).ok()?;
        }
        _ => {
            intent.checked(chain, header.height).ok()?;
        }
    }
    if receipt.summary != summary_from_pages(&intent.pages, header.height, header.timestamp)
        || !crate::tx_tree::verify_path(
            facts.logical_txid.0,
            &receipt.merkle_path,
            usize::from(receipt.tx_index),
            usize::from(receipt.tx_count),
            receipt.claimed_root,
        )
    {
        return None;
    }
    Some((header, intent))
}
