// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Owned native action receipts from the canonical retained body window.

use std::collections::BTreeMap;

use noid_chain::{
    block::payload::BlockBodyPayload,
    consensus::{
        params::RECENT_BLOCK_RETENTION_DEPTH,
        receipt::{
            native_receipt_details, native_receipt_for_group, trade_receipt_for_policy,
            verify_against_header, verify_merkle_inclusion, ParanoidReceipt,
        },
    },
    storage::{MdbxChainContext, MdbxStore},
    Block, BlockHeader,
};
use noid_poseidon2b::primitives::Address;

use super::{persistence::ReceiptMap, WalletState};

pub(super) fn retain_payload_for_accounts(
    receipts: &mut ReceiptMap,
    accounts: &BTreeMap<[u8; 32], u32>,
    active: Address,
    payload: &BlockBodyPayload,
    parent: &BlockHeader,
) -> Result<(usize, Vec<[u8; 32]>), String> {
    let mut staged = Vec::new();
    let mut confirmed = Vec::new();
    for batch in payload.trade_batches() {
        for policy in batch.policies() {
            if !accounts.contains_key(&policy.policy.owner.0)
                && !accounts.contains_key(&policy.policy.recipient.0)
                && policy.policy.recipient != active
            {
                continue;
            }
            let id = policy.authorization_id().map_err(|e| e.to_string())?.0;
            confirmed.push(id);
            if receipts
                .get(&id)
                .and_then(|bytes| ParanoidReceipt::from_bytes(bytes).ok())
                .is_some_and(|receipt| {
                    receipt.is_trade()
                        && receipt.summary.logical_txid == id
                        && verify_merkle_inclusion(&receipt)
                        && verify_against_header(&receipt, &payload.block().header)
                })
            {
                continue;
            }
            let receipt = trade_receipt_for_policy(payload, parent, &id)?
                .ok_or("owned trade policy missing from canonical body")?;
            staged.push((id, receipt.to_bytes()));
        }
    }
    let block = payload.block();
    let stream = noid_chain::block::native_assets::validate_scheduled_block_page_stream(
        &block.transactions,
        block.header.height,
    )
    .map_err(|e| e.to_string())?;
    for group in stream.groups() {
        let noid_chain::block::native_assets::ScheduledSpendKind::Native(facts) = group.kind else {
            continue;
        };
        if super::scanner::is_trade_group(&group.kind) || !facts.operation.requires_owner() {
            continue;
        }
        let id = group.logical_txid().0;
        let receipt = native_receipt_for_group(payload, parent, &id)?
            .ok_or("native action missing from canonical body")?;
        let details = native_receipt_details(&receipt).ok_or("invalid native action receipt")?;
        if !details
            .participants()
            .iter()
            .any(|owner| *owner == active || accounts.contains_key(&owner.0))
        {
            continue;
        }
        confirmed.push(id);
        let retained = receipts
            .get(&id)
            .and_then(|bytes| ParanoidReceipt::from_bytes(bytes).ok())
            .is_some_and(|old| {
                old.is_native()
                    && verify_merkle_inclusion(&old)
                    && verify_against_header(&old, &block.header)
            });
        if !retained {
            staged.push((id, receipt.to_bytes()));
        }
    }
    let changed = staged.len();
    for (id, bytes) in staged {
        receipts.insert(id, bytes);
    }
    Ok((changed, confirmed))
}

fn retain_payload(
    wallet: &mut WalletState,
    payload: &BlockBodyPayload,
    parent: &BlockHeader,
) -> Result<usize, String> {
    if payload.native_openings().is_empty() {
        return Ok(0);
    }
    wallet.refresh_receipt_accounts();
    let active = wallet.active_address();
    let (changed, ids) = retain_payload_for_accounts(
        &mut wallet.receipts,
        &wallet.receipt_accounts,
        active,
        payload,
        parent,
    )?;
    let block = payload.block();
    let mut native_ids: std::collections::HashSet<_> = ids.into_iter().collect();
    let stream = noid_chain::block::native_assets::validate_scheduled_block_page_stream(
        &block.transactions,
        block.header.height,
    )
    .map_err(|e| e.to_string())?;
    for group in stream.groups().filter(|group| {
        matches!(
            group.kind,
            noid_chain::block::native_assets::ScheduledSpendKind::Native(_)
        )
    }) {
        native_ids.insert(group.logical_txid().0);
    }
    let before = wallet.history.len();
    wallet
        .history
        .retain(|entry| !native_ids.contains(&entry.tx_hash));
    if wallet.history.len() != before {
        wallet.mark_history_dirty(0);
    }
    wallet.receipts_dirty |= wallet.receipts.has_changes();
    Ok(changed)
}

pub(super) fn retain_from_block(
    wallet: &mut WalletState,
    store: &MdbxStore,
    block: &Block,
) -> Result<usize, String> {
    if !block
        .transactions
        .iter()
        .any(|transaction| noid_tx::native_assets::wire::is_native_header(&transaction.body))
    {
        return Ok(0);
    }
    let bytes = store
        .get_recent_canonical_body_payload(block.header.height)
        .map_err(|e| e.to_string())?
        .ok_or("native body unavailable for receipt retention")?;
    let payload = BlockBodyPayload::decode(&bytes).map_err(|e| e.to_string())?;
    if payload.block() != block {
        return Err("native receipt block differs from canonical body".into());
    }
    if payload.native_openings().is_empty() {
        return Ok(0);
    }
    let parent = store
        .get_header(block.header.height - 1)
        .map_err(|e| e.to_string())?
        .ok_or("native receipt parent missing")?;
    retain_payload(wallet, &payload, &parent)
}

pub(super) fn reconcile_canonical(
    wallet: &mut WalletState,
    store: &MdbxStore,
) -> Result<usize, String> {
    let mut removed = Vec::new();
    for (id, bytes) in &wallet.receipts {
        let Ok(receipt) = ParanoidReceipt::from_bytes(bytes) else {
            continue;
        };
        if (receipt.is_trade() || receipt.is_native())
            && store
                .get_header(receipt.claimed_height)
                .map_err(|e| e.to_string())?
                .is_some_and(|header| !verify_against_header(&receipt, &header))
        {
            removed.push(*id);
        }
    }
    for id in &removed {
        wallet.receipts.remove(id);
    }
    if !removed.is_empty() {
        let before = wallet.history.len();
        wallet
            .history
            .retain(|entry| !removed.contains(&entry.tx_hash));
        if wallet.history.len() != before {
            wallet.mark_history_dirty(0);
        }
    }
    wallet.receipts_dirty |= wallet.receipts.has_changes();
    Ok(removed.len())
}

pub(super) fn retain_from_chain(
    wallet: &mut WalletState,
    chain: &MdbxChainContext,
) -> Result<(usize, usize), String> {
    let removed = reconcile_canonical(wallet, &chain.store)?;
    let tip = chain.tip_height();
    if !noid_chain::consensus::params::v2_1_active(tip) {
        return Ok((removed, 0));
    }
    let first = tip
        .saturating_sub(RECENT_BLOCK_RETENTION_DEPTH.saturating_sub(1))
        .max(1);
    let mut changed = 0;
    for height in first..=tip {
        if !noid_chain::consensus::params::v2_1_active(height) {
            continue;
        }
        let Some(bytes) = chain
            .store
            .get_recent_canonical_body_payload(height)
            .map_err(|e| e.to_string())?
        else {
            continue;
        };
        let payload = BlockBodyPayload::decode(&bytes).map_err(|e| e.to_string())?;
        if payload.native_openings().is_empty() {
            continue;
        }
        let parent = chain
            .store
            .get_header(height - 1)
            .map_err(|e| e.to_string())?
            .ok_or("native receipt parent missing")?;
        changed += retain_payload(wallet, &payload, &parent)?;
    }
    Ok((removed, changed))
}

pub(super) fn persist(wallet: &mut WalletState) -> Result<(), String> {
    if wallet.history_dirty {
        wallet.save_history()?;
    }
    if wallet.receipts_dirty {
        wallet.save_receipts()?;
    }
    Ok(())
}
