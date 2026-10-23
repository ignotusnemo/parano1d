// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Resumable retention for the local recent-transaction locator.

use super::*;

const CURSOR_KEY: &[u8] = &[4];
const SCAN_LIMIT: usize = 4096;

pub(super) fn prune(txn: &Transaction<'_, RW, NoWriteMap>) -> Result<usize, StoreError> {
    let metadata = txn.open_table(Some(T_CONSENSUS_META))?;
    let raw: Vec<u8> = txn
        .get(&metadata, KEY_CONSENSUS_META)?
        .ok_or(StoreError::Decode("transaction locator consensus metadata"))?;
    let consensus = decode_consensus_meta(&raw)
        .ok_or(StoreError::Decode("transaction locator consensus encoding"))?;
    if consensus.tip_height <= RETAINED_BLOCK_SERVING_DEPTH {
        return Ok(0);
    }
    let tip_table = txn.open_table(Some(T_CHAIN_TIP))?;
    let tip: Vec<u8> = txn
        .get(&tip_table, KEY_TIP)?
        .ok_or(StoreError::Decode("transaction locator canonical tip"))?;
    if decode_chain_tip(&tip) != Some((consensus.tip_height, consensus.tip_hash))
        || consensus.finalized.height > consensus.tip_height
    {
        return Err(StoreError::Decode("transaction locator tip binding"));
    }
    let headers = txn.open_table(Some(T_HEADERS))?;
    let finalized: Vec<u8> = txn
        .get(&headers, &u64_key(consensus.finalized.height))?
        .ok_or(StoreError::Decode("transaction locator finalized header"))?;
    let finalized = decode_header(&finalized)
        .ok_or(StoreError::Decode("transaction locator finalized encoding"))?;
    if finalized.height != consensus.finalized.height
        || crate::block_id(&finalized) != consensus.finalized.hash
    {
        return Err(StoreError::Decode("transaction locator finalized binding"));
    }
    let cutoff =
        (consensus.tip_height - RETAINED_BLOCK_SERVING_DEPTH).min(consensus.finalized.height);
    let retention = txn.open_table(Some(T_RETENTION_META))?;
    let resume: Option<Vec<u8>> = txn.get(&retention, CURSOR_KEY)?;
    if resume.as_ref().is_some_and(|key| key.len() != 32) {
        return Err(StoreError::Decode("transaction locator cursor"));
    }
    let table = txn.open_table(Some(T_TX_INDEX))?;
    let (expired, last, reached_end) = {
        let mut cursor = txn.cursor(&table)?;
        let mut row: Option<(Vec<u8>, Vec<u8>)> = if let Some(key) = resume.as_deref() {
            let found: Option<(Vec<u8>, Vec<u8>)> = cursor.set_range(key)?;
            match found {
                Some((found, _)) if found.as_slice() == key => cursor.next()?,
                other => other,
            }
        } else {
            cursor.first()?
        };
        let mut expired = Vec::new();
        let mut last = None;
        for _ in 0..SCAN_LIMIT {
            let Some((key, value)) = row.take() else {
                break;
            };
            if key.len() != 32 {
                return Err(StoreError::Decode("transaction locator key"));
            }
            let (height, _) = decode_tx_index_value(&value)
                .ok_or(StoreError::Decode("transaction locator value"))?;
            if height <= cutoff {
                expired.push(key.clone());
            }
            last = Some(key);
            row = cursor.next()?;
        }
        (expired, last, row.is_none())
    };
    for key in &expired {
        txn.del(&table, key, None)?;
    }
    if reached_end {
        txn.del(&retention, CURSOR_KEY, None)?;
    } else if let Some(key) = last {
        txn.put(&retention, CURSOR_KEY, key, WriteFlags::empty())?;
    }
    Ok(expired.len())
}
