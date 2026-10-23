// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::types::{
    ReceiptOrder, ReceiptQuery, ReceiptQueryMetadata, ReceiptVerification, WalletReceiptQueryPage,
};
use noid_chain::consensus::receipt::{verify_against_header, ParanoidReceipt};
use std::collections::{BTreeMap, BinaryHeap};

static RECEIPT_QUERY_GATE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    asset: [u8; 32],
    operation: u8,
    height: u64,
    timestamp: u64,
    id: [u8; 32],
}

impl Key {
    fn from_metadata(
        query: &ReceiptQuery,
        metadata: &ReceiptQueryMetadata,
    ) -> Result<Self, String> {
        let mut asset = [0; 32];
        if query.order == ReceiptOrder::Asset {
            if let Some(value) = metadata.assets.first() {
                hex::decode_to_slice(value, &mut asset)
                    .map_err(|_| "invalid authenticated asset identity")?;
            }
        }
        let ascending = query.order == ReceiptOrder::Oldest;
        Ok(Self {
            asset,
            operation: if query.order == ReceiptOrder::Operation {
                metadata.operation.rank()
            } else {
                0
            },
            height: if ascending {
                metadata.height
            } else {
                !metadata.height
            },
            timestamp: if ascending {
                metadata.timestamp
            } else {
                !metadata.timestamp
            },
            id: if ascending {
                metadata.id
            } else {
                metadata.id.map(|byte| !byte)
            },
        })
    }
    fn id(self, order: ReceiptOrder) -> [u8; 32] {
        if order == ReceiptOrder::Oldest {
            self.id
        } else {
            self.id.map(|byte| !byte)
        }
    }
}

impl RpcHandler {
    pub(super) async fn query_wallet_receipts(
        &self,
        page: u32,
        page_size: u32,
        query: ReceiptQuery,
    ) -> RpcResult<WalletReceiptQueryPage> {
        query.validate().map_err(rpc_err)?;
        if page == 0 || page_size == 0 || page_size > 50 {
            return Err(rpc_err(
                "receipt page must be positive and page_size in 1..=50",
            ));
        }
        let offset = usize::try_from(page - 1)
            .ok()
            .and_then(|page| page.checked_mul(page_size as usize))
            .ok_or_else(|| rpc_err("receipt page offset overflow"))?;
        let permit = RECEIPT_QUERY_GATE
            .try_acquire()
            .map_err(|_| rpc_err("a receipt query is already running; retry shortly"))?;
        let handler = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            handler.scan_receipts(page, page_size, offset, query)
        })
        .await
        .map_err(|_| rpc_err("receipt query did not finish"))?
    }

    fn scan_receipts(
        &self,
        page: u32,
        page_size: u32,
        offset: usize,
        query: ReceiptQuery,
    ) -> RpcResult<WalletReceiptQueryPage> {
        let tip = self.chain.blocking_read().tip_hash();
        let index = self.wallet.receipt_query_index().map_err(rpc_err)?;
        let required = offset
            .checked_add(page_size as usize)
            .ok_or_else(|| rpc_err("receipt page limit overflow"))?;
        let mut selected = BinaryHeap::new();
        let mut total = 0usize;
        let mut headers = BTreeMap::new();
        for id in index.ids {
            let bytes = self
                .wallet
                .receipt_query_bytes(&index.revision, &id)
                .map_err(rpc_err)?;
            let receipt = ParanoidReceipt::from_bytes(&bytes)
                .map_err(|_| rpc_err("invalid saved receipt encoding"))?;
            if receipt.summary.logical_txid != id {
                return Err(rpc_err("saved receipt identity differs from its key"));
            }
            let Some(metadata) = ReceiptQueryMetadata::authenticated(&receipt).map_err(rpc_err)?
            else {
                continue;
            };
            if !query.matches(&metadata) {
                continue;
            }
            if query.verification != ReceiptVerification::Any {
                if !headers.contains_key(&receipt.claimed_height) {
                    let header = self
                        .chain
                        .blocking_read()
                        .get_header_from_store(receipt.claimed_height)
                        .map_err(|e| rpc_err(e.to_string()))?;
                    if headers.len() >= 1024 {
                        headers.clear();
                    }
                    headers.insert(receipt.claimed_height, header);
                }
                let status = match headers
                    .get(&receipt.claimed_height)
                    .and_then(Option::as_ref)
                {
                    Some(header) if verify_against_header(&receipt, header) => {
                        ReceiptVerification::Confirmed
                    }
                    Some(_) => ReceiptVerification::OffChain,
                    None => ReceiptVerification::MissingHeader,
                };
                if query.verification != status {
                    continue;
                }
            }
            total = total
                .checked_add(1)
                .ok_or_else(|| rpc_err("receipt count overflow"))?;
            let key = Key::from_metadata(&query, &metadata).map_err(rpc_err)?;
            if selected.len() < required {
                selected.push(key);
            } else if selected.peek().is_some_and(|largest| key < *largest) {
                let mut largest = selected.peek_mut().expect("nonempty selected receipts");
                *largest = key;
            }
        }
        let ids: Vec<_> = selected
            .into_sorted_vec()
            .into_iter()
            .skip(offset)
            .map(|key| key.id(query.order))
            .collect();
        let records = self
            .wallet
            .receipt_query_records(&index.revision, &ids)
            .map_err(rpc_err)?;
        if self.chain.blocking_read().tip_hash() != tip {
            return Err(rpc_err(
                "canonical headers changed during the receipt query; refresh",
            ));
        }
        let receipts = records
            .into_iter()
            .map(|receipt| WalletReceiptInfo {
                txid: hex::encode(receipt.txid),
                height: receipt.height,
                timestamp: receipt.timestamp,
                amount_micronoid: receipt.amount_micronoid,
                fee_micronoid: receipt.fee_micronoid,
                peer_address: receipt.peer_address,
                own_address: receipt.own_address,
                own_key_index: receipt.own_key_index,
                input_count: receipt.input_count,
                output_count: receipt.output_count,
                receipt_bytes: receipt.receipt_bytes,
                trade: receipt.trade,
                native: receipt.native,
            })
            .collect();
        let total_pages = u32::try_from(total.div_ceil(page_size as usize))
            .map_err(|_| rpc_err("receipt page count overflow"))?;
        Ok(WalletReceiptQueryPage {
            page,
            page_size,
            query,
            total,
            total_pages,
            receipts,
        })
    }
}
