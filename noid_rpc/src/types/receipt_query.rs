// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::{ReceiptFilter, ReceiptSummaryInfo, WalletReceiptInfo};
use noid_chain::consensus::receipt::ParanoidReceipt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOrder {
    #[default]
    Newest,
    Oldest,
    Asset,
    Operation,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptVerification {
    #[default]
    Any,
    Confirmed,
    OffChain,
    MissingHeader,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOperation {
    #[default]
    Any,
    Payment,
    CreateToken,
    TransferToken,
    BurnToken,
    Trade,
    CreateNft,
    TransferNft,
    BurnNft,
    ListNft,
    BuyNft,
    CancelListing,
}

impl ReceiptOperation {
    pub fn native(operation: &str) -> Self {
        match operation {
            "create_token" => Self::CreateToken,
            "transfer_token" => Self::TransferToken,
            "burn_token" => Self::BurnToken,
            "create_collection" | "mint_nft" => Self::CreateNft,
            "transfer_nft" => Self::TransferNft,
            "burn_nft" => Self::BurnNft,
            "list_nft" => Self::ListNft,
            "buy_nft" => Self::BuyNft,
            "cancel_listing" => Self::CancelListing,
            _ => Self::Any,
        }
    }
    pub fn rank(self) -> u8 {
        match self {
            Self::Payment => 0,
            Self::CreateToken => 1,
            Self::TransferToken => 2,
            Self::BurnToken => 3,
            Self::Trade => 4,
            Self::CreateNft => 5,
            Self::TransferNft => 6,
            Self::BurnNft => 7,
            Self::ListNft => 8,
            Self::BuyNft => 9,
            Self::CancelListing => 10,
            Self::Any => 255,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReceiptQuery {
    pub filter: ReceiptFilter,
    pub asset_id: Option<String>,
    pub operation: ReceiptOperation,
    pub timestamp_from: Option<u64>,
    pub timestamp_before: Option<u64>,
    pub verification: ReceiptVerification,
    pub order: ReceiptOrder,
}

impl ReceiptQuery {
    pub fn validate(&self) -> Result<(), String> {
        if self.asset_id.as_ref().is_some_and(|id| {
            id.len() != 64
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err(
                "asset_id must be a canonical 64-character lowercase hexadecimal identifier".into(),
            );
        }
        const YEAR_10000: u64 = 253_402_300_800;
        if self.timestamp_from.is_some_and(|from| from >= YEAR_10000)
            || self
                .timestamp_before
                .is_some_and(|before| before > YEAR_10000)
            || self
                .timestamp_from
                .zip(self.timestamp_before)
                .is_some_and(|(from, before)| from >= before)
        {
            return Err(
                "receipt date range must be ordered and within years 1970 through 9999".into(),
            );
        }
        Ok(())
    }

    pub fn matches(&self, metadata: &ReceiptQueryMetadata) -> bool {
        (self.filter == ReceiptFilter::All || self.filter == metadata.family)
            && (self.operation == ReceiptOperation::Any || self.operation == metadata.operation)
            && self
                .asset_id
                .as_ref()
                .is_none_or(|asset| metadata.assets.contains(asset))
            && self
                .timestamp_from
                .is_none_or(|from| metadata.timestamp >= from)
            && self
                .timestamp_before
                .is_none_or(|before| metadata.timestamp < before)
    }
}

pub struct ReceiptQueryMetadata {
    pub family: ReceiptFilter,
    pub operation: ReceiptOperation,
    pub assets: BTreeSet<String>,
    pub height: u64,
    pub timestamp: u64,
    pub id: [u8; 32],
}

impl ReceiptQueryMetadata {
    pub fn authenticated(receipt: &ParanoidReceipt) -> Result<Option<Self>, String> {
        let summary = ReceiptSummaryInfo::authenticated(receipt)
            .ok_or("saved receipt failed mathematical verification")?;
        let mut assets = BTreeSet::new();
        let (family, operation) = if let Some(trade) = summary.trade {
            assets.insert(trade.asset_id);
            (ReceiptFilter::Trades, ReceiptOperation::Trade)
        } else if let Some(native) = summary.native {
            let operation = ReceiptOperation::native(&native.operation);
            let nft = matches!(
                operation,
                ReceiptOperation::CreateNft
                    | ReceiptOperation::TransferNft
                    | ReceiptOperation::BurnNft
                    | ReceiptOperation::ListNft
                    | ReceiptOperation::BuyNft
                    | ReceiptOperation::CancelListing
            );
            for item in native.token_inputs.iter().chain(&native.token_outputs) {
                assets.insert(item.asset_id.clone());
            }
            for item in native.nft_inputs.iter().chain(&native.nft_outputs) {
                assets.insert(item.collection_id.clone());
            }
            for item in &native.reserves {
                assets.insert(item.asset_id.clone());
            }
            for item in &native.created {
                assets.insert(item.id.clone());
            }
            (
                if nft {
                    ReceiptFilter::Nfts
                } else {
                    ReceiptFilter::Tokens
                },
                operation,
            )
        } else {
            if receipt.is_trade() || receipt.is_native() {
                return Err("saved native receipt effects are invalid".into());
            }
            let different_recipient = receipt.summary.inputs.first().is_some_and(|(_, owner)| {
                receipt
                    .summary
                    .outputs
                    .iter()
                    .any(|(_, _, recipient)| recipient != owner)
            });
            if !different_recipient {
                return Ok(None);
            }
            (ReceiptFilter::Noid, ReceiptOperation::Payment)
        };
        Ok(Some(Self {
            family,
            operation,
            assets,
            height: receipt.claimed_height,
            timestamp: receipt.summary.confirmed_unix,
            id: receipt.summary.logical_txid,
        }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletReceiptQueryPage {
    pub page: u32,
    pub page_size: u32,
    pub query: ReceiptQuery,
    pub total: usize,
    pub total_pages: u32,
    pub receipts: Vec<WalletReceiptInfo>,
}
