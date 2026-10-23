// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Public native wallet views with exact integer and State identities.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCatalogKind {
    Markets,
    Collections,
    NftListings,
}

impl NativeCatalogKind {
    pub fn storage(self) -> noid_chain::storage::NativeCatalogKind {
        use noid_chain::storage::NativeCatalogKind as Store;
        match self {
            Self::Markets => Store::Markets,
            Self::Collections => Store::Collections,
            Self::NftListings => Store::NftListings,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCatalogCursor {
    pub kind: NativeCatalogKind,
    pub height: u64,
    pub block_hash: String,
    pub after_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeCatalogItem {
    pub key: String,
    pub primary: NativeHolding,
    pub related: Vec<NativeHolding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeCatalogPage {
    pub kind: NativeCatalogKind,
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub scanned: usize,
    pub items: Vec<NativeCatalogItem>,
    pub next: Option<NativeCatalogCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeMarketDetails {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub item: Option<NativeCatalogItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWalletCursor {
    pub owner: String,
    pub height: u64,
    pub block_hash: String,
    pub after_root: Option<String>,
    pub from_slot: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeHolding {
    pub root: String,
    pub kind: u16,
    pub opening_hex: String,
    pub dependency_hex: Option<String>,
    pub slot_index: u32,
    pub creation_id: String,
    pub amount_micronoid: String,
    pub unlock_height: u64,
    #[serde(default)]
    pub reserved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeHoldingsPage {
    pub owner: String,
    pub key_index: Option<u32>,
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub holdings: Vec<NativeHolding>,
    pub next: Option<NativeWalletCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeProtocolInfo {
    pub tip_height: u64,
    pub activation_height: Option<u64>,
    pub active_at_next_block: bool,
    pub runtime_available: bool,
    pub initial_creator_purchase: bool,
    pub nft_batch_limit: Option<usize>,
    pub token_decimals: u8,
    pub minimum_launch_whole_tokens: String,
    pub maximum_launch_whole_tokens: String,
    pub minimum_backing_micronoid_per_whole_token: String,
    pub pages: Option<usize>,
    pub headers: Option<usize>,
    pub actions: Option<usize>,
    pub markets: Option<usize>,
    pub trade_policies: Option<usize>,
    pub trade_funding_inputs: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeWalletRequest {
    TransferToken {
        asset_id: String,
        units: String,
        recipient: String,
    },
    BurnToken {
        asset_id: String,
        units: String,
    },
    Trade {
        asset_id: String,
        buy: bool,
        gross_input: String,
        minimum_output: Option<String>,
        slippage_bps: Option<u16>,
        valid_until: Option<u64>,
    },
    CreateToken {
        whole_tokens: String,
        metadata_hash: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initial_buy_units: Option<String>,
    },
    CreateCollection {
        maximum_items: String,
        metadata_hash: String,
    },
    MintNft {
        collection_id: String,
        metadata_hash: String,
    },
    MintNfts {
        collection_id: String,
        metadata_hashes: Vec<String>,
    },
    TransferNft {
        collection_id: String,
        serial: String,
        recipient: String,
    },
    BurnNft {
        collection_id: String,
        serial: String,
    },
    ListNft {
        collection_id: String,
        serial: String,
        ask_micronoid: String,
        expiry_height: u64,
    },
    BuyNft {
        collection_id: String,
        serial: String,
        maximum_ask_micronoid: String,
    },
    CancelListing {
        collection_id: String,
        serial: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativePendingQuote {
    pub pending_policies: usize,
    pub selected_policies: usize,
    pub selected_markets: usize,
    pub position: Option<usize>,
    pub output: Option<String>,
    pub spent_input: Option<String>,
    pub market_fee: Option<String>,
    pub network_fee: Option<String>,
    pub confirmed_output: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeWalletPreview {
    pub plan_id: String,
    pub txid: String,
    pub owner: String,
    pub key_index: u32,
    pub height: u64,
    pub parent_hash: String,
    pub state_root: String,
    pub request: NativeWalletRequest,
    pub fee_micronoid: String,
    pub fee_limit_micronoid: Option<String>,
    pub noid_debit_micronoid: String,
    pub noid_credit_micronoid: String,
    pub reserve_deposit_micronoid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_buy_cost_micronoid: Option<String>,
    pub redemption_micronoid: Option<String>,
    pub quoted_output: Option<String>,
    pub minimum_output: Option<String>,
    pub valid_until: Option<u64>,
    pub asset_id: Option<String>,
    pub collection_id: Option<String>,
    pub serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_serial: Option<String>,
    pub input_count: usize,
    pub output_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_quote: Option<NativePendingQuote>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeWalletSubmitResult {
    pub txid: String,
    pub plan_id: String,
    pub fee_micronoid: String,
    pub fee_limit_micronoid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeWalletPending {
    pub txid: String,
    pub owner: String,
    pub key_index: u32,
    pub parent_height: u64,
    pub input_count: usize,
    pub output_count: usize,
    #[serde(default)]
    pub status: NativeWalletPendingStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitted_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<NativeWalletPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation_height: Option<u64>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeWalletPendingStatus {
    #[default]
    Pending,
    Unconfirmed,
    Confirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWalletActivity {
    pub submitted_unix: u64,
    pub preview: NativeWalletPreview,
}
