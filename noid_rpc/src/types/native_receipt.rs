// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Authenticated asset effects for native wallet receipts.

use noid_tx::native_assets::{
    financial::FinancialOperation, nft_market::NftMarketOpening, transition::NativeOperation,
    NativeOpening,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptFilter {
    #[default]
    All,
    Noid,
    Tokens,
    Trades,
    Nfts,
}

impl ReceiptFilter {
    pub fn includes(
        self,
        receipt: &noid_chain::consensus::receipt::ParanoidReceipt,
    ) -> Result<bool, String> {
        if self == Self::All {
            return Ok(true);
        }
        if receipt.is_trade() {
            return Ok(self == Self::Trades);
        }
        if !receipt.is_native() {
            return Ok(self == Self::Noid);
        }
        let details = noid_chain::consensus::receipt::native_receipt_details(receipt)
            .ok_or("invalid native action receipt")?;
        let nft = matches!(
            details.operation,
            NativeOperation::CreateCollection { .. }
                | NativeOperation::MintNft
                | NativeOperation::TransferNft
                | NativeOperation::BurnNft
                | NativeOperation::Financial(
                    FinancialOperation::CreateListing { .. }
                        | FinancialOperation::Purchase { .. }
                        | FinancialOperation::CancelListing
                )
        );
        Ok(if nft {
            self == Self::Nfts
        } else {
            self == Self::Tokens
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptNativeInfo {
    pub operation: String,
    pub authority: String,
    pub token_inputs: Vec<ReceiptTokenInfo>,
    pub token_outputs: Vec<ReceiptTokenInfo>,
    pub nft_inputs: Vec<ReceiptNftInfo>,
    pub nft_outputs: Vec<ReceiptNftInfo>,
    pub noid_inputs: Vec<ReceiptNoidInfo>,
    pub noid_outputs: Vec<ReceiptNoidInfo>,
    pub reserves: Vec<ReceiptReserveInfo>,
    pub created: Vec<ReceiptCreatedInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptTokenInfo {
    pub asset_id: String,
    pub owner: String,
    pub units: String,
    pub unlock_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptNftInfo {
    pub collection_id: String,
    pub serial: u64,
    pub owner: String,
    pub metadata_hash: String,
    pub unlock_height: u64,
    pub listed: bool,
    pub ask_micronoid: Option<u64>,
    pub expiry_height: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptNoidInfo {
    pub owner: String,
    pub amount_micronoid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptReserveInfo {
    pub asset_id: String,
    pub after: bool,
    pub amount_micronoid: String,
    pub outstanding_units: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptCreatedInfo {
    pub kind: String,
    pub id: String,
    pub metadata_hash: String,
    pub supply_or_maximum: String,
}

impl From<noid_chain::consensus::receipt::NativeReceiptDetails> for ReceiptNativeInfo {
    fn from(details: noid_chain::consensus::receipt::NativeReceiptDetails) -> Self {
        let operation = match details.operation {
            NativeOperation::CreateToken { .. }
            | NativeOperation::Financial(FinancialOperation::CreateLaunch { .. }) => "create_token",
            NativeOperation::TransferToken { .. } => "transfer_token",
            NativeOperation::RedeemToken { .. } => "burn_token",
            NativeOperation::TopUpReserve { .. } => "top_up_reserve",
            NativeOperation::CreateCollection { .. } => "create_collection",
            NativeOperation::MintNft => "mint_nft",
            NativeOperation::TransferNft => "transfer_nft",
            NativeOperation::BurnNft => "burn_nft",
            NativeOperation::Financial(FinancialOperation::CreateListing { .. }) => "list_nft",
            NativeOperation::Financial(FinancialOperation::Purchase { .. }) => "buy_nft",
            NativeOperation::Financial(FinancialOperation::CancelListing) => "cancel_listing",
            NativeOperation::Financial(FinancialOperation::ExecuteTrades { .. }) => "trade_batch",
            _ => "native_action",
        };
        let mut result = Self {
            operation: operation.into(),
            authority: details.authority.to_bech32(),
            token_inputs: Vec::new(),
            token_outputs: Vec::new(),
            nft_inputs: Vec::new(),
            nft_outputs: Vec::new(),
            noid_inputs: Vec::new(),
            noid_outputs: Vec::new(),
            reserves: Vec::new(),
            created: Vec::new(),
        };
        for (after, owner, amount, opening) in details
            .inputs
            .iter()
            .map(|claim| (false, claim.root, claim.input.amount, claim.opening))
            .chain(
                details
                    .outputs
                    .iter()
                    .map(|claim| (true, claim.output.owner, claim.output.amount, claim.opening)),
            )
        {
            let Some(opening) = opening else {
                let balances = if after {
                    &mut result.noid_outputs
                } else {
                    &mut result.noid_inputs
                };
                balances.push(ReceiptNoidInfo {
                    owner: owner.to_bech32(),
                    amount_micronoid: amount.to_string(),
                });
                continue;
            };
            match opening {
                NativeOpening::TokenBalance(balance) => {
                    let balances = if after {
                        &mut result.token_outputs
                    } else {
                        &mut result.token_inputs
                    };
                    balances.push(ReceiptTokenInfo {
                        asset_id: hex::encode(balance.asset.0),
                        owner: balance.owner.to_bech32(),
                        units: balance.units.to_string(),
                        unlock_height: balance.unlock_height,
                    });
                }
                NativeOpening::NftItem(item) => {
                    let items = if after {
                        &mut result.nft_outputs
                    } else {
                        &mut result.nft_inputs
                    };
                    items.push(ReceiptNftInfo {
                        collection_id: hex::encode(item.collection.0),
                        serial: item.serial,
                        owner: item.owner.to_bech32(),
                        metadata_hash: hex::encode(item.metadata),
                        unlock_height: item.unlock_height,
                        listed: false,
                        ask_micronoid: None,
                        expiry_height: None,
                    });
                }
                NativeOpening::NftMarket(NftMarketOpening::Listing(listing)) => {
                    let definition = details.dependencies.iter().find_map(|value| match value {
                        NativeOpening::NftMarket(NftMarketOpening::Definition(definition))
                            if definition.id() == listing.listing =>
                        {
                            Some(definition)
                        }
                        _ => None,
                    });
                    if let Some(definition) = definition {
                        let items = if after {
                            &mut result.nft_outputs
                        } else {
                            &mut result.nft_inputs
                        };
                        items.push(ReceiptNftInfo {
                            collection_id: hex::encode(definition.collection.0),
                            serial: definition.serial,
                            owner: definition.seller.to_bech32(),
                            metadata_hash: hex::encode(definition.metadata),
                            unlock_height: 0,
                            listed: true,
                            ask_micronoid: Some(definition.ask),
                            expiry_height: Some(definition.expiry_height),
                        });
                    }
                }
                NativeOpening::TokenReserve(reserve) => result.reserves.push(ReceiptReserveInfo {
                    asset_id: hex::encode(reserve.asset.0),
                    after,
                    amount_micronoid: reserve.reserve_micronoid.to_string(),
                    outstanding_units: reserve.outstanding_units.to_string(),
                }),
                NativeOpening::FungibleDefinition(definition) if after => {
                    result.created.push(ReceiptCreatedInfo {
                        kind: "token".into(),
                        id: hex::encode(definition.asset.0),
                        metadata_hash: hex::encode(definition.metadata),
                        supply_or_maximum: definition.initial_supply.to_string(),
                    })
                }
                NativeOpening::NftCollection(collection)
                    if after
                        && matches!(
                            details.operation,
                            NativeOperation::CreateCollection { .. }
                        ) =>
                {
                    result.created.push(ReceiptCreatedInfo {
                        kind: "collection".into(),
                        id: hex::encode(collection.collection.0),
                        metadata_hash: hex::encode(collection.metadata),
                        supply_or_maximum: collection.maximum_items.to_string(),
                    })
                }
                _ => {}
            }
        }
        result
    }
}
