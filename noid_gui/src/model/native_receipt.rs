// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    pub const ALL: [Self; 5] = [
        Self::All,
        Self::Noid,
        Self::Tokens,
        Self::Trades,
        Self::Nfts,
    ];
}

impl std::fmt::Display for ReceiptFilter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::All => "ALL",
            Self::Noid => "NOID",
            Self::Tokens => "TOKENS",
            Self::Trades => "TRADES",
            Self::Nfts => "NFT",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceiptNativeSnapshot {
    pub operation: String,
    pub authority: String,
    pub token_inputs: Vec<ReceiptTokenSnapshot>,
    pub token_outputs: Vec<ReceiptTokenSnapshot>,
    pub nft_inputs: Vec<ReceiptNftSnapshot>,
    pub nft_outputs: Vec<ReceiptNftSnapshot>,
    pub noid_inputs: Vec<ReceiptNoidSnapshot>,
    pub noid_outputs: Vec<ReceiptNoidSnapshot>,
    pub reserves: Vec<ReceiptReserveSnapshot>,
    pub created: Vec<ReceiptCreatedSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceiptTokenSnapshot {
    pub asset_id: String,
    pub owner: String,
    pub units: String,
    pub unlock_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceiptNftSnapshot {
    pub collection_id: String,
    pub serial: u64,
    pub owner: String,
    pub metadata_hash: String,
    pub unlock_height: u64,
    pub listed: bool,
    pub ask_micronoid: Option<u64>,
    pub expiry_height: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceiptNoidSnapshot {
    pub owner: String,
    pub amount_micronoid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceiptReserveSnapshot {
    pub asset_id: String,
    pub after: bool,
    pub amount_micronoid: String,
    pub outstanding_units: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceiptCreatedSnapshot {
    pub kind: String,
    pub id: String,
    pub metadata_hash: String,
    pub supply_or_maximum: String,
}

pub fn format_native_units(value: &str) -> String {
    let Ok(value) = value.parse::<u128>() else {
        return "invalid amount".into();
    };
    let fraction = format!("{:06}", value % 1_000_000);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        (value / 1_000_000).to_string()
    } else {
        format!("{}.{fraction}", value / 1_000_000)
    }
}

impl ReceiptNativeSnapshot {
    pub fn label(&self) -> String {
        let amount = match self.operation.as_str() {
            "transfer_token" => {
                let sent: u128 = self
                    .token_outputs
                    .iter()
                    .filter(|value| value.owner != self.authority)
                    .filter_map(|value| value.units.parse::<u128>().ok())
                    .sum();
                if sent == 0 {
                    return "TOKEN TRANSFER".into();
                }
                return format!("TRANSFER {} TOKEN", format_native_units(&sent.to_string()));
            }
            "burn_token" => {
                let before: u128 = self
                    .token_inputs
                    .iter()
                    .filter_map(|value| value.units.parse::<u128>().ok())
                    .sum();
                let after: u128 = self
                    .token_outputs
                    .iter()
                    .filter_map(|value| value.units.parse::<u128>().ok())
                    .sum();
                return format!(
                    "BURN {} TOKEN",
                    format_native_units(&before.saturating_sub(after).to_string())
                );
            }
            "trade_batch" => return "TRADE BATCH".into(),
            "create_token" => return "TOKEN CREATED".into(),
            "create_collection" => return "COLLECTION CREATED".into(),
            "mint_nft" => "CREATED",
            "transfer_nft" => "TRANSFER",
            "burn_nft" => "BURN",
            "list_nft" => "LISTED",
            "buy_nft" => "PURCHASED",
            "cancel_listing" => "LISTING CANCELLED",
            "top_up_reserve" => return "RESERVE FUNDED".into(),
            _ => return "NATIVE ACTION".into(),
        };
        let serial = self
            .nft_outputs
            .first()
            .or(self.nft_inputs.first())
            .map(|item| item.serial);
        serial.map_or_else(|| amount.into(), |serial| format!("{amount} NFT #{serial}"))
    }

    pub fn subject(&self) -> Option<&str> {
        self.token_outputs
            .first()
            .or(self.token_inputs.first())
            .map(|value| value.asset_id.as_str())
            .or_else(|| {
                self.nft_outputs
                    .first()
                    .or(self.nft_inputs.first())
                    .map(|value| value.collection_id.as_str())
            })
            .or_else(|| self.created.first().map(|value| value.id.as_str()))
    }
}
