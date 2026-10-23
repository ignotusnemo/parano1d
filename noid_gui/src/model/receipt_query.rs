// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::ReceiptFilter;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Order {
    #[default]
    Newest,
    Oldest,
    Asset,
    Operation,
}
impl Order {
    pub const ALL: [Self; 4] = [Self::Newest, Self::Oldest, Self::Asset, Self::Operation];
}
impl std::fmt::Display for Order {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::i18n::translate(match self {
            Self::Newest => "Newest first",
            Self::Oldest => "Oldest first",
            Self::Asset => "Asset",
            Self::Operation => "Operation",
        }))
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    #[default]
    Any,
    Confirmed,
    OffChain,
    MissingHeader,
}
impl Verification {
    pub const ALL: [Self; 4] = [
        Self::Any,
        Self::Confirmed,
        Self::OffChain,
        Self::MissingHeader,
    ];
}
impl std::fmt::Display for Verification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::i18n::translate(match self {
            Self::Any => "Any status",
            Self::Confirmed => "Confirmed",
            Self::OffChain => "Off chain",
            Self::MissingHeader => "Header unavailable",
        }))
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
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
impl Operation {
    pub const ALL: [Self; 12] = [
        Self::Any,
        Self::Payment,
        Self::CreateToken,
        Self::TransferToken,
        Self::BurnToken,
        Self::Trade,
        Self::CreateNft,
        Self::TransferNft,
        Self::BurnNft,
        Self::ListNft,
        Self::BuyNft,
        Self::CancelListing,
    ];
}
impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::i18n::translate(match self {
            Self::Any => "Any operation",
            Self::Payment => "Payment",
            Self::CreateToken => "Create token",
            Self::TransferToken => "Send tokens",
            Self::BurnToken => "Burn & redeem",
            Self::Trade => "Trade",
            Self::CreateNft => "Create NFT",
            Self::TransferNft => "Send NFT",
            Self::BurnNft => "Burn NFT",
            Self::ListNft => "List NFT",
            Self::BuyNft => "Buy NFT",
            Self::CancelListing => "Cancel listing",
        }))
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub filter: ReceiptFilter,
    pub asset_id: Option<String>,
    pub operation: Operation,
    pub timestamp_from: Option<u64>,
    pub timestamp_before: Option<u64>,
    pub verification: Verification,
    pub order: Order,
}

impl Query {
    pub fn is_default(&self) -> bool {
        *self
            == Self {
                filter: self.filter,
                ..Self::default()
            }
    }
}

#[derive(Debug, Clone)]
pub enum Action {
    Toggle,
    Asset(String),
    Operation(Operation),
    From(String),
    Through(String),
    Verification(Verification),
    Order(Order),
    Apply,
    Clear,
}

#[derive(Debug, Default)]
pub struct State {
    pub open: bool,
    pub asset: String,
    pub operation: Operation,
    pub from: String,
    pub through: String,
    pub verification: Verification,
    pub order: Order,
    pub applied: Query,
    pub error: Option<String>,
}

impl State {
    pub fn set_order(&mut self, order: Order) -> bool {
        self.order = order;
        let changed = self.applied.order != order;
        self.applied.order = order;
        changed
    }

    pub fn query(&self, filter: ReceiptFilter) -> Result<Query, String> {
        let asset = self.asset.trim();
        let asset_id = if asset.is_empty() {
            None
        } else {
            if asset.len() != 64 || !asset.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err("Use the complete 64-character asset or collection ID.".into());
            }
            Some(asset.to_ascii_lowercase())
        };
        let from = parse_date(&self.from)?;
        let before = parse_date(&self.through)?.map(|date| date + 86400);
        if from
            .zip(before)
            .is_some_and(|(from, before)| from >= before)
        {
            return Err("The end date must be on or after the start date.".into());
        }
        Ok(Query {
            filter,
            asset_id,
            operation: self.operation,
            timestamp_from: from,
            timestamp_before: before,
            verification: self.verification,
            order: self.order,
        })
    }

    pub fn apply(&mut self, filter: ReceiptFilter) -> bool {
        match self.query(filter) {
            Ok(query) => {
                self.error = None;
                let changed = self.applied != query;
                self.applied = query;
                changed
            }
            Err(error) => {
                self.error = Some(error);
                false
            }
        }
    }

    pub fn family(&mut self, filter: ReceiptFilter) {
        self.asset.clear();
        self.operation = Operation::Any;
        self.applied.filter = filter;
        self.applied.asset_id = None;
        self.applied.operation = Operation::Any;
        self.apply(filter);
    }

    pub fn clear(&mut self, filter: ReceiptFilter) {
        *self = Self {
            open: self.open,
            applied: Query {
                filter,
                ..Query::default()
            },
            ..Self::default()
        };
    }
}

fn parse_date(value: &str) -> Result<Option<u64>, String> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, c)| i != 4 && i != 7 && !c.is_ascii_digit())
    {
        return Err("Use dates in YYYY-MM-DD format (UTC).".into());
    }
    let year = value[..4].parse::<u64>().map_err(|_| "Invalid year.")?;
    let month = value[5..7].parse::<usize>().map_err(|_| "Invalid month.")?;
    let day = value[8..].parse::<u64>().map_err(|_| "Invalid day.")?;
    let leap = |y: u64| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day == 0
        || day > months[month - 1]
    {
        return Err("Enter a valid date from 1970 to 9999.".into());
    }
    let leaps_before = |year: u64| (year - 1) / 4 - (year - 1) / 100 + (year - 1) / 400;
    let days = (year - 1970) * 365 + leaps_before(year) - leaps_before(1970)
        + months[..month - 1].iter().sum::<u64>()
        + day
        - 1;
    Ok(Some(days * 86400))
}
