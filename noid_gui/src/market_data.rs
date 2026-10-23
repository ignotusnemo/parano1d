// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_BLOCKS: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 512 * 1024;

pub fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Price {
    pub noid: u64,
    pub tokens: u64,
}

impl Price {
    pub fn value(self) -> f64 {
        self.noid as f64 / self.tokens as f64
    }
    pub fn valid(self) -> bool {
        self.noid > 0 && self.tokens > 0
    }
    pub fn cmp(self, other: Self) -> std::cmp::Ordering {
        (u128::from(self.noid) * u128::from(other.tokens))
            .cmp(&(u128::from(other.noid) * u128::from(self.tokens)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candle {
    pub open: Price,
    pub high: Price,
    pub low: Price,
    pub close: Price,
    pub trades: u16,
}

impl Candle {
    pub fn record(candle: &mut Option<Self>, price: Price) -> Result<(), String> {
        if !price.valid() {
            return Err("Invalid trade price.".into());
        }
        if let Some(candle) = candle {
            if price.cmp(candle.high).is_gt() {
                candle.high = price;
            }
            if price.cmp(candle.low).is_lt() {
                candle.low = price;
            }
            candle.close = price;
            candle.trades = candle
                .trades
                .checked_add(1)
                .ok_or("Too many trades in one candle.")?;
        } else {
            *candle = Some(Self {
                open: price,
                high: price,
                low: price,
                close: price,
                trades: 1,
            });
        }
        Ok(())
    }
    pub fn valid(&self) -> bool {
        self.trades > 0
            && self.trades <= 48
            && [self.open, self.high, self.low, self.close]
                .iter()
                .all(|p| p.valid())
            && self.low.cmp(self.high).is_le()
            && [self.open, self.close]
                .iter()
                .all(|p| p.cmp(self.low).is_ge() && p.cmp(self.high).is_le())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub timestamp: u64,
}

impl Header {
    pub fn valid(&self) -> bool {
        digest(&self.hash) && digest(&self.prev_hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub header: Header,
    pub candle: Option<Candle>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct History {
    pub schema: u8,
    pub chain: String,
    pub asset: String,
    pub through: Header,
    pub blocks: Vec<Block>,
}

impl History {
    pub fn validate(&self, chain: &str, asset: &str, maximum_height: u64) -> Result<(), String> {
        if self.schema != 1
            || self.chain != chain
            || self.asset != asset
            || !digest(chain)
            || !digest(asset)
            || !self.through.valid()
            || self.through.height > maximum_height
            || self.blocks.len() > MAX_BLOCKS
        {
            return Err("Invalid price history identity or size.".into());
        }
        let start = self.through.height.saturating_sub(MAX_BLOCKS as u64 - 1);
        let mut previous: Option<&Header> = None;
        for block in &self.blocks {
            let header = &block.header;
            if !header.valid()
                || header.height < start
                || header.height > self.through.height
                || block.candle.as_ref().is_some_and(|c| !c.valid())
                || previous.is_some_and(|p| {
                    p.height.checked_add(1) != Some(header.height) || p.hash != header.prev_hash
                })
            {
                return Err("Invalid price history sequence.".into());
            }
            previous = Some(header);
        }
        if previous.is_some_and(|last| last != &self.through) {
            return Err("Price history has a different endpoint.".into());
        }
        Ok(())
    }
}

pub fn block_trades(
    details: &serde_json::Value,
) -> Result<(Header, BTreeMap<String, Candle>), String> {
    let header: Header = serde_json::from_value(serde_json::json!({
        "height": details["header"]["height"], "hash": details["header"]["hash"],
        "prev_hash": details["header"]["prev_hash"], "timestamp": details["header"]["timestamp"],
    }))
    .map_err(|_| "Invalid market block header.")?;
    if !header.valid() {
        return Err("Invalid market block identity.".into());
    }
    let mut candles: BTreeMap<String, Candle> = BTreeMap::new();
    if let Some(transactions) = details["retained"]["transactions"].as_array() {
        if transactions.len() > 256 {
            return Err("Too many market transactions.".into());
        }
        let mut count = 0usize;
        for transaction in transactions {
            if let Some(trades) = transaction["trades"].as_array() {
                let mut previous = None;
                for item in trades {
                    count += 1;
                    if count > 48 {
                        return Err("Too many market fills.".into());
                    }
                    let asset = item["asset_id"]
                        .as_str()
                        .filter(|s| digest(s))
                        .ok_or("Invalid traded asset.")?;
                    let index = item["execution_index"]
                        .as_u64()
                        .ok_or("Invalid trade position.")?;
                    if previous.is_some_and(|p| p >= index) {
                        return Err("Invalid trade execution order.".into());
                    }
                    previous = Some(index);
                    let amount = |key: &str| {
                        item[key]
                            .as_str()
                            .and_then(|s| s.parse::<u64>().ok())
                            .filter(|n| *n > 0)
                            .ok_or("Invalid trade quantity.")
                    };
                    let spent = amount("spent_input_units")?;
                    let output = amount("output_units")?;
                    let price = match item["side"].as_str() {
                        Some("buy") => Price {
                            noid: spent,
                            tokens: output,
                        },
                        Some("sell") => Price {
                            noid: output,
                            tokens: spent,
                        },
                        _ => return Err("Invalid trade side.".into()),
                    };
                    let mut candle = candles.remove(asset);
                    Candle::record(&mut candle, price)?;
                    candles.insert(asset.to_owned(), candle.unwrap());
                }
            }
        }
    }
    Ok((header, candles))
}
