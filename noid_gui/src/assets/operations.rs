// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::live::Key;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
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

impl Request {
    pub fn title(&self) -> &'static str {
        match self {
            Self::TransferToken { .. } => "SEND TOKENS",
            Self::BurnToken { .. } => "BURN & REDEEM",
            Self::Trade { buy: true, .. } => "BUY TOKENS",
            Self::Trade { buy: false, .. } => "SELL TOKENS",
            Self::CreateToken { .. } => "CREATE TOKEN",
            Self::CreateCollection { maximum_items, .. } if maximum_items == "1" => "PREPARE NFT",
            Self::CreateCollection { .. } => "CREATE COLLECTION",
            Self::MintNft { .. } => "MINT NFT",
            Self::MintNfts { .. } => "MINT NFTS",
            Self::TransferNft { .. } => "SEND NFT",
            Self::BurnNft { .. } => "BURN NFT",
            Self::ListNft { .. } => "LIST NFT",
            Self::BuyNft { .. } => "BUY NFT",
            Self::CancelListing { .. } => "CANCEL LISTING",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingQuote {
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
pub struct Preview {
    pub plan_id: String,
    pub txid: String,
    pub owner: String,
    pub key_index: u32,
    pub height: u64,
    pub parent_hash: String,
    pub state_root: String,
    pub request: Request,
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
    pub pending_quote: Option<PendingQuote>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Submission {
    pub txid: String,
    pub plan_id: String,
    pub fee_micronoid: String,
    pub fee_limit_micronoid: Option<String>,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn integer(value: &str) -> Result<u128, String> {
    if value.is_empty()
        || value.len() > 39
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("The node returned an invalid native amount.".into());
    }
    value
        .parse()
        .map_err(|_| "The native amount exceeds its limit.".into())
}

pub fn parse_amount(value: &str) -> Result<String, String> {
    parse_amount_inner(value, false)
}

pub fn parse_optional_amount(value: &str) -> Result<Option<String>, String> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    let units = parse_amount_inner(value, true)?;
    Ok((units != "0").then_some(units))
}

fn parse_amount_inner(value: &str, allow_zero: bool) -> Result<String, String> {
    let value = value.trim();
    if value.len() > 27 {
        return Err("Amount is too large.".into());
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 6
    {
        return Err("Enter a positive amount with up to six decimal places.".into());
    }
    let whole = whole.parse::<u64>().map_err(|_| "Amount is too large.")?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u64>().map_err(|_| "Invalid amount.")?
            * 10u64.pow((6 - fraction.len()) as u32)
    };
    let units = whole
        .checked_mul(1_000_000)
        .and_then(|n| n.checked_add(fraction))
        .ok_or("Amount is too large.")?;
    if units == 0 && !allow_zero {
        return Err("Amount must be at least 0.000001.".into());
    }
    Ok(units.to_string())
}

impl Preview {
    pub fn validate(&self, key: &Key, request: &Request) -> Result<(), String> {
        if self.owner != key.owner
            || self.key_index != key.key_index
            || Some(self.height) != key.height.checked_add(1)
            || self.parent_hash != key.block_hash
            || self.state_root != key.state_root
            || &self.request != request
        {
            return Err("The address, State or operation changed. Review it again.".into());
        }
        if !digest(&self.plan_id)
            || !digest(&self.txid)
            || self.asset_id.as_deref().is_some_and(|id| !digest(id))
            || self.collection_id.as_deref().is_some_and(|id| !digest(id))
            || self.input_count == 0
            || self.input_count > 504
            || self.output_count > 504
        {
            return Err("The node returned an invalid native operation.".into());
        }
        for value in [
            Some(&self.fee_micronoid),
            self.fee_limit_micronoid.as_ref(),
            Some(&self.noid_debit_micronoid),
            Some(&self.noid_credit_micronoid),
            self.reserve_deposit_micronoid.as_ref(),
            self.initial_buy_cost_micronoid.as_ref(),
            self.redemption_micronoid.as_ref(),
            self.quoted_output.as_ref(),
            self.minimum_output.as_ref(),
            self.serial.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            integer(value)?;
        }
        match request {
            Request::CreateToken {
                whole_tokens,
                initial_buy_units,
                ..
            } => {
                let whole = whole_tokens
                    .parse::<u64>()
                    .map_err(|_| "Invalid token supply.")?;
                let supply = noid_tx::native_assets::launch::launch_supply_from_whole(whole)
                    .map_err(|e| e.to_string())?;
                let units = initial_buy_units
                    .as_deref()
                    .map(integer)
                    .transpose()?
                    .unwrap_or(0);
                let units =
                    u64::try_from(units).map_err(|_| "Initial purchase exceeds its limit.")?;
                let cost = noid_tx::native_assets::launch::curve_cash_for_supply(supply, units)
                    .map_err(|e| e.to_string())?;
                let reported_cost = self
                    .initial_buy_cost_micronoid
                    .as_deref()
                    .map(integer)
                    .transpose()?
                    .unwrap_or(0);
                let reserve = u128::from(supply / 1000);
                let debit = reserve
                    .checked_add(u128::from(cost))
                    .and_then(|n| n.checked_add(integer(&self.fee_micronoid).ok()?))
                    .ok_or("Launch cost exceeds its limit.")?;
                if self.asset_id.is_none()
                    || reported_cost != u128::from(cost)
                    || self
                        .reserve_deposit_micronoid
                        .as_deref()
                        .map(integer)
                        .transpose()?
                        != Some(reserve)
                    || integer(&self.noid_debit_micronoid)? != debit
                    || integer(&self.noid_credit_micronoid)? != 0
                    || self
                        .quoted_output
                        .as_deref()
                        .map(integer)
                        .transpose()?
                        .unwrap_or(0)
                        != u128::from(units)
                {
                    return Err(
                        "The launch funding or initial purchase differs from the reviewed terms."
                            .into(),
                    );
                }
            }
            Request::CreateCollection { .. } if self.collection_id.is_none() => {
                return Err("The prepared collection identity is missing.".into());
            }
            Request::MintNft { collection_id, .. } => {
                if self.collection_id.as_ref() != Some(collection_id)
                    || self
                        .serial
                        .as_ref()
                        .is_none_or(|serial| !integer(serial).is_ok_and(|serial| serial > 0))
                {
                    return Err("The NFT identity differs from the requested collection.".into());
                }
            }
            Request::MintNfts {
                collection_id,
                metadata_hashes,
            } => {
                let first = self.serial.as_deref().map(integer).transpose()?;
                let last = self.last_serial.as_deref().map(integer).transpose()?;
                if self.collection_id.as_ref() != Some(collection_id)
                    || metadata_hashes.is_empty()
                    || metadata_hashes.len() > noid_tx::MAX_PAGED_SPEND_OUTPUTS.saturating_sub(2)
                    || metadata_hashes.iter().any(|hash| !digest(hash))
                    || !matches!((first, last), (Some(first), Some(last)) if first > 0
                        && last <= u128::from(u64::MAX)
                        && first.checked_add(metadata_hashes.len() as u128 - 1) == Some(last))
                    || !(metadata_hashes.len() + 1..=metadata_hashes.len() + 2)
                        .contains(&self.output_count)
                {
                    return Err(
                        "The NFT batch differs from the reviewed collection or serial range."
                            .into(),
                    );
                }
            }
            _ => {}
        }
        if let Some(pending) = &self.pending_quote {
            if !matches!(request, Request::Trade { .. })
                || pending.selected_policies > noid_tx::MAX_PAGED_SPEND_INPUTS
                || pending.selected_markets > pending.selected_policies
                || pending.selected_policies > pending.pending_policies.saturating_add(1)
                || pending
                    .position
                    .is_some_and(|position| position >= pending.selected_policies)
                || pending.position.is_some() != pending.output.is_some()
                || pending.output.is_some() != pending.spent_input.is_some()
                || pending.output.is_some() != pending.market_fee.is_some()
                || pending.output.is_some() != pending.network_fee.is_some()
            {
                return Err("The node returned an invalid pending-trade estimate.".into());
            }
            for number in [
                pending.output.as_ref(),
                pending.spent_input.as_ref(),
                pending.market_fee.as_ref(),
                pending.network_fee.as_ref(),
                pending.confirmed_output.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                integer(number)?;
            }
            if pending
                .output
                .as_ref()
                .is_some_and(|output| self.quoted_output.as_ref() != Some(output))
                || pending
                    .network_fee
                    .as_ref()
                    .is_some_and(|fee| &self.fee_micronoid != fee)
            {
                return Err("The pending estimate differs from the reviewed outcome.".into());
            }
            if let Request::Trade {
                gross_input,
                minimum_output,
                buy,
                ..
            } = request
            {
                let minimum = self
                    .minimum_output
                    .as_deref()
                    .ok_or_else(|| "The trade minimum is missing.".to_owned())
                    .and_then(integer)?;
                let output = self
                    .quoted_output
                    .as_deref()
                    .ok_or_else(|| "The trade estimate is missing.".to_owned())
                    .and_then(integer)?;
                let fee = integer(&self.fee_micronoid)?;
                let limit = self
                    .fee_limit_micronoid
                    .as_deref()
                    .ok_or_else(|| "The trade fee limit is missing.".to_owned())
                    .and_then(integer)?;
                if minimum == 0
                    || output < minimum
                    || fee > limit
                    || minimum_output
                        .as_ref()
                        .is_some_and(|requested| self.minimum_output.as_ref() != Some(requested))
                {
                    return Err("The estimate exceeds the authorized trade bounds.".into());
                }
                if let Some(spent) = &pending.spent_input {
                    let spent = integer(spent)?;
                    if spent == 0
                        || spent > integer(gross_input)?
                        || pending.market_fee.as_ref().is_some_and(|market_fee| {
                            integer(market_fee).is_ok_and(|fee| fee > spent)
                        })
                    {
                        return Err("The estimate exceeds the authorized input.".into());
                    }
                    let debit = if *buy {
                        spent.checked_add(fee).ok_or("Trade debit overflow.")?
                    } else {
                        fee.saturating_sub(output)
                    };
                    let credit = if *buy { 0 } else { output.saturating_sub(fee) };
                    if integer(&self.noid_debit_micronoid)? != debit
                        || integer(&self.noid_credit_micronoid)? != credit
                    {
                        return Err("The estimated NOID effect differs from the trade.".into());
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Idle,
    Previewing,
    Ready,
    Submitting,
    Submitted,
}

#[derive(Debug, Default)]
pub struct State {
    pub generation: u64,
    pub phase: Phase,
    pub context: Option<Key>,
    pub request: Option<Request>,
    pub preview: Option<Preview>,
    pub submission: Option<Submission>,
    pub error: Option<String>,
}

impl State {
    pub fn submitting(&self) -> bool {
        self.phase == Phase::Submitting
    }

    pub fn edit(&mut self) {
        if self.submitting() {
            return;
        }
        *self = Self {
            generation: self.generation.wrapping_add(1),
            ..Self::default()
        };
    }

    pub fn observe(&mut self, key: &Key) {
        if self.context.as_ref().is_some_and(|old| old != key) && !self.submitting() {
            if self.phase == Phase::Submitted
                && self
                    .context
                    .as_ref()
                    .is_some_and(|old| old.owner == key.owner && old.key_index == key.key_index)
            {
                return;
            }
            let reviewed = self.preview.is_some();
            self.edit();
            if reviewed {
                self.error = Some("State changed. Review the updated operation.".into());
            }
        }
    }

    pub fn begin_preview(&mut self, key: Key, request: Request) -> Result<u64, String> {
        if self.submitting() {
            return Err("An operation is already being submitted.".into());
        }
        self.edit();
        self.context = Some(key);
        self.request = Some(request);
        self.phase = Phase::Previewing;
        Ok(self.generation)
    }

    pub fn finish_preview(&mut self, generation: u64, result: Result<Preview, String>) {
        if self.generation != generation || self.phase != Phase::Previewing {
            return;
        }
        self.phase = Phase::Idle;
        let result = result.and_then(|preview| {
            preview.validate(
                self.context
                    .as_ref()
                    .ok_or("Wallet context is unavailable.")?,
                self.request
                    .as_ref()
                    .ok_or("The operation is unavailable.")?,
            )?;
            Ok(preview)
        });
        match result {
            Ok(preview) => {
                self.preview = Some(preview);
                self.phase = Phase::Ready;
            }
            Err(error) => self.error = Some(error),
        }
    }

    pub fn begin_submit(&mut self, key: &Key, request: &Request) -> Result<(u64, Preview), String> {
        if self.phase != Phase::Ready {
            return Err("Review the operation before confirming.".into());
        }
        let preview = self.preview.as_ref().ok_or("Review the operation again.")?;
        preview.validate(key, request)?;
        self.phase = Phase::Submitting;
        self.error = None;
        Ok((self.generation, preview.clone()))
    }

    pub fn finish_submit(&mut self, generation: u64, result: Result<Submission, String>) {
        if self.generation != generation || !self.submitting() {
            return;
        }
        self.phase = Phase::Idle;
        let result = result.and_then(|submission| {
            let preview = self.preview.as_ref().ok_or("The reviewed operation is unavailable.")?;
            if submission.plan_id != preview.plan_id || submission.txid != preview.txid
                || submission.fee_micronoid != preview.fee_micronoid
                || submission.fee_limit_micronoid != preview.fee_limit_micronoid
            { return Err("The submission response differs from the reviewed operation. Check activity before retrying.".into()); }
            Ok(submission)
        });
        match result {
            Ok(submission) => {
                self.submission = Some(submission);
                self.phase = Phase::Submitted;
            }
            Err(error) => {
                self.preview = None;
                self.error = Some(error);
            }
        }
    }
}
