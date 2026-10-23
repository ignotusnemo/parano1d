// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use serde::Deserialize;

use super::{
    live::Key,
    operations::{Preview, Request},
};
use crate::model::ReceiptFilter;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[default]
    Pending,
    Unconfirmed,
    Confirmed,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Pending {
    pub txid: String,
    pub owner: String,
    pub key_index: u32,
    pub parent_height: u64,
    pub input_count: usize,
    pub output_count: usize,
    #[serde(default)]
    pub status: Status,
    pub submitted_unix: Option<u64>,
    pub preview: Option<Preview>,
    pub confirmation_height: Option<u64>,
}

impl Pending {
    pub fn validate(&self) -> Result<(), String> {
        let mut id = [0; 32];
        if self.txid.len() != 64
            || hex::decode_to_slice(&self.txid, &mut id).is_err()
            || hex::encode(id) != self.txid
        {
            return Err("Invalid submission identity.".into());
        }
        let Some(preview) = &self.preview else {
            return if self.status == Status::Pending
                && self.confirmation_height.is_none()
                && self.submitted_unix.is_none()
            {
                Ok(())
            } else {
                Err("Submission details are unavailable.".into())
            };
        };
        let key = Key {
            owner: self.owner.clone(),
            key_index: self.key_index,
            height: self.parent_height,
            block_hash: preview.parent_hash.clone(),
            state_root: preview.state_root.clone(),
        };
        preview.validate(&key, &preview.request)?;
        if preview.txid != self.txid
            || preview.input_count != self.input_count
            || preview.output_count != self.output_count
            || self.submitted_unix.is_none()
            || match (self.status, self.confirmation_height) {
                (Status::Confirmed, Some(height)) => height < preview.height,
                (Status::Confirmed, None) | (_, Some(_)) => true,
                _ => false,
            }
        {
            return Err("Submission details do not match its status.".into());
        }
        Ok(())
    }

    pub fn includes(&self, filter: ReceiptFilter) -> bool {
        if filter == ReceiptFilter::All {
            return true;
        }
        let Some(preview) = &self.preview else {
            return false;
        };
        match &preview.request {
            Request::Trade { .. } => filter == ReceiptFilter::Trades,
            Request::TransferToken { .. }
            | Request::BurnToken { .. }
            | Request::CreateToken { .. } => filter == ReceiptFilter::Tokens,
            _ => filter == ReceiptFilter::Nfts,
        }
    }

    pub fn title(&self) -> &'static str {
        self.preview
            .as_ref()
            .map(|p| p.request.title())
            .unwrap_or("NATIVE OPERATION")
    }

    pub fn includes_query(&self, query: &crate::model::receipt_query::Query) -> bool {
        use crate::model::receipt_query::{Operation, Verification};
        if self.status == Status::Confirmed
            || !self.includes(query.filter)
            || query.verification != Verification::Any
        {
            return false;
        }
        let Some(preview) = &self.preview else {
            return query.is_default();
        };
        let (operation, asset) = match &preview.request {
            Request::CreateToken { .. } => (Operation::CreateToken, None),
            Request::TransferToken { asset_id, .. } => {
                (Operation::TransferToken, Some(asset_id.as_str()))
            }
            Request::BurnToken { asset_id, .. } => (Operation::BurnToken, Some(asset_id.as_str())),
            Request::Trade { asset_id, .. } => (Operation::Trade, Some(asset_id.as_str())),
            Request::CreateCollection { .. } => (Operation::CreateNft, None),
            Request::MintNft { collection_id, .. } | Request::MintNfts { collection_id, .. } => {
                (Operation::CreateNft, Some(collection_id.as_str()))
            }
            Request::TransferNft { collection_id, .. } => {
                (Operation::TransferNft, Some(collection_id.as_str()))
            }
            Request::BurnNft { collection_id, .. } => {
                (Operation::BurnNft, Some(collection_id.as_str()))
            }
            Request::ListNft { collection_id, .. } => {
                (Operation::ListNft, Some(collection_id.as_str()))
            }
            Request::BuyNft { collection_id, .. } => {
                (Operation::BuyNft, Some(collection_id.as_str()))
            }
            Request::CancelListing { collection_id, .. } => {
                (Operation::CancelListing, Some(collection_id.as_str()))
            }
        };
        if query.operation != Operation::Any && query.operation != operation {
            return false;
        }
        if query
            .asset_id
            .as_deref()
            .is_some_and(|expected| asset != Some(expected))
        {
            return false;
        }
        if query.timestamp_from.is_some() || query.timestamp_before.is_some() {
            let Some(time) = self.submitted_unix else {
                return false;
            };
            if query.timestamp_from.is_some_and(|start| time < start)
                || query.timestamp_before.is_some_and(|end| time >= end)
            {
                return false;
            }
        }
        true
    }
}

pub fn validate(records: Vec<Pending>) -> Result<Vec<Pending>, String> {
    if records.len() > 4096 {
        return Err("Too many recent submissions.".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for record in &records {
        record.validate()?;
        if !seen.insert(&record.txid) {
            return Err("Duplicate recent submission.".into());
        }
    }
    Ok(records)
}
