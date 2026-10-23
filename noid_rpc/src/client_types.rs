// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Address-based native plans for client-side authorization.

use crate::native_types::{NativePendingQuote, NativeWalletPreview, NativeWalletRequest};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeClientIntentKind {
    Operation,
    Trade,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeClientPlan {
    pub schema_version: u16,
    pub plan_id: String,
    pub intent_id: String,
    pub owner: String,
    pub candidate_height: u64,
    pub parent_header_hex: String,
    pub chain_id: String,
    pub epoch_anchor: String,
    pub owner_authorization_version: u8,
    pub intent_kind: NativeClientIntentKind,
    pub unsigned_intent_hex: String,
    pub review: NativeClientReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeClientReview {
    pub parent_hash: String,
    pub state_root: String,
    pub request: NativeWalletRequest,
    pub fee_micronoid: String,
    pub fee_limit_micronoid: Option<String>,
    pub noid_debit_micronoid: String,
    pub noid_credit_micronoid: String,
    pub reserve_deposit_micronoid: Option<String>,
    pub initial_buy_cost_micronoid: Option<String>,
    pub redemption_micronoid: Option<String>,
    pub quoted_output: Option<String>,
    pub minimum_output: Option<String>,
    pub valid_until: Option<u64>,
    pub asset_id: Option<String>,
    pub collection_id: Option<String>,
    pub serial: Option<String>,
    pub last_serial: Option<String>,
    pub input_count: usize,
    pub output_count: usize,
    pub pending_quote: Option<NativePendingQuote>,
}

impl From<NativeWalletPreview> for NativeClientReview {
    fn from(value: NativeWalletPreview) -> Self {
        Self {
            parent_hash: value.parent_hash,
            state_root: value.state_root,
            request: value.request,
            fee_micronoid: value.fee_micronoid,
            fee_limit_micronoid: value.fee_limit_micronoid,
            noid_debit_micronoid: value.noid_debit_micronoid,
            noid_credit_micronoid: value.noid_credit_micronoid,
            reserve_deposit_micronoid: value.reserve_deposit_micronoid,
            initial_buy_cost_micronoid: value.initial_buy_cost_micronoid,
            redemption_micronoid: value.redemption_micronoid,
            quoted_output: value.quoted_output,
            minimum_output: value.minimum_output,
            valid_until: value.valid_until,
            asset_id: value.asset_id,
            collection_id: value.collection_id,
            serial: value.serial,
            last_serial: value.last_serial,
            input_count: value.input_count,
            output_count: value.output_count,
            pending_quote: value.pending_quote,
        }
    }
}
