// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Owner-verified native trade groups and their exact State payouts.

use std::collections::BTreeMap;

use noid_chain::{
    state::native_assets::{
        trade::{
            apply_prepared_trade_batch, prepare_trade_batch_at_log_slots,
            prepare_trade_batch_from_intent, PreparedTradeBatch, TradeOutputSlots, TradeStateError,
        },
        NativeStateTransition,
    },
    ChainState,
};
use noid_gkr::wallet_authorization::{
    verify_native_trade_authorization, WalletAuthorizationBundle,
};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_tx::{
    native_assets::trade::{batch::TradeBatch, sequencing::TradeBoundary},
    OwnerAuthorizationVersion,
};

#[derive(Debug, Clone)]
pub struct TradeAuthorization {
    pub authorization_id: TxBodyHash,
    pub bundle: WalletAuthorizationBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TradePreparationError {
    State(TradeStateError),
    AuthorizationSet,
    Authorization,
}

impl core::fmt::Display for TradePreparationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "trade preparation: {self:?}")
    }
}
impl std::error::Error for TradePreparationError {}
impl From<TradeStateError> for TradePreparationError {
    fn from(value: TradeStateError) -> Self {
        Self::State(value)
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizedTradeBatch {
    batch: TradeBatch,
    prepared: PreparedTradeBatch,
    authorizations: Vec<TradeAuthorization>,
}

impl AuthorizedTradeBatch {
    pub fn batch(&self) -> &TradeBatch {
        &self.batch
    }
    pub fn prepared(&self) -> &PreparedTradeBatch {
        &self.prepared
    }
    /// Owner capsules follow the canonical policy order of the committed batch.
    pub fn authorizations(&self) -> &[TradeAuthorization] {
        &self.authorizations
    }
    pub fn apply(
        &self,
        state: &mut ChainState,
    ) -> Result<NativeStateTransition, TradePreparationError> {
        apply_prepared_trade_batch(state, &self.prepared).map_err(Into::into)
    }
}

pub fn prepare_authorized_trade_batch(
    parent_state: &ChainState,
    boundary: TradeBoundary,
    batch: TradeBatch,
    authorizations: Vec<TradeAuthorization>,
    slots: &TradeOutputSlots,
) -> Result<AuthorizedTradeBatch, TradePreparationError> {
    prepare_authorized_trade_batch_at_log_slots(
        parent_state,
        boundary,
        parent_state.state.log_slots() as u32,
        batch,
        authorizations,
        slots,
    )
}

pub fn prepare_authorized_trade_batch_at_log_slots(
    parent_state: &ChainState,
    boundary: TradeBoundary,
    child_log_slots: u32,
    batch: TradeBatch,
    authorizations: Vec<TradeAuthorization>,
    slots: &TradeOutputSlots,
) -> Result<AuthorizedTradeBatch, TradePreparationError> {
    let prepared =
        prepare_trade_batch_at_log_slots(parent_state, boundary, child_log_slots, &batch, slots)?;
    verify_authorizations(batch, prepared, authorizations)
}

pub fn prepare_authorized_trade_intent(
    parent_state: &ChainState,
    boundary: TradeBoundary,
    child_log_slots: u32,
    batch: TradeBatch,
    intent: &noid_tx::native_assets::wire::NativeIntent,
    authorizations: Vec<TradeAuthorization>,
) -> Result<AuthorizedTradeBatch, TradePreparationError> {
    let prepared =
        prepare_trade_batch_from_intent(parent_state, boundary, child_log_slots, &batch, intent)?;
    verify_authorizations(batch, prepared, authorizations)
}

fn verify_authorizations(
    batch: TradeBatch,
    prepared: PreparedTradeBatch,
    authorizations: Vec<TradeAuthorization>,
) -> Result<AuthorizedTradeBatch, TradePreparationError> {
    let boundary = prepared.boundary();
    if authorizations.len() != batch.policies().len() {
        return Err(TradePreparationError::AuthorizationSet);
    }
    let mut keyed = BTreeMap::new();
    for authorization in authorizations {
        if keyed
            .insert(authorization.authorization_id.0, authorization)
            .is_some()
        {
            return Err(TradePreparationError::AuthorizationSet);
        }
    }
    let mut authorizations = Vec::with_capacity(batch.policies().len());
    for intent in batch.policies() {
        let id = intent
            .authorization_id()
            .map_err(|_| TradePreparationError::AuthorizationSet)?;
        let authorization = keyed
            .remove(&id.0)
            .ok_or(TradePreparationError::AuthorizationSet)?;
        verify_native_trade_authorization(
            intent,
            boundary.chain,
            boundary.epoch_anchor,
            boundary.height,
            &authorization.bundle,
            OwnerAuthorizationVersion::V4,
        )
        .map_err(|_| TradePreparationError::Authorization)?;
        authorizations.push(authorization);
    }
    Ok(AuthorizedTradeBatch {
        batch,
        prepared,
        authorizations,
    })
}
