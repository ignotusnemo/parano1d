// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Admission of complete native operation envelopes at the current State tip.

use super::*;
use noid_chain::state::native_assets::native_chain_id;
use noid_tx::native_assets::{
    nft_market::NftRoundContext, transition::NativeOperation, wire::NativeIntent,
};

#[derive(Clone, Copy)]
enum NativeAuthorizationContext {
    Base(u64),
    Financial(NftRoundContext),
}

impl NativeAuthorizationContext {
    fn height(self) -> u64 {
        match self {
            Self::Base(height) => height,
            Self::Financial(round) => round.height(),
        }
    }
}

impl AsyncMempool {
    pub(super) async fn submit_native(
        &self,
        intent: NativeIntent,
        bytes: Vec<u8>,
    ) -> Result<TxBodyHash, SubmitError> {
        if bytes.len() > MAX_TX_INTENT_BYTES_GLOBAL {
            return Err(SubmitError::IntentTooLarge {
                actual: bytes.len(),
                max: MAX_TX_INTENT_BYTES_GLOBAL,
            });
        }
        let encoded = intent
            .to_bytes()
            .map_err(|error| SubmitError::MalformedIntent(error.to_string()))?;
        if encoded != bytes {
            return Err(SubmitError::MalformedIntent(
                "native envelope differs from retained bytes".into(),
            ));
        }
        drop(encoded);
        if intent.authorization_bytes.is_empty() {
            return Err(SubmitError::MissingProof);
        }
        if intent.authorization_bytes.len() > MAX_AUTHORIZATION_BYTES {
            return Err(SubmitError::ProofTooLarge {
                actual: intent.authorization_bytes.len(),
                max: MAX_AUTHORIZATION_BYTES,
            });
        }
        let id = intent
            .logical_txid()
            .map_err(|error| SubmitError::MalformedIntent(error.to_string()))?;
        let authorization = {
            let state = self.state.lock().await;
            check_native_limits(&intent, &state, &self.config, bytes.len(), id)?
        };
        let worker_intent = intent.clone();
        let executor = Arc::clone(&self.auth_verify_executor);
        let permit = Arc::clone(&self.auth_verify_semaphore)
            .acquire_owned()
            .await
            .map_err(|_| SubmitError::Internal("proof-verification semaphore closed".into()))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            executor(Box::new(move || {
                let bundle = noid_gkr::WalletAuthorizationBundle::from_bytes(
                    &worker_intent.authorization_bytes,
                )
                .map_err(|error| format!("authorization decode: {error}"))?;
                let version = noid_chain::consensus::params::owner_authorization_version(
                    authorization.height(),
                );
                match authorization {
                    NativeAuthorizationContext::Base(height) => {
                        noid_gkr::wallet_authorization::verify_native_asset_authorization(
                            &worker_intent,
                            native_chain_id(),
                            height,
                            &bundle,
                            version,
                        )
                    }
                    NativeAuthorizationContext::Financial(round) => {
                        noid_gkr::wallet_authorization::verify_native_financial_authorization(
                            &worker_intent,
                            native_chain_id(),
                            round,
                            &bundle,
                            version,
                        )
                    }
                }
                .map_err(|error| error.to_string())
            }))
        })
        .await
        .map_err(|error| SubmitError::Internal(format!("spawn_blocking: {error}")))?
        .map_err(SubmitError::InvalidProof)?;
        let mut state = self.state.lock().await;
        let current = check_native_limits(&intent, &state, &self.config, bytes.len(), id)?;
        if noid_chain::consensus::params::owner_authorization_version(current.height())
            != noid_chain::consensus::params::owner_authorization_version(authorization.height())
        {
            return Err(SubmitError::InvalidProof(
                "authorization version changed".into(),
            ));
        }
        let fee = intent.pages[0].body.fee;
        let tip = state.view.tip_height;
        let projected = state.pool.total_intent_bytes().saturating_add(bytes.len());
        match state.pool.admit_native(intent, tip) {
            Ok(()) => {}
            Err(noid_chain::mempool::MempoolError::Full) => {
                return Err(SubmitError::Full {
                    capacity: self.config.capacity,
                })
            }
            Err(noid_chain::mempool::MempoolError::AlreadyAdmitted) => {
                return Err(SubmitError::AlreadyAdmitted(id))
            }
            Err(error) => return Err(SubmitError::Internal(format!("{error:?}"))),
        }
        self.retain_admitted_intent(&mut state, id, fee, bytes, projected)
    }
}

fn check_native_limits(
    intent: &NativeIntent,
    state: &MempoolState,
    config: &MempoolConfig,
    bytes: usize,
    id: TxBodyHash,
) -> Result<NativeAuthorizationContext, SubmitError> {
    if state.pool.contains(&id) {
        return Err(SubmitError::AlreadyAdmitted(id));
    }
    let projected = state.pool.total_intent_bytes().saturating_add(bytes);
    if projected > config.max_total_intent_bytes {
        return Err(SubmitError::BytesFull {
            actual: projected,
            max: config.max_total_intent_bytes,
        });
    }
    let authorization = check_native_context(intent, &state.view, config)?;
    let facts = intent
        .validate_structure()
        .map_err(|error| SubmitError::MalformedIntent(error.to_string()))?;
    let minimum = fee_breakdown(
        facts.live_inputs as u64,
        facts.live_outputs as u64,
        state.view.active_slot_count,
        state.view.log_slots(),
    )
    .required_total;
    if matches!(authorization, NativeAuthorizationContext::Financial(_)) && facts.fee != minimum {
        return Err(SubmitError::MalformedIntent(
            "financial fee differs from the parent State requirement".into(),
        ));
    }
    let required = state.floor.current().max(minimum);
    if facts.fee < required {
        return Err(SubmitError::Consensus(
            noid_chain::consensus::ConsensusError::BelowMinFee {
                required,
                actual: facts.fee,
            },
        ));
    }
    if facts.epoch_anchor == [0; 32] || facts.epoch_anchor != state.view.user_epoch_anchor_id {
        return Err(SubmitError::Consensus(
            noid_chain::consensus::ConsensusError::BadEpochAnchor,
        ));
    }
    check_slot_conflicts_with_pool(
        &intent.pages,
        &state.admitted_input_slots,
        &state.admitted_output_slots,
    )?;
    for page in intent.pages.iter().skip(1) {
        for (_, input) in page.body.live_inputs() {
            let expected = SlotValue::with_owner_fields(
                input.amount,
                input.creation_id,
                page.body.input_owner.as_fields(),
            );
            if u64::from(input.slot_index) >= state.view.num_slots
                || state
                    .view
                    .try_slot(input.slot_index)
                    .map_err(|error| SubmitError::Internal(error.to_string()))?
                    != expected
            {
                return Err(SubmitError::Consensus(
                    noid_chain::consensus::ConsensusError::BadStateRoot,
                ));
            }
        }
    }
    check_output_slots(&intent.pages, &state.view)?;
    Ok(authorization)
}

fn check_native_context(
    intent: &NativeIntent,
    view: &ChainView,
    config: &MempoolConfig,
) -> Result<NativeAuthorizationContext, SubmitError> {
    let height = view
        .tip_height
        .checked_add(1)
        .ok_or_else(|| SubmitError::Internal("height exhausted".into()))?;
    if !noid_chain::consensus::params::v2_1_active(height) {
        return Err(SubmitError::MalformedIntent(
            "native operations are not active at the candidate height".into(),
        ));
    }
    let pages = intent
        .validate_structure()
        .map_err(|error| SubmitError::MalformedIntent(error.to_string()))?;
    let authorization = if let NativeOperation::Financial(operation) = pages.operation {
        if !matches!(operation.code(), 48 | 64 | 65 | 66) {
            return Err(SubmitError::MalformedIntent(
                "financial operation is outside the Owner admission profile".into(),
            ));
        }
        let parent = view
            .native_financial_parent()
            .map_err(|error| SubmitError::Internal(error.to_string()))?;
        let round = NftRoundContext::new(height, view.tip_hash, parent.alloc_counter)
            .map_err(|error| SubmitError::MalformedIntent(error.to_string()))?;
        intent
            .checked_financial_owner(native_chain_id(), round)
            .map_err(|error| SubmitError::MalformedIntent(error.to_string()))?;
        if let Some(reference) = operation.parent() {
            reference
                .check_boundary(parent.alloc_counter)
                .map_err(|error| SubmitError::MalformedIntent(error.to_string()))?;
            let opening = intent.opening(reference.root).ok_or_else(|| {
                SubmitError::MalformedIntent("financial parent opening is unavailable".into())
            })?;
            let expected = SlotValue::with_owner_fields(
                opening.amount_micronoid(),
                reference.creation_id,
                reference.root.as_fields(),
            );
            if u64::from(reference.slot_index) >= view.num_slots
                || view
                    .try_slot(reference.slot_index)
                    .map_err(|error| SubmitError::Internal(error.to_string()))?
                    != expected
            {
                return Err(SubmitError::Consensus(
                    noid_chain::consensus::ConsensusError::BadStateRoot,
                ));
            }
        }
        NativeAuthorizationContext::Financial(round)
    } else {
        intent
            .checked(native_chain_id(), height)
            .map_err(|error| SubmitError::MalformedIntent(error.to_string()))?;
        NativeAuthorizationContext::Base(height)
    };
    let resources = noid_chain::mempool::NativeResourceUsage::for_intent(intent)
        .map_err(|error| SubmitError::MalformedIntent(error.to_string()))?;
    config.check_native_resources(height, intent.pages.len(), pages.live_inputs, 0, resources)?;
    Ok(authorization)
}

pub(super) fn eviction_required(
    entry: &MempoolEntry,
    view: &ChainView,
    config: &MempoolConfig,
) -> bool {
    entry
        .native_intent()
        .is_some_and(|intent| check_native_context(&intent, view, config).is_err())
}
