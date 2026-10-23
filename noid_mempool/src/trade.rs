// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Admission and retention of independently authorized funded trade policies.

use super::*;
use noid_chain::mempool::trade_policy_resources;
use noid_tx::native_assets::trade::{wire::TradeOwnerIntent, TradeIntent};

impl AsyncMempool {
    pub(super) async fn submit_trade(
        &self,
        envelope: TradeOwnerIntent,
        bytes: Vec<u8>,
    ) -> Result<TxBodyHash, SubmitError> {
        if bytes.len() > MAX_TX_INTENT_BYTES_GLOBAL {
            return Err(SubmitError::IntentTooLarge {
                actual: bytes.len(),
                max: MAX_TX_INTENT_BYTES_GLOBAL,
            });
        }
        if envelope.to_bytes().map_err(malformed)? != bytes {
            return Err(SubmitError::MalformedIntent(
                "trade envelope differs from retained bytes".into(),
            ));
        }
        if envelope.authorization_bytes.is_empty() {
            return Err(SubmitError::MissingProof);
        }
        if envelope.authorization_bytes.len() > MAX_AUTHORIZATION_BYTES {
            return Err(SubmitError::ProofTooLarge {
                actual: envelope.authorization_bytes.len(),
                max: MAX_AUTHORIZATION_BYTES,
            });
        }
        let id = envelope.intent.authorization_id().map_err(malformed)?;
        let (height, epoch) = {
            let state = self.state.lock().await;
            check_limits(&envelope.intent, &state, &self.config, bytes.len(), id)?
        };
        let intent = envelope.intent.clone();
        let authorization = envelope.authorization_bytes.clone();
        let executor = Arc::clone(&self.auth_verify_executor);
        let permit = Arc::clone(&self.auth_verify_semaphore)
            .acquire_owned()
            .await
            .map_err(|_| SubmitError::Internal("proof-verification semaphore closed".into()))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            executor(Box::new(move || {
                let bundle = noid_gkr::WalletAuthorizationBundle::from_bytes(&authorization)
                    .map_err(|error| error.to_string())?;
                noid_gkr::wallet_authorization::verify_native_trade_authorization(
                    &intent,
                    noid_chain::state::native_assets::native_chain_id(),
                    epoch,
                    height,
                    &bundle,
                    noid_tx::OwnerAuthorizationVersion::V4,
                )
                .map_err(|error| error.to_string())
            }))
        })
        .await
        .map_err(|error| SubmitError::Internal(format!("spawn_blocking: {error}")))?
        .map_err(SubmitError::InvalidProof)?;
        let mut state = self.state.lock().await;
        check_limits(&envelope.intent, &state, &self.config, bytes.len(), id)?;
        let tip = state.view.tip_height;
        let projected = state.pool.total_intent_bytes().saturating_add(bytes.len());
        match state.pool.admit_trade(envelope, tip) {
            Ok(()) => {}
            Err(noid_chain::mempool::MempoolError::Full) => {
                return Err(SubmitError::Full {
                    capacity: self.config.capacity,
                });
            }
            Err(noid_chain::mempool::MempoolError::AlreadyAdmitted) => {
                return Err(SubmitError::AlreadyAdmitted(id));
            }
            Err(error) => return Err(SubmitError::Internal(format!("{error:?}"))),
        }
        self.retain_admitted_intent(&mut state, id, 0, bytes, projected)
    }
}

fn malformed(error: impl core::fmt::Display) -> SubmitError {
    SubmitError::MalformedIntent(error.to_string())
}

fn check_context(
    intent: &TradeIntent,
    view: &ChainView,
    config: &MempoolConfig,
) -> Result<(u64, [u8; 32]), SubmitError> {
    let height = view
        .tip_height
        .checked_add(1)
        .ok_or_else(|| SubmitError::Internal("height exhausted".into()))?;
    if !noid_chain::consensus::params::v2_1_active(height) {
        return Err(SubmitError::MalformedIntent(
            "native trading is not active at the candidate height".into(),
        ));
    }
    let parent = view
        .native_financial_parent()
        .map_err(|error| SubmitError::Internal(error.to_string()))?;
    intent
        .checked(
            noid_chain::state::native_assets::native_chain_id(),
            view.user_epoch_anchor_id,
            height,
        )
        .map_err(malformed)?;
    let (pages, resources) = trade_policy_resources(intent).map_err(malformed)?;
    config.check_native_resources(height, pages, intent.funding.len() + 1, 0, resources)?;
    let minimum = fee_breakdown(
        intent.funding.len() as u64 + 1,
        2,
        view.active_slot_count,
        view.log_slots(),
    )
    .required_total;
    if intent.policy.fee_limit < minimum {
        return Err(SubmitError::Consensus(
            noid_chain::consensus::ConsensusError::BelowMinFee {
                required: minimum,
                actual: intent.policy.fee_limit,
            },
        ));
    }
    for claim in &intent.funding {
        let input = claim.input;
        let expected =
            SlotValue::with_owner_fields(input.amount, input.creation_id, claim.root.as_fields());
        if u64::from(input.slot_index) >= view.num_slots
            || !noid_chain::consensus::params::creation_id_within_boundary(
                input.creation_id,
                parent.alloc_counter,
                parent.height,
            )
            || view
                .try_slot(input.slot_index)
                .map_err(|error| SubmitError::Internal(error.to_string()))?
                != expected
        {
            return Err(SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::BadStateRoot,
            ));
        }
    }
    Ok((height, view.user_epoch_anchor_id))
}

fn check_limits(
    intent: &TradeIntent,
    state: &MempoolState,
    config: &MempoolConfig,
    bytes: usize,
    id: TxBodyHash,
) -> Result<(u64, [u8; 32]), SubmitError> {
    if state.pool.contains(&id) {
        return Err(SubmitError::AlreadyAdmitted(id));
    }
    if state.pool.len() >= config.capacity {
        return Err(SubmitError::Full {
            capacity: config.capacity,
        });
    }
    let projected = state.pool.total_intent_bytes().saturating_add(bytes);
    if projected > config.max_total_intent_bytes {
        return Err(SubmitError::BytesFull {
            actual: projected,
            max: config.max_total_intent_bytes,
        });
    }
    let context = check_context(intent, &state.view, config)?;
    // The ceiling is authorized; the exact protocol charge follows the final payouts.
    if intent.policy.fee_limit < state.floor.current() {
        return Err(SubmitError::Consensus(
            noid_chain::consensus::ConsensusError::BelowMinFee {
                required: state.floor.current(),
                actual: intent.policy.fee_limit,
            },
        ));
    }
    if intent.funding.iter().any(|claim| {
        state.admitted_input_slots.contains(&claim.input.slot_index)
            || state
                .admitted_output_slots
                .contains(&claim.input.slot_index)
    }) {
        return Err(SubmitError::Consensus(
            noid_chain::consensus::ConsensusError::SlotConflict,
        ));
    }
    Ok(context)
}

pub(super) fn eviction_reason(
    intent: &TradeIntent,
    view: &ChainView,
    config: &MempoolConfig,
) -> Option<EvictReason> {
    if intent.policy.epoch_anchor != view.user_epoch_anchor_id {
        return Some(EvictReason::EpochAnchorChanged);
    }
    if view
        .tip_height
        .checked_add(1)
        .is_some_and(|height| height > intent.policy.valid_until)
    {
        return Some(EvictReason::TradePolicyExpired);
    }
    match check_context(intent, view, config) {
        Ok(_) => None,
        Err(SubmitError::Consensus(noid_chain::consensus::ConsensusError::BadStateRoot)) => {
            Some(EvictReason::InputConsumed)
        }
        Err(SubmitError::Consensus(noid_chain::consensus::ConsensusError::BelowMinFee {
            ..
        })) => Some(EvictReason::ConsensusFeeIncreased),
        Err(
            SubmitError::V2LimitsUnavailable
            | SubmitError::NoProofClass { .. }
            | SubmitError::InputLimitExceeded { .. },
        ) => Some(EvictReason::BlockCapacityChanged),
        Err(_) => Some(EvictReason::NativeContextChanged),
    }
}
