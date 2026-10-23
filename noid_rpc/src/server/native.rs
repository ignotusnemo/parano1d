// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::native_types::*;
use noid_chain::storage::{NativeWalletCursor as StoreCursor, NativeWalletQueryError};
use noid_poseidon2b::primitives::Address;
use std::collections::HashSet;

mod client;
mod discovery;
mod planner;
pub(super) use client::prepare as prepare_client;
pub(super) use discovery::{catalog, market};

pub(super) struct ReviewedOperation {
    prepared: planner::Prepared,
}

async fn reconcile_pending(handler: &RpcHandler) -> RpcResult<()> {
    for pending in handler.wallet.native_pending_submissions() {
        if handler
            .mempool
            .get_entry_metadata(&noid_poseidon2b::primitives::TxBodyHash(pending.txid))
            .await
            .is_none()
        {
            handler
                .wallet
                .rollback_native_submission(pending.txid, pending.lease);
        }
    }
    let records = handler.wallet.native_activity().map_err(rpc_err)?;
    let chain = handler.chain.read().await;
    for record in records {
        if record.preview.height <= chain.finalized.height {
            let id = digest(&record.preview.txid)?;
            if canonical_submission_height(handler, &chain, id)?
                .is_some_and(|height| height <= chain.finalized.height)
            {
                handler.wallet.forget_native_activity(id).map_err(rpc_err)?;
            }
        }
    }
    Ok(())
}

async fn prepare(
    handler: &RpcHandler,
    request: NativeWalletRequest,
) -> RpcResult<planner::Prepared> {
    if !matches!(request, NativeWalletRequest::Trade { .. }) {
        return prepare_current_native(handler, request).await;
    }
    reconcile_pending(handler).await?;
    handler.reload_active_wallet().await?;
    let (key_index, address) = handler
        .wallet
        .active_address()
        .ok_or_else(|| rpc_err("wallet unavailable"))?;
    let owner = parse_address_param(&address)?;
    let mut reserved = handler.mempool.reserved_slots().await;
    reserved.0.extend(reserved.1);
    let floor = handler.mempool.fee_floor().await;
    let budget = handler
        .history_step_runtime
        .as_deref()
        .and_then(|runtime| runtime.v21_native_admission_budget())
        .ok_or_else(|| rpc_err("native runtime unavailable"))?;
    let utxos = handler.wallet.list_utxos();
    let snapshot = if matches!(request, NativeWalletRequest::Trade { .. }) {
        let mut chain = handler.chain.write().await;
        Some(
            noid_miner::template::TemplateChainSnapshot::from_context(&mut chain)
                .map_err(|e| rpc_err(e.to_string()))?,
        )
    } else {
        None
    };
    let pending = if let Some(snapshot) = &snapshot {
        Some(
            handler
                .mempool
                .trade_mining_snapshot(
                    snapshot.parent.height,
                    noid_chain::block_id(&snapshot.parent),
                    noid_chain::block_id(&snapshot.child_tx_epoch_anchor_header),
                )
                .await
                .map_err(|e| rpc_err(e.to_string()))?,
        )
    } else {
        None
    };
    let chain = Arc::clone(&handler.chain).read_owned().await;
    tokio::task::spawn_blocking(move || {
        if let (Some(snapshot), Some(pending)) = (&snapshot, &pending) {
            if chain.tip_header() != &snapshot.parent {
                return Err("native quote State changed; refresh the operation".into());
            }
            let project = |trade: &noid_tx::native_assets::trade::TradeIntent| {
                noid_miner::template::project_trade(snapshot, pending, trade, budget)
            };
            planner::prepare_with_projection(
                &chain,
                key_index,
                owner,
                request,
                utxos,
                reserved.0,
                floor,
                budget,
                Some(&project),
            )
        } else {
            planner::prepare(
                &chain, key_index, owner, request, utxos, reserved.0, floor, budget,
            )
        }
    })
    .await
    .map_err(|_| rpc_err("native wallet planning task failed"))?
    .map_err(rpc_err)
}

async fn prepare_current_native(
    handler: &RpcHandler,
    request: NativeWalletRequest,
) -> RpcResult<planner::Prepared> {
    reconcile_pending(handler).await?;
    let budget = handler
        .history_step_runtime
        .as_deref()
        .and_then(|runtime| runtime.v21_native_admission_budget())
        .ok_or_else(|| rpc_err("native runtime unavailable"))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let (chain, mut reservations) = loop {
        let chain = Arc::clone(&handler.chain).read_owned().await;
        if let Some(reservations) = handler
            .mempool
            .reservation_snapshot_at(chain.tip_height(), chain.tip_hash())
            .await
        {
            break (chain, reservations);
        }
        drop(chain);
        if Instant::now() >= deadline {
            return Err(rpc_err(
                "wait for the node to finish applying its current block",
            ));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let activation = handler.wallet.preview_active_reload().map_err(rpc_err)?;
    let snapshot = chain
        .store
        .get_verified_utxos_by_owner(&activation.owner)
        .map_err(|error| rpc_err(error.to_string()))?;
    handler
        .wallet
        .commit_activation_snapshot(
            activation,
            snapshot,
            &reservations.input_slots,
            &reservations.output_slots,
        )
        .map_err(rpc_err)?;
    let (key_index, address) = handler
        .wallet
        .active_address()
        .ok_or_else(|| rpc_err("wallet unavailable"))?;
    let owner = parse_address_param(&address)?;
    let utxos = handler.wallet.list_utxos();
    reservations.input_slots.extend(reservations.output_slots);
    tokio::task::spawn_blocking(move || {
        planner::prepare(
            &chain,
            key_index,
            owner,
            request,
            utxos,
            reservations.input_slots,
            reservations.fee_floor,
            budget,
        )
    })
    .await
    .map_err(|_| rpc_err("native wallet planning task failed"))?
    .map_err(rpc_err)
}

pub(super) async fn preview(
    handler: &RpcHandler,
    request: NativeWalletRequest,
) -> RpcResult<NativeWalletPreview> {
    let _operation = handler.wallet_operation_gate.lock().await;
    let prepared = prepare(handler, request).await?;
    let review = prepared.review.clone();
    *handler.native_review.lock().await =
        matches!(review.request, NativeWalletRequest::Trade { .. })
            .then_some(ReviewedOperation { prepared });
    Ok(review)
}

pub(super) async fn submit(
    handler: &RpcHandler,
    request: NativeWalletRequest,
    plan_id: String,
) -> RpcResult<NativeWalletSubmitResult> {
    let reviewed = digest(&plan_id)?;
    let operation = Arc::clone(&handler.wallet_operation_gate)
        .lock_owned()
        .await;
    let prepared = if matches!(request, NativeWalletRequest::Trade { .. }) {
        let mut cached = handler.native_review.lock().await;
        let entry = cached
            .as_ref()
            .ok_or_else(|| rpc_err("review the trade before confirming"))?;
        if entry.prepared.review.request != request
            || digest(&entry.prepared.review.plan_id)? != reviewed
        {
            return Err(rpc_err(
                "native plan changed; preview and review the operation again",
            ));
        }
        cached.take().expect("checked trade review").prepared
    } else {
        prepare(handler, request).await?
    };
    if digest(&prepared.review.plan_id)? != reviewed {
        return Err(rpc_err(
            "native plan changed; preview and review the operation again",
        ));
    }
    let expected = prepared.proof.context.clone();
    let review = prepared.review;
    handler.reload_active_wallet().await?;
    let store = {
        let chain = handler.chain.read().await;
        if chain.tip_header() != &expected.parent
            || handler.wallet.active_address()
                != Some((expected.key_index, expected.owner.to_bech32()))
        {
            return Err(rpc_err(
                "native wallet context changed; review the operation again",
            ));
        }
        chain.store.clone()
    };
    let wallet = Arc::clone(&handler.wallet);
    let (proved, operation) = tokio::task::spawn_blocking(move || {
        let proved = noid_miner::install_wallet_proof_cpu(|| {
            wallet.build_native_authorization(prepared.proof, store)
        })
        .map_err(|e| format!("native proof CPU admission: {e}"))
        .and_then(|result| result);
        (proved, operation)
    })
    .await
    .map_err(|e| rpc_err(format!("native wallet task: {e}")))?;
    let _operation = operation;
    let submission = proved.map_err(rpc_err)?;
    let chain = handler.chain.read().await;
    if chain.tip_header() != &expected.parent
        || handler.wallet.active_address() != Some((expected.key_index, expected.owner.to_bech32()))
    {
        return Err(rpc_err(
            "native wallet context changed; review the operation again",
        ));
    }
    if submission.context != expected || hex::encode(submission.txid) != review.txid {
        return Err(rpc_err(
            "native wallet authorization differs from the reviewed operation",
        ));
    }
    let reservation =
        PendingAdmissionGuard::reserve_native(Arc::clone(&handler.wallet), &submission)
            .map_err(rpc_err)?;
    handler
        .wallet
        .remember_native_submission(&submission, &review)
        .map_err(rpc_err)?;
    let admitted = handler
        .wallet_submission_mempool
        .submit_encoded(submission.intent_bytes)
        .await;
    let txid = match admitted {
        Ok(txid) => txid,
        Err(error) => {
            if let Err(write_error) = handler.wallet.forget_native_activity(submission.txid) {
                tracing::warn!(%write_error, "failed to update native submission journal");
            }
            return Err(rpc_err(error.to_string()));
        }
    };
    if txid.0 != submission.txid {
        return Err(rpc_err(
            "native admission returned a different transaction identity",
        ));
    }
    reservation.commit();
    drop(chain);
    Ok(NativeWalletSubmitResult {
        txid: hex::encode(txid.0),
        plan_id: review.plan_id,
        fee_micronoid: review.fee_micronoid,
        fee_limit_micronoid: review.fee_limit_micronoid,
    })
}

pub(super) async fn pending(handler: &RpcHandler) -> RpcResult<Vec<NativeWalletPending>> {
    let _operation = handler.wallet_operation_gate.lock().await;
    reconcile_pending(handler).await?;
    let records = handler.wallet.native_activity().map_err(rpc_err)?;
    let chain = handler.chain.read().await;
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for record in records {
        let review = record.preview;
        let id = digest(&review.txid)?;
        seen.insert(id);
        let confirmation_height = canonical_submission_height(handler, &chain, id)?;
        if confirmation_height.is_some_and(|height| height <= chain.finalized.height) {
            handler.wallet.forget_native_activity(id).map_err(rpc_err)?;
            continue;
        }
        let status = if confirmation_height.is_some() {
            NativeWalletPendingStatus::Confirmed
        } else if handler
            .mempool
            .get_entry_metadata(&noid_poseidon2b::primitives::TxBodyHash(id))
            .await
            .is_some()
        {
            NativeWalletPendingStatus::Pending
        } else {
            NativeWalletPendingStatus::Unconfirmed
        };
        result.push(NativeWalletPending {
            txid: review.txid.clone(),
            owner: review.owner.clone(),
            key_index: review.key_index,
            parent_height: review.height - 1,
            input_count: review.input_count,
            output_count: review.output_count,
            status,
            submitted_unix: Some(record.submitted_unix),
            preview: Some(review),
            confirmation_height,
        });
    }
    for pending in handler.wallet.native_pending_submissions() {
        if seen.insert(pending.txid) {
            result.push(NativeWalletPending {
                txid: hex::encode(pending.txid),
                owner: pending.owner.to_bech32(),
                key_index: pending.key_index,
                parent_height: pending.parent_height,
                input_count: pending.input_slots.len(),
                output_count: pending.output_slots.len(),
                status: NativeWalletPendingStatus::Pending,
                submitted_unix: None,
                preview: None,
                confirmation_height: None,
            });
        }
    }
    Ok(result)
}

fn canonical_submission_height(
    handler: &RpcHandler,
    chain: &MdbxChainContext,
    id: [u8; 32],
) -> RpcResult<Option<u64>> {
    use noid_chain::consensus::receipt::{
        verify_against_header, verify_merkle_inclusion, ParanoidReceipt,
    };
    let Ok(encoded) = handler.wallet.export_receipt(&hex::encode(id)) else {
        return Ok(None);
    };
    let bytes = decode_bounded_hex("receipt", &encoded, MAX_RPC_RECEIPT_BYTES)?;
    let receipt = ParanoidReceipt::from_bytes(&bytes)
        .map_err(|e| rpc_err(format!("decode native submission receipt: {e}")))?;
    if receipt.summary.logical_txid != id || !verify_merkle_inclusion(&receipt) {
        return Err(rpc_err("invalid native submission receipt"));
    }
    let canonical = chain
        .store
        .get_header(receipt.claimed_height)
        .map_err(|e| rpc_err(e.to_string()))?
        .is_some_and(|header| verify_against_header(&receipt, &header));
    Ok(canonical.then_some(receipt.claimed_height))
}

pub(super) async fn dismiss_pending(handler: &RpcHandler, txid: String) -> RpcResult<()> {
    let id = digest(&txid)?;
    let _operation = handler.wallet_operation_gate.lock().await;
    let chain = handler.chain.read().await;
    if handler
        .mempool
        .get_entry_metadata(&noid_poseidon2b::primitives::TxBodyHash(id))
        .await
        .is_some()
        || canonical_submission_height(handler, &chain, id)?.is_some()
    {
        return Err(rpc_err(
            "only unconfirmed submissions outside the local queue can be dismissed",
        ));
    }
    handler.wallet.forget_native_activity(id).map_err(rpc_err)
}

fn digest(value: &str) -> RpcResult<[u8; 32]> {
    if value.len() != 64 {
        return Err(rpc_err(
            "native digest must contain 64 hexadecimal characters",
        ));
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| rpc_err("invalid native hexadecimal digest"))?;
    Ok(bytes)
}

pub(super) async fn protocol(handler: &RpcHandler) -> RpcResult<NativeProtocolInfo> {
    let height = handler.chain.read().await.tip_height();
    let next = height
        .checked_add(1)
        .ok_or_else(|| rpc_err("height exhausted"))?;
    let native = handler
        .history_step_runtime
        .as_deref()
        .and_then(|runtime| runtime.finance_config())
        .map(|config| {
            config
                .class(noid_recursive::acceptance::history_step::v2::capacity_banked::Class::Native)
        });
    let trade = native.and_then(|config| config.native_sequential_config());
    Ok(NativeProtocolInfo {
        tip_height: height,
        activation_height: noid_chain::consensus::params::V2_1_ACTIVATION_HEIGHT,
        active_at_next_block: noid_chain::consensus::params::v2_1_active(next),
        runtime_available: native.is_some(),
        initial_creator_purchase: native.is_some(),
        nft_batch_limit: native.and_then(|config| {
            config.native_action_capacity().map(|actions| {
                (config.pages().saturating_sub(1) * noid_tx::TX_OUTPUTS)
                    .saturating_sub(2)
                    .min(actions.saturating_sub(4))
            })
        }),
        token_decimals: noid_tx::native_assets::TOKEN_DECIMALS,
        minimum_launch_whole_tokens: noid_tx::native_assets::launch::LAUNCH_MIN_WHOLE_TOKENS
            .to_string(),
        maximum_launch_whole_tokens: (noid_tx::native_assets::launch::LAUNCH_MAX_SUPPLY
            / noid_tx::native_assets::TOKEN_UNITS)
            .to_string(),
        minimum_backing_micronoid_per_whole_token:
            noid_tx::asset_backing::MIN_BACKING_MICRONOID_PER_TOKEN.to_string(),
        pages: native.map(|config| config.pages()),
        headers: native.and_then(|config| config.native_header_capacity()),
        actions: native.and_then(|config| config.native_action_capacity()),
        markets: trade.map(|config| config.markets),
        trade_policies: trade.map(|config| config.policies),
        trade_funding_inputs: trade.map(|config| config.funding),
    })
}

pub(super) async fn holdings(
    handler: &RpcHandler,
    address: String,
    key_index: Option<u32>,
    cursor: Option<NativeWalletCursor>,
    limit: u32,
) -> RpcResult<NativeHoldingsPage> {
    let owner = parse_address_param(&address)?;
    let cursor = cursor
        .map(|c| -> RpcResult<StoreCursor> {
            let cursor_owner = parse_address_param(&c.owner)?;
            if cursor_owner != owner {
                return Err(rpc_err("native wallet cursor belongs to another address"));
            }
            Ok(StoreCursor {
                owner: owner.0,
                height: c.height,
                tip_hash: digest(&c.block_hash)?,
                after_root: c.after_root.as_deref().map(digest).transpose()?,
                from_slot: c.from_slot,
            })
        })
        .transpose()?;
    let store = handler.chain.read().await.store.clone();
    let reserved = handler.mempool.reserved_slots().await.0;
    let page = store
        .native_wallet_page(owner, cursor, limit as usize)
        .map_err(|error| match error {
            NativeWalletQueryError::TipChanged { height, tip_hash } => ErrorObject::owned(
                -32041,
                "native wallet State changed; restart pagination",
                Some(serde_json::json!({"height":height,"block_hash":hex::encode(tip_hash)})),
            ),
            other => rpc_err(other.to_string()),
        })?;
    let holdings = page
        .items
        .into_iter()
        .map(|item| -> RpcResult<NativeHolding> {
            Ok(NativeHolding {
                root: hex::encode(item.root),
                kind: item.opening.kind() as u16,
                opening_hex: hex::encode(
                    item.opening
                        .to_bytes()
                        .map_err(|e| rpc_err(e.to_string()))?,
                ),
                dependency_hex: item
                    .dependency
                    .map(|o| {
                        o.to_bytes()
                            .map(hex::encode)
                            .map_err(|e| rpc_err(e.to_string()))
                    })
                    .transpose()?,
                slot_index: item.carrier.slot_index,
                creation_id: item.carrier.creation_id.to_string(),
                amount_micronoid: item.carrier.amount.to_string(),
                unlock_height: item.opening.unlock_height(),
                reserved: reserved.contains(&item.carrier.slot_index),
            })
        })
        .collect::<RpcResult<Vec<_>>>()?;
    Ok(NativeHoldingsPage {
        owner: owner.to_bech32(),
        key_index,
        height: page.height,
        block_hash: hex::encode(page.tip_hash),
        state_root: hex::encode(page.state_root),
        holdings,
        next: page.next.map(|c| NativeWalletCursor {
            owner: Address(c.owner).to_bech32(),
            height: c.height,
            block_hash: hex::encode(c.tip_hash),
            after_root: c.after_root.map(hex::encode),
            from_slot: c.from_slot,
        }),
    })
}
