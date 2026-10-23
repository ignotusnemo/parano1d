// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native Owner capsules produced by the active local master-derived account.

use noid_chain::storage::MdbxStore;
use noid_gkr::wallet_authorization::{
    prove_native_asset_authorization, prove_native_financial_authorization,
    prove_native_trade_authorization,
};
use noid_rpc::wallet_ops::{
    WalletNativeClaims, WalletNativeContext, WalletNativeIntent, WalletNativeProofRequest,
    WalletNativeSubmission,
};
use noid_tx::native_assets::{trade::wire::TradeOwnerIntent, transition::NativeOperation};

use super::{WalletHandle, WalletState};

fn check_parent(store: &MdbxStore, context: &WalletNativeContext) -> Result<(), String> {
    let page = store
        .get_verified_owner_page(&context.owner.0, 0, 1)
        .map_err(|e| e.to_string())?;
    if page.height != context.parent.height
        || page.tip_hash != noid_chain::block_id(&context.parent)
    {
        return Err("native wallet State changed; review the operation again".into());
    }
    let height = context.candidate_height()?;
    let epoch_height = noid_chain::consensus::tx_epoch_anchor_height_for_child(height);
    let epoch = store
        .get_header(epoch_height)
        .map_err(|e| e.to_string())?
        .ok_or("native wallet epoch header is unavailable")?;
    if noid_chain::block_id(&epoch) != context.epoch_anchor {
        return Err("native wallet epoch changed; review the operation again".into());
    }
    Ok(())
}

fn check_sources(
    store: &MdbxStore,
    context: &WalletNativeContext,
    claims: &WalletNativeClaims,
) -> Result<(), String> {
    check_parent(store, context)?;
    for claim in &claims.inputs {
        let page = store
            .get_verified_owner_page(&claim.root.0, claim.input.slot_index, 1)
            .map_err(|e| e.to_string())?;
        if page.height != context.parent.height
            || page.tip_hash != noid_chain::block_id(&context.parent)
            || !page.utxos.first().is_some_and(|u| {
                u.slot_index == claim.input.slot_index
                    && u.creation_id == claim.input.creation_id
                    && u.amount == claim.input.amount
            })
        {
            return Err("native wallet input changed; review the operation again".into());
        }
        if let Some(opening) = claim.opening {
            let record = store
                .native_payload(claim.root.0)
                .map_err(|e| e.to_string())?
                .ok_or("native wallet input terms are unavailable")?;
            if record.opening != opening || record.live_slots == 0 {
                return Err("native wallet input terms changed".into());
            }
        }
    }
    Ok(())
}

fn check_wallet(
    wallet: &WalletState,
    context: &WalletNativeContext,
    claims: &WalletNativeClaims,
) -> Result<(), String> {
    if wallet.active_index != context.key_index || wallet.active_address() != context.owner {
        return Err("native wallet account changed; review the operation again".into());
    }
    let snapshot = wallet
        .active_snapshot
        .as_ref()
        .ok_or("reload the active wallet before authorizing native operations")?;
    if snapshot.height != context.parent.height
        || snapshot.tip_hash != noid_chain::block_id(&context.parent)
        || snapshot.state_root != context.parent.state_root
        || snapshot.alloc_counter != context.parent.alloc_counter
        || snapshot.log_slots != context.parent.log_slots
        || snapshot.active_slot_count != context.parent.active_slot_count
    {
        return Err("native wallet snapshot changed; review the operation again".into());
    }
    for slot in claims
        .inputs
        .iter()
        .map(|i| i.input.slot_index)
        .chain(claims.output_slots.iter().copied())
    {
        if wallet.pending_input_slots.contains(&slot) || wallet.pending_output_slots.contains(&slot)
        {
            return Err("native wallet operation conflicts with a pending transaction".into());
        }
    }
    for claim in claims.inputs.iter().filter(|i| i.opening.is_none()) {
        if claim.root != context.owner
            || !wallet.utxos.get(&claim.input.slot_index).is_some_and(|u| {
                u.key_index == context.key_index
                    && u.address == context.owner
                    && u.value == claim.input.amount
                    && u.creation_id == claim.input.creation_id
            })
        {
            return Err("native wallet NOID funding does not match the active account".into());
        }
    }
    Ok(())
}

pub(super) fn build(
    handle: &WalletHandle,
    request: WalletNativeProofRequest,
    store: MdbxStore,
) -> Result<WalletNativeSubmission, String> {
    let claims = request.checked_claims()?;
    check_sources(&store, &request.context, &claims)?;
    let witness = {
        let guard = handle.inner.lock().map_err(|_| "wallet lock poisoned")?;
        let wallet = guard.as_ref().ok_or("wallet not initialized")?;
        check_wallet(wallet, &request.context, &claims)?;
        noid_gkr::OwnerAuthWitness::new(wallet.spend_secret_for(request.context.key_index))
    };
    let height = request.context.candidate_height()?;
    let chain = noid_chain::state::native_assets::native_chain_id();
    let version = noid_chain::consensus::params::owner_authorization_version(height);
    let intent_bytes = match request.intent {
        WalletNativeIntent::Operation(mut intent) => {
            let pages = intent.validate_structure().map_err(|e| e.to_string())?;
            let proof = if matches!(pages.operation, NativeOperation::Financial(_)) {
                prove_native_financial_authorization(
                    &intent,
                    chain,
                    request.context.round()?,
                    witness,
                    version,
                )
            } else {
                prove_native_asset_authorization(&intent, chain, height, witness, version)
            }
            .map_err(|e| e.to_string())?;
            intent.authorization_bytes = proof.to_bytes().map_err(|e| e.to_string())?;
            intent.to_bytes().map_err(|e| e.to_string())?
        }
        WalletNativeIntent::Trade(intent) => {
            let proof = prove_native_trade_authorization(
                &intent,
                chain,
                request.context.epoch_anchor,
                height,
                witness,
                version,
            )
            .map_err(|e| e.to_string())?;
            TradeOwnerIntent {
                intent,
                authorization_bytes: proof.to_bytes().map_err(|e| e.to_string())?,
            }
            .to_bytes()
            .map_err(|e| e.to_string())?
        }
    };
    check_parent(&store, &request.context)?;
    {
        let guard = handle.inner.lock().map_err(|_| "wallet lock poisoned")?;
        check_wallet(
            guard.as_ref().ok_or("wallet not initialized")?,
            &request.context,
            &claims,
        )?;
    }
    Ok(WalletNativeSubmission {
        context: request.context,
        txid: claims.txid,
        intent_bytes,
        input_slots: claims.inputs.iter().map(|i| i.input.slot_index).collect(),
        output_slots: claims.output_slots,
    })
}

pub(super) fn reserve(
    handle: &WalletHandle,
    submission: &WalletNativeSubmission,
) -> Result<u128, String> {
    let claims = submission.checked_claims()?;
    let mut guard = handle.inner.lock().map_err(|_| "wallet lock poisoned")?;
    let wallet = guard.as_mut().ok_or("wallet not initialized")?;
    check_wallet(wallet, &submission.context, &claims)?;
    if wallet.native_pending.len() >= 256 || wallet.native_pending.contains_key(&submission.txid) {
        return Err("native wallet pending limit or duplicate submission".into());
    }
    let lease = rand::random();
    wallet.native_pending.insert(
        submission.txid,
        noid_rpc::wallet_ops::WalletNativeReservation {
            lease,
            txid: submission.txid,
            owner: submission.context.owner,
            key_index: submission.context.key_index,
            parent_height: submission.context.parent.height,
            input_slots: submission.input_slots.clone(),
            output_slots: submission.output_slots.clone(),
        },
    );
    wallet.add_pending_inputs(&submission.input_slots);
    wallet.add_pending_outputs(&submission.output_slots);
    Ok(lease)
}

pub(super) fn rollback(handle: &WalletHandle, txid: [u8; 32], lease: u128) {
    let Ok(mut guard) = handle.inner.lock() else {
        return;
    };
    let Some(wallet) = guard.as_mut() else {
        return;
    };
    if wallet
        .native_pending
        .get(&txid)
        .is_some_and(|pending| pending.lease == lease)
    {
        if let Some(pending) = wallet.native_pending.remove(&txid) {
            wallet.remove_pending_inputs(&pending.input_slots);
            wallet.remove_pending_outputs(&pending.output_slots);
        }
    }
}

pub(super) fn on_accepted_block(wallet: &mut WalletState, block: &noid_chain::Block) {
    let inputs: std::collections::HashSet<_> = block
        .transactions
        .iter()
        .flat_map(|tx| tx.body.live_inputs().map(|(_, i)| i.slot_index))
        .collect();
    let outputs: std::collections::HashSet<_> = block
        .transactions
        .iter()
        .flat_map(|tx| tx.body.live_outputs().map(|(_, o)| o.slot_index))
        .collect();
    let retired: Vec<_> = wallet
        .native_pending
        .iter()
        .filter(|(_, pending)| {
            pending.input_slots.iter().any(|slot| inputs.contains(slot))
                || pending
                    .output_slots
                    .iter()
                    .any(|slot| outputs.contains(slot))
        })
        .map(|(id, _)| *id)
        .collect();
    for id in retired {
        if let Some(pending) = wallet.native_pending.remove(&id) {
            wallet.remove_pending_inputs(&pending.input_slots);
            wallet.remove_pending_outputs(&pending.output_slots);
        }
    }
}
