// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Stateless native planning from a verified owner view and one canonical tip.

use super::*;
use crate::client_types::{NativeClientIntentKind, NativeClientPlan};
use crate::wallet_ops::WalletNativeIntent;
use noid_tx::native_assets::trade::wire::TradeOwnerIntent;

const MAX_CLIENT_REQUEST_BYTES: usize = 32 * 1024;
const MAX_CLIENT_FUNDING_SOURCES: usize = 16_384;

fn state_changed(header: &noid_chain::BlockHeader) -> ErrorObject<'static> {
    ErrorObject::owned(
        -32041,
        "native planning State changed; prepare the operation again",
        Some(serde_json::json!({
            "height": header.height,
            "block_hash": hex::encode(noid_chain::block_id(header)),
        })),
    )
}

fn funding(
    chain: &noid_chain::storage::MdbxChainContext,
    owner: Address,
) -> Result<Vec<crate::types::WalletUtxoInfo>, String> {
    let parent = chain.tip_header();
    let parent_id = noid_chain::block_id(parent);
    let address = owner.to_bech32();
    let mut cursor = 0;
    let mut result = Vec::new();
    loop {
        let page = chain
            .store
            .get_verified_owner_page(&owner.0, cursor, 256)
            .map_err(|e| e.to_string())?;
        if page.height != parent.height || page.tip_hash != parent_id {
            return Err("native funding State changed; prepare the operation again".into());
        }
        if result.len() + page.utxos.len() > MAX_CLIENT_FUNDING_SOURCES {
            return Err("native funding source limit reached; consolidate NOID outputs".into());
        }
        result.extend(
            page.utxos
                .into_iter()
                .map(|utxo| crate::types::WalletUtxoInfo {
                    slot_index: utxo.slot_index,
                    value_micronoid: utxo.amount,
                    creation_id: utxo.creation_id,
                    value_noid: utxo.amount as f64 / 1_000_000.0,
                    address: address.clone(),
                    key_index: 0,
                    confirmed_height: parent.height,
                    reserved: false,
                }),
        );
        match page.next_slot {
            Some(next) if next > cursor => cursor = next,
            Some(_) => return Err("invalid native funding cursor".into()),
            None => return Ok(result),
        }
    }
}

fn export(prepared: planner::Prepared) -> Result<NativeClientPlan, String> {
    let claims = prepared.proof.checked_claims()?;
    let context = &prepared.proof.context;
    let height = context.candidate_height()?;
    let (kind, bytes) = match &prepared.proof.intent {
        WalletNativeIntent::Operation(intent) => (
            NativeClientIntentKind::Operation,
            intent.to_bytes().map_err(|e| e.to_string())?,
        ),
        WalletNativeIntent::Trade(intent) => (
            NativeClientIntentKind::Trade,
            TradeOwnerIntent {
                intent: intent.clone(),
                authorization_bytes: Vec::new(),
            }
            .to_bytes()
            .map_err(|e| e.to_string())?,
        ),
    };
    let request = serde_json::to_vec(&prepared.review.request).map_err(|e| e.to_string())?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOIDNativeClientPlan1");
    hasher.update(&context.parent.to_bytes());
    hasher.update(&context.owner.0);
    hasher.update(&context.epoch_anchor);
    hasher.update(&(request.len() as u32).to_le_bytes());
    hasher.update(&request);
    hasher.update(&bytes);
    Ok(NativeClientPlan {
        schema_version: 1,
        plan_id: hasher.finalize().to_hex().to_string(),
        intent_id: hex::encode(claims.txid),
        owner: context.owner.to_bech32(),
        candidate_height: height,
        parent_header_hex: hex::encode(context.parent.to_bytes()),
        chain_id: hex::encode(noid_chain::state::native_assets::native_chain_id()),
        epoch_anchor: hex::encode(context.epoch_anchor),
        owner_authorization_version: noid_chain::consensus::params::owner_authorization_version(
            height,
        ) as u8,
        intent_kind: kind,
        unsigned_intent_hex: hex::encode(bytes),
        review: prepared.review.into(),
    })
}

pub(in crate::server) async fn prepare(
    handler: &RpcHandler,
    owner: String,
    request: NativeWalletRequest,
    expected_parent_hash: Option<String>,
) -> RpcResult<NativeClientPlan> {
    if serde_json::to_vec(&request)
        .map_err(|e| rpc_err(e.to_string()))?
        .len()
        > MAX_CLIENT_REQUEST_BYTES
    {
        return Err(rpc_err("native client request exceeds 32 KiB"));
    }
    let owner = parse_address_param(&owner)?;
    let expected = expected_parent_hash.as_deref().map(digest).transpose()?;
    let budget = handler
        .history_step_runtime
        .as_deref()
        .and_then(|runtime| runtime.v21_native_admission_budget())
        .ok_or_else(|| rpc_err("native runtime unavailable"))?;
    let projection = if matches!(request, NativeWalletRequest::Trade { .. }) {
        let mut chain = handler.chain.write().await;
        Some(
            noid_miner::template::TemplateChainSnapshot::from_context(&mut chain)
                .map_err(|e| rpc_err(e.to_string()))?,
        )
    } else {
        None
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let (chain, mut reservations) = loop {
        let chain = Arc::clone(&handler.chain).read_owned().await;
        let parent = chain.tip_header();
        if expected.is_some_and(|hash| hash != chain.tip_hash())
            || projection
                .as_ref()
                .is_some_and(|snapshot| &snapshot.parent != parent)
        {
            return Err(state_changed(parent));
        }
        if let Some(reservations) = handler
            .mempool
            .reservation_snapshot_at(parent.height, chain.tip_hash())
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
    let pending = if let Some(snapshot) = &projection {
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
    reservations.input_slots.extend(reservations.output_slots);
    tokio::task::spawn_blocking(move || {
        let utxos = funding(&chain, owner)?;
        let prepared = if let (Some(snapshot), Some(pending)) = (&projection, &pending) {
            let project = |trade: &noid_tx::native_assets::trade::TradeIntent| {
                noid_miner::template::project_trade(snapshot, pending, trade, budget)
            };
            planner::prepare_with_projection(
                &chain,
                0,
                owner,
                request,
                utxos,
                reservations.input_slots,
                reservations.fee_floor,
                budget,
                Some(&project),
            )?
        } else {
            planner::prepare(
                &chain,
                0,
                owner,
                request,
                utxos,
                reservations.input_slots,
                reservations.fee_floor,
                budget,
            )?
        };
        export(prepared)
    })
    .await
    .map_err(|_| rpc_err("native client planning task failed"))?
    .map_err(rpc_err)
}
