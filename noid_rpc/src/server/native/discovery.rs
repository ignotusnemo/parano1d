// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use std::collections::HashSet;

fn holding(
    item: noid_chain::storage::NativeWalletItem,
    reserved: &HashSet<u32>,
) -> RpcResult<NativeHolding> {
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
}

fn item(
    item: noid_chain::storage::NativeCatalogItem,
    reserved: &HashSet<u32>,
) -> RpcResult<NativeCatalogItem> {
    Ok(NativeCatalogItem {
        key: hex::encode(item.key),
        primary: holding(item.primary, reserved)?,
        related: item
            .related
            .into_iter()
            .map(|h| holding(h, reserved))
            .collect::<RpcResult<Vec<_>>>()?,
    })
}

pub(in crate::server) async fn catalog(
    handler: &RpcHandler,
    kind: NativeCatalogKind,
    cursor: Option<NativeCatalogCursor>,
    limit: u32,
) -> RpcResult<NativeCatalogPage> {
    if !(1..=64).contains(&limit) {
        return Err(rpc_err("native catalogue page limit must be 1..=64"));
    }
    let storage_kind = kind.storage();
    let cursor = cursor
        .map(
            |cursor| -> RpcResult<noid_chain::storage::NativeCatalogCursor> {
                if cursor.kind != kind || cursor.after_key.len() > 84 {
                    return Err(rpc_err("native catalogue cursor binding"));
                }
                let after_key = hex::decode(cursor.after_key)
                    .map_err(|_| rpc_err("invalid native catalogue cursor key"))?;
                if !storage_kind.check_key(&after_key) {
                    return Err(rpc_err("native catalogue cursor key binding"));
                }
                Ok(noid_chain::storage::NativeCatalogCursor {
                    kind: storage_kind,
                    height: cursor.height,
                    tip_hash: digest(&cursor.block_hash)?,
                    after_key,
                })
            },
        )
        .transpose()?;
    let store = handler.chain.read().await.store.clone();
    let reserved = handler.mempool.reserved_slots().await.0;
    let page = tokio::task::spawn_blocking(move || {
        store.native_catalog_page(storage_kind, cursor, limit as usize)
    })
    .await
    .map_err(|_| rpc_err("native catalogue task failed"))?
    .map_err(|error| match error {
        NativeWalletQueryError::TipChanged { height, tip_hash } => ErrorObject::owned(
            -32041,
            "native catalogue State changed; restart pagination",
            Some(serde_json::json!({"height":height,"block_hash":hex::encode(tip_hash)})),
        ),
        other => rpc_err(other.to_string()),
    })?;
    Ok(NativeCatalogPage {
        kind,
        height: page.height,
        block_hash: hex::encode(page.tip_hash),
        state_root: hex::encode(page.state_root),
        scanned: page.scanned,
        items: page
            .items
            .into_iter()
            .map(|i| item(i, &reserved))
            .collect::<RpcResult<Vec<_>>>()?,
        next: page.next.map(|c| NativeCatalogCursor {
            kind,
            height: c.height,
            block_hash: hex::encode(c.tip_hash),
            after_key: hex::encode(c.after_key),
        }),
    })
}

pub(in crate::server) async fn market(
    handler: &RpcHandler,
    asset_id: String,
) -> RpcResult<NativeMarketDetails> {
    let asset = noid_tx::native_assets::AssetId(digest(&asset_id)?);
    let chain = handler.chain.read().await;
    let header = *chain.tip_header();
    let store = chain.store.clone();
    drop(chain);
    let hash = noid_chain::block_id(&header);
    let reserved = handler.mempool.reserved_slots().await.0;
    let found = tokio::task::spawn_blocking(move || {
        store.native_market_details_at(asset, header.height, hash)
    })
    .await
    .map_err(|_| rpc_err("native market discovery task failed"))?
    .map_err(|e| rpc_err(e.to_string()))?;
    Ok(NativeMarketDetails {
        height: header.height,
        block_hash: hex::encode(hash),
        state_root: hex::encode(header.state_root),
        item: found.map(|i| item(i, &reserved)).transpose()?,
    })
}
