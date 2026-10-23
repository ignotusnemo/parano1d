// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded native discovery from one durable canonical State snapshot.

pub use super::super::native_payloads::NativeCatalogKind;
use super::super::native_payloads::{self, NativeAssetLookup};
use super::*;
use noid_poseidon2b::primitives::Address;
use noid_tx::native_assets::{
    launch::LaunchOpening, market::MarketOpening, nft_market::NftMarketOpening, AssetId,
    NativeOpening,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCatalogCursor {
    pub kind: NativeCatalogKind,
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub after_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCatalogItem {
    pub key: Vec<u8>,
    pub primary: NativeWalletItem,
    pub related: Vec<NativeWalletItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCatalogPage {
    pub kind: NativeCatalogKind,
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub scanned: usize,
    pub items: Vec<NativeCatalogItem>,
    pub next: Option<NativeCatalogCursor>,
}

fn live_item(
    txn: &Transaction<'_, RO, NoWriteMap>,
    root: [u8; 32],
    header: &BlockHeader,
) -> Result<NativeWalletItem, StoreError> {
    let record = native_payloads::read(txn, root)?
        .ok_or(StoreError::Decode("native discovery payload missing"))?;
    if record.live_slots != 1 {
        return Err(StoreError::Decode("native discovery controller count"));
    }
    let dependency = record
        .opening
        .dependency_root()
        .map(|root| {
            let record = native_payloads::read(txn, root.0)?
                .ok_or(StoreError::Decode("native discovery dependency missing"))?;
            if !record.is_referenced() {
                return Err(StoreError::Decode("native discovery dependency references"));
            }
            Ok(record.opening)
        })
        .transpose()?;
    record
        .opening
        .check_dependency(dependency)
        .map_err(|_| StoreError::Decode("native discovery dependency binding"))?;
    let owners = MdbxStore::verified_owner_snapshot_in_txn(txn, &root, Some(2), None, true)?;
    if owners.height != header.height
        || owners.tip_hash != crate::block_id(header)
        || owners.state_root != header.state_root
        || owners.utxos.len() != 1
    {
        return Err(StoreError::Decode("native discovery State binding"));
    }
    let carrier = owners.utxos[0];
    if !crate::consensus::params::creation_id_within_boundary(
        carrier.creation_id,
        owners.alloc_counter,
        owners.height,
    ) {
        return Err(StoreError::Decode("native discovery allocation boundary"));
    }
    record
        .opening
        .check_input_binding(
            &noid_tx::TxInput {
                slot_index: carrier.slot_index,
                amount: carrier.amount,
                creation_id: carrier.creation_id,
            },
            Address(root),
        )
        .map_err(|_| StoreError::Decode("native discovery carrier binding"))?;
    Ok(NativeWalletItem {
        root,
        opening: record.opening,
        dependency,
        carrier,
    })
}

fn catalog_item(
    txn: &Transaction<'_, RO, NoWriteMap>,
    key: Vec<u8>,
    root: [u8; 32],
    header: &BlockHeader,
) -> Result<NativeCatalogItem, StoreError> {
    let primary = live_item(txn, root, header)?;
    let asset = match primary.dependency {
        Some(NativeOpening::Launch(LaunchOpening::Definition(definition))) => {
            Some(definition.asset)
        }
        Some(NativeOpening::Market(MarketOpening::Definition(definition)))
            if definition.base_is_noid() =>
        {
            Some(definition.quote)
        }
        _ => None,
    };
    let mut related = Vec::new();
    if let Some(asset) = asset {
        for lookup in [
            NativeAssetLookup::TokenDefinition(asset),
            NativeAssetLookup::TokenReserve(asset),
        ] {
            let root = native_payloads::asset_root(txn, lookup)?
                .ok_or(StoreError::Decode("native discovery token terms missing"))?;
            related.push(live_item(txn, root, header)?);
        }
        let NativeOpening::FungibleDefinition(definition) = related[0].opening else {
            return Err(StoreError::Decode("native discovery token definition"));
        };
        let NativeOpening::TokenReserve(reserve) = related[1].opening else {
            return Err(StoreError::Decode("native discovery token reserve"));
        };
        if definition.asset != asset || reserve.check_definition(&definition).is_err() {
            return Err(StoreError::Decode("native discovery token terms binding"));
        }
        if let Some(NativeOpening::Launch(LaunchOpening::Definition(launch))) = primary.dependency {
            if launch.definition_root != Address(related[0].root)
                || launch.initial_supply != definition.initial_supply
            {
                return Err(StoreError::Decode("native discovery launch token binding"));
            }
        }
    }
    Ok(NativeCatalogItem {
        key,
        primary,
        related,
    })
}

impl MdbxStore {
    pub fn native_catalog_page(
        &self,
        kind: NativeCatalogKind,
        cursor: Option<NativeCatalogCursor>,
        limit: usize,
    ) -> Result<NativeCatalogPage, NativeWalletQueryError> {
        if !(1..=256).contains(&limit) {
            return Err(NativeWalletQueryError::Limit);
        }
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.kind != kind || !kind.check_key(&cursor.after_key))
        {
            return Err(StoreError::Decode("native catalogue cursor binding").into());
        }
        let txn = self.db.begin_ro_txn()?;
        let table = txn.open_table(Some(T_CHAIN_TIP))?;
        let raw: Vec<u8> = txn
            .get(&table, KEY_TIP)?
            .ok_or(StoreError::Decode("native catalogue tip missing"))?;
        let (height, tip_hash) =
            decode_chain_tip(&raw).ok_or(StoreError::Decode("native catalogue tip encoding"))?;
        if cursor
            .as_ref()
            .is_some_and(|c| (c.height, c.tip_hash) != (height, tip_hash))
        {
            return Err(NativeWalletQueryError::TipChanged { height, tip_hash });
        }
        let headers = txn.open_table(Some(T_HEADERS))?;
        let raw: Vec<u8> = txn
            .get(&headers, &u64_key(height))?
            .ok_or(StoreError::Decode("native catalogue header missing"))?;
        let header =
            decode_header(&raw).ok_or(StoreError::Decode("native catalogue header encoding"))?;
        if header.height != height || crate::block_id(&header) != tip_hash {
            return Err(StoreError::Decode("native catalogue header binding").into());
        }
        let rows = native_payloads::catalog_roots(
            &txn,
            kind,
            cursor.as_ref().map(|c| c.after_key.as_slice()),
            limit,
        )?;
        let scanned = rows.len();
        let next = (scanned == limit).then(|| NativeCatalogCursor {
            kind,
            height,
            tip_hash,
            after_key: rows.last().unwrap().0.clone(),
        });
        let mut items = Vec::with_capacity(scanned);
        for (key, root) in rows {
            if kind == NativeCatalogKind::NftListings {
                let record = native_payloads::read(&txn, root)?
                    .ok_or(StoreError::Decode("native listing payload missing"))?;
                if !matches!(
                    record.opening,
                    NativeOpening::NftMarket(NftMarketOpening::Listing(_))
                ) {
                    continue;
                }
            }
            items.push(catalog_item(&txn, key, root, &header)?);
        }
        Ok(NativeCatalogPage {
            kind,
            height,
            tip_hash,
            state_root: header.state_root,
            scanned,
            items,
            next,
        })
    }

    pub fn native_market_details_at(
        &self,
        asset: AssetId,
        height: u64,
        tip_hash: [u8; 32],
    ) -> Result<Option<NativeCatalogItem>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let table = txn.open_table(Some(T_CHAIN_TIP))?;
        let raw: Vec<u8> = txn
            .get(&table, KEY_TIP)?
            .ok_or(StoreError::Decode("native market tip missing"))?;
        if decode_chain_tip(&raw) != Some((height, tip_hash)) {
            return Err(StoreError::Decode("native market State changed"));
        }
        let headers = txn.open_table(Some(T_HEADERS))?;
        let raw: Vec<u8> = txn
            .get(&headers, &u64_key(height))?
            .ok_or(StoreError::Decode("native market header missing"))?;
        let header =
            decode_header(&raw).ok_or(StoreError::Decode("native market header encoding"))?;
        if header.height != height || crate::block_id(&header) != tip_hash {
            return Err(StoreError::Decode("native market header binding"));
        }
        let Some(root) =
            native_payloads::asset_root(&txn, NativeAssetLookup::MarketForAsset(asset))?
        else {
            return Ok(None);
        };
        let mut key = Vec::with_capacity(34);
        key.extend_from_slice(&0x8000u16.to_be_bytes());
        key.extend_from_slice(&asset.0);
        catalog_item(&txn, key, root, &header).map(Some)
    }
}
