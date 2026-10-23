// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Current native openings and bounded retained preimages for branch recovery.

use super::StoreError;
use crate::consensus::params::{
    BLOCK_MAX_ACTIONS, RETAINED_BLOCK_SERVING_DEPTH, UNDO_RETENTION_DEPTH,
};
use crate::fri_state::SlotValue;
use libmdbx::{NoWriteMap, TableFlags, Transaction, TransactionKind, WriteFlags, RW};
use noid_poseidon2b::primitives::{Address, Digest};
use noid_tx::native_assets::{
    launch::{LaunchId, LaunchOpening},
    market::{MarketOpening, PoolId},
    native_sequence,
    nft_market::NftMarketOpening,
    AssetId, CollectionId, NativeOpening, MAX_NATIVE_OPENING_BYTES, NATIVE_CREATION_TAG,
};
use std::collections::BTreeMap;

pub(crate) const TABLES: [&str; 6] = [
    "native_payloads",
    "native_owners",
    "native_assets",
    "native_retired",
    "native_pending",
    "native_metadata",
];
const DATA: &str = TABLES[0];
const OWNER: &str = TABLES[1];
const ASSET: &str = TABLES[2];
const RETIRED: &str = TABLES[3];
const PENDING: &str = TABLES[4];
const META: &str = TABLES[5];
const MARKET_INDEX_VERSION_KEY: &[u8] = b"market_index_version";
const VERSION: u16 = 2;
const LEGACY_PREFIX_BYTES: usize = 19;
const PREFIX_BYTES: usize = 27;
pub const NATIVE_PENDING_PAYLOAD_LIMIT: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativePayloadRecord {
    pub opening: NativeOpening,
    pub live_slots: u64,
    pub auxiliary_refs: u64,
    pub last_seen_height: u64,
    pub was_canonical: bool,
}

impl NativePayloadRecord {
    pub fn is_referenced(self) -> bool {
        self.live_slots != 0 || self.auxiliary_refs != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAssetLookup {
    TokenDefinition(AssetId),
    TokenReserve(AssetId),
    Collection(CollectionId),
    Pool(PoolId),
    Launch(LaunchId),
    MarketForAsset(AssetId),
    Nft {
        collection: CollectionId,
        serial: u64,
    },
    NftListing {
        collection: CollectionId,
        serial: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeCatalogKind {
    Markets,
    Collections,
    NftListings,
}

impl NativeCatalogKind {
    pub fn check_key(self, key: &[u8]) -> bool {
        let (prefix, length) = self.key_shape();
        key.len() == length && key[..2] == prefix.to_be_bytes()
    }

    fn key_shape(self) -> (u16, usize) {
        match self {
            Self::Markets => (0x8000, 34),
            Self::Collections => (4, 34),
            Self::NftListings => (0x8001, 42),
        }
    }
}

impl NativeAssetLookup {
    fn key(self) -> Vec<u8> {
        let (kind, id, serial) = match self {
            Self::TokenDefinition(id) => (1u16, id.0, None),
            Self::TokenReserve(id) => (3, id.0, None),
            Self::Collection(id) => (4, id.0, None),
            Self::Pool(id) => (33, id.0, None),
            Self::Launch(id) => (49, id.0, None),
            Self::MarketForAsset(id) => (0x8000, id.0, None),
            Self::Nft { collection, serial } => (5, collection.0, Some(serial)),
            Self::NftListing { collection, serial } => (0x8001, collection.0, Some(serial)),
        };
        let mut key = Vec::with_capacity(42);
        key.extend_from_slice(&kind.to_be_bytes());
        key.extend_from_slice(&id);
        if let Some(serial) = serial {
            key.extend_from_slice(&serial.to_be_bytes());
        }
        key
    }
}

pub(crate) fn create_tables(txn: &Transaction<'_, RW, NoWriteMap>) -> Result<(), StoreError> {
    for name in TABLES {
        txn.create_table(Some(name), TableFlags::empty())?;
    }
    initialize_market_index(txn)?;
    Ok(())
}

fn decode(root: Digest, raw: &[u8]) -> Result<NativePayloadRecord, StoreError> {
    if raw.len() < LEGACY_PREFIX_BYTES || raw[2] > 1 {
        return Err(StoreError::Decode("native payload record format"));
    }
    let prefix = match u16::from_le_bytes([raw[0], raw[1]]) {
        1 => LEGACY_PREFIX_BYTES,
        VERSION => PREFIX_BYTES,
        _ => return Err(StoreError::Decode("native payload record version")),
    };
    if raw.len() < prefix || raw.len() > prefix + MAX_NATIVE_OPENING_BYTES {
        return Err(StoreError::Decode("native payload record size"));
    }
    let opening = NativeOpening::from_bytes(&raw[prefix..])
        .map_err(|_| StoreError::Decode("native payload opening"))?;
    if opening.root().0 != root {
        return Err(StoreError::Decode("native payload root"));
    }
    let record = NativePayloadRecord {
        opening,
        live_slots: u64::from_le_bytes(raw[3..11].try_into().unwrap()),
        auxiliary_refs: if prefix == PREFIX_BYTES {
            u64::from_le_bytes(raw[19..27].try_into().unwrap())
        } else {
            0
        },
        was_canonical: raw[2] != 0,
        last_seen_height: u64::from_le_bytes(raw[11..19].try_into().unwrap()),
    };
    if record.is_referenced() && !record.was_canonical {
        return Err(StoreError::Decode("pending native payload is referenced"));
    }
    if (record.auxiliary_refs != 0 && !opening.is_auxiliary())
        || (record.live_slots != 0 && opening.is_auxiliary())
    {
        return Err(StoreError::Decode("native payload reference class"));
    }
    Ok(record)
}

fn encode(record: NativePayloadRecord) -> Result<Vec<u8>, StoreError> {
    let opening = record
        .opening
        .to_bytes()
        .map_err(|_| StoreError::Decode("native payload opening"))?;
    let mut raw = Vec::with_capacity(PREFIX_BYTES + opening.len());
    raw.extend_from_slice(&VERSION.to_le_bytes());
    raw.push(u8::from(record.was_canonical));
    raw.extend_from_slice(&record.live_slots.to_le_bytes());
    raw.extend_from_slice(&record.last_seen_height.to_le_bytes());
    raw.extend_from_slice(&record.auxiliary_refs.to_le_bytes());
    raw.extend_from_slice(&opening);
    Ok(raw)
}

pub(crate) fn read<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
    root: Digest,
) -> Result<Option<NativePayloadRecord>, StoreError> {
    let table = txn.open_table(Some(DATA))?;
    txn.get::<Vec<u8>>(&table, &root)?
        .as_deref()
        .map(|raw| decode(root, raw))
        .transpose()
}

fn age_key(height: u64, root: Digest) -> [u8; 40] {
    let mut key = [0; 40];
    key[..8].copy_from_slice(&height.to_be_bytes());
    key[8..].copy_from_slice(&root);
    key
}
fn owner_key(owner: Address, root: Digest) -> [u8; 64] {
    let mut key = [0; 64];
    key[..32].copy_from_slice(&owner.0);
    key[32..].copy_from_slice(&root);
    key
}

fn authorities<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
    opening: NativeOpening,
) -> Result<Vec<Address>, StoreError> {
    if !matches!(
        opening,
        NativeOpening::NftMarket(NftMarketOpening::Listing(_))
    ) {
        return Ok(opening.owners());
    }
    let dependency = opening
        .dependency_root()
        .map(|root| {
            read(txn, root.0)?
                .map(|r| r.opening)
                .ok_or(StoreError::Decode("native owner dependency missing"))
        })
        .transpose()?;
    opening
        .owners_with_dependency(dependency)
        .map_err(|_| StoreError::Decode("native owner dependency binding"))
}

fn lookup(opening: NativeOpening) -> Option<NativeAssetLookup> {
    match opening {
        NativeOpening::FungibleDefinition(d) => Some(NativeAssetLookup::TokenDefinition(d.asset)),
        NativeOpening::TokenBalance(_) => None,
        NativeOpening::Market(MarketOpening::Pool(p)) => Some(NativeAssetLookup::Pool(p.pool)),
        NativeOpening::Market(_) => None,
        NativeOpening::Launch(LaunchOpening::State(s)) => Some(NativeAssetLookup::Launch(s.launch)),
        NativeOpening::Launch(_) => None,
        NativeOpening::NftMarket(NftMarketOpening::Listing(s)) => Some(NativeAssetLookup::Nft {
            collection: s.collection,
            serial: s.serial,
        }),
        NativeOpening::NftMarket(_) => None,
        NativeOpening::TokenReserve(r) => Some(NativeAssetLookup::TokenReserve(r.asset)),
        NativeOpening::NftCollection(c) => Some(NativeAssetLookup::Collection(c.collection)),
        NativeOpening::NftItem(n) => Some(NativeAssetLookup::Nft {
            collection: n.collection,
            serial: n.serial,
        }),
    }
}

fn derived_lookup<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
    opening: NativeOpening,
) -> Result<Option<NativeAssetLookup>, StoreError> {
    if let NativeOpening::NftMarket(NftMarketOpening::Listing(listing)) = opening {
        return Ok(Some(NativeAssetLookup::NftListing {
            collection: listing.collection,
            serial: listing.serial,
        }));
    }
    if !matches!(
        opening,
        NativeOpening::Launch(LaunchOpening::State(_))
            | NativeOpening::Market(MarketOpening::Pool(_))
    ) {
        return Ok(None);
    }
    let root = opening
        .dependency_root()
        .ok_or(StoreError::Decode("native market definition root"))?;
    let definition = read(txn, root.0)?
        .ok_or(StoreError::Decode("native market definition missing"))?
        .opening;
    opening
        .check_dependency(Some(definition))
        .map_err(|_| StoreError::Decode("native market definition binding"))?;
    match definition {
        NativeOpening::Launch(LaunchOpening::Definition(definition)) => {
            Ok(Some(NativeAssetLookup::MarketForAsset(definition.asset)))
        }
        NativeOpening::Market(MarketOpening::Definition(definition))
            if definition.base_is_noid() =>
        {
            Ok(Some(NativeAssetLookup::MarketForAsset(definition.quote)))
        }
        NativeOpening::Market(MarketOpening::Definition(_)) => Ok(None),
        _ => Err(StoreError::Decode("native market definition kind")),
    }
}

fn initialize_market_index(txn: &Transaction<'_, RW, NoWriteMap>) -> Result<(), StoreError> {
    let meta = txn.open_table(Some(META))?;
    match txn.get::<Vec<u8>>(&meta, MARKET_INDEX_VERSION_KEY)? {
        Some(version) if version == [2] => return Ok(()),
        Some(version) if version == [1] => {}
        Some(_) => return Err(StoreError::Decode("native market index version")),
        None => {}
    }
    let data = txn.open_table(Some(DATA))?;
    let assets = txn.open_table(Some(ASSET))?;
    let mut cursor = txn.cursor(&data)?;
    let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
    while let Some((key, value)) = item {
        let root: Digest = key
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Decode("native market source key"))?;
        let record = decode(root, &value)?;
        if record.live_slots != 0 {
            if let Some(asset) = derived_lookup(txn, record.opening)? {
                let key = asset.key();
                if txn
                    .get::<Vec<u8>>(&assets, &key)?
                    .is_some_and(|old| old != root)
                {
                    return Err(StoreError::Decode("duplicate native market asset"));
                }
                txn.put(&assets, key, root, WriteFlags::empty())?;
            }
        }
        item = cursor.next()?;
    }
    txn.put(&meta, MARKET_INDEX_VERSION_KEY, [2u8], WriteFlags::empty())?;
    Ok(())
}

/// Cache entries have zero references and acquire wallet/catalog indexes only
/// when the atomic canonical State commit makes them live.
pub(crate) fn cache(
    txn: &Transaction<'_, RW, NoWriteMap>,
    height: u64,
    openings: &[NativeOpening],
) -> Result<(), StoreError> {
    if openings.len() > 2 * BLOCK_MAX_ACTIONS {
        return Err(StoreError::Decode("native payload cache batch"));
    }
    let data = txn.open_table(Some(DATA))?;
    let pending = txn.open_table(Some(PENDING))?;
    for &opening in openings {
        opening
            .validate()
            .map_err(|_| StoreError::Decode("native cached opening"))?;
        let root = opening.root().0;
        if let Some(old) = read(txn, root)? {
            if old.opening != opening {
                return Err(StoreError::Decode("conflicting native preimage"));
            }
            continue;
        }
        if txn.table_stat(&pending)?.entries() >= NATIVE_PENDING_PAYLOAD_LIMIT {
            let oldest: Option<(Vec<u8>, Vec<u8>)> = txn.cursor(&pending)?.first()?;
            let (key, _) = oldest.ok_or(StoreError::Decode("native pending count"))?;
            if key.len() != 40 {
                return Err(StoreError::Decode("native pending key"));
            }
            let root: Digest = key[8..].try_into().unwrap();
            let record =
                read(txn, root)?.ok_or(StoreError::Decode("native pending opening missing"))?;
            if record.was_canonical
                || record.is_referenced()
                || age_key(record.last_seen_height, root).as_slice() != key
            {
                return Err(StoreError::Decode("native pending age mismatch"));
            }
            txn.del(&data, root, None)?;
            txn.del(&pending, key, None)?;
        }
        let record = NativePayloadRecord {
            opening,
            live_slots: 0,
            auxiliary_refs: 0,
            last_seen_height: height,
            was_canonical: false,
        };
        txn.put(&data, root, encode(record)?, WriteFlags::empty())?;
        txn.put(&pending, age_key(height, root), [], WriteFlags::empty())?;
    }
    Ok(())
}

/// Stage records from an accepted body or authenticated State in its write transaction.
pub(crate) fn stage_canonical(
    txn: &Transaction<'_, RW, NoWriteMap>,
    height: u64,
    openings: &[NativeOpening],
) -> Result<(), StoreError> {
    if openings.len() > 2 * BLOCK_MAX_ACTIONS {
        return Err(StoreError::Decode("native accepted record batch"));
    }
    let data = txn.open_table(Some(DATA))?;
    let pending = txn.open_table(Some(PENDING))?;
    let retired = txn.open_table(Some(RETIRED))?;
    for &opening in openings {
        opening
            .validate()
            .map_err(|_| StoreError::Decode("native accepted record"))?;
        let root = opening.root().0;
        if let Some(old) = read(txn, root)? {
            if old.opening != opening {
                return Err(StoreError::Decode("conflicting native preimage"));
            }
            if old.was_canonical {
                continue;
            }
            if !txn.del(&pending, age_key(old.last_seen_height, root), None)? {
                return Err(StoreError::Decode("native pending age missing"));
            }
        }
        let record = NativePayloadRecord {
            opening,
            live_slots: 0,
            auxiliary_refs: 0,
            last_seen_height: height,
            was_canonical: true,
        };
        txn.put(&data, root, encode(record)?, WriteFlags::empty())?;
        txn.put(&retired, age_key(height, root), [], WriteFlags::empty())?;
    }
    Ok(())
}

pub(crate) fn native_slot_root(slot: SlotValue) -> Result<Option<Digest>, StoreError> {
    let id = slot.creation_id();
    if id & (3u64 << 62) != NATIVE_CREATION_TAG {
        return Ok(None);
    }
    native_sequence(id).map_err(|_| StoreError::Decode("native slot incarnation"))?;
    let mut root = [0; 32];
    root[..16].copy_from_slice(&slot.owner_hi.0.to_le_bytes());
    root[16..].copy_from_slice(&slot.owner_lo.0.to_le_bytes());
    Ok(Some(root))
}

pub(crate) fn apply_slot_changes(
    txn: &Transaction<'_, RW, NoWriteMap>,
    height: u64,
    changes: &[(SlotValue, SlotValue)],
) -> Result<(), StoreError> {
    if changes.len() > BLOCK_MAX_ACTIONS {
        return Err(StoreError::Decode("native slot delta bound"));
    }
    let mut counts: BTreeMap<Digest, (u64, u64, Option<u64>)> = BTreeMap::new();
    for &(before, after) in changes {
        for (slot, old) in [(before, true), (after, false)] {
            let Some(root) = native_slot_root(slot)? else {
                continue;
            };
            let count = counts.entry(root).or_insert((0, 0, Some(slot.amount())));
            if count.2 != Some(slot.amount()) {
                return Err(StoreError::Decode("native State amount binding"));
            }
            if old {
                count.0 += 1
            } else {
                count.1 += 1
            }
        }
    }
    update_refs(txn, height, counts)
}

fn update_refs(
    txn: &Transaction<'_, RW, NoWriteMap>,
    height: u64,
    counts: BTreeMap<Digest, (u64, u64, Option<u64>)>,
) -> Result<(), StoreError> {
    let mut updates = Vec::with_capacity(counts.len() * 2);
    let mut dependencies: BTreeMap<Digest, (u64, u64)> = BTreeMap::new();
    for (root, (removed, added, amount)) in counts {
        let old = read(txn, root)?.ok_or(StoreError::Decode("native reference payload missing"))?;
        if old.opening.is_auxiliary() || amount.is_some_and(|n| n != old.opening.amount_micronoid())
        {
            return Err(StoreError::Decode("native State amount or carrier binding"));
        }
        let live_slots = old
            .live_slots
            .checked_sub(removed)
            .and_then(|n| n.checked_add(added))
            .ok_or(StoreError::Decode("native reference count"))?;
        if removed > 0 && !old.was_canonical {
            return Err(StoreError::Decode("native preimage was not canonical"));
        }
        if !old.opening.allows_duplicate_carriers() && live_slots > 1 {
            return Err(StoreError::Decode("duplicate native object"));
        }
        if let Some(dependency) = old.opening.dependency_root() {
            let value =
                read(txn, dependency.0)?.ok_or(StoreError::Decode("native dependency missing"))?;
            old.opening
                .check_dependency(Some(value.opening))
                .map_err(|_| StoreError::Decode("native dependency binding"))?;
            let delta = dependencies.entry(dependency.0).or_default();
            if old.live_slots != 0 && live_slots == 0 {
                delta.0 += 1;
            }
            if old.live_slots == 0 && live_slots != 0 {
                delta.1 += 1;
            }
        }
        let next = NativePayloadRecord {
            live_slots,
            last_seen_height: old.last_seen_height.max(height),
            was_canonical: true,
            ..old
        };
        updates.push((root, old, next));
    }
    for (root, (removed, added)) in dependencies {
        if removed == 0 && added == 0 {
            continue;
        }
        let old = read(txn, root)?.ok_or(StoreError::Decode("native auxiliary payload missing"))?;
        if !old.opening.is_auxiliary() || old.live_slots != 0 {
            return Err(StoreError::Decode("native auxiliary reference class"));
        }
        let auxiliary_refs = old
            .auxiliary_refs
            .checked_sub(removed)
            .and_then(|n| n.checked_add(added))
            .ok_or(StoreError::Decode("native auxiliary reference count"))?;
        let next = NativePayloadRecord {
            auxiliary_refs,
            last_seen_height: old.last_seen_height.max(height),
            was_canonical: true,
            ..old
        };
        updates.push((root, old, next));
    }
    let owners = txn.open_table(Some(OWNER))?;
    let assets = txn.open_table(Some(ASSET))?;
    for &(root, old, next) in &updates {
        if old.live_slots == 0 || next.live_slots != 0 {
            continue;
        }
        for owner in authorities(txn, old.opening)? {
            if !txn.del(&owners, owner_key(owner, root), None)? {
                return Err(StoreError::Decode("native owner index missing"));
            }
        }
        for asset in [lookup(old.opening), derived_lookup(txn, old.opening)?]
            .into_iter()
            .flatten()
        {
            let key = asset.key();
            if txn.get::<Vec<u8>>(&assets, &key)?.as_deref() != Some(root.as_slice()) {
                return Err(StoreError::Decode("native asset index mismatch"));
            }
            txn.del(&assets, key, None)?;
        }
    }
    for &(root, old, next) in &updates {
        if old.live_slots != 0 || next.live_slots == 0 {
            continue;
        }
        for owner in authorities(txn, next.opening)? {
            let key = owner_key(owner, root);
            if txn.get::<Vec<u8>>(&owners, &key)?.is_some() {
                return Err(StoreError::Decode("native owner index duplicate"));
            }
            txn.put(&owners, key, [], WriteFlags::empty())?;
        }
        for asset in [lookup(next.opening), derived_lookup(txn, next.opening)?]
            .into_iter()
            .flatten()
        {
            let key = asset.key();
            if txn.get::<Vec<u8>>(&assets, &key)?.is_some() {
                return Err(StoreError::Decode("native asset identity duplicate"));
            }
            txn.put(&assets, key, root, WriteFlags::empty())?;
        }
    }
    let data = txn.open_table(Some(DATA))?;
    let pending = txn.open_table(Some(PENDING))?;
    let retired = txn.open_table(Some(RETIRED))?;
    for (root, old, next) in updates {
        if !old.is_referenced() {
            let table = if old.was_canonical {
                &retired
            } else {
                &pending
            };
            if !txn.del(table, age_key(old.last_seen_height, root), None)? {
                return Err(StoreError::Decode("native age index missing"));
            }
        }
        txn.put(&data, root, encode(next)?, WriteFlags::empty())?;
        if !next.is_referenced() {
            txn.put(
                &retired,
                age_key(next.last_seen_height, root),
                [],
                WriteFlags::empty(),
            )?;
        }
    }
    Ok(())
}

/// Reset derived references before streaming one authenticated State.
pub(crate) fn clear_live_refs(
    txn: &Transaction<'_, RW, NoWriteMap>,
    height: u64,
) -> Result<(), StoreError> {
    let table = txn.open_table(Some(DATA))?;
    let mut after: Option<Digest> = None;
    loop {
        let mut cursor = txn.cursor(&table)?;
        let mut row: Option<(Vec<u8>, Vec<u8>)> = match after {
            Some(root) => {
                let found: Option<(Vec<u8>, Vec<u8>)> = cursor.set_range(&root)?;
                if found
                    .as_ref()
                    .is_some_and(|(key, _)| key.as_slice() == root.as_slice())
                {
                    cursor.next()?
                } else {
                    found
                }
            }
            None => cursor.first()?,
        };
        let mut counts = BTreeMap::new();
        let mut visited = 0;
        while let Some((key, raw)) = row {
            let root: Digest = key
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Decode("native payload key"))?;
            let record = decode(root, &raw)?;
            if record.live_slots != 0 {
                counts.insert(root, (record.live_slots, 0, None));
            }
            after = Some(root);
            visited += 1;
            if visited == BLOCK_MAX_ACTIONS {
                break;
            }
            row = cursor.next()?;
        }
        drop(cursor);
        update_refs(txn, height, counts)?;
        if visited < BLOCK_MAX_ACTIONS {
            break;
        }
    }
    Ok(())
}

pub(crate) fn replace_refs(
    txn: &Transaction<'_, RW, NoWriteMap>,
    height: u64,
    desired: BTreeMap<Digest, (u64, u64)>,
) -> Result<(), StoreError> {
    let table = txn.open_table(Some(DATA))?;
    let mut cursor = txn.cursor(&table)?;
    let mut row: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
    let mut counts = BTreeMap::new();
    while let Some((key, raw)) = row {
        let root: Digest = key
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Decode("native payload key"))?;
        let record = decode(root, &raw)?;
        if record.live_slots != 0 {
            counts.insert(root, (record.live_slots, 0, None));
        }
        row = cursor.next()?;
    }
    drop(cursor);
    for (root, (count, amount)) in desired {
        if count == 0 {
            return Err(StoreError::Decode("native snapshot amount"));
        }
        let entry = counts.entry(root).or_default();
        entry.1 = count;
        entry.2 = Some(amount);
    }
    update_refs(txn, height, counts)
}

pub(crate) fn collect_slot(
    counts: &mut BTreeMap<Digest, (u64, u64)>,
    slot: SlotValue,
) -> Result<(), StoreError> {
    let Some(root) = native_slot_root(slot)? else {
        return Ok(());
    };
    let entry = counts.entry(root).or_insert((0, slot.amount()));
    if entry.1 != slot.amount() {
        return Err(StoreError::Decode("native root has conflicting amounts"));
    }
    entry.0 = entry
        .0
        .checked_add(1)
        .ok_or(StoreError::Decode("native snapshot reference overflow"))?;
    Ok(())
}

pub(crate) fn owner_roots<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
    owner: Address,
    after: Option<Digest>,
    limit: usize,
) -> Result<Vec<Digest>, StoreError> {
    if !(1..=256).contains(&limit) {
        return Err(StoreError::Decode("native owner page limit"));
    }
    let table = txn.open_table(Some(OWNER))?;
    let mut cursor = txn.cursor(&table)?;
    let start = after.map(|root| owner_key(owner, root));
    let mut row: Option<(Vec<u8>, Vec<u8>)> = cursor.set_range(
        start
            .as_ref()
            .map_or(owner.0.as_slice(), |key| key.as_slice()),
    )?;
    let mut roots = Vec::with_capacity(limit);
    while let Some((key, _)) = row {
        if key.get(..32) != Some(owner.0.as_slice()) {
            break;
        }
        if key.len() != 64 {
            return Err(StoreError::Decode("native owner key"));
        }
        let root: Digest = key[32..].try_into().unwrap();
        if Some(root) != after {
            let record =
                read(txn, root)?.ok_or(StoreError::Decode("native indexed payload missing"))?;
            if record.live_slots == 0 || !authorities(txn, record.opening)?.contains(&owner) {
                return Err(StoreError::Decode("native owner index binding"));
            }
            roots.push(root);
            if roots.len() == limit {
                break;
            }
        }
        row = cursor.next()?;
    }
    Ok(roots)
}

pub(crate) fn asset_root<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
    asset: NativeAssetLookup,
) -> Result<Option<Digest>, StoreError> {
    let table = txn.open_table(Some(ASSET))?;
    let Some(root) = txn.get::<Vec<u8>>(&table, &asset.key())? else {
        return Ok(None);
    };
    let root: Digest = root
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Decode("native asset root"))?;
    let record = read(txn, root)?.ok_or(StoreError::Decode("native asset payload missing"))?;
    let matches = match asset {
        NativeAssetLookup::MarketForAsset(_) | NativeAssetLookup::NftListing { .. } => {
            derived_lookup(txn, record.opening)? == Some(asset)
        }
        _ => lookup(record.opening) == Some(asset),
    };
    if record.live_slots == 0 || !matches {
        return Err(StoreError::Decode("native asset index binding"));
    }
    Ok(Some(root))
}

pub(crate) fn catalog_roots<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
    kind: NativeCatalogKind,
    after: Option<&[u8]>,
    limit: usize,
) -> Result<Vec<(Vec<u8>, Digest)>, StoreError> {
    if !(1..=256).contains(&limit) || after.is_some_and(|key| !kind.check_key(key)) {
        return Err(StoreError::Decode("native catalogue page bounds"));
    }
    let prefix = kind.key_shape().0.to_be_bytes();
    let table = txn.open_table(Some(ASSET))?;
    let mut cursor = txn.cursor(&table)?;
    let mut row: Option<(Vec<u8>, Vec<u8>)> = cursor.set_range(after.unwrap_or(&prefix))?;
    let mut roots = Vec::with_capacity(limit);
    while let Some((key, raw)) = row {
        if !key.starts_with(&prefix) {
            break;
        }
        if !kind.check_key(&key) {
            return Err(StoreError::Decode("native catalogue index key"));
        }
        if Some(key.as_slice()) != after {
            let root: Digest = raw
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Decode("native catalogue root"))?;
            let record =
                read(txn, root)?.ok_or(StoreError::Decode("native catalogue payload missing"))?;
            let lookup = if matches!(
                kind,
                NativeCatalogKind::Markets | NativeCatalogKind::NftListings
            ) {
                derived_lookup(txn, record.opening)?
            } else {
                lookup(record.opening)
            };
            if record.live_slots != 1 || lookup.is_none_or(|lookup| lookup.key() != key) {
                return Err(StoreError::Decode("native catalogue index binding"));
            }
            roots.push((key, root));
            if roots.len() == limit {
                break;
            }
        }
        row = cursor.next()?;
    }
    Ok(roots)
}

pub(crate) fn prune(txn: &Transaction<'_, RW, NoWriteMap>, height: u64) -> Result<(), StoreError> {
    let retention = UNDO_RETENTION_DEPTH.max(RETAINED_BLOCK_SERVING_DEPTH);
    let Some(floor) = height.checked_sub(retention) else {
        return Ok(());
    };
    let data = txn.open_table(Some(DATA))?;
    let mut budget = BLOCK_MAX_ACTIONS * 2;
    for (table_name, canonical) in [(RETIRED, true), (PENDING, false)] {
        let table = txn.open_table(Some(table_name))?;
        while budget > 0 {
            let row: Option<(Vec<u8>, Vec<u8>)> = txn.cursor(&table)?.first()?;
            let Some((key, _)) = row else { break };
            if key.len() != 40 {
                return Err(StoreError::Decode("native age key"));
            }
            let age = u64::from_be_bytes(key[..8].try_into().unwrap());
            if age >= floor {
                break;
            }
            let root: Digest = key[8..].try_into().unwrap();
            let record =
                read(txn, root)?.ok_or(StoreError::Decode("native aged payload missing"))?;
            if record.is_referenced()
                || record.was_canonical != canonical
                || record.last_seen_height != age
            {
                return Err(StoreError::Decode("native aged payload binding"));
            }
            txn.del(&data, root, None)?;
            txn.del(&table, key, None)?;
            budget -= 1;
        }
    }
    Ok(())
}
