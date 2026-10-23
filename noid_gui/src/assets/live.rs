// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Confirmed native holdings, loaded in bounded pages from the local node.

use noid_tx::native_assets::{
    native_sequence, nft_market::NftMarketOpening, NativeOpening, MAX_NATIVE_OPENING_BYTES,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub owner: String,
    pub key_index: u32,
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    pub owner: String,
    pub height: u64,
    pub block_hash: String,
    pub after_root: Option<String>,
    pub from_slot: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Protocol {
    pub activation_height: Option<u64>,
    pub active_at_next_block: bool,
    pub runtime_available: bool,
    #[serde(default)]
    pub initial_creator_purchase: bool,
    #[serde(default)]
    pub nft_batch_limit: Option<usize>,
    pub token_decimals: u8,
    pub minimum_launch_whole_tokens: String,
    pub minimum_backing_micronoid_per_whole_token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Holding {
    pub root: String,
    pub kind: u16,
    pub opening_hex: String,
    pub dependency_hex: Option<String>,
    pub slot_index: u32,
    pub creation_id: String,
    pub amount_micronoid: String,
    pub unlock_height: u64,
    #[serde(default)]
    pub reserved: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Page {
    pub owner: String,
    pub key_index: Option<u32>,
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub holdings: Vec<Holding>,
    pub next: Option<Cursor>,
}

#[derive(Debug, Clone)]
pub struct Loaded {
    pub protocol: Option<Protocol>,
    pub page: Page,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub id: [u8; 32],
    pub units: u128,
    pub locked_units: u128,
    pub reserved_units: u128,
    pub outputs: usize,
    pub carriers: Vec<TokenOutput>,
    pub issued_here: bool,
}

#[derive(Debug, Clone)]
pub struct TokenOutput {
    pub slot: u32,
    pub creation_id: u64,
    pub units: u64,
    pub unlock_height: u64,
    pub reserved: bool,
}

#[derive(Debug, Clone)]
pub struct Nft {
    pub collection: [u8; 32],
    pub serial: u64,
    pub metadata: [u8; 32],
    pub unlock_height: u64,
    pub listing: Option<(u64, u64)>,
    pub reserved: bool,
}

#[derive(Debug, Clone)]
pub struct Collection {
    pub id: [u8; 32],
    pub metadata: [u8; 32],
    pub maximum: u64,
    pub issued: u64,
    pub reserved: bool,
}

impl Collection {
    pub fn unfinished_nft(&self) -> bool {
        self.maximum == 1 && self.issued == 0 && !self.reserved
    }
}

#[derive(Debug, Default)]
pub struct State {
    pub key: Option<Key>,
    pub protocol: Option<Protocol>,
    pub loading: bool,
    pub complete: bool,
    pub error: Option<String>,
    pub generation: u64,
    pub next: Option<Cursor>,
    pub tokens: BTreeMap<[u8; 32], Token>,
    pub nfts: BTreeMap<([u8; 32], u64), Nft>,
    pub collections: BTreeMap<[u8; 32], Collection>,
    pub selected_asset: Option<[u8; 32]>,
    pub selected_nft: Option<([u8; 32], u64)>,
    pub loaded_outputs: usize,
    slots: BTreeSet<u32>,
    cursors: BTreeSet<String>,
    displayed_key: Option<Key>,
    refresh: Option<Box<State>>,
}

impl State {
    pub fn operation_asset(&self) -> Option<[u8; 32]> {
        self.selected_asset
            .or_else(|| self.tokens.keys().next().copied())
    }

    pub fn spendable_units(&self, asset: [u8; 32]) -> u128 {
        self.tokens.get(&asset).map_or(0, |token| {
            token
                .units
                .saturating_sub(token.locked_units)
                .saturating_sub(token.reserved_units)
        })
    }

    pub fn observe(&mut self, key: Key) {
        if self.key.as_ref() == Some(&key) {
            return;
        }
        self.reload(Some(key));
    }

    pub fn has_snapshot(&self) -> bool {
        self.complete || self.displayed_key.is_some()
    }

    pub fn display_key(&self) -> Option<&Key> {
        self.displayed_key.as_ref().or(self.key.as_ref())
    }

    fn reload(&mut self, key: Option<Key>) {
        let same_owner = self
            .key
            .as_ref()
            .zip(key.as_ref())
            .is_some_and(|(old, key)| old.owner == key.owner && old.key_index == key.key_index);
        let protocol = same_owner.then(|| self.protocol.clone()).flatten();
        let generation = self.generation.wrapping_add(1);
        if same_owner && self.has_snapshot() {
            // Publish a complete replacement while keeping the current view stable.
            self.displayed_key = self.display_key().cloned();
            self.refresh = Some(Box::new(Self {
                key: key.clone(),
                protocol,
                ..Self::default()
            }));
            self.key = key;
            self.generation = generation;
            self.loading = false;
            self.complete = false;
            self.error = None;
            self.next = None;
            return;
        }
        let selected_asset = same_owner.then_some(self.selected_asset).flatten();
        let selected_nft = same_owner.then_some(self.selected_nft).flatten();
        *self = Self {
            key,
            protocol,
            generation,
            selected_asset,
            selected_nft,
            ..Self::default()
        };
    }

    pub fn retry(&mut self) {
        self.reload(self.key.clone());
    }

    pub fn ingest(&mut self, loaded: Loaded) -> Result<(), String> {
        if let Some(refresh) = self.refresh.as_mut() {
            refresh.ingest(loaded)?;
            self.next = refresh.next.clone();
            if refresh.complete {
                let mut current = *self.refresh.take().expect("completed holdings refresh");
                current.generation = self.generation;
                current.selected_asset = self.selected_asset;
                current.selected_nft = self.selected_nft;
                *self = current;
            }
            return Ok(());
        }
        if loaded.protocol.as_ref().is_some_and(|protocol| {
            protocol.token_decimals != noid_tx::native_assets::TOKEN_DECIMALS
        }) {
            return Err("This node uses an unsupported token precision.".into());
        }
        let key = self
            .key
            .as_ref()
            .ok_or("Native wallet address is not loaded.")?;
        let page = loaded.page;
        if (
            page.owner.as_str(),
            page.key_index,
            page.height,
            page.block_hash.as_str(),
            page.state_root.as_str(),
        ) != (
            key.owner.as_str(),
            Some(key.key_index),
            key.height,
            key.block_hash.as_str(),
            key.state_root.as_str(),
        ) {
            return Err("Wallet address or State changed. Refreshing native holdings.".into());
        }
        if page.holdings.len() > 64 {
            return Err("Native wallet page exceeds its requested size.".into());
        }
        let mut next_identity = None;
        if let Some(cursor) = &page.next {
            if cursor.owner != key.owner
                || cursor.height != key.height
                || cursor.block_hash != key.block_hash
            {
                return Err("Native wallet continuation has a different address or State.".into());
            }
            let identity = serde_json::to_string(cursor).map_err(|e| e.to_string())?;
            if self.cursors.contains(&identity) {
                return Err("Native wallet continuation did not advance.".into());
            }
            next_identity = Some(identity);
        }
        let mut checked = Vec::with_capacity(page.holdings.len());
        let mut page_slots = BTreeSet::new();
        for item in page.holdings {
            if self.slots.contains(&item.slot_index) || !page_slots.insert(item.slot_index) {
                return Err("Native wallet returned a duplicate State slot.".into());
            }
            let opening = decode_opening(&item.opening_hex)?;
            let dependency = item
                .dependency_hex
                .as_deref()
                .map(decode_opening)
                .transpose()?;
            let creation_id = integer(&item.creation_id)?;
            let amount = integer(&item.amount_micronoid)?;
            native_sequence(creation_id).map_err(|e| e.to_string())?;
            if item.root != hex::encode(opening.root().0)
                || item.kind != opening.kind() as u16
                || item.unlock_height != opening.unlock_height()
            {
                return Err("Native wallet opening differs from its State record.".into());
            }
            if !opening
                .owners_with_dependency(dependency)
                .map_err(|e| e.to_string())?
                .iter()
                .any(|owner| owner.to_bech32() == key.owner)
            {
                return Err("Native wallet holding belongs to another address.".into());
            }
            opening
                .check_input_binding(
                    &noid_tx::TxInput {
                        slot_index: item.slot_index,
                        amount,
                        creation_id,
                    },
                    opening.root(),
                )
                .map_err(|e| e.to_string())?;
            checked.push((
                item.slot_index,
                creation_id,
                item.reserved,
                opening,
                dependency,
            ));
        }
        let mut token_changes = BTreeMap::new();
        let mut nft_changes = BTreeMap::new();
        let mut collection_changes = BTreeMap::new();
        for (slot, creation_id, reserved, opening, dependency) in &checked {
            match opening {
                NativeOpening::TokenBalance(balance) => {
                    let token = token_changes.entry(balance.asset.0).or_insert_with(|| {
                        self.tokens.get(&balance.asset.0).cloned().unwrap_or(Token {
                            id: balance.asset.0,
                            units: 0,
                            locked_units: 0,
                            reserved_units: 0,
                            outputs: 0,
                            carriers: Vec::new(),
                            issued_here: false,
                        })
                    });
                    token.units = token
                        .units
                        .checked_add(u128::from(balance.units))
                        .ok_or("Native token balance overflow.")?;
                    if balance.unlock_height > key.height.saturating_add(1) {
                        token.locked_units = token
                            .locked_units
                            .checked_add(u128::from(balance.units))
                            .ok_or("Native token locked balance overflow.")?;
                    } else if *reserved {
                        token.reserved_units = token
                            .reserved_units
                            .checked_add(u128::from(balance.units))
                            .ok_or("Native token pending balance overflow.")?;
                    }
                    token.outputs += 1;
                    token.carriers.push(TokenOutput {
                        slot: *slot,
                        creation_id: *creation_id,
                        units: balance.units,
                        unlock_height: balance.unlock_height,
                        reserved: *reserved,
                    });
                }
                NativeOpening::FungibleDefinition(definition) => {
                    token_changes
                        .entry(definition.asset.0)
                        .or_insert_with(|| {
                            self.tokens
                                .get(&definition.asset.0)
                                .cloned()
                                .unwrap_or(Token {
                                    id: definition.asset.0,
                                    units: 0,
                                    locked_units: 0,
                                    reserved_units: 0,
                                    outputs: 0,
                                    carriers: Vec::new(),
                                    issued_here: false,
                                })
                        })
                        .issued_here = true;
                }
                NativeOpening::NftItem(item) => {
                    let id = (item.collection.0, item.serial);
                    if self.nfts.contains_key(&id)
                        || nft_changes
                            .insert(
                                id,
                                Nft {
                                    collection: item.collection.0,
                                    serial: item.serial,
                                    metadata: item.metadata,
                                    unlock_height: item.unlock_height,
                                    listing: None,
                                    reserved: *reserved,
                                },
                            )
                            .is_some()
                    {
                        return Err(
                            "Native NFT identity appears in more than one State slot.".into()
                        );
                    }
                }
                NativeOpening::NftCollection(collection) => {
                    let id = collection.collection.0;
                    if self.collections.contains_key(&id)
                        || collection_changes
                            .insert(
                                id,
                                Collection {
                                    id,
                                    metadata: collection.metadata,
                                    maximum: collection.maximum_items,
                                    issued: collection.issued_items,
                                    reserved: *reserved,
                                },
                            )
                            .is_some()
                    {
                        return Err(
                            "Native collection identity appears in more than one State slot."
                                .into(),
                        );
                    }
                }
                NativeOpening::NftMarket(NftMarketOpening::Listing(_)) => {
                    let Some(NativeOpening::NftMarket(NftMarketOpening::Definition(definition))) =
                        dependency
                    else {
                        return Err("NFT listing definition is unavailable.".into());
                    };
                    let id = (definition.collection.0, definition.serial);
                    if self.nfts.contains_key(&id)
                        || nft_changes
                            .insert(
                                id,
                                Nft {
                                    collection: definition.collection.0,
                                    serial: definition.serial,
                                    metadata: definition.metadata,
                                    unlock_height: 0,
                                    listing: Some((definition.ask, definition.expiry_height)),
                                    reserved: *reserved,
                                },
                            )
                            .is_some()
                    {
                        return Err(
                            "Native NFT identity appears in more than one State slot.".into()
                        );
                    }
                }
                _ => {}
            }
        }
        self.slots
            .extend(checked.iter().map(|(slot, _, _, _, _)| *slot));
        self.tokens.extend(token_changes);
        self.nfts.extend(nft_changes);
        self.collections.extend(collection_changes);
        if let Some(identity) = next_identity {
            self.cursors.insert(identity);
        }
        self.loaded_outputs = self.slots.len();
        if let Some(protocol) = loaded.protocol {
            self.protocol = Some(protocol);
        }
        self.next = page.next;
        self.complete = self.next.is_none();
        Ok(())
    }
}

pub(super) fn integer(value: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| "Invalid native wallet integer.".to_string())?;
    if parsed.to_string() != value {
        return Err("Invalid native wallet integer encoding.".into());
    }
    Ok(parsed)
}

pub(super) fn decode_opening(encoded: &str) -> Result<NativeOpening, String> {
    if encoded.len() > 2 * MAX_NATIVE_OPENING_BYTES {
        return Err("Native wallet opening exceeds its size bound.".into());
    }
    NativeOpening::from_bytes(
        &hex::decode(encoded).map_err(|_| "Invalid native wallet opening encoding.".to_string())?,
    )
    .map_err(|e| e.to_string())
}

pub fn units(value: u128) -> String {
    format!("{}.{:06}", value / 1_000_000, value % 1_000_000)
}
pub fn short_id(id: &[u8; 32]) -> String {
    let text = hex::encode(id);
    format!("{}…{}", &text[..8], &text[56..])
}
