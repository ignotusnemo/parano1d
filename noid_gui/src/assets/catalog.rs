// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Tip-bound public native markets and NFT listings from the local node.

use super::live::{decode_opening, integer, Holding, Key};
use noid_tx::native_assets::{
    launch::{LaunchDefinition, LaunchOpening},
    market::{MarketOpening, PoolPhase},
    nft_market::NftMarketOpening,
    NativeOpening,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Markets,
    Collections,
    NftListings,
}

impl Kind {
    fn key_shape(self) -> (u16, usize) {
        match self {
            Self::Markets => (0x8000, 34),
            Self::Collections => (4, 34),
            Self::NftListings => (0x8001, 42),
        }
    }
    fn check_key(self, key: &[u8]) -> bool {
        let (prefix, len) = self.key_shape();
        key.len() == len && key[..2] == prefix.to_be_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    pub kind: Kind,
    pub height: u64,
    pub block_hash: String,
    pub after_key: String,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Item {
    pub key: String,
    pub primary: Holding,
    pub related: Vec<Holding>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Page {
    pub kind: Kind,
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub scanned: usize,
    pub items: Vec<Item>,
    pub next: Option<Cursor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Curve,
    Dex,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Discovery {
    #[default]
    New,
    Gainers,
    Graduated,
    Liquidity,
}

#[derive(Debug, Default)]
pub struct Browse {
    pub filter: Discovery,
    pub search: String,
    pub page: usize,
    pub scroll: f32,
}
#[derive(Debug, Clone)]
pub struct Market {
    pub id: [u8; 32],
    pub metadata: [u8; 32],
    pub issuer: String,
    pub initial_supply: u64,
    pub created_order: u64,
    pub outstanding: u64,
    pub backing: u64,
    pub phase: Phase,
    pub noid: u64,
    pub inventory: u64,
    pub price_numerator: u64,
    pub price_denominator: u64,
    pub sale_units: u64,
    pub sold_units: u64,
    pub curve: Option<LaunchDefinition>,
    pub ready: bool,
    pub reserved: bool,
}
#[derive(Debug, Clone)]
pub struct Listing {
    pub collection: [u8; 32],
    pub serial: u64,
    pub seller: String,
    pub metadata: [u8; 32],
    pub ask: u64,
    pub expiry: u64,
    pub ready: bool,
    pub reserved: bool,
}

#[derive(Debug, Clone)]
pub struct Collection {
    pub id: [u8; 32],
    pub metadata: [u8; 32],
    pub creator: String,
    pub maximum: u64,
    pub issued: u64,
    pub reserved: bool,
}

fn collection(item: &Item) -> Result<Collection, String> {
    if !item.related.is_empty() {
        return Err("Unexpected collection dependencies.".into());
    }
    let (opening, _) = public(&item.primary)?;
    let NativeOpening::NftCollection(value) = opening else {
        return Err("Invalid collection definition.".into());
    };
    if hex::decode(&item.key).map_err(|_| "Invalid collection key.")?[2..] != value.collection.0 {
        return Err("The collection differs from its discovery key.".into());
    }
    Ok(Collection {
        id: value.collection.0,
        metadata: value.metadata,
        creator: value.creator.to_bech32(),
        maximum: value.maximum_items,
        issued: value.issued_items,
        reserved: item.primary.reserved,
    })
}

fn public(item: &Holding) -> Result<(NativeOpening, Option<NativeOpening>), String> {
    let opening = decode_opening(&item.opening_hex)?;
    let dependency = item
        .dependency_hex
        .as_deref()
        .map(decode_opening)
        .transpose()?;
    if item.root != hex::encode(opening.root().0)
        || item.kind != opening.kind() as u16
        || item.unlock_height != opening.unlock_height()
    {
        return Err("Discovery object differs from its State record.".into());
    }
    opening
        .check_dependency(dependency)
        .map_err(|_| "Discovery object has different terms.".to_owned())?;
    opening
        .check_input_binding(
            &noid_tx::TxInput {
                slot_index: item.slot_index,
                amount: integer(&item.amount_micronoid)?,
                creation_id: integer(&item.creation_id)?,
            },
            opening.root(),
        )
        .map_err(|_| "Discovery object differs from its live State output.".to_owned())?;
    Ok((opening, dependency))
}

fn market(item: &Item) -> Result<Market, String> {
    if item.related.len() != 2 {
        return Err("The market's token terms are incomplete.".into());
    }
    let (opening, dependency) = public(&item.primary)?;
    let (token, _) = public(&item.related[0])?;
    let (reserve, _) = public(&item.related[1])?;
    let NativeOpening::FungibleDefinition(token) = token else {
        return Err("Invalid token definition.".into());
    };
    let NativeOpening::TokenReserve(reserve) = reserve else {
        return Err("Invalid token backing.".into());
    };
    reserve
        .check_definition(&token)
        .map_err(|_| "Token backing has different terms.".to_owned())?;
    let (
        phase,
        noid,
        inventory,
        price_numerator,
        price_denominator,
        sale_units,
        sold_units,
        curve,
        ready,
    ) = match (opening, dependency) {
        (
            NativeOpening::Launch(LaunchOpening::State(state)),
            Some(NativeOpening::Launch(LaunchOpening::Definition(def))),
        ) => {
            if def.asset != token.asset
                || def.definition_root != NativeOpening::FungibleDefinition(token).root()
                || def.initial_supply != token.initial_supply
            {
                return Err("Launchpad identity differs from the token.".into());
            }
            let sold = def
                .initial_supply
                .checked_sub(state.inventory_units)
                .ok_or("Invalid launchpad inventory.")?;
            let price = def.marginal_price(sold).map_err(|e| e.to_string())?;
            (
                Phase::Curve,
                state.market_noid,
                state.inventory_units,
                price.numerator,
                price.denominator,
                def.sale_units(),
                sold,
                Some(def),
                state.phase == PoolPhase::Idle,
            )
        }
        (
            NativeOpening::Market(MarketOpening::Pool(state)),
            Some(NativeOpening::Market(MarketOpening::Definition(def))),
        ) if def.base_is_noid() && def.quote == token.asset => (
            Phase::Dex,
            state.base_reserve,
            state.quote_reserve,
            state.base_reserve,
            state.quote_reserve,
            0,
            0,
            None,
            state.phase == PoolPhase::Idle,
        ),
        _ => return Err("Unsupported native market.".into()),
    };
    let mut expected = 0x8000u16.to_be_bytes().to_vec();
    expected.extend_from_slice(&token.asset.0);
    if item.key != hex::encode(expected) {
        return Err("Market catalogue has a different asset ID.".into());
    }
    let mut slots = BTreeSet::new();
    for record in std::iter::once(&item.primary).chain(&item.related) {
        if !slots.insert(record.slot_index) {
            return Err("Market terms repeat a State output.".into());
        }
    }
    Ok(Market {
        id: token.asset.0,
        metadata: token.metadata,
        issuer: token.issuer.to_bech32(),
        initial_supply: token.initial_supply,
        created_order: integer(&item.related[0].creation_id)?,
        outstanding: reserve.outstanding_units,
        backing: reserve.reserve_micronoid,
        phase,
        noid,
        inventory,
        price_numerator,
        price_denominator,
        sale_units,
        sold_units,
        curve,
        ready,
        reserved: item.primary.reserved,
    })
}

fn listing(item: &Item) -> Result<Listing, String> {
    if !item.related.is_empty() {
        return Err("Unexpected NFT listing records.".into());
    }
    let (opening, dependency) = public(&item.primary)?;
    let (
        NativeOpening::NftMarket(NftMarketOpening::Listing(state)),
        Some(NativeOpening::NftMarket(NftMarketOpening::Definition(def))),
    ) = (opening, dependency)
    else {
        return Err("Invalid NFT listing.".into());
    };
    let mut expected = 0x8001u16.to_be_bytes().to_vec();
    expected.extend_from_slice(&def.collection.0);
    expected.extend_from_slice(&def.serial.to_be_bytes());
    if item.key != hex::encode(expected) {
        return Err("NFT catalogue has a different identity.".into());
    }
    Ok(Listing {
        collection: def.collection.0,
        serial: def.serial,
        seller: def.seller.to_bech32(),
        metadata: def.metadata,
        ask: def.ask,
        expiry: def.expiry_height,
        ready: noid_tx::native_assets::nft_market::ListingState::initial(def).ok() == Some(state),
        reserved: item.primary.reserved,
    })
}

#[derive(Debug)]
pub struct State {
    pub kind: Kind,
    pub key: Option<Key>,
    pub generation: u64,
    pub loading: bool,
    pub complete: bool,
    pub error: Option<String>,
    pub next: Option<Cursor>,
    pub markets: BTreeMap<[u8; 32], Market>,
    pub listings: BTreeMap<([u8; 32], u64), Listing>,
    pub collections: BTreeMap<[u8; 32], Collection>,
    pub selected_listing: Option<([u8; 32], u64)>,
    last_key: Option<Vec<u8>>,
    displayed_key: Option<Key>,
    refresh: Option<Box<State>>,
}

impl State {
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            key: None,
            generation: 0,
            loading: false,
            complete: false,
            error: None,
            next: None,
            markets: BTreeMap::new(),
            listings: BTreeMap::new(),
            collections: BTreeMap::new(),
            selected_listing: None,
            last_key: None,
            displayed_key: None,
            refresh: None,
        }
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
    fn reload(&mut self, key: Option<Key>) {
        let same_owner = self
            .key
            .as_ref()
            .zip(key.as_ref())
            .is_some_and(|(old, key)| old.owner == key.owner && old.key_index == key.key_index);
        let generation = self.generation.wrapping_add(1);
        if same_owner && self.has_snapshot() {
            self.displayed_key = self.displayed_key.take().or_else(|| self.key.clone());
            let mut refresh = Self::new(self.kind);
            refresh.key = key.clone();
            self.refresh = Some(Box::new(refresh));
            self.key = key;
            self.generation = generation;
            self.loading = false;
            self.complete = false;
            self.error = None;
            self.next = None;
            return;
        }
        let selected_listing = same_owner.then_some(self.selected_listing).flatten();
        *self = Self::new(self.kind);
        self.key = key;
        self.generation = generation;
        self.selected_listing = selected_listing;
    }
    pub fn retry(&mut self) {
        self.reload(self.key.clone());
    }
    pub fn ingest(&mut self, page: Page) -> Result<(), String> {
        if let Some(refresh) = self.refresh.as_mut() {
            refresh.ingest(page)?;
            self.next = refresh.next.clone();
            if refresh.complete {
                let mut current = *self.refresh.take().expect("completed catalogue refresh");
                current.generation = self.generation;
                current.selected_listing = self.selected_listing;
                *self = current;
            }
            return Ok(());
        }
        let key = self.key.as_ref().ok_or("The wallet State is not loaded.")?;
        if page.kind != self.kind
            || (
                page.height,
                page.block_hash.as_str(),
                page.state_root.as_str(),
            ) != (key.height, key.block_hash.as_str(), key.state_root.as_str())
        {
            return Err("Discovery State changed. Refresh the market list.".into());
        }
        if page.scanned > 64 || page.items.len() > page.scanned {
            return Err("The discovery page exceeds its size limit.".into());
        }
        let mut after = self.last_key.clone();
        let mut markets = Vec::new();
        let mut listings = Vec::new();
        let mut collections = Vec::new();
        for item in &page.items {
            if item.key.len() > 84 {
                return Err("Invalid discovery key size.".into());
            }
            let identity = hex::decode(&item.key).map_err(|_| "Invalid discovery key.")?;
            if !self.kind.check_key(&identity) || after.as_ref().is_some_and(|old| old >= &identity)
            {
                return Err("The discovery page repeats or reorders an asset.".into());
            }
            match self.kind {
                Kind::Markets => markets.push(market(item)?),
                Kind::NftListings => listings.push(listing(item)?),
                Kind::Collections => collections.push(collection(item)?),
            }
            after = Some(identity);
        }
        if let Some(next) = &page.next {
            if next.kind != self.kind
                || next.height != key.height
                || next.block_hash != key.block_hash
                || next.after_key.len() > 84
                || page.scanned != 64
            {
                return Err("The discovery cursor has a different State or page size.".into());
            }
            let identity = hex::decode(&next.after_key).map_err(|_| "Invalid discovery cursor.")?;
            if !self.kind.check_key(&identity)
                || self.last_key.as_ref().is_some_and(|old| old >= &identity)
                || after.as_ref().is_some_and(|last| last > &identity)
            {
                return Err("The discovery cursor did not advance.".into());
            }
            after = Some(identity);
        }
        for market in markets {
            self.markets.insert(market.id, market);
        }
        for listing in listings {
            self.listings
                .insert((listing.collection, listing.serial), listing);
        }
        for collection in collections {
            self.collections.insert(collection.id, collection);
        }
        self.last_key = after;
        self.next = page.next;
        self.complete = self.next.is_none();
        Ok(())
    }
}
