// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::{media, State};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Filter {
    #[default]
    All,
    Collections,
    Singles,
}
#[derive(Debug, Default)]
pub struct Browse {
    pub search: String,
    pub filter: Filter,
    pub page: usize,
}
#[derive(Debug, Clone)]
pub struct Card {
    pub collection: [u8; 32],
    pub serial: Option<u64>,
    pub metadata: [u8; 32],
    pub fallback: Option<[u8; 32]>,
    pub title: String,
    pub count: usize,
    pub ask: Option<u64>,
    pub creator: bool,
    pub prepared: bool,
    pub pending: bool,
}
impl State {
    pub fn nft_matches(
        &self,
        id: &[u8; 32],
        serial: Option<u64>,
        title: &str,
        query: &str,
    ) -> bool {
        query.is_empty()
            || (serial.is_some() || self.collection_manifest(id).is_some())
                && title.to_lowercase().contains(query)
            || self
                .collection_manifest(id)
                .is_some_and(|manifest| manifest.name.to_lowercase().contains(query))
            || query.len() >= 4 && hex::encode(id).contains(query)
            || serial.is_some_and(|serial| serial.to_string() == query)
    }
    pub fn nft_browse(&self, market: bool) -> &Browse {
        if market {
            &self.nft_market_browse
        } else if self.nft_background_page() == super::Page::Listings
            || self.nft_group_listed_only
                && self.nft_background_page() == super::Page::NftCollectionDetail
        {
            &self.nft_listed_browse
        } else {
            &self.nft_owned_browse
        }
    }
    pub fn nft_browse_mut(&mut self, market: bool) -> &mut Browse {
        if market {
            &mut self.nft_market_browse
        } else if self.nft_background_page() == super::Page::Listings
            || self.nft_group_listed_only
                && self.nft_background_page() == super::Page::NftCollectionDetail
        {
            &mut self.nft_listed_browse
        } else {
            &mut self.nft_owned_browse
        }
    }
    pub fn nft_standalone(&self, id: &[u8; 32]) -> bool {
        self.live
            .collections
            .get(id)
            .map(|c| c.maximum)
            .or_else(|| self.nft_collections.collections.get(id).map(|c| c.maximum))
            == Some(1)
    }
    pub fn nft_item_name(&self, metadata: &[u8; 32], serial: u64) -> String {
        self.library
            .manifest(metadata)
            .filter(|b| b.kind == media::Kind::Nft)
            .map_or_else(|| format!("NFT #{serial}"), |b| b.name.clone())
    }
    pub fn nft_cards(&self, market: bool, group: Option<[u8; 32]>, listed_only: bool) -> Vec<Card> {
        let browse = self.nft_browse(market);
        let query = browse.search.trim().to_lowercase();
        let mut groups = BTreeMap::<[u8; 32], Card>::new();
        let mut singles = vec![];
        let mut add =
            |id: [u8; 32], serial: u64, metadata: [u8; 32], ask: Option<u64>, pending: bool| {
                if group.is_some_and(|g| g != id) {
                    return;
                }
                let title = self.nft_item_name(&metadata, serial);
                let group_name = self.collection_name(&id);
                if !self.nft_matches(&id, Some(serial), &title, &query) {
                    return;
                }
                let standalone = self.nft_standalone(&id);
                if group.is_none()
                    && ((browse.filter == Filter::Collections && standalone)
                        || (browse.filter == Filter::Singles && !standalone))
                {
                    return;
                }
                if group.is_some() || standalone || listed_only {
                    singles.push(Card {
                        collection: id,
                        serial: Some(serial),
                        metadata,
                        fallback: None,
                        title,
                        count: 1,
                        ask,
                        creator: false,
                        prepared: false,
                        pending,
                    });
                } else {
                    let item = groups.entry(id).or_insert_with(|| Card {
                        collection: id,
                        serial: None,
                        metadata: self.collection_metadata(&id).unwrap_or(metadata),
                        fallback: Some(metadata),
                        title: group_name,
                        count: 0,
                        ask: None,
                        creator: self.live.collections.contains_key(&id),
                        prepared: false,
                        pending: true,
                    });
                    item.count += 1;
                    item.pending &= pending;
                    if !pending {
                        item.ask = match (item.ask, ask) {
                            (Some(a), Some(b)) => Some(a.min(b)),
                            (a, None) => a,
                            (None, b) => b,
                        };
                    }
                }
            };
        if market {
            let height = self
                .listings
                .key
                .as_ref()
                .map_or(0, |k| k.height.saturating_add(1));
            for item in self
                .listings
                .listings
                .values()
                .filter(|i| i.ready && height < i.expiry)
            {
                add(
                    item.collection,
                    item.serial,
                    item.metadata,
                    Some(item.ask),
                    item.reserved,
                );
            }
        } else {
            for item in self
                .live
                .nfts
                .values()
                .filter(|i| !listed_only || i.listing.is_some())
            {
                add(
                    item.collection,
                    item.serial,
                    item.metadata,
                    item.listing.map(|p| p.0),
                    item.reserved,
                );
            }
        }
        if !market && group.is_none() && !listed_only {
            for collection in self.live.collections.values() {
                let prepared = collection.unfinished_nft();
                if collection.maximum == 1 && !prepared {
                    continue;
                }
                if (browse.filter == Filter::Collections && prepared)
                    || (browse.filter == Filter::Singles && !prepared)
                {
                    continue;
                }
                let title = if prepared {
                    self.nft_item_name(&collection.metadata, 1)
                } else {
                    self.collection_name(&collection.id)
                };
                if !self.nft_matches(&collection.id, prepared.then_some(1), &title, &query) {
                    continue;
                }
                groups.entry(collection.id).or_insert_with(|| Card {
                    collection: collection.id,
                    serial: None,
                    metadata: collection.metadata,
                    fallback: None,
                    title,
                    count: 0,
                    ask: None,
                    creator: true,
                    prepared,
                    pending: collection.reserved,
                });
            }
        }
        let mut cards = groups.into_values().collect::<Vec<_>>();
        cards.extend(singles);
        cards.sort_by_key(|c| (!c.creator, c.collection, c.serial));
        cards
    }
}
