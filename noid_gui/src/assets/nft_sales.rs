// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::{
    nft_gallery::Card,
    operations::{self, Request},
    Page, State,
};

impl State {
    pub fn nft_tab(&self) -> Page {
        match self.nft_background_page() {
            Page::CreateNft | Page::CreateNftCollection => Page::CreateNft,
            Page::NftCollectionDetail if self.nft_group_listed_only => Page::Listings,
            Page::NftCollectionDetail | Page::MintNfts => Page::Collection,
            Page::NftDetail => match self.nft_home {
                Page::Marketplace | Page::NftMarketCollection => Page::Marketplace,
                Page::NftCollectionDetail if self.nft_group_listed_only => Page::Listings,
                Page::NftCollectionDetail => Page::Collection,
                page => page,
            },
            Page::NftMarketCollection => Page::Marketplace,
            page => page,
        }
    }
    pub fn nft_background_page(&self) -> Page {
        match self.nft_page {
            Page::NftBuy | Page::NftListPicker => self.nft_home,
            Page::NftSend | Page::NftList | Page::NftBurn | Page::NftCancel => {
                if self.nft_action_home == Page::NftListPicker {
                    self.nft_home
                } else {
                    self.nft_action_home
                }
            }
            page => page,
        }
    }

    pub fn can_list_nft(&self, id: [u8; 32], serial: u64) -> bool {
        self.live.complete
            && self.live.error.is_none()
            && self.live.nfts.get(&(id, serial)).is_some_and(|item| {
                !item.reserved
                    && item.listing.is_none()
                    && self
                        .live
                        .key
                        .as_ref()
                        .is_some_and(|key| item.unlock_height <= key.height.saturating_add(1))
            })
    }

    pub fn nft_sale_cards(&self) -> Vec<Card> {
        let query = self.nft_sale_browse.search.trim().to_lowercase();
        let height = self
            .live
            .display_key()
            .map_or(0, |key| key.height.saturating_add(1));
        self.live
            .nfts
            .values()
            .filter(|item| !item.reserved && item.listing.is_none() && item.unlock_height <= height)
            .filter_map(|item| {
                let title = self.nft_item_name(&item.metadata, item.serial);
                if !self.nft_matches(&item.collection, Some(item.serial), &title, &query) {
                    return None;
                }
                Some(Card {
                    collection: item.collection,
                    serial: Some(item.serial),
                    metadata: item.metadata,
                    fallback: None,
                    title,
                    count: 1,
                    ask: None,
                    creator: false,
                    prepared: false,
                    pending: false,
                })
            })
            .collect()
    }

    pub(super) fn remove_nft_listing(&mut self, id: [u8; 32], serial: u64) {
        let Some(item) = self
            .live
            .nfts
            .get(&(id, serial))
            .filter(|item| !item.reserved && self.live.complete)
        else {
            return;
        };
        if item.listing.is_none() {
            return;
        }
        let home = self.nft_background_page();
        if matches!(
            home,
            Page::Marketplace | Page::NftMarketCollection | Page::Listings | Page::Collection
        ) {
            self.nft_home = home;
        }
        self.live.selected_nft = Some((id, serial));
        self.open(Page::NftCancel);
    }

    pub fn reconcile_nft_sales(&mut self) -> bool {
        if !matches!(self.nft_page, Page::NftList | Page::NftCancel)
            || !self.live.complete
            || self.live.error.is_some()
            || self.operation.phase != operations::Phase::Submitted
        {
            return false;
        }
        let Some(key) = &self.live.key else {
            return false;
        };
        let Some(context) = &self.operation.context else {
            return false;
        };
        let Some(preview) = &self.operation.preview else {
            return false;
        };
        if key.owner != context.owner
            || key.key_index != context.key_index
            || key.height < preview.height
        {
            return false;
        }
        let Some(identity) = self.live.selected_nft else {
            return false;
        };
        let request_identity = match &preview.request {
            Request::ListNft {
                collection_id,
                serial,
                ..
            }
            | Request::CancelListing {
                collection_id,
                serial,
            } => (collection_id, serial),
            _ => return false,
        };
        if request_identity.0 != &hex::encode(identity.0)
            || request_identity.1 != &identity.1.to_string()
        {
            return false;
        }
        let Some(item) = self.live.nfts.get(&identity) else {
            self.operation.edit();
            self.open(Page::Listings);
            self.nft_notice =
                Some("This NFT has changed ownership. Check its receipt in Receipts.".into());
            return true;
        };
        match &preview.request {
            Request::CancelListing { .. } if item.listing.is_none() && !item.reserved => {
                self.operation.edit();
                self.open(Page::Listings);
                self.nft_notice = Some("Listing removed. The NFT is available in My NFTs.".into());
            }
            Request::ListNft {
                ask_micronoid,
                expiry_height,
                ..
            } if item.listing.is_some_and(|(ask, expiry)| {
                ask_micronoid == &ask.to_string() && *expiry_height == expiry
            }) =>
            {
                self.operation.edit();
                self.open(Page::Listings);
                self.nft_notice = Some("NFT listed for sale.".into());
            }
            _ => return false,
        }
        true
    }
}
