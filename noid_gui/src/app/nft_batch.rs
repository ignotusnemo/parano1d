// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::assets::{
    catalog,
    nft_batch::{self, LoadedImages},
    Page,
};

impl App {
    pub(super) fn choose_nft_batch_images(&mut self) -> Task<Message> {
        if self.section != Section::Nfts
            || self.assets.nft_page != Page::MintNfts
            || self.assets.nft_batch.loading
        {
            return Task::none();
        }
        let Some(collection) = self.assets.nft_group else {
            return Task::none();
        };
        if let Err(error) = self.assets.mintable_collection(&collection) {
            self.assets.nft_batch.error = Some(error);
            return Task::none();
        }
        let available = self
            .assets
            .nft_batch_limit()
            .saturating_sub(self.assets.nft_batch.items.len());
        if available == 0 {
            self.assets.nft_batch.error =
                Some("This batch is full. Mint it before adding more NFTs.".into());
            return Task::none();
        }
        let Some(key) = self.assets.live.key.clone() else {
            return Task::none();
        };
        let generation = self.assets.nft_batch.begin();
        let existing_bytes = self.assets.nft_batch.bytes();
        self.assets.operation.edit();
        Task::perform(
            async move {
                let result = async {
                    let selected = rfd::AsyncFileDialog::new()
                        .set_title("Choose NFT images")
                        .add_filter("Images", &["png", "jpg", "jpeg", "webp"])
                        .pick_files()
                        .await;
                    let Some(files) = selected else {
                        return Ok(None);
                    };
                    let paths = files
                        .into_iter()
                        .map(|file| file.path().to_path_buf())
                        .collect();
                    tokio::task::spawn_blocking(move || {
                        nft_batch::prepare_files(paths, available, existing_bytes)
                    })
                    .await
                    .map_err(|_| "The NFT images could not be prepared.".to_owned())?
                    .map(Some)
                }
                .await;
                LoadedImages {
                    generation,
                    owner: key.owner,
                    key_index: key.key_index,
                    collection,
                    result,
                }
            },
            Message::NativeNftBatchImagesLoaded,
        )
    }

    pub(super) fn finish_nft_batch_images(&mut self, loaded: LoadedImages) {
        if loaded.generation != self.assets.nft_batch.generation || !self.assets.nft_batch.loading {
            return;
        }
        self.assets.nft_batch.loading = false;
        if self.assets.nft_page != Page::MintNfts
            || self.assets.nft_group != Some(loaded.collection)
            || self.snapshot.active_address().address != loaded.owner
            || self.snapshot.active_address().key_index != loaded.key_index
        {
            return;
        }
        match loaded.result {
            Ok(Some(images)) => {
                if self.assets.nft_batch.items.len() + images.len() > self.assets.nft_batch_limit()
                {
                    self.assets.nft_batch.error =
                        Some("The batch size changed. Choose fewer images.".into());
                    return;
                }
                self.assets.nft_batch.items.extend(
                    images
                        .into_iter()
                        .map(|image| nft_batch::Item { image, name: None }),
                );
                self.assets.operation.edit();
            }
            Ok(None) => {}
            Err(error) => self.assets.nft_batch.error = Some(error),
        }
    }

    pub(super) fn refresh_native_collections(&mut self) -> Task<Message> {
        if self.section != Section::Nfts
            || self.backend_state != BackendState::Online
            || !self.snapshot.network.synced
            || self.shutting_down
            || self.address_operation.is_some()
            || self.secret_action_in_flight
            || !self
                .assets
                .live
                .protocol
                .as_ref()
                .is_some_and(|protocol| protocol.active_at_next_block)
        {
            return Task::none();
        }
        let catalog = &mut self.assets.nft_collections;
        if catalog.key.is_none() || catalog.loading || catalog.complete || catalog.error.is_some() {
            return Task::none();
        }
        catalog.loading = true;
        let generation = catalog.generation;
        let cursor = catalog.next.clone();
        let backend = self.backend.clone();
        Task::perform(
            async move {
                backend
                    .native_catalog_page(catalog::Kind::Collections, cursor)
                    .await
                    .map(Box::new)
            },
            move |result| Message::NativeCollectionsLoaded(generation, result),
        )
    }

    pub(super) fn finish_native_collections(
        &mut self,
        generation: u64,
        result: Result<Box<catalog::Page>, String>,
    ) -> Task<Message> {
        let catalog = &mut self.assets.nft_collections;
        if catalog.generation != generation {
            return Task::none();
        }
        catalog.loading = false;
        match result {
            Ok(page) => {
                if let Err(error) = catalog.ingest(*page) {
                    catalog.error = Some(error);
                }
            }
            Err(error) => catalog.error = Some(error),
        }
        Task::batch([
            self.refresh_native_collections(),
            self.refresh_native_media(),
        ])
    }
}
