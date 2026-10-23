// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::{live, media, operations, Page, State};
use std::{path::PathBuf, sync::Arc};

pub const IMAGE_MEMORY_LIMIT: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct LoadedImages {
    pub generation: u64,
    pub owner: String,
    pub key_index: u32,
    pub collection: [u8; 32],
    pub result: Result<Option<Vec<Arc<media::PreparedImage>>>, String>,
}

#[derive(Debug)]
pub struct Item {
    pub image: Arc<media::PreparedImage>,
    pub name: Option<String>,
}

#[derive(Debug, Default)]
pub struct Draft {
    pub items: Vec<Item>,
    pub loading: bool,
    pub generation: u64,
    pub error: Option<String>,
}

impl Draft {
    pub fn cancel_loading(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.loading = false;
    }
    pub fn clear(&mut self) {
        let generation = self.generation.wrapping_add(1);
        *self = Self {
            generation,
            ..Self::default()
        };
    }
    pub fn begin(&mut self) -> u64 {
        self.cancel_loading();
        self.loading = true;
        self.error = None;
        self.generation
    }
    pub fn bytes(&self) -> usize {
        self.items
            .iter()
            .map(|item| item.image.memory_bytes())
            .sum()
    }
}

pub fn prepare_files(
    paths: Vec<PathBuf>,
    available: usize,
    existing_bytes: usize,
) -> Result<Vec<Arc<media::PreparedImage>>, String> {
    if paths.is_empty() || paths.len() > available {
        return Err(format!(
            "Choose between 1 and {available} more images for this batch."
        ));
    }
    let mut images = Vec::with_capacity(paths.len());
    let mut bytes = existing_bytes;
    for path in paths {
        let image = media::PreparedImage::from_file(&path, media::Kind::Nft)?;
        bytes = bytes
            .checked_add(image.memory_bytes())
            .ok_or("The image batch is too large.")?;
        if bytes > IMAGE_MEMORY_LIMIT {
            return Err("The prepared images exceed the batch memory limit. Choose fewer or smaller images.".into());
        }
        images.push(Arc::new(image));
    }
    Ok(images)
}

impl State {
    pub fn collection_metadata(&self, id: &[u8; 32]) -> Option<[u8; 32]> {
        self.live
            .collections
            .get(id)
            .map(|group| group.metadata)
            .or_else(|| {
                self.nft_collections
                    .collections
                    .get(id)
                    .map(|group| group.metadata)
            })
    }
    pub fn collection_manifest(&self, id: &[u8; 32]) -> Option<&media::Manifest> {
        self.library
            .manifest(&self.collection_metadata(id)?)
            .filter(|manifest| manifest.kind == media::Kind::Collection)
    }
    pub fn collection_name(&self, id: &[u8; 32]) -> String {
        self.collection_manifest(id)
            .map_or_else(|| live::short_id(id), |manifest| manifest.name.clone())
    }
    pub fn collection_creation_media(&self) -> Result<media::Bundle, String> {
        if self.media.loading {
            return Err("Wait for the cover image to finish loading.".into());
        }
        media::Bundle::new(
            media::Kind::Collection,
            &self.nft_name,
            None,
            &self.description,
            self.media.image.clone(),
        )?
        .with_website(&self.website)
    }
    pub fn nft_batch_limit(&self) -> usize {
        self.live
            .protocol
            .as_ref()
            .and_then(|protocol| protocol.nft_batch_limit)
            .unwrap_or(0)
            .min(noid_tx::MAX_PAGED_SPEND_OUTPUTS.saturating_sub(2))
    }
    pub fn mintable_collection(&self, id: &[u8; 32]) -> Result<&live::Collection, String> {
        if self.nft_batch_limit() == 0 {
            return Err("The connected node does not support NFT batches.".into());
        }
        let group = self
            .live
            .collections
            .get(id)
            .ok_or("Only the collection's creator can add NFTs.")?;
        if group.reserved || group.issued >= group.maximum {
            return Err(
                "This collection has a pending operation or its serial range is exhausted.".into(),
            );
        }
        Ok(group)
    }
    pub fn nft_batch_serial(&self, index: usize) -> Option<u64> {
        let id = self.nft_group.unwrap_or_default();
        let reviewed_first = self.operation.preview.as_ref().filter(|preview| {
            matches!(&preview.request, operations::Request::MintNfts { collection_id, .. } if *collection_id == hex::encode(id))
        }).and_then(|preview| preview.serial.as_ref()).and_then(|serial| serial.parse::<u64>().ok());
        let first = reviewed_first.or_else(|| {
            self.live
                .collections
                .get(&id)
                .and_then(|group| group.issued.checked_add(1))
        });
        first.and_then(|first| first.checked_add(index as u64))
    }
    pub fn nft_batch_name(&self, index: usize) -> String {
        if let Some(name) = self
            .nft_batch
            .items
            .get(index)
            .and_then(|item| item.name.as_ref())
        {
            return name.clone();
        }
        let id = self.nft_group.unwrap_or_default();
        let prefix: String = self
            .collection_manifest(&id)
            .map_or("NFT", |manifest| manifest.name.as_str())
            .chars()
            .take(40)
            .collect();
        format!(
            "{prefix} #{}",
            self.nft_batch_serial(index)
                .map_or_else(|| "?".into(), |value| value.to_string())
        )
    }
    pub fn nft_batch_media(&self) -> Result<Vec<media::Bundle>, String> {
        let id = self.nft_group.ok_or("Choose a collection.")?;
        let group = self.mintable_collection(&id)?;
        if self.nft_batch.loading {
            return Err("Wait for the images to finish loading.".into());
        }
        let count = self.nft_batch.items.len();
        if count == 0 || count > self.nft_batch_limit() {
            return Err("Add images within the current batch limit.".into());
        }
        if group
            .issued
            .checked_add(count as u64)
            .is_none_or(|issued| issued > group.maximum)
        {
            return Err("The NFT serial range is exhausted.".into());
        }
        self.nft_batch
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                media::Bundle::new(
                    media::Kind::Nft,
                    &self.nft_batch_name(index),
                    None,
                    &self.description,
                    Some(item.image.clone()),
                )?
                .with_website(&self.website)
            })
            .collect()
    }
    pub fn reconcile_nft_batch(&mut self) -> bool {
        if !self.live.complete
            || self.live.error.is_some()
            || self.operation.phase != operations::Phase::Submitted
        {
            return false;
        }
        let Some(key) = &self.live.key else {
            return false;
        };
        if self
            .operation
            .context
            .as_ref()
            .is_none_or(|context| context.owner != key.owner || context.key_index != key.key_index)
        {
            return false;
        }
        let Some(preview) = &self.operation.preview else {
            return false;
        };
        let Some(id) = preview
            .collection_id
            .as_ref()
            .and_then(|value| hex::decode(value).ok())
            .and_then(|value| value.try_into().ok())
        else {
            return false;
        };
        match &preview.request {
            operations::Request::CreateCollection {
                maximum_items,
                metadata_hash,
            } if self.nft_page == Page::CreateNftCollection
                && maximum_items == &u64::MAX.to_string() =>
            {
                if self.live.collections.get(&id).is_none_or(|group| {
                    group.maximum != u64::MAX || hex::encode(group.metadata) != *metadata_hash
                }) {
                    return false;
                }
                self.nft_group = Some(id);
            }
            operations::Request::MintNfts {
                collection_id,
                metadata_hashes,
            } if self.nft_page == Page::MintNfts => {
                if *collection_id != hex::encode(id) || metadata_hashes.is_empty() {
                    return false;
                }
                let Some(first) = preview
                    .serial
                    .as_ref()
                    .and_then(|value| value.parse::<u64>().ok())
                else {
                    return false;
                };
                if metadata_hashes.iter().enumerate().any(|(index, hash)| {
                    first
                        .checked_add(index as u64)
                        .and_then(|serial| self.live.nfts.get(&(id, serial)))
                        .is_none_or(|item| hex::encode(item.metadata) != *hash)
                }) {
                    return false;
                }
                self.nft_batch.clear();
                self.nft_group = Some(id);
            }
            _ => return false,
        }
        self.nft_page = Page::NftCollectionDetail;
        self.nft_home = Page::Collection;
        self.operation.edit();
        true
    }
}
