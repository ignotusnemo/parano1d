// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::{Bundle, Manifest};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Default)]
pub struct Library {
    bundles: BTreeMap<String, Bundle>,
    manifests: BTreeMap<String, Manifest>,
    order: VecDeque<String>,
    bytes: usize,
    pub loading: bool,
    pub publication_pending: usize,
    pub publication_error: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct Loaded {
    pub bundles: Vec<(String, Bundle)>,
    pub manifests: Vec<(String, Manifest)>,
    pub publication_pending: usize,
    pub publication_error: Option<String>,
}

fn size(bundle: &Bundle) -> usize {
    8192 + bundle.image().map_or(0, |image| image.memory_bytes())
}

impl Library {
    pub fn clear_images(&mut self) {
        self.bundles.clear();
        self.order.clear();
        self.bytes = 0;
    }
    pub fn clear_cache(&mut self) {
        let pending = self.publication_pending;
        let error = self.publication_error.take();
        *self = Self::default();
        self.publication_pending = pending;
        self.publication_error = error;
    }
    pub fn manifest(&self, metadata: &[u8; 32]) -> Option<&Manifest> {
        self.manifests.get(&hex::encode(metadata))
    }
    pub fn has_manifest(&self, metadata: &[u8; 32]) -> bool {
        self.manifest(metadata).is_some()
    }
    fn add_manifest(&mut self, hash: String, manifest: Manifest) {
        if manifest.hash().ok().as_deref() != Some(hash.as_str()) {
            return;
        }
        if self.manifests.len() >= 8192 && !self.manifests.contains_key(&hash) {
            self.manifests.pop_first();
        }
        self.manifests.insert(hash, manifest);
    }
    pub fn get(&self, metadata: &[u8; 32]) -> Option<&Bundle> {
        self.bundles.get(&hex::encode(metadata))
    }
    pub fn contains(&self, hash: &str) -> bool {
        self.bundles.contains_key(hash)
    }
    pub fn ingest(&mut self, loaded: Loaded) {
        self.loading = false;
        self.publication_pending = loaded.publication_pending;
        self.publication_error = loaded.publication_error;
        for (hash, manifest) in loaded.manifests {
            self.add_manifest(hash, manifest);
        }
        for (hash, bundle) in loaded.bundles {
            self.add_manifest(hash.clone(), bundle.manifest().clone());
            if bundle.hash().ok().as_deref() != Some(hash.as_str())
                || self.bundles.contains_key(&hash)
            {
                continue;
            }
            let cost = size(&bundle);
            if cost > 64 * 1024 * 1024 {
                continue;
            }
            while self.bytes + cost > 64 * 1024 * 1024 || self.bundles.len() >= 64 {
                let Some(old) = self.order.pop_front() else {
                    break;
                };
                if let Some(bundle) = self.bundles.remove(&old) {
                    self.bytes -= size(&bundle);
                }
            }
            self.bytes += cost;
            self.order.push_back(hash.clone());
            self.bundles.insert(hash, bundle);
        }
    }
}
