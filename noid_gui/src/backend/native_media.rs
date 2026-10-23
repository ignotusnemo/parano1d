// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::assets::media::{
    self,
    library::Loaded,
    transport::{self, Origin, Upload},
    Bundle,
};
use std::time::Instant;

#[derive(Default)]
pub(super) struct Maintenance {
    client: Option<Client>,
    directory: PathBuf,
    last_publish: Option<Instant>,
    attempted: BTreeMap<String, Instant>,
    downloads_enabled: Option<bool>,
    publish_cursor: usize,
    publication_pending: usize,
    publication_error: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    schema: u8,
    txid: String,
    metadata_hash: String,
    #[serde(skip)]
    filename: String,
}

pub(super) fn queue(directory: &Path, txid: &str, metadata_hash: &str) -> Result<(), String> {
    if !media::digest(txid) || !media::digest(metadata_hash) {
        return Err("Invalid media publication identity.".into());
    }
    let bytes = serde_json::to_vec(&Publication {
        schema: 1,
        txid: txid.into(),
        metadata_hash: metadata_hash.into(),
        filename: String::new(),
    })
    .map_err(|_| "Cannot save media publication.")?;
    media::save_immutable(
        &directory
            .join("queue")
            .join(format!("{txid}-{metadata_hash}.json")),
        &bytes,
        1024,
    )
}

fn pending(directory: &Path) -> Result<Vec<Publication>, String> {
    let path = directory.join("queue");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for item in std::fs::read_dir(path).map_err(|_| "Cannot read media publication queue.")? {
        if records.len() >= 4096 {
            return Err("The media publication queue exceeds its limit.".into());
        }
        let path = item
            .map_err(|_| "Cannot read media publication entry.")?
            .path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let mut record: Publication = serde_json::from_slice(&media::read_bounded(&path, 1024)?)
            .map_err(|_| "Invalid media publication entry.")?;
        if record.schema != 1
            || !media::digest(&record.txid)
            || !media::digest(&record.metadata_hash)
            || ![
                record.txid.clone(),
                format!("{}-{}", record.txid, record.metadata_hash),
            ]
            .iter()
            .any(|stem| path.file_stem().and_then(|s| s.to_str()) == Some(stem.as_str()))
        {
            return Err("Invalid media publication entry.".into());
        }
        record.filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("Invalid media publication filename.")?
            .to_owned();
        records.push(record);
    }
    records.sort_by(|a, b| {
        a.txid
            .cmp(&b.txid)
            .then(a.metadata_hash.cmp(&b.metadata_hash))
    });
    Ok(records)
}

impl Backend {
    pub async fn clear_asset_cache(&self) -> Result<u64, String> {
        let mut maintenance = self.inner.native_media.lock().await;
        let directory = self.config_snapshot()?.data_dir.join("native-media");
        let bytes = tokio::task::spawn_blocking(move || media::cache::clear(&directory))
            .await
            .map_err(|_| "The asset cache could not be cleared.".to_owned())??;
        maintenance.attempted.clear();
        Ok(bytes)
    }

    pub async fn native_media(&self, desired: Vec<String>) -> Loaded {
        self.native_media_and_names(desired, Vec::new()).await
    }

    pub async fn native_media_and_names(&self, desired: Vec<String>, names: Vec<String>) -> Loaded {
        self.native_media_with_origin(desired, names, Some(transport::configured_origin()))
            .await
    }

    pub(super) async fn native_media_with_origin(
        &self,
        desired: Vec<String>,
        names: Vec<String>,
        media_origin: Option<String>,
    ) -> Loaded {
        let mut result = Loaded::default();
        if self.is_mock() {
            return result;
        }
        let Ok(config) = self.config_snapshot() else {
            return result;
        };
        let Ok(mut maintenance) = self.inner.native_media.try_lock() else {
            return result;
        };
        let directory = config.data_dir.join("native-media");
        if maintenance.directory != directory {
            *maintenance = Maintenance {
                directory: directory.clone(),
                ..Maintenance::default()
            };
        }
        result.publication_pending = maintenance.publication_pending;
        result.publication_error = maintenance.publication_error.clone();
        let origin = media_origin.map(|s| Origin::parse(&s)).transpose();
        let origin = match origin {
            Ok(origin) => origin,
            Err(error) => {
                result.publication_error = Some(error);
                None
            }
        };
        if maintenance.client.is_none() {
            let Ok(client) = transport::client() else {
                return result;
            };
            maintenance.client = Some(client);
        }
        let client = maintenance.client.as_ref().unwrap().clone();
        let now = Instant::now();
        let mut downloads = self.inner.media_downloads.subscribe();
        let enabled = *downloads.borrow_and_update();
        if maintenance.downloads_enabled != Some(enabled) {
            maintenance.attempted.clear();
            maintenance.downloads_enabled = Some(enabled);
        }
        let mut attempts = 0;
        for hash in desired.into_iter().filter(|s| media::digest(s)).take(64) {
            if maintenance
                .attempted
                .get(&hash)
                .is_some_and(|time| time.elapsed() < Duration::from_secs(60))
            {
                continue;
            }
            if attempts >= 4 {
                break;
            }
            attempts += 1;
            if maintenance.attempted.len() >= 1024 {
                maintenance.attempted.clear();
            }
            maintenance.attempted.insert(hash.clone(), now);
            let cache = directory.clone();
            let expected = hash.clone();
            let cached =
                tokio::task::spawn_blocking(move || media::cache::load(&cache, &expected)).await;
            let downloads_enabled = *downloads.borrow_and_update();
            let bundle = match cached {
                Ok(Ok(bundle)) => Some(bundle),
                _ => match &origin {
                    Some(origin) if downloads_enabled => match tokio::select! {
                        result = transport::fetch(&client, origin, &hash) => Some(result),
                        _ = downloads.changed() => None,
                    } {
                        Some(Ok(bundle)) => {
                            let cache = directory.clone();
                            let saved = bundle.clone();
                            let _ = tokio::task::spawn_blocking(move || {
                                media::cache::save_bundle(&cache, &saved)
                            })
                            .await;
                            Some(bundle)
                        }
                        Some(Err(_)) => None,
                        None => {
                            maintenance.attempted.remove(&hash);
                            None
                        }
                    },
                    _ => None,
                },
            };
            if let Some(bundle) = bundle {
                result.bundles.push((hash, bundle));
            }
        }
        let mut checked_names = 0;
        for hash in names
            .into_iter()
            .filter(|hash| media::digest(hash))
            .take(8192)
        {
            let key = format!("manifest:{hash}");
            if maintenance
                .attempted
                .get(&key)
                .is_some_and(|at| at.elapsed() < Duration::from_secs(60))
            {
                continue;
            }
            if checked_names >= 128 {
                break;
            }
            checked_names += 1;
            let path = directory.clone();
            let expected = hash.clone();
            let cached =
                tokio::task::spawn_blocking(move || media::cache::manifest(&path, &expected)).await;
            let manifest = match cached {
                Ok(Ok(manifest)) => Some(manifest),
                _ => {
                    let enabled = *downloads.borrow_and_update();
                    if enabled && origin.is_some() {
                        if attempts >= 4 {
                            break;
                        }
                        attempts += 1;
                        let fetched = tokio::select! {value=transport::fetch_manifest(&client,origin.as_ref().unwrap(),&hash)=>Some(value),_=downloads.changed()=>None};
                        match fetched {
                            Some(Ok(manifest)) => {
                                let path = directory.clone();
                                let saved = manifest.clone();
                                let _ = tokio::task::spawn_blocking(move || {
                                    media::cache::save_manifest(&path, &saved)
                                })
                                .await;
                                Some(manifest)
                            }
                            Some(Err(_)) => {
                                maintenance.attempted.insert(key.clone(), Instant::now());
                                None
                            }
                            None => None,
                        }
                    } else {
                        maintenance.attempted.insert(key.clone(), Instant::now());
                        None
                    }
                }
            };
            if let Some(manifest) = manifest {
                result.manifests.push((hash, manifest));
            }
            if maintenance.attempted.len() > 1024 {
                maintenance.attempted.clear();
            }
        }
        if maintenance
            .last_publish
            .is_some_and(|last| last.elapsed() < Duration::from_secs(30))
        {
            return result;
        }
        maintenance.last_publish = Some(now);
        result.publication_error = None;
        let path = directory.clone();
        let mut records = match tokio::task::spawn_blocking(move || pending(&path)).await {
            Ok(Ok(records)) => records,
            _ => {
                result.publication_error =
                    Some("The media publication queue could not be read.".into());
                return result;
            }
        };
        result.publication_pending = records.len();
        maintenance.publication_pending = records.len();
        let Some(origin) = origin else {
            if !records.is_empty() && result.publication_error.is_none() {
                result.publication_error = Some(
                    "Media is saved locally. A publication service has not been configured.".into(),
                );
            }
            maintenance.publication_error = result.publication_error.clone();
            return result;
        };
        if !records.is_empty() {
            let offset = maintenance.publish_cursor % records.len();
            records.rotate_left(offset);
            maintenance.publish_cursor = maintenance.publish_cursor.wrapping_add(4);
        }
        let mut published = false;
        for record in records.into_iter().take(4) {
            let Ok(receipt) = self
                .rpc::<String>("walletExportReceipt", json!([record.txid]))
                .await
            else {
                continue;
            };
            let path = directory.clone();
            let hash = record.metadata_hash.clone();
            let Ok(Ok(bundle)) =
                tokio::task::spawn_blocking(move || Bundle::load(&path, &hash)).await
            else {
                continue;
            };
            let Ok(upload) = Upload::new(&bundle, receipt) else {
                continue;
            };
            match transport::publish(&client, &origin, &upload).await {
                Ok(()) => {
                    let path = directory.join("queue").join(record.filename);
                    if std::fs::remove_file(path).is_ok() {
                        published = true;
                        result.publication_pending = result.publication_pending.saturating_sub(1);
                    }
                }
                Err(error) => result.publication_error = Some(error),
            }
        }
        if published && result.publication_pending != 0 {
            maintenance.last_publish = None;
        }
        maintenance.publication_pending = result.publication_pending;
        maintenance.publication_error = result.publication_error.clone();
        result
    }
}
