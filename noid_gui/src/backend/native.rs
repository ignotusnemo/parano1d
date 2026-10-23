// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::assets::operations::{Preview, Request, Submission};

impl Backend {
    pub async fn native_pending(&self) -> Result<Vec<crate::assets::activity::Pending>, String> {
        if self.is_mock() {
            return Ok(Vec::new());
        }
        let records = self.rpc("walletNativePending", json!([])).await?;
        crate::assets::activity::validate(records)
    }

    pub async fn dismiss_native_pending(&self, txid: String) -> Result<(), String> {
        self.rpc("walletDismissNativePending", json!([txid])).await
    }

    pub async fn native_catalog_page(
        &self,
        kind: crate::assets::catalog::Kind,
        cursor: Option<crate::assets::catalog::Cursor>,
    ) -> Result<crate::assets::catalog::Page, String> {
        self.rpc("getNativeCatalog", json!([kind, cursor, 64]))
            .await
    }
    pub async fn native_preview_with_media(
        &self,
        request: Request,
        media: Option<crate::assets::media::Bundle>,
    ) -> Result<Preview, String> {
        self.native_preview_with_media_batch(request, media.into_iter().collect())
            .await
    }

    pub async fn native_preview_with_media_batch(
        &self,
        request: Request,
        media: Vec<crate::assets::media::Bundle>,
    ) -> Result<Preview, String> {
        let expected = creation_metadata(&request)
            .into_iter()
            .map(|(hash, kind)| (hash.to_owned(), kind))
            .collect::<Vec<_>>();
        if expected.len() != media.len() {
            return Err("Add the exact asset details before continuing.".into());
        }
        for ((hash, kind), bundle) in expected.iter().zip(&media) {
            if bundle.manifest().kind != *kind || bundle.hash()? != *hash {
                return Err("The asset details changed. Review them again.".into());
            }
        }
        if !media.is_empty() {
            let directory = self.config_snapshot()?.data_dir.join("native-media");
            tokio::task::spawn_blocking(move || {
                for bundle in media {
                    bundle.persist(&directory)?;
                }
                Ok::<_, String>(())
            })
            .await
            .map_err(|_| "The asset details could not be saved.".to_owned())??;
        }
        self.native_preview(request).await
    }

    pub async fn native_preview(&self, request: Request) -> Result<Preview, String> {
        if self.is_mock() {
            return Err("Connect to a v2.1.0 node to use native assets.".into());
        }
        self.rpc_with_timeout(
            "walletPreviewNative",
            json!([request]),
            Duration::from_secs(120),
        )
        .await
    }

    pub async fn native_submit(&self, preview: Preview) -> Result<Submission, String> {
        if self.is_mock() {
            return Err("Connect to a v2.1.0 node to use native assets.".into());
        }
        let expected = creation_metadata(&preview.request)
            .into_iter()
            .map(|(hash, kind)| (hash.to_owned(), kind))
            .collect::<Vec<_>>();
        if !expected.is_empty() {
            let directory = self.config_snapshot()?.data_dir.join("native-media");
            let txid = preview.txid.clone();
            tokio::task::spawn_blocking(move || {
                for (hash, kind) in &expected {
                    let bundle = crate::assets::media::Bundle::load(&directory, hash)?;
                    if bundle.manifest().kind != *kind {
                        return Err("The saved asset type differs from the operation.".to_owned());
                    }
                }
                for (hash, _) in expected {
                    super::native_media::queue(&directory, &txid, &hash)?;
                }
                Ok::<_, String>(())
            })
            .await
            .map_err(|_| "The saved asset details could not be verified.".to_owned())??;
        }
        self.rpc_with_timeout(
            "walletSubmitNative",
            json!([preview.request, preview.plan_id]),
            Duration::from_secs(600),
        )
        .await
    }

    pub async fn native_nft_draft(
        &self,
        metadata_hash: String,
    ) -> Result<crate::assets::media::Bundle, String> {
        let directory = self.config_snapshot()?.data_dir.join("native-media");
        tokio::task::spawn_blocking(move || {
            let bundle = crate::assets::media::Bundle::load(&directory, &metadata_hash)?;
            if bundle.manifest().kind != crate::assets::media::Kind::Nft {
                return Err("The saved details are not an NFT.".into());
            }
            Ok(bundle)
        })
        .await
        .map_err(|_| "The saved NFT details could not be loaded.".to_owned())?
    }
}

fn creation_metadata(request: &Request) -> Vec<(&str, crate::assets::media::Kind)> {
    use crate::assets::media::Kind;
    match request {
        Request::CreateToken { metadata_hash, .. } => vec![(metadata_hash, Kind::Token)],
        Request::CreateCollection {
            maximum_items,
            metadata_hash,
        } => vec![(
            metadata_hash,
            if maximum_items == "1" {
                Kind::Nft
            } else {
                Kind::Collection
            },
        )],
        Request::MintNft { metadata_hash, .. } => vec![(metadata_hash, Kind::Nft)],
        Request::MintNfts {
            metadata_hashes, ..
        } => metadata_hashes
            .iter()
            .map(|hash| (hash.as_str(), Kind::Nft))
            .collect(),
        _ => Vec::new(),
    }
}
