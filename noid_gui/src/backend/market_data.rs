// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::{
    assets::{
        live::Key,
        media::transport::{self, Origin},
    },
    market_data::{History, MAX_RESPONSE_BYTES},
};
use std::sync::OnceLock;

impl Backend {
    pub async fn chart_point_is_canonical(
        &self,
        previous: crate::assets::chart::Point,
    ) -> Result<bool, String> {
        Ok(self
            .rpc::<Option<BlockHeaderInfo>>("getBlockHeader", json!([previous.height]))
            .await?
            .is_some_and(|header| header.hash == previous.hash))
    }
    pub async fn external_price_history(
        &self,
        asset: [u8; 32],
        key: Key,
    ) -> Result<History, String> {
        self.external_price_history_from(asset, key, Some(transport::configured_origin()))
            .await
    }

    async fn external_price_history_from(
        &self,
        asset: [u8; 32],
        key: Key,
        origin: Option<String>,
    ) -> Result<History, String> {
        let mut enabled = self.inner.media_downloads.subscribe();
        if !*enabled.borrow_and_update() {
            return Err("External data is off.".into());
        }
        let origin = origin.ok_or("Price history service is not configured.")?;
        let origin = Origin::parse(&origin)?;
        static CLIENT: OnceLock<Client> = OnceLock::new();
        if CLIENT.get().is_none() {
            let _ = CLIENT.set(transport::client()?);
        }
        let client = CLIENT
            .get()
            .ok_or("The price history client is unavailable.")?;
        let path = format!("history/{}/{}.json", hex::encode(asset), key.height);
        let fetch = async {
            let response = client
                .get(origin.path(&path)?)
                .send()
                .await
                .map_err(|_| "Price history is temporarily unavailable.")?;
            let bytes = transport::bounded_response(response, MAX_RESPONSE_BYTES).await?;
            let history: History =
                serde_json::from_slice(&bytes).map_err(|_| "Invalid price history response.")?;
            let genesis = self
                .rpc::<Option<BlockHeaderInfo>>("getBlockHeader", json!([0]))
                .await?
                .ok_or("The chart chain is unavailable.")?;
            history.validate(&genesis.hash, &hex::encode(asset), key.height)?;
            let canonical = self
                .rpc::<Option<BlockHeaderInfo>>("getBlockHeader", json!([history.through.height]))
                .await?
                .ok_or("The chart header is unavailable.")?;
            if canonical.hash != history.through.hash {
                return Err("Price history is updating to the current chain.".into());
            }
            Ok(history)
        };
        tokio::select! {
            result = fetch => result,
            _ = enabled.changed() => Err("External data preference changed.".into()),
        }
    }
}
