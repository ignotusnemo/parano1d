// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::{digest, Bundle, Kind, Manifest, MAX_IMAGE_BYTES, MAX_MANIFEST_BYTES};
use reqwest::{Client, Response, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

pub const MAX_RECEIPT_BYTES: usize = 1024 * 1024;
pub const MAX_UPLOAD_BYTES: usize = 2 * (MAX_IMAGE_BYTES + MAX_RECEIPT_BYTES) + 32 * 1024;
pub const MAX_RPC_BYTES: usize = 3 * 1024 * 1024;
pub const DEFAULT_ORIGIN: &str = "https://tradedata.parano1d.org/";

pub fn configured_origin() -> String {
    std::env::var("NOID_GUI_MEDIA_ORIGIN").unwrap_or_else(|_| DEFAULT_ORIGIN.to_owned())
}

#[derive(Debug, Clone)]
pub struct Origin(Url);

impl Origin {
    pub fn parse(value: &str) -> Result<Self, String> {
        let url = Url::parse(value).map_err(|_| "Invalid media service address.")?;
        let loopback = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("Use an HTTPS media origin, or HTTP on loopback for local testing.".into());
        }
        Ok(Self(url))
    }

    pub(crate) fn path(&self, path: &str) -> Result<Url, String> {
        self.0
            .join(path)
            .map_err(|_| "Invalid media object path.".into())
    }
}

pub fn client() -> Result<Client, String> {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| "The media client could not be started.".into())
}

pub async fn bounded_response(mut response: Response, limit: usize) -> Result<Vec<u8>, String> {
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > limit as u64)
    {
        return Err("The media service did not return a valid bounded response.".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "The media response was interrupted.")?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err("The media response exceeds its size limit.".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub async fn fetch_manifest(
    client: &Client,
    origin: &Origin,
    expected: &str,
) -> Result<Manifest, String> {
    if !digest(expected) {
        return Err("Invalid metadata hash.".into());
    }
    let response = client
        .get(origin.path(&format!("metadata/{expected}.json"))?)
        .send()
        .await
        .map_err(|_| "Asset details are temporarily unavailable.")?;
    let bytes = bounded_response(response, MAX_MANIFEST_BYTES).await?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid asset manifest.")?;
    if manifest.hash()? != expected {
        return Err("The metadata differs from State.".into());
    }
    Ok(manifest)
}

pub async fn fetch(client: &Client, origin: &Origin, expected: &str) -> Result<Bundle, String> {
    let manifest = fetch_manifest(client, origin, expected).await?;
    let bytes = manifest.canonical_bytes()?;
    let image = if let Some(image) = &manifest.image {
        let response = client
            .get(origin.path(&format!("images/{}.png", image.hash))?)
            .send()
            .await
            .map_err(|_| "The asset image is temporarily unavailable.")?;
        Some(bounded_response(response, MAX_IMAGE_BYTES).await?)
    } else {
        None
    };
    let expected = expected.to_owned();
    tokio::task::spawn_blocking(move || Bundle::from_untrusted(&expected, &bytes, image.as_deref()))
        .await
        .map_err(|_| "The asset details could not be checked.".to_owned())?
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upload {
    pub schema: u8,
    pub metadata_hash: String,
    pub manifest_hex: String,
    pub image_hex: Option<String>,
    pub receipt_hex: String,
}

impl Upload {
    pub fn new(bundle: &Bundle, receipt_hex: String) -> Result<Self, String> {
        receipt_bytes(&receipt_hex)?;
        Ok(Self {
            schema: 1,
            metadata_hash: bundle.hash()?,
            manifest_hex: hex::encode(bundle.manifest().canonical_bytes()?),
            image_hex: bundle.image().map(|image| hex::encode(image.bytes())),
            receipt_hex,
        })
    }

    pub fn bundle(&self) -> Result<Bundle, String> {
        if self.schema != 1 || !digest(&self.metadata_hash) {
            return Err("Unsupported media upload.".into());
        }
        receipt_bytes(&self.receipt_hex)?;
        let manifest = decode(&self.manifest_hex, MAX_MANIFEST_BYTES)?;
        let image = self
            .image_hex
            .as_ref()
            .map(|s| decode(s, MAX_IMAGE_BYTES))
            .transpose()?;
        Bundle::from_untrusted(&self.metadata_hash, &manifest, image.as_deref())
    }
}

fn decode(value: &str, limit: usize) -> Result<Vec<u8>, String> {
    if value.len() > 2 * limit || value.len() % 2 != 0 {
        return Err("The media object exceeds its encoding limit.".into());
    }
    hex::decode(value).map_err(|_| "Invalid media object encoding.".into())
}

pub fn receipt_bytes(value: &str) -> Result<Vec<u8>, String> {
    let bytes = decode(value, MAX_RECEIPT_BYTES)?;
    if bytes.is_empty() {
        return Err("A creation receipt is required.".into());
    }
    Ok(bytes)
}

pub async fn publish(client: &Client, origin: &Origin, upload: &Upload) -> Result<(), String> {
    let response = client
        .post(origin.path("publish")?)
        .json(upload)
        .send()
        .await
        .map_err(|_| "Media publication is waiting for the service.".to_owned())?;
    let bytes = bounded_response(response, MAX_MANIFEST_BYTES).await?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid publication response.")?;
    if value.get("metadata_hash").and_then(Value::as_str) != Some(upload.metadata_hash.as_str()) {
        return Err("The publication response identifies different metadata.".into());
    }
    Ok(())
}

pub async fn verify_receipt(client: &Client, rpc: &str, receipt: &str) -> Result<Value, String> {
    receipt_bytes(receipt)?;
    let url = Url::parse(rpc).map_err(|_| "Invalid local node address.")?;
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
    if url.scheme() != "http"
        || !(host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("Receipt verification requires a loopback node endpoint.".into());
    }
    let response = client
        .post(url)
        .json(&json!({"jsonrpc":"2.0", "id":1,
        "method":"paranoid_verifyReceipt", "params":[receipt]}))
        .send()
        .await
        .map_err(|_| "The local node could not verify the receipt.".to_owned())?;
    let bytes = bounded_response(response, MAX_RPC_BYTES).await?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid receipt verification response.")?;
    if value.get("id") != Some(&json!(1)) || value.get("error").is_some() {
        return Err("Receipt verification failed.".into());
    }
    value
        .get("result")
        .cloned()
        .ok_or("Missing receipt verification.".into())
}

pub fn bindings(verified: &Value, hash: &str, kind: Kind) -> Result<Value, String> {
    if !digest(hash)
        || verified.get("merkle_valid") != Some(&json!(true))
        || verified.get("canonical") != Some(&json!(true))
        || verified.get("confirmed") != Some(&json!(true))
        || verified.get("error").is_some_and(|error| !error.is_null())
    {
        return Err("Publication requires a confirmed canonical native receipt.".into());
    }
    let summary = &verified["authenticated_summary"];
    let txid = summary["txid"]
        .as_str()
        .filter(|s| digest(s))
        .ok_or("Missing receipt identity.")?;
    let height = summary["claimed_height"]
        .as_u64()
        .ok_or("Missing receipt height.")?;
    let native = &summary["native"];
    let mut subjects = Vec::new();
    if let Some(created) = native["created"].as_array() {
        for item in created.iter().take(129) {
            let matches = match kind {
                Kind::Token => item["kind"] == "token",
                Kind::Collection => item["kind"] == "collection",
                Kind::Nft => item["kind"] == "collection" && item["supply_or_maximum"] == "1",
            };
            if matches && item["metadata_hash"] == hash && item["id"].as_str().is_some_and(digest) {
                subjects.push(json!({"kind":item["kind"], "id":item["id"]}));
            }
        }
    }
    if kind == Kind::Nft {
        if let Some(items) = native["nft_outputs"].as_array() {
            for item in items.iter().take(129) {
                if item["metadata_hash"] == hash
                    && item["collection_id"].as_str().is_some_and(digest)
                    && item["serial"].as_u64().is_some()
                {
                    subjects.push(
                        json!({"kind":"nft", "id":item["collection_id"], "serial":item["serial"]}),
                    );
                }
            }
        }
    }
    if subjects.is_empty() || subjects.len() > 128 {
        return Err("The receipt does not authenticate these asset details.".into());
    }
    Ok(
        json!({"schema":1,"metadata_hash":hash,"txid":txid,"checked_height":height,"subjects":subjects}),
    )
}
