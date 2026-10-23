// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use crate::market_data::{self, Block, Candle, Header, History, MAX_BLOCKS};
use libmdbx::{
    Database, DatabaseOptions, Mode, NoWriteMap, ReadWriteOptions, TableFlags, WriteFlags,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};

const META: &str = "meta";
const HEADERS: &str = "headers";
const CANDLES: &str = "candles";

fn db_error(error: impl std::fmt::Display) -> String {
    format!("Price history storage: {error}")
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|_| "Cannot encode price history.".into())
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    if bytes.len() > 16 * 1024 {
        return Err("Price history record exceeds its limit.".into());
    }
    serde_json::from_slice(bytes).map_err(|_| "Invalid stored price history.".into())
}
fn candle_key(asset: &str, height: u64) -> Result<Vec<u8>, String> {
    if !market_data::digest(asset) {
        return Err("Invalid price history asset.".into());
    }
    let mut key = hex::decode(asset).map_err(|_| "Invalid price history asset.")?;
    key.extend_from_slice(&height.to_be_bytes());
    Ok(key)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredHeader {
    header: Header,
    assets: Vec<String>,
}

pub struct Index {
    db: Database<NoWriteMap>,
}

impl Index {
    pub fn open(path: &Path, quota: u64) -> Result<Self, String> {
        if quota < 16 * 1024 * 1024 || quota > isize::MAX as u64 {
            return Err("Use a price history quota of at least 16 MiB.".into());
        }
        std::fs::create_dir_all(path).map_err(|_| "Cannot create price history storage.")?;
        if !std::fs::symlink_metadata(path).is_ok_and(|info| info.is_dir()) {
            return Err("Invalid price history directory.".into());
        }
        let db = Database::<NoWriteMap>::open_with_options(
            path,
            DatabaseOptions {
                max_tables: Some(3),
                max_readers: Some(32),
                mode: Mode::ReadWrite(ReadWriteOptions {
                    min_size: Some(1024 * 1024),
                    max_size: Some(quota as isize),
                    growth_step: Some(8 * 1024 * 1024),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .map_err(db_error)?;
        let txn = db.begin_rw_txn().map_err(db_error)?;
        for name in [META, HEADERS, CANDLES] {
            txn.create_table(Some(name), TableFlags::empty())
                .map_err(db_error)?;
        }
        txn.commit().map_err(db_error)?;
        Ok(Self { db })
    }

    pub fn tip(&self) -> Result<Option<Header>, String> {
        let txn = self.db.begin_ro_txn().map_err(db_error)?;
        let meta = txn.open_table(Some(META)).map_err(db_error)?;
        let raw: Option<Vec<u8>> = txn.get(&meta, b"tip").map_err(db_error)?;
        raw.map(|bytes| decode(&bytes)).transpose()
    }

    pub fn anchor(&self, chain: &str, header: Header) -> Result<(), String> {
        if !market_data::digest(chain) || !header.valid() {
            return Err("Invalid history anchor.".into());
        }
        let txn = self.db.begin_rw_txn().map_err(db_error)?;
        let meta = txn.open_table(Some(META)).map_err(db_error)?;
        let saved: Option<Vec<u8>> = txn.get(&meta, b"chain").map_err(db_error)?;
        if saved
            .as_deref()
            .is_some_and(|bytes| bytes != chain.as_bytes())
        {
            return Err("Price history belongs to another chain.".into());
        }
        let tip: Option<Vec<u8>> = txn.get(&meta, b"tip").map_err(db_error)?;
        if tip.as_ref().is_some_and(|bytes| {
            decode::<Header>(bytes).is_ok_and(|tip| tip.height >= header.height)
        }) {
            return Ok(());
        }
        let headers = txn.open_table(Some(HEADERS)).map_err(db_error)?;
        let record = StoredHeader {
            header: header.clone(),
            assets: Vec::new(),
        };
        txn.put(
            &headers,
            header.height.to_be_bytes(),
            encode(&record)?,
            WriteFlags::empty(),
        )
        .map_err(db_error)?;
        txn.put(&meta, b"chain", chain.as_bytes(), WriteFlags::empty())
            .map_err(db_error)?;
        txn.put(
            &meta,
            b"first",
            header.height.to_be_bytes(),
            WriteFlags::empty(),
        )
        .map_err(db_error)?;
        txn.put(&meta, b"tip", encode(&header)?, WriteFlags::empty())
            .map_err(db_error)?;
        txn.commit().map_err(db_error)?;
        Ok(())
    }

    pub fn append(&self, header: Header, candles: BTreeMap<String, Candle>) -> Result<(), String> {
        if !header.valid() || candles.len() > 4 || candles.values().any(|c| !c.valid()) {
            return Err("Invalid price history block.".into());
        }
        let txn = self.db.begin_rw_txn().map_err(db_error)?;
        let meta = txn.open_table(Some(META)).map_err(db_error)?;
        let previous: Vec<u8> = txn
            .get(&meta, b"tip")
            .map_err(db_error)?
            .ok_or("Price history has no anchor.")?;
        let previous: Header = decode(&previous)?;
        if previous.height.checked_add(1) != Some(header.height)
            || previous.hash != header.prev_hash
        {
            return Err("Price history parent changed.".into());
        }
        let table = txn.open_table(Some(CANDLES)).map_err(db_error)?;
        let assets = candles.keys().cloned().collect();
        for (asset, candle) in candles {
            txn.put(
                &table,
                candle_key(&asset, header.height)?,
                encode(&candle)?,
                WriteFlags::empty(),
            )
            .map_err(db_error)?;
        }
        let table = txn.open_table(Some(HEADERS)).map_err(db_error)?;
        txn.put(
            &table,
            header.height.to_be_bytes(),
            encode(&StoredHeader {
                header: header.clone(),
                assets,
            })?,
            WriteFlags::empty(),
        )
        .map_err(db_error)?;
        txn.put(&meta, b"tip", encode(&header)?, WriteFlags::empty())
            .map_err(db_error)?;
        txn.commit().map_err(db_error)?;
        Ok(())
    }

    pub fn rewind(&self) -> Result<(), String> {
        let txn = self.db.begin_rw_txn().map_err(db_error)?;
        let meta = txn.open_table(Some(META)).map_err(db_error)?;
        let raw: Vec<u8> = txn
            .get(&meta, b"tip")
            .map_err(db_error)?
            .ok_or("Price history has no tip.")?;
        let tip: Header = decode(&raw)?;
        let table = txn.open_table(Some(HEADERS)).map_err(db_error)?;
        let raw: Vec<u8> = txn
            .get(&table, &tip.height.to_be_bytes())
            .map_err(db_error)?
            .ok_or("Missing price history tip.")?;
        let record: StoredHeader = decode(&raw)?;
        let raw: Vec<u8> = txn
            .get(&table, &tip.height.saturating_sub(1).to_be_bytes())
            .map_err(db_error)?
            .ok_or("Price history restart anchor is unavailable.")?;
        let parent: StoredHeader = decode(&raw)?;
        if tip.prev_hash != parent.header.hash {
            return Err("Price history restart anchor changed.".into());
        }
        let candles = txn.open_table(Some(CANDLES)).map_err(db_error)?;
        for asset in record.assets {
            txn.del(&candles, candle_key(&asset, tip.height)?, None)
                .map_err(db_error)?;
        }
        txn.del(&table, tip.height.to_be_bytes(), None)
            .map_err(db_error)?;
        txn.put(&meta, b"tip", encode(&parent.header)?, WriteFlags::empty())
            .map_err(db_error)?;
        txn.commit().map_err(db_error)?;
        Ok(())
    }

    pub fn query(&self, asset: &str, end: u64) -> Result<History, String> {
        candle_key(asset, end)?;
        let txn = self.db.begin_ro_txn().map_err(db_error)?;
        let meta = txn.open_table(Some(META)).map_err(db_error)?;
        let raw: Vec<u8> = txn
            .get(&meta, b"tip")
            .map_err(db_error)?
            .ok_or("Price history is starting.")?;
        let tip: Header = decode(&raw)?;
        let raw: Vec<u8> = txn
            .get(&meta, b"first")
            .map_err(db_error)?
            .ok_or("Missing price history start.")?;
        let first = u64::from_be_bytes(raw.try_into().map_err(|_| "Invalid price history start.")?);
        let through = end.min(tip.height);
        if through < first {
            return Err("The requested history precedes the index.".into());
        }
        let raw: Vec<u8> = txn
            .get(&meta, b"chain")
            .map_err(db_error)?
            .ok_or("Missing price history chain.")?;
        let chain = String::from_utf8(raw).map_err(|_| "Invalid history chain.")?;
        let headers = txn.open_table(Some(HEADERS)).map_err(db_error)?;
        let candles = txn.open_table(Some(CANDLES)).map_err(db_error)?;
        let mut blocks = Vec::new();
        for height in through.saturating_sub(MAX_BLOCKS as u64 - 1).max(first)..=through {
            let raw: Vec<u8> = txn
                .get(&headers, &height.to_be_bytes())
                .map_err(db_error)?
                .ok_or("Missing price history header.")?;
            let record: StoredHeader = decode(&raw)?;
            let raw: Option<Vec<u8>> = txn
                .get(&candles, &candle_key(asset, height)?)
                .map_err(db_error)?;
            blocks.push(Block {
                header: record.header,
                candle: raw.map(|bytes| decode(&bytes)).transpose()?,
            });
        }
        let through = blocks
            .last()
            .ok_or("Price history is empty.")?
            .header
            .clone();
        let history = History {
            schema: 1,
            chain,
            asset: asset.to_owned(),
            through,
            blocks,
        };
        history.validate(&history.chain, asset, end)?;
        Ok(history)
    }
}

fn local_url(rpc: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(rpc).map_err(|_| "Invalid history node address.")?;
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
        return Err("Price history requires a loopback node endpoint.".into());
    }
    Ok(url)
}

async fn rpc(
    client: &reqwest::Client,
    url: &reqwest::Url,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let response = client
        .post(url.clone())
        .json(
            &json!({"jsonrpc":"2.0", "id":1,"method":format!("paranoid_{method}"),"params":params}),
        )
        .send()
        .await
        .map_err(|_| "The history node is unavailable.")?;
    let bytes = super::transport::bounded_response(response, 8 * 1024 * 1024).await?;
    let mut value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid history node response.")?;
    if value["id"] != json!(1) || value.get("error").is_some() {
        return Err("The history node rejected the request.".into());
    }
    value
        .get_mut("result")
        .map(Value::take)
        .ok_or_else(|| "Missing history node result.".into())
}

fn header(value: &Value) -> Result<Header, String> {
    let header: Header = serde_json::from_value(json!({"height":value["height"],"hash":value["hash"],"prev_hash":value["prev_hash"],"timestamp":value["timestamp"]}))
        .map_err(|_| "Invalid history node header.")?;
    if !header.valid() {
        return Err("Invalid history node header.".into());
    }
    Ok(header)
}

async fn synchronize(
    index: &Arc<Index>,
    client: &reqwest::Client,
    url: &reqwest::Url,
) -> Result<(), String> {
    let chain = rpc(client, url, "getChainInfo", json!([])).await?;
    let height = chain["height"]
        .as_u64()
        .ok_or("Missing history node height.")?;
    let mut tip = index.tip()?;
    if tip.as_ref().is_some_and(|tip| {
        tip.height == height && chain["best_hash"].as_str() == Some(tip.hash.as_str())
    }) {
        return Ok(());
    }
    let first = if tip
        .as_ref()
        .is_none_or(|tip| height.saturating_sub(tip.height) > 32)
    {
        let recent = rpc(client, url, "getRecentTransactions", json!([0, 1, null])).await?;
        recent["retained_from_height"]
            .as_u64()
            .ok_or("Missing retained history boundary.")?
            .max(1)
    } else {
        1
    };
    if tip
        .as_ref()
        .is_none_or(|tip| tip.height.saturating_add(1) < first)
    {
        let genesis = rpc(client, url, "getBlockHeader", json!([0])).await?;
        let anchor = header(&rpc(client, url, "getBlockHeader", json!([first - 1])).await?)?;
        index.anchor(
            genesis["hash"]
                .as_str()
                .ok_or("Missing history chain identity.")?,
            anchor.clone(),
        )?;
        tip = Some(anchor);
    }
    for _ in 0..64 {
        let stored = tip.as_ref().ok_or("Missing history cursor.")?;
        let canonical = if stored.height <= height {
            rpc(client, url, "getBlockHeader", json!([stored.height])).await?
        } else {
            Value::Null
        };
        if canonical["hash"].as_str() == Some(stored.hash.as_str()) {
            break;
        }
        index.rewind()?;
        tip = index.tip()?;
    }
    let mut tip = tip.ok_or("Missing history cursor.")?;
    for next in tip.height.saturating_add(1)..=height.min(tip.height.saturating_add(16)) {
        let details = rpc(client, url, "getBlockDetails", json!([next])).await?;
        let (observed, candles) = market_data::block_trades(&details)?;
        if details["retained"].is_null()
            || observed.height != next
            || observed.prev_hash != tip.hash
        {
            return Err("The history node changed its retained block range.".into());
        }
        let current = rpc(client, url, "getBlockHeader", json!([next])).await?;
        if current["hash"].as_str() != Some(observed.hash.as_str()) {
            return Err("The history node changed its canonical block.".into());
        }
        index.append(observed.clone(), candles)?;
        tip = observed;
    }
    Ok(())
}

pub async fn follow(
    index: Arc<Index>,
    client: reqwest::Client,
    rpc_url: String,
) -> Result<(), String> {
    let url = local_url(&rpc_url)?;
    let mut previous_error = None;
    loop {
        match synchronize(&index, &client, &url).await {
            Ok(()) => previous_error = None,
            Err(error) => {
                if previous_error.as_ref() != Some(&error) {
                    eprintln!("{error}");
                }
                previous_error = Some(error);
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
