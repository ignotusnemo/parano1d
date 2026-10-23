// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::transport::{self, Upload, MAX_UPLOAD_BYTES};
use super::{digest, read_bounded, save_immutable, Bundle, MAX_IMAGE_BYTES, MAX_MANIFEST_BYTES};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
};

const HEADER_LIMIT: usize = 8192;
const PROOF_LIMIT: usize = 2 * transport::MAX_RECEIPT_BYTES + 64 * 1024;

struct HistoryWorker(tokio::task::JoinHandle<()>);
impl Drop for HistoryWorker {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct Store {
    _lease: std::fs::File,
    directory: PathBuf,
    quota: u64,
    used: Mutex<u64>,
    rpc: String,
    client: reqwest::Client,
}

impl Store {
    pub fn open(directory: PathBuf, quota: u64, rpc: String) -> Result<Self, String> {
        std::fs::create_dir_all(&directory).map_err(|_| "Cannot create media storage.")?;
        let lease_path = directory.join("service.lock");
        if std::fs::symlink_metadata(&lease_path).is_ok_and(|meta| !meta.is_file()) {
            return Err("Invalid media storage lease.".into());
        }
        let lease = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(lease_path)
            .map_err(|_| "Cannot open media storage lease.")?;
        lease
            .try_lock()
            .map_err(|_| "The media store already has an active writer.".to_owned())?;
        let mut used = 0u64;
        for area in ["metadata", "images", "proofs"] {
            let path = directory.join(area);
            std::fs::create_dir_all(&path).map_err(|_| "Cannot create media storage area.")?;
            if !std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()) {
                return Err("Invalid media storage directory.".into());
            }
            for entry in std::fs::read_dir(path).map_err(|_| "Cannot inspect media storage.")? {
                let path = entry.map_err(|_| "Cannot inspect media object.")?.path();
                let meta =
                    std::fs::symlink_metadata(&path).map_err(|_| "Cannot inspect media object.")?;
                if !meta.is_file() {
                    return Err("Media storage contains an unsupported file type.".into());
                }
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default();
                let temporary = name.strip_prefix('.').and_then(|s| s.strip_suffix(".tmp"));
                if temporary.is_some_and(|s| {
                    s.len() == 32
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                }) {
                    std::fs::remove_file(&path)
                        .map_err(|_| "Cannot retire an interrupted media write.")?;
                    continue;
                }
                used = used
                    .checked_add(meta.len())
                    .ok_or("Media storage size overflow.")?;
            }
        }
        if used > quota {
            return Err("The media store exceeds its configured quota.".into());
        }
        Ok(Self {
            _lease: lease,
            directory,
            quota,
            used: Mutex::new(used),
            rpc,
            client: transport::client()?,
        })
    }

    pub async fn publish(&self, upload: Upload) -> Result<Value, String> {
        let verified =
            transport::verify_receipt(&self.client, &self.rpc, &upload.receipt_hex).await?;
        let directory = self.directory.clone();
        let (bundle, mut record) = tokio::task::spawn_blocking(move || {
            let bundle = upload.bundle()?;
            let mut record =
                transport::bindings(&verified, &upload.metadata_hash, bundle.manifest().kind)?;
            record["receipt_hex"] = json!(upload.receipt_hex);
            Ok::<_, String>((bundle, record))
        })
        .await
        .map_err(|_| "Media verification did not finish.")??;
        let hash = bundle.hash()?;
        let txid = record["txid"]
            .as_str()
            .ok_or("Missing receipt identity.")?
            .to_owned();
        // The record describes the check at publication time; clients obtain current rights from State.
        record["metadata_hash"] = json!(hash);
        let mut bytes =
            serde_json::to_vec(&record).map_err(|_| "Cannot encode publication record.")?;
        bytes.push(b'\n');
        if bytes.len() > PROOF_LIMIT {
            return Err("Publication record exceeds its limit.".into());
        }
        let mut used = self.used.lock().await;
        let quota = self.quota;
        let current_used = *used;
        let (result, added) = tokio::task::spawn_blocking(move || {
            let mut files = vec![
                (
                    directory.join("metadata").join(format!("{hash}.json")),
                    bundle.manifest().canonical_bytes()?,
                    MAX_MANIFEST_BYTES,
                ),
                (
                    directory.join("proofs").join(format!("{txid}-{hash}.json")),
                    bytes,
                    PROOF_LIMIT,
                ),
            ];
            if let Some(image) = bundle.image() {
                files.insert(
                    0,
                    (
                        directory
                            .join("images")
                            .join(format!("{}.png", image.record().hash)),
                        image.bytes().to_vec(),
                        MAX_IMAGE_BYTES,
                    ),
                );
            }
            let mut required = 0u64;
            for (path, bytes, limit) in &files {
                if path.exists() {
                    if read_bounded(path, *limit)? != *bytes {
                        return Err("An immutable media object differs from storage.".into());
                    }
                } else {
                    required += bytes.len() as u64;
                }
            }
            if current_used.saturating_add(required) > quota {
                return Err("The media storage quota has been reached.".into());
            }
            let mut added = 0u64;
            let result = (|| {
                for (path, bytes, limit) in files {
                    let missing = !path.exists();
                    save_immutable(&path, &bytes, limit)?;
                    if missing {
                        added += bytes.len() as u64;
                    }
                }
                Ok(json!({"schema":1,"metadata_hash":hash}))
            })();
            Ok::<_, String>((result, added))
        })
        .await
        .map_err(|_| "Media storage did not finish.")??;
        *used = used.saturating_add(added);
        result
    }

    fn get(&self, target: &str) -> Result<(&'static str, Vec<u8>), String> {
        let (area, file) = target
            .strip_prefix('/')
            .ok_or("Invalid object path.")?
            .split_once('/')
            .ok_or("Invalid object path.")?;
        let (suffix, limit, content_type) = match area {
            "metadata" => (".json", MAX_MANIFEST_BYTES, "application/json"),
            "images" => (".png", MAX_IMAGE_BYTES, "image/png"),
            _ => return Err("Unknown object area.".into()),
        };
        let hash = file
            .strip_suffix(suffix)
            .filter(|s| digest(s))
            .ok_or("Invalid object identity.")?;
        let bytes = read_bounded(&self.directory.join(area).join(file), limit)?;
        if area == "metadata" {
            let manifest: super::Manifest =
                serde_json::from_slice(&bytes).map_err(|_| "Invalid stored manifest.")?;
            if manifest.hash()? != hash {
                return Err("Stored metadata differs from its name.".into());
            }
        } else if super::content_hash(b"Parano1d/native-image/v1\0", &bytes) != hash {
            return Err("Stored image differs from its name.".into());
        }
        Ok((content_type, bytes))
    }

    pub fn verify_files(&self) -> Result<usize, String> {
        let mut count = 0;
        for entry in std::fs::read_dir(self.directory.join("metadata"))
            .map_err(|_| "Cannot read metadata directory.")?
        {
            let path = entry.map_err(|_| "Cannot read metadata entry.")?.path();
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or("Invalid metadata filename.")?;
            if path.extension().and_then(|s| s.to_str()) != Some("json") || !digest(name) {
                return Err("Invalid metadata filename.".into());
            }
            Bundle::load(&self.directory, name)?;
            count += 1;
        }
        Ok(count)
    }
}

struct Request {
    method: String,
    target: String,
    body: Vec<u8>,
}

async fn read_request(stream: &mut TcpStream) -> Result<Request, String> {
    let mut bytes = Vec::new();
    let end = loop {
        if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() >= HEADER_LIMIT {
            return Err("Request headers exceed their limit.".into());
        }
        let mut chunk = [0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .map_err(|_| "Request header timed out.")?
            .map_err(|_| "Cannot read request.")?;
        if n == 0 {
            return Err("Incomplete request.".into());
        }
        bytes.extend_from_slice(&chunk[..n]);
    };
    if end > HEADER_LIMIT {
        return Err("Request headers exceed their limit.".into());
    }
    let text = std::str::from_utf8(&bytes[..end - 4]).map_err(|_| "Invalid request headers.")?;
    let mut lines = text.split("\r\n");
    let first: Vec<_> = lines.next().unwrap_or_default().split(' ').collect();
    if first.len() != 3
        || !matches!(first[2], "HTTP/1.1" | "HTTP/1.0")
        || first[1].len() > 256
        || !first[1].starts_with('/')
    {
        return Err("Unsupported HTTP request.".into());
    }
    let method = first[0].to_owned();
    let target = first[1].to_owned();
    let mut length = None;
    let mut json_type = false;
    let mut host = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("Invalid request header.")?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        {
            return Err("Invalid request header.".into());
        }
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                if length.is_some()
                    || value.is_empty()
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err("Invalid content length.".into());
                }
                length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| "Invalid content length.")?,
                );
            }
            "transfer-encoding" | "expect" => return Err("Unsupported request framing.".into()),
            "content-type" => {
                if json_type || value != "application/json" {
                    return Err("Unsupported content type.".into());
                }
                json_type = true;
            }
            "host" => {
                if host || value.is_empty() {
                    return Err("Invalid Host header.".into());
                }
                host = true;
            }
            _ => {}
        }
    }
    let length = match (method.as_str(), target.as_str(), length) {
        ("GET", _, None | Some(0)) => 0,
        ("POST", "/publish", Some(n)) if json_type && n > 0 && n <= MAX_UPLOAD_BYTES => n,
        _ => return Err("Unsupported request method, path or size.".into()),
    };
    let mut body = bytes.split_off(end);
    if body.len() > length {
        return Err("Unexpected request data.".into());
    }
    let received = body.len();
    body.resize(length, 0);
    tokio::time::timeout(
        Duration::from_secs(20),
        stream.read_exact(&mut body[received..]),
    )
    .await
    .map_err(|_| "Request body timed out.")?
    .map_err(|_| "Incomplete request body.")?;
    Ok(Request {
        method,
        target,
        body,
    })
}

async fn response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    bytes: &[u8],
    immutable: bool,
) {
    let header = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; sandbox\r\nCache-Control: {}\r\n\r\n", bytes.len(), if immutable {"public, max-age=31536000, immutable"} else {"no-store"});
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(bytes).await?;
        stream.shutdown().await
    })
    .await;
}

pub async fn serve(store: Arc<Store>, address: SocketAddr) -> Result<(), String> {
    if !address.ip().is_loopback() {
        return Err("The media service must listen on loopback behind a TLS proxy.".into());
    }
    store.verify_files()?;
    let listener = TcpListener::bind(address)
        .await
        .map_err(|_| "Cannot bind media listener.")?;
    let quota = std::env::var("NOID_HISTORY_QUOTA_MIB")
        .unwrap_or_else(|_| "1024".into())
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(1024 * 1024))
        .ok_or("Invalid price history quota.")?;
    let history = Arc::new(super::history::Index::open(
        &store.directory.join("history"),
        quota,
    )?);
    let index = history.clone();
    let client = store.client.clone();
    let rpc = store.rpc.clone();
    let _history_worker = HistoryWorker(tokio::spawn(async move {
        if let Err(error) = super::history::follow(index, client, rpc).await {
            eprintln!("{error}");
        }
    }));
    let workers = Arc::new(Semaphore::new(4));
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|_| "Cannot accept media connection.")?;
        let Ok(permit) = workers.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let store = store.clone();
        let history = history.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(request)) =
                tokio::time::timeout(Duration::from_secs(25), read_request(&mut stream)).await
            else {
                response(
                    &mut stream,
                    "400 Bad Request",
                    "application/json",
                    b"{\"error\":\"invalid bounded request\"}\n",
                    false,
                )
                .await;
                return;
            };
            if request.method == "GET" {
                if let Some(target) = request.target.strip_prefix("/history/") {
                    let query = target.split_once('/').and_then(|(asset, end)| {
                        let end = end.strip_suffix(".json")?;
                        (digest(asset)
                            && !end.is_empty()
                            && end.len() <= 20
                            && end.bytes().all(|b| b.is_ascii_digit()))
                        .then(|| (asset.to_owned(), end.parse::<u64>().ok()))
                        .and_then(|(asset, end)| end.map(|height| (asset, height)))
                    });
                    let got = match query {
                        Some((asset, height)) => tokio::task::spawn_blocking(move || {
                            let page = history.query(&asset, height)?;
                            let bytes = serde_json::to_vec(&page)
                                .map_err(|_| "Cannot encode price history.".to_owned())?;
                            if bytes.len() > crate::market_data::MAX_RESPONSE_BYTES {
                                return Err("Price history exceeds its response limit.".into());
                            }
                            Ok::<_, String>(bytes)
                        })
                        .await
                        .ok()
                        .and_then(Result::ok),
                        None => None,
                    };
                    match got {
                        Some(bytes) => {
                            response(&mut stream, "200 OK", "application/json", &bytes, false).await
                        }
                        None => {
                            response(
                                &mut stream,
                                "404 Not Found",
                                "application/json",
                                b"{\"error\":\"history unavailable\"}\n",
                                false,
                            )
                            .await
                        }
                    }
                    return;
                }
                let got = tokio::task::spawn_blocking(move || store.get(&request.target)).await;
                match got {
                    Ok(Ok((kind, bytes))) => {
                        response(&mut stream, "200 OK", kind, &bytes, true).await
                    }
                    _ => {
                        response(
                            &mut stream,
                            "404 Not Found",
                            "application/json",
                            b"{\"error\":\"object unavailable\"}\n",
                            false,
                        )
                        .await
                    }
                }
            } else {
                let result = match serde_json::from_slice::<Upload>(&request.body) {
                    Ok(upload) => store.publish(upload).await,
                    Err(_) => Err("Unsupported upload.".into()),
                };
                match result {
                    Ok(value) => {
                        response(
                            &mut stream,
                            "200 OK",
                            "application/json",
                            &serde_json::to_vec(&value).unwrap_or_default(),
                            false,
                        )
                        .await
                    }
                    Err(_) => {
                        response(
                            &mut stream,
                            "422 Unprocessable Content",
                            "application/json",
                            b"{\"error\":\"publication checks failed\"}\n",
                            false,
                        )
                        .await
                    }
                }
            }
        });
    }
}

pub fn check_store(directory: &Path) -> Result<usize, String> {
    Store::open(
        directory.to_owned(),
        u64::MAX,
        "http://127.0.0.1:9601".into(),
    )?
    .verify_files()
}
