// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! # parano1d-miner — External Poseidon2b PoW miner for the ParanO(1)d.
//!
//! Connects to any `parano1d` full node via JSON-RPC, fetches a block template,
//! searches for a valid PoW nonce using all available CPU cores (rayon), and
//! returns only that nonce to the node-owned template.
//!
//! ## Usage
//!
//! ```bash
//! # Solo (node on localhost, no auth)
//! parano1d-miner --rpc http://127.0.0.1:9601
//!
//! # Pool (remote node with bearer token)
//! parano1d-miner --rpc https://pool.example.com:9601 --key-file /secure/mining.key
//!
//! # Limit threads
//! parano1d-miner --rpc http://127.0.0.1:9601 --threads 4
//! ```
//!
//! ## Template protocol
//!
//! `getBlockTemplate("")` returns:
//!   - `template_id`              — opaque, single-use node capability
//!   - `pow_fields_hex`           — 16-field Poseidon2b PoW input
//!   - `nonce_field_index`        — nonce lane (canonical value: 10)
//!   - `difficulty_target_hex`    — 256-bit LE target
//!   - block metadata             — operator display only
//!
//! The miner calls `submitBlock(template_id, nonce_hex)`, where `nonce_hex` is
//! exactly the 16-byte little-endian nonce in lowercase hex. The worker never
//! receives or submits a block body, HistoryStep witness or proof.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::batch::FixedFieldNonceBatch;
use noid_poseidon2b::native::domain::TAG_POWHDR;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "parano1d-miner",
    version,
    about = "External Poseidon2b PoW miner for ParanO(1)d",
    long_about = "Fetches block templates from a ParanO(1)d node and mines blocks \
                  using all available CPU cores.\n\n\
                  The node builds the proven template; this worker only does PoW.\n\
                  Coinbase is the node payout address unless the node enables \
                  --allow-custom-coinbase and the worker supplies --coinbase."
)]
struct Cli {
    /// Check production CPU support and exit without connecting to a node.
    #[arg(long, exclusive = true)]
    check_hardware: bool,

    /// JSON-RPC endpoint of the ParanO(1)d node or pool.
    #[arg(long, default_value = "http://127.0.0.1:9601", value_name = "URL")]
    rpc: String,

    /// Bearer token for pool/external RPC access.
    #[arg(long, value_name = "TOKEN", conflicts_with = "key_file")]
    key: Option<String>,

    /// Owner-only file containing the Bearer token for pool/external RPC access.
    /// Must match the node's configured mining credential.
    /// Not needed for solo miners using the default 127.0.0.1 binding.
    #[arg(long, value_name = "FILE")]
    key_file: Option<PathBuf>,

    /// Number of PoW threads. 0 = every logical CPU visible to the process.
    #[arg(long, default_value_t = 0, value_name = "N")]
    threads: usize,

    /// Your own payout address (bech32m o1...).
    /// Only works when the node is started with --allow-custom-coinbase.
    /// Leave empty to use the node's configured payout address (pool mode).
    #[arg(long, value_name = "ADDRESS", default_value = "")]
    coinbase: String,

    /// Milliseconds to wait before re-fetching a new template after a solve
    /// or stale detection. Lower = more responsive to new blocks.
    #[arg(long, default_value_t = 500, value_name = "MS")]
    poll_ms: u64,

    /// Log level (error | warn | info | debug).
    #[arg(long, default_value = "info", value_name = "LEVEL")]
    log: String,
}

// ---------------------------------------------------------------------------
// RPC types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct BlockTemplateResponse {
    template_id: String,
    pow_fields_hex: String,
    nonce_field_index: usize,
    difficulty_target_hex: String,
    height: u64,
    expires_in_seconds: u64,
    n_txs: usize,
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest<'a, P: Serialize> {
    jsonrpc: &'a str,
    id: u32,
    method: &'a str,
    params: P,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// RPC client
// ---------------------------------------------------------------------------

struct RpcClient {
    url: String,
    key: Option<String>,
    http: reqwest::blocking::Client,
}

impl RpcClient {
    fn new(url: &str, key: Option<String>) -> Self {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("build HTTP client");
        Self {
            url: url.to_string(),
            key,
            http,
        }
    }

    fn call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R> {
        let body = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        };
        let mut req = self.http.post(&self.url).json(&body);
        if let Some(ref token) = self.key {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let resp = req.send().with_context(|| format!("POST {}", self.url))?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(anyhow!(
                "401 Unauthorized — node requires a mining credential. \
                 Make sure --key or --key-file matches the node."
            ));
        }
        if !status.is_success() {
            return Err(anyhow!("HTTP {status} from {}", self.url));
        }
        let rpc: JsonRpcResponse<R> = resp.json().context("decode JSON-RPC response")?;
        if let Some(err) = rpc.error {
            return Err(anyhow!("RPC error: {err}"));
        }
        rpc.result
            .ok_or_else(|| anyhow!("RPC returned null result"))
    }

    fn get_template(&self, coinbase: &str) -> Result<BlockTemplateResponse> {
        self.call("paranoid_getBlockTemplate", [coinbase])
    }

    fn submit_nonce(&self, template_id: &str, nonce: u128) -> Result<String> {
        let nonce_hex = hex::encode(nonce.to_le_bytes());
        self.call("paranoid_submitBlock", (template_id, nonce_hex))
    }
}

// ---------------------------------------------------------------------------
// PoW
// ---------------------------------------------------------------------------

const CHUNK_SIZE: u128 = 10_000_000;
const DIGEST_BATCH: usize = 256;
const POW_HEADER_FIELD_COUNT: usize = 16;
const POW_NONCE_FIELD_INDEX: usize = 10;
const POW_FIELDS_HEX_BYTES: usize = POW_HEADER_FIELD_COUNT * 16;
const TEMPLATE_SUBMIT_MARGIN: Duration = Duration::from_secs(1);
const MAX_MINING_KEY_FILE_BYTES: u64 = 4096;

fn read_mining_key_file(path: &Path) -> Result<String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open mining key file: {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect mining key file: {}", path.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!(
            "mining key path is not a regular file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(anyhow!(
                "mining key file must not be accessible by group or others: {} has mode {mode:03o}",
                path.display()
            ));
        }
        let actual = metadata.uid();
        // SAFETY: geteuid has no preconditions and only reads process state.
        let expected = unsafe { libc::geteuid() };
        if actual != expected {
            return Err(anyhow!(
                "mining key file must be owned by the current user: {} is uid {actual}, expected {expected}",
                path.display()
            ));
        }
    }

    let mut raw = String::new();
    file.take(MAX_MINING_KEY_FILE_BYTES + 1)
        .read_to_string(&mut raw)
        .with_context(|| format!("read mining key file: {}", path.display()))?;
    if raw.len() as u64 > MAX_MINING_KEY_FILE_BYTES {
        return Err(anyhow!("mining key file is too large: {}", path.display()));
    }
    let key = raw.trim_end_matches(['\r', '\n']).to_owned();
    if key.len() < 16 {
        return Err(anyhow!("mining key must contain at least 16 characters"));
    }
    if key.chars().any(char::is_whitespace) {
        return Err(anyhow!("mining key must not contain whitespace"));
    }
    Ok(key)
}

fn template_search_deadline(received_at: Instant, expires_in_seconds: u64) -> Instant {
    let usable = Duration::from_secs(expires_in_seconds).saturating_sub(TEMPLATE_SUBMIT_MARGIN);
    received_at.checked_add(usable).unwrap_or(received_at)
}

/// Search for a valid nonce using all rayon threads.
/// Returns `Some(nonce)` or `None` when the node-owned template is too close
/// to expiry to submit safely.
fn search_nonce(
    pow_fields: &[Block128; POW_HEADER_FIELD_COUNT],
    target: &[u8; 32],
    deadline: Instant,
) -> Option<u128> {
    let num_threads = rayon::current_num_threads();
    let per_thread = CHUNK_SIZE.div_ceil(num_threads as u128);

    // Random start so multiple miners on the same template don't collide.
    let start_nonce: u128 = {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u128;
        t & 0xFFFF_FFFF_FFFF_FFFF
    };

    let mut chunk_start = start_nonce;

    loop {
        if Instant::now() >= deadline {
            return None;
        }

        let chunk_end = chunk_start + CHUNK_SIZE;
        let solution = (0..num_threads).into_par_iter().find_map_any(|tid| {
            let ts = chunk_start + tid as u128 * per_thread;
            let te = (ts + per_thread).min(chunk_end);
            if ts >= te {
                return None;
            }

            let fields = *pow_fields;
            let mut hasher = FixedFieldNonceBatch::new(TAG_POWHDR, &fields, POW_NONCE_FIELD_INDEX);
            let mut digests = [[0u8; 32]; DIGEST_BATCH];
            let mut nonce = ts;
            while nonce < te {
                if Instant::now() >= deadline {
                    return None;
                }
                let n = ((te - nonce).min(DIGEST_BATCH as u128)) as usize;
                hasher.hash_into(nonce, &mut digests[..n]);
                for (i, hash) in digests[..n].iter().enumerate() {
                    if le256_lt(hash, target) {
                        return Some(nonce + i as u128);
                    }
                }
                nonce += n as u128;
            }
            None
        });

        if solution.is_some() {
            return solution;
        }

        chunk_start = chunk_start.wrapping_add(CHUNK_SIZE);
    }
}

fn decode_pow_fields_hex(hex_str: &str) -> Result<[Block128; POW_HEADER_FIELD_COUNT]> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != POW_FIELDS_HEX_BYTES {
        return Err(anyhow!(
            "pow_fields_hex must be {POW_FIELDS_HEX_BYTES} bytes, got {}",
            bytes.len()
        ));
    }
    let mut fields = [Block128::ZERO; POW_HEADER_FIELD_COUNT];
    for (i, chunk) in bytes.chunks_exact(16).enumerate() {
        fields[i] = Block128::from(u128::from_le_bytes(chunk.try_into().unwrap()));
    }
    Ok(fields)
}

/// Compare two 32-byte values as 256-bit LE integers: `a < b`.
#[inline]
fn le256_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Mining loop
// ---------------------------------------------------------------------------

fn mine(cli: &Cli, key: Option<String>) -> Result<()> {
    let authenticated = key.is_some();
    let rpc = RpcClient::new(&cli.rpc, key);

    // Configure rayon thread pool.
    if cli.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(cli.threads)
            .build_global()
            .context("configure PoW thread pool")?;
    }
    let threads = rayon::current_num_threads();

    eprintln!(
        "parano1d-miner  rpc={}  threads={}  backend={}  poll={}ms",
        cli.rpc,
        threads,
        noid_core::cpu::selected_backend(),
        cli.poll_ms,
    );
    if authenticated {
        eprintln!("auth: bearer token configured");
    }
    if !cli.coinbase.is_empty() {
        eprintln!(
            "coinbase: {} (custom — node must have --allow-custom-coinbase)",
            cli.coinbase
        );
    } else {
        eprintln!("coinbase: node's payout address (pool mode)");
    }
    eprintln!("Connecting to node...\n");

    let mut blocks_found: u64 = 0;
    let mut last_height: u64 = 0;

    loop {
        // Fetch template.
        let (tmpl, template_received_at) = match rpc.get_template(&cli.coinbase) {
            Ok(t) => (t, Instant::now()),
            Err(e) => {
                eprintln!("template fetch failed: {e}  — retrying in 2s");
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
        };

        // Skip if height unchanged and we already solved it.
        if tmpl.height == last_height {
            std::thread::sleep(Duration::from_millis(cli.poll_ms));
            continue;
        }

        let height = tmpl.height;
        let n_txs = tmpl.n_txs;

        let pow_fields =
            decode_pow_fields_hex(&tmpl.pow_fields_hex).context("decode pow_fields_hex")?;
        if tmpl.nonce_field_index != POW_NONCE_FIELD_INDEX {
            return Err(anyhow!(
                "template nonce_field_index must be {POW_NONCE_FIELD_INDEX}, got {}",
                tmpl.nonce_field_index
            ));
        }

        let target: [u8; 32] = hex::decode(&tmpl.difficulty_target_hex)
            .context("decode difficulty_target_hex")?
            .try_into()
            .map_err(|_| anyhow!("difficulty_target must be 32 bytes"))?;

        // Count leading zero bits for display.
        let diff_bits = {
            let mut z = 0u32;
            for i in (0..32usize).rev() {
                if target[i] == 0 {
                    z += 8;
                } else if z.is_multiple_of(8) {
                    z += target[i].leading_zeros();
                    break;
                } else {
                    break;
                }
            }
            z
        };

        eprintln!(
            "┌─ h={height} txs={n_txs} expires={}s diff={diff_bits} leading-zero-bits  \
             target={}…",
            tmpl.expires_in_seconds,
            &tmpl.difficulty_target_hex[tmpl.difficulty_target_hex.len().saturating_sub(8)..]
        );

        let t0 = Instant::now();
        let deadline = template_search_deadline(template_received_at, tmpl.expires_in_seconds);

        let nonce = match search_nonce(&pow_fields, &target, deadline) {
            Some(n) => n,
            None => {
                eprintln!("└─ EXPIRED  refreshing node-owned template");
                continue;
            }
        };

        let elapsed = t0.elapsed();
        if Instant::now() >= deadline {
            eprintln!("└─ EXPIRED  solution arrived too late; refreshing template");
            continue;
        }

        // Submit only the nonce for this single-use node-owned template.
        match rpc.submit_nonce(&tmpl.template_id, nonce) {
            Ok(hash) => {
                blocks_found += 1;
                last_height = height;
                eprintln!(
                    "└─ SOLVED  nonce={nonce}  time={:.2}s  hash={}…  \
                     [total={blocks_found}]",
                    elapsed.as_secs_f64(),
                    &hash[..20.min(hash.len())],
                );
            }
            Err(e) => {
                let err = e.to_string();
                if err.to_ascii_lowercase().contains("stale") {
                    eprintln!("└─ STALE  template parent lost race; fetching fresh template");
                } else {
                    eprintln!("└─ submit failed: {err}");
                }
            }
        }

        std::thread::sleep(Duration::from_millis(cli.poll_ms));
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();
    if cli.check_hardware {
        let report = noid_core::cpu::ProductionHardwareReport::detect();
        print!("{report}");
        if report.ready() {
            return;
        }
        let _ = std::io::Write::flush(&mut std::io::stdout());
        std::process::exit(1);
    }
    if let Err(error) = noid_core::cpu::ensure_production_hardware() {
        eprintln!("fatal: {error}");
        std::process::exit(1);
    }
    let key = match (&cli.key, cli.key_file.as_deref()) {
        (Some(key), None) => Some(key.clone()),
        (None, Some(path)) => match read_mining_key_file(path) {
            Ok(key) => Some(key),
            Err(error) => {
                eprintln!("fatal: {error}");
                std::process::exit(1);
            }
        },
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap rejects conflicting key sources"),
    };
    if let Err(e) = mine(&cli, key) {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use clap::Parser;

    use super::{
        read_mining_key_file, search_nonce, template_search_deadline, Block128, Cli,
        POW_HEADER_FIELD_COUNT,
    };

    #[test]
    fn worker_accepts_legacy_and_file_credentials() {
        let legacy = Cli::try_parse_from(["parano1d-miner", "--key", "0123456789abcdef"]).unwrap();
        assert_eq!(legacy.key.as_deref(), Some("0123456789abcdef"));
        assert!(legacy.key_file.is_none());

        let file =
            Cli::try_parse_from(["parano1d-miner", "--key-file", "/secure/mining.key"]).unwrap();
        assert!(file.key.is_none());
        assert_eq!(
            file.key_file.as_deref(),
            Some(std::path::Path::new("/secure/mining.key"))
        );

        assert!(Cli::try_parse_from([
            "parano1d-miner",
            "--key",
            "0123456789abcdef",
            "--key-file",
            "/secure/mining.key",
        ])
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn mining_key_file_requires_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("mining.key");
        std::fs::write(&path, b"0123456789abcdef0123456789abcdef\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_mining_key_file(&path).unwrap(),
            "0123456789abcdef0123456789abcdef"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_mining_key_file(&path).is_err());
    }

    #[test]
    fn nonce_submission_is_canonical_little_endian_hex() {
        let nonce = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128;
        let encoded = hex::encode(nonce.to_le_bytes());
        assert_eq!(encoded.len(), 32);
        assert_eq!(
            u128::from_le_bytes(hex::decode(encoded).unwrap().try_into().unwrap()),
            nonce
        );
    }

    #[test]
    fn template_deadline_reserves_submit_margin() {
        let received_at = Instant::now();
        let deadline = template_search_deadline(received_at, 30);
        assert_eq!(
            deadline.duration_since(received_at),
            Duration::from_secs(29)
        );
        assert_eq!(template_search_deadline(received_at, 1), received_at);
        assert_eq!(template_search_deadline(received_at, 0), received_at);
    }

    #[test]
    fn expired_template_stops_before_hashing() {
        let fields = [Block128::from(0u128); POW_HEADER_FIELD_COUNT];
        assert_eq!(search_nonce(&fields, &[0xff; 32], Instant::now()), None);
    }
}
