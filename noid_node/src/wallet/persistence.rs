// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Local wallet artifact journals. This framing is not a consensus or receipt
//! format. Each checksummed frame is one complete delta; an incomplete final
//! frame is ignored after a crash, while corruption in a complete frame fails
//! closed. Periodic snapshots bound obsolete journal data.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};

pub(super) const RECEIPTS_MAGIC: &[u8; 8] = b"NOIDRCJ1";
pub(super) const HISTORY_MAGIC: &[u8; 8] = b"NOIDHSJ1";
const FRAME_HEADER_BYTES: u64 = 16;
const FRAME_DIGEST_BYTES: u64 = 32;
const COMPACTION_SLACK_BYTES: u64 = 16 * 1024 * 1024;

/// Receipt mutations are tracked at their source, including same-length
/// replacements and deletions. Read-only HashMap operations remain available;
/// no mutable dereference can bypass the dirty-key set.
#[derive(Default)]
pub struct ReceiptMap {
    data: HashMap<[u8; 32], Vec<u8>>,
    dirty: HashSet<[u8; 32]>,
    payload_bytes: u64,
}

impl ReceiptMap {
    pub fn insert(&mut self, key: [u8; 32], value: Vec<u8>) -> Option<Vec<u8>> {
        self.payload_bytes = self.payload_bytes.saturating_add(value.len() as u64);
        let previous = self.data.insert(key, value);
        if let Some(value) = &previous {
            self.payload_bytes = self.payload_bytes.saturating_sub(value.len() as u64);
        }
        self.dirty.insert(key);
        previous
    }

    pub fn remove(&mut self, key: &[u8; 32]) -> Option<Vec<u8>> {
        let previous = self.data.remove(key);
        if let Some(value) = &previous {
            self.payload_bytes = self.payload_bytes.saturating_sub(value.len() as u64);
            self.dirty.insert(*key);
        }
        previous
    }

    pub(super) fn has_changes(&self) -> bool {
        !self.dirty.is_empty()
    }
    pub(super) fn changed_keys(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.dirty.iter()
    }
    pub(super) fn mark_saved(&mut self) {
        self.dirty.clear();
    }
    pub(super) fn encoded_budget(&self) -> u64 {
        self.payload_bytes
            .saturating_mul(2)
            .saturating_add((self.len() as u64).saturating_mul(100))
            .saturating_add(128)
    }
}

impl Deref for ReceiptMap {
    type Target = HashMap<[u8; 32], Vec<u8>>;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<'a> IntoIterator for &'a ReceiptMap {
    type Item = (&'a [u8; 32], &'a Vec<u8>);
    type IntoIter = std::collections::hash_map::Iter<'a, [u8; 32], Vec<u8>>;
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter()
    }
}

pub(super) fn legacy_backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".legacy");
    PathBuf::from(name)
}

pub(super) struct Journal {
    valid_len: u64,
    observed_len: u64,
    needs_directory_sync: bool,
}

impl Journal {
    /// `None` means a missing or legacy JSON artifact. Only the caller knows
    /// that legacy schema, and must decode it successfully before migration.
    pub(super) fn load(
        path: &Path,
        magic: &[u8; 8],
        mut apply: impl FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<Option<Self>, String> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("open wallet artifact {}: {error}", path.display())),
        };
        let observed_len = file.metadata().map_err(|e| e.to_string())?.len();
        let mut header = [0u8; 8];
        if observed_len < 8 {
            return Ok(None);
        }
        file.read_exact(&mut header).map_err(|e| e.to_string())?;
        if &header != magic {
            return Ok(None);
        }
        let mut valid_len = 8u64;
        while valid_len < observed_len {
            let remaining = observed_len - valid_len;
            if remaining < FRAME_HEADER_BYTES {
                break;
            }
            let mut frame_header = [0u8; 16];
            file.read_exact(&mut frame_header)
                .map_err(|e| e.to_string())?;
            let length = u64::from_le_bytes(frame_header[..8].try_into().unwrap());
            let inverted = u64::from_le_bytes(frame_header[8..].try_into().unwrap());
            if length != !inverted {
                return Err(format!(
                    "corrupt wallet journal length at {valid_len} in {}",
                    path.display()
                ));
            }
            let frame_len = length
                .checked_add(FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES)
                .ok_or_else(|| "wallet journal frame length overflow".to_string())?;
            if frame_len > remaining {
                break;
            }
            // The complete frame must exist on disk before allocating its
            // payload. No length from a truncated/untrusted header is trusted.
            let length = usize::try_from(length)
                .map_err(|_| "wallet journal frame exceeds address space".to_string())?;
            let mut payload = vec![0; length];
            file.read_exact(&mut payload).map_err(|e| e.to_string())?;
            let mut digest = [0; 32];
            file.read_exact(&mut digest).map_err(|e| e.to_string())?;
            if digest != frame_digest(magic, &frame_header, &payload) {
                return Err(format!(
                    "corrupt wallet journal checksum at {valid_len} in {}",
                    path.display()
                ));
            }
            apply(&payload)?;
            valid_len += frame_len;
        }
        if valid_len == 8 {
            return Err(format!(
                "wallet journal {} has no complete initial snapshot",
                path.display()
            ));
        }
        if valid_len != observed_len {
            tracing::warn!(path = %path.display(), valid_len, observed_len,
                "ignoring incomplete final wallet journal write; preserving committed frames");
        }
        Ok(Some(Self {
            valid_len,
            observed_len,
            needs_directory_sync: false,
        }))
    }

    pub(super) fn has_pending_write(&self) -> bool {
        self.needs_directory_sync || self.valid_len != self.observed_len
    }

    pub(super) fn needs_compaction(&self, live_encoded_budget: u64) -> bool {
        self.valid_len
            > live_encoded_budget
                .saturating_mul(2)
                .saturating_add(COMPACTION_SLACK_BYTES)
    }

    /// A retry rewrites only the uncommitted tail of this journal. The tracked
    /// file length prevents silently truncating an append by another process.
    pub(super) fn save(
        journal: &mut Option<Self>,
        path: &Path,
        magic: &[u8; 8],
        payload: &[u8],
        replace: bool,
    ) -> Result<(), String> {
        let frame = encode_frame(magic, payload)?;
        if journal.is_none() || replace {
            if let Some(current) = journal.as_ref() {
                current.open_unchanged(path, magic)?;
            } else if path.exists() {
                preserve_legacy(path)?;
            }
            let mut bytes = Vec::with_capacity(8 + frame.len());
            bytes.extend_from_slice(magic);
            bytes.extend_from_slice(&frame);
            let extension = format!(
                "{}.tmp",
                path.extension().unwrap_or_default().to_string_lossy()
            );
            let published =
                super::state::persist_atomically(path, &extension, &bytes, "wallet journal");
            let length = bytes.len() as u64;
            // rename may succeed before directory fsync fails. Remember our
            // own visible replacement so a retry does not mistake it for a
            // changed legacy file or try appending at the old offset.
            if published.is_ok() || std::fs::read(path).is_ok_and(|actual| actual == bytes) {
                *journal = Some(Self {
                    valid_len: length,
                    observed_len: length,
                    needs_directory_sync: published.is_err(),
                });
            }
            return published;
        }
        let current = journal.as_mut().unwrap();
        let mut file = current.open_unchanged(path, magic)?;
        let result = (|| -> std::io::Result<()> {
            // Only a known incomplete/failed final write is discarded. A
            // successfully checksummed earlier frame is never truncated here.
            if current.observed_len != current.valid_len {
                file.set_len(current.valid_len)?;
            }
            file.seek(SeekFrom::Start(current.valid_len))?;
            file.write_all(&frame)?;
            file.sync_all()
        })();
        current.observed_len = file.metadata().map_err(|e| e.to_string())?.len();
        result.map_err(|error| format!("append wallet journal {}: {error}", path.display()))?;
        current.valid_len += frame.len() as u64;
        if current.needs_directory_sync {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            super::state::sync_directory(parent, "wallet journal")?;
            current.needs_directory_sync = false;
        }
        Ok(())
    }

    fn open_unchanged(&self, path: &Path, magic: &[u8; 8]) -> Result<File, String> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("open wallet journal {}: {error}", path.display()))?;
        if file.metadata().map_err(|e| e.to_string())?.len() != self.observed_len {
            return Err(format!(
                "wallet journal {} changed outside this wallet; reload before writing",
                path.display()
            ));
        }
        let mut header = [0; 8];
        file.read_exact(&mut header).map_err(|e| e.to_string())?;
        if &header != magic {
            return Err("wallet journal format changed before writing".into());
        }
        Ok(file)
    }
}

fn frame_digest(magic: &[u8; 8], header: &[u8; 16], payload: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"NOID/local-wallet-journal/frame/v1");
    hash.update(magic);
    hash.update(header);
    hash.update(payload);
    *hash.finalize().as_bytes()
}

fn encode_frame(magic: &[u8; 8], payload: &[u8]) -> Result<Vec<u8>, String> {
    let length = u64::try_from(payload.len()).map_err(|_| "wallet journal payload too large")?;
    let mut header = [0; 16];
    header[..8].copy_from_slice(&length.to_le_bytes());
    header[8..].copy_from_slice(&(!length).to_le_bytes());
    let mut bytes = Vec::with_capacity(
        payload
            .len()
            .checked_add(48)
            .ok_or("wallet journal size overflow")?,
    );
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&frame_digest(magic, &header, payload));
    Ok(bytes)
}

fn preserve_legacy(path: &Path) -> Result<(), String> {
    let backup = legacy_backup_path(path);
    match std::fs::hard_link(path, &backup) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // A completed backup followed by a crash before migration is
            // idempotent. Never overwrite a different older backup.
            if std::fs::read(path).map_err(|e| e.to_string())?
                != std::fs::read(&backup).map_err(|e| e.to_string())?
            {
                return Err(format!(
                    "legacy wallet backup {} differs; preserve it before retrying migration",
                    backup.display()
                ));
            }
        }
        Err(error) => {
            return Err(format!(
                "preserve legacy wallet artifact {}: {error}",
                path.display()
            ))
        }
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    super::state::sync_directory(parent, "legacy wallet backup")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_incomplete_tail_recovers_only_complete_frames() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.receipts");
        let mut journal = None;
        Journal::save(&mut journal, &path, RECEIPTS_MAGIC, b"first", false).unwrap();
        let committed = std::fs::read(&path).unwrap();
        let tail = encode_frame(RECEIPTS_MAGIC, b"second").unwrap();
        for cut in 1..tail.len() {
            let mut interrupted = committed.clone();
            interrupted.extend_from_slice(&tail[..cut]);
            std::fs::write(&path, interrupted).unwrap();
            let mut seen = Vec::new();
            let mut recovered = Journal::load(&path, RECEIPTS_MAGIC, |bytes| {
                seen.push(bytes.to_vec());
                Ok(())
            })
            .unwrap();
            assert_eq!(seen, [b"first".to_vec()], "cut {cut}");
            Journal::save(&mut recovered, &path, RECEIPTS_MAGIC, b"third", false).unwrap();
            seen.clear();
            Journal::load(&path, RECEIPTS_MAGIC, |bytes| {
                seen.push(bytes.to_vec());
                Ok(())
            })
            .unwrap();
            assert_eq!(seen, [b"first".to_vec(), b"third".to_vec()], "cut {cut}");
        }
    }

    #[test]
    fn complete_corruption_is_not_treated_as_a_torn_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.history");
        Journal::save(&mut None, &path, HISTORY_MAGIC, b"payload", false).unwrap();
        let original = std::fs::read(&path).unwrap();
        for offset in 8..original.len() {
            let mut corrupted = original.clone();
            corrupted[offset] ^= 1;
            std::fs::write(&path, corrupted).unwrap();
            assert!(
                Journal::load(&path, HISTORY_MAGIC, |_| Ok(())).is_err(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn a_missing_initial_snapshot_is_corruption_not_an_empty_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.receipts");
        let frame = encode_frame(RECEIPTS_MAGIC, b"snapshot").unwrap();
        for cut in 0..frame.len() {
            let mut bytes = RECEIPTS_MAGIC.to_vec();
            bytes.extend_from_slice(&frame[..cut]);
            std::fs::write(&path, bytes).unwrap();
            assert!(Journal::load(&path, RECEIPTS_MAGIC, |_| Ok(())).is_err());
        }
    }

    #[test]
    fn legacy_backup_is_idempotent_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.history");
        std::fs::write(&path, b"[]").unwrap();
        preserve_legacy(&path).unwrap();
        preserve_legacy(&path).unwrap();
        // Replace rather than modify the hard-linked legacy inode.
        let changed = dir.path().join("replacement");
        std::fs::write(&changed, b"[{}]").unwrap();
        std::fs::rename(changed, &path).unwrap();
        assert!(preserve_legacy(&path).is_err());
        assert_eq!(std::fs::read(legacy_backup_path(&path)).unwrap(), b"[]");
        assert_eq!(std::fs::read(&path).unwrap(), b"[{}]");
    }

    #[test]
    fn append_and_compaction_preserve_committed_data_and_external_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.history");
        let mut journal = None;
        Journal::save(&mut journal, &path, HISTORY_MAGIC, b"first", false).unwrap();
        let prefix = std::fs::read(&path).unwrap();
        Journal::save(&mut journal, &path, HISTORY_MAGIC, b"second", false).unwrap();
        assert!(std::fs::read(&path).unwrap().starts_with(&prefix));
        Journal::save(&mut journal, &path, HISTORY_MAGIC, b"snapshot", true).unwrap();
        let mut seen = Vec::new();
        Journal::load(&path, HISTORY_MAGIC, |bytes| {
            seen.push(bytes.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, [b"snapshot".to_vec()]);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"external")
            .unwrap();
        assert!(Journal::save(&mut journal, &path, HISTORY_MAGIC, b"third", false).is_err());
        assert!(std::fs::read(&path).unwrap().ends_with(b"external"));
    }
}
