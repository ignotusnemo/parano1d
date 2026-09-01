// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Disk-backed compact block-body tail for finalized snapshot synchronization.
//!
//! A snapshot generation owns the immutable blocks immediately following its
//! finalized state boundary. The receiver stores only canonical block bodies,
//! then fetches one recursive HistoryStep terminal for the sealed suffix tip.
//! That terminal authenticates the complete linked sequence without repeating
//! roughly 750 KiB of proof data at every height.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use noid_chain::consensus::wire_limits::{history_step_terminal_bytes_limit, MAX_BLOCK_BYTES};
use noid_chain::{
    Block, BlockHeader, HistoryStepTerminalMetadata, HISTORY_STEP_TERMINAL_BINDING_BYTES,
};

const FILE_MAGIC: [u8; 4] = *b"NST3";
const FILE_HEADER_BYTES: u64 = 4 + 8 + 32 + 32;
const RECORD_HEADER_BYTES: u64 = 4;
static NEXT_TAIL_FILE_ID: AtomicU64 = AtomicU64::new(0);

/// Transient, not consensus: enough for hours of full-rate catch-up while
/// bounding hostile disk growth. A client that cannot ingest chain data
/// within this limit restarts from a newer finalized generation.
pub const MAX_SNAPSHOT_TAIL_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_SNAPSHOT_TAIL_BLOCKS: u64 = 4096;

#[derive(Debug)]
pub struct SnapshotTailStaging {
    path: PathBuf,
    boundary_height: u64,
    boundary_hash: [u8; 32],
    boundary_chainwork: [u8; 32],
    tip_height: u64,
    tip_hash: [u8; 32],
    tip_header: Option<BlockHeader>,
    tip_chainwork: [u8; 32],
    block_count: u64,
    payload_bytes: u64,
    armed: bool,
}

#[derive(Debug)]
pub struct FinalizedSnapshotTail {
    path: PathBuf,
    boundary_height: u64,
    boundary_hash: [u8; 32],
    boundary_chainwork: [u8; 32],
    tip_height: u64,
    tip_hash: [u8; 32],
    tip_header: Option<BlockHeader>,
    block_count: u64,
    payload_bytes: u64,
    terminal_bytes: Vec<u8>,
    _inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    armed: bool,
}

#[derive(Debug)]
pub enum SnapshotTailFinalizeError {
    Terminal(String),
    Local(String),
}

impl std::fmt::Display for SnapshotTailFinalizeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Terminal(error) | Self::Local(error) => formatter.write_str(error),
        }
    }
}

pub struct SnapshotTailReader {
    reader: BufReader<File>,
    next_height: u64,
    previous_hash: [u8; 32],
    expected_tip_height: u64,
    expected_tip_hash: [u8; 32],
    remaining: u64,
    remaining_payload_bytes: u64,
}

impl SnapshotTailStaging {
    pub fn create(
        root: &Path,
        boundary_height: u64,
        boundary_hash: [u8; 32],
        boundary_chainwork: [u8; 32],
    ) -> Result<Self, String> {
        fs::create_dir_all(root).map_err(|error| format!("create tail staging root: {error}"))?;
        // A reset can abandon an append worker while a fresh sync for the same
        // boundary starts. Give every in-process session a distinct path so
        // the stale handle's Drop can never unlink the replacement file.
        let file_id = NEXT_TAIL_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!(
            "tail-{boundary_height:020}-{}-{file_id:016x}.bin",
            short_hash(boundary_hash)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| format!("create tail staging file: {error}"))?;
        file.write_all(&FILE_MAGIC)
            .and_then(|()| file.write_all(&boundary_height.to_le_bytes()))
            .and_then(|()| file.write_all(&boundary_hash))
            .and_then(|()| file.write_all(&boundary_chainwork))
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("seal tail staging header: {error}"))?;
        sync_parent(&path).map_err(|error| format!("sync tail staging directory: {error}"))?;
        Ok(Self {
            path,
            boundary_height,
            boundary_hash,
            boundary_chainwork,
            tip_height: boundary_height,
            tip_hash: boundary_hash,
            tip_header: None,
            tip_chainwork: boundary_chainwork,
            block_count: 0,
            payload_bytes: 0,
            armed: true,
        })
    }

    pub fn next_height(&self) -> u64 {
        self.tip_height.saturating_add(1)
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }

    pub fn tip_chainwork(&self) -> [u8; 32] {
        self.tip_chainwork
    }

    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    pub fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub fn append(mut self, block_bytes: Vec<u8>) -> Result<Self, String> {
        if block_bytes.is_empty() || block_bytes.len() > MAX_BLOCK_BYTES {
            return Err("tail block body length is outside bounds".to_string());
        }
        let block = Block::from_bytes(&block_bytes)
            .map_err(|error| format!("decode tail block body: {error:?}"))?;
        let height = block.header.height;
        if height != self.next_height() {
            return Err(format!(
                "tail block height {height} does not follow {}",
                self.tip_height
            ));
        }
        if block.header.height != height || block.header.prev_block_hash != self.tip_hash {
            return Err(format!("tail block {height} is not linked to staged tip"));
        }
        let block_hash = noid_chain::hash_block_header(&block.header);
        let encoded_len_u32 = u32::try_from(block_bytes.len())
            .map_err(|_| format!("tail block {height} length does not fit u32"))?;
        let next_count = self
            .block_count
            .checked_add(1)
            .ok_or_else(|| "tail block counter overflow".to_string())?;
        let next_bytes = self
            .payload_bytes
            .checked_add(block_bytes.len() as u64)
            .ok_or_else(|| "tail byte counter overflow".to_string())?;
        if next_count > MAX_SNAPSHOT_TAIL_BLOCKS || next_bytes > MAX_SNAPSHOT_TAIL_BYTES {
            return Err("snapshot live-tail staging limit exceeded".to_string());
        }

        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|error| format!("open tail staging append: {error}"))?;
        // The entire staging root is discarded after a process restart, so a
        // per-block fsync buys no recovery. Seal once in `finalize` instead.
        file.write_all(&encoded_len_u32.to_le_bytes())
            .and_then(|()| file.write_all(&block_bytes))
            .map_err(|error| format!("append tail block {height}: {error}"))?;

        self.tip_height = height;
        self.tip_hash = block_hash;
        self.tip_header = Some(block.header);
        self.tip_chainwork = noid_chain::add_work(
            &self.tip_chainwork,
            &noid_chain::block_work(&block.header.difficulty_target),
        );
        self.block_count = next_count;
        self.payload_bytes = next_bytes;
        Ok(self)
    }

    /// Append one transport-bounded consecutive batch. Each body still passes
    /// through the exact same canonical decode, link, work and disk checks as
    /// the former one-request-per-height path.
    pub fn append_batch(mut self, block_bodies: Vec<Vec<u8>>) -> Result<Self, String> {
        if block_bodies.is_empty()
            || block_bodies.len()
                > noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH as usize
        {
            return Err("snapshot tail batch count is outside bounds".to_string());
        }
        for block_bytes in block_bodies {
            self = self.append(block_bytes)?;
        }
        Ok(self)
    }

    pub fn finalize(
        mut self,
        terminal_bytes: Vec<u8>,
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    ) -> Result<FinalizedSnapshotTail, SnapshotTailFinalizeError> {
        let tip_header = self.tip_header.ok_or_else(|| {
            SnapshotTailFinalizeError::Local(
                "snapshot tail cannot finalize without a block body".to_string(),
            )
        })?;
        if terminal_bytes.len() < HISTORY_STEP_TERMINAL_BINDING_BYTES
            || terminal_bytes.len() > history_step_terminal_bytes_limit(tip_header.height)
        {
            return Err(SnapshotTailFinalizeError::Terminal(
                "snapshot tail terminal length is outside bounds".to_string(),
            ));
        }
        let metadata =
            HistoryStepTerminalMetadata::decode_prefix(&terminal_bytes).map_err(|error| {
                SnapshotTailFinalizeError::Terminal(format!(
                    "snapshot tail terminal metadata: {error}"
                ))
            })?;
        if metadata.terminal_height() != tip_header.height
            || metadata.terminal_hash() != noid_chain::block_header::semantic_header_id(&tip_header)
        {
            return Err(SnapshotTailFinalizeError::Terminal(
                "snapshot tail terminal does not bind its sealed tip".to_string(),
            ));
        }
        File::open(&self.path)
            .and_then(|file| file.sync_all())
            .map_err(|error| {
                SnapshotTailFinalizeError::Local(format!("finalize snapshot tail: {error}"))
            })?;
        self.armed = false;
        Ok(FinalizedSnapshotTail {
            path: self.path.clone(),
            boundary_height: self.boundary_height,
            boundary_hash: self.boundary_hash,
            boundary_chainwork: self.boundary_chainwork,
            tip_height: self.tip_height,
            tip_hash: self.tip_hash,
            tip_header: Some(tip_header),
            block_count: self.block_count,
            payload_bytes: self.payload_bytes,
            terminal_bytes,
            _inbound_memory_permit: inbound_memory_permit,
            armed: true,
        })
    }
}

impl FinalizedSnapshotTail {
    pub fn boundary_height(&self) -> u64 {
        self.boundary_height
    }

    pub fn boundary_hash(&self) -> [u8; 32] {
        self.boundary_hash
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }

    pub fn tip_header(&self) -> Result<BlockHeader, String> {
        self.tip_header
            .ok_or_else(|| "finalized snapshot tail has no tip header".to_string())
    }

    pub fn terminal_bytes(&self) -> &[u8] {
        &self.terminal_bytes
    }

    pub fn take_terminal_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.terminal_bytes)
    }

    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    pub fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub fn reader(&self) -> Result<SnapshotTailReader, String> {
        let mut file =
            File::open(&self.path).map_err(|error| format!("open finalized tail: {error}"))?;
        let mut header = [0u8; FILE_HEADER_BYTES as usize];
        file.read_exact(&mut header)
            .map_err(|error| format!("read finalized tail header: {error}"))?;
        if header[..4] != FILE_MAGIC
            || u64::from_le_bytes(header[4..12].try_into().unwrap()) != self.boundary_height
            || header[12..44] != self.boundary_hash
            || header[44..76] != self.boundary_chainwork
        {
            return Err("finalized tail header does not match its session".to_string());
        }
        Ok(SnapshotTailReader {
            reader: BufReader::new(file),
            next_height: self.boundary_height.saturating_add(1),
            previous_hash: self.boundary_hash,
            expected_tip_height: self.tip_height,
            expected_tip_hash: self.tip_hash,
            remaining: self.block_count,
            remaining_payload_bytes: self.payload_bytes,
        })
    }

    /// Resolve a header retained inside the compact suffix.
    pub fn header_at(&self, height: u64) -> Result<Option<BlockHeader>, String> {
        if height <= self.boundary_height || height > self.tip_height {
            return Ok(None);
        }
        let mut reader = self.reader()?;
        while let Some(block_bytes) = reader.next_block()? {
            let block = Block::from_bytes(&block_bytes)
                .map_err(|error| format!("decode finalized tail block: {error:?}"))?;
            if block.header.height == height {
                return Ok(Some(block.header));
            }
        }
        Ok(None)
    }
}

impl SnapshotTailReader {
    pub fn next_block(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.remaining == 0 {
            if self.remaining_payload_bytes != 0 {
                return Err("finalized tail byte accounting did not close".to_string());
            }
            if self.next_height.saturating_sub(1) != self.expected_tip_height
                || self.previous_hash != self.expected_tip_hash
            {
                return Err("finalized tail does not end at its sealed tip".to_string());
            }
            let position = self
                .reader
                .stream_position()
                .map_err(|error| format!("inspect finalized tail position: {error}"))?;
            let length = self
                .reader
                .get_ref()
                .metadata()
                .map_err(|error| format!("inspect finalized tail length: {error}"))?
                .len();
            if position != length {
                return Err("finalized tail contains trailing bytes".to_string());
            }
            return Ok(None);
        }

        let mut encoded_len = [0u8; RECORD_HEADER_BYTES as usize];
        self.reader
            .read_exact(&mut encoded_len)
            .map_err(|error| format!("read tail record length: {error}"))?;
        let encoded_len = u32::from_le_bytes(encoded_len) as usize;
        if encoded_len == 0 || encoded_len > MAX_BLOCK_BYTES {
            return Err("finalized tail record length is outside bounds".to_string());
        }
        if encoded_len as u64 > self.remaining_payload_bytes {
            return Err("finalized tail record exceeds byte accounting".to_string());
        }
        let mut block_bytes = Vec::new();
        block_bytes
            .try_reserve_exact(encoded_len)
            .map_err(|_| "allocate finalized tail block".to_string())?;
        block_bytes.resize(encoded_len, 0);
        self.reader
            .read_exact(&mut block_bytes)
            .map_err(|error| format!("read finalized tail payload: {error}"))?;
        let block = Block::from_bytes(&block_bytes)
            .map_err(|error| format!("decode finalized tail block: {error:?}"))?;
        if block.header.height != self.next_height
            || block.header.prev_block_hash != self.previous_hash
        {
            return Err(format!(
                "finalized tail block {} is outside its staged sequence",
                block.header.height
            ));
        }
        self.next_height = self.next_height.saturating_add(1);
        self.previous_hash = noid_chain::hash_block_header(&block.header);
        self.remaining -= 1;
        self.remaining_payload_bytes -= encoded_len as u64;
        Ok(Some(block_bytes))
    }
}

impl Drop for SnapshotTailStaging {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl Drop for FinalizedSnapshotTail {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn short_hash(hash: [u8; 32]) -> String {
    let mut out = String::with_capacity(16);
    for byte in hash.iter().take(8) {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::genesis::genesis_header;

    fn linked_block(parent: &Block, height: u64) -> Block {
        let mut header = parent.header;
        header.height = height;
        header.prev_block_hash = noid_chain::hash_block_header(&parent.header);
        header.timestamp = header.timestamp.saturating_add(15);
        Block {
            header,
            transactions: Vec::new(),
        }
    }

    fn terminal_for(block: &Block) -> Vec<u8> {
        let mut terminal = noid_chain::HistoryStepTerminalMetadata::new(
            block.header.height,
            noid_chain::block_header::semantic_header_id(&block.header),
            0,
        )
        .unwrap()
        .encode_prefix()
        .to_vec();
        terminal.push(1);
        terminal
    }

    #[test]
    fn empty_tail_cannot_claim_a_recursive_suffix() {
        let root = tempfile::tempdir().unwrap();
        let boundary = genesis_header();
        let hash = noid_chain::hash_block_header(&boundary);
        assert!(SnapshotTailStaging::create(root.path(), 0, hash, [0; 32])
            .unwrap()
            .finalize(vec![1], None)
            .is_err());
    }

    #[test]
    fn finalized_tail_rejects_trailing_bytes() {
        let root = tempfile::tempdir().unwrap();
        let genesis = Block {
            header: genesis_header(),
            transactions: Vec::new(),
        };
        let hash = noid_chain::hash_block_header(&genesis.header);
        let block = linked_block(&genesis, 1);
        let finalized = SnapshotTailStaging::create(root.path(), 0, hash, [0; 32])
            .unwrap()
            .append(block.to_bytes())
            .unwrap()
            .finalize(terminal_for(&block), None)
            .unwrap();
        assert!(finalized.reader().unwrap().next_block().unwrap().is_some());
        let mut file = OpenOptions::new()
            .append(true)
            .open(&finalized.path)
            .unwrap();
        file.write_all(&[1]).unwrap();
        let mut reader = finalized.reader().unwrap();
        assert!(reader.next_block().unwrap().is_some());
        assert!(reader.next_block().is_err());
    }

    #[test]
    fn tail_rejects_unlinked_bodies_and_a_terminal_for_another_tip() {
        let root = tempfile::tempdir().unwrap();
        let genesis = Block {
            header: genesis_header(),
            transactions: Vec::new(),
        };
        let boundary_hash = noid_chain::hash_block_header(&genesis.header);
        let first = linked_block(&genesis, 1);
        let mut unlinked = linked_block(&genesis, 1);
        unlinked.header.prev_block_hash = [0x55; 32];
        assert!(
            SnapshotTailStaging::create(root.path(), 0, boundary_hash, [0; 32])
                .unwrap()
                .append(unlinked.to_bytes())
                .is_err()
        );

        let staged = SnapshotTailStaging::create(root.path(), 0, boundary_hash, [0; 32])
            .unwrap()
            .append(first.to_bytes())
            .unwrap();
        assert!(staged.finalize(terminal_for(&genesis), None).is_err());
    }

    #[test]
    fn linked_tail_round_trips_height_hash_and_chainwork() {
        let root = tempfile::tempdir().unwrap();
        let genesis = Block {
            header: genesis_header(),
            transactions: Vec::new(),
        };
        let boundary_hash = noid_chain::hash_block_header(&genesis.header);
        let boundary_work = noid_chain::block_work(&genesis.header.difficulty_target);
        let first = linked_block(&genesis, 1);
        let second = linked_block(&first, 2);
        let expected_work = noid_chain::add_work(
            &noid_chain::add_work(
                &boundary_work,
                &noid_chain::block_work(&first.header.difficulty_target),
            ),
            &noid_chain::block_work(&second.header.difficulty_target),
        );

        let staged = SnapshotTailStaging::create(root.path(), 0, boundary_hash, boundary_work)
            .unwrap()
            .append(first.to_bytes())
            .unwrap()
            .append(second.to_bytes())
            .unwrap();
        assert_eq!(staged.tip_height(), 2);
        assert_eq!(
            staged.tip_hash(),
            noid_chain::hash_block_header(&second.header)
        );
        assert_eq!(staged.tip_chainwork(), expected_work);

        let finalized = staged.finalize(terminal_for(&second), None).unwrap();
        assert_eq!(finalized.tip_header().unwrap(), second.header);
        assert_eq!(finalized.header_at(1).unwrap(), Some(first.header));
        let mut reader = finalized.reader().unwrap();
        assert_eq!(reader.next_block().unwrap(), Some(first.to_bytes()));
        assert_eq!(reader.next_block().unwrap(), Some(second.to_bytes()));
        assert_eq!(reader.next_block().unwrap(), None);
    }

    #[test]
    fn linked_batch_uses_the_same_tail_invariants() {
        let root = tempfile::tempdir().unwrap();
        let genesis = Block {
            header: genesis_header(),
            transactions: Vec::new(),
        };
        let boundary_hash = noid_chain::hash_block_header(&genesis.header);
        let first = linked_block(&genesis, 1);
        let second = linked_block(&first, 2);
        let staged = SnapshotTailStaging::create(root.path(), 0, boundary_hash, [0; 32])
            .unwrap()
            .append_batch(vec![first.to_bytes(), second.to_bytes()])
            .unwrap();
        assert_eq!(staged.tip_height(), 2);
        assert_eq!(staged.block_count(), 2);

        let mut broken = second;
        broken.header.prev_block_hash = [0x55; 32];
        assert!(
            SnapshotTailStaging::create(root.path(), 0, boundary_hash, [0; 32])
                .unwrap()
                .append_batch(vec![first.to_bytes(), broken.to_bytes()])
                .is_err()
        );
    }
}
