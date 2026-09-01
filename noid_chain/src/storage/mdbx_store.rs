// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! MDBX-backed persistent storage for the chain.
//!
//! `MdbxStore` owns the MDBX `Database` and provides methods for
//! all persistent chain data: headers, undo logs, segments, recent blocks,
//! and chain tip.
//!
//! The core operation is `commit_block`, which writes all block-related data in
//! one atomic MDBX transaction.

use std::{borrow::Cow, path::Path, sync::Arc};

use libmdbx::{
    Database, DatabaseOptions, Mode, NoWriteMap, ObjectLength, Table, TableFlags, Transaction,
    WriteFlags, RO, RW,
};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_tx::unpack_amount_creation_id;

use crate::block_header::BlockHeader;
use crate::consensus::da_prune::BlockUndoLog;
use crate::consensus::params::{
    CONSENSUS_FINALITY_DEPTH, RETAINED_BLOCK_SERVING_DEPTH, UNDO_RETENTION_DEPTH,
};
use crate::exact_state_hash::slot_leaf_hash;
use crate::fri_state::SlotValue;
use crate::header_anchor::{
    compute_header_chain_anchor, extend_header_chain_anchor, extend_header_chain_anchor_prehashed,
    HeaderChainAnchor, HeaderChainAnchorError,
};
use crate::segmented_state::SegmentColumns;
use crate::state::{ChainState, StreamingSparseRoot};
use crate::storage::meta::ConsensusMeta;
use crate::storage::serial::{
    decode_chain_tip, decode_chain_work, decode_circulating_supply, decode_consensus_meta,
    decode_header, decode_header_chain_anchor, decode_segment, decode_segment_summary,
    decode_sparse_segment, decode_state_meta, decode_tx_index_value, decode_undo_log,
    encode_chain_tip, encode_chain_work, encode_consensus_meta, encode_header,
    encode_header_chain_anchor, encode_segment, encode_segment_summary, encode_state_meta,
    encode_tx_index_value, encode_undo_log, encoded_segment_live_count_from_len, u64_from_key,
    u64_key,
};
use crate::storage::snapshot_staging::{FinalizedSnapshotStaging, SnapshotStagingError};

// ---------------------------------------------------------------------------
// Table names
// ---------------------------------------------------------------------------
const T_HEADERS: &str = "headers";
const T_HEADER_ANCHORS: &str = "header_anchors";
const T_HASH_TO_HEIGHT: &str = "h2h";
const T_CHAIN_TIP: &str = "tip";
const T_CONSENSUS_META: &str = "consensus_meta";
const T_CHAIN_WORK: &str = "chain_work";
const T_UNDO_LOGS: &str = "undo";
const T_SEGMENTS: &str = "segments";
/// Compact restart accelerator. Key: segment_id(u16 LE). Value:
/// live_count(u32 LE) + exact segment root([u8; 32]). The complete exact-root
/// set is authenticated against the canonical tip header during restart;
/// dense columns are checked lazily when first touched.
const T_SEGMENT_SUMMARIES: &str = "segment_summaries";
const T_STATE_META: &str = "state_meta";
const T_RECENT_BLOCKS: &str = "recent";
/// Content-addressable cache of complete block bodies, independent of the
/// canonical height row. Snapshot and reorg plans may outlive the moving
/// retained-height window, and displaced branch bodies remain useful exact
/// objects until this bounded operational cache expires.
/// Key: `height_be[8] || block_id[32]`.
const T_BLOCK_BODY_OBJECTS: &str = "block_body_objects";
/// Transaction index for receipt lookup. Key: canonical logical txid (32B).
/// Value: `(height, logical_position)` (12B), with coinbase at position zero.
const T_TX_INDEX: &str = "tx_index";
/// Detached current-height HistoryStep terminals carried by every
/// canonical non-genesis block. Retained and served with the block so peers
/// can natively re-verify the exact accepted history step.
/// Key: height (u64 LE). Value: serialized terminal package bytes.
const T_HISTORY_STEP_TERMINALS: &str = "history_step_terminals";
/// Content-addressable cache of complete recursive terminals, independent of
/// the canonical height row. One-terminal suffix application may place local
/// authorization markers at intermediate canonical heights, while recently
/// displaced or boundary proofs must remain serveable to other nodes.
/// Key: `height_be[8] || semantic_header_id[32] || proof_class[1]`.
const T_HISTORY_STEP_PROOF_OBJECTS: &str = "history_step_proof_objects";
/// Owner UTXO index. Key: `owner[32] || slot_be[4]`. Value:
/// `packed_value_le[16]`. `packed_value` contains both the amount and the
/// allocation-counter creation id, so an index lookup can be checked exactly
/// against the durable state segment before it is exposed.  One MDBX record
/// per live slot avoids ever materializing one owner's complete UTXO set while
/// updating or rebuilding the index. Maintained incrementally in
/// `commit_block`.
const T_OWNER_INDEX: &str = "owner_idx";
const T_RETENTION_META: &str = "retention_meta";
const N_TABLES: u64 = 17;

/// Maximum reclaimed-page list searched for one contiguous overflow value.
///
/// HistoryStep terminals are close to one MiB and rotate through two bounded
/// tables.  The libmdbx dynamic default is only about 2,044 pages on a small
/// database; once free space becomes fragmented, that search can miss every
/// suitable run and extend the file despite gigabytes already being free.
/// 65,536 page numbers cover 256 MiB at the production 4 KiB page size while
/// keeping the temporary allocator list bounded and small.
const MDBX_RECLAIM_PAGE_SEARCH_LIMIT: u64 = 65_536;

// Single-entry table keys
const KEY_TIP: &[u8] = &[0u8];
const KEY_META: &[u8] = &[0u8];
const KEY_CONSENSUS_META: &[u8] = &[0u8];
const KEY_RETAINED_PAYLOAD_PRUNE_WATERMARK: &[u8] = &[2u8];
const KEY_VERIFIED_SUFFIX_AUTHORITY: &[u8] = &[3u8];

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum StoreError {
    Mdbx(libmdbx::Error),
    Decode(&'static str),
    HeaderAnchor(HeaderChainAnchorError),
    SnapshotStaging(SnapshotStagingError),
    SnapshotHeaders(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mdbx(e) => write!(f, "mdbx: {e}"),
            Self::Decode(ctx) => write!(f, "decode error: {ctx}"),
            Self::HeaderAnchor(e) => write!(f, "header anchor: {e}"),
            Self::SnapshotStaging(e) => write!(f, "snapshot staging: {e}"),
            Self::SnapshotHeaders(e) => write!(f, "snapshot headers: {e}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Mdbx(error) => Some(error),
            Self::HeaderAnchor(error) => Some(error),
            Self::SnapshotStaging(error) => Some(error),
            Self::Decode(_) | Self::SnapshotHeaders(_) => None,
        }
    }
}

impl From<libmdbx::Error> for StoreError {
    fn from(e: libmdbx::Error) -> Self {
        Self::Mdbx(e)
    }
}

impl From<HeaderChainAnchorError> for StoreError {
    fn from(e: HeaderChainAnchorError) -> Self {
        Self::HeaderAnchor(e)
    }
}

impl From<SnapshotStagingError> for StoreError {
    fn from(e: SnapshotStagingError) -> Self {
        Self::SnapshotStaging(e)
    }
}

// ---------------------------------------------------------------------------
// MdbxStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct MdbxStore {
    db: Arc<Database<NoWriteMap>>,
    block_body_object_retention_floor: Arc<std::sync::atomic::AtomicU64>,
}

/// One owned, already native-validated header record from a sealed snapshot
/// candidate suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedHeaderBatchRecord {
    pub header: BlockHeader,
    pub hash: [u8; 32],
    pub cumulative_chainwork: [u8; 32],
}

/// A sealed, native-validated candidate header suffix consumed exactly once
/// by the atomic snapshot installer. Implementations stream records from
/// private staging storage, so an arbitrarily deep suffix never has to be
/// materialized in RAM.
pub trait SnapshotHeaderInstallSource {
    /// Last canonical record from which the staged suffix was validated.
    fn base_record(&self) -> VerifiedHeaderBatchRecord;

    /// Exact authenticated target record named by the snapshot manifest.
    fn target_record(&self) -> VerifiedHeaderBatchRecord;

    /// Exact bounded suffix required immediately after snapshot installation
    /// for MTP, expansion and transaction-epoch checks.
    fn recent_headers(&self) -> &[BlockHeader];

    /// Yield the next record after `base_record`, in ascending height order.
    fn next_record(&mut self) -> Result<Option<VerifiedHeaderBatchRecord>, String>;
}

/// One stable MVCC view used by bounded historical-state reconstruction.
///
/// The transaction owns no decoded payload collection. Each requested header,
/// undo record, or segment is read on demand from the same database version,
/// while a concurrent writer may advance the live canonical tip.
pub(super) struct MdbxHistoricalReadSnapshot<'a> {
    txn: Transaction<'a, RO, NoWriteMap>,
}

impl MdbxHistoricalReadSnapshot<'_> {
    pub(super) fn get_chain_tip(&self) -> Result<Option<(u64, [u8; 32])>, StoreError> {
        let table = self.txn.open_table(Some(T_CHAIN_TIP))?;
        let raw: Option<[u8; 40]> = self.txn.get(&table, KEY_TIP)?;
        Ok(raw.as_ref().and_then(|raw| decode_chain_tip(raw)))
    }

    pub(super) fn get_state_meta(&self) -> Result<Option<(u32, u64, u64)>, StoreError> {
        let table = self.txn.open_table(Some(T_STATE_META))?;
        let raw: Option<Vec<u8>> = self.txn.get(&table, KEY_META)?;
        Ok(raw.and_then(|raw| decode_state_meta(&raw)))
    }

    pub(super) fn get_header(&self, height: u64) -> Result<Option<BlockHeader>, StoreError> {
        let table = self.txn.open_table(Some(T_HEADERS))?;
        let raw: Option<Vec<u8>> = self.txn.get(&table, &u64_key(height))?;
        Ok(raw.and_then(|raw| decode_header(&raw)))
    }

    pub(super) fn get_chain_work(&self, height: u64) -> Result<Option<[u8; 32]>, StoreError> {
        let table = self.txn.open_table(Some(T_CHAIN_WORK))?;
        let raw: Option<Vec<u8>> = self.txn.get(&table, &u64_key(height))?;
        Ok(raw.and_then(|raw| decode_chain_work(&raw)))
    }

    pub(super) fn get_undo_log(&self, height: u64) -> Result<Option<BlockUndoLog>, StoreError> {
        let table = self.txn.open_table(Some(T_UNDO_LOGS))?;
        let raw: Option<Vec<u8>> = self.txn.get(&table, &u64_key(height))?;
        Ok(raw.and_then(|raw| decode_undo_log(&raw)))
    }

    /// Read the exact canonical HistoryStep terminal from this pinned MVCC
    /// view. Snapshot generations retain the finalized boundary terminal
    /// alongside their immutable state and suffix, so serving does not race
    /// the live retained-payload pruner.
    pub(super) fn get_history_step_terminal_at(
        &self,
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        read_history_step_terminal(&self.txn, height, block_hash)
    }

    /// Read a complete recent terminal independently of the canonical height
    /// row. One-terminal suffix admission intentionally stores compact local
    /// markers at intermediate heights; snapshot export may use only the
    /// separately retained full proof object for such a boundary.
    pub(super) fn get_any_history_step_proof_object(
        &self,
        height: u64,
        semantic_id: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        for proof_class in 0..crate::history_step::HISTORY_STEP_CLASS_COUNT {
            if let Some(bytes) =
                read_history_step_proof_object(&self.txn, height, semantic_id, proof_class)?
            {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    /// Read one canonical retained block body from this same pinned MVCC view.
    /// Snapshot generations authenticate the complete body sequence together
    /// with the one full HistoryStep terminal at its final height; compact
    /// recursive-suffix markers are local storage authority and never become
    /// network proof payloads.
    pub(super) fn get_recent_block(&self, height: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let key = u64_key(height);
        let blocks = self.txn.open_table(Some(T_RECENT_BLOCKS))?;
        let block_len: Option<ObjectLength> = self.txn.get(&blocks, &key)?;
        let Some(ObjectLength(block_len)) = block_len else {
            return Ok(None);
        };
        let block_bytes: Vec<u8> = self
            .txn
            .get(&blocks, &key)?
            .ok_or(StoreError::Decode("accepted block disappeared during read"))?;
        if block_bytes.len() != block_len {
            return Err(StoreError::Decode(
                "accepted block length changed during read",
            ));
        }
        let block = crate::Block::from_bytes(&block_bytes)
            .map_err(|_| StoreError::Decode("accepted block body is malformed"))?;
        if block.header.height != height {
            return Err(StoreError::Decode(
                "accepted block height differs from its key",
            ));
        }
        let headers = self.txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<Vec<u8>> = self.txn.get(&headers, &key)?;
        if header_raw
            .as_deref()
            .and_then(canonical_hash_from_encoded_header)
            != Some(crate::block_header::block_id(&block.header))
        {
            return Err(StoreError::Decode("accepted block body is not canonical"));
        }
        Ok(Some(block_bytes))
    }

    pub(super) fn get_encoded_segment(
        &self,
        segment_id: u16,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let table = self.txn.open_table(Some(T_SEGMENTS))?;
        let encoded = self.txn.get(&table, &segment_id.to_le_bytes())?;
        Ok(encoded)
    }

    pub(super) fn get_segment(
        &self,
        segment_id: u16,
    ) -> Result<Option<(u8, SegmentColumns)>, StoreError> {
        self.get_encoded_segment(segment_id)?
            .map(|encoded| {
                decode_segment(&encoded)
                    .ok_or(StoreError::Decode("invalid stored historical segment"))
            })
            .transpose()
    }

    pub(super) fn segment_ids(&self) -> Result<Vec<u16>, StoreError> {
        let table = self.txn.open_table(Some(T_SEGMENTS))?;
        let mut cursor = self.txn.cursor(&table)?;
        let mut segment_ids = Vec::new();
        let mut item: Option<(Vec<u8>, ())> = cursor.first()?;
        while let Some((key, ())) = item {
            if key.len() != 2 {
                return Err(StoreError::Decode("invalid stored segment key"));
            }
            segment_ids.push(u16::from_le_bytes([key[0], key[1]]));
            item = cursor.next()?;
        }
        sort_unique_segment_ids(segment_ids)
    }
}

// ---------------------------------------------------------------------------
// Owner index helpers
// ---------------------------------------------------------------------------

const OWNER_INDEX_KEY_BYTES: usize = 32 + 4;
const OWNER_INDEX_VALUE_BYTES: usize = 16;

/// One owner-index entry after exact verification against the durable state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedOwnerUtxo {
    pub slot_index: u32,
    pub amount: u64,
    pub creation_id: u64,
}

/// Exact owner view tied to one atomic durable chain snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOwnerSnapshot {
    /// Owner key whose complete derived index entry was queried.
    pub owner: [u8; 32],
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    pub utxos: Vec<VerifiedOwnerUtxo>,
}

/// Owned per-block material accumulated while a replacement branch is fully
/// validated in RAM.  `commit_reorg` writes the entire vector together with
/// the final exact state in one MDBX transaction.
#[derive(Debug)]
pub(crate) struct StagedAcceptedBlockCommit {
    pub header: BlockHeader,
    pub hash: [u8; 32],
    pub cumulative_chainwork: [u8; 32],
    pub undo_log: BlockUndoLog,
}

/// Payload authorization used by the single durable block-commit path.
///
/// Ordinary blocks carry their complete current-height terminal. During
/// snapshot catch-up, intermediate bodies are already covered by one verified
/// recursive suffix terminal; storing another ~750 KiB proof per height would
/// defeat the compact transport. Those entries carry a fixed-size local
/// authorization marker tied to the persisted verified suffix authority.
#[derive(Clone, Copy)]
pub(crate) enum AcceptedBlockCommit<'a> {
    Complete(&'a crate::AcceptedBlockBundle),
    /// A complete accepted unit supplied as exact borrowed objects.
    ///
    /// This is used by the v2 object pipeline after a body and its terminal
    /// have been fetched independently.  Storage validates the same binding
    /// as `Complete`; the variant only avoids rebuilding/copying a roughly
    /// one-megabyte terminal into an `AcceptedBlockBundle`.
    CompleteObjects {
        block_bytes: &'a [u8],
        terminal_bytes: &'a [u8],
    },
    RecursiveSuffix {
        block_bytes: &'a [u8],
        authority_tip_height: u64,
        authority_tip_hash: [u8; 32],
    },
}

impl<'a> AcceptedBlockCommit<'a> {
    pub(crate) fn block_bytes(self) -> &'a [u8] {
        match self {
            Self::Complete(bundle) => bundle.block_bytes(),
            Self::CompleteObjects { block_bytes, .. }
            | Self::RecursiveSuffix { block_bytes, .. } => block_bytes,
        }
    }

    fn complete_terminal(self) -> Option<&'a [u8]> {
        match self {
            Self::Complete(bundle) => Some(bundle.history_step_terminal_bytes()),
            Self::CompleteObjects { terminal_bytes, .. } => Some(terminal_bytes),
            Self::RecursiveSuffix { .. } => None,
        }
    }

    fn recursive_authority(self) -> Option<(u64, [u8; 32])> {
        match self {
            Self::RecursiveSuffix {
                authority_tip_height,
                authority_tip_hash,
                ..
            } => Some((authority_tip_height, authority_tip_hash)),
            Self::Complete(_) | Self::CompleteObjects { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// HistoryStep terminal retention
// ---------------------------------------------------------------------------

const RETAINED_PAYLOAD_PRUNE_WATERMARK_MAGIC: [u8; 4] = *b"RPW1";
const RETAINED_PAYLOAD_PRUNE_WATERMARK_BYTES: usize = 4 + 8;
const VERIFIED_SUFFIX_AUTHORITY_MAGIC: [u8; 4] = *b"VSA1";
const VERIFIED_SUFFIX_AUTHORITY_BYTES: usize = 4 + 8 + 32 + 8 + 32;
const RECURSIVE_SUFFIX_MARKER_MAGIC: [u8; 4] = *b"RSM1";
const RECURSIVE_SUFFIX_MARKER_BYTES: usize =
    crate::history_step::HISTORY_STEP_TERMINAL_BINDING_BYTES + 4 + 8 + 32;
const HISTORY_STEP_PROOF_OBJECT_KEY_BYTES: usize = 8 + 32 + 1;
const BLOCK_BODY_OBJECT_KEY_BYTES: usize = 8 + 32;
/// Operational proof availability window. This is not a consensus retention
/// rule and may be increased without changing block or proof validity.
const HISTORY_STEP_PROOF_OBJECT_RETENTION_DEPTH: u64 = 128;
const HISTORY_STEP_PROOF_OBJECT_PRUNE_LIMIT: usize = 32;
/// Bodies and terminals use the same operational availability horizon. This
/// is deliberately independent of finality and consensus validity.
const BLOCK_BODY_OBJECT_RETENTION_DEPTH: u64 = HISTORY_STEP_PROOF_OBJECT_RETENTION_DEPTH;
/// An active data-plane lease may extend retention, but never without bound.
/// At the 20-second target this is about 2.8 hours of exact body availability.
const BLOCK_BODY_OBJECT_MAX_PIN_DEPTH: u64 = 512;
const BLOCK_BODY_OBJECT_PRUNE_LIMIT: usize = 8;
const BLOCK_BODY_OBJECT_PRUNE_BYTE_LIMIT: usize =
    crate::consensus::wire_limits::MAX_BLOCK_BYTES * 2;
/// Bound numeric maintenance work even after a large snapshot jump.
const RETAINED_PAYLOAD_PRUNE_HEIGHT_LIMIT: usize = 16;
/// One retained block plus terminal is bounded by the canonical wire caps.
const RETAINED_PAYLOAD_PRUNE_BYTE_LIMIT: usize = crate::consensus::wire_limits::MAX_BLOCK_BYTES
    + crate::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_BYTES;
/// A normal retired height deletes a block and terminal; advancing the exact
/// boundary additionally removes one block body.
const RETAINED_PAYLOAD_PRUNE_DELETE_LIMIT: usize = RETAINED_PAYLOAD_PRUNE_HEIGHT_LIMIT * 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VerifiedSuffixAuthorityRecord {
    boundary_height: u64,
    boundary_hash: [u8; 32],
    tip_height: u64,
    tip_hash: [u8; 32],
}

fn encode_verified_suffix_authority(
    authority: VerifiedSuffixAuthorityRecord,
) -> [u8; VERIFIED_SUFFIX_AUTHORITY_BYTES] {
    let mut encoded = [0u8; VERIFIED_SUFFIX_AUTHORITY_BYTES];
    encoded[..4].copy_from_slice(&VERIFIED_SUFFIX_AUTHORITY_MAGIC);
    encoded[4..12].copy_from_slice(&authority.boundary_height.to_le_bytes());
    encoded[12..44].copy_from_slice(&authority.boundary_hash);
    encoded[44..52].copy_from_slice(&authority.tip_height.to_le_bytes());
    encoded[52..84].copy_from_slice(&authority.tip_hash);
    encoded
}

fn decode_verified_suffix_authority(bytes: &[u8]) -> Option<VerifiedSuffixAuthorityRecord> {
    if bytes.len() != VERIFIED_SUFFIX_AUTHORITY_BYTES
        || bytes[..4] != VERIFIED_SUFFIX_AUTHORITY_MAGIC
    {
        return None;
    }
    let authority = VerifiedSuffixAuthorityRecord {
        boundary_height: u64::from_le_bytes(bytes[4..12].try_into().ok()?),
        boundary_hash: bytes[12..44].try_into().ok()?,
        tip_height: u64::from_le_bytes(bytes[44..52].try_into().ok()?),
        tip_hash: bytes[52..84].try_into().ok()?,
    };
    (authority.boundary_height < authority.tip_height).then_some(authority)
}

fn encode_recursive_suffix_marker(
    header: &BlockHeader,
    class_slot: usize,
    authority_tip_height: u64,
    authority_tip_hash: [u8; 32],
) -> Result<[u8; RECURSIVE_SUFFIX_MARKER_BYTES], StoreError> {
    let class_id = u8::try_from(class_slot)
        .map_err(|_| StoreError::Decode("recursive suffix class does not fit u8"))?;
    let metadata = crate::history_step::HistoryStepTerminalMetadata::new(
        header.height,
        crate::block_header::semantic_header_id(header),
        class_id,
    )
    .map_err(|_| StoreError::Decode("recursive suffix class is not canonical"))?;
    let mut encoded = [0u8; RECURSIVE_SUFFIX_MARKER_BYTES];
    let prefix = metadata.encode_prefix();
    encoded[..prefix.len()].copy_from_slice(&prefix);
    let marker_start = prefix.len();
    encoded[marker_start..marker_start + 4].copy_from_slice(&RECURSIVE_SUFFIX_MARKER_MAGIC);
    encoded[marker_start + 4..marker_start + 12]
        .copy_from_slice(&authority_tip_height.to_le_bytes());
    encoded[marker_start + 12..marker_start + 44].copy_from_slice(&authority_tip_hash);
    Ok(encoded)
}

fn recursive_suffix_marker_authority(
    bytes: &[u8],
    height: u64,
    semantic_id: [u8; 32],
    class_slot: Option<usize>,
) -> Option<(u64, [u8; 32])> {
    if bytes.len() != RECURSIVE_SUFFIX_MARKER_BYTES {
        return None;
    }
    let prefix_len = crate::history_step::HISTORY_STEP_TERMINAL_BINDING_BYTES;
    if bytes[prefix_len..prefix_len + 4] != RECURSIVE_SUFFIX_MARKER_MAGIC {
        return None;
    }
    let (actual_height, actual_semantic, actual_class) = history_step_terminal_metadata(bytes)?;
    if actual_height != height
        || actual_semantic != semantic_id
        || class_slot.is_some_and(|expected| actual_class != expected)
    {
        return None;
    }
    let authority_height =
        u64::from_le_bytes(bytes[prefix_len + 4..prefix_len + 12].try_into().ok()?);
    let authority_hash = bytes[prefix_len + 12..prefix_len + 44].try_into().ok()?;
    (authority_height >= height).then_some((authority_height, authority_hash))
}

fn history_step_proof_object_key(
    height: u64,
    semantic_id: [u8; 32],
    proof_class: u8,
) -> [u8; HISTORY_STEP_PROOF_OBJECT_KEY_BYTES] {
    let mut key = [0u8; HISTORY_STEP_PROOF_OBJECT_KEY_BYTES];
    // Big endian keeps the operational cache ordered by height so bounded
    // pruning never scans the complete table.
    key[..8].copy_from_slice(&height.to_be_bytes());
    key[8..40].copy_from_slice(&semantic_id);
    key[40] = proof_class;
    key
}

fn block_body_object_key(height: u64, block_hash: [u8; 32]) -> [u8; BLOCK_BODY_OBJECT_KEY_BYTES] {
    let mut key = [0u8; BLOCK_BODY_OBJECT_KEY_BYTES];
    key[..8].copy_from_slice(&height.to_be_bytes());
    key[8..].copy_from_slice(&block_hash);
    key
}

fn archive_block_body_object(
    txn: &Transaction<'_, RW, NoWriteMap>,
    expected_height: u64,
    expected_hash: [u8; 32],
    block_bytes: &[u8],
) -> Result<(), StoreError> {
    if block_bytes.is_empty() || block_bytes.len() > crate::consensus::wire_limits::MAX_BLOCK_BYTES
    {
        return Err(StoreError::Decode(
            "archived block body length is outside hard bounds",
        ));
    }
    let block = crate::Block::from_bytes(block_bytes)
        .map_err(|_| StoreError::Decode("archived block body is malformed"))?;
    if block.header.height != expected_height
        || crate::block_header::block_id(&block.header) != expected_hash
    {
        return Err(StoreError::Decode(
            "archived block body does not match its object key",
        ));
    }
    let table = txn.open_table(Some(T_BLOCK_BODY_OBJECTS))?;
    txn.put(
        &table,
        block_body_object_key(expected_height, expected_hash),
        block_bytes,
        WriteFlags::empty(),
    )?;
    Ok(())
}

fn archive_history_step_proof_object(
    txn: &Transaction<'_, RW, NoWriteMap>,
    terminal_bytes: &[u8],
) -> Result<(), StoreError> {
    if terminal_bytes.len() > crate::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_BYTES {
        return Err(StoreError::Decode(
            "archived HistoryStep terminal exceeds hard bounds",
        ));
    }
    let metadata = crate::history_step::HistoryStepTerminalMetadata::decode_prefix(terminal_bytes)
        .map_err(|_| StoreError::Decode("archived HistoryStep terminal metadata is malformed"))?;
    if recursive_suffix_marker_authority(
        terminal_bytes,
        metadata.terminal_height(),
        metadata.terminal_hash(),
        Some(metadata.current_class_slot()),
    )
    .is_some()
    {
        return Err(StoreError::Decode(
            "recursive suffix marker cannot enter the proof-object cache",
        ));
    }
    let table = txn.open_table(Some(T_HISTORY_STEP_PROOF_OBJECTS))?;
    txn.put(
        &table,
        history_step_proof_object_key(
            metadata.terminal_height(),
            metadata.terminal_hash(),
            metadata.class_id(),
        ),
        terminal_bytes,
        WriteFlags::empty(),
    )?;
    Ok(())
}

fn prune_history_step_proof_objects(
    txn: &Transaction<'_, RW, NoWriteMap>,
    current_height: u64,
) -> Result<(), StoreError> {
    let cutoff = current_height.saturating_sub(HISTORY_STEP_PROOF_OBJECT_RETENTION_DEPTH);
    let table = txn.open_table(Some(T_HISTORY_STEP_PROOF_OBJECTS))?;
    let deletions = {
        let mut cursor = txn.cursor(&table)?;
        let mut item: Option<(Vec<u8>, ObjectLength)> = cursor.first()?;
        let mut keys = Vec::new();
        while let Some((key, _)) = item {
            if key.len() != HISTORY_STEP_PROOF_OBJECT_KEY_BYTES {
                return Err(StoreError::Decode(
                    "invalid HistoryStep proof-object key length",
                ));
            }
            let height = u64::from_be_bytes(key[..8].try_into().unwrap());
            if height >= cutoff || keys.len() == HISTORY_STEP_PROOF_OBJECT_PRUNE_LIMIT {
                break;
            }
            keys.push(key);
            item = cursor.next()?;
        }
        keys
    };
    for key in deletions {
        txn.del(&table, key, None)?;
    }
    Ok(())
}

fn prune_block_body_objects(
    txn: &Transaction<'_, RW, NoWriteMap>,
    current_height: u64,
    retention_floor: Option<u64>,
) -> Result<(), StoreError> {
    let mut cutoff = current_height.saturating_sub(BLOCK_BODY_OBJECT_RETENTION_DEPTH);
    if let Some(floor) = retention_floor {
        let bounded_floor =
            floor.max(current_height.saturating_sub(BLOCK_BODY_OBJECT_MAX_PIN_DEPTH));
        cutoff = cutoff.min(bounded_floor.saturating_add(1));
    }
    let table = txn.open_table(Some(T_BLOCK_BODY_OBJECTS))?;
    let deletions = {
        let mut cursor = txn.cursor(&table)?;
        let mut item: Option<(Vec<u8>, ObjectLength)> = cursor.first()?;
        let mut keys = Vec::new();
        let mut bytes = 0usize;
        while let Some((key, ObjectLength(value_len))) = item {
            if key.len() != BLOCK_BODY_OBJECT_KEY_BYTES {
                return Err(StoreError::Decode("invalid block-body object key length"));
            }
            let height = u64::from_be_bytes(key[..8].try_into().unwrap());
            if height >= cutoff || keys.len() == BLOCK_BODY_OBJECT_PRUNE_LIMIT {
                break;
            }
            if !keys.is_empty()
                && bytes
                    .checked_add(value_len)
                    .is_none_or(|total| total > BLOCK_BODY_OBJECT_PRUNE_BYTE_LIMIT)
            {
                break;
            }
            bytes = bytes.checked_add(value_len).ok_or(StoreError::Decode(
                "block-body prune byte accounting overflow",
            ))?;
            keys.push(key);
            item = cursor.next()?;
        }
        keys
    };
    for key in deletions {
        txn.del(&table, key, None)?;
    }
    Ok(())
}

fn recursive_suffix_marker_has_durable_authority(
    txn: &Transaction<'_, RW, NoWriteMap>,
    marker_height: u64,
    authority_tip_height: u64,
    authority_tip_hash: [u8; 32],
) -> Result<bool, StoreError> {
    if authority_tip_height <= marker_height {
        return Ok(false);
    }

    // While a compact suffix is only partially installed, its verified final
    // terminal is represented by one crash-recovery authority record. A later
    // completed suffix may overwrite that transient record, so it cannot be
    // the durable authority for completed history.
    let retention = txn.open_table(Some(T_RETENTION_META))?;
    let authority_raw: Option<Vec<u8>> = txn.get(&retention, KEY_VERIFIED_SUFFIX_AUTHORITY)?;
    if let Some(authority_raw) = authority_raw {
        let authority = decode_verified_suffix_authority(&authority_raw).ok_or(
            StoreError::Decode("verified recursive suffix authority is malformed"),
        )?;
        if authority.tip_height == authority_tip_height
            && authority.tip_hash == authority_tip_hash
            && marker_height > authority.boundary_height
            && marker_height < authority.tip_height
        {
            return Ok(true);
        }
    }

    // Once the suffix is complete, its full terminal at the exact canonical
    // tip is the permanent authority for every intermediate local marker. It
    // already carries the recursively verified ancestry, remains available
    // throughout the reorg window, and avoids retaining an overwrite-prone
    // singleton side record for each completed suffix.
    let headers = txn.open_table(Some(T_HEADERS))?;
    let authority_header_raw: Option<Vec<u8>> =
        txn.get(&headers, &u64_key(authority_tip_height))?;
    let Some(authority_header) = authority_header_raw.as_deref().and_then(decode_header) else {
        return Ok(false);
    };
    if authority_header.height != authority_tip_height
        || crate::block_header::block_id(&authority_header) != authority_tip_hash
    {
        return Ok(false);
    }

    let terminals = txn.open_table(Some(T_HISTORY_STEP_TERMINALS))?;
    let Some(ObjectLength(length)) = txn.get(&terminals, &u64_key(authority_tip_height))? else {
        return Ok(false);
    };
    if length == 0 || length > crate::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_BYTES {
        return Err(StoreError::Decode(
            "recursive suffix authority terminal exceeds hard bounds",
        ));
    }
    let authority_terminal: Vec<u8> =
        txn.get(&terminals, &u64_key(authority_tip_height))?
            .ok_or(StoreError::Decode(
                "recursive suffix authority terminal disappeared",
            ))?;
    let authority_semantic = crate::block_header::semantic_header_id(&authority_header);
    Ok(recursive_suffix_marker_authority(
        &authority_terminal,
        authority_tip_height,
        authority_semantic,
        None,
    )
    .is_none()
        && history_step_terminal_prefix_matches(
            &authority_terminal,
            authority_tip_height,
            authority_semantic,
        ))
}

fn validate_history_step_parent_boundary_in_rw_txn(
    txn: &Transaction<'_, RW, NoWriteMap>,
    header: &BlockHeader,
) -> Result<(), StoreError> {
    let parent_height = header
        .height
        .checked_sub(1)
        .ok_or(StoreError::Decode("genesis has no HistoryStep parent"))?;
    let headers = txn.open_table(Some(T_HEADERS))?;
    let parent_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(parent_height))?;
    let parent_is_exact = parent_raw
        .as_deref()
        .and_then(decode_header)
        .is_some_and(|parent| {
            parent.height == parent_height
                && crate::block_header::block_id(&parent) == header.prev_block_hash
        });
    if !parent_is_exact {
        return Err(StoreError::Decode(
            "HistoryStep parent header is not canonical",
        ));
    }

    if parent_height != 0 {
        let terminals = txn.open_table(Some(T_HISTORY_STEP_TERMINALS))?;
        let ObjectLength(length) = txn
            .get(&terminals, &u64_key(parent_height))?
            .ok_or(StoreError::Decode("HistoryStep parent terminal is missing"))?;
        if length == 0 || length > crate::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_BYTES {
            return Err(StoreError::Decode(
                "HistoryStep parent terminal exceeds hard bounds",
            ));
        }
        let parent_terminal: Vec<u8> =
            txn.get(&terminals, &u64_key(parent_height))?
                .ok_or(StoreError::Decode(
                    "HistoryStep parent terminal disappeared",
                ))?;
        let parent_semantic = crate::block_header::semantic_header_id(
            &parent_raw
                .as_deref()
                .and_then(decode_header)
                .ok_or(StoreError::Decode("HistoryStep parent header disappeared"))?,
        );
        let recursive_authority = recursive_suffix_marker_authority(
            &parent_terminal,
            parent_height,
            parent_semantic,
            None,
        );
        if let Some((authority_tip_height, authority_tip_hash)) = recursive_authority {
            if !recursive_suffix_marker_has_durable_authority(
                txn,
                parent_height,
                authority_tip_height,
                authority_tip_hash,
            )? {
                return Err(StoreError::Decode(
                    "recursive suffix parent authority is missing",
                ));
            }
        } else if !history_step_terminal_prefix_matches(
            &parent_terminal,
            parent_height,
            parent_semantic,
        ) {
            return Err(StoreError::Decode(
                "HistoryStep parent authorization is malformed",
            ));
        }
    }
    Ok(())
}

fn encode_retained_payload_prune_watermark(
    height: u64,
) -> [u8; RETAINED_PAYLOAD_PRUNE_WATERMARK_BYTES] {
    let mut encoded = [0u8; RETAINED_PAYLOAD_PRUNE_WATERMARK_BYTES];
    encoded[..4].copy_from_slice(&RETAINED_PAYLOAD_PRUNE_WATERMARK_MAGIC);
    encoded[4..].copy_from_slice(&height.to_le_bytes());
    encoded
}

fn decode_retained_payload_prune_watermark(encoded: &[u8]) -> Option<u64> {
    if encoded.len() != RETAINED_PAYLOAD_PRUNE_WATERMARK_BYTES
        || encoded[..4] != RETAINED_PAYLOAD_PRUNE_WATERMARK_MAGIC
    {
        return None;
    }
    Some(u64::from_le_bytes(encoded[4..12].try_into().ok()?))
}

fn retained_payload_prune_watermark_in_rw_txn(
    txn: &Transaction<'_, RW, NoWriteMap>,
) -> Result<Option<u64>, StoreError> {
    let table = txn.open_table(Some(T_RETENTION_META))?;
    let raw: Option<[u8; RETAINED_PAYLOAD_PRUNE_WATERMARK_BYTES]> =
        txn.get(&table, KEY_RETAINED_PAYLOAD_PRUNE_WATERMARK)?;
    raw.as_ref()
        .map(|raw| {
            decode_retained_payload_prune_watermark(raw).ok_or(StoreError::Decode(
                "invalid retained payload prune watermark",
            ))
        })
        .transpose()
}

fn set_retained_payload_prune_watermark(
    txn: &Transaction<'_, RW, NoWriteMap>,
    height: u64,
) -> Result<(), StoreError> {
    let table = txn.open_table(Some(T_RETENTION_META))?;
    txn.put(
        &table,
        KEY_RETAINED_PAYLOAD_PRUNE_WATERMARK,
        encode_retained_payload_prune_watermark(height),
        WriteFlags::empty(),
    )?;
    Ok(())
}

fn rewind_retained_payload_prune_watermark(
    txn: &Transaction<'_, RW, NoWriteMap>,
    ancestor_height: u64,
) -> Result<(), StoreError> {
    let Some(current) = retained_payload_prune_watermark_in_rw_txn(txn)? else {
        return Ok(());
    };
    if current <= ancestor_height {
        return Ok(());
    }
    if ancestor_height == 0 {
        let table = txn.open_table(Some(T_RETENTION_META))?;
        let _ = txn.del(&table, KEY_RETAINED_PAYLOAD_PRUNE_WATERMARK, None);
    } else {
        set_retained_payload_prune_watermark(txn, ancestor_height)?;
    }
    Ok(())
}

fn history_step_terminal_prefix_matches(bytes: &[u8], height: u64, semantic_id: [u8; 32]) -> bool {
    history_step_terminal_metadata(bytes).is_some_and(|(actual_height, actual_hash, _)| {
        actual_height == height && actual_hash == semantic_id
    })
}

fn history_step_terminal_matches_class(
    bytes: &[u8],
    height: u64,
    semantic_id: [u8; 32],
    class_slot: usize,
) -> bool {
    history_step_terminal_metadata(bytes).is_some_and(
        |(actual_height, actual_hash, actual_slot)| {
            actual_height == height && actual_hash == semantic_id && actual_slot == class_slot
        },
    )
}

fn history_step_terminal_metadata(bytes: &[u8]) -> Option<(u64, [u8; 32], usize)> {
    let metadata = crate::history_step::HistoryStepTerminalMetadata::decode_prefix(bytes).ok()?;
    let class_slot = metadata.current_class_slot();
    Some((
        metadata.terminal_height(),
        metadata.terminal_hash(),
        class_slot,
    ))
}

fn history_step_class_slot(effective_page_count: usize) -> Option<usize> {
    match crate::consensus::paged_spend::BlockProofClass::for_page_count(effective_page_count)? {
        crate::consensus::paged_spend::BlockProofClass::B25 => Some(0),
        crate::consensus::paged_spend::BlockProofClass::B255 => Some(1),
    }
}

fn read_history_step_terminal(
    txn: &Transaction<'_, RO, NoWriteMap>,
    height: u64,
    block_hash: [u8; 32],
) -> Result<Option<Vec<u8>>, StoreError> {
    let headers = txn.open_table(Some(T_HEADERS))?;
    let header_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(height))?;
    let Some(header) = header_raw.as_deref().and_then(decode_header) else {
        return Ok(None);
    };
    if crate::block_header::block_id(&header) != block_hash {
        return Ok(None);
    }
    let semantic_id = crate::block_header::semantic_header_id(&header);

    let terminals = txn.open_table(Some(T_HISTORY_STEP_TERMINALS))?;
    let Some(ObjectLength(length)) = txn.get(&terminals, &u64_key(height))? else {
        return Ok(None);
    };
    if length == 0 || length > crate::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_BYTES {
        return Err(StoreError::Decode(
            "HistoryStep terminal stored length exceeds hard bounds",
        ));
    }
    let bytes: Vec<u8> = txn
        .get(&terminals, &u64_key(height))?
        .ok_or(StoreError::Decode("HistoryStep terminal disappeared"))?;
    if bytes.len() != length {
        return Err(StoreError::Decode(
            "HistoryStep terminal length changed during read",
        ));
    }
    if recursive_suffix_marker_authority(&bytes, height, semantic_id, None).is_some() {
        return Ok(None);
    }
    if !history_step_terminal_prefix_matches(&bytes, height, semantic_id) {
        return Err(StoreError::Decode(
            "HistoryStep terminal does not match its canonical boundary",
        ));
    }
    Ok(Some(bytes))
}

fn read_history_step_proof_object(
    txn: &Transaction<'_, RO, NoWriteMap>,
    height: u64,
    semantic_id: [u8; 32],
    proof_class: u8,
) -> Result<Option<Vec<u8>>, StoreError> {
    if proof_class >= crate::history_step::HISTORY_STEP_CLASS_COUNT {
        return Ok(None);
    }
    let table = txn.open_table(Some(T_HISTORY_STEP_PROOF_OBJECTS))?;
    let key = history_step_proof_object_key(height, semantic_id, proof_class);
    let Some(ObjectLength(length)) = txn.get(&table, &key)? else {
        return Ok(None);
    };
    if length == 0 || length > crate::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_BYTES {
        return Err(StoreError::Decode(
            "HistoryStep proof-object length exceeds hard bounds",
        ));
    }
    let bytes: Vec<u8> = txn
        .get(&table, &key)?
        .ok_or(StoreError::Decode("HistoryStep proof object disappeared"))?;
    if bytes.len() != length {
        return Err(StoreError::Decode(
            "HistoryStep proof-object length changed during read",
        ));
    }
    let metadata = crate::history_step::HistoryStepTerminalMetadata::decode_prefix(&bytes)
        .map_err(|_| StoreError::Decode("HistoryStep proof-object metadata is malformed"))?;
    if metadata.terminal_height() != height
        || metadata.terminal_hash() != semantic_id
        || metadata.class_id() != proof_class
        || recursive_suffix_marker_authority(
            &bytes,
            height,
            semantic_id,
            Some(proof_class as usize),
        )
        .is_some()
    {
        return Err(StoreError::Decode(
            "HistoryStep proof object does not match its key",
        ));
    }
    Ok(Some(bytes))
}

#[inline]
fn retained_payload_prune_budget_allows(
    retired_bytes: usize,
    deletes: usize,
    height_bytes: usize,
    height_deletes: usize,
) -> bool {
    retired_bytes
        .checked_add(height_bytes)
        .is_some_and(|total| total <= RETAINED_PAYLOAD_PRUNE_BYTE_LIMIT)
        && deletes
            .checked_add(height_deletes)
            .is_some_and(|total| total <= RETAINED_PAYLOAD_PRUNE_DELETE_LIMIT)
}

/// Delete at most one fixed numeric batch of finalized retained payloads.
///
/// Height table keys are little-endian, so cursor order is not numeric. The
/// durable watermark makes direct `u64_key(height)` reads both
/// crash-resumable and independent of table cardinality.  Every candidate
/// height is preflighted in full before the first delete at that height; the
/// transaction therefore never exposes a partially-pruned watermark.
fn prune_retained_payloads_bounded(
    txn: &Transaction<'_, RW, NoWriteMap>,
    current_height: u64,
) -> Result<(), StoreError> {
    if current_height <= RETAINED_BLOCK_SERVING_DEPTH {
        return Ok(());
    }

    let consensus_table = txn.open_table(Some(T_CONSENSUS_META))?;
    let consensus_raw: Option<Cow<'_, [u8]>> = txn.get(&consensus_table, KEY_CONSENSUS_META)?;
    let consensus = consensus_raw
        .as_deref()
        .and_then(decode_consensus_meta)
        .ok_or(StoreError::Decode(
            "consensus metadata is missing during retained payload pruning",
        ))?;
    if consensus.tip_height != current_height || consensus.finalized.height > current_height {
        return Err(StoreError::Decode(
            "consensus heights disagree during retained payload pruning",
        ));
    }
    let headers = txn.open_table(Some(T_HEADERS))?;
    let finalized_raw: Option<Cow<'_, [u8]>> =
        txn.get(&headers, &u64_key(consensus.finalized.height))?;
    let finalized = finalized_raw
        .as_deref()
        .and_then(decode_header)
        .ok_or(StoreError::Decode(
            "finalized header is missing during retained payload pruning",
        ))?;
    if finalized.height != consensus.finalized.height
        || crate::block_header::block_id(&finalized) != consensus.finalized.hash
    {
        return Err(StoreError::Decode(
            "finalized checkpoint is not canonical during retained payload pruning",
        ));
    }

    let cutoff = (current_height - RETAINED_BLOCK_SERVING_DEPTH).min(consensus.finalized.height);
    let watermark = retained_payload_prune_watermark_in_rw_txn(txn)?;
    if watermark.is_some_and(|height| height > current_height) {
        return Err(StoreError::Decode(
            "retained payload prune watermark exceeds canonical tip",
        ));
    }
    let Some(mut height) = watermark.unwrap_or(0).checked_add(1) else {
        return Ok(());
    };
    if height > cutoff {
        return Ok(());
    }

    let recent = txn.open_table(Some(T_RECENT_BLOCKS))?;
    let terminals = txn.open_table(Some(T_HISTORY_STEP_TERMINALS))?;

    let mut processed_heights = 0usize;
    let mut retired_bytes = 0usize;
    let mut deletes = 0usize;
    let mut last_processed = None;
    // Fully retire heights below F. The immediately preceding F may already
    // contain only its terminal: at tip T we deliberately retain bundles
    // F+1..=T but terminals F..=T, where F is the local serving boundary.
    while height < cutoff && processed_heights < RETAINED_PAYLOAD_PRUNE_HEIGHT_LIMIT {
        let key = u64_key(height);
        let header_raw: Option<Cow<'_, [u8]>> = txn.get(&headers, &key)?;
        header_raw
            .as_deref()
            .and_then(decode_header)
            .filter(|header| header.height == height)
            .ok_or(StoreError::Decode(
                "canonical header is missing during retained payload pruning",
            ))?;

        let block_len: Option<ObjectLength> = txn.get(&recent, &key)?;
        let ObjectLength(terminal_len) = txn.get(&terminals, &key)?.ok_or(StoreError::Decode(
            "retained HistoryStep terminal is missing",
        ))?;
        if terminal_len == 0
            || terminal_len > crate::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_BYTES
        {
            return Err(StoreError::Decode(
                "retained HistoryStep terminal length is invalid",
            ));
        }
        let (height_bytes, height_deletes) = match block_len {
            Some(ObjectLength(block_len)) => {
                crate::AcceptedBlockBundle::validate_declared_lengths(
                    block_len as u64,
                    terminal_len as u64,
                )
                .map_err(|_| StoreError::Decode("retained accepted bundle length is invalid"))?;
                (
                    block_len
                        .checked_add(terminal_len)
                        .ok_or(StoreError::Decode(
                            "retained payload prune byte accounting overflow",
                        ))?,
                    2,
                )
            }
            None => (terminal_len, 1),
        };
        if height_bytes > RETAINED_PAYLOAD_PRUNE_BYTE_LIMIT {
            return Err(StoreError::Decode(
                "one retained payload height exceeds maintenance budget",
            ));
        }
        if !retained_payload_prune_budget_allows(
            retired_bytes,
            deletes,
            height_bytes,
            height_deletes,
        ) {
            break;
        }

        if block_len.is_some() {
            txn.del(&recent, &key, None)?;
        }
        txn.del(&terminals, &key, None)?;

        retired_bytes += height_bytes;
        deletes += height_deletes;
        processed_heights += 1;
        last_processed = Some(height);
        let Some(next) = height.checked_add(1) else {
            break;
        };
        height = next;
    }

    if let Some(last_processed) = last_processed {
        set_retained_payload_prune_watermark(txn, last_processed)?;
    }

    // Only once every older height is retired, turn F itself into the compact
    // snapshot/sync boundary by removing its body and retaining its terminal.
    if height == cutoff {
        let key = u64_key(cutoff);
        let header_raw: Option<Cow<'_, [u8]>> = txn.get(&headers, &key)?;
        header_raw
            .as_deref()
            .and_then(decode_header)
            .filter(|header| header.height == cutoff)
            .ok_or(StoreError::Decode(
                "canonical boundary header is missing during retained payload pruning",
            ))?;
        let ObjectLength(terminal_len) = txn.get(&terminals, &key)?.ok_or(StoreError::Decode(
            "retained boundary HistoryStep terminal is missing",
        ))?;
        if terminal_len == 0
            || terminal_len > crate::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_BYTES
        {
            return Err(StoreError::Decode(
                "retained boundary HistoryStep terminal length is invalid",
            ));
        }
        if let Some(ObjectLength(block_len)) = txn.get(&recent, &key)? {
            crate::AcceptedBlockBundle::validate_declared_lengths(
                block_len as u64,
                terminal_len as u64,
            )
            .map_err(|_| StoreError::Decode("retained boundary bundle length is invalid"))?;
            if retained_payload_prune_budget_allows(retired_bytes, deletes, block_len, 1) {
                txn.del(&recent, &key, None)?;
            }
        }
    }
    Ok(())
}

/// Delete height keys without collecting the table or assuming that
/// lexicographic cursor order is numeric.
fn delete_height_keys_at_or_below(
    txn: &Transaction<'_, RW, NoWriteMap>,
    table: &Table<'_>,
    cutoff: u64,
) -> Result<(), StoreError> {
    const DELETE_KEY_CHUNK: usize = 64;
    const DELETE_SCAN_CHUNK: usize = 4096;
    let mut resume_after: Option<Vec<u8>> = None;
    loop {
        let (deletions, last_scanned, reached_end) = {
            let mut cursor = txn.cursor(table)?;
            let mut item: Option<(Vec<u8>, ())> = if let Some(resume) = resume_after.as_deref() {
                let found: Option<(Vec<u8>, ())> = cursor.set_range(resume)?;
                match found {
                    Some((key, _)) if key.as_slice() == resume => cursor.next()?,
                    other => other,
                }
            } else {
                cursor.first()?
            };
            let mut deletions = Vec::with_capacity(DELETE_KEY_CHUNK);
            let mut last_scanned = None;
            let mut scanned = 0usize;
            let reached_end = loop {
                let Some((key, _)) = item.take() else {
                    break true;
                };
                let height = u64_from_key(&key).ok_or(StoreError::Decode(
                    "invalid durable height key during pruning",
                ))?;
                if height <= cutoff {
                    deletions.push(height);
                }
                last_scanned = Some(key);
                scanned += 1;
                if deletions.len() == DELETE_KEY_CHUNK || scanned == DELETE_SCAN_CHUNK {
                    break false;
                }
                item = cursor.next()?;
            };
            (deletions, last_scanned, reached_end)
        };
        for height in deletions {
            txn.del(table, u64_key(height), None)?;
        }
        if reached_end {
            return Ok(());
        }
        resume_after = last_scanned;
    }
}

#[inline]
fn canonical_hash_from_encoded_header(bytes: &[u8]) -> Option<[u8; 32]> {
    decode_header(bytes).map(|header| crate::block_header::block_id(&header))
}

/// Extract the 32-byte owner key from a slot's owner fields.
#[inline]
fn owner_key_from_fields(owner_hi: noid_core::Block128, owner_lo: noid_core::Block128) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&owner_hi.0.to_le_bytes());
    key[16..].copy_from_slice(&owner_lo.0.to_le_bytes());
    key
}

#[inline]
fn owner_index_key(owner: &[u8; 32], slot_index: u32) -> [u8; OWNER_INDEX_KEY_BYTES] {
    let mut key = [0u8; OWNER_INDEX_KEY_BYTES];
    key[..32].copy_from_slice(owner);
    // Big endian is consensus-adjacent storage canonicalization: MDBX prefix
    // iteration is then also strictly increasing by physical slot.
    key[32..].copy_from_slice(&slot_index.to_be_bytes());
    key
}

/// Decode the canonical owner-index key format.
#[inline]
fn decode_owner_index_key(bytes: &[u8]) -> Result<([u8; 32], u32), StoreError> {
    if bytes.len() != OWNER_INDEX_KEY_BYTES {
        return Err(StoreError::Decode("invalid owner-index key length"));
    }
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&bytes[..32]);
    let slot_index = u32::from_be_bytes(bytes[32..].try_into().unwrap());
    Ok((owner, slot_index))
}

#[inline]
fn encode_owner_index_value(packed_value: u128) -> [u8; OWNER_INDEX_VALUE_BYTES] {
    packed_value.to_le_bytes()
}

#[inline]
fn decode_owner_index_value(bytes: &[u8]) -> Result<u128, StoreError> {
    if bytes.len() != OWNER_INDEX_VALUE_BYTES {
        return Err(StoreError::Decode("invalid owner-index value length"));
    }
    Ok(u128::from_le_bytes(bytes.try_into().unwrap()))
}

fn sort_unique_segment_ids(mut segment_ids: Vec<u16>) -> Result<Vec<u16>, StoreError> {
    segment_ids.sort_unstable();
    if segment_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(StoreError::Decode("duplicate stored segment key"));
    }
    Ok(segment_ids)
}

#[inline]
fn segment_columns_empty(cols: &SegmentColumns) -> bool {
    cols.values.iter().all(|v| v.0 == 0)
        && cols.owners_hi.iter().all(|v| v.0 == 0)
        && cols.owners_lo.iter().all(|v| v.0 == 0)
}

/// Stream every live owner-index record in one segment without building an
/// owner map or a segment-sized side vector.
fn visit_live_owner_records(
    segment_id: u16,
    effective_log: u8,
    columns: &SegmentColumns,
    mut visitor: impl FnMut([u8; 32], u32, u128) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    if columns.values.len() != columns.owners_hi.len()
        || columns.values.len() != columns.owners_lo.len()
    {
        return Err(StoreError::Decode("owner-index segment columns disagree"));
    }
    let segment_capacity = 1usize
        .checked_shl(u32::from(effective_log))
        .ok_or(StoreError::Decode("owner-index segment log is invalid"))?;
    if columns.values.len() > segment_capacity {
        return Err(StoreError::Decode(
            "owner-index segment exceeds effective domain",
        ));
    }
    let segment_base = u64::from(segment_id)
        .checked_shl(u32::from(effective_log))
        .ok_or(StoreError::Decode("owner-index segment base overflow"))?;
    for local in 0..columns.values.len() {
        let value = columns.values[local];
        let owner_hi = columns.owners_hi[local];
        let owner_lo = columns.owners_lo[local];
        if value.0 == 0 && owner_hi.0 == 0 && owner_lo.0 == 0 {
            continue;
        }
        let slot_index = segment_base
            .checked_add(local as u64)
            .and_then(|slot| u32::try_from(slot).ok())
            .ok_or(StoreError::Decode("owner-index slot exceeds u32 domain"))?;
        visitor(
            owner_key_from_fields(owner_hi, owner_lo),
            slot_index,
            value.0,
        )?;
    }
    Ok(())
}

impl MdbxStore {
    /// Open or create the MDBX database at `path`.
    /// Creates all tables on first run; subsequent opens reuse them.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        use libmdbx::{ReadWriteOptions, SyncMode};
        // Set explicit MDBX geometry via ReadWriteOptions.
        //
        // Default libmdbx pre-allocates ~256 MB on first open regardless of actual data
        // size. For a node with 160 active UTXOs this wastes disk and inflates VmSize.
        //
        // Sizing rationale:
        //   min_size  = 4 MB — enough for genesis + a few hundred blocks
        //   max_size  = 1 TiB — at the theoretical 2^32 live-slot ceiling the
        //                        sparse segment payloads are ~200 GiB and the
        //                        mandatory owner index is another ~208 GiB before
        //                        permanent indexes and B+tree overhead. This is
        //                        an address-space ceiling, not eager allocation.
        //   growth_step = 64 MB — incremental growth to avoid resize churn
        let rw = ReadWriteOptions {
            sync_mode: SyncMode::Durable,
            min_size: Some(4 * 1024 * 1024),                // 4 MiB
            max_size: Some(1024isize * 1024 * 1024 * 1024), // 1 TiB virtual ceiling
            growth_step: Some(64 * 1024 * 1024),            // 64 MiB steps
            ..Default::default()
        };
        let db = Database::<NoWriteMap>::open_with_options(
            path,
            DatabaseOptions {
                max_tables: Some(N_TABLES),
                mode: Mode::ReadWrite(rw),
                // Reuse the most recently retired contiguous terminal pages
                // before walking older fragmented GC records. This changes
                // only local page allocation; the MDBX format and all chain
                // data remain identical and readable without this flag.
                liforeclaim: true,
                rp_augment_limit: Some(MDBX_RECLAIM_PAGE_SEARCH_LIMIT),
                ..Default::default()
            },
        )?;
        // Ensure all named tables exist — idempotent on re-open.
        let txn = db.begin_rw_txn()?;
        for name in [
            T_HEADERS,
            T_HEADER_ANCHORS,
            T_HASH_TO_HEIGHT,
            T_CHAIN_TIP,
            T_CONSENSUS_META,
            T_CHAIN_WORK,
            T_UNDO_LOGS,
            T_SEGMENTS,
            T_SEGMENT_SUMMARIES,
            T_STATE_META,
            T_RECENT_BLOCKS,
            T_BLOCK_BODY_OBJECTS,
            T_TX_INDEX,
            T_HISTORY_STEP_TERMINALS,
            T_HISTORY_STEP_PROOF_OBJECTS,
            T_OWNER_INDEX,
            T_RETENTION_META,
        ] {
            txn.create_table(Some(name), TableFlags::empty())?;
        }
        txn.commit()?;
        let store = Self {
            db: Arc::new(db),
            block_body_object_retention_floor: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        Ok(store)
    }

    // -----------------------------------------------------------------------
    // Reads
    // -----------------------------------------------------------------------

    pub(super) fn historical_read_snapshot(
        &self,
    ) -> Result<MdbxHistoricalReadSnapshot<'_>, StoreError> {
        Ok(MdbxHistoricalReadSnapshot {
            txn: self.db.begin_ro_txn()?,
        })
    }

    /// Pin content-addressed bodies above one active snapshot boundary. This
    /// is an operational serving lease, not consensus state. `None` restores
    /// the ordinary bounded retention window.
    pub fn set_block_body_object_retention_floor(&self, floor: Option<u64>) {
        self.block_body_object_retention_floor
            .store(floor.unwrap_or(0), std::sync::atomic::Ordering::Release);
    }

    pub fn get_chain_tip(&self) -> Result<Option<(u64, [u8; 32])>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, KEY_TIP)?;
        Ok(raw.and_then(|b| decode_chain_tip(&b)))
    }

    pub fn get_consensus_meta(&self) -> Result<Option<ConsensusMeta>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_CONSENSUS_META))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, KEY_CONSENSUS_META)?;
        Ok(raw.and_then(|b| decode_consensus_meta(&b)))
    }

    pub fn get_chain_work(&self, height: u64) -> Result<Option<[u8; 32]>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_CHAIN_WORK))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
        Ok(raw.and_then(|b| decode_chain_work(&b)))
    }

    /// Persist the authority for a previously verified recursive snapshot
    /// suffix before its first body is committed. If the process stops between
    /// bodies, the fixed-size per-height marker and this record explain the
    /// durable partial tip without retaining every intermediate proof.
    pub(crate) fn begin_verified_recursive_suffix(
        &self,
        boundary_height: u64,
        boundary_hash: [u8; 32],
        tip_header: &BlockHeader,
        terminal_bytes: &[u8],
    ) -> Result<(), StoreError> {
        if boundary_height >= tip_header.height {
            return Err(StoreError::Decode(
                "verified recursive suffix does not advance the boundary",
            ));
        }
        let tip_hash = crate::block_header::block_id(tip_header);
        let terminal =
            crate::history_step::HistoryStepTerminalMetadata::decode_prefix(terminal_bytes)
                .map_err(|_| {
                    StoreError::Decode("verified recursive suffix terminal is malformed")
                })?;
        if terminal.terminal_height() != tip_header.height
            || terminal.terminal_hash() != crate::block_header::semantic_header_id(tip_header)
        {
            return Err(StoreError::Decode(
                "verified recursive suffix terminal does not bind its tip",
            ));
        }

        let txn = self.db.begin_rw_txn()?;
        let tip_table = txn.open_table(Some(T_CHAIN_TIP))?;
        let durable_tip: Option<Vec<u8>> = txn.get(&tip_table, KEY_TIP)?;
        if durable_tip.as_deref().and_then(decode_chain_tip)
            != Some((boundary_height, boundary_hash))
        {
            return Err(StoreError::Decode(
                "canonical boundary changed before recursive suffix authorization",
            ));
        }
        let header_table = txn.open_table(Some(T_HEADERS))?;
        let boundary_raw: Option<Vec<u8>> = txn.get(&header_table, &u64_key(boundary_height))?;
        let boundary_header = boundary_raw
            .as_deref()
            .and_then(decode_header)
            .filter(|header| crate::block_header::block_id(header) == boundary_hash)
            .ok_or(StoreError::Decode(
                "recursive suffix boundary header is not canonical",
            ))?;
        if boundary_header.height != boundary_height {
            return Err(StoreError::Decode(
                "recursive suffix boundary header is not canonical",
            ));
        }
        let authority = VerifiedSuffixAuthorityRecord {
            boundary_height,
            boundary_hash,
            tip_height: tip_header.height,
            tip_hash,
        };
        let retention = txn.open_table(Some(T_RETENTION_META))?;
        let existing_raw: Option<Vec<u8>> = txn.get(&retention, KEY_VERIFIED_SUFFIX_AUTHORITY)?;
        let existing = existing_raw
            .as_deref()
            .and_then(decode_verified_suffix_authority);
        let preserve_existing = if boundary_height == 0 {
            false
        } else {
            let terminals = txn.open_table(Some(T_HISTORY_STEP_TERMINALS))?;
            let boundary_terminal: Option<Vec<u8>> =
                txn.get(&terminals, &u64_key(boundary_height))?;
            match boundary_terminal.as_deref().and_then(|terminal| {
                recursive_suffix_marker_authority(
                    terminal,
                    boundary_height,
                    crate::block_header::semantic_header_id(&boundary_header),
                    None,
                )
            }) {
                None => false,
                Some(marker_authority) if marker_authority == (tip_header.height, tip_hash) => {
                    let existing_matches = existing.is_some_and(|existing| {
                        existing.tip_height == tip_header.height
                            && existing.tip_hash == tip_hash
                            && boundary_height > existing.boundary_height
                            && boundary_height < existing.tip_height
                    });
                    if !existing_matches {
                        return Err(StoreError::Decode(
                            "recursive suffix retry marker authority is missing",
                        ));
                    }
                    true
                }
                Some(_) => {
                    return Err(StoreError::Decode(
                        "recursive suffix retry target differs from marker authority",
                    ));
                }
            }
        };
        if !preserve_existing {
            txn.put(
                &retention,
                KEY_VERIFIED_SUFFIX_AUTHORITY,
                encode_verified_suffix_authority(authority),
                WriteFlags::empty(),
            )?;
        }
        txn.commit()?;
        Ok(())
    }

    pub(crate) fn durable_tip_has_verified_suffix_authority(
        &self,
        tip_header: &BlockHeader,
        tip_hash: [u8; 32],
    ) -> Result<bool, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let retention = txn.open_table(Some(T_RETENTION_META))?;
        let authority_raw: Option<Vec<u8>> = txn.get(&retention, KEY_VERIFIED_SUFFIX_AUTHORITY)?;
        let Some(authority) = authority_raw
            .as_deref()
            .and_then(decode_verified_suffix_authority)
        else {
            return Ok(false);
        };
        if tip_header.height <= authority.boundary_height
            || tip_header.height >= authority.tip_height
            || tip_hash != crate::block_header::block_id(tip_header)
        {
            return Ok(false);
        }
        let terminal_table = txn.open_table(Some(T_HISTORY_STEP_TERMINALS))?;
        let marker: Option<Vec<u8>> = txn.get(&terminal_table, &u64_key(tip_header.height))?;
        Ok(marker.as_deref().is_some_and(|marker| {
            recursive_suffix_marker_authority(
                marker,
                tip_header.height,
                crate::block_header::semantic_header_id(tip_header),
                None,
            ) == Some((authority.tip_height, authority.tip_hash))
        }))
    }

    /// Load one HistoryStep terminal at an exact canonical boundary.
    pub fn get_history_step_terminal_at(
        &self,
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        read_history_step_terminal(&txn, height, block_hash)
    }

    /// Load a complete recent recursive terminal by semantic identity,
    /// independently of which branch is currently canonical.
    pub fn get_history_step_proof_object(
        &self,
        height: u64,
        semantic_id: [u8; 32],
        proof_class: u8,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        read_history_step_proof_object(&txn, height, semantic_id, proof_class)
    }

    /// Load the canonical class for a recent semantic terminal when the
    /// caller has a header but not the body-derived class selector.
    pub fn get_any_history_step_proof_object(
        &self,
        height: u64,
        semantic_id: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        for proof_class in 0..crate::history_step::HISTORY_STEP_CLASS_COUNT {
            if let Some(bytes) =
                read_history_step_proof_object(&txn, height, semantic_id, proof_class)?
            {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    pub fn has_any_history_step_proof_object(
        &self,
        height: u64,
        semantic_id: [u8; 32],
    ) -> Result<bool, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let table = txn.open_table(Some(T_HISTORY_STEP_PROOF_OBJECTS))?;
        for proof_class in 0..crate::history_step::HISTORY_STEP_CLASS_COUNT {
            let key = history_step_proof_object_key(height, semantic_id, proof_class);
            if let Some(ObjectLength(length)) = txn.get(&table, &key)? {
                if length == 0
                    || length > crate::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_BYTES
                {
                    return Err(StoreError::Decode(
                        "HistoryStep proof-object length exceeds hard bounds",
                    ));
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Check whether the exact canonical boundary has a retained HistoryStep
    /// terminal without loading the terminal payload.
    pub fn has_history_step_terminal_at(
        &self,
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<bool, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let key = u64_key(height);
        let headers = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<Vec<u8>> = txn.get(&headers, &key)?;
        if header_raw
            .as_deref()
            .and_then(canonical_hash_from_encoded_header)
            != Some(block_hash)
        {
            return Ok(false);
        }

        let terminals = txn.open_table(Some(T_HISTORY_STEP_TERMINALS))?;
        let Some(ObjectLength(length)) = txn.get(&terminals, &key)? else {
            return Ok(false);
        };
        if length == 0 || length > crate::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_BYTES {
            return Err(StoreError::Decode(
                "HistoryStep terminal length exceeds hard bounds",
            ));
        }
        let terminal: Vec<u8> = txn
            .get(&terminals, &key)?
            .ok_or(StoreError::Decode("HistoryStep terminal disappeared"))?;
        let header = header_raw
            .as_deref()
            .and_then(decode_header)
            .ok_or(StoreError::Decode("canonical terminal header disappeared"))?;
        Ok(recursive_suffix_marker_authority(
            &terminal,
            height,
            crate::block_header::semantic_header_id(&header),
            None,
        )
        .is_none())
    }

    /// Cache a complete terminal that has already been verified for an exact
    /// snapshot boundary. The capability type is constructed only by
    /// `MdbxChainContext::verify_snapshot_boundary`; this method additionally
    /// binds it to the canonical finalized chain in the same write
    /// transaction before the bytes enter the independent proof-object store.
    pub(crate) fn cache_verified_snapshot_boundary_proof(
        &self,
        boundary: &crate::storage::VerifiedSnapshotBoundary,
    ) -> Result<(), StoreError> {
        let header = *boundary.header();
        let height = header.height;
        let block_hash = crate::block_header::block_id(&header);

        let txn = self.db.begin_rw_txn()?;
        let headers = txn.open_table(Some(T_HEADERS))?;
        let canonical_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(height))?;
        if canonical_raw.as_deref().and_then(decode_header) != Some(header) {
            return Err(StoreError::Decode(
                "verified snapshot proof boundary is not canonical",
            ));
        }

        let consensus = txn.open_table(Some(T_CONSENSUS_META))?;
        let meta_raw: Option<Vec<u8>> = txn.get(&consensus, KEY_CONSENSUS_META)?;
        let meta =
            meta_raw
                .as_deref()
                .and_then(decode_consensus_meta)
                .ok_or(StoreError::Decode(
                    "canonical consensus metadata is missing",
                ))?;
        if meta.finalized.height < height
            || (meta.finalized.height == height && meta.finalized.hash != block_hash)
        {
            return Err(StoreError::Decode(
                "verified snapshot proof boundary is not finalized",
            ));
        }

        archive_history_step_proof_object(&txn, boundary.history_step_terminal_bytes())?;
        prune_history_step_proof_objects(&txn, meta.tip_height)?;
        txn.commit()?;
        Ok(())
    }

    pub fn put_consensus_meta(&self, meta: &ConsensusMeta) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_CONSENSUS_META))?;
        txn.put(
            &tbl,
            KEY_CONSENSUS_META,
            encode_consensus_meta(meta),
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn get_state_meta(&self) -> Result<Option<(u32, u64, u64)>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_STATE_META))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, KEY_META)?;
        Ok(raw.and_then(|b| decode_state_meta(&b)))
    }

    pub fn get_circulating_supply(&self) -> Result<Option<u128>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_STATE_META))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, KEY_META)?;
        Ok(raw.and_then(|bytes| decode_circulating_supply(&bytes)))
    }

    pub fn get_header(&self, height: u64) -> Result<Option<BlockHeader>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_HEADERS))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
        Ok(raw.and_then(|b| decode_header(&b)))
    }

    /// Load one bounded consecutive canonical-header range from a single
    /// MDBX read snapshot.
    ///
    /// The shared store handle is MVCC-backed, so P2P serving can use this
    /// path while block acceptance owns the hot chain-context writer. A
    /// missing height ends the range; malformed durable rows fail the whole
    /// read rather than silently producing a non-contiguous response.
    pub fn get_headers(
        &self,
        start_height: u64,
        count: u16,
    ) -> Result<Vec<BlockHeader>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_HEADERS))?;
        let mut headers = Vec::with_capacity(count as usize);
        for offset in 0..u64::from(count) {
            let Some(height) = start_height.checked_add(offset) else {
                break;
            };
            let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
            let Some(raw) = raw else {
                break;
            };
            let header =
                decode_header(&raw).ok_or(StoreError::Decode("canonical header is malformed"))?;
            if header.height != height {
                return Err(StoreError::Decode(
                    "canonical header row has the wrong height",
                ));
            }
            headers.push(header);
        }
        Ok(headers)
    }

    pub fn get_header_anchor(&self, height: u64) -> Result<Option<HeaderChainAnchor>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_HEADER_ANCHORS))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
        raw.map(|b| decode_header_chain_anchor(&b).ok_or(StoreError::Decode("header chain anchor")))
            .transpose()
    }

    /// Look up a header by its `H_BLOCK` hash (O(1) via the h2h index).
    pub fn get_header_by_hash(&self, hash: &[u8; 32]) -> Result<Option<BlockHeader>, StoreError> {
        // Scope the first transaction so it is dropped before we open a second.
        let height = {
            let txn = self.db.begin_ro_txn()?;
            let h_tbl = txn.open_table(Some(T_HASH_TO_HEIGHT))?;
            let height_raw: Option<Vec<u8>> = txn.get(&h_tbl, hash.as_slice())?;
            match height_raw.and_then(|b| u64_from_key(&b)) {
                Some(h) => h,
                None => return Ok(None),
            }
            // h_tbl and txn are dropped here
        };
        match self.get_header(height)? {
            Some(header) if crate::consensus::pow::block_id(&header) == *hash => Ok(Some(header)),
            _ => Ok(None),
        }
    }

    pub fn get_undo_log(&self, height: u64) -> Result<Option<BlockUndoLog>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_UNDO_LOGS))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
        Ok(raw.and_then(|b| decode_undo_log(&b)))
    }

    pub fn get_segment(&self, seg_id: u16) -> Result<Option<(u8, SegmentColumns)>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_SEGMENTS))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &seg_id.to_le_bytes())?;
        Ok(raw.and_then(|b| decode_segment(&b)))
    }

    /// Sum the exact canonical bytes stored in the current-state segment
    /// table without materializing any payload value.
    ///
    /// The operation is O(non-empty segments), not O(slot capacity) or
    /// O(live UTXOs): MDBX exposes each value's length directly.
    pub fn encoded_state_bytes(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let meta_table = txn.open_table(Some(T_STATE_META))?;
        let meta_raw: Option<Vec<u8>> = txn.get(&meta_table, KEY_META)?;
        let (log_slots, _, _) = meta_raw
            .as_deref()
            .and_then(decode_state_meta)
            .ok_or(StoreError::Decode("state metadata is missing"))?;
        let effective_log = log_slots.min(crate::fri_state::LOG_SEGMENT_SIZE as u32) as u8;

        let segment_table = txn.open_table(Some(T_SEGMENTS))?;
        let mut cursor = txn.cursor(&segment_table)?;
        let mut total = 0u64;
        let mut item: Option<(Vec<u8>, ObjectLength)> = cursor.first()?;
        while let Some((key, ObjectLength(length))) = item {
            if key.len() != 2 {
                return Err(StoreError::Decode("invalid stored segment key"));
            }
            if encoded_segment_live_count_from_len(effective_log, length)
                .is_none_or(|live_count| live_count == 0)
            {
                return Err(StoreError::Decode(
                    "stored segment has noncanonical sparse length",
                ));
            }
            total = total
                .checked_add(
                    u64::try_from(length)
                        .map_err(|_| StoreError::Decode("stored segment length exceeds u64"))?,
                )
                .ok_or(StoreError::Decode("encoded state byte count overflows"))?;
            item = cursor.next()?;
        }
        Ok(total)
    }

    /// Read one segment from the same MDBX snapshot that still names the
    /// caller's expected canonical tip.  Mempool views use this to avoid
    /// mixing slot data from a newly committed block with old anchor metadata.
    pub fn get_segment_at_tip(
        &self,
        expected_height: u64,
        expected_hash: [u8; 32],
        seg_id: u16,
    ) -> Result<Option<(u8, SegmentColumns)>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tip_tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        let tip_raw: Option<Vec<u8>> = txn.get(&tip_tbl, KEY_TIP)?;
        if tip_raw.as_deref().and_then(decode_chain_tip) != Some((expected_height, expected_hash)) {
            return Ok(None);
        }
        let segment_tbl = txn.open_table(Some(T_SEGMENTS))?;
        let raw: Option<Vec<u8>> = txn.get(&segment_tbl, &seg_id.to_le_bytes())?;
        raw.map(|bytes| decode_segment(&bytes).ok_or(StoreError::Decode("invalid stored segment")))
            .transpose()
    }

    pub fn get_recent_block(&self, height: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_RECENT_BLOCKS))?;
        Ok(txn.get(&tbl, &u64_key(height))?)
    }

    /// Read one bounded content-addressed block body independently of the
    /// canonical height row. The caller still validates its expected byte
    /// digest; this lookup only fixes the exact height/header identity.
    pub fn get_block_body_object(
        &self,
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let table = txn.open_table(Some(T_BLOCK_BODY_OBJECTS))?;
        let bytes: Option<Vec<u8>> = txn.get(&table, &block_body_object_key(height, block_hash))?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let block = crate::Block::from_bytes(&bytes)
            .map_err(|_| StoreError::Decode("cached block-body object is malformed"))?;
        if block.header.height != height
            || crate::block_header::block_id(&block.header) != block_hash
        {
            return Err(StoreError::Decode(
                "cached block-body object does not match its key",
            ));
        }
        Ok(Some(bytes))
    }

    /// Encode one canonical NAB1 block + HistoryStep terminal from a single
    /// accepted-state snapshot.
    pub fn get_recent_accepted_block_bundle_bounded(
        &self,
        height: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let key = u64_key(height);
        let blocks = txn.open_table(Some(T_RECENT_BLOCKS))?;
        let terminals = txn.open_table(Some(T_HISTORY_STEP_TERMINALS))?;
        let block_len: Option<ObjectLength> = txn.get(&blocks, &key)?;
        let terminal_len: Option<ObjectLength> = txn.get(&terminals, &key)?;

        let Some(ObjectLength(block_len)) = block_len else {
            // The exact snapshot boundary F intentionally keeps terminal_F
            // without body_F. It is read through get_history_step_terminal_at;
            // the accepted-bundle suffix begins at F+1.
            return Ok(None);
        };
        let ObjectLength(terminal_len) = terminal_len.ok_or(StoreError::Decode(
            "accepted block is missing its HistoryStep terminal",
        ))?;
        crate::AcceptedBlockBundle::validate_declared_lengths(
            block_len as u64,
            terminal_len as u64,
        )
        .map_err(|_| StoreError::Decode("accepted block bundle length is invalid"))?;

        let block_bytes: Vec<u8> = txn
            .get(&blocks, &key)?
            .ok_or(StoreError::Decode("accepted block disappeared during read"))?;
        let terminal_bytes: Vec<u8> = txn.get(&terminals, &key)?.ok_or(StoreError::Decode(
            "accepted HistoryStep terminal disappeared during read",
        ))?;
        if block_bytes.len() != block_len || terminal_bytes.len() != terminal_len {
            return Err(StoreError::Decode(
                "accepted block bundle length changed during read",
            ));
        }
        let block = crate::Block::from_bytes(&block_bytes)
            .map_err(|_| StoreError::Decode("accepted block body is malformed"))?;
        if recursive_suffix_marker_authority(
            &terminal_bytes,
            height,
            crate::block_header::semantic_header_id(&block.header),
            None,
        )
        .is_some()
        {
            return Ok(None);
        }
        let bundle = crate::AcceptedBlockBundle::try_from_parts(block_bytes, terminal_bytes)
            .map_err(|_| StoreError::Decode("accepted block bundle is malformed"))?;
        if bundle.height() != height {
            return Err(StoreError::Decode(
                "accepted block bundle height differs from its key",
            ));
        }
        let headers = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<Vec<u8>> = txn.get(&headers, &key)?;
        if header_raw
            .as_deref()
            .and_then(canonical_hash_from_encoded_header)
            != Some(bundle.block_hash())
        {
            return Err(StoreError::Decode("accepted block bundle is not canonical"));
        }
        Ok(Some(bundle.encode()))
    }

    /// Look up one owner's live UTXOs and verify every secondary-index entry
    /// against the exact durable state in the same MDBX read transaction.
    ///
    /// The owner index is only an accelerator. A malformed, stale, duplicate,
    /// out-of-domain, or value-mismatched entry fails closed rather than being
    /// returned to the wallet. Absence of an owner key canonically means that
    /// the owner currently has no live UTXOs.
    pub fn get_verified_utxos_by_owner(
        &self,
        owner: &[u8; 32],
    ) -> Result<VerifiedOwnerSnapshot, StoreError> {
        self.get_verified_utxos_by_owner_bounded(owner, None)
    }

    /// Check whether an owner has at least one live UTXO without loading its
    /// complete balance. Imported-wallet discovery uses this bounded query
    /// while full active-address activation continues to use the complete
    /// snapshot above.
    pub fn has_verified_utxo_by_owner(&self, owner: &[u8; 32]) -> Result<bool, StoreError> {
        self.get_verified_utxos_by_owner_bounded(owner, Some(1))
            .map(|snapshot| !snapshot.utxos.is_empty())
    }

    fn get_verified_utxos_by_owner_bounded(
        &self,
        owner: &[u8; 32],
        max_utxos: Option<usize>,
    ) -> Result<VerifiedOwnerSnapshot, StoreError> {
        let txn = self.db.begin_ro_txn()?;

        // Bind the returned owner view to the exact chain/state identity from
        // this same MDBX snapshot. Callers never supply log_slots from a
        // separately locked in-memory view.
        let tip_tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        let tip_raw: Vec<u8> = txn.get(&tip_tbl, KEY_TIP)?.ok_or(StoreError::Decode(
            "missing chain tip for owner-index query",
        ))?;
        let (height, tip_hash) = decode_chain_tip(&tip_raw).ok_or(StoreError::Decode(
            "invalid chain tip for owner-index query",
        ))?;
        let header_tbl = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Vec<u8> =
            txn.get(&header_tbl, &u64_key(height))?
                .ok_or(StoreError::Decode(
                    "missing tip header for owner-index query",
                ))?;
        let header = decode_header(&header_raw).ok_or(StoreError::Decode(
            "invalid tip header for owner-index query",
        ))?;
        if header.height != height || crate::consensus::pow::block_id(&header) != tip_hash {
            return Err(StoreError::Decode(
                "tip identity mismatch during owner-index query",
            ));
        }
        let state_meta_tbl = txn.open_table(Some(T_STATE_META))?;
        let state_meta_raw: Vec<u8> =
            txn.get(&state_meta_tbl, KEY_META)?
                .ok_or(StoreError::Decode(
                    "missing state metadata for owner-index query",
                ))?;
        let (log_slots, active_slot_count, alloc_counter) = decode_state_meta(&state_meta_raw)
            .ok_or(StoreError::Decode(
                "invalid state metadata for owner-index query",
            ))?;
        if header.log_slots != log_slots
            || header.active_slot_count != active_slot_count
            || header.alloc_counter != alloc_counter
        {
            return Err(StoreError::Decode(
                "tip header and state metadata disagree during owner-index query",
            ));
        }
        if !(1..=32).contains(&log_slots) {
            return Err(StoreError::Decode(
                "owner-index query log_slots is outside the u32 slot domain",
            ));
        }
        let effective_log = log_slots.min(crate::consensus::params::LOG_SEGMENT_SIZE);
        let slot_domain = 1u64 << log_slots;

        let owner_tbl = txn.open_table(Some(T_OWNER_INDEX))?;
        let segment_tbl = txn.open_table(Some(T_SEGMENTS))?;
        // Composite keys are strictly slot-sorted within this owner prefix,
        // hence segment-sorted. Verify records as the cursor yields them and
        // merge against one segment's live sparse entries at a time.
        let mut owner_cursor = txn.cursor(&owner_tbl)?;
        let mut item: Option<(Vec<u8>, Vec<u8>)> = owner_cursor.set_range(owner.as_slice())?;
        let mut current_segment: Option<(u16, Vec<(u16, SlotValue)>, usize)> = None;
        let mut previous_slot = None;
        let mut verified = Vec::new();
        while let Some((key, raw_value)) = item {
            // Reaching another owner's prefix is the canonical end of this
            // owner's range. A key that begins with the requested owner but
            // has any non-canonical length is corruption, including the old
            // aggregate owner-only encoding.
            if key.get(..32) != Some(owner.as_slice()) {
                break;
            }
            let (indexed_owner, slot_index) = decode_owner_index_key(&key)?;
            if indexed_owner != *owner {
                return Err(StoreError::Decode("owner-index prefix mismatch"));
            }
            if previous_slot.is_some_and(|previous| previous >= slot_index) {
                return Err(StoreError::Decode(
                    "owner-index slots are not strictly sorted and unique",
                ));
            }
            previous_slot = Some(slot_index);
            if verified.len() as u64 >= slot_domain {
                return Err(StoreError::Decode(
                    "owner-index entry count exceeds slot domain",
                ));
            }
            if slot_index as u64 >= slot_domain {
                return Err(StoreError::Decode(
                    "owner-index slot is outside current state domain",
                ));
            }
            let packed_value = decode_owner_index_value(&raw_value)?;
            let segment_id = (slot_index >> effective_log) as u16;
            if current_segment
                .as_ref()
                .is_none_or(|(loaded_id, _, _)| *loaded_id != segment_id)
            {
                let segment_raw: Option<Vec<u8>> =
                    txn.get(&segment_tbl, &segment_id.to_le_bytes())?;
                let segment_raw = segment_raw.ok_or(StoreError::Decode(
                    "owner-index slot references a missing durable segment",
                ))?;
                let sparse = decode_sparse_segment(&segment_raw).ok_or(StoreError::Decode(
                    "invalid durable segment referenced by owner index",
                ))?;
                if u32::from(sparse.effective_log_segment()) != effective_log {
                    return Err(StoreError::Decode(
                        "owner-index segment effective log mismatch",
                    ));
                }
                current_segment = Some((segment_id, sparse.entries().collect(), 0));
            }

            let local_mask = (1u32 << effective_log) - 1;
            let local = (slot_index & local_mask) as u16;
            let (_, entries, cursor) = current_segment
                .as_mut()
                .expect("segment was inserted above");
            while entries
                .get(*cursor)
                .is_some_and(|(entry_local, _)| *entry_local < local)
            {
                *cursor += 1;
            }
            let Some((entry_local, slot)) = entries.get(*cursor).copied() else {
                return Err(StoreError::Decode(
                    "owner-index slot is absent from durable sparse segment",
                ));
            };
            if entry_local != local {
                return Err(StoreError::Decode(
                    "owner-index slot is absent from durable sparse segment",
                ));
            }
            *cursor += 1;
            if slot.is_empty() {
                return Err(StoreError::Decode(
                    "owner-index slot is empty in durable state",
                ));
            }
            let SlotValue {
                value,
                owner_hi,
                owner_lo,
            } = slot;
            if owner_key_from_fields(owner_hi, owner_lo) != *owner {
                return Err(StoreError::Decode(
                    "owner-index owner does not match durable state",
                ));
            }
            if value.0 != packed_value {
                return Err(StoreError::Decode(
                    "owner-index packed value does not match durable state",
                ));
            }
            let (amount, creation_id) = unpack_amount_creation_id(value);
            verified.push(VerifiedOwnerUtxo {
                slot_index,
                amount,
                creation_id,
            });
            if max_utxos.is_some_and(|limit| verified.len() >= limit) {
                break;
            }
            item = owner_cursor.next()?;
        }
        Ok(VerifiedOwnerSnapshot {
            owner: *owner,
            height,
            tip_hash,
            state_root: header.state_root,
            log_slots,
            active_slot_count,
            alloc_counter,
            utxos: verified,
        })
    }

    /// The staging handle has already passed receiver finalization, but every
    /// file is re-opened and independently checked inside this single RW
    /// transaction. Segment payload, composite owner-index records and exact
    /// summaries are consumed one sparse segment at a time. Any error drops the
    /// transaction, preserving the complete previous volatile state epoch.
    ///
    /// The returned `ChainState` contains only compact exact summaries and
    /// evicted-segment metadata.  It is returned only after MDBX commit, so the
    /// context can switch hot state without a fallible post-commit disk reload.
    pub(crate) fn install_finalized_snapshot_staging<S: SnapshotHeaderInstallSource>(
        &self,
        staging: &FinalizedSnapshotStaging,
        consensus_meta: &ConsensusMeta,
        canonical_recent_headers: &[BlockHeader],
        boundary: &crate::storage::VerifiedSnapshotBoundary,
        header_source: &mut S,
        allow_nonfinal_rebase: bool,
    ) -> Result<ChainState, StoreError> {
        let metadata = staging.metadata();
        let tip_header = *metadata.header();
        let tip_hash = metadata.tip_hash();
        let effective_log = metadata.effective_log_segment();
        let base_record = header_source.base_record();
        let target_record = header_source.target_record();

        if crate::block_header::block_id(&tip_header) != tip_hash
            || consensus_meta.tip_height != tip_header.height
            || consensus_meta.tip_hash != tip_hash
            || consensus_meta.finalized.height != tip_header.height
            || consensus_meta.finalized.hash != tip_hash
            || target_record.header != tip_header
            || target_record.hash != tip_hash
            || target_record.cumulative_chainwork != consensus_meta.cumulative_chainwork
        {
            return Err(StoreError::Decode(
                "staged snapshot metadata and consensus boundary disagree",
            ));
        }
        if base_record.header.height >= target_record.header.height
            || crate::block_header::block_id(&base_record.header) != base_record.hash
            || crate::block_header::block_id(&target_record.header) != target_record.hash
        {
            return Err(StoreError::Decode(
                "staged snapshot header source boundary is invalid",
            ));
        }
        if canonical_recent_headers.last() != Some(&tip_header)
            || canonical_recent_headers.is_empty()
            || canonical_recent_headers.windows(2).any(|pair| {
                pair[1].height != pair[0].height.saturating_add(1)
                    || pair[1].prev_block_hash != crate::block_header::block_id(&pair[0])
            })
        {
            return Err(StoreError::Decode(
                "staged snapshot recent header window is not canonical",
            ));
        }
        let expected_effective_log = tip_header
            .log_slots
            .min(crate::consensus::params::LOG_SEGMENT_SIZE)
            as u8;
        if effective_log != expected_effective_log {
            return Err(StoreError::Decode(
                "staged snapshot effective segment log mismatch",
            ));
        }
        if boundary.header() != &tip_header || boundary.block_hash() != tip_hash {
            return Err(StoreError::Decode(
                "verified snapshot boundary does not match snapshot metadata",
            ));
        }

        let mut segmented =
            crate::segmented_state::SegmentedFriState::new_empty(tip_header.log_slots as usize);
        let mut exact = StreamingSparseRoot::new(tip_header.log_slots)
            .map_err(|_| StoreError::Decode("invalid staged snapshot exact-root depth"))?;
        let mut exact_segment_roots = Vec::with_capacity(staging.descriptors().len());
        let mut counted_live = 0u64;
        let mut circulating_supply_micronoid = 0u128;
        let mut previous_segment = None;

        let txn = self.db.begin_rw_txn()?;

        // Header archive, state, terminal, consensus metadata and rewarded tip
        // are one acceptance unit. No staged header becomes canonical until
        // this transaction has rechecked the current accepted prefix and can
        // commit the complete authenticated snapshot boundary.
        let header_tbl = txn.open_table(Some(T_HEADERS))?;
        let hash_to_height_tbl = txn.open_table(Some(T_HASH_TO_HEIGHT))?;
        let work_tbl = txn.open_table(Some(T_CHAIN_WORK))?;
        let anchor_tbl = txn.open_table(Some(T_HEADER_ANCHORS))?;
        let tip_tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        let current_tip_raw: Option<[u8; 40]> = txn.get(&tip_tbl, KEY_TIP)?;
        let (current_tip_height, current_tip_hash) = current_tip_raw
            .as_ref()
            .and_then(|raw| decode_chain_tip(raw))
            .ok_or(StoreError::Decode("canonical tip is missing or invalid"))?;
        if current_tip_height < base_record.header.height
            || current_tip_height >= target_record.header.height
        {
            return Err(StoreError::Decode(
                "accepted tip is outside the staged snapshot prefix",
            ));
        }
        let consensus_tbl = txn.open_table(Some(T_CONSENSUS_META))?;
        let current_meta_raw: Option<Vec<u8>> = txn.get(&consensus_tbl, KEY_CONSENSUS_META)?;
        let current_meta = current_meta_raw
            .as_deref()
            .and_then(decode_consensus_meta)
            .ok_or(StoreError::Decode(
                "canonical consensus metadata is missing or invalid",
            ))?;
        if current_meta.tip_height != current_tip_height
            || current_meta.tip_hash != current_tip_hash
        {
            return Err(StoreError::Decode(
                "canonical tip and consensus metadata disagree",
            ));
        }
        let expected_canonical_records = current_tip_height
            .checked_add(1)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(StoreError::Decode("canonical header count overflows usize"))?;
        for table in [&header_tbl, &hash_to_height_tbl, &work_tbl, &anchor_tbl] {
            if txn.table_stat(table)?.entries() != expected_canonical_records {
                return Err(StoreError::Decode(
                    "canonical header tables contain rows beyond or below the accepted tip",
                ));
            }
        }

        let base_key = u64_key(base_record.header.height);
        let base_header_raw: Option<Vec<u8>> = txn.get(&header_tbl, &base_key)?;
        let base_height_raw: Option<Vec<u8>> =
            txn.get(&hash_to_height_tbl, base_record.hash.as_slice())?;
        let base_work_raw: Option<Vec<u8>> = txn.get(&work_tbl, &base_key)?;
        let base_anchor_raw: Option<Vec<u8>> = txn.get(&anchor_tbl, &base_key)?;
        let expected_base_anchor = HeaderChainAnchor {
            height: base_record.header.height,
            block_id: base_record.hash,
            state_root: base_record.header.state_root,
            tx_root: base_record.header.tx_root,
            miner_address: base_record.header.miner_address,
            log_slots: base_record.header.log_slots,
            active_slot_count: base_record.header.active_slot_count,
            alloc_counter: base_record.header.alloc_counter,
            cumulative_chainwork: base_record.cumulative_chainwork,
        };
        if base_header_raw.as_deref().and_then(decode_header) != Some(base_record.header)
            || base_height_raw.as_deref().and_then(u64_from_key) != Some(base_record.header.height)
            || base_work_raw.as_deref().and_then(decode_chain_work)
                != Some(base_record.cumulative_chainwork)
            || base_anchor_raw
                .as_deref()
                .and_then(decode_header_chain_anchor)
                != Some(expected_base_anchor.clone())
        {
            return Err(StoreError::Decode(
                "staged snapshot base conflicts with canonical records",
            ));
        }
        if current_tip_height == base_record.header.height
            && (current_tip_hash != base_record.hash
                || current_meta.cumulative_chainwork != base_record.cumulative_chainwork)
        {
            return Err(StoreError::Decode(
                "accepted tip diverged from staged snapshot base",
            ));
        }

        let mut previous = base_record;
        let mut previous_anchor = expected_base_anchor;
        let mut expected_height = base_record
            .header
            .height
            .checked_add(1)
            .ok_or(StoreError::Decode("snapshot header height overflow"))?;
        let mut matched_current_tip = current_tip_height == base_record.header.height;
        let mut replacing_nonfinal_suffix = false;
        let mut last_matching_height = base_record.header.height;
        while let Some(record) = header_source
            .next_record()
            .map_err(StoreError::SnapshotHeaders)?
        {
            if record.header.height != expected_height
                || record.header.prev_block_hash != previous.hash
            {
                return Err(StoreError::Decode(
                    "staged snapshot headers are not an exact contiguous chain",
                ));
            }
            let expected_work = crate::consensus::add_work(
                &previous.cumulative_chainwork,
                &crate::consensus::block_work(&record.header.difficulty_target),
            );
            if record.cumulative_chainwork != expected_work {
                return Err(StoreError::Decode(
                    "staged snapshot header cumulative chainwork mismatch",
                ));
            }
            let anchor = extend_header_chain_anchor_prehashed(
                &previous_anchor,
                &record.header,
                record.hash,
                record.cumulative_chainwork,
            )?;

            let height_key = u64_key(record.header.height);
            if record.header.height <= current_tip_height && !replacing_nonfinal_suffix {
                let stored_header_raw: Option<Vec<u8>> = txn.get(&header_tbl, &height_key)?;
                let stored_height_raw: Option<Vec<u8>> =
                    txn.get(&hash_to_height_tbl, record.hash.as_slice())?;
                let stored_work_raw: Option<Vec<u8>> = txn.get(&work_tbl, &height_key)?;
                let stored_anchor_raw: Option<Vec<u8>> = txn.get(&anchor_tbl, &height_key)?;
                let matches_canonical = stored_header_raw.as_deref().and_then(decode_header)
                    == Some(record.header)
                    && stored_height_raw.as_deref().and_then(u64_from_key)
                        == Some(record.header.height)
                    && stored_work_raw.as_deref().and_then(decode_chain_work)
                        == Some(record.cumulative_chainwork)
                    && stored_anchor_raw
                        .as_deref()
                        .and_then(decode_header_chain_anchor)
                        == Some(anchor.clone());
                if matches_canonical {
                    last_matching_height = record.header.height;
                    if record.header.height == current_tip_height {
                        if record.hash != current_tip_hash
                            || record.cumulative_chainwork != current_meta.cumulative_chainwork
                        {
                            return Err(StoreError::Decode(
                                "accepted tip hash diverged from staged snapshot prefix",
                            ));
                        }
                        matched_current_tip = true;
                    }
                } else {
                    let ancestor_height = record.header.height.saturating_sub(1);
                    let reorg_depth = current_tip_height.saturating_sub(ancestor_height);
                    let candidate_wins = matches!(
                        crate::consensus::choose_chain_by_work(
                            &target_record.cumulative_chainwork,
                            &target_record.hash,
                            &current_meta.cumulative_chainwork,
                            &current_tip_hash,
                        ),
                        crate::consensus::fork_choice::ChainChoice::A
                    );
                    if !allow_nonfinal_rebase
                        || ancestor_height != last_matching_height
                        || ancestor_height < current_meta.finalized.height
                        || reorg_depth > CONSENSUS_FINALITY_DEPTH
                        || !candidate_wins
                    {
                        return Err(StoreError::Decode(
                            "staged snapshot cannot replace the accepted finalized suffix",
                        ));
                    }

                    // Replace only the losing non-final header suffix.  The
                    // state, indexes, undo data and retained payload tables are
                    // replaced later in this same transaction. Any error rolls
                    // the complete operation back to the old branch.
                    // The authorized replacement is bounded by finality, so
                    // delete the exact numeric suffix directly. A cursor from
                    // the first archived header would turn this rare recovery
                    // into O(chain age) work despite replacing at most 18 rows.
                    let mut old_headers = Vec::with_capacity(reorg_depth as usize);
                    for height in ancestor_height.saturating_add(1)..=current_tip_height {
                        let raw: Option<Vec<u8>> = txn.get(&header_tbl, &u64_key(height))?;
                        let header =
                            raw.as_deref()
                                .and_then(decode_header)
                                .ok_or(StoreError::Decode(
                                    "invalid canonical header during snapshot rebase",
                                ))?;
                        old_headers.push((height, crate::hash_block_header(&header)));
                    }
                    for (height, hash) in old_headers {
                        txn.del(&header_tbl, u64_key(height), None)?;
                        let _ = txn.del(&hash_to_height_tbl, hash.as_slice(), None);
                        let _ = txn.del(&work_tbl, u64_key(height), None);
                        let _ = txn.del(&anchor_tbl, u64_key(height), None);
                    }
                    replacing_nonfinal_suffix = true;
                    matched_current_tip = true;
                    txn.put(
                        &header_tbl,
                        height_key,
                        encode_header(&record.header),
                        WriteFlags::NO_OVERWRITE,
                    )?;
                    txn.put(
                        &hash_to_height_tbl,
                        record.hash.as_slice(),
                        height_key,
                        WriteFlags::NO_OVERWRITE,
                    )?;
                    txn.put(
                        &work_tbl,
                        height_key,
                        encode_chain_work(&record.cumulative_chainwork),
                        WriteFlags::NO_OVERWRITE,
                    )?;
                    txn.put(
                        &anchor_tbl,
                        height_key,
                        encode_header_chain_anchor(&anchor),
                        WriteFlags::NO_OVERWRITE,
                    )?;
                }
            } else {
                txn.put(
                    &header_tbl,
                    height_key,
                    encode_header(&record.header),
                    WriteFlags::NO_OVERWRITE,
                )?;
                txn.put(
                    &hash_to_height_tbl,
                    record.hash.as_slice(),
                    height_key,
                    WriteFlags::NO_OVERWRITE,
                )?;
                txn.put(
                    &work_tbl,
                    height_key,
                    encode_chain_work(&record.cumulative_chainwork),
                    WriteFlags::NO_OVERWRITE,
                )?;
                txn.put(
                    &anchor_tbl,
                    height_key,
                    encode_header_chain_anchor(&anchor),
                    WriteFlags::NO_OVERWRITE,
                )?;
            }

            previous = record;
            previous_anchor = anchor;
            expected_height = expected_height
                .checked_add(1)
                .ok_or(StoreError::Decode("snapshot header height overflow"))?;
        }
        if !matched_current_tip || previous != target_record {
            return Err(StoreError::Decode(
                "staged snapshot header stream ended at the wrong boundary",
            ));
        }
        for header in canonical_recent_headers {
            let raw: Option<Vec<u8>> = txn.get(&header_tbl, &u64_key(header.height))?;
            if raw.as_deref().and_then(decode_header) != Some(*header) {
                return Err(StoreError::Decode(
                    "staged snapshot recent header changed before install",
                ));
            }
        }

        for name in [
            T_SEGMENTS,
            T_SEGMENT_SUMMARIES,
            T_UNDO_LOGS,
            T_RECENT_BLOCKS,
            T_TX_INDEX,
            T_HISTORY_STEP_TERMINALS,
            T_HISTORY_STEP_PROOF_OBJECTS,
            T_OWNER_INDEX,
            T_RETENTION_META,
        ] {
            let table = txn.open_table(Some(name))?;
            txn.clear_table(&table)?;
        }

        // Every height below the verified terminal-only boundary was retired
        // atomically above. The watermark names the last fully removed height;
        // F itself remains as the HistoryStep boundary for F+1.
        set_retained_payload_prune_watermark(&txn, tip_header.height - 1)?;

        let terminal_tbl = txn.open_table(Some(T_HISTORY_STEP_TERMINALS))?;
        txn.put(
            &terminal_tbl,
            u64_key(boundary.header().height),
            boundary.history_step_terminal_bytes(),
            WriteFlags::empty(),
        )?;
        archive_history_step_proof_object(&txn, boundary.history_step_terminal_bytes())?;
        let segment_tbl = txn.open_table(Some(T_SEGMENTS))?;
        let summary_tbl = txn.open_table(Some(T_SEGMENT_SUMMARIES))?;
        let owner_tbl = txn.open_table(Some(T_OWNER_INDEX))?;
        for staged_file in staging.encoded_files() {
            let descriptor = *staged_file.descriptor();
            if previous_segment.is_some_and(|previous| previous >= descriptor.segment_id) {
                return Err(StoreError::Decode(
                    "staged snapshot segment ids are not strictly increasing",
                ));
            }
            previous_segment = Some(descriptor.segment_id);
            if staged_file.effective_log_segment() != effective_log {
                return Err(StoreError::Decode(
                    "staged snapshot file effective log mismatch",
                ));
            }

            // `read_encoded` closes finalize-to-install file corruption. Parse
            // the canonical sparse entries again inside this transaction so
            // owner-index construction and both exact roots consume precisely
            // the bytes that are atomically installed.
            let encoded = staged_file.read_encoded()?;
            let sparse = decode_sparse_segment(&encoded).ok_or(StoreError::Decode(
                "staged sparse segment decode failed during install",
            ))?;
            if sparse.effective_log_segment() != effective_log {
                return Err(StoreError::Decode(
                    "staged snapshot sparse segment shape mismatch",
                ));
            }

            let segment_base = u64::from(descriptor.segment_id) << effective_log;
            let mut segment_exact = StreamingSparseRoot::new(u32::from(effective_log))
                .map_err(|_| StoreError::Decode("invalid staged segment exact-root depth"))?;
            for (local, slot) in sparse.entries() {
                let creation_in_target = crate::consensus::params::creation_id_within_boundary(
                    slot.creation_id(),
                    tip_header.alloc_counter,
                    tip_header.height,
                );
                if !creation_in_target {
                    return Err(StoreError::Decode(
                        "staged snapshot creation_id exceeds target boundary",
                    ));
                }
                counted_live = counted_live
                    .checked_add(1)
                    .ok_or(StoreError::Decode("staged snapshot active-count overflow"))?;
                circulating_supply_micronoid = circulating_supply_micronoid
                    .checked_add(u128::from(slot.amount()))
                    .ok_or(StoreError::Decode(
                        "staged snapshot circulating supply overflow",
                    ))?;
                let global = segment_base
                    .checked_add(u64::from(local))
                    .and_then(|index| u32::try_from(index).ok())
                    .ok_or(StoreError::Decode(
                        "staged snapshot live slot exceeds u32 domain",
                    ))?;
                exact.push_leaf(global, slot_leaf_hash(slot)).map_err(|_| {
                    StoreError::Decode("staged snapshot exact leaf is out of range")
                })?;
                segment_exact
                    .push_leaf(u32::from(local), slot_leaf_hash(slot))
                    .map_err(|_| StoreError::Decode("staged segment exact leaf is out of range"))?;
                let owner = owner_key_from_fields(slot.owner_hi, slot.owner_lo);
                txn.put(
                    &owner_tbl,
                    owner_index_key(&owner, global),
                    encode_owner_index_value(slot.value.0),
                    WriteFlags::empty(),
                )?;
            }
            let segment_live = sparse.live_count();
            if segment_live == 0 {
                return Err(StoreError::Decode(
                    "staged snapshot advertises an empty segment",
                ));
            }
            let exact_root = segment_exact
                .finish()
                .map_err(|_| StoreError::Decode("staged segment exact-root build failed"))?;
            if exact_root != descriptor.segment_root {
                return Err(StoreError::Decode(
                    "staged snapshot exact segment root mismatch during install",
                ));
            }

            txn.put(
                &segment_tbl,
                descriptor.segment_id.to_le_bytes(),
                &encoded,
                WriteFlags::empty(),
            )?;
            segmented
                .install_evicted_exact_summary(descriptor.segment_id, segment_live)
                .map_err(StoreError::Decode)?;
            txn.put(
                &summary_tbl,
                descriptor.segment_id.to_le_bytes(),
                encode_segment_summary(segment_live, &exact_root),
                WriteFlags::empty(),
            )?;
            exact_segment_roots.push((descriptor.segment_id, exact_root));
            // The encoded payload drops before the next file. Only compact
            // exact roots/counts survive the pass.
        }

        if counted_live != tip_header.active_slot_count {
            return Err(StoreError::Decode(
                "staged snapshot active count does not match target header",
            ));
        }
        let exact_root = exact
            .finish()
            .map_err(|_| StoreError::Decode("staged snapshot exact-root build failed"))?;
        if exact_root != tip_header.state_root {
            return Err(StoreError::Decode(
                "staged snapshot exact root does not match target header",
            ));
        }
        segmented.finish_evicted_exact_summaries();
        let hot_state = ChainState::from_evicted_parts(
            segmented,
            tip_header.active_slot_count,
            tip_header.alloc_counter,
            circulating_supply_micronoid,
            exact_root,
            &exact_segment_roots,
        )
        .map_err(|_| StoreError::Decode("staged snapshot compact exact cache mismatch"))?;
        txn.put(
            &tip_tbl,
            KEY_TIP,
            encode_chain_tip(tip_header.height, &tip_hash),
            WriteFlags::empty(),
        )?;
        txn.put(
            &consensus_tbl,
            KEY_CONSENSUS_META,
            encode_consensus_meta(consensus_meta),
            WriteFlags::empty(),
        )?;
        txn.put(
            &work_tbl,
            u64_key(tip_header.height),
            encode_chain_work(&consensus_meta.cumulative_chainwork),
            WriteFlags::empty(),
        )?;
        let state_meta_tbl = txn.open_table(Some(T_STATE_META))?;
        txn.put(
            &state_meta_tbl,
            KEY_META,
            encode_state_meta(
                tip_header.log_slots,
                tip_header.active_slot_count,
                tip_header.alloc_counter,
                circulating_supply_micronoid,
            ),
            WriteFlags::empty(),
        )?;
        prune_history_step_proof_objects(&txn, tip_header.height)?;
        txn.commit()?;
        Ok(hot_state)
    }

    /// Look up a transaction by its body hash. Returns `(block_height, tx_pos_in_block)`.
    pub fn get_tx_index(&self, hash: &[u8; 32]) -> Result<Option<(u64, u32)>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_TX_INDEX))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, hash.as_slice())?;
        Ok(raw.and_then(|b| decode_tx_index_value(&b)))
    }

    /// Return the numeric, strictly unique durable segment ID set without
    /// copying or decoding any segment payload.
    ///
    /// Segment keys predate this API and are little-endian, so MDBX's
    /// lexicographic cursor order is not numeric once IDs exceed 255.  The
    /// complete u16 namespace costs at most 128 KiB here; values are decoded
    /// as `()` so even corrupt or very large payloads are not materialized.
    pub(crate) fn segment_ids(&self) -> Result<Vec<u16>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_SEGMENTS))?;
        let mut cursor = txn.cursor(&tbl)?;
        let mut segment_ids = Vec::new();
        let mut item: Option<(Vec<u8>, ())> = cursor.first()?;
        while let Some((key, ())) = item {
            if key.len() != 2 {
                return Err(StoreError::Decode("invalid stored segment key"));
            }
            segment_ids.push(u16::from_le_bytes([key[0], key[1]]));
            item = cursor.next()?;
        }
        sort_unique_segment_ids(segment_ids)
    }

    /// Read the complete compact restart index without touching dense segment
    /// values. Records are returned in numeric segment order.
    pub(crate) fn segment_summaries(&self) -> Result<Vec<(u16, u32, [u8; 32])>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let table = txn.open_table(Some(T_SEGMENT_SUMMARIES))?;
        let mut cursor = txn.cursor(&table)?;
        let mut summaries = Vec::new();
        let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
        while let Some((key, raw)) = item {
            if key.len() != 2 {
                return Err(StoreError::Decode("invalid stored segment-summary key"));
            }
            let segment_id = u16::from_le_bytes([key[0], key[1]]);
            let (live_count, exact_root) = decode_segment_summary(&raw)
                .ok_or(StoreError::Decode("invalid stored segment summary"))?;
            if live_count == 0 {
                return Err(StoreError::Decode("empty stored segment summary"));
            }
            summaries.push((segment_id, live_count, exact_root));
            item = cursor.next()?;
        }
        summaries.sort_unstable_by_key(|(segment_id, _, _)| *segment_id);
        if summaries
            .windows(2)
            .any(|window| window[0].0 == window[1].0)
        {
            return Err(StoreError::Decode("duplicate stored segment summary"));
        }
        Ok(summaries)
    }

    /// Replace a missing/legacy compact restart index after the dense state has
    /// passed the old full verification path. The canonical tip, header and
    /// counters are rechecked inside the same transaction, so a future caller
    /// can never observe summaries for another state epoch.
    pub(crate) fn replace_segment_summaries(
        &self,
        expected_height: u64,
        expected_hash: [u8; 32],
        state: &ChainState,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tip_table = txn.open_table(Some(T_CHAIN_TIP))?;
        let tip_raw: Option<Vec<u8>> = txn.get(&tip_table, KEY_TIP)?;
        if tip_raw.as_deref().and_then(decode_chain_tip) != Some((expected_height, expected_hash)) {
            return Err(StoreError::Decode(
                "canonical tip changed while rebuilding segment summaries",
            ));
        }
        let header_table = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<Vec<u8>> = txn.get(&header_table, &u64_key(expected_height))?;
        let header = header_raw
            .as_deref()
            .and_then(decode_header)
            .ok_or(StoreError::Decode(
                "canonical header missing while rebuilding segment summaries",
            ))?;
        if crate::hash_block_header(&header) != expected_hash
            || header.state_root != state.cached_state_root()
            || header.log_slots as usize != state.state.log_slots()
            || header.active_slot_count != state.active_slot_count
            || header.alloc_counter != state.alloc_counter
        {
            return Err(StoreError::Decode(
                "canonical state changed while rebuilding segment summaries",
            ));
        }

        let table = txn.open_table(Some(T_SEGMENT_SUMMARIES))?;
        txn.clear_table(&table)?;
        for segment_id in state.state.active_segment_ids() {
            let live_count = state.state.segment_live_count(segment_id);
            let exact_root = state
                .cached_exact_segment_root(segment_id)
                .ok_or(StoreError::Decode("missing compact exact segment root"))?;
            txn.put(
                &table,
                segment_id.to_le_bytes(),
                encode_segment_summary(live_count, &exact_root),
                WriteFlags::empty(),
            )?;
        }
        let state_meta = txn.open_table(Some(T_STATE_META))?;
        txn.put(
            &state_meta,
            KEY_META,
            encode_state_meta(
                header.log_slots,
                header.active_slot_count,
                header.alloc_counter,
                state.circulating_supply_micronoid,
            ),
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    /// Stream stored segments through a one-segment ownership boundary.
    ///
    /// Startup and reorg recovery use this path so the node never materializes
    /// a second `Vec` containing the complete durable state.  Peak temporary
    /// memory is one encoded segment plus one decoded `SegmentColumns`.
    pub(crate) fn visit_segments(
        &self,
        mut visitor: impl FnMut(u16, u8, SegmentColumns) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        for segment_id in self.segment_ids()? {
            let (effective_log, columns) = self.get_segment(segment_id)?.ok_or(
                StoreError::Decode("stored segment disappeared while streaming"),
            )?;
            visitor(segment_id, effective_log, columns)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Atomic block commit (P.18 — 7-step protocol)
    // -----------------------------------------------------------------------

    /// Atomically commit all data for a newly applied block.
    ///
    /// Steps (all in ONE MDBX transaction, either fully committed or fully aborted):
    /// 1. Write dirty segment columns
    /// 2. Write BlockHeader (height → bytes)
    /// 3. Write hash→height index
    /// 4. Write chain_tip and consensus_meta
    /// 5. Write exact cumulative chainwork at this height
    /// 6. Write state_meta (log_slots, active_slot_count, alloc_counter)
    /// 7. Write BlockUndoLog
    /// 8. Write the accepted block body and HistoryStep terminal
    /// 9. Remove reverted tx-index entries and index this block's transactions
    ///
    /// After commit (non-atomic, re-runnable):
    ///   - Prune old undo_logs beyond UNDO_RETENTION_DEPTH.
    ///   - Prune block bodies outside the shorter recent peer-serving window,
    ///     while retaining its preceding HistoryStep terminal.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_block(
        &self,
        header: &BlockHeader,
        hash: &[u8; 32],
        undo_log: &BlockUndoLog,
        dirty_segments: &[(u16, u8, Option<&SegmentColumns>)],
        dirty_segment_summaries: &[(u16, u32, [u8; 32])],
        tx_hashes: &[TxBodyHash],
        tx_index_deletes: &[TxBodyHash],
        accepted_block: Option<AcceptedBlockCommit<'_>>,
        circulating_supply_micronoid: u128,
        consensus_meta: &ConsensusMeta,
        rebuild_owner_index: bool,
    ) -> Result<(), StoreError> {
        if dirty_segments.len() != dirty_segment_summaries.len()
            || dirty_segments.iter().zip(dirty_segment_summaries).any(
                |((segment_id, _, columns), (summary_id, live_count, _))| {
                    segment_id != summary_id
                        || (columns.is_none() && *live_count != 0)
                        || (columns.is_some() && *live_count == 0)
                },
            )
        {
            return Err(StoreError::Decode(
                "dirty segment summaries do not match dirty columns",
            ));
        }
        // A canonical non-genesis block is one atomic block + HistoryStep
        // unit. Keep the low-level storage API fail-closed too: no caller can
        // accidentally materialize a PoW-only tip even if it bypasses
        // `MdbxChainContext::apply_next_block`.
        let accepted_non_genesis = if header.height != 0 {
            let accepted = accepted_block.ok_or(StoreError::Decode(
                "non-genesis block is missing its accepted authorization",
            ))?;
            let (block_bytes, complete_terminal, recursive_authority) = match accepted {
                AcceptedBlockCommit::Complete(bundle) => {
                    if bundle.height() != header.height || bundle.block_hash() != *hash {
                        return Err(StoreError::Decode(
                            "accepted bundle does not bind the committed header",
                        ));
                    }
                    (
                        bundle.block_bytes(),
                        Some(bundle.history_step_terminal_bytes()),
                        None,
                    )
                }
                AcceptedBlockCommit::CompleteObjects {
                    block_bytes,
                    terminal_bytes,
                } => (block_bytes, Some(terminal_bytes), None),
                AcceptedBlockCommit::RecursiveSuffix {
                    block_bytes,
                    authority_tip_height,
                    authority_tip_hash,
                } => {
                    if authority_tip_height <= header.height {
                        return Err(StoreError::Decode(
                            "intermediate recursive suffix block is not below its authority tip",
                        ));
                    }
                    (
                        block_bytes,
                        None,
                        Some((authority_tip_height, authority_tip_hash)),
                    )
                }
            };
            let block = crate::Block::from_bytes(block_bytes)
                .map_err(|_| StoreError::Decode("accepted block body is malformed"))?;
            let logical_txids = crate::block::try_compute_logical_txids(&block.transactions)
                .map_err(|_| StoreError::Decode("accepted logical tx stream is malformed"))?;
            if block.header != *header
                || logical_txids != tx_hashes
                || logical_txids != undo_log.tx_hashes
            {
                return Err(StoreError::Decode(
                    "accepted logical txids do not bind the committed block",
                ));
            }
            let effective_page_count =
                block
                    .transactions
                    .len()
                    .checked_sub(1)
                    .ok_or(StoreError::Decode(
                        "accepted block is missing its coinbase record",
                    ))?;
            let expected_class = history_step_class_slot(effective_page_count).ok_or(
                StoreError::Decode("accepted block page count has no canonical HistoryStep tier"),
            )?;
            let terminal_bytes: Cow<'_, [u8]> = match complete_terminal {
                Some(terminal) => {
                    if !history_step_terminal_matches_class(
                        terminal,
                        header.height,
                        crate::block_header::semantic_header_id(header),
                        expected_class,
                    ) {
                        return Err(StoreError::Decode(
                            "accepted current-height history terminal class is malformed",
                        ));
                    }
                    Cow::Borrowed(terminal)
                }
                None => {
                    let (authority_tip_height, authority_tip_hash) =
                        recursive_authority.expect("recursive authorization is present");
                    Cow::Owned(
                        encode_recursive_suffix_marker(
                            header,
                            expected_class,
                            authority_tip_height,
                            authority_tip_hash,
                        )?
                        .to_vec(),
                    )
                }
            };
            Some((block_bytes, terminal_bytes, recursive_authority))
        } else {
            if accepted_block.is_some() {
                return Err(StoreError::Decode(
                    "genesis must not carry an accepted block authorization",
                ));
            }
            None
        };

        let txn = self.db.begin_rw_txn()?;

        if header.height != 0 {
            let tip_table = txn.open_table(Some(T_CHAIN_TIP))?;
            let tip_raw: Option<[u8; 40]> = txn.get(&tip_table, KEY_TIP)?;
            if tip_raw.as_ref().and_then(|raw| decode_chain_tip(raw))
                != Some((header.height - 1, header.prev_block_hash))
            {
                return Err(StoreError::Decode(
                    "accepted block is not the exact canonical successor",
                ));
            }
            validate_history_step_parent_boundary_in_rw_txn(&txn, header)?;
            if let Some((authority_tip_height, authority_tip_hash)) = accepted_non_genesis
                .as_ref()
                .and_then(|(_, _, authority)| *authority)
            {
                let retention = txn.open_table(Some(T_RETENTION_META))?;
                let authority_raw: Option<Vec<u8>> =
                    txn.get(&retention, KEY_VERIFIED_SUFFIX_AUTHORITY)?;
                let authority = authority_raw
                    .as_deref()
                    .and_then(decode_verified_suffix_authority)
                    .ok_or(StoreError::Decode(
                        "verified recursive suffix authority is missing",
                    ))?;
                if authority.tip_height != authority_tip_height
                    || authority.tip_hash != authority_tip_hash
                    || header.height <= authority.boundary_height
                    || header.height >= authority.tip_height
                {
                    return Err(StoreError::Decode(
                        "recursive suffix block lies outside its verified authority",
                    ));
                }
            }
        }

        // --- 1. Dirty segments ---
        let seg_tbl = txn.open_table(Some(T_SEGMENTS))?;
        let summary_tbl = txn.open_table(Some(T_SEGMENT_SUMMARIES))?;
        for ((seg_id, eff_log, cols), (_, live_count, exact_root)) in
            dirty_segments.iter().zip(dirty_segment_summaries)
        {
            let key = seg_id.to_le_bytes();
            match cols {
                None => {
                    // Do not persist fully-empty segments. This keeps disk and
                    // snapshot size proportional to live UTXOs.
                    let _ = txn.del(&seg_tbl, key, None);
                    let _ = txn.del(&summary_tbl, key, None);
                }
                Some(cols) => {
                    if segment_columns_empty(cols) {
                        return Err(StoreError::Decode("non-delete dirty segment is empty"));
                    }
                    let val = encode_segment(cols, *eff_log);
                    txn.put(&seg_tbl, key, val, WriteFlags::empty())?;
                    txn.put(
                        &summary_tbl,
                        key,
                        encode_segment_summary(*live_count, exact_root),
                        WriteFlags::empty(),
                    )?;
                }
            }
        }
        // Reorg rollback may cross a slot-domain expansion. Purge every
        // persisted segment outside the ancestor header's domain in this same
        // atomic checkpoint transaction; otherwise a restart could reload
        // stale upper-half data under the smaller depth.
        let domain_segments = if header.log_slots > crate::consensus::params::LOG_SEGMENT_SIZE {
            1usize
                .checked_shl(header.log_slots - crate::consensus::params::LOG_SEGMENT_SIZE)
                .ok_or(StoreError::Decode(
                    "header log_slots exceeds segment domain",
                ))?
        } else {
            1
        };
        let out_of_domain_keys: Vec<Vec<u8>> = {
            let mut cursor = txn.cursor(&seg_tbl)?;
            let mut keys = Vec::new();
            let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
            while let Some((key, _)) = item {
                if key.len() != 2 {
                    return Err(StoreError::Decode("invalid segment key"));
                }
                let seg_id = u16::from_le_bytes([key[0], key[1]]) as usize;
                if seg_id >= domain_segments {
                    keys.push(key);
                }
                item = cursor.next()?;
            }
            keys
        };
        for key in out_of_domain_keys {
            txn.del(&seg_tbl, &key, None)?;
            txn.del(&summary_tbl, &key, None)?;
        }

        // --- 2. BlockHeader ---
        let hdr_tbl = txn.open_table(Some(T_HEADERS))?;
        txn.put(
            &hdr_tbl,
            u64_key(header.height),
            encode_header(header),
            WriteFlags::empty(),
        )?;

        // --- 3. hash → height ---
        let h2h_tbl = txn.open_table(Some(T_HASH_TO_HEIGHT))?;
        txn.put(
            &h2h_tbl,
            hash.as_slice(),
            u64_key(header.height),
            WriteFlags::empty(),
        )?;

        // --- 4. chain_tip + consensus_meta ---
        debug_assert_eq!(consensus_meta.tip_height, header.height);
        debug_assert_eq!(consensus_meta.tip_hash, *hash);

        let tip_tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        txn.put(
            &tip_tbl,
            KEY_TIP,
            encode_chain_tip(header.height, hash),
            WriteFlags::empty(),
        )?;

        let consensus_tbl = txn.open_table(Some(T_CONSENSUS_META))?;
        txn.put(
            &consensus_tbl,
            KEY_CONSENSUS_META,
            encode_consensus_meta(consensus_meta),
            WriteFlags::empty(),
        )?;

        // --- 5. exact chainwork at canonical height ---
        let work_tbl = txn.open_table(Some(T_CHAIN_WORK))?;
        txn.put(
            &work_tbl,
            u64_key(header.height),
            encode_chain_work(&consensus_meta.cumulative_chainwork),
            WriteFlags::empty(),
        )?;

        // --- 5.5. persistent header-chain anchor ---
        let anchor_tbl = txn.open_table(Some(T_HEADER_ANCHORS))?;
        let anchor = if header.height == 0 {
            compute_header_chain_anchor(
                std::iter::once(header),
                consensus_meta.cumulative_chainwork,
            )?
        } else {
            let previous_raw: Option<Vec<u8>> =
                txn.get(&anchor_tbl, &u64_key(header.height - 1))?;
            let previous = previous_raw
                .as_deref()
                .and_then(decode_header_chain_anchor)
                .ok_or(StoreError::Decode("missing previous header chain anchor"))?;
            extend_header_chain_anchor(&previous, header, consensus_meta.cumulative_chainwork)?
        };
        if anchor.block_id != *hash {
            return Err(StoreError::Decode("header anchor block id mismatch"));
        }
        txn.put(
            &anchor_tbl,
            u64_key(header.height),
            encode_header_chain_anchor(&anchor),
            WriteFlags::empty(),
        )?;

        // --- 6. state_meta ---
        let meta_tbl = txn.open_table(Some(T_STATE_META))?;
        txn.put(
            &meta_tbl,
            KEY_META,
            encode_state_meta(
                header.log_slots,
                header.active_slot_count,
                header.alloc_counter,
                circulating_supply_micronoid,
            ),
            WriteFlags::empty(),
        )?;

        // --- 7. BlockUndoLog ---
        let undo_tbl = txn.open_table(Some(T_UNDO_LOGS))?;
        txn.put(
            &undo_tbl,
            u64_key(header.height),
            encode_undo_log(undo_log),
            WriteFlags::empty(),
        )?;

        // --- 8. Accepted block + HistoryStep terminal ---
        if let Some((block_bytes, terminal_bytes, recursive_authority)) = accepted_non_genesis {
            let height_key = u64_key(header.height);
            let recent_tbl = txn.open_table(Some(T_RECENT_BLOCKS))?;
            txn.put(&recent_tbl, height_key, block_bytes, WriteFlags::empty())?;
            archive_block_body_object(&txn, header.height, *hash, block_bytes)?;
            let terminal_tbl = txn.open_table(Some(T_HISTORY_STEP_TERMINALS))?;
            txn.put(
                &terminal_tbl,
                height_key,
                terminal_bytes.as_ref(),
                WriteFlags::empty(),
            )?;
            if recursive_authority.is_none() {
                archive_history_step_proof_object(&txn, terminal_bytes.as_ref())?;
                let retention = txn.open_table(Some(T_RETENTION_META))?;
                let _ = txn.del(&retention, KEY_VERIFIED_SUFFIX_AUTHORITY, None);
            }
        }

        // --- 8.5. tx_index: logical txid → (height, logical position) ---
        // Enables O(1) receipt lookup in the same leaf namespace as tx_root.
        // Reorg
        // deletions live in this same transaction as the ancestor checkpoint,
        // so a crash can never expose an orphan transaction as canonical.
        let tx_idx_tbl = txn.open_table(Some(T_TX_INDEX))?;
        for h in tx_index_deletes {
            let raw: Option<Vec<u8>> = txn.get(&tx_idx_tbl, h.0.as_slice())?;
            if let Some(raw) = raw {
                let (indexed_height, _) = decode_tx_index_value(&raw)
                    .ok_or(StoreError::Decode("invalid tx index entry during reorg"))?;
                // Preserve an older canonical occurrence defensively. Valid
                // user transaction hashes are one-shot, but this guard keeps a
                // malformed delete list from erasing ancestor history.
                if indexed_height > header.height {
                    txn.del(&tx_idx_tbl, h.0.as_slice(), None)?;
                }
            }
        }
        for (pos, h) in tx_hashes.iter().enumerate() {
            txn.put(
                &tx_idx_tbl,
                h.0,
                encode_tx_index_value(header.height, pos as u32),
                WriteFlags::empty(),
            )?;
        }

        // --- 9. Owner index: update live-UTXO index incrementally, or rebuild
        // it from the post-write segment table for a reorg checkpoint. A reorg
        // restores an ancestor using that ancestor's historical undo log; that
        // log is not a forward delta and must never drive the incremental path.
        // Uses undo_log (which records pre-block slot values) and dirty_segments
        // (which hold post-block slot values) to determine what changed.
        {
            use crate::fri_state::SlotValue;
            let oidx_tbl = txn.open_table(Some(T_OWNER_INDEX))?;
            if rebuild_owner_index {
                txn.clear_table(&oidx_tbl)?;
                let mut cursor = txn.cursor(&seg_tbl)?;
                let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
                while let Some((key, raw)) = item {
                    if key.len() != 2 {
                        return Err(StoreError::Decode(
                            "invalid segment key during owner rebuild",
                        ));
                    }
                    let segment_id = u16::from_le_bytes([key[0], key[1]]);
                    let (effective_log, columns) = decode_segment(&raw)
                        .ok_or(StoreError::Decode("invalid segment during owner rebuild"))?;
                    visit_live_owner_records(
                        segment_id,
                        effective_log,
                        &columns,
                        |owner, slot_index, packed_value| {
                            txn.put(
                                &oidx_tbl,
                                owner_index_key(&owner, slot_index),
                                encode_owner_index_value(packed_value),
                                WriteFlags::empty(),
                            )?;
                            Ok(())
                        },
                    )?;
                    item = cursor.next()?;
                }
            } else {
                // eff_log = log2(slots_per_segment) — same for every dirty segment.
                let eff_log: u32 = dirty_segments
                    .first()
                    .map(|(_, e, _)| *e as u32)
                    .unwrap_or(crate::consensus::params::LOG_SEGMENT_SIZE);

                for &(slot_index, ref prev_value) in &undo_log.slot_changes {
                    // Remove the pre-block owner, if any.
                    if *prev_value != SlotValue::EMPTY {
                        let owner_key =
                            owner_key_from_fields(prev_value.owner_hi, prev_value.owner_lo);
                        let index_key = owner_index_key(&owner_key, slot_index);
                        let existing: Option<Vec<u8>> = txn.get(&oidx_tbl, &index_key)?;
                        let existing = existing
                            .ok_or(StoreError::Decode("missing pre-block owner-index record"))?;
                        if decode_owner_index_value(&existing)? != prev_value.value.0 {
                            return Err(StoreError::Decode("pre-block owner-index value mismatch"));
                        }
                        txn.del(&oidx_tbl, index_key, None)?;
                    }

                    // Add the post-block owner, if any. Doing both halves for
                    // every first-touch slot also handles live→live physical
                    // reuse with a fresh creation ID.
                    let seg_id = (slot_index >> eff_log) as u16;
                    let local = (slot_index & ((1u32 << eff_log) - 1)) as usize;
                    let post_value = match dirty_segments.iter().find(|(id, _, _)| *id == seg_id) {
                        // A proven transient EMPTY→mint→spend→EMPTY action
                        // collapses to no final slot update. The segment is
                        // legitimately absent and durable post == pre.
                        None => *prev_value,
                        // Spending the last live slot dematerializes the dirty
                        // segment; persistence represents its post-state as an
                        // empty/zero-length column payload.
                        Some((_, _, None)) => SlotValue::EMPTY,
                        Some((_, _, Some(cols))) => {
                            if local >= cols.values.len()
                                || local >= cols.owners_hi.len()
                                || local >= cols.owners_lo.len()
                            {
                                return Err(StoreError::Decode(
                                    "owner-index dirty segment is truncated",
                                ));
                            }
                            SlotValue {
                                value: cols.values[local],
                                owner_hi: cols.owners_hi[local],
                                owner_lo: cols.owners_lo[local],
                            }
                        }
                    };
                    let SlotValue {
                        value,
                        owner_hi,
                        owner_lo,
                    } = post_value;
                    if value.0 != 0 || owner_hi.0 != 0 || owner_lo.0 != 0 {
                        let owner_key = owner_key_from_fields(owner_hi, owner_lo);
                        let index_key = owner_index_key(&owner_key, slot_index);
                        if txn.get::<Vec<u8>>(&oidx_tbl, &index_key)?.is_some() {
                            return Err(StoreError::Decode(
                                "duplicate post-block owner-index record",
                            ));
                        }
                        txn.put(
                            &oidx_tbl,
                            index_key,
                            encode_owner_index_value(value.0),
                            WriteFlags::empty(),
                        )?;
                    }
                }
            }
        }

        // Commit atomically — all steps or none.
        txn.commit()?;

        // Post-commit pruning is non-atomic and non-critical.
        // A prune failure leaves stale undo entries until
        // the next commit, but the chain state is already
        // fully consistent after the commit above.  We must NOT propagate the
        // error here: doing so would cause `apply_next_block` to return Err
        // after the block is already durably in MDBX, leaving RAM and MDBX
        // desynchronised until the next restart.
        if let Err(_e) = self.prune_after_commit(header.height) {
            // Safe to ignore: prune is retried on the next commit.
        }

        Ok(())
    }

    /// Atomically replace the canonical suffix above `ancestor_height`.
    ///
    /// Every replacement bundle has already passed HistoryStep verification
    /// in RAM. This transaction installs the final exact state, all replacement
    /// bundles, headers/undo records, and the final tip at
    /// once.  A validation or MDBX failure therefore leaves the old canonical
    /// branch byte-for-byte durable.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_reorg(
        &self,
        ancestor_height: u64,
        final_header: &BlockHeader,
        final_hash: &[u8; 32],
        final_dirty_segments: &[(u16, u8, Option<&SegmentColumns>)],
        final_dirty_segment_summaries: &[(u16, u32, [u8; 32])],
        reverted_tx_hashes: &[TxBodyHash],
        replacement_objects: &[AcceptedBlockCommit<'_>],
        replacement: &[StagedAcceptedBlockCommit],
        circulating_supply_micronoid: u128,
        consensus_meta: &ConsensusMeta,
    ) -> Result<(), StoreError> {
        if final_dirty_segments.len() != final_dirty_segment_summaries.len()
            || final_dirty_segments
                .iter()
                .zip(final_dirty_segment_summaries)
                .any(|((segment_id, _, columns), (summary_id, live_count, _))| {
                    segment_id != summary_id
                        || (columns.is_none() && *live_count != 0)
                        || (columns.is_some() && *live_count == 0)
                })
        {
            return Err(StoreError::Decode(
                "final reorg segment summaries do not match dirty columns",
            ));
        }
        if final_header.height < ancestor_height
            || consensus_meta.tip_height != final_header.height
            || consensus_meta.tip_hash != *final_hash
        {
            return Err(StoreError::Decode("invalid staged reorg tip"));
        }
        if replacement_objects.len() != replacement.len() {
            return Err(StoreError::Decode("staged reorg object count mismatch"));
        }
        let mut expected_height = ancestor_height.saturating_add(1);
        for (accepted, staged) in replacement_objects.iter().copied().zip(replacement) {
            let block = crate::Block::from_bytes(accepted.block_bytes())
                .map_err(|_| StoreError::Decode("staged reorg block is malformed"))?;
            if staged.header.height != expected_height
                || block.header != staged.header
                || staged.hash != crate::hash_block_header(&staged.header)
                || match crate::block::try_compute_logical_txids(&block.transactions) {
                    Ok(txids) => txids != staged.undo_log.tx_hashes,
                    Err(_) => true,
                }
            {
                return Err(StoreError::Decode("invalid staged reorg block"));
            }
            if let Some((authority_height, authority_hash)) = accepted.recursive_authority() {
                if staged.header.height >= authority_height
                    || authority_height != final_header.height
                    || authority_hash != *final_hash
                {
                    return Err(StoreError::Decode(
                        "staged reorg marker has the wrong recursive authority",
                    ));
                }
            }
            expected_height = expected_height
                .checked_add(1)
                .ok_or(StoreError::Decode("staged reorg height overflow"))?;
        }
        match replacement.last() {
            Some(last)
                if last.header != *final_header
                    || last.hash != *final_hash
                    || last.cumulative_chainwork != consensus_meta.cumulative_chainwork =>
            {
                return Err(StoreError::Decode("staged reorg final block mismatch"));
            }
            None if final_header.height != ancestor_height => {
                return Err(StoreError::Decode("empty staged reorg changed height"));
            }
            _ => {}
        }
        if let Some(last) = replacement_objects.last().copied() {
            if last.complete_terminal().is_none() {
                return Err(StoreError::Decode(
                    "staged reorg tip is missing its complete terminal",
                ));
            }
        }

        let txn = self.db.begin_rw_txn()?;
        let tip_tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        let old_tip_raw: Option<[u8; 40]> = txn.get(&tip_tbl, KEY_TIP)?;
        let (old_tip_height, _) = old_tip_raw
            .as_ref()
            .and_then(|raw| decode_chain_tip(raw))
            .ok_or(StoreError::Decode("canonical tip is missing during reorg"))?;
        if old_tip_height < ancestor_height
            || old_tip_height.saturating_sub(ancestor_height) > CONSENSUS_FINALITY_DEPTH
        {
            return Err(StoreError::Decode(
                "staged reorg lies outside the canonical non-final suffix",
            ));
        }

        // A compact-sync parent may carry a fixed-size local marker whose
        // authority terminal lives later in the old canonical suffix. A
        // successful reorg can remove that terminal while retaining the
        // marker at or below the common ancestor. Collect every such marker in
        // the bounded reorg window now, then retarget it to the fully verified
        // terminal at the replacement tip after that terminal is installed.
        // This also repairs markers left pointing at an authority removed by
        // an earlier v1.0.0 reorg.
        let marker_rebindings = if replacement.is_empty() {
            Vec::new()
        } else {
            let terminal_tbl = txn.open_table(Some(T_HISTORY_STEP_TERMINALS))?;
            let header_tbl = txn.open_table(Some(T_HEADERS))?;
            let first_height = ancestor_height.saturating_sub(CONSENSUS_FINALITY_DEPTH);
            let mut rebindings = Vec::new();
            for height in first_height..=ancestor_height {
                let key = u64_key(height);
                let terminal: Option<Vec<u8>> = txn.get(&terminal_tbl, &key)?;
                let Some(terminal) = terminal else {
                    continue;
                };
                if terminal.len() != RECURSIVE_SUFFIX_MARKER_BYTES {
                    continue;
                }
                let header_raw: Option<Vec<u8>> = txn.get(&header_tbl, &key)?;
                let header =
                    header_raw
                        .as_deref()
                        .and_then(decode_header)
                        .ok_or(StoreError::Decode(
                            "recursive suffix marker header is missing during reorg",
                        ))?;
                let semantic_id = crate::block_header::semantic_header_id(&header);
                let (_, _, class_slot) = history_step_terminal_metadata(&terminal).ok_or(
                    StoreError::Decode("recursive suffix marker metadata is malformed"),
                )?;
                if recursive_suffix_marker_authority(
                    &terminal,
                    height,
                    semantic_id,
                    Some(class_slot),
                )
                .is_none()
                {
                    return Err(StoreError::Decode(
                        "recursive suffix marker is malformed during reorg",
                    ));
                }
                rebindings.push((
                    height,
                    encode_recursive_suffix_marker(
                        &header,
                        class_slot,
                        final_header.height,
                        *final_hash,
                    )?,
                ));
            }
            rebindings
        };

        if replacement.is_empty() && final_header.height != 0 {
            let recent_tbl = txn.open_table(Some(T_RECENT_BLOCKS))?;
            let terminal_tbl = txn.open_table(Some(T_HISTORY_STEP_TERMINALS))?;
            let key = u64_key(final_header.height);
            let block_len: Option<ObjectLength> = txn.get(&recent_tbl, &key)?;
            let terminal_len: Option<ObjectLength> = txn.get(&terminal_tbl, &key)?;
            let retained = match (block_len, terminal_len) {
                (Some(ObjectLength(block_len)), Some(ObjectLength(terminal_len))) => {
                    crate::AcceptedBlockBundle::validate_declared_lengths(
                        block_len as u64,
                        terminal_len as u64,
                    )
                    .is_ok()
                }
                _ => false,
            };
            if !retained {
                return Err(StoreError::Decode(
                    "reorg ancestor is missing its accepted bundle",
                ));
            }
        }

        // Install the final post-reorg exact segments once.  Dirty tracking is
        // deliberately retained across every staged block, so this is the
        // union of rollback and replacement writes.
        let seg_tbl = txn.open_table(Some(T_SEGMENTS))?;
        let summary_tbl = txn.open_table(Some(T_SEGMENT_SUMMARIES))?;
        for ((seg_id, eff_log, cols), (_, live_count, exact_root)) in final_dirty_segments
            .iter()
            .zip(final_dirty_segment_summaries)
        {
            let key = seg_id.to_le_bytes();
            match cols {
                None => {
                    let _ = txn.del(&seg_tbl, key, None);
                    let _ = txn.del(&summary_tbl, key, None);
                }
                Some(cols) => {
                    if segment_columns_empty(cols) {
                        return Err(StoreError::Decode("non-delete reorg segment is empty"));
                    }
                    txn.put(
                        &seg_tbl,
                        key,
                        encode_segment(cols, *eff_log),
                        WriteFlags::empty(),
                    )?;
                    txn.put(
                        &summary_tbl,
                        key,
                        encode_segment_summary(*live_count, exact_root),
                        WriteFlags::empty(),
                    )?;
                }
            }
        }
        let domain_segments = if final_header.log_slots > crate::consensus::params::LOG_SEGMENT_SIZE
        {
            1usize
                .checked_shl(final_header.log_slots - crate::consensus::params::LOG_SEGMENT_SIZE)
                .ok_or(StoreError::Decode(
                    "reorg final log_slots exceeds segment domain",
                ))?
        } else {
            1
        };
        let out_of_domain_keys: Vec<Vec<u8>> = {
            let mut cursor = txn.cursor(&seg_tbl)?;
            let mut keys = Vec::new();
            let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
            while let Some((key, _)) = item {
                if key.len() != 2 {
                    return Err(StoreError::Decode("invalid segment key"));
                }
                if u16::from_le_bytes([key[0], key[1]]) as usize >= domain_segments {
                    keys.push(key);
                }
                item = cursor.next()?;
            }
            keys
        };
        for key in out_of_domain_keys {
            txn.del(&seg_tbl, &key, None)?;
            txn.del(&summary_tbl, &key, None)?;
        }

        // Remove every old canonical height record above the ancestor before
        // installing the replacement.  Hash and tx indexes are cleaned in the
        // same transaction, so shorter replacement branches cannot expose a
        // stale suffix after restart.
        let hdr_tbl = txn.open_table(Some(T_HEADERS))?;
        let mut old_headers = Vec::with_capacity(
            usize::try_from(old_tip_height.saturating_sub(ancestor_height))
                .expect("finality-bounded reorg depth fits usize"),
        );
        for height in ancestor_height.saturating_add(1)..=old_tip_height {
            let raw: Option<Vec<u8>> = txn.get(&hdr_tbl, &u64_key(height))?;
            let header = raw
                .as_deref()
                .and_then(decode_header)
                .ok_or(StoreError::Decode("invalid header during reorg"))?;
            old_headers.push((height, crate::hash_block_header(&header)));
        }
        let h2h_tbl = txn.open_table(Some(T_HASH_TO_HEIGHT))?;
        for (height, hash) in &old_headers {
            txn.del(&hdr_tbl, u64_key(*height), None)?;
            let _ = txn.del(&h2h_tbl, hash.as_slice(), None);
        }

        // Preserve displaced, previously canonical bodies as exact objects
        // before their height-indexed rows are replaced. They remain useful
        // for another peer's in-flight plan and are bounded by object-cache
        // retention rather than by fork choice.
        let old_recent_tbl = txn.open_table(Some(T_RECENT_BLOCKS))?;
        for (height, hash) in &old_headers {
            let bytes: Option<Vec<u8>> = txn.get(&old_recent_tbl, &u64_key(*height))?;
            if let Some(bytes) = bytes {
                archive_block_body_object(&txn, *height, *hash, &bytes)?;
            }
        }

        macro_rules! truncate_reorg_suffix {
            ($name:expr) => {{
                let table = txn.open_table(Some($name))?;
                for height in ancestor_height.saturating_add(1)..=old_tip_height {
                    let _ = txn.del(&table, u64_key(height), None)?;
                }
            }};
        }
        for table_name in [
            T_HEADER_ANCHORS,
            T_CHAIN_WORK,
            T_UNDO_LOGS,
            T_RECENT_BLOCKS,
            T_HISTORY_STEP_TERMINALS,
        ] {
            truncate_reorg_suffix!(table_name);
        }
        rewind_retained_payload_prune_watermark(&txn, ancestor_height)?;

        let tx_idx_tbl = txn.open_table(Some(T_TX_INDEX))?;
        for tx_hash in reverted_tx_hashes {
            let raw: Option<Vec<u8>> = txn.get(&tx_idx_tbl, tx_hash.0.as_slice())?;
            if raw
                .as_deref()
                .and_then(decode_tx_index_value)
                .is_some_and(|(height, _)| height > ancestor_height)
            {
                txn.del(&tx_idx_tbl, tx_hash.0.as_slice(), None)?;
            }
        }

        let anchor_tbl = txn.open_table(Some(T_HEADER_ANCHORS))?;
        let work_tbl = txn.open_table(Some(T_CHAIN_WORK))?;
        let undo_tbl = txn.open_table(Some(T_UNDO_LOGS))?;
        let recent_tbl = txn.open_table(Some(T_RECENT_BLOCKS))?;
        let terminal_tbl = txn.open_table(Some(T_HISTORY_STEP_TERMINALS))?;
        for (accepted, staged) in replacement_objects.iter().copied().zip(replacement) {
            let block = crate::Block::from_bytes(accepted.block_bytes())
                .map_err(|_| StoreError::Decode("staged reorg block is malformed"))?;
            let height_key = u64_key(staged.header.height);
            txn.put(
                &hdr_tbl,
                height_key,
                encode_header(&staged.header),
                WriteFlags::empty(),
            )?;
            txn.put(
                &h2h_tbl,
                staged.hash.as_slice(),
                height_key,
                WriteFlags::empty(),
            )?;
            txn.put(
                &work_tbl,
                height_key,
                encode_chain_work(&staged.cumulative_chainwork),
                WriteFlags::empty(),
            )?;

            let previous_raw: Option<Vec<u8>> =
                txn.get(&anchor_tbl, &u64_key(staged.header.height - 1))?;
            let previous = previous_raw
                .as_deref()
                .and_then(decode_header_chain_anchor)
                .ok_or(StoreError::Decode("missing staged reorg parent anchor"))?;
            let anchor =
                extend_header_chain_anchor(&previous, &staged.header, staged.cumulative_chainwork)?;
            if anchor.block_id != staged.hash {
                return Err(StoreError::Decode("staged reorg anchor mismatch"));
            }
            txn.put(
                &anchor_tbl,
                height_key,
                encode_header_chain_anchor(&anchor),
                WriteFlags::empty(),
            )?;
            txn.put(
                &undo_tbl,
                height_key,
                encode_undo_log(&staged.undo_log),
                WriteFlags::empty(),
            )?;
            txn.put(
                &recent_tbl,
                height_key,
                accepted.block_bytes(),
                WriteFlags::empty(),
            )?;
            archive_block_body_object(
                &txn,
                staged.header.height,
                staged.hash,
                accepted.block_bytes(),
            )?;
            if staged.header.height != 0 {
                let expected_class = block
                    .transactions
                    .len()
                    .checked_sub(1)
                    .and_then(history_step_class_slot)
                    .ok_or(StoreError::Decode(
                        "staged reorg transaction count has no canonical HistoryStep tier",
                    ))?;
                let terminal_bytes: Cow<'_, [u8]> =
                    if let Some(terminal) = accepted.complete_terminal() {
                        if !history_step_terminal_matches_class(
                            terminal,
                            staged.header.height,
                            crate::block_header::semantic_header_id(&staged.header),
                            expected_class,
                        ) {
                            return Err(StoreError::Decode(
                                "staged reorg terminal class does not match its block",
                            ));
                        }
                        Cow::Borrowed(terminal)
                    } else {
                        let (authority_tip_height, authority_tip_hash) = accepted
                            .recursive_authority()
                            .ok_or(StoreError::Decode("staged reorg authorization is missing"))?;
                        Cow::Owned(
                            encode_recursive_suffix_marker(
                                &staged.header,
                                expected_class,
                                authority_tip_height,
                                authority_tip_hash,
                            )?
                            .to_vec(),
                        )
                    };
                txn.put(
                    &terminal_tbl,
                    height_key,
                    terminal_bytes.as_ref(),
                    WriteFlags::empty(),
                )?;
                if accepted.complete_terminal().is_some() {
                    archive_history_step_proof_object(&txn, terminal_bytes.as_ref())?;
                }
            }
            let logical_txids = crate::block::try_compute_logical_txids(&block.transactions)
                .map_err(|_| StoreError::Decode("staged logical tx stream is malformed"))?;
            for (position, tx_hash) in logical_txids.iter().enumerate() {
                txn.put(
                    &tx_idx_tbl,
                    tx_hash.0,
                    encode_tx_index_value(staged.header.height, position as u32),
                    WriteFlags::empty(),
                )?;
            }
        }

        // The replacement tip's complete terminal is now present in this
        // transaction. Rebind surviving compact markers to that canonical
        // authority before checking the first replacement's parent. The
        // operation is atomic with deleting the old suffix and installing the
        // new one, so a crash exposes either the old valid authority graph or
        // the new valid authority graph.
        for (height, marker) in marker_rebindings {
            txn.put(&terminal_tbl, u64_key(height), marker, WriteFlags::empty())?;
        }
        // Validate every parent only after all replacement objects have been
        // installed in this uncommitted transaction. Intermediate markers in
        // a one-terminal reorg point at the replacement tip, so their durable
        // authority becomes visible only when that final terminal row exists.
        for staged in replacement {
            validate_history_step_parent_boundary_in_rw_txn(&txn, &staged.header)?;
        }
        if !replacement.is_empty() {
            let retention = txn.open_table(Some(T_RETENTION_META))?;
            let _ = txn.del(&retention, KEY_VERIFIED_SUFFIX_AUTHORITY, None);
        }

        txn.put(
            &tip_tbl,
            KEY_TIP,
            encode_chain_tip(final_header.height, final_hash),
            WriteFlags::empty(),
        )?;
        let consensus_tbl = txn.open_table(Some(T_CONSENSUS_META))?;
        txn.put(
            &consensus_tbl,
            KEY_CONSENSUS_META,
            encode_consensus_meta(consensus_meta),
            WriteFlags::empty(),
        )?;
        let meta_tbl = txn.open_table(Some(T_STATE_META))?;
        txn.put(
            &meta_tbl,
            KEY_META,
            encode_state_meta(
                final_header.log_slots,
                final_header.active_slot_count,
                final_header.alloc_counter,
                circulating_supply_micronoid,
            ),
            WriteFlags::empty(),
        )?;
        // Rebuild the owner accelerator from the exact post-reorg segment
        // table. Clear is an MDBX operation (no all-key Vec), and records are
        // written as each single decoded segment is visited (no owner map).
        let owner_tbl = txn.open_table(Some(T_OWNER_INDEX))?;
        txn.clear_table(&owner_tbl)?;
        let mut cursor = txn.cursor(&seg_tbl)?;
        let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
        while let Some((key, raw)) = item {
            if key.len() != 2 {
                return Err(StoreError::Decode(
                    "invalid segment key during reorg owner rebuild",
                ));
            }
            let segment_id = u16::from_le_bytes([key[0], key[1]]);
            let (effective_log, columns) = decode_segment(&raw).ok_or(StoreError::Decode(
                "invalid segment during reorg owner rebuild",
            ))?;
            visit_live_owner_records(
                segment_id,
                effective_log,
                &columns,
                |owner, slot_index, packed_value| {
                    txn.put(
                        &owner_tbl,
                        owner_index_key(&owner, slot_index),
                        encode_owner_index_value(packed_value),
                        WriteFlags::empty(),
                    )?;
                    Ok(())
                },
            )?;
            item = cursor.next()?;
        }
        txn.commit()?;
        if let Err(_error) = self.prune_after_commit(final_header.height) {
            // The accepted branch is already durable.  Pruning is retryable
            // maintenance and must not masquerade as a failed reorg.
        }
        Ok(())
    }

    fn prune_after_commit(&self, current_height: u64) -> Result<(), StoreError> {
        // Retained payload maintenance owns one short transaction whose work
        // is bounded simultaneously by numeric heights, retired bytes, and
        // delete count. The watermark and deletions commit atomically.
        let txn = self.db.begin_rw_txn()?;
        prune_retained_payloads_bounded(&txn, current_height)?;
        prune_history_step_proof_objects(&txn, current_height)?;
        let object_retention_floor = match self
            .block_body_object_retention_floor
            .load(std::sync::atomic::Ordering::Acquire)
        {
            0 => None,
            floor => Some(floor),
        };
        prune_block_body_objects(&txn, current_height, object_retention_floor)?;
        txn.commit()?;

        // --- Prune undo_logs older than UNDO_RETENTION_DEPTH ---
        if current_height > UNDO_RETENTION_DEPTH {
            let txn = self.db.begin_rw_txn()?;
            let undo_tbl = txn.open_table(Some(T_UNDO_LOGS))?;
            let cutoff = current_height - UNDO_RETENTION_DEPTH;
            delete_height_keys_at_or_below(&txn, &undo_tbl, cutoff)?;
            txn.commit()?;
        }
        Ok(())
    }

    /// Atomically clear every chain table.
    ///
    /// The on-disk format has one canonical epoch. A database that cannot be
    /// restored must never retain headers, bundles, indexes, or old state while
    /// installing a fresh genesis state; that would create a mixed-epoch store.
    pub fn clear_all(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tables = [
            T_HEADERS,
            T_HEADER_ANCHORS,
            T_HASH_TO_HEIGHT,
            T_CHAIN_TIP,
            T_CONSENSUS_META,
            T_CHAIN_WORK,
            T_UNDO_LOGS,
            T_SEGMENTS,
            T_SEGMENT_SUMMARIES,
            T_STATE_META,
            T_RECENT_BLOCKS,
            T_BLOCK_BODY_OBJECTS,
            T_TX_INDEX,
            T_HISTORY_STEP_TERMINALS,
            T_HISTORY_STEP_PROOF_OBJECTS,
            T_OWNER_INDEX,
            T_RETENTION_META,
        ];
        for name in tables {
            let tbl = txn.open_table(Some(name))?;
            txn.clear_table(&tbl)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Returns `true` if the store has never had a block committed (fresh database).
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.get_chain_tip()?.is_none())
    }
}

// ---------------------------------------------------------------------------
// BlockStore trait implementation
// ---------------------------------------------------------------------------

impl crate::storage::BlockStore for MdbxStore {
    fn best_tip(&self) -> Option<(u64, [u8; 32])> {
        self.get_chain_tip().ok().flatten()
    }

    fn get_header(
        &self,
        height: u64,
    ) -> Result<Option<crate::block_header::BlockHeader>, StoreError> {
        MdbxStore::get_header(self, height)
    }

    fn get_header_by_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<crate::block_header::BlockHeader>, StoreError> {
        MdbxStore::get_header_by_hash(self, hash)
    }

    fn get_recent_block(&self, height: u64) -> Result<Option<Vec<u8>>, StoreError> {
        MdbxStore::get_recent_block(self, height)
    }

    fn get_tx_index(&self, hash: &[u8; 32]) -> Result<Option<(u64, u32)>, StoreError> {
        MdbxStore::get_tx_index(self, hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fri_state::SlotValue;
    use crate::state::ChainState;
    use crate::storage::FinalizedCheckpoint;
    use noid_core::Block128;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, PAGED_SPEND_END_BIT,
        PAGED_SPEND_START_BIT, TX_INPUTS, TX_OUTPUTS,
    };

    fn coinbase(tag: u8) -> Transaction {
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: u32::from(tag),
            amount: 1,
            owner: Address([tag; 32]),
        };
        Transaction::new(TxBody {
            epoch_anchor: [tag; 32],
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        })
    }

    fn terminal(height: u64, hash: [u8; 32], current_slot: u8) -> Vec<u8> {
        let class_id = current_slot * crate::history_step::HISTORY_STEP_TIER_SLOT_COUNT;
        let mut bytes =
            crate::history_step::HistoryStepTerminalMetadata::new(height, hash, class_id)
                .unwrap()
                .encode_prefix()
                .to_vec();
        bytes.push(1); // non-empty recursive envelope
        bytes
    }

    fn block(parent: &BlockHeader, height: u64, tag: u8) -> crate::Block {
        let transaction = coinbase(tag);
        let mut header = *parent;
        header.height = height;
        header.prev_block_hash = crate::hash_block_header(parent);
        header.timestamp = parent.timestamp.saturating_add(1);
        header.nonce = u128::from(tag).saturating_add(1);
        header.tx_root = crate::compute_tx_root(std::slice::from_ref(&transaction));
        crate::Block {
            header,
            transactions: vec![transaction],
        }
    }

    fn two_page_group(tag: u8) -> [Transaction; 2] {
        let owner = Address([tag; 32]);
        let mut first_inputs = [TxInput::dummy(); TX_INPUTS];
        for (index, input) in first_inputs.iter_mut().enumerate() {
            *input = TxInput {
                slot_index: 100 + index as u32,
                amount: 2,
                creation_id: index as u64 + 1,
            };
        }
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 1_000,
            amount: 19,
            owner: Address([tag.wrapping_add(1); 32]),
        };
        let first = Transaction::new(TxBody {
            epoch_anchor: [0xA5; 32],
            fee: 1,
            input_owner: owner,
            inputs: first_inputs,
            outputs,
            validity_bitmap: ((1u16 << TX_INPUTS) - 1)
                | output_bitmap_bit(0)
                | PAGED_SPEND_START_BIT,
            is_coinbase: false,
        });
        let mut second_inputs = [TxInput::dummy(); TX_INPUTS];
        second_inputs[0] = TxInput {
            slot_index: 108,
            amount: 4,
            creation_id: 9,
        };
        let second = Transaction::new(TxBody {
            epoch_anchor: [0xA5; 32],
            fee: 0,
            input_owner: owner,
            inputs: second_inputs,
            outputs: [TxOutput::dummy(); TX_OUTPUTS],
            validity_bitmap: 1 | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        });
        [first, second]
    }

    fn commit_genesis(store: &MdbxStore) -> (BlockHeader, ConsensusMeta) {
        let genesis = crate::consensus::genesis::genesis_header();
        let hash = crate::hash_block_header(&genesis);
        let meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: hash,
            cumulative_chainwork: crate::block_work(&genesis.difficulty_target),
            finalized: FinalizedCheckpoint { height: 0, hash },
        };
        store
            .commit_block(
                &genesis,
                &hash,
                &BlockUndoLog::empty(0, genesis.log_slots),
                &[],
                &[],
                &[],
                &[],
                None,
                0,
                &meta,
                false,
            )
            .unwrap();
        (genesis, meta)
    }

    fn commit_stateful_test_genesis(store: &MdbxStore) -> (ChainState, BlockHeader, [u8; 32]) {
        let slot = SlotValue::from_parts(11, 1, Block128::from(0x22u128), Block128::from(0x33u128));
        let state = ChainState::from_sparse_utxos(8, &[(7, slot)], 1).unwrap();
        let mut header = crate::consensus::genesis::genesis_header();
        header.state_root = state.cached_state_root();
        header.log_slots = 8;
        header.active_slot_count = 1;
        header.alloc_counter = 1;
        let hash = crate::hash_block_header(&header);
        let meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: hash,
            cumulative_chainwork: crate::block_work(&header.difficulty_target),
            finalized: FinalizedCheckpoint { height: 0, hash },
        };
        let columns = state.state.try_get_segment_columns(0).unwrap();
        let exact_root = state.cached_exact_segment_root(0).unwrap();
        store
            .commit_block(
                &header,
                &hash,
                &BlockUndoLog::empty(0, header.log_slots),
                &[(0, 8, Some(columns))],
                &[(0, 1, exact_root)],
                &[],
                &[],
                None,
                state.circulating_supply_micronoid,
                &meta,
                true,
            )
            .unwrap();
        assert_eq!(
            store.get_circulating_supply().unwrap(),
            Some(state.circulating_supply_micronoid)
        );
        (state, header, hash)
    }

    #[test]
    fn canonical_header_batch_uses_one_bounded_contiguous_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, _) = commit_genesis(&store);

        assert_eq!(store.get_headers(0, 512).unwrap(), vec![genesis]);
        assert!(store.get_headers(1, 512).unwrap().is_empty());
        assert!(store.get_headers(0, 0).unwrap().is_empty());
        assert!(store.get_headers(u64::MAX, 2).unwrap().is_empty());
    }

    #[test]
    fn bounded_owner_presence_query_distinguishes_funded_and_empty_addresses() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        commit_stateful_test_genesis(&store);
        let funded = owner_key_from_fields(Block128::from(0x22u128), Block128::from(0x33u128));

        assert!(store.has_verified_utxo_by_owner(&funded).unwrap());
        assert!(!store.has_verified_utxo_by_owner(&[0xA5; 32]).unwrap());
        assert_eq!(
            store
                .get_verified_utxos_by_owner(&funded)
                .unwrap()
                .utxos
                .len(),
            1
        );
    }

    #[test]
    fn sparse_disk_carrier_defeats_one_utxo_per_segment_amplification() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, _) = commit_genesis(&store);
        assert_eq!(genesis.log_slots, 24);

        // This is the hostile placement pattern: one live slot in every one
        // of the 256 genesis-domain segments. Only one dense working segment
        // is needed to produce the canonical carrier reused by the fixture.
        let mut columns = SegmentColumns::new_zero(1usize << 16);
        let slot = SlotValue::from_parts(1, 1, Block128::from(2u128), Block128::from(3u128));
        columns.values[0] = slot.value;
        columns.owners_hi[0] = slot.owner_hi;
        columns.owners_lo[0] = slot.owner_lo;
        let encoded = encode_segment(&columns, 16);
        assert_eq!(encoded.len(), 59);

        let txn = store.db.begin_rw_txn().unwrap();
        let segments = txn.open_table(Some(T_SEGMENTS)).unwrap();
        for segment_id in 0u16..=255 {
            txn.put(
                &segments,
                segment_id.to_le_bytes(),
                encoded.as_slice(),
                WriteFlags::empty(),
            )
            .unwrap();
        }
        let state_meta = txn.open_table(Some(T_STATE_META)).unwrap();
        txn.put(
            &state_meta,
            KEY_META,
            encode_state_meta(24, 256, 256, 0),
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();

        assert_eq!(store.encoded_state_bytes().unwrap(), 256 * 59);
        assert!(store.encoded_state_bytes().unwrap() < 16 * 1024);
        assert_eq!(256u64 * 3 * (1u64 << 16) * 16, 768 * 1024 * 1024);
    }

    #[test]
    fn missing_restart_summaries_are_rebuilt_once_from_dense_state() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (state, header, _) = commit_stateful_test_genesis(&store);
        assert_eq!(store.segment_summaries().unwrap().len(), 1);

        let txn = store.db.begin_rw_txn().unwrap();
        let table = txn.open_table(Some(T_SEGMENT_SUMMARIES)).unwrap();
        txn.clear_table(&table).unwrap();
        txn.commit().unwrap();
        assert!(store.segment_summaries().unwrap().is_empty());

        let restored = crate::storage::mdbx_context::MdbxChainContext::load_streamed_chain_state(
            &store,
            header.log_slots,
            header.active_slot_count,
            header.alloc_counter,
            store.get_circulating_supply().unwrap(),
            header.height,
            header.state_root,
        )
        .unwrap();
        assert_eq!(restored.cached_state_root(), state.cached_state_root());
        assert_eq!(
            restored.circulating_supply_micronoid,
            state.circulating_supply_micronoid
        );
        assert_eq!(store.segment_summaries().unwrap().len(), 1);
    }

    #[test]
    fn legacy_state_metadata_upgrades_supply_during_existing_dense_verification() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (state, header, _) = commit_stateful_test_genesis(&store);

        let txn = store.db.begin_rw_txn().unwrap();
        let table = txn.open_table(Some(T_STATE_META)).unwrap();
        let encoded: Vec<u8> = txn.get(&table, KEY_META).unwrap().unwrap();
        txn.put(
            &table,
            KEY_META,
            &encoded[..crate::storage::serial::ENCODED_STATE_META_V1_BYTES],
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();
        assert_eq!(store.get_circulating_supply().unwrap(), None);

        let restored = crate::storage::mdbx_context::MdbxChainContext::load_streamed_chain_state(
            &store,
            header.log_slots,
            header.active_slot_count,
            header.alloc_counter,
            store.get_circulating_supply().unwrap(),
            header.height,
            header.state_root,
        )
        .unwrap();

        assert_eq!(
            restored.circulating_supply_micronoid,
            state.circulating_supply_micronoid
        );
        assert_eq!(
            store.get_circulating_supply().unwrap(),
            Some(state.circulating_supply_micronoid)
        );
    }

    #[test]
    fn compact_restart_defers_raw_segment_check_until_hydration() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (_, header, _) = commit_stateful_test_genesis(&store);

        let (_, mut tampered) = store.get_segment(0).unwrap().unwrap();
        tampered.values[7] = noid_tx::pack_amount_creation_id(12, 1);
        let txn = store.db.begin_rw_txn().unwrap();
        let table = txn.open_table(Some(T_SEGMENTS)).unwrap();
        txn.put(
            &table,
            0u16.to_le_bytes(),
            encode_segment(&tampered, 8),
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();

        // Startup consumes only the header-authenticated compact roots, so a
        // cold segment does not impose dense work on every restart.
        let mut restored =
            crate::storage::mdbx_context::MdbxChainContext::load_streamed_chain_state(
                &store,
                header.log_slots,
                header.active_slot_count,
                header.alloc_counter,
                store.get_circulating_supply().unwrap(),
                header.height,
                header.state_root,
            )
            .unwrap();
        assert!(restored.state.is_evicted(0));

        // The first actual access verifies the raw payload against that exact
        // root and rejects the modified value before it can enter hot state.
        let (_, raw) = store.get_segment(0).unwrap().unwrap();
        assert!(restored.restore_evicted_segment(0, raw).is_err());
    }

    fn put_test_header_row(store: &MdbxStore, header: &BlockHeader) {
        let hash = crate::hash_block_header(header);
        let txn = store.db.begin_rw_txn().unwrap();
        let headers = txn.open_table(Some(T_HEADERS)).unwrap();
        let hash_to_height = txn.open_table(Some(T_HASH_TO_HEIGHT)).unwrap();
        txn.put(
            &headers,
            u64_key(header.height),
            encode_header(header),
            WriteFlags::empty(),
        )
        .unwrap();
        txn.put(
            &hash_to_height,
            hash,
            u64_key(header.height),
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();
    }

    #[derive(Clone)]
    struct TestSnapshotHeaderSource {
        base: VerifiedHeaderBatchRecord,
        records: Vec<VerifiedHeaderBatchRecord>,
        recent: Vec<BlockHeader>,
        next: usize,
        fail_at: Option<usize>,
    }

    impl SnapshotHeaderInstallSource for TestSnapshotHeaderSource {
        fn base_record(&self) -> VerifiedHeaderBatchRecord {
            self.base
        }

        fn target_record(&self) -> VerifiedHeaderBatchRecord {
            *self.records.last().expect("snapshot target record")
        }

        fn recent_headers(&self) -> &[BlockHeader] {
            &self.recent
        }

        fn next_record(&mut self) -> Result<Option<VerifiedHeaderBatchRecord>, String> {
            if self.fail_at == Some(self.next) {
                return Err("deliberate staged header read failure".into());
            }
            let record = self.records.get(self.next).copied();
            self.next += usize::from(record.is_some());
            Ok(record)
        }
    }

    fn snapshot_header_source(
        genesis: BlockHeader,
        genesis_meta: &ConsensusMeta,
        count: u64,
    ) -> (TestSnapshotHeaderSource, Vec<crate::Block>) {
        let base = VerifiedHeaderBatchRecord {
            header: genesis,
            hash: crate::hash_block_header(&genesis),
            cumulative_chainwork: genesis_meta.cumulative_chainwork,
        };
        let mut parent = genesis;
        let mut work = base.cumulative_chainwork;
        let mut records = Vec::new();
        let mut blocks = Vec::new();
        let mut recent = vec![genesis];
        for height in 1..=count {
            let candidate = block(&parent, height, height as u8);
            let hash = crate::hash_block_header(&candidate.header);
            work = crate::add_work(
                &work,
                &crate::block_work(&candidate.header.difficulty_target),
            );
            records.push(VerifiedHeaderBatchRecord {
                header: candidate.header,
                hash,
                cumulative_chainwork: work,
            });
            recent.push(candidate.header);
            parent = candidate.header;
            blocks.push(candidate);
        }
        (
            TestSnapshotHeaderSource {
                base,
                records,
                recent,
                next: 0,
                fail_at: None,
            },
            blocks,
        )
    }

    fn finalized_empty_snapshot(
        staging_root: &Path,
        target: BlockHeader,
    ) -> FinalizedSnapshotStaging {
        let effective_log = target
            .log_slots
            .min(crate::consensus::params::LOG_SEGMENT_SIZE) as u8;
        let metadata = crate::storage::AuthenticatedSnapshotMetadata::from_authenticated_header(
            target,
            crate::hash_block_header(&target),
            effective_log,
        )
        .unwrap();
        crate::storage::SnapshotStagingSession::new(staging_root, metadata, Vec::new())
            .unwrap()
            .finalize()
            .unwrap()
    }

    fn target_meta(source: &TestSnapshotHeaderSource) -> ConsensusMeta {
        let target = source.target_record();
        ConsensusMeta {
            tip_height: target.header.height,
            tip_hash: target.hash,
            cumulative_chainwork: target.cumulative_chainwork,
            finalized: FinalizedCheckpoint {
                height: target.header.height,
                hash: target.hash,
            },
        }
    }

    fn commit_accepted_test_block(
        store: &MdbxStore,
        block: &crate::Block,
        parent_meta: &ConsensusMeta,
    ) -> ConsensusMeta {
        let hash = crate::hash_block_header(&block.header);
        let bundle = crate::AcceptedBlockBundle::try_from_parts(
            block.to_bytes(),
            terminal(
                block.header.height,
                crate::block_header::semantic_header_id(&block.header),
                0,
            ),
        )
        .unwrap();
        let tx_hashes = crate::block::try_compute_logical_txids(&block.transactions).unwrap();
        let mut undo = BlockUndoLog::empty(block.header.height, block.header.log_slots);
        undo.tx_hashes.clone_from(&tx_hashes);
        let meta = ConsensusMeta {
            tip_height: block.header.height,
            tip_hash: hash,
            cumulative_chainwork: crate::add_work(
                &parent_meta.cumulative_chainwork,
                &crate::block_work(&block.header.difficulty_target),
            ),
            finalized: parent_meta.finalized,
        };
        store
            .commit_block(
                &block.header,
                &hash,
                &undo,
                &[],
                &[],
                &tx_hashes,
                &[],
                Some(AcceptedBlockCommit::Complete(&bundle)),
                0,
                &meta,
                false,
            )
            .unwrap();
        meta
    }

    fn identity_only_undo(block: &crate::Block) -> BlockUndoLog {
        let mut undo = BlockUndoLog::empty(block.header.height, block.header.log_slots);
        undo.tx_hashes = crate::block::try_compute_logical_txids(&block.transactions).unwrap();
        undo
    }

    #[test]
    fn non_genesis_commit_requires_and_persists_one_complete_bundle() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, genesis_meta) = commit_genesis(&store);
        let block = block(&genesis, 1, 7);
        let hash = crate::hash_block_header(&block.header);
        let bundle = crate::AcceptedBlockBundle::try_from_parts(
            block.to_bytes(),
            terminal(1, crate::block_header::semantic_header_id(&block.header), 0),
        )
        .unwrap();
        let tx_hashes = [block.transactions[0].txid()];
        let meta = ConsensusMeta {
            tip_height: 1,
            tip_hash: hash,
            cumulative_chainwork: crate::add_work(
                &genesis_meta.cumulative_chainwork,
                &crate::block_work(&block.header.difficulty_target),
            ),
            finalized: genesis_meta.finalized,
        };

        store
            .commit_block(
                &block.header,
                &hash,
                &identity_only_undo(&block),
                &[],
                &[],
                &tx_hashes,
                &[],
                Some(AcceptedBlockCommit::Complete(&bundle)),
                0,
                &meta,
                false,
            )
            .unwrap();

        assert_eq!(
            store.get_recent_accepted_block_bundle_bounded(1).unwrap(),
            Some(bundle.encode())
        );
        assert_eq!(
            store.get_block_body_object(1, hash).unwrap(),
            Some(block.to_bytes())
        );
        assert!(store.has_history_step_terminal_at(1, hash).unwrap());
        let semantic_id = crate::block_header::semantic_header_id(&block.header);
        assert_eq!(
            store
                .get_history_step_proof_object(1, semantic_id, 0)
                .unwrap()
                .as_deref(),
            Some(bundle.history_step_terminal_bytes())
        );
        assert_eq!(store.get_chain_tip().unwrap(), Some((1, hash)));

        // Canonical height rows may later become recursive markers or be
        // displaced by a reorg. The independent recent proof object remains
        // available by its semantic identity.
        let txn = store.db.begin_rw_txn().unwrap();
        let terminals = txn.open_table(Some(T_HISTORY_STEP_TERMINALS)).unwrap();
        txn.del(&terminals, u64_key(1), None).unwrap();
        txn.commit().unwrap();
        assert_eq!(store.get_history_step_terminal_at(1, hash).unwrap(), None);
        assert_eq!(
            store
                .get_any_history_step_proof_object(1, semantic_id)
                .unwrap()
                .as_deref(),
            Some(bundle.history_step_terminal_bytes())
        );

        // Snapshot export must use the same independent object store. A
        // compact canonical marker (or displaced height row) cannot make an
        // otherwise complete boundary falsely unavailable.
        let exports = tempfile::tempdir().unwrap();
        let generation =
            crate::storage::export_snapshot_generation(&store, exports.path(), 1, None).unwrap();
        assert_eq!(
            generation.read_boundary_terminal().unwrap(),
            bundle.history_step_terminal_bytes()
        );
    }

    #[test]
    fn active_snapshot_floor_pins_exact_block_objects_beyond_normal_retention() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, _) = commit_genesis(&store);
        let body = block(&genesis, 2, 0x42);
        let hash = crate::hash_block_header(&body.header);
        let encoded = body.to_bytes();

        let txn = store.db.begin_rw_txn().unwrap();
        archive_block_body_object(&txn, 2, hash, &encoded).unwrap();
        prune_block_body_objects(&txn, 200, Some(1)).unwrap();
        txn.commit().unwrap();
        assert_eq!(store.get_block_body_object(2, hash).unwrap(), Some(encoded));

        let txn = store.db.begin_rw_txn().unwrap();
        prune_block_body_objects(&txn, 200, None).unwrap();
        txn.commit().unwrap();
        assert!(store.get_block_body_object(2, hash).unwrap().is_none());
    }

    #[test]
    fn proof_object_cache_rejects_recursive_markers() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, _) = commit_genesis(&store);
        let candidate = block(&genesis, 1, 7);
        let marker = encode_recursive_suffix_marker(&candidate.header, 0, 2, [0xA5; 32]).unwrap();

        let txn = store.db.begin_rw_txn().unwrap();
        assert!(matches!(
            archive_history_step_proof_object(&txn, &marker),
            Err(StoreError::Decode(
                "recursive suffix marker cannot enter the proof-object cache"
            ))
        ));
    }

    #[test]
    fn verified_boundary_cache_rebinds_to_the_canonical_finalized_header() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, genesis_meta) = commit_genesis(&store);
        let candidate = block(&genesis, 1, 7);
        let mut meta = commit_accepted_test_block(&store, &candidate, &genesis_meta);
        let block_hash = crate::hash_block_header(&candidate.header);
        meta.finalized = FinalizedCheckpoint {
            height: 1,
            hash: block_hash,
        };
        store.put_consensus_meta(&meta).unwrap();

        let semantic_id = crate::block_header::semantic_header_id(&candidate.header);
        let terminal_bytes = terminal(1, semantic_id, 0);
        let txn = store.db.begin_rw_txn().unwrap();
        let proofs = txn.open_table(Some(T_HISTORY_STEP_PROOF_OBJECTS)).unwrap();
        txn.del(
            &proofs,
            history_step_proof_object_key(1, semantic_id, 0),
            None,
        )
        .unwrap();
        txn.commit().unwrap();
        assert!(!store
            .has_any_history_step_proof_object(1, semantic_id)
            .unwrap());

        let mut wrong_header = candidate.header;
        wrong_header.state_root[0] ^= 1;
        let wrong = crate::storage::VerifiedSnapshotBoundary::new_verified(
            wrong_header,
            terminal(1, crate::block_header::semantic_header_id(&wrong_header), 0),
        );
        assert!(store
            .cache_verified_snapshot_boundary_proof(&wrong)
            .is_err());

        let verified = crate::storage::VerifiedSnapshotBoundary::new_verified(
            candidate.header,
            terminal_bytes.clone(),
        );
        store
            .cache_verified_snapshot_boundary_proof(&verified)
            .unwrap();
        assert_eq!(
            store
                .get_history_step_proof_object(1, semantic_id, 0)
                .unwrap(),
            Some(terminal_bytes)
        );
    }

    #[test]
    fn proof_object_cache_prunes_by_bounded_height_window() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let old = terminal(1, [1; 32], 0);
        let retained = terminal(100, [2; 32], 0);
        let tip = terminal(200, [3; 32], 0);

        let txn = store.db.begin_rw_txn().unwrap();
        archive_history_step_proof_object(&txn, &old).unwrap();
        archive_history_step_proof_object(&txn, &retained).unwrap();
        archive_history_step_proof_object(&txn, &tip).unwrap();
        prune_history_step_proof_objects(&txn, 200).unwrap();
        txn.commit().unwrap();

        assert_eq!(
            store.get_history_step_proof_object(1, [1; 32], 0).unwrap(),
            None
        );
        assert_eq!(
            store
                .get_history_step_proof_object(100, [2; 32], 0)
                .unwrap()
                .as_deref(),
            Some(retained.as_slice())
        );
        assert_eq!(
            store
                .get_history_step_proof_object(200, [3; 32], 0)
                .unwrap()
                .as_deref(),
            Some(tip.as_slice())
        );
    }

    #[test]
    fn tx_index_uses_one_logical_id_for_a_multipage_group() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, genesis_meta) = commit_genesis(&store);
        let mut candidate = block(&genesis, 1, 9);
        let pages = two_page_group(0x44);
        let page_hashes = [pages[0].txid(), pages[1].txid()];
        candidate.transactions.extend(pages);
        candidate.header.tx_root = crate::compute_tx_root(&candidate.transactions);
        let logical = crate::try_compute_logical_txids(&candidate.transactions).unwrap();
        assert_eq!(logical.len(), 2);

        commit_accepted_test_block(&store, &candidate, &genesis_meta);

        assert_eq!(store.get_tx_index(&logical[1].0).unwrap(), Some((1, 1)));
        assert_eq!(store.get_tx_index(&page_hashes[0].0).unwrap(), None);
        assert_eq!(store.get_tx_index(&page_hashes[1].0).unwrap(), None);
    }

    #[test]
    fn missing_bundle_cannot_create_a_pow_only_tip() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, genesis_meta) = commit_genesis(&store);
        let block = block(&genesis, 1, 8);
        let hash = crate::hash_block_header(&block.header);
        let tx_hashes = [block.transactions[0].txid()];
        let meta = ConsensusMeta {
            tip_height: 1,
            tip_hash: hash,
            cumulative_chainwork: genesis_meta.cumulative_chainwork,
            finalized: genesis_meta.finalized,
        };

        assert!(store
            .commit_block(
                &block.header,
                &hash,
                &BlockUndoLog::empty(1, block.header.log_slots),
                &[],
                &[],
                &tx_hashes,
                &[],
                None,
                0,
                &meta,
                false,
            )
            .is_err());
        assert_eq!(
            store.get_chain_tip().unwrap(),
            Some((0, crate::hash_block_header(&genesis)))
        );
        assert_eq!(store.get_header(1).unwrap(), None);
    }

    #[test]
    fn retention_keeps_serving_reserve_bodies_and_boundary_terminal() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let mut parent = crate::consensus::genesis::genesis_header();
        put_test_header_row(&store, &parent);
        let tip = RETAINED_BLOCK_SERVING_DEPTH + 2;
        let mut tip_hash = [0; 32];
        for height in 1..=tip {
            let candidate = block(&parent, height, height as u8);
            let hash = crate::hash_block_header(&candidate.header);
            let terminal = terminal(
                height,
                crate::block_header::semantic_header_id(&candidate.header),
                0,
            );
            crate::AcceptedBlockBundle::try_from_parts(candidate.to_bytes(), terminal.clone())
                .unwrap();
            put_test_header_row(&store, &candidate.header);
            let txn = store.db.begin_rw_txn().unwrap();
            let blocks = txn.open_table(Some(T_RECENT_BLOCKS)).unwrap();
            let terminals = txn.open_table(Some(T_HISTORY_STEP_TERMINALS)).unwrap();
            txn.put(
                &blocks,
                u64_key(height),
                candidate.to_bytes(),
                WriteFlags::empty(),
            )
            .unwrap();
            txn.put(&terminals, u64_key(height), terminal, WriteFlags::empty())
                .unwrap();
            txn.commit().unwrap();
            parent = candidate.header;
            tip_hash = hash;
        }
        store
            .put_consensus_meta(&ConsensusMeta {
                tip_height: tip,
                tip_hash,
                cumulative_chainwork: [0; 32],
                finalized: FinalizedCheckpoint {
                    height: tip,
                    hash: tip_hash,
                },
            })
            .unwrap();
        let txn = store.db.begin_rw_txn().unwrap();
        prune_retained_payloads_bounded(&txn, tip).unwrap();
        txn.commit().unwrap();

        let boundary = tip - RETAINED_BLOCK_SERVING_DEPTH;
        let boundary_hash = crate::hash_block_header(&store.get_header(boundary).unwrap().unwrap());
        assert_eq!(store.get_recent_block(boundary).unwrap(), None);
        assert!(store
            .get_history_step_terminal_at(boundary, boundary_hash)
            .unwrap()
            .is_some());
        assert_eq!(
            store
                .get_recent_accepted_block_bundle_bounded(boundary)
                .unwrap(),
            None
        );
        assert!(store.get_recent_block(boundary + 1).unwrap().is_some());
        assert!(store
            .get_history_step_terminal_at(
                boundary + 1,
                crate::hash_block_header(&store.get_header(boundary + 1).unwrap().unwrap())
            )
            .unwrap()
            .is_some());
        assert_eq!(store.get_recent_block(boundary - 1).unwrap(), None);
        assert!(!store
            .has_history_step_terminal_at(
                boundary - 1,
                crate::hash_block_header(&store.get_header(boundary - 1).unwrap().unwrap()),
            )
            .unwrap());
    }

    #[test]
    fn fragmented_terminal_rotation_reuses_freed_overflow_pages() {
        const FRAGMENT_RECORDS: u64 = 256;
        const FRAGMENT_BYTES: usize = 256 * 1024;
        const ROTATING_BYTES: usize = 512 * 1024;
        const TERMINAL_RETENTION: u64 = 43;
        const PROOF_RETENTION: u64 = 129;
        const WARMUP_HEIGHT: u64 = 300;
        const FINAL_HEIGHT: u64 = 500;
        const ONE_GROWTH_STEP: u64 = 64 * 1024 * 1024;

        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();

        // Build a fragmented free list whose individual 256 KiB holes cannot
        // hold a rotating HistoryStep-sized value. This mirrors a mature node
        // after State and proof objects of different lifetimes have churned.
        let fragment = vec![0xA5; FRAGMENT_BYTES];
        for first in (0..FRAGMENT_RECORDS).step_by(16) {
            let txn = store.db.begin_rw_txn().unwrap();
            let table = txn.open_table(Some(T_SEGMENTS)).unwrap();
            for id in first..(first + 16).min(FRAGMENT_RECORDS) {
                txn.put(&table, u64_key(id), &fragment, WriteFlags::empty())
                    .unwrap();
            }
            txn.commit().unwrap();
        }
        for first in (0..FRAGMENT_RECORDS).step_by(32) {
            let txn = store.db.begin_rw_txn().unwrap();
            let table = txn.open_table(Some(T_SEGMENTS)).unwrap();
            for id in first..(first + 32).min(FRAGMENT_RECORDS) {
                if id % 2 == 0 {
                    txn.del(&table, u64_key(id), None).unwrap();
                }
            }
            txn.commit().unwrap();
        }

        let rotating = vec![0x5A; ROTATING_BYTES];
        let mut size_after_warmup = 0;
        for height in 1..=FINAL_HEIGHT {
            let txn = store.db.begin_rw_txn().unwrap();
            let terminals = txn.open_table(Some(T_HISTORY_STEP_TERMINALS)).unwrap();
            let proofs = txn.open_table(Some(T_HISTORY_STEP_PROOF_OBJECTS)).unwrap();
            txn.put(&terminals, u64_key(height), &rotating, WriteFlags::empty())
                .unwrap();
            txn.put(
                &proofs,
                history_step_proof_object_key(height, [height as u8; 32], 0),
                &rotating,
                WriteFlags::empty(),
            )
            .unwrap();
            if height > TERMINAL_RETENTION {
                txn.del(&terminals, u64_key(height - TERMINAL_RETENTION), None)
                    .unwrap();
            }
            if height > PROOF_RETENTION {
                txn.del(
                    &proofs,
                    history_step_proof_object_key(
                        height - PROOF_RETENTION,
                        [(height - PROOF_RETENTION) as u8; 32],
                        0,
                    ),
                    None,
                )
                .unwrap();
            }
            txn.commit().unwrap();

            if height == WARMUP_HEIGHT {
                size_after_warmup = std::fs::metadata(directory.path().join("mdbx.dat"))
                    .unwrap()
                    .len();
            }
        }

        let final_size = std::fs::metadata(directory.path().join("mdbx.dat"))
            .unwrap()
            .len();
        let free_bytes =
            store.db.freelist().unwrap() as u64 * u64::from(store.db.stat().unwrap().page_size());
        assert!(free_bytes > 0, "stress fixture did not create free pages");
        assert!(
            final_size <= size_after_warmup + ONE_GROWTH_STEP,
            "rotating bounded proof data grew fragmented MDBX from {size_after_warmup} to {final_size} bytes despite {free_bytes} free bytes"
        );
    }

    #[test]
    fn snapshot_install_atomically_commits_headers_state_terminal_and_tip() {
        let directory = tempfile::tempdir().unwrap();
        let staging_root = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, genesis_meta) = commit_genesis(&store);
        let (mut source, _) = snapshot_header_source(genesis, &genesis_meta, 2);
        let meta = target_meta(&source);
        let target = source.target_record();
        let staging = finalized_empty_snapshot(staging_root.path(), target.header);
        let terminal_bytes = terminal(
            target.header.height,
            crate::block_header::semantic_header_id(&target.header),
            0,
        );
        let boundary = crate::storage::VerifiedSnapshotBoundary::new_verified(
            target.header,
            terminal_bytes.clone(),
        );
        let recent = source.recent.clone();

        store
            .install_finalized_snapshot_staging(
                &staging,
                &meta,
                &recent,
                &boundary,
                &mut source,
                false,
            )
            .unwrap();

        assert_eq!(store.get_chain_tip().unwrap(), Some((2, target.hash)));
        assert_eq!(store.get_header(1).unwrap(), Some(recent[1]));
        assert_eq!(store.get_header(2).unwrap(), Some(target.header));
        assert_eq!(
            store
                .get_history_step_terminal_at(target.header.height, target.hash)
                .unwrap(),
            Some(terminal_bytes)
        );
        assert_eq!(
            store.get_state_meta().unwrap(),
            Some((target.header.log_slots, 0, 0))
        );
        assert_eq!(store.get_circulating_supply().unwrap(), Some(0));
    }

    #[test]
    fn snapshot_install_accepts_concurrent_same_prefix_advance() {
        let directory = tempfile::tempdir().unwrap();
        let staging_root = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, genesis_meta) = commit_genesis(&store);
        let (mut source, blocks) = snapshot_header_source(genesis, &genesis_meta, 2);
        commit_accepted_test_block(&store, &blocks[0], &genesis_meta);
        let meta = target_meta(&source);
        let target = source.target_record();
        let staging = finalized_empty_snapshot(staging_root.path(), target.header);
        let boundary = crate::storage::VerifiedSnapshotBoundary::new_verified(
            target.header,
            terminal(
                target.header.height,
                crate::block_header::semantic_header_id(&target.header),
                0,
            ),
        );
        let recent = source.recent.clone();

        store
            .install_finalized_snapshot_staging(
                &staging,
                &meta,
                &recent,
                &boundary,
                &mut source,
                false,
            )
            .unwrap();

        assert_eq!(store.get_chain_tip().unwrap(), Some((2, target.hash)));
        assert_eq!(store.get_header(1).unwrap(), Some(blocks[0].header));
        assert_eq!(store.get_header(2).unwrap(), Some(target.header));
    }

    #[test]
    fn snapshot_install_rejects_divergent_advance_without_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let staging_root = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, genesis_meta) = commit_genesis(&store);
        let (mut source, _) = snapshot_header_source(genesis, &genesis_meta, 2);
        let mut divergent = block(&genesis, 1, 77);
        divergent.header.tx_root[0] ^= 0x80;
        let divergent_meta = commit_accepted_test_block(&store, &divergent, &genesis_meta);
        let divergent_hash = crate::hash_block_header(&divergent.header);
        let meta = target_meta(&source);
        let target = source.target_record();
        let staging = finalized_empty_snapshot(staging_root.path(), target.header);
        let boundary = crate::storage::VerifiedSnapshotBoundary::new_verified(
            target.header,
            terminal(
                target.header.height,
                crate::block_header::semantic_header_id(&target.header),
                0,
            ),
        );
        let recent = source.recent.clone();

        assert!(store
            .install_finalized_snapshot_staging(
                &staging,
                &meta,
                &recent,
                &boundary,
                &mut source,
                false,
            )
            .is_err());

        assert_eq!(store.get_chain_tip().unwrap(), Some((1, divergent_hash)));
        assert_eq!(store.get_consensus_meta().unwrap(), Some(divergent_meta));
        assert_eq!(store.get_header(1).unwrap(), Some(divergent.header));
        assert_eq!(store.get_header(2).unwrap(), None);
        assert!(store
            .has_history_step_terminal_at(1, divergent_hash)
            .unwrap());
    }

    #[test]
    fn snapshot_install_replaces_only_an_authorized_nonfinal_suffix() {
        let directory = tempfile::tempdir().unwrap();
        let staging_root = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, genesis_meta) = commit_genesis(&store);
        let (mut source, _) = snapshot_header_source(genesis, &genesis_meta, 2);
        let mut divergent = block(&genesis, 1, 77);
        divergent.header.tx_root[0] ^= 0x80;
        commit_accepted_test_block(&store, &divergent, &genesis_meta);
        let divergent_hash = crate::hash_block_header(&divergent.header);
        let meta = target_meta(&source);
        let target = source.target_record();
        let staging = finalized_empty_snapshot(staging_root.path(), target.header);
        let boundary = crate::storage::VerifiedSnapshotBoundary::new_verified(
            target.header,
            terminal(
                target.header.height,
                crate::block_header::semantic_header_id(&target.header),
                0,
            ),
        );
        let recent = source.recent.clone();

        store
            .install_finalized_snapshot_staging(
                &staging,
                &meta,
                &recent,
                &boundary,
                &mut source,
                true,
            )
            .unwrap();

        assert_eq!(store.get_chain_tip().unwrap(), Some((2, target.hash)));
        assert_eq!(store.get_header(1).unwrap(), Some(recent[1]));
        assert_eq!(store.get_header_by_hash(&divergent_hash).unwrap(), None);
    }

    #[test]
    fn snapshot_rebase_refuses_a_boundary_that_does_not_yet_win_fork_choice() {
        let directory = tempfile::tempdir().unwrap();
        let staging_root = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, genesis_meta) = commit_genesis(&store);
        let (mut source, _) = snapshot_header_source(genesis, &genesis_meta, 2);

        // The advertised branch may become the winner only in its later
        // compact bridge. Replacing durable State at an earlier, still-losing
        // snapshot boundary would expose a lower-work chain after a crash.
        // Keep the old chain until the authenticated boundary itself wins.
        let mut stronger_local = block(&genesis, 1, 0x71);
        stronger_local.header.difficulty_target = [0u8; 32];
        stronger_local.header.difficulty_target[0] = 1;
        let stronger_meta = commit_accepted_test_block(&store, &stronger_local, &genesis_meta);
        let stronger_hash = stronger_meta.tip_hash;

        let meta = target_meta(&source);
        let target = source.target_record();
        let staging = finalized_empty_snapshot(staging_root.path(), target.header);
        let boundary = crate::storage::VerifiedSnapshotBoundary::new_verified(
            target.header,
            terminal(
                target.header.height,
                crate::block_header::semantic_header_id(&target.header),
                0,
            ),
        );
        let recent = source.recent.clone();

        assert!(store
            .install_finalized_snapshot_staging(
                &staging,
                &meta,
                &recent,
                &boundary,
                &mut source,
                true,
            )
            .is_err());
        assert_eq!(store.get_chain_tip().unwrap(), Some((1, stronger_hash)));
        assert_eq!(store.get_consensus_meta().unwrap(), Some(stronger_meta));
    }

    #[test]
    fn snapshot_rebase_accepts_the_exact_maximum_nonfinal_depth() {
        let directory = tempfile::tempdir().unwrap();
        let staging_root = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, genesis_meta) = commit_genesis(&store);
        let target_height = CONSENSUS_FINALITY_DEPTH + 1;
        let (mut source, _) = snapshot_header_source(genesis, &genesis_meta, target_height);

        let mut divergent_parent = genesis;
        let mut divergent_meta = genesis_meta;
        for height in 1..=CONSENSUS_FINALITY_DEPTH {
            let divergent = block(&divergent_parent, height, (height as u8) ^ 0xA5);
            divergent_meta = commit_accepted_test_block(&store, &divergent, &divergent_meta);
            divergent_parent = divergent.header;
        }
        let old_tip_hash = divergent_meta.tip_hash;
        let meta = target_meta(&source);
        let target = source.target_record();
        let staging = finalized_empty_snapshot(staging_root.path(), target.header);
        let boundary = crate::storage::VerifiedSnapshotBoundary::new_verified(
            target.header,
            terminal(
                target.header.height,
                crate::block_header::semantic_header_id(&target.header),
                0,
            ),
        );
        let recent = source.recent.clone();

        store
            .install_finalized_snapshot_staging(
                &staging,
                &meta,
                &recent,
                &boundary,
                &mut source,
                true,
            )
            .unwrap();

        assert_eq!(
            store.get_chain_tip().unwrap(),
            Some((target_height, target.hash))
        );
        assert_eq!(store.get_header_by_hash(&old_tip_hash).unwrap(), None);
    }

    #[test]
    fn snapshot_rebase_cannot_cross_the_local_finalized_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let staging_root = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, genesis_meta) = commit_genesis(&store);
        let (mut source, _) = snapshot_header_source(genesis, &genesis_meta, 2);
        let mut divergent = block(&genesis, 1, 91);
        divergent.header.tx_root[0] ^= 0x40;
        let mut divergent_meta = commit_accepted_test_block(&store, &divergent, &genesis_meta);
        let divergent_hash = crate::hash_block_header(&divergent.header);
        divergent_meta.finalized = FinalizedCheckpoint {
            height: 1,
            hash: divergent_hash,
        };
        store.put_consensus_meta(&divergent_meta).unwrap();

        let meta = target_meta(&source);
        let target = source.target_record();
        let staging = finalized_empty_snapshot(staging_root.path(), target.header);
        let boundary = crate::storage::VerifiedSnapshotBoundary::new_verified(
            target.header,
            terminal(
                target.header.height,
                crate::block_header::semantic_header_id(&target.header),
                0,
            ),
        );
        let recent = source.recent.clone();

        assert!(store
            .install_finalized_snapshot_staging(
                &staging,
                &meta,
                &recent,
                &boundary,
                &mut source,
                true,
            )
            .is_err());
        assert_eq!(store.get_chain_tip().unwrap(), Some((1, divergent_hash)));
        assert_eq!(store.get_consensus_meta().unwrap(), Some(divergent_meta));
    }

    #[test]
    fn snapshot_header_stream_failure_rolls_back_partial_suffix() {
        let directory = tempfile::tempdir().unwrap();
        let staging_root = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (genesis, genesis_meta) = commit_genesis(&store);
        let (mut source, _) = snapshot_header_source(genesis, &genesis_meta, 2);
        source.fail_at = Some(1);
        let meta = target_meta(&source);
        let target = source.target_record();
        let staging = finalized_empty_snapshot(staging_root.path(), target.header);
        let boundary = crate::storage::VerifiedSnapshotBoundary::new_verified(
            target.header,
            terminal(
                target.header.height,
                crate::block_header::semantic_header_id(&target.header),
                0,
            ),
        );
        let recent = source.recent.clone();

        assert!(store
            .install_finalized_snapshot_staging(
                &staging,
                &meta,
                &recent,
                &boundary,
                &mut source,
                false,
            )
            .is_err());

        assert_eq!(
            store.get_chain_tip().unwrap(),
            Some((0, crate::hash_block_header(&genesis)))
        );
        assert_eq!(store.get_header(1).unwrap(), None);
        assert_eq!(store.get_header(2).unwrap(), None);
        assert_eq!(store.get_chain_work(1).unwrap(), None);
        assert_eq!(store.get_header_anchor(1).unwrap(), None);
    }
}
