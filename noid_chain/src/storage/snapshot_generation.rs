// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded-memory immutable state-snapshot generation.
//!
//! The durable MDBX state always describes the current canonical tip.  This
//! module reconstructs any target inside the retained undo window without
//! cloning that state. The first generation visits the numeric union of
//! durable and touched segment IDs once. Later generations hard-link unchanged
//! immutable payloads and reconstruct only segments touched since the previous
//! finalized boundary. Sparse entries are rolled back and authenticated
//! directly; no 3 MiB dense segment image is created by the snapshot path.
//!
//! Segment payloads are written and synced into a private temporary generation
//! directory as they are reconstructed.  The manifest is created only after
//! the exact sparse root, live counter, creation-id bound, target header and
//! source-tip stability have all been checked.  Renaming the complete
//! directory publishes the immutable generation atomically.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bincode::Options;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;
use serde::{Deserialize, Serialize};

use crate::block_header::{block_id, BlockHeader};
use crate::consensus::params::{
    BLOCK_MAX_ACTIONS, LOG_SLOTS_MAX, RECENT_BLOCK_RETENTION_DEPTH, UNDO_RETENTION_DEPTH,
};
use crate::consensus::wire_limits::{
    history_step_terminal_bytes_limit, MAX_BLOCK_BYTES, MAX_SEGMENT_BYTES,
    MAX_SNAPSHOT_MANIFEST_SEGMENTS,
};
use crate::exact_state_hash::{slot_leaf_hash, state_node_hash, zero_slot_roots, StateHash};
use crate::fri_state::{SlotValue, LOG_SEGMENT_SIZE};
use crate::state::StreamingSparseRoot;
use crate::storage::mdbx_store::MdbxHistoricalReadSnapshot;
#[cfg(all(test, unix))]
use crate::storage::serial::encoded_segment_len_for_live_count;
use crate::storage::serial::{
    decode_sparse_segment, encode_sparse_segment_entries, encoded_segment_live_count_from_len,
    max_encoded_segment_len_for_eff_log, SparseSegmentView,
};
use crate::storage::{MdbxStore, StoreError};
const SNAPSHOT_MANIFEST_DOMAIN: &[u8] = b"NOID_DISK_SNAPSHOT_GENERATION_MANIFEST_V6";
const SNAPSHOT_PAYLOAD_DOMAIN: &[u8] = b"NOID_DISK_SNAPSHOT_GENERATION_PAYLOAD_V1";
const SNAPSHOT_GENERATION_VERSION: u32 = 6;
const MANIFEST_FILE_NAME: &str = "manifest.bin";
const MANIFEST_TEMP_FILE_NAME: &str = ".manifest.tmp";
const SEGMENTS_DIRECTORY_NAME: &str = "segments";
const BRIDGE_DIRECTORY_NAME: &str = "bridge";
const BOUNDARY_TERMINAL_FILE_NAME: &str = "boundary.history-step";
const BRIDGE_TERMINAL_FILE_NAME: &str = "bridge.history-step";

/// A manifest contains only bounded segment metadata, never segment payloads.
/// The complete `u16` segment namespace occupies less than 8 MiB here.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

/// Consensus bounds make the retained rollback journal independent of state
/// size: at most one action pre-image per accepted block action.
const MAX_GROUPED_UNDO_CHANGES: usize = UNDO_RETENTION_DEPTH as usize * BLOCK_MAX_ACTIONS;

static NEXT_TEMP_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Metadata for one non-empty immutable segment payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSegmentDescriptor {
    pub segment_id: u16,
    /// Exact Poseidon sparse-Merkle root of this segment subtree.
    pub segment_root: [u8; 32],
    /// Exact byte length of `storage::encode_segment` output.
    pub encoded_len: u32,
}

/// One immutable canonical block body following the finalized state boundary.
/// The complete suffix shares one terminal at `bridge_tip_height`.
/// Generations hard-link overlapping descriptors, so advancing the rolling
/// snapshot normally writes only newly accepted suffix blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBridgeDescriptor {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub encoded_len: u32,
    pub encoded_digest: [u8; 32],
}

/// Exact state boundary described by one disk-backed snapshot generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotGenerationManifest {
    pub version: u32,
    pub target_height: u64,
    pub target_hash: [u8; 32],
    pub cumulative_chainwork: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    pub state_root: [u8; 32],
    pub effective_log_segment_size: u8,
    /// Exact HistoryStep authority for `target_height`, retained independently
    /// of the live database's moving terminal window.
    pub boundary_terminal_len: u32,
    pub boundary_terminal_digest: [u8; 32],
    /// Immutable canonical suffix captured in the same MVCC view as the state.
    pub bridge_tip_height: u64,
    pub bridge_tip_hash: [u8; 32],
    pub bridge_cumulative_chainwork: [u8; 32],
    /// One full HistoryStep terminal covering the complete bridge. Empty only
    /// when the bridge itself is empty and the boundary terminal is sufficient.
    pub bridge_terminal_len: u32,
    pub bridge_terminal_digest: [u8; 32],
    pub bridge: Vec<SnapshotBridgeDescriptor>,
    /// Strictly increasing non-empty segment descriptors.  Payloads live in
    /// separate files and are never accumulated in this vector.
    pub segments: Vec<SnapshotSegmentDescriptor>,
}

impl SnapshotGenerationManifest {
    /// Domain-separated immutable generation identifier.
    pub fn generation_id(&self) -> Result<[u8; 32], SnapshotGenerationError> {
        let encoded = encode_manifest(self)?;
        Ok(poseidon2b_hash_byte_slices(
            SNAPSHOT_MANIFEST_DOMAIN,
            &[&encoded],
        ))
    }

    /// Look up a segment without allocating a second ID table.
    pub fn segment(&self, segment_id: u16) -> Option<&SnapshotSegmentDescriptor> {
        self.segments
            .binary_search_by_key(&segment_id, |entry| entry.segment_id)
            .ok()
            .map(|index| &self.segments[index])
    }

    pub fn bridge_block(&self, height: u64) -> Option<&SnapshotBridgeDescriptor> {
        self.bridge
            .binary_search_by_key(&height, |entry| entry.height)
            .ok()
            .map(|index| &self.bridge[index])
    }
}

/// Open handle to an already-published immutable generation.
#[derive(Debug, Clone)]
pub struct SnapshotGeneration {
    directory: PathBuf,
    manifest: SnapshotGenerationManifest,
}

impl SnapshotGeneration {
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn manifest(&self) -> &SnapshotGenerationManifest {
        &self.manifest
    }

    /// Stable canonical boundary key used by P2P export registries.
    pub fn key(&self) -> (u64, [u8; 32]) {
        (self.manifest.target_height, self.manifest.target_hash)
    }

    /// Content-derived key for distinguishing separately encoded generations
    /// of the same canonical boundary.
    pub fn generation_id(&self) -> Result<[u8; 32], SnapshotGenerationError> {
        self.manifest.generation_id()
    }

    /// Read and authenticate the finalized boundary terminal retained with
    /// this generation.
    pub fn read_boundary_terminal(&self) -> Result<Vec<u8>, SnapshotGenerationError> {
        read_authenticated_payload(
            &self.directory.join(BOUNDARY_TERMINAL_FILE_NAME),
            self.manifest.boundary_terminal_len,
            self.manifest.boundary_terminal_digest,
            history_step_terminal_bytes_limit(self.manifest.target_height),
            "snapshot boundary terminal",
        )
    }

    /// Read the one exact terminal covering the complete immutable bridge.
    pub fn read_bridge_terminal(&self) -> Result<Vec<u8>, SnapshotGenerationError> {
        if self.manifest.bridge_tip_height == self.manifest.target_height {
            return self.read_boundary_terminal();
        }
        read_authenticated_payload(
            &self.directory.join(BRIDGE_TERMINAL_FILE_NAME),
            self.manifest.bridge_terminal_len,
            self.manifest.bridge_terminal_digest,
            history_step_terminal_bytes_limit(self.manifest.bridge_tip_height),
            "snapshot bridge terminal",
        )
    }

    /// Read one exact terminal owned by this immutable generation.
    ///
    /// The boundary and bridge-tip terminals are stored separately. Exposing
    /// this uniform lookup lets compact snapshot clients request only the
    /// single recursive terminal at the sealed suffix tip even if live pruning
    /// has advanced.
    pub fn read_terminal_at(
        &self,
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<Vec<u8>, SnapshotGenerationError> {
        if height == self.manifest.target_height && block_hash == self.manifest.target_hash {
            return self.read_boundary_terminal();
        }
        if height == self.manifest.bridge_tip_height && block_hash == self.manifest.bridge_tip_hash
        {
            return self.read_bridge_terminal();
        }
        Err(SnapshotGenerationError::BridgeBlockNotInManifest(height))
    }

    /// Read and authenticate one immutable post-snapshot block body.
    pub fn read_bridge_block_body(&self, height: u64) -> Result<Vec<u8>, SnapshotGenerationError> {
        let descriptor = self
            .manifest
            .bridge_block(height)
            .ok_or(SnapshotGenerationError::BridgeBlockNotInManifest(height))?;
        let encoded = read_authenticated_payload(
            &bridge_path(&self.directory, height),
            descriptor.encoded_len,
            descriptor.encoded_digest,
            MAX_BLOCK_BYTES,
            "snapshot bridge block",
        )?;
        let block = crate::Block::from_bytes(&encoded)
            .map_err(|_| SnapshotGenerationError::InvalidBridgeBlock(height))?;
        if block.header.height != height || block_id(&block.header) != descriptor.block_hash {
            return Err(SnapshotGenerationError::InvalidBridgeBlock(height));
        }
        Ok(encoded)
    }

    /// Read and authenticate one encoded segment without expanding its empty
    /// slots into dense columns.
    pub fn read_encoded_segment(
        &self,
        segment_id: u16,
    ) -> Result<Vec<u8>, SnapshotGenerationError> {
        let descriptor = self
            .manifest
            .segment(segment_id)
            .ok_or(SnapshotGenerationError::SegmentNotInManifest(segment_id))?;
        let path = segment_path(&self.directory, segment_id);
        let mut file = File::open(&path)?;
        let metadata_len = file.metadata()?.len();
        if metadata_len != u64::from(descriptor.encoded_len)
            || metadata_len > MAX_SEGMENT_BYTES as u64
        {
            return Err(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "encoded length does not match manifest",
            ));
        }

        let mut encoded = Vec::with_capacity(descriptor.encoded_len as usize);
        Read::by_ref(&mut file)
            .take(u64::from(descriptor.encoded_len) + 1)
            .read_to_end(&mut encoded)?;
        if encoded.len() != descriptor.encoded_len as usize {
            return Err(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "short or overlong segment file",
            ));
        }
        let sparse = decode_sparse_segment(&encoded).ok_or(
            SnapshotGenerationError::InvalidSegment(segment_id, "sparse segment decode failed"),
        )?;
        if sparse.effective_log_segment() != self.manifest.effective_log_segment_size {
            return Err(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "effective segment log does not match manifest",
            ));
        }
        let exact_root = validate_sparse_segment(
            segment_id,
            sparse,
            self.manifest.alloc_counter,
            self.manifest.target_height,
        )?;
        if sparse.live_count() == 0 {
            return Err(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "manifest contains an empty segment",
            ));
        }
        if exact_root != descriptor.segment_root {
            return Err(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "exact segment root does not match manifest",
            ));
        }
        Ok(encoded)
    }
}

#[derive(Debug)]
pub enum SnapshotGenerationError {
    Store(StoreError),
    Io(io::Error),
    ManifestCodec(String),
    MissingChainTip,
    MissingStateMeta,
    MissingHeader(u64),
    MissingChainwork(u64),
    MissingUndo(u64),
    TargetAboveTip {
        target: u64,
        tip: u64,
    },
    TargetOutsideUndoWindow {
        target: u64,
        tip: u64,
    },
    SourceChanged,
    Corrupt(&'static str),
    UndoTooLarge(u64),
    UnsupportedGeometry {
        target_log: u32,
        tip_log: u32,
    },
    InvalidSegment(u16, &'static str),
    SegmentNotInManifest(u16),
    MissingBoundaryTerminal(u64),
    MissingBridgeTerminal(u64),
    MissingBridgeBlock(u64),
    InvalidBridgeBlock(u64),
    BridgeBlockNotInManifest(u64),
    InvalidPayload(&'static str),
    CreationIdExceedsTarget {
        segment_id: u16,
        local_index: u32,
        creation_id: u64,
        alloc_counter: u64,
    },
    ActiveSlotCountMismatch {
        expected: u64,
        actual: u64,
    },
    ExactStateRootMismatch,
    PublishedGenerationConflict(PathBuf),
}

impl std::fmt::Display for SnapshotGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "snapshot store read: {error}"),
            Self::Io(error) => write!(f, "snapshot filesystem: {error}"),
            Self::ManifestCodec(error) => write!(f, "snapshot manifest codec: {error}"),
            Self::MissingChainTip => f.write_str("durable chain tip is missing"),
            Self::MissingStateMeta => f.write_str("durable state metadata is missing"),
            Self::MissingHeader(height) => write!(f, "canonical header {height} is missing"),
            Self::MissingChainwork(height) => {
                write!(f, "cumulative chainwork at height {height} is missing")
            }
            Self::MissingUndo(height) => write!(f, "undo log at height {height} is missing"),
            Self::TargetAboveTip { target, tip } => {
                write!(f, "snapshot target {target} is above durable tip {tip}")
            }
            Self::TargetOutsideUndoWindow { target, tip } => write!(
                f,
                "snapshot target {target} is outside the retained undo window at tip {tip}"
            ),
            Self::SourceChanged => {
                f.write_str("durable canonical source changed during snapshot generation")
            }
            Self::Corrupt(context) => write!(f, "corrupt durable snapshot source: {context}"),
            Self::UndoTooLarge(height) => {
                write!(f, "undo log {height} exceeds the consensus action bound")
            }
            Self::UnsupportedGeometry {
                target_log,
                tip_log,
            } => write!(
                f,
                "snapshot rollback changes segment geometry ({tip_log} -> {target_log})"
            ),
            Self::InvalidSegment(id, context) => {
                write!(f, "invalid snapshot segment {id}: {context}")
            }
            Self::SegmentNotInManifest(id) => {
                write!(f, "segment {id} is not present in this snapshot manifest")
            }
            Self::MissingBoundaryTerminal(height) => {
                write!(f, "snapshot boundary terminal {height} is missing")
            }
            Self::MissingBridgeTerminal(height) => {
                write!(f, "snapshot bridge terminal {height} is missing")
            }
            Self::MissingBridgeBlock(height) => {
                write!(f, "snapshot bridge block {height} is missing")
            }
            Self::InvalidBridgeBlock(height) => {
                write!(f, "snapshot bridge block {height} is invalid")
            }
            Self::BridgeBlockNotInManifest(height) => {
                write!(f, "block {height} is not present in this snapshot bridge")
            }
            Self::InvalidPayload(context) => write!(f, "invalid immutable payload: {context}"),
            Self::CreationIdExceedsTarget {
                segment_id,
                local_index,
                creation_id,
                alloc_counter,
            } => write!(
                f,
                "segment {segment_id} slot {local_index} creation id {creation_id} exceeds target allocator {alloc_counter}"
            ),
            Self::ActiveSlotCountMismatch { expected, actual } => write!(
                f,
                "snapshot live count {actual} does not match target header {expected}"
            ),
            Self::ExactStateRootMismatch => {
                f.write_str("snapshot exact state root does not match target header")
            }
            Self::PublishedGenerationConflict(path) => write!(
                f,
                "a different snapshot generation is already published at {}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for SnapshotGenerationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StoreError> for SnapshotGenerationError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<io::Error> for SnapshotGenerationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Export `target_height` from the current durable MDBX tip into `export_root`.
///
/// The target must be canonical and no deeper than `UNDO_RETENTION_DEPTH`.
/// A canonical `previous` generation enables delta reconstruction; otherwise
/// a complete self-authenticating generation is built. Published generations
/// are content-addressed and never overwritten.
pub fn export_snapshot_generation(
    store: &MdbxStore,
    export_root: &Path,
    target_height: u64,
    previous: Option<&SnapshotGeneration>,
) -> Result<SnapshotGeneration, SnapshotGenerationError> {
    export_snapshot_generation_inner(store, export_root, target_height, previous, true)
}

/// Export an immutable State boundary without capturing the moving live
/// suffix. Network v6 installs this boundary and then obtains a separately
/// frozen exact suffix selected by the header DAG.
pub fn export_snapshot_boundary_generation(
    store: &MdbxStore,
    export_root: &Path,
    target_height: u64,
    previous: Option<&SnapshotGeneration>,
) -> Result<SnapshotGeneration, SnapshotGenerationError> {
    export_snapshot_generation_inner(store, export_root, target_height, previous, false)
}

fn export_snapshot_generation_inner(
    store: &MdbxStore,
    export_root: &Path,
    target_height: u64,
    previous: Option<&SnapshotGeneration>,
    include_bridge: bool,
) -> Result<SnapshotGeneration, SnapshotGenerationError> {
    // One MVCC transaction pins all source metadata and segment bytes. Mining
    // may advance concurrently without making a long export internally mixed.
    let snapshot = store.historical_read_snapshot()?;
    let (tip_height, tip_hash) = snapshot
        .get_chain_tip()?
        .ok_or(SnapshotGenerationError::MissingChainTip)?;
    if target_height > tip_height {
        return Err(SnapshotGenerationError::TargetAboveTip {
            target: target_height,
            tip: tip_height,
        });
    }
    if tip_height.saturating_sub(target_height) > UNDO_RETENTION_DEPTH {
        return Err(SnapshotGenerationError::TargetOutsideUndoWindow {
            target: target_height,
            tip: tip_height,
        });
    }

    let tip_header = canonical_header(&snapshot, tip_height)?;
    if block_id(&tip_header) != tip_hash {
        return Err(SnapshotGenerationError::Corrupt(
            "tip hash does not match canonical tip header",
        ));
    }
    let state_meta = snapshot
        .get_state_meta()?
        .ok_or(SnapshotGenerationError::MissingStateMeta)?;
    if state_meta
        != (
            tip_header.log_slots,
            tip_header.active_slot_count,
            tip_header.alloc_counter,
        )
    {
        return Err(SnapshotGenerationError::Corrupt(
            "tip state metadata does not match tip header",
        ));
    }

    let target_header = canonical_header(&snapshot, target_height)?;
    let target_hash = block_id(&target_header);
    let cumulative_chainwork = snapshot
        .get_chain_work(target_height)?
        .ok_or(SnapshotGenerationError::MissingChainwork(target_height))?;
    validate_log_slots(tip_header.log_slots)?;
    validate_log_slots(target_header.log_slots)?;

    let tip_effective_log = effective_log(tip_header.log_slots);
    let target_effective_log = effective_log(target_header.log_slots);
    if tip_effective_log != target_effective_log {
        return Err(SnapshotGenerationError::UnsupportedGeometry {
            target_log: target_header.log_slots,
            tip_log: tip_header.log_slots,
        });
    }
    let effective_log = tip_effective_log;

    let rollback_by_segment = collect_grouped_undo(
        &snapshot,
        target_height,
        tip_height,
        tip_hash,
        effective_log,
    )?;

    // Discover only the strict numeric u16 key set. Segment payloads remain in
    // MDBX until the one-segment reconstruction loop below needs each one.
    let durable_ids = snapshot.segment_ids()?;

    let tip_segment_count = segment_count(tip_header.log_slots)?;
    if durable_ids
        .last()
        .is_some_and(|id| usize::from(*id) >= tip_segment_count)
    {
        return Err(SnapshotGenerationError::Corrupt(
            "durable segment lies outside tip slot domain",
        ));
    }

    // A preceding canonical generation is an authenticated state base. Only
    // segments touched between that boundary and the new finalized boundary
    // can differ; all other immutable files are linked into the new generation
    // without reading, hashing, or copying their sparse payloads.
    let eligible_base = match previous {
        Some(candidate)
            if incremental_base_is_eligible(
                &snapshot,
                candidate,
                &target_header,
                tip_height,
                effective_log,
            )? =>
        {
            Some(candidate)
        }
        _ => None,
    };
    let (incremental_base, changed_segments) = match eligible_base {
        Some(base) => match collect_grouped_undo(
            &snapshot,
            base.manifest.target_height,
            target_height,
            target_hash,
            effective_log,
        ) {
            Ok(changes) => (Some(base), changes.into_keys().collect::<BTreeSet<_>>()),
            // A database upgraded from the former one-window retention may
            // not yet have the small previous->target delta. The full path is
            // self-authenticating and provides a clean new incremental base.
            Err(SnapshotGenerationError::MissingUndo(_)) => (None, BTreeSet::new()),
            Err(error) => return Err(error),
        },
        None => (None, BTreeSet::new()),
    };

    // The full first generation visits the durable/touched numeric union. An
    // incremental generation reconstructs only its changed segment set.
    let mut union_ids = if incremental_base.is_some() {
        changed_segments.iter().copied().collect::<Vec<_>>()
    } else {
        let mut ids = durable_ids.clone();
        ids.extend(rollback_by_segment.keys().copied());
        ids.sort_unstable();
        ids.dedup();
        ids
    };
    union_ids.sort_unstable();
    if union_ids.len() > MAX_SNAPSHOT_MANIFEST_SEGMENTS {
        return Err(SnapshotGenerationError::Corrupt(
            "segment id union exceeds manifest cap",
        ));
    }
    let rebuilt_segment_count = union_ids.len();
    let incremental_base_height = incremental_base.map(|base| base.manifest.target_height);

    fs::create_dir_all(export_root)?;
    let mut temporary = TemporaryGeneration::create(export_root)?;
    let segments_directory = temporary.path().join(SEGMENTS_DIRECTORY_NAME);
    fs::create_dir(&segments_directory)?;

    let target_segment_count = segment_count(target_header.log_slots)?;
    let mut entries: Vec<SnapshotSegmentDescriptor> = Vec::new();
    let mut reused_segment_count = 0usize;

    if let Some(base) = incremental_base {
        for descriptor in &base.manifest.segments {
            if changed_segments.contains(&descriptor.segment_id) {
                continue;
            }
            if usize::from(descriptor.segment_id) >= target_segment_count {
                return Err(SnapshotGenerationError::InvalidSegment(
                    descriptor.segment_id,
                    "incremental base contains state outside target domain",
                ));
            }
            reuse_snapshot_segment(
                base,
                temporary.path(),
                descriptor.segment_id,
                descriptor.encoded_len,
            )?;
            entries.push(*descriptor);
            reused_segment_count += 1;
        }
    }

    for segment_id in union_ids {
        let was_durable = durable_ids.binary_search(&segment_id).is_ok();
        let mut sparse_slots = match snapshot.get_encoded_segment(segment_id)? {
            Some(encoded) => {
                let sparse = decode_sparse_segment(&encoded).ok_or(
                    SnapshotGenerationError::InvalidSegment(
                        segment_id,
                        "durable sparse segment decode failed",
                    ),
                )?;
                if sparse.effective_log_segment() != effective_log {
                    return Err(SnapshotGenerationError::InvalidSegment(
                        segment_id,
                        "durable segment shape does not match tip geometry",
                    ));
                }
                sparse.entries().collect::<BTreeMap<_, _>>()
            }
            None if was_durable => {
                return Err(SnapshotGenerationError::InvalidSegment(
                    segment_id,
                    "durable segment disappeared during export",
                ));
            }
            None => BTreeMap::new(),
        };

        if let Some(changes) = rollback_by_segment.get(&segment_id) {
            apply_sparse_segment_rollbacks(&mut sparse_slots, changes, effective_log)?;
        }

        if usize::from(segment_id) >= target_segment_count {
            if !sparse_slots.is_empty() {
                return Err(SnapshotGenerationError::InvalidSegment(
                    segment_id,
                    "rollback left live data outside target slot domain",
                ));
            }
            continue;
        }

        if sparse_slots.is_empty() {
            continue;
        }

        let ordered_entries = sparse_slots.into_iter().collect::<Vec<_>>();
        let encoded = encode_sparse_segment_entries(effective_log, &ordered_entries).ok_or(
            SnapshotGenerationError::InvalidSegment(
                segment_id,
                "sparse segment entries are noncanonical",
            ),
        )?;
        if encoded.len() > MAX_SEGMENT_BYTES {
            return Err(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "encoded segment exceeds wire/storage cap",
            ));
        }
        let encoded_len = u32::try_from(encoded.len()).map_err(|_| {
            SnapshotGenerationError::InvalidSegment(
                segment_id,
                "encoded segment length exceeds u32",
            )
        })?;
        let sparse =
            decode_sparse_segment(&encoded).ok_or(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "rebuilt sparse segment decode failed",
            ))?;
        let exact_segment_root = validate_sparse_segment(
            segment_id,
            sparse,
            target_header.alloc_counter,
            target_header.height,
        )?;
        write_synced_file(&segment_path(temporary.path(), segment_id), &encoded)?;
        entries.push(SnapshotSegmentDescriptor {
            segment_id,
            segment_root: exact_segment_root,
            encoded_len,
        });
        // `encoded` and sparse entry storage drop before the next segment.
    }

    entries.sort_unstable_by_key(|descriptor| descriptor.segment_id);
    sync_directory(&segments_directory)?;

    let (boundary_terminal_len, boundary_terminal_digest) = if target_height == 0 {
        (0, [0; 32])
    } else {
        let canonical_terminal =
            snapshot.get_history_step_terminal_at(target_height, target_hash)?;
        let terminal = match canonical_terminal {
            Some(terminal) => terminal,
            None => snapshot
                .get_any_history_step_proof_object(
                    target_height,
                    crate::block_header::semantic_header_id(&target_header),
                )?
                .ok_or(SnapshotGenerationError::MissingBoundaryTerminal(
                    target_height,
                ))?,
        };
        if terminal.is_empty() || terminal.len() > history_step_terminal_bytes_limit(target_height)
        {
            return Err(SnapshotGenerationError::InvalidPayload(
                "snapshot boundary terminal length is outside bounds",
            ));
        }
        let terminal_len = u32::try_from(terminal.len()).map_err(|_| {
            SnapshotGenerationError::InvalidPayload(
                "snapshot boundary terminal length does not fit u32",
            )
        })?;
        let terminal_digest = snapshot_payload_digest(&terminal);
        write_synced_file(
            &temporary.path().join(BOUNDARY_TERMINAL_FILE_NAME),
            &terminal,
        )?;
        (terminal_len, terminal_digest)
    };

    let (bridge_tip_height, bridge_tip_hash) = if include_bridge {
        (tip_height, tip_hash)
    } else {
        (target_height, target_hash)
    };
    let bridge_span = bridge_tip_height.saturating_sub(target_height);
    if bridge_span > RECENT_BLOCK_RETENTION_DEPTH {
        return Err(SnapshotGenerationError::Corrupt(
            "snapshot bridge exceeds recent block retention",
        ));
    }
    let bridge_directory = temporary.path().join(BRIDGE_DIRECTORY_NAME);
    fs::create_dir(&bridge_directory)?;
    let mut bridge = Vec::with_capacity(bridge_span as usize);
    let mut expected_parent = target_hash;
    for height in target_height.saturating_add(1)..=bridge_tip_height {
        let encoded = snapshot
            .get_recent_block(height)?
            .ok_or(SnapshotGenerationError::MissingBridgeBlock(height))?;
        if encoded.is_empty() || encoded.len() > MAX_BLOCK_BYTES {
            return Err(SnapshotGenerationError::InvalidBridgeBlock(height));
        }
        let block = crate::Block::from_bytes(&encoded)
            .map_err(|_| SnapshotGenerationError::InvalidBridgeBlock(height))?;
        if block.header.height != height || block.header.prev_block_hash != expected_parent {
            return Err(SnapshotGenerationError::InvalidBridgeBlock(height));
        }
        let canonical = canonical_header(&snapshot, height)?;
        let block_hash = block_id(&canonical);
        if canonical != block.header {
            return Err(SnapshotGenerationError::InvalidBridgeBlock(height));
        }
        expected_parent = block_hash;
        let encoded_len = u32::try_from(encoded.len())
            .map_err(|_| SnapshotGenerationError::InvalidBridgeBlock(height))?;
        let encoded_digest = snapshot_payload_digest(&encoded);
        let descriptor = SnapshotBridgeDescriptor {
            height,
            block_hash,
            encoded_len,
            encoded_digest,
        };
        let reused = match incremental_base {
            Some(base) => reuse_snapshot_bridge_block(base, temporary.path(), &descriptor)?,
            None => false,
        };
        if !reused {
            write_synced_file(&bridge_path(temporary.path(), height), &encoded)?;
        }
        bridge.push(descriptor);
    }
    sync_directory(&bridge_directory)?;

    let (bridge_terminal_len, bridge_terminal_digest) = if bridge_span == 0 {
        (0, [0; 32])
    } else {
        let bridge_tip_header = if include_bridge {
            tip_header
        } else {
            target_header
        };
        let canonical_terminal =
            snapshot.get_history_step_terminal_at(bridge_tip_height, bridge_tip_hash)?;
        let terminal = match canonical_terminal {
            Some(terminal) => terminal,
            None => snapshot
                .get_any_history_step_proof_object(
                    bridge_tip_height,
                    crate::block_header::semantic_header_id(&bridge_tip_header),
                )?
                .ok_or(SnapshotGenerationError::MissingBridgeTerminal(
                    bridge_tip_height,
                ))?,
        };
        if terminal.is_empty()
            || terminal.len() > history_step_terminal_bytes_limit(bridge_tip_height)
        {
            return Err(SnapshotGenerationError::InvalidPayload(
                "snapshot bridge terminal length is outside bounds",
            ));
        }
        let terminal_len = u32::try_from(terminal.len()).map_err(|_| {
            SnapshotGenerationError::InvalidPayload(
                "snapshot bridge terminal length does not fit u32",
            )
        })?;
        let terminal_digest = snapshot_payload_digest(&terminal);
        write_synced_file(&temporary.path().join(BRIDGE_TERMINAL_FILE_NAME), &terminal)?;
        (terminal_len, terminal_digest)
    };

    let manifest = SnapshotGenerationManifest {
        version: SNAPSHOT_GENERATION_VERSION,
        target_height,
        target_hash,
        cumulative_chainwork,
        log_slots: target_header.log_slots,
        active_slot_count: target_header.active_slot_count,
        alloc_counter: target_header.alloc_counter,
        state_root: target_header.state_root,
        effective_log_segment_size: effective_log,
        boundary_terminal_len,
        boundary_terminal_digest,
        bridge_tip_height,
        bridge_tip_hash,
        bridge_cumulative_chainwork: snapshot
            .get_chain_work(bridge_tip_height)?
            .ok_or(SnapshotGenerationError::MissingChainwork(bridge_tip_height))?,
        bridge_terminal_len,
        bridge_terminal_digest,
        bridge,
        segments: entries,
    };
    validate_manifest(&manifest)?;
    tracing::info!(
        target_height,
        incremental_base_height = ?incremental_base_height,
        reused_segments = reused_segment_count,
        rebuilt_segments = rebuilt_segment_count,
        output_segments = manifest.segments.len(),
        "assembled bounded disk snapshot generation"
    );

    // Recheck the pinned MVCC source before publication. A concurrent writer
    // may have advanced the live tip, which does not invalidate this exact
    // internally-consistent generation.
    if snapshot.get_chain_tip()? != Some((tip_height, tip_hash))
        || snapshot.get_state_meta()? != Some(state_meta)
        || canonical_header(&snapshot, target_height)? != target_header
        || snapshot.get_chain_work(target_height)? != Some(cumulative_chainwork)
    {
        return Err(SnapshotGenerationError::SourceChanged);
    }

    let manifest_bytes = encode_manifest(&manifest)?;
    let temporary_manifest = temporary.path().join(MANIFEST_TEMP_FILE_NAME);
    write_synced_file(&temporary_manifest, &manifest_bytes)?;
    fs::rename(
        &temporary_manifest,
        temporary.path().join(MANIFEST_FILE_NAME),
    )?;
    sync_directory(temporary.path())?;

    let generation_id = manifest.generation_id()?;
    let final_directory = export_root.join(format!(
        "snapshot-v{}-{:020}-{}",
        SNAPSHOT_GENERATION_VERSION,
        target_height,
        hex_digest(&generation_id)
    ));
    match fs::rename(temporary.path(), &final_directory) {
        Ok(()) => {
            temporary.disarm();
            sync_directory(export_root)?;
        }
        Err(_error) if final_directory.exists() => {
            let existing = open_snapshot_generation(&final_directory)?;
            if existing.manifest != manifest {
                return Err(SnapshotGenerationError::PublishedGenerationConflict(
                    final_directory,
                ));
            }
            return Ok(existing);
        }
        Err(error) => return Err(SnapshotGenerationError::Io(error)),
    }

    open_snapshot_generation(&final_directory)
}

/// Open and validate a published manifest without loading any segment payload.
pub fn open_snapshot_generation(
    directory: impl AsRef<Path>,
) -> Result<SnapshotGeneration, SnapshotGenerationError> {
    let directory = directory.as_ref().to_path_buf();
    let manifest_path = directory.join(MANIFEST_FILE_NAME);
    let mut file = File::open(&manifest_path)?;
    let length = file.metadata()?.len();
    if length == 0 || length > MAX_MANIFEST_BYTES {
        return Err(SnapshotGenerationError::Corrupt(
            "snapshot manifest length is outside bounds",
        ));
    }
    let mut encoded = Vec::with_capacity(length as usize);
    Read::by_ref(&mut file)
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() as u64 != length {
        return Err(SnapshotGenerationError::Corrupt(
            "snapshot manifest changed while reading",
        ));
    }
    let manifest = decode_manifest(&encoded)?;
    validate_manifest(&manifest)?;
    Ok(SnapshotGeneration {
        directory,
        manifest,
    })
}

fn incremental_base_is_eligible(
    snapshot: &MdbxHistoricalReadSnapshot<'_>,
    previous: &SnapshotGeneration,
    target: &BlockHeader,
    source_tip_height: u64,
    effective_log: u8,
) -> Result<bool, SnapshotGenerationError> {
    let manifest = previous.manifest();
    if manifest.target_height >= target.height
        || source_tip_height.saturating_sub(manifest.target_height) > UNDO_RETENTION_DEPTH
        || manifest.effective_log_segment_size != effective_log
        || manifest.log_slots > target.log_slots
    {
        return Ok(false);
    }
    let Some(canonical) = snapshot.get_header(manifest.target_height)? else {
        return Ok(false);
    };
    let canonical_work = snapshot.get_chain_work(manifest.target_height)?;
    Ok(block_id(&canonical) == manifest.target_hash
        && canonical_work == Some(manifest.cumulative_chainwork)
        && canonical.state_root == manifest.state_root
        && canonical.log_slots == manifest.log_slots
        && canonical.active_slot_count == manifest.active_slot_count
        && canonical.alloc_counter == manifest.alloc_counter)
}

/// Reuse one immutable payload through a hard link. Snapshot generations live
/// under one export root, so this is normally metadata-only and consumes no
/// additional segment blocks. The copy fallback keeps the implementation
/// portable to filesystems that do not implement hard links.
fn reuse_snapshot_segment(
    previous: &SnapshotGeneration,
    target_directory: &Path,
    segment_id: u16,
    encoded_len: u32,
) -> Result<(), SnapshotGenerationError> {
    let source = segment_path(previous.directory(), segment_id);
    let metadata = fs::symlink_metadata(&source)?;
    if !metadata.file_type().is_file() || metadata.len() != u64::from(encoded_len) {
        return Err(SnapshotGenerationError::InvalidSegment(
            segment_id,
            "incremental base payload length is invalid",
        ));
    }
    let target = segment_path(target_directory, segment_id);
    match fs::hard_link(&source, &target) {
        Ok(()) => Ok(()),
        Err(_) => {
            let copied = fs::copy(&source, &target)?;
            if copied != u64::from(encoded_len) {
                return Err(SnapshotGenerationError::InvalidSegment(
                    segment_id,
                    "incremental payload copy was truncated",
                ));
            }
            File::open(&target)?.sync_all()?;
            Ok(())
        }
    }
}

fn reuse_snapshot_bridge_block(
    previous: &SnapshotGeneration,
    target_directory: &Path,
    descriptor: &SnapshotBridgeDescriptor,
) -> Result<bool, SnapshotGenerationError> {
    let Some(previous_descriptor) = previous.manifest().bridge_block(descriptor.height) else {
        return Ok(false);
    };
    if previous_descriptor != descriptor {
        return Ok(false);
    }
    let source = bridge_path(previous.directory(), descriptor.height);
    let metadata = match fs::symlink_metadata(&source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || metadata.len() != u64::from(descriptor.encoded_len) {
        return Ok(false);
    }
    let target = bridge_path(target_directory, descriptor.height);
    match fs::hard_link(&source, &target) {
        Ok(()) => Ok(true),
        Err(_) => {
            let copied = fs::copy(&source, &target)?;
            if copied != u64::from(descriptor.encoded_len) {
                return Err(SnapshotGenerationError::InvalidBridgeBlock(
                    descriptor.height,
                ));
            }
            File::open(&target)?.sync_all()?;
            Ok(true)
        }
    }
}

fn canonical_header(
    snapshot: &MdbxHistoricalReadSnapshot<'_>,
    height: u64,
) -> Result<crate::block_header::BlockHeader, SnapshotGenerationError> {
    snapshot
        .get_header(height)?
        .ok_or(SnapshotGenerationError::MissingHeader(height))
}

fn validate_log_slots(log_slots: u32) -> Result<(), SnapshotGenerationError> {
    if log_slots > LOG_SLOTS_MAX {
        return Err(SnapshotGenerationError::Corrupt(
            "header log_slots exceeds consensus maximum",
        ));
    }
    Ok(())
}

fn effective_log(log_slots: u32) -> u8 {
    log_slots.min(LOG_SEGMENT_SIZE as u32) as u8
}

fn segment_count(log_slots: u32) -> Result<usize, SnapshotGenerationError> {
    if log_slots <= LOG_SEGMENT_SIZE as u32 {
        return Ok(1);
    }
    1usize
        .checked_shl(log_slots - LOG_SEGMENT_SIZE as u32)
        .ok_or(SnapshotGenerationError::Corrupt(
            "segment domain does not fit usize",
        ))
}

fn slot_is_in_domain(slot_index: u32, log_slots: u32) -> bool {
    log_slots >= 32 || u64::from(slot_index) < (1u64 << log_slots)
}

fn validate_undo_preimage_creation_boundary(
    previous: SlotValue,
    parent: &BlockHeader,
) -> Result<(), &'static str> {
    if previous.is_empty()
        || crate::consensus::params::creation_id_within_boundary(
            previous.creation_id(),
            parent.alloc_counter,
            parent.height,
        )
    {
        Ok(())
    } else {
        Err("undo pre-image creation id exceeds parent boundary")
    }
}

type SegmentRollback = (u32, SlotValue);

fn collect_grouped_undo(
    snapshot: &MdbxHistoricalReadSnapshot<'_>,
    target_height: u64,
    tip_height: u64,
    tip_hash: [u8; 32],
    segment_log: u8,
) -> Result<BTreeMap<u16, Vec<SegmentRollback>>, SnapshotGenerationError> {
    let mut grouped: BTreeMap<u16, Vec<SegmentRollback>> = BTreeMap::new();
    let mut total_changes = 0usize;

    for height in (target_height + 1..=tip_height).rev() {
        let child = canonical_header(snapshot, height)?;
        let parent = canonical_header(snapshot, height - 1)?;
        if child.prev_block_hash != block_id(&parent) {
            return Err(SnapshotGenerationError::Corrupt(
                "retained canonical headers are not linked",
            ));
        }
        if height == tip_height && block_id(&child) != tip_hash {
            return Err(SnapshotGenerationError::SourceChanged);
        }
        if effective_log(parent.log_slots) != segment_log {
            return Err(SnapshotGenerationError::UnsupportedGeometry {
                target_log: parent.log_slots,
                tip_log: child.log_slots,
            });
        }
        let undo = snapshot
            .get_undo_log(height)?
            .ok_or(SnapshotGenerationError::MissingUndo(height))?;
        if undo.block_height != height
            || undo.log_slots_before != parent.log_slots
            || undo.active_slot_count_before != parent.active_slot_count
            || undo.alloc_counter_before != parent.alloc_counter
        {
            return Err(SnapshotGenerationError::Corrupt(
                "undo metadata does not match parent header",
            ));
        }
        if undo.slot_changes.len() > BLOCK_MAX_ACTIONS {
            return Err(SnapshotGenerationError::UndoTooLarge(height));
        }
        total_changes = total_changes
            .checked_add(undo.slot_changes.len())
            .ok_or(SnapshotGenerationError::UndoTooLarge(height))?;
        if total_changes > MAX_GROUPED_UNDO_CHANGES {
            return Err(SnapshotGenerationError::UndoTooLarge(height));
        }

        let mut seen_slots = BTreeSet::new();
        // Match `revert_block`: within-block order is reversed even though a
        // valid undo contains each physical slot exactly once.
        for &(slot_index, previous) in undo.slot_changes.iter().rev() {
            if !seen_slots.insert(slot_index) {
                return Err(SnapshotGenerationError::Corrupt(
                    "undo contains a duplicate physical slot",
                ));
            }
            if !slot_is_in_domain(slot_index, child.log_slots) {
                return Err(SnapshotGenerationError::Corrupt(
                    "undo slot lies outside child slot domain",
                ));
            }
            if !slot_is_in_domain(slot_index, parent.log_slots) && !previous.is_empty() {
                return Err(SnapshotGenerationError::Corrupt(
                    "new expansion-half undo pre-image is not empty",
                ));
            }
            validate_undo_preimage_creation_boundary(previous, &parent)
                .map_err(SnapshotGenerationError::Corrupt)?;
            let segment_id = (slot_index >> segment_log) as u16;
            let local_index = slot_index & ((1u32 << segment_log) - 1);
            grouped
                .entry(segment_id)
                .or_default()
                .push((local_index, previous));
        }
    }
    Ok(grouped)
}

fn apply_sparse_segment_rollbacks(
    entries: &mut BTreeMap<u16, SlotValue>,
    changes: &[SegmentRollback],
    effective_log: u8,
) -> Result<(), SnapshotGenerationError> {
    let capacity =
        1u32.checked_shl(u32::from(effective_log))
            .ok_or(SnapshotGenerationError::Corrupt(
                "segment-local rollback geometry overflows",
            ))?;
    for &(local_index, previous) in changes {
        if local_index >= capacity {
            return Err(SnapshotGenerationError::Corrupt(
                "segment-local undo index is out of range",
            ));
        }
        let local_index = local_index as u16;
        if previous.is_empty() {
            entries.remove(&local_index);
        } else {
            entries.insert(local_index, previous);
        }
    }
    Ok(())
}

fn validate_sparse_segment(
    segment_id: u16,
    sparse: SparseSegmentView<'_>,
    alloc_counter: u64,
    target_height: u64,
) -> Result<StateHash, SnapshotGenerationError> {
    let mut exact =
        StreamingSparseRoot::new(u32::from(sparse.effective_log_segment())).map_err(|_| {
            SnapshotGenerationError::InvalidSegment(segment_id, "invalid exact segment depth")
        })?;
    for (local, slot) in sparse.entries() {
        // Same tag-aware namespace rule as the historical carrier.
        let creation_in_target = crate::consensus::params::creation_id_within_boundary(
            slot.creation_id(),
            alloc_counter,
            target_height,
        );
        if !creation_in_target {
            return Err(SnapshotGenerationError::CreationIdExceedsTarget {
                segment_id,
                local_index: u32::from(local),
                creation_id: slot.creation_id(),
                alloc_counter,
            });
        }
        exact
            .push_leaf(u32::from(local), slot_leaf_hash(slot))
            .map_err(|_| {
                SnapshotGenerationError::InvalidSegment(
                    segment_id,
                    "live slot lies outside exact segment domain",
                )
            })?;
    }
    let exact_root = exact.finish().map_err(|_| {
        SnapshotGenerationError::InvalidSegment(segment_id, "exact segment stream did not close")
    })?;
    Ok(exact_root)
}

/// Reconstruct the consensus exact-state root from one compact exact subtree
/// root per non-empty segment. Missing segments are canonical zero subtrees.
/// At the maximum 32-bit slot domain this touches only 65,536 hashes/roots,
/// independent of the number of live UTXOs and raw snapshot bytes.
fn exact_state_root_from_manifest(
    manifest: &SnapshotGenerationManifest,
) -> Result<StateHash, SnapshotGenerationError> {
    let count = segment_count(manifest.log_slots)?;
    let effective_log = usize::from(manifest.effective_log_segment_size);
    let zero_roots = zero_slot_roots(effective_log);
    let mut roots = vec![zero_roots[effective_log]; count];
    for descriptor in &manifest.segments {
        roots[usize::from(descriptor.segment_id)] = descriptor.segment_root;
    }
    while roots.len() > 1 {
        let parent_count = roots.len() / 2;
        for index in 0..parent_count {
            roots[index] = state_node_hash(roots[2 * index], roots[2 * index + 1]);
        }
        roots.truncate(parent_count);
    }
    roots
        .into_iter()
        .next()
        .ok_or(SnapshotGenerationError::Corrupt(
            "snapshot exact-root tree is empty",
        ))
}

fn validate_manifest(manifest: &SnapshotGenerationManifest) -> Result<(), SnapshotGenerationError> {
    if manifest.version != SNAPSHOT_GENERATION_VERSION {
        return Err(SnapshotGenerationError::Corrupt(
            "unsupported snapshot manifest version",
        ));
    }
    validate_log_slots(manifest.log_slots)?;
    if manifest.effective_log_segment_size != effective_log(manifest.log_slots) {
        return Err(SnapshotGenerationError::Corrupt(
            "manifest effective segment log is inconsistent",
        ));
    }
    if manifest.target_height == 0 {
        if manifest.boundary_terminal_len != 0 || manifest.boundary_terminal_digest != [0; 32] {
            return Err(SnapshotGenerationError::Corrupt(
                "genesis snapshot carries a boundary terminal",
            ));
        }
    } else if manifest.boundary_terminal_len == 0
        || manifest.boundary_terminal_len as usize
            > history_step_terminal_bytes_limit(manifest.target_height)
    {
        return Err(SnapshotGenerationError::Corrupt(
            "snapshot boundary terminal length is outside bounds",
        ));
    }
    if manifest.bridge_tip_height < manifest.target_height {
        return Err(SnapshotGenerationError::Corrupt(
            "snapshot bridge tip precedes its state boundary",
        ));
    }
    let bridge_span = manifest.bridge_tip_height - manifest.target_height;
    if bridge_span > RECENT_BLOCK_RETENTION_DEPTH || bridge_span as usize != manifest.bridge.len() {
        return Err(SnapshotGenerationError::Corrupt(
            "snapshot bridge length is outside retention bounds",
        ));
    }
    if bridge_span == 0 {
        if manifest.bridge_terminal_len != 0 || manifest.bridge_terminal_digest != [0; 32] {
            return Err(SnapshotGenerationError::Corrupt(
                "empty snapshot bridge carries a separate terminal",
            ));
        }
    } else if manifest.bridge_terminal_len == 0
        || manifest.bridge_terminal_len as usize
            > history_step_terminal_bytes_limit(manifest.bridge_tip_height)
    {
        return Err(SnapshotGenerationError::Corrupt(
            "snapshot bridge terminal length is outside bounds",
        ));
    }
    let mut expected_height = manifest.target_height.saturating_add(1);
    for descriptor in &manifest.bridge {
        if descriptor.height != expected_height
            || descriptor.encoded_len == 0
            || descriptor.encoded_len as usize > MAX_BLOCK_BYTES
        {
            return Err(SnapshotGenerationError::InvalidBridgeBlock(
                descriptor.height,
            ));
        }
        expected_height = expected_height.saturating_add(1);
    }
    let expected_bridge_hash = manifest
        .bridge
        .last()
        .map_or(manifest.target_hash, |descriptor| descriptor.block_hash);
    if expected_bridge_hash != manifest.bridge_tip_hash {
        return Err(SnapshotGenerationError::Corrupt(
            "snapshot bridge tip hash does not match its final descriptor",
        ));
    }
    if bridge_span == 0 {
        if manifest.bridge_cumulative_chainwork != manifest.cumulative_chainwork {
            return Err(SnapshotGenerationError::Corrupt(
                "empty snapshot bridge changes cumulative chainwork",
            ));
        }
    } else if !crate::work_gt(
        &manifest.bridge_cumulative_chainwork,
        &manifest.cumulative_chainwork,
    ) {
        return Err(SnapshotGenerationError::Corrupt(
            "snapshot bridge does not advance cumulative chainwork",
        ));
    }
    if manifest.segments.len() > MAX_SNAPSHOT_MANIFEST_SEGMENTS {
        return Err(SnapshotGenerationError::Corrupt(
            "manifest segment count exceeds cap",
        ));
    }
    if manifest.segments.len() as u64 > manifest.active_slot_count {
        return Err(SnapshotGenerationError::Corrupt(
            "manifest has more non-empty segments than live slots",
        ));
    }
    if !manifest
        .segments
        .windows(2)
        .all(|pair| pair[0].segment_id < pair[1].segment_id)
    {
        return Err(SnapshotGenerationError::Corrupt(
            "manifest segment ids are not strictly increasing",
        ));
    }
    let domain_segments = segment_count(manifest.log_slots)?;
    let maximum_encoded_len =
        max_encoded_segment_len_for_eff_log(manifest.effective_log_segment_size).ok_or(
            SnapshotGenerationError::Corrupt("manifest segment geometry overflows"),
        )?;
    if maximum_encoded_len > MAX_SEGMENT_BYTES {
        return Err(SnapshotGenerationError::Corrupt(
            "manifest segment geometry exceeds segment byte cap",
        ));
    }
    let mut counted_live = 0u64;
    for descriptor in &manifest.segments {
        if usize::from(descriptor.segment_id) >= domain_segments {
            return Err(SnapshotGenerationError::InvalidSegment(
                descriptor.segment_id,
                "manifest id lies outside target domain",
            ));
        }
        let live_count = encoded_segment_live_count_from_len(
            manifest.effective_log_segment_size,
            descriptor.encoded_len as usize,
        )
        .ok_or(SnapshotGenerationError::InvalidSegment(
            descriptor.segment_id,
            "manifest encoded length has invalid sparse geometry",
        ))?;
        if live_count == 0 {
            return Err(SnapshotGenerationError::InvalidSegment(
                descriptor.segment_id,
                "manifest describes an empty segment",
            ));
        }
        counted_live = counted_live.checked_add(u64::from(live_count)).ok_or(
            SnapshotGenerationError::Corrupt("manifest live count overflows"),
        )?;
    }
    if counted_live != manifest.active_slot_count {
        return Err(SnapshotGenerationError::ActiveSlotCountMismatch {
            expected: manifest.active_slot_count,
            actual: counted_live,
        });
    }
    if exact_state_root_from_manifest(manifest)? != manifest.state_root {
        return Err(SnapshotGenerationError::ExactStateRootMismatch);
    }
    Ok(())
}

fn encode_manifest(
    manifest: &SnapshotGenerationManifest,
) -> Result<Vec<u8>, SnapshotGenerationError> {
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(manifest)
        .map_err(|error| SnapshotGenerationError::ManifestCodec(error.to_string()))?;
    if encoded.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(SnapshotGenerationError::Corrupt(
            "encoded snapshot manifest exceeds byte cap",
        ));
    }
    Ok(encoded)
}

fn decode_manifest(bytes: &[u8]) -> Result<SnapshotGenerationManifest, SnapshotGenerationError> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_MANIFEST_BYTES)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|error| SnapshotGenerationError::ManifestCodec(error.to_string()))
}

fn segment_path(generation_directory: &Path, segment_id: u16) -> PathBuf {
    generation_directory
        .join(SEGMENTS_DIRECTORY_NAME)
        .join(format!("{segment_id:05}.segment"))
}

fn bridge_path(generation_directory: &Path, height: u64) -> PathBuf {
    generation_directory
        .join(BRIDGE_DIRECTORY_NAME)
        .join(format!("{height:020}.block"))
}

fn snapshot_payload_digest(bytes: &[u8]) -> [u8; 32] {
    poseidon2b_hash_byte_slices(SNAPSHOT_PAYLOAD_DOMAIN, &[bytes])
}

fn read_authenticated_payload(
    path: &Path,
    declared_len: u32,
    expected_digest: [u8; 32],
    maximum_len: usize,
    context: &'static str,
) -> Result<Vec<u8>, SnapshotGenerationError> {
    let declared_len = declared_len as usize;
    if declared_len == 0 || declared_len > maximum_len {
        return Err(SnapshotGenerationError::InvalidPayload(context));
    }
    let mut file = File::open(path)?;
    if file.metadata()?.len() != declared_len as u64 {
        return Err(SnapshotGenerationError::InvalidPayload(context));
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(declared_len)
        .map_err(|_| SnapshotGenerationError::InvalidPayload(context))?;
    Read::by_ref(&mut file)
        .take(declared_len as u64 + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() != declared_len || snapshot_payload_digest(&encoded) != expected_digest {
        return Err(SnapshotGenerationError::InvalidPayload(context));
    }
    Ok(encoded)
}

fn write_synced_file(path: &Path, bytes: &[u8]) -> Result<(), SnapshotGenerationError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), SnapshotGenerationError> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn hex_digest(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

struct TemporaryGeneration {
    path: PathBuf,
    armed: bool,
}

impl TemporaryGeneration {
    fn create(export_root: &Path) -> Result<Self, SnapshotGenerationError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _ in 0..32 {
            let sequence = NEXT_TEMP_GENERATION.fetch_add(1, Ordering::Relaxed);
            let path = export_root.join(format!(
                ".snapshot-generation-{}-{now}-{sequence}.tmp",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path, armed: true }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(SnapshotGenerationError::Io(error)),
            }
        }
        Err(SnapshotGenerationError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary snapshot directory",
        )))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryGeneration {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use noid_core::Block128;
    #[cfg(unix)]
    use noid_poseidon2b::primitives::Address;
    #[cfg(unix)]
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    use crate::consensus::genesis::genesis_header;
    use crate::consensus::params::coinbase_creation_id;
    #[cfg(unix)]
    use crate::storage::{ConsensusMeta, FinalizedCheckpoint};

    #[test]
    fn spent_coinbase_undo_preimage_uses_parent_height_boundary() {
        let mut parent = genesis_header();
        parent.height = 7;
        parent.alloc_counter = 3;

        let at_parent_height = SlotValue::from_parts(
            1,
            coinbase_creation_id(parent.height),
            Block128(1),
            Block128(2),
        );
        assert!(validate_undo_preimage_creation_boundary(at_parent_height, &parent).is_ok());

        let from_future_height = SlotValue::from_parts(
            1,
            coinbase_creation_id(parent.height + 1),
            Block128(1),
            Block128(2),
        );
        assert_eq!(
            validate_undo_preimage_creation_boundary(from_future_height, &parent),
            Err("undo pre-image creation id exceeds parent boundary")
        );
    }

    #[test]
    fn manifest_sequence_length_bomb_is_bounded_and_rejected() {
        let manifest = SnapshotGenerationManifest {
            version: SNAPSHOT_GENERATION_VERSION,
            target_height: 1,
            target_hash: [1; 32],
            cumulative_chainwork: [2; 32],
            log_slots: 16,
            active_slot_count: 0,
            alloc_counter: 0,
            state_root: crate::exact_state_hash::zero_slot_roots(16)[16],
            effective_log_segment_size: 16,
            boundary_terminal_len: 1,
            boundary_terminal_digest: [3; 32],
            bridge_tip_height: 1,
            bridge_tip_hash: [1; 32],
            bridge_cumulative_chainwork: [2; 32],
            bridge_terminal_len: 0,
            bridge_terminal_digest: [0; 32],
            bridge: Vec::new(),
            segments: Vec::new(),
        };
        let mut encoded = encode_manifest(&manifest).unwrap();
        // Fixed-int bincode places the descriptor Vec length in the final
        // eight bytes for this empty fixture. The decoder limit and Serde's
        // cautious reserve reject it without attempting that capacity.
        let length_offset = encoded.len() - core::mem::size_of::<u64>();
        encoded[length_offset..].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            decode_manifest(&encoded),
            Err(SnapshotGenerationError::ManifestCodec(_))
        ));
    }

    #[test]
    fn oversized_manifest_file_rejects_before_payload_allocation() {
        let generation = tempfile::tempdir().unwrap();
        let path = generation.path().join(MANIFEST_FILE_NAME);
        let file = File::create(path).unwrap();
        file.set_len(MAX_MANIFEST_BYTES + 1).unwrap();
        drop(file);
        assert!(matches!(
            open_snapshot_generation(generation.path()),
            Err(SnapshotGenerationError::Corrupt(
                "snapshot manifest length is outside bounds"
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn incremental_generation_hard_links_unchanged_payload() {
        use std::os::unix::fs::MetadataExt;

        let previous_root = tempfile::tempdir().unwrap();
        fs::create_dir(previous_root.path().join(SEGMENTS_DIRECTORY_NAME)).unwrap();
        let source = segment_path(previous_root.path(), 7);
        fs::write(&source, b"immutable-segment").unwrap();
        let previous = SnapshotGeneration {
            directory: previous_root.path().to_path_buf(),
            manifest: SnapshotGenerationManifest {
                version: SNAPSHOT_GENERATION_VERSION,
                target_height: 1,
                target_hash: [1; 32],
                cumulative_chainwork: [2; 32],
                log_slots: 24,
                active_slot_count: 1,
                alloc_counter: 1,
                state_root: [3; 32],
                effective_log_segment_size: 16,
                boundary_terminal_len: 1,
                boundary_terminal_digest: [5; 32],
                bridge_tip_height: 1,
                bridge_tip_hash: [1; 32],
                bridge_cumulative_chainwork: [2; 32],
                bridge_terminal_len: 0,
                bridge_terminal_digest: [0; 32],
                bridge: Vec::new(),
                segments: vec![SnapshotSegmentDescriptor {
                    segment_id: 7,
                    segment_root: [4; 32],
                    encoded_len: b"immutable-segment".len() as u32,
                }],
            },
        };

        let target = tempfile::tempdir().unwrap();
        fs::create_dir(target.path().join(SEGMENTS_DIRECTORY_NAME)).unwrap();
        reuse_snapshot_segment(
            &previous,
            target.path(),
            7,
            b"immutable-segment".len() as u32,
        )
        .unwrap();
        let linked = segment_path(target.path(), 7);
        assert_eq!(fs::read(&linked).unwrap(), b"immutable-segment");
        assert_eq!(
            fs::metadata(&source).unwrap().ino(),
            fs::metadata(linked).unwrap().ino()
        );
    }

    #[cfg(unix)]
    #[test]
    fn unchanged_canonical_state_exports_incrementally_end_to_end() {
        use std::os::unix::fs::MetadataExt;

        let database = tempfile::tempdir().unwrap();
        let exports = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(database.path()).unwrap();
        let slot = SlotValue::from_parts(11, 1, Block128(0x22), Block128(0x33));
        let state = crate::state::ChainState::from_sparse_utxos(8, &[(7, slot)], 1).unwrap();
        let mut genesis = genesis_header();
        genesis.state_root = state.cached_state_root();
        genesis.log_slots = 8;
        genesis.active_slot_count = 1;
        genesis.alloc_counter = 1;
        let genesis_hash = block_id(&genesis);
        let genesis_work = crate::block_work(&genesis.difficulty_target);
        let genesis_meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: genesis_hash,
            cumulative_chainwork: genesis_work,
            finalized: FinalizedCheckpoint {
                height: 0,
                hash: genesis_hash,
            },
        };
        let columns = state.state.try_get_segment_columns(0).unwrap();
        store
            .commit_block(
                &genesis,
                &genesis_hash,
                &crate::consensus::da_prune::BlockUndoLog::empty(0, 8),
                &[(0, 8, Some(columns))],
                &[(0, 1, state.cached_exact_segment_root(0).unwrap())],
                &[],
                &[],
                None,
                state.circulating_supply_micronoid,
                &genesis_meta,
                true,
            )
            .unwrap();
        let first = export_snapshot_generation(&store, exports.path(), 0, None).unwrap();

        let mut child = genesis;
        child.height = 1;
        child.prev_block_hash = genesis_hash;
        child.timestamp += 1;
        child.nonce = 1;
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 7,
            amount: 11,
            owner: Address([0x33; 32]),
        };
        let coinbase = Transaction::new(TxBody {
            epoch_anchor: genesis_hash,
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        });
        child.tx_root = crate::compute_tx_root(std::slice::from_ref(&coinbase));
        let child_hash = block_id(&child);
        let block = crate::Block {
            header: child,
            transactions: vec![coinbase],
        };
        let mut terminal = crate::history_step::HistoryStepTerminalMetadata::new(
            1,
            crate::block_header::semantic_header_id(&child),
            0,
        )
        .unwrap()
        .encode_prefix()
        .to_vec();
        terminal.push(1);
        let child_terminal = terminal.clone();
        let bundle =
            crate::AcceptedBlockBundle::try_from_parts(block.to_bytes(), terminal).unwrap();
        let child_meta = ConsensusMeta {
            tip_height: 1,
            tip_hash: child_hash,
            cumulative_chainwork: crate::add_work(
                &genesis_work,
                &crate::block_work(&child.difficulty_target),
            ),
            finalized: genesis_meta.finalized,
        };
        let mut undo = crate::consensus::da_prune::BlockUndoLog::empty(1, 8);
        undo.active_slot_count_before = 1;
        undo.alloc_counter_before = 1;
        undo.tx_hashes = crate::block::try_compute_logical_txids(&block.transactions).unwrap();
        let tx_hashes = undo.tx_hashes.clone();
        store
            .commit_block(
                &child,
                &child_hash,
                &undo,
                &[],
                &[],
                &tx_hashes,
                &[],
                Some(crate::storage::mdbx_store::AcceptedBlockCommit::Complete(
                    &bundle,
                )),
                state.circulating_supply_micronoid,
                &child_meta,
                false,
            )
            .unwrap();

        let second = export_snapshot_generation(&store, exports.path(), 1, Some(&first)).unwrap();
        assert_eq!(
            second.read_encoded_segment(0).unwrap(),
            first.read_encoded_segment(0).unwrap()
        );
        assert_eq!(
            fs::metadata(segment_path(first.directory(), 0))
                .unwrap()
                .ino(),
            fs::metadata(segment_path(second.directory(), 0))
                .unwrap()
                .ino()
        );
        assert_eq!(second.manifest().target_height, 1);
        assert_eq!(second.manifest().state_root, child.state_root);

        let boundary_only =
            export_snapshot_boundary_generation(&store, exports.path(), 1, Some(&first)).unwrap();
        assert_eq!(boundary_only.manifest().target_height, 1);
        assert_eq!(boundary_only.manifest().bridge_tip_height, 1);
        assert_eq!(boundary_only.manifest().bridge_tip_hash, child_hash);
        assert!(boundary_only.manifest().bridge.is_empty());
        assert_eq!(
            boundary_only.read_boundary_terminal().unwrap(),
            child_terminal
        );
        assert_eq!(
            boundary_only.read_bridge_terminal().unwrap(),
            child_terminal
        );

        let mut changed_state = state.clone();
        let changed_slot = SlotValue::from_parts(12, 1, Block128(0x22), Block128(0x33));
        changed_state
            .state
            .apply_delta_unrooted(&[(7, changed_slot)])
            .unwrap();
        changed_state.circulating_supply_micronoid = u128::from(changed_slot.amount());
        let changed_root = changed_state.try_state_root().unwrap();
        let mut grandchild = child;
        grandchild.height = 2;
        grandchild.prev_block_hash = child_hash;
        grandchild.timestamp += 1;
        grandchild.nonce = 2;
        grandchild.state_root = changed_root;
        let grandchild_hash = block_id(&grandchild);
        let grandchild_block = crate::Block {
            header: grandchild,
            transactions: block.transactions.clone(),
        };
        let mut terminal = crate::history_step::HistoryStepTerminalMetadata::new(
            2,
            crate::block_header::semantic_header_id(&grandchild),
            0,
        )
        .unwrap()
        .encode_prefix()
        .to_vec();
        terminal.push(1);
        let grandchild_terminal = terminal.clone();
        let bundle =
            crate::AcceptedBlockBundle::try_from_parts(grandchild_block.to_bytes(), terminal)
                .unwrap();
        let grandchild_meta = ConsensusMeta {
            tip_height: 2,
            tip_hash: grandchild_hash,
            cumulative_chainwork: crate::add_work(
                &child_meta.cumulative_chainwork,
                &crate::block_work(&grandchild.difficulty_target),
            ),
            finalized: child_meta.finalized,
        };
        let mut undo = crate::consensus::da_prune::BlockUndoLog::empty(2, 8);
        undo.active_slot_count_before = 1;
        undo.alloc_counter_before = 1;
        undo.slot_changes.push((7, slot));
        undo.tx_hashes =
            crate::block::try_compute_logical_txids(&grandchild_block.transactions).unwrap();
        let tx_hashes = undo.tx_hashes.clone();
        let changed_columns = changed_state.state.try_get_segment_columns(0).unwrap();
        store
            .commit_block(
                &grandchild,
                &grandchild_hash,
                &undo,
                &[(0, 8, Some(changed_columns))],
                &[(0, 1, changed_state.cached_exact_segment_root(0).unwrap())],
                &tx_hashes,
                &[],
                Some(crate::storage::mdbx_store::AcceptedBlockCommit::Complete(
                    &bundle,
                )),
                changed_state.circulating_supply_micronoid,
                &grandchild_meta,
                false,
            )
            .unwrap();
        let bridged = export_snapshot_generation(&store, exports.path(), 1, Some(&second)).unwrap();
        assert_eq!(bridged.manifest().target_height, 1);
        assert_eq!(bridged.manifest().bridge_tip_height, 2);
        assert_eq!(bridged.manifest().bridge_tip_hash, grandchild_hash);
        assert_eq!(bridged.manifest().bridge.len(), 1);
        assert_eq!(bridged.read_boundary_terminal().unwrap(), child_terminal);
        assert_eq!(
            bridged.read_bridge_block_body(2).unwrap(),
            grandchild_block.to_bytes()
        );
        assert_eq!(bridged.read_bridge_terminal().unwrap(), grandchild_terminal);

        let third = export_snapshot_generation(&store, exports.path(), 2, Some(&second)).unwrap();
        assert_ne!(
            fs::metadata(segment_path(second.directory(), 0))
                .unwrap()
                .ino(),
            fs::metadata(segment_path(third.directory(), 0))
                .unwrap()
                .ino()
        );
        assert_ne!(
            second.manifest().segments[0].segment_root,
            third.manifest().segments[0].segment_root
        );
        assert_eq!(third.manifest().state_root, changed_root);
        assert_eq!(
            third.read_encoded_segment(0).unwrap().len(),
            encoded_segment_len_for_live_count(8, 1).unwrap()
        );

        let mut bad_exact_metadata = third.manifest().clone();
        bad_exact_metadata.segments[0].segment_root[0] ^= 1;
        assert!(matches!(
            validate_manifest(&bad_exact_metadata),
            Err(SnapshotGenerationError::ExactStateRootMismatch)
        ));
        let mut bad_live_metadata = third.manifest().clone();
        bad_live_metadata.active_slot_count += 1;
        assert!(matches!(
            validate_manifest(&bad_live_metadata),
            Err(SnapshotGenerationError::ActiveSlotCountMismatch { .. })
        ));
    }
}
