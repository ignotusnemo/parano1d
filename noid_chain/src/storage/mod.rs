// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! State storage backend abstraction .
//!
//! `StateBackend` decouples the chain state from its physical storage.
//! `RamBackend` is the sole current `StateBackend` implementor.
//! `MdbxChainContext` manages on-disk state through its own `MdbxStore` layer
//! rather than implementing this trait.
//!
//! A future MDBX-backed `StateBackend` should expose zero-copy segment views
//! instead of materializing `Vec<Block128>` when large state sizes make memcpy
//! bandwidth relevant.

pub mod historical_state;
pub mod mdbx_context;
pub mod mdbx_store;
pub mod memory;
pub mod meta;
pub mod native_payloads;
pub mod native_segment;
pub mod serial;
pub mod snapshot_generation;
pub mod snapshot_staging;

pub use historical_state::{
    reconstruct_historical_exact_state, CanonicalTipBinding, HistoricalExactStateView,
    HistoricalStateError,
};
pub use mdbx_context::{
    verify_history_step_terminal_candidate, HistoryStepTerminalClaim, IndexedReorgSuffixError,
    MdbxChainContext, MdbxContextError, VerifiedHistoryStepTerminal, VerifiedRecursiveSuffix,
    VerifiedReorgSuffix,
};
pub use mdbx_store::{
    MdbxStore, NativeCatalogCursor, NativeCatalogItem, NativeCatalogKind, NativeCatalogPage,
    NativeWalletCursor, NativeWalletItem, NativeWalletPage, NativeWalletQueryError,
    SnapshotHeaderInstallSource, StoreError, VerifiedHeaderBatchRecord, VerifiedOwnerPage,
    VerifiedOwnerSnapshot, VerifiedOwnerUtxo,
};
pub use memory::RamBackend;
pub use meta::{ConsensusMeta, FinalizedCheckpoint};
pub use serial::{
    decode_chain_tip, decode_chain_work, decode_consensus_meta, decode_header,
    decode_header_chain_anchor, decode_segment, decode_sparse_segment, decode_state_meta,
    decode_tx_index_value, decode_undo_log, encode_chain_tip, encode_chain_work,
    encode_consensus_meta, encode_header, encode_header_chain_anchor, encode_segment,
    encode_slot_value, encode_sparse_segment_entries, encode_state_meta, encode_tx_index_value,
    encode_undo_log, encoded_segment_len_for_live_count, encoded_segment_live_count_from_len,
    max_encoded_segment_len_for_eff_log, max_encoded_segments_total_len, u64_key,
    SparseSegmentView,
};
pub use snapshot_generation::{
    export_snapshot_boundary_generation, export_snapshot_generation, open_snapshot_generation,
    SnapshotBridgeDescriptor, SnapshotGeneration, SnapshotGenerationError,
    SnapshotGenerationManifest, SnapshotSegmentDescriptor,
};
pub use snapshot_staging::{
    AuthenticatedSnapshotMetadata, FinalizedSnapshotStaging, SnapshotStagingError,
    SnapshotStagingSession, VerifiedSnapshotBoundary,
};

use crate::block_header::BlockHeader;
use crate::fri_state::{SlotValue, StateRoot};
use crate::segmented_state::SegmentColumns;

/// Slot storage abstraction.
///
/// Implementations must be byte-identical for `root()`: two backends
/// initialised from the same sequence of `set_slot` calls MUST produce
/// the same `StateRoot`.
pub trait StateBackend {
    /// Read the value at `(seg_id, local_idx)`.
    fn get_slot(&self, seg_id: u16, local_idx: u16) -> SlotValue;

    /// Write the value at `(seg_id, local_idx)`.
    fn set_slot(&mut self, seg_id: u16, local_idx: u16, v: SlotValue);

    /// Load all three column vectors for segment `seg_id`.
    ///
    /// For virtual zero segments, returns all-zero columns without allocating
    /// (via static zero buffer or equivalent).
    fn load_segment_columns(&mut self, seg_id: u16) -> &SegmentColumns;

    /// Flush pending writes to durable storage (no-op for RAM backend).
    fn flush(&mut self);

    /// Compute (or return cached) global state root.
    fn state_root(&mut self) -> StateRoot;
}

// ---------------------------------------------------------------------------
// Block-level store traits
// ---------------------------------------------------------------------------

/// Read-only access to block headers (stored forever).
pub trait HeaderProvider {
    /// Retrieve a header by height. Always `Some` for finalised blocks.
    fn get_header(&self, height: u64) -> Option<BlockHeader>;
    /// Retrieve a header by its `H_BLOCK` hash. O(1) via hash-to-height index.
    fn get_header_by_hash(&self, hash: &[u8; 32]) -> Option<BlockHeader>;
}

/// Combined durable chain store.
///
/// Implementors provide unified access to headers, the transaction index, and
/// retained full blocks. `MdbxStore` implements this
/// trait for the disk-backed node.
pub trait BlockStore: Send + Sync {
    /// Current best tip: `(height, H_BLOCK hash)`.
    fn best_tip(&self) -> Option<(u64, [u8; 32])>;

    /// Retrieve a header by height. Returns `None` only if the height was
    /// never committed (headers are stored forever once committed).
    fn get_header(&self, height: u64) -> Result<Option<BlockHeader>, StoreError>;

    /// Retrieve a header by its `H_BLOCK` hash.
    fn get_header_by_hash(&self, hash: &[u8; 32]) -> Result<Option<BlockHeader>, StoreError>;

    /// Retrieve a retained block's raw bytes. Data is retained only for the
    /// bounded recent suffix. Its HistoryStep terminal is stored atomically.
    fn get_recent_block(&self, height: u64) -> Result<Option<Vec<u8>>, StoreError>;

    /// Look up a transaction by body hash. Returns `(block_height, tx_pos)`
    /// for O(1) logical-tx receipt lookup and Merkle path reconstruction.
    fn get_tx_index(&self, hash: &[u8; 32]) -> Result<Option<(u64, u32)>, StoreError>;
}
