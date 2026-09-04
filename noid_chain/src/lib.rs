// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Chain layer for Paranoid.
//!
//! Ties transactions (`noid_tx`) to the on-chain state: the segmented raw UTXO
//! vector, exact state commitments, and block-header hash.
//!
//! Two primary entry points:
//!
//! - [`hash_block_header`] — canonical `H_BLOCK` with the `BLOCKHDR`
//!   capacity IV.
//! - [`apply_tx`] — applies one `TxBody` to mutable raw state. User block
//!   acceptance additionally verifies and commits an exact authenticated
//!   state transition.

pub mod accepted_block_bundle;
pub mod block;
pub mod block_header;
pub mod consensus;
pub mod exact_state_hash;
pub mod fri_state;
pub mod header_anchor;
pub mod history_step;
pub mod mempool;
pub mod segmented_state;
pub mod sparse_merkle;
pub mod state;
pub mod state_delta;
pub mod storage;
pub mod tx_tree;
pub mod wire;

// ---------------------------------------------------------------------------
// Raw state primitives (per-segment level)
// ---------------------------------------------------------------------------

pub use fri_state::{
    cap_to_seg_root, FriState, SlotValue, StateError, StateRoot, LOG_SEGMENT_SIZE, STATE_LOG_SLOTS,
};

// ---------------------------------------------------------------------------
// Segmented state
// ---------------------------------------------------------------------------

pub use segmented_state::{
    zero_segment_root_16, zero_segtree_node, SegmentColumns, SegmentedFriState, StateResizeError,
    MAX_SEGTREE_DEPTH, SEGMENT_SIZE,
};

// ---------------------------------------------------------------------------
// Storage backends
// ---------------------------------------------------------------------------

pub use storage::{
    reconstruct_historical_exact_state, CanonicalTipBinding, ConsensusMeta, FinalizedCheckpoint,
    HistoricalExactStateView, HistoricalStateError, MdbxChainContext, MdbxContextError, MdbxStore,
    RamBackend, StateBackend, StoreError, VerifiedReorgSuffix, VerifiedSnapshotBoundary,
};

// ---------------------------------------------------------------------------
// Block layer
// ---------------------------------------------------------------------------

pub use accepted_block_bundle::{
    AcceptedBlockBundle, AcceptedBlockBundleError, ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES,
    ACCEPTED_BLOCK_BUNDLE_MAGIC, MAX_ACCEPTED_BLOCK_BUNDLE_BYTES,
};
pub use block::{
    apply_genesis_block, canonical_block_wire_len, compute_tx_root,
    materialize_accepted_block_state, try_compute_logical_txids, try_compute_tx_root,
    validate_block_page_stream, Block, BlockApplyError, BlockPageStreamError, BlockPageStreamFacts,
    BLOCK_MAX_TXS, BLOCK_WIRE_FIXED_OVERHEAD, BLOCK_WIRE_HEADER_OFFSET, BLOCK_WIRE_MARKER,
    BLOCK_WIRE_NONCE_OFFSET,
};
pub use block_header::{block_id, hash_block_header, BlockHeader};
pub use header_anchor::{
    compute_header_chain_anchor, extend_header_chain_anchor, HeaderChainAnchor,
    HeaderChainAnchorError,
};
pub use history_step::{
    HistoryStepTerminalMetadata, HistoryStepTerminalMetadataError, HISTORY_STEP_CLASS_COUNT,
    HISTORY_STEP_TERMINAL_BINDING_BYTES, HISTORY_STEP_TERMINAL_VERSION,
};

// ---------------------------------------------------------------------------
// Chain state
// ---------------------------------------------------------------------------

pub use mempool::{Mempool, MempoolEntry, MempoolError};
pub use state::{
    apply_tx, apply_tx_at, ApplyError, ChainState, SparseUtxoBuildError, StateTransition,
};
pub use state_delta::{
    build_exact_action_surface, build_exact_action_surface_at_log_slots,
    build_exact_action_surface_for_transactions_at_log_slots, build_state_delta_action_surface,
    build_state_delta_witness, ExactActionSurface, StateDeltaAction, StateDeltaActionKind,
    StateDeltaActionSurface, StateDeltaError, StateDeltaWitness,
};
pub use wire::BLOCK_HEADER_WIRE_SIZE;

// ---------------------------------------------------------------------------
// Chainwork primitives (re-exported for external crates)
// ---------------------------------------------------------------------------

pub use consensus::difficulty::{add_work, block_work, work_gt};
pub use consensus::fork_choice::choose_chain_by_work;
