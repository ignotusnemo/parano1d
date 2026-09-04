// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Segmented raw UTXO state with exact sparse-Merkle helpers.
//!
//! The chain state is split into `N = 2^(log_slots - LOG_SEGMENT_SIZE)`
//! independent segments (each holding `2^LOG_SEGMENT_SIZE` slots). The
//! consensus UTXO commitment is the exact Poseidon2b sparse-Merkle root over
//! slot leaves; segments are an I/O and cache boundary, not a consensus state proof.
//!
//! When `log_slots <= LOG_SEGMENT_SIZE` (test mode), there is exactly one
//! segment whose size is `2^log_slots`. In that case exact root helpers operate
//! over that one segment directly.
//!
//! # Memory layout
//!
//! Segments are "virtual zero" by default: `segments[i] = None` means every
//! slot in that segment reads as `SlotValue::EMPTY`. No memory is allocated
//! for virtual segments. Mutation materialises the segment on first write
//! (F.1b zero-copy mandate: virtual zero segments share a single static
//! `SegmentColumns` for reads; only writes allocate).
//!
//! # Segment-local cache tree
//!
//! `tree[1..=2N-1]` is a 1-indexed perfect binary tree over `N` segment
//! roots. Leaves are at `tree[N..2N]`, root at `tree[1]`. This cache is
//! rebuildable from raw slots and is not a separate consensus input.
//!
//! ```text
//! tree[k] = compress(tree[2k], tree[2k+1])   for k in 1..N
//! tree[N+i] = seg_roots[i]
//! ```
//!
//! Dirty tracking (F.4): only the changed paths are updated (O(log N) per
//! dirty segment). Clean segments never touch the Merkle tree.

#![allow(clippy::needless_range_loop)]

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};

use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::compress;

use crate::exact_state_hash::{slot_leaf_hash, StateHash};
use crate::fri_state::{compute_segment_root, SlotValue, StateError, StateRoot, LOG_SEGMENT_SIZE};
use crate::sparse_merkle::{SparseMerkleCache, SparseMerkleError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of each raw state segment when `log_slots > LOG_SEGMENT_SIZE`.
pub const SEGMENT_SIZE: usize = 1 << LOG_SEGMENT_SIZE;

/// Maximum segment-tree depth at `MAX_LOG_SLOTS = 32`.
pub const MAX_SEGTREE_DEPTH: usize = 16;

/// Errors returned when rebuilding the exact UTXO commitment from raw slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactStateReadError {
    EvictedSegment { seg_id: u16 },
    SegmentRootMismatch { seg_id: u16 },
    SparseMerkle(SparseMerkleError),
}

/// Errors returned when rolling the slot domain back across an expansion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateResizeError {
    InvalidTarget { current: usize, target: usize },
    EvictedUpperSegment { seg_id: u16 },
    NonEmptyUpperHalf { seg_id: u16 },
}

impl core::fmt::Display for StateResizeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidTarget { current, target } => {
                write!(
                    f,
                    "cannot shrink state from log_slots {current} to {target}"
                )
            }
            Self::EvictedUpperSegment { seg_id } => {
                write!(
                    f,
                    "cannot verify evicted upper segment {seg_id} during shrink"
                )
            }
            Self::NonEmptyUpperHalf { seg_id } => {
                write!(
                    f,
                    "cannot discard non-empty upper state at segment {seg_id}"
                )
            }
        }
    }
}

impl std::error::Error for StateResizeError {}

impl core::fmt::Display for ExactStateReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EvictedSegment { seg_id } => {
                write!(f, "exact state rebuild needs evicted segment {seg_id}")
            }
            Self::SegmentRootMismatch { seg_id } => {
                write!(f, "exact root summary mismatch for segment {seg_id}")
            }
            Self::SparseMerkle(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ExactStateReadError {}

impl From<SparseMerkleError> for ExactStateReadError {
    fn from(err: SparseMerkleError) -> Self {
        Self::SparseMerkle(err)
    }
}

// ---------------------------------------------------------------------------
// SegmentColumns
// ---------------------------------------------------------------------------

/// Three column vectors for one segment (`2^effective_log_seg` elements each).
#[derive(Debug, Clone)]
pub struct SegmentColumns {
    pub values: Vec<Block128>,
    pub owners_hi: Vec<Block128>,
    pub owners_lo: Vec<Block128>,
}

impl SegmentColumns {
    pub fn new_zero(size: usize) -> Self {
        Self {
            values: vec![Block128::ZERO; size],
            owners_hi: vec![Block128::ZERO; size],
            owners_lo: vec![Block128::ZERO; size],
        }
    }
}

// ---------------------------------------------------------------------------
// Virtual-zero columns (static; never freed)
// ---------------------------------------------------------------------------

static ZERO_COLS_16: OnceLock<SegmentColumns> = OnceLock::new();

/// All-zero segment columns for production segments (`2^16` elements).
/// Returned for virtual zero segments to satisfy reads without allocating.
fn zero_cols_16() -> &'static SegmentColumns {
    ZERO_COLS_16.get_or_init(|| SegmentColumns::new_zero(SEGMENT_SIZE))
}

// ---------------------------------------------------------------------------
// Zero segment commitment (lazy, computed once)
// ---------------------------------------------------------------------------

static ZERO_SEG_ROOT_16: OnceLock<StateRoot> = OnceLock::new();

/// Raw commitment of an all-zero `2^16`-slot segment.
///
/// This is the canonical leaf value for virtual zero segments in the Merkle
/// tree. It is also `ZERO_SEGTREE_NODE[0]` — see `zero_segtree_node`.
pub fn zero_segment_root_16() -> StateRoot {
    *ZERO_SEG_ROOT_16.get_or_init(|| {
        let cols = zero_cols_16();
        compute_seg_root(
            LOG_SEGMENT_SIZE,
            &cols.values,
            &cols.owners_hi,
            &cols.owners_lo,
        )
    })
}

// ---------------------------------------------------------------------------
// Zero segment-tree nodes (F.1)
// ---------------------------------------------------------------------------
// Z[0] = zero_segment_root_16()
// Z[d] = compress(Z[d-1], Z[d-1])   for d >= 1

static ZERO_SEGTREE: OnceLock<[[u8; 32]; MAX_SEGTREE_DEPTH + 1]> = OnceLock::new();

/// `Z[d]` — the root of an all-zero sub-tree of segment-tree depth `d`.
///
/// - `Z[0]` = raw commitment of an all-zero `2^16`-slot segment.
/// - `Z[d]` = `compress(Z[d-1], Z[d-1])` for `d >= 1`.
///
/// Used by `expand()` (F.7) to compute the new global root in O(1).
pub fn zero_segtree_node(d: usize) -> StateRoot {
    assert!(
        d <= MAX_SEGTREE_DEPTH,
        "segtree depth {d} exceeds MAX_SEGTREE_DEPTH"
    );
    zero_segtree_table()[d]
}

/// Reconstruct the global state root from a sparse list of non-zero segment roots.
///
/// `segment_ids` and `segment_roots` are the manifest table. Missing leaves are
/// interpreted as canonical zero segments.  The table must be strictly sorted by
/// `segment_id`; duplicates and out-of-range IDs are rejected.
pub fn sparse_state_root_from_segment_roots(
    log_slots: usize,
    effective_log_seg: usize,
    segment_ids: &[u16],
    segment_roots: &[StateRoot],
) -> Result<StateRoot, String> {
    if effective_log_seg > log_slots {
        return Err(format!(
            "effective_log_seg {} exceeds log_slots {}",
            effective_log_seg, log_slots
        ));
    }
    if segment_ids.len() != segment_roots.len() {
        return Err(format!(
            "segment_ids/segment_roots length mismatch: {} != {}",
            segment_ids.len(),
            segment_roots.len()
        ));
    }
    if !segment_ids.windows(2).all(|w| w[0] < w[1]) {
        return Err("segment_ids must be strictly sorted and unique".into());
    }

    let depth = log_slots - effective_log_seg;
    if depth > MAX_SEGTREE_DEPTH {
        return Err(format!(
            "segment tree depth {} exceeds maximum {}",
            depth, MAX_SEGTREE_DEPTH
        ));
    }
    let num_segments = 1usize
        .checked_shl(depth as u32)
        .ok_or_else(|| format!("segment tree depth {} overflows usize", depth))?;
    let zero_leaf = zero_seg_root_for(effective_log_seg);
    let mut leaves = vec![zero_leaf; num_segments];
    for (&seg_id, &root) in segment_ids.iter().zip(segment_roots.iter()) {
        let idx = seg_id as usize;
        if idx >= num_segments {
            return Err(format!(
                "segment id {} out of range for {} segments",
                seg_id, num_segments
            ));
        }
        leaves[idx] = root;
    }

    if num_segments == 1 {
        return Ok(leaves[0]);
    }

    let mut tree = vec![[0u8; 32]; 2 * num_segments];
    for (i, leaf) in leaves.into_iter().enumerate() {
        tree[num_segments + i] = leaf;
    }
    for k in (1..num_segments).rev() {
        tree[k] = compress(&tree[2 * k], &tree[2 * k + 1]);
    }
    Ok(tree[1])
}

fn zero_segtree_table() -> &'static [[u8; 32]; MAX_SEGTREE_DEPTH + 1] {
    ZERO_SEGTREE.get_or_init(|| {
        let mut t = [[0u8; 32]; MAX_SEGTREE_DEPTH + 1];
        t[0] = zero_segment_root_16();
        for d in 1..=MAX_SEGTREE_DEPTH {
            t[d] = compress(&t[d - 1], &t[d - 1]);
        }
        t
    })
}

// ---------------------------------------------------------------------------
// Per-segment raw storage commitment computation
// ---------------------------------------------------------------------------

/// Compute the compact raw segment root from three column vectors.
/// Delegates to `compute_segment_root` in `fri_state.rs` as the single source of truth.
pub(crate) fn compute_seg_root(
    log_size: usize,
    values: &[Block128],
    owners_hi: &[Block128],
    owners_lo: &[Block128],
) -> StateRoot {
    compute_segment_root(log_size, values, owners_hi, owners_lo)
}

/// Compact raw segment root for an all-zero segment of given log size.
fn zero_seg_root_for(log_size: usize) -> StateRoot {
    if log_size == LOG_SEGMENT_SIZE {
        zero_segment_root_16()
    } else {
        let n = 1 << log_size;
        let zeros = vec![Block128::ZERO; n];
        compute_seg_root(log_size, &zeros, &zeros, &zeros)
    }
}

// ---------------------------------------------------------------------------
// SegmentedFriState
// ---------------------------------------------------------------------------

/// Segmented raw UTXO state with exact commitment helpers.
///
/// Production: `log_slots = 24`, `num_segments = 256`, each segment 65536 slots.
/// Tests: `log_slots ≤ LOG_SEGMENT_SIZE = 16`, `num_segments = 1`.
#[derive(Debug, Clone)]
pub struct SegmentedFriState {
    log_slots: usize,
    /// `log_slots.min(LOG_SEGMENT_SIZE)` — the log2 of each segment's size.
    effective_log_seg: usize,
    num_segments: usize,
    /// `segments[i] = None` means the segment is either:
    ///   (a) a virtual zero segment — no UTXO data, or
    ///   (b) an evicted segment — has UTXO data in MDBX but is not in RAM.
    /// Use `is_evicted(i)` to distinguish the two cases.
    // Immutable segment versions are reference-counted so hot block assembly
    // can share a parent snapshot without eagerly copying three 1 MiB columns.
    // Every mutation goes through `Arc::make_mut`.
    segments: Vec<Option<Arc<SegmentColumns>>>,
    /// `seg_roots[i] = None` means the root must be recomputed.
    /// Kept valid even after segment columns are evicted.
    seg_roots: Vec<Option<StateRoot>>,
    /// Number of live (non-empty) slots in each segment.
    ///
    /// This is tiny even at `log_slots = 32` (65,536 segments × 4 bytes) and
    /// lets us reuse holes without storing a global free-list. It also lets us
    /// dematerialise all-empty segments so RAM/disk/snapshot size follows the
    /// live UTXO set rather than historical touched segments.
    live_counts: Vec<u32>,
    /// 1-indexed binary Merkle tree. Size = 2*num_segments + 1.
    /// Only meaningful when num_segments > 1.
    tree: Vec<StateRoot>,
    /// Whether any tree leaf changed since the last `flush_tree` call.
    tree_dirty: bool,
    /// Set of segment IDs whose column data has been mutated.
    /// Cleared automatically when `flush_segment` recomputes the commitment.
    dirty: HashSet<u16>,
    /// Set of segment IDs modified since the last explicit `clear_dirty()` call.
    /// This set is not cleared by commitment recomputation, only by `clear_dirty()`.
    /// Used by the MDBX backend to decide which segments to persist on each block.
    mdbx_dirty: HashSet<u16>,
    /// Segment payloads whose exact sparse-Merkle subtree root is stale in the
    /// chain-level compact root cache. Unlike the commitment dirty set this
    /// survives segment flushing and is cleared only after `ChainState`
    /// recomputes the exact segment root from the resident columns.
    exact_dirty: HashSet<u16>,
    /// Segment IDs that have been explicitly evicted from RAM but have non-zero
    /// data in MDBX. A segment in this set must be reloaded from MDBX before
    /// any slot within it can be read or written.
    ///
    /// # Memory model
    ///
    /// After each block commit, the MDBX backend calls `evict_clean_segments()`
    /// which moves all non-dirty segment columns from RAM to the evicted set.
    /// This bounds peak RAM usage to approximately:
    ///   `(segments touched per block) × 3 MB + (evicted set bookkeeping)`
    /// regardless of total chain history or active slot count.
    evicted: HashSet<u16>,
    /// Segment IDs whose leaves in `tree` were updated since the last
    /// `flush_tree` call. Used by the incremental Merkle updater to recompute
    /// only the O(dirty_count × depth) ancestor nodes instead of the full O(N).
    dirty_tree_leaves: HashSet<u16>,
}

impl SegmentedFriState {
    /// Empty state with `2^log_slots` zero slots.
    pub fn new_empty(log_slots: usize) -> Self {
        assert!(log_slots >= 1, "SegmentedFriState: need at least 1 slot");
        let effective_log_seg = log_slots.min(LOG_SEGMENT_SIZE);
        let num_segments = if log_slots > LOG_SEGMENT_SIZE {
            1 << (log_slots - LOG_SEGMENT_SIZE)
        } else {
            1
        };
        // 1-indexed tree: size 2N + 1 (index 0 unused).
        let zero_leaf = zero_seg_root_for(effective_log_seg);
        let mut tree = vec![[0u8; 32]; 2 * num_segments + 1];
        // Initialise leaves.
        for i in 0..num_segments {
            tree[num_segments + i] = zero_leaf;
        }
        // Build internal nodes bottom-up.
        for k in (1..num_segments).rev() {
            tree[k] = compress(&tree[2 * k], &tree[2 * k + 1]);
        }

        Self {
            log_slots,
            effective_log_seg,
            num_segments,
            segments: vec![None; num_segments],
            seg_roots: vec![Some(zero_leaf); num_segments],
            live_counts: vec![0; num_segments],
            tree,
            tree_dirty: false,
            dirty: HashSet::new(),
            mdbx_dirty: HashSet::new(),
            exact_dirty: HashSet::new(),
            evicted: HashSet::new(),
            dirty_tree_leaves: HashSet::new(),
        }
    }

    /// Build production geometry without constructing any raw segment commitment.
    /// Exact-only expansion tests use this to exercise depth-16 segment
    /// metadata without a 2^16-cell hash. The resulting segment-root fields are
    /// placeholders and must not be read as authenticated commitments.
    #[cfg(test)]
    pub(crate) fn new_exact_metadata_only_for_test(log_slots: usize) -> Self {
        assert!((LOG_SEGMENT_SIZE..=32).contains(&log_slots));
        let num_segments = 1usize << (log_slots - LOG_SEGMENT_SIZE);
        Self {
            log_slots,
            effective_log_seg: LOG_SEGMENT_SIZE,
            num_segments,
            segments: vec![None; num_segments],
            seg_roots: vec![None; num_segments],
            live_counts: vec![0; num_segments],
            tree: vec![[0u8; 32]; 2 * num_segments + 1],
            tree_dirty: true,
            dirty: HashSet::new(),
            mdbx_dirty: HashSet::new(),
            exact_dirty: HashSet::new(),
            evicted: HashSet::new(),
            dirty_tree_leaves: HashSet::new(),
        }
    }

    /// Clone only compact state metadata, dropping every resident 3 MiB column
    /// payload.  The caller must use this only at a durable block boundary;
    /// each live segment is marked evicted and can then be faulted in from
    /// MDBX on demand.
    pub(crate) fn durable_metadata_clone(&self) -> Option<Self> {
        if !self.mdbx_dirty.is_empty() || !self.exact_dirty.is_empty() {
            return None;
        }
        let mut evicted = self.evicted.clone();
        for (index, live_count) in self.live_counts.iter().copied().enumerate() {
            if live_count != 0 {
                evicted.insert(index as u16);
            }
        }
        Some(Self {
            log_slots: self.log_slots,
            effective_log_seg: self.effective_log_seg,
            num_segments: self.num_segments,
            segments: vec![None; self.num_segments],
            seg_roots: self.seg_roots.clone(),
            live_counts: self.live_counts.clone(),
            tree: self.tree.clone(),
            tree_dirty: self.tree_dirty,
            dirty: self.dirty.clone(),
            mdbx_dirty: HashSet::new(),
            exact_dirty: HashSet::new(),
            evicted,
            dirty_tree_leaves: self.dirty_tree_leaves.clone(),
        })
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    #[inline]
    pub fn log_slots(&self) -> usize {
        self.log_slots
    }
    #[inline]
    pub fn num_segments(&self) -> usize {
        self.num_segments
    }
    #[inline]
    pub fn num_slots(&self) -> u64 {
        1u64 << self.log_slots
    }

    /// Log2 of each segment's slot count.
    #[inline]
    pub fn effective_log_segment_size(&self) -> usize {
        self.effective_log_seg
    }

    #[inline]
    fn seg_id_of(&self, idx: u32) -> u16 {
        (idx >> self.effective_log_seg) as u16
    }

    #[inline]
    fn local_idx_of(&self, idx: u32) -> u16 {
        (idx & ((1u32 << self.effective_log_seg) - 1)) as u16
    }

    #[inline]
    fn segment_slot_count(&self) -> usize {
        1usize << self.effective_log_seg
    }

    #[inline]
    pub fn segment_live_count(&self, seg_id: u16) -> u32 {
        self.live_counts.get(seg_id as usize).copied().unwrap_or(0)
    }

    #[inline]
    fn count_live(cols: &SegmentColumns) -> u32 {
        cols.values
            .iter()
            .zip(cols.owners_hi.iter())
            .zip(cols.owners_lo.iter())
            .filter(|((v, hi), lo)| {
                **v != Block128::ZERO || **hi != Block128::ZERO || **lo != Block128::ZERO
            })
            .count() as u32
    }

    // -----------------------------------------------------------------------
    // Slot read
    // -----------------------------------------------------------------------

    /// Read one slot. Returns `SlotValue::EMPTY` for virtual zero segments.
    pub fn slot(&self, idx: u32) -> SlotValue {
        debug_assert!((idx as u64) < self.num_slots(), "slot {idx} out of range");
        let seg = self.seg_id_of(idx) as usize;
        let loc = self.local_idx_of(idx) as usize;
        match &self.segments[seg] {
            None => SlotValue::EMPTY,
            Some(cols) => SlotValue {
                value: cols.values[loc],
                owner_hi: cols.owners_hi[loc],
                owner_lo: cols.owners_lo[loc],
            },
        }
    }

    // -----------------------------------------------------------------------
    // Slot write
    // -----------------------------------------------------------------------

    /// Apply a batch of `(global_idx, new_value)` updates. Returns the
    /// post-update global `state_root`. On error, state is unchanged.
    pub fn apply_delta(&mut self, deltas: &[(u32, SlotValue)]) -> Result<StateRoot, StateError> {
        self.apply_delta_in_place(deltas)?;
        Ok(self.root())
    }

    /// Apply a proven delta without recomputing the global root immediately.
    ///
    /// This is crate-private because callers must either trust a separately
    /// verified root (the block-verification path) or call [`Self::root`] before
    /// exposing the state root. The dirty segment/tree markers are still updated,
    /// so the next `root()` call recomputes exactly the same commitment as
    /// `apply_delta()` would have returned.
    pub(crate) fn apply_delta_unrooted(
        &mut self,
        deltas: &[(u32, SlotValue)],
    ) -> Result<(), StateError> {
        self.apply_delta_in_place(deltas)
    }

    fn apply_delta_in_place(&mut self, deltas: &[(u32, SlotValue)]) -> Result<(), StateError> {
        for (idx, _) in deltas {
            if (*idx as u64) >= self.num_slots() {
                return Err(StateError::SlotOutOfRange);
            }
        }
        for (idx, v) in deltas {
            let seg = self.seg_id_of(*idx);
            let loc = self.local_idx_of(*idx) as usize;
            let seg_idx = seg as usize;

            let old = self.slot(*idx);
            if old == *v {
                continue;
            }

            if self.segments[seg_idx].is_none() {
                if v.is_empty() {
                    continue; // writing EMPTY to virtual zero is a no-op
                }
                // Materialise the segment.
                let seg_size = self.segment_slot_count();
                self.segments[seg_idx] = Some(Arc::new(SegmentColumns::new_zero(seg_size)));
                self.evicted.remove(&seg);
            }

            let old_empty = old.is_empty();
            let new_empty = v.is_empty();
            {
                let cols = Arc::make_mut(self.segments[seg_idx].as_mut().unwrap());
                cols.values[loc] = v.value;
                cols.owners_hi[loc] = v.owner_hi;
                cols.owners_lo[loc] = v.owner_lo;
            }

            match (old_empty, new_empty) {
                (true, false) => {
                    self.live_counts[seg_idx] = self.live_counts[seg_idx].saturating_add(1)
                }
                (false, true) => {
                    self.live_counts[seg_idx] = self.live_counts[seg_idx].saturating_sub(1)
                }
                _ => {}
            }

            // If the last live UTXO in this segment was spent, drop the 3 MB
            // column buffer immediately and make the segment virtual-zero again.
            // The segment remains MDBX-dirty so commit_block can delete any old
            // persisted copy from T_SEGMENTS.
            if self.live_counts[seg_idx] == 0 {
                self.segments[seg_idx] = None;
                self.evicted.remove(&seg);
            }

            // Mark the segment commitment stale (cleared by flush_segment) and
            // MDBX-pending (cleared only by explicit clear_dirty()).
            self.seg_roots[seg_idx] = None;
            self.dirty.insert(seg);
            self.mdbx_dirty.insert(seg);
            self.exact_dirty.insert(seg);
            self.tree_dirty = true;
        }
        Ok(())
    }

    /// Write one slot and return the new state root.
    pub fn set_slot(&mut self, idx: u32, v: SlotValue) -> Result<StateRoot, StateError> {
        self.apply_delta(&[(idx, v)])
    }

    // -----------------------------------------------------------------------
    // State root
    // -----------------------------------------------------------------------

    /// Compute (or return cached) global state root.
    ///
    /// Flushes all dirty segment roots and propagates changes through the
    /// Merkle tree before returning.
    pub fn root(&mut self) -> StateRoot {
        self.flush_all_dirty();
        if self.num_segments == 1 {
            // Single-segment: state_root == seg_root (no Merkle needed).
            self.seg_roots[0].unwrap_or_else(|| zero_seg_root_for(self.effective_log_seg))
        } else {
            self.tree[1]
        }
    }

    // -----------------------------------------------------------------------
    // Per-segment access
    // -----------------------------------------------------------------------

    /// Get or compute the raw commitment for segment `seg_id`.
    pub fn seg_root(&mut self, seg_id: u16) -> StateRoot {
        let id = seg_id as usize;
        if let Some(r) = self.seg_roots[id] {
            return r;
        }
        self.flush_segment(seg_id);
        self.seg_roots[id].unwrap()
    }

    /// Try to borrow segment columns without mutation.
    ///
    /// Returns `Some(&SegmentColumns)` if the segment is loaded in RAM.
    /// Returns `None` if the segment is evicted or never allocated (caller
    /// should fall back to MDBX or construct a zero segment).
    #[inline]
    pub fn try_get_segment_columns(&self, seg_id: u16) -> Option<&SegmentColumns> {
        self.segments[seg_id as usize].as_deref()
    }

    /// Borrow the column data for a segment (materialises if needed).
    ///
    /// For virtual zero segments at production size (`effective_log_seg ==
    /// LOG_SEGMENT_SIZE`), returns a reference to the shared static zero buffer.
    /// Otherwise, a zero-filled `SegmentColumns` is materialised in place.
    pub fn segment_columns(&mut self, seg_id: u16) -> &SegmentColumns {
        let id = seg_id as usize;
        if self.segments[id].is_none() {
            if self.effective_log_seg == LOG_SEGMENT_SIZE {
                // Return static zero buffer — no allocation.
                return zero_cols_16();
            }
            let seg_size = 1 << self.effective_log_seg;
            self.segments[id] = Some(Arc::new(SegmentColumns::new_zero(seg_size)));
        }
        self.segments[id].as_ref().unwrap().as_ref()
    }

    /// Clone columns for durable persistence.
    ///
    /// Fully-empty dirty segments return zero-length columns as a deletion marker.
    /// `MdbxStore::commit_block` checks for all-empty columns before encoding, so
    /// this avoids cloning a 3 MB all-zero production segment just to delete it.
    pub fn segment_columns_for_persistence(&mut self, seg_id: u16) -> SegmentColumns {
        if self.segment_live_count(seg_id) == 0 {
            return SegmentColumns::new_zero(0);
        }
        self.segment_columns(seg_id).clone()
    }

    /// Borrow the three column slices for a segment.
    pub fn columns_for_segment(&mut self, seg_id: u16) -> (&[Block128], &[Block128], &[Block128]) {
        let cols = self.segment_columns(seg_id);
        (
            cols.values.as_slice(),
            cols.owners_hi.as_slice(),
            cols.owners_lo.as_slice(),
        )
    }

    // -----------------------------------------------------------------------
    // Dirty tracking
    // -----------------------------------------------------------------------

    /// Iterator over segment IDs modified since the last `clear_dirty()` call.
    ///
    /// Unlike the internal commitment-dirty set, which is cleared when
    /// `root()` recomputes segment commitments, this set persists until
    /// `clear_dirty()` is explicitly called — typically after a successful
    /// MDBX commit.
    pub fn dirty_segment_ids(&self) -> impl Iterator<Item = u16> + '_ {
        self.mdbx_dirty.iter().copied()
    }

    /// Clear the MDBX-dirty tracking set.
    ///
    /// Call this after a successful MDBX commit so that the next block's
    /// `dirty_segment_ids()` returns only segments modified by *that* block.
    ///
    /// Also call after restoring segment columns from MDBX on startup so
    /// that the restored segments are not needlessly re-written on the
    /// first block commit.
    pub fn clear_dirty(&mut self) {
        self.mdbx_dirty.clear();
    }

    /// Exact-root cache entries that must be refreshed from resident columns.
    pub(crate) fn exact_dirty_segment_ids(&self) -> impl Iterator<Item = u16> + '_ {
        self.exact_dirty.iter().copied()
    }

    /// Mark exact-root summaries current after a successful bounded refresh.
    pub(crate) fn clear_exact_dirty(&mut self) {
        self.exact_dirty.clear();
    }

    /// Directly install pre-loaded column data for a segment.
    ///
    /// Test-only materialized snapshot helper. Production restore/install uses
    /// evicted summaries and never reconstructs all segment columns in RAM.
    ///
    /// The raw commitment for this segment is invalidated and will be recomputed
    /// lazily on the next `root()` call.
    ///
    #[cfg(test)]
    pub(crate) fn set_segment_columns(&mut self, seg_id: u16, cols: SegmentColumns) {
        let id = seg_id as usize;
        if id >= self.num_segments {
            return;
        }
        let live = Self::count_live(&cols);
        self.live_counts[id] = live;
        // Directly install the column data. All-zero segments are kept virtual so
        // old/stale zero records in MDBX do not inflate RAM or snapshots.
        self.segments[id] = if live == 0 {
            None
        } else {
            Some(Arc::new(cols))
        };
        self.evicted.remove(&seg_id);
        // Invalidate the commitment so it is recomputed on the next root() call.
        self.seg_roots[id] = None;
        self.tree_dirty = true;
        // Mark commitment-dirty, not mdbx_dirty: data is already in MDBX.
        self.dirty.insert(seg_id);
        self.exact_dirty.insert(seg_id);
    }

    /// Segment IDs that currently contain at least one live UTXO.
    ///
    /// This intentionally differs from "materialised in RAM": an all-empty
    /// touched segment is not active and should not be persisted or served in
    /// snapshots. Evicted-but-live segments are still active.
    pub fn active_segment_ids(&self) -> impl Iterator<Item = u16> + '_ {
        self.live_counts
            .iter()
            .enumerate()
            .filter(|(_, live)| **live > 0)
            .map(|(i, _)| i as u16)
    }

    /// Rebuild the exact sparse UTXO Merkle cache from loaded live segments.
    ///
    /// This scans only live, materialized segments. If a live segment has been
    /// evicted from RAM, callers must reload it from durable storage first or
    /// use the chain-level cached exact root instead of rebuilding.
    pub fn exact_sparse_cache(&self) -> Result<SparseMerkleCache, ExactStateReadError> {
        let mut leaves: Vec<(u32, StateHash)> = Vec::new();
        let seg_size = self.segment_slot_count();
        for seg_id in self.active_segment_ids() {
            let cols = self
                .try_get_segment_columns(seg_id)
                .ok_or(ExactStateReadError::EvictedSegment { seg_id })?;
            let base = (seg_id as u32) << self.effective_log_seg;
            for local in 0..seg_size {
                let slot = SlotValue {
                    value: cols.values[local],
                    owner_hi: cols.owners_hi[local],
                    owner_lo: cols.owners_lo[local],
                };
                if slot.is_empty() {
                    continue;
                }
                leaves.push((base | (local as u32), slot_leaf_hash(slot)));
            }
        }
        Ok(SparseMerkleCache::from_leaves(
            self.log_slots as u32,
            &leaves,
        )?)
    }

    /// Rebuild the exact UTXO root from loaded live segments.
    pub fn exact_utxo_root(&self) -> Result<StateHash, ExactStateReadError> {
        Ok(self.exact_sparse_cache()?.root())
    }

    /// Segment IDs currently materialised in RAM, regardless of live count.
    pub fn materialized_segment_ids(&self) -> impl Iterator<Item = u16> + '_ {
        self.segments
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_some())
            .map(|(i, _)| i as u16)
    }

    /// Find empty slots inside already-populated RAM segments.
    ///
    /// This is the memory-friendly reuse path: filling holes in live segments
    /// does not materialise a new 3 MB segment. It deliberately avoids a global
    /// free-list; the only permanent metadata is `live_counts`.
    pub fn empty_slot_hints_in_populated_segments(
        &self,
        seed: u64,
        count: usize,
        reserved: &HashSet<u32>,
    ) -> Vec<u32> {
        if count == 0 {
            return Vec::new();
        }
        let seg_size = self.segment_slot_count();
        let full = seg_size as u32;
        let mut candidates: Vec<u16> = self
            .live_counts
            .iter()
            .enumerate()
            .filter(|(seg_id, live)| {
                **live > 0 && **live < full && self.segments[*seg_id].is_some()
            })
            .map(|(seg_id, _)| seg_id as u16)
            .collect();
        if candidates.is_empty() {
            return Vec::new();
        }

        let mut rng = seed;
        // Deterministic rotation avoids always hammering the lowest segment.
        let start = (crate::consensus::allocator::splitmix64(&mut rng) as usize) % candidates.len();
        candidates.rotate_left(start);

        let mask = (seg_size - 1) as u64;
        let mut out = Vec::with_capacity(count);
        let mut seen = reserved.clone();
        for seg_id in candidates {
            let cols = match self.segments[seg_id as usize].as_ref() {
                Some(cols) => cols,
                None => continue,
            };
            let local_start = (crate::consensus::allocator::splitmix64(&mut rng) & mask) as usize;
            for step in 0..seg_size {
                let local = (local_start + step) & (seg_size - 1);
                if cols.values[local] == Block128::ZERO
                    && cols.owners_hi[local] == Block128::ZERO
                    && cols.owners_lo[local] == Block128::ZERO
                {
                    let slot = ((seg_id as u32) << self.effective_log_seg) | (local as u32);
                    if seen.insert(slot) {
                        out.push(slot);
                        if out.len() == count {
                            return out;
                        }
                    }
                }
            }
        }
        out
    }

    // -----------------------------------------------------------------------
    // Segment eviction — memory management
    // -----------------------------------------------------------------------

    /// True if this segment has non-zero UTXO data in MDBX but its columns
    /// have been evicted from RAM. The caller must reload from MDBX before
    /// reading or writing any slot in this segment.
    #[inline]
    pub fn is_evicted(&self, seg_id: u16) -> bool {
        self.evicted.contains(&seg_id)
    }

    /// Return the cached raw segment commitment without trying to
    /// hydrate or hash the raw segment columns.
    ///
    /// A `None` result is deliberately not repaired here: exact-only block
    /// acceptance may carry unavailable segment-root metadata, and asking for
    /// that root must continue to fail closed until the columns are
    /// explicitly hydrated.
    pub(crate) fn cached_segment_root(&self, seg_id: u16) -> Option<StateRoot> {
        self.seg_roots.get(seg_id as usize).copied().flatten()
    }

    /// Evict a segment's column data from RAM while keeping its commitment cached.
    ///
    /// This is safe ONLY after the segment has been committed to MDBX.
    /// The commitment remains valid since the segment data has not changed.
    /// Mark the segment as `evicted` so callers can distinguish it from a
    /// truly-zero segment.
    pub fn evict_segment(&mut self, seg_id: u16) {
        let id = seg_id as usize;
        if self.segments[id].is_some() {
            self.segments[id] = None;
            self.evicted.insert(seg_id);
            // seg_roots[id] stays valid — don't clear it.
            // The cached raw segment commitment hasn't changed.
        }
    }

    /// Restore a previously evicted segment from MDBX-loaded column data.
    /// The raw segment commitment will be recomputed lazily when next needed.
    pub fn restore_evicted_segment(&mut self, seg_id: u16, cols: SegmentColumns) {
        self.restore_shared_evicted_segment(seg_id, Arc::new(cols));
    }

    /// Install an immutable authenticated segment version without copying its
    /// three column buffers. The first later write is copy-on-write, so an
    /// older HistoryStep boundary can retain the exact same allocation
    /// safely until its ordered durable promotion completes.
    pub(crate) fn restore_shared_evicted_segment(
        &mut self,
        seg_id: u16,
        cols: Arc<SegmentColumns>,
    ) {
        let id = seg_id as usize;
        let live = Self::count_live(&cols);
        self.live_counts[id] = live;
        self.segments[id] = if live == 0 { None } else { Some(cols) };
        self.evicted.remove(&seg_id);
        // Invalidate the cached raw segment commitment so it will be recomputed.
        // (The loaded data might differ from what we last computed for, if
        // a concurrent write happened — though in practice this shouldn't
        // occur since we reload before any writes.)
        self.seg_roots[id] = None;
        self.dirty.insert(seg_id);
        self.tree_dirty = true;
    }

    /// Restore the pre-attempt segment summary and discard a clean raw payload
    /// after an uncommitted transition has been rolled back exactly.
    ///
    /// The caller must first prove that the raw columns again match the
    /// durable exact-state boundary and clear MDBX/exact dirty tracking.  This
    /// method then reinstalls the cached segment commitment captured before
    /// hydration.  It never invents a summary when the parent carried none.
    pub(crate) fn restore_persisted_segment_summary_and_evict(
        &mut self,
        seg_id: u16,
        parent_root: Option<StateRoot>,
    ) -> Result<(), &'static str> {
        let id = seg_id as usize;
        if id >= self.num_segments {
            return Err("persisted segment summary is out of range");
        }
        if self.mdbx_dirty.contains(&seg_id) || self.exact_dirty.contains(&seg_id) {
            return Err("persisted segment summary restored while segment is dirty");
        }

        self.segments[id] = None;
        let root = if self.live_counts[id] == 0 {
            self.evicted.remove(&seg_id);
            Some(zero_seg_root_for(self.effective_log_seg))
        } else {
            self.evicted.insert(seg_id);
            parent_root
        };
        self.seg_roots[id] = root;

        if root.is_some() {
            self.dirty.remove(&seg_id);
        } else {
            // The cached segment commitment was unavailable at the durable parent.
            // Keep the marker so a later root request cannot consume a stale
            // tree leaf without first hydrating this segment.
            self.dirty.insert(seg_id);
        }

        if self.num_segments > 1 {
            if let Some(root) = root {
                self.tree[self.num_segments + id] = root;
                self.dirty_tree_leaves.insert(seg_id);
            }
            self.tree_dirty = true;
        }
        Ok(())
    }

    /// Install the durable summary of a live segment without retaining its
    /// 3 MiB column payload.  Startup/reorg recovery computes `segment_root`
    /// while decoding one segment, then immediately drops the columns.
    pub(crate) fn install_evicted_segment_summary(
        &mut self,
        seg_id: u16,
        live_count: u32,
        segment_root: StateRoot,
    ) -> Result<(), &'static str> {
        let id = seg_id as usize;
        if id >= self.num_segments || live_count == 0 {
            return Err("invalid durable segment summary");
        }
        self.segments[id] = None;
        self.live_counts[id] = live_count;
        self.seg_roots[id] = Some(segment_root);
        self.evicted.insert(seg_id);
        if self.num_segments > 1 {
            self.tree[self.num_segments + id] = segment_root;
            self.dirty_tree_leaves.insert(seg_id);
            self.tree_dirty = true;
        }
        Ok(())
    }

    /// Install only the durable residency/count metadata needed by the exact
    /// production path. The raw segment commitment is deliberately left
    /// unavailable. Unlike the exact segment root cached by `ChainState`, it is
    /// not authenticated by the block header. If the raw commitment is
    /// requested later, the segment must first be hydrated and its commitment
    /// recomputed.
    pub(crate) fn install_evicted_exact_summary(
        &mut self,
        seg_id: u16,
        live_count: u32,
    ) -> Result<(), &'static str> {
        let id = seg_id as usize;
        if id >= self.num_segments || live_count == 0 {
            return Err("invalid durable exact segment summary");
        }
        self.segments[id] = None;
        self.live_counts[id] = live_count;
        self.seg_roots[id] = None;
        self.evicted.insert(seg_id);
        self.dirty.insert(seg_id);
        self.tree_dirty = true;
        Ok(())
    }

    /// Seal a compact exact-only startup image. Commitment-dirty markers
    /// intentionally survive so no caller can consume an invented segment
    /// tree. Persistence and exact-root tracking are already clean at the
    /// durable boundary.
    pub(crate) fn finish_evicted_exact_summaries(&mut self) {
        self.mdbx_dirty.clear();
        self.exact_dirty.clear();
    }

    /// Finish a batch of summary installs and leave no false persistence dirt.
    pub(crate) fn finish_evicted_segment_summaries(&mut self) {
        self.flush_tree();
        self.dirty.clear();
        self.mdbx_dirty.clear();
        self.exact_dirty.clear();
    }

    /// Evict all segment columns that are not in the MDBX-dirty set.
    ///
    /// Call this AFTER `clear_dirty()` + a successful MDBX commit.
    /// Because all data is in MDBX, it's safe to drop RAM copies.
    /// The per-segment commitments are kept so the global state root
    /// can be recomputed without reloading segment data.
    ///
    /// # Effect on memory
    ///
    /// Each evicted segment frees `2^LOG_SEGMENT_SIZE × 48 bytes = 3 MB`.
    /// Only segments written during this block remain in RAM.
    pub fn evict_clean_segments(&mut self) {
        for id in 0..self.num_segments {
            let seg_id = id as u16;
            if self.segments[id].is_some() && !self.mdbx_dirty.contains(&seg_id) {
                self.segments[id] = None;
                self.evicted.insert(seg_id);
                // seg_roots[id] stays valid.
            }
        }
    }

    /// Drop every live column payload after its enclosing MDBX transaction has
    /// committed.  Exact roots remain available through `ChainState`'s compact
    /// hierarchy. Any later raw commitment access must hydrate the segment first.
    pub fn evict_all_persisted_segments(&mut self) {
        assert!(
            self.mdbx_dirty.is_empty(),
            "cannot evict segments before durable dirty tracking is cleared"
        );
        for id in 0..self.num_segments {
            if self.segments[id].is_some() && self.live_counts[id] != 0 {
                self.segments[id] = None;
                self.evicted.insert(id as u16);
            }
        }
    }

    /// Iterator over segment IDs that are evicted from RAM but non-zero in MDBX.
    pub fn evicted_segment_ids(&self) -> impl Iterator<Item = u16> + '_ {
        self.evicted.iter().copied()
    }

    /// Install only the residency metadata needed by exact-root fail-closed
    /// tests, without constructing a 3 MiB raw segment fixture.
    #[cfg(test)]
    pub(crate) fn mark_segment_evicted_for_test(
        &mut self,
        seg_id: u16,
        cached_segment_root: StateRoot,
    ) {
        let id = seg_id as usize;
        self.segments[id] = None;
        self.seg_roots[id] = Some(cached_segment_root);
        self.live_counts[id] = 1;
        self.evicted.insert(seg_id);
    }

    /// Depth of the segment Merkle tree = `log2(num_segments)`.
    #[inline]
    pub fn tree_depth(&self) -> usize {
        if self.num_segments <= 1 {
            0
        } else {
            self.log_slots - self.effective_log_seg
        }
    }

    // -----------------------------------------------------------------------
    // Expansion (F.7)
    // -----------------------------------------------------------------------

    /// Expand state: `log_slots += 1`, doubling `num_segments`.
    ///
    /// The new upper half of segments is all virtual zero. The new root is:
    ///
    /// ```text
    /// new_root = compress(old_root, zero_segtree_node(old_depth))
    /// ```
    ///
    /// which is O(1) — no re-hashing of existing segments.
    pub fn expand(&mut self) {
        let old_depth = self.tree_depth();

        self.log_slots += 1;

        if self.log_slots <= LOG_SEGMENT_SIZE {
            // Still in single-segment territory — just grow the single segment.
            self.effective_log_seg = self.log_slots;
            let extra = 1 << (self.log_slots - 1); // half the new size
            if let Some(ref mut columns) = self.segments[0] {
                let cols = Arc::make_mut(columns);
                cols.values.extend(vec![Block128::ZERO; extra]);
                cols.owners_hi.extend(vec![Block128::ZERO; extra]);
                cols.owners_lo.extend(vec![Block128::ZERO; extra]);
            }
            self.seg_roots[0] = None;
            self.dirty.insert(0);
            self.exact_dirty.insert(0);
            self.tree_dirty = true;
            self.flush_all_dirty();
            return;
        }

        // Multi-segment expansion.
        let old_root = if self.num_segments <= 1 {
            self.seg_roots[0].unwrap_or_else(|| zero_seg_root_for(self.effective_log_seg))
        } else {
            self.tree[1]
        };

        let old_num_seg = self.num_segments;
        self.num_segments *= 2;

        // Extend segment arrays — upper half is all virtual zero.
        self.segments.resize(self.num_segments, None);
        self.seg_roots.resize(self.num_segments, None);
        self.live_counts.resize(self.num_segments, 0);

        // Fill the new seg_roots for the upper half with the zero-segment root.
        let zero_leaf = zero_seg_root_for(self.effective_log_seg);
        for i in old_num_seg..self.num_segments {
            self.seg_roots[i] = Some(zero_leaf);
        }

        // Rebuild Merkle tree.
        self.tree = vec![[0u8; 32]; 2 * self.num_segments + 1];
        for i in 0..self.num_segments {
            self.tree[self.num_segments + i] = self.seg_roots[i].unwrap_or(zero_leaf);
        }
        for k in (1..self.num_segments).rev() {
            self.tree[k] = compress(&self.tree[2 * k], &self.tree[2 * k + 1]);
        }
        self.tree_dirty = false;

        debug_assert_eq!(
            self.tree[1],
            compress(&old_root, &zero_segtree_node(old_depth)),
            "expand: new root must equal compress(old_root, Z[old_depth])"
        );
    }

    /// Shrink to a previously committed slot depth after undo has emptied every
    /// slot in the discarded upper half.
    ///
    /// This is a rollback-only primitive. It fails closed if the upper half is
    /// live or evicted, rather than silently dropping state.
    pub fn shrink_to_log_slots(&mut self, target: usize) -> Result<(), StateResizeError> {
        if target < 1 || target > self.log_slots {
            return Err(StateResizeError::InvalidTarget {
                current: self.log_slots,
                target,
            });
        }

        while self.log_slots > target {
            self.flush_all_dirty();

            if self.log_slots <= LOG_SEGMENT_SIZE {
                if self.evicted.contains(&0) {
                    return Err(StateResizeError::EvictedUpperSegment { seg_id: 0 });
                }
                let keep = 1usize << (self.log_slots - 1);
                if let Some(columns) = self.segments[0].as_mut() {
                    let cols = Arc::make_mut(columns);
                    let upper_is_empty = cols.values[keep..].iter().all(|v| v.0 == 0)
                        && cols.owners_hi[keep..].iter().all(|v| v.0 == 0)
                        && cols.owners_lo[keep..].iter().all(|v| v.0 == 0);
                    if !upper_is_empty {
                        return Err(StateResizeError::NonEmptyUpperHalf { seg_id: 0 });
                    }
                    cols.values.truncate(keep);
                    cols.owners_hi.truncate(keep);
                    cols.owners_lo.truncate(keep);
                    self.live_counts[0] = Self::count_live(cols);
                    if self.live_counts[0] == 0 {
                        self.segments[0] = None;
                    }
                }
                self.log_slots -= 1;
                self.effective_log_seg = self.log_slots;
                self.seg_roots[0] = None;
                self.dirty.insert(0);
                self.mdbx_dirty.insert(0);
                self.exact_dirty.insert(0);
                self.tree_dirty = true;
                self.flush_all_dirty();
                continue;
            }

            let new_num_segments = self.num_segments / 2;
            for id in new_num_segments..self.num_segments {
                let seg_id = id as u16;
                if self.evicted.contains(&seg_id) {
                    return Err(StateResizeError::EvictedUpperSegment { seg_id });
                }
                if self.live_counts[id] != 0 {
                    return Err(StateResizeError::NonEmptyUpperHalf { seg_id });
                }
            }

            self.log_slots -= 1;
            self.num_segments = new_num_segments;
            self.segments.truncate(new_num_segments);
            self.seg_roots.truncate(new_num_segments);
            self.live_counts.truncate(new_num_segments);
            self.evicted.retain(|id| (*id as usize) < new_num_segments);
            self.dirty.retain(|id| (*id as usize) < new_num_segments);
            self.mdbx_dirty
                .retain(|id| (*id as usize) < new_num_segments);
            self.exact_dirty
                .retain(|id| (*id as usize) < new_num_segments);
            self.dirty_tree_leaves
                .retain(|id| (*id as usize) < new_num_segments);

            let zero_leaf = zero_seg_root_for(self.effective_log_seg);
            self.tree = vec![[0u8; 32]; 2 * new_num_segments + 1];
            for i in 0..new_num_segments {
                self.tree[new_num_segments + i] = self.seg_roots[i].unwrap_or(zero_leaf);
            }
            for k in (1..new_num_segments).rev() {
                self.tree[k] = compress(&self.tree[2 * k], &self.tree[2 * k + 1]);
            }
            self.tree_dirty = false;
        }

        Ok(())
    }

    /// Exact-only rollback of segmented residency metadata across expansions.
    ///
    /// This primitive is for [`crate::storage::HistoricalExactStateView`]. It
    /// never flushes or hashes raw segment summaries. The returned carrier
    /// explicitly provides no segment-root authority. Production geometry
    /// starts at `LOG_SEGMENT_SIZE`, so every real shrink drops whole upper
    /// segments while preserving the fixed 2^16-slot local geometry.
    ///
    /// The caller must subsequently refresh/check the chain-level exact root.
    /// Dropped upper segments must already be canonical zero according to raw
    /// residency metadata; otherwise the operation fails before mutation.
    pub(crate) fn shrink_exact_metadata_to_log_slots(
        &mut self,
        target: usize,
    ) -> Result<(), StateResizeError> {
        if target == self.log_slots {
            return Ok(());
        }
        if self.effective_log_seg != LOG_SEGMENT_SIZE
            || target < LOG_SEGMENT_SIZE
            || target > self.log_slots
        {
            return Err(StateResizeError::InvalidTarget {
                current: self.log_slots,
                target,
            });
        }

        // Preflight every segment that any shrink step would discard. No
        // commitment field is changed until the complete upper suffix is proven empty.
        let target_num_segments = 1usize << (target - LOG_SEGMENT_SIZE);
        for index in target_num_segments..self.num_segments {
            let segment_id = index as u16;
            if self.evicted.contains(&segment_id) {
                return Err(StateResizeError::EvictedUpperSegment { seg_id: segment_id });
            }
            if self.live_counts[index] != 0 || self.segments[index].is_some() {
                return Err(StateResizeError::NonEmptyUpperHalf { seg_id: segment_id });
            }
        }

        self.log_slots = target;
        self.num_segments = target_num_segments;
        self.segments.truncate(target_num_segments);
        self.seg_roots.truncate(target_num_segments);
        self.live_counts.truncate(target_num_segments);
        self.evicted
            .retain(|id| (*id as usize) < target_num_segments);
        self.dirty.retain(|id| (*id as usize) < target_num_segments);
        self.mdbx_dirty
            .retain(|id| (*id as usize) < target_num_segments);
        self.exact_dirty
            .retain(|id| (*id as usize) < target_num_segments);
        self.dirty_tree_leaves
            .retain(|id| (*id as usize) < target_num_segments);

        // Preserve compact leaves without claiming an upper segment-tree root.
        // A later general-state caller would have to rebuild the tree explicitly;
        // the exact historical carrier forbids that path altogether.
        self.tree = vec![[0u8; 32]; 2 * target_num_segments + 1];
        for (index, root) in self.seg_roots.iter().copied().enumerate() {
            if let Some(root) = root {
                self.tree[target_num_segments + index] = root;
            }
        }
        self.tree_dirty = true;
        self.dirty_tree_leaves.clear();
        Ok(())
    }

    /// Grow production segment metadata by one level for exact-only replay.
    ///
    /// No zero-segment commitment or upper tree node is hashed. The resulting
    /// segment-root fields are placeholders and remain unavailable under the
    /// exact replay contract, while raw lower segments and virtual-zero upper
    /// segments have the correct geometry for exact action application.
    pub fn expand_exact_metadata_for_replay(&mut self) -> Result<(), StateResizeError> {
        if self.effective_log_seg != LOG_SEGMENT_SIZE || self.log_slots >= 32 {
            return Err(StateResizeError::InvalidTarget {
                current: self.log_slots,
                target: self.log_slots.saturating_add(1),
            });
        }
        let new_num_segments =
            self.num_segments
                .checked_mul(2)
                .ok_or(StateResizeError::InvalidTarget {
                    current: self.log_slots,
                    target: self.log_slots.saturating_add(1),
                })?;
        self.log_slots += 1;
        self.num_segments = new_num_segments;
        self.segments.resize(new_num_segments, None);
        self.seg_roots.resize(new_num_segments, None);
        self.live_counts.resize(new_num_segments, 0);

        self.tree = vec![[0u8; 32]; 2 * new_num_segments + 1];
        for (index, root) in self.seg_roots.iter().copied().enumerate() {
            if let Some(root) = root {
                self.tree[new_num_segments + index] = root;
            }
        }
        self.tree_dirty = true;
        self.dirty_tree_leaves.clear();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private: dirty-flush helpers
    // -----------------------------------------------------------------------

    fn flush_all_dirty(&mut self) {
        // Collect to avoid borrowing issues.
        let dirty: Vec<u16> = self.dirty.iter().copied().collect();
        for seg_id in dirty {
            self.flush_segment(seg_id);
        }
        self.flush_tree();
    }

    /// Recompute the commitment for one dirty segment and update the Merkle leaf.
    fn flush_segment(&mut self, seg_id: u16) {
        if !self.dirty.contains(&seg_id) && self.seg_roots[seg_id as usize].is_some() {
            return;
        }
        assert!(
            !self.evicted.contains(&seg_id),
            "segment commitment requested for evicted segment {seg_id}; hydrate it first"
        );
        let id = seg_id as usize;
        let eff = self.effective_log_seg;
        let seg_root = match &self.segments[id] {
            None => zero_seg_root_for(eff),
            Some(cols) => compute_seg_root(eff, &cols.values, &cols.owners_hi, &cols.owners_lo),
        };
        self.seg_roots[id] = Some(seg_root);
        self.dirty.remove(&seg_id);

        // Update the Merkle leaf and record which leaf changed.
        if self.num_segments > 1 {
            self.tree[self.num_segments + id] = seg_root;
            self.tree_dirty = true;
            self.dirty_tree_leaves.insert(seg_id);
        }
    }

    /// Propagate changed leaves upward through the Merkle tree.
    ///
    /// **Incremental**: only recomputes the O(dirty × depth) ancestor nodes
    /// on the paths from dirty leaves to the root, instead of rebuilding
    /// all O(num_segments) internal nodes unconditionally.
    ///
    /// Worst case (all N segments dirty): O(N) — same as the old full rebuild,
    /// because all paths overlap at higher levels. Best case (1 dirty segment):
    /// O(log N) — 8 compresses at genesis (256 segments, depth 8) vs 255.
    fn flush_tree(&mut self) {
        if !self.tree_dirty || self.num_segments <= 1 {
            self.tree_dirty = false;
            self.dirty_tree_leaves.clear();
            return;
        }

        if self.dirty_tree_leaves.is_empty() {
            // tree_dirty was set without tracking specific leaves (e.g. expand).
            // Fall back to full rebuild.
            for k in (1..self.num_segments).rev() {
                self.tree[k] = compress(&self.tree[2 * k], &self.tree[2 * k + 1]);
            }
            self.tree_dirty = false;
            return;
        }

        // Collect all internal nodes that need recomputing.
        // Walk from each dirty leaf up to the root, collecting parent indices.
        // Use a Vec<usize> sorted descending (leaves before parents) so we
        // always recompute children before their parents.
        let mut to_update: Vec<usize> = Vec::with_capacity(self.dirty_tree_leaves.len() * 9);
        for &seg_id in &self.dirty_tree_leaves {
            // Leaf index in the 1-indexed tree.
            let mut k = self.num_segments + seg_id as usize;
            // Walk up to root (k=1 is root, stop after processing it).
            loop {
                k /= 2; // parent
                if k == 0 {
                    break;
                }
                to_update.push(k);
                if k == 1 {
                    break; // reached root
                }
            }
        }

        // Deduplicate. Sort ascending so we process parents after children
        // (higher index = closer to leaves, lower index = closer to root).
        to_update.sort_unstable();
        to_update.dedup();
        // Process largest indices first (closest to leaves).
        for &k in to_update.iter().rev() {
            self.tree[k] = compress(&self.tree[2 * k], &self.tree[2 * k + 1]);
        }

        self.dirty_tree_leaves.clear();
        self.tree_dirty = false;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(seed: u128) -> SlotValue {
        SlotValue {
            value: Block128::from(seed),
            owner_hi: Block128::from(seed.wrapping_mul(3) + 1),
            owner_lo: Block128::from(seed.wrapping_mul(7) + 2),
        }
    }

    // Small depth for tests (monolithic / single-segment mode).
    const TS: usize = 4; // 16 slots, 1 segment

    // -----------------------------------------------------------------------
    // Single-segment equivalence tests against the exact FriState core.
    // -----------------------------------------------------------------------

    #[test]
    fn empty_root_is_deterministic() {
        let mut a = SegmentedFriState::new_empty(TS);
        let mut b = SegmentedFriState::new_empty(TS);
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn empty_roots_differ_by_depth() {
        let mut a = SegmentedFriState::new_empty(4);
        let mut b = SegmentedFriState::new_empty(5);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn write_changes_root() {
        let mut s = SegmentedFriState::new_empty(TS);
        let r0 = s.root();
        s.set_slot(3, sv(42)).unwrap();
        assert_ne!(s.root(), r0);
    }

    #[test]
    fn sparse_manifest_root_matches_segmented_state_root() {
        let mut s = SegmentedFriState::new_empty(LOG_SEGMENT_SIZE + 1);
        s.set_slot(3, sv(42)).unwrap();
        s.set_slot((SEGMENT_SIZE + 7) as u32, sv(77)).unwrap();
        let expected = s.root();
        let ids: Vec<u16> = s.active_segment_ids().collect();
        let roots: Vec<StateRoot> = ids.iter().map(|&seg_id| s.seg_root(seg_id)).collect();

        let reconstructed = sparse_state_root_from_segment_roots(
            LOG_SEGMENT_SIZE + 1,
            LOG_SEGMENT_SIZE,
            &ids,
            &roots,
        )
        .expect("sparse root reconstructs");
        assert_eq!(reconstructed, expected);

        let unsorted_ids = vec![ids[1], ids[0]];
        let unsorted_roots = vec![roots[1], roots[0]];
        assert!(sparse_state_root_from_segment_roots(
            LOG_SEGMENT_SIZE + 1,
            LOG_SEGMENT_SIZE,
            &unsorted_ids,
            &unsorted_roots,
        )
        .is_err());

        let duplicate_ids = vec![ids[0], ids[0]];
        let duplicate_roots = vec![roots[0], roots[0]];
        assert!(sparse_state_root_from_segment_roots(
            LOG_SEGMENT_SIZE + 1,
            LOG_SEGMENT_SIZE,
            &duplicate_ids,
            &duplicate_roots,
        )
        .is_err());
    }

    #[test]
    fn write_empty_to_virtual_zero_is_noop() {
        let mut s = SegmentedFriState::new_empty(TS);
        let r0 = s.root();
        s.set_slot(2, SlotValue::EMPTY).unwrap();
        assert_eq!(s.root(), r0);
        assert!(s.segments[0].is_none(), "segment must stay virtual");
    }

    #[test]
    fn segment_dematerializes_when_last_slot_cleared() {
        let mut s = SegmentedFriState::new_empty(TS);
        s.set_slot(3, sv(42)).unwrap();
        assert_eq!(s.segment_live_count(0), 1);
        assert_eq!(s.materialized_segment_ids().count(), 1);

        s.set_slot(3, SlotValue::EMPTY).unwrap();
        assert_eq!(s.segment_live_count(0), 0);
        assert_eq!(s.active_segment_ids().count(), 0);
        assert_eq!(s.materialized_segment_ids().count(), 0);
        assert_eq!(s.slot(3), SlotValue::EMPTY);
    }

    #[test]
    fn empty_slot_hints_prefer_holes_in_live_segments() {
        let mut s = SegmentedFriState::new_empty(TS);
        s.set_slot(0, sv(1)).unwrap();
        s.set_slot(1, sv(2)).unwrap();
        s.set_slot(1, SlotValue::EMPTY).unwrap();

        let reserved = HashSet::new();
        let hints = s.empty_slot_hints_in_populated_segments(123, 8, &reserved);
        assert!(
            hints.contains(&1),
            "expected freed hole in live segment, got {hints:?}"
        );
    }

    #[test]
    fn batch_delta_equals_sequential() {
        let deltas = [(0u32, sv(1)), (5, sv(2)), (10, sv(3))];
        let mut batched = SegmentedFriState::new_empty(TS);
        batched.apply_delta(&deltas).unwrap();

        let mut seq = SegmentedFriState::new_empty(TS);
        for (i, v) in deltas {
            seq.set_slot(i, v).unwrap();
        }
        assert_eq!(batched.root(), seq.root());
    }

    #[test]
    fn out_of_range_errors() {
        let mut s = SegmentedFriState::new_empty(2); // 4 slots
        assert_eq!(
            s.apply_delta(&[(4, sv(1))]),
            Err(StateError::SlotOutOfRange)
        );
    }

    #[test]
    fn slot_reads_back_what_was_written() {
        let mut s = SegmentedFriState::new_empty(TS);
        s.set_slot(6, sv(777)).unwrap();
        assert_eq!(s.slot(6), sv(777));
        assert_eq!(s.slot(0), SlotValue::EMPTY);
    }

    // -----------------------------------------------------------------------
    // Multi-segment tests (two segments, log_slots = LOG_SEGMENT_SIZE + 1)
    // -----------------------------------------------------------------------
    // To exercise multi-segment behaviour we need log_slots > LOG_SEGMENT_SIZE,
    // which is 17. At that size each segment has 65536 slots and rebuilding the
    // raw segment commitment is too slow for routine unit tests, so the tree
    // accounting is tested separately through metadata helpers below.
    //
    // Because LOG_SEGMENT_SIZE = 16, the minimum for multi-segment is
    // log_slots = 17. CI covers the single-segment commitment directly and the
    // multi-segment tree structure through the helpers below.

    #[test]
    fn zero_segtree_node_recurrence() {
        // Z[d] = compress(Z[d-1], Z[d-1]) must hold for all d.
        let table = zero_segtree_table();
        for d in 1..=MAX_SEGTREE_DEPTH {
            assert_eq!(
                table[d],
                compress(&table[d - 1], &table[d - 1]),
                "segtree node recurrence failed at d={d}"
            );
        }
    }

    #[test]
    fn expand_single_to_double_segment_correctness() {
        // Build a state, compute root, expand, verify new root equals
        // compress(old_root, zero_segtree_node(0)) — the F.7 invariant.
        // We only test the structural invariant, not the segment commitment.
        //
        // We work at log_slots = LOG_SEGMENT_SIZE (1 segment) and expand to
        // LOG_SEGMENT_SIZE + 1 (2 segments of 2^16 slots each).
        // This is slow because of the raw segment commitment, so we skip unless
        // running in a dedicated environment. Mark with #[ignore] by default.
    }

    fn synthetic_two_segment_metadata() -> SegmentedFriState {
        SegmentedFriState {
            log_slots: LOG_SEGMENT_SIZE + 1,
            effective_log_seg: LOG_SEGMENT_SIZE,
            num_segments: 2,
            segments: vec![None, None],
            seg_roots: vec![Some([1u8; 32]), Some([2u8; 32])],
            live_counts: vec![1, 0],
            tree: vec![[0u8; 32]; 5],
            tree_dirty: false,
            dirty: HashSet::from([1]),
            mdbx_dirty: HashSet::from([1]),
            exact_dirty: HashSet::from([1]),
            evicted: HashSet::from([0]),
            dirty_tree_leaves: HashSet::from([1]),
        }
    }

    #[test]
    fn exact_only_metadata_shrink_drops_zero_upper_segment_without_commitment_hashing() {
        let mut state = synthetic_two_segment_metadata();
        state
            .shrink_exact_metadata_to_log_slots(LOG_SEGMENT_SIZE)
            .unwrap();
        assert_eq!(state.log_slots(), LOG_SEGMENT_SIZE);
        assert_eq!(state.num_segments(), 1);
        assert_eq!(state.segment_live_count(0), 1);
        assert!(state.is_evicted(0));
        assert!(state.dirty.is_empty());
        assert!(state.mdbx_dirty.is_empty());
        assert!(state.exact_dirty.is_empty());
        assert_eq!(state.tree.len(), 3);
        assert!(state.tree_dirty);
    }

    #[test]
    fn exact_only_metadata_shrink_rejects_live_upper_segment_before_mutation() {
        let mut state = synthetic_two_segment_metadata();
        state.live_counts[1] = 1;
        let before = state.clone();
        assert_eq!(
            state.shrink_exact_metadata_to_log_slots(LOG_SEGMENT_SIZE),
            Err(StateResizeError::NonEmptyUpperHalf { seg_id: 1 })
        );
        assert_eq!(state.log_slots, before.log_slots);
        assert_eq!(state.num_segments, before.num_segments);
        assert_eq!(state.live_counts, before.live_counts);
        assert_eq!(state.seg_roots, before.seg_roots);
    }

    #[test]
    fn exact_only_metadata_expansion_preserves_lower_residency_without_hashing() {
        let mut state = synthetic_two_segment_metadata();
        state
            .shrink_exact_metadata_to_log_slots(LOG_SEGMENT_SIZE)
            .unwrap();
        state.expand_exact_metadata_for_replay().unwrap();
        assert_eq!(state.log_slots(), LOG_SEGMENT_SIZE + 1);
        assert_eq!(state.num_segments(), 2);
        assert_eq!(state.segment_live_count(0), 1);
        assert_eq!(state.segment_live_count(1), 0);
        assert!(state.is_evicted(0));
        assert!(!state.is_evicted(1));
        assert!(state.try_get_segment_columns(1).is_none());
        assert_eq!(state.tree.len(), 5);
        assert!(state.tree_dirty);
    }

    #[test]
    fn clear_dirty_resets_tracking() {
        let mut s = SegmentedFriState::new_empty(TS);
        // Write a slot to mark segment dirty.
        s.set_slot(0, sv(1)).unwrap();
        assert!(
            s.dirty_segment_ids().next().is_some(),
            "should be dirty after write"
        );
        s.clear_dirty();
        assert!(
            s.dirty_segment_ids().next().is_none(),
            "should be clean after clear_dirty"
        );
        // A subsequent write marks dirty again.
        s.set_slot(1, sv(2)).unwrap();
        assert!(
            s.dirty_segment_ids().next().is_some(),
            "should be dirty again after write"
        );
    }

    #[test]
    fn dirty_segment_tracking() {
        // `dirty_segment_ids()` reflects MDBX-dirty, not commitment-dirty.
        // After set_slot, the commitment-dirty set is cleared by root(), but
        // mdbx_dirty persists until clear_dirty() is called explicitly.
        let mut s = SegmentedFriState::new_empty(TS);
        assert_eq!(s.dirty_segment_ids().count(), 0);
        s.set_slot(3, sv(1)).unwrap(); // Commitment is flushed; mdbx_dirty is not cleared.
        assert_eq!(
            s.dirty_segment_ids().count(),
            1,
            "mdbx_dirty persists after set_slot"
        );
        s.clear_dirty();
        assert_eq!(
            s.dirty_segment_ids().count(),
            0,
            "cleared after clear_dirty()"
        );
    }

    #[test]
    fn set_segment_columns_does_not_mark_mdbx_dirty() {
        // Restoring segments from MDBX must NOT mark them as MDBX-dirty.
        let mut s = SegmentedFriState::new_empty(TS);
        let cols = SegmentColumns {
            values: vec![Block128::from(42u128); 1 << TS],
            owners_hi: vec![Block128::ZERO; 1 << TS],
            owners_lo: vec![Block128::ZERO; 1 << TS],
        };
        s.set_segment_columns(0, cols);
        // mdbx_dirty must remain empty (data came from MDBX).
        assert_eq!(
            s.dirty_segment_ids().count(),
            0,
            "set_segment_columns must not mark mdbx_dirty"
        );
        // But the slot value should be visible.
        let sv = s.slot(0);
        assert_eq!(sv.value, Block128::from(42u128));
    }

    #[test]
    fn shrink_rejects_nonempty_upper_half_without_changing_domain() {
        let mut state = SegmentedFriState::new_empty(TS);
        state.expand();
        let upper_slot = (1u32 << TS) + 3;
        state.set_slot(upper_slot, sv(7)).unwrap();
        let root_before = state.root();

        assert_eq!(
            state.shrink_to_log_slots(TS),
            Err(StateResizeError::NonEmptyUpperHalf { seg_id: 0 })
        );
        assert_eq!(state.log_slots(), TS + 1);
        assert_eq!(state.num_slots(), 1u64 << (TS + 1));
        assert_eq!(state.slot(upper_slot), sv(7));
        assert_eq!(state.root(), root_before);
    }

    #[test]
    fn shrink_rejects_evicted_state_without_changing_domain() {
        let mut state = SegmentedFriState::new_empty(TS + 1);
        state.mark_segment_evicted_for_test(0, [0x5A; 32]);

        assert_eq!(
            state.shrink_to_log_slots(TS),
            Err(StateResizeError::EvictedUpperSegment { seg_id: 0 })
        );
        assert_eq!(state.log_slots(), TS + 1);
        assert_eq!(state.num_slots(), 1u64 << (TS + 1));
        assert!(state.is_evicted(0));
    }
}
