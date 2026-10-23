// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native-side state transition for the transparent UTXO chain.
//!
//! The chain state is a segmented raw UTXO slot vector plus exact commitments.
//! A spend zeroes the slot at `input.slot_index`; a mint writes to the
//! wallet-chosen `output.slot_index` only if the verifier-derived prefix state
//! says it is empty. Every mint receives a fresh monotone `creation_id`, so a
//! stale spend cannot consume a later UTXO that reuses the same slot index.
//! The block header state root is the exact sparse-Merkle UTXO root directly.
//!
//! This is the canonical native state engine used by miners, validators,
//! storage and tests.
//! User-transaction block acceptance uses the exact authenticated transition
//! proof, then commits the sealed verifier result atomically.

pub mod native_assets;

use std::collections::{BTreeMap, HashSet};

use noid_poseidon2b::primitives::Digest;
use noid_tx::TxBody;

use crate::exact_segment_cache::ExactSegmentTree;
use crate::exact_state_hash::{slot_leaf_hash, state_node_hash, zero_slot_roots, StateHash};
use crate::fri_state::{SlotValue, StateError, LOG_SEGMENT_SIZE, STATE_LOG_SLOTS};
use crate::segmented_state::{
    ExactStateReadError, SegmentColumns, SegmentedFriState, StateResizeError,
};
use crate::sparse_merkle::{frontier_sibling_positions, SparseMerkleError};

/// Chain-level mutable state.
///
/// The wallet picks each output's `slot_index` and binds it into the
/// body hash. The chain only *verifies* that the chosen slot is
/// currently empty and that the outputs of a single tx don't collide.
/// `alloc_counter` assigns the globally monotone `creation_id` packed into
/// every newly minted UTXO. It is also the seed for splitmix64-based wallet
/// slot hints and is therefore consensus-significant on both paths.
#[derive(Debug, Clone)]
pub struct ChainState {
    /// Segmented raw UTXO state (2^16 slots per segment).
    pub state: SegmentedFriState,
    /// Exact sparse Merkle root over the UTXO slot vector.
    pub utxo_root: StateHash,
    /// Number of live (non-empty) slots. Grows on activation, shrinks
    /// on deactivation. This is the consensus-significant occupancy
    /// signal for the `log_slots` expansion trigger.
    pub active_slot_count: u64,
    /// Monotone counter incremented on each successful allocation. The next
    /// live output stores `creation_id = alloc_counter + 1`; the updated value
    /// also seeds deterministic wallet slot hints.
    pub alloc_counter: u64,
    /// Exact sum of every live UTXO amount in μNOID.
    ///
    /// This is derived local metadata, not a header or proof input. Snapshot
    /// installation accumulates it while already streaming authenticated
    /// slots; normal transitions update it from their bounded touched set.
    pub circulating_supply_micronoid: u128,
    /// Compact exact-root hierarchy: one 32-byte root per 2^16-slot segment
    /// plus its upper binary tree.  Raw columns remain an MDBX-backed cache;
    /// exact root updates therefore need only the segments touched by a block.
    exact_roots: ExactSegmentRootCache,
}

/// O(depth)-memory builder for a sparse Merkle root from sorted non-default
/// leaves.  Gaps are emitted as maximal aligned canonical-zero subtrees, so no
/// live-leaf vector or all-node cache is materialized.
pub(crate) struct StreamingSparseRoot {
    depth: u32,
    position: u64,
    zero_roots: Vec<StateHash>,
    stack: Vec<(u32, StateHash)>,
}

impl StreamingSparseRoot {
    pub(crate) fn new(depth: u32) -> Result<Self, ApplyExactTransitionError> {
        let _ = 1u64
            .checked_shl(depth)
            .ok_or(ApplyExactTransitionError::HeaderLogSlotsMismatch)?;
        Ok(Self {
            depth,
            position: 0,
            zero_roots: zero_slot_roots(depth as usize),
            stack: Vec::with_capacity(depth as usize + 1),
        })
    }

    fn append_block(&mut self, mut level: u32, mut hash: StateHash) {
        while self
            .stack
            .last()
            .is_some_and(|(pending_level, _)| *pending_level == level)
        {
            let (_, left) = self.stack.pop().expect("level checked above");
            hash = state_node_hash(left, hash);
            level += 1;
        }
        self.stack.push((level, hash));
    }

    fn fill_zero_gap(&mut self, end: u64) -> Result<(), ApplyExactTransitionError> {
        let limit = 1u64
            .checked_shl(self.depth)
            .ok_or(ApplyExactTransitionError::HeaderLogSlotsMismatch)?;
        if end < self.position || end > limit {
            return Err(ApplyExactTransitionError::SlotOutOfRange);
        }
        while self.position < end {
            let remaining = end - self.position;
            let by_remaining = 63 - remaining.leading_zeros();
            let by_alignment = if self.position == 0 {
                self.depth
            } else {
                self.position.trailing_zeros().min(self.depth)
            };
            let level = by_remaining.min(by_alignment);
            self.append_block(level, self.zero_roots[level as usize]);
            self.position += 1u64 << level;
        }
        Ok(())
    }

    pub(crate) fn push_leaf(
        &mut self,
        index: u32,
        hash: StateHash,
    ) -> Result<(), ApplyExactTransitionError> {
        let index = u64::from(index);
        self.fill_zero_gap(index)?;
        self.append_block(0, hash);
        self.position = index + 1;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<StateHash, ApplyExactTransitionError> {
        let limit = 1u64
            .checked_shl(self.depth)
            .ok_or(ApplyExactTransitionError::HeaderLogSlotsMismatch)?;
        self.fill_zero_gap(limit)?;
        match self.stack.as_slice() {
            [(level, root)] if *level == self.depth => Ok(*root),
            _ => Err(ApplyExactTransitionError::HeaderLogSlotsMismatch),
        }
    }
}

/// Compact two-level exact-state root cache.
///
/// At production depth 24 this is 256 segment roots plus 255 upper nodes (under
/// 17 KiB), independent of the number of live UTXOs.  It deliberately stores
/// no slot leaves and no full Merkle paths.
#[derive(Debug, Clone)]
struct ExactSegmentRootCache {
    log_slots: usize,
    effective_log_seg: usize,
    segment_roots: Vec<StateHash>,
    tree: Vec<StateHash>,
}

impl ExactSegmentRootCache {
    fn empty(log_slots: usize) -> Self {
        let effective_log_seg = log_slots.min(crate::fri_state::LOG_SEGMENT_SIZE);
        Self::empty_with_segment_log(log_slots, effective_log_seg)
    }

    fn empty_with_segment_log(log_slots: usize, effective_log_seg: usize) -> Self {
        let segment_count = 1usize << (log_slots - effective_log_seg);
        let zero_segment = zero_slot_roots(effective_log_seg)[effective_log_seg];
        let segment_roots = vec![zero_segment; segment_count];
        let tree = Self::build_tree(&segment_roots);
        Self {
            log_slots,
            effective_log_seg,
            segment_roots,
            tree,
        }
    }

    fn build_tree(segment_roots: &[StateHash]) -> Vec<StateHash> {
        let count = segment_roots.len();
        let mut tree = vec![[0u8; 32]; 2 * count];
        for (index, root) in segment_roots.iter().copied().enumerate() {
            tree[count + index] = root;
        }
        for index in (1..count).rev() {
            tree[index] = state_node_hash(tree[2 * index], tree[2 * index + 1]);
        }
        tree
    }

    #[inline]
    fn root(&self) -> StateHash {
        if self.segment_roots.len() == 1 {
            self.segment_roots[0]
        } else {
            self.tree[1]
        }
    }

    fn set_segment_root(&mut self, segment_id: u16, root: StateHash) {
        let index = segment_id as usize;
        self.segment_roots[index] = root;
        if self.segment_roots.len() == 1 {
            return;
        }
        let count = self.segment_roots.len();
        let mut node = count + index;
        self.tree[node] = root;
        while node > 1 {
            node /= 2;
            self.tree[node] = state_node_hash(self.tree[2 * node], self.tree[2 * node + 1]);
        }
    }

    fn segment_node_hash(&self, level: u32, node_index: u64) -> Option<StateHash> {
        let count = self.segment_roots.len();
        let upper_depth = count.ilog2();
        if level > upper_depth || node_index >= ((count as u64) >> level) {
            return None;
        }
        if level == 0 {
            return self.segment_roots.get(node_index as usize).copied();
        }
        let base = count >> level;
        self.tree.get(base + node_index as usize).copied()
    }

    fn expand_one(&mut self) {
        let old_log_slots = self.log_slots;
        let old_root = self.root();
        self.log_slots += 1;
        if self.log_slots <= crate::fri_state::LOG_SEGMENT_SIZE {
            self.effective_log_seg = self.log_slots;
            let empty_right = zero_slot_roots(old_log_slots)[old_log_slots];
            self.segment_roots[0] = state_node_hash(old_root, empty_right);
            self.tree = Self::build_tree(&self.segment_roots);
            return;
        }

        let old_count = self.segment_roots.len();
        let zero_segment = zero_slot_roots(self.effective_log_seg)[self.effective_log_seg];
        self.segment_roots.resize(old_count * 2, zero_segment);
        self.tree = Self::build_tree(&self.segment_roots);
        debug_assert_eq!(
            self.root(),
            state_node_hash(old_root, zero_slot_roots(old_log_slots)[old_log_slots])
        );
    }

    fn shrink_to(&mut self, target: usize) {
        while self.log_slots > target {
            if self.log_slots <= crate::fri_state::LOG_SEGMENT_SIZE {
                self.log_slots -= 1;
                self.effective_log_seg = self.log_slots;
                // The resident segment is recomputed immediately after the raw
                // state shrink; use the canonical empty root as a placeholder.
                self.segment_roots = vec![zero_slot_roots(self.log_slots)[self.log_slots]];
                self.tree = Self::build_tree(&self.segment_roots);
            } else {
                self.log_slots -= 1;
                self.segment_roots.truncate(self.segment_roots.len() / 2);
                self.tree = Self::build_tree(&self.segment_roots);
            }
        }
    }
}

fn exact_segment_root_with_updates(
    effective_log_seg: usize,
    columns: Option<&SegmentColumns>,
    updates: &BTreeMap<u32, SlotValue>,
) -> StateHash {
    let segment_len = 1usize << effective_log_seg;
    let mut stream = StreamingSparseRoot::new(effective_log_seg as u32)
        .expect("effective segment depth is always a valid sparse depth");
    for local in 0..segment_len {
        let local = local as u32;
        let slot = updates.get(&local).copied().unwrap_or_else(|| {
            let Some(columns) = columns else {
                return SlotValue::EMPTY;
            };
            let local = local as usize;
            if local >= columns.values.len() {
                return SlotValue::EMPTY;
            }
            SlotValue {
                value: columns.values[local],
                owner_hi: columns.owners_hi[local],
                owner_lo: columns.owners_lo[local],
            }
        });
        if !slot.is_empty() {
            stream
                .push_leaf(local, slot_leaf_hash(slot))
                .expect("local indices are streamed in canonical order");
        }
    }
    stream
        .finish()
        .expect("complete segment stream has the declared depth")
}

pub(crate) fn exact_segment_root_from_columns(
    effective_log_seg: usize,
    columns: &SegmentColumns,
) -> StateHash {
    exact_segment_root_with_updates(effective_log_seg, Some(columns), &BTreeMap::new())
}

#[derive(Debug)]
pub enum ExactFrontierError {
    SparseMerkle(SparseMerkleError),
    ExactStateRead(ExactStateReadError),
    CompactRootMismatch,
}

impl core::fmt::Display for ExactFrontierError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SparseMerkle(error) => write!(f, "{error}"),
            Self::ExactStateRead(error) => write!(f, "{error}"),
            Self::CompactRootMismatch => write!(f, "compact exact-root cache mismatch"),
        }
    }
}

impl std::error::Error for ExactFrontierError {}

impl From<SparseMerkleError> for ExactFrontierError {
    fn from(error: SparseMerkleError) -> Self {
        Self::SparseMerkle(error)
    }
}

fn exact_local_subtree_root(
    columns: Option<&SegmentColumns>,
    local_start: usize,
    level: u32,
) -> StateHash {
    let Some(columns) = columns else {
        return zero_slot_roots(level as usize)[level as usize];
    };
    let subtree_len = 1usize << level;
    let mut stream = StreamingSparseRoot::new(level)
        .expect("frontier level is bounded by the exact segment depth");
    for offset in 0..subtree_len {
        let local = local_start + offset;
        let slot = SlotValue {
            value: columns.values[local],
            owner_hi: columns.owners_hi[local],
            owner_lo: columns.owners_lo[local],
        };
        if !slot.is_empty() {
            stream
                .push_leaf(offset as u32, slot_leaf_hash(slot))
                .expect("subtree offsets are canonical and in range");
        }
    }
    stream
        .finish()
        .expect("complete local subtree stream has the declared depth")
}

#[derive(Debug)]
pub enum SparseUtxoBuildError {
    SlotOutOfRange,
    DuplicateSlot(u32),
    EmptySlot(u32),
    CreationIdExceedsAllocCounter {
        slot_index: u32,
        creation_id: u64,
        alloc_counter: u64,
    },
    CreationIdOutsideBoundary {
        slot_index: u32,
        creation_id: u64,
        alloc_counter: u64,
        height: u64,
    },
    State(StateError),
    SparseMerkle(SparseMerkleError),
}

impl ChainState {
    /// Fresh production-sized state: `2^STATE_LOG_SLOTS` empty slots.
    pub fn new() -> Self {
        Self::with_log_slots(STATE_LOG_SLOTS)
    }

    /// Fresh state with a custom slot depth. Tests use a small depth to keep
    /// exact sparse-Merkle fixtures cheap.
    pub fn with_log_slots(log_slots: usize) -> Self {
        let utxo_root = zero_slot_roots(log_slots)[log_slots];
        Self {
            state: SegmentedFriState::new_empty(log_slots),
            utxo_root,
            active_slot_count: 0,
            alloc_counter: 0,
            circulating_supply_micronoid: 0,
            exact_roots: ExactSegmentRootCache::empty(log_slots),
        }
    }

    /// Snapshot a durable chain boundary without cloning resident raw columns.
    pub fn durable_metadata_clone(&self) -> Option<Self> {
        Some(Self {
            state: self.state.durable_metadata_clone()?,
            utxo_root: self.utxo_root,
            active_slot_count: self.active_slot_count,
            alloc_counter: self.alloc_counter,
            circulating_supply_micronoid: self.circulating_supply_micronoid,
            exact_roots: self.exact_roots.clone(),
        })
    }

    /// Build chain state from fully loaded raw segment columns.
    pub fn from_loaded_parts(
        state: SegmentedFriState,
        active_slot_count: u64,
        alloc_counter: u64,
    ) -> Result<Self, ExactStateReadError> {
        let circulating_supply_micronoid = Self::loaded_circulating_supply(&state)?;
        let exact_roots = ExactSegmentRootCache::empty(state.log_slots());
        let mut out = Self {
            utxo_root: zero_slot_roots(state.log_slots())[state.log_slots()],
            state,
            active_slot_count,
            alloc_counter,
            circulating_supply_micronoid,
            exact_roots,
        };
        out.rebuild_exact_utxo_root_loaded()?;
        Ok(out)
    }

    /// Build a hot state from durable per-segment summaries without retaining
    /// any segment columns. The compact exact-root set is accepted only when
    /// its reconstructed upper root equals the canonical header commitment.
    pub(crate) fn from_evicted_parts(
        state: SegmentedFriState,
        active_slot_count: u64,
        alloc_counter: u64,
        circulating_supply_micronoid: u128,
        expected_root: StateHash,
        exact_segment_roots: &[(u16, StateHash)],
    ) -> Result<Self, ExactStateReadError> {
        let mut exact_roots = ExactSegmentRootCache::empty(state.log_slots());
        for &(segment_id, root) in exact_segment_roots {
            if segment_id as usize >= exact_roots.segment_roots.len() {
                return Err(ExactStateReadError::SegmentRootMismatch { seg_id: segment_id });
            }
            exact_roots.set_segment_root(segment_id, root);
        }
        if exact_roots.root() != expected_root {
            return Err(ExactStateReadError::SegmentRootMismatch { seg_id: 0 });
        }
        Ok(Self {
            state,
            utxo_root: expected_root,
            active_slot_count,
            alloc_counter,
            circulating_supply_micronoid,
            exact_roots,
        })
    }

    /// Build state from a sparse set of live UTXO slots.
    ///
    /// This is a loaded-state constructor, not a transaction-application API.
    /// It writes the raw slots without computing the old segment cache root and
    /// computes the consensus exact UTXO root directly from the same leaves.
    /// Callers must provide only live, unique slots.
    pub fn from_sparse_utxos(
        log_slots: usize,
        slots: &[(u32, SlotValue)],
        alloc_counter: u64,
    ) -> Result<Self, SparseUtxoBuildError> {
        Self::from_sparse_utxos_with_boundary(log_slots, slots, alloc_counter, None)
    }

    /// Rebuild the exact raw State at a header-bound height, checking native
    /// allocator sequences and coinbase mint heights in their own namespaces.
    pub fn from_sparse_utxos_at(
        log_slots: usize,
        slots: &[(u32, SlotValue)],
        alloc_counter: u64,
        height: u64,
    ) -> Result<Self, SparseUtxoBuildError> {
        Self::from_sparse_utxos_with_boundary(log_slots, slots, alloc_counter, Some(height))
    }

    fn from_sparse_utxos_with_boundary(
        log_slots: usize,
        slots: &[(u32, SlotValue)],
        alloc_counter: u64,
        height: Option<u64>,
    ) -> Result<Self, SparseUtxoBuildError> {
        let mut seen = HashSet::with_capacity(slots.len());
        let max_slots = 1u64
            .checked_shl(log_slots as u32)
            .ok_or(SparseUtxoBuildError::SlotOutOfRange)?;
        for &(index, slot) in slots {
            if (index as u64) >= max_slots {
                return Err(SparseUtxoBuildError::SlotOutOfRange);
            }
            if !seen.insert(index) {
                return Err(SparseUtxoBuildError::DuplicateSlot(index));
            }
            if slot.is_empty() {
                return Err(SparseUtxoBuildError::EmptySlot(index));
            }
            // Tagged coinbase ids live in the `COINBASE_CREATION_TAG | height`
            // namespace and are bounded by chain height, not the allocator.
            if let Some(height) = height {
                if !crate::consensus::params::creation_id_within_boundary(
                    slot.creation_id(),
                    alloc_counter,
                    height,
                ) {
                    return Err(SparseUtxoBuildError::CreationIdOutsideBoundary {
                        slot_index: index,
                        creation_id: slot.creation_id(),
                        alloc_counter,
                        height,
                    });
                }
            } else if !crate::consensus::params::is_coinbase_creation_id(slot.creation_id())
                && slot.creation_id() > alloc_counter
            {
                return Err(SparseUtxoBuildError::CreationIdExceedsAllocCounter {
                    slot_index: index,
                    creation_id: slot.creation_id(),
                    alloc_counter,
                });
            }
        }

        let mut state = Self::with_log_slots(log_slots);
        state
            .state
            .apply_delta_unrooted(slots)
            .map_err(SparseUtxoBuildError::State)?;
        state.active_slot_count = slots.len() as u64;
        // The highest historical creation ID may already have been spent, so
        // it cannot be reconstructed from the live sparse set. Callers must
        // supply the trusted header/checkpoint counter explicitly.
        state.alloc_counter = alloc_counter;
        state.circulating_supply_micronoid = slots
            .iter()
            .map(|(_, slot)| u128::from(slot.amount()))
            .sum();
        state
            .rebuild_exact_utxo_root_loaded()
            .expect("fresh sparse constructor has every live segment resident");
        Ok(state)
    }

    fn loaded_circulating_supply(state: &SegmentedFriState) -> Result<u128, ExactStateReadError> {
        let mut supply = 0u128;
        for segment_id in state.active_segment_ids() {
            if state.is_evicted(segment_id) {
                return Err(ExactStateReadError::EvictedSegment { seg_id: segment_id });
            }
            let columns = state
                .try_get_segment_columns(segment_id)
                .ok_or(ExactStateReadError::EvictedSegment { seg_id: segment_id })?;
            for index in 0..columns.values.len() {
                let slot = SlotValue {
                    value: columns.values[index],
                    owner_hi: columns.owners_hi[index],
                    owner_lo: columns.owners_lo[index],
                };
                if !slot.is_empty() {
                    supply = supply
                        .checked_add(u128::from(slot.amount()))
                        .expect("the bounded u32 slot domain fits a u128 monetary sum");
                }
            }
        }
        Ok(supply)
    }

    pub(crate) fn supply_after_slot_updates(
        &self,
        slot_updates: &[(u32, SlotValue)],
    ) -> Option<u128> {
        let mut canonical = BTreeMap::new();
        for &(slot_index, value) in slot_updates {
            canonical.insert(slot_index, value);
        }

        let mut supply = self.circulating_supply_micronoid;
        let current_slots = self.state.num_slots();
        let effective_log = self.state.effective_log_segment_size();
        for (slot_index, value) in canonical {
            let previous = if u64::from(slot_index) < current_slots {
                let segment_id = (slot_index >> effective_log) as u16;
                if self.state.is_evicted(segment_id) {
                    return None;
                }
                self.state.slot(slot_index)
            } else {
                SlotValue::EMPTY
            };
            supply = supply
                .checked_sub(u128::from(previous.amount()))?
                .checked_add(u128::from(value.amount()))?;
        }
        Some(supply)
    }

    /// Total number of slots in the state vector.
    pub fn num_slots(&self) -> u64 {
        self.state.num_slots()
    }

    /// Slots that can still be allocated without a `log_slots` bump.
    pub fn available_slots(&self) -> u64 {
        self.state.num_slots() - self.active_slot_count
    }

    /// Occupancy fraction used by the `log_slots` expansion trigger.
    pub fn occupancy(&self) -> f64 {
        (self.active_slot_count as f64) / (self.state.num_slots() as f64)
    }

    /// Grow the slot domain by one level while updating the exact root in O(1).
    ///
    /// The old tree becomes the left child and a depth-`old_log_slots` empty
    /// subtree becomes the right child. This remains valid when live segment
    /// columns are evicted and a full exact-root rebuild is unavailable.
    pub fn expand_one(&mut self) {
        let old_log_slots = self.state.log_slots();
        let exact_cache_was_current = self.state.exact_dirty_segment_ids().next().is_none()
            && self.exact_roots.log_slots == old_log_slots
            && self.exact_roots.root() == self.utxo_root;
        let empty_right = zero_slot_roots(old_log_slots)[old_log_slots];
        self.state.expand();
        self.exact_roots.expand_one();
        self.utxo_root = state_node_hash(self.utxo_root, empty_right);
        // Below LOG_SEGMENT_SIZE the raw FRI carrier grows its sole resident
        // segment and conservatively marks the exact segment root stale.  At
        // the ChainState layer the same transition is already authenticated by
        // the O(1) old-root-as-left-child rule, so preserve the sealed status.
        // If the parent was dirty or inconsistent, leave the marker intact and
        // let the next exact read recompute (or reject) it normally.
        if exact_cache_was_current {
            self.state.clear_exact_dirty();
        }
        debug_assert_eq!(self.exact_roots.root(), self.utxo_root);
    }

    /// Expand one production slot-domain level for exact-only replay.
    ///
    /// The consensus exact cache/root is updated with the same O(1) rule as
    /// [`Self::expand_one`], while segmented FRI metadata is resized without
    /// hashing and remains explicitly unavailable to the caller.
    pub fn expand_exact_metadata_for_replay(&mut self) -> Result<(), StateResizeError> {
        let old_log_slots = self.state.log_slots();
        let empty_right = zero_slot_roots(old_log_slots)[old_log_slots];
        self.state.expand_exact_metadata_for_replay()?;
        self.exact_roots.expand_one();
        self.utxo_root = state_node_hash(self.utxo_root, empty_right);
        debug_assert_eq!(self.exact_roots.root(), self.utxo_root);
        Ok(())
    }

    #[inline]
    pub fn state_root(&mut self) -> Digest {
        self.try_state_root()
            .expect("dirty exact-state segments must be resident")
    }

    /// Refresh only exact subtree roots dirtied by local slot updates.
    /// Untouched live segments may remain evicted; their verified 32-byte
    /// summaries are sufficient for the upper tree.
    #[inline]
    pub fn try_state_root(&mut self) -> Result<Digest, ExactStateReadError> {
        while self.exact_roots.log_slots < self.state.log_slots() {
            self.exact_roots.expand_one();
        }
        if self.exact_roots.log_slots > self.state.log_slots() {
            self.exact_roots.shrink_to(self.state.log_slots());
        }
        let mut dirty: Vec<u16> = self.state.exact_dirty_segment_ids().collect();
        // Consume already-current trees before cold builds can evict them.
        // This also benefits blocks whose working set exceeds the byte budget.
        dirty.sort_unstable_by_key(|id| self.state.cached_exact_segment_tree(*id).is_none());
        for segment_id in dirty {
            if self.state.is_evicted(segment_id) {
                return Err(ExactStateReadError::EvictedSegment { seg_id: segment_id });
            }
            let root = self.state.exact_segment_root(segment_id)?;
            self.exact_roots.set_segment_root(segment_id, root);
        }
        self.state.clear_exact_dirty();
        let root = self.exact_roots.root();
        self.utxo_root = root;
        Ok(root)
    }

    #[inline]
    pub fn cached_state_root(&self) -> Digest {
        self.utxo_root
    }

    /// Return one compact exact segment root from the already-sealed cache.
    ///
    /// MDBX persists this alongside changed raw columns so restart can rebuild
    /// the authenticated upper tree without rereading every dense segment.
    pub(crate) fn cached_exact_segment_root(&self, segment_id: u16) -> Option<StateHash> {
        self.exact_roots
            .segment_roots
            .get(segment_id as usize)
            .copied()
    }

    pub fn rebuild_exact_utxo_root_loaded(&mut self) -> Result<StateHash, ExactStateReadError> {
        self.try_state_root()
    }

    /// Reinstall one durable segment after checking it against the compact
    /// exact-root summary retained in RAM.
    pub fn restore_evicted_segment(
        &mut self,
        segment_id: u16,
        columns: SegmentColumns,
    ) -> Result<(), ExactStateReadError> {
        let expected_len = 1usize << self.state.effective_log_segment_size();
        if columns.values.len() != expected_len
            || columns.owners_hi.len() != expected_len
            || columns.owners_lo.len() != expected_len
        {
            return Err(ExactStateReadError::SegmentRootMismatch { seg_id: segment_id });
        }
        let actual_live = (0..expected_len)
            .filter(|&local| {
                !SlotValue {
                    value: columns.values[local],
                    owner_hi: columns.owners_hi[local],
                    owner_lo: columns.owners_lo[local],
                }
                .is_empty()
            })
            .count();
        if usize::try_from(self.state.segment_live_count(segment_id)).ok() != Some(actual_live) {
            return Err(ExactStateReadError::SegmentRootMismatch { seg_id: segment_id });
        }
        let tree =
            ExactSegmentTree::from_columns(self.state.effective_log_segment_size(), &columns);
        if self
            .exact_roots
            .segment_roots
            .get(segment_id as usize)
            .copied()
            != Some(tree.root())
        {
            return Err(ExactStateReadError::SegmentRootMismatch { seg_id: segment_id });
        }
        self.state.restore_evicted_segment(segment_id, columns);
        self.state.remember_exact_segment_tree(segment_id, tree);
        Ok(())
    }

    /// Read the canonical exact-state sibling frontier without building a
    /// global sparse-node map.  Local sibling subtrees are streamed from the
    /// already-hydrated touched segments; upper siblings come from the compact
    /// per-segment tree.
    pub fn exact_frontier_siblings(
        &self,
        touched_indices: &[u32],
        depth: u32,
    ) -> Result<Vec<StateHash>, ExactFrontierError> {
        if depth as usize != self.state.log_slots()
            || self.exact_roots.log_slots != self.state.log_slots()
        {
            return Err(ExactFrontierError::SparseMerkle(
                SparseMerkleError::CacheDepthMismatch {
                    cache_depth: self.exact_roots.log_slots as u32,
                    requested_depth: depth,
                },
            ));
        }
        if self.state.exact_dirty_segment_ids().next().is_some()
            || self.exact_roots.root() != self.utxo_root
        {
            return Err(ExactFrontierError::CompactRootMismatch);
        }

        let positions = frontier_sibling_positions(touched_indices, depth)?;
        let effective_log = self.state.effective_log_segment_size() as u32;
        let mut siblings = Vec::with_capacity(positions.len());
        for position in positions {
            let level = u32::from(position.level);
            if level >= effective_log {
                let root = self
                    .exact_roots
                    .segment_node_hash(level - effective_log, position.node_index)
                    .ok_or(ExactFrontierError::CompactRootMismatch)?;
                siblings.push(root);
                continue;
            }

            let nodes_per_segment_shift = effective_log - level;
            let segment_id = (position.node_index >> nodes_per_segment_shift) as u16;
            if self.state.is_evicted(segment_id) {
                return Err(ExactFrontierError::ExactStateRead(
                    ExactStateReadError::EvictedSegment { seg_id: segment_id },
                ));
            }
            let local_node_mask = (1u64 << nodes_per_segment_shift) - 1;
            let local_node = position.node_index & local_node_mask;
            if let Some(root) = self
                .state
                .cached_exact_segment_tree(segment_id)
                .and_then(|tree| tree.subtree_root(level, local_node))
            {
                siblings.push(root);
                continue;
            }
            let local_start = (local_node << level) as usize;
            siblings.push(exact_local_subtree_root(
                self.state.try_get_segment_columns(segment_id),
                local_start,
                level,
            ));
        }
        Ok(siblings)
    }

    pub fn exact_sparse_cache(
        &mut self,
    ) -> Result<crate::sparse_merkle::SparseMerkleCache, ExactStateReadError> {
        let cache = self.state.exact_sparse_cache()?;
        self.utxo_root = cache.root();
        Ok(cache)
    }

    pub fn exact_utxo_root_after_slot_updates(
        &self,
        log_slots: u32,
        slot_updates: &[(u32, SlotValue)],
    ) -> Result<StateHash, ApplyExactTransitionError> {
        let current_depth = self.state.log_slots() as u32;
        if log_slots < current_depth || log_slots > current_depth.saturating_add(1) {
            return Err(ApplyExactTransitionError::HeaderLogSlotsMismatch);
        }
        let target_slots = 1u64
            .checked_shl(log_slots)
            .ok_or(ApplyExactTransitionError::HeaderLogSlotsMismatch)?;
        let mut updates_by_segment: BTreeMap<u16, BTreeMap<u32, SlotValue>> = BTreeMap::new();
        let target_effective_log = (log_slots as usize).min(crate::fri_state::LOG_SEGMENT_SIZE);
        let local_mask = (1u32 << target_effective_log) - 1;
        for &(index, value) in slot_updates {
            if u64::from(index) >= target_slots {
                return Err(ApplyExactTransitionError::SlotOutOfRange);
            }
            updates_by_segment
                .entry((index >> target_effective_log) as u16)
                .or_default()
                .insert(index & local_mask, value);
        }

        // Refresh any pre-existing local dirt in a temporary compact cache so
        // this read-only derivation never mutates or clones raw state columns.
        let mut exact_roots = self.exact_roots.clone();
        for segment_id in self.state.exact_dirty_segment_ids() {
            if self.state.is_evicted(segment_id) {
                return Err(ApplyExactTransitionError::ExactStateRead(
                    ExactStateReadError::EvictedSegment { seg_id: segment_id },
                ));
            }
            let root = self
                .state
                .cached_exact_segment_tree(segment_id)
                .map(|tree| tree.root())
                .unwrap_or_else(|| {
                    exact_segment_root_with_updates(
                        self.state.effective_log_segment_size(),
                        self.state.try_get_segment_columns(segment_id),
                        &BTreeMap::new(),
                    )
                });
            exact_roots.set_segment_root(segment_id, root);
        }
        if exact_roots.root() != self.utxo_root {
            return Err(ApplyExactTransitionError::CachedRootMismatch);
        }

        if log_slots > current_depth {
            exact_roots.expand_one();
        }
        for (segment_id, local_updates) in updates_by_segment {
            let columns = if segment_id as usize >= self.state.num_segments() {
                None
            } else {
                if self.state.is_evicted(segment_id) {
                    return Err(ApplyExactTransitionError::ExactStateRead(
                        ExactStateReadError::EvictedSegment { seg_id: segment_id },
                    ));
                }
                self.state.try_get_segment_columns(segment_id)
            };
            let root = self
                .state
                .cached_exact_segment_tree(segment_id)
                .filter(|tree| tree.log_slots() == target_effective_log)
                .map(|tree| tree.root_with_updates(&local_updates))
                .unwrap_or_else(|| {
                    exact_segment_root_with_updates(target_effective_log, columns, &local_updates)
                });
            exact_roots.set_segment_root(segment_id, root);
        }
        Ok(exact_roots.root())
    }

    pub fn apply_verified_exact_transition(
        &mut self,
        log_slots: u32,
        child_state_root: StateHash,
        slot_updates: &[(u32, SlotValue)],
        active_slot_count: u64,
        alloc_counter: u64,
    ) -> Result<Digest, ApplyExactTransitionError> {
        let current_log_slots = self.state.log_slots();
        if (log_slots as usize) < current_log_slots
            || (log_slots as usize) > current_log_slots.saturating_add(1)
        {
            return Err(ApplyExactTransitionError::HeaderLogSlotsMismatch);
        }
        let target_slots = 1u64
            .checked_shl(log_slots)
            .ok_or(ApplyExactTransitionError::HeaderLogSlotsMismatch)?;
        if slot_updates
            .iter()
            .any(|(slot_index, _)| u64::from(*slot_index) >= target_slots)
        {
            return Err(ApplyExactTransitionError::SlotOutOfRange);
        }
        let computed_child = self.exact_utxo_root_after_slot_updates(log_slots, slot_updates)?;
        if computed_child != child_state_root {
            return Err(ApplyExactTransitionError::CachedRootMismatch);
        }
        let circulating_supply_micronoid = self
            .supply_after_slot_updates(slot_updates)
            .ok_or(ApplyExactTransitionError::CirculatingSupplyInvariant)?;
        if log_slots as usize == current_log_slots + 1 {
            if current_log_slots >= LOG_SEGMENT_SIZE {
                self.expand_exact_metadata_for_replay()
                    .map_err(|_| ApplyExactTransitionError::HeaderLogSlotsMismatch)?;
            } else {
                self.expand_one();
            }
        }
        self.state
            .apply_delta_unrooted(slot_updates)
            .map_err(|_| ApplyExactTransitionError::SlotOutOfRange)?;
        let applied_root = self
            .try_state_root()
            .map_err(ApplyExactTransitionError::ExactStateRead)?;
        debug_assert_eq!(applied_root, computed_child);
        self.active_slot_count = active_slot_count;
        self.alloc_counter = alloc_counter;
        self.circulating_supply_micronoid = circulating_supply_micronoid;
        Ok(applied_root)
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of applying one transaction: the post-transition state root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateTransition {
    pub new_state_root: Digest,
}

/// Error cases that invalidate a transaction at the state-transition
/// level (independent of balance / range, which the circuit checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyError {
    /// `input.slot_index` or `output.slot_index` is outside the state
    /// vector.
    SlotOutOfRange,
    /// The slot's `(value, owner)` does not match the input's claimed
    /// fields — spending a non-existent or already-spent UTXO.
    UnknownOrSpentInput,
    /// Native carriers use the typed operation transition at the shared fork.
    NativeInputRequiresNativeOperation,
    /// The wallet-chosen output slot is already occupied in the
    /// prev-state (not `(0,0,0)`). The mint would clobber a live UTXO.
    OutputSlotNotEmpty,
    /// Two valid outputs in the same tx target the same `slot_index`,
    /// which would produce a double-write to one cell.
    DuplicateOutputSlot,
    /// A tx tries to spend and mint to the same slot in one body. Reuse is
    /// allowed after a slot is freed, but not inside the same transaction: the
    /// exact transition surface requires output slots to be empty before the tx.
    InputOutputSlotOverlap,
    /// A live spend was attempted while the occupancy counter was already
    /// zero. Consensus code must fail closed instead of panicking or wrapping.
    ActiveSlotCountUnderflow,
    /// Minting a live output would overflow the occupancy counter.
    ActiveSlotCountOverflow,
    /// No fresh non-zero creation ID can be assigned to the next live output.
    /// The allocator namespace ends at `COINBASE_CREATION_TAG` (`2^63`): ids
    /// with the high bit set are reserved for tagged coinbase mints.
    AllocCounterOverflow,
    /// A coinbase body was applied without the mint height needed to derive
    /// its tagged `creation_id = COINBASE_CREATION_TAG | height`.
    CoinbaseMintHeightMissing,
    /// The exact post-state root cannot be recomputed because part of the raw
    /// state is evicted. Acceptance must fail closed or preload the state.
    ExactStateUnavailable,
    /// Derived monetary accounting disagrees with the exact slot transition.
    CirculatingSupplyInvariant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyExactTransitionError {
    SlotOutOfRange,
    HeaderLogSlotsMismatch,
    ExactStateRead(ExactStateReadError),
    CachedRootMismatch,
    CirculatingSupplyInvariant,
}

/// Apply a non-coinbase `TxBody` to `state` in place, returning the
/// post-transition root on success. Bitmap-dead slots are skipped entirely.
///
/// State root validation happens at block level via the exact authenticated
/// transition proof — this function purely executes the UTXO state transition
/// without checking anchors.
///
/// Coinbase bodies must go through [`apply_tx_at`]: their tagged
/// `creation_id` derives from the mint height, which only the block context
/// knows. Applying a coinbase here fails closed.
///
/// On `Err`, `state` is left untouched.
pub fn apply_tx(state: &mut ChainState, body: &TxBody) -> Result<StateTransition, ApplyError> {
    if body.is_coinbase {
        return Err(ApplyError::CoinbaseMintHeightMissing);
    }
    apply_tx_inner(state, body, None)
}

/// Apply a `TxBody` minted inside the block at `block_height`.
///
/// The primary coinbase output receives the tagged
/// `creation_id = COINBASE_CREATION_TAG | block_height`; development-payout
/// and user outputs receive fresh monotone allocator ids exactly as
/// [`apply_tx`].
pub fn apply_tx_at(
    state: &mut ChainState,
    body: &TxBody,
    block_height: u64,
) -> Result<StateTransition, ApplyError> {
    apply_tx_inner(state, body, Some(block_height))
}

fn apply_tx_inner(
    state: &mut ChainState,
    body: &TxBody,
    block_height: Option<u64>,
) -> Result<StateTransition, ApplyError> {
    let mut snapshot = state.clone();
    apply_tx_checked_deferred_root(&mut snapshot, body, block_height)?;
    let new_state_root = snapshot
        .try_state_root()
        .map_err(|_| ApplyError::ExactStateUnavailable)?;
    *state = snapshot;
    Ok(StateTransition { new_state_root })
}

/// Apply a `TxBody` to `state` while deferring the expensive Merkle root rebuild.
///
/// This preserves the same validation and atomicity semantics as [`apply_tx`],
/// but leaves dirty segment/tree roots to be flushed by a later `state_root()`
/// call. This is a consensus-internal construction helper, not a block
/// acceptance API; callers must compute/bind the final root before publishing or
/// accepting a header.
///
/// `coinbase_mint_height` supplies block context for system-mint bodies and the
/// tagged primary-coinbase `creation_id`; it MUST be `Some` when
/// `body.is_coinbase`.
pub(crate) fn apply_tx_checked_deferred_root(
    state: &mut ChainState,
    body: &TxBody,
    coinbase_mint_height: Option<u64>,
) -> Result<(), ApplyError> {
    if body.is_coinbase && coinbase_mint_height.is_none() {
        return Err(ApplyError::CoinbaseMintHeightMissing);
    }
    let native_active = coinbase_mint_height.is_some_and(crate::consensus::params::v2_1_active);
    let mut input_slots = HashSet::new();
    for (_, input) in body.live_inputs() {
        if native_active
            && input.creation_id & (3u64 << 62) == noid_tx::native_assets::NATIVE_CREATION_TAG
        {
            return Err(ApplyError::NativeInputRequiresNativeOperation);
        }
        if !input_slots.insert(input.slot_index) {
            return Err(ApplyError::UnknownOrSpentInput);
        }
    }

    // Wallet-chosen output slots: reject duplicates *within this tx*
    // up-front so we don't silently overwrite our own earlier write.
    let mut seen: HashSet<u32> = HashSet::new();
    for (_, output) in body.live_outputs() {
        if !seen.insert(output.slot_index) {
            return Err(ApplyError::DuplicateOutputSlot);
        }
        if input_slots.contains(&output.slot_index) {
            return Err(ApplyError::InputOutputSlotOverlap);
        }
    }

    let effective_log = state.state.effective_log_segment_size();
    let mut deltas = Vec::with_capacity(input_slots.len() + seen.len());
    for (_, input) in body.live_inputs() {
        if (input.slot_index as u64) >= state.state.num_slots() {
            return Err(ApplyError::SlotOutOfRange);
        }
        let segment_id = (input.slot_index >> effective_log) as u16;
        if state.state.is_evicted(segment_id) {
            return Err(ApplyError::ExactStateUnavailable);
        }
        let expected = SlotValue::with_owner_fields(
            input.amount,
            input.creation_id,
            body.input_owner.as_fields(),
        );
        if state.state.slot(input.slot_index) != expected {
            return Err(ApplyError::UnknownOrSpentInput);
        }
        deltas.push((input.slot_index, SlotValue::EMPTY));
    }

    let input_count = body.live_input_count() as u64;
    let output_count = body.live_output_count() as u64;
    let active_after_spends = state
        .active_slot_count
        .checked_sub(input_count)
        .ok_or(ApplyError::ActiveSlotCountUnderflow)?;
    let active_after = active_after_spends
        .checked_add(output_count)
        .ok_or(ApplyError::ActiveSlotCountOverflow)?;
    let final_alloc_counter = state
        .alloc_counter
        .checked_add(output_count)
        .ok_or(ApplyError::AllocCounterOverflow)?;
    // Normal mints live strictly below the coinbase tag namespace. Fail
    // closed instead of ever colliding with a tagged coinbase creation id.
    if crate::consensus::params::is_coinbase_creation_id(final_alloc_counter) {
        return Err(ApplyError::AllocCounterOverflow);
    }
    if native_active && final_alloc_counter > noid_tx::native_assets::NATIVE_SEQUENCE_MAX {
        return Err(ApplyError::AllocCounterOverflow);
    }

    let mut alloc_cursor = state.alloc_counter;
    for (_, output) in body.live_outputs() {
        if (output.slot_index as u64) >= state.state.num_slots() {
            return Err(ApplyError::SlotOutOfRange);
        }
        let segment_id = (output.slot_index >> effective_log) as u16;
        if state.state.is_evicted(segment_id) {
            return Err(ApplyError::ExactStateUnavailable);
        }
        if state.state.slot(output.slot_index) != SlotValue::EMPTY {
            return Err(ApplyError::OutputSlotNotEmpty);
        }
        // Every mint consumes one allocator increment, keeping
        // `alloc_counter` = "number of mints ever" and the wallet slot-hint
        // seed unchanged. The STORED id diverges only for the primary
        // coinbase: its live output is tagged with the mint height so spends
        // can be gated on an accepted HistoryStep boundary.
        alloc_cursor = alloc_cursor
            .checked_add(1)
            .ok_or(ApplyError::AllocCounterOverflow)?;
        let creation_id = if body.is_primary_coinbase_shape() {
            crate::consensus::params::coinbase_creation_id(
                coinbase_mint_height.ok_or(ApplyError::CoinbaseMintHeightMissing)?,
            )
        } else {
            alloc_cursor
        };
        deltas.push((
            output.slot_index,
            SlotValue::with_owner_fields(output.amount, creation_id, output.owner.as_fields()),
        ));
    }

    let circulating_supply_micronoid = state
        .supply_after_slot_updates(&deltas)
        .ok_or(ApplyError::CirculatingSupplyInvariant)?;
    state
        .state
        .apply_delta_unrooted(&deltas)
        .expect("all transaction delta indices were preflighted");
    state.active_slot_count = active_after;
    state.alloc_counter = final_alloc_counter;
    state.circulating_supply_micronoid = circulating_supply_micronoid;
    Ok(())
}

#[cfg(test)]
#[path = "state_cache_tests.rs"]
mod cache_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

    fn funded() -> ChainState {
        let mut state = ChainState::with_log_slots(8);
        state
            .state
            .set_slot(
                1,
                SlotValue::with_owner_fields(11, 7, Address([1u8; 32]).as_fields()),
            )
            .unwrap();
        state.active_slot_count = 1;
        state.alloc_counter = 7;
        state.circulating_supply_micronoid = 11;
        state
    }

    fn body(owner: Address, input_slot: u32, output_slot: u32) -> TxBody {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: input_slot,
            amount: 11,
            creation_id: 7,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: output_slot,
            amount: 10,
            owner: Address([2u8; 32]),
        };
        TxBody {
            epoch_anchor: [3u8; 32],
            fee: 1,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        }
    }

    #[test]
    fn explicit_input_owner_matches_state_and_output_gets_new_incarnation() {
        let mut state = funded();
        apply_tx(&mut state, &body(Address([1u8; 32]), 1, 2)).unwrap();
        assert_eq!(state.state.slot(1), SlotValue::EMPTY);
        assert_eq!(state.state.slot(2).amount(), 10);
        assert_eq!(state.state.slot(2).creation_id(), 8);
        assert_eq!(state.active_slot_count, 1);
        assert_eq!(state.alloc_counter, 8);
        assert_eq!(state.circulating_supply_micronoid, 10);
    }

    #[test]
    fn wrong_owner_and_occupied_output_fail_atomically() {
        let mut state = funded();
        let root = state.state_root();
        let supply = state.circulating_supply_micronoid;
        assert_eq!(
            apply_tx(&mut state, &body(Address([9u8; 32]), 1, 2)),
            Err(ApplyError::UnknownOrSpentInput)
        );
        assert_eq!(state.state_root(), root);
        assert_eq!(state.circulating_supply_micronoid, supply);

        let overlap = body(Address([1u8; 32]), 1, 1);
        assert_eq!(
            apply_tx(&mut state, &overlap),
            Err(ApplyError::InputOutputSlotOverlap)
        );
    }

    #[test]
    fn coinbase_mint_is_height_tagged_and_aba_binds_exact_creation_id() {
        use crate::consensus::params::{
            coinbase_creation_id, is_coinbase_creation_id, COINBASE_CREATION_TAG,
        };

        let miner = Address([5u8; 32]);
        let mut coinbase_outputs = [TxOutput::dummy(); TX_OUTPUTS];
        coinbase_outputs[0] = TxOutput {
            slot_index: 4,
            amount: 50,
            owner: miner,
        };
        let coinbase = TxBody {
            epoch_anchor: [9u8; 32],
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: coinbase_outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        };

        // A coinbase cannot be applied without its mint height.
        let mut state = ChainState::with_log_slots(8);
        assert_eq!(
            apply_tx(&mut state, &coinbase),
            Err(ApplyError::CoinbaseMintHeightMissing)
        );

        // Applied at height 42 the unique live output stores TAG | 42 while
        // the allocator still burns exactly one increment.
        apply_tx_at(&mut state, &coinbase, 42).unwrap();
        let minted = state.state.slot(4);
        assert_eq!(minted.creation_id(), coinbase_creation_id(42));
        assert_eq!(minted.creation_id(), COINBASE_CREATION_TAG | 42);
        assert!(is_coinbase_creation_id(minted.creation_id()));
        assert_eq!(state.alloc_counter, 1);
        assert_eq!(state.active_slot_count, 1);
        assert_eq!(state.circulating_supply_micronoid, 50);

        // ABA: a spend binds the EXACT tagged creation id. The untagged
        // allocator id the coinbase burned does not match the stored slot.
        let spend = |creation_id: u64| {
            let mut inputs = [TxInput::dummy(); TX_INPUTS];
            inputs[0] = TxInput {
                slot_index: 4,
                amount: 50,
                creation_id,
            };
            let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
            outputs[0] = TxOutput {
                slot_index: 6,
                amount: 49,
                owner: Address([6u8; 32]),
            };
            TxBody {
                epoch_anchor: [9u8; 32],
                fee: 1,
                input_owner: miner,
                inputs,
                outputs,
                validity_bitmap: 1 | output_bitmap_bit(0),
                is_coinbase: false,
            }
        };
        assert_eq!(
            apply_tx(&mut state.clone(), &spend(1)),
            Err(ApplyError::UnknownOrSpentInput)
        );
        assert_eq!(
            apply_tx(&mut state.clone(), &spend(coinbase_creation_id(41))),
            Err(ApplyError::UnknownOrSpentInput)
        );
        apply_tx(&mut state, &spend(coinbase_creation_id(42))).unwrap();
        // The user mint after the coinbase continues the untagged namespace.
        assert_eq!(state.state.slot(6).creation_id(), 2);
        assert_eq!(state.circulating_supply_micronoid, 49);
    }

    #[test]
    fn development_payout_uses_the_normal_allocator_namespace() {
        use crate::consensus::development_allocation::TARGET_BLOCKS_PER_DAY;
        use crate::consensus::params::is_coinbase_creation_id;

        let mut state = ChainState::with_log_slots(8);
        let mut miner_outputs = [TxOutput::dummy(); TX_OUTPUTS];
        miner_outputs[0] = TxOutput {
            slot_index: 4,
            amount: 45,
            owner: Address([5u8; 32]),
        };
        let miner = TxBody {
            epoch_anchor: [9u8; 32],
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: miner_outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        };
        apply_tx_at(&mut state, &miner, TARGET_BLOCKS_PER_DAY).unwrap();

        let payout = TxBody {
            epoch_anchor: [9u8; 32],
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: [
                TxOutput {
                    slot_index: 5,
                    amount: 10,
                    owner: crate::consensus::development_allocation::O1_NETWORK_FUND_ADDRESS,
                },
                TxOutput {
                    slot_index: 6,
                    amount: 10,
                    owner: crate::consensus::development_allocation::PARANO1D_LAB_ADDRESS,
                },
            ],
            validity_bitmap: output_bitmap_bit(0) | output_bitmap_bit(1),
            is_coinbase: true,
        };
        apply_tx_at(&mut state, &payout, TARGET_BLOCKS_PER_DAY).unwrap();

        assert_eq!(state.state.slot(5).creation_id(), 2);
        assert_eq!(state.state.slot(6).creation_id(), 3);
        assert!(!is_coinbase_creation_id(state.state.slot(5).creation_id()));
        assert!(!is_coinbase_creation_id(state.state.slot(6).creation_id()));
        assert_eq!(state.alloc_counter, 3);
        assert_eq!(state.active_slot_count, 3);
        assert_eq!(state.circulating_supply_micronoid, 65);
    }

    #[test]
    fn allocator_fails_closed_at_the_coinbase_tag_namespace() {
        use crate::consensus::params::COINBASE_CREATION_TAG;

        let mut state = ChainState::with_log_slots(8);
        state.alloc_counter = COINBASE_CREATION_TAG - 1;
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 2,
            amount: 1,
            owner: Address([7u8; 32]),
        };
        let mint_only = TxBody {
            epoch_anchor: [3u8; 32],
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        };
        // Even the coinbase's own allocator increment must not cross 2^63.
        assert_eq!(
            apply_tx_at(&mut state, &mint_only, 1),
            Err(ApplyError::AllocCounterOverflow)
        );
    }

    #[test]
    fn duplicate_live_outputs_reject() {
        let mut body = body(Address([1u8; 32]), 1, 2);
        body.outputs[1] = body.outputs[0];
        body.validity_bitmap |= output_bitmap_bit(1);
        assert_eq!(
            apply_tx(&mut funded(), &body),
            Err(ApplyError::DuplicateOutputSlot)
        );
    }

    #[test]
    fn streaming_exact_update_root_matches_full_rebuild_without_state_clone() {
        let owner = Address([0x51; 32]);
        let slots = [
            (0, SlotValue::with_owner_fields(3, 1, owner.as_fields())),
            (1, SlotValue::with_owner_fields(5, 2, owner.as_fields())),
            (7, SlotValue::with_owner_fields(7, 3, owner.as_fields())),
            (31, SlotValue::with_owner_fields(11, 4, owner.as_fields())),
            (63, SlotValue::with_owner_fields(13, 5, owner.as_fields())),
        ];
        let state = ChainState::from_sparse_utxos(6, &slots, 5).unwrap();
        let updates = [
            (1, SlotValue::EMPTY),
            (8, SlotValue::with_owner_fields(17, 6, owner.as_fields())),
            (31, SlotValue::with_owner_fields(19, 7, owner.as_fields())),
        ];

        let mut reference = state.clone();
        reference.state.apply_delta_unrooted(&updates).unwrap();
        let expected = reference.rebuild_exact_utxo_root_loaded().unwrap();
        assert_eq!(
            state
                .exact_utxo_root_after_slot_updates(6, &updates)
                .unwrap(),
            expected
        );

        let expansion_update = [(100, SlotValue::with_owner_fields(23, 8, owner.as_fields()))];
        let mut expanded_reference = state.clone();
        expanded_reference.expand_one();
        expanded_reference
            .state
            .apply_delta_unrooted(&expansion_update)
            .unwrap();
        let expanded_expected = expanded_reference.rebuild_exact_utxo_root_loaded().unwrap();
        assert_eq!(
            state
                .exact_utxo_root_after_slot_updates(7, &expansion_update)
                .unwrap(),
            expanded_expected
        );
    }

    #[test]
    fn exact_only_production_expansion_matches_normal_exact_root_rule() {
        let log_slots = LOG_SEGMENT_SIZE;
        let old_root = zero_slot_roots(log_slots)[log_slots];
        let expected = state_node_hash(old_root, old_root);
        let mut state = ChainState {
            state: SegmentedFriState::new_exact_metadata_only_for_test(log_slots),
            utxo_root: old_root,
            active_slot_count: 0,
            alloc_counter: 0,
            circulating_supply_micronoid: 0,
            exact_roots: ExactSegmentRootCache::empty(log_slots),
        };

        state.expand_exact_metadata_for_replay().unwrap();
        assert_eq!(state.state.log_slots(), log_slots + 1);
        assert_eq!(state.state.num_segments(), 2);
        assert_eq!(state.cached_state_root(), expected);
        assert_eq!(state.exact_roots.root(), expected);
        assert_eq!(state.state.materialized_segment_ids().count(), 0);
    }

    #[test]
    fn sealed_small_expansion_keeps_the_exact_frontier_readable() {
        let owner = Address([0x5E; 32]);
        let mut state = ChainState::from_sparse_utxos(
            8,
            &[(3, SlotValue::with_owner_fields(9, 1, owner.as_fields()))],
            1,
        )
        .unwrap();
        let parent_root = state.cached_state_root();

        state.expand_one();

        assert_eq!(
            state.cached_state_root(),
            state_node_hash(parent_root, zero_slot_roots(8)[8])
        );
        assert!(state.exact_frontier_siblings(&[3], 9).is_ok());
    }

    #[test]
    fn streaming_exact_update_rebinds_cached_parent_root() {
        let mut state = ChainState::from_sparse_utxos(
            4,
            &[(
                3,
                SlotValue::with_owner_fields(9, 1, Address([0x61; 32]).as_fields()),
            )],
            1,
        )
        .unwrap();
        state.utxo_root = [0xA5; 32];
        assert_eq!(
            state.exact_utxo_root_after_slot_updates(4, &[]),
            Err(ApplyExactTransitionError::CachedRootMismatch)
        );
    }

    #[test]
    fn compact_frontier_matches_full_cache_with_unrelated_segment_evicted() {
        let owner = Address([0x69; 32]);
        let mut state = ChainState::from_sparse_utxos(
            17,
            &[
                (3, SlotValue::with_owner_fields(9, 1, owner.as_fields())),
                (
                    (1 << 16) + 5,
                    SlotValue::with_owner_fields(11, 2, owner.as_fields()),
                ),
            ],
            2,
        )
        .unwrap();
        let touched = [3, 7];
        let full = crate::sparse_merkle::build_multiproof(
            &state.state.exact_sparse_cache().unwrap(),
            &touched,
            17,
        )
        .unwrap();

        state.state.evict_segment(1);
        assert_eq!(
            state.exact_frontier_siblings(&touched, 17).unwrap(),
            full.siblings
        );
        assert!(matches!(
            state.exact_frontier_siblings(&[(1 << 16) + 5], 17),
            Err(ExactFrontierError::ExactStateRead(
                ExactStateReadError::EvictedSegment { seg_id: 1 }
            ))
        ));
    }

    #[test]
    fn verified_transition_rejects_shape_before_in_place_mutation() {
        let mut state = ChainState::from_sparse_utxos(
            4,
            &[(
                3,
                SlotValue::with_owner_fields(9, 1, Address([0x71; 32]).as_fields()),
            )],
            1,
        )
        .unwrap();
        let root = state.cached_state_root();
        let slot = state.state.slot(3);
        assert_eq!(
            state.apply_verified_exact_transition(4, [0x11; 32], &[(16, SlotValue::EMPTY)], 0, 1,),
            Err(ApplyExactTransitionError::SlotOutOfRange)
        );
        assert_eq!(state.cached_state_root(), root);
        assert_eq!(state.state.slot(3), slot);
        assert_eq!(state.state.log_slots(), 4);
    }

    #[test]
    fn verified_exact_transition_updates_the_derived_supply_atomically() {
        let owner = Address([0x72; 32]);
        let mut state = ChainState::from_sparse_utxos(
            4,
            &[(3, SlotValue::with_owner_fields(9, 1, owner.as_fields()))],
            1,
        )
        .unwrap();
        let updates = [
            (3, SlotValue::EMPTY),
            (5, SlotValue::with_owner_fields(8, 2, owner.as_fields())),
        ];
        let child_root = state
            .exact_utxo_root_after_slot_updates(4, &updates)
            .unwrap();

        state
            .apply_verified_exact_transition(4, child_root, &updates, 1, 2)
            .unwrap();

        assert_eq!(state.circulating_supply_micronoid, 8);
        assert_eq!(state.cached_state_root(), child_root);
    }
}
