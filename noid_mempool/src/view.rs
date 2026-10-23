// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `ChainView` — a lightweight snapshot of chain state for mempool admission checks.
//!
//! The view is updated by the node on each new block via `AsyncMempool::on_new_block`.
//! It is intentionally a value type so that admission checks see a consistent snapshot
//! even if a new block arrives concurrently.
//!
//! ## What fits in the view
//!
//! Only data needed for admission:
//! 1. `recent_headers` — exact transaction-epoch anchor validation
//! 2. `state` — slot liveness and emptiness checks
//! 3. `tip_height` — next-child epoch-boundary selection
//!
//! The full `SegmentedFriState` is included because it uses lazy segment
//! materialisation — virtual-zero segments are not allocated. At genesis with no
//! activity, a clone costs O(1). Growth is proportional to occupied slots.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::{pow::block_id, tx_epoch_anchor_height_for_child};
use noid_chain::fri_state::SlotValue;
use noid_chain::segmented_state::SegmentedFriState;
use noid_chain::storage::MdbxStore;

const SEGMENT_READ_CACHE_CAPACITY: usize = 4;

#[derive(Debug)]
pub enum ChainViewReadError {
    StaleOrUnavailable,
    CorruptSegment,
    CachePoisoned,
}

impl core::fmt::Display for ChainViewReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StaleOrUnavailable => write!(f, "chain view is stale or segment unavailable"),
            Self::CorruptSegment => write!(f, "durable segment shape is corrupt"),
            Self::CachePoisoned => write!(f, "chain view segment cache is poisoned"),
        }
    }
}

impl std::error::Error for ChainViewReadError {}

#[derive(Default)]
struct SegmentReadCache {
    entries: VecDeque<(u16, Arc<noid_chain::segmented_state::SegmentColumns>)>,
}

/// A consistent snapshot of chain state used for mempool admission.
#[derive(Clone)]
pub struct ChainView {
    /// Current chain tip height.
    pub tip_height: u64,

    /// Retained block headers needed to resolve the one current transaction
    /// epoch anchor.
    pub recent_headers: HashMap<u64, BlockHeader>,

    /// Total number of slots in the current state space.
    pub num_slots: u64,

    /// Number of live UTXO slots at the current tip.
    pub active_slot_count: u64,

    /// Exact anchor id accepted by user transactions in the next child block.
    pub user_epoch_anchor_id: [u8; 32],

    /// Canonical tip hash paired with `tip_height` for atomic durable reads.
    pub tip_hash: [u8; 32],

    /// UTXO state for slot liveness / emptiness checks.
    /// Lazy: only materialized segments are allocated.
    state: SegmentedFriState,
    store: Option<MdbxStore>,
    segment_cache: Arc<Mutex<SegmentReadCache>>,
}

impl ChainView {
    pub(crate) fn native_financial_parent(&self) -> Result<BlockHeader, ChainViewReadError> {
        let parent = self
            .recent_headers
            .get(&self.tip_height)
            .ok_or(ChainViewReadError::StaleOrUnavailable)?;
        if parent.height != self.tip_height
            || block_id(parent) != self.tip_hash
            || parent.log_slots != self.log_slots()
            || parent.active_slot_count != self.active_slot_count
            || parent.alloc_counter > noid_tx::native_assets::NATIVE_SEQUENCE_MAX
        {
            return Err(ChainViewReadError::StaleOrUnavailable);
        }
        Ok(*parent)
    }

    /// Construct a `ChainView` from the given state components.
    pub fn new(
        tip_height: u64,
        recent_headers: HashMap<u64, BlockHeader>,
        active_slot_count: u64,
        state: SegmentedFriState,
    ) -> Self {
        let num_slots = state.num_slots();
        let anchor_height = tx_epoch_anchor_height_for_child(tip_height + 1);
        let user_epoch_anchor_id = recent_headers
            .get(&anchor_height)
            .map(block_id)
            .unwrap_or([0u8; 32]);
        let tip_hash = recent_headers
            .get(&tip_height)
            .map(block_id)
            .unwrap_or([0u8; 32]);
        Self {
            tip_height,
            recent_headers,
            num_slots,
            active_slot_count,
            user_epoch_anchor_id,
            tip_hash,
            state,
            store: None,
            segment_cache: Arc::new(Mutex::new(SegmentReadCache::default())),
        }
    }

    /// Current log2(state_size): number of slot address bits.
    pub fn log_slots(&self) -> u32 {
        self.state.log_slots() as u32
    }

    /// Read one slot, faulting at most one durable segment into a four-entry
    /// shared LRU.  A tip mismatch fails closed instead of interpreting an
    /// evicted live segment as EMPTY.
    pub fn try_slot(&self, idx: u32) -> Result<SlotValue, ChainViewReadError> {
        if (idx as u64) >= self.num_slots {
            return Ok(SlotValue::EMPTY);
        }
        let effective_log = self.state.effective_log_segment_size();
        let segment_id = (idx >> effective_log) as u16;
        if !self.state.is_evicted(segment_id) {
            return Ok(self.state.slot(idx));
        }
        let store = self
            .store
            .as_ref()
            .ok_or(ChainViewReadError::StaleOrUnavailable)?;
        let mut cache = self
            .segment_cache
            .lock()
            .map_err(|_| ChainViewReadError::CachePoisoned)?;
        let columns = if let Some(position) = cache
            .entries
            .iter()
            .position(|(cached_id, _)| *cached_id == segment_id)
        {
            let entry = cache.entries.remove(position).expect("position exists");
            let columns = entry.1.clone();
            cache.entries.push_front(entry);
            columns
        } else {
            let (stored_log, columns) = store
                .get_segment_at_tip(self.tip_height, self.tip_hash, segment_id)
                .map_err(|_| ChainViewReadError::StaleOrUnavailable)?
                .ok_or(ChainViewReadError::StaleOrUnavailable)?;
            let expected_len = 1usize << effective_log;
            if usize::from(stored_log) != effective_log
                || columns.values.len() != expected_len
                || columns.owners_hi.len() != expected_len
                || columns.owners_lo.len() != expected_len
            {
                return Err(ChainViewReadError::CorruptSegment);
            }
            let columns = Arc::new(columns);
            cache.entries.push_front((segment_id, columns.clone()));
            cache.entries.truncate(SEGMENT_READ_CACHE_CAPACITY);
            columns
        };
        let local = (idx & ((1u32 << effective_log) - 1)) as usize;
        Ok(SlotValue {
            value: columns.values[local],
            owner_hi: columns.owners_hi[local],
            owner_lo: columns.owners_lo[local],
        })
    }

    /// Build a `ChainView` from a `MdbxChainContext` (call on every new block).
    ///
    /// Clones only the metadata (headers) and the sparse state.
    /// The state clone is cheap when few segments are materialised.
    pub fn from_mdbx(ctx: &noid_chain::storage::MdbxChainContext) -> Self {
        let metadata_state = ctx
            .state
            .durable_metadata_clone()
            .expect("ChainView must be captured at a durable block boundary");
        let mut view = Self::new(
            ctx.tip_height,
            ctx.recent_headers.clone(),
            ctx.state.active_slot_count,
            metadata_state.state,
        );
        view.tip_hash = ctx.tip_hash;
        view.store = Some(ctx.store.clone());
        let anchor_height = tx_epoch_anchor_height_for_child(ctx.tip_height + 1);
        view.user_epoch_anchor_id = ctx
            .get_header_from_store(anchor_height)
            .ok()
            .flatten()
            .map(|header| block_id(&header))
            .unwrap_or([0u8; 32]);
        view
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_child_anchor_is_exact_at_143_144_145_boundary() {
        let genesis = noid_chain::consensus::genesis::genesis_header();
        let mut boundary = genesis;
        boundary.height = 144;
        boundary.timestamp = boundary.timestamp.saturating_add(144);
        let genesis_id = block_id(&genesis);
        let boundary_id = block_id(&boundary);
        let headers = HashMap::from([(0, genesis), (144, boundary)]);

        let view = |tip_height| {
            ChainView::new(
                tip_height,
                headers.clone(),
                0,
                noid_chain::state::ChainState::with_log_slots(8).state,
            )
        };
        assert_eq!(view(142).user_epoch_anchor_id, genesis_id); // child 143
        assert_eq!(view(143).user_epoch_anchor_id, genesis_id); // child 144
        assert_eq!(view(144).user_epoch_anchor_id, boundary_id); // child 145
    }
}
