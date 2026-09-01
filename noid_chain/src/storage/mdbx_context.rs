// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `MdbxChainContext` — crash-consistent chain context backed by MDBX.
//!
//! This is the sole chain context that can advance the accepted canonical tip.
//! It survives process restarts and commits one complete accepted bundle at a
//! time.
//!
//! # Crash-consistency guarantee (P.18)
//!
//! Every `apply_next_block` call writes all block data in ONE atomic MDBX
//! transaction. Either the full block is committed or nothing is. On restart,
//! `open_or_create` reads `chain_tip` from MDBX and rebuilds hot RAM state
//! from compact per-segment exact summaries. No replay from genesis needed.
//!
//! # Restart strategy
//!
//! On startup, the node authenticates the compact exact segment-root set
//! against the canonical tip's `state_root`, then faults raw columns in and
//! checks them only when first touched. A legacy database without summaries
//! performs one dense verification and writes the accelerator for later runs.
//!
//! If persisted state cannot be restored, every chain table is cleared before
//! the canonical genesis is installed. Mixed-epoch recovery is never attempted.
//!
//! This prevents simultaneous-restart network death: when all nodes reboot,
//! each resumes from its own verified state instead of needing a peer snapshot.
//!
//! # Hot vs cold data
//!
//! | Data | Where | Why |
//! |------|-------|-----|
//! | Headers | MDBX (forever) | Random access by height/hash |
//! | Segment columns | MDBX (forever) | Persist across restarts |
//! | Exact segment summaries | MDBX (forever) | Header-authenticated fast restart |
//! | Undo logs | MDBX retained window | Reorg recovery |
//! | Accepted block bundles | MDBX retained suffix | Bounded peer sync and reorg input |
//! | ChainState (active/alloc) | MDBX (state_meta) | Fast restart |
//! | Recent headers | RAM (MTP/expansion window) | Header validation |

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// Keep the normal per-block profile at debug level, but surface genuinely
/// slow local storage work in production logs. This is observability only:
/// it neither changes admission nor adds work to the commit path beyond the
/// `Instant` measurements that were already present.
const RECURSIVE_SUFFIX_SLOW_PATH: Duration = Duration::from_secs(2);

use crate::block::Block;
use crate::block_header::BlockHeader;
use crate::consensus::{
    da_prune::{build_undo_log, revert_block, BlockUndoLog},
    difficulty::{add_work, block_work},
    epoch_anchor::{tx_epoch_anchor_height_for_child, validate_block_epoch_anchors},
    genesis::genesis_header,
    header::asert_anchor_height,
    params::{
        BLOCK_MAX_DISTINCT_SEGMENTS, CONSENSUS_FINALITY_DEPTH, EXPANSION_HEADER_LOOKBACK,
        EXPANSION_WINDOW, GENESIS_TARGET, LOG_SEGMENT_SIZE, MEDIAN_TIME_BLOCKS, TX_EPOCH_BLOCKS,
    },
    pow::{block_id, validate_pow},
    slot_expansion::finalized_expansion_window,
    template::LocallyProvedBlockCommit,
    validation::{validate_block_checks, AnchorInfo},
    ConsensusError,
};
use crate::segmented_state::SegmentedFriState;
use crate::state::{ChainState, StreamingSparseRoot};
use crate::storage::mdbx_store::{AcceptedBlockCommit, StagedAcceptedBlockCommit};
use crate::storage::{
    ConsensusMeta, FinalizedCheckpoint, FinalizedSnapshotStaging, MdbxStore,
    SnapshotHeaderInstallSource, StoreError, VerifiedSnapshotBoundary,
};

fn canonical_genesis_parts() -> (ChainState, HashMap<u64, BlockHeader>, [u8; 32]) {
    let header = genesis_header();
    let hash = block_id(&header);
    let mut headers = HashMap::new();
    headers.insert(0, header);
    (ChainState::new(), headers, hash)
}

fn recent_header_lookback() -> u64 {
    (MEDIAN_TIME_BLOCKS as u64).max(EXPANSION_HEADER_LOOKBACK)
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum MdbxContextError {
    Store(StoreError),
    Consensus(ConsensusError),
    Corrupt(&'static str),
    ResourceLimit {
        resource: &'static str,
        actual: usize,
        maximum: usize,
    },
}

impl std::fmt::Display for MdbxContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "store: {e}"),
            Self::Consensus(e) => write!(f, "consensus: {e}"),
            Self::Corrupt(msg) => write!(f, "corrupt: {msg}"),
            Self::ResourceLimit {
                resource,
                actual,
                maximum,
            } => write!(f, "resource limit: {resource} {actual} exceeds {maximum}"),
        }
    }
}
impl std::error::Error for MdbxContextError {}

impl From<StoreError> for MdbxContextError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<ConsensusError> for MdbxContextError {
    fn from(e: ConsensusError) -> Self {
        Self::Consensus(e)
    }
}

/// Failure while atomically installing a preverified recursive suffix.
///
/// `body_index` is present only when validation actually entered that exact
/// replacement body. Preflight fork-choice races, canonical-view changes and
/// database failures deliberately carry no peer attribution.
#[derive(Debug)]
pub struct IndexedReorgSuffixError {
    pub body_index: Option<usize>,
    pub error: MdbxContextError,
}

impl std::fmt::Display for IndexedReorgSuffixError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for IndexedReorgSuffixError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<MdbxContextError> for IndexedReorgSuffixError {
    fn from(error: MdbxContextError) -> Self {
        Self {
            body_index: None,
            error,
        }
    }
}

impl From<StoreError> for IndexedReorgSuffixError {
    fn from(error: StoreError) -> Self {
        MdbxContextError::Store(error).into()
    }
}

/// One block's claim that a terminal attests its own HistoryStep.
///
/// `noid_chain` resolves the canonical headers the native verifier must bind
/// against; the injected verifier (owned by the node, which holds the pinned
/// registry/matrix artifacts) performs the actual cryptographic check.
#[derive(Debug, Clone, Copy)]
pub struct HistoryStepTerminalClaim<'a> {
    /// Serialized HistoryStep terminal package bytes.
    pub terminal_bytes: &'a [u8],
    /// The exact candidate header the terminal must bind. It is deliberately
    /// not loaded from the older canonical store because the candidate is not
    /// committed until this verification succeeds.
    pub header: BlockHeader,
    /// Canonical transaction-epoch anchor header for height C.
    pub epoch_anchor_header: BlockHeader,
}

/// Non-cloneable proof that one exact terminal passed the pinned recursive
/// verifier for its sealed tip and transaction-epoch anchor. Canonical base
/// and fork-choice checks intentionally happen later when a chain context
/// consumes this capability under the sole-writer boundary.
#[derive(Debug)]
pub struct VerifiedHistoryStepTerminal {
    tip_header: BlockHeader,
    epoch_anchor_header: BlockHeader,
    terminal_bytes: Vec<u8>,
}

/// Perform the expensive recursive verification without holding the mutable
/// chain lock. The returned capability cannot commit anything by itself.
pub fn verify_history_step_terminal_candidate<A>(
    tip_header: BlockHeader,
    epoch_anchor_header: BlockHeader,
    terminal_bytes: Vec<u8>,
    verify_history_step_terminal: A,
) -> Result<VerifiedHistoryStepTerminal, MdbxContextError>
where
    A: FnOnce(&HistoryStepTerminalClaim<'_>) -> Result<(), String>,
{
    if terminal_bytes.len() > crate::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_BYTES {
        return Err(MdbxContextError::Consensus(
            ConsensusError::BadHistoryStepTerminal(
                "recursive suffix terminal exceeds the wire cap".to_string(),
            ),
        ));
    }
    let expected_epoch_height = tx_epoch_anchor_height_for_child(tip_header.height);
    if epoch_anchor_header.height != expected_epoch_height {
        return Err(MdbxContextError::Consensus(
            ConsensusError::BadHistoryStepTerminal(
                "recursive suffix terminal epoch anchor is invalid".to_string(),
            ),
        ));
    }
    let metadata = crate::history_step::HistoryStepTerminalMetadata::decode_prefix(&terminal_bytes)
        .map_err(|error| {
            MdbxContextError::Consensus(ConsensusError::BadHistoryStepTerminal(format!(
                "recursive suffix terminal metadata is invalid: {error}"
            )))
        })?;
    if metadata.terminal_height() != tip_header.height
        || metadata.terminal_hash() != crate::block_header::semantic_header_id(&tip_header)
    {
        return Err(MdbxContextError::Consensus(
            ConsensusError::BadHistoryStepTerminal(
                "recursive suffix terminal does not bind its sealed tip".to_string(),
            ),
        ));
    }
    verify_history_step_terminal(&HistoryStepTerminalClaim {
        terminal_bytes: &terminal_bytes,
        header: tip_header,
        epoch_anchor_header,
    })
    .map_err(|error| MdbxContextError::Consensus(ConsensusError::BadHistoryStepTerminal(error)))?;

    Ok(VerifiedHistoryStepTerminal {
        tip_header,
        epoch_anchor_header,
        terminal_bytes,
    })
}

/// Non-cloneable authority for one exact linked snapshot suffix.
///
/// Construction verifies the suffix tip's recursive HistoryStep terminal and
/// persists a crash-recovery record at the current boundary. Each successful
/// body commit advances this capability exactly once; the final body stores
/// the complete verified terminal and closes the temporary authority.
#[derive(Debug)]
pub struct VerifiedRecursiveSuffix {
    boundary_height: u64,
    tip_header: BlockHeader,
    epoch_anchor_header: BlockHeader,
    terminal_bytes: Vec<u8>,
    next_height: u64,
    previous_hash: [u8; 32],
    complete: bool,
}

impl VerifiedRecursiveSuffix {
    pub fn boundary_height(&self) -> u64 {
        self.boundary_height
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_header.height
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        block_id(&self.tip_header)
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

/// Non-cloneable authority for one exact replacement suffix.
///
/// The recursive terminal is verified while the old canonical view is still
/// intact. Application later rechecks that exact view under the sole chain
/// writer before any RAM rollback, consumes the suffix linearly, and commits
/// the complete replacement in one MDBX transaction.
#[derive(Debug)]
pub struct VerifiedReorgSuffix {
    suffix: VerifiedRecursiveSuffix,
    original_tip_height: u64,
    original_tip_hash: [u8; 32],
    original_finalized: FinalizedCheckpoint,
}

impl VerifiedReorgSuffix {
    pub fn ancestor_height(&self) -> u64 {
        self.suffix.boundary_height()
    }

    pub fn tip_height(&self) -> u64 {
        self.suffix.tip_height()
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.suffix.tip_hash()
    }
}

/// A shallow in-RAM reorg may retain the union of old-branch and replacement
/// segments until the single atomic commit. One maximally dispersed old block
/// plus one replacement block is supported; larger unions use snapshot sync.
const MAX_REORG_RESIDENT_SEGMENTS: usize = BLOCK_MAX_DISTINCT_SEGMENTS * 2;
/// A replacement may advance beyond the old tip while still sharing a
/// non-final ancestor. Larger gaps use snapshot admission rather than holding
/// an unbounded atomic reorg candidate in RAM.
const MAX_REORG_REPLACEMENT_BLOCKS: usize = CONSENSUS_FINALITY_DEPTH as usize * 2;

/// Compact pre-hydration FRI authority for one block-touched segment.
/// Raw columns are never retained for rollback: the exact parent commitment
/// proves the restored bytes, while this optional 32-byte value restores the
/// non-consensus FRI cache to precisely the authority it had beforehand.
type ParentSegmentSummary = (u16, Option<[u8; 32]>);

fn track_reorg_segment(
    segment_ids: &mut std::collections::HashSet<u16>,
    slot_index: u32,
) -> Result<(), MdbxContextError> {
    segment_ids.insert((slot_index >> LOG_SEGMENT_SIZE) as u16);
    if segment_ids.len() > MAX_REORG_RESIDENT_SEGMENTS {
        return Err(MdbxContextError::ResourceLimit {
            resource: "reorg resident segments",
            actual: segment_ids.len(),
            maximum: MAX_REORG_RESIDENT_SEGMENTS,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MdbxChainContext
// ---------------------------------------------------------------------------

/// Crash-consistent chain context backed by MDBX.
///
/// On startup: reads tip from MDBX, loads all segment columns, rebuilds
/// loads recent headers.
///
/// On each block: writes all data atomically, then updates hot RAM state.
pub struct MdbxChainContext {
    /// MDBX database (all durable storage).
    pub store: MdbxStore,

    /// Hot in-memory UTXO state (rebuilt from MDBX on startup, updated on each block).
    /// `state.state` is a `SegmentedFriState` whose dirty segments are written to MDBX
    /// atomically with each block commit.
    pub state: ChainState,

    /// Recent headers needed for MTP, ASERT and finalized state expansion.
    pub recent_headers: HashMap<u64, BlockHeader>,

    /// Current tip height.
    pub tip_height: u64,

    /// H_BLOCK of the current tip.
    pub tip_hash: [u8; 32],

    /// Cumulative PoW work for the current tip chain.
    /// Sum of block_work(difficulty_target) for all blocks from genesis to tip.
    /// Used as the primary fork choice criterion (more work = canonical chain).
    pub tip_chain_work: [u8; 32],

    /// Non-optional hard-finalized canonical checkpoint.
    pub finalized: FinalizedCheckpoint,

    /// Internal guard used during batch reorg application: finality is advanced
    /// only after the whole replacement branch has been applied successfully.
    defer_finality_updates: bool,

    /// Owned commits produced while a replacement branch is validated in RAM.
    /// `Some` suppresses per-block MDBX writes; the complete vector is installed
    /// together only after every replacement block succeeds.
    reorg_staging: Option<Vec<StagedAcceptedBlockCommit>>,
}

impl MdbxChainContext {
    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    fn load_dense_chain_state(
        store: &MdbxStore,
        log_slots: u32,
        active_slot_count: u64,
        alloc_counter: u64,
        tip_height: u64,
        expected_root: [u8; 32],
    ) -> Result<ChainState, MdbxContextError> {
        let mut segmented = SegmentedFriState::new_empty(log_slots as usize);
        let effective_log = segmented.effective_log_segment_size();
        let expected_segment_len = 1usize << effective_log;
        let mut exact = StreamingSparseRoot::new(log_slots)
            .map_err(|_| MdbxContextError::Corrupt("invalid durable state depth"))?;
        let mut exact_segment_roots = Vec::new();
        let mut counted_live = 0u64;
        let mut circulating_supply_micronoid = 0u128;
        store.visit_segments(|segment_id, stored_log, columns| {
            if usize::from(stored_log) != effective_log
                || columns.values.len() != expected_segment_len
                || columns.owners_hi.len() != expected_segment_len
                || columns.owners_lo.len() != expected_segment_len
            {
                return Err(StoreError::Decode("invalid durable segment shape"));
            }
            let mut segment_live = 0u32;
            let base = (segment_id as u32) << effective_log;
            for local in 0..expected_segment_len {
                let slot = crate::fri_state::SlotValue {
                    value: columns.values[local],
                    owner_hi: columns.owners_hi[local],
                    owner_lo: columns.owners_lo[local],
                };
                if slot.is_empty() {
                    continue;
                }
                if !crate::consensus::params::creation_id_within_boundary(
                    slot.creation_id(),
                    alloc_counter,
                    tip_height,
                ) {
                    return Err(StoreError::Decode(
                        "persisted slot creation_id exceeds tip boundary",
                    ));
                }
                segment_live = segment_live
                    .checked_add(1)
                    .ok_or(StoreError::Decode("durable segment live-count overflow"))?;
                circulating_supply_micronoid = circulating_supply_micronoid
                    .checked_add(u128::from(slot.amount()))
                    .ok_or(StoreError::Decode("durable circulating supply overflow"))?;
                exact
                    .push_leaf(
                        base | local as u32,
                        crate::exact_state_hash::slot_leaf_hash(slot),
                    )
                    .map_err(|_| StoreError::Decode("durable exact leaf is out of range"))?;
            }
            counted_live = counted_live
                .checked_add(u64::from(segment_live))
                .ok_or(StoreError::Decode("durable active count overflow"))?;
            let segment_root = crate::fri_state::compute_segment_root(
                effective_log,
                &columns.values,
                &columns.owners_hi,
                &columns.owners_lo,
            );
            segmented
                .install_evicted_segment_summary(segment_id, segment_live, segment_root)
                .map_err(StoreError::Decode)?;
            exact_segment_roots.push((
                segment_id,
                crate::state::exact_segment_root_from_columns(effective_log, &columns),
            ));
            Ok(())
        })?;
        if counted_live != active_slot_count {
            return Err(MdbxContextError::Corrupt(
                "durable active count does not match exact segments",
            ));
        }
        segmented.finish_evicted_segment_summaries();
        let root = exact
            .finish()
            .map_err(|_| MdbxContextError::Corrupt("durable exact root build failed"))?;
        if root != expected_root {
            return Err(MdbxContextError::Corrupt(
                "durable exact state root mismatch",
            ));
        }
        ChainState::from_evicted_parts(
            segmented,
            active_slot_count,
            alloc_counter,
            circulating_supply_micronoid,
            root,
            &exact_segment_roots,
        )
        .map_err(|_| MdbxContextError::Corrupt("durable exact segment summary mismatch"))
    }

    /// Rebuild the hot exact state from the compact per-segment restart index.
    /// `Ok(None)` means the accelerator is absent, incomplete or invalid and
    /// the caller must fall back to the dense one-time verifier above.
    fn try_load_compact_chain_state(
        store: &MdbxStore,
        log_slots: u32,
        active_slot_count: u64,
        alloc_counter: u64,
        circulating_supply_micronoid: u128,
        expected_root: [u8; 32],
    ) -> Result<Option<ChainState>, MdbxContextError> {
        let segment_ids = store.segment_ids()?;
        let summaries = match store.segment_summaries() {
            Ok(summaries) => summaries,
            Err(error) => {
                tracing::warn!(%error, "compact segment summaries are unreadable; rebuilding");
                return Ok(None);
            }
        };
        if segment_ids.len() != summaries.len()
            || segment_ids
                .iter()
                .zip(&summaries)
                .any(|(segment_id, (summary_id, _, _))| segment_id != summary_id)
        {
            return Ok(None);
        }

        let mut segmented = SegmentedFriState::new_empty(log_slots as usize);
        let segment_capacity = 1u32
            .checked_shl(segmented.effective_log_segment_size() as u32)
            .ok_or(MdbxContextError::Corrupt(
                "invalid compact segment geometry",
            ))?;
        let mut exact_segment_roots = Vec::with_capacity(summaries.len());
        let mut counted_live = 0u64;
        for (segment_id, live_count, exact_root) in summaries {
            if live_count == 0 || live_count > segment_capacity {
                return Ok(None);
            }
            counted_live = match counted_live.checked_add(u64::from(live_count)) {
                Some(counted) => counted,
                None => return Ok(None),
            };
            if segmented
                .install_evicted_exact_summary(segment_id, live_count)
                .is_err()
            {
                return Ok(None);
            }
            exact_segment_roots.push((segment_id, exact_root));
        }
        if counted_live != active_slot_count {
            return Ok(None);
        }
        segmented.finish_evicted_exact_summaries();
        match ChainState::from_evicted_parts(
            segmented,
            active_slot_count,
            alloc_counter,
            circulating_supply_micronoid,
            expected_root,
            &exact_segment_roots,
        ) {
            Ok(state) => Ok(Some(state)),
            Err(_) => Ok(None),
        }
    }

    pub(crate) fn load_streamed_chain_state(
        store: &MdbxStore,
        log_slots: u32,
        active_slot_count: u64,
        alloc_counter: u64,
        persisted_circulating_supply_micronoid: Option<u128>,
        tip_height: u64,
        expected_root: [u8; 32],
    ) -> Result<ChainState, MdbxContextError> {
        if let Some(circulating_supply_micronoid) = persisted_circulating_supply_micronoid {
            if let Some(state) = Self::try_load_compact_chain_state(
                store,
                log_slots,
                active_slot_count,
                alloc_counter,
                circulating_supply_micronoid,
                expected_root,
            )? {
                tracing::info!(
                    active_segments = state.state.active_segment_ids().count(),
                    active_slot_count,
                    "resumed exact state from compact segment summaries"
                );
                return Ok(state);
            }
        }

        tracing::info!(
            "compact state metadata is absent or incomplete; performing one-time dense verification"
        );
        let state = Self::load_dense_chain_state(
            store,
            log_slots,
            active_slot_count,
            alloc_counter,
            tip_height,
            expected_root,
        )?;
        if let Some((stored_height, stored_hash)) = store.get_chain_tip()? {
            if stored_height == tip_height {
                if let Err(error) =
                    store.replace_segment_summaries(stored_height, stored_hash, &state)
                {
                    // The verified state remains usable. A later canonical
                    // commit or restart can retry this optional accelerator.
                    tracing::warn!(%error, "failed to persist rebuilt segment summaries");
                } else {
                    tracing::info!(
                        active_segments = state.state.active_segment_ids().count(),
                        "persisted compact segment summaries"
                    );
                }
            }
        }
        Ok(state)
    }

    /// Open an existing MDBX database, or initialise a fresh one from genesis.
    ///
    /// State persistence strategy:
    ///
    /// 1. If MDBX has valid state (chain_tip + segments with correct state_root),
    ///    resume from local state. The P2P layer handles forward-sync (block-by-block
    ///    if gap <= CONSENSUS_FINALITY_DEPTH, snapshot-sync if gap is larger).
    ///
    /// 2. If state cannot be restored, atomically clear every chain table and
    ///    initialise the canonical genesis. No format migration is attempted.
    ///
    /// 3. If MDBX is empty (first run), initialise from genesis.
    ///
    /// This prevents simultaneous-restart network death: when all nodes reboot at
    /// once (provider outage), each resumes from its own verified local state instead
    /// of requiring peers to serve a snapshot that nobody has.
    ///
    pub fn open_or_create(path: &Path) -> Result<Self, MdbxContextError> {
        let store = MdbxStore::open(path)?;

        if store.is_empty()? {
            // First run: initialise from genesis.
            let (state, recent_headers, tip_hash) = canonical_genesis_parts();
            let tip_chain_work = block_work(&GENESIS_TARGET);
            let finalized = FinalizedCheckpoint {
                height: 0,
                hash: tip_hash,
            };
            let ctx = Self {
                store,
                state,
                recent_headers,
                tip_height: 0,
                tip_hash,
                tip_chain_work,
                finalized,
                defer_finality_updates: false,
                reorg_staging: None,
            };
            ctx.persist_genesis()?;
            Ok(ctx)
        } else {
            // Try to restore from existing MDBX state (state_root integrity check inside).
            match Self::restore_from_mdbx(store) {
                Ok(ctx) => {
                    tracing::info!(height = ctx.tip_height, "resumed from persisted state");
                    Ok(ctx)
                }
                Err(MdbxContextError::Corrupt(reason)) => {
                    tracing::warn!(
                        reason,
                        "persisted state rejected — clearing the chain database"
                    );
                    // Re-open store (the previous one was consumed by restore_from_mdbx).
                    let store = MdbxStore::open(path)?;
                    store.clear_all()?;
                    let (state, recent_headers, tip_hash) = canonical_genesis_parts();
                    let tip_chain_work = block_work(&GENESIS_TARGET);
                    let finalized = FinalizedCheckpoint {
                        height: 0,
                        hash: tip_hash,
                    };
                    let ctx = Self {
                        store,
                        state,
                        recent_headers,
                        tip_height: 0,
                        tip_hash,
                        tip_chain_work,
                        finalized,
                        defer_finality_updates: false,
                        reorg_staging: None,
                    };
                    ctx.persist_genesis()?;
                    Ok(ctx)
                }
                Err(e) => Err(e),
            }
        }
    }

    fn persist_genesis(&self) -> Result<(), MdbxContextError> {
        use crate::consensus::da_prune::BlockUndoLog;
        use crate::consensus::genesis::genesis_header;

        let genesis = genesis_header();
        let genesis_hash = block_id(&genesis);
        let meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: genesis_hash,
            cumulative_chainwork: self.tip_chain_work,
            finalized: self.finalized,
        };

        // Write genesis header + tip + state_meta + consensus_meta in one transaction.
        // For genesis: segments are all virtual-zero, no dirty segments.
        self.store.commit_block(
            &genesis,
            &genesis_hash,
            &BlockUndoLog::empty(0, genesis.log_slots),
            &[], // no dirty segments (all virtual zero)
            &[],
            &[],
            &[],
            None, // genesis is built in and has no accepted bundle
            self.state.circulating_supply_micronoid,
            &meta,
            false,
        )?;
        Ok(())
    }

    fn restore_from_mdbx(store: MdbxStore) -> Result<Self, MdbxContextError> {
        // 1. Read non-optional consensus metadata.
        let meta = store
            .get_consensus_meta()?
            .ok_or(MdbxContextError::Corrupt("missing consensus_meta"))?;
        let tip_height = meta.tip_height;
        let tip_hash = meta.tip_hash;
        let finalized = meta.finalized;

        if store.get_chain_tip()? != Some((tip_height, tip_hash)) {
            return Err(MdbxContextError::Corrupt(
                "chain_tip mismatch with consensus_meta",
            ));
        }
        if finalized.height > tip_height {
            return Err(MdbxContextError::Corrupt(
                "finalized checkpoint is above canonical tip",
            ));
        }
        let stored_tip_chain_work = store
            .get_chain_work(tip_height)?
            .ok_or(MdbxContextError::Corrupt("missing exact chainwork for tip"))?;
        if stored_tip_chain_work != meta.cumulative_chainwork {
            return Err(MdbxContextError::Corrupt(
                "tip chainwork mismatch with consensus_meta",
            ));
        }

        // 2. Read state_meta.
        let (log_slots, active_slot_count, alloc_counter) = store
            .get_state_meta()?
            .ok_or(MdbxContextError::Corrupt("missing state_meta"))?;
        let circulating_supply_micronoid = store.get_circulating_supply()?;
        // 3. Validate canonical metadata before restoring compact state.
        let tip_hdr = store
            .get_header(tip_height)?
            .ok_or(MdbxContextError::Corrupt("tip header missing from store"))?;
        if block_id(&tip_hdr) != tip_hash {
            return Err(MdbxContextError::Corrupt(
                "tip hash mismatch with persisted tip header",
            ));
        }
        Self::validate_durable_tip_history_terminal(&store, &tip_hdr, tip_hash)?;
        if log_slots != tip_hdr.log_slots
            || active_slot_count != tip_hdr.active_slot_count
            || alloc_counter != tip_hdr.alloc_counter
        {
            return Err(MdbxContextError::Corrupt(
                "state_meta counters mismatch with persisted tip header",
            ));
        }
        let finalized_hdr =
            store
                .get_header(finalized.height)?
                .ok_or(MdbxContextError::Corrupt(
                    "finalized header missing from store",
                ))?;
        if block_id(&finalized_hdr) != finalized.hash {
            return Err(MdbxContextError::Corrupt(
                "finalized hash mismatch with persisted finalized header",
            ));
        }
        // 4. Authenticate the compact exact-root set against the tip header.
        //    Legacy stores run the dense verifier once and persist summaries.
        //    Raw columns are faulted in and checked lazily on first access.
        let state = Self::load_streamed_chain_state(
            &store,
            log_slots,
            active_slot_count,
            alloc_counter,
            circulating_supply_micronoid,
            tip_height,
            tip_hdr.state_root,
        )?;

        // 5. Rebuild the bounded header window used by native header checks.
        let window = recent_header_lookback();
        let start_height = tip_height.saturating_sub(window);
        let mut recent_headers = HashMap::new();
        for h in start_height..=tip_height {
            if let Some(hdr) = store.get_header(h)? {
                recent_headers.insert(h, hdr);
            }
        }

        // 6. Use exact persisted cumulative chainwork.
        let tip_chain_work = meta.cumulative_chainwork;

        Ok(Self {
            store,
            state,
            recent_headers,
            tip_height,
            tip_hash,
            tip_chain_work,
            finalized,
            defer_finality_updates: false,
            reorg_staging: None,
        })
    }

    fn validate_durable_tip_history_terminal(
        store: &MdbxStore,
        tip_header: &BlockHeader,
        tip_hash: [u8; 32],
    ) -> Result<(), MdbxContextError> {
        if tip_header.height == 0 {
            return Ok(());
        }
        let Some(terminal) = store.get_history_step_terminal_at(tip_header.height, tip_hash)?
        else {
            if store.durable_tip_has_verified_suffix_authority(tip_header, tip_hash)? {
                return Ok(());
            }
            return Err(MdbxContextError::Corrupt(
                "durable non-genesis tip history authorization is missing",
            ));
        };
        let metadata = crate::history_step::HistoryStepTerminalMetadata::decode_prefix(&terminal)
            .map_err(|_| {
            MdbxContextError::Corrupt("durable non-genesis tip history terminal is malformed")
        })?;
        if metadata.terminal_height() != tip_header.height
            || metadata.terminal_hash() != crate::block_header::semantic_header_id(tip_header)
        {
            return Err(MdbxContextError::Corrupt(
                "durable non-genesis tip history terminal binding mismatch",
            ));
        }
        Ok(())
    }

    /// Reload the durable canonical tip without retaining a second full state
    /// image in RAM.  Used only to abort a staged reorg; MDBX is still on the
    /// old branch until the final atomic replacement transaction commits.
    fn reload_hot_state_from_mdbx(&mut self) -> Result<(), MdbxContextError> {
        let meta = self
            .store
            .get_consensus_meta()?
            .ok_or(MdbxContextError::Corrupt("missing consensus_meta"))?;
        let (log_slots, active_slot_count, alloc_counter) = self
            .store
            .get_state_meta()?
            .ok_or(MdbxContextError::Corrupt("missing state_meta"))?;
        let circulating_supply_micronoid = self.store.get_circulating_supply()?;
        let tip_header = self
            .store
            .get_header(meta.tip_height)?
            .ok_or(MdbxContextError::Corrupt("durable tip header missing"))?;
        if block_id(&tip_header) != meta.tip_hash
            || tip_header.log_slots != log_slots
            || tip_header.active_slot_count != active_slot_count
            || tip_header.alloc_counter != alloc_counter
        {
            return Err(MdbxContextError::Corrupt(
                "durable reorg recovery metadata mismatch",
            ));
        }
        Self::validate_durable_tip_history_terminal(&self.store, &tip_header, meta.tip_hash)?;

        // Release the failed candidate before decoding durable segments.  The
        // replacement is a sparse virtual-zero state and does not allocate the
        // full slot domain.
        self.state = ChainState::with_log_slots(log_slots as usize);
        self.recent_headers.clear();
        let state = Self::load_streamed_chain_state(
            &self.store,
            log_slots,
            active_slot_count,
            alloc_counter,
            circulating_supply_micronoid,
            tip_header.height,
            tip_header.state_root,
        )?;

        let window = recent_header_lookback();
        let start_height = meta.tip_height.saturating_sub(window);
        let mut recent_headers = HashMap::new();
        for height in start_height..=meta.tip_height {
            if let Some(header) = self.store.get_header(height)? {
                recent_headers.insert(height, header);
            }
        }
        if !recent_headers.contains_key(&meta.tip_height) {
            return Err(MdbxContextError::Corrupt(
                "durable recent header window misses tip",
            ));
        }

        self.state = state;
        self.recent_headers = recent_headers;
        self.tip_height = meta.tip_height;
        self.tip_hash = meta.tip_hash;
        self.tip_chain_work = meta.cumulative_chainwork;
        self.finalized = meta.finalized;
        self.defer_finality_updates = false;
        self.reorg_staging = None;
        Ok(())
    }

    fn abort_staged_reorg(&mut self, original: MdbxContextError) -> MdbxContextError {
        self.reorg_staging = None;
        match self.reload_hot_state_from_mdbx() {
            Ok(()) => original,
            Err(reload) => reload,
        }
    }

    // -----------------------------------------------------------------------
    // Block application
    // -----------------------------------------------------------------------

    fn finalized_for_tip(&self, tip_height: u64) -> Result<FinalizedCheckpoint, MdbxContextError> {
        let finalized_height = tip_height.saturating_sub(CONSENSUS_FINALITY_DEPTH);
        if finalized_height <= self.finalized.height {
            return Ok(self.finalized);
        }
        let header =
            self.get_header_from_store(finalized_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "missing header for finalized checkpoint",
                ))?;
        Ok(FinalizedCheckpoint {
            height: finalized_height,
            hash: block_id(&header),
        })
    }

    /// Restore an uncommitted in-place transition from its bounded touched-set
    /// undo.  The durable store still points to `parent`, so retaining another
    /// full `ChainState` image solely for error handling is unnecessary.
    fn rollback_uncommitted_block(
        &mut self,
        undo: &crate::consensus::da_prune::BlockUndoLog,
        parent: &BlockHeader,
        parent_segment_summaries: &[ParentSegmentSummary],
    ) -> Result<(), MdbxContextError> {
        let current_log_slots = self.state.state.log_slots() as u32;
        if current_log_slots != parent.log_slots
            && current_log_slots != parent.log_slots.saturating_add(1)
        {
            return Err(MdbxContextError::Corrupt(
                "uncommitted block has invalid rollback geometry",
            ));
        }
        let circulating_supply_micronoid = self
            .state
            .supply_after_slot_updates(&undo.slot_changes)
            .ok_or(MdbxContextError::Corrupt(
                "uncommitted block supply rollback failed",
            ))?;
        let current_slots = self.state.state.num_slots();
        for &(slot_index, previous) in &undo.slot_changes {
            if u64::from(slot_index) >= current_slots {
                // A verifier may reject an expansion candidate before growing
                // the parent state. Its new upper-half pre-images are already
                // canonical zero and require no write.
                if previous.is_empty() && current_log_slots == parent.log_slots {
                    continue;
                }
                return Err(MdbxContextError::Corrupt(
                    "uncommitted block undo is out of range",
                ));
            }
            self.state
                .state
                .apply_delta_unrooted(std::slice::from_ref(&(slot_index, previous)))
                .map_err(|_| MdbxContextError::Corrupt("uncommitted block undo is out of range"))?;
        }
        let rollback_log_slots = undo.log_slots_before as usize;
        if self.state.state.log_slots() > rollback_log_slots
            && rollback_log_slots >= LOG_SEGMENT_SIZE as usize
        {
            // Production state roots are exact-only. Avoid forcing unrelated
            // evicted FRI-dirty payloads back into RAM merely to discard the
            // canonical-zero expansion half during rollback.
            self.state
                .state
                .shrink_exact_metadata_to_log_slots(rollback_log_slots)
                .map_err(|_| {
                    MdbxContextError::Corrupt("uncommitted block depth rollback failed")
                })?;
        } else {
            self.state
                .state
                .shrink_to_log_slots(rollback_log_slots)
                .map_err(|_| {
                    MdbxContextError::Corrupt("uncommitted block depth rollback failed")
                })?;
        }
        self.state.active_slot_count = undo.active_slot_count_before;
        self.state.alloc_counter = undo.alloc_counter_before;
        self.state.circulating_supply_micronoid = circulating_supply_micronoid;
        if self.state.state.log_slots() as u32 != parent.log_slots
            || self.state.active_slot_count != parent.active_slot_count
            || self.state.alloc_counter != parent.alloc_counter
        {
            return Err(MdbxContextError::Corrupt(
                "uncommitted block undo does not restore parent boundary",
            ));
        }
        let restored_root = self.state.try_state_root().map_err(|_| {
            MdbxContextError::Corrupt("uncommitted block exact-root rollback failed")
        })?;
        if restored_root != parent.state_root {
            return Err(MdbxContextError::Corrupt(
                "uncommitted block undo does not restore parent exact root",
            ));
        }

        // A normal next-block parent is already durable.  Once both its exact
        // commitment and counters have been re-established, every touched raw
        // payload is again backed by MDBX and may be discarded.  Staged reorg
        // parents are intentionally excluded: their dirty predecessor state is
        // not durable until the final replacement transaction commits.
        if self.reorg_staging.is_none() {
            self.state.state.clear_dirty();
            for &(segment_id, parent_fri_root) in parent_segment_summaries {
                self.state
                    .state
                    .restore_persisted_segment_summary_and_evict(segment_id, parent_fri_root)
                    .map_err(MdbxContextError::Corrupt)?;
            }
            self.state.state.evict_all_persisted_segments();
        }
        Ok(())
    }

    /// Return the original rejection after a successful bounded rollback.  If
    /// rollback detects any root/counter/cache corruption, discard the entire
    /// candidate state and reconstruct the canonical boundary from MDBX before
    /// exposing the context again.
    fn reject_uncommitted_block(
        &mut self,
        undo: &crate::consensus::da_prune::BlockUndoLog,
        parent: &BlockHeader,
        parent_segment_summaries: &[ParentSegmentSummary],
        original: MdbxContextError,
    ) -> MdbxContextError {
        match self.rollback_uncommitted_block(undo, parent, parent_segment_summaries) {
            Ok(()) => original,
            Err(rollback_error) => match self.reload_hot_state_from_mdbx() {
                Ok(()) => rollback_error,
                Err(reload_error) => reload_error,
            },
        }
    }

    fn commit_applied_next_block(
        &mut self,
        accepted_block: AcceptedBlockCommit<'_>,
        block: &Block,
        undo: &crate::consensus::da_prune::BlockUndoLog,
        parent: &BlockHeader,
        parent_segment_summaries: &[ParentSegmentSummary],
        retain_persisted_segments: bool,
    ) -> Result<(), MdbxContextError> {
        let tx_hashes = crate::block::try_compute_logical_txids(&block.transactions)
            .map_err(|_| MdbxContextError::Corrupt("committed logical tx stream is invalid"))?;
        let block_hash = block_id(&block.header);
        let new_tip_chain_work = add_work(
            &self.tip_chain_work,
            &block_work(&block.header.difficulty_target),
        );
        let new_finalized = if self.defer_finality_updates {
            self.finalized
        } else {
            self.finalized_for_tip(block.header.height)?
        };
        let staged = self.reorg_staging.is_some();
        if let Some(replacement) = self.reorg_staging.as_mut() {
            replacement.push(StagedAcceptedBlockCommit {
                header: block.header,
                hash: block_hash,
                cumulative_chainwork: new_tip_chain_work,
                undo_log: undo.clone(),
            });
        } else {
            let consensus_meta = ConsensusMeta {
                tip_height: block.header.height,
                tip_hash: block_hash,
                cumulative_chainwork: new_tip_chain_work,
                finalized: new_finalized,
            };
            let commit_result = (|| -> Result<(), StoreError> {
                let dirty_ids: Vec<u16> = self.state.state.dirty_segment_ids().collect();
                let eff_log = self.state.state.effective_log_segment_size() as u8;
                let mut dirty_refs = Vec::with_capacity(dirty_ids.len());
                let mut dirty_summaries = Vec::with_capacity(dirty_ids.len());
                for segment_id in dirty_ids {
                    let live_count = self.state.state.segment_live_count(segment_id);
                    let exact_root = self
                        .state
                        .cached_exact_segment_root(segment_id)
                        .ok_or(StoreError::Decode("dirty exact segment root is missing"))?;
                    let columns =
                        if live_count == 0 {
                            None
                        } else {
                            Some(self.state.state.try_get_segment_columns(segment_id).ok_or(
                                StoreError::Decode("dirty accepted segment is not resident"),
                            )?)
                        };
                    dirty_refs.push((segment_id, eff_log, columns));
                    dirty_summaries.push((segment_id, live_count, exact_root));
                }
                self.store.commit_block(
                    &block.header,
                    &block_hash,
                    undo,
                    &dirty_refs,
                    &dirty_summaries,
                    &tx_hashes,
                    &[],
                    Some(accepted_block),
                    self.state.circulating_supply_micronoid,
                    &consensus_meta,
                    false,
                )
            })();
            if let Err(e) = commit_result {
                let commit_error = MdbxContextError::from(e);
                return Err(self.reject_uncommitted_block(
                    undo,
                    parent,
                    parent_segment_summaries,
                    commit_error,
                ));
            }
        }

        self.recent_headers
            .insert(block.header.height, block.header);
        self.tip_height = block.header.height;
        self.tip_hash = block_hash;
        self.tip_chain_work = new_tip_chain_work;
        self.finalized = new_finalized;
        if !staged {
            self.state.state.clear_dirty();
            if !retain_persisted_segments {
                // The exact hierarchy is compact and current. Raw columns have
                // reached MDBX atomically, so retain no full segment merely because
                // it was touched by the latest block.
                self.state.state.evict_all_persisted_segments();
            }
        }

        let window = recent_header_lookback();
        if self.tip_height > window {
            self.recent_headers.remove(&(self.tip_height - window - 1));
        }

        Ok(())
    }

    fn current_terminal_epoch_anchor_header(
        &self,
        current_header: &BlockHeader,
    ) -> Result<BlockHeader, MdbxContextError> {
        let epoch_anchor_height = tx_epoch_anchor_height_for_child(current_header.height);
        match self.recent_headers.get(&epoch_anchor_height) {
            Some(header) => Ok(*header),
            None => {
                self.get_header_from_store(epoch_anchor_height)?
                    .ok_or(MdbxContextError::Consensus(
                        ConsensusError::BadHistoryStepTerminal(
                            "canonical epoch anchor for the current terminal is missing"
                                .to_string(),
                        ),
                    ))
            }
        }
    }

    /// Commit one node-owned block whose exact HistoryStep and public
    /// transition were completed before this call.
    ///
    /// This is deliberately separate from [`Self::apply_next_block`].  It
    /// consumes a non-cloneable typed capability minted with the canonical
    /// template and sealed only after local HistoryStep proving, so it does
    /// not decode the just-built block, re-run terminal verification, or
    /// replay its public state transition.  The capability carries the exact
    /// immutable header/body/bundle binding; exact current-parent and
    /// post-state boundaries are rechecked under the chain write lock before
    /// the same single-transaction MDBX commit used by inbound acceptance.
    pub fn commit_locally_proved_next_block(
        &mut self,
        proved: LocallyProvedBlockCommit,
    ) -> Result<(Block, crate::AcceptedBlockBundle), MdbxContextError> {
        if self.reorg_staging.is_some() {
            return Err(MdbxContextError::Corrupt(
                "local proved block cannot commit during reorg staging",
            ));
        }

        let parent = *self.tip_header();
        if proved.parent_header() != &parent
            || proved.block().header.prev_block_hash != self.tip_hash
        {
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash));
        }
        if parent
            .height
            .checked_add(1)
            .is_none_or(|height| proved.block().header.height != height)
        {
            return Err(MdbxContextError::Consensus(ConsensusError::BadHeight));
        }
        // The proof itself is deliberately not self-verified on the trusted
        // local producer path. PoW is cheap and closes the only native field
        // a miner can change after template preparation, so fail closed here
        // before installing the prepared state image.
        validate_pow(&proved.block().header)?;
        if self.state.cached_state_root() != parent.state_root
            || self.state.state.log_slots() as u32 != parent.log_slots
            || self.state.active_slot_count != parent.active_slot_count
            || self.state.alloc_counter != parent.alloc_counter
        {
            return Err(MdbxContextError::Corrupt(
                "hot state does not match the exact local parent boundary",
            ));
        }

        let (block, accepted_bundle, post_state, undo) = proved.into_commit_parts();
        if post_state.state.exact_dirty_segment_ids().next().is_some() {
            return Err(MdbxContextError::Consensus(ConsensusError::ShapeMismatch(
                "locally prepared post-state has an unsealed exact root".to_string(),
            )));
        }
        if post_state.cached_state_root() != block.header.state_root {
            return Err(MdbxContextError::Consensus(ConsensusError::BadStateRoot));
        }
        if post_state.state.log_slots() as u32 != block.header.log_slots
            || post_state.active_slot_count != block.header.active_slot_count
            || post_state.alloc_counter != block.header.alloc_counter
        {
            return Err(MdbxContextError::Consensus(ConsensusError::ShapeMismatch(
                "locally prepared post-state counters do not match the sealed header".to_string(),
            )));
        }
        let block_hash = block_id(&block.header);
        if accepted_bundle.height() != block.header.height
            || accepted_bundle.block_hash() != block_hash
        {
            return Err(MdbxContextError::Consensus(
                ConsensusError::BadHistoryStepTerminal(
                    "local proved bundle does not bind the sealed block".to_string(),
                ),
            ));
        }

        let touched_segment_ids = self.segment_ids_for_block(&block);
        let parent_segment_summaries: Vec<ParentSegmentSummary> = touched_segment_ids
            .iter()
            .copied()
            .filter(|segment_id| (*segment_id as usize) < self.state.state.num_segments())
            .map(|segment_id| (segment_id, self.state.state.cached_segment_root(segment_id)))
            .collect();

        // The capability owns the exact state image used to derive the header.
        // Install it only after every immutable binding above has succeeded;
        // commit failure then uses its prepared undo to restore `parent`.
        self.state = post_state;
        let state_root = self.state.cached_state_root();
        self.commit_applied_next_block(
            AcceptedBlockCommit::Complete(&accepted_bundle),
            &block,
            &undo,
            &parent,
            &parent_segment_summaries,
            false,
        )?;
        debug_assert_eq!(state_root, block.header.state_root);
        Ok((block, accepted_bundle))
    }

    /// Accept one indivisible block + HistoryStep unit.
    ///
    /// The terminal verifier runs before any state mutation. Once it has
    /// established the full recursive statement, `materialize_state` applies
    /// the public block body to the hot exact state. The final state root must
    /// still equal the header before the bundle and state are committed in one
    /// MDBX transaction.
    pub fn apply_next_block<F, E, A>(
        &mut self,
        accepted_bundle: &crate::AcceptedBlockBundle,
        local_time: u64,
        materialize_state: F,
        verify_history_step_terminal: A,
    ) -> Result<[u8; 32], MdbxContextError>
    where
        F: FnOnce(&Block, &mut ChainState) -> Result<[u8; 32], E>,
        E: std::fmt::Display,
        A: FnOnce(&HistoryStepTerminalClaim<'_>) -> Result<(), String>,
    {
        let block = Block::from_bytes(accepted_bundle.block_bytes()).map_err(|_| {
            MdbxContextError::Corrupt("accepted bundle contains a malformed canonical block")
        })?;
        let block = &block;
        let history_step_terminal_bytes = accepted_bundle.history_step_terminal_bytes();
        let parent = *self.tip_header();
        let prev_timestamps = self.prev_timestamps()?;
        let finalized_active_counts = self.finalized_active_counts()?;
        let anchor = self.anchor_info()?;
        let tx_anchor_height = tx_epoch_anchor_height_for_child(block.header.height);
        let tx_anchor_header =
            self.get_header_from_store(tx_anchor_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "canonical transaction epoch-anchor header missing",
                ))?;
        let tx_epoch_anchor_id = block_id(&tx_anchor_header);
        validate_block_epoch_anchors(block, tx_epoch_anchor_id, block_id(&parent))?;
        // All deterministic cheap checks, including bitmap-live resources
        // and the segment cap, precede proof decode, segment hydration, state
        // cloning, and undo allocation.
        validate_block_checks(
            block,
            &parent,
            &prev_timestamps,
            &finalized_active_counts,
            local_time,
            &anchor,
        )?;

        // The terminal is bound directly to this uncommitted candidate, never
        // to an older header fetched from storage. There is no canonical
        // PoW-only intermediate state.
        if block.header.height == 0 {
            return Err(MdbxContextError::Consensus(
                ConsensusError::BadHistoryStepTerminal(
                    "genesis is not transported as an accepted block bundle".to_string(),
                ),
            ));
        }
        let height = block.header.height;
        let current_semantic = crate::block_header::semantic_header_id(&block.header);
        let terminal_metadata = crate::history_step::HistoryStepTerminalMetadata::decode_prefix(
            history_step_terminal_bytes,
        )
        .map_err(|error| {
            MdbxContextError::Consensus(ConsensusError::BadHistoryStepTerminal(format!(
                "terminal metadata is invalid: {error}"
            )))
        })?;
        if terminal_metadata.terminal_height() != height
            || terminal_metadata.terminal_hash() != current_semantic
        {
            return Err(MdbxContextError::Consensus(
                ConsensusError::BadHistoryStepTerminal(
                    "terminal metadata does not bind the current block".to_string(),
                ),
            ));
        }

        let epoch_anchor_header = self.current_terminal_epoch_anchor_header(&block.header)?;
        let claim = HistoryStepTerminalClaim {
            terminal_bytes: history_step_terminal_bytes,
            header: block.header,
            epoch_anchor_header,
        };
        verify_history_step_terminal(&claim).map_err(|error| {
            MdbxContextError::Consensus(ConsensusError::BadHistoryStepTerminal(error))
        })?;

        let touched_segment_ids = self.segment_ids_for_block(block);
        let parent_segment_summaries: Vec<ParentSegmentSummary> = touched_segment_ids
            .iter()
            .copied()
            .filter(|segment_id| (*segment_id as usize) < self.state.state.num_segments())
            .map(|segment_id| (segment_id, self.state.state.cached_segment_root(segment_id)))
            .collect();
        self.preload_segment_ids(&touched_segment_ids)?;
        let undo = build_undo_log(&self.state, block).map_err(|_| {
            MdbxContextError::Corrupt("accepted block has a non-canonical logical tx stream")
        })?;

        let state_root = match materialize_state(block, &mut self.state) {
            Ok(state_root) => state_root,
            Err(e) => {
                let original = MdbxContextError::Consensus(ConsensusError::ShapeMismatch(format!(
                    "public block state materialization failed: {e}"
                )));
                return Err(self.reject_uncommitted_block(
                    &undo,
                    &parent,
                    &parent_segment_summaries,
                    original,
                ));
            }
        };

        if state_root != block.header.state_root {
            return Err(self.reject_uncommitted_block(
                &undo,
                &parent,
                &parent_segment_summaries,
                MdbxContextError::Consensus(ConsensusError::BadStateRoot),
            ));
        }
        self.commit_applied_next_block(
            AcceptedBlockCommit::Complete(accepted_bundle),
            block,
            &undo,
            &parent,
            &parent_segment_summaries,
            false,
        )?;
        Ok(state_root)
    }

    /// Materialize one body covered by a previously verified recursive suffix.
    ///
    /// This is not a proof bypass. `VerifiedRecursiveSuffix` can only be
    /// created after the final terminal has passed the pinned verifier, and it
    /// advances along one exact parent/hash sequence. Native header, PoW,
    /// epoch-anchor, transaction and exact post-state checks remain identical
    /// to ordinary block acceptance. Intermediate durable rows carry a compact
    /// local authorization marker; the final row stores the complete terminal.
    pub fn apply_verified_recursive_suffix_block<F, E>(
        &mut self,
        authority: &mut VerifiedRecursiveSuffix,
        block_bytes: &[u8],
        local_time: u64,
        materialize_state: F,
    ) -> Result<[u8; 32], MdbxContextError>
    where
        F: FnOnce(&Block, &mut ChainState) -> Result<[u8; 32], E>,
        E: std::fmt::Display,
    {
        let total_started = Instant::now();
        if authority.complete {
            return Err(MdbxContextError::Corrupt(
                "recursive suffix authority is already complete",
            ));
        }
        if self.tip_height.saturating_add(1) != authority.next_height
            || self.tip_hash != authority.previous_hash
        {
            return Err(MdbxContextError::Corrupt(
                "recursive suffix authority no longer matches the canonical tip",
            ));
        }

        let block = Block::from_bytes(block_bytes)
            .map_err(|_| MdbxContextError::Corrupt("recursive suffix block body is malformed"))?;
        if block.header.height != authority.next_height
            || block.header.prev_block_hash != authority.previous_hash
            || block.header.height > authority.tip_header.height
        {
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash));
        }
        let is_final = block.header.height == authority.tip_header.height;
        if is_final && block.header != authority.tip_header {
            return Err(MdbxContextError::Consensus(
                ConsensusError::BadHistoryStepTerminal(
                    "recursive suffix final body differs from its verified tip".to_string(),
                ),
            ));
        }
        if block.header.height == authority.epoch_anchor_header.height
            && block.header != authority.epoch_anchor_header
        {
            return Err(MdbxContextError::Consensus(
                ConsensusError::BadHistoryStepTerminal(
                    "recursive suffix body differs from its verified epoch anchor".to_string(),
                ),
            ));
        }

        let parent = *self.tip_header();
        let checks_started = Instant::now();
        let prev_timestamps = self.prev_timestamps()?;
        let finalized_active_counts = self.finalized_active_counts()?;
        let anchor = self.anchor_info()?;
        let tx_anchor_height = tx_epoch_anchor_height_for_child(block.header.height);
        let tx_anchor_header =
            self.get_header_from_store(tx_anchor_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "canonical transaction epoch-anchor header missing",
                ))?;
        validate_block_epoch_anchors(&block, block_id(&tx_anchor_header), block_id(&parent))?;
        validate_block_checks(
            &block,
            &parent,
            &prev_timestamps,
            &finalized_active_counts,
            local_time,
            &anchor,
        )?;
        let checks_elapsed = checks_started.elapsed();

        let preload_started = Instant::now();
        let touched_segment_ids = self.segment_ids_for_block(&block);
        let parent_segment_summaries: Vec<ParentSegmentSummary> = touched_segment_ids
            .iter()
            .copied()
            .filter(|segment_id| (*segment_id as usize) < self.state.state.num_segments())
            .map(|segment_id| (segment_id, self.state.state.cached_segment_root(segment_id)))
            .collect();
        self.preload_segment_ids(&touched_segment_ids)?;
        let undo = build_undo_log(&self.state, &block).map_err(|_| {
            MdbxContextError::Corrupt("recursive suffix block has invalid logical transactions")
        })?;
        let preload_elapsed = preload_started.elapsed();
        let materialize_started = Instant::now();
        let state_root = match materialize_state(&block, &mut self.state) {
            Ok(state_root) => state_root,
            Err(error) => {
                let original = MdbxContextError::Consensus(ConsensusError::ShapeMismatch(format!(
                    "public recursive suffix state materialization failed: {error}"
                )));
                return Err(self.reject_uncommitted_block(
                    &undo,
                    &parent,
                    &parent_segment_summaries,
                    original,
                ));
            }
        };
        let materialize_elapsed = materialize_started.elapsed();
        if state_root != block.header.state_root {
            return Err(self.reject_uncommitted_block(
                &undo,
                &parent,
                &parent_segment_summaries,
                MdbxContextError::Consensus(ConsensusError::BadStateRoot),
            ));
        }

        let final_bundle = if is_final {
            Some(
                crate::AcceptedBlockBundle::try_from_parts(
                    block_bytes.to_vec(),
                    authority.terminal_bytes.clone(),
                )
                .map_err(|error| {
                    self.reject_uncommitted_block(
                        &undo,
                        &parent,
                        &parent_segment_summaries,
                        MdbxContextError::Consensus(ConsensusError::BadHistoryStepTerminal(
                            format!("verified recursive suffix bundle is malformed: {error}"),
                        )),
                    )
                })?,
            )
        } else {
            None
        };
        let commit_authorization = match final_bundle.as_ref() {
            Some(bundle) => AcceptedBlockCommit::Complete(bundle),
            None => AcceptedBlockCommit::RecursiveSuffix {
                block_bytes,
                authority_tip_height: authority.tip_header.height,
                authority_tip_hash: block_id(&authority.tip_header),
            },
        };
        let commit_started = Instant::now();
        self.commit_applied_next_block(
            commit_authorization,
            &block,
            &undo,
            &parent,
            &parent_segment_summaries,
            !is_final,
        )?;
        let commit_elapsed = commit_started.elapsed();

        authority.previous_hash = block_id(&block.header);
        authority.next_height = block.header.height.saturating_add(1);
        authority.complete = is_final;
        let total_elapsed = total_started.elapsed();
        if total_elapsed >= RECURSIVE_SUFFIX_SLOW_PATH {
            tracing::warn!(
                height = block.header.height,
                checks_ms = checks_elapsed.as_millis(),
                preload_undo_ms = preload_elapsed.as_millis(),
                materialize_ms = materialize_elapsed.as_millis(),
                commit_ms = commit_elapsed.as_millis(),
                total_ms = total_elapsed.as_millis(),
                "recursive suffix block slow path"
            );
        } else {
            tracing::debug!(
                height = block.header.height,
                checks_ms = checks_elapsed.as_millis(),
                preload_undo_ms = preload_elapsed.as_millis(),
                materialize_ms = materialize_elapsed.as_millis(),
                commit_ms = commit_elapsed.as_millis(),
                total_ms = total_elapsed.as_millis(),
                "recursive suffix block profile"
            );
        }
        Ok(state_root)
    }

    // -----------------------------------------------------------------------
    // Chain reorganization (MDBX-backed)
    // -----------------------------------------------------------------------

    /// Find the height of a block with the given hash in our chain.
    ///
    /// Searches `recent_headers` first (fast RAM lookup), then falls back to
    /// the MDBX hash→height index. Returns `None` if the hash is not found
    /// within the last `CONSENSUS_FINALITY_DEPTH` blocks.
    pub fn find_ancestor_height(&self, hash: &[u8; 32]) -> Option<u64> {
        // Search recent_headers first (fast path in RAM).
        for (height, header) in &self.recent_headers {
            if &block_id(header) == hash {
                return Some(*height);
            }
        }

        // Fall back to MDBX hash→height index.
        let oldest = self.tip_height.saturating_sub(CONSENSUS_FINALITY_DEPTH);
        match self.store.get_header_by_hash(hash) {
            Ok(Some(header)) if header.height >= oldest => Some(header.height),
            _ => None,
        }
    }

    /// Apply a chain reorganization backed by MDBX undo logs.
    ///
    /// 1. Reverts our chain from tip back to `ancestor_height` using MDBX undo logs.
    /// 2. Persists the reverted state to MDBX atomically (crash-safe checkpoint).
    /// 3. Applies complete accepted-block bundles on top of `ancestor_height`
    ///    through the same terminal-first `apply_next_block` path.
    ///
    /// Returns the hashes of reclaimed transactions for mempool re-admission.
    ///
    /// Fails if the reorg would change the finalized prefix, if an undo log is
    /// missing, or if any fork bundle fails full validation/materialization.
    pub fn apply_reorg_mdbx_with_applier<F>(
        &mut self,
        ancestor_height: u64,
        replacement: &[crate::AcceptedBlockBundle],
        local_time: u64,
        mut apply_block: F,
    ) -> Result<crate::consensus::reorg::ReorgResult, MdbxContextError>
    where
        F: FnMut(&mut Self, &crate::AcceptedBlockBundle, u64) -> Result<(), MdbxContextError>,
    {
        let replacement_objects: Vec<AcceptedBlockCommit<'_>> = replacement
            .iter()
            .map(AcceptedBlockCommit::Complete)
            .collect();
        self.apply_reorg_mdbx_with_objects(
            ancestor_height,
            &replacement_objects,
            local_time,
            |context, index, time| apply_block(context, &replacement[index], time),
        )
    }

    /// Atomically replace the canonical non-final suffix using exact block
    /// bodies and one already verified recursive terminal at the selected tip.
    ///
    /// The complete candidate is pinned before rollback, must still beat the
    /// current canonical view under the normal cumulative-work rule, and every
    /// body passes the same native validation and exact State transition as a
    /// normally accepted block. Any failure reloads the untouched durable old
    /// branch; only the fully validated replacement reaches MDBX.
    pub fn apply_verified_reorg_suffix_with_applier<F, E>(
        &mut self,
        authority: VerifiedReorgSuffix,
        replacement: &[Vec<u8>],
        local_time: u64,
        materialize_state: F,
    ) -> Result<crate::consensus::reorg::ReorgResult, MdbxContextError>
    where
        F: FnMut(&Block, &mut ChainState) -> Result<[u8; 32], E>,
        E: std::fmt::Display,
    {
        self.apply_verified_reorg_suffix_with_applier_indexed(
            authority,
            replacement,
            local_time,
            materialize_state,
        )
        .map_err(|failure| failure.error)
    }

    /// Indexed variant used by the network admission path to quarantine only
    /// the source of an exact body that actually failed native application.
    pub fn apply_verified_reorg_suffix_with_applier_indexed<F, E>(
        &mut self,
        mut authority: VerifiedReorgSuffix,
        replacement: &[Vec<u8>],
        local_time: u64,
        mut materialize_state: F,
    ) -> Result<crate::consensus::reorg::ReorgResult, IndexedReorgSuffixError>
    where
        F: FnMut(&Block, &mut ChainState) -> Result<[u8; 32], E>,
        E: std::fmt::Display,
    {
        if self.tip_height != authority.original_tip_height
            || self.tip_hash != authority.original_tip_hash
            || self.finalized != authority.original_finalized
        {
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash).into());
        }
        if replacement.is_empty() {
            return Err(MdbxContextError::Corrupt("recursive reorg replacement is empty").into());
        }
        if replacement.len() > MAX_REORG_REPLACEMENT_BLOCKS {
            return Err(MdbxContextError::ResourceLimit {
                resource: "recursive reorg bodies",
                actual: replacement.len(),
                maximum: MAX_REORG_REPLACEMENT_BLOCKS,
            }
            .into());
        }

        let ancestor_height = authority.suffix.boundary_height;
        let ancestor_header =
            self.get_header_from_store(ancestor_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "reorg ancestor header disappeared",
                ))?;
        let ancestor_hash = block_id(&ancestor_header);
        if ancestor_hash != authority.suffix.previous_hash {
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash).into());
        }
        let mut expected_height = ancestor_height.saturating_add(1);
        let mut previous_hash = ancestor_hash;
        let mut candidate_work =
            self.store
                .get_chain_work(ancestor_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "reorg ancestor chainwork disappeared",
                ))?;
        for (index, body_bytes) in replacement.iter().enumerate() {
            let block = Block::from_bytes(body_bytes).map_err(|_| IndexedReorgSuffixError {
                body_index: Some(index),
                error: MdbxContextError::Corrupt("recursive reorg body is malformed"),
            })?;
            if block.header.height != expected_height
                || block.header.prev_block_hash != previous_hash
                || block.header.height > authority.suffix.tip_header.height
            {
                return Err(IndexedReorgSuffixError {
                    body_index: Some(index),
                    error: MdbxContextError::Consensus(ConsensusError::BadParentHash),
                });
            }
            previous_hash = block_id(&block.header);
            candidate_work = add_work(
                &candidate_work,
                &block_work(&block.header.difficulty_target),
            );
            expected_height = expected_height
                .checked_add(1)
                .ok_or(MdbxContextError::Corrupt("recursive reorg height overflow"))?;
        }
        let final_block = Block::from_bytes(
            replacement
                .last()
                .expect("non-empty recursive reorg was checked"),
        )
        .map_err(|_| IndexedReorgSuffixError {
            body_index: Some(replacement.len() - 1),
            error: MdbxContextError::Corrupt("recursive reorg tip body is malformed"),
        })?;
        if final_block.header != authority.suffix.tip_header
            || previous_hash != authority.suffix.tip_hash()
        {
            return Err(IndexedReorgSuffixError {
                body_index: Some(replacement.len() - 1),
                error: MdbxContextError::Consensus(ConsensusError::BadHistoryStepTerminal(
                    "recursive reorg bodies do not end at the verified tip".to_string(),
                )),
            });
        }
        if !matches!(
            crate::consensus::fork_choice::choose_chain_by_work(
                &candidate_work,
                &previous_hash,
                &self.tip_chain_work,
                &self.tip_hash,
            ),
            crate::consensus::fork_choice::ChainChoice::A
        ) {
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash).into());
        }

        // Keep the commit payload independent from the linearly consumed
        // authority. This is one bounded terminal copy, not one per block.
        let terminal_for_commit = authority.suffix.terminal_bytes.clone();
        let authority_tip_height = authority.suffix.tip_height();
        let authority_tip_hash = authority.suffix.tip_hash();
        let last_index = replacement.len() - 1;
        let replacement_objects: Vec<AcceptedBlockCommit<'_>> = replacement
            .iter()
            .enumerate()
            .map(|(index, block_bytes)| {
                if index == last_index {
                    AcceptedBlockCommit::CompleteObjects {
                        block_bytes,
                        terminal_bytes: &terminal_for_commit,
                    }
                } else {
                    AcceptedBlockCommit::RecursiveSuffix {
                        block_bytes,
                        authority_tip_height,
                        authority_tip_hash,
                    }
                }
            })
            .collect();

        let failed_body_index = std::cell::Cell::new(None);
        let result = self
            .apply_reorg_mdbx_with_objects(
                ancestor_height,
                &replacement_objects,
                local_time,
                |context, index, time| {
                    let result = context
                        .apply_verified_recursive_suffix_block(
                            &mut authority.suffix,
                            &replacement[index],
                            time,
                            |block, state| materialize_state(block, state),
                        )
                        .map(|_| ());
                    if result.is_err() {
                        failed_body_index.set(Some(index));
                    }
                    result
                },
            )
            .map_err(|error| IndexedReorgSuffixError {
                body_index: failed_body_index.get(),
                error,
            })?;
        debug_assert!(authority.suffix.is_complete());
        debug_assert_eq!(self.tip_chain_work, candidate_work);
        Ok(result)
    }

    fn apply_reorg_mdbx_with_objects<F>(
        &mut self,
        ancestor_height: u64,
        replacement_objects: &[AcceptedBlockCommit<'_>],
        local_time: u64,
        mut apply_block: F,
    ) -> Result<crate::consensus::reorg::ReorgResult, MdbxContextError>
    where
        F: FnMut(&mut Self, usize, u64) -> Result<(), MdbxContextError>,
    {
        use crate::consensus::reorg::{restore_state_counters, ReorgResult};

        let total_started = Instant::now();

        // Re-validate inside write lock: ancestor_height must be <= our CURRENT tip.
        // The caller computed ancestor_height outside the lock — if another task applied
        // blocks (or completed a reorg) in the meantime, ancestor_height may now be
        // ABOVE our tip, which would make saturating_sub silently return 0 and
        // discard the reorg. Fail loudly instead.
        if ancestor_height > self.tip_height {
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash));
        }
        let reorg_depth = self.tip_height - ancestor_height; // safe: guarded above

        if ancestor_height < self.finalized.height {
            tracing::warn!(
                ancestor_height,
                finalized_height = self.finalized.height,
                "reorg rejected: ancestor is below finalized checkpoint"
            );
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash));
        }
        if ancestor_height == self.finalized.height {
            let ancestor_header =
                self.get_header_from_store(ancestor_height)?
                    .ok_or(MdbxContextError::Corrupt(
                        "finalized ancestor header missing",
                    ))?;
            if block_id(&ancestor_header) != self.finalized.hash {
                tracing::warn!(
                    ancestor_height,
                    "reorg rejected: finalized checkpoint hash mismatch"
                );
                return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash));
            }
        }
        if reorg_depth > CONSENSUS_FINALITY_DEPTH {
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash));
        }

        if reorg_depth == 0 {
            return Ok(ReorgResult {
                reverted_heights: vec![],
                applied_heights: vec![],
                reclaimed_tx_hashes: vec![],
            });
        }

        if self.reorg_staging.is_some() {
            return Err(MdbxContextError::Corrupt("nested reorg staging"));
        }

        tracing::info!(
            "reorg: reverting height {}..{} depth={} new_blocks={}",
            self.tip_height,
            ancestor_height,
            reorg_depth,
            replacement_objects.len()
        );

        // Load the ancestor metadata before installing any reverted RAM
        // candidate. Read/corruption errors must leave state and tip pointers
        // byte-for-byte on the old canonical chain.
        let ancestor_header =
            self.get_header_from_store(ancestor_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "ancestor header missing from store",
                ))?;
        let ancestor_chain_work =
            self.store
                .get_chain_work(ancestor_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "missing exact chainwork for reorg ancestor",
                ))?;

        // -----------------------------------------------------------------------
        // Validate ALL undo logs before modifying any state.
        //
        // This is critical for safety: if we start reverting and then discover a
        // missing undo log mid-loop, we leave the node in an inconsistent state:
        //   - Some headers removed from recent_headers
        //   - tip_height still pointing to the OLD tip (not in recent_headers)
        //   → tip_header().expect() PANICS across all RPC threads
        //
        // By validating upfront, we either succeed fully or fail before touching
        // any in-memory state.
        // -----------------------------------------------------------------------
        let mut reorg_segment_ids = std::collections::HashSet::new();
        for accepted in replacement_objects.iter().copied() {
            let block = Block::from_bytes(accepted.block_bytes()).map_err(|_| {
                MdbxContextError::Corrupt("reorg object contains a malformed canonical block")
            })?;
            for tx in &block.transactions {
                for (_, input) in tx.body.live_inputs() {
                    track_reorg_segment(&mut reorg_segment_ids, input.slot_index)?;
                }
                for (_, output) in tx.body.live_outputs() {
                    track_reorg_segment(&mut reorg_segment_ids, output.slot_index)?;
                }
            }
        }

        let (reclaimed_tx_hashes, reverted_heights) = {
            if ancestor_height != 0 && self.store.get_undo_log(ancestor_height)?.is_none() {
                return Err(MdbxContextError::Corrupt("reorg ancestor undo log missing"));
            }
            let old_tip_height = self.tip_height;
            for height in (ancestor_height + 1..=old_tip_height).rev() {
                match self.store.get_undo_log(height) {
                    Ok(Some(undo)) => {
                        for &(slot_index, _) in &undo.slot_changes {
                            track_reorg_segment(&mut reorg_segment_ids, slot_index)?;
                        }
                    }
                    Ok(None) => {
                        tracing::error!(
                            height,
                            tip = self.tip_height,
                            ancestor = ancestor_height,
                            "reorg: undo log missing — cannot safely revert"
                        );
                        return Err(MdbxContextError::Corrupt(
                            "undo log missing: reorg aborted before any state modification",
                        ));
                    }
                    Err(e) => return Err(e.into()),
                }
            }

            // -----------------------------------------------------------------------
            // Revert blocks from tip to ancestor (RAM only).
            // Safe to execute: all undo logs were validated above.  Read them
            // again one at a time so peak RAM is one decoded undo log instead
            // of the complete finality window.
            // -----------------------------------------------------------------------
            let mut reclaimed_tx_hashes = Vec::new();
            let mut reverted_heights = Vec::new();

            let revert_result = (|| -> Result<(), MdbxContextError> {
                for height in (ancestor_height + 1..=old_tip_height).rev() {
                    let undo =
                        self.store
                            .get_undo_log(height)?
                            .ok_or(MdbxContextError::Corrupt(
                                "validated reorg undo disappeared",
                            ))?;
                    Self::preload_segments_for_undo_in_state(&self.store, &mut self.state, &undo)?;
                    reclaimed_tx_hashes.extend_from_slice(&undo.tx_hashes);
                    revert_block(&mut self.state, &undo).map_err(|_| {
                        MdbxContextError::Corrupt("circulating supply reorg rollback failed")
                    })?;
                    self.state
                        .state
                        .shrink_to_log_slots(undo.log_slots_before as usize)
                        .map_err(|_| {
                            MdbxContextError::Corrupt("state shrink after reorg failed")
                        })?;
                    restore_state_counters(&mut self.state, &undo);
                    self.state.rebuild_exact_utxo_root_loaded().map_err(|_| {
                        MdbxContextError::Corrupt("exact root rebuild after reorg failed")
                    })?;
                    let parent_header = self
                        .store
                        .get_header(height - 1)?
                        .ok_or(MdbxContextError::Corrupt("reorg parent header missing"))?;
                    if undo.log_slots_before != parent_header.log_slots
                        || self.state.state.log_slots() as u32 != parent_header.log_slots
                        || self.state.utxo_root != parent_header.state_root
                        || self.state.active_slot_count != parent_header.active_slot_count
                        || self.state.alloc_counter != parent_header.alloc_counter
                    {
                        return Err(MdbxContextError::Corrupt(
                            "reorg undo does not restore parent header state",
                        ));
                    }
                    self.recent_headers.remove(&height);
                    reverted_heights.push(height);
                }
                Ok(())
            })();
            if let Err(error) = revert_result {
                return Err(self.abort_staged_reorg(error));
            }
            (reclaimed_tx_hashes, reverted_heights)
        };

        // -----------------------------------------------------------------------
        // Update tip pointers to the ancestor.
        // -----------------------------------------------------------------------
        self.tip_height = ancestor_height;
        self.tip_hash = block_id(&ancestor_header);
        self.tip_chain_work = ancestor_chain_work;

        // -----------------------------------------------------------------------
        // Validate the entire fork through the normal terminal-first applier,
        // but stage every resulting commit in RAM. The old canonical MDBX
        // branch remains untouched until every replacement block succeeds.
        // -----------------------------------------------------------------------
        let mut applied_heights: Vec<u64> = Vec::new();
        self.defer_finality_updates = true;
        self.reorg_staging = Some(Vec::with_capacity(replacement_objects.len()));

        for (index, accepted) in replacement_objects.iter().copied().enumerate() {
            let candidate = Block::from_bytes(accepted.block_bytes()).map_err(|_| {
                self.abort_staged_reorg(MdbxContextError::Corrupt(
                    "validated reorg object became malformed",
                ))
            })?;
            match apply_block(self, index, local_time) {
                Ok(()) => {
                    applied_heights.push(candidate.header.height);
                    tracing::info!(height = candidate.header.height, "reorg: applied new block");
                }
                Err(e) => {
                    tracing::error!(height = candidate.header.height, err = ?e, "reorg: failed to apply block");
                    return Err(self.abort_staged_reorg(e));
                }
            }
        }

        let staged = match self.reorg_staging.take() {
            Some(staged) => staged,
            None => {
                return Err(
                    self.abort_staged_reorg(MdbxContextError::Corrupt("reorg staging disappeared"))
                );
            }
        };
        let finalized_after_reorg = match self.finalized_for_tip(self.tip_height) {
            Ok(finalized) => finalized,
            Err(error) => {
                return Err(self.abort_staged_reorg(error));
            }
        };
        let final_header = *self.tip_header();
        let final_hash = self.tip_hash;
        let consensus_meta = ConsensusMeta {
            tip_height: self.tip_height,
            tip_hash: final_hash,
            cumulative_chainwork: self.tip_chain_work,
            finalized: finalized_after_reorg,
        };
        let commit_started = Instant::now();
        let commit_result = (|| -> Result<(), MdbxContextError> {
            let dirty_ids: Vec<u16> = self.state.state.dirty_segment_ids().collect();
            let eff_log = self.state.state.effective_log_segment_size() as u8;
            let mut dirty_refs = Vec::with_capacity(dirty_ids.len());
            let mut dirty_summaries = Vec::with_capacity(dirty_ids.len());
            for segment_id in dirty_ids {
                let live_count = self.state.state.segment_live_count(segment_id);
                let exact_root = self.state.cached_exact_segment_root(segment_id).ok_or(
                    MdbxContextError::Corrupt("dirty reorg exact segment root is missing"),
                )?;
                let columns = if live_count == 0 {
                    None
                } else {
                    Some(self.state.state.try_get_segment_columns(segment_id).ok_or(
                        MdbxContextError::Corrupt("dirty reorg segment is not resident"),
                    )?)
                };
                dirty_refs.push((segment_id, eff_log, columns));
                dirty_summaries.push((segment_id, live_count, exact_root));
            }
            self.store.commit_reorg(
                ancestor_height,
                &final_header,
                &final_hash,
                &dirty_refs,
                &dirty_summaries,
                &reclaimed_tx_hashes,
                replacement_objects,
                &staged,
                self.state.circulating_supply_micronoid,
                &consensus_meta,
            )?;
            Ok(())
        })();
        if let Err(error) = commit_result {
            return Err(self.abort_staged_reorg(error));
        }
        let commit_elapsed = commit_started.elapsed();
        self.state.state.clear_dirty();
        self.state.state.evict_all_persisted_segments();
        self.finalized = finalized_after_reorg;
        self.defer_finality_updates = false;

        tracing::info!(
            reverted = reverted_heights.len(),
            applied = applied_heights.len(),
            new_tip = self.tip_height,
            "reorg complete"
        );
        let total_elapsed = total_started.elapsed();
        if total_elapsed >= RECURSIVE_SUFFIX_SLOW_PATH {
            tracing::warn!(
                ancestor_height,
                reverted = reverted_heights.len(),
                applied = applied_heights.len(),
                prepare_apply_ms = total_elapsed.saturating_sub(commit_elapsed).as_millis(),
                commit_ms = commit_elapsed.as_millis(),
                total_ms = total_elapsed.as_millis(),
                "atomic reorg slow path"
            );
        }

        Ok(ReorgResult {
            reverted_heights,
            applied_heights,
            reclaimed_tx_hashes,
        })
    }

    fn preload_segments_for_undo_in_state(
        store: &MdbxStore,
        state: &mut ChainState,
        undo: &BlockUndoLog,
    ) -> Result<(), MdbxContextError> {
        let effective_log = state.state.effective_log_segment_size();
        let mut needed: Vec<u16> = undo
            .slot_changes
            .iter()
            .map(|(slot_index, _)| (*slot_index >> effective_log) as u16)
            .collect();
        needed.sort_unstable();
        needed.dedup();
        for segment_id in needed {
            if !state.state.is_evicted(segment_id) {
                continue;
            }
            let (_, columns) = store
                .get_segment(segment_id)?
                .ok_or(MdbxContextError::Corrupt(
                    "evicted undo segment is missing from MDBX",
                ))?;
            state
                .restore_evicted_segment(segment_id, columns)
                .map_err(|_| {
                    MdbxContextError::Corrupt("evicted undo segment exact summary mismatch")
                })?;
        }
        Ok(())
    }

    /// Preload evicted segments that the block will access.
    ///
    /// Checks each input slot (must be non-empty = need to read existing data)
    /// and each output slot (must be empty = need to read to verify).
    /// Reloads from MDBX any segment that is currently evicted.
    pub fn preload_segments_for_block(&mut self, block: &Block) -> Result<(), MdbxContextError> {
        // Keep the public preload helper fail-closed even when a caller does
        // not come through `apply_next_block`.
        crate::consensus::validate_block_resource_preflight(block)?;
        let segment_ids = self.segment_ids_for_block(block);
        self.preload_segment_ids(&segment_ids)
    }

    fn segment_ids_for_block(&self, block: &Block) -> Vec<u16> {
        let parent_log = self.state.state.log_slots();
        let mapped_log = if block.header.log_slots as usize == parent_log.saturating_add(1) {
            parent_log + 1
        } else {
            parent_log
        };
        // Below the production 2^16 segment boundary, a one-level expansion
        // grows the existing segment rather than introducing segment 1. Map
        // against the validated child geometry so an evicted segment 0 is
        // hydrated before the verifier touches its new upper half.
        let eff_log = mapped_log.min(LOG_SEGMENT_SIZE as usize);
        let mut needed = Vec::new();

        for tx in &block.transactions {
            for (_, inp) in tx.body.live_inputs() {
                needed.push((inp.slot_index >> eff_log) as u16);
            }
            for (_, out) in tx.body.live_outputs() {
                needed.push((out.slot_index >> eff_log) as u16);
            }
            // System-mint slots are allocator-assigned: include their outputs
            // alongside user actions when selecting segments to hydrate.
        }
        needed.sort_unstable();
        needed.dedup();
        needed
    }

    fn preload_segment_ids(&mut self, needed: &[u16]) -> Result<(), MdbxContextError> {
        let mut hydrated: Vec<ParentSegmentSummary> = Vec::new();
        let expected_log = self.state.state.effective_log_segment_size() as u8;
        let expected_len = 1usize << usize::from(expected_log);

        for &seg_id in needed {
            // A legal one-level expansion may address the canonical-zero new
            // upper half. It has no parent MDBX payload to hydrate.
            if seg_id as usize >= self.state.state.num_segments() {
                continue;
            }
            if self.state.state.is_evicted(seg_id) {
                let parent_fri_root = self.state.state.cached_segment_root(seg_id);
                // Reload from MDBX.
                match self.store.get_segment(seg_id) {
                    Ok(Some((stored_log, cols))) => {
                        if stored_log != expected_log
                            || cols.values.len() != expected_len
                            || cols.owners_hi.len() != expected_len
                            || cols.owners_lo.len() != expected_len
                        {
                            let original = MdbxContextError::Corrupt(
                                "evicted segment has invalid durable geometry",
                            );
                            return match self.evict_preloaded_segments(&hydrated) {
                                Ok(()) => Err(original),
                                Err(cleanup) => Err(cleanup),
                            };
                        }
                        if self.state.restore_evicted_segment(seg_id, cols).is_err() {
                            let original =
                                MdbxContextError::Corrupt("evicted segment exact summary mismatch");
                            return match self.evict_preloaded_segments(&hydrated) {
                                Ok(()) => Err(original),
                                Err(cleanup) => Err(cleanup),
                            };
                        }
                        hydrated.push((seg_id, parent_fri_root));
                    }
                    Ok(None) => {
                        let original =
                            MdbxContextError::Corrupt("evicted live segment is missing from MDBX");
                        return match self.evict_preloaded_segments(&hydrated) {
                            Ok(()) => Err(original),
                            Err(cleanup) => Err(cleanup),
                        };
                    }
                    Err(e) => {
                        let original = MdbxContextError::Store(e);
                        return match self.evict_preloaded_segments(&hydrated) {
                            Ok(()) => Err(original),
                            Err(cleanup) => Err(cleanup),
                        };
                    }
                }
            }
        }
        Ok(())
    }

    fn evict_preloaded_segments(
        &mut self,
        hydrated: &[ParentSegmentSummary],
    ) -> Result<(), MdbxContextError> {
        for &(segment_id, parent_fri_root) in hydrated {
            self.state
                .state
                .restore_persisted_segment_summary_and_evict(segment_id, parent_fri_root)
                .map_err(MdbxContextError::Corrupt)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // State snapshot sync
    // -----------------------------------------------------------------------

    /// Verify the snapshot tip's full HistoryStep terminal before any state
    /// epoch can be installed. The boundary block body may already be pruned;
    /// the sealed candidate header, terminal and finalized staging state are the
    /// complete O(1)-sync boundary.
    pub fn verify_snapshot_boundary<A>(
        &self,
        header: BlockHeader,
        epoch_anchor_header: BlockHeader,
        history_step_terminal_bytes: Vec<u8>,
        verify_history_step_terminal: A,
    ) -> Result<VerifiedSnapshotBoundary, MdbxContextError>
    where
        A: FnOnce(&HistoryStepTerminalClaim<'_>) -> Result<(), String>,
    {
        if header.height == 0 {
            return Err(MdbxContextError::Corrupt(
                "snapshot boundary header metadata is invalid",
            ));
        }
        let expected_epoch_height = tx_epoch_anchor_height_for_child(header.height);
        if epoch_anchor_header.height != expected_epoch_height {
            return Err(MdbxContextError::Corrupt(
                "snapshot boundary epoch anchor is invalid",
            ));
        }
        if history_step_terminal_bytes.len()
            > crate::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_BYTES
        {
            return Err(MdbxContextError::Consensus(
                ConsensusError::BadHistoryStepTerminal(
                    "snapshot HistoryStep terminal exceeds the wire cap".to_string(),
                ),
            ));
        }
        let terminal_metadata = crate::history_step::HistoryStepTerminalMetadata::decode_prefix(
            &history_step_terminal_bytes,
        )
        .map_err(|error| {
            MdbxContextError::Consensus(ConsensusError::BadHistoryStepTerminal(format!(
                "snapshot terminal metadata is invalid: {error}"
            )))
        })?;
        if terminal_metadata.terminal_height() != header.height
            || terminal_metadata.terminal_hash() != crate::block_header::semantic_header_id(&header)
        {
            return Err(MdbxContextError::Consensus(
                ConsensusError::BadHistoryStepTerminal(
                    "snapshot terminal does not bind its staged boundary".to_string(),
                ),
            ));
        }
        verify_history_step_terminal(&HistoryStepTerminalClaim {
            terminal_bytes: &history_step_terminal_bytes,
            header,
            epoch_anchor_header,
        })
        .map_err(|error| {
            MdbxContextError::Consensus(ConsensusError::BadHistoryStepTerminal(error))
        })?;
        Ok(VerifiedSnapshotBoundary::new_verified(
            header,
            history_step_terminal_bytes,
        ))
    }

    fn authorize_recursive_terminal_from_boundary(
        &self,
        boundary_height: u64,
        boundary_hash: [u8; 32],
        verified: VerifiedHistoryStepTerminal,
    ) -> Result<VerifiedRecursiveSuffix, MdbxContextError> {
        let VerifiedHistoryStepTerminal {
            tip_header,
            epoch_anchor_header,
            terminal_bytes,
        } = verified;
        if tip_header.height <= boundary_height {
            return Err(MdbxContextError::Corrupt(
                "recursive suffix tip does not advance its exact boundary",
            ));
        }
        let expected_epoch_height = tx_epoch_anchor_height_for_child(tip_header.height);
        if expected_epoch_height <= boundary_height {
            let canonical_epoch_anchor = self.get_header_from_store(expected_epoch_height)?.ok_or(
                MdbxContextError::Corrupt("recursive suffix canonical epoch anchor is missing"),
            )?;
            if canonical_epoch_anchor != epoch_anchor_header {
                return Err(MdbxContextError::Consensus(
                    ConsensusError::BadHistoryStepTerminal(
                        "recursive suffix epoch anchor is not canonical".to_string(),
                    ),
                ));
            }
        } else if expected_epoch_height >= tip_header.height {
            return Err(MdbxContextError::Consensus(
                ConsensusError::BadHistoryStepTerminal(
                    "recursive suffix epoch anchor lies outside its body sequence".to_string(),
                ),
            ));
        }
        Ok(VerifiedRecursiveSuffix {
            boundary_height,
            tip_header,
            epoch_anchor_header,
            terminal_bytes,
            next_height: boundary_height.saturating_add(1),
            previous_hash: boundary_hash,
            complete: false,
        })
    }

    /// Verify one recursive terminal for an exact post-snapshot body suffix.
    ///
    /// The terminal proves the complete HistoryStep recursion through
    /// `tip_header`; the caller separately supplies the linked canonical block
    /// bodies. Those bodies still pass all native checks and exact state-root
    /// materialization one by one, but no redundant intermediate terminal is
    /// transferred or verified.
    pub fn verify_recursive_suffix<A>(
        &mut self,
        tip_header: BlockHeader,
        epoch_anchor_header: BlockHeader,
        terminal_bytes: Vec<u8>,
        verify_history_step_terminal: A,
    ) -> Result<VerifiedRecursiveSuffix, MdbxContextError>
    where
        A: FnOnce(&HistoryStepTerminalClaim<'_>) -> Result<(), String>,
    {
        if self.reorg_staging.is_some() {
            return Err(MdbxContextError::Corrupt(
                "recursive suffix cannot begin during reorg staging",
            ));
        }
        if tip_header.height <= self.tip_height {
            return Err(MdbxContextError::Corrupt(
                "recursive suffix tip does not advance the canonical boundary",
            ));
        }
        let verified = verify_history_step_terminal_candidate(
            tip_header,
            epoch_anchor_header,
            terminal_bytes,
            verify_history_step_terminal,
        )?;
        self.begin_preverified_recursive_suffix(verified)
    }

    /// Consume an already verified terminal under the current canonical base
    /// and persist its crash-recovery authority before body application.
    pub fn begin_preverified_recursive_suffix(
        &mut self,
        verified: VerifiedHistoryStepTerminal,
    ) -> Result<VerifiedRecursiveSuffix, MdbxContextError> {
        if self.reorg_staging.is_some() {
            return Err(MdbxContextError::Corrupt(
                "recursive suffix cannot begin during reorg staging",
            ));
        }
        let boundary_height = self.tip_height;
        let boundary_hash = self.tip_hash;
        let authority = self.authorize_recursive_terminal_from_boundary(
            boundary_height,
            boundary_hash,
            verified,
        )?;
        self.store.begin_verified_recursive_suffix(
            boundary_height,
            boundary_hash,
            &authority.tip_header,
            &authority.terminal_bytes,
        )?;
        Ok(authority)
    }

    /// Verify one terminal for a candidate replacement suffix without
    /// modifying the current canonical chain.
    pub fn verify_reorg_suffix<A>(
        &self,
        ancestor_height: u64,
        tip_header: BlockHeader,
        epoch_anchor_header: BlockHeader,
        terminal_bytes: Vec<u8>,
        verify_history_step_terminal: A,
    ) -> Result<VerifiedReorgSuffix, MdbxContextError>
    where
        A: FnOnce(&HistoryStepTerminalClaim<'_>) -> Result<(), String>,
    {
        let verified = verify_history_step_terminal_candidate(
            tip_header,
            epoch_anchor_header,
            terminal_bytes,
            verify_history_step_terminal,
        )?;
        self.authorize_preverified_reorg_suffix(ancestor_height, verified)
    }

    /// Bind a preverified terminal to the exact current non-final canonical
    /// view. This is cheap and is repeated immediately before atomic commit.
    pub fn authorize_preverified_reorg_suffix(
        &self,
        ancestor_height: u64,
        verified: VerifiedHistoryStepTerminal,
    ) -> Result<VerifiedReorgSuffix, MdbxContextError> {
        if self.reorg_staging.is_some() {
            return Err(MdbxContextError::Corrupt(
                "recursive reorg cannot begin during reorg staging",
            ));
        }
        if ancestor_height >= self.tip_height
            || self.tip_height - ancestor_height > CONSENSUS_FINALITY_DEPTH
            || ancestor_height < self.finalized.height
        {
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash));
        }
        let ancestor_header =
            self.get_header_from_store(ancestor_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "reorg ancestor header is missing",
                ))?;
        let ancestor_hash = block_id(&ancestor_header);
        if ancestor_height == self.finalized.height && ancestor_hash != self.finalized.hash {
            return Err(MdbxContextError::Consensus(ConsensusError::BadParentHash));
        }
        let suffix = self.authorize_recursive_terminal_from_boundary(
            ancestor_height,
            ancestor_hash,
            verified,
        )?;
        Ok(VerifiedReorgSuffix {
            suffix,
            original_tip_height: self.tip_height,
            original_tip_hash: self.tip_hash,
            original_finalized: self.finalized,
        })
    }

    /// Install a fully verified snapshot boundary in one durable state epoch.
    pub fn apply_staged_state_snapshot<S: SnapshotHeaderInstallSource>(
        &mut self,
        staging: &FinalizedSnapshotStaging,
        boundary: &VerifiedSnapshotBoundary,
        header_source: &mut S,
        allow_nonfinal_rebase: bool,
    ) -> Result<(), MdbxContextError> {
        if self.reorg_staging.is_some() {
            return Err(MdbxContextError::Corrupt(
                "snapshot install cannot run during reorg staging",
            ));
        }

        let authenticated = staging.metadata();
        let tip_header = *authenticated.header();
        let tip_height = tip_header.height;
        let tip_hash = authenticated.tip_hash();
        if tip_height <= self.tip_height {
            return Err(MdbxContextError::Corrupt(
                "snapshot tip is not ahead of local state",
            ));
        }
        if block_id(&tip_header) != tip_hash {
            return Err(MdbxContextError::Corrupt(
                "staged snapshot tip hash does not match authenticated header",
            ));
        }
        if boundary.header() != &tip_header || boundary.block_hash() != tip_hash {
            return Err(MdbxContextError::Corrupt(
                "verified snapshot boundary does not match staged state",
            ));
        }
        let target_record = header_source.target_record();
        if target_record.header != tip_header || target_record.hash != tip_hash {
            return Err(MdbxContextError::Corrupt(
                "staged snapshot tip conflicts with sealed header source",
            ));
        }

        // Keep exactly the bounded header window used by MTP, expansion and
        // transaction-epoch checks. Requiring the complete suffix avoids a
        // successful install followed by fallback-to-tip header semantics.
        let history_window = MEDIAN_TIME_BLOCKS as u64 + TX_EPOCH_BLOCKS;
        let expected_first = tip_height.saturating_sub(history_window);
        let expected_header_count =
            tip_height.saturating_sub(expected_first).saturating_add(1) as usize;
        let decoded_recent = header_source.recent_headers().to_vec();
        if decoded_recent.len() != expected_header_count {
            return Err(MdbxContextError::Corrupt(
                "staged snapshot recent header window has the wrong length",
            ));
        }
        if decoded_recent.first().map(|header| header.height) != Some(expected_first)
            || decoded_recent.last().copied() != Some(tip_header)
        {
            return Err(MdbxContextError::Corrupt(
                "staged snapshot recent headers do not cover the required boundary",
            ));
        }
        for pair in decoded_recent.windows(2) {
            if pair[1].height != pair[0].height.saturating_add(1)
                || pair[1].prev_block_hash != block_id(&pair[0])
            {
                return Err(MdbxContextError::Corrupt(
                    "staged snapshot recent headers are not canonical and contiguous",
                ));
            }
        }
        let cumulative_chainwork = target_record.cumulative_chainwork;
        let finalized = FinalizedCheckpoint {
            height: tip_height,
            hash: tip_hash,
        };
        let consensus_meta = ConsensusMeta {
            tip_height,
            tip_hash,
            cumulative_chainwork,
            finalized,
        };
        let mut recent_headers = HashMap::with_capacity(decoded_recent.len());
        for &header in &decoded_recent {
            recent_headers.insert(header.height, header);
        }

        // The installer returns a compact state only after the single RW
        // transaction has committed. Every operation below is an infallible
        // in-memory swap, so no post-commit error can leave hot and durable
        // state at different boundaries.
        let snapshot_state = self.store.install_finalized_snapshot_staging(
            staging,
            &consensus_meta,
            &decoded_recent,
            boundary,
            header_source,
            allow_nonfinal_rebase,
        )?;
        debug_assert_eq!(snapshot_state.state.materialized_segment_ids().count(), 0);

        self.state = snapshot_state;
        self.recent_headers = recent_headers;
        self.tip_height = tip_height;
        self.tip_hash = tip_hash;
        self.tip_chain_work = cumulative_chainwork;
        self.finalized = finalized;
        self.defer_finality_updates = false;
        Ok(())
    }

    /// Preserve a complete, already verified terminal for a canonical
    /// finalized snapshot boundary. This is operational proof availability,
    /// not consensus state: failure cannot change the accepted chain.
    pub fn cache_verified_snapshot_boundary_proof(
        &self,
        boundary: &VerifiedSnapshotBoundary,
    ) -> Result<(), MdbxContextError> {
        self.store
            .cache_verified_snapshot_boundary_proof(boundary)
            .map_err(MdbxContextError::Store)
    }

    // -----------------------------------------------------------------------
    // Chain accessors
    // -----------------------------------------------------------------------

    pub fn tip_header(&self) -> &BlockHeader {
        self.recent_headers
            .get(&self.tip_height)
            .expect("tip header must always be in recent_headers")
    }

    pub fn header(&self, height: u64) -> Option<&BlockHeader> {
        self.recent_headers.get(&height)
    }

    /// Load any header from MDBX (including old ones not in RAM).
    pub fn get_header_from_store(&self, height: u64) -> Result<Option<BlockHeader>, StoreError> {
        // Check RAM first (fast path).
        if let Some(h) = self.recent_headers.get(&height) {
            return Ok(Some(*h));
        }
        self.store.get_header(height)
    }

    pub fn prev_timestamps(&self) -> Result<Vec<u64>, MdbxContextError> {
        let tip = self.tip_height;
        let start = tip.saturating_sub(MEDIAN_TIME_BLOCKS as u64 - 1);
        let mut timestamps = Vec::with_capacity(tip.saturating_sub(start) as usize + 1);
        for height in start..=tip {
            let header = self
                .get_header_from_store(height)?
                .ok_or(MdbxContextError::Corrupt("canonical MTP header is missing"))?;
            timestamps.push(header.timestamp);
        }
        Ok(timestamps)
    }

    /// Collect the complete oldest-first hard-finalized occupancy window that
    /// decides the next child state depth.
    ///
    /// The range is derived from `tip_height`, never from the local persisted
    /// finality checkpoint: snapshot-installed and fully replayed nodes must
    /// validate the same child header at the same chain height.
    pub fn finalized_active_counts(&self) -> Result<Vec<u64>, MdbxContextError> {
        let Some((start, end)) = finalized_expansion_window(self.tip_height) else {
            return Ok(Vec::new());
        };
        let mut counts = Vec::with_capacity(EXPANSION_WINDOW as usize);
        for height in start..=end {
            let header = self
                .get_header_from_store(height)?
                .ok_or(MdbxContextError::Corrupt(
                    "hard-finalized expansion header is missing",
                ))?;
            counts.push(header.active_slot_count);
        }
        if counts.len() != EXPANSION_WINDOW as usize {
            return Err(MdbxContextError::Corrupt(
                "hard-finalized expansion window has the wrong length",
            ));
        }
        Ok(counts)
    }

    pub fn anchor_info(&self) -> Result<AnchorInfo, MdbxContextError> {
        let anchor_height = asert_anchor_height(self.tip_height);
        let anchor_header =
            self.get_header_from_store(anchor_height)?
                .ok_or(MdbxContextError::Corrupt(
                    "canonical ASERT anchor header is missing",
                ))?;
        Ok(AnchorInfo {
            anchor_height,
            anchor_timestamp: anchor_header.timestamp,
            anchor_target: anchor_header.difficulty_target,
        })
    }

    /// Check exact equality with the start anchor for the next child block.
    pub fn is_current_tx_epoch_anchor(&self, anchor_hash: &[u8; 32]) -> bool {
        let height = tx_epoch_anchor_height_for_child(self.tip_height + 1);
        self.get_header_from_store(height)
            .ok()
            .flatten()
            .is_some_and(|header| block_id(&header) == *anchor_hash)
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }
    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }
    pub fn tip_chain_work(&self) -> &[u8; 32] {
        &self.tip_chain_work
    }
    pub fn finalized_checkpoint(&self) -> FinalizedCheckpoint {
        self.finalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_next_bundle(context: &MdbxChainContext) -> crate::AcceptedBlockBundle {
        test_next_bundle_for_miner(context, 0x44)
    }

    fn test_next_bundle_for_miner(
        context: &MdbxChainContext,
        miner_byte: u8,
    ) -> crate::AcceptedBlockBundle {
        let parent = *context.tip_header();
        let timestamp = parent.timestamp.saturating_add(1);
        let anchor = context.anchor_info().unwrap();
        let target = crate::consensus::next_target(
            anchor.anchor_height,
            anchor.anchor_timestamp,
            &anchor.anchor_target,
            parent.height.saturating_add(1),
            timestamp,
        );
        let finalized_active_counts = context.finalized_active_counts().unwrap();
        let (template, _) = crate::consensus::template::build_node_owned_block_template(
            &parent,
            &context.state,
            &finalized_active_counts,
            Vec::new(),
            noid_poseidon2b::primitives::Address([miner_byte; 32]),
            timestamp,
            target,
        )
        .unwrap();
        let mut nonce = 0u128;
        let block = loop {
            let candidate = template.clone().into_block(nonce);
            if crate::consensus::validate_pow(&candidate.header).is_ok() {
                break candidate;
            }
            nonce = nonce.checked_add(1).expect("test nonce space exhausted");
        };
        let mut terminal = crate::history_step::HistoryStepTerminalMetadata::new(
            block.header.height,
            crate::block_header::semantic_header_id(&block.header),
            0,
        )
        .unwrap()
        .encode_prefix()
        .to_vec();
        terminal.push(0xA5);
        crate::AcceptedBlockBundle::try_from_parts(block.to_bytes(), terminal).unwrap()
    }

    fn accept_test_bundle(context: &mut MdbxChainContext, bundle: &crate::AcceptedBlockBundle) {
        let block = crate::Block::from_bytes(bundle.block_bytes()).unwrap();
        context
            .apply_next_block(
                bundle,
                block.header.timestamp,
                |block, state| {
                    crate::materialize_accepted_block_state(state, block)
                        .map_err(|error| format!("{error:?}"))
                },
                |_| Ok(()),
            )
            .unwrap();
    }

    fn block_sequence(count: usize) -> Vec<crate::AcceptedBlockBundle> {
        let directory = tempfile::tempdir().unwrap();
        let mut producer = easy_block_context(directory.path());
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            let bundle = test_next_bundle(&producer);
            accept_test_bundle(&mut producer, &bundle);
            blocks.push(bundle);
        }
        blocks
    }

    fn two_block_suffix() -> (crate::AcceptedBlockBundle, crate::AcceptedBlockBundle) {
        let mut blocks = block_sequence(2).into_iter();
        (blocks.next().unwrap(), blocks.next().unwrap())
    }

    fn test_context_with_log(path: &Path, log_slots: u32) -> MdbxChainContext {
        let store = MdbxStore::open(path).unwrap();
        let state = ChainState::with_log_slots(log_slots as usize);
        let header = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: state.cached_state_root(),
            tx_root: [0u8; 32],
            timestamp: 1_000,
            height: 0,
            miner_address: noid_poseidon2b::primitives::Address([0u8; 32]),
            nonce: 0,
            difficulty_target: [0xff; 32],
            log_slots,
            active_slot_count: 0,
            alloc_counter: 0,
        };
        let hash = block_id(&header);
        let chain_work = block_work(&header.difficulty_target);
        let finalized = FinalizedCheckpoint { height: 0, hash };
        store
            .commit_block(
                &header,
                &hash,
                &BlockUndoLog::empty(0, header.log_slots),
                &[],
                &[],
                &[],
                &[],
                None,
                state.circulating_supply_micronoid,
                &ConsensusMeta {
                    tip_height: 0,
                    tip_hash: hash,
                    cumulative_chainwork: chain_work,
                    finalized,
                },
                false,
            )
            .unwrap();
        MdbxChainContext {
            store,
            state,
            recent_headers: std::collections::HashMap::from([(0, header)]),
            tip_height: 0,
            tip_hash: hash,
            tip_chain_work: chain_work,
            finalized,
            defer_finality_updates: false,
            reorg_staging: None,
        }
    }

    fn small_context(path: &Path) -> MdbxChainContext {
        test_context_with_log(path, 8)
    }

    fn easy_block_context(path: &Path) -> MdbxChainContext {
        test_context_with_log(path, crate::consensus::params::LOG_SLOTS_GENESIS)
    }

    fn unsafe_claimed_coinbase_with_impossible_pow(
        context: &MdbxChainContext,
    ) -> crate::consensus::template::LocallyProvedBlockCommit {
        let parent = *context.tip_header();
        let (template, prepared) = crate::consensus::template::build_node_owned_block_template(
            &parent,
            &context.state,
            &[parent.active_slot_count],
            vec![],
            noid_poseidon2b::primitives::Address([0x44; 32]),
            parent.timestamp + crate::consensus::params::BLOCK_TIME,
            [0; 32],
        )
        .unwrap();
        let block = template.into_block(0);
        let mut terminal = crate::history_step::HistoryStepTerminalMetadata::new(
            block.header.height,
            crate::block_header::semantic_header_id(&block.header),
            0,
        )
        .unwrap()
        .encode_prefix()
        .to_vec();
        terminal.push(0xA5);
        // SAFETY: this is deliberately not a real proof. The negative test
        // below exercises the commit boundary's independent PoW guard and
        // asserts that no canonical state is mutated.
        unsafe {
            prepared
                .seal_after_trusted_history_step_proof_unchecked(block, terminal)
                .unwrap()
        }
    }

    fn occupancy_header(height: u64, active_slot_count: u64) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [height.saturating_sub(1) as u8; 32],
            state_root: [height as u8; 32],
            tx_root: [0x33; 32],
            timestamp: 1_000 + height,
            height,
            miner_address: noid_poseidon2b::primitives::Address([0x44; 32]),
            nonce: 0,
            difficulty_target: [0xff; 32],
            log_slots: 8,
            active_slot_count,
            alloc_counter: active_slot_count,
        }
    }

    #[test]
    fn expansion_ignores_unfinalized_tip_pressure_and_requires_strict_majority() {
        let directory = tempfile::tempdir().unwrap();
        let mut context = small_context(directory.path());
        let threshold = (1u64 << 8) * crate::consensus::params::EXPAND_NUM
            / crate::consensus::params::EXPAND_DENOM;
        context.recent_headers.clear();
        for height in 0..=62 {
            let active = if height >= 35 {
                threshold
            } else {
                threshold - 1
            };
            context
                .recent_headers
                .insert(height, occupancy_header(height, active));
        }

        // At parent 52, headers 35..52 are all under unfinalized pressure,
        // while the deciding finalized window is 17..34 and remains below.
        context.tip_height = 52;
        let counts = context.finalized_active_counts().unwrap();
        assert_eq!(counts, vec![threshold - 1; EXPANSION_WINDOW as usize]);
        assert_eq!(
            crate::consensus::expected_child_log_slots(context.tip_height, 8, &counts),
            8
        );

        // Parent 61 sees only nine finalized threshold headers (35..43): tie,
        // therefore no irreversible expansion.
        context.tip_height = 61;
        let counts = context.finalized_active_counts().unwrap();
        assert_eq!(
            counts.iter().filter(|&&active| active >= threshold).count(),
            9
        );
        assert_eq!(
            crate::consensus::expected_child_log_slots(context.tip_height, 8, &counts),
            8
        );

        // Parent 62 finalizes header 44, producing the required ten of 18.
        context.tip_height = 62;
        let counts = context.finalized_active_counts().unwrap();
        assert_eq!(
            counts.iter().filter(|&&active| active >= threshold).count(),
            10
        );
        assert_eq!(
            crate::consensus::expected_child_log_slots(context.tip_height, 8, &counts),
            9
        );
    }

    #[test]
    fn missing_finalized_expansion_header_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let mut context = small_context(directory.path());
        context.recent_headers = (0..=35)
            .map(|height| (height, occupancy_header(height, 0)))
            .collect();
        context.tip_height = 35;
        context.recent_headers.remove(&7);

        assert!(matches!(
            context.finalized_active_counts(),
            Err(MdbxContextError::Corrupt(
                "hard-finalized expansion header is missing"
            ))
        ));
    }

    #[test]
    fn header_validation_helpers_load_ram_misses_from_the_canonical_store() {
        let directory = tempfile::tempdir().unwrap();
        let mut context = small_context(directory.path());
        context.recent_headers = (1..=5)
            .map(|height| (height, occupancy_header(height, 0)))
            .collect();
        context.tip_height = 5;

        let genesis = context.get_header_from_store(0).unwrap().unwrap();
        let timestamps = context.prev_timestamps().unwrap();
        assert_eq!(timestamps.len(), 6);
        assert_eq!(timestamps[0], genesis.timestamp);

        let anchor = context.anchor_info().unwrap();
        assert_eq!(anchor.anchor_height, 0);
        assert_eq!(anchor.anchor_timestamp, genesis.timestamp);
        assert_eq!(anchor.anchor_target, genesis.difficulty_target);
    }

    #[test]
    fn header_validation_helpers_fail_closed_on_a_missing_canonical_row() {
        let directory = tempfile::tempdir().unwrap();
        let mut context = small_context(directory.path());
        context.recent_headers = (0..=11)
            .map(|height| (height, occupancy_header(height, 0)))
            .collect();
        context.tip_height = 11;

        context.recent_headers.remove(&2);
        assert!(matches!(
            context.prev_timestamps(),
            Err(MdbxContextError::Corrupt("canonical MTP header is missing"))
        ));

        context.recent_headers.insert(2, occupancy_header(2, 0));
        context.recent_headers.remove(&6);
        assert!(matches!(
            context.anchor_info(),
            Err(MdbxContextError::Corrupt(
                "canonical ASERT anchor header is missing"
            ))
        ));
    }

    #[test]
    fn rejected_snapshot_terminal_leaves_canonical_headers_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let context = MdbxChainContext::open_or_create(directory.path()).unwrap();
        let genesis = genesis_header();
        let genesis_hash = block_id(&genesis);
        let mut candidate = genesis;
        candidate.height = 1;
        candidate.prev_block_hash = genesis_hash;
        candidate.timestamp = candidate.timestamp.saturating_add(1);
        candidate.nonce = candidate.nonce.saturating_add(1);
        let candidate_hash = block_id(&candidate);
        let mut terminal = crate::history_step::HistoryStepTerminalMetadata::new(
            candidate.height,
            candidate_hash,
            0,
        )
        .unwrap()
        .encode_prefix()
        .to_vec();
        terminal.push(1);

        assert!(context
            .verify_snapshot_boundary(candidate, genesis, terminal, |_| {
                Err("deliberate verifier rejection".to_owned())
            })
            .is_err());
        assert_eq!(
            context.store.get_chain_tip().unwrap(),
            Some((0, genesis_hash))
        );
        assert_eq!(context.store.get_header(1).unwrap(), None);
        assert_eq!(context.store.get_chain_work(1).unwrap(), None);
        assert_eq!(context.store.get_header_anchor(1).unwrap(), None);
    }

    #[test]
    fn recursive_suffix_verifies_once_and_commits_only_the_final_terminal() {
        let (first, second) = two_block_suffix();
        let directory = tempfile::tempdir().unwrap();
        let mut context = easy_block_context(directory.path());
        let second_block = crate::Block::from_bytes(second.block_bytes()).unwrap();
        let genesis = context.get_header_from_store(0).unwrap().unwrap();
        let mut verifier_calls = 0usize;
        let mut authority = context
            .verify_recursive_suffix(
                second_block.header,
                genesis,
                second.history_step_terminal_bytes().to_vec(),
                |_| {
                    verifier_calls += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(verifier_calls, 1);

        for bundle in [&first, &second] {
            context
                .apply_verified_recursive_suffix_block(
                    &mut authority,
                    bundle.block_bytes(),
                    crate::Block::from_bytes(bundle.block_bytes())
                        .unwrap()
                        .header
                        .timestamp,
                    |block, state| {
                        crate::materialize_accepted_block_state(state, block)
                            .map_err(|error| format!("{error:?}"))
                    },
                )
                .unwrap();
        }

        assert!(authority.is_complete());
        assert_eq!(context.tip_height(), 2);
        assert_eq!(context.tip_hash(), second.block_hash());
        assert!(context.store.get_undo_log(1).unwrap().is_some());
        assert!(context.store.get_undo_log(2).unwrap().is_some());
        assert!(context.store.get_recent_block(1).unwrap().is_some());
        assert!(context
            .store
            .get_recent_accepted_block_bundle_bounded(1)
            .unwrap()
            .is_none());
        assert!(context
            .store
            .get_history_step_terminal_at(1, first.block_hash())
            .unwrap()
            .is_none());
        assert_eq!(
            context
                .store
                .get_recent_accepted_block_bundle_bounded(2)
                .unwrap(),
            Some(second.encode())
        );
        assert!(!context
            .store
            .durable_tip_has_verified_suffix_authority(context.tip_header(), context.tip_hash())
            .unwrap());

        // A node which obtained this suffix through compact snapshot sync must
        // immediately be able to export the same authenticated body sequence
        // for the next node. Intermediate local markers are not proof payloads;
        // the generation carries both bodies and only the final full terminal.
        let exports = tempfile::tempdir().unwrap();
        let generation =
            crate::storage::export_snapshot_generation(&context.store, exports.path(), 0, None)
                .unwrap();
        assert_eq!(
            generation.read_bridge_block_body(1).unwrap(),
            first.block_bytes()
        );
        assert_eq!(
            generation.read_bridge_block_body(2).unwrap(),
            second.block_bytes()
        );
        assert_eq!(
            generation.read_bridge_terminal().unwrap(),
            second.history_step_terminal_bytes()
        );
        assert_eq!(
            generation.read_terminal_at(2, second.block_hash()).unwrap(),
            second.history_step_terminal_bytes()
        );
        assert!(generation.read_terminal_at(1, first.block_hash()).is_err());
    }

    #[test]
    fn completed_recursive_suffix_can_reorg_from_its_last_compact_marker() {
        let (first, second) = two_block_suffix();
        let directory = tempfile::tempdir().unwrap();
        let mut context = easy_block_context(directory.path());
        let second_block = crate::Block::from_bytes(second.block_bytes()).unwrap();
        let genesis = context.get_header_from_store(0).unwrap().unwrap();
        let mut authority = context
            .verify_recursive_suffix(
                second_block.header,
                genesis,
                second.history_step_terminal_bytes().to_vec(),
                |_| Ok(()),
            )
            .unwrap();

        for bundle in [&first, &second] {
            context
                .apply_verified_recursive_suffix_block(
                    &mut authority,
                    bundle.block_bytes(),
                    crate::Block::from_bytes(bundle.block_bytes())
                        .unwrap()
                        .header
                        .timestamp,
                    |block, state| {
                        crate::materialize_accepted_block_state(state, block)
                            .map_err(|error| format!("{error:?}"))
                    },
                )
                .unwrap();
        }
        assert!(authority.is_complete());

        let result = context.apply_reorg_mdbx_with_applier(
            1,
            std::slice::from_ref(&second),
            second_block.header.timestamp,
            |context, bundle, local_time| {
                context.apply_next_block(
                    bundle,
                    local_time,
                    |block, state| {
                        crate::materialize_accepted_block_state(state, block)
                            .map_err(|error| format!("{error:?}"))
                    },
                    |_| Ok(()),
                )?;
                Ok(())
            },
        );

        assert!(result.is_ok(), "compact-suffix reorg failed: {result:?}");
        assert_eq!(context.tip_height(), 2);
        assert_eq!(context.tip_hash(), second.block_hash());
    }

    #[test]
    fn one_terminal_reorg_commits_exact_bodies_atomically() {
        let producer_dir = tempfile::tempdir().unwrap();
        let mut producer = easy_block_context(producer_dir.path());
        let first = test_next_bundle_for_miner(&producer, 0x55);
        accept_test_bundle(&mut producer, &first);
        let second = test_next_bundle_for_miner(&producer, 0x55);
        accept_test_bundle(&mut producer, &second);

        let directory = tempfile::tempdir().unwrap();
        let mut context = easy_block_context(directory.path());
        let old = test_next_bundle_for_miner(&context, 0x44);
        accept_test_bundle(&mut context, &old);
        let old_tip = old.block_hash();
        assert_ne!(old_tip, first.block_hash());

        let genesis = context.get_header_from_store(0).unwrap().unwrap();
        let second_block = Block::from_bytes(second.block_bytes()).unwrap();
        let verify_calls = std::cell::Cell::new(0usize);
        let authority = context
            .verify_reorg_suffix(
                0,
                second_block.header,
                genesis,
                second.history_step_terminal_bytes().to_vec(),
                |_| {
                    verify_calls.set(verify_calls.get() + 1);
                    Ok(())
                },
            )
            .unwrap();
        let bodies = vec![first.block_bytes().to_vec(), second.block_bytes().to_vec()];
        let result = context
            .apply_verified_reorg_suffix_with_applier(
                authority,
                &bodies,
                second_block.header.timestamp,
                |block, state| {
                    crate::materialize_accepted_block_state(state, block)
                        .map_err(|error| format!("{error:?}"))
                },
            )
            .unwrap();

        assert_eq!(verify_calls.get(), 1);
        assert_eq!(result.reverted_heights, vec![1]);
        assert_eq!(result.applied_heights, vec![1, 2]);
        assert_eq!(context.tip_height(), 2);
        assert_eq!(context.tip_hash(), second.block_hash());
        assert!(context
            .store
            .get_history_step_terminal_at(1, first.block_hash())
            .unwrap()
            .is_none());
        assert_eq!(
            context
                .store
                .get_history_step_terminal_at(2, second.block_hash())
                .unwrap()
                .as_deref(),
            Some(second.history_step_terminal_bytes())
        );

        drop(context);
        let reopened =
            MdbxChainContext::restore_from_mdbx(MdbxStore::open(directory.path()).unwrap())
                .unwrap();
        assert_eq!(reopened.tip_height(), 2);
        assert_eq!(reopened.tip_hash(), second.block_hash());
    }

    #[test]
    fn failed_one_terminal_reorg_preserves_old_durable_branch() {
        let producer_dir = tempfile::tempdir().unwrap();
        let mut producer = easy_block_context(producer_dir.path());
        let first = test_next_bundle_for_miner(&producer, 0x55);
        accept_test_bundle(&mut producer, &first);
        let second = test_next_bundle_for_miner(&producer, 0x55);
        accept_test_bundle(&mut producer, &second);

        let directory = tempfile::tempdir().unwrap();
        let mut context = easy_block_context(directory.path());
        let old = test_next_bundle_for_miner(&context, 0x44);
        accept_test_bundle(&mut context, &old);
        let old_tip = old.block_hash();
        let old_root = context.state.cached_state_root();

        let genesis = context.get_header_from_store(0).unwrap().unwrap();
        let second_block = Block::from_bytes(second.block_bytes()).unwrap();
        let authority = context
            .verify_reorg_suffix(
                0,
                second_block.header,
                genesis,
                second.history_step_terminal_bytes().to_vec(),
                |_| Ok(()),
            )
            .unwrap();
        let bodies = vec![first.block_bytes().to_vec(), second.block_bytes().to_vec()];
        let applied = std::cell::Cell::new(0usize);
        let result = context.apply_verified_reorg_suffix_with_applier_indexed(
            authority,
            &bodies,
            second_block.header.timestamp,
            |block, state| {
                let index = applied.get();
                applied.set(index + 1);
                if index == 1 {
                    return Err("deliberate replacement materialization failure".to_string());
                }
                crate::materialize_accepted_block_state(state, block)
                    .map_err(|error| format!("{error:?}"))
            },
        );

        let failure = result.expect_err("deliberate replacement failure must abort reorg");
        assert_eq!(failure.body_index, Some(1));
        assert_eq!(applied.get(), 2);
        assert_eq!(context.tip_height(), 1);
        assert_eq!(context.tip_hash(), old_tip);
        assert_eq!(context.state.cached_state_root(), old_root);
        assert_eq!(context.store.get_chain_tip().unwrap(), Some((1, old_tip)));
        assert!(context.store.get_recent_block(2).unwrap().is_none());
    }

    #[test]
    fn reorg_rebinds_surviving_compact_marker_to_the_new_branch() {
        let producer_a_dir = tempfile::tempdir().unwrap();
        let mut producer_a = easy_block_context(producer_a_dir.path());
        let first = test_next_bundle(&producer_a);
        accept_test_bundle(&mut producer_a, &first);
        let branch_a = test_next_bundle_for_miner(&producer_a, 0x44);

        let producer_b_dir = tempfile::tempdir().unwrap();
        let mut producer_b = easy_block_context(producer_b_dir.path());
        accept_test_bundle(&mut producer_b, &first);
        let branch_b = test_next_bundle_for_miner(&producer_b, 0x55);
        assert_ne!(branch_a.block_hash(), branch_b.block_hash());

        let directory = tempfile::tempdir().unwrap();
        let mut context = easy_block_context(directory.path());
        let branch_a_block = crate::Block::from_bytes(branch_a.block_bytes()).unwrap();
        let genesis = context.get_header_from_store(0).unwrap().unwrap();
        let mut authority = context
            .verify_recursive_suffix(
                branch_a_block.header,
                genesis,
                branch_a.history_step_terminal_bytes().to_vec(),
                |_| Ok(()),
            )
            .unwrap();
        for bundle in [&first, &branch_a] {
            let block = crate::Block::from_bytes(bundle.block_bytes()).unwrap();
            context
                .apply_verified_recursive_suffix_block(
                    &mut authority,
                    bundle.block_bytes(),
                    block.header.timestamp,
                    |block, state| {
                        crate::materialize_accepted_block_state(state, block)
                            .map_err(|error| format!("{error:?}"))
                    },
                )
                .unwrap();
        }

        let apply =
            |context: &mut MdbxChainContext, bundle: &crate::AcceptedBlockBundle, local_time| {
                context.apply_next_block(
                    bundle,
                    local_time,
                    |block, state| {
                        crate::materialize_accepted_block_state(state, block)
                            .map_err(|error| format!("{error:?}"))
                    },
                    |_| Ok(()),
                )?;
                Ok(())
            };

        let branch_b_block = crate::Block::from_bytes(branch_b.block_bytes()).unwrap();
        context
            .apply_reorg_mdbx_with_applier(
                1,
                std::slice::from_ref(&branch_b),
                branch_b_block.header.timestamp,
                apply,
            )
            .unwrap();
        assert_eq!(context.tip_hash(), branch_b.block_hash());

        // The first reorg removed branch A's authority terminal. A second
        // reorg from the same compact marker must use the marker rebound to
        // branch B, not fail with "parent authority is missing".
        context
            .apply_reorg_mdbx_with_applier(
                1,
                std::slice::from_ref(&branch_a),
                branch_a_block.header.timestamp,
                apply,
            )
            .unwrap();
        assert_eq!(context.tip_hash(), branch_a.block_hash());
    }

    #[test]
    fn consecutive_completed_recursive_suffixes_keep_older_markers_reorgable() {
        let blocks = block_sequence(4);
        let directory = tempfile::tempdir().unwrap();
        let mut context = easy_block_context(directory.path());
        let genesis = context.get_header_from_store(0).unwrap().unwrap();

        for range in [0..2, 2..4] {
            let final_bundle = &blocks[range.end - 1];
            let final_block = crate::Block::from_bytes(final_bundle.block_bytes()).unwrap();
            let mut authority = context
                .verify_recursive_suffix(
                    final_block.header,
                    genesis,
                    final_bundle.history_step_terminal_bytes().to_vec(),
                    |_| Ok(()),
                )
                .unwrap();
            for bundle in &blocks[range] {
                let block = crate::Block::from_bytes(bundle.block_bytes()).unwrap();
                context
                    .apply_verified_recursive_suffix_block(
                        &mut authority,
                        bundle.block_bytes(),
                        block.header.timestamp,
                        |block, state| {
                            crate::materialize_accepted_block_state(state, block)
                                .map_err(|error| format!("{error:?}"))
                        },
                    )
                    .unwrap();
            }
            assert!(authority.is_complete());
        }
        assert_eq!(context.tip_height(), 4);

        // Height 1 is a marker authorized by the first completed suffix. The
        // second suffix must not make that still-reorgable parent unusable.
        let replacement = &blocks[1];
        let replacement_block = crate::Block::from_bytes(replacement.block_bytes()).unwrap();
        let result = context.apply_reorg_mdbx_with_applier(
            1,
            std::slice::from_ref(replacement),
            replacement_block.header.timestamp,
            |context, bundle, local_time| {
                context.apply_next_block(
                    bundle,
                    local_time,
                    |block, state| {
                        crate::materialize_accepted_block_state(state, block)
                            .map_err(|error| format!("{error:?}"))
                    },
                    |_| Ok(()),
                )?;
                Ok(())
            },
        );

        assert!(
            result.is_ok(),
            "older compact-marker reorg failed: {result:?}"
        );
        assert_eq!(context.tip_height(), 2);
        assert_eq!(context.tip_hash(), replacement.block_hash());
    }

    #[test]
    fn interrupted_recursive_suffix_reopens_and_accepts_a_normal_successor() {
        let (first, second) = two_block_suffix();
        let directory = tempfile::tempdir().unwrap();
        {
            let mut context = easy_block_context(directory.path());
            let second_block = crate::Block::from_bytes(second.block_bytes()).unwrap();
            let genesis = context.get_header_from_store(0).unwrap().unwrap();
            let mut authority = context
                .verify_recursive_suffix(
                    second_block.header,
                    genesis,
                    second.history_step_terminal_bytes().to_vec(),
                    |_| Ok(()),
                )
                .unwrap();
            context
                .apply_verified_recursive_suffix_block(
                    &mut authority,
                    first.block_bytes(),
                    crate::Block::from_bytes(first.block_bytes())
                        .unwrap()
                        .header
                        .timestamp,
                    |block, state| {
                        crate::materialize_accepted_block_state(state, block)
                            .map_err(|error| format!("{error:?}"))
                    },
                )
                .unwrap();
            assert_eq!(context.tip_height(), 1);
            assert!(!authority.is_complete());
            assert!(
                context
                    .store
                    .durable_tip_has_verified_suffix_authority(
                        context.tip_header(),
                        context.tip_hash(),
                    )
                    .unwrap()
            );
        }

        let mut reopened =
            MdbxChainContext::restore_from_mdbx(MdbxStore::open(directory.path()).unwrap())
                .unwrap();
        assert_eq!(reopened.tip_height(), 1);
        assert_eq!(reopened.tip_hash(), first.block_hash());
        accept_test_bundle(&mut reopened, &second);
        assert_eq!(reopened.tip_height(), 2);
        assert!(!reopened
            .store
            .durable_tip_has_verified_suffix_authority(reopened.tip_header(), reopened.tip_hash(),)
            .unwrap());
    }

    #[test]
    fn interrupted_recursive_suffix_resumes_through_live_suffix_retry() {
        let (first, second) = two_block_suffix();
        let directory = tempfile::tempdir().unwrap();
        {
            let mut context = easy_block_context(directory.path());
            let second_block = crate::Block::from_bytes(second.block_bytes()).unwrap();
            let genesis = context.get_header_from_store(0).unwrap().unwrap();
            let mut authority = context
                .verify_recursive_suffix(
                    second_block.header,
                    genesis,
                    second.history_step_terminal_bytes().to_vec(),
                    |_| Ok(()),
                )
                .unwrap();
            context
                .apply_verified_recursive_suffix_block(
                    &mut authority,
                    first.block_bytes(),
                    crate::Block::from_bytes(first.block_bytes())
                        .unwrap()
                        .header
                        .timestamp,
                    |block, state| {
                        crate::materialize_accepted_block_state(state, block)
                            .map_err(|error| format!("{error:?}"))
                    },
                )
                .unwrap();
            assert_eq!(context.tip_height(), 1);
            assert!(!authority.is_complete());
        }

        {
            let mut reopened =
                MdbxChainContext::restore_from_mdbx(MdbxStore::open(directory.path()).unwrap())
                    .unwrap();
            let second_block = crate::Block::from_bytes(second.block_bytes()).unwrap();
            let genesis = reopened.get_header_from_store(0).unwrap().unwrap();
            let mut retry = reopened
                .verify_recursive_suffix(
                    second_block.header,
                    genesis,
                    second.history_step_terminal_bytes().to_vec(),
                    |_| Ok(()),
                )
                .unwrap();
            reopened
                .apply_verified_recursive_suffix_block(
                    &mut retry,
                    second.block_bytes(),
                    second_block.header.timestamp,
                    |block, state| {
                        crate::materialize_accepted_block_state(state, block)
                            .map_err(|error| format!("{error:?}"))
                    },
                )
                .unwrap();
            assert!(retry.is_complete());
            assert_eq!(reopened.tip_height(), 2);
            assert_eq!(reopened.tip_hash(), second.block_hash());
        }

        let reopened = MdbxChainContext::open_or_create(directory.path()).unwrap();
        assert_eq!(reopened.tip_height(), 2);
        assert_eq!(reopened.tip_hash(), second.block_hash());
    }

    #[test]
    fn interrupted_recursive_suffix_rejects_authority_rotation_without_poisoning_reopen() {
        let blocks = block_sequence(3);
        let first = &blocks[0];
        let second = &blocks[1];
        let third = &blocks[2];
        let directory = tempfile::tempdir().unwrap();
        {
            let mut context = easy_block_context(directory.path());
            let second_block = crate::Block::from_bytes(second.block_bytes()).unwrap();
            let genesis = context.get_header_from_store(0).unwrap().unwrap();
            let mut authority = context
                .verify_recursive_suffix(
                    second_block.header,
                    genesis,
                    second.history_step_terminal_bytes().to_vec(),
                    |_| Ok(()),
                )
                .unwrap();
            context
                .apply_verified_recursive_suffix_block(
                    &mut authority,
                    first.block_bytes(),
                    crate::Block::from_bytes(first.block_bytes())
                        .unwrap()
                        .header
                        .timestamp,
                    |block, state| {
                        crate::materialize_accepted_block_state(state, block)
                            .map_err(|error| format!("{error:?}"))
                    },
                )
                .unwrap();

            let third_block = crate::Block::from_bytes(third.block_bytes()).unwrap();
            let error = context
                .verify_recursive_suffix(
                    third_block.header,
                    genesis,
                    third.history_step_terminal_bytes().to_vec(),
                    |_| Ok(()),
                )
                .unwrap_err();
            assert!(matches!(
                error,
                MdbxContextError::Store(StoreError::Decode(
                    "recursive suffix retry target differs from marker authority"
                ))
            ));
            assert_eq!(context.tip_height(), 1);
        }

        let reopened = MdbxChainContext::open_or_create(directory.path()).unwrap();
        assert_eq!(reopened.tip_height(), 1);
        assert_eq!(reopened.tip_hash(), first.block_hash());
    }

    #[test]
    fn rejected_recursive_suffix_terminal_never_authorizes_or_mutates_bodies() {
        let (first, second) = two_block_suffix();
        let directory = tempfile::tempdir().unwrap();
        let mut context = easy_block_context(directory.path());
        let genesis = context.get_header_from_store(0).unwrap().unwrap();
        let second_block = crate::Block::from_bytes(second.block_bytes()).unwrap();
        let original_tip = context.tip_hash();
        let result = context.verify_recursive_suffix(
            second_block.header,
            genesis,
            second.history_step_terminal_bytes().to_vec(),
            |_| Err("deliberate recursive verifier rejection".to_string()),
        );
        assert!(result.is_err());
        assert_eq!(context.tip_height(), 0);
        assert_eq!(context.tip_hash(), original_tip);
        assert!(context.store.get_recent_block(1).unwrap().is_none());
        assert!(!context
            .store
            .durable_tip_has_verified_suffix_authority(context.tip_header(), original_tip)
            .unwrap());

        let mut authority = context
            .verify_recursive_suffix(
                second_block.header,
                genesis,
                second.history_step_terminal_bytes().to_vec(),
                |_| Ok(()),
            )
            .unwrap();
        let mut tampered_first = crate::Block::from_bytes(first.block_bytes()).unwrap();
        tampered_first.header.prev_block_hash = [0x55; 32];
        assert!(context
            .apply_verified_recursive_suffix_block(
                &mut authority,
                &tampered_first.to_bytes(),
                tampered_first.header.timestamp,
                |block, state| {
                    crate::materialize_accepted_block_state(state, block)
                        .map_err(|error| format!("{error:?}"))
                },
            )
            .is_err());
        assert_eq!(context.tip_height(), 0);
        assert_eq!(context.tip_hash(), original_tip);
        assert!(context.store.get_recent_block(1).unwrap().is_none());

        // A normal fully proved successor supersedes the unused authority.
        accept_test_bundle(&mut context, &first);
        assert_eq!(context.tip_height(), 1);
        assert!(!context
            .store
            .durable_tip_has_verified_suffix_authority(context.tip_header(), context.tip_hash())
            .unwrap());
    }

    #[test]
    fn local_fast_commit_rejects_impossible_pow_before_state_or_tip_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let mut context = small_context(directory.path());
        let parent_tip = context.tip_hash();
        let parent_root = context.state.cached_state_root();
        let claimed = unsafe_claimed_coinbase_with_impossible_pow(&context);
        let error = context
            .commit_locally_proved_next_block(claimed)
            .unwrap_err();
        assert!(matches!(
            error,
            MdbxContextError::Consensus(ConsensusError::InvalidPoW)
        ));
        assert_eq!(context.tip_height(), 0);
        assert_eq!(context.tip_hash(), parent_tip);
        assert_eq!(context.state.cached_state_root(), parent_root);
        assert_eq!(
            context.store.get_chain_tip().unwrap(),
            Some((0, parent_tip))
        );
        assert_eq!(
            context
                .store
                .get_recent_accepted_block_bundle_bounded(1)
                .unwrap(),
            None
        );
    }
}
