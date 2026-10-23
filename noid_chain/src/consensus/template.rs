// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block template construction for the mining pipeline .
//!
//! A `BlockTemplate` is a fully computed block ready for PoW search:
//! - Transaction set selected and conflict-resolved
//! - State applied to scratch copy → `state_root` known
//! - All semantic header fields computed except `nonce`
//!
//! The miner receives a semantic header with `nonce = 0` and searches for a
//! valid nonce under the fixed Poseidon2b PoW field schedule.
//! When found, the full node finalises the semantic header and attaches detached
//! proof/sidecar witness bytes for validation.
//!
//! # Why state_root is in the PoW input
//!
//! Including `state_root` in the PoW hash prevents external miners from changing
//! the coinbase address: a different coinbase → different post-state → different
//! `state_root` → different Poseidon2b PoW input → must redo PoW from scratch.
//! This is Paranoid's block-withholding protection.

use std::collections::{BTreeSet, HashSet};

use noid_poseidon2b::primitives::{Address, Digest};
use noid_tx::{PagedSpendFacts, Transaction};

use crate::accepted_block_bundle::AcceptedBlockBundle;
use crate::block::Block;
use crate::block_header::BlockHeader;
use crate::consensus::da_prune::{build_undo_log, BlockUndoLog};
use crate::consensus::pow::block_id;
use crate::state::{apply_tx_checked_deferred_root, ChainState};

mod native;

// ---------------------------------------------------------------------------
// BlockTemplate
// ---------------------------------------------------------------------------

/// A fully assembled block template ready for PoW search.
///
/// All semantic header fields except `nonce` are fixed.
/// The miner iterates nonces over the fixed Poseidon2b PoW field schedule.
#[derive(Debug, Clone)]
pub struct BlockTemplate {
    /// Coinbase transaction (always first in the block).
    pub coinbase: Transaction,
    /// Mandatory batched development payout, present only on scheduled heights.
    pub development_payout: Option<Transaction>,
    /// User PagedSpend pages in canonical order (system mints excluded here).
    pub txs: Vec<Transaction>,
    /// Post-apply state root (computed from applying all txs to prev state).
    pub state_root: Digest,
    /// Merkle root of all transactions: compute_tx_root(&[coinbase] + txs).
    pub tx_root: Digest,
    /// Post-apply active slot count.
    pub active_slot_count: u64,
    /// Post-apply alloc counter.
    pub alloc_counter: u64,
    /// Current log_slots depth.
    pub log_slots: u32,
    /// Block height (parent.height + 1).
    pub height: u64,
    /// Block timestamp (wall-clock seconds at template creation).
    pub timestamp: u64,
    /// Miner's payout address (embedded in coinbase).
    pub miner_address: Address,
    /// ASERT difficulty target for this block.
    pub difficulty_target: Digest,
    /// Hash of parent block header.
    pub prev_block_hash: Digest,
}

impl BlockTemplate {
    /// Consume the template into its exact block without cloning transactions.
    pub fn into_block(self, nonce: u128) -> crate::block::Block {
        let Self {
            coinbase,
            development_payout,
            txs,
            state_root,
            tx_root,
            active_slot_count,
            alloc_counter,
            log_slots,
            height,
            timestamp,
            miner_address,
            difficulty_target,
            prev_block_hash,
        } = self;
        let mut transactions =
            Vec::with_capacity(1 + usize::from(development_payout.is_some()) + txs.len());
        transactions.push(coinbase);
        transactions.extend(development_payout);
        transactions.extend(txs);
        crate::block::Block {
            header: BlockHeader {
                prev_block_hash,
                state_root,
                tx_root,
                timestamp,
                height,
                miner_address,
                nonce,
                difficulty_target,
                log_slots,
                active_slot_count,
                alloc_counter,
            },
            transactions,
        }
    }

    /// Build a semantic `BlockHeader` from this template with the given nonce.
    pub fn into_header(self, nonce: u128) -> BlockHeader {
        BlockHeader {
            prev_block_hash: self.prev_block_hash,
            state_root: self.state_root,
            tx_root: self.tx_root,
            timestamp: self.timestamp,
            height: self.height,
            miner_address: self.miner_address,
            nonce,
            difficulty_target: self.difficulty_target,
            log_slots: self.log_slots,
            active_slot_count: self.active_slot_count,
            alloc_counter: self.alloc_counter,
        }
    }

    /// Build a `BlockHeader` for PoW purposes with the supplied nonce.
    /// Use `pow_header_fields(hdr)` from pow.rs to get the fixed PoW input.
    pub fn to_pow_header(&self, nonce: u128) -> BlockHeader {
        BlockHeader {
            prev_block_hash: self.prev_block_hash,
            state_root: self.state_root,
            tx_root: self.tx_root,
            timestamp: self.timestamp,
            height: self.height,
            miner_address: self.miner_address,
            nonce,
            difficulty_target: self.difficulty_target,
            log_slots: self.log_slots,
            active_slot_count: self.active_slot_count,
            alloc_counter: self.alloc_counter,
        }
    }

    /// All bodies in block order: coinbase, optional payout, then user pages.
    pub fn all_txs(&self) -> Vec<Transaction> {
        let mut all = vec![self.coinbase.clone()];
        all.extend(self.development_payout.iter().cloned());
        all.extend(self.txs.iter().cloned());
        all
    }

    /// Total tx count (coinbase + non-coinbase).
    pub fn n_txs(&self) -> usize {
        1 + usize::from(self.development_payout.is_some()) + self.txs.len()
    }
}

/// Non-serializable state handoff minted together with one canonical
/// node-owned block template.
///
/// It owns the already-computed post-state and exact parent undo rather than
/// asking the commit path to replay the public transition.  Private fields and
/// the absence of `Clone` make this a one-shot phase capability.
#[must_use = "dropping the prepared state capability cancels its local fast commit"]
pub struct PreparedBlockStateCommit {
    parent_header: BlockHeader,
    nonce_free_header: BlockHeader,
    post_state: ChainState,
    undo_log: BlockUndoLog,
    native_openings: Vec<noid_tx::native_assets::NativeOpening>,
    trade_batches: Vec<noid_tx::native_assets::trade::batch::TradeBatch>,
}

/// One-shot commit authority after the node-owned HistoryStep prover has
/// produced the bundle for the exact prepared block.
///
/// Network and reorg acceptance never construct this type; they continue
/// through full terminal verification and state materialization.
#[must_use = "a locally proved block is not accepted until this capability is committed"]
pub struct LocallyProvedBlockCommit {
    parent_header: BlockHeader,
    block: Block,
    bundle: AcceptedBlockBundle,
    post_state: ChainState,
    undo_log: BlockUndoLog,
}

impl PreparedBlockStateCommit {
    pub fn native_openings(&self) -> &[noid_tx::native_assets::NativeOpening] {
        &self.native_openings
    }

    pub fn trade_batches(&self) -> &[noid_tx::native_assets::trade::batch::TradeBatch] {
        &self.trade_batches
    }

    /// Consume the prepared phase after trusted local HistoryStep proving and
    /// bind it to the exact sealed block and complete bundle without
    /// re-verifying that just-authored proof.
    ///
    /// # Safety
    ///
    /// `history_step_terminal_bytes` must be the canonical encoding returned
    /// by the pinned HistoryStep prover after full native consensus validation
    /// for this exact `block`. Violating this precondition can authorize the
    /// local fast-commit path to persist an unverified terminal. Inbound and
    /// reorg acceptance do not use this bridge and always verify the proof.
    pub unsafe fn seal_after_trusted_history_step_proof_unchecked(
        self,
        block: Block,
        history_step_terminal_bytes: Vec<u8>,
    ) -> Result<LocallyProvedBlockCommit, String> {
        let mut nonce_free_header = block.header;
        nonce_free_header.nonce = 0;
        if nonce_free_header != self.nonce_free_header {
            return Err("sealed block header differs from its prepared template".to_string());
        }
        let tx_hashes = crate::block::native_assets::validate_scheduled_block_page_stream(
            &block.transactions,
            block.header.height,
        )
        .map_err(|error| format!("sealed block has invalid page stream: {error}"))?
        .logical_txids(&block.transactions);
        if tx_hashes != self.undo_log.tx_hashes {
            return Err("sealed block body differs from its prepared template".to_string());
        }
        if self.post_state.cached_state_root() != block.header.state_root
            || self.post_state.state.log_slots() as u32 != block.header.log_slots
            || self.post_state.active_slot_count != block.header.active_slot_count
            || self.post_state.alloc_counter != block.header.alloc_counter
        {
            return Err("prepared post-state differs from the sealed block header".to_string());
        }
        if self.undo_log.block_height != block.header.height {
            return Err("prepared undo does not bind the sealed block height".to_string());
        }
        let bundle = AcceptedBlockBundle::try_from_locally_built_block_with_native_data(
            &block,
            history_step_terminal_bytes,
            self.native_openings,
            self.trade_batches,
        )
        .map_err(|error| error.to_string())?;

        Ok(LocallyProvedBlockCommit {
            parent_header: self.parent_header,
            block,
            bundle,
            post_state: self.post_state,
            undo_log: self.undo_log,
        })
    }
}

impl LocallyProvedBlockCommit {
    pub const fn block(&self) -> &Block {
        &self.block
    }

    pub const fn bundle(&self) -> &AcceptedBlockBundle {
        &self.bundle
    }

    pub(crate) const fn parent_header(&self) -> &BlockHeader {
        &self.parent_header
    }

    pub(crate) fn into_commit_parts(
        self,
    ) -> (Block, AcceptedBlockBundle, ChainState, BlockUndoLog) {
        (self.block, self.bundle, self.post_state, self.undo_log)
    }
}

// ---------------------------------------------------------------------------
// Template builder
// ---------------------------------------------------------------------------

/// Error returned by `build_block_template`.
#[derive(Debug, Clone)]
pub enum TemplateBuildError {
    /// No empty slot available for the coinbase output.
    NoCoinbaseSlot,
    /// State application failed for a transaction (conflict, out-of-range, etc.).
    StateApplyError(String),
}

#[derive(Clone, Default)]
struct TemplateResourceSelection {
    system_record_count: usize,
    system_output_count: usize,
    user_page_count: usize,
    logical_count: usize,
    live_input_count: usize,
    live_output_count: usize,
    touched_slots: HashSet<u32>,
    touched_segments: BTreeSet<u32>,
}

impl TemplateResourceSelection {
    fn with_system_outputs(system_record_count: usize, system_output_count: usize) -> Self {
        Self {
            system_record_count,
            system_output_count,
            ..Self::default()
        }
    }

    /// Return the next bounded selection, reserving possible new segments for
    /// every mandatory system output.
    fn with_group(&self, pages: &[Transaction], spend: &PagedSpendFacts) -> Option<Self> {
        let user_page_count = self.user_page_count.checked_add(pages.len())?;
        let logical_count = self.logical_count.checked_add(1)?;
        let live_input_count = self
            .live_input_count
            .checked_add(usize::from(spend.live_inputs))?;
        let live_output_count = self
            .live_output_count
            .checked_add(usize::from(spend.live_outputs))?;
        if user_page_count.checked_add(self.system_record_count)?
            > crate::consensus::params::BLOCK_MAX_USER_PAGES
            || logical_count > crate::consensus::params::BLOCK_MAX_USER_PAGES
            || live_input_count > crate::consensus::params::BLOCK_MAX_LIVE_INPUTS
            || live_output_count.checked_add(self.system_output_count)?
                > crate::consensus::params::BLOCK_MAX_USER_OUTPUTS + 1
            || live_input_count
                .checked_add(live_output_count)?
                .checked_add(self.system_output_count)?
                > crate::consensus::params::BLOCK_MAX_ACTIONS
        {
            return None;
        }

        let mut touched_slots = self.touched_slots.clone();
        let mut touched_segments = self.touched_segments.clone();
        for page in pages {
            for slot in page
                .body
                .live_inputs()
                .map(|(_, input)| input.slot_index)
                .chain(
                    page.body
                        .live_outputs()
                        .map(|(_, output)| output.slot_index),
                )
            {
                if !touched_slots.insert(slot) {
                    return None;
                }
                touched_segments.insert(slot >> crate::consensus::params::LOG_SEGMENT_SIZE);
            }
        }
        if touched_segments
            .len()
            .checked_add(self.system_output_count)?
            > crate::consensus::params::BLOCK_MAX_DISTINCT_SEGMENTS
        {
            return None;
        }

        Some(Self {
            system_record_count: self.system_record_count,
            system_output_count: self.system_output_count,
            user_page_count,
            logical_count,
            live_input_count,
            live_output_count,
            touched_slots,
            touched_segments,
        })
    }
}

#[derive(Debug)]
struct CandidatePagedSpend {
    pages: Vec<Transaction>,
    spend: PagedSpendFacts,
    native: Option<noid_tx::native_assets::wire::NativeSpendFacts>,
}

impl CandidatePagedSpend {
    fn apply(&self, state: &mut ChainState, height: u64) -> Result<(), TemplateBuildError> {
        if let Some(native) = &self.native {
            crate::state::native_assets::apply_checked_native_deferred_root(
                state,
                &native.context,
                &native.inputs,
                &native.outputs,
                native.transition.clone(),
            )
            .map_err(|error| TemplateBuildError::StateApplyError(error.to_string()))?;
        } else {
            for page in &self.pages {
                apply_tx_checked_deferred_root(state, &page.body, Some(height))
                    .map_err(|error| TemplateBuildError::StateApplyError(format!("{error:?}")))?;
            }
        }
        Ok(())
    }
}

/// Select one exact empty slot for the mandatory coinbase.
///
/// Loaded live segments are searched first so ordinary churn reuses holes and
/// does not grow durable state. If none has an available hole, the allocator's
/// duplicate-free segment probe skips full zones and opens one virtual-zero
/// segment. Evicted live segments remain fail-closed; the miner snapshot must
/// authenticate and hydrate one before calling the pure builder.
fn select_system_mint_slot(
    state: &ChainState,
    reuse_seed: u64,
    reserved: &HashSet<u32>,
) -> Option<u32> {
    if let Some(slot) = state
        .state
        .empty_slot_hints_in_populated_segments(reuse_seed, 1, reserved)
        .into_iter()
        .next()
    {
        return Some(slot);
    }

    let log_slots = state.state.log_slots() as u32;
    let effective_log = state.state.effective_log_segment_size();
    let segment_size = 1usize << effective_log;
    let local_mask = segment_size - 1;
    let segment_count = state.state.num_segments();
    let local_start = if log_slots <= 16 {
        crate::consensus::allocator::generate_slot_hints(state.alloc_counter, log_slots, 1)
            .first()
            .copied()
            .unwrap_or(0) as usize
    } else {
        (state.alloc_counter as usize) & local_mask
    };

    for segment_id in crate::consensus::allocator::generate_zone_segment_hints(
        state.alloc_counter,
        log_slots,
        segment_count,
    ) {
        // A non-zero evicted segment cannot be treated as empty. A resident
        // non-full segment would already have produced a reuse hint above.
        if state.state.segment_live_count(segment_id) != 0 || state.state.is_evicted(segment_id) {
            continue;
        }

        let base = (u32::from(segment_id)) << effective_log;
        // A virtual-zero segment needs only `reserved + 1` probes to prove one
        // unreserved slot exists; never scan or allocate all 65,536 columns.
        let probes = segment_size.min(reserved.len().saturating_add(1));
        for step in 0..probes {
            let slot = base | (((local_start + step) & local_mask) as u32);
            if !reserved.contains(&slot)
                && state.state.slot(slot) == crate::fri_state::SlotValue::EMPTY
            {
                return Some(slot);
            }
        }
    }
    None
}

/// Allocate bounded template outputs from authenticated resident holes and
/// virtual-zero segments without materializing unrelated State.
pub fn select_template_output_slots(
    state: &ChainState,
    reuse_seed: u64,
    count: usize,
    reserved: &HashSet<u32>,
) -> Option<Vec<u32>> {
    if count > noid_tx::MAX_PAGED_SPEND_OUTPUTS {
        return None;
    }
    let mut slots = state
        .state
        .empty_slot_hints_in_populated_segments(reuse_seed, count, reserved);
    let mut occupied = reserved.clone();
    occupied.extend(&slots);
    while slots.len() < count {
        let slot = select_system_mint_slot(
            state,
            reuse_seed.wrapping_add(slots.len() as u64),
            &occupied,
        )?;
        if !occupied.insert(slot) {
            return None;
        }
        slots.push(slot);
    }
    Some(slots)
}

/// A local preference, not a consensus reservation. Keep the legacy slot as
/// a fallback and inspect at most 64 neighbours in the same resident or
/// virtual-zero segment. Pending transactions cannot force another segment
/// load, expand the search, or prevent a mandatory mint.
const SYSTEM_MINT_PREFERENCE_PROBES: u32 = 64;

fn select_system_mint_slot_avoiding_outputs(
    state: &ChainState,
    reuse_seed: u64,
    reserved: &HashSet<u32>,
    pending_outputs: &HashSet<u32>,
) -> Option<u32> {
    let fallback = select_system_mint_slot(state, reuse_seed, reserved)?;
    if !pending_outputs.contains(&fallback) {
        return Some(fallback);
    }

    let local_mask = (1u32 << state.state.effective_log_segment_size()) - 1;
    let base = fallback & !local_mask;
    for step in 1..=SYSTEM_MINT_PREFERENCE_PROBES.min(local_mask) {
        let slot = base | (((fallback & local_mask) + step) & local_mask);
        if !reserved.contains(&slot)
            && !pending_outputs.contains(&slot)
            && state.state.slot(slot) == crate::fri_state::SlotValue::EMPTY
        {
            return Some(slot);
        }
    }
    Some(fallback)
}

/// Build a `BlockTemplate` from a set of candidate transactions.
///
/// Steps:
/// 1. Conflict-resolve candidate txs, then enforce full touched-slot
///    disjointness during bounded selection.
/// 2. Apply all txs to a scratch copy of `state`.
/// 3. Compute coinbase: slot from `alloc_counter + 1`, value = block_reward + fees.
/// 4. Apply coinbase to scratch state.
/// 5. Compute `state_root`, `tx_root`, `active_slot_count`, `alloc_counter`.
/// 6. Return the fully populated `BlockTemplate`.
///
/// `state` is NOT modified — all changes happen on a scratch copy.
///
/// `candidate_txs` must be pre-validated (not yet conflict-resolved).
/// Coinbase is constructed internally using `miner_address`.
///
/// A miner may search PoW over this template, but the resulting block is not
/// admissible until its exact current-height terminal has also been produced.
pub fn build_block_template(
    parent: &BlockHeader,
    state: &ChainState,
    finalized_active_counts: &[u64],
    candidate_txs: Vec<Transaction>,
    miner_address: Address,
    timestamp: u64,
    difficulty_target: Digest,
) -> Result<BlockTemplate, TemplateBuildError> {
    build_block_template_with_post_state(
        parent,
        state,
        finalized_active_counts,
        candidate_txs,
        miner_address,
        timestamp,
        difficulty_target,
        &HashSet::new(),
        &[],
        &[],
    )
    .map(|(template, _)| template)
}

/// Build the canonical node-owned template together with its one-shot local
/// state-commit capability.
///
/// The returned post-state is the same scratch state used to derive the
/// header, not a second replay.  Only the local miner/RPC template pipeline
/// carries this value; inbound blocks cannot select this commit path.
pub fn build_node_owned_block_template(
    parent: &BlockHeader,
    state: &ChainState,
    finalized_active_counts: &[u64],
    candidate_txs: Vec<Transaction>,
    miner_address: Address,
    timestamp: u64,
    difficulty_target: Digest,
) -> Result<(BlockTemplate, PreparedBlockStateCommit), TemplateBuildError> {
    build_node_owned_block_template_avoiding_outputs(
        parent,
        state,
        finalized_active_counts,
        candidate_txs,
        miner_address,
        timestamp,
        difficulty_target,
        &HashSet::new(),
    )
}

/// Build once, with a best-effort preference against minting into outputs of
/// other locally pending transactions. Selected transactions retain their
/// hard slot exclusions. Neither validation nor the proof relation consumes
/// this local snapshot, which may become stale while the template is mined.
#[allow(clippy::too_many_arguments)]
pub fn build_node_owned_block_template_avoiding_outputs(
    parent: &BlockHeader,
    state: &ChainState,
    finalized_active_counts: &[u64],
    candidate_txs: Vec<Transaction>,
    miner_address: Address,
    timestamp: u64,
    difficulty_target: Digest,
    pending_outputs: &HashSet<u32>,
) -> Result<(BlockTemplate, PreparedBlockStateCommit), TemplateBuildError> {
    build_node_owned_block_template_with_native_openings(
        parent,
        state,
        finalized_active_counts,
        candidate_txs,
        miner_address,
        timestamp,
        difficulty_target,
        pending_outputs,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_node_owned_block_template_with_native_openings(
    parent: &BlockHeader,
    state: &ChainState,
    finalized_active_counts: &[u64],
    candidate_txs: Vec<Transaction>,
    miner_address: Address,
    timestamp: u64,
    difficulty_target: Digest,
    pending_outputs: &HashSet<u32>,
    native_openings: &[noid_tx::native_assets::NativeOpening],
) -> Result<(BlockTemplate, PreparedBlockStateCommit), TemplateBuildError> {
    build_node_owned_block_template_with_native_data(
        parent,
        state,
        finalized_active_counts,
        candidate_txs,
        miner_address,
        timestamp,
        difficulty_target,
        pending_outputs,
        native_openings,
        &[],
    )
}

/// Carry exact trade policies and native dependencies through selection,
/// State preparation and the locally proved block handoff.
#[allow(clippy::too_many_arguments)]
pub fn build_node_owned_block_template_with_native_data(
    parent: &BlockHeader,
    state: &ChainState,
    finalized_active_counts: &[u64],
    candidate_txs: Vec<Transaction>,
    miner_address: Address,
    timestamp: u64,
    difficulty_target: Digest,
    pending_outputs: &HashSet<u32>,
    native_openings: &[noid_tx::native_assets::NativeOpening],
    trade_batches: &[noid_tx::native_assets::trade::batch::TradeBatch],
) -> Result<(BlockTemplate, PreparedBlockStateCommit), TemplateBuildError> {
    let (template, post_state) = build_block_template_with_post_state(
        parent,
        state,
        finalized_active_counts,
        candidate_txs,
        miner_address,
        timestamp,
        difficulty_target,
        pending_outputs,
        native_openings,
        trade_batches,
    )?;
    let nonce_free_block = template.clone().into_block(0);
    let undo_log = build_undo_log(state, &nonce_free_block).map_err(|error| {
        TemplateBuildError::StateApplyError(format!("canonical PagedSpend undo log: {error}"))
    })?;
    let (native_openings, trade_batches) =
        native::selected_data(&nonce_free_block, native_openings, trade_batches)?;
    let prepared = PreparedBlockStateCommit {
        parent_header: *parent,
        nonce_free_header: nonce_free_block.header,
        post_state,
        undo_log,
        native_openings,
        trade_batches,
    };
    Ok((template, prepared))
}

#[allow(clippy::too_many_arguments)]
fn build_block_template_with_post_state(
    parent: &BlockHeader,
    state: &ChainState,
    finalized_active_counts: &[u64],
    candidate_txs: Vec<Transaction>,
    miner_address: Address,
    timestamp: u64,
    difficulty_target: Digest,
    pending_outputs: &HashSet<u32>,
    native_openings: &[noid_tx::native_assets::NativeOpening],
    trade_batches: &[noid_tx::native_assets::trade::batch::TradeBatch],
) -> Result<(BlockTemplate, ChainState), TemplateBuildError> {
    use crate::consensus::development_allocation::{
        development_allocation_at_height, O1_NETWORK_FUND_ADDRESS, PARANO1D_LAB_ADDRESS,
    };
    use crate::consensus::expected_child_log_slots;
    use crate::consensus::fees::fee_breakdown;
    use noid_tx::{TxBody, TxInput, TxOutput, TX_INPUTS};

    let child_height = parent.height.checked_add(1).ok_or_else(|| {
        TemplateBuildError::StateApplyError("parent height exhausted".to_string())
    })?;
    let new_log_slots =
        expected_child_log_slots(parent.height, parent.log_slots, finalized_active_counts);

    // 1. Parse complete groups once, then sort the indivisible candidates by
    // fee and logical txid. Physical pages are never independently reordered.
    let mut payloads = std::collections::BTreeMap::new();
    if native_openings.len() > crate::consensus::params::BLOCK_MAX_ACTIONS {
        return Err(TemplateBuildError::StateApplyError(
            "native opening resource limit".into(),
        ));
    }
    for opening in native_openings {
        opening
            .validate()
            .map_err(|error| TemplateBuildError::StateApplyError(error.to_string()))?;
        if payloads
            .insert(opening.root().0, *opening)
            .is_some_and(|old| old != *opening)
        {
            return Err(TemplateBuildError::StateApplyError(
                "conflicting native openings".into(),
            ));
        }
    }
    let native_flags = noid_tx::native_assets::wire::NATIVE_PAGE_BIT
        | noid_tx::native_assets::wire::NATIVE_HEADER_BIT;
    let groups = if candidate_txs
        .iter()
        .any(|tx| tx.body.validity_bitmap & native_flags != 0)
    {
        crate::block::native_assets::validate_user_page_stream_at(&candidate_txs, child_height)
            .map_err(|error| TemplateBuildError::StateApplyError(error.to_string()))?
            .groups
    } else {
        crate::consensus::paged_spend::validate_paged_spend_transaction_stream(&candidate_txs)
            .map_err(|error| TemplateBuildError::StateApplyError(error.to_string()))?
            .groups
            .into_iter()
            .map(|group| crate::block::native_assets::BlockSpendGroup {
                body_start: usize::from(group.start_page),
                page_count: usize::from(group.page_count),
                kind: crate::block::native_assets::BlockSpendKind::Ordinary(group.spend),
            })
            .collect()
    };
    let batches = native::candidate_batches(&groups, trade_batches)?;
    let mut source = candidate_txs.into_iter();
    let mut candidates = Vec::with_capacity(groups.len());
    for group in groups {
        let pages: Vec<_> = source.by_ref().take(group.page_count).collect();
        debug_assert_eq!(pages.len(), group.page_count);
        let (spend, native) = match group.kind {
            crate::block::native_assets::BlockSpendKind::Ordinary(spend) => (spend, None),
            crate::block::native_assets::BlockSpendKind::Native(_) => {
                let intent = noid_tx::native_assets::wire::NativeIntent::from_pages_with_openings(
                    pages
                        .iter()
                        .map(|tx| noid_tx::TxPage {
                            body: tx.body.clone(),
                        })
                        .collect(),
                    |root| payloads.get(&root.0).copied(),
                )
                .map_err(|error| TemplateBuildError::StateApplyError(error.to_string()))?;
                let native =
                    native::checked_candidate(parent, state, new_log_slots, &intent, &batches)?;
                let spend = intent
                    .resource_facts()
                    .map_err(|error| TemplateBuildError::StateApplyError(error.to_string()))?;
                (spend, Some(native))
            }
        };
        candidates.push(CandidatePagedSpend {
            pages,
            spend,
            native,
        });
    }
    debug_assert!(source.next().is_none());
    candidates.sort_by(|left, right| {
        let contract = |group: &CandidatePagedSpend| {
            super::params::v2_active(child_height)
                && group.pages[0].body.validity_bitmap & noid_tx::PAGED_SPEND_CONTRACT_BIT != 0
        };
        // The v2 relation uses a prefix of contract calls. Order complete
        // groups before State application so proofs, roots and creation IDs
        // all refer to the same physical stream. Legacy ordering is unchanged.
        contract(right).cmp(&contract(left)).then_with(|| {
            right
                .spend
                .fee
                .cmp(&left.spend.fee)
                .then_with(|| left.spend.logical_txid.0.cmp(&right.spend.logical_txid.0))
        })
    });

    // 2. Determine expansion from the strict-majority hard-finalized window.
    //    Must match validate_block_consensus exactly so the block we produce
    //    passes consensus validation.
    let should_expand = new_log_slots != parent.log_slots;
    let allocation =
        development_allocation_at_height(child_height, new_log_slots).map_err(|error| {
            TemplateBuildError::StateApplyError(format!("development allocation: {error}"))
        })?;
    let system_record_count = usize::from(allocation.payout_due);
    let system_output_count = 1 + 2 * system_record_count;

    // 3. Apply non-coinbase txs to scratch state.
    // PagedSpend authorization binds (logical_txid, owner), not the state
    // depth.  Expansion therefore keeps valid parent-mempool work: the miner
    // builds its exact-state frontier directly against the expanded domain.
    let mut selection_scratch = state.clone();
    if should_expand {
        selection_scratch.expand_one();
    }
    // Selection executes users before their fee-dependent coinbase is known.
    // Reserve every system mint's canonical creation IDs so user outputs get
    // exactly the same IDs here as in the final system -> users replay.
    selection_scratch.alloc_counter = selection_scratch
        .alloc_counter
        .checked_add(system_output_count as u64)
        .ok_or_else(|| {
            TemplateBuildError::StateApplyError(
                "alloc_counter exhausted while reserving system mint creation IDs".into(),
            )
        })?;

    let mut applied_winners: Vec<CandidatePagedSpend> = Vec::new();
    // Reserve one segment for coinbase. Typical templates place coinbase in
    // an already-populated segment, but this conservative reservation makes
    // the final 256-segment consensus bound unconditional.
    let mut resources =
        TemplateResourceSelection::with_system_outputs(system_record_count, system_output_count);
    for group in candidates {
        let Some(next_resources) = resources.with_group(&group.pages, &group.spend) else {
            continue;
        };
        let required = fee_breakdown(
            u64::from(group.spend.live_inputs),
            u64::from(group.spend.live_outputs),
            parent.active_slot_count,
            parent.log_slots,
        )
        .required_total;
        let actual = group.spend.fee;
        if actual < required {
            continue;
        }
        group.apply(&mut selection_scratch, child_height)?;
        resources = next_resources;
        applied_winners.push(group);
    }
    let ordered_winners = applied_winners;

    // Selection and final replay need the same logical parent state, but never
    // at the same time.  Release the first dense scratch image before cloning
    // the final replay state; otherwise a maximal state keeps two additional
    // resident state images alive across the rest of template construction.
    drop(selection_scratch);

    // Rebuild the final scratch state in semantic block order. Selection runs
    // users first because coinbase value depends on the selected fee set, but
    // the actual block and exact action stream are system mints -> users.
    let mut scratch = state.clone();
    if should_expand {
        scratch.expand_one();
    }

    // 4. Build coinbase transaction.
    // Find an empty slot for coinbase output using the allocator.
    // Use the scratch state's actual capacity so hints are always in range.
    let (coinbase_slot, development_slots) = {
        let mut reserved: HashSet<u32> = ordered_winners
            .iter()
            .flat_map(|group| {
                group.pages.iter().flat_map(|page| {
                    page.body
                        .live_inputs()
                        .map(|(_, input)| input.slot_index)
                        .chain(
                            page.body
                                .live_outputs()
                                .map(|(_, output)| output.slot_index),
                        )
                })
            })
            .collect();
        let seed =
            scratch.alloc_counter ^ u64::from_le_bytes(parent.state_root[..8].try_into().unwrap());

        let coinbase =
            select_system_mint_slot_avoiding_outputs(&scratch, seed, &reserved, pending_outputs)
                .ok_or(TemplateBuildError::NoCoinbaseSlot)?;
        reserved.insert(coinbase);
        let development = if allocation.payout_due {
            let first = select_system_mint_slot_avoiding_outputs(
                &scratch,
                seed,
                &reserved,
                pending_outputs,
            )
            .ok_or(TemplateBuildError::NoCoinbaseSlot)?;
            reserved.insert(first);
            let second = select_system_mint_slot_avoiding_outputs(
                &scratch,
                seed,
                &reserved,
                pending_outputs,
            )
            .ok_or(TemplateBuildError::NoCoinbaseSlot)?;
            Some([first, second])
        } else {
            None
        };
        (coinbase, development)
    };

    // Sum only claimable fees. The deterministic state-growth component is burned.
    let claimable_fee_sum: u128 = ordered_winners
        .iter()
        .map(|group| {
            let burned = fee_breakdown(
                u64::from(group.spend.live_inputs),
                u64::from(group.spend.live_outputs),
                parent.active_slot_count,
                parent.log_slots,
            )
            .burned;
            u128::from(group.spend.fee.saturating_sub(burned))
        })
        .sum();
    // The mathematical ceiling may exceed the body amount lane. Claiming less
    // is canonical, so the miner selects the largest representable amount.
    let coinbase_value =
        (u128::from(allocation.miner_subsidy) + claimable_fee_sum).min(u128::from(u64::MAX)) as u64;

    let prev_block_hash = block_id(parent);
    let cb_body = TxBody {
        epoch_anchor: prev_block_hash,
        fee: 0,
        input_owner: Address([0u8; 32]),
        inputs: [TxInput::dummy(); TX_INPUTS],
        outputs: [
            TxOutput {
                slot_index: coinbase_slot,
                amount: coinbase_value,
                owner: miner_address,
            },
            TxOutput::dummy(),
        ],
        validity_bitmap: 1 << TX_INPUTS,
        is_coinbase: true,
    };
    let coinbase = Transaction::new(cb_body);
    let development_payout = allocation.payout_each.map(|amount| {
        let [network_slot, lab_slot] =
            development_slots.expect("scheduled payout has two selected slots");
        Transaction::new(TxBody {
            epoch_anchor: prev_block_hash,
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: [
                TxOutput {
                    slot_index: network_slot,
                    amount,
                    owner: O1_NETWORK_FUND_ADDRESS,
                },
                TxOutput {
                    slot_index: lab_slot,
                    amount,
                    owner: PARANO1D_LAB_ADDRESS,
                },
            ],
            validity_bitmap: noid_tx::output_bitmap_bit(0) | noid_tx::output_bitmap_bit(1),
            is_coinbase: true,
        })
    });

    // Apply the complete block to scratch in its real semantic order.
    apply_tx_checked_deferred_root(&mut scratch, &coinbase.body, Some(child_height))
        .map_err(|e| TemplateBuildError::StateApplyError(format!("{:?}", e)))?;
    if let Some(payout) = &development_payout {
        apply_tx_checked_deferred_root(&mut scratch, &payout.body, Some(child_height))
            .map_err(|e| TemplateBuildError::StateApplyError(format!("{:?}", e)))?;
    }
    for group in &ordered_winners {
        group.apply(&mut scratch, child_height)?;
    }

    // 5. Compute final header fields.
    let state_root = scratch
        .try_state_root()
        .map_err(|e| TemplateBuildError::StateApplyError(format!("{e:?}")))?;
    let tx_hashes_for_root: Vec<[u8; 32]> = std::iter::once(coinbase.txid().0)
        .chain(development_payout.iter().map(|payout| payout.txid().0))
        .chain(
            ordered_winners
                .iter()
                .map(|group| group.spend.logical_txid.0),
        )
        .collect();
    let tx_root = crate::tx_tree::root_from_hashes(&tx_hashes_for_root);

    let ordered_pages = ordered_winners
        .into_iter()
        .flat_map(|group| group.pages)
        .collect();

    let template = BlockTemplate {
        coinbase,
        development_payout,
        txs: ordered_pages,
        state_root,
        tx_root,
        active_slot_count: scratch.active_slot_count,
        alloc_counter: scratch.alloc_counter,
        log_slots: new_log_slots,
        height: child_height,
        timestamp,
        miner_address,
        difficulty_target,
        prev_block_hash,
    };
    Ok((template, scratch))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::fees::required_fee_for_tx_body;
    use crate::history_step::HistoryStepTerminalMetadata;
    use noid_tx::{
        output_bitmap_bit, TxBody, TxInput, TxOutput, PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT,
        TX_INPUTS, TX_OUTPUTS,
    };

    const DAY_BLOCKS: u64 = if crate::consensus::params::ISOLATED_V2_FORK_TESTNET {
        2880
    } else {
        4320
    };
    const FIRST_PAYOUT_HEIGHT: u64 = if crate::consensus::params::ISOLATED_V2_FORK_TESTNET {
        10 + DAY_BLOCKS - 1
    } else {
        DAY_BLOCKS
    };

    fn parent(state: &mut ChainState) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: state.state_root(),
            tx_root: [0u8; 32],
            timestamp: 0,
            height: 0,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: [0xff; 32],
            log_slots: state.state.log_slots() as u32,
            active_slot_count: state.active_slot_count,
            alloc_counter: state.alloc_counter,
        }
    }

    fn user(
        input_slot: u32,
        output_slot: u32,
        amount: u64,
        owner: Address,
        parent: &BlockHeader,
    ) -> Transaction {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: input_slot,
            amount,
            creation_id: 1,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: output_slot,
            amount,
            owner,
        };
        let mut body = TxBody {
            epoch_anchor: block_id(parent),
            fee: 0,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0) | PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        };
        body.fee = required_fee_for_tx_body(&body, parent.active_slot_count, parent.log_slots);
        body.outputs[0].amount -= body.fee;
        Transaction::new(body)
    }

    #[test]
    fn contract_prefix_is_height_selected_before_state_and_creation_ids() {
        use crate::fri_state::SlotValue;
        let Some(fork) = super::super::params::V2_ACTIVATION_HEIGHT else {
            return;
        };
        // Include the backwards crossing and a system-record block. This is
        // an ordering/state test; authorization is checked by the producer.
        for height in [fork - 1, fork, fork + 1, fork - 1, fork + 2879] {
            let owner = Address([4; 32]);
            let mut state = ChainState::with_log_slots(8);
            for slot in 1..=3 {
                state
                    .state
                    .set_slot(
                        slot,
                        SlotValue::with_owner_fields(1_000_000, 1, owner.as_fields()),
                    )
                    .unwrap();
            }
            state.active_slot_count = 3;
            state.alloc_counter = 3;
            state.circulating_supply_micronoid = 3_000_000;
            let mut parent = parent(&mut state);
            parent.height = height - 1;
            let mut pages = Vec::new();
            for (input, output, extra_fee, contract) in [
                (1, 11, 3_000, false),
                (2, 12, 1_000, true),
                (3, 13, 2_000, true),
            ] {
                let mut tx = user(input, output, 1_000_000, owner, &parent);
                tx.body.fee += extra_fee;
                tx.body.outputs[0].amount -= extra_fee;
                if contract {
                    tx.body.validity_bitmap |= noid_tx::PAGED_SPEND_CONTRACT_BIT;
                }
                pages.push(tx);
            }
            let (template, prepared) = build_node_owned_block_template(
                &parent,
                &state,
                &[3; 18],
                pages,
                Address([9; 32]),
                1,
                [0xff; 32],
            )
            .unwrap();
            let outputs: Vec<_> = template
                .txs
                .iter()
                .map(|tx| tx.body.outputs[0].slot_index)
                .collect();
            assert_eq!(
                outputs,
                if height < fork {
                    vec![11, 13, 12]
                } else {
                    vec![13, 12, 11]
                }
            );
            let system_outputs = if template.development_payout.is_some() {
                3
            } else {
                1
            };
            for (index, slot) in outputs.into_iter().enumerate() {
                assert_eq!(
                    prepared.post_state.state.slot(slot).creation_id(),
                    state.alloc_counter + system_outputs + index as u64 + 1
                );
            }
            let block = template.into_block(0);
            let root = crate::materialize_accepted_block_state(&mut state, &block).unwrap();
            assert_eq!(root, block.header.state_root);
            assert_eq!(state.alloc_counter, prepared.post_state.alloc_counter);
            assert_eq!(
                state.active_slot_count,
                prepared.post_state.active_slot_count
            );
            assert_eq!(
                crate::block::compute_tx_root(&block.transactions),
                block.header.tx_root
            );
        }
    }

    #[test]
    fn template_coinbase_is_exact_and_root_uses_shared_helper() {
        let mut state = ChainState::with_log_slots(8);
        let parent = parent(&mut state);
        let template = build_block_template(
            &parent,
            &state,
            &[0],
            vec![],
            Address([9u8; 32]),
            1,
            [0xff; 32],
        )
        .unwrap();
        assert!(template.coinbase.body.is_coinbase);
        assert_eq!(template.height, 1);
        assert_eq!(template.coinbase.body.validity_bitmap, output_bitmap_bit(0));
        assert_eq!(template.coinbase.body.input_owner, Address([0u8; 32]));
        assert_eq!(
            template.tx_root,
            crate::block::compute_tx_root(&template.all_txs())
        );
    }

    #[test]
    fn due_template_builds_the_mandatory_two_recipient_payout() {
        use crate::consensus::development_allocation::{
            development_share_each, miner_subsidy_at_height, O1_NETWORK_FUND_ADDRESS,
            PARANO1D_LAB_ADDRESS,
        };
        use crate::consensus::emission::block_reward_at_height;

        let mut state = ChainState::with_log_slots(8);
        let mut parent = parent(&mut state);
        parent.height = FIRST_PAYOUT_HEIGHT - 1;
        let share = development_share_each(block_reward_at_height(
            FIRST_PAYOUT_HEIGHT,
            parent.log_slots,
        ))
        .unwrap();

        let template = build_block_template(
            &parent,
            &state,
            &[0; 18],
            vec![],
            Address([9u8; 32]),
            1,
            [0xff; 32],
        )
        .unwrap();
        let payout = template
            .development_payout
            .as_ref()
            .expect("daily payout is mandatory");
        assert_eq!(payout.body.outputs[0].owner, O1_NETWORK_FUND_ADDRESS);
        assert_eq!(payout.body.outputs[1].owner, PARANO1D_LAB_ADDRESS);
        assert_eq!(payout.body.outputs[0].amount, share * DAY_BLOCKS);
        assert_eq!(payout.body.outputs[1].amount, share * DAY_BLOCKS);
        assert_eq!(
            template.coinbase.body.outputs[0].amount,
            miner_subsidy_at_height(FIRST_PAYOUT_HEIGHT, template.log_slots)
        );
        assert_eq!(template.active_slot_count, 3);
        assert_eq!(template.alloc_counter, 3);

        let block = template.into_block(0);
        assert_eq!(
            crate::consensus::validation::validate_mandatory_coinbase(&block, &parent),
            Ok(())
        );
        assert_eq!(
            block.header.tx_root,
            crate::block::compute_tx_root(&block.transactions)
        );
    }

    #[test]
    fn scheduled_payout_and_state_expansion_use_the_child_reward_tier() {
        use crate::consensus::development_allocation::{
            development_share_each, miner_subsidy_at_height,
        };
        use crate::consensus::emission::block_reward_at_height;

        // The system mint anchors directly to the selected parent; its share
        // uses the newly expanded child depth in both activation profiles.
        let mut state = ChainState::with_log_slots(24);
        let mut parent = parent(&mut state);
        parent.height = FIRST_PAYOUT_HEIGHT - 1;
        let new_share =
            development_share_each(block_reward_at_height(FIRST_PAYOUT_HEIGHT, 25)).unwrap();
        let expansion_threshold = (1u64 << 24) * 3 / 4;

        let template = build_block_template(
            &parent,
            &state,
            &[expansion_threshold; 18],
            vec![],
            Address([9u8; 32]),
            1,
            [0xff; 32],
        )
        .unwrap();

        assert_eq!(template.log_slots, 25);
        assert_eq!(
            template.coinbase.body.outputs[0].amount,
            miner_subsidy_at_height(FIRST_PAYOUT_HEIGHT, 25)
        );
        let payout = template
            .development_payout
            .as_ref()
            .expect("payout remains mandatory on an expansion block");
        let expected_each = new_share * DAY_BLOCKS;
        assert_eq!(payout.body.outputs[0].amount, expected_each);
        assert_eq!(payout.body.outputs[1].amount, expected_each);
        assert_eq!(payout.body.epoch_anchor, block_id(&parent));

        let block = template.into_block(0);
        assert_eq!(
            crate::consensus::validation::validate_mandatory_coinbase(&block, &parent),
            Ok(())
        );
    }

    #[test]
    fn payout_and_user_keep_distinct_anchors() {
        use crate::consensus::validate_block_epoch_anchors;
        use crate::fri_state::SlotValue;

        let owner = Address([4u8; 32]);
        let mut state = ChainState::with_log_slots(8);
        state
            .state
            .set_slot(
                7,
                SlotValue::with_owner_fields(1_000_000, 1, owner.as_fields()),
            )
            .unwrap();
        state.active_slot_count = 1;
        state.alloc_counter = 1;
        state.circulating_supply_micronoid = 1_000_000;
        let mut parent = parent(&mut state);
        parent.height = FIRST_PAYOUT_HEIGHT - 1;

        // The mainnet fixture also coincides with a transaction-epoch boundary.
        // Both system mints always bind the immediate parent, independently
        // of the profile's alignment with the user transaction epoch.
        let user_epoch_anchor = [0x44u8; 32];
        let mut candidate = user(7, 8, 1_000_000, owner, &parent);
        candidate.body.epoch_anchor = user_epoch_anchor;
        let template = build_block_template(
            &parent,
            &state,
            &[1; 18],
            vec![candidate],
            Address([9u8; 32]),
            2,
            [0xff; 32],
        )
        .unwrap();
        let block = template.into_block(0);
        let parent_id = block_id(&parent);

        assert_eq!(block.transactions.len(), 3);
        assert_eq!(block.transactions[0].body.epoch_anchor, parent_id);
        assert_eq!(block.transactions[1].body.epoch_anchor, parent_id);
        assert_eq!(block.transactions[2].body.epoch_anchor, user_epoch_anchor);
        assert_eq!(
            validate_block_epoch_anchors(&block, user_epoch_anchor, parent_id),
            Ok(())
        );
    }

    #[test]
    fn coinbase_segment_probe_escapes_a_full_current_zone() {
        use crate::consensus::allocator::generate_zone_segment_hints;

        let mut state = ChainState::with_log_slots(17);
        let primary = generate_zone_segment_hints(0, 17, 2)[0];
        state
            .state
            .install_evicted_exact_summary(primary, 1u32 << 16)
            .unwrap();
        state.state.finish_evicted_exact_summaries();
        state.active_slot_count = 1u64 << 16;

        let slot = select_system_mint_slot(&state, 7, &HashSet::new())
            .expect("the other production-size segment is virtual zero");
        assert_ne!((slot >> 16) as u16, primary);
        assert_eq!(state.state.slot(slot), crate::fri_state::SlotValue::EMPTY);
    }

    #[test]
    fn mint_preference_preserves_legacy_choice_without_a_collision() {
        for log_slots in [4, 8, 17, 32] {
            let state = ChainState::with_log_slots(log_slots);
            let hard = HashSet::from([0, 1, 2]);
            for seed in [0, 7, u64::MAX] {
                let legacy = select_system_mint_slot(&state, seed, &hard).unwrap();
                for soft in [HashSet::new(), HashSet::from([legacy ^ 1])] {
                    assert_eq!(
                        select_system_mint_slot_avoiding_outputs(&state, seed, &hard, &soft),
                        Some(legacy)
                    );
                }
                assert_eq!(state.state.materialized_segment_ids().count(), 0);
            }
        }
    }

    #[test]
    fn mint_preference_skips_hard_soft_and_occupied_neighbours() {
        use crate::fri_state::SlotValue;

        let mut state = ChainState::with_log_slots(17);
        let value = SlotValue::with_owner_fields(100_000, 1, Address([4; 32]).as_fields());
        state.state.set_slot(7, value).unwrap();
        let legacy = select_system_mint_slot(&state, 7, &HashSet::new()).unwrap();
        let base = legacy & !0xffff;
        let neighbour = |step| base | ((legacy + step) & 0xffff);
        state.state.set_slot(neighbour(3), value).unwrap();
        let hard = HashSet::from([neighbour(1)]);
        let soft = HashSet::from([legacy, neighbour(2)]);
        assert_eq!(select_system_mint_slot(&state, 7, &hard), Some(legacy));
        assert_eq!(
            select_system_mint_slot_avoiding_outputs(&state, 7, &hard, &soft),
            Some(neighbour(4))
        );
        assert_eq!(state.state.materialized_segment_ids().count(), 1);
    }

    #[test]
    fn mint_preference_stops_at_the_probe_budget_and_never_relaxes_hard_exclusions() {
        let state = ChainState::with_log_slots(17);
        let hard = HashSet::from([0, 1, 2]);
        let legacy = select_system_mint_slot(&state, 0, &hard).unwrap();
        let base = legacy & !0xffff;
        for last in [
            SYSTEM_MINT_PREFERENCE_PROBES - 1,
            SYSTEM_MINT_PREFERENCE_PROBES,
        ] {
            let soft = (0..=last)
                .map(|step| base | ((legacy + step) & 0xffff))
                .collect();
            let expected = if last < SYSTEM_MINT_PREFERENCE_PROBES {
                base | ((legacy + SYSTEM_MINT_PREFERENCE_PROBES) & 0xffff)
            } else {
                legacy
            };
            assert_eq!(
                select_system_mint_slot_avoiding_outputs(&state, 0, &hard, &soft),
                Some(expected)
            );
            assert!(!hard.contains(&expected));
        }
        let small = ChainState::with_log_slots(4);
        let all = (0..16).collect();
        assert_eq!(
            select_system_mint_slot_avoiding_outputs(&small, 0, &all, &all),
            None
        );
    }

    #[test]
    fn mint_preference_wraps_within_one_segment_without_hydrating_evicted_state() {
        use crate::consensus::allocator::generate_zone_segment_hints;

        let mut state = ChainState::with_log_slots(17);
        state.alloc_counter = 0xffff;
        let evicted = generate_zone_segment_hints(state.alloc_counter, 17, 2)[0];
        state
            .state
            .install_evicted_exact_summary(evicted, 1)
            .unwrap();
        state.state.finish_evicted_exact_summaries();
        let legacy = select_system_mint_slot(&state, 7, &HashSet::new()).unwrap();
        assert_eq!(legacy & 0xffff, 0xffff);
        let base = legacy & !0xffff;
        let hard = HashSet::from([base]);
        let soft = HashSet::from([legacy]);
        assert_eq!(
            select_system_mint_slot_avoiding_outputs(&state, 7, &hard, &soft),
            Some(base + 1)
        );
        assert_ne!((base >> 16) as u16, evicted);
        assert!(state.state.is_evicted(evicted));
        assert_eq!(state.state.materialized_segment_ids().count(), 0);
    }

    #[test]
    fn mint_preference_cannot_move_a_mint_to_another_segment() {
        let state = ChainState::with_log_slots(17);
        let hard = HashSet::new();
        let legacy = select_system_mint_slot(&state, 0, &hard).unwrap();
        let base = legacy & !0xffff;
        let soft = (base..base + (1 << 16)).collect();
        assert_eq!(
            select_system_mint_slot_avoiding_outputs(&state, 0, &hard, &soft),
            Some(legacy),
            "the other empty segment must not be opened for a soft preference"
        );
    }

    #[test]
    fn mint_preference_covers_daily_payouts_and_all_reserved_fallback() {
        for payout in [false, true] {
            let mut state = ChainState::with_log_slots(8);
            let mut parent = parent(&mut state);
            if payout {
                parent.height = FIRST_PAYOUT_HEIGHT - 1;
            }
            let legacy = node_owned_coinbase_template(&parent, &state)
                .0
                .into_block(0);
            let old_slots: HashSet<_> = legacy
                .transactions
                .iter()
                .flat_map(|tx| tx.body.live_outputs().map(|(_, out)| out.slot_index))
                .collect();
            for soft in [old_slots, (0..256).collect()] {
                let (template, prepared) = build_node_owned_block_template_avoiding_outputs(
                    &parent,
                    &state,
                    &[0],
                    vec![],
                    Address([9; 32]),
                    1,
                    [0xff; 32],
                    &soft,
                )
                .unwrap();
                let block = template.into_block(0);
                assert_eq!(block.header.active_slot_count, if payout { 3 } else { 1 });
                let slots: HashSet<_> = block
                    .transactions
                    .iter()
                    .flat_map(|tx| tx.body.live_outputs().map(|(_, out)| out.slot_index))
                    .collect();
                assert_eq!(slots.len(), if payout { 3 } else { 1 });
                if soft.len() == 256 {
                    assert_eq!(
                        block, legacy,
                        "full soft reservation keeps the legacy block"
                    );
                } else {
                    assert!(slots.is_disjoint(&soft));
                }
                assert_eq!(
                    crate::consensus::validation::validate_mandatory_coinbase(&block, &parent),
                    Ok(())
                );
                let mut replay = state.clone();
                crate::block::apply_block(&mut replay, &block).unwrap();
                assert_eq!(replay.state_root(), block.header.state_root);
                assert_eq!(
                    prepared.post_state.cached_state_root(),
                    replay.cached_state_root()
                );
            }
        }
    }

    #[test]
    fn mint_preference_cannot_block_a_payout_with_only_three_free_slots() {
        use crate::fri_state::SlotValue;

        let owner = Address([4; 32]);
        let free = HashSet::from([1, 77, 200]);
        let occupied: Vec<_> = (0..256)
            .filter(|slot| !free.contains(slot))
            .map(|slot| {
                (
                    slot,
                    SlotValue::with_owner_fields(100_000, u64::from(slot) + 1, owner.as_fields()),
                )
            })
            .collect();
        let mut state = ChainState::with_log_slots(8);
        state.state.apply_delta_unrooted(&occupied).unwrap();
        state.active_slot_count = 253;
        state.alloc_counter = 256;
        state.circulating_supply_micronoid = 25_300_000;
        let mut parent = parent(&mut state);
        parent.height = FIRST_PAYOUT_HEIGHT - 1;
        let old = build_node_owned_block_template(
            &parent,
            &state,
            &[0; 18],
            vec![],
            Address([9; 32]),
            1,
            [0xff; 32],
        )
        .unwrap()
        .0
        .into_block(0);
        let new = build_node_owned_block_template_avoiding_outputs(
            &parent,
            &state,
            &[0; 18],
            vec![],
            Address([9; 32]),
            1,
            [0xff; 32],
            &free,
        )
        .unwrap()
        .0
        .into_block(0);
        assert_eq!(new, old, "soft reservations cannot veto mandatory mints");
        assert_eq!(new.header.active_slot_count, 256);
        crate::block::apply_block(&mut state, &new).unwrap();
        assert_eq!(state.state_root(), new.header.state_root);
    }

    #[test]
    fn mint_preference_keeps_b25_b255_users_and_their_slots_unchanged() {
        use crate::fri_state::SlotValue;

        for (count, payout) in [(25u32, false), (255, false), (24, true), (255, true)] {
            let owner = Address([4; 32]);
            let mut state = ChainState::with_log_slots(16);
            let occupied: Vec<_> = (0..count)
                .map(|slot| {
                    (
                        slot,
                        SlotValue::with_owner_fields(1_000_000, 1, owner.as_fields()),
                    )
                })
                .collect();
            state.state.apply_delta_unrooted(&occupied).unwrap();
            state.active_slot_count = u64::from(count);
            state.alloc_counter = u64::from(count);
            state.circulating_supply_micronoid = u128::from(count) * 1_000_000;
            let mut parent = parent(&mut state);
            if payout {
                parent.height = FIRST_PAYOUT_HEIGHT - 1;
            }
            let candidates: Vec<_> = (0..count)
                .map(|slot| user(slot, 1024 + slot, 1_000_000, owner, &parent))
                .collect();
            let legacy = build_block_template(
                &parent,
                &state,
                &[u64::from(count)],
                candidates.clone(),
                Address([9; 32]),
                1,
                [0xff; 32],
            )
            .unwrap();
            let old_slots: HashSet<_> = std::iter::once(&legacy.coinbase)
                .chain(legacy.development_payout.iter())
                .flat_map(|tx| tx.body.live_outputs().map(|(_, out)| out.slot_index))
                .collect();
            let mut soft: HashSet<_> = (1024..1024 + count).collect();
            soft.extend(&old_slots);
            let selected_count = (count as usize).min(255 - usize::from(payout));
            for all_soft in [false, true] {
                let avoid = if all_soft {
                    (0..1 << 16).collect()
                } else {
                    soft.clone()
                };
                let (template, prepared) = build_node_owned_block_template_avoiding_outputs(
                    &parent,
                    &state,
                    &[u64::from(count)],
                    candidates.clone(),
                    Address([9; 32]),
                    1,
                    [0xff; 32],
                    &avoid,
                )
                .unwrap();
                assert_eq!(template.txs, legacy.txs);
                assert_eq!(template.txs.len(), selected_count);
                let mint_slots: HashSet<_> = std::iter::once(&template.coinbase)
                    .chain(template.development_payout.iter())
                    .flat_map(|tx| tx.body.live_outputs().map(|(_, out)| out.slot_index))
                    .collect();
                assert_eq!(mint_slots.len(), if payout { 3 } else { 1 });
                for slot in &mint_slots {
                    assert!(!(0..count).contains(slot));
                    assert!(!(1024..1024 + count).contains(slot));
                }
                for (new, old) in std::iter::once(&template.coinbase)
                    .chain(template.development_payout.iter())
                    .zip(std::iter::once(&legacy.coinbase).chain(legacy.development_payout.iter()))
                {
                    let mut old_body = old.body.clone();
                    for (old_output, new_output) in
                        old_body.outputs.iter_mut().zip(&new.body.outputs)
                    {
                        old_output.slot_index = new_output.slot_index;
                    }
                    assert_eq!(new.body, old_body, "only mint slots may change");
                }
                if all_soft {
                    assert_eq!(template.clone().into_block(0), legacy.clone().into_block(0));
                } else {
                    assert!(mint_slots.is_disjoint(&old_slots));
                    assert!(mint_slots.is_disjoint(&avoid));
                }
                let block = template.into_block(0);
                crate::consensus::validation::validate_mandatory_coinbase(&block, &parent).unwrap();
                let layout = crate::block::validate_block_page_stream(&block.transactions).unwrap();
                assert_eq!(usize::from(layout.page_count), selected_count);
                assert_eq!(layout.has_development_payout, payout);
                assert_eq!(
                    layout.proof_class,
                    crate::consensus::paged_spend::BlockProofClass::for_page_count(
                        selected_count + usize::from(payout)
                    )
                    .unwrap()
                );
                let mut replay = state.clone();
                crate::block::apply_block(&mut replay, &block).unwrap();
                assert_eq!(replay.state_root(), block.header.state_root);
                assert_eq!(
                    prepared.post_state.cached_state_root(),
                    replay.cached_state_root()
                );
                crate::consensus::da_prune::revert_block(&mut replay, &prepared.undo_log).unwrap();
                replay.active_slot_count = prepared.undo_log.active_slot_count_before;
                replay.alloc_counter = prepared.undo_log.alloc_counter_before;
                assert_eq!(replay.state_root(), parent.state_root);
                assert_eq!(
                    replay.circulating_supply_micronoid,
                    state.circulating_supply_micronoid
                );
            }
        }
    }

    #[test]
    #[ignore = "manual release-mode latency benchmark, not a timing assertion"]
    fn mint_preference_latency_benchmark() {
        use crate::fri_state::SlotValue;
        use std::hint::black_box;
        use std::time::Instant;

        fn median_ns(mut samples: Vec<u128>) -> u128 {
            samples.sort_unstable();
            samples[samples.len() / 2]
        }

        let mut state = ChainState::with_log_slots(24);
        let owner = Address([4; 32]);
        let occupied: Vec<_> = (0..255)
            .map(|slot| {
                (
                    slot,
                    SlotValue::with_owner_fields(1_000_000, 1, owner.as_fields()),
                )
            })
            .collect();
        state.state.apply_delta_unrooted(&occupied).unwrap();
        state.active_slot_count = 255;
        state.alloc_counter = 255;
        state.circulating_supply_micronoid = 255_000_000;
        let parent = parent(&mut state);
        let seed =
            state.alloc_counter ^ u64::from_le_bytes(parent.state_root[..8].try_into().unwrap());
        let hard = (0..255).collect();
        let legacy_slot = select_system_mint_slot(&state, seed, &hard).unwrap();
        let worst_probe: HashSet<_> = (0..=SYSTEM_MINT_PREFERENCE_PROBES)
            .map(|step| (legacy_slot & !0xffff) | ((legacy_slot + step) & 0xffff))
            .collect();
        let start = Instant::now();
        for _ in 0..20_000 {
            black_box(select_system_mint_slot(&state, seed, &hard));
        }
        let legacy_ns = start.elapsed().as_nanos() / 20_000;
        let start = Instant::now();
        for _ in 0..20_000 {
            black_box(select_system_mint_slot_avoiding_outputs(
                &state,
                seed,
                &hard,
                &worst_probe,
            ));
        }
        eprintln!(
            "mint_probe legacy_ns={legacy_ns} all_64_blocked_ns={}",
            start.elapsed().as_nanos() / 20_000
        );

        // This isolates the added integer-index copy. The largest case is an
        // upper envelope of 1,024 entries with 255 two-output pages each, not
        // a claim that all such proofs fit the byte-limited live mempool.
        for count in [0, 2_048, 1_024 * 255 * 2] {
            let outputs: HashSet<u32> = (1_000_000..1_000_000 + count).collect();
            let samples = (0..31)
                .map(|_| {
                    let start = Instant::now();
                    let copy = black_box(outputs.clone());
                    let elapsed = start.elapsed().as_nanos();
                    drop(copy);
                    elapsed
                })
                .collect();
            eprintln!(
                "reservation_clone slots={count} median_ns={}",
                median_ns(samples)
            );
        }
        for pages in [0, 25, 255] {
            let candidates: Vec<_> = (0..pages)
                .map(|slot| user(slot, 1024 + slot, 1_000_000, owner, &parent))
                .collect();
            let legacy = build_node_owned_block_template(
                &parent,
                &state,
                &[255],
                candidates.clone(),
                Address([9; 32]),
                1,
                [0xff; 32],
            )
            .unwrap()
            .0;
            let soft = HashSet::from([legacy.coinbase.body.outputs[0].slot_index]);
            let mut baseline = Vec::new();
            let mut preferred = Vec::new();
            for _ in 0..15 {
                let start = Instant::now();
                drop(black_box(
                    build_node_owned_block_template(
                        &parent,
                        &state,
                        &[255],
                        candidates.clone(),
                        Address([9; 32]),
                        1,
                        [0xff; 32],
                    )
                    .unwrap(),
                ));
                baseline.push(start.elapsed().as_nanos());
                let start = Instant::now();
                drop(black_box(
                    build_node_owned_block_template_avoiding_outputs(
                        &parent,
                        &state,
                        &[255],
                        candidates.clone(),
                        Address([9; 32]),
                        1,
                        [0xff; 32],
                        &soft,
                    )
                    .unwrap(),
                ));
                preferred.push(start.elapsed().as_nanos());
            }
            eprintln!(
                "template pages={pages} legacy_median_ns={} preferred_median_ns={}",
                median_ns(baseline),
                median_ns(preferred)
            );
        }
    }

    #[test]
    fn expansion_block_keeps_parent_mempool_and_grows_exact_domain_once() {
        use crate::fri_state::SlotValue;

        let owner = Address([4u8; 32]);
        let mut state = ChainState::with_log_slots(8);
        let occupied = (0..192u32)
            .map(|slot| {
                (
                    slot,
                    SlotValue::with_owner_fields(
                        100_000_000,
                        u64::from(slot) + 1,
                        owner.as_fields(),
                    ),
                )
            })
            .collect::<Vec<_>>();
        state.state.apply_delta_unrooted(&occupied).unwrap();
        state.active_slot_count = occupied.len() as u64;
        state.alloc_counter = occupied.len() as u64;
        state.circulating_supply_micronoid = occupied
            .iter()
            .map(|(_, slot)| u128::from(slot.amount()))
            .sum();
        let mut parent = parent(&mut state);
        parent.height = 35;
        let candidate = user(0, 220, 100_000_000, owner, &parent);

        let template = build_block_template(
            &parent,
            &state,
            &[192; 18],
            vec![candidate.clone()],
            Address([9u8; 32]),
            1,
            [0xff; 32],
        )
        .unwrap();

        assert_eq!(template.log_slots, 9);
        assert_eq!(template.txs.len(), 1);
        assert_eq!(template.txs[0].txid(), candidate.txid());
        assert_eq!(template.active_slot_count, 193);
        assert_eq!(template.alloc_counter, 194);
        assert!(u64::from(template.coinbase.body.outputs[0].slot_index) < (1u64 << 9));
    }

    #[test]
    fn competing_expansion_miners_include_pending_work_and_advance_once() {
        use crate::fri_state::SlotValue;

        let owner = Address([4u8; 32]);
        let mut state = ChainState::with_log_slots(8);
        let occupied = (0..192u32)
            .map(|slot| {
                (
                    slot,
                    SlotValue::with_owner_fields(
                        100_000_000,
                        u64::from(slot) + 1,
                        owner.as_fields(),
                    ),
                )
            })
            .collect::<Vec<_>>();
        state.state.apply_delta_unrooted(&occupied).unwrap();
        state.active_slot_count = occupied.len() as u64;
        state.alloc_counter = occupied.len() as u64;
        state.circulating_supply_micronoid = occupied
            .iter()
            .map(|(_, slot)| u128::from(slot.amount()))
            .sum();
        let mut parent = parent(&mut state);
        parent.height = 35;

        let pending = user(0, 220, 100_000_000, owner, &parent);

        let first = build_block_template(
            &parent,
            &state,
            &[192; 18],
            vec![pending.clone()],
            Address([9u8; 32]),
            1,
            [0xff; 32],
        )
        .unwrap();
        let second = build_block_template(
            &parent,
            &state,
            &[192; 18],
            vec![pending.clone()],
            Address([10u8; 32]),
            1,
            [0xff; 32],
        )
        .unwrap();
        assert_eq!(first.log_slots, 9);
        assert_eq!(second.log_slots, 9);
        assert_eq!(first.txs.len(), 1);
        assert_eq!(second.txs.len(), 1);
        assert_eq!(first.txs[0].txid(), pending.txid());
        assert_eq!(second.txs[0].txid(), pending.txid());
        assert_ne!(first.state_root, second.state_root);

        let winning = crate::block::Block {
            header: first.to_pow_header(0),
            transactions: first.all_txs(),
        };
        crate::block::apply_block(&mut state, &winning).unwrap();
        assert_eq!(state.state.log_slots(), 9);
        assert_eq!(state.active_slot_count, 193);
        assert_eq!(state.alloc_counter, 194);
        assert_eq!(state.state.slot(0), SlotValue::EMPTY);
        assert!(!state.state.slot(220).is_empty());

        // The competing block is now stale. Applying it must fail atomically:
        // the winner's tip/state stays unchanged.
        let losing = crate::block::Block {
            header: second.to_pow_header(0),
            transactions: second.all_txs(),
        };
        let winning_root = state.cached_state_root();
        assert!(crate::block::apply_block(&mut state, &losing).is_err());
        assert_eq!(state.cached_state_root(), winning_root);
        assert_eq!(state.state.log_slots(), 9);

        // The following block remains at the expanded depth and continues
        // normally; the boundary was crossed exactly once.
        let next = build_block_template(
            &winning.header,
            &state,
            &[193; 18],
            vec![],
            Address([11u8; 32]),
            2,
            [0xff; 32],
        )
        .unwrap();
        assert_eq!(next.log_slots, 9);
        assert!(next.txs.is_empty());
        let next_block = crate::block::Block {
            header: next.to_pow_header(0),
            transactions: next.all_txs(),
        };
        crate::block::apply_block(&mut state, &next_block).unwrap();
        assert_eq!(state.state.log_slots(), 9);
        assert_eq!(state.active_slot_count, 194);
    }

    #[test]
    fn reward_minted_at_parent_height_is_selected_for_child() {
        use crate::consensus::params::coinbase_creation_id;

        let owner = Address([1u8; 32]);
        let mut state = ChainState::with_log_slots(8);
        let mint_height = 6;
        // The accepted parent state already contains its height-6 reward.
        state
            .state
            .set_slot(
                1,
                crate::fri_state::SlotValue::with_owner_fields(
                    1_000_000,
                    coinbase_creation_id(mint_height),
                    owner.as_fields(),
                ),
            )
            .unwrap();
        state.active_slot_count = 1;
        state.alloc_counter = 1;
        state.circulating_supply_micronoid = 1_000_000;
        let mut parent = parent(&mut state);
        parent.height = mint_height;

        let mut spend = user(1, 3, 1_000_000, owner, &parent);
        let mut body = spend.body;
        body.inputs[0].creation_id = coinbase_creation_id(mint_height);
        spend = Transaction::new(body);

        let child = build_block_template(
            &parent,
            &state,
            &[1],
            vec![spend],
            Address([9u8; 32]),
            1,
            [0xff; 32],
        )
        .unwrap();
        assert_eq!(child.height, mint_height + 1);
        assert_eq!(child.txs.len(), 1);
    }

    #[test]
    fn candidate_stream_rejects_same_block_slot_chains() {
        let owner = Address([1u8; 32]);
        let mut state = ChainState::with_log_slots(8);
        for slot in [1u32, 2] {
            state
                .state
                .set_slot(
                    slot,
                    crate::fri_state::SlotValue::with_owner_fields(1_000_000, 1, owner.as_fields()),
                )
                .unwrap();
        }
        state.active_slot_count = 2;
        state.alloc_counter = 1;
        state.circulating_supply_micronoid = 2_000_000;
        let parent = parent(&mut state);
        let a = user(1, 3, 1_000_000, owner, &parent);
        let b = user(2, 1, 1_000_000, owner, &parent);
        let error = build_block_template(
            &parent,
            &state,
            &[2],
            vec![a, b],
            Address([9u8; 32]),
            1,
            [0xff; 32],
        )
        .unwrap_err();
        assert!(matches!(error, TemplateBuildError::StateApplyError(_)));
    }

    fn node_owned_coinbase_template(
        parent: &BlockHeader,
        state: &ChainState,
    ) -> (BlockTemplate, PreparedBlockStateCommit) {
        build_node_owned_block_template(
            parent,
            state,
            &[parent.active_slot_count],
            vec![],
            Address([9u8; 32]),
            parent.timestamp + 1,
            [0xff; 32],
        )
        .unwrap()
    }

    fn structural_terminal_for_unsafe_binding_test(block: &Block) -> Vec<u8> {
        let mut terminal =
            HistoryStepTerminalMetadata::new(block.header.height, block_id(&block.header), 0)
                .unwrap()
                .encode_prefix()
                .to_vec();
        terminal.push(0xA5);
        terminal
    }

    #[test]
    fn unsafe_local_seal_still_binds_header_body_and_post_state() {
        let mut state = ChainState::with_log_slots(8);
        let parent = parent(&mut state);

        let (template, prepared) = node_owned_coinbase_template(&parent, &state);
        let mut changed_header = template.into_block(17);
        changed_header.header.miner_address = Address([0xA5; 32]);
        let terminal = structural_terminal_for_unsafe_binding_test(&changed_header);
        assert_eq!(
            // SAFETY: this deliberately malformed test input exercises only
            // the unsafe bridge's immutable template binding and is never
            // committed.
            unsafe {
                prepared.seal_after_trusted_history_step_proof_unchecked(changed_header, terminal)
            }
            .err(),
            Some("sealed block header differs from its prepared template".to_string())
        );

        let (template, prepared) = node_owned_coinbase_template(&parent, &state);
        let mut changed_body = template.into_block(17);
        let mut body = changed_body.transactions[0].body.clone();
        body.outputs[0].amount = body.outputs[0].amount.saturating_sub(1);
        changed_body.transactions[0] = Transaction::new(body);
        let terminal = structural_terminal_for_unsafe_binding_test(&changed_body);
        assert_eq!(
            // SAFETY: as above, no capability produced here reaches commit.
            unsafe {
                prepared.seal_after_trusted_history_step_proof_unchecked(changed_body, terminal)
            }
            .err(),
            Some("sealed block body differs from its prepared template".to_string())
        );
    }
}
