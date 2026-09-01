// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block template management.
//!
//! A `BlockTemplate` is a fully computed block ready for phase-ordered proving
//! preparation and PoW:
//! - Transaction set selected, conflict-resolved, ordered
//! - State applied to scratch → `state_root` known
//! - Coinbase constructed
//! - Correct ASERT difficulty target computed
//! - All semantic header fields set except `nonce`
//!
//! ## Template refresh triggers
//!
//! 1. Heartbeat every `refresh_interval_secs` seconds (safety net)
//! 2. First `TxAdmitted` while a coinbase-only template is being mined
//! 3. New chain tip from P2P (block received or snapshot applied)

use std::collections::{HashMap, HashSet};

use noid_chain::block::Block;
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::difficulty::next_target;
use noid_chain::consensus::pow::block_id;
use noid_chain::consensus::template::BlockTemplate as ChainTemplate;
use noid_chain::consensus::AnchorInfo;
use noid_chain::state::ChainState;
use noid_chain::storage::{MdbxChainContext, MdbxContextError, MdbxStore};
use noid_mempool::AsyncMempool;
use noid_poseidon2b::primitives::Address;

use crate::cpu_budget::install_history_step_phase_cpu;

/// Why the template was refreshed (carried in `MinerEvent::TemplateRefreshed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateRefreshTrigger {
    /// Regular heartbeat (safety net — fires every `refresh_interval_secs`).
    Heartbeat,
    /// First `TxAdmitted` event while prove was already done (Sealed state).
    /// The miner immediately rebuilds to include the new tx in the current block.
    TxAdmitted,
    /// New chain tip available: P2P block applied or state snapshot synced.
    SyncReady,
    /// Node startup — generate the very first template.
    Startup,
}

/// A `BlockTemplate` ready for nonce-independent witness preparation followed
/// by the all-core PoW phase.
///
/// Security: `state_root` is in the Poseidon2b PoW field schedule.
/// An external miner cannot change the coinbase or any other semantic field;
/// it receives the fixed PoW header and returns only a nonce.
pub struct BlockTemplate {
    /// Inner chain-level template with tx ordering and coinbase.
    pub inner: ChainTemplate,
    /// Correctly computed ASERT difficulty target for the new block.
    pub difficulty_target: [u8; 32],
    /// Miner address (coinbase recipient).
    pub miner_address: Address,
    /// Timestamp used for this template.
    pub timestamp: u64,
    /// Parent header.
    pub parent: BlockHeader,
    /// Cached WalletAuthorizationBundle bytes for each non-coinbase tx (same order as inner.txs).
    pub authorization_bytes: Vec<Option<Vec<u8>>>,
    /// Hydrated exact parent state reused directly by HistoryStep preparation.
    pub parent_state: ChainState,
    pub finalized_active_counts: Vec<u64>,
    pub previous_timestamps: Vec<u64>,
    pub asert_anchor: AnchorInfo,
    /// Canonical anchor carried by the parent terminal. This is deliberately
    /// distinct from the anchor selected for this template's child
    /// transactions at a 144-block boundary.
    pub parent_tx_epoch_anchor_header: BlockHeader,
    pub parent_history_step_terminal_bytes: Option<Vec<u8>>,
    /// One-shot post-state/undo capability minted by the same canonical
    /// builder that fixed `inner.state_root`.
    pub(crate) prepared_state_commit: noid_chain::consensus::template::PreparedBlockStateCommit,
}

impl BlockTemplate {
    /// Build the partial header for PoW search.
    ///
    /// The miner hashes the fixed semantic header field schedule.
    pub fn header_for_pow(&self, nonce: u128) -> BlockHeader {
        self.inner.to_pow_header(nonce)
    }

    /// Assemble the final sealed block after PoW fixes its nonce.
    pub fn seal(&self, nonce: u128) -> Block {
        let header = self.inner.clone().into_header(nonce);
        Block {
            header,
            transactions: self.inner.all_txs(),
        }
    }

    /// Number of selected physical user pages.
    pub fn n_user_txs(&self) -> usize {
        self.inner.txs.len()
    }
}

/// Immutable chain view used for template construction.
///
/// Capture this under the chain lock, then drop the lock before awaiting mempool
/// selection or doing proof/template work. Raw segment columns are deliberately
/// excluded; selected transaction segments are faulted in from the cloned MDBX
/// handle for the chosen block.
pub struct TemplateChainSnapshot {
    pub parent: BlockHeader,
    pub finalized_active_counts: Vec<u64>,
    pub prev_timestamps: Vec<u64>,
    pub anchor: AnchorInfo,
    pub state: ChainState,
    /// Anchor committed by the current parent terminal.
    pub parent_tx_epoch_anchor_header: BlockHeader,
    /// Anchor that user transactions in the next child block must bind.
    pub child_tx_epoch_anchor_header: BlockHeader,
    pub parent_history_step_terminal_bytes: Option<Vec<u8>>,
    store: MdbxStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TemplateEpochAnchorHeights {
    parent_terminal: u64,
    child_transactions: u64,
}

fn template_epoch_anchor_heights(parent_height: u64) -> Option<TemplateEpochAnchorHeights> {
    let child_height = parent_height.checked_add(1)?;
    Some(TemplateEpochAnchorHeights {
        parent_terminal: noid_chain::consensus::tx_epoch_anchor_height_for_child(parent_height),
        child_transactions: noid_chain::consensus::tx_epoch_anchor_height_for_child(child_height),
    })
}

impl TemplateChainSnapshot {
    pub fn from_context(ctx: &mut MdbxChainContext) -> Result<Self, MdbxContextError> {
        let parent = *ctx.tip_header();
        let anchor_heights = template_epoch_anchor_heights(parent.height).ok_or(
            MdbxContextError::Corrupt("tip height cannot produce a child block template"),
        )?;
        let parent_tx_epoch_anchor_header = ctx
            .get_header_from_store(anchor_heights.parent_terminal)?
            .ok_or(MdbxContextError::Corrupt(
                "parent terminal transaction epoch anchor header missing",
            ))?;
        let child_tx_epoch_anchor_header =
            if anchor_heights.child_transactions == anchor_heights.parent_terminal {
                parent_tx_epoch_anchor_header
            } else {
                ctx.get_header_from_store(anchor_heights.child_transactions)?
                    .ok_or(MdbxContextError::Corrupt(
                        "child transaction epoch anchor header missing",
                    ))?
            };
        let parent_history_step_terminal_bytes = if parent.height == 0 {
            None
        } else {
            Some(
                ctx.store
                    .get_history_step_terminal_at(parent.height, block_id(&parent))?
                    .ok_or(MdbxContextError::Corrupt(
                        "parent HistoryStep terminal missing",
                    ))?,
            )
        };
        Ok(Self {
            parent,
            finalized_active_counts: ctx.finalized_active_counts()?,
            prev_timestamps: ctx.prev_timestamps()?,
            anchor: ctx.anchor_info()?,
            state: ctx
                .state
                .durable_metadata_clone()
                .ok_or(MdbxContextError::Corrupt(
                    "template snapshot requested outside durable state boundary",
                ))?,
            parent_tx_epoch_anchor_header,
            child_tx_epoch_anchor_header,
            parent_history_step_terminal_bytes,
            store: ctx.store.clone(),
        })
    }

    pub fn prev_state_root(&self) -> [u8; 32] {
        self.parent.state_root
    }

    fn hydrate_transaction_segments(
        &self,
        state: &mut ChainState,
        txs: &[noid_tx::Transaction],
    ) -> Result<(), MdbxContextError> {
        let effective_log = state.state.effective_log_segment_size();
        let mut needed = HashSet::new();
        for tx in txs {
            for (_, input) in tx.body.live_inputs() {
                needed.insert((input.slot_index >> effective_log) as u16);
            }
            for (_, output) in tx.body.live_outputs() {
                needed.insert((output.slot_index >> effective_log) as u16);
            }
        }
        self.hydrate_segments(state, needed)
    }

    /// Hydrate one evicted non-full segment so coinbase construction can reuse
    /// a durable hole without retaining the complete state in RAM.
    ///
    /// Compact live counts identify the segment without raw reads. The segment
    /// with the most holes is chosen, so one 3-MiB load is sufficient even when
    /// selected transaction outputs reserve many candidate slots. If every
    /// live segment is full, the pure template builder opens a virtual-zero
    /// allocator segment and no hydration is needed.
    fn hydrate_coinbase_reuse_segment(
        &self,
        state: &mut ChainState,
    ) -> Result<(), MdbxContextError> {
        if !state
            .state
            .empty_slot_hints_in_populated_segments(0, 1, &HashSet::new())
            .is_empty()
        {
            return Ok(());
        }

        let segment_capacity = 1u32 << state.state.effective_log_segment_size();
        let candidate = (0..state.state.num_segments())
            .map(|segment| segment as u16)
            .filter(|segment| {
                let live = state.state.segment_live_count(*segment);
                live > 0 && live < segment_capacity
            })
            .min_by_key(|segment| state.state.segment_live_count(*segment));
        match candidate {
            Some(segment) => self.hydrate_segments(state, HashSet::from([segment])),
            None => Ok(()),
        }
    }

    fn hydrate_segments(
        &self,
        state: &mut ChainState,
        needed: HashSet<u16>,
    ) -> Result<(), MdbxContextError> {
        for segment_id in needed {
            if !state.state.is_evicted(segment_id) {
                continue;
            }
            let (_, columns) =
                self.store
                    .get_segment(segment_id)?
                    .ok_or(MdbxContextError::Corrupt(
                        "template segment is missing from durable state",
                    ))?;
            state
                .restore_evicted_segment(segment_id, columns)
                .map_err(|_| {
                    MdbxContextError::Corrupt("template segment exact summary mismatch")
                })?;
        }
        Ok(())
    }
}

/// Builds `BlockTemplate` from a chain snapshot and top-fee mempool txs.
pub struct TemplateBuilder {
    pub mempool: AsyncMempool,
}

impl TemplateBuilder {
    pub fn new(mempool: AsyncMempool) -> Self {
        Self { mempool }
    }

    /// Build a B25-default template from a pre-captured chain snapshot.
    ///
    /// Computes the ASERT difficulty target correctly using `next_target()`.
    pub async fn build_from_snapshot(
        &self,
        snapshot: TemplateChainSnapshot,
        miner_address: Address,
        now_unix: u64,
    ) -> Option<BlockTemplate> {
        self.build_from_snapshot_with_limit(
            snapshot,
            miner_address,
            now_unix,
            noid_chain::consensus::paged_spend::BlockProofClass::B25.page_capacity(),
        )
        .await
    }

    /// Build a template within one effective proof-class page budget. A
    /// mandatory development payout consumes one position; complete
    /// PagedSpend groups remain indivisible while fee-packing the remainder.
    pub async fn build_from_snapshot_with_limit(
        &self,
        snapshot: TemplateChainSnapshot,
        miner_address: Address,
        now_unix: u64,
        max_effective_pages: usize,
    ) -> Option<BlockTemplate> {
        use noid_chain::consensus::median_time_past;

        let parent = snapshot.parent;
        if !mining_launch_is_open(&parent, now_unix) {
            return None;
        }
        let finalized_active_counts = &snapshot.finalized_active_counts;
        let prev_timestamps = &snapshot.prev_timestamps;

        // Compute the minimum valid timestamp for the new block:
        //   timestamp MUST be strictly greater than MTP (median of last 11 blocks).
        //   See validate_timestamp in noid_chain::consensus::timestamps.
        // This prevents BadTimestamp when blocks are found faster than 1 second
        // (genesis target is trivial; multiple blocks per second are possible).
        let mtp = median_time_past(prev_timestamps);
        let min_valid_ts = mtp + 1;
        let timestamp = now_unix.max(min_valid_ts);

        // Compute the correct ASERT target for the new block.
        // MUST match what validate_header computes; wrong target = block rejected.
        let anchor = &snapshot.anchor;
        let difficulty_target = next_target(
            anchor.anchor_height,
            anchor.anchor_timestamp,
            &anchor.anchor_target,
            parent.height + 1,
            timestamp,
        );

        // Select top txs from mempool (coinbase is added separately by the chain template).
        let max_user_pages = user_page_limit_for_child(parent.height, max_effective_pages)?;
        let user_epoch_anchor = block_id(&snapshot.child_tx_epoch_anchor_header);
        // Filter against the captured anchor while entries are still borrowed
        // under the mempool lock. This preserves the same fee-ordered prefix
        // while cloning only the authorization bundles selected for this block.
        let entries = self
            .mempool
            .select_for_block_at_anchor(max_user_pages, user_epoch_anchor)
            .await;
        // Keep each authorization paired with its indivisible logical group;
        // flatten only the public pages passed into the chain template.
        let (authorization_bytes, groups): (Vec<Option<Vec<u8>>>, Vec<_>) = entries
            .into_iter()
            .map(|e| (e.cached_authorization, (e.logical_txid, e.pages)))
            .unzip();

        // Recheck the exact start-of-block anchor after selection. A boundary
        // may have advanced while the transaction waited in the mempool.
        let (authorization_bytes, groups): (Vec<_>, Vec<_>) = authorization_bytes
            .into_iter()
            .zip(groups)
            .filter(|(_, (_, pages))| {
                pages
                    .first()
                    .is_some_and(|page| page.body.epoch_anchor == user_epoch_anchor)
            })
            .unzip();
        let mut proof_by_hash: HashMap<noid_poseidon2b::primitives::TxBodyHash, Option<Vec<u8>>> =
            authorization_bytes
                .into_iter()
                .zip(groups.iter().map(|(logical_txid, _)| *logical_txid))
                .map(|(proof, logical_txid)| (logical_txid, proof))
                .collect();
        let txs: Vec<_> = groups
            .into_iter()
            .flat_map(|(_, pages)| pages)
            .map(|page| noid_tx::Transaction::new(page.body))
            .collect();

        // Fault in only segments referenced by the admitted transaction set.
        // The canonical snapshot itself remains metadata-only, so template
        // construction never clones unrelated UTXO columns.
        let mut state = snapshot.state.clone();
        if let Err(error) = snapshot.hydrate_transaction_segments(&mut state, &txs) {
            tracing::warn!(err = %error, "template touched-segment hydration failed");
            return None;
        }
        if let Err(error) = snapshot.hydrate_coinbase_reuse_segment(&mut state) {
            tracing::warn!(err = %error, "template coinbase-reuse hydration failed");
            return None;
        }
        let template_cpu_result = install_history_step_phase_cpu(|| {
            match noid_chain::consensus::template::build_node_owned_block_template(
                &parent,
                &state,
                finalized_active_counts,
                txs,
                miner_address,
                timestamp,
                difficulty_target,
            ) {
                Ok(inner) => Some(inner),
                Err(error) => {
                    tracing::warn!(err = ?error, "template build failed");
                    None
                }
            }
        });
        let (inner, prepared_state_commit) = match template_cpu_result {
            Ok(Some(built)) => built,
            Ok(None) => return None,
            Err(error) => {
                tracing::error!(%error, "template CPU phase failed");
                return None;
            }
        };

        let selected_stream =
            noid_chain::consensus::validate_paged_spend_transaction_stream(&inner.txs)
                .expect("chain template emits one canonical PagedSpend stream");
        let authorization_bytes = selected_stream
            .groups
            .iter()
            .map(|group| {
                proof_by_hash
                    .remove(&group.spend.logical_txid)
                    .unwrap_or(None)
            })
            .collect();
        Some(BlockTemplate {
            inner,
            difficulty_target,
            miner_address,
            timestamp,
            parent,
            authorization_bytes,
            parent_state: state,
            finalized_active_counts: snapshot.finalized_active_counts,
            previous_timestamps: snapshot.prev_timestamps,
            asert_anchor: snapshot.anchor,
            parent_tx_epoch_anchor_header: snapshot.parent_tx_epoch_anchor_header,
            parent_history_step_terminal_bytes: snapshot.parent_history_step_terminal_bytes,
            prepared_state_commit,
        })
    }
}

fn user_page_limit_for_child(parent_height: u64, max_effective_pages: usize) -> Option<usize> {
    let child_height = parent_height.checked_add(1)?;
    let consensus_max = noid_chain::consensus::params::BLOCK_MAX_USER_PAGES;
    let system_positions = usize::from(
        noid_chain::consensus::development_allocation::development_payout_due(child_height),
    );
    Some(
        max_effective_pages
            .min(consensus_max)
            .saturating_sub(system_positions),
    )
}

pub(crate) fn mining_launch_is_open(parent: &BlockHeader, now_unix: u64) -> bool {
    parent.height != 0 || now_unix >= parent.timestamp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payout_position_stays_inside_the_selected_proof_class() {
        use noid_chain::consensus::development_allocation::{
            DEVELOPMENT_ALLOCATION_END_HEIGHT, TARGET_BLOCKS_PER_DAY,
        };

        assert_eq!(
            user_page_limit_for_child(TARGET_BLOCKS_PER_DAY - 2, 25),
            Some(25)
        );
        assert_eq!(
            user_page_limit_for_child(TARGET_BLOCKS_PER_DAY - 1, 25),
            Some(24)
        );
        assert_eq!(
            user_page_limit_for_child(TARGET_BLOCKS_PER_DAY - 1, 255),
            Some(254)
        );
        assert_eq!(
            user_page_limit_for_child(DEVELOPMENT_ALLOCATION_END_HEIGHT, 25),
            Some(25)
        );
        assert_eq!(user_page_limit_for_child(u64::MAX, 25), None);
    }

    #[test]
    fn template_separates_parent_and_child_anchors_at_transaction_epoch_boundary() {
        for (parent_height, parent_terminal, child_transactions) in [
            (143, 0, 0),
            (144, 0, 144),
            (145, 144, 144),
            (287, 144, 144),
            (288, 144, 288),
        ] {
            assert_eq!(
                template_epoch_anchor_heights(parent_height),
                Some(TemplateEpochAnchorHeights {
                    parent_terminal,
                    child_transactions,
                }),
                "parent height {parent_height}",
            );
        }
        assert_eq!(template_epoch_anchor_heights(u64::MAX), None);
    }

    #[test]
    fn first_template_unlocks_exactly_at_genesis_time() {
        let genesis = noid_chain::consensus::genesis_header();
        assert!(!mining_launch_is_open(
            &genesis,
            genesis.timestamp.saturating_sub(1)
        ));
        assert!(mining_launch_is_open(&genesis, genesis.timestamp));

        let mut later_parent = genesis;
        later_parent.height = 1;
        assert!(mining_launch_is_open(&later_parent, 0));
    }
}
