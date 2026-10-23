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

mod trades;
pub use trades::{project_trade, TradeProjection};

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
    /// Cached Owner bundles in the final semantic authorization order.
    pub authorization_bytes: Vec<Option<Vec<u8>>>,
    /// Openings in the final contract prefix, paired by logical transaction id.
    pub object_openings: Vec<noid_tx::experimental_object::ObjectOpening>,
    pub native_openings: Vec<noid_tx::native_assets::NativeOpening>,
    pub trade_batches: Vec<noid_tx::native_assets::trade::batch::TradeBatch>,
    /// Explicit v2 proof class. Legacy classes are still selected by their
    /// published page rule before activation.
    pub v2_class: Option<noid_recursive::acceptance::history_step::v2::banked::Class>,
    pub v21_class: Option<noid_recursive::acceptance::history_step::v2::capacity_banked::Class>,
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
    v2_config: Option<noid_recursive::acceptance::history_step::v2::banked::Config>,
    authorization_v2_config: Option<noid_recursive::acceptance::history_step::v2::banked::Config>,
    finance_config: Option<noid_recursive::acceptance::history_step::v2::capacity_banked::Config>,
    large_v2_mining: bool,
}

impl TemplateBuilder {
    pub fn new(mempool: AsyncMempool) -> Self {
        Self {
            mempool,
            v2_config: None,
            authorization_v2_config: None,
            finance_config: None,
            large_v2_mining: false,
        }
    }

    pub fn with_history_protocol(mut self, runtime: &crate::HistoryProtocolRuntime) -> Self {
        self.v2_config = runtime.v2().ok().map(|runtime| runtime.bank().config());
        self.authorization_v2_config =
            noid_chain::consensus::params::OWNER_AUTHORIZATION_ACTIVATION_HEIGHT
                .and_then(|height| runtime.v2_at(height).ok())
                .map(|runtime| runtime.bank().config());
        self.large_v2_mining = runtime.large_v2_mining_allowed();
        self.finance_config = runtime.finance_config();
        self
    }

    /// Build from a pre-captured chain snapshot, defaulting to B25 before
    /// v2 and the pinned small class after activation.
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

    /// Build with the legacy capacity ceiling before v2 and the pinned bank's
    /// resource budgets afterward. A system record consumes one page position.
    /// Complete PagedSpend groups remain indivisible when packing resources.
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
            parent.timestamp,
            timestamp,
        );

        // Select top txs from mempool (coinbase is added separately by the chain template).
        let user_epoch_anchor = block_id(&snapshot.child_tx_epoch_anchor_header);
        // Filter against the captured anchor while entries are still borrowed
        // under the mempool lock. This preserves the same fee-ordered prefix
        // while cloning only the authorization bundles selected for this block.
        let height = parent.height.checked_add(1)?;
        let mut grouped_intents = Vec::new();
        let mut trade_batches = Vec::new();
        let mut trade_authorizations = Vec::new();
        let (entries, pending_outputs, v2_class, v21_class) = if let Some(config) = self
            .finance_config
            .filter(|_| noid_chain::consensus::params::v2_1_active(height))
        {
            use noid_recursive::acceptance::history_step::v2::capacity_banked::Class;
            let mut classes = vec![Class::Small];
            if self.large_v2_mining {
                classes.push(Class::Large);
            }
            classes.push(Class::Native);
            let budgets: Vec<_> = classes
                .iter()
                .map(|class| v2_selection_budget(config.class(*class), height))
                .collect();
            let selected = trades::select_candidates(self, &snapshot, &budgets, user_epoch_anchor)
                .await
                .map_err(|e| tracing::debug!(%e, "v2.1 template selection unavailable"))
                .ok()?;
            let class = *classes.get(selected.candidate_index)?;
            grouped_intents = selected.intents;
            trade_batches = selected.batches;
            trade_authorizations = selected.authorizations;
            (
                selected.entries,
                selected.pending_outputs,
                None,
                Some(class),
            )
        } else if noid_chain::consensus::params::v2_active(height) {
            use noid_recursive::acceptance::history_step::v2::banked::Class;
            let config = if noid_chain::consensus::params::v2_1_active(height) {
                self.authorization_v2_config?
            } else {
                self.v2_config?
            };
            let small = v2_selection_budget(config.class(Class::Small), height);
            let large = self
                .large_v2_mining
                .then(|| v2_selection_budget(config.class(Class::Large), height));
            let selected = trades::select(self, &snapshot, small, large, user_epoch_anchor)
                .await
                .map_err(|e| tracing::debug!(%e, "v2 template selection unavailable"))
                .ok()?;
            grouped_intents = selected.intents;
            trade_batches = selected.batches;
            trade_authorizations = selected.authorizations;
            let class = if selected.candidate_index == 1 {
                Class::Large
            } else {
                Class::Small
            };
            (
                selected.entries,
                selected.pending_outputs,
                Some(class),
                None,
            )
        } else {
            let max_user_pages = user_page_limit_for_child(parent.height, max_effective_pages)?;
            let (entries, pending) = self
                .mempool
                .select_for_block_at_anchor_with_output_reservations(
                    max_user_pages,
                    user_epoch_anchor,
                )
                .await;
            (entries, pending, None, None)
        };
        let has_versioned_class = v2_class.is_some() || v21_class.is_some();
        // Retain proof/opening pairs by logical id through group ordering and
        // native State/resource selection. Recheck at this exact parent height:
        // the mempool may already have advanced while this snapshot was built.
        let mut proof_by_hash = HashMap::new();
        let mut opening_by_hash = HashMap::new();
        let mut native_payloads = std::collections::BTreeMap::new();
        let mut txs = Vec::new();
        for entry in entries {
            if !entry
                .pages
                .first()
                .is_some_and(|page| page.body.epoch_anchor == user_epoch_anchor)
            {
                continue;
            }
            if let Some(opening) = &entry.contract_opening {
                if !has_versioned_class
                    || entry.pages.len() != 1
                    || opening.check_call(&entry.pages[0], height).is_err()
                {
                    continue;
                }
            }
            if let Some(native) = &entry.native_intent {
                if !has_versioned_class {
                    continue;
                }
                let chain_id = noid_chain::state::native_assets::native_chain_id();
                let checked = match native.validate_structure().map(|facts| facts.operation) {
                    Ok(noid_tx::native_assets::transition::NativeOperation::Financial(_)) => {
                        noid_tx::native_assets::nft_market::NftRoundContext::new(
                            height,
                            block_id(&parent),
                            parent.alloc_counter,
                        )
                        .ok()
                        .is_some_and(|round| {
                            native.checked_financial_owner(chain_id, round).is_ok()
                        })
                    }
                    Ok(_) => native.checked(chain_id, height).is_ok(),
                    Err(_) => false,
                };
                if !checked {
                    continue;
                }
                for opening in native
                    .input_openings
                    .iter()
                    .chain(&native.output_openings)
                    .flatten()
                    .chain(&native.dependencies)
                {
                    native_payloads.insert(opening.root().0, *opening);
                }
            }
            proof_by_hash.insert(entry.logical_txid, entry.cached_authorization);
            if let Some(opening) = entry.contract_opening {
                opening_by_hash.insert(entry.logical_txid, opening);
            }
            txs.extend(
                entry
                    .pages
                    .into_iter()
                    .map(|page| noid_tx::Transaction::new(page.body)),
            );
        }
        for (id, proof) in trade_authorizations {
            proof_by_hash.insert(id, Some(proof));
        }
        for intent in grouped_intents {
            for opening in intent
                .input_openings
                .iter()
                .chain(&intent.output_openings)
                .flatten()
                .chain(&intent.dependencies)
            {
                native_payloads.insert(opening.root().0, *opening);
            }
            txs.extend(
                intent
                    .pages
                    .into_iter()
                    .map(|page| noid_tx::Transaction::new(page.body)),
            );
        }

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
        let all_native_openings: Vec<_> = native_payloads.values().copied().collect();
        let template_cpu_result = install_history_step_phase_cpu(|| {
            match noid_chain::consensus::template::build_node_owned_block_template_with_native_data(
                &parent,
                &state,
                finalized_active_counts,
                txs,
                miner_address,
                timestamp,
                difficulty_target,
                &pending_outputs,
                &all_native_openings,
                &trade_batches,
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

        let complete_txs = inner.all_txs();
        let selected_stream =
            noid_chain::block::native_assets::validate_scheduled_block_page_stream(
                &complete_txs,
                height,
            )
            .expect("chain template emits one canonical page stream");
        let native_openings = prepared_state_commit.native_openings().to_vec();
        let trade_batches = prepared_state_commit.trade_batches().to_vec();
        let mut authorization_bytes = Vec::with_capacity(selected_stream.logical_count());
        let mut object_openings = Vec::new();
        for (index, group) in selected_stream.groups().enumerate() {
            let id = group.logical_txid();
            use noid_chain::block::native_assets::ScheduledSpendKind;
            use noid_tx::native_assets::{
                financial::FinancialOperation, transition::NativeOperation,
            };
            let trade_root = match group.kind {
                ScheduledSpendKind::Native(facts) => match facts.operation {
                    NativeOperation::Financial(FinancialOperation::ExecuteTrades {
                        commitment,
                    }) => Some(commitment),
                    _ => None,
                },
                _ => None,
            };
            if let Some(root) = trade_root {
                let batch = trade_batches
                    .iter()
                    .find(|batch| batch.root().ok() == Some(root))?;
                for policy in batch.policies() {
                    let id = policy.authorization_id().ok()?;
                    authorization_bytes.push(Some(proof_by_hash.remove(&id).flatten()?));
                }
            } else {
                authorization_bytes.push(proof_by_hash.remove(&id).unwrap_or(None));
            }
            let page = &complete_txs[group.body_start];
            if page.body.validity_bitmap & noid_tx::PAGED_SPEND_CONTRACT_BIT != 0 {
                if !has_versioned_class || index != object_openings.len() || group.page_count != 1 {
                    tracing::error!("selected contracts do not form a single-page prefix");
                    return None;
                }
                let Some(opening) = opening_by_hash.remove(&id) else {
                    tracing::error!("selected contract has no retained opening");
                    return None;
                };
                object_openings.push(opening);
            }
        }
        Some(BlockTemplate {
            inner,
            difficulty_target,
            miner_address,
            timestamp,
            parent,
            authorization_bytes,
            object_openings,
            native_openings,
            trade_batches,
            v2_class,
            v21_class,
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

pub(crate) fn v2_full_selection_budget(
    config: noid_recursive::acceptance::history_step::v2::V2Config,
) -> noid_chain::mempool::BlockSelectionBudget {
    let financial = config.native_financial_config().map(|financial| {
        let trade = config.native_sequential_config();
        noid_chain::mempool::NativeFinancialBudget {
            actions: financial.action_capacity,
            definitions: financial.kernel.definition_capacity,
            markets: trade.map_or(0, |trade| trade.markets),
            policies: trade.map_or(0, |trade| trade.policies),
            funding: trade.map_or(0, |trade| trade.funding),
            owner_operations: financial.phase
                != noid_recursive::acceptance::trace::native_assets::financial_kernel::FinancialKernelPhase::Settlement,
        }
    });
    noid_chain::mempool::BlockSelectionBudget {
        pages: config.pages(),
        live_inputs: config.max_live_inputs(),
        contract_calls: config.contract_slots(),
        native_headers: config.native_header_capacity().unwrap_or(0),
        native_records: config.native_action_capacity().unwrap_or(0),
        owner_authorizations: config.pages(),
        financial,
    }
}

fn v2_selection_budget(
    config: noid_recursive::acceptance::history_step::v2::V2Config,
    height: u64,
) -> noid_chain::mempool::BlockSelectionBudget {
    let system_pages = usize::from(
        noid_chain::consensus::development_allocation::development_payout_due_at_height(height),
    );
    let mut budget = v2_full_selection_budget(config);
    budget.pages = budget.pages.saturating_sub(system_pages);
    budget
}

fn user_page_limit_for_child(parent_height: u64, max_effective_pages: usize) -> Option<usize> {
    user_page_limit_with_activation(
        parent_height,
        max_effective_pages,
        noid_chain::consensus::params::V1_1_ACTIVATION_HEIGHT,
    )
}

fn user_page_limit_with_activation(
    parent_height: u64,
    max_effective_pages: usize,
    activation_height: Option<u64>,
) -> Option<usize> {
    let child_height = parent_height.checked_add(1)?;
    let consensus_max = noid_chain::consensus::params::BLOCK_MAX_USER_PAGES;
    // This is a producer-only ceiling. Keep the hardware observation independent
    // of the candidate's activation gate so reorgs do not reset calibration.
    let producer_max = if activation_height.is_some_and(|height| child_height >= height) {
        consensus_max
    } else {
        noid_chain::consensus::paged_spend::BlockProofClass::B25.page_capacity()
    };
    let system_positions = usize::from(
        noid_chain::consensus::development_allocation::development_payout_due_at_height(
            child_height,
        ),
    );
    Some(
        max_effective_pages
            .min(producer_max)
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
        let payout_height = if noid_chain::consensus::params::ISOLATED_V2_FORK_TESTNET {
            noid_chain::consensus::params::V2_ACTIVATION_HEIGHT.unwrap() + 2879
        } else {
            TARGET_BLOCKS_PER_DAY
        };

        assert_eq!(user_page_limit_for_child(payout_height - 2, 25), Some(25));
        assert_eq!(user_page_limit_for_child(payout_height - 1, 25), Some(24));
        assert_eq!(
            user_page_limit_with_activation(payout_height - 1, 255, Some(10)),
            Some(254)
        );
        assert_eq!(
            user_page_limit_with_activation(payout_height - 1, 255, None),
            Some(24)
        );
        assert_eq!(
            user_page_limit_for_child(DEVELOPMENT_ALLOCATION_END_HEIGHT, 25),
            Some(25)
        );
        assert_eq!(user_page_limit_for_child(u64::MAX, 25), None);
    }

    #[test]
    fn v2_budget_uses_every_pinned_resource_and_reserves_system_pages() {
        use noid_chain::consensus::forks::ACTIVE_SCHEDULE;
        use noid_recursive::acceptance::history_step::v2::V2Config;
        let Some(at) = ACTIVE_SCHEDULE.v2() else {
            return;
        };
        let payout = at.height() + 86_400 / at.block_time() - 1;
        for (m, pages, inputs, calls) in [
            (23, 63, 504, 63),
            (24, 206, 504, 63),
            (24, 211, 384, 64),
            (24, 223, 1020, 64),
            (24, 255, 1020, 26),
        ] {
            let config = V2Config::with_limits(m, pages, inputs, calls, ACTIVE_SCHEDULE).unwrap();
            for (height, reserved) in [
                (at.height(), 0),
                (payout - 1, 0),
                (payout, 1),
                (payout + 1, 0),
            ] {
                let budget = v2_selection_budget(config, height);
                assert_eq!(budget.pages, pages - reserved);
                assert_eq!(budget.live_inputs, inputs);
                assert_eq!(budget.contract_calls, calls);
            }
        }
    }

    #[test]
    fn activation_uses_candidate_height_and_unset_height_stays_small() {
        assert_eq!(user_page_limit_with_activation(8, 255, Some(10)), Some(25));
        assert_eq!(user_page_limit_with_activation(9, 255, Some(10)), Some(255));
        assert_eq!(user_page_limit_with_activation(10, 25, Some(10)), Some(25));
        assert_eq!(
            user_page_limit_with_activation(10, usize::MAX, Some(10)),
            Some(255)
        );
        assert_eq!(user_page_limit_with_activation(100, 255, None), Some(25));
        assert_eq!(
            user_page_limit_with_activation(u64::MAX, 255, Some(10)),
            None
        );
        assert_eq!(
            user_page_limit_for_child(9, 255),
            user_page_limit_with_activation(
                9,
                255,
                noid_chain::consensus::params::V1_1_ACTIVATION_HEIGHT,
            )
        );
    }

    #[test]
    fn running_miner_keeps_first_sample_across_activation_and_reorgs() {
        use crate::proof_capacity::AdaptiveProofCapacity;
        use noid_chain::consensus::paged_spend::BlockProofClass;
        use std::time::Duration;

        for (sample_ms, post_activation_max) in [(5_000, 255), (5_001, 25)] {
            let mut capacity = AdaptiveProofCapacity::default();
            assert_eq!(
                user_page_limit_with_activation(9, capacity.page_limit(), Some(10)),
                Some(25),
            );
            capacity.observe_preparation(BlockProofClass::B25, Duration::from_millis(sample_ms));
            for (parent, expected) in [
                (8, 25),
                (9, post_activation_max),
                (10, post_activation_max),
                (8, 25),
                (9, post_activation_max),
            ] {
                assert_eq!(
                    user_page_limit_with_activation(parent, capacity.page_limit(), Some(10)),
                    Some(expected),
                );
            }
        }
    }

    #[test]
    fn actual_page_count_selects_proof_without_occupancy_threshold() {
        use noid_chain::consensus::paged_spend::BlockProofClass;
        for pages in [0, 1, 24, 25] {
            assert_eq!(
                BlockProofClass::for_page_count(pages),
                Some(BlockProofClass::B25)
            );
        }
        for pages in [26, 30, 70, 127, 128, 129, 254, 255] {
            assert_eq!(
                BlockProofClass::for_page_count(pages),
                Some(BlockProofClass::B255)
            );
        }
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
