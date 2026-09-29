// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `AsyncMempool` — async wrapper around the synchronous `noid_chain::Mempool`.
//!
//! ## Architecture
//!
//! ```text
//!  submit(PagedSpendIntent)
//!    │
//!    ├─ Stateless check (no lock): canonical body logic + derived txid
//!    │
//!    ├─ Pre-proof filter (lock, brief): all cheap checks on current view
//!    │   fee floor → consensus → epoch_anchor → slot conflicts → slot state
//!    │   Extracts log_slots: u32 only — NO ChainView clone.
//!    │   DoS guard: invalid txs rejected here, never reach proof verification.
//!    │
//!    ├─ selected-ZK authorization verification (no lock), semaphore-bounded
//!    │
//!    └─ Final admission (lock): re-run all checks against current state (TOCTOU guard)
//!                        anchor_height derived here → pool.admit
//!
//!  on_new_block() ──► [remove confirmed] ──► [evict expired] ──► [update chain view]
//!
//!  select_for_block() ──► fee-sorted list of MempoolEntry (verified txs only)
//! ```
//!
//! ## Pre-proving cache
//!
//! When a wallet submits a `PagedSpendIntent`, it includes a `WalletAuthorizationBundle`
//! (one versioned witness-hiding proof). The pool retains one immutable intent
//! allocation and borrows the bundle suffix from it during block assembly.
//! The block assembler uses cached bundles so that `prove_block` only
//! needs to run the unified block-level SpineGKR + single FRI — the
//! per-tx wallet work is already done.

use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::{broadcast, Mutex, Semaphore};

use noid_chain::consensus::params::BLOCK_MAX_USER_PAGES;
use noid_chain::consensus::wire_limits::{MAX_AUTHORIZATION_BYTES, MAX_TX_INTENT_BYTES_GLOBAL};
use noid_chain::consensus::{fee_breakdown, tx_epoch_anchor_height_for_child};
use noid_chain::fri_state::SlotValue;
use noid_chain::mempool::MempoolEntry;
use noid_chain::Mempool;
use noid_poseidon2b::primitives::{Address, TxBodyHash};
use noid_tx::{
    validate_paged_spend, PagedSpendFacts, PagedSpendIntent, TxPage, PAGED_SPEND_INTENT_MARKER,
};

use crate::config::MempoolConfig;
use crate::contracts::{check_candidate_call, DecodedMempoolIntent};
use crate::error::SubmitError;
use crate::event::{EvictReason, MempoolEvent};
use crate::floor::FeeFloor;
use crate::view::ChainView;

/// One CPU-heavy authorization verification ready to run on a node-owned
/// executor. The mempool owns protocol validation; the embedding node owns
/// process-wide CPU admission.
pub type AuthorizationVerificationTask = Box<dyn FnOnce() -> Result<(), String> + Send + 'static>;

/// Executor hook for authorization verification. The default runs the task on
/// the surrounding `spawn_blocking` thread. Production nodes replace it with
/// their common proof Rayon pool so mempool traffic cannot activate an
/// independent global pool beside Block/Link/Verify.
pub type AuthorizationVerificationExecutor =
    Arc<dyn Fn(AuthorizationVerificationTask) -> Result<(), String> + Send + Sync + 'static>;

// ---------------------------------------------------------------------------
// Internal state (held under Mutex)
// ---------------------------------------------------------------------------

pub(crate) struct MempoolState {
    /// Synchronous core pool (conflict tracking, fee ordering).
    pub pool: Mempool,
    /// Chain view snapshot — updated on every new block.
    pub view: ChainView,
    /// Dynamic fee floor.
    pub floor: FeeFloor,
    /// Input slot indices currently held by admitted txs. O(1) conflict check.
    pub admitted_input_slots: HashSet<u32>,
    /// Output slot indices currently held by admitted txs. O(1) conflict check.
    pub admitted_output_slots: HashSet<u32>,
}

/// Mempool policy follows the candidate block, like the producer's activation
/// gate. Refresh only on existing mutations; every consumer reads one floor.
fn refresh_fee_floor(state: &mut MempoolState, config: &MempoolConfig, retained_bytes: usize) {
    state.floor.update_pressure(
        noid_chain::consensus::params::v1_1_active(state.view.tip_height.saturating_add(1)),
        state.pool.len(),
        config.capacity,
        retained_bytes,
        config.max_total_intent_bytes,
    );
}

/// Compact immutable RPC/diagnostic projection of one mempool entry.
///
/// This type deliberately contains no intent or authorization byte vector, so
/// inspecting a full pool cannot duplicate its retained proof payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolEntryMetadata {
    pub tx_hash: TxBodyHash,
    pub fee_micronoid: u64,
    pub fee_rate: u64,
    pub n_inputs: u16,
    pub n_outputs: u16,
    pub page_count: u16,
    pub admitted_height: u64,
    pub has_authorization: bool,
}

/// One bounded RPC lookup. The opening is public and fixed-size; the full
/// intent and detached authorization stay inside the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MempoolEntryDetails {
    pub metadata: MempoolEntryMetadata,
    pub contract_opening: Option<[u8; noid_tx::experimental_object::OPENING_BYTES]>,
}

/// One lock-consistent compact view of fee floor and all entry metadata.
#[derive(Debug, PartialEq, Eq)]
pub struct MempoolMetadataSnapshot {
    pub fee_floor: u64,
    pub entries: Vec<MempoolEntryMetadata>,
}

/// Constant-size lock-consistent mempool pressure snapshot for status UIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolUsageSnapshot {
    pub size: usize,
    pub capacity: usize,
    pub intent_bytes: usize,
    pub max_intent_bytes: usize,
    pub fee_floor: u64,
}

/// Minimal owned block-template selection.
///
/// Raw `PagedSpendIntent` bytes are a networking cache and are never cloned into the
/// miner. Only the semantic body and the cached authorization bundle cross the
/// mempool lock.
#[derive(Debug)]
pub struct SelectedMempoolEntry {
    pub pages: Vec<TxPage>,
    pub logical_txid: TxBodyHash,
    pub cached_authorization: Option<Vec<u8>>,
    pub contract_opening: Option<noid_tx::experimental_object::ObjectOpening>,
}

/// A lock-consistent v2 mining choice. Only the winning selection's proof
/// bytes are copied out of the pool. Large must be explicitly offered by the
/// producer; equal claimable fees keep the smaller class.
#[derive(Debug)]
pub struct V2MempoolSelection {
    pub large_class: bool,
    pub entries: Vec<SelectedMempoolEntry>,
    pub pending_outputs: HashSet<u32>,
}

fn entry_metadata(
    hash: TxBodyHash,
    entry: &noid_chain::mempool::MempoolEntry,
) -> MempoolEntryMetadata {
    MempoolEntryMetadata {
        tx_hash: hash,
        fee_micronoid: entry.spend.fee,
        fee_rate: entry.fee_rate,
        n_inputs: entry.spend.live_inputs,
        n_outputs: entry.spend.live_outputs,
        page_count: entry.pages.len() as u16,
        admitted_height: entry.admitted_height,
        has_authorization: entry.cached_authorization().is_some(),
    }
}

// ---------------------------------------------------------------------------
// AsyncMempool
// ---------------------------------------------------------------------------

/// Async, thread-safe mempool for the Paranoid full node.
///
/// Clone is O(1) — the inner state is reference-counted.
#[derive(Clone)]
pub struct AsyncMempool {
    state: Arc<Mutex<MempoolState>>,
    events: broadcast::Sender<MempoolEvent>,
    config: Arc<MempoolConfig>,
    /// Semaphore limiting concurrent authorization verification tasks.
    /// Bounds CPU usage: at most `config.auth_verify_workers` proofs in flight.
    /// Set to 0 in config → semaphore with MAX permits (no limit).
    auth_verify_semaphore: Arc<Semaphore>,
    auth_verify_executor: AuthorizationVerificationExecutor,
}

impl AsyncMempool {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a new empty mempool with the given initial chain view.
    pub fn new(view: ChainView, config: MempoolConfig) -> Self {
        let (events, _) = broadcast::channel(1024);
        let floor = FeeFloor::new(config.fee_floor_window);
        let mut state = MempoolState {
            pool: Mempool::new(config.capacity),
            view,
            floor,
            admitted_input_slots: HashSet::new(),
            admitted_output_slots: HashSet::new(),
        };
        refresh_fee_floor(&mut state, &config, 0);
        let max_permits = if config.auth_verify_workers == 0 {
            // 0 = unlimited concurrency; verification is still required
            usize::MAX / 2 // Semaphore::MAX_PERMITS
        } else {
            config.auth_verify_workers
        };
        let auth_verify_semaphore = Arc::new(Semaphore::new(max_permits));
        Self {
            state: Arc::new(Mutex::new(state)),
            events,
            config: Arc::new(config),
            auth_verify_semaphore,
            auth_verify_executor: Arc::new(|task| task()),
        }
    }

    /// Route authorization proof work through a process-owned CPU executor.
    /// Configure this before cloning the mempool into RPC/P2P tasks.
    pub fn with_authorization_verification_executor(
        mut self,
        executor: AuthorizationVerificationExecutor,
    ) -> Self {
        self.auth_verify_executor = executor;
        self
    }

    /// Subscribe to mempool events (P2P, RPC WebSocket subscriptions, miner wakeup).
    pub fn subscribe(&self) -> broadcast::Receiver<MempoolEvent> {
        self.events.subscribe()
    }

    // -----------------------------------------------------------------------
    // Tx submission
    // -----------------------------------------------------------------------

    /// Submit one complete `PagedSpendIntent` for admission.
    ///
    /// Runs the full native admission pipeline:
    /// 1. Fee ≥ dynamic floor
    /// 2. Basic consensus checks (fee overflow, body hash, anchor)
    /// 3. epoch_anchor equals the one canonical next-block epoch anchor
    /// 4. No slot conflict with admitted mempool txs
    /// 5. Input slots live in state, output slots empty
    ///
    /// Selected-ZK authorization verification is performed synchronously (in a
    /// `spawn_blocking` task) BEFORE the pool mutex is acquired, so invalid
    /// proofs are rejected at the mempool boundary without holding the lock.
    ///
    /// Returns the `TxBodyHash` on success.
    pub async fn submit(
        &self,
        intent: PagedSpendIntent,
        intent_bytes: Vec<u8>,
    ) -> Result<TxBodyHash, SubmitError> {
        self.submit_inner(intent, intent_bytes, None).await
    }

    /// Shared bounded entry point for ordinary spends and contract calls.
    pub async fn submit_encoded(&self, bytes: Vec<u8>) -> Result<TxBodyHash, SubmitError> {
        let decoded = DecodedMempoolIntent::from_bytes(&bytes)?;
        self.submit_decoded(decoded, bytes).await
    }

    /// A syntax decode grants no admission authority. Retained bytes are
    /// rebound here before State, activation and authorization checks.
    pub async fn submit_decoded(
        &self,
        decoded: DecodedMempoolIntent,
        bytes: Vec<u8>,
    ) -> Result<TxBodyHash, SubmitError> {
        self.submit_inner(decoded.intent, bytes, decoded.opening)
            .await
    }

    async fn submit_inner(
        &self,
        intent: PagedSpendIntent,
        intent_bytes: Vec<u8>,
        opening: Option<noid_tx::experimental_object::ObjectOpening>,
    ) -> Result<TxBodyHash, SubmitError> {
        if intent_bytes.len() > MAX_TX_INTENT_BYTES_GLOBAL {
            return Err(SubmitError::IntentTooLarge {
                actual: intent_bytes.len(),
                max: MAX_TX_INTENT_BYTES_GLOBAL,
            });
        }
        let ordinary_bytes = if let Some(opening) = &opening {
            use noid_tx::experimental_object::{INTENT_MAGIC, INTENT_PREFIX_BYTES};
            let prefix = intent_bytes.get(..INTENT_PREFIX_BYTES).ok_or_else(|| {
                SubmitError::MalformedIntent("truncated contract envelope".into())
            })?;
            let canonical = opening
                .to_bytes()
                .map_err(|e| SubmitError::MalformedIntent(e.to_string()))?;
            if !prefix.starts_with(INTENT_MAGIC) || prefix[INTENT_MAGIC.len()..] != canonical {
                return Err(SubmitError::MalformedIntent(
                    "decoded opening does not match retained wire bytes".into(),
                ));
            }
            &intent_bytes[INTENT_PREFIX_BYTES..]
        } else {
            &intent_bytes
        };
        if !canonical_intent_bytes_match(&intent, ordinary_bytes) {
            return Err(SubmitError::MalformedIntent(
                "decoded intent does not match retained canonical wire bytes".into(),
            ));
        }
        // ── Stateless sanity check (no lock, no IO) ────────────────────
        // Revalidate group semantics at this trust boundary even when the
        // caller already used the bounded decoder.
        let spend = validate_paged_spend(&intent.pages)
            .map_err(|e| SubmitError::MalformedIntent(format!("PagedSpend: {e}")))?;
        let txid = spend.logical_txid;

        // Relay policy: these bits require the complete bounded envelope.
        // Published legacy block/proof validation is unaffected.
        if opening.is_none()
            && intent
                .pages
                .iter()
                .any(|page| page.body.validity_bitmap & noid_tx::PAGED_SPEND_V2_CONTRACT_MASK != 0)
        {
            return Err(SubmitError::MalformedIntent(
                "contract call requires its opening envelope".into(),
            ));
        }

        if intent.authorization_bytes.is_empty() {
            return Err(SubmitError::MissingProof);
        }
        if intent.authorization_bytes.len() > MAX_AUTHORIZATION_BYTES {
            return Err(SubmitError::ProofTooLarge {
                actual: intent.authorization_bytes.len(),
                max: MAX_AUTHORIZATION_BYTES,
            });
        }
        // ── Cheap pre-filter (lock held briefly) ─────────────────
        // Runs all cheap state checks before expensive Auth verification.
        let authorized_height = {
            let st = self.state.lock().await;
            if st.pool.contains(&txid) {
                return Err(SubmitError::AlreadyAdmitted(txid));
            }
            let projected_bytes = st
                .pool
                .total_intent_bytes()
                .saturating_add(intent_bytes.len());
            if projected_bytes > self.config.max_total_intent_bytes {
                return Err(SubmitError::BytesFull {
                    actual: projected_bytes,
                    max: self.config.max_total_intent_bytes,
                });
            }
            let _ = run_admission_checks(&intent.pages, &spend, &st, &self.config)?;
            let height = st
                .view
                .tip_height
                .checked_add(1)
                .ok_or_else(|| SubmitError::Internal("height exhausted".into()))?;
            if let Some(opening) = &opening {
                check_candidate_call(opening, &intent.pages, height)?;
            }
            height
        };

        // ── Authorization verification (CPU-heavy, outside lock, semaphore-bounded) ─
        // Runs only when the pre-filter passed — invalid fee/anchor/slot txs are
        // already gone.  Semaphore caps concurrent CPU threads.
        {
            let proof_bytes = intent.authorization_bytes.clone();
            let pages = intent.pages.clone();
            let executor = Arc::clone(&self.auth_verify_executor);
            let opening = opening.clone();

            let permit = Arc::clone(&self.auth_verify_semaphore)
                .acquire_owned()
                .await
                .map_err(|_| SubmitError::Internal("proof-verification semaphore closed".into()))?;

            tokio::task::spawn_blocking(move || {
                // Cancelling an RPC or relay future cannot cancel an already
                // running blocking worker. Keep its CPU slot until it exits.
                let _permit = permit;
                executor(Box::new(move || {
                    if let Some(opening) = opening {
                        let bundle = noid_gkr::WalletAuthorizationBundle::from_bytes(&proof_bytes)
                            .map_err(|e| format!("authorization decode: {e}"))?;
                        noid_gkr::wallet_authorization::verify_experimental_object_authorization(
                            &pages[0],
                            &opening,
                            authorized_height,
                            &bundle,
                        )
                        .map_err(|e| e.to_string())
                    } else {
                        verify_intent_authorization(&pages, &proof_bytes)
                    }
                }))
            })
            .await
            .map_err(|e| SubmitError::Internal(format!("spawn_blocking: {e}")))?
            .map_err(SubmitError::InvalidProof)?;
        }

        // ── Final admission under lock ───────────────────────
        // Re-run all cheap checks against CURRENT state: the chain may have
        // advanced during the authorization verification window (new block → new
        // spent slots and changed fee floor). This is the
        // authoritative check; the pre-filter was the DoS guard.
        let mut st = self.state.lock().await;

        let hash = spend.logical_txid;

        if st.pool.contains(&hash) {
            return Err(SubmitError::AlreadyAdmitted(hash));
        }
        let projected_bytes = st
            .pool
            .total_intent_bytes()
            .saturating_add(intent_bytes.len());
        if projected_bytes > self.config.max_total_intent_bytes {
            return Err(SubmitError::BytesFull {
                actual: projected_bytes,
                max: self.config.max_total_intent_bytes,
            });
        }

        // Re-derive anchor_height from current state (needed by pool.admit).
        let _anchor_height = run_admission_checks(&intent.pages, &spend, &st, &self.config)?;
        if let Some(opening) = &opening {
            let height = st
                .view
                .tip_height
                .checked_add(1)
                .ok_or_else(|| SubmitError::Internal("height exhausted".into()))?;
            let current = check_candidate_call(opening, &intent.pages, height)?;
            if current.authority != opening.authority_at(authorized_height) {
                return Err(SubmitError::InvalidProof(
                    "contract authority changed during authorization verification".into(),
                ));
            }
        }

        // --- Admit ---
        let fee = spend.fee;
        let tip_height = st.view.tip_height;
        match st.pool.admit(intent.pages, tip_height) {
            Ok(()) => {
                // Maintain persistent slot sets so future checks are O(1).
                let entry = st
                    .pool
                    .get(&hash)
                    .expect("newly admitted PagedSpend is indexed by logical txid");
                let input_slots: Vec<_> = entry
                    .pages
                    .iter()
                    .flat_map(|page| page.body.live_inputs())
                    .map(|(_, input)| input.slot_index)
                    .collect();
                let output_slots: Vec<_> = entry
                    .pages
                    .iter()
                    .flat_map(|page| page.body.live_outputs())
                    .map(|(_, output)| output.slot_index)
                    .collect();
                for slot in input_slots {
                    st.admitted_input_slots.insert(slot);
                }
                for slot in output_slots {
                    st.admitted_output_slots.insert(slot);
                }
            }
            Err(noid_chain::mempool::MempoolError::Full) => {
                return Err(SubmitError::Full {
                    capacity: self.config.capacity,
                });
            }
            Err(noid_chain::mempool::MempoolError::AlreadyAdmitted) => {
                return Err(SubmitError::AlreadyAdmitted(hash));
            }
            Err(e) => {
                return Err(SubmitError::Internal(format!("{e:?}")));
            }
        }

        // One immutable allocation backs durable mempool serving and every
        // broadcast subscriber. The miner's cached authorization is a borrowed
        // suffix of this allocation rather than a second retained proof copy.
        let intent_bytes: Arc<[u8]> = intent_bytes.into();
        st.pool.set_intent_bytes(&hash, Arc::clone(&intent_bytes));
        st.floor.record(fee);
        // Reuse the authoritative byte-cap calculation above; no new scan.
        refresh_fee_floor(&mut st, &self.config, projected_bytes);
        let _ = self.events.send(MempoolEvent::TxAdmitted {
            hash,
            fee,
            intent_bytes: Arc::clone(&intent_bytes),
        });
        let _ = self
            .events
            .send(MempoolEvent::TxAuthorizationVerified { hash });

        tracing::debug!(
            hash = ?hash,
            fee = fee,
            tip = st.view.tip_height,
            pool_size = st.pool.len(),
            "tx admitted to mempool"
        );

        Ok(hash)
    }

    // -----------------------------------------------------------------------
    // Block assembly
    // -----------------------------------------------------------------------

    /// Select fee-ordered indivisible groups fitting `max_pages` pages.
    ///
    /// Returns a fee-sorted list of `(Transaction, Option<cached_proof>)`.
    /// The caller (block builder) applies conflict resolution and coinbase on top.
    ///
    /// Returned txs are in descending fee-rate order with txid tie-break.
    pub async fn select_for_block(&self, max_pages: usize) -> Vec<SelectedMempoolEntry> {
        let st = self.state.lock().await;
        let limit = max_pages.min(BLOCK_MAX_USER_PAGES);
        st.pool
            .select_for_block(limit)
            .into_iter()
            .map(|entry| SelectedMempoolEntry {
                pages: entry.pages.clone(),
                logical_txid: entry.spend.logical_txid,
                cached_authorization: entry.cached_authorization().map(<[u8]>::to_vec),
                contract_opening: entry.contract_opening(),
            })
            .collect()
    }

    /// Select the same fee-ordered current-anchor prefix used by block
    /// assembly, cloning only the entries the caller can actually prove.
    ///
    /// The scan remains bounded by the consensus block maximum. Filtering is
    /// performed while entries are borrowed under the pool lock, so a
    /// memory-governed B25 template does not first clone up to 255 cached proof
    /// bundles and discard the excess.
    pub async fn select_for_block_at_anchor(
        &self,
        max_pages: usize,
        epoch_anchor: [u8; 32],
    ) -> Vec<SelectedMempoolEntry> {
        let st = self.state.lock().await;
        let limit = max_pages.min(BLOCK_MAX_USER_PAGES);
        st.pool
            .select_for_block_at_anchor(limit, &epoch_anchor)
            .into_iter()
            .map(|entry| SelectedMempoolEntry {
                pages: entry.pages.clone(),
                logical_txid: entry.spend.logical_txid,
                cached_authorization: entry.cached_authorization().map(<[u8]>::to_vec),
                contract_opening: entry.contract_opening(),
            })
            .collect()
    }

    /// Snapshot the same anchored selection and existing output reservations
    /// under one lock. Only selected proofs are copied; the rest contributes
    /// slot indices, not another payload scan or a new admission index.
    pub async fn select_for_block_at_anchor_with_output_reservations(
        &self,
        max_pages: usize,
        epoch_anchor: [u8; 32],
    ) -> (Vec<SelectedMempoolEntry>, HashSet<u32>) {
        let st = self.state.lock().await;
        let limit = max_pages.min(BLOCK_MAX_USER_PAGES);
        let entries = st
            .pool
            .select_for_block_at_anchor(limit, &epoch_anchor)
            .into_iter()
            .map(|entry| SelectedMempoolEntry {
                pages: entry.pages.clone(),
                logical_txid: entry.spend.logical_txid,
                cached_authorization: entry.cached_authorization().map(<[u8]>::to_vec),
                contract_opening: entry.contract_opening(),
            })
            .collect();
        let outputs = if st.admitted_output_slots.is_empty() {
            HashSet::new()
        } else {
            st.admitted_output_slots.clone()
        };
        (entries, outputs)
    }

    /// Use the exact pinned v2 class budgets without copying unselected
    /// authorizations. The opening stays paired with its logical transaction.
    pub async fn select_for_v2_mining(
        &self,
        small: noid_chain::mempool::BlockSelectionBudget,
        large: Option<noid_chain::mempool::BlockSelectionBudget>,
        candidate_height: u64,
        epoch_anchor: [u8; 32],
    ) -> Result<V2MempoolSelection, SubmitError> {
        let st = self.state.lock().await;
        let height = st
            .view
            .tip_height
            .checked_add(1)
            .ok_or_else(|| SubmitError::Internal("height exhausted".into()))?;
        if height != candidate_height {
            return Err(SubmitError::MalformedIntent(
                "mempool view does not match the candidate height".into(),
            ));
        }
        if !noid_chain::consensus::params::v2_active(height) {
            return Err(SubmitError::MalformedIntent(
                "v2 is not active at the candidate height".into(),
            ));
        }
        let mut selected = st.pool.select_for_block_with_budget(small, &epoch_anchor);
        let mut large_class = false;
        if let Some(budget) = large {
            let alternative = st.pool.select_for_block_with_budget(budget, &epoch_anchor);
            let claimable = |entries: &[&MempoolEntry]| -> u128 {
                entries
                    .iter()
                    .map(|entry| {
                        let burned = fee_breakdown(
                            u64::from(entry.spend.live_inputs),
                            u64::from(entry.spend.live_outputs),
                            st.view.active_slot_count,
                            st.view.log_slots(),
                        )
                        .burned;
                        u128::from(entry.spend.fee.saturating_sub(burned))
                    })
                    .sum()
            };
            if claimable(&alternative) > claimable(&selected) {
                selected = alternative;
                large_class = true;
            }
        }
        let entries = selected
            .into_iter()
            .map(|entry| SelectedMempoolEntry {
                pages: entry.pages.clone(),
                logical_txid: entry.spend.logical_txid,
                cached_authorization: entry.cached_authorization().map(<[u8]>::to_vec),
                contract_opening: entry.contract_opening(),
            })
            .collect();
        let outputs = if st.admitted_output_slots.is_empty() {
            HashSet::new()
        } else {
            st.admitted_output_slots.clone()
        };
        Ok(V2MempoolSelection {
            large_class,
            entries,
            pending_outputs: outputs,
        })
    }

    // -----------------------------------------------------------------------
    // Block confirmation
    // -----------------------------------------------------------------------

    /// Called when a new block is confirmed. Updates the chain view, removes
    /// confirmed txs, evicts expired txs, and broadcasts events.
    ///
    /// `confirmed_hashes`: derived txids of all txs in the confirmed block.
    /// `new_view`: updated chain state snapshot.
    pub async fn on_new_block(
        &self,
        confirmed_hashes: &[TxBodyHash],
        new_height: u64,
        new_view: ChainView,
    ) {
        let mut st = self.state.lock().await;

        // Remove confirmed txs.
        let removed = st.pool.on_block_confirmed(confirmed_hashes);
        for &hash in confirmed_hashes {
            let _ = self.events.send(MempoolEvent::TxConfirmed {
                hash,
                block_height: new_height,
            });
        }

        // Update chain view BEFORE eviction so anchor check uses new state.
        st.view = new_view;

        // Reuse the epoch-cleanup scan for cheap parent-context fee checks.
        // The local relay floor is admission policy, not a reason to evict an
        // already-admitted spend. No authorization proof is reprocessed;
        // bounded contract openings are rechecked at the new candidate height.
        let stale_context: Vec<_> = st
            .pool
            .iter()
            .filter_map(|(hash, entry)| {
                let reason = if entry.spend.epoch_anchor != st.view.user_epoch_anchor_id {
                    EvictReason::EpochAnchorChanged
                } else if check_candidate_resources(
                    &self.config,
                    st.view.tip_height,
                    entry.pages.len(),
                    usize::from(entry.spend.live_inputs),
                    contract_call_count(&entry.pages),
                )
                .is_err()
                {
                    EvictReason::BlockCapacityChanged
                } else if entry.spend.fee
                    < fee_breakdown(
                        u64::from(entry.spend.live_inputs),
                        u64::from(entry.spend.live_outputs),
                        st.view.active_slot_count,
                        st.view.log_slots(),
                    )
                    .required_total
                {
                    EvictReason::ConsensusFeeIncreased
                } else if let Some(reason) =
                    crate::contracts::eviction_reason(entry, st.view.tip_height.checked_add(1))
                {
                    reason
                } else {
                    return None;
                };
                Some((*hash, reason))
            })
            .collect();
        for (hash, reason) in stale_context {
            st.pool.remove(&hash);
            let _ = self.events.send(MempoolEvent::TxEvicted { hash, reason });
        }

        // Evict txs whose output slots became occupied in the new block.
        // This happens when a coinbase (from a block mined while the tx was
        // in the mempool) landed on the same slot the wallet chose for its output.
        // The wallet must re-prove with fresh slot hints.
        use noid_chain::fri_state::SlotValue;
        let output_conflicts: Vec<TxBodyHash> = st
            .pool
            .iter()
            .filter_map(|(hash, entry)| {
                let occupied = entry.pages.iter().any(|page| {
                    page.body.live_outputs().any(|(_, out)| {
                        st.view
                            .try_slot(out.slot_index)
                            .map_or(true, |slot| slot != SlotValue::EMPTY)
                    })
                });
                if occupied {
                    Some(*hash)
                } else {
                    None
                }
            })
            .collect();
        for hash in output_conflicts {
            st.pool.remove(&hash);
            tracing::debug!(?hash, "tx evicted: output slot occupied by confirmed block");
            let _ = self.events.send(MempoolEvent::TxEvicted {
                hash,
                reason: EvictReason::OutputSlotOccupied,
            });
        }

        // Evict txs whose INPUT slots are no longer live in the new state.
        //
        // After a block is applied, some input slots of pool txs may have been
        // spent by other confirmed txs (not the same tx). Those pool txs are now
        // invalid: their input slot is EMPTY (was moved elsewhere by the block).
        //
        // They also fail silently in build_block_template (apply_tx returns Err),
        // wasting template-build cycles.
        let input_consumed: Vec<TxBodyHash> = st
            .pool
            .iter()
            .filter_map(|(hash, entry)| {
                let stale = entry.pages.iter().any(|page| {
                    page.body.live_inputs().any(|(_, inp)| {
                        // Input must still hold exactly (value, creation_id,
                        // group owner) for this intent to remain includable.
                        let expected = SlotValue::with_owner_fields(
                            inp.amount,
                            inp.creation_id,
                            entry.spend.input_owner.as_fields(),
                        );
                        st.view
                            .try_slot(inp.slot_index)
                            .map_or(true, |slot| slot != expected)
                    })
                });
                if stale {
                    Some(*hash)
                } else {
                    None
                }
            })
            .collect();
        let input_evict_count = input_consumed.len();
        for hash in input_consumed {
            st.pool.remove(&hash);
            tracing::debug!(
                ?hash,
                "tx evicted: input slot consumed or changed by confirmed block"
            );
            let _ = self.events.send(MempoolEvent::TxEvicted {
                hash,
                reason: EvictReason::InputConsumed,
            });
        }
        if input_evict_count > 0 {
            tracing::debug!(
                evicted = input_evict_count,
                "evicted stale txs with consumed input slots"
            );
        }

        // Rebuild slot sets after bulk eviction (O(pool) once/block vs O(N²) per submit).
        let retained_bytes = rebuild_slot_sets(&mut st);
        refresh_fee_floor(&mut st, &self.config, retained_bytes);

        tracing::debug!(
            height = new_height,
            confirmed = confirmed_hashes.len(),
            removed_from_pool = removed,
            pool_size = st.pool.len(),
            "mempool updated after new block"
        );
    }

    /// Re-admit transactions that were reclaimed by a chain reorg.
    ///
    /// These TXs were in reverted blocks. We log the count for observability
    /// and evict any that happen to be sitting in the pool already (duplicate
    /// re-submission race). Full re-admission with fresh authorizations is the
    /// wallet's responsibility — wallets detect the unconfirmed state via
    /// wallet scan and resubmit.
    ///
    /// NOTE: We do not have the original authorization bytes after a reorg (they
    /// are not persisted). Durable TX storage could enable
    /// automatic re-admission without wallet involvement.
    pub async fn readmit_after_reorg(&self, tx_hashes: Vec<TxBodyHash>) {
        if tx_hashes.is_empty() {
            return;
        }

        tracing::info!(
            count = tx_hashes.len(),
            "reorg: {} TX(s) reclaimed — wallets should resubmit if needed",
            tx_hashes.len()
        );

        // Evict any entries with the same hash that may have been re-submitted
        // concurrently (unlikely but keeps the pool clean).
        let mut st = self.state.lock().await;
        let mut removed = false;
        for hash in &tx_hashes {
            if st.pool.contains(hash) {
                st.pool.remove(hash);
                removed = true;
                tracing::debug!(?hash, "reorg: removed re-submitted duplicate from pool");
            }
        }
        if removed {
            let retained_bytes = rebuild_slot_sets(&mut st);
            refresh_fee_floor(&mut st, &self.config, retained_bytes);
        } else if st.pool.is_empty() {
            refresh_fee_floor(&mut st, &self.config, 0);
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Number of transactions currently in the pool.
    pub async fn len(&self) -> usize {
        self.state.lock().await.pool.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Current dynamic fee floor (μNOID).
    pub async fn fee_floor(&self) -> u64 {
        self.state.lock().await.floor.current()
    }

    /// Snapshot of output slots currently reserved by admitted mempool txs.
    pub async fn reserved_output_slots(&self) -> HashSet<u32> {
        self.state.lock().await.admitted_output_slots.clone()
    }

    /// Snapshot of input slots currently reserved by admitted mempool txs.
    pub async fn reserved_input_slots(&self) -> HashSet<u32> {
        self.state.lock().await.admitted_input_slots.clone()
    }

    /// Atomically snapshot both input and output reservations.
    ///
    /// Wallet reloads use this instead of two independent reads so an
    /// intervening admission/eviction cannot leave their pending sets sourced
    /// from different mempool states.
    pub async fn reserved_slots(&self) -> (HashSet<u32>, HashSet<u32>) {
        let state = self.state.lock().await;
        (
            state.admitted_input_slots.clone(),
            state.admitted_output_slots.clone(),
        )
    }

    /// Current chain occupancy used for fee estimation: (active slots, log_slots).
    pub async fn fee_context(&self) -> (u64, u32) {
        let st = self.state.lock().await;
        (st.view.active_slot_count, st.view.log_slots())
    }

    /// Cheap wallet preflight against the same candidate-height limits used
    /// on both sides of authorization verification. No proof is checked here.
    pub async fn check_candidate_resources(
        &self,
        pages: usize,
        inputs: usize,
        calls: usize,
    ) -> Result<(), SubmitError> {
        let st = self.state.lock().await;
        check_candidate_resources(&self.config, st.view.tip_height, pages, inputs, calls)
    }

    /// Pending value sent to an external owner, excluding change from that
    /// same owner. The underlying index is maintained at admission/removal.
    pub async fn pending_incoming_for_owner(&self, owner: &Address) -> u64 {
        self.state
            .lock()
            .await
            .pool
            .pending_incoming_for_owner(owner)
    }

    /// Snapshot compact RPC metadata without cloning intent/proof payloads.
    pub async fn metadata_snapshot(&self) -> MempoolMetadataSnapshot {
        let st = self.state.lock().await;
        MempoolMetadataSnapshot {
            fee_floor: st.floor.current(),
            entries: st
                .pool
                .iter()
                .map(|(hash, entry)| entry_metadata(*hash, entry))
                .collect(),
        }
    }

    /// Read count and retained-byte pressure without cloning entry metadata or
    /// any transaction/proof payload.
    pub async fn usage_snapshot(&self) -> MempoolUsageSnapshot {
        let state = self.state.lock().await;
        MempoolUsageSnapshot {
            size: state.pool.len(),
            capacity: self.config.capacity,
            intent_bytes: state.pool.total_intent_bytes(),
            max_intent_bytes: self.config.max_total_intent_bytes,
            fee_floor: state.floor.current(),
        }
    }

    /// Compact, consistent recovery inventory without waiting behind block
    /// application or template selection. A busy pool defers background sync
    /// to a later timer tick; the network event loop must remain available.
    pub fn try_recovery_inventory(&self) -> Option<(MempoolUsageSnapshot, Vec<TxBodyHash>)> {
        let state = self.state.try_lock().ok()?;
        let usage = MempoolUsageSnapshot {
            size: state.pool.len(),
            capacity: self.config.capacity,
            intent_bytes: state.pool.total_intent_bytes(),
            max_intent_bytes: self.config.max_total_intent_bytes,
            fee_floor: state.floor.current(),
        };
        let ids = state.pool.iter().map(|(hash, _)| *hash).collect();
        Some((usage, ids))
    }

    /// O(1) compact lookup without cloning the entry's retained byte payloads.
    pub async fn get_entry_metadata(&self, hash: &TxBodyHash) -> Option<MempoolEntryMetadata> {
        let st = self.state.lock().await;
        st.pool.get(hash).map(|entry| entry_metadata(*hash, entry))
    }

    /// Read metadata and the optional public opening from the same admission
    /// snapshot, copying at most one 699-byte opening.
    pub async fn get_entry_details(&self, hash: &TxBodyHash) -> Option<MempoolEntryDetails> {
        let st = self.state.lock().await;
        let entry = st.pool.get(hash)?;
        Some(MempoolEntryDetails {
            metadata: entry_metadata(*hash, entry),
            contract_opening: entry.contract_opening_bytes().copied(),
        })
    }

    /// Nonblocking relay-cache check. `None` means the pool is being updated;
    /// callers must forfeit the shortcut, not stall the swarm or assume that
    /// an old admission still survives a confirmation, eviction or reorg.
    pub fn try_contains(&self, hash: &TxBodyHash) -> Option<bool> {
        self.state
            .try_lock()
            .ok()
            .map(|state| state.pool.contains(hash))
    }

    /// Clone at most one bounded mempool-sync response while holding one
    /// consistent pool lock.
    pub async fn intent_bytes_prefix(
        &self,
        max_txs: usize,
        max_total_bytes: usize,
        max_tx_bytes: usize,
    ) -> Vec<Vec<u8>> {
        let st = self.state.lock().await;
        st.pool
            .intent_bytes_prefix(max_txs, max_total_bytes, max_tx_bytes)
    }

    /// Bounded missing-only reconciliation. Retained proof bytes are cloned
    /// only after exclusion and response-size checks under one pool lock.
    pub async fn intent_bytes_missing(
        &self,
        known: &[[u8; 32]],
        max_txs: usize,
        max_total_bytes: usize,
        max_tx_bytes: usize,
    ) -> Vec<Vec<u8>> {
        self.state.lock().await.pool.intent_bytes_missing(
            known,
            max_txs,
            max_total_bytes,
            max_tx_bytes,
        )
    }

    /// Update the chain view without applying a new block.
    /// Used on startup (initial state) or after a reorg.
    pub async fn update_chain_view(&self, view: ChainView) {
        // A replacement (including a same-height reorg) can change anchors,
        // slots or contract results. Recheck rather than retaining stale calls.
        self.on_new_block(&[], view.tip_height, view).await;
    }

    /// Serialized owner-auth proof bytes for the given admitted tx body
    /// hashes — the byte-exact objects this pool cryptographically verified
    /// at admission. Block acceptance uses them as a re-verification fast
    /// path: a block-carried proof that serializes to the same bytes needs
    /// no second verification; anything else falls back to the full check.
    pub async fn verified_authorization_proof_bytes(
        &self,
        hashes: &[TxBodyHash],
    ) -> std::collections::HashMap<[u8; 32], Vec<u8>> {
        use noid_gkr::WalletAuthorizationBundle;
        let mut out = std::collections::HashMap::with_capacity(hashes.len());
        for hash in hashes {
            // Clone only this one bounded bundle while holding the lock. The
            // raw intent (which contains the same authorization again) remains
            // resident in the pool and no all-entry byte snapshot is built.
            let authorization = {
                let state = self.state.lock().await;
                state
                    .pool
                    .get(hash)
                    .and_then(|entry| entry.cached_authorization().map(<[u8]>::to_vec))
            };
            let Some(authorization) = authorization else {
                continue;
            };
            let Ok(bundle) = WalletAuthorizationBundle::from_bytes(&authorization) else {
                continue;
            };
            let Some(proof_bytes) = bundle.proof_wire_bytes() else {
                continue;
            };
            out.insert(hash.0, proof_bytes);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Helper: all cheap admission checks
// ---------------------------------------------------------------------------

fn contract_call_count(pages: &[TxPage]) -> usize {
    pages
        .iter()
        .filter(|page| page.body.validity_bitmap & noid_tx::PAGED_SPEND_CONTRACT_BIT != 0)
        .count()
}

fn check_candidate_resources(
    config: &MempoolConfig,
    tip_height: u64,
    pages: usize,
    inputs: usize,
    calls: usize,
) -> Result<(), SubmitError> {
    let height = tip_height
        .checked_add(1)
        .ok_or_else(|| SubmitError::Internal("height exhausted".into()))?;
    config.check_resources(height, pages, inputs, calls)
}

/// Bind the semantic object to its retained wire allocation without encoding
/// or cloning the potentially large authorization proof a second time.
fn canonical_intent_bytes_match(intent: &PagedSpendIntent, bytes: &[u8]) -> bool {
    let Ok(auth_len) = u32::try_from(intent.authorization_bytes.len()) else {
        return false;
    };
    let Ok(auth_offset) = intent.authorization_wire_offset() else {
        return false;
    };
    let Some(expected_len) = auth_offset.checked_add(auth_len as usize) else {
        return false;
    };
    if bytes.len() != expected_len {
        return false;
    }

    let mut prefix = Vec::with_capacity(auth_offset);
    prefix.push(PAGED_SPEND_INTENT_MARKER);
    prefix.extend_from_slice(&(intent.pages.len() as u16).to_le_bytes());
    for page in &intent.pages {
        if page.encode(&mut prefix).is_err() {
            return false;
        }
    }
    prefix.extend_from_slice(&auth_len.to_le_bytes());
    prefix.len() == auth_offset
        && bytes.starts_with(&prefix)
        && bytes[auth_offset..] == intent.authorization_bytes
}

/// Run every cheap admission check against `st`.
///
/// Called **twice** per `submit`:
/// - Pre-proof filter (DoS guard): rejects invalid txs before CPU-heavy work.
/// - Post-proof TOCTOU guard: final authority against current state.
///
/// Returns `anchor_height` (needed by `pool.admit` for expiry tracking).
/// The pre-filter discards it; the final admission step uses it.
fn run_admission_checks(
    pages: &[TxPage],
    spend: &PagedSpendFacts,
    st: &MempoolState,
    config: &MempoolConfig,
) -> Result<u64, SubmitError> {
    check_candidate_resources(
        config,
        st.view.tip_height,
        pages.len(),
        usize::from(spend.live_inputs),
        contract_call_count(pages),
    )?;
    // Dynamic fee floor layered over the deterministic consensus minimum.
    let consensus_required = fee_breakdown(
        u64::from(spend.live_inputs),
        u64::from(spend.live_outputs),
        st.view.active_slot_count,
        st.view.log_slots(),
    )
    .required_total;
    let required = st.floor.current().max(consensus_required);
    let actual = spend.fee;
    if actual < required {
        return Err(SubmitError::Consensus(
            noid_chain::consensus::ConsensusError::BelowMinFee { required, actual },
        ));
    }

    validate_paged_spend(pages)
        .map_err(|error| SubmitError::MalformedIntent(format!("PagedSpend: {error}")))?;
    if spend.epoch_anchor == [0u8; 32] {
        return Err(SubmitError::Consensus(
            noid_chain::consensus::ConsensusError::BadEpochAnchor,
        ));
    }

    // Epoch anchor is the one start-of-next-block transaction-epoch anchor.
    // Returns its height for deterministic mempool bookkeeping.
    let anchor_height = tx_epoch_anchor_height_for_child(
        st.view
            .tip_height
            .checked_add(1)
            .ok_or_else(|| SubmitError::Internal("height exhausted".into()))?,
    );
    if st.view.user_epoch_anchor_id == [0u8; 32]
        || spend.epoch_anchor != st.view.user_epoch_anchor_id
    {
        return Err(SubmitError::Consensus(
            noid_chain::consensus::ConsensusError::BadEpochAnchor,
        ));
    }

    // No slot conflict with currently admitted txs (O(inputs + outputs)).
    check_slot_conflicts_with_pool(pages, &st.admitted_input_slots, &st.admitted_output_slots)?;

    // Input slots must be live in state.
    check_input_slots(pages, spend, &st.view)?;

    // Output slots must be empty in state.
    check_output_slots(pages, &st.view)?;

    Ok(anchor_height)
}

// ---------------------------------------------------------------------------
// Helper: rebuild admitted slot sets from current pool (O(pool), after eviction)
// ---------------------------------------------------------------------------

fn rebuild_slot_sets(st: &mut MempoolState) -> usize {
    st.admitted_input_slots.clear();
    st.admitted_output_slots.clear();
    let mut retained_bytes = 0usize;
    for (_, entry) in st.pool.iter() {
        // Account for bytes inside the existing cleanup walk, without
        // cloning payloads or adding a separate full-pool pass.
        retained_bytes = retained_bytes.saturating_add(entry.intent_bytes.len());
        for page in &entry.pages {
            for (_, inp) in page.body.live_inputs() {
                st.admitted_input_slots.insert(inp.slot_index);
            }
            for (_, out) in page.body.live_outputs() {
                st.admitted_output_slots.insert(out.slot_index);
            }
        }
    }
    retained_bytes
}

// ---------------------------------------------------------------------------
// Helper: slot conflict with admitted pool — O(MAX_INPUTS + MAX_OUTPUTS)
// ---------------------------------------------------------------------------

fn check_slot_conflicts_with_pool(
    pages: &[TxPage],
    pool_inputs: &HashSet<u32>,
    pool_outputs: &HashSet<u32>,
) -> Result<(), SubmitError> {
    for page in pages {
        for (_, inp) in page.body.live_inputs() {
            if pool_inputs.contains(&inp.slot_index) {
                return Err(SubmitError::Consensus(
                    noid_chain::consensus::ConsensusError::SlotConflict,
                ));
            }
        }
        for (_, out) in page.body.live_outputs() {
            if pool_outputs.contains(&out.slot_index) {
                return Err(SubmitError::Consensus(
                    noid_chain::consensus::ConsensusError::SlotConflict,
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: input slots must be live in state
// ---------------------------------------------------------------------------

fn check_input_slots(
    pages: &[TxPage],
    spend: &PagedSpendFacts,
    view: &ChainView,
) -> Result<(), SubmitError> {
    for page in pages {
        for (_, inp) in page.body.live_inputs() {
            let idx = inp.slot_index;
            if (idx as u64) >= view.num_slots {
                return Err(SubmitError::Consensus(
                    noid_chain::consensus::ConsensusError::ShapeMismatch(format!(
                        "input slot {idx} out of range"
                    )),
                ));
            }
            let expected = SlotValue::with_owner_fields(
                inp.amount,
                inp.creation_id,
                spend.input_owner.as_fields(),
            );
            let actual = view.try_slot(idx).map_err(|error| {
                SubmitError::Internal(format!("chain state read failed: {error}"))
            })?;
            if actual != expected {
                tracing::warn!(
                    slot_index = idx,
                    expected_value = inp.amount,
                    expected_creation_id = inp.creation_id,
                    actual_empty = actual.is_empty(),
                    "check_input_slots: canonical slot mismatch"
                );
                return Err(SubmitError::Consensus(
                    noid_chain::consensus::ConsensusError::BadStateRoot,
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: output slots must be empty in state
// ---------------------------------------------------------------------------

fn check_output_slots(pages: &[TxPage], view: &ChainView) -> Result<(), SubmitError> {
    for page in pages {
        for (_, out) in page.body.live_outputs() {
            let idx = out.slot_index;
            if (idx as u64) >= view.num_slots {
                return Err(SubmitError::Consensus(
                    noid_chain::consensus::ConsensusError::ShapeMismatch(format!(
                        "output slot {idx} out of range"
                    )),
                ));
            }
            if view.try_slot(idx).map_err(|error| {
                SubmitError::Internal(format!("chain state read failed: {error}"))
            })? != SlotValue::EMPTY
            {
                return Err(SubmitError::Consensus(
                    noid_chain::consensus::ConsensusError::SlotConflict,
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: Auth-only wallet authorization verification
// ---------------------------------------------------------------------------

/// Verify the wallet authorization for a non-coinbase tx.
/// Returns Ok(()) if valid, Err(String) with reason if invalid.
fn verify_intent_authorization(pages: &[TxPage], authorization_bytes: &[u8]) -> Result<(), String> {
    use noid_gkr::{verify_paged_spend_authorization, WalletAuthorizationBundle};

    let bundle = WalletAuthorizationBundle::from_bytes(authorization_bytes)
        .map_err(|e| format!("authorization decode: {e}"))?;
    verify_paged_spend_authorization(pages, &bundle)
        .map_err(|e| format!("authorization verify: {e}"))
}

#[cfg(test)]
#[path = "pool_capacity_tests.rs"]
mod capacity_tests;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use noid_chain::consensus::genesis::genesis_header;
    use noid_chain::fri_state::SlotValue;
    use noid_chain::state::ChainState;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, validate_paged_spend, TxBody, TxInput, TxOutput, TxPage,
        PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT, TX_INPUTS, TX_OUTPUTS,
    };

    use super::{
        check_input_slots, rebuild_slot_sets, refresh_fee_floor, run_admission_checks,
        AsyncMempool, MempoolState,
    };
    use crate::config::{test_config, MempoolConfig};
    use crate::error::SubmitError;
    use crate::view::ChainView;
    use std::collections::HashSet;

    fn user_pages(epoch_anchor: [u8; 32], fee: u64, seed: u8) -> Vec<TxPage> {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: u32::from(seed) * 2 + 1,
            amount: 100 + fee,
            creation_id: u64::from(seed) + 1,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: u32::from(seed) * 2 + 2,
            amount: 100,
            owner: Address([seed; 32]),
        };
        vec![TxPage::new(TxBody {
            epoch_anchor,
            fee,
            input_owner: Address([0xA5; 32]),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0) | PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        })
        .unwrap()]
    }

    fn retained_intent(auth_byte: u8, auth_len: usize) -> Vec<u8> {
        let mut bytes = vec![0; noid_tx::paged_spend_authorization_wire_offset(1).unwrap()];
        bytes.extend(std::iter::repeat_n(auth_byte, auth_len));
        bytes
    }

    #[tokio::test]
    async fn relay_presence_is_nonblocking_and_tracks_reorg_removal() {
        let state = ChainState::with_log_slots(6);
        let pool = AsyncMempool::new(
            ChainView::new(0, HashMap::new(), 0, state.state),
            test_config().with_capacity(8),
        );
        let pages = user_pages([0x31; 32], 400, 1);
        let txid = validate_paged_spend(&pages).unwrap().logical_txid;
        assert_eq!(pool.try_contains(&txid), Some(false));
        let (usage, ids) = pool.try_recovery_inventory().unwrap();
        assert_eq!(usage.size, 0);
        assert_eq!(usage.capacity, 8);
        assert!(ids.is_empty());
        {
            let mut locked = pool.state.lock().await;
            locked.pool.admit(pages, 0).unwrap();
            assert_eq!(pool.try_contains(&txid), None);
            assert!(pool.try_recovery_inventory().is_none());
        }
        assert_eq!(pool.try_contains(&txid), Some(true));
        let (usage, ids) = pool.try_recovery_inventory().unwrap();
        assert_eq!(usage.size, 1);
        assert_eq!(ids, vec![txid]);
        pool.readmit_after_reorg(vec![txid]).await;
        assert_eq!(pool.try_contains(&txid), Some(false));
        let (usage, ids) = pool.try_recovery_inventory().unwrap();
        assert_eq!(usage.size, 0);
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn reorg_duplicate_removal_releases_slot_reservations() {
        let state = ChainState::with_log_slots(6);
        let pool = AsyncMempool::new(
            ChainView::new(0, HashMap::new(), 0, state.state),
            test_config().with_capacity(8),
        );
        let pages = user_pages([0x31; 32], 400, 1);
        let txid = validate_paged_spend(&pages).unwrap().logical_txid;
        let input_slot = pages[0].body.inputs[0].slot_index;
        let output_slot = pages[0].body.outputs[0].slot_index;
        {
            let mut locked = pool.state.lock().await;
            locked.pool.admit(pages, 0).expect("admit fixture");
            rebuild_slot_sets(&mut locked);
            assert!(locked.admitted_input_slots.contains(&input_slot));
            assert!(locked.admitted_output_slots.contains(&output_slot));
        }

        pool.readmit_after_reorg(vec![txid]).await;

        let locked = pool.state.lock().await;
        assert!(locked.pool.is_empty());
        assert!(!locked.admitted_input_slots.contains(&input_slot));
        assert!(!locked.admitted_output_slots.contains(&output_slot));
    }

    #[tokio::test]
    async fn empty_pool_resets_stale_dynamic_fee_floor_on_block_advance() {
        use noid_chain::consensus::params::MIN_FEE_BASE;

        let state = ChainState::with_log_slots(6);
        let view = ChainView::new(0, HashMap::new(), 0, state.state);
        let pool = AsyncMempool::new(view.clone(), test_config());
        {
            let mut locked = pool.state.lock().await;
            locked.floor.record(100_000);
            assert!(locked.floor.current() > MIN_FEE_BASE);
            assert!(locked.pool.is_empty());
        }

        pool.on_new_block(&[], 1, view).await;

        assert_eq!(pool.fee_floor().await, MIN_FEE_BASE);
    }

    // Populate already-admitted metadata directly: these tests exercise fee
    // policy and removal, not wallet authorization generation or verification.
    async fn fee_test_pool(
        fees: &[u64],
    ) -> (
        AsyncMempool,
        ChainView,
        Vec<noid_poseidon2b::primitives::TxBodyHash>,
    ) {
        fee_test_pool_at(fees, 0, test_config(), 0).await
    }

    async fn fee_test_pool_at(
        fees: &[u64],
        tip_height: u64,
        config: MempoolConfig,
        retained_bytes_per_entry: usize,
    ) -> (
        AsyncMempool,
        ChainView,
        Vec<noid_poseidon2b::primitives::TxBodyHash>,
    ) {
        // Fee-policy fixtures must belong to the candidate's actual epoch,
        // including production activation heights well beyond genesis.
        let anchor_height = noid_chain::consensus::tx_epoch_anchor_height_for_child(tip_height + 1);
        let mut epoch_header = genesis_header();
        epoch_header.height = anchor_height;
        epoch_header.timestamp += anchor_height * noid_chain::consensus::params::BLOCK_TIME;
        let anchor = noid_chain::consensus::pow::block_id(&epoch_header);
        let mut state = ChainState::with_log_slots(6);
        let groups: Vec<_> = fees
            .iter()
            .enumerate()
            .map(|(index, fee)| user_pages(anchor, *fee, (index + 1) as u8))
            .collect();
        for pages in &groups {
            let body = &pages[0].body;
            let input = body.inputs[0];
            state
                .state
                .set_slot(
                    input.slot_index,
                    SlotValue::with_owner_fields(
                        input.amount,
                        input.creation_id,
                        body.input_owner.as_fields(),
                    ),
                )
                .unwrap();
        }
        let view = ChainView::new(
            tip_height,
            HashMap::from([(anchor_height, epoch_header)]),
            fees.len() as u64,
            state.state,
        );
        let pool = AsyncMempool::new(view.clone(), config);
        let mut ids = Vec::new();
        {
            let mut st = pool.state.lock().await;
            for pages in groups {
                let facts = validate_paged_spend(&pages).unwrap();
                ids.push(facts.logical_txid);
                st.pool.admit(pages, tip_height).unwrap();
                if retained_bytes_per_entry > 0 {
                    // Synthetic retained bytes test counter accounting only.
                    st.pool.set_intent_bytes(
                        &facts.logical_txid,
                        vec![0x5A; retained_bytes_per_entry],
                    );
                }
                st.floor.record(facts.fee);
                let retained_bytes = st.pool.len() * retained_bytes_per_entry;
                refresh_fee_floor(&mut st, &pool.config, retained_bytes);
            }
            rebuild_slot_sets(&mut st);
        }
        (pool, view, ids)
    }

    #[tokio::test]
    async fn cancelled_submission_keeps_its_cpu_permit_until_the_worker_exits() {
        use noid_tx::PagedSpendIntent;
        use std::sync::Arc;
        let (mut pool, _, ids) =
            fee_test_pool_at(&[40_000], 0, test_config().with_auth_verify_workers(1), 0).await;
        let pages = {
            let mut state = pool.state.lock().await;
            let pages = state.pool.remove(&ids[0]).unwrap().pages;
            rebuild_slot_sets(&mut state);
            pages
        };
        let intent = PagedSpendIntent::new(pages, vec![1; 20]).unwrap();
        let bytes = intent.to_bytes().unwrap();
        let (started, signal) = tokio::sync::oneshot::channel();
        let started = std::sync::Mutex::new(Some(started));
        let (release, waiting) = std::sync::mpsc::channel();
        let waiting = std::sync::Mutex::new(waiting);
        pool = pool.with_authorization_verification_executor(Arc::new(move |task| {
            started.lock().unwrap().take().unwrap().send(()).unwrap();
            waiting
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            task()
        }));
        let submitter = pool.clone();
        let submitted = tokio::spawn(async move { submitter.submit(intent, bytes).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), signal)
            .await
            .unwrap()
            .unwrap();
        submitted.abort();
        assert!(submitted.await.unwrap_err().is_cancelled());
        assert_eq!(pool.auth_verify_semaphore.available_permits(), 0);
        assert!(pool.auth_verify_semaphore.try_acquire().is_err());
        release.send(()).unwrap();
        let permit = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pool.auth_verify_semaphore.acquire(),
        )
        .await
        .unwrap()
        .unwrap();
        drop(permit);
        assert_eq!(pool.auth_verify_semaphore.available_permits(), 1);
        assert!(pool.is_empty().await);
    }

    #[tokio::test]
    async fn v2_selection_rejects_a_changed_candidate_height() {
        use noid_chain::mempool::BlockSelectionBudget;
        let Some(height) = noid_chain::consensus::params::V2_ACTIVATION_HEIGHT else {
            return;
        };
        let (pool, view, _) = fee_test_pool_at(&[40_000], height - 1, test_config(), 0).await;
        let budget = BlockSelectionBudget {
            pages: 63,
            live_inputs: 504,
            contract_calls: 63,
        };
        for stale_height in [height - 1, height + 1] {
            assert!(pool
                .select_for_v2_mining(budget, None, stale_height, view.user_epoch_anchor_id)
                .await
                .is_err());
        }
        assert_eq!(
            pool.select_for_v2_mining(budget, None, height, view.user_epoch_anchor_id)
                .await
                .unwrap()
                .entries
                .len(),
            1
        );
        assert_eq!(pool.len().await, 1);
    }

    #[tokio::test]
    async fn optional_large_selection_preserves_the_more_valuable_small_call_set() {
        use noid_chain::mempool::BlockSelectionBudget;
        let Some(height) = noid_chain::consensus::params::V2_ACTIVATION_HEIGHT else {
            return;
        };
        let small = BlockSelectionBudget {
            pages: 3,
            live_inputs: 24,
            contract_calls: 3,
        };
        let large = BlockSelectionBudget {
            pages: 6,
            live_inputs: 24,
            contract_calls: 2,
        };
        for payment_fee in [7_000, 10_000, 13_000] {
            let mut fees = vec![40_000; 3];
            fees.extend([payment_fee; 6]);
            let (pool, view, ids) = fee_test_pool_at(&fees, height - 1, test_config(), 0).await;
            {
                // Resource-selection fixture: real controller authorization
                // and admission are exercised by the integration tests.
                let mut state = pool.state.lock().await;
                for id in &ids[..3] {
                    let mut pages = state.pool.remove(id).unwrap().pages;
                    pages[0].body.validity_bitmap |= noid_tx::PAGED_SPEND_CONTRACT_BIT;
                    state.pool.admit(pages, height - 1).unwrap();
                }
            }
            for allowed in [false, true] {
                let choice = pool
                    .select_for_v2_mining(
                        small,
                        allowed.then_some(large),
                        height,
                        view.user_epoch_anchor_id,
                    )
                    .await
                    .unwrap();
                let use_large = allowed && payment_fee > 10_000;
                assert_eq!(choice.large_class, use_large);
                assert_eq!(choice.entries.len(), if use_large { 6 } else { 3 });
                assert_eq!(
                    choice
                        .entries
                        .iter()
                        .filter(|entry| entry.pages[0].body.validity_bitmap
                            & noid_tx::PAGED_SPEND_CONTRACT_BIT
                            != 0)
                        .count(),
                    if use_large { 2 } else { 3 }
                );
                assert_eq!(choice.pending_outputs.len(), 9);
            }
            assert_eq!(pool.len().await, 9);
        }
    }

    #[tokio::test]
    async fn fee_policy_fixtures_preserve_current_epoch_at_large_heights() {
        for tip in [0, 143, 144, 95_124, 1_000_000] {
            let (pool, view, _) = fee_test_pool_at(&[9_000; 2], tip, test_config(), 0).await;
            assert_ne!(view.user_epoch_anchor_id, [0; 32]);
            pool.on_new_block(&[], tip, view).await;
            assert_eq!(pool.len().await, 2, "current-epoch fixtures at tip={tip}");
        }
    }

    #[tokio::test]
    async fn configured_activation_uses_next_child_and_reorg_restores_legacy_policy() {
        use noid_chain::consensus::params::{MIN_FEE_BASE, V1_1_ACTIVATION_HEIGHT};
        // Run the same scenario at the configured mainnet height and with
        // noid_chain/isolated-v1-1-testnet (the shared H5 test gate).
        let activation = V1_1_ACTIVATION_HEIGHT.unwrap_or(5);
        let (pool, mut view, _) = fee_test_pool_at(
            &[100_000; 6],
            activation - 2,
            test_config().with_capacity(10),
            0,
        )
        .await;
        assert_eq!(pool.fee_floor().await, 90_000);
        for tip in [activation - 1, activation, activation - 2, activation - 1] {
            view.tip_height = tip;
            pool.on_new_block(&[], tip, view.clone()).await;
            let expected = if V1_1_ACTIVATION_HEIGHT.is_some() && tip + 1 >= activation {
                MIN_FEE_BASE
            } else {
                90_000
            };
            assert_eq!(
                pool.len().await,
                6,
                "policy change must not evict admitted fees"
            );
            assert_eq!(pool.fee_floor().await, expected, "tip={tip}");
        }
        let fresh = AsyncMempool::new(view, test_config());
        assert_eq!(fresh.fee_floor().await, MIN_FEE_BASE);
    }

    #[tokio::test]
    async fn partial_block_and_reorg_drains_refresh_count_and_byte_pressure() {
        use noid_chain::consensus::params::{MIN_FEE_BASE, V1_1_ACTIVATION_HEIGHT};
        let tip = V1_1_ACTIVATION_HEIGHT.unwrap_or(5) - 1;
        for byte_pressure in [false, true] {
            for reorg in [false, true] {
                let config = test_config()
                    .with_capacity(if byte_pressure { 100 } else { 10 })
                    .with_max_total_intent_bytes(1000);
                let (pool, view, ids) = fee_test_pool_at(
                    &[100_000; 8],
                    tip,
                    config,
                    if byte_pressure { 100 } else { 0 },
                )
                .await;
                assert_eq!(pool.fee_floor().await, 90_000);
                for index in 0..8 {
                    if reorg {
                        pool.readmit_after_reorg(vec![ids[index]]).await;
                    } else {
                        pool.on_new_block(&[ids[index]], tip, view.clone()).await;
                    }
                    let remaining = 7 - index;
                    let low = remaining == 0 || (V1_1_ACTIVATION_HEIGHT.is_some() && remaining < 5);
                    let usage = pool.usage_snapshot().await;
                    assert_eq!(usage.size, remaining);
                    assert_eq!(
                        usage.intent_bytes,
                        if byte_pressure { remaining * 100 } else { 0 }
                    );
                    assert_eq!(usage.fee_floor, if low { MIN_FEE_BASE } else { 90_000 });
                }
            }
        }
    }

    #[tokio::test]
    async fn admission_and_every_fee_projection_use_the_same_latched_floor() {
        use noid_chain::consensus::params::{MIN_FEE_BASE, V1_1_ACTIVATION_HEIGHT};
        let tip = V1_1_ACTIVATION_HEIGHT.unwrap_or(5) - 1;
        let (pool, view, ids) =
            fee_test_pool_at(&[9_000; 8], tip, test_config().with_capacity(10), 0).await;
        {
            let mut st = pool.state.lock().await;
            for _ in 0..50 {
                st.floor.record(100_000);
            }
            refresh_fee_floor(&mut st, &pool.config, 0);
        }
        for removed in [0, 4] {
            pool.on_new_block(&ids[..removed], tip, view.clone()).await;
            let expected = if removed == 4 && V1_1_ACTIVATION_HEIGHT.is_some() {
                MIN_FEE_BASE
            } else {
                90_000
            };
            assert_eq!(pool.fee_floor().await, expected);
            assert_eq!(pool.usage_snapshot().await.fee_floor, expected);
            assert_eq!(pool.metadata_snapshot().await.fee_floor, expected);
            assert_eq!(pool.try_recovery_inventory().unwrap().0.fee_floor, expected);
            let pages = user_pages(view.user_epoch_anchor_id, 9_000, 1);
            let facts = validate_paged_spend(&pages).unwrap();
            let st = pool.state.lock().await;
            let result = run_admission_checks(&pages, &facts, &st, &pool.config);
            if expected == MIN_FEE_BASE {
                result.unwrap(); // The removed input is live and unreserved.
            } else {
                assert!(matches!(
                    result,
                    Err(SubmitError::Consensus(
                        noid_chain::consensus::ConsensusError::BelowMinFee {
                            required: 90_000,
                            actual: 9_000,
                        }
                    ))
                ));
            }
        }
    }

    #[test]
    fn pressure_updates_do_not_add_full_pool_byte_scans() {
        let source = include_str!("pool.rs");
        let helper = source
            .split_once("fn refresh_fee_floor(")
            .unwrap()
            .1
            .split_once("/// Compact immutable")
            .unwrap()
            .0;
        assert!(!helper.contains("total_intent_bytes()"));
        assert!(!helper.contains(".iter()"));
        let admission = source
            .split_once("pub async fn submit(")
            .unwrap()
            .1
            .split_once("// Block assembly")
            .unwrap()
            .0;
        assert_eq!(admission.matches(".total_intent_bytes()").count(), 2);
        let cleanup = source
            .split_once("pub async fn on_new_block(")
            .unwrap()
            .1
            .split_once("// Accessors")
            .unwrap()
            .0;
        assert!(!cleanup.contains(".total_intent_bytes()"));
    }

    #[tokio::test]
    async fn fee_floor_resets_after_each_kind_of_block_driven_drain() {
        use noid_chain::consensus::params::MIN_FEE_BASE;

        for reason in ["confirmed", "epoch", "input", "output"] {
            let (pool, mut view, ids) = fee_test_pool(&[100_000]).await;
            assert_eq!(pool.fee_floor().await, 90_000);
            match reason {
                "epoch" => view.user_epoch_anchor_id = [0x77; 32],
                "input" | "output" => {
                    let mut state = ChainState::with_log_slots(6);
                    if reason == "output" {
                        state.state.set_slot(3, view.try_slot(3).unwrap()).unwrap();
                        state
                            .state
                            .set_slot(
                                4,
                                SlotValue::with_owner_fields(
                                    100,
                                    42,
                                    Address([0x77; 32]).as_fields(),
                                ),
                            )
                            .unwrap();
                    }
                    view = ChainView::new(
                        view.tip_height,
                        view.recent_headers.clone(),
                        if reason == "output" { 2 } else { 0 },
                        state.state,
                    );
                }
                _ => {}
            }
            pool.on_new_block(if reason == "confirmed" { &ids } else { &[] }, 1, view)
                .await;
            assert!(pool.is_empty().await, "{reason}");
            assert_eq!(pool.fee_floor().await, MIN_FEE_BASE, "{reason}");
        }
    }

    #[tokio::test]
    async fn fee_floor_survives_partial_drain_and_resets_after_last_entry() {
        use noid_chain::consensus::params::MIN_FEE_BASE;

        for reorg in [false, true] {
            let (pool, view, ids) = fee_test_pool(&[100_000, 100_000]).await;
            for (index, hash) in ids.iter().enumerate() {
                if reorg {
                    pool.readmit_after_reorg(vec![*hash]).await;
                } else {
                    pool.on_new_block(&[*hash], index as u64 + 1, view.clone())
                        .await;
                }
                assert_eq!(pool.len().await, 1 - index);
                assert_eq!(
                    pool.fee_floor().await,
                    if index == 0 { 90_000 } else { MIN_FEE_BASE }
                );
            }
        }
    }

    #[tokio::test]
    async fn fee_floor_is_local_and_a_fresh_pool_starts_at_base() {
        let (busy, view, _) = fee_test_pool(&[100_000]).await;
        let fresh = AsyncMempool::new(view, test_config());
        assert_eq!(busy.fee_floor().await, 90_000);
        assert_eq!(
            fresh.fee_floor().await,
            noid_chain::consensus::params::MIN_FEE_BASE
        );
    }

    #[tokio::test]
    async fn admission_uses_current_fee_floor_not_the_original_quote() {
        let (pool, view, ids) = fee_test_pool(&[9_000]).await;
        pool.readmit_after_reorg(ids).await;
        let pages = user_pages(view.user_epoch_anchor_id, 9_000, 1);
        let facts = validate_paged_spend(&pages).unwrap();
        let mut st = pool.state.lock().await;
        run_admission_checks(&pages, &facts, &st, &pool.config).unwrap();
        st.floor.record(100_000);
        assert!(matches!(
            run_admission_checks(&pages, &facts, &st, &pool.config),
            Err(crate::error::SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::BelowMinFee {
                    required: 90_000,
                    actual: 9_000,
                }
            ))
        ));
        st.floor.reset();
        run_admission_checks(&pages, &facts, &st, &pool.config).unwrap();
    }

    async fn growth_fee_test_pool(
        active_slots: u64,
        fee: u64,
    ) -> (
        AsyncMempool,
        ChainView,
        noid_poseidon2b::primitives::TxBodyHash,
    ) {
        let genesis = genesis_header();
        let anchor = noid_chain::consensus::pow::block_id(&genesis);
        let mut pages = user_pages(anchor, fee, 1);
        pages[0].body.outputs[0].amount = 50;
        pages[0].body.outputs[1] = TxOutput {
            slot_index: 62,
            amount: 50,
            owner: Address([2; 32]),
        };
        pages[0].body.validity_bitmap |= output_bitmap_bit(1);
        let facts = validate_paged_spend(&pages).unwrap();
        let input = pages[0].body.inputs[0];
        let mut state = ChainState::with_log_slots(6);
        state
            .state
            .set_slot(
                input.slot_index,
                SlotValue::with_owner_fields(
                    input.amount,
                    input.creation_id,
                    pages[0].body.input_owner.as_fields(),
                ),
            )
            .unwrap();
        let view = ChainView::new(0, HashMap::from([(0, genesis)]), active_slots, state.state);
        let pool = AsyncMempool::new(view.clone(), test_config());
        {
            let mut st = pool.state.lock().await;
            run_admission_checks(&pages, &facts, &st, &pool.config).unwrap();
            st.pool.admit(pages, 0).unwrap();
            st.floor.record(facts.fee);
            rebuild_slot_sets(&mut st);
        }
        (pool, view, facts.logical_txid)
    }

    #[tokio::test]
    async fn growth_pressure_evicts_only_underpriced_pending_spends_at_every_boundary() {
        use crate::event::{EvictReason, MempoolEvent};
        use noid_chain::consensus::params::MIN_FEE_BASE;

        for (before, at, old_fee, new_fee) in [
            (31, 32, 9_000, 11_500),
            (47, 48, 11_500, 16_500),
            (57, 58, 16_500, 26_500),
        ] {
            for fee in [old_fee, new_fee] {
                let (pool, mut view, id) = growth_fee_test_pool(before, fee).await;
                let mut events = pool.subscribe();
                view.active_slot_count = at;
                pool.on_new_block(&[], 1, view).await;
                let st = pool.state.lock().await;
                if fee < new_fee {
                    assert!(st.pool.is_empty());
                    assert!(st.admitted_input_slots.is_empty());
                    assert!(st.admitted_output_slots.is_empty());
                    assert_eq!(st.floor.current(), MIN_FEE_BASE);
                    assert!(
                        matches!(events.try_recv().unwrap(), MempoolEvent::TxEvicted {
                        hash, reason: EvictReason::ConsensusFeeIncreased,
                    } if hash == id)
                    );
                } else {
                    assert!(st.pool.contains(&id));
                    assert_eq!(st.pool.get(&id).unwrap().spend.fee, fee);
                    assert!(st.admitted_input_slots.contains(&3));
                    assert!(st.admitted_output_slots.contains(&62));
                }
                assert!(events.try_recv().is_err());
            }
        }
    }

    #[tokio::test]
    async fn confirmation_at_old_parent_price_precedes_new_pressure_cleanup() {
        use crate::event::MempoolEvent;
        let (pool, mut view, id) = growth_fee_test_pool(31, 9_000).await;
        let mut events = pool.subscribe();
        view.active_slot_count = 32;
        pool.on_new_block(&[id], 1, view).await;
        assert!(pool.is_empty().await);
        assert!(
            matches!(events.try_recv().unwrap(), MempoolEvent::TxConfirmed {
            hash, block_height: 1,
        } if hash == id)
        );
        assert!(events.try_recv().is_err());
    }

    #[tokio::test]
    async fn rising_local_floor_and_state_pressure_do_not_evict_nongrowing_spends() {
        let (pool, mut view, ids) = fee_test_pool(&[9_000]).await;
        {
            let mut st = pool.state.lock().await;
            for _ in 0..50 {
                st.floor.record(100_000);
            }
        }
        view.active_slot_count = 58;
        pool.on_new_block(&[], 1, view).await;
        assert_eq!(pool.len().await, 1);
        assert_eq!(pool.try_contains(&ids[0]), Some(true));
        assert_eq!(pool.fee_floor().await, 90_000);
        assert!(pool.reserved_input_slots().await.contains(&3));
    }

    #[tokio::test]
    async fn falling_pressure_preserves_pending_spends_and_does_not_recreate_evicted_ones() {
        let (pool, mut view, id) = growth_fee_test_pool(32, 11_500).await;
        view.active_slot_count = 31;
        pool.on_new_block(&[], 1, view.clone()).await;
        assert_eq!(pool.try_contains(&id), Some(true));
        view.active_slot_count = 48;
        pool.on_new_block(&[], 2, view.clone()).await;
        assert!(pool.is_empty().await);
        view.active_slot_count = 31;
        pool.on_new_block(&[], 3, view).await;
        assert!(pool.is_empty().await);
    }

    #[tokio::test]
    async fn anchored_selection_filters_before_cloning_bounded_prefix() {
        let state = ChainState::with_log_slots(6);
        let pool = AsyncMempool::new(
            ChainView::new(0, HashMap::new(), 0, state.state),
            test_config().with_capacity(8),
        );
        let anchor = [0x11; 32];
        let wrong_anchor = [0x22; 32];
        let high = user_pages(anchor, 300, 1);
        let wrong = user_pages(wrong_anchor, 200, 2);
        let low = user_pages(anchor, 100, 3);
        let high_id = validate_paged_spend(&high).unwrap().logical_txid;
        let low_id = validate_paged_spend(&low).unwrap().logical_txid;
        {
            let mut locked = pool.state.lock().await;
            locked.pool.admit(high, 0).expect("admit high fee");
            locked.pool.admit(wrong, 0).expect("admit wrong anchor");
            locked.pool.admit(low, 0).expect("admit low fee");
            locked
                .pool
                .set_intent_bytes(&high_id, retained_intent(0xA5, 1024));
            locked
                .pool
                .set_intent_bytes(&low_id, retained_intent(0x5A, 1024));
        }

        let one = pool.select_for_block_at_anchor(1, anchor).await;
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].logical_txid, high_id);
        assert_eq!(one[0].cached_authorization.as_ref().unwrap().len(), 1024);

        let two = pool.select_for_block_at_anchor(2, anchor).await;
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].logical_txid, high_id);
        assert_eq!(two[1].logical_txid, low_id);
    }

    #[tokio::test]
    async fn template_selection_snapshots_unselected_outputs_without_changing_selection() {
        let state = ChainState::with_log_slots(6);
        let pool = AsyncMempool::new(
            ChainView::new(0, HashMap::new(), 0, state.state),
            test_config().with_capacity(8),
        );
        let anchor = [0x11; 32];
        let high = user_pages(anchor, 300, 1);
        let low = user_pages(anchor, 100, 2);
        let stale = user_pages([0x22; 32], 400, 3);
        let high_id = validate_paged_spend(&high).unwrap().logical_txid;
        {
            let mut locked = pool.state.lock().await;
            for pages in [high, low, stale] {
                locked.pool.admit(pages, 0).unwrap();
            }
            locked
                .pool
                .set_intent_bytes(&high_id, retained_intent(0xA5, 1024));
            rebuild_slot_sets(&mut locked);
        }
        for limit in [0, 1, 25, 255] {
            let legacy = pool.select_for_block_at_anchor(limit, anchor).await;
            let (selected, outputs) = pool
                .select_for_block_at_anchor_with_output_reservations(limit, anchor)
                .await;
            assert_eq!(outputs, HashSet::from([4, 6, 8]));
            assert_eq!(selected.len(), legacy.len());
            for (new, old) in selected.iter().zip(&legacy) {
                assert_eq!(new.logical_txid, old.logical_txid);
                assert_eq!(new.pages, old.pages);
                assert_eq!(new.cached_authorization, old.cached_authorization);
            }
        }
        let (_, before) = pool
            .select_for_block_at_anchor_with_output_reservations(1, anchor)
            .await;
        {
            let mut locked = pool.state.lock().await;
            locked.pool.on_block_confirmed(&[high_id]);
            rebuild_slot_sets(&mut locked);
        }
        let (_, after) = pool
            .select_for_block_at_anchor_with_output_reservations(1, anchor)
            .await;
        assert_eq!(before, HashSet::from([4, 6, 8]), "snapshot is owned");
        assert_eq!(after, HashSet::from([6, 8]), "no stale reservation index");
    }

    #[tokio::test]
    async fn empty_template_reservations_do_not_clone_retained_hash_capacity() {
        let state = ChainState::with_log_slots(6);
        let pool = AsyncMempool::new(
            ChainView::new(0, HashMap::new(), 0, state.state),
            test_config(),
        );
        {
            let mut locked = pool.state.lock().await;
            locked.admitted_output_slots.reserve(65_536);
        }
        let (entries, outputs) = pool
            .select_for_block_at_anchor_with_output_reservations(25, [0; 32])
            .await;
        assert!(entries.is_empty());
        assert!(outputs.is_empty());
        assert_eq!(outputs.capacity(), 0);
    }

    #[tokio::test]
    async fn mint_preference_preserves_a_real_pending_spend_for_the_next_block() {
        use noid_chain::consensus::template::{
            build_block_template, build_node_owned_block_template_avoiding_outputs,
        };
        use noid_gkr::{prove_paged_spend_authorization, OwnerAuthWitness};
        use noid_poseidon2b::primitives::{derive_address, SpendSecret};
        use noid_tx::PagedSpendIntent;

        let secret = SpendSecret::from_bytes([0x39; 32]);
        let owner = derive_address(&secret);
        let mut state = ChainState::with_log_slots(8);
        state
            .state
            .set_slot(
                3,
                SlotValue::with_owner_fields(100_000, 2, owner.as_fields()),
            )
            .unwrap();
        state.active_slot_count = 1;
        state.alloc_counter = 2;
        state.circulating_supply_micronoid = 100_000;
        let mut parent = genesis_header();
        parent.log_slots = 8;
        parent.state_root = state.state_root();
        parent.active_slot_count = 1;
        parent.alloc_counter = 2;
        let anchor = noid_chain::consensus::pow::block_id(&parent);
        let miner = Address([9; 32]);
        let timestamp = parent.timestamp + 1;
        let legacy =
            build_block_template(&parent, &state, &[1], vec![], miner, timestamp, [0xff; 32])
                .unwrap()
                .into_block(0);
        let colliding_slot = legacy.transactions[0].body.outputs[0].slot_index;
        let mut body = user_pages(anchor, 6_500, 1).remove(0).body;
        body.input_owner = owner;
        body.inputs[0].amount = 100_000;
        body.outputs[0].slot_index = colliding_slot;
        body.outputs[0].amount = 93_500;
        let pages = vec![TxPage::new(body).unwrap()];
        let proof = prove_paged_spend_authorization(&pages, OwnerAuthWitness::new(secret)).unwrap();
        let intent = PagedSpendIntent::new(pages, proof.to_bytes().unwrap()).unwrap();
        let initial_view = ChainView::new(0, HashMap::from([(0, parent)]), 1, state.state.clone());

        for avoid in [false, true] {
            let pool = AsyncMempool::new(initial_view.clone(), test_config());
            let id = pool
                .submit(intent.clone(), intent.to_bytes().unwrap())
                .await
                .unwrap();
            // Model an admitted transaction outside this block's selected prefix.
            let (selected, pending) = pool
                .select_for_block_at_anchor_with_output_reservations(0, anchor)
                .await;
            assert!(selected.is_empty());
            assert!(pending.contains(&colliding_slot));
            let block = if avoid {
                build_node_owned_block_template_avoiding_outputs(
                    &parent,
                    &state,
                    &[1],
                    vec![],
                    miner,
                    timestamp,
                    [0xff; 32],
                    &pending,
                )
                .unwrap()
                .0
                .into_block(0)
            } else {
                legacy.clone()
            };
            let mut next_state = state.clone();
            for tx in &block.transactions {
                noid_chain::state::apply_tx_at(&mut next_state, &tx.body, block.header.height)
                    .unwrap();
            }
            assert_eq!(next_state.state_root(), block.header.state_root);
            let headers = HashMap::from([(0, parent), (1, block.header)]);
            let view = ChainView::new(
                1,
                headers.clone(),
                next_state.active_slot_count,
                next_state.state.clone(),
            );
            pool.on_new_block(&[], 1, view).await;
            assert_eq!(pool.try_contains(&id), Some(avoid));
            assert_eq!(
                next_state.state.slot(3),
                state.state.slot(3),
                "neither branch spends or charges the pending input"
            );
            if avoid {
                let (entries, outputs) = pool
                    .select_for_block_at_anchor_with_output_reservations(25, anchor)
                    .await;
                assert_eq!(entries.len(), 1);
                assert_eq!(
                    entries[0].cached_authorization.as_deref(),
                    Some(intent.authorization_bytes.as_slice()),
                    "reuse the original proof"
                );
                let users = entries[0]
                    .pages
                    .iter()
                    .map(|page| noid_tx::Transaction::new(page.body.clone()))
                    .collect();
                let child = build_node_owned_block_template_avoiding_outputs(
                    &block.header,
                    &next_state,
                    &[next_state.active_slot_count],
                    users,
                    miner,
                    timestamp + 1,
                    [0xff; 32],
                    &outputs,
                )
                .unwrap()
                .0
                .into_block(0);
                for tx in &child.transactions {
                    noid_chain::state::apply_tx_at(&mut next_state, &tx.body, child.header.height)
                        .unwrap();
                }
                assert_eq!(next_state.state_root(), child.header.state_root);
                let mut headers = headers;
                headers.insert(2, child.header);
                pool.on_new_block(
                    &[id],
                    2,
                    ChainView::new(
                        2,
                        headers,
                        next_state.active_slot_count,
                        next_state.state.clone(),
                    ),
                )
                .await;
                assert!(pool.is_empty().await);
                assert!(pool.reserved_input_slots().await.is_empty());
                assert!(pool.reserved_output_slots().await.is_empty());
                assert!(next_state.state.slot(3).is_empty());
                assert_eq!(next_state.state.slot(colliding_slot).amount(), 93_500);
            } else {
                assert!(pool.reserved_input_slots().await.is_empty());
                assert!(pool.reserved_output_slots().await.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn metadata_snapshot_never_carries_retained_intent_or_authorization_bytes() {
        let state = ChainState::with_log_slots(6);
        let pool = AsyncMempool::new(
            ChainView::new(0, HashMap::new(), 0, state.state),
            test_config().with_capacity(8),
        );
        let tx = user_pages([0x31; 32], 400, 1);
        let txid = validate_paged_spend(&tx).unwrap().logical_txid;
        {
            let mut locked = pool.state.lock().await;
            locked.pool.admit(tx, 7).expect("admit metadata fixture");
            locked
                .pool
                .set_intent_bytes(&txid, vec![0x5A; 2 * 1024 * 1024]);
        }

        let snapshot = pool.metadata_snapshot().await;
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.entries[0].tx_hash, txid);
        assert!(snapshot.entries[0].has_authorization);
        assert!(std::mem::size_of::<super::MempoolEntryMetadata>() <= 64);

        let single = pool.get_entry_metadata(&txid).await.unwrap();
        assert_eq!(single, snapshot.entries[0]);
        let details = pool.get_entry_details(&txid).await.unwrap();
        assert_eq!(details.metadata, single);
        assert!(details.contract_opening.is_none());
        let usage = pool.usage_snapshot().await;
        assert_eq!(usage.size, 1);
        assert_eq!(usage.capacity, 8);
        assert_eq!(usage.intent_bytes, 2 * 1024 * 1024);
        assert_eq!(
            usage.max_intent_bytes,
            noid_chain::consensus::wire_limits::MAX_MEMPOOL_BYTES
        );
        assert_eq!(
            pool.state.lock().await.pool.total_intent_bytes(),
            2 * 1024 * 1024
        );
    }

    #[test]
    fn template_and_preverified_paths_never_clone_raw_intent_payloads() {
        let source = include_str!("pool.rs");
        let selection = source
            .split("pub async fn select_for_block(")
            .nth(1)
            .expect("selection method")
            .split("// -----------------------------------------------------------------------\n    // Block confirmation")
            .next()
            .expect("selection boundary");
        assert!(!selection.contains("intent_bytes"));
        assert!(!selection.contains(".cloned()"));

        let preverified = source
            .split("pub async fn verified_authorization_proof_bytes(")
            .nth(1)
            .expect("preverified method")
            .split("// ---------------------------------------------------------------------------\n// Helper: all cheap admission checks")
            .next()
            .expect("preverified boundary");
        assert!(!preverified.contains("intent_bytes.clone"));
        assert!(!preverified.contains("Vec<Vec<u8>>"));
    }

    #[test]
    fn admission_accepts_tip_reward_for_the_next_block() {
        use noid_chain::consensus::params::coinbase_creation_id;

        let owner = Address([0xA5; 32]);
        let mint_height = 3;
        let mut state = ChainState::with_log_slots(6);
        state
            .state
            .set_slot(
                7,
                SlotValue::with_owner_fields(
                    1_000_000,
                    coinbase_creation_id(mint_height),
                    owner.as_fields(),
                ),
            )
            .unwrap();
        let genesis = genesis_header();
        let mut tip = genesis.clone();
        tip.height = mint_height;
        let mut headers = HashMap::new();
        headers.insert(0, genesis);
        headers.insert(mint_height, tip);
        let view = ChainView::new(mint_height, headers, 1, state.state);
        let mempool_state = |view: ChainView| MempoolState {
            pool: noid_chain::Mempool::new(16),
            view,
            floor: crate::floor::FeeFloor::new(4),
            admitted_input_slots: HashSet::new(),
            admitted_output_slots: HashSet::new(),
        };

        let spend = |fee: u64| {
            let mut inputs = [TxInput::dummy(); TX_INPUTS];
            inputs[0] = TxInput {
                slot_index: 7,
                amount: 1_000_000,
                creation_id: coinbase_creation_id(mint_height),
            };
            let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
            outputs[0] = TxOutput {
                slot_index: 8,
                amount: 1_000_000 - fee,
                owner: Address([0xB6; 32]),
            };
            vec![TxPage::new(TxBody {
                epoch_anchor: [1; 32],
                fee,
                input_owner: owner,
                inputs,
                outputs,
                validity_bitmap: 1
                    | output_bitmap_bit(0)
                    | PAGED_SPEND_START_BIT
                    | PAGED_SPEND_END_BIT,
                is_coinbase: false,
            })
            .unwrap()]
        };

        // Learn the consensus fee, then anchor the child-height-4 candidate
        // to the epoch id captured by the accepted height-3 view.
        let probe_state = mempool_state(view);
        let required = noid_chain::consensus::fee_breakdown(
            1,
            1,
            probe_state.view.active_slot_count,
            probe_state.view.log_slots(),
        )
        .required_total;
        let mut candidate = spend(required);
        candidate[0].body.epoch_anchor = probe_state.view.user_epoch_anchor_id;
        let facts = validate_paged_spend(&candidate).unwrap();
        run_admission_checks(&candidate, &facts, &probe_state, &test_config())
            .expect("accepted tip reward is spendable in its child block");
    }

    #[test]
    fn input_state_match_binds_creation_id() {
        let owner = Address([0xA5; 32]);
        let mut state = ChainState::with_log_slots(6);
        state
            .state
            .set_slot(
                7,
                SlotValue::with_owner_fields(1_000, 42, owner.as_fields()),
            )
            .unwrap();
        let mut headers = HashMap::new();
        headers.insert(0, genesis_header());
        let view = ChainView::new(0, headers, 1, state.state);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 7,
            amount: 1_000,
            creation_id: 41,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 8,
            amount: 999,
            owner: Address([0xB6; 32]),
        };
        let mut pages = vec![TxPage::new(TxBody {
            epoch_anchor: [1; 32],
            fee: 1,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0) | PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        })
        .unwrap()];
        let mut facts = validate_paged_spend(&pages).unwrap();

        assert!(check_input_slots(&pages, &facts, &view).is_err());
        pages[0].body.inputs[0].creation_id = 42;
        facts = validate_paged_spend(&pages).unwrap();
        assert!(check_input_slots(&pages, &facts, &view).is_ok());
    }
}
