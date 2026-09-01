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
use noid_chain::Mempool;
use noid_poseidon2b::primitives::{Address, TxBodyHash};
use noid_tx::{
    validate_paged_spend, PagedSpendFacts, PagedSpendIntent, TxPage, PAGED_SPEND_INTENT_MARKER,
};

use crate::config::MempoolConfig;
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
        let state = MempoolState {
            pool: Mempool::new(config.capacity),
            view,
            floor,
            admitted_input_slots: HashSet::new(),
            admitted_output_slots: HashSet::new(),
        };
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
        if intent_bytes.len() > MAX_TX_INTENT_BYTES_GLOBAL {
            return Err(SubmitError::IntentTooLarge {
                actual: intent_bytes.len(),
                max: MAX_TX_INTENT_BYTES_GLOBAL,
            });
        }
        if !canonical_intent_bytes_match(&intent, &intent_bytes) {
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
        {
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
            let _ = run_admission_checks(&intent.pages, &spend, &st)?;
        }

        // ── Authorization verification (CPU-heavy, outside lock, semaphore-bounded) ─
        // Runs only when the pre-filter passed — invalid fee/anchor/slot txs are
        // already gone.  Semaphore caps concurrent CPU threads.
        {
            let proof_bytes = intent.authorization_bytes.clone();
            let pages = intent.pages.clone();
            let executor = Arc::clone(&self.auth_verify_executor);

            let _permit =
                self.auth_verify_semaphore.acquire().await.map_err(|_| {
                    SubmitError::Internal("proof-verification semaphore closed".into())
                })?;

            tokio::task::spawn_blocking(move || {
                executor(Box::new(move || {
                    verify_intent_authorization(&pages, &proof_bytes)
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
        let _anchor_height = run_admission_checks(&intent.pages, &spend, &st)?;

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
            })
            .collect()
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

        // Evict transactions from the previous exact epoch after a boundary.
        let stale_anchor: Vec<TxBodyHash> = st
            .pool
            .iter()
            .filter(|(_, entry)| entry.spend.epoch_anchor != st.view.user_epoch_anchor_id)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in stale_anchor {
            st.pool.remove(&hash);
            let _ = self.events.send(MempoolEvent::TxEvicted {
                hash,
                reason: EvictReason::EpochAnchorChanged,
            });
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
        rebuild_slot_sets(&mut st);
        if st.pool.is_empty() {
            st.floor.reset();
        }

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
            rebuild_slot_sets(&mut st);
        }
        if st.pool.is_empty() {
            st.floor.reset();
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

    /// O(1) compact lookup without cloning the entry's retained byte payloads.
    pub async fn get_entry_metadata(&self, hash: &TxBodyHash) -> Option<MempoolEntryMetadata> {
        let st = self.state.lock().await;
        st.pool.get(hash).map(|entry| entry_metadata(*hash, entry))
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

    /// Update the chain view without applying a new block.
    /// Used on startup (initial state) or after a reorg.
    pub async fn update_chain_view(&self, view: ChainView) {
        self.state.lock().await.view = view;
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
) -> Result<u64, SubmitError> {
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
    let anchor_height = tx_epoch_anchor_height_for_child(st.view.tip_height + 1);
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

fn rebuild_slot_sets(st: &mut MempoolState) {
    st.admitted_input_slots.clear();
    st.admitted_output_slots.clear();
    for (_, entry) in st.pool.iter() {
        for page in &entry.pages {
            for (_, inp) in page.body.live_inputs() {
                st.admitted_input_slots.insert(inp.slot_index);
            }
            for (_, out) in page.body.live_outputs() {
                st.admitted_output_slots.insert(out.slot_index);
            }
        }
    }
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
        check_input_slots, rebuild_slot_sets, run_admission_checks, AsyncMempool, MempoolState,
    };
    use crate::config::MempoolConfig;
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
    async fn reorg_duplicate_removal_releases_slot_reservations() {
        let state = ChainState::with_log_slots(6);
        let pool = AsyncMempool::new(
            ChainView::new(0, HashMap::new(), 0, state.state),
            MempoolConfig::default().with_capacity(8),
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
        let pool = AsyncMempool::new(view.clone(), MempoolConfig::default());
        {
            let mut locked = pool.state.lock().await;
            locked.floor.record(100_000);
            assert!(locked.floor.current() > MIN_FEE_BASE);
            assert!(locked.pool.is_empty());
        }

        pool.on_new_block(&[], 1, view).await;

        assert_eq!(pool.fee_floor().await, MIN_FEE_BASE);
    }

    #[tokio::test]
    async fn anchored_selection_filters_before_cloning_bounded_prefix() {
        let state = ChainState::with_log_slots(6);
        let pool = AsyncMempool::new(
            ChainView::new(0, HashMap::new(), 0, state.state),
            MempoolConfig::default().with_capacity(8),
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
    async fn metadata_snapshot_never_carries_retained_intent_or_authorization_bytes() {
        let state = ChainState::with_log_slots(6);
        let pool = AsyncMempool::new(
            ChainView::new(0, HashMap::new(), 0, state.state),
            MempoolConfig::default().with_capacity(8),
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
        run_admission_checks(&candidate, &facts, &probe_state)
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
