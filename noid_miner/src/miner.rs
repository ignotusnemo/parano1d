// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `BlockMiner` — phase-ordered block-production orchestrator.
//!
//! ## Block production design
//!
//! ```text
//! loop {
//!   template + complete nonce-independent HistoryStep proof
//!   bounded parallel PoW search
//!   seal exact nonce/header into the prepared terminal
//!   atomic commit + broadcast
//! }
//! ```
//!
//! Internal mining has one Rayon pool below the host-visible CPU ceiling. CPU
//! heavy phases reuse that same pool in order; there is no permanent one-core
//! PoW reservation and no independent prover pool. Every process starts with
//! a 25-page template budget and may jump directly to 255 pages only when
//! complete proof-class timings support the 20-second target.
//! External miner mode disables internal PoW, so the node can spend its CPUs on
//! template and HistoryStep preparation, validation, RPC, and P2P while miners run elsewhere.
//!
//! Template refresh triggers (see run loop):
//!   1. Heartbeat every `refresh_interval_secs` seconds (safety net)
//!   2. First `TxAdmitted` while a coinbase-only template is being mined
//!   3. New chain tip from P2P (block received or snapshot applied)

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, watch, RwLock};
use tokio::time::interval;

use noid_chain::consensus::paged_spend::BlockProofClass;
use noid_chain::consensus::pow::block_id;
use noid_chain::storage::MdbxChainContext;
use noid_mempool::{AsyncMempool, MempoolEvent};
use noid_poseidon2b::primitives::Address;

use crate::block_production::{PreparedBlockAttempt, ProvedBlock};
use crate::cpu_budget::{
    configure_process_cpu_budget, configured_process_cpu_budget, install_history_step_phase_cpu,
    install_pow_phase_cpu, ProcessCpuBudgetMode,
};
use crate::proof_capacity::AdaptiveProofCapacity;
use crate::template::{
    mining_launch_is_open, TemplateBuilder, TemplateChainSnapshot, TemplateRefreshTrigger,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the block miner.
#[derive(Debug, Clone)]
pub struct MinerConfig {
    /// Address that receives the coinbase reward.
    pub miner_address: Address,
    /// Safety-net heartbeat interval (seconds).
    ///
    /// Fires only if the miner has been stuck without a block for this long.
    /// Normal template refreshes happen immediately when the parent, dynamic
    /// payout, or coinbase-only mempool input changes.
    /// This timer exists only for edge cases where both are silent.
    ///
    /// Must be > BLOCK_TIME to avoid firing during active proving and
    /// inserting unnecessary coinbase blocks. Default: 5 × BLOCK_TIME.
    pub refresh_interval_secs: u64,
}

impl Default for MinerConfig {
    fn default() -> Self {
        Self {
            miner_address: Address([0u8; 32]),
            refresh_interval_secs: noid_chain::consensus::params::BLOCK_TIME * 5,
        }
    }
}

impl MinerConfig {
    pub fn with_address(mut self, addr: Address) -> Self {
        self.miner_address = addr;
        self
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Events emitted by the miner for P2P broadcast and local status.
#[derive(Debug, Clone)]
pub enum MinerEvent {
    /// A complete block was proved and committed atomically.
    BlockFound {
        height: u64,
        hash: [u8; 32],
        n_txs: usize,
        pow_nonce: u128,
        /// The only network/storage representation of a non-genesis block.
        bundle: noid_chain::AcceptedBlockBundle,
    },
    /// Template refreshed.
    TemplateRefreshed {
        height: u64,
        n_txs: usize,
        trigger: TemplateRefreshTrigger,
    },
    /// Mining cancelled (new P2P block or heartbeat).
    MiningCancelled { reason: String },
    /// Witness preparation or HistoryStep proving failed; the block is abandoned.
    ProveFailed { height: u64, error: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MiningMempoolRefresh {
    TransactionAdmitted,
    ReceiverLagged(u64),
}

/// Wait for a mempool event that can actually change a coinbase-only
/// template. Confirmations and evictions emitted while applying our own block
/// belong to the previous height and must not cancel fresh PoW on the next
/// height.
async fn next_mining_mempool_refresh(
    receiver: &mut broadcast::Receiver<MempoolEvent>,
) -> MiningMempoolRefresh {
    loop {
        match receiver.recv().await {
            Ok(MempoolEvent::TxAdmitted { .. }) => {
                return MiningMempoolRefresh::TransactionAdmitted;
            }
            Ok(
                MempoolEvent::TxConfirmed { .. }
                | MempoolEvent::TxEvicted { .. }
                | MempoolEvent::TxAuthorizationVerified { .. },
            ) => {}
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                return MiningMempoolRefresh::ReceiverLagged(skipped);
            }
            Err(broadcast::error::RecvError::Closed) => {
                return std::future::pending().await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BlockMiner
// ---------------------------------------------------------------------------

/// The main block production orchestrator.
/// Callback invoked synchronously inside `apply_found_block`, before the mempool
/// is updated. Enables the built-in wallet to capture receipts race-free:
/// by the time `getMempoolSize` drops to 0, the receipt is already stored.
///
/// Remote wallets subscribe via the P2P block event instead.
pub type BlockAppliedHook = Arc<dyn Fn(&noid_chain::block::Block) + Send + Sync>;
/// Resolves the payout address immediately before each template is built.
/// Used by the built-in wallet when no explicit mining address is configured.
pub type MiningPayoutResolver = Arc<dyn Fn() -> Address + Send + Sync>;
/// Optional node-wide ordering gate for canonical chain operations which also
/// replace wallet/mempool views (snapshot install, reorg, mining apply).
pub type ChainOperationGate = Arc<tokio::sync::Mutex<()>>;
fn resolve_mining_payout(configured: Address, resolver: Option<&MiningPayoutResolver>) -> Address {
    resolver.map(|resolve| resolve()).unwrap_or(configured)
}

pub struct BlockMiner {
    config: MinerConfig,
    mempool: AsyncMempool,
    chain: Arc<RwLock<MdbxChainContext>>,
    events: broadcast::Sender<MinerEvent>,
    /// Cancel flag: set to abort current PoW search and restart.
    cancel_pow: Arc<AtomicBool>,
    /// Permanent stop flag: set only by stop(), never reset. The main loop
    /// checks this at the top of each iteration and breaks cleanly.
    stopped: Arc<AtomicBool>,
    /// Stable permission to construct the recursive proof for the committed
    /// parent. Ordinary child commits do not revoke it.
    proof_network_ready: watch::Receiver<bool>,
    /// Exact authorization to search a nonce for the current template parent.
    /// This may pause briefly while fresh frontier reports are collected,
    /// without throwing away an already prepared proof-valid template.
    nonce_network_ready: watch::Receiver<bool>,
    /// Edge-triggered changes which invalidate a prepared template: a new
    /// canonical tip or a dynamic wallet payout switch.
    template_changes: broadcast::Receiver<()>,
    /// Keep the channel open for library-only miners even when their caller
    /// does not retain a sender after construction.
    _template_change_sender: broadcast::Sender<()>,
    history_step_runtime: Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>,
    ghost_authorization:
        Arc<noid_recursive::acceptance::history_step::PreparedHistoryStepGhostAuthorization>,
    /// Optional hook called synchronously after block is applied to chain, before
    /// the mempool is updated. Used by the built-in wallet to generate receipts
    /// race-free (receipt ready before getMempoolSize → 0 is observable).
    on_block_applied: Option<BlockAppliedHook>,
    /// Optional dynamic payout. Explicitly configured miner addresses leave
    /// this unset and continue to use `config.miner_address`.
    payout_resolver: Option<MiningPayoutResolver>,
    /// When installed by the full node, prevents a template capture or found
    /// block apply from entering the interval between snapshot commit and the
    /// corresponding mempool/wallet reload. Library-only miners may leave it
    /// unset when no external state-replacement path exists.
    chain_operation_gate: Option<ChainOperationGate>,
}

impl BlockMiner {
    pub fn new(
        config: MinerConfig,
        mempool: AsyncMempool,
        chain: Arc<RwLock<MdbxChainContext>>,
        proof_network_ready: watch::Receiver<bool>,
        nonce_network_ready: watch::Receiver<bool>,
        template_change_sender: broadcast::Sender<()>,
        history_step_runtime: Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>,
        ghost_authorization: Arc<
            noid_recursive::acceptance::history_step::PreparedHistoryStepGhostAuthorization,
        >,
    ) -> (Self, broadcast::Receiver<MinerEvent>) {
        let (events, rx) = broadcast::channel(32);
        let cpu_plan = configured_process_cpu_budget()
            .map(Ok)
            .unwrap_or_else(|| configure_process_cpu_budget(ProcessCpuBudgetMode::InternalMiner))
            .unwrap_or_else(|error| {
                panic!("invalid process CPU budget for internal miner: {error}")
            });
        assert!(
            cpu_plan.pow_phase_threads > 0,
            "internal miner requires a process CPU budget with PoW enabled"
        );
        let pow_threads = cpu_plan.pow_phase_threads;
        let history_step_threads = cpu_plan.history_step_phase_threads;
        tracing::debug!(
            pow_threads,
            history_step_threads,
            "internal miner bounded PoW and HistoryStep pool configured"
        );
        let miner = Self {
            config,
            mempool,
            chain,
            events,
            cancel_pow: Arc::new(AtomicBool::new(false)),
            stopped: Arc::new(AtomicBool::new(false)),
            proof_network_ready,
            nonce_network_ready,
            template_changes: template_change_sender.subscribe(),
            _template_change_sender: template_change_sender,
            history_step_runtime,
            ghost_authorization,
            on_block_applied: None,
            payout_resolver: None,
            chain_operation_gate: None,
        };
        (miner, rx)
    }

    /// Register a callback to be called synchronously after each block is applied
    /// to the chain, before the mempool is updated. The built-in wallet uses this
    /// to generate payment receipts race-free at any mining speed.
    pub fn set_block_applied_hook(&mut self, hook: BlockAppliedHook) {
        self.on_block_applied = Some(hook);
    }

    /// Resolve the wallet's active address for every future template.
    pub fn set_payout_resolver(&mut self, resolver: MiningPayoutResolver) {
        self.payout_resolver = Some(resolver);
    }

    /// Serialize template capture and canonical apply with node-wide snapshot
    /// and reorg replacement. The gate is held only while shared boundaries
    /// are captured/updated, never while HistoryStep proving or PoW runs.
    pub fn set_chain_operation_gate(&mut self, gate: ChainOperationGate) {
        self.chain_operation_gate = Some(gate);
    }

    /// Cancel the current PoW search (call when a new P2P block arrives).
    pub fn cancel_current_pow(&self) {
        self.cancel_pow.store(true, Ordering::Relaxed);
    }

    /// Signal the miner to stop after the current search iteration.
    /// Sets both the permanent `stopped` flag (causes the loop to break) and
    /// `cancel_pow` (causes the current PoW chunk to abort quickly).
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.cancel_pow.store(true, Ordering::SeqCst);
        tracing::info!("miner stop signal sent — Rayon threads will exit at next iteration");
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MinerEvent> {
        self.events.subscribe()
    }

    /// Return a cloned handle to the PoW cancel flag.
    /// Call `handle.store(true, Ordering::SeqCst)` to stop mining cleanly.
    /// This must be called BEFORE `run()` consumes the miner.
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        self.cancel_pow.clone()
    }

    /// Return a cloned handle to the permanent shutdown flag.
    /// Set to `true` (with `Ordering::Release`) to signal the miner loop to
    /// exit after the current PoW chunk finishes. Combine with `stop_handle()`
    /// to also abort the current PoW immediately.
    /// This must be called BEFORE `run()` consumes the miner.
    pub fn stopped_handle(&self) -> Arc<AtomicBool> {
        self.stopped.clone()
    }

    async fn wait_for_proof_network(&mut self) -> bool {
        if *self.proof_network_ready.borrow() {
            return true;
        }
        tracing::info!("miner: waiting for a synchronized authenticated chain view");
        loop {
            if self.stopped.load(Ordering::Acquire) {
                return false;
            }
            tokio::select! {
                result = self.proof_network_ready.changed() => {
                    if result.is_err() {
                        tracing::info!("miner: proof readiness channel closed");
                        return false;
                    }
                    if *self.proof_network_ready.borrow() {
                        tracing::info!("miner: synchronized chain view ready for proving");
                        return true;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
        }
    }

    /// Main mining loop. Run in a dedicated `tokio::spawn` task.
    /// Never returns under normal operation.
    pub async fn run(mut self) {
        let builder = TemplateBuilder::new(self.mempool.clone());
        let cancel = self.cancel_pow.clone();
        let mut heartbeat = interval(Duration::from_secs(self.config.refresh_interval_secs));
        let mut mempool_events = self.mempool.subscribe();
        let mut proof_capacity = AdaptiveProofCapacity::default();

        tracing::debug!("BlockMiner started");

        'mining: loop {
            // Clean shutdown: stop() sets `stopped` permanently; break before
            // starting a new template build so the task exits promptly.
            if self.stopped.load(Ordering::Acquire) {
                tracing::info!("miner: shutdown flag set, exiting loop");
                break;
            }
            if !self.wait_for_proof_network().await {
                break;
            }

            // Changes already observed before this iteration are represented
            // by the fresh parent and payout captured below.
            loop {
                match self.template_changes.try_recv() {
                    Ok(()) | Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
                    Err(broadcast::error::TryRecvError::Empty) => break,
                    Err(broadcast::error::TryRecvError::Closed) => unreachable!(),
                }
            }
            // Readiness may have become true before `run()` began polling its
            // receivers. Mark those current values observed so an old true
            // edge cannot later cancel valid work.
            let _ = *self.proof_network_ready.borrow_and_update();
            let _ = *self.nonce_network_ready.borrow_and_update();

            // --- Build template ---
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Resolve payout under the same chain guard that captures the
            // template snapshot. Account activation takes `chain -> wallet`
            // too, so the selected owner and parent snapshot form one instant.
            // An already-built template remains immutable.
            let chain_operation = match &self.chain_operation_gate {
                Some(gate) => Some(gate.lock().await),
                None => None,
            };
            let (snapshot_result, addr) = {
                let mut ctx = self.chain.write().await;
                let addr =
                    resolve_mining_payout(self.config.miner_address, self.payout_resolver.as_ref());
                (TemplateChainSnapshot::from_context(&mut ctx), addr)
            };
            drop(chain_operation);
            let snapshot = match snapshot_result {
                Ok(snapshot) => snapshot,
                Err(e) => {
                    tracing::warn!(err = ?e, "template snapshot failed, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            if !mining_launch_is_open(&snapshot.parent, now) {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            let max_effective_pages = proof_capacity.page_limit();
            let tmpl = match builder
                .build_from_snapshot_with_limit(snapshot, addr, now, max_effective_pages)
                .await
            {
                Some(t) => t,
                None => {
                    tracing::warn!("template build failed, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let height = tmpl.inner.height;
            let n_txs = tmpl.inner.n_txs();

            let _ = self.events.send(MinerEvent::TemplateRefreshed {
                height,
                n_txs,
                trigger: TemplateRefreshTrigger::Startup,
            });
            tracing::debug!(height, n_txs, max_effective_pages, "mining template ready");

            let expected_parent_height = tmpl.parent.height;
            let expected_parent_hash = block_id(&tmpl.parent);
            let prepare_runtime = Arc::clone(&self.history_step_runtime);
            let prepare_ghost = Arc::clone(&self.ghost_authorization);
            let prepare_cancellation = Arc::new(AtomicBool::new(false));
            let worker_cancellation = Arc::clone(&prepare_cancellation);
            let mut prepare_handle = tokio::task::spawn_blocking(move || {
                let started = Instant::now();
                let result = install_history_step_phase_cpu(|| {
                    PreparedBlockAttempt::prepare_cancellable(
                        tmpl,
                        &prepare_runtime,
                        &prepare_ghost,
                        now,
                        &worker_cancellation,
                    )
                })
                .map_err(|error| format!("HistoryStep preparation CPU phase: {error}"))
                .and_then(|result| result);
                (result, started.elapsed())
            });
            let prepare_result = loop {
                tokio::select! {
                    result = &mut prepare_handle => break result,
                    template_change = self.template_changes.recv() => {
                        prepare_cancellation.store(true, Ordering::Release);
                        let _ = prepare_handle.await;
                        match template_change {
                            Ok(()) => tracing::debug!(height, "canonical/template change cancelled HistoryStep preparation"),
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                tracing::debug!(height, skipped, "lagged template change cancelled HistoryStep preparation");
                            }
                            Err(broadcast::error::RecvError::Closed) => unreachable!(),
                        }
                        continue 'mining;
                    }
                    readiness = self.proof_network_ready.changed() => {
                        match readiness {
                            Ok(()) if !*self.proof_network_ready.borrow() => {
                                prepare_cancellation.store(true, Ordering::Release);
                                let _ = prepare_handle.await;
                                tracing::info!(height, "miner: canonical sync authority cancelled HistoryStep preparation");
                                continue 'mining;
                            }
                            Ok(()) => {}
                            Err(_) => {
                                prepare_cancellation.store(true, Ordering::Release);
                                let _ = prepare_handle.await;
                                break 'mining;
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {
                        if self.stopped.load(Ordering::Acquire) {
                            prepare_cancellation.store(true, Ordering::Release);
                            let _ = prepare_handle.await;
                            break 'mining;
                        }
                    }
                }
            };
            let (attempt, prepare_elapsed) = match prepare_result {
                Ok((Ok(Some(attempt)), elapsed)) => (attempt, elapsed),
                Ok((Ok(None), elapsed)) => {
                    tracing::debug!(
                        height,
                        prepare_ms = elapsed.as_millis(),
                        "HistoryStep preparation cancelled before completion"
                    );
                    continue;
                }
                Ok((Err(error), elapsed)) => {
                    tracing::error!(
                        height,
                        prepare_ms = elapsed.as_millis(),
                        %error,
                        "HistoryStep witness preparation failed"
                    );
                    let _ = self.events.send(MinerEvent::ProveFailed { height, error });
                    continue;
                }
                Err(error) => {
                    tracing::error!(height, ?error, "HistoryStep preparation task panicked");
                    continue;
                }
            };

            let user_pages = attempt.user_page_count();
            let proof_class = attempt.proof_class();

            // Complete class cost is independent of live-page occupancy. A
            // coinbase-only B25 therefore calibrates the hardware just as a
            // full B25 block does.
            let previous_page_limit = proof_capacity.page_limit();
            proof_capacity.observe_preparation(proof_class, prepare_elapsed);
            let next_page_limit = proof_capacity.page_limit();
            let b25_prepare_ms_ewma = proof_capacity.prepare_ms_ewma(BlockProofClass::B25);
            let b255_prepare_ms_ewma = proof_capacity.prepare_ms_ewma(BlockProofClass::B255);
            if previous_page_limit != next_page_limit {
                tracing::info!(
                    ?proof_class,
                    previous_page_limit,
                    next_page_limit,
                    prepare_ms = prepare_elapsed.as_millis(),
                    b25_prepare_ms_ewma,
                    b255_prepare_ms_ewma,
                    "miner proof capacity changed"
                );
            }

            // HistoryStep preparation is deliberately atomic and therefore
            // may finish after a shutdown request. Never turn that completed
            // work into a new block: discard it before resetting the PoW
            // cancellation flag.
            if self.stopped.load(Ordering::Acquire) {
                tracing::info!(
                    height,
                    "miner: shutdown requested during preparation; discarding prepared block"
                );
                break;
            }
            if !*self.proof_network_ready.borrow() {
                tracing::info!(
                    height,
                    "miner: canonical sync changed during preparation; discarding prepared block"
                );
                continue;
            }

            // Preparation may be expensive. Refuse to spend PoW on a parent
            // that was replaced while it ran; the final commit repeats this
            // exact-parent check under the canonical write lock.
            let parent_is_still_tip = {
                let context = self.chain.read().await;
                context.tip_height() == expected_parent_height
                    && block_id(context.tip_header()) == expected_parent_hash
            };
            if !parent_is_still_tip {
                tracing::debug!(height, "prepared template parent changed before PoW");
                continue;
            }
            match self.template_changes.try_recv() {
                Ok(()) => {
                    tracing::debug!(height, "prepared template input changed before PoW");
                    continue;
                }
                Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                    tracing::debug!(
                        height,
                        skipped,
                        "template-change receiver lagged before PoW"
                    );
                    continue;
                }
                Err(broadcast::error::TryRecvError::Empty) => {}
                Err(broadcast::error::TryRecvError::Closed) => unreachable!(),
            }

            // Frontier authorization may lag an ordinary child commit by one
            // compact header round-trip. Preserve the expensive prepared
            // transition while waiting; only a real parent/sync change makes
            // it stale.
            if !*self.nonce_network_ready.borrow() {
                tracing::info!(
                    height,
                    "miner: proof ready; waiting for exact frontier authorization"
                );
                loop {
                    if self.stopped.load(Ordering::Acquire) {
                        break 'mining;
                    }
                    tokio::select! {
                        readiness = self.nonce_network_ready.changed() => {
                            match readiness {
                                Ok(()) if *self.nonce_network_ready.borrow() => break,
                                Ok(()) => {}
                                Err(_) => break 'mining,
                            }
                        }
                        readiness = self.proof_network_ready.changed() => {
                            match readiness {
                                Ok(()) if !*self.proof_network_ready.borrow() => {
                                    tracing::info!(height, "miner: canonical sync changed while awaiting frontier authorization");
                                    continue 'mining;
                                }
                                Ok(()) => {}
                                Err(_) => break 'mining,
                            }
                        }
                        template_change = self.template_changes.recv() => {
                            match template_change {
                                Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => {
                                    tracing::debug!(height, "prepared template parent changed while awaiting frontier authorization");
                                    continue 'mining;
                                }
                                Err(broadcast::error::RecvError::Closed) => unreachable!(),
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                    }
                }
                let parent_is_still_tip = {
                    let context = self.chain.read().await;
                    context.tip_height() == expected_parent_height
                        && block_id(context.tip_header()) == expected_parent_hash
                };
                if !parent_is_still_tip || !*self.proof_network_ready.borrow() {
                    tracing::debug!(height, "prepared template became stale before nonce search");
                    continue;
                }
            }

            tracing::info!(
                height,
                txs = n_txs,
                user_pages,
                ?proof_class,
                prepare_ms = prepare_elapsed.as_millis(),
                "mining complete block"
            );

            // `watch::Receiver::changed` is edge-triggered. Readiness may
            // have become true while this miner was waiting to start or
            // while the proof was being built; consume that already-observed
            // version before entering the PoW select. Otherwise the stale
            // true edge wakes the select immediately and throws away a valid
            // proof even though network authorization never changed.
            let _ = *self.proof_network_ready.borrow_and_update();
            let _ = *self.nonce_network_ready.borrow_and_update();

            // Phase 2: all workers search the already-proven semantic header.
            // A winning nonce only seals the nonce-free HistoryStep terminal.
            let pow_header = attempt.pow_header(0);
            let cancel_pow = Arc::clone(&cancel);
            cancel.store(false, Ordering::Relaxed);
            // Close the race where shutdown set cancel between the check
            // above and the reset. A later shutdown cannot be lost because it
            // sets cancel after this point and the PoW worker observes it.
            if self.stopped.load(Ordering::Acquire) {
                cancel.store(true, Ordering::SeqCst);
                tracing::info!(
                    height,
                    "miner: shutdown requested before PoW; discarding prepared block"
                );
                break;
            }
            heartbeat.reset();
            let pow_start = Instant::now();
            let mut pow_handle = tokio::task::spawn_blocking(move || {
                install_pow_phase_cpu(|| crate::pow::search_pow_parallel(&pow_header, &cancel_pow))
            });

            tokio::select! {
                pow_res = &mut pow_handle => {
                    match pow_res {
                        Ok(Ok(Some(sol))) => {
                            if self.stopped.load(Ordering::Acquire) {
                                tracing::info!(height, "miner: shutdown requested after PoW; discarding nonce");
                                break 'mining;
                            }
                            if !*self.proof_network_ready.borrow()
                                || !*self.nonce_network_ready.borrow()
                            {
                                tracing::info!(height, "miner: network authority changed after PoW; discarding nonce");
                                continue;
                            }
                            let nonce_found_at = Instant::now();
                            let sealed_header = attempt.pow_header(sol.nonce);
                            let hash = block_id(&sealed_header);
                            let elapsed = pow_start.elapsed();
                            let elapsed_s = elapsed.as_secs_f64();

                            // Count leading zeros of the difficulty target (MSB-first, LE).
                            // Matches block_work() in difficulty.rs — higher = harder.
                            // Genesis = 27lz. ASERT raises this when blocks arrive faster
                            // than BLOCK_TIME and lowers it when they're slower.
                            let diff_lz = noid_chain::consensus::target_leading_zero_bits(
                                &sealed_header.difficulty_target,
                            );

                            tracing::debug!(
                                height,
                                hash = %hex::encode(hash),
                                n_txs,
                                prepare_ms = prepare_elapsed.as_millis(),
                                ?proof_class,
                                b25_prepare_ms_ewma,
                                b255_prepare_ms_ewma,
                                pow_time = %format!("{elapsed_s:.2}s"),
                                diff = %format!("lz{diff_lz}"),
                                "PoW nonce found; sealing prepared HistoryStep"
                            );

                            let seal_runtime = Arc::clone(&self.history_step_runtime);
                            let seal_handle = tokio::task::spawn_blocking(move || {
                                let started = Instant::now();
                                let result = install_history_step_phase_cpu(|| {
                                    attempt.prove(&seal_runtime, sol.nonce)
                                })
                                .map_err(|error| format!("HistoryStep seal CPU phase: {error}"))
                                .and_then(|result| result);
                                (result, started.elapsed())
                            });
                            let (proved, seal_elapsed) = match seal_handle.await {
                                Ok((Ok(proved), elapsed)) => (proved, elapsed),
                                Ok((Err(error), elapsed)) => {
                                    tracing::error!(
                                        height,
                                        seal_ms = elapsed.as_millis(),
                                        %error,
                                        "prepared HistoryStep sealing failed"
                                    );
                                    let _ = self.events.send(MinerEvent::ProveFailed { height, error });
                                    continue;
                                }
                                Err(error) => {
                                    tracing::error!(height, ?error, "HistoryStep sealing task panicked");
                                    continue;
                                }
                            };

                            if self.stopped.load(Ordering::Acquire) {
                                tracing::info!(height, "miner: shutdown requested during seal; discarding proved block");
                                break 'mining;
                            }
                            if !*self.proof_network_ready.borrow()
                                || !*self.nonce_network_ready.borrow()
                            {
                                tracing::info!(height, "miner: network authority changed during seal; discarding proved block");
                                continue;
                            }

                            // IMPORTANT: apply and store the block FIRST, THEN fire the event.
                            // The announcement triggers peers to request the block immediately;
                            // if we fire the event before storing, a fast peer gets None.
                            let proved = match self.apply_found_block(proved, addr).await {
                                Ok(proved) => proved,
                                Err(error) => {
                                    tracing::warn!(height, "miner: block superseded: {error}");
                                    continue;
                                }
                            };
                            tracing::info!(
                                height,
                                hash = %hex::encode(hash),
                                txs = n_txs,
                                pow_ms = elapsed.as_millis(),
                                history_step_ms = prepare_elapsed.as_millis(),
                                seal_ms = seal_elapsed.as_millis(),
                                nonce_to_commit_ms = nonce_found_at.elapsed().as_millis(),
                                "block accepted"
                            );

                            // Now safe to announce: the complete bundle is durable.
                            let _ = self.events.send(MinerEvent::BlockFound {
                                height,
                                hash,
                                n_txs,
                                pow_nonce: sol.nonce,
                                bundle: proved.into_parts().1,
                            });
                        }
                        Ok(Ok(None)) => {
                            // PoW cancelled.
                            let _ = self.events.send(MinerEvent::MiningCancelled {
                                reason: "cancelled".into(),
                            });
                        }
                        Ok(Err(error)) => {
                            tracing::error!(height, %error, "PoW CPU admission failed");
                        }
                        Err(error) => {
                            tracing::error!(height, ?error, "PoW task panicked");
                        }
                    }
                }

                _ = heartbeat.tick(), if user_pages == 0 => {
                    cancel.store(true, Ordering::Relaxed);
                    let _ = pow_handle.await;
                    tracing::debug!("heartbeat: refreshing coinbase-only template (safety net)");
                }

                refresh = next_mining_mempool_refresh(&mut mempool_events), if user_pages == 0 => {
                    // No blocking PoW task may escape this select branch. A
                    // new transaction must be included immediately. Lag is
                    // conservative because the missed range may contain an
                    // admission; previous-height confirmations are filtered
                    // inside `next_mining_mempool_refresh`.
                    cancel.store(true, Ordering::Relaxed);
                    let _ = pow_handle.await;
                    match refresh {
                        MiningMempoolRefresh::TransactionAdmitted => {
                            tracing::debug!("coinbase-only template: new tx admitted, cancelling PoW for immediate inclusion");
                        }
                        MiningMempoolRefresh::ReceiverLagged(skipped) => {
                            tracing::debug!(skipped, "coinbase-only template: mempool receiver lagged, rebuilding after PoW drain");
                        }
                    }
                }

                template_change = self.template_changes.recv() => {
                    // A new chain tip or wallet payout invalidates this exact template.
                    cancel.store(true, Ordering::Relaxed);
                    let _ = pow_handle.await;
                    match template_change {
                        Ok(()) => tracing::debug!("template input changed: cancelling PoW to rebuild"),
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::debug!(skipped, "template-change receiver lagged: cancelling PoW to rebuild");
                        }
                        // The miner owns a sender, so closure is unreachable
                        // until the miner itself is dropped.
                        Err(broadcast::error::RecvError::Closed) => unreachable!(),
                    }
                }

                readiness = self.nonce_network_ready.changed() => {
                    cancel.store(true, Ordering::Relaxed);
                    let _ = pow_handle.await;
                    match readiness {
                        Ok(()) if !*self.nonce_network_ready.borrow() => {
                            tracing::info!("miner: frontier authorization lost; pausing nonce search");
                        }
                        Ok(()) => {
                            tracing::debug!("miner: frontier authorization changed; rebuilding");
                        }
                        Err(_) => break 'mining,
                    }
                }

                readiness = self.proof_network_ready.changed() => {
                    cancel.store(true, Ordering::Relaxed);
                    let _ = pow_handle.await;
                    match readiness {
                        Ok(()) if !*self.proof_network_ready.borrow() => {
                            tracing::info!("miner: canonical sync authority changed; discarding template");
                        }
                        Ok(()) => {
                            tracing::debug!("miner: proof readiness changed; rebuilding");
                        }
                        Err(_) => break 'mining,
                    }
                }
            }
        }
    }

    /// Apply a found block to the chain and update the mempool.
    ///
    /// # Lock strategy
    ///
    /// Write lock is held for MDBX commit + wallet hook + ChainView clone.
    /// Building ChainView inside the write lock adds zero contention (the lock
    /// is already exclusive) and eliminates a separate ~50ms read lock.
    async fn apply_found_block(
        &self,
        proved: ProvedBlock,
        expected_payout: Address,
    ) -> anyhow::Result<crate::block_production::CommittedBlock> {
        use noid_mempool::ChainView;

        // Snapshot installation retains this gate from before its atomic MDBX
        // commit through mempool and wallet reload. A mined block therefore
        // cannot observe the new parent and publish a newer ChainView halfway
        // through that replacement sequence.
        let chain_operation = match &self.chain_operation_gate {
            Some(gate) => Some(gate.lock().await),
            None => None,
        };
        if self.payout_resolver.is_some()
            && resolve_mining_payout(self.config.miner_address, self.payout_resolver.as_ref())
                != expected_payout
        {
            anyhow::bail!("wallet mining payout changed");
        }

        // --- MDBX commit + ChainView build off the async executor ---
        //
        // SyncMode::Durable means commit_block issues fsync before returning —
        // a blocking syscall.  spawn_blocking keeps it off the tokio worker.
        // The wallet hook fires inside the closure while the write lock is
        // still held, preserving the original "hook before mempool" ordering.
        // ChainView is built inside the write lock (no added contention since
        // the lock is already exclusive).
        let (new_view, committed) = {
            let chain_clone = self.chain.clone();
            let hook = self.on_block_applied.clone();
            tokio::task::spawn_blocking(move || {
                let mut ctx = chain_clone.blocking_write();
                let committed = proved.commit(&mut ctx)?;
                if let Some(h) = &hook {
                    h(committed.block());
                }
                let view = ChainView::from_mdbx(&ctx);
                Ok::<_, noid_chain::storage::MdbxContextError>((view, committed))
            })
            .await
            .expect("apply_next_block panicked in spawn_blocking")
            .map_err(anyhow::Error::from)?
        };

        // --- Update mempool (no chain lock held) ---
        let block = committed.block();
        let confirmed = noid_chain::try_compute_logical_txids(&block.transactions)
            .expect("locally committed block has a canonical logical tx stream");
        self.mempool
            .on_new_block(&confirmed, block.header.height, new_view)
            .await;
        drop(chain_operation);

        Ok(committed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU8;

    #[test]
    fn payout_resolver_is_dynamic_while_configured_address_is_fixed() {
        let configured = noid_poseidon2b::primitives::Address([0x11; 32]);
        assert_eq!(resolve_mining_payout(configured, None), configured);

        let marker = Arc::new(AtomicU8::new(0x22));
        let resolver_marker = Arc::clone(&marker);
        let resolver: MiningPayoutResolver = Arc::new(move || {
            noid_poseidon2b::primitives::Address([resolver_marker.load(Ordering::Relaxed); 32])
        });
        assert_eq!(
            resolve_mining_payout(configured, Some(&resolver)),
            noid_poseidon2b::primitives::Address([0x22; 32])
        );
        marker.store(0x33, Ordering::Relaxed);
        assert_eq!(
            resolve_mining_payout(configured, Some(&resolver)),
            noid_poseidon2b::primitives::Address([0x33; 32])
        );
    }

    #[tokio::test]
    async fn previous_height_confirmation_does_not_cancel_fresh_pow() {
        let (sender, mut receiver) = broadcast::channel(8);
        sender
            .send(MempoolEvent::TxConfirmed {
                hash: noid_poseidon2b::primitives::TxBodyHash([0x11; 32]),
                block_height: 1,
            })
            .unwrap();

        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                next_mining_mempool_refresh(&mut receiver),
            )
            .await
            .is_err(),
            "a confirmation from our own previous block must be ignored",
        );

        sender
            .send(MempoolEvent::TxAdmitted {
                hash: noid_poseidon2b::primitives::TxBodyHash([0x22; 32]),
                fee: 1,
                intent_bytes: Arc::from(Vec::<u8>::new().into_boxed_slice()),
            })
            .unwrap();
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                next_mining_mempool_refresh(&mut receiver),
            )
            .await
            .unwrap(),
            MiningMempoolRefresh::TransactionAdmitted,
        );
    }
}
