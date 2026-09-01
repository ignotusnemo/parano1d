// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! # parano1d — ParanO(1)d Full Node Binary
//!
//! Startup sequence:
//! 1. Load config + init tracing
//! 2. Open MDBX (open_or_create — genesis if first run)
//! 3. Start mempool (ChainView snapshot from MDBX)
//! 4. Start P2P network (gossipsub + req-resp)
//! 5. Dial seed peers
//! 6. Start RPC server (JSON-RPC on configured address)
//! 7. Start miner (if --mine or config.mining.enabled)
//! 8. Shutdown on Ctrl-C

#![allow(clippy::items_after_test_module)]

// ---------------------------------------------------------------------------
// Global allocator: jemalloc
//
// glibc malloc retains freed pages from large proof-generation allocations (FRI/NTT Vecs,
// often 10-100 MB each) indefinitely, causing 3-4 GB RSS fragmentation on
// a full node even with only a few hundred active UTXOs.
//
// jemalloc with background_threads enabled returns dirty pages to the OS
// within dirty_decay_ms (default 10 000 ms) via a background reclaim thread.
// This keeps the node's RSS proportional to actual working set size.
// ---------------------------------------------------------------------------
#[cfg(unix)]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
};

use anyhow::Context;
use clap::Parser;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

use noid_chain::consensus::wire_limits::MAX_TX_INTENT_BYTES_GLOBAL;
use noid_chain::consensus::NetworkConfig;
use noid_chain::storage::snapshot_staging::{
    AuthenticatedSnapshotMetadata, FinalizedSnapshotStaging, SnapshotStagingError,
    SnapshotStagingSession,
};
use noid_chain::storage::{MdbxChainContext, MdbxStore, SnapshotSegmentDescriptor};
use noid_mempool::{AsyncMempool, ChainView, MempoolConfig};
use noid_miner::{BlockMiner, MinerConfig};
use noid_node::snapshot_header_staging::{
    validate_bounded_header_extension, CanonicalHeaderBoundary, SnapshotHeaderBoundary,
    SnapshotHeaderStaging, SnapshotHeaderStagingError, ValidatedSnapshotHeaderStaging,
    MAX_STAGED_HEADER_BATCH,
};
use noid_p2p::{NetworkEvent, P2PNetwork};
use noid_rpc::types::NodeSyncStage;
use noid_rpc::{start_rpc_server, ExternalMiningAttemptInvalidator, WalletOperationGate};

struct AppliedCompactSuffix {
    height: u64,
    block_hash: [u8; 32],
    confirmed_tx_hashes: Vec<noid_poseidon2b::primitives::TxBodyHash>,
    view: ChainView,
    applied_blocks: u64,
    payload_bytes: u64,
    apply_elapsed: std::time::Duration,
    trailing_error: Option<ExactSuffixApplyError>,
}

enum AppliedExactSuffix {
    Live(AppliedCompactSuffix),
    Reorg(AppliedReorg),
}

#[derive(Debug)]
enum ExactSuffixApplyError {
    Terminal {
        source: libp2p::PeerId,
        error: String,
    },
    Body {
        sources: Vec<libp2p::PeerId>,
        error: String,
    },
    Other(String),
}

impl ExactSuffixApplyError {
    fn terminal(source: libp2p::PeerId, error: impl Into<String>) -> Self {
        Self::Terminal {
            source,
            error: error.into(),
        }
    }

    fn body(source: libp2p::PeerId, error: impl Into<String>) -> Self {
        Self::Body {
            sources: vec![source],
            error: error.into(),
        }
    }

    fn peer_sources(&self) -> &[libp2p::PeerId] {
        match self {
            Self::Terminal { source, .. } => std::slice::from_ref(source),
            Self::Body { sources, .. } => sources,
            Self::Other(_) => &[],
        }
    }

    fn is_terminal_fault(&self) -> bool {
        matches!(self, Self::Terminal { .. })
    }
}

impl std::fmt::Display for ExactSuffixApplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Terminal { error, .. } | Self::Body { error, .. } | Self::Other(error) => {
                formatter.write_str(error)
            }
        }
    }
}

struct AppliedReorg {
    result: noid_chain::consensus::ReorgResult,
    confirmed_tx_hashes: Vec<noid_poseidon2b::primitives::TxBodyHash>,
    view: ChainView,
}

/// Canonical common ancestor from which a verified fork-choice-winning snapshot may
/// replace only the local, non-final suffix.  This is armed only after native
/// header validation and ordinary fork-choice comparison have already selected
/// a better branch; the atomic installer independently rechecks work and
/// finality before replacing anything.
#[derive(Clone, Copy)]
struct SnapshotRebaseHint {
    ancestor_height: u64,
    ancestor_hash: [u8; 32],
    competing_tip_height: u64,
    competing_tip_hash: [u8; 32],
    armed_at: Instant,
}

/// Exact HeaderDAG point which a farther on-disk snapshot candidate must cross.
/// This lets bounded in-memory fork discovery hand off to the existing
/// O(height)-on-disk header validator without trusting the manifest's claimed
/// ancestry or cumulative work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SnapshotRebaseAnchor {
    height: u64,
    hash: [u8; 32],
    cumulative_work: [u8; 32],
}

/// One temporary exact-object allowance after a verified snapshot jump.
///
/// Ordinary catch-up switches to a snapshot as soon as a deterministic
/// finalized snapshot boundary exists ahead of the committed State. A
/// snapshot itself lands on that finalized generation, so the live tip learned
/// after its commit can be farther away while State was transferred. The
/// larger 42-block serving window exists only to discover and finish this one
/// authenticated tail; it must never become the ordinary sync threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PostSnapshotTail {
    boundary: noid_node::networking::ChainPoint,
    target: Option<noid_node::networking::ChainPoint>,
}

impl PostSnapshotTail {
    fn serving_limit(self) -> u64 {
        self.boundary
            .height
            .saturating_add(noid_chain::consensus::params::RETAINED_BLOCK_SERVING_DEPTH)
    }

    /// Header requests include the local anchor. Probe the complete one-shot
    /// serving allowance so HeaderDAG can choose the best available tail before
    /// exact objects are committed in several artificial 19-block steps.
    fn probe_count(self, local_height: u64) -> Option<u16> {
        let serving_limit = self.serving_limit();
        (local_height >= self.boundary.height && local_height <= serving_limit).then(|| {
            serving_limit
                .saturating_sub(local_height)
                .saturating_add(1)
                .min(DIRECT_SYNC_HEADER_REQUEST_CAP)
                .min(u64::from(u16::MAX)) as u16
        })
    }

    fn allows_exact_target(self, local_height: u64, candidate_height: u64) -> bool {
        let serving_limit = self.serving_limit();
        // The first authenticated target fixes the lifetime of this allowance,
        // not its height ceiling. A fresher HeaderDAG-selected descendant may
        // arrive while that immutable suffix is still being applied; admission
        // below will defer it instead of restarting the active plan.
        local_height >= self.boundary.height
            && candidate_height > local_height
            && candidate_height <= serving_limit
            && self
                .target
                .is_none_or(|target| target.height <= serving_limit && local_height < target.height)
    }

    /// Pin the first target selected by native HeaderDAG validation after the
    /// snapshot commit. Raw announcements can trigger header discovery inside
    /// the bounded serving window, but cannot set this target.
    fn pin_selected_target(
        &mut self,
        local: noid_node::networking::ChainPoint,
        selected: noid_node::networking::ChainPoint,
    ) -> bool {
        if self.target.is_some() {
            return self.target == Some(selected);
        }
        if local.height < self.boundary.height
            || selected.height <= local.height
            || selected.height > self.serving_limit()
        {
            return false;
        }
        self.target = Some(selected);
        true
    }

    fn is_finished_or_invalid_at(self, local_height: u64) -> bool {
        local_height < self.boundary.height
            || self
                .target
                .is_some_and(|target| local_height >= target.height)
    }
}

fn newest_deterministic_snapshot_boundary(peer_height: u64) -> u64 {
    let finalized_height =
        peer_height.saturating_sub(noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH);
    finalized_height - finalized_height % noid_p2p::protocol::SNAPSHOT_BOUNDARY_INTERVAL
}

fn gap_requires_snapshot_sync(local_height: u64, peer_height: u64) -> bool {
    peer_height > local_height && newest_deterministic_snapshot_boundary(peer_height) > local_height
}

fn sync_target_requires_snapshot(
    local_height: u64,
    peer_height: u64,
    post_snapshot_tail: Option<PostSnapshotTail>,
) -> bool {
    gap_requires_snapshot_sync(local_height, peer_height)
        && !post_snapshot_tail
            .is_some_and(|tail| tail.allows_exact_target(local_height, peer_height))
}

/// A proactive manifest is only a discovery hint while the verified snapshot
/// is still completing its bounded exact tail. HeaderDAG may explicitly
/// authorize a new snapshot by marking the correlated request as forced.
fn unforced_manifest_waits_for_header_dag(
    force_snapshot: bool,
    post_snapshot_tail: Option<PostSnapshotTail>,
) -> bool {
    !force_snapshot && post_snapshot_tail.is_some()
}

fn canonical_tip_supersedes_snapshot_boundary(
    canonical_tip_height: u64,
    canonical_boundary: Option<noid_node::networking::ChainPoint>,
    snapshot_boundary: noid_node::networking::ChainPoint,
) -> bool {
    canonical_tip_height >= snapshot_boundary.height
        && canonical_boundary == Some(snapshot_boundary)
}

fn validate_snapshot_install_selection(
    header_dag: &noid_node::networking::header_dag::HeaderDag,
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
) -> Result<Option<SnapshotRebaseAnchor>, String> {
    let selected_tip = header_dag.best_tip();
    if manifest.tip_height > selected_tip.height {
        let selected_work = header_dag
            .cumulative_work(selected_tip)
            .map_err(|error| format!("selected snapshot anchor work is unavailable: {error}"))?;
        if !matches!(
            noid_chain::choose_chain_by_work(
                &manifest.cumulative_chainwork,
                &manifest.tip_hash,
                &selected_work,
                &selected_tip.hash,
            ),
            noid_chain::consensus::fork_choice::ChainChoice::A
        ) {
            return Err("snapshot boundary does not improve the HeaderDAG-selected work".into());
        }
        return Ok(Some(SnapshotRebaseAnchor {
            height: selected_tip.height,
            hash: selected_tip.hash,
            cumulative_work: selected_work,
        }));
    }
    let boundary = header_dag
        .point_at_height(selected_tip, manifest.tip_height)
        .map_err(|error| format!("snapshot boundary is absent from selected ancestry: {error}"))?;
    if boundary.hash != manifest.tip_hash {
        return Err("snapshot boundary hash is not on the HeaderDAG-selected ancestry".into());
    }
    let boundary_work = header_dag
        .cumulative_work(boundary)
        .map_err(|error| format!("selected snapshot boundary work is unavailable: {error}"))?;
    if boundary_work != manifest.cumulative_chainwork {
        return Err("snapshot boundary work differs from HeaderDAG authority".into());
    }
    Ok(None)
}

fn validate_rebase_snapshot_selection(
    header_dag: &noid_node::networking::header_dag::HeaderDag,
    hint: SnapshotRebaseHint,
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
) -> Result<Option<SnapshotRebaseAnchor>, String> {
    use noid_node::networking::ChainPoint;

    let hinted_tip = ChainPoint::new(hint.competing_tip_height, hint.competing_tip_hash);
    let selected_tip = header_dag.best_tip();
    if !header_dag
        .is_ancestor(hinted_tip, selected_tip)
        .map_err(|error| format!("selected snapshot target is no longer in HeaderDAG: {error}"))?
    {
        return Err("selected snapshot target was superseded by another header branch".into());
    }
    if manifest.tip_height <= hint.ancestor_height {
        return Err("snapshot boundary is outside the selected replacement ancestry".into());
    }
    validate_snapshot_install_selection(header_dag, manifest)
}

/// Admit one exact header job to the reserved header lane before publishing
/// any in-flight correlation state. A full lane leaves the job Wanted; it must
/// never create a phantom request that suppresses later gossip or retries.
const fn direct_header_request_within_cap(count: u16) -> bool {
    count as u64 <= DIRECT_SYNC_HEADER_REQUEST_CAP
}

fn try_dispatch_header_fetch(
    p2p_cmd: &noid_p2p::NetworkCommandSender,
    fetch_in_progress: &mut std::collections::HashSet<libp2p::PeerId>,
    recent_header_fetches: &mut std::collections::HashMap<(libp2p::PeerId, u64, u16), Instant>,
    peer: libp2p::PeerId,
    start_height: u64,
    count: u16,
    requested_at: Instant,
) -> bool {
    if !direct_header_request_within_cap(count) {
        tracing::error!(
            peer = %peer,
            start_height,
            count,
            cap = DIRECT_SYNC_HEADER_REQUEST_CAP,
            "refusing oversized direct header request"
        );
        return false;
    }
    if fetch_in_progress.contains(&peer) {
        return false;
    }
    if p2p_cmd
        .try_send(noid_p2p::NetworkCommand::FetchHeaders {
            peer,
            start_height,
            count,
        })
        .is_err()
    {
        tracing::debug!(
            peer = %peer,
            start_height,
            count,
            "header request remains Wanted behind the reserved header lane"
        );
        return false;
    }
    fetch_in_progress.insert(peer);
    recent_header_fetches.insert((peer, start_height, count), requested_at);
    true
}

fn finalized_header_search_floor(local_height: u64) -> u64 {
    local_height.saturating_sub(noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH)
}

fn header_batch_exhausts_nonfinal_window(local_height: u64, oldest_height: u64) -> bool {
    oldest_height <= finalized_header_search_floor(local_height)
}

#[cfg(test)]
fn competing_suffix_wins(
    competing_work: &[u8; 32],
    competing_tip_hash: &[u8; 32],
    local_work: &[u8; 32],
    local_tip_hash: &[u8; 32],
) -> bool {
    matches!(
        noid_chain::choose_chain_by_work(
            competing_work,
            competing_tip_hash,
            local_work,
            local_tip_hash,
        ),
        noid_chain::consensus::fork_choice::ChainChoice::A
    )
}

fn nonfinal_header_discovery_range(local_height: u64) -> Option<(u64, u16)> {
    if local_height == 0 {
        return None;
    }
    let start_height = finalized_header_search_floor(local_height);
    let count = local_height.saturating_sub(start_height).saturating_add(1);
    Some((
        start_height,
        u16::try_from(count).expect("finality-bounded header discovery count fits u16"),
    ))
}

fn selected_tip_probe_range(local_height: u64, selected_height: u64, cap: u16) -> (u64, u16) {
    let count = selected_height
        .saturating_sub(local_height)
        .saturating_add(1)
        .max(1)
        .min(u64::from(cap)) as u16;
    let start_height = selected_height
        .saturating_add(1)
        .saturating_sub(u64::from(count));
    (start_height.max(local_height), count)
}

/// Ordinary recent/direct recovery stays deliberately smaller than the 4,096
/// record compressed wire batch used by snapshot and long-range header sync.
const DIRECT_SYNC_HEADER_REQUEST_CAP: u64 = 512;

/// Re-query every object-bearing header between the committed and selected
/// tips while also leaving room to discover descendants that gossip may have
/// missed.  A tail-only request cannot recover an unavailable body near the
/// base and can keep the selected tip frozen just below the snapshot-routing
/// threshold.
fn unresolved_tip_probe_range(
    base_height: u64,
    selected_height: u64,
    forward_headers: u16,
) -> (u64, u16) {
    let selected_span = selected_height
        .saturating_sub(base_height)
        .saturating_add(1);
    let count = selected_span
        .saturating_add(u64::from(forward_headers))
        .min(DIRECT_SYNC_HEADER_REQUEST_CAP)
        .max(1) as u16;
    (base_height, count)
}

fn unresolved_selected_tip_probe_range(
    dag: &noid_node::networking::header_dag::HeaderDag,
    committed_tip: noid_node::networking::ChainPoint,
    forward_headers: u16,
) -> Result<(u64, u16), noid_node::networking::header_dag::HeaderDagError> {
    let (base, _) = dag.selected_path_from(committed_tip)?;
    Ok(unresolved_tip_probe_range(
        base.height,
        dag.best_tip().height,
        forward_headers,
    ))
}

fn snapshot_rebase_discovery_range(finalized_height: u64, target_height: u64) -> (u64, u16) {
    unresolved_tip_probe_range(finalized_height, target_height, 0)
}

fn mark_initial_sync_ready(sender: &tokio::sync::watch::Sender<bool>) {
    let already_ready = *sender.borrow();
    if !already_ready {
        sender.send_replace(true);
    }
}

fn advance_initial_sync_stage(
    current: NodeSyncStage,
    state_active: bool,
    tip_active: bool,
) -> NodeSyncStage {
    let observed = if state_active {
        NodeSyncStage::State
    } else if tip_active {
        NodeSyncStage::Tip
    } else {
        NodeSyncStage::Headers
    };

    match (current, observed) {
        (NodeSyncStage::Tip, _) => NodeSyncStage::Tip,
        (NodeSyncStage::State, NodeSyncStage::Headers) => NodeSyncStage::State,
        (_, observed) => observed,
    }
}

fn initial_sync_may_skip_peer_confirmation(isolated_genesis: bool) -> bool {
    isolated_genesis
}

const MINING_PEER_QUORUM: usize = 1;
const CONNECTED_TIP_PROBE_HEADERS: u16 = (noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH
    + noid_p2p::protocol::SNAPSHOT_BOUNDARY_INTERVAL
    + 1) as u16;
/// A gossipsub forwarder is not necessarily the node which produced or has
/// already stored the announced block. Probe the forwarder plus a small
/// bounded set of maintained neighbours immediately instead of waiting for
/// the 30-second stale-tip recovery path.
const EXACT_INVENTORY_PROBE_LANES: usize = 3;
const EXACT_INVENTORY_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const EXACT_INVENTORY_RETRY_TTL: std::time::Duration = std::time::Duration::from_secs(2);
/// Keep one low-rate authenticated tip lane alive after mining readiness.
/// Gossip is intentionally only a latency hint; a dropped announcement must
/// never leave a healthy connected node permanently parked on an old tip.
const STEADY_TIP_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
/// At most two ancestry-lease refresh lanes are opened per interval. Failed
/// or non-confirming identities rotate least-recently-first.
const MINING_QUORUM_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);
/// A peer's tip confirmation is an expiring authorization, not a permanent
/// property of the connection.  If authenticated tip traffic stops, mining
/// must stop before the node can keep extending a stale parent indefinitely.
const MINING_PEER_CONFIRMATION_TTL: std::time::Duration = std::time::Duration::from_secs(45);
/// An immutable data plan is replaced only after its exact sources are truly
/// exhausted and several fresh provider queries produced no progress.
const EXACT_PLAN_NO_PROGRESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);
const EXACT_PLAN_DISCOVERY_ROUNDS: u8 = 6;

fn complete_snapshot_provider_discovery_round(rounds: u8, _dispatched: usize) -> u8 {
    rounds.saturating_add(1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MiningTipConfirmation {
    confirmed_at: Instant,
}

/// Compatibility wrapper around the network-v7 readiness model.
///
/// Stable authenticated chain-view health and frontier authorization are
/// separate. A normal validated child preserves mining permission; a branch
/// replacement, stronger unresolved view, expiry, or disconnect revokes it.
struct MiningPeerQuorum {
    isolated: bool,
    origin: Instant,
    initial_sync_complete: bool,
    unresolved_better_header: bool,
    readiness: noid_node::networking::mining_readiness::MiningReadiness,
    connected: std::collections::HashMap<libp2p::PeerId, noid_node::networking::FailureDomain>,
    frontier_confirmed: std::collections::HashMap<libp2p::PeerId, MiningTipConfirmation>,
    probe_attempts: std::collections::HashMap<libp2p::PeerId, Instant>,
    proof_ready: tokio::sync::watch::Sender<bool>,
    nonce_ready: tokio::sync::watch::Sender<bool>,
    count: tokio::sync::watch::Sender<usize>,
}

impl MiningPeerQuorum {
    fn new(
        isolated: bool,
        proof_ready: tokio::sync::watch::Sender<bool>,
        nonce_ready: tokio::sync::watch::Sender<bool>,
        count: tokio::sync::watch::Sender<usize>,
    ) -> Self {
        let origin = Instant::now();
        let initial = noid_node::networking::ChainPoint::new(0, [0u8; 32]);
        let quorum = Self {
            isolated,
            origin,
            initial_sync_complete: isolated,
            unresolved_better_header: false,
            readiness: noid_node::networking::mining_readiness::MiningReadiness::new(
                isolated,
                MINING_PEER_QUORUM,
                initial,
            ),
            connected: std::collections::HashMap::new(),
            frontier_confirmed: std::collections::HashMap::new(),
            probe_attempts: std::collections::HashMap::new(),
            proof_ready,
            nonce_ready,
            count,
        };
        quorum.publish_at(origin);
        quorum
    }

    fn now_ms(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.origin).as_millis() as u64
    }

    fn expiry_ms(&self, now: Instant) -> u64 {
        self.now_ms(now)
            .saturating_add(MINING_PEER_CONFIRMATION_TTL.as_millis() as u64)
    }

    fn connect(
        &mut self,
        peer: libp2p::PeerId,
        failure_domain: noid_node::networking::FailureDomain,
    ) {
        self.connected.insert(peer, failure_domain);
    }

    fn set_sync_state(&mut self, complete: bool, unresolved_better_header: bool) {
        if self.initial_sync_complete == complete
            && self.unresolved_better_header == unresolved_better_header
        {
            return;
        }
        self.initial_sync_complete = complete;
        self.unresolved_better_header = unresolved_better_header;
        self.readiness
            .set_sync_state(complete, unresolved_better_header);
        self.publish();
    }

    fn set_canonical_tip(&mut self, height: u64, hash: [u8; 32], extends_previous: bool) {
        self.set_canonical_tip_state(height, hash, extends_previous, false);
    }

    fn set_canonical_tip_unresolved(
        &mut self,
        height: u64,
        hash: [u8; 32],
        extends_previous: bool,
    ) {
        self.set_canonical_tip_state(height, hash, extends_previous, true);
    }

    fn set_canonical_tip_state(
        &mut self,
        height: u64,
        hash: [u8; 32],
        extends_previous: bool,
        unresolved_better_header: bool,
    ) {
        let tip = noid_node::networking::ChainPoint::new(height, hash);
        if self.readiness.committed_tip() != tip {
            self.readiness.set_committed_tip(tip, extends_previous);
            self.frontier_confirmed.clear();
        }
        self.unresolved_better_header = unresolved_better_header;
        self.readiness
            .set_sync_state(self.initial_sync_complete, unresolved_better_header);
        self.publish();
    }

    fn resolve_committed_view(&mut self) {
        self.readiness.resolve_committed_view();
        self.publish();
    }

    fn reconcile_canonical_tip(&mut self, height: u64, hash: [u8; 32], prev_hash: [u8; 32]) {
        let previous = self.readiness.committed_tip();
        let current = noid_node::networking::ChainPoint::new(height, hash);
        if previous == current {
            return;
        }
        self.set_canonical_tip(
            height,
            hash,
            height == previous.height.saturating_add(1) && prev_hash == previous.hash,
        );
    }

    /// A natively validated compatible view refreshes stable network health.
    /// A stronger header by itself does not pause mining; the separate sync
    /// state closes that gate only after exact data transport is admitted.
    fn observe_compatible(&mut self, peer: libp2p::PeerId) {
        let now = Instant::now();
        let Some(failure_domain) = self.connected.get(&peer).copied() else {
            return;
        };
        self.readiness
            .renew_health(peer, failure_domain, self.expiry_ms(now), true, false);
        self.publish_at(now);
    }

    fn reject_incompatible(&mut self, peer: libp2p::PeerId) {
        let now = Instant::now();
        let Some(failure_domain) = self.connected.get(&peer).copied() else {
            return;
        };
        self.readiness
            .renew_health(peer, failure_domain, self.expiry_ms(now), false, true);
        self.frontier_confirmed.remove(&peer);
        self.publish_at(now);
    }

    fn confirm_tip(&mut self, peer: libp2p::PeerId, height: u64, hash: [u8; 32]) {
        self.confirm_tip_at(peer, height, hash, Instant::now());
    }

    fn confirm_tip_at(
        &mut self,
        peer: libp2p::PeerId,
        height: u64,
        hash: [u8; 32],
        confirmed_at: Instant,
    ) {
        let point = noid_node::networking::ChainPoint::new(height, hash);
        let Some(failure_domain) = self.connected.get(&peer).copied() else {
            return;
        };
        if self.readiness.committed_tip() != point {
            return;
        }
        let now_ms = self.now_ms(confirmed_at);
        let expires_at_ms = self.expiry_ms(confirmed_at);
        self.readiness
            .renew_health(peer, failure_domain, expires_at_ms, true, false);
        if self
            .readiness
            .authorize_frontier(peer, point, expires_at_ms, now_ms)
        {
            self.frontier_confirmed
                .insert(peer, MiningTipConfirmation { confirmed_at });
        }
        self.publish_at(confirmed_at);
    }

    fn expire_stale(&mut self, now: Instant) {
        let now_ms = self.now_ms(now);
        self.readiness.expire(now_ms);
        let connected = &self.connected;
        self.frontier_confirmed.retain(|peer, confirmation| {
            connected.contains_key(peer)
                && now.saturating_duration_since(confirmation.confirmed_at)
                    < MINING_PEER_CONFIRMATION_TTL
        });
        self.publish_at(now);
    }

    fn disconnect(&mut self, peer: libp2p::PeerId) {
        self.connected.remove(&peer);
        self.probe_attempts.remove(&peer);
        self.frontier_confirmed.remove(&peer);
        self.readiness.disconnect(peer);
        self.publish();
    }

    fn waiting_for_quorum(&self) -> bool {
        !self.isolated
            && !self
                .readiness
                .snapshot(self.now_ms(Instant::now()))
                .nonce_search_ready
    }

    fn probe_candidates(&self, limit: usize) -> Vec<libp2p::PeerId> {
        let mut confirmed = self
            .frontier_confirmed
            .iter()
            .filter(|(peer, _)| self.connected.contains_key(peer))
            .map(|(peer, confirmation)| (*peer, confirmation.confirmed_at))
            .collect::<Vec<_>>();
        confirmed.sort_by(|(left_peer, left_at), (right_peer, right_at)| {
            left_at
                .cmp(right_at)
                .then_with(|| left_peer.to_bytes().cmp(&right_peer.to_bytes()))
        });
        let mut unconfirmed = self
            .connected
            .keys()
            .filter(|peer| !self.frontier_confirmed.contains_key(peer))
            .map(|peer| (*peer, self.probe_attempts.get(peer).copied()))
            .collect::<Vec<_>>();
        unconfirmed.sort_by(|(left_peer, left_at), (right_peer, right_at)| {
            left_at
                .cmp(right_at)
                .then_with(|| left_peer.to_bytes().cmp(&right_peer.to_bytes()))
        });
        unconfirmed
            .into_iter()
            .map(|(peer, _)| peer)
            .chain(confirmed.into_iter().map(|(peer, _)| peer))
            .take(limit)
            .collect()
    }

    fn mark_probe_sent(&mut self, peer: libp2p::PeerId, now: Instant) {
        if self.connected.contains_key(&peer) {
            self.probe_attempts.insert(peer, now);
        }
    }

    fn publish(&self) {
        self.publish_at(Instant::now());
    }

    fn publish_at(&self, now: Instant) {
        let snapshot = self.readiness.snapshot(self.now_ms(now));
        if *self.count.borrow() != snapshot.healthy_failure_domains {
            self.count.send_replace(snapshot.healthy_failure_domains);
        }
        if *self.proof_ready.borrow() != snapshot.proof_build_ready {
            self.proof_ready.send_replace(snapshot.proof_build_ready);
        }
        if *self.nonce_ready.borrow() != snapshot.nonce_search_ready {
            self.nonce_ready.send_replace(snapshot.nonce_search_ready);
            tracing::info!(
                authenticated_peers = snapshot.authenticated_leases,
                failure_domains = snapshot.healthy_failure_domains,
                frontier_authorizations = snapshot.frontier_authorizations,
                required_domains = MINING_PEER_QUORUM,
                isolated = self.isolated,
                proof_ready = snapshot.proof_build_ready,
                nonce_ready = snapshot.nonce_search_ready,
                "mining network readiness changed"
            );
        }
    }
}
/// A state-manifest round with no usable candidate is re-requested after this
/// deadline. A dropped stream must not wedge sync: with few peers there may
/// never be another PeerConnected event to retrigger the probe. This fallback
/// runs only after the request-response layer's 30-second deadline and the
/// P2P event loop's complete-local 35-second deadline. The extra margin lets
/// that layer flush a request which never opened a substream before the node
/// starts another manifest generation.
const STATE_MANIFEST_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(38);
/// Do not let connection order choose an immutable snapshot generation. Keep
/// only the strongest bounded candidate during one short discovery window;
/// its advertised work remains a scheduling hint until native headers, PoW,
/// the recursive terminal, and State are independently verified.
const STATE_MANIFEST_CANDIDATE_SETTLE: std::time::Duration = std::time::Duration::from_secs(5);
/// A terminal normally arrives in about two seconds on the live seed network.
/// libp2p starts its transport timeout only after an outbound substream opens,
/// so a request queued behind stream capacity otherwise has no node-visible
/// deadline. Hedge the same exact terminal to one advertised alternate before
/// that internal queue can stall cold sync.
const HISTORY_STEP_TERMINAL_HEDGE_AFTER: std::time::Duration = std::time::Duration::from_secs(3);
/// Bound the whole logical race, including time before libp2p opens either
/// outbound substream. This is deliberately longer than the transport's
/// 60-second request timeout, plus the hedge offset and timer sweep, so both
/// honest candidates keep their complete transport budget.
const HISTORY_STEP_TERMINAL_HARD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(70);
const MINER_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

fn manifest_round_retry_due(started_at: Option<Instant>, now: Instant) -> bool {
    started_at.is_some_and(|started| now.duration_since(started) >= STATE_MANIFEST_RESPONSE_TIMEOUT)
}

fn manifest_candidate_selection_due(started_at: Option<Instant>, now: Instant) -> bool {
    started_at.is_some_and(|started| now.duration_since(started) >= STATE_MANIFEST_CANDIDATE_SETTLE)
}

fn state_manifest_candidate_is_preferred(
    candidate: &noid_p2p::protocol::GetStateManifestResponse,
    current: &noid_p2p::protocol::GetStateManifestResponse,
) -> bool {
    matches!(
        noid_chain::consensus::fork_choice::choose_chain_by_work(
            &candidate.bridge_cumulative_chainwork,
            &candidate.bridge_tip_hash,
            &current.bridge_cumulative_chainwork,
            &current.bridge_tip_hash,
        ),
        noid_chain::consensus::fork_choice::ChainChoice::A
    )
}

fn steady_tip_probe_due(
    last_probe: Instant,
    now: Instant,
    waiting_for_quorum: bool,
    canonical_sync_idle: bool,
) -> bool {
    !waiting_for_quorum
        && canonical_sync_idle
        && now.duration_since(last_probe) >= STEADY_TIP_PROBE_INTERVAL
}

fn mining_quorum_probe_due(
    last_probe: Instant,
    now: Instant,
    waiting_for_quorum: bool,
    canonical_sync_idle: bool,
) -> bool {
    waiting_for_quorum
        && canonical_sync_idle
        && now.duration_since(last_probe) >= MINING_QUORUM_PROBE_INTERVAL
}

const MAX_MEMPOOL_SYNC_PEERS: usize = 4;

fn peer_connect_bootstrap_policy(
    locally_selected: bool,
    initial_sync_ready: bool,
    requested_mempool_peers: usize,
) -> (bool, bool) {
    // Public listeners may authenticate hundreds of inbound wallets at once.
    // Those peers remain useful exact-object providers, but letting each
    // connection trigger reciprocal manifest/header/mempool pulls recreates
    // the launch herd at every seed. The maintained outbound neighbour set is
    // bounded by topology policy and therefore owns proactive discovery.
    let discover_chain = locally_selected;
    let request_mempool =
        locally_selected && initial_sync_ready && requested_mempool_peers < MAX_MEMPOOL_SYNC_PEERS;
    (discover_chain, request_mempool)
}

fn manifest_round_gap_is_resolved(local_height: u64, highest_announced: u64) -> bool {
    local_height >= highest_announced
}

fn stale_gap_recovery_is_due(
    stale_secs: u64,
    local_height: u64,
    highest_announced: u64,
    canonical_transition_active: bool,
) -> bool {
    stale_secs >= 30 && highest_announced > local_height && !canonical_transition_active
}

fn terminal_transport_can_retry_same_peer(kind: noid_p2p::RequestFailureKind) -> bool {
    matches!(
        kind,
        noid_p2p::RequestFailureKind::Timeout | noid_p2p::RequestFailureKind::Io
    )
}

fn rotating_manifest_peers(
    peers: &std::collections::HashSet<libp2p::PeerId>,
    excluded_peers: &std::collections::HashSet<libp2p::PeerId>,
    failed_peer: Option<libp2p::PeerId>,
    allow_failed_peer: bool,
    cursor: &mut usize,
    limit: usize,
) -> Vec<libp2p::PeerId> {
    let mut candidates = peers
        .iter()
        .copied()
        .filter(|peer| Some(*peer) != failed_peer)
        .filter(|peer| !excluded_peers.contains(peer))
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|peer| peer.to_bytes());
    if candidates.is_empty() {
        return failed_peer
            .filter(|peer| {
                allow_failed_peer && peers.contains(peer) && !excluded_peers.contains(peer)
            })
            .into_iter()
            .collect();
    }

    let start = *cursor % candidates.len();
    let selected = (0..limit.min(candidates.len()))
        .map(|offset| candidates[(start + offset) % candidates.len()])
        .collect::<Vec<_>>();
    *cursor = (start + selected.len()) % candidates.len();
    selected
}

fn history_step_cache_directory(data_dir: &Path, metadata_digest: [u8; 32]) -> PathBuf {
    let mut digest_hex = String::with_capacity(64);
    for byte in metadata_digest {
        use std::fmt::Write as _;
        write!(&mut digest_hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    data_dir.join("history-step-cache").join(digest_hex)
}

fn embedded_history_step_cache_file(
    data_dir: &Path,
    class: HistoryStepCacheClass,
) -> Option<PathBuf> {
    let pack = embedded_history_step_pack::embedded_history_step_pack()?;
    Some(
        history_step_cache_directory(data_dir, pack.runtime_metadata_digest()).join(
            noid_miner::history_step_runtime_image_file_name(class.class_id()),
        ),
    )
}

fn embedded_history_step_cache_ready(data_dir: &Path, class: HistoryStepCacheClass) -> bool {
    embedded_history_step_cache_file(data_dir, class)
        .and_then(|path| std::fs::metadata(path).ok())
        .is_some_and(|metadata| metadata.is_file() && metadata.len() > 0)
}

fn embedded_history_step_runtime(
    data_dir: &Path,
) -> Result<Option<Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>>, String> {
    let Some(pack) = embedded_history_step_pack::embedded_history_step_pack() else {
        return Ok(None);
    };
    let metadata = noid_miner::decode_history_step_runtime_metadata_pinned(
        pack.runtime_metadata(),
        pack.runtime_metadata_digest(),
    )
    .map_err(|error| format!("embedded HistoryStep metadata rejected: {error}"))?;
    // The packed runtime layout is derived from the embedded canonical
    // leaves once per release build (keyed by the pinned metadata digest)
    // and reused on later starts.
    let cache_directory = history_step_cache_directory(data_dir, pack.runtime_metadata_digest());
    let matrix_source = pack
        .matrix_source(Some(cache_directory))
        .map_err(|error| format!("embedded HistoryStep matrices rejected: {error}"))?;
    let (bank, runtime_parts) = metadata.into_parts();
    let runtime = noid_recursive::acceptance::history_step::HistoryStepRuntime::new(
        bank,
        Box::new(matrix_source),
        runtime_parts,
    )
    .map_err(|error| format!("embedded HistoryStep runtime rejected: {error}"))?;
    tracing::debug!(
        embedded_matrix_mib = pack.embedded_bytes_total() / (1024 * 1024),
        "preflight-authenticated HistoryStep runtime images loaded from the executable"
    );
    Ok(Some(Arc::new(runtime)))
}

fn prepare_history_step_ghost_authorization() -> Result<
    Arc<noid_recursive::acceptance::history_step::PreparedHistoryStepGhostAuthorization>,
    String,
> {
    noid_miner::install_history_step_phase_cpu(|| {
        let proof = noid_gkr::ghost_tx::prove_selected_ghost_authorization()
            .map_err(|error| format!("canonical ghost authorization proof failed: {error}"))?;
        noid_recursive::acceptance::history_step::prepare_history_step_ghost_authorization(proof)
            .map(Arc::new)
            .map_err(|error| format!("canonical ghost authorization rejected: {error}"))
    })
    .map_err(|error| format!("HistoryStep ghost CPU phase failed: {error}"))?
}

mod config;
mod embedded_history_step_pack;
mod sync_phase_telemetry;
mod wallet;
use config::NodeConfig;
use sync_phase_telemetry::{SnapshotSyncTelemetry, SyncPhase, SyncPhaseMeasurement};
use wallet::{SharedWallet, WalletHandle, WalletState};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Operating mode for the full node.
///
/// Exactly one mode must be active. The default is `node`.
#[derive(Debug, Clone, PartialEq, Eq, clap::ValueEnum, Default)]
pub enum NodeMode {
    /// Ordinary node and wallet (default). No mining or template serving.
    /// Verifies all complete blocks and serves recent block/header sync.
    /// Snapshot sync uses the same manifest/HistoryStep pipeline that the O(1)
    /// verifier will authorize.
    #[default]
    Node,
    /// Mining node with built-in parallel PoW followed by the required
    /// HistoryStep and atomic complete-block commit.
    Miner,
    /// Mining node with an external PoW worker. The node owns the immutable
    /// template; the worker returns only a nonce, after which the node proves
    /// and commits the complete block. Requires a mining credential.
    Extminer,
}

const MAX_RPC_KEY_FILE_BYTES: u64 = 4096;

fn validate_rpc_key(key: String, role: &str) -> anyhow::Result<String> {
    if key.len() < 16 {
        anyhow::bail!("{role} key must contain at least 16 characters");
    }
    if key.chars().any(char::is_whitespace) {
        anyhow::bail!("{role} key must not contain whitespace");
    }
    if key.len() as u64 > MAX_RPC_KEY_FILE_BYTES {
        anyhow::bail!("{role} key is too large");
    }
    Ok(key)
}

fn read_rpc_key_file(path: &Path, role: &str) -> anyhow::Result<String> {
    let expanded = expand_tilde(path);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(&expanded)
        .with_context(|| format!("open {role} key file: {}", expanded.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {role} key file: {}", expanded.display()))?;
    if !metadata.is_file() {
        anyhow::bail!(
            "{role} key path is not a regular file: {}",
            expanded.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "{role} key file must not be accessible by group or others: {} has mode {mode:03o}",
                expanded.display()
            );
        }
        let actual = metadata.uid();
        // SAFETY: geteuid has no preconditions and only reads process state.
        let expected = unsafe { libc::geteuid() };
        if actual != expected {
            anyhow::bail!(
                "{role} key file must be owned by the current user: {} is uid {actual}, expected {expected}",
                expanded.display()
            );
        }
    }

    let mut raw = String::new();
    file.take(MAX_RPC_KEY_FILE_BYTES + 1)
        .read_to_string(&mut raw)
        .with_context(|| format!("read {role} key file: {}", expanded.display()))?;
    if raw.len() as u64 > MAX_RPC_KEY_FILE_BYTES {
        anyhow::bail!("{role} key file is too large: {}", expanded.display());
    }
    let key = raw.trim_end_matches(['\r', '\n']).to_owned();
    validate_rpc_key(key, role)
}

fn distinct_rpc_keys(mining_key: Option<&str>, operator_key: Option<&str>) -> anyhow::Result<()> {
    if mining_key.is_some() && mining_key == operator_key {
        anyhow::bail!("mining key and operator key must be different");
    }
    Ok(())
}

fn validate_rpc_listener_auth(
    listen: std::net::SocketAddr,
    mining_key: Option<&str>,
    operator_key: Option<&str>,
) -> anyhow::Result<()> {
    if !listen.ip().is_loopback() && mining_key.is_none() && operator_key.is_none() {
        anyhow::bail!(
            "non-loopback RPC listener {listen} requires --mining-key[-file] or --operator-key[-file]"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum HistoryStepCacheClass {
    B25,
    B255,
}

impl HistoryStepCacheClass {
    fn class_id(self) -> noid_recursive::CanonicalHistoryStepClassId {
        noid_recursive::CanonicalHistoryStepClassId::new(match self {
            Self::B25 => 0,
            Self::B255 => 1,
        })
        .expect("GUI cache class is canonical")
    }

    fn label(self) -> &'static str {
        match self {
            Self::B25 => "B25/m22",
            Self::B255 => "B255/m24",
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "parano1d",
    about = "ParanO(1)d full node daemon — proof-native HistoryStep UTXO network",
    version = env!("CARGO_PKG_VERSION"),
    long_about = "Run a ParanO(1)d node and wallet.\n\nExample:\n  parano1d --miner --data-dir ~/.parano1d/data\n  parano1d --p2p-listen 0.0.0.0:9600 --seed 1.2.3.4:9600",
)]
struct Cli {
    /// Path to TOML config file. A missing file is created with safe defaults.
    /// Default: ~/.parano1d/parano1d.toml
    #[arg(short = 'c', long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Node operating mode.
    ///
    /// node     — ordinary node and wallet, no mining (default)
    /// miner    — mining node with built-in PoW and automatic proof pipeline
    /// extminer — mining node with external PoW nonce search; requires a mining key
    #[arg(long, value_enum, default_value_t = NodeMode::Node)]
    mode: NodeMode,

    /// Shorthand for `--mode miner`.
    #[arg(long, conflicts_with = "extminer")]
    miner: bool,

    /// Shorthand for `--mode extminer`.
    #[arg(long, conflicts_with = "miner")]
    extminer: bool,

    /// Permit isolated block production without a peer quorum.
    /// Used for the first network node and explicit local-chain testing.
    #[arg(long, hide = true)]
    genesis: bool,

    /// Miner payout address (canonical bech32m, beginning with `o1`).
    /// Defaults to the wallet's active address.
    #[arg(long, value_name = "ADDRESS")]
    miner_address: Option<String>,

    /// Logical CPU threads used by the built-in miner and its proof phases.
    /// Defaults to the protocol-safe CPU ceiling (one or two logical CPUs are
    /// reserved for networking, RPC and storage).
    #[arg(long, value_name = "N")]
    cpu_threads: Option<usize>,

    /// Data directory for the MDBX database and wallet key.
    /// Default: ~/.parano1d/data
    #[arg(long, value_name = "PATH")]
    data_dir: Option<PathBuf>,

    /// P2P listen address in HOST:PORT format. Default: 0.0.0.0:9600
    #[arg(long, value_name = "HOST:PORT")]
    p2p_listen: Option<String>,

    /// JSON-RPC listen address in HOST:PORT format. Default: 127.0.0.1:9601.
    /// A non-loopback address requires a mining or operator credential.
    #[arg(long, value_name = "HOST:PORT")]
    rpc_listen: Option<String>,

    /// Seed peer address (HOST:PORT). Repeat for multiple seeds.
    /// Example: --seed 1.2.3.4:9600 --seed 5.6.7.8:9600
    #[arg(long, value_name = "HOST:PORT", action = clap::ArgAction::Append)]
    seed: Vec<String>,

    /// Do not dial the embedded DNS bootstrap set.
    /// Used by isolated multi-node protocol tests with explicit loopback seeds.
    #[arg(long, hide = true)]
    disable_dns_seeds: bool,

    /// Log level filter. Examples: debug, info, warn, error.
    #[arg(long, default_value = "info", value_name = "LEVEL")]
    log: String,

    /// Bearer token required for external mining API access.
    /// The credential is restricted to getBlockTemplate and submitBlock.
    #[arg(long, value_name = "TOKEN", conflicts_with = "mining_key_file")]
    mining_key: Option<String>,

    /// Owner-only file containing the Bearer token for the external mining API.
    ///
    /// The file must contain one token of at least 16 characters. On Unix it
    /// must be owned by the current user and inaccessible to group and others.
    /// The credential authorizes only getBlockTemplate and submitBlock.
    ///
    /// Pool example:
    ///   parano1d --mode extminer --mining-key-file ~/.parano1d/mining.key
    #[arg(long, value_name = "FILE")]
    mining_key_file: Option<PathBuf>,

    /// Bearer token for remote pool accounting and payout operations.
    /// The credential is restricted to the documented operator RPC allowlist.
    #[arg(long, value_name = "TOKEN", conflicts_with = "operator_key_file")]
    operator_key: Option<String>,

    /// Owner-only file containing the remote pool operator Bearer token.
    ///
    /// The file must contain one token of at least 16 characters. On Unix it
    /// must be owned by the current user and inaccessible to group and others.
    /// This credential can spend from the active wallet; use it only across an
    /// authenticated private network or encrypted tunnel.
    #[arg(long, value_name = "FILE")]
    operator_key_file: Option<PathBuf>,

    /// Allow external miners to specify their own coinbase address in getBlockTemplate.
    ///
    /// Requires either --mining-key or --mining-key-file. Without a credential
    /// this flag is rejected at startup.
    ///
    /// Use case: infrastructure pool where the node prepares and proves complete blocks and
    /// relays them over P2P, while each miner receives rewards directly to its own address.
    /// The node operator earns via an off-chain service fee, not via coinbase.
    ///
    /// Example:
    ///   parano1d --mode extminer --mining-key-file ~/.parano1d/mining.key \
    ///     --allow-custom-coinbase
    ///   # Miner: getBlockTemplate("o1their_own_address")
    #[arg(long)]
    allow_custom_coinbase: bool,

    /// Clear the complete chain database on startup and synchronize it again.
    /// Wallet files, receipts and the P2P identity are stored separately and remain.
    /// Use after an incompatible chain-data upgrade or suspected corruption.
    #[arg(long)]
    purge_state: bool,

    /// Check production CPU support and exit without touching node data.
    #[arg(long, exclusive = true)]
    check_hardware: bool,

    /// Print the generated master secret as 64 hexadecimal characters, then exit.
    #[arg(long, hide = true, conflicts_with = "import_wallet_secret")]
    export_wallet_secret: bool,

    /// Read a 64-character master secret from stdin, replace the wallet, then exit.
    #[arg(long, hide = true, conflicts_with = "export_wallet_secret")]
    import_wallet_secret: bool,

    /// Materialize one HistoryStep packed cache image, then exit.
    #[arg(long, value_enum, value_name = "CLASS", hide = true)]
    prepare_history_step_cache: Option<HistoryStepCacheClass>,
}

/// Resolve a seed string to a libp2p Multiaddr.
///
/// Handles four formats:
///
/// 1. `HOST:PORT`            — IP or hostname + port  → `/ip4/H/tcp/P` or `/dns/H/tcp/P`
/// 2. `hostname`             — bare DNS name           → `/dns/hostname/tcp/{default_port}`
/// 3. `/ip4/.../tcp/...`     — libp2p multiaddr, passed through unchanged
/// 4. `dnsaddr:hostname`     — _dnsaddr TXT lookup     → `/dnsaddr/hostname`
///
/// Format 4 is the production DNS seed mechanism.  libp2p resolves
/// `_dnsaddr.<hostname>` TXT records at dial time, each encoding a full
/// multiaddr with PeerID.  This gives cryptographic peer verification and
/// easy multi-node seed rotation via DNS.
///
/// DNS setup for format 4:
///   _dnsaddr.example.org  TXT  "dnsaddr=/ip4/1.2.3.4/tcp/9600/p2p/12D3KooW..."
///   _dnsaddr.example.org  TXT  "dnsaddr=/ip4/5.6.7.8/tcp/9600/p2p/12D3KooW..."
fn seed_to_multiaddr(s: &str, default_port: u16) -> anyhow::Result<libp2p::Multiaddr> {
    let seed = s.trim();

    // Format 3: an explicit multiaddr is already complete. In particular,
    // retain a trailing /p2p/<PeerId>: it cryptographically binds the dial to
    // the identity selected by the operator.
    if seed.starts_with('/') {
        return seed
            .parse()
            .with_context(|| format!("parse multiaddr: {seed}"));
    }

    // Format 4: "dnsaddr:<hostname>" → /dnsaddr/<hostname>
    // Resolves _dnsaddr.<hostname> TXT records (libp2p standard).
    if let Some(host) = seed.strip_prefix("dnsaddr:") {
        let ma_str = format!("/dnsaddr/{}", host.trim());
        return ma_str
            .parse()
            .with_context(|| format!("build dnsaddr multiaddr for {host:?}"));
    }

    // Format 1: HOST:PORT
    if seed.contains(':') {
        return seed_host_port_to_multiaddr(seed);
    }

    // Format 2: bare hostname — use default network port. `/dns/` lets
    // libp2p try both A and AAAA answers (up to its bounded dial limit).
    let ma_str = format!("/dns/{seed}/tcp/{default_port}");
    ma_str
        .parse()
        .with_context(|| format!("build DNS multiaddr for {seed:?}"))
}

const SYSTEM_SEED_DNS_TIMEOUT: Duration = Duration::from_secs(5);
// Match libp2p-dns' bounded address-attempt set. These are registered as
// fallback candidates; the topology scheduler still permits only four pending
// bootstrap dials and retains only two seed connections during initial sync.
const MAX_SYSTEM_ADDRS_PER_SEED: usize = 16;

fn resolved_system_seed_addrs(
    socket_addrs: impl IntoIterator<Item = std::net::SocketAddr>,
    port: u16,
) -> Vec<libp2p::Multiaddr> {
    use libp2p::multiaddr::Protocol;

    let mut result = Vec::new();
    for socket in socket_addrs {
        let ip_protocol = match socket.ip() {
            std::net::IpAddr::V4(ip) => Protocol::Ip4(ip),
            std::net::IpAddr::V6(ip) => Protocol::Ip6(ip),
        };
        let mut addr = libp2p::Multiaddr::empty();
        addr.push(ip_protocol);
        addr.push(Protocol::Tcp(port));
        if !result.contains(&addr) {
            result.push(addr);
            if result.len() == MAX_SYSTEM_ADDRS_PER_SEED {
                break;
            }
        }
    }
    result
}

async fn resolve_embedded_seed_with_system_dns(
    seed: &str,
    port: u16,
) -> Result<Vec<libp2p::Multiaddr>, String> {
    let query = tokio::net::lookup_host((seed.to_owned(), port));
    let socket_addrs = tokio::time::timeout(SYSTEM_SEED_DNS_TIMEOUT, query)
        .await
        .map_err(|_| format!("system DNS lookup for {seed} timed out"))?
        .map_err(|error| format!("system DNS lookup for {seed} failed: {error}"))?;
    let resolved = resolved_system_seed_addrs(socket_addrs, port);
    if resolved.is_empty() {
        return Err(format!(
            "system DNS lookup for {seed} returned no addresses"
        ));
    }
    Ok(resolved)
}

async fn embedded_seed_multiaddrs(
    seed: &str,
    default_port: u16,
) -> anyhow::Result<Vec<libp2p::Multiaddr>> {
    let original = seed_to_multiaddr(seed, default_port)?;
    match resolve_embedded_seed_with_system_dns(seed, default_port).await {
        Ok(mut addresses) => {
            tracing::debug!(
                seed,
                addresses = addresses.len(),
                "resolved embedded seed through system DNS"
            );
            // Native resolution is the first path because it follows scoped
            // VPN and platform resolver configuration. Keep the hostname as
            // one last fallback as well: libp2p can then re-resolve a seed
            // whose A/AAAA records change during a long-running daemon.
            if !addresses.contains(&original) {
                addresses.push(original);
            }
            Ok(addresses)
        }
        Err(error) => {
            tracing::warn!(
                seed,
                %error,
                "system DNS could not resolve embedded seed; retaining libp2p DNS fallback"
            );
            Ok(vec![original])
        }
    }
}

fn split_host_port(addr: &str) -> anyhow::Result<(&str, &str)> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .with_context(|| format!("invalid bracketed IPv6 address {addr:?}"))?;
        return Ok((host, port));
    }
    addr.rsplit_once(':').with_context(|| {
        format!(
            "invalid address {:?}: expected HOST:PORT (e.g. 127.0.0.1:9600)",
            addr
        )
    })
}

fn seed_host_port_to_multiaddr(addr: &str) -> anyhow::Result<libp2p::Multiaddr> {
    let (host, port_str) = split_host_port(addr)?;
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("invalid port in {addr:?}"))?;
    let protocol = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => format!("/ip4/{ip}"),
        Ok(std::net::IpAddr::V6(ip)) => format!("/ip6/{ip}"),
        Err(_) => format!("/dns/{host}"),
    };
    format!("{protocol}/tcp/{port}")
        .parse()
        .with_context(|| format!("build seed multiaddr from {addr:?}"))
}

/// Convert a user-friendly "HOST:PORT" string into a libp2p Multiaddr.
///
/// Users type:  `127.0.0.1:9600`  or  `0.0.0.0:9600`
/// libp2p needs: `/ip4/127.0.0.1/tcp/9600`
///
/// This conversion is purely internal — users never see multiaddrs.
fn ip_port_to_multiaddr(addr: &str) -> anyhow::Result<libp2p::Multiaddr> {
    let (host, port_str) = split_host_port(addr)?;
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("invalid port in {:?}", addr))?;

    let ma_str = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => format!("/ip4/{ip}/tcp/{port}"),
        Ok(std::net::IpAddr::V6(ip)) => format!("/ip6/{ip}/tcp/{port}"),
        Err(error) => {
            anyhow::bail!("invalid IP address {host:?} in {addr:?}: {error}");
        }
    };
    ma_str
        .parse()
        .with_context(|| format!("build multiaddr from {:?}", addr))
}

/// Parse a P2P listen address from either the friendly `HOST:PORT` form used
/// by the CLI or the libp2p multiaddr form accepted by existing config files.
fn p2p_listen_to_multiaddr(addr: &str) -> anyhow::Result<libp2p::Multiaddr> {
    let addr = addr.trim();
    if addr.starts_with('/') {
        return addr
            .parse()
            .with_context(|| format!("parse P2P listen multiaddr {addr:?}"));
    }
    ip_port_to_multiaddr(addr)
}

// Bind the selected storage directory to this schema and genesis without ever
// deleting user data implicitly. A missing marker is repaired when the MDBX
// database is empty or already contains this mainnet genesis. An incompatible
// database fails closed unless the operator explicitly requests --purge-state;
// that operation clears chain tables only and preserves wallet.key.
const NETWORK_STORAGE_EPOCH_MARKER_FILE: &str = ".network-storage-epoch";
const NETWORK_STORAGE_SCHEMA: &[u8] = b"parano1d/mainnet/network-storage/v1/";

fn network_storage_epoch_bytes() -> Vec<u8> {
    let genesis = noid_chain::consensus::genesis_header();
    let genesis_id = noid_chain::block_header::block_id(&genesis);
    let mut bytes = Vec::with_capacity(NETWORK_STORAGE_SCHEMA.len() + 65);
    bytes.extend_from_slice(NETWORK_STORAGE_SCHEMA);
    bytes.extend_from_slice(hex::encode(genesis_id).as_bytes());
    bytes.push(b'\n');
    bytes
}

fn network_storage_epoch_is_current(data_dir: &Path) -> anyhow::Result<bool> {
    let marker = data_dir.join(NETWORK_STORAGE_EPOCH_MARKER_FILE);
    match std::fs::read(&marker) {
        Ok(bytes) => Ok(bytes == network_storage_epoch_bytes()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("read {}", marker.display())),
    }
}

fn persist_network_storage_epoch_marker(data_dir: &Path) -> anyhow::Result<()> {
    let marker = data_dir.join(NETWORK_STORAGE_EPOCH_MARKER_FILE);
    let temporary = data_dir.join(format!(
        "{NETWORK_STORAGE_EPOCH_MARKER_FILE}.tmp.{}",
        std::process::id()
    ));
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("remove stale marker {}", temporary.display()));
        }
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create network storage marker {}", temporary.display()))?;
    if let Err(error) = file
        .write_all(&network_storage_epoch_bytes())
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        return Err(error).context("write network storage marker");
    }
    drop(file);

    #[cfg(target_os = "windows")]
    if marker.exists() {
        std::fs::remove_file(&marker)
            .with_context(|| format!("replace network storage marker {}", marker.display()))?;
    }
    if let Err(error) = std::fs::rename(&temporary, &marker) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("install network storage marker {}", marker.display()));
    }
    #[cfg(unix)]
    std::fs::File::open(data_dir)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync data directory {}", data_dir.display()))?;
    Ok(())
}

/// Ensure the storage marker is bound to this mainnet genesis. Returns true
/// only when an explicit --purge-state was consumed while repairing it.
fn ensure_network_storage_epoch(data_dir: &Path, explicit_purge: bool) -> anyhow::Result<bool> {
    if network_storage_epoch_is_current(data_dir)? {
        return Ok(false);
    }

    let database_path = data_dir.join("mdbx.dat");
    if !database_path.exists() {
        persist_network_storage_epoch_marker(data_dir)?;
        tracing::info!(
            path = %data_dir.display(),
            "initialized mainnet storage identity without deleting existing files"
        );
        return Ok(false);
    }

    let store = MdbxStore::open(data_dir).context("inspect unmarked MDBX storage")?;
    let database_empty = store.is_empty().context("inspect unmarked MDBX contents")?;
    let mainnet_genesis = noid_chain::consensus::genesis_header();
    let genesis_matches = store
        .get_header(0)
        .context("read genesis from unmarked MDBX storage")?
        .is_some_and(|header| header == mainnet_genesis);
    drop(store);

    if database_empty || genesis_matches {
        persist_network_storage_epoch_marker(data_dir)?;
        tracing::info!(
            path = %data_dir.display(),
            database_empty,
            "repaired missing mainnet storage identity without deleting user data"
        );
        return Ok(false);
    }

    if !explicit_purge {
        anyhow::bail!(
            "data directory {} contains a database that is not bound to this mainnet genesis; \
             no files were modified. Select a fresh --data-dir, move the old directory aside, \
             or rerun with --purge-state to clear chain state while preserving wallet.key",
            data_dir.display()
        );
    }

    purge_chain_state(data_dir)?;
    persist_network_storage_epoch_marker(data_dir)?;
    tracing::warn!(
        path = %data_dir.display(),
        "explicitly purged incompatible chain state; wallet and local preferences were preserved"
    );
    Ok(true)
}

fn purge_chain_state(data_dir: &Path) -> anyhow::Result<()> {
    let store = MdbxStore::open(data_dir).context("open MDBX for chain-data reset")?;
    let previous_height = store
        .get_chain_tip()
        .context("read chain tip before chain-data reset")?
        .map(|(height, _)| height);
    tracing::info!(
        ?previous_height,
        "--purge-state: clearing the chain database"
    );
    store.clear_all().context("clear MDBX chain state")?;
    drop(store);
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    if cli.check_hardware {
        let report = noid_core::cpu::ProductionHardwareReport::detect();
        print!("{report}");
        if report.ready() {
            return Ok(());
        }
        let _ = std::io::Write::flush(&mut std::io::stdout());
        std::process::exit(1);
    }
    let production_hardware = noid_core::cpu::ensure_production_hardware()?;

    // Shorthand role flags override the default mode; clap already rejects
    // combining them with each other.
    if cli.miner {
        cli.mode = NodeMode::Miner;
    } else if cli.extminer {
        cli.mode = NodeMode::Extminer;
    }

    let inline_mining_key_configured = cli.mining_key.is_some();
    let inline_operator_key_configured = cli.operator_key.is_some();
    let mining_key = match (cli.mining_key.take(), cli.mining_key_file.as_deref()) {
        (Some(key), None) => Some(validate_rpc_key(key, "mining")?),
        (None, Some(path)) => Some(read_rpc_key_file(path, "mining")?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap rejects conflicting mining key sources"),
    };
    let operator_key = match (cli.operator_key.take(), cli.operator_key_file.as_deref()) {
        (Some(key), None) => Some(validate_rpc_key(key, "operator")?),
        (None, Some(path)) => Some(read_rpc_key_file(path, "operator")?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap rejects conflicting operator key sources"),
    };
    distinct_rpc_keys(mining_key.as_deref(), operator_key.as_deref())?;

    // --- Tracing ---
    // Log format: HH:MM:SS LEVEL target: message
    //
    // libp2p internal chatter is suppressed by default. Pass --log debug
    // or RUST_LOG=libp2p=debug to see everything.
    let mut log_filter = EnvFilter::new(&cli.log)
        // libp2p internals — suppress unless user asks for debug
        .add_directive("libp2p_swarm=warn".parse().unwrap_or_default())
        .add_directive("libp2p_tcp=warn".parse().unwrap_or_default())
        .add_directive("libp2p_noise=warn".parse().unwrap_or_default())
        .add_directive("libp2p_yamux=warn".parse().unwrap_or_default())
        // yamux logs a warning when a peer closes the socket before our
        // best-effort closing frame is flushed. The connection is already
        // closed at that point, so this is not an operator-actionable fault.
        .add_directive("yamux=error".parse().unwrap_or_default())
        .add_directive("libp2p_gossipsub=error".parse().unwrap_or_default())
        .add_directive("libp2p_request_response=warn".parse().unwrap_or_default())
        .add_directive("libp2p_identify=warn".parse().unwrap_or_default())
        .add_directive("libp2p_ping=warn".parse().unwrap_or_default())
        .add_directive("libp2p_mdns=warn".parse().unwrap_or_default())
        .add_directive("multiaddr=warn".parse().unwrap_or_default());
    if cli.genesis {
        // An isolated genesis node has no Kademlia peers yet. The library's
        // periodic bootstrap warning is expected and not actionable.
        log_filter = log_filter.add_directive("libp2p_kad=error".parse().unwrap_or_default());
    }

    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_timer(UtcHms) // HH:MM:SS instead of full ISO timestamp
        .with_target(false) // no module path clutter
        .with_thread_ids(false)
        .compact() // single-line events
        .init();

    // --- Mode validation ---
    if cli.mode == NodeMode::Extminer && mining_key.is_none() {
        anyhow::bail!("--mode extminer requires --mining-key or --mining-key-file");
    }
    if cli.mode == NodeMode::Miner && mining_key.is_some() {
        tracing::warn!("mining key is ignored in --mode miner (internal miner needs no token)");
    }
    if cli.cpu_threads.is_some() && cli.mode != NodeMode::Miner {
        anyhow::bail!("--cpu-threads requires --mode miner");
    }
    // allow_custom_coinbase only makes sense with extminer mode
    if cli.allow_custom_coinbase && cli.mode != NodeMode::Extminer {
        anyhow::bail!("--allow-custom-coinbase requires --mode extminer");
    }
    let wallet_maintenance = cli.export_wallet_secret || cli.import_wallet_secret;
    if wallet_maintenance && cli.prepare_history_step_cache.is_some() {
        anyhow::bail!("owner secret maintenance and matrix preparation are separate operations");
    }
    if wallet_maintenance
        && (cli.mode != NodeMode::Node
            || cli.genesis
            || cli.purge_state
            || cli.miner_address.is_some()
            || cli.cpu_threads.is_some()
            || inline_mining_key_configured
            || cli.mining_key_file.is_some()
            || inline_operator_key_configured
            || cli.operator_key_file.is_some()
            || cli.allow_custom_coinbase)
    {
        anyhow::bail!("owner secret maintenance cannot be combined with node or mining actions");
    }
    if cli.prepare_history_step_cache.is_some()
        && (cli.mode != NodeMode::Node
            || cli.genesis
            || cli.purge_state
            || cli.miner_address.is_some()
            || cli.cpu_threads.is_some()
            || inline_mining_key_configured
            || cli.mining_key_file.is_some()
            || inline_operator_key_configured
            || cli.operator_key_file.is_some()
            || cli.allow_custom_coinbase)
    {
        anyhow::bail!("matrix preparation cannot be combined with node or mining actions");
    }
    // --- Network ---
    let net = NetworkConfig::mainnet();
    tracing::debug!(network = %net.kind, "daemon starting");

    // --- Config file ---
    let config_path = cli
        .config
        .unwrap_or_else(|| expand_tilde(&PathBuf::from("~/.parano1d/parano1d.toml")));
    let mut config_defaults = NodeConfig::default();
    config_defaults.network.listen = Some(format!("0.0.0.0:{}", net.default_p2p_port));
    config_defaults.rpc.listen = Some(net.default_rpc_listen());
    let (mut cfg, config_created) = load_or_create_config(&config_path, &config_defaults)?;
    if config_created {
        tracing::info!(path = %config_path.display(), "created default node config");
    }
    if let Some(dir) = cli.data_dir.as_ref() {
        cfg.storage.path = dir.clone();
    }
    // Resolve and bind the selected storage directory before opening wallet or
    // P2P identity data. Incompatible chain data is never removed implicitly.
    let data_dir = if cfg.storage.path == Path::new("~/.parano1d/data") {
        expand_tilde(Path::new("~/.parano1d/data"))
    } else {
        expand_tilde(&cfg.storage.path)
    };
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("create data dir: {}", data_dir.display()))?;
    let epoch_purge_applied = ensure_network_storage_epoch(&data_dir, cli.purge_state)?;
    // CLI flags remain authoritative over persisted settings.
    cfg.mining.enabled = cli.mode == NodeMode::Miner;
    if let Some(addr) = cli.miner_address {
        cfg.mining.miner_address = addr;
    }
    // Validate both listeners before artifact prewarm, database opening, or
    // wallet creation. A typo in user configuration must fail immediately.
    let p2p_listen_str = cli.p2p_listen.unwrap_or_else(|| {
        cfg.network
            .listen
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| net.default_p2p_listen())
    });
    let listen_addr = p2p_listen_to_multiaddr(&p2p_listen_str).context("--p2p-listen")?;
    let public_p2p_addresses = cfg
        .network
        .public_addresses
        .iter()
        .map(|address| {
            p2p_listen_to_multiaddr(address)
                .with_context(|| format!("parse network.public_addresses entry {address:?}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let rpc_addr_str = cli.rpc_listen.unwrap_or_else(|| {
        cfg.rpc
            .listen
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| net.default_rpc_listen())
    });
    let rpc_listen: std::net::SocketAddr = rpc_addr_str.parse().context("parse RPC listen")?;
    validate_rpc_listener_auth(rpc_listen, mining_key.as_deref(), operator_key.as_deref())?;

    // Establish the process-wide bounded phase pool before the embedded
    // registry/matrix prewarm or any verifier can enter Rayon. Internal PoW,
    // HistoryStep and inbound verification reuse this same fixed worker set;
    // `BlockMiner::new` sees the identical idempotent plan.
    let cpu_budget_mode = if cli.mode != NodeMode::Node {
        noid_miner::ProcessCpuBudgetMode::InternalMiner
    } else {
        noid_miner::ProcessCpuBudgetMode::ProofOnly
    };
    let cpu_plan = noid_miner::configure_process_cpu_budget_with_threads(
        cpu_budget_mode,
        if cli.mode == NodeMode::Miner {
            cli.cpu_threads
        } else {
            None
        },
    )
    .context("configure process CPU budget")?;
    tracing::info!(
        backend = %production_hardware.backend,
        threads = cpu_plan.shared_pool_threads,
        "CPU proof and mining backend selected"
    );
    // GUI Settings and the CLI share the complete seed syntax accepted by
    // seed_to_multiaddr (hostname, IP, dnsaddr, or explicit multiaddr).
    for raw_seed in cli.seed {
        let ma = seed_to_multiaddr(&raw_seed, net.default_p2p_port)
            .with_context(|| format!("--seed {raw_seed}"))?;
        cfg.network.seeds.push(ma.to_string());
    }

    let wallet_path = data_dir.join("wallet.key");
    if cli.export_wallet_secret {
        let master_secret = wallet::state::export_generated_master_secret(&wallet_path)
            .map_err(anyhow::Error::msg)?;
        println!("{}", master_secret.as_str());
        return Ok(());
    }
    if cli.import_wallet_secret {
        let mut master_secret = zeroize::Zeroizing::new(String::new());
        std::io::stdin()
            .take(4_097)
            .read_to_string(&mut master_secret)
            .context("read master secret from stdin")?;
        wallet::state::import_generated_master_secret(&wallet_path, &master_secret)
            .map_err(anyhow::Error::msg)?;
        println!("Master secret imported");
        return Ok(());
    }
    if let Some(class) = cli.prepare_history_step_cache {
        if embedded_history_step_cache_ready(&data_dir, class) {
            println!("HistoryStep {} matrix cache is ready", class.label());
            return Ok(());
        }
    }
    let history_proof_bank_id = embedded_history_step_pack::embedded_history_step_pack()
        .map(|pack| pack.runtime_metadata_digest())
        .unwrap_or([0; 32]);
    let history_step_runtime =
        embedded_history_step_runtime(&data_dir).map_err(anyhow::Error::msg)?;
    match &history_step_runtime {
        None => tracing::warn!(
            "HistoryStep verification unavailable in this pack-free development build"
        ),
        Some(_) => {
            tracing::debug!("HistoryStep verifier uses executable-embedded registry and matrices")
        }
    }
    if let Some(class) = cli.prepare_history_step_cache {
        let runtime = history_step_runtime.clone().ok_or_else(|| {
            anyhow::anyhow!("matrix preparation requires an embedded release pack")
        })?;
        tokio::task::spawn_blocking(move || runtime.prepare_matrix_cache(class.class_id()))
            .await
            .context("HistoryStep cache preparation task panicked")?
            .map_err(anyhow::Error::msg)?;
        println!("HistoryStep {} matrix cache is ready", class.label());
        return Ok(());
    }
    // Receiver snapshots are transactional scratch data. A crash can leave
    // sealed segment files behind, but they are never authoritative and must
    // not survive into a new sync session. Maintenance helpers return above:
    // a cache prewarm running beside a live node must never touch sync state.
    let snapshot_staging_root = data_dir.join("snapshot-staging");
    match std::fs::remove_dir_all(&snapshot_staging_root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "remove stale snapshot staging: {}",
                    snapshot_staging_root.display()
                )
            });
        }
    }
    std::fs::create_dir_all(&snapshot_staging_root).with_context(|| {
        format!(
            "create snapshot staging directory: {}",
            snapshot_staging_root.display()
        )
    })?;
    let block_production_enabled = cli.mode != NodeMode::Node;
    if block_production_enabled && history_step_runtime.is_none() {
        anyhow::bail!(
            "block production requires the release-pinned HistoryStep runtime and 2 matrices"
        );
    }
    let history_step_ghost = if block_production_enabled {
        Some(
            tokio::task::spawn_blocking(prepare_history_step_ghost_authorization)
                .await
                .context("HistoryStep ghost preparation task panicked")?
                .map_err(anyhow::Error::msg)?,
        )
    } else {
        None
    };

    // --- Storage ---
    tracing::debug!(path = %data_dir.display(), "opening MDBX");
    if cli.purge_state && !epoch_purge_applied {
        purge_chain_state(&data_dir)?;
    }
    let ctx = MdbxChainContext::open_or_create(&data_dir).context("open MDBX")?;
    let tip_height = ctx.tip_height();
    let state_root = hex::encode(ctx.tip_header().state_root);
    tracing::debug!(height = tip_height, state_root = %state_root, "chain loaded");
    let chain = Arc::new(RwLock::new(ctx));
    let initial_canonical_tip = {
        let ctx = chain.read().await;
        noid_p2p::object_protocol::ChainPoint::new(ctx.tip_height(), ctx.tip_hash())
    };
    let (canonical_tip_change_tx, canonical_tip_change_rx) =
        tokio::sync::watch::channel(initial_canonical_tip);

    // Durable initial readiness is separate from edge-triggered tip changes.
    // A Notify permit can be consumed by one of many mempool/miner waiters;
    // watch preserves the state for every current and future subscriber.
    let (initial_sync_ready_tx, initial_sync_ready_rx) = tokio::sync::watch::channel(false);
    let (initial_sync_stage_tx, initial_sync_stage_rx) =
        tokio::sync::watch::channel(NodeSyncStage::Headers);
    let (mining_proof_ready_tx, mining_proof_ready_rx) = tokio::sync::watch::channel(cli.genesis);
    let (mining_network_ready_tx, mining_network_ready_rx) =
        tokio::sync::watch::channel(cli.genesis);
    let (mining_confirmed_peer_count_tx, mining_confirmed_peer_count_rx) =
        tokio::sync::watch::channel(0usize);
    // Edge-triggered changes cancel active proof/PoW work when either the
    // canonical parent or a dynamic wallet payout changes.
    let (template_change_tx, _) = tokio::sync::broadcast::channel::<()>(16);
    // Extminer mode owns one prepared/proving attempt. P2P canonical advances
    // use this same handle to invalidate stale ready capabilities immediately.
    let external_mining_attempts = ExternalMiningAttemptInvalidator::new();
    // A recent local timestamp is not evidence that the durable tip is the
    // network tip. Ordinary restarts remain unready until an authenticated
    // peer confirms the exact tip or the sync pipeline applies its extension.

    // --- Mempool ---
    let view = ChainView::from_mdbx(&*chain.read().await);
    let authorization_verification_executor: noid_mempool::AuthorizationVerificationExecutor =
        Arc::new(|task: noid_mempool::AuthorizationVerificationTask| {
            noid_miner::install_inbound_verifier_cpu(task).map_err(|error| {
                format!("authorization verification CPU admission failed: {error}")
            })?
        });
    let mempool = AsyncMempool::new(view, MempoolConfig::default())
        .with_authorization_verification_executor(authorization_verification_executor);
    tracing::debug!("mempool ready");

    // --- Wallet ---
    let wallet_state = match WalletState::create_or_load(wallet_path) {
        Ok(w) => {
            tracing::debug!(address = %w.active_address(), "wallet ready");
            w
        }
        Err(e) => {
            tracing::error!(err = %e, "wallet init failed");
            return Err(anyhow::anyhow!("wallet: {e}"));
        }
    };
    let shared_wallet: SharedWallet = Arc::new(std::sync::Mutex::new(Some(wallet_state)));
    {
        let ctx = chain.read().await;
        let (active_index, next_index, owner, receipts_removed, receipts_recovered) = {
            let mut guard = shared_wallet.lock().unwrap();
            match guard.as_mut() {
                None => unreachable!("wallet just initialized"),
                Some(wallet) => {
                    let (removed, recovered) = wallet::reconcile_receipts_at_startup(wallet, &ctx)
                        .map_err(|error| anyhow::anyhow!("wallet receipt recovery: {error}"))?;
                    (
                        wallet.active_index,
                        wallet.next_index,
                        wallet.active_address().0,
                        removed,
                        recovered,
                    )
                }
            }
        };
        let snapshot = ctx
            .store
            .get_verified_utxos_by_owner(&owner)
            .map_err(|error| anyhow::anyhow!("wallet owner lookup: {error}"))?;
        let height = snapshot.height;
        let found = snapshot.utxos.len();
        let balance = snapshot
            .utxos
            .iter()
            .map(|utxo| utxo.amount)
            .fold(0u64, u64::saturating_add);
        let (reserved_inputs, reserved_outputs) = mempool.reserved_slots().await;
        {
            let mut guard = shared_wallet.lock().unwrap();
            if let Some(w) = guard.as_mut() {
                w.commit_verified_activation(
                    active_index,
                    next_index,
                    active_index,
                    owner,
                    snapshot,
                    &reserved_inputs,
                    &reserved_outputs,
                )
                .map_err(|error| anyhow::anyhow!("wallet owner reload: {error}"))?;
            }
        }
        drop(ctx);
        tracing::info!(
            height,
            active_index,
            utxos = found,
            balance,
            receipts_removed,
            receipts_recovered,
            "wallet active address loaded"
        );
    }
    let wallet = WalletHandle::new(shared_wallet.clone());
    let wallet_operation_gate = Arc::new(tokio::sync::Mutex::new(()));

    // --- P2P Network ---
    let topics = noid_p2p::protocol::NetworkTopics::for_network_cfg(&net);
    let p2p_background_capacity = if cli.mode == NodeMode::Node {
        noid_p2p::BackgroundCapacity::Full
    } else {
        noid_p2p::BackgroundCapacity::MiningReserved
    };
    let (p2p, mut p2p_task) = P2PNetwork::start(
        listen_addr.clone(),
        public_p2p_addresses,
        chain.clone(),
        mempool.clone(),
        topics,
        history_proof_bank_id,
        data_dir.clone(),
        p2p_background_capacity,
    )
    .context("start P2P network")?;
    let p2p_health_rx = p2p.health_receiver();
    tracing::debug!(listen = %listen_addr, "P2P started");

    // Dial seeds: CLI seeds + config seeds + the embedded DNS bootstrap set.
    // Isolated release-binary protocol tests disable only the final source;
    // explicit loopback seeds still exercise the normal P2P dial path.
    let dns_seeds = if cli.disable_dns_seeds {
        tracing::debug!("embedded DNS bootstrap disabled for isolated protocol test");
        &[][..]
    } else {
        net.dns_seeds
    };
    let mut registered_seed_addrs = std::collections::HashSet::new();
    for seed_addr in &cfg.network.seeds {
        let ma = seed_to_multiaddr(seed_addr, net.default_p2p_port);
        match ma {
            Ok(addr) => {
                if registered_seed_addrs.insert(addr.clone()) {
                    tracing::debug!(addr = %addr, "dialing configured seed");
                    p2p.dial(addr).await;
                }
            }
            Err(e) => {
                tracing::warn!(addr = %seed_addr, err = %e, "cannot parse seed address");
            }
        }
    }
    // Resolve all four embedded names concurrently through the operating
    // system. This includes scoped resolvers installed by VPN clients that may
    // be invisible to libp2p's resolver. If native resolution is unavailable,
    // retain the existing libp2p DNS multiaddr as a fallback.
    let embedded_seed_results = futures::future::join_all(
        dns_seeds
            .iter()
            .map(|seed| embedded_seed_multiaddrs(seed, net.default_p2p_port)),
    )
    .await;
    for (seed, result) in dns_seeds.iter().zip(embedded_seed_results) {
        match result {
            Ok(addresses) => {
                for address in addresses {
                    if registered_seed_addrs.insert(address.clone()) {
                        tracing::debug!(addr = %address, "dialing embedded seed");
                        p2p.dial(address).await;
                    }
                }
            }
            Err(error) => {
                tracing::warn!(addr = %seed, err = %error, "cannot parse embedded seed address");
            }
        }
    }

    // --genesis is an explicit isolated-mining override for network bootstrap
    // and local-chain tests. It remains valid after restart at any local height.
    // Normal miners require confirmed ordinary P2P nodes; peers need not mine.
    if initial_sync_may_skip_peer_confirmation(cli.genesis) {
        tracing::debug!("genesis mode: marking initial sync ready immediately");
        mark_initial_sync_ready(&initial_sync_ready_tx);
    }

    // Background P2P event handler.
    let p2p_chain = chain.clone();
    let p2p_mempool = mempool.clone();
    let p2p_wallet = shared_wallet.clone();
    let p2p_events = p2p.subscribe();
    let p2p_cmd_for_events = p2p.cmd_tx.clone();
    let p2p_template_changes = template_change_tx.clone();
    let p2p_initial_sync_ready = initial_sync_ready_tx.clone();
    let p2p_initial_sync_stage = initial_sync_stage_tx;
    let p2p_mining_peer_quorum = MiningPeerQuorum::new(
        cli.genesis,
        mining_proof_ready_tx,
        mining_network_ready_tx,
        mining_confirmed_peer_count_tx,
    );
    let p2p_wallet_operation_gate = Arc::clone(&wallet_operation_gate);
    let p2p_snapshot_staging_root = snapshot_staging_root.clone();
    let p2p_history_step_runtime = history_step_runtime.clone();
    let p2p_external_mining_attempts = external_mining_attempts.clone();
    let p2p_canonical_tip_changes = canonical_tip_change_rx;
    let mut p2p_event_task = tokio::spawn(async move {
        handle_p2p_events(
            p2p_events,
            p2p_chain,
            p2p_mempool,
            p2p_wallet,
            p2p_cmd_for_events,
            p2p_initial_sync_ready,
            p2p_initial_sync_stage,
            p2p_mining_peer_quorum,
            p2p_template_changes,
            p2p_wallet_operation_gate,
            p2p_snapshot_staging_root,
            p2p_history_step_runtime,
            p2p_external_mining_attempts,
            p2p_canonical_tip_changes,
        )
        .await
    });

    // Relay mempool TxAdmitted → P2P gossip.
    let mut mp_events = mempool.subscribe();
    let p2p_tx_relay = p2p.cmd_tx.clone();
    tokio::spawn(async move {
        loop {
            match mp_events.recv().await {
                Ok(noid_mempool::MempoolEvent::TxAdmitted { intent_bytes, .. }) => {
                    let _ = p2p_tx_relay
                        .send(noid_p2p::NetworkCommand::BroadcastTx { intent_bytes })
                        .await;
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "mempool relay: lagged, some TXs not gossiped");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // --- RPC Server ---
    // Payout address for the mining template API: explicit override or active wallet address.
    let mining_payout_address = if cfg.mining.miner_address.is_empty() {
        None
    } else {
        Some(parse_address(&cfg.mining.miner_address)?)
    };
    if mining_key.is_some() {
        tracing::info!(
            allow_custom_coinbase = cli.allow_custom_coinbase,
            "mining API: external access enabled with bearer token authentication"
        );
        if cli.allow_custom_coinbase {
            tracing::info!(
                "mining API: --allow-custom-coinbase active — \
                 authenticated miners may specify their own payout address"
            );
        }
    }
    if operator_key.is_some() {
        tracing::info!(
            "operator API: pool accounting and payout allowlist enabled with separate bearer authentication"
        );
        if !rpc_listen.ip().is_loopback() {
            tracing::warn!(
                listen = %rpc_listen,
                "operator API carries wallet authority without transport encryption; require a private firewall, VPN, or TLS tunnel"
            );
        }
    }
    let (rpc_handle, rpc_stop_rx) = start_rpc_server(
        rpc_listen,
        chain.clone(),
        mempool.clone(),
        wallet,
        Arc::clone(&wallet_operation_gate),
        p2p.cmd_tx.clone(),
        p2p_health_rx,
        canonical_tip_change_tx.clone(),
        initial_sync_ready_rx.clone(),
        initial_sync_stage_rx,
        mining_network_ready_rx.clone(),
        mining_confirmed_peer_count_rx.clone(),
        MINING_PEER_QUORUM,
        cli.genesis,
        cfg.mining.enabled,
        noid_core::cpu::selected_backend().to_string(),
        cpu_plan.available_threads,
        cpu_plan.shared_pool_threads,
        history_step_runtime.clone(),
        history_step_ghost.clone(),
        external_mining_attempts,
        template_change_tx.clone(),
        cli.mode == NodeMode::Extminer,
        mining_payout_address,
        mining_key,
        operator_key,
        cli.allow_custom_coinbase,
    )
    .await
    .context("start RPC server")?;
    tracing::debug!(listen = %rpc_listen, "RPC ready");

    // --- Miner (optional) ---
    let miner_handle = if cfg.mining.enabled {
        // If no miner address is configured, resolve the active wallet address
        // afresh for every template.
        // This ensures coinbase rewards go directly to the built-in wallet.
        let miner_addr = if cfg.mining.miner_address.is_empty() {
            let guard = shared_wallet.lock().unwrap();
            guard
                .as_ref()
                .map(|w| w.active_address())
                .unwrap_or(noid_poseidon2b::primitives::Address([0u8; 32]))
        } else {
            parse_address(&cfg.mining.miner_address)?
        };
        tracing::debug!(address = %miner_addr, "miner coinbase address");
        let miner_cfg = MinerConfig {
            miner_address: miner_addr,
            ..Default::default()
        };
        let (mut miner, mut miner_rx) = BlockMiner::new(
            miner_cfg,
            mempool.clone(),
            chain.clone(),
            mining_proof_ready_rx,
            mining_network_ready_rx,
            template_change_tx.clone(),
            Arc::clone(
                history_step_runtime
                    .as_ref()
                    .expect("producer runtime checked at startup"),
            ),
            Arc::clone(
                history_step_ghost
                    .as_ref()
                    .expect("producer ghost checked at startup"),
            ),
        );
        miner.set_chain_operation_gate(Arc::clone(&wallet_operation_gate));

        if cfg.mining.miner_address.is_empty() {
            let payout_wallet = shared_wallet.clone();
            let fallback_payout = miner_addr;
            miner.set_payout_resolver(std::sync::Arc::new(move || {
                payout_wallet
                    .lock()
                    .ok()
                    .and_then(|wallet| wallet.as_ref().map(|wallet| wallet.active_address()))
                    .unwrap_or(fallback_payout)
            }));
        }

        // Register wallet hook: called synchronously in apply_found_block BEFORE
        // on_new_block. Guarantees receipt is stored before getMempoolSize drops to 0.
        // Works at any mining speed — no channel, no capacity limit, no race.
        // Remote wallets use P2P block subscription independently.
        {
            let hook_wallet = shared_wallet.clone();
            let hook_canonical_tip_changes = canonical_tip_change_tx.clone();
            miner.set_block_applied_hook(std::sync::Arc::new(move |block| {
                update_wallet_for_block(&hook_wallet, block);
                hook_canonical_tip_changes.send_replace(
                    noid_p2p::object_protocol::ChainPoint::new(
                        block.header.height,
                        noid_chain::block_id(&block.header),
                    ),
                );
            }));
        }

        let miner_stop = miner.stop_handle(); // cancel_pow — aborts current PoW chunk
        let miner_stopped = miner.stopped_handle(); // permanent stop — breaks the loop

        let p2p_block_relay = p2p.cmd_tx.clone();
        tokio::spawn(async move {
            loop {
                match miner_rx.recv().await {
                    Ok(noid_miner::MinerEvent::BlockFound {
                        bundle,
                        height,
                        hash,
                        n_txs,
                        ..
                    }) => {
                        tracing::debug!(
                            height,
                            hash = %hex::encode(hash),
                            txs = n_txs,
                            "broadcast block"
                        );
                        let mut command = noid_p2p::NetworkCommand::AnnounceBlock { bundle };
                        loop {
                            match p2p_block_relay.try_send(command) {
                                Ok(()) => break,
                                Err(tokio::sync::mpsc::error::TrySendError::Full(returned)) => {
                                    command = returned;
                                    // Block production is independent of this
                                    // relay task. Preserve the locally accepted
                                    // header until the reserved lane drains
                                    // instead of silently losing propagation.
                                    tokio::time::sleep(Duration::from_millis(5)).await;
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                    tracing::error!(
                                        height,
                                        "P2P command lanes closed before local block announcement"
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    Ok(noid_miner::MinerEvent::ProveFailed { height, error }) => {
                        tracing::warn!(height, err = %error, "block prove failed");
                    }
                    Ok(_) => {} // TemplateRefreshed, MiningCancelled — no action needed
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // Channel lagged (fast mining at genesis difficulty).
                        // Wallet updates are unaffected — they go through the hook, not here.
                        tracing::warn!(skipped = n, "miner event channel lagged (broadcast only)");
                    }
                    Err(_) => break, // channel closed (miner stopped)
                }
            }
        });

        let task = tokio::spawn(async move { miner.run().await });
        tracing::debug!("miner started");
        Some((task, miner_stop, miner_stopped))
    } else {
        None
    };

    // --- Startup Banner ---
    {
        use noid_chain::consensus::emission::block_reward;
        use noid_chain::fri_state::LOG_SEGMENT_SIZE;

        let wallet_bech32 = {
            let g = shared_wallet.lock().unwrap();
            g.as_ref().map(|w| w.active_address().to_bech32())
        };
        let miner_bech32 = if cfg.mining.enabled {
            mining_payout_address
                .map(|address| address.to_bech32())
                .or_else(|| {
                    let wallet = shared_wallet.lock().unwrap();
                    wallet
                        .as_ref()
                        .map(|wallet| wallet.active_address().to_bech32())
                })
        } else {
            None
        };
        let ctx = chain.read().await;
        let tip_hdr = *ctx.tip_header();

        let log_slots = tip_hdr.log_slots;
        let active = tip_hdr.active_slot_count;
        let num_segs = if log_slots as usize > LOG_SEGMENT_SIZE {
            1usize << (log_slots as usize - LOG_SEGMENT_SIZE)
        } else {
            1
        };
        let mat_segs = ctx.state.state.active_segment_ids().count();
        let encoded_state_bytes = ctx
            .store
            .encoded_state_bytes()
            .context("read encoded state size for startup banner")?;
        let reward = block_reward(log_slots) as f64 / 1_000_000.0;

        drop(ctx);

        let p2p_display = listen_addr
            .to_string()
            .replace("/ip4/", "")
            .replace("/ip6/", "")
            .replace("/tcp/", ":");

        print_startup_banner(
            net.kind.as_str(),
            cli.genesis,
            &p2p_display,
            &rpc_listen.to_string(),
            tip_height,
            &tip_hdr.state_root,
            active,
            log_slots,
            mat_segs,
            num_segs,
            encoded_state_bytes,
            reward,
            wallet_bech32.as_deref(),
            cfg.mining.enabled,
            miner_bech32.as_deref(),
            env!("CARGO_PKG_VERSION"),
        );
    }

    // --- Shutdown ---
    // Wait for either Ctrl-C or a `paranoid_stop` RPC call.
    let fatal_runtime_error = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl-C received");
            None
        }
        _ = rpc_stop_rx => {
            tracing::info!("stop command received via RPC");
            None
        }
        result = &mut p2p_task => {
            let error = match result {
                Ok(Ok(())) => anyhow::anyhow!("P2P reactor stopped unexpectedly"),
                Ok(Err(error)) => anyhow::anyhow!("P2P reactor failed: {error}"),
                Err(error) => anyhow::anyhow!("P2P reactor task failed: {error}"),
            };
            tracing::error!(%error, "fatal networking task failure");
            Some(error)
        }
        result = &mut p2p_event_task => {
            let error = match result {
                Ok(Ok(())) => anyhow::anyhow!("P2P node event actor stopped unexpectedly"),
                Ok(Err(error)) => anyhow::anyhow!("P2P node event actor failed: {error}"),
                Err(error) => anyhow::anyhow!("P2P node event actor failed: {error}"),
            };
            tracing::error!(%error, "fatal networking task failure");
            Some(error)
        }
    };

    tracing::info!("shutting down — cancelling miner and closing connections");

    // 1. Signal the miner to stop: set `stopped` (breaks the loop) then
    //    `cancel_pow` (aborts the current PoW chunk so the loop reaches the
    //    top-of-loop check quickly).
    if let Some((_, ref stop_flag, ref stopped_flag)) = miner_handle {
        stopped_flag.store(true, std::sync::atomic::Ordering::Release);
        stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        tracing::debug!("miner stop flags set");
    }
    // 2. Stop RPC server (no new requests accepted).
    let _ = rpc_handle.stop();

    // 3. Wait for the miner task to exit cleanly. The miner checks `stopped`
    //    at the top of each loop iteration; `cancel_pow` ensures the current
    //    PoW chunk finishes quickly. Nonce-independent preparation and the
    //    atomic HistoryStep proof are deliberately not interrupted midway,
    //    so allow one bounded production phase to finish cleanly.
    if let Some((task, _, _)) = miner_handle {
        match tokio::time::timeout(MINER_SHUTDOWN_GRACE, task).await {
            Ok(Ok(_)) => tracing::debug!("miner task exited cleanly"),
            Ok(Err(e)) if e.is_cancelled() => tracing::debug!("miner task cancelled"),
            Ok(Err(e)) => tracing::warn!("miner task error: {e}"),
            Err(_) => tracing::warn!(
                grace_secs = MINER_SHUTDOWN_GRACE.as_secs(),
                "miner task did not finish its bounded phase before shutdown grace elapsed"
            ),
        }
    }
    if !p2p_task.is_finished() {
        p2p_task.abort();
        // Complete reactor cancellation before dropping its required-event
        // receiver. Otherwise a disconnect event already being emitted can
        // race the receiver abort and report a false fatal dispatch error
        // during an ordinary RPC/Ctrl-C shutdown.
        let _ = (&mut p2p_task).await;
    }
    if !p2p_event_task.is_finished() {
        p2p_event_task.abort();
        let _ = (&mut p2p_event_task).await;
    }
    tracing::info!("goodbye — MDBX flushed on drop");
    if let Some(error) = fatal_runtime_error {
        Err(error)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// P2P event handler
// ---------------------------------------------------------------------------

fn log_sync_phase_measurement(measurement: SyncPhaseMeasurement) {
    tracing::info!(
        phase = measurement.phase.label(),
        scaling = measurement.phase.scaling(),
        count = measurement.count,
        bytes = measurement.bytes,
        elapsed_ms = measurement.elapsed_ms(),
        timing_basis = "active_work",
        outcome = if measurement.succeeded {
            "accepted"
        } else {
            "rejected"
        },
        "snapshot sync phase measurement"
    );
}

struct PendingSnapshotHeaderSync {
    /// Immutable authority for this staging session. Sources may rotate
    /// independently without changing it.
    snapshot: noid_node::networking::SnapshotId,
    /// Transport preference only; never snapshot ownership or authority.
    preferred_peer: libp2p::PeerId,
    manifest: noid_p2p::protocol::VerifiedStateManifest,
    staging: SnapshotHeaderStaging,
    /// Required only when the manifest boundary is beyond the bounded
    /// in-memory HeaderDAG. The exact staged chain must contain this point.
    rebase_anchor: Option<SnapshotRebaseAnchor>,
    next_height: u64,
    target_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManifestTerminalCapability {
    boundary_height: u64,
    boundary_hash: [u8; 32],
}

impl ManifestTerminalCapability {
    fn advertises(self, height: u64, block_hash: [u8; 32]) -> bool {
        self.boundary_height == height && self.boundary_hash == block_hash
    }
}

fn retained_terminal_capability(
    records: &[noid_p2p::header_protocol::HeaderInventoryRecord],
    height: u64,
    block_hash: [u8; 32],
) -> Option<ManifestTerminalCapability> {
    records.iter().find_map(|record| {
        let terminal = record.terminal?;
        (record.header.height == height
            && noid_chain::block_header::block_id(&record.header) == block_hash
            && terminal.claim.height == height
            && terminal.claim.semantic_header_id
                == noid_chain::block_header::semantic_header_id(&record.header))
        .then_some(ManifestTerminalCapability {
            boundary_height: height,
            boundary_hash: block_hash,
        })
    })
}

fn is_single_header_inventory_for_point(
    records: &[noid_p2p::header_protocol::HeaderInventoryRecord],
    height: u64,
    block_hash: [u8; 32],
) -> bool {
    records.len() == 1
        && records[0].header.height == height
        && noid_chain::block_header::block_id(&records[0].header) == block_hash
}

fn remember_terminal_capability(
    capabilities: &mut std::collections::HashMap<libp2p::PeerId, ManifestTerminalCapability>,
    peer: libp2p::PeerId,
    observed: ManifestTerminalCapability,
    pinned: Option<ManifestTerminalCapability>,
) {
    let active_exact_inventory_is_pinned = pinned.is_some_and(|pinned| {
        observed != pinned && capabilities.get(&peer).is_some_and(|known| *known == pinned)
    });
    if !active_exact_inventory_is_pinned {
        capabilities.insert(peer, observed);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BoundaryProofTarget {
    header: noid_chain::BlockHeader,
    epoch_anchor_header: noid_chain::BlockHeader,
}

impl BoundaryProofTarget {
    fn height(self) -> u64 {
        self.header.height
    }

    fn block_hash(self) -> [u8; 32] {
        noid_chain::block_header::block_id(&self.header)
    }
}

/// Return the newest deterministic finalized snapshot boundary whose complete
/// terminal is absent locally. Recursive suffix markers deliberately do not
/// satisfy this check.
fn missing_snapshot_boundary_proof(
    ctx: &MdbxChainContext,
) -> Result<Option<BoundaryProofTarget>, String> {
    let finalized = ctx.finalized_checkpoint();
    let interval = noid_p2p::protocol::SNAPSHOT_BOUNDARY_INTERVAL;
    let height = finalized.height - finalized.height % interval;
    if height == 0 {
        return Ok(None);
    }
    let header = ctx
        .get_header_from_store(height)
        .map_err(|error| format!("read snapshot-boundary header: {error}"))?
        .ok_or_else(|| "canonical snapshot-boundary header is missing".to_owned())?;
    let block_hash = noid_chain::block_header::block_id(&header);
    if height == finalized.height && block_hash != finalized.hash {
        return Err("finalized snapshot-boundary hash is not canonical".to_owned());
    }
    let semantic_id = noid_chain::block_header::semantic_header_id(&header);
    let has_terminal = ctx
        .store
        .has_history_step_terminal_at(height, block_hash)
        .map_err(|error| format!("inspect canonical snapshot terminal: {error}"))?;
    let has_cached = ctx
        .store
        .has_any_history_step_proof_object(height, semantic_id)
        .map_err(|error| format!("inspect cached snapshot terminal: {error}"))?;
    if has_terminal || has_cached {
        return Ok(None);
    }
    let epoch_anchor_height =
        noid_chain::consensus::tx_epoch_anchor_height_for_child(header.height);
    let epoch_anchor_header = ctx
        .get_header_from_store(epoch_anchor_height)
        .map_err(|error| format!("read snapshot-boundary epoch anchor: {error}"))?
        .ok_or_else(|| "snapshot-boundary epoch anchor is missing".to_owned())?;
    Ok(Some(BoundaryProofTarget {
        header,
        epoch_anchor_header,
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingTerminalRequest {
    peer: libp2p::PeerId,
    token: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SnapshotTerminalSourceKey {
    peer: libp2p::PeerId,
    height: u64,
    block_hash: [u8; 32],
}

fn record_snapshot_terminal_transport_failure(
    failures: &mut std::collections::HashMap<SnapshotTerminalSourceKey, u8>,
    key: SnapshotTerminalSourceKey,
) -> u8 {
    let count = failures.entry(key).or_default();
    *count = count.saturating_add(1);
    *count
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TerminalRequestRace {
    primary: PendingTerminalRequest,
    primary_pending: bool,
    primary_active: bool,
    hedge: Option<PendingTerminalRequest>,
    hedge_pending: bool,
    hedge_active: bool,
    started_at: Instant,
}

impl TerminalRequestRace {
    fn new(peer: libp2p::PeerId, token: u64) -> Self {
        Self {
            primary: PendingTerminalRequest { peer, token },
            primary_pending: true,
            primary_active: false,
            hedge: None,
            hedge_pending: false,
            hedge_active: false,
            started_at: Instant::now(),
        }
    }

    fn hedge_due(&self, now: Instant) -> bool {
        self.primary_active
            && self.hedge.is_none()
            && now.saturating_duration_since(self.started_at) >= HISTORY_STEP_TERMINAL_HEDGE_AFTER
    }

    fn deadline_due(&self, now: Instant) -> bool {
        self.has_active()
            && now.saturating_duration_since(self.started_at) >= HISTORY_STEP_TERMINAL_HARD_DEADLINE
    }

    fn matches(&self, peer: libp2p::PeerId, token: u64) -> bool {
        (self.primary_active && self.primary == PendingTerminalRequest { peer, token })
            || (self.hedge_active && self.hedge == Some(PendingTerminalRequest { peer, token }))
    }

    fn has_active(&self) -> bool {
        self.primary_active || self.hedge_active
    }

    fn has_work(&self) -> bool {
        self.primary_pending || self.primary_active || self.hedge_pending || self.hedge_active
    }

    fn used_peer(&self, peer: libp2p::PeerId) -> bool {
        self.primary.peer == peer || self.hedge.is_some_and(|request| request.peer == peer)
    }

    fn install_hedge(&mut self, peer: libp2p::PeerId) {
        debug_assert!(self.hedge.is_none());
        self.hedge = Some(PendingTerminalRequest {
            peer,
            token: self.primary.token,
        });
        self.hedge_pending = true;
        self.hedge_active = false;
    }

    fn pending(&self) -> impl Iterator<Item = PendingTerminalRequest> + '_ {
        self.primary_pending
            .then_some(self.primary)
            .into_iter()
            .chain(self.hedge_pending.then_some(self.hedge).flatten())
    }

    fn active(&self) -> impl Iterator<Item = PendingTerminalRequest> + '_ {
        self.primary_active
            .then_some(self.primary)
            .into_iter()
            .chain(self.hedge_active.then_some(self.hedge).flatten())
    }

    fn mark_dispatched(&mut self, peer: libp2p::PeerId, token: u64) -> bool {
        let request = PendingTerminalRequest { peer, token };
        if self.primary_pending && self.primary == request {
            self.primary_pending = false;
            self.primary_active = true;
            self.started_at = Instant::now();
            return true;
        }
        if self.hedge_pending && self.hedge == Some(request) {
            self.hedge_pending = false;
            self.hedge_active = true;
            return true;
        }
        false
    }

    fn mark_failed(&mut self, peer: libp2p::PeerId, token: u64) -> bool {
        let request = PendingTerminalRequest { peer, token };
        if self.primary_active && self.primary == request {
            self.primary_active = false;
            return true;
        }
        if self.hedge_active && self.hedge == Some(request) {
            self.hedge_active = false;
            self.hedge = None;
            return true;
        }
        false
    }

    /// Return a request that never entered the transport correlation table to
    /// the local pending state. This is local backpressure, not evidence
    /// against the peer or its exact object advertisement.
    fn defer(&mut self, peer: libp2p::PeerId, token: u64) -> bool {
        let request = PendingTerminalRequest { peer, token };
        if self.primary_active && self.primary == request {
            self.primary_active = false;
            self.primary_pending = true;
            return true;
        }
        if self.hedge_active && self.hedge == Some(request) {
            self.hedge_active = false;
            self.hedge_pending = true;
            return true;
        }
        false
    }

    fn mark_succeeded(&mut self, peer: libp2p::PeerId, token: u64) -> bool {
        if !self.matches(peer, token) {
            return false;
        }
        self.primary_pending = false;
        self.primary_active = false;
        self.hedge_pending = false;
        self.hedge_active = false;
        true
    }

    fn retire_peer(&mut self, peer: libp2p::PeerId) -> bool {
        let mut retired = false;
        if self.primary.peer == peer && (self.primary_pending || self.primary_active) {
            self.primary_pending = false;
            self.primary_active = false;
            retired = true;
        }
        if self.hedge.is_some_and(|request| request.peer == peer)
            && (self.hedge_pending || self.hedge_active)
        {
            self.hedge_pending = false;
            self.hedge_active = false;
            self.hedge = None;
            retired = true;
        }
        retired
    }
}

#[cfg(test)]
fn terminal_alternate_peer(
    peers: &std::collections::HashSet<libp2p::PeerId>,
    rejected: &std::collections::HashSet<libp2p::PeerId>,
    requests: &TerminalRequestRace,
) -> Option<libp2p::PeerId> {
    peers
        .iter()
        .copied()
        .filter(|peer| !requests.used_peer(*peer))
        .filter(|peer| !rejected.contains(peer))
        .min_by_key(|peer| peer.to_bytes())
}

fn advertised_terminal_alternate_peer(
    peers: &std::collections::HashSet<libp2p::PeerId>,
    capabilities: &std::collections::HashMap<libp2p::PeerId, ManifestTerminalCapability>,
    rejected: &std::collections::HashSet<libp2p::PeerId>,
    exhausted: &std::collections::HashSet<SnapshotTerminalSourceKey>,
    retry_after: &std::collections::HashMap<libp2p::PeerId, Instant>,
    requests: &TerminalRequestRace,
    height: u64,
    block_hash: [u8; 32],
    now: Instant,
) -> Option<libp2p::PeerId> {
    peers
        .iter()
        .copied()
        .filter(|peer| !requests.used_peer(*peer))
        .filter(|peer| !rejected.contains(peer))
        .filter(|peer| {
            !exhausted.contains(&SnapshotTerminalSourceKey {
                peer: *peer,
                height,
                block_hash,
            })
        })
        .filter(|peer| retry_after.get(peer).is_none_or(|until| *until <= now))
        .filter(|peer| {
            capabilities
                .get(peer)
                .is_some_and(|capability| capability.advertises(height, block_hash))
        })
        .min_by_key(|peer| peer.to_bytes())
}

fn advertised_terminal_peer(
    peers: &std::collections::HashSet<libp2p::PeerId>,
    capabilities: &std::collections::HashMap<libp2p::PeerId, ManifestTerminalCapability>,
    rejected: &std::collections::HashSet<libp2p::PeerId>,
    exhausted: &std::collections::HashSet<SnapshotTerminalSourceKey>,
    retry_after: &std::collections::HashMap<libp2p::PeerId, Instant>,
    preferred: libp2p::PeerId,
    height: u64,
    block_hash: [u8; 32],
    now: Instant,
) -> Option<libp2p::PeerId> {
    peers
        .iter()
        .copied()
        .filter(|peer| !rejected.contains(peer))
        .filter(|peer| {
            !exhausted.contains(&SnapshotTerminalSourceKey {
                peer: *peer,
                height,
                block_hash,
            })
        })
        .filter(|peer| retry_after.get(peer).is_none_or(|until| *until <= now))
        .filter(|peer| {
            capabilities
                .get(peer)
                .is_some_and(|capability| capability.advertises(height, block_hash))
        })
        .min_by_key(|peer| (*peer != preferred, peer.to_bytes()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SnapshotHeaderNextAction {
    Fetch { start_height: u64, count: u16 },
    RequestTerminal,
}

/// Consecutive, non-overlapping ranges requested from one selected peer. They
/// may arrive out of order, but only the exact next height enters native
/// validation. This hides request/response latency without racing sources.
const SNAPSHOT_HEADER_REQUEST_WINDOW: usize = 4;
/// Use the codec's allocation-bounded response cap directly. The bounded
/// ordered window avoids paying one request-response round trip per range.
const SNAPSHOT_HEADER_BATCH: u64 = MAX_STAGED_HEADER_BATCH as u64;
/// A timeout on a slow path reduces only the failed range. Successful paths
/// retain the full bulk batch, while a VPN or constrained relay can make
/// progress without repeatedly timing out on the same full-size response.
const SNAPSHOT_HEADER_MIN_BATCH: u16 = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SnapshotHeaderRequestPlan {
    peer: libp2p::PeerId,
    token: u64,
    start_height: u64,
    count: u16,
}

#[derive(Clone, Debug)]
struct SnapshotHeaderAttempt {
    peer: libp2p::PeerId,
    token: u64,
}

#[derive(Clone, Debug)]
struct OutstandingSnapshotHeaderRequest {
    count: u16,
    primary: SnapshotHeaderAttempt,
    attempted_peers: std::collections::HashSet<libp2p::PeerId>,
}

#[derive(Clone, Debug)]
struct BlockedSnapshotHeaderRange {
    start_height: u64,
    count: u16,
    attempted_peers: std::collections::HashSet<libp2p::PeerId>,
    blocked_at: Instant,
}

impl OutstandingSnapshotHeaderRequest {
    fn accepts(&self, peer: libp2p::PeerId, token: u64) -> bool {
        self.primary.peer == peer && self.primary.token == token
    }
}

#[derive(Debug)]
struct ReadySnapshotHeaderRange {
    source_peer: libp2p::PeerId,
    count: u16,
    attempted_peers: std::collections::HashSet<libp2p::PeerId>,
    headers: Vec<noid_chain::BlockHeader>,
}

#[derive(Debug)]
struct SnapshotHeaderPipeline {
    generation: u64,
    snapshot: noid_node::networking::SnapshotId,
    /// Exact headers are ordinary chain data. A peer that wins a range becomes
    /// the preferred source for later ranges without changing snapshot owner.
    preferred_peer: libp2p::PeerId,
    target_height: u64,
    next_request_height: u64,
    next_request_token: u64,
    batch_cap: u16,
    peer_cursor: usize,
    outstanding: std::collections::BTreeMap<u64, OutstandingSnapshotHeaderRequest>,
    ready: std::collections::BTreeMap<u64, ReadySnapshotHeaderRange>,
    /// Exact requests that exist in the immutable header plan but could not
    /// enter the bounded node-to-swarm data lane yet.
    deferred_dispatch: std::collections::BTreeSet<u64>,
    /// Exact gap retained when every currently connected source has failed.
    /// A later peer or bounded retry resumes this range without replacing the
    /// snapshot plan or its validated prefix.
    blocked: Option<BlockedSnapshotHeaderRange>,
    /// Bounded retries may revisit the same connected sources after a timeout,
    /// but cannot turn one dead range into an infinite transport loop.
    blocked_retry_rounds: u8,
}

impl SnapshotHeaderPipeline {
    fn new(
        generation: u64,
        snapshot: noid_node::networking::SnapshotId,
        initial_peer: libp2p::PeerId,
        next_height: u64,
        target_height: u64,
    ) -> Self {
        Self {
            generation,
            snapshot,
            preferred_peer: initial_peer,
            target_height,
            next_request_height: next_height,
            next_request_token: 0,
            batch_cap: SNAPSHOT_HEADER_BATCH as u16,
            peer_cursor: 0,
            outstanding: std::collections::BTreeMap::new(),
            ready: std::collections::BTreeMap::new(),
            deferred_dispatch: std::collections::BTreeSet::new(),
            blocked: None,
            blocked_retry_rounds: 0,
        }
    }

    fn allocate_token(&mut self) -> u64 {
        self.next_request_token = self.next_request_token.wrapping_add(1);
        self.next_request_token
    }

    fn refill_plan(&mut self, locally_staging: bool) -> Vec<SnapshotHeaderRequestPlan> {
        let mut plan = Vec::with_capacity(SNAPSHOT_HEADER_REQUEST_WINDOW);
        let reserved = usize::from(locally_staging);

        let deferred = self
            .deferred_dispatch
            .iter()
            .copied()
            .take(SNAPSHOT_HEADER_REQUEST_WINDOW.saturating_sub(reserved))
            .collect::<Vec<_>>();
        for start_height in deferred {
            self.deferred_dispatch.remove(&start_height);
            let request = self
                .outstanding
                .get(&start_height)
                .expect("deferred snapshot header request remains outstanding");
            plan.push(SnapshotHeaderRequestPlan {
                peer: request.primary.peer,
                token: request.primary.token,
                start_height,
                count: request.count,
            });
        }
        if self.blocked.is_some() {
            return plan;
        }
        while self.outstanding.len() + self.ready.len() + reserved < SNAPSHOT_HEADER_REQUEST_WINDOW
            && self.next_request_height <= self.target_height
        {
            let start_height = self.next_request_height;
            let count = (self.target_height - start_height + 1)
                .min(u64::from(self.batch_cap))
                .min(MAX_STAGED_HEADER_BATCH as u64) as u16;
            self.next_request_height += u64::from(count);
            let token = self.allocate_token();
            self.outstanding.insert(
                start_height,
                OutstandingSnapshotHeaderRequest {
                    count,
                    primary: SnapshotHeaderAttempt {
                        peer: self.preferred_peer,
                        token,
                    },
                    attempted_peers: std::iter::once(self.preferred_peer).collect(),
                },
            );
            plan.push(SnapshotHeaderRequestPlan {
                peer: self.preferred_peer,
                token,
                start_height,
                count,
            });
        }
        plan
    }

    fn defer_dispatch(&mut self, request: SnapshotHeaderRequestPlan) -> Result<(), String> {
        if !self.matches_outstanding(
            request.peer,
            request.start_height,
            request.count,
            request.token,
        ) {
            return Err("cannot defer a stale snapshot header request".into());
        }
        self.deferred_dispatch.insert(request.start_height);
        Ok(())
    }

    fn matches_generation(&self, generation: u64) -> bool {
        self.generation == generation
    }

    fn accept(
        &mut self,
        generation: u64,
        token: u64,
        from: libp2p::PeerId,
        start_height: u64,
        requested_count: u16,
        headers: Vec<noid_chain::BlockHeader>,
    ) -> Result<(), String> {
        if generation != self.generation {
            return Err("snapshot header response belongs to another session".into());
        }
        let Some(expected) = self.outstanding.remove(&start_height) else {
            return Err("snapshot header response has no matching outstanding range".into());
        };
        self.deferred_dispatch.remove(&start_height);
        let response_valid = (|| {
            if !expected.accepts(from, token) {
                return Err("snapshot header response has a stale correlation token".to_owned());
            }
            if expected.count != requested_count || headers.len() != usize::from(expected.count) {
                return Err(
                    "snapshot header response length does not match its exact request".to_owned(),
                );
            }
            if headers
                .first()
                .is_none_or(|header| header.height != start_height)
            {
                return Err("snapshot header response starts at the wrong height".to_owned());
            }
            let expected_end = start_height + u64::from(expected.count) - 1;
            if headers
                .last()
                .is_none_or(|header| header.height != expected_end)
            {
                return Err("snapshot header response ends at the wrong height".to_owned());
            }
            Ok(())
        })();
        if let Err(error) = response_valid {
            self.outstanding.insert(start_height, expected);
            return Err(error);
        }
        self.preferred_peer = from;
        self.blocked_retry_rounds = 0;
        if self
            .ready
            .insert(
                start_height,
                ReadySnapshotHeaderRange {
                    source_peer: from,
                    count: expected.count,
                    attempted_peers: expected.attempted_peers,
                    headers,
                },
            )
            .is_some()
        {
            return Err("duplicate snapshot header response".into());
        }
        Ok(())
    }

    fn matches_outstanding(
        &self,
        peer: libp2p::PeerId,
        start_height: u64,
        count: u16,
        token: u64,
    ) -> bool {
        self.outstanding
            .get(&start_height)
            .is_some_and(|request| request.count == count && request.accepts(peer, token))
    }

    fn rotating_peer(
        &mut self,
        peers: &std::collections::HashSet<libp2p::PeerId>,
        attempted: &std::collections::HashSet<libp2p::PeerId>,
    ) -> Option<libp2p::PeerId> {
        let mut candidates = peers
            .iter()
            .copied()
            .filter(|peer| !attempted.contains(peer))
            .collect::<Vec<_>>();
        candidates.sort_by_key(|peer| peer.to_bytes());
        if candidates.is_empty() {
            return None;
        }
        let index = self.peer_cursor % candidates.len();
        self.peer_cursor = self.peer_cursor.wrapping_add(1);
        Some(candidates[index])
    }

    fn restart_range(
        &mut self,
        start_height: u64,
        peer: libp2p::PeerId,
        count: u16,
        mut attempted_peers: std::collections::HashSet<libp2p::PeerId>,
    ) -> SnapshotHeaderRequestPlan {
        self.blocked = None;
        let token = self.allocate_token();
        attempted_peers.insert(peer);
        self.outstanding.insert(
            start_height,
            OutstandingSnapshotHeaderRequest {
                count,
                primary: SnapshotHeaderAttempt { peer, token },
                attempted_peers,
            },
        );
        SnapshotHeaderRequestPlan {
            peer,
            token,
            start_height,
            count,
        }
    }

    fn failure_plan(
        &mut self,
        peer: libp2p::PeerId,
        start_height: u64,
        count: u16,
        token: u64,
        kind: noid_p2p::RequestFailureKind,
        peers: &std::collections::HashSet<libp2p::PeerId>,
    ) -> Option<SnapshotHeaderRequestPlan> {
        let (mut retry_count, mut attempted_peers, failed_peer) = {
            let request = self.outstanding.remove(&start_height)?;
            if request.count != count {
                self.outstanding.insert(start_height, request);
                return None;
            }
            if request.primary.peer != peer || request.primary.token != token {
                self.outstanding.insert(start_height, request);
                return None;
            }
            (request.count, request.attempted_peers, request.primary.peer)
        };

        // Every later range was scheduled from the failed prefix. Retire it
        // deterministically and rebuild from this exact height. Earlier ranges
        // remain useful and are still consumed in order.
        self.outstanding
            .retain(|range_start, _| *range_start < start_height);
        self.ready
            .retain(|range_start, _| *range_start < start_height);
        self.deferred_dispatch
            .retain(|range_start| *range_start < start_height);

        if matches!(kind, noid_p2p::RequestFailureKind::Timeout)
            && retry_count > SNAPSHOT_HEADER_MIN_BATCH
        {
            retry_count = (retry_count / 2).max(SNAPSHOT_HEADER_MIN_BATCH);
            self.batch_cap = self.batch_cap.min(retry_count);
            attempted_peers.clear();
            if peers.len() > 1 {
                attempted_peers.insert(failed_peer);
            }
        }
        self.next_request_height = start_height.saturating_add(u64::from(retry_count));
        let Some(alternate) = self.rotating_peer(peers, &attempted_peers) else {
            self.blocked = Some(BlockedSnapshotHeaderRange {
                start_height,
                count: retry_count,
                attempted_peers,
                blocked_at: Instant::now(),
            });
            return None;
        };
        Some(self.restart_range(start_height, alternate, retry_count, attempted_peers))
    }

    fn retry_rejected_range(
        &mut self,
        start_height: u64,
        count: u16,
        attempted_peers: std::collections::HashSet<libp2p::PeerId>,
        peers: &std::collections::HashSet<libp2p::PeerId>,
    ) -> Option<SnapshotHeaderRequestPlan> {
        if self.next_request_height < start_height.saturating_add(u64::from(count)) {
            return None;
        }
        // Later ranges may have overlapped local validation of this batch. They
        // are based on the rejected prefix, so retire their correlation tokens
        // and rebuild the ordered pipeline from this exact height.
        self.outstanding
            .retain(|range_start, _| *range_start < start_height);
        self.ready
            .retain(|range_start, _| *range_start < start_height);
        self.deferred_dispatch
            .retain(|range_start| *range_start < start_height);
        self.next_request_height = start_height.saturating_add(u64::from(count));
        let Some(alternate) = self.rotating_peer(peers, &attempted_peers) else {
            self.blocked = Some(BlockedSnapshotHeaderRange {
                start_height,
                count,
                attempted_peers,
                blocked_at: Instant::now(),
            });
            return None;
        };
        Some(self.restart_range(start_height, alternate, count, attempted_peers))
    }

    fn resume_blocked(
        &mut self,
        peers: &std::collections::HashSet<libp2p::PeerId>,
        now: Instant,
    ) -> Option<SnapshotHeaderRequestPlan> {
        let mut blocked = self.blocked.take()?;
        if now.saturating_duration_since(blocked.blocked_at) >= Duration::from_secs(5)
            && self.blocked_retry_rounds < 3
        {
            blocked.attempted_peers.clear();
            blocked.blocked_at = now;
            self.blocked_retry_rounds = self.blocked_retry_rounds.saturating_add(1);
        }
        let Some(peer) = self.rotating_peer(peers, &blocked.attempted_peers) else {
            self.blocked = Some(blocked);
            return None;
        };
        Some(self.restart_range(
            blocked.start_height,
            peer,
            blocked.count,
            blocked.attempted_peers,
        ))
    }

    fn take_ready(&mut self, next_height: u64) -> Option<ReadySnapshotHeaderRange> {
        self.ready.remove(&next_height)
    }

    fn is_drained(&self) -> bool {
        self.next_request_height > self.target_height
            && self.outstanding.is_empty()
            && self.ready.is_empty()
            && self.blocked.is_none()
    }

    fn has_transport_or_local_work(&self) -> bool {
        !self.outstanding.is_empty() || !self.ready.is_empty() || !self.deferred_dispatch.is_empty()
    }

    fn is_parked_without_source(&self) -> bool {
        self.blocked.is_some() && !self.has_transport_or_local_work()
    }
}

fn dispatch_snapshot_header_plans(
    pipeline: &mut SnapshotHeaderPipeline,
    p2p_cmd: &noid_p2p::NetworkCommandSender,
    plans: impl IntoIterator<Item = SnapshotHeaderRequestPlan>,
) {
    let generation = pipeline.generation;
    let mut data_lane_full = false;
    for request in plans {
        let dispatched = !data_lane_full
            && p2p_cmd
                .try_send(noid_p2p::NetworkCommand::FetchSnapshotHeaders {
                    generation,
                    token: request.token,
                    peer: request.peer,
                    start_height: request.start_height,
                    count: request.count,
                })
                .is_ok();
        if !dispatched {
            data_lane_full = true;
            pipeline
                .defer_dispatch(request)
                .expect("fresh snapshot header request must remain deferrable");
        }
    }
}

fn snapshot_header_next_action(
    next_height: u64,
    target_height: u64,
) -> Result<SnapshotHeaderNextAction, String> {
    if next_height <= target_height {
        let count = (target_height - next_height + 1)
            .min(SNAPSHOT_HEADER_BATCH)
            .min(MAX_STAGED_HEADER_BATCH as u64) as u16;
        return Ok(SnapshotHeaderNextAction::Fetch {
            start_height: next_height,
            count,
        });
    }
    if target_height.checked_add(1) == Some(next_height) {
        return Ok(SnapshotHeaderNextAction::RequestTerminal);
    }
    Err("snapshot header staging advanced beyond its exact target".into())
}

fn validate_snapshot_header_batch_admission(
    next_height: u64,
    target_height: u64,
    batch_len: usize,
) -> Result<(), String> {
    if next_height > target_height {
        return Err("snapshot exact header target is already staged".into());
    }
    let remaining = target_height - next_height + 1;
    if batch_len == 0 {
        return Err("snapshot header batch is empty".into());
    }
    if batch_len > MAX_STAGED_HEADER_BATCH {
        return Err("snapshot header batch exceeds the bounded response cap".into());
    }
    if batch_len as u64 > remaining {
        return Err("snapshot header batch crosses the exact target".into());
    }
    Ok(())
}

fn snapshot_header_staging_path(
    staging_root: &Path,
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
) -> PathBuf {
    staging_root.join("headers").join(format!(
        "{}-{}.stage",
        manifest.tip_height,
        hex::encode(manifest.tip_hash)
    ))
}

fn prune_superseded_snapshot_header_staging(directory: &Path, keep: &Path) -> Result<(), String> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| format!("read snapshot header staging directory: {error}"))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("read snapshot header staging entry: {error}"))?;
        let path = entry.path();
        if path == keep || path.extension().and_then(|ext| ext.to_str()) != Some("stage") {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "remove superseded snapshot header staging {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

/// Find the highest contiguous canonical header boundary at or below target.
/// Header anchors are created strictly in height order, so a binary search is
/// sufficient and never materializes an O(H) header collection.
enum SnapshotHeaderPrepareError {
    BaseMoved(String),
    Fatal(String),
}

enum SnapshotSessionPrepareError {
    CandidateRejected(String),
    Fatal(String),
}

enum SnapshotFinalizationOutcome {
    Finalized(FinalizedSnapshotStaging),
    CandidateRejected(String),
    Fatal(String),
}

fn classify_snapshot_finalization_error(
    error: SnapshotStagingError,
) -> SnapshotFinalizationOutcome {
    let message = error.to_string();
    match error {
        // Every segment can match its advertised subtree root while the set of
        // advertised roots still fails to reconstruct the State commitment in
        // the authenticated boundary. That rejects the immutable generation;
        // it is not a local daemon failure.
        SnapshotStagingError::ActiveCountMismatch { .. }
        | SnapshotStagingError::StateRootMismatch { .. } => {
            SnapshotFinalizationOutcome::CandidateRejected(message)
        }
        // Files were already authenticated and atomically published. Any I/O,
        // mutation, missing file or impossible session state at the second
        // pass is local and must fail explicitly rather than blame a peer.
        _ => SnapshotFinalizationOutcome::Fatal(message),
    }
}

fn classify_snapshot_session_prepare_error(
    error: SnapshotStagingError,
) -> SnapshotSessionPrepareError {
    let message = error.to_string();
    match error {
        // These values originate in the peer's immutable manifest. They may
        // reject that candidate, but cannot make local storage unhealthy.
        SnapshotStagingError::TipHashMismatch
        | SnapshotStagingError::EffectiveLogMismatch { .. }
        | SnapshotStagingError::TooManyDescriptors { .. }
        | SnapshotStagingError::DescriptorOrder { .. }
        | SnapshotStagingError::SegmentIdOutOfRange { .. }
        | SnapshotStagingError::DescriptorLength { .. }
        | SnapshotStagingError::SegmentTooLarge { .. } => {
            SnapshotSessionPrepareError::CandidateRejected(message)
        }
        // Header invariants, filesystem errors and impossible session-state
        // errors are local faults. A different peer cannot repair them.
        _ => SnapshotSessionPrepareError::Fatal(message),
    }
}

fn classify_snapshot_header_prepare_error(
    error: SnapshotHeaderStagingError,
) -> SnapshotHeaderPrepareError {
    match error {
        SnapshotHeaderStagingError::CanonicalBaseMoved { .. } => {
            SnapshotHeaderPrepareError::BaseMoved(error.to_string())
        }
        _ => SnapshotHeaderPrepareError::Fatal(error.to_string()),
    }
}

fn snapshot_header_cache_can_be_recreated(error: &SnapshotHeaderStagingError) -> bool {
    matches!(
        error,
        SnapshotHeaderStagingError::Format(_)
            | SnapshotHeaderStagingError::InvalidCandidate { .. }
            | SnapshotHeaderStagingError::ParentMismatch { .. }
            | SnapshotHeaderStagingError::CanonicalBaseMoved { .. }
    ) || matches!(
        error,
        SnapshotHeaderStagingError::Io(io)
            if io.kind() == std::io::ErrorKind::UnexpectedEof
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SnapshotSegmentFailureScope {
    Source,
    Candidate,
    Fatal,
}

/// Separate transport bytes, immutable-candidate semantics and local state.
/// Semantic errors are classified as candidate failures only after the State
/// segment verifier has matched the exact advertised subtree root.
fn snapshot_segment_failure_scope(error: &SnapshotStagingError) -> SnapshotSegmentFailureScope {
    match error {
        SnapshotStagingError::ResponseEffectiveLogMismatch { .. }
        | SnapshotStagingError::PayloadLength { .. }
        | SnapshotStagingError::SegmentDecode { .. }
        | SnapshotStagingError::EncodedEffectiveLogMismatch { .. }
        | SnapshotStagingError::ExactSegmentRootMismatch { .. } => {
            SnapshotSegmentFailureScope::Source
        }
        SnapshotStagingError::CreationIdExceedsBound { .. }
        | SnapshotStagingError::CoinbaseCreationHeightExceedsBoundary { .. }
        | SnapshotStagingError::EmptyAdvertisedSegment { .. } => {
            SnapshotSegmentFailureScope::Candidate
        }
        _ => SnapshotSegmentFailureScope::Fatal,
    }
}

fn highest_snapshot_header_boundary(
    store: &noid_chain::storage::MdbxStore,
    target_height: u64,
) -> Result<CanonicalHeaderBoundary, SnapshotHeaderPrepareError> {
    let state_tip = store
        .get_chain_tip()
        .map_err(|error| {
            SnapshotHeaderPrepareError::Fatal(format!(
                "snapshot canonical tip read failed: {error}"
            ))
        })?
        .ok_or_else(|| {
            SnapshotHeaderPrepareError::Fatal("snapshot canonical tip is missing".to_owned())
        })?
        .0;
    let floor = state_tip.min(target_height);
    CanonicalHeaderBoundary::load(store, floor).map_err(classify_snapshot_header_prepare_error)?;
    if floor == target_height {
        return CanonicalHeaderBoundary::load(store, floor)
            .map_err(classify_snapshot_header_prepare_error);
    }
    if store
        .get_header_anchor(target_height)
        .map_err(|error| {
            SnapshotHeaderPrepareError::Fatal(format!(
                "snapshot target anchor read failed: {error}"
            ))
        })?
        .is_some()
    {
        return CanonicalHeaderBoundary::load(store, target_height)
            .map_err(classify_snapshot_header_prepare_error);
    }

    let mut present = floor;
    let mut missing = target_height;
    while present + 1 < missing {
        let middle = present + (missing - present) / 2;
        if store
            .get_header_anchor(middle)
            .map_err(|error| {
                SnapshotHeaderPrepareError::Fatal(format!(
                    "snapshot header anchor read h={middle}: {error}"
                ))
            })?
            .is_some()
        {
            present = middle;
        } else {
            missing = middle;
        }
    }
    CanonicalHeaderBoundary::load(store, present).map_err(classify_snapshot_header_prepare_error)
}

fn prepare_snapshot_header_sync(
    staging_root: &Path,
    store: &noid_chain::storage::MdbxStore,
    from: libp2p::PeerId,
    manifest: noid_p2p::protocol::VerifiedStateManifest,
    rebase_base: Option<(u64, [u8; 32])>,
    rebase_anchor: Option<SnapshotRebaseAnchor>,
) -> Result<PendingSnapshotHeaderSync, SnapshotHeaderPrepareError> {
    let target_height = manifest.tip_height;
    let allow_nonfinal_rebase = rebase_base.is_some();
    let after_target = target_height.checked_add(1).ok_or_else(|| {
        SnapshotHeaderPrepareError::Fatal(
            "snapshot target height has no representable successor".to_owned(),
        )
    })?;
    let base = match rebase_base.filter(|(height, _)| *height < target_height) {
        Some((height, expected_hash)) => {
            let base = CanonicalHeaderBoundary::load(store, height)
                .map_err(classify_snapshot_header_prepare_error)?;
            if base.block_hash != expected_hash {
                return Err(SnapshotHeaderPrepareError::BaseMoved(
                    "snapshot rebase boundary changed before staging".into(),
                ));
            }
            base
        }
        None => highest_snapshot_header_boundary(store, target_height)?,
    };
    let directory = staging_root.join("headers");
    std::fs::create_dir_all(&directory).map_err(|error| {
        SnapshotHeaderPrepareError::Fatal(format!(
            "create snapshot header staging directory: {error}"
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                SnapshotHeaderPrepareError::Fatal(format!(
                    "secure snapshot header staging directory: {error}"
                ))
            },
        )?;
    }
    let path = snapshot_header_staging_path(staging_root, &manifest);
    // A failed exact terminal may leave one expensive header prefix available
    // for immediate failover. Once a different boundary wins, delete the old
    // file before opening the new session so disk use stays bounded to one
    // O(height) staging artifact.
    prune_superseded_snapshot_header_staging(&directory, &path)
        .map_err(SnapshotHeaderPrepareError::Fatal)?;

    let create_staging = || {
        if base.header.height == target_height {
            SnapshotHeaderStaging::create_at_canonical_boundary(&path, store, base)
        } else if allow_nonfinal_rebase {
            SnapshotHeaderStaging::create_at_nonfinal_rebase_boundary(&path, store, base)
        } else {
            SnapshotHeaderStaging::create(&path, store, base)
        }
        .map_err(classify_snapshot_header_prepare_error)
    };
    let staging = if path.exists() {
        match SnapshotHeaderStaging::open(&path, store) {
            Ok(staging) => {
                let next_height = staging
                    .next_height()
                    .map_err(classify_snapshot_header_prepare_error)?;
                if staging.base() == base && next_height <= after_target {
                    staging
                } else {
                    staging
                        .discard()
                        .map_err(classify_snapshot_header_prepare_error)?;
                    create_staging()?
                }
            }
            Err(error) if snapshot_header_cache_can_be_recreated(&error) => {
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(SnapshotHeaderPrepareError::Fatal(format!(
                            "discard recoverable snapshot header staging: {error}"
                        )));
                    }
                }
                create_staging()?
            }
            Err(error) => return Err(classify_snapshot_header_prepare_error(error)),
        }
    } else {
        create_staging()?
    };
    let next_height = staging
        .next_height()
        .map_err(classify_snapshot_header_prepare_error)?;
    Ok(PendingSnapshotHeaderSync {
        snapshot: noid_node::networking::SnapshotId {
            boundary: noid_node::networking::ChainPoint::new(
                manifest.tip_height,
                manifest.tip_hash,
            ),
            state_root: manifest.state_root,
            manifest_digest: manifest.manifest_digest,
            format_version: manifest.format_version,
        },
        preferred_peer: from,
        manifest,
        staging,
        rebase_anchor,
        next_height,
        target_height,
    })
}

struct VerifiedHistoryStepSnapshot {
    height: u64,
    block_hash: [u8; 32],
    boundary: noid_chain::VerifiedSnapshotBoundary,
    headers: ValidatedSnapshotHeaderStaging,
    allow_nonfinal_rebase: bool,
    /// The exact inbound allocation remains charged until the terminal bytes
    /// have entered the same MDBX transaction as the snapshot state.
    inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}

struct RetainedSnapshotHeaderAuthority {
    snapshot: noid_node::networking::SnapshotId,
    headers: ValidatedSnapshotHeaderStaging,
    allow_nonfinal_rebase: bool,
    staged_header_count: u64,
}

enum SnapshotBoundaryVerificationOutcome {
    Accepted(VerifiedHistoryStepSnapshot),
    TerminalRejected {
        error: String,
        authority: RetainedSnapshotHeaderAuthority,
    },
    CandidateRejected {
        error: String,
        authority: Option<RetainedSnapshotHeaderAuthority>,
    },
    BaseMoved {
        error: String,
        authority: Option<RetainedSnapshotHeaderAuthority>,
    },
    Fatal {
        error: String,
        authority: Option<RetainedSnapshotHeaderAuthority>,
    },
}

fn snapshot_header_completion_rejects_candidate(error: &SnapshotHeaderStagingError) -> bool {
    matches!(
        error,
        SnapshotHeaderStagingError::InvalidCandidate { .. }
            | SnapshotHeaderStagingError::ParentMismatch { .. }
    )
}

fn snapshot_header_completion_base_moved(error: &SnapshotHeaderStagingError) -> bool {
    matches!(error, SnapshotHeaderStagingError::CanonicalBaseMoved { .. })
}

fn verify_terminal_against_validated_snapshot_headers(
    chain: &RwLock<MdbxChainContext>,
    runtime: &noid_recursive::acceptance::history_step::HistoryStepRuntime,
    authority: RetainedSnapshotHeaderAuthority,
    terminal_bytes: Vec<u8>,
    inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
) -> (SnapshotBoundaryVerificationOutcome, SyncPhaseMeasurement) {
    let boundary = authority.headers.boundary();
    if boundary.tip_header.height != authority.snapshot.boundary.height
        || boundary.tip_hash != authority.snapshot.boundary.hash
    {
        return (
            SnapshotBoundaryVerificationOutcome::Fatal {
                error: "validated snapshot headers no longer match their immutable SnapshotId"
                    .to_owned(),
                authority: Some(authority),
            },
            SyncPhaseMeasurement::new(
                SyncPhase::HistoryStepTerminal,
                0,
                0,
                std::time::Duration::ZERO,
                false,
            ),
        );
    }

    let terminal_len = terminal_bytes.len() as u64;
    let terminal_started = Instant::now();
    let terminal_result = {
        let ctx = chain.blocking_read();
        ctx.verify_snapshot_boundary(
            boundary.tip_header,
            boundary.epoch_anchor_header,
            terminal_bytes,
            |claim| verify_history_step_terminal(claim, Some(runtime)),
        )
    };
    let measurement = SyncPhaseMeasurement::new(
        SyncPhase::HistoryStepTerminal,
        1,
        terminal_len,
        terminal_started.elapsed(),
        terminal_result.is_ok(),
    );
    let outcome = match terminal_result {
        Ok(verified_boundary) => {
            SnapshotBoundaryVerificationOutcome::Accepted(VerifiedHistoryStepSnapshot {
                height: authority.snapshot.boundary.height,
                block_hash: authority.snapshot.boundary.hash,
                boundary: verified_boundary,
                headers: authority.headers,
                allow_nonfinal_rebase: authority.allow_nonfinal_rebase,
                inbound_memory_permit,
            })
        }
        Err(error) => {
            let message = format!("verify snapshot HistoryStep boundary: {error}");
            if history_step_context_error_is_terminal_peer_fault(&error) {
                SnapshotBoundaryVerificationOutcome::TerminalRejected {
                    error: message,
                    authority,
                }
            } else {
                SnapshotBoundaryVerificationOutcome::Fatal {
                    error: message,
                    authority: Some(authority),
                }
            }
        }
    };
    (outcome, measurement)
}

#[derive(Debug)]
struct AppliedVerifiedSnapshot {
    height: u64,
    block_hash: [u8; 32],
    tail_blocks: u64,
    tail_bytes: u64,
    tail_apply_elapsed: std::time::Duration,
    state_install_elapsed: std::time::Duration,
}

#[derive(Debug)]
enum SnapshotInstallError {
    /// The canonical chain advanced to or beyond this exact snapshot while
    /// its already-verified State was waiting for the sole chain writer.
    /// This is a successful competing sync path, not corruption.
    Superseded {
        snapshot_height: u64,
        local_height: u64,
        local_hash: [u8; 32],
    },
    BeforeCommit(String),
    AfterCommit {
        applied: AppliedVerifiedSnapshot,
        error: String,
        terminal_rejected: bool,
    },
}

fn superseded_snapshot_install(
    snapshot_height: u64,
    local_height: u64,
    local_hash: [u8; 32],
) -> Option<SnapshotInstallError> {
    (snapshot_height <= local_height).then_some(SnapshotInstallError::Superseded {
        snapshot_height,
        local_height,
        local_hash,
    })
}

impl std::fmt::Display for SnapshotInstallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Superseded {
                snapshot_height,
                local_height,
                ..
            } => write!(
                formatter,
                "snapshot boundary {snapshot_height} was superseded by canonical height {local_height}"
            ),
            Self::BeforeCommit(error) | Self::AfterCommit { error, .. } => {
                formatter.write_str(error)
            }
        }
    }
}

fn validate_snapshot_staged_header_boundary(
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
    boundary: &SnapshotHeaderBoundary,
) -> Result<(), String> {
    if manifest.tip_height == 0 {
        return Err("snapshot manifest has no tip".into());
    }
    if !manifest.has_valid_manifest_digest() {
        return Err("snapshot manifest generation digest is invalid".into());
    }
    if boundary.tip_header.height != manifest.tip_height || boundary.tip_hash != manifest.tip_hash {
        return Err("snapshot manifest boundary does not match staged header tip".into());
    }
    if boundary.tip_header.log_slots != manifest.log_slots {
        return Err("snapshot manifest log_slots does not match staged header".into());
    }
    if boundary.tip_header.state_root != manifest.state_root {
        return Err("snapshot manifest State root does not match staged header".into());
    }
    if boundary.tip_header.active_slot_count != manifest.active_slot_count {
        return Err("snapshot manifest active_slot_count does not match staged header".into());
    }
    if boundary.tip_header.alloc_counter != manifest.alloc_counter {
        return Err("snapshot manifest alloc_counter does not match staged header".into());
    }
    if boundary.cumulative_chainwork != manifest.cumulative_chainwork {
        return Err("snapshot manifest chainwork does not match staged headers".into());
    }
    let bridge_span = manifest
        .bridge_tip_height
        .checked_sub(manifest.tip_height)
        .ok_or_else(|| "snapshot bridge precedes its boundary".to_string())?;
    if bridge_span > noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH {
        return Err("snapshot bridge exceeds retained suffix depth".into());
    }
    if bridge_span == 0 {
        if manifest.bridge_tip_hash != manifest.tip_hash
            || manifest.bridge_cumulative_chainwork != manifest.cumulative_chainwork
        {
            return Err("empty snapshot bridge differs from its boundary".into());
        }
    } else if !noid_chain::work_gt(
        &manifest.bridge_cumulative_chainwork,
        &manifest.cumulative_chainwork,
    ) {
        return Err("snapshot bridge does not advance cumulative chainwork".into());
    }
    // A boundary block still consumes the preceding transaction-epoch
    // anchor; its own header becomes active only for the following child.
    let expected_epoch_height =
        noid_chain::consensus::tx_epoch_anchor_height_for_child(manifest.tip_height);
    if boundary.epoch_anchor_header.height != expected_epoch_height {
        return Err("snapshot staged transaction-epoch anchor has wrong height".into());
    }
    Ok(())
}

/// Verify the fused HistoryStep terminal for the exact uncommitted block.
fn verify_history_step_terminal(
    claim: &noid_chain::storage::HistoryStepTerminalClaim<'_>,
    runtime: Option<&noid_recursive::acceptance::history_step::HistoryStepRuntime>,
) -> Result<(), String> {
    let Some(runtime) = runtime else {
        return Err("embedded HistoryStep verifier unavailable".to_string());
    };
    noid_miner::install_inbound_verifier_cpu(|| {
        noid_recursive::acceptance::history_step::decode_verify_history_step_terminal(
            runtime,
            claim.terminal_bytes,
            &claim.header,
            &claim.epoch_anchor_header,
        )
    })
    .map_err(|error| format!("HistoryStep verification CPU admission failed: {error}"))?
    .map(|_| ())
    .map_err(|error| format!("HistoryStep terminal rejected: {error}"))
}

fn history_step_context_error_is_terminal_peer_fault(
    error: &noid_chain::storage::MdbxContextError,
) -> bool {
    match error {
        noid_chain::storage::MdbxContextError::Consensus(
            noid_chain::consensus::ConsensusError::BadHistoryStepTerminal(message),
        ) => {
            message.contains("terminal exceeds the wire cap")
                || message.contains("terminal metadata is invalid")
                || message.contains("terminal does not bind")
                || message.contains("HistoryStep terminal rejected:")
        }
        _ => false,
    }
}

fn exact_suffix_context_error_is_body_peer_fault(
    error: &noid_chain::storage::MdbxContextError,
) -> bool {
    match error {
        // The headers and terminal have already been independently admitted.
        // A consensus failure while materializing the exact body therefore
        // belongs to that body, not to transport or local storage.
        noid_chain::storage::MdbxContextError::Consensus(_) => true,
        noid_chain::storage::MdbxContextError::Corrupt(message) => matches!(
            *message,
            "recursive suffix block body is malformed"
                | "recursive suffix block has invalid logical transactions"
                | "recursive reorg body is malformed"
                | "recursive reorg tip body is malformed"
        ),
        noid_chain::storage::MdbxContextError::Store(_)
        | noid_chain::storage::MdbxContextError::ResourceLimit { .. } => false,
    }
}

fn quarantine_exact_suffix_sources(
    header_dag: &mut noid_node::networking::header_dag::HeaderDag,
    rejected: &mut std::collections::HashSet<libp2p::PeerId>,
    sources: &[libp2p::PeerId],
) -> usize {
    let mut newly_rejected = 0usize;
    for source in sources {
        header_dag.remove_inventory_provider(*source);
        if rejected.insert(*source) {
            newly_rejected = newly_rejected.saturating_add(1);
        }
    }
    newly_rejected
}

/// Local time admission is checked at the last fixed-width
/// boundary before expensive terminal verification.  Historical header
/// validation is timeless, but a snapshot must not make a locally
/// far-future tip authoritative merely because its recursive proof is valid.
fn validate_history_step_tip_future_drift(
    boundary: &SnapshotHeaderBoundary,
    local_time: u64,
) -> Result<(), String> {
    noid_chain::consensus::validate_future_drift(boundary.tip_header.timestamp, local_time)
        .map_err(|error| format!("HistoryStep target tip exceeds local future drift: {error}"))
}

// ---------------------------------------------------------------------------
// Blocking-I/O helpers
// ---------------------------------------------------------------------------

/// Apply an exact-object v3 suffix. The selected peer is deliberately absent:
/// source identities have no authority after the bytes satisfy the immutable
/// plan. Forward catch-up commits native-validated blocks in order; a reorg
/// uses the all-or-nothing one-terminal replacement transaction.
#[allow(clippy::too_many_arguments)]
async fn apply_exact_suffix_offthread(
    chain: &Arc<RwLock<MdbxChainContext>>,
    mempool: &AsyncMempool,
    wallet: &SharedWallet,
    fetched: noid_node::networking::suffix_sync::FetchedSuffix,
    history_step_runtime: Option<Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>>,
    wallet_operation_gate: &WalletOperationGate,
) -> Result<AppliedExactSuffix, ExactSuffixApplyError> {
    use noid_node::networking::sync_plan::SyncPlanKind;

    let _wallet_operation = wallet_operation_gate.lock().await;
    let (reserved_input_slots, reserved_output_slots) = mempool.reserved_slots().await;
    let apply_chain = Arc::clone(chain);
    let apply_store = {
        let ctx = chain.read().await;
        ctx.store.clone()
    };
    let apply_wallet = Arc::clone(wallet);
    let result = tokio::task::spawn_blocking(move || {
        let (
            plan,
            body_bytes,
            body_sources,
            terminal_bytes,
            terminal_source,
            inbound_permits,
        ) = fetched.into_parts();
        let _inbound_permits = inbound_permits;
        if body_bytes.len() != plan.headers().len()
            || body_sources.len() != body_bytes.len()
            || body_bytes.is_empty()
        {
            return Err(ExactSuffixApplyError::Other(
                "exact suffix body/source count differs from its immutable plan".into(),
            ));
        }
        let mut blocks = Vec::with_capacity(body_bytes.len());
        for ((bytes, source), expected) in body_bytes
            .iter()
            .zip(&body_sources)
            .zip(plan.headers())
        {
            let block = noid_chain::Block::from_bytes(bytes).map_err(|error| {
                ExactSuffixApplyError::body(
                    *source,
                    format!("decode exact suffix body: {error:?}"),
                )
            })?;
            if block.header != expected.header {
                return Err(ExactSuffixApplyError::body(
                    *source,
                    "exact suffix body header differs from its validated header",
                ));
            }
            blocks.push(block);
        }
        let tip_header = blocks
            .last()
            .expect("non-empty exact suffix checked above")
            .header;
        if noid_chain::block_id(&tip_header) != plan.target().hash {
            return Err(ExactSuffixApplyError::body(
                *body_sources
                    .last()
                    .expect("non-empty body sources checked above"),
                "exact suffix bodies do not end at the selected target",
            ));
        }

        let epoch_height =
            noid_chain::consensus::tx_epoch_anchor_height_for_child(tip_header.height);
        let epoch_anchor_header = if epoch_height <= plan.base().height {
            apply_store
                .get_header(epoch_height)
                .map_err(|error| {
                    ExactSuffixApplyError::Other(format!(
                        "load exact suffix epoch anchor: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    ExactSuffixApplyError::Other(
                        "exact suffix epoch anchor is missing from canonical storage".into(),
                    )
                })?
        } else {
            blocks
                .iter()
                .find(|block| block.header.height == epoch_height)
                .map(|block| block.header)
                .ok_or_else(|| {
                    ExactSuffixApplyError::Other(
                        "exact suffix epoch anchor is missing from candidate bodies".into(),
                    )
                })?
        };

        // Recursive verification is the expensive part of admission. It runs
        // before the sole chain writer is acquired. The resulting non-cloneable
        // capability still has to pass exact base/finality checks after the
        // lock is acquired and cannot mutate storage by itself.
        let terminal_started = Instant::now();
        let verified_terminal = noid_chain::storage::verify_history_step_terminal_candidate(
            tip_header,
            epoch_anchor_header,
            terminal_bytes,
            |claim| verify_history_step_terminal(claim, history_step_runtime.as_deref()),
        )
        .map_err(|error| {
            let message = format!("verify exact suffix terminal: {error}");
            if history_step_context_error_is_terminal_peer_fault(&error) {
                ExactSuffixApplyError::terminal(terminal_source, message)
            } else {
                ExactSuffixApplyError::Other(message)
            }
        })?;
        tracing::info!(
            height = tip_header.height,
            elapsed_ms = terminal_started.elapsed().as_millis(),
            "exact suffix terminal verified outside the chain writer"
        );

        let writer_wait_started = Instant::now();
        let mut ctx = apply_chain.blocking_write();
        let writer_wait = writer_wait_started.elapsed();
        if writer_wait >= Duration::from_secs(2) {
            tracing::warn!(
                target_height = plan.target().height,
                wait_ms = writer_wait.as_millis(),
                "exact suffix waited for the chain writer"
            );
        }

        match plan.kind() {
            SyncPlanKind::LiveSuffix => {
                if ctx.tip_height() != plan.base().height || ctx.tip_hash() != plan.base().hash {
                    return Err(ExactSuffixApplyError::Other(
                        "exact live suffix base changed before commit".into(),
                    ));
                }
                let mut authority = ctx
                    .begin_preverified_recursive_suffix(verified_terminal)
                    .map_err(|error| {
                        let message = format!("authorize exact live suffix terminal: {error}");
                        if history_step_context_error_is_terminal_peer_fault(&error) {
                            ExactSuffixApplyError::terminal(terminal_source, message)
                        } else {
                            ExactSuffixApplyError::Other(message)
                        }
                    })?;
                let started = Instant::now();
                let payload_bytes = body_bytes
                    .iter()
                    .fold(0u64, |total, bytes| total.saturating_add(bytes.len() as u64));
                let mut confirmed_tx_hashes = Vec::new();
                let mut applied_blocks = 0u64;
                let mut trailing_error = None;
                for ((block, bytes), source) in
                    blocks.iter().zip(&body_bytes).zip(&body_sources)
                {
                    let txids = match noid_chain::try_compute_logical_txids(&block.transactions) {
                        Ok(txids) => txids,
                        Err(error) => {
                            trailing_error = Some(ExactSuffixApplyError::body(
                                *source,
                                format!("exact suffix logical transaction stream: {error}"),
                            ));
                            break;
                        }
                    };
                    if let Err(error) = ctx.apply_verified_recursive_suffix_block(
                        &mut authority,
                        bytes,
                        unix_now(),
                        |block, state| {
                            noid_chain::materialize_accepted_block_state(state, block)
                                .map_err(|error| format!("{error:?}"))
                        },
                    ) {
                        let message = format!(
                            "apply exact suffix block {}: {error}",
                            block.header.height
                        );
                        trailing_error = Some(if exact_suffix_context_error_is_body_peer_fault(
                            &error,
                        ) {
                            ExactSuffixApplyError::body(*source, message)
                        } else {
                            ExactSuffixApplyError::Other(message)
                        });
                        break;
                    }
                    update_wallet_for_block(&apply_wallet, block);
                    confirmed_tx_hashes.extend(txids);
                    applied_blocks = applied_blocks.saturating_add(1);
                }
                if trailing_error.is_none() && !authority.is_complete() {
                    trailing_error = Some(ExactSuffixApplyError::Other(
                        "exact suffix ended before its verified tip".into(),
                    ));
                }
                let view = ChainView::from_mdbx(&ctx);
                Ok(AppliedExactSuffix::Live(AppliedCompactSuffix {
                    height: ctx.tip_height(),
                    block_hash: ctx.tip_hash(),
                    confirmed_tx_hashes,
                    view,
                    applied_blocks,
                    payload_bytes,
                    apply_elapsed: started.elapsed(),
                    trailing_error,
                }))
            }
            SyncPlanKind::Reorg => {
                let authority = ctx
                    .authorize_preverified_reorg_suffix(plan.base().height, verified_terminal)
                    .map_err(|error| {
                        let message = format!("authorize exact reorg terminal: {error}");
                        if history_step_context_error_is_terminal_peer_fault(&error) {
                            ExactSuffixApplyError::terminal(terminal_source, message)
                        } else {
                            ExactSuffixApplyError::Other(message)
                        }
                    })?;
                let reorg = ctx
                    .apply_verified_reorg_suffix_with_applier_indexed(
                        authority,
                        &body_bytes,
                        unix_now(),
                        |block, state| {
                            noid_chain::materialize_accepted_block_state(state, block)
                                .map_err(|error| format!("{error:?}"))
                        },
                    )
                    .map_err(|failure| {
                        let message =
                            format!("apply atomic exact reorg suffix: {}", failure.error);
                        match failure.body_index {
                            Some(index)
                                if exact_suffix_context_error_is_body_peer_fault(
                                    &failure.error,
                                ) => match body_sources.get(index).copied() {
                                Some(source) => ExactSuffixApplyError::body(source, message),
                                None => ExactSuffixApplyError::Other(message),
                            },
                            _ => ExactSuffixApplyError::Other(message),
                        }
                    })?;

                let selection = match apply_wallet.lock() {
                    Ok(guard) => guard.as_ref().map(|wallet| {
                        (
                            wallet.active_index,
                            wallet.next_index,
                            wallet.active_address().0,
                        )
                    }),
                    Err(_) => {
                        tracing::error!("wallet state lock poisoned after exact reorg");
                        None
                    }
                };
                if let Some((active_index, next_index, owner)) = selection {
                    match ctx.store.get_verified_utxos_by_owner(&owner) {
                        Ok(snapshot) => {
                            let block_refs = blocks.iter().collect::<Vec<_>>();
                            if let Err(error) = wallet::install_reorg_snapshot_and_artifacts(
                                &apply_wallet,
                                active_index,
                                next_index,
                                owner,
                                snapshot,
                                &reserved_input_slots,
                                &reserved_output_slots,
                                &reorg.reclaimed_tx_hashes,
                                &block_refs,
                            ) {
                                tracing::error!(%error, "post-exact-reorg wallet snapshot install failed");
                                wallet::invalidate_active_cache(&apply_wallet);
                            }
                        }
                        Err(error) => {
                            tracing::error!(%error, "post-exact-reorg owner lookup failed");
                            wallet::invalidate_active_cache(&apply_wallet);
                        }
                    }
                }
                let confirmed_tx_hashes = blocks
                    .iter()
                    .flat_map(|block| {
                        noid_chain::try_compute_logical_txids(&block.transactions)
                            .expect("committed exact reorg blocks have canonical transactions")
                    })
                    .collect();
                let view = ChainView::from_mdbx(&ctx);
                Ok(AppliedExactSuffix::Reorg(AppliedReorg {
                    result: reorg,
                    confirmed_tx_hashes,
                    view,
                }))
            }
            SyncPlanKind::Snapshot => Err(ExactSuffixApplyError::Other(
                "snapshot plan reached the live suffix committer".into(),
            )),
        }
    })
    .await
    .map_err(|error| ExactSuffixApplyError::Other(format!("exact suffix worker panicked: {error}")))??;

    match &result {
        AppliedExactSuffix::Live(applied) if applied.applied_blocks != 0 => {
            mempool
                .on_new_block(
                    &applied.confirmed_tx_hashes,
                    applied.height,
                    applied.view.clone(),
                )
                .await;
        }
        AppliedExactSuffix::Reorg(applied) => {
            mempool
                .on_new_block(
                    &applied.confirmed_tx_hashes,
                    applied.view.tip_height,
                    applied.view.clone(),
                )
                .await;
            mempool
                .readmit_after_reorg(applied.result.reclaimed_tx_hashes.clone())
                .await;
        }
        AppliedExactSuffix::Live(_) => {}
    }
    Ok(result)
}

enum HeaderInventoryPlan {
    Confirmed {
        tip: noid_node::networking::ChainPoint,
    },
    Behind,
    NeedOlder {
        start_height: u64,
        count: u16,
    },
    Candidate {
        headers: Vec<noid_node::networking::header_dag::ValidatedHeader>,
        records: Vec<noid_p2p::header_protocol::HeaderInventoryRecord>,
        old_tip: noid_node::networking::ChainPoint,
        target: noid_node::networking::ChainPoint,
    },
    FinalizedDivergence,
}

const HEADER_DAG_MAX_NODES: usize = 1024;
// Direct responses include their known anchor, so each branch contributes at
// most `DIRECT_SYNC_HEADER_REQUEST_CAP - 1` new nodes. Keep room for two
// independently validated branches. Bulk snapshot headers bypass HeaderDAG
// and are streamed into bounded disk staging instead.
const _: () = assert!(DIRECT_SYNC_HEADER_REQUEST_CAP as usize * 2 <= HEADER_DAG_MAX_NODES);

/// Reconstruct the bounded control-plane DAG from the durable canonical
/// non-final window. This is used at startup and after an atomic snapshot
/// jump; ordinary header arrivals update the DAG incrementally.
fn canonical_header_dag(
    context: &MdbxChainContext,
) -> Result<noid_node::networking::header_dag::HeaderDag, String> {
    use noid_node::networking::{header_dag::ValidatedHeader, ChainPoint};

    let finalized = context.finalized_checkpoint();
    let finalized_work = context
        .store
        .get_chain_work(finalized.height)
        .map_err(|error| format!("load finalized header DAG work: {error}"))?
        .ok_or_else(|| "finalized header DAG work is missing".to_owned())?;
    let mut dag = noid_node::networking::header_dag::HeaderDag::new(
        ChainPoint::new(finalized.height, finalized.hash),
        finalized_work,
        HEADER_DAG_MAX_NODES,
    );
    for height in finalized.height.saturating_add(1)..=context.tip_height() {
        let header = context
            .get_header_from_store(height)
            .map_err(|error| format!("load canonical header DAG row {height}: {error}"))?
            .ok_or_else(|| format!("canonical header DAG row {height} is missing"))?;
        let cumulative_work = context
            .store
            .get_chain_work(height)
            .map_err(|error| format!("load canonical header DAG work {height}: {error}"))?
            .ok_or_else(|| format!("canonical header DAG work {height} is missing"))?;
        dag.insert(ValidatedHeader::new_after_consensus_checks(
            header,
            cumulative_work,
        ))
        .map_err(|error| format!("rebuild canonical header DAG at {height}: {error}"))?;
    }
    Ok(dag)
}

/// Reconcile a durable canonical commit without discarding validated competing
/// branches. Only a large finalized snapshot jump reconstructs the DAG; every
/// ordinary child and non-final reorganization advances/prunes it in place.
fn reconcile_canonical_header_dag(
    context: &MdbxChainContext,
    dag: &mut noid_node::networking::header_dag::HeaderDag,
) -> Result<(), String> {
    use noid_node::networking::{header_dag::ValidatedHeader, ChainPoint};

    let finalized = context.finalized_checkpoint();
    let finalized_point = ChainPoint::new(finalized.height, finalized.hash);
    if finalized.height < dag.finalized().height
        || (finalized.height == dag.finalized().height && finalized_point != dag.finalized())
    {
        return Err("durable finalized checkpoint conflicts with HeaderDAG authority".into());
    }

    const MAX_INCREMENTAL_FINALITY_ADVANCE: u64 = 64;
    if finalized.height.saturating_sub(dag.finalized().height) > MAX_INCREMENTAL_FINALITY_ADVANCE {
        *dag = canonical_header_dag(context)?;
        return Ok(());
    }

    for height in dag.finalized().height.saturating_add(1)..=context.tip_height() {
        let header = context
            .get_header_from_store(height)
            .map_err(|error| format!("load canonical HeaderDAG row {height}: {error}"))?
            .ok_or_else(|| format!("canonical HeaderDAG row {height} is missing"))?;
        let hash = noid_chain::block_header::block_id(&header);
        if dag.get(&hash).is_some() {
            continue;
        }
        let cumulative_work = context
            .store
            .get_chain_work(height)
            .map_err(|error| format!("load canonical HeaderDAG work {height}: {error}"))?
            .ok_or_else(|| format!("canonical HeaderDAG work {height} is missing"))?;
        dag.insert(ValidatedHeader::new_after_consensus_checks(
            header,
            cumulative_work,
        ))
        .map_err(|error| format!("advance canonical HeaderDAG at {height}: {error}"))?;
    }

    let finalized_work = context
        .store
        .get_chain_work(finalized.height)
        .map_err(|error| format!("load advanced finalized HeaderDAG work: {error}"))?
        .ok_or_else(|| "advanced finalized HeaderDAG work is missing".to_owned())?;
    dag.advance_finalized(finalized_point, finalized_work)
        .map_err(|error| format!("advance finalized HeaderDAG checkpoint: {error}"))
}

fn record_validated_headers(
    dag: &mut noid_node::networking::header_dag::HeaderDag,
    headers: &[noid_node::networking::header_dag::ValidatedHeader],
) -> Result<(), noid_node::networking::header_dag::HeaderDagError> {
    for header in headers {
        dag.insert(*header)?;
    }
    Ok(())
}

/// A provider response may repeat headers which already entered HeaderDAG
/// through an earlier header-only announcement. Preserve its exact object
/// inventory even when the control-plane planner consequently classifies the
/// batch as already known/behind. Unknown headers still require the native
/// validation path before they may receive any availability hints.
fn advertise_inventory_for_known_headers(
    dag: &mut noid_node::networking::header_dag::HeaderDag,
    peer: libp2p::PeerId,
    records: &[noid_p2p::header_protocol::HeaderInventoryRecord],
) -> Result<usize, noid_node::networking::header_dag::HeaderDagError> {
    let known_inventory = records
        .iter()
        .filter(|record| record.body.is_some() || record.terminal.is_some())
        .filter(|record| {
            let hash = noid_chain::block_id(&record.header);
            dag.get(&hash)
                .is_some_and(|known| known.header == record.header)
        })
        .copied()
        .collect::<Vec<_>>();
    if known_inventory.is_empty() {
        return Ok(0);
    }
    dag.advertise_inventory(peer, &known_inventory)
}

fn header_inventory_validation_anchor(
    canonical: Option<noid_node::networking::ChainPoint>,
    validated_dag: Option<noid_node::networking::ChainPoint>,
) -> Option<noid_node::networking::ChainPoint> {
    // If the response includes a canonical point, replay the bounded branch
    // from that point even when every later header is already present in the
    // DAG. This turns a later exact-inventory response into a fresh data plan
    // instead of incorrectly classifying it as Behind. A DAG-only anchor is
    // still required for a continuation whose canonical base is outside the
    // bounded response.
    canonical.or(validated_dag)
}

fn header_dag_has_unresolved_better_tip(
    dag: &noid_node::networking::header_dag::HeaderDag,
    canonical_tip: noid_node::networking::ChainPoint,
    canonical_work: [u8; 32],
) -> bool {
    let best = dag.best_tip();
    best != canonical_tip
        && matches!(
            noid_chain::choose_chain_by_work(
                &dag.best_work(),
                &best.hash,
                &canonical_work,
                &canonical_tip.hash,
            ),
            noid_chain::consensus::fork_choice::ChainChoice::A
        )
}

/// Turn one bounded v3 inventory into a source-independent suffix plan. All
/// native header checks and cumulative-work comparison happen before any body
/// request is scheduled.
async fn plan_header_inventory(
    chain: &Arc<RwLock<MdbxChainContext>>,
    store: &MdbxStore,
    header_dag: &noid_node::networking::header_dag::HeaderDag,
    records: Vec<noid_p2p::header_protocol::HeaderInventoryRecord>,
) -> Result<HeaderInventoryPlan, String> {
    use noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH;
    use noid_node::networking::{header_dag::ValidatedHeader, ChainPoint};

    let (our_tip, our_tip_hash, canonical_ancestors) = {
        let ctx = chain.read().await;
        let our_tip = ctx.tip_height();
        let ancestors = records
            .iter()
            .filter_map(|record| {
                let hash = noid_chain::block_id(&record.header);
                ctx.find_ancestor_height(&hash).map(|height| (height, hash))
            })
            .collect::<Vec<_>>();
        (our_tip, ctx.tip_hash(), ancestors)
    };
    let old_tip = ChainPoint::new(our_tip, our_tip_hash);
    if records.is_empty() {
        return Ok(nonfinal_header_discovery_range(our_tip).map_or(
            HeaderInventoryPlan::Behind,
            |(start_height, count)| HeaderInventoryPlan::NeedOlder {
                start_height,
                count,
            },
        ));
    }
    // A continuation may be anchored at an already native-validated DAG
    // parent which has not yet been committed. Canonical MDBX is therefore
    // not the only valid control-plane anchor.
    let dag_ancestors = records.iter().filter_map(|record| {
        let hash = noid_chain::block_id(&record.header);
        let point = ChainPoint::new(record.header.height, hash);
        if point == header_dag.finalized() {
            return Some(point);
        }
        header_dag
            .get(&hash)
            .filter(|known| known.header == record.header)
            .map(ValidatedHeader::point)
    });
    let canonical_ancestor = canonical_ancestors
        .into_iter()
        .map(|(height, hash)| ChainPoint::new(height, hash))
        .filter(|point| point.height >= header_dag.finalized().height)
        .max_by_key(|point| point.height);
    let dag_ancestor = dag_ancestors.max_by_key(|point| point.height);
    let ancestor = header_inventory_validation_anchor(canonical_ancestor, dag_ancestor);

    let Some(ancestor) = ancestor else {
        let oldest = records.first().map_or(0, |record| record.header.height);
        if header_batch_exhausts_nonfinal_window(our_tip, oldest) {
            return Ok(HeaderInventoryPlan::FinalizedDivergence);
        }
        return Ok(HeaderInventoryPlan::NeedOlder {
            start_height: finalized_header_search_floor(our_tip),
            count: (CONSENSUS_FINALITY_DEPTH as u16 * 2).min(512),
        });
    };
    if ancestor.height < header_dag.finalized().height {
        return Ok(HeaderInventoryPlan::FinalizedDivergence);
    }
    let ancestor_height = ancestor.height;
    let ancestor_hash = ancestor.hash;

    let competing_records = records
        .into_iter()
        .filter(|record| record.header.height > ancestor_height)
        .collect::<Vec<_>>();
    if competing_records.is_empty() {
        return Ok(
            if ancestor_height == our_tip && ancestor_hash == our_tip_hash {
                HeaderInventoryPlan::Confirmed { tip: old_tip }
            } else {
                HeaderInventoryPlan::Behind
            },
        );
    }
    let competing_headers = competing_records
        .iter()
        .map(|record| record.header)
        .collect::<Vec<_>>();
    let validation_store = store.clone();
    let mut validation_headers = if ancestor == header_dag.finalized() {
        Vec::new()
    } else {
        header_dag
            .path_from(header_dag.finalized(), ancestor)
            .map_err(|error| format!("load header DAG validation ancestry: {error}"))?
            .into_iter()
            .map(|header| header.header)
            .collect::<Vec<_>>()
    };
    validation_headers.extend_from_slice(&competing_headers);
    let validation_base_height = header_dag.finalized().height;
    let target_work = tokio::task::spawn_blocking(move || {
        validate_bounded_header_extension(
            &validation_store,
            validation_base_height,
            &validation_headers,
            unix_now(),
        )
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("header validation worker failed: {error}"))??;

    let mut cumulative_work = header_dag
        .cumulative_work(ancestor)
        .map_err(|error| format!("load header-plan ancestor work: {error}"))?;
    let mut validated = Vec::with_capacity(competing_headers.len());
    for header in competing_headers {
        cumulative_work = noid_chain::add_work(
            &cumulative_work,
            &noid_chain::block_work(&header.difficulty_target),
        );
        validated.push(ValidatedHeader::new_after_consensus_checks(
            header,
            cumulative_work,
        ));
    }
    if cumulative_work != target_work {
        return Err("header-plan chainwork disagrees with native validation".into());
    }
    let target = validated
        .last()
        .expect("non-empty competing header suffix")
        .point();
    Ok(HeaderInventoryPlan::Candidate {
        headers: validated,
        records: competing_records,
        old_tip,
        target,
    })
}

/// Build one immutable suffix plan from HeaderDAG authority while keeping
/// object availability attributed to the exact peers that advertised it.
/// The bootstrap offer contains only the selected tip terminal; body sources
/// are merged independently afterwards.
fn source_independent_suffix_offer(
    dag: &noid_node::networking::header_dag::HeaderDag,
    preferred_peer: libp2p::PeerId,
    old_tip: noid_node::networking::ChainPoint,
    base: noid_node::networking::ChainPoint,
    headers: Vec<noid_node::networking::header_dag::ValidatedHeader>,
) -> Result<
    (
        libp2p::PeerId,
        noid_node::networking::suffix_sync::SuffixOffer,
        Vec<(
            libp2p::PeerId,
            Vec<noid_p2p::header_protocol::HeaderInventoryRecord>,
        )>,
    ),
    noid_node::networking::suffix_sync::SuffixSyncError,
> {
    use noid_node::networking::suffix_sync::{SuffixOffer, SuffixSyncError};

    let target = headers.last().ok_or(SuffixSyncError::EmptySuffix)?.point();
    let (terminal_peer, terminal) = dag
        .terminal_provider(target, Some(preferred_peer))
        .ok_or(SuffixSyncError::MissingTipTerminal)?;
    let mut bootstrap = headers
        .iter()
        .map(|header| noid_p2p::header_protocol::HeaderInventoryRecord::header_only(header.header))
        .collect::<Vec<_>>();
    bootstrap
        .last_mut()
        .expect("non-empty suffix checked above")
        .terminal = Some(terminal);
    let offer = if base == old_tip {
        SuffixOffer::live(base, headers.clone(), &bootstrap)?
    } else {
        SuffixOffer::reorg(old_tip, base, headers.clone(), &bootstrap)?
    };
    let inventories = dag
        .inventory_providers(&headers)
        .into_iter()
        .map(|peer| (peer, dag.inventory_for_provider(peer, &headers)))
        .collect::<Vec<_>>();
    let every_body_has_a_source = headers.iter().enumerate().all(|(index, header)| {
        inventories.iter().any(|(_, records)| {
            records
                .get(index)
                .and_then(|record| record.body)
                .is_some_and(|body| {
                    body.claim.height == header.header.height
                        && body.claim.block_hash == header.hash
                })
        })
    });
    if !every_body_has_a_source {
        return Err(SuffixSyncError::MissingBodySource);
    }
    Ok((terminal_peer, offer, inventories))
}

fn dispatch_exact_suffix_requests(
    sync: &mut noid_node::networking::suffix_sync::SuffixSync,
    p2p_cmd: &noid_p2p::NetworkCommandSender,
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    for request in sync.schedule(now_ms) {
        if p2p_cmd
            .try_send(noid_p2p::NetworkCommand::FetchObjects {
                token: request.token,
                peer: request.peer,
                objects: request.objects.clone(),
            })
            .is_err()
        {
            let _ = sync.defer_request(request.token, request.peer, &request.objects);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SuffixAdmission {
    Started,
    Merged,
    Duplicate,
    DeferredExtension,
    Replaced,
    KeptStrongerActive,
}

fn suffix_admission_made_progress(admission: SuffixAdmission) -> bool {
    matches!(
        admission,
        SuffixAdmission::Started | SuffixAdmission::Merged | SuffixAdmission::Replaced
    )
}

/// Merge storage-backed object availability for the currently pinned suffix
/// even when the returned header range ends below HeaderDAG's newer selected
/// descendant. The headers are control-plane history in that case, but their
/// body/terminal inventory is still exactly the data plane needed to finish
/// the immutable plan.
fn merge_active_suffix_inventory(
    active: &mut Option<noid_node::networking::suffix_sync::SuffixSync>,
    peer: libp2p::PeerId,
    failure_domain: noid_node::networking::FailureDomain,
    records: &[noid_p2p::header_protocol::HeaderInventoryRecord],
) -> Result<usize, noid_node::networking::suffix_sync::SuffixSyncError> {
    let Some(sync) = active.as_mut() else {
        return Ok(0);
    };
    let headers = sync.plan().headers().to_vec();
    let base_height = sync.plan().base().height;
    let target_height = sync.plan().target().height;
    let matching = records
        .iter()
        .filter(|record| {
            record.header.height > base_height && record.header.height <= target_height
        })
        .cloned()
        .collect::<Vec<_>>();
    if matching.len() != headers.len()
        || matching
            .iter()
            .zip(&headers)
            .any(|(record, header)| record.header != header.header)
    {
        return Ok(0);
    }
    sync.add_inventory(peer, failure_domain, &headers, &matching)
}

fn admit_exact_suffix_offer(
    active: &mut Option<noid_node::networking::suffix_sync::SuffixSync>,
    peer: libp2p::PeerId,
    failure_domain: noid_node::networking::FailureDomain,
    offer: noid_node::networking::suffix_sync::SuffixOffer,
) -> Result<SuffixAdmission, String> {
    use noid_chain::consensus::fork_choice::ChainChoice;
    use noid_node::networking::suffix_sync::SuffixSync;

    let Some(current) = active.as_mut() else {
        *active = Some(
            SuffixSync::from_offer(peer, failure_domain, offer)
                .map_err(|error| error.to_string())?,
        );
        return Ok(SuffixAdmission::Started);
    };
    if current.plan_id() == offer.plan().id() {
        let added = current
            .add_offer(peer, failure_domain, offer)
            .map_err(|error| error.to_string())?;
        return Ok(if added > 0 {
            SuffixAdmission::Merged
        } else {
            SuffixAdmission::Duplicate
        });
    }

    // A later header on the already selected ancestry may replace a plan which
    // has not authenticated any object yet. This coalesces concurrent bounded
    // HeaderDAG probes without discarding verified bytes. Once object progress
    // exists, complete the immutable target first. A genuinely different
    // winning branch is still allowed to supersede the plan below.
    if offer.plan().target() != current.plan().target()
        && offer.plan().contains_point(current.plan().target())
    {
        if current.has_verified_objects() {
            return Ok(SuffixAdmission::DeferredExtension);
        }
        *active = Some(
            SuffixSync::from_offer(peer, failure_domain, offer)
                .map_err(|error| error.to_string())?,
        );
        return Ok(SuffixAdmission::Replaced);
    }

    let candidate_work = offer
        .plan()
        .target_work()
        .ok_or_else(|| "live suffix offer has no cumulative work".to_owned())?;
    let current_work = current
        .plan()
        .target_work()
        .ok_or_else(|| "active live suffix plan has no cumulative work".to_owned())?;
    if !matches!(
        noid_chain::choose_chain_by_work(
            &candidate_work,
            &offer.plan().target().hash,
            &current_work,
            &current.plan().target().hash,
        ),
        ChainChoice::A
    ) {
        return Ok(SuffixAdmission::KeptStrongerActive);
    }
    *active = Some(
        SuffixSync::from_offer(peer, failure_domain, offer).map_err(|error| error.to_string())?,
    );
    Ok(SuffixAdmission::Replaced)
}

#[cfg(test)]
mod tests {
    use super::{
        admit_exact_suffix_offer, advance_initial_sync_stage,
        advertise_inventory_for_known_headers, advertised_terminal_alternate_peer,
        advertised_terminal_peer, canonical_tip_supersedes_snapshot_boundary,
        classify_snapshot_finalization_error, classify_snapshot_session_prepare_error,
        competing_suffix_wins, direct_header_request_within_cap, distinct_rpc_keys,
        embedded_seed_multiaddrs, ensure_network_storage_epoch, gap_requires_snapshot_sync,
        header_batch_exhausts_nonfinal_window, header_inventory_validation_anchor,
        initial_sync_may_skip_peer_confirmation, is_single_header_inventory_for_point,
        load_or_create_config,
        manifest_candidate_selection_due, manifest_round_gap_is_resolved, manifest_round_retry_due,
        mark_initial_sync_ready, merge_active_suffix_inventory, mining_quorum_probe_due,
        network_storage_epoch_is_current, nonfinal_header_discovery_range, p2p_listen_to_multiaddr,
        peer_connect_bootstrap_policy, persist_network_storage_epoch_marker,
        prune_superseded_snapshot_header_staging, quarantine_exact_suffix_sources,
        read_rpc_key_file, record_snapshot_terminal_transport_failure,
        remember_terminal_capability, retained_terminal_capability,
        resolve_embedded_seed_with_system_dns, resolved_system_seed_addrs, rotating_manifest_peers,
        seed_to_multiaddr, selected_tip_probe_range, snapshot_header_completion_base_moved,
        snapshot_header_completion_rejects_candidate, snapshot_header_next_action,
        snapshot_rebase_discovery_range, snapshot_segment_failure_scope,
        source_independent_suffix_offer, stale_gap_recovery_is_due,
        state_manifest_candidate_is_preferred, steady_tip_probe_due, superseded_snapshot_install,
        sync_target_requires_snapshot, terminal_alternate_peer,
        terminal_transport_can_retry_same_peer, unforced_manifest_waits_for_header_dag,
        unresolved_selected_tip_probe_range, unresolved_tip_probe_range,
        validate_history_step_tip_future_drift, validate_rebase_snapshot_selection,
        validate_rpc_key, validate_rpc_listener_auth, validate_snapshot_header_batch_admission,
        validate_snapshot_install_selection, validate_snapshot_staged_header_boundary, Cli,
        ManifestTerminalCapability, MiningPeerQuorum, NodeConfig, NodeMode, PostSnapshotTail,
        SnapshotFinalizationOutcome, SnapshotHeaderBoundary, SnapshotHeaderNextAction,
        SnapshotHeaderPipeline, SnapshotHeaderStagingError, SnapshotRebaseAnchor,
        SnapshotRebaseHint, SnapshotSegmentFailureScope, SnapshotSessionPrepareError,
        SnapshotTerminalSourceKey, SuffixAdmission, TerminalRequestRace,
        CONNECTED_TIP_PROBE_HEADERS, DIRECT_SYNC_HEADER_REQUEST_CAP, HEADER_DAG_MAX_NODES,
        HISTORY_STEP_TERMINAL_HARD_DEADLINE, HISTORY_STEP_TERMINAL_HEDGE_AFTER,
        MAX_MEMPOOL_SYNC_PEERS, MAX_SYSTEM_ADDRS_PER_SEED, MINING_PEER_CONFIRMATION_TTL,
        MINING_PEER_QUORUM, MINING_QUORUM_PROBE_INTERVAL, SNAPSHOT_HEADER_BATCH,
        SNAPSHOT_HEADER_REQUEST_WINDOW, STATE_MANIFEST_CANDIDATE_SETTLE,
        STATE_MANIFEST_RESPONSE_TIMEOUT, STEADY_TIP_PROBE_INTERVAL,
    };
    use super::{complete_snapshot_provider_discovery_round, EXACT_PLAN_DISCOVERY_ROUNDS};
    use noid_rpc::types::NodeSyncStage;

    fn test_snapshot_id() -> noid_node::networking::SnapshotId {
        noid_node::networking::SnapshotId {
            boundary: noid_node::networking::ChainPoint::new(100, [1; 32]),
            state_root: [2; 32],
            manifest_digest: [3; 32],
            format_version: noid_p2p::protocol::SNAPSHOT_MANIFEST_FORMAT_VERSION,
        }
    }

    #[test]
    fn canonical_suffix_progress_supersedes_an_older_snapshot_install() {
        let local_hash = [9; 32];
        let Some(super::SnapshotInstallError::Superseded {
            snapshot_height,
            local_height,
            local_hash: observed_hash,
        }) = superseded_snapshot_install(54, 73, local_hash)
        else {
            panic!("older snapshot was not classified as superseded");
        };
        assert_eq!(snapshot_height, 54);
        assert_eq!(local_height, 73);
        assert_eq!(observed_hash, local_hash);
        assert!(superseded_snapshot_install(74, 73, local_hash).is_none());
    }

    #[test]
    fn exact_progress_retires_only_a_canonical_snapshot_boundary() {
        let snapshot = noid_node::networking::ChainPoint::new(54, [1; 32]);
        let competing = noid_node::networking::ChainPoint::new(54, [2; 32]);

        assert!(canonical_tip_supersedes_snapshot_boundary(
            73,
            Some(snapshot),
            snapshot,
        ));
        assert!(!canonical_tip_supersedes_snapshot_boundary(
            73,
            Some(competing),
            snapshot,
        ));
        assert!(!canonical_tip_supersedes_snapshot_boundary(
            53,
            Some(snapshot),
            snapshot,
        ));
        assert!(!canonical_tip_supersedes_snapshot_boundary(
            73, None, snapshot,
        ));
    }

    #[test]
    fn inbound_connection_herd_cannot_start_reciprocal_bootstrap_work() {
        for _ in 0..100 {
            assert_eq!(
                peer_connect_bootstrap_policy(false, false, 0),
                (false, false)
            );
            assert_eq!(
                peer_connect_bootstrap_policy(false, true, 0),
                (false, false)
            );
        }
    }

    #[test]
    fn outbound_mempool_bootstrap_is_bounded() {
        assert_eq!(peer_connect_bootstrap_policy(true, false, 0), (true, false));
        assert_eq!(peer_connect_bootstrap_policy(true, true, 3), (true, true));
        assert_eq!(
            peer_connect_bootstrap_policy(true, true, MAX_MEMPOOL_SYNC_PEERS),
            (true, false)
        );
    }

    fn test_exact_suffix_offer(
        nonces: &[u128],
        cumulative_work_bytes: &[u8],
    ) -> noid_node::networking::suffix_sync::SuffixOffer {
        use noid_chain::block_header::{block_id, semantic_header_id};
        use noid_node::networking::{header_dag::ValidatedHeader, ChainPoint};
        use noid_p2p::{
            header_protocol::HeaderInventoryRecord,
            object_protocol::{
                BlockBodyClaimId, BlockBodyObjectId, TerminalClaimId, TerminalObjectId,
            },
        };

        assert_eq!(nonces.len(), cumulative_work_bytes.len());
        let genesis = noid_chain::consensus::genesis_header();
        let base = ChainPoint::new(0, block_id(&genesis));
        let mut parent = genesis;
        let mut headers = Vec::with_capacity(nonces.len());
        let mut records = Vec::with_capacity(nonces.len());
        for (nonce, work_byte) in nonces.iter().zip(cumulative_work_bytes) {
            let mut header = parent;
            header.height = parent.height.saturating_add(1);
            header.prev_block_hash = block_id(&parent);
            header.timestamp = parent.timestamp.saturating_add(1);
            header.nonce = *nonce;
            let validated = ValidatedHeader::new_after_consensus_checks(header, [*work_byte; 32]);
            let body_claim = BlockBodyClaimId {
                height: header.height,
                block_hash: validated.hash,
            };
            records.push(HeaderInventoryRecord {
                header,
                body: Some(BlockBodyObjectId::from_bytes(body_claim, &[*work_byte]).unwrap()),
                terminal: None,
            });
            headers.push(validated);
            parent = header;
        }
        let tip = headers.last().expect("test suffix is non-empty");
        records.last_mut().unwrap().terminal = Some(
            TerminalObjectId::from_bytes(
                TerminalClaimId {
                    height: tip.header.height,
                    semantic_header_id: semantic_header_id(&tip.header),
                    proof_class: 0,
                },
                &[0xEE],
            )
            .unwrap(),
        );
        noid_node::networking::suffix_sync::SuffixOffer::live(base, headers, &records).unwrap()
    }

    #[test]
    fn dag_selected_suffix_merges_objects_from_independent_sources() {
        use noid_chain::block_header::{block_id, semantic_header_id};
        use noid_node::networking::{
            header_dag::{HeaderDag, ValidatedHeader},
            suffix_sync::SuffixSync,
            ChainPoint, FailureDomain,
        };
        use noid_p2p::{
            header_protocol::HeaderInventoryRecord,
            object_protocol::{
                BlockBodyClaimId, BlockBodyObjectId, ObjectId, TerminalClaimId, TerminalObjectId,
            },
        };

        let genesis = noid_chain::consensus::genesis_header();
        let base = ChainPoint::new(0, block_id(&genesis));
        let base_work = [0u8; 32];
        let mut first_header = genesis;
        first_header.height = 1;
        first_header.prev_block_hash = base.hash;
        first_header.timestamp = genesis.timestamp + 1;
        first_header.nonce = 1;
        let first_work = noid_chain::add_work(
            &base_work,
            &noid_chain::block_work(&first_header.difficulty_target),
        );
        let first = ValidatedHeader::new_after_consensus_checks(first_header, first_work);
        let mut second_header = first_header;
        second_header.height = 2;
        second_header.prev_block_hash = first.hash;
        second_header.timestamp += 1;
        second_header.nonce = 2;
        let second_work = noid_chain::add_work(
            &first_work,
            &noid_chain::block_work(&second_header.difficulty_target),
        );
        let second = ValidatedHeader::new_after_consensus_checks(second_header, second_work);

        let body_peer = libp2p::PeerId::random();
        let tip_peer = libp2p::PeerId::random();
        let first_body = BlockBodyObjectId {
            claim: BlockBodyClaimId {
                height: 1,
                block_hash: first.hash,
            },
            byte_digest: [1; 32],
            encoded_len: 1,
        };
        let second_body = BlockBodyObjectId {
            claim: BlockBodyClaimId {
                height: 2,
                block_hash: second.hash,
            },
            byte_digest: [2; 32],
            encoded_len: 1,
        };
        let terminal = TerminalObjectId {
            claim: TerminalClaimId {
                height: 2,
                semantic_header_id: semantic_header_id(&second_header),
                proof_class: 0,
            },
            byte_digest: [3; 32],
            encoded_len: 1,
        };

        let mut dag = HeaderDag::new(base, base_work, 16);
        dag.insert(first).unwrap();
        dag.insert(second).unwrap();
        dag.advertise_inventory(
            tip_peer,
            &[HeaderInventoryRecord {
                header: second_header,
                body: Some(second_body),
                terminal: Some(terminal),
            }],
        )
        .unwrap();

        let headers = vec![first, second];

        // The competing headers can arrive first through gossip/header-only
        // inventory. A later exact response for those already validated
        // headers must enrich the DAG even though header planning will call
        // the repeated batch Behind.
        assert_eq!(
            source_independent_suffix_offer(&dag, tip_peer, base, base, headers.clone())
                .unwrap_err(),
            noid_node::networking::suffix_sync::SuffixSyncError::MissingBodySource
        );
        assert_eq!(
            advertise_inventory_for_known_headers(
                &mut dag,
                body_peer,
                &[HeaderInventoryRecord {
                    header: first_header,
                    body: Some(first_body),
                    terminal: None,
                }],
            )
            .unwrap(),
            1
        );

        let (terminal_peer, offer, inventories) =
            source_independent_suffix_offer(&dag, body_peer, base, base, headers.clone()).unwrap();
        assert_eq!(terminal_peer, tip_peer);
        let mut sync = SuffixSync::from_offer(terminal_peer, FailureDomain(2), offer).unwrap();
        for (peer, inventory) in inventories {
            let domain = if peer == body_peer {
                FailureDomain(1)
            } else {
                FailureDomain(2)
            };
            sync.add_inventory(peer, domain, &headers, &inventory)
                .unwrap();
        }
        let requests = sync.schedule(1);
        assert!(requests.iter().any(|request| {
            request.peer == body_peer && request.objects.contains(&ObjectId::BlockBody(first_body))
        }));
        assert!(requests.iter().any(|request| {
            request.peer == tip_peer && request.objects.contains(&ObjectId::BlockBody(second_body))
        }));
        assert!(requests.iter().any(|request| {
            request.peer == tip_peer && request.objects.contains(&ObjectId::Terminal(terminal))
        }));

        // A terminal identity alone must not start an immutable transport
        // plan. Every selected header needs at least one exact body source;
        // otherwise a header-only peer could pause miners indefinitely.
        dag.remove_inventory_provider(body_peer);
        assert_eq!(
            source_independent_suffix_offer(&dag, tip_peer, base, base, headers.clone(),)
                .unwrap_err(),
            noid_node::networking::suffix_sync::SuffixSyncError::MissingBodySource
        );

        let mut rejected = std::collections::HashSet::new();
        assert_eq!(
            quarantine_exact_suffix_sources(&mut dag, &mut rejected, &[tip_peer]),
            1
        );
        assert_eq!(dag.best_tip(), second.point());
        assert!(dag.terminal_provider(second.point(), None).is_none());
        assert!(rejected.contains(&tip_peer));
    }

    #[test]
    fn network_storage_epoch_marker_requires_exact_genesis_bound_value() {
        let directory = tempfile::tempdir().unwrap();
        assert!(!network_storage_epoch_is_current(directory.path()).unwrap());

        persist_network_storage_epoch_marker(directory.path()).unwrap();
        assert!(network_storage_epoch_is_current(directory.path()).unwrap());

        std::fs::write(
            directory.path().join(".network-storage-epoch"),
            b"incomplete",
        )
        .unwrap();
        assert!(!network_storage_epoch_is_current(directory.path()).unwrap());
    }

    #[test]
    fn storage_epoch_initialization_preserves_wallet_and_local_files() {
        let directory = tempfile::tempdir().unwrap();
        let wallet = directory.path().join("wallet.key");
        std::fs::write(&wallet, b"canonical-wallet-secret").unwrap();
        std::fs::write(directory.path().join("wallet.receipts"), b"old receipts").unwrap();
        std::fs::write(directory.path().join("wallet.meta"), b"old metadata").unwrap();
        std::fs::write(directory.path().join("peers.json"), b"old peers").unwrap();
        std::fs::write(directory.path().join("parano1d-node.log"), b"old log").unwrap();
        std::fs::write(directory.path().join("parano1d.toml"), b"local config").unwrap();
        let cache = directory.path().join("history-step-cache");
        std::fs::create_dir(&cache).unwrap();
        std::fs::write(cache.join("derived.bin"), b"derived").unwrap();

        assert!(!ensure_network_storage_epoch(directory.path(), false).unwrap());
        assert!(network_storage_epoch_is_current(directory.path()).unwrap());
        assert_eq!(std::fs::read(&wallet).unwrap(), b"canonical-wallet-secret");
        assert_eq!(
            std::fs::read(directory.path().join("wallet.receipts")).unwrap(),
            b"old receipts"
        );
        assert_eq!(
            std::fs::read(directory.path().join("wallet.meta")).unwrap(),
            b"old metadata"
        );
        assert_eq!(
            std::fs::read(directory.path().join("peers.json")).unwrap(),
            b"old peers"
        );
        assert_eq!(
            std::fs::read(directory.path().join("parano1d-node.log")).unwrap(),
            b"old log"
        );
        assert_eq!(
            std::fs::read(directory.path().join("parano1d.toml")).unwrap(),
            b"local config"
        );
        assert_eq!(
            std::fs::read(cache.join("derived.bin")).unwrap(),
            b"derived"
        );
    }

    #[test]
    fn empty_directory_initializes_mainnet_storage_identity_once() {
        let directory = tempfile::tempdir().unwrap();
        assert!(!ensure_network_storage_epoch(directory.path(), false).unwrap());
        assert!(network_storage_epoch_is_current(directory.path()).unwrap());
        assert!(!ensure_network_storage_epoch(directory.path(), false).unwrap());
    }

    #[test]
    fn missing_marker_is_repaired_for_an_existing_mainnet_database() {
        let directory = tempfile::tempdir().unwrap();
        let context =
            noid_chain::storage::MdbxChainContext::open_or_create(directory.path()).unwrap();
        assert_eq!(context.tip_height(), 0);
        drop(context);
        std::fs::write(directory.path().join("wallet.key"), b"preserved-wallet").unwrap();

        assert!(!ensure_network_storage_epoch(directory.path(), false).unwrap());
        assert!(network_storage_epoch_is_current(directory.path()).unwrap());
        assert_eq!(
            std::fs::read(directory.path().join("wallet.key")).unwrap(),
            b"preserved-wallet"
        );
        let reopened =
            noid_chain::storage::MdbxChainContext::open_or_create(directory.path()).unwrap();
        assert_eq!(reopened.tip_height(), 0);
    }

    #[test]
    fn moving_tip_replaces_a_plan_before_exact_object_progress() {
        let first_peer = libp2p::PeerId::random();
        let extension_peer = libp2p::PeerId::random();
        let pinned = test_exact_suffix_offer(&[1], &[1]);
        let extension = test_exact_suffix_offer(&[1, 2], &[1, 2]);
        let extension_id = extension.plan().id();
        let mut active = None;

        assert_eq!(
            admit_exact_suffix_offer(
                &mut active,
                first_peer,
                noid_node::networking::FailureDomain(1),
                pinned,
            )
            .unwrap(),
            SuffixAdmission::Started
        );
        assert!(!active.as_mut().unwrap().schedule(0).is_empty());
        assert_eq!(
            admit_exact_suffix_offer(
                &mut active,
                extension_peer,
                noid_node::networking::FailureDomain(2),
                extension,
            )
            .unwrap(),
            SuffixAdmission::Replaced
        );
        assert_eq!(active.as_ref().unwrap().plan_id(), extension_id);
    }

    #[test]
    fn moving_tip_preserves_a_plan_after_exact_object_progress() {
        use noid_p2p::object_protocol::{ObjectId, ObjectPayload};

        let first_peer = libp2p::PeerId::random();
        let extension_peer = libp2p::PeerId::random();
        let pinned = test_exact_suffix_offer(&[1], &[1]);
        let pinned_id = pinned.plan().id();
        let extension = test_exact_suffix_offer(&[1, 2], &[1, 2]);
        let mut active = None;

        assert_eq!(
            admit_exact_suffix_offer(
                &mut active,
                first_peer,
                noid_node::networking::FailureDomain(1),
                pinned,
            )
            .unwrap(),
            SuffixAdmission::Started
        );
        let body_request = active
            .as_mut()
            .unwrap()
            .schedule(0)
            .into_iter()
            .find(|request| {
                request
                    .objects
                    .iter()
                    .all(|object| matches!(object, ObjectId::BlockBody(_)))
            })
            .expect("the suffix schedules its body");
        let payloads = body_request
            .objects
            .iter()
            .copied()
            .map(|object| ObjectPayload {
                object,
                bytes: Some(vec![1]),
            })
            .collect();
        assert_eq!(
            active
                .as_mut()
                .unwrap()
                .accept_response(body_request.token, body_request.peer, payloads, None)
                .unwrap(),
            1
        );
        assert!(active.as_ref().unwrap().has_verified_objects());

        assert_eq!(
            admit_exact_suffix_offer(
                &mut active,
                extension_peer,
                noid_node::networking::FailureDomain(2),
                extension,
            )
            .unwrap(),
            SuffixAdmission::DeferredExtension
        );
        assert_eq!(active.as_ref().unwrap().plan_id(), pinned_id);
    }

    #[test]
    fn behind_header_range_still_supplies_the_pinned_suffix_objects() {
        use noid_node::networking::FailureDomain;
        use noid_p2p::{header_protocol::HeaderInventoryRecord, object_protocol::ObjectId};

        let original_peer = libp2p::PeerId::random();
        let alternate_peer = libp2p::PeerId::random();
        let offer = test_exact_suffix_offer(&[1], &[1]);
        let target_header = offer.plan().headers()[0].header;
        let body = offer.objects().iter().find_map(|object| match object {
            ObjectId::BlockBody(body) => Some(*body),
            _ => None,
        });
        let terminal = offer.objects().iter().find_map(|object| match object {
            ObjectId::Terminal(terminal) => Some(*terminal),
            _ => None,
        });
        let records = vec![
            HeaderInventoryRecord::header_only(noid_chain::consensus::genesis_header()),
            HeaderInventoryRecord {
                header: target_header,
                body,
                terminal,
            },
        ];
        let mut active = Some(
            noid_node::networking::suffix_sync::SuffixSync::from_offer(
                original_peer,
                FailureDomain(1),
                offer,
            )
            .unwrap(),
        );
        active.as_mut().unwrap().disconnect(original_peer);

        assert_eq!(
            merge_active_suffix_inventory(&mut active, alternate_peer, FailureDomain(2), &records,)
                .unwrap(),
            2
        );
        let requests = active.as_mut().unwrap().schedule(0);
        assert_eq!(requests.len(), 2);
        assert!(requests
            .iter()
            .all(|request| request.peer == alternate_peer));
    }

    #[test]
    fn exhausted_suffix_can_be_retired_and_rematerialized_from_moving_tip() {
        let failed_peer = libp2p::PeerId::random();
        let replacement_peer = libp2p::PeerId::random();
        let pinned = test_exact_suffix_offer(&[1], &[1]);
        let extension = test_exact_suffix_offer(&[1, 2], &[1, 2]);
        let extension_id = extension.plan().id();
        let mut active = None;

        assert_eq!(
            admit_exact_suffix_offer(
                &mut active,
                failed_peer,
                noid_node::networking::FailureDomain(1),
                pinned,
            )
            .unwrap(),
            SuffixAdmission::Started
        );
        for now_ms in [0, 1_000, 3_000] {
            let requests = active.as_mut().unwrap().schedule(now_ms);
            assert!(!requests.is_empty());
            for request in requests {
                active
                    .as_mut()
                    .unwrap()
                    .request_failed(request.token, request.peer, &request.objects, now_ms)
                    .unwrap();
            }
        }
        assert!(active.as_ref().unwrap().unfinished_transport_is_extinct());

        // Production reaches this transition only after bounded provider
        // discovery. Retiring the transport plan leaves its HeaderDAG target
        // available, so a later same-branch target can be materialized cleanly.
        active.take();
        assert_eq!(
            admit_exact_suffix_offer(
                &mut active,
                replacement_peer,
                noid_node::networking::FailureDomain(2),
                extension,
            )
            .unwrap(),
            SuffixAdmission::Started
        );
        assert_eq!(active.as_ref().unwrap().plan_id(), extension_id);
    }

    #[test]
    fn genuinely_better_competing_branch_replaces_an_inflight_plan() {
        let first_peer = libp2p::PeerId::random();
        let winner_peer = libp2p::PeerId::random();
        let losing = test_exact_suffix_offer(&[1], &[1]);
        let winning = test_exact_suffix_offer(&[9], &[2]);
        let winning_id = winning.plan().id();
        let mut active = None;

        admit_exact_suffix_offer(
            &mut active,
            first_peer,
            noid_node::networking::FailureDomain(1),
            losing,
        )
        .unwrap();
        assert_eq!(
            admit_exact_suffix_offer(
                &mut active,
                winner_peer,
                noid_node::networking::FailureDomain(2),
                winning,
            )
            .unwrap(),
            SuffixAdmission::Replaced
        );
        assert_eq!(active.as_ref().unwrap().plan_id(), winning_id);
    }

    #[test]
    fn initial_sync_readiness_is_durable_for_all_subscribers() {
        let (sender, first) = tokio::sync::watch::channel(false);
        let second = sender.subscribe();
        mark_initial_sync_ready(&sender);
        let late = sender.subscribe();

        assert!(*first.borrow());
        assert!(*second.borrow());
        assert!(*late.borrow());
    }

    #[test]
    fn initial_sync_stage_advances_without_regressing_during_idle_gaps() {
        let stage = advance_initial_sync_stage(NodeSyncStage::Headers, false, false);
        assert_eq!(stage, NodeSyncStage::Headers);

        let stage = advance_initial_sync_stage(stage, true, false);
        assert_eq!(stage, NodeSyncStage::State);
        let stage = advance_initial_sync_stage(stage, false, false);
        assert_eq!(stage, NodeSyncStage::State);

        let stage = advance_initial_sync_stage(stage, false, true);
        assert_eq!(stage, NodeSyncStage::Tip);
        assert_eq!(
            advance_initial_sync_stage(stage, true, false),
            NodeSyncStage::Tip
        );
        assert_eq!(
            advance_initial_sync_stage(stage, false, false),
            NodeSyncStage::Tip
        );
    }

    #[test]
    fn durable_tip_needs_peer_confirmation_outside_genesis_mode() {
        assert!(!initial_sync_may_skip_peer_confirmation(false));
        assert!(initial_sync_may_skip_peer_confirmation(true));
    }

    #[test]
    fn history_step_terminal_failover_keeps_both_exact_requests_correlated() {
        let primary = libp2p::PeerId::random();
        let alternate = libp2p::PeerId::random();
        let mut requests = TerminalRequestRace::new(primary, 41);
        assert!(requests.mark_dispatched(primary, 41));

        requests.install_hedge(alternate);
        assert!(requests.mark_dispatched(alternate, 41));
        assert!(requests.matches(primary, 41));
        assert!(requests.matches(alternate, 41));

        assert!(requests.mark_failed(primary, 41));
        assert!(requests.has_active());
        assert!(requests.matches(alternate, 41));
        assert!(requests.mark_failed(alternate, 41));
        assert!(!requests.has_active());

        let mut successful = TerminalRequestRace::new(primary, 42);
        assert!(successful.mark_dispatched(primary, 42));
        successful.install_hedge(alternate);
        assert!(successful.mark_dispatched(alternate, 42));
        assert!(successful.mark_succeeded(primary, 42));
        assert!(!successful.has_active());
        assert!(!successful.matches(alternate, 42));
    }

    #[test]
    fn retained_inventory_advertises_an_older_selected_snapshot_terminal() {
        use noid_p2p::{
            header_protocol::HeaderInventoryRecord,
            object_protocol::ObjectId,
        };

        let offer = test_exact_suffix_offer(&[1], &[1]);
        let header = offer.plan().headers()[0].header;
        let hash = noid_chain::block_header::block_id(&header);
        let terminal = offer
            .objects()
            .iter()
            .find_map(|object| match object {
                ObjectId::Terminal(terminal) => Some(*terminal),
                _ => None,
            })
            .unwrap();
        let retained = [HeaderInventoryRecord {
            header,
            body: None,
            terminal: Some(terminal),
        }];

        assert_eq!(
            retained_terminal_capability(&retained, header.height, hash),
            Some(ManifestTerminalCapability {
                boundary_height: header.height,
                boundary_hash: hash,
            })
        );
        assert!(is_single_header_inventory_for_point(
            &retained,
            header.height,
            hash
        ));

        let header_only = [HeaderInventoryRecord::header_only(header)];
        assert_eq!(
            retained_terminal_capability(&header_only, header.height, hash),
            None
        );
        assert!(is_single_header_inventory_for_point(
            &header_only,
            header.height,
            hash
        ));
    }

    #[test]
    fn active_snapshot_terminal_inventory_survives_a_newer_manifest_response() {
        let peer = libp2p::PeerId::random();
        let selected = ManifestTerminalCapability {
            boundary_height: 72,
            boundary_hash: [0x72; 32],
        };
        let newer = ManifestTerminalCapability {
            boundary_height: 78,
            boundary_hash: [0x78; 32],
        };
        let mut capabilities = std::collections::HashMap::from([(peer, selected)]);

        remember_terminal_capability(&mut capabilities, peer, newer, Some(selected));
        assert_eq!(capabilities.get(&peer), Some(&selected));

        remember_terminal_capability(&mut capabilities, peer, newer, None);
        assert_eq!(capabilities.get(&peer), Some(&newer));
    }

    #[test]
    fn failed_terminal_hedge_rotates_without_abandoning_the_primary() {
        let primary = libp2p::PeerId::random();
        let failed_hedge = libp2p::PeerId::random();
        let replacement = libp2p::PeerId::random();
        let height = 77;
        let block_hash = [7; 32];
        let mut requests = TerminalRequestRace::new(primary, 43);
        assert!(requests.mark_dispatched(primary, 43));
        requests.install_hedge(failed_hedge);
        assert!(requests.mark_dispatched(failed_hedge, 43));

        assert!(requests.mark_failed(failed_hedge, 43));
        assert!(requests.matches(primary, 43));
        assert!(requests.hedge.is_none());

        let peers = std::collections::HashSet::from([primary, failed_hedge, replacement]);
        let capabilities = peers
            .iter()
            .copied()
            .map(|peer| {
                (
                    peer,
                    ManifestTerminalCapability {
                        boundary_height: height,
                        boundary_hash: block_hash,
                    },
                )
            })
            .collect();
        let rejected = std::collections::HashSet::new();
        let exhausted = std::collections::HashSet::new();
        let now = std::time::Instant::now();
        let retry_after = std::collections::HashMap::from([(
            failed_hedge,
            now + std::time::Duration::from_secs(3),
        )]);
        assert_eq!(
            advertised_terminal_alternate_peer(
                &peers,
                &capabilities,
                &rejected,
                &exhausted,
                &retry_after,
                &requests,
                height,
                block_hash,
                now,
            ),
            Some(replacement)
        );

        requests.install_hedge(replacement);
        assert!(requests.mark_dispatched(replacement, 43));
        assert!(requests.matches(primary, 43));
        assert!(requests.matches(replacement, 43));
        assert!(requests.retire_peer(replacement));
        assert!(requests.matches(primary, 43));
        assert!(requests.hedge.is_none());
    }

    #[test]
    fn history_step_terminal_hedge_uses_one_distinct_connected_peer() {
        let primary = libp2p::PeerId::random();
        let alternate = libp2p::PeerId::random();
        let third = libp2p::PeerId::random();
        let mut peers = std::collections::HashSet::from([primary, alternate, third]);
        let mut requests = TerminalRequestRace::new(primary, 1);
        assert!(requests.mark_dispatched(primary, 1));

        let rejected = std::collections::HashSet::new();
        let selected = terminal_alternate_peer(&peers, &rejected, &requests)
            .expect("one alternate must be selected");
        assert_ne!(selected, primary);
        requests.install_hedge(selected);
        assert_eq!(
            terminal_alternate_peer(&peers, &rejected, &requests),
            Some(if selected == alternate {
                third
            } else {
                alternate
            })
        );

        peers.retain(|peer| requests.used_peer(*peer));
        assert_eq!(terminal_alternate_peer(&peers, &rejected, &requests), None);
    }

    #[test]
    fn history_step_terminal_hedge_has_a_node_local_deadline() {
        let primary = libp2p::PeerId::random();
        let alternate = libp2p::PeerId::random();
        let mut requests = TerminalRequestRace::new(primary, 7);
        assert!(requests.mark_dispatched(primary, 7));

        assert!(!requests.hedge_due(
            requests.started_at + HISTORY_STEP_TERMINAL_HEDGE_AFTER
                - std::time::Duration::from_millis(1)
        ));
        assert!(requests.hedge_due(requests.started_at + HISTORY_STEP_TERMINAL_HEDGE_AFTER));

        requests.install_hedge(alternate);
        assert!(requests.mark_dispatched(alternate, 7));
        assert!(!requests.hedge_due(requests.started_at + HISTORY_STEP_TERMINAL_HEDGE_AFTER));
        assert!(!requests.deadline_due(
            requests.started_at + HISTORY_STEP_TERMINAL_HARD_DEADLINE
                - std::time::Duration::from_millis(1)
        ));
        assert!(requests.deadline_due(requests.started_at + HISTORY_STEP_TERMINAL_HARD_DEADLINE));
        assert!(requests.mark_succeeded(primary, 7));
        assert!(!requests.deadline_due(requests.started_at + HISTORY_STEP_TERMINAL_HARD_DEADLINE));
    }

    #[test]
    fn local_queue_pressure_keeps_terminal_request_pending() {
        let primary = libp2p::PeerId::random();
        let mut requests = TerminalRequestRace::new(primary, 9);
        assert_eq!(requests.pending().collect::<Vec<_>>().len(), 1);
        assert!(requests.has_work());
        assert!(!requests.has_active());
        assert!(!requests.deadline_due(requests.started_at + HISTORY_STEP_TERMINAL_HARD_DEADLINE));
        assert!(requests.mark_dispatched(primary, 9));
        assert!(requests.has_active());
        assert!(requests.defer(primary, 9));
        assert!(!requests.has_active());
        assert_eq!(requests.pending().collect::<Vec<_>>().len(), 1);
    }

    #[test]
    fn only_transient_terminal_transport_failures_retry_the_same_peer() {
        use noid_p2p::RequestFailureKind;

        assert!(terminal_transport_can_retry_same_peer(
            RequestFailureKind::Timeout
        ));
        assert!(terminal_transport_can_retry_same_peer(
            RequestFailureKind::Io
        ));
        assert!(!terminal_transport_can_retry_same_peer(
            RequestFailureKind::ConnectionClosed
        ));
        assert!(!terminal_transport_can_retry_same_peer(
            RequestFailureKind::Dial
        ));
        assert!(!terminal_transport_can_retry_same_peer(
            RequestFailureKind::UnsupportedProtocol
        ));
        assert!(!terminal_transport_can_retry_same_peer(
            RequestFailureKind::InvalidResponse
        ));
        assert!(!terminal_transport_can_retry_same_peer(
            RequestFailureKind::LocalCapacity
        ));
    }

    #[test]
    fn repeated_terminal_transport_failures_remain_retryable() {
        let key = SnapshotTerminalSourceKey {
            peer: libp2p::PeerId::random(),
            height: 77,
            block_hash: [7; 32],
        };
        let mut failures = std::collections::HashMap::new();

        for expected in 1..=5 {
            assert_eq!(
                record_snapshot_terminal_transport_failure(&mut failures, key),
                expected
            );
        }
        assert_eq!(failures.get(&key), Some(&5));
    }

    #[test]
    fn terminal_retry_cooldown_rotates_then_reuses_the_exact_provider() {
        let preferred = libp2p::PeerId::random();
        let alternate = libp2p::PeerId::random();
        let height = 77;
        let block_hash = [7; 32];
        let peers = std::collections::HashSet::from([preferred, alternate]);
        let capabilities = std::collections::HashMap::from([
            (
                preferred,
                ManifestTerminalCapability {
                    boundary_height: height,
                    boundary_hash: block_hash,
                },
            ),
            (
                alternate,
                ManifestTerminalCapability {
                    boundary_height: height,
                    boundary_hash: block_hash,
                },
            ),
        ]);
        let rejected = std::collections::HashSet::new();
        let mut exhausted = std::collections::HashSet::new();
        let now = std::time::Instant::now();
        let mut retry_after =
            std::collections::HashMap::from([(preferred, now + std::time::Duration::from_secs(3))]);

        assert_eq!(
            advertised_terminal_peer(
                &peers,
                &capabilities,
                &rejected,
                &exhausted,
                &retry_after,
                preferred,
                height,
                block_hash,
                now,
            ),
            Some(alternate)
        );
        assert_eq!(
            advertised_terminal_peer(
                &peers,
                &capabilities,
                &rejected,
                &exhausted,
                &retry_after,
                preferred,
                height,
                block_hash,
                now + std::time::Duration::from_secs(3),
            ),
            Some(preferred)
        );

        exhausted.insert(SnapshotTerminalSourceKey {
            peer: preferred,
            height,
            block_hash,
        });
        retry_after.clear();
        assert_eq!(
            advertised_terminal_peer(
                &peers,
                &capabilities,
                &rejected,
                &exhausted,
                &retry_after,
                preferred,
                height,
                block_hash,
                now,
            ),
            Some(alternate)
        );
    }

    #[test]
    fn mining_gate_accepts_one_confirmed_ordinary_peer() {
        let (proof_tx, proof_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, proof_tx, ready_tx, count_tx);
        let first = libp2p::PeerId::random();
        let height = 17;
        let hash = [0x17; 32];

        quorum.set_canonical_tip(height, hash, false);
        quorum.set_sync_state(true, false);
        quorum.connect(first, noid_node::networking::FailureDomain(1));
        assert_eq!(quorum.probe_candidates(MINING_PEER_QUORUM).len(), 1);
        assert_eq!(*count_rx.borrow(), 0);
        assert!(!*ready_rx.borrow());

        quorum.confirm_tip(first, height, hash);
        assert_eq!(*count_rx.borrow(), MINING_PEER_QUORUM);
        assert!(*proof_rx.borrow());
        assert!(*ready_rx.borrow());

        quorum.disconnect(first);
        assert_eq!(*count_rx.borrow(), 0);
        assert!(!*ready_rx.borrow());

        quorum.confirm_tip(first, height, hash);
        assert_eq!(
            *count_rx.borrow(),
            0,
            "a delayed result cannot resurrect a disconnected peer"
        );
        assert!(!*ready_rx.borrow());
    }

    #[test]
    fn mining_quorum_expires_stale_tip_authority() {
        let (proof_tx, _proof_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, proof_tx, ready_tx, count_tx);
        let first = libp2p::PeerId::random();
        let confirmed_at = std::time::Instant::now();
        let height = 23;
        let hash = [0x23; 32];

        quorum.set_canonical_tip(height, hash, false);
        quorum.set_sync_state(true, false);
        quorum.connect(first, noid_node::networking::FailureDomain(1));
        quorum.confirm_tip_at(first, height, hash, confirmed_at);
        assert!(*ready_rx.borrow());

        quorum.expire_stale(
            confirmed_at + MINING_PEER_CONFIRMATION_TTL - std::time::Duration::from_millis(1),
        );
        assert_eq!(*count_rx.borrow(), MINING_PEER_QUORUM);
        assert!(*ready_rx.borrow());

        quorum.expire_stale(confirmed_at + MINING_PEER_CONFIRMATION_TTL);
        assert_eq!(*count_rx.borrow(), 0);
        assert!(!*ready_rx.borrow());
        assert_eq!(quorum.probe_candidates(MINING_PEER_QUORUM).len(), 1);
    }

    #[test]
    fn mining_quorum_reacquisition_prioritizes_unconfirmed_public_peers() {
        let (proof_tx, _proof_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, _ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, _count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, proof_tx, ready_tx, count_tx);
        let peers = (0..64)
            .map(|_| libp2p::PeerId::random())
            .collect::<Vec<_>>();
        for (index, peer) in peers.iter().enumerate() {
            quorum.connect(*peer, noid_node::networking::FailureDomain(index as u64));
        }
        let height = 31;
        let hash = [0x31; 32];
        quorum.set_canonical_tip(height, hash, false);
        quorum.set_sync_state(true, false);
        assert_eq!(quorum.probe_candidates(MINING_PEER_QUORUM).len(), 1);

        quorum.confirm_tip(peers[0], height, hash);
        quorum.confirm_tip(peers[1], height, hash);
        let candidates = quorum.probe_candidates(MINING_PEER_QUORUM);
        assert_eq!(candidates.len(), 1);
        assert!(!candidates.contains(&peers[0]));
    }

    #[test]
    fn mining_quorum_rotates_unconfirmed_probe_lanes() {
        let (proof_tx, _proof_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, _ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, _count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, proof_tx, ready_tx, count_tx);
        let peers = (0..6).map(|_| libp2p::PeerId::random()).collect::<Vec<_>>();
        for (index, peer) in peers.iter().enumerate() {
            quorum.connect(*peer, noid_node::networking::FailureDomain(index as u64));
        }

        let first = quorum.probe_candidates(MINING_PEER_QUORUM);
        assert_eq!(first.len(), MINING_PEER_QUORUM);
        let attempted_at = std::time::Instant::now();
        for peer in &first {
            quorum.mark_probe_sent(*peer, attempted_at);
        }
        let second = quorum.probe_candidates(MINING_PEER_QUORUM);
        assert_eq!(second.len(), MINING_PEER_QUORUM);
        assert!(first.iter().all(|peer| !second.contains(peer)));

        assert!(MINING_QUORUM_PROBE_INTERVAL < MINING_PEER_CONFIRMATION_TTL);
    }

    #[test]
    fn mining_gate_survives_a_normal_child_and_revokes_on_replacement() {
        let (proof_tx, proof_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, proof_tx, ready_tx, count_tx);
        let first = libp2p::PeerId::random();
        quorum.connect(first, noid_node::networking::FailureDomain(1));

        quorum.set_canonical_tip(40, [0x40; 32], false);
        quorum.set_sync_state(true, false);
        quorum.confirm_tip(first, 40, [0x40; 32]);
        assert!(*ready_rx.borrow());

        quorum.set_canonical_tip(41, [0x41; 32], true);
        assert_eq!(*count_rx.borrow(), MINING_PEER_QUORUM);
        assert!(*proof_rx.borrow());
        assert!(*ready_rx.borrow());

        // A delayed report for the old parent is ignored but cannot close the
        // gate carried by the locally validated canonical extension.
        quorum.confirm_tip(first, 40, [0x40; 32]);
        assert!(*ready_rx.borrow());

        quorum.set_canonical_tip(41, [0x51; 32], false);
        assert!(!*ready_rx.borrow());

        // Delayed reports for the displaced branch cannot resurrect the gate.
        quorum.confirm_tip(first, 40, [0x40; 32]);
        assert_eq!(*count_rx.borrow(), MINING_PEER_QUORUM);
        assert!(!*ready_rx.borrow());

        quorum.confirm_tip(first, 41, [0x51; 32]);
        assert!(*ready_rx.borrow());
    }

    #[test]
    fn verified_exact_suffix_source_reauthorizes_the_committed_tip_immediately() {
        let (proof_tx, proof_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, _count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, proof_tx, ready_tx, count_tx);
        let source = libp2p::PeerId::random();
        let second_announcer = libp2p::PeerId::random();
        quorum.connect(source, noid_node::networking::FailureDomain(1));
        quorum.connect(second_announcer, noid_node::networking::FailureDomain(2));

        quorum.set_canonical_tip(50, [0x50; 32], false);
        quorum.set_sync_state(true, false);
        quorum.confirm_tip(source, 50, [0x50; 32]);
        quorum.confirm_tip(second_announcer, 50, [0x50; 32]);
        assert!(*proof_rx.borrow());
        assert!(*ready_rx.borrow());

        // Multiple peers announce the same stronger child. Mining must pause
        // while its exact objects and recursive terminal are unverified.
        quorum.observe_compatible(source);
        quorum.observe_compatible(second_announcer);
        quorum.set_sync_state(true, true);
        assert!(!*proof_rx.borrow());
        assert!(!*ready_rx.borrow());

        // Once that exact selected suffix commits, every compatible
        // announcement is resolved. One exact object source is sufficient
        // liveness evidence for the new parent; the second announcer must not
        // keep proof construction blocked until the next periodic probe.
        quorum.set_canonical_tip(51, [0x51; 32], true);
        quorum.resolve_committed_view();
        quorum.confirm_tip(source, 51, [0x51; 32]);
        assert!(*proof_rx.borrow());
        assert!(*ready_rx.borrow());
    }

    #[test]
    fn header_only_candidate_does_not_pause_until_exact_plan_exists() {
        let (proof_tx, proof_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, _count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, proof_tx, ready_tx, count_tx);
        let peer = libp2p::PeerId::random();
        let height = 50;
        let hash = [0x50; 32];

        quorum.connect(peer, noid_node::networking::FailureDomain(1));
        quorum.set_canonical_tip(height, hash, false);
        quorum.set_sync_state(true, false);
        quorum.confirm_tip(peer, height, hash);
        assert!(*proof_rx.borrow());
        assert!(*ready_rx.borrow());

        // The peer supplied a native-valid stronger header, but no complete
        // exact-object inventory yet. Keep the committed template live while
        // bounded provider discovery continues.
        quorum.observe_compatible(peer);
        assert!(*proof_rx.borrow());
        assert!(*ready_rx.borrow());

        // Admitting the immutable exact plan pauses both stages immediately.
        quorum.set_sync_state(true, true);
        assert!(!*proof_rx.borrow());
        assert!(!*ready_rx.borrow());

        // If every exact source is later exhausted, retiring transport alone
        // reopens the same committed parent without losing its frontier lease.
        quorum.set_sync_state(true, false);
        quorum.resolve_committed_view();
        assert!(*proof_rx.borrow());
        assert!(*ready_rx.borrow());
    }

    #[test]
    fn heartbeat_reconcile_does_not_clear_unresolved_work_for_the_same_tip() {
        let (proof_tx, proof_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, _count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, proof_tx, ready_tx, count_tx);
        let peer = libp2p::PeerId::random();
        let height = 60;
        let hash = [0x60; 32];

        quorum.connect(peer, noid_node::networking::FailureDomain(1));
        quorum.set_canonical_tip(height, hash, false);
        quorum.set_sync_state(true, false);
        quorum.confirm_tip(peer, height, hash);
        assert!(*proof_rx.borrow());
        assert!(*ready_rx.borrow());

        quorum.set_sync_state(true, true);
        assert!(!*proof_rx.borrow());
        assert!(!*ready_rx.borrow());

        // The 500 ms heartbeat repeatedly observes this unchanged canonical
        // point while an exact child is still being fetched. It must not
        // momentarily reopen mining and then close it again.
        quorum.reconcile_canonical_tip(height, hash, [0x59; 32]);
        assert!(!*proof_rx.borrow());
        assert!(!*ready_rx.borrow());
    }

    #[test]
    fn isolated_mining_bypasses_peer_quorum_at_any_height() {
        let (proof_tx, proof_rx) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, count_rx) = tokio::sync::watch::channel(0usize);
        let _quorum = MiningPeerQuorum::new(true, proof_tx, ready_tx, count_tx);

        assert_eq!(*count_rx.borrow(), 0);
        assert!(*proof_rx.borrow());
        assert!(*ready_rx.borrow());
    }

    #[test]
    fn p2p_listener_accepts_socket_and_multiaddr_forms() {
        assert_eq!(
            p2p_listen_to_multiaddr("0.0.0.0:9600").unwrap().to_string(),
            "/ip4/0.0.0.0/tcp/9600"
        );
        assert_eq!(
            p2p_listen_to_multiaddr("/ip4/0.0.0.0/tcp/9600")
                .unwrap()
                .to_string(),
            "/ip4/0.0.0.0/tcp/9600"
        );
    }

    #[test]
    fn seed_parser_accepts_gui_and_operator_forms_without_losing_peer_id() {
        let peer = libp2p::PeerId::random();
        assert_eq!(
            seed_to_multiaddr("seed.example:9600", 9600)
                .unwrap()
                .to_string(),
            "/dns/seed.example/tcp/9600"
        );
        assert_eq!(
            seed_to_multiaddr("203.0.113.10:9600", 9600)
                .unwrap()
                .to_string(),
            "/ip4/203.0.113.10/tcp/9600"
        );
        assert_eq!(
            seed_to_multiaddr("[2001:db8::10]:9600", 9600)
                .unwrap()
                .to_string(),
            "/ip6/2001:db8::10/tcp/9600"
        );
        assert_eq!(
            seed_to_multiaddr("dnsaddr:example.net", 9600)
                .unwrap()
                .to_string(),
            "/dnsaddr/example.net"
        );
        let explicit = format!("/ip4/203.0.113.10/tcp/9600/p2p/{peer}");
        assert_eq!(
            seed_to_multiaddr(&explicit, 9600).unwrap().to_string(),
            explicit
        );
    }

    #[test]
    fn system_seed_resolution_is_deduplicated_and_bounded() {
        let mut answers = vec![
            "203.0.113.10:9600".parse().unwrap(),
            "[2001:db8::10]:9600".parse().unwrap(),
            "203.0.113.10:9600".parse().unwrap(),
        ];
        answers.extend((1..=20).map(|host| {
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, host)),
                9600,
            )
        }));
        let resolved = resolved_system_seed_addrs(answers, 9600);
        assert_eq!(resolved.len(), MAX_SYSTEM_ADDRS_PER_SEED);
        assert_eq!(resolved[0].to_string(), "/ip4/203.0.113.10/tcp/9600");
        assert_eq!(resolved[1].to_string(), "/ip6/2001:db8::10/tcp/9600");
    }

    #[tokio::test]
    async fn system_seed_resolution_uses_native_localhost_lookup() {
        let resolved = resolve_embedded_seed_with_system_dns("localhost", 9600)
            .await
            .unwrap();
        assert!(!resolved.is_empty());
        assert!(resolved.iter().all(|addr| {
            let mut protocols = addr.iter();
            matches!(
                protocols.next(),
                Some(libp2p::multiaddr::Protocol::Ip4(_) | libp2p::multiaddr::Protocol::Ip6(_))
            ) && matches!(
                protocols.next(),
                Some(libp2p::multiaddr::Protocol::Tcp(9600))
            )
        }));
    }

    #[tokio::test]
    async fn embedded_seed_keeps_dns_reresolution_after_native_lookup() {
        let resolved = embedded_seed_multiaddrs("localhost", 9600).await.unwrap();
        assert!(resolved
            .iter()
            .any(|addr| addr.to_string() == "/dns/localhost/tcp/9600"));
        assert!(resolved.iter().any(|addr| {
            matches!(
                addr.iter().next(),
                Some(libp2p::multiaddr::Protocol::Ip4(_) | libp2p::multiaddr::Protocol::Ip6(_))
            )
        }));
    }

    #[test]
    fn snapshot_header_failover_keeps_only_the_exact_candidate_file() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("headers");
        std::fs::create_dir(&directory).unwrap();
        let keep = directory.join("current.stage");
        let stale_a = directory.join("old-a.stage");
        let stale_b = directory.join("old-b.stage");
        let unrelated = directory.join("README");
        for path in [&keep, &stale_a, &stale_b, &unrelated] {
            std::fs::write(path, b"bounded test artifact").unwrap();
        }

        prune_superseded_snapshot_header_staging(&directory, &keep).unwrap();

        assert!(keep.exists());
        assert!(!stale_a.exists());
        assert!(!stale_b.exists());
        assert!(unrelated.exists());
    }

    #[test]
    fn first_start_creates_and_reuses_default_config() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested/parano1d.toml");
        let mut defaults = NodeConfig::default();
        defaults.network.listen = Some("0.0.0.0:9600".into());
        defaults.rpc.listen = Some("127.0.0.1:9601".into());

        let (created_config, created) = load_or_create_config(&path, &defaults).unwrap();
        assert!(created);
        assert_eq!(created_config.network.listen, defaults.network.listen);
        assert!(path.is_file());

        let original = std::fs::read(&path).unwrap();
        let (loaded_config, created_again) = load_or_create_config(&path, &defaults).unwrap();
        assert!(!created_again);
        assert_eq!(loaded_config.network.listen, defaults.network.listen);
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn malformed_config_is_reported_instead_of_silently_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("parano1d.toml");
        std::fs::write(&path, "[network\n").unwrap();

        let error = load_or_create_config(&path, &NodeConfig::default()).unwrap_err();
        assert!(error.to_string().contains("parse node config"));
    }

    #[test]
    fn rpc_roles_accept_independent_inline_and_file_credentials() {
        use clap::Parser;

        let inline = Cli::try_parse_from([
            "parano1d",
            "--mode",
            "extminer",
            "--mining-key",
            "0123456789abcdef",
            "--operator-key",
            "fedcba9876543210",
        ])
        .unwrap();
        assert_eq!(inline.mode, NodeMode::Extminer);
        assert_eq!(inline.mining_key.as_deref(), Some("0123456789abcdef"));
        assert_eq!(inline.operator_key.as_deref(), Some("fedcba9876543210"));
        assert!(inline.mining_key_file.is_none());
        assert!(inline.operator_key_file.is_none());

        let file = Cli::try_parse_from([
            "parano1d",
            "--mining-key-file",
            "/secure/mining.key",
            "--operator-key-file",
            "/secure/operator.key",
        ])
        .unwrap();
        assert!(file.mining_key.is_none());
        assert!(file.operator_key.is_none());
        assert_eq!(
            file.mining_key_file.as_deref(),
            Some(std::path::Path::new("/secure/mining.key"))
        );
        assert_eq!(
            file.operator_key_file.as_deref(),
            Some(std::path::Path::new("/secure/operator.key"))
        );

        assert!(Cli::try_parse_from([
            "parano1d",
            "--mining-key",
            "0123456789abcdef",
            "--mining-key-file",
            "/secure/mining.key",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "parano1d",
            "--operator-key",
            "fedcba9876543210",
            "--operator-key-file",
            "/secure/operator.key",
        ])
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rpc_key_file_is_owner_only_and_trims_only_line_endings() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("operator.key");
        std::fs::write(&path, b"0123456789abcdef0123456789abcdef\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            read_rpc_key_file(&path, "operator").unwrap(),
            "0123456789abcdef0123456789abcdef"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_rpc_key_file(&path, "operator")
            .unwrap_err()
            .to_string()
            .contains("group or others"));
    }

    #[cfg(unix)]
    #[test]
    fn rpc_key_file_rejects_symlinks_and_short_values() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.key");
        std::fs::write(&target, b"too-short\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_rpc_key_file(&target, "operator")
            .unwrap_err()
            .to_string()
            .contains("at least 16"));

        let link = temp.path().join("link.key");
        symlink(&target, &link).unwrap();
        assert!(read_rpc_key_file(&link, "operator").is_err());
    }

    #[test]
    fn rpc_keys_are_strong_and_roles_cannot_share_a_token() {
        assert!(validate_rpc_key("too-short".into(), "operator").is_err());
        assert!(validate_rpc_key("0123456789abcde f".into(), "operator").is_err());
        assert!(validate_rpc_key("0123456789abcdef".into(), "operator").is_ok());

        assert!(distinct_rpc_keys(Some("0123456789abcdef"), Some("0123456789abcdef")).is_err());
        assert!(distinct_rpc_keys(Some("0123456789abcdef"), Some("fedcba9876543210")).is_ok());
        assert!(distinct_rpc_keys(None, None).is_ok());
    }

    #[test]
    fn unauthenticated_rpc_cannot_bind_beyond_loopback() {
        for listen in ["127.0.0.1:9601", "127.42.0.1:9601", "[::1]:9601"] {
            assert!(validate_rpc_listener_auth(listen.parse().unwrap(), None, None).is_ok());
        }

        for listen in ["0.0.0.0:9601", "192.168.1.20:9601", "[::]:9601"] {
            let listen = listen.parse().unwrap();
            assert!(validate_rpc_listener_auth(listen, None, None).is_err());
            assert!(validate_rpc_listener_auth(listen, Some("mining"), None).is_ok());
            assert!(validate_rpc_listener_auth(listen, None, Some("operator")).is_ok());
        }
    }

    #[test]
    fn ordinary_sync_waits_for_a_snapshot_boundary_ahead_of_local_state() {
        assert!(!gap_requires_snapshot_sync(20_371, 20_393));
        assert!(gap_requires_snapshot_sync(20_371, 20_394));

        // Finality is 18 blocks and deterministic snapshot boundaries are six
        // blocks apart. Depending on local height alignment, the first usable
        // boundary appears at a gap from 19 through 24. The exact bridge can
        // therefore never exceed 23 blocks.
        for local_height in 96..102 {
            let first_snapshot_gap = (1..=24)
                .find(|gap| {
                    gap_requires_snapshot_sync(local_height, local_height.saturating_add(*gap))
                })
                .expect("a forward snapshot boundary exists within 24 blocks");
            assert_eq!(first_snapshot_gap, 24 - local_height % 6);
            assert!((19..=24).contains(&first_snapshot_gap));
            for gap in 0..first_snapshot_gap {
                assert!(!gap_requires_snapshot_sync(
                    local_height,
                    local_height.saturating_add(gap)
                ));
            }
        }
    }

    #[test]
    fn verified_snapshot_gets_one_bounded_exact_tail_without_moving_the_normal_threshold() {
        use noid_node::networking::ChainPoint;

        let mut tail = PostSnapshotTail {
            boundary: ChainPoint::new(100, [1; 32]),
            target: None,
        };

        assert_eq!(tail.probe_count(100), Some(43));
        assert_eq!(tail.probe_count(118), Some(25));
        assert_eq!(tail.probe_count(142), Some(1));
        assert_eq!(tail.probe_count(99), None);
        assert_eq!(tail.probe_count(143), None);
        assert!(!sync_target_requires_snapshot(100, 119, None));
        assert!(sync_target_requires_snapshot(100, 120, None));
        assert!(!sync_target_requires_snapshot(100, 142, Some(tail)));
        assert!(sync_target_requires_snapshot(100, 143, Some(tail)));
        assert!(
            tail.pin_selected_target(ChainPoint::new(100, [1; 32]), ChainPoint::new(123, [2; 32]),)
        );
        assert!(!sync_target_requires_snapshot(100, 119, Some(tail)));
        assert!(!sync_target_requires_snapshot(100, 120, Some(tail)));
        assert!(!sync_target_requires_snapshot(100, 123, Some(tail)));
        assert!(!sync_target_requires_snapshot(100, 124, Some(tail)));
        assert!(!sync_target_requires_snapshot(100, 142, Some(tail)));
        assert!(sync_target_requires_snapshot(100, 143, Some(tail)));
        assert!(tail.allows_exact_target(122, 142));
        assert!(tail.is_finished_or_invalid_at(123));
        assert!(!tail.allows_exact_target(123, 142));

        let advanced_unfinished_tail = PostSnapshotTail {
            boundary: ChainPoint::new(100, [3; 32]),
            target: Some(ChainPoint::new(123, [4; 32])),
        };
        assert!(advanced_unfinished_tail.allows_exact_target(110, 142));
        assert!(!advanced_unfinished_tail.allows_exact_target(110, 143));

        let stale_completed_tail = PostSnapshotTail {
            boundary: ChainPoint::new(96, [5; 32]),
            target: Some(ChainPoint::new(97, [6; 32])),
        };
        assert!(sync_target_requires_snapshot(
            97,
            120,
            Some(stale_completed_tail)
        ));

        let longest_retained_tail = PostSnapshotTail {
            boundary: ChainPoint::new(100, [7; 32]),
            target: Some(ChainPoint::new(142, [8; 32])),
        };
        assert!(!sync_target_requires_snapshot(
            100,
            142,
            Some(longest_retained_tail)
        ));

        let outside_serving_window = PostSnapshotTail {
            boundary: ChainPoint::new(100, [9; 32]),
            target: Some(ChainPoint::new(143, [10; 32])),
        };
        assert!(!outside_serving_window.allows_exact_target(100, 120));
        assert!(!outside_serving_window.allows_exact_target(100, 142));
        assert!(sync_target_requires_snapshot(
            100,
            120,
            Some(outside_serving_window)
        ));

        assert!(!tail.allows_exact_target(99, 120));
        assert!(!tail.allows_exact_target(110, 110));

        let saturated_tail = PostSnapshotTail {
            boundary: ChainPoint::new(u64::MAX - 10, [11; 32]),
            target: Some(ChainPoint::new(u64::MAX - 5, [12; 32])),
        };
        assert!(saturated_tail.allows_exact_target(u64::MAX - 10, u64::MAX));
        assert!(!saturated_tail.allows_exact_target(u64::MAX - 5, u64::MAX));

        assert!(unforced_manifest_waits_for_header_dag(false, Some(tail)));
        assert!(!unforced_manifest_waits_for_header_dag(true, Some(tail)));
        assert!(!unforced_manifest_waits_for_header_dag(false, None));
    }

    #[test]
    fn serving_reserve_does_not_change_finality_or_snapshot_suffix() {
        assert_eq!(noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH, 18);
        assert_eq!(
            noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH,
            18
        );
        assert_eq!(
            noid_chain::consensus::params::RETAINED_BLOCK_SERVING_DEPTH,
            42
        );
    }

    #[test]
    fn fork_choice_is_work_first_and_uses_the_canonical_hash_tie_break() {
        let less = [1u8; 32];
        let more = [2u8; 32];
        let smaller_hash = [0x11; 32];
        let larger_hash = [0x22; 32];
        assert!(competing_suffix_wins(
            &more,
            &larger_hash,
            &less,
            &smaller_hash,
        ));
        assert!(!competing_suffix_wins(
            &less,
            &smaller_hash,
            &more,
            &larger_hash,
        ));
        assert!(competing_suffix_wins(
            &more,
            &smaller_hash,
            &more,
            &larger_hash,
        ));
        assert!(!competing_suffix_wins(
            &more,
            &larger_hash,
            &more,
            &smaller_hash,
        ));
        assert!(!competing_suffix_wins(
            &more,
            &smaller_hash,
            &more,
            &smaller_hash,
        ));
    }

    #[test]
    fn shorter_peer_discovery_reads_only_the_complete_nonfinal_window() {
        assert_eq!(nonfinal_header_discovery_range(100), Some((82, 19)));
        assert_eq!(nonfinal_header_discovery_range(10), Some((0, 11)));
        assert_eq!(nonfinal_header_discovery_range(0), None);
    }

    #[test]
    fn steady_tip_probe_survives_completed_mining_quorum() {
        let started = std::time::Instant::now();
        assert!(!steady_tip_probe_due(
            started,
            started + STEADY_TIP_PROBE_INTERVAL,
            true,
            true,
        ));
        assert!(!steady_tip_probe_due(
            started,
            started + STEADY_TIP_PROBE_INTERVAL,
            false,
            false,
        ));
        assert!(!steady_tip_probe_due(
            started,
            started + STEADY_TIP_PROBE_INTERVAL - std::time::Duration::from_millis(1),
            false,
            true,
        ));
        assert!(steady_tip_probe_due(
            started,
            started + STEADY_TIP_PROBE_INTERVAL,
            false,
            true,
        ));
    }

    #[test]
    fn mining_quorum_refresh_stays_off_the_canonical_sync_path() {
        let started = std::time::Instant::now();
        assert!(!mining_quorum_probe_due(
            started,
            started + MINING_QUORUM_PROBE_INTERVAL,
            true,
            false,
        ));
        assert!(!mining_quorum_probe_due(
            started,
            started + MINING_QUORUM_PROBE_INTERVAL - std::time::Duration::from_millis(1),
            true,
            true,
        ));
        assert!(!mining_quorum_probe_due(
            started,
            started + MINING_QUORUM_PROBE_INTERVAL,
            false,
            true,
        ));
        assert!(mining_quorum_probe_due(
            started,
            started + MINING_QUORUM_PROBE_INTERVAL,
            true,
            true,
        ));
    }

    #[test]
    fn connected_tip_probe_reaches_every_first_usable_snapshot_boundary() {
        assert_eq!(
            u64::from(CONNECTED_TIP_PROBE_HEADERS),
            noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH
                + noid_p2p::protocol::SNAPSHOT_BOUNDARY_INTERVAL
                + 1
        );
        assert_eq!(CONNECTED_TIP_PROBE_HEADERS, 25);

        // The response includes the committed anchor, leaving 24 descendant
        // headers. That reaches the first usable snapshot boundary for every
        // possible six-block boundary alignment.
        let visible_descendants = u64::from(CONNECTED_TIP_PROBE_HEADERS) - 1;
        for local_height in 96..102 {
            let first_snapshot_gap = (1..=visible_descendants)
                .find(|gap| {
                    gap_requires_snapshot_sync(local_height, local_height.saturating_add(*gap))
                })
                .expect("connected probe reaches a usable snapshot boundary");
            assert_eq!(first_snapshot_gap, 24 - local_height % 6);
        }
    }

    #[test]
    fn direct_header_windows_cannot_fill_the_bounded_dag_with_one_branch() {
        assert_eq!(DIRECT_SYNC_HEADER_REQUEST_CAP, 512);
        assert_eq!(HEADER_DAG_MAX_NODES, 1024);
        assert!(
            DIRECT_SYNC_HEADER_REQUEST_CAP as usize * 2 <= HEADER_DAG_MAX_NODES,
            "two direct branch windows must fit before leaf eviction is needed"
        );
        assert!(direct_header_request_within_cap(512));
        assert!(!direct_header_request_within_cap(513));
    }

    #[test]
    fn rematerialization_probe_always_ends_at_the_selected_tip() {
        assert_eq!(selected_tip_probe_range(60, 87, 20), (68, 20));
        assert_eq!(selected_tip_probe_range(60, 68, 20), (60, 9));
    }

    #[test]
    fn unresolved_tip_probe_covers_the_missing_prefix_and_future_tip() {
        assert_eq!(unresolved_tip_probe_range(60, 68, 20), (60, 29));
        assert_eq!(unresolved_tip_probe_range(60, 87, 20), (60, 48));
        assert_eq!(unresolved_tip_probe_range(60, 900, 20), (60, 512));
    }

    #[test]
    fn repeated_known_branch_revalidates_from_the_canonical_anchor() {
        use noid_node::networking::ChainPoint;

        let canonical = ChainPoint::new(7_819, [0x19; 32]);
        let known_selected_tip = ChainPoint::new(7_835, [0x35; 32]);
        assert_eq!(
            header_inventory_validation_anchor(Some(canonical), Some(known_selected_tip)),
            Some(canonical)
        );
        assert_eq!(
            header_inventory_validation_anchor(None, Some(known_selected_tip)),
            Some(known_selected_tip)
        );
    }

    #[test]
    fn snapshot_parent_mismatch_discovers_from_finalized_not_local_tip() {
        assert_eq!(snapshot_rebase_discovery_range(7_802, 7_848), (7_802, 47));
    }

    #[test]
    fn unresolved_reorg_probe_starts_at_the_common_ancestor() {
        use noid_chain::block_header::block_id;
        use noid_node::networking::{
            header_dag::{HeaderDag, ValidatedHeader},
            ChainPoint,
        };

        let genesis = noid_chain::consensus::genesis_header();
        let base = ChainPoint::new(0, block_id(&genesis));
        let base_work = [0u8; 32];

        let mut local_header = genesis;
        local_header.height = 1;
        local_header.prev_block_hash = base.hash;
        local_header.timestamp += 1;
        local_header.nonce = 11;
        let local_work = noid_chain::add_work(
            &base_work,
            &noid_chain::block_work(&local_header.difficulty_target),
        );
        let local = ValidatedHeader::new_after_consensus_checks(local_header, local_work);

        let mut competing_header = local_header;
        competing_header.nonce = 12;
        let competing_first =
            ValidatedHeader::new_after_consensus_checks(competing_header, local_work);
        let mut competing_tip_header = competing_header;
        competing_tip_header.height = 2;
        competing_tip_header.prev_block_hash = competing_first.hash;
        competing_tip_header.timestamp += 1;
        competing_tip_header.nonce = 13;
        let competing_tip_work = noid_chain::add_work(
            &local_work,
            &noid_chain::block_work(&competing_tip_header.difficulty_target),
        );
        let competing_tip =
            ValidatedHeader::new_after_consensus_checks(competing_tip_header, competing_tip_work);

        let mut dag = HeaderDag::new(base, base_work, 16);
        dag.insert(local).unwrap();
        dag.insert(competing_first).unwrap();
        dag.insert(competing_tip).unwrap();
        assert_eq!(dag.best_tip(), competing_tip.point());
        assert_eq!(
            unresolved_selected_tip_probe_range(&dag, local.point(), 20).unwrap(),
            (base.height, 23)
        );
    }

    #[test]
    fn far_rebase_snapshot_is_bound_to_the_selected_header_dag_tip() {
        use noid_chain::block_header::block_id;
        use noid_node::networking::{
            header_dag::{HeaderDag, ValidatedHeader},
            ChainPoint,
        };

        let genesis = noid_chain::consensus::genesis_header();
        let base = ChainPoint::new(0, block_id(&genesis));
        let base_work = [0u8; 32];
        let mut first_header = genesis;
        first_header.height = 1;
        first_header.prev_block_hash = base.hash;
        first_header.timestamp += 1;
        first_header.nonce = 31;
        let first_work = noid_chain::add_work(
            &base_work,
            &noid_chain::block_work(&first_header.difficulty_target),
        );
        let first = ValidatedHeader::new_after_consensus_checks(first_header, first_work);
        let mut selected_header = first_header;
        selected_header.height = 2;
        selected_header.prev_block_hash = first.hash;
        selected_header.timestamp += 1;
        selected_header.nonce = 32;
        let selected_work = noid_chain::add_work(
            &first_work,
            &noid_chain::block_work(&selected_header.difficulty_target),
        );
        let selected = ValidatedHeader::new_after_consensus_checks(selected_header, selected_work);
        let mut dag = HeaderDag::new(base, base_work, 16);
        dag.insert(first).unwrap();
        dag.insert(selected).unwrap();
        let hint = SnapshotRebaseHint {
            ancestor_height: base.height,
            ancestor_hash: base.hash,
            competing_tip_height: selected.header.height,
            competing_tip_hash: selected.hash,
            armed_at: std::time::Instant::now(),
        };

        let farther_work = noid_chain::add_work(
            &selected_work,
            &noid_chain::block_work(&selected_header.difficulty_target),
        );
        let farther = noid_p2p::protocol::GetStateManifestResponse {
            tip_height: 3,
            tip_hash: [0xA3; 32],
            cumulative_chainwork: farther_work,
            ..Default::default()
        };
        assert_eq!(
            validate_rebase_snapshot_selection(&dag, hint, &farther).unwrap(),
            Some(SnapshotRebaseAnchor {
                height: selected.header.height,
                hash: selected.hash,
                cumulative_work: selected_work,
            })
        );

        let exact = noid_p2p::protocol::GetStateManifestResponse {
            tip_height: selected.header.height,
            tip_hash: selected.hash,
            cumulative_chainwork: selected_work,
            ..Default::default()
        };
        assert_eq!(
            validate_rebase_snapshot_selection(&dag, hint, &exact).unwrap(),
            None
        );

        let losing = noid_p2p::protocol::GetStateManifestResponse {
            cumulative_chainwork: selected_work,
            ..farther.clone()
        };
        assert!(validate_rebase_snapshot_selection(&dag, hint, &losing).is_err());

        let mut third_header = selected_header;
        third_header.height = 3;
        third_header.prev_block_hash = selected.hash;
        third_header.timestamp += 1;
        third_header.nonce = 33;
        let third_work = noid_chain::add_work(
            &selected_work,
            &noid_chain::block_work(&third_header.difficulty_target),
        );
        let third = ValidatedHeader::new_after_consensus_checks(third_header, third_work);
        let mut fourth_header = third_header;
        fourth_header.height = 4;
        fourth_header.prev_block_hash = third.hash;
        fourth_header.timestamp += 1;
        fourth_header.nonce = 34;
        let fourth_work = noid_chain::add_work(
            &third_work,
            &noid_chain::block_work(&fourth_header.difficulty_target),
        );
        let fourth = ValidatedHeader::new_after_consensus_checks(fourth_header, fourth_work);
        dag.insert(third).unwrap();
        dag.insert(fourth).unwrap();

        assert!(validate_rebase_snapshot_selection(&dag, hint, &farther).is_err());
        let selected_ancestor = noid_p2p::protocol::GetStateManifestResponse {
            tip_height: third.header.height,
            tip_hash: third.hash,
            cumulative_chainwork: third.cumulative_work,
            ..Default::default()
        };
        assert_eq!(
            validate_rebase_snapshot_selection(&dag, hint, &selected_ancestor).unwrap(),
            None,
            "a verified snapshot on selected ancestry remains installable below the live tip"
        );
    }

    #[test]
    fn linear_snapshot_install_is_bound_to_selected_header_dag_ancestry() {
        use noid_chain::block_header::block_id;
        use noid_node::networking::{
            header_dag::{HeaderDag, ValidatedHeader},
            ChainPoint,
        };

        let genesis = noid_chain::consensus::genesis_header();
        let base = ChainPoint::new(0, block_id(&genesis));
        let base_work = [0u8; 32];
        let mut dag = HeaderDag::new(base, base_work, 32);

        let mut branch_a_parent = base;
        let mut branch_a_header = genesis;
        let mut branch_a_work = base_work;
        for height in 1..=6 {
            branch_a_header.height = height;
            branch_a_header.prev_block_hash = branch_a_parent.hash;
            branch_a_header.timestamp = genesis.timestamp + height;
            branch_a_header.nonce = 100 + u128::from(height);
            branch_a_work = noid_chain::add_work(
                &branch_a_work,
                &noid_chain::block_work(&branch_a_header.difficulty_target),
            );
            let validated =
                ValidatedHeader::new_after_consensus_checks(branch_a_header, branch_a_work);
            branch_a_parent = validated.point();
            dag.insert(validated).unwrap();
        }
        let losing_boundary = branch_a_parent;
        let losing_boundary_work = branch_a_work;

        let mut branch_b_parent = base;
        let mut branch_b_header = genesis;
        let mut branch_b_work = base_work;
        let mut selected_boundary = None;
        for height in 1..=7 {
            branch_b_header.height = height;
            branch_b_header.prev_block_hash = branch_b_parent.hash;
            branch_b_header.timestamp = genesis.timestamp + height;
            branch_b_header.nonce = 200 + u128::from(height);
            branch_b_work = noid_chain::add_work(
                &branch_b_work,
                &noid_chain::block_work(&branch_b_header.difficulty_target),
            );
            let validated =
                ValidatedHeader::new_after_consensus_checks(branch_b_header, branch_b_work);
            branch_b_parent = validated.point();
            if height == 6 {
                selected_boundary = Some((branch_b_parent, branch_b_work));
            }
            dag.insert(validated).unwrap();
        }
        assert_eq!(dag.best_tip(), branch_b_parent);

        let losing = noid_p2p::protocol::GetStateManifestResponse {
            tip_height: losing_boundary.height,
            tip_hash: losing_boundary.hash,
            cumulative_chainwork: losing_boundary_work,
            ..Default::default()
        };
        assert!(validate_snapshot_install_selection(&dag, &losing).is_err());

        let (selected_boundary, selected_boundary_work) = selected_boundary.unwrap();
        let selected_ancestor = noid_p2p::protocol::GetStateManifestResponse {
            tip_height: selected_boundary.height,
            tip_hash: selected_boundary.hash,
            cumulative_chainwork: selected_boundary_work,
            ..Default::default()
        };
        assert_eq!(
            validate_snapshot_install_selection(&dag, &selected_ancestor).unwrap(),
            None
        );
        let mut farther_work = branch_b_work;
        for _ in 8..=12 {
            farther_work = noid_chain::add_work(
                &farther_work,
                &noid_chain::block_work(&branch_b_header.difficulty_target),
            );
        }
        let farther = noid_p2p::protocol::GetStateManifestResponse {
            tip_height: 12,
            tip_hash: [0xA5; 32],
            cumulative_chainwork: farther_work,
            ..Default::default()
        };
        assert_eq!(
            validate_snapshot_install_selection(&dag, &farther).unwrap(),
            Some(SnapshotRebaseAnchor {
                height: branch_b_parent.height,
                hash: branch_b_parent.hash,
                cumulative_work: branch_b_work,
            })
        );
    }

    #[test]
    fn snapshot_segment_errors_separate_remote_bytes_from_local_state() {
        use noid_chain::storage::snapshot_staging::SnapshotStagingError;

        assert_eq!(
            snapshot_segment_failure_scope(&SnapshotStagingError::SegmentDecode { segment_id: 7 }),
            SnapshotSegmentFailureScope::Source
        );
        assert_eq!(
            snapshot_segment_failure_scope(&SnapshotStagingError::ExactSegmentRootMismatch {
                segment_id: 7,
            }),
            SnapshotSegmentFailureScope::Source
        );
        assert_eq!(
            snapshot_segment_failure_scope(&SnapshotStagingError::CreationIdExceedsBound {
                segment_id: 7,
                local_index: 1,
                creation_id: 9,
                alloc_counter: 8,
            }),
            SnapshotSegmentFailureScope::Candidate
        );
        assert_eq!(
            snapshot_segment_failure_scope(&SnapshotStagingError::SessionClosed),
            SnapshotSegmentFailureScope::Fatal
        );
        assert_eq!(
            snapshot_segment_failure_scope(&SnapshotStagingError::DuplicateSegment {
                segment_id: 7,
            }),
            SnapshotSegmentFailureScope::Fatal
        );
        assert_eq!(
            snapshot_segment_failure_scope(&SnapshotStagingError::Io {
                operation: "test",
                source: std::io::Error::other("disk failed"),
            }),
            SnapshotSegmentFailureScope::Fatal
        );
        assert!(matches!(
            classify_snapshot_session_prepare_error(
                noid_chain::storage::snapshot_staging::SnapshotStagingError::EffectiveLogMismatch {
                    expected: 16,
                    actual: 15,
                }
            ),
            SnapshotSessionPrepareError::CandidateRejected(_)
        ));
        assert!(matches!(
            classify_snapshot_session_prepare_error(
                noid_chain::storage::snapshot_staging::SnapshotStagingError::Io {
                    operation: "test",
                    source: std::io::Error::other("disk failed"),
                }
            ),
            SnapshotSessionPrepareError::Fatal(_)
        ));
        assert!(matches!(
            classify_snapshot_finalization_error(
                noid_chain::storage::snapshot_staging::SnapshotStagingError::StateRootMismatch {
                    expected: [1; 32],
                    actual: [2; 32],
                }
            ),
            SnapshotFinalizationOutcome::CandidateRejected(_)
        ));
        assert!(matches!(
            classify_snapshot_finalization_error(
                noid_chain::storage::snapshot_staging::SnapshotStagingError::StagedFileLength {
                    segment_id: 7,
                    expected: 10,
                    actual: 9,
                }
            ),
            SnapshotFinalizationOutcome::Fatal(_)
        ));
    }

    #[test]
    fn snapshot_completion_separates_candidate_rejection_from_local_failure() {
        assert!(snapshot_header_completion_rejects_candidate(
            &SnapshotHeaderStagingError::InvalidCandidate {
                height: 83,
                reason: "BadDifficultyTarget".into(),
            }
        ));
        assert!(!snapshot_header_completion_rejects_candidate(
            &SnapshotHeaderStagingError::CanonicalBaseMoved {
                height: 82,
                reason: "selected base moved".into(),
            }
        ));
        assert!(snapshot_header_completion_base_moved(
            &SnapshotHeaderStagingError::CanonicalBaseMoved {
                height: 82,
                reason: "selected base moved".into(),
            }
        ));
        assert!(!snapshot_header_completion_base_moved(
            &SnapshotHeaderStagingError::CanonicalInvariant {
                height: 64,
                reason: "finalized anchor missing".into(),
            }
        ));
        assert!(!snapshot_header_completion_rejects_candidate(
            &SnapshotHeaderStagingError::VerifiedFileChanged("inode changed")
        ));
        assert!(!snapshot_header_completion_rejects_candidate(
            &SnapshotHeaderStagingError::Poisoned
        ));
    }

    #[test]
    fn ancestor_search_stops_after_the_complete_nonfinal_window() {
        assert!(header_batch_exhausts_nonfinal_window(100, 82));
        assert!(!header_batch_exhausts_nonfinal_window(100, 83));
        assert!(header_batch_exhausts_nonfinal_window(10, 0));
    }

    #[test]
    fn snapshot_header_pipeline_uses_one_ordered_same_peer_window() {
        let peer = libp2p::PeerId::random();
        let target = SNAPSHOT_HEADER_BATCH * 5;
        let mut pipeline = SnapshotHeaderPipeline::new(7, test_snapshot_id(), peer, 1, target);
        let initial = pipeline.refill_plan(false);
        assert_eq!(initial.len(), SNAPSHOT_HEADER_REQUEST_WINDOW);
        assert!(initial.iter().all(|request| request.peer == peer));
        assert_eq!(
            initial
                .iter()
                .map(|request| request.start_height)
                .collect::<Vec<_>>(),
            vec![
                1,
                SNAPSHOT_HEADER_BATCH + 1,
                SNAPSHOT_HEADER_BATCH * 2 + 1,
                SNAPSHOT_HEADER_BATCH * 3 + 1,
            ]
        );
        assert!(pipeline.refill_plan(false).is_empty());

        let headers = |start: u64, count: u16| {
            (start..start + u64::from(count))
                .map(|height| {
                    let mut header = noid_chain::consensus::genesis::genesis_header();
                    header.height = height;
                    header
                })
                .collect::<Vec<_>>()
        };
        // A later response may arrive first, but it cannot advance the
        // authoritative staging height.
        pipeline
            .accept(
                7,
                initial[1].token,
                peer,
                SNAPSHOT_HEADER_BATCH + 1,
                SNAPSHOT_HEADER_BATCH as u16,
                headers(SNAPSHOT_HEADER_BATCH + 1, SNAPSHOT_HEADER_BATCH as u16),
            )
            .unwrap();
        assert!(pipeline.take_ready(1).is_none());
        pipeline
            .accept(
                7,
                initial[0].token,
                peer,
                1,
                SNAPSHOT_HEADER_BATCH as u16,
                headers(1, SNAPSHOT_HEADER_BATCH as u16),
            )
            .unwrap();
        assert_eq!(
            pipeline.take_ready(1).unwrap().headers.len(),
            SNAPSHOT_HEADER_BATCH as usize
        );
        assert!(pipeline.refill_plan(true).is_empty());
        assert!(pipeline.take_ready(SNAPSHOT_HEADER_BATCH + 1).is_some());
        let refill = pipeline.refill_plan(true);
        assert_eq!(refill.len(), 1);
        assert_eq!(refill[0].start_height, SNAPSHOT_HEADER_BATCH * 4 + 1);
    }

    #[test]
    fn snapshot_header_transport_failure_retries_only_its_exact_range() {
        let peer = libp2p::PeerId::random();
        let alternate = libp2p::PeerId::random();
        let peers = std::collections::HashSet::from([peer, alternate]);
        let mut pipeline =
            SnapshotHeaderPipeline::new(7, test_snapshot_id(), peer, 1, SNAPSHOT_HEADER_BATCH * 3);
        let initial = pipeline.refill_plan(false);
        assert_eq!(initial.len(), 3);
        let failed = initial[1];
        let retry = pipeline
            .failure_plan(
                peer,
                failed.start_height,
                SNAPSHOT_HEADER_BATCH as u16,
                failed.token,
                noid_p2p::RequestFailureKind::Io,
                &peers,
            )
            .expect("failed exact range must be retried");
        assert_eq!(
            (retry.peer, retry.start_height, retry.count),
            (
                alternate,
                SNAPSHOT_HEADER_BATCH + 1,
                SNAPSHOT_HEADER_BATCH as u16
            )
        );
        assert!(pipeline.matches_outstanding(
            peer,
            1,
            SNAPSHOT_HEADER_BATCH as u16,
            initial[0].token
        ));
        assert!(!pipeline.matches_outstanding(
            peer,
            SNAPSHOT_HEADER_BATCH * 2 + 1,
            SNAPSHOT_HEADER_BATCH as u16,
            initial[2].token
        ));
        assert!(pipeline.matches_outstanding(
            alternate,
            SNAPSHOT_HEADER_BATCH + 1,
            SNAPSHOT_HEADER_BATCH as u16,
            retry.token
        ));
    }

    #[test]
    fn snapshot_header_timeout_reduces_only_the_slow_range() {
        let peer = libp2p::PeerId::random();
        let peers = std::collections::HashSet::from([peer]);
        let mut pipeline =
            SnapshotHeaderPipeline::new(9, test_snapshot_id(), peer, 1, SNAPSHOT_HEADER_BATCH * 2);
        let initial = pipeline.refill_plan(false).remove(0);
        let retry = pipeline
            .failure_plan(
                peer,
                initial.start_height,
                initial.count,
                initial.token,
                noid_p2p::RequestFailureKind::Timeout,
                &peers,
            )
            .unwrap();
        assert_eq!(retry.start_height, 1);
        assert_eq!(retry.count, (SNAPSHOT_HEADER_BATCH as u16) / 2);
        assert_eq!(pipeline.next_request_height, 1 + u64::from(retry.count));
    }

    #[test]
    fn snapshot_header_queue_pressure_preserves_the_exact_request() {
        let peer = libp2p::PeerId::random();
        let mut pipeline =
            SnapshotHeaderPipeline::new(9, test_snapshot_id(), peer, 1, SNAPSHOT_HEADER_BATCH);
        let request = pipeline.refill_plan(false).remove(0);
        pipeline.defer_dispatch(request).unwrap();
        let retried = pipeline.refill_plan(false);
        assert_eq!(retried, vec![request]);
        assert!(pipeline.matches_outstanding(
            request.peer,
            request.start_height,
            request.count,
            request.token,
        ));
    }

    #[test]
    fn snapshot_header_failures_try_every_connected_peer_before_reuse() {
        let first = libp2p::PeerId::random();
        let second = libp2p::PeerId::random();
        let third = libp2p::PeerId::random();
        let peers = std::collections::HashSet::from([first, second, third]);
        let mut pipeline =
            SnapshotHeaderPipeline::new(11, test_snapshot_id(), first, 1, SNAPSHOT_HEADER_BATCH);
        let initial = pipeline.refill_plan(false).pop().unwrap();
        let retry_one = pipeline
            .failure_plan(
                first,
                initial.start_height,
                initial.count,
                initial.token,
                noid_p2p::RequestFailureKind::InvalidResponse,
                &peers,
            )
            .unwrap();
        assert_ne!(retry_one.peer, first);
        let retry_two = pipeline
            .failure_plan(
                retry_one.peer,
                retry_one.start_height,
                retry_one.count,
                retry_one.token,
                noid_p2p::RequestFailureKind::InvalidResponse,
                &peers,
            )
            .unwrap();
        assert_ne!(retry_two.peer, first);
        assert_ne!(retry_two.peer, retry_one.peer);
    }

    #[test]
    fn snapshot_header_source_exhaustion_parks_the_exact_range() {
        let first = libp2p::PeerId::random();
        let second = libp2p::PeerId::random();
        let peers = std::collections::HashSet::from([first]);
        let mut pipeline =
            SnapshotHeaderPipeline::new(12, test_snapshot_id(), first, 1, SNAPSHOT_HEADER_BATCH);
        let request = pipeline.refill_plan(false).remove(0);
        assert!(pipeline
            .failure_plan(
                first,
                request.start_height,
                request.count,
                request.token,
                noid_p2p::RequestFailureKind::Io,
                &peers,
            )
            .is_none());
        assert!(pipeline.refill_plan(false).is_empty());
        assert!(!pipeline.is_drained());

        let resumed = pipeline
            .resume_blocked(
                &std::collections::HashSet::from([first, second]),
                std::time::Instant::now(),
            )
            .expect("a new source resumes the parked exact range");
        assert_eq!(resumed.peer, second);
        assert_eq!(resumed.start_height, request.start_height);
        assert_eq!(resumed.count, request.count);
    }

    #[test]
    fn snapshot_header_source_retry_rounds_are_bounded() {
        let peer = libp2p::PeerId::random();
        let peers = std::collections::HashSet::from([peer]);
        let mut pipeline =
            SnapshotHeaderPipeline::new(13, test_snapshot_id(), peer, 1, SNAPSHOT_HEADER_BATCH);
        let mut request = pipeline.refill_plan(false).remove(0);
        let started = std::time::Instant::now();

        for round in 0..3 {
            assert!(pipeline
                .failure_plan(
                    peer,
                    request.start_height,
                    request.count,
                    request.token,
                    noid_p2p::RequestFailureKind::Io,
                    &peers,
                )
                .is_none());
            request = pipeline
                .resume_blocked(
                    &peers,
                    started + std::time::Duration::from_secs((round + 1) * 6),
                )
                .expect("bounded retry round is available");
        }

        assert!(pipeline
            .failure_plan(
                peer,
                request.start_height,
                request.count,
                request.token,
                noid_p2p::RequestFailureKind::Io,
                &peers,
            )
            .is_none());
        assert!(pipeline
            .resume_blocked(&peers, started + std::time::Duration::from_secs(30))
            .is_none());
        assert!(pipeline.is_parked_without_source());
    }

    #[test]
    fn delayed_snapshot_header_generation_is_inert() {
        let current_peer = libp2p::PeerId::random();
        let mut pipeline =
            SnapshotHeaderPipeline::new(8, test_snapshot_id(), current_peer, 1, 5_000);
        let plan = pipeline.refill_plan(false);
        assert_eq!(plan.len(), 2);
        assert_eq!(
            (plan[0].start_height, plan[0].count),
            (1, SNAPSHOT_HEADER_BATCH as u16)
        );
        assert!(!pipeline.matches_generation(7));
        assert!(pipeline.matches_generation(8));
        assert!(
            pipeline.matches_outstanding(
                current_peer,
                1,
                SNAPSHOT_HEADER_BATCH as u16,
                plan[0].token
            ),
            "stale response filtering cannot consume the active window"
        );
    }

    #[test]
    fn empty_manifest_response_round_is_retried_after_deadline() {
        let started = std::time::Instant::now();
        assert!(!manifest_round_retry_due(
            Some(started),
            started + STATE_MANIFEST_RESPONSE_TIMEOUT - std::time::Duration::from_millis(1),
        ));
        assert!(manifest_round_retry_due(
            Some(started),
            started + STATE_MANIFEST_RESPONSE_TIMEOUT,
        ));
    }

    #[test]
    fn snapshot_manifest_selection_waits_for_the_bounded_discovery_window() {
        let started = std::time::Instant::now();
        assert!(!manifest_candidate_selection_due(
            None,
            started + STATE_MANIFEST_CANDIDATE_SETTLE,
        ));
        assert!(!manifest_candidate_selection_due(
            Some(started),
            started + STATE_MANIFEST_CANDIDATE_SETTLE - std::time::Duration::from_millis(1),
        ));
        assert!(manifest_candidate_selection_due(
            Some(started),
            started + STATE_MANIFEST_CANDIDATE_SETTLE,
        ));
    }

    #[test]
    fn snapshot_manifest_selection_replaces_the_first_stale_candidate() {
        let mut first = noid_p2p::protocol::GetStateManifestResponse::default();
        first.tip_height = 27_072;
        first.tip_hash = [0x22; 32];
        first.cumulative_chainwork[0] = 1;
        first.bridge_tip_height = 27_091;
        first.bridge_tip_hash = [0x33; 32];
        first.bridge_cumulative_chainwork[0] = 2;

        let mut fresher = first.clone();
        fresher.tip_height = 27_078;
        fresher.tip_hash = [0x11; 32];
        fresher.cumulative_chainwork[0] = 2;
        fresher.bridge_tip_height = 27_097;
        fresher.bridge_tip_hash = [0x10; 32];
        fresher.bridge_cumulative_chainwork[0] = 3;

        assert!(state_manifest_candidate_is_preferred(&fresher, &first));
        assert!(!state_manifest_candidate_is_preferred(&first, &fresher));
    }

    #[test]
    fn snapshot_manifest_selection_uses_the_canonical_hash_tiebreak() {
        let mut current = noid_p2p::protocol::GetStateManifestResponse::default();
        current.bridge_tip_height = 27_091;
        current.bridge_tip_hash = [0x22; 32];
        current.bridge_cumulative_chainwork[0] = 2;

        let mut better_hash = current.clone();
        better_hash.bridge_tip_hash = [0x10; 32];

        assert!(state_manifest_candidate_is_preferred(
            &better_hash,
            &current,
        ));
        assert!(!state_manifest_candidate_is_preferred(
            &current,
            &better_hash,
        ));
    }

    #[test]
    fn bounded_manifest_retries_rotate_across_six_peers() {
        let peers = (0..6)
            .map(|_| libp2p::PeerId::random())
            .collect::<std::collections::HashSet<_>>();
        let mut cursor = 0;
        let excluded = std::collections::HashSet::new();
        let first = rotating_manifest_peers(&peers, &excluded, None, false, &mut cursor, 3);
        let second = rotating_manifest_peers(&peers, &excluded, None, false, &mut cursor, 3);
        assert_eq!(first.len(), 3);
        assert_eq!(second.len(), 3);
        assert_eq!(
            first
                .into_iter()
                .chain(second)
                .collect::<std::collections::HashSet<_>>(),
            peers
        );
    }

    #[test]
    fn empty_snapshot_provider_rounds_reach_the_extinction_threshold() {
        let mut rounds = 0;
        for _ in 0..EXACT_PLAN_DISCOVERY_ROUNDS {
            rounds = complete_snapshot_provider_discovery_round(rounds, 0);
        }
        assert_eq!(rounds, EXACT_PLAN_DISCOVERY_ROUNDS);
    }

    #[test]
    fn manifest_round_becomes_obsolete_when_announced_gap_is_closed() {
        assert!(!manifest_round_gap_is_resolved(99, 100));
        assert!(manifest_round_gap_is_resolved(100, 100));
        assert!(manifest_round_gap_is_resolved(101, 100));
    }

    #[test]
    fn stale_gap_recovery_never_duplicates_an_active_canonical_transition() {
        assert!(!stale_gap_recovery_is_due(29, 99, 100, false));
        assert!(stale_gap_recovery_is_due(30, 99, 100, false));
        assert!(!stale_gap_recovery_is_due(30, 99, 100, true));
        assert!(!stale_gap_recovery_is_due(30, 100, 100, false));
    }

    #[test]
    fn snapshot_header_progress_rejects_delayed_and_oversized_batches() {
        assert_eq!(
            snapshot_header_next_action(10, 20).unwrap(),
            SnapshotHeaderNextAction::Fetch {
                start_height: 10,
                count: 11,
            }
        );
        assert_eq!(
            snapshot_header_next_action(21, 20).unwrap(),
            SnapshotHeaderNextAction::RequestTerminal
        );
        assert!(snapshot_header_next_action(22, 20).is_err());

        assert!(validate_snapshot_header_batch_admission(20, 20, 1).is_ok());
        assert!(validate_snapshot_header_batch_admission(21, 20, 1).is_err());
        assert!(validate_snapshot_header_batch_admission(20, 20, 0).is_err());
        assert!(validate_snapshot_header_batch_admission(20, 20, 2).is_err());
        assert!(validate_snapshot_header_batch_admission(
            1,
            1_000,
            super::MAX_STAGED_HEADER_BATCH + 1,
        )
        .is_err());
    }

    fn test_coinbase_child(
        parent: &noid_chain::BlockHeader,
        state: &noid_chain::ChainState,
    ) -> noid_chain::block::Block {
        let timestamp = parent.timestamp + noid_chain::consensus::params::BLOCK_TIME;
        let difficulty_target = noid_chain::consensus::difficulty::next_target(
            0,
            parent.timestamp,
            &parent.difficulty_target,
            parent.height + 1,
            timestamp,
        );
        let template = noid_chain::consensus::build_block_template(
            parent,
            state,
            &[parent.active_slot_count],
            vec![],
            noid_poseidon2b::primitives::Address([0x22; 32]),
            timestamp,
            difficulty_target,
        )
        .expect("canonical coinbase child template");
        let transactions = template.all_txs();
        let header = template.into_header(0);
        noid_chain::block::Block {
            header,
            transactions,
        }
    }

    #[test]
    fn snapshot_history_boundary_checks_staged_header_chainwork() {
        let state = noid_chain::ChainState::with_log_slots(
            noid_chain::consensus::params::LOG_SLOTS_GENESIS
                .try_into()
                .expect("genesis log_slots fits usize"),
        );
        let h0 = noid_chain::consensus::genesis_header();
        let h0_hash = noid_chain::hash_block_header(&h0);
        let high_start_work = noid_chain::consensus::block_work(&h0.difficulty_target);

        let block = test_coinbase_child(&h0, &state);
        let h1 = block.header;
        let h1_hash = noid_chain::hash_block_header(&h1);
        let h1_work = noid_chain::consensus::add_work(
            &high_start_work,
            &noid_chain::consensus::block_work(&h1.difficulty_target),
        );
        let mut manifest = noid_p2p::protocol::GetStateManifestResponse {
            tip_height: 1,
            tip_hash: h1_hash,
            cumulative_chainwork: h1_work,
            state_root: h1.state_root,
            log_slots: h1.log_slots,
            active_slot_count: h1.active_slot_count,
            alloc_counter: h1.alloc_counter,
            bridge_tip_height: 1,
            bridge_tip_hash: h1_hash,
            bridge_cumulative_chainwork: h1_work,
            format_version: noid_p2p::protocol::SNAPSHOT_MANIFEST_FORMAT_VERSION,
            ..Default::default()
        };
        assert!(manifest.seal_manifest_digest());
        let boundary = SnapshotHeaderBoundary {
            tip_header: h1,
            tip_hash: h1_hash,
            cumulative_chainwork: h1_work,
            epoch_anchor_header: h0,
        };
        validate_snapshot_staged_header_boundary(&manifest, &boundary)
            .expect("staged snapshot boundary preflight succeeds");
        assert_eq!(boundary.tip_header, h1);
        assert_eq!(boundary.epoch_anchor_header, h0);

        let mut wrong_fork = boundary;
        wrong_fork.tip_hash = h0_hash;
        assert!(
            validate_snapshot_staged_header_boundary(&manifest, &wrong_fork)
                .expect_err("manifest for another staged fork must reject")
                .contains("boundary")
        );

        let mut bad = manifest.clone();
        bad.cumulative_chainwork = [3u8; 32];
        assert!(bad.seal_manifest_digest());
        assert!(validate_snapshot_staged_header_boundary(&bad, &boundary)
            .expect_err("bad chainwork must reject")
            .contains("chainwork"));
    }

    #[test]
    fn snapshot_epoch_anchor_obeys_start_of_block_boundaries() {
        for (tip_height, expected_epoch_height) in [
            (143, 0),
            (144, 0),
            (145, 144),
            (5_327, 5_184),
            (5_328, 5_184),
            (5_329, 5_328),
        ] {
            let mut tip_header = noid_chain::consensus::genesis_header();
            tip_header.height = tip_height;
            let tip_hash = noid_chain::hash_block_header(&tip_header);
            let cumulative_chainwork = [0xA5; 32];
            let mut manifest = noid_p2p::protocol::GetStateManifestResponse {
                tip_height,
                tip_hash,
                cumulative_chainwork,
                state_root: tip_header.state_root,
                log_slots: tip_header.log_slots,
                active_slot_count: tip_header.active_slot_count,
                alloc_counter: tip_header.alloc_counter,
                bridge_tip_height: tip_height,
                bridge_tip_hash: tip_hash,
                bridge_cumulative_chainwork: cumulative_chainwork,
                format_version: noid_p2p::protocol::SNAPSHOT_MANIFEST_FORMAT_VERSION,
                ..Default::default()
            };
            assert!(manifest.seal_manifest_digest());
            let mut epoch_anchor_header = noid_chain::consensus::genesis_header();
            epoch_anchor_header.height = expected_epoch_height;
            let boundary = SnapshotHeaderBoundary {
                tip_header,
                tip_hash,
                cumulative_chainwork,
                epoch_anchor_header,
            };

            validate_snapshot_staged_header_boundary(&manifest, &boundary).unwrap_or_else(
                |error| {
                    panic!(
                        "tip {tip_height} must accept epoch anchor {expected_epoch_height}: {error}"
                    )
                },
            );
        }

        let tip_height = noid_chain::consensus::params::TX_EPOCH_BLOCKS;
        let mut tip_header = noid_chain::consensus::genesis_header();
        tip_header.height = tip_height;
        let tip_hash = noid_chain::hash_block_header(&tip_header);
        let cumulative_chainwork = [0x5A; 32];
        let mut manifest = noid_p2p::protocol::GetStateManifestResponse {
            tip_height,
            tip_hash,
            cumulative_chainwork,
            state_root: tip_header.state_root,
            log_slots: tip_header.log_slots,
            active_slot_count: tip_header.active_slot_count,
            alloc_counter: tip_header.alloc_counter,
            bridge_tip_height: tip_height,
            bridge_tip_hash: tip_hash,
            bridge_cumulative_chainwork: cumulative_chainwork,
            format_version: noid_p2p::protocol::SNAPSHOT_MANIFEST_FORMAT_VERSION,
            ..Default::default()
        };
        assert!(manifest.seal_manifest_digest());
        let mut wrong_anchor = noid_chain::consensus::genesis_header();
        wrong_anchor.height = tip_height;
        let boundary = SnapshotHeaderBoundary {
            tip_header,
            tip_hash,
            cumulative_chainwork,
            epoch_anchor_header: wrong_anchor,
        };
        assert!(
            validate_snapshot_staged_header_boundary(&manifest, &boundary)
                .expect_err("a boundary block cannot activate itself as its own epoch anchor")
                .contains("epoch anchor")
        );
    }

    #[test]
    fn snapshot_history_step_tip_obeys_local_future_drift_admission() {
        let local_time = 1_000_000u64;
        let mut tip = noid_chain::consensus::genesis::genesis_header();
        tip.timestamp = local_time + noid_chain::consensus::params::MAX_FUTURE_DRIFT;
        let mut boundary = SnapshotHeaderBoundary {
            tip_header: tip,
            tip_hash: noid_chain::hash_block_header(&tip),
            cumulative_chainwork: [0u8; 32],
            epoch_anchor_header: tip,
        };
        validate_history_step_tip_future_drift(&boundary, local_time)
            .expect("exact future-drift boundary is admitted");

        boundary.tip_header.timestamp += 1;
        assert!(
            validate_history_step_tip_future_drift(&boundary, local_time)
                .expect_err("far-future HistoryStep terminal tip must reject")
                .contains("future drift")
        );
    }
}

fn resolve_tx_gossip(
    p2p_cmd: &noid_p2p::NetworkCommandSender,
    propagation_source: libp2p::PeerId,
    message_id: Option<libp2p::gossipsub::MessageId>,
    acceptance: libp2p::gossipsub::MessageAcceptance,
) {
    let Some(message_id) = message_id else {
        return;
    };
    if let Err(error) = p2p_cmd.try_send(noid_p2p::NetworkCommand::ResolveTxGossip {
        message_id,
        propagation_source,
        acceptance,
    }) {
        tracing::debug!(peer = %propagation_source, %error, "tx gossip validation result could not be queued");
    }
}

async fn handle_p2p_events(
    mut rx: noid_p2p::NetworkEventReceiver,
    chain: Arc<RwLock<MdbxChainContext>>,
    mempool: AsyncMempool,
    wallet: SharedWallet,
    p2p_cmd: noid_p2p::NetworkCommandSender,
    initial_sync_ready: tokio::sync::watch::Sender<bool>,
    initial_sync_stage_tx: tokio::sync::watch::Sender<NodeSyncStage>,
    mut mining_peer_quorum: MiningPeerQuorum,
    template_changes: tokio::sync::broadcast::Sender<()>,
    wallet_operation_gate: WalletOperationGate,
    snapshot_staging_root: PathBuf,
    history_step_runtime: Option<Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>>,
    external_mining_attempts: ExternalMiningAttemptInvalidator,
    mut canonical_tip_changes: tokio::sync::watch::Receiver<noid_p2p::object_protocol::ChainPoint>,
) -> anyhow::Result<()> {
    use noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH;
    use std::collections::HashMap;
    let mut snapshot_rebase_hint: Option<SnapshotRebaseHint> = None;
    {
        let ctx = chain.read().await;
        mining_peer_quorum.set_canonical_tip(ctx.tip_height(), ctx.tip_hash(), false);
    }

    // --- Snapshot verification state ---
    //
    // Snapshot sync:
    //   (1) receive an immutable exact-state snapshot manifest
    //   (2) verify the O(1) HistoryStep terminal for that boundary
    //       before segment download
    // --- Segmented state sync state ---
    //
    // All live catch-up and non-final reorganization work is selected by the
    // HeaderDAG and fetched as exact objects. Snapshot admission authenticates
    // one immutable boundary; later blocks use the same exact suffix path.
    // A manifest starts bounded speculative work immediately. Concurrent peer
    // probes remain live so PoW fork choice is not frozen by connection order.
    // Source leases are deliberately separate from this authority. A peer
    // disconnect may rotate transport, but cannot retire the plan or erase
    // verified headers, proof authority, or State segments.
    struct PendingManifest {
        preferred_peer: libp2p::PeerId,
        providers: std::collections::HashSet<libp2p::PeerId>,
        /// Canonical point from which this generation is permitted to replace
        /// a local non-final branch. None means the manifest was staged as a
        /// direct continuation of the current canonical tip.
        rebase_base: Option<noid_node::networking::ChainPoint>,
        manifest: noid_p2p::protocol::VerifiedStateManifest,
        offer: noid_node::networking::snapshot_sync::SnapshotOffer,
        history_step: Option<VerifiedHistoryStepSnapshot>,
    }
    struct SnapshotManifestCandidate {
        from: libp2p::PeerId,
        manifest: noid_p2p::protocol::VerifiedStateManifest,
        rebase_anchor: Option<SnapshotRebaseAnchor>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SnapshotHeaderStagingOperationKey {
        Prepare {
            generation: u64,
            token: u64,
            snapshot: noid_node::networking::SnapshotId,
        },
        Append {
            generation: u64,
            token: u64,
            snapshot: noid_node::networking::SnapshotId,
            range_from: libp2p::PeerId,
            start_height: u64,
            count: u16,
        },
    }
    enum SnapshotHeaderStagingResult {
        Success(PendingSnapshotHeaderSync),
        PrepareBaseMoved(String),
        BaseMoved {
            sync: PendingSnapshotHeaderSync,
            error: SnapshotHeaderStagingError,
        },
        CandidateRejected {
            sync: PendingSnapshotHeaderSync,
            attempted_peers: std::collections::HashSet<libp2p::PeerId>,
            error: SnapshotHeaderStagingError,
        },
        Fatal(String),
    }
    struct SnapshotHeaderStagingCompletion {
        key: SnapshotHeaderStagingOperationKey,
        work_elapsed: std::time::Duration,
        result: SnapshotHeaderStagingResult,
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct HistoryStepVerificationKey {
        token: u64,
        terminal_request_token: u64,
        snapshot: noid_node::networking::SnapshotId,
        /// Peer that supplied the terminal bytes being verified.
        terminal_from: libp2p::PeerId,
        height: u64,
        block_hash: [u8; 32],
    }
    struct HistoryStepVerificationCompletion {
        key: HistoryStepVerificationKey,
        generation: u64,
        manifest: noid_p2p::protocol::VerifiedStateManifest,
        header_validation_elapsed: std::time::Duration,
        terminal_measurement: Option<SyncPhaseMeasurement>,
        staged_header_count: u64,
        result: SnapshotBoundaryVerificationOutcome,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SnapshotStagingOperationKey {
        Accept {
            generation: u64,
            snapshot: noid_node::networking::SnapshotId,
            from: libp2p::PeerId,
            segment_id: u16,
        },
        Finalize {
            generation: u64,
            snapshot: noid_node::networking::SnapshotId,
        },
    }
    enum SnapshotStagingCompletion {
        Accepted {
            key: SnapshotStagingOperationKey,
            payload_bytes: u64,
            work_elapsed: std::time::Duration,
            result: SnapshotSegmentStageResult,
        },
        Finalized {
            key: SnapshotStagingOperationKey,
            segment_count: usize,
            work_elapsed: std::time::Duration,
            result: SnapshotFinalizationOutcome,
        },
    }
    enum SnapshotSegmentStageResult {
        Accepted(SnapshotStagingSession),
        SourceRejected {
            staging: SnapshotStagingSession,
            error: String,
        },
        CandidateRejected(String),
        Fatal(String),
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SnapshotBoundaryTerminalKey {
        generation: u64,
        snapshot: noid_node::networking::SnapshotId,
        requests: TerminalRequestRace,
        height: u64,
        block_hash: [u8; 32],
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct BoundaryProofMaintenanceKey {
        target: BoundaryProofTarget,
        requests: TerminalRequestRace,
    }
    enum BoundaryProofMaintenanceResult {
        Cached,
        TerminalRejected(String),
        LocalFailure(String),
    }
    struct BoundaryProofMaintenanceCompletion {
        target: BoundaryProofTarget,
        from: libp2p::PeerId,
        result: BoundaryProofMaintenanceResult,
    }
    struct PrefetchedHistoryStepTerminal {
        token: u64,
        from: libp2p::PeerId,
        terminal_bytes: Vec<u8>,
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    }
    struct ExactSuffixApplyCompletion {
        plan_id: noid_node::networking::PlanId,
        target: noid_node::networking::ChainPoint,
        tip_announcement: noid_p2p::header_protocol::HeaderAnnouncement,
        confirmation_sources: Vec<libp2p::PeerId>,
        result: Result<AppliedExactSuffix, ExactSuffixApplyError>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SnapshotInstallKey {
        generation: u64,
        snapshot: noid_node::networking::SnapshotId,
        /// A peer that observed the exact boundary, used only to refresh
        /// post-install liveness. It is not part of snapshot authority.
        observer_peer: libp2p::PeerId,
        terminal_from: Option<libp2p::PeerId>,
        terminal_request_token: Option<u64>,
        height: u64,
        block_hash: [u8; 32],
    }
    struct SnapshotInstallCompletion {
        key: SnapshotInstallKey,
        result: Result<AppliedVerifiedSnapshot, SnapshotInstallError>,
    }
    let mut pending_manifest: Option<PendingManifest> = None;
    // One bounded pre-install selection prevents response order from fixing an
    // obsolete generation. Only the strongest manifest body is retained, and
    // every claimed chain field is still checked against native headers before
    // the candidate can authorize State.
    let mut best_manifest_candidate: Option<SnapshotManifestCandidate> = None;
    let mut manifest_candidate_started_at: Option<std::time::Instant> = None;
    let mut active_snapshot_sync: Option<noid_node::networking::snapshot_sync::SnapshotSync> = None;
    let mut candidate_manifest_providers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    let mut rejected_snapshot_manifest_providers =
        std::collections::HashMap::<[u8; 32], std::collections::HashSet<libp2p::PeerId>>::new();
    let mut last_snapshot_provider_probe = Instant::now()
        .checked_sub(Duration::from_secs(5))
        .unwrap_or_else(Instant::now);
    let mut snapshot_plan_last_progress: Option<Instant> = None;
    let mut snapshot_provider_discovery_rounds = 0u8;
    let mut pending_snapshot_header_sync: Option<PendingSnapshotHeaderSync> = None;
    let mut snapshot_header_pipeline: Option<SnapshotHeaderPipeline> = None;
    let (snapshot_header_staging_tx, mut snapshot_header_staging_rx) =
        tokio::sync::mpsc::channel::<SnapshotHeaderStagingCompletion>(1);
    let mut snapshot_header_staging_inflight: Option<SnapshotHeaderStagingOperationKey> = None;
    let mut snapshot_header_staging_token = 0u64;
    let (history_step_verification_tx, mut history_step_verification_rx) =
        tokio::sync::mpsc::channel::<HistoryStepVerificationCompletion>(1);
    let mut history_step_verification_inflight: Option<HistoryStepVerificationKey> = None;
    // A rejected terminal only retires that byte source. The already sealed,
    // native-validated header authority remains available for an alternate
    // terminal without another O(height) pass or network download.
    let mut retained_snapshot_headers: Option<RetainedSnapshotHeaderAuthority> = None;
    let mut history_step_verification_token = 0u64;
    // Snapshot payload CPU/disk work is strictly serialized.  The bounded
    // completion channels cannot accumulate segment-sized allocations: each
    // completion owns only the compact staging session or finalized handle.
    let (snapshot_staging_completion_tx, mut snapshot_staging_completion_rx) =
        tokio::sync::mpsc::channel::<SnapshotStagingCompletion>(1);
    let mut snapshot_staging_inflight: Option<SnapshotStagingOperationKey> = None;
    let mut snapshot_boundary_terminal_inflight: Option<SnapshotBoundaryTerminalKey> = None;
    let mut boundary_proof_maintenance_inflight: Option<BoundaryProofMaintenanceKey> = None;
    let (boundary_proof_maintenance_tx, mut boundary_proof_maintenance_rx) =
        tokio::sync::mpsc::channel::<BoundaryProofMaintenanceCompletion>(1);
    let mut boundary_proof_verification_inflight: Option<BoundaryProofTarget> = None;
    let mut last_boundary_proof_maintenance = Instant::now()
        .checked_sub(Duration::from_secs(5))
        .unwrap_or_else(Instant::now);
    let mut snapshot_terminal_retry_after: std::collections::HashMap<libp2p::PeerId, Instant> =
        std::collections::HashMap::new();
    let mut snapshot_terminal_transport_failures =
        std::collections::HashMap::<SnapshotTerminalSourceKey, u8>::new();
    let mut snapshot_terminal_exhausted =
        std::collections::HashSet::<SnapshotTerminalSourceKey>::new();
    let mut prefetched_snapshot_boundary_terminal: Option<PrefetchedHistoryStepTerminal> = None;
    let mut history_step_request_token = 0u64;
    let (exact_suffix_apply_tx, mut exact_suffix_apply_rx) =
        tokio::sync::mpsc::channel::<ExactSuffixApplyCompletion>(1);
    let mut active_suffix_sync: Option<noid_node::networking::suffix_sync::SuffixSync> = None;
    let mut suffix_plan_last_progress: Option<Instant> = None;
    let mut suffix_provider_discovery_rounds = 0u8;
    let mut suffix_inventory_probe_peers = std::collections::HashSet::<libp2p::PeerId>::new();
    let mut exact_suffix_apply_inflight: Option<noid_node::networking::PlanId> = None;
    let mut peer_failure_domains: std::collections::HashMap<
        libp2p::PeerId,
        noid_node::networking::FailureDomain,
    > = std::collections::HashMap::new();
    let mut finalized_snapshot_waiting: Option<(FinalizedSnapshotStaging, usize)> = None;
    let (snapshot_install_completion_tx, mut snapshot_install_completion_rx) =
        tokio::sync::mpsc::channel::<SnapshotInstallCompletion>(1);
    let mut snapshot_install_inflight: Option<SnapshotInstallKey> = None;
    let mut snapshot_sync_generation = 0u64;
    let mut p2p_snapshot_generation_announced = 0u64;
    let snapshot_sync_generation_guard = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // One fixed-size set of scalar phase totals for the active snapshot sync.
    // No per-header, per-segment, or per-block timing history is retained.
    let mut sync_phase_telemetry = SnapshotSyncTelemetry::default();
    let snapshot_header_store = {
        let ctx = chain.read().await;
        ctx.store.clone()
    };
    let (mut header_dag, mut header_dag_canonical_tip) = {
        let ctx = chain.read().await;
        let canonical_tip =
            noid_node::networking::ChainPoint::new(ctx.tip_height(), ctx.tip_hash());
        let dag = canonical_header_dag(&ctx)
            .expect("validated durable chain must reconstruct the bounded header DAG");
        (dag, canonical_tip)
    };
    let mut header_dag_faulted = false;
    let mut last_header_dag_reconcile_attempt = Instant::now();
    // Segment staging is intentionally wiped on startup; validated header
    // candidates are separately crash-resumable and therefore use a sibling.
    let snapshot_header_staging_root =
        snapshot_staging_root.with_file_name("snapshot-header-staging");
    // Tracks peers already asked; cleared on failure so recovery is automatic.
    let mut manifest_requested_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    // Tracks peers for forced snapshot attempts. The manifest advertises the
    // snapshot boundary, so non-empty responses stay on the snapshot path.
    let mut manifest_force_snapshot_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    // Count of manifest responses received (including tip=0 "no state" replies).
    // Used only to diagnose and recover rounds that produced no usable response.
    let mut manifest_response_count: usize = 0;
    // Set while a manifest round is waiting for at least one usable candidate.
    // Empty responses mean the peer has no usable immutable generation, so
    // receiving a response alone must not disarm the retry timer.
    let mut manifest_round_started_at: Option<std::time::Instant> = None;
    // Connected peers eligible for manifest (re-)requests.
    let mut manifest_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    // A bounded subset selected by our own topology manager. Inbound peers
    // can serve content and gossip normally, but never make a public node fan
    // out one new bootstrap round per connection.
    let mut locally_selected_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    let mut manifest_terminal_capabilities: std::collections::HashMap<
        libp2p::PeerId,
        ManifestTerminalCapability,
    > = std::collections::HashMap::new();
    // A peer that supplied an exact-bound but cryptographically invalid
    // recursive terminal has proved that its terminal service is unusable for
    // this process lifetime. Do not let a fast invalid hedge preempt an honest
    // peer again on the next snapshot generation.
    let mut rejected_terminal_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    // Exact object bytes are content-addressed, but content identity alone
    // does not prove transaction/state semantics or a recursive terminal.
    // Once a provider supplies bytes that fail those checks, keep its headers
    // but never use its object inventory again during this process.
    let mut rejected_suffix_object_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    // A peer whose authenticated header view has no common ancestor in our
    // complete non-final window cannot be used for an automatic rebase. Keep
    // it out of snapshot selection for this connection lifetime instead of
    // cycling through manifests guaranteed to fail at the first parent link.
    let mut finalized_divergent_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    let mut mempool_sync_requested_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    // Bounded retries rotate through the connected set instead of repeatedly
    // selecting the same HashSet iteration prefix.
    let mut manifest_retry_cursor = 0usize;
    // Independent round-robin cursor for the single steady-state tip lane.
    // This never fans one logical probe out across the peer set.
    let mut steady_tip_probe_cursor = 0usize;
    let mut last_steady_tip_probe = Instant::now();
    let mut last_mining_quorum_probe = Instant::now()
        .checked_sub(MINING_QUORUM_PROBE_INTERVAL)
        .unwrap_or_else(Instant::now);
    let mut exact_inventory_probe_cursor = 0usize;
    let mut last_exact_inventory_probe = Instant::now()
        .checked_sub(Duration::from_secs(2))
        .unwrap_or_else(Instant::now);
    let mut last_snapshot_rebase_probe: Option<Instant> = None;
    // Payloads are authenticated one at a time and sealed to disk.  The
    // session retains only compact descriptors and a received bitset.
    let mut snapshot_staging: Option<SnapshotStagingSession> = None;
    // One complete response may wait behind the single disk/authentication
    // worker. Together they form a strict two-segment pipeline; no response is
    // discarded and downloaded again merely because the worker is busy.
    let mut queued_segment_response: Option<(
        libp2p::PeerId,
        noid_p2p::protocol::GetStateSegmentResponse,
    )> = None;
    // Segment IDs still outstanding.

    // Clear only manifest-round bookkeeping. Unlike retire_snapshot_plan!, this
    // does not disturb an already-applied direct suffix, orphan pool, or any
    // unrelated recovery state.
    macro_rules! clear_manifest_round_state {
        () => {{
            manifest_requested_peers.clear();
            manifest_force_snapshot_peers.clear();
            manifest_response_count = 0;
            manifest_round_started_at = None;
            candidate_manifest_providers.clear();
            best_manifest_candidate = None;
            manifest_candidate_started_at = None;
        }};
    }

    /// Snapshot generation retirement is a durable control-plane command. If
    /// the bounded control lane is momentarily full, the heartbeat retries it
    /// until the swarm has discarded every older paging job.
    macro_rules! dispatch_snapshot_generation_advance {
        () => {{
            if p2p_snapshot_generation_announced != snapshot_sync_generation
                && p2p_cmd
                    .try_send(noid_p2p::NetworkCommand::AdvanceSnapshotGeneration {
                        generation: snapshot_sync_generation,
                    })
                    .is_ok()
            {
                p2p_snapshot_generation_announced = snapshot_sync_generation;
            }
        }};
    }

    /// Manifest discovery is a Wanted job, not an awaited action in the
    /// authoritative event loop. A saturated data lane leaves the peer
    /// eligible for the next bounded retry instead of pretending a request is
    /// in flight.
    macro_rules! try_request_manifest {
        ($peer:expr, $requester_height:expr, $digest:expr) => {{
            let peer = $peer;
            if manifest_requested_peers.contains(&peer) {
                false
            } else if p2p_cmd
                .try_send(noid_p2p::NetworkCommand::RequestStateManifest {
                    generation: snapshot_sync_generation,
                    peer,
                    requester_height: $requester_height,
                    requested_manifest_digest: $digest,
                })
                .is_ok()
            {
                manifest_requested_peers.insert(peer);
                manifest_round_started_at.get_or_insert_with(Instant::now);
                true
            } else {
                tracing::debug!(peer = %peer, "snapshot manifest remains Wanted behind bounded data lane");
                false
            }
        }};
    }

    /// Terminal requests retain their exact identity until the bounded data
    /// lane accepts them. Local queue pressure is neither a peer failure nor a
    /// reason to abandon verified snapshot headers.
    macro_rules! dispatch_pending_boundary_terminal_requests {
        () => {{
            if let Some(pending) = snapshot_boundary_terminal_inflight.as_mut() {
                let requests = pending.requests.pending().collect::<Vec<_>>();
                for request in requests {
                    if p2p_cmd
                        .try_send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                            token: request.token,
                            peer: request.peer,
                            height: pending.height,
                            block_hash: pending.block_hash,
                        })
                        .is_ok()
                    {
                        let marked = pending
                            .requests
                            .mark_dispatched(request.peer, request.token);
                        debug_assert!(marked, "pending terminal request must become active");
                    } else {
                        break;
                    }
                }
            }
        }};
    }

    /// Operational proof availability uses the same exact terminal protocol
    /// as snapshot admission but owns an independent Wanted job. Queue
    /// pressure cannot perturb canonical synchronization.
    macro_rules! dispatch_boundary_proof_maintenance_requests {
        () => {{
            if let Some(pending) = boundary_proof_maintenance_inflight.as_mut() {
                let requests = pending.requests.pending().collect::<Vec<_>>();
                for request in requests {
                    if p2p_cmd
                        .try_send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                            token: request.token,
                            peer: request.peer,
                            height: pending.target.height(),
                            block_hash: pending.target.block_hash(),
                        })
                        .is_ok()
                    {
                        let marked = pending
                            .requests
                            .mark_dispatched(request.peer, request.token);
                        debug_assert!(
                            marked,
                            "pending proof maintenance request must become active"
                        );
                    } else {
                        break;
                    }
                }
            }
        }};
    }

    macro_rules! ensure_snapshot_boundary_terminal_request {
        () => {{
            if snapshot_boundary_terminal_inflight.is_none()
                && history_step_verification_inflight.is_none()
                && prefetched_snapshot_boundary_terminal.is_none()
            {
                // The exact terminal is independently content-addressed and
                // inbound-memory-bounded. Fetch it as soon as the immutable
                // manifest is selected, then verify it only after native header
                // staging reaches the boundary. This overlaps transport with
                // O(height) header validation without weakening authority.
                let ready = pending_manifest
                    .as_ref()
                    .filter(|pending| pending.history_step.is_none())
                    .map(|pending| {
                        let snapshot = pending.offer.snapshot_id();
                        (
                            snapshot,
                            pending.preferred_peer,
                            snapshot.boundary.height,
                            snapshot.boundary.hash,
                        )
                    });
                if let Some((snapshot, preferred, height, block_hash)) = ready {
                    if let Some(peer) = advertised_terminal_peer(
                        &manifest_peers,
                        &manifest_terminal_capabilities,
                        &rejected_terminal_peers,
                        &snapshot_terminal_exhausted,
                        &snapshot_terminal_retry_after,
                        preferred,
                        height,
                        block_hash,
                        Instant::now(),
                    ) {
                        history_step_request_token = history_step_request_token.wrapping_add(1);
                        snapshot_boundary_terminal_inflight = Some(SnapshotBoundaryTerminalKey {
                            generation: snapshot_sync_generation,
                            snapshot,
                            requests: TerminalRequestRace::new(peer, history_step_request_token),
                            height,
                            block_hash,
                        });
                    }
                }
            }
            dispatch_pending_boundary_terminal_requests!();
        }};
    }

    // Transport loss must not erase the expensive exact header prefix. The
    // staging file is already native-validated and crash-safe. Dropping its
    // handle closes the descriptor but deliberately leaves the exact-boundary
    // file for the next manifest lease to reopen and revalidate.
    macro_rules! preserve_active_snapshot_headers {
        () => {{
            if let Some(sync) = pending_snapshot_header_sync.take() {
                let staged_headers = sync.staging.staged_len();
                let staging_path = sync.staging.path().to_owned();
                drop(sync.staging);
                tracing::debug!(
                    staged_headers,
                    path = %staging_path.display(),
                    "retained exact snapshot header staging across transport loss"
                );
            }
            // Verified HistoryStep authority remains owned by the immutable
            // PendingManifest. Transport recovery must never take or drop it.
        }};
    }

    // Retire one complete immutable snapshot plan. Transport loss, a busy
    // provider, a malformed exact object, or a missing segment must never call
    // this: those conditions rotate only the affected source lease. This is
    // reserved for a proven-stale base, a completed install, or an explicitly
    // abandoned candidate before it owns verified authority.
    macro_rules! retire_snapshot_plan {
        () => {{
            snapshot_sync_generation = snapshot_sync_generation.wrapping_add(1);
            sync_phase_telemetry.reset();
            snapshot_sync_generation_guard.store(
                snapshot_sync_generation,
                std::sync::atomic::Ordering::Release,
            );
            dispatch_snapshot_generation_advance!();
            if let Some(mut stale_manifest) = pending_manifest.take() {
                if let Some(verified) = stale_manifest.history_step.take() {
                    drop_verified_history_step(verified);
                }
            }
            if let Some(authority) = retained_snapshot_headers.take() {
                cleanup_validated_snapshot_headers_offthread(authority.headers);
            }
            active_snapshot_sync = None;
            snapshot_plan_last_progress = None;
            snapshot_provider_discovery_rounds = 0;
            rejected_snapshot_manifest_providers.clear();
            snapshot_terminal_transport_failures.clear();
            snapshot_terminal_exhausted.clear();
            snapshot_terminal_retry_after.clear();
            if let Some(stale_headers) = pending_snapshot_header_sync.take() {
                cleanup_snapshot_header_staging_offthread(stale_headers.staging);
            }
            snapshot_header_pipeline = None;
            clear_manifest_round_state!();
            if let Some(stale_staging) = snapshot_staging.take() {
                cleanup_snapshot_staging_session_offthread(stale_staging);
            }
            queued_segment_response = None;
            if let Some(request) = snapshot_boundary_terminal_inflight.take() {
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                        token: request.requests.primary.token,
                    })
                    .await;
            }
            prefetched_snapshot_boundary_terminal = None;
            if let Some((finalized, _)) = finalized_snapshot_waiting.take() {
                cleanup_finalized_snapshot_staging_offthread(finalized);
            }
            if history_step_verification_inflight.is_some() {
                tracing::debug!(
                    "retired snapshot plan is waiting for the bounded verifier to release admission"
                );
            } else if snapshot_header_staging_inflight.is_some()
                || snapshot_staging_inflight.is_some()
                || snapshot_install_inflight.is_some()
            {
                tracing::debug!(
                    "retired snapshot plan is waiting for bounded snapshot I/O to complete"
                );
            } else {
                tracing::debug!("retired snapshot plan is ready for fresh manifest discovery");
            }
        }};
    }

    macro_rules! request_bounded_manifest_failover {
        ($failed_peer:expr, $allow_failed_peer:expr) => {{
            let failed_peer = $failed_peer;
            let our_height = {
                let ctx = chain.read().await;
                ctx.tip_height()
            };
            let excluded_peers = rejected_terminal_peers
                .union(&finalized_divergent_peers)
                .copied()
                .collect::<std::collections::HashSet<_>>();
            let candidates = rotating_manifest_peers(
                &manifest_peers,
                &excluded_peers,
                Some(failed_peer),
                $allow_failed_peer,
                &mut manifest_retry_cursor,
                3,
            );
            for peer in candidates {
                try_request_manifest!(peer, our_height, [0; 32]);
            }
            if !manifest_requested_peers.is_empty() {
                manifest_round_started_at = Some(Instant::now());
            }
        }};
    }

    macro_rules! snapshot_plan_active {
        () => {{
            best_manifest_candidate.is_some()
                || pending_manifest.is_some()
                || pending_snapshot_header_sync.is_some()
                || retained_snapshot_headers.is_some()
                || snapshot_header_staging_inflight.is_some()
                || history_step_verification_inflight.is_some()
                || active_snapshot_sync.is_some()
                || snapshot_staging.is_some()
                || snapshot_staging_inflight.is_some()
                || snapshot_install_inflight.is_some()
        }};
    }

    macro_rules! dispatch_snapshot_segments_from_available_source {
        () => {{
            if let Some(sync) = active_snapshot_sync.as_mut() {
                dispatch_exact_snapshot_segments(
                    sync,
                    &p2p_cmd,
                    snapshot_staging_inflight.is_some(),
                    queued_segment_response.is_some(),
                );
            }
        }};
    }

    macro_rules! request_snapshot_generation_providers {
        ($failed_peer:expr) => {{
            let failed_peer = $failed_peer;
            let requester_height = {
                let ctx = chain.read().await;
                ctx.tip_height()
            };
            let mut excluded = std::collections::HashSet::from([failed_peer]);
            if let Some(pending) = pending_manifest.as_ref() {
                excluded.extend(pending.providers.iter().copied());
            }
            let requested_manifest_digest = pending_manifest
                .as_ref()
                .map(|pending| pending.manifest.manifest_digest)
                .unwrap_or([0; 32]);
            let rejected_exact = rejected_snapshot_manifest_providers
                .get(&requested_manifest_digest)
                .cloned()
                .unwrap_or_default();
            let excluded = excluded
                .union(&rejected_exact)
                .copied()
                .collect::<std::collections::HashSet<_>>();
            let candidates = rotating_manifest_peers(
                &manifest_peers,
                &excluded,
                None,
                false,
                &mut manifest_retry_cursor,
                3,
            );
            let mut dispatched = 0usize;
            for peer in candidates {
                if try_request_manifest!(peer, requester_height, requested_manifest_digest) {
                    dispatched = dispatched.saturating_add(1);
                }
            }
            dispatched
        }};
    }

    macro_rules! rotate_snapshot_segment_source {
        ($failed_peer:expr, $segment_id:expr, $reason:expr) => {{
            let failed_peer = $failed_peer;
            let segment_id = $segment_id;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let correlated = if let Some(sync) = active_snapshot_sync.as_mut() {
                if let Some(segment) = sync.segment(segment_id) {
                    sync.request_failed(failed_peer, segment, now_ms).is_ok()
                } else {
                    false
                }
            } else {
                false
            };
            tracing::warn!(
                peer = %failed_peer,
                segment = segment_id,
                correlated,
                reason = $reason,
                "snapshot object source failed; preserving generation and verified segments"
            );
            request_snapshot_generation_providers!(failed_peer);
            dispatch_snapshot_segments_from_available_source!();
        }};
    }

    macro_rules! reject_snapshot_segment_source {
        ($failed_peer:expr, $segment_id:expr, $reason:expr) => {{
            let failed_peer = $failed_peer;
            let segment_id = $segment_id;
            let correlated = if let Some(sync) = active_snapshot_sync.as_mut() {
                if let Some(segment) = sync.segment(segment_id) {
                    sync.reject_provider(failed_peer, segment).is_ok()
                } else {
                    false
                }
            } else {
                false
            };
            if correlated {
                if let Some(pending) = pending_manifest.as_mut() {
                    pending.providers.remove(&failed_peer);
                }
            }
            tracing::warn!(
                peer = %failed_peer,
                segment = segment_id,
                correlated,
                reason = $reason,
                "snapshot object source rejected; preserving generation and verified segments"
            );
            request_snapshot_generation_providers!(failed_peer);
            dispatch_snapshot_segments_from_available_source!();
        }};
    }

    macro_rules! begin_snapshot_header_staging {
        ($from:expr, $manifest:expr, $rebase_anchor:expr, $fetches:expr, $recent:expr) => {{
            sync_phase_telemetry.begin_snapshot();
            let from = $from;
            let manifest = $manifest;
            let rebase_anchor = $rebase_anchor;
            let snapshot_offer = match noid_node::networking::snapshot_sync::SnapshotOffer::from_verified_manifest(
                manifest.clone(),
            ) {
                Ok(offer) => offer,
                Err(error) => {
                    tracing::warn!(peer = %from, %error, "snapshot manifest could not form an immutable plan");
                    clear_manifest_round_state!();
                    request_bounded_manifest_failover!(from, false);
                    continue;
                }
            };
            let snapshot = snapshot_offer.snapshot_id();
            let header_manifest = manifest.clone();
            let terminal_height = manifest.tip_height;
            let rebase_base = snapshot_rebase_hint.and_then(|hint| {
                (hint.ancestor_height < terminal_height).then_some(
                    noid_node::networking::ChainPoint::new(
                        hint.ancestor_height,
                        hint.ancestor_hash,
                    ),
                )
            });

            // The manifest fixes one immutable State generation. Snapshot
            // admission ends at that exact boundary. Any later live tip is a
            // separate HeaderDAG-selected exact suffix, never a peer-owned
            // bridge hidden inside this snapshot session.
            let providers = if candidate_manifest_providers.contains(&from) {
                candidate_manifest_providers.clone()
            } else {
                std::iter::once(from).collect()
            };
            pending_manifest = Some(PendingManifest {
                preferred_peer: from,
                providers,
                rebase_base,
                manifest,
                offer: snapshot_offer,
                history_step: None,
            });
            snapshot_plan_last_progress = Some(Instant::now());
            snapshot_provider_discovery_rounds = 0;

            // A peer may already publish a newer snapshot generation while the
            // selected boundary terminal remains inside its retained-object
            // window. Ask for the one exact boundary inventory record before
            // considering a near-megabyte terminal transfer. This preserves the
            // advertised-source rule without tying proof availability to State
            // generation equality.
            let selected_terminal = ManifestTerminalCapability {
                boundary_height: snapshot.boundary.height,
                boundary_hash: snapshot.boundary.hash,
            };
            let mut terminal_probe_excluded = rejected_terminal_peers.clone();
            terminal_probe_excluded.insert(from);
            terminal_probe_excluded.extend(
                manifest_terminal_capabilities
                    .iter()
                    .filter_map(|(peer, capability)| {
                        (*capability == selected_terminal).then_some(*peer)
                    }),
            );
            terminal_probe_excluded.extend(snapshot_terminal_exhausted.iter().filter_map(
                |source| {
                    (source.height == snapshot.boundary.height
                        && source.block_hash == snapshot.boundary.hash)
                        .then_some(source.peer)
                },
            ));
            let terminal_probe_peers = rotating_manifest_peers(
                &locally_selected_peers,
                &terminal_probe_excluded,
                None,
                false,
                &mut exact_inventory_probe_cursor,
                EXACT_INVENTORY_PROBE_LANES.saturating_sub(1),
            );
            for peer in terminal_probe_peers {
                let _ = try_dispatch_header_fetch(
                    &p2p_cmd,
                    $fetches,
                    $recent,
                    peer,
                    snapshot.boundary.height,
                    1,
                    Instant::now(),
                );
            }
            if candidate_manifest_providers.len() < EXACT_INVENTORY_PROBE_LANES {
                let _ = request_snapshot_generation_providers!(from);
            }
            ensure_snapshot_boundary_terminal_request!();

            snapshot_header_staging_token = snapshot_header_staging_token.wrapping_add(1);
            let key = SnapshotHeaderStagingOperationKey::Prepare {
                generation: snapshot_sync_generation,
                token: snapshot_header_staging_token,
                snapshot,
            };
            snapshot_header_staging_inflight = Some(key);
            let completion = snapshot_header_staging_tx.clone();
            let store = snapshot_header_store.clone();
            let staging_root = snapshot_header_staging_root.clone();
            tokio::task::spawn_blocking(move || {
                let started = Instant::now();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    prepare_snapshot_header_sync(
                        &staging_root,
                        &store,
                        from,
                        header_manifest,
                        rebase_base.map(|base| (base.height, base.hash)),
                        rebase_anchor,
                    )
                }));
                let _ = completion.blocking_send(SnapshotHeaderStagingCompletion {
                    key,
                    work_elapsed: started.elapsed(),
                    result: match result {
                        Ok(Ok(sync)) => SnapshotHeaderStagingResult::Success(sync),
                        Ok(Err(SnapshotHeaderPrepareError::BaseMoved(error))) => {
                            SnapshotHeaderStagingResult::PrepareBaseMoved(error)
                        }
                        Ok(Err(SnapshotHeaderPrepareError::Fatal(error))) => {
                            SnapshotHeaderStagingResult::Fatal(error)
                        }
                        Err(_) => SnapshotHeaderStagingResult::Fatal(
                            "snapshot header preparation worker panicked".to_owned(),
                        ),
                    },
                });
            });
            tracing::info!(
                peer = %from,
                target_height = terminal_height,
                rebase_base_height = rebase_base.map(|base| base.height),
                "snapshot: staging exact boundary headers"
            );
        }};
    }

    macro_rules! spawn_snapshot_header_append {
        ($sync:expr, $range:expr) => {{
            let sync = $sync;
            let range: ReadySnapshotHeaderRange = $range;
            let snapshot = sync.snapshot;
            let range_from = range.source_peer;
            let start_height = sync.next_height;
            let count = range.count;
            snapshot_header_staging_token = snapshot_header_staging_token.wrapping_add(1);
            let key = SnapshotHeaderStagingOperationKey::Append {
                generation: snapshot_sync_generation,
                token: snapshot_header_staging_token,
                snapshot,
                range_from,
                start_height,
                count,
            };
            snapshot_header_staging_inflight = Some(key);
            let completion = snapshot_header_staging_tx.clone();
            let store = snapshot_header_store.clone();
            tokio::task::spawn_blocking(move || {
                let started = Instant::now();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let mut sync = sync;
                    match sync.staging.append_batch(&store, &range.headers) {
                        Ok(next_height) => {
                            sync.next_height = next_height;
                            SnapshotHeaderStagingResult::Success(sync)
                        }
                        Err(
                            error @ (SnapshotHeaderStagingError::InvalidCandidate { .. }
                            | SnapshotHeaderStagingError::ParentMismatch { .. }),
                        ) => SnapshotHeaderStagingResult::CandidateRejected {
                            sync,
                            attempted_peers: range.attempted_peers,
                            error,
                        },
                        Err(error @ SnapshotHeaderStagingError::CanonicalBaseMoved { .. }) => {
                            SnapshotHeaderStagingResult::BaseMoved { sync, error }
                        }
                        Err(error) => {
                            let message = error.to_string();
                            let _ = sync.staging.discard();
                            SnapshotHeaderStagingResult::Fatal(message)
                        }
                    }
                }))
                .unwrap_or_else(|_| {
                    SnapshotHeaderStagingResult::Fatal(
                        "snapshot header append worker panicked".to_owned(),
                    )
                });
                let _ = completion.blocking_send(SnapshotHeaderStagingCompletion {
                    key,
                    work_elapsed: started.elapsed(),
                    result,
                });
            });
        }};
    }

    macro_rules! start_snapshot_boundary_verification {
        ($sync:expr, $payload:expr) => {{
            let sync = $sync;
            let payload = $payload;
            let terminal_from = payload.from;
            let terminal_request_token = payload.token;
            let Some(runtime) = history_step_runtime.clone() else {
                tracing::error!(
                    preferred_peer = %sync.preferred_peer,
                    tip = sync.manifest.tip_height,
                    "snapshot rejected: HistoryStep verifier unavailable"
                );
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                        token: terminal_request_token,
                    })
                    .await;
                cleanup_snapshot_header_staging_offthread(sync.staging);
                drop(payload);
                return Err(anyhow::anyhow!(
                    "HistoryStep verifier unavailable for snapshot boundary"
                ));
            };
            let expected_height = sync.manifest.tip_height;
            let expected_hash = sync.manifest.tip_hash;
            let preferred_peer = sync.preferred_peer;
            let snapshot = sync.snapshot;
            history_step_verification_token =
                history_step_verification_token.wrapping_add(1);
            let key = HistoryStepVerificationKey {
                token: history_step_verification_token,
                terminal_request_token,
                snapshot,
                terminal_from,
                height: expected_height,
                block_hash: expected_hash,
            };
            let generation = snapshot_sync_generation;
            let completion = history_step_verification_tx.clone();
            let generation_guard = Arc::clone(&snapshot_sync_generation_guard);
            let store = snapshot_header_store.clone();
            let verification_chain = Arc::clone(&chain);
            let manifest = sync.manifest;
            let allow_nonfinal_rebase = snapshot_rebase_hint.is_some_and(|hint| {
                let base = sync.staging.base();
                base.header.height == hint.ancestor_height
                    && base.block_hash == hint.ancestor_hash
            });
            let rebase_anchor = sync.rebase_anchor;
            let mut staging = sync.staging;
            let staged_header_count = staging.staged_len();
            let terminal_bytes = payload.terminal_bytes;
            let inbound_memory_permit = payload.inbound_memory_permit;
            history_step_verification_inflight = Some(key);
            tokio::task::spawn_blocking(move || {
                let mut header_validation_elapsed = std::time::Duration::ZERO;
                let mut terminal_measurement = None;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if generation_guard.load(std::sync::atomic::Ordering::Acquire) != generation {
                        return SnapshotBoundaryVerificationOutcome::Fatal {
                            error: "HistoryStep verification superseded before start".to_owned(),
                            authority: None,
                        };
                    }
                    if let Some(anchor) = rebase_anchor {
                        match staging.matches_exact_point(
                            anchor.height,
                            anchor.hash,
                            anchor.cumulative_work,
                        ) {
                            Ok(true) => {}
                            Ok(false) => {
                                let _ = staging.discard();
                                return SnapshotBoundaryVerificationOutcome::CandidateRejected {
                                    error: format!(
                                        "staged snapshot ancestry does not cross HeaderDAG point h={}",
                                        anchor.height
                                    ),
                                    authority: None,
                                };
                            }
                            Err(error) => {
                                let _ = staging.discard();
                                return SnapshotBoundaryVerificationOutcome::Fatal {
                                    error: format!(
                                        "read staged HeaderDAG binding at h={}: {error}",
                                        anchor.height
                                    ),
                                    authority: None,
                                };
                            }
                        }
                    }
                    let header_started = Instant::now();
                    let validated_headers = match staging.validate_complete(
                            &store,
                            expected_height,
                            expected_hash,
                            manifest.cumulative_chainwork,
                        ) {
                        Ok(headers) => headers,
                        Err(error) => {
                            let candidate_rejected =
                                snapshot_header_completion_rejects_candidate(&error);
                            let base_moved = snapshot_header_completion_base_moved(&error);
                            let error = error.to_string();
                            return if base_moved {
                                SnapshotBoundaryVerificationOutcome::BaseMoved {
                                    error,
                                    authority: None,
                                }
                            } else if candidate_rejected {
                                SnapshotBoundaryVerificationOutcome::CandidateRejected {
                                    error,
                                    authority: None,
                                }
                            } else {
                                SnapshotBoundaryVerificationOutcome::Fatal {
                                    error,
                                    authority: None,
                                }
                            };
                        }
                    };
                    let authority = RetainedSnapshotHeaderAuthority {
                        snapshot,
                        headers: validated_headers,
                        allow_nonfinal_rebase,
                        staged_header_count,
                    };
                    let boundary = authority.headers.boundary();
                    if let Err(error) = validate_snapshot_staged_header_boundary(&manifest, &boundary)
                    {
                        return SnapshotBoundaryVerificationOutcome::CandidateRejected {
                            error,
                            authority: Some(authority),
                        };
                    }
                    if let Err(error) =
                        validate_history_step_tip_future_drift(&boundary, unix_now())
                    {
                        return SnapshotBoundaryVerificationOutcome::CandidateRejected {
                            error,
                            authority: Some(authority),
                        };
                    }
                    header_validation_elapsed = header_started.elapsed();
                    if generation_guard.load(std::sync::atomic::Ordering::Acquire) != generation {
                        return SnapshotBoundaryVerificationOutcome::Fatal {
                            error: "HistoryStep verification superseded before completion"
                                .to_owned(),
                            authority: Some(authority),
                        };
                    }
                    let (outcome, measurement) = verify_terminal_against_validated_snapshot_headers(
                        verification_chain.as_ref(),
                        runtime.as_ref(),
                        authority,
                        terminal_bytes,
                        inbound_memory_permit,
                    );
                    terminal_measurement = Some(measurement);
                    outcome
                }))
                .unwrap_or_else(|_| SnapshotBoundaryVerificationOutcome::Fatal {
                    error: "HistoryStep verifier worker panicked".to_owned(),
                    authority: None,
                });
                let _ = completion.blocking_send(HistoryStepVerificationCompletion {
                    key,
                    generation,
                    manifest,
                    header_validation_elapsed,
                    terminal_measurement,
                    staged_header_count,
                    result,
                });
            });
            tracing::info!(
                preferred_peer = %preferred_peer,
                terminal_from = %terminal_from,
                tip = expected_height,
                "snapshot HistoryStep verification started off-thread"
            );
        }};
    }

    macro_rules! retry_snapshot_boundary_verification {
        ($authority:expr, $payload:expr) => {{
            let authority = $authority;
            let payload = $payload;
            let snapshot = authority.snapshot;
            let terminal_from = payload.from;
            let terminal_request_token = payload.token;
            let Some(runtime) = history_step_runtime.clone() else {
                cleanup_validated_snapshot_headers_offthread(authority.headers);
                drop(payload);
                tracing::error!(
                    boundary = snapshot.boundary.height,
                    "snapshot rejected: HistoryStep verifier unavailable during terminal failover"
                );
                return Err(anyhow::anyhow!(
                    "HistoryStep verifier unavailable during terminal failover at {}",
                    snapshot.boundary.height
                ));
            };
            let Some(manifest) = pending_manifest
                .as_ref()
                .filter(|pending| pending.offer.snapshot_id() == snapshot)
                .map(|pending| pending.manifest.clone())
            else {
                cleanup_validated_snapshot_headers_offthread(authority.headers);
                drop(payload);
                tracing::error!(
                    boundary = snapshot.boundary.height,
                    "validated snapshot headers lost their immutable manifest"
                );
                return Err(anyhow::anyhow!(
                    "validated snapshot headers lost immutable manifest at {}",
                    snapshot.boundary.height
                ));
            };
            history_step_verification_token = history_step_verification_token.wrapping_add(1);
            let key = HistoryStepVerificationKey {
                token: history_step_verification_token,
                terminal_request_token,
                snapshot,
                terminal_from,
                height: snapshot.boundary.height,
                block_hash: snapshot.boundary.hash,
            };
            let generation = snapshot_sync_generation;
            let completion = history_step_verification_tx.clone();
            let generation_guard = Arc::clone(&snapshot_sync_generation_guard);
            let verification_chain = Arc::clone(&chain);
            let staged_header_count = authority.staged_header_count;
            let terminal_bytes = payload.terminal_bytes;
            let inbound_memory_permit = payload.inbound_memory_permit;
            history_step_verification_inflight = Some(key);
            tokio::task::spawn_blocking(move || {
                let (result, terminal_measurement) =
                    if generation_guard.load(std::sync::atomic::Ordering::Acquire) != generation {
                        (
                            SnapshotBoundaryVerificationOutcome::Fatal {
                                error: "HistoryStep retry superseded before start".to_owned(),
                                authority: Some(authority),
                            },
                            None,
                        )
                    } else {
                        let (outcome, measurement) =
                            verify_terminal_against_validated_snapshot_headers(
                                verification_chain.as_ref(),
                                runtime.as_ref(),
                                authority,
                                terminal_bytes,
                                inbound_memory_permit,
                            );
                        (outcome, Some(measurement))
                    };
                let _ = completion.blocking_send(HistoryStepVerificationCompletion {
                    key,
                    generation,
                    manifest,
                    header_validation_elapsed: std::time::Duration::ZERO,
                    terminal_measurement,
                    staged_header_count,
                    result,
                });
            });
            tracing::info!(
                terminal_from = %terminal_from,
                tip = snapshot.boundary.height,
                "retrying snapshot terminal against retained validated headers"
            );
        }};
    }

    macro_rules! spawn_boundary_proof_maintenance_verification {
        ($target:expr, $from:expr, $terminal_bytes:expr, $permit:expr) => {{
            let target = $target;
            let from = $from;
            let terminal_bytes = $terminal_bytes;
            let inbound_memory_permit = $permit;
            let Some(runtime) = history_step_runtime.clone() else {
                drop(terminal_bytes);
                drop(inbound_memory_permit);
                tracing::warn!(
                    height = target.height(),
                    "snapshot-boundary proof maintenance deferred: verifier unavailable"
                );
                last_boundary_proof_maintenance = Instant::now();
                continue;
            };
            let verification_chain = Arc::clone(&chain);
            let completion = boundary_proof_maintenance_tx.clone();
            boundary_proof_verification_inflight = Some(target);
            tokio::task::spawn_blocking(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let ctx = verification_chain.blocking_read();
                    match ctx.verify_snapshot_boundary(
                        target.header,
                        target.epoch_anchor_header,
                        terminal_bytes,
                        |claim| verify_history_step_terminal(claim, Some(runtime.as_ref())),
                    ) {
                        Ok(boundary) => match ctx.cache_verified_snapshot_boundary_proof(&boundary)
                        {
                            Ok(()) => BoundaryProofMaintenanceResult::Cached,
                            Err(error) => BoundaryProofMaintenanceResult::LocalFailure(format!(
                                "cache verified snapshot-boundary terminal: {error}"
                            )),
                        },
                        Err(error) if history_step_context_error_is_terminal_peer_fault(&error) => {
                            BoundaryProofMaintenanceResult::TerminalRejected(format!(
                                "verify snapshot-boundary terminal: {error}"
                            ))
                        }
                        Err(error) => BoundaryProofMaintenanceResult::LocalFailure(format!(
                            "verify snapshot-boundary terminal: {error}"
                        )),
                    }
                }))
                .unwrap_or_else(|_| {
                    BoundaryProofMaintenanceResult::LocalFailure(
                        "snapshot-boundary proof maintenance worker panicked".to_owned(),
                    )
                });
                drop(inbound_memory_permit);
                let _ = completion.blocking_send(BoundaryProofMaintenanceCompletion {
                    target,
                    from,
                    result,
                });
            });
        }};
    }

    macro_rules! stage_snapshot_segment_response {
        ($from:expr, $response:expr) => {{
            let from = $from;
            let response = $response;
            let Some(mut staging) = snapshot_staging.take() else {
                tracing::warn!(
                    from = %from,
                    segment = response.segment_id,
                    "discarding stale segment received without snapshot staging session"
                );
                drop(response);
                continue;
            };
            let snapshot = active_snapshot_sync
                .as_ref()
                .and_then(|sync| sync.segment(response.segment_id))
                .map(|segment| segment.snapshot)
                .expect("correlated segment response belongs to the active snapshot plan");
            let key = SnapshotStagingOperationKey::Accept {
                generation: snapshot_sync_generation,
                snapshot,
                from,
                segment_id: response.segment_id,
            };
            snapshot_staging_inflight = Some(key);
            let completion = snapshot_staging_completion_tx.clone();
            let response_effective_log = response.eff_log;
            let segment_id = response.segment_id;
            let payload_bytes = response
                .data
                .as_ref()
                .map_or(0u64, |data| data.len() as u64);
            tokio::task::spawn_blocking(move || {
                let started = Instant::now();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    match staging.accept_segment_recoverable(
                            segment_id,
                            response_effective_log,
                            response
                                .data
                                .as_deref()
                                .expect("present segment payload moved intact"),
                        ) {
                            Ok(()) => SnapshotSegmentStageResult::Accepted(staging),
                            Err(error)
                                if snapshot_segment_failure_scope(&error)
                                    == SnapshotSegmentFailureScope::Source =>
                            {
                                SnapshotSegmentStageResult::SourceRejected {
                                    staging,
                                    error: error.to_string(),
                                }
                            }
                            Err(error)
                                if snapshot_segment_failure_scope(&error)
                                    == SnapshotSegmentFailureScope::Candidate =>
                            {
                                SnapshotSegmentStageResult::CandidateRejected(error.to_string())
                            }
                            Err(error) => SnapshotSegmentStageResult::Fatal(error.to_string()),
                        }
                }))
                .unwrap_or_else(|_| {
                    SnapshotSegmentStageResult::Fatal(
                        "snapshot segment staging worker panicked".to_owned(),
                    )
                });
                // The wire allocation and inbound permit stay charged through
                // authentication and atomic disk publication by the closure.
                let _ = completion.blocking_send(SnapshotStagingCompletion::Accepted {
                    key,
                    payload_bytes,
                    work_elapsed: started.elapsed(),
                    result,
                });
            });
            tracing::debug!(
                from = %from,
                segment = segment_id,
                "snapshot segment queued for bounded authentication/staging"
            );
        }};
    }

    macro_rules! start_snapshot_install {
        ($finalized:expr, $segment_count:expr) => {{
            let finalized = $finalized;
            let segment_count = $segment_count;
            let Some(mut pending) = pending_manifest.take() else {
                tracing::warn!("snapshot finalized without selected manifest");
                cleanup_finalized_snapshot_staging_offthread(finalized);
                return Err(anyhow::anyhow!(
                    "finalized snapshot lost its immutable manifest"
                ));
            };
            let source = pending.preferred_peer;
            let Some(history_step) = pending.history_step.take() else {
                tracing::error!(source = %source, "verified snapshot lost HistoryStep authority");
                cleanup_finalized_snapshot_staging_offthread(finalized);
                return Err(anyhow::anyhow!(
                    "finalized snapshot lost verified HistoryStep authority"
                ));
            };

            let manifest = pending.manifest;
            let snapshot = pending.offer.snapshot_id();
            let key = SnapshotInstallKey {
                generation: snapshot_sync_generation,
                snapshot,
                observer_peer: source,
                terminal_from: None,
                terminal_request_token: None,
                height: manifest.tip_height,
                block_hash: manifest.tip_hash,
            };
            snapshot_install_inflight = Some(key);
            let install_chain = Arc::clone(&chain);
            let install_mempool = mempool.clone();
            let install_wallet = Arc::clone(&wallet);
            let install_wallet_operation_gate = Arc::clone(&wallet_operation_gate);
            let install_external_mining_attempts = external_mining_attempts.clone();
            let completion = snapshot_install_completion_tx.clone();
            let install_task = tokio::spawn(async move {
                apply_verified_snapshot_boundary(
                    &install_chain,
                    &install_mempool,
                    &install_wallet,
                    manifest,
                    finalized,
                    history_step,
                    &install_wallet_operation_gate,
                    &install_external_mining_attempts,
                )
                .await
            });
            tokio::spawn(async move {
                let result = install_task
                    .await
                    .map_err(|error| {
                        SnapshotInstallError::BeforeCommit(format!(
                            "snapshot install task panicked: {error}"
                        ))
                    })
                    .and_then(|result| result);
                let _ = completion
                    .send(SnapshotInstallCompletion { key, result })
                    .await;
            });
            tracing::info!(
                source = %source,
                tip = key.height,
                segments = segment_count,
                "snapshot boundary finalized — atomic State install running off event loop"
            );
        }};
    }

    macro_rules! try_start_ready_snapshot_install {
        () => {{
            if finalized_snapshot_waiting.is_some() {
                let stale_snapshot_candidate = pending_manifest.as_ref().and_then(|pending| {
                    match snapshot_rebase_hint {
                        Some(hint) => validate_rebase_snapshot_selection(
                            &header_dag,
                            hint,
                            &pending.manifest,
                        ),
                        None => {
                            validate_snapshot_install_selection(&header_dag, &pending.manifest)
                        }
                    }
                    .err()
                });
                if let Some(error) = stale_snapshot_candidate {
                    let previous_peer = pending_manifest
                        .as_ref()
                        .map(|pending| pending.preferred_peer);
                    tracing::info!(
                        selected_height = header_dag.best_tip().height,
                        %error,
                        "verified snapshot left the HeaderDAG-selected ancestry; selecting a fresh boundary"
                    );
                    retire_snapshot_plan!();
                    if let Some(previous_peer) = previous_peer {
                        request_bounded_manifest_failover!(previous_peer, true);
                    }
                    continue;
                }
                let (finalized, segment_count) = finalized_snapshot_waiting
                    .take()
                    .expect("checked finalized snapshot state");
                start_snapshot_install!(finalized, segment_count);
            }
        }};
    }

    // General header request deduplication is shared with compact-suffix
    // recovery, whose macro is defined below.
    let mut fetch_in_progress: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    let mut recent_header_fetches: HashMap<(libp2p::PeerId, u64, u16), Instant> = HashMap::new();
    // One bounded hint retained while compact catch-up owns canonical
    // mutation. It preserves an equal-height competing-fork signal without
    // retaining or validating payloads concurrently with the active suffix.
    let mut deferred_sync_peer: Option<libp2p::PeerId> = None;

    macro_rules! try_start_exact_suffix_apply {
        () => {{
            let ready = exact_suffix_apply_inflight.is_none()
                && !header_dag_faulted
                && active_suffix_sync
                    .as_ref()
                    .is_some_and(|sync| {
                        sync.is_complete()
                            && header_dag
                                .is_ancestor(sync.plan().target(), header_dag.best_tip())
                                .unwrap_or(false)
                    });
            if ready {
                let sync = active_suffix_sync
                    .take()
                    .expect("checked complete exact suffix");
                suffix_plan_last_progress = None;
                suffix_provider_discovery_rounds = 0;
                suffix_inventory_probe_peers.clear();
                let plan_id = sync.plan_id();
                let target = sync.plan().target();
                match sync.into_fetched() {
                    Ok(fetched) => {
                        let confirmation_sources = fetched.tip_confirmation_sources();
                        let tip_announcement = fetched.tip_announcement();
                        exact_suffix_apply_inflight = Some(plan_id);
                        let apply_chain = Arc::clone(&chain);
                        let apply_mempool = mempool.clone();
                        let apply_wallet = Arc::clone(&wallet);
                        let apply_runtime = history_step_runtime.clone();
                        let apply_gate = wallet_operation_gate.clone();
                        let completion = exact_suffix_apply_tx.clone();
                        tokio::spawn(async move {
                            let result = apply_exact_suffix_offthread(
                                &apply_chain,
                                &apply_mempool,
                                &apply_wallet,
                                fetched,
                                apply_runtime,
                                &apply_gate,
                            )
                            .await;
                            let _ = completion
                                .send(ExactSuffixApplyCompletion {
                                    plan_id,
                                    target,
                                    tip_announcement,
                                    confirmation_sources,
                                    result,
                                })
                                .await;
                        });
                        tracing::info!(
                            ?plan_id,
                            target_height = target.height,
                            "exact suffix objects complete — verification/commit started"
                        );
                    }
                    Err(error) => {
                        tracing::error!(?plan_id, %error, "complete exact suffix could not be sealed");
                    }
                }
            }
        }};
    }

    // --- FetchHeaders in-progress guard ---
    //
    // Prevents FetchHeaders from being sent to the same peer thousands of
    // times during a block burst. Entry is removed when HeaderInventoryBatch
    // arrives
    // from that peer (or on disconnect).  Without this guard, 10 peers each
    // sending 40 blocks/s = 400 redundant FetchHeaders/s.
    // --- Per-peer tx rate limiter ---
    //
    // Sliding-window rate limiter: tracks (tx_count_in_window, window_start) per peer.
    // Prevents a single peer from flooding the proof-verification semaphore queue.
    // Short-lived dedup for fork-recovery pulls. During two-miner races the same
    // orphan/fork announcement can be observed many times before the local node
    // reorganizes. Without this, each observation re-sends identical header/block
    // requests and floods logs/P2P with no extra safety.
    const FETCH_DEDUP_TTL: Duration = Duration::from_secs(15);

    let mut peer_tx_rate: HashMap<libp2p::PeerId, (u32, Instant)> = HashMap::new();
    const TX_RATE_WINDOW: Duration = Duration::from_secs(10);
    const TX_RATE_MAX: u32 = 50; // max 50 tx per peer per 10s window
    let mut tx_event_count: u32 = 0;

    // --- Stale-tip detection ---
    //
    // In large networks, block requests may fail (peer doesn't have the block
    // yet, stream capacity hit, etc.) with no retry.  The stale-tip check
    // detects when our chain hasn't advanced despite seeing higher announcements
    // and re-requests from a random connected peer.
    let mut last_tip_advance: Instant = Instant::now();
    let mut highest_announced: u64 = 0;
    let mut last_announcement_peer: Option<libp2p::PeerId> = None;
    let mut bootstrap_complete_sent = false;
    // Armed only by a successfully installed, HeaderDAG-bound snapshot. It
    // lets that one snapshot finish its pinned exact tail without changing
    // the ordinary 18-block snapshot threshold.
    let mut post_snapshot_tail: Option<PostSnapshotTail> = None;

    macro_rules! arm_post_snapshot_tail {
        ($height:expr, $hash:expr) => {{
            let boundary = noid_node::networking::ChainPoint::new($height, $hash);
            let tail = PostSnapshotTail {
                boundary,
                target: None,
            };
            tracing::info!(
                boundary_height = boundary.height,
                serving_limit = tail.serving_limit(),
                "snapshot installed — awaiting one authenticated HeaderDAG tail target"
            );
            post_snapshot_tail = Some(tail);
        }};
    }

    macro_rules! retire_post_snapshot_tail_if_finished {
        ($height:expr) => {{
            let height = $height;
            if post_snapshot_tail.is_some_and(|tail| tail.is_finished_or_invalid_at(height)) {
                if let Some(tail) = post_snapshot_tail.take() {
                    tracing::debug!(
                        height,
                        boundary_height = tail.boundary.height,
                        target_height = tail.target.map(|target| target.height),
                        "retired completed post-snapshot exact-tail allowance"
                    );
                }
            }
        }};
    }

    // Raw announcement and manifest heights are routing hints only. This
    // target advances exclusively after native header validation or atomic
    // acceptance, so one dishonest peer cannot hold readiness or recovery at
    // an invented height.
    macro_rules! record_authenticated_height {
        ($height:expr, $peer:expr) => {{
            let height = $height;
            if height > highest_announced {
                highest_announced = height;
                sync_phase_telemetry.extend_suffix_target(height);
                last_announcement_peer = Some($peer);
            }
        }};
    }

    macro_rules! request_exact_tip_confirmation {
        ($peer:expr, $local_height:expr) => {{
            let peer = $peer;
            let local_height = $local_height;
            if !*initial_sync_ready.borrow()
                && local_height >= highest_announced
                && manifest_peers.contains(&peer)
            {
                let count = post_snapshot_tail
                    .and_then(|tail| tail.probe_count(local_height))
                    .unwrap_or(CONNECTED_TIP_PROBE_HEADERS);
                let request_key = (peer, local_height, count);
                let recently_requested = recent_header_fetches
                    .get(&request_key)
                    .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL);
                if !fetch_in_progress.contains(&peer) && !recently_requested {
                    let now = Instant::now();
                    if try_dispatch_header_fetch(
                        &p2p_cmd,
                        &mut fetch_in_progress,
                        &mut recent_header_fetches,
                        peer,
                        local_height,
                        count,
                        now,
                    ) {
                        mining_peer_quorum.mark_probe_sent(peer, Instant::now());
                        tracing::debug!(
                            peer = %peer,
                            local_height,
                            "requesting exact post-commit tip confirmation"
                        );
                    }
                }
            }
        }};
    }

    macro_rules! mark_bootstrap_complete_if_caught_up {
        ($local_height:expr) => {{
            let local_height = $local_height;
            if !bootstrap_complete_sent
                && *initial_sync_ready.borrow()
                && local_height >= highest_announced
                && !manifest_peers.is_empty()
                && manifest_requested_peers.is_empty()
                && manifest_round_started_at.is_none()
                && best_manifest_candidate.is_none()
                && pending_manifest.is_none()
                && pending_snapshot_header_sync.is_none()
                && snapshot_header_staging_inflight.is_none()
                && history_step_verification_inflight.is_none()
                && snapshot_staging_inflight.is_none()
                && snapshot_install_inflight.is_none()
                && active_snapshot_sync
                    .as_ref()
                    .is_none_or(|sync| sync.all_segments_verified())
            {
                if p2p_cmd
                    .send(noid_p2p::NetworkCommand::BootstrapComplete)
                    .await
                    .is_ok()
                {
                    bootstrap_complete_sent = true;
                    if let Some(tail) = post_snapshot_tail.take() {
                        tracing::debug!(
                            local_height,
                            boundary_height = tail.boundary.height,
                            target_height = tail.target.map(|target| target.height),
                            "retired post-snapshot exact-tail allowance at bootstrap completion"
                        );
                    }
                    tracing::debug!(
                        local_height,
                        highest_announced,
                        "exact initial catch-up complete — bootstrap peers may be replaced"
                    );
                }
            }
        }};
    }

    // Heartbeat for time-dependent checks (manifest timeout, etc.)
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_millis(500));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await; // skip first

    loop {
        tokio::select! {
        changed = canonical_tip_changes.changed() => {
            if changed.is_ok() {
                let _announced_point = *canonical_tip_changes.borrow_and_update();
                let (height, hash, prev_hash) = {
                    let ctx = chain.read().await;
                    (
                        ctx.tip_height(),
                        ctx.tip_hash(),
                        ctx.tip_header().prev_block_hash,
                    )
                };
                mining_peer_quorum.reconcile_canonical_tip(height, hash, prev_hash);
                retire_post_snapshot_tail_if_finished!(height);
                // Local commits arrive through this watch channel (including blocks
                // submitted by an external miner).  They advance the canonical tip
                // just as surely as an exact-suffix or snapshot commit, so stale-gap
                // recovery must measure from this commit rather than an older
                // network-applied tip.
                last_tip_advance = Instant::now();
                let _ = template_changes.send(());
                external_mining_attempts.invalidate_for_tip(height, hash);
                tracing::debug!(
                    height,
                    hash = %hex::encode(hash),
                    "canonical commit synchronously replaced the mining template"
                );
            }
        }
        rx_result = rx.recv() => { let rx_item = rx_result;
        match rx_item {
            Ok(NetworkEvent::HeaderAnnouncement {
                from,
                announcement,
                source_has_objects,
            }) => {
                let announced_header = announcement.header;
                let exact_inventory = (source_has_objects && manifest_peers.contains(&from))
                    .then(|| {
                        noid_p2p::header_protocol::HeaderInventoryRecord::from_announcement(
                            announcement,
                        )
                    });
                let height = announced_header.height;
                let announcement_data_blocked = snapshot_plan_active!()
                    || exact_suffix_apply_inflight.is_some()
                    || pending_manifest.is_some()
                    || snapshot_install_inflight.is_some();
                // Compact block announcement: validate the advertised header before
                // downloading a potentially large accepted bundle. Direct-next
                // headers can be fully checked against the current tip; larger recent
                // gaps first pull headers, then bodies are requested only for the
                // verified competing chain in the HeaderInventoryBatch path.
                let announced_hash = noid_chain::block_id(&announced_header);
                let (our_height, our_hash, finalized_height, canonical_hash_at_height) = {
                    let ctx = chain.read().await;
                    (
                        ctx.tip_height(),
                        ctx.tip_hash(),
                        ctx.finalized_checkpoint().height,
                        ctx.header(height).map(noid_chain::block_id),
                    )
                };
                if height < our_height {
                    if height <= finalized_height
                        || canonical_hash_at_height == Some(announced_hash)
                    {
                        continue;
                    }
                    // A shorter tip may still carry more cumulative work.
                    // Height alone is never fork-choice authority, so compare
                    // its complete non-final ancestry through HeaderDAG.
                    let start_height = finalized_header_search_floor(our_height);
                    let count = (CONSENSUS_FINALITY_DEPTH as u16 * 2).min(512);
                    let request_key = (from, start_height, count);
                    let recently_requested = recent_header_fetches
                        .get(&request_key)
                        .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL);
                    if !fetch_in_progress.contains(&from) && !recently_requested {
                        try_dispatch_header_fetch(
                            &p2p_cmd,
                            &mut fetch_in_progress,
                            &mut recent_header_fetches,
                            from,
                            start_height,
                            count,
                            Instant::now(),
                        );
                    }
                    continue;
                }
                if height == our_height {
                    if announced_hash == our_hash {
                        mining_peer_quorum.confirm_tip(from, our_height, our_hash);
                        continue;
                    }
                    let start_height = finalized_header_search_floor(our_height);
                    let count = (CONSENSUS_FINALITY_DEPTH as u16 * 2).min(512);
                    let request_key = (from, start_height, count);
                    let recently_requested = recent_header_fetches
                        .get(&request_key)
                        .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL);
                    if !fetch_in_progress.contains(&from) && !recently_requested {
                        try_dispatch_header_fetch(
                            &p2p_cmd,
                            &mut fetch_in_progress,
                            &mut recent_header_fetches,
                            from,
                            start_height,
                            count,
                            Instant::now(),
                        );
                    }
                    continue;
                }

                if height > our_height.saturating_add(1) {
                    // Raw height is only a routing hint. Every non-adjacent
                    // target first pulls a bounded native header range; only
                    // HeaderDAG may then select either an exact continuation
                    // or a snapshot-backed target.
                    let start_height = finalized_header_search_floor(our_height);
                    let (_, count) = unresolved_tip_probe_range(start_height, height, 0);
                    let request_key = (from, start_height, count);
                    let recently_requested = recent_header_fetches
                        .get(&request_key)
                        .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL);
                    if !fetch_in_progress.contains(&from) && !recently_requested {
                        try_dispatch_header_fetch(
                            &p2p_cmd,
                            &mut fetch_in_progress,
                            &mut recent_header_fetches,
                            from,
                            start_height,
                            count,
                            Instant::now(),
                        );
                    }
                    continue;
                } else if height == our_height + 1 {
                    let precheck = {
                        let ctx = chain.read().await;
                        let parent = *ctx.tip_header();
                        let local_time = unix_now();
                        let validation_context =
                            (|| -> Result<_, noid_chain::storage::MdbxContextError> {
                                Ok((
                                    ctx.prev_timestamps()?,
                                    ctx.anchor_info()?,
                                    ctx.finalized_active_counts()?,
                                ))
                            })();
                        match validation_context {
                            Ok((prev_timestamps, anchor, finalized_active_counts)) => {
                                Some((
                                    noid_chain::consensus::validate_header(
                                        &announced_header,
                                        &parent,
                                        &prev_timestamps,
                                        &finalized_active_counts,
                                        local_time,
                                        anchor.anchor_height,
                                        anchor.anchor_timestamp,
                                        &anchor.anchor_target,
                                    ),
                                    noid_node::networking::ChainPoint::new(
                                        ctx.tip_height(),
                                        ctx.tip_hash(),
                                    ),
                                    *ctx.tip_chain_work(),
                                ))
                            }
                            Err(error) => {
                                tracing::error!(
                                    err = %error,
                                    "canonical header-validation window is unavailable"
                                );
                                None
                            }
                        }
                    };
                    let Some((precheck, base, base_work)) = precheck else {
                        continue;
                    };
                    if let Err(e) = precheck {
                        if e == noid_chain::consensus::ConsensusError::BadParentHash {
                            // A valid-looking child of another same-height tip is
                            // the normal shape of a two-miner race.  Do not pull
                            // its large body against the wrong pre-state; first
                            // recover a linked header suffix and common ancestor.
                            let fetch_from =
                                our_height.saturating_sub(CONSENSUS_FINALITY_DEPTH);
                            let fetch_count =
                                (CONSENSUS_FINALITY_DEPTH as u16 * 2).min(512);
                            let request_key = (from, fetch_from, fetch_count);
                            let recently_requested = recent_header_fetches
                                .get(&request_key)
                                .is_some_and(|t| t.elapsed() < FETCH_DEDUP_TTL);
                            if !recently_requested && !fetch_in_progress.contains(&from) {
                                if try_dispatch_header_fetch(
                                    &p2p_cmd,
                                    &mut fetch_in_progress,
                                    &mut recent_header_fetches,
                                    from,
                                    fetch_from,
                                    fetch_count,
                                    Instant::now(),
                                ) {
                                    tracing::info!(
                                        peer = %from,
                                        our_height,
                                        announced_height = height,
                                        fetch_from,
                                        "competing parent announced — fetching headers for fork choice"
                                    );
                                }
                            }
                        } else {
                            tracing::debug!(
                                peer = %from,
                                height,
                                err = %e,
                                "compact block header precheck failed — not pulling block body"
                            );
                        }
                        continue;
                    }

                    // A native-valid header is control-plane authority for
                    // fork choice, but it is not yet proof that the exact
                    // body and recursive terminal remain obtainable. Keep
                    // mining on the committed view until an immutable exact
                    // data plan has actually been admitted. This prevents a
                    // header-only source from pinning miners in sync forever.
                    mining_peer_quorum.observe_compatible(from);
                    record_authenticated_height!(height, from);

                    let cumulative_work = noid_chain::add_work(
                        &base_work,
                        &noid_chain::block_work(&announced_header.difficulty_target),
                    );
                    let validated = noid_node::networking::header_dag::ValidatedHeader::new_after_consensus_checks(
                        announced_header,
                        cumulative_work,
                    );
                    if let Err(error) = record_validated_headers(&mut header_dag, &[validated]) {
                        header_dag_faulted = true;
                        tracing::warn!(
                            peer = %from,
                            height,
                            %error,
                            "validated direct-child header could not enter the bounded DAG"
                        );
                        continue;
                    }

                    if header_dag.best_tip() != validated.point() {
                        mining_peer_quorum.observe_compatible(from);
                        tracing::debug!(
                            peer = %from,
                            height,
                            best_height = header_dag.best_tip().height,
                            "validated direct child retained; HeaderDAG selected another tip"
                        );
                        continue;
                    }
                    if announcement_data_blocked {
                        deferred_sync_peer = Some(from);
                        tracing::debug!(
                            peer = %from,
                            height,
                            "HeaderDAG selected direct child; object scheduling deferred"
                        );
                        continue;
                    }

                    if let Some(record) = exact_inventory
                        .filter(|_| !rejected_suffix_object_peers.contains(&from))
                    {
                        match noid_node::networking::suffix_sync::SuffixOffer::live(
                            base,
                            vec![validated],
                            &[record],
                        ) {
                            Ok(offer) => {
                                let domain = peer_failure_domains.get(&from).copied().unwrap_or(
                                    noid_node::networking::FailureDomain(u64::MAX),
                                );
                                match admit_exact_suffix_offer(
                                    &mut active_suffix_sync,
                                    from,
                                    domain,
                                    offer,
                                ) {
                                    Ok(admission) => {
                                        if matches!(admission, SuffixAdmission::DeferredExtension) {
                                            deferred_sync_peer = Some(from);
                                        }
                                        if suffix_admission_made_progress(admission) {
                                            suffix_plan_last_progress = Some(Instant::now());
                                            suffix_provider_discovery_rounds = 0;
                                            if matches!(
                                                admission,
                                                SuffixAdmission::Started
                                                    | SuffixAdmission::Replaced
                                            ) {
                                                suffix_inventory_probe_peers.clear();
                                            }
                                        }
                                        tracing::debug!(
                                            peer = %from,
                                            height,
                                            admission = match admission {
                                                SuffixAdmission::Started => "started",
                                                SuffixAdmission::Merged => "merged",
                                                SuffixAdmission::Duplicate => "duplicate",
                                                SuffixAdmission::DeferredExtension => "deferred-extension",
                                                SuffixAdmission::Replaced => "replaced",
                                                SuffixAdmission::KeptStrongerActive => "kept-stronger",
                                            },
                                            "exact direct-child suffix admitted"
                                        );
                                        mining_peer_quorum.set_sync_state(
                                            *initial_sync_ready.borrow(),
                                            true,
                                        );
                                        if let Some(sync) = active_suffix_sync.as_mut() {
                                            dispatch_exact_suffix_requests(sync, &p2p_cmd);
                                        }
                                        try_start_exact_suffix_apply!();
                                    }
                                    Err(error) => {
                                        tracing::warn!(peer = %from, height, %error, "exact direct-child plan rejected");
                                    }
                                }
                            }
                            Err(error) => {
                                tracing::warn!(peer = %from, height, %error, "exact direct-child inventory rejected");
                            }
                        }
                        continue;
                    }

                    // A gossipsub forwarder is authoritative for neither
                    // advertised object. Ask its storage-backed inventory;
                    // if it is still catching up, periodic probes will
                    // discover another exact provider. Network v7 never falls
                    // back to complete-bundle pull for ordinary catch-up.
                    let count = 2;
                    let mut candidates = Vec::with_capacity(EXACT_INVENTORY_PROBE_LANES);
                    if !rejected_suffix_object_peers.contains(&from) {
                        candidates.push(from);
                    }
                    let mut excluded = rejected_suffix_object_peers.clone();
                    excluded.insert(from);
                    let alternate_limit = EXACT_INVENTORY_PROBE_LANES
                        .saturating_sub(candidates.len());
                    candidates.extend(rotating_manifest_peers(
                        &locally_selected_peers,
                        &excluded,
                        None,
                        false,
                        &mut exact_inventory_probe_cursor,
                        alternate_limit,
                    ));
                    if candidates.len() < EXACT_INVENTORY_PROBE_LANES {
                        excluded.extend(candidates.iter().copied());
                        let remaining = EXACT_INVENTORY_PROBE_LANES - candidates.len();
                        candidates.extend(rotating_manifest_peers(
                            &manifest_peers,
                            &excluded,
                            None,
                            false,
                            &mut exact_inventory_probe_cursor,
                            remaining,
                        ));
                    }

                    let requested_at = Instant::now();
                    let mut dispatched = 0usize;
                    for peer in candidates {
                        let request_key = (peer, our_height, count);
                        let recently_requested = recent_header_fetches
                            .get(&request_key)
                            .is_some_and(|requested| {
                                requested.elapsed() < EXACT_INVENTORY_RETRY_TTL
                            });
                        if fetch_in_progress.contains(&peer) || recently_requested {
                            continue;
                        }
                        if try_dispatch_header_fetch(
                            &p2p_cmd,
                            &mut fetch_in_progress,
                            &mut recent_header_fetches,
                            peer,
                            our_height,
                            count,
                            requested_at,
                        ) {
                            dispatched = dispatched.saturating_add(1);
                        }
                    }
                    if dispatched > 0 {
                        last_exact_inventory_probe = requested_at;
                    }
                    tracing::debug!(
                        forwarding_peer = %from,
                        height,
                        dispatched,
                        "gossip-only child triggered bounded exact-inventory discovery"
                    );
                    continue;
                } else {
                    // Recent gap > 1: pull headers first so complete block bundles are
                    // requested only after the header chain is anchored to our tip.
                    let count = (height - our_height + 1).min(512) as u16;
                    let request_key = (from, our_height, count);
                    let recently_requested = recent_header_fetches
                        .get(&request_key)
                        .is_some_and(|t| t.elapsed() < FETCH_DEDUP_TTL);
                    if fetch_in_progress.contains(&from) || recently_requested {
                        tracing::debug!(peer = %from, height, our_height, "header fetch already in-flight for compact gap");
                        continue;
                    }
                    try_dispatch_header_fetch(
                        &p2p_cmd,
                        &mut fetch_in_progress,
                        &mut recent_header_fetches,
                        from,
                        our_height,
                        count,
                        Instant::now(),
                    );
                }
            }
            Ok(NetworkEvent::ObjectsResponse {
                token,
                from,
                objects,
                inbound_memory_permit,
            }) => {
                let Some(sync) = active_suffix_sync.as_mut() else {
                    tracing::debug!(
                        token,
                        peer = %from,
                        objects = objects.len(),
                        "discarding stale exact-object response"
                    );
                    continue;
                };
                match sync.accept_response(
                    token,
                    from,
                    objects,
                    inbound_memory_permit,
                ) {
                    Ok(received) => {
                        if received > 0 {
                            suffix_plan_last_progress = Some(Instant::now());
                            suffix_provider_discovery_rounds = 0;
                        }
                        dispatch_exact_suffix_requests(sync, &p2p_cmd);
                        try_start_exact_suffix_apply!();
                    }
                    Err(
                        noid_node::networking::suffix_sync::SuffixSyncError::UnknownToken,
                    ) => {
                        tracing::debug!(
                            token,
                            peer = %from,
                            "discarding response for a superseded exact-object request"
                        );
                    }
                    Err(
                        noid_node::networking::suffix_sync::SuffixSyncError::ContentMismatch,
                    ) => {
                        sync.quarantine_provider(from);
                        let newly_rejected = quarantine_exact_suffix_sources(
                            &mut header_dag,
                            &mut rejected_suffix_object_peers,
                            &[from],
                        );
                        tracing::warn!(
                            token,
                            peer = %from,
                            newly_rejected,
                            "content-invalid exact-object provider quarantined; plan progress preserved"
                        );
                        dispatch_exact_suffix_requests(sync, &p2p_cmd);
                    }
                    Err(error) => {
                        tracing::warn!(
                            token,
                            peer = %from,
                            %error,
                            "exact-object response rejected; preserving unrelated plan progress"
                        );
                        dispatch_exact_suffix_requests(sync, &p2p_cmd);
                    }
                }
            }
            Ok(NetworkEvent::ObjectsRequestFailed {
                token,
                from,
                objects,
                kind,
            }) => {
                let Some(sync) = active_suffix_sync.as_mut() else {
                    tracing::debug!(
                        token,
                        peer = %from,
                        objects = objects.len(),
                        ?kind,
                        "discarding failure for a superseded exact-object request"
                    );
                    continue;
                };
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let result = match kind {
                    noid_p2p::RequestFailureKind::LocalCapacity => {
                        sync.defer_request(token, from, &objects)
                    }
                    noid_p2p::RequestFailureKind::InvalidResponse => {
                        sync.reject_response_provider(token, from, &objects)
                    }
                    noid_p2p::RequestFailureKind::Unavailable => {
                        sync.request_unavailable(token, from, &objects)
                    }
                    _ => sync.request_failed(token, from, &objects, now_ms),
                };
                match result {
                    Ok(()) => {
                        let rejected = matches!(kind, noid_p2p::RequestFailureKind::InvalidResponse);
                        let newly_rejected = if rejected {
                            quarantine_exact_suffix_sources(
                                &mut header_dag,
                                &mut rejected_suffix_object_peers,
                                &[from],
                            )
                        } else {
                            0
                        };
                        tracing::debug!(
                            token,
                            peer = %from,
                            objects = objects.len(),
                            ?kind,
                            newly_rejected,
                            "exact-object source lease failed; rotating only affected objects"
                        );
                        dispatch_exact_suffix_requests(sync, &p2p_cmd);
                    }
                    Err(
                        noid_node::networking::suffix_sync::SuffixSyncError::UnknownToken,
                    ) => {
                        tracing::debug!(
                            token,
                            peer = %from,
                            ?kind,
                            "discarding failure for an expired exact-object lease"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(
                            token,
                            peer = %from,
                            ?kind,
                            %error,
                            "exact-object failure correlation rejected"
                        );
                        dispatch_exact_suffix_requests(sync, &p2p_cmd);
                    }
                }
            }
            Ok(NetworkEvent::ObjectsRequestBusy {
                token,
                from,
                objects,
                retry_after_ms,
            }) => {
                let Some(sync) = active_suffix_sync.as_mut() else {
                    tracing::debug!(token, peer = %from, "discarding busy response for a superseded exact-object request");
                    continue;
                };
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                match sync.request_busy(
                    token,
                    from,
                    &objects,
                    now_ms.saturating_add(u64::from(retry_after_ms)),
                ) {
                    Ok(()) => {
                        tracing::debug!(token, peer = %from, retry_after_ms, "exact-object provider is busy; plan and source retained");
                    }
                    Err(noid_node::networking::suffix_sync::SuffixSyncError::UnknownToken) => {}
                    Err(error) => {
                        tracing::warn!(token, peer = %from, %error, "busy exact-object response failed correlation");
                    }
                }
                dispatch_exact_suffix_requests(sync, &p2p_cmd);
            }
            Ok(NetworkEvent::MempoolSyncResponse {
                from,
                txs,
                inbound_memory_permit,
            }) => {
                tracing::info!(
                    peer = %from,
                    tx_count = txs.len(),
                    "mempool sync: received pending TXs from peer"
                );
                let mempool_task = mempool.clone();
                let mut initial_sync_ready_task = initial_sync_ready.subscribe();
                let chain_task = Arc::clone(&chain);
                tokio::spawn(async move {
                    {
                        let h = chain_task.read().await.tip_height();
                        if h == 0 && !*initial_sync_ready_task.borrow() {
                            tracing::debug!("mempool sync: waiting for state sync before admitting TXs");
                            if initial_sync_ready_task.changed().await.is_err() {
                                tracing::debug!("mempool sync: readiness channel closed — dropping deferred TXs");
                                return;
                            }
                            tracing::debug!("mempool sync: state ready, submitting {} TXs", txs.len());
                        }
                    }
                    for intent_bytes in txs {
                        if intent_bytes.len() > MAX_TX_INTENT_BYTES_GLOBAL {
                            tracing::debug!(
                                size = intent_bytes.len(),
                                max = MAX_TX_INTENT_BYTES_GLOBAL,
                                "mempool sync: tx dropped before decode due to size cap"
                            );
                            continue;
                        }
                        if let Ok(intent) = noid_tx::PagedSpendIntent::from_bytes(&intent_bytes) {
                            match mempool_task.submit(intent, intent_bytes).await {
                                Ok(hash) => {
                                    tracing::debug!(hash = ?hash, "mempool sync: tx admitted");
                                }
                                Err(e) if e.is_soft() => {}
                                Err(e) => {
                                    tracing::debug!(err = %e, "mempool sync: tx rejected");
                                }
                            }
                        }
                    }
                    // The decoded response owns one process-global inbound
                    // reservation. Release it only after every intent has been
                    // submitted or rejected by the local admission pipeline.
                    drop(inbound_memory_permit);
                });
            }
            Ok(NetworkEvent::NewTx {
                from,
                intent_bytes,
                gossip_message_id,
                inbound_memory_permit,
            }) => {
                // Hard cap: reject oversized payloads before any processing.
                if intent_bytes.len() > MAX_TX_INTENT_BYTES_GLOBAL {
                    tracing::debug!(
                        peer = %from,
                        size = intent_bytes.len(),
                        max = MAX_TX_INTENT_BYTES_GLOBAL,
                        "tx dropped: exceeds global TxIntent wire size limit"
                    );
                    resolve_tx_gossip(
                        &p2p_cmd,
                        from,
                        gossip_message_id,
                        libp2p::gossipsub::MessageAcceptance::Reject,
                    );
                    continue;
                }

                tracing::debug!(peer = %from, "received tx from P2P");

                // Per-peer rate limiting: enforce before any further processing.
                // This check is synchronous (O(1) HashMap lookup) so the event loop
                // is not blocked; the heavy AuthGKR authorization verification is spawned below.
                {
                    let now = Instant::now();
                    let entry = peer_tx_rate.entry(from).or_insert((0, now));
                    if now.duration_since(entry.1) > TX_RATE_WINDOW {
                        *entry = (1, now);
                    } else if entry.0 >= TX_RATE_MAX {
                        tracing::debug!(peer = %from, "tx rate limit exceeded, dropping");
                        resolve_tx_gossip(
                            &p2p_cmd,
                            from,
                            gossip_message_id,
                            libp2p::gossipsub::MessageAcceptance::Ignore,
                        );
                        continue;
                    } else {
                        entry.0 += 1;
                    }
                }

                // Periodic cleanup of stale rate-limit entries.
                tx_event_count += 1;
                if tx_event_count.is_multiple_of(100) {
                    let cutoff = Instant::now() - Duration::from_secs(60);
                    peer_tx_rate.retain(|_, (_, window_start)| *window_start >= cutoff);
                }

                // Spawn AuthGKR authorization verification + mempool admit as a background task.
                //
                // WHY: `mempool.submit()` runs an AuthGKR authorization verification (~84ms, CPU-bound via
                // spawn_blocking) under an async semaphore. If we await it here, the
                // entire P2P event loop stalls for 84ms — delaying block propagation.
                //
                // SAFETY: `mempool.submit()` never touches the chain (Arc<RwLock<...>>),
                // only the mempool's internal Arc<Mutex<MempoolState>>. Concurrent task
                // access is safe. P2P relay of admitted txs is handled by the dedicated
                // relay task spawned in main() — no extra work needed here.
                let mempool_task = mempool.clone();
                let p2p_cmd_task = p2p_cmd.clone();
                tokio::spawn(async move {
                    let acceptance = match noid_tx::PagedSpendIntent::from_bytes(&intent_bytes) {
                        Ok(intent) => match mempool_task.submit(intent, intent_bytes).await {
                            Ok(hash) => {
                                tracing::debug!(hash = ?hash, "P2P tx admitted");
                                libp2p::gossipsub::MessageAcceptance::Accept
                            }
                            Err(e) if e.is_soft() => {
                                // Soft reject (duplicate, slot conflict) — normal, ignore.
                                libp2p::gossipsub::MessageAcceptance::Ignore
                            }
                            Err(e) => {
                                tracing::debug!(err = %e, "P2P tx rejected");
                                // Consensus admission can depend on the current
                                // tip. Do not penalize the forwarding peer for
                                // a transaction that became stale in flight.
                                libp2p::gossipsub::MessageAcceptance::Ignore
                            }
                        },
                        Err(error) => {
                            tracing::debug!(%error, "P2P tx wire decode rejected");
                            libp2p::gossipsub::MessageAcceptance::Reject
                        }
                    };
                    resolve_tx_gossip(
                        &p2p_cmd_task,
                        from,
                        gossip_message_id,
                        acceptance,
                    );
                    // A direct relay owns one process-global inbound byte
                    // reservation. Gossip messages carry `None`.
                    drop(inbound_memory_permit);
                });
            }
            Ok(NetworkEvent::PeerConnected {
                peer,
                locally_selected,
                failure_domain,
            }) => {
                tracing::info!(peer = %peer, "peer connected");
                peer_failure_domains.insert(
                    peer,
                    noid_node::networking::FailureDomain(failure_domain),
                );
                mining_peer_quorum.connect(
                    peer,
                    noid_node::networking::FailureDomain(failure_domain),
                );
                manifest_peers.insert(peer);
                if locally_selected {
                    locally_selected_peers.insert(peer);
                } else {
                    locally_selected_peers.remove(&peer);
                }

                let our_height = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };

                let (discover_chain, request_mempool) = peer_connect_bootstrap_policy(
                    locally_selected,
                    *initial_sync_ready.borrow(),
                    mempool_sync_requested_peers.len(),
                );
                if discover_chain {
                    // Manifest and tip discovery are independent, tiny
                    // requests. Only our bounded outbound neighbour set starts
                    // them; an inbound wallet cannot make a seed reciprocate.
                    if snapshot_install_inflight.is_none() {
                        try_request_manifest!(peer, our_height, [0; 32]);
                    }

                    // During snapshot admission, the selected boundary record
                    // is more useful than another genesis-anchored tip probe:
                    // it advertises whether this peer still retains the exact
                    // terminal even when it publishes a newer State generation.
                    let snapshot_terminal_probe = pending_manifest
                        .as_ref()
                        .filter(|pending| pending.history_step.is_none())
                        .filter(|_| {
                            history_step_verification_inflight.is_none()
                                && prefetched_snapshot_boundary_terminal.is_none()
                        })
                        .map(|pending| pending.offer.snapshot_id().boundary);
                    let (probe_start_height, probe_count) = snapshot_terminal_probe
                        .map_or((our_height, CONNECTED_TIP_PROBE_HEADERS), |boundary| {
                            (boundary.height, 1)
                        });
                    let now = Instant::now();
                    if try_dispatch_header_fetch(
                        &p2p_cmd,
                        &mut fetch_in_progress,
                        &mut recent_header_fetches,
                        peer,
                        probe_start_height,
                        probe_count,
                        now,
                    ) {
                        if snapshot_terminal_probe.is_some() {
                            tracing::debug!(
                                peer = %peer,
                                boundary_height = probe_start_height,
                                "probing connected peer for retained snapshot terminal"
                            );
                        } else {
                            mining_peer_quorum.mark_probe_sent(peer, now);
                            tracing::debug!(
                                peer = %peer,
                                start_height = our_height,
                                "probing connected peer tip with anchored headers"
                            );
                        }
                    }
                }

                // Mempool payloads can be much larger than the complete cold
                // snapshot. Pull once from at most four maintained outbound
                // neighbours, never from every inbound connection.
                if request_mempool
                    && !mempool_sync_requested_peers.contains(&peer)
                    && p2p_cmd
                        .try_send(noid_p2p::NetworkCommand::RequestMempoolSync { peer })
                        .is_ok()
                {
                    mempool_sync_requested_peers.insert(peer);
                }
            }
            Ok(NetworkEvent::SnapshotHeadersBatch {
                generation,
                token,
                from,
                start_height,
                requested_count,
                headers,
                snapshot_boundary,
            }) => {
                if let Some(boundary) = snapshot_boundary.filter(|boundary| {
                    boundary.height > 0
                        && boundary.height % noid_p2p::protocol::SNAPSHOT_BOUNDARY_INTERVAL == 0
                        && boundary.hash != [0; 32]
                }) {
                    let pinned = pending_manifest
                        .as_ref()
                        .filter(|pending| pending.history_step.is_none())
                        .map(|pending| ManifestTerminalCapability {
                            boundary_height: pending.manifest.tip_height,
                            boundary_hash: pending.manifest.tip_hash,
                        });
                    remember_terminal_capability(
                        &mut manifest_terminal_capabilities,
                        from,
                        ManifestTerminalCapability {
                            boundary_height: boundary.height,
                            boundary_hash: boundary.hash,
                        },
                        pinned,
                    );
                }
                let Some(pipeline) = snapshot_header_pipeline.as_mut() else {
                    tracing::debug!(
                        peer = %from,
                        generation,
                        start_height,
                        "dropping snapshot headers without an active pipeline"
                    );
                    continue;
                };
                if !pipeline.matches_generation(generation) {
                    tracing::debug!(
                        peer = %from,
                        generation,
                        active_generation = pipeline.generation,
                        start_height,
                        "dropping delayed snapshot headers from a superseded session"
                    );
                    continue;
                }
                if !pipeline.matches_outstanding(from, start_height, requested_count, token) {
                    tracing::debug!(
                        peer = %from,
                        generation,
                        token,
                        start_height,
                        requested_count,
                        "dropping delayed snapshot headers from a retired exact request"
                    );
                    continue;
                }
                if let Err(error) = pipeline.accept(
                    generation,
                    token,
                    from,
                    start_height,
                    requested_count,
                    headers,
                ) {
                    let failed_generation_peer = pipeline.preferred_peer;
                    let retry = pipeline.failure_plan(
                        from,
                        start_height,
                        requested_count,
                        token,
                        noid_p2p::RequestFailureKind::InvalidResponse,
                        &manifest_peers,
                    );
                    tracing::warn!(
                        peer = %from,
                        generation,
                        start_height,
                        requested_count,
                        err = %error,
                        "snapshot header response failed exact validation"
                    );
                    if let Some(request) = retry {
                        dispatch_snapshot_header_plans(
                            pipeline,
                            &p2p_cmd,
                            std::iter::once(request),
                        );
                    } else {
                        tracing::warn!(
                            preferred_peer = %failed_generation_peer,
                            start_height,
                            "invalid snapshot header range exhausted current sources; exact plan is parked"
                        );
                        request_snapshot_generation_providers!(failed_generation_peer);
                    }
                    continue;
                }
                snapshot_plan_last_progress = Some(Instant::now());
                snapshot_provider_discovery_rounds = 0;

                if snapshot_header_staging_inflight.is_some() {
                    tracing::debug!(
                        peer = %from,
                        start_height,
                        requested_count,
                        buffered = pipeline.ready.len(),
                        "snapshot header response retained in bounded reorder window"
                    );
                    continue;
                }

                let Some(sync) = pending_snapshot_header_sync.take() else {
                    tracing::warn!(
                        peer = %from,
                        start_height,
                        "snapshot header pipeline lost its disk staging session"
                    );
                    return Err(anyhow::anyhow!(
                        "snapshot header pipeline lost its disk staging session"
                    ));
                };
                let Some(range) = pipeline.take_ready(sync.next_height) else {
                    pending_snapshot_header_sync = Some(sync);
                    continue;
                };
                if let Err(error) = validate_snapshot_header_batch_admission(
                    sync.next_height,
                    sync.target_height,
                    range.headers.len(),
                ) {
                    tracing::warn!(
                        peer = %range.source_peer,
                        headers = range.headers.len(),
                        err = %error,
                        "snapshot header batch failed bounded staging admission"
                    );
                    cleanup_snapshot_header_staging_offthread(sync.staging);
                    return Err(anyhow::anyhow!(
                        "snapshot header batch violated bounded staging admission: {error}"
                    ));
                }
                let refill = pipeline.refill_plan(true);
                dispatch_snapshot_header_plans(pipeline, &p2p_cmd, refill);
                spawn_snapshot_header_append!(sync, range);
                continue;
            }
            Ok(NetworkEvent::SnapshotHeadersRequestFailed {
                generation,
                token,
                from,
                start_height,
                count,
                kind,
            }) => {
                let correlated = snapshot_header_pipeline.as_ref().is_some_and(|pipeline| {
                    pipeline.matches_generation(generation)
                        && pipeline.matches_outstanding(from, start_height, count, token)
                });
                if !correlated {
                    tracing::debug!(
                        peer = %from,
                        generation,
                        token,
                        start_height,
                        count,
                        "ignoring stale snapshot header request failure"
                    );
                    continue;
                }
                if kind == noid_p2p::RequestFailureKind::LocalCapacity {
                    let request = SnapshotHeaderRequestPlan {
                        peer: from,
                        token,
                        start_height,
                        count,
                    };
                    snapshot_header_pipeline
                        .as_mut()
                        .expect("correlated snapshot header pipeline is present")
                        .defer_dispatch(request)
                        .expect("correlated local-capacity range remains outstanding");
                    tracing::debug!(
                        peer = %from,
                        generation,
                        start_height,
                        count,
                        "snapshot header range deferred behind local correlation capacity"
                    );
                    continue;
                }
                let retry = snapshot_header_pipeline
                    .as_mut()
                    .and_then(|pipeline| {
                        pipeline.failure_plan(
                            from,
                            start_height,
                            count,
                            token,
                            kind,
                            &manifest_peers,
                        )
                    });
                let Some(request) = retry else {
                    let failed_generation_peer = snapshot_header_pipeline
                        .as_ref()
                        .map_or(from, |pipeline| pipeline.preferred_peer);
                    tracing::warn!(
                        peer = %from,
                        generation,
                        start_height,
                        count,
                        ?kind,
                        "snapshot header range exhausted current sources; exact plan is parked"
                    );
                    request_snapshot_generation_providers!(failed_generation_peer);
                    continue;
                };
                dispatch_snapshot_header_plans(
                    snapshot_header_pipeline
                        .as_mut()
                        .expect("retry belongs to the active snapshot header pipeline"),
                    &p2p_cmd,
                    std::iter::once(request),
                );
                tracing::warn!(
                    peer = %from,
                    retry_peer = %request.peer,
                    start_height,
                    count,
                    ?kind,
                    "snapshot header request failed; retrying only the exact range"
                );
                continue;
            }
            Ok(NetworkEvent::HeaderInventoryBatch {
                from,
                records,
                snapshot_boundary,
            }) => {
                suffix_inventory_probe_peers.remove(&from);
                let pinned_terminal = pending_manifest
                    .as_ref()
                    .filter(|pending| pending.history_step.is_none())
                    .map(|pending| ManifestTerminalCapability {
                        boundary_height: pending.manifest.tip_height,
                        boundary_hash: pending.manifest.tip_hash,
                    });
                let retained_terminal = pinned_terminal.and_then(|target| {
                    retained_terminal_capability(
                        &records,
                        target.boundary_height,
                        target.boundary_hash,
                    )
                });
                let exact_boundary_probe = pinned_terminal.is_some_and(|target| {
                    is_single_header_inventory_for_point(
                        &records,
                        target.boundary_height,
                        target.boundary_hash,
                    )
                });
                if let Some(boundary) = snapshot_boundary.filter(|boundary| {
                    boundary.height > 0
                        && boundary.height % noid_p2p::protocol::SNAPSHOT_BOUNDARY_INTERVAL == 0
                        && boundary.hash != [0; 32]
                }) {
                    remember_terminal_capability(
                        &mut manifest_terminal_capabilities,
                        from,
                        ManifestTerminalCapability {
                            boundary_height: boundary.height,
                            boundary_hash: boundary.hash,
                        },
                        pinned_terminal,
                    );
                }
                let header_count = records.len();
                // Headers batch arrived — clear the in-progress guard.
                fetch_in_progress.remove(&from);
                if let Some(capability) = retained_terminal
                    .filter(|_| !rejected_terminal_peers.contains(&from))
                {
                    remember_terminal_capability(
                        &mut manifest_terminal_capabilities,
                        from,
                        capability,
                        pinned_terminal,
                    );
                    snapshot_plan_last_progress = Some(Instant::now());
                    snapshot_provider_discovery_rounds = 0;
                }
                if exact_boundary_probe {
                    ensure_snapshot_boundary_terminal_request!();
                    tracing::debug!(
                        peer = %from,
                        boundary_height = pinned_terminal.map(|target| target.boundary_height),
                        terminal = retained_terminal.is_some(),
                        "retained snapshot boundary inventory received"
                    );
                    continue;
                }
                if !rejected_suffix_object_peers.contains(&from) {
                    let domain = peer_failure_domains
                        .get(&from)
                        .copied()
                        .unwrap_or(noid_node::networking::FailureDomain(u64::MAX));
                    match merge_active_suffix_inventory(
                        &mut active_suffix_sync,
                        from,
                        domain,
                        &records,
                    ) {
                        Ok(added) => {
                            if added > 0 {
                                suffix_plan_last_progress = Some(Instant::now());
                                suffix_provider_discovery_rounds = 0;
                                tracing::debug!(
                                    peer = %from,
                                    added,
                                    "exact inventory merged into the pinned suffix below the newer HeaderDAG tip"
                                );
                            }
                            if let Some(sync) = active_suffix_sync.as_mut() {
                                dispatch_exact_suffix_requests(sync, &p2p_cmd);
                            }
                            try_start_exact_suffix_apply!();
                        }
                        Err(error) => {
                            tracing::warn!(
                                peer = %from,
                                %error,
                                "exact inventory did not satisfy the pinned suffix"
                            );
                        }
                    }
                }
                if manifest_peers.contains(&from)
                    && !rejected_suffix_object_peers.contains(&from)
                {
                    match advertise_inventory_for_known_headers(
                        &mut header_dag,
                        from,
                        &records,
                    ) {
                        Ok(added) if added > 0 => {
                            tracing::debug!(
                                peer = %from,
                                added,
                                "exact inventory attached to already validated HeaderDAG headers"
                            );
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(
                                peer = %from,
                                %error,
                                "known-header exact inventory was not attached to HeaderDAG"
                            );
                        }
                    }
                }
                // Data admission may be busy, but native-validated headers are
                // control-plane authority and must still enter HeaderDAG. A
                // busy data plane only defers object scheduling.
                let mut data_plan_blocked = snapshot_plan_active!()
                    || snapshot_install_inflight.is_some()
                    || exact_suffix_apply_inflight.is_some();
                if data_plan_blocked {
                    deferred_sync_peer = Some(from);
                    tracing::debug!(
                        peer = %from,
                        headers = header_count,
                        "data admission busy — retaining headers and deferring object plan"
                    );
                }

                let plan = plan_header_inventory(
                    &chain,
                    &snapshot_header_store,
                    &header_dag,
                    records,
                )
                .await;
                match plan {
                    Ok(HeaderInventoryPlan::Confirmed { tip }) => {
                        finalized_divergent_peers.remove(&from);
                        if active_suffix_sync.is_none() && tip.height >= highest_announced {
                            clear_manifest_round_state!();
                            mark_initial_sync_ready(&initial_sync_ready);
                            mining_peer_quorum.confirm_tip(from, tip.height, tip.hash);
                            mark_bootstrap_complete_if_caught_up!(tip.height);
                        }
                        tracing::debug!(
                            peer = %from,
                            height = tip.height,
                            "validated header inventory confirms the canonical tip"
                        );
                    }
                    Ok(HeaderInventoryPlan::Behind) => {
                        tracing::debug!(
                            peer = %from,
                            "header inventory is behind the canonical view"
                        );
                    }
                    Ok(HeaderInventoryPlan::NeedOlder {
                        start_height,
                        count,
                    }) => {
                        let request_key = (from, start_height, count);
                        let recently_requested = recent_header_fetches
                            .get(&request_key)
                            .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL);
                        if !fetch_in_progress.contains(&from) && !recently_requested {
                            try_dispatch_header_fetch(
                                &p2p_cmd,
                                &mut fetch_in_progress,
                                &mut recent_header_fetches,
                                from,
                                start_height,
                                count,
                                Instant::now(),
                            );
                        }
                    }
                    Ok(HeaderInventoryPlan::Candidate {
                        headers,
                        records,
                        old_tip,
                        target,
                    }) => {
                        finalized_divergent_peers.remove(&from);
                        if let Err(error) = record_validated_headers(&mut header_dag, &headers) {
                            header_dag_faulted = true;
                            tracing::warn!(
                                peer = %from,
                                target_height = target.height,
                                %error,
                                "validated header branch could not enter the bounded DAG"
                            );
                            continue;
                        }
                        if !manifest_peers.contains(&from) {
                            // A disconnect event may overtake a previously
                            // decoded data-lane response. Its headers remain
                            // useful, but a closed session is not a current
                            // exact-object source.
                            tracing::debug!(
                                peer = %from,
                                target_height = target.height,
                                "retaining late headers without disconnected object inventory"
                            );
                        } else if rejected_suffix_object_peers.contains(&from) {
                            tracing::debug!(
                                peer = %from,
                                target_height = target.height,
                                "ignoring exact-object inventory from a rejected data provider"
                            );
                        } else if let Err(error) = header_dag.advertise_inventory(from, &records) {
                            // Availability is never header authority. A bad or
                            // over-capacity provider hint cannot invalidate an
                            // otherwise native-validated branch.
                            tracing::warn!(
                                peer = %from,
                                target_height = target.height,
                                %error,
                                "validated object inventory was not attached to HeaderDAG"
                            );
                        }
                        record_authenticated_height!(target.height, from);

                        // HeaderDAG, not the peer and not the object inventory,
                        // decides whether this exact target is authoritative.
                        if header_dag.best_tip() != target {
                            mining_peer_quorum.observe_compatible(from);
                            tracing::debug!(
                                peer = %from,
                                target_height = target.height,
                                best_height = header_dag.best_tip().height,
                                "validated branch retained; HeaderDAG selected another tip"
                            );
                            continue;
                        }

                        let (selected_base, selected_headers) =
                            match header_dag.selected_path_from(old_tip) {
                                Ok(selected) => selected,
                                Err(error) => {
                                    header_dag_faulted = true;
                                    tracing::error!(
                                        peer = %from,
                                        target_height = target.height,
                                        %error,
                                        "HeaderDAG could not freeze its selected ancestry"
                                    );
                                    continue;
                                }
                            };
                        // The winning ancestry may have been assembled from
                        // several peers. Freeze the DAG path itself; exact
                        // object availability is merged independently below.
                        let base = selected_base;
                        let headers = selected_headers;
                        let target = headers
                            .last()
                            .expect("HeaderDAG selected a non-empty candidate suffix")
                            .point();

                        // Header authority and object availability are kept
                        // separate. A valid stronger header renews peer
                        // health, but mining pauses only after a concrete
                        // suffix/snapshot data plan exists.
                        mining_peer_quorum.observe_compatible(from);

                        let selected_rebase_base = (base != old_tip).then_some(base);
                        if base == old_tip {
                            if let Some(tail) = post_snapshot_tail.as_mut() {
                                let was_unpinned = tail.target.is_none();
                                if tail.pin_selected_target(old_tip, target) && was_unpinned {
                                    tracing::info!(
                                        boundary_height = tail.boundary.height,
                                        target_height = target.height,
                                        "post-snapshot exact tail pinned to authenticated HeaderDAG target"
                                    );
                                }
                            }
                        }
                        let needs_snapshot = if base == old_tip {
                            sync_target_requires_snapshot(
                                old_tip.height,
                                target.height,
                                post_snapshot_tail,
                            )
                        } else {
                            old_tip.height.saturating_sub(base.height)
                                > noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH
                                || headers.len()
                                    > noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH
                                        as usize
                                        * 2
                        };

                        // A snapshot manifest can race ahead of the header
                        // control plane after restart. If HeaderDAG later
                        // proves that the selected chain has a different
                        // non-final base, the old staging plan is objectively
                        // stale. Retire only that transport generation and
                        // keep the validated DAG/canonical database intact.
                        let snapshot_base_mismatch = pending_manifest.as_ref().is_some_and(
                            |pending| pending.rebase_base != selected_rebase_base,
                        );
                        if data_plan_blocked && snapshot_base_mismatch {
                            snapshot_rebase_hint = needs_snapshot.then_some(SnapshotRebaseHint {
                                ancestor_height: base.height,
                                ancestor_hash: base.hash,
                                competing_tip_height: target.height,
                                competing_tip_hash: target.hash,
                                armed_at: Instant::now(),
                            });
                            tracing::info!(
                                peer = %from,
                                old_base_height = old_tip.height,
                                selected_base_height = base.height,
                                target_height = target.height,
                                needs_snapshot,
                                "HeaderDAG superseded a snapshot staged on the wrong local branch"
                            );
                            retire_snapshot_plan!();
                            data_plan_blocked = snapshot_plan_active!()
                                || snapshot_install_inflight.is_some()
                                || exact_suffix_apply_inflight.is_some();
                        }
                        if data_plan_blocked {
                            tracing::debug!(
                                peer = %from,
                                target_height = target.height,
                                "HeaderDAG selected target; exact-object plan deferred"
                            );
                            continue;
                        }

                        if needs_snapshot {
                            snapshot_rebase_hint =
                                (base != old_tip).then_some(SnapshotRebaseHint {
                                    ancestor_height: base.height,
                                    ancestor_hash: base.hash,
                                    competing_tip_height: target.height,
                                    competing_tip_hash: target.hash,
                                    armed_at: Instant::now(),
                                });
                            let our_height = old_tip.height;
                            if pending_manifest.is_none()
                                && pending_snapshot_header_sync.is_none()
                                && snapshot_header_staging_inflight.is_none()
                                && history_step_verification_inflight.is_none()
                                && snapshot_staging_inflight.is_none()
                                && snapshot_install_inflight.is_none()
                                && active_snapshot_sync
                                    .as_ref()
                                    .is_none_or(|sync| sync.all_segments_verified())
                            {
                                // A proactive manifest request may already be in flight from
                                // PeerConnected. Once HeaderDAG selects a snapshot route, upgrade
                                // that exact request instead of waiting for a second round.
                                if manifest_requested_peers.contains(&from)
                                    || try_request_manifest!(from, our_height, [0; 32])
                                {
                                    manifest_force_snapshot_peers.insert(from);
                                    tracing::info!(
                                        peer = %from,
                                        our_height,
                                        peer_tip = target.height,
                                        "HeaderDAG target requires snapshot synchronization"
                                    );
                                }
                            }
                            continue;
                        }

                        match source_independent_suffix_offer(
                            &header_dag,
                            from,
                            old_tip,
                            base,
                            headers.clone(),
                        ) {
                            Ok((terminal_peer, offer, inventories)) => {
                                let plan_id = offer.plan().id();
                                let terminal_domain = peer_failure_domains
                                    .get(&terminal_peer)
                                    .copied()
                                    .unwrap_or(noid_node::networking::FailureDomain(u64::MAX));
                                clear_manifest_round_state!();
                                match admit_exact_suffix_offer(
                                    &mut active_suffix_sync,
                                    terminal_peer,
                                    terminal_domain,
                                    offer,
                                ) {
                                    Ok(admission) => {
                                        if matches!(admission, SuffixAdmission::DeferredExtension) {
                                            deferred_sync_peer = Some(from);
                                        }
                                        if suffix_admission_made_progress(admission) {
                                            suffix_plan_last_progress = Some(Instant::now());
                                            suffix_provider_discovery_rounds = 0;
                                            if matches!(
                                                admission,
                                                SuffixAdmission::Started
                                                    | SuffixAdmission::Replaced
                                            ) {
                                                suffix_inventory_probe_peers.clear();
                                            }
                                        }
                                        tracing::info!(
                                            peer = %terminal_peer,
                                            base_height = base.height,
                                            target_height = target.height,
                                            admission = match admission {
                                                SuffixAdmission::Started => "started",
                                                SuffixAdmission::Merged => "merged",
                                                SuffixAdmission::Duplicate => "duplicate",
                                                SuffixAdmission::DeferredExtension => "deferred-extension",
                                                SuffixAdmission::Replaced => "replaced",
                                                SuffixAdmission::KeptStrongerActive => "kept-stronger",
                                            },
                                            "HeaderDAG-selected exact suffix plan admitted"
                                        );
                                        mining_peer_quorum.set_sync_state(
                                            *initial_sync_ready.borrow(),
                                            true,
                                        );
                                        if let Some(sync) = active_suffix_sync
                                            .as_mut()
                                            .filter(|sync| sync.plan_id() == plan_id)
                                        {
                                            let mut added_sources = 0usize;
                                            for (provider, inventory) in inventories {
                                                let domain = peer_failure_domains
                                                    .get(&provider)
                                                    .copied()
                                                    .unwrap_or(
                                                        noid_node::networking::FailureDomain(
                                                            u64::MAX,
                                                        ),
                                                    );
                                                match sync.add_inventory(
                                                    provider, domain, &headers, &inventory,
                                                ) {
                                                    Ok(added) => {
                                                        added_sources =
                                                            added_sources.saturating_add(added);
                                                    }
                                                    Err(error) => {
                                                        tracing::warn!(
                                                            peer = %provider,
                                                            target_height = target.height,
                                                            %error,
                                                            "exact-object provider inventory rejected"
                                                        );
                                                    }
                                                }
                                            }
                                            if added_sources > 0 {
                                                suffix_plan_last_progress = Some(Instant::now());
                                                suffix_provider_discovery_rounds = 0;
                                            }
                                            dispatch_exact_suffix_requests(sync, &p2p_cmd);
                                        }
                                        try_start_exact_suffix_apply!();
                                    }
                                    Err(error) => {
                                        tracing::warn!(
                                            peer = %terminal_peer,
                                            target_height = target.height,
                                            %error,
                                            "HeaderDAG-selected suffix offer rejected"
                                        );
                                    }
                                }
                            }
                            Err(
                                noid_node::networking::suffix_sync::SuffixSyncError::MissingTipTerminal,
                            ) => {
                                let domain = peer_failure_domains.get(&from).copied().unwrap_or(
                                    noid_node::networking::FailureDomain(u64::MAX),
                                );
                                let provider_inventory =
                                    header_dag.inventory_for_provider(from, &headers);
                                let merge_result = active_suffix_sync.as_mut().and_then(|sync| {
                                    (sync.plan().base() == base
                                        && sync.plan().headers() == headers)
                                        .then(|| {
                                            sync.add_inventory(
                                                from,
                                                domain,
                                                &headers,
                                                &provider_inventory,
                                            )
                                        })
                                });
                                if let Some(result) = merge_result {
                                    match result {
                                        Ok(advertised) => {
                                            if advertised > 0 {
                                                suffix_plan_last_progress = Some(Instant::now());
                                                suffix_provider_discovery_rounds = 0;
                                            }
                                            tracing::debug!(
                                                peer = %from,
                                                base_height = base.height,
                                                target_height = target.height,
                                                advertised,
                                                "partial exact-object inventory merged into immutable plan"
                                            );
                                            if let Some(sync) = active_suffix_sync.as_mut() {
                                                dispatch_exact_suffix_requests(sync, &p2p_cmd);
                                            }
                                            try_start_exact_suffix_apply!();
                                        }
                                        Err(error) => tracing::warn!(
                                            peer = %from,
                                            target_height = target.height,
                                            %error,
                                            "partial exact-object inventory rejected"
                                        ),
                                    }
                                    continue;
                                }

                                // A semantic target can be selected from its
                                // native-validated headers, but an immutable
                                // exact-object plan also needs the tip terminal
                                // identity (including its proof class). Ask
                                // other connected storage providers without
                                // discarding any active plan or chain state.
                                let count = target
                                    .height
                                    .saturating_sub(base.height)
                                    .saturating_add(1)
                                    .min(512) as u16;
                                let excluded = std::collections::HashSet::from([from]);
                                let candidates = rotating_manifest_peers(
                                    &manifest_peers,
                                    &excluded,
                                    None,
                                    false,
                                    &mut exact_inventory_probe_cursor,
                                    2,
                                );
                                for peer in candidates {
                                    try_dispatch_header_fetch(
                                        &p2p_cmd,
                                        &mut fetch_in_progress,
                                        &mut recent_header_fetches,
                                        peer,
                                        base.height,
                                        count,
                                        Instant::now(),
                                    );
                                }
                                tracing::debug!(
                                    peer = %from,
                                    canonical_tip = old_tip.height,
                                    base_height = base.height,
                                    target_height = target.height,
                                    "validated stronger branch is waiting for an exact tip terminal"
                                );
                            }
                            Err(error) => tracing::warn!(
                                peer = %from,
                                target_height = target.height,
                                %error,
                                "HeaderDAG-selected inventory cannot form an exact plan"
                            ),
                        }
                    }
                    Ok(HeaderInventoryPlan::FinalizedDivergence) => {
                        mining_peer_quorum.reject_incompatible(from);
                        finalized_divergent_peers.insert(from);
                        manifest_requested_peers.remove(&from);
                        manifest_force_snapshot_peers.remove(&from);
                        tracing::warn!(
                            peer = %from,
                            "peer has no common ancestor inside the accepted non-final window"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(
                            peer = %from,
                            %error,
                            "header inventory failed native validation"
                        );
                    }
                }
            }
            Ok(NetworkEvent::HeadersRequestFailed {
                from,
                start_height,
                count,
                kind,
            }) => {
                suffix_inventory_probe_peers.remove(&from);
                fetch_in_progress.remove(&from);
                recent_header_fetches.remove(&(from, start_height, count));
                tracing::debug!(
                    peer = %from,
                    start_height,
                    count,
                    ?kind,
                    "general header request failed"
                );
            }
            Ok(NetworkEvent::StateManifest {
                generation,
                from,
                requester_height,
                manifest,
            }) => {
                if generation != snapshot_sync_generation {
                    tracing::debug!(
                        generation,
                        active_generation = snapshot_sync_generation,
                        from = %from,
                        requester_height,
                        "ignoring stale state-manifest response"
                    );
                    continue;
                }
                manifest_requested_peers.remove(&from);
                if finalized_divergent_peers.contains(&from) {
                    tracing::warn!(
                        from = %from,
                        tip = manifest.tip_height,
                        "ignoring manifest from a branch outside the accepted non-final window"
                    );
                    if !snapshot_plan_active!()
                        && manifest_requested_peers.is_empty()
                    {
                        request_bounded_manifest_failover!(from, false);
                    }
                    continue;
                }
                if rejected_terminal_peers.contains(&from) {
                    tracing::warn!(
                        from = %from,
                        "ignoring manifest from a peer that supplied an invalid recursive terminal"
                    );
                    if !snapshot_plan_active!()
                        && manifest_requested_peers.is_empty()
                    {
                        request_bounded_manifest_failover!(from, false);
                    }
                    continue;
                }
                if rejected_snapshot_manifest_providers
                    .get(&manifest.manifest_digest)
                    .is_some_and(|providers| providers.contains(&from))
                {
                    tracing::warn!(
                        peer = %from,
                        manifest = %hex::encode(manifest.manifest_digest),
                        "ignoring a provider already rejected for this exact snapshot"
                    );
                    continue;
                }
                let manifest_tip_height = manifest.tip_height;
                if snapshot_install_inflight.is_some() {
                    tracing::debug!(
                        from = %from,
                        tip = manifest.tip_height,
                        "snapshot install active — dropping stale manifest response"
                    );
                    continue;
                }
                // The P2P manifest assembler has already authenticated the
                // small header, every exact descriptor page and all global
                // State geometry in a blocking worker. This event carries the
                // resulting typestate, so the node loop never re-hashes a
                // multi-megabyte manifest. Headers, PoW, the recursive terminal
                // and State root remain mandatory before installation.
                let force_snapshot = manifest_force_snapshot_peers.remove(&from);
                manifest_response_count += 1;
                if manifest.tip_height == 0 {
                    tracing::debug!(from = %from, "manifest tip_height=0, peer has no state yet");
                } else if history_step_runtime.is_none() {
                    tracing::warn!(
                        from = %from,
                        tip = manifest.tip_height,
                        "snapshot manifest ignored: HistoryStep verifier unavailable"
                    );
                    continue;
                }

                let rebase_anchor = if manifest.tip_height > 0 {
                    if let Some(hint) = snapshot_rebase_hint {
                        match validate_rebase_snapshot_selection(&header_dag, hint, &manifest) {
                            Ok(anchor) => anchor,
                            Err(error) => {
                                tracing::warn!(
                                    peer = %from,
                                    boundary = manifest.tip_height,
                                    selected_tip = header_dag.best_tip().height,
                                    %error,
                                    "snapshot manifest is not bound to the HeaderDAG-selected ancestry"
                                );
                                deferred_sync_peer = Some(from);
                                continue;
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                if manifest.tip_height > 0 {
                    let pinned = pending_manifest
                        .as_ref()
                        .filter(|pending| pending.history_step.is_none())
                        .map(|pending| ManifestTerminalCapability {
                            boundary_height: pending.manifest.tip_height,
                            boundary_hash: pending.manifest.tip_hash,
                        });
                    remember_terminal_capability(
                        &mut manifest_terminal_capabilities,
                        from,
                        ManifestTerminalCapability {
                            boundary_height: manifest.tip_height,
                            boundary_hash: manifest.tip_hash,
                        },
                        pinned,
                    );
                    if pending_manifest
                        .as_ref()
                        .is_some_and(|pending| pending.manifest.as_ref() == manifest.as_ref())
                    {
                        candidate_manifest_providers.insert(from);
                        let provider_added = pending_manifest
                            .as_mut()
                            .is_some_and(|pending| pending.providers.insert(from));
                        if let Some(sync) = active_snapshot_sync.as_mut() {
                            let domain = peer_failure_domains.get(&from).copied().unwrap_or(
                                noid_node::networking::FailureDomain(u64::MAX),
                            );
                            let offer = noid_node::networking::snapshot_sync::SnapshotOffer::from_verified_manifest(
                                manifest.clone(),
                            );
                            if let Ok(offer) = offer {
                                if let Err(error) = sync.add_provider(from, domain, offer) {
                                    tracing::warn!(peer = %from, %error, "exact snapshot provider rejected");
                                    continue;
                                }
                            }
                        }
                        if provider_added {
                            snapshot_plan_last_progress = Some(Instant::now());
                            snapshot_provider_discovery_rounds = 0;
                        }
                        tracing::debug!(
                            peer = %from,
                            snapshot_height = manifest.tip_height,
                            "registered an additional exact snapshot provider"
                        );
                        ensure_snapshot_boundary_terminal_request!();
                        dispatch_snapshot_segments_from_available_source!();
                        continue;
                    }
                    let our_height = {
                        let ctx = chain.read().await;
                        ctx.tip_height()
                    };
                    retire_post_snapshot_tail_if_finished!(our_height);
                    if manifest.tip_height <= our_height {
                        tracing::debug!(
                            from = %from,
                            our_height,
                            snapshot_height = manifest.tip_height,
                            "manifest snapshot boundary not ahead"
                        );
                        if manifest_round_gap_is_resolved(our_height, highest_announced)
                            && best_manifest_candidate.is_none()
                            && pending_manifest.is_none()
                            && pending_snapshot_header_sync.is_none()
                            && snapshot_header_staging_inflight.is_none()
                            && history_step_verification_inflight.is_none()
                            && snapshot_staging.is_none()
                            && snapshot_staging_inflight.is_none()
                            && snapshot_install_inflight.is_none()
                            && active_snapshot_sync
                                .as_ref()
                                .is_none_or(|sync| sync.all_segments_verified())
                        {
                            clear_manifest_round_state!();
                            mark_bootstrap_complete_if_caught_up!(our_height);
                            tracing::debug!(
                                our_height,
                                highest_announced,
                                "announced gap closed — discarded obsolete manifest round"
                            );
                        }
                        continue;
                    }

                    // A normal connection probe is not authority to replace a
                    // snapshot which has just committed. Let the parallel native
                    // header probe reach HeaderDAG: it either admits the bounded
                    // exact tail or marks a subsequent manifest request as forced.
                    // Matching providers for an already active immutable snapshot
                    // were admitted above and never reach this branch.
                    if unforced_manifest_waits_for_header_dag(force_snapshot, post_snapshot_tail)
                    {
                        deferred_sync_peer = Some(from);
                        if manifest_requested_peers.is_empty() {
                            manifest_response_count = 0;
                            manifest_round_started_at = None;
                        }
                        tracing::info!(
                            from = %from,
                            our_height,
                            snapshot_height = manifest.tip_height,
                            "post-snapshot exact tail deferred an unforced manifest to HeaderDAG"
                        );
                        continue;
                    }

                    let snapshot_gap = manifest.tip_height.saturating_sub(our_height);
                    tracing::info!(
                        from = %from,
                        our_height,
                        snapshot_height = manifest.tip_height,
                        snapshot_gap,
                        force_snapshot,
                        "manifest snapshot boundary ahead — queueing snapshot candidate"
                    );
                }

                if manifest.tip_height > 0
                    && pending_manifest.is_none()
                    && pending_snapshot_header_sync.is_none()
                    && snapshot_header_staging_inflight.is_none()
                    && history_step_verification_inflight.is_none()
                    && snapshot_staging_inflight.is_none()
                    && snapshot_install_inflight.is_none()
                {
                    let same_candidate = best_manifest_candidate.as_ref().is_some_and(|current| {
                        current.manifest.as_ref() == manifest.as_ref()
                    });
                    if same_candidate {
                        if let Some(current) = best_manifest_candidate.as_mut() {
                            current.rebase_anchor = rebase_anchor;
                        }
                        candidate_manifest_providers.insert(from);
                        tracing::debug!(
                            from = %from,
                            tip = manifest.tip_height,
                            providers = candidate_manifest_providers.len(),
                            "registered another provider for the bounded snapshot candidate"
                        );
                    } else {
                        let replace = best_manifest_candidate.as_ref().is_none_or(|current| {
                            state_manifest_candidate_is_preferred(
                                manifest.as_ref(),
                                current.manifest.as_ref(),
                            )
                        });
                        if replace {
                            tracing::info!(
                                from = %from,
                                tip = manifest.tip_height,
                                bridge_tip = manifest.bridge_tip_height,
                                segments = manifest.segment_ids.len(),
                                "stronger snapshot manifest entered bounded candidate selection"
                            );
                            best_manifest_candidate = Some(SnapshotManifestCandidate {
                                from,
                                manifest,
                                rebase_anchor,
                            });
                            candidate_manifest_providers.clear();
                            candidate_manifest_providers.insert(from);
                        } else {
                            tracing::debug!(
                                from = %from,
                                tip = manifest.tip_height,
                                bridge_tip = manifest.bridge_tip_height,
                                "weaker snapshot manifest ignored during bounded candidate selection"
                            );
                        }
                    }
                    manifest_candidate_started_at.get_or_insert_with(Instant::now);
                } else if manifest.tip_height > 0 {
                    // Manifest chainwork is only a claim until its exact native
                    // header chain has been validated. Never interrupt useful
                    // work because an unauthenticated peer writes a larger
                    // integer here. Ordinary fork choice probes this peer after
                    // the active, fully authenticated snapshot is installed.
                    deferred_sync_peer = Some(from);
                    tracing::debug!(
                        from = %from,
                        tip = manifest.tip_height,
                        "late manifest deferred to authenticated post-install fork choice"
                    );
                }
                if manifest_tip_height == 0
                    && manifest_requested_peers.is_empty()
                    && !snapshot_plan_active!()
                {
                    let our_height = {
                        let ctx = chain.read().await;
                        ctx.tip_height()
                    };
                    if manifest_round_gap_is_resolved(our_height, highest_announced) {
                        tracing::debug!(
                            our_height,
                            "empty manifest round settled; awaiting authenticated tip probe"
                        );
                    }
                }
            }

            Ok(NetworkEvent::StateSegment { from, response }) => {
                // Received one segment (step 2 of snapshot sync).
                // Authenticate and seal it to disk immediately; decoded state
                // never accumulates in the node process.  Hashing, decoding,
                // fsync, and atomic publication run one-at-a-time on the
                // blocking pool so the sole P2P event loop keeps draining.
                if snapshot_install_inflight.is_some() {
                    tracing::debug!(
                        from = %from,
                        segment = response.segment_id,
                        "snapshot install active — releasing stale segment response"
                    );
                    drop(response);
                    continue;
                }
                let Some(sync) = active_snapshot_sync.as_mut() else {
                    tracing::warn!(
                        from = %from,
                        segment = response.segment_id,
                        "snapshot segment has no active immutable plan — dropped"
                    );
                    drop(response);
                    continue;
                };
                let Some(segment) = sync.segment(response.segment_id) else {
                    tracing::warn!(
                        from = %from,
                        segment = response.segment_id,
                        "snapshot response names a segment outside the immutable plan"
                    );
                    drop(response);
                    continue;
                };
                if response.expected_tip_height != segment.snapshot.boundary.height
                    || response.expected_tip_hash != segment.snapshot.boundary.hash
                    || response.manifest_digest != segment.snapshot.manifest_digest
                {
                    tracing::warn!(
                        from = %from,
                        segment = response.segment_id,
                        "snapshot response belongs to another immutable generation"
                    );
                    drop(response);
                    continue;
                }
                let Some(data_len) = response.data.as_ref().map(Vec::len) else {
                    // A served exact manifest promises a complete immutable
                    // generation. Missing any advertised segment makes this
                    // peer unsuitable for the whole plan, even if it is an
                    // honest exporter/storage bug rather than malicious data.
                    let _ = sync.reject_provider(from, segment);
                    if let Some(pending) = pending_manifest.as_mut() {
                        pending.providers.remove(&from);
                    }
                    request_snapshot_generation_providers!(from);
                    dispatch_snapshot_segments_from_available_source!();
                    continue;
                };
                if snapshot_staging_inflight.is_some() && queued_segment_response.is_some() {
                    // Both bounded local staging slots are occupied. The
                    // response has not yet been admitted into ObjectFetcher,
                    // so return its exact request to Wanted without scoring
                    // the peer or manufacturing an orphan Received state.
                    let request =
                        noid_node::networking::snapshot_sync::SnapshotSegmentRequest {
                            peer: from,
                            segment,
                        };
                    if let Err(error) = sync.defer_request(request) {
                        tracing::warn!(peer = %from, segment = response.segment_id, %error, "could not defer State response behind local staging capacity");
                    }
                    drop(response);
                    dispatch_snapshot_segments_from_available_source!();
                    continue;
                }
                if let Err(error) = sync.accept_response(from, segment, data_len) {
                    tracing::warn!(peer = %from, segment = response.segment_id, %error, "snapshot response failed exact correlation");
                    if matches!(
                        error,
                        noid_node::networking::snapshot_sync::SnapshotSyncError::ResponseLengthMismatch
                    ) {
                        // This response was correlated to the immutable
                        // descriptor but cannot be its advertised object.
                        // Do not let a repeated manifest resurrect this
                        // provider for the same segment.
                        let _ = sync.reject_provider(from, segment);
                        if let Some(pending) = pending_manifest.as_mut() {
                            pending.providers.remove(&from);
                        }
                        request_snapshot_generation_providers!(from);
                    }
                    // Other correlation failures are stale/duplicate
                    // transport responses. They provide no evidence against
                    // the currently active source lease.
                    drop(response);
                    dispatch_snapshot_segments_from_available_source!();
                    continue;
                }

                if snapshot_staging_inflight.is_none() {
                    stage_snapshot_segment_response!(from, response);
                } else if queued_segment_response.is_none() {
                    let segment_id = response.segment_id;
                    queued_segment_response = Some((from, response));
                    tracing::debug!(
                        from = %from,
                        segment = segment_id,
                        "snapshot segment retained in the one-response staging buffer"
                    );
                } else {
                    unreachable!("State response capacity was checked before Received admission");
                }
                dispatch_snapshot_segments_from_available_source!();
                continue;
            }

            Ok(NetworkEvent::StateSegmentRequestFailed {
                from,
                segment_id,
                expected_tip_height,
                expected_tip_hash,
                manifest_digest,
                kind,
            }) => {
                let correlated_segment = active_snapshot_sync
                    .as_ref()
                    .and_then(|sync| sync.segment(segment_id))
                    .filter(|segment| {
                        segment.snapshot.boundary.height == expected_tip_height
                            && segment.snapshot.boundary.hash == expected_tip_hash
                            && segment.snapshot.manifest_digest == manifest_digest
                    });
                let Some(segment) = correlated_segment else {
                    tracing::debug!(
                        peer = %from,
                        segment = segment_id,
                        expected_tip_height,
                        ?kind,
                        "ignoring stale state-segment request failure"
                    );
                    continue;
                };
                if kind == noid_p2p::RequestFailureKind::LocalCapacity {
                    if let Some(sync) = active_snapshot_sync.as_mut() {
                        let request =
                            noid_node::networking::snapshot_sync::SnapshotSegmentRequest {
                                peer: from,
                                segment,
                            };
                        if let Err(error) = sync.defer_request(request) {
                            tracing::warn!(peer = %from, segment = segment_id, %error, "could not defer locally saturated State request");
                        }
                    }
                    dispatch_snapshot_segments_from_available_source!();
                    continue;
                }
                if matches!(
                    kind,
                    noid_p2p::RequestFailureKind::InvalidResponse
                        | noid_p2p::RequestFailureKind::Unavailable
                ) {
                    if let Some(sync) = active_snapshot_sync.as_mut() {
                        if let Err(error) = sync.reject_provider(from, segment) {
                            tracing::warn!(peer = %from, segment = segment_id, %error, "invalid State provider quarantine failed");
                        }
                    }
                    if let Some(pending) = pending_manifest.as_mut() {
                        pending.providers.remove(&from);
                    }
                    tracing::warn!(peer = %from, segment = segment_id, "provider returned a malformed exact State response and was quarantined for this generation");
                    dispatch_snapshot_segments_from_available_source!();
                } else {
                    rotate_snapshot_segment_source!(from, segment_id, "transport request failed");
                }
            }

            Ok(NetworkEvent::StateSegmentRequestBusy {
                from,
                segment_id,
                expected_tip_height,
                expected_tip_hash,
                manifest_digest,
                retry_after_ms,
            }) => {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let correlated = active_snapshot_sync
                    .as_mut()
                    .and_then(|sync| sync.segment(segment_id).map(|segment| (sync, segment)))
                    .is_some_and(|(sync, segment)| {
                        segment.snapshot.boundary.height == expected_tip_height
                            && segment.snapshot.boundary.hash == expected_tip_hash
                            && segment.snapshot.manifest_digest == manifest_digest
                            && sync
                                .request_busy(
                                    from,
                                    segment,
                                    now_ms.saturating_add(u64::from(retry_after_ms)),
                                )
                                .is_ok()
                    });
                if correlated {
                    tracing::debug!(peer = %from, segment = segment_id, retry_after_ms, "snapshot provider is busy; verified generation progress retained");
                    dispatch_snapshot_segments_from_available_source!();
                } else {
                    tracing::debug!(peer = %from, segment = segment_id, "ignoring stale snapshot busy response");
                }
            }

            Ok(NetworkEvent::HistoryStepTerminal {
                token,
                from,
                height,
                block_hash,
                terminal_bytes,
                inbound_memory_permit,
            }) => {
                let maintenance_key = boundary_proof_maintenance_inflight.filter(|pending| {
                    pending.requests.matches(from, token)
                        && pending.target.height() == height
                        && pending.target.block_hash() == block_hash
                });
                if let Some(maintenance_key) = maintenance_key {
                    if terminal_bytes.is_empty() {
                        drop(inbound_memory_permit);
                        let pending = boundary_proof_maintenance_inflight
                            .as_mut()
                            .expect("correlated proof maintenance request is present");
                        let marked = pending.requests.mark_failed(from, token);
                        debug_assert!(marked, "correlated proof maintenance request must be active");
                        manifest_terminal_capabilities.remove(&from);
                        if !pending.requests.has_work() {
                            let alternate = advertised_terminal_alternate_peer(
                                &manifest_peers,
                                &manifest_terminal_capabilities,
                                &rejected_terminal_peers,
                                &snapshot_terminal_exhausted,
                                &snapshot_terminal_retry_after,
                                &pending.requests,
                                height,
                                block_hash,
                                Instant::now(),
                            );
                            if let Some(alternate) = alternate {
                                pending.requests.install_hedge(alternate);
                                dispatch_boundary_proof_maintenance_requests!();
                            } else {
                                boundary_proof_maintenance_inflight = None;
                                last_boundary_proof_maintenance = Instant::now();
                            }
                        }
                        tracing::debug!(
                            peer = %from,
                            height,
                            "advertised snapshot-boundary terminal is unavailable"
                        );
                        continue;
                    }
                    let won = boundary_proof_maintenance_inflight
                        .as_mut()
                        .expect("correlated proof maintenance request is present")
                        .requests
                        .mark_succeeded(from, token);
                    debug_assert!(won, "correlated proof maintenance request must win its race");
                    boundary_proof_maintenance_inflight = None;
                    let _ = p2p_cmd.try_send(
                        noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace { token },
                    );
                    spawn_boundary_proof_maintenance_verification!(
                        maintenance_key.target,
                        from,
                        terminal_bytes,
                        inbound_memory_permit
                    );
                    continue;
                }
                let boundary_key = snapshot_boundary_terminal_inflight.filter(|pending| {
                    pending.generation == snapshot_sync_generation
                        && pending.requests.matches(from, token)
                        && pending.height == height
                        && pending.block_hash == block_hash
                });
                let Some(boundary_key) = boundary_key else {
                    drop(terminal_bytes);
                    drop(inbound_memory_permit);
                    tracing::debug!(
                        from = %from,
                        height,
                        "dropping stale or mismatched HistoryStep terminal response"
                    );
                    continue;
                };
                if terminal_bytes.is_empty() {
                    drop(inbound_memory_permit);
                    let source_key = SnapshotTerminalSourceKey {
                        peer: from,
                        height,
                        block_hash,
                    };
                    snapshot_terminal_exhausted.insert(source_key);
                    snapshot_terminal_transport_failures.remove(&source_key);
                    manifest_terminal_capabilities.remove(&from);
                    snapshot_terminal_retry_after
                        .insert(from, Instant::now() + Duration::from_secs(5));
                    let mut pending = snapshot_boundary_terminal_inflight
                        .take()
                        .expect("correlated boundary terminal is present");
                    let marked = pending.requests.mark_failed(from, token);
                    debug_assert!(marked, "correlated boundary terminal must be active");
                    if pending.requests.has_work() {
                        snapshot_boundary_terminal_inflight = Some(pending);
                        continue;
                    }
                    let alternate = (pending.requests.hedge.is_none())
                        .then(|| {
                            advertised_terminal_alternate_peer(
                                &manifest_peers,
                                &manifest_terminal_capabilities,
                                &rejected_terminal_peers,
                                &snapshot_terminal_exhausted,
                                &snapshot_terminal_retry_after,
                                &pending.requests,
                                height,
                                block_hash,
                                Instant::now(),
                            )
                        })
                        .flatten();
                    if let Some(alternate) = alternate {
                        pending.requests.install_hedge(alternate);
                        snapshot_boundary_terminal_inflight = Some(pending);
                        dispatch_pending_boundary_terminal_requests!();
                        tracing::warn!(
                            peer = %from,
                            alternate = %alternate,
                            height,
                            "snapshot boundary terminal unavailable — trying one alternate peer"
                        );
                        continue;
                    }
                    tracing::warn!(
                        from = %from,
                        height,
                        "snapshot boundary terminal is unavailable; exact plan remains active"
                    );
                    request_snapshot_generation_providers!(from);
                    ensure_snapshot_boundary_terminal_request!();
                    continue;
                }
                let won = snapshot_boundary_terminal_inflight
                    .as_mut()
                    .expect("correlated boundary terminal is present")
                    .requests
                    .mark_succeeded(from, token);
                debug_assert!(won, "correlated boundary terminal must win its race");
                snapshot_boundary_terminal_inflight = None;
                snapshot_terminal_retry_after.remove(&from);
                let source_key = SnapshotTerminalSourceKey {
                    peer: from,
                    height,
                    block_hash,
                };
                snapshot_terminal_transport_failures.remove(&source_key);
                snapshot_terminal_exhausted.remove(&source_key);
                snapshot_plan_last_progress = Some(Instant::now());
                snapshot_provider_discovery_rounds = 0;
                let payload = PrefetchedHistoryStepTerminal {
                    token,
                    from,
                    terminal_bytes,
                    inbound_memory_permit,
                };
                let retained_headers_ready = retained_snapshot_headers
                    .as_ref()
                    .is_some_and(|authority| authority.snapshot == boundary_key.snapshot);
                let headers_ready = snapshot_header_staging_inflight.is_none()
                    && pending_snapshot_header_sync.as_ref().is_some_and(|sync| {
                        sync.snapshot == boundary_key.snapshot
                            && sync.next_height == sync.target_height.saturating_add(1)
                    });
                if retained_headers_ready {
                    let authority = retained_snapshot_headers
                        .take()
                        .expect("checked retained snapshot header authority");
                    retry_snapshot_boundary_verification!(authority, payload);
                } else if headers_ready {
                    let sync = pending_snapshot_header_sync
                        .take()
                        .expect("checked completed snapshot header staging");
                    start_snapshot_boundary_verification!(sync, payload);
                } else {
                    prefetched_snapshot_boundary_terminal = Some(payload);
                    tracing::info!(
                        from = %from,
                        height,
                        "snapshot boundary terminal prefetched — waiting for staged headers"
                    );
                }
                continue;
            }
            Ok(NetworkEvent::HistoryStepTerminalRequestFailed {
                token,
                from,
                height,
                block_hash,
                kind,
            }) => {
                if kind == noid_p2p::RequestFailureKind::LocalCapacity {
                    if let Some(pending) = boundary_proof_maintenance_inflight.as_mut().filter(
                        |pending| {
                            pending.requests.matches(from, token)
                                && pending.target.height() == height
                                && pending.target.block_hash() == block_hash
                        },
                    ) {
                        let deferred = pending.requests.defer(from, token);
                        debug_assert!(deferred, "correlated proof request was active");
                        tracing::debug!(peer = %from, height, "proof request deferred behind local correlation capacity");
                        continue;
                    }
                    if let Some(pending) = snapshot_boundary_terminal_inflight.as_mut().filter(
                        |pending| {
                            pending.generation == snapshot_sync_generation
                                && pending.requests.matches(from, token)
                                && pending.height == height
                                && pending.block_hash == block_hash
                        },
                    ) {
                        let deferred = pending.requests.defer(from, token);
                        debug_assert!(deferred, "correlated boundary request was active");
                        tracing::debug!(peer = %from, height, "snapshot terminal request deferred behind local correlation capacity");
                    }
                    continue;
                }
                let maintenance_correlated = boundary_proof_maintenance_inflight
                    .as_ref()
                    .is_some_and(|pending| {
                        pending.requests.matches(from, token)
                            && pending.target.height() == height
                            && pending.target.block_hash() == block_hash
                    });
                if maintenance_correlated {
                    let pending = boundary_proof_maintenance_inflight
                        .as_mut()
                        .expect("correlated proof maintenance request is present");
                    let marked = pending.requests.mark_failed(from, token);
                    debug_assert!(marked, "correlated proof maintenance request must be active");
                    if !pending.requests.has_work() {
                        let alternate = advertised_terminal_alternate_peer(
                            &manifest_peers,
                            &manifest_terminal_capabilities,
                            &rejected_terminal_peers,
                            &snapshot_terminal_exhausted,
                            &snapshot_terminal_retry_after,
                            &pending.requests,
                            height,
                            block_hash,
                            Instant::now(),
                        );
                        if let Some(alternate) = alternate {
                            pending.requests.install_hedge(alternate);
                            dispatch_boundary_proof_maintenance_requests!();
                        } else {
                            boundary_proof_maintenance_inflight = None;
                            last_boundary_proof_maintenance = Instant::now();
                        }
                    }
                    tracing::debug!(
                        peer = %from,
                        height,
                        ?kind,
                        "snapshot-boundary proof source failed; canonical sync unchanged"
                    );
                    continue;
                }
                let boundary_correlated =
                    snapshot_boundary_terminal_inflight.is_some_and(|pending| {
                        pending.generation == snapshot_sync_generation
                            && pending.requests.matches(from, token)
                            && pending.height == height
                            && pending.block_hash == block_hash
                    });
                if !boundary_correlated {
                    tracing::debug!(
                        peer = %from,
                        height,
                        ?kind,
                        "ignoring stale HistoryStep transport failure"
                    );
                    continue;
                }

                let source_key = SnapshotTerminalSourceKey {
                    peer: from,
                    height,
                    block_hash,
                };
                let source_exhausted = match kind {
                    noid_p2p::RequestFailureKind::LocalCapacity => {
                        unreachable!("local capacity was handled before terminal failure scoring")
                    }
                    noid_p2p::RequestFailureKind::InvalidResponse => {
                        rejected_terminal_peers.insert(from);
                        manifest_terminal_capabilities.remove(&from);
                        quarantine_exact_suffix_sources(
                            &mut header_dag,
                            &mut rejected_suffix_object_peers,
                            &[from],
                        );
                        snapshot_terminal_exhausted.insert(source_key);
                        true
                    }
                    noid_p2p::RequestFailureKind::Unavailable
                    | noid_p2p::RequestFailureKind::UnsupportedProtocol => {
                        manifest_terminal_capabilities.remove(&from);
                        snapshot_terminal_exhausted.insert(source_key);
                        true
                    }
                    noid_p2p::RequestFailureKind::Timeout
                    | noid_p2p::RequestFailureKind::Io
                    | noid_p2p::RequestFailureKind::Dial
                    | noid_p2p::RequestFailureKind::ConnectionClosed => {
                        record_snapshot_terminal_transport_failure(
                            &mut snapshot_terminal_transport_failures,
                            source_key,
                        );
                        false
                    }
                };

                if !source_exhausted {
                    snapshot_terminal_retry_after.insert(
                        from,
                        Instant::now()
                            + if terminal_transport_can_retry_same_peer(kind) {
                                Duration::from_secs(3)
                            } else {
                                Duration::from_secs(10)
                            },
                    );
                }

                let pending = snapshot_boundary_terminal_inflight
                    .as_mut()
                    .expect("correlated boundary terminal is present");
                let marked = pending.requests.mark_failed(from, token);
                debug_assert!(marked, "correlated HistoryStep request must be active");
                if pending.requests.has_work() {
                    tracing::warn!(
                        peer = %from,
                        height,
                        ?kind,
                        "one HistoryStep terminal request failed; exact race remains active"
                    );
                    continue;
                }

                let alternate = snapshot_boundary_terminal_inflight.as_ref().and_then(|pending| {
                    pending.requests.hedge.is_none()
                        .then(|| {
                            advertised_terminal_alternate_peer(
                                &manifest_peers,
                                &manifest_terminal_capabilities,
                                &rejected_terminal_peers,
                                &snapshot_terminal_exhausted,
                                &snapshot_terminal_retry_after,
                                &pending.requests,
                                height,
                                block_hash,
                                Instant::now(),
                            )
                        })
                        .flatten()
                });
                if let Some(alternate) = alternate {
                    let pending = snapshot_boundary_terminal_inflight
                        .as_mut()
                        .expect("correlated boundary terminal is present");
                    pending.requests.install_hedge(alternate);
                    dispatch_pending_boundary_terminal_requests!();
                    tracing::warn!(
                        peer = %from,
                        alternate = %alternate,
                        height,
                        ?kind,
                        "HistoryStep terminal failed — retaining headers and trying one alternate peer"
                    );
                    continue;
                }

                snapshot_boundary_terminal_inflight = None;
                tracing::warn!(
                    peer = %from,
                    height,
                    ?kind,
                    "HistoryStep transport failed; retaining exact snapshot plan and all staged work"
                );
                request_snapshot_generation_providers!(from);
                ensure_snapshot_boundary_terminal_request!();
            }
            Ok(NetworkEvent::HistoryStepTerminalRequestBusy {
                token,
                from,
                height,
                block_hash,
                retry_after_ms,
            }) => {
                snapshot_terminal_retry_after.insert(
                    from,
                    Instant::now() + Duration::from_millis(u64::from(retry_after_ms)),
                );
                let maintenance_correlated = boundary_proof_maintenance_inflight
                    .as_ref()
                    .is_some_and(|pending| {
                        pending.requests.matches(from, token)
                            && pending.target.height() == height
                            && pending.target.block_hash() == block_hash
                    });
                if maintenance_correlated {
                    let pending = boundary_proof_maintenance_inflight
                        .as_mut()
                        .expect("correlated proof maintenance request is present");
                    let marked = pending.requests.mark_failed(from, token);
                    debug_assert!(marked, "correlated busy proof request must be active");
                    if !pending.requests.has_work() {
                        if let Some(alternate) = advertised_terminal_alternate_peer(
                            &manifest_peers,
                            &manifest_terminal_capabilities,
                            &rejected_terminal_peers,
                            &snapshot_terminal_exhausted,
                            &snapshot_terminal_retry_after,
                            &pending.requests,
                            height,
                            block_hash,
                            Instant::now(),
                        ) {
                            pending.requests.install_hedge(alternate);
                            dispatch_boundary_proof_maintenance_requests!();
                        } else {
                            boundary_proof_maintenance_inflight = None;
                            last_boundary_proof_maintenance = Instant::now();
                        }
                    }
                    tracing::debug!(peer = %from, height, retry_after_ms, "proof provider is busy; availability claim retained");
                    continue;
                }

                let boundary_correlated = snapshot_boundary_terminal_inflight
                    .as_ref()
                    .is_some_and(|pending| {
                        pending.generation == snapshot_sync_generation
                            && pending.requests.matches(from, token)
                            && pending.height == height
                            && pending.block_hash == block_hash
                    });
                if !boundary_correlated {
                    tracing::debug!(peer = %from, height, "ignoring stale terminal busy response");
                    continue;
                }
                let pending = snapshot_boundary_terminal_inflight
                    .as_mut()
                    .expect("correlated boundary terminal is present");
                let marked = pending.requests.mark_failed(from, token);
                debug_assert!(marked, "correlated busy terminal request must be active");
                if pending.requests.has_work() {
                    continue;
                }
                if let Some(alternate) = advertised_terminal_alternate_peer(
                    &manifest_peers,
                    &manifest_terminal_capabilities,
                    &rejected_terminal_peers,
                    &snapshot_terminal_exhausted,
                    &snapshot_terminal_retry_after,
                    &pending.requests,
                    height,
                    block_hash,
                    Instant::now(),
                ) {
                    pending.requests.install_hedge(alternate);
                    dispatch_pending_boundary_terminal_requests!();
                } else {
                    snapshot_boundary_terminal_inflight = None;
                    ensure_snapshot_boundary_terminal_request!();
                }
                tracing::debug!(peer = %from, height, retry_after_ms, "snapshot terminal provider is busy; exact plan and capability retained");
            }
            Ok(NetworkEvent::StateManifestRequestFailed {
                generation,
                from,
                requester_height,
                requested_manifest_digest,
                kind,
            }) => {
                if generation != snapshot_sync_generation {
                    tracing::debug!(
                        generation,
                        active_generation = snapshot_sync_generation,
                        peer = %from,
                        requester_height,
                        "ignoring stale state-manifest request failure"
                    );
                    continue;
                }
                manifest_requested_peers.remove(&from);
                if kind == noid_p2p::RequestFailureKind::LocalCapacity {
                    tracing::debug!(
                        generation,
                        peer = %from,
                        requester_height,
                        "state-manifest request deferred behind local correlation capacity"
                    );
                    continue;
                }
                let rejected_exact_provider = matches!(
                    kind,
                    noid_p2p::RequestFailureKind::InvalidResponse
                        | noid_p2p::RequestFailureKind::Unavailable
                ) && requested_manifest_digest != [0; 32];
                if rejected_exact_provider {
                    rejected_snapshot_manifest_providers
                        .entry(requested_manifest_digest)
                        .or_default()
                        .insert(from);
                    if let Some(sync) = active_snapshot_sync.as_mut().filter(|sync| {
                        sync.manifest().manifest_digest == requested_manifest_digest
                    }) {
                        sync.quarantine_provider(from);
                    }
                    candidate_manifest_providers.remove(&from);
                    if let Some(pending) = pending_manifest.as_mut().filter(|pending| {
                        pending.manifest.manifest_digest == requested_manifest_digest
                    }) {
                        pending.providers.remove(&from);
                    }
                    tracing::warn!(peer = %from, manifest = %hex::encode(requested_manifest_digest), "unusable exact manifest provider quarantined for this generation");
                    dispatch_snapshot_segments_from_available_source!();
                }
                tracing::debug!(
                    generation,
                    peer = %from,
                    requester_height,
                    exact = requested_manifest_digest != [0; 32],
                    ?kind,
                    "state-manifest request failed; active snapshot work is unchanged"
                );
                if !snapshot_plan_active!() && manifest_requested_peers.is_empty() {
                    request_bounded_manifest_failover!(
                        from,
                        terminal_transport_can_retry_same_peer(kind)
                    );
                    if manifest_round_started_at.is_none() {
                        manifest_round_started_at = Some(Instant::now());
                    }
                }
            }
            Ok(NetworkEvent::PeerDisconnected(peer)) => {
                suffix_inventory_probe_peers.remove(&peer);
                peer_failure_domains.remove(&peer);
                header_dag.remove_inventory_provider(peer);
                if let Some(sync) = active_suffix_sync.as_mut() {
                    sync.disconnect(peer);
                    dispatch_exact_suffix_requests(sync, &p2p_cmd);
                }
                mining_peer_quorum.disconnect(peer);
                manifest_peers.remove(&peer);
                locally_selected_peers.remove(&peer);
                manifest_terminal_capabilities.remove(&peer);
                snapshot_terminal_retry_after.remove(&peer);
                let maintenance_retry = boundary_proof_maintenance_inflight
                    .as_mut()
                    .and_then(|pending| {
                        let retired = pending.requests.retire_peer(peer);
                        (retired && !pending.requests.has_work()).then(|| {
                            advertised_terminal_alternate_peer(
                                &manifest_peers,
                                &manifest_terminal_capabilities,
                                &rejected_terminal_peers,
                                &snapshot_terminal_exhausted,
                                &snapshot_terminal_retry_after,
                                &pending.requests,
                                pending.target.height(),
                                pending.target.block_hash(),
                                Instant::now(),
                            )
                        })
                    })
                    .flatten();
                if let Some(alternate) = maintenance_retry {
                    boundary_proof_maintenance_inflight
                        .as_mut()
                        .expect("proof maintenance retry remains active")
                        .requests
                        .install_hedge(alternate);
                    dispatch_boundary_proof_maintenance_requests!();
                } else if boundary_proof_maintenance_inflight
                    .as_ref()
                    .is_some_and(|pending| !pending.requests.has_work())
                {
                    boundary_proof_maintenance_inflight = None;
                    last_boundary_proof_maintenance = Instant::now();
                }
                if let Some(pending) = pending_manifest.as_mut() {
                    pending.providers.remove(&peer);
                    if pending.preferred_peer == peer {
                        if let Some(replacement) = pending
                            .providers
                            .iter()
                            .copied()
                            .min_by_key(|candidate| candidate.to_bytes())
                        {
                            pending.preferred_peer = replacement;
                        }
                    }
                }
                tracing::debug!(peer = %peer, "peer disconnected");
                let retry_terminal = snapshot_boundary_terminal_inflight
                    .as_mut()
                    .and_then(|pending| {
                        let retired = pending.requests.retire_peer(peer);
                        (retired
                            && !pending.requests.has_work()
                            && pending.requests.hedge.is_none())
                        .then(|| {
                            advertised_terminal_alternate_peer(
                                &manifest_peers,
                                &manifest_terminal_capabilities,
                                &rejected_terminal_peers,
                                &snapshot_terminal_exhausted,
                                &snapshot_terminal_retry_after,
                                &pending.requests,
                                pending.height,
                                pending.block_hash,
                                Instant::now(),
                            )
                        })
                    })
                    .flatten();
                if let Some(alternate) = retry_terminal {
                    snapshot_boundary_terminal_inflight
                        .as_mut()
                        .expect("terminal retry still belongs to active snapshot")
                        .requests
                        .install_hedge(alternate);
                    dispatch_pending_boundary_terminal_requests!();
                }
                let terminal_exhausted = snapshot_boundary_terminal_inflight
                    .as_ref()
                    .is_some_and(|pending| !pending.requests.has_work());
                if terminal_exhausted {
                    snapshot_boundary_terminal_inflight = None;
                    request_snapshot_generation_providers!(peer);
                    ensure_snapshot_boundary_terminal_request!();
                }
                let replacement_snapshot_peer = pending_manifest
                    .as_ref()
                    .and_then(|pending| {
                        pending
                            .providers
                            .iter()
                            .copied()
                            .min_by_key(|candidate| candidate.to_bytes())
                    })
                    .or_else(|| {
                        manifest_peers
                            .iter()
                            .copied()
                            .min_by_key(|candidate| candidate.to_bytes())
                    });
                if let Some(sync) = pending_snapshot_header_sync.as_mut() {
                    if sync.preferred_peer == peer {
                        if let Some(replacement) = replacement_snapshot_peer {
                            sync.preferred_peer = replacement;
                        }
                    }
                }
                if let Some(pipeline) = snapshot_header_pipeline.as_mut() {
                    if pipeline.preferred_peer == peer {
                        if let Some(replacement) = replacement_snapshot_peer {
                            pipeline.preferred_peer = replacement;
                        }
                    }
                }
                if let Some(sync) = active_snapshot_sync.as_mut() {
                    let before = sync.counts();
                    sync.disconnect(peer);
                    let after = sync.counts();
                    tracing::warn!(
                        peer = %peer,
                        interrupted = before.in_flight.saturating_sub(after.in_flight),
                        remaining = after.wanted + after.in_flight + after.received,
                        "snapshot object source disconnected; preserving exact generation progress"
                    );
                    if !sync.all_segments_verified() {
                        request_snapshot_generation_providers!(peer);
                    }
                    dispatch_snapshot_segments_from_available_source!();
                }
                fetch_in_progress.remove(&peer);
                recent_header_fetches.retain(|(p, _, _), _| *p != peer);
                manifest_requested_peers.remove(&peer);
                mempool_sync_requested_peers.remove(&peer);
                finalized_divergent_peers.remove(&peer);
                peer_tx_rate.remove(&peer);
            }
            Err(noid_p2p::NetworkEventRecvError::Lagged(n)) => {
                tracing::warn!(n, "P2P gossip receiver lagged — recoverable gossip events dropped");
            }
            Err(noid_p2p::NetworkEventRecvError::Closed) => {
                return Err(anyhow::anyhow!("P2P event channel closed"));
            }
        } // match rx_item
        } // rx_result arm

        completed = snapshot_header_staging_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            if snapshot_header_staging_inflight != Some(completed.key) {
                match completed.result {
                    SnapshotHeaderStagingResult::Success(sync)
                    | SnapshotHeaderStagingResult::BaseMoved { sync, .. }
                    | SnapshotHeaderStagingResult::CandidateRejected { sync, .. } => {
                        // A retired request does not invalidate the durable
                        // native-validated prefix. The next generation reopens
                        // and revalidates this exact file.
                        drop(sync.staging);
                    }
                    SnapshotHeaderStagingResult::PrepareBaseMoved(_) => {}
                    SnapshotHeaderStagingResult::Fatal(_) => {}
                }
                tracing::debug!(
                    key = ?completed.key,
                    "discarding superseded snapshot header staging completion"
                );
                continue;
            }
            snapshot_header_staging_inflight = None;
            let (generation, snapshot, append_range) = match completed.key {
                SnapshotHeaderStagingOperationKey::Prepare {
                    generation,
                    snapshot,
                    ..
                } => (generation, snapshot, None),
                SnapshotHeaderStagingOperationKey::Append {
                    generation,
                    snapshot,
                    range_from,
                    start_height,
                    count,
                    ..
                } => (
                    generation,
                    snapshot,
                    Some((range_from, start_height, count)),
                ),
            };
            if generation != snapshot_sync_generation {
                match completed.result {
                    SnapshotHeaderStagingResult::Success(sync)
                    | SnapshotHeaderStagingResult::BaseMoved { sync, .. }
                    | SnapshotHeaderStagingResult::CandidateRejected { sync, .. } => {
                        // Transport generation churn must not turn completed
                        // local validation into another O(height) download.
                        drop(sync.staging);
                    }
                    SnapshotHeaderStagingResult::PrepareBaseMoved(_) => {}
                    SnapshotHeaderStagingResult::Fatal(_) => {}
                }
                tracing::debug!(
                    boundary = snapshot.boundary.height,
                    "discarding snapshot headers from a retired plan generation"
                );
                continue;
            }
            sync_phase_telemetry.record_header_work(completed.work_elapsed);
            let sync = match completed.result {
                SnapshotHeaderStagingResult::Success(sync) => sync,
                SnapshotHeaderStagingResult::PrepareBaseMoved(error) => {
                    let Some(previous_peer) = pending_manifest
                        .as_ref()
                        .map(|pending| pending.preferred_peer)
                    else {
                        return Err(anyhow::anyhow!(
                            "snapshot base moved without an active immutable manifest: {error}"
                        ));
                    };
                    snapshot_rebase_hint = None;
                    tracing::info!(
                        boundary = snapshot.boundary.height,
                        err = %error,
                        "local non-final snapshot base moved before staging; selecting a fresh exact plan"
                    );
                    retire_snapshot_plan!();
                    request_bounded_manifest_failover!(previous_peer, true);
                    continue;
                }
                SnapshotHeaderStagingResult::BaseMoved { sync, error } => {
                    let previous_peer = sync.preferred_peer;
                    cleanup_snapshot_header_staging_offthread(sync.staging);
                    snapshot_rebase_hint = None;
                    tracing::info!(
                        boundary = snapshot.boundary.height,
                        err = %error,
                        "local non-final snapshot base moved during staging; selecting a fresh exact plan"
                    );
                    retire_snapshot_plan!();
                    request_bounded_manifest_failover!(previous_peer, true);
                    continue;
                }
                SnapshotHeaderStagingResult::CandidateRejected {
                    sync,
                    attempted_peers,
                    error,
                } => {
                    let Some((range_from, start_height, count)) = append_range else {
                        cleanup_snapshot_header_staging_offthread(sync.staging);
                        tracing::error!(err = %error, "snapshot header prepare was misclassified as peer input");
                        return Err(anyhow::anyhow!(
                            "snapshot header prepare was misclassified as peer input: {error}"
                        ));
                    };
                    let parent_mismatch_at_base = matches!(
                        &error,
                        SnapshotHeaderStagingError::ParentMismatch { height }
                            if *height == sync.staging.base().header.height.saturating_add(1)
                                && sync.staging.staged_len() == 0
                    );
                    if parent_mismatch_at_base
                        && last_snapshot_rebase_probe.is_none_or(|last| {
                            Instant::now().saturating_duration_since(last)
                                >= EXACT_INVENTORY_RETRY_TTL
                        })
                    {
                        let (probe_start, probe_count) = snapshot_rebase_discovery_range(
                            header_dag.finalized().height,
                            sync.target_height,
                        );
                        if try_dispatch_header_fetch(
                            &p2p_cmd,
                            &mut fetch_in_progress,
                            &mut recent_header_fetches,
                            range_from,
                            probe_start,
                            probe_count,
                            Instant::now(),
                        ) {
                            last_snapshot_rebase_probe = Some(Instant::now());
                            tracing::info!(
                                peer = %range_from,
                                probe_start,
                                probe_count,
                                snapshot_target = sync.target_height,
                                "snapshot parent differs from the local tip; discovering the authenticated common ancestor"
                            );
                        }
                    }
                    // A parent mismatch proves only that this source supplied
                    // the wrong exact range. It does not prove that the local
                    // base moved. Preserve the immutable plan and its staged
                    // prefix; only independent HeaderDAG/canonical evidence is
                    // allowed to retire or rebase it.
                    let retry = snapshot_header_pipeline.as_mut().and_then(|pipeline| {
                        (pipeline.generation == generation && pipeline.snapshot == snapshot)
                            .then(|| {
                                pipeline.retry_rejected_range(
                                    start_height,
                                    count,
                                    attempted_peers,
                                    &manifest_peers,
                                )
                            })
                            .flatten()
                    });
                    let Some(request) = retry else {
                        let staged_headers = sync.staging.staged_len();
                        let preferred_peer = sync.preferred_peer;
                        tracing::warn!(
                            preferred_peer = %preferred_peer,
                            range_peer = %range_from,
                            start_height,
                            count,
                            staged_headers,
                            err = %error,
                            "rejected snapshot header range exhausted current sources; exact plan is parked"
                        );
                        pending_snapshot_header_sync = Some(sync);
                        request_snapshot_generation_providers!(preferred_peer);
                        continue;
                    };
                    let preferred_peer = sync.preferred_peer;
                    pending_snapshot_header_sync = Some(sync);
                    dispatch_snapshot_header_plans(
                        snapshot_header_pipeline
                            .as_mut()
                            .expect("rejected range retry belongs to the active pipeline"),
                        &p2p_cmd,
                        std::iter::once(request),
                    );
                    tracing::warn!(
                        preferred_peer = %preferred_peer,
                        range_peer = %range_from,
                        retry_peer = %request.peer,
                        start_height,
                        count,
                        err = %error,
                        "snapshot header candidate rejected; retained valid prefix and rotated the exact range"
                    );
                    continue;
                }
                SnapshotHeaderStagingResult::Fatal(error) => {
                    tracing::error!(
                        boundary = snapshot.boundary.height,
                        err = %error,
                        "local snapshot header preparation/staging failed"
                    );
                    return Err(anyhow::anyhow!(
                        "local snapshot header preparation/staging failed at {}: {error}",
                        snapshot.boundary.height
                    ));
                }
            };
            snapshot_plan_last_progress = Some(Instant::now());
            snapshot_provider_discovery_rounds = 0;
            if sync.snapshot != snapshot {
                cleanup_snapshot_header_staging_offthread(sync.staging);
                tracing::warn!("snapshot header staging plan changed");
                return Err(anyhow::anyhow!(
                    "snapshot header staging completed for a different immutable plan"
                ));
            }

            let action = match snapshot_header_next_action(sync.next_height, sync.target_height) {
                Ok(action) => action,
                Err(error) => {
                    cleanup_snapshot_header_staging_offthread(sync.staging);
                    tracing::warn!(boundary = snapshot.boundary.height, err = %error, "snapshot header staging has invalid progress");
                    return Err(anyhow::anyhow!(
                        "snapshot header staging has invalid progress at {}: {error}",
                        snapshot.boundary.height
                    ));
                }
            };
            match action {
                SnapshotHeaderNextAction::Fetch {
                    start_height,
                    count: _,
                } => {
                    let target_height = sync.target_height;
                    if snapshot_header_pipeline.is_none() {
                        snapshot_header_pipeline = Some(SnapshotHeaderPipeline::new(
                            generation,
                            snapshot,
                            sync.preferred_peer,
                            start_height,
                            target_height,
                        ));
                    }
                    let pipeline = snapshot_header_pipeline
                        .as_mut()
                        .expect("snapshot header pipeline was initialized");
                    if pipeline.generation != generation || pipeline.snapshot != snapshot {
                        cleanup_snapshot_header_staging_offthread(sync.staging);
                        tracing::warn!(
                            boundary = snapshot.boundary.height,
                            generation,
                            "snapshot header pipeline changed during disk staging"
                        );
                        return Err(anyhow::anyhow!(
                            "snapshot header pipeline changed during disk staging at {}",
                            snapshot.boundary.height
                        ));
                    }

                    if let Some(range) = pipeline.take_ready(sync.next_height) {
                        if let Err(error) = validate_snapshot_header_batch_admission(
                            sync.next_height,
                            sync.target_height,
                            range.headers.len(),
                        ) {
                            cleanup_snapshot_header_staging_offthread(sync.staging);
                            tracing::warn!(
                                peer = %range.source_peer,
                                err = %error,
                                "buffered snapshot header batch failed staging admission"
                            );
                            return Err(anyhow::anyhow!(
                                "buffered snapshot header batch violated admission at {}: {error}",
                                snapshot.boundary.height
                            ));
                        }
                        let refill = pipeline.refill_plan(true);
                        dispatch_snapshot_header_plans(pipeline, &p2p_cmd, refill);
                        spawn_snapshot_header_append!(sync, range);
                        continue;
                    }

                    let refill = pipeline.refill_plan(false);
                    let preferred_peer = sync.preferred_peer;
                    pending_snapshot_header_sync = Some(sync);
                    dispatch_snapshot_header_plans(pipeline, &p2p_cmd, refill);
                    tracing::info!(
                        preferred_peer = %preferred_peer,
                        next_height = start_height,
                        target_height,
                        window = SNAPSHOT_HEADER_REQUEST_WINDOW,
                        "snapshot: pipelining exactly correlated headers into disk staging"
                    );
                }
                SnapshotHeaderNextAction::RequestTerminal => {
                    if snapshot_header_pipeline
                        .as_ref()
                        .is_some_and(|pipeline| !pipeline.is_drained())
                    {
                        cleanup_snapshot_header_staging_offthread(sync.staging);
                        tracing::warn!(
                            boundary = snapshot.boundary.height,
                            "snapshot header target reached with an undrained request window"
                        );
                        return Err(anyhow::anyhow!(
                            "snapshot header target reached with undrained request window at {}",
                            snapshot.boundary.height
                        ));
                    }
                    snapshot_header_pipeline = None;
                    let terminal_height = sync.manifest.tip_height;
                    let terminal_hash = sync.manifest.tip_hash;
                    if let Some(payload) = prefetched_snapshot_boundary_terminal.take() {
                        start_snapshot_boundary_verification!(sync, payload);
                    } else {
                        let preferred_peer = sync.preferred_peer;
                        pending_snapshot_header_sync = Some(sync);
                        ensure_snapshot_boundary_terminal_request!();
                        tracing::info!(
                            preferred_peer = %preferred_peer,
                            target_height = terminal_height,
                            terminal_hash = %hex::encode(terminal_hash),
                            "snapshot: exact headers staged — requesting terminal from an exact provider"
                        );
                    }
                }
            }
        }

        completed = exact_suffix_apply_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            if exact_suffix_apply_inflight != Some(completed.plan_id) {
                tracing::debug!(
                    ?completed.plan_id,
                    target_height = completed.target.height,
                    "discarding superseded exact suffix apply completion"
                );
                continue;
            }
            exact_suffix_apply_inflight = None;
            let mut committed_exact_tip = None;

            match completed.result {
                Ok(AppliedExactSuffix::Live(mut applied)) => {
                    let complete = applied.trailing_error.is_none()
                        && applied.height == completed.target.height
                        && applied.block_hash == completed.target.hash;
                    let selected_tip_committed = complete
                        && !header_dag_faulted
                        && header_dag.best_tip() == completed.target;
                    if applied.applied_blocks != 0 {
                        if selected_tip_committed {
                            mining_peer_quorum
                                .set_canonical_tip(applied.height, applied.block_hash, true);
                            mining_peer_quorum.resolve_committed_view();
                            for source in &completed.confirmation_sources {
                                mining_peer_quorum.confirm_tip(
                                    *source,
                                    applied.height,
                                    applied.block_hash,
                                );
                            }
                        } else {
                            // A partial prefix or a target superseded while its
                            // objects were verified is valid chain progress,
                            // but it is not authority to mine this parent.
                            mining_peer_quorum.set_canonical_tip_unresolved(
                                applied.height,
                                applied.block_hash,
                                true,
                            );
                        }
                        external_mining_attempts
                            .invalidate_for_tip(applied.height, applied.block_hash);
                        last_tip_advance = Instant::now();
                        let _ = template_changes.send(());
                    }
                    tracing::info!(
                        ?completed.plan_id,
                        target_height = completed.target.height,
                        height = applied.height,
                        blocks = applied.applied_blocks,
                        bytes = applied.payload_bytes,
                        elapsed_ms = applied.apply_elapsed.as_millis(),
                        complete,
                        "header-first exact suffix application completed"
                    );
                    if let Some(error) = applied.trailing_error.take() {
                        let rejected_sources = error.peer_sources().to_vec();
                        let newly_rejected = quarantine_exact_suffix_sources(
                            &mut header_dag,
                            &mut rejected_suffix_object_peers,
                            &rejected_sources,
                        );
                        tracing::warn!(
                            ?completed.plan_id,
                            height = applied.height,
                            rejected_sources = rejected_sources.len(),
                            newly_rejected,
                            %error,
                            "exact suffix stopped after a committed valid prefix"
                        );
                    }
                    if complete {
                        committed_exact_tip = Some(noid_node::networking::ChainPoint::new(
                            applied.height,
                            applied.block_hash,
                        ));
                        let relay = p2p_cmd.clone();
                        let announcement = completed.tip_announcement;
                        tokio::spawn(async move {
                            if relay
                                .send(noid_p2p::NetworkCommand::AnnounceAvailability {
                                    announcement,
                                })
                                .await
                                .is_err()
                            {
                                tracing::warn!(
                                    height = announcement.header.height,
                                    "P2P command lanes closed before exact availability cascade"
                                );
                            }
                        });
                        mark_bootstrap_complete_if_caught_up!(applied.height);
                    }
                }
                Ok(AppliedExactSuffix::Reorg(applied)) => {
                    committed_exact_tip = Some(completed.target);
                    let reverted = applied.result.reverted_heights.len();
                    let applied_blocks = applied.result.applied_heights.len();
                    let selected_tip_committed = !header_dag_faulted
                        && header_dag.best_tip() == completed.target;
                    if selected_tip_committed {
                        mining_peer_quorum.set_canonical_tip(
                            completed.target.height,
                            completed.target.hash,
                            false,
                        );
                        mining_peer_quorum.resolve_committed_view();
                        for source in &completed.confirmation_sources {
                            mining_peer_quorum.confirm_tip(
                                *source,
                                completed.target.height,
                                completed.target.hash,
                            );
                        }
                        let relay = p2p_cmd.clone();
                        let announcement = completed.tip_announcement;
                        tokio::spawn(async move {
                            if relay
                                .send(noid_p2p::NetworkCommand::AnnounceAvailability {
                                    announcement,
                                })
                                .await
                                .is_err()
                            {
                                tracing::warn!(
                                    height = announcement.header.height,
                                    "P2P command lanes closed before reorg availability cascade"
                                );
                            }
                        });
                    } else {
                        mining_peer_quorum.set_canonical_tip_unresolved(
                            completed.target.height,
                            completed.target.hash,
                            false,
                        );
                    }
                    external_mining_attempts.invalidate_for_tip(
                        completed.target.height,
                        completed.target.hash,
                    );
                    last_tip_advance = Instant::now();
                    let _ = template_changes.send(());
                    tracing::info!(
                        ?completed.plan_id,
                        new_tip = completed.target.height,
                        reverted,
                        applied = applied_blocks,
                        "atomic one-terminal exact reorg completed"
                    );
                }
                Err(error) => {
                    let terminal_rejected = error.is_terminal_fault();
                    let rejected_sources = error.peer_sources().to_vec();
                    if terminal_rejected {
                        for source in &rejected_sources {
                            rejected_terminal_peers.insert(*source);
                            manifest_terminal_capabilities.remove(source);
                        }
                    }
                    let newly_rejected = quarantine_exact_suffix_sources(
                        &mut header_dag,
                        &mut rejected_suffix_object_peers,
                        &rejected_sources,
                    );
                    tracing::warn!(
                        ?completed.plan_id,
                        target_height = completed.target.height,
                        terminal_rejected,
                        rejected_sources = rejected_sources.len(),
                        newly_rejected,
                        %error,
                        "exact suffix rejected before canonical selection completed"
                    );
                }
            }

            if let Some(exact_tip) = committed_exact_tip {
                let snapshot = pending_manifest
                    .as_ref()
                    .map(|pending| pending.offer.snapshot_id());
                let superseded_snapshot = if let Some(snapshot) = snapshot {
                    let (canonical_tip_height, canonical_boundary) = {
                        let ctx = chain.read().await;
                        let canonical_boundary = if ctx.tip_height() >= snapshot.boundary.height {
                            match ctx.get_header_from_store(snapshot.boundary.height) {
                                Ok(Some(header)) => {
                                    Some(noid_node::networking::ChainPoint::new(
                                        snapshot.boundary.height,
                                        noid_chain::block_header::block_id(&header),
                                    ))
                                }
                                Ok(None) => None,
                                Err(error) => {
                                    tracing::error!(
                                        snapshot_height = snapshot.boundary.height,
                                        %error,
                                        "failed to load canonical snapshot-boundary header after exact progress"
                                    );
                                    None
                                }
                            }
                        } else {
                            None
                        };
                        (ctx.tip_height(), canonical_boundary)
                    };
                    canonical_tip_supersedes_snapshot_boundary(
                        canonical_tip_height,
                        canonical_boundary,
                        snapshot.boundary,
                    )
                    .then_some(snapshot)
                } else {
                    None
                };
                if let Some(snapshot) = superseded_snapshot {
                    tracing::info!(
                        exact_height = exact_tip.height,
                        snapshot_height = snapshot.boundary.height,
                        "exact suffix completed first — retiring superseded snapshot transfer"
                    );
                    retire_snapshot_plan!();
                }
            }

            // The canonical base may have changed while announcements were
            // deferred. Ask one connected source for a fresh compact view;
            // failures rotate at the object layer and never erase progress.
            let current_height = {
                let ctx = chain.read().await;
                ctx.tip_height()
            };
            retire_post_snapshot_tail_if_finished!(current_height);
            let probe_peer = deferred_sync_peer
                .take()
                .filter(|peer| manifest_peers.contains(peer))
                .or_else(|| manifest_peers.iter().copied().min_by_key(|peer| peer.to_bytes()));
            if let Some(peer) = probe_peer {
                let count = CONNECTED_TIP_PROBE_HEADERS;
                let request_key = (peer, current_height, count);
                if !fetch_in_progress.contains(&peer)
                    && !recent_header_fetches
                        .get(&request_key)
                        .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL)
                {
                    try_dispatch_header_fetch(
                        &p2p_cmd,
                        &mut fetch_in_progress,
                        &mut recent_header_fetches,
                        peer,
                        current_height,
                        count,
                        Instant::now(),
                    );
                }
            }
        }

        completed = snapshot_staging_completion_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            let key = match &completed {
                SnapshotStagingCompletion::Accepted { key, .. }
                | SnapshotStagingCompletion::Finalized { key, .. } => *key,
            };
            if snapshot_staging_inflight != Some(key) {
                tracing::debug!(?key, "discarding superseded snapshot staging completion");
                match completed {
                    SnapshotStagingCompletion::Accepted {
                        result:
                            SnapshotSegmentStageResult::Accepted(staging)
                            | SnapshotSegmentStageResult::SourceRejected { staging, .. },
                        ..
                    } => cleanup_snapshot_staging_session_offthread(staging),
                    SnapshotStagingCompletion::Finalized {
                        result: SnapshotFinalizationOutcome::Finalized(finalized),
                        ..
                    } => cleanup_finalized_snapshot_staging_offthread(finalized),
                    _ => {}
                }
                continue;
            }
            snapshot_staging_inflight = None;

            match completed {
                SnapshotStagingCompletion::Accepted {
                    key,
                    payload_bytes,
                    work_elapsed,
                    result,
                } => {
                    let SnapshotStagingOperationKey::Accept {
                        generation,
                        snapshot,
                        from,
                        segment_id,
                    } = key
                    else {
                        unreachable!("accepted completion always has an accept key");
                    };
                    if generation != snapshot_sync_generation {
                        match result {
                            SnapshotSegmentStageResult::Accepted(staging)
                            | SnapshotSegmentStageResult::SourceRejected { staging, .. } => {
                                cleanup_snapshot_staging_session_offthread(staging);
                            }
                            SnapshotSegmentStageResult::CandidateRejected(_)
                            | SnapshotSegmentStageResult::Fatal(_) => {}
                        }
                        tracing::debug!(
                            from = %from,
                            segment = segment_id,
                            "discarding snapshot segment staged for a retired plan generation"
                        );
                        continue;
                    }
                    if active_snapshot_sync
                        .as_ref()
                        .is_none_or(|sync| sync.plan().snapshot_id() != Some(snapshot))
                    {
                        match result {
                            SnapshotSegmentStageResult::Accepted(staging)
                            | SnapshotSegmentStageResult::SourceRejected { staging, .. } => {
                                cleanup_snapshot_staging_session_offthread(staging);
                            }
                            SnapshotSegmentStageResult::CandidateRejected(_)
                            | SnapshotSegmentStageResult::Fatal(_) => {}
                        }
                        tracing::debug!(
                            from = %from,
                            segment = segment_id,
                            "discarding snapshot segment staged for another exact plan"
                        );
                        continue;
                    }
                    let staging = match result {
                        SnapshotSegmentStageResult::Accepted(staging) => staging,
                        SnapshotSegmentStageResult::SourceRejected { staging, error } => {
                            tracing::warn!(
                                from = %from,
                                segment = segment_id,
                                err = %error,
                                "snapshot segment authentication/staging failed; retaining verified objects"
                            );
                            snapshot_staging = Some(staging);
                            reject_snapshot_segment_source!(
                                from,
                                segment_id,
                                "segment authentication failed"
                            );
                            // One exact response may already be buffered behind
                            // this disk operation. It has its own descriptor and
                            // root, so authenticate it normally instead of
                            // throwing away useful bytes with the failed object.
                            if let Some((queued_from, response)) =
                                queued_segment_response.take()
                            {
                                stage_snapshot_segment_response!(queued_from, response);
                            }
                            continue;
                        }
                        SnapshotSegmentStageResult::CandidateRejected(error) => {
                            let failed_peer = pending_manifest
                                .as_ref()
                                .map(|pending| pending.preferred_peer)
                                .unwrap_or(from);
                            tracing::warn!(
                                peer = %from,
                                segment = segment_id,
                                err = %error,
                                "root-bound snapshot segment violates boundary semantics; retiring immutable candidate"
                            );
                            retire_snapshot_plan!();
                            request_bounded_manifest_failover!(failed_peer, false);
                            continue;
                        }
                        SnapshotSegmentStageResult::Fatal(error) => {
                            tracing::error!(
                                from = %from,
                                segment = segment_id,
                                err = %error,
                                "snapshot segment staging worker failed"
                            );
                            return Err(anyhow::anyhow!(
                                "snapshot segment staging worker failed for segment {segment_id}: {error}"
                            ));
                        }
                    };
                    sync_phase_telemetry.record_state_segment(payload_bytes, work_elapsed);
                    if pending_manifest.is_none() {
                        tracing::warn!(
                            from = %from,
                            segment = segment_id,
                            "snapshot staging completion lost its selected manifest"
                        );
                        cleanup_snapshot_staging_session_offthread(staging);
                        return Err(anyhow::anyhow!(
                            "snapshot staging completion lost its immutable manifest"
                        ));
                    }
                    let Some(segment) = active_snapshot_sync
                        .as_ref()
                        .and_then(|sync| sync.segment(segment_id))
                    else {
                        cleanup_snapshot_staging_session_offthread(staging);
                        return Err(anyhow::anyhow!(
                            "snapshot staging completion lost exact segment {segment_id}"
                        ));
                    };
                    if let Err(error) = active_snapshot_sync
                        .as_mut()
                        .expect("exact snapshot plan exists")
                        .mark_verified(segment)
                    {
                        tracing::error!(from = %from, segment = segment_id, %error, "staged snapshot segment lost exact-object authority");
                        cleanup_snapshot_staging_session_offthread(staging);
                        return Err(anyhow::anyhow!(
                            "staged snapshot segment {segment_id} lost exact-object authority: {error}"
                        ));
                    }
                    snapshot_staging = Some(staging);
                    snapshot_plan_last_progress = Some(Instant::now());
                    snapshot_provider_discovery_rounds = 0;

                    if let Some((queued_from, response)) = queued_segment_response.take() {
                        stage_snapshot_segment_response!(queued_from, response);
                    }

                    dispatch_snapshot_segments_from_available_source!();
                    let remaining = active_snapshot_sync
                        .as_ref()
                        .map(|sync| {
                            let counts = sync.counts();
                            counts.wanted + counts.in_flight + counts.received
                        })
                        .unwrap_or(0);
                    tracing::debug!(
                        from = %from,
                        segment = segment_id,
                        remaining,
                        "snapshot segment authenticated and sealed to disk"
                    );

                    // Once every response is durably staged, independently
                    // reconstruct the exact root in the same one-operation
                    // blocking lane.  `pending_manifest` continues to own the
                    // authenticated HistoryStep boundary and inbound permit during this pass.
                    if snapshot_staging_inflight.is_none()
                        && queued_segment_response.is_none()
                        && active_snapshot_sync
                            .as_ref()
                            .is_some_and(|sync| sync.all_segments_verified())
                    {
                        let staging = snapshot_staging
                            .take()
                            .expect("accepted snapshot session is available for finalization");
                        let segment_count = staging.descriptors().len();
                        let snapshot = pending_manifest
                            .as_ref()
                            .expect("snapshot manifest exists during finalization")
                            .offer
                            .snapshot_id();
                        let key = SnapshotStagingOperationKey::Finalize {
                            generation: snapshot_sync_generation,
                            snapshot,
                        };
                        snapshot_staging_inflight = Some(key);
                        let completion = snapshot_staging_completion_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let started = Instant::now();
                            let result = std::panic::catch_unwind(
                                std::panic::AssertUnwindSafe(move || {
                                    match staging.finalize() {
                                        Ok(finalized) => {
                                            SnapshotFinalizationOutcome::Finalized(finalized)
                                        }
                                        Err(error) => classify_snapshot_finalization_error(error),
                                    }
                                }),
                            )
                            .unwrap_or_else(|_| {
                                SnapshotFinalizationOutcome::Fatal(
                                    "snapshot finalization worker panicked".to_owned(),
                                )
                            });
                            let _ = completion.blocking_send(
                                SnapshotStagingCompletion::Finalized {
                                    key,
                                    segment_count,
                                    work_elapsed: started.elapsed(),
                                    result,
                                },
                            );
                        });
                    }
                }
                SnapshotStagingCompletion::Finalized {
                    key,
                    segment_count,
                    work_elapsed,
                    result,
                } => {
                    let SnapshotStagingOperationKey::Finalize {
                        generation,
                        snapshot,
                    } = key
                    else {
                        unreachable!("finalized completion always has a finalize key");
                    };
                    if generation != snapshot_sync_generation {
                        if let SnapshotFinalizationOutcome::Finalized(finalized) = result {
                            cleanup_finalized_snapshot_staging_offthread(finalized);
                        }
                        tracing::debug!(
                            boundary = snapshot.boundary.height,
                            "discarding snapshot finalization for a retired plan generation"
                        );
                        continue;
                    }
                    let finalized = match result {
                        SnapshotFinalizationOutcome::Finalized(finalized) => finalized,
                        SnapshotFinalizationOutcome::CandidateRejected(error) => {
                            let failed_peer = pending_manifest
                                .as_ref()
                                .map(|pending| pending.preferred_peer)
                                .ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "invalid finalized snapshot lost its immutable manifest"
                                    )
                                })?;
                            tracing::warn!(
                                peer = %failed_peer,
                                boundary = snapshot.boundary.height,
                                err = %error,
                                "snapshot generation does not reconstruct its authenticated State commitment"
                            );
                            retire_snapshot_plan!();
                            request_bounded_manifest_failover!(failed_peer, false);
                            continue;
                        }
                        SnapshotFinalizationOutcome::Fatal(error) => {
                            tracing::error!(
                                boundary = snapshot.boundary.height,
                                err = %error,
                                "fatal local snapshot exact-state finalization failure"
                            );
                            return Err(anyhow::anyhow!(
                                "local snapshot exact-state finalization failed at {}: {error}",
                                snapshot.boundary.height
                            ));
                        }
                    };
                    sync_phase_telemetry.record_state_work(work_elapsed);
                    let Some(pending) = pending_manifest.as_ref() else {
                        tracing::warn!(boundary = snapshot.boundary.height, "snapshot finalized without selected manifest");
                        cleanup_finalized_snapshot_staging_offthread(finalized);
                        return Err(anyhow::anyhow!(
                            "finalized snapshot lost selected manifest at {}",
                            snapshot.boundary.height
                        ));
                    };
                    if pending.offer.snapshot_id() != snapshot {
                        tracing::warn!(boundary = snapshot.boundary.height, "snapshot finalization plan changed");
                        cleanup_finalized_snapshot_staging_offthread(finalized);
                        preserve_active_snapshot_headers!();
                        return Err(anyhow::anyhow!(
                            "finalized snapshot plan changed at {}",
                            snapshot.boundary.height
                        ));
                    }
                    finalized_snapshot_waiting = Some((finalized, segment_count));
                    tracing::info!(
                        boundary = pending.manifest.tip_height,
                        "snapshot State finalized at its exact boundary"
                    );
                    try_start_ready_snapshot_install!();
                }
            }
        }

        completed = snapshot_install_completion_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            if snapshot_install_inflight != Some(completed.key) {
                tracing::debug!(?completed.key, "discarding superseded snapshot install completion");
                continue;
            }
            snapshot_install_inflight = None;
            if let Some(token) = completed.key.terminal_request_token {
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace { token })
                    .await;
            }
            match completed.result {
                Ok(applied) => {
                    snapshot_rebase_hint = None;
                    sync_phase_telemetry.record_state_work(applied.state_install_elapsed);
                    log_sync_phase_measurement(sync_phase_telemetry.finish_headers());
                    log_sync_phase_measurement(sync_phase_telemetry.finish_state());
                    log_sync_phase_measurement(sync_phase_telemetry.complete_staged_tail(
                        applied.tail_blocks,
                        applied.tail_bytes,
                        applied.tail_apply_elapsed,
                    ));

                    let height = applied.height;
                    arm_post_snapshot_tail!(height, applied.block_hash);
                    mining_peer_quorum.set_canonical_tip(height, applied.block_hash, false);
                    record_authenticated_height!(height, completed.key.observer_peer);
                    tracing::info!(
                        height,
                        tail_blocks = applied.tail_blocks,
                        observer_peer = %completed.key.observer_peer,
                        "snapshot install completed"
                    );
                    retire_snapshot_plan!();
                    if highest_announced > height {
                        let _ = sync_phase_telemetry.begin_suffix(height, highest_announced);
                    }
                    last_tip_advance = Instant::now();
                    mining_peer_quorum.confirm_tip(
                        completed.key.observer_peer,
                        height,
                        applied.block_hash,
                    );
                    let _ = template_changes.send(());
                    let preferred_probe_peer = deferred_sync_peer
                        .take()
                        .filter(|peer| manifest_peers.contains(peer))
                        .or_else(|| {
                            (highest_announced > height)
                                .then_some(last_announcement_peer)
                                .flatten()
                                .filter(|peer| manifest_peers.contains(peer))
                        })
                        .or_else(|| {
                            manifest_peers
                                .contains(&completed.key.observer_peer)
                                .then_some(completed.key.observer_peer)
                        });
                    let mut probe_peers = preferred_probe_peer.into_iter().collect::<Vec<_>>();
                    let excluded = std::collections::HashSet::new();
                    for peer in rotating_manifest_peers(
                        &manifest_peers,
                        &excluded,
                        None,
                        false,
                        &mut exact_inventory_probe_cursor,
                        EXACT_INVENTORY_PROBE_LANES,
                    ) {
                        if !probe_peers.contains(&peer) {
                            probe_peers.push(peer);
                        }
                        if probe_peers.len() >= EXACT_INVENTORY_PROBE_LANES {
                            break;
                        }
                    }
                    let count = post_snapshot_tail
                        .and_then(|tail| tail.probe_count(height))
                        .unwrap_or(CONNECTED_TIP_PROBE_HEADERS);
                    let mut dispatched = 0usize;
                    for peer in probe_peers {
                        if try_dispatch_header_fetch(
                            &p2p_cmd,
                            &mut fetch_in_progress,
                            &mut recent_header_fetches,
                            peer,
                            height,
                            count,
                            Instant::now(),
                        ) {
                            dispatched = dispatched.saturating_add(1);
                        }
                    }
                    if dispatched > 0 {
                        tracing::debug!(
                            from_height = height,
                            count,
                            dispatched,
                            highest_announced,
                            "probing the complete bounded tail immediately after snapshot install"
                        );
                    } else {
                        request_exact_tip_confirmation!(completed.key.observer_peer, height);
                    }
                }
                Err(SnapshotInstallError::Superseded {
                    snapshot_height,
                    local_height,
                    local_hash,
                }) => {
                    snapshot_rebase_hint = None;
                    tracing::info!(
                        snapshot_height,
                        local_height,
                        local_hash = %hex::encode(local_hash),
                        "verified snapshot install became unnecessary after exact suffix progress"
                    );
                    retire_snapshot_plan!();
                }
                Err(SnapshotInstallError::BeforeCommit(error)) => {
                    tracing::error!(
                        observer_peer = %completed.key.observer_peer,
                        tip = completed.key.height,
                        err = %error,
                        "failed to apply verified state snapshot"
                    );
                    preserve_active_snapshot_headers!();
                    return Err(anyhow::anyhow!(
                        "verified snapshot install failed before commit at {}: {error}",
                        completed.key.height
                    ));
                }
                Err(SnapshotInstallError::AfterCommit {
                    applied,
                    error,
                    terminal_rejected,
                }) => {
                    snapshot_rebase_hint = None;
                    if terminal_rejected {
                        if let Some(terminal_from) = completed.key.terminal_from {
                            rejected_terminal_peers.insert(terminal_from);
                            manifest_terminal_capabilities.remove(&terminal_from);
                            quarantine_exact_suffix_sources(
                                &mut header_dag,
                                &mut rejected_suffix_object_peers,
                                &[terminal_from],
                            );
                        }
                    }
                    sync_phase_telemetry.record_state_work(applied.state_install_elapsed);
                    log_sync_phase_measurement(sync_phase_telemetry.finish_headers());
                    log_sync_phase_measurement(sync_phase_telemetry.finish_state());
                    log_sync_phase_measurement(sync_phase_telemetry.complete_staged_tail(
                        applied.tail_blocks,
                        applied.tail_bytes,
                        applied.tail_apply_elapsed,
                    ));
                    let height = applied.height;
                    arm_post_snapshot_tail!(height, applied.block_hash);
                    mining_peer_quorum.set_canonical_tip(height, applied.block_hash, false);
                    record_authenticated_height!(height, completed.key.observer_peer);
                    tracing::warn!(
                        observer_peer = %completed.key.observer_peer,
                        height,
                        block_hash = %hex::encode(applied.block_hash),
                        tail_blocks = applied.tail_blocks,
                        err = %error,
                        "snapshot committed a valid prefix; continuing sync from the durable tip"
                    );
                    retire_snapshot_plan!();
                    last_tip_advance = Instant::now();
                    let _ = template_changes.send(());
                    let recovery_peer = deferred_sync_peer
                        .take()
                        .filter(|peer| {
                            manifest_peers.contains(peer)
                                && !rejected_terminal_peers.contains(peer)
                        })
                        .or_else(|| {
                            manifest_peers
                                .iter()
                                .copied()
                                .filter(|peer| *peer != completed.key.observer_peer)
                                .filter(|peer| !rejected_terminal_peers.contains(peer))
                                .min_by_key(|peer| peer.to_bytes())
                        })
                        .or_else(|| {
                            (manifest_peers.contains(&completed.key.observer_peer)
                                && !rejected_terminal_peers.contains(&completed.key.observer_peer))
                                .then_some(completed.key.observer_peer)
                        });
                    if let Some(peer) = recovery_peer {
                        let count = post_snapshot_tail
                            .and_then(|tail| tail.probe_count(height))
                            .unwrap_or(CONNECTED_TIP_PROBE_HEADERS);
                        try_dispatch_header_fetch(
                            &p2p_cmd,
                            &mut fetch_in_progress,
                            &mut recent_header_fetches,
                            peer,
                            height,
                            count,
                            Instant::now(),
                        );
                    }
                }
            }
        }

        completed = history_step_verification_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            let terminal_rejected = matches!(
                &completed.result,
                SnapshotBoundaryVerificationOutcome::TerminalRejected { .. }
            );
            let _ = p2p_cmd
                .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                    token: completed.key.terminal_request_token,
                })
                .await;
            if terminal_rejected {
                rejected_terminal_peers.insert(completed.key.terminal_from);
                manifest_terminal_capabilities.remove(&completed.key.terminal_from);
                quarantine_exact_suffix_sources(
                    &mut header_dag,
                    &mut rejected_suffix_object_peers,
                    &[completed.key.terminal_from],
                );
            }
            if history_step_verification_inflight != Some(completed.key) {
                // Supersession is not proof invalidity. Close the handles but
                // leave the exact staging file available to the selected plan.
                drop(completed.result);
                tracing::debug!(
                    boundary = completed.key.snapshot.boundary.height,
                    tip = completed.key.height,
                    "discarding superseded HistoryStep verification"
                );
                continue;
            }
            history_step_verification_inflight = None;
            if completed.generation != snapshot_sync_generation {
                // A new exact generation may reopen this file. Never turn a
                // stale transport completion into another network download.
                drop(completed.result);
                tracing::debug!(
                    boundary = completed.key.snapshot.boundary.height,
                    tip = completed.key.height,
                    "discarding HistoryStep verification from a retired plan generation"
                );
                continue;
            }

            sync_phase_telemetry.record_header_work(completed.header_validation_elapsed);
            sync_phase_telemetry.observe_header_scale(
                completed.staged_header_count,
                completed
                    .staged_header_count
                    .saturating_mul(noid_chain::BLOCK_HEADER_WIRE_SIZE as u64),
            );
            if let Some(measurement) = completed.terminal_measurement {
                log_sync_phase_measurement(measurement);
            }

            let verified_history_step = match completed.result {
                SnapshotBoundaryVerificationOutcome::Accepted(verified) => verified,
                SnapshotBoundaryVerificationOutcome::TerminalRejected {
                    error,
                    authority,
                } => {
                    tracing::error!(
                        boundary = completed.key.snapshot.boundary.height,
                        terminal_from = %completed.key.terminal_from,
                        tip = completed.key.height,
                        err = %error,
                        "snapshot terminal rejected; retaining validated headers and rotating source"
                    );
                    retained_snapshot_headers = Some(authority);
                    request_snapshot_generation_providers!(completed.key.terminal_from);
                    ensure_snapshot_boundary_terminal_request!();
                    continue;
                }
                SnapshotBoundaryVerificationOutcome::CandidateRejected { error, authority } => {
                    if let Some(authority) = authority {
                        cleanup_validated_snapshot_headers_offthread(authority.headers);
                    }
                    let failed_peer = pending_manifest
                        .as_ref()
                        .map(|pending| pending.preferred_peer)
                        .unwrap_or(completed.key.terminal_from);
                    tracing::warn!(
                        boundary = completed.key.snapshot.boundary.height,
                        terminal_from = %completed.key.terminal_from,
                        tip = completed.key.height,
                        err = %error,
                        "snapshot candidate rejected; retiring only its immutable plan"
                    );
                    retire_snapshot_plan!();
                    request_bounded_manifest_failover!(failed_peer, false);
                    continue;
                }
                SnapshotBoundaryVerificationOutcome::BaseMoved { error, authority } => {
                    if let Some(authority) = authority {
                        cleanup_validated_snapshot_headers_offthread(authority.headers);
                    }
                    let previous_peer = pending_manifest
                        .as_ref()
                        .map(|pending| pending.preferred_peer)
                        .unwrap_or(completed.key.terminal_from);
                    tracing::info!(
                        boundary = completed.key.snapshot.boundary.height,
                        tip = completed.key.height,
                        err = %error,
                        "local non-final snapshot base moved; selecting a fresh exact plan"
                    );
                    snapshot_rebase_hint = None;
                    retire_snapshot_plan!();
                    // This is local canonical movement, not peer misbehaviour.
                    request_bounded_manifest_failover!(previous_peer, true);
                    continue;
                }
                SnapshotBoundaryVerificationOutcome::Fatal { error, authority } => {
                    if let Some(authority) = authority {
                        cleanup_validated_snapshot_headers_offthread(authority.headers);
                    }
                    tracing::error!(
                        boundary = completed.key.snapshot.boundary.height,
                        terminal_from = %completed.key.terminal_from,
                        tip = completed.key.height,
                        err = %error,
                        "fatal local snapshot boundary verification failure"
                    );
                    return Err(anyhow::anyhow!(
                        "local snapshot boundary verification failed at {}: {error}",
                        completed.key.height
                    ));
                }
            };

            tracing::info!(
                terminal_from = %completed.key.terminal_from,
                tip = completed.manifest.tip_height,
                segments = completed.manifest.segment_ids.len(),
                "snapshot authority accepted — starting exact state staging"
            );
            let boundary_header = *verified_history_step.boundary.header();
            let Some(selected) = pending_manifest.as_mut() else {
                tracing::warn!(
                    boundary = completed.key.snapshot.boundary.height,
                    "verified snapshot authority lost its selected manifest"
                );
                drop_verified_history_step(verified_history_step);
                return Err(anyhow::anyhow!(
                    "verified snapshot authority lost selected manifest at {}",
                    completed.key.snapshot.boundary.height
                ));
            };
            if selected.offer.snapshot_id() != completed.key.snapshot
                || selected.manifest.as_ref() != completed.manifest.as_ref()
            {
                tracing::warn!(
                    boundary = completed.key.snapshot.boundary.height,
                    "verified snapshot authority differs from the selected generation"
                );
                drop_verified_history_step(verified_history_step);
                return Err(anyhow::anyhow!(
                    "verified snapshot authority differs from immutable generation at {}",
                    completed.key.snapshot.boundary.height
                ));
            }
            let initial_peer = selected.preferred_peer;
            let selected_offer = selected.offer.clone();
            let selected_providers = selected.providers.iter().copied().collect::<Vec<_>>();
            let manifest = selected.manifest.clone();
            let staging = match create_snapshot_staging_session(
                &snapshot_staging_root,
                &manifest,
                boundary_header,
            ) {
                Ok(staging) => staging,
                Err(SnapshotSessionPrepareError::CandidateRejected(error)) => {
                    tracing::warn!(
                        peer = %initial_peer,
                        boundary = completed.key.snapshot.boundary.height,
                        err = %error,
                        "authenticated snapshot manifest cannot initialize State staging"
                    );
                    drop_verified_history_step(verified_history_step);
                    retire_snapshot_plan!();
                    request_bounded_manifest_failover!(initial_peer, false);
                    continue;
                }
                Err(SnapshotSessionPrepareError::Fatal(error)) => {
                    tracing::error!(
                        boundary = completed.key.snapshot.boundary.height,
                        err = %error,
                        "fatal local snapshot State staging initialization failure"
                    );
                    drop_verified_history_step(verified_history_step);
                    return Err(anyhow::anyhow!(
                        "local snapshot State staging initialization failed at {}: {error}",
                        completed.key.snapshot.boundary.height
                    ));
                }
            };
            let initial_domain = peer_failure_domains.get(&initial_peer).copied().unwrap_or(
                noid_node::networking::FailureDomain(u64::MAX),
            );
            let semantic_header_id = noid_chain::block_header::semantic_header_id(&boundary_header);
            let mut snapshot_sync = match noid_node::networking::snapshot_sync::SnapshotSync::new(
                initial_peer,
                initial_domain,
                selected_offer.clone(),
                verified_history_step.boundary.history_step_terminal_bytes(),
                semantic_header_id,
            ) {
                Ok(sync) => sync,
                Err(error) => {
                    tracing::warn!(boundary = completed.key.snapshot.boundary.height, %error, "verified snapshot could not enter its immutable object plan");
                    drop_verified_history_step(verified_history_step);
                    return Err(anyhow::anyhow!(
                        "verified snapshot could not enter immutable object plan at {}: {error}",
                        completed.key.snapshot.boundary.height
                    ));
                }
            };
            for provider in selected_providers {
                if provider == initial_peer {
                    continue;
                }
                let domain = peer_failure_domains.get(&provider).copied().unwrap_or(
                    noid_node::networking::FailureDomain(u64::MAX),
                );
                if let Err(error) = snapshot_sync.add_provider(provider, domain, selected_offer.clone()) {
                    tracing::warn!(peer = %provider, %error, "snapshot provider does not match immutable plan");
                }
            }
            if let Some(rejected) = rejected_snapshot_manifest_providers
                .get(&selected_offer.manifest().manifest_digest)
            {
                for provider in rejected {
                    snapshot_sync.quarantine_provider(*provider);
                }
            }
            active_snapshot_sync = Some(snapshot_sync);
            snapshot_plan_last_progress = Some(Instant::now());
            snapshot_provider_discovery_rounds = 0;
            // The terminal allocation and inbound permit remain owned by the
            // selected manifest until atomic snapshot installation.
            record_authenticated_height!(completed.manifest.tip_height, completed.key.terminal_from);
            pending_manifest
                .as_mut()
                .expect("selected snapshot manifest is installed")
                .history_step = Some(verified_history_step);
            snapshot_staging = Some(staging);
            dispatch_snapshot_segments_from_available_source!();

            if active_snapshot_sync
                .as_ref()
                .is_some_and(|sync| sync.all_segments_verified())
            {
                let staging = snapshot_staging
                    .take()
                    .expect("snapshot staging exists before empty finalization");
                let segment_count = staging.descriptors().len();
                let key = SnapshotStagingOperationKey::Finalize {
                    generation: snapshot_sync_generation,
                    snapshot: completed.key.snapshot,
                };
                snapshot_staging_inflight = Some(key);
                let completion = snapshot_staging_completion_tx.clone();
                tokio::task::spawn_blocking(move || {
                    let started = Instant::now();
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                        move || match staging.finalize() {
                            Ok(finalized) => SnapshotFinalizationOutcome::Finalized(finalized),
                            Err(error) => classify_snapshot_finalization_error(error),
                        },
                    ))
                    .unwrap_or_else(|_| {
                        SnapshotFinalizationOutcome::Fatal(
                            "snapshot finalization worker panicked".to_owned(),
                        )
                    });
                    let _ = completion.blocking_send(SnapshotStagingCompletion::Finalized {
                        key,
                        segment_count,
                        work_elapsed: started.elapsed(),
                        result,
                    });
                });
            }
        }

        completed = boundary_proof_maintenance_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            if boundary_proof_verification_inflight != Some(completed.target) {
                tracing::debug!(
                    height = completed.target.height(),
                    "discarding superseded snapshot-boundary proof maintenance completion"
                );
                continue;
            }
            boundary_proof_verification_inflight = None;
            last_boundary_proof_maintenance = Instant::now();
            match completed.result {
                BoundaryProofMaintenanceResult::Cached => {
                    tracing::info!(
                        peer = %completed.from,
                        height = completed.target.height(),
                        "cached verified terminal for deterministic snapshot boundary"
                    );
                }
                BoundaryProofMaintenanceResult::TerminalRejected(error) => {
                    rejected_terminal_peers.insert(completed.from);
                    manifest_terminal_capabilities.remove(&completed.from);
                    quarantine_exact_suffix_sources(
                        &mut header_dag,
                        &mut rejected_suffix_object_peers,
                        &[completed.from],
                    );
                    tracing::warn!(
                        peer = %completed.from,
                        height = completed.target.height(),
                        %error,
                        "snapshot-boundary proof source rejected; canonical chain unchanged"
                    );
                }
                BoundaryProofMaintenanceResult::LocalFailure(error) => {
                    tracing::error!(
                        height = completed.target.height(),
                        %error,
                        "snapshot-boundary proof maintenance failed locally"
                    );
                    return Err(anyhow::anyhow!(
                        "snapshot-boundary proof maintenance failed locally at {}: {error}",
                        completed.target.height()
                    ));
                }
            }
        }

        // Heartbeat: re-evaluate manifest timeout without waiting for a new P2P event.
        _ = heartbeat.tick() => {
            let now = Instant::now();
            dispatch_snapshot_generation_advance!();
            if let Some(pipeline) = snapshot_header_pipeline.as_mut() {
                let mut plans = pipeline
                    .resume_blocked(&manifest_peers, now)
                    .into_iter()
                    .collect::<Vec<_>>();
                plans.extend(pipeline.refill_plan(snapshot_header_staging_inflight.is_some()));
                dispatch_snapshot_header_plans(pipeline, &p2p_cmd, plans);
            }
            ensure_snapshot_boundary_terminal_request!();
            dispatch_boundary_proof_maintenance_requests!();
            let (our_height, our_hash, our_prev_hash, our_work, reconciled_header_dag) = {
                let ctx = chain.read().await;
                let canonical_tip = noid_node::networking::ChainPoint::new(
                    ctx.tip_height(),
                    ctx.tip_hash(),
                );
                let reconcile_due = canonical_tip != header_dag_canonical_tip
                    || (header_dag_faulted
                        && now.saturating_duration_since(last_header_dag_reconcile_attempt)
                            >= Duration::from_secs(10));
                let reconciled = reconcile_due
                    .then(|| reconcile_canonical_header_dag(&ctx, &mut header_dag));
                (
                    ctx.tip_height(),
                    ctx.tip_hash(),
                    ctx.tip_header().prev_block_hash,
                    *ctx.tip_chain_work(),
                    reconciled,
                )
            };
            if let Some(reconciled) = reconciled_header_dag {
                last_header_dag_reconcile_attempt = now;
                match reconciled {
                    Ok(()) => {
                        header_dag_canonical_tip = noid_node::networking::ChainPoint::new(
                            our_height,
                            our_hash,
                        );
                        header_dag_faulted = false;
                    }
                    Err(error) => {
                        header_dag_faulted = true;
                        tracing::error!(%error, "canonical HeaderDAG reconciliation failed");
                    }
                }
            }
            retire_post_snapshot_tail_if_finished!(our_height);

            if manifest_candidate_selection_due(manifest_candidate_started_at, now)
                && pending_manifest.is_none()
                && pending_snapshot_header_sync.is_none()
                && snapshot_header_staging_inflight.is_none()
                && history_step_verification_inflight.is_none()
                && snapshot_staging_inflight.is_none()
                && snapshot_install_inflight.is_none()
            {
                let candidate = best_manifest_candidate
                    .take()
                    .expect("settled manifest selection has a candidate");
                manifest_candidate_started_at = None;
                let responses_considered = manifest_response_count;
                manifest_requested_peers.clear();
                manifest_force_snapshot_peers.clear();
                manifest_response_count = 0;
                manifest_round_started_at = None;
                if candidate.manifest.tip_height > our_height {
                    tracing::info!(
                        from = %candidate.from,
                        tip = candidate.manifest.tip_height,
                        bridge_tip = candidate.manifest.bridge_tip_height,
                        providers = candidate_manifest_providers.len(),
                        responses_considered,
                        "bounded snapshot candidate selection settled"
                    );
                    begin_snapshot_header_staging!(
                        candidate.from,
                        candidate.manifest,
                        candidate.rebase_anchor,
                        &mut fetch_in_progress,
                        &mut recent_header_fetches
                    );
                } else {
                    candidate_manifest_providers.clear();
                    tracing::debug!(
                        from = %candidate.from,
                        tip = candidate.manifest.tip_height,
                        our_height,
                        "snapshot manifest candidate became obsolete before selection settled"
                    );
                }
            }

            if !*initial_sync_ready.borrow() {
                let state_active = best_manifest_candidate.is_some()
                    || retained_snapshot_headers.is_some()
                    || history_step_verification_inflight.is_some()
                    || active_snapshot_sync.is_some()
                    || snapshot_staging.is_some()
                    || snapshot_staging_inflight.is_some()
                    || snapshot_install_inflight.is_some();
                let stage = advance_initial_sync_stage(
                    *initial_sync_stage_tx.borrow(),
                    state_active,
                    active_suffix_sync.is_some()
                        || exact_suffix_apply_inflight.is_some()
                        || post_snapshot_tail.is_some(),
                );
                if *initial_sync_stage_tx.borrow() != stage {
                    initial_sync_stage_tx.send_replace(stage);
                }
            }
            // This also catches locally mined or RPC-submitted blocks, whose
            // commits do not pass through this P2P event handler. A direct
            // child preserves fresh ancestry leases; any discontinuity is a
            // branch replacement and revokes them.
            mining_peer_quorum.reconcile_canonical_tip(our_height, our_hash, our_prev_hash);
            let unresolved_canonical_work = active_suffix_sync.is_some()
                || exact_suffix_apply_inflight.is_some()
                || header_dag_faulted
                || best_manifest_candidate.is_some()
                || pending_manifest.is_some()
                || pending_snapshot_header_sync.is_some()
                || snapshot_header_staging_inflight.is_some()
                || history_step_verification_inflight.is_some()
                || snapshot_install_inflight.is_some();
            mining_peer_quorum.set_sync_state(
                *initial_sync_ready.borrow(),
                unresolved_canonical_work,
            );
            mining_peer_quorum.expire_stale(now);

            // Data-lane backpressure is local scheduling, not a peer failure.
            // Exact jobs returned to Wanted are retried here without ever
            // blocking the header/control event loop.
            if let Some(sync) = active_suffix_sync.as_mut() {
                dispatch_exact_suffix_requests(sync, &p2p_cmd);
            }
            let fetch_cutoff = now - FETCH_DEDUP_TTL;
            recent_header_fetches.retain(|_, t| *t >= fetch_cutoff);

            let transport_now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            if active_snapshot_sync
                .as_ref()
                .is_some_and(|sync| !sync.all_segments_verified())
                && snapshot_install_inflight.is_none()
            {
                dispatch_snapshot_segments_from_available_source!();
            }

            // One watchdog covers every immutable snapshot phase. Header and
            // terminal transport may disappear before State fetching begins;
            // State sources may disappear later. Local verification/staging
            // always wins over transport retirement, and Busy/backoff is only
            // a temporary stall, never extinction.
            let snapshot_local_work = snapshot_header_staging_inflight.is_some()
                || history_step_verification_inflight.is_some()
                || snapshot_staging_inflight.is_some()
                || snapshot_install_inflight.is_some()
                || queued_segment_response.is_some()
                || finalized_snapshot_waiting.is_some();
            let snapshot_header_parked = snapshot_header_pipeline
                .as_ref()
                .is_some_and(SnapshotHeaderPipeline::is_parked_without_source);
            let snapshot_terminal_waiting = (retained_snapshot_headers.is_some()
                || pending_snapshot_header_sync.as_ref().is_some_and(|sync| {
                    sync.next_height == sync.target_height.saturating_add(1)
                }))
                && snapshot_boundary_terminal_inflight
                    .as_ref()
                    .is_none_or(|pending| !pending.requests.has_work())
                && history_step_verification_inflight.is_none();
            let snapshot_terminal_target = retained_snapshot_headers
                .as_ref()
                .map(|authority| {
                    (
                        authority.snapshot.boundary.height,
                        authority.snapshot.boundary.hash,
                    )
                })
                .or_else(|| {
                    pending_snapshot_header_sync.as_ref().and_then(|sync| {
                        (sync.next_height == sync.target_height.saturating_add(1))
                            .then_some((sync.manifest.tip_height, sync.manifest.tip_hash))
                    })
                });
            let snapshot_terminal_has_live_source =
                snapshot_terminal_target.is_some_and(|(height, block_hash)| {
                    manifest_peers.iter().any(|peer| {
                        !rejected_terminal_peers.contains(peer)
                            && !snapshot_terminal_exhausted.contains(
                                &SnapshotTerminalSourceKey {
                                    peer: *peer,
                                    height,
                                    block_hash,
                                },
                            )
                            && manifest_terminal_capabilities.get(peer).is_some_and(
                                |capability| capability.advertises(height, block_hash),
                            )
                    })
                });
            let snapshot_terminal_extinct =
                snapshot_terminal_waiting && !snapshot_terminal_has_live_source;
            let snapshot_state_stalled = active_snapshot_sync
                .as_ref()
                .is_some_and(|sync| sync.unfinished_transport_is_stalled(transport_now_ms));
            let snapshot_state_extinct = active_snapshot_sync
                .as_ref()
                .is_some_and(|sync| sync.unfinished_transport_is_extinct());
            let snapshot_pre_state_stalled = active_snapshot_sync.is_none()
                && snapshot_plan_active!()
                && !snapshot_local_work
                && (snapshot_header_parked || snapshot_terminal_waiting);
            let snapshot_pre_state_extinct = active_snapshot_sync.is_none()
                && snapshot_plan_active!()
                && !snapshot_local_work
                && (snapshot_header_parked || snapshot_terminal_extinct);
            let snapshot_transport_stalled = snapshot_state_stalled || snapshot_pre_state_stalled;

            if snapshot_transport_stalled
                && manifest_requested_peers.is_empty()
                && now.saturating_duration_since(last_snapshot_provider_probe)
                    >= Duration::from_secs(5)
            {
                if let Some((height, _)) = snapshot_terminal_target {
                    let mut excluded = rejected_terminal_peers.clone();
                    if let Some(pending) = snapshot_boundary_terminal_inflight.as_ref() {
                        excluded.extend(
                            manifest_peers
                                .iter()
                                .copied()
                                .filter(|peer| pending.requests.used_peer(*peer)),
                        );
                    }
                    let candidates = rotating_manifest_peers(
                        &locally_selected_peers,
                        &excluded,
                        None,
                        false,
                        &mut exact_inventory_probe_cursor,
                        EXACT_INVENTORY_PROBE_LANES.saturating_sub(1),
                    );
                    for peer in candidates {
                        let request_key = (peer, height, 1);
                        let recently_requested = recent_header_fetches
                            .get(&request_key)
                            .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL);
                        if !recently_requested {
                            let _ = try_dispatch_header_fetch(
                                &p2p_cmd,
                                &mut fetch_in_progress,
                                &mut recent_header_fetches,
                                peer,
                                height,
                                1,
                                now,
                            );
                        }
                    }
                }
                if let Some(original) = pending_manifest
                    .as_ref()
                    .map(|pending| pending.preferred_peer)
                {
                    let dispatched = request_snapshot_generation_providers!(original);
                    snapshot_provider_discovery_rounds = complete_snapshot_provider_discovery_round(
                        snapshot_provider_discovery_rounds,
                        dispatched,
                    );
                }
                last_snapshot_provider_probe = now;
            }

            let snapshot_extinction_confirmed = !snapshot_local_work
                && (snapshot_state_extinct || snapshot_pre_state_extinct)
                && manifest_requested_peers.is_empty()
                && snapshot_provider_discovery_rounds >= EXACT_PLAN_DISCOVERY_ROUNDS
                && snapshot_plan_last_progress.is_some_and(|last| {
                    now.saturating_duration_since(last) >= EXACT_PLAN_NO_PROGRESS_TIMEOUT
                });
            if snapshot_extinction_confirmed {
                let failed_peer = pending_manifest
                    .as_ref()
                    .map(|pending| pending.preferred_peer)
                    .or_else(|| manifest_peers.iter().copied().next());
                tracing::warn!(
                    generation = snapshot_sync_generation,
                    rounds = snapshot_provider_discovery_rounds,
                    "exact snapshot transport exhausted; selecting a fresh HeaderDAG-bound generation"
                );
                retire_snapshot_plan!();
                if let Some(failed_peer) = failed_peer {
                    request_bounded_manifest_failover!(failed_peer, false);
                }
            }

            if snapshot_rebase_hint.is_some_and(|hint| {
                now.duration_since(hint.armed_at) >= Duration::from_secs(600)
            }) && !snapshot_plan_active!()
                && snapshot_install_inflight.is_none()
            {
                let expired = snapshot_rebase_hint
                    .take()
                    .expect("expired snapshot rebase hint exists");
                tracing::warn!(
                    ancestor = expired.ancestor_height,
                    competing_tip = expired.competing_tip_height,
                    "snapshot rebase hint expired without an active authenticated candidate"
                );
            }

            if *initial_sync_ready.borrow() {
                let remaining = MAX_MEMPOOL_SYNC_PEERS
                    .saturating_sub(mempool_sync_requested_peers.len());
                let mut mempool_peers = locally_selected_peers
                    .iter()
                    .copied()
                    .filter(|peer| !mempool_sync_requested_peers.contains(peer))
                    .collect::<Vec<_>>();
                mempool_peers.sort_unstable_by_key(|peer| peer.to_bytes());
                mempool_peers.truncate(remaining);
                for peer in mempool_peers {
                    if p2p_cmd
                        .try_send(noid_p2p::NetworkCommand::RequestMempoolSync { peer })
                        .is_ok()
                    {
                        mempool_sync_requested_peers.insert(peer);
                    }
                }
            }

            // An announcement may arrive through a gossipsub forwarder that
            // does not yet hold its advertised body/proof. Enrich the same
            // immutable plan from storage-backed inventories of other peers.
            // This is a tiny header request, never a duplicate bulk download.
            let suffix_transport_stalled = active_suffix_sync
                .as_ref()
                .is_some_and(|sync| sync.unfinished_transport_is_stalled(transport_now_ms));
            let suffix_transport_extinct = active_suffix_sync
                .as_ref()
                .is_some_and(|sync| sync.unfinished_transport_is_extinct());
            if let Some(sync) = active_suffix_sync.as_ref() {
                if now.saturating_duration_since(last_exact_inventory_probe)
                    >= EXACT_INVENTORY_PROBE_INTERVAL
                {
                    let base = sync.plan().base();
                    let target = sync.plan().target();
                    let count = target
                        .height
                        .saturating_sub(base.height)
                        .saturating_add(1)
                        .min(512) as u16;
                    let excluded = rejected_suffix_object_peers.clone();
                    let candidates = rotating_manifest_peers(
                        &manifest_peers,
                        &excluded,
                        None,
                        false,
                        &mut exact_inventory_probe_cursor,
                        EXACT_INVENTORY_PROBE_LANES,
                    );
                    let mut dispatched = 0usize;
                    for peer in candidates {
                        let request_key = (peer, base.height, count);
                        let recently_requested = recent_header_fetches
                            .get(&request_key)
                            .is_some_and(|requested| {
                                requested.elapsed() < EXACT_INVENTORY_RETRY_TTL
                            });
                        if recently_requested {
                            continue;
                        }
                        if try_dispatch_header_fetch(
                            &p2p_cmd,
                            &mut fetch_in_progress,
                            &mut recent_header_fetches,
                            peer,
                            base.height,
                            count,
                            now,
                        ) {
                            suffix_inventory_probe_peers.insert(peer);
                            dispatched = dispatched.saturating_add(1);
                        }
                    }
                    if dispatched > 0 {
                        last_exact_inventory_probe = now;
                        if suffix_transport_extinct {
                            suffix_provider_discovery_rounds =
                                suffix_provider_discovery_rounds.saturating_add(1);
                        }
                    }
                }
            }
            // Drive retry/hedge timers even when no new inventory response is
            // needed.  In particular, an already known alternate terminal
            // provider must become usable after the four-second no-progress
            // threshold without waiting for an unrelated network event.
            if let Some(sync) = active_suffix_sync.as_mut() {
                dispatch_exact_suffix_requests(sync, &p2p_cmd);
            }

            // Header gossip can arrive through a peer which has not fetched
            // the separately transported body/terminal yet. Keep the
            // HeaderDAG-selected target fixed and poll a small rotating set of
            // storage providers until one advertises the exact objects. This
            // is the normal header-first bridge; waiting for the 30-second
            // stale-tip fallback made GUI miners spend most short intervals in
            // SYNCING TIP even though the selected header was already valid.
            let unresolved_header_waiting_for_inventory = active_suffix_sync.is_none()
                && exact_suffix_apply_inflight.is_none()
                && !snapshot_plan_active!()
                && !header_dag_faulted
                && header_dag_has_unresolved_better_tip(
                    &header_dag,
                    noid_node::networking::ChainPoint::new(our_height, our_hash),
                    our_work,
                );
            if unresolved_header_waiting_for_inventory
                && now.saturating_duration_since(last_exact_inventory_probe)
                    >= EXACT_INVENTORY_PROBE_INTERVAL
            {
                let target = header_dag.best_tip();
                let committed_tip = noid_node::networking::ChainPoint::new(our_height, our_hash);
                let (start_height, count) = match unresolved_selected_tip_probe_range(
                    &header_dag,
                    committed_tip,
                    CONNECTED_TIP_PROBE_HEADERS,
                ) {
                    Ok(range) => range,
                    Err(error) => {
                        header_dag_faulted = true;
                        tracing::error!(
                            target_height = target.height,
                            %error,
                            "HeaderDAG could not locate the selected tip's common ancestor"
                        );
                        continue;
                    }
                };
                let mut excluded = rejected_suffix_object_peers.clone();
                let mut candidates = rotating_manifest_peers(
                    &locally_selected_peers,
                    &excluded,
                    None,
                    false,
                    &mut exact_inventory_probe_cursor,
                    EXACT_INVENTORY_PROBE_LANES,
                );
                if candidates.len() < EXACT_INVENTORY_PROBE_LANES {
                    excluded.extend(candidates.iter().copied());
                    let remaining = EXACT_INVENTORY_PROBE_LANES - candidates.len();
                    candidates.extend(rotating_manifest_peers(
                        &manifest_peers,
                        &excluded,
                        None,
                        false,
                        &mut exact_inventory_probe_cursor,
                        remaining,
                    ));
                }

                let mut dispatched = 0usize;
                for peer in candidates {
                    let request_key = (peer, start_height, count);
                    let recently_requested = recent_header_fetches
                        .get(&request_key)
                        .is_some_and(|requested| {
                            requested.elapsed() < EXACT_INVENTORY_RETRY_TTL
                        });
                    if fetch_in_progress.contains(&peer) || recently_requested {
                        continue;
                    }
                    if try_dispatch_header_fetch(
                        &p2p_cmd,
                        &mut fetch_in_progress,
                        &mut recent_header_fetches,
                        peer,
                        start_height,
                        count,
                        now,
                    ) {
                        dispatched = dispatched.saturating_add(1);
                    }
                }
                if dispatched > 0 {
                    last_exact_inventory_probe = now;
                    tracing::debug!(
                        our_height,
                        target_height = target.height,
                        dispatched,
                        "HeaderDAG-selected tip is discovering exact object providers"
                    );
                }
            }

            let suffix_extinction_confirmed = suffix_transport_extinct
                && suffix_inventory_probe_peers.is_empty()
                && suffix_provider_discovery_rounds >= EXACT_PLAN_DISCOVERY_ROUNDS
                && suffix_plan_last_progress.is_some_and(|last| {
                    now.saturating_duration_since(last) >= EXACT_PLAN_NO_PROGRESS_TIMEOUT
                });
            if suffix_extinction_confirmed {
                let retired = active_suffix_sync
                    .take()
                    .expect("confirmed suffix extinction has an active plan");
                let retired_target = retired.plan().target();
                suffix_plan_last_progress = None;
                suffix_provider_discovery_rounds = 0;
                suffix_inventory_probe_peers.clear();
                tracing::warn!(
                    target_height = retired_target.height,
                    target_hash = %hex::encode(retired_target.hash),
                    "exact suffix transport exhausted; retaining HeaderDAG and rematerializing its selected tip"
                );

                // The selected header remains in the DAG and provider probes
                // continue, but no exact transport is currently viable. Mine
                // on the last committed valid parent until a new immutable
                // object plan can be materialized; a header alone must not be
                // a permanent remote pause switch.
                mining_peer_quorum.resolve_committed_view();

                let (start_height, count) = selected_tip_probe_range(
                    our_height,
                    header_dag.best_tip().height,
                    CONNECTED_TIP_PROBE_HEADERS,
                );
                let excluded = std::collections::HashSet::new();
                let candidates = rotating_manifest_peers(
                    &manifest_peers,
                    &excluded,
                    None,
                    false,
                    &mut exact_inventory_probe_cursor,
                    2,
                );
                for peer in candidates {
                    let _ = try_dispatch_header_fetch(
                        &p2p_cmd,
                        &mut fetch_in_progress,
                        &mut recent_header_fetches,
                        peer,
                        start_height,
                        count,
                        now,
                    );
                }
            } else if suffix_transport_stalled {
                tracing::trace!(
                    rounds = suffix_provider_discovery_rounds,
                    "exact suffix transport temporarily stalled; immutable plan retained"
                );
            }

            // Mining-authority refresh must not compete with canonical sync
            // for the bounded general-header request lanes. Connection-time
            // probes still bootstrap discovery; once a snapshot, suffix, or
            // reorg session is active, the readiness gate can safely remain
            // closed until that exact canonical transition has completed.
            let canonical_sync_idle = active_suffix_sync.is_none()
                && exact_suffix_apply_inflight.is_none()
                && best_manifest_candidate.is_none()
                && pending_manifest.is_none()
                && pending_snapshot_header_sync.is_none()
                && snapshot_header_pipeline.is_none()
                && snapshot_header_staging_inflight.is_none()
                && history_step_verification_inflight.is_none()
                && snapshot_boundary_terminal_inflight.is_none()
                && snapshot_staging.is_none()
                && snapshot_staging_inflight.is_none()
                && snapshot_install_inflight.is_none()
                && active_snapshot_sync
                    .as_ref()
                    .is_none_or(|sync| sync.all_segments_verified())
                && manifest_requested_peers.is_empty();

            // A node that caught up through one recursive tip terminal may
            // have compact markers at intermediate heights. Fetch exactly the
            // newest deterministic finalized boundary proof in the
            // background so the node can become a truthful snapshot provider
            // without waiting for another local production window.
            if *initial_sync_ready.borrow()
                && canonical_sync_idle
                && boundary_proof_maintenance_inflight.is_none()
                && boundary_proof_verification_inflight.is_none()
                && now.saturating_duration_since(last_boundary_proof_maintenance)
                    >= Duration::from_secs(5)
            {
                let missing = {
                    let ctx = chain.read().await;
                    missing_snapshot_boundary_proof(&ctx)
                };
                match missing {
                    Ok(Some(target)) => {
                        let preferred = manifest_peers
                            .iter()
                            .copied()
                            .filter(|peer| {
                                manifest_terminal_capabilities.get(peer).is_some_and(|capability| {
                                    capability.advertises(target.height(), target.block_hash())
                                })
                            })
                            .min_by_key(|peer| peer.to_bytes());
                        if let Some(preferred) = preferred {
                            if let Some(peer) = advertised_terminal_peer(
                                &manifest_peers,
                                &manifest_terminal_capabilities,
                                &rejected_terminal_peers,
                                &snapshot_terminal_exhausted,
                                &snapshot_terminal_retry_after,
                                preferred,
                                target.height(),
                                target.block_hash(),
                                now,
                            ) {
                                history_step_request_token =
                                    history_step_request_token.wrapping_add(1);
                                boundary_proof_maintenance_inflight =
                                    Some(BoundaryProofMaintenanceKey {
                                        target,
                                        requests: TerminalRequestRace::new(
                                            peer,
                                            history_step_request_token,
                                        ),
                                    });
                                dispatch_boundary_proof_maintenance_requests!();
                            }
                        }
                        last_boundary_proof_maintenance = now;
                    }
                    Ok(None) => {
                        last_boundary_proof_maintenance = now;
                    }
                    Err(error) => {
                        tracing::error!(%error, "cannot inspect deterministic snapshot-boundary proof availability");
                        return Err(anyhow::anyhow!(
                            "cannot inspect deterministic snapshot-boundary proof availability: {error}"
                        ));
                    }
                }
            }

            // Reacquire a lost quorum through at most two lanes, preferring
            // peers which have not confirmed the exact current tip. Once the
            // quorum is complete, the single rotating steady lane below keeps
            // confirmations fresh without redundant two-lane traffic.
            const MINING_QUORUM_TIP_PROBE_HEADERS: u16 = CONNECTED_TIP_PROBE_HEADERS;
            let waiting_for_quorum = mining_peer_quorum.waiting_for_quorum();
            if mining_quorum_probe_due(
                last_mining_quorum_probe,
                now,
                waiting_for_quorum,
                canonical_sync_idle,
            ) {
                let mut lane_capacity = MINING_PEER_QUORUM
                    .saturating_sub(fetch_in_progress.len().min(MINING_PEER_QUORUM));
                let mut dispatched = false;
                for peer in mining_peer_quorum.probe_candidates(usize::MAX) {
                    if lane_capacity == 0 {
                        break;
                    }
                    let request_key = (peer, our_height, MINING_QUORUM_TIP_PROBE_HEADERS);
                    let recently_requested = recent_header_fetches
                        .get(&request_key)
                        .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL);
                    if fetch_in_progress.contains(&peer) || recently_requested {
                        continue;
                    }
                    if try_dispatch_header_fetch(
                        &p2p_cmd,
                        &mut fetch_in_progress,
                        &mut recent_header_fetches,
                        peer,
                        our_height,
                        MINING_QUORUM_TIP_PROBE_HEADERS,
                        now,
                    ) {
                        mining_peer_quorum.mark_probe_sent(peer, now);
                        lane_capacity -= 1;
                        dispatched = true;
                    }
                }
                if dispatched {
                    last_mining_quorum_probe = now;
                }
            }

            if !waiting_for_quorum {
                if steady_tip_probe_due(
                    last_steady_tip_probe,
                    now,
                    false,
                    canonical_sync_idle,
                ) {
                    let excluded = std::collections::HashSet::new();
                    let candidates = rotating_manifest_peers(
                        &manifest_peers,
                        &excluded,
                        None,
                        false,
                        &mut steady_tip_probe_cursor,
                        1,
                    );
                    for peer in candidates {
                        let request_key = (peer, our_height, CONNECTED_TIP_PROBE_HEADERS);
                        let recently_requested = recent_header_fetches
                            .get(&request_key)
                            .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL);
                        if fetch_in_progress.contains(&peer) || recently_requested {
                            continue;
                        }
                        if try_dispatch_header_fetch(
                            &p2p_cmd,
                            &mut fetch_in_progress,
                            &mut recent_header_fetches,
                            peer,
                            our_height,
                            CONNECTED_TIP_PROBE_HEADERS,
                            now,
                        ) {
                            last_steady_tip_probe = now;
                            tracing::debug!(
                                peer = %peer,
                                our_height,
                                "steady authenticated tip probe dispatched"
                            );
                        }
                        break;
                    }
                }
            }

            if boundary_proof_maintenance_inflight
                .as_ref()
                .is_some_and(|pending| pending.requests.deadline_due(now))
            {
                let pending = boundary_proof_maintenance_inflight
                    .take()
                    .expect("expired proof maintenance race is present");
                let _ = p2p_cmd.try_send(
                    noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                        token: pending.requests.primary.token,
                    },
                );
                last_boundary_proof_maintenance = now;
                tracing::debug!(
                    height = pending.target.height(),
                    "snapshot-boundary proof maintenance timed out; canonical sync unchanged"
                );
            }

            let maintenance_hedge = boundary_proof_maintenance_inflight
                .as_ref()
                .filter(|pending| pending.requests.hedge_due(now))
                .and_then(|pending| {
                    advertised_terminal_alternate_peer(
                        &manifest_peers,
                        &manifest_terminal_capabilities,
                        &rejected_terminal_peers,
                        &snapshot_terminal_exhausted,
                        &snapshot_terminal_retry_after,
                        &pending.requests,
                        pending.target.height(),
                        pending.target.block_hash(),
                        now,
                    )
                });
            if let Some(alternate) = maintenance_hedge {
                boundary_proof_maintenance_inflight
                    .as_mut()
                    .expect("proof maintenance hedge remains active")
                    .requests
                    .install_hedge(alternate);
                dispatch_boundary_proof_maintenance_requests!();
            }

            if snapshot_boundary_terminal_inflight
                .as_ref()
                .is_some_and(|pending| pending.requests.deadline_due(now))
            {
                let pending = snapshot_boundary_terminal_inflight
                    .take()
                    .expect("expired boundary terminal race is present");
                let active_requests = pending.requests.active().collect::<Vec<_>>();
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                        token: pending.requests.primary.token,
                    })
                    .await;
                tracing::warn!(
                    last_source = %pending.requests.primary.peer,
                    height = pending.height,
                    "snapshot boundary terminal race expired; exact plan and staged headers retained"
                );
                for request in active_requests {
                    let key = SnapshotTerminalSourceKey {
                        peer: request.peer,
                        height: pending.height,
                        block_hash: pending.block_hash,
                    };
                    record_snapshot_terminal_transport_failure(
                        &mut snapshot_terminal_transport_failures,
                        key,
                    );
                    snapshot_terminal_retry_after
                        .insert(request.peer, now + Duration::from_secs(10));
                }
                request_snapshot_generation_providers!(pending.requests.primary.peer);
                continue;
            }


            // request-response starts its 60-second timeout only after an
            // outbound substream opens. A request waiting inside libp2p's
            // stream-capacity queue therefore needs this node-level hedge.
            // The alternate must advertise the exact immutable terminal, and
            // the first valid response closes the logical race.
            let boundary_terminal_hedge = snapshot_boundary_terminal_inflight
                .as_ref()
                .filter(|pending| pending.requests.hedge_due(now))
                .and_then(|pending| {
                    advertised_terminal_alternate_peer(
                        &manifest_peers,
                        &manifest_terminal_capabilities,
                        &rejected_terminal_peers,
                        &snapshot_terminal_exhausted,
                        &snapshot_terminal_retry_after,
                        &pending.requests,
                        pending.height,
                        pending.block_hash,
                        now,
                    )
                    .map(|alternate| {
                        (pending.requests.primary.peer, alternate, pending.height)
                    })
                });
            if let Some((primary, alternate, height)) = boundary_terminal_hedge
            {
                snapshot_boundary_terminal_inflight
                    .as_mut()
                    .expect("planned boundary terminal hedge is still active")
                    .requests
                    .install_hedge(alternate);
                dispatch_pending_boundary_terminal_requests!();
                tracing::warn!(
                    primary = %primary,
                    alternate = %alternate,
                    height,
                    "snapshot boundary terminal primary stalled; hedging exact request"
                );
            }


            // Some manifest request sites are event-driven and may begin a
            // round without explicitly arming its timer. Arm it here so every
            // outstanding round has the same bounded recovery path.
            if manifest_round_started_at.is_none()
                && !manifest_requested_peers.is_empty()
                && best_manifest_candidate.is_none()
                && pending_manifest.is_none()
                && pending_snapshot_header_sync.is_none()
                && snapshot_header_staging_inflight.is_none()
                && history_step_verification_inflight.is_none()
                && snapshot_staging_inflight.is_none()
                && snapshot_install_inflight.is_none()
                && active_snapshot_sync
                    .as_ref()
                    .is_none_or(|sync| sync.all_segments_verified())
            {
                manifest_round_started_at = Some(now);
            }

            // A manifest round with no usable candidate is dead air. This
            // includes dropped responses and explicit empty responses. Clear only the discovery
            // round and re-request from
            // a bounded peer set; with a single seed there is no second
            // PeerConnected event to save us.
            if manifest_round_retry_due(manifest_round_started_at, now)
                && best_manifest_candidate.is_none()
                && pending_manifest.is_none()
                && pending_snapshot_header_sync.is_none()
                && snapshot_header_staging_inflight.is_none()
                && history_step_verification_inflight.is_none()
                && snapshot_staging.is_none()
                && snapshot_staging_inflight.is_none()
                && snapshot_install_inflight.is_none()
                && active_snapshot_sync
                    .as_ref()
                    .is_none_or(|sync| sync.all_segments_verified())
            {
                let our_height = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };
                if manifest_round_gap_is_resolved(our_height, highest_announced) {
                    if *initial_sync_ready.borrow() {
                        clear_manifest_round_state!();
                        mark_bootstrap_complete_if_caught_up!(our_height);
                        tracing::debug!(
                            our_height,
                            highest_announced,
                            "announced gap closed; cancelled manifest retry"
                        );
                    } else {
                        clear_manifest_round_state!();
                        for peer in manifest_peers.iter().copied().collect::<Vec<_>>() {
                            request_exact_tip_confirmation!(peer, our_height);
                        }
                        let _ = manifest_round_started_at.get_or_insert(now);
                        tracing::debug!(
                            our_height,
                            "manifest round settled before tip authority; repeated authenticated tip probe"
                        );
                    }
                } else {
                    tracing::warn!(
                        peers = manifest_peers.len(),
                        responses = manifest_response_count,
                        "state manifest round produced no usable candidate — re-requesting"
                    );
                    clear_manifest_round_state!();
                    let excluded_peers = rejected_terminal_peers
                        .union(&finalized_divergent_peers)
                        .copied()
                        .collect::<std::collections::HashSet<_>>();
                    let retry_peers = rotating_manifest_peers(
                        &manifest_peers,
                        &excluded_peers,
                        None,
                        false,
                        &mut manifest_retry_cursor,
                        3,
                    );
                    for peer in retry_peers {
                        try_request_manifest!(peer, our_height, [0; 32]);
                    }
                    if !manifest_peers.is_empty() {
                        manifest_round_started_at = Some(now);
                    }
                }
            }

            // --- Stale-tip recovery ---
            // If our chain hasn't advanced in 30s but we've seen higher announcements,
            // re-request the missing blocks from the peer that announced highest.
            // This handles the case where all initial block requests failed (peer
            // didn't have the block yet, stream capacity hit, etc.) in large networks.
            let stale_secs = last_tip_advance.elapsed().as_secs();
            if stale_secs >= 30 {
                let our_height = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };
                let canonical_transition_active = active_suffix_sync.is_some()
                    || exact_suffix_apply_inflight.is_some()
                    || snapshot_plan_active!();
                if stale_gap_recovery_is_due(
                    stale_secs,
                    our_height,
                    highest_announced,
                    canonical_transition_active,
                ) {
                    if let Some(peer) = last_announcement_peer {
                        let gap = highest_announced - our_height;
                        let mut recovery_dispatched = false;
                        if sync_target_requires_snapshot(
                            our_height,
                            highest_announced,
                            post_snapshot_tail,
                        ) {
                            if pending_manifest.is_none()
                                && pending_snapshot_header_sync.is_none()
                                && snapshot_header_staging_inflight.is_none()
                                && history_step_verification_inflight.is_none()
                                && snapshot_staging_inflight.is_none()
                                && snapshot_install_inflight.is_none()
                                && active_snapshot_sync
                                    .as_ref()
                                    .is_none_or(|sync| sync.all_segments_verified())
                            {
                                if try_request_manifest!(peer, our_height, [0; 32]) {
                                    recovery_dispatched = true;
                                    manifest_force_snapshot_peers.insert(peer);
                                    tracing::info!(
                                        our_height,
                                        highest_announced,
                                        stale_secs,
                                        peer = %peer,
                                        "stale deep gap — requesting snapshot manifest"
                                    );
                                }
                            }
                        } else {
                            let count = (gap + 1).min(DIRECT_SYNC_HEADER_REQUEST_CAP) as u16;
                            recovery_dispatched = try_dispatch_header_fetch(
                                &p2p_cmd,
                                &mut fetch_in_progress,
                                &mut recent_header_fetches,
                                peer,
                                our_height,
                                count,
                                Instant::now(),
                            );
                            if recovery_dispatched {
                                tracing::info!(
                                    our_height,
                                    highest_announced,
                                    stale_secs,
                                    peer = %peer,
                                    "stale recent gap — re-requesting authenticated headers"
                                );
                            }
                        }
                        if recovery_dispatched {
                            last_tip_advance = Instant::now();
                        }
                    }
                }
            }

        }

        } // tokio::select!
    } // loop

    #[allow(unreachable_code)]
    Ok(())
}

fn cleanup_snapshot_staging_session_offthread(staging: SnapshotStagingSession) {
    tokio::task::spawn_blocking(move || drop(staging));
}

fn cleanup_snapshot_header_staging_offthread(staging: SnapshotHeaderStaging) {
    tokio::task::spawn_blocking(move || {
        let _ = staging.discard();
    });
}

fn cleanup_validated_snapshot_headers_offthread(headers: ValidatedSnapshotHeaderStaging) {
    tokio::task::spawn_blocking(move || {
        let _ = headers.discard();
    });
}

fn drop_verified_history_step(verified: VerifiedHistoryStepSnapshot) {
    let VerifiedHistoryStepSnapshot {
        headers,
        boundary,
        inbound_memory_permit,
        ..
    } = verified;
    drop(boundary);
    drop(inbound_memory_permit);
    tokio::task::spawn_blocking(move || {
        let _ = headers.discard();
    });
}

fn cleanup_finalized_snapshot_staging_offthread(staging: FinalizedSnapshotStaging) {
    tokio::task::spawn_blocking(move || drop(staging));
}

fn create_snapshot_staging_session(
    staging_root: &Path,
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
    header: noid_chain::BlockHeader,
) -> Result<SnapshotStagingSession, SnapshotSessionPrepareError> {
    if noid_chain::block_header::block_id(&header) != manifest.tip_hash
        || header.height != manifest.tip_height
        || header.state_root != manifest.state_root
        || header.log_slots != manifest.log_slots
        || header.active_slot_count != manifest.active_slot_count
        || header.alloc_counter != manifest.alloc_counter
    {
        return Err(SnapshotSessionPrepareError::CandidateRejected(
            "snapshot boundary header/manifest metadata mismatch".into(),
        ));
    }
    let metadata = AuthenticatedSnapshotMetadata::from_authenticated_header(
        header,
        manifest.tip_hash,
        manifest.eff_log,
    )
    .map_err(classify_snapshot_session_prepare_error)?;
    if manifest.segment_ids.len() != manifest.segment_roots.len()
        || manifest.segment_ids.len() != manifest.segment_lengths.len()
    {
        return Err(SnapshotSessionPrepareError::CandidateRejected(
            "snapshot manifest descriptor vectors are not parallel".into(),
        ));
    }
    let descriptors = manifest
        .segment_ids
        .iter()
        .copied()
        .zip(manifest.segment_roots.iter().copied())
        .zip(manifest.segment_lengths.iter().copied())
        .map(
            |((segment_id, segment_root), encoded_len)| SnapshotSegmentDescriptor {
                segment_id,
                segment_root,
                encoded_len,
            },
        )
        .collect();
    SnapshotStagingSession::new(staging_root, metadata, descriptors)
        .map_err(classify_snapshot_session_prepare_error)
}

fn dispatch_exact_snapshot_segments(
    sync: &mut noid_node::networking::snapshot_sync::SnapshotSync,
    p2p_cmd: &noid_p2p::NetworkCommandSender,
    _staging_active: bool,
    response_buffered: bool,
) {
    if response_buffered || sync.counts().in_flight > 0 {
        return;
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    for request in sync.schedule(now_ms, 1) {
        let command = noid_p2p::NetworkCommand::RequestStateSegment {
            peer: request.peer,
            segment_id: request.segment.segment_id,
            expected_tip_height: request.segment.snapshot.boundary.height,
            expected_tip_hash: request.segment.snapshot.boundary.hash,
            manifest_digest: request.segment.snapshot.manifest_digest,
        };
        if p2p_cmd.try_send(command).is_err() {
            let _ = sync.defer_request(request);
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Wallet block update
// ---------------------------------------------------------------------------

async fn rescan_wallet_from_chain(
    wallet: &SharedWallet,
    chain: &Arc<RwLock<MdbxChainContext>>,
    mempool: &AsyncMempool,
    reason: &'static str,
) -> Result<(), String> {
    let (active_index, next_index, owner) = {
        let guard = wallet
            .lock()
            .map_err(|_| "wallet state lock is poisoned".to_string())?;
        match guard.as_ref() {
            None => return Ok(()),
            Some(w) => (w.active_index, w.next_index, w.active_address().0),
        }
    };
    let (reserved_inputs, reserved_outputs) = mempool.reserved_slots().await;
    let ctx = chain.read().await;
    let snapshot = ctx
        .store
        .get_verified_utxos_by_owner(&owner)
        .map_err(|error| format!("verified owner reload failed: {error}"))?;
    let height = snapshot.height;
    let found = snapshot.utxos.len();
    let balance = snapshot
        .utxos
        .iter()
        .map(|utxo| utxo.amount)
        .fold(0u64, u64::saturating_add);
    {
        let mut guard = wallet
            .lock()
            .map_err(|_| "wallet state lock is poisoned".to_string())?;
        if let Some(w) = guard.as_mut() {
            w.commit_verified_activation(
                active_index,
                next_index,
                active_index,
                owner,
                snapshot,
                &reserved_inputs,
                &reserved_outputs,
            )
            .map_err(|error| format!("active address changed during reload: {error}"))?;
        }
    }
    drop(ctx);
    tracing::info!(
        height,
        active_index,
        utxos = found,
        balance,
        reason,
        "wallet active address reloaded"
    );
    Ok(())
}

/// Install exactly the authenticated snapshot boundary.
///
/// Catch-up beyond this point is deliberately not part of the snapshot
/// transaction. It is planned afterwards from HeaderDAG and uses the same
/// exact one-terminal suffix pipeline as ordinary live catch-up and reorgs.
#[allow(clippy::too_many_arguments)]
async fn apply_verified_snapshot_boundary(
    chain: &Arc<RwLock<MdbxChainContext>>,
    mempool: &AsyncMempool,
    wallet: &SharedWallet,
    manifest: noid_p2p::protocol::VerifiedStateManifest,
    staging: FinalizedSnapshotStaging,
    history_step: VerifiedHistoryStepSnapshot,
    wallet_operation_gate: &WalletOperationGate,
    external_mining_attempts: &ExternalMiningAttemptInvalidator,
) -> Result<AppliedVerifiedSnapshot, SnapshotInstallError> {
    if history_step.height != manifest.tip_height || history_step.block_hash != manifest.tip_hash {
        drop_verified_history_step(history_step);
        return Err(SnapshotInstallError::BeforeCommit(
            "HistoryStep authority does not match snapshot manifest".into(),
        ));
    }
    let snapshot_height = manifest.tip_height;
    let segment_count = staging.descriptors().len();
    let VerifiedHistoryStepSnapshot {
        boundary,
        mut headers,
        allow_nonfinal_rebase,
        inbound_memory_permit,
        ..
    } = history_step;

    let wallet_operation = wallet_operation_gate.lock().await;
    let install_chain = Arc::clone(chain);
    let result = tokio::task::spawn_blocking(move || {
        // Keep both linear capabilities alive until the atomic MDBX commit:
        // the verified recursive boundary and the finalized State staging.
        let inbound_memory_permit = inbound_memory_permit;
        let mut ctx = install_chain.blocking_write();
        if let Some(superseded) =
            superseded_snapshot_install(snapshot_height, ctx.tip_height(), ctx.tip_hash())
        {
            drop(ctx);
            drop(staging);
            drop(boundary);
            drop(inbound_memory_permit);
            if let Err(error) = headers.discard() {
                tracing::warn!(
                    err = %error,
                    "superseded snapshot header staging cleanup deferred"
                );
            }
            return Err(superseded);
        }
        let state_install_started = Instant::now();
        if let Err(error) = ctx.apply_staged_state_snapshot(
            &staging,
            &boundary,
            &mut headers,
            allow_nonfinal_rebase,
        ) {
            drop(ctx);
            let _ = headers.discard();
            return Err(SnapshotInstallError::BeforeCommit(format!(
                "apply authenticated state snapshot: {error:?}"
            )));
        }
        let state_install_elapsed = state_install_started.elapsed();
        let view = ChainView::from_mdbx(&ctx);
        let height = ctx.tip_height();
        drop(ctx);
        drop(staging);
        drop(boundary);
        drop(inbound_memory_permit);
        if let Err(error) = headers.discard() {
            tracing::warn!(err = %error, "committed snapshot header staging cleanup deferred");
        }
        Ok::<_, SnapshotInstallError>((height, view, state_install_elapsed))
    })
    .await
    .map_err(|error| {
        SnapshotInstallError::BeforeCommit(format!("snapshot install worker panicked: {error}"))
    })??;

    let (applied_height, view, state_install_elapsed) = result;
    let applied = AppliedVerifiedSnapshot {
        height: applied_height,
        block_hash: view.tip_hash,
        tail_blocks: 0,
        tail_bytes: 0,
        tail_apply_elapsed: std::time::Duration::ZERO,
        state_install_elapsed,
    };
    external_mining_attempts.invalidate_for_tip(applied_height, view.tip_hash);
    mempool.on_new_block(&[], applied_height, view).await;

    if let Err(error) = rescan_wallet_from_chain(wallet, chain, mempool, "snapshot sync").await {
        wallet::invalidate_active_cache(wallet);
        return Err(SnapshotInstallError::AfterCommit {
            applied,
            error: format!("snapshot applied but active-wallet reload failed: {error}"),
            terminal_rejected: false,
        });
    }

    tracing::info!(
        snapshot_height,
        applied_height,
        segments = segment_count,
        "snapshot boundary State installed"
    );
    drop(wallet_operation);
    Ok(applied)
}

/// Apply a newly confirmed block to the in-process wallet state.
///
/// Must be called after `apply_next_block` succeeds and before block pruning.
/// No-op if the wallet is not initialized.
fn update_wallet_for_block(wallet: &SharedWallet, block: &noid_chain::block::Block) {
    if let Err(error) = wallet::update_for_accepted_block(wallet, block) {
        tracing::error!(
            height = block.header.height,
            %error,
            "committed block but wallet update failed"
        );
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// HH:MM:SS timer for tracing (UTC, no new deps)
// ---------------------------------------------------------------------------

/// Compact UTC time formatter: `HH:MM:SS`.
/// Implements `tracing_subscriber::fmt::time::FormatTime` without the `time`
/// crate dep by reading `SystemTime` directly.
struct UtcHms;

impl tracing_subscriber::fmt::time::FormatTime for UtcHms {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let h = (secs / 3600) % 24;
        let m = (secs / 60) % 60;
        let s = secs % 60;
        write!(w, "{h:02}:{m:02}:{s:02}")
    }
}

// ---------------------------------------------------------------------------
// Startup banner
// ---------------------------------------------------------------------------

/// Print a startup banner after all components are initialised.
///
/// Professional, dense, information-rich. Everything an operator needs
/// at a glance without being verbose. Uses println! so it is always
/// visible regardless of --log level.
#[allow(clippy::too_many_arguments)]
fn print_startup_banner(
    net_kind: &str,
    genesis: bool,
    p2p_listen: &str,
    rpc_listen: &str,
    tip_height: u64,
    state_root: &[u8; 32],
    active_slots: u64,
    log_slots: u32,
    materialized_segs: usize,
    total_segs: usize,
    encoded_state_bytes: u64,
    block_reward_noid: f64,
    wallet_addr: Option<&str>,
    mining: bool,
    coinbase: Option<&str>,
    version: &str,
) {
    // ANSI helpers
    let is_tty =
        std::env::var("TERM").is_ok_and(|t| t != "dumb") && std::env::var("NO_COLOR").is_err();
    macro_rules! col {
        ($c:expr, $s:expr) => {
            if is_tty {
                format!("{}{}{}", $c, $s, "\x1b[0m")
            } else {
                $s.to_string()
            }
        };
    }
    let b = |s: &str| col!("\x1b[1m", s);
    let dim = |s: &str| col!("\x1b[2m", s);
    let ylw = |s: &str| col!("\x1b[33m", s);
    let cyn = |s: &str| col!("\x1b[36m", s);

    let w = 76usize;
    let line = if is_tty {
        format!("\x1b[2m{}\x1b[0m", "─".repeat(w))
    } else {
        "─".repeat(w)
    };

    // Row helper: left-pad key to 14 chars
    let row = |key: &str, val: &str| {
        println!("  {}  {}", cyn(&format!("{key:<13}")), val);
    };

    // Fill bar for state
    let capacity = 1u64.checked_shl(log_slots).unwrap_or(u64::MAX);
    let fill_pct = if capacity > 0 {
        active_slots as f64 / capacity as f64 * 100.0
    } else {
        0.0
    };
    let bar_w = 24usize;
    let filled = ((fill_pct / 100.0) * bar_w as f64).round() as usize;
    let trigger = ((0.75_f64) * bar_w as f64).round() as usize;
    let bar: String = (0..bar_w)
        .map(|i| {
            if i < filled {
                '\u{2588}'
            } else if i == trigger.min(bar_w - 1) {
                '|'
            } else {
                '\u{2591}'
            }
        })
        .collect();
    let effective_log = log_slots.min(noid_chain::fri_state::LOG_SEGMENT_SIZE as u32) as u8;
    let max_segment_bytes = noid_chain::storage::max_encoded_segment_len_for_eff_log(effective_log)
        .unwrap_or(usize::MAX) as u64;
    let max_bytes = (total_segs as u64).saturating_mul(max_segment_bytes);
    let hb = |n: u64| -> String {
        if n >= 1 << 30 {
            format!("{:.1}GB", n as f64 / (1 << 30) as f64)
        } else if n >= 1 << 20 {
            format!("{:.1}MB", n as f64 / (1 << 20) as f64)
        } else if n >= 1 << 10 {
            format!("{:.1}KB", n as f64 / (1 << 10) as f64)
        } else {
            format!("{n}B")
        }
    };

    println!();
    println!("{line}");
    // Title line: name + version + network
    let title = format!(
        "PARANOID  {}   {}",
        b(&format!("v{version}")),
        dim(&format!(
            "·  {net_kind}{}",
            if genesis { "  (genesis mode)" } else { "" }
        ))
    );
    println!("  {}", title);
    println!("{line}");

    // Network
    row(
        "p2p / rpc",
        &format!("{p2p_listen}   {}", dim(&format!("rpc  {rpc_listen}"))),
    );

    // Chain
    row(
        "chain",
        &format!(
            "h={}   state  {}",
            b(&tip_height.to_string()),
            dim(&hex::encode(state_root))
        ),
    );

    // State
    row(
        "state",
        &format!(
            "{}/{} slots  {:.2}%  [{}]  {} seg  {} encoded  {} domain max",
            active_slots,
            capacity,
            fill_pct,
            bar,
            dim(&format!("{}/{}", materialized_segs, total_segs)),
            dim(&hb(encoded_state_bytes)),
            dim(&hb(max_bytes))
        ),
    );

    // Wallet
    if let Some(addr) = wallet_addr {
        row("wallet", &b(addr));
    }

    // Mining
    if mining {
        let cb = coinbase.unwrap_or_else(|| wallet_addr.unwrap_or("(none)"));
        row(
            "mining",
            &format!(
                "{reward:.2} NOID/block   coinbase  {cb}",
                reward = block_reward_noid
            ),
        );
    } else {
        row("mining", &ylw("disabled"));
    }

    println!("{line}");
    println!();

    // If state is near expansion threshold, warn the operator
    if fill_pct >= 70.0 {
        println!(
            "  {} state is {fill_pct:.1}% full \u{2014} expansion requires 10/18 \
             hard-finalized headers at or above 75%",
            ylw("WARN")
        );
        println!();
    }
}

fn load_or_create_config(path: &Path, defaults: &NodeConfig) -> anyhow::Result<(NodeConfig, bool)> {
    let expanded = expand_tilde(path);
    match std::fs::read_to_string(&expanded) {
        Ok(text) => {
            let config = toml::from_str(&text)
                .with_context(|| format!("parse node config: {}", expanded.display()))?;
            Ok((config, false))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = expanded
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("create node config directory: {}", parent.display())
                })?;
            }

            let encoded =
                toml::to_string_pretty(defaults).context("serialize default node config")?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }

            match options.open(&expanded) {
                Ok(mut file) => {
                    let write_result = file
                        .write_all(encoded.as_bytes())
                        .and_then(|()| file.sync_all());
                    if let Err(error) = write_result {
                        drop(file);
                        let _ = std::fs::remove_file(&expanded);
                        return Err(error).with_context(|| {
                            format!("write default node config: {}", expanded.display())
                        });
                    }
                    Ok((defaults.clone(), true))
                }
                // Another node may have created the file after our initial
                // read. Never overwrite it; load and validate that file.
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let text = std::fs::read_to_string(&expanded).with_context(|| {
                        format!(
                            "read concurrently created node config: {}",
                            expanded.display()
                        )
                    })?;
                    let config = toml::from_str(&text)
                        .with_context(|| format!("parse node config: {}", expanded.display()))?;
                    Ok((config, false))
                }
                Err(error) => Err(error)
                    .with_context(|| format!("create node config: {}", expanded.display())),
            }
        }
        Err(error) => {
            Err(error).with_context(|| format!("read node config: {}", expanded.display()))
        }
    }
}

fn expand_tilde(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    let rest = if s == "~" {
        Some("")
    } else {
        s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\"))
    };
    let Some(rest) = rest else {
        return p.to_path_buf();
    };

    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .or_else(|| {
            let drive = std::env::var_os("HOMEDRIVE")?;
            let path = std::env::var_os("HOMEPATH")?;
            let mut home = PathBuf::from(drive);
            home.push(path);
            Some(home)
        });
    match home {
        Some(mut home) => {
            if !rest.is_empty() {
                home.push(rest);
            }
            home
        }
        None => p.to_path_buf(),
    }
}

/// Parse a miner/wallet address from canonical bech32m (`o1…`).
fn parse_address(s: &str) -> anyhow::Result<noid_poseidon2b::primitives::Address> {
    if s.is_empty() {
        return Ok(noid_poseidon2b::primitives::Address([0u8; 32]));
    }
    noid_poseidon2b::primitives::Address::parse(s)
        .map_err(|e| anyhow::anyhow!("invalid address: {e}"))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
