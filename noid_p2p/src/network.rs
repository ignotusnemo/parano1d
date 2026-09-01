// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `P2PNetwork` — the libp2p swarm event loop.
//!
//! Handles:
//! - GossipSub: receiving blocks and txs from peers, broadcasting our blocks/txs
//! - Request-Response: serving headers, accepted-block bundles, and HistoryStep terminals
//! - Identify: maintaining peer address books
//! - Ping: pruning stale connections

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::{
    dcutr, gossipsub, identify, kad, mdns, relay, request_response, swarm::SwarmEvent, Multiaddr,
    PeerId,
};
use rand::seq::SliceRandom;
use tokio::sync::{mpsc, OwnedSemaphorePermit, RwLock, Semaphore};

use noid_chain::consensus::wire_limits::{
    MAX_HISTORY_STEP_TERMINAL_BYTES, MAX_MEMPOOL_SYNC_BYTES, MAX_MEMPOOL_SYNC_TXS,
    MAX_SEGMENT_BYTES, MAX_TX_INTENT_BYTES_GLOBAL,
};
use noid_chain::storage::{
    encoded_segment_live_count_from_len, max_encoded_segment_len_for_eff_log, MdbxChainContext,
    MdbxStore,
};
use noid_chain::storage::{
    export_snapshot_boundary_generation, open_snapshot_generation, SnapshotGeneration,
};
use noid_chain::AcceptedBlockBundle;
use noid_mempool::AsyncMempool;

use crate::availability_codec::{AvailabilityRequest, AvailabilityResponse};
use crate::behaviour::{NodeBehaviour, NodeBehaviourEvent};
use crate::command_dispatch::{self, NetworkCommandReceiver, NetworkCommandSender};
use crate::event_dispatch::{self, RequiredEventReceiver, RequiredEventSender};
use crate::header_protocol::{HeaderAnnouncement, HeaderInventoryRecord, ProviderFlags};
use crate::network_profile::{NetworkProfile, NetworkProfileRequest, NetworkProfileResponse};
use crate::object_protocol::{
    DataResponseStatus, GetObjectsRequest, GetObjectsResponse, ObjectId, ObjectPayload,
    MAX_BUSY_RETRY_MS, MIN_BUSY_RETRY_MS,
};
use crate::outbound_budget::OutboundResponseBudget;
use crate::peer_diversity::{PeerDiversity, PublicNetworkGroup};
use crate::protocol::{
    GetHeadersResponse, GetHistoryStepTerminalResponse, GetMempoolResponse,
    GetSnapshotManifestPageResponse, GetStateManifestHeader, GetStateManifestResponse,
    GetStateSegmentRequest, GetStateSegmentResponse, MempoolRequest, NetworkTopics,
    SnapshotManifestPageObjectId, VerifiedStateManifest,
};
use crate::resource_profile::BackgroundCapacity;

struct PendingStateSegmentResponse {
    peer: PeerId,
    snapshot_lease: Option<(SnapshotExportKey, [u8; 32])>,
    channel: request_response::ResponseChannel<GetStateSegmentResponse>,
    response: GetStateSegmentResponse,
}

struct PendingHeaderResponse {
    channel: request_response::ResponseChannel<GetHeadersResponse>,
    response: GetHeadersResponse,
}

struct PendingHistoryStepTerminalResponse {
    peer: PeerId,
    snapshot_lease_key: Option<SnapshotExportKey>,
    channel: request_response::ResponseChannel<GetHistoryStepTerminalResponse>,
    response: GetHistoryStepTerminalResponse,
}

struct PendingMempoolResponse {
    channel: request_response::ResponseChannel<GetMempoolResponse>,
    response: GetMempoolResponse,
}

struct PendingObjectResponse {
    channel: request_response::ResponseChannel<GetObjectsResponse>,
    response: GetObjectsResponse,
}

struct PendingManifestPageResponse {
    peer: PeerId,
    snapshot_lease: Option<(SnapshotExportKey, [u8; 32])>,
    channel: request_response::ResponseChannel<GetSnapshotManifestPageResponse>,
    response: GetSnapshotManifestPageResponse,
}

/// Fair admission shared by proof, body and State serving. Header/profile
/// traffic deliberately bypasses it, so bulk clients cannot occupy the
/// control plane. One peer may hold at most two of eight active data slots.
struct DataPlaneServingAdmission {
    global_slots: usize,
    metadata_slots: usize,
    #[cfg(test)]
    state_slots: usize,
    #[cfg(test)]
    state_outstanding_slots: usize,
    #[cfg(test)]
    live_slots: usize,
    #[cfg(test)]
    live_outstanding_slots: usize,
    global_outstanding_slots: usize,
    metadata_outstanding_slots: usize,
    per_peer_slots: usize,
    per_peer_outstanding_slots: usize,
    global: Arc<Semaphore>,
    metadata_global: Arc<Semaphore>,
    state: Arc<Semaphore>,
    live: Arc<Semaphore>,
    metadata: Arc<Semaphore>,
    state_outstanding: Arc<Semaphore>,
    live_outstanding: Arc<Semaphore>,
    global_outstanding: Arc<Semaphore>,
    metadata_outstanding: Arc<Semaphore>,
    metadata_class_outstanding: Arc<Semaphore>,
    peers: std::collections::HashMap<PeerId, Arc<PeerDataPlaneSlots>>,
}

struct PeerDataPlaneSlots {
    active: Arc<Semaphore>,
    outstanding: Arc<Semaphore>,
    metadata_active: Arc<Semaphore>,
    metadata_outstanding: Arc<Semaphore>,
}

struct DataPlaneServingLease {
    global: Arc<Semaphore>,
    class: Arc<Semaphore>,
    peer_active: Arc<Semaphore>,
    outstanding: Vec<OwnedSemaphorePermit>,
}

impl DataPlaneServingLease {
    async fn acquire(self) -> Result<Vec<OwnedSemaphorePermit>, ()> {
        let class = self.class.acquire_owned().await.map_err(|_| ())?;
        // Take the per-peer slot first. At most two requests from one identity
        // can therefore enter the global FIFO, even if that peer fills every
        // request-response stream on every bulk protocol.
        let peer = self.peer_active.acquire_owned().await.map_err(|_| ())?;
        let global = self.global.acquire_owned().await.map_err(|_| ())?;
        let mut permits = self.outstanding;
        permits.push(class);
        permits.push(peer);
        permits.push(global);
        Ok(permits)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DataPlaneClass {
    Live,
    State,
    StateMetadata,
}

impl DataPlaneServingAdmission {
    fn new(background_capacity: BackgroundCapacity) -> Self {
        let global_slots = background_capacity.global_data_slots();
        let metadata_slots = background_capacity.state_metadata_slots();
        let state_slots = background_capacity.state_data_slots();
        let state_outstanding_slots = background_capacity.state_data_outstanding();
        let global_outstanding_slots = background_capacity.global_data_outstanding();
        let metadata_outstanding_slots = background_capacity.state_metadata_outstanding();
        let live_slots = global_slots.saturating_sub(state_slots);
        let live_outstanding_slots = background_capacity.live_data_outstanding();
        let per_peer_slots = background_capacity.per_peer_data_slots();
        let per_peer_outstanding_slots = background_capacity.per_peer_data_outstanding();
        assert!(state_slots > 0 && live_slots > 0);
        assert!(state_outstanding_slots > 0 && live_outstanding_slots > 0);
        Self {
            global_slots,
            metadata_slots,
            #[cfg(test)]
            state_slots,
            #[cfg(test)]
            state_outstanding_slots,
            #[cfg(test)]
            live_slots,
            #[cfg(test)]
            live_outstanding_slots,
            global_outstanding_slots,
            metadata_outstanding_slots,
            per_peer_slots,
            per_peer_outstanding_slots,
            global: Arc::new(Semaphore::new(global_slots)),
            metadata_global: Arc::new(Semaphore::new(metadata_slots)),
            state: Arc::new(Semaphore::new(state_slots)),
            live: Arc::new(Semaphore::new(live_slots)),
            metadata: Arc::new(Semaphore::new(metadata_slots)),
            state_outstanding: Arc::new(Semaphore::new(state_outstanding_slots)),
            live_outstanding: Arc::new(Semaphore::new(live_outstanding_slots)),
            global_outstanding: Arc::new(Semaphore::new(global_outstanding_slots)),
            metadata_outstanding: Arc::new(Semaphore::new(metadata_outstanding_slots)),
            metadata_class_outstanding: Arc::new(Semaphore::new(metadata_outstanding_slots)),
            peers: std::collections::HashMap::new(),
        }
    }

    fn lease(&mut self, peer: PeerId, class: DataPlaneClass) -> Option<DataPlaneServingLease> {
        let per_peer_slots = self.per_peer_slots;
        let per_peer_outstanding_slots = self.per_peer_outstanding_slots;
        let peer_slots = self
            .peers
            .entry(peer)
            .or_insert_with(|| {
                Arc::new(PeerDataPlaneSlots {
                    active: Arc::new(Semaphore::new(per_peer_slots)),
                    outstanding: Arc::new(Semaphore::new(per_peer_outstanding_slots)),
                    metadata_active: Arc::new(Semaphore::new(1)),
                    metadata_outstanding: Arc::new(Semaphore::new(2)),
                })
            })
            .clone();
        let (
            global_active,
            global_outstanding,
            class_active,
            class_outstanding,
            peer_active,
            peer_outstanding,
        ) = match class {
            DataPlaneClass::Live => (
                Arc::clone(&self.global),
                Arc::clone(&self.global_outstanding)
                    .try_acquire_owned()
                    .ok()?,
                Arc::clone(&self.live),
                Arc::clone(&self.live_outstanding)
                    .try_acquire_owned()
                    .ok()?,
                Arc::clone(&peer_slots.active),
                Arc::clone(&peer_slots.outstanding)
                    .try_acquire_owned()
                    .ok()?,
            ),
            DataPlaneClass::State => (
                Arc::clone(&self.global),
                Arc::clone(&self.global_outstanding)
                    .try_acquire_owned()
                    .ok()?,
                Arc::clone(&self.state),
                Arc::clone(&self.state_outstanding)
                    .try_acquire_owned()
                    .ok()?,
                Arc::clone(&peer_slots.active),
                Arc::clone(&peer_slots.outstanding)
                    .try_acquire_owned()
                    .ok()?,
            ),
            DataPlaneClass::StateMetadata => (
                Arc::clone(&self.metadata_global),
                Arc::clone(&self.metadata_outstanding)
                    .try_acquire_owned()
                    .ok()?,
                Arc::clone(&self.metadata),
                Arc::clone(&self.metadata_class_outstanding)
                    .try_acquire_owned()
                    .ok()?,
                Arc::clone(&peer_slots.metadata_active),
                Arc::clone(&peer_slots.metadata_outstanding)
                    .try_acquire_owned()
                    .ok()?,
            ),
        };
        Some(DataPlaneServingLease {
            global: global_active,
            class: class_active,
            peer_active,
            outstanding: vec![class_outstanding, peer_outstanding, global_outstanding],
        })
    }

    fn prune(&mut self, connected: impl Fn(&PeerId) -> bool) {
        self.peers
            .retain(|peer, slots| connected(peer) || Arc::strong_count(slots) > 1);
    }

    fn active_slots(&self) -> usize {
        self.global_slots
            .saturating_sub(self.global.available_permits())
            .saturating_add(
                self.metadata_slots
                    .saturating_sub(self.metadata_global.available_permits()),
            )
    }

    fn outstanding_slots(&self) -> usize {
        self.global_outstanding_slots
            .saturating_sub(self.global_outstanding.available_permits())
            .saturating_add(
                self.metadata_outstanding_slots
                    .saturating_sub(self.metadata_outstanding.available_permits()),
            )
    }
}

#[derive(Clone, Copy, Debug)]
struct PendingNetworkProfileRequest {
    peer: PeerId,
    issued_at: Instant,
}

#[derive(Clone, Debug)]
struct PendingObjectRequest {
    token: u64,
    peer: PeerId,
    objects: Vec<ObjectId>,
    issued_at: Instant,
}

/// Admit the maximum legal response before invoking the payload loader.
/// Keeping this boundary in one helper makes it impossible for a serving path
/// to accidentally move mempool cloning ahead of process-wide byte admission.
async fn prepare_mempool_response_after_admission<Load, Loaded>(
    budget: OutboundResponseBudget,
    load: Load,
) -> std::io::Result<GetMempoolResponse>
where
    Load: FnOnce() -> Loaded,
    Loaded: std::future::Future<Output = Vec<Vec<u8>>>,
{
    let outbound_memory_permit =
        budget
            .acquire(MAX_MEMPOOL_SYNC_BYTES)
            .await?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "non-empty mempool reservation returned no permit",
                )
            })?;
    let txs = load().await;
    Ok(GetMempoolResponse {
        txs,
        inbound_memory_permit: None,
        outbound_memory_permit: Some(outbound_memory_permit),
    })
}

type SnapshotExportKey = (u64, [u8; 32]);
struct SnapshotExportEntry {
    generation: SnapshotGeneration,
    network_manifest: VerifiedStateManifest,
    manifest_header: Arc<GetStateManifestHeader>,
    manifest_pages: Vec<Arc<[u8]>>,
    /// Fresh clients may join this immutable cohort only during this fixed
    /// window.  The generation itself remains protected for the complete
    /// size-derived transfer budget below.
    join_deadline: Instant,
    available_until: Instant,
}

impl SnapshotExportEntry {
    fn new(generation: SnapshotGeneration) -> Option<Self> {
        let manifest = generation.manifest();
        if manifest.bridge_tip_height != manifest.target_height
            || manifest.bridge_tip_hash != manifest.target_hash
            || manifest.bridge_cumulative_chainwork != manifest.cumulative_chainwork
        {
            return None;
        }
        let network_manifest = GetStateManifestResponse {
            tip_height: manifest.target_height,
            tip_hash: manifest.target_hash,
            cumulative_chainwork: manifest.cumulative_chainwork,
            format_version: crate::protocol::SNAPSHOT_MANIFEST_FORMAT_VERSION,
            state_root: manifest.state_root,
            manifest_digest: [0; 32],
            log_slots: manifest.log_slots,
            active_slot_count: manifest.active_slot_count,
            alloc_counter: manifest.alloc_counter,
            eff_log: manifest.effective_log_segment_size,
            bridge_tip_height: manifest.bridge_tip_height,
            bridge_tip_hash: manifest.bridge_tip_hash,
            bridge_cumulative_chainwork: manifest.bridge_cumulative_chainwork,
            segment_ids: manifest
                .segments
                .iter()
                .map(|segment| segment.segment_id)
                .collect(),
            segment_roots: manifest
                .segments
                .iter()
                .map(|segment| segment.segment_root)
                .collect(),
            segment_lengths: manifest
                .segments
                .iter()
                .map(|segment| segment.encoded_len)
                .collect(),
        };
        let (network_manifest, manifest_header, manifest_pages) =
            VerifiedStateManifest::prepare_local(network_manifest)?;
        let now = Instant::now();
        let join_deadline = now
            .checked_add(SNAPSHOT_EXPORT_LEASE_SETUP_ALLOWANCE)
            .expect("snapshot join window must fit Instant");
        let available_until = join_deadline
            .checked_add(snapshot_export_transfer_allowance(&network_manifest))
            .expect("bounded snapshot transfer allowance must fit Instant");
        Some(Self {
            generation,
            network_manifest,
            manifest_header: Arc::new(manifest_header),
            manifest_pages,
            join_deadline,
            available_until,
        })
    }
}

impl std::ops::Deref for SnapshotExportEntry {
    type Target = SnapshotGeneration;

    fn deref(&self) -> &Self::Target {
        &self.generation
    }
}

type SnapshotExport = Arc<SnapshotExportEntry>;

enum PreparedSnapshotExport {
    Ready(SnapshotExportEntry),
    GenerationError(noid_chain::storage::SnapshotGenerationError),
    InvalidManifest,
}

const MAX_CACHED_SNAPSHOT_EXPORTS: usize = 2;
const MAX_ACTIVE_SNAPSHOT_EXPORT_GENERATIONS: usize = 4;
const SNAPSHOT_EXPORT_LEASE_TTL: Duration = Duration::from_secs(15 * 60);
/// Fixed setup budget before the size-dependent transfer allowance.  The
/// absolute deadline is computed once when the immutable generation is
/// leased; repeated requests can never extend it.
const SNAPSHOT_EXPORT_LEASE_SETUP_ALLOWANCE: Duration = Duration::from_secs(30 * 60);
/// A generation remains protected long enough for a client making steady
/// progress at this deliberately conservative throughput.  This is a serving
/// policy, not a consensus parameter.
const SNAPSHOT_EXPORT_MIN_SUPPORTED_BYTES_PER_SECOND: u64 = 256 * 1024;
/// Account for request scheduling, disk reads and verification between exact
/// State objects.  Large sparse States may legitimately contain many small
/// segments, for which a byte-only deadline would be too short.
const SNAPSHOT_EXPORT_PER_SEGMENT_ALLOWANCE: Duration = Duration::from_secs(2);
/// All honest exporters use the same finalized height buckets. Their cached
/// manifests therefore have a source-independent identity and a client can
/// rotate individual State objects across peers. Six blocks add at most five
/// blocks to the ordinary 18-block finalized lag and remain inside undo and
/// retained-payload windows.
/// Keep six blocks of serving reserve beyond the largest suffix admitted from
/// a cached immutable State boundary. The current retention policy preserves
/// 42 exact bodies, so a fresh finalized boundary starts 18 blocks behind the
/// live tip and remains useful without racing the payload pruner.
const SNAPSHOT_BOUNDARY_MAX_LIVE_GAP: u64 =
    noid_chain::consensus::params::RETAINED_BLOCK_SERVING_DEPTH - 6;
const MAX_OUTBOUND_HISTORY_STEP_RESPONSE_BYTES: usize = MAX_HISTORY_STEP_TERMINAL_BYTES;
const MAX_PENDING_NETWORK_PROFILE_REQUESTS: usize = 256;
const MAX_PENDING_OBJECT_REQUESTS: usize = 64;
const MAX_PENDING_HEADER_REQUESTS: usize = 64;
const MAX_PENDING_STATE_MANIFEST_REQUESTS: usize = 16;
const MAX_PENDING_STATE_SEGMENT_REQUESTS: usize = 64;
const MAX_PENDING_HISTORY_STEP_REQUESTS: usize = 8;
/// The request-response transport timeout starts only after substream open.
/// These complete-local deadlines also cover time queued before that point.
const SMALL_SYNC_PENDING_DEADLINE: Duration = Duration::from_secs(35);
const NETWORK_PROFILE_PENDING_DEADLINE: Duration = Duration::from_secs(15);
const OBJECT_PENDING_DEADLINE: Duration = Duration::from_secs(65);
const STATE_SEGMENT_PENDING_DEADLINE: Duration = Duration::from_secs(65);
/// libp2p starts its request timeout only after an outbound substream opens.
/// Bound the complete local lifetime as well, including time spent waiting in
/// the stream-capacity queue.
const HISTORY_STEP_PENDING_DEADLINE: Duration = Duration::from_secs(65);
/// In a small network, direct-push to every connected peer so an edge wallet
/// cannot depend on an already-formed gossipsub mesh to reach the miner.
const TX_DIRECT_SMALL_NETWORK_MAX_PEERS: usize = 8;
/// At scale gossipsub remains primary, while a constant direct fanout gives
/// every newly admitted transaction independent first-hop paths without
/// flooding all connections.
const TX_DIRECT_LARGE_NETWORK_FANOUT: usize = 4;
const TX_RELAY_RATE_WINDOW: Duration = Duration::from_secs(10);
const TX_RELAY_RATE_MAX: u32 = 50;
/// Raw GossipSub payloads accepted for propagation in one fixed window.
/// GossipSub retains accepted messages for several heartbeats. Bounding bytes
/// globally, in addition to the per-peer event count, prevents a Sybil set of
/// individually compliant peers from filling that cache with proof-sized
/// competing blocks. 64 MiB per ten seconds is orders of magnitude above the
/// honest 20-second block and bounded transaction workload.
const GOSSIP_ACCEPT_WINDOW: Duration = Duration::from_secs(10);
const GOSSIP_ACCEPT_BYTES_PER_WINDOW: usize = 64 * 1024 * 1024;
// Maintain an eight-neighbour ordinary topology, with at least half selected
// outbound by this node. This leaves ample socket headroom for inbound service
// and relay upgrades. The former target of twelve amplified Kademlia/circuit
// retries in a tiny NAT-heavy network; four was too sparse for independent
// object sources and GUI-to-GUI growth.
const AUTOMATIC_OUTBOUND_TARGET: usize = 8;
// Inbound and behaviour-owned transports are useful bidirectional mesh
// neighbours, but allowing them to satisfy the complete target lets a small
// inbound set stop independent peer discovery. Credit at most half of the
// target to such paths; every node therefore maintains at least four ordinary
// neighbours selected by its own bounded discovery manager.
const MAX_UNSELECTED_TOPOLOGY_CREDIT: usize = AUTOMATIC_OUTBOUND_TARGET / 2;
// The shipped topology contains four individual DNS seeds. Probe all of them
// when necessary, but leave room in the global pending table for ordinary
// peers learned through Kademlia.
const MAX_PENDING_BOOTSTRAP_DIALS: usize = 4;
const MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS: usize =
    AUTOMATIC_OUTBOUND_TARGET + MAX_PENDING_BOOTSTRAP_DIALS + 1;
// Eight peers may legitimately use two relay/direct paths each. Keep another
// eight bounded slots for bootstrap overlap and DCUtR while staying well below
// the swarm's 64 established-outbound ceiling.
const MAX_AUTOMATIC_TRANSPORT_OCCUPANCY: usize = 24;
// The swarm itself admits at most 32 pending outbound transports.
const _: () = assert!(MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS <= 32);
// Most GUI nodes discovered through Kademlia are not publicly dialable through
// their NAT. Keep two bootstrap transports until stable ordinary peers replace
// them one-for-one. This preserves independent recovery paths without pinning
// clients to every public seed.
const INITIAL_BOOTSTRAP_FANOUT: usize = 2;
const MAX_AUTOMATIC_PEER_CANDIDATES: usize = 512;
const MAX_AUTOMATIC_ADDRS_PER_PEER: usize = 8;
const AUTOMATIC_PEER_HEALTHY_AFTER: Duration = Duration::from_secs(30);
// A failed ordinary dial must not immediately launch another iterative DHT
// walk. One such walk can itself touch dozens of relayed candidates, so a
// short feedback loop amplifies a full relay into thousands of circuit
// attempts. Initial bootstrap remains immediate; recovery discovery is paced.
const DISCOVERY_RETRY_MIN: Duration = Duration::from_secs(30);
const DISCOVERY_RETRY_MAX: Duration = Duration::from_secs(5 * 60);
// A failed relay circuit is a property of one relay/destination route, not of
// either peer globally. Keep direct and alternative-relay paths eligible while
// spacing retries of only the route that just failed.
const MAX_RELAY_CIRCUIT_BACKOFFS: usize = 1024;
const RELAY_CIRCUIT_RETRY_FIRST: Duration = Duration::from_secs(30);
const RELAY_CIRCUIT_RETRY_SECOND: Duration = Duration::from_secs(60);
const RELAY_CIRCUIT_RETRY_MAX: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct RelayCircuitRoute {
    relay: PeerId,
    destination: PeerId,
}

#[derive(Clone, Debug)]
struct RelayCircuitBackoffEntry {
    addr: Multiaddr,
    failures: u8,
    retry_at: Instant,
    suppressed: bool,
    last_failure: Instant,
}

#[derive(Default)]
struct RelayCircuitBackoff {
    entries: std::collections::HashMap<RelayCircuitRoute, RelayCircuitBackoffEntry>,
}

impl RelayCircuitBackoff {
    fn retry_delay(failures: u8) -> Duration {
        match failures {
            0 | 1 => RELAY_CIRCUIT_RETRY_FIRST,
            2 => RELAY_CIRCUIT_RETRY_SECOND,
            _ => RELAY_CIRCUIT_RETRY_MAX,
        }
    }

    fn note_failure(
        &mut self,
        destination: PeerId,
        addr: &Multiaddr,
        now: Instant,
    ) -> Option<(RelayCircuitRoute, Multiaddr, u8, Duration)> {
        let (route, normalized_addr) = relay_circuit_route(destination, addr)?;
        if !self.entries.contains_key(&route) && self.entries.len() >= MAX_RELAY_CIRCUIT_BACKOFFS {
            if let Some(oldest) = self
                .entries
                .iter()
                .filter(|(_, entry)| !entry.suppressed)
                .min_by_key(|(_, entry)| entry.last_failure)
                .map(|(route, _)| *route)
            {
                self.entries.remove(&oldest);
            } else {
                // Never forget an address while it is removed from discovery:
                // doing so would make a memory cap turn into a permanent
                // reachability loss. At the hard cap, leave this new route
                // untouched instead of tracking it incompletely.
                return None;
            }
        }
        let entry = self
            .entries
            .entry(route)
            .or_insert(RelayCircuitBackoffEntry {
                addr: normalized_addr.clone(),
                failures: 0,
                retry_at: now,
                suppressed: false,
                last_failure: now,
            });
        entry.addr = normalized_addr.clone();
        entry.failures = entry.failures.saturating_add(1);
        let delay = Self::retry_delay(entry.failures);
        entry.retry_at = now + delay;
        entry.suppressed = true;
        entry.last_failure = now;
        Some((route, normalized_addr, entry.failures, delay))
    }

    fn is_blocked(&self, destination: PeerId, addr: &Multiaddr, now: Instant) -> bool {
        let Some((route, _)) = relay_circuit_route(destination, addr) else {
            return false;
        };
        self.entries
            .get(&route)
            .is_some_and(|entry| entry.suppressed && entry.retry_at > now)
    }

    fn take_due(&mut self, now: Instant) -> Vec<(RelayCircuitRoute, Multiaddr)> {
        self.entries
            .iter_mut()
            .filter_map(|(route, entry)| {
                (entry.suppressed && entry.retry_at <= now).then(|| {
                    entry.suppressed = false;
                    (*route, entry.addr.clone())
                })
            })
            .collect()
    }

    fn note_success(&mut self, destination: PeerId, addr: &Multiaddr) -> bool {
        let Some((route, _)) = relay_circuit_route(destination, addr) else {
            return false;
        };
        self.entries.remove(&route).is_some()
    }
}

/// Return the exact relay/destination identity and the address form stored by
/// Kademlia/automatic discovery (without a duplicate trailing destination).
fn relay_circuit_route(
    destination: PeerId,
    addr: &Multiaddr,
) -> Option<(RelayCircuitRoute, Multiaddr)> {
    use libp2p::multiaddr::Protocol;

    let mut relay = None;
    let mut after_circuit = false;
    let mut advertised_destination = None;
    for protocol in addr.iter() {
        match protocol {
            Protocol::P2p(peer) if !after_circuit => relay = Some(peer),
            Protocol::P2pCircuit => after_circuit = true,
            Protocol::P2p(peer) if after_circuit => advertised_destination = Some(peer),
            _ => {}
        }
    }
    if !after_circuit || advertised_destination.is_some_and(|peer| peer != destination) {
        return None;
    }
    let normalized_addr = sanitize_automatic_peer_addr(destination, addr.clone())?;
    Some((
        RelayCircuitRoute {
            relay: relay?,
            destination,
        },
        normalized_addr,
    ))
}

/// Prefer a peer's direct transport without discarding its relay fallback.
/// After a failed attempt, put that exact address last once so the fallback is
/// actually tried. The caller randomizes first, preserving load distribution
/// inside each remaining group.
fn prioritize_peer_addresses(
    destination: PeerId,
    attempted: &[Multiaddr],
    addrs: &mut [Multiaddr],
) {
    addrs.sort_by_key(|addr| {
        (
            attempted.contains(addr),
            relay_circuit_route(destination, addr).is_some(),
        )
    });
}

fn direct_tx_relay_limit(connected_peers: usize) -> usize {
    if connected_peers <= TX_DIRECT_SMALL_NETWORK_MAX_PEERS {
        connected_peers
    } else {
        connected_peers.min(TX_DIRECT_LARGE_NETWORK_FANOUT)
    }
}

#[derive(Clone, Debug)]
struct BootstrapCandidate {
    peer: Option<PeerId>,
    failures: u8,
    next_attempt: Instant,
}

#[derive(Clone, Debug)]
struct AutomaticPeerCandidate {
    addrs: Vec<Multiaddr>,
    failures: u8,
    next_attempt: Instant,
    last_seen: Instant,
    /// Transports already tried in the current bounded address round. They
    /// remain cached and become eligible again after every address was tried.
    attempted_addrs: Vec<Multiaddr>,
}

#[derive(Clone, Copy, Debug)]
struct SyncPath {
    peer: PeerId,
    direct: bool,
    dialer: bool,
    identified: bool,
    availability_capable: bool,
    profile_handshake_started: bool,
    closing: bool,
}

/// Mirrors every connection visible to request-response and exposes only
/// peers for which arbitrary per-peer connection selection is safe.
///
/// libp2p request-response distributes requests across every established
/// connection for one PeerId. A second direct connection must therefore be
/// collapsed before the node issues another sync request. Relay and direct
/// paths may coexist during a DCUtR upgrade.
#[derive(Default)]
struct PeerSyncPaths {
    paths: std::collections::HashMap<libp2p::swarm::ConnectionId, SyncPath>,
    announced: std::collections::HashSet<PeerId>,
    profile_verified: std::collections::HashSet<PeerId>,
}

const MAX_RELAY_RESERVATIONS: usize = 2;
const RELAY_RESERVATION_PENDING_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_RESERVATION_RETRY: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct RelayCandidate {
    addrs: Vec<Multiaddr>,
    failure_domain: u64,
    hop_capable: bool,
    retry_at: Instant,
}

#[derive(Clone, Debug)]
struct RelayReservation {
    listener_id: libp2p::core::transport::ListenerId,
    failure_domain: u64,
    requested_at: Instant,
    accepted: bool,
}

/// Maintains a tiny set of explicit Circuit Relay v2 reservations. A relay is
/// only eligible after Identify advertises the HOP protocol and the exact
/// network profile has authenticated the peer. Reservations in one public
/// failure domain do not count as independent reachability.
struct RelayReservations {
    target: usize,
    selection_salt: [u8; 32],
    candidates: std::collections::HashMap<PeerId, RelayCandidate>,
    active: std::collections::HashMap<PeerId, RelayReservation>,
    proven_direct_dial_peers: std::collections::HashSet<PeerId>,
}

impl RelayReservations {
    fn new(target: usize, local_peer: PeerId) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"parano1d/relay-selection/v1");
        hasher.update(&local_peer.to_bytes());
        Self {
            target: target.min(MAX_RELAY_RESERVATIONS),
            selection_salt: *hasher.finalize().as_bytes(),
            candidates: std::collections::HashMap::new(),
            active: std::collections::HashMap::new(),
            proven_direct_dial_peers: std::collections::HashSet::new(),
        }
    }

    fn candidate_rank(&self, peer: PeerId) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"parano1d/relay-candidate/v1");
        hasher.update(&self.selection_salt);
        hasher.update(&peer.to_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Record an address that this process has actually reached over a direct
    /// outbound transport. Identify claims alone are not reachability proofs:
    /// accepting them would let one unreachable peer occupy half of the two
    /// automatic relay reservations.
    fn observe_direct_transport(&mut self, peer: PeerId, addr: Multiaddr, failure_domain: u64) {
        self.proven_direct_dial_peers.insert(peer);
        let Some(addr) = relay_reservation_addr(peer, addr) else {
            return;
        };
        self.insert_reachable_addr(peer, addr, failure_domain);
    }

    /// DNS bootstrap endpoints may remain `/dns4/...` in the swarm endpoint
    /// even though the transport resolved and connected successfully. After
    /// that direct identity proof, admit at most two public TCP addresses from
    /// Identify; profile authentication and HOP capability are still required
    /// before selection, and failed reservations are timed out and rotated.
    fn observe_identified_transports(
        &mut self,
        peer: PeerId,
        addrs: impl IntoIterator<Item = Multiaddr>,
        failure_domain: u64,
    ) {
        if !self.proven_direct_dial_peers.contains(&peer) {
            return;
        }
        for addr in addrs
            .into_iter()
            .filter_map(|addr| relay_reservation_addr(peer, addr))
            .take(2)
        {
            self.insert_reachable_addr(peer, addr, failure_domain);
        }
    }

    fn insert_reachable_addr(&mut self, peer: PeerId, addr: Multiaddr, failure_domain: u64) {
        let retry_at = self
            .candidates
            .get(&peer)
            .map(|candidate| candidate.retry_at)
            .unwrap_or_else(Instant::now);
        let candidate = self.candidates.entry(peer).or_insert(RelayCandidate {
            addrs: Vec::new(),
            failure_domain,
            hop_capable: false,
            retry_at,
        });
        candidate.failure_domain = failure_domain;
        candidate.addrs.push(addr);
        candidate
            .addrs
            .sort_unstable_by(|left, right| left.to_string().cmp(&right.to_string()));
        candidate.addrs.dedup();
    }

    fn mark_hop_capable(&mut self, peer: PeerId, supported: bool) {
        if let Some(candidate) = self.candidates.get_mut(&peer) {
            candidate.hop_capable = supported;
        }
    }

    fn mark_accepted(&mut self, peer: PeerId) {
        if let Some(reservation) = self.active.get_mut(&peer) {
            reservation.accepted = true;
        }
    }

    /// A reservation listener is backed by its direct control connection to
    /// the relay. Closing that transport does not hand the client off to an
    /// ordinary neighbour: it tears down reachability and makes libp2p reopen
    /// the same carrier. Topology pruning must therefore treat both pending
    /// and accepted reservations as protected outbound paths.
    fn protects_peer(&self, peer: PeerId) -> bool {
        self.active.contains_key(&peer)
    }

    fn remove_listener(
        &mut self,
        listener_id: libp2p::core::transport::ListenerId,
    ) -> Option<PeerId> {
        let peer = self.active.iter().find_map(|(peer, reservation)| {
            (reservation.listener_id == listener_id).then_some(*peer)
        })?;
        self.active.remove(&peer);
        if let Some(candidate) = self.candidates.get_mut(&peer) {
            candidate.retry_at = Instant::now() + RELAY_RESERVATION_RETRY;
        }
        Some(peer)
    }

    fn retire_peer(&mut self, swarm: &mut libp2p::Swarm<NodeBehaviour>, peer: PeerId) {
        if let Some(reservation) = self.active.remove(&peer) {
            let _ = swarm.remove_listener(reservation.listener_id);
        }
        self.candidates.remove(&peer);
        self.proven_direct_dial_peers.remove(&peer);
    }

    fn maintain(
        &mut self,
        swarm: &mut libp2p::Swarm<NodeBehaviour>,
        profile_verified: &std::collections::HashSet<PeerId>,
        now: Instant,
    ) {
        let expired = self
            .active
            .iter()
            .filter_map(|(peer, reservation)| {
                (!reservation.accepted
                    && now.saturating_duration_since(reservation.requested_at)
                        >= RELAY_RESERVATION_PENDING_TIMEOUT)
                    .then_some((*peer, reservation.listener_id))
            })
            .collect::<Vec<_>>();
        for (peer, listener_id) in expired {
            self.active.remove(&peer);
            let _ = swarm.remove_listener(listener_id);
            if let Some(candidate) = self.candidates.get_mut(&peer) {
                candidate.retry_at = now + RELAY_RESERVATION_RETRY;
            }
            tracing::debug!(relay = %peer, "relay reservation timed out; bounded retry scheduled");
        }

        if self.target == 0 || self.active.len() >= self.target {
            return;
        }
        let mut used_domains = self
            .active
            .values()
            .map(|reservation| reservation.failure_domain)
            .collect::<std::collections::HashSet<_>>();
        let mut candidates = self
            .candidates
            .iter()
            .filter(|(peer, candidate)| {
                profile_verified.contains(peer)
                    && swarm.is_connected(peer)
                    && candidate.hop_capable
                    && candidate.retry_at <= now
                    && !self.active.contains_key(peer)
                    && !used_domains.contains(&candidate.failure_domain)
            })
            .map(|(peer, candidate)| (*peer, candidate.clone()))
            .collect::<Vec<_>>();
        // Raw PeerId order made every NAT client reserve the same two relays.
        // Salt the stable rendezvous rank by local identity so clients spread
        // across eligible public nodes while each client keeps deterministic
        // choices across maintenance ticks.
        candidates.sort_unstable_by_key(|(peer, _)| (self.candidate_rank(*peer), peer.to_bytes()));

        for (peer, candidate) in candidates {
            if self.active.len() >= self.target {
                break;
            }
            if !used_domains.insert(candidate.failure_domain) {
                continue;
            }
            let Some(addr) = candidate.addrs.first().cloned() else {
                continue;
            };
            match swarm.listen_on(addr.clone()) {
                Ok(listener_id) => {
                    self.active.insert(
                        peer,
                        RelayReservation {
                            listener_id,
                            failure_domain: candidate.failure_domain,
                            requested_at: now,
                            accepted: false,
                        },
                    );
                    tracing::debug!(relay = %peer, address = %addr, "relay reservation requested");
                }
                Err(error) => {
                    if let Some(candidate) = self.candidates.get_mut(&peer) {
                        candidate.retry_at = now + RELAY_RESERVATION_RETRY;
                    }
                    tracing::debug!(relay = %peer, address = %addr, %error, "relay reservation request rejected locally");
                }
            }
        }
    }
}

fn relay_reservation_addr(peer: PeerId, mut addr: Multiaddr) -> Option<Multiaddr> {
    use libp2p::multiaddr::Protocol;

    if addr
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
    {
        return None;
    }
    if let Some(Protocol::P2p(advertised_peer)) = addr.iter().last() {
        if advertised_peer != peer {
            return None;
        }
        addr.pop();
    }
    let has_tcp = addr
        .iter()
        .any(|protocol| matches!(protocol, Protocol::Tcp(port) if port != 0));
    if !is_routable_identify_addr(&addr) || !has_tcp {
        return None;
    }
    Some(addr.with(Protocol::P2p(peer)).with(Protocol::P2pCircuit))
}

impl PeerSyncPaths {
    fn insert(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        peer: PeerId,
        direct: bool,
        dialer: bool,
    ) {
        let previous = self.paths.insert(
            connection_id,
            SyncPath {
                peer,
                direct,
                dialer,
                identified: false,
                availability_capable: false,
                profile_handshake_started: false,
                closing: false,
            },
        );
        debug_assert!(previous.is_none(), "libp2p connection IDs are unique");
    }

    /// Select one canonical direct path and return exact connections to close.
    fn canonicalize_direct(
        &mut self,
        local: PeerId,
        peer: PeerId,
        new_connection: libp2p::swarm::ConnectionId,
    ) -> Vec<libp2p::swarm::ConnectionId> {
        let Some(new_path) = self.paths.get(&new_connection).copied() else {
            return Vec::new();
        };
        if !new_path.direct || new_path.closing {
            return Vec::new();
        }

        let existing = self
            .paths
            .iter()
            .filter_map(|(connection_id, path)| {
                (*connection_id != new_connection
                    && path.peer == peer
                    && path.direct
                    && !path.closing)
                    .then_some((*connection_id, *path))
            })
            .collect::<Vec<_>>();
        if existing.is_empty() {
            return Vec::new();
        }

        let has_dialer = new_path.dialer || existing.iter().any(|(_, path)| path.dialer);
        let has_listener = !new_path.dialer || existing.iter().any(|(_, path)| !path.dialer);
        let losers = if has_dialer && has_listener {
            // Opposite-direction cross-dials must retain the same physical
            // path at both endpoints even if Identify completes in a different
            // order. PeerId ordering makes that choice independent of local
            // ConnectionIds, arrival order and handshake speed.
            let prefer_dialer = local.to_bytes() < peer.to_bytes();
            if new_path.dialer == prefer_dialer {
                existing
                    .iter()
                    .filter_map(|(connection_id, path)| {
                        (path.dialer != prefer_dialer).then_some(*connection_id)
                    })
                    .collect()
            } else if existing
                .iter()
                .any(|(_, path)| path.dialer == prefer_dialer)
            {
                vec![new_connection]
            } else {
                Vec::new()
            }
        } else if existing.iter().any(|(_, path)| path.identified) {
            // For same-direction duplicates, preserve an already usable path.
            // This is the common cached-peer plus unresolved-DNS case.
            vec![new_connection]
        } else if has_dialer {
            // Repeated outbound DNS dials have one owner. Keep the path that
            // was already established and close the new duplicate.
            vec![new_connection]
        } else {
            // Repeated inbound paths are resolved by their remote dialer.
            // Until its close arrives, two direct paths keep this peer
            // non-dispatchable.
            Vec::new()
        };

        for connection_id in &losers {
            if let Some(path) = self.paths.get_mut(connection_id) {
                path.closing = true;
            }
        }
        losers
    }

    fn mark_identified(&mut self, connection_id: libp2p::swarm::ConnectionId) {
        if let Some(path) = self.paths.get_mut(&connection_id) {
            path.identified = true;
        }
    }

    fn mark_availability_capable(&mut self, connection_id: libp2p::swarm::ConnectionId) {
        if let Some(path) = self.paths.get_mut(&connection_id) {
            path.availability_capable = true;
        }
    }

    fn supports_availability(&self, peer: PeerId) -> bool {
        self.paths.values().any(|path| {
            path.peer == peer && path.identified && path.availability_capable && !path.closing
        })
    }

    fn mark_closing(&mut self, connection_id: libp2p::swarm::ConnectionId) {
        if let Some(path) = self.paths.get_mut(&connection_id) {
            path.closing = true;
        }
    }

    fn is_closing(&self, connection_id: libp2p::swarm::ConnectionId) -> bool {
        self.paths
            .get(&connection_id)
            .is_some_and(|path| path.closing)
    }

    /// Exactly one endpoint initiates the compatibility round trip for each
    /// surviving physical path. A peer-level verification may outlive an
    /// overlapping reconnect, but the remote endpoint may already have
    /// observed a zero-connection interval and cleared its copy. Repeating
    /// the tiny handshake from the transport dialer restores symmetric
    /// readiness without making both endpoints race requests.
    fn should_start_profile_handshake(&self, connection_id: libp2p::swarm::ConnectionId) -> bool {
        self.paths.get(&connection_id).is_some_and(|path| {
            path.dialer && path.identified && !path.profile_handshake_started && !path.closing
        })
    }

    fn mark_profile_handshake_started(&mut self, connection_id: libp2p::swarm::ConnectionId) {
        if let Some(path) = self.paths.get_mut(&connection_id) {
            path.profile_handshake_started = true;
        }
    }

    fn remove(&mut self, connection_id: libp2p::swarm::ConnectionId) -> Option<PeerId> {
        self.paths.remove(&connection_id).map(|path| path.peer)
    }

    fn has_identified_path(&self, peer: PeerId) -> bool {
        self.paths
            .values()
            .any(|path| path.peer == peer && path.identified && !path.closing)
    }

    fn is_dispatchable(&self, peer: PeerId) -> bool {
        if !self.profile_verified.contains(&peer) {
            return false;
        }
        let paths = self
            .paths
            .values()
            .filter(|path| path.peer == peer)
            .collect::<Vec<_>>();
        if paths.is_empty() || paths.iter().any(|path| !path.identified || path.closing) {
            return false;
        }
        paths.iter().filter(|path| path.direct).count() <= 1
    }

    fn try_mark_announced(&mut self, peer: PeerId) -> bool {
        self.is_dispatchable(peer) && self.announced.insert(peer)
    }

    fn mark_profile_verified(&mut self, peer: PeerId) {
        self.profile_verified.insert(peer);
    }

    fn clear_profile_verified(&mut self, peer: PeerId) {
        self.profile_verified.remove(&peer);
    }

    fn is_announced(&self, peer: PeerId) -> bool {
        self.announced.contains(&peer)
    }

    fn clear_announced(&mut self, peer: PeerId) {
        self.announced.remove(&peer);
    }

    fn dispatchable_peer_count(&self) -> usize {
        self.paths
            .values()
            .map(|path| path.peer)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .filter(|peer| self.is_dispatchable(*peer))
            .count()
    }
}

#[derive(Clone, Debug)]
enum PendingAutomaticDial {
    Bootstrap(Multiaddr),
    Peer {
        peer: PeerId,
        group: PublicNetworkGroup,
    },
    /// A direct address learned through mDNS. LAN discovery shares the same
    /// bounded neighbour slots but has no public failure-domain group.
    Lan {
        peer: PeerId,
    },
}

#[derive(Clone, Debug)]
enum ManagedOutboundKind {
    Bootstrap(Multiaddr),
    Peer,
}

#[derive(Clone, Debug)]
struct ManagedOutboundConnection {
    peer: PeerId,
    kind: ManagedOutboundKind,
    established_at: Instant,
    identified: bool,
}

struct AutomaticPeerState {
    bootstrap: std::collections::HashMap<Multiaddr, BootstrapCandidate>,
    peers: std::collections::HashMap<PeerId, AutomaticPeerCandidate>,
    pending: std::collections::HashMap<libp2p::swarm::ConnectionId, PendingAutomaticDial>,
    /// Every outbound transport, including short Kademlia sessions.
    /// These are useful for DNS classification and duplicate suppression but
    /// do not count toward the maintained neighbour target by themselves.
    outbound_connections: std::collections::HashMap<libp2p::swarm::ConnectionId, PeerId>,
    /// Noise-authenticated direct TCP endpoints for live outbound transports.
    /// Keeping the observed endpoint lets a late DNS-seed registration repair
    /// an ordinary classification loaded from an older `peers.json` without
    /// trusting the address that the remote peer advertised through Identify.
    authenticated_direct_addrs: std::collections::HashMap<libp2p::swarm::ConnectionId, Multiaddr>,
    managed_connections:
        std::collections::HashMap<libp2p::swarm::ConnectionId, ManagedOutboundConnection>,
    outbound_counts: std::collections::HashMap<PeerId, usize>,
    /// Every connection that completed Identify, regardless of which side's
    /// physical TCP half survived a simultaneous cross-dial.
    identified_connections: std::collections::HashMap<libp2p::swarm::ConnectionId, PeerId>,
    /// Peer identities deliberately selected by this process for an outbound
    /// bootstrap/neighbour dial. The intent survives cross-dial collapse when
    /// libp2p keeps the inbound half, and is removed after the last transport
    /// closes. It is therefore a topology decision, not a TCP direction bit.
    locally_selected_peers: std::collections::HashSet<PeerId>,
    /// Logical selected neighbours that currently have at least one identified
    /// transport. This is the topology count; physical dial direction is not.
    selected_identified_since: std::collections::HashMap<PeerId, Instant>,
    bootstrap_complete: bool,
    /// At least one bounded random lookup has been started from a live seed.
    /// A full `kad.bootstrap()` walks every populated bucket and is far too
    /// expensive when many relay-only wallets join at once.
    initial_discovery_started: bool,
    retry_salt: Vec<u8>,
    discovery_query: Option<kad::QueryId>,
    discovery_learned: bool,
    discovery_failures: u8,
    next_discovery_at: Instant,
}

impl AutomaticPeerState {
    fn new(local_peer: PeerId) -> Self {
        let initial_discovery_at = Instant::now() + initial_discovery_delay(local_peer);
        Self {
            bootstrap: std::collections::HashMap::new(),
            peers: std::collections::HashMap::new(),
            pending: std::collections::HashMap::new(),
            outbound_connections: std::collections::HashMap::new(),
            authenticated_direct_addrs: std::collections::HashMap::new(),
            managed_connections: std::collections::HashMap::new(),
            outbound_counts: std::collections::HashMap::new(),
            identified_connections: std::collections::HashMap::new(),
            locally_selected_peers: std::collections::HashSet::new(),
            selected_identified_since: std::collections::HashMap::new(),
            bootstrap_complete: false,
            initial_discovery_started: false,
            retry_salt: local_peer.to_bytes(),
            discovery_query: None,
            discovery_learned: false,
            discovery_failures: 0,
            next_discovery_at: initial_discovery_at,
        }
    }

    fn register_bootstrap(&mut self, addr: Multiaddr) -> Vec<PeerId> {
        self.bootstrap
            .entry(addr.clone())
            .or_insert(BootstrapCandidate {
                peer: None,
                failures: 0,
                next_attempt: Instant::now(),
            });

        // The network task starts before the node finishes system-DNS seed
        // resolution. An older peers.json may therefore reconnect a seed as
        // an ordinary peer just before its configured IP is registered. Use
        // only the actual authenticated endpoint retained at connection time
        // to repair that startup race.
        let matching_connections = self
            .authenticated_direct_addrs
            .iter()
            .filter(|(_, observed)| *observed == &addr)
            .filter_map(|(connection_id, _)| {
                self.outbound_connections
                    .get(connection_id)
                    .map(|peer| (*connection_id, *peer))
            })
            .collect::<Vec<_>>();
        let mut reclassified = Vec::new();
        for (connection_id, peer) in matching_connections {
            if let Some(candidate) = self.bootstrap.get_mut(&addr) {
                candidate.peer = Some(peer);
            }
            self.peers.remove(&peer);
            let identified = self.identified_connections.get(&connection_id) == Some(&peer);
            if let Some(connection) = self.managed_connections.get_mut(&connection_id) {
                connection.kind = ManagedOutboundKind::Bootstrap(addr.clone());
            } else {
                self.track_managed_connection(
                    connection_id,
                    peer,
                    ManagedOutboundKind::Bootstrap(addr.clone()),
                );
            }
            if identified {
                if let Some(connection) = self.managed_connections.get_mut(&connection_id) {
                    connection.identified = true;
                }
                self.refresh_selected_identified(peer);
            }
            if !reclassified.contains(&peer) {
                reclassified.push(peer);
            }
        }
        reclassified
    }

    fn add_peer_candidate(
        &mut self,
        local: PeerId,
        peer: PeerId,
        addrs: impl IntoIterator<Item = Multiaddr>,
    ) -> bool {
        if peer == local || self.is_bootstrap_peer(peer) {
            return false;
        }
        let mut accepted = addrs
            .into_iter()
            .filter_map(|addr| sanitize_automatic_peer_addr(peer, addr))
            .collect::<Vec<_>>();
        accepted.sort_unstable_by(|a, b| a.to_string().cmp(&b.to_string()));
        accepted.dedup();
        if accepted.is_empty() {
            return false;
        }
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_AUTOMATIC_PEER_CANDIDATES {
            let pending = self
                .pending
                .values()
                .filter_map(|dial| match dial {
                    PendingAutomaticDial::Peer { peer, .. }
                    | PendingAutomaticDial::Lan { peer } => Some(*peer),
                    PendingAutomaticDial::Bootstrap(_) => None,
                })
                .collect::<std::collections::HashSet<_>>();
            let evict = self
                .peers
                .iter()
                .filter(|(candidate, _)| {
                    !self.outbound_counts.contains_key(candidate) && !pending.contains(candidate)
                })
                .min_by_key(|(_, candidate)| candidate.last_seen)
                .map(|(candidate, _)| *candidate);
            if let Some(evict) = evict {
                self.peers.remove(&evict);
            }
            if self.peers.len() >= MAX_AUTOMATIC_PEER_CANDIDATES {
                return false;
            }
        }
        let now = Instant::now();
        let candidate = self.peers.entry(peer).or_insert(AutomaticPeerCandidate {
            addrs: Vec::new(),
            failures: 0,
            next_attempt: now,
            last_seen: now,
            attempted_addrs: Vec::new(),
        });
        candidate.last_seen = now;
        let mut changed = false;
        for addr in accepted {
            if candidate.addrs.contains(&addr) {
                continue;
            }
            if candidate.addrs.len() == MAX_AUTOMATIC_ADDRS_PER_PEER {
                candidate.addrs.remove(0);
            }
            candidate.addrs.push(addr);
            changed = true;
        }
        candidate
            .attempted_addrs
            .retain(|attempted| candidate.addrs.contains(attempted));
        changed
    }

    fn remove_peer_candidate_addr(&mut self, peer: PeerId, addr: &Multiaddr) -> bool {
        let Some(candidate) = self.peers.get_mut(&peer) else {
            return false;
        };
        let previous_len = candidate.addrs.len();
        candidate.addrs.retain(|known| known != addr);
        let changed = candidate.addrs.len() != previous_len;
        if candidate.addrs.is_empty() {
            self.peers.remove(&peer);
        }
        changed
    }

    fn outbound_peer_count(&self) -> usize {
        self.selected_identified_since.len()
    }

    /// Every identified peer is a bidirectional libp2p neighbour, but an
    /// arbitrary inbound set may satisfy at most half of the maintained
    /// topology target. Explicit bootstrap peers are discovery roots rather
    /// than ordinary mesh replacements and therefore do not count here.
    /// This preserves inbound fanout while every node still selects at least
    /// two independent ordinary neighbours of its own.
    fn topology_peer_count(&self) -> usize {
        let bootstrap = self.bootstrap_peer_ids();
        let selected = self
            .selected_identified_since
            .keys()
            .filter(|peer| !bootstrap.contains(peer))
            .copied()
            .collect::<std::collections::HashSet<_>>();
        let unselected = self
            .identified_connections
            .values()
            .copied()
            .filter(|peer| !bootstrap.contains(peer) && !selected.contains(peer))
            .collect::<std::collections::HashSet<_>>()
            .len()
            .min(MAX_UNSELECTED_TOPOLOGY_CREDIT);
        selected.len().saturating_add(unselected)
    }

    fn is_outbound(&self, peer: PeerId) -> bool {
        self.outbound_connections
            .values()
            .any(|known| *known == peer)
    }

    fn bootstrap_peer_ids(&self) -> std::collections::HashSet<PeerId> {
        self.bootstrap
            .values()
            .filter_map(|candidate| candidate.peer)
            .collect()
    }

    fn is_bootstrap_peer(&self, peer: PeerId) -> bool {
        self.bootstrap
            .values()
            .any(|candidate| candidate.peer == Some(peer))
    }

    fn is_locally_selected(&self, peer: PeerId) -> bool {
        self.locally_selected_peers.contains(&peer)
    }

    fn mark_local_selection(&mut self, peer: PeerId) {
        self.locally_selected_peers.insert(peer);
        self.refresh_selected_identified(peer);
    }

    fn clear_local_selection(&mut self, peer: PeerId) {
        self.locally_selected_peers.remove(&peer);
        self.selected_identified_since.remove(&peer);
    }

    fn refresh_selected_identified(&mut self, peer: PeerId) {
        let usable = self.locally_selected_peers.contains(&peer)
            && self
                .identified_connections
                .values()
                .any(|identified| *identified == peer);
        if usable {
            self.selected_identified_since
                .entry(peer)
                .or_insert_with(Instant::now);
        } else {
            self.selected_identified_since.remove(&peer);
        }
    }

    fn connected_bootstrap_peer_ids(&self) -> Vec<PeerId> {
        let bootstrap_peers = self.bootstrap_peer_ids();
        self.selected_identified_since
            .keys()
            .filter(|peer| bootstrap_peers.contains(peer))
            .copied()
            .into_iter()
            .collect()
    }

    fn stable_non_bootstrap_peer_count(&self, now: Instant) -> usize {
        let bootstrap_peers = self.bootstrap_peer_ids();
        self.selected_identified_since
            .iter()
            .filter(|(peer, since)| {
                !bootstrap_peers.contains(peer)
                    && now.saturating_duration_since(**since) >= AUTOMATIC_PEER_HEALTHY_AFTER
            })
            .count()
    }

    fn note_connection_established(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        peer: PeerId,
        outbound: bool,
        direct_remote_addr: Option<&Multiaddr>,
    ) {
        // A DHT record is untrusted and may advertise somebody else's seed
        // address. Classify a discovered transport as bootstrap only after
        // Noise authenticated its PeerId and the connection's actual direct
        // TCP endpoint matched an address configured by the local operator.
        let authenticated_direct_addr = if outbound {
            direct_remote_addr.and_then(|addr| sanitize_automatic_peer_addr(peer, addr.clone()))
        } else {
            None
        };
        let authenticated_bootstrap = authenticated_direct_addr
            .as_ref()
            .filter(|addr| self.bootstrap.contains_key(*addr))
            .cloned();
        let pending = self.pending.remove(&connection_id);
        let managed_kind = match pending {
            Some(pending) => match pending {
                PendingAutomaticDial::Bootstrap(addr) => Some(ManagedOutboundKind::Bootstrap(addr)),
                PendingAutomaticDial::Peer { peer: expected, .. } if expected == peer => {
                    authenticated_bootstrap
                        .clone()
                        .map(ManagedOutboundKind::Bootstrap)
                        .or(Some(ManagedOutboundKind::Peer))
                }
                PendingAutomaticDial::Peer { .. } => None,
                PendingAutomaticDial::Lan { peer: expected } if expected == peer => {
                    authenticated_bootstrap
                        .clone()
                        .map(ManagedOutboundKind::Bootstrap)
                        .or(Some(ManagedOutboundKind::Peer))
                }
                PendingAutomaticDial::Lan { .. } => None,
            },
            // Kademlia and relay behaviours also open short-lived outbound
            // transports. They are useful to the behaviour that owns them,
            // but must not become maintained neighbours merely because the
            // remote PeerId is already present in the candidate table. The
            // one exception is an authenticated direct connection to an
            // address explicitly registered as a bootstrap endpoint.
            None => authenticated_bootstrap.map(ManagedOutboundKind::Bootstrap),
        };
        if let Some(ManagedOutboundKind::Bootstrap(addr)) = &managed_kind {
            if let Some(candidate) = self.bootstrap.get_mut(addr) {
                candidate.peer = Some(peer);
            }
            // A seed may already exist in the successful-peer cache from an
            // earlier release. Once its identity is learned through an
            // authenticated bootstrap transport, it must no longer compete
            // for an ordinary neighbour slot.
            self.peers.remove(&peer);
        }
        if outbound {
            self.outbound_connections.insert(connection_id, peer);
            if let Some(addr) = authenticated_direct_addr {
                self.authenticated_direct_addrs.insert(connection_id, addr);
            }
            if let Some(kind) = managed_kind {
                self.mark_local_selection(peer);
                // Keep up to the transport's two-path hard limit. A second
                // connection may be the direct half of an active relay→DCUtR
                // upgrade, so blindly closing every duplicate PeerId here
                // would strand NATed wallets on the relay path.
                self.track_managed_connection(connection_id, peer, kind);
            }
        }
    }

    fn track_managed_connection(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        peer: PeerId,
        kind: ManagedOutboundKind,
    ) {
        self.mark_local_selection(peer);
        if self.managed_connections.contains_key(&connection_id) {
            return;
        }
        self.managed_connections.insert(
            connection_id,
            ManagedOutboundConnection {
                peer,
                kind,
                established_at: Instant::now(),
                identified: false,
            },
        );
        *self.outbound_counts.entry(peer).or_default() += 1;
    }

    fn note_identified(&mut self, connection_id: libp2p::swarm::ConnectionId, peer: PeerId) {
        self.identified_connections.insert(connection_id, peer);
        // Kademlia opens useful outbound transports while resolving a bounded
        // random lookup. Adopt up to the maintained topology target instead
        // of ignoring those live peers and immediately launching another DHT
        // walk. Configured bootstrap identities remain managed by their DNS
        // entries and are never reclassified here.
        let adopt_discovered_transport = self
            .outbound_connections
            .get(&connection_id)
            .is_some_and(|connected| *connected == peer)
            && !self.managed_connections.contains_key(&connection_id)
            && !self.is_bootstrap_peer(peer)
            && self.topology_peer_count() <= AUTOMATIC_OUTBOUND_TARGET;
        if adopt_discovered_transport {
            self.track_managed_connection(connection_id, peer, ManagedOutboundKind::Peer);
        }
        if let Some(connection) = self.managed_connections.get_mut(&connection_id) {
            connection.identified = true;
        }
        self.refresh_selected_identified(peer);
    }

    fn refresh_healthy_connections(&mut self, now: Instant) {
        for connection in self.managed_connections.values() {
            if !connection.identified
                || now.duration_since(connection.established_at) < AUTOMATIC_PEER_HEALTHY_AFTER
            {
                continue;
            }
            match &connection.kind {
                ManagedOutboundKind::Bootstrap(addr) => {
                    if let Some(candidate) = self.bootstrap.get_mut(addr) {
                        candidate.failures = 0;
                        candidate.next_attempt = now;
                    }
                }
                ManagedOutboundKind::Peer => {
                    if let Some(candidate) = self.peers.get_mut(&connection.peer) {
                        candidate.failures = 0;
                        candidate.next_attempt = now;
                        candidate.attempted_addrs.clear();
                    }
                }
            }
        }
    }

    fn expired_unidentified_connections(
        &self,
        now: Instant,
    ) -> Vec<(libp2p::swarm::ConnectionId, PeerId)> {
        self.managed_connections
            .iter()
            .filter_map(|(connection_id, connection)| {
                (!connection.identified
                    && now.duration_since(connection.established_at)
                        >= AUTOMATIC_PEER_HEALTHY_AFTER)
                    .then_some((*connection_id, connection.peer))
            })
            .collect()
    }

    fn note_connection_closed(&mut self, connection_id: libp2p::swarm::ConnectionId) {
        self.outbound_connections.remove(&connection_id);
        self.authenticated_direct_addrs.remove(&connection_id);
        let identified_peer = self.identified_connections.remove(&connection_id);
        let Some(managed) = self.managed_connections.remove(&connection_id) else {
            if let Some(peer) = identified_peer {
                self.refresh_selected_identified(peer);
                if self.topology_peer_count() < AUTOMATIC_OUTBOUND_TARGET {
                    self.accelerate_discovery();
                }
            }
            return;
        };
        let peer = managed.peer;
        self.refresh_selected_identified(peer);
        let accelerate_discovery =
            managed.identified || matches!(&managed.kind, ManagedOutboundKind::Peer);
        if let Some(count) = self.outbound_counts.get_mut(&peer) {
            *count -= 1;
            if *count == 0 {
                self.outbound_counts.remove(&peer);
                match managed.kind {
                    ManagedOutboundKind::Peer => {
                        schedule_peer_retry(
                            self.peers.get_mut(&peer),
                            peer.to_bytes(),
                            &self.retry_salt,
                        );
                    }
                    ManagedOutboundKind::Bootstrap(addr) => {
                        if let Some(candidate) = self.bootstrap.get_mut(&addr) {
                            schedule_bootstrap_retry(candidate, addr.as_ref(), &self.retry_salt);
                        }
                    }
                }
            }
        }
        if accelerate_discovery {
            self.accelerate_discovery();
        }
    }

    fn note_dial_failed(&mut self, connection_id: libp2p::swarm::ConnectionId) {
        let Some(pending) = self.pending.remove(&connection_id) else {
            return;
        };
        let accelerate_discovery = matches!(&pending, PendingAutomaticDial::Peer { .. });
        match pending {
            PendingAutomaticDial::Bootstrap(addr) => {
                if let Some(candidate) = self.bootstrap.get_mut(&addr) {
                    // DNS pools may legitimately rotate to a different node
                    // identity. One identity-bound reconnect is attempted;
                    // after failure the next dial re-resolves without pinning
                    // the obsolete PeerId.
                    candidate.peer = None;
                    schedule_bootstrap_retry(candidate, addr.as_ref(), &self.retry_salt);
                }
            }
            PendingAutomaticDial::Peer { peer, .. } => {
                schedule_peer_retry(self.peers.get_mut(&peer), peer.to_bytes(), &self.retry_salt);
            }
            PendingAutomaticDial::Lan { peer } => {
                // One PeerId may be reached concurrently through an explicit
                // bootstrap dial and an mDNS alternative. Failure of the LAN
                // leg must not erase the topology intent already backed by a
                // live or still-identifying managed connection. Otherwise a
                // successful seed connection is reported as unsolicited and
                // skips its one-time cold-sync/mempool bootstrap work.
                let has_other_path = self
                    .managed_connections
                    .values()
                    .any(|connection| connection.peer == peer)
                    || self
                        .identified_connections
                        .values()
                        .any(|identified| *identified == peer);
                if !has_other_path {
                    self.clear_local_selection(peer);
                }
            }
        }
        // DNS sources have their own bounded retry schedule. Accelerating a
        // Kademlia walk for every dead hostname would defeat discovery
        // backoff when several future seed names are intentionally offline.
        if accelerate_discovery {
            self.accelerate_discovery();
        }
    }

    fn pending_group_count(&self, group: PublicNetworkGroup) -> usize {
        self.pending
            .values()
            .filter_map(|pending| match pending {
                PendingAutomaticDial::Peer {
                    peer,
                    group: candidate_group,
                } if *candidate_group == group => Some(*peer),
                PendingAutomaticDial::Lan { .. } => None,
                _ => None,
            })
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    fn pending_bootstrap_count(&self) -> usize {
        self.pending
            .values()
            .filter(|pending| matches!(pending, PendingAutomaticDial::Bootstrap(_)))
            .count()
    }

    fn pending_ordinary_count(&self) -> usize {
        self.pending
            .values()
            .filter(|pending| {
                matches!(
                    pending,
                    PendingAutomaticDial::Peer { .. } | PendingAutomaticDial::Lan { .. }
                )
            })
            .count()
    }

    fn automatic_occupancy(&self) -> usize {
        self.managed_connections
            .len()
            .saturating_add(self.pending.len())
    }

    fn automatic_dial_capacity(&self) -> usize {
        let unconfirmed = self
            .managed_connections
            .values()
            .filter(|connection| !connection.identified)
            .count()
            .saturating_add(self.pending.len());
        MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS
            .saturating_sub(unconfirmed)
            .min(MAX_AUTOMATIC_TRANSPORT_OCCUPANCY.saturating_sub(self.automatic_occupancy()))
    }

    fn accelerate_discovery(&mut self) {
        if !self.discovery_active() {
            let paced = Instant::now() + DISCOVERY_RETRY_MIN;
            if self.next_discovery_at > paced {
                self.next_discovery_at = paced;
            }
        }
    }

    fn discovery_active(&self) -> bool {
        self.discovery_query.is_some()
    }

    fn begin_discovery(&mut self, query: kad::QueryId) {
        self.discovery_query = Some(query);
        self.discovery_learned = false;
    }

    fn finish_discovery_at_target(&mut self) -> Option<kad::QueryId> {
        if self.topology_peer_count() < AUTOMATIC_OUTBOUND_TARGET {
            return None;
        }
        let query = self.discovery_query.take()?;
        self.discovery_learned = false;
        self.discovery_failures = 0;
        self.next_discovery_at = Instant::now() + DISCOVERY_RETRY_MIN;
        Some(query)
    }

    fn observe_discovery(&mut self, query: kad::QueryId, learned: bool, complete: bool) {
        if self.discovery_query != Some(query) {
            return;
        }
        self.discovery_learned |= learned;
        if !complete {
            return;
        }
        self.discovery_query = None;
        if self.discovery_learned {
            self.discovery_failures = 0;
        } else {
            self.discovery_failures = self.discovery_failures.saturating_add(1);
        }
        let multiplier = 1u64 << self.discovery_failures.min(5);
        let delay = DISCOVERY_RETRY_MIN
            .saturating_mul(multiplier as u32)
            .min(DISCOVERY_RETRY_MAX);
        self.next_discovery_at = Instant::now() + delay;
        self.discovery_learned = false;
    }
}

fn initial_discovery_delay(local_peer: PeerId) -> Duration {
    // A public release can bring hundreds of wallets online in one second.
    // Stable identity-derived jitter prevents all of them from asking the
    // same small relay set to execute an iterative lookup simultaneously.
    let hash = local_peer
        .to_bytes()
        .into_iter()
        .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    Duration::from_secs(2 + hash % 29)
}

fn stop_discovery_after_mesh_formed(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    automatic: &mut AutomaticPeerState,
) -> bool {
    let Some(query_id) = automatic.finish_discovery_at_target() else {
        return false;
    };
    if let Some(mut query) = swarm.behaviour_mut().kad.query_mut(&query_id) {
        query.finish();
    }
    tracing::debug!(
        peers = automatic.topology_peer_count(),
        "kad: bounded lookup stopped after reaching outbound target"
    );
    true
}

/// `libp2p-kad` starts a full bootstrap automatically whenever its routing
/// table is small. Parano1d has its own identity-jittered, topology-bounded
/// `GetClosestPeers` controller, so allowing both mechanisms makes one wallet
/// launch walk up to K_VALUE peers through relays before the eight-peer target
/// can stop it. The first `SwarmEvent::Dialing` gives the outer reactor a
/// chance to finish the implicit query before it schedules the remaining
/// peers. Explicit bounded lookups have a different `QueryInfo` and are left
/// untouched.
fn stop_implicit_kad_bootstraps(swarm: &mut libp2p::Swarm<NodeBehaviour>) -> usize {
    let query_ids = swarm
        .behaviour()
        .kad
        .iter_queries()
        .filter_map(|query| {
            matches!(query.info(), kad::QueryInfo::Bootstrap { .. }).then_some(query.id())
        })
        .collect::<Vec<_>>();
    let mut stopped = 0usize;
    for query_id in query_ids {
        if let Some(mut query) = swarm.behaviour_mut().kad.query_mut(&query_id) {
            query.finish();
            stopped += 1;
        }
    }
    stopped
}

fn automatic_retry_delay(
    failures: u8,
    salt: impl AsRef<[u8]>,
    local_salt: impl AsRef<[u8]>,
) -> Duration {
    let exponential = 5u64.saturating_mul(1u64 << failures.saturating_sub(1).min(6));
    let capped = exponential.min(300);
    let jitter = salt
        .as_ref()
        .iter()
        .chain(local_salt.as_ref())
        .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
        % 5;
    Duration::from_secs(capped + jitter)
}

fn schedule_bootstrap_retry(
    candidate: &mut BootstrapCandidate,
    salt: impl AsRef<[u8]>,
    local_salt: impl AsRef<[u8]>,
) {
    candidate.failures = candidate.failures.saturating_add(1);
    candidate.next_attempt =
        Instant::now() + automatic_retry_delay(candidate.failures, salt, local_salt);
}

fn schedule_peer_retry(
    candidate: Option<&mut AutomaticPeerCandidate>,
    salt: impl AsRef<[u8]>,
    local_salt: impl AsRef<[u8]>,
) {
    let Some(candidate) = candidate else {
        return;
    };
    candidate.failures = candidate.failures.saturating_add(1);
    candidate.next_attempt =
        Instant::now() + automatic_retry_delay(candidate.failures, salt, local_salt);
}
const _: () = assert!(
    MAX_PENDING_STATE_SEGMENT_REQUESTS >= noid_chain::consensus::wire_limits::MAX_INFLIGHT_SEGMENTS
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SnapshotLeaseProgress {
    Terminal { height: u64, block_hash: [u8; 32] },
    ManifestPage(u16),
    Segment(u16),
}

#[derive(Clone, Debug)]
struct SnapshotLeaseProgressSet {
    terminals: [Option<(u64, [u8; 32])>; 2],
    manifest_pages: u64,
    segments: Box<[u64; 1024]>,
}

impl SnapshotLeaseProgressSet {
    fn new() -> Self {
        Self {
            terminals: [None; 2],
            manifest_pages: 0,
            segments: Box::new([0; 1024]),
        }
    }

    fn insert(&mut self, progress: SnapshotLeaseProgress) -> bool {
        match progress {
            SnapshotLeaseProgress::Terminal { height, block_hash } => {
                let terminal = (height, block_hash);
                if self.terminals.contains(&Some(terminal)) {
                    return false;
                }
                let Some(slot) = self.terminals.iter_mut().find(|slot| slot.is_none()) else {
                    return false;
                };
                *slot = Some(terminal);
                true
            }
            SnapshotLeaseProgress::ManifestPage(page) => {
                let Some(bit) = 1u64.checked_shl(u32::from(page)) else {
                    return false;
                };
                let fresh = self.manifest_pages & bit == 0;
                self.manifest_pages |= bit;
                fresh
            }
            SnapshotLeaseProgress::Segment(segment) => {
                let segment = usize::from(segment);
                let word = segment / 64;
                let bit = 1u64 << (segment % 64);
                let fresh = self.segments[word] & bit == 0;
                self.segments[word] |= bit;
                fresh
            }
        }
    }
}

#[derive(Clone, Debug)]
struct SnapshotExportLease {
    key: SnapshotExportKey,
    manifest_digest: [u8; 32],
    absolute_deadline: Instant,
    last_activity: Instant,
    served_objects: SnapshotLeaseProgressSet,
}

/// A disconnected client no longer needs per-peer authorization, but the
/// immutable generation it was downloading must remain available until the
/// same bounded lease deadline. Otherwise one transport loss can strand a
/// valid client plan after the exporter deletes its exact segment set.
type SnapshotExportDisconnectGrace = std::collections::HashMap<SnapshotExportKey, Instant>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingStateSegmentRequest {
    peer: PeerId,
    segment_id: u16,
    expected_tip_height: u64,
    expected_tip_hash: [u8; 32],
    manifest_digest: [u8; 32],
    issued_at: Instant,
    notify_node: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingStateManifestRequest {
    generation: u64,
    peer: PeerId,
    requester_height: u64,
    requested_manifest_digest: [u8; 32],
    issued_at: Instant,
    notify_node: bool,
}

const MAX_MANIFEST_PAGE_ASSEMBLIES: usize = 8;
const MAX_MANIFEST_CANDIDATE_TOMBSTONES: usize = 32;
const MAX_MANIFEST_PAGE_REQUESTS: usize = 64;
const MAX_MANIFEST_PAGES_IN_FLIGHT_PER_ASSEMBLY: usize = 4;
const MANIFEST_PAGE_OPERATIONAL_RETRY: Duration = Duration::from_millis(750);
const MANIFEST_PAGE_ASSEMBLY_IDLE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ManifestAssemblyKey {
    generation: u64,
    snapshot: crate::object_protocol::SnapshotId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManifestProviderAdmission {
    Added,
    Existing,
    Rejected,
}

struct VerifiedManifestPageBytes {
    bytes: Arc<[u8]>,
    _inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}

struct ManifestPageAssembly {
    header: Arc<GetStateManifestHeader>,
    provider_requester_heights: std::collections::HashMap<PeerId, u64>,
    rejected_providers: std::collections::HashSet<PeerId>,
    delivered_providers: std::collections::HashSet<PeerId>,
    pages: Vec<Option<VerifiedManifestPageBytes>>,
    in_flight_pages: std::collections::HashSet<u16>,
    retry_after: std::collections::HashMap<(u16, PeerId), Instant>,
    completed: Option<VerifiedStateManifest>,
    finalization_inflight: bool,
    last_progress: Instant,
}

impl ManifestPageAssembly {
    fn new(
        header: GetStateManifestHeader,
        provider: PeerId,
        requester_height: u64,
    ) -> Option<Self> {
        let snapshot = header.snapshot_id()?;
        let pages = (0..header.descriptor_pages.len()).map(|_| None).collect();
        let _ = snapshot;
        Some(Self {
            header: Arc::new(header),
            provider_requester_heights: std::iter::once((provider, requester_height)).collect(),
            rejected_providers: std::collections::HashSet::new(),
            delivered_providers: std::collections::HashSet::new(),
            pages,
            in_flight_pages: std::collections::HashSet::new(),
            retry_after: std::collections::HashMap::new(),
            completed: None,
            finalization_inflight: false,
            last_progress: Instant::now(),
        })
    }

    fn add_provider(
        &mut self,
        provider: PeerId,
        requester_height: u64,
    ) -> ManifestProviderAdmission {
        if self.rejected_providers.contains(&provider) {
            return ManifestProviderAdmission::Rejected;
        }
        match self.provider_requester_heights.entry(provider) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.insert(requester_height);
                ManifestProviderAdmission::Existing
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(requester_height);
                self.last_progress = Instant::now();
                ManifestProviderAdmission::Added
            }
        }
    }

    fn reject_provider(&mut self, provider: PeerId) {
        let changed = self.provider_requester_heights.remove(&provider).is_some()
            | self.rejected_providers.insert(provider);
        self.delivered_providers.remove(&provider);
        self.retry_after.retain(|(_, peer), _| *peer != provider);
        if changed {
            self.last_progress = Instant::now();
        }
    }

    fn detach_provider(&mut self, provider: PeerId) {
        if self.provider_requester_heights.remove(&provider).is_some() {
            self.last_progress = Instant::now();
        }
        self.delivered_providers.remove(&provider);
        self.rejected_providers.remove(&provider);
        self.retry_after.retain(|(_, peer), _| *peer != provider);
    }

    fn has_provider(&self, provider: PeerId) -> bool {
        self.provider_requester_heights.contains_key(&provider)
    }

    fn has_live_providers(&self) -> bool {
        !self.provider_requester_heights.is_empty()
    }

    fn has_local_progress(&self) -> bool {
        self.completed.is_some()
            || self.finalization_inflight
            || !self.in_flight_pages.is_empty()
            || self.pages.iter().any(Option::is_some)
    }

    fn finish_request(&mut self, page_index: u16) {
        self.in_flight_pages.remove(&page_index);
    }

    fn all_pages_received(&self) -> bool {
        self.pages.iter().all(Option::is_some)
    }
}

#[derive(Clone, Copy, Debug)]
struct PendingManifestPageRequest {
    key: ManifestAssemblyKey,
    peer: PeerId,
    requester_height: u64,
    object: SnapshotManifestPageObjectId,
    requested_manifest_digest: [u8; 32],
    issued_at: Instant,
}

struct ManifestPageVerificationCompletion {
    pending: PendingManifestPageRequest,
    response: GetSnapshotManifestPageResponse,
    digest_valid: bool,
}

struct ManifestAssemblyCompletion {
    key: ManifestAssemblyKey,
    result: Option<VerifiedStateManifest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingHeaderRequest {
    peer: PeerId,
    start_height: u64,
    count: u16,
    kind: HeaderRequestKind,
    issued_at: Instant,
    notify_node: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderRequestKind {
    General,
    Snapshot { generation: u64, token: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingHistoryStepTerminalRequest {
    token: u64,
    peer: PeerId,
    height: u64,
    block_hash: [u8; 32],
    issued_at: Instant,
    notify_node: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestFailureKind {
    /// A bounded local correlation table or the peer's explicitly bounded
    /// serving lane was full. The peer and its advertisement remain healthy;
    /// the node must defer the same exact work without scoring or rotating
    /// the source.
    LocalCapacity,
    Dial,
    Timeout,
    ConnectionClosed,
    UnsupportedProtocol,
    Io,
    /// The peer correctly answered that it no longer retains one exact
    /// immutable object/generation. This is plan-wide source unavailability,
    /// not malformed data and not a reason to retry the same source.
    Unavailable,
    InvalidResponse,
}

impl From<&request_response::OutboundFailure> for RequestFailureKind {
    fn from(failure: &request_response::OutboundFailure) -> Self {
        match failure {
            request_response::OutboundFailure::DialFailure => Self::Dial,
            request_response::OutboundFailure::Timeout => Self::Timeout,
            request_response::OutboundFailure::ConnectionClosed => Self::ConnectionClosed,
            request_response::OutboundFailure::UnsupportedProtocols => Self::UnsupportedProtocol,
            request_response::OutboundFailure::Io(error)
                if error.kind() == std::io::ErrorKind::InvalidData =>
            {
                Self::InvalidResponse
            }
            request_response::OutboundFailure::Io(_) => Self::Io,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct MempoolSyncRetry {
    failures: u8,
    next_attempt: Instant,
}

const MAX_MEMPOOL_SYNC_FAILURES: u8 = 7;
const MEMPOOL_SYNC_RETRY_INFLIGHT: Duration = Duration::from_secs(35);

fn mempool_sync_retry_jitter(local: PeerId, remote: PeerId) -> Duration {
    // Every client requesting the same busy peer must get a different retry
    // phase. Hashing only `remote` synchronizes the entire fan-in on one tick.
    // FNV-1a is sufficient here: this is load spreading, not authentication.
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in local.to_bytes().iter().chain(remote.to_bytes().iter()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    Duration::from_millis(hash % 4_000)
}

fn data_plane_busy_retry_ms(local: PeerId, remote: PeerId) -> u16 {
    // Spread clients that hit the same full anchor across distinct retry
    // phases. This is operational load shedding, not cryptographic entropy.
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in local.to_bytes().iter().chain(remote.to_bytes().iter()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let span = u64::from(MAX_BUSY_RETRY_MS.min(1_500) - MIN_BUSY_RETRY_MS);
    MIN_BUSY_RETRY_MS + u16::try_from(hash % (span + 1)).expect("bounded retry jitter")
}

fn schedule_mempool_sync_retry(
    retries: &mut std::collections::HashMap<PeerId, MempoolSyncRetry>,
    local: PeerId,
    peer: PeerId,
) -> Option<MempoolSyncRetry> {
    let previous_failures = retries.get(&peer).map_or(0, |retry| retry.failures);
    if previous_failures >= MAX_MEMPOOL_SYNC_FAILURES {
        retries.remove(&peer);
        return None;
    }
    let failures = previous_failures + 1;
    let exponential_secs = 1u64 << failures.saturating_sub(1).min(5);
    let retry = MempoolSyncRetry {
        failures,
        next_attempt: Instant::now()
            + Duration::from_secs(exponential_secs)
            + mempool_sync_retry_jitter(local, peer),
    };
    retries.insert(peer, retry);
    Some(retry)
}

/// A fixed-capacity request correlation table. Request IDs are local transport
/// capabilities: a response is consumed exactly once and only by the peer and
/// request tuple recorded when `send_request` returned that ID.
struct BoundedPendingRequests<K, V> {
    entries: std::collections::HashMap<K, V>,
    max_len: usize,
}

impl<K: std::hash::Hash + Eq, V> BoundedPendingRequests<K, V> {
    fn new(max_len: usize) -> Self {
        Self {
            entries: std::collections::HashMap::with_capacity(max_len),
            max_len,
        }
    }

    fn has_capacity(&self) -> bool {
        self.entries.len() < self.max_len
    }

    fn try_insert(&mut self, request_id: K, pending: V) -> bool {
        if !self.has_capacity() || self.entries.contains_key(&request_id) {
            return false;
        }
        self.entries.insert(request_id, pending);
        true
    }

    fn remove(&mut self, request_id: &K) -> Option<V> {
        self.entries.remove(request_id)
    }

    fn retain(&mut self, keep: impl FnMut(&K, &mut V) -> bool) {
        self.entries.retain(keep);
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl<K: std::hash::Hash + Eq + Clone, V> BoundedPendingRequests<K, V> {
    fn take_where_entries(&mut self, mut matches: impl FnMut(&V) -> bool) -> Vec<(K, V)> {
        let ids = self
            .entries
            .iter()
            .filter_map(|(id, pending)| matches(pending).then_some(id.clone()))
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| self.entries.remove(&id).map(|pending| (id, pending)))
            .collect()
    }

    fn take_where(&mut self, matches: impl FnMut(&V) -> bool) -> Vec<V> {
        self.take_where_entries(matches)
            .into_iter()
            .map(|(_, pending)| pending)
            .collect()
    }
}

/// Advance the node-local snapshot epoch and immediately release every
/// transport allocation belonging to an older immutable candidate. Late
/// request-response completions remain safe: their correlation entries are
/// gone, so the reactor treats them as stale and never revives retired work.
fn advance_manifest_generation(
    generation: u64,
    latest_generation: &mut u64,
    pending_manifests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingStateManifestRequest,
    >,
    pending_pages: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingManifestPageRequest,
    >,
    assemblies: &mut std::collections::HashMap<ManifestAssemblyKey, ManifestPageAssembly>,
    rejected_candidates: &mut std::collections::HashMap<ManifestAssemblyKey, Instant>,
) -> bool {
    if generation <= *latest_generation {
        return false;
    }
    *latest_generation = generation;
    pending_manifests.take_where(|pending| pending.generation < generation);
    pending_pages.take_where(|pending| pending.key.generation < generation);
    assemblies.retain(|key, _| key.generation >= generation);
    rejected_candidates.retain(|key, _| key.generation >= generation);
    true
}

fn state_segment_response_matches_pending(
    pending: PendingStateSegmentRequest,
    peer: PeerId,
    response: &GetStateSegmentResponse,
) -> bool {
    pending.peer == peer
        && pending.segment_id == response.segment_id
        && pending.expected_tip_height == response.expected_tip_height
        && pending.expected_tip_hash == response.expected_tip_hash
        && pending.manifest_digest == response.manifest_digest
}

fn schedule_manifest_page_requests(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    assemblies: &mut std::collections::HashMap<ManifestAssemblyKey, ManifestPageAssembly>,
    pending_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingManifestPageRequest,
    >,
    sync_paths: &PeerSyncPaths,
) {
    let now = Instant::now();
    let keys = assemblies.keys().copied().collect::<Vec<_>>();
    for key in keys {
        if !pending_requests.has_capacity() {
            break;
        }
        let requests = {
            let Some(assembly) = assemblies.get(&key) else {
                continue;
            };
            if assembly.completed.is_some() || assembly.finalization_inflight {
                continue;
            }
            let remaining = MAX_MANIFEST_PAGES_IN_FLIGHT_PER_ASSEMBLY
                .saturating_sub(assembly.in_flight_pages.len());
            let mut requests = Vec::with_capacity(remaining);
            for (index, page) in assembly.header.descriptor_pages.iter().copied().enumerate() {
                let Ok(page_index) = u16::try_from(index) else {
                    break;
                };
                if requests.len() >= remaining
                    || assembly.pages[index].is_some()
                    || assembly.in_flight_pages.contains(&page_index)
                {
                    continue;
                }
                let mut providers = assembly
                    .provider_requester_heights
                    .keys()
                    .copied()
                    .filter(|peer| {
                        !assembly.rejected_providers.contains(peer)
                            && sync_paths.is_dispatchable(*peer)
                            && assembly
                                .retry_after
                                .get(&(page_index, *peer))
                                .is_none_or(|retry| *retry <= now)
                    })
                    .collect::<Vec<_>>();
                providers.sort_by_key(|peer| {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(b"PARANO1D/P2P/MANIFEST-PAGE-SOURCE/V1");
                    hasher.update(&swarm.local_peer_id().to_bytes());
                    hasher.update(&key.snapshot.manifest_digest);
                    hasher.update(&page_index.to_le_bytes());
                    hasher.update(&peer.to_bytes());
                    *hasher.finalize().as_bytes()
                });
                let Some(peer) = providers.first().copied() else {
                    continue;
                };
                requests.push((
                    page_index,
                    peer,
                    SnapshotManifestPageObjectId {
                        snapshot: key.snapshot,
                        page,
                    },
                ));
            }
            requests
        };
        for (page_index, peer, object) in requests {
            if !pending_requests.has_capacity() {
                break;
            }
            let request_id = swarm.behaviour_mut().manifest_page_sync.send_request(
                &peer,
                crate::protocol::GetSnapshotManifestPageRequest { object },
            );
            let inserted = pending_requests.try_insert(
                request_id,
                PendingManifestPageRequest {
                    key,
                    peer,
                    requester_height: assemblies
                        .get(&key)
                        .and_then(|assembly| {
                            assembly.provider_requester_heights.get(&peer).copied()
                        })
                        .unwrap_or_default(),
                    object,
                    requested_manifest_digest: key.snapshot.manifest_digest,
                    issued_at: now,
                },
            );
            if inserted {
                if let Some(assembly) = assemblies.get_mut(&key) {
                    assembly.in_flight_pages.insert(page_index);
                }
            } else {
                debug_assert!(false, "manifest-page capacity checked before request");
            }
        }
    }
}

fn cancel_manifest_page_requests_for_provider(
    key: ManifestAssemblyKey,
    provider: PeerId,
    assemblies: &mut std::collections::HashMap<ManifestAssemblyKey, ManifestPageAssembly>,
    pending_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingManifestPageRequest,
    >,
) {
    let canceled =
        pending_requests.take_where(|pending| pending.key == key && pending.peer == provider);
    if let Some(assembly) = assemblies.get_mut(&key) {
        for pending in canceled {
            assembly.finish_request(pending.object.page.page_index);
        }
    }
}

fn reject_manifest_page_provider(
    key: ManifestAssemblyKey,
    provider: PeerId,
    assemblies: &mut std::collections::HashMap<ManifestAssemblyKey, ManifestPageAssembly>,
    pending_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingManifestPageRequest,
    >,
) {
    cancel_manifest_page_requests_for_provider(key, provider, assemblies, pending_requests);
    if let Some(assembly) = assemblies.get_mut(&key) {
        assembly.reject_provider(provider);
    }
}

/// One peer may contribute to only one unresolved candidate per node
/// generation. A moving peer can replace its previous candidate, but cannot
/// occupy every bounded assembly slot with unrelated headers.
fn detach_manifest_provider_from_other_candidates(
    generation: u64,
    provider: PeerId,
    keep: ManifestAssemblyKey,
    assemblies: &mut std::collections::HashMap<ManifestAssemblyKey, ManifestPageAssembly>,
    pending_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingManifestPageRequest,
    >,
) {
    let old_keys = assemblies
        .iter()
        .filter_map(|(key, assembly)| {
            (key.generation == generation
                && *key != keep
                && (assembly.has_provider(provider)
                    || assembly.rejected_providers.contains(&provider)))
            .then_some(*key)
        })
        .collect::<Vec<_>>();
    for key in old_keys {
        cancel_manifest_page_requests_for_provider(key, provider, assemblies, pending_requests);
        let remove = if let Some(assembly) = assemblies.get_mut(&key) {
            assembly.detach_provider(provider);
            // This is an explicit candidate switch, not transport loss for
            // the same immutable object. With no alternate provider the old
            // partial candidate has no owner and must not occupy a slot.
            !assembly.has_live_providers()
        } else {
            false
        };
        if remove {
            assemblies.remove(&key);
            pending_requests.take_where(|pending| pending.key == key);
        }
    }
}

fn disconnect_manifest_page_provider(
    provider: PeerId,
    assemblies: &mut std::collections::HashMap<ManifestAssemblyKey, ManifestPageAssembly>,
    pending_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingManifestPageRequest,
    >,
) -> Vec<(ManifestAssemblyKey, u64)> {
    let candidates = assemblies
        .iter()
        .filter_map(|(key, assembly)| {
            assembly
                .provider_requester_heights
                .get(&provider)
                .copied()
                .map(|height| (*key, height))
        })
        .collect::<Vec<_>>();
    for (key, _) in &candidates {
        cancel_manifest_page_requests_for_provider(*key, provider, assemblies, pending_requests);
        let remove = if let Some(assembly) = assemblies.get_mut(key) {
            assembly.detach_provider(provider);
            !assembly.has_live_providers() && !assembly.has_local_progress()
        } else {
            false
        };
        if remove {
            assemblies.remove(key);
            pending_requests.take_where(|pending| pending.key == *key);
        }
    }
    candidates
}

async fn emit_verified_manifest_to_new_providers(
    key: ManifestAssemblyKey,
    assembly: &mut ManifestPageAssembly,
    required_event_tx: &RequiredEventSender,
) {
    let Some(manifest) = assembly.completed.clone() else {
        return;
    };
    let providers = assembly
        .provider_requester_heights
        .iter()
        .map(|(peer, requester_height)| (*peer, *requester_height))
        .filter(|(peer, _)| !assembly.delivered_providers.contains(peer))
        .collect::<Vec<_>>();
    for (peer, requester_height) in providers {
        let result = required_event_tx
            .send(NetworkEvent::StateManifest {
                generation: key.generation,
                from: peer,
                requester_height,
                manifest: manifest.clone(),
            })
            .await;
        if result.is_ok() {
            assembly.delivered_providers.insert(peer);
        }
    }
}

fn start_manifest_assembly_if_ready(
    key: ManifestAssemblyKey,
    assembly: &mut ManifestPageAssembly,
    completion: &mpsc::Sender<ManifestAssemblyCompletion>,
) {
    if assembly.completed.is_some()
        || assembly.finalization_inflight
        || !assembly.all_pages_received()
    {
        return;
    }
    let header = Arc::clone(&assembly.header);
    let pages = assembly
        .pages
        .iter()
        .map(|page| {
            Arc::clone(
                &page
                    .as_ref()
                    .expect("all manifest pages checked before assembly")
                    .bytes,
            )
        })
        .collect::<Vec<_>>();
    assembly.finalization_inflight = true;
    let completion = completion.clone();
    tokio::task::spawn_blocking(move || {
        let result = VerifiedStateManifest::from_pages(header.as_ref(), &pages);
        let _ = completion.blocking_send(ManifestAssemblyCompletion { key, result });
    });
}

fn unavailable_state_segment_response(request: &GetStateSegmentRequest) -> GetStateSegmentResponse {
    GetStateSegmentResponse {
        segment_id: request.segment_id,
        expected_tip_height: request.expected_tip_height,
        expected_tip_hash: request.expected_tip_hash,
        manifest_digest: request.manifest_digest,
        status: crate::object_protocol::DataResponseStatus::Ready,
        eff_log: 0,
        data: None,
        inbound_memory_permit: None,
        outbound_memory_permit: None,
    }
}

fn busy_state_segment_response(
    request: &GetStateSegmentRequest,
    retry_after_ms: u16,
) -> GetStateSegmentResponse {
    GetStateSegmentResponse {
        segment_id: request.segment_id,
        expected_tip_height: request.expected_tip_height,
        expected_tip_hash: request.expected_tip_hash,
        manifest_digest: request.manifest_digest,
        status: DataResponseStatus::Busy { retry_after_ms },
        eff_log: 0,
        data: None,
        inbound_memory_permit: None,
        outbound_memory_permit: None,
    }
}

// Hard caps on incoming response sizes are shared via noid_chain::consensus::wire_limits.

fn snapshot_suffix_is_retained(tip_height: u64, terminal_height: u64) -> bool {
    terminal_height <= tip_height
        && tip_height.saturating_sub(terminal_height)
            <= noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH
}

fn retained_object_inventory_floor(tip_height: u64) -> u64 {
    tip_height.saturating_sub(noid_chain::consensus::params::RETAINED_BLOCK_SERVING_DEPTH)
}

fn deterministic_snapshot_boundary_window(
    tip_height: u64,
    finalized_height: u64,
) -> Option<(u64, u64)> {
    if finalized_height > tip_height {
        return None;
    }
    let newest = finalized_height - finalized_height % crate::protocol::SNAPSHOT_BOUNDARY_INTERVAL;
    let oldest = tip_height
        .saturating_sub(noid_chain::consensus::params::UNDO_RETENTION_DEPTH)
        .max(1);
    (newest > 0 && newest >= oldest).then_some((oldest, newest))
}

/// Choose the finalized snapshot boundary only when its exact HistoryStep
/// terminal is durably available.
fn local_history_step_boundary(store: &MdbxStore) -> Option<(u64, [u8; 32])> {
    let meta = store.get_consensus_meta().ok().flatten()?;
    let (oldest, newest) =
        deterministic_snapshot_boundary_window(meta.tip_height, meta.finalized.height)?;

    // Snapshot-installed compact suffix rows intentionally carry local
    // authorization markers rather than duplicate full terminals. Select the
    // newest deterministic checkpoint whose complete terminal is durable.
    // Never fall back to an arbitrary per-node height: exact cross-peer object
    // failover depends on independent exporters producing the same manifest.
    for height in (oldest..=newest)
        .rev()
        .filter(|height| height % crate::protocol::SNAPSHOT_BOUNDARY_INTERVAL == 0)
    {
        let header = store.get_header(height).ok().flatten()?;
        let block_hash = noid_chain::hash_block_header(&header);
        if height == meta.finalized.height && block_hash != meta.finalized.hash {
            return None;
        }
        let has_canonical = store
            .has_history_step_terminal_at(height, block_hash)
            .ok()?;
        let has_cached = store
            .has_any_history_step_proof_object(
                height,
                noid_chain::block_header::semantic_header_id(&header),
            )
            .ok()?;
        if has_canonical || has_cached {
            return Some((height, block_hash));
        }
    }
    None
}

fn load_exact_object(store: &MdbxStore, object: ObjectId) -> Result<Option<Vec<u8>>, String> {
    match object {
        ObjectId::BlockBody(expected) => {
            let canonical = store
                .get_recent_block(expected.claim.height)
                .map_err(|error| format!("read retained block: {error}"))?;
            let bytes = match canonical {
                Some(bytes) => {
                    let matches = noid_chain::Block::from_bytes(&bytes)
                        .ok()
                        .is_some_and(|block| {
                            block.header.height == expected.claim.height
                                && noid_chain::block_header::block_id(&block.header)
                                    == expected.claim.block_hash
                                && expected.matches_bytes(&bytes)
                        });
                    if matches {
                        return Ok(Some(bytes));
                    }
                    store
                        .get_block_body_object(expected.claim.height, expected.claim.block_hash)
                        .map_err(|error| format!("read cached block object: {error}"))?
                }
                None => store
                    .get_block_body_object(expected.claim.height, expected.claim.block_hash)
                    .map_err(|error| format!("read cached block object: {error}"))?,
            };
            let Some(bytes) = bytes else {
                return Ok(None);
            };
            let block = noid_chain::Block::from_bytes(&bytes)
                .map_err(|error| format!("decode cached block object: {error:?}"))?;
            if block.header.height != expected.claim.height
                || noid_chain::block_header::block_id(&block.header) != expected.claim.block_hash
                || !expected.matches_bytes(&bytes)
            {
                return Ok(None);
            }
            Ok(Some(bytes))
        }
        ObjectId::Terminal(expected) => {
            let canonical = store
                .get_header(expected.claim.height)
                .map_err(|error| format!("read terminal header: {error}"))?
                .filter(|header| {
                    noid_chain::block_header::semantic_header_id(header)
                        == expected.claim.semantic_header_id
                });
            let canonical_bytes = match canonical {
                Some(header) => store
                    .get_history_step_terminal_at(
                        expected.claim.height,
                        noid_chain::block_header::block_id(&header),
                    )
                    .map_err(|error| format!("read retained terminal: {error}"))?,
                None => None,
            };
            let Some(bytes) = canonical_bytes.or(store
                .get_history_step_proof_object(
                    expected.claim.height,
                    expected.claim.semantic_header_id,
                    expected.claim.proof_class,
                )
                .map_err(|error| format!("read cached terminal object: {error}"))?)
            else {
                return Ok(None);
            };
            let metadata =
                noid_chain::history_step::HistoryStepTerminalMetadata::decode_prefix(&bytes)
                    .map_err(|error| format!("decode retained terminal metadata: {error}"))?;
            if metadata.terminal_height() != expected.claim.height
                || metadata.terminal_hash() != expected.claim.semantic_header_id
                || metadata.class_id() != expected.claim.proof_class
                || !expected.matches_bytes(&bytes)
            {
                return Ok(None);
            }
            Ok(Some(bytes))
        }
        ObjectId::SnapshotManifest(_) | ObjectId::StateSegment(_) => Ok(None),
    }
}

fn snapshot_boundary_has_live_headroom(live_tip: u64, boundary_height: u64) -> bool {
    boundary_height <= live_tip
        && live_tip.saturating_sub(boundary_height) <= SNAPSHOT_BOUNDARY_MAX_LIVE_GAP
}

fn snapshot_export_selection_rank(
    key: SnapshotExportKey,
    bridge_tip_height: u64,
    leased_keys: &std::collections::HashSet<SnapshotExportKey>,
) -> (bool, u64, u64) {
    (leased_keys.contains(&key), key.0, bridge_tip_height)
}

/// Select one complete immutable generation with ample live-window headroom.
/// New peers join the freshest still-usable leased generation instead of
/// splitting an active bootstrap cohort every time the 30-second exporter
/// publishes a newer boundary. If all generation slots are pinned, a fresh
/// admission fails closed and the requester rotates to another provider; an
/// active exact-generation lease is never revoked underneath a slow client.
/// The state boundary itself may be older than the node's newest finalized
/// checkpoint: its terminal and State segments are generation-owned. The
/// client selects the moving suffix independently from validated headers.
fn select_snapshot_export(
    store: &MdbxStore,
    exports: &std::collections::HashMap<SnapshotExportKey, SnapshotExport>,
    leases: &std::collections::HashMap<PeerId, SnapshotExportLease>,
    disconnect_grace: &SnapshotExportDisconnectGrace,
    requester_height: u64,
    requested_manifest_digest: [u8; 32],
) -> Option<SnapshotExport> {
    let meta = store.get_consensus_meta().ok().flatten()?;
    let now = Instant::now();
    let exact_generation_requested = requested_manifest_digest != [0; 32];
    let leased_keys = leases
        .values()
        .map(|lease| lease.key)
        .chain(disconnect_grace.keys().copied())
        .collect::<std::collections::HashSet<_>>();
    exports
        .values()
        .filter(|generation| {
            let manifest = generation.manifest();
            if now > generation.available_until
                || (!exact_generation_requested && now > generation.join_deadline)
            {
                return false;
            }
            if exact_generation_requested
                && generation.network_manifest.manifest_digest != requested_manifest_digest
            {
                return false;
            }
            if manifest.target_height == 0
                || manifest.target_height > meta.finalized.height
                || manifest.bridge_tip_height < manifest.target_height
                || (!exact_generation_requested && manifest.target_height <= requester_height)
                || (!exact_generation_requested
                    && !snapshot_boundary_has_live_headroom(
                        meta.tip_height,
                        manifest.target_height,
                    ))
            {
                return false;
            }
            let boundary_matches = store
                .get_header(manifest.target_height)
                .ok()
                .flatten()
                .is_some_and(|header| {
                    noid_chain::hash_block_header(&header) == manifest.target_hash
                        && header.state_root == manifest.state_root
                        && header.log_slots == manifest.log_slots
                        && header.active_slot_count == manifest.active_slot_count
                        && header.alloc_counter == manifest.alloc_counter
                });
            let bridge_matches = store
                .get_header(manifest.bridge_tip_height)
                .ok()
                .flatten()
                .is_some_and(|header| {
                    noid_chain::hash_block_header(&header) == manifest.bridge_tip_hash
                });
            let work_matches = store.get_chain_work(manifest.target_height).ok().flatten()
                == Some(manifest.cumulative_chainwork)
                && store
                    .get_chain_work(manifest.bridge_tip_height)
                    .ok()
                    .flatten()
                    == Some(manifest.bridge_cumulative_chainwork);
            boundary_matches && bridge_matches && work_matches
        })
        .max_by_key(|generation| {
            snapshot_export_selection_rank(
                generation.key(),
                generation.manifest().bridge_tip_height,
                &leased_keys,
            )
        })
        .cloned()
}

/// Load one exact canonical HistoryStep terminal. The canonical height table
/// is consulted only inside the bounded recent suffix; the independent proof
/// object store may serve an older exact canonical proof for as long as that
/// verified object remains retained. This lets a node obtain the rounded
/// finalized boundary proof needed to become a snapshot exporter itself.
fn local_history_step_terminal(
    store: &MdbxStore,
    height: u64,
    block_hash: [u8; 32],
) -> Option<Vec<u8>> {
    let tip_height = store.get_consensus_meta().ok().flatten()?.tip_height;
    if height == 0 || height > tip_height {
        return None;
    }
    let header = store.get_header(height).ok().flatten()?;
    if noid_chain::block_header::block_id(&header) != block_hash {
        return None;
    }
    if snapshot_suffix_is_retained(tip_height, height) {
        if let Some(terminal) = store
            .get_history_step_terminal_at(height, block_hash)
            .ok()
            .flatten()
        {
            return Some(terminal);
        }
    }
    store
        .get_any_history_step_proof_object(
            height,
            noid_chain::block_header::semantic_header_id(&header),
        )
        .ok()
        .flatten()
}

/// Check the cheap structural shape of one already allocation-bounded decoded
/// batch. Parent hashes, PoW, ASERT and the remaining consensus rules are
/// checked once by the authoritative node-side header path.
fn validate_header_batch_shape(records: &[HeaderInventoryRecord]) -> Result<(), &'static str> {
    if records.len() > crate::header_sync_codec::MAX_HEADERS_PER_BATCH {
        return Err("header count exceeds cap");
    }
    for pair in records.windows(2) {
        let [parent, header] = pair else {
            unreachable!("windows(2) always has two entries")
        };
        if header.header.height
            != parent
                .header
                .height
                .checked_add(1)
                .ok_or("header height overflow")?
        {
            return Err("header batch is not height-contiguous");
        }
    }
    Ok(())
}

/// Bind an ordinary header response to the exact range requested by this
/// node. Honest peers may return fewer records when they reach their tip, but
/// they may not move the start height or expand a small probe into a bulk
/// HeaderDAG insertion.
fn validate_general_header_response(
    pending: &PendingHeaderRequest,
    records: &[HeaderInventoryRecord],
) -> Result<(), &'static str> {
    debug_assert_eq!(pending.kind, HeaderRequestKind::General);
    validate_header_batch_shape(records)?;
    if records.len() > usize::from(pending.count) {
        return Err("header response exceeds requested count");
    }
    if records
        .first()
        .is_some_and(|record| record.header.height != pending.start_height)
    {
        return Err("header response starts outside the requested range");
    }
    Ok(())
}

fn snapshot_header_request_is_superseded(
    pending: &PendingHeaderRequest,
    generation: u64,
    start_height: u64,
) -> bool {
    matches!(
        pending.kind,
        HeaderRequestKind::Snapshot {
            generation: pending_generation,
            ..
        } if pending_generation != generation || pending.start_height == start_height
    )
}

/// Commands sent to the P2P network event loop.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Announce one complete accepted-block bundle. The event loop chooses
    /// inline gossip or header-only gossip from its canonical encoded size.
    AnnounceBlock { bundle: AcceptedBlockBundle },
    /// Tell current mesh neighbours that this already authenticated header's
    /// exact body and terminal are now locally serveable. This is best-effort
    /// transport metadata, never consensus authority.
    AnnounceAvailability { announcement: HeaderAnnouncement },
    /// Broadcast a new TxIntent to all peers.
    BroadcastTx { intent_bytes: Arc<[u8]> },
    /// Resolve manual GossipSub validation after node-side mempool admission.
    ResolveTxGossip {
        message_id: gossipsub::MessageId,
        propagation_source: PeerId,
        acceptance: gossipsub::MessageAcceptance,
    },
    /// Register a bootstrap address with automatic retry and peer maintenance.
    Dial { addr: Multiaddr },
    /// Initial chain synchronization is complete; bootstrap connections may be
    /// released once enough ordinary outbound peers are available.
    BootstrapComplete,
    /// Get current peer count.
    PeerCount {
        reply: tokio::sync::oneshot::Sender<usize>,
    },
    /// Fetch one exact content-addressed object set from one candidate source.
    /// The token is node-local and is returned unchanged in the result.
    FetchObjects {
        token: u64,
        peer: PeerId,
        objects: Vec<ObjectId>,
    },
    /// Fetch a range of headers from a peer for reorg ancestor search.
    /// Emits `NetworkEvent::HeaderInventoryBatch` with decoded headers and
    /// exact retained-object availability.
    /// Used to find the common ancestor efficiently in O(1) round-trips
    /// instead of O(depth) hop-by-hop backwards traversal.
    FetchHeaders {
        peer: PeerId,
        start_height: u64,
        count: u16, // bounded by the fixed header codec
    },
    /// Fetch one exactly correlated header range for snapshot disk staging.
    ///
    /// Unlike `FetchHeaders`, this request belongs to the exact snapshot
    /// generation and single bounded transfer lane.
    /// `generation`, the node-local `token`, `start_height`, and `count` are
    /// returned unchanged so the node can reject stale or out-of-order
    /// responses without confusing them with reorg/tip probes.
    FetchSnapshotHeaders {
        generation: u64,
        /// Node-local correlation token. It is never sent on the wire.
        token: u64,
        peer: PeerId,
        start_height: u64,
        count: u16,
    },
    /// Request the state manifest from a peer (step 1 of snapshot sync).
    /// Returns metadata + active segment IDs. Emits `NetworkEvent::StateManifest`.
    RequestStateManifest {
        /// Node-local snapshot generation. It is never sent on the wire.
        generation: u64,
        peer: PeerId,
        requester_height: u64,
        requested_manifest_digest: [u8; 32],
    },
    /// Retire every transport job owned by an older node-local snapshot
    /// generation. This is control-plane state: stale page workers and late
    /// responses become inert, while the newly selected generation starts
    /// with the full bounded paging capacity.
    AdvanceSnapshotGeneration { generation: u64 },
    /// Request a single state segment from a peer (step 2, one per segment).
    /// Emits `NetworkEvent::StateSegment`.
    RequestStateSegment {
        peer: PeerId,
        segment_id: u16,
        expected_tip_height: u64,
        expected_tip_hash: [u8; 32],
        manifest_digest: [u8; 32],
    },
    /// Request the fused HistoryStep terminal for an exact snapshot boundary.
    RequestHistoryStepTerminal {
        /// Node-local correlation token. It is never sent on the wire.
        token: u64,
        peer: PeerId,
        height: u64,
        block_hash: [u8; 32],
    },
    /// Retire node notifications for one completed terminal race. Transport
    /// correlation remains until response, failure, or the local deadline so
    /// a pre-substream stall can still be detected and flushed.
    CancelHistoryStepTerminalRace { token: u64 },
    /// Request a peer's mempool contents (all pending TxIntent bytes).
    /// Triggered on peer connect so late-joining nodes receive existing TXs.
    /// Emits `NetworkEvent::MempoolSyncResponse` when the response arrives.
    RequestMempoolSync { peer: PeerId },
}

/// Events emitted by the P2P layer to the node.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// Fixed-size network-v7 header announcement with exact body/terminal IDs.
    HeaderAnnouncement {
        from: PeerId,
        announcement: HeaderAnnouncement,
        /// True only when `from` is the directly connected original
        /// publisher and advertised both exact objects. A gossipsub forwarder
        /// is a header source, not automatically a body/proof provider.
        source_has_objects: bool,
    },
    /// Exact-object response correlated to one immutable planner job.
    ObjectsResponse {
        token: u64,
        from: PeerId,
        objects: Vec<ObjectPayload>,
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
    /// Transport or protocol failure for one exact-object source lease.
    ObjectsRequestFailed {
        token: u64,
        from: PeerId,
        objects: Vec<ObjectId>,
        kind: RequestFailureKind,
    },
    /// The exact provider remains valid, but its bounded bulk-serving lane is
    /// temporarily full. This is not a source failure or unavailability.
    ObjectsRequestBusy {
        token: u64,
        from: PeerId,
        objects: Vec<ObjectId>,
        retry_after_ms: u16,
    },
    /// A new TxIntent arrived from a peer.
    NewTx {
        from: PeerId,
        intent_bytes: Vec<u8>,
        /// Present only for GossipSub delivery. The node resolves this after
        /// authoritative mempool admission.
        gossip_message_id: Option<gossipsub::MessageId>,
        /// Direct-push requests reserve their decoded bytes process-globally
        /// until node-side admission finishes. Gossip messages carry `None`.
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
    /// Response to FetchHeaders: decoded headers plus exact retained-object
    /// availability from the peer. Used by HeaderDAG and immutable plans.
    HeaderInventoryBatch {
        from: PeerId,
        records: Vec<HeaderInventoryRecord>,
        snapshot_boundary: Option<crate::object_protocol::ChainPoint>,
    },
    /// Transport or decoding failed for one exact header request.
    HeadersRequestFailed {
        from: PeerId,
        start_height: u64,
        count: u16,
        kind: RequestFailureKind,
    },
    /// Exactly correlated response for snapshot header staging.
    SnapshotHeadersBatch {
        generation: u64,
        token: u64,
        from: PeerId,
        start_height: u64,
        requested_count: u16,
        headers: Vec<noid_chain::block_header::BlockHeader>,
        snapshot_boundary: Option<crate::object_protocol::ChainPoint>,
    },
    /// Transport or decoding failed for one exact snapshot header range.
    SnapshotHeadersRequestFailed {
        generation: u64,
        token: u64,
        from: PeerId,
        start_height: u64,
        count: u16,
        kind: RequestFailureKind,
    },
    /// State manifest received from a peer (step 1 of snapshot sync).
    StateManifest {
        generation: u64,
        from: PeerId,
        requester_height: u64,
        manifest: crate::protocol::VerifiedStateManifest,
    },
    /// Transport failed for one exactly correlated state-manifest request.
    StateManifestRequestFailed {
        generation: u64,
        from: PeerId,
        requester_height: u64,
        requested_manifest_digest: [u8; 32],
        kind: RequestFailureKind,
    },
    /// One state segment received from a peer (step 2).
    StateSegment {
        from: PeerId,
        response: crate::protocol::GetStateSegmentResponse,
    },
    /// Transport failed for one exact state-segment request.
    StateSegmentRequestFailed {
        from: PeerId,
        segment_id: u16,
        expected_tip_height: u64,
        expected_tip_hash: [u8; 32],
        manifest_digest: [u8; 32],
        kind: RequestFailureKind,
    },
    StateSegmentRequestBusy {
        from: PeerId,
        segment_id: u16,
        expected_tip_height: u64,
        expected_tip_hash: [u8; 32],
        manifest_digest: [u8; 32],
        retry_after_ms: u16,
    },
    /// Fused HistoryStep terminal response for O(1) snapshot sync.
    HistoryStepTerminal {
        /// Exact node-local token supplied with the corresponding request.
        token: u64,
        from: PeerId,
        height: u64,
        block_hash: [u8; 32],
        /// Exact-bound HistoryStep terminal bytes, or empty when unavailable.
        terminal_bytes: Vec<u8>,
        /// Holds the process-global inbound terminal byte budget until the node
        /// finishes verifying this response.
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
    /// Transport failed for one exact HistoryStep terminal request. The
    /// request tuple remains available so snapshot sync can preserve unrelated
    /// staged headers and report the real transport failure.
    HistoryStepTerminalRequestFailed {
        token: u64,
        from: PeerId,
        height: u64,
        block_hash: [u8; 32],
        kind: RequestFailureKind,
    },
    HistoryStepTerminalRequestBusy {
        token: u64,
        from: PeerId,
        height: u64,
        block_hash: [u8; 32],
        retry_after_ms: u16,
    },
    /// Mempool sync response: raw TxIntent bytes from a peer's mempool.
    /// Received after sending `RequestMempoolSync` on peer connect.
    MempoolSyncResponse {
        from: PeerId,
        /// Raw TxIntent bytes, one per pending transaction.
        txs: Vec<Vec<u8>>,
        /// Holds the process-global inbound mempool byte budget until node-side
        /// submission has consumed this response.
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
    /// A peer connected.
    PeerConnected {
        peer: PeerId,
        /// True when this identity was deliberately selected by the local
        /// topology manager. This survives simultaneous cross-dial collapse
        /// even if libp2p keeps the inbound physical half. Node-side bootstrap
        /// pulls are restricted to this bounded set so a public seed does not
        /// reciprocate every inbound wallet connection.
        locally_selected: bool,
        /// Coarse public network group (IPv4 /16, IPv6 /32), or an
        /// identity-derived domain for private/LAN transports.
        failure_domain: u64,
    },
    /// A peer disconnected.
    PeerDisconnected(PeerId),
}

/// Receive side for node-facing P2P events.
///
/// Required request/response results use a bounded, backpressured MPSC queue;
/// recoverable gossip and peer-lifecycle notifications use broadcast and may
/// report lag. This prevents a slow consumer from retaining unbounded gossip
/// or silently losing a requested exact-object response.
pub struct NetworkEventReceiver {
    required_rx: RequiredEventReceiver,
    gossip_rx: tokio::sync::broadcast::Receiver<NetworkEvent>,
    required_closed: bool,
    gossip_closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEventRecvError {
    /// Recoverable gossip notifications were overwritten while the consumer
    /// was busy. Required sync responses never use this queue.
    Lagged(u64),
    /// Both event producers have closed.
    Closed,
}

impl NetworkEventReceiver {
    pub async fn recv(&mut self) -> Result<NetworkEvent, NetworkEventRecvError> {
        loop {
            match (self.required_closed, self.gossip_closed) {
                (true, true) => return Err(NetworkEventRecvError::Closed),
                (true, false) => match self.gossip_rx.recv().await {
                    Ok(event) => return Ok(event),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        return Err(NetworkEventRecvError::Lagged(skipped));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        self.gossip_closed = true;
                    }
                },
                (false, true) => match self.required_rx.recv().await {
                    Some(event) => return Ok(event),
                    None => self.required_closed = true,
                },
                (false, false) => {
                    tokio::select! {
                        // Sync progress is authoritative and should not sit behind
                        // a flood of replaceable announcements.
                        biased;
                        event = self.required_rx.recv() => match event {
                            Some(event) => return Ok(event),
                            None => self.required_closed = true,
                        },
                        event = self.gossip_rx.recv() => match event {
                            Ok(event) => return Ok(event),
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                return Err(NetworkEventRecvError::Lagged(skipped));
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                self.gossip_closed = true;
                            }
                        }
                    }
                }
            }
        }
    }
}

// Recoverable gossip is deliberately separate from required exact-object and
// snapshot results. Backpressure begins before a second data wave can
// accumulate without delaying header/control delivery.
const GOSSIP_EVENT_QUEUE_CAPACITY: usize = 64;

/// The P2P network manager.
pub struct P2PNetwork {
    /// Channel to send commands to the event loop.
    pub cmd_tx: NetworkCommandSender,
    /// Subscribe to events from the event loop.
    gossip_event_tx: tokio::sync::broadcast::Sender<NetworkEvent>,
    required_event_rx: std::sync::Mutex<Option<RequiredEventReceiver>>,
    health_rx: tokio::sync::watch::Receiver<P2PHealthSnapshot>,
}

#[derive(Clone, Debug)]
pub struct P2PHealthSnapshot {
    pub sequence: u64,
    pub updated_at: Instant,
    pub connected_peers: usize,
    pub dispatchable_peers: usize,
    pub relay_reservations: usize,
    pub control_queue: usize,
    pub header_queue: usize,
    pub data_queue: usize,
    pub pending_requests: usize,
    pub active_data_serving_slots: usize,
    pub outstanding_data_serving_slots: usize,
}

impl Default for P2PHealthSnapshot {
    fn default() -> Self {
        Self {
            sequence: 0,
            updated_at: Instant::now(),
            connected_peers: 0,
            dispatchable_peers: 0,
            relay_reservations: 0,
            control_queue: 0,
            header_queue: 0,
            data_queue: 0,
            pending_requests: 0,
            active_data_serving_slots: 0,
            outstanding_data_serving_slots: 0,
        }
    }
}

impl P2PNetwork {
    /// Build and start the P2P network.
    ///
    /// `topics` controls which gossipsub topics to subscribe to and which
    /// stream protocol IDs to use for sync — use
    /// `NetworkTopics::for_network_cfg(cfg)` to get the right network.
    pub fn start(
        listen_addr: Multiaddr,
        public_addresses: Vec<Multiaddr>,
        chain: Arc<RwLock<MdbxChainContext>>,
        mempool: AsyncMempool,
        topics: NetworkTopics,
        history_proof_bank_id: [u8; 32],
        data_dir: std::path::PathBuf,
        background_capacity: BackgroundCapacity,
    ) -> anyhow::Result<(Self, tokio::task::JoinHandle<anyhow::Result<()>>)> {
        // Load before spawning so an absent, corrupt, symlinked, or publicly
        // readable private identity fails node startup instead of silently
        // leaving RPC alive with a dead P2P task.
        let identity = crate::identity_store::load_or_create(&data_dir)?;
        let local_peer_id = identity.public().to_peer_id();
        tracing::info!(peer = %local_peer_id, "loaded persistent P2P identity");
        let (cmd_tx, cmd_rx) = command_dispatch::channel();
        let (gossip_event_tx, _) = tokio::sync::broadcast::channel(GOSSIP_EVENT_QUEUE_CAPACITY);
        let (required_event_tx, required_event_rx) = event_dispatch::channel();
        let (health_tx, health_rx) = tokio::sync::watch::channel(P2PHealthSnapshot::default());

        let gossip_event_tx_clone = gossip_event_tx.clone();
        let handle = tokio::spawn(async move {
            run_swarm(
                listen_addr,
                public_addresses,
                cmd_rx,
                gossip_event_tx_clone,
                required_event_tx,
                chain,
                mempool,
                topics,
                history_proof_bank_id,
                data_dir,
                identity,
                health_tx,
                background_capacity,
            )
            .await
        });

        Ok((
            Self {
                cmd_tx,
                gossip_event_tx,
                required_event_rx: std::sync::Mutex::new(Some(required_event_rx)),
                health_rx,
            },
            handle,
        ))
    }

    /// Attach the node's single authoritative event consumer.
    ///
    /// Sync responses cannot be broadcast safely because lagging receivers
    /// silently lose entries. There is deliberately exactly one such consumer.
    pub fn subscribe(&self) -> NetworkEventReceiver {
        let required_rx = self
            .required_event_rx
            .lock()
            .expect("P2P required event receiver mutex poisoned")
            .take()
            .expect("P2P event receiver may only be subscribed once");
        NetworkEventReceiver {
            required_rx,
            gossip_rx: self.gossip_event_tx.subscribe(),
            required_closed: false,
            gossip_closed: false,
        }
    }

    pub fn health_receiver(&self) -> tokio::sync::watch::Receiver<P2PHealthSnapshot> {
        self.health_rx.clone()
    }

    /// Announce one complete accepted block to all peers.
    pub async fn announce_block(&self, bundle: AcceptedBlockBundle) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::AnnounceBlock { bundle })
            .await;
    }

    pub async fn broadcast_tx(&self, intent_bytes: Vec<u8>) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::BroadcastTx {
                intent_bytes: intent_bytes.into(),
            })
            .await;
    }

    pub async fn dial(&self, addr: Multiaddr) {
        let _ = self.cmd_tx.send(NetworkCommand::Dial { addr }).await;
    }

    pub async fn mark_bootstrap_complete(&self) {
        let _ = self.cmd_tx.send(NetworkCommand::BootstrapComplete).await;
    }

    /// Request the state manifest from a peer (step 1 of snapshot sync).
    pub async fn request_state_manifest(&self, peer: PeerId) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestStateManifest {
                generation: 0,
                peer,
                requester_height: 0,
                requested_manifest_digest: [0; 32],
            })
            .await;
    }

    /// Request a single state segment from a peer (step 2).
    pub async fn request_state_segment(
        &self,
        peer: PeerId,
        segment_id: u16,
        expected_tip_height: u64,
        expected_tip_hash: [u8; 32],
        manifest_digest: [u8; 32],
    ) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestStateSegment {
                peer,
                segment_id,
                expected_tip_height,
                expected_tip_hash,
                manifest_digest,
            })
            .await;
    }

    /// Request the HistoryStep terminal for an exact snapshot boundary.
    pub async fn request_history_step_terminal(
        &self,
        token: u64,
        peer: PeerId,
        height: u64,
        block_hash: [u8; 32],
    ) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestHistoryStepTerminal {
                token,
                peer,
                height,
                block_hash,
            })
            .await;
    }

    /// Request all pending transactions from a peer's mempool.
    /// Used on peer connect so late-joining nodes receive existing TXs.
    pub async fn request_mempool_sync(&self, peer: PeerId) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestMempoolSync { peer })
            .await;
    }

    /// Get peer count via an existing command channel (for RPC handler).
    pub async fn peer_count_via(cmd: &NetworkCommandSender) -> usize {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = cmd.send(NetworkCommand::PeerCount { reply: tx }).await;
        rx.await.unwrap_or(0)
    }

    pub async fn peer_count(&self) -> usize {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self
            .cmd_tx
            .send(NetworkCommand::PeerCount { reply: tx })
            .await;
        rx.await.unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Swarm event loop
// ---------------------------------------------------------------------------

async fn run_swarm(
    listen_addr: Multiaddr,
    public_addresses: Vec<Multiaddr>,
    mut cmd_rx: NetworkCommandReceiver,
    gossip_event_tx: tokio::sync::broadcast::Sender<NetworkEvent>,
    required_event_tx: RequiredEventSender,
    chain: Arc<RwLock<MdbxChainContext>>,
    mempool: AsyncMempool,
    topics: NetworkTopics,
    history_proof_bank_id: [u8; 32],
    data_dir: std::path::PathBuf,
    identity: libp2p::identity::Keypair,
    health_tx: tokio::sync::watch::Sender<P2PHealthSnapshot>,
    background_capacity: BackgroundCapacity,
) -> anyhow::Result<()> {
    use libp2p::{noise, tcp, yamux, SwarmBuilder};

    // P2P data serving must remain responsive while expensive block proof
    // verification owns the mutable hot chain context. MDBX readers use
    // independent MVCC snapshots and never need that application-level lock.
    let chain_store = {
        let ctx = chain.read().await;
        ctx.store.clone()
    };

    let protocol_id = topics.protocol_id.clone();
    let network_profile = NetworkProfile::for_proof_bank(history_proof_bank_id);
    let public_relay_enabled = !public_addresses.is_empty();
    let mut swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_dns()?
        // Relay client transport: enables dialling and listening through relay
        // nodes.  The relay::client::Behaviour is wired here by the builder
        // and passed into NodeBehaviour::new() via the closure below.
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(move |key, relay_client| {
            NodeBehaviour::new(
                key,
                &protocol_id,
                relay_client,
                background_capacity,
                public_relay_enabled,
            )
        })?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(std::time::Duration::from_secs(300))
                // A peer can advertise one direct path plus several relay
                // paths. Swarm's default factor races up to eight addresses
                // for one logical dial, so a simultaneous wallet launch can
                // multiply one Kademlia edge into eight accepted relay
                // circuits before duplicate-path canonicalisation runs.
                // Try exact paths sequentially instead: this bounds carrier
                // load without reducing the number of distinct neighbours
                // that discovery may select.
                .with_dial_concurrency_factor(std::num::NonZeroU8::new(1).expect("one is non-zero"))
        })
        .build();

    // A wildcard listen socket is not a public address. Circuit Relay v2
    // reservations are unusable unless the relay returns at least one
    // externally reachable address, and Identify must advertise the same
    // direct path to ordinary peers. Public operators declare those addresses
    // explicitly; private GUI nodes leave the list empty and reserve paths
    // through public peers instead.
    for address in public_addresses {
        let has_public_ip = crate::peer_diversity::contains_public_ip(&address);
        let has_tcp = address.iter().any(
            |protocol| matches!(protocol, libp2p::multiaddr::Protocol::Tcp(port) if port != 0),
        );
        let has_identity_or_relay_component = address.iter().any(|protocol| {
            matches!(
                protocol,
                libp2p::multiaddr::Protocol::P2p(_) | libp2p::multiaddr::Protocol::P2pCircuit
            )
        });
        if !has_public_ip || !has_tcp || has_identity_or_relay_component {
            anyhow::bail!(
                "invalid public P2P address {address}: expected a globally routable IP/TCP address without /p2p or /p2p-circuit"
            );
        }
        tracing::info!(%address, "registered public P2P address");
        swarm.add_external_address(address);
    }

    // Subscribe to network-specific gossip topics.
    let blocks_topic = gossipsub::IdentTopic::new(topics.blocks.clone());
    let txs_topic = gossipsub::IdentTopic::new(topics.txs.clone());
    swarm.behaviour_mut().gossipsub.subscribe(&blocks_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&txs_topic)?;

    swarm.listen_on(listen_addr)?;

    // After subscribing and listening, kick off Kademlia bootstrap.
    // This triggers FIND_NODE walks starting from any peers already in the
    // routing table (populated when seeds connect and identify fires).
    // The bootstrap is a no-op if the routing table is empty; it will be
    // re-triggered automatically when the first peer is added via identify.
    // Load only previously successful outbound peers. They seed Kademlia and
    // enter the same bounded automatic manager as DNS bootstrap sources, so a
    // restart cannot create a second untracked dial burst.
    let mut successful_peer_cache = crate::peer_store::load(&data_dir);
    let local_peer_id = *swarm.local_peer_id();
    let mut automatic_peers = AutomaticPeerState::new(local_peer_id);
    for peer in successful_peer_cache.entries() {
        automatic_peers.add_peer_candidate(local_peer_id, peer.peer_id, peer.addrs.iter().cloned());
    }
    let cached_peer_count = successful_peer_cache.entries().count();
    if cached_peer_count > 0 {
        tracing::debug!(
            count = cached_peer_count,
            "peer store: seeding Kademlia from successful outbound cache"
        );
        for peer in successful_peer_cache.entries() {
            for addr in &peer.addrs {
                swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&peer.peer_id, addr.clone());
            }
        }
    }

    // Do not start a Kademlia walk from disk cache alone. A stale cached
    // address can otherwise hold the single discovery slot for the full query
    // timeout while a live DNS seed is already connected. Identify starts the
    // first bootstrap only after a transport has proved live.

    // Cheap P2P-layer DoS guards that run before emitting NetworkEvent into
    // the bounded broadcast channel.
    let mut block_event_rate: std::collections::HashMap<PeerId, (u32, Instant)> =
        std::collections::HashMap::new();
    let mut tx_gossip_rate: std::collections::HashMap<PeerId, (u32, Instant)> =
        std::collections::HashMap::new();
    let mut gossip_accept_bytes = GossipByteWindow::new();
    let mut mempool_sync_last_request: std::collections::HashMap<PeerId, Instant> =
        std::collections::HashMap::new();
    let mut mempool_sync_retries: std::collections::HashMap<PeerId, MempoolSyncRetry> =
        std::collections::HashMap::new();
    let mut snapshot_segment_rate: std::collections::HashMap<PeerId, (u32, Instant)> =
        std::collections::HashMap::new();
    let mut pending_network_profile_requests =
        BoundedPendingRequests::new(MAX_PENDING_NETWORK_PROFILE_REQUESTS);
    let mut pending_object_requests = BoundedPendingRequests::new(MAX_PENDING_OBJECT_REQUESTS);
    let mut pending_header_requests = BoundedPendingRequests::new(MAX_PENDING_HEADER_REQUESTS);
    let mut pending_state_manifest_requests =
        BoundedPendingRequests::new(MAX_PENDING_STATE_MANIFEST_REQUESTS);
    let mut pending_manifest_page_requests =
        BoundedPendingRequests::new(MAX_MANIFEST_PAGE_REQUESTS);
    let mut manifest_page_assemblies =
        std::collections::HashMap::<ManifestAssemblyKey, ManifestPageAssembly>::new();
    let mut rejected_manifest_candidates =
        std::collections::HashMap::<ManifestAssemblyKey, Instant>::new();
    let mut latest_manifest_generation = 0u64;
    let mut pending_state_segment_requests =
        BoundedPendingRequests::new(MAX_PENDING_STATE_SEGMENT_REQUESTS);
    let mut pending_history_step_requests =
        BoundedPendingRequests::new(MAX_PENDING_HISTORY_STEP_REQUESTS);
    let mut peer_diversity = PeerDiversity::default();
    let mut sync_paths = PeerSyncPaths::default();
    // A directly reachable public node is already discoverable and should
    // contribute bounded relay capacity, not build nested relay paths through
    // other public nodes. Private nodes reserve two diverse public paths.
    let relay_reservation_target = if public_relay_enabled {
        0
    } else {
        MAX_RELAY_RESERVATIONS
    };
    let mut relay_reservations =
        RelayReservations::new(relay_reservation_target, *swarm.local_peer_id());
    let mut relay_circuit_backoff = RelayCircuitBackoff::default();

    // One waiting response of each kind is sufficient: the request-response
    // behaviour owns the next response while its codec writes it. Byte permits
    // retained by both stages are the process-wide RAM bound.
    let (header_response_tx, mut header_response_rx) = mpsc::channel::<PendingHeaderResponse>(1);
    let (history_step_response_tx, mut history_step_response_rx) =
        mpsc::channel::<PendingHistoryStepTerminalResponse>(1);
    let (segment_response_tx, mut segment_response_rx) =
        mpsc::channel::<PendingStateSegmentResponse>(1);
    let (manifest_page_response_tx, mut manifest_page_response_rx) =
        mpsc::channel::<PendingManifestPageResponse>(2);
    let (manifest_page_verify_tx, mut manifest_page_verify_rx) =
        mpsc::channel::<ManifestPageVerificationCompletion>(4);
    let (manifest_assembly_tx, mut manifest_assembly_rx) =
        mpsc::channel::<ManifestAssemblyCompletion>(2);
    let (mempool_response_tx, mut mempool_response_rx) = mpsc::channel::<PendingMempoolResponse>(1);
    let (object_response_tx, mut object_response_rx) = mpsc::channel::<PendingObjectResponse>(4);
    let header_response_prepare_semaphore = Arc::new(Semaphore::new(
        background_capacity.header_response_prepare_slots(),
    ));
    let history_step_response_prepare_semaphore = Arc::new(Semaphore::new(4));
    let segment_encode_semaphore = Arc::new(Semaphore::new(2));
    let mempool_response_prepare_semaphore = Arc::new(Semaphore::new(1));
    let outbound_response_budget = OutboundResponseBudget::process_global();
    let mut data_plane_serving = DataPlaneServingAdmission::new(background_capacity);
    let snapshot_export_root = data_dir.join("snapshot-exports");
    std::fs::create_dir_all(&snapshot_export_root)?;
    let mut snapshot_exports = load_snapshot_exports(&snapshot_export_root);
    let mut snapshot_export_leases: std::collections::HashMap<PeerId, SnapshotExportLease> =
        std::collections::HashMap::new();
    let mut snapshot_export_disconnect_grace = SnapshotExportDisconnectGrace::new();
    prune_snapshot_exports(
        &mut snapshot_exports,
        &snapshot_export_leases,
        &snapshot_export_disconnect_grace,
    );
    let (snapshot_export_tx, mut snapshot_export_rx) =
        mpsc::channel::<(SnapshotExportKey, PreparedSnapshotExport)>(1);
    let mut snapshot_export_inflight: Option<SnapshotExportKey> = None;
    let mut snapshot_export_timer = tokio::time::interval(Duration::from_secs(30));
    snapshot_export_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Keep user-visible peer counts and queue telemetry close to the actual
    // reactor state.  A ten-second publication interval made a newly connected
    // GUI briefly report zero peers even while header sync was already active.
    let mut reactor_health_timer = tokio::time::interval(Duration::from_secs(1));
    reactor_health_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    reactor_health_timer.tick().await;

    // Keep retry jitter effective under a large simultaneous fan-in. Folding
    // this into the two-second peer-maintenance tick would release every due peer
    // as one batch and recreate the handshake herd we are avoiding.
    let mut mempool_retry_timer = tokio::time::interval(Duration::from_millis(250));
    mempool_retry_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    mempool_retry_timer.tick().await; // skip first immediate tick

    // Peer store save timer: persist routing table every 5 minutes.
    let mut peer_store_timer = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
    peer_store_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    peer_store_timer.tick().await; // skip first immediate tick

    let mut automatic_peer_timer = tokio::time::interval(Duration::from_secs(2));
    automatic_peer_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        if required_event_tx.has_fatal_dispatch_failure() {
            anyhow::bail!(
                "required node-event lane overflowed or closed; refusing to run with lost request correlation"
            );
        }
        // Drain all pending commands first (priority: outgoing blocks must propagate
        // immediately without waiting for swarm event processing).
        for _ in 0..32 {
            let Ok(cmd) = cmd_rx.try_recv() else {
                break;
            };
            handle_network_command(
                &mut swarm,
                cmd,
                &topics,
                &mut mempool_sync_last_request,
                &mut mempool_sync_retries,
                &required_event_tx,
                &mut pending_object_requests,
                &mut pending_header_requests,
                &mut pending_state_manifest_requests,
                &mut pending_manifest_page_requests,
                &mut manifest_page_assemblies,
                &mut rejected_manifest_candidates,
                &mut latest_manifest_generation,
                &mut pending_state_segment_requests,
                &mut pending_history_step_requests,
                &mut automatic_peers,
                &mut successful_peer_cache,
                &sync_paths,
            )
            .await;
        }

        tokio::select! {
            // Swarm events.
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    &mut swarm,
                    event,
                    &gossip_event_tx,
                    &required_event_tx,
                    &chain_store,
                    &mempool,
                    &topics,
                    &network_profile,
                    &header_response_tx,
                    &header_response_prepare_semaphore,
                    &history_step_response_tx,
                    &history_step_response_prepare_semaphore,
                    &segment_response_tx,
                    &segment_encode_semaphore,
                    &manifest_page_response_tx,
                    &manifest_page_verify_tx,
                    &manifest_assembly_tx,
                    &mempool_response_tx,
                    &mempool_response_prepare_semaphore,
                    &object_response_tx,
                    &outbound_response_budget,
                    &mut data_plane_serving,
                    &mut snapshot_exports,
                    &mut snapshot_export_leases,
                    &mut snapshot_export_disconnect_grace,
                    &mut block_event_rate,
                    &mut tx_gossip_rate,
                    &mut gossip_accept_bytes,
                    &mut mempool_sync_last_request,
                    &mut mempool_sync_retries,
                    &mut snapshot_segment_rate,
                    &mut pending_network_profile_requests,
                    &mut pending_object_requests,
                    &mut pending_header_requests,
                    &mut pending_state_manifest_requests,
                    &mut pending_manifest_page_requests,
                    &mut pending_state_segment_requests,
                    &mut pending_history_step_requests,
                    &mut automatic_peers,
                    &mut peer_diversity,
                    &mut sync_paths,
                    &mut manifest_page_assemblies,
                    &mut rejected_manifest_candidates,
                    &mut relay_reservations,
                    &mut relay_circuit_backoff,
                    &mut successful_peer_cache,
                )
                .await;
            }

            prepared = header_response_rx.recv() => {
                if let Some(prepared) = prepared {
                    let _ = swarm
                        .behaviour_mut()
                        .chain_sync
                        .send_response(prepared.channel, prepared.response);
                }
            }

            prepared = history_step_response_rx.recv() => {
                if let Some(prepared) = prepared {
                    let height = prepared.response.height;
                    let block_hash = prepared.response.block_hash;
                    let terminal_len = prepared
                        .response
                        .terminal_bytes
                        .as_ref()
                        .map_or(0, Vec::len);
                    let served_exact_snapshot_terminal = terminal_len > 0;
                    match swarm
                        .behaviour_mut()
                        .history_step_sync
                        .send_response(prepared.channel, prepared.response)
                    {
                        Ok(()) => {
                            if served_exact_snapshot_terminal {
                                if let Some(key) = prepared.snapshot_lease_key {
                                    refresh_snapshot_export_lease_after_service(
                                        &mut snapshot_export_leases,
                                        prepared.peer,
                                        key,
                                        None,
                                        SnapshotLeaseProgress::Terminal {
                                            height,
                                            block_hash,
                                        },
                                    );
                                }
                            }
                            tracing::debug!(
                                height,
                                terminal_len,
                                "queued HistoryStep terminal response"
                            );
                        }
                        Err(_) => tracing::warn!(
                            height,
                            terminal_len,
                            "HistoryStep response channel closed before queueing"
                        ),
                    }
                }
            }

            // Completed bounded disk reads. Responses must be sent from the
            // swarm task, while segment authentication/I/O runs on workers.
            encoded = segment_response_rx.recv() => {
                if let Some(encoded) = encoded {
                    let served_exact_snapshot_segment = encoded.response.data.is_some();
                    let segment_id = encoded.response.segment_id;
                    let queued = swarm
                        .behaviour_mut()
                        .state_segment_sync
                        .send_response(encoded.channel, encoded.response);
                    if queued.is_ok() && served_exact_snapshot_segment {
                        if let Some((key, manifest_digest)) = encoded.snapshot_lease {
                            refresh_snapshot_export_lease_after_service(
                                &mut snapshot_export_leases,
                                encoded.peer,
                                key,
                                Some(manifest_digest),
                                SnapshotLeaseProgress::Segment(segment_id),
                            );
                        }
                    }
                }
            }

            prepared = manifest_page_response_rx.recv() => {
                if let Some(prepared) = prepared {
                    let served = prepared.response.data.is_some();
                    let page_index = prepared.response.object.page.page_index;
                    let queued = swarm
                        .behaviour_mut()
                        .manifest_page_sync
                        .send_response(prepared.channel, prepared.response);
                    if queued.is_ok() && served {
                        if let Some((key, manifest_digest)) = prepared.snapshot_lease {
                            refresh_snapshot_export_lease_after_service(
                                &mut snapshot_export_leases,
                                prepared.peer,
                                key,
                                Some(manifest_digest),
                                SnapshotLeaseProgress::ManifestPage(page_index),
                            );
                        }
                    }
                }
            }

            verified = manifest_page_verify_rx.recv() => {
                if let Some(verified) = verified {
                    let key = verified.pending.key;
                    let mut reject_provider = false;
                    if let Some(assembly) = manifest_page_assemblies.get_mut(&key) {
                        assembly.finish_request(verified.pending.object.page.page_index);
                        let expected = assembly
                            .header
                            .descriptor_pages
                            .get(usize::from(verified.pending.object.page.page_index))
                            .copied();
                        if assembly.rejected_providers.contains(&verified.pending.peer)
                            || expected != Some(verified.pending.object.page)
                            || !verified.digest_valid
                        {
                            reject_provider = true;
                        } else if let Some(bytes) = verified.response.data {
                            let index = usize::from(verified.pending.object.page.page_index);
                            if assembly.pages[index].is_none() {
                                assembly.pages[index] = Some(VerifiedManifestPageBytes {
                                    bytes,
                                    _inbound_memory_permit: verified.response.inbound_memory_permit,
                                });
                                assembly.last_progress = Instant::now();
                            }
                        } else {
                            // A peer that advertised the exact complete
                            // generation but cannot serve one committed page
                            // is not a source for any object in that plan.
                            reject_provider = true;
                        }
                        if !reject_provider {
                            start_manifest_assembly_if_ready(
                                key,
                                assembly,
                                &manifest_assembly_tx,
                            );
                        }
                    }
                    if reject_provider {
                        reject_manifest_page_provider(
                            key,
                            verified.pending.peer,
                            &mut manifest_page_assemblies,
                            &mut pending_manifest_page_requests,
                        );
                        let _ = required_event_tx
                            .send(NetworkEvent::StateManifestRequestFailed {
                                generation: key.generation,
                                from: verified.pending.peer,
                                requester_height: verified.pending.requester_height,
                                requested_manifest_digest: verified.pending.requested_manifest_digest,
                                kind: RequestFailureKind::InvalidResponse,
                            })
                            .await;
                    }
                    schedule_manifest_page_requests(
                        &mut swarm,
                        &mut manifest_page_assemblies,
                        &mut pending_manifest_page_requests,
                        &sync_paths,
                    );
                }
            }

            completed = manifest_assembly_rx.recv() => {
                if let Some(completed) = completed {
                    let mut invalid_providers = Vec::new();
                    if let Some(assembly) = manifest_page_assemblies.get_mut(&completed.key) {
                        assembly.finalization_inflight = false;
                        match completed.result {
                            Some(manifest) => {
                                assembly.completed = Some(manifest);
                                // Descriptor pages are no longer needed once
                                // the verified immutable manifest exists.
                                assembly.pages.clear();
                                assembly.in_flight_pages.clear();
                                assembly.last_progress = Instant::now();
                                emit_verified_manifest_to_new_providers(
                                    completed.key,
                                    assembly,
                                    &required_event_tx,
                                )
                                .await;
                            }
                            None => {
                                invalid_providers.extend(
                                    assembly
                                        .provider_requester_heights
                                        .iter()
                                        .map(|(peer, height)| (*peer, *height)),
                                );
                            }
                        }
                    }
                    if !invalid_providers.is_empty() {
                        if rejected_manifest_candidates.len()
                            >= MAX_MANIFEST_CANDIDATE_TOMBSTONES
                        {
                            if let Some(oldest) = rejected_manifest_candidates
                                .iter()
                                .min_by_key(|(_, rejected_at)| **rejected_at)
                                .map(|(key, _)| *key)
                            {
                                rejected_manifest_candidates.remove(&oldest);
                            }
                        }
                        rejected_manifest_candidates
                            .insert(completed.key, Instant::now());
                        manifest_page_assemblies.remove(&completed.key);
                        for (peer, requester_height) in invalid_providers {
                            let _ = required_event_tx
                                .send(NetworkEvent::StateManifestRequestFailed {
                                    generation: completed.key.generation,
                                    from: peer,
                                    requester_height,
                                    requested_manifest_digest: completed.key.snapshot.manifest_digest,
                                    kind: RequestFailureKind::InvalidResponse,
                                })
                                .await;
                        }
                    }
                }
            }

            prepared = mempool_response_rx.recv() => {
                if let Some(prepared) = prepared {
                    let _ = swarm
                        .behaviour_mut()
                        .mempool_sync
                        .send_response(prepared.channel, prepared.response);
                }
            }

            prepared = object_response_rx.recv() => {
                if let Some(prepared) = prepared {
                    let _ = swarm
                        .behaviour_mut()
                        .object_sync
                        .send_response(prepared.channel, prepared.response);
                }
            }

            completed = snapshot_export_rx.recv() => {
                if let Some((key, result)) = completed {
                    snapshot_export_inflight = None;
                    match result {
                        PreparedSnapshotExport::Ready(export) if export.key() == key => {
                            tracing::info!(height = key.0, "published bounded disk snapshot generation");
                            snapshot_exports.insert(key, Arc::new(export));
                            prune_snapshot_export_leases(&mut snapshot_export_leases);
                            prune_snapshot_export_disconnect_grace(
                                &mut snapshot_export_disconnect_grace,
                            );
                            refresh_snapshot_object_retention_floor(
                                &chain_store,
                                &snapshot_export_leases,
                                &snapshot_export_disconnect_grace,
                            );
                            prune_snapshot_exports(
                                &mut snapshot_exports,
                                &snapshot_export_leases,
                                &snapshot_export_disconnect_grace,
                            );
                        }
                        PreparedSnapshotExport::Ready(_) => {
                            tracing::warn!(height = key.0, "snapshot generation boundary mismatch")
                        }
                        PreparedSnapshotExport::InvalidManifest => {
                            tracing::error!(height = key.0, "snapshot generation has no canonical network manifest identity");
                        }
                        PreparedSnapshotExport::GenerationError(error) => {
                            let retry_after_tail_install = matches!(
                                error,
                                noid_chain::storage::SnapshotGenerationError::MissingBridgeTerminal(_)
                                    | noid_chain::storage::SnapshotGenerationError::MissingBoundaryTerminal(_)
                            );
                            tracing::warn!(height = key.0, err = %error, "snapshot generation build failed");
                            if retry_after_tail_install {
                                // The exporter may race the atomic compact-tail
                                // installer and pin an intermediate marker.
                                // Retry after that fixed local race instead of
                                // waiting for the regular 30-second cadence.
                                snapshot_export_timer.reset_after(Duration::from_secs(1));
                            }
                        }
                    }
                }
            }

            _ = snapshot_export_timer.tick() => {
                prune_snapshot_export_leases(&mut snapshot_export_leases);
                prune_snapshot_export_disconnect_grace(
                    &mut snapshot_export_disconnect_grace,
                );
                refresh_snapshot_object_retention_floor(
                    &chain_store,
                    &snapshot_export_leases,
                    &snapshot_export_disconnect_grace,
                );
                prune_snapshot_exports(
                    &mut snapshot_exports,
                    &snapshot_export_leases,
                    &snapshot_export_disconnect_grace,
                );
                if snapshot_export_inflight.is_none() {
                    let candidate = local_history_step_boundary(&chain_store).and_then(|key| {
                        if snapshot_exports.contains_key(&key) {
                            None
                        } else {
                            let previous = snapshot_exports
                                .iter()
                                .filter(|((height, _), _)| *height < key.0)
                                .max_by_key(|((height, _), _)| *height)
                                .map(|(_, generation)| Arc::clone(generation));
                            Some((key, chain_store.clone(), previous))
                        }
                    });
                    if let Some((key, store, previous)) = candidate {
                        snapshot_export_inflight = Some(key);
                        let export_root = snapshot_export_root.clone();
                        let completion = snapshot_export_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let result = export_snapshot_boundary_generation(
                                &store,
                                &export_root,
                                key.0,
                                previous.as_ref().map(|entry| &entry.generation),
                            )
                            .map_or_else(
                                PreparedSnapshotExport::GenerationError,
                                |generation| {
                                    SnapshotExportEntry::new(generation).map_or(
                                        PreparedSnapshotExport::InvalidManifest,
                                        PreparedSnapshotExport::Ready,
                                    )
                                },
                            );
                            let _ = completion.blocking_send((key, result));
                        });
                    }
                }
            }

            _ = reactor_health_timer.tick() => {
                let queues = required_event_tx.queue_depths();
                let command_queues = cmd_rx.queue_depths();
                let pending_requests = pending_network_profile_requests.len()
                    + pending_object_requests.len()
                    + pending_header_requests.len()
                    + pending_state_manifest_requests.len()
                    + pending_manifest_page_requests.len()
                    + pending_state_segment_requests.len()
                    + pending_history_step_requests.len();
                let outbound_bytes_in_use =
                    crate::outbound_budget::OUTBOUND_RESPONSE_BUDGET_BYTES
                        .saturating_sub(outbound_response_budget.available_bytes());
                data_plane_serving.prune(|peer| swarm.is_connected(peer));
                let active_data_serving_slots = data_plane_serving.active_slots();
                let outstanding_data_serving_slots = data_plane_serving.outstanding_slots();
                let next_health_sequence = health_tx.borrow().sequence.saturating_add(1);
                health_tx.send_replace(P2PHealthSnapshot {
                    sequence: next_health_sequence,
                    updated_at: Instant::now(),
                    connected_peers: swarm.connected_peers().count(),
                    dispatchable_peers: sync_paths.dispatchable_peer_count(),
                    relay_reservations: relay_reservations.active.len(),
                    control_queue: queues.control.saturating_add(command_queues.control),
                    header_queue: queues.header.saturating_add(command_queues.header),
                    data_queue: queues
                        .live
                        .saturating_add(queues.historical)
                        .saturating_add(queues.background)
                        .saturating_add(command_queues.data),
                    pending_requests,
                    active_data_serving_slots,
                    outstanding_data_serving_slots,
                });
                if queues.control != 0
                    || queues.header != 0
                    || command_queues.control != 0
                    || command_queues.header != 0
                {
                    tracing::warn!(
                        control_queue = queues.control,
                        header_queue = queues.header,
                        live_queue = queues.live,
                        historical_queue = queues.historical,
                        background_queue = queues.background,
                        queue_total = queues.total(),
                        command_control_queue = command_queues.control,
                        command_header_queue = command_queues.header,
                        command_data_queue = command_queues.data,
                        command_queue_total = command_queues.total(),
                        pending_requests,
                        outbound_bytes_in_use,
                        active_data_serving_slots,
                        outstanding_data_serving_slots,
                        "P2P control-plane queue pressure"
                    );
                } else {
                    tracing::debug!(
                        live_queue = queues.live,
                        historical_queue = queues.historical,
                        background_queue = queues.background,
                        queue_total = queues.total(),
                        command_data_queue = command_queues.data,
                        command_queue_total = command_queues.total(),
                        pending_requests,
                        outbound_bytes_in_use,
                        active_data_serving_slots,
                        outstanding_data_serving_slots,
                        "P2P reactor health"
                    );
                }
            }

            // Commands from the node (when no swarm event pending).
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(cmd) => handle_network_command(
                        &mut swarm,
                        cmd,
                        &topics,
                        &mut mempool_sync_last_request,
                        &mut mempool_sync_retries,
                        &required_event_tx,
                        &mut pending_object_requests,
                        &mut pending_header_requests,
                        &mut pending_state_manifest_requests,
                        &mut pending_manifest_page_requests,
                        &mut manifest_page_assemblies,
                        &mut rejected_manifest_candidates,
                        &mut latest_manifest_generation,
                        &mut pending_state_segment_requests,
                        &mut pending_history_step_requests,
                        &mut automatic_peers,
                        &mut successful_peer_cache,
                        &sync_paths,
                    )
                    .await,
                    None => break, // cmd_tx dropped
                }
            }

            _ = automatic_peer_timer.tick() => {
                let now = Instant::now();
                let mut wedged_sync_peers = std::collections::HashSet::new();

                let expired_profiles = pending_network_profile_requests.take_where_entries(
                    |request| {
                        now.saturating_duration_since(request.issued_at)
                            >= NETWORK_PROFILE_PENDING_DEADLINE
                    },
                );
                for (request_id, request) in expired_profiles {
                    let transport_stuck = swarm
                        .behaviour()
                        .network_profile_sync
                        .is_pending_outbound(&request.peer, &request_id);
                    tracing::warn!(
                        peer = %request.peer,
                        transport_stuck,
                            "network-v7 profile handshake timed out"
                    );
                    let _ = swarm.disconnect_peer_id(request.peer);
                }

                let expired_objects = pending_object_requests.take_where_entries(|request| {
                    now.saturating_duration_since(request.issued_at) >= OBJECT_PENDING_DEADLINE
                });
                for (request_id, request) in expired_objects {
                    let transport_stuck = swarm
                        .behaviour()
                        .object_sync
                        .is_pending_outbound(&request.peer, &request_id);
                    tracing::warn!(
                        peer = %request.peer,
                        token = request.token,
                        transport_stuck,
                        "exact-object request exceeded its complete local deadline"
                    );
                    let _ = required_event_tx
                        .send(NetworkEvent::ObjectsRequestFailed {
                            token: request.token,
                            from: request.peer,
                            objects: request.objects,
                            kind: RequestFailureKind::Timeout,
                        })
                        .await;
                    if transport_stuck {
                        wedged_sync_peers.insert(request.peer);
                    }
                }

                let expired_headers = pending_header_requests.take_where_entries(|request| {
                    now.saturating_duration_since(request.issued_at)
                        >= SMALL_SYNC_PENDING_DEADLINE
                });
                for (request_id, request) in expired_headers {
                    let transport_stuck = swarm
                        .behaviour()
                        .chain_sync
                        .is_pending_outbound(&request.peer, &request_id);
                    if transport_stuck {
                        tracing::warn!(
                            protocol = "headers",
                            peer = %request.peer,
                            start_height = request.start_height,
                            count = request.count,
                            kind = ?request.kind,
                            active = request.notify_node,
                            "sync request exceeded its complete local deadline"
                        );
                        wedged_sync_peers.insert(request.peer);
                    }
                    if request.notify_node {
                        match request.kind {
                            HeaderRequestKind::General => {
                                let _ = required_event_tx
                                    .send(NetworkEvent::HeadersRequestFailed {
                                        from: request.peer,
                                        start_height: request.start_height,
                                        count: request.count,
                                        kind: RequestFailureKind::Timeout,
                                    })
                                    .await;
                            }
                            HeaderRequestKind::Snapshot { generation, token } => {
                                let _ = required_event_tx
                                    .send(NetworkEvent::SnapshotHeadersRequestFailed {
                                        generation,
                                        token,
                                        from: request.peer,
                                        start_height: request.start_height,
                                        count: request.count,
                                        kind: RequestFailureKind::Timeout,
                                    })
                                    .await;
                            }
                        }
                    }
                }

                let expired_manifests = pending_state_manifest_requests.take_where_entries(
                    |request| {
                        now.saturating_duration_since(request.issued_at)
                            >= SMALL_SYNC_PENDING_DEADLINE
                    },
                );
                for (request_id, request) in expired_manifests {
                    let transport_stuck = swarm
                        .behaviour()
                        .state_manifest_sync
                        .is_pending_outbound(&request.peer, &request_id);
                    if transport_stuck {
                        tracing::warn!(
                            protocol = "manifest",
                            peer = %request.peer,
                            generation = request.generation,
                            requester_height = request.requester_height,
                            active = request.notify_node,
                            "sync request exceeded its complete local deadline"
                        );
                        wedged_sync_peers.insert(request.peer);
                    }
                    if request.notify_node {
                        let _ = required_event_tx
                            .send(NetworkEvent::StateManifestRequestFailed {
                                generation: request.generation,
                                from: request.peer,
                                requester_height: request.requester_height,
                                requested_manifest_digest: request.requested_manifest_digest,
                                kind: RequestFailureKind::Timeout,
                            })
                            .await;
                    }
                }

                let expired_manifest_pages = pending_manifest_page_requests
                    .take_where_entries(|request| {
                        now.saturating_duration_since(request.issued_at)
                            >= SMALL_SYNC_PENDING_DEADLINE
                    });
                for (request_id, request) in expired_manifest_pages {
                    let transport_stuck = swarm
                        .behaviour()
                        .manifest_page_sync
                        .is_pending_outbound(&request.peer, &request_id);
                    if transport_stuck {
                        wedged_sync_peers.insert(request.peer);
                    }
                    if let Some(assembly) = manifest_page_assemblies.get_mut(&request.key) {
                        assembly.finish_request(request.object.page.page_index);
                        assembly.retry_after.insert(
                            (request.object.page.page_index, request.peer),
                            now + MANIFEST_PAGE_OPERATIONAL_RETRY,
                        );
                    }
                }

                let expired_assemblies = manifest_page_assemblies
                    .iter()
                    .filter_map(|(key, assembly)| {
                        (now.saturating_duration_since(assembly.last_progress)
                            >= MANIFEST_PAGE_ASSEMBLY_IDLE_TTL)
                            .then_some((
                                *key,
                                assembly
                                    .provider_requester_heights
                                    .iter()
                                    .map(|(peer, height)| (*peer, *height))
                                    .collect::<Vec<_>>(),
                            ))
                    })
                    .collect::<Vec<_>>();
                for (key, providers) in expired_assemblies {
                    manifest_page_assemblies.remove(&key);
                    pending_manifest_page_requests.take_where(|pending| pending.key == key);
                    for (peer, requester_height) in providers {
                        let _ = required_event_tx
                            .send(NetworkEvent::StateManifestRequestFailed {
                                generation: key.generation,
                                from: peer,
                                requester_height,
                                requested_manifest_digest: key.snapshot.manifest_digest,
                                kind: RequestFailureKind::Timeout,
                            })
                            .await;
                    }
                }
                rejected_manifest_candidates.retain(|_, rejected_at| {
                    now.saturating_duration_since(*rejected_at)
                        < MANIFEST_PAGE_ASSEMBLY_IDLE_TTL
                });
                schedule_manifest_page_requests(
                    &mut swarm,
                    &mut manifest_page_assemblies,
                    &mut pending_manifest_page_requests,
                    &sync_paths,
                );

                let expired_segments = pending_state_segment_requests.take_where_entries(
                    |request| {
                        now.saturating_duration_since(request.issued_at)
                            >= STATE_SEGMENT_PENDING_DEADLINE
                    },
                );
                for (request_id, request) in expired_segments {
                    let transport_stuck = swarm
                        .behaviour()
                        .state_segment_sync
                        .is_pending_outbound(&request.peer, &request_id);
                    if transport_stuck {
                        tracing::warn!(
                            protocol = "segment",
                            peer = %request.peer,
                            segment = request.segment_id,
                            snapshot_height = request.expected_tip_height,
                            active = request.notify_node,
                            "sync request exceeded its complete local deadline"
                        );
                        wedged_sync_peers.insert(request.peer);
                    }
                    if request.notify_node {
                        let _ = required_event_tx
                            .send(NetworkEvent::StateSegmentRequestFailed {
                                from: request.peer,
                                segment_id: request.segment_id,
                                expected_tip_height: request.expected_tip_height,
                                expected_tip_hash: request.expected_tip_hash,
                                manifest_digest: request.manifest_digest,
                                kind: RequestFailureKind::Timeout,
                            })
                            .await;
                    }
                }

                let expired_terminals = pending_history_step_requests.take_where_entries(
                    |request| {
                        now.saturating_duration_since(request.issued_at)
                            >= HISTORY_STEP_PENDING_DEADLINE
                    },
                );
                for (request_id, request) in expired_terminals {
                    if swarm
                        .behaviour()
                        .history_step_sync
                        .is_pending_outbound(&request.peer, &request_id)
                    {
                        wedged_sync_peers.insert(request.peer);
                    }
                    tracing::warn!(
                        token = request.token,
                        peer = %request.peer,
                        height = request.height,
                        "HistoryStep terminal request exceeded its complete local deadline"
                    );
                    if request.notify_node {
                        let _ = required_event_tx
                            .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                                token: request.token,
                                from: request.peer,
                                height: request.height,
                                block_hash: request.block_hash,
                                kind: RequestFailureKind::Timeout,
                            })
                            .await;
                    }
                }
                for peer in wedged_sync_peers {
                    tracing::warn!(
                        peer = %peer,
                        "closing connection to flush a sync request stuck before its transport timeout"
                    );
                    let _ = swarm.disconnect_peer_id(peer);
                }
                let local_peer = *swarm.local_peer_id();
                for (route, addr) in relay_circuit_backoff.take_due(now) {
                    automatic_peers.add_peer_candidate(
                        local_peer,
                        route.destination,
                        [addr.clone()],
                    );
                    swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&route.destination, addr);
                    tracing::debug!(
                        relay = %route.relay,
                        destination = %route.destination,
                        "relay circuit retry became eligible"
                    );
                }
                maintain_automatic_outbound(
                    &mut swarm,
                    &mut automatic_peers,
                    &peer_diversity,
                    &relay_reservations,
                );
                relay_reservations.maintain(
                    &mut swarm,
                    &sync_paths.profile_verified,
                    now,
                );
                // A lookup is a discovery operation, not a request to build a
                // full all-to-all relay graph. Once the bounded eight-neighbour
                // topology exists, stop its remaining Kademlia work
                // before it probes more relay-only wallets.
                stop_discovery_after_mesh_formed(&mut swarm, &mut automatic_peers);
                let under_target = automatic_peers
                    .topology_peer_count()
                    // A slow or unresolved DNS seed is only a probe. It must
                    // not suppress discovery of a real ordinary neighbour.
                    .saturating_add(automatic_peers.pending_ordinary_count())
                    < AUTOMATIC_OUTBOUND_TARGET;
                if under_target
                    && swarm.connected_peers().next().is_some()
                    && automatic_peers.initial_discovery_started
                    && !automatic_peers.discovery_active()
                    && Instant::now() >= automatic_peers.next_discovery_at
                {
                    let query = swarm
                        .behaviour_mut()
                        .kad
                        .get_closest_peers(libp2p::PeerId::random());
                    automatic_peers.begin_discovery(query);
                    tracing::debug!(
                        peers = automatic_peers.topology_peer_count(),
                        pending = automatic_peers.pending.len(),
                        target = AUTOMATIC_OUTBOUND_TARGET,
                        "kad: accelerated lookup below outbound target"
                    );
                }
            }

            // Persist only peers confirmed by successful outbound transport.
            _ = peer_store_timer.tick() => {
                let cache = successful_peer_cache.clone();
                let data_dir = data_dir.clone();
                let _gc_task = tokio::task::spawn_blocking(move || {
                    crate::peer_store::save(&data_dir, &cache);
                });
            }

            // Recover a mempool exchange rejected during a busy simultaneous
            // multi-peer handshake. State is bounded by connected PeerIds,
            // attempts are finite, and local+remote jitter spreads clients
            // requesting the same server across timer ticks.
            _ = mempool_retry_timer.tick() => {
                let mempool_now = Instant::now();
                let retry_peers: Vec<_> = mempool_sync_retries
                    .iter()
                    .filter(|(peer, retry)| {
                        mempool_now >= retry.next_attempt
                            && sync_paths.is_dispatchable(**peer)
                    })
                    .map(|(peer, retry)| (*peer, retry.failures))
                    .collect();
                mempool_sync_retries.retain(|peer, _| swarm.is_connected(peer));
                for (peer, failures) in retry_peers {
                    let _ = swarm
                        .behaviour_mut()
                        .mempool_sync
                        .send_request(&peer, MempoolRequest::Pull);
                    mempool_sync_last_request.insert(peer, mempool_now);
                    if let Some(retry) = mempool_sync_retries.get_mut(&peer) {
                        // Do not issue a duplicate while the request-response
                        // timeout is still in flight.
                        retry.next_attempt = mempool_now + MEMPOOL_SYNC_RETRY_INFLIGHT;
                    }
                    tracing::debug!(peer = %peer, failures, "retrying mempool sync");
                }
            }
        }
    }
    crate::peer_store::save(&data_dir, &successful_peer_cache);
    Ok(())
}

fn load_snapshot_exports(
    root: &std::path::Path,
) -> std::collections::HashMap<SnapshotExportKey, SnapshotExport> {
    let mut exports = std::collections::HashMap::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return exports;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        match open_snapshot_generation(entry.path()) {
            Ok(generation) => {
                let key = generation.key();
                if let Some(export) = SnapshotExportEntry::new(generation) {
                    exports.insert(key, Arc::new(export));
                } else {
                    tracing::warn!(
                        height = key.0,
                        "ignoring snapshot generation with invalid network manifest identity"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(path = %entry.path().display(), err = %error, "ignoring invalid snapshot generation");
            }
        }
    }
    exports
}

fn prune_snapshot_export_leases(
    leases: &mut std::collections::HashMap<PeerId, SnapshotExportLease>,
) {
    let now = Instant::now();
    leases.retain(|_, lease| {
        now.duration_since(lease.last_activity) <= SNAPSHOT_EXPORT_LEASE_TTL
            && now <= lease.absolute_deadline
    });
}

fn snapshot_export_transfer_allowance(manifest: &GetStateManifestResponse) -> Duration {
    let payload_bytes = manifest
        .segment_lengths
        .iter()
        .fold(0u64, |total, length| {
            total.saturating_add(u64::from(*length))
        })
        .saturating_add(MAX_OUTBOUND_HISTORY_STEP_RESPONSE_BYTES as u64)
        .saturating_add((manifest.segment_ids.len() as u64).saturating_mul((2 + 32 + 4) as u64));
    let transfer_seconds = payload_bytes
        .saturating_add(SNAPSHOT_EXPORT_MIN_SUPPORTED_BYTES_PER_SECOND - 1)
        / SNAPSHOT_EXPORT_MIN_SUPPORTED_BYTES_PER_SECOND;
    let per_segment_seconds = (manifest.segment_ids.len() as u64)
        .saturating_mul(SNAPSHOT_EXPORT_PER_SEGMENT_ALLOWANCE.as_secs());
    Duration::from_secs(transfer_seconds).saturating_add(Duration::from_secs(per_segment_seconds))
}

fn prune_snapshot_export_disconnect_grace(grace: &mut SnapshotExportDisconnectGrace) {
    let now = Instant::now();
    grace.retain(|_, expires_at| *expires_at > now);
}

fn detach_snapshot_export_lease(
    leases: &mut std::collections::HashMap<PeerId, SnapshotExportLease>,
    grace: &mut SnapshotExportDisconnectGrace,
    peer: PeerId,
) {
    let Some(lease) = leases.remove(&peer) else {
        return;
    };
    let idle_deadline = lease.last_activity + SNAPSHOT_EXPORT_LEASE_TTL;
    let expires_at = idle_deadline.min(lease.absolute_deadline);
    if expires_at <= Instant::now() {
        return;
    }
    grace
        .entry(lease.key)
        .and_modify(|current| *current = (*current).max(expires_at))
        .or_insert(expires_at);
}

fn protected_snapshot_export_keys(
    leases: &std::collections::HashMap<PeerId, SnapshotExportLease>,
    grace: &SnapshotExportDisconnectGrace,
) -> std::collections::HashSet<SnapshotExportKey> {
    leases
        .values()
        .map(|lease| lease.key)
        .chain(grace.keys().copied())
        .collect()
}

fn refresh_snapshot_export_lease_after_service(
    leases: &mut std::collections::HashMap<PeerId, SnapshotExportLease>,
    peer: PeerId,
    key: SnapshotExportKey,
    manifest_digest: Option<[u8; 32]>,
    progress: SnapshotLeaseProgress,
) {
    let now = Instant::now();
    let Some(lease) = leases.get_mut(&peer) else {
        return;
    };
    if lease.key != key
        || manifest_digest.is_some_and(|digest| lease.manifest_digest != digest)
        || now > lease.absolute_deadline
    {
        return;
    }
    if lease.served_objects.insert(progress) {
        lease.last_activity = now;
    }
}

fn refresh_snapshot_object_retention_floor(
    store: &MdbxStore,
    leases: &std::collections::HashMap<PeerId, SnapshotExportLease>,
    disconnect_grace: &SnapshotExportDisconnectGrace,
) {
    store.set_block_body_object_retention_floor(
        leases
            .values()
            .map(|lease| lease.key.0)
            .chain(disconnect_grace.keys().map(|key| key.0))
            .min(),
    );
}

fn lease_snapshot_export(
    leases: &mut std::collections::HashMap<PeerId, SnapshotExportLease>,
    disconnect_grace: &SnapshotExportDisconnectGrace,
    peer: PeerId,
    key: SnapshotExportKey,
    manifest_digest: [u8; 32],
    absolute_deadline: Instant,
) -> bool {
    prune_snapshot_export_leases(leases);
    if MAX_ACTIVE_SNAPSHOT_EXPORT_GENERATIONS == 0 {
        return false;
    }
    let now = Instant::now();
    let distinct_other_keys = leases
        .iter()
        .filter(|(leased_peer, _)| **leased_peer != peer)
        .map(|(_, lease)| lease.key)
        .chain(disconnect_grace.keys().copied())
        .collect::<std::collections::HashSet<_>>();
    if !distinct_other_keys.contains(&key)
        && distinct_other_keys.len() >= MAX_ACTIVE_SNAPSHOT_EXPORT_GENERATIONS
    {
        // Never revoke a live immutable-generation lease. Doing so strands a
        // slow client with a valid plan whose exact objects disappear midway
        // through transfer. Capacity pressure rejects only the new admission;
        // the client can rotate to another authenticated provider and every
        // existing transfer remains serviceable until inactivity expiry.
        return false;
    }
    if leases.get(&peer).is_some_and(|lease| {
        lease.key == key
            && lease.manifest_digest == manifest_digest
            && now <= lease.absolute_deadline
    }) {
        return true;
    }
    if now > absolute_deadline {
        return false;
    }
    leases.insert(
        peer,
        SnapshotExportLease {
            key,
            manifest_digest,
            absolute_deadline,
            last_activity: now,
            served_objects: SnapshotLeaseProgressSet::new(),
        },
    );
    true
}

fn prune_snapshot_exports(
    exports: &mut std::collections::HashMap<SnapshotExportKey, SnapshotExport>,
    leases: &std::collections::HashMap<PeerId, SnapshotExportLease>,
    disconnect_grace: &SnapshotExportDisconnectGrace,
) {
    let protected = protected_snapshot_export_keys(leases, disconnect_grace);
    let mut keys: Vec<_> = exports.keys().copied().collect();
    keys.sort_unstable_by_key(|(height, _)| std::cmp::Reverse(*height));
    let mut unprotected_kept = 0usize;
    for key in keys {
        if protected.contains(&key) {
            continue;
        }
        unprotected_kept += 1;
        if unprotected_kept <= MAX_CACHED_SNAPSHOT_EXPORTS {
            continue;
        }
        let removable = exports
            .get(&key)
            .is_some_and(|generation| Arc::strong_count(generation) == 1);
        if removable {
            if let Some(generation) = exports.remove(&key) {
                let directory = generation.directory().to_owned();
                // A generation may contain many segment directory entries.
                // Filesystem GC must never run in the swarm reactor where it
                // could delay header gossip, request correlation, or peer
                // liveness. Removal is already logically complete above.
                tokio::task::spawn_blocking(move || {
                    if let Err(error) = std::fs::remove_dir_all(&directory) {
                        tracing::warn!(path = %directory.display(), err = %error, "snapshot generation GC failed");
                    }
                });
            }
        }
    }
}

fn allow_peer_rate(
    rates: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
    peer: PeerId,
    max: u32,
    window: Duration,
) -> bool {
    let now = Instant::now();
    let entry = rates.entry(peer).or_insert((0, now));
    if now.duration_since(entry.1) > window {
        *entry = (1, now);
        true
    } else if entry.0 >= max {
        false
    } else {
        entry.0 += 1;
        true
    }
}

#[derive(Debug)]
struct GossipByteWindow {
    bytes: usize,
    started_at: Instant,
}

impl GossipByteWindow {
    fn new() -> Self {
        Self {
            bytes: 0,
            started_at: Instant::now(),
        }
    }

    fn admit(&mut self, bytes: usize, max_bytes: usize, window: Duration) -> bool {
        let now = Instant::now();
        if now.duration_since(self.started_at) > window {
            self.bytes = 0;
            self.started_at = now;
        }
        let Some(next) = self.bytes.checked_add(bytes) else {
            return false;
        };
        if next > max_bytes {
            return false;
        }
        self.bytes = next;
        true
    }
}

fn report_gossip_validation(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    message_id: &gossipsub::MessageId,
    propagation_source: &PeerId,
    acceptance: gossipsub::MessageAcceptance,
) {
    if !swarm
        .behaviour_mut()
        .gossipsub
        .report_message_validation_result(message_id, propagation_source, acceptance)
    {
        tracing::debug!(
            peer = %propagation_source,
            message = %message_id,
            "GossipSub validation result was no longer available"
        );
    }
}

fn is_routable_identify_addr(addr: &Multiaddr) -> bool {
    // DNS names advertised by an untrusted peer are cheap aliases around one
    // attacker-controlled host and bypass IP-group diversity. Explicit DNS
    // seeds remain supported by the node CLI; Identify learns only resolved,
    // globally-routable transport addresses.
    crate::peer_diversity::contains_public_ip(addr)
}

fn sanitize_automatic_peer_addr(peer: PeerId, mut addr: Multiaddr) -> Option<Multiaddr> {
    if let Some(libp2p::multiaddr::Protocol::P2p(advertised_peer)) = addr.iter().last() {
        if advertised_peer != peer {
            return None;
        }
        addr.pop();
    }
    let has_tcp = addr
        .iter()
        .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::Tcp(port) if port != 0));
    (is_routable_identify_addr(&addr) && has_tcp).then_some(addr)
}

fn sanitize_mdns_peer_addr(peer: PeerId, mut addr: Multiaddr) -> Option<Multiaddr> {
    use libp2p::multiaddr::Protocol;

    // mDNS is a direct-LAN discovery mechanism. Relay listen addresses are
    // also announced by libp2p after reservations change, but redialing those
    // through every machine on the LAN creates an all-to-all circuit herd.
    if addr
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
    {
        return None;
    }
    if let Some(Protocol::P2p(advertised_peer)) = addr.iter().last() {
        if advertised_peer != peer {
            return None;
        }
        addr.pop();
    }
    if addr
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2p(_)))
    {
        return None;
    }
    let has_tcp = addr
        .iter()
        .any(|protocol| matches!(protocol, Protocol::Tcp(port) if port != 0));
    let has_usable_ip = addr.iter().any(|protocol| match protocol {
        Protocol::Ip4(ip) => !ip.is_unspecified() && !ip.is_multicast(),
        Protocol::Ip6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
        _ => false,
    });
    (has_tcp && has_usable_ip).then_some(addr)
}

fn begin_bootstrap_dial(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    automatic: &mut AutomaticPeerState,
    addr: Multiaddr,
    peer: Option<PeerId>,
) -> bool {
    let options = if let Some(peer) = peer {
        libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
            .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
            // Ordinary bootstrap traffic does not need TCP source-port
            // reuse. Some VPN, NAT and stateful-firewall paths silently drop
            // a 9600 -> 9600 flow while accepting the same destination from
            // an ephemeral source port. DCUtR owns its separate reuse dials
            // for hole punching and is deliberately unaffected here.
            .allocate_new_port()
            .addresses(vec![addr.clone()])
            .build()
    } else {
        libp2p::swarm::dial_opts::DialOpts::unknown_peer_id()
            .address(addr.clone())
            .allocate_new_port()
            .build()
    };
    let connection_id = options.connection_id();
    automatic
        .pending
        .insert(connection_id, PendingAutomaticDial::Bootstrap(addr.clone()));
    match swarm.dial(options) {
        Ok(()) => {
            tracing::debug!(address = %addr, "automatic bootstrap dial started");
            true
        }
        Err(error) => {
            automatic.note_dial_failed(connection_id);
            tracing::debug!(address = %addr, err = %error, "automatic bootstrap dial rejected");
            false
        }
    }
}

fn begin_peer_dial(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    automatic: &mut AutomaticPeerState,
    peer: PeerId,
    addr: Multiaddr,
    group: PublicNetworkGroup,
) -> bool {
    let options = libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
        .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
        // Maintained neighbours are ordinary outbound sessions. Allocate an
        // ephemeral TCP source port so their reachability does not depend on
        // listener-port reuse surviving the local VPN/NAT path. DCUtR dials
        // still request PortUse::Reuse independently when hole punching.
        .allocate_new_port()
        .addresses(vec![addr])
        .build();
    let connection_id = options.connection_id();
    automatic
        .pending
        .insert(connection_id, PendingAutomaticDial::Peer { peer, group });
    match swarm.dial(options) {
        Ok(()) => {
            tracing::debug!(peer = %peer, "automatic peer dial started");
            true
        }
        Err(error) => {
            automatic.note_dial_failed(connection_id);
            tracing::debug!(peer = %peer, err = %error, "automatic peer dial rejected");
            false
        }
    }
}

fn begin_lan_peer_dial(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    automatic: &mut AutomaticPeerState,
    peer: PeerId,
    addresses: Vec<Multiaddr>,
) -> bool {
    let options = libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
        .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
        .addresses(addresses)
        .build();
    let connection_id = options.connection_id();
    automatic
        .pending
        .insert(connection_id, PendingAutomaticDial::Lan { peer });
    automatic.mark_local_selection(peer);
    match swarm.dial(options) {
        Ok(()) => {
            tracing::debug!(peer = %peer, "bounded mDNS peer dial started");
            true
        }
        Err(error) => {
            automatic.note_dial_failed(connection_id);
            tracing::debug!(peer = %peer, err = %error, "bounded mDNS peer dial rejected");
            false
        }
    }
}

fn maintain_automatic_outbound(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    automatic: &mut AutomaticPeerState,
    peer_diversity: &PeerDiversity,
    relay_reservations: &RelayReservations,
) {
    let now = Instant::now();
    automatic.refresh_healthy_connections(now);
    let expired_unidentified = automatic.expired_unidentified_connections(now);
    if !expired_unidentified.is_empty() {
        for (connection_id, peer) in expired_unidentified {
            if swarm.close_connection(connection_id) {
                tracing::debug!(
                    peer = %peer,
                    "closing automatic outbound connection that did not identify in time"
                );
            }
        }
        // Let the close events retire their exact transport records before
        // starting replacement dials on the next two-second maintenance tick.
        return;
    }
    let stable_non_bootstrap = automatic.stable_non_bootstrap_peer_count(now);
    let desired_bootstrap = desired_bootstrap_connections(
        automatic.bootstrap_complete,
        stable_non_bootstrap,
        automatic.bootstrap.len(),
    );
    let connected_bootstrap = automatic.connected_bootstrap_peer_ids();
    let bootstrap_peers = automatic.bootstrap_peer_ids();

    // `desired_bootstrap` falls to zero only after a stable ordinary
    // replacement exists. Extra bootstrap transports can therefore be closed
    // immediately without waiting for the complete eight-peer topology target; that
    // target is filled independently from Kademlia below.
    let protected_bootstrap = connected_bootstrap
        .iter()
        .filter(|peer| relay_reservations.protects_peer(**peer))
        .count();
    // Active relay carriers are useful reachability paths even after ordinary
    // neighbours have replaced bootstrap for discovery. They count toward the
    // retained bootstrap floor and are never selected for connection pruning.
    let retained_bootstrap_floor = desired_bootstrap.max(protected_bootstrap);
    let release_seed = connected_bootstrap.len() > retained_bootstrap_floor;
    // Protected bootstrap/relay carriers are outside the ordinary topology
    // target. Counting them here would repeatedly prune a useful GUI/daemon
    // neighbour each time discovery filled the ordinary mesh.
    let release_ordinary = ordinary_release_needed(release_seed, automatic.topology_peer_count());
    if release_seed || release_ordinary {
        let mut releasable = automatic
            .managed_connections
            .iter()
            .filter(|(_, connection)| {
                if relay_reservations.protects_peer(connection.peer) {
                    return false;
                }
                if release_seed {
                    bootstrap_peers.contains(&connection.peer)
                } else {
                    matches!(connection.kind, ManagedOutboundKind::Peer)
                        && !bootstrap_peers.contains(&connection.peer)
                }
            })
            .map(|(connection_id, connection)| (*connection_id, connection.peer))
            .collect::<Vec<_>>();
        releasable.shuffle(&mut rand::thread_rng());
        if let Some((connection_id, peer)) = releasable.first().copied() {
            if release_seed {
                // Do not let later Kademlia maintenance immediately redial a
                // seed that has just handed us off to ordinary neighbours.
                swarm.behaviour_mut().kad.remove_peer(&peer);
            }
            if swarm.close_connection(connection_id) {
                tracing::debug!(
                    peer = %peer,
                    desired_bootstrap,
                    "released replaced automatic outbound connection"
                );
            }
            return;
        }
        // Every excess transport may be an active relay carrier. In that
        // case there is nothing safe to prune, but ordinary peer discovery
        // must continue instead of being starved by the release branch.
    }

    let pending_capacity = automatic.automatic_dial_capacity();
    if pending_capacity == 0 {
        return;
    }

    let pending_bootstrap = automatic.pending_bootstrap_count();
    // Pending DNS work is not connectivity. Start a small staggered reserve
    // probe on later maintenance ticks instead of waiting for one dead seed's
    // transport timeout before trying the next hostname.
    let bootstrap_needed = desired_bootstrap.saturating_sub(connected_bootstrap.len());
    if bootstrap_needed > 0 {
        let occupied = automatic
            .outbound_peer_count()
            .saturating_add(automatic.pending.len());
        let available = bootstrap_probe_capacity(
            desired_bootstrap,
            connected_bootstrap.len(),
            pending_bootstrap,
            pending_capacity,
            AUTOMATIC_OUTBOUND_TARGET
                .saturating_add(1)
                .saturating_sub(occupied),
        );
        let pending_addrs = automatic
            .pending
            .values()
            .filter_map(|pending| match pending {
                PendingAutomaticDial::Bootstrap(addr) => Some(addr.clone()),
                PendingAutomaticDial::Peer { .. } | PendingAutomaticDial::Lan { .. } => None,
            })
            .collect::<std::collections::HashSet<_>>();
        let mut due = automatic
            .bootstrap
            .iter()
            .filter(|(addr, candidate)| {
                candidate.next_attempt <= now
                    && !pending_addrs.contains(*addr)
                    && candidate.peer.is_none_or(|peer| !swarm.is_connected(&peer))
            })
            .map(|(addr, candidate)| (addr.clone(), candidate.peer))
            .collect::<Vec<_>>();
        due.shuffle(&mut rand::thread_rng());
        let mut occupied_groups = connected_bootstrap
            .iter()
            .filter_map(|peer| peer_diversity.public_group_for_peer(*peer))
            .chain(
                automatic
                    .pending
                    .values()
                    .filter_map(|pending| match pending {
                        PendingAutomaticDial::Bootstrap(addr) => {
                            crate::peer_diversity::public_network_group(addr)
                        }
                        PendingAutomaticDial::Peer { .. } | PendingAutomaticDial::Lan { .. } => {
                            None
                        }
                    }),
            )
            .collect::<std::collections::HashSet<_>>();
        let mut remaining = available;
        while remaining > 0 && !due.is_empty() {
            // Prefer a known public group not already represented by an
            // established or pending bootstrap. DNS names whose resolved IP
            // is not visible yet remain eligible, followed by a duplicate
            // group only when no diverse alternative exists.
            let selected = due
                .iter()
                .position(|(addr, _)| {
                    crate::peer_diversity::public_network_group(addr)
                        .is_some_and(|group| !occupied_groups.contains(&group))
                })
                .or_else(|| {
                    due.iter().position(|(addr, _)| {
                        crate::peer_diversity::public_network_group(addr).is_none()
                    })
                })
                .unwrap_or(0);
            let (addr, peer) = due.swap_remove(selected);
            let group = crate::peer_diversity::public_network_group(&addr);
            if begin_bootstrap_dial(swarm, automatic, addr, peer) {
                if let Some(group) = group {
                    occupied_groups.insert(group);
                }
                remaining -= 1;
            }
        }
    }

    let pending_peers = automatic
        .pending
        .values()
        .filter_map(|pending| match pending {
            PendingAutomaticDial::Peer { peer, .. } | PendingAutomaticDial::Lan { peer } => {
                Some(*peer)
            }
            PendingAutomaticDial::Bootstrap(_) => None,
        })
        .collect::<std::collections::HashSet<_>>();
    let mut candidates = automatic
        .peers
        .iter()
        .filter(|(peer, candidate)| {
            candidate.next_attempt <= now
                && !candidate.addrs.is_empty()
                && !bootstrap_peers.contains(peer)
                && !pending_peers.contains(peer)
                && !swarm.is_connected(peer)
        })
        .map(|(peer, candidate)| {
            (
                *peer,
                candidate.addrs.clone(),
                candidate.attempted_addrs.clone(),
            )
        })
        .collect::<Vec<_>>();
    candidates.shuffle(&mut rand::thread_rng());

    let pending_ordinary = automatic.pending_ordinary_count();
    // A slow DNS bootstrap attempt must not hold a real neighbour slot
    // hostage. If it later succeeds above target, the swap branch releases
    // one ordinary connection without ever dropping below target.
    let mut available = automatic_ordinary_dial_capacity(
        automatic.topology_peer_count(),
        pending_ordinary,
        connected_bootstrap.len() > desired_bootstrap,
        automatic.automatic_dial_capacity(),
    );
    for (peer, mut addrs, mut attempted_addrs) in candidates {
        if available == 0 {
            break;
        }
        if addrs.iter().all(|addr| attempted_addrs.contains(addr)) {
            attempted_addrs.clear();
            if let Some(candidate) = automatic.peers.get_mut(&peer) {
                candidate.attempted_addrs.clear();
            }
        }
        addrs.shuffle(&mut rand::thread_rng());
        prioritize_peer_addresses(peer, &attempted_addrs, &mut addrs);
        let selected = addrs.into_iter().find_map(|addr| {
            let group = crate::peer_diversity::public_network_group(&addr)?;
            let pending_same_group = automatic.pending_group_count(group);
            peer_diversity
                .outbound_candidate_allowed_with_pending(peer, &addr, pending_same_group)
                .then_some((addr, group))
        });
        let Some((addr, group)) = selected else {
            continue;
        };
        if let Some(candidate) = automatic.peers.get_mut(&peer) {
            if !candidate.attempted_addrs.contains(&addr) {
                candidate.attempted_addrs.push(addr.clone());
            }
        }
        if begin_peer_dial(swarm, automatic, peer, addr, group) {
            available -= 1;
        }
    }
}

fn desired_bootstrap_connections(
    bootstrap_complete: bool,
    stable_non_bootstrap: usize,
    configured_bootstraps: usize,
) -> usize {
    let fanout = INITIAL_BOOTSTRAP_FANOUT.min(configured_bootstraps);
    if !bootstrap_complete {
        return fanout;
    }
    // Once sync is complete, one independently discovered connection replaces
    // the bootstrap transport. The replacement is established first by the
    // caller, so releasing the seed never creates a connectivity gap.
    fanout.saturating_sub(stable_non_bootstrap)
}

/// Pending DNS transports are probes, not authenticated connectivity. Keep
/// opening staggered alternatives until the desired number is established,
/// while the hard pending and transport caps bound simultaneous work.
fn bootstrap_probe_capacity(
    desired: usize,
    connected: usize,
    pending: usize,
    transport_capacity: usize,
    target_capacity: usize,
) -> usize {
    desired
        .saturating_sub(connected)
        .min(MAX_PENDING_BOOTSTRAP_DIALS.saturating_sub(pending))
        .min(transport_capacity)
        .min(target_capacity)
}

fn automatic_ordinary_dial_capacity(
    outbound_peers: usize,
    pending_ordinary: usize,
    seed_replacement_needed: bool,
    transport_capacity: usize,
) -> usize {
    let occupied = outbound_peers.saturating_add(pending_ordinary);
    let replacement = usize::from(seed_replacement_needed && occupied >= AUTOMATIC_OUTBOUND_TARGET);
    AUTOMATIC_OUTBOUND_TARGET
        .saturating_add(replacement)
        .saturating_sub(occupied)
        .min(transport_capacity)
}

fn ordinary_release_needed(release_seed: bool, topology_peers: usize) -> bool {
    !release_seed && topology_peers > AUTOMATIC_OUTBOUND_TARGET
}

/// Push one small exact-object availability hint across the current block
/// mesh. Each receiver that commits the block repeats this step, so providers
/// expand with the propagation wave instead of every wallet polling the same
/// public anchors. Header gossip remains independent and is still the only
/// authority that can enter HeaderDAG.
fn announce_availability_to_mesh(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    topics: &NetworkTopics,
    sync_paths: &PeerSyncPaths,
    announcement: HeaderAnnouncement,
) -> usize {
    const MAX_AVAILABILITY_FANOUT: usize = 8;

    let topic = gossipsub::IdentTopic::new(topics.blocks.clone());
    let mut peers = swarm
        .behaviour()
        .gossipsub
        .mesh_peers(&topic.hash())
        .copied()
        .filter(|peer| sync_paths.is_dispatchable(*peer) && sync_paths.supports_availability(*peer))
        .collect::<Vec<_>>();
    if peers.is_empty() {
        // A two-node network or a freshly formed connection may not have run
        // a GossipSub heartbeat yet. Preserve zero-config first-hop delivery
        // without turning a public node's full inbound set into fanout.
        peers.extend(
            swarm
                .connected_peers()
                .copied()
                .filter(|peer| {
                    sync_paths.is_dispatchable(*peer) && sync_paths.supports_availability(*peer)
                })
                .take(MAX_AVAILABILITY_FANOUT),
        );
    }
    peers.sort_unstable_by_key(|peer| peer.to_bytes());
    peers.dedup();
    peers.truncate(MAX_AVAILABILITY_FANOUT);

    for peer in &peers {
        swarm
            .behaviour_mut()
            .availability_sync
            .send_request(peer, AvailabilityRequest { announcement });
    }
    peers.len()
}

/// Process a single network command. Separated from the select! loop so that
/// pending commands can be drained via `try_recv` before blocking.
async fn handle_network_command(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    cmd: NetworkCommand,
    topics: &NetworkTopics,
    mempool_sync_last_request: &mut std::collections::HashMap<PeerId, Instant>,
    mempool_sync_retries: &mut std::collections::HashMap<PeerId, MempoolSyncRetry>,
    required_event_tx: &RequiredEventSender,
    pending_object_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingObjectRequest,
    >,
    pending_header_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingHeaderRequest,
    >,
    pending_state_manifest_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingStateManifestRequest,
    >,
    pending_manifest_page_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingManifestPageRequest,
    >,
    manifest_page_assemblies: &mut std::collections::HashMap<
        ManifestAssemblyKey,
        ManifestPageAssembly,
    >,
    rejected_manifest_candidates: &mut std::collections::HashMap<ManifestAssemblyKey, Instant>,
    latest_manifest_generation: &mut u64,
    pending_state_segment_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingStateSegmentRequest,
    >,
    pending_history_step_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingHistoryStepTerminalRequest,
    >,
    automatic_peers: &mut AutomaticPeerState,
    successful_peer_cache: &mut crate::peer_store::SuccessfulPeerCache,
    sync_paths: &PeerSyncPaths,
) {
    match cmd {
        NetworkCommand::AnnounceBlock { bundle } => {
            let height = bundle.height();
            let announcement = match HeaderAnnouncement::from_accepted_bundle(
                &bundle,
                ProviderFlags::new(true, true, false),
            ) {
                Ok(announcement) => announcement,
                Err(error) => {
                    tracing::error!(height, %error, "refusing to announce an invalid local block object set");
                    return;
                }
            };
            let message = announcement
                .encode()
                .expect("validated local header announcement must encode");
            let topic = gossipsub::IdentTopic::new(topics.blocks.clone());
            if let Err(error) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic, message.to_vec())
            {
                tracing::debug!(height, err = %error, "gossipsub: block announcement");
            }
            let providers = announce_availability_to_mesh(swarm, topics, sync_paths, announcement);
            tracing::debug!(
                height,
                providers,
                "announced exact block availability to mesh peers"
            );
        }
        NetworkCommand::AnnounceAvailability { announcement } => {
            let height = announcement.header.height;
            if announcement.validate().is_err()
                || !announcement.providers.serves_body()
                || !announcement.providers.serves_terminal()
            {
                tracing::error!(
                    height,
                    "refusing to announce invalid exact-object availability"
                );
                return;
            }
            let providers = announce_availability_to_mesh(swarm, topics, sync_paths, announcement);
            tracing::debug!(
                height,
                providers,
                "cascaded exact block availability to mesh peers"
            );
        }
        NetworkCommand::BroadcastTx { intent_bytes } => {
            let topic = gossipsub::IdentTopic::new(topics.txs.clone());
            let gossip_result = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic, intent_bytes.as_ref().to_vec());
            if let Err(error) = &gossip_result {
                tracing::debug!(err = %error, "gossipsub: transaction publish");
            }

            let mut connected: Vec<_> = swarm
                .connected_peers()
                .copied()
                .filter(|peer| sync_paths.is_dispatchable(*peer))
                .collect();
            let direct_limit = direct_tx_relay_limit(connected.len());
            if direct_limit > 0 {
                connected.shuffle(&mut rand::thread_rng());
                connected.truncate(direct_limit);
                for peer in connected {
                    let _ = swarm.behaviour_mut().mempool_sync.send_request(
                        &peer,
                        MempoolRequest::Push {
                            intent_bytes: intent_bytes.as_ref().to_vec(),
                            inbound_memory_permit: None,
                        },
                    );
                }
                tracing::debug!(
                    peers = direct_limit,
                    gossip_ok = gossip_result.is_ok(),
                    "direct transaction relay queued"
                );
            }
        }
        NetworkCommand::ResolveTxGossip {
            message_id,
            propagation_source,
            acceptance,
        } => {
            report_gossip_validation(swarm, &message_id, &propagation_source, acceptance);
        }
        NetworkCommand::Dial { addr } => {
            tracing::debug!(address = %addr, "registered automatic bootstrap candidate");
            for peer in automatic_peers.register_bootstrap(addr) {
                // A seed reconnected from an older peers.json before system
                // DNS finished. Its authenticated endpoint has now repaired
                // the classification, so do not persist it as ordinary again.
                successful_peer_cache.remove(&peer);
            }
        }
        NetworkCommand::BootstrapComplete => {
            automatic_peers.bootstrap_complete = true;
            tracing::debug!("initial synchronization complete — bootstrap peers are releasable");
        }
        NetworkCommand::PeerCount { reply } => {
            let count = sync_paths.dispatchable_peer_count();
            let _ = reply.send(count);
        }
        NetworkCommand::FetchObjects {
            token,
            peer,
            objects,
        } => {
            let shape_valid = !objects.is_empty()
                && objects.len() <= crate::object_protocol::MAX_OBJECTS_PER_REQUEST
                && objects
                    .iter()
                    .all(|object| object.is_live_transfer_object())
                && {
                    let terminal_count = objects
                        .iter()
                        .filter(|object| matches!(object, ObjectId::Terminal(_)))
                        .count();
                    terminal_count == 0 || (terminal_count == 1 && objects.len() == 1)
                }
                && objects
                    .iter()
                    .try_fold(0usize, |total, object| {
                        total.checked_add(object.encoded_len()? as usize)
                    })
                    .is_some_and(|total| {
                        total <= crate::object_protocol::MAX_OBJECT_RESPONSE_PAYLOAD_BYTES
                    })
                && objects
                    .iter()
                    .copied()
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    == objects.len();
            if !shape_valid || !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::ObjectsRequestFailed {
                        token,
                        from: peer,
                        objects,
                        kind: if shape_valid {
                            RequestFailureKind::ConnectionClosed
                        } else {
                            RequestFailureKind::InvalidResponse
                        },
                    })
                    .await;
                return;
            }
            if !pending_object_requests.has_capacity() {
                let _ = required_event_tx
                    .send(NetworkEvent::ObjectsRequestFailed {
                        token,
                        from: peer,
                        objects,
                        kind: RequestFailureKind::LocalCapacity,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().object_sync.send_request(
                &peer,
                GetObjectsRequest {
                    objects: objects.clone(),
                },
            );
            let inserted = pending_object_requests.try_insert(
                request_id,
                PendingObjectRequest {
                    token,
                    peer,
                    objects,
                    issued_at: Instant::now(),
                },
            );
            debug_assert!(inserted, "object capacity checked before request");
        }
        NetworkCommand::RequestStateManifest {
            generation,
            peer,
            requester_height,
            requested_manifest_digest,
        } => {
            // Control and data use physically separate queues. A generation
            // advance may therefore overtake an already queued old request;
            // never let that stale data command recreate retired paging state.
            if generation < *latest_manifest_generation {
                tracing::debug!(
                    generation,
                    active_generation = *latest_manifest_generation,
                    peer = %peer,
                    "discarding retired snapshot manifest request"
                );
                return;
            }
            if generation > *latest_manifest_generation {
                let advanced = advance_manifest_generation(
                    generation,
                    latest_manifest_generation,
                    pending_state_manifest_requests,
                    pending_manifest_page_requests,
                    manifest_page_assemblies,
                    rejected_manifest_candidates,
                );
                debug_assert!(advanced, "strictly newer generation must advance");
            }
            if !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifestRequestFailed {
                        generation,
                        from: peer,
                        requester_height,
                        requested_manifest_digest,
                        kind: RequestFailureKind::ConnectionClosed,
                    })
                    .await;
                return;
            }
            // Exact generation correlation makes superseded responses inert.
            // Keep their transport IDs until completion or local expiry so a
            // request stuck before substream negotiation can still be flushed.
            pending_state_manifest_requests.retain(|_, pending| {
                if pending.peer == peer {
                    pending.notify_node = false;
                }
                true
            });
            if !pending_state_manifest_requests.has_capacity() {
                tracing::warn!(
                    generation,
                    peer = %peer,
                    requester_height,
                    limit = MAX_PENDING_STATE_MANIFEST_REQUESTS,
                    "state-manifest request correlation table full"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifestRequestFailed {
                        generation,
                        from: peer,
                        requester_height,
                        requested_manifest_digest,
                        kind: RequestFailureKind::LocalCapacity,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().state_manifest_sync.send_request(
                &peer,
                crate::protocol::GetStateManifestRequest {
                    requester_height,
                    requested_manifest_digest,
                },
            );
            let inserted = pending_state_manifest_requests.try_insert(
                request_id,
                PendingStateManifestRequest {
                    generation,
                    peer,
                    requester_height,
                    requested_manifest_digest,
                    issued_at: Instant::now(),
                    notify_node: true,
                },
            );
            debug_assert!(inserted, "fresh manifest request ID must be unique");
            tracing::debug!(generation, peer = %peer, requester_height, "requesting state manifest");
        }
        NetworkCommand::AdvanceSnapshotGeneration { generation } => {
            if advance_manifest_generation(
                generation,
                latest_manifest_generation,
                pending_state_manifest_requests,
                pending_manifest_page_requests,
                manifest_page_assemblies,
                rejected_manifest_candidates,
            ) {
                tracing::debug!(generation, "advanced snapshot transport generation");
            }
        }
        NetworkCommand::RequestStateSegment {
            peer,
            segment_id,
            expected_tip_height,
            expected_tip_hash,
            manifest_digest,
        } => {
            if !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::StateSegmentRequestFailed {
                        from: peer,
                        segment_id,
                        expected_tip_height,
                        expected_tip_hash,
                        manifest_digest,
                        kind: RequestFailureKind::ConnectionClosed,
                    })
                    .await;
                return;
            }
            // Exact peer, segment and tip correlation makes superseded
            // responses inert. Retain old transport IDs until completion or
            // local expiry so pre-substream stalls remain observable.
            pending_state_segment_requests.retain(|_, pending| {
                let same_session = pending.peer == peer
                    && pending.expected_tip_height == expected_tip_height
                    && pending.expected_tip_hash == expected_tip_hash
                    && pending.manifest_digest == manifest_digest;
                if !same_session || pending.segment_id == segment_id {
                    pending.notify_node = false;
                }
                true
            });
            if !pending_state_segment_requests.has_capacity() {
                tracing::warn!(
                    peer = %peer,
                    segment_id,
                    limit = MAX_PENDING_STATE_SEGMENT_REQUESTS,
                    "state-segment request correlation table full"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::StateSegmentRequestFailed {
                        from: peer,
                        segment_id,
                        expected_tip_height,
                        expected_tip_hash,
                        manifest_digest,
                        kind: RequestFailureKind::LocalCapacity,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().state_segment_sync.send_request(
                &peer,
                crate::protocol::GetStateSegmentRequest {
                    segment_id,
                    expected_tip_height,
                    expected_tip_hash,
                    manifest_digest,
                },
            );
            let inserted = pending_state_segment_requests.try_insert(
                request_id,
                PendingStateSegmentRequest {
                    peer,
                    segment_id,
                    expected_tip_height,
                    expected_tip_hash,
                    manifest_digest,
                    issued_at: Instant::now(),
                    notify_node: true,
                },
            );
            debug_assert!(inserted, "fresh segment-sync request ID must be unique");
            tracing::debug!(peer = %peer, segment_id, "requesting state segment");
        }
        NetworkCommand::RequestHistoryStepTerminal {
            token,
            peer,
            height,
            block_hash,
        } => {
            if !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                        token,
                        from: peer,
                        height,
                        block_hash,
                        kind: RequestFailureKind::ConnectionClosed,
                    })
                    .await;
                return;
            }
            if !pending_history_step_requests.has_capacity() {
                tracing::warn!(
                    token,
                    peer = %peer,
                    height,
                    limit = MAX_PENDING_HISTORY_STEP_REQUESTS,
                    "HistoryStep request correlation table full"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                        token,
                        from: peer,
                        height,
                        block_hash,
                        kind: RequestFailureKind::LocalCapacity,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().history_step_sync.send_request(
                &peer,
                crate::protocol::GetHistoryStepTerminalRequest { height, block_hash },
            );
            let inserted = pending_history_step_requests.try_insert(
                request_id,
                PendingHistoryStepTerminalRequest {
                    token,
                    peer,
                    height,
                    block_hash,
                    issued_at: Instant::now(),
                    notify_node: true,
                },
            );
            debug_assert!(inserted, "fresh HistoryStep request ID must be unique");
            tracing::debug!(token, peer = %peer, height, "requesting HistoryStep terminal for snapshot verification");
        }
        NetworkCommand::CancelHistoryStepTerminalRace { token } => {
            let mut retired = 0usize;
            pending_history_step_requests.retain(|_, request| {
                if request.token == token {
                    request.notify_node = false;
                    retired += 1;
                }
                true
            });
            tracing::debug!(
                token,
                requests = retired,
                "retired node notification for HistoryStep terminal race"
            );
        }
        NetworkCommand::FetchHeaders {
            peer,
            start_height,
            count,
        } => {
            let count = count.min(
                crate::header_sync_codec::MAX_HEADERS_PER_BATCH
                    .try_into()
                    .expect("header batch cap fits u16"),
            );
            if !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::HeadersRequestFailed {
                        from: peer,
                        start_height,
                        count,
                        kind: RequestFailureKind::ConnectionClosed,
                    })
                    .await;
                return;
            }
            // Exact range correlation makes superseded responses inert. Keep
            // their transport IDs until completion or local expiry so a
            // request stuck before substream negotiation can be flushed.
            pending_header_requests.retain(|_, pending| {
                if pending.peer == peer && pending.kind == HeaderRequestKind::General {
                    pending.notify_node = false;
                }
                true
            });
            if !pending_header_requests.has_capacity() {
                let _ = required_event_tx
                    .send(NetworkEvent::HeadersRequestFailed {
                        from: peer,
                        start_height,
                        count,
                        kind: RequestFailureKind::LocalCapacity,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().chain_sync.send_request(
                &peer,
                crate::protocol::GetHeadersRequest {
                    start_height,
                    count,
                    include_inventory: true,
                },
            );
            let inserted = pending_header_requests.try_insert(
                request_id,
                PendingHeaderRequest {
                    peer,
                    start_height,
                    count,
                    kind: HeaderRequestKind::General,
                    issued_at: Instant::now(),
                    notify_node: true,
                },
            );
            debug_assert!(inserted, "fresh header request ID must be unique");
        }
        NetworkCommand::FetchSnapshotHeaders {
            generation,
            token,
            peer,
            start_height,
            count,
        } => {
            let count = count.min(
                crate::header_sync_codec::MAX_HEADERS_PER_BATCH
                    .try_into()
                    .expect("header batch cap fits u16"),
            );
            if !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::SnapshotHeadersRequestFailed {
                        generation,
                        token,
                        from: peer,
                        start_height,
                        count,
                        kind: RequestFailureKind::ConnectionClosed,
                    })
                    .await;
                return;
            }
            // Keep distinct ranges in the same generation live: the node uses
            // a bounded ordered window against one selected peer. Only an old
            // generation or a replacement of this exact start height is
            // superseded. Transport IDs remain until completion or local
            // expiry so pre-substream stalls stay observable.
            pending_header_requests.retain(|_, pending| {
                if snapshot_header_request_is_superseded(pending, generation, start_height) {
                    pending.notify_node = false;
                }
                true
            });
            if !pending_header_requests.has_capacity() {
                let _ = required_event_tx
                    .send(NetworkEvent::SnapshotHeadersRequestFailed {
                        generation,
                        token,
                        from: peer,
                        start_height,
                        count,
                        kind: RequestFailureKind::LocalCapacity,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().chain_sync.send_request(
                &peer,
                crate::protocol::GetHeadersRequest {
                    start_height,
                    count,
                    include_inventory: false,
                },
            );
            let inserted = pending_header_requests.try_insert(
                request_id,
                PendingHeaderRequest {
                    peer,
                    start_height,
                    count,
                    kind: HeaderRequestKind::Snapshot { generation, token },
                    issued_at: Instant::now(),
                    notify_node: true,
                },
            );
            debug_assert!(inserted, "fresh snapshot header request ID must be unique");
        }
        NetworkCommand::RequestMempoolSync { peer } => {
            if !sync_paths.is_dispatchable(peer) {
                let local = *swarm.local_peer_id();
                let _ = schedule_mempool_sync_retry(mempool_sync_retries, local, peer);
                return;
            }
            const MEMPOOL_SYNC_REQUEST_COOLDOWN: Duration = Duration::from_secs(30);
            let now = Instant::now();
            if let Some(last) = mempool_sync_last_request.get(&peer) {
                if now.duration_since(*last) < MEMPOOL_SYNC_REQUEST_COOLDOWN {
                    tracing::debug!(peer = %peer, "mempool sync request suppressed by cooldown");
                    return;
                }
            }
            mempool_sync_last_request.insert(peer, now);
            mempool_sync_retries.remove(&peer);
            let _ = swarm
                .behaviour_mut()
                .mempool_sync
                .send_request(&peer, MempoolRequest::Pull);
            tracing::debug!(peer = %peer, "requesting mempool sync");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_swarm_event(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    event: SwarmEvent<NodeBehaviourEvent>,
    gossip_event_tx: &tokio::sync::broadcast::Sender<NetworkEvent>,
    required_event_tx: &RequiredEventSender,
    chain_store: &MdbxStore,
    mempool: &AsyncMempool,
    topics: &NetworkTopics,
    network_profile: &NetworkProfile,
    header_response_tx: &mpsc::Sender<PendingHeaderResponse>,
    header_response_prepare_semaphore: &Arc<Semaphore>,
    history_step_response_tx: &mpsc::Sender<PendingHistoryStepTerminalResponse>,
    history_step_response_prepare_semaphore: &Arc<Semaphore>,
    segment_response_tx: &mpsc::Sender<PendingStateSegmentResponse>,
    segment_encode_semaphore: &Arc<Semaphore>,
    manifest_page_response_tx: &mpsc::Sender<PendingManifestPageResponse>,
    manifest_page_verify_tx: &mpsc::Sender<ManifestPageVerificationCompletion>,
    manifest_assembly_tx: &mpsc::Sender<ManifestAssemblyCompletion>,
    mempool_response_tx: &mpsc::Sender<PendingMempoolResponse>,
    mempool_response_prepare_semaphore: &Arc<Semaphore>,
    object_response_tx: &mpsc::Sender<PendingObjectResponse>,
    outbound_response_budget: &OutboundResponseBudget,
    data_plane_serving: &mut DataPlaneServingAdmission,
    snapshot_exports: &mut std::collections::HashMap<SnapshotExportKey, SnapshotExport>,
    snapshot_export_leases: &mut std::collections::HashMap<PeerId, SnapshotExportLease>,
    snapshot_export_disconnect_grace: &mut SnapshotExportDisconnectGrace,
    block_event_rate: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
    tx_gossip_rate: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
    gossip_accept_bytes: &mut GossipByteWindow,
    mempool_sync_last_request: &mut std::collections::HashMap<PeerId, Instant>,
    mempool_sync_retries: &mut std::collections::HashMap<PeerId, MempoolSyncRetry>,
    snapshot_segment_rate: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
    pending_network_profile_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingNetworkProfileRequest,
    >,
    pending_object_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingObjectRequest,
    >,
    pending_header_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingHeaderRequest,
    >,
    pending_state_manifest_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingStateManifestRequest,
    >,
    pending_manifest_page_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingManifestPageRequest,
    >,
    pending_state_segment_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingStateSegmentRequest,
    >,
    pending_history_step_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingHistoryStepTerminalRequest,
    >,
    automatic_peers: &mut AutomaticPeerState,
    peer_diversity: &mut PeerDiversity,
    sync_paths: &mut PeerSyncPaths,
    manifest_page_assemblies: &mut std::collections::HashMap<
        ManifestAssemblyKey,
        ManifestPageAssembly,
    >,
    rejected_manifest_candidates: &mut std::collections::HashMap<ManifestAssemblyKey, Instant>,
    relay_reservations: &mut RelayReservations,
    relay_circuit_backoff: &mut RelayCircuitBackoff,
    successful_peer_cache: &mut crate::peer_store::SuccessfulPeerCache,
) {
    let implicit_bootstraps = stop_implicit_kad_bootstraps(swarm);
    if implicit_bootstraps > 0 {
        tracing::debug!(
            count = implicit_bootstraps,
            "kad: stopped implicit full bootstrap in favour of bounded discovery"
        );
    }

    macro_rules! fail_state_segment_request {
        ($pending:expr, $kind:expr) => {{
            let pending = $pending;
            if pending.notify_node {
                let _ = required_event_tx
                    .send(NetworkEvent::StateSegmentRequestFailed {
                        from: pending.peer,
                        segment_id: pending.segment_id,
                        expected_tip_height: pending.expected_tip_height,
                        expected_tip_hash: pending.expected_tip_hash,
                        manifest_digest: pending.manifest_digest,
                        kind: $kind,
                    })
                    .await;
            }
        }};
    }

    match event {
        // --- GossipSub: received broadcast ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        })) => {
            // Prefer the original publisher (message.source) if we have a direct
            // connection — they definitely have the full block. Fall back to
            // propagation_source (forwarder) for nodes not directly connected to
            // the publisher (common in large networks with multi-hop gossip).
            let direct_origin = message.source.filter(|src| swarm.is_connected(src));
            let origin = direct_origin.unwrap_or(propagation_source);

            let topic = message.topic.as_str();
            if topic == topics.blocks.as_str() {
                match HeaderAnnouncement::decode(&message.data) {
                    Ok(announcement) => {
                        const BLOCK_RATE_WINDOW: Duration = Duration::from_secs(10);
                        const BLOCK_RATE_MAX: u32 = 40;
                        if !sync_paths.is_dispatchable(propagation_source)
                            || !allow_peer_rate(
                                block_event_rate,
                                propagation_source,
                                BLOCK_RATE_MAX,
                                BLOCK_RATE_WINDOW,
                            )
                            || !gossip_accept_bytes.admit(
                                message.data.len(),
                                GOSSIP_ACCEPT_BYTES_PER_WINDOW,
                                GOSSIP_ACCEPT_WINDOW,
                            )
                        {
                            report_gossip_validation(
                                swarm,
                                &message_id,
                                &propagation_source,
                                gossipsub::MessageAcceptance::Ignore,
                            );
                            tracing::debug!(peer = %propagation_source, "block announcement rate limit exceeded — dropped before propagation");
                            return;
                        }
                        let source_has_objects = direct_origin.is_some()
                            && announcement.providers.serves_body()
                            && announcement.providers.serves_terminal();
                        let queued = required_event_tx.try_send(NetworkEvent::HeaderAnnouncement {
                            from: origin,
                            announcement,
                            source_has_objects,
                        });
                        report_gossip_validation(
                            swarm,
                            &message_id,
                            &propagation_source,
                            if queued.is_ok() {
                                gossipsub::MessageAcceptance::Accept
                            } else {
                                gossipsub::MessageAcceptance::Ignore
                            },
                        );
                        if let Err(error) = queued {
                            tracing::warn!(peer = %propagation_source, %error, "reserved header event lane is full");
                        }
                    }
                    Err(error) => {
                        report_gossip_validation(
                            swarm,
                            &message_id,
                            &propagation_source,
                            gossipsub::MessageAcceptance::Reject,
                        );
                        tracing::debug!(
                            peer = %propagation_source,
                            %error,
                            "network-v7 header announcement decode failed"
                        );
                    }
                }
            } else if topic == topics.txs.as_str() {
                if message.data.len() > MAX_TX_INTENT_BYTES_GLOBAL {
                    report_gossip_validation(
                        swarm,
                        &message_id,
                        &propagation_source,
                        gossipsub::MessageAcceptance::Reject,
                    );
                    tracing::warn!(peer = %propagation_source, len = message.data.len(), "tx gossip too large — dropped");
                } else {
                    if !allow_peer_rate(
                        tx_gossip_rate,
                        propagation_source,
                        TX_RELAY_RATE_MAX,
                        TX_RELAY_RATE_WINDOW,
                    ) {
                        report_gossip_validation(
                            swarm,
                            &message_id,
                            &propagation_source,
                            gossipsub::MessageAcceptance::Ignore,
                        );
                        tracing::debug!(peer = %propagation_source, "tx gossip rate limit exceeded — dropped before propagation");
                        return;
                    }
                    if !gossip_accept_bytes.admit(
                        message.data.len(),
                        GOSSIP_ACCEPT_BYTES_PER_WINDOW,
                        GOSSIP_ACCEPT_WINDOW,
                    ) {
                        report_gossip_validation(
                            swarm,
                            &message_id,
                            &propagation_source,
                            gossipsub::MessageAcceptance::Ignore,
                        );
                        tracing::debug!(peer = %propagation_source, bytes = message.data.len(), "global gossip byte budget exhausted — transaction dropped before propagation");
                        return;
                    }
                    if gossip_event_tx
                        .send(NetworkEvent::NewTx {
                            from: propagation_source,
                            intent_bytes: message.data,
                            gossip_message_id: Some(message_id.clone()),
                            inbound_memory_permit: None,
                        })
                        .is_err()
                    {
                        report_gossip_validation(
                            swarm,
                            &message_id,
                            &propagation_source,
                            gossipsub::MessageAcceptance::Ignore,
                        );
                    }
                }
            } else {
                report_gossip_validation(
                    swarm,
                    &message_id,
                    &propagation_source,
                    gossipsub::MessageAcceptance::Ignore,
                );
            }
        }

        // --- Identify: populate Kademlia routing table + address book ---
        //
        // This is the critical integration point that all libp2p chains must
        // implement.  Without it, Kademlia only knows bootstrap nodes and
        // discovery stops there.
        //
        // Reference: libp2p docs — "Peer Discovery with Identify:
        //   the Identify protocol must be manually hooked up to Kademlia
        //   through calls to Behaviour::add_address."
        SwarmEvent::Behaviour(NodeBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            connection_id,
            info,
            ..
        })) => {
            // A duplicate or policy-rejected endpoint remains visible to
            // request-response until its exact ConnectionClosed event. Do not
            // promote it while the close is in flight.
            if sync_paths.is_closing(connection_id) {
                return;
            }
            // Identify is only capability discovery. The endpoint becomes a
            // usable network-v7 peer after the explicit profile round trip
            // below proves the exact genesis, caps, finality and proof bank.
            let profile_protocol = format!("{}/sync/profile/6", topics.protocol_id);
            let object_protocol = format!("{}/sync/objects/2", topics.protocol_id);
            let availability_protocol = format!("{}/sync/availability/1", topics.protocol_id);
            let header_protocol_v5 = format!("{}/sync/headers/5", topics.protocol_id);
            let header_protocol_v4 = format!("{}/sync/headers/4", topics.protocol_id);
            let manifest_protocol = format!("{}/sync/manifest/7", topics.protocol_id);
            let manifest_page_protocol = format!("{}/sync/manifest-page/1", topics.protocol_id);
            let supports = |required: &str| {
                info.protocols
                    .iter()
                    .any(|protocol| protocol.as_ref() == required)
            };
            let supports_availability = supports(&availability_protocol);
            let supports_headers = supports(&header_protocol_v5) || supports(&header_protocol_v4);
            if !supports(&profile_protocol)
                || !supports(&object_protocol)
                || !supports_headers
                || !supports(&manifest_protocol)
                || !supports(&manifest_page_protocol)
            {
                sync_paths.mark_closing(connection_id);
                let _ = swarm.close_connection(connection_id);
                swarm.behaviour_mut().kad.remove_peer(&peer_id);
                tracing::debug!(
                    peer = %peer_id,
                    profile_protocol,
                    object_protocol,
                    header_protocol_v5,
                    header_protocol_v4,
                    "closing endpoint without the compatible network-v7 protocol set"
                );
                return;
            }

            // 1. Add a bounded, routable subset of advertised listen addresses
            //    to Kademlia and the swarm address book. Blindly accepting all
            //    Identify addresses lets a peer bloat our peer store/routing state
            //    or advertise localhost/private addresses that are useless off-LAN.
            const MAX_IDENTIFY_ADDRS_PER_PEER: usize = 8;
            let mut accepted_addrs = 0usize;
            let mut dropped_addrs = 0usize;
            let mut routable_addrs = Vec::new();
            let now = Instant::now();
            for addr in &info.listen_addrs {
                if accepted_addrs >= MAX_IDENTIFY_ADDRS_PER_PEER {
                    dropped_addrs += 1;
                    continue;
                }
                if !is_routable_identify_addr(addr) {
                    dropped_addrs += 1;
                    continue;
                }
                if relay_circuit_backoff.is_blocked(peer_id, addr, now) {
                    dropped_addrs += 1;
                    continue;
                }
                swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&peer_id, addr.clone());
                // Also populate the swarm's address book so GossipSub PX
                // can build signed PeerInfo records for this peer.
                swarm.add_peer_address(peer_id, addr.clone());
                routable_addrs.push(addr.clone());
                accepted_addrs += 1;
            }
            if automatic_peers
                .outbound_connections
                .contains_key(&connection_id)
            {
                if let Some(addr) = routable_addrs.first() {
                    if let Err(reason) = peer_diversity.classify_outbound_dns_connection(
                        connection_id,
                        peer_id,
                        addr,
                    ) {
                        sync_paths.mark_closing(connection_id);
                        let _ = swarm.close_connection(connection_id);
                        swarm.behaviour_mut().kad.remove_peer(&peer_id);
                        tracing::debug!(
                            peer = %peer_id,
                            address = %addr,
                            ?reason,
                            "closing DNS connection that violates public peer diversity"
                        );
                        return;
                    }
                }
            }
            automatic_peers.add_peer_candidate(
                *swarm.local_peer_id(),
                peer_id,
                routable_addrs.iter().cloned(),
            );
            let relay_hop_capable = supports(relay::HOP_PROTOCOL_NAME.as_ref());
            if relay_hop_capable {
                relay_reservations.observe_identified_transports(
                    peer_id,
                    routable_addrs.iter().cloned(),
                    peer_diversity.failure_domain(peer_id),
                );
            }
            relay_reservations.mark_hop_capable(peer_id, relay_hop_capable);
            automatic_peers.note_identified(connection_id, peer_id);
            sync_paths.mark_identified(connection_id);
            if supports_availability {
                sync_paths.mark_availability_capable(connection_id);
            }
            // Stop an iterative lookup on the exact event that completes the
            // eight-peer topology. Waiting for the two-second maintenance tick lets
            // a fast relay-backed DHT open many unnecessary circuits first.
            stop_discovery_after_mesh_formed(swarm, automatic_peers);
            let profile_request_active = pending_network_profile_requests
                .entries
                .values()
                .any(|pending| pending.peer == peer_id);
            // The physical transport dialer initiates exactly once per
            // surviving connection. Peer-level verification can legitimately
            // remain set during an overlapping reconnect while the other end
            // has already cleared it; skipping this refresh would leave the
            // replacement connection usable in only one direction.
            let initiate_profile = sync_paths.should_start_profile_handshake(connection_id);
            if initiate_profile && !profile_request_active {
                if !pending_network_profile_requests.has_capacity() {
                    sync_paths.mark_closing(connection_id);
                    let _ = swarm.close_connection(connection_id);
                    tracing::warn!(peer = %peer_id, "network-profile correlation table is full");
                    return;
                }
                let expected_profile_id = network_profile.profile_id;
                let request_id = swarm.behaviour_mut().network_profile_sync.send_request(
                    &peer_id,
                    NetworkProfileRequest {
                        expected_profile_id,
                    },
                );
                let inserted = pending_network_profile_requests.try_insert(
                    request_id,
                    PendingNetworkProfileRequest {
                        peer: peer_id,
                        issued_at: Instant::now(),
                    },
                );
                debug_assert!(inserted, "profile capacity checked before request");
                sync_paths.mark_profile_handshake_started(connection_id);
                tracing::debug!(peer = %peer_id, "network-v7 profile handshake started");
            }
            if sync_paths.try_mark_announced(peer_id) {
                let _ = required_event_tx
                    .send(NetworkEvent::PeerConnected {
                        peer: peer_id,
                        locally_selected: automatic_peers.is_locally_selected(peer_id),
                        failure_domain: peer_diversity.failure_domain(peer_id),
                    })
                    .await;
                tracing::debug!(peer = %peer_id, "peer network-v7 profile ready");
            }
            if automatic_peers.is_bootstrap_peer(peer_id) {
                // Older releases recorded seeds as generic successful peers.
                // Retire that derived cache entry once the bootstrap identity
                // is known so restarts do not recreate permanent seed load.
                successful_peer_cache.remove(&peer_id);
            } else if automatic_peers.is_outbound(peer_id) {
                for addr in routable_addrs {
                    successful_peer_cache.record_success(peer_id, addr);
                }
            }

            // 2. Arm one bounded random lookup now that at least one routable
            //    peer is present. It starts later on an identity-jittered
            //    maintenance tick. Unselected incoming peers receive bounded
            //    topology credit, so they help the mesh without suppressing
            //    independently selected ordinary neighbours. Starting a
            //    lookup immediately in every newly launched wallet creates a
            //    quadratic relay herd.
            //    Ordinary peers intentionally stay out
            //    of GossipSub's explicit set: explicit peers receive every
            //    publication outside the bounded mesh, producing O(degree)
            //    block and transaction fan-out on large networks.
            if !automatic_peers.initial_discovery_started {
                automatic_peers.initial_discovery_started = true;
                tracing::debug!(
                    delay_ms = automatic_peers
                        .next_discovery_at
                        .saturating_duration_since(Instant::now())
                        .as_millis(),
                    "kad: initial bounded lookup armed"
                );
            }

            tracing::debug!(
                peer = %peer_id,
                protocols = ?info.protocols,
                advertised_addrs = info.listen_addrs.len(),
                accepted_addrs,
                dropped_addrs,
                "peer identified"
            );
        }

        // --- mDNS: dial LAN peers immediately ---
        //
        // Discovered peers are on the same LAN — dial them directly.
        // On the public internet mDNS never fires (UDP broadcast is LAN-scoped).
        SwarmEvent::Behaviour(NodeBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
            let mut dial_addresses: std::collections::HashMap<PeerId, Vec<Multiaddr>> =
                std::collections::HashMap::new();
            for (peer_id, addr) in peers {
                let Some(addr) = sanitize_mdns_peer_addr(peer_id, addr) else {
                    tracing::debug!(peer = %peer_id, "mDNS: ignored non-direct LAN address");
                    continue;
                };
                tracing::debug!(peer = %peer_id, addr = %addr, "mDNS: discovered direct LAN peer");
                swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&peer_id, addr.clone());
                dial_addresses.entry(peer_id).or_default().push(addr);
            }
            let mut dial_addresses = dial_addresses.into_iter().collect::<Vec<_>>();
            dial_addresses.shuffle(&mut rand::thread_rng());
            let mut available = automatic_ordinary_dial_capacity(
                automatic_peers.topology_peer_count(),
                automatic_peers.pending_ordinary_count(),
                false,
                automatic_peers.automatic_dial_capacity(),
            );
            for (peer_id, addresses) in dial_addresses {
                if available == 0 {
                    break;
                }
                if peer_id == *swarm.local_peer_id()
                    || swarm.is_connected(&peer_id)
                    || automatic_peers.is_locally_selected(peer_id)
                {
                    continue;
                }
                // One mDNS answer commonly contains the same PeerId on Wi-Fi,
                // Ethernet and container bridges. Treat those as alternative
                // paths in one conditional attempt; dialing each address as a
                // separate connection races request streams against paths the
                // per-peer limit then closes.
                if begin_lan_peer_dial(swarm, automatic_peers, peer_id, addresses) {
                    available -= 1;
                }
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
            for (peer_id, addr) in peers {
                tracing::debug!(peer = %peer_id, addr = %addr, "mDNS: LAN peer expired");
                swarm.behaviour_mut().kad.remove_address(&peer_id, &addr);
                if !swarm.is_connected(&peer_id) {
                    automatic_peers.clear_local_selection(peer_id);
                }
            }
        }

        // --- Kademlia: log routing table events ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::Kad(ev)) => match ev {
            kad::Event::RoutingUpdated {
                peer, is_new_peer, ..
            } => {
                if is_new_peer {
                    tracing::debug!(peer = %peer, "kad: new peer in routing table");
                }
            }
            kad::Event::OutboundQueryProgressed {
                id,
                step,
                result: kad::QueryResult::GetClosestPeers(Ok(kad::GetClosestPeersOk { peers, .. })),
                ..
            } => {
                let found = peers.len();
                let local = *swarm.local_peer_id();
                let mut learned = false;
                for peer in peers {
                    let mut eligible = Vec::new();
                    for addr in peer.addrs {
                        if relay_circuit_backoff.is_blocked(peer.peer_id, &addr, Instant::now()) {
                            if let Some((_, normalized)) = relay_circuit_route(peer.peer_id, &addr)
                            {
                                swarm
                                    .behaviour_mut()
                                    .kad
                                    .remove_address(&peer.peer_id, &normalized);
                            }
                        } else {
                            eligible.push(addr);
                        }
                    }
                    learned |= automatic_peers.add_peer_candidate(local, peer.peer_id, eligible);
                }
                automatic_peers.observe_discovery(id, learned, step.last);
                tracing::debug!(found, learned, "kad: FIND_NODE returned peers");
            }
            kad::Event::OutboundQueryProgressed {
                id,
                step,
                result:
                    kad::QueryResult::GetClosestPeers(Err(kad::GetClosestPeersError::Timeout {
                        peers,
                        ..
                    })),
                ..
            } => {
                let found = peers.len();
                let local = *swarm.local_peer_id();
                let mut learned = false;
                for peer in peers {
                    let mut eligible = Vec::new();
                    for addr in peer.addrs {
                        if relay_circuit_backoff.is_blocked(peer.peer_id, &addr, Instant::now()) {
                            if let Some((_, normalized)) = relay_circuit_route(peer.peer_id, &addr)
                            {
                                swarm
                                    .behaviour_mut()
                                    .kad
                                    .remove_address(&peer.peer_id, &normalized);
                            }
                        } else {
                            eligible.push(addr);
                        }
                    }
                    learned |= automatic_peers.add_peer_candidate(local, peer.peer_id, eligible);
                }
                automatic_peers.observe_discovery(id, learned, step.last);
                tracing::debug!(
                    found,
                    learned,
                    "kad: timed-out FIND_NODE retained partial peers"
                );
            }
            _ => {}
        },

        // --- Relay client: reservation / circuit events ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::RelayClient(ev)) => match ev {
            relay::client::Event::ReservationReqAccepted { relay_peer_id, .. } => {
                relay_reservations.mark_accepted(relay_peer_id);
                tracing::info!(relay = %relay_peer_id, "relay: reservation accepted — reachable via circuit");
            }
            relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. } => {
                tracing::debug!(relay = %relay_peer_id, "relay: outbound circuit established");
            }
            relay::client::Event::InboundCircuitEstablished { src_peer_id, .. } => {
                tracing::debug!(peer = %src_peer_id, "relay: inbound circuit from peer");
            }
        },

        SwarmEvent::Behaviour(NodeBehaviourEvent::RelayServer(ev)) => match ev {
            relay::Event::ReservationReqAccepted {
                src_peer_id,
                renewed,
            } => {
                tracing::debug!(peer = %src_peer_id, renewed, "relay: bounded reservation accepted");
            }
            #[allow(deprecated)]
            relay::Event::ReservationReqAcceptFailed { src_peer_id, error } => {
                tracing::debug!(peer = %src_peer_id, err = ?error, "relay: reservation rejected");
            }
            relay::Event::CircuitReqDenied {
                src_peer_id,
                dst_peer_id,
            } => {
                tracing::debug!(source = %src_peer_id, destination = %dst_peer_id, "relay: circuit request denied");
            }
            relay::Event::CircuitReqAccepted {
                src_peer_id,
                dst_peer_id,
            } => {
                tracing::debug!(source = %src_peer_id, destination = %dst_peer_id, "relay: bounded circuit accepted");
            }
            relay::Event::CircuitClosed {
                src_peer_id,
                dst_peer_id,
                error,
            } => {
                tracing::debug!(source = %src_peer_id, destination = %dst_peer_id, err = ?error, "relay: circuit closed");
            }
            other => tracing::debug!(event = ?other, "relay: bounded server event"),
        },

        // --- DCUtR: direct connection upgrade through relay ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::Dcutr(dcutr::Event {
            remote_peer_id,
            result,
        })) => match result {
            Ok(_conn_id) => {
                tracing::debug!(
                    peer = %remote_peer_id,
                    "dcutr: hole punch succeeded — direct connection established"
                );
            }
            Err(e) => {
                tracing::debug!(
                    peer = %remote_peer_id,
                    err = %e,
                    "dcutr: hole punch failed — relay connection kept"
                );
            }
        },

        // --- Exact network-v7 profile handshake ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::NetworkProfileSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
                ..
            },
        )) => {
            let current = *network_profile;
            let compatible = request.expected_profile_id == current.profile_id;
            if !compatible {
                tracing::debug!(
                    peer = %peer,
                    expected = ?request.expected_profile_id,
                    local = ?current.profile_id,
                    "peer requested a different network profile"
                );
            }
            let _ = swarm
                .behaviour_mut()
                .network_profile_sync
                .send_response(channel, NetworkProfileResponse { profile: current });
            if compatible {
                // The request states the exact profile the remote endpoint is
                // running against. For honest compatibility detection this is
                // equivalent to checking the symmetric response; a malicious
                // peer can claim either field, so a second request adds no
                // authentication. Let only the dialer initiate the round trip.
                sync_paths.mark_profile_verified(peer);
                relay_reservations.maintain(swarm, &sync_paths.profile_verified, Instant::now());
                if sync_paths.try_mark_announced(peer) {
                    let _ = required_event_tx
                        .send(NetworkEvent::PeerConnected {
                            peer,
                            locally_selected: automatic_peers.is_locally_selected(peer),
                            failure_domain: peer_diversity.failure_domain(peer),
                        })
                        .await;
                }
                tracing::debug!(peer = %peer, profile = ?current.profile_id, "network-v7 profile verified from inbound request");
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::NetworkProfileSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
                ..
            },
        )) => {
            let Some(pending) = pending_network_profile_requests.remove(&request_id) else {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale network-profile response");
                return;
            };
            if pending.peer != peer
                || !response
                    .profile
                    .is_for_proof_bank(network_profile.history_proof_bank_id)
            {
                tracing::warn!(
                    peer = %peer,
                    requested_peer = %pending.peer,
                    profile = ?response.profile.profile_id,
                    "network-v7 profile mismatch; closing peer"
                );
                let _ = swarm.disconnect_peer_id(peer);
                return;
            }
            sync_paths.mark_profile_verified(peer);
            relay_reservations.maintain(swarm, &sync_paths.profile_verified, Instant::now());
            if sync_paths.try_mark_announced(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::PeerConnected {
                        peer,
                        locally_selected: automatic_peers.is_locally_selected(peer),
                        failure_domain: peer_diversity.failure_domain(peer),
                    })
                    .await;
            }
            tracing::debug!(peer = %peer, profile = ?response.profile.profile_id, "network-v7 profile verified");
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::NetworkProfileSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            if pending_network_profile_requests
                .remove(&request_id)
                .is_some()
            {
                tracing::warn!(peer = %peer, err = %error, "network-v7 profile handshake failed");
                let _ = swarm.disconnect_peer_id(peer);
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::NetworkProfileSync(
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            tracing::debug!(peer = %peer, ?request_id, err = %error, "network-profile response failed");
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::NetworkProfileSync(
            request_response::Event::ResponseSent { .. },
        )) => {}

        // --- Content-addressed body/terminal transfer ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::ObjectSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
                ..
            },
        )) => {
            let Some(serving_lease) = data_plane_serving.lease(peer, DataPlaneClass::Live) else {
                let retry_after_ms = data_plane_busy_retry_ms(*swarm.local_peer_id(), peer);
                let response = GetObjectsResponse {
                    status: DataResponseStatus::Busy { retry_after_ms },
                    objects: request
                        .objects
                        .into_iter()
                        .map(|object| ObjectPayload {
                            object,
                            bytes: None,
                        })
                        .collect(),
                    inbound_memory_permit: None,
                    outbound_memory_permit: None,
                };
                let _ = swarm
                    .behaviour_mut()
                    .object_sync
                    .send_response(channel, response);
                tracing::debug!(peer = %peer, retry_after_ms, "exact-object serving queue is full");
                return;
            };
            let declared_bytes = request
                .objects
                .iter()
                .filter_map(|object| object.encoded_len())
                .fold(0usize, |total, length| {
                    total.saturating_add(length as usize)
                });
            let store = chain_store.clone();
            let budget = outbound_response_budget.clone();
            let completion = object_response_tx.clone();
            tokio::spawn(async move {
                let Ok(serving_permits) = serving_lease.acquire().await else {
                    return;
                };
                let Ok(outbound_memory_permit) = budget
                    .acquire_with_serving(declared_bytes, serving_permits)
                    .await
                else {
                    tracing::warn!(peer = %peer, declared_bytes, "exact-object response admission failed");
                    return;
                };
                let requested = request.objects;
                let loaded = tokio::task::spawn_blocking(move || {
                    requested
                        .into_iter()
                        .map(|object| {
                            let bytes = match load_exact_object(&store, object) {
                                Ok(bytes) => bytes,
                                Err(error) => {
                                    tracing::warn!(peer = %peer, ?object, %error, "exact-object storage read failed");
                                    None
                                }
                            };
                            ObjectPayload { object, bytes }
                        })
                        .collect::<Vec<_>>()
                })
                .await;
                let Ok(objects) = loaded else {
                    tracing::warn!(peer = %peer, "exact-object storage worker failed");
                    return;
                };
                let response = GetObjectsResponse {
                    status: DataResponseStatus::Ready,
                    objects,
                    inbound_memory_permit: None,
                    outbound_memory_permit,
                };
                let _ = completion
                    .send(PendingObjectResponse { channel, response })
                    .await;
            });
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::ObjectSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
                ..
            },
        )) => {
            let Some(pending) = pending_object_requests.remove(&request_id) else {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale exact-object response");
                return;
            };
            let response_ids = response
                .objects
                .iter()
                .map(|payload| payload.object)
                .collect::<Vec<_>>();
            if pending.peer != peer || response_ids != pending.objects {
                drop(response);
                let _ = required_event_tx
                    .send(NetworkEvent::ObjectsRequestFailed {
                        token: pending.token,
                        from: pending.peer,
                        objects: pending.objects,
                        kind: RequestFailureKind::InvalidResponse,
                    })
                    .await;
                return;
            }
            let GetObjectsResponse {
                status,
                objects,
                inbound_memory_permit,
                outbound_memory_permit,
            } = response;
            debug_assert!(outbound_memory_permit.is_none());
            if let DataResponseStatus::Busy { retry_after_ms } = status {
                drop(inbound_memory_permit);
                let _ = required_event_tx
                    .send(NetworkEvent::ObjectsRequestBusy {
                        token: pending.token,
                        from: peer,
                        objects: pending.objects,
                        retry_after_ms,
                    })
                    .await;
                return;
            }
            let _ = required_event_tx
                .send(NetworkEvent::ObjectsResponse {
                    token: pending.token,
                    from: peer,
                    objects,
                    inbound_memory_permit,
                })
                .await;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::ObjectSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            let Some(pending) = pending_object_requests.remove(&request_id) else {
                return;
            };
            let _ = required_event_tx
                .send(NetworkEvent::ObjectsRequestFailed {
                    token: pending.token,
                    from: peer,
                    objects: pending.objects,
                    kind: RequestFailureKind::from(&error),
                })
                .await;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::ObjectSync(
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            tracing::debug!(peer = %peer, ?request_id, err = %error, "exact-object response failed");
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::ObjectSync(
            request_response::Event::ResponseSent { .. },
        )) => {}

        // --- Direct exact-object availability between block-mesh peers ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::AvailabilitySync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
                ..
            },
        )) => {
            const AVAILABILITY_RATE_WINDOW: Duration = Duration::from_secs(10);
            const AVAILABILITY_RATE_MAX: u32 = 20;
            let announcement = request.announcement;
            let admissible = sync_paths.is_dispatchable(peer)
                && announcement.providers.serves_body()
                && announcement.providers.serves_terminal()
                && allow_peer_rate(
                    block_event_rate,
                    peer,
                    AVAILABILITY_RATE_MAX,
                    AVAILABILITY_RATE_WINDOW,
                );
            let response = if admissible
                && required_event_tx
                    .try_send(NetworkEvent::HeaderAnnouncement {
                        from: peer,
                        announcement,
                        source_has_objects: true,
                    })
                    .is_ok()
            {
                AvailabilityResponse::Accepted
            } else {
                AvailabilityResponse::Busy
            };
            if swarm
                .behaviour_mut()
                .availability_sync
                .send_response(channel, response)
                .is_err()
            {
                tracing::debug!(peer = %peer, "availability response channel closed");
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::AvailabilitySync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
                ..
            },
        )) => {
            if response == AvailabilityResponse::Busy {
                tracing::debug!(peer = %peer, "mesh peer deferred exact-object availability");
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::AvailabilitySync(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "direct availability delivery failed");
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::AvailabilitySync(
            request_response::Event::InboundFailure { peer, error, .. },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "direct availability response failed");
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::AvailabilitySync(
            request_response::Event::ResponseSent { .. },
        )) => {}

        // --- Request-Response: headers client side (response to our FetchHeaders) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::ChainSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
                ..
            },
        )) => {
            let Some(pending) = pending_header_requests.remove(&request_id) else {
                tracing::debug!(
                    peer = %peer,
                    request_id = %request_id,
                    "ignoring stale header response"
                );
                return;
            };
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded header response");
                return;
            }
            if pending.peer != peer {
                match pending.kind {
                    HeaderRequestKind::General => {
                        let _ = required_event_tx
                            .send(NetworkEvent::HeadersRequestFailed {
                                from: pending.peer,
                                start_height: pending.start_height,
                                count: pending.count,
                                kind: RequestFailureKind::InvalidResponse,
                            })
                            .await;
                    }
                    HeaderRequestKind::Snapshot { generation, token } => {
                        let _ = required_event_tx
                            .send(NetworkEvent::SnapshotHeadersRequestFailed {
                                generation,
                                token,
                                from: pending.peer,
                                start_height: pending.start_height,
                                count: pending.count,
                                kind: RequestFailureKind::InvalidResponse,
                            })
                            .await;
                    }
                }
                return;
            }
            let GetHeadersResponse {
                status,
                records,
                snapshot_boundary,
            } = response;
            if let DataResponseStatus::Busy { retry_after_ms } = status {
                tracing::debug!(
                    from = %peer,
                    retry_after_ms,
                    "header source is temporarily busy"
                );
                match pending.kind {
                    HeaderRequestKind::General => {
                        let _ = required_event_tx
                            .send(NetworkEvent::HeadersRequestFailed {
                                from: pending.peer,
                                start_height: pending.start_height,
                                count: pending.count,
                                kind: RequestFailureKind::LocalCapacity,
                            })
                            .await;
                    }
                    HeaderRequestKind::Snapshot { generation, token } => {
                        let _ = required_event_tx
                            .send(NetworkEvent::SnapshotHeadersRequestFailed {
                                generation,
                                token,
                                from: pending.peer,
                                start_height: pending.start_height,
                                count: pending.count,
                                kind: RequestFailureKind::LocalCapacity,
                            })
                            .await;
                    }
                }
                return;
            }
            let response_shape = match pending.kind {
                HeaderRequestKind::General => validate_general_header_response(&pending, &records),
                HeaderRequestKind::Snapshot { .. } => validate_header_batch_shape(&records),
            };
            if let Err(error) = response_shape {
                tracing::warn!(from = %peer, error, "invalid header batch response — dropped");
                match pending.kind {
                    HeaderRequestKind::General => {
                        let _ = required_event_tx
                            .send(NetworkEvent::HeadersRequestFailed {
                                from: pending.peer,
                                start_height: pending.start_height,
                                count: pending.count,
                                kind: RequestFailureKind::InvalidResponse,
                            })
                            .await;
                    }
                    HeaderRequestKind::Snapshot { generation, token } => {
                        let _ = required_event_tx
                            .send(NetworkEvent::SnapshotHeadersRequestFailed {
                                generation,
                                token,
                                from: pending.peer,
                                start_height: pending.start_height,
                                count: pending.count,
                                kind: RequestFailureKind::InvalidResponse,
                            })
                            .await;
                    }
                }
                return;
            }
            match pending.kind {
                HeaderRequestKind::General => {
                    let _ = required_event_tx
                        .send(NetworkEvent::HeaderInventoryBatch {
                            from: peer,
                            records,
                            snapshot_boundary,
                        })
                        .await;
                }
                HeaderRequestKind::Snapshot { generation, token } => {
                    let headers = records.into_iter().map(|record| record.header).collect();
                    let _ = required_event_tx
                        .send(NetworkEvent::SnapshotHeadersBatch {
                            generation,
                            token,
                            from: peer,
                            start_height: pending.start_height,
                            requested_count: pending.count,
                            headers,
                            snapshot_boundary,
                        })
                        .await;
                }
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::ChainSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            let kind = RequestFailureKind::from(&error);
            let Some(pending) = pending_header_requests.remove(&request_id) else {
                tracing::debug!(
                    peer = %peer,
                    request_id = %request_id,
                    "ignoring stale header request failure"
                );
                return;
            };
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded header request failure");
                return;
            }
            tracing::debug!(
                peer = %peer,
                request_id = %request_id,
                err = %error,
                "header request transport failed"
            );
            match pending.kind {
                HeaderRequestKind::General => {
                    let _ = required_event_tx
                        .send(NetworkEvent::HeadersRequestFailed {
                            from: pending.peer,
                            start_height: pending.start_height,
                            count: pending.count,
                            kind,
                        })
                        .await;
                }
                HeaderRequestKind::Snapshot { generation, token } => {
                    let _ = required_event_tx
                        .send(NetworkEvent::SnapshotHeadersRequestFailed {
                            generation,
                            token,
                            from: pending.peer,
                            start_height: pending.start_height,
                            count: pending.count,
                            kind,
                        })
                        .await;
                }
            }
        }

        // --- Request-Response: headers server side ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::ChainSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
                ..
            },
        )) => {
            let count = request.count.min(
                crate::header_sync_codec::MAX_HEADERS_PER_BATCH
                    .try_into()
                    .expect("header batch cap fits u16"),
            );
            let start_height = request.start_height;
            let include_inventory = request.include_inventory;
            let store = chain_store.clone();
            let preparation_permit = match header_response_prepare_semaphore
                .clone()
                .try_acquire_owned()
            {
                Ok(permit) => permit,
                Err(_) => {
                    let retry_after_ms = data_plane_busy_retry_ms(*swarm.local_peer_id(), peer);
                    let response = GetHeadersResponse {
                        status: DataResponseStatus::Busy { retry_after_ms },
                        records: Vec::new(),
                        snapshot_boundary: None,
                    };
                    if swarm
                        .behaviour_mut()
                        .chain_sync
                        .send_response(channel, response)
                        .is_err()
                    {
                        tracing::debug!(
                            peer = %peer,
                            "header Busy response channel closed"
                        );
                    }
                    tracing::debug!(
                        peer = %peer,
                        retry_after_ms,
                        "header preparation workers are full"
                    );
                    return;
                }
            };
            let completion = header_response_tx.clone();
            tokio::spawn(async move {
                let _preparation_permit = preparation_permit;
                let loaded = tokio::task::spawn_blocking(move || {
                    let snapshot_boundary = local_history_step_boundary(&store)
                        .map(|(height, hash)| crate::object_protocol::ChainPoint::new(height, hash));
                    let records = match store.get_headers(start_height, count) {
                        Ok(headers) => {
                            let tip_height = store
                                .get_chain_tip()
                                .ok()
                                .flatten()
                                .map(|(height, _)| height);
                            let retained_floor = tip_height.map(retained_object_inventory_floor);
                            let target_height = headers.last().map(|header| header.height);
                            headers
                                .into_iter()
                                .map(|header| {
                                    if !include_inventory {
                                        return HeaderInventoryRecord::header_only(header);
                                    }
                                    let body = retained_floor
                                        .is_some_and(|floor| header.height >= floor)
                                        .then(|| {
                                            store.get_recent_block(header.height).ok().flatten()
                                        })
                                        .flatten();
                                    let terminal = (Some(header.height) == target_height)
                                        .then(|| {
                                            let canonical = store
                                                .get_history_step_terminal_at(
                                                    header.height,
                                                    noid_chain::block_header::block_id(&header),
                                                )
                                                .ok()
                                                .flatten();
                                            canonical.or_else(|| {
                                                store
                                                    .get_any_history_step_proof_object(
                                                        header.height,
                                                        noid_chain::block_header::semantic_header_id(
                                                            &header,
                                                        ),
                                                    )
                                                    .ok()
                                                    .flatten()
                                            })
                                        })
                                        .flatten();
                                    match HeaderInventoryRecord::from_retained_objects(
                                        header,
                                        body.as_deref(),
                                        terminal.as_deref(),
                                    ) {
                                        Ok(record) => record,
                                        Err(error) => {
                                            tracing::warn!(
                                                height = header.height,
                                                %error,
                                                "retained header inventory is inconsistent"
                                            );
                                            HeaderInventoryRecord::header_only(header)
                                        }
                                    }
                                })
                                .collect()
                        }
                        Err(error) => {
                            tracing::warn!(
                                start_height,
                                count,
                                err = %error,
                                "canonical header range read failed"
                            );
                            Vec::new()
                        }
                    };
                    (records, snapshot_boundary)
                })
                .await;
                let (records, snapshot_boundary) = match loaded {
                    Ok(loaded) => loaded,
                    Err(error) => {
                        tracing::warn!(
                            start_height,
                            count,
                            err = %error,
                            "header response storage worker failed"
                        );
                        (Vec::new(), None)
                    }
                };
                let _ = completion
                    .send(PendingHeaderResponse {
                        channel,
                        response: GetHeadersResponse {
                            status: DataResponseStatus::Ready,
                            records,
                            snapshot_boundary,
                        },
                    })
                    .await;
            });
        }

        // --- Request-Response: HistoryStep terminal server ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::HistoryStepSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request,
                        channel,
                        request_id,
                    },
                peer,
                ..
            },
        )) => {
            tracing::debug!(
                %peer,
                ?request_id,
                height = request.height,
                "received HistoryStep terminal request"
            );
            // Snapshot-boundary proofs are cold-sync data.  Charging them to
            // the Live class allowed a wave of new wallets to occupy every
            // recent body/terminal slot on a miner.  State admission remains
            // bounded independently, while Live capacity stays available for
            // propagation of the current winning tip.
            let Some(serving_lease) = data_plane_serving.lease(peer, DataPlaneClass::State) else {
                let retry_after_ms = data_plane_busy_retry_ms(*swarm.local_peer_id(), peer);
                let response = GetHistoryStepTerminalResponse {
                    height: request.height,
                    block_hash: request.block_hash,
                    status: DataResponseStatus::Busy { retry_after_ms },
                    terminal_bytes: None,
                    inbound_memory_permit: None,
                    outbound_memory_permit: None,
                };
                let _ = swarm
                    .behaviour_mut()
                    .history_step_sync
                    .send_response(channel, response);
                tracing::debug!(peer = %peer, height = request.height, retry_after_ms, "terminal serving queue is full");
                return;
            };
            // The protocol admits at most four concurrent terminal streams.
            // Queue those streams behind the four storage workers off the
            // swarm loop rather than dropping an exact, immutable terminal
            // request and forcing a second near-megabyte transfer.
            let preparation_admission = history_step_response_prepare_semaphore.clone();
            let store = chain_store.clone();
            let budget = outbound_response_budget.clone();
            let completion = history_step_response_tx.clone();
            let request_height = request.height;
            let request_hash = request.block_hash;
            let leased_generation = snapshot_export_leases.get(&peer).and_then(|lease| {
                let generation = snapshot_exports.get(&lease.key)?;
                let manifest = generation.manifest();
                let exact_boundary = manifest.target_height == request_height
                    && manifest.target_hash == request_hash;
                let exact_bridge = manifest.bridge_tip_height == request_height
                    && manifest.bridge_tip_hash == request_hash;
                if !exact_boundary && !exact_bridge {
                    return None;
                }
                Some((lease.key, generation.clone()))
            });
            let snapshot_lease_key = leased_generation.as_ref().map(|(key, _)| *key);
            tokio::spawn(async move {
                let Ok(serving_permits) = serving_lease.acquire().await else {
                    return;
                };
                let Ok(preparation_permit) = preparation_admission.acquire_owned().await else {
                    return;
                };
                let _preparation_permit = preparation_permit;
                let Ok(Some(outbound_memory_permit)) = budget
                    .acquire_with_serving(MAX_OUTBOUND_HISTORY_STEP_RESPONSE_BYTES, serving_permits)
                    .await
                else {
                    return;
                };
                let loaded = tokio::task::spawn_blocking(move || {
                    if let Some((_, generation)) = leased_generation {
                        return generation
                            .read_terminal_at(request_height, request_hash)
                            .ok();
                    }
                    local_history_step_terminal(&store, request_height, request_hash)
                })
                .await;
                let terminal_bytes = match loaded {
                    Ok(terminal_bytes) => terminal_bytes,
                    Err(error) => {
                        tracing::warn!(err = %error, "HistoryStep response storage worker failed");
                        None
                    }
                };
                let terminal_len = terminal_bytes.as_ref().map_or(0, Vec::len);
                tracing::debug!(
                    %peer,
                    ?request_id,
                    height = request_height,
                    terminal_len,
                    "prepared HistoryStep terminal response"
                );
                let response = GetHistoryStepTerminalResponse {
                    height: request_height,
                    block_hash: request_hash,
                    status: DataResponseStatus::Ready,
                    terminal_bytes,
                    inbound_memory_permit: None,
                    outbound_memory_permit: Some(outbound_memory_permit),
                };
                if completion
                    .send(PendingHistoryStepTerminalResponse {
                        peer,
                        snapshot_lease_key,
                        channel,
                        response,
                    })
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        %peer,
                        ?request_id,
                        height = request_height,
                        "HistoryStep response completion queue closed"
                    );
                }
            });
        }

        // --- Request-Response: HistoryStep terminal client ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::HistoryStepSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
                ..
            },
        )) => {
            let Some(pending) = pending_history_step_requests.remove(&request_id) else {
                tracing::debug!(
                    peer = %peer,
                    request_id = %request_id,
                    "ignoring stale HistoryStep terminal response"
                );
                return;
            };
            if !pending.notify_node {
                tracing::debug!(
                    token = pending.token,
                    peer = %peer,
                    request_id = %request_id,
                    "discarding response for a completed HistoryStep terminal race"
                );
                return;
            }
            if pending.peer != peer
                || pending.height != response.height
                || pending.block_hash != response.block_hash
            {
                tracing::warn!(
                    token = pending.token,
                    peer = %peer,
                    request_id = %request_id,
                    "ignoring mismatched HistoryStep terminal response"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                        token: pending.token,
                        from: pending.peer,
                        height: pending.height,
                        block_hash: pending.block_hash,
                        kind: RequestFailureKind::InvalidResponse,
                    })
                    .await;
                return;
            }
            if let DataResponseStatus::Busy { retry_after_ms } = response.status {
                let _ = required_event_tx
                    .send(NetworkEvent::HistoryStepTerminalRequestBusy {
                        token: pending.token,
                        from: peer,
                        height: pending.height,
                        block_hash: pending.block_hash,
                        retry_after_ms,
                    })
                    .await;
                return;
            }
            if response.terminal_bytes.is_none() {
                tracing::warn!(
                    token = pending.token,
                    peer = %peer,
                    request_id = %request_id,
                    "HistoryStep terminal is unavailable from peer"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                        token: pending.token,
                        from: pending.peer,
                        height: pending.height,
                        block_hash: pending.block_hash,
                        kind: RequestFailureKind::Unavailable,
                    })
                    .await;
                return;
            }
            let inbound_memory_permit = response.inbound_memory_permit.clone();
            let height = response.height;
            let block_hash = response.block_hash;
            let terminal_bytes = response
                .terminal_bytes
                .expect("availability checked before terminal delivery");
            tracing::debug!(
                token = pending.token,
                from = %peer,
                terminal_len = terminal_bytes.len(),
                "received HistoryStep terminal from peer"
            );
            let _ = required_event_tx
                .send(NetworkEvent::HistoryStepTerminal {
                    token: pending.token,
                    from: peer,
                    height,
                    block_hash,
                    terminal_bytes,
                    inbound_memory_permit,
                })
                .await;
        }

        // --- State sync: manifest server (step 1) ---
        //
        // Serve only a fully validated immutable disk generation keyed by the
        // advertised boundary. Live mining cannot mutate its segment files.
        SwarmEvent::Behaviour(NodeBehaviourEvent::StateManifestSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
                ..
            },
        )) => {
            prune_snapshot_export_leases(snapshot_export_leases);
            prune_snapshot_export_disconnect_grace(snapshot_export_disconnect_grace);
            refresh_snapshot_object_retention_floor(
                chain_store,
                snapshot_export_leases,
                snapshot_export_disconnect_grace,
            );
            prune_snapshot_exports(
                snapshot_exports,
                snapshot_export_leases,
                snapshot_export_disconnect_grace,
            );
            let response = 'ready_manifest: {
                let Some(generation) = select_snapshot_export(
                    &chain_store,
                    snapshot_exports,
                    snapshot_export_leases,
                    snapshot_export_disconnect_grace,
                    request.requester_height,
                    request.requested_manifest_digest,
                ) else {
                    break 'ready_manifest GetStateManifestHeader::default();
                };
                let key = generation.key();
                let manifest = generation.manifest();
                let live_tip = chain_store
                    .get_consensus_meta()
                    .ok()
                    .flatten()
                    .map_or(manifest.bridge_tip_height, |meta| meta.tip_height);

                tracing::debug!(
                    requester_height = request.requester_height,
                    snapshot_height = manifest.target_height,
                    live_tip,
                    segments = manifest.segments.len(),
                    "serving cached immutable snapshot manifest"
                );
                let response = generation.manifest_header.as_ref().clone();
                if !lease_snapshot_export(
                    snapshot_export_leases,
                    snapshot_export_disconnect_grace,
                    peer,
                    key,
                    response.manifest_digest,
                    generation.available_until,
                ) {
                    tracing::debug!(
                        peer = %peer,
                        snapshot_height = key.0,
                        "snapshot generation lease capacity is full"
                    );
                    break 'ready_manifest GetStateManifestHeader::default();
                }
                refresh_snapshot_object_retention_floor(
                    chain_store,
                    snapshot_export_leases,
                    snapshot_export_disconnect_grace,
                );
                response
            };
            let _ = swarm
                .behaviour_mut()
                .state_manifest_sync
                .send_response(channel, response);
        }

        // --- State sync: manifest client (step 1 response) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::StateManifestSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
                ..
            },
        )) => {
            let Some(pending) = pending_state_manifest_requests.remove(&request_id) else {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale state-manifest response");
                return;
            };
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded state-manifest response");
                return;
            }
            if pending.peer != peer {
                tracing::debug!(
                    peer = %peer,
                    requested_peer = %pending.peer,
                    request_id = %request_id,
                    "ignoring mismatched state-manifest response"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifestRequestFailed {
                        generation: pending.generation,
                        from: pending.peer,
                        requester_height: pending.requester_height,
                        requested_manifest_digest: pending.requested_manifest_digest,
                        kind: RequestFailureKind::InvalidResponse,
                    })
                    .await;
                return;
            }
            if response.tip_height == 0 {
                if pending.requested_manifest_digest != [0; 32] {
                    let _ = required_event_tx
                        .send(NetworkEvent::StateManifestRequestFailed {
                            generation: pending.generation,
                            from: peer,
                            requester_height: pending.requester_height,
                            requested_manifest_digest: pending.requested_manifest_digest,
                            kind: RequestFailureKind::Unavailable,
                        })
                        .await;
                } else {
                    tracing::debug!(from = %peer, "received empty state manifest header");
                    let _ = required_event_tx
                        .send(NetworkEvent::StateManifest {
                            generation: pending.generation,
                            from: peer,
                            requester_height: pending.requester_height,
                            manifest: VerifiedStateManifest::empty(),
                        })
                        .await;
                }
                return;
            }
            if pending.requested_manifest_digest != [0; 32]
                && response.manifest_digest != pending.requested_manifest_digest
            {
                tracing::warn!(peer = %peer, "exact manifest request returned another generation");
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifestRequestFailed {
                        generation: pending.generation,
                        from: peer,
                        requester_height: pending.requester_height,
                        requested_manifest_digest: pending.requested_manifest_digest,
                        kind: RequestFailureKind::InvalidResponse,
                    })
                    .await;
                return;
            }
            let Some(snapshot) = response.snapshot_id() else {
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifestRequestFailed {
                        generation: pending.generation,
                        from: peer,
                        requester_height: pending.requester_height,
                        requested_manifest_digest: pending.requested_manifest_digest,
                        kind: RequestFailureKind::InvalidResponse,
                    })
                    .await;
                return;
            };
            let key = ManifestAssemblyKey {
                generation: pending.generation,
                snapshot,
            };
            if rejected_manifest_candidates.contains_key(&key) {
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifestRequestFailed {
                        generation: pending.generation,
                        from: peer,
                        requester_height: pending.requester_height,
                        requested_manifest_digest: response.manifest_digest,
                        kind: RequestFailureKind::InvalidResponse,
                    })
                    .await;
                return;
            }
            detach_manifest_provider_from_other_candidates(
                pending.generation,
                peer,
                key,
                manifest_page_assemblies,
                pending_manifest_page_requests,
            );
            if let Some(assembly) = manifest_page_assemblies.get_mut(&key) {
                if assembly.header.as_ref() != &response {
                    let _ = required_event_tx
                        .send(NetworkEvent::StateManifestRequestFailed {
                            generation: pending.generation,
                            from: peer,
                            requester_height: pending.requester_height,
                            requested_manifest_digest: response.manifest_digest,
                            kind: RequestFailureKind::InvalidResponse,
                        })
                        .await;
                    return;
                }
                if assembly.add_provider(peer, pending.requester_height)
                    == ManifestProviderAdmission::Rejected
                {
                    let _ = required_event_tx
                        .send(NetworkEvent::StateManifestRequestFailed {
                            generation: pending.generation,
                            from: peer,
                            requester_height: pending.requester_height,
                            requested_manifest_digest: response.manifest_digest,
                            kind: RequestFailureKind::InvalidResponse,
                        })
                        .await;
                    return;
                }
                emit_verified_manifest_to_new_providers(key, assembly, required_event_tx).await;
            } else {
                if manifest_page_assemblies.len() >= MAX_MANIFEST_PAGE_ASSEMBLIES {
                    let _ = required_event_tx
                        .send(NetworkEvent::StateManifestRequestFailed {
                            generation: pending.generation,
                            from: peer,
                            requester_height: pending.requester_height,
                            requested_manifest_digest: response.manifest_digest,
                            kind: RequestFailureKind::LocalCapacity,
                        })
                        .await;
                    return;
                }
                let Some(mut assembly) =
                    ManifestPageAssembly::new(response, peer, pending.requester_height)
                else {
                    let _ = required_event_tx
                        .send(NetworkEvent::StateManifestRequestFailed {
                            generation: pending.generation,
                            from: peer,
                            requester_height: pending.requester_height,
                            requested_manifest_digest: pending.requested_manifest_digest,
                            kind: RequestFailureKind::InvalidResponse,
                        })
                        .await;
                    return;
                };
                // A valid empty descriptor set is already complete and still
                // goes through the same blocking typestate constructor.
                start_manifest_assembly_if_ready(key, &mut assembly, &manifest_assembly_tx);
                manifest_page_assemblies.insert(key, assembly);
            }
            schedule_manifest_page_requests(
                swarm,
                manifest_page_assemblies,
                pending_manifest_page_requests,
                sync_paths,
            );
        }

        // Descriptor pages are a small, independently admitted State metadata
        // plane. The swarm only clones cached `Arc` bytes; page hashing and
        // manifest construction never run in this reactor.
        SwarmEvent::Behaviour(NodeBehaviourEvent::ManifestPageSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
                ..
            },
        )) => {
            let unavailable = || GetSnapshotManifestPageResponse {
                object: request.object,
                status: DataResponseStatus::Ready,
                data: None,
                inbound_memory_permit: None,
                outbound_memory_permit: None,
            };
            let key = (
                request.object.snapshot.boundary.height,
                request.object.snapshot.boundary.hash,
            );
            let lease_matches = snapshot_export_leases.get(&peer).is_some_and(|lease| {
                lease.key == key && lease.manifest_digest == request.object.snapshot.manifest_digest
            });
            let Some(export) = lease_matches
                .then(|| snapshot_exports.get(&key).cloned())
                .flatten()
            else {
                let _ = swarm
                    .behaviour_mut()
                    .manifest_page_sync
                    .send_response(channel, unavailable());
                return;
            };
            let snapshot_matches = export.network_manifest.tip_height
                == request.object.snapshot.boundary.height
                && export.network_manifest.tip_hash == request.object.snapshot.boundary.hash
                && export.network_manifest.state_root == request.object.snapshot.state_root
                && export.network_manifest.manifest_digest
                    == request.object.snapshot.manifest_digest
                && export.network_manifest.format_version == request.object.snapshot.format_version;
            let index = usize::from(request.object.page.page_index);
            let page_matches = export
                .manifest_header
                .descriptor_pages
                .get(index)
                .is_some_and(|page| *page == request.object.page);
            let Some(data) = (snapshot_matches && page_matches)
                .then(|| export.manifest_pages.get(index).cloned())
                .flatten()
            else {
                let _ = swarm
                    .behaviour_mut()
                    .manifest_page_sync
                    .send_response(channel, unavailable());
                return;
            };
            let Some(serving_lease) = data_plane_serving.lease(peer, DataPlaneClass::StateMetadata)
            else {
                let retry_after_ms = data_plane_busy_retry_ms(*swarm.local_peer_id(), peer);
                let _ = swarm.behaviour_mut().manifest_page_sync.send_response(
                    channel,
                    GetSnapshotManifestPageResponse {
                        object: request.object,
                        status: DataResponseStatus::Busy { retry_after_ms },
                        data: None,
                        inbound_memory_permit: None,
                        outbound_memory_permit: None,
                    },
                );
                return;
            };
            let completion = manifest_page_response_tx.clone();
            let budget = outbound_response_budget.clone();
            let object = request.object;
            tokio::spawn(async move {
                let Ok(serving_permits) = serving_lease.acquire().await else {
                    return;
                };
                let Ok(Some(outbound_memory_permit)) = budget
                    .acquire_with_serving(data.len(), serving_permits)
                    .await
                else {
                    return;
                };
                let _ = completion
                    .send(PendingManifestPageResponse {
                        peer,
                        snapshot_lease: Some((key, object.snapshot.manifest_digest)),
                        channel,
                        response: GetSnapshotManifestPageResponse {
                            object,
                            status: DataResponseStatus::Ready,
                            data: Some(data),
                            inbound_memory_permit: None,
                            outbound_memory_permit: Some(outbound_memory_permit),
                        },
                    })
                    .await;
            });
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::ManifestPageSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
                ..
            },
        )) => {
            let Some(pending) = pending_manifest_page_requests.remove(&request_id) else {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale manifest-page response");
                return;
            };
            let correlated = pending.peer == peer && pending.object == response.object;
            let Some(assembly) = manifest_page_assemblies.get_mut(&pending.key) else {
                return;
            };
            if !correlated {
                assembly.finish_request(pending.object.page.page_index);
                reject_manifest_page_provider(
                    pending.key,
                    pending.peer,
                    manifest_page_assemblies,
                    pending_manifest_page_requests,
                );
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifestRequestFailed {
                        generation: pending.key.generation,
                        from: pending.peer,
                        requester_height: pending.requester_height,
                        requested_manifest_digest: pending.requested_manifest_digest,
                        kind: RequestFailureKind::InvalidResponse,
                    })
                    .await;
                return;
            }
            if let DataResponseStatus::Busy { retry_after_ms } = response.status {
                assembly.finish_request(pending.object.page.page_index);
                assembly.retry_after.insert(
                    (pending.object.page.page_index, peer),
                    Instant::now() + Duration::from_millis(u64::from(retry_after_ms)),
                );
                schedule_manifest_page_requests(
                    swarm,
                    manifest_page_assemblies,
                    pending_manifest_page_requests,
                    sync_paths,
                );
                return;
            }
            if response.data.is_none() {
                assembly.finish_request(pending.object.page.page_index);
                reject_manifest_page_provider(
                    pending.key,
                    peer,
                    manifest_page_assemblies,
                    pending_manifest_page_requests,
                );
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifestRequestFailed {
                        generation: pending.key.generation,
                        from: peer,
                        requester_height: pending.requester_height,
                        requested_manifest_digest: pending.requested_manifest_digest,
                        kind: RequestFailureKind::Unavailable,
                    })
                    .await;
                schedule_manifest_page_requests(
                    swarm,
                    manifest_page_assemblies,
                    pending_manifest_page_requests,
                    sync_paths,
                );
                return;
            }
            let completion = manifest_page_verify_tx.clone();
            tokio::task::spawn_blocking(move || {
                let digest_valid = response
                    .data
                    .as_deref()
                    .is_some_and(|bytes| pending.object.page.matches_bytes(bytes));
                let _ = completion.blocking_send(ManifestPageVerificationCompletion {
                    pending,
                    response,
                    digest_valid,
                });
            });
        }

        // --- State sync: segment server (step 2) ---
        //
        // Responses are pinned to the exact manifest snapshot boundary
        // (height + hash). The immutable disk generation remains available
        // while a live miner advances; only one segment is read per worker.
        SwarmEvent::Behaviour(NodeBehaviourEvent::StateSegmentSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
                ..
            },
        )) => {
            const SEGMENT_RATE_WINDOW: Duration = Duration::from_secs(1);
            const MAX_SEGMENT_REQUESTS_PER_WINDOW: u32 = 64;
            let now = Instant::now();
            let entry = snapshot_segment_rate.entry(peer).or_insert((0, now));
            if now.duration_since(entry.1) >= SEGMENT_RATE_WINDOW {
                *entry = (0, now);
            }
            if entry.0 >= MAX_SEGMENT_REQUESTS_PER_WINDOW {
                let retry_after_ms = data_plane_busy_retry_ms(*swarm.local_peer_id(), peer);
                tracing::debug!(peer = %peer, "snapshot segment request rate limited");
                let _ = swarm.behaviour_mut().state_segment_sync.send_response(
                    channel,
                    busy_state_segment_response(&request, retry_after_ms),
                );
                return;
            }
            entry.0 += 1;
            prune_snapshot_export_leases(snapshot_export_leases);
            prune_snapshot_export_disconnect_grace(snapshot_export_disconnect_grace);
            refresh_snapshot_object_retention_floor(
                chain_store,
                snapshot_export_leases,
                snapshot_export_disconnect_grace,
            );
            prune_snapshot_exports(
                snapshot_exports,
                snapshot_export_leases,
                snapshot_export_disconnect_grace,
            );
            let key = (request.expected_tip_height, request.expected_tip_hash);
            let lease_matches = snapshot_export_leases.get(&peer).is_some_and(|lease| {
                lease.key == key && lease.manifest_digest == request.manifest_digest
            });
            if !lease_matches {
                let _ = swarm
                    .behaviour_mut()
                    .state_segment_sync
                    .send_response(channel, unavailable_state_segment_response(&request));
                return;
            }
            let Some(export) = snapshot_exports.get(&key).cloned() else {
                let _ = swarm
                    .behaviour_mut()
                    .state_segment_sync
                    .send_response(channel, unavailable_state_segment_response(&request));
                return;
            };
            let Some(descriptor) = export.manifest().segment(request.segment_id).copied() else {
                let _ = swarm
                    .behaviour_mut()
                    .state_segment_sync
                    .send_response(channel, unavailable_state_segment_response(&request));
                return;
            };
            let effective_log = export.manifest().effective_log_segment_size;
            let declared_len = descriptor.encoded_len as usize;
            if declared_len > MAX_SEGMENT_BYTES
                || encoded_segment_live_count_from_len(effective_log, declared_len)
                    .is_none_or(|live_count| live_count == 0)
            {
                tracing::warn!(
                    segment = descriptor.segment_id,
                    declared_len,
                    "snapshot descriptor has non-canonical segment length"
                );
                let _ = swarm
                    .behaviour_mut()
                    .state_segment_sync
                    .send_response(channel, unavailable_state_segment_response(&request));
                return;
            }
            let Some(serving_lease) = data_plane_serving.lease(peer, DataPlaneClass::State) else {
                let retry_after_ms = data_plane_busy_retry_ms(*swarm.local_peer_id(), peer);
                let _ = swarm.behaviour_mut().state_segment_sync.send_response(
                    channel,
                    busy_state_segment_response(&request, retry_after_ms),
                );
                tracing::debug!(peer = %peer, segment = request.segment_id, retry_after_ms, "State segment serving queue is full");
                return;
            };
            let requested_tip_height = request.expected_tip_height;
            let requested_tip_hash = request.expected_tip_hash;
            let requested_manifest_digest = request.manifest_digest;
            let completion = segment_response_tx.clone();
            let budget = outbound_response_budget.clone();
            let encode_admission = Arc::clone(segment_encode_semaphore);
            tokio::spawn(async move {
                let Ok(serving_permits) = serving_lease.acquire().await else {
                    return;
                };
                // Stream concurrency and the request rate cap already bound the
                // waiter count. Queue behind the two disk encoders instead of
                // lying that an immutable advertised segment is unavailable.
                let Ok(permit) = encode_admission.acquire_owned().await else {
                    return;
                };
                let Ok(Some(outbound_memory_permit)) = budget
                    .acquire_with_serving(declared_len, serving_permits)
                    .await
                else {
                    return;
                };
                // The exact descriptor length has been admitted before the
                // generation opens or allocates its encoded payload Vec.
                let loaded = tokio::task::spawn_blocking(move || {
                    let _encode_permit = permit;
                    export.read_encoded_segment(descriptor.segment_id)
                })
                .await;
                let response = match loaded {
                    Ok(Ok(data)) => GetStateSegmentResponse {
                        segment_id: descriptor.segment_id,
                        expected_tip_height: requested_tip_height,
                        expected_tip_hash: requested_tip_hash,
                        manifest_digest: requested_manifest_digest,
                        status: DataResponseStatus::Ready,
                        eff_log: effective_log,
                        data: Some(data),
                        inbound_memory_permit: None,
                        outbound_memory_permit: Some(outbound_memory_permit),
                    },
                    Ok(Err(error)) => {
                        tracing::warn!(segment = descriptor.segment_id, err = %error, "disk snapshot segment read failed");
                        GetStateSegmentResponse {
                            segment_id: descriptor.segment_id,
                            expected_tip_height: requested_tip_height,
                            expected_tip_hash: requested_tip_hash,
                            manifest_digest: requested_manifest_digest,
                            status: DataResponseStatus::Ready,
                            eff_log: 0,
                            data: None,
                            inbound_memory_permit: None,
                            // The permit is harmless for an empty response and
                            // is retained until the codec reports completion.
                            outbound_memory_permit: Some(outbound_memory_permit),
                        }
                    }
                    Err(error) => {
                        tracing::warn!(segment = descriptor.segment_id, err = %error, "snapshot segment worker failed");
                        GetStateSegmentResponse {
                            segment_id: descriptor.segment_id,
                            expected_tip_height: requested_tip_height,
                            expected_tip_hash: requested_tip_hash,
                            manifest_digest: requested_manifest_digest,
                            status: DataResponseStatus::Ready,
                            eff_log: 0,
                            data: None,
                            inbound_memory_permit: None,
                            outbound_memory_permit: Some(outbound_memory_permit),
                        }
                    }
                };
                let _ = completion
                    .send(PendingStateSegmentResponse {
                        peer,
                        snapshot_lease: Some((key, requested_manifest_digest)),
                        channel,
                        response,
                    })
                    .await;
            });
        }

        // --- State sync: segment client (step 2 response) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::StateSegmentSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
                ..
            },
        )) => {
            let Some(pending) = pending_state_segment_requests.remove(&request_id) else {
                tracing::warn!(
                    peer = %peer,
                    request_id = %request_id,
                    segment = response.segment_id,
                    "unknown or delayed state-segment response — dropped"
                );
                return;
            };
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded state-segment response");
                return;
            }
            if !state_segment_response_matches_pending(pending, peer, &response) {
                tracing::warn!(
                    peer = %peer,
                    request_id = %request_id,
                    requested_peer = %pending.peer,
                    requested_segment = pending.segment_id,
                    requested_height = pending.expected_tip_height,
                    response_segment = response.segment_id,
                    response_height = response.expected_tip_height,
                    "state-segment response does not match its exact request — dropped"
                );
                fail_state_segment_request!(pending, RequestFailureKind::InvalidResponse);
                return;
            }
            if let DataResponseStatus::Busy { retry_after_ms } = response.status {
                let _ = required_event_tx
                    .send(NetworkEvent::StateSegmentRequestBusy {
                        from: peer,
                        segment_id: pending.segment_id,
                        expected_tip_height: pending.expected_tip_height,
                        expected_tip_hash: pending.expected_tip_hash,
                        manifest_digest: pending.manifest_digest,
                        retry_after_ms,
                    })
                    .await;
                return;
            }
            if let Some(ref data) = response.data {
                let Some(maximum_len) = max_encoded_segment_len_for_eff_log(response.eff_log)
                else {
                    tracing::warn!(peer = %peer, segment = response.segment_id, eff_log = response.eff_log, "segment response has invalid effective segment log — dropped");
                    fail_state_segment_request!(pending, RequestFailureKind::InvalidResponse);
                    return;
                };
                if maximum_len > MAX_SEGMENT_BYTES
                    || encoded_segment_live_count_from_len(response.eff_log, data.len())
                        .is_none_or(|live_count| live_count == 0)
                {
                    tracing::warn!(
                        peer = %peer,
                        segment = response.segment_id,
                        len = data.len(),
                        "segment response has non-canonical sparse length — dropped"
                    );
                    fail_state_segment_request!(pending, RequestFailureKind::InvalidResponse);
                    return;
                }
                if data.len() > MAX_SEGMENT_BYTES {
                    tracing::warn!(peer = %peer, segment = response.segment_id, len = data.len(), "segment response too large — dropped");
                    fail_state_segment_request!(pending, RequestFailureKind::InvalidResponse);
                    return;
                }
            }
            tracing::debug!(
                from = %peer,
                segment_id = response.segment_id,
                present = response.data.is_some(),
                "received state segment"
            );
            let _ = required_event_tx
                .send(NetworkEvent::StateSegment {
                    from: peer,
                    response,
                })
                .await;
        }

        // --- Mempool exchange: pull existing entries or push one new TX ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::MempoolSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
                ..
            },
        )) => match request {
            MempoolRequest::Pull => {
                let Ok(preparation_permit) =
                    Arc::clone(mempool_response_prepare_semaphore).try_acquire_owned()
                else {
                    // Mempool state is recoverable through gossip and a later
                    // sync. Dropping the channel rejects excess preparation
                    // without stalling the swarm task or cloning payload bytes.
                    tracing::debug!(peer = %peer, "mempool sync preparation already occupied");
                    return;
                };
                let budget = outbound_response_budget.clone();
                let mempool = mempool.clone();
                let completion = mempool_response_tx.clone();
                tokio::spawn(async move {
                    // Reserve the maximum legal response before taking the
                    // mempool lock or cloning the first retained intent.
                    let response = match prepare_mempool_response_after_admission(
                        budget,
                        || async {
                            mempool
                                .intent_bytes_prefix(
                                    MAX_MEMPOOL_SYNC_TXS,
                                    MAX_MEMPOOL_SYNC_BYTES,
                                    MAX_TX_INTENT_BYTES_GLOBAL,
                                )
                                .await
                        },
                    )
                    .await
                    {
                        Ok(response) => response,
                        Err(error) => {
                            tracing::debug!(peer = %peer, err = %error, "mempool sync byte admission failed");
                            return;
                        }
                    };
                    let total_bytes: usize = response.txs.iter().map(Vec::len).sum();
                    tracing::debug!(
                        peer = %peer,
                        tx_count = response.txs.len(),
                        total_bytes,
                        "serving mempool sync request"
                    );
                    let _preparation_permit = preparation_permit;
                    let _ = completion
                        .send(PendingMempoolResponse { channel, response })
                        .await;
                });
            }
            MempoolRequest::Push {
                intent_bytes,
                inbound_memory_permit,
            } => {
                let response = GetMempoolResponse {
                    txs: Vec::new(),
                    inbound_memory_permit: None,
                    outbound_memory_permit: None,
                };
                let _ = swarm
                    .behaviour_mut()
                    .mempool_sync
                    .send_response(channel, response);
                if !allow_peer_rate(
                    tx_gossip_rate,
                    peer,
                    TX_RELAY_RATE_MAX,
                    TX_RELAY_RATE_WINDOW,
                ) {
                    tracing::debug!(peer = %peer, "direct tx relay rate limit exceeded");
                    return;
                }
                let len = intent_bytes.len();
                if let Err(error) = required_event_tx.try_send(NetworkEvent::NewTx {
                    from: peer,
                    intent_bytes,
                    gossip_message_id: None,
                    inbound_memory_permit,
                }) {
                    tracing::debug!(
                        peer = %peer,
                        len,
                        err = %error,
                        "direct tx relay dropped under node backpressure"
                    );
                } else {
                    tracing::debug!(peer = %peer, len, "received direct transaction relay");
                }
            }
        },

        // --- Mempool sync: client side (response to our request) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::MempoolSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
                ..
            },
        )) => {
            mempool_sync_retries.remove(&peer);
            let GetMempoolResponse {
                txs,
                inbound_memory_permit,
                outbound_memory_permit: _,
            } = response;
            tracing::debug!(
                from = %peer,
                tx_count = txs.len(),
                "mempool sync response complete"
            );
            if !txs.is_empty() {
                tracing::debug!(
                    from = %peer,
                    tx_count = txs.len(),
                    "received mempool sync response"
                );
                // The fixed codec has already validated all caps. Mempool sync
                // is recoverable, so do not block the swarm if authoritative
                // sync events currently occupy the bounded node queue.
                if let Err(error) = required_event_tx.try_send(NetworkEvent::MempoolSyncResponse {
                    from: peer,
                    txs,
                    inbound_memory_permit,
                }) {
                    tracing::debug!(peer = %peer, err = %error, "mempool sync response dropped under node backpressure");
                }
            }
        }

        // --- Mempool sync: outbound failure ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::MempoolSync(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            // A simultaneous handshake or a busy bounded response worker is
            // transient. Keep the one-stream memory discipline and retry with
            // bounded exponential backoff plus per-peer jitter.
            mempool_sync_last_request.remove(&peer);
            let local = *swarm.local_peer_id();
            if let Some(retry) = schedule_mempool_sync_retry(mempool_sync_retries, local, peer) {
                tracing::debug!(
                    peer = %peer,
                    err = %error,
                    failures = retry.failures,
                    retry_ms = retry.next_attempt.saturating_duration_since(Instant::now()).as_millis(),
                    "mempool sync request failed — retry scheduled"
                );
            } else {
                tracing::debug!(
                    peer = %peer,
                    err = %error,
                    failures = MAX_MEMPOOL_SYNC_FAILURES,
                    "mempool sync request failed — retry limit reached"
                );
            }
        }

        // --- Connection events ---
        SwarmEvent::ConnectionEstablished {
            peer_id,
            connection_id,
            endpoint,
            ..
        } => {
            let dialer = endpoint.is_dialer();
            let direct = !endpoint.is_relayed();
            sync_paths.insert(connection_id, peer_id, direct, dialer);
            if let Err(reason) = peer_diversity.try_admit(
                connection_id,
                peer_id,
                endpoint.get_remote_address(),
                dialer,
            ) {
                sync_paths.mark_closing(connection_id);
                automatic_peers.note_dial_failed(connection_id);
                let _ = swarm.close_connection(connection_id);
                // `BucketInserts::OnConnected` may have admitted the peer just
                // before the outer swarm event reached us. Do not let a
                // rejected Sybil occupy Kademlia and trigger repeated dials.
                swarm.behaviour_mut().kad.remove_peer(&peer_id);
                tracing::debug!(
                    peer = %peer_id,
                    address = %endpoint.get_remote_address(),
                    ?reason,
                    "closing connection that violates public peer diversity"
                );
                return;
            }
            if !direct && relay_circuit_backoff.note_success(peer_id, endpoint.get_remote_address())
            {
                tracing::debug!(
                    destination = %peer_id,
                    address = %endpoint.get_remote_address(),
                    "relay circuit route recovered; retry backoff cleared"
                );
            }
            if dialer && direct {
                relay_reservations.observe_direct_transport(
                    peer_id,
                    endpoint.get_remote_address().clone(),
                    peer_diversity.failure_domain(peer_id),
                );
            }
            automatic_peers.note_connection_established(
                connection_id,
                peer_id,
                dialer,
                (dialer && direct).then_some(endpoint.get_remote_address()),
            );
            let duplicate_losers =
                sync_paths.canonicalize_direct(*swarm.local_peer_id(), peer_id, connection_id);
            for loser in &duplicate_losers {
                let _ = swarm.close_connection(*loser);
            }
            tracing::debug!(
                peer = %peer_id,
                ?connection_id,
                dialer,
                direct,
                duplicate_losers = ?duplicate_losers,
                "peer transport connected; awaiting Identify"
            );
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            connection_id,
            num_established,
            cause,
            ..
        } => {
            let removed_sync_path = sync_paths.remove(connection_id);
            if peer_diversity.remove(connection_id) {
                automatic_peers.note_connection_closed(connection_id);
            } else {
                tracing::debug!(
                    peer = %peer_id,
                    "diversity-rejected connection closed"
                );
            }
            debug_assert!(
                removed_sync_path.is_none_or(|path_peer| path_peer == peer_id),
                "ConnectionClosed peer must match the tracked sync path"
            );
            let sync_peer_became_unready =
                sync_paths.is_announced(peer_id) && !sync_paths.has_identified_path(peer_id);
            if sync_peer_became_unready {
                sync_paths.clear_announced(peer_id);
                // Deliver exact request failures before the generic
                // disconnect event. This deterministic ordering lets the node
                // retain or fail over its disk staging without racing the
                // broader peer cleanup path.
                let failed_objects =
                    pending_object_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_objects {
                    let _ = required_event_tx
                        .send(NetworkEvent::ObjectsRequestFailed {
                            token: pending.token,
                            from: pending.peer,
                            objects: pending.objects,
                            kind: RequestFailureKind::ConnectionClosed,
                        })
                        .await;
                }
                let failed_headers =
                    pending_header_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_headers {
                    if !pending.notify_node {
                        continue;
                    }
                    match pending.kind {
                        HeaderRequestKind::General => {
                            let _ = required_event_tx
                                .send(NetworkEvent::HeadersRequestFailed {
                                    from: pending.peer,
                                    start_height: pending.start_height,
                                    count: pending.count,
                                    kind: RequestFailureKind::ConnectionClosed,
                                })
                                .await;
                        }
                        HeaderRequestKind::Snapshot { generation, token } => {
                            let _ = required_event_tx
                                .send(NetworkEvent::SnapshotHeadersRequestFailed {
                                    generation,
                                    token,
                                    from: pending.peer,
                                    start_height: pending.start_height,
                                    count: pending.count,
                                    kind: RequestFailureKind::ConnectionClosed,
                                })
                                .await;
                        }
                    }
                }
                let failed_segments =
                    pending_state_segment_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_segments {
                    fail_state_segment_request!(pending, RequestFailureKind::ConnectionClosed);
                }
                let failed_terminals =
                    pending_history_step_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_terminals {
                    if pending.notify_node {
                        let _ = required_event_tx
                            .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                                token: pending.token,
                                from: pending.peer,
                                height: pending.height,
                                block_hash: pending.block_hash,
                                kind: RequestFailureKind::ConnectionClosed,
                            })
                            .await;
                    }
                }
                let failed_manifests =
                    pending_state_manifest_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_manifests {
                    if pending.notify_node {
                        let _ = required_event_tx
                            .send(NetworkEvent::StateManifestRequestFailed {
                                generation: pending.generation,
                                from: pending.peer,
                                requester_height: pending.requester_height,
                                requested_manifest_digest: pending.requested_manifest_digest,
                                kind: RequestFailureKind::ConnectionClosed,
                            })
                            .await;
                    }
                }
                let failed_manifest_candidates = disconnect_manifest_page_provider(
                    peer_id,
                    manifest_page_assemblies,
                    pending_manifest_page_requests,
                );
                for (key, requester_height) in failed_manifest_candidates {
                    let _ = required_event_tx
                        .send(NetworkEvent::StateManifestRequestFailed {
                            generation: key.generation,
                            from: peer_id,
                            requester_height,
                            requested_manifest_digest: key.snapshot.manifest_digest,
                            kind: RequestFailureKind::ConnectionClosed,
                        })
                        .await;
                }
                let _ = required_event_tx
                    .send(NetworkEvent::PeerDisconnected(peer_id))
                    .await;
                tracing::debug!(peer = %peer_id, cause = ?cause, "peer lost its last sync-ready connection");
            }
            if sync_paths.try_mark_announced(peer_id) {
                let _ = required_event_tx
                    .send(NetworkEvent::PeerConnected {
                        peer: peer_id,
                        locally_selected: automatic_peers.is_locally_selected(peer_id),
                        failure_domain: peer_diversity.failure_domain(peer_id),
                    })
                    .await;
                tracing::debug!(peer = %peer_id, "peer sync protocols ready after duplicate path closed");
            }
            if num_established == 0 {
                automatic_peers.clear_local_selection(peer_id);
                relay_reservations.retire_peer(swarm, peer_id);
                sync_paths.clear_profile_verified(peer_id);
                pending_network_profile_requests.take_where(|pending| pending.peer == peer_id);
                block_event_rate.remove(&peer_id);
                tx_gossip_rate.remove(&peer_id);
                mempool_sync_last_request.remove(&peer_id);
                mempool_sync_retries.remove(&peer_id);
                snapshot_segment_rate.remove(&peer_id);
                detach_snapshot_export_lease(
                    snapshot_export_leases,
                    snapshot_export_disconnect_grace,
                    peer_id,
                );
                prune_snapshot_export_disconnect_grace(snapshot_export_disconnect_grace);
                refresh_snapshot_object_retention_floor(
                    chain_store,
                    snapshot_export_leases,
                    snapshot_export_disconnect_grace,
                );
                prune_snapshot_exports(
                    snapshot_exports,
                    snapshot_export_leases,
                    snapshot_export_disconnect_grace,
                );
            }
        }

        // --- Outgoing connection failed (dial error) ---
        SwarmEvent::OutgoingConnectionError {
            peer_id,
            connection_id,
            error,
            ..
        } => {
            if let (Some(destination), libp2p::swarm::DialError::Transport(errors)) =
                (peer_id, &error)
            {
                let mut suppressed_routes = std::collections::HashSet::new();
                for (addr, _) in errors {
                    let Some((route, _)) = relay_circuit_route(destination, addr) else {
                        continue;
                    };
                    if !suppressed_routes.insert(route) {
                        continue;
                    }
                    if let Some((_, normalized_addr, failures, delay)) =
                        relay_circuit_backoff.note_failure(destination, addr, Instant::now())
                    {
                        automatic_peers.remove_peer_candidate_addr(destination, &normalized_addr);
                        swarm
                            .behaviour_mut()
                            .kad
                            .remove_address(&destination, &normalized_addr);
                        tracing::debug!(
                            relay = %route.relay,
                            destination = %destination,
                            failures,
                            retry_ms = delay.as_millis(),
                            "failed relay circuit route entered bounded backoff"
                        );
                    }
                }
            }
            automatic_peers.note_dial_failed(connection_id);
            if let Some(peer) = peer_id.filter(|peer| !swarm.is_connected(peer)) {
                automatic_peers.clear_local_selection(peer);
            }
            tracing::debug!(peer = ?peer_id, err = %error, "outgoing connection error");
            // The automatic manager retries bootstrap addresses and replaces
            // ordinary peers with bounded backoff.
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::StateManifestSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            let kind = RequestFailureKind::from(&error);
            tracing::debug!(peer = %peer, err = %error, "manifest sync request failed");
            let Some(pending) = pending_state_manifest_requests.remove(&request_id) else {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale state-manifest failure");
                return;
            };
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded state-manifest failure");
                return;
            }
            if pending.peer != peer {
                tracing::debug!(
                    peer = %peer,
                    requested_peer = %pending.peer,
                    request_id = %request_id,
                    "ignoring mismatched state-manifest failure"
                );
                return;
            }
            let _ = required_event_tx
                .send(NetworkEvent::StateManifestRequestFailed {
                    generation: pending.generation,
                    from: peer,
                    requester_height: pending.requester_height,
                    requested_manifest_digest: pending.requested_manifest_digest,
                    kind,
                })
                .await;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::ManifestPageSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            let Some(pending) = pending_manifest_page_requests.remove(&request_id) else {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale manifest-page failure");
                return;
            };
            let kind = RequestFailureKind::from(&error);
            let mut rejected = false;
            if let Some(assembly) = manifest_page_assemblies.get_mut(&pending.key) {
                assembly.finish_request(pending.object.page.page_index);
                if peer != pending.peer || kind == RequestFailureKind::InvalidResponse {
                    rejected = true;
                } else {
                    assembly.retry_after.insert(
                        (pending.object.page.page_index, pending.peer),
                        Instant::now() + MANIFEST_PAGE_OPERATIONAL_RETRY,
                    );
                }
            }
            if rejected {
                reject_manifest_page_provider(
                    pending.key,
                    pending.peer,
                    manifest_page_assemblies,
                    pending_manifest_page_requests,
                );
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifestRequestFailed {
                        generation: pending.key.generation,
                        from: pending.peer,
                        requester_height: pending.requester_height,
                        requested_manifest_digest: pending.requested_manifest_digest,
                        kind: RequestFailureKind::InvalidResponse,
                    })
                    .await;
            }
            schedule_manifest_page_requests(
                swarm,
                manifest_page_assemblies,
                pending_manifest_page_requests,
                sync_paths,
            );
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::StateSegmentSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "segment sync request failed");
            let Some(pending) = pending_state_segment_requests.remove(&request_id) else {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale segment-sync failure");
                return;
            };
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded state-segment failure");
                return;
            }
            if pending.peer != peer {
                tracing::debug!(
                    peer = %peer,
                    requested_peer = %pending.peer,
                    request_id = %request_id,
                    "ignoring mismatched segment-sync failure"
                );
                return;
            }
            fail_state_segment_request!(pending, RequestFailureKind::from(&error));
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::HistoryStepSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            let kind = RequestFailureKind::from(&error);
            tracing::warn!(
                peer = %peer,
                request_id = %request_id,
                ?kind,
                err = %error,
                "HistoryStep terminal request transport failed"
            );
            let Some(pending) = pending_history_step_requests.remove(&request_id) else {
                tracing::debug!(
                    peer = %peer,
                    request_id = %request_id,
                    "ignoring stale HistoryStep request failure"
                );
                return;
            };
            if pending.peer != peer {
                tracing::debug!(
                    peer = %peer,
                    requested_peer = %pending.peer,
                    request_id = %request_id,
                    "ignoring mismatched HistoryStep request failure"
                );
                return;
            }
            if pending.notify_node {
                let _ = required_event_tx
                    .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                        token: pending.token,
                        from: peer,
                        height: pending.height,
                        block_hash: pending.block_hash,
                        kind,
                    })
                    .await;
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::HistoryStepSync(
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            tracing::warn!(
                %peer,
                ?request_id,
                err = %error,
                "HistoryStep terminal response failed"
            );
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::HistoryStepSync(
            request_response::Event::ResponseSent {
                peer, request_id, ..
            },
        )) => {
            tracing::debug!(
                %peer,
                ?request_id,
                "HistoryStep terminal response flushed"
            );
        }

        SwarmEvent::NewListenAddr { address, .. } => {
            tracing::debug!(%address, "P2P listening");
        }

        SwarmEvent::ListenerClosed {
            listener_id,
            reason,
            ..
        } => {
            if let Some(peer) = relay_reservations.remove_listener(listener_id) {
                tracing::debug!(relay = %peer, ?reason, "relay reservation listener closed; retry scheduled");
            }
        }

        SwarmEvent::ListenerError { listener_id, error } => {
            if let Some(peer) = relay_reservations.remove_listener(listener_id) {
                tracing::debug!(relay = %peer, %error, "relay reservation listener failed; retry scheduled");
            } else {
                tracing::warn!(?listener_id, %error, "P2P listener failed");
            }
        }

        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    fn ordered_peer_ids() -> (PeerId, PeerId) {
        let first = PeerId::random();
        let second = PeerId::random();
        if first.to_bytes() < second.to_bytes() {
            (first, second)
        } else {
            (second, first)
        }
    }

    fn manifest_header(discriminator: u8) -> GetStateManifestHeader {
        let mut manifest = GetStateManifestResponse {
            tip_height: 77,
            tip_hash: [discriminator; 32],
            cumulative_chainwork: [discriminator.wrapping_add(1); 32],
            format_version: crate::protocol::SNAPSHOT_MANIFEST_FORMAT_VERSION,
            state_root: [discriminator.wrapping_add(2); 32],
            log_slots: 17,
            active_slot_count: 9,
            alloc_counter: 12,
            eff_log: 16,
            bridge_tip_height: 77,
            bridge_tip_hash: [discriminator; 32],
            bridge_cumulative_chainwork: [discriminator.wrapping_add(1); 32],
            segment_ids: vec![0, 1],
            segment_roots: vec![[3; 32], [4; 32]],
            segment_lengths: vec![209, 259],
            ..Default::default()
        };
        assert!(manifest.seal_manifest_digest());
        manifest.to_header_and_pages().unwrap().0
    }

    #[test]
    fn rejected_manifest_provider_cannot_reenter_the_same_candidate() {
        let peer = PeerId::random();
        let mut assembly = ManifestPageAssembly::new(manifest_header(7), peer, 10).unwrap();
        assembly.reject_provider(peer);
        assert_eq!(
            assembly.add_provider(peer, 11),
            ManifestProviderAdmission::Rejected
        );
        assert!(!assembly.has_live_providers());
    }

    #[test]
    fn manifest_disconnect_preserves_locally_received_pages() {
        let peer = PeerId::random();
        let header = manifest_header(8);
        let key = ManifestAssemblyKey {
            generation: 3,
            snapshot: header.snapshot_id().unwrap(),
        };
        let mut assembly = ManifestPageAssembly::new(header, peer, 10).unwrap();
        assembly.pages[0] = Some(VerifiedManifestPageBytes {
            bytes: Arc::from([1u8, 2, 3]),
            _inbound_memory_permit: None,
        });
        let mut assemblies = std::collections::HashMap::from([(key, assembly)]);
        let mut pending = BoundedPendingRequests::new(4);

        let disconnected = disconnect_manifest_page_provider(peer, &mut assemblies, &mut pending);

        assert_eq!(disconnected, vec![(key, 10)]);
        assert!(assemblies.contains_key(&key));
        assert!(assemblies[&key].has_local_progress());
        assert!(!assemblies[&key].has_live_providers());
    }

    #[test]
    fn manifest_provider_occupies_only_one_candidate_per_generation() {
        let peer = PeerId::random();
        let old_header = manifest_header(9);
        let new_header = manifest_header(10);
        let old_key = ManifestAssemblyKey {
            generation: 4,
            snapshot: old_header.snapshot_id().unwrap(),
        };
        let new_key = ManifestAssemblyKey {
            generation: 4,
            snapshot: new_header.snapshot_id().unwrap(),
        };
        let mut assemblies = std::collections::HashMap::from([(
            old_key,
            ManifestPageAssembly::new(old_header, peer, 10).unwrap(),
        )]);
        let mut pending = BoundedPendingRequests::new(4);

        detach_manifest_provider_from_other_candidates(
            4,
            peer,
            new_key,
            &mut assemblies,
            &mut pending,
        );

        assert!(!assemblies.contains_key(&old_key));
    }

    #[test]
    fn snapshot_generation_advance_releases_every_older_candidate() {
        let old_peer = PeerId::random();
        let current_peer = PeerId::random();
        let old_header = manifest_header(11);
        let current_header = manifest_header(12);
        let old_key = ManifestAssemblyKey {
            generation: 4,
            snapshot: old_header.snapshot_id().unwrap(),
        };
        let current_key = ManifestAssemblyKey {
            generation: 5,
            snapshot: current_header.snapshot_id().unwrap(),
        };
        let mut assemblies = std::collections::HashMap::from([
            (
                old_key,
                ManifestPageAssembly::new(old_header, old_peer, 10).unwrap(),
            ),
            (
                current_key,
                ManifestPageAssembly::new(current_header, current_peer, 10).unwrap(),
            ),
        ]);
        let mut rejected = std::collections::HashMap::from([
            (old_key, Instant::now()),
            (current_key, Instant::now()),
        ]);
        let mut pending_manifests = BoundedPendingRequests::new(4);
        let mut pending_pages = BoundedPendingRequests::new(4);
        let mut latest = 3;

        assert!(advance_manifest_generation(
            5,
            &mut latest,
            &mut pending_manifests,
            &mut pending_pages,
            &mut assemblies,
            &mut rejected,
        ));
        assert_eq!(latest, 5);
        assert!(!assemblies.contains_key(&old_key));
        assert!(!rejected.contains_key(&old_key));
        assert!(assemblies.contains_key(&current_key));
        assert!(rejected.contains_key(&current_key));

        assert!(!advance_manifest_generation(
            4,
            &mut latest,
            &mut pending_manifests,
            &mut pending_pages,
            &mut assemblies,
            &mut rejected,
        ));
        assert!(assemblies.contains_key(&current_key));
    }

    #[test]
    fn snapshot_lease_progress_is_fixed_and_duplicate_safe() {
        let mut progress = SnapshotLeaseProgressSet::new();
        assert!(progress.insert(SnapshotLeaseProgress::Segment(u16::MAX)));
        assert!(!progress.insert(SnapshotLeaseProgress::Segment(u16::MAX)));
        assert!(progress.insert(SnapshotLeaseProgress::ManifestPage(63)));
        assert!(!progress.insert(SnapshotLeaseProgress::ManifestPage(63)));
        assert!(!progress.insert(SnapshotLeaseProgress::ManifestPage(64)));
        assert!(progress.insert(SnapshotLeaseProgress::Terminal {
            height: 1,
            block_hash: [1; 32],
        }));
        assert!(!progress.insert(SnapshotLeaseProgress::Terminal {
            height: 1,
            block_hash: [1; 32],
        }));
    }

    #[test]
    fn relay_reservation_address_requires_one_public_direct_transport() {
        use libp2p::multiaddr::Protocol;

        let peer = PeerId::random();
        let direct: Multiaddr = "/ip4/8.8.8.8/tcp/9500".parse().unwrap();
        let reservation = relay_reservation_addr(peer, direct.clone()).unwrap();
        assert_eq!(
            reservation,
            direct.with(Protocol::P2p(peer)).with(Protocol::P2pCircuit)
        );

        let private: Multiaddr = "/ip4/10.0.0.2/tcp/9500".parse().unwrap();
        assert!(relay_reservation_addr(peer, private).is_none());

        let nested = reservation.with(Protocol::P2p(PeerId::random()));
        assert!(relay_reservation_addr(peer, nested).is_none());
    }

    #[test]
    fn mdns_accepts_only_the_named_peers_direct_lan_transport() {
        let peer = PeerId::random();
        let other = PeerId::random();
        let direct: Multiaddr = "/ip4/192.168.10.20/tcp/9500".parse().unwrap();

        assert_eq!(
            sanitize_mdns_peer_addr(
                peer,
                direct.clone().with(libp2p::multiaddr::Protocol::P2p(peer)),
            ),
            Some(direct.clone())
        );
        assert_eq!(
            sanitize_mdns_peer_addr(peer, direct.clone()),
            Some(direct.clone())
        );
        assert!(sanitize_mdns_peer_addr(
            peer,
            direct.clone().with(libp2p::multiaddr::Protocol::P2p(other))
        )
        .is_none());
        assert!(sanitize_mdns_peer_addr(
            peer,
            direct
                .with(libp2p::multiaddr::Protocol::P2p(other))
                .with(libp2p::multiaddr::Protocol::P2pCircuit)
                .with(libp2p::multiaddr::Protocol::P2p(peer))
        )
        .is_none());
    }

    #[test]
    fn relay_candidate_rank_is_salted_by_local_identity() {
        let candidate = PeerId::random();
        let first_local = PeerId::random();
        let second_local = PeerId::random();
        let first = RelayReservations::new(2, first_local);
        let first_again = RelayReservations::new(2, first_local);
        let second = RelayReservations::new(2, second_local);

        assert_eq!(
            first.candidate_rank(candidate),
            first_again.candidate_rank(candidate)
        );
        assert_ne!(
            first.candidate_rank(candidate),
            second.candidate_rank(candidate)
        );
    }

    #[test]
    fn pending_and_accepted_relay_carriers_are_protected_from_topology_pruning() {
        let relay = PeerId::random();
        let unrelated = PeerId::random();
        let mut reservations = RelayReservations::new(2, PeerId::random());
        reservations.active.insert(
            relay,
            RelayReservation {
                listener_id: libp2p::core::transport::ListenerId::next(),
                failure_domain: 1,
                requested_at: Instant::now(),
                accepted: false,
            },
        );

        assert!(reservations.protects_peer(relay));
        assert!(!reservations.protects_peer(unrelated));
        reservations.mark_accepted(relay);
        assert!(reservations.protects_peer(relay));
    }

    #[test]
    fn identify_cannot_create_a_relay_candidate_without_a_direct_dial() {
        let peer = PeerId::random();
        let mut reservations = RelayReservations::new(2, PeerId::random());
        reservations.observe_identified_transports(
            peer,
            ["/ip4/8.8.8.8/tcp/9500".parse().unwrap()],
            1,
        );
        assert!(!reservations.candidates.contains_key(&peer));
        assert!(!reservations.proven_direct_dial_peers.contains(&peer));
    }

    #[test]
    fn successful_dns_dial_admits_only_bounded_identified_relay_addresses() {
        let peer = PeerId::random();
        let mut reservations = RelayReservations::new(2, PeerId::random());
        reservations.observe_direct_transport(
            peer,
            "/dns4/seed.example/tcp/9500".parse().unwrap(),
            7,
        );
        assert!(reservations.proven_direct_dial_peers.contains(&peer));
        assert!(!reservations.candidates.contains_key(&peer));

        reservations.observe_identified_transports(
            peer,
            [
                "/ip4/8.8.8.8/tcp/9500".parse().unwrap(),
                "/ip4/8.8.4.4/tcp/9500".parse().unwrap(),
                "/ip4/1.1.1.1/tcp/9500".parse().unwrap(),
            ],
            7,
        );
        let candidate = reservations.candidates.get(&peer).unwrap();
        assert_eq!(candidate.addrs.len(), 2);
        assert_eq!(candidate.failure_domain, 7);
    }

    #[test]
    fn automatic_discovery_keeps_a_routable_relay_path() {
        use libp2p::multiaddr::Protocol;

        let relay = PeerId::random();
        let destination = PeerId::random();
        let advertised = "/ip4/8.8.4.4/tcp/9500"
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(relay))
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(destination));
        let dial_addr = sanitize_automatic_peer_addr(destination, advertised).unwrap();
        assert!(dial_addr
            .iter()
            .any(|protocol| matches!(protocol, Protocol::P2pCircuit)));
        assert!(crate::peer_diversity::contains_public_ip(&dial_addr));
    }

    #[test]
    fn automatic_peer_addresses_prefer_direct_before_relay_fallbacks() {
        use libp2p::multiaddr::Protocol;

        let destination = PeerId::random();
        let first_relay = PeerId::random();
        let second_relay = PeerId::random();
        let direct: Multiaddr = "/ip4/1.1.1.1/tcp/9600".parse().unwrap();
        let relay_one = "/ip4/8.8.8.8/tcp/9600"
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(first_relay))
            .with(Protocol::P2pCircuit);
        let relay_two = "/ip4/8.8.4.4/tcp/9600"
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(second_relay))
            .with(Protocol::P2pCircuit);
        let mut addresses = vec![relay_one.clone(), relay_two.clone(), direct.clone()];

        prioritize_peer_addresses(destination, &[], &mut addresses);

        assert_eq!(addresses[0], direct);
        assert!(addresses[1..]
            .iter()
            .all(|addr| relay_circuit_route(destination, addr).is_some()));
        assert!(addresses.contains(&relay_one));
        assert!(addresses.contains(&relay_two));

        prioritize_peer_addresses(destination, std::slice::from_ref(&direct), &mut addresses);
        assert!(relay_circuit_route(destination, &addresses[0]).is_some());
        assert_eq!(addresses.last(), Some(&direct));
    }

    #[test]
    fn relay_circuit_backoff_is_scoped_to_one_relay_destination_pair() {
        use libp2p::multiaddr::Protocol;

        let relay = PeerId::random();
        let destination = PeerId::random();
        let other_destination = PeerId::random();
        let advertised = "/ip4/8.8.4.4/tcp/9500"
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(relay))
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(destination));
        let direct = "/ip4/1.1.1.1/tcp/9500".parse::<Multiaddr>().unwrap();
        let now = Instant::now();
        let mut backoff = RelayCircuitBackoff::default();

        let (route, normalized, failures, delay) =
            backoff.note_failure(destination, &advertised, now).unwrap();
        assert_eq!(route.relay, relay);
        assert_eq!(route.destination, destination);
        assert_eq!(
            normalized,
            sanitize_automatic_peer_addr(destination, advertised.clone()).unwrap()
        );
        assert_eq!(failures, 1);
        assert_eq!(delay, Duration::from_secs(30));
        assert!(backoff.is_blocked(destination, &advertised, now));
        assert!(!backoff.is_blocked(other_destination, &advertised, now));
        assert!(!backoff.is_blocked(destination, &direct, now));

        assert!(backoff.take_due(now + Duration::from_secs(29)).is_empty());
        assert_eq!(
            backoff.take_due(now + Duration::from_secs(30)),
            vec![(route, normalized.clone())]
        );
        assert!(!backoff.is_blocked(destination, &advertised, now + Duration::from_secs(30)));

        let (_, _, failures, delay) = backoff
            .note_failure(destination, &advertised, now + Duration::from_secs(31))
            .unwrap();
        assert_eq!(failures, 2);
        assert_eq!(delay, Duration::from_secs(60));
        assert_eq!(backoff.take_due(now + Duration::from_secs(91)).len(), 1);

        let (_, _, failures, delay) = backoff
            .note_failure(destination, &advertised, now + Duration::from_secs(92))
            .unwrap();
        assert_eq!(failures, 3);
        assert_eq!(delay, Duration::from_secs(5 * 60));
        assert!(backoff.note_success(destination, &advertised));
        assert!(!backoff.is_blocked(destination, &advertised, now));
    }

    #[test]
    fn malformed_relay_route_cannot_backoff_a_different_destination() {
        use libp2p::multiaddr::Protocol;

        let relay = PeerId::random();
        let expected_destination = PeerId::random();
        let advertised_destination = PeerId::random();
        let mismatched = "/ip4/8.8.8.8/tcp/9500"
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(relay))
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(advertised_destination));
        let mut backoff = RelayCircuitBackoff::default();

        assert!(backoff
            .note_failure(expected_destination, &mismatched, Instant::now())
            .is_none());
        assert!(backoff.entries.is_empty());
    }

    #[test]
    fn suppressing_one_relay_route_preserves_direct_and_other_relay_candidates() {
        use libp2p::multiaddr::Protocol;

        let local = PeerId::random();
        let destination = PeerId::random();
        let failed_relay = PeerId::random();
        let other_relay = PeerId::random();
        let direct = "/ip4/1.1.1.1/tcp/9500".parse::<Multiaddr>().unwrap();
        let failed = "/ip4/8.8.8.8/tcp/9500"
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(failed_relay))
            .with(Protocol::P2pCircuit);
        let alternative = "/ip4/8.8.4.4/tcp/9500"
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(other_relay))
            .with(Protocol::P2pCircuit);
        let mut automatic = AutomaticPeerState::new(local);
        assert!(automatic.add_peer_candidate(
            local,
            destination,
            [direct.clone(), failed.clone(), alternative.clone()],
        ));

        assert!(automatic.remove_peer_candidate_addr(destination, &failed));
        let remaining = &automatic.peers.get(&destination).unwrap().addrs;
        assert!(remaining.contains(&direct));
        assert!(remaining.contains(&alternative));
        assert!(!remaining.contains(&failed));
    }

    #[test]
    fn identify_alone_cannot_authorize_network_v2_dispatch() {
        let peer = PeerId::random();
        let connection = libp2p::swarm::ConnectionId::new_unchecked(10_000);
        let mut paths = PeerSyncPaths::default();

        paths.insert(connection, peer, true, true);
        paths.mark_identified(connection);
        assert!(!paths.supports_availability(peer));
        assert!(!paths.is_dispatchable(peer));
        assert!(!paths.try_mark_announced(peer));

        paths.mark_availability_capable(connection);
        assert!(paths.supports_availability(peer));
        paths.mark_profile_verified(peer);
        assert!(paths.is_dispatchable(peer));
        assert!(paths.try_mark_announced(peer));

        paths.clear_profile_verified(peer);
        assert!(!paths.is_dispatchable(peer));
    }

    #[test]
    fn replacement_dialer_refreshes_profile_even_when_peer_was_already_verified() {
        let peer = PeerId::random();
        let connection = libp2p::swarm::ConnectionId::new_unchecked(100_001);
        let mut paths = PeerSyncPaths::default();

        paths.insert(connection, peer, true, true);
        paths.mark_identified(connection);
        paths.mark_profile_verified(peer);

        assert!(paths.should_start_profile_handshake(connection));
        paths.mark_profile_handshake_started(connection);
        assert!(!paths.should_start_profile_handshake(connection));
    }

    #[test]
    fn replacement_listener_waits_for_the_dialers_profile_request() {
        let peer = PeerId::random();
        let connection = libp2p::swarm::ConnectionId::new_unchecked(100_002);
        let mut paths = PeerSyncPaths::default();

        paths.insert(connection, peer, true, false);
        paths.mark_identified(connection);
        assert!(!paths.should_start_profile_handshake(connection));
    }

    #[test]
    fn identified_direct_path_wins_over_a_late_dns_duplicate() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let established = libp2p::swarm::ConnectionId::new_unchecked(10_001);
        let duplicate = libp2p::swarm::ConnectionId::new_unchecked(10_002);
        let mut paths = PeerSyncPaths::default();

        paths.insert(established, peer, true, true);
        paths.mark_identified(established);
        paths.mark_profile_verified(peer);
        assert!(paths.is_dispatchable(peer));
        assert!(paths.try_mark_announced(peer));

        paths.insert(duplicate, peer, true, true);
        assert_eq!(
            paths.canonicalize_direct(local, peer, duplicate),
            vec![duplicate]
        );
        assert!(paths.is_closing(duplicate));
        assert!(!paths.is_dispatchable(peer));

        assert_eq!(paths.remove(duplicate), Some(peer));
        assert!(paths.is_dispatchable(peer));
        assert!(!paths.try_mark_announced(peer));
    }

    #[test]
    fn opposite_cross_dials_keep_the_same_physical_path() {
        let (lower, higher) = ordered_peer_ids();
        let lower_inbound = libp2p::swarm::ConnectionId::new_unchecked(10_101);
        let lower_outbound = libp2p::swarm::ConnectionId::new_unchecked(10_102);
        let mut lower_paths = PeerSyncPaths::default();
        lower_paths.insert(lower_inbound, higher, true, false);
        lower_paths.mark_identified(lower_inbound);
        lower_paths.insert(lower_outbound, higher, true, true);
        assert_eq!(
            lower_paths.canonicalize_direct(lower, higher, lower_outbound),
            vec![lower_inbound],
            "the lower PeerId keeps its outbound half"
        );

        let higher_outbound = libp2p::swarm::ConnectionId::new_unchecked(10_201);
        let higher_inbound = libp2p::swarm::ConnectionId::new_unchecked(10_202);
        let mut higher_paths = PeerSyncPaths::default();
        higher_paths.insert(higher_outbound, lower, true, true);
        higher_paths.mark_identified(higher_outbound);
        higher_paths.insert(higher_inbound, lower, true, false);
        assert_eq!(
            higher_paths.canonicalize_direct(higher, lower, higher_inbound),
            vec![higher_outbound],
            "the higher PeerId keeps the matching inbound half"
        );
    }

    #[test]
    fn repeated_outbound_dns_dial_keeps_the_established_path() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let first = libp2p::swarm::ConnectionId::new_unchecked(10_301);
        let duplicate = libp2p::swarm::ConnectionId::new_unchecked(10_302);
        let mut paths = PeerSyncPaths::default();

        paths.insert(first, peer, true, true);
        paths.insert(duplicate, peer, true, true);
        assert_eq!(
            paths.canonicalize_direct(local, peer, duplicate),
            vec![duplicate]
        );
        assert!(!paths.is_closing(first));
        assert!(paths.is_closing(duplicate));
    }

    #[test]
    fn inbound_duplicates_block_dispatch_until_the_remote_dialer_closes_one() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let first = libp2p::swarm::ConnectionId::new_unchecked(10_401);
        let duplicate = libp2p::swarm::ConnectionId::new_unchecked(10_402);
        let mut paths = PeerSyncPaths::default();

        paths.insert(first, peer, true, false);
        paths.insert(duplicate, peer, true, false);
        assert!(
            paths.canonicalize_direct(local, peer, duplicate).is_empty(),
            "the listener cannot choose between remote-owned duplicate dials"
        );
        paths.mark_identified(first);
        paths.mark_identified(duplicate);
        paths.mark_profile_verified(peer);
        assert!(!paths.is_dispatchable(peer));

        assert_eq!(paths.remove(duplicate), Some(peer));
        assert!(paths.is_dispatchable(peer));
    }

    #[test]
    fn identified_direct_and_relay_paths_can_coexist() {
        let peer = PeerId::random();
        let direct = libp2p::swarm::ConnectionId::new_unchecked(10_501);
        let relay = libp2p::swarm::ConnectionId::new_unchecked(10_502);
        let mut paths = PeerSyncPaths::default();

        paths.insert(direct, peer, true, true);
        paths.insert(relay, peer, false, true);
        paths.mark_identified(direct);
        paths.mark_identified(relay);
        paths.mark_profile_verified(peer);
        assert!(paths.is_dispatchable(peer));
        assert_eq!(paths.dispatchable_peer_count(), 1);
    }

    #[test]
    fn direct_tx_relay_covers_small_networks_and_stays_bounded_at_scale() {
        assert_eq!(direct_tx_relay_limit(0), 0);
        assert_eq!(direct_tx_relay_limit(3), 3);
        assert_eq!(
            direct_tx_relay_limit(TX_DIRECT_SMALL_NETWORK_MAX_PEERS),
            TX_DIRECT_SMALL_NETWORK_MAX_PEERS
        );
        assert_eq!(
            direct_tx_relay_limit(TX_DIRECT_SMALL_NETWORK_MAX_PEERS + 1),
            TX_DIRECT_LARGE_NETWORK_FANOUT
        );
        assert_eq!(direct_tx_relay_limit(1_000), TX_DIRECT_LARGE_NETWORK_FANOUT);
    }

    #[test]
    fn global_gossip_byte_window_is_exact_and_resets() {
        let mut budget = GossipByteWindow::new();
        assert!(budget.admit(40, 64, Duration::from_secs(10)));
        assert!(budget.admit(24, 64, Duration::from_secs(10)));
        assert!(!budget.admit(1, 64, Duration::from_secs(10)));
        assert!(!budget.admit(usize::MAX, 64, Duration::from_secs(10)));

        budget.started_at = Instant::now() - Duration::from_secs(11);
        assert!(budget.admit(64, 64, Duration::from_secs(10)));
        assert_eq!(budget.bytes, 64);
    }

    #[test]
    fn snapshot_terminal_serving_requires_retained_suffix() {
        let retention = noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH;
        assert!(snapshot_suffix_is_retained(100, 100));
        assert!(snapshot_suffix_is_retained(100, 100 - retention));
        assert!(!snapshot_suffix_is_retained(100, 100 - retention - 1));
        assert!(!snapshot_suffix_is_retained(100, 101));
    }

    #[test]
    fn snapshot_boundary_keeps_payload_pruning_headroom() {
        let allowance = SNAPSHOT_BOUNDARY_MAX_LIVE_GAP;
        assert!(snapshot_boundary_has_live_headroom(100, 100));
        assert!(snapshot_boundary_has_live_headroom(100, 100 - allowance));
        assert!(!snapshot_boundary_has_live_headroom(
            100,
            100 - allowance - 1
        ));
        assert!(!snapshot_boundary_has_live_headroom(100, 101));
    }

    #[test]
    fn header_inventory_serves_the_complete_retained_payload_window() {
        let serving = noid_chain::consensus::params::RETAINED_BLOCK_SERVING_DEPTH;
        let recent = noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH;
        let tip = serving + 100;
        assert!(serving > recent);
        assert_eq!(retained_object_inventory_floor(tip), 100);
        assert!(100 < tip - recent);
    }

    #[test]
    fn deterministic_snapshot_boundary_exists_for_every_bucket_residue() {
        let finality = noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH;
        for residue in 0..crate::protocol::SNAPSHOT_BOUNDARY_INTERVAL {
            let tip_height = 120 + residue;
            let finalized_height = tip_height - finality;
            let (oldest, boundary) =
                deterministic_snapshot_boundary_window(tip_height, finalized_height)
                    .expect("every ordinary finalized tip has an exportable rounded boundary");

            assert_eq!(boundary % crate::protocol::SNAPSHOT_BOUNDARY_INTERVAL, 0);
            assert!(boundary >= oldest);
            assert!(boundary <= finalized_height);
            assert!(tip_height - boundary <= noid_chain::consensus::params::UNDO_RETENTION_DEPTH);
            assert!(
                (finality..finality + crate::protocol::SNAPSHOT_BOUNDARY_INTERVAL)
                    .contains(&(tip_height - boundary))
            );
        }
    }

    #[test]
    fn cached_boundary_proof_outlives_the_recent_suffix_window() {
        let tip_height = 100;
        let boundary_height =
            tip_height - noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH - 5;
        assert!(!snapshot_suffix_is_retained(tip_height, boundary_height));
        assert!(
            tip_height - boundary_height <= noid_chain::consensus::params::UNDO_RETENTION_DEPTH,
            "the rounded boundary remains reconstructible and its exact cached proof may be served"
        );
    }

    #[test]
    fn snapshot_selection_keeps_a_live_leased_cohort() {
        let leased = (100, [1; 32]);
        let fresh = (101, [2; 32]);
        let leased_keys = std::collections::HashSet::from([leased]);

        assert!(
            snapshot_export_selection_rank(leased, 109, &leased_keys)
                > snapshot_export_selection_rank(fresh, 110, &leased_keys),
            "a newer disk generation must not split an active bootstrap cohort"
        );
    }

    #[test]
    fn snapshot_generation_leases_never_revoke_a_live_exact_generation() {
        let first = PeerId::random();
        let second = PeerId::random();
        let third = PeerId::random();
        let fourth = PeerId::random();
        let joiner = PeerId::random();
        let key_a = (100, [1; 32]);
        let key_b = (101, [2; 32]);
        let key_c = (102, [3; 32]);
        let key_d = (103, [4; 32]);
        let key_e = (104, [5; 32]);
        let mut leases = std::collections::HashMap::new();
        let grace = SnapshotExportDisconnectGrace::new();

        assert!(lease_snapshot_export(
            &mut leases,
            &grace,
            first,
            key_a,
            [1; 32],
            Instant::now() + Duration::from_secs(60 * 60),
        ));
        assert!(lease_snapshot_export(
            &mut leases,
            &grace,
            second,
            key_b,
            [2; 32],
            Instant::now() + Duration::from_secs(60 * 60),
        ));
        assert!(lease_snapshot_export(
            &mut leases,
            &grace,
            third,
            key_c,
            [3; 32],
            Instant::now() + Duration::from_secs(60 * 60),
        ));
        assert!(lease_snapshot_export(
            &mut leases,
            &grace,
            fourth,
            key_d,
            [4; 32],
            Instant::now() + Duration::from_secs(60 * 60),
        ));
        assert!(lease_snapshot_export(
            &mut leases,
            &grace,
            joiner,
            key_a,
            [1; 32],
            Instant::now() + Duration::from_secs(60 * 60),
        ));
        assert!(!lease_snapshot_export(
            &mut leases,
            &grace,
            joiner,
            key_e,
            [5; 32],
            Instant::now() + Duration::from_secs(60 * 60),
        ));
        assert_eq!(leases.get(&first).map(|lease| lease.key), Some(key_a));
        assert_eq!(leases.get(&second).map(|lease| lease.key), Some(key_b));
        assert_eq!(leases.get(&third).map(|lease| lease.key), Some(key_c));
        assert_eq!(leases.get(&fourth).map(|lease| lease.key), Some(key_d));
        assert_eq!(leases.get(&joiner).map(|lease| lease.key), Some(key_a));
        assert_eq!(
            leases
                .values()
                .map(|lease| lease.key)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            MAX_ACTIVE_SNAPSHOT_EXPORT_GENERATIONS
        );

        leases.get_mut(&second).unwrap().last_activity =
            Instant::now() - SNAPSHOT_EXPORT_LEASE_TTL - Duration::from_secs(1);
        prune_snapshot_export_leases(&mut leases);
        assert!(!leases.contains_key(&second));
        assert!(lease_snapshot_export(
            &mut leases,
            &grace,
            joiner,
            key_e,
            [5; 32],
            Instant::now() + Duration::from_secs(60 * 60),
        ));
    }

    #[test]
    fn snapshot_generation_lease_has_a_nonrenewable_maximum_age() {
        let peer = PeerId::random();
        let key = (100, [1; 32]);
        let mut leases = std::collections::HashMap::new();
        let grace = SnapshotExportDisconnectGrace::new();
        assert!(lease_snapshot_export(
            &mut leases,
            &grace,
            peer,
            key,
            [1; 32],
            Instant::now() + Duration::from_secs(60 * 60),
        ));
        let lease = leases.get_mut(&peer).unwrap();
        lease.absolute_deadline = Instant::now() - Duration::from_secs(1);
        lease.last_activity = Instant::now();
        prune_snapshot_export_leases(&mut leases);
        assert!(!leases.contains_key(&peer));
    }

    #[test]
    fn disconnect_preserves_exact_generation_until_original_lease_deadline() {
        let peer = PeerId::random();
        let key = (100, [1; 32]);
        let mut leases = std::collections::HashMap::new();
        let mut grace = SnapshotExportDisconnectGrace::new();
        assert!(lease_snapshot_export(
            &mut leases,
            &grace,
            peer,
            key,
            [1; 32],
            Instant::now() + Duration::from_secs(60 * 60),
        ));

        detach_snapshot_export_lease(&mut leases, &mut grace, peer);

        assert!(!leases.contains_key(&peer));
        assert!(grace
            .get(&key)
            .is_some_and(|deadline| *deadline > Instant::now()));
        assert!(protected_snapshot_export_keys(&leases, &grace).contains(&key));
    }

    #[test]
    fn automatic_peer_state_recovers_bootstrap_and_unique_outbound_slots() {
        let addr: Multiaddr = "/dns4/seed.example/tcp/9500".parse().unwrap();
        let peer = PeerId::random();
        let connection_id = libp2p::swarm::ConnectionId::new_unchecked(1);
        let mut state = AutomaticPeerState::new(PeerId::random());
        assert!(state.register_bootstrap(addr.clone()).is_empty());
        state
            .pending
            .insert(connection_id, PendingAutomaticDial::Bootstrap(addr.clone()));
        state.note_connection_established(connection_id, peer, true, None);

        assert_eq!(
            state.outbound_peer_count(),
            0,
            "transport alone is not a usable network peer"
        );
        state.note_identified(connection_id, peer);
        assert_eq!(state.outbound_peer_count(), 1);
        assert_eq!(state.bootstrap.get(&addr).unwrap().peer, Some(peer));
        assert!(state.pending.is_empty());

        state.note_connection_closed(connection_id);
        assert_eq!(state.outbound_peer_count(), 0);
        let candidate = state.bootstrap.get(&addr).unwrap();
        assert_eq!(candidate.failures, 1);
        assert!(candidate.next_attempt > Instant::now());
    }

    #[test]
    fn discovered_outbound_transport_fills_a_bounded_managed_neighbour_slot() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let connection_id = libp2p::swarm::ConnectionId::new_unchecked(2);
        let mut state = AutomaticPeerState::new(local);
        assert!(state.add_peer_candidate(local, peer, ["/ip4/8.8.8.8/tcp/9500".parse().unwrap()]));

        // Kademlia owns this connection: no PendingAutomaticDial exists. Once
        // it identifies, reuse the live authenticated transport rather than
        // running another random lookup to find the same peer again.
        state.note_connection_established(connection_id, peer, true, None);
        state.note_identified(connection_id, peer);

        assert_eq!(state.outbound_connections.get(&connection_id), Some(&peer));
        assert_eq!(state.outbound_peer_count(), 1);
        assert!(state.managed_connections.contains_key(&connection_id));
        assert!(state.is_locally_selected(peer));
    }

    #[test]
    fn authenticated_discovered_seed_transport_is_managed_as_bootstrap() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let seed: Multiaddr = "/ip4/8.8.8.8/tcp/9500".parse().unwrap();
        let remote: Multiaddr = format!("{seed}/p2p/{peer}").parse().unwrap();
        let connection_id = libp2p::swarm::ConnectionId::new_unchecked(3);
        let mut state = AutomaticPeerState::new(local);
        assert!(state.register_bootstrap(seed.clone()).is_empty());

        // Simulate the DHT learning this identity before it opens the
        // connection. The address claim alone remains an ordinary candidate.
        assert!(state.add_peer_candidate(local, peer, [seed.clone()]));
        assert!(!state.is_bootstrap_peer(peer));

        // Once Noise authenticates the direct endpoint, the same transport is
        // classified as bootstrap and removed from ordinary neighbour state.
        state.note_connection_established(connection_id, peer, true, Some(&remote));
        state.note_identified(connection_id, peer);

        assert_eq!(state.bootstrap.get(&seed).unwrap().peer, Some(peer));
        assert!(state.is_bootstrap_peer(peer));
        assert!(!state.peers.contains_key(&peer));
        assert!(matches!(
            state
                .managed_connections
                .get(&connection_id)
                .map(|connection| &connection.kind),
            Some(ManagedOutboundKind::Bootstrap(addr)) if addr == &seed
        ));
        assert_eq!(state.outbound_peer_count(), 1);
        assert_eq!(state.topology_peer_count(), 0);
    }

    #[test]
    fn late_seed_registration_repairs_an_old_peer_cache_connection() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let seed: Multiaddr = "/ip4/1.1.1.1/tcp/9500".parse().unwrap();
        let remote: Multiaddr = format!("{seed}/p2p/{peer}").parse().unwrap();
        let connection_id = libp2p::swarm::ConnectionId::new_unchecked(4);
        let mut state = AutomaticPeerState::new(local);

        // peers.json is loaded before the node finishes resolving and
        // registering its DNS seeds, so an old release may reconnect this
        // endpoint through the ordinary-candidate path first.
        assert!(state.add_peer_candidate(local, peer, [seed.clone()]));
        state.note_connection_established(connection_id, peer, true, Some(&remote));
        state.note_identified(connection_id, peer);
        assert_eq!(state.topology_peer_count(), 1);
        assert!(matches!(
            state
                .managed_connections
                .get(&connection_id)
                .map(|connection| &connection.kind),
            Some(ManagedOutboundKind::Peer)
        ));

        let reclassified = state.register_bootstrap(seed.clone());

        assert_eq!(reclassified, vec![peer]);
        assert_eq!(state.bootstrap.get(&seed).unwrap().peer, Some(peer));
        assert!(!state.peers.contains_key(&peer));
        assert!(matches!(
            state
                .managed_connections
                .get(&connection_id)
                .map(|connection| &connection.kind),
            Some(ManagedOutboundKind::Bootstrap(addr)) if addr == &seed
        ));
        assert_eq!(state.outbound_peer_count(), 1);
        assert_eq!(state.topology_peer_count(), 0);
    }

    #[test]
    fn advertised_seed_address_alone_cannot_bind_bootstrap_identity() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let seed: Multiaddr = "/ip4/8.8.4.4/tcp/9500".parse().unwrap();
        let connection_id = libp2p::swarm::ConnectionId::new_unchecked(5);
        let mut state = AutomaticPeerState::new(local);
        assert!(state.register_bootstrap(seed.clone()).is_empty());
        assert!(state.add_peer_candidate(local, peer, [seed.clone()]));

        // No authenticated direct endpoint was supplied. Identify may adopt
        // the transport as an ordinary neighbour, but it cannot pin the peer
        // to the configured seed address.
        state.note_connection_established(connection_id, peer, true, None);
        state.note_identified(connection_id, peer);

        assert_eq!(state.bootstrap.get(&seed).unwrap().peer, None);
        assert!(!state.is_bootstrap_peer(peer));
        assert!(state.peers.contains_key(&peer));
        assert!(matches!(
            state
                .managed_connections
                .get(&connection_id)
                .map(|connection| &connection.kind),
            Some(ManagedOutboundKind::Peer)
        ));
    }

    #[test]
    fn discovered_outbound_transports_cannot_exceed_the_mesh_target() {
        let mut state = AutomaticPeerState::new(PeerId::random());
        for index in 0..AUTOMATIC_OUTBOUND_TARGET + 3 {
            let peer = PeerId::random();
            let connection_id = libp2p::swarm::ConnectionId::new_unchecked(10 + index);
            state.note_connection_established(connection_id, peer, true, None);
            state.note_identified(connection_id, peer);
        }

        assert_eq!(state.outbound_peer_count(), AUTOMATIC_OUTBOUND_TARGET);
        assert_eq!(state.managed_connections.len(), AUTOMATIC_OUTBOUND_TARGET);
    }

    #[test]
    fn automatic_retry_is_bounded_and_jittered() {
        let first = automatic_retry_delay(1, b"first", b"local-a");
        let later = automatic_retry_delay(u8::MAX, b"later", b"local-b");
        assert!((Duration::from_secs(5)..Duration::from_secs(10)).contains(&first));
        assert!((Duration::from_secs(300)..Duration::from_secs(305)).contains(&later));
    }

    #[test]
    fn only_explicit_invalid_data_is_classified_as_malformed_transport() {
        let malformed = request_response::OutboundFailure::Io(std::io::Error::from(
            std::io::ErrorKind::InvalidData,
        ));
        let truncated = request_response::OutboundFailure::Io(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof,
        ));
        let transient = request_response::OutboundFailure::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset,
        ));

        assert_eq!(
            RequestFailureKind::from(&malformed),
            RequestFailureKind::InvalidResponse
        );
        assert_eq!(RequestFailureKind::from(&truncated), RequestFailureKind::Io);
        assert_eq!(RequestFailureKind::from(&transient), RequestFailureKind::Io);
    }

    #[test]
    fn bootstrap_preserves_two_peer_quorum_until_ordinary_replacement() {
        for (ordinary, expected_seeds) in [(0, 2), (1, 1), (2, 0), (12, 0)] {
            assert_eq!(
                desired_bootstrap_connections(true, ordinary, 6),
                expected_seeds,
                "ordinary={ordinary}"
            );
        }
        assert_eq!(desired_bootstrap_connections(false, 12, 3), 2);
        assert_eq!(desired_bootstrap_connections(true, 0, 3), 2);
        assert_eq!(desired_bootstrap_connections(true, 0, 1), 1);
        assert_eq!(desired_bootstrap_connections(true, 0, 0), 0);
    }

    #[test]
    fn protected_seed_paths_do_not_prune_a_full_ordinary_topology() {
        assert!(!ordinary_release_needed(false, AUTOMATIC_OUTBOUND_TARGET));
        assert!(ordinary_release_needed(
            false,
            AUTOMATIC_OUTBOUND_TARGET + 1
        ));
        assert!(!ordinary_release_needed(
            true,
            AUTOMATIC_OUTBOUND_TARGET + 1
        ));
    }

    #[test]
    fn pending_dns_probe_does_not_impersonate_connected_bootstrap_quorum() {
        assert_eq!(
            bootstrap_probe_capacity(2, 1, 1, 8, 8),
            1,
            "one connected seed still requires one staggered alternative"
        );
        assert_eq!(
            bootstrap_probe_capacity(2, 0, 2, 8, 8),
            2,
            "two unresolved DNS transports must not stop alternate probes"
        );
        assert_eq!(bootstrap_probe_capacity(2, 0, 4, 8, 8), 0);
        assert_eq!(bootstrap_probe_capacity(2, 2, 0, 8, 8), 0);
    }

    #[tokio::test]
    async fn data_plane_admission_prevents_one_peer_from_occupying_all_slots() {
        let mut admission = DataPlaneServingAdmission::new(BackgroundCapacity::Full);
        let first = PeerId::random();
        let second = PeerId::random();
        let first_a = admission
            .lease(first, DataPlaneClass::Live)
            .unwrap()
            .acquire()
            .await
            .unwrap();
        let _first_b = admission
            .lease(first, DataPlaneClass::Live)
            .unwrap()
            .acquire()
            .await
            .unwrap();
        let third_from_first = tokio::spawn(
            admission
                .lease(first, DataPlaneClass::Live)
                .unwrap()
                .acquire(),
        );
        tokio::task::yield_now().await;
        assert!(!third_from_first.is_finished());
        let _fourth_from_first = admission.lease(first, DataPlaneClass::Live).unwrap();
        assert!(admission.lease(first, DataPlaneClass::Live).is_none());

        let _second = admission
            .lease(second, DataPlaneClass::Live)
            .unwrap()
            .acquire()
            .await
            .unwrap();
        assert_eq!(admission.active_slots(), 3);

        drop(first_a);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), third_from_first)
                .await
                .unwrap()
                .unwrap()
                .is_ok()
        );
    }

    #[test]
    fn data_plane_waiters_are_globally_bounded() {
        let mut admission = DataPlaneServingAdmission::new(BackgroundCapacity::Full);
        let live_outstanding = admission.live_outstanding_slots;
        let per_peer_outstanding = admission.per_peer_outstanding_slots;
        let mut leases = Vec::new();
        for _ in 0..(live_outstanding / per_peer_outstanding) {
            let peer = PeerId::random();
            for _ in 0..per_peer_outstanding {
                leases.push(admission.lease(peer, DataPlaneClass::Live).unwrap());
            }
        }
        assert_eq!(leases.len(), live_outstanding);
        assert!(admission
            .lease(PeerId::random(), DataPlaneClass::Live)
            .is_none());
        drop(leases.pop());
        assert!(admission
            .lease(PeerId::random(), DataPlaneClass::Live)
            .is_some());
    }

    #[tokio::test]
    async fn saturated_state_slots_return_busy_admission_without_hiding_a_queue() {
        let mut admission = DataPlaneServingAdmission::new(BackgroundCapacity::Full);
        let mut active_state = Vec::new();
        for _ in 0..admission.state_slots {
            active_state.push(
                admission
                    .lease(PeerId::random(), DataPlaneClass::State)
                    .unwrap()
                    .acquire()
                    .await
                    .unwrap(),
            );
        }
        assert!(admission
            .lease(PeerId::random(), DataPlaneClass::State)
            .is_none());

        let live = admission
            .lease(PeerId::random(), DataPlaneClass::Live)
            .unwrap()
            .acquire()
            .await
            .unwrap();
        assert_eq!(admission.active_slots(), admission.state_slots + 1);
        drop(live);
        drop(active_state);
    }

    #[tokio::test]
    async fn queued_state_transfers_cannot_fill_shared_outstanding_admission() {
        let mut admission = DataPlaneServingAdmission::new(BackgroundCapacity::Full);
        let mut queued_state = Vec::new();
        for _ in 0..admission.state_outstanding_slots {
            queued_state.push(
                admission
                    .lease(PeerId::random(), DataPlaneClass::State)
                    .expect("State queue retains its class permit"),
            );
        }
        assert!(admission
            .lease(PeerId::random(), DataPlaneClass::State)
            .is_none());
        assert!(admission
            .lease(PeerId::random(), DataPlaneClass::Live)
            .is_some());
        drop(queued_state);
    }

    #[tokio::test]
    async fn saturated_live_work_cannot_starve_reserved_state_capacity() {
        let mut admission = DataPlaneServingAdmission::new(BackgroundCapacity::Full);
        let mut active_live = Vec::new();
        for _ in 0..admission.live_slots {
            active_live.push(
                admission
                    .lease(PeerId::random(), DataPlaneClass::Live)
                    .unwrap()
                    .acquire()
                    .await
                    .unwrap(),
            );
        }
        let queued_live = tokio::spawn(
            admission
                .lease(PeerId::random(), DataPlaneClass::Live)
                .unwrap()
                .acquire(),
        );
        tokio::task::yield_now().await;
        assert!(!queued_live.is_finished());

        let state = admission
            .lease(PeerId::random(), DataPlaneClass::State)
            .expect("State retains a reserved outstanding slot")
            .acquire()
            .await
            .expect("State retains a reserved active slot");
        assert_eq!(admission.active_slots(), admission.live_slots + 1);
        assert!(admission.outstanding_slots() <= admission.global_outstanding_slots);

        drop(state);
        drop(active_live);
        queued_live.abort();
    }

    #[test]
    fn saturated_live_queue_cannot_starve_state_outstanding_admission() {
        let mut admission = DataPlaneServingAdmission::new(BackgroundCapacity::Full);
        let mut live = Vec::new();
        for _ in 0..admission.live_outstanding_slots {
            live.push(
                admission
                    .lease(PeerId::random(), DataPlaneClass::Live)
                    .expect("Live queue retains its class permit"),
            );
        }
        assert!(admission
            .lease(PeerId::random(), DataPlaneClass::Live)
            .is_none());
        assert!(admission
            .lease(PeerId::random(), DataPlaneClass::State)
            .is_some());
        drop(live);
    }

    #[test]
    fn miner_prioritizes_live_propagation_with_smaller_background_budgets() {
        let full = DataPlaneServingAdmission::new(BackgroundCapacity::Full);
        let mining = DataPlaneServingAdmission::new(BackgroundCapacity::MiningReserved);
        assert_eq!(mining.global_slots, full.global_slots);
        assert_eq!(
            mining.global_outstanding_slots * 2,
            full.global_outstanding_slots
        );
        assert_eq!(mining.state_slots * 2, full.state_slots);
        assert!(mining.live_slots > full.live_slots);
        assert_eq!(
            mining.state_outstanding_slots * 2,
            full.state_outstanding_slots
        );
        assert_eq!(full.state_outstanding_slots, full.state_slots);
        assert_eq!(mining.state_outstanding_slots, mining.state_slots);
        assert!(mining.live_outstanding_slots > full.live_outstanding_slots);
        assert_eq!(full.live_outstanding_slots, full.live_slots * 2);
        assert_eq!(mining.live_outstanding_slots, mining.live_slots * 2);
        assert!(full.state_slots < full.global_slots);
        assert!(mining.global_slots > 0);
        assert!(mining.per_peer_slots > 0);
    }

    #[test]
    fn failed_dns_identity_pin_is_cleared_before_reresolution() {
        let local = PeerId::random();
        let old_peer = PeerId::random();
        let addr: Multiaddr = "/dns4/seed.example/tcp/9500".parse().unwrap();
        let connection_id = libp2p::swarm::ConnectionId::new_unchecked(7);
        let mut state = AutomaticPeerState::new(local);
        assert!(state.register_bootstrap(addr.clone()).is_empty());
        state.bootstrap.get_mut(&addr).unwrap().peer = Some(old_peer);
        state
            .pending
            .insert(connection_id, PendingAutomaticDial::Bootstrap(addr.clone()));

        state.note_dial_failed(connection_id);

        let candidate = state.bootstrap.get(&addr).unwrap();
        assert_eq!(candidate.peer, None);
        assert_eq!(candidate.failures, 1);
        assert!(candidate.next_attempt > Instant::now());
    }

    #[test]
    fn aggregate_and_individual_dns_sources_count_one_target_peer() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let aggregate: Multiaddr = "/dnsaddr/noid.network".parse().unwrap();
        let individual: Multiaddr = "/dns4/seed1.parano1d.org/tcp/9500".parse().unwrap();
        let first = libp2p::swarm::ConnectionId::new_unchecked(71);
        let duplicate = libp2p::swarm::ConnectionId::new_unchecked(72);
        let mut state = AutomaticPeerState::new(local);
        state.add_peer_candidate(local, peer, ["/ip4/8.8.8.8/tcp/9500".parse().unwrap()]);
        assert!(state.peers.contains_key(&peer));
        assert!(state.register_bootstrap(aggregate.clone()).is_empty());
        assert!(state.register_bootstrap(individual.clone()).is_empty());
        state
            .pending
            .insert(first, PendingAutomaticDial::Bootstrap(aggregate.clone()));
        state.pending.insert(
            duplicate,
            PendingAutomaticDial::Bootstrap(individual.clone()),
        );

        state.note_connection_established(first, peer, true, None);
        assert!(!state.peers.contains_key(&peer));
        assert!(!state.add_peer_candidate(local, peer, ["/ip4/8.8.4.4/tcp/9500".parse().unwrap()]));
        assert!(!state.peers.contains_key(&peer));
        state.note_connection_established(duplicate, peer, true, None);
        state.note_identified(first, peer);
        state.note_identified(duplicate, peer);
        assert_eq!(state.outbound_peer_count(), 1);
        assert_eq!(state.managed_connections.len(), 2);
        assert_eq!(state.outbound_connections.get(&first), Some(&peer));
        assert_eq!(state.outbound_connections.get(&duplicate), Some(&peer));
        assert_eq!(state.bootstrap.get(&aggregate).unwrap().peer, Some(peer));
        assert_eq!(state.bootstrap.get(&individual).unwrap().peer, Some(peer));
    }

    #[test]
    fn local_selection_survives_cross_dial_direction_collapse() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let seed: Multiaddr = "/dns4/seed.example/tcp/9500".parse().unwrap();
        let outbound = libp2p::swarm::ConnectionId::new_unchecked(81);
        let inbound = libp2p::swarm::ConnectionId::new_unchecked(82);
        let mut state = AutomaticPeerState::new(local);
        assert!(state.register_bootstrap(seed.clone()).is_empty());
        state
            .pending
            .insert(outbound, PendingAutomaticDial::Bootstrap(seed));

        state.note_connection_established(outbound, peer, true, None);
        state.note_connection_established(inbound, peer, false, None);
        state.note_identified(outbound, peer);
        state.note_identified(inbound, peer);
        assert!(state.is_locally_selected(peer));
        assert_eq!(state.outbound_peer_count(), 1);

        // Canonical cross-dial resolution may close our physical outbound
        // half while the authenticated inbound half remains. The local
        // topology intent and logical neighbour count must survive so this
        // configured seed still starts cold-sync discovery without triggering
        // a replacement-dial loop.
        state.note_connection_closed(outbound);
        assert!(state.is_locally_selected(peer));
        assert_eq!(state.outbound_peer_count(), 1);

        state.note_connection_closed(inbound);
        assert_eq!(state.outbound_peer_count(), 0);

        state.clear_local_selection(peer);
        assert!(!state.is_locally_selected(peer));
    }

    #[test]
    fn failed_parallel_lan_dial_preserves_live_bootstrap_selection() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let seed: Multiaddr = "/dns4/seed.example/tcp/9500".parse().unwrap();
        let bootstrap = libp2p::swarm::ConnectionId::new_unchecked(83);
        let lan = libp2p::swarm::ConnectionId::new_unchecked(84);
        let mut state = AutomaticPeerState::new(local);
        assert!(state.register_bootstrap(seed.clone()).is_empty());
        state
            .pending
            .insert(bootstrap, PendingAutomaticDial::Bootstrap(seed));
        state.note_connection_established(bootstrap, peer, true, None);
        state.note_identified(bootstrap, peer);
        assert!(state.is_locally_selected(peer));

        state
            .pending
            .insert(lan, PendingAutomaticDial::Lan { peer });
        state.note_dial_failed(lan);

        assert!(state.is_locally_selected(peer));
        assert_eq!(state.selected_identified_since.len(), 1);
    }

    #[test]
    fn unsolicited_inbound_peer_is_not_a_proactive_sync_source() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let inbound = libp2p::swarm::ConnectionId::new_unchecked(91);
        let mut state = AutomaticPeerState::new(local);
        state.note_connection_established(inbound, peer, false, None);
        state.note_identified(inbound, peer);
        assert!(!state.is_locally_selected(peer));
        assert_eq!(state.outbound_peer_count(), 0);
        assert_eq!(state.topology_peer_count(), 1);
    }

    #[test]
    fn inbound_gui_neighbours_receive_only_bounded_topology_credit() {
        let mut state = AutomaticPeerState::new(PeerId::random());
        for index in 0..AUTOMATIC_OUTBOUND_TARGET {
            let peer = PeerId::random();
            let connection_id = libp2p::swarm::ConnectionId::new_unchecked(100 + index);
            state.note_connection_established(connection_id, peer, false, None);
            state.note_identified(connection_id, peer);
        }

        assert_eq!(state.topology_peer_count(), MAX_UNSELECTED_TOPOLOGY_CREDIT);
        assert_eq!(state.outbound_peer_count(), 0);
        assert_eq!(
            automatic_ordinary_dial_capacity(
                state.topology_peer_count(),
                state.pending_ordinary_count(),
                false,
                state.automatic_dial_capacity(),
            ),
            AUTOMATIC_OUTBOUND_TARGET - MAX_UNSELECTED_TOPOLOGY_CREDIT
        );
    }

    #[test]
    fn seeds_and_inbound_clients_cannot_suppress_four_ordinary_selections() {
        let mut state = AutomaticPeerState::new(PeerId::random());
        for index in 0..INITIAL_BOOTSTRAP_FANOUT {
            let addr: Multiaddr = format!("/ip4/203.0.113.{}/tcp/9500", index + 1)
                .parse()
                .unwrap();
            let peer = PeerId::random();
            let connection_id = libp2p::swarm::ConnectionId::new_unchecked(200 + index);
            assert!(state.register_bootstrap(addr.clone()).is_empty());
            state
                .pending
                .insert(connection_id, PendingAutomaticDial::Bootstrap(addr));
            state.note_connection_established(connection_id, peer, true, None);
            state.note_identified(connection_id, peer);
        }
        for index in 0..AUTOMATIC_OUTBOUND_TARGET {
            let peer = PeerId::random();
            let connection_id = libp2p::swarm::ConnectionId::new_unchecked(300 + index);
            state.note_connection_established(connection_id, peer, false, None);
            state.note_identified(connection_id, peer);
        }

        assert_eq!(state.outbound_peer_count(), INITIAL_BOOTSTRAP_FANOUT);
        assert_eq!(
            state.topology_peer_count(),
            MAX_UNSELECTED_TOPOLOGY_CREDIT,
            "bootstrap roots do not replace ordinary mesh neighbours"
        );
        assert_eq!(
            automatic_ordinary_dial_capacity(
                state.topology_peer_count(),
                state.pending_ordinary_count(),
                false,
                state.automatic_dial_capacity(),
            ),
            AUTOMATIC_OUTBOUND_TARGET - MAX_UNSELECTED_TOPOLOGY_CREDIT
        );
    }

    #[test]
    fn automatic_target_keeps_eight_neighbours_with_four_selected_locally() {
        assert_eq!(AUTOMATIC_OUTBOUND_TARGET, 8);
        assert_eq!(MAX_UNSELECTED_TOPOLOGY_CREDIT, 4);
        assert_eq!(INITIAL_BOOTSTRAP_FANOUT, 2);
        assert!(MAX_AUTOMATIC_TRANSPORT_OCCUPANCY >= AUTOMATIC_OUTBOUND_TARGET * 2);
    }

    #[test]
    fn initial_discovery_is_identity_jittered_inside_a_bounded_window() {
        let delay = initial_discovery_delay(PeerId::random());
        assert!((Duration::from_secs(2)..=Duration::from_secs(30)).contains(&delay));
    }

    #[test]
    fn failed_peer_dial_cannot_immediately_restart_iterative_discovery() {
        let mut state = AutomaticPeerState::new(PeerId::random());
        state.next_discovery_at = Instant::now() + Duration::from_secs(5 * 60);
        let before = Instant::now();

        state.accelerate_discovery();

        assert!(state.next_discovery_at >= before + DISCOVERY_RETRY_MIN);
        assert!(state.next_discovery_at <= Instant::now() + DISCOVERY_RETRY_MIN);
    }

    #[test]
    fn bounded_discovery_remains_available_after_topology_loss() {
        let mut state = AutomaticPeerState::new(PeerId::random());
        state.next_discovery_at = Instant::now() + Duration::from_secs(5 * 60);
        let before = Instant::now();

        state.accelerate_discovery();

        assert!(state.next_discovery_at >= before + DISCOVERY_RETRY_MIN);
        assert!(state.next_discovery_at <= Instant::now() + DISCOVERY_RETRY_MIN);
        assert!(!state.discovery_active());
    }

    #[test]
    fn unresolved_seed_probes_do_not_reserve_ordinary_peer_slots() {
        let local = PeerId::random();
        let mut state = AutomaticPeerState::new(local);
        for id in 1..=MAX_PENDING_BOOTSTRAP_DIALS {
            let addr: Multiaddr = format!("/dns4/seed{id}.example/tcp/9500").parse().unwrap();
            state.pending.insert(
                libp2p::swarm::ConnectionId::new_unchecked(id),
                PendingAutomaticDial::Bootstrap(addr),
            );
        }
        for id in 100..100 + AUTOMATIC_OUTBOUND_TARGET {
            state.pending.insert(
                libp2p::swarm::ConnectionId::new_unchecked(id),
                PendingAutomaticDial::Peer {
                    peer: PeerId::random(),
                    group: PublicNetworkGroup::Ipv4([8, 8]),
                },
            );
        }

        assert_eq!(state.pending_bootstrap_count(), MAX_PENDING_BOOTSTRAP_DIALS);
        assert_eq!(state.pending_ordinary_count(), AUTOMATIC_OUTBOUND_TARGET);
        assert!(state.pending.len() < MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS);
        assert_eq!(
            state
                .outbound_peer_count()
                .saturating_add(state.pending_ordinary_count()),
            AUTOMATIC_OUTBOUND_TARGET
        );
        assert_eq!(
            automatic_ordinary_dial_capacity(
                0,
                0,
                false,
                MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS - MAX_PENDING_BOOTSTRAP_DIALS,
            ),
            AUTOMATIC_OUTBOUND_TARGET
        );
    }

    #[test]
    fn unidentified_transports_are_bounded_without_counting_as_healthy_peers() {
        let mut state = AutomaticPeerState::new(PeerId::random());
        for id in 0..MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS {
            state.track_managed_connection(
                libp2p::swarm::ConnectionId::new_unchecked(1_000 + id),
                PeerId::random(),
                ManagedOutboundKind::Peer,
            );
        }
        assert_eq!(state.outbound_peer_count(), 0);
        assert_eq!(
            state.automatic_occupancy(),
            MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS
        );
        assert_eq!(
            automatic_ordinary_dial_capacity(
                state.outbound_peer_count(),
                state.pending_ordinary_count(),
                false,
                state.automatic_dial_capacity(),
            ),
            0
        );

        let released = *state.managed_connections.keys().next().unwrap();
        state.note_connection_closed(released);
        assert_eq!(
            state.automatic_occupancy(),
            MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS - 1
        );
        assert_eq!(
            automatic_ordinary_dial_capacity(
                state.outbound_peer_count(),
                state.pending_ordinary_count(),
                false,
                state.automatic_dial_capacity(),
            ),
            1
        );
    }

    #[test]
    fn two_healthy_paths_per_peer_still_reach_the_unique_peer_target() {
        let mut state = AutomaticPeerState::new(PeerId::random());
        for peer_index in 0..AUTOMATIC_OUTBOUND_TARGET {
            let peer = PeerId::random();
            for path in 0..2 {
                let connection_id =
                    libp2p::swarm::ConnectionId::new_unchecked(2_000 + peer_index * 2 + path);
                state.track_managed_connection(connection_id, peer, ManagedOutboundKind::Peer);
                state.note_identified(connection_id, peer);
            }
        }
        assert_eq!(state.outbound_peer_count(), AUTOMATIC_OUTBOUND_TARGET);
        assert_eq!(state.automatic_occupancy(), AUTOMATIC_OUTBOUND_TARGET * 2);
        assert_eq!(
            automatic_ordinary_dial_capacity(
                state.outbound_peer_count(),
                state.pending_ordinary_count(),
                false,
                state.automatic_dial_capacity(),
            ),
            0
        );
    }

    #[test]
    fn seed_replacement_has_exactly_one_overlap_slot() {
        assert_eq!(
            automatic_ordinary_dial_capacity(
                AUTOMATIC_OUTBOUND_TARGET,
                0,
                true,
                MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS,
            ),
            1
        );
        assert_eq!(
            automatic_ordinary_dial_capacity(
                AUTOMATIC_OUTBOUND_TARGET,
                1,
                true,
                MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS,
            ),
            0,
            "one pending replacement must suppress another overlap dial"
        );
        assert_eq!(
            automatic_ordinary_dial_capacity(
                AUTOMATIC_OUTBOUND_TARGET - 1,
                0,
                false,
                MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS,
            ),
            1
        );
    }

    #[test]
    fn invalid_kad_candidates_cannot_fill_the_bounded_pool() {
        let local = PeerId::random();
        let mut state = AutomaticPeerState::new(local);
        for _ in 0..(MAX_AUTOMATIC_PEER_CANDIDATES + 50) {
            assert!(!state.add_peer_candidate(
                local,
                PeerId::random(),
                ["/ip4/127.0.0.1/tcp/9500".parse().unwrap()]
            ));
        }
        assert!(state.peers.is_empty());

        let valid = PeerId::random();
        assert!(state.add_peer_candidate(local, valid, ["/ip4/8.8.8.8/tcp/9500".parse().unwrap()]));
        assert!(state.peers.contains_key(&valid));

        let mismatched = PeerId::random();
        let advertised = PeerId::random();
        assert!(!state.add_peer_candidate(
            local,
            mismatched,
            [format!("/ip4/9.9.9.9/tcp/9500/p2p/{advertised}")
                .parse()
                .unwrap()]
        ));
    }

    #[test]
    fn pending_outbound_dials_reserve_public_network_group_capacity() {
        let local = PeerId::random();
        let mut state = AutomaticPeerState::new(local);
        let group =
            crate::peer_diversity::public_network_group(&"/ip4/8.8.1.1/tcp/9500".parse().unwrap())
                .unwrap();
        for id in 1..=2 {
            state.pending.insert(
                libp2p::swarm::ConnectionId::new_unchecked(id),
                PendingAutomaticDial::Peer {
                    peer: PeerId::random(),
                    group,
                },
            );
        }
        let candidate = PeerId::random();
        let addr: Multiaddr = "/ip4/8.8.2.2/tcp/9500".parse().unwrap();
        assert_eq!(state.pending_group_count(group), 2);
        assert!(
            !PeerDiversity::default().outbound_candidate_allowed_with_pending(
                candidate,
                &addr,
                state.pending_group_count(group)
            )
        );
    }

    #[test]
    fn state_segment_transport_rejects_same_peer_cross_session_response() {
        let peer = PeerId::random();
        let old = PendingStateSegmentRequest {
            peer,
            segment_id: 7,
            expected_tip_height: 144,
            expected_tip_hash: [0xA5; 32],
            manifest_digest: [0x11; 32],
            issued_at: Instant::now(),
            notify_node: true,
        };
        let response = GetStateSegmentResponse {
            segment_id: 7,
            expected_tip_height: 144,
            expected_tip_hash: [0xA5; 32],
            manifest_digest: [0x11; 32],
            status: crate::object_protocol::DataResponseStatus::Ready,
            eff_log: 0,
            data: None,
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        assert!(state_segment_response_matches_pending(old, peer, &response));

        let new_session = PendingStateSegmentRequest {
            manifest_digest: [0x22; 32],
            ..old
        };
        assert!(!state_segment_response_matches_pending(
            new_session,
            peer,
            &response
        ));
        assert!(!state_segment_response_matches_pending(
            old,
            PeerId::random(),
            &response
        ));

        let request = GetStateSegmentRequest {
            segment_id: 9,
            expected_tip_height: 200,
            expected_tip_hash: [0xCC; 32],
            manifest_digest: [0x33; 32],
        };
        let unavailable = unavailable_state_segment_response(&request);
        assert_eq!(unavailable.segment_id, request.segment_id);
        assert_eq!(unavailable.expected_tip_height, request.expected_tip_height);
        assert_eq!(unavailable.expected_tip_hash, request.expected_tip_hash);
        assert_eq!(unavailable.manifest_digest, request.manifest_digest);
    }

    #[test]
    fn superseded_snapshot_header_transport_is_retained_until_expiry() {
        let peer = PeerId::random();
        let now = Instant::now();
        let expired_at = now
            .checked_sub(SMALL_SYNC_PENDING_DEADLINE)
            .expect("process monotonic clock exceeds request deadline");
        let mut registry = BoundedPendingRequests::new(4);
        assert!(registry.try_insert(
            1u64,
            PendingHeaderRequest {
                peer,
                start_height: 1,
                count: 512,
                kind: HeaderRequestKind::Snapshot {
                    generation: 7,
                    token: 11,
                },
                issued_at: expired_at,
                notify_node: false,
            }
        ));
        assert!(registry.try_insert(
            2u64,
            PendingHeaderRequest {
                peer,
                start_height: 513,
                count: 512,
                kind: HeaderRequestKind::Snapshot {
                    generation: 8,
                    token: 12,
                },
                issued_at: now,
                notify_node: true,
            }
        ));
        assert!(registry.try_insert(
            3u64,
            PendingHeaderRequest {
                peer,
                start_height: 99,
                count: 20,
                kind: HeaderRequestKind::General,
                issued_at: now,
                notify_node: true,
            }
        ));

        assert_eq!(registry.len(), 3);
        let expired = registry.take_where_entries(|pending| {
            now.saturating_duration_since(pending.issued_at) >= SMALL_SYNC_PENDING_DEADLINE
        });
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, 1);
        assert_eq!(registry.len(), 2);
        assert!(registry.remove(&1).is_none());
        assert!(registry.remove(&2).is_some());
        assert!(
            registry.remove(&3).is_some(),
            "general tip probes are independent"
        );
    }

    #[test]
    fn snapshot_header_window_keeps_distinct_ranges_in_one_generation_live() {
        let peer = PeerId::random();
        let request = |generation, start_height| PendingHeaderRequest {
            peer,
            start_height,
            count: 512,
            kind: HeaderRequestKind::Snapshot {
                generation,
                token: start_height,
            },
            issued_at: Instant::now(),
            notify_node: true,
        };

        let first = request(9, 1);
        let second = request(9, 513);
        let old = request(8, 1025);
        assert!(snapshot_header_request_is_superseded(&first, 9, 1));
        assert!(!snapshot_header_request_is_superseded(&first, 9, 513));
        assert!(!snapshot_header_request_is_superseded(&second, 9, 1));
        assert!(snapshot_header_request_is_superseded(&old, 9, 1));

        let general = PendingHeaderRequest {
            kind: HeaderRequestKind::General,
            ..first
        };
        assert!(!snapshot_header_request_is_superseded(&general, 9, 1));
    }

    #[test]
    fn header_batch_shape_rejects_noncontiguity_without_rehashing_links() {
        let mut first = noid_chain::consensus::genesis::genesis_header();
        first.height = 77;
        let mut second = first;
        second.height = 78;
        second.prev_block_hash = noid_chain::hash_block_header(&first);
        assert_eq!(
            validate_header_batch_shape(&[
                HeaderInventoryRecord::header_only(first),
                HeaderInventoryRecord::header_only(second),
            ]),
            Ok(())
        );

        let mut skipped = second;
        skipped.height = 79;
        assert_eq!(
            validate_header_batch_shape(&[
                HeaderInventoryRecord::header_only(first),
                HeaderInventoryRecord::header_only(skipped),
            ]),
            Err("header batch is not height-contiguous")
        );

        // Parent-link hashing belongs to the single authoritative consensus
        // pass in snapshot staging, not the transport-shape layer.
        let mut wrong_parent = second;
        wrong_parent.prev_block_hash[0] ^= 1;
        assert_eq!(
            validate_header_batch_shape(&[
                HeaderInventoryRecord::header_only(first),
                HeaderInventoryRecord::header_only(wrong_parent),
            ]),
            Ok(())
        );
    }

    #[test]
    fn general_header_response_is_bound_to_the_requested_range() {
        let peer = PeerId::random();
        let pending = PendingHeaderRequest {
            peer,
            start_height: 77,
            count: 2,
            kind: HeaderRequestKind::General,
            issued_at: Instant::now(),
            notify_node: true,
        };
        let mut first = noid_chain::consensus::genesis::genesis_header();
        first.height = 77;
        let mut second = first;
        second.height = 78;
        second.prev_block_hash = noid_chain::hash_block_header(&first);
        let mut third = second;
        third.height = 79;
        third.prev_block_hash = noid_chain::hash_block_header(&second);

        assert_eq!(validate_general_header_response(&pending, &[]), Ok(()));
        assert_eq!(
            validate_general_header_response(
                &pending,
                &[HeaderInventoryRecord::header_only(first)],
            ),
            Ok(()),
            "an honest peer at its tip may return fewer headers than requested"
        );
        assert_eq!(
            validate_general_header_response(
                &pending,
                &[
                    HeaderInventoryRecord::header_only(first),
                    HeaderInventoryRecord::header_only(second),
                ],
            ),
            Ok(())
        );
        assert_eq!(
            validate_general_header_response(
                &pending,
                &[
                    HeaderInventoryRecord::header_only(first),
                    HeaderInventoryRecord::header_only(second),
                    HeaderInventoryRecord::header_only(third),
                ],
            ),
            Err("header response exceeds requested count")
        );
        assert_eq!(
            validate_general_header_response(
                &pending,
                &[
                    HeaderInventoryRecord::header_only(second),
                    HeaderInventoryRecord::header_only(third),
                ],
            ),
            Err("header response starts outside the requested range")
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn canonical_wire_caps_are_ordered() {
        assert!(crate::header_protocol::HEADER_ANNOUNCE_BYTES < MAX_TX_INTENT_BYTES_GLOBAL);
        assert!(MAX_MEMPOOL_SYNC_BYTES >= MAX_TX_INTENT_BYTES_GLOBAL);
        assert!(MAX_HISTORY_STEP_TERMINAL_BYTES > MAX_TX_INTENT_BYTES_GLOBAL);
    }

    #[tokio::test]
    async fn required_response_survives_recoverable_gossip_lag() {
        let (required_tx, required_rx) = event_dispatch::channel();
        let (gossip_tx, gossip_rx) = tokio::sync::broadcast::channel(2);
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let mut receiver = NetworkEventReceiver {
            required_rx,
            gossip_rx,
            required_closed: false,
            gossip_closed: false,
        };

        for byte in 0..3 {
            gossip_tx
                .send(NetworkEvent::NewTx {
                    from: peer,
                    intent_bytes: vec![byte],
                    gossip_message_id: None,
                    inbound_memory_permit: None,
                })
                .unwrap();
        }
        required_tx
            .send(NetworkEvent::PeerConnected {
                peer,
                locally_selected: true,
                failure_domain: 99,
            })
            .await
            .unwrap();

        assert!(matches!(
            receiver.recv().await,
            Ok(NetworkEvent::PeerConnected {
                failure_domain: 99,
                ..
            })
        ));
        assert!(matches!(
            receiver.recv().await,
            Err(NetworkEventRecvError::Lagged(1))
        ));
    }

    #[tokio::test]
    async fn mempool_serving_admits_bytes_before_invoking_payload_source() {
        let budget = OutboundResponseBudget::with_capacity(MAX_MEMPOOL_SYNC_BYTES);
        let source_invoked = Arc::new(AtomicBool::new(false));
        let observed_budget = budget.clone();
        let observed_source = source_invoked.clone();
        let response =
            prepare_mempool_response_after_admission(budget.clone(), move || async move {
                assert_eq!(observed_budget.available_bytes(), 0);
                observed_source.store(true, Ordering::SeqCst);
                vec![vec![0xA5]]
            })
            .await
            .unwrap();

        assert!(source_invoked.load(Ordering::SeqCst));
        assert_eq!(budget.available_bytes(), 0);
        drop(response);
        assert_eq!(budget.available_bytes(), MAX_MEMPOOL_SYNC_BYTES);
    }

    #[test]
    fn mempool_retry_is_per_peer_bounded_and_exponential() {
        let local = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let mut retries = std::collections::HashMap::new();
        let before = Instant::now();
        schedule_mempool_sync_retry(&mut retries, local, peer).unwrap();
        let first = retries[&peer];
        assert_eq!(first.failures, 1);
        assert!(first.next_attempt >= before + Duration::from_secs(1));
        assert!(first.next_attempt <= before + Duration::from_secs(5));

        schedule_mempool_sync_retry(&mut retries, local, peer).unwrap();
        let second = retries[&peer];
        assert_eq!(second.failures, 2);
        assert!(second.next_attempt > first.next_attempt);
        for expected_failures in 3..=MAX_MEMPOOL_SYNC_FAILURES {
            let retry = schedule_mempool_sync_retry(&mut retries, local, peer).unwrap();
            assert_eq!(retry.failures, expected_failures);
        }
        assert!(schedule_mempool_sync_retry(&mut retries, local, peer).is_none());
        assert!(retries.is_empty());
        assert!(mempool_sync_retry_jitter(local, peer) < Duration::from_secs(4));
    }
}
