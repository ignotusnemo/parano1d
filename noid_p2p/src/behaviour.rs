// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Combined libp2p NetworkBehaviour for the Paranoid full node.
//!
//! ## Peer discovery stack
//!
//! Paranoid uses three complementary mechanisms, mirroring the approach taken
//! by Substrate/Polkadot:
//!
//! 1. **Bootstrap nodes** — hard-coded seed addresses dialled on startup.
//! 2. **Kademlia DHT** — once connected, random `FIND_NODE` walks propagate
//!    the network view across all nodes.  Critical lesson from all libp2p
//!    chains: Kademlia is useless without Identify hooked to it.  Every time
//!    `identify::Event::Received` fires the handler must call
//!    `kad.add_address(peer_id, addr)` for every listen address.  Without
//!    this, remote nodes cannot put us into their routing tables and discovery
//!    stops at the boot nodes.
//! 3. **mDNS** — UDP broadcast on the local network.  Useful for local dev
//!    and private clusters; has no effect on the public internet.
//!
//! GossipSub PX is intentionally not used with rust-libp2p 0.47: that version
//! cannot consume the signed address records required to make PeerId-only PX a
//! trustworthy discovery mechanism. Kademlia remains the address-bearing
//! discovery layer.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use libp2p::{
    dcutr, gossipsub, identify, kad, mdns, ping, relay, request_response,
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour},
    StreamProtocol,
};
use libp2p_connection_limits as connection_limits;
use noid_chain::consensus::wire_limits::MAX_TX_INTENT_BYTES_GLOBAL;
use noid_poseidon2b::native::poseidon2b_hash_bytes;

const GOSSIPSUB_MESSAGE_ID_DOMAIN: &[u8] = b"NOID_P2P_GOSSIPSUB_MESSAGE_ID";

use crate::availability_codec::AvailabilityCodec;
use crate::header_protocol::MAX_HEADER_ANNOUNCE_BYTES;
use crate::header_sync_codec::HeaderSyncCodec;
use crate::history_step_codec::HistoryStepTerminalCodec;
use crate::manifest_page_codec::ManifestPageCodec;
use crate::mempool_sync_codec::MempoolSyncCodec;
use crate::network_profile::NetworkProfileCodec;
use crate::object_codec::ObjectCodec;
use crate::resource_profile::BackgroundCapacity;
use crate::state_manifest_codec::StateManifestCodec;
use crate::state_segment_codec::StateSegmentCodec;

/// All P2P behaviours composed via the derive macro.
///
/// Field order matters. Connection limits must reject an endpoint before any
/// stateful behaviour records its ConnectionId. The remaining behaviours keep
/// latency-sensitive gossip and request-response near the front.
#[derive(NetworkBehaviour)]
pub struct NodeBehaviour {
    /// Hard connection limits — evaluated before every stateful behaviour.
    ///
    /// Limits (production defaults, tunable via config):
    ///   128 established inbound  — matches Substrate's default
    ///    64 established outbound — we initiate fewer than we accept
    ///    64 pending inbound      — cap half-open handshakes
    ///    32 pending outbound     — cap simultaneous dial attempts
    ///     2 established per peer — direct plus relay during path upgrade
    ///
    /// Inbound network-group admission keeps 32 slots reserved for
    /// underrepresented prefixes, while allowing shared CGNAT/VPN exits to
    /// use the unreserved pool.
    pub connection_limits: connection_limits::Behaviour,

    /// Fixed header announcements and TxIntent gossip broadcast.
    pub gossipsub: gossipsub::Behaviour,

    /// Exact network-v7 profile handshake. A transport is never exposed to
    /// consensus/sync until this profile matches byte-for-byte.
    pub network_profile_sync: request_response::Behaviour<NetworkProfileCodec>,

    /// Content-addressed bodies and recursive terminals for header-first
    /// propagation and immutable sync plans.
    pub object_sync: request_response::Behaviour<ObjectCodec>,

    /// Small direct availability notices between current GossipSub mesh
    /// neighbours. This lets newly committed object providers expand the data
    /// plane without globally gossiping large proofs or polling public nodes.
    pub availability_sync: request_response::Behaviour<AvailabilityCodec>,

    /// Typed request-response for chain headers.
    pub chain_sync: request_response::Behaviour<HeaderSyncCodec>,

    /// Fused HistoryStep terminal for O(1) snapshot sync.
    pub history_step_sync: request_response::Behaviour<HistoryStepTerminalCodec>,
    pub fork_origin_sync: request_response::Behaviour<crate::fork_origin::ForkOriginCodec>,

    /// Kademlia DHT — primary peer discovery mechanism.
    ///
    /// Performs random `FIND_NODE` walks once connected to bootstrap peers.
    /// MUST be integrated with `identify`: every `identify::Event::Received`
    /// must call `kad.add_address()` to populate the routing table.
    pub kad: kad::Behaviour<kad::store::MemoryStore>,

    /// mDNS — LAN peer discovery (zero-config for local clusters and dev).
    ///
    /// Silent on the public internet (UDP broadcast is LAN-scoped).
    /// Discovered peers are immediately dialled.
    pub mdns: mdns::tokio::Behaviour,

    /// Peer identification — required for Kademlia routing table population.
    ///
    /// Every `identify::Event::Received` MUST call `kad.add_address()` for
    /// each listen address.  This is the #1 lesson from all libp2p chains:
    /// Kademlia alone cannot discover peers beyond boot nodes without Identify.
    pub identify: identify::Behaviour,

    /// Liveness probing.
    pub ping: ping::Behaviour,

    /// Circuit relay client — routes traffic through relay nodes when
    /// direct connections are not possible (NAT, firewall).
    ///
    /// A relay reservation can make the node reachable via:
    ///   /ip4/<relay>/tcp/<port>/p2p/<relay_id>/p2p-circuit/p2p/<our_id>
    pub relay_client: relay::client::Behaviour,

    /// Bounded Circuit Relay v2 service, enabled automatically only when this
    /// node declares a globally routable direct address. Private GUI nodes are
    /// relay clients, never accidental relay servers.
    pub relay_server: Toggle<relay::Behaviour>,

    /// DCUtR — Direct Connection Upgrade Through Relay.
    ///
    /// Once two NAT'd nodes are connected through a relay, DCUtR coordinates
    /// simultaneous TCP/UDP connection attempts to punch through both NATs.
    /// On success the relay connection is replaced by a direct connection.
    pub dcutr: dcutr::Behaviour,

    /// State manifest sync — small control header only.
    pub state_manifest_sync: request_response::Behaviour<StateManifestCodec>,

    /// Exact content-addressed descriptor pages. This is a State-metadata data
    /// plane separate from live bodies/terminals and multi-megabyte segments.
    pub manifest_page_sync: request_response::Behaviour<ManifestPageCodec>,

    /// State segment sync — step 2: request individual segments (~3 MB each).
    /// The node keeps one network request in flight and overlaps transfer with
    /// bounded disk authentication.
    pub state_segment_sync: request_response::Behaviour<StateSegmentCodec>,

    /// Mempool sync — exchange pending TXs on peer connect.
    /// When a new peer joins, both sides request each other's mempool so that
    /// TXs submitted before connection are immediately propagated.
    /// This complements gossipsub (which only delivers NEW events) with a
    /// state-sync mechanism for existing mempool entries.
    pub mempool_sync: request_response::Behaviour<MempoolSyncCodec>,
}

impl NodeBehaviour {
    /// Build the combined behaviour from a libp2p keypair.
    ///
    /// `protocol_id` is the network-specific prefix used for all sync stream
    /// protocols (for example the current mainnet namespace). This
    /// ensures distinct networks can never accidentally sync with each other.
    /// Build the combined behaviour.
    ///
    /// `relay_client` MUST come from `SwarmBuilder::with_relay_client()` —
    /// it cannot be constructed manually because it is wired into the relay
    /// transport layer by the builder.
    pub fn new(
        key: &libp2p::identity::Keypair,
        protocol_id: &str,
        relay_client: relay::client::Behaviour,
        background_capacity: BackgroundCapacity,
        serve_relay: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use libp2p::gossipsub::MessageAuthenticity;
        use libp2p::request_response::ProtocolSupport;

        // ----------------------------------------------------------------
        // GossipSub
        // ----------------------------------------------------------------
        //
        // Tuned for heterogeneous network sizes (2 → 10 000+ peers):
        //
        //  flood_publish=false  rely on the mesh for propagation at scale.
        //                       With flood_publish=true every block would be
        //                       sent to all 192 connections simultaneously
        //                       (~400 MB/s egress at max capacity).  The mesh
        //                       handles small networks fine once formed.
        //
        //  mesh_n / _low / _high  scaled-down so a mesh FORMS with as few as
        //                         2 nodes in local tests; still works at scale.
        //
        //  Kademlia             is the address-bearing discovery mechanism.
        //                       PX is deliberately disabled: rust-libp2p 0.47
        //                       cannot consume signed address records here, so
        //                       unauthenticated PeerId-only PX is not a safe
        //                       substitute for discovery.
        //
        //  heartbeat 700ms      fast mesh maintenance for dev/test; fine at
        //                       scale (Ethereum uses 700ms too).
        // Network v2 never places bodies or recursive terminals in gossip.
        // Its transmit cap therefore covers only one fixed header announcement
        // or one bounded TxIntent; bulk data uses exact request-response.

        let gossipsub_cfg = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_millis(700))
            // Mesh params tuned for 2-1000 peers:
            //   mesh_n(4)           — target mesh; forms with as few as 4 peers
            //   mesh_n_low(2)       — expand if fewer than 2 mesh peers
            //   mesh_n_high(8)      — prune above 8 (vs 12 before)
            //   mesh_outbound_min(1)— CRITICAL: was 2, blocked publish with ≤1 outbound
            //                        (every spoke node connecting to a single seed
            //                         has exactly 1 outbound; publish was silently
            //                         failing with InsufficientPeers for all of them)
            .mesh_n(4)
            .mesh_n_low(2)
            .mesh_n_high(8)
            .mesh_outbound_min(1)
            .max_transmit_size(MAX_TX_INTENT_BYTES_GLOBAL.max(MAX_HEADER_ANNOUNCE_BYTES))
            // Hold inbound messages until the network event loop has applied
            // structural, per-peer, and process-global admission. Without
            // manual validation, GossipSub forwards and retains a large block
            // bundle before our rate limit can see it, so many divergent
            // miners can turn a harmless node-side drop into unbounded
            // memcache and outbound-buffer growth.
            .validate_messages()
            // Public network: rely on the mesh for publish fanout. Flood-publishing to
            // every connected peer turns inbound spam into O(connected_peers)
            // outbound bandwidth even when downstream validation drops it.
            .flood_publish(false)
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(|msg| {
                // Content-addressed: hash the message data (not author+seq).
                let hash = poseidon2b_hash_bytes(GOSSIPSUB_MESSAGE_ID_DOMAIN, &msg.data);
                gossipsub::MessageId::from(hash.to_vec())
            })
            .build()
            .map_err(|e| format!("gossipsub config: {e}"))?;

        let mut gossipsub =
            gossipsub::Behaviour::new(MessageAuthenticity::Signed(key.clone()), gossipsub_cfg)
                .map_err(|e| format!("gossipsub: {e}"))?;

        // Peer scoring is a topology control, not a consensus oracle. Even
        // without application topic scores it provides two important v1.1
        // defences: protocol-behaviour penalties and exact-IP colocation
        // penalties. The threshold of eight follows Lighthouse's production
        // profile: ordinary NAT/datacenter co-location remains usable while a
        // large identity farm on one IP becomes expensive. Loopback is
        // whitelisted so multi-process local networks retain realistic mesh
        // behaviour.
        let mut ip_colocation_whitelist = HashSet::new();
        ip_colocation_whitelist.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        ip_colocation_whitelist.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
        let peer_score_params = gossipsub::PeerScoreParams {
            ip_colocation_factor_threshold: 8.0,
            ip_colocation_factor_whitelist: ip_colocation_whitelist,
            ..gossipsub::PeerScoreParams::default()
        };
        let peer_score_thresholds = gossipsub::PeerScoreThresholds {
            // With no trusted-bootstrap application score, accepting PX must
            // fail closed. Kademlia carries actual transport addresses.
            accept_px_threshold: 1.0,
            // Trigger recovery only when the current mesh median is negative.
            opportunistic_graft_threshold: 0.0,
            ..gossipsub::PeerScoreThresholds::default()
        };
        gossipsub
            .with_peer_score(peer_score_params, peer_score_thresholds)
            .map_err(|e| format!("gossipsub peer score: {e}"))?;

        // ----------------------------------------------------------------
        // Request-response protocols
        // ----------------------------------------------------------------
        //
        // Network-aware protocol IDs — use the network's protocol_id prefix.
        // This keeps distinct network sync protocols fully isolated.
        let network_profile_sync = request_response::Behaviour::new(
            [(
                StreamProtocol::try_from_owned(format!("{}/sync/profile/6", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(10))
                .with_max_concurrent_streams(16),
        );

        let object_sync = request_response::Behaviour::new(
            [(
                StreamProtocol::try_from_owned(format!("{}/sync/objects/2", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(60))
                .with_max_concurrent_streams(8),
        );

        let availability_sync = request_response::Behaviour::new(
            [(
                StreamProtocol::try_from_owned(format!("{}/sync/availability/1", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(10))
                .with_max_concurrent_streams(16),
        );

        let chain_sync = request_response::Behaviour::new(
            [
                (
                    // New peers negotiate v5 and receive explicit bounded
                    // Busy backpressure from a saturated header server.
                    StreamProtocol::try_from_owned(format!("{}/sync/headers/5", protocol_id))?,
                    ProtocolSupport::Full,
                ),
                (
                    // v2.0.1 already carries the same canonical headers and
                    // exact retained-object inventory. Keep v4 as a fallback
                    // so transport improvements do not split mainnet.
                    StreamProtocol::try_from_owned(format!("{}/sync/headers/4", protocol_id))?,
                    ProtocolSupport::Full,
                ),
            ],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30))
                .with_max_concurrent_streams(8),
        );

        let history_step_sync = request_response::Behaviour::new(
            [(
                StreamProtocol::try_from_owned(format!("{}/sync/history-step/1", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                // A legal terminal is almost 1 MiB. Ten seconds was shorter
                // than an ordinary residential path needs and caused a
                // verified header staging pass to be thrown away mid-sync.
                .with_request_timeout(Duration::from_secs(60))
                .with_max_concurrent_streams(4),
        );

        let fork_origin_sync = request_response::Behaviour::new(
            [(
                StreamProtocol::try_from_owned(format!("{}/sync/fork-origin/1", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(45))
                .with_max_concurrent_streams(4),
        );

        // Manifest v7 carries only fixed metadata and <=64 page identities.
        let state_manifest_sync = request_response::Behaviour::new(
            [(
                StreamProtocol::try_from_owned(format!("{}/sync/manifest/7", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30))
                .with_max_concurrent_streams(8),
        );

        let manifest_page_sync = request_response::Behaviour::new(
            [(
                StreamProtocol::try_from_owned(format!("{}/sync/manifest-page/1", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30))
                .with_max_concurrent_streams(8),
        );

        // Segment: each response is ~3 MB; 60s per segment is generous.
        // The server cap bounds aggregate inbound work from concurrent peers;
        // one snapshot client uses a single transfer lane.
        let state_segment_sync = request_response::Behaviour::new(
            [
                (
                    StreamProtocol::try_from_owned(format!("{}/sync/segment/7", protocol_id))?,
                    ProtocolSupport::Full,
                ),
                (
                    // Transport-only compression; the canonical SGS1 bytes,
                    // snapshot identity and verification rules are unchanged.
                    StreamProtocol::try_from_owned(format!("{}/sync/segment/6", protocol_id))?,
                    ProtocolSupport::Full,
                ),
                (
                    StreamProtocol::try_from_owned(format!("{}/sync/segment/5", protocol_id))?,
                    ProtocolSupport::Full,
                ),
            ],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(60))
                .with_max_concurrent_streams(8),
        );

        // Optional v4 adds bounded missing-only reconciliation. Retain v3
        // negotiation and its exact Pull/Push bytes for unupgraded peers.
        // Response caps, stream count and shared memory budgets are unchanged.
        let mempool_sync = request_response::Behaviour::new(
            [
                (
                    StreamProtocol::try_from_owned(format!("{}/sync/mempool/4", protocol_id))?,
                    ProtocolSupport::Full,
                ),
                (
                    StreamProtocol::try_from_owned(format!("{}/sync/mempool/3", protocol_id))?,
                    ProtocolSupport::Full,
                ),
            ],
            request_response::Config::default()
                // A full bounded response is 16 MiB; permit ordinary
                // residential links to complete without weakening byte caps.
                .with_request_timeout(Duration::from_secs(30))
                // Pulls and a small bounded direct relay fanout may overlap.
                // Request decoding and response bytes remain process-globally
                // governed by the shared inbound/outbound budgets.
                .with_max_concurrent_streams(8),
        );

        // ----------------------------------------------------------------
        // Kademlia DHT
        // ----------------------------------------------------------------
        //
        // Network-isolated: each chain gets its own protocol ID so distinct
        // networks never pollute each other's routing tables.
        //
        // KBucketInserts::OnConnected: only insert peers we actually have
        // open connections to. This prevents phantom entries from stale
        // `FIND_NODE` responses from filling the table.
        let kad_protocol = StreamProtocol::try_from_owned(format!("{}/kad/1.0.0", protocol_id))?;
        let mut kad_cfg = kad::Config::new(kad_protocol);
        kad_cfg
            // Discovery is paced by the outer topology controller. The
            // library default additionally starts a complete multi-bucket
            // bootstrap every five minutes; that duplicates the bounded
            // random lookup below and can create a relay circuit wave.
            .set_periodic_bootstrap_interval(None)
            .set_replication_factor(std::num::NonZeroUsize::new(20).unwrap())
            // One probe at a time is enough because every fresh node already
            // has two independent bootstrap paths. It also lets the outer
            // topology controller stop the lookup as soon as two ordinary
            // neighbours complete the four-peer mesh, before a relay wave can
            // fan out to the rest of the returned routing table.
            .set_parallelism(std::num::NonZeroUsize::new(1).unwrap())
            .set_query_timeout(Duration::from_secs(60))
            // Only insert peers into the routing table when we have an
            // established connection (not from hearsay in FIND_NODE responses).
            .set_kbucket_inserts(kad::BucketInserts::OnConnected);
        let kad_store = kad::store::MemoryStore::new(key.public().to_peer_id());
        let mut kad = kad::Behaviour::with_config(key.public().to_peer_id(), kad_store, kad_cfg);
        // Start in server mode: respond to Kademlia queries from other nodes.
        // Client mode would only query, not serve — wrong for a full node.
        kad.set_mode(Some(kad::Mode::Server));

        // ----------------------------------------------------------------
        // mDNS (LAN discovery)
        // ----------------------------------------------------------------
        //
        // Broadcasts UDP packets on the local network. Peers that respond
        // are immediately dialled. Completely harmless on the public internet
        // (broadcast is LAN-scoped; no external packets are sent).
        // This makes local clusters and dev setups zero-config.
        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config {
                // Re-query every 60s so long-lived LANs stay connected.
                query_interval: Duration::from_secs(60),
                ..Default::default()
            },
            key.public().to_peer_id(),
        )?;

        // ----------------------------------------------------------------
        // Identify
        // ----------------------------------------------------------------
        //
        // Tells connected peers our listen addresses and supported protocols.
        // CRITICAL: the event handler in network.rs MUST call
        //   `kad.add_address(peer_id, addr)` for every listen address
        //   received via `identify::Event::Received`.
        // Without this, Kademlia cannot populate its routing table because
        // the DHT only stores addresses it has been explicitly told about.
        let identify = identify::Behaviour::new(
            identify::Config::new("/noid/1.0.0".into(), key.public())
                .with_push_listen_addr_updates(true)
                // Re-identify periodically so address changes propagate.
                .with_interval(Duration::from_secs(300)),
        );

        let ping = ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(30)));

        // ----------------------------------------------------------------
        // NAT traversal: relay client + DCUtR
        // ----------------------------------------------------------------
        // DCUtR: coordinates simultaneous dial attempts between two NAT'd
        // nodes connected through a relay, upgrading to a direct connection.
        let dcutr = dcutr::Behaviour::new(key.public().to_peer_id());
        let relay_server = serve_relay
            .then(|| {
                relay::Behaviour::new(
                    key.public().to_peer_id(),
                    relay::Config {
                        max_reservations: background_capacity.relay_max_reservations(),
                        max_reservations_per_peer:
                            crate::resource_profile::relay_018_per_peer_config(1),
                        // Relay is an auxiliary reachability path, not the
                        // bulk-data backbone. A small per-node cap protects
                        // ordinary public nodes while capacity grows with
                        // their number.
                        max_circuits: background_capacity.relay_max_circuits(),
                        max_circuits_per_peer: crate::resource_profile::relay_018_per_peer_config(
                            background_capacity.relay_max_circuits_per_peer(),
                        ),
                        max_circuit_duration: Duration::from_secs(5 * 60),
                        // A client that cannot complete DCUtR must still
                        // sustain the declared 256 KiB/s minimum for the
                        // complete five-minute circuit lifetime.
                        max_circuit_bytes: 80 * 1024 * 1024,
                        ..relay::Config::default()
                    },
                )
            })
            .into();

        // ----------------------------------------------------------------
        // Connection limits
        // ----------------------------------------------------------------
        //
        // Enforced at the swarm level before any behaviour receives events.
        // Substrate defaults: 100 in / 25 out.  We use slightly higher
        // values because public nodes also serve bounded snapshot and proof
        // objects over request-response streams.
        let connection_limits = connection_limits::Behaviour::new(
            connection_limits::ConnectionLimits::default()
                .with_max_established_incoming(Some(128))
                .with_max_established_outgoing(Some(64))
                .with_max_pending_incoming(Some(64))
                .with_max_pending_outgoing(Some(32))
                // Simultaneous dials and direct/relay upgrades can briefly
                // require two paths. More paths from one identity must not be
                // able to consume a node's connection budget.
                .with_max_established_per_peer(Some(2)),
        );

        Ok(Self {
            connection_limits,
            gossipsub,
            network_profile_sync,
            object_sync,
            availability_sync,
            chain_sync,
            history_step_sync,
            fork_origin_sync,
            kad,
            mdns,
            identify,
            ping,
            relay_client,
            relay_server,
            dcutr,
            state_manifest_sync,
            manifest_page_sync,
            state_segment_sync,
            mempool_sync,
        })
    }
}
