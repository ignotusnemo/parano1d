// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Wire message types for the Paranoid P2P protocol.
//!
//! Block propagation is header-first. Gossip carries one fixed header
//! announcement; bodies and recursive terminals move only through the exact
//! content-addressed object protocol selected by HeaderDAG.
//!
//! ## State sync
//!
//! State snapshots are served in three bounded stages:
//!
//! 1. Client requests `GetStateManifestRequest` and receives only fixed
//!    metadata plus at most 64 content-addressed descriptor-page identities.
//! 2. Descriptor pages move through the bounded State-metadata data plane.
//! 3. Client requests each segment individually via `GetStateSegmentRequest`
//!    → receives one 3 MB segment per response.
//!
//! This enables progress reporting, resumable sync, and correct memory usage
//! regardless of total state size.

use noid_poseidon2b::native::poseidon2b_hash_bytes;
use serde::{Deserialize, Serialize};
use std::{ops::Deref, sync::Arc};

use crate::header_protocol::HeaderInventoryRecord;
use crate::object_protocol::{ChainPoint, DataResponseStatus, SnapshotId};

/// Deterministic finalized heights at which independent nodes build the same
/// source-independent snapshot generation. This is an operational serving
/// cadence, not a consensus parameter.
pub const SNAPSHOT_BOUNDARY_INTERVAL: u64 = 6;
const _: () = assert!(SNAPSHOT_BOUNDARY_INTERVAL > 0);
const _: () =
    assert!(SNAPSHOT_BOUNDARY_INTERVAL <= noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH);

// ---------------------------------------------------------------------------
// Block pull: headers
// ---------------------------------------------------------------------------

/// Get block headers by height range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHeadersRequest {
    pub start_height: u64,
    pub count: u16, // wire cap: MAX_HEADERS_PER_BATCH; callers may request smaller batches
    /// Include exact retained-object identities for recent sync planning.
    /// Snapshot header staging sets this to false and receives headers only.
    pub include_inventory: bool,
}

/// Response: canonical block headers and optional exact retained-object
/// inventory decoded by the allocation-bounded header-sync codec.
#[derive(Debug, Clone)]
pub struct GetHeadersResponse {
    /// `Busy` is bounded control-plane backpressure. It never carries headers
    /// and does not invalidate the responding peer as an exact source.
    pub status: DataResponseStatus,
    pub records: Vec<HeaderInventoryRecord>,
    /// Exact deterministic finalized boundary whose complete terminal and
    /// snapshot generation this responding peer can currently serve. This is
    /// an availability hint only; the receiver independently verifies every
    /// referenced object.
    pub snapshot_boundary: Option<ChainPoint>,
}

// ---------------------------------------------------------------------------
// HistoryStep terminal for O(1) snapshot sync
// ---------------------------------------------------------------------------

/// Request the fused HistoryStep terminal at one exact snapshot boundary.
#[derive(Debug, Clone)]
pub struct GetHistoryStepTerminalRequest {
    pub height: u64,
    pub block_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct GetHistoryStepTerminalResponse {
    /// Exact request boundary echoed by the server so delayed responses cannot
    /// consume a newer manifest session for the same peer. This is the
    /// nonce-bearing chain-link block id.
    pub height: u64,
    pub block_hash: [u8; 32],
    pub status: DataResponseStatus,
    /// Serialized fused HistoryStep terminal bound to `height` and the
    /// nonce-free semantic id of the same header. Node-side snapshot
    /// verification checks both ids against that authenticated staged header.
    pub terminal_bytes: Option<Vec<u8>>,
    /// Process-wide inbound byte admission retained until node-side terminal
    /// verification has consumed the response.
    pub(crate) inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    /// Process-wide outbound byte admission retained through the codec write.
    pub(crate) outbound_memory_permit: Option<crate::outbound_budget::OutboundMemoryPermit>,
}

// ---------------------------------------------------------------------------
// State sync — manifest (step 1)
// ---------------------------------------------------------------------------

/// Request the state manifest: metadata + list of active segment IDs.
///
/// The manifest describes the state snapshot authorized by the corresponding
/// fused HistoryStep terminal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStateManifestRequest {
    /// Requester's current tip height (0 for fresh nodes).
    pub requester_height: u64,
    /// Zero requests the freshest usable generation. A non-zero digest asks
    /// for that exact immutable generation so object failover never silently
    /// changes the selected State plan.
    pub requested_manifest_digest: [u8; 32],
}

pub const SNAPSHOT_MANIFEST_DESCRIPTORS_PER_PAGE: usize = 1024;
pub const SNAPSHOT_MANIFEST_DESCRIPTOR_BYTES: usize = 2 + 32 + 4;
pub const SNAPSHOT_MANIFEST_PAGE_HEADER_BYTES: usize = 4 + 2 + 2;
pub const MAX_SNAPSHOT_MANIFEST_PAGES: usize =
    noid_chain::consensus::wire_limits::MAX_SNAPSHOT_MANIFEST_SEGMENTS
        .div_ceil(SNAPSHOT_MANIFEST_DESCRIPTORS_PER_PAGE);
const SNAPSHOT_MANIFEST_PAGE_MAGIC: [u8; 4] = *b"NMP1";
const SNAPSHOT_MANIFEST_PAGE_DIGEST_DOMAIN: &[u8] = b"PARANO1D/P2P/SNAPSHOT-MANIFEST-PAGE/V1";

/// Exact immutable identity of one canonical descriptor page. Page size and
/// descriptor count are derived from the manifest's total segment count; a
/// peer cannot advertise arbitrary page geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotManifestPageRef {
    pub page_index: u16,
    pub byte_digest: [u8; 32],
    pub encoded_len: u32,
    pub descriptor_count: u16,
}

impl SnapshotManifestPageRef {
    pub fn matches_bytes(self, bytes: &[u8]) -> bool {
        usize::try_from(self.encoded_len).ok() == Some(bytes.len())
            && poseidon2b_hash_bytes(SNAPSHOT_MANIFEST_PAGE_DIGEST_DOMAIN, bytes)
                == self.byte_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotManifestPageObjectId {
    pub snapshot: SnapshotId,
    pub page: SnapshotManifestPageRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetSnapshotManifestPageRequest {
    pub object: SnapshotManifestPageObjectId,
}

#[derive(Debug, Clone)]
pub struct GetSnapshotManifestPageResponse {
    pub object: SnapshotManifestPageObjectId,
    pub status: DataResponseStatus,
    pub data: Option<Arc<[u8]>>,
    pub(crate) inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    pub(crate) outbound_memory_permit: Option<crate::outbound_budget::OutboundMemoryPermit>,
}

/// Small control-plane response. Segment descriptors never travel in this
/// frame; only their ordered content identities do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GetStateManifestHeader {
    pub tip_height: u64,
    pub tip_hash: [u8; 32],
    pub cumulative_chainwork: [u8; 32],
    pub format_version: u32,
    pub state_root: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    pub eff_log: u8,
    pub bridge_tip_height: u64,
    pub bridge_tip_hash: [u8; 32],
    pub bridge_cumulative_chainwork: [u8; 32],
    pub segment_count: u32,
    pub descriptor_pages: Vec<SnapshotManifestPageRef>,
}

/// Manifest response: chain metadata + list of active segment IDs.
///
/// `tip_height = 0` means no snapshot is being advertised.
/// `tip_height`, `tip_hash`, and `cumulative_chainwork` describe the finalized
/// snapshot boundary `F`, not the peer's live tip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GetStateManifestResponse {
    /// Finalized snapshot boundary height. 0 = "use block sync instead".
    pub tip_height: u64,
    pub tip_hash: [u8; 32],
    /// Exact cumulative chainwork at `tip_height`, as validated with headers.
    pub cumulative_chainwork: [u8; 32],
    /// Immutable snapshot layout version. This is a transport/storage
    /// format version, not a consensus parameter.
    pub format_version: u32,
    /// Exact State root committed by the boundary header.
    pub state_root: [u8; 32],
    /// Source-independent digest of every immutable manifest field and
    /// segment descriptor. Peers with this same digest may serve different
    /// segments of one plan without becoming consensus authorities.
    pub manifest_digest: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    /// Effective log segment size (determines each segment's slot capacity).
    pub eff_log: u8,
    /// Last immutable accepted bundle captured with this snapshot generation.
    /// The complete range `tip_height + 1 ..= bridge_tip_height` is served
    /// from generation-owned files and cannot be pruned by the live chain.
    pub bridge_tip_height: u64,
    pub bridge_tip_hash: [u8; 32],
    pub bridge_cumulative_chainwork: [u8; 32],
    /// IDs of all non-empty state segments.  Each must be fetched individually.
    pub segment_ids: Vec<u16>,
    /// Exact Poseidon subtree roots aligned with `segment_ids`. Each sparse
    /// payload is checked directly against its subtree root; the receiver then
    /// independently rebuilds the global root committed by the tip header.
    pub segment_roots: Vec<[u8; 32]>,
    /// Canonical sparse payload lengths aligned with `segment_ids`. The length
    /// commits the number of live entries before any payload allocation.
    pub segment_lengths: Vec<u32>,
}

pub const SNAPSHOT_MANIFEST_FORMAT_VERSION: u32 = 2;
const SNAPSHOT_MANIFEST_DIGEST_DOMAIN: &[u8] = b"PARANO1D/P2P/SNAPSHOT-MANIFEST/V2";

impl GetStateManifestHeader {
    pub fn computed_manifest_digest(&self) -> Option<[u8; 32]> {
        if self.tip_height == 0 || !self.has_canonical_page_shape() {
            return None;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(SNAPSHOT_MANIFEST_DIGEST_DOMAIN);
        hasher.update(&self.format_version.to_le_bytes());
        hasher.update(&self.tip_height.to_le_bytes());
        hasher.update(&self.tip_hash);
        hasher.update(&self.cumulative_chainwork);
        hasher.update(&self.state_root);
        hasher.update(&self.log_slots.to_le_bytes());
        hasher.update(&self.active_slot_count.to_le_bytes());
        hasher.update(&self.alloc_counter.to_le_bytes());
        hasher.update(&[self.eff_log]);
        hasher.update(&self.bridge_tip_height.to_le_bytes());
        hasher.update(&self.bridge_tip_hash);
        hasher.update(&self.bridge_cumulative_chainwork);
        hasher.update(&self.segment_count.to_le_bytes());
        hasher.update(&(self.descriptor_pages.len() as u16).to_le_bytes());
        for page in &self.descriptor_pages {
            hasher.update(&page.page_index.to_le_bytes());
            hasher.update(&page.byte_digest);
            hasher.update(&page.encoded_len.to_le_bytes());
            hasher.update(&page.descriptor_count.to_le_bytes());
        }
        Some(*hasher.finalize().as_bytes())
    }

    pub fn seal_manifest_digest(&mut self) -> bool {
        let Some(digest) = self.computed_manifest_digest() else {
            return false;
        };
        self.manifest_digest = digest;
        true
    }

    pub fn has_valid_manifest_digest(&self) -> bool {
        self.computed_manifest_digest() == Some(self.manifest_digest)
    }

    pub fn has_canonical_page_shape(&self) -> bool {
        let Ok(segment_count) = usize::try_from(self.segment_count) else {
            return false;
        };
        if segment_count > noid_chain::consensus::wire_limits::MAX_SNAPSHOT_MANIFEST_SEGMENTS {
            return false;
        }
        let expected_pages = segment_count.div_ceil(SNAPSHOT_MANIFEST_DESCRIPTORS_PER_PAGE);
        if expected_pages != self.descriptor_pages.len()
            || expected_pages > MAX_SNAPSHOT_MANIFEST_PAGES
        {
            return false;
        }
        self.descriptor_pages
            .iter()
            .enumerate()
            .all(|(index, page)| {
                let first = index.saturating_mul(SNAPSHOT_MANIFEST_DESCRIPTORS_PER_PAGE);
                let remaining = segment_count.saturating_sub(first);
                let expected_count = remaining.min(SNAPSHOT_MANIFEST_DESCRIPTORS_PER_PAGE);
                let expected_len = SNAPSHOT_MANIFEST_PAGE_HEADER_BYTES.saturating_add(
                    expected_count.saturating_mul(SNAPSHOT_MANIFEST_DESCRIPTOR_BYTES),
                );
                usize::from(page.page_index) == index
                    && usize::from(page.descriptor_count) == expected_count
                    && usize::try_from(page.encoded_len).ok() == Some(expected_len)
            })
    }

    pub fn snapshot_id(&self) -> Option<SnapshotId> {
        (self.tip_height > 0 && self.has_valid_manifest_digest()).then_some(SnapshotId {
            boundary: ChainPoint {
                height: self.tip_height,
                hash: self.tip_hash,
            },
            state_root: self.state_root,
            manifest_digest: self.manifest_digest,
            format_version: self.format_version,
        })
    }

    fn assemble_manifest(&self, pages: &[Arc<[u8]>]) -> Option<GetStateManifestResponse> {
        if !self.has_valid_manifest_digest() || pages.len() != self.descriptor_pages.len() {
            return None;
        }
        let mut segment_ids = Vec::with_capacity(self.segment_count as usize);
        let mut segment_roots = Vec::with_capacity(self.segment_count as usize);
        let mut segment_lengths = Vec::with_capacity(self.segment_count as usize);
        for (expected, encoded) in self.descriptor_pages.iter().zip(pages) {
            let descriptors = decode_snapshot_manifest_page(*expected, encoded)?;
            for (segment_id, segment_root, encoded_len) in descriptors {
                if segment_ids
                    .last()
                    .is_some_and(|previous| *previous >= segment_id)
                {
                    return None;
                }
                segment_ids.push(segment_id);
                segment_roots.push(segment_root);
                segment_lengths.push(encoded_len);
            }
        }
        if segment_ids.len() != self.segment_count as usize {
            return None;
        }
        let response = GetStateManifestResponse {
            tip_height: self.tip_height,
            tip_hash: self.tip_hash,
            cumulative_chainwork: self.cumulative_chainwork,
            format_version: self.format_version,
            state_root: self.state_root,
            manifest_digest: self.manifest_digest,
            log_slots: self.log_slots,
            active_slot_count: self.active_slot_count,
            alloc_counter: self.alloc_counter,
            eff_log: self.eff_log,
            bridge_tip_height: self.bridge_tip_height,
            bridge_tip_hash: self.bridge_tip_hash,
            bridge_cumulative_chainwork: self.bridge_cumulative_chainwork,
            segment_ids,
            segment_roots,
            segment_lengths,
        };
        validate_manifest_descriptors(&response).then_some(response)
    }
}

/// A complete manifest whose small header, every exact descriptor page and
/// all cross-page State invariants have already been authenticated.  The
/// constructor is intentionally private to this module: network consumers can
/// clone the `Arc`, but cannot accidentally turn unverified vectors into
/// snapshot scheduling authority.
#[derive(Debug, Clone)]
pub struct VerifiedStateManifest {
    manifest: Arc<GetStateManifestResponse>,
}

impl VerifiedStateManifest {
    pub(crate) fn empty() -> Self {
        Self {
            manifest: Arc::new(GetStateManifestResponse::default()),
        }
    }

    /// Build and authenticate a local export.  Page hashing and the full
    /// descriptor pass are deliberately performed by the caller's blocking
    /// export worker, never by the swarm reactor.
    pub(crate) fn prepare_local(
        mut manifest: GetStateManifestResponse,
    ) -> Option<(Self, GetStateManifestHeader, Vec<Arc<[u8]>>)> {
        let (header, pages) = manifest.to_header_and_pages()?;
        manifest.manifest_digest = header.manifest_digest;
        if !validate_manifest_descriptors(&manifest) {
            return None;
        }
        Some((
            Self {
                manifest: Arc::new(manifest),
            },
            header,
            pages,
        ))
    }

    /// Assemble one network manifest after every page has independently
    /// matched the exact identities committed by the header.  This includes
    /// the one full cross-page semantic pass and is therefore called only on
    /// a blocking worker.
    pub(crate) fn from_pages(header: &GetStateManifestHeader, pages: &[Arc<[u8]>]) -> Option<Self> {
        let manifest = header.assemble_manifest(pages)?;
        Some(Self {
            manifest: Arc::new(manifest),
        })
    }

    /// Test/local compatibility constructor. Production network admission
    /// uses `from_pages`, which never re-encodes an already received page.
    pub fn verify(manifest: GetStateManifestResponse) -> Option<Self> {
        if manifest == GetStateManifestResponse::default() {
            return Some(Self::empty());
        }
        let (verified, _, _) = Self::prepare_local(manifest)?;
        Some(verified)
    }

    pub fn into_arc(self) -> Arc<GetStateManifestResponse> {
        self.manifest
    }
}

impl Deref for VerifiedStateManifest {
    type Target = GetStateManifestResponse;

    fn deref(&self) -> &Self::Target {
        self.manifest.as_ref()
    }
}

impl AsRef<GetStateManifestResponse> for VerifiedStateManifest {
    fn as_ref(&self) -> &GetStateManifestResponse {
        self.manifest.as_ref()
    }
}

impl PartialEq for VerifiedStateManifest {
    fn eq(&self, other: &Self) -> bool {
        self.manifest == other.manifest
    }
}

impl Eq for VerifiedStateManifest {}

impl GetStateManifestResponse {
    pub fn to_header_and_pages(&self) -> Option<(GetStateManifestHeader, Vec<Arc<[u8]>>)> {
        if self.tip_height == 0 {
            return Some((GetStateManifestHeader::default(), Vec::new()));
        }
        if self.format_version != SNAPSHOT_MANIFEST_FORMAT_VERSION
            || self.segment_ids.len() != self.segment_roots.len()
            || self.segment_ids.len() != self.segment_lengths.len()
            || self.segment_ids.len()
                > noid_chain::consensus::wire_limits::MAX_SNAPSHOT_MANIFEST_SEGMENTS
        {
            return None;
        }
        let mut pages = Vec::with_capacity(
            self.segment_ids
                .len()
                .div_ceil(SNAPSHOT_MANIFEST_DESCRIPTORS_PER_PAGE),
        );
        let mut refs = Vec::with_capacity(pages.capacity());
        for (page_index, first) in (0..self.segment_ids.len())
            .step_by(SNAPSHOT_MANIFEST_DESCRIPTORS_PER_PAGE)
            .enumerate()
        {
            let end = (first + SNAPSHOT_MANIFEST_DESCRIPTORS_PER_PAGE).min(self.segment_ids.len());
            let encoded = encode_snapshot_manifest_page(
                page_index as u16,
                &self.segment_ids[first..end],
                &self.segment_roots[first..end],
                &self.segment_lengths[first..end],
            )?;
            refs.push(SnapshotManifestPageRef {
                page_index: page_index as u16,
                byte_digest: poseidon2b_hash_bytes(SNAPSHOT_MANIFEST_PAGE_DIGEST_DOMAIN, &encoded),
                encoded_len: u32::try_from(encoded.len()).ok()?,
                descriptor_count: u16::try_from(end - first).ok()?,
            });
            pages.push(Arc::from(encoded));
        }
        let mut header = GetStateManifestHeader {
            tip_height: self.tip_height,
            tip_hash: self.tip_hash,
            cumulative_chainwork: self.cumulative_chainwork,
            format_version: self.format_version,
            state_root: self.state_root,
            manifest_digest: [0; 32],
            log_slots: self.log_slots,
            active_slot_count: self.active_slot_count,
            alloc_counter: self.alloc_counter,
            eff_log: self.eff_log,
            bridge_tip_height: self.bridge_tip_height,
            bridge_tip_hash: self.bridge_tip_hash,
            bridge_cumulative_chainwork: self.bridge_cumulative_chainwork,
            segment_count: u32::try_from(self.segment_ids.len()).ok()?,
            descriptor_pages: refs,
        };
        header.seal_manifest_digest().then_some((header, pages))
    }

    /// Compute the canonical network identity of a non-empty immutable
    /// snapshot manifest. The digest deliberately excludes itself.
    pub fn computed_manifest_digest(&self) -> Option<[u8; 32]> {
        self.to_header_and_pages()?.0.computed_manifest_digest()
    }

    pub fn seal_manifest_digest(&mut self) -> bool {
        let Some(digest) = self.computed_manifest_digest() else {
            return false;
        };
        self.manifest_digest = digest;
        true
    }

    pub fn has_valid_manifest_digest(&self) -> bool {
        self.computed_manifest_digest() == Some(self.manifest_digest)
    }
}

fn validate_manifest_descriptors(manifest: &GetStateManifestResponse) -> bool {
    use noid_chain::{
        consensus::wire_limits::MAX_SNAPSHOT_MANIFEST_SEGMENTS,
        storage::{
            encoded_segment_live_count_from_len,
            native_segment::{
                max_snapshot_segment_len, snapshot_segment_bytes_limit, snapshot_segment_len_valid,
            },
        },
        LOG_SEGMENT_SIZE,
    };

    if manifest.tip_height == 0
        || manifest.format_version != SNAPSHOT_MANIFEST_FORMAT_VERSION
        || manifest.segment_ids.len() != manifest.segment_roots.len()
        || manifest.segment_ids.len() != manifest.segment_lengths.len()
        || manifest.segment_ids.len() > MAX_SNAPSHOT_MANIFEST_SEGMENTS
        || !(1..=u32::BITS).contains(&manifest.log_slots)
        || manifest.active_slot_count > manifest.alloc_counter
        || u64::try_from(manifest.segment_ids.len())
            .ok()
            .is_none_or(|count| count > manifest.active_slot_count)
    {
        return false;
    }
    let Some(slot_domain) = 1u64.checked_shl(manifest.log_slots) else {
        return false;
    };
    if manifest.active_slot_count > slot_domain {
        return false;
    }
    let Some(bridge_span) = manifest.bridge_tip_height.checked_sub(manifest.tip_height) else {
        return false;
    };
    if bridge_span > noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH
        || (bridge_span == 0
            && (manifest.bridge_tip_hash != manifest.tip_hash
                || manifest.bridge_cumulative_chainwork != manifest.cumulative_chainwork))
        || (bridge_span > 0
            && !noid_chain::work_gt(
                &manifest.bridge_cumulative_chainwork,
                &manifest.cumulative_chainwork,
            ))
    {
        return false;
    }
    let expected_eff_log = manifest.log_slots.min(LOG_SEGMENT_SIZE as u32) as u8;
    if manifest.eff_log != expected_eff_log
        || max_snapshot_segment_len(manifest.eff_log, manifest.tip_height)
            .is_none_or(|length| length > snapshot_segment_bytes_limit(manifest.tip_height))
    {
        return false;
    }
    let segment_span = manifest
        .log_slots
        .saturating_sub(u32::from(manifest.eff_log));
    let Some(maximum_segments) = 1usize.checked_shl(segment_span) else {
        return false;
    };
    if manifest.segment_ids.len() > maximum_segments
        || !manifest
            .segment_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || manifest
            .segment_ids
            .iter()
            .any(|segment_id| usize::from(*segment_id) >= maximum_segments)
    {
        return false;
    }
    if noid_chain::consensus::params::v2_1_active(manifest.tip_height) {
        return manifest.active_slot_count
            <= (manifest.segment_ids.len() as u64) * (1u64 << manifest.eff_log)
            && manifest.segment_lengths.iter().all(|length| {
                snapshot_segment_len_valid(manifest.eff_log, *length as usize, manifest.tip_height)
            });
    }
    manifest
        .segment_lengths
        .iter()
        .try_fold(0u64, |total, encoded_len| {
            let live = encoded_segment_live_count_from_len(
                manifest.eff_log,
                usize::try_from(*encoded_len).ok()?,
            )?;
            (live > 0)
                .then_some(())
                .and_then(|()| total.checked_add(u64::from(live)))
        })
        == Some(manifest.active_slot_count)
}

fn encode_snapshot_manifest_page(
    page_index: u16,
    segment_ids: &[u16],
    segment_roots: &[[u8; 32]],
    segment_lengths: &[u32],
) -> Option<Vec<u8>> {
    if segment_ids.is_empty()
        || segment_ids.len() > SNAPSHOT_MANIFEST_DESCRIPTORS_PER_PAGE
        || segment_ids.len() != segment_roots.len()
        || segment_ids.len() != segment_lengths.len()
    {
        return None;
    }
    let count = u16::try_from(segment_ids.len()).ok()?;
    let mut encoded = Vec::with_capacity(
        SNAPSHOT_MANIFEST_PAGE_HEADER_BYTES
            + segment_ids.len() * SNAPSHOT_MANIFEST_DESCRIPTOR_BYTES,
    );
    encoded.extend_from_slice(&SNAPSHOT_MANIFEST_PAGE_MAGIC);
    encoded.extend_from_slice(&page_index.to_le_bytes());
    encoded.extend_from_slice(&count.to_le_bytes());
    for ((segment_id, segment_root), encoded_len) in
        segment_ids.iter().zip(segment_roots).zip(segment_lengths)
    {
        encoded.extend_from_slice(&segment_id.to_le_bytes());
        encoded.extend_from_slice(segment_root);
        encoded.extend_from_slice(&encoded_len.to_le_bytes());
    }
    Some(encoded)
}

pub fn decode_snapshot_manifest_page(
    expected: SnapshotManifestPageRef,
    encoded: &[u8],
) -> Option<Vec<(u16, [u8; 32], u32)>> {
    if usize::try_from(expected.encoded_len).ok() != Some(encoded.len())
        || poseidon2b_hash_bytes(SNAPSHOT_MANIFEST_PAGE_DIGEST_DOMAIN, encoded)
            != expected.byte_digest
        || encoded.len() < SNAPSHOT_MANIFEST_PAGE_HEADER_BYTES
        || encoded[..4] != SNAPSHOT_MANIFEST_PAGE_MAGIC
        || u16::from_le_bytes(encoded[4..6].try_into().ok()?) != expected.page_index
        || u16::from_le_bytes(encoded[6..8].try_into().ok()?) != expected.descriptor_count
    {
        return None;
    }
    let count = usize::from(expected.descriptor_count);
    if count == 0
        || encoded.len()
            != SNAPSHOT_MANIFEST_PAGE_HEADER_BYTES + count * SNAPSHOT_MANIFEST_DESCRIPTOR_BYTES
    {
        return None;
    }
    let mut descriptors = Vec::with_capacity(count);
    for descriptor in encoded[SNAPSHOT_MANIFEST_PAGE_HEADER_BYTES..]
        .chunks_exact(SNAPSHOT_MANIFEST_DESCRIPTOR_BYTES)
    {
        descriptors.push((
            u16::from_le_bytes(descriptor[..2].try_into().ok()?),
            descriptor[2..34].try_into().ok()?,
            u32::from_le_bytes(descriptor[34..38].try_into().ok()?),
        ));
    }
    Some(descriptors)
}

// ---------------------------------------------------------------------------
// State sync — single segment (step 2)
// ---------------------------------------------------------------------------

/// Request one state segment by ID.
///
/// Segment data is bound to the exact manifest snapshot boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStateSegmentRequest {
    pub segment_id: u16,
    /// Protocols 6 and 7 can carry a bounded ascending set of small segments.
    /// Protocol 5 sends only the first segment, preserving its original bytes.
    pub additional_segments: Vec<u16>,
    /// Expected snapshot height from the manifest (for staleness guard).
    pub expected_tip_height: u64,
    /// Expected snapshot hash from the manifest. Height alone is not enough across
    /// reorgs or competing blocks at the same height.
    pub expected_tip_hash: [u8; 32],
    /// Exact immutable manifest generation selected by the client.
    pub manifest_digest: [u8; 32],
}

/// Response: one encoded state segment (~3 MB).
///
/// `None` if the peer cannot serve this exact snapshot segment, usually
/// because the requested export expired or the peer never advertised it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStateSegmentResponse {
    pub segment_id: u16,
    pub additional_segments: Vec<StateSegmentPayload>,
    /// Exact snapshot height echoed from the request.
    pub expected_tip_height: u64,
    /// Exact snapshot hash echoed from the request. Together with the segment
    /// ID and libp2p request ID this prevents cross-session response reuse.
    pub expected_tip_hash: [u8; 32],
    /// Echo of the exact immutable manifest generation.
    pub manifest_digest: [u8; 32],
    pub status: DataResponseStatus,
    pub eff_log: u8,
    /// Complete canonical sparse segment and its committed native records.
    /// `None` if the peer cannot serve this segment.
    pub data: Option<Vec<u8>>,
    /// Local transport measurements; never part of canonical state or CBOR.
    #[serde(skip)]
    pub transport: StateSegmentTransport,
    /// Inbound payload admission retained until the node consumes the segment.
    #[serde(skip)]
    pub(crate) inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    /// Process-wide outbound byte admission retained through the codec write.
    #[serde(skip)]
    pub(crate) outbound_memory_permit: Option<crate::outbound_budget::OutboundMemoryPermit>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StateSegmentTransport {
    pub version: u8,
    pub payload_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSegmentPayload {
    pub segment_id: u16,
    pub data: Vec<u8>,
}

pub const MAX_STATE_SEGMENT_BATCH: usize = 64;
pub const MAX_STATE_SEGMENT_BATCH_BYTES: usize = 64 * 1024;

impl GetStateSegmentResponse {
    pub fn payloads(&self) -> impl Iterator<Item = (u16, &[u8])> {
        self.data
            .as_deref()
            .map(|data| (self.segment_id, data))
            .into_iter()
            .chain(
                self.additional_segments
                    .iter()
                    .map(|part| (part.segment_id, part.data.as_slice())),
            )
    }
}

// ---------------------------------------------------------------------------
// Mempool sync — request-response on peer connect
// ---------------------------------------------------------------------------

/// One bounded mempool exchange request.
///
/// `Pull` fills the late-join gap on peer connect. `Push` gives a newly
/// admitted transaction bounded independent first-hop paths; ordinary
/// propagation still uses gossipsub.
#[derive(Debug, Clone)]
pub enum MempoolRequest {
    Pull,
    /// Optional v4 reconciliation. Old peers negotiate v3 and receive the
    /// unchanged empty Pull. IDs are sorted, unique and bounded by pool size.
    PullMissing {
        known_txids: Vec<[u8; 32]>,
        /// Count request metadata in the same process-wide inbound byte
        /// domain until the serving worker has finished using it.
        inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
    Push {
        intent_bytes: Vec<u8>,
        /// Process-wide inbound byte admission retained until node-side
        /// submission has consumed the pushed intent. Local flow-control
        /// state; never serialized.
        inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
}

impl MempoolRequest {
    pub(crate) fn missing(known_txids: Vec<[u8; 32]>) -> Self {
        Self::PullMissing {
            known_txids,
            inbound_memory_permit: None,
        }
    }
}

/// Response: raw TxIntent bytes for every pending transaction.
///
/// The receiver submits each entry to its own mempool; duplicates are silently
/// ignored by the admission pipeline (hash already present → Ok(existing_hash)).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GetMempoolResponse {
    /// Raw `TxIntent` bytes, one per pending transaction.
    /// Empty when the peer's mempool is empty or the node is just starting.
    pub txs: Vec<Vec<u8>>,
    /// Local negotiated transport capability, never trusted peer metadata.
    #[serde(skip)]
    pub(crate) supports_missing: bool,
    /// Process-wide inbound byte admission retained until node-side mempool
    /// submission has consumed every decoded intent. Local flow-control state;
    /// never serialized.
    #[serde(skip)]
    pub(crate) inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    /// Process-wide outbound byte admission retained through the codec write.
    /// Local flow-control state; never serialized.
    #[serde(skip)]
    pub(crate) outbound_memory_permit: Option<crate::outbound_budget::OutboundMemoryPermit>,
}

// ---------------------------------------------------------------------------
// GossipSub topics
// ---------------------------------------------------------------------------

pub struct Topics;

impl Topics {
    pub const BLOCKS: &'static str = "/noid/devnet/blocks/1";
    pub const TXS: &'static str = "/noid/devnet/txs/1";
}

#[derive(Debug, Clone)]
pub struct NetworkTopics {
    pub blocks: String,
    pub txs: String,
    pub protocol_id: String,
}

impl NetworkTopics {
    pub fn for_network_cfg(cfg: &noid_chain::consensus::NetworkConfig) -> Self {
        Self {
            // Network v7 gossips only the fixed header announcement. Large
            // bodies and terminals travel through exact-object pulls.
            blocks: format!("{}/gossip/headers/3", cfg.p2p_protocol_id),
            txs: cfg.topic_txs.to_string(),
            protocol_id: cfg.p2p_protocol_id.to_string(),
        }
    }
}
