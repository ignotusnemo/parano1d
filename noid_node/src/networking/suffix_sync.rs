// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Source-independent exact-object runtime for one immutable live suffix.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use noid_p2p::{
    header_protocol::HeaderInventoryRecord,
    object_protocol::{
        ObjectId, ObjectPayload, MAX_OBJECTS_PER_REQUEST, MAX_OBJECT_RESPONSE_PAYLOAD_BYTES,
    },
};
use thiserror::Error;
use tokio::sync::OwnedSemaphorePermit;

use super::{
    header_dag::ValidatedHeader,
    object_fetcher::{FetchError, FetchState, ObjectFetcher},
    sync_plan::{SyncPlan, SyncPlanError, SyncPlanKind},
    types::{ChainPoint, FailureDomain, ObjectClaimId, PlanId},
};

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone, Debug)]
pub struct SuffixOffer {
    plan: SyncPlan,
    objects: Vec<ObjectId>,
}

impl SuffixOffer {
    pub fn live(
        base: ChainPoint,
        headers: Vec<ValidatedHeader>,
        records: &[HeaderInventoryRecord],
    ) -> Result<Self, SuffixSyncError> {
        Self::new(SyncPlanKind::LiveSuffix, None, base, headers, records)
    }

    pub fn reorg(
        old_tip: ChainPoint,
        ancestor: ChainPoint,
        headers: Vec<ValidatedHeader>,
        records: &[HeaderInventoryRecord],
    ) -> Result<Self, SuffixSyncError> {
        Self::new(
            SyncPlanKind::Reorg,
            Some(old_tip),
            ancestor,
            headers,
            records,
        )
    }

    fn new(
        kind: SyncPlanKind,
        old_tip: Option<ChainPoint>,
        base: ChainPoint,
        headers: Vec<ValidatedHeader>,
        records: &[HeaderInventoryRecord],
    ) -> Result<Self, SuffixSyncError> {
        if records.len() != headers.len() {
            return Err(SuffixSyncError::InventoryLength);
        }
        let mut objects = Vec::with_capacity(headers.len().saturating_add(1));
        for (header, record) in headers.iter().zip(records) {
            if header.header != record.header {
                return Err(SuffixSyncError::InventoryHeaderMismatch);
            }
            if let Some(body) = record.body {
                if body.claim.height != header.header.height || body.claim.block_hash != header.hash
                {
                    return Err(SuffixSyncError::ObjectClaimMismatch);
                }
                objects.push(ObjectId::BlockBody(body));
            }
        }
        let target_header = headers.last().ok_or(SuffixSyncError::EmptySuffix)?;
        let terminal = records
            .last()
            .and_then(|record| record.terminal)
            .ok_or(SuffixSyncError::MissingTipTerminal)?;
        if terminal.claim.height != target_header.header.height
            || terminal.claim.semantic_header_id
                != noid_chain::block_header::semantic_header_id(&target_header.header)
        {
            return Err(SuffixSyncError::ObjectClaimMismatch);
        }
        objects.push(ObjectId::Terminal(terminal));

        let plan = match kind {
            SyncPlanKind::LiveSuffix => {
                SyncPlan::live_suffix(base, headers, terminal.claim.proof_class)?
            }
            SyncPlanKind::Reorg => SyncPlan::reorg(
                old_tip.ok_or(SuffixSyncError::MissingOldTip)?,
                base,
                headers,
                terminal.claim.proof_class,
            )?,
            SyncPlanKind::Snapshot => return Err(SuffixSyncError::WrongPlanKind),
        };
        if objects
            .iter()
            .any(|object| !plan.required_objects().contains(&object.claim()))
        {
            return Err(SuffixSyncError::ObjectClaimMismatch);
        }
        Ok(Self { plan, objects })
    }

    pub const fn plan(&self) -> &SyncPlan {
        &self.plan
    }

    pub fn objects(&self) -> &[ObjectId] {
        &self.objects
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactObjectRequest {
    pub token: u64,
    pub peer: PeerId,
    pub objects: Vec<ObjectId>,
}

#[derive(Debug)]
struct PendingRequest {
    peer: PeerId,
    objects: Vec<ObjectId>,
    disconnected_at: Option<Instant>,
}

const DISCONNECTED_RESPONSE_GRACE: Duration = Duration::from_secs(70);

#[derive(Debug)]
struct ReceivedObject {
    object: ObjectId,
    source: PeerId,
    bytes: Vec<u8>,
    _permit: Option<Arc<OwnedSemaphorePermit>>,
}

/// Fully downloaded suffix. The inbound permits stay alive until the caller
/// finishes verification/commit and drops this value.
#[derive(Debug)]
pub struct FetchedSuffix {
    pub plan: SyncPlan,
    pub body_bytes: Vec<Vec<u8>>,
    pub body_sources: Vec<PeerId>,
    pub terminal_bytes: Vec<u8>,
    pub terminal_source: PeerId,
    _permits: Vec<Arc<OwnedSemaphorePermit>>,
}

impl FetchedSuffix {
    /// Peers that supplied exact objects for the selected tip.
    ///
    /// These identities carry no consensus authority by themselves.  The
    /// node may use them as fresh liveness confirmations only after the
    /// terminal has passed recursive verification and the suffix has
    /// committed exactly at the HeaderDAG-selected tip.  Keeping both the
    /// terminal and target-body source avoids an unnecessary probe delay if
    /// either connection closes while verification runs.
    pub fn tip_confirmation_sources(&self) -> Vec<PeerId> {
        let mut sources = vec![self.terminal_source];
        if let Some(source) = self.body_sources.last().copied() {
            if source != self.terminal_source {
                sources.push(source);
            }
        }
        sources
    }

    pub fn into_parts(
        self,
    ) -> (
        SyncPlan,
        Vec<Vec<u8>>,
        Vec<PeerId>,
        Vec<u8>,
        PeerId,
        Vec<Arc<OwnedSemaphorePermit>>,
    ) {
        (
            self.plan,
            self.body_bytes,
            self.body_sources,
            self.terminal_bytes,
            self.terminal_source,
            self._permits,
        )
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SuffixSyncError {
    #[error("the suffix is empty")]
    EmptySuffix,
    #[error("header inventory length differs from the validated suffix")]
    InventoryLength,
    #[error("header inventory identifies another header")]
    InventoryHeaderMismatch,
    #[error("the selected suffix tip has no exact terminal identity")]
    MissingTipTerminal,
    #[error("an exact object claim differs from the immutable plan")]
    ObjectClaimMismatch,
    #[error("a reorg offer has no old canonical tip")]
    MissingOldTip,
    #[error("snapshot plans do not use the live suffix runtime")]
    WrongPlanKind,
    #[error("the offer belongs to another immutable plan")]
    PlanMismatch,
    #[error("the response token is unknown or stale")]
    UnknownToken,
    #[error("the response peer or exact object vector does not match its request")]
    CorrelationMismatch,
    #[error("the exact object payload failed its content identity")]
    ContentMismatch,
    #[error("the suffix has not received every required object")]
    Incomplete,
    #[error("the exact-object scheduler rejected the transition: {0}")]
    Fetch(#[from] FetchError),
    #[error("the immutable plan is invalid: {0}")]
    Plan(#[from] SyncPlanError),
}

/// Mutable transport state for one immutable semantic suffix plan.
///
/// Peers and byte encodings are source leases. Disconnecting one peer never
/// changes the plan or discards bytes already received for another claim.
pub struct SuffixSync {
    plan: SyncPlan,
    fetcher: ObjectFetcher,
    received: HashMap<ObjectClaimId, ReceivedObject>,
    pending: HashMap<u64, PendingRequest>,
    next_token: u64,
}

impl SuffixSync {
    pub fn from_offer(
        peer: PeerId,
        failure_domain: FailureDomain,
        offer: SuffixOffer,
    ) -> Result<Self, SuffixSyncError> {
        let token_seed = u64::from_le_bytes(offer.plan.id().0[..8].try_into().unwrap()).max(1);
        let mut runtime = Self {
            plan: offer.plan.clone(),
            fetcher: ObjectFetcher::new(),
            received: HashMap::new(),
            pending: HashMap::new(),
            next_token: token_seed,
        };
        for claim in runtime.plan.required_objects() {
            runtime.fetcher.want(*claim);
        }
        runtime.add_offer(peer, failure_domain, offer)?;
        Ok(runtime)
    }

    pub const fn plan(&self) -> &SyncPlan {
        &self.plan
    }

    pub const fn plan_id(&self) -> PlanId {
        self.plan.id()
    }

    pub fn add_offer(
        &mut self,
        peer: PeerId,
        failure_domain: FailureDomain,
        offer: SuffixOffer,
    ) -> Result<usize, SuffixSyncError> {
        if offer.plan.id() != self.plan.id() {
            return Err(SuffixSyncError::PlanMismatch);
        }
        let mut added = 0usize;
        for object in offer.objects {
            if self
                .fetcher
                .advertise_new(object.claim(), peer, failure_domain, object)?
            {
                added = added.saturating_add(1);
            }
        }
        Ok(added)
    }

    /// Merge storage-backed availability for the already selected semantic
    /// suffix. A provider may hold only some bodies or only the tip terminal;
    /// source diversity must not require every object to coexist on one peer.
    pub fn add_inventory(
        &mut self,
        peer: PeerId,
        failure_domain: FailureDomain,
        headers: &[ValidatedHeader],
        records: &[HeaderInventoryRecord],
    ) -> Result<usize, SuffixSyncError> {
        if headers != self.plan.headers() || records.len() != headers.len() {
            return Err(SuffixSyncError::PlanMismatch);
        }
        let mut advertised = 0usize;
        for (header, record) in headers.iter().zip(records) {
            if record.header != header.header {
                return Err(SuffixSyncError::InventoryHeaderMismatch);
            }
            if let Some(body) = record.body {
                if body.claim.height != header.header.height || body.claim.block_hash != header.hash
                {
                    return Err(SuffixSyncError::ObjectClaimMismatch);
                }
                if self.fetcher.advertise_new(
                    ObjectClaimId::BlockBody(body.claim),
                    peer,
                    failure_domain,
                    ObjectId::BlockBody(body),
                )? {
                    advertised = advertised.saturating_add(1);
                }
            }
        }
        if let Some(terminal) = records.last().and_then(|record| record.terminal) {
            let required_terminal = self
                .plan
                .required_objects()
                .last()
                .copied()
                .ok_or(SuffixSyncError::MissingTipTerminal)?;
            if required_terminal != ObjectClaimId::Terminal(terminal.claim) {
                return Err(SuffixSyncError::ObjectClaimMismatch);
            }
            if self.fetcher.advertise_new(
                required_terminal,
                peer,
                failure_domain,
                ObjectId::Terminal(terminal),
            )? {
                advertised = advertised.saturating_add(1);
            }
        }
        Ok(advertised)
    }

    /// Start all currently schedulable jobs and coalesce body requests by
    /// source. A terminal always occupies its own bounded request.
    pub fn schedule(&mut self, now_ms: u64) -> Vec<ExactObjectRequest> {
        self.expire_disconnected_requests();
        let mut assignments = Vec::new();
        for claim in self.plan.required_objects() {
            if self.fetcher.state(*claim) != Some(FetchState::Wanted) {
                continue;
            }
            if let Ok(assignment) = self.fetcher.start_primary(*claim, now_ms) {
                assignments.push(assignment);
            }
        }

        let mut body_groups: Vec<(PeerId, Vec<ObjectId>, usize)> = Vec::new();
        let mut requests = Vec::new();
        for assignment in assignments {
            if matches!(assignment.object, ObjectId::Terminal(_)) {
                requests.push(self.allocate_request(assignment.peer, vec![assignment.object]));
                continue;
            }
            let encoded_len = assignment.object.encoded_len().unwrap_or(0) as usize;
            if let Some((_, objects, bytes)) =
                body_groups.iter_mut().find(|(peer, objects, bytes)| {
                    *peer == assignment.peer
                        && objects.len() < MAX_OBJECTS_PER_REQUEST
                        && bytes.saturating_add(encoded_len) <= MAX_OBJECT_RESPONSE_PAYLOAD_BYTES
                })
            {
                objects.push(assignment.object);
                *bytes += encoded_len;
            } else {
                body_groups.push((assignment.peer, vec![assignment.object], encoded_len));
            }
        }
        requests.extend(
            body_groups
                .into_iter()
                .map(|(peer, objects, _)| self.allocate_request(peer, objects)),
        );
        requests
    }

    fn allocate_request(&mut self, peer: PeerId, objects: Vec<ObjectId>) -> ExactObjectRequest {
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1).max(1);
        let previous = self.pending.insert(
            token,
            PendingRequest {
                peer,
                objects: objects.clone(),
                disconnected_at: None,
            },
        );
        debug_assert!(previous.is_none());
        ExactObjectRequest {
            token,
            peer,
            objects,
        }
    }

    pub fn accept_response(
        &mut self,
        token: u64,
        peer: PeerId,
        payloads: Vec<ObjectPayload>,
        permit: Option<Arc<OwnedSemaphorePermit>>,
    ) -> Result<usize, SuffixSyncError> {
        let pending = self
            .pending
            .remove(&token)
            .ok_or(SuffixSyncError::UnknownToken)?;
        let response_objects = payloads
            .iter()
            .map(|payload| payload.object)
            .collect::<Vec<_>>();
        if pending.peer != peer || pending.objects != response_objects {
            for object in pending.objects {
                let _ =
                    self.fetcher
                        .fail_source_at(object.claim(), pending.peer, current_time_ms());
            }
            return Err(SuffixSyncError::CorrelationMismatch);
        }

        // Validate the complete response before advancing any object. One bad
        // member of a coalesced body response must rotate the whole source
        // lease, not leave the remaining claims stuck in Receiving after the
        // correlation token has been consumed.
        if payloads.iter().any(|payload| {
            payload
                .bytes
                .as_ref()
                .is_some_and(|bytes| !payload.object.matches_bytes(bytes))
        }) {
            self.fetcher.quarantine_source(peer);
            return Err(SuffixSyncError::ContentMismatch);
        }

        let mut received = 0usize;
        for payload in payloads {
            let claim = payload.object.claim();
            let Some(bytes) = payload.bytes else {
                self.fetcher.mark_unavailable(claim, peer)?;
                continue;
            };
            self.fetcher.finish_receive(claim, peer, payload.object)?;
            self.fetcher.mark_verified(claim, payload.object)?;
            self.received.insert(
                claim,
                ReceivedObject {
                    object: payload.object,
                    source: peer,
                    bytes,
                    _permit: permit.clone(),
                },
            );
            received = received.saturating_add(1);
        }
        Ok(received)
    }

    /// Reject a provider across this immutable suffix after a response proves
    /// that its exact-object service is malformed. Headers from that peer may
    /// still be useful; only its object advertisements lose transport trust.
    pub fn quarantine_provider(&mut self, peer: PeerId) {
        self.fetcher.quarantine_source(peer);
    }

    pub fn request_unavailable(
        &mut self,
        token: u64,
        peer: PeerId,
        objects: &[ObjectId],
    ) -> Result<(), SuffixSyncError> {
        let pending = self
            .pending
            .remove(&token)
            .ok_or(SuffixSyncError::UnknownToken)?;
        if pending.peer != peer || pending.objects != objects {
            for object in pending.objects {
                let _ =
                    self.fetcher
                        .fail_source_at(object.claim(), pending.peer, current_time_ms());
            }
            return Err(SuffixSyncError::CorrelationMismatch);
        }
        for object in pending.objects {
            self.fetcher.mark_unavailable(object.claim(), peer)?;
        }
        Ok(())
    }

    pub fn reject_response_provider(
        &mut self,
        token: u64,
        peer: PeerId,
        objects: &[ObjectId],
    ) -> Result<(), SuffixSyncError> {
        let pending = self
            .pending
            .remove(&token)
            .ok_or(SuffixSyncError::UnknownToken)?;
        if pending.peer != peer || pending.objects != objects {
            for object in pending.objects {
                let _ =
                    self.fetcher
                        .fail_source_at(object.claim(), pending.peer, current_time_ms());
            }
            return Err(SuffixSyncError::CorrelationMismatch);
        }
        self.fetcher.quarantine_source(peer);
        Ok(())
    }

    pub fn request_failed(
        &mut self,
        token: u64,
        peer: PeerId,
        objects: &[ObjectId],
        now_ms: u64,
    ) -> Result<(), SuffixSyncError> {
        let pending = self
            .pending
            .remove(&token)
            .ok_or(SuffixSyncError::UnknownToken)?;
        if pending.peer != peer || pending.objects != objects {
            for object in pending.objects {
                let _ = self
                    .fetcher
                    .fail_source_at(object.claim(), pending.peer, now_ms);
            }
            return Err(SuffixSyncError::CorrelationMismatch);
        }
        for object in pending.objects {
            self.fetcher.fail_source_at(object.claim(), peer, now_ms)?;
        }
        Ok(())
    }

    /// The serving peer is healthy and still advertises these exact objects,
    /// but its bounded data plane is temporarily full. Preserve the immutable
    /// selection and every verified object while delaying only this source.
    pub fn request_busy(
        &mut self,
        token: u64,
        peer: PeerId,
        objects: &[ObjectId],
        retry_at_ms: u64,
    ) -> Result<(), SuffixSyncError> {
        let pending = self
            .pending
            .remove(&token)
            .ok_or(SuffixSyncError::UnknownToken)?;
        if pending.peer != peer || pending.objects != objects {
            for object in pending.objects {
                let _ =
                    self.fetcher
                        .fail_source_at(object.claim(), pending.peer, current_time_ms());
            }
            return Err(SuffixSyncError::CorrelationMismatch);
        }
        for object in pending.objects {
            self.fetcher
                .busy_source(object.claim(), peer, retry_at_ms)?;
        }
        Ok(())
    }

    /// True when this immutable suffix still has missing objects but no
    /// eligible source, request, locally received bytes, or late correlated
    /// response. The caller may then perform bounded provider discovery and,
    /// only after that fails, retire this transport plan without touching the
    /// HeaderDAG or canonical database.
    pub fn unfinished_transport_is_stalled(&self, now_ms: u64) -> bool {
        self.fetcher.unfinished_transport_is_stalled(now_ms)
    }

    pub fn unfinished_transport_is_extinct(&self) -> bool {
        self.fetcher.unfinished_transport_is_extinct()
    }

    /// Undo a request that never left the local process because the bounded
    /// data lane was full. Unlike `request_failed`, this does not increment a
    /// source failure or rotate away from a healthy provider.
    pub fn defer_request(
        &mut self,
        token: u64,
        peer: PeerId,
        objects: &[ObjectId],
    ) -> Result<(), SuffixSyncError> {
        let pending = self
            .pending
            .remove(&token)
            .ok_or(SuffixSyncError::UnknownToken)?;
        if pending.peer != peer || pending.objects != objects {
            for object in pending.objects {
                let _ =
                    self.fetcher
                        .fail_source_at(object.claim(), pending.peer, current_time_ms());
            }
            return Err(SuffixSyncError::CorrelationMismatch);
        }
        for object in pending.objects {
            self.fetcher.defer_source(object.claim(), peer)?;
        }
        Ok(())
    }

    pub fn disconnect(&mut self, peer: PeerId) {
        let now = Instant::now();
        for pending in self.pending.values_mut() {
            if pending.peer == peer {
                pending.disconnected_at.get_or_insert(now);
            }
        }
        self.fetcher.disconnect(peer);
    }

    fn expire_disconnected_requests(&mut self) {
        let now = Instant::now();
        let expired = self
            .pending
            .iter()
            .filter_map(|(token, pending)| {
                pending
                    .disconnected_at
                    .is_some_and(|at| now.duration_since(at) >= DISCONNECTED_RESPONSE_GRACE)
                    .then_some(*token)
            })
            .collect::<Vec<_>>();
        for token in expired {
            if let Some(pending) = self.pending.remove(&token) {
                for object in pending.objects {
                    self.fetcher
                        .forget_late_response(object.claim(), pending.peer, object);
                }
            }
        }
    }

    pub fn is_complete(&self) -> bool {
        self.plan.required_objects().iter().all(|claim| {
            matches!(
                self.fetcher.state(*claim),
                Some(FetchState::Verified { .. })
            ) && self.received.contains_key(claim)
        })
    }

    pub fn into_fetched(mut self) -> Result<FetchedSuffix, SuffixSyncError> {
        if !self.is_complete() {
            return Err(SuffixSyncError::Incomplete);
        }
        let mut body_bytes = Vec::with_capacity(self.plan.headers().len());
        let mut body_sources = Vec::with_capacity(self.plan.headers().len());
        let mut terminal_bytes = None;
        let mut terminal_source = None;
        let mut permits = Vec::new();
        for claim in self.plan.required_objects() {
            let received = self
                .received
                .remove(claim)
                .ok_or(SuffixSyncError::Incomplete)?;
            if received.object.claim() != *claim {
                return Err(SuffixSyncError::ObjectClaimMismatch);
            }
            if let Some(permit) = received._permit {
                permits.push(permit);
            }
            match received.object {
                ObjectId::BlockBody(_) => {
                    body_bytes.push(received.bytes);
                    body_sources.push(received.source);
                }
                ObjectId::Terminal(_) => {
                    terminal_bytes = Some(received.bytes);
                    terminal_source = Some(received.source);
                }
                ObjectId::SnapshotManifest(_) | ObjectId::StateSegment(_) => {
                    return Err(SuffixSyncError::WrongPlanKind)
                }
            }
        }
        Ok(FetchedSuffix {
            plan: self.plan,
            body_bytes,
            body_sources,
            terminal_bytes: terminal_bytes.ok_or(SuffixSyncError::MissingTipTerminal)?,
            terminal_source: terminal_source.ok_or(SuffixSyncError::MissingTipTerminal)?,
            _permits: permits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::{
        block_header::{block_id, semantic_header_id, BlockHeader},
        consensus::genesis_header,
    };
    use noid_p2p::object_protocol::{
        BlockBodyClaimId, BlockBodyObjectId, TerminalClaimId, TerminalObjectId,
    };

    fn child(parent: BlockHeader, marker: u8) -> ValidatedHeader {
        let mut header = parent;
        header.height += 1;
        header.prev_block_hash = block_id(&parent);
        header.timestamp += 1;
        header.nonce = marker.into();
        ValidatedHeader::new_after_consensus_checks(header, [marker; 32])
    }

    fn offer(markers: &[u8], body_digest_delta: u8) -> SuffixOffer {
        let genesis = genesis_header();
        let base = ChainPoint::new(0, block_id(&genesis));
        let mut parent = genesis;
        let mut headers = Vec::new();
        let mut records = Vec::new();
        for marker in markers {
            let validated = child(parent, *marker);
            parent = validated.header;
            let body = BlockBodyObjectId {
                claim: BlockBodyClaimId {
                    height: validated.header.height,
                    block_hash: validated.hash,
                },
                byte_digest: [marker.wrapping_add(body_digest_delta); 32],
                encoded_len: 8,
            };
            records.push(HeaderInventoryRecord {
                header: validated.header,
                body: Some(body),
                terminal: None,
            });
            headers.push(validated);
        }
        let tip = headers.last().unwrap();
        records.last_mut().unwrap().terminal = Some(TerminalObjectId {
            claim: TerminalClaimId {
                height: tip.header.height,
                semantic_header_id: semantic_header_id(&tip.header),
                proof_class: 0,
            },
            byte_digest: [0xEE; 32],
            encoded_len: 16,
        });
        SuffixOffer::live(base, headers, &records).unwrap()
    }

    fn payload(object: ObjectId) -> ObjectPayload {
        // Tests below exercise state transitions rather than the production
        // Poseidon digest, so synthesize unavailable replies unless exact
        // bytes are explicitly built by the test.
        ObjectPayload {
            object,
            bytes: None,
        }
    }

    #[test]
    fn offer_accepts_partial_bodies_but_requires_one_tip_terminal() {
        let valid = offer(&[1, 2], 1);
        assert_eq!(valid.plan().required_objects().len(), 3);

        let mut records = valid
            .plan()
            .headers()
            .iter()
            .map(|header| HeaderInventoryRecord::header_only(header.header))
            .collect::<Vec<_>>();
        records[0].body = valid.objects()[0].into_block_body();
        records[1].terminal = match valid.objects().last().copied().unwrap() {
            ObjectId::Terminal(terminal) => Some(terminal),
            _ => panic!("suffix offer must end in a terminal"),
        };
        let partial = SuffixOffer::live(
            valid.plan().base(),
            valid.plan().headers().to_vec(),
            &records,
        )
        .unwrap();
        assert_eq!(partial.objects().len(), 2);

        records[1].terminal = None;
        assert_eq!(
            SuffixOffer::live(
                valid.plan().base(),
                valid.plan().headers().to_vec(),
                &records,
            )
            .unwrap_err(),
            SuffixSyncError::MissingTipTerminal
        );
    }

    #[test]
    fn failed_source_rotates_without_losing_other_object_progress() {
        let first_peer = PeerId::random();
        let second_peer = PeerId::random();
        let first_offer = offer(&[1, 2], 1);
        let second_offer = first_offer.clone();
        let first_claim = first_offer.objects()[0].claim();
        let second_claim = first_offer.objects()[1].claim();
        let mut sync = SuffixSync::from_offer(first_peer, FailureDomain(1), first_offer).unwrap();
        sync.add_offer(second_peer, FailureDomain(2), second_offer)
            .unwrap();
        let requests = sync.schedule(0);
        let body_request = requests
            .iter()
            .find(|request| {
                request
                    .objects
                    .iter()
                    .any(|object| object.claim() == first_claim)
            })
            .unwrap()
            .clone();
        sync.request_failed(
            body_request.token,
            body_request.peer,
            &body_request.objects,
            0,
        )
        .unwrap();
        let retried = sync.schedule(1);
        assert!(retried.iter().any(|request| {
            request.peer != body_request.peer
                && request
                    .objects
                    .iter()
                    .any(|object| object.claim() == first_claim)
        }));
        assert_ne!(sync.fetcher.state(second_claim), None);
    }

    #[test]
    fn unavailable_encoding_can_move_to_another_exact_encoding() {
        let first_peer = PeerId::random();
        let second_peer = PeerId::random();
        let first_offer = offer(&[1], 1);
        let second_offer = offer(&[1], 9);
        assert_eq!(first_offer.plan().id(), second_offer.plan().id());
        let claim = first_offer.objects()[0].claim();
        let mut sync = SuffixSync::from_offer(first_peer, FailureDomain(1), first_offer).unwrap();
        sync.add_offer(second_peer, FailureDomain(2), second_offer)
            .unwrap();
        let request = sync
            .schedule(0)
            .into_iter()
            .find(|request| request.objects.iter().any(|object| object.claim() == claim))
            .unwrap();
        let unavailable = request.objects.iter().copied().map(payload).collect();
        sync.accept_response(request.token, request.peer, unavailable, None)
            .unwrap();
        let replacement = sync
            .schedule(1)
            .into_iter()
            .find(|request| request.objects.iter().any(|object| object.claim() == claim))
            .unwrap();
        assert_ne!(replacement.peer, request.peer);
        assert_ne!(replacement.objects[0], request.objects[0]);
    }

    #[test]
    fn body_only_inventory_can_join_an_existing_terminal_plan() {
        let first_peer = PeerId::random();
        let second_peer = PeerId::random();
        let offer = offer(&[1, 2], 1);
        let headers = offer.plan().headers().to_vec();
        let mut records = headers
            .iter()
            .map(|header| HeaderInventoryRecord::header_only(header.header))
            .collect::<Vec<_>>();
        for (record, object) in records.iter_mut().zip(&offer.objects[..headers.len()]) {
            record.body = (*object).into_block_body();
        }
        let first_body = offer.objects[0];
        let mut sync = SuffixSync::from_offer(first_peer, FailureDomain(1), offer).unwrap();
        assert_eq!(
            sync.add_inventory(second_peer, FailureDomain(2), &headers, &records)
                .unwrap(),
            headers.len()
        );
        let request = sync
            .schedule(0)
            .into_iter()
            .find(|request| request.objects.contains(&first_body))
            .unwrap();
        let expected_retry_peer = if request.peer == first_peer {
            second_peer
        } else {
            first_peer
        };
        sync.request_failed(request.token, request.peer, &request.objects, 0)
            .unwrap();
        assert!(sync.schedule(1).iter().any(|retry| {
            retry.peer == expected_retry_peer && retry.objects.contains(&first_body)
        }));
    }

    #[test]
    fn local_data_queue_backpressure_returns_every_object_to_wanted() {
        let peer = PeerId::random();
        let offer = offer(&[1, 2], 1);
        let mut sync = SuffixSync::from_offer(peer, FailureDomain(1), offer).unwrap();
        let requests = sync.schedule(0);
        assert!(!requests.is_empty());
        for request in &requests {
            sync.defer_request(request.token, request.peer, &request.objects)
                .unwrap();
        }
        let counts = sync.fetcher.counts();
        assert_eq!(counts.in_flight, 0);
        assert_eq!(counts.wanted, sync.plan.required_objects().len());
        assert_eq!(sync.schedule(1).len(), requests.len());
    }

    #[test]
    fn remote_busy_preserves_exact_objects_and_delays_the_source() {
        let peer = PeerId::random();
        let offer = offer(&[1], 1);
        let mut sync = SuffixSync::from_offer(peer, FailureDomain(1), offer).unwrap();
        let request = sync.schedule(10).pop().unwrap();
        sync.request_busy(request.token, peer, &request.objects, 100)
            .unwrap();
        assert!(sync.schedule(99).is_empty());
        let retry = sync.schedule(100).pop().unwrap();
        assert_eq!(retry.peer, peer);
        assert_eq!(retry.objects, request.objects);
    }

    #[test]
    fn complete_exact_responses_preserve_body_order_and_tip_terminal() {
        let peer = PeerId::random();
        let mut offer = offer(&[1, 2], 1);
        let mut expected = HashMap::new();
        for (index, object) in offer.objects.iter_mut().enumerate() {
            let bytes = vec![0x40 + index as u8; 11 + index];
            *object = match *object {
                ObjectId::BlockBody(body) => {
                    ObjectId::BlockBody(BlockBodyObjectId::from_bytes(body.claim, &bytes).unwrap())
                }
                ObjectId::Terminal(terminal) => ObjectId::Terminal(
                    TerminalObjectId::from_bytes(terminal.claim, &bytes).unwrap(),
                ),
                _ => unreachable!(),
            };
            expected.insert(*object, bytes);
        }
        let expected_bodies = offer.objects[..2]
            .iter()
            .map(|object| expected[object].clone())
            .collect::<Vec<_>>();
        let expected_terminal = expected[offer.objects.last().unwrap()].clone();
        let mut sync = SuffixSync::from_offer(peer, FailureDomain(1), offer).unwrap();
        for request in sync.schedule(0) {
            let payloads = request
                .objects
                .iter()
                .map(|object| ObjectPayload {
                    object: *object,
                    bytes: Some(expected[object].clone()),
                })
                .collect();
            sync.accept_response(request.token, request.peer, payloads, None)
                .unwrap();
        }
        assert!(sync.is_complete());
        let fetched = sync.into_fetched().unwrap();
        assert_eq!(fetched.body_bytes, expected_bodies);
        assert_eq!(fetched.body_sources, vec![peer, peer]);
        assert_eq!(fetched.terminal_bytes, expected_terminal);
        assert_eq!(fetched.terminal_source, peer);
    }

    #[test]
    fn fetched_suffix_preserves_independent_body_and_terminal_sources() {
        let body_peer = PeerId::random();
        let terminal_peer = PeerId::random();
        let mut complete = offer(&[1, 2], 1);
        let mut bytes_by_object = HashMap::new();
        for (index, object) in complete.objects.iter_mut().enumerate() {
            let bytes = vec![0x50 + index as u8; 12 + index];
            *object = match *object {
                ObjectId::BlockBody(body) => {
                    ObjectId::BlockBody(BlockBodyObjectId::from_bytes(body.claim, &bytes).unwrap())
                }
                ObjectId::Terminal(terminal) => ObjectId::Terminal(
                    TerminalObjectId::from_bytes(terminal.claim, &bytes).unwrap(),
                ),
                _ => unreachable!(),
            };
            bytes_by_object.insert(*object, bytes);
        }

        let headers = complete.plan().headers().to_vec();
        let mut terminal_records = headers
            .iter()
            .map(|header| HeaderInventoryRecord::header_only(header.header))
            .collect::<Vec<_>>();
        terminal_records.last_mut().unwrap().terminal =
            complete.objects.last().copied().unwrap().into_terminal();
        let terminal_offer =
            SuffixOffer::live(complete.plan().base(), headers.clone(), &terminal_records).unwrap();

        let mut body_records = headers
            .iter()
            .map(|header| HeaderInventoryRecord::header_only(header.header))
            .collect::<Vec<_>>();
        for (record, object) in body_records
            .iter_mut()
            .zip(&complete.objects[..headers.len()])
        {
            record.body = (*object).into_block_body();
        }

        let mut sync =
            SuffixSync::from_offer(terminal_peer, FailureDomain(1), terminal_offer).unwrap();
        sync.add_inventory(body_peer, FailureDomain(2), &headers, &body_records)
            .unwrap();
        for request in sync.schedule(0) {
            let payloads = request
                .objects
                .iter()
                .map(|object| ObjectPayload {
                    object: *object,
                    bytes: Some(bytes_by_object[object].clone()),
                })
                .collect();
            sync.accept_response(request.token, request.peer, payloads, None)
                .unwrap();
        }

        let fetched = sync.into_fetched().unwrap();
        assert_eq!(fetched.body_sources, vec![body_peer, body_peer]);
        assert_eq!(fetched.terminal_source, terminal_peer);
    }

    #[test]
    fn queued_exact_response_survives_disconnect_event_overtake() {
        let first_peer = PeerId::random();
        let second_peer = PeerId::random();
        let mut offer = offer(&[1, 2], 1);
        let mut bytes_by_object = HashMap::new();
        for (index, object) in offer.objects.iter_mut().enumerate() {
            let bytes = vec![0x60 + index as u8; 12 + index];
            *object = match *object {
                ObjectId::BlockBody(body) => {
                    ObjectId::BlockBody(BlockBodyObjectId::from_bytes(body.claim, &bytes).unwrap())
                }
                ObjectId::Terminal(terminal) => ObjectId::Terminal(
                    TerminalObjectId::from_bytes(terminal.claim, &bytes).unwrap(),
                ),
                _ => unreachable!(),
            };
            bytes_by_object.insert(*object, bytes);
        }
        let second_offer = offer.clone();
        let mut sync = SuffixSync::from_offer(first_peer, FailureDomain(1), offer).unwrap();
        sync.add_offer(second_peer, FailureDomain(2), second_offer)
            .unwrap();
        let queued = sync.schedule(0).pop().unwrap();
        let disconnected = queued.peer;
        let payloads = queued
            .objects
            .iter()
            .map(|object| ObjectPayload {
                object: *object,
                bytes: Some(bytes_by_object[object].clone()),
            })
            .collect::<Vec<_>>();

        sync.disconnect(disconnected);
        let retry = sync
            .schedule(1)
            .into_iter()
            .find(|request| {
                request.peer != disconnected
                    && request
                        .objects
                        .iter()
                        .any(|object| queued.objects.contains(object))
            })
            .expect("failover begins without invalidating the queued old response");
        assert_ne!(retry.peer, disconnected);

        sync.accept_response(queued.token, disconnected, payloads, None)
            .unwrap();
        for object in queued.objects {
            assert!(matches!(
                sync.fetcher.state(object.claim()),
                Some(FetchState::Verified { object: verified }) if verified == object
            ));
        }
    }

    #[test]
    fn one_bad_batched_body_rotates_every_claim_in_the_consumed_request() {
        let first_peer = PeerId::random();
        let second_peer = PeerId::random();
        let mut offer = offer(&[1, 2], 1);
        let mut bytes_by_object = HashMap::new();
        for (index, object) in offer.objects.iter_mut().enumerate() {
            let bytes = vec![0x70 + index as u8; 13 + index];
            *object = match *object {
                ObjectId::BlockBody(body) => {
                    ObjectId::BlockBody(BlockBodyObjectId::from_bytes(body.claim, &bytes).unwrap())
                }
                ObjectId::Terminal(terminal) => ObjectId::Terminal(
                    TerminalObjectId::from_bytes(terminal.claim, &bytes).unwrap(),
                ),
                _ => unreachable!(),
            };
            bytes_by_object.insert(*object, bytes);
        }
        let second_offer = offer.clone();
        let mut sync = SuffixSync::from_offer(first_peer, FailureDomain(1), offer).unwrap();
        sync.add_offer(second_peer, FailureDomain(2), second_offer)
            .unwrap();

        let request = sync
            .schedule(0)
            .into_iter()
            .find(|request| request.objects.len() == 2)
            .expect("two body claims are coalesced");
        let mut payloads = request
            .objects
            .iter()
            .map(|object| ObjectPayload {
                object: *object,
                bytes: Some(bytes_by_object[object].clone()),
            })
            .collect::<Vec<_>>();
        payloads[1].bytes.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            sync.accept_response(request.token, request.peer, payloads, None),
            Err(SuffixSyncError::ContentMismatch)
        );

        let replacements = sync.schedule(1);
        assert!(
            replacements
                .iter()
                .all(|candidate| candidate.peer != request.peer),
            "a content-invalid provider is quarantined across the whole suffix"
        );
        let replacement = replacements
            .into_iter()
            .find(|candidate| candidate.objects.len() == 2)
            .expect("every claim from the consumed request is schedulable again");
        assert_eq!(replacement.objects, request.objects);
    }

    trait ObjectIdTestExt {
        fn into_block_body(self) -> Option<BlockBodyObjectId>;
        fn into_terminal(self) -> Option<TerminalObjectId>;
    }

    impl ObjectIdTestExt for ObjectId {
        fn into_block_body(self) -> Option<BlockBodyObjectId> {
            match self {
                ObjectId::BlockBody(body) => Some(body),
                _ => None,
            }
        }

        fn into_terminal(self) -> Option<TerminalObjectId> {
            match self {
                ObjectId::Terminal(terminal) => Some(terminal),
                _ => None,
            }
        }
    }
}
