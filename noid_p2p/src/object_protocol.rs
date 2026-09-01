// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Source-independent identities for objects transferred by network v2.

use noid_poseidon2b::native::poseidon2b_hash_bytes;
use serde::{Deserialize, Serialize};

pub type Hash32 = [u8; 32];

pub const MAX_OBJECTS_PER_REQUEST: usize = 8;
pub const MAX_OBJECT_RESPONSE_PAYLOAD_BYTES: usize =
    noid_chain::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES;

/// Canonical response state for bounded bulk-serving protocols. `Busy` is
/// deliberately distinct from `Unavailable`: it preserves the provider's
/// exact object advertisement and asks the requester to retry later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataResponseStatus {
    Ready,
    Busy { retry_after_ms: u16 },
}

pub const MIN_BUSY_RETRY_MS: u16 = 100;
pub const MAX_BUSY_RETRY_MS: u16 = 10_000;

impl DataResponseStatus {
    pub const fn busy_retry_after_ms(self) -> Option<u16> {
        match self {
            Self::Ready => None,
            Self::Busy { retry_after_ms } => Some(retry_after_ms),
        }
    }

    pub const fn is_canonical(self) -> bool {
        match self {
            Self::Ready => true,
            Self::Busy { retry_after_ms } => {
                retry_after_ms >= MIN_BUSY_RETRY_MS && retry_after_ms <= MAX_BUSY_RETRY_MS
            }
        }
    }
}

const BODY_DIGEST_DOMAIN: &[u8] = b"NOID/P2P/OBJECT/BLOCK-BODY/V2";
const TERMINAL_DIGEST_DOMAIN: &[u8] = b"NOID/P2P/OBJECT/HISTORY-TERMINAL/V2";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"NOID/P2P/OBJECT/SNAPSHOT-MANIFEST/V2";
const SEGMENT_DIGEST_DOMAIN: &[u8] = b"NOID/P2P/OBJECT/STATE-SEGMENT/V2";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainPoint {
    pub height: u64,
    pub hash: Hash32,
}

impl ChainPoint {
    pub const fn new(height: u64, hash: Hash32) -> Self {
        Self { height, hash }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockBodyClaimId {
    pub height: u64,
    pub block_hash: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockBodyObjectId {
    pub claim: BlockBodyClaimId,
    pub byte_digest: Hash32,
    pub encoded_len: u32,
}

impl BlockBodyObjectId {
    pub fn from_bytes(claim: BlockBodyClaimId, bytes: &[u8]) -> Option<Self> {
        Some(Self {
            claim,
            byte_digest: poseidon2b_hash_bytes(BODY_DIGEST_DOMAIN, bytes),
            encoded_len: u32::try_from(bytes.len()).ok()?,
        })
    }

    pub fn matches_bytes(self, bytes: &[u8]) -> bool {
        usize::try_from(self.encoded_len).ok() == Some(bytes.len())
            && self.byte_digest == poseidon2b_hash_bytes(BODY_DIGEST_DOMAIN, bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TerminalClaimId {
    pub height: u64,
    pub semantic_header_id: Hash32,
    pub proof_class: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TerminalObjectId {
    pub claim: TerminalClaimId,
    pub byte_digest: Hash32,
    pub encoded_len: u32,
}

impl TerminalObjectId {
    pub fn from_bytes(claim: TerminalClaimId, bytes: &[u8]) -> Option<Self> {
        Some(Self {
            claim,
            byte_digest: poseidon2b_hash_bytes(TERMINAL_DIGEST_DOMAIN, bytes),
            encoded_len: u32::try_from(bytes.len()).ok()?,
        })
    }

    pub fn matches_bytes(self, bytes: &[u8]) -> bool {
        usize::try_from(self.encoded_len).ok() == Some(bytes.len())
            && self.byte_digest == poseidon2b_hash_bytes(TERMINAL_DIGEST_DOMAIN, bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotId {
    pub boundary: ChainPoint,
    pub state_root: Hash32,
    pub manifest_digest: Hash32,
    pub format_version: u32,
}

impl SnapshotId {
    pub fn manifest_digest(bytes: &[u8]) -> Hash32 {
        poseidon2b_hash_bytes(MANIFEST_DIGEST_DOMAIN, bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateSegmentId {
    pub snapshot: SnapshotId,
    pub segment_id: u16,
    pub segment_root: Hash32,
    pub encoded_len: u32,
}

impl StateSegmentId {
    pub fn byte_digest(bytes: &[u8]) -> Hash32 {
        poseidon2b_hash_bytes(SEGMENT_DIGEST_DOMAIN, bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObjectClaimId {
    BlockBody(BlockBodyClaimId),
    Terminal(TerminalClaimId),
    SnapshotManifest(SnapshotId),
    StateSegment(StateSegmentId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObjectId {
    BlockBody(BlockBodyObjectId),
    Terminal(TerminalObjectId),
    SnapshotManifest(SnapshotId),
    StateSegment(StateSegmentId),
}

impl ObjectId {
    pub const fn claim(self) -> ObjectClaimId {
        match self {
            Self::BlockBody(object) => ObjectClaimId::BlockBody(object.claim),
            Self::Terminal(object) => ObjectClaimId::Terminal(object.claim),
            Self::SnapshotManifest(snapshot) => ObjectClaimId::SnapshotManifest(snapshot),
            Self::StateSegment(segment) => ObjectClaimId::StateSegment(segment),
        }
    }

    pub const fn encoded_len(self) -> Option<u32> {
        match self {
            Self::BlockBody(object) => Some(object.encoded_len),
            Self::Terminal(object) => Some(object.encoded_len),
            Self::SnapshotManifest(_) => None,
            Self::StateSegment(segment) => Some(segment.encoded_len),
        }
    }

    pub const fn is_live_transfer_object(self) -> bool {
        matches!(self, Self::BlockBody(_) | Self::Terminal(_))
    }

    pub fn matches_bytes(self, bytes: &[u8]) -> bool {
        match self {
            Self::BlockBody(object) => object.matches_bytes(bytes),
            Self::Terminal(object) => object.matches_bytes(bytes),
            Self::SnapshotManifest(_) | Self::StateSegment(_) => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetObjectsRequest {
    pub objects: Vec<ObjectId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectPayload {
    pub object: ObjectId,
    pub bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct GetObjectsResponse {
    pub status: DataResponseStatus,
    pub objects: Vec<ObjectPayload>,
    pub(crate) inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    pub(crate) outbound_memory_permit: Option<crate::outbound_budget::OutboundMemoryPermit>,
}

impl PartialEq for GetObjectsResponse {
    fn eq(&self, other: &Self) -> bool {
        self.status == other.status && self.objects == other.objects
    }
}

impl Eq for GetObjectsResponse {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_identity_binds_length_domain_and_bytes() {
        let claim = BlockBodyClaimId {
            height: 7,
            block_hash: [7; 32],
        };
        let object = BlockBodyObjectId::from_bytes(claim, b"block").unwrap();
        assert!(object.matches_bytes(b"block"));
        assert!(!object.matches_bytes(b"blocks"));

        let terminal_claim = TerminalClaimId {
            height: 7,
            semantic_header_id: [8; 32],
            proof_class: 0,
        };
        let terminal = TerminalObjectId::from_bytes(terminal_claim, b"block").unwrap();
        assert_ne!(object.byte_digest, terminal.byte_digest);
    }
}
