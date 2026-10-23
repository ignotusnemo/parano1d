// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Allocation-bounded receiver staging for authenticated state snapshots.
//!
//! Network payloads never expand into dense segment columns. Sparse entries
//! are checked against their exact subtree descriptor and atomically published
//! into a private staging directory. Finalization performs an independent
//! numeric second pass to reconstruct the global exact UTXO root and count.
//!
//! The finalized handle owns the directory.  It is `Send`, so the receiver can
//! move it into a blocking MDBX installation task; files remain alive until
//! that task drops the handle on either commit or error.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::block_header::{block_id, BlockHeader};
use crate::consensus::wire_limits::MAX_SNAPSHOT_MANIFEST_SEGMENTS;
use crate::exact_state_hash::{slot_leaf_hash, StateHash};
use crate::fri_state::LOG_SEGMENT_SIZE;
use crate::state::StreamingSparseRoot;

use super::native_segment::{
    max_snapshot_segment_len, snapshot_segment_bytes_limit, snapshot_segment_len_valid,
    SnapshotSegmentPayload,
};
use super::serial::{encoded_segment_len_for_live_count, SparseSegmentView};
use super::snapshot_generation::SnapshotSegmentDescriptor;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(0);

/// Canonical snapshot boundary already authenticated by HistoryStep and
/// the locally verified header chain.
///
/// Construction rechecks internal metadata consistency; it does not replace
/// the caller's HistoryStep/header authentication step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedSnapshotMetadata {
    header: BlockHeader,
    tip_hash: [u8; 32],
    effective_log_segment: u8,
}

impl AuthenticatedSnapshotMetadata {
    pub fn from_authenticated_header(
        header: BlockHeader,
        tip_hash: [u8; 32],
        effective_log_segment: u8,
    ) -> Result<Self, SnapshotStagingError> {
        if block_id(&header) != tip_hash {
            return Err(SnapshotStagingError::TipHashMismatch);
        }
        if header.log_slots == 0 || header.log_slots > u32::BITS {
            return Err(SnapshotStagingError::InvalidMetadata(
                "snapshot log_slots must be in 1..=32",
            ));
        }
        let expected_effective_log = header.log_slots.min(LOG_SEGMENT_SIZE as u32) as u8;
        if effective_log_segment != expected_effective_log {
            return Err(SnapshotStagingError::EffectiveLogMismatch {
                expected: expected_effective_log,
                actual: effective_log_segment,
            });
        }
        let total_slots =
            1u64.checked_shl(header.log_slots)
                .ok_or(SnapshotStagingError::InvalidMetadata(
                    "snapshot slot domain does not fit u64",
                ))?;
        if header.active_slot_count > total_slots {
            return Err(SnapshotStagingError::InvalidMetadata(
                "active slot count exceeds snapshot domain",
            ));
        }
        if header.active_slot_count > header.alloc_counter {
            return Err(SnapshotStagingError::InvalidMetadata(
                "active slot count exceeds allocation counter",
            ));
        }
        Ok(Self {
            header,
            tip_hash,
            effective_log_segment,
        })
    }

    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }

    pub fn effective_log_segment(&self) -> u8 {
        self.effective_log_segment
    }
}

/// Snapshot boundary whose full HistoryStep terminal has been verified
/// against a sealed, native-validated candidate header chain.
///
/// Only `MdbxChainContext::verify_snapshot_boundary` can construct this type.
/// The finalized staging handle separately proves that the streamed state
/// equals `header.state_root`; together they form the complete snapshot
/// boundary without requiring an already-pruned block body.
#[derive(Debug)]
pub struct VerifiedSnapshotBoundary {
    header: BlockHeader,
    history_step_terminal_bytes: Vec<u8>,
}

impl VerifiedSnapshotBoundary {
    pub(crate) fn new_verified(header: BlockHeader, history_step_terminal_bytes: Vec<u8>) -> Self {
        Self {
            header,
            history_step_terminal_bytes,
        }
    }

    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn block_hash(&self) -> [u8; 32] {
        block_id(&self.header)
    }

    pub fn history_step_terminal_bytes(&self) -> &[u8] {
        &self.history_step_terminal_bytes
    }
}

#[derive(Debug)]
pub enum SnapshotStagingError {
    InvalidMetadata(&'static str),
    TipHashMismatch,
    EffectiveLogMismatch {
        expected: u8,
        actual: u8,
    },
    TooManyDescriptors {
        actual: usize,
        maximum: usize,
    },
    DescriptorOrder {
        previous: u16,
        current: u16,
    },
    SegmentIdOutOfRange {
        segment_id: u16,
        maximum: u32,
    },
    DescriptorLength {
        segment_id: u16,
        minimum: u64,
        maximum: u64,
        actual: u64,
    },
    SegmentTooLarge {
        segment_id: u16,
        bytes: u64,
        maximum: usize,
    },
    SessionClosed,
    UnknownSegment {
        segment_id: u16,
    },
    DuplicateSegment {
        segment_id: u16,
    },
    ResponseEffectiveLogMismatch {
        expected: u8,
        actual: u8,
    },
    PayloadLength {
        segment_id: u16,
        expected: u64,
        actual: u64,
    },
    SegmentDecode {
        segment_id: u16,
    },
    NativeAmountBinding {
        segment_id: u16,
    },
    EncodedEffectiveLogMismatch {
        segment_id: u16,
        expected: u8,
        actual: u8,
    },
    ExactSegmentRootMismatch {
        segment_id: u16,
    },
    CreationIdExceedsBound {
        segment_id: u16,
        local_index: u32,
        creation_id: u64,
        alloc_counter: u64,
    },
    CoinbaseCreationHeightExceedsBoundary {
        segment_id: u16,
        local_index: u32,
        mint_height: u64,
        snapshot_height: u64,
    },
    EmptyAdvertisedSegment {
        segment_id: u16,
    },
    Incomplete {
        received: usize,
        expected: usize,
    },
    ActiveCountOverflow,
    ActiveCountMismatch {
        expected: u64,
        actual: u64,
    },
    StateRootMismatch {
        expected: StateHash,
        actual: StateHash,
    },
    ExactRootConstruction,
    StagedFileLength {
        segment_id: u16,
        expected: u64,
        actual: u64,
    },
    Io {
        operation: &'static str,
        source: io::Error,
    },
}

impl SnapshotStagingError {
    /// These errors reject payload bytes before boundary semantics acquire
    /// authority. Network sources and local reuse hints can both be retried.
    pub fn is_payload_authentication_error(&self) -> bool {
        matches!(
            self,
            Self::ResponseEffectiveLogMismatch { .. }
                | Self::PayloadLength { .. }
                | Self::SegmentDecode { .. }
                | Self::EncodedEffectiveLogMismatch { .. }
                | Self::ExactSegmentRootMismatch { .. }
        )
    }
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl fmt::Display for SnapshotStagingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetadata(reason) => write!(f, "invalid snapshot metadata: {reason}"),
            Self::TipHashMismatch => write!(f, "snapshot tip hash does not match header"),
            Self::EffectiveLogMismatch { expected, actual } => write!(
                f,
                "snapshot effective segment log mismatch: expected {expected}, got {actual}"
            ),
            Self::TooManyDescriptors { actual, maximum } => write!(
                f,
                "snapshot descriptor count {actual} exceeds maximum {maximum}"
            ),
            Self::DescriptorOrder { previous, current } => write!(
                f,
                "snapshot descriptors are not strictly sorted: {previous} then {current}"
            ),
            Self::SegmentIdOutOfRange {
                segment_id,
                maximum,
            } => write!(f, "snapshot segment {segment_id} is outside 0..{maximum}"),
            Self::DescriptorLength {
                segment_id,
                minimum,
                maximum,
                actual,
            } => write!(
                f,
                "snapshot segment {segment_id} descriptor length {actual}, expected canonical sparse length in {minimum}..={maximum}"
            ),
            Self::SegmentTooLarge {
                segment_id,
                bytes,
                maximum,
            } => write!(
                f,
                "snapshot segment {segment_id} has {bytes} bytes, maximum {maximum}"
            ),
            Self::SessionClosed => write!(f, "snapshot staging session is closed"),
            Self::UnknownSegment { segment_id } => {
                write!(f, "snapshot segment {segment_id} is not in the manifest")
            }
            Self::DuplicateSegment { segment_id } => {
                write!(f, "snapshot segment {segment_id} was already staged")
            }
            Self::ResponseEffectiveLogMismatch { expected, actual } => write!(
                f,
                "snapshot response effective segment log {actual}, expected {expected}"
            ),
            Self::PayloadLength {
                segment_id,
                expected,
                actual,
            } => write!(
                f,
                "snapshot segment {segment_id} payload length {actual}, expected {expected}"
            ),
            Self::SegmentDecode { segment_id } => {
                write!(f, "snapshot segment {segment_id} failed canonical decode")
            }
            Self::EncodedEffectiveLogMismatch {
                segment_id,
                expected,
                actual,
            } => write!(
                f,
                "snapshot segment {segment_id} encoded log {actual}, expected {expected}"
            ),
            Self::ExactSegmentRootMismatch { segment_id } => {
                write!(f, "snapshot segment {segment_id} exact root mismatch")
            }
            Self::CreationIdExceedsBound {
                segment_id,
                local_index,
                creation_id,
                alloc_counter,
            } => write!(
                f,
                "snapshot segment {segment_id} slot {local_index} creation id {creation_id} exceeds {alloc_counter}"
            ),
            Self::CoinbaseCreationHeightExceedsBoundary {
                segment_id,
                local_index,
                mint_height,
                snapshot_height,
            } => write!(
                f,
                "snapshot segment {segment_id} slot {local_index} coinbase mint height {mint_height} exceeds snapshot height {snapshot_height}"
            ),
            Self::EmptyAdvertisedSegment { segment_id } => {
                write!(f, "snapshot manifest advertises empty segment {segment_id}")
            }
            Self::NativeAmountBinding { segment_id } => {
                write!(f, "snapshot segment {segment_id} native amount binding")
            }
            Self::Incomplete { received, expected } => write!(
                f,
                "snapshot staging incomplete: received {received} of {expected} segments"
            ),
            Self::ActiveCountOverflow => write!(f, "snapshot active slot count overflow"),
            Self::ActiveCountMismatch { expected, actual } => write!(
                f,
                "snapshot active slot count {actual}, header commits {expected}"
            ),
            Self::StateRootMismatch { expected, actual } => write!(
                f,
                "snapshot exact root mismatch: expected {}, got {}",
                digest_hex(expected),
                digest_hex(actual)
            ),
            Self::ExactRootConstruction => {
                write!(f, "snapshot exact sparse root construction failed")
            }
            Self::StagedFileLength {
                segment_id,
                expected,
                actual,
            } => write!(
                f,
                "staged segment {segment_id} file length {actual}, expected {expected}"
            ),
            Self::Io { operation, source } => write!(f, "snapshot staging {operation}: {source}"),
        }
    }
}

impl std::error::Error for SnapshotStagingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// In-progress receiver session. Metadata is compact; segment payloads live in
/// the private staging directory rather than process RAM.
pub struct SnapshotStagingSession {
    metadata: AuthenticatedSnapshotMetadata,
    descriptors: Vec<SnapshotSegmentDescriptor>,
    received: Vec<u64>,
    received_count: usize,
    directory: Option<PathBuf>,
    closed: bool,
}

impl SnapshotStagingSession {
    pub fn new(
        staging_parent: impl AsRef<Path>,
        metadata: AuthenticatedSnapshotMetadata,
        descriptors: Vec<SnapshotSegmentDescriptor>,
    ) -> Result<Self, SnapshotStagingError> {
        validate_descriptors(&metadata, &descriptors)?;
        let directory = create_session_directory(staging_parent.as_ref(), &metadata)?;
        let received_words = descriptors.len().saturating_add(63) / 64;
        Ok(Self {
            metadata,
            descriptors,
            received: vec![0; received_words],
            received_count: 0,
            directory: Some(directory),
            closed: false,
        })
    }

    pub fn metadata(&self) -> &AuthenticatedSnapshotMetadata {
        &self.metadata
    }

    pub fn descriptors(&self) -> &[SnapshotSegmentDescriptor] {
        &self.descriptors
    }

    pub fn received_count(&self) -> usize {
        self.received_count
    }

    /// Authenticate and seal root-matching local segments before transport
    /// dispatch. At most one encoded payload is resident. A corrupt local
    /// hint falls back to the network without invalidating verified progress;
    /// boundary semantic failures and disk failures propagate to the caller.
    pub fn reuse_local_segments(
        &mut self,
        store: &super::MdbxStore,
        still_current: impl Fn() -> bool,
    ) -> Result<(Vec<u16>, u64), super::StoreError> {
        let effective_log = self.metadata.effective_log_segment;
        let mut segment_ids = Vec::new();
        let mut bytes = 0u64;
        for index in 0..self.descriptors.len() {
            if !still_current() {
                break;
            }
            let descriptor = self.descriptors[index];
            let Some(encoded) = store.matching_encoded_segment_at(
                &descriptor,
                effective_log,
                self.metadata.header.height,
            )?
            else {
                continue;
            };
            match self.accept_segment_recoverable(descriptor.segment_id, effective_log, &encoded) {
                Ok(()) => {
                    segment_ids.push(descriptor.segment_id);
                    bytes = bytes.saturating_add(encoded.len() as u64);
                }
                Err(error) if error.is_payload_authentication_error() => {
                    tracing::warn!(segment = descriptor.segment_id, %error,
                        "local snapshot reuse failed authentication; fetching exact segment from network");
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok((segment_ids, bytes))
    }

    #[cfg(test)]
    fn staging_directory(&self) -> Option<&Path> {
        self.directory.as_deref()
    }

    /// Validate and atomically stage one network response. Any rejection
    /// invalidates the whole session and eagerly removes previously staged
    /// files; `Drop` retries cleanup if the filesystem removal itself fails.
    pub fn accept_segment(
        &mut self,
        segment_id: u16,
        response_effective_log: u8,
        encoded: &[u8],
    ) -> Result<(), SnapshotStagingError> {
        if self.closed || self.directory.is_none() {
            return Err(SnapshotStagingError::SessionClosed);
        }
        let result = self.accept_segment_inner(segment_id, response_effective_log, encoded);
        if result.is_err() {
            self.closed = true;
            self.cleanup_best_effort();
        }
        result
    }

    /// Validate and atomically stage one independently authenticated segment
    /// without invalidating segments that were already accepted. This is used
    /// by the multi-source snapshot fetcher: one peer supplying bad bytes must
    /// cost only that exact object, not the verified progress obtained from
    /// other peers.
    ///
    /// `accept_segment_inner` publishes only after the complete payload has
    /// passed its descriptor, length, canonical encoding and subtree-root
    /// checks. Therefore an error leaves the session's received set and every
    /// previously published segment unchanged.
    pub fn accept_segment_recoverable(
        &mut self,
        segment_id: u16,
        response_effective_log: u8,
        encoded: &[u8],
    ) -> Result<(), SnapshotStagingError> {
        if self.closed || self.directory.is_none() {
            return Err(SnapshotStagingError::SessionClosed);
        }
        self.accept_segment_inner(segment_id, response_effective_log, encoded)
    }

    fn accept_segment_inner(
        &mut self,
        segment_id: u16,
        response_effective_log: u8,
        encoded: &[u8],
    ) -> Result<(), SnapshotStagingError> {
        let index = self
            .descriptors
            .binary_search_by_key(&segment_id, |descriptor| descriptor.segment_id)
            .map_err(|_| SnapshotStagingError::UnknownSegment { segment_id })?;
        if self.is_received(index) {
            return Err(SnapshotStagingError::DuplicateSegment { segment_id });
        }
        if response_effective_log != self.metadata.effective_log_segment {
            return Err(SnapshotStagingError::ResponseEffectiveLogMismatch {
                expected: self.metadata.effective_log_segment,
                actual: response_effective_log,
            });
        }
        let descriptor = self.descriptors[index];
        let actual_len = encoded.len() as u64;
        if actual_len != u64::from(descriptor.encoded_len) {
            return Err(SnapshotStagingError::PayloadLength {
                segment_id,
                expected: u64::from(descriptor.encoded_len),
                actual: actual_len,
            });
        }
        decode_and_verify_segment(&self.metadata, &descriptor, encoded)?;

        let directory = self
            .directory
            .as_deref()
            .ok_or(SnapshotStagingError::SessionClosed)?;
        atomic_publish_segment(directory, segment_id, encoded)?;
        self.mark_received(index);
        self.received_count += 1;
        Ok(())
    }

    /// Re-open every staged file in numeric descriptor order and independently
    /// reconstruct the exact header state root and live count.
    pub fn finalize(mut self) -> Result<FinalizedSnapshotStaging, SnapshotStagingError> {
        if self.closed || self.directory.is_none() {
            return Err(SnapshotStagingError::SessionClosed);
        }
        if self.received_count != self.descriptors.len() {
            return Err(SnapshotStagingError::Incomplete {
                received: self.received_count,
                expected: self.descriptors.len(),
            });
        }

        let mut exact = StreamingSparseRoot::new(self.metadata.header.log_slots)
            .map_err(|_| SnapshotStagingError::ExactRootConstruction)?;
        let mut active_count = 0u64;
        let effective_log = self.metadata.effective_log_segment;
        let directory = self
            .directory
            .as_deref()
            .ok_or(SnapshotStagingError::SessionClosed)?;

        for descriptor in &self.descriptors {
            let encoded = read_staged_file(directory, descriptor)?;
            let sparse = decode_and_verify_segment(&self.metadata, descriptor, &encoded)?;

            let base = u64::from(descriptor.segment_id) << effective_log;
            for (local, slot) in sparse.entries() {
                active_count = active_count
                    .checked_add(1)
                    .ok_or(SnapshotStagingError::ActiveCountOverflow)?;
                let global = base
                    .checked_add(u64::from(local))
                    .ok_or(SnapshotStagingError::ExactRootConstruction)?;
                let global = u32::try_from(global)
                    .map_err(|_| SnapshotStagingError::ExactRootConstruction)?;
                exact
                    .push_leaf(global, slot_leaf_hash(slot))
                    .map_err(|_| SnapshotStagingError::ExactRootConstruction)?;
            }
        }

        let actual_root = exact
            .finish()
            .map_err(|_| SnapshotStagingError::ExactRootConstruction)?;
        if active_count != self.metadata.header.active_slot_count {
            return Err(SnapshotStagingError::ActiveCountMismatch {
                expected: self.metadata.header.active_slot_count,
                actual: active_count,
            });
        }
        if actual_root != self.metadata.header.state_root {
            return Err(SnapshotStagingError::StateRootMismatch {
                expected: self.metadata.header.state_root,
                actual: actual_root,
            });
        }

        self.closed = true;
        let directory = self
            .directory
            .take()
            .ok_or(SnapshotStagingError::SessionClosed)?;
        Ok(FinalizedSnapshotStaging {
            metadata: self.metadata,
            descriptors: std::mem::take(&mut self.descriptors),
            directory: Some(directory),
        })
    }

    fn is_received(&self, index: usize) -> bool {
        let word = index / 64;
        let bit = index % 64;
        self.received
            .get(word)
            .is_some_and(|value| value & (1u64 << bit) != 0)
    }

    fn mark_received(&mut self, index: usize) {
        let word = index / 64;
        let bit = index % 64;
        self.received[word] |= 1u64 << bit;
    }

    fn cleanup_best_effort(&mut self) {
        let Some(directory) = self.directory.as_ref() else {
            return;
        };
        match fs::remove_dir_all(directory) {
            Ok(()) => self.directory = None,
            Err(error) if error.kind() == io::ErrorKind::NotFound => self.directory = None,
            Err(_) => {}
        }
    }
}

impl Drop for SnapshotStagingSession {
    fn drop(&mut self) {
        self.cleanup_best_effort();
    }
}

/// Fully checked snapshot files ready for one atomic MDBX installation.
///
/// Move this handle into the blocking installer. Its `Drop` removes all files,
/// so the iterator must be consumed and the MDBX transaction committed before
/// the handle leaves scope.
pub struct FinalizedSnapshotStaging {
    metadata: AuthenticatedSnapshotMetadata,
    descriptors: Vec<SnapshotSegmentDescriptor>,
    directory: Option<PathBuf>,
}

impl FinalizedSnapshotStaging {
    pub fn metadata(&self) -> &AuthenticatedSnapshotMetadata {
        &self.metadata
    }

    pub fn descriptors(&self) -> &[SnapshotSegmentDescriptor] {
        &self.descriptors
    }

    pub fn encoded_files(&self) -> StagedEncodedSegmentFiles<'_> {
        StagedEncodedSegmentFiles {
            directory: self
                .directory
                .as_deref()
                .expect("finalized snapshot handle always owns its directory"),
            metadata: &self.metadata,
            descriptors: self.descriptors.iter(),
        }
    }

    fn cleanup_best_effort(&mut self) {
        let Some(directory) = self.directory.as_ref() else {
            return;
        };
        match fs::remove_dir_all(directory) {
            Ok(()) => self.directory = None,
            Err(error) if error.kind() == io::ErrorKind::NotFound => self.directory = None,
            Err(_) => {}
        }
    }
}

impl Drop for FinalizedSnapshotStaging {
    fn drop(&mut self) {
        self.cleanup_best_effort();
    }
}

pub struct StagedEncodedSegmentFiles<'a> {
    directory: &'a Path,
    metadata: &'a AuthenticatedSnapshotMetadata,
    descriptors: std::slice::Iter<'a, SnapshotSegmentDescriptor>,
}

impl<'a> Iterator for StagedEncodedSegmentFiles<'a> {
    type Item = StagedEncodedSegmentFile<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.descriptors
            .next()
            .map(|descriptor| StagedEncodedSegmentFile {
                directory: self.directory,
                metadata: self.metadata,
                descriptor,
            })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.descriptors.size_hint()
    }
}

impl ExactSizeIterator for StagedEncodedSegmentFiles<'_> {}

/// One finalized encoded file. The MDBX installer should call `read_encoded`,
/// decode/install it, drop that segment, and only then advance the iterator.
pub struct StagedEncodedSegmentFile<'a> {
    directory: &'a Path,
    metadata: &'a AuthenticatedSnapshotMetadata,
    descriptor: &'a SnapshotSegmentDescriptor,
}

impl StagedEncodedSegmentFile<'_> {
    pub fn descriptor(&self) -> &SnapshotSegmentDescriptor {
        self.descriptor
    }

    pub fn segment_id(&self) -> u16 {
        self.descriptor.segment_id
    }

    pub fn effective_log_segment(&self) -> u8 {
        self.metadata.effective_log_segment
    }

    /// Read and re-authenticate the immutable bytes immediately before the
    /// MDBX transaction consumes them. This closes the finalize-to-install
    /// corruption window without retaining more than one segment.
    pub fn read_encoded(&self) -> Result<Vec<u8>, SnapshotStagingError> {
        let encoded = read_staged_file(self.directory, self.descriptor)?;
        decode_and_verify_segment(self.metadata, self.descriptor, &encoded)?;
        Ok(encoded)
    }
}

fn validate_descriptors(
    metadata: &AuthenticatedSnapshotMetadata,
    descriptors: &[SnapshotSegmentDescriptor],
) -> Result<(), SnapshotStagingError> {
    if descriptors.len() > MAX_SNAPSHOT_MANIFEST_SEGMENTS {
        return Err(SnapshotStagingError::TooManyDescriptors {
            actual: descriptors.len(),
            maximum: MAX_SNAPSHOT_MANIFEST_SEGMENTS,
        });
    }
    let minimum_len = encoded_segment_len_for_live_count(metadata.effective_log_segment, 1).ok_or(
        SnapshotStagingError::InvalidMetadata("invalid effective segment logarithm"),
    )? as u64;
    let maximum_len =
        max_snapshot_segment_len(metadata.effective_log_segment, metadata.header.height).ok_or(
            SnapshotStagingError::InvalidMetadata("invalid effective segment logarithm"),
        )? as u64;
    if maximum_len > snapshot_segment_bytes_limit(metadata.header.height) as u64 {
        return Err(SnapshotStagingError::InvalidMetadata(
            "canonical segment encoding exceeds wire limit",
        ));
    }
    let segment_bits = metadata.header.log_slots - u32::from(metadata.effective_log_segment);
    let maximum_segments =
        1u32.checked_shl(segment_bits)
            .ok_or(SnapshotStagingError::InvalidMetadata(
                "snapshot segment namespace overflow",
            ))?;

    let mut previous = None;
    for descriptor in descriptors {
        if let Some(previous) = previous {
            if descriptor.segment_id <= previous {
                return Err(SnapshotStagingError::DescriptorOrder {
                    previous,
                    current: descriptor.segment_id,
                });
            }
        }
        previous = Some(descriptor.segment_id);
        if u32::from(descriptor.segment_id) >= maximum_segments {
            return Err(SnapshotStagingError::SegmentIdOutOfRange {
                segment_id: descriptor.segment_id,
                maximum: maximum_segments,
            });
        }
        let actual_len = u64::from(descriptor.encoded_len);
        if actual_len > snapshot_segment_bytes_limit(metadata.header.height) as u64 {
            return Err(SnapshotStagingError::SegmentTooLarge {
                segment_id: descriptor.segment_id,
                bytes: actual_len,
                maximum: snapshot_segment_bytes_limit(metadata.header.height),
            });
        }
        if !snapshot_segment_len_valid(
            metadata.effective_log_segment,
            descriptor.encoded_len as usize,
            metadata.header.height,
        ) {
            return Err(SnapshotStagingError::DescriptorLength {
                segment_id: descriptor.segment_id,
                minimum: minimum_len,
                maximum: maximum_len,
                actual: actual_len,
            });
        }
    }
    Ok(())
}

fn decode_and_verify_segment<'a>(
    metadata: &AuthenticatedSnapshotMetadata,
    descriptor: &SnapshotSegmentDescriptor,
    encoded: &'a [u8],
) -> Result<SparseSegmentView<'a>, SnapshotStagingError> {
    let payload =
        SnapshotSegmentPayload::decode_for_root_authentication(encoded, metadata.header.height)
            .ok_or(SnapshotStagingError::SegmentDecode {
                segment_id: descriptor.segment_id,
            })?;
    let sparse = payload.sparse();
    let encoded_effective_log = sparse.effective_log_segment();
    if encoded_effective_log != metadata.effective_log_segment {
        return Err(SnapshotStagingError::EncodedEffectiveLogMismatch {
            segment_id: descriptor.segment_id,
            expected: metadata.effective_log_segment,
            actual: encoded_effective_log,
        });
    }
    let mut exact = StreamingSparseRoot::new(u32::from(encoded_effective_log))
        .map_err(|_| SnapshotStagingError::ExactRootConstruction)?;
    for (local, slot) in sparse.entries() {
        exact
            .push_leaf(u32::from(local), slot_leaf_hash(slot))
            .map_err(|_| SnapshotStagingError::ExactRootConstruction)?;
    }
    let actual_root = exact
        .finish()
        .map_err(|_| SnapshotStagingError::ExactRootConstruction)?;
    if actual_root != descriptor.segment_root {
        return Err(SnapshotStagingError::ExactSegmentRootMismatch {
            segment_id: descriptor.segment_id,
        });
    }
    // Only after the payload is bound to the immutable manifest root do
    // semantic failures reject the generation rather than merely its source.
    // This prevents cycling forever through peers that all serve the same
    // content-addressed but semantically impossible segment.
    if sparse.live_count() == 0 {
        return Err(SnapshotStagingError::EmptyAdvertisedSegment {
            segment_id: descriptor.segment_id,
        });
    }
    if !payload.native_amounts_valid() {
        return Err(SnapshotStagingError::NativeAmountBinding {
            segment_id: descriptor.segment_id,
        });
    }
    for (local, slot) in sparse.entries() {
        let creation_id = slot.creation_id();
        if !crate::consensus::params::creation_id_within_boundary(
            creation_id,
            metadata.header.alloc_counter,
            metadata.header.height,
        ) {
            if crate::consensus::params::is_coinbase_creation_id(creation_id) {
                return Err(
                    SnapshotStagingError::CoinbaseCreationHeightExceedsBoundary {
                        segment_id: descriptor.segment_id,
                        local_index: u32::from(local),
                        mint_height: crate::consensus::params::coinbase_creation_height(
                            creation_id,
                        ),
                        snapshot_height: metadata.header.height,
                    },
                );
            }
            return Err(SnapshotStagingError::CreationIdExceedsBound {
                segment_id: descriptor.segment_id,
                local_index: u32::from(local),
                creation_id,
                alloc_counter: metadata.header.alloc_counter,
            });
        }
    }
    Ok(sparse)
}

fn create_session_directory(
    parent: &Path,
    metadata: &AuthenticatedSnapshotMetadata,
) -> Result<PathBuf, SnapshotStagingError> {
    fs::create_dir_all(parent)
        .map_err(|error| SnapshotStagingError::io("create staging parent", error))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let process = std::process::id();
    for attempt in 0..128u64 {
        let sequence = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            "snapshot-{}-{:02x}{:02x}-{process}-{now:x}-{sequence:x}-{attempt:x}",
            metadata.header.height, metadata.tip_hash[0], metadata.tip_hash[1]
        );
        let directory = parent.join(name);
        match fs::create_dir(&directory) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let permissions = fs::Permissions::from_mode(0o700);
                    if let Err(error) = fs::set_permissions(&directory, permissions) {
                        let _ = fs::remove_dir_all(&directory);
                        return Err(SnapshotStagingError::io(
                            "set staging directory permissions",
                            error,
                        ));
                    }
                }
                return Ok(directory);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(SnapshotStagingError::io("create staging directory", error));
            }
        }
    }
    Err(SnapshotStagingError::io(
        "create unique staging directory",
        io::Error::new(io::ErrorKind::AlreadyExists, "session name collision"),
    ))
}

fn atomic_publish_segment(
    directory: &Path,
    segment_id: u16,
    encoded: &[u8],
) -> Result<(), SnapshotStagingError> {
    let temporary = temporary_segment_path(directory, segment_id);
    let final_path = segment_path(directory, segment_id);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(|error| SnapshotStagingError::io("create temporary segment", error))?;
        file.write_all(encoded)
            .map_err(|error| SnapshotStagingError::io("write temporary segment", error))?;
        file.sync_all()
            .map_err(|error| SnapshotStagingError::io("sync temporary segment", error))?;
        #[cfg(unix)]
        {
            let mut permissions = file
                .metadata()
                .map_err(|error| SnapshotStagingError::io("read segment permissions", error))?
                .permissions();
            permissions.set_readonly(true);
            file.set_permissions(permissions)
                .map_err(|error| SnapshotStagingError::io("seal segment read-only", error))?;
        }
        drop(file);

        // `hard_link` publishes a fully synced inode atomically and, unlike
        // `rename`, cannot replace an existing final name.
        fs::hard_link(&temporary, &final_path)
            .map_err(|error| SnapshotStagingError::io("publish staged segment", error))?;
        fs::remove_file(&temporary)
            .map_err(|error| SnapshotStagingError::io("remove temporary segment link", error))?;
        sync_directory(directory)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        let _ = fs::remove_file(&final_path);
    }
    result
}

fn sync_directory(directory: &Path) -> Result<(), SnapshotStagingError> {
    #[cfg(unix)]
    {
        let directory_file = File::open(directory)
            .map_err(|error| SnapshotStagingError::io("open staging directory", error))?;
        directory_file
            .sync_all()
            .map_err(|error| SnapshotStagingError::io("sync staging directory", error))?;
    }
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

fn read_staged_file(
    directory: &Path,
    descriptor: &SnapshotSegmentDescriptor,
) -> Result<Vec<u8>, SnapshotStagingError> {
    let path = segment_path(directory, descriptor.segment_id);
    let mut file = File::open(path).map_err(|error| SnapshotStagingError::io("open", error))?;
    let actual = file
        .metadata()
        .map_err(|error| SnapshotStagingError::io("metadata", error))?
        .len();
    if actual != u64::from(descriptor.encoded_len) {
        return Err(SnapshotStagingError::StagedFileLength {
            segment_id: descriptor.segment_id,
            expected: u64::from(descriptor.encoded_len),
            actual,
        });
    }
    let expected = descriptor.encoded_len as usize;
    let mut encoded = vec![0u8; expected];
    file.read_exact(&mut encoded)
        .map_err(|error| SnapshotStagingError::io("read staged segment", error))?;
    let mut extra = [0u8; 1];
    if file
        .read(&mut extra)
        .map_err(|error| SnapshotStagingError::io("check staged segment EOF", error))?
        != 0
    {
        return Err(SnapshotStagingError::StagedFileLength {
            segment_id: descriptor.segment_id,
            expected: u64::from(descriptor.encoded_len),
            actual: u64::from(descriptor.encoded_len).saturating_add(1),
        });
    }
    Ok(encoded)
}

fn segment_path(directory: &Path, segment_id: u16) -> PathBuf {
    directory.join(format!("segment-{segment_id:05}.bin"))
}

fn temporary_segment_path(directory: &Path, segment_id: u16) -> PathBuf {
    directory.join(format!("segment-{segment_id:05}.part"))
}

fn digest_hex(digest: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use noid_core::Block128;
    use noid_poseidon2b::primitives::Address;

    use super::*;
    use crate::exact_state_hash::zero_slot_roots;
    use crate::fri_state::SlotValue;
    use crate::segmented_state::SegmentColumns;
    use crate::state::{exact_segment_root_from_columns, ChainState};
    use crate::storage::serial::{decode_segment, encode_segment, encode_sparse_segment_entries};

    fn slot(amount: u64, creation_id: u64, owner: u128) -> SlotValue {
        SlotValue::with_owner_fields(
            amount,
            creation_id,
            [Block128::from(owner), Block128::from(owner + 1)],
        )
    }

    fn columns(log: u8, entries: &[(usize, SlotValue)]) -> SegmentColumns {
        let mut columns = SegmentColumns::new_zero(1usize << log);
        for &(index, value) in entries {
            columns.values[index] = value.value;
            columns.owners_hi[index] = value.owner_hi;
            columns.owners_lo[index] = value.owner_lo;
        }
        columns
    }

    fn header(log_slots: u32, root: [u8; 32], active: u64, alloc: u64) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [0x11; 32],
            state_root: root,
            tx_root: [0x22; 32],
            timestamp: 1_700_000_000,
            height: 7,
            miner_address: Address([0x33; 32]),
            nonce: 9,
            difficulty_target: [0xff; 32],
            log_slots,
            active_slot_count: active,
            alloc_counter: alloc,
        }
    }

    fn fixture() -> (
        AuthenticatedSnapshotMetadata,
        SnapshotSegmentDescriptor,
        Vec<u8>,
    ) {
        let first = slot(50, 2, 0xA1);
        let second = slot(70, 5, 0xB2);
        let columns = columns(3, &[(1, first), (6, second)]);
        let encoded = encode_segment(&columns, 3);
        let exact =
            ChainState::from_sparse_utxos(3, &[(1, first), (6, second)], 5).expect("exact fixture");
        let header = header(3, exact.utxo_root, 2, 5);
        let metadata =
            AuthenticatedSnapshotMetadata::from_authenticated_header(header, block_id(&header), 3)
                .expect("authenticated fixture metadata");
        let descriptor = SnapshotSegmentDescriptor {
            segment_id: 0,
            segment_root: exact.cached_exact_segment_root(0).unwrap(),
            encoded_len: encoded.len() as u32,
        };
        (metadata, descriptor, encoded)
    }

    #[test]
    fn stages_finalizes_and_keeps_files_alive_until_handle_drop() {
        fn assert_send<T: Send>() {}
        assert_send::<FinalizedSnapshotStaging>();

        let parent = tempfile::tempdir().expect("temp staging parent");
        let (metadata, descriptor, encoded) = fixture();
        let mut session = SnapshotStagingSession::new(parent.path(), metadata, vec![descriptor])
            .expect("new staging session");
        let directory = session.staging_directory().unwrap().to_path_buf();
        session
            .accept_segment(0, 3, &encoded)
            .expect("accept authenticated segment");
        drop(encoded);
        let finalized = session.finalize().expect("exact second pass");
        assert!(directory.exists());
        let mut files = finalized.encoded_files();
        let staged = files.next().expect("one staged segment");
        assert_eq!(staged.segment_id(), 0);
        assert_eq!(staged.effective_log_segment(), 3);
        assert_eq!(
            staged.read_encoded().unwrap().len() as u64,
            u64::from(descriptor.encoded_len)
        );
        assert!(files.next().is_none());
        drop(finalized);
        assert!(!directory.exists());
    }

    #[test]
    fn sparse_snapshot_scales_across_all_256_genesis_segments() {
        let parent = tempfile::tempdir().unwrap();
        let mut global = StreamingSparseRoot::new(24).unwrap();
        let mut descriptors = Vec::with_capacity(256);
        let mut payloads = Vec::with_capacity(256);

        for segment_id in 0u16..=255 {
            let creation_id = u64::from(segment_id) + 1;
            let slot = SlotValue::from_parts(
                1,
                creation_id,
                Block128::from(creation_id + 1),
                Block128::from(creation_id + 2),
            );
            let mut segment_exact = StreamingSparseRoot::new(16).unwrap();
            segment_exact.push_leaf(0, slot_leaf_hash(slot)).unwrap();
            let segment_root = segment_exact.finish().unwrap();
            global
                .push_leaf(u32::from(segment_id) << 16, slot_leaf_hash(slot))
                .unwrap();
            let encoded = encode_sparse_segment_entries(16, &[(0, slot)]).unwrap();
            assert_eq!(encoded.len(), 59);
            descriptors.push(SnapshotSegmentDescriptor {
                segment_id,
                segment_root,
                encoded_len: encoded.len() as u32,
            });
            payloads.push(encoded);
        }

        let root = global.finish().unwrap();
        let hdr = header(24, root, 256, 256);
        let metadata =
            AuthenticatedSnapshotMetadata::from_authenticated_header(hdr, block_id(&hdr), 16)
                .unwrap();
        let mut session =
            SnapshotStagingSession::new(parent.path(), metadata, descriptors).unwrap();
        for (segment_id, encoded) in payloads.iter().enumerate() {
            session
                .accept_segment(segment_id as u16, 16, encoded)
                .unwrap();
        }
        let finalized = session.finalize().unwrap();
        assert_eq!(finalized.descriptors().len(), 256);
        assert_eq!(
            finalized
                .encoded_files()
                .map(|file| file.read_encoded().unwrap().len())
                .sum::<usize>(),
            256 * 59
        );
    }

    #[test]
    fn expanded_domain_snapshot_authenticates_sparse_lower_and_upper_segments() {
        let parent = tempfile::tempdir().unwrap();
        let cases = [(0u16, 7u16, 1u64), (511u16, u16::MAX, 2u64)];
        let mut global = StreamingSparseRoot::new(25).unwrap();
        let mut descriptors = Vec::with_capacity(cases.len());
        let mut payloads = Vec::with_capacity(cases.len());

        for (segment_id, local_index, creation_id) in cases {
            let slot = SlotValue::from_parts(
                5,
                creation_id,
                Block128::from(creation_id + 11),
                Block128::from(creation_id + 12),
            );
            let mut segment_exact = StreamingSparseRoot::new(16).unwrap();
            segment_exact
                .push_leaf(u32::from(local_index), slot_leaf_hash(slot))
                .unwrap();
            let segment_root = segment_exact.finish().unwrap();
            let global_index = (u32::from(segment_id) << 16) | u32::from(local_index);
            global
                .push_leaf(global_index, slot_leaf_hash(slot))
                .unwrap();
            let encoded = encode_sparse_segment_entries(16, &[(local_index, slot)]).unwrap();
            descriptors.push(SnapshotSegmentDescriptor {
                segment_id,
                segment_root,
                encoded_len: encoded.len() as u32,
            });
            payloads.push((segment_id, encoded));
        }

        let root = global.finish().unwrap();
        let hdr = header(25, root, cases.len() as u64, 2);
        let metadata =
            AuthenticatedSnapshotMetadata::from_authenticated_header(hdr, block_id(&hdr), 16)
                .unwrap();
        let mut session =
            SnapshotStagingSession::new(parent.path(), metadata, descriptors).unwrap();
        for (segment_id, encoded) in &payloads {
            session.accept_segment(*segment_id, 16, encoded).unwrap();
        }
        let finalized = session.finalize().unwrap();
        assert_eq!(
            finalized
                .descriptors()
                .iter()
                .map(|descriptor| descriptor.segment_id)
                .collect::<Vec<_>>(),
            vec![0, 511]
        );
        assert_eq!(
            finalized
                .encoded_files()
                .map(|file| file.read_encoded().unwrap().len())
                .sum::<usize>(),
            2 * 59
        );
    }

    #[test]
    fn authenticated_manifest_boundary_and_geometry_fail_closed_before_staging() {
        let parent = tempfile::tempdir().unwrap();
        let (metadata, descriptor, _) = fixture();
        let hdr = *metadata.header();

        let mut wrong_hash = block_id(&hdr);
        wrong_hash[0] ^= 1;
        assert!(matches!(
            AuthenticatedSnapshotMetadata::from_authenticated_header(hdr, wrong_hash, 3),
            Err(SnapshotStagingError::TipHashMismatch)
        ));
        assert!(matches!(
            AuthenticatedSnapshotMetadata::from_authenticated_header(hdr, block_id(&hdr), 2),
            Err(SnapshotStagingError::EffectiveLogMismatch {
                expected: 3,
                actual: 2,
            })
        ));

        let mut impossible_count = hdr;
        impossible_count.active_slot_count = 9;
        assert!(matches!(
            AuthenticatedSnapshotMetadata::from_authenticated_header(
                impossible_count,
                block_id(&impossible_count),
                3,
            ),
            Err(SnapshotStagingError::InvalidMetadata(
                "active slot count exceeds snapshot domain"
            ))
        ));

        let mut out_of_domain = descriptor;
        out_of_domain.segment_id = 1;
        assert!(matches!(
            SnapshotStagingSession::new(parent.path(), metadata, vec![out_of_domain]),
            Err(SnapshotStagingError::SegmentIdOutOfRange {
                segment_id: 1,
                maximum: 1,
            })
        ));
        let mut noncanonical_len = descriptor;
        noncanonical_len.encoded_len += 1;
        assert!(matches!(
            SnapshotStagingSession::new(parent.path(), metadata, vec![noncanonical_len]),
            Err(SnapshotStagingError::DescriptorLength { segment_id: 0, .. })
        ));
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    #[test]
    fn duplicate_reject_aborts_and_cleans_the_session() {
        let parent = tempfile::tempdir().unwrap();
        let (metadata, descriptor, encoded) = fixture();
        let mut session =
            SnapshotStagingSession::new(parent.path(), metadata, vec![descriptor]).unwrap();
        let directory = session.staging_directory().unwrap().to_path_buf();
        session.accept_segment(0, 3, &encoded).unwrap();
        assert!(matches!(
            session.accept_segment(0, 3, &encoded),
            Err(SnapshotStagingError::DuplicateSegment { segment_id: 0 })
        ));
        assert!(!directory.exists());
        assert!(matches!(
            session.accept_segment(0, 3, &encoded),
            Err(SnapshotStagingError::SessionClosed)
        ));
    }

    #[test]
    fn recoverable_rejection_keeps_session_for_an_exact_source_retry() {
        let parent = tempfile::tempdir().unwrap();
        let (metadata, descriptor, encoded) = fixture();
        let mut session =
            SnapshotStagingSession::new(parent.path(), metadata, vec![descriptor]).unwrap();
        let directory = session.staging_directory().unwrap().to_path_buf();
        let mut corrupted = encoded.clone();
        let last = corrupted.last_mut().expect("fixture payload is non-empty");
        *last ^= 1;

        assert!(session
            .accept_segment_recoverable(0, 3, &corrupted)
            .is_err());
        assert!(directory.exists());
        assert_eq!(session.received_count(), 0);

        session
            .accept_segment_recoverable(0, 3, &encoded)
            .expect("the same exact object from another source is accepted");
        session.finalize().expect("recovered session finalizes");
    }

    #[test]
    fn creation_bound_is_checked_before_file_publication() {
        let parent = tempfile::tempdir().unwrap();
        let bad_slot = slot(1, 6, 0xCA);
        let columns = columns(3, &[(4, bad_slot)]);
        let encoded = encode_segment(&columns, 3);
        let exact_root = exact_segment_root_from_columns(3, &columns);
        let hdr = header(3, zero_slot_roots(3)[3], 1, 5);
        let metadata =
            AuthenticatedSnapshotMetadata::from_authenticated_header(hdr, block_id(&hdr), 3)
                .unwrap();
        let descriptor = SnapshotSegmentDescriptor {
            segment_id: 0,
            segment_root: exact_root,
            encoded_len: encoded.len() as u32,
        };
        let mut session =
            SnapshotStagingSession::new(parent.path(), metadata, vec![descriptor]).unwrap();
        let directory = session.staging_directory().unwrap().to_path_buf();
        assert!(matches!(
            session.accept_segment(0, 3, &encoded),
            Err(SnapshotStagingError::CreationIdExceedsBound {
                segment_id: 0,
                local_index: 4,
                creation_id: 6,
                alloc_counter: 5,
            })
        ));
        assert!(!directory.exists());
    }

    #[test]
    fn coinbase_creation_ids_use_snapshot_height_not_allocator_bound() {
        use crate::consensus::params::coinbase_creation_id;

        let parent = tempfile::tempdir().unwrap();
        let coinbase = slot(1, coinbase_creation_id(7), 0xCB);
        let coinbase_columns = columns(3, &[(4, coinbase)]);
        let encoded = encode_segment(&coinbase_columns, 3);
        let exact_root = exact_segment_root_from_columns(3, &coinbase_columns);
        let exact = ChainState::from_sparse_utxos(3, &[(4, coinbase)], 5)
            .expect("tagged coinbase snapshot state");
        let hdr = header(3, exact.utxo_root, 1, 5);
        let metadata =
            AuthenticatedSnapshotMetadata::from_authenticated_header(hdr, block_id(&hdr), 3)
                .unwrap();
        let descriptor = SnapshotSegmentDescriptor {
            segment_id: 0,
            segment_root: exact_root,
            encoded_len: encoded.len() as u32,
        };
        let mut session =
            SnapshotStagingSession::new(parent.path(), metadata, vec![descriptor]).unwrap();
        session
            .accept_segment(0, 3, &encoded)
            .expect("coinbase tag is bounded by mint height");
        session.finalize().expect("coinbase snapshot finalizes");

        let future = slot(1, coinbase_creation_id(8), 0xCC);
        let future_columns = columns(3, &[(4, future)]);
        let future_encoded = encode_segment(&future_columns, 3);
        let future_root = exact_segment_root_from_columns(3, &future_columns);
        let future_descriptor = SnapshotSegmentDescriptor {
            segment_id: 0,
            segment_root: future_root,
            encoded_len: future_encoded.len() as u32,
        };
        let mut future_session =
            SnapshotStagingSession::new(parent.path(), metadata, vec![future_descriptor]).unwrap();
        assert!(matches!(
            future_session.accept_segment(0, 3, &future_encoded),
            Err(
                SnapshotStagingError::CoinbaseCreationHeightExceedsBoundary {
                    segment_id: 0,
                    local_index: 4,
                    mint_height: 8,
                    snapshot_height: 7,
                }
            )
        ));
    }

    #[test]
    fn strict_length_and_exact_root_failures_abort_without_partial_files() {
        let parent = tempfile::tempdir().unwrap();
        let (metadata, descriptor, mut encoded) = fixture();
        let mut short_session =
            SnapshotStagingSession::new(parent.path(), metadata, vec![descriptor]).unwrap();
        let short_dir = short_session.staging_directory().unwrap().to_path_buf();
        assert!(matches!(
            short_session.accept_segment(0, 3, &encoded[..encoded.len() - 1]),
            Err(SnapshotStagingError::PayloadLength { segment_id: 0, .. })
        ));
        assert!(!short_dir.exists());

        let (_, mut changed_columns) = decode_segment(&encoded).unwrap();
        changed_columns.owners_hi[1] = Block128::from(0xC3u128);
        encoded = encode_segment(&changed_columns, 3);
        let mut root_session =
            SnapshotStagingSession::new(parent.path(), metadata, vec![descriptor]).unwrap();
        let root_dir = root_session.staging_directory().unwrap().to_path_buf();
        assert!(matches!(
            root_session.accept_segment(0, 3, &encoded),
            Err(SnapshotStagingError::ExactSegmentRootMismatch { segment_id: 0 })
        ));
        assert!(!root_dir.exists());
    }

    #[test]
    fn finalize_second_pass_detects_file_tampering_and_cleans() {
        let parent = tempfile::tempdir().unwrap();
        let (metadata, descriptor, encoded) = fixture();
        let mut session =
            SnapshotStagingSession::new(parent.path(), metadata, vec![descriptor]).unwrap();
        session.accept_segment(0, 3, &encoded).unwrap();
        let directory = session.staging_directory().unwrap().to_path_buf();
        let path = segment_path(&directory, 0);
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&path, permissions).unwrap();
        fs::write(&path, &encoded[..encoded.len() - 1]).unwrap();
        assert!(matches!(
            session.finalize(),
            Err(SnapshotStagingError::StagedFileLength { segment_id: 0, .. })
        ));
        assert!(!directory.exists());
    }

    #[test]
    fn finalized_iterator_reauthenticates_before_mdbx_handoff() {
        let parent = tempfile::tempdir().unwrap();
        let (metadata, descriptor, encoded) = fixture();
        let mut session =
            SnapshotStagingSession::new(parent.path(), metadata, vec![descriptor]).unwrap();
        session.accept_segment(0, 3, &encoded).unwrap();
        let finalized = session.finalize().unwrap();
        let directory = finalized.directory.as_ref().unwrap().clone();
        let path = segment_path(&directory, 0);
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&path, permissions).unwrap();
        let (_, mut changed_columns) = decode_segment(&encoded).unwrap();
        changed_columns.owners_hi[1] = Block128::from(0xC3u128);
        let tampered = encode_segment(&changed_columns, 3);
        fs::write(&path, tampered).unwrap();

        let staged = finalized.encoded_files().next().unwrap();
        assert!(matches!(
            staged.read_encoded(),
            Err(SnapshotStagingError::ExactSegmentRootMismatch { segment_id: 0 })
        ));
        drop(finalized);
        assert!(!directory.exists());
    }

    #[test]
    fn finalize_binds_header_live_count_and_exact_root() {
        let parent = tempfile::tempdir().unwrap();
        let (metadata, descriptor, encoded) = fixture();

        let mut count_header = *metadata.header();
        count_header.active_slot_count = 3;
        let count_metadata = AuthenticatedSnapshotMetadata::from_authenticated_header(
            count_header,
            block_id(&count_header),
            3,
        )
        .unwrap();
        let mut count_session =
            SnapshotStagingSession::new(parent.path(), count_metadata, vec![descriptor]).unwrap();
        count_session.accept_segment(0, 3, &encoded).unwrap();
        assert!(matches!(
            count_session.finalize(),
            Err(SnapshotStagingError::ActiveCountMismatch {
                expected: 3,
                actual: 2,
            })
        ));

        let mut root_header = *metadata.header();
        root_header.state_root[0] ^= 1;
        let root_metadata = AuthenticatedSnapshotMetadata::from_authenticated_header(
            root_header,
            block_id(&root_header),
            3,
        )
        .unwrap();
        let mut root_session =
            SnapshotStagingSession::new(parent.path(), root_metadata, vec![descriptor]).unwrap();
        root_session.accept_segment(0, 3, &encoded).unwrap();
        assert!(matches!(
            root_session.finalize(),
            Err(SnapshotStagingError::StateRootMismatch { .. })
        ));
    }

    #[test]
    fn incomplete_and_unsorted_sessions_fail_closed() {
        let parent = tempfile::tempdir().unwrap();
        let (metadata, descriptor, _) = fixture();
        let session =
            SnapshotStagingSession::new(parent.path(), metadata, vec![descriptor]).unwrap();
        let directory = session.staging_directory().unwrap().to_path_buf();
        assert!(matches!(
            session.finalize(),
            Err(SnapshotStagingError::Incomplete {
                received: 0,
                expected: 1,
            })
        ));
        assert!(!directory.exists());

        let log = 17;
        let hdr = header(log, zero_slot_roots(log as usize)[log as usize], 0, 0);
        let metadata = AuthenticatedSnapshotMetadata::from_authenticated_header(
            hdr,
            block_id(&hdr),
            LOG_SEGMENT_SIZE as u8,
        )
        .unwrap();
        let encoded_len =
            encoded_segment_len_for_live_count(LOG_SEGMENT_SIZE as u8, 1).unwrap() as u32;
        let descriptors = vec![
            SnapshotSegmentDescriptor {
                segment_id: 1,
                segment_root: [1; 32],
                encoded_len,
            },
            SnapshotSegmentDescriptor {
                segment_id: 0,
                segment_root: [2; 32],
                encoded_len,
            },
        ];
        assert!(matches!(
            SnapshotStagingSession::new(parent.path(), metadata, descriptors),
            Err(SnapshotStagingError::DescriptorOrder {
                previous: 1,
                current: 0,
            })
        ));
    }
}
