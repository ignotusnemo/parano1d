// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded-memory candidate-header staging for deep snapshot synchronization.
//!
//! Peer headers are consensus-validated against one fixed canonical base and
//! appended to a private, crash-disposable file. Once the complete suffix is
//! natively validated, it travels with the verified HistoryStep terminal and
//! is streamed into the same MDBX transaction as snapshot state and rewarded
//! tip. The file uses fixed-size records, so validation and restart
//! recovery retain only the consensus windows (currently at most 36 headers)
//! in memory regardless of candidate chain length.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::header::validate_header_timeless_prehashed_parent;
use noid_chain::consensus::params::{
    EPOCH_LENGTH, EXPANSION_HEADER_LOOKBACK, EXPANSION_WINDOW, MEDIAN_TIME_BLOCKS, TX_EPOCH_BLOCKS,
};
use noid_chain::consensus::{
    add_work, asert_anchor_height, block_work, finalized_expansion_window,
};
use noid_chain::storage::{MdbxStore, SnapshotHeaderInstallSource, VerifiedHeaderBatchRecord};
use noid_chain::wire::BLOCK_HEADER_WIRE_SIZE;
use noid_chain::{hash_block_header, HeaderChainAnchor};

const FILE_MAGIC: [u8; 8] = *b"NHSTAGE1";
const FILE_VERSION: u32 = 2;
const FILE_HEADER_SIZE: u64 = 8 + 4 + 4 + 8 + 32 + 32 + 8;
const RECORD_SIZE: usize = BLOCK_HEADER_WIRE_SIZE + 32 + 32;

/// Matches the P2P header response cap.  Keeping this explicit prevents an
/// accidentally unbounded caller-provided slice from becoming the temporary
/// working set even though the on-disk chain itself is not RAM-bounded.
pub const MAX_STAGED_HEADER_BATCH: usize = noid_p2p::header_sync_codec::MAX_HEADERS_PER_BATCH;

#[derive(Debug, thiserror::Error)]
pub enum SnapshotHeaderStagingError {
    #[error("snapshot header staging I/O: {0}")]
    Io(#[from] io::Error),
    #[error("snapshot header staging store error: {0}")]
    Store(String),
    #[error("snapshot header staging format error: {0}")]
    Format(&'static str),
    #[error("snapshot header candidate rejected at h={height}: {reason}")]
    InvalidCandidate { height: u64, reason: String },
    #[error("snapshot header candidate rejected at h={height}: BadParentHash")]
    ParentMismatch { height: u64 },
    #[error("snapshot header canonical base moved at h={height}: {reason}")]
    CanonicalBaseMoved { height: u64, reason: String },
    #[error("snapshot header canonical-store invariant failed at h={height}: {reason}")]
    CanonicalInvariant { height: u64, reason: String },
    #[error("validated snapshot header staging changed before atomic install: {0}")]
    VerifiedFileChanged(&'static str),
    #[error("snapshot header staging is poisoned by a failed durable write; reopen it")]
    Poisoned,
}

type Result<T> = std::result::Result<T, SnapshotHeaderStagingError>;

/// Distinguish an ordinary non-final canonical movement from a broken durable
/// invariant. A non-final base may legitimately change while snapshot headers
/// are staged; finalized canonical rows may not disappear or disagree.
fn canonical_source_error(
    height: u64,
    finalized_height_at_pin: u64,
    reason: impl Into<String>,
) -> SnapshotHeaderStagingError {
    let reason = reason.into();
    if height > finalized_height_at_pin {
        SnapshotHeaderStagingError::CanonicalBaseMoved { height, reason }
    } else {
        SnapshotHeaderStagingError::CanonicalInvariant { height, reason }
    }
}

/// Immutable canonical boundary from which one candidate suffix is built.
#[derive(Clone, Copy, Debug)]
pub struct CanonicalHeaderBoundary {
    pub header: BlockHeader,
    pub block_hash: [u8; 32],
    pub cumulative_chainwork: [u8; 32],
    finalized_height_at_pin: u64,
}

impl PartialEq for CanonicalHeaderBoundary {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
            && self.block_hash == other.block_hash
            && self.cumulative_chainwork == other.cumulative_chainwork
    }
}

impl Eq for CanonicalHeaderBoundary {}

impl CanonicalHeaderBoundary {
    /// Load a boundary which is backed by the canonical header-anchor table.
    /// Merely finding a loose header row is not sufficient authority.
    pub fn load(store: &MdbxStore, height: u64) -> Result<Self> {
        let finalized_height_at_pin = store
            .get_consensus_meta()
            .map_err(store_error)?
            .ok_or_else(|| SnapshotHeaderStagingError::CanonicalInvariant {
                height,
                reason: "canonical consensus metadata is missing".into(),
            })?
            .finalized
            .height;
        Self::load_with_pinned_finality(store, height, finalized_height_at_pin)
    }

    fn load_with_pinned_finality(
        store: &MdbxStore,
        height: u64,
        finalized_height_at_pin: u64,
    ) -> Result<Self> {
        let header = store
            .get_header(height)
            .map_err(store_error)?
            .ok_or_else(|| {
                canonical_source_error(
                    height,
                    finalized_height_at_pin,
                    "canonical base header is missing",
                )
            })?;
        let block_hash = hash_block_header(&header);
        let cumulative_chainwork = store
            .get_chain_work(height)
            .map_err(store_error)?
            .ok_or_else(|| {
                canonical_source_error(
                    height,
                    finalized_height_at_pin,
                    "canonical base chainwork is missing",
                )
            })?;
        let boundary = Self {
            header,
            block_hash,
            cumulative_chainwork,
            finalized_height_at_pin,
        };
        boundary.validate_against(store)?;
        Ok(boundary)
    }

    fn validate_against(&self, store: &MdbxStore) -> Result<()> {
        if self.header.height == u64::MAX {
            return Err(SnapshotHeaderStagingError::Format(
                "canonical base has no representable child height",
            ));
        }
        if hash_block_header(&self.header) != self.block_hash {
            return Err(SnapshotHeaderStagingError::CanonicalInvariant {
                height: self.header.height,
                reason: "base header does not match its claimed hash".into(),
            });
        }
        let stored_header = store
            .get_header(self.header.height)
            .map_err(store_error)?
            .ok_or_else(|| {
                canonical_source_error(
                    self.header.height,
                    self.finalized_height_at_pin,
                    "canonical base header disappeared",
                )
            })?;
        if stored_header != self.header {
            return Err(canonical_source_error(
                self.header.height,
                self.finalized_height_at_pin,
                "canonical base header changed",
            ));
        }
        if store
            .get_chain_work(self.header.height)
            .map_err(store_error)?
            != Some(self.cumulative_chainwork)
        {
            return Err(canonical_source_error(
                self.header.height,
                self.finalized_height_at_pin,
                "canonical base chainwork changed",
            ));
        }
        let expected_anchor = HeaderChainAnchor {
            height: self.header.height,
            block_id: self.block_hash,
            state_root: self.header.state_root,
            tx_root: self.header.tx_root,
            miner_address: self.header.miner_address,
            log_slots: self.header.log_slots,
            active_slot_count: self.header.active_slot_count,
            alloc_counter: self.header.alloc_counter,
            cumulative_chainwork: self.cumulative_chainwork,
        };
        if store
            .get_header_anchor(self.header.height)
            .map_err(store_error)?
            != Some(expected_anchor)
        {
            return Err(canonical_source_error(
                self.header.height,
                self.finalized_height_at_pin,
                "canonical base header anchor is missing or inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StagedHeaderRecord {
    header: BlockHeader,
    block_hash: [u8; 32],
    cumulative_chainwork: [u8; 32],
}

/// Stable identity captured when the writable staging handle is sealed.  The
/// length is part of the authority: an appended complete or partial record is
/// a different candidate even when the original prefix remains valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StagingFileIdentity {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl StagingFileIdentity {
    fn capture(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                len: metadata.len(),
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                len: metadata.len(),
            })
        }
    }

    fn same_file(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.device == other.device && self.inode == other.inode
        }
        #[cfg(not(unix))]
        {
            // The staging directory is private to the node.  On platforms
            // without a stable std file-id API, the already-open handle is
            // still authoritative and the exact length/content checks below
            // fail closed for ordinary local drift.
            let _ = other;
            true
        }
    }
}

/// Exact header inputs supplied to HistoryStep verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotHeaderBoundary {
    pub tip_header: BlockHeader,
    pub tip_hash: [u8; 32],
    pub cumulative_chainwork: [u8; 32],
    pub epoch_anchor_header: BlockHeader,
}

/// One isolated candidate suffix.  `count` is derived from fixed-size durable
/// records, never from an attacker-controlled decoded collection.
pub struct SnapshotHeaderStaging {
    path: PathBuf,
    file: File,
    base: CanonicalHeaderBoundary,
    count: u64,
    poisoned: bool,
    content_hasher: blake3::Hasher,
}

impl SnapshotHeaderStaging {
    /// Create a new staging file.  The base child must be the first currently
    /// missing canonical height, preventing accidental staging over a known
    /// canonical suffix.
    pub fn create(path: &Path, store: &MdbxStore, base: CanonicalHeaderBoundary) -> Result<Self> {
        base.validate_against(store)?;
        let first_missing = base.header.height + 1;
        if store
            .get_header(first_missing)
            .map_err(store_error)?
            .is_some()
        {
            return Err(SnapshotHeaderStagingError::CanonicalBaseMoved {
                height: first_missing,
                reason: "candidate base is not immediately before the first missing header".into(),
            });
        }

        Self::create_file(path, base)
    }

    /// Create an empty candidate at an already-canonical exact target. This
    /// keeps zero-missing-header syncs on the same terminal-verification
    /// typestate path without pretending that the target's child is missing.
    pub fn create_at_canonical_boundary(
        path: &Path,
        store: &MdbxStore,
        base: CanonicalHeaderBoundary,
    ) -> Result<Self> {
        base.validate_against(store)?;
        Self::create_file(path, base)
    }

    /// Create a candidate which replaces only the canonical suffix after an
    /// independently selected common ancestor. The caller must already hold
    /// HeaderDAG fork-choice authority for this exact base. Unlike `create`,
    /// an existing canonical child is expected here; the base itself must
    /// still be canonical and may never be below the pinned finalized point.
    pub fn create_at_nonfinal_rebase_boundary(
        path: &Path,
        store: &MdbxStore,
        base: CanonicalHeaderBoundary,
    ) -> Result<Self> {
        base.validate_against(store)?;
        if base.header.height < base.finalized_height_at_pin {
            return Err(SnapshotHeaderStagingError::CanonicalInvariant {
                height: base.header.height,
                reason: "snapshot rebase boundary is below finalized history".into(),
            });
        }
        Self::create_file(path, base)
    }

    fn create_file(path: &Path, base: CanonicalHeaderBoundary) -> Result<Self> {
        let mut file = secure_create_new(path)?;
        write_file_header(&mut file, &base)?;
        file.sync_all()?;
        sync_parent(path)?;
        Ok(Self {
            path: path.to_owned(),
            file,
            base,
            count: 0,
            poisoned: false,
            content_hasher: initial_content_hasher(&base),
        })
    }

    /// Reopen a crash-left staging file.  A partial final fixed-size record is
    /// truncated; every complete record is revalidated sequentially with a
    /// bounded consensus window before it is trusted.
    pub fn open(path: &Path, store: &MdbxStore) -> Result<Self> {
        let mut file = secure_open_existing(path)?;
        let encoded_base = read_file_header(&mut file)?;
        let base = CanonicalHeaderBoundary::load_with_pinned_finality(
            store,
            encoded_base.height,
            encoded_base.finalized_height_at_pin,
        )?;
        if base.block_hash != encoded_base.block_hash
            || base.cumulative_chainwork != encoded_base.cumulative_chainwork
        {
            return Err(canonical_source_error(
                base.header.height,
                encoded_base.finalized_height_at_pin,
                "staging file is pinned to a different canonical base",
            ));
        }

        let len = file.metadata()?.len();
        if len < FILE_HEADER_SIZE {
            return Err(SnapshotHeaderStagingError::Format(
                "file is shorter than its header",
            ));
        }
        let payload_len = len - FILE_HEADER_SIZE;
        let complete_len = payload_len - payload_len % RECORD_SIZE as u64;
        if complete_len != payload_len {
            file.set_len(FILE_HEADER_SIZE + complete_len)?;
            file.sync_all()?;
        }
        let count = complete_len / RECORD_SIZE as u64;
        let mut staging = Self {
            path: path.to_owned(),
            file,
            base,
            count,
            poisoned: false,
            content_hasher: initial_content_hasher(&base),
        };
        staging.revalidate_complete_file(store)?;
        Ok(staging)
    }

    pub fn base(&self) -> CanonicalHeaderBoundary {
        self.base
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn staged_len(&self) -> u64 {
        self.count
    }

    pub fn next_height(&self) -> Result<u64> {
        self.base
            .header
            .height
            .checked_add(self.count)
            .and_then(|height| height.checked_add(1))
            .ok_or(SnapshotHeaderStagingError::Format(
                "candidate height overflow",
            ))
    }

    /// Validate a response atomically at the batch level, then append it.
    /// A peer error leaves the previous durable prefix unchanged.  A process
    /// crash may leave a valid complete prefix plus one partial record, which
    /// `open` safely repairs.
    pub fn append_batch(&mut self, store: &MdbxStore, headers: &[BlockHeader]) -> Result<u64> {
        if self.poisoned {
            return Err(SnapshotHeaderStagingError::Poisoned);
        }
        if headers.is_empty() {
            return Err(SnapshotHeaderStagingError::InvalidCandidate {
                height: self.next_height()?,
                reason: "empty header batch".into(),
            });
        }
        if headers.len() > MAX_STAGED_HEADER_BATCH {
            return Err(SnapshotHeaderStagingError::InvalidCandidate {
                height: self.next_height()?,
                reason: format!(
                    "batch has {} headers, maximum is {MAX_STAGED_HEADER_BATCH}",
                    headers.len()
                ),
            });
        }
        // Validate and derive every record before writing. The bounded working
        // set makes a bad later header unable to partially commit an otherwise
        // valid batch, while each semantic block id is computed only once.
        let tip = self.tip_record()?;
        let mut expected_height =
            tip.header
                .height
                .checked_add(1)
                .ok_or(SnapshotHeaderStagingError::Format(
                    "candidate height overflow",
                ))?;
        let mut previous_hash = tip.block_hash;
        let mut previous_work = tip.cumulative_chainwork;
        let mut window = self.load_consensus_window(store, tip.header.height)?;
        let mut records = Vec::with_capacity(headers.len());
        for header in headers {
            validate_next_header(header, expected_height, previous_hash, &window)?;
            let block_hash = hash_block_header(header);
            let cumulative_chainwork =
                add_work(&previous_work, &block_work(&header.difficulty_target));
            records.push(StagedHeaderRecord {
                header: *header,
                block_hash,
                cumulative_chainwork,
            });
            previous_hash = block_hash;
            previous_work = cumulative_chainwork;
            push_window(&mut window, *header);
            expected_height =
                expected_height
                    .checked_add(1)
                    .ok_or(SnapshotHeaderStagingError::Format(
                        "candidate height overflow",
                    ))?;
        }

        // Write fixed-size sequential records. The staging file is disposable:
        // durability is established once when the complete candidate is
        // sealed, rather than forcing an fsync after every network range.
        let original_len = FILE_HEADER_SIZE
            .checked_add(self.count.checked_mul(RECORD_SIZE as u64).ok_or(
                SnapshotHeaderStagingError::Format("staging file length overflow"),
            )?)
            .ok_or(SnapshotHeaderStagingError::Format(
                "staging file length overflow",
            ))?;
        let write_result = (|| -> io::Result<()> {
            self.file.seek(SeekFrom::Start(original_len))?;
            for record in &records {
                write_record(&mut self.file, record)?;
            }
            Ok(())
        })();
        if let Err(error) = write_result {
            self.poisoned = true;
            let _ = self.file.set_len(original_len);
            let _ = self.file.sync_all();
            return Err(SnapshotHeaderStagingError::Io(error));
        }
        for record in &records {
            self.content_hasher.update(&encode_record(record));
        }
        self.count = self.count.checked_add(headers.len() as u64).ok_or(
            SnapshotHeaderStagingError::Format("staged header count overflow"),
        )?;
        Ok(expected_height)
    }

    /// Read one canonical-or-staged header without materializing the suffix.
    pub fn header_at(&mut self, store: &MdbxStore, height: u64) -> Result<Option<BlockHeader>> {
        if height <= self.base.header.height {
            return store.get_header(height).map_err(store_error);
        }
        let index = height - self.base.header.height - 1;
        if index >= self.count {
            return Ok(None);
        }
        Ok(Some(self.read_record(index)?.header))
    }

    /// Check that the already native-validated candidate crosses one exact
    /// HeaderDAG point. This binds a long on-disk suffix to bounded in-memory
    /// fork choice without loading the suffix back into RAM.
    pub fn matches_exact_point(
        &mut self,
        height: u64,
        expected_hash: [u8; 32],
        expected_chainwork: [u8; 32],
    ) -> Result<bool> {
        let record = if height == self.base.header.height {
            StagedHeaderRecord {
                header: self.base.header,
                block_hash: self.base.block_hash,
                cumulative_chainwork: self.base.cumulative_chainwork,
            }
        } else {
            let Some(index) = height
                .checked_sub(self.base.header.height.saturating_add(1))
                .filter(|index| *index < self.count)
            else {
                return Ok(false);
            };
            self.read_record(index)?
        };
        Ok(record.header.height == height
            && record.block_hash == expected_hash
            && record.cumulative_chainwork == expected_chainwork)
    }

    /// Bind the staged tip, exact work and transaction-epoch header.
    pub fn exact_boundary(
        &mut self,
        store: &MdbxStore,
        expected_height: u64,
        expected_hash: [u8; 32],
        expected_chainwork: [u8; 32],
    ) -> Result<SnapshotHeaderBoundary> {
        let tip = self.tip_record()?;
        if tip.header.height != expected_height {
            return Err(SnapshotHeaderStagingError::InvalidCandidate {
                height: tip.header.height,
                reason: format!("staged tip does not equal requested h={expected_height}"),
            });
        }
        if tip.block_hash != expected_hash {
            return Err(SnapshotHeaderStagingError::InvalidCandidate {
                height: expected_height,
                reason: "staged tip hash does not match candidate manifest".into(),
            });
        }
        if tip.cumulative_chainwork != expected_chainwork {
            return Err(SnapshotHeaderStagingError::InvalidCandidate {
                height: expected_height,
                reason: "staged exact chainwork does not match candidate manifest".into(),
            });
        }
        let epoch_height = noid_chain::consensus::tx_epoch_anchor_height_for_child(expected_height);
        let epoch_anchor_header = self.header_at(store, epoch_height)?.ok_or(
            SnapshotHeaderStagingError::InvalidCandidate {
                height: epoch_height,
                reason: "transaction-epoch anchor header is missing".into(),
            },
        )?;
        Ok(SnapshotHeaderBoundary {
            tip_header: tip.header,
            tip_hash: tip.block_hash,
            cumulative_chainwork: tip.cumulative_chainwork,
            epoch_anchor_header,
        })
    }

    /// Validate and read-only seal a complete native header chain before it
    /// may enter the atomic snapshot installation transaction.
    pub fn validate_complete(
        mut self,
        store: &MdbxStore,
        expected_height: u64,
        expected_hash: [u8; 32],
        expected_chainwork: [u8; 32],
    ) -> Result<ValidatedSnapshotHeaderStaging> {
        // Establish the candidate's single durability point, then replace the
        // writable descriptor with a read-only O_NOFOLLOW descriptor for the
        // same inode. Consensus rules were already checked exactly once while
        // appending. The atomic installer streams the file through the expected
        // digest and cannot commit any bytes which differ from that pass.
        self.file.sync_data()?;
        let writable_identity = StagingFileIdentity::capture(&self.file)?;
        let expected_len = staged_file_len(self.count)?;
        if writable_identity.len != expected_len {
            return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
                "staging length changed before read-only sealing",
            ));
        }
        let read_only = secure_open_existing_read_only(&self.path)?;
        let read_only_identity = StagingFileIdentity::capture(&read_only)?;
        if !writable_identity.same_file(&read_only_identity)
            || read_only_identity.len != writable_identity.len
        {
            return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
                "staging path no longer names the verified inode and length",
            ));
        }
        self.file = read_only;
        let expected_digest = *self.content_hasher.finalize().as_bytes();
        let boundary =
            self.exact_boundary(store, expected_height, expected_hash, expected_chainwork)?;
        let sealed_identity = StagingFileIdentity::capture(&self.file)?;
        if sealed_identity != read_only_identity {
            return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
                "staging metadata changed while sealing",
            ));
        }
        let history_window = MEDIAN_TIME_BLOCKS as u64 + TX_EPOCH_BLOCKS;
        let first_recent = boundary.tip_header.height.saturating_sub(history_window);
        let mut recent_headers = Vec::with_capacity(
            boundary
                .tip_header
                .height
                .saturating_sub(first_recent)
                .saturating_add(1) as usize,
        );
        for height in first_recent..=boundary.tip_header.height {
            let header = self.header_at(store, height)?.ok_or_else(|| {
                if height <= self.base.header.height {
                    canonical_source_error(
                        height,
                        self.base.finalized_height_at_pin,
                        "header required by the post-snapshot consensus window is missing",
                    )
                } else {
                    SnapshotHeaderStagingError::Format(
                        "staged post-snapshot consensus-window header is missing",
                    )
                }
            })?;
            recent_headers.push(header);
        }
        if StagingFileIdentity::capture(&self.file)? != sealed_identity {
            return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
                "staging metadata changed while reading the recent header window",
            ));
        }
        Ok(ValidatedSnapshotHeaderStaging {
            staging: self,
            boundary,
            file_identity: sealed_identity,
            expected_digest,
            recent_headers,
            next_install_index: 0,
            install_hasher: blake3::Hasher::new(),
            install_started: false,
            install_complete: false,
        })
    }

    /// Explicitly destroy a rejected or superseded candidate.
    pub fn discard(self) -> Result<()> {
        let identity = StagingFileIdentity::capture(&self.file)?;
        let path = self.path.clone();
        drop(self);
        remove_staging_file_if_same(&path, identity)
    }

    fn tip_record(&mut self) -> Result<StagedHeaderRecord> {
        if self.count == 0 {
            return Ok(StagedHeaderRecord {
                header: self.base.header,
                block_hash: self.base.block_hash,
                cumulative_chainwork: self.base.cumulative_chainwork,
            });
        }
        self.read_record(self.count - 1)
    }

    fn read_record(&mut self, index: u64) -> Result<StagedHeaderRecord> {
        decode_record(&self.read_record_bytes(index)?)
    }

    fn load_consensus_window(
        &mut self,
        store: &MdbxStore,
        tip_height: u64,
    ) -> Result<VecDeque<BlockHeader>> {
        let max_window = consensus_window_len();
        let start = tip_height.saturating_sub(max_window as u64 - 1);
        let mut window = VecDeque::with_capacity(max_window);
        for height in start..=tip_height {
            let header = self.header_at(store, height)?.ok_or_else(|| {
                if height <= self.base.header.height {
                    canonical_source_error(
                        height,
                        self.base.finalized_height_at_pin,
                        "header needed by the bounded consensus window is missing",
                    )
                } else {
                    SnapshotHeaderStagingError::Format(
                        "staged bounded consensus-window header is missing",
                    )
                }
            })?;
            window.push_back(header);
        }
        Ok(window)
    }

    fn revalidate_complete_file(&mut self, store: &MdbxStore) -> Result<()> {
        self.base.validate_against(store)?;
        let identity = StagingFileIdentity::capture(&self.file)?;
        if identity.len != staged_file_len(self.count)? {
            return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
                "staging file has an appended or partial record",
            ));
        }
        let encoded_base = read_file_header(&mut self.file)?;
        if encoded_base.height != self.base.header.height
            || encoded_base.block_hash != self.base.block_hash
            || encoded_base.cumulative_chainwork != self.base.cumulative_chainwork
            || encoded_base.finalized_height_at_pin != self.base.finalized_height_at_pin
        {
            return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
                "staging file base header changed",
            ));
        }
        let mut content_hasher = initial_content_hasher(&self.base);
        let mut window = self.load_canonical_window(store)?;
        let mut previous_hash = self.base.block_hash;
        let mut previous_work = self.base.cumulative_chainwork;
        let mut expected_height = self.base.header.height + 1;
        for index in 0..self.count {
            let encoded = self.read_record_bytes(index)?;
            let record = decode_record(&encoded)?;
            validate_next_header(&record.header, expected_height, previous_hash, &window)?;
            let block_hash = hash_block_header(&record.header);
            if block_hash != record.block_hash {
                return Err(SnapshotHeaderStagingError::InvalidCandidate {
                    height: expected_height,
                    reason: "record hash does not match header".into(),
                });
            }
            let expected_work = add_work(
                &previous_work,
                &block_work(&record.header.difficulty_target),
            );
            if record.cumulative_chainwork != expected_work {
                return Err(SnapshotHeaderStagingError::InvalidCandidate {
                    height: expected_height,
                    reason: "record does not contain exact cumulative chainwork".into(),
                });
            }
            previous_hash = block_hash;
            previous_work = expected_work;
            push_window(&mut window, record.header);
            content_hasher.update(&encoded);
            expected_height =
                expected_height
                    .checked_add(1)
                    .ok_or(SnapshotHeaderStagingError::Format(
                        "candidate height overflow",
                    ))?;
        }
        self.content_hasher = content_hasher;
        Ok(())
    }

    fn read_record_bytes(&mut self, index: u64) -> Result<[u8; RECORD_SIZE]> {
        if index >= self.count {
            return Err(SnapshotHeaderStagingError::Format(
                "record index is beyond staged suffix",
            ));
        }
        self.file.seek(SeekFrom::Start(record_offset(index)?))?;
        let mut bytes = [0u8; RECORD_SIZE];
        self.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn load_canonical_window(&self, store: &MdbxStore) -> Result<VecDeque<BlockHeader>> {
        let max_window = consensus_window_len();
        let start = self
            .base
            .header
            .height
            .saturating_sub(max_window as u64 - 1);
        let mut window = VecDeque::with_capacity(max_window);
        for height in start..=self.base.header.height {
            let header = store
                .get_header(height)
                .map_err(store_error)?
                .ok_or_else(|| {
                    canonical_source_error(
                        height,
                        self.base.finalized_height_at_pin,
                        "canonical consensus-window header is missing",
                    )
                })?;
            window.push_back(header);
        }
        Ok(window)
    }
}

/// A fully native-validated, read-only header suffix. No public constructor
/// exists, so unvalidated bytes cannot reach the permanent header archive.
pub struct ValidatedSnapshotHeaderStaging {
    staging: SnapshotHeaderStaging,
    boundary: SnapshotHeaderBoundary,
    file_identity: StagingFileIdentity,
    expected_digest: [u8; 32],
    recent_headers: Vec<BlockHeader>,
    next_install_index: u64,
    install_hasher: blake3::Hasher,
    install_started: bool,
    install_complete: bool,
}

impl ValidatedSnapshotHeaderStaging {
    pub fn boundary(&self) -> SnapshotHeaderBoundary {
        self.boundary
    }

    pub fn discard(self) -> Result<()> {
        self.staging.discard()
    }

    fn assert_file_unchanged_before_read(&self) -> Result<()> {
        let current = StagingFileIdentity::capture(&self.staging.file)?;
        if current != self.file_identity {
            return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
                "verified descriptor identity or length changed",
            ));
        }
        Ok(())
    }
}

impl SnapshotHeaderInstallSource for ValidatedSnapshotHeaderStaging {
    fn base_record(&self) -> VerifiedHeaderBatchRecord {
        VerifiedHeaderBatchRecord {
            header: self.staging.base.header,
            hash: self.staging.base.block_hash,
            cumulative_chainwork: self.staging.base.cumulative_chainwork,
        }
    }

    fn target_record(&self) -> VerifiedHeaderBatchRecord {
        VerifiedHeaderBatchRecord {
            header: self.boundary.tip_header,
            hash: self.boundary.tip_hash,
            cumulative_chainwork: self.boundary.cumulative_chainwork,
        }
    }

    fn recent_headers(&self) -> &[BlockHeader] {
        &self.recent_headers
    }

    fn next_record(&mut self) -> std::result::Result<Option<VerifiedHeaderBatchRecord>, String> {
        if !self.install_started {
            self.assert_file_unchanged_before_read()
                .map_err(|error| error.to_string())?;
            self.staging
                .file
                .seek(SeekFrom::Start(0))
                .map_err(|error| error.to_string())?;
            let mut file_header = [0u8; FILE_HEADER_SIZE as usize];
            self.staging
                .file
                .read_exact(&mut file_header)
                .map_err(|error| error.to_string())?;
            self.install_hasher.update(&file_header);
            self.install_started = true;
        }
        if self.next_install_index == self.staging.count {
            if !self.install_complete {
                self.assert_file_unchanged_before_read()
                    .map_err(|error| error.to_string())?;
                if self.install_hasher.finalize().as_bytes() != &self.expected_digest {
                    return Err(
                        "snapshot header staging content changed during atomic install".into(),
                    );
                }
                self.install_complete = true;
            }
            return Ok(None);
        }
        if self.next_install_index > self.staging.count {
            return Err("snapshot header staging stream advanced beyond its sealed suffix".into());
        }
        let mut encoded = [0u8; RECORD_SIZE];
        self.staging
            .file
            .read_exact(&mut encoded)
            .map_err(|error| error.to_string())?;
        let record = decode_record(&encoded).map_err(|error| error.to_string())?;
        self.install_hasher.update(&encoded);
        self.next_install_index += 1;
        Ok(Some(VerifiedHeaderBatchRecord {
            header: record.header,
            hash: record.block_hash,
            cumulative_chainwork: record.cumulative_chainwork,
        }))
    }
}

fn validate_next_header(
    header: &BlockHeader,
    expected_height: u64,
    parent_id: [u8; 32],
    window: &VecDeque<BlockHeader>,
) -> Result<()> {
    if header.height != expected_height {
        return Err(SnapshotHeaderStagingError::InvalidCandidate {
            height: header.height,
            reason: format!("expected contiguous h={expected_height}"),
        });
    }
    let parent = window
        .back()
        .ok_or(SnapshotHeaderStagingError::Format("empty consensus window"))?;
    let timestamp_start = window.len().saturating_sub(MEDIAN_TIME_BLOCKS);
    let timestamp_len = window.len() - timestamp_start;
    let mut prev_timestamps = [0u64; MEDIAN_TIME_BLOCKS];
    for (slot, ancestor) in prev_timestamps
        .iter_mut()
        .zip(window.iter().skip(timestamp_start))
    {
        *slot = ancestor.timestamp;
    }
    let (finalized_active_counts, expansion_len) =
        finalized_active_counts_for_parent(parent.height, window)?;
    let anchor_height = asert_anchor_height(parent.height);
    let anchor = window
        .iter()
        .find(|ancestor| ancestor.height == anchor_height)
        .ok_or(SnapshotHeaderStagingError::InvalidCandidate {
            height: header.height,
            reason: format!("ASERT anchor h={anchor_height} is outside the validated window"),
        })?;
    validate_header_timeless_prehashed_parent(
        header,
        parent,
        parent_id,
        &prev_timestamps[..timestamp_len],
        &finalized_active_counts[..expansion_len],
        anchor_height,
        anchor.timestamp,
        &anchor.difficulty_target,
    )
    .map_err(|error| match error {
        noid_chain::consensus::ConsensusError::BadParentHash => {
            SnapshotHeaderStagingError::ParentMismatch {
                height: header.height,
            }
        }
        error => SnapshotHeaderStagingError::InvalidCandidate {
            height: header.height,
            reason: error.to_string(),
        },
    })
}

/// Validate one bounded in-memory extension before its block bodies can steer
/// sync or fork choice. This is the same native header relation used by deep
/// snapshot staging, anchored at an exact canonical header record, but without
/// creating a durable candidate file for a recent suffix.
pub fn validate_bounded_header_extension(
    store: &MdbxStore,
    ancestor_height: u64,
    headers: &[BlockHeader],
    local_time: u64,
) -> Result<[u8; 32]> {
    if headers.is_empty() {
        return Err(SnapshotHeaderStagingError::InvalidCandidate {
            height: ancestor_height,
            reason: "empty header extension".into(),
        });
    }
    if headers.len() > MAX_STAGED_HEADER_BATCH {
        return Err(SnapshotHeaderStagingError::InvalidCandidate {
            height: ancestor_height.saturating_add(1),
            reason: format!(
                "extension has {} headers, maximum is {MAX_STAGED_HEADER_BATCH}",
                headers.len()
            ),
        });
    }

    let base = CanonicalHeaderBoundary::load(store, ancestor_height)?;
    let max_window = consensus_window_len();
    let start = ancestor_height.saturating_sub(max_window as u64 - 1);
    let mut window = VecDeque::with_capacity(max_window);
    for height in start..=ancestor_height {
        let header = store
            .get_header(height)
            .map_err(store_error)?
            .ok_or_else(|| {
                canonical_source_error(
                    height,
                    base.finalized_height_at_pin,
                    "canonical consensus-window header is missing",
                )
            })?;
        window.push_back(header);
    }

    let mut expected_height =
        ancestor_height
            .checked_add(1)
            .ok_or(SnapshotHeaderStagingError::Format(
                "candidate height overflow",
            ))?;
    let mut cumulative_chainwork = base.cumulative_chainwork;
    let mut previous_hash = base.block_hash;
    for header in headers {
        validate_next_header(header, expected_height, previous_hash, &window)?;
        noid_chain::consensus::validate_future_drift(header.timestamp, local_time).map_err(
            |error| SnapshotHeaderStagingError::InvalidCandidate {
                height: header.height,
                reason: error.to_string(),
            },
        )?;
        cumulative_chainwork = add_work(
            &cumulative_chainwork,
            &block_work(&header.difficulty_target),
        );
        previous_hash = hash_block_header(header);
        push_window(&mut window, *header);
        expected_height =
            expected_height
                .checked_add(1)
                .ok_or(SnapshotHeaderStagingError::Format(
                    "candidate height overflow",
                ))?;
    }
    Ok(cumulative_chainwork)
}

fn finalized_active_counts_for_parent(
    parent_height: u64,
    window: &VecDeque<BlockHeader>,
) -> Result<([u64; EXPANSION_WINDOW as usize], usize)> {
    let mut counts = [0u64; EXPANSION_WINDOW as usize];
    let Some((start, end)) = finalized_expansion_window(parent_height) else {
        return Ok((counts, 0));
    };
    let first_height = window
        .front()
        .ok_or(SnapshotHeaderStagingError::Format("empty consensus window"))?
        .height;
    let offset = start
        .checked_sub(first_height)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(SnapshotHeaderStagingError::InvalidCandidate {
            height: parent_height.saturating_add(1),
            reason: "hard-finalized expansion window is outside the validated suffix".into(),
        })?;
    for (index, height) in (start..=end).enumerate() {
        let ancestor =
            window
                .get(offset + index)
                .ok_or(SnapshotHeaderStagingError::InvalidCandidate {
                    height: parent_height.saturating_add(1),
                    reason: "hard-finalized expansion window is incomplete".into(),
                })?;
        if ancestor.height != height {
            return Err(SnapshotHeaderStagingError::InvalidCandidate {
                height: parent_height.saturating_add(1),
                reason: "hard-finalized expansion window is not contiguous".into(),
            });
        }
        counts[index] = ancestor.active_slot_count;
    }
    Ok((counts, EXPANSION_WINDOW as usize))
}

fn consensus_window_len() -> usize {
    usize::try_from(EXPANSION_HEADER_LOOKBACK.saturating_add(1))
        .unwrap_or(usize::MAX)
        .max(MEDIAN_TIME_BLOCKS)
        .max(usize::try_from(EPOCH_LENGTH).unwrap_or(usize::MAX))
        .max(1)
}

fn push_window(window: &mut VecDeque<BlockHeader>, header: BlockHeader) {
    if window.len() == consensus_window_len() {
        window.pop_front();
    }
    window.push_back(header);
}

fn write_file_header(file: &mut File, base: &CanonicalHeaderBoundary) -> io::Result<()> {
    file.write_all(&encode_file_header(base))
}

fn encode_file_header(base: &CanonicalHeaderBoundary) -> [u8; FILE_HEADER_SIZE as usize] {
    let mut encoded = [0u8; FILE_HEADER_SIZE as usize];
    encoded[..8].copy_from_slice(&FILE_MAGIC);
    encoded[8..12].copy_from_slice(&FILE_VERSION.to_le_bytes());
    encoded[12..16].copy_from_slice(&(RECORD_SIZE as u32).to_le_bytes());
    encoded[16..24].copy_from_slice(&base.header.height.to_le_bytes());
    encoded[24..56].copy_from_slice(&base.block_hash);
    encoded[56..88].copy_from_slice(&base.cumulative_chainwork);
    encoded[88..96].copy_from_slice(&base.finalized_height_at_pin.to_le_bytes());
    encoded
}

fn initial_content_hasher(base: &CanonicalHeaderBoundary) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&encode_file_header(base));
    hasher
}

#[derive(Clone, Copy)]
struct EncodedBase {
    height: u64,
    block_hash: [u8; 32],
    cumulative_chainwork: [u8; 32],
    finalized_height_at_pin: u64,
}

fn read_file_header(file: &mut File) -> Result<EncodedBase> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = [0u8; FILE_HEADER_SIZE as usize];
    file.read_exact(&mut bytes)?;
    if bytes[..8] != FILE_MAGIC {
        return Err(SnapshotHeaderStagingError::Format("bad file magic"));
    }
    if u32::from_le_bytes(bytes[8..12].try_into().expect("fixed range")) != FILE_VERSION {
        return Err(SnapshotHeaderStagingError::Format(
            "unsupported file version",
        ));
    }
    if u32::from_le_bytes(bytes[12..16].try_into().expect("fixed range")) as usize != RECORD_SIZE {
        return Err(SnapshotHeaderStagingError::Format(
            "record size does not match this build",
        ));
    }
    let height = u64::from_le_bytes(bytes[16..24].try_into().expect("fixed range"));
    let block_hash = bytes[24..56].try_into().expect("fixed range");
    let cumulative_chainwork = bytes[56..88].try_into().expect("fixed range");
    let finalized_height_at_pin =
        u64::from_le_bytes(bytes[88..96].try_into().expect("fixed range"));
    // The header itself is deliberately sourced from canonical MDBX during
    // `open`; only its identity and work are persisted in this untrusted file.
    Ok(EncodedBase {
        height,
        block_hash,
        cumulative_chainwork,
        finalized_height_at_pin,
    })
}

fn write_record(file: &mut File, record: &StagedHeaderRecord) -> io::Result<()> {
    file.write_all(&encode_record(record))
}

fn encode_record(record: &StagedHeaderRecord) -> [u8; RECORD_SIZE] {
    let mut encoded = [0u8; RECORD_SIZE];
    encoded[..BLOCK_HEADER_WIRE_SIZE].copy_from_slice(&record.header.to_bytes());
    encoded[BLOCK_HEADER_WIRE_SIZE..BLOCK_HEADER_WIRE_SIZE + 32]
        .copy_from_slice(&record.block_hash);
    encoded[BLOCK_HEADER_WIRE_SIZE + 32..].copy_from_slice(&record.cumulative_chainwork);
    encoded
}

fn decode_record(bytes: &[u8; RECORD_SIZE]) -> Result<StagedHeaderRecord> {
    let header = BlockHeader::from_bytes(&bytes[..BLOCK_HEADER_WIRE_SIZE])
        .map_err(|_| SnapshotHeaderStagingError::Format("record contains an invalid header"))?;
    let block_hash = bytes[BLOCK_HEADER_WIRE_SIZE..BLOCK_HEADER_WIRE_SIZE + 32]
        .try_into()
        .expect("fixed range");
    let cumulative_chainwork = bytes[BLOCK_HEADER_WIRE_SIZE + 32..]
        .try_into()
        .expect("fixed range");
    Ok(StagedHeaderRecord {
        header,
        block_hash,
        cumulative_chainwork,
    })
}

fn record_offset(index: u64) -> Result<u64> {
    FILE_HEADER_SIZE
        .checked_add(
            index
                .checked_mul(RECORD_SIZE as u64)
                .ok_or(SnapshotHeaderStagingError::Format("record offset overflow"))?,
        )
        .ok_or(SnapshotHeaderStagingError::Format("record offset overflow"))
}

fn staged_file_len(count: u64) -> Result<u64> {
    FILE_HEADER_SIZE
        .checked_add(count.checked_mul(RECORD_SIZE as u64).ok_or(
            SnapshotHeaderStagingError::Format("staging file length overflow"),
        )?)
        .ok_or(SnapshotHeaderStagingError::Format(
            "staging file length overflow",
        ))
}

fn store_error(error: impl std::fmt::Display) -> SnapshotHeaderStagingError {
    SnapshotHeaderStagingError::Store(error.to_string())
}

fn secure_create_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn secure_open_existing(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn secure_open_existing_read_only(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn remove_staging_file_if_same(path: &Path, expected: StagingFileIdentity) -> Result<()> {
    let current = match secure_open_existing_read_only(path) {
        Ok(file) => StagingFileIdentity::capture(&file)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(SnapshotHeaderStagingError::Io(error)),
    };
    if !expected.same_file(&current) {
        return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
            "cleanup path no longer names the staged inode",
        ));
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SnapshotHeaderStagingError::Io(error)),
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::genesis::genesis_header;
    use noid_chain::consensus::next_target;
    use noid_chain::consensus::params::BLOCK_TIME;
    use std::sync::OnceLock;

    #[test]
    fn canonical_movement_is_classified_against_pinned_finality() {
        assert!(matches!(
            canonical_source_error(11, 10, "moved"),
            SnapshotHeaderStagingError::CanonicalBaseMoved { height: 11, .. }
        ));
        assert!(matches!(
            canonical_source_error(10, 10, "broken"),
            SnapshotHeaderStagingError::CanonicalInvariant { height: 10, .. }
        ));
    }

    fn occupancy_header(height: u64, active_slot_count: u64) -> BlockHeader {
        let mut header = genesis_header();
        header.height = height;
        header.active_slot_count = active_slot_count;
        header.alloc_counter = active_slot_count;
        header
    }

    #[test]
    fn snapshot_validation_uses_only_the_depth_finalized_window() {
        assert_eq!(consensus_window_len(), 36);
        let window = (65..=100)
            .map(|height| occupancy_header(height, if height <= 82 { height } else { u64::MAX }))
            .collect::<VecDeque<_>>();

        let (counts, len) = finalized_active_counts_for_parent(100, &window).unwrap();
        assert_eq!(len, EXPANSION_WINDOW as usize);
        assert_eq!(&counts[..len], &(65..=82).collect::<Vec<_>>());
        assert!(
            !counts[..len].contains(&u64::MAX),
            "unfinalized tip values must not enter the expansion decision"
        );
    }

    #[test]
    fn snapshot_validation_requires_the_complete_finalized_window() {
        let early = (0..=34)
            .map(|height| occupancy_header(height, u64::MAX))
            .collect::<VecDeque<_>>();
        let (_, len) = finalized_active_counts_for_parent(34, &early).unwrap();
        assert_eq!(len, 0);

        let incomplete = (66..=100)
            .map(|height| occupancy_header(height, height))
            .collect::<VecDeque<_>>();
        assert!(finalized_active_counts_for_parent(100, &incomplete).is_err());
    }

    fn fixture_chain() -> &'static [BlockHeader] {
        static HEADERS: OnceLock<Vec<BlockHeader>> = OnceLock::new();
        HEADERS.get_or_init(|| {
            let mut headers = vec![genesis_header()];
            for height in 1..=1u64 {
                let parent = *headers.last().expect("genesis");
                let anchor_height = asert_anchor_height(parent.height);
                let anchor = headers
                    .iter()
                    .find(|header| header.height == anchor_height)
                    .expect("short fixture anchor");
                let timestamp = parent.timestamp + BLOCK_TIME;
                let header = BlockHeader {
                    prev_block_hash: hash_block_header(&parent),
                    state_root: [height as u8; 32],
                    tx_root: [0x40 + height as u8; 32],
                    timestamp,
                    height,
                    miner_address: parent.miner_address,
                    // Pre-mined for this exact deterministic fixture. Keeping
                    // it fixed avoids debug-mode PoW work in CI.
                    nonce: 58_902,
                    difficulty_target: next_target(
                        anchor_height,
                        anchor.timestamp,
                        &anchor.difficulty_target,
                        height,
                        timestamp,
                    ),
                    log_slots: parent.log_slots,
                    active_slot_count: parent.active_slot_count,
                    alloc_counter: parent.alloc_counter,
                };
                headers.push(header);
            }
            headers
        })
    }

    /// Print a fresh pre-mined nonce for `fixture_chain` after header-layout
    /// changes. Run with:
    /// `cargo test --release -p noid_node print_new_fixture_nonce -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_new_fixture_nonce() {
        let mut header = fixture_chain()[1];
        header.nonce = 0;
        let nonce = noid_chain::consensus::pow::search_pow(&header, 0, 2_000_000_000)
            .expect("fixture target is satisfiable");
        println!("\nNew fixture nonce: {nonce}");
    }

    fn canonical_base(store: &MdbxStore) -> CanonicalHeaderBoundary {
        CanonicalHeaderBoundary::load(store, 0).expect("load base")
    }

    fn native_coinbase_child(chain: &noid_chain::storage::MdbxChainContext) -> noid_chain::Block {
        let parent = *chain.tip_header();
        let timestamp = parent.timestamp + BLOCK_TIME;
        let anchor = chain.anchor_info().unwrap();
        let difficulty_target = next_target(
            anchor.anchor_height,
            anchor.anchor_timestamp,
            &anchor.anchor_target,
            parent.height + 1,
            timestamp,
        );
        noid_chain::consensus::build_block_template(
            &parent,
            &chain.state,
            &chain.finalized_active_counts().unwrap(),
            Vec::new(),
            parent.miner_address,
            timestamp,
            difficulty_target,
        )
        .expect("build native-valid coinbase child")
        // Pre-mined for this exact deterministic coinbase-only template.
        .into_block(382_055)
    }

    /// Print a fresh pre-mined nonce for `native_coinbase_child` after a
    /// consensus or block-layout change.
    #[test]
    #[ignore]
    fn print_new_native_coinbase_child_nonce() {
        let db = tempfile::tempdir().unwrap();
        let chain = noid_chain::storage::MdbxChainContext::open_or_create(db.path()).unwrap();
        let child = native_coinbase_child(&chain);
        let nonce = noid_chain::consensus::pow::search_pow(&child.header, 0, 2_000_000_000)
            .expect("fixture target is satisfiable");
        println!("\nNew native coinbase child nonce: {nonce}");
    }

    fn fixture_terminal(height: u64, hash: [u8; 32]) -> Vec<u8> {
        let mut bytes = noid_chain::HistoryStepTerminalMetadata::new(height, hash, 0)
            .unwrap()
            .encode_prefix()
            .to_vec();
        bytes.push(1);
        bytes
    }

    #[test]
    fn invalid_late_header_does_not_partially_append_batch() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let chain = noid_chain::storage::MdbxChainContext::open_or_create(db.path()).unwrap();
        let store = &chain.store;
        let base = canonical_base(store);
        let mut staging =
            SnapshotHeaderStaging::create(&stage_dir.path().join("candidate"), store, base)
                .unwrap();
        let mut bad_second = fixture_chain()[1];
        bad_second.height = 2;
        bad_second.timestamp += BLOCK_TIME;
        bad_second.prev_block_hash = [0xAA; 32];
        assert!(staging
            .append_batch(store, &[fixture_chain()[1], bad_second])
            .is_err());
        assert_eq!(staging.staged_len(), 0);
        assert!(store.get_header(1).unwrap().is_none());
    }

    #[test]
    fn first_parent_mismatch_is_typed_for_rebase_discovery() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let chain = noid_chain::storage::MdbxChainContext::open_or_create(db.path()).unwrap();
        let store = &chain.store;
        let base = canonical_base(store);
        let mut staging =
            SnapshotHeaderStaging::create(&stage_dir.path().join("candidate"), store, base)
                .unwrap();
        let mut competing = fixture_chain()[1];
        competing.prev_block_hash = [0xA5; 32];

        assert!(matches!(
            staging.append_batch(store, &[competing]),
            Err(SnapshotHeaderStagingError::ParentMismatch { height: 1 })
        ));
        assert_eq!(staging.staged_len(), 0);
    }

    #[test]
    fn restart_recovers_complete_prefix_and_truncates_partial_tail() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let path = stage_dir.path().join("candidate");
        let chain = noid_chain::storage::MdbxChainContext::open_or_create(db.path()).unwrap();
        let store = &chain.store;
        let base = canonical_base(store);
        {
            let mut staging = SnapshotHeaderStaging::create(&path, store, base).unwrap();
            staging
                .append_batch(store, &fixture_chain()[1..=1])
                .unwrap();
        }
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&[0xCC; 17]).unwrap();
            file.sync_all().unwrap();
        }
        let reopened = SnapshotHeaderStaging::open(&path, store).unwrap();
        assert_eq!(reopened.staged_len(), 1);
        assert_eq!(reopened.next_height().unwrap(), 2);
        assert_eq!(
            reopened.base.finalized_height_at_pin,
            base.finalized_height_at_pin
        );
    }

    #[test]
    fn tampered_valid_looking_tip_cannot_match_the_sealed_install_boundary() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let path = stage_dir.path().join("candidate");
        let chain = noid_chain::storage::MdbxChainContext::open_or_create(db.path()).unwrap();
        let store = &chain.store;
        let base = canonical_base(store);
        let mut staging = SnapshotHeaderStaging::create(&path, store, base).unwrap();
        staging
            .append_batch(store, &fixture_chain()[1..=1])
            .unwrap();
        let tip = staging.tip_record().unwrap();
        let mut validated = staging
            .validate_complete(
                store,
                tip.header.height,
                tip.block_hash,
                tip.cumulative_chainwork,
            )
            .unwrap();

        // The replacement is a complete, parseable fixed-size record with a
        // self-consistent header hash.  It is nevertheless not the exact
        // validated candidate tip and must never reach the header archive.
        let mut changed_header = fixture_chain()[1];
        changed_header.state_root = [0xA5; 32];
        let changed = StagedHeaderRecord {
            header: changed_header,
            block_hash: hash_block_header(&changed_header),
            cumulative_chainwork: tip.cumulative_chainwork,
        };
        let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
        writer
            .seek(SeekFrom::Start(record_offset(0).unwrap()))
            .unwrap();
        write_record(&mut writer, &changed).unwrap();
        writer.sync_all().unwrap();
        drop(writer);

        let streamed = validated.next_record().unwrap().unwrap();
        assert_eq!(streamed.header, changed_header);
        assert_ne!(streamed, validated.target_record());
        assert!(validated.next_record().is_err());
        assert!(store.get_header(1).unwrap().is_none());
        assert!(store.get_chain_work(1).unwrap().is_none());
    }

    #[test]
    fn staged_candidate_can_be_bound_to_an_exact_header_dag_point() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let path = stage_dir.path().join("candidate");
        let chain = noid_chain::storage::MdbxChainContext::open_or_create(db.path()).unwrap();
        let store = &chain.store;
        let base = canonical_base(store);
        let mut staging = SnapshotHeaderStaging::create(&path, store, base).unwrap();
        staging
            .append_batch(store, &fixture_chain()[1..=1])
            .unwrap();
        let tip = staging.tip_record().unwrap();

        assert!(staging
            .matches_exact_point(tip.header.height, tip.block_hash, tip.cumulative_chainwork)
            .unwrap());
        assert!(!staging
            .matches_exact_point(tip.header.height, [0xFF; 32], tip.cumulative_chainwork)
            .unwrap());
        assert!(staging
            .matches_exact_point(
                base.header.height,
                base.block_hash,
                base.cumulative_chainwork
            )
            .unwrap());
    }
    #[test]
    fn appended_partial_record_after_validation_cannot_be_streamed() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let path = stage_dir.path().join("candidate");
        let chain = noid_chain::storage::MdbxChainContext::open_or_create(db.path()).unwrap();
        let store = &chain.store;
        let base = canonical_base(store);
        let mut staging = SnapshotHeaderStaging::create(&path, store, base).unwrap();
        staging
            .append_batch(store, &fixture_chain()[1..=1])
            .unwrap();
        let tip = staging.tip_record().unwrap();
        let mut validated = staging
            .validate_complete(
                store,
                tip.header.height,
                tip.block_hash,
                tip.cumulative_chainwork,
            )
            .unwrap();

        let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
        writer.write_all(&[0xCC; 17]).unwrap();
        writer.sync_all().unwrap();
        drop(writer);

        assert!(validated.next_record().is_err());
        assert!(store.get_header(1).unwrap().is_none());
    }

    #[test]
    fn appended_complete_record_after_validation_cannot_be_streamed() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let path = stage_dir.path().join("candidate");
        let chain = noid_chain::storage::MdbxChainContext::open_or_create(db.path()).unwrap();
        let store = &chain.store;
        let base = canonical_base(store);
        let mut staging = SnapshotHeaderStaging::create(&path, store, base).unwrap();
        staging
            .append_batch(store, &fixture_chain()[1..=1])
            .unwrap();
        let tip = staging.tip_record().unwrap();
        let mut validated = staging
            .validate_complete(
                store,
                tip.header.height,
                tip.block_hash,
                tip.cumulative_chainwork,
            )
            .unwrap();

        let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
        write_record(&mut writer, &tip).unwrap();
        writer.sync_all().unwrap();
        drop(writer);

        assert!(validated.next_record().is_err());
        assert!(store.get_header(1).unwrap().is_none());
    }

    #[test]
    fn empty_exact_target_uses_typestate_even_with_canonical_child() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let mut chain = noid_chain::storage::MdbxChainContext::open_or_create(db.path()).unwrap();
        let genesis_base = canonical_base(&chain.store);
        let block = native_coinbase_child(&chain);
        let child = block.header;
        let bundle = noid_chain::AcceptedBlockBundle::try_from_parts(
            block.to_bytes(),
            fixture_terminal(
                child.height,
                noid_chain::block_header::semantic_header_id(&child),
            ),
        )
        .unwrap();
        chain
            .apply_next_block(
                &bundle,
                child.timestamp,
                |block, state| {
                    noid_chain::materialize_accepted_block_state(state, block)
                        .map_err(|error| format!("{error:?}"))
                },
                |_| Ok(()),
            )
            .unwrap();
        let store = &chain.store;

        let ordinary =
            SnapshotHeaderStaging::create(&stage_dir.path().join("ordinary"), store, genesis_base);
        assert!(matches!(
            ordinary,
            Err(SnapshotHeaderStagingError::CanonicalBaseMoved { height: 1, .. })
        ));
        let exact = SnapshotHeaderStaging::create_at_canonical_boundary(
            &stage_dir.path().join("exact"),
            store,
            genesis_base,
        )
        .unwrap();
        assert_eq!(exact.staged_len(), 0);
        assert_eq!(exact.next_height().unwrap(), 1);

        // HeaderDAG-authorized replacement begins after the canonical common
        // ancestor, so an existing non-final child is expected rather than a
        // reason to reject the staging file.  The ordinary path above keeps
        // its stricter first-missing-height invariant.
        let rebase = SnapshotHeaderStaging::create_at_nonfinal_rebase_boundary(
            &stage_dir.path().join("rebase"),
            store,
            genesis_base,
        )
        .unwrap();
        assert_eq!(rebase.staged_len(), 0);
        assert_eq!(rebase.next_height().unwrap(), 1);
    }

    #[test]
    fn validated_suffix_streams_once_without_mutating_canonical_store() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let path = stage_dir.path().join("candidate");
        let chain = noid_chain::storage::MdbxChainContext::open_or_create(db.path()).unwrap();
        let store = &chain.store;
        let base = canonical_base(store);
        let mut staging = SnapshotHeaderStaging::create(&path, store, base).unwrap();
        staging
            .append_batch(store, &fixture_chain()[1..=1])
            .unwrap();
        let tip = staging.tip_record().unwrap();
        let mut validated = staging
            .validate_complete(
                store,
                tip.header.height,
                tip.block_hash,
                tip.cumulative_chainwork,
            )
            .unwrap();
        assert_eq!(validated.boundary().tip_header, fixture_chain()[1]);
        assert_eq!(validated.boundary().epoch_anchor_header, genesis_header());
        let record = validated.next_record().unwrap().unwrap();
        assert_eq!(record, validated.target_record());
        assert!(validated.next_record().unwrap().is_none());
        assert!(store.get_header(1).unwrap().is_none());
    }
}
