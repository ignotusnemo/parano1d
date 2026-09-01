// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical wire container for one complete accepted block candidate.
//!
//! A semantic [`Block`] intentionally excludes recursive proof bytes because
//! including them in the header would make the block id circular.  Network and
//! RPC acceptance nevertheless must never model a PoW-only block as complete.
//! [`AcceptedBlockBundle`] is that fail-closed transport boundary: its fields
//! are private and construction requires both the canonical block bytes and a
//! non-empty `HistoryStep` terminal bound to the exact current block.
//!
//! This module performs only allocation-bounded framing and public binding
//! checks.  It does not claim that opaque terminal bytes are cryptographically
//! valid; the pinned recursive verifier must still decide them before state or
//! canonical chain metadata is mutated.

use core::fmt;

use noid_tx::wire::WireError;

use crate::block::Block;
use crate::block_header::semantic_header_id;
use crate::consensus::pow::block_id;
use crate::consensus::wire_limits::{
    history_step_terminal_bytes_limit, MAX_BLOCK_BYTES, MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES,
};
use crate::history_step::{
    HistoryStepTerminalMetadata, HistoryStepTerminalMetadataError,
    HISTORY_STEP_TERMINAL_BINDING_BYTES,
};

/// Fixed marker for the canonical all-or-none accepted-block bundle wire.
pub const ACCEPTED_BLOCK_BUNDLE_MAGIC: [u8; 4] = *b"NAB1";

/// `magic || block_len:u32 || history_step_terminal_len:u32`.
pub const ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES: usize = 4 + 4 + 4;

/// Maximum complete encoded bundle, including its fixed framing header.
pub const MAX_ACCEPTED_BLOCK_BUNDLE_BYTES: usize = ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES
    + MAX_BLOCK_BYTES
    + MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES;

/// One structurally complete, not-yet-cryptographically-decided block bundle.
///
/// Private fields ensure callers cannot create a value with a missing
/// `HistoryStep` terminal.  `Clone` is intentional for transport fan-out; this
/// is not the non-cloneable miner hot-witness carrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedBlockBundle {
    block_bytes: Vec<u8>,
    history_step_terminal_bytes: Vec<u8>,
    height: u64,
    block_hash: [u8; 32],
}

impl AcceptedBlockBundle {
    /// Construct the wire bundle for a block already built and validated by
    /// the node-owned mining pipeline.
    ///
    /// Unlike [`Self::try_from_parts`], this path does not decode the canonical
    /// bytes it has just encoded.  The opaque HistoryStep terminal still has
    /// to bind the exact sealed header, and inbound/network construction keeps
    /// using the fully decoding constructor below.
    pub(crate) fn try_from_locally_built_block(
        block: &Block,
        history_step_terminal_bytes: Vec<u8>,
    ) -> Result<Self, AcceptedBlockBundleError> {
        if block.header.height == 0 {
            return Err(AcceptedBlockBundleError::GenesisIsNotTransported);
        }
        let block_bytes = block.to_bytes();
        validate_payload_lengths(
            block_bytes.len() as u64,
            history_step_terminal_bytes.len() as u64,
        )?;
        let height = block.header.height;
        validate_terminal_length_at_height(history_step_terminal_bytes.len() as u64, height)?;
        let block_hash = block_id(&block.header);
        validate_terminal_binding(
            &history_step_terminal_bytes,
            height,
            semantic_header_id(&block.header),
        )?;

        Ok(Self {
            block_bytes,
            history_step_terminal_bytes,
            height,
            block_hash,
        })
    }

    /// Construct from the two required canonical payloads.
    ///
    /// Length caps are checked before block decoding.  The terminal's public
    /// prefix must identify this exact non-genesis block; complete recursive
    /// decoding and proof verification remain the verifier's responsibility.
    pub fn try_from_parts(
        block_bytes: Vec<u8>,
        history_step_terminal_bytes: Vec<u8>,
    ) -> Result<Self, AcceptedBlockBundleError> {
        validate_payload_lengths(
            block_bytes.len() as u64,
            history_step_terminal_bytes.len() as u64,
        )?;

        let block =
            Block::from_bytes(&block_bytes).map_err(AcceptedBlockBundleError::BlockDecode)?;
        if block.header.height == 0 {
            return Err(AcceptedBlockBundleError::GenesisIsNotTransported);
        }
        let height = block.header.height;
        validate_terminal_length_at_height(history_step_terminal_bytes.len() as u64, height)?;
        let block_hash = block_id(&block.header);
        validate_terminal_binding(
            &history_step_terminal_bytes,
            height,
            semantic_header_id(&block.header),
        )?;

        Ok(Self {
            block_bytes,
            history_step_terminal_bytes,
            height,
            block_hash,
        })
    }

    /// Decode one canonical, all-or-none bundle.
    ///
    /// Declared lengths are validated against hard caps and the exact input
    /// size before either payload is copied into an owned allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, AcceptedBlockBundleError> {
        if bytes.len() > MAX_ACCEPTED_BLOCK_BUNDLE_BYTES {
            return Err(AcceptedBlockBundleError::BundleTooLarge {
                actual: bytes.len(),
                max: MAX_ACCEPTED_BLOCK_BUNDLE_BYTES,
            });
        }
        if bytes.len() < ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES {
            return Err(AcceptedBlockBundleError::TruncatedHeader);
        }
        if bytes[..4] != ACCEPTED_BLOCK_BUNDLE_MAGIC {
            return Err(AcceptedBlockBundleError::BadMagic);
        }

        let block_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as u64;
        let terminal_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as u64;
        let payload_len = validate_payload_lengths(block_len, terminal_len)?;
        let expected = ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES
            .checked_add(payload_len)
            .ok_or(AcceptedBlockBundleError::LengthOverflow)?;

        match bytes.len().cmp(&expected) {
            core::cmp::Ordering::Less => {
                return Err(AcceptedBlockBundleError::TruncatedPayload {
                    expected,
                    actual: bytes.len(),
                });
            }
            core::cmp::Ordering::Greater => {
                return Err(AcceptedBlockBundleError::TrailingBytes {
                    expected,
                    actual: bytes.len(),
                });
            }
            core::cmp::Ordering::Equal => {}
        }

        let block_len =
            usize::try_from(block_len).map_err(|_| AcceptedBlockBundleError::LengthOverflow)?;
        let block_end = ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES
            .checked_add(block_len)
            .ok_or(AcceptedBlockBundleError::LengthOverflow)?;
        Self::try_from_parts(
            bytes[ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES..block_end].to_vec(),
            bytes[block_end..expected].to_vec(),
        )
    }

    /// Encode the already-validated canonical parts with fixed framing.
    pub fn encode(&self) -> Vec<u8> {
        let block_len = u32::try_from(self.block_bytes.len())
            .expect("accepted block bytes are bounded below u32::MAX");
        let terminal_len = u32::try_from(self.history_step_terminal_bytes.len())
            .expect("HistoryStep terminal bytes are bounded below u32::MAX");
        let mut encoded = Vec::with_capacity(
            ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES
                + self.block_bytes.len()
                + self.history_step_terminal_bytes.len(),
        );
        encoded.extend_from_slice(&ACCEPTED_BLOCK_BUNDLE_MAGIC);
        encoded.extend_from_slice(&block_len.to_le_bytes());
        encoded.extend_from_slice(&terminal_len.to_le_bytes());
        encoded.extend_from_slice(&self.block_bytes);
        encoded.extend_from_slice(&self.history_step_terminal_bytes);
        encoded
    }

    pub fn block_bytes(&self) -> &[u8] {
        &self.block_bytes
    }

    pub fn history_step_terminal_bytes(&self) -> &[u8] {
        &self.history_step_terminal_bytes
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.block_bytes, self.history_step_terminal_bytes)
    }

    /// Preflight absolute payload bounds before a streaming codec allocates.
    /// This does not replace the height-selected consensus check below.
    pub fn validate_declared_transport_lengths(
        block_len: u64,
        history_step_terminal_len: u64,
    ) -> Result<usize, AcceptedBlockBundleError> {
        validate_payload_lengths(block_len, history_step_terminal_len)
    }

    /// Validate allocation bounds and the consensus cap active for one block
    /// height without decoding either retained payload.
    pub fn validate_declared_lengths_at_height(
        block_len: u64,
        history_step_terminal_len: u64,
        height: u64,
    ) -> Result<usize, AcceptedBlockBundleError> {
        let payload_len = validate_payload_lengths(block_len, history_step_terminal_len)?;
        validate_terminal_length_at_height(history_step_terminal_len, height)?;
        Ok(payload_len)
    }
}

fn validate_payload_lengths(
    block_len: u64,
    terminal_len: u64,
) -> Result<usize, AcceptedBlockBundleError> {
    if block_len == 0 {
        return Err(AcceptedBlockBundleError::MissingBlock);
    }
    if block_len > MAX_BLOCK_BYTES as u64 {
        return Err(AcceptedBlockBundleError::BlockTooLarge {
            actual: block_len,
            max: MAX_BLOCK_BYTES,
        });
    }
    if terminal_len <= HISTORY_STEP_TERMINAL_BINDING_BYTES as u64 {
        return Err(AcceptedBlockBundleError::MissingHistoryStepTerminal);
    }
    if terminal_len > MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES as u64 {
        return Err(AcceptedBlockBundleError::HistoryStepTerminalTooLarge {
            actual: terminal_len,
            max: MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES,
        });
    }
    let block_len =
        usize::try_from(block_len).map_err(|_| AcceptedBlockBundleError::LengthOverflow)?;
    let terminal_len =
        usize::try_from(terminal_len).map_err(|_| AcceptedBlockBundleError::LengthOverflow)?;
    block_len
        .checked_add(terminal_len)
        .ok_or(AcceptedBlockBundleError::LengthOverflow)
}

fn validate_terminal_length_at_height(
    terminal_len: u64,
    height: u64,
) -> Result<(), AcceptedBlockBundleError> {
    validate_terminal_length(terminal_len, history_step_terminal_bytes_limit(height))
}

fn validate_terminal_length(terminal_len: u64, max: usize) -> Result<(), AcceptedBlockBundleError> {
    if terminal_len > max as u64 {
        return Err(AcceptedBlockBundleError::HistoryStepTerminalTooLarge {
            actual: terminal_len,
            max,
        });
    }
    Ok(())
}

fn validate_terminal_binding(
    terminal: &[u8],
    expected_height: u64,
    expected_hash: [u8; 32],
) -> Result<(), AcceptedBlockBundleError> {
    let metadata = HistoryStepTerminalMetadata::decode_prefix(terminal)
        .map_err(AcceptedBlockBundleError::HistoryStepMetadata)?;
    if metadata.terminal_height() != expected_height {
        return Err(AcceptedBlockBundleError::TerminalHeightMismatch {
            expected: expected_height,
            actual: metadata.terminal_height(),
        });
    }
    if metadata.terminal_hash() != expected_hash {
        return Err(AcceptedBlockBundleError::TerminalHashMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcceptedBlockBundleError {
    BundleTooLarge { actual: usize, max: usize },
    TruncatedHeader,
    BadMagic,
    MissingBlock,
    BlockTooLarge { actual: u64, max: usize },
    MissingHistoryStepTerminal,
    HistoryStepTerminalTooLarge { actual: u64, max: usize },
    LengthOverflow,
    TruncatedPayload { expected: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
    BlockDecode(WireError),
    GenesisIsNotTransported,
    HistoryStepMetadata(HistoryStepTerminalMetadataError),
    TerminalHeightMismatch { expected: u64, actual: u64 },
    TerminalHashMismatch,
}

impl fmt::Display for AcceptedBlockBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BundleTooLarge { actual, max } => {
                write!(
                    formatter,
                    "accepted-block bundle is {actual} bytes; cap is {max}"
                )
            }
            Self::TruncatedHeader => {
                formatter.write_str("accepted-block bundle header is truncated")
            }
            Self::BadMagic => formatter.write_str("invalid accepted-block bundle magic/version"),
            Self::MissingBlock => {
                formatter.write_str("accepted-block bundle is missing block bytes")
            }
            Self::BlockTooLarge { actual, max } => {
                write!(
                    formatter,
                    "accepted-block payload is {actual} bytes; cap is {max}"
                )
            }
            Self::MissingHistoryStepTerminal => formatter
                .write_str("accepted-block bundle is missing a non-empty HistoryStep terminal"),
            Self::HistoryStepTerminalTooLarge { actual, max } => write!(
                formatter,
                "HistoryStep terminal is {actual} bytes; cap is {max}"
            ),
            Self::LengthOverflow => formatter.write_str("accepted-block bundle length overflow"),
            Self::TruncatedPayload { expected, actual } => write!(
                formatter,
                "accepted-block bundle is truncated: expected {expected} bytes, got {actual}"
            ),
            Self::TrailingBytes { expected, actual } => write!(
                formatter,
                "accepted-block bundle has trailing bytes: expected {expected}, got {actual}"
            ),
            Self::BlockDecode(error) => {
                write!(formatter, "canonical block decode failed: {error:?}")
            }
            Self::GenesisIsNotTransported => formatter.write_str(
                "genesis is built into consensus and is not an accepted-block wire bundle",
            ),
            Self::HistoryStepMetadata(error) => write!(formatter, "{error}"),
            Self::TerminalHeightMismatch { expected, actual } => write!(
                formatter,
                "HistoryStep terminal height {actual} does not bind block height {expected}"
            ),
            Self::TerminalHashMismatch => formatter
                .write_str("HistoryStep terminal block id does not bind the bundled current block"),
        }
    }
}

impl std::error::Error for AcceptedBlockBundleError {}

#[cfg(test)]
mod tests {
    use noid_poseidon2b::primitives::Address;

    use super::*;
    use crate::block_header::BlockHeader;

    fn block(height: u64) -> Block {
        Block {
            header: BlockHeader {
                prev_block_hash: [0x11; 32],
                state_root: [0x22; 32],
                tx_root: [0x33; 32],
                timestamp: 1_700_000_000,
                height,
                miner_address: Address([0x44; 32]),
                nonce: 7,
                difficulty_target: [0xff; 32],
                log_slots: 24,
                active_slot_count: 0,
                alloc_counter: 0,
            },
            transactions: Vec::new(),
        }
    }

    fn terminal_for(block: &Block) -> Vec<u8> {
        let mut terminal = Vec::with_capacity(HISTORY_STEP_TERMINAL_BINDING_BYTES + 1);
        terminal.extend_from_slice(
            &HistoryStepTerminalMetadata::new(
                block.header.height,
                semantic_header_id(&block.header),
                1,
            )
            .expect("canonical HistoryStep class")
            .encode_prefix(),
        );
        terminal.push(0xA5); // opaque recursive proof payload
        terminal
    }

    fn bundle() -> AcceptedBlockBundle {
        let block = block(9);
        AcceptedBlockBundle::try_from_parts(block.to_bytes(), terminal_for(&block)).unwrap()
    }

    #[test]
    fn canonical_bundle_roundtrips_as_one_required_object() {
        let bundle = bundle();
        let encoded = bundle.encode();
        assert_eq!(&encoded[..4], &ACCEPTED_BLOCK_BUNDLE_MAGIC);
        assert_eq!(AcceptedBlockBundle::decode(&encoded), Ok(bundle));
    }

    #[test]
    fn locally_built_constructor_matches_the_decoding_constructor() {
        let block = block(7);
        let terminal = terminal_for(&block);
        let local =
            AcceptedBlockBundle::try_from_locally_built_block(&block, terminal.clone()).unwrap();
        let decoded = AcceptedBlockBundle::try_from_parts(block.to_bytes(), terminal).unwrap();
        assert_eq!(local, decoded);
    }

    #[test]
    fn neither_required_payload_can_be_absent() {
        let block = block(9);
        assert_eq!(
            AcceptedBlockBundle::try_from_parts(Vec::new(), terminal_for(&block)),
            Err(AcceptedBlockBundleError::MissingBlock)
        );
        assert_eq!(
            AcceptedBlockBundle::try_from_parts(block.to_bytes(), Vec::new()),
            Err(AcceptedBlockBundleError::MissingHistoryStepTerminal)
        );
    }

    #[test]
    fn block_payload_must_be_exactly_one_canonical_block() {
        let block = block(9);
        let terminal = terminal_for(&block);

        let mut bad_marker = block.to_bytes();
        bad_marker[0] ^= 1;
        assert!(matches!(
            AcceptedBlockBundle::try_from_parts(bad_marker, terminal.clone()),
            Err(AcceptedBlockBundleError::BlockDecode(WireError::BadMarker))
        ));

        let mut trailing = block.to_bytes();
        trailing.push(0);
        assert!(matches!(
            AcceptedBlockBundle::try_from_parts(trailing, terminal),
            Err(AcceptedBlockBundleError::BlockDecode(
                WireError::TrailingBytes
            ))
        ));
    }

    #[test]
    fn terminal_must_bind_exact_current_height_and_hash() {
        let block = block(9);
        let mut wrong_height = terminal_for(&block);
        wrong_height[1..9].copy_from_slice(&8u64.to_le_bytes());
        assert_eq!(
            AcceptedBlockBundle::try_from_parts(block.to_bytes(), wrong_height),
            Err(AcceptedBlockBundleError::TerminalHeightMismatch {
                expected: 9,
                actual: 8,
            })
        );

        let mut wrong_hash = terminal_for(&block);
        wrong_hash[9] ^= 1;
        assert_eq!(
            AcceptedBlockBundle::try_from_parts(block.to_bytes(), wrong_hash),
            Err(AcceptedBlockBundleError::TerminalHashMismatch)
        );
    }

    #[test]
    fn wrong_terminal_version_is_rejected() {
        let block = block(9);
        let mut wrong_version = terminal_for(&block);
        wrong_version[0] = 1;
        assert_eq!(
            AcceptedBlockBundle::try_from_parts(block.to_bytes(), wrong_version),
            Err(AcceptedBlockBundleError::HistoryStepMetadata(
                HistoryStepTerminalMetadataError::UnsupportedVersion { actual: 1 }
            ))
        );
    }

    #[test]
    fn terminal_class_is_bounded_by_the_canonical_bank() {
        let block = block(9);
        let mut wrong_class = terminal_for(&block);
        wrong_class[41] = crate::history_step::HISTORY_STEP_CLASS_COUNT;
        assert_eq!(
            AcceptedBlockBundle::try_from_parts(block.to_bytes(), wrong_class),
            Err(AcceptedBlockBundleError::HistoryStepMetadata(
                HistoryStepTerminalMetadataError::InvalidClassId {
                    actual: crate::history_step::HISTORY_STEP_CLASS_COUNT,
                }
            ))
        );
    }

    #[test]
    fn genesis_is_not_network_bundle_data() {
        let genesis = block(0);
        assert_eq!(
            AcceptedBlockBundle::try_from_parts(genesis.to_bytes(), terminal_for(&genesis)),
            Err(AcceptedBlockBundleError::GenesisIsNotTransported)
        );
    }

    #[test]
    fn forged_lengths_fail_before_payload_allocation_or_decode() {
        let mut oversized_block = vec![0u8; ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES];
        oversized_block[..4].copy_from_slice(&ACCEPTED_BLOCK_BUNDLE_MAGIC);
        oversized_block[4..8]
            .copy_from_slice(&(u32::try_from(MAX_BLOCK_BYTES).unwrap() + 1).to_le_bytes());
        oversized_block[8..12].copy_from_slice(
            &u32::try_from(HISTORY_STEP_TERMINAL_BINDING_BYTES + 1)
                .unwrap()
                .to_le_bytes(),
        );
        assert!(matches!(
            AcceptedBlockBundle::decode(&oversized_block),
            Err(AcceptedBlockBundleError::BlockTooLarge { .. })
        ));

        let mut oversized_terminal = vec![0u8; ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES];
        oversized_terminal[..4].copy_from_slice(&ACCEPTED_BLOCK_BUNDLE_MAGIC);
        oversized_terminal[4..8].copy_from_slice(&1u32.to_le_bytes());
        oversized_terminal[8..12].copy_from_slice(
            &(u32::try_from(MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES).unwrap() + 1).to_le_bytes(),
        );
        assert!(matches!(
            AcceptedBlockBundle::decode(&oversized_terminal),
            Err(AcceptedBlockBundleError::HistoryStepTerminalTooLarge { .. })
        ));
    }

    #[test]
    fn transport_headroom_does_not_activate_the_v2_cap_early() {
        use crate::consensus::wire_limits::V1_MAX_HISTORY_STEP_TERMINAL_BYTES;

        let terminal_len = (V1_MAX_HISTORY_STEP_TERMINAL_BYTES + 1) as u64;
        assert!(AcceptedBlockBundle::validate_declared_transport_lengths(1, terminal_len).is_ok());
        assert_eq!(
            AcceptedBlockBundle::validate_declared_lengths_at_height(1, terminal_len, 1),
            Err(AcceptedBlockBundleError::HistoryStepTerminalTooLarge {
                actual: terminal_len,
                max: V1_MAX_HISTORY_STEP_TERMINAL_BYTES,
            })
        );
    }

    #[test]
    fn canonical_b255_terminal_switches_exactly_at_the_v2_height() {
        use crate::consensus::wire_limits::history_step_terminal_bytes_limit_with_activation;

        const ACTIVATION_HEIGHT: u64 = 42;
        const B255_TERMINAL_BYTES: u64 = 1_081_108;
        let before = history_step_terminal_bytes_limit_with_activation(
            ACTIVATION_HEIGHT - 1,
            Some(ACTIVATION_HEIGHT),
        );
        let at = history_step_terminal_bytes_limit_with_activation(
            ACTIVATION_HEIGHT,
            Some(ACTIVATION_HEIGHT),
        );
        assert!(validate_terminal_length(B255_TERMINAL_BYTES, before).is_err());
        assert!(validate_terminal_length(B255_TERMINAL_BYTES, at).is_ok());
    }

    #[test]
    fn decoder_rejects_truncation_and_trailing_bytes() {
        let encoded = bundle().encode();
        assert!(matches!(
            AcceptedBlockBundle::decode(&encoded[..encoded.len() - 1]),
            Err(AcceptedBlockBundleError::TruncatedPayload { .. })
        ));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            AcceptedBlockBundle::decode(&trailing),
            Err(AcceptedBlockBundleError::TrailingBytes { .. })
        ));
    }

    // ----------------------------------------------------------------------
    // v2 phase-1 semantic-binding catalog. Staged red; un-ignored when the
    // terminal prefix binds `(height, semantic_id)` instead of
    // `(height, block_id)`. Each name states the exact obligation.
    // ----------------------------------------------------------------------

    /// A terminal whose `semantic_id` does not equal the semantic projection
    /// of the decoded header must be rejected before any state mutation.
    #[test]
    fn terminal_with_mismatched_semantic_id_is_rejected() {
        let block = block(9);
        let mut mismatched = terminal_for(&block);
        mismatched[9] ^= 1;
        assert_eq!(
            AcceptedBlockBundle::try_from_parts(block.to_bytes(), mismatched),
            Err(AcceptedBlockBundleError::TerminalHashMismatch)
        );
    }

    /// A valid terminal replayed under a bundle at a different height must
    /// fail the `(height, semantic_id)` binding.
    #[test]
    fn terminal_reused_under_different_height_is_rejected() {
        let nine = block(9);
        let eight = block(8);
        assert_eq!(
            AcceptedBlockBundle::try_from_parts(eight.to_bytes(), terminal_for(&nine)),
            Err(AcceptedBlockBundleError::TerminalHeightMismatch {
                expected: 8,
                actual: 9,
            })
        );
    }

    /// Altering any semantic header field changes the recomputed projection
    /// and must invalidate a terminal minted for the original template.
    #[test]
    fn terminal_reused_under_altered_semantic_field_is_rejected() {
        let original = block(9);
        let terminal = terminal_for(&original);
        let mut altered = original.clone();
        altered.header.state_root = [0x77; 32];
        assert_eq!(
            AcceptedBlockBundle::try_from_parts(altered.to_bytes(), terminal),
            Err(AcceptedBlockBundleError::TerminalHashMismatch)
        );
    }

    /// Positive: two headers differing only in nonce share one semantic
    /// projection; one terminal binds both encodings.
    #[test]
    fn two_nonces_over_one_semantic_id_share_semantics() {
        let original = block(9);
        let terminal = terminal_for(&original);
        let mut renonced = original.clone();
        renonced.header.nonce = original.header.nonce.wrapping_add(1);
        let first =
            AcceptedBlockBundle::try_from_parts(original.to_bytes(), terminal.clone()).unwrap();
        let second = AcceptedBlockBundle::try_from_parts(renonced.to_bytes(), terminal).unwrap();
        assert_eq!(first.height(), second.height());
        assert_ne!(first.block_hash(), second.block_hash());
    }
}
