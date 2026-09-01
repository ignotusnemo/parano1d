// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed header-first announcement for network v2.

use noid_chain::{
    block::BLOCK_WIRE_HEADER_OFFSET,
    block_header::{block_id, semantic_header_id},
    consensus::wire_limits::{history_step_terminal_bytes_limit, MAX_BLOCK_BYTES},
    history_step::{HistoryStepTerminalMetadata, HISTORY_STEP_CLASS_COUNT},
    AcceptedBlockBundle, BlockHeader, BLOCK_HEADER_WIRE_SIZE,
};
use thiserror::Error;

use crate::object_protocol::{
    BlockBodyClaimId, BlockBodyObjectId, TerminalClaimId, TerminalObjectId,
};

const HEADER_ANNOUNCE_MAGIC: [u8; 4] = *b"NHA2";
const RESERVED_BYTES: usize = 2;
pub const HEADER_ANNOUNCE_BYTES: usize =
    4 + BLOCK_HEADER_WIRE_SIZE + 32 + 4 + 32 + 4 + 1 + 1 + RESERVED_BYTES;
pub const MAX_HEADER_ANNOUNCE_BYTES: usize = 512;

const INVENTORY_BODY: u8 = 1 << 0;
const INVENTORY_TERMINAL: u8 = 1 << 1;
const INVENTORY_KNOWN: u8 = INVENTORY_BODY | INVENTORY_TERMINAL;
const INVENTORY_RESERVED_BYTES: usize = 2;
pub const HEADER_INVENTORY_RECORD_BYTES: usize =
    BLOCK_HEADER_WIRE_SIZE + 1 + 1 + INVENTORY_RESERVED_BYTES + 32 + 4 + 32 + 4;

const _: () = assert!(HEADER_ANNOUNCE_BYTES <= MAX_HEADER_ANNOUNCE_BYTES);

/// One canonical header plus scheduling hints for exact retained objects.
///
/// Missing object identities are explicit availability statements, not
/// consensus claims. In particular, a compact recursive marker is never
/// encoded as a terminal object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderInventoryRecord {
    pub header: BlockHeader,
    pub body: Option<BlockBodyObjectId>,
    pub terminal: Option<TerminalObjectId>,
}

impl HeaderInventoryRecord {
    pub const fn header_only(header: BlockHeader) -> Self {
        Self {
            header,
            body: None,
            terminal: None,
        }
    }

    pub fn from_announcement(announcement: HeaderAnnouncement) -> Self {
        Self {
            header: announcement.header,
            body: Some(announcement.body),
            terminal: Some(announcement.terminal),
        }
    }

    pub fn from_retained_objects(
        header: BlockHeader,
        body_bytes: Option<&[u8]>,
        terminal_bytes: Option<&[u8]>,
    ) -> Result<Self, HeaderAnnounceError> {
        if body_bytes.is_some_and(|bytes| {
            noid_chain::Block::from_bytes(bytes)
                .map(|block| block.header != header)
                .unwrap_or(true)
        }) {
            return Err(HeaderAnnounceError::InvalidBundleHeader);
        }
        let body_claim = BlockBodyClaimId {
            height: header.height,
            block_hash: block_id(&header),
        };
        let body = body_bytes
            .map(|bytes| {
                BlockBodyObjectId::from_bytes(body_claim, bytes)
                    .ok_or(HeaderAnnounceError::ObjectLengthOverflow)
            })
            .transpose()?;
        let terminal = terminal_bytes
            .map(|bytes| {
                let metadata = HistoryStepTerminalMetadata::decode_prefix(bytes)
                    .map_err(|_| HeaderAnnounceError::InvalidTerminalMetadata)?;
                let claim = TerminalClaimId {
                    height: header.height,
                    semantic_header_id: semantic_header_id(&header),
                    proof_class: metadata.class_id(),
                };
                if metadata.terminal_height() != claim.height
                    || metadata.terminal_hash() != claim.semantic_header_id
                {
                    return Err(HeaderAnnounceError::TerminalClaimMismatch);
                }
                TerminalObjectId::from_bytes(claim, bytes)
                    .ok_or(HeaderAnnounceError::ObjectLengthOverflow)
            })
            .transpose()?;
        let record = Self {
            header,
            body,
            terminal,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn encode(self) -> Result<[u8; HEADER_INVENTORY_RECORD_BYTES], HeaderAnnounceError> {
        self.validate()?;
        let mut encoded = [0u8; HEADER_INVENTORY_RECORD_BYTES];
        encoded[..BLOCK_HEADER_WIRE_SIZE].copy_from_slice(&self.header.to_bytes());
        let mut cursor = BLOCK_HEADER_WIRE_SIZE;
        encoded[cursor] = (self.body.is_some() as u8) * INVENTORY_BODY
            | (self.terminal.is_some() as u8) * INVENTORY_TERMINAL;
        cursor += 1;
        encoded[cursor] = self
            .terminal
            .map_or(0, |terminal| terminal.claim.proof_class);
        cursor += 1 + INVENTORY_RESERVED_BYTES;
        if let Some(body) = self.body {
            encoded[cursor..cursor + 32].copy_from_slice(&body.byte_digest);
            cursor += 32;
            encoded[cursor..cursor + 4].copy_from_slice(&body.encoded_len.to_le_bytes());
        } else {
            cursor += 32;
        }
        cursor += 4;
        if let Some(terminal) = self.terminal {
            encoded[cursor..cursor + 32].copy_from_slice(&terminal.byte_digest);
            cursor += 32;
            encoded[cursor..cursor + 4].copy_from_slice(&terminal.encoded_len.to_le_bytes());
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, HeaderAnnounceError> {
        if encoded.len() != HEADER_INVENTORY_RECORD_BYTES {
            return Err(HeaderAnnounceError::NonCanonicalInventoryLength(
                encoded.len(),
            ));
        }
        let header = BlockHeader::from_bytes(&encoded[..BLOCK_HEADER_WIRE_SIZE])
            .map_err(|_| HeaderAnnounceError::InvalidHeader)?;
        let mut cursor = BLOCK_HEADER_WIRE_SIZE;
        let flags = encoded[cursor];
        if flags & !INVENTORY_KNOWN != 0 {
            return Err(HeaderAnnounceError::UnknownInventoryFlags(flags));
        }
        cursor += 1;
        let proof_class = encoded[cursor];
        cursor += 1;
        if encoded[cursor..cursor + INVENTORY_RESERVED_BYTES] != [0; INVENTORY_RESERVED_BYTES] {
            return Err(HeaderAnnounceError::NonZeroReserved);
        }
        cursor += INVENTORY_RESERVED_BYTES;

        let body_digest: [u8; 32] = encoded[cursor..cursor + 32].try_into().unwrap();
        cursor += 32;
        let body_len = u32::from_le_bytes(encoded[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let terminal_digest: [u8; 32] = encoded[cursor..cursor + 32].try_into().unwrap();
        cursor += 32;
        let terminal_len = u32::from_le_bytes(encoded[cursor..cursor + 4].try_into().unwrap());

        let body = if flags & INVENTORY_BODY != 0 {
            Some(BlockBodyObjectId {
                claim: BlockBodyClaimId {
                    height: header.height,
                    block_hash: block_id(&header),
                },
                byte_digest: body_digest,
                encoded_len: body_len,
            })
        } else {
            if body_digest != [0; 32] || body_len != 0 {
                return Err(HeaderAnnounceError::NonCanonicalMissingInventory);
            }
            None
        };
        let terminal = if flags & INVENTORY_TERMINAL != 0 {
            Some(TerminalObjectId {
                claim: TerminalClaimId {
                    height: header.height,
                    semantic_header_id: semantic_header_id(&header),
                    proof_class,
                },
                byte_digest: terminal_digest,
                encoded_len: terminal_len,
            })
        } else {
            if proof_class != 0 || terminal_digest != [0; 32] || terminal_len != 0 {
                return Err(HeaderAnnounceError::NonCanonicalMissingInventory);
            }
            None
        };
        let record = Self {
            header,
            body,
            terminal,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), HeaderAnnounceError> {
        let expected_hash = block_id(&self.header);
        if self.body.is_some_and(|body| {
            body.claim.height != self.header.height
                || body.claim.block_hash != expected_hash
                || body.encoded_len == 0
                || body.encoded_len as usize > MAX_BLOCK_BYTES
        }) {
            return Err(HeaderAnnounceError::BodyClaimMismatch);
        }
        if self.terminal.is_some_and(|terminal| {
            terminal.claim.height != self.header.height
                || terminal.claim.semantic_header_id != semantic_header_id(&self.header)
                || terminal.claim.proof_class >= HISTORY_STEP_CLASS_COUNT
                || terminal.encoded_len == 0
                || terminal.encoded_len as usize
                    > history_step_terminal_bytes_limit(self.header.height)
        }) {
            return Err(HeaderAnnounceError::TerminalClaimMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderFlags(u8);

impl ProviderFlags {
    pub const BODY: u8 = 1 << 0;
    pub const TERMINAL: u8 = 1 << 1;
    pub const SNAPSHOT: u8 = 1 << 2;
    const KNOWN: u8 = Self::BODY | Self::TERMINAL | Self::SNAPSHOT;

    pub const fn new(body: bool, terminal: bool, snapshot: bool) -> Self {
        Self(
            (body as u8) * Self::BODY
                | (terminal as u8) * Self::TERMINAL
                | (snapshot as u8) * Self::SNAPSHOT,
        )
    }

    pub const fn serves_body(self) -> bool {
        self.0 & Self::BODY != 0
    }

    pub const fn serves_terminal(self) -> bool {
        self.0 & Self::TERMINAL != 0
    }

    pub const fn serves_snapshot(self) -> bool {
        self.0 & Self::SNAPSHOT != 0
    }

    fn decode(bits: u8) -> Result<Self, HeaderAnnounceError> {
        if bits & !Self::KNOWN != 0 {
            return Err(HeaderAnnounceError::UnknownProviderFlags(bits));
        }
        Ok(Self(bits))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderAnnouncement {
    pub header: BlockHeader,
    pub body: BlockBodyObjectId,
    pub terminal: TerminalObjectId,
    pub providers: ProviderFlags,
}

impl HeaderAnnouncement {
    pub fn from_accepted_bundle(
        bundle: &AcceptedBlockBundle,
        providers: ProviderFlags,
    ) -> Result<Self, HeaderAnnounceError> {
        let header_end = BLOCK_WIRE_HEADER_OFFSET
            .checked_add(BLOCK_HEADER_WIRE_SIZE)
            .ok_or(HeaderAnnounceError::InvalidBundleHeader)?;
        let header = BlockHeader::from_bytes(
            bundle
                .block_bytes()
                .get(BLOCK_WIRE_HEADER_OFFSET..header_end)
                .ok_or(HeaderAnnounceError::InvalidBundleHeader)?,
        )
        .map_err(|_| HeaderAnnounceError::InvalidBundleHeader)?;
        let metadata =
            HistoryStepTerminalMetadata::decode_prefix(bundle.history_step_terminal_bytes())
                .map_err(|_| HeaderAnnounceError::InvalidTerminalMetadata)?;
        let body_claim = BlockBodyClaimId {
            height: header.height,
            block_hash: block_id(&header),
        };
        let terminal_claim = TerminalClaimId {
            height: header.height,
            semantic_header_id: semantic_header_id(&header),
            proof_class: metadata.class_id(),
        };
        let body = BlockBodyObjectId::from_bytes(body_claim, bundle.block_bytes())
            .ok_or(HeaderAnnounceError::ObjectLengthOverflow)?;
        let terminal =
            TerminalObjectId::from_bytes(terminal_claim, bundle.history_step_terminal_bytes())
                .ok_or(HeaderAnnounceError::ObjectLengthOverflow)?;
        let announcement = Self {
            header,
            body,
            terminal,
            providers,
        };
        announcement.validate()?;
        Ok(announcement)
    }

    pub fn encode(self) -> Result<[u8; HEADER_ANNOUNCE_BYTES], HeaderAnnounceError> {
        self.validate()?;
        let mut encoded = [0u8; HEADER_ANNOUNCE_BYTES];
        encoded[..4].copy_from_slice(&HEADER_ANNOUNCE_MAGIC);
        let mut cursor = 4;
        encoded[cursor..cursor + BLOCK_HEADER_WIRE_SIZE].copy_from_slice(&self.header.to_bytes());
        cursor += BLOCK_HEADER_WIRE_SIZE;
        encoded[cursor..cursor + 32].copy_from_slice(&self.body.byte_digest);
        cursor += 32;
        encoded[cursor..cursor + 4].copy_from_slice(&self.body.encoded_len.to_le_bytes());
        cursor += 4;
        encoded[cursor..cursor + 32].copy_from_slice(&self.terminal.byte_digest);
        cursor += 32;
        encoded[cursor..cursor + 4].copy_from_slice(&self.terminal.encoded_len.to_le_bytes());
        cursor += 4;
        encoded[cursor] = self.terminal.claim.proof_class;
        cursor += 1;
        encoded[cursor] = self.providers.0;
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, HeaderAnnounceError> {
        if encoded.len() != HEADER_ANNOUNCE_BYTES {
            return Err(HeaderAnnounceError::NonCanonicalLength(encoded.len()));
        }
        if encoded[..4] != HEADER_ANNOUNCE_MAGIC {
            return Err(HeaderAnnounceError::BadMagic);
        }
        if encoded[HEADER_ANNOUNCE_BYTES - RESERVED_BYTES..] != [0; RESERVED_BYTES] {
            return Err(HeaderAnnounceError::NonZeroReserved);
        }
        let mut cursor = 4;
        let header = BlockHeader::from_bytes(&encoded[cursor..cursor + BLOCK_HEADER_WIRE_SIZE])
            .map_err(|_| HeaderAnnounceError::InvalidHeader)?;
        cursor += BLOCK_HEADER_WIRE_SIZE;
        let body_digest = encoded[cursor..cursor + 32].try_into().unwrap();
        cursor += 32;
        let body_len = u32::from_le_bytes(encoded[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let terminal_digest = encoded[cursor..cursor + 32].try_into().unwrap();
        cursor += 32;
        let terminal_len = u32::from_le_bytes(encoded[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let proof_class = encoded[cursor];
        cursor += 1;
        let providers = ProviderFlags::decode(encoded[cursor])?;

        let announcement = Self {
            header,
            body: BlockBodyObjectId {
                claim: BlockBodyClaimId {
                    height: header.height,
                    block_hash: block_id(&header),
                },
                byte_digest: body_digest,
                encoded_len: body_len,
            },
            terminal: TerminalObjectId {
                claim: TerminalClaimId {
                    height: header.height,
                    semantic_header_id: semantic_header_id(&header),
                    proof_class,
                },
                byte_digest: terminal_digest,
                encoded_len: terminal_len,
            },
            providers,
        };
        announcement.validate()?;
        Ok(announcement)
    }

    pub fn validate(&self) -> Result<(), HeaderAnnounceError> {
        let expected_hash = block_id(&self.header);
        if self.body.claim.height != self.header.height
            || self.body.claim.block_hash != expected_hash
        {
            return Err(HeaderAnnounceError::BodyClaimMismatch);
        }
        if self.terminal.claim.height != self.header.height
            || self.terminal.claim.semantic_header_id != semantic_header_id(&self.header)
        {
            return Err(HeaderAnnounceError::TerminalClaimMismatch);
        }
        if self.terminal.claim.proof_class >= HISTORY_STEP_CLASS_COUNT {
            return Err(HeaderAnnounceError::InvalidProofClass(
                self.terminal.claim.proof_class,
            ));
        }
        if self.body.encoded_len == 0 || self.body.encoded_len as usize > MAX_BLOCK_BYTES {
            return Err(HeaderAnnounceError::BodyLength(self.body.encoded_len));
        }
        if self.terminal.encoded_len == 0
            || self.terminal.encoded_len as usize
                > history_step_terminal_bytes_limit(self.header.height)
        {
            return Err(HeaderAnnounceError::TerminalLength(
                self.terminal.encoded_len,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HeaderAnnounceError {
    #[error("header announcement has non-canonical length {0}")]
    NonCanonicalLength(usize),
    #[error("header inventory record has non-canonical length {0}")]
    NonCanonicalInventoryLength(usize),
    #[error("header announcement magic/version is invalid")]
    BadMagic,
    #[error("header announcement reserved bytes are non-zero")]
    NonZeroReserved,
    #[error("canonical block header decode failed")]
    InvalidHeader,
    #[error("accepted bundle does not contain a canonical header")]
    InvalidBundleHeader,
    #[error("accepted bundle terminal metadata is invalid")]
    InvalidTerminalMetadata,
    #[error("object length does not fit the fixed wire field")]
    ObjectLengthOverflow,
    #[error("body object claim does not match the announced header")]
    BodyClaimMismatch,
    #[error("terminal object claim does not match the announced semantic header")]
    TerminalClaimMismatch,
    #[error("proof class {0} is not part of the active class bank")]
    InvalidProofClass(u8),
    #[error("block body length {0} is outside the fixed wire cap")]
    BodyLength(u32),
    #[error("HistoryStep terminal length {0} is outside the active profile cap")]
    TerminalLength(u32),
    #[error("provider flag byte contains unknown bits: {0:#04x}")]
    UnknownProviderFlags(u8),
    #[error("header inventory flag byte contains unknown bits: {0:#04x}")]
    UnknownInventoryFlags(u8),
    #[error("an unavailable header inventory object has non-zero fields")]
    NonCanonicalMissingInventory,
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::{history_step::HISTORY_STEP_TERMINAL_VERSION, Block};

    fn bundle() -> AcceptedBlockBundle {
        let mut header = noid_chain::consensus::genesis_header();
        header.height = 1;
        header.prev_block_hash = block_id(&noid_chain::consensus::genesis_header());
        let block = Block {
            header,
            transactions: Vec::new(),
        };
        let mut terminal = Vec::new();
        terminal.push(HISTORY_STEP_TERMINAL_VERSION);
        terminal.extend_from_slice(&header.height.to_le_bytes());
        terminal.extend_from_slice(&semantic_header_id(&header));
        terminal.push(0);
        terminal.push(0xA5);
        AcceptedBlockBundle::try_from_parts(block.to_bytes(), terminal).unwrap()
    }

    #[test]
    fn announcement_round_trip_binds_header_and_exact_objects() {
        let accepted = bundle();
        let announcement = HeaderAnnouncement::from_accepted_bundle(
            &accepted,
            ProviderFlags::new(true, true, false),
        )
        .unwrap();
        let decoded = HeaderAnnouncement::decode(&announcement.encode().unwrap()).unwrap();
        assert_eq!(decoded, announcement);
        assert!(decoded.providers.serves_body());
        assert!(decoded.providers.serves_terminal());
        assert!(decoded.body.matches_bytes(accepted.block_bytes()));
        assert!(decoded
            .terminal
            .matches_bytes(accepted.history_step_terminal_bytes()));
    }

    #[test]
    fn inventory_round_trip_binds_retained_bytes_to_the_header() {
        let accepted = bundle();
        let announcement = HeaderAnnouncement::from_accepted_bundle(
            &accepted,
            ProviderFlags::new(true, true, false),
        )
        .unwrap();
        let record = HeaderInventoryRecord::from_retained_objects(
            announcement.header,
            Some(accepted.block_bytes()),
            Some(accepted.history_step_terminal_bytes()),
        )
        .unwrap();
        assert_eq!(
            HeaderInventoryRecord::decode(&record.encode().unwrap()).unwrap(),
            record
        );
        assert!(record.body.unwrap().matches_bytes(accepted.block_bytes()));
        assert!(record
            .terminal
            .unwrap()
            .matches_bytes(accepted.history_step_terminal_bytes()));
    }

    #[test]
    fn inventory_round_trip_allows_terminal_after_body_pruning() {
        let accepted = bundle();
        let announcement = HeaderAnnouncement::from_accepted_bundle(
            &accepted,
            ProviderFlags::new(true, true, false),
        )
        .unwrap();
        let record = HeaderInventoryRecord::from_retained_objects(
            announcement.header,
            None,
            Some(accepted.history_step_terminal_bytes()),
        )
        .unwrap();

        assert!(record.body.is_none());
        assert!(record.terminal.is_some());
        assert_eq!(
            HeaderInventoryRecord::decode(&record.encode().unwrap()).unwrap(),
            record
        );
    }

    #[test]
    fn inventory_absence_and_flag_encoding_is_canonical() {
        let accepted = bundle();
        let announcement = HeaderAnnouncement::from_accepted_bundle(
            &accepted,
            ProviderFlags::new(true, true, false),
        )
        .unwrap();
        let encoded = HeaderInventoryRecord::header_only(announcement.header)
            .encode()
            .unwrap();
        assert_eq!(
            HeaderInventoryRecord::decode(&encoded).unwrap(),
            HeaderInventoryRecord::header_only(announcement.header)
        );

        let mut unknown_flag = encoded;
        unknown_flag[BLOCK_HEADER_WIRE_SIZE] = 0x80;
        assert_eq!(
            HeaderInventoryRecord::decode(&unknown_flag),
            Err(HeaderAnnounceError::UnknownInventoryFlags(0x80))
        );

        let mut hidden_body = encoded;
        hidden_body[BLOCK_HEADER_WIRE_SIZE + 1 + 1 + INVENTORY_RESERVED_BYTES] = 1;
        assert_eq!(
            HeaderInventoryRecord::decode(&hidden_body),
            Err(HeaderAnnounceError::NonCanonicalMissingInventory)
        );
    }

    #[test]
    fn inventory_rejects_body_bytes_from_another_header() {
        let accepted = bundle();
        let announcement = HeaderAnnouncement::from_accepted_bundle(
            &accepted,
            ProviderFlags::new(true, true, false),
        )
        .unwrap();
        let mut wrong_body = accepted.block_bytes().to_vec();
        wrong_body[BLOCK_WIRE_HEADER_OFFSET] ^= 1;
        assert_eq!(
            HeaderInventoryRecord::from_retained_objects(
                announcement.header,
                Some(&wrong_body),
                None,
            ),
            Err(HeaderAnnounceError::InvalidBundleHeader)
        );
    }

    #[test]
    fn malformed_lengths_flags_and_reserved_bytes_fail_closed() {
        let announcement = HeaderAnnouncement::from_accepted_bundle(
            &bundle(),
            ProviderFlags::new(true, true, false),
        )
        .unwrap();
        let encoded = announcement.encode().unwrap();
        assert!(matches!(
            HeaderAnnouncement::decode(&encoded[..encoded.len() - 1]),
            Err(HeaderAnnounceError::NonCanonicalLength(_))
        ));

        let mut bad_flags = encoded;
        bad_flags[HEADER_ANNOUNCE_BYTES - RESERVED_BYTES - 1] = 0x80;
        assert_eq!(
            HeaderAnnouncement::decode(&bad_flags),
            Err(HeaderAnnounceError::UnknownProviderFlags(0x80))
        );

        let mut bad_reserved = encoded;
        bad_reserved[HEADER_ANNOUNCE_BYTES - 1] = 1;
        assert_eq!(
            HeaderAnnouncement::decode(&bad_reserved),
            Err(HeaderAnnounceError::NonZeroReserved)
        );
    }

    #[test]
    fn object_claim_substitution_is_rejected_before_encoding() {
        let mut announcement = HeaderAnnouncement::from_accepted_bundle(
            &bundle(),
            ProviderFlags::new(true, true, false),
        )
        .unwrap();
        announcement.body.claim.block_hash[0] ^= 1;
        assert_eq!(
            announcement.encode(),
            Err(HeaderAnnounceError::BodyClaimMismatch)
        );
    }
}
