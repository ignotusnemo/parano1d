// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;

const MAGIC: &[u8; 8] = b"O1A4OR01";
const HEADER: usize = noid_chain::wire::BLOCK_HEADER_WIRE_SIZE;
const PREFIX: usize = 40 + 2 * HEADER + 8;
pub const MAX_AUTHORIZATION_ORIGIN_BYTES: usize =
    noid_chain::consensus::wire_limits::MAX_V2_FORK_ORIGIN_TRANSPORT_BYTES;

#[derive(Clone, Debug)]
pub struct AuthorizationOriginCertificate {
    parent: BlockHeader,
    epoch: BlockHeader,
    terminal: Vec<u8>,
    previous_origin: Vec<u8>,
    previous_request: [u8; 32],
}

impl AuthorizationOriginCertificate {
    pub fn new(
        parent: BlockHeader,
        epoch: BlockHeader,
        terminal: Vec<u8>,
        previous_origin: Vec<u8>,
        previous_request: [u8; 32],
    ) -> Result<Self, V2Error> {
        Self::check_metadata(&parent, &epoch, &terminal, &previous_origin)?;
        Ok(Self {
            parent,
            epoch,
            terminal,
            previous_origin,
            previous_request,
        })
    }

    fn check_metadata(
        parent: &BlockHeader,
        epoch: &BlockHeader,
        terminal: &[u8],
        origin: &[u8],
    ) -> Result<(), V2Error> {
        let metadata =
            noid_chain::history_step::HistoryStepTerminalMetadata::decode_prefix(terminal)
                .map_err(|_| V2Error::Origin)?;
        if !noid_chain::consensus::params::v2_active(parent.height)
            || metadata.terminal_height() != parent.height
            || metadata.terminal_hash() != noid_chain::block_header::semantic_header_id(parent)
            || metadata.class_id() >= 2
            || epoch.height
                != noid_chain::consensus::tx_epoch_anchor_height_for_child(parent.height)
            || terminal.len()
                > noid_chain::consensus::wire_limits::history_step_terminal_bytes_limit(
                    parent.height,
                )
            || !(origin.starts_with(b"O1V2OR01") || origin.starts_with(b"O1V2OR02"))
            || origin.len() > MAX_RETIREMENT_ORIGIN_BYTES
            || PREFIX
                .checked_add(terminal.len())
                .and_then(|n| n.checked_add(origin.len()))
                .is_none_or(|n| n > MAX_AUTHORIZATION_ORIGIN_BYTES)
        {
            return Err(V2Error::Origin);
        }
        Ok(())
    }

    pub const fn previous_origin_request(&self) -> [u8; 32] {
        self.previous_request
    }

    pub fn with_previous_origin_bytes(self, bytes: Vec<u8>) -> Result<Self, V2Error> {
        Self::new(
            self.parent,
            self.epoch,
            self.terminal,
            bytes,
            self.previous_request,
        )
    }

    pub fn previous_origin_bytes(&self) -> &[u8] {
        &self.previous_origin
    }

    pub fn verify(
        &self,
        previous: &Runtime,
        previous_origin: &VerifiedOrigin,
        next: &Bank,
    ) -> Result<VerifiedOrigin, V2Error> {
        Self::check_metadata(
            &self.parent,
            &self.epoch,
            &self.terminal,
            &self.previous_origin,
        )?;
        if previous_origin.origin().request_binding() != self.previous_request {
            return Err(V2Error::Origin);
        }
        let terminal = decode_terminal(previous, &self.terminal)?;
        VerifiedOrigin::from_authorization_boundary(
            previous,
            previous_origin,
            &terminal,
            &self.parent,
            &self.epoch,
            next,
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(PREFIX + self.terminal.len() + self.previous_origin.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.previous_request);
        bytes.extend_from_slice(&self.parent.to_bytes());
        bytes.extend_from_slice(&self.epoch.to_bytes());
        bytes.extend_from_slice(&(self.terminal.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.previous_origin.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.terminal);
        bytes.extend_from_slice(&self.previous_origin);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, V2Error> {
        if bytes.len() <= PREFIX
            || bytes.len() > MAX_AUTHORIZATION_ORIGIN_BYTES
            || !bytes.starts_with(MAGIC)
        {
            return Err(V2Error::Origin);
        }
        let terminal_len = u32::from_le_bytes(
            bytes[PREFIX - 8..PREFIX - 4]
                .try_into()
                .map_err(|_| V2Error::Origin)?,
        ) as usize;
        let origin_len = u32::from_le_bytes(
            bytes[PREFIX - 4..PREFIX]
                .try_into()
                .map_err(|_| V2Error::Origin)?,
        ) as usize;
        let end = PREFIX.checked_add(terminal_len).ok_or(V2Error::Origin)?;
        if end.checked_add(origin_len) != Some(bytes.len()) {
            return Err(V2Error::Origin);
        }
        let parent =
            BlockHeader::from_bytes(&bytes[40..40 + HEADER]).map_err(|_| V2Error::Origin)?;
        let epoch = BlockHeader::from_bytes(&bytes[40 + HEADER..PREFIX - 8])
            .map_err(|_| V2Error::Origin)?;
        Self::check_metadata(&parent, &epoch, &bytes[PREFIX..end], &bytes[end..])?;
        Self::new(
            parent,
            epoch,
            bytes[PREFIX..end].to_vec(),
            bytes[end..].to_vec(),
            bytes[8..40].try_into().map_err(|_| V2Error::Origin)?,
        )
    }
}
