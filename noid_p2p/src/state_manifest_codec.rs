// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed, allocation-bounded framing for snapshot manifest headers.
//!
//! Segment descriptors are deliberately absent. The control response carries
//! at most 64 content-addressed page identities; pages use the bounded State
//! metadata data plane and are assembled only after independent verification.

use std::io;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
use noid_chain::{
    consensus::params::RECENT_BLOCK_RETENTION_DEPTH,
    consensus::wire_limits::MAX_SNAPSHOT_MANIFEST_SEGMENTS,
    storage::native_segment::{max_snapshot_segment_len, snapshot_segment_bytes_limit},
    LOG_SEGMENT_SIZE,
};

use crate::protocol::{
    GetStateManifestHeader, GetStateManifestRequest, SnapshotManifestPageRef,
    MAX_SNAPSHOT_MANIFEST_PAGES, SNAPSHOT_MANIFEST_FORMAT_VERSION,
};

const REQUEST_MAGIC: [u8; 4] = *b"NMQ7";
const RESPONSE_MAGIC: [u8; 4] = *b"NMH7";
const REQUEST_BYTES: usize = 4 + 8 + 32;
const RESPONSE_HEADER_BYTES: usize =
    4 + 8 + 32 + 32 + 4 + 32 + 32 + 4 + 8 + 8 + 1 + 8 + 32 + 32 + 4 + 2;
const PAGE_REF_BYTES: usize = 2 + 32 + 4 + 2;

#[derive(Debug, Clone, Copy, Default)]
pub struct StateManifestCodec;

#[async_trait]
impl request_response::Codec for StateManifestCodec {
    type Protocol = StreamProtocol;
    type Request = GetStateManifestRequest;
    type Response = GetStateManifestHeader;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut encoded = [0u8; REQUEST_BYTES];
        io.read_exact(&mut encoded).await?;
        if encoded[..4] != REQUEST_MAGIC {
            return Err(invalid_data("invalid state-manifest request magic/version"));
        }
        ensure_eof(io).await?;
        Ok(GetStateManifestRequest {
            requester_height: u64::from_le_bytes(encoded[4..12].try_into().unwrap()),
            requested_manifest_digest: encoded[12..44].try_into().unwrap(),
        })
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut encoded = [0u8; RESPONSE_HEADER_BYTES];
        io.read_exact(&mut encoded).await?;
        if encoded[..4] != RESPONSE_MAGIC {
            return Err(invalid_data("invalid state-manifest header magic/version"));
        }
        let page_count = u16::from_le_bytes(encoded[241..243].try_into().unwrap()) as usize;
        if page_count > MAX_SNAPSHOT_MANIFEST_PAGES {
            return Err(invalid_data("manifest descriptor page count exceeds cap"));
        }
        let mut descriptor_pages = Vec::new();
        descriptor_pages
            .try_reserve_exact(page_count)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "manifest page allocation failed",
                )
            })?;
        for _ in 0..page_count {
            let mut page = [0u8; PAGE_REF_BYTES];
            io.read_exact(&mut page).await?;
            descriptor_pages.push(SnapshotManifestPageRef {
                page_index: u16::from_le_bytes(page[..2].try_into().unwrap()),
                byte_digest: page[2..34].try_into().unwrap(),
                encoded_len: u32::from_le_bytes(page[34..38].try_into().unwrap()),
                descriptor_count: u16::from_le_bytes(page[38..40].try_into().unwrap()),
            });
        }
        ensure_eof(io).await?;
        let response = GetStateManifestHeader {
            tip_height: u64::from_le_bytes(encoded[4..12].try_into().unwrap()),
            tip_hash: encoded[12..44].try_into().unwrap(),
            cumulative_chainwork: encoded[44..76].try_into().unwrap(),
            format_version: u32::from_le_bytes(encoded[76..80].try_into().unwrap()),
            state_root: encoded[80..112].try_into().unwrap(),
            manifest_digest: encoded[112..144].try_into().unwrap(),
            log_slots: u32::from_le_bytes(encoded[144..148].try_into().unwrap()),
            active_slot_count: u64::from_le_bytes(encoded[148..156].try_into().unwrap()),
            alloc_counter: u64::from_le_bytes(encoded[156..164].try_into().unwrap()),
            eff_log: encoded[164],
            bridge_tip_height: u64::from_le_bytes(encoded[165..173].try_into().unwrap()),
            bridge_tip_hash: encoded[173..205].try_into().unwrap(),
            bridge_cumulative_chainwork: encoded[205..237].try_into().unwrap(),
            segment_count: u32::from_le_bytes(encoded[237..241].try_into().unwrap()),
            descriptor_pages,
        };
        validate_header(&response)?;
        Ok(response)
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let mut encoded = [0u8; REQUEST_BYTES];
        encoded[..4].copy_from_slice(&REQUEST_MAGIC);
        encoded[4..12].copy_from_slice(&request.requester_height.to_le_bytes());
        encoded[12..44].copy_from_slice(&request.requested_manifest_digest);
        io.write_all(&encoded).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        validate_header(&response)?;
        let mut encoded = [0u8; RESPONSE_HEADER_BYTES];
        encoded[..4].copy_from_slice(&RESPONSE_MAGIC);
        encoded[4..12].copy_from_slice(&response.tip_height.to_le_bytes());
        encoded[12..44].copy_from_slice(&response.tip_hash);
        encoded[44..76].copy_from_slice(&response.cumulative_chainwork);
        encoded[76..80].copy_from_slice(&response.format_version.to_le_bytes());
        encoded[80..112].copy_from_slice(&response.state_root);
        encoded[112..144].copy_from_slice(&response.manifest_digest);
        encoded[144..148].copy_from_slice(&response.log_slots.to_le_bytes());
        encoded[148..156].copy_from_slice(&response.active_slot_count.to_le_bytes());
        encoded[156..164].copy_from_slice(&response.alloc_counter.to_le_bytes());
        encoded[164] = response.eff_log;
        encoded[165..173].copy_from_slice(&response.bridge_tip_height.to_le_bytes());
        encoded[173..205].copy_from_slice(&response.bridge_tip_hash);
        encoded[205..237].copy_from_slice(&response.bridge_cumulative_chainwork);
        encoded[237..241].copy_from_slice(&response.segment_count.to_le_bytes());
        encoded[241..243].copy_from_slice(
            &u16::try_from(response.descriptor_pages.len())
                .map_err(|_| invalid_data("manifest page count does not fit u16"))?
                .to_le_bytes(),
        );
        io.write_all(&encoded).await?;
        for page in response.descriptor_pages {
            io.write_all(&page.page_index.to_le_bytes()).await?;
            io.write_all(&page.byte_digest).await?;
            io.write_all(&page.encoded_len.to_le_bytes()).await?;
            io.write_all(&page.descriptor_count.to_le_bytes()).await?;
        }
        io.flush().await
    }
}

fn validate_header(header: &GetStateManifestHeader) -> io::Result<()> {
    if header.tip_height == 0 {
        if header != &GetStateManifestHeader::default() {
            return Err(invalid_data(
                "empty state manifest carries non-zero metadata",
            ));
        }
        return Ok(());
    }
    if header.format_version != SNAPSHOT_MANIFEST_FORMAT_VERSION {
        return Err(invalid_data("unsupported snapshot manifest format"));
    }
    if !(1..=32).contains(&header.log_slots) {
        return Err(invalid_data("manifest log_slots is outside 1..=32"));
    }
    let total_slots = 1u64
        .checked_shl(header.log_slots)
        .ok_or_else(|| invalid_data("manifest slot domain overflows"))?;
    if header.active_slot_count > total_slots
        || header.active_slot_count > header.alloc_counter
        || u64::from(header.segment_count) > header.active_slot_count
    {
        return Err(invalid_data("manifest State counts are inconsistent"));
    }
    if header.segment_count as usize > MAX_SNAPSHOT_MANIFEST_SEGMENTS {
        return Err(invalid_data("manifest segment count exceeds cap"));
    }
    if header.bridge_tip_height < header.tip_height
        || header.bridge_tip_height.saturating_sub(header.tip_height) > RECENT_BLOCK_RETENTION_DEPTH
        || (header.bridge_tip_height == header.tip_height
            && (header.bridge_tip_hash != header.tip_hash
                || header.bridge_cumulative_chainwork != header.cumulative_chainwork))
        || (header.bridge_tip_height > header.tip_height
            && !noid_chain::work_gt(
                &header.bridge_cumulative_chainwork,
                &header.cumulative_chainwork,
            ))
    {
        return Err(invalid_data("manifest bridge geometry is invalid"));
    }
    let expected_eff_log = header.log_slots.min(LOG_SEGMENT_SIZE as u32) as u8;
    if header.eff_log != expected_eff_log
        || max_snapshot_segment_len(header.eff_log, header.tip_height)
            .is_none_or(|length| length > snapshot_segment_bytes_limit(header.tip_height))
    {
        return Err(invalid_data("manifest segment geometry is invalid"));
    }
    let maximum_segments = 1u32
        .checked_shl(header.log_slots - u32::from(header.eff_log))
        .ok_or_else(|| invalid_data("manifest segment namespace overflows"))?;
    if header.segment_count > maximum_segments {
        return Err(invalid_data("manifest segment count exceeds State domain"));
    }
    if !header.has_canonical_page_shape() || !header.has_valid_manifest_digest() {
        return Err(invalid_data("manifest page shape or digest is invalid"));
    }
    Ok(())
}

async fn ensure_eof<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<()> {
    let mut trailing = [0u8; 1];
    if io.read(&mut trailing).await? != 0 {
        return Err(invalid_data("trailing bytes in state-manifest message"));
    }
    Ok(())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use libp2p::request_response::Codec;

    use super::*;
    use crate::protocol::GetStateManifestResponse;

    fn protocol() -> StreamProtocol {
        StreamProtocol::new("/noid/test/sync/manifest/7")
    }

    fn populated() -> (GetStateManifestHeader, Vec<std::sync::Arc<[u8]>>) {
        let mut manifest = GetStateManifestResponse {
            tip_height: 77,
            tip_hash: [0x11; 32],
            cumulative_chainwork: [0x22; 32],
            format_version: SNAPSHOT_MANIFEST_FORMAT_VERSION,
            state_root: [0x21; 32],
            manifest_digest: [0; 32],
            log_slots: 17,
            active_slot_count: 9,
            alloc_counter: 12,
            eff_log: 16,
            bridge_tip_height: 95,
            bridge_tip_hash: [0x23; 32],
            bridge_cumulative_chainwork: [0x24; 32],
            segment_ids: vec![0, 1],
            segment_roots: vec![[0x33; 32], [0x44; 32]],
            segment_lengths: vec![209, 259],
        };
        assert!(manifest.seal_manifest_digest());
        manifest.to_header_and_pages().unwrap()
    }

    #[tokio::test]
    async fn small_header_round_trip_never_contains_descriptors() {
        let (header, _) = populated();
        let mut wire = Cursor::new(Vec::new());
        StateManifestCodec
            .write_response(&protocol(), &mut wire, header.clone())
            .await
            .unwrap();
        assert_eq!(wire.get_ref().len(), RESPONSE_HEADER_BYTES + PAGE_REF_BYTES);
        wire.set_position(0);
        assert_eq!(
            StateManifestCodec
                .read_response(&protocol(), &mut wire)
                .await
                .unwrap(),
            header
        );
    }

    #[tokio::test]
    async fn page_count_bomb_rejects_before_allocation() {
        let (header, _) = populated();
        let mut wire = Cursor::new(Vec::new());
        StateManifestCodec
            .write_response(&protocol(), &mut wire, header)
            .await
            .unwrap();
        let mut bytes = wire.into_inner();
        bytes[241..243].copy_from_slice(&u16::MAX.to_le_bytes());
        let error = StateManifestCodec
            .read_response(&protocol(), &mut Cursor::new(bytes))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn empty_header_has_one_canonical_frame() {
        let mut wire = Cursor::new(Vec::new());
        StateManifestCodec
            .write_response(&protocol(), &mut wire, GetStateManifestHeader::default())
            .await
            .unwrap();
        assert_eq!(wire.get_ref().len(), RESPONSE_HEADER_BYTES);
    }
}
