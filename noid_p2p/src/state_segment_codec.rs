// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Allocation-bounded snapshot-segment wire codec.
//!
//! Lengths are bounded by sparse geometry before allocation. Protocol 5 keeps
//! its original framing; protocol 6 adds bounded compression and batches.
//! Protocol 7 carries complete segments with committed native records. The
//! node authenticates each payload against its immutable snapshot descriptor.

use std::{io, sync::Arc};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
#[cfg(test)]
use noid_chain::storage::{
    encoded_segment_len_for_live_count, max_encoded_segment_len_for_eff_log,
};

use crate::{
    inbound_budget::process_global_inbound_budget,
    object_protocol::DataResponseStatus,
    outbound_budget::OutboundResponseBudget,
    protocol::{
        GetStateSegmentRequest, GetStateSegmentResponse, StateSegmentPayload,
        StateSegmentTransport, MAX_STATE_SEGMENT_BATCH, MAX_STATE_SEGMENT_BATCH_BYTES,
    },
};

const REQUEST_MAGIC: [u8; 4] = *b"NSR5";
const RESPONSE_MAGIC: [u8; 4] = *b"NSS6";
const REQUEST_HEADER_BYTES: usize = 80;
const RESPONSE_HEADER_BYTES: usize = 86;
const NONE_LEN: u32 = u32::MAX;
const COMPRESSED_REQUEST_MAGIC: [u8; 4] = *b"NSR6";
const COMPRESSED_RESPONSE_MAGIC: [u8; 4] = *b"NSS7";
const NATIVE_REQUEST_MAGIC: [u8; 4] = *b"NSR7";
const NATIVE_RESPONSE_MAGIC: [u8; 4] = *b"NSS8";
const TRANSPORT_HEADER_BYTES: usize = 5;
const RAW: u8 = 0;
const ZSTD: u8 = 1;
const BATCH_RAW: u8 = 2;
const BATCH_ZSTD: u8 = 3;
const COMPRESSION_LEVEL: i32 = 3;
const ZSTD_WINDOW_LOG_MAX: u32 = 22;

/// Reserve both buffers in one admission operation before the storage read.
/// Server requests do not expose the negotiated version, so this conservative
/// reservation also covers v5. It never increases the shared 64 MiB budget.
pub(crate) fn outbound_reservation_bytes(canonical_len: usize) -> usize {
    if canonical_len == 0 {
        0
    } else {
        canonical_len + zstd::zstd_safe::compress_bound(canonical_len)
    }
}

pub(crate) fn batch_outbound_reservation_bytes(canonical_len: usize, count: usize) -> usize {
    outbound_reservation_bytes(canonical_len) + if count > 1 { canonical_len } else { 0 }
}

fn validate_batch_ids(first: u16, additional: &[u16]) -> io::Result<()> {
    if additional.len() >= MAX_STATE_SEGMENT_BATCH
        || additional.first().is_some_and(|id| *id <= first)
        || additional.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid_data(
            "invalid bounded ascending State segment batch",
        ));
    }
    Ok(())
}

fn segment_protocol_version(protocol: &StreamProtocol) -> io::Result<u8> {
    if protocol.as_ref().ends_with("/sync/segment/7") {
        Ok(7)
    } else if protocol.as_ref().ends_with("/sync/segment/6") {
        Ok(6)
    } else if protocol.as_ref().ends_with("/sync/segment/5") {
        Ok(5)
    } else {
        Err(invalid_data("unsupported state-segment protocol"))
    }
}
#[derive(Debug, Clone)]
pub struct StateSegmentCodec {
    inbound_budget: Arc<tokio::sync::Semaphore>,
    outbound_budget: OutboundResponseBudget,
}

impl Default for StateSegmentCodec {
    fn default() -> Self {
        Self {
            inbound_budget: process_global_inbound_budget(),
            outbound_budget: OutboundResponseBudget::process_global(),
        }
    }
}

impl StateSegmentCodec {
    #[cfg(test)]
    fn with_inbound_budget(bytes: usize) -> Self {
        Self {
            inbound_budget: Arc::new(tokio::sync::Semaphore::new(bytes)),
            outbound_budget: OutboundResponseBudget::process_global(),
        }
    }

    async fn acquire_inbound(
        &self,
        bytes: usize,
    ) -> io::Result<Option<Arc<tokio::sync::OwnedSemaphorePermit>>> {
        if bytes == 0 {
            return Ok(None);
        }
        let permits =
            u32::try_from(bytes).map_err(|_| invalid_data("state-segment byte budget overflow"))?;
        let permit = self
            .inbound_budget
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "state-segment budget closed")
            })?;
        Ok(Some(Arc::new(permit)))
    }
}

#[async_trait]
impl request_response::Codec for StateSegmentCodec {
    type Protocol = StreamProtocol;
    type Request = GetStateSegmentRequest;
    type Response = GetStateSegmentResponse;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut header = [0u8; REQUEST_HEADER_BYTES];
        io.read_exact(&mut header).await?;
        let version = segment_protocol_version(protocol)?;
        let compressed = version >= 6;
        let magic = if version == 7 {
            NATIVE_REQUEST_MAGIC
        } else if compressed {
            COMPRESSED_REQUEST_MAGIC
        } else {
            REQUEST_MAGIC
        };
        if header[..4] != magic {
            return Err(invalid_data("invalid state-segment request magic/version"));
        }
        let additional_count = u16::from_le_bytes(header[6..8].try_into().unwrap()) as usize;
        if (!compressed && additional_count != 0) || additional_count >= MAX_STATE_SEGMENT_BATCH {
            return Err(invalid_data(
                "non-zero state-segment request reserved bytes",
            ));
        }
        if header[48..80] == [0; 32] {
            return Err(invalid_data(
                "state-segment request has no manifest identity",
            ));
        }
        let segment_id = u16::from_le_bytes(header[4..6].try_into().unwrap());
        let mut additional_segments = Vec::with_capacity(additional_count);
        for _ in 0..additional_count {
            let mut id = [0; 2];
            io.read_exact(&mut id).await?;
            additional_segments.push(u16::from_le_bytes(id));
        }
        validate_batch_ids(segment_id, &additional_segments)?;
        ensure_eof(io).await?;
        Ok(GetStateSegmentRequest {
            segment_id,
            additional_segments,
            expected_tip_height: u64::from_le_bytes(
                header[8..16].try_into().expect("fixed tip height"),
            ),
            expected_tip_hash: header[16..48].try_into().expect("fixed tip hash"),
            manifest_digest: header[48..80].try_into().expect("fixed manifest digest"),
        })
    }

    async fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let version = segment_protocol_version(protocol)?;
        let compressed_protocol = version >= 6;
        let mut header = [0u8; RESPONSE_HEADER_BYTES];
        io.read_exact(&mut header).await?;
        if compressed_protocol {
            if header[..4]
                != if version == 7 {
                    NATIVE_RESPONSE_MAGIC
                } else {
                    COMPRESSED_RESPONSE_MAGIC
                }
            {
                return Err(invalid_data("invalid state-segment response magic/version"));
            }
            // The remaining fields retain their v5 positions and invariants.
            header[..4].copy_from_slice(&RESPONSE_MAGIC);
        }
        let fields = parse_response_header_for(&header, version)?;
        let first_len = decoded_len(fields.encoded_len);
        let mut payload_len = first_len;
        let mut extra = Vec::new();
        let (encoding, wire_len) = if compressed_protocol {
            let mut transport = [0u8; TRANSPORT_HEADER_BYTES];
            io.read_exact(&mut transport).await?;
            let encoding = transport[0];
            let wire_len = u32::from_le_bytes(transport[1..5].try_into().unwrap()) as usize;
            if matches!(encoding, BATCH_RAW | BATCH_ZSTD) {
                let mut count = [0; 2];
                io.read_exact(&mut count).await?;
                let count = u16::from_le_bytes(count) as usize;
                if !(2..=MAX_STATE_SEGMENT_BATCH).contains(&count) || fields.encoded_len == NONE_LEN
                {
                    return Err(invalid_data("invalid State segment batch count"));
                }
                let mut previous = fields.segment_id;
                for _ in 1..count {
                    let mut part = [0; 6];
                    io.read_exact(&mut part).await?;
                    let id = u16::from_le_bytes(part[..2].try_into().unwrap());
                    let len = u32::from_le_bytes(part[2..].try_into().unwrap());
                    validate_response_length_at(
                        fields.eff_log,
                        len,
                        if version == 7 {
                            fields.expected_tip_height
                        } else {
                            0
                        },
                    )?;
                    if id <= previous || len == NONE_LEN {
                        return Err(invalid_data("invalid State segment batch descriptor"));
                    }
                    previous = id;
                    payload_len += len as usize;
                    extra.push((id, len as usize));
                }
                if payload_len > MAX_STATE_SEGMENT_BATCH_BYTES {
                    return Err(invalid_data(
                        "State segment batch exceeds aggregate byte cap",
                    ));
                }
            }
            match encoding {
                RAW | BATCH_RAW if wire_len == payload_len => {}
                ZSTD | BATCH_ZSTD if wire_len > 0 && wire_len < payload_len => {}
                _ => {
                    return Err(invalid_data(
                        "invalid state-segment transport length/encoding",
                    ))
                }
            }
            (encoding, wire_len)
        } else {
            (RAW, payload_len)
        };
        let is_zstd = matches!(encoding, ZSTD | BATCH_ZSTD);
        let reserved = payload_len
            + if version == 7 { payload_len } else { 0 }
            + if is_zstd { wire_len } else { 0 }
            + if extra.is_empty() { 0 } else { payload_len };
        let inbound_memory_permit = self.acquire_inbound(reserved).await?;
        let mut data = if fields.encoded_len == NONE_LEN {
            None
        } else {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(wire_len).map_err(|_| {
                io::Error::new(io::ErrorKind::OutOfMemory, "segment allocation failed")
            })?;
            bytes.resize(wire_len, 0);
            io.read_exact(&mut bytes).await?;
            if is_zstd {
                Some(decompress_segment(&bytes, payload_len)?)
            } else {
                Some(bytes)
            }
        };
        ensure_eof(io).await?;
        let mut additional_segments = Vec::with_capacity(extra.len());
        if !extra.is_empty() {
            let bytes = data.as_mut().expect("batch payload is present");
            let mut offset = first_len;
            for (segment_id, len) in extra {
                additional_segments.push(StateSegmentPayload {
                    segment_id,
                    data: bytes[offset..offset + len].to_vec(),
                });
                offset += len;
            }
            bytes.truncate(first_len);
        }
        Ok(GetStateSegmentResponse {
            segment_id: fields.segment_id,
            additional_segments,
            expected_tip_height: fields.expected_tip_height,
            expected_tip_hash: fields.expected_tip_hash,
            manifest_digest: fields.manifest_digest,
            status: fields.status,
            eff_log: fields.eff_log,
            data,
            transport: StateSegmentTransport {
                version,
                payload_bytes: wire_len as u64,
            },
            inbound_memory_permit,
            outbound_memory_permit: None,
        })
    }

    async fn write_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let mut header = [0u8; REQUEST_HEADER_BYTES];
        let version = segment_protocol_version(protocol)?;
        let compressed = version >= 6;
        validate_batch_ids(request.segment_id, &request.additional_segments)?;
        let magic = if version == 7 {
            NATIVE_REQUEST_MAGIC
        } else if compressed {
            COMPRESSED_REQUEST_MAGIC
        } else {
            REQUEST_MAGIC
        };
        header[..4].copy_from_slice(&magic);
        header[4..6].copy_from_slice(&request.segment_id.to_le_bytes());
        if compressed {
            header[6..8].copy_from_slice(&(request.additional_segments.len() as u16).to_le_bytes());
        }
        header[8..16].copy_from_slice(&request.expected_tip_height.to_le_bytes());
        header[16..48].copy_from_slice(&request.expected_tip_hash);
        header[48..80].copy_from_slice(&request.manifest_digest);
        io.write_all(&header).await?;
        if compressed {
            for id in request.additional_segments {
                io.write_all(&id.to_le_bytes()).await?;
            }
        }
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let GetStateSegmentResponse {
            segment_id,
            additional_segments,
            expected_tip_height,
            expected_tip_hash,
            manifest_digest,
            status,
            eff_log,
            data,
            transport: _,
            inbound_memory_permit,
            outbound_memory_permit,
        } = response;
        if !status.is_canonical() {
            return Err(invalid_data("non-canonical state-segment response status"));
        }
        if matches!(status, DataResponseStatus::Busy { .. }) && data.is_some() {
            return Err(invalid_data("busy state-segment response carries data"));
        }
        let encoded_len = optional_len(data.as_deref())?;
        let version = segment_protocol_version(protocol)?;
        let compressed_protocol = version >= 6;
        let height = if version == 7 { expected_tip_height } else { 0 };
        validate_response_length_at(eff_log, encoded_len, height)?;
        if version < 7
            && data.as_deref().is_some_and(|bytes| {
                bytes.starts_with(noid_chain::storage::native_segment::NATIVE_SEGMENT_MAGIC)
            })
        {
            return Err(invalid_data(
                "native State records require segment protocol 7",
            ));
        }
        let mut payload_len = decoded_len(encoded_len);
        let is_batch = !additional_segments.is_empty();
        if is_batch {
            validate_batch_ids(
                segment_id,
                &additional_segments
                    .iter()
                    .map(|part| part.segment_id)
                    .collect::<Vec<_>>(),
            )?;
            if !compressed_protocol
                || data.is_none()
                || !matches!(status, DataResponseStatus::Ready)
            {
                return Err(invalid_data(
                    "State batch requires protocol 6 and complete Ready payloads",
                ));
            }
            for part in &additional_segments {
                validate_response_length_at(eff_log, optional_len(Some(&part.data))?, height)?;
                if version < 7
                    && part
                        .data
                        .starts_with(noid_chain::storage::native_segment::NATIVE_SEGMENT_MAGIC)
                {
                    return Err(invalid_data(
                        "native State records require segment protocol 7",
                    ));
                }
                payload_len += part.data.len();
            }
            if payload_len > MAX_STATE_SEGMENT_BATCH_BYTES {
                return Err(invalid_data(
                    "State segment batch exceeds aggregate byte cap",
                ));
            }
        }
        let reserved = if compressed_protocol {
            batch_outbound_reservation_bytes(payload_len, additional_segments.len() + 1)
        } else {
            payload_len
        };
        let outbound_memory_permit = match outbound_memory_permit {
            Some(permit) if permit.reserved_bytes() >= reserved => Some(permit),
            Some(_) => {
                return Err(invalid_data(
                    "insufficient state-segment outbound reservation",
                ))
            }
            None => self.outbound_budget.acquire(reserved).await?,
        };
        // Both permits (the latter normally only exists for locally-served
        // responses) remain in scope until the final write resolves.
        let _memory_permits = (inbound_memory_permit, outbound_memory_permit);

        let mut header = [0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&if version == 7 {
            NATIVE_RESPONSE_MAGIC
        } else if compressed_protocol {
            COMPRESSED_RESPONSE_MAGIC
        } else {
            RESPONSE_MAGIC
        });
        header[4..6].copy_from_slice(&segment_id.to_le_bytes());
        header[6] = eff_log;
        header[8..16].copy_from_slice(&expected_tip_height.to_le_bytes());
        header[16..48].copy_from_slice(&expected_tip_hash);
        header[48..52].copy_from_slice(&encoded_len.to_le_bytes());
        header[52..84].copy_from_slice(&manifest_digest);
        if let DataResponseStatus::Busy { retry_after_ms } = status {
            header[7] = 1;
            header[84..86].copy_from_slice(&retry_after_ms.to_le_bytes());
        }
        let combined = if is_batch {
            let mut bytes = Vec::with_capacity(payload_len);
            bytes.extend_from_slice(data.as_deref().unwrap());
            for part in &additional_segments {
                bytes.extend_from_slice(&part.data);
            }
            Some(bytes)
        } else {
            None
        };
        let canonical = combined.as_deref().or(data.as_deref());
        let compressed = if compressed_protocol {
            canonical
                .map(|bytes| zstd::bulk::compress(bytes, COMPRESSION_LEVEL))
                .transpose()?
                .filter(|bytes| bytes.len() < payload_len)
        } else {
            None
        };
        let wire_payload = compressed.as_deref().or(canonical);
        io.write_all(&header).await?;
        if compressed_protocol {
            let mut transport = [0u8; TRANSPORT_HEADER_BYTES];
            transport[0] = match (is_batch, compressed.is_some()) {
                (false, false) => RAW,
                (false, true) => ZSTD,
                (true, false) => BATCH_RAW,
                (true, true) => BATCH_ZSTD,
            };
            transport[1..5]
                .copy_from_slice(&(wire_payload.map_or(0, <[u8]>::len) as u32).to_le_bytes());
            io.write_all(&transport).await?;
            if is_batch {
                io.write_all(&((additional_segments.len() + 1) as u16).to_le_bytes())
                    .await?;
                for part in &additional_segments {
                    io.write_all(&part.segment_id.to_le_bytes()).await?;
                    io.write_all(&(part.data.len() as u32).to_le_bytes())
                        .await?;
                }
            }
        }
        if let Some(bytes) = wire_payload {
            io.write_all(bytes).await?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResponseHeaderFields {
    segment_id: u16,
    expected_tip_height: u64,
    expected_tip_hash: [u8; 32],
    manifest_digest: [u8; 32],
    eff_log: u8,
    encoded_len: u32,
    status: DataResponseStatus,
}

fn parse_response_header_for(
    header: &[u8; RESPONSE_HEADER_BYTES],
    version: u8,
) -> io::Result<ResponseHeaderFields> {
    if header[..4] != RESPONSE_MAGIC {
        return Err(invalid_data("invalid state-segment response magic/version"));
    }
    let segment_id = u16::from_le_bytes(header[4..6].try_into().expect("fixed segment id"));
    let eff_log = header[6];
    let expected_tip_height =
        u64::from_le_bytes(header[8..16].try_into().expect("fixed tip height"));
    let expected_tip_hash = header[16..48].try_into().expect("fixed tip hash");
    let encoded_len = u32::from_le_bytes(header[48..52].try_into().expect("fixed length"));
    let manifest_digest = header[52..84].try_into().expect("fixed manifest digest");
    let retry_after_ms = u16::from_le_bytes(header[84..86].try_into().unwrap());
    let status = match header[7] {
        0 if retry_after_ms == 0 => DataResponseStatus::Ready,
        1 => DataResponseStatus::Busy { retry_after_ms },
        _ => return Err(invalid_data("invalid state-segment response status")),
    };
    if !status.is_canonical() {
        return Err(invalid_data("non-canonical state-segment response status"));
    }
    if manifest_digest == [0; 32] {
        return Err(invalid_data(
            "state-segment response has no manifest identity",
        ));
    }
    validate_response_length_at(
        eff_log,
        encoded_len,
        if version == 7 { expected_tip_height } else { 0 },
    )?;
    if matches!(status, DataResponseStatus::Busy { .. })
        && (encoded_len != NONE_LEN || eff_log != 0)
    {
        return Err(invalid_data("busy state-segment response carries data"));
    }
    Ok(ResponseHeaderFields {
        segment_id,
        expected_tip_height,
        expected_tip_hash,
        manifest_digest,
        eff_log,
        encoded_len,
        status,
    })
}

fn validate_response_length_at(eff_log: u8, encoded_len: u32, height: u64) -> io::Result<()> {
    if encoded_len == NONE_LEN {
        return if eff_log == 0 {
            Ok(())
        } else {
            Err(invalid_data(
                "unavailable segment has non-zero effective log",
            ))
        };
    }
    if !noid_chain::storage::native_segment::snapshot_segment_len_valid(
        eff_log,
        encoded_len as usize,
        height,
    ) {
        return Err(invalid_data(
            "declared state-segment length is not canonical for its geometry",
        ));
    }
    Ok(())
}

fn optional_len(data: Option<&[u8]>) -> io::Result<u32> {
    match data {
        Some(bytes) => u32::try_from(bytes.len())
            .map_err(|_| invalid_data("state-segment length does not fit u32")),
        None => Ok(NONE_LEN),
    }
}

fn decompress_segment(compressed: &[u8], canonical_len: usize) -> io::Result<Vec<u8>> {
    let frame_len = zstd::zstd_safe::find_frame_compressed_size(compressed)
        .map_err(|_| invalid_data("invalid state-segment zstd frame"))?;
    if frame_len != compressed.len() {
        return Err(invalid_data(
            "state segment must contain exactly one zstd frame",
        ));
    }
    let content_size = zstd::zstd_safe::get_frame_content_size(compressed)
        .map_err(|_| invalid_data("invalid state-segment zstd content size"))?;
    if content_size != Some(canonical_len as u64) {
        return Err(invalid_data(
            "state-segment zstd content size differs from canonical length",
        ));
    }
    let mut decoder = zstd::bulk::Decompressor::new()?;
    decoder.window_log_max(ZSTD_WINDOW_LOG_MAX)?;
    let decoded = decoder
        .decompress(compressed, canonical_len)
        .map_err(|_| invalid_data("state-segment zstd decompression failed"))?;
    if decoded.len() != canonical_len {
        return Err(invalid_data(
            "state-segment decompressed length differs from canonical length",
        ));
    }
    Ok(decoded)
}

#[inline]
fn decoded_len(encoded_len: u32) -> usize {
    if encoded_len == NONE_LEN {
        0
    } else {
        encoded_len as usize
    }
}

async fn ensure_eof<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<()> {
    let mut trailing = [0u8; 1];
    if io.read(&mut trailing).await? != 0 {
        return Err(invalid_data("trailing bytes in state-segment message"));
    }
    Ok(())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use futures::io::Cursor;
    use libp2p::request_response::Codec;

    use super::*;

    fn protocol() -> StreamProtocol {
        StreamProtocol::new("/noid/test/sync/segment/5")
    }

    fn protocol_v6() -> StreamProtocol {
        StreamProtocol::new("/noid/test/sync/segment/6")
    }

    fn response(data: Option<Vec<u8>>, eff_log: u8) -> GetStateSegmentResponse {
        GetStateSegmentResponse {
            segment_id: 7,
            additional_segments: Vec::new(),
            expected_tip_height: 77,
            expected_tip_hash: [0xA5; 32],
            manifest_digest: [0xB6; 32],
            status: DataResponseStatus::Ready,
            eff_log,
            data,
            transport: Default::default(),
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        }
    }

    fn v6_wire(eff_log: u8, canonical_len: u32, encoding: u8, payload: &[u8]) -> Vec<u8> {
        let mut wire = response_header(eff_log, canonical_len);
        wire[..4].copy_from_slice(&COMPRESSED_RESPONSE_MAGIC);
        wire.push(encoding);
        wire.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        wire.extend_from_slice(payload);
        wire
    }

    #[tokio::test]
    async fn batch_round_trip_keeps_exact_payloads_and_charges_split_buffers() {
        let mut value = response(Some(vec![7; 59]), 16);
        value.additional_segments = (8..71)
            .map(|segment_id| StateSegmentPayload {
                segment_id,
                data: vec![segment_id as u8; 59],
            })
            .collect();
        let canonical = value
            .payloads()
            .map(|(id, data)| (id, data.to_vec()))
            .collect::<Vec<_>>();
        let mut wire = Cursor::new(Vec::new());
        StateSegmentCodec::default()
            .write_response(&protocol_v6(), &mut wire, value)
            .await
            .unwrap();
        assert_eq!(wire.get_ref()[RESPONSE_HEADER_BYTES], BATCH_ZSTD);
        let wire_len = u32::from_le_bytes(wire.get_ref()[87..91].try_into().unwrap()) as usize;
        let charged = 2 * 64 * 59 + wire_len;
        let mut codec = StateSegmentCodec::with_inbound_budget(charged);
        let decoded = codec
            .read_response(&protocol_v6(), &mut Cursor::new(wire.into_inner()))
            .await
            .unwrap();
        assert_eq!(
            decoded
                .payloads()
                .map(|(id, data)| (id, data.to_vec()))
                .collect::<Vec<_>>(),
            canonical
        );
        assert_eq!(codec.inbound_budget.available_permits(), 0);
        drop(decoded);
        assert_eq!(codec.inbound_budget.available_permits(), charged);
    }

    #[tokio::test]
    async fn malformed_batches_fail_before_payload_admission() {
        for (count, second_id, second_len) in [
            (0u16, 8u16, 59u32),
            (1, 8, 59),
            (65, 8, 59),
            (2, 7, 59),
            (2, 8, 60),
            (2, 8, 65509),
        ] {
            let mut wire = v6_wire(16, 59, BATCH_RAW, &[]);
            wire[87..91].copy_from_slice(&(59u32 + second_len).to_le_bytes());
            wire.extend_from_slice(&count.to_le_bytes());
            wire.extend_from_slice(&second_id.to_le_bytes());
            wire.extend_from_slice(&second_len.to_le_bytes());
            let mut codec = StateSegmentCodec::with_inbound_budget(0);
            let result = tokio::time::timeout(
                Duration::from_millis(100),
                codec.read_response(&protocol_v6(), &mut Cursor::new(wire)),
            )
            .await;
            assert!(result.unwrap().is_err());
        }
    }

    #[tokio::test]
    async fn batch_request_round_trip_and_legacy_fallback() {
        let request = GetStateSegmentRequest {
            segment_id: 7,
            additional_segments: vec![8, 9],
            expected_tip_height: 77,
            expected_tip_hash: [0xA5; 32],
            manifest_digest: [0xB6; 32],
        };
        for (protocol, ids, bytes) in [(protocol_v6(), vec![8, 9], 84), (protocol(), vec![], 80)] {
            let mut wire = Cursor::new(Vec::new());
            let mut codec = StateSegmentCodec::default();
            codec
                .write_request(&protocol, &mut wire, request.clone())
                .await
                .unwrap();
            assert_eq!(wire.get_ref().len(), bytes);
            let decoded = codec
                .read_request(&protocol, &mut Cursor::new(wire.into_inner()))
                .await
                .unwrap();
            assert_eq!(decoded.additional_segments, ids);
        }
        let mut codec = StateSegmentCodec::default();
        for ids in [vec![7], vec![9, 8], (8..72).collect()] {
            let mut bad = request.clone();
            bad.additional_segments = ids;
            assert!(codec
                .write_request(&protocol_v6(), &mut Cursor::new(Vec::new()), bad)
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn v5_wire_is_byte_identical_to_original_framing() {
        let data = vec![0x5a; encoded_segment_len_for_live_count(10, 3).unwrap()];
        let mut expected = response_header(10, data.len() as u32);
        expected.extend_from_slice(&data);
        let mut wire = Cursor::new(Vec::new());
        StateSegmentCodec::default()
            .write_response(&protocol(), &mut wire, response(Some(data), 10))
            .await
            .unwrap();
        assert_eq!(wire.into_inner(), expected);
    }

    #[tokio::test]
    async fn v6_full_segment_round_trip_charges_both_buffers_until_consumption() {
        let len = max_encoded_segment_len_for_eff_log(16).unwrap();
        let data = vec![0x5a; len];
        let mut wire = Cursor::new(Vec::new());
        StateSegmentCodec::default()
            .write_response(&protocol_v6(), &mut wire, response(Some(data.clone()), 16))
            .await
            .unwrap();
        assert_eq!(wire.get_ref()[RESPONSE_HEADER_BYTES], ZSTD);
        let payload_len = wire.get_ref().len() - RESPONSE_HEADER_BYTES - TRANSPORT_HEADER_BYTES;
        assert!(payload_len < len / 10);
        let reserved = len + payload_len;
        let mut codec = StateSegmentCodec::with_inbound_budget(reserved);
        wire.set_position(0);
        let decoded = codec
            .read_response(&protocol_v6(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.data.as_deref(), Some(data.as_slice()));
        assert_eq!(decoded.transport.version, 6);
        assert_eq!(decoded.transport.payload_bytes, payload_len as u64);
        assert_eq!(codec.inbound_budget.available_permits(), 0);
        drop(decoded);
        assert_eq!(codec.inbound_budget.available_permits(), reserved);
    }

    #[tokio::test]
    async fn v6_uses_raw_when_compression_would_expand_a_small_segment() {
        let len = encoded_segment_len_for_live_count(16, 1).unwrap();
        let data: Vec<u8> = (0..len).map(|index| index as u8).collect();
        let mut wire = Cursor::new(Vec::new());
        StateSegmentCodec::default()
            .write_response(&protocol_v6(), &mut wire, response(Some(data.clone()), 16))
            .await
            .unwrap();
        assert_eq!(wire.get_ref()[RESPONSE_HEADER_BYTES], RAW);
        assert_eq!(
            wire.get_ref().len(),
            RESPONSE_HEADER_BYTES + TRANSPORT_HEADER_BYTES + len
        );
        wire.set_position(0);
        let decoded = StateSegmentCodec::default()
            .read_response(&protocol_v6(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.data.unwrap(), data);
        assert_eq!(decoded.transport.payload_bytes, len as u64);
    }

    #[tokio::test]
    async fn v6_preserves_busy_and_unavailable_without_payload_allocation() {
        for status in [
            DataResponseStatus::Ready,
            DataResponseStatus::Busy {
                retry_after_ms: 800,
            },
        ] {
            let mut value = response(None, 0);
            value.status = status;
            let mut wire = Cursor::new(Vec::new());
            StateSegmentCodec::default()
                .write_response(&protocol_v6(), &mut wire, value)
                .await
                .unwrap();
            wire.set_position(0);
            let decoded = StateSegmentCodec::with_inbound_budget(0)
                .read_response(&protocol_v6(), &mut wire)
                .await
                .unwrap();
            assert_eq!(decoded.status, status);
            assert!(decoded.data.is_none());
            assert!(decoded.inbound_memory_permit.is_none());
        }
    }

    #[tokio::test]
    async fn v6_rejects_invalid_transport_lengths_before_admission() {
        let len = encoded_segment_len_for_live_count(16, 1).unwrap();
        for (encoding, wire_len) in [(RAW, len + 1), (ZSTD, len), (ZSTD, 0), (4, 1)] {
            let wire = v6_wire(16, len as u32, encoding, &vec![0; wire_len]);
            let mut codec = StateSegmentCodec::with_inbound_budget(0);
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                codec.read_response(&protocol_v6(), &mut Cursor::new(wire)),
            )
            .await
            .expect("invalid framing must not wait for byte admission");
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn v6_rejects_wrong_content_size_concatenation_truncation_and_trailing_data() {
        let len = encoded_segment_len_for_live_count(16, 20).unwrap();
        let compressed = zstd::bulk::compress(&vec![0x5a; len], COMPRESSION_LEVEL).unwrap();
        let mut concatenated = compressed.clone();
        concatenated.extend_from_slice(&compressed);
        let mut trailing = compressed.clone();
        trailing.push(0);
        let wrong_size = zstd::bulk::compress(&vec![0; len - 50], COMPRESSION_LEVEL).unwrap();
        for payload in [
            concatenated,
            trailing,
            wrong_size,
            compressed[..compressed.len() - 1].to_vec(),
        ] {
            let mut codec = StateSegmentCodec::with_inbound_budget(len * 2);
            let error = codec
                .read_response(
                    &protocol_v6(),
                    &mut Cursor::new(v6_wire(16, len as u32, ZSTD, &payload)),
                )
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(codec.inbound_budget.available_permits(), len * 2);
        }
        let mut truncated_wire = v6_wire(16, len as u32, ZSTD, &compressed);
        truncated_wire.pop();
        let mut codec = StateSegmentCodec::with_inbound_budget(len * 2);
        assert_eq!(
            codec
                .read_response(&protocol_v6(), &mut Cursor::new(truncated_wire))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(codec.inbound_budget.available_permits(), len * 2);
    }

    #[tokio::test]
    async fn protocol_versions_cannot_be_cross_decoded() {
        let data = vec![0; encoded_segment_len_for_live_count(16, 1).unwrap()];
        for (sender, receiver) in [(protocol(), protocol_v6()), (protocol_v6(), protocol())] {
            let mut wire = Cursor::new(Vec::new());
            StateSegmentCodec::default()
                .write_response(&sender, &mut wire, response(Some(data.clone()), 16))
                .await
                .unwrap();
            wire.set_position(0);
            assert_eq!(
                StateSegmentCodec::default()
                    .read_response(&receiver, &mut wire)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[tokio::test]
    async fn compressed_write_uses_one_precharged_reservation_without_waiting_for_more() {
        let len = encoded_segment_len_for_live_count(16, 100).unwrap();
        let reserved = outbound_reservation_bytes(len);
        let budget = OutboundResponseBudget::with_capacity(reserved);
        let serving = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = budget
            .acquire_with_serving(reserved, vec![serving.clone().try_acquire_owned().unwrap()])
            .await
            .unwrap();
        let mut value = response(Some(vec![0x5a; len]), 16);
        value.outbound_memory_permit = permit;
        let mut codec = StateSegmentCodec {
            outbound_budget: budget.clone(),
            ..Default::default()
        };
        let mut wire = Cursor::new(Vec::new());
        tokio::time::timeout(
            Duration::from_secs(1),
            codec.write_response(&protocol_v6(), &mut wire, value),
        )
        .await
        .expect("compression must not wait for a second reservation while holding the first")
        .unwrap();
        assert_eq!(wire.get_ref()[RESPONSE_HEADER_BYTES], ZSTD);
        assert_eq!(budget.available_bytes(), reserved);
        assert_eq!(serving.available_permits(), 1);
    }

    fn response_header(eff_log: u8, encoded_len: u32) -> Vec<u8> {
        let mut header = vec![0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..6].copy_from_slice(&7u16.to_le_bytes());
        header[6] = eff_log;
        header[8..16].copy_from_slice(&77u64.to_le_bytes());
        header[16..48].copy_from_slice(&[0xA5; 32]);
        header[48..52].copy_from_slice(&encoded_len.to_le_bytes());
        header[52..84].copy_from_slice(&[0xB6; 32]);
        header
    }

    #[test]
    fn production_codecs_share_one_process_inbound_budget() {
        let first = StateSegmentCodec::default();
        let second = StateSegmentCodec::default();
        let shared = process_global_inbound_budget();
        assert!(Arc::ptr_eq(&first.inbound_budget, &second.inbound_budget));
        assert!(Arc::ptr_eq(&first.inbound_budget, &shared));
    }

    #[tokio::test]
    async fn request_round_trip_binds_segment_and_exact_snapshot_boundary() {
        let request = GetStateSegmentRequest {
            segment_id: 0x1234,
            additional_segments: Vec::new(),
            expected_tip_height: 77,
            expected_tip_hash: [0xA5; 32],
            manifest_digest: [0xB6; 32],
        };
        let mut wire = Cursor::new(Vec::new());
        StateSegmentCodec::default()
            .write_request(&protocol(), &mut wire, request)
            .await
            .unwrap();
        assert_eq!(wire.get_ref().len(), REQUEST_HEADER_BYTES);
        wire.set_position(0);
        let decoded = StateSegmentCodec::default()
            .read_request(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.segment_id, 0x1234);
        assert_eq!(decoded.expected_tip_height, 77);
        assert_eq!(decoded.expected_tip_hash, [0xA5; 32]);
        assert_eq!(decoded.manifest_digest, [0xB6; 32]);

        let mut noncanonical = wire.into_inner();
        noncanonical[6] = 1;
        let error = StateSegmentCodec::default()
            .read_request(&protocol(), &mut Cursor::new(noncanonical))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    struct GatedWriter {
        started: Arc<AtomicBool>,
        released: Arc<AtomicBool>,
        waker: Arc<Mutex<Option<Waker>>>,
    }

    impl AsyncWrite for GatedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.started.store(true, Ordering::SeqCst);
            if !self.released.load(Ordering::SeqCst) {
                *self.waker.lock().unwrap() = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn round_trip_streams_one_canonical_segment() {
        let len = encoded_segment_len_for_live_count(10, 3).unwrap();
        let response = GetStateSegmentResponse {
            segment_id: 7,
            additional_segments: Vec::new(),
            expected_tip_height: 77,
            expected_tip_hash: [0xA5; 32],
            manifest_digest: [0xB6; 32],
            status: DataResponseStatus::Ready,
            eff_log: 10,
            data: Some(vec![0x5a; len]),
            transport: Default::default(),
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        let mut wire = Cursor::new(Vec::new());
        StateSegmentCodec::default()
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap();
        assert_eq!(wire.get_ref().len(), RESPONSE_HEADER_BYTES + len);
        wire.set_position(0);
        let decoded = StateSegmentCodec::default()
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.segment_id, 7);
        assert_eq!(decoded.expected_tip_height, 77);
        assert_eq!(decoded.expected_tip_hash, [0xA5; 32]);
        assert_eq!(decoded.manifest_digest, [0xB6; 32]);
        assert_eq!(decoded.data.unwrap(), vec![0x5a; len]);
    }

    #[tokio::test]
    async fn busy_response_is_not_decoded_as_unavailable() {
        let response = GetStateSegmentResponse {
            segment_id: 7,
            additional_segments: Vec::new(),
            expected_tip_height: 77,
            expected_tip_hash: [0xA5; 32],
            manifest_digest: [0xB6; 32],
            status: DataResponseStatus::Busy {
                retry_after_ms: 800,
            },
            eff_log: 0,
            data: None,
            transport: Default::default(),
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        let mut wire = Cursor::new(Vec::new());
        StateSegmentCodec::default()
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap();
        wire.set_position(0);
        let decoded = StateSegmentCodec::default()
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(
            decoded.status,
            DataResponseStatus::Busy {
                retry_after_ms: 800
            }
        );
        assert!(decoded.data.is_none());
    }

    #[tokio::test]
    async fn malicious_length_is_rejected_before_payload_read_or_allocation() {
        let declared = max_encoded_segment_len_for_eff_log(16).unwrap() + 1;
        let error = StateSegmentCodec::default()
            .read_response(
                &protocol(),
                &mut Cursor::new(response_header(16, declared as u32)),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("not canonical"));

        let empty_sparse_len = encoded_segment_len_for_live_count(16, 0).unwrap();
        let error = StateSegmentCodec::default()
            .read_response(
                &protocol(),
                &mut Cursor::new(response_header(16, empty_sparse_len as u32)),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("not canonical"));
    }

    #[tokio::test]
    async fn inbound_budget_blocks_second_segment_until_first_is_consumed() {
        let len = encoded_segment_len_for_live_count(6, 3).unwrap();
        let codec = StateSegmentCodec::with_inbound_budget(len);
        let mut first_wire = response_header(6, len as u32);
        first_wire.extend(std::iter::repeat_n(1u8, len));
        let first = codec
            .clone()
            .read_response(&protocol(), &mut Cursor::new(first_wire))
            .await
            .unwrap();

        let mut second_wire = response_header(6, len as u32);
        second_wire.extend(std::iter::repeat_n(2u8, len));
        let mut second_codec = codec.clone();
        let second = tokio::spawn(async move {
            second_codec
                .read_response(&protocol(), &mut Cursor::new(second_wire))
                .await
        });
        tokio::task::yield_now().await;
        assert!(!second.is_finished());
        drop(first);
        let second = tokio::time::timeout(std::time::Duration::from_secs(1), second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(second.data.unwrap()[0], 2);
    }

    #[tokio::test]
    async fn outbound_permit_lives_until_codec_write_completes() {
        let len = encoded_segment_len_for_live_count(6, 3).unwrap();
        let budget = OutboundResponseBudget::with_capacity(len);
        let permit = budget.acquire(len).await.unwrap().unwrap();
        let response = GetStateSegmentResponse {
            segment_id: 3,
            additional_segments: Vec::new(),
            expected_tip_height: 77,
            expected_tip_hash: [0xA5; 32],
            manifest_digest: [0xB6; 32],
            status: DataResponseStatus::Ready,
            eff_log: 6,
            data: Some(vec![0x33; len]),
            transport: Default::default(),
            inbound_memory_permit: None,
            outbound_memory_permit: Some(permit),
        };
        let started = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(Mutex::new(None));
        let writer = GatedWriter {
            started: started.clone(),
            released: released.clone(),
            waker: waker.clone(),
        };
        let write = tokio::spawn(async move {
            let mut writer = writer;
            StateSegmentCodec::default()
                .write_response(&protocol(), &mut writer, response)
                .await
        });
        while !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        assert_eq!(budget.available_bytes(), 0);
        assert!(!write.is_finished());

        let waiter_budget = budget.clone();
        let waiter = tokio::spawn(async move { waiter_budget.acquire(len).await.unwrap() });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        released.store(true, Ordering::SeqCst);
        if let Some(waker) = waker.lock().unwrap().take() {
            waker.wake();
        }
        write.await.unwrap().unwrap();
        let second_permit = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(budget.available_bytes(), 0);
        drop(second_permit);
        assert_eq!(budget.available_bytes(), len);
    }
}
