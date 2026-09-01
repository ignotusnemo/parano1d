// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Allocation-bounded exact body/terminal transfer for network v2.

use std::{collections::HashSet, io, sync::Arc};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
use noid_chain::consensus::wire_limits::{history_step_terminal_bytes_limit, MAX_BLOCK_BYTES};

use crate::{
    inbound_budget::process_global_inbound_budget,
    object_protocol::{
        BlockBodyClaimId, BlockBodyObjectId, DataResponseStatus, GetObjectsRequest,
        GetObjectsResponse, ObjectId, ObjectPayload, TerminalClaimId, TerminalObjectId,
        MAX_OBJECTS_PER_REQUEST, MAX_OBJECT_RESPONSE_PAYLOAD_BYTES,
    },
};

const REQUEST_MAGIC: [u8; 4] = *b"NOQ2";
const RESPONSE_MAGIC: [u8; 4] = *b"NOS2";
const FIXED_HEADER_BYTES: usize = 8;
const TERMINAL_ID_BYTES: usize = 1 + 8 + 32 + 1 + 32 + 4;
const AVAILABLE: u8 = 1;
const UNAVAILABLE: u8 = 0;
pub const MAX_OBJECT_REQUEST_BYTES: usize =
    FIXED_HEADER_BYTES + MAX_OBJECTS_PER_REQUEST * TERMINAL_ID_BYTES;

const _: () = assert!(MAX_OBJECT_REQUEST_BYTES <= 2 * 1024);

#[derive(Debug, Clone)]
pub struct ObjectCodec {
    inbound_budget: Arc<tokio::sync::Semaphore>,
}

impl Default for ObjectCodec {
    fn default() -> Self {
        Self {
            inbound_budget: process_global_inbound_budget(),
        }
    }
}

impl ObjectCodec {
    #[cfg(test)]
    fn with_inbound_budget(bytes: usize) -> Self {
        Self {
            inbound_budget: Arc::new(tokio::sync::Semaphore::new(bytes)),
        }
    }

    async fn acquire_inbound(
        &self,
        bytes: usize,
    ) -> io::Result<Option<Arc<tokio::sync::OwnedSemaphorePermit>>> {
        if bytes == 0 {
            return Ok(None);
        }
        let permits = u32::try_from(bytes)
            .map_err(|_| invalid_data("object response byte budget overflow"))?;
        let permit = Arc::clone(&self.inbound_budget)
            .acquire_many_owned(permits)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "object byte budget closed"))?;
        Ok(Some(Arc::new(permit)))
    }
}

#[async_trait]
impl request_response::Codec for ObjectCodec {
    type Protocol = StreamProtocol;
    type Request = GetObjectsRequest;
    type Response = GetObjectsResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let count = read_header(io, REQUEST_MAGIC).await?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(count)
            .map_err(|_| invalid_data("object request allocation failed"))?;
        for _ in 0..count {
            objects.push(read_object_id(io).await?);
        }
        validate_request(&objects)?;
        ensure_eof(io).await?;
        Ok(GetObjectsRequest { objects })
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let (count, status) = read_response_header(io).await?;
        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(count)
            .map_err(|_| invalid_data("object response descriptor allocation failed"))?;
        for _ in 0..count {
            let object = read_object_id(io).await?;
            let availability = read_u8(io).await?;
            if availability != AVAILABLE && availability != UNAVAILABLE {
                return Err(invalid_data("object availability marker is invalid"));
            }
            descriptors.push((object, availability == AVAILABLE));
        }
        let ids = descriptors
            .iter()
            .map(|(object, _)| *object)
            .collect::<Vec<_>>();
        validate_request(&ids)?;
        let payload_bytes = response_payload_len(&descriptors)?;
        if matches!(status, DataResponseStatus::Busy { .. })
            && descriptors.iter().any(|(_, available)| *available)
        {
            return Err(invalid_data("busy exact-object response carries payload"));
        }
        let inbound_memory_permit = self.acquire_inbound(payload_bytes).await?;

        let mut objects = Vec::new();
        objects
            .try_reserve_exact(count)
            .map_err(|_| invalid_data("object response allocation failed"))?;
        for (object, available) in descriptors {
            let bytes = if available {
                let encoded_len = usize::try_from(
                    object
                        .encoded_len()
                        .ok_or_else(|| invalid_data("unsupported transfer object"))?,
                )
                .map_err(|_| invalid_data("object length does not fit usize"))?;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(encoded_len)
                    .map_err(|_| invalid_data("object payload allocation failed"))?;
                bytes.resize(encoded_len, 0);
                io.read_exact(&mut bytes).await?;
                if !object.matches_bytes(&bytes) {
                    return Err(invalid_data("object payload digest mismatch"));
                }
                Some(bytes)
            } else {
                None
            };
            objects.push(ObjectPayload { object, bytes });
        }
        ensure_eof(io).await?;
        Ok(GetObjectsResponse {
            status,
            objects,
            inbound_memory_permit,
            outbound_memory_permit: None,
        })
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
        validate_request(&request.objects)?;
        write_header(io, REQUEST_MAGIC, request.objects.len()).await?;
        for object in request.objects {
            write_object_id(io, object).await?;
        }
        io.flush().await
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
        let GetObjectsResponse {
            status,
            objects,
            inbound_memory_permit,
            outbound_memory_permit,
        } = response;
        let ids = objects
            .iter()
            .map(|payload| payload.object)
            .collect::<Vec<_>>();
        validate_request(&ids)?;
        let descriptors = objects
            .iter()
            .map(|payload| (payload.object, payload.bytes.is_some()))
            .collect::<Vec<_>>();
        response_payload_len(&descriptors)?;
        if !status.is_canonical() {
            return Err(invalid_data("non-canonical exact-object response status"));
        }
        if matches!(status, DataResponseStatus::Busy { .. })
            && objects.iter().any(|payload| payload.bytes.is_some())
        {
            return Err(invalid_data("busy exact-object response carries payload"));
        }
        for payload in &objects {
            if let Some(bytes) = payload.bytes.as_deref() {
                if !payload.object.matches_bytes(bytes) {
                    return Err(invalid_data("refusing to encode mismatched object bytes"));
                }
            }
        }

        write_response_header(io, objects.len(), status).await?;
        for payload in &objects {
            write_object_id(io, payload.object).await?;
            io.write_all(&[if payload.bytes.is_some() {
                AVAILABLE
            } else {
                UNAVAILABLE
            }])
            .await?;
        }
        for payload in objects {
            if let Some(bytes) = payload.bytes {
                io.write_all(&bytes).await?;
            }
        }
        io.flush().await?;
        drop(inbound_memory_permit);
        drop(outbound_memory_permit);
        Ok(())
    }
}

fn validate_request(objects: &[ObjectId]) -> io::Result<()> {
    if objects.is_empty() || objects.len() > MAX_OBJECTS_PER_REQUEST {
        return Err(invalid_data(
            "object request count is outside the fixed cap",
        ));
    }
    if objects
        .iter()
        .any(|object| !object.is_live_transfer_object())
    {
        return Err(invalid_data(
            "object type is not served by the live object protocol",
        ));
    }
    let terminals = objects
        .iter()
        .filter(|object| matches!(object, ObjectId::Terminal(_)))
        .count();
    if terminals > 0 && (terminals != 1 || objects.len() != 1) {
        return Err(invalid_data(
            "a terminal request must contain exactly one object",
        ));
    }
    let unique = objects.iter().copied().collect::<HashSet<_>>();
    if unique.len() != objects.len() {
        return Err(invalid_data("object request contains duplicate ids"));
    }
    for object in objects {
        validate_object_id(*object)?;
    }
    let total = objects.iter().try_fold(0usize, |total, object| {
        total.checked_add(object.encoded_len().unwrap_or(0) as usize)
    });
    if total.is_none_or(|total| total > MAX_OBJECT_RESPONSE_PAYLOAD_BYTES) {
        return Err(invalid_data(
            "object request exceeds the aggregate payload cap",
        ));
    }
    Ok(())
}

fn validate_object_id(object: ObjectId) -> io::Result<()> {
    match object {
        ObjectId::BlockBody(object) => {
            if object.claim.height == 0
                || object.encoded_len == 0
                || object.encoded_len as usize > MAX_BLOCK_BYTES
            {
                return Err(invalid_data(
                    "block body object id is outside its fixed cap",
                ));
            }
        }
        ObjectId::Terminal(object) => {
            if object.claim.height == 0
                || object.encoded_len == 0
                || object.encoded_len as usize
                    > history_step_terminal_bytes_limit(object.claim.height)
                || object.claim.proof_class >= noid_chain::history_step::HISTORY_STEP_CLASS_COUNT
            {
                return Err(invalid_data(
                    "terminal object id is outside the active profile",
                ));
            }
        }
        ObjectId::SnapshotManifest(_) | ObjectId::StateSegment(_) => {
            return Err(invalid_data("unsupported live object id"));
        }
    }
    Ok(())
}

fn response_payload_len(descriptors: &[(ObjectId, bool)]) -> io::Result<usize> {
    descriptors
        .iter()
        .try_fold(0usize, |total, (object, available)| {
            if !available {
                return Ok(total);
            }
            let encoded_len = object
                .encoded_len()
                .ok_or_else(|| invalid_data("unsupported transfer object"))?
                as usize;
            total
                .checked_add(encoded_len)
                .filter(|total| *total <= MAX_OBJECT_RESPONSE_PAYLOAD_BYTES)
                .ok_or_else(|| invalid_data("object response payload exceeds the fixed cap"))
        })
}

async fn read_header<T: AsyncRead + Unpin>(io: &mut T, magic: [u8; 4]) -> io::Result<usize> {
    let mut header = [0u8; FIXED_HEADER_BYTES];
    io.read_exact(&mut header).await?;
    if header[..4] != magic {
        return Err(invalid_data("invalid exact-object magic/version"));
    }
    if header[5..] != [0; 3] {
        return Err(invalid_data("exact-object reserved bytes are non-zero"));
    }
    let count = header[4] as usize;
    if count == 0 || count > MAX_OBJECTS_PER_REQUEST {
        return Err(invalid_data("exact-object count exceeds the fixed cap"));
    }
    Ok(count)
}

async fn read_response_header<T: AsyncRead + Unpin>(
    io: &mut T,
) -> io::Result<(usize, DataResponseStatus)> {
    let mut header = [0u8; FIXED_HEADER_BYTES];
    io.read_exact(&mut header).await?;
    if header[..4] != RESPONSE_MAGIC {
        return Err(invalid_data("invalid exact-object magic/version"));
    }
    let count = header[4] as usize;
    if count == 0 || count > MAX_OBJECTS_PER_REQUEST {
        return Err(invalid_data("exact-object count exceeds the fixed cap"));
    }
    let retry_after_ms = u16::from_le_bytes([header[6], header[7]]);
    let status = match header[5] {
        0 if retry_after_ms == 0 => DataResponseStatus::Ready,
        1 => DataResponseStatus::Busy { retry_after_ms },
        _ => return Err(invalid_data("invalid exact-object response status")),
    };
    if !status.is_canonical() {
        return Err(invalid_data("non-canonical exact-object response status"));
    }
    Ok((count, status))
}

async fn write_response_header<T: AsyncWrite + Unpin>(
    io: &mut T,
    count: usize,
    status: DataResponseStatus,
) -> io::Result<()> {
    if !status.is_canonical() {
        return Err(invalid_data("non-canonical exact-object response status"));
    }
    let count = u8::try_from(count).map_err(|_| invalid_data("object count does not fit u8"))?;
    let mut header = [0u8; FIXED_HEADER_BYTES];
    header[..4].copy_from_slice(&RESPONSE_MAGIC);
    header[4] = count;
    if let DataResponseStatus::Busy { retry_after_ms } = status {
        header[5] = 1;
        header[6..8].copy_from_slice(&retry_after_ms.to_le_bytes());
    }
    io.write_all(&header).await
}

async fn write_header<T: AsyncWrite + Unpin>(
    io: &mut T,
    magic: [u8; 4],
    count: usize,
) -> io::Result<()> {
    let count = u8::try_from(count).map_err(|_| invalid_data("object count does not fit u8"))?;
    let mut header = [0u8; FIXED_HEADER_BYTES];
    header[..4].copy_from_slice(&magic);
    header[4] = count;
    io.write_all(&header).await
}

async fn read_object_id<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<ObjectId> {
    let tag = read_u8(io).await?;
    match tag {
        0 => {
            let height = read_u64(io).await?;
            let block_hash = read_hash(io).await?;
            let byte_digest = read_hash(io).await?;
            let encoded_len = read_u32(io).await?;
            let object = ObjectId::BlockBody(BlockBodyObjectId {
                claim: BlockBodyClaimId { height, block_hash },
                byte_digest,
                encoded_len,
            });
            validate_object_id(object)?;
            Ok(object)
        }
        1 => {
            let height = read_u64(io).await?;
            let semantic_header_id = read_hash(io).await?;
            let proof_class = read_u8(io).await?;
            let byte_digest = read_hash(io).await?;
            let encoded_len = read_u32(io).await?;
            let object = ObjectId::Terminal(TerminalObjectId {
                claim: TerminalClaimId {
                    height,
                    semantic_header_id,
                    proof_class,
                },
                byte_digest,
                encoded_len,
            });
            validate_object_id(object)?;
            Ok(object)
        }
        _ => Err(invalid_data("unknown exact-object id tag")),
    }
}

async fn write_object_id<T: AsyncWrite + Unpin>(io: &mut T, object: ObjectId) -> io::Result<()> {
    validate_object_id(object)?;
    match object {
        ObjectId::BlockBody(object) => {
            io.write_all(&[0]).await?;
            io.write_all(&object.claim.height.to_le_bytes()).await?;
            io.write_all(&object.claim.block_hash).await?;
            io.write_all(&object.byte_digest).await?;
            io.write_all(&object.encoded_len.to_le_bytes()).await
        }
        ObjectId::Terminal(object) => {
            io.write_all(&[1]).await?;
            io.write_all(&object.claim.height.to_le_bytes()).await?;
            io.write_all(&object.claim.semantic_header_id).await?;
            io.write_all(&[object.claim.proof_class]).await?;
            io.write_all(&object.byte_digest).await?;
            io.write_all(&object.encoded_len.to_le_bytes()).await
        }
        ObjectId::SnapshotManifest(_) | ObjectId::StateSegment(_) => {
            Err(invalid_data("unsupported live object id"))
        }
    }
}

async fn read_hash<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<[u8; 32]> {
    let mut hash = [0u8; 32];
    io.read_exact(&mut hash).await?;
    Ok(hash)
}

async fn read_u64<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<u64> {
    let mut encoded = [0u8; 8];
    io.read_exact(&mut encoded).await?;
    Ok(u64::from_le_bytes(encoded))
}

async fn read_u32<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<u32> {
    let mut encoded = [0u8; 4];
    io.read_exact(&mut encoded).await?;
    Ok(u32::from_le_bytes(encoded))
}

async fn read_u8<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<u8> {
    let mut encoded = [0u8; 1];
    io.read_exact(&mut encoded).await?;
    Ok(encoded[0])
}

async fn ensure_eof<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<()> {
    let mut trailing = [0u8; 1];
    match io.read(&mut trailing).await? {
        0 => Ok(()),
        _ => Err(invalid_data("trailing bytes after exact-object frame")),
    }
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::request_response::Codec;

    fn body(height: u64, byte: u8, bytes: &[u8]) -> ObjectId {
        ObjectId::BlockBody(
            BlockBodyObjectId::from_bytes(
                BlockBodyClaimId {
                    height,
                    block_hash: [byte; 32],
                },
                bytes,
            )
            .unwrap(),
        )
    }

    fn terminal(height: u64, bytes: &[u8]) -> ObjectId {
        ObjectId::Terminal(
            TerminalObjectId::from_bytes(
                TerminalClaimId {
                    height,
                    semantic_header_id: [height as u8; 32],
                    proof_class: 0,
                },
                bytes,
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn request_and_response_round_trip_exact_ids_and_bytes() {
        let first_bytes = b"first".to_vec();
        let second_bytes = b"second".to_vec();
        let first = body(1, 1, &first_bytes);
        let second = body(2, 2, &second_bytes);
        let protocol = StreamProtocol::new("/test");
        let mut codec = ObjectCodec::with_inbound_budget(1024);

        let mut request_wire = futures::io::Cursor::new(Vec::new());
        codec
            .write_request(
                &protocol,
                &mut request_wire,
                GetObjectsRequest {
                    objects: vec![first, second],
                },
            )
            .await
            .unwrap();
        let decoded = codec
            .read_request(
                &protocol,
                &mut futures::io::Cursor::new(request_wire.into_inner()),
            )
            .await
            .unwrap();
        assert_eq!(decoded.objects, vec![first, second]);

        let mut response_wire = futures::io::Cursor::new(Vec::new());
        codec
            .write_response(
                &protocol,
                &mut response_wire,
                GetObjectsResponse {
                    status: DataResponseStatus::Ready,
                    objects: vec![
                        ObjectPayload {
                            object: first,
                            bytes: Some(first_bytes),
                        },
                        ObjectPayload {
                            object: second,
                            bytes: Some(second_bytes),
                        },
                    ],
                    inbound_memory_permit: None,
                    outbound_memory_permit: None,
                },
            )
            .await
            .unwrap();
        let decoded = codec
            .read_response(
                &protocol,
                &mut futures::io::Cursor::new(response_wire.into_inner()),
            )
            .await
            .unwrap();
        assert_eq!(decoded.objects.len(), 2);
        assert!(decoded
            .objects
            .iter()
            .all(|payload| payload.bytes.is_some()));
    }

    #[tokio::test]
    async fn terminal_cannot_be_mixed_or_batched() {
        let one = terminal(1, b"terminal");
        let two = terminal(2, b"other");
        assert!(validate_request(&[one, two]).is_err());
        assert!(validate_request(&[one, body(1, 1, b"body")]).is_err());
    }

    #[tokio::test]
    async fn busy_response_preserves_exact_ids_without_payload() {
        let object = body(1, 1, b"body");
        let protocol = StreamProtocol::new("/test");
        let mut wire = futures::io::Cursor::new(Vec::new());
        ObjectCodec::default()
            .write_response(
                &protocol,
                &mut wire,
                GetObjectsResponse {
                    status: DataResponseStatus::Busy {
                        retry_after_ms: 700,
                    },
                    objects: vec![ObjectPayload {
                        object,
                        bytes: None,
                    }],
                    inbound_memory_permit: None,
                    outbound_memory_permit: None,
                },
            )
            .await
            .unwrap();
        wire.set_position(0);
        let response = ObjectCodec::default()
            .read_response(&protocol, &mut wire)
            .await
            .unwrap();
        assert_eq!(
            response.status,
            DataResponseStatus::Busy {
                retry_after_ms: 700
            }
        );
        assert_eq!(response.objects[0].object, object);
        assert!(response.objects[0].bytes.is_none());
    }

    #[tokio::test]
    async fn digest_mismatch_and_trailing_bytes_are_rejected() {
        let bytes = b"canonical".to_vec();
        let object = body(1, 1, &bytes);
        let protocol = StreamProtocol::new("/test");
        let mut codec = ObjectCodec::with_inbound_budget(1024);
        let mut wire = futures::io::Cursor::new(Vec::new());
        codec
            .write_response(
                &protocol,
                &mut wire,
                GetObjectsResponse {
                    status: DataResponseStatus::Ready,
                    objects: vec![ObjectPayload {
                        object,
                        bytes: Some(bytes),
                    }],
                    inbound_memory_permit: None,
                    outbound_memory_permit: None,
                },
            )
            .await
            .unwrap();
        let mut encoded = wire.into_inner();
        let last = encoded.last_mut().unwrap();
        *last ^= 1;
        assert!(codec
            .read_response(&protocol, &mut futures::io::Cursor::new(encoded))
            .await
            .is_err());

        let mut canonical = futures::io::Cursor::new(Vec::new());
        codec
            .write_request(
                &protocol,
                &mut canonical,
                GetObjectsRequest {
                    objects: vec![object],
                },
            )
            .await
            .unwrap();
        let mut trailing = canonical.into_inner();
        trailing.push(0);
        assert!(codec
            .read_request(&protocol, &mut futures::io::Cursor::new(trailing))
            .await
            .is_err());
    }

    #[test]
    fn aggregate_cap_is_checked_from_ids_before_payload_allocation() {
        let oversized = (0..MAX_OBJECTS_PER_REQUEST)
            .map(|index| {
                ObjectId::BlockBody(BlockBodyObjectId {
                    claim: BlockBodyClaimId {
                        height: index as u64 + 1,
                        block_hash: [index as u8; 32],
                    },
                    byte_digest: [index as u8; 32],
                    encoded_len: MAX_BLOCK_BYTES as u32,
                })
            })
            .collect::<Vec<_>>();
        assert!(validate_request(&oversized).is_ok());

        let terminal = ObjectId::Terminal(TerminalObjectId {
            claim: TerminalClaimId {
                height: 1,
                semantic_header_id: [1; 32],
                proof_class: 0,
            },
            byte_digest: [2; 32],
            encoded_len: (MAX_OBJECT_RESPONSE_PAYLOAD_BYTES + 1) as u32,
        });
        assert!(validate_request(&[terminal]).is_err());
    }
}
