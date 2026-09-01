// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-framing codec for the HistoryStep terminal used by O(1) sync.

use std::{io, sync::Arc};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, swarm::StreamProtocol};
#[cfg(test)]
use noid_chain::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES;
use noid_chain::{
    consensus::wire_limits::history_step_terminal_bytes_limit, HistoryStepTerminalMetadata,
    HISTORY_STEP_TERMINAL_BINDING_BYTES,
};

use crate::{
    inbound_budget::process_global_inbound_budget,
    object_protocol::DataResponseStatus,
    outbound_budget::OutboundResponseBudget,
    protocol::{GetHistoryStepTerminalRequest, GetHistoryStepTerminalResponse},
};

const REQUEST_MAGIC: [u8; 4] = *b"NTR1";
const REQUEST_BYTES: usize = 4 + 8 + 32;
const RESPONSE_MAGIC: [u8; 4] = *b"NTS2";
const RESPONSE_HEADER_BYTES: usize = 4 + 4 + 8 + 32 + 1 + 1 + 2;
const NONE_LEN: u32 = u32::MAX;

#[derive(Debug, Clone)]
pub struct HistoryStepTerminalCodec {
    inbound_budget: Arc<tokio::sync::Semaphore>,
    outbound_budget: OutboundResponseBudget,
}

impl Default for HistoryStepTerminalCodec {
    fn default() -> Self {
        Self {
            inbound_budget: process_global_inbound_budget(),
            outbound_budget: OutboundResponseBudget::process_global(),
        }
    }
}

#[async_trait]
impl request_response::Codec for HistoryStepTerminalCodec {
    type Protocol = StreamProtocol;
    type Request = GetHistoryStepTerminalRequest;
    type Response = GetHistoryStepTerminalResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut request = [0u8; REQUEST_BYTES];
        io.read_exact(&mut request).await?;
        if request[..4] != REQUEST_MAGIC {
            return Err(invalid_data(
                "invalid HistoryStep terminal request magic/version",
            ));
        }
        ensure_eof(io).await?;
        Ok(GetHistoryStepTerminalRequest {
            height: u64::from_le_bytes(request[4..12].try_into().unwrap()),
            block_hash: request[12..44].try_into().unwrap(),
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
        let mut header = [0u8; RESPONSE_HEADER_BYTES];
        io.read_exact(&mut header).await?;
        let (terminal_len, height, block_hash, status) = parse_response_header(&header)?;
        let payload_len = decoded_len(terminal_len);
        let inbound_memory_permit = self.acquire_inbound(payload_len).await?;
        let terminal_bytes = read_optional(io, terminal_len).await?;
        ensure_eof(io).await?;
        if let Some(terminal) = terminal_bytes.as_deref() {
            validate_terminal_envelope(terminal, height)?;
        }
        Ok(GetHistoryStepTerminalResponse {
            height,
            block_hash,
            status,
            terminal_bytes,
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
        let mut encoded = [0u8; REQUEST_BYTES];
        encoded[..4].copy_from_slice(&REQUEST_MAGIC);
        encoded[4..12].copy_from_slice(&request.height.to_le_bytes());
        encoded[12..44].copy_from_slice(&request.block_hash);
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
        let GetHistoryStepTerminalResponse {
            height,
            block_hash,
            status,
            terminal_bytes,
            inbound_memory_permit,
            outbound_memory_permit,
        } = response;
        if !status.is_canonical() {
            return Err(invalid_data("non-canonical HistoryStep response status"));
        }
        if matches!(status, DataResponseStatus::Busy { .. }) && terminal_bytes.is_some() {
            return Err(invalid_data("busy HistoryStep response carries a terminal"));
        }
        if let Some(terminal) = terminal_bytes.as_deref() {
            validate_terminal_envelope(terminal, height)?;
        }
        let terminal_len = optional_len(terminal_bytes.as_deref(), "HistoryStep terminal")?;
        validate_length(terminal_len, height)?;
        let payload_len = decoded_len(terminal_len);
        let outbound_memory_permit = match outbound_memory_permit {
            Some(permit) => Some(permit),
            None => self.outbound_budget.acquire(payload_len).await?,
        };
        let _memory_permits = (inbound_memory_permit, outbound_memory_permit);

        let mut header = [0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..8].copy_from_slice(&terminal_len.to_le_bytes());
        header[8..16].copy_from_slice(&height.to_le_bytes());
        header[16..48].copy_from_slice(&block_hash);
        if let DataResponseStatus::Busy { retry_after_ms } = status {
            header[48] = 1;
            header[50..52].copy_from_slice(&retry_after_ms.to_le_bytes());
        }
        io.write_all(&header).await?;
        if let Some(bytes) = terminal_bytes {
            io.write_all(&bytes).await?;
        }
        Ok(())
    }
}

impl HistoryStepTerminalCodec {
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
        let permits = u32::try_from(bytes)
            .map_err(|_| invalid_data("HistoryStep response byte budget overflow"))?;
        let permit = self
            .inbound_budget
            .clone()
            .acquire_many_owned(permits)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "HistoryStep byte budget closed")
            })?;
        Ok(Some(Arc::new(permit)))
    }
}

fn parse_response_header(
    header: &[u8; RESPONSE_HEADER_BYTES],
) -> io::Result<(u32, u64, [u8; 32], DataResponseStatus)> {
    if header[..4] != RESPONSE_MAGIC {
        return Err(invalid_data(
            "invalid HistoryStep terminal response magic/version",
        ));
    }
    let terminal_len = u32::from_le_bytes(header[4..8].try_into().unwrap());
    let height = u64::from_le_bytes(header[8..16].try_into().unwrap());
    validate_length(terminal_len, height)?;
    let block_hash = header[16..48].try_into().unwrap();
    if header[49] != 0 {
        return Err(invalid_data("non-zero HistoryStep response reserved byte"));
    }
    let retry_after_ms = u16::from_le_bytes(header[50..52].try_into().unwrap());
    let status = match header[48] {
        0 if retry_after_ms == 0 => DataResponseStatus::Ready,
        1 => DataResponseStatus::Busy { retry_after_ms },
        _ => return Err(invalid_data("invalid HistoryStep response status")),
    };
    if !status.is_canonical() {
        return Err(invalid_data("non-canonical HistoryStep response status"));
    }
    if matches!(status, DataResponseStatus::Busy { .. }) && terminal_len != NONE_LEN {
        return Err(invalid_data("busy HistoryStep response carries a terminal"));
    }
    Ok((terminal_len, height, block_hash, status))
}

fn validate_length(terminal_len: u32, height: u64) -> io::Result<()> {
    let terminal_is_present = terminal_len != NONE_LEN;
    let terminal_len = decoded_len(terminal_len);
    if terminal_is_present && terminal_len <= HISTORY_STEP_TERMINAL_BINDING_BYTES {
        return Err(invalid_data("declared HistoryStep terminal is truncated"));
    }
    if terminal_len > history_step_terminal_bytes_limit(height) {
        return Err(invalid_data(
            "declared HistoryStep terminal exceeds wire cap",
        ));
    }
    Ok(())
}

fn validate_terminal_envelope(terminal: &[u8], expected_height: u64) -> io::Result<()> {
    if terminal.len() <= HISTORY_STEP_TERMINAL_BINDING_BYTES {
        return Err(invalid_data("HistoryStep terminal is truncated"));
    }
    let metadata = HistoryStepTerminalMetadata::decode_prefix(terminal).map_err(|error| {
        invalid_data(&format!("invalid HistoryStep terminal metadata: {error}"))
    })?;
    if metadata.terminal_height() != expected_height {
        return Err(invalid_data(
            "HistoryStep terminal does not bind its response height",
        ));
    }

    // The response header carries the nonce-bearing chain-link block id used
    // to correlate this transport session. The terminal deliberately carries
    // the nonce-free semantic header id so one proof can be built before PoW.
    // Their exact relationship can only be checked against the authenticated
    // staged header and is enforced by MdbxChainContext::verify_snapshot_boundary
    // before the terminal is verified or any snapshot state is installed.
    Ok(())
}

async fn read_optional<T: AsyncRead + Unpin + Send>(
    io: &mut T,
    encoded_len: u32,
) -> io::Result<Option<Vec<u8>>> {
    if encoded_len == NONE_LEN {
        return Ok(None);
    }
    let len = encoded_len as usize;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            "HistoryStep response allocation failed",
        )
    })?;
    bytes.resize(len, 0);
    io.read_exact(&mut bytes).await?;
    Ok(Some(bytes))
}

fn optional_len(bytes: Option<&[u8]>, field: &'static str) -> io::Result<u32> {
    match bytes {
        Some(bytes) => u32::try_from(bytes.len())
            .map_err(|_| invalid_data(&format!("{field} length does not fit u32"))),
        None => Ok(NONE_LEN),
    }
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
        return Err(invalid_data("trailing bytes in HistoryStep message"));
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

    fn protocol() -> StreamProtocol {
        StreamProtocol::new("/noid/test/sync/history-step/1")
    }

    fn terminal(height: u64, semantic_id: [u8; 32], fill: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &HistoryStepTerminalMetadata::new(height, semantic_id, 1)
                .unwrap()
                .encode_prefix(),
        );
        bytes.push(fill);
        bytes
    }

    fn response_wire(
        height: u64,
        block_hash: [u8; 32],
        semantic_id: [u8; 32],
        fill: u8,
    ) -> Vec<u8> {
        let terminal = terminal(height, semantic_id, fill);
        let mut wire = vec![0u8; RESPONSE_HEADER_BYTES];
        wire[..4].copy_from_slice(&RESPONSE_MAGIC);
        wire[4..8].copy_from_slice(&(terminal.len() as u32).to_le_bytes());
        wire[8..16].copy_from_slice(&height.to_le_bytes());
        wire[16..48].copy_from_slice(&block_hash);
        wire.extend_from_slice(&terminal);
        wire
    }

    #[tokio::test]
    async fn request_round_trip_binds_exact_snapshot_boundary() {
        let request = GetHistoryStepTerminalRequest {
            height: 77,
            block_hash: [0xA5; 32],
        };
        let mut wire = Cursor::new(Vec::new());
        HistoryStepTerminalCodec::default()
            .write_request(&protocol(), &mut wire, request.clone())
            .await
            .unwrap();
        wire.set_position(0);
        let decoded = HistoryStepTerminalCodec::default()
            .read_request(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.height, request.height);
        assert_eq!(decoded.block_hash, request.block_hash);
    }

    #[tokio::test]
    async fn terminal_round_trip_preserves_distinct_chain_and_semantic_ids() {
        let response = GetHistoryStepTerminalResponse {
            height: 77,
            block_hash: [0xA5; 32],
            status: DataResponseStatus::Ready,
            terminal_bytes: Some(terminal(77, [0x5A; 32], 1)),
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        let mut wire = Cursor::new(Vec::new());
        HistoryStepTerminalCodec::default()
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap();
        wire.set_position(0);
        let decoded = HistoryStepTerminalCodec::default()
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(decoded.height, 77);
        assert_eq!(decoded.block_hash, [0xA5; 32]);
        let terminal = decoded.terminal_bytes.unwrap();
        assert_eq!(terminal[9..41], [0x5A; 32]);
        assert_eq!(terminal[42], 1);
    }

    #[tokio::test]
    async fn busy_response_is_distinct_from_terminal_unavailability() {
        let response = GetHistoryStepTerminalResponse {
            height: 77,
            block_hash: [0xA5; 32],
            status: DataResponseStatus::Busy {
                retry_after_ms: 900,
            },
            terminal_bytes: None,
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        let mut wire = Cursor::new(Vec::new());
        HistoryStepTerminalCodec::default()
            .write_response(&protocol(), &mut wire, response)
            .await
            .unwrap();
        wire.set_position(0);
        let decoded = HistoryStepTerminalCodec::default()
            .read_response(&protocol(), &mut wire)
            .await
            .unwrap();
        assert_eq!(
            decoded.status,
            DataResponseStatus::Busy {
                retry_after_ms: 900
            }
        );
        assert!(decoded.terminal_bytes.is_none());
    }

    #[tokio::test]
    async fn terminal_with_wrong_response_height_is_rejected() {
        let mut wire = response_wire(77, [0xA5; 32], [0x5A; 32], 1);
        wire[RESPONSE_HEADER_BYTES + 1] ^= 1;
        assert_eq!(
            HistoryStepTerminalCodec::default()
                .read_response(&protocol(), &mut Cursor::new(wire))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn out_of_bank_class_is_rejected() {
        let mut wire = response_wire(77, [0xA5; 32], [0x5A; 32], 1);
        wire[RESPONSE_HEADER_BYTES + 41] = noid_chain::HISTORY_STEP_CLASS_COUNT;
        assert_eq!(
            HistoryStepTerminalCodec::default()
                .read_response(&protocol(), &mut Cursor::new(wire))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn malicious_length_is_rejected_before_payload_read() {
        let mut header = vec![0u8; RESPONSE_HEADER_BYTES];
        header[..4].copy_from_slice(&RESPONSE_MAGIC);
        header[4..8].copy_from_slice(
            &((MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES + 1) as u32).to_le_bytes(),
        );
        assert_eq!(
            HistoryStepTerminalCodec::default()
                .read_response(&protocol(), &mut Cursor::new(header))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn inbound_budget_follows_terminal_until_consumption() {
        let wire = response_wire(77, [0xA5; 32], [0x5A; 32], 1);
        let terminal_len = HISTORY_STEP_TERMINAL_BINDING_BYTES + 1;
        let codec = HistoryStepTerminalCodec::with_inbound_budget(terminal_len);
        let first = codec
            .clone()
            .read_response(&protocol(), &mut Cursor::new(wire.clone()))
            .await
            .unwrap();
        let mut second_codec = codec.clone();
        let second = tokio::spawn(async move {
            second_codec
                .read_response(&protocol(), &mut Cursor::new(wire))
                .await
        });
        tokio::task::yield_now().await;
        assert!(!second.is_finished());
        drop(first);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), second)
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .terminal_bytes
                .is_some()
        );
    }
}
