// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded, reversible origin transport. Proof authority is established by
//! the recursive verifier after decoding these sections.

use std::{io::Read, ops::Range, sync::Arc};

pub const UNIFIED_ORIGIN_MAGIC: &[u8; 8] = b"O1A4OR02";
pub const MAX_ORIGIN_BYTES: usize =
    crate::consensus::wire_limits::MAX_V2_FORK_ORIGIN_TRANSPORT_BYTES;
pub const MAX_REDUCTION_BYTES: usize = 8192;
pub const UNIFIED_ORIGIN_PREFIX: usize = 76;
const WINDOW_LOG: u32 = 22;
const AUTHORIZATION_PREFIX: usize = 40 + 2 * crate::wire::BLOCK_HEADER_WIRE_SIZE + 8;

#[derive(Clone, Debug)]
pub struct UnifiedOriginCarrier {
    request: [u8; 32],
    body: Arc<Vec<u8>>,
    authorization: Range<usize>,
    reduction: Range<usize>,
    evaluations: Vec<(u8, Range<usize>)>,
}

impl UnifiedOriginCarrier {
    pub fn new(
        request: [u8; 32],
        authorization: &[u8],
        reduction: &[u8],
        evaluations: &[(u8, Vec<u8>)],
    ) -> Result<Self, String> {
        let size = 4usize
            .checked_add(authorization.len())
            .and_then(|n| n.checked_add(2 + reduction.len() + 1))
            .and_then(|n| {
                evaluations
                    .iter()
                    .try_fold(n, |n, (_, p)| n.checked_add(5 + p.len()))
            })
            .filter(|n| *n <= MAX_ORIGIN_BYTES)
            .ok_or("unified origin size bound")?;
        let mut body = Vec::with_capacity(size);
        body.extend_from_slice(&(authorization.len() as u32).to_le_bytes());
        body.extend_from_slice(authorization);
        body.extend_from_slice(
            &(u16::try_from(reduction.len()).map_err(|_| "reduction size")?).to_le_bytes(),
        );
        body.extend_from_slice(reduction);
        body.push(u8::try_from(evaluations.len()).map_err(|_| "evaluation count")?);
        for (class, proof) in evaluations {
            body.push(*class);
            body.extend_from_slice(&(proof.len() as u32).to_le_bytes());
            body.extend_from_slice(proof);
        }
        Self::parse(request, body.into())
    }

    fn parse(request: [u8; 32], body: Arc<Vec<u8>>) -> Result<Self, String> {
        fn span(body: &[u8], at: &mut usize, size: usize) -> Result<Range<usize>, String> {
            let end = at
                .checked_add(size)
                .filter(|end| *end <= body.len())
                .ok_or("unified origin section bound")?;
            let range = *at..end;
            *at = end;
            Ok(range)
        }
        if body.len() > MAX_ORIGIN_BYTES {
            return Err("unified origin body bound".into());
        }
        let mut at = 0;
        let n = u32::from_le_bytes(body[span(&body, &mut at, 4)?].try_into().unwrap()) as usize;
        let authorization = span(&body, &mut at, n)?;
        let auth = &body[authorization.clone()];
        if auth.len() <= AUTHORIZATION_PREFIX || !auth.starts_with(b"O1A4OR01") {
            return Err("unified authorization format".into());
        }
        let terminal = u32::from_le_bytes(
            auth[AUTHORIZATION_PREFIX - 8..AUTHORIZATION_PREFIX - 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let predecessor = u32::from_le_bytes(
            auth[AUTHORIZATION_PREFIX - 4..AUTHORIZATION_PREFIX]
                .try_into()
                .unwrap(),
        ) as usize;
        if AUTHORIZATION_PREFIX
            .checked_add(terminal)
            .and_then(|n| n.checked_add(predecessor))
            != Some(auth.len())
            || terminal == 0
            || predecessor == 0
        {
            return Err("unified authorization framing".into());
        }
        if !auth[AUTHORIZATION_PREFIX + terminal..].starts_with(b"O1V2OR02") {
            return Err("unified origin requires a matrix-free predecessor".into());
        }
        let n = u16::from_le_bytes(body[span(&body, &mut at, 2)?].try_into().unwrap()) as usize;
        if n == 0 || n > MAX_REDUCTION_BYTES {
            return Err("unified reduction bound".into());
        }
        let reduction = span(&body, &mut at, n)?;
        let count = body[span(&body, &mut at, 1)?][0] as usize;
        if !(1..=2).contains(&count) {
            return Err("unified evaluation count".into());
        }
        let mut evaluations = Vec::with_capacity(count);
        for _ in 0..count {
            let class = body[span(&body, &mut at, 1)?][0];
            if class >= 2
                || evaluations
                    .last()
                    .is_some_and(|(previous, _)| *previous >= class)
            {
                return Err("unified evaluation order".into());
            }
            let n = u32::from_le_bytes(body[span(&body, &mut at, 4)?].try_into().unwrap()) as usize;
            if n == 0 {
                return Err("unified evaluation size".into());
            }
            evaluations.push((class, span(&body, &mut at, n)?));
        }
        if at != body.len() {
            return Err("unified origin trailing body".into());
        }
        Ok(Self {
            request,
            body,
            authorization,
            reduction,
            evaluations,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() <= UNIFIED_ORIGIN_PREFIX
            || bytes.len() > MAX_ORIGIN_BYTES
            || !bytes.starts_with(UNIFIED_ORIGIN_MAGIC)
        {
            return Err("unified origin transport bound".into());
        }
        let expected = u32::from_le_bytes(bytes[72..76].try_into().unwrap()) as usize;
        if expected == 0 || expected > MAX_ORIGIN_BYTES {
            return Err("unified origin inflation bound".into());
        }
        let mut decoder = zstd::stream::read::Decoder::with_buffer(&bytes[UNIFIED_ORIGIN_PREFIX..])
            .map_err(|e| e.to_string())?
            .single_frame();
        decoder
            .window_log_max(WINDOW_LOG)
            .map_err(|e| e.to_string())?;
        let mut body = Vec::with_capacity(expected + 1);
        (&mut decoder)
            .take(expected as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| e.to_string())?;
        if body.len() != expected || !decoder.finish().is_empty() {
            return Err("unified origin frame length or trailing data".into());
        }
        let carrier = Self::parse(bytes[8..40].try_into().unwrap(), body.into())?;
        if carrier.predecessor_request() != bytes[40..72] {
            return Err("unified predecessor hint mismatch".into());
        }
        Ok(carrier)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        use std::io::Write;
        let mut encoder =
            zstd::stream::write::Encoder::new(Vec::new(), 9).map_err(|e| e.to_string())?;
        encoder.window_log(WINDOW_LOG).map_err(|e| e.to_string())?;
        encoder.write_all(&self.body).map_err(|e| e.to_string())?;
        let compressed = encoder.finish().map_err(|e| e.to_string())?;
        if compressed.len() > MAX_ORIGIN_BYTES - UNIFIED_ORIGIN_PREFIX {
            return Err("unified compressed origin bound".into());
        }
        let mut bytes = Vec::with_capacity(UNIFIED_ORIGIN_PREFIX + compressed.len());
        bytes.extend_from_slice(UNIFIED_ORIGIN_MAGIC);
        bytes.extend_from_slice(&self.request);
        bytes.extend_from_slice(&self.predecessor_request());
        bytes.extend_from_slice(&(self.body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&compressed);
        Ok(bytes)
    }

    pub fn authorization_bytes(&self) -> &[u8] {
        &self.body[self.authorization.clone()]
    }
    pub fn request_binding(&self) -> [u8; 32] {
        self.request
    }
    pub fn reduction_bytes(&self) -> &[u8] {
        &self.body[self.reduction.clone()]
    }
    pub fn evaluations(&self) -> impl ExactSizeIterator<Item = (u8, &[u8])> {
        self.evaluations
            .iter()
            .map(|(class, span)| (*class, &self.body[span.clone()]))
    }
    pub fn predecessor_request(&self) -> [u8; 32] {
        self.authorization_bytes()[8..40].try_into().unwrap()
    }
    pub fn predecessor_bytes(&self) -> &[u8] {
        let auth = self.authorization_bytes();
        let terminal = u32::from_le_bytes(
            auth[AUTHORIZATION_PREFIX - 8..AUTHORIZATION_PREFIX - 4]
                .try_into()
                .unwrap(),
        ) as usize;
        &auth[AUTHORIZATION_PREFIX + terminal..]
    }

    fn into_legacy_bytes(self, request: [u8; 32]) -> Result<Vec<u8>, String> {
        let span = if request == self.predecessor_request() {
            self.authorization.end - self.predecessor_bytes().len()..self.authorization.end
        } else if request == self.request {
            self.authorization.clone()
        } else {
            return Err("unified certificate belongs to a different origin".into());
        };
        // A decoded transport owns this Vec uniquely. Move its public section
        // to the front so serving the legacy format needs no second body.
        let mut body = Arc::try_unwrap(self.body)
            .map_err(|_| "legacy export requires its owned transport buffer")?;
        let length = span.len();
        body.copy_within(span, 0);
        body.truncate(length);
        Ok(body)
    }
}

/// Choose a reversible representation for a requested origin. The returned
/// bytes remain untrusted transport and require the ordinary proof verifier.
pub fn select_origin_transport(
    bytes: Vec<u8>,
    request: [u8; 32],
    unified_supported: bool,
) -> Result<Vec<u8>, String> {
    if !bytes.starts_with(UNIFIED_ORIGIN_MAGIC) {
        return Ok(bytes);
    }
    if bytes.len() < UNIFIED_ORIGIN_PREFIX {
        return Err("unified origin prefix".into());
    }
    if unified_supported && bytes[8..40] == request {
        return Ok(bytes);
    }
    legacy_origin_transport(&bytes, request)
}

pub fn legacy_origin_transport(bytes: &[u8], request: [u8; 32]) -> Result<Vec<u8>, String> {
    UnifiedOriginCarrier::from_bytes(bytes)?.into_legacy_bytes(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn fixture() -> (UnifiedOriginCarrier, Vec<u8>, Vec<u8>) {
        let predecessor = [b"O1V2OR02".as_slice(), &[9; 64]].concat();
        let terminal = vec![17; 100];
        let mut auth = vec![0; AUTHORIZATION_PREFIX];
        auth[..8].copy_from_slice(b"O1A4OR01");
        auth[8..40].copy_from_slice(&[2; 32]);
        auth[AUTHORIZATION_PREFIX - 8..AUTHORIZATION_PREFIX - 4]
            .copy_from_slice(&(terminal.len() as u32).to_le_bytes());
        auth[AUTHORIZATION_PREFIX - 4..AUTHORIZATION_PREFIX]
            .copy_from_slice(&(predecessor.len() as u32).to_le_bytes());
        auth.extend_from_slice(&terminal);
        auth.extend_from_slice(&predecessor);
        let carrier = UnifiedOriginCarrier::new(
            [3; 32],
            &auth,
            &[4; 100],
            &[(0, vec![5; 100]), (1, vec![6; 100])],
        )
        .unwrap();
        (carrier, auth, predecessor)
    }

    #[test]
    fn unified_transport_preserves_both_legacy_representations() {
        let (carrier, auth, predecessor) = fixture();
        let bytes = carrier.to_bytes().unwrap();
        let decoded = UnifiedOriginCarrier::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.authorization_bytes(), auth);
        assert_eq!(decoded.predecessor_bytes(), predecessor);
        assert_eq!(decoded.to_bytes().unwrap(), bytes);
        assert_eq!(
            select_origin_transport(bytes.clone(), [3; 32], true).unwrap(),
            bytes
        );
        assert_eq!(
            select_origin_transport(bytes.clone(), [3; 32], false).unwrap(),
            auth
        );
        assert_eq!(
            select_origin_transport(bytes.clone(), [2; 32], true).unwrap(),
            predecessor
        );
        assert!(select_origin_transport(bytes, [1; 32], true).is_err());
    }

    #[test]
    fn unified_transport_rejects_truncation_extra_frames_and_unbounded_inflation() {
        let (carrier, _, _) = fixture();
        let bytes = carrier.to_bytes().unwrap();
        for cut in [0, 7, 75, bytes.len() - 1] {
            assert!(UnifiedOriginCarrier::from_bytes(&bytes[..cut]).is_err());
        }
        for size in [0u32, u32::MAX] {
            let mut changed = bytes.clone();
            changed[72..76].copy_from_slice(&size.to_le_bytes());
            assert!(UnifiedOriginCarrier::from_bytes(&changed).is_err());
        }
        let mut changed = bytes.clone();
        changed[40] ^= 1;
        assert!(UnifiedOriginCarrier::from_bytes(&changed).is_err());
        changed = bytes.clone();
        changed.push(0);
        assert!(UnifiedOriginCarrier::from_bytes(&changed).is_err());
        changed = bytes.clone();
        changed.extend_from_slice(&bytes[UNIFIED_ORIGIN_PREFIX..]);
        assert!(UnifiedOriginCarrier::from_bytes(&changed).is_err());
    }
}
