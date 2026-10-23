// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete sparse State segments with their committed native records.

use std::collections::{BTreeMap, BTreeSet};

use noid_poseidon2b::primitives::{Address, Digest};
use noid_tx::native_assets::{
    native_sequence, NativeOpening, COMPACT_NATIVE_OPENING_FIELDS, MAX_NATIVE_OPENING_BYTES,
    NATIVE_CREATION_TAG, NATIVE_OPENING_HEADER_BYTES,
};

use super::serial::{
    decode_sparse_segment, encoded_segment_len_for_live_count, encoded_segment_live_count_from_len,
    max_encoded_segment_len_for_eff_log, SparseSegmentView,
};

pub const NATIVE_SEGMENT_MAGIC: &[u8; 4] = b"NSG1";
pub const NATIVE_SEGMENT_HEADER_BYTES: usize = 12;
/// One compact control record and its compact immutable definition.
pub const MAX_NATIVE_CLOSURE_BYTES_PER_SLOT: usize =
    2 * (2 + NATIVE_OPENING_HEADER_BYTES + 16 * COMPACT_NATIVE_OPENING_FIELDS);
const _: () = assert!(2 + MAX_NATIVE_OPENING_BYTES <= MAX_NATIVE_CLOSURE_BYTES_PER_SLOT);

pub fn max_snapshot_segment_len(effective_log: u8, height: u64) -> Option<usize> {
    let raw = max_encoded_segment_len_for_eff_log(effective_log)?;
    if !crate::consensus::params::v2_1_active(height) {
        return Some(raw);
    }
    raw.checked_add(NATIVE_SEGMENT_HEADER_BYTES)?.checked_add(
        (1usize.checked_shl(u32::from(effective_log))?)
            .checked_mul(MAX_NATIVE_CLOSURE_BYTES_PER_SLOT)?,
    )
}

pub fn snapshot_segment_bytes_limit(height: u64) -> usize {
    max_snapshot_segment_len(16, height)
        .unwrap()
        .max(crate::consensus::wire_limits::MAX_SEGMENT_BYTES)
}

/// Pre-allocation geometry check. The complete decoder establishes exact framing.
pub fn snapshot_segment_len_valid(effective_log: u8, len: usize, height: u64) -> bool {
    if encoded_segment_live_count_from_len(effective_log, len).is_some_and(|n| n > 0) {
        return true;
    }
    crate::consensus::params::v2_1_active(height)
        && encoded_segment_len_for_live_count(effective_log, 1).is_some_and(|minimum| {
            len >= minimum + NATIVE_SEGMENT_HEADER_BYTES + 3
                && max_snapshot_segment_len(effective_log, height)
                    .is_some_and(|maximum| len <= maximum)
        })
}

#[derive(Clone, Copy)]
pub struct SnapshotSegmentPayload<'a> {
    raw: &'a [u8],
    sparse: SparseSegmentView<'a>,
    records: &'a [u8],
    count: usize,
    amounts_valid: bool,
}

impl<'a> SnapshotSegmentPayload<'a> {
    pub fn decode(bytes: &'a [u8], height: u64) -> Option<Self> {
        let payload = Self::decode_for_root_authentication(bytes, height)?;
        payload.amounts_valid.then_some(payload)
    }

    pub(crate) fn decode_for_root_authentication(bytes: &'a [u8], height: u64) -> Option<Self> {
        if bytes.len() > snapshot_segment_bytes_limit(height) {
            return None;
        }
        let framed = bytes.starts_with(NATIVE_SEGMENT_MAGIC);
        let (raw, records, count) = if framed {
            if !crate::consensus::params::v2_1_active(height)
                || bytes.len() < NATIVE_SEGMENT_HEADER_BYTES
            {
                return None;
            }
            let raw_len = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
            let count = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as usize;
            let end = NATIVE_SEGMENT_HEADER_BYTES.checked_add(raw_len)?;
            if count == 0
                || count > 2 << 16
                || count.checked_mul(3)?.checked_add(end)? > bytes.len()
            {
                return None;
            }
            (
                bytes.get(NATIVE_SEGMENT_HEADER_BYTES..end)?,
                bytes.get(end..)?,
                count,
            )
        } else {
            (bytes, &[][..], 0)
        };
        let sparse = decode_sparse_segment(raw)?;
        if !snapshot_segment_len_valid(sparse.effective_log_segment(), bytes.len(), height) {
            return None;
        }
        let (required, mut amounts_valid) = required_records(sparse, height)?;
        if count < required.len() || count > 2 * required.len() || framed != (count != 0) {
            return None;
        }
        let mut cursor = records;
        let mut previous = None;
        let mut offsets = BTreeMap::<Digest, u32>::new();
        for _ in 0..count {
            let offset = u32::try_from(records.len() - cursor.len()).ok()?;
            let opening = take_record(&mut cursor)?;
            let root = opening.root().0;
            if previous.is_some_and(|old| old >= root) {
                return None;
            }
            previous = Some(root);
            if let Some(&amount) = required.get(&root) {
                amounts_valid &= !opening.is_auxiliary() && amount == opening.amount_micronoid();
            } else if !opening.is_auxiliary() {
                return None;
            }
            offsets.insert(root, offset);
        }
        if !cursor.is_empty() {
            return None;
        }
        let resolve = |root: Digest| -> Option<NativeOpening> {
            let offset = *offsets.get(&root)? as usize;
            take_record(&mut records.get(offset..)?)
        };
        let mut dependencies = BTreeSet::new();
        for &root in required.keys() {
            let opening = resolve(root)?;
            let dependency = if let Some(root) = opening.dependency_root() {
                dependencies.insert(root.0);
                Some(resolve(root.0)?)
            } else {
                None
            };
            amounts_valid &= opening.check_dependency(dependency).is_ok();
        }
        if offsets
            .keys()
            .any(|root| !required.contains_key(root) && !dependencies.contains(root))
        {
            return None;
        }
        Some(Self {
            raw,
            sparse,
            records,
            count,
            amounts_valid,
        })
    }

    pub fn sparse(self) -> SparseSegmentView<'a> {
        self.sparse
    }
    pub fn raw_bytes(self) -> &'a [u8] {
        self.raw
    }
    pub(crate) fn native_amounts_valid(self) -> bool {
        self.amounts_valid
    }
    pub fn native_record_count(self) -> usize {
        self.count
    }

    pub fn native_openings(self) -> impl ExactSizeIterator<Item = NativeOpening> + 'a {
        let mut cursor = self.records;
        (0..self.count)
            .map(move |_| take_record(&mut cursor).expect("validated native State record"))
    }
}

fn take_record(bytes: &mut &[u8]) -> Option<NativeOpening> {
    let len = usize::from(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?));
    if len == 0 || len > MAX_NATIVE_OPENING_BYTES {
        return None;
    }
    let end = 2usize.checked_add(len)?;
    let opening = NativeOpening::from_bytes(bytes.get(2..end)?).ok()?;
    *bytes = bytes.get(end..)?;
    Some(opening)
}

fn required_records(
    sparse: SparseSegmentView<'_>,
    height: u64,
) -> Option<(BTreeMap<Digest, u64>, bool)> {
    let mut roots = BTreeMap::new();
    let mut amounts_valid = true;
    if crate::consensus::params::v2_1_active(height) {
        for (_, slot) in sparse.entries() {
            if slot.creation_id() & (3u64 << 62) != NATIVE_CREATION_TAG {
                continue;
            }
            native_sequence(slot.creation_id()).ok()?;
            let mut root = [0; 32];
            root[..16].copy_from_slice(&slot.owner_hi.0.to_le_bytes());
            root[16..].copy_from_slice(&slot.owner_lo.0.to_le_bytes());
            amounts_valid &= roots
                .insert(root, slot.amount())
                .is_none_or(|old| old == slot.amount());
        }
    }
    Some((roots, amounts_valid))
}

pub fn encode_snapshot_segment(
    raw: Vec<u8>,
    height: u64,
    mut resolve: impl FnMut(Address) -> Option<NativeOpening>,
) -> Option<Vec<u8>> {
    let sparse = decode_sparse_segment(&raw)?;
    let (required, amounts_valid) = required_records(sparse, height)?;
    if !amounts_valid {
        return None;
    }
    if required.is_empty() {
        return Some(raw);
    }
    let mut encoded_records = BTreeMap::<Digest, Vec<u8>>::new();
    for (&root, &amount) in &required {
        let opening = resolve(Address(root))?;
        if opening.root().0 != root
            || opening.is_auxiliary()
            || opening.amount_micronoid() != amount
        {
            return None;
        }
        let dependency = if let Some(dependency_root) = opening.dependency_root() {
            let dependency = if let Some(bytes) = encoded_records.get(&dependency_root.0) {
                NativeOpening::from_bytes(bytes).ok()?
            } else {
                let dependency = resolve(dependency_root)?;
                if dependency.root() != dependency_root || !dependency.is_auxiliary() {
                    return None;
                }
                encoded_records.insert(dependency_root.0, dependency.to_bytes().ok()?);
                dependency
            };
            Some(dependency)
        } else {
            None
        };
        opening.check_dependency(dependency).ok()?;
        encoded_records.insert(root, opening.to_bytes().ok()?);
    }
    let length = encoded_records.values().try_fold(
        NATIVE_SEGMENT_HEADER_BYTES.checked_add(raw.len())?,
        |sum, record| sum.checked_add(2 + record.len()),
    )?;
    if length > max_snapshot_segment_len(sparse.effective_log_segment(), height)? {
        return None;
    }
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(NATIVE_SEGMENT_MAGIC);
    bytes.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(encoded_records.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&raw);
    for encoded in encoded_records.into_values() {
        bytes.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&encoded);
    }
    Some(bytes)
}
