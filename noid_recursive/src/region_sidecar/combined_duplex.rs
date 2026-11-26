// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Recording-free post-commit authority for a heterogeneous combined duplex.
//!
//! This is the typed Walk L-A vertical used by the link-local `[R]` PCS leaf
//! walk.  Its verification key carries only an ordered list of transcript
//! schedules and capacity IVs plus the padded transaction-tile count.  Both
//! sides reconstruct the padded sub-channel set, common `S`, combined layout,
//! seven fixed tables and canonical six-column refs from that descriptor.
//! Recording blocks (including B-to-A transcript hosting) have no V1
//! representation.

use std::sync::Arc;

use noid_ivc_core::challenger::Challenger;
use noid_ivc_core::deep_chain::c1::C1LaneClaimGroup;
use noid_ivc_core::deep_chain::relations::FixedPattern;
use noid_ivc_core::deep_chain::schedule::{
    compile_duplex, duplex_family_refs, DuplexFamilyRefs, DuplexLayout, TranscriptOp,
};
use noid_ivc_core::field::{F128, F256};
use noid_ivc_core::field_circuit::FsChannelOps;
use noid_ivc_core::pcs::{C1QuirkyDirectClaim, QuirkyDirectClaim};
use noid_ivc_core::public_io::WitnessSlice;
use noid_ivc_core::verifier::FieldPostCommitVerifierContext;
use noid_ivc_prover::field_prover::FieldPostCommitProverContext;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

use crate::acceptance::trace::region_source_binding::{
    combined_duplex_fixed_patterns, combined_duplex_layout, prove_duplex_union_with_challenger,
    verify_duplex_union_with_challenger, DuplexColumnClaim, DuplexUnion, DuplexUnionProof,
    SubChannel,
};
use crate::acceptance::trace::region_source_binding_c1::{
    prove_c1_duplex_walk_prefix, prove_c1_duplex_walk_suffix, verify_c1_duplex_walk_prefix,
    verify_c1_duplex_walk_prefix_trace, verify_c1_duplex_walk_suffix,
    verify_c1_duplex_walk_suffix_trace, C1DuplexColumnClaim, C1DuplexColumnClaimTrace,
    C1DuplexProverWalkPrefix, C1DuplexUnionTraceWalkPrefix, C1DuplexUnionWalkDeferredProof,
    C1DuplexVerifierWalkPrefix,
};
use crate::acceptance::trace::self_verify::{
    C1QuirkyDirectClaimTrace, FieldPostCommitTraceContext, QuirkyDirectClaimTrace,
};
use crate::acceptance::trace::{ExtExpr, FieldR1csBuilder, LinExpr};

#[cfg(test)]
use super::bounded_decode::FixedProofShape;
use super::bounded_decode::{
    duplex_like_proof_shape, preflight_fixed_proof, record_serde_attempt, DeferredFixedProofShape,
};
use super::trace::{
    preflight_duplex_authority, verify_duplex_union_proof_trace, DuplexColumnClaimTrace,
};
use super::{push_f128, push_usize, validate_c1_endpoint_lengths, witness_log, RegionSidecarError};

pub const COMBINED_DUPLEX_REGION_SIDECAR_VERSION: u8 = 1;
pub const COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS: usize = 6;
pub const MAX_COMBINED_DUPLEX_SUBCHANNELS: usize = 64;
pub const MAX_COMBINED_DUPLEX_SCHEDULE_OPS: usize = 64;
pub const MAX_COMBINED_DUPLEX_SUBCHANNEL_SLOTS: usize = 1 << 12;
pub const MAX_COMBINED_DUPLEX_DATA_LANES: usize = 1 << 13;
pub const MAX_COMBINED_DUPLEX_CHALLENGES: usize = 1 << 12;
/// Two recursive `[R]`s at every supported BaseFold rate fit below this
/// canonical tile ceiling: the largest rate-1/2 query set has `2 * 204`
/// live tiles, padded to `2^9`.
pub const MAX_COMBINED_DUPLEX_TX_TILE_LOG: usize = 9;
pub const MAX_COMBINED_DUPLEX_W_LOG: usize = 27;

const MAX_COMBINED_DUPLEX_FIXED_CELLS: usize = 1 << 22;
const COMBINED_DUPLEX_LAYOUT_DIGEST_DOMAIN: &[u8] =
    b"NOID/REGION-SIDECAR/COMBINED-DUPLEX-LAYOUT/V1";
const COMBINED_DUPLEX_VK_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/COMBINED-DUPLEX-VK/V1";
const COMBINED_DUPLEX_SIDECAR_TRANSCRIPT_LABEL: &[u8] =
    b"history-region-sidecar-combined-duplex-v1";

/// One real heterogeneous sub-channel.  `schedule` is kept as transcript
/// operations, rather than a prover-authored compiled layout, so all slot and
/// data-lane numbering is deterministically reconstructed with
/// [`compile_duplex`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CombinedDuplexSubChannelDescriptor {
    schedule: Vec<TranscriptOp>,
    iv_flat: [F128; 2],
}

impl CombinedDuplexSubChannelDescriptor {
    pub fn new(
        schedule: Vec<TranscriptOp>,
        iv_flat: [F128; 2],
    ) -> Result<Self, RegionSidecarError> {
        let descriptor = Self { schedule, iv_flat };
        schedule_shape(&descriptor.schedule)?;
        Ok(descriptor)
    }

    pub fn schedule(&self) -> &[TranscriptOp] {
        &self.schedule
    }

    pub fn iv_flat(&self) -> [F128; 2] {
        self.iv_flat
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        push_usize(bytes, self.schedule.len());
        for op in &self.schedule {
            match op {
                TranscriptOp::Absorb(lanes) => {
                    bytes.push(0);
                    push_usize(bytes, lanes.len());
                    for lane in lanes {
                        match lane {
                            None => bytes.push(0),
                            Some(value) => {
                                bytes.push(1);
                                bytes.extend_from_slice(&value.to_le_bytes());
                            }
                        }
                    }
                }
                TranscriptOp::Squeeze(count) => {
                    bytes.push(1);
                    push_usize(bytes, *count);
                }
            }
        }
        for value in self.iv_flat {
            push_f128(bytes, value);
        }
    }
}

/// Canonical combined-duplex class descriptor.  `tx_tile_log` counts the
/// dyadically padded tile axis; the total walk log is reconstructed as
/// `block_log + tx_tile_log`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CombinedDuplexRegionDescriptor {
    tx_tile_log: usize,
    subchannels: Vec<CombinedDuplexSubChannelDescriptor>,
}

impl CombinedDuplexRegionDescriptor {
    pub fn new(
        tx_tile_log: usize,
        subchannels: Vec<CombinedDuplexSubChannelDescriptor>,
    ) -> Result<Self, RegionSidecarError> {
        let descriptor = Self {
            tx_tile_log,
            subchannels,
        };
        preflight_descriptor(&descriptor)?;
        Ok(descriptor)
    }

    pub fn tx_tile_log(&self) -> usize {
        self.tx_tile_log
    }

    pub fn subchannels(&self) -> &[CombinedDuplexSubChannelDescriptor] {
        &self.subchannels
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        push_usize(bytes, self.tx_tile_log);
        push_usize(bytes, self.subchannels.len());
        for subchannel in &self.subchannels {
            subchannel.encode(bytes);
        }
    }
}

#[derive(Clone, Debug)]
struct CanonicalCombinedDuplexProtocol {
    common_s_log: usize,
    block_log: usize,
    w_log: usize,
    fixed: Arc<[FixedPattern]>,
    refs: DuplexFamilyRefs,
    layout: DuplexLayout,
}

const CANONICAL_CACHE_ENTRIES: usize = 8;
const CANONICAL_CACHE_BYTES: usize = 16 << 20;

struct CanonicalCacheEntry {
    descriptor: CombinedDuplexRegionDescriptor,
    protocol: Arc<CanonicalCombinedDuplexProtocol>,
    digest: [u8; 32],
    bytes: usize,
}

#[derive(Default)]
struct CanonicalProtocolCache {
    entries: Vec<CanonicalCacheEntry>,
    bytes: usize,
}

impl CanonicalProtocolCache {
    fn get(
        &self,
        descriptor: &CombinedDuplexRegionDescriptor,
    ) -> Option<(Arc<CanonicalCombinedDuplexProtocol>, [u8; 32])> {
        self.entries
            .iter()
            .find(|entry| &entry.descriptor == descriptor)
            .map(|entry| (Arc::clone(&entry.protocol), entry.digest))
    }

    fn insert(&mut self, entry: CanonicalCacheEntry) {
        if entry.bytes > CANONICAL_CACHE_BYTES || self.get(&entry.descriptor).is_some() {
            return;
        }
        while !self.entries.is_empty()
            && (self.entries.len() >= CANONICAL_CACHE_ENTRIES
                || self.bytes.saturating_add(entry.bytes) > CANONICAL_CACHE_BYTES)
        {
            self.bytes -= self.entries.remove(0).bytes;
        }
        self.bytes += entry.bytes;
        self.entries.push(entry);
    }
}

fn canonical_cache_bytes(
    descriptor: &CombinedDuplexRegionDescriptor,
    protocol: &CanonicalCombinedDuplexProtocol,
) -> usize {
    let mut encoded = Vec::new();
    descriptor.encode(&mut encoded);
    // A None absorb lane occupies one encoded byte and one Option<u128>.
    // This also bounds descriptor vectors and operation enum storage.
    let mut bytes = encoded
        .len()
        .saturating_mul(core::mem::size_of::<Option<u128>>());
    bytes = bytes.saturating_add(core::mem::size_of::<CanonicalCacheEntry>());
    bytes = bytes.saturating_add(
        protocol
            .layout
            .slots
            .capacity()
            .saturating_mul(core::mem::size_of_val(&protocol.layout.slots[0])),
    );
    bytes = bytes.saturating_add(
        protocol
            .layout
            .challenges
            .capacity()
            .saturating_mul(core::mem::size_of::<(usize, usize)>()),
    );
    for pattern in protocol.fixed.iter() {
        bytes = bytes.saturating_add(core::mem::size_of_val(pattern));
        bytes = bytes.saturating_add(
            pattern
                .table
                .capacity()
                .saturating_mul(core::mem::size_of::<F128>()),
        );
        if let Some((_, bits)) = &pattern.hi_gate {
            bytes = bytes.saturating_add(bits.capacity());
        }
    }
    bytes
}

/// Cache only canonical plans built from an exact typed descriptor. Unknown
/// descriptors pass through the same bounded compiler and digest function.
fn cached_canonical_protocol(
    descriptor: &CombinedDuplexRegionDescriptor,
) -> Result<(Arc<CanonicalCombinedDuplexProtocol>, [u8; 32]), RegionSidecarError> {
    static CACHE: std::sync::Mutex<CanonicalProtocolCache> =
        std::sync::Mutex::new(CanonicalProtocolCache {
            entries: Vec::new(),
            bytes: 0,
        });
    if let Ok(cache) = CACHE.lock() {
        if let Some(cached) = cache.get(descriptor) {
            return Ok(cached);
        }
    }
    let protocol = Arc::new(canonical_protocol(descriptor)?);
    let digest = combined_duplex_protocol_digest(descriptor, &protocol);
    let bytes = canonical_cache_bytes(descriptor, &protocol);
    let Ok(mut cache) = CACHE.lock() else {
        return Ok((protocol, digest));
    };
    if let Some(cached) = cache.get(descriptor) {
        return Ok(cached);
    }
    cache.insert(CanonicalCacheEntry {
        descriptor: descriptor.clone(),
        protocol: Arc::clone(&protocol),
        digest,
        bytes,
    });
    Ok((protocol, digest))
}

/// Canonical verification key for one recording-free heterogeneous duplex
/// vertical.  The six slices are `A0,A1,C0..C3` in that exact contiguous order.
#[derive(Clone, Debug)]
pub struct CombinedDuplexRegionVk {
    purpose: [u8; 32],
    descriptor: CombinedDuplexRegionDescriptor,
    common_s_log: usize,
    block_log: usize,
    w_log: usize,
    slices: [WitnessSlice; COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS],
    fixed: Arc<[FixedPattern]>,
    layout_digest: [u8; 32],
    protocol: Arc<CanonicalCombinedDuplexProtocol>,
}

impl PartialEq for CombinedDuplexRegionVk {
    fn eq(&self, other: &Self) -> bool {
        self.purpose == other.purpose
            && self.descriptor == other.descriptor
            && self.common_s_log == other.common_s_log
            && self.block_log == other.block_log
            && self.w_log == other.w_log
            && self.slices == other.slices
            && self.fixed == other.fixed
            && self.layout_digest == other.layout_digest
    }
}

impl Eq for CombinedDuplexRegionVk {}

impl CombinedDuplexRegionVk {
    pub fn new(
        purpose: [u8; 32],
        descriptor: CombinedDuplexRegionDescriptor,
        slices: [WitnessSlice; COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS],
    ) -> Result<Self, RegionSidecarError> {
        let (protocol, layout_digest) = cached_canonical_protocol(&descriptor)?;
        let vk = Self {
            purpose,
            descriptor,
            common_s_log: protocol.common_s_log,
            block_log: protocol.block_log,
            w_log: protocol.w_log,
            slices,
            fixed: Arc::clone(&protocol.fixed),
            layout_digest,
            protocol,
        };
        vk.validate_structure()?;
        Ok(vk)
    }

    /// Checked bridge used while replacing the old pre-commit combined union.
    /// It accepts only the exact recording-free output of
    /// `build_combined_duplex_union` for this typed descriptor.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_union(
        purpose: [u8; 32],
        descriptor: CombinedDuplexRegionDescriptor,
        slices: [WitnessSlice; COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS],
        union: &DuplexUnion,
    ) -> Result<Self, RegionSidecarError> {
        if !union.rec_refs.is_empty()
            || !union.rec_blocks.is_empty()
            || !union.rec_challenges.is_empty()
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let vk = Self::new(purpose, descriptor, slices)?;
        vk.check_recording_free_union_certified_c1(union)?;
        Ok(vk)
    }

    /// Match an actual recording-free union to this immutable, constructor-
    /// certified key. The canonical protocol is retained in the private key.
    /// Incoming union geometry is still checked before it can supply columns.
    pub(crate) fn check_recording_free_union_certified_c1(
        &self,
        union: &DuplexUnion,
    ) -> Result<(), RegionSidecarError> {
        if !union.rec_refs.is_empty()
            || !union.rec_blocks.is_empty()
            || !union.rec_challenges.is_empty()
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let protocol = &self.protocol;
        let expected_len = checked_pow2(protocol.w_log)?;
        if union.w_log != protocol.w_log
            || union.block_log != protocol.block_log
            || union.refs != protocol.refs
            || union.fixed.as_slice() != protocol.fixed.as_ref()
            || !layouts_equal(&union.layout, &protocol.layout)
            || union
                .committed
                .iter()
                .chain(union.s0.iter())
                .chain(union.s_out.iter())
                .any(|column| column.len() != expected_len)
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        Ok(())
    }

    pub fn purpose(&self) -> &[u8; 32] {
        &self.purpose
    }

    pub fn descriptor(&self) -> &CombinedDuplexRegionDescriptor {
        &self.descriptor
    }

    pub fn common_s_log(&self) -> usize {
        self.common_s_log
    }

    pub fn block_log(&self) -> usize {
        self.block_log
    }

    pub fn w_log(&self) -> usize {
        self.w_log
    }

    pub fn slices(&self) -> &[WitnessSlice; COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS] {
        &self.slices
    }

    pub fn fixed(&self) -> &[FixedPattern] {
        &self.fixed
    }

    pub fn layout_digest(&self) -> &[u8; 32] {
        &self.layout_digest
    }

    /// Stable manual key encoding.  The canonical protocol digest covers the
    /// reconstructed padded layout and fixed tables, while the descriptor is
    /// also encoded directly to bind schedule/IV order and tile geometry.
    pub fn transcript_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.push(COMBINED_DUPLEX_REGION_SIDECAR_VERSION);
        bytes.extend_from_slice(&self.purpose);
        self.descriptor.encode(&mut bytes);
        for value in [self.common_s_log, self.block_log, self.w_log] {
            push_usize(&mut bytes, value);
        }
        for slice in self.slices {
            push_usize(&mut bytes, slice.log2_len);
            push_usize(&mut bytes, slice.index);
        }
        bytes.extend_from_slice(&self.layout_digest);
        poseidon2b_hash_byte_slices(COMBINED_DUPLEX_VK_DIGEST_DOMAIN, &[&bytes])
    }

    fn validate_structure(&self) -> Result<CanonicalCombinedDuplexProtocol, RegionSidecarError> {
        let (protocol, digest) = cached_canonical_protocol(&self.descriptor)?;
        if self.common_s_log != protocol.common_s_log
            || self.block_log != protocol.block_log
            || self.w_log != protocol.w_log
            || self.fixed != protocol.fixed
            || self.layout_digest != digest
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let base = self.slices[0].index;
        for (column, slice) in self.slices.iter().enumerate() {
            if slice.log2_len != protocol.w_log
                || slice.index
                    != base
                        .checked_add(column)
                        .ok_or(RegionSidecarError::BadSlice)?
            {
                return Err(RegionSidecarError::BadSlice);
            }
        }
        Ok((*protocol).clone())
    }

    fn validate_in_witness(
        &self,
        total_vars: usize,
    ) -> Result<CanonicalCombinedDuplexProtocol, RegionSidecarError> {
        let protocol = self.validate_structure()?;
        if self.slices.iter().any(|slice| !slice.fits(total_vars)) {
            return Err(RegionSidecarError::BadSlice);
        }
        Ok(protocol)
    }

    /// Hot C1 path for a VK whose private fields were populated only by the
    /// checked constructors above. Structural regeneration remains in
    /// `validate_structure`; per-proof verification only needs to bind the
    /// already-certified protocol to the enclosing witness width.
    fn certified_c1_protocol_in_witness(
        &self,
        total_vars: usize,
    ) -> Result<Arc<CanonicalCombinedDuplexProtocol>, RegionSidecarError> {
        if self.slices.iter().any(|slice| !slice.fits(total_vars)) {
            return Err(RegionSidecarError::BadSlice);
        }
        Ok(Arc::clone(&self.protocol))
    }
}

/// Prover-only walk endpoints.  The committed columns are always sliced from
/// the already-committed outer witness `z`; `s0/s_out` never enter the proof.
pub struct CombinedDuplexRegionProverPlan<'a> {
    vk: &'a CombinedDuplexRegionVk,
    s0: &'a [Vec<F128>; 4],
    s_out: &'a [Vec<F128>; 4],
}

pub(crate) struct C1CombinedDuplexRegionProverWalkContinuation<'a, 'z> {
    vk: &'a CombinedDuplexRegionVk,
    total_vars: usize,
    protocol: Arc<CanonicalCombinedDuplexProtocol>,
    committed: [&'z [F128]; COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS],
    s0: &'a [Vec<F128>; 4],
    prefix: C1DuplexProverWalkPrefix,
}

impl C1CombinedDuplexRegionProverWalkContinuation<'_, '_> {
    pub(crate) fn group(&self) -> &C1LaneClaimGroup {
        self.prefix.walk_group()
    }

    pub(crate) fn s0(&self) -> &[Vec<F128>; 4] {
        self.s0
    }

    pub(crate) fn finish<Ch: Challenger>(
        self,
        terminal: &C1LaneClaimGroup,
        challenger: &mut Ch,
    ) -> Result<
        (
            C1CombinedDuplexRegionWalkDeferredProof,
            Vec<C1QuirkyDirectClaim>,
        ),
        RegionSidecarError,
    > {
        let (authority, terminal_claims) = prove_c1_duplex_walk_suffix(
            self.protocol.w_log,
            &self.protocol.fixed,
            &self.protocol.refs,
            &[],
            &self.committed,
            self.prefix,
            terminal,
            challenger,
        );
        let claims = resolve_c1_terminal_claims(self.vk, self.total_vars, terminal_claims)?;
        Ok((
            C1CombinedDuplexRegionWalkDeferredProof::new(authority),
            claims,
        ))
    }
}

pub(crate) struct C1CombinedDuplexRegionVerifierWalkContinuation<'a> {
    vk: &'a CombinedDuplexRegionVk,
    total_vars: usize,
    protocol: Arc<CanonicalCombinedDuplexProtocol>,
    prefix: C1DuplexVerifierWalkPrefix<'a>,
}

impl C1CombinedDuplexRegionVerifierWalkContinuation<'_> {
    pub(crate) fn group(&self) -> &C1LaneClaimGroup {
        self.prefix.walk_group()
    }

    pub(crate) fn finish<Ch: Challenger>(
        self,
        terminal: &C1LaneClaimGroup,
        challenger: &mut Ch,
    ) -> Result<Vec<C1QuirkyDirectClaim>, RegionSidecarError> {
        let terminal_claims = verify_c1_duplex_walk_suffix(
            self.protocol.w_log,
            &self.protocol.fixed,
            &self.protocol.refs,
            &[],
            self.prefix,
            terminal,
            challenger,
        )
        .map_err(|_| RegionSidecarError::InvalidProof)?;
        resolve_c1_terminal_claims(self.vk, self.total_vars, terminal_claims)
    }
}

impl<'a> CombinedDuplexRegionProverPlan<'a> {
    pub fn new(
        vk: &'a CombinedDuplexRegionVk,
        s0: &'a [Vec<F128>; 4],
        s_out: &'a [Vec<F128>; 4],
    ) -> Result<Self, RegionSidecarError> {
        let protocol = vk.validate_structure()?;
        let expected = checked_pow2(protocol.w_log)?;
        if s0.iter().any(|column| column.len() != expected)
            || s_out.iter().any(|column| column.len() != expected)
        {
            return Err(RegionSidecarError::BadWalkColumns);
        }
        Ok(Self { vk, s0, s_out })
    }

    pub(super) fn new_certified_c1(
        vk: &'a CombinedDuplexRegionVk,
        s0: &'a [Vec<F128>; 4],
        s_out: &'a [Vec<F128>; 4],
    ) -> Result<Self, RegionSidecarError> {
        validate_c1_endpoint_lengths(vk.w_log, s0, s_out)?;
        Ok(Self { vk, s0, s_out })
    }

    pub(crate) fn prove_c1_walk_deferred_prefix<'z, Ch: Challenger>(
        &self,
        z: &'z [F128],
        challenger: &mut Ch,
    ) -> Result<C1CombinedDuplexRegionProverWalkContinuation<'a, 'z>, RegionSidecarError> {
        let total_vars = witness_log(z)?;
        let protocol = self.vk.certified_c1_protocol_in_witness(total_vars)?;
        let committed: [&[F128]; COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS] =
            std::array::from_fn(|column| {
                let slice = self.vk.slices[column];
                &z[slice.start()..slice.start() + slice.len()]
            });
        bind_combined_duplex_vk(challenger, self.vk);
        let prefix = prove_c1_duplex_walk_prefix(
            protocol.w_log,
            &protocol.fixed,
            &protocol.refs,
            &committed,
            self.s_out,
            challenger,
        );
        Ok(C1CombinedDuplexRegionProverWalkContinuation {
            vk: self.vk,
            total_vars,
            protocol,
            committed,
            s0: self.s0,
            prefix,
        })
    }

    /// Run only inside the enclosing FieldR1cs post-commit callback on its
    /// exact challenger.  No challenger-constructing or recording shortcut is
    /// exposed.
    pub fn prove<Ch: Challenger>(
        &self,
        z: &[F128],
        challenger: &mut Ch,
    ) -> Result<(CombinedDuplexRegionSidecarProof, Vec<QuirkyDirectClaim>), RegionSidecarError>
    {
        let total_vars = witness_log(z)?;
        let protocol = self.vk.validate_in_witness(total_vars)?;
        let committed: [&[F128]; COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS] =
            std::array::from_fn(|column| {
                let slice = self.vk.slices[column];
                &z[slice.start()..slice.start() + slice.len()]
            });

        bind_combined_duplex_vk(challenger, self.vk);
        let (authority, terminal) = prove_duplex_union_with_challenger(
            protocol.w_log,
            &protocol.fixed,
            &protocol.refs,
            &[],
            &committed,
            self.s0,
            self.s_out,
            challenger,
        );
        let claims = resolve_terminal_claims(self.vk, total_vars, terminal)?;
        Ok((
            CombinedDuplexRegionSidecarProof {
                version: COMBINED_DUPLEX_REGION_SIDECAR_VERSION,
                authority,
            },
            claims,
        ))
    }

    /// Production entry point: the opaque context proves that the enclosing
    /// Field witness has already been committed and owns the mandatory PCS
    /// claim sink.  Every verifier-derived terminal is deposited before this
    /// method returns the proof authority.
    pub fn prove_post_commit<Ch: Challenger>(
        &self,
        context: &mut FieldPostCommitProverContext<'_, Ch>,
    ) -> Result<CombinedDuplexRegionSidecarProof, RegionSidecarError> {
        let witness = context.witness();
        let (proof, claims) = self.prove(witness, context)?;
        context.append_claims(claims);
        Ok(proof)
    }
}

/// Serializable proof authority.  Pending opening descriptors and recording
/// refs are absent by construction.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CombinedDuplexRegionSidecarProof {
    version: u8,
    authority: DuplexUnionProof,
}

impl CombinedDuplexRegionSidecarProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("combined duplex sidecar serialized length") as usize
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct C1CombinedDuplexRegionWalkDeferredProof {
    version: u8,
    authority: C1DuplexUnionWalkDeferredProof,
}

impl C1CombinedDuplexRegionWalkDeferredProof {
    pub(crate) fn new(authority: C1DuplexUnionWalkDeferredProof) -> Self {
        Self {
            version: COMBINED_DUPLEX_REGION_SIDECAR_VERSION,
            authority,
        }
    }

    pub(crate) fn version(&self) -> u8 {
        self.version
    }

    pub(crate) fn authority(&self) -> &C1DuplexUnionWalkDeferredProof {
        &self.authority
    }
}

/// The canonical padded union domain log of one combined-duplex descriptor,
/// without constructing a full VK (the slices-first recording-layout
/// derivation needs the width before any witness slice exists).
pub(crate) fn combined_duplex_protocol_w_log(
    descriptor: &CombinedDuplexRegionDescriptor,
) -> Result<usize, RegionSidecarError> {
    Ok(canonical_protocol(descriptor)?.w_log)
}

/// Decode one heterogeneous combined-Duplex sidecar only after its canonical
/// class has fixed every nested bincode sequence length without allocating.
pub fn decode_combined_duplex_region_sidecar_bounded(
    vk: &CombinedDuplexRegionVk,
    total_vars: usize,
    bytes: &[u8],
) -> Result<CombinedDuplexRegionSidecarProof, RegionSidecarError> {
    let protocol = vk.validate_in_witness(total_vars)?;
    let shape = duplex_like_proof_shape(
        COMBINED_DUPLEX_REGION_SIDECAR_VERSION,
        protocol.w_log,
        &protocol.refs,
    );
    preflight_fixed_proof(bytes, &shape)?;
    record_serde_attempt();
    let proof: CombinedDuplexRegionSidecarProof =
        bincode::deserialize(bytes).map_err(|_| RegionSidecarError::InvalidProof)?;
    if proof.version != COMBINED_DUPLEX_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    preflight_duplex_authority(protocol.w_log, &protocol.refs, &proof.authority)?;
    Ok(proof)
}

#[cfg(test)]
pub(super) fn combined_bounded_shape(
    vk: &CombinedDuplexRegionVk,
    total_vars: usize,
) -> Result<FixedProofShape, RegionSidecarError> {
    let protocol = vk.validate_in_witness(total_vars)?;
    Ok(duplex_like_proof_shape(
        COMBINED_DUPLEX_REGION_SIDECAR_VERSION,
        protocol.w_log,
        &protocol.refs,
    ))
}

/// Exact fixed-int wire shape of a CombinedDuplex child with only its walk
/// removed. The joint canonical codec reuses this rather than maintaining a
/// second hand-written relation/shift count.
pub(super) fn combined_walk_deferred_bounded_shape(
    vk: &CombinedDuplexRegionVk,
    total_vars: usize,
) -> Result<DeferredFixedProofShape, RegionSidecarError> {
    let protocol = vk.certified_c1_protocol_in_witness(total_vars)?;
    Ok(duplex_like_proof_shape(
        COMBINED_DUPLEX_REGION_SIDECAR_VERSION,
        protocol.w_log,
        &protocol.refs,
    )
    .walk_deferred())
}

/// Replay the recording-free combined vertical and derive all terminal outer
/// PCS claims from the canonical six VK slices.
pub fn verify_combined_duplex_region_sidecar<Ch: Challenger>(
    vk: &CombinedDuplexRegionVk,
    total_vars: usize,
    proof: &CombinedDuplexRegionSidecarProof,
    challenger: &mut Ch,
) -> Result<Vec<QuirkyDirectClaim>, RegionSidecarError> {
    let protocol = vk.validate_in_witness(total_vars)?;
    if proof.version != COMBINED_DUPLEX_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    bind_combined_duplex_vk(challenger, vk);
    let terminal = verify_duplex_union_with_challenger(
        protocol.w_log,
        &protocol.fixed,
        &protocol.refs,
        &[],
        &proof.authority,
        challenger,
    )
    .map_err(|_| RegionSidecarError::InvalidProof)?;
    resolve_terminal_claims(vk, total_vars, terminal)
}

pub(crate) fn verify_c1_combined_duplex_region_walk_deferred_prefix<'a, Ch: Challenger>(
    vk: &'a CombinedDuplexRegionVk,
    total_vars: usize,
    proof: &'a C1CombinedDuplexRegionWalkDeferredProof,
    challenger: &mut Ch,
) -> Result<C1CombinedDuplexRegionVerifierWalkContinuation<'a>, RegionSidecarError> {
    let timing = std::env::var_os("NOIDH_C1_VERIFY_TIMING").is_some();
    let total_started = std::time::Instant::now();
    let protocol = vk.certified_c1_protocol_in_witness(total_vars)?;
    let validate_micros = total_started.elapsed().as_micros();
    if proof.version() != COMBINED_DUPLEX_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    bind_combined_duplex_vk(challenger, vk);
    let bind_micros = total_started.elapsed().as_micros() - validate_micros;
    let prefix_started = std::time::Instant::now();
    let prefix = verify_c1_duplex_walk_prefix(
        protocol.w_log,
        &protocol.fixed,
        &protocol.refs,
        proof.authority().as_ref(),
        challenger,
    )
    .map_err(|_| RegionSidecarError::InvalidProof)?;
    if timing {
        eprintln!(
            "[combined-duplex-c1 prefix] w_log={} validate_us={validate_micros} bind_us={bind_micros} proof_us={} total_us={}",
            protocol.w_log,
            prefix_started.elapsed().as_micros(),
            total_started.elapsed().as_micros(),
        );
    }
    Ok(C1CombinedDuplexRegionVerifierWalkContinuation {
        vk,
        total_vars,
        protocol,
        prefix,
    })
}

/// Production verifier entry point.  The context both witnesses the causal
/// post-commit position and prevents callers from verifying the authority
/// while accidentally dropping its terminal PCS claims.
pub fn verify_combined_duplex_region_sidecar_post_commit<Ch: Challenger>(
    vk: &CombinedDuplexRegionVk,
    proof: &CombinedDuplexRegionSidecarProof,
    context: &mut FieldPostCommitVerifierContext<'_, Ch>,
) -> Result<(), RegionSidecarError> {
    let claims = verify_combined_duplex_region_sidecar(vk, context.total_vars(), proof, context)?;
    context.append_claims(claims);
    Ok(())
}

pub(crate) struct C1CombinedDuplexRegionTraceWalkContinuation<'a> {
    vk: &'a CombinedDuplexRegionVk,
    total_vars: usize,
    protocol: Arc<CanonicalCombinedDuplexProtocol>,
    prefix: C1DuplexUnionTraceWalkPrefix<'a>,
}

impl C1CombinedDuplexRegionTraceWalkContinuation<'_> {
    pub(crate) fn walk_group(&self) -> crate::acceptance::trace::deep_chain::C1LaneClaimGroupTrace {
        self.prefix.walk_group().clone()
    }

    pub(crate) fn finish<C: FsChannelOps>(
        self,
        b: &mut FieldR1csBuilder,
        context: &mut FieldPostCommitTraceContext<'_, C>,
        walk_terminal: &crate::acceptance::trace::deep_chain::C1LaneClaimGroupTrace,
    ) -> Result<Vec<C1QuirkyDirectClaimTrace>, RegionSidecarError> {
        if context.total_vars() != self.total_vars {
            return Err(RegionSidecarError::InvalidProof);
        }
        let terminal = verify_c1_duplex_walk_suffix_trace(
            b,
            context,
            self.protocol.w_log,
            &self.protocol.fixed,
            &self.protocol.refs,
            &[],
            self.prefix,
            walk_terminal,
        )?;
        resolve_c1_combined_terminal_claims_trace(self.vk, self.total_vars, terminal)
    }
}

pub(crate) fn verify_c1_combined_duplex_region_walk_deferred_prefix_trace<'a, C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    context: &mut FieldPostCommitTraceContext<'_, C>,
    vk: &'a CombinedDuplexRegionVk,
    proof: &'a C1CombinedDuplexRegionWalkDeferredProof,
) -> Result<C1CombinedDuplexRegionTraceWalkContinuation<'a>, RegionSidecarError> {
    let total_vars = context.total_vars();
    let protocol = vk.certified_c1_protocol_in_witness(total_vars)?;
    if proof.version() != COMBINED_DUPLEX_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    context.observe_label(b, COMBINED_DUPLEX_SIDECAR_TRANSCRIPT_LABEL);
    crate::acceptance::trace::self_verify::observe_pinned_digest(
        b,
        context,
        &vk.transcript_digest(),
    );
    let prefix = verify_c1_duplex_walk_prefix_trace(
        b,
        context,
        protocol.w_log,
        &protocol.fixed,
        &protocol.refs,
        proof.authority().as_ref(),
    )?;
    Ok(C1CombinedDuplexRegionTraceWalkContinuation {
        vk,
        total_vars,
        protocol,
        prefix,
    })
}

/// Recursive typestate verifier for the heterogeneous recording-free L-A
/// vertical. It reuses the generic duplex authority replay with the canonical
/// combined protocol reconstructed from this VK, then deposits every derived
/// claim directly into the enclosing trace context.
pub fn verify_combined_duplex_region_sidecar_trace_post_commit<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    context: &mut FieldPostCommitTraceContext<'_, C>,
    vk: &CombinedDuplexRegionVk,
    proof: &CombinedDuplexRegionSidecarProof,
) -> Result<(), RegionSidecarError> {
    let total_vars = context.total_vars();
    preflight_combined_duplex_sidecar_trace(vk, total_vars, proof)?;
    let protocol = vk.validate_in_witness(total_vars)?;

    context.observe_label(b, COMBINED_DUPLEX_SIDECAR_TRANSCRIPT_LABEL);
    crate::acceptance::trace::self_verify::observe_pinned_digest(
        b,
        context,
        &vk.transcript_digest(),
    );
    let terminal = verify_duplex_union_proof_trace(
        b,
        context,
        protocol.w_log,
        &protocol.fixed,
        &protocol.refs,
        &proof.authority,
    )?;
    context.append_claims(resolve_combined_terminal_claims_trace(
        vk, total_vars, terminal,
    )?);
    Ok(())
}

fn resolve_combined_terminal_claims_trace(
    vk: &CombinedDuplexRegionVk,
    total_vars: usize,
    terminal: Vec<DuplexColumnClaimTrace>,
) -> Result<Vec<QuirkyDirectClaimTrace>, RegionSidecarError> {
    terminal
        .into_iter()
        .map(|claim| {
            let slice = *vk
                .slices
                .get(claim.column)
                .ok_or(RegionSidecarError::InvalidProof)?;
            if claim.point.len() != slice.log2_len {
                return Err(RegionSidecarError::InvalidProof);
            }
            let mut x_rest = claim.point;
            x_rest.extend(
                slice
                    .prefix_coords(total_vars)
                    .into_iter()
                    .map(LinExpr::constant),
            );
            Ok(QuirkyDirectClaimTrace {
                z_skip: LinExpr::zero(),
                k_skip: 0,
                x_rest,
                value: claim.value,
            })
        })
        .collect()
}

fn resolve_c1_combined_terminal_claims_trace(
    vk: &CombinedDuplexRegionVk,
    total_vars: usize,
    terminal: Vec<C1DuplexColumnClaimTrace>,
) -> Result<Vec<C1QuirkyDirectClaimTrace>, RegionSidecarError> {
    terminal
        .into_iter()
        .map(|claim| {
            let slice = *vk
                .slices
                .get(claim.column)
                .ok_or(RegionSidecarError::InvalidProof)?;
            if claim.point.len() != slice.log2_len {
                return Err(RegionSidecarError::InvalidProof);
            }
            let mut x_rest = claim.point;
            x_rest.extend(
                slice
                    .prefix_coords(total_vars)
                    .into_iter()
                    .map(|value| ExtExpr::constant(F256::from_base(value))),
            );
            Ok(C1QuirkyDirectClaimTrace {
                z_skip: ExtExpr::zero(),
                k_skip: 0,
                x_rest,
                value: claim.value,
            })
        })
        .collect()
}

pub(crate) fn preflight_combined_duplex_sidecar_trace(
    vk: &CombinedDuplexRegionVk,
    total_vars: usize,
    proof: &CombinedDuplexRegionSidecarProof,
) -> Result<(), RegionSidecarError> {
    let protocol = vk.validate_in_witness(total_vars)?;
    if proof.version != COMBINED_DUPLEX_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    preflight_duplex_authority(protocol.w_log, &protocol.refs, &proof.authority)
}

fn preflight_descriptor(
    descriptor: &CombinedDuplexRegionDescriptor,
) -> Result<(usize, usize, usize), RegionSidecarError> {
    if descriptor.subchannels.len() < 2
        || descriptor.subchannels.len() > MAX_COMBINED_DUPLEX_SUBCHANNELS
        || descriptor.tx_tile_log > MAX_COMBINED_DUPLEX_TX_TILE_LOG
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let padded_subchannels = descriptor
        .subchannels
        .len()
        .checked_next_power_of_two()
        .ok_or(RegionSidecarError::BadVk)?;
    let max_slots = descriptor
        .subchannels
        .iter()
        .map(|subchannel| schedule_shape(&subchannel.schedule).map(|shape| shape.slots))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or(RegionSidecarError::UnsupportedVkShape)?;
    let common_s = max_slots
        .max(1)
        .checked_next_power_of_two()
        .ok_or(RegionSidecarError::BadVk)?;
    let per_tile = padded_subchannels
        .checked_mul(common_s)
        .ok_or(RegionSidecarError::BadVk)?;
    if !per_tile.is_power_of_two() {
        return Err(RegionSidecarError::BadVk);
    }
    let fixed_cells = per_tile.checked_mul(7).ok_or(RegionSidecarError::BadVk)?;
    if fixed_cells > MAX_COMBINED_DUPLEX_FIXED_CELLS {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let tile_count = checked_pow2(descriptor.tx_tile_log)?;
    let total_slots = per_tile
        .checked_mul(tile_count)
        .ok_or(RegionSidecarError::BadVk)?;
    if !total_slots.is_power_of_two() {
        return Err(RegionSidecarError::BadVk);
    }
    let common_s_log = common_s.trailing_zeros() as usize;
    let block_log = per_tile.trailing_zeros() as usize;
    let w_log = total_slots.trailing_zeros() as usize;
    if w_log == 0 || w_log > MAX_COMBINED_DUPLEX_W_LOG || w_log >= usize::BITS as usize {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    Ok((common_s_log, block_log, w_log))
}

fn canonical_protocol(
    descriptor: &CombinedDuplexRegionDescriptor,
) -> Result<CanonicalCombinedDuplexProtocol, RegionSidecarError> {
    let (common_s_log, block_log, w_log) = preflight_descriptor(descriptor)?;
    let padded_len = descriptor
        .subchannels
        .len()
        .checked_next_power_of_two()
        .ok_or(RegionSidecarError::BadVk)?;
    let mut subchannels = Vec::with_capacity(padded_len);
    for descriptor in &descriptor.subchannels {
        let shape = schedule_shape(&descriptor.schedule)?;
        let layout = compile_duplex(&descriptor.schedule);
        if layout.slots.len() != shape.slots
            || layout.n_data != shape.data_lanes
            || layout.challenges.len() != shape.challenges
        {
            return Err(RegionSidecarError::BadVk);
        }
        subchannels.push(SubChannel {
            layout,
            iv_flat: descriptor.iv_flat,
        });
    }
    subchannels.resize_with(padded_len, || SubChannel {
        layout: DuplexLayout {
            slots: Vec::new(),
            challenges: Vec::new(),
            n_data: 0,
        },
        iv_flat: [F128::ZERO, F128::ZERO],
    });

    let fixed = combined_duplex_fixed_patterns(&subchannels, common_s_log);
    let layout = combined_duplex_layout(&subchannels, common_s_log);
    if fixed.len() != 7
        || fixed.iter().any(|pattern| {
            pattern.low_log != block_log
                || pattern.table.len() != (1usize << block_log)
                || pattern.hi_gate.is_some()
        })
        || layout.slots.len() != (1usize << block_log)
    {
        return Err(RegionSidecarError::BadVk);
    }
    Ok(CanonicalCombinedDuplexProtocol {
        common_s_log,
        block_log,
        w_log,
        fixed: fixed.into(),
        refs: duplex_family_refs(0, 0),
        layout,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScheduleShape {
    slots: usize,
    data_lanes: usize,
    challenges: usize,
}

/// Allocation-free mirror of `compile_duplex`'s shape transitions.  It rejects
/// every panic/oversize input before compiling any schedule or fixed table.
fn schedule_shape(schedule: &[TranscriptOp]) -> Result<ScheduleShape, RegionSidecarError> {
    if schedule.is_empty() || schedule.len() > MAX_COMBINED_DUPLEX_SCHEDULE_OPS {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let mut slots = 0usize;
    let mut data_lanes = 0usize;
    let mut schedule_lanes = 0usize;
    let mut challenges = 0usize;
    let mut filled = 0usize;
    let mut squeezing = false;
    let mut pending = false;

    for op in schedule {
        match op {
            TranscriptOp::Absorb(lanes) => {
                if lanes.is_empty() || lanes.len() > MAX_COMBINED_DUPLEX_DATA_LANES {
                    return Err(RegionSidecarError::UnsupportedVkShape);
                }
                schedule_lanes = schedule_lanes
                    .checked_add(lanes.len())
                    .ok_or(RegionSidecarError::BadVk)?;
                if schedule_lanes > MAX_COMBINED_DUPLEX_DATA_LANES {
                    return Err(RegionSidecarError::UnsupportedVkShape);
                }
                if squeezing {
                    squeezing = false;
                    pending = false;
                }
                data_lanes = lanes
                    .iter()
                    .try_fold(data_lanes, |count, lane| {
                        if lane.is_none() {
                            count.checked_add(1)
                        } else {
                            Some(count)
                        }
                    })
                    .ok_or(RegionSidecarError::BadVk)?;
                let buffered = filled
                    .checked_add(lanes.len())
                    .ok_or(RegionSidecarError::BadVk)?;
                slots = slots
                    .checked_add(buffered / 2)
                    .ok_or(RegionSidecarError::BadVk)?;
                filled = buffered % 2;
            }
            TranscriptOp::Squeeze(count) => {
                if *count == 0 || *count > MAX_COMBINED_DUPLEX_CHALLENGES {
                    return Err(RegionSidecarError::UnsupportedVkShape);
                }
                if !squeezing {
                    if filled == 1 {
                        slots = slots.checked_add(1).ok_or(RegionSidecarError::BadVk)?;
                        filled = 0;
                    }
                    squeezing = true;
                    pending = false;
                }
                if slots == 0 {
                    return Err(RegionSidecarError::UnsupportedVkShape);
                }
                challenges = challenges
                    .checked_add(*count)
                    .ok_or(RegionSidecarError::BadVk)?;
                if challenges > MAX_COMBINED_DUPLEX_CHALLENGES {
                    return Err(RegionSidecarError::UnsupportedVkShape);
                }
                let consumed_pending = usize::from(pending);
                let remaining = count
                    .checked_sub(consumed_pending)
                    .ok_or(RegionSidecarError::BadVk)?;
                let eager_slots = remaining.checked_add(1).ok_or(RegionSidecarError::BadVk)? / 2;
                slots = slots
                    .checked_add(eager_slots)
                    .ok_or(RegionSidecarError::BadVk)?;
                pending = remaining % 2 == 1;
                if slots > MAX_COMBINED_DUPLEX_SUBCHANNEL_SLOTS {
                    return Err(RegionSidecarError::UnsupportedVkShape);
                }
            }
        }
        if data_lanes > MAX_COMBINED_DUPLEX_DATA_LANES
            || slots > MAX_COMBINED_DUPLEX_SUBCHANNEL_SLOTS
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
    }
    if filled == 1 {
        slots = slots.checked_add(1).ok_or(RegionSidecarError::BadVk)?;
    }
    if slots == 0
        || slots > MAX_COMBINED_DUPLEX_SUBCHANNEL_SLOTS
        || data_lanes == 0
        || challenges > MAX_COMBINED_DUPLEX_CHALLENGES
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    Ok(ScheduleShape {
        slots,
        data_lanes,
        challenges,
    })
}

fn combined_duplex_protocol_digest(
    descriptor: &CombinedDuplexRegionDescriptor,
    protocol: &CanonicalCombinedDuplexProtocol,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.push(COMBINED_DUPLEX_REGION_SIDECAR_VERSION);
    descriptor.encode(&mut bytes);
    for value in [protocol.common_s_log, protocol.block_log, protocol.w_log] {
        push_usize(&mut bytes, value);
    }
    bytes.extend_from_slice(&super::duplex_layout_digest(&protocol.layout));
    push_usize(&mut bytes, protocol.fixed.len());
    for pattern in protocol.fixed.iter() {
        push_usize(&mut bytes, pattern.low_log);
        push_usize(&mut bytes, pattern.table.len());
        for value in &pattern.table {
            push_f128(&mut bytes, *value);
        }
        match &pattern.hi_gate {
            None => bytes.push(0),
            Some((first, bits)) => {
                bytes.push(1);
                push_usize(&mut bytes, *first);
                push_usize(&mut bytes, bits.len());
                bytes.extend(bits.iter().map(|bit| u8::from(*bit)));
            }
        }
    }
    poseidon2b_hash_byte_slices(COMBINED_DUPLEX_LAYOUT_DIGEST_DOMAIN, &[&bytes])
}

fn bind_combined_duplex_vk<Ch: Challenger>(challenger: &mut Ch, vk: &CombinedDuplexRegionVk) {
    challenger.observe_label(COMBINED_DUPLEX_SIDECAR_TRANSCRIPT_LABEL);
    challenger.observe_bytes(&vk.transcript_digest());
}

fn resolve_terminal_claims(
    vk: &CombinedDuplexRegionVk,
    total_vars: usize,
    terminal: Vec<DuplexColumnClaim>,
) -> Result<Vec<QuirkyDirectClaim>, RegionSidecarError> {
    let mut claims = Vec::with_capacity(terminal.len());
    for claim in terminal {
        let slice = *vk
            .slices
            .get(claim.column)
            .ok_or(RegionSidecarError::InvalidProof)?;
        if claim.point.len() != slice.log2_len {
            return Err(RegionSidecarError::InvalidProof);
        }
        let mut x_rest = claim.point;
        x_rest.extend(slice.prefix_coords(total_vars));
        claims.push(QuirkyDirectClaim {
            z_skip: F128::ZERO,
            k_skip: 0,
            x_rest,
            value: claim.value,
        });
    }
    Ok(claims)
}

fn resolve_c1_terminal_claims(
    vk: &CombinedDuplexRegionVk,
    total_vars: usize,
    terminal: Vec<C1DuplexColumnClaim>,
) -> Result<Vec<C1QuirkyDirectClaim>, RegionSidecarError> {
    let mut claims = Vec::with_capacity(terminal.len());
    for claim in terminal {
        let slice = *vk
            .slices
            .get(claim.column)
            .ok_or(RegionSidecarError::InvalidProof)?;
        if claim.point.len() != slice.log2_len {
            return Err(RegionSidecarError::InvalidProof);
        }
        let mut x_rest = claim.point;
        x_rest.extend(
            slice
                .prefix_coords(total_vars)
                .into_iter()
                .map(F256::from_base),
        );
        claims.push(C1QuirkyDirectClaim {
            z_skip: F256::ZERO,
            k_skip: 0,
            x_rest,
            value: claim.value,
        });
    }
    Ok(claims)
}

fn checked_pow2(log: usize) -> Result<usize, RegionSidecarError> {
    if log >= usize::BITS as usize {
        return Err(RegionSidecarError::BadVk);
    }
    Ok(1usize << log)
}

fn layouts_equal(left: &DuplexLayout, right: &DuplexLayout) -> bool {
    left.slots == right.slots && left.challenges == right.challenges && left.n_data == right.n_data
}

#[cfg(test)]
pub(in crate::region_sidecar) mod tests {
    use super::super::bounded_decode;
    use super::*;

    use crate::acceptance::trace::region_source_binding::{
        build_combined_duplex_union, build_combined_duplex_union_with_recordings, RecordingSpec,
    };
    use crate::region_sidecar::DuplexRegionVk;
    use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
    use noid_ivc_core::deep_chain::relations::{
        prove_column_relation, verify_column_relation, RelationColumns,
    };
    use noid_ivc_core::deep_chain::schedule::{carry_selection_terms, TranscriptOp};

    use noid_ivc_core::field_circuit::FieldR1csBuilder;
    use noid_ivc_core::lincheck::build_eq_table;
    use noid_ivc_core::pcs::{self, PcsParams};
    use noid_ivc_core::public_io::PublicIoSpec;
    use noid_ivc_core::verifier::{
        verify_field_with_public_io, verify_field_with_public_io_and_post_commit_context,
        VerifyError,
    };
    use noid_ivc_prover::field_prover::prove_field_with_public_io_and_post_commit_context;

    const FIELD_DOMAIN: &[u8] = b"combined-duplex-region-sidecar-field-e2e-v1";

    struct CombinedFixture {
        descriptor: CombinedDuplexRegionDescriptor,
        subs: Vec<SubChannel>,
        data: Vec<Vec<Vec<F128>>>,
        union: DuplexUnion,
    }

    fn params(m: usize) -> PcsParams {
        PcsParams {
            m: m + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        }
    }

    fn fixture() -> CombinedFixture {
        let channels = vec![
            CombinedDuplexSubChannelDescriptor::new(
                vec![
                    TranscriptOp::Absorb(vec![None; 2]),
                    TranscriptOp::Squeeze(3),
                    TranscriptOp::Absorb(vec![None]),
                ],
                [F128::new(0x1111, 0x2222), F128::new(0x3333, 0x4444)],
            )
            .unwrap(),
            CombinedDuplexSubChannelDescriptor::new(
                vec![
                    TranscriptOp::Absorb(vec![None; 4]),
                    TranscriptOp::Squeeze(2),
                    TranscriptOp::Absorb(vec![None; 2]),
                ],
                [F128::new(0xAAAA, 0xBBBB), F128::new(0xCCCC, 0xDDDD)],
            )
            .unwrap(),
        ];
        let subs = channels
            .iter()
            .map(|channel| SubChannel {
                layout: compile_duplex(channel.schedule()),
                iv_flat: channel.iv_flat(),
            })
            .collect::<Vec<_>>();
        let data = vec![
            vec![
                vec![F128::new(3, 0), F128::new(5, 0), F128::new(7, 0)],
                vec![
                    F128::new(11, 0),
                    F128::new(13, 0),
                    F128::new(17, 0),
                    F128::new(19, 0),
                    F128::new(23, 0),
                    F128::new(29, 0),
                ],
            ],
            vec![
                vec![F128::new(31, 0), F128::new(37, 0), F128::new(41, 0)],
                vec![
                    F128::new(43, 0),
                    F128::new(47, 0),
                    F128::new(53, 0),
                    F128::new(59, 0),
                    F128::new(61, 0),
                    F128::new(67, 0),
                ],
            ],
        ];
        let union = build_combined_duplex_union(&subs, &data);
        let descriptor = CombinedDuplexRegionDescriptor::new(1, channels).unwrap();
        CombinedFixture {
            descriptor,
            subs,
            data,
            union,
        }
    }

    fn placeholder_slices(
        w_log: usize,
    ) -> [WitnessSlice; COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS] {
        std::array::from_fn(|index| WitnessSlice {
            log2_len: w_log,
            index,
        })
    }

    #[test]
    fn canonical_protocol_cache_binds_exact_descriptors_and_limits_retention() {
        let mut cache = CanonicalProtocolCache::default();
        let base = fixture().descriptor;
        let mut last = None;
        for index in 0..CANONICAL_CACHE_ENTRIES + 3 {
            let mut descriptor = base.clone();
            descriptor.subchannels[0].iv_flat[0] += F128::new(index as u64 + 1, 0);
            let fresh = Arc::new(canonical_protocol(&descriptor).unwrap());
            let digest = combined_duplex_protocol_digest(&descriptor, &fresh);
            let bytes = canonical_cache_bytes(&descriptor, &fresh);
            assert!(cache.get(&descriptor).is_none());
            cache.insert(CanonicalCacheEntry {
                descriptor: descriptor.clone(),
                protocol: Arc::clone(&fresh),
                digest,
                bytes,
            });
            let (cached, cached_digest) = cache.get(&descriptor).unwrap();
            assert!(Arc::ptr_eq(&fresh, &cached));
            assert_eq!(digest, cached_digest);
            assert!(cache.entries.len() <= CANONICAL_CACHE_ENTRIES);
            assert!(cache.bytes <= CANONICAL_CACHE_BYTES);
            last = Some(descriptor);
        }
        let mut oversized = base.clone();
        oversized.subchannels[0].iv_flat[1] += F128::ONE;
        let fresh = Arc::new(canonical_protocol(&oversized).unwrap());
        cache.insert(CanonicalCacheEntry {
            descriptor: oversized.clone(),
            digest: combined_duplex_protocol_digest(&oversized, &fresh),
            protocol: fresh,
            bytes: CANONICAL_CACHE_BYTES + 1,
        });
        assert!(cache.get(&oversized).is_none());
        assert!(cache.get(&last.unwrap()).is_some());
    }

    pub(in crate::region_sidecar) fn composite_decode_fixture(
        purpose: [u8; 32],
    ) -> (
        CombinedDuplexRegionVk,
        usize,
        CombinedDuplexRegionSidecarProof,
    ) {
        let fixture = fixture();
        let column_len = 1usize << fixture.union.w_log;
        let mut z = vec![
            F128::ZERO;
            (COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS * column_len).next_power_of_two()
        ];
        for (column, values) in fixture.union.committed.iter().enumerate() {
            z[column * column_len..(column + 1) * column_len].copy_from_slice(values);
        }
        let slices = std::array::from_fn(|index| WitnessSlice {
            log2_len: fixture.union.w_log,
            index,
        });
        let vk =
            CombinedDuplexRegionVk::from_union(purpose, fixture.descriptor, slices, &fixture.union)
                .unwrap();
        let plan =
            CombinedDuplexRegionProverPlan::new(&vk, &fixture.union.s0, &fixture.union.s_out)
                .unwrap();
        let mut challenger = FsLaneChallenger::new(b"combined-duplex-bounded-decode-v1");
        let (proof, _) = plan.prove(&z, &mut challenger).unwrap();
        (vk, z.len().trailing_zeros() as usize, proof)
    }

    #[test]
    fn combined_duplex_bounded_decode_rejects_forged_lengths_before_serde() {
        let (vk, total_vars, proof) = composite_decode_fixture([0xD3; 32]);
        let encoded = bincode::serialize(&proof).unwrap();

        let before = bounded_decode::serde_attempts();
        assert_eq!(
            decode_combined_duplex_region_sidecar_bounded(&vk, total_vars, &encoded).unwrap(),
            proof
        );
        assert_eq!(bounded_decode::serde_attempts(), before + 1);

        let malformed_start = bounded_decode::serde_attempts();
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_combined_duplex_region_sidecar_bounded(&vk, total_vars, &trailing).unwrap_err(),
            RegionSidecarError::InvalidProof
        );
        assert_eq!(
            decode_combined_duplex_region_sidecar_bounded(
                &vk,
                total_vars,
                &encoded[..encoded.len() - 1],
            )
            .unwrap_err(),
            RegionSidecarError::InvalidProof
        );
        let mut wrong_version = encoded.clone();
        wrong_version[0] = COMBINED_DUPLEX_REGION_SIDECAR_VERSION.wrapping_add(1);
        assert_eq!(
            decode_combined_duplex_region_sidecar_bounded(&vk, total_vars, &wrong_version)
                .unwrap_err(),
            RegionSidecarError::UnsupportedVersion
        );

        let shape = combined_bounded_shape(&vk, total_vars).unwrap();
        let offsets = bounded_decode::layout_offsets(&encoded, &shape).unwrap();
        for (field, offset) in offsets {
            if !matches!(field, bounded_decode::LayoutField::VecLength(_)) {
                continue;
            }
            let mut forged = encoded.clone();
            forged[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert_eq!(
                decode_combined_duplex_region_sidecar_bounded(&vk, total_vars, &forged)
                    .unwrap_err(),
                RegionSidecarError::InvalidProof
            );
        }
        assert_eq!(
            bounded_decode::serde_attempts(),
            malformed_start,
            "malformed combined lengths reached allocation-bearing serde"
        );
    }

    #[test]
    fn combined_c1_child_shape_is_derived_from_the_full_authority() {
        let (vk, total_vars, _) = composite_decode_fixture([0xD4; 32]);
        let full_shape = combined_bounded_shape(&vk, total_vars).unwrap();
        let shape = combined_walk_deferred_bounded_shape(&vk, total_vars).unwrap();
        assert_eq!(shape, full_shape.walk_deferred());
    }

    #[test]
    fn combined_descriptor_exactly_matches_recording_free_builder_and_rejects_hosting() {
        let fixture = fixture();
        let slices = placeholder_slices(fixture.union.w_log);
        let purpose = [0xA5; 32];
        let vk = CombinedDuplexRegionVk::new(purpose, fixture.descriptor.clone(), slices).unwrap();
        let bridged = CombinedDuplexRegionVk::from_union(
            purpose,
            fixture.descriptor.clone(),
            slices,
            &fixture.union,
        )
        .unwrap();
        assert_eq!(vk, bridged);
        assert_eq!(vk.common_s_log(), 2);
        assert_eq!(vk.block_log(), fixture.union.block_log);
        assert_eq!(vk.w_log(), fixture.union.w_log);
        assert_eq!(vk.fixed(), fixture.union.fixed.as_slice());
        vk.check_recording_free_union_certified_c1(&fixture.union)
            .unwrap();
        let protocol = canonical_protocol(&fixture.descriptor).unwrap();
        assert!(layouts_equal(&protocol.layout, &fixture.union.layout));

        assert!(
            DuplexRegionVk::from_union(purpose, slices, &fixture.union).is_err(),
            "homogeneous VK accepted heterogeneous combined fixed tables"
        );
        assert!(
            DuplexRegionVk::new(
                purpose,
                fixture.union.w_log,
                slices,
                fixture.union.fixed.clone(),
                fixture.union.refs,
                &fixture.union.layout,
            )
            .is_err(),
            "homogeneous direct constructor accepted a combined layout"
        );

        let recording_layout = compile_duplex(&[TranscriptOp::Absorb(vec![None; 2])]);
        let recording_data = [F128::new(43, 0), F128::new(47, 0)];
        let recording = RecordingSpec {
            layout: recording_layout,
            iv_flat: [F128::new(0x55, 0), F128::new(0x77, 0)],
            data: &recording_data,
        };
        let hosted = build_combined_duplex_union_with_recordings(
            &fixture.subs,
            &fixture.data,
            std::slice::from_ref(&recording),
        );
        assert_eq!(
            CombinedDuplexRegionVk::from_union(
                purpose,
                fixture.descriptor,
                placeholder_slices(hosted.w_log),
                &hosted,
            ),
            Err(RegionSidecarError::UnsupportedVkShape),
            "V1 accepted a B-to-A recording host"
        );
    }

    #[test]
    fn cached_combined_protocol_checks_every_incoming_union_shape() {
        let f = fixture();
        let vk = CombinedDuplexRegionVk::new(
            [0xB5; 32],
            f.descriptor,
            placeholder_slices(f.union.w_log),
        )
        .unwrap();
        for mutation in 0..7 {
            let mut altered = fixture().union;
            match mutation {
                0 => altered.w_log += 1,
                1 => altered.block_log += 1,
                2 => altered.fixed[0].table[0] += F128::ONE,
                3 => altered.layout.n_data += 1,
                4 => {
                    altered.committed[0].pop();
                }
                5 => {
                    altered.s0[0].pop();
                }
                6 => {
                    altered.s_out[0].pop();
                }
                _ => unreachable!(),
            }
            assert!(
                vk.check_recording_free_union_certified_c1(&altered)
                    .is_err(),
                "mutation={mutation}"
            );
        }
    }

    #[test]
    fn combined_duplex_field_postcommit_roundtrip_and_mutation_battery() {
        let fixture = fixture();
        let mut builder = FieldR1csBuilder::new();
        let column_len = 1usize << fixture.union.w_log;
        while builder.num_wires() % column_len != 0 {
            builder.alloc_f128(F128::ZERO);
        }
        let base = builder.num_wires() / column_len;
        for column in &fixture.union.committed {
            for value in column {
                builder.alloc_f128(*value);
            }
        }
        let slices: [WitnessSlice; COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS] =
            std::array::from_fn(|column| WitnessSlice {
                log2_len: fixture.union.w_log,
                index: base + column,
            });
        let (r1cs, z) = builder.build();
        let purpose = poseidon2b_hash_byte_slices(
            b"COMBINED-DUPLEX-SIDECAR-TEST-PURPOSE",
            &[b"heterogeneous"],
        );
        let vk = CombinedDuplexRegionVk::from_union(
            purpose,
            fixture.descriptor.clone(),
            slices,
            &fixture.union,
        )
        .unwrap();
        let plan =
            CombinedDuplexRegionProverPlan::new(&vk, &fixture.union.s0, &fixture.union.s_out)
                .unwrap();
        let spec = PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 0,
                index: 0,
            },
            io_len: 1,
            claims: Vec::new(),
        };
        let io = [F128::ONE];
        let class_digest = poseidon2b_hash_byte_slices(
            b"COMBINED-DUPLEX-SIDECAR-OUTER-CLASS/V1",
            &[&vk.transcript_digest()],
        );
        let mut prover = FsLaneChallenger::new(FIELD_DOMAIN);
        let (field_proof, sidecar, commitment, _) =
            prove_field_with_public_io_and_post_commit_context(
                &r1cs,
                &z,
                &params(r1cs.m),
                &spec,
                &io,
                &class_digest,
                &mut prover,
                |context| {
                    plan.prove_post_commit(context)
                        .expect("honest combined sidecar")
                },
            );

        let encoded = bincode::serialize(&sidecar).expect("serialize combined sidecar");
        assert_eq!(encoded.len(), sidecar.byte_len());
        let decoded: CombinedDuplexRegionSidecarProof =
            bincode::deserialize(&encoded).expect("deserialize combined sidecar");
        assert_eq!(decoded, sidecar);

        let verify_with_class =
            |candidate_class_digest: &[u8; 32],
             candidate_vk: &CombinedDuplexRegionVk,
             candidate_proof: &CombinedDuplexRegionSidecarProof| {
                let mut challenger = FsLaneChallenger::new(FIELD_DOMAIN);
                verify_field_with_public_io_and_post_commit_context(
                    &r1cs,
                    &commitment,
                    &field_proof,
                    &spec,
                    &io,
                    candidate_class_digest,
                    candidate_proof,
                    &mut challenger,
                    |proof, context| {
                        verify_combined_duplex_region_sidecar_post_commit(
                            candidate_vk,
                            proof,
                            context,
                        )
                        .map_err(|_| VerifyError::Auxiliary)
                    },
                )
            };
        let verify = |candidate_vk: &CombinedDuplexRegionVk,
                      candidate_proof: &CombinedDuplexRegionSidecarProof| {
            verify_with_class(&class_digest, candidate_vk, candidate_proof)
        };
        assert!(verify(&vk, &decoded).is_ok());

        let mut wrong_class = class_digest;
        wrong_class[0] ^= 1;
        assert!(
            verify_with_class(&wrong_class, &vk, &decoded).is_err(),
            "outer post-commit proof class mutation"
        );

        let mut core_only = FsLaneChallenger::new(FIELD_DOMAIN);
        assert!(
            verify_field_with_public_io(
                &r1cs,
                &commitment,
                &field_proof,
                &spec,
                &io,
                &mut core_only,
            )
            .is_err(),
            "sidecar-bearing proof downgraded to the core-only verifier"
        );

        let mut bad_version = decoded.clone();
        bad_version.version = 0;
        assert!(verify(&vk, &bad_version).is_err(), "version downgrade");

        let mut bad_proof = decoded.clone();
        bad_proof.authority.selection.rounds[0][0] += F128::ONE;
        assert!(verify(&vk, &bad_proof).is_err(), "authority mutation");

        let mut bad_layout_digest = vk.clone();
        bad_layout_digest.layout_digest[0] ^= 1;
        assert!(
            verify(&bad_layout_digest, &decoded).is_err(),
            "layout digest mutation"
        );

        let mut bad_slices = vk.clone();
        bad_slices.slices.swap(0, 1);
        assert!(verify(&bad_slices, &decoded).is_err(), "slice mutation");

        let mut reordered_channels = fixture.descriptor.subchannels.clone();
        reordered_channels.swap(0, 1);
        let reordered_vk = CombinedDuplexRegionVk::new(
            purpose,
            CombinedDuplexRegionDescriptor::new(1, reordered_channels).unwrap(),
            slices,
        )
        .unwrap();
        assert!(
            verify(&reordered_vk, &decoded).is_err(),
            "ordered sub-channel schedule mutation"
        );

        let mut changed_iv_descriptor = fixture.descriptor.clone();
        changed_iv_descriptor.subchannels[0].iv_flat[0] += F128::ONE;
        let changed_iv_vk =
            CombinedDuplexRegionVk::new(purpose, changed_iv_descriptor, slices).unwrap();
        assert!(
            verify(&changed_iv_vk, &decoded).is_err(),
            "sub-channel IV mutation"
        );
    }

    #[test]
    fn combined_descriptor_preflight_is_checked_and_bounded() {
        assert_eq!(
            (2 * noid_ivc_core::pcs::basefold::default_fri_queries(17, 1))
                .next_power_of_two()
                .trailing_zeros() as usize,
            MAX_COMBINED_DUPLEX_TX_TILE_LOG,
            "V1 tile ceiling must cover two supported rate-1/2 proofs"
        );
        let valid = CombinedDuplexSubChannelDescriptor::new(
            vec![TranscriptOp::Absorb(vec![None; 2])],
            [F128::ONE, F128::ZERO],
        )
        .unwrap();
        let different = CombinedDuplexSubChannelDescriptor::new(
            vec![TranscriptOp::Absorb(vec![None; 4])],
            [F128::ZERO, F128::ONE],
        )
        .unwrap();
        assert_eq!(
            CombinedDuplexSubChannelDescriptor::new(
                vec![TranscriptOp::Squeeze(usize::MAX)],
                [F128::ZERO; 2],
            ),
            Err(RegionSidecarError::UnsupportedVkShape)
        );
        assert_eq!(
            CombinedDuplexSubChannelDescriptor::new(
                vec![TranscriptOp::Absorb(vec![
                    None;
                    MAX_COMBINED_DUPLEX_DATA_LANES + 1
                ])],
                [F128::ZERO; 2],
            ),
            Err(RegionSidecarError::UnsupportedVkShape)
        );
        assert_eq!(
            CombinedDuplexSubChannelDescriptor::new(
                vec![TranscriptOp::Absorb(vec![Some(7)])],
                [F128::ZERO; 2],
            ),
            Err(RegionSidecarError::UnsupportedVkShape)
        );
        assert_eq!(
            CombinedDuplexRegionDescriptor::new(0, vec![valid.clone()]),
            Err(RegionSidecarError::UnsupportedVkShape)
        );
        assert_eq!(
            CombinedDuplexRegionDescriptor::new(
                MAX_COMBINED_DUPLEX_TX_TILE_LOG + 1,
                vec![valid.clone(), different.clone()],
            ),
            Err(RegionSidecarError::UnsupportedVkShape)
        );
        assert_eq!(
            CombinedDuplexRegionDescriptor::new(
                0,
                vec![valid.clone(); MAX_COMBINED_DUPLEX_SUBCHANNELS + 1],
            ),
            Err(RegionSidecarError::UnsupportedVkShape)
        );

        let mixed = vec![
            TranscriptOp::Absorb(vec![None, None, None]),
            TranscriptOp::Squeeze(3),
            TranscriptOp::Absorb(vec![None, None]),
            TranscriptOp::Squeeze(2),
        ];
        let shape = schedule_shape(&mixed).unwrap();
        let compiled = compile_duplex(&mixed);
        assert_eq!(shape.slots, compiled.slots.len());
        assert_eq!(shape.data_lanes, compiled.n_data);
        assert_eq!(shape.challenges, compiled.challenges.len());

        let descriptor = CombinedDuplexRegionDescriptor::new(0, vec![valid, different]).unwrap();
        let protocol = canonical_protocol(&descriptor).unwrap();
        let mut bad_slices = placeholder_slices(protocol.w_log);
        bad_slices[2].index += 1;
        assert_eq!(
            CombinedDuplexRegionVk::new([0; 32], descriptor, bad_slices),
            Err(RegionSidecarError::BadSlice)
        );
    }

    #[test]
    fn combined_precommit_selection_kernel_fails_after_root_and_vk_binding() {
        let fixture = fixture();
        let vk = CombinedDuplexRegionVk::new(
            [0xC3; 32],
            fixture.descriptor,
            placeholder_slices(fixture.union.w_log),
        )
        .unwrap();
        let refs = duplex_family_refs(0, 0);
        let mut old_prover = FsLaneChallenger::new(b"combined-duplex-precommit-kernel-v0");
        let beta = old_prover.sample_f128();
        let rho = old_prover.sample_f128_vec(vk.w_log());
        let mut delta = vec![F128::ZERO; 1usize << vk.w_log()];
        delta[0] = rho[0];
        delta[1] = F128::ONE + rho[0];
        let eval = delta
            .iter()
            .zip(build_eq_table(&rho))
            .fold(F128::ZERO, |sum, (value, weight)| sum + *value * weight);
        assert_eq!(eval, F128::ZERO);
        assert!(delta.iter().any(|value| *value != F128::ZERO));

        let zero = vec![F128::ZERO; delta.len()];
        let mut committed_owned: [Vec<F128>; COMBINED_DUPLEX_REGION_COMMITTED_COLUMNS] =
            std::array::from_fn(|_| zero.clone());
        committed_owned[refs.c[0]] = delta.clone();
        let committed = committed_owned
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let internal_owned: [Vec<F128>; 4] = std::array::from_fn(|_| zero.clone());
        let internal = internal_owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let terms = carry_selection_terms(&refs.c, beta);
        let (old_proof, _, _) = prove_column_relation(
            F128::ZERO,
            &rho,
            &terms,
            &RelationColumns {
                committed: &committed,
                internal: &internal,
                fixed: &[],
            },
            &mut old_prover,
        );

        let mut old_verifier = FsLaneChallenger::new(b"combined-duplex-precommit-kernel-v0");
        let old_beta = old_verifier.sample_f128();
        let old_rho = old_verifier.sample_f128_vec(vk.w_log());
        assert_eq!(old_beta, beta);
        assert_eq!(old_rho, rho);
        assert!(
            verify_column_relation(
                vk.w_log(),
                F128::ZERO,
                &old_rho,
                &carry_selection_terms(&refs.c, old_beta),
                &[],
                &old_proof,
                &mut old_verifier,
            )
            .is_ok(),
            "old precommit transcript should expose the known-rho kernel"
        );

        let mut postcommit = FsLaneChallenger::new(b"combined-duplex-precommit-kernel-v0");
        postcommit.observe_bytes(b"outer-field-witness-root");
        bind_combined_duplex_vk(&mut postcommit, &vk);
        let post_beta = postcommit.sample_f128();
        let post_rho = postcommit.sample_f128_vec(vk.w_log());
        let post_eval = delta
            .iter()
            .zip(build_eq_table(&post_rho))
            .fold(F128::ZERO, |sum, (value, weight)| sum + *value * weight);
        assert_ne!(post_eval, F128::ZERO);
        assert!(
            verify_column_relation(
                vk.w_log(),
                F128::ZERO,
                &post_rho,
                &carry_selection_terms(&refs.c, post_beta),
                &[],
                &old_proof,
                &mut postcommit,
            )
            .is_err(),
            "precommit kernel proof survived root + combined VK binding"
        );
    }
}
