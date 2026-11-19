// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Post-commit proof authority for committed recursive-region columns.
//!
//! Production HistoryStep uses one joint C1 transcript for its three Link and
//! six Block regions. Every algebraic challenge and proof message is in
//! GF(2^256). The nine region prefixes share one ragged deep-chain walk, Block
//! completes on its derived child channel, and Link completes only after the
//! child terminal is absorbed back into the outer FieldR1cs post-commit
//! channel. The resulting terminal evaluations are appended to the same outer
//! PCS batch.
//!
//! The serialized proof contains only algebraic proof authority. It never
//! carries a prover-authored list of pending openings: the verifier derives
//! every [`QuirkyDirectClaim`] from the canonical VK column slices and the
//! replayed relation endpoints.

use noid_ivc_core::challenger::Challenger;
use noid_ivc_core::deep_chain::c1::C1LaneClaimGroup;
use noid_ivc_core::deep_chain::ff_merkle::{ff_merkle_fixed_patterns, FfMerklePathFamily};
use noid_ivc_core::deep_chain::relations::FixedPattern;
use noid_ivc_core::deep_chain::schedule::{
    duplex_family_refs, duplex_fixed_patterns, merkle_fixed_patterns, DuplexFamilyRefs,
    DuplexLayout, LaneSource, MerklePathFamily,
};
use noid_ivc_core::field::{F128, F256};
use noid_ivc_core::pcs::{C1QuirkyDirectClaim, QuirkyDirectClaim};
use noid_ivc_core::public_io::WitnessSlice;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

use crate::acceptance::trace::paired_merkle_update::{
    paired_merkle_update_fixed_patterns, PAIRED_UPDATE_STRIDE,
};
use crate::acceptance::trace::region_source_binding::{
    common_period_ones, common_period_pattern, prove_duplex_union_with_challenger,
    prove_merkle_union_with_challenger, verify_duplex_union_with_challenger,
    verify_merkle_union_with_challenger, DuplexColumnClaim, DuplexUnion, DuplexUnionProof,
    MerkleColumnClaim, MerkleProtocolFamily, MerkleUnionProof,
};
use crate::acceptance::trace::region_source_binding_c1::{
    prove_c1_duplex_walk_prefix, prove_c1_duplex_walk_suffix, prove_c1_merkle_walk_prefix,
    prove_c1_merkle_walk_suffix, verify_c1_duplex_walk_prefix, verify_c1_duplex_walk_suffix,
    verify_c1_merkle_walk_prefix, verify_c1_merkle_walk_suffix, C1DuplexColumnClaim,
    C1DuplexProverWalkPrefix, C1DuplexUnionWalkDeferredProof, C1DuplexVerifierWalkPrefix,
    C1MerkleColumnClaim, C1MerkleProverWalkPrefix, C1MerkleUnionWalkDeferredProof,
    C1MerkleVerifierWalkPrefix,
};

mod block;
pub use block::*;
mod bounded_decode;
mod canonical_codec;
mod joint_c1;
pub use bounded_decode::*;
pub(crate) use joint_c1::*;
mod link;
pub use link::*;
mod merkle_trace;
pub use merkle_trace::*;
mod combined_duplex;
pub use combined_duplex::*;
mod recording_duplex;
pub use recording_duplex::*;
mod trace;
pub use trace::*;
mod walk_a;
pub use walk_a::*;

pub const DUPLEX_REGION_SIDECAR_VERSION: u8 = 1;
pub const DUPLEX_REGION_COMMITTED_COLUMNS: usize = 6;
pub const MERKLE_REGION_SIDECAR_VERSION: u8 = 2;
pub const MERKLE_REGION_COMMITTED_COLUMNS: usize = 9;
/// Number of Link claim groups in the production joint C1 History walk.
pub const JOINT_C1_LINK_GROUPS: usize = 3;
/// Number of Block claim groups in the production joint C1 History walk.
pub const JOINT_C1_BLOCK_GROUPS: usize = 6;
/// Total claim groups sharing each joint C1 deep-chain batching challenge.
pub const JOINT_C1_GROUPS: usize = JOINT_C1_LINK_GROUPS + JOINT_C1_BLOCK_GROUPS;
pub const MAX_MERKLE_PATTERN_LOG: usize = 20;
const MAX_MERKLE_FAMILIES: usize = 64;
const MAX_MERKLE_FIXED_CELLS: usize = 1 << 22;

const DUPLEX_LAYOUT_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/DUPLEX-LAYOUT/V1";
const DUPLEX_VK_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/DUPLEX-VK/V1";
const DUPLEX_SIDECAR_TRANSCRIPT_LABEL: &[u8] = b"history-region-sidecar-duplex-v1";
const MERKLE_LAYOUT_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/MERKLE-LAYOUT/V1";
const MERKLE_VK_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/MERKLE-VK/V1";
const MERKLE_SIDECAR_TRANSCRIPT_LABEL: &[u8] = b"history-region-sidecar-merkle-v1";

/// Canonical verification key for a V1 duplex sidecar.
///
/// `slices[i]` is the exact dyadic slice of outer witness elements holding
/// committed duplex column `i` (`A0,A1,C0..C3`). V1 accepts exactly the
/// canonical refs `duplex_family_refs(0,0)` and one ungated seven-pattern set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplexRegionVk {
    purpose: [u8; 32],
    w_log: usize,
    slices: [WitnessSlice; DUPLEX_REGION_COMMITTED_COLUMNS],
    fixed: Vec<FixedPattern>,
    refs: DuplexFamilyRefs,
    layout_digest: [u8; 32],
}

impl DuplexRegionVk {
    pub fn new(
        purpose: [u8; 32],
        w_log: usize,
        slices: [WitnessSlice; DUPLEX_REGION_COMMITTED_COLUMNS],
        fixed: Vec<FixedPattern>,
        refs: DuplexFamilyRefs,
        layout: &DuplexLayout,
    ) -> Result<Self, RegionSidecarError> {
        let vk = Self {
            purpose,
            w_log,
            slices,
            fixed,
            refs,
            layout_digest: duplex_compiled_layout_digest(layout, w_log),
        };
        vk.validate_structure()?;
        let block_log = layout
            .slots
            .len()
            .max(1)
            .next_power_of_two()
            .trailing_zeros() as usize;
        if w_log < block_log {
            return Err(RegionSidecarError::BadVk);
        }
        let iv = [
            vk.fixed[vk.refs.consts[2]].table[0],
            vk.fixed[vk.refs.consts[3]].table[0],
        ];
        if vk.fixed != duplex_fixed_patterns(layout, iv, block_log) {
            return Err(RegionSidecarError::BadVk);
        }
        Ok(vk)
    }

    /// Internal bridge for an assembled, recording-free duplex union.
    /// Recording-bearing unions are rejected rather than silently treating
    /// post-root transcript recordings as ordinary fixed patterns.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_union(
        purpose: [u8; 32],
        slices: [WitnessSlice; DUPLEX_REGION_COMMITTED_COLUMNS],
        union: &DuplexUnion,
    ) -> Result<Self, RegionSidecarError> {
        if !union.rec_refs.is_empty() || !union.rec_blocks.is_empty() {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        if union.fixed.len() != 7 || union.refs != duplex_family_refs(0, 0) {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let iv = [
            union.fixed[union.refs.consts[2]].table[0],
            union.fixed[union.refs.consts[3]].table[0],
        ];
        let canonical_block_log = union
            .layout
            .slots
            .len()
            .max(1)
            .next_power_of_two()
            .trailing_zeros() as usize;
        if union.block_log != canonical_block_log
            || union.w_log < union.block_log
            || union.fixed != duplex_fixed_patterns(&union.layout, iv, canonical_block_log)
        {
            return Err(RegionSidecarError::BadVk);
        }
        let vk = Self {
            purpose,
            w_log: union.w_log,
            slices,
            fixed: union.fixed.clone(),
            refs: union.refs,
            layout_digest: duplex_compiled_layout_digest(&union.layout, union.w_log),
        };
        vk.validate_structure()?;
        Ok(vk)
    }

    pub fn purpose(&self) -> &[u8; 32] {
        &self.purpose
    }

    pub fn w_log(&self) -> usize {
        self.w_log
    }

    pub fn slices(&self) -> &[WitnessSlice; DUPLEX_REGION_COMMITTED_COLUMNS] {
        &self.slices
    }

    pub fn fixed(&self) -> &[FixedPattern] {
        &self.fixed
    }

    pub fn refs(&self) -> DuplexFamilyRefs {
        self.refs
    }

    pub fn layout_digest(&self) -> &[u8; 32] {
        &self.layout_digest
    }

    /// Stable digest absorbed by both post-commit replays.  It binds the
    /// purpose, exact outer slices, fixed patterns, refs and compiled-layout
    /// digest without relying on a platform-dependent serde encoding.
    pub fn transcript_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.purpose);
        push_usize(&mut bytes, self.w_log);
        for slice in self.slices {
            push_usize(&mut bytes, slice.log2_len);
            push_usize(&mut bytes, slice.index);
        }
        push_usize(&mut bytes, self.fixed.len());
        for pattern in &self.fixed {
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
        encode_refs(&mut bytes, &self.refs);
        bytes.extend_from_slice(&self.layout_digest);
        poseidon2b_hash_byte_slices(DUPLEX_VK_DIGEST_DOMAIN, &[&bytes])
    }

    fn validate_structure(&self) -> Result<(), RegionSidecarError> {
        if self.w_log == 0 || self.w_log >= usize::BITS as usize {
            return Err(RegionSidecarError::BadVk);
        }
        if self.fixed.len() != 7 || self.refs != duplex_family_refs(0, 0) {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let base = self.slices[0].index;
        for (column, slice) in self.slices.into_iter().enumerate() {
            if slice.log2_len != self.w_log {
                return Err(RegionSidecarError::BadSlice);
            }
            if slice.index
                != base
                    .checked_add(column)
                    .ok_or(RegionSidecarError::BadSlice)?
            {
                return Err(RegionSidecarError::BadSlice);
            }
        }
        for pattern in &self.fixed {
            if pattern.low_log > self.w_log
                || pattern.table.len() != (1usize << pattern.low_log)
                || pattern.hi_gate.is_some()
            {
                return Err(RegionSidecarError::UnsupportedVkShape);
            }
        }
        Ok(())
    }

    fn validate_in_witness(&self, total_vars: usize) -> Result<(), RegionSidecarError> {
        self.validate_structure()?;
        if self.slices.iter().any(|slice| !slice.fits(total_vars)) {
            return Err(RegionSidecarError::BadSlice);
        }
        Ok(())
    }

    /// Per-proof C1 witness gate for a key authenticated by `new` or
    /// `from_union`. The immutable layout and fixed bank are constructor
    /// invariants; only the enclosing witness width varies between proofs.
    fn validate_certified_c1_in_witness(
        &self,
        total_vars: usize,
    ) -> Result<(), RegionSidecarError> {
        if self.slices.iter().any(|slice| !slice.fits(total_vars)) {
            return Err(RegionSidecarError::BadSlice);
        }
        Ok(())
    }
}

/// Prover-only inputs not carried by the sidecar proof: layer-0 and layer-66
/// walk columns.  The six committed columns are never supplied separately;
/// they are read from `z` through the VK's exact slices.
pub struct DuplexRegionProverPlan<'a> {
    vk: &'a DuplexRegionVk,
    s0: &'a [Vec<F128>; 4],
    s_out: &'a [Vec<F128>; 4],
}

impl<'a> DuplexRegionProverPlan<'a> {
    pub fn new(
        vk: &'a DuplexRegionVk,
        s0: &'a [Vec<F128>; 4],
        s_out: &'a [Vec<F128>; 4],
    ) -> Result<Self, RegionSidecarError> {
        vk.validate_structure()?;
        let expected = 1usize << vk.w_log;
        if s0.iter().any(|column| column.len() != expected)
            || s_out.iter().any(|column| column.len() != expected)
        {
            return Err(RegionSidecarError::BadWalkColumns);
        }
        Ok(Self { vk, s0, s_out })
    }

    fn new_certified_c1(
        vk: &'a DuplexRegionVk,
        s0: &'a [Vec<F128>; 4],
        s_out: &'a [Vec<F128>; 4],
    ) -> Result<Self, RegionSidecarError> {
        validate_c1_endpoint_lengths(vk.w_log, s0, s_out)?;
        Ok(Self { vk, s0, s_out })
    }

    /// Run inside `prove_field_with_public_io_and_post_commit` on its passed
    /// challenger.  Calling this before the outer commitment is unsound and is
    /// intentionally not exposed through a challenger-constructing shortcut.
    pub fn prove<Ch: Challenger>(
        &self,
        z: &[F128],
        challenger: &mut Ch,
    ) -> Result<(DuplexRegionSidecarProof, Vec<QuirkyDirectClaim>), RegionSidecarError> {
        let total_vars = witness_log(z)?;
        self.vk.validate_in_witness(total_vars)?;
        let committed: [&[F128]; DUPLEX_REGION_COMMITTED_COLUMNS] = std::array::from_fn(|column| {
            let slice = self.vk.slices[column];
            &z[slice.start()..slice.start() + slice.len()]
        });

        bind_vk(challenger, self.vk);
        let (authority, terminal) = prove_duplex_union_with_challenger(
            self.vk.w_log,
            &self.vk.fixed,
            &self.vk.refs,
            &[],
            &committed,
            self.s0,
            self.s_out,
            challenger,
        );
        let claims = resolve_terminal_claims(self.vk, total_vars, terminal)?;
        Ok((
            DuplexRegionSidecarProof {
                version: DUPLEX_REGION_SIDECAR_VERSION,
                authority,
            },
            claims,
        ))
    }
}

pub(crate) struct C1DuplexRegionProverWalkContinuation<'a, 'z> {
    vk: &'a DuplexRegionVk,
    total_vars: usize,
    committed: [&'z [F128]; DUPLEX_REGION_COMMITTED_COLUMNS],
    s0: &'a [Vec<F128>; 4],
    prefix: C1DuplexProverWalkPrefix,
}

impl C1DuplexRegionProverWalkContinuation<'_, '_> {
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
    ) -> Result<(C1DuplexRegionWalkDeferredProof, Vec<C1QuirkyDirectClaim>), RegionSidecarError>
    {
        let (authority, terminal_claims) = prove_c1_duplex_walk_suffix(
            self.vk.w_log,
            &self.vk.fixed,
            &self.vk.refs,
            &[],
            &self.committed,
            self.prefix,
            terminal,
            challenger,
        );
        let claims = resolve_c1_terminal_claims(self.vk, self.total_vars, terminal_claims)?;
        Ok((C1DuplexRegionWalkDeferredProof::new(authority), claims))
    }
}

pub(crate) struct C1DuplexRegionVerifierWalkContinuation<'a> {
    vk: &'a DuplexRegionVk,
    total_vars: usize,
    prefix: C1DuplexVerifierWalkPrefix<'a>,
}

impl C1DuplexRegionVerifierWalkContinuation<'_> {
    pub(crate) fn group(&self) -> &C1LaneClaimGroup {
        self.prefix.walk_group()
    }

    pub(crate) fn finish<Ch: Challenger>(
        self,
        terminal: &C1LaneClaimGroup,
        challenger: &mut Ch,
    ) -> Result<Vec<C1QuirkyDirectClaim>, RegionSidecarError> {
        let terminal_claims = verify_c1_duplex_walk_suffix(
            self.vk.w_log,
            &self.vk.fixed,
            &self.vk.refs,
            &[],
            self.prefix,
            terminal,
            challenger,
        )
        .map_err(|_| RegionSidecarError::InvalidProof)?;
        resolve_c1_terminal_claims(self.vk, self.total_vars, terminal_claims)
    }
}

impl<'a> DuplexRegionProverPlan<'a> {
    pub(crate) fn prove_c1_walk_deferred_prefix<'z, Ch: Challenger>(
        &self,
        z: &'z [F128],
        challenger: &mut Ch,
    ) -> Result<C1DuplexRegionProverWalkContinuation<'a, 'z>, RegionSidecarError> {
        let total_vars = witness_log(z)?;
        self.vk.validate_certified_c1_in_witness(total_vars)?;
        let committed: [&[F128]; DUPLEX_REGION_COMMITTED_COLUMNS] = std::array::from_fn(|column| {
            let slice = self.vk.slices[column];
            &z[slice.start()..slice.start() + slice.len()]
        });
        bind_vk(challenger, self.vk);
        let prefix = prove_c1_duplex_walk_prefix(
            self.vk.w_log,
            &self.vk.fixed,
            &self.vk.refs,
            &committed,
            self.s_out,
            challenger,
        );
        Ok(C1DuplexRegionProverWalkContinuation {
            vk: self.vk,
            total_vars,
            committed,
            s0: self.s0,
            prefix,
        })
    }
}

/// Serializable duplex proof authority.  There is no pending-descriptor field:
/// terminal PCS claims exist only as verifier replay output.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DuplexRegionSidecarProof {
    version: u8,
    authority: DuplexUnionProof,
}

impl DuplexRegionSidecarProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("duplex sidecar serialized length") as usize
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct C1DuplexRegionWalkDeferredProof {
    version: u8,
    authority: C1DuplexUnionWalkDeferredProof,
}

impl C1DuplexRegionWalkDeferredProof {
    pub(crate) fn new(authority: C1DuplexUnionWalkDeferredProof) -> Self {
        Self {
            version: DUPLEX_REGION_SIDECAR_VERSION,
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

pub(crate) fn verify_c1_duplex_region_walk_deferred_prefix<'a, Ch: Challenger>(
    vk: &'a DuplexRegionVk,
    total_vars: usize,
    proof: &'a C1DuplexRegionWalkDeferredProof,
    challenger: &mut Ch,
) -> Result<C1DuplexRegionVerifierWalkContinuation<'a>, RegionSidecarError> {
    let timing = std::env::var_os("NOIDH_C1_VERIFY_TIMING").is_some();
    let total_started = std::time::Instant::now();
    vk.validate_in_witness(total_vars)?;
    let validate_micros = total_started.elapsed().as_micros();
    if proof.version != DUPLEX_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    bind_vk(challenger, vk);
    let bind_micros = total_started.elapsed().as_micros() - validate_micros;
    let prefix_started = std::time::Instant::now();
    let prefix = verify_c1_duplex_walk_prefix(
        vk.w_log,
        &vk.fixed,
        &vk.refs,
        proof.authority.as_ref(),
        challenger,
    )
    .map_err(|_| RegionSidecarError::InvalidProof)?;
    if timing {
        eprintln!(
            "[duplex-c1 prefix] w_log={} validate_us={validate_micros} bind_us={bind_micros} proof_us={} total_us={}",
            vk.w_log,
            prefix_started.elapsed().as_micros(),
            total_started.elapsed().as_micros(),
        );
    }
    Ok(C1DuplexRegionVerifierWalkContinuation {
        vk,
        total_vars,
        prefix,
    })
}

/// Replay a V1 duplex sidecar inside
/// `verify_field_with_public_io_and_post_commit` (or its deferred-matrix twin).
/// The returned claims are resolved solely through the VK's six exact slices.
pub fn verify_duplex_region_sidecar<Ch: Challenger>(
    vk: &DuplexRegionVk,
    total_vars: usize,
    proof: &DuplexRegionSidecarProof,
    challenger: &mut Ch,
) -> Result<Vec<QuirkyDirectClaim>, RegionSidecarError> {
    vk.validate_in_witness(total_vars)?;
    if proof.version != DUPLEX_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    bind_vk(challenger, vk);
    let terminal = verify_duplex_union_with_challenger(
        vk.w_log,
        &vk.fixed,
        &vk.refs,
        &[],
        &proof.authority,
        challenger,
    )
    .map_err(|_| RegionSidecarError::InvalidProof)?;
    resolve_terminal_claims(vk, total_vars, terminal)
}

/// Ordered canonical relation families in a Walk-B sidecar.
///
/// Each variant has one fixed pattern group followed by its exact region
/// selector: 5+1 patterns for feed-forward, 8+1 for two-permutation, and
/// 11+1 for paired-update.  The shared nine committed refs are implicit and
/// reconstructed by the verifier from this order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleRegionFamily {
    FeedForward {
        offset: usize,
        depth: usize,
        n_paths: usize,
        iv: [F128; 2],
    },
    /// Feed-forward paths whose active nodes occupy a fixed caller-selected
    /// stride. This represents disjoint packed families such as the selected
    /// authorization layout's `10 + 6` nodes inside each 16-slot query tile.
    /// No root-copy padding slot is enabled; the final feed-forward root is
    /// linked from the last active node by the caller's composite-root trace.
    FeedForwardStrided {
        offset: usize,
        depth: usize,
        n_paths: usize,
        stride: usize,
        iv: [F128; 2],
    },
    TwoPermutation {
        offset: usize,
        depth: usize,
        n_paths: usize,
        iv: [F128; 2],
    },
    TwoPermutationStrided {
        offset: usize,
        depth: usize,
        n_paths: usize,
        stride: usize,
        iv: [F128; 2],
    },
    PairedUpdate {
        offset: usize,
        n_updates: usize,
        iv: [F128; 2],
    },
}

impl MerkleRegionFamily {
    pub(crate) fn proof_nodes(
        version: noid_poseidon2b::native::ProofNodeHashVersion,
        offset: usize,
        depth: usize,
        n_paths: usize,
        stride: usize,
        iv: [F128; 2],
    ) -> Self {
        match version {
            noid_poseidon2b::native::ProofNodeHashVersion::FeedForward => {
                Self::FeedForwardStrided {
                    offset,
                    depth,
                    n_paths,
                    stride,
                    iv,
                }
            }
            noid_poseidon2b::native::ProofNodeHashVersion::FixedCapacity => {
                Self::TwoPermutationStrided {
                    offset,
                    depth,
                    n_paths,
                    stride,
                    iv,
                }
            }
        }
    }

    fn fixed_len(self) -> usize {
        match self {
            Self::FeedForward { .. } | Self::FeedForwardStrided { .. } => 6,
            Self::TwoPermutation { .. } | Self::TwoPermutationStrided { .. } => 9,
            Self::PairedUpdate { .. } => 12,
        }
    }

    fn protocol(self, fixed_base: usize) -> MerkleProtocolFamily {
        match self {
            Self::FeedForward { .. } | Self::FeedForwardStrided { .. } => {
                MerkleProtocolFamily::feed_forward(fixed_base)
            }
            Self::TwoPermutation { .. } | Self::TwoPermutationStrided { .. } => {
                MerkleProtocolFamily::two_permutation(fixed_base)
            }
            Self::PairedUpdate { .. } => MerkleProtocolFamily::paired_update(fixed_base),
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::FeedForward { .. } => 0,
            Self::TwoPermutation { .. } => 1,
            Self::PairedUpdate { .. } => 2,
            Self::FeedForwardStrided { .. } => 3,
            Self::TwoPermutationStrided { .. } => 4,
        }
    }

    fn geometry(self) -> Option<(usize, usize)> {
        match self {
            Self::FeedForward {
                offset,
                depth,
                n_paths,
                ..
            } => {
                let stride = depth.checked_next_power_of_two()?;
                Some((offset, n_paths.checked_mul(stride)?))
            }
            Self::FeedForwardStrided {
                offset,
                depth,
                n_paths,
                stride,
                ..
            } => {
                if depth == 0 || n_paths == 0 || stride < depth {
                    return None;
                }
                let span = (n_paths - 1).checked_mul(stride)?.checked_add(depth)?;
                Some((offset, span))
            }
            Self::TwoPermutationStrided {
                offset,
                depth,
                n_paths,
                stride,
                ..
            } => {
                let active = depth.checked_mul(2)?;
                if depth == 0 || n_paths == 0 || stride < active {
                    return None;
                }
                Some((
                    offset,
                    (n_paths - 1).checked_mul(stride)?.checked_add(active)?,
                ))
            }
            Self::TwoPermutation {
                offset,
                depth,
                n_paths,
                ..
            } => {
                let twice_depth = depth.checked_mul(2)?;
                let stride = twice_depth.checked_next_power_of_two()?;
                Some((offset, n_paths.checked_mul(stride)?))
            }
            Self::PairedUpdate {
                offset, n_updates, ..
            } => Some((offset, n_updates.checked_mul(PAIRED_UPDATE_STRIDE)?)),
        }
    }

    fn canonical_fixed(self, block_log: usize) -> Option<Vec<FixedPattern>> {
        let (offset, active_slots) = self.geometry()?;
        if let Self::TwoPermutationStrided {
            depth,
            n_paths,
            stride,
            iv,
            ..
        } = self
        {
            let active = depth.checked_mul(2)?;
            let block = 1usize.checked_shl(block_log as u32)?;
            let mut fixed = merkle_fixed_patterns(&MerklePathFamily { depth, n_paths: 1 }, iv)
                .into_iter()
                .map(|pattern| {
                    let mut table = vec![F128::ZERO; block];
                    for path in 0..n_paths {
                        let start = offset + path * stride;
                        table[start..start + active].copy_from_slice(&pattern.table[..active]);
                    }
                    FixedPattern::new(block_log, table)
                })
                .collect::<Vec<_>>();
            let mut region = vec![F128::ZERO; block];
            for path in 0..n_paths {
                let start = offset + path * stride;
                region[start..start + active].fill(F128::ONE);
            }
            fixed.push(FixedPattern::new(block_log, region));
            return Some(fixed);
        }
        if let Self::FeedForwardStrided {
            depth,
            n_paths,
            stride,
            iv,
            ..
        } = self
        {
            let family = FfMerklePathFamily { depth, n_paths: 1 };
            let block = 1usize.checked_shl(block_log as u32)?;
            let mut fixed = ff_merkle_fixed_patterns(&family, iv)
                .into_iter()
                .map(|pattern| {
                    let mut table = vec![F128::ZERO; block];
                    for path in 0..n_paths {
                        let start = offset + path * stride;
                        table[start..start + depth].copy_from_slice(&pattern.table[..depth]);
                    }
                    FixedPattern::new(block_log, table)
                })
                .collect::<Vec<_>>();
            let mut region = vec![F128::ZERO; block];
            for path in 0..n_paths {
                let start = offset + path * stride;
                region[start..start + depth].fill(F128::ONE);
            }
            fixed.push(FixedPattern::new(block_log, region));
            return Some(fixed);
        }
        let mut fixed = match self {
            Self::FeedForward {
                depth, n_paths, iv, ..
            } => {
                let family = FfMerklePathFamily { depth, n_paths };
                ff_merkle_fixed_patterns(&family, iv)
                    .into_iter()
                    .map(|pattern| {
                        common_period_pattern(&pattern.table, offset, n_paths, block_log)
                    })
                    .collect::<Vec<_>>()
            }
            Self::TwoPermutation {
                depth, n_paths, iv, ..
            } => {
                let family = MerklePathFamily { depth, n_paths };
                merkle_fixed_patterns(&family, iv)
                    .into_iter()
                    .map(|pattern| {
                        common_period_pattern(&pattern.table, offset, n_paths, block_log)
                    })
                    .collect::<Vec<_>>()
            }
            Self::PairedUpdate { n_updates, iv, .. } => paired_merkle_update_fixed_patterns(iv)
                .into_iter()
                .map(|pattern| common_period_pattern(&pattern.table, offset, n_updates, block_log))
                .collect::<Vec<_>>(),
            Self::FeedForwardStrided { .. } | Self::TwoPermutationStrided { .. } => {
                unreachable!("handled above")
            }
        };
        fixed.push(common_period_ones(offset, active_slots, block_log));
        Some(fixed)
    }

    fn encode(self, bytes: &mut Vec<u8>) {
        bytes.push(self.tag());
        match self {
            Self::FeedForward {
                offset,
                depth,
                n_paths,
                iv,
            }
            | Self::TwoPermutation {
                offset,
                depth,
                n_paths,
                iv,
            } => {
                push_usize(bytes, offset);
                push_usize(bytes, depth);
                push_usize(bytes, n_paths);
                for value in iv {
                    push_f128(bytes, value);
                }
            }
            Self::FeedForwardStrided {
                offset,
                depth,
                n_paths,
                stride,
                iv,
            }
            | Self::TwoPermutationStrided {
                offset,
                depth,
                n_paths,
                stride,
                iv,
            } => {
                push_usize(bytes, offset);
                push_usize(bytes, depth);
                push_usize(bytes, n_paths);
                push_usize(bytes, stride);
                for value in iv {
                    push_f128(bytes, value);
                }
            }
            Self::PairedUpdate {
                offset,
                n_updates,
                iv,
            } => {
                push_usize(bytes, offset);
                push_usize(bytes, n_updates);
                for value in iv {
                    push_f128(bytes, value);
                }
            }
        }
    }
}

/// Canonical verification key for a recording-free V1 Walk-B sidecar.
///
/// The fixed tables are part of the trusted key, not prover data.  Their
/// ordered family groups determine all fixed refs and the shared committed
/// refs.  Consequently neither refs nor opening descriptors appear in the
/// serialized proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleRegionVk {
    purpose: [u8; 32],
    w_log: usize,
    block_log: usize,
    slices: [WitnessSlice; MERKLE_REGION_COMMITTED_COLUMNS],
    fixed: Vec<FixedPattern>,
    families: Vec<MerkleRegionFamily>,
    layout_digest: [u8; 32],
}

impl MerkleRegionVk {
    pub fn new(
        purpose: [u8; 32],
        w_log: usize,
        slices: [WitnessSlice; MERKLE_REGION_COMMITTED_COLUMNS],
        block_log: usize,
        families: Vec<MerkleRegionFamily>,
    ) -> Result<Self, RegionSidecarError> {
        preflight_merkle_layout(w_log, block_log, &families)?;
        let fixed = canonical_merkle_fixed(block_log, &families)?;
        let layout_digest = merkle_layout_digest(w_log, block_log, &fixed, &families);
        let vk = Self {
            purpose,
            w_log,
            block_log,
            slices,
            fixed,
            families,
            layout_digest,
        };
        vk.validate_structure()?;
        Ok(vk)
    }

    /// Production bridge for an already assembled Walk-B union.  The raw
    /// tables are accepted only if they exactly equal the descriptor-derived
    /// canonical tables.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_fixed(
        purpose: [u8; 32],
        w_log: usize,
        slices: [WitnessSlice; MERKLE_REGION_COMMITTED_COLUMNS],
        block_log: usize,
        families: Vec<MerkleRegionFamily>,
        fixed: &[FixedPattern],
    ) -> Result<Self, RegionSidecarError> {
        let vk = Self::new(purpose, w_log, slices, block_log, families)?;
        if vk.fixed != fixed {
            return Err(RegionSidecarError::BadVk);
        }
        Ok(vk)
    }

    pub fn purpose(&self) -> &[u8; 32] {
        &self.purpose
    }

    pub fn w_log(&self) -> usize {
        self.w_log
    }

    pub fn block_log(&self) -> usize {
        self.block_log
    }

    pub fn slices(&self) -> &[WitnessSlice; MERKLE_REGION_COMMITTED_COLUMNS] {
        &self.slices
    }

    pub fn fixed(&self) -> &[FixedPattern] {
        &self.fixed
    }

    pub fn families(&self) -> &[MerkleRegionFamily] {
        &self.families
    }

    pub fn layout_digest(&self) -> &[u8; 32] {
        &self.layout_digest
    }

    /// Stable digest bound into the already post-commit outer transcript.
    pub fn transcript_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.push(MERKLE_REGION_SIDECAR_VERSION);
        bytes.extend_from_slice(&self.purpose);
        push_usize(&mut bytes, self.w_log);
        for slice in self.slices {
            push_usize(&mut bytes, slice.log2_len);
            push_usize(&mut bytes, slice.index);
        }
        bytes.extend_from_slice(&self.layout_digest);
        poseidon2b_hash_byte_slices(MERKLE_VK_DIGEST_DOMAIN, &[&bytes])
    }

    fn protocol_families(&self) -> Vec<MerkleProtocolFamily> {
        let mut fixed_base = 0usize;
        self.families
            .iter()
            .map(|family| {
                let protocol = family.protocol(fixed_base);
                fixed_base += family.fixed_len();
                protocol
            })
            .collect()
    }

    fn validate_structure(&self) -> Result<(), RegionSidecarError> {
        preflight_merkle_layout(self.w_log, self.block_log, &self.families)?;
        if self.families.iter().any(|family| {
            matches!(
                family,
                MerkleRegionFamily::TwoPermutation { .. }
                    | MerkleRegionFamily::TwoPermutationStrided { .. }
                    | MerkleRegionFamily::PairedUpdate { .. }
            ) && self.w_log <= 1
        }) {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let canonical = canonical_merkle_fixed(self.block_log, &self.families)?;
        if self.fixed != canonical
            || self.layout_digest
                != merkle_layout_digest(self.w_log, self.block_log, &self.fixed, &self.families)
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }

        let base = self.slices[0].index;
        for (column, slice) in self.slices.into_iter().enumerate() {
            if slice.log2_len != self.w_log {
                return Err(RegionSidecarError::BadSlice);
            }
            if slice.index
                != base
                    .checked_add(column)
                    .ok_or(RegionSidecarError::BadSlice)?
            {
                return Err(RegionSidecarError::BadSlice);
            }
        }
        Ok(())
    }

    fn validate_in_witness(&self, total_vars: usize) -> Result<(), RegionSidecarError> {
        self.validate_structure()?;
        if self.slices.iter().any(|slice| !slice.fits(total_vars)) {
            return Err(RegionSidecarError::BadSlice);
        }
        Ok(())
    }

    /// Witness-width gate for the per-proof C1 path. `MerkleRegionVk` has no
    /// public raw-field constructor: `new` authenticates the complete fixed
    /// bank and layout before this value can exist.
    fn validate_certified_c1_in_witness(
        &self,
        total_vars: usize,
    ) -> Result<(), RegionSidecarError> {
        if self.slices.iter().any(|slice| !slice.fits(total_vars)) {
            return Err(RegionSidecarError::BadSlice);
        }
        Ok(())
    }
}

/// Prover-only Walk-B endpoints.  The committed columns are read exclusively
/// from the outer witness using the exact VK slices.
pub struct MerkleRegionProverPlan<'a> {
    vk: &'a MerkleRegionVk,
    s0: &'a [Vec<F128>; 4],
    s_out: &'a [Vec<F128>; 4],
}

impl<'a> MerkleRegionProverPlan<'a> {
    pub fn new(
        vk: &'a MerkleRegionVk,
        s0: &'a [Vec<F128>; 4],
        s_out: &'a [Vec<F128>; 4],
    ) -> Result<Self, RegionSidecarError> {
        vk.validate_structure()?;
        let expected = 1usize << vk.w_log;
        if s0.iter().any(|column| column.len() != expected)
            || s_out.iter().any(|column| column.len() != expected)
        {
            return Err(RegionSidecarError::BadWalkColumns);
        }
        Ok(Self { vk, s0, s_out })
    }

    /// Must run inside the enclosing FieldR1cs post-commit callback, using its
    /// exact challenger state.
    pub fn prove<Ch: Challenger>(
        &self,
        z: &[F128],
        challenger: &mut Ch,
    ) -> Result<(MerkleRegionSidecarProof, Vec<QuirkyDirectClaim>), RegionSidecarError> {
        let total_vars = witness_log(z)?;
        self.vk.validate_in_witness(total_vars)?;
        let committed: [&[F128]; MERKLE_REGION_COMMITTED_COLUMNS] = std::array::from_fn(|column| {
            let slice = self.vk.slices[column];
            &z[slice.start()..slice.start() + slice.len()]
        });
        let families = self.vk.protocol_families();
        bind_merkle_vk(challenger, self.vk);
        let (authority, terminal) = prove_merkle_union_with_challenger(
            self.vk.w_log,
            &self.vk.fixed,
            &[0, 1, 2, 3],
            &families,
            &committed,
            self.s0,
            self.s_out,
            challenger,
        );
        let claims = resolve_merkle_terminal_claims(self.vk, total_vars, terminal)?;
        Ok((
            MerkleRegionSidecarProof {
                version: MERKLE_REGION_SIDECAR_VERSION,
                authority,
            },
            claims,
        ))
    }
}

pub(crate) struct C1MerkleRegionProverWalkContinuation<'a, 'z> {
    vk: &'a MerkleRegionVk,
    total_vars: usize,
    committed: [&'z [F128]; MERKLE_REGION_COMMITTED_COLUMNS],
    families: Vec<MerkleProtocolFamily>,
    s0: &'a [Vec<F128>; 4],
    prefix: C1MerkleProverWalkPrefix,
}

impl C1MerkleRegionProverWalkContinuation<'_, '_> {
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
    ) -> Result<(C1MerkleRegionWalkDeferredProof, Vec<C1QuirkyDirectClaim>), RegionSidecarError>
    {
        let (authority, terminal_claims) = prove_c1_merkle_walk_suffix(
            self.vk.w_log,
            &self.vk.fixed,
            &self.families,
            &self.committed,
            self.prefix,
            terminal,
            challenger,
        );
        let claims = resolve_c1_merkle_terminal_claims(self.vk, self.total_vars, terminal_claims)?;
        Ok((C1MerkleRegionWalkDeferredProof::new(authority), claims))
    }
}

pub(crate) struct C1MerkleRegionVerifierWalkContinuation<'a> {
    vk: &'a MerkleRegionVk,
    total_vars: usize,
    families: Vec<MerkleProtocolFamily>,
    prefix: C1MerkleVerifierWalkPrefix<'a>,
}

impl C1MerkleRegionVerifierWalkContinuation<'_> {
    pub(crate) fn group(&self) -> &C1LaneClaimGroup {
        self.prefix.walk_group()
    }

    pub(crate) fn finish<Ch: Challenger>(
        self,
        terminal: &C1LaneClaimGroup,
        challenger: &mut Ch,
    ) -> Result<Vec<C1QuirkyDirectClaim>, RegionSidecarError> {
        let terminal_claims = verify_c1_merkle_walk_suffix(
            self.vk.w_log,
            &self.vk.fixed,
            &self.families,
            self.prefix,
            terminal,
            challenger,
        )
        .map_err(|_| RegionSidecarError::InvalidProof)?;
        resolve_c1_merkle_terminal_claims(self.vk, self.total_vars, terminal_claims)
    }
}

impl<'a> MerkleRegionProverPlan<'a> {
    fn new_certified_c1(
        vk: &'a MerkleRegionVk,
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
    ) -> Result<C1MerkleRegionProverWalkContinuation<'a, 'z>, RegionSidecarError> {
        let total_vars = witness_log(z)?;
        self.vk.validate_certified_c1_in_witness(total_vars)?;
        let committed: [&[F128]; MERKLE_REGION_COMMITTED_COLUMNS] = std::array::from_fn(|column| {
            let slice = self.vk.slices[column];
            &z[slice.start()..slice.start() + slice.len()]
        });
        let families = self.vk.protocol_families();
        bind_merkle_vk(challenger, self.vk);
        let prefix = prove_c1_merkle_walk_prefix(
            self.vk.w_log,
            &self.vk.fixed,
            &[0, 1, 2, 3],
            &families,
            &committed,
            self.s_out,
            challenger,
        );
        Ok(C1MerkleRegionProverWalkContinuation {
            vk: self.vk,
            total_vars,
            committed,
            families,
            s0: self.s0,
            prefix,
        })
    }
}

/// Serializable Walk-B authority without prover-authored PCS descriptors.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MerkleRegionSidecarProof {
    version: u8,
    authority: MerkleUnionProof,
}

impl MerkleRegionSidecarProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("merkle sidecar serialized length") as usize
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct C1MerkleRegionWalkDeferredProof {
    version: u8,
    authority: C1MerkleUnionWalkDeferredProof,
}

impl C1MerkleRegionWalkDeferredProof {
    pub(crate) fn new(authority: C1MerkleUnionWalkDeferredProof) -> Self {
        Self {
            version: MERKLE_REGION_SIDECAR_VERSION,
            authority,
        }
    }

    pub(crate) fn version(&self) -> u8 {
        self.version
    }

    pub(crate) fn authority(&self) -> &C1MerkleUnionWalkDeferredProof {
        &self.authority
    }
}

pub(crate) fn verify_c1_merkle_region_walk_deferred_prefix<'a, Ch: Challenger>(
    vk: &'a MerkleRegionVk,
    total_vars: usize,
    proof: &'a C1MerkleRegionWalkDeferredProof,
    challenger: &mut Ch,
) -> Result<C1MerkleRegionVerifierWalkContinuation<'a>, RegionSidecarError> {
    let timing = std::env::var_os("NOIDH_C1_VERIFY_TIMING").is_some();
    let total_started = std::time::Instant::now();
    vk.validate_certified_c1_in_witness(total_vars)?;
    let validate_micros = total_started.elapsed().as_micros();
    if proof.version != MERKLE_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    let families = vk.protocol_families();
    bind_merkle_vk(challenger, vk);
    let bind_micros = total_started.elapsed().as_micros() - validate_micros;
    let prefix_started = std::time::Instant::now();
    let prefix = verify_c1_merkle_walk_prefix(
        vk.w_log,
        &vk.fixed,
        &[0, 1, 2, 3],
        &families,
        proof.authority.as_ref(),
        challenger,
    )
    .map_err(|_| RegionSidecarError::InvalidProof)?;
    if timing {
        eprintln!(
            "[merkle-c1 prefix] w_log={} validate_us={validate_micros} bind_us={bind_micros} proof_us={} total_us={}",
            vk.w_log,
            prefix_started.elapsed().as_micros(),
            total_started.elapsed().as_micros(),
        );
    }
    Ok(C1MerkleRegionVerifierWalkContinuation {
        vk,
        total_vars,
        families,
        prefix,
    })
}

/// Replay a recording-free V1 Walk-B sidecar and derive its terminal PCS
/// claims solely from the VK and verified relation endpoints.
pub fn verify_merkle_region_sidecar<Ch: Challenger>(
    vk: &MerkleRegionVk,
    total_vars: usize,
    proof: &MerkleRegionSidecarProof,
    challenger: &mut Ch,
) -> Result<Vec<QuirkyDirectClaim>, RegionSidecarError> {
    vk.validate_in_witness(total_vars)?;
    if proof.version != MERKLE_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    let families = vk.protocol_families();
    bind_merkle_vk(challenger, vk);
    let terminal = verify_merkle_union_with_challenger(
        vk.w_log,
        &vk.fixed,
        &[0, 1, 2, 3],
        &families,
        &proof.authority,
        challenger,
    )
    .map_err(|error| {
        if std::env::var_os("NOID_HISTORY_STEP_AUX_DEBUG").is_some() {
            eprintln!("[merkle-sidecar verify] complete proof: {error:?}");
        }
        RegionSidecarError::InvalidProof
    })?;
    resolve_merkle_terminal_claims(vk, total_vars, terminal)
}

fn validate_merkle_family_geometry(
    block_log: usize,
    families: &[MerkleRegionFamily],
) -> Result<(), RegionSidecarError> {
    if block_log >= usize::BITS as usize || families.is_empty() {
        return Err(RegionSidecarError::BadVk);
    }
    let block = 1usize << block_log;
    let mut ranges = Vec::new();
    let mut previous_offset = None;
    for family in families {
        let nonempty = match family {
            MerkleRegionFamily::FeedForward { depth, n_paths, .. }
            | MerkleRegionFamily::FeedForwardStrided { depth, n_paths, .. }
            | MerkleRegionFamily::TwoPermutationStrided { depth, n_paths, .. }
            | MerkleRegionFamily::TwoPermutation { depth, n_paths, .. } => {
                *depth > 0 && *n_paths > 0
            }
            MerkleRegionFamily::PairedUpdate { n_updates, .. } => *n_updates > 0,
        };
        let (offset, len) = family.geometry().ok_or(RegionSidecarError::BadVk)?;
        let end = offset.checked_add(len).ok_or(RegionSidecarError::BadVk)?;
        if !nonempty
            || len == 0
            || end > block
            || previous_offset.is_some_and(|previous| offset < previous)
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        previous_offset = Some(offset);
        match *family {
            MerkleRegionFamily::TwoPermutationStrided {
                offset,
                depth,
                n_paths,
                stride,
                ..
            } => {
                let active = depth.checked_mul(2).ok_or(RegionSidecarError::BadVk)?;
                for path in 0..n_paths {
                    let start = offset
                        .checked_add(path.checked_mul(stride).ok_or(RegionSidecarError::BadVk)?)
                        .ok_or(RegionSidecarError::BadVk)?;
                    let end = start.checked_add(active).ok_or(RegionSidecarError::BadVk)?;
                    if end > block {
                        return Err(RegionSidecarError::UnsupportedVkShape);
                    }
                    ranges.push((start, end));
                }
            }
            MerkleRegionFamily::FeedForwardStrided {
                offset,
                depth,
                n_paths,
                stride,
                ..
            } => {
                for path in 0..n_paths {
                    let start = offset
                        .checked_add(path.checked_mul(stride).ok_or(RegionSidecarError::BadVk)?)
                        .ok_or(RegionSidecarError::BadVk)?;
                    let end = start.checked_add(depth).ok_or(RegionSidecarError::BadVk)?;
                    if end > block {
                        return Err(RegionSidecarError::UnsupportedVkShape);
                    }
                    ranges.push((start, end));
                }
            }
            _ => ranges.push((offset, end)),
        }
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    Ok(())
}

fn preflight_merkle_layout(
    w_log: usize,
    block_log: usize,
    families: &[MerkleRegionFamily],
) -> Result<(), RegionSidecarError> {
    if w_log == 0
        || w_log >= usize::BITS as usize
        || block_log > w_log
        || block_log > MAX_MERKLE_PATTERN_LOG
        || families.is_empty()
        || families.len() > MAX_MERKLE_FAMILIES
    {
        return Err(RegionSidecarError::BadVk);
    }
    validate_merkle_family_geometry(block_log, families)?;
    let pattern_count = families
        .iter()
        .try_fold(0usize, |sum, family| sum.checked_add(family.fixed_len()))
        .ok_or(RegionSidecarError::BadVk)?;
    let block = 1usize << block_log;
    let fixed_cells = pattern_count
        .checked_mul(block)
        .ok_or(RegionSidecarError::BadVk)?;
    if fixed_cells > MAX_MERKLE_FIXED_CELLS {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    Ok(())
}

fn canonical_merkle_fixed(
    block_log: usize,
    families: &[MerkleRegionFamily],
) -> Result<Vec<FixedPattern>, RegionSidecarError> {
    validate_merkle_family_geometry(block_log, families)?;
    let capacity = families
        .iter()
        .try_fold(0usize, |sum, family| sum.checked_add(family.fixed_len()))
        .ok_or(RegionSidecarError::BadVk)?;
    let mut fixed = Vec::with_capacity(capacity);
    for family in families {
        fixed.extend(
            family
                .canonical_fixed(block_log)
                .ok_or(RegionSidecarError::BadVk)?,
        );
    }
    Ok(fixed)
}

/// Stable manual encoding of the full canonical Walk-B relation layout.
pub fn merkle_layout_digest(
    w_log: usize,
    block_log: usize,
    fixed: &[FixedPattern],
    families: &[MerkleRegionFamily],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.push(MERKLE_REGION_SIDECAR_VERSION);
    push_usize(&mut bytes, w_log);
    push_usize(&mut bytes, block_log);
    push_usize(&mut bytes, families.len());
    for family in families {
        family.encode(&mut bytes);
    }
    push_usize(&mut bytes, fixed.len());
    for pattern in fixed {
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
    poseidon2b_hash_byte_slices(MERKLE_LAYOUT_DIGEST_DOMAIN, &[&bytes])
}

fn bind_merkle_vk<Ch: Challenger>(challenger: &mut Ch, vk: &MerkleRegionVk) {
    challenger.observe_label(MERKLE_SIDECAR_TRANSCRIPT_LABEL);
    challenger.observe_bytes(&vk.transcript_digest());
}

fn resolve_merkle_terminal_claims(
    vk: &MerkleRegionVk,
    total_vars: usize,
    terminal: Vec<MerkleColumnClaim>,
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

fn resolve_c1_merkle_terminal_claims(
    vk: &MerkleRegionVk,
    total_vars: usize,
    terminal: Vec<C1MerkleColumnClaim>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionSidecarError {
    BadVk,
    UnsupportedVkShape,
    BadSlice,
    BadWalkColumns,
    WitnessShape,
    UnsupportedVersion,
    InvalidProof,
}

impl std::fmt::Display for RegionSidecarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::BadVk => "malformed region sidecar VK",
            Self::UnsupportedVkShape => "region sidecar VK shape is not supported by V1",
            Self::BadSlice => "region sidecar committed slice is malformed",
            Self::BadWalkColumns => "region sidecar walk-column shape mismatch",
            Self::WitnessShape => "outer field witness is not a non-empty dyadic vector",
            Self::UnsupportedVersion => "unsupported region sidecar version",
            Self::InvalidProof => "invalid region sidecar proof",
        };
        f.write_str(message)
    }
}

impl std::error::Error for RegionSidecarError {}

/// Stable digest of the compiled schedule.  Constants and witness-data indices
/// are encoded explicitly; debug/serde formatting is never transcript input.
pub fn duplex_layout_digest(layout: &DuplexLayout) -> [u8; 32] {
    let mut bytes = Vec::new();
    push_usize(&mut bytes, layout.slots.len());
    push_usize(&mut bytes, layout.challenges.len());
    push_usize(&mut bytes, layout.n_data);
    for slot in &layout.slots {
        for lane in slot.lanes {
            match lane {
                None => bytes.push(0),
                Some(LaneSource::Data(index)) => {
                    bytes.push(1);
                    push_usize(&mut bytes, index);
                }
                Some(LaneSource::Const(value)) => {
                    bytes.push(2);
                    bytes.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
    }
    for (slot, lane) in &layout.challenges {
        push_usize(&mut bytes, *slot);
        push_usize(&mut bytes, *lane);
    }
    poseidon2b_hash_byte_slices(DUPLEX_LAYOUT_DIGEST_DOMAIN, &[&bytes])
}

fn duplex_compiled_layout_digest(layout: &DuplexLayout, w_log: usize) -> [u8; 32] {
    let block_log = layout
        .slots
        .len()
        .max(1)
        .next_power_of_two()
        .trailing_zeros() as usize;
    let mut bytes = Vec::new();
    bytes.push(DUPLEX_REGION_SIDECAR_VERSION);
    push_usize(&mut bytes, w_log);
    push_usize(&mut bytes, block_log);
    bytes.extend_from_slice(&duplex_layout_digest(layout));
    poseidon2b_hash_byte_slices(DUPLEX_LAYOUT_DIGEST_DOMAIN, &[b"UNION", &bytes])
}

fn bind_vk<Ch: Challenger>(challenger: &mut Ch, vk: &DuplexRegionVk) {
    challenger.observe_label(DUPLEX_SIDECAR_TRANSCRIPT_LABEL);
    challenger.observe_bytes(&vk.transcript_digest());
}

fn resolve_terminal_claims(
    vk: &DuplexRegionVk,
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
    vk: &DuplexRegionVk,
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

fn witness_log(z: &[F128]) -> Result<usize, RegionSidecarError> {
    if z.is_empty() || !z.len().is_power_of_two() {
        return Err(RegionSidecarError::WitnessShape);
    }
    Ok(z.len().trailing_zeros() as usize)
}

fn validate_c1_endpoint_lengths(
    w_log: usize,
    s0: &[Vec<F128>; 4],
    s_out: &[Vec<F128>; 4],
) -> Result<(), RegionSidecarError> {
    if w_log >= usize::BITS as usize {
        return Err(RegionSidecarError::BadWalkColumns);
    }
    let expected = 1usize << w_log;
    if s0.iter().any(|column| column.len() != expected)
        || s_out.iter().any(|column| column.len() != expected)
    {
        return Err(RegionSidecarError::BadWalkColumns);
    }
    Ok(())
}

fn push_usize(out: &mut Vec<u8>, value: usize) {
    let encoded = u64::try_from(value).expect("region-sidecar index exceeds u64");
    out.extend_from_slice(&encoded.to_le_bytes());
}

fn push_f128(out: &mut Vec<u8>, value: F128) {
    out.extend_from_slice(&value.lo.to_le_bytes());
    out.extend_from_slice(&value.hi.to_le_bytes());
}

fn encode_refs(out: &mut Vec<u8>, refs: &DuplexFamilyRefs) {
    for index in refs
        .a
        .into_iter()
        .chain(refs.c)
        .chain(std::iter::once(refs.start))
        .chain(refs.abs)
        .chain(refs.consts)
    {
        push_usize(out, index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acceptance::trace::region_source_binding::{
        build_duplex_union, build_duplex_union_with_recordings, RecordingSpec,
    };
    use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
    use noid_ivc_core::deep_chain::ff_merkle::{
        build_ff_merkle_path_columns, FfMerklePathFamily, FfMerklePathWitness,
    };
    use noid_ivc_core::deep_chain::relations::{
        prove_column_relation, verify_column_relation, RelationColumns,
    };
    use noid_ivc_core::deep_chain::schedule::{
        build_merkle_path_columns, carry_selection_terms, compile_duplex, MerklePathWitness,
        TranscriptOp,
    };
    use noid_ivc_core::field_circuit::FieldR1csBuilder;
    use noid_ivc_core::lincheck::build_eq_table;
    use noid_ivc_core::pcs::{self, PcsParams};
    use noid_ivc_core::public_io::PublicIoSpec;
    use noid_ivc_core::verifier::{
        verify_field_with_public_io, verify_field_with_public_io_and_post_commit, VerifyError,
    };
    use noid_ivc_prover::field_prover::prove_field_with_public_io_and_post_commit;

    const OUTER_DOMAIN: &[u8] = b"duplex-region-sidecar-field-e2e-v1";

    #[test]
    fn certified_c1_endpoint_gate_checks_both_boundaries() {
        let s0: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; 8]);
        let s_out = s0.clone();
        assert_eq!(validate_c1_endpoint_lengths(3, &s0, &s_out), Ok(()));

        let mut short_s0 = s0.clone();
        short_s0[1].pop();
        assert_eq!(
            validate_c1_endpoint_lengths(3, &short_s0, &s_out),
            Err(RegionSidecarError::BadWalkColumns)
        );

        let mut long_s_out = s_out.clone();
        long_s_out[2].push(F128::ZERO);
        assert_eq!(
            validate_c1_endpoint_lengths(3, &s0, &long_s_out),
            Err(RegionSidecarError::BadWalkColumns)
        );
        assert_eq!(
            validate_c1_endpoint_lengths(usize::BITS as usize, &s0, &s_out),
            Err(RegionSidecarError::BadWalkColumns)
        );
    }

    fn params(m: usize) -> PcsParams {
        PcsParams {
            m: m + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        }
    }

    pub(super) fn duplex_decode_fixture_with_purpose(
        purpose: [u8; 32],
    ) -> (DuplexRegionVk, usize, DuplexRegionSidecarProof, Vec<u8>) {
        let layout = compile_duplex(&[
            TranscriptOp::Absorb(vec![None, None, None]),
            TranscriptOp::Squeeze(3),
        ]);
        let union = build_duplex_union(
            &layout,
            [F128::new(0x1111, 0x2222), F128::new(0x3333, 0x4444)],
            &[vec![F128::new(5, 0), F128::new(7, 0), F128::new(11, 0)]],
        );
        let column_len = 1usize << union.w_log;
        let mut z =
            vec![F128::ZERO; (DUPLEX_REGION_COMMITTED_COLUMNS * column_len).next_power_of_two()];
        for (column, values) in union.committed.iter().enumerate() {
            z[column * column_len..(column + 1) * column_len].copy_from_slice(values);
        }
        let slices = std::array::from_fn(|index| WitnessSlice {
            log2_len: union.w_log,
            index,
        });
        let vk = DuplexRegionVk::from_union(purpose, slices, &union).unwrap();
        let plan = DuplexRegionProverPlan::new(&vk, &union.s0, &union.s_out).unwrap();
        let mut challenger = FsLaneChallenger::new(b"duplex-bounded-decode-v1");
        let (proof, _) = plan.prove(&z, &mut challenger).unwrap();
        let encoded = bincode::serialize(&proof).unwrap();
        (vk, z.len().trailing_zeros() as usize, proof, encoded)
    }

    #[test]
    fn duplex_bounded_decode_rejects_forged_lengths_before_serde() {
        let (vk, total_vars, proof, encoded) = duplex_decode_fixture_with_purpose([0xD1; 32]);
        let before = bounded_decode::serde_attempts();
        let decoded = decode_duplex_region_sidecar_bounded(&vk, total_vars, &encoded).unwrap();
        assert_eq!(decoded, proof);
        assert_eq!(bounded_decode::serde_attempts(), before + 1);

        let malformed_start = bounded_decode::serde_attempts();
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_duplex_region_sidecar_bounded(&vk, total_vars, &trailing).unwrap_err(),
            RegionSidecarError::InvalidProof
        );
        let truncated = &encoded[..encoded.len() - 1];
        assert_eq!(
            decode_duplex_region_sidecar_bounded(&vk, total_vars, truncated).unwrap_err(),
            RegionSidecarError::InvalidProof
        );
        let mut wrong_version = encoded.clone();
        wrong_version[0] = DUPLEX_REGION_SIDECAR_VERSION.wrapping_add(1);
        assert_eq!(
            decode_duplex_region_sidecar_bounded(&vk, total_vars, &wrong_version).unwrap_err(),
            RegionSidecarError::UnsupportedVersion
        );

        let shape = bounded_decode::duplex_proof_shape(&vk);
        let offsets = bounded_decode::layout_offsets(&encoded, &shape).unwrap();
        let vec_offsets = offsets
            .iter()
            .filter_map(|(field, offset)| {
                matches!(field, bounded_decode::LayoutField::VecLength(_)).then_some(*offset)
            })
            .collect::<Vec<_>>();
        assert_eq!(vec_offsets.len(), 8, "all Duplex Vec classes covered");
        for offset in vec_offsets {
            let mut forged = encoded.clone();
            forged[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert_eq!(
                decode_duplex_region_sidecar_bounded(&vk, total_vars, &forged).unwrap_err(),
                RegionSidecarError::InvalidProof
            );
        }
        assert_eq!(
            bounded_decode::serde_attempts(),
            malformed_start,
            "malformed lengths reached allocation-bearing serde"
        );
    }

    #[test]
    fn duplex_sidecar_v1_rejects_recording_union() {
        let layout = compile_duplex(&[
            TranscriptOp::Absorb(vec![None, None]),
            TranscriptOp::Squeeze(2),
        ]);
        let iv = [F128::new(0x11, 0), F128::new(0x22, 0)];
        let primary = vec![F128::new(3, 0), F128::new(5, 0)];
        let recording_data = vec![F128::new(7, 0), F128::new(11, 0)];
        let recording = RecordingSpec {
            layout: layout.clone(),
            iv_flat: iv,
            data: &recording_data,
        };
        let union = build_duplex_union_with_recordings(
            &layout,
            iv,
            std::slice::from_ref(&primary),
            std::slice::from_ref(&recording),
        );
        let slices = std::array::from_fn(|index| WitnessSlice {
            log2_len: union.w_log,
            index,
        });
        assert_eq!(
            DuplexRegionVk::from_union([0xA5; 32], slices, &union),
            Err(RegionSidecarError::UnsupportedVkShape)
        );
    }

    #[test]
    fn duplex_sidecar_field_roundtrip_and_mutation_negatives() {
        let layout = compile_duplex(&[
            TranscriptOp::Absorb(vec![None, None, None]),
            TranscriptOp::Squeeze(3),
        ]);
        let union = build_duplex_union(
            &layout,
            [F128::new(0x1111, 0x2222), F128::new(0x3333, 0x4444)],
            &[vec![F128::new(5, 0), F128::new(7, 0), F128::new(11, 0)]],
        );

        let mut builder = FieldR1csBuilder::new();
        let column_len = 1usize << union.w_log;
        while builder.num_wires() % column_len != 0 {
            builder.alloc_f128(F128::ZERO);
        }
        let base = builder.num_wires();
        for column in &union.committed {
            for value in column {
                builder.alloc_f128(*value);
            }
        }
        let slices: [WitnessSlice; DUPLEX_REGION_COMMITTED_COLUMNS] =
            std::array::from_fn(|column| WitnessSlice {
                log2_len: union.w_log,
                index: (base / column_len) + column,
            });
        let (r1cs, z) = builder.build();
        let spec = PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 0,
                index: 0,
            },
            io_len: 1,
            claims: Vec::new(),
        };
        let io = [F128::ONE];
        let purpose = poseidon2b_hash_byte_slices(b"DUPLEX-SIDECAR-TEST-PURPOSE", &[b"honest"]);
        let vk = DuplexRegionVk::from_union(purpose, slices, &union).expect("canonical VK");
        let direct_vk = DuplexRegionVk::new(
            purpose,
            union.w_log,
            slices,
            union.fixed.clone(),
            union.refs,
            &union.layout,
        )
        .expect("canonical direct VK");
        assert_eq!(vk, direct_vk, "constructor/from-union VK canonicality");
        assert_eq!(vk.transcript_digest(), direct_vk.transcript_digest());
        let plan = DuplexRegionProverPlan::new(&vk, &union.s0, &union.s_out).unwrap();

        let mut prover_challenger = FsLaneChallenger::new(OUTER_DOMAIN);
        let (field_proof, sidecar, commitment, _) = prove_field_with_public_io_and_post_commit(
            &r1cs,
            &z,
            &params(r1cs.m),
            &spec,
            &io,
            &mut prover_challenger,
            |z, _commitment, challenger| plan.prove(z, challenger).expect("honest sidecar"),
        );

        let encoded = bincode::serialize(&sidecar).expect("serialize sidecar proof");
        assert_eq!(encoded.len(), sidecar.byte_len());
        let decoded: DuplexRegionSidecarProof =
            bincode::deserialize(&encoded).expect("deserialize sidecar proof");
        assert_eq!(decoded, sidecar);

        let verify = |candidate_vk: &DuplexRegionVk, candidate_proof: &DuplexRegionSidecarProof| {
            let mut challenger = FsLaneChallenger::new(OUTER_DOMAIN);
            verify_field_with_public_io_and_post_commit(
                &r1cs,
                &commitment,
                &field_proof,
                &spec,
                &io,
                candidate_proof,
                &mut challenger,
                |proof, challenger| {
                    verify_duplex_region_sidecar(candidate_vk, r1cs.m, proof, challenger)
                        .map_err(|_| VerifyError::Auxiliary)
                },
            )
        };

        assert!(verify(&vk, &decoded).is_ok());

        let mut standard_challenger = FsLaneChallenger::new(OUTER_DOMAIN);
        assert!(
            verify_field_with_public_io(
                &r1cs,
                &commitment,
                &field_proof,
                &spec,
                &io,
                &mut standard_challenger,
            )
            .is_err(),
            "duplex sidecar proof accepted by standard verifier"
        );

        let mut bad_proof = decoded.clone();
        bad_proof.authority.selection.rounds[0][0] += F128::ONE;
        assert!(verify(&vk, &bad_proof).is_err(), "proof mutation");

        let mut bad_vk = vk.clone();
        bad_vk.layout_digest[0] ^= 1;
        assert!(verify(&bad_vk, &decoded).is_err(), "VK mutation");

        let mut bad_slices = vk.clone();
        bad_slices.slices.swap(0, 1);
        assert!(
            verify(&bad_slices, &decoded).is_err(),
            "exact-slice mutation"
        );
    }

    #[test]
    fn precommit_rho_kernel_is_rejected_after_commit_binding() {
        // The weakened ordering sampled rho before committing the columns.
        // An adversary can then choose a non-zero two-entry column whose MLE
        // is exactly zero at that known rho.
        let refs = duplex_family_refs(0, 0);
        let fixed = Vec::new();
        let mut old_prover = FsLaneChallenger::new(b"duplex-precommit-kernel-v0");
        let beta = old_prover.sample_f128();
        let rho = old_prover.sample_f128_vec(1);
        let delta = [rho[0], F128::ONE + rho[0]];
        let eval = delta
            .iter()
            .zip(build_eq_table(&rho))
            .fold(F128::ZERO, |sum, (value, weight)| sum + *value * weight);
        assert_eq!(eval, F128::ZERO);
        assert!(delta.iter().any(|value| *value != F128::ZERO));

        let zero = [F128::ZERO; 2];
        let mut committed_owned: [Vec<F128>; 6] = std::array::from_fn(|_| zero.to_vec());
        committed_owned[refs.c[0]] = delta.to_vec();
        let committed: Vec<&[F128]> = committed_owned.iter().map(Vec::as_slice).collect();
        let internal_owned: [Vec<F128>; 4] = std::array::from_fn(|_| zero.to_vec());
        let internal: Vec<&[F128]> = internal_owned.iter().map(Vec::as_slice).collect();
        let terms = carry_selection_terms(&refs.c, beta);
        let (old_proof, _, _) = prove_column_relation(
            F128::ZERO,
            &rho,
            &terms,
            &RelationColumns {
                committed: &committed,
                internal: &internal,
                fixed: &fixed,
            },
            &mut old_prover,
        );

        let mut old_verifier = FsLaneChallenger::new(b"duplex-precommit-kernel-v0");
        let old_beta = old_verifier.sample_f128();
        let old_rho = old_verifier.sample_f128_vec(1);
        assert_eq!(old_beta, beta);
        assert_eq!(old_rho, rho);
        assert!(
            verify_column_relation(
                1,
                F128::ZERO,
                &old_rho,
                &carry_selection_terms(&refs.c, old_beta),
                &fixed,
                &old_proof,
                &mut old_verifier,
            )
            .is_ok(),
            "the old precommit ordering admits the rho-kernel witness"
        );

        // In V1 the outer root is already in the SAME challenger before beta
        // and rho are drawn.  Replaying the precommit proof under that state
        // fails, and the malicious column is no longer in the new rho kernel.
        let mut postcommit = FsLaneChallenger::new(b"duplex-precommit-kernel-v0");
        postcommit.observe_bytes(b"outer-field-witness-root");
        let post_beta = postcommit.sample_f128();
        let post_rho = postcommit.sample_f128_vec(1);
        let post_eval = delta
            .iter()
            .zip(build_eq_table(&post_rho))
            .fold(F128::ZERO, |sum, (value, weight)| sum + *value * weight);
        assert_ne!(post_eval, F128::ZERO);
        assert!(
            verify_column_relation(
                1,
                F128::ZERO,
                &post_rho,
                &carry_selection_terms(&refs.c, post_beta),
                &fixed,
                &old_proof,
                &mut postcommit,
            )
            .is_err(),
            "postcommit transcript must reject the fixed-rho kernel proof"
        );
    }

    fn merkle_fixture() -> (
        Vec<Vec<F128>>,
        [Vec<F128>; 4],
        [Vec<F128>; 4],
        usize,
        usize,
        Vec<MerkleRegionFamily>,
    ) {
        let w_log = 2;
        let block_log = 2;
        let iv = [F128::new(0x1337, 0x2448), F128::new(0x3559, 0x466a)];
        let family = MerklePathFamily {
            depth: 2,
            n_paths: 1,
        };
        let columns = build_merkle_path_columns(
            &family,
            iv,
            &[MerklePathWitness {
                entry: [F128::new(3, 5), F128::new(7, 11)],
                siblings: vec![
                    [F128::new(13, 17), F128::new(19, 23)],
                    [F128::new(29, 31), F128::new(37, 41)],
                ],
                directions: vec![false, true],
            }],
            w_log,
        );
        let committed = vec![
            columns.c[0].clone(),
            columns.c[1].clone(),
            columns.c[2].clone(),
            columns.c[3].clone(),
            columns.e[0].clone(),
            columns.e[1].clone(),
            columns.sib[0].clone(),
            columns.sib[1].clone(),
            columns.d.clone(),
        ];
        let families = vec![MerkleRegionFamily::TwoPermutation {
            offset: 0,
            depth: family.depth,
            n_paths: family.n_paths,
            iv,
        }];
        (
            committed,
            columns.s0,
            columns.s_out,
            w_log,
            block_log,
            families,
        )
    }

    #[test]
    fn strided_feed_forward_ten_plus_six_matches_dense_wallet_layout_end_to_end() {
        const W_LOG: usize = 5;
        const BLOCK_LOG: usize = 5;
        const N_PATHS: usize = 2;
        const DESTINATION_STRIDE: usize = 16;
        const SOURCE_DEPTH: usize = 10;
        const MID_DEPTH: usize = 6;

        let iv = [F128::new(0x1357, 0x2468), F128::new(0x3579, 0x468a)];
        let paths = |depth: usize, salt: u64| {
            (0..N_PATHS)
                .map(|path| FfMerklePathWitness {
                    entry: [
                        F128::new(salt + path as u64 + 1, salt + 0x100 + path as u64),
                        F128::new(salt + path as u64 + 3, salt + 0x200 + path as u64),
                    ],
                    siblings: (0..depth)
                        .map(|level| {
                            [
                                F128::new(
                                    salt + 0x300 + (path * depth + level) as u64,
                                    salt + 0x400 + level as u64,
                                ),
                                F128::new(
                                    salt + 0x500 + (path * depth + level) as u64,
                                    salt + 0x600 + level as u64,
                                ),
                            ]
                        })
                        .collect(),
                    directions: (0..depth)
                        .map(|level| (path + level + salt as usize) & 1 == 1)
                        .collect(),
                })
                .collect::<Vec<_>>()
        };
        let source_family = FfMerklePathFamily {
            depth: SOURCE_DEPTH,
            n_paths: N_PATHS,
        };
        let mid_family = FfMerklePathFamily {
            depth: MID_DEPTH,
            n_paths: N_PATHS,
        };
        let source =
            build_ff_merkle_path_columns(&source_family, iv, &paths(SOURCE_DEPTH, 0x1000), W_LOG);
        let mid = build_ff_merkle_path_columns(&mid_family, iv, &paths(MID_DEPTH, 0x2000), 4);

        let column_len = 1usize << W_LOG;
        let mut committed: [Vec<F128>; MERKLE_REGION_COMMITTED_COLUMNS] =
            std::array::from_fn(|_| vec![F128::ZERO; column_len]);
        let mut s0: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; column_len]);
        let mut s_out: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; column_len]);
        let mut place = |columns: &noid_ivc_core::deep_chain::ff_merkle::FfMerklePathColumns,
                         depth: usize,
                         source_stride: usize,
                         destination_offset: usize| {
            for path in 0..N_PATHS {
                for level in 0..depth {
                    let from = path * source_stride + level;
                    let to = path * DESTINATION_STRIDE + destination_offset + level;
                    for lane in 0..2 {
                        committed[4 + lane][to] = columns.cr[lane][from];
                        committed[6 + lane][to] = columns.sib[lane][from];
                    }
                    committed[8][to] = columns.d[from];
                    for lane in 0..4 {
                        committed[lane][to] = columns.c[lane][from];
                        s0[lane][to] = columns.s0[lane][from];
                        s_out[lane][to] = columns.s_out[lane][from];
                    }
                }
            }
        };
        place(&source, SOURCE_DEPTH, source_family.stride(), 0);
        place(&mid, MID_DEPTH, mid_family.stride(), SOURCE_DEPTH);

        let mut z =
            vec![F128::ZERO; (MERKLE_REGION_COMMITTED_COLUMNS * column_len).next_power_of_two()];
        for (column, values) in committed.iter().enumerate() {
            z[column * column_len..(column + 1) * column_len].copy_from_slice(values);
        }
        let slices = std::array::from_fn(|index| WitnessSlice {
            log2_len: W_LOG,
            index,
        });
        let purpose = [0xA6; 32];
        let families = vec![
            MerkleRegionFamily::FeedForwardStrided {
                offset: 0,
                depth: SOURCE_DEPTH,
                n_paths: N_PATHS,
                stride: DESTINATION_STRIDE,
                iv,
            },
            MerkleRegionFamily::FeedForwardStrided {
                offset: SOURCE_DEPTH,
                depth: MID_DEPTH,
                n_paths: N_PATHS,
                stride: DESTINATION_STRIDE,
                iv,
            },
        ];
        let vk = MerkleRegionVk::new(purpose, W_LOG, slices, BLOCK_LOG, families).unwrap();
        assert_eq!(vk.fixed().len(), 12);
        for slot in 0..column_len {
            let local = slot % DESTINATION_STRIDE;
            assert_eq!(
                vk.fixed()[5].table[slot],
                if local < SOURCE_DEPTH {
                    F128::ONE
                } else {
                    F128::ZERO
                }
            );
            assert_eq!(
                vk.fixed()[11].table[slot],
                if local >= SOURCE_DEPTH {
                    F128::ONE
                } else {
                    F128::ZERO
                }
            );
        }

        let plan = MerkleRegionProverPlan::new(&vk, &s0, &s_out).unwrap();
        let mut prover = FsLaneChallenger::new(b"strided-wallet-b-10-plus-6-v1");
        let (proof, claims) = plan.prove(&z, &mut prover).unwrap();
        let prover_next = prover.sample_f128();
        let mut verifier = FsLaneChallenger::new(b"strided-wallet-b-10-plus-6-v1");
        let replay = verify_merkle_region_sidecar(
            &vk,
            z.len().trailing_zeros() as usize,
            &proof,
            &mut verifier,
        )
        .unwrap();
        let claim_tuples = |claims: &[QuirkyDirectClaim]| {
            claims
                .iter()
                .map(|claim| {
                    (
                        claim.z_skip,
                        claim.k_skip,
                        claim.x_rest.clone(),
                        claim.value,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(claim_tuples(&claims), claim_tuples(&replay));
        assert_eq!(prover_next, verifier.sample_f128());

        let old_eight_plus_eight = MerkleRegionVk::new(
            purpose,
            W_LOG,
            slices,
            BLOCK_LOG,
            vec![
                MerkleRegionFamily::FeedForwardStrided {
                    offset: 0,
                    depth: 8,
                    n_paths: N_PATHS,
                    stride: DESTINATION_STRIDE,
                    iv,
                },
                MerkleRegionFamily::FeedForwardStrided {
                    offset: 8,
                    depth: 8,
                    n_paths: N_PATHS,
                    stride: DESTINATION_STRIDE,
                    iv,
                },
            ],
        )
        .unwrap();
        let mut wrong_verifier = FsLaneChallenger::new(b"strided-wallet-b-10-plus-6-v1");
        assert!(
            verify_merkle_region_sidecar(
                &old_eight_plus_eight,
                z.len().trailing_zeros() as usize,
                &proof,
                &mut wrong_verifier,
            )
            .is_err(),
            "the selected 10+6 authority replayed under the retired 8+8 key"
        );
    }

    #[test]
    fn family_major_feed_forward_paths_fill_the_dyadic_domain_end_to_end() {
        const W_LOG: usize = 8;
        const DEPTHS: [usize; 4] = [21, 17, 13, 9];
        const PATH_COUNTS: [usize; 4] = [5, 5, 3, 3];

        let iv = [F128::new(0x1357, 0x2468), F128::new(0x3579, 0x468a)];
        let column_len = 1usize << W_LOG;
        let mut committed: [Vec<F128>; MERKLE_REGION_COMMITTED_COLUMNS] =
            std::array::from_fn(|_| vec![F128::ZERO; column_len]);
        let mut s0: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; column_len]);
        let mut s_out: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; column_len]);
        let mut families = Vec::with_capacity(DEPTHS.len());
        let mut offset = 0usize;

        for (family_index, (depth, path_count)) in DEPTHS.into_iter().zip(PATH_COUNTS).enumerate() {
            let source_family = FfMerklePathFamily {
                depth,
                n_paths: path_count,
            };
            let source_stride = source_family.stride();
            let source_slots = (path_count * source_stride).next_power_of_two();
            let witnesses = (0..path_count)
                .map(|path| {
                    let salt = ((family_index + 1) * 0x1000 + path * 0x100) as u64;
                    FfMerklePathWitness {
                        entry: [F128::new(salt + 1, salt + 2), F128::new(salt + 3, salt + 4)],
                        siblings: (0..depth)
                            .map(|level| {
                                [
                                    F128::new(salt + 0x10 + level as u64, salt + 0x20),
                                    F128::new(salt + 0x30 + level as u64, salt + 0x40),
                                ]
                            })
                            .collect(),
                        directions: (0..depth)
                            .map(|level| (path + level + family_index) & 1 == 1)
                            .collect(),
                    }
                })
                .collect::<Vec<_>>();
            let source = build_ff_merkle_path_columns(
                &source_family,
                iv,
                &witnesses,
                source_slots.trailing_zeros() as usize,
            );
            for path in 0..path_count {
                for level in 0..depth {
                    let from = path * source_stride + level;
                    let to = offset + path * depth + level;
                    for lane in 0..2 {
                        committed[4 + lane][to] = source.cr[lane][from];
                        committed[6 + lane][to] = source.sib[lane][from];
                    }
                    committed[8][to] = source.d[from];
                    for lane in 0..4 {
                        committed[lane][to] = source.c[lane][from];
                        s0[lane][to] = source.s0[lane][from];
                        s_out[lane][to] = source.s_out[lane][from];
                    }
                }
            }
            families.push(MerkleRegionFamily::FeedForwardStrided {
                offset,
                depth,
                n_paths: path_count,
                stride: depth,
                iv,
            });
            offset += path_count * depth;
        }
        assert_eq!(offset, column_len, "families cover the dyadic domain");

        let mut z =
            vec![F128::ZERO; (MERKLE_REGION_COMMITTED_COLUMNS * column_len).next_power_of_two()];
        for (column, values) in committed.iter().enumerate() {
            z[column * column_len..(column + 1) * column_len].copy_from_slice(values);
        }
        let slices = std::array::from_fn(|index| WitnessSlice {
            log2_len: W_LOG,
            index,
        });
        let vk = MerkleRegionVk::new([0xA7; 32], W_LOG, slices, W_LOG, families).unwrap();
        let plan = MerkleRegionProverPlan::new(&vk, &s0, &s_out).unwrap();
        let mut prover = FsLaneChallenger::new(b"family-major-feed-forward-v1");
        let (proof, claims) = plan.prove(&z, &mut prover).unwrap();
        let prover_next = prover.sample_f128();
        let mut verifier = FsLaneChallenger::new(b"family-major-feed-forward-v1");
        let replay = verify_merkle_region_sidecar(
            &vk,
            z.len().trailing_zeros() as usize,
            &proof,
            &mut verifier,
        )
        .unwrap();
        let claim_tuples = |claims: &[QuirkyDirectClaim]| {
            claims
                .iter()
                .map(|claim| {
                    (
                        claim.z_skip,
                        claim.k_skip,
                        claim.x_rest.clone(),
                        claim.value,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(claim_tuples(&claims), claim_tuples(&replay));
        assert_eq!(prover_next, verifier.sample_f128());
    }

    pub(super) fn merkle_decode_fixture_with_purpose(
        purpose: [u8; 32],
    ) -> (MerkleRegionVk, usize, MerkleRegionSidecarProof, Vec<u8>) {
        let (committed, s0, s_out, w_log, block_log, families) = merkle_fixture();
        let column_len = 1usize << w_log;
        let mut z =
            vec![F128::ZERO; (MERKLE_REGION_COMMITTED_COLUMNS * column_len).next_power_of_two()];
        for (column, values) in committed.iter().enumerate() {
            z[column * column_len..(column + 1) * column_len].copy_from_slice(values);
        }
        let slices = std::array::from_fn(|index| WitnessSlice {
            log2_len: w_log,
            index,
        });
        let vk = MerkleRegionVk::new(purpose, w_log, slices, block_log, families).unwrap();
        let plan = MerkleRegionProverPlan::new(&vk, &s0, &s_out).unwrap();
        let mut challenger = FsLaneChallenger::new(b"merkle-bounded-decode-v1");
        let (proof, _) = plan.prove(&z, &mut challenger).unwrap();
        let encoded = bincode::serialize(&proof).unwrap();
        (vk, z.len().trailing_zeros() as usize, proof, encoded)
    }

    #[test]
    fn merkle_bounded_decode_rejects_forged_lengths_before_serde() {
        let (vk, total_vars, proof, encoded) = merkle_decode_fixture_with_purpose([0xD2; 32]);
        let before = bounded_decode::serde_attempts();
        assert_eq!(
            decode_merkle_region_sidecar_bounded(&vk, total_vars, &encoded).unwrap(),
            proof
        );
        assert_eq!(bounded_decode::serde_attempts(), before + 1);

        let malformed_start = bounded_decode::serde_attempts();
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_merkle_region_sidecar_bounded(&vk, total_vars, &trailing).unwrap_err(),
            RegionSidecarError::InvalidProof
        );
        assert_eq!(
            decode_merkle_region_sidecar_bounded(&vk, total_vars, &encoded[..encoded.len() - 1],)
                .unwrap_err(),
            RegionSidecarError::InvalidProof
        );
        let mut wrong_version = encoded.clone();
        wrong_version[0] = MERKLE_REGION_SIDECAR_VERSION.wrapping_add(1);
        assert_eq!(
            decode_merkle_region_sidecar_bounded(&vk, total_vars, &wrong_version).unwrap_err(),
            RegionSidecarError::UnsupportedVersion
        );

        let shape = bounded_decode::merkle_shape_for_vk(&vk, total_vars).unwrap();
        let offsets = bounded_decode::layout_offsets_merkle(&encoded, &shape).unwrap();
        assert!(offsets.iter().any(|(field, _)| {
            *field == bounded_decode::LayoutField::VecLength(bounded_decode::VecClass::ZeroShifts)
        }));
        for (field, offset) in offsets {
            if !matches!(field, bounded_decode::LayoutField::VecLength(_)) {
                continue;
            }
            let mut forged = encoded.clone();
            forged[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert_eq!(
                decode_merkle_region_sidecar_bounded(&vk, total_vars, &forged).unwrap_err(),
                RegionSidecarError::InvalidProof
            );
        }
        assert_eq!(
            bounded_decode::serde_attempts(),
            malformed_start,
            "malformed Merkle lengths reached allocation-bearing serde"
        );
    }

    #[test]
    fn merkle_sidecar_field_roundtrip_causality_and_mutation_negatives() {
        const DOMAIN: &[u8] = b"merkle-region-sidecar-field-e2e-v1";
        let (committed, s0, s_out, w_log, block_log, families) = merkle_fixture();
        let mut builder = FieldR1csBuilder::new();
        let column_len = 1usize << w_log;
        while builder.num_wires() % column_len != 0 {
            builder.alloc_f128(F128::ZERO);
        }
        let base = builder.num_wires();
        for column in &committed {
            for value in column {
                builder.alloc_f128(*value);
            }
        }
        let slices: [WitnessSlice; MERKLE_REGION_COMMITTED_COLUMNS] =
            std::array::from_fn(|column| WitnessSlice {
                log2_len: w_log,
                index: base / column_len + column,
            });
        let (r1cs, z) = builder.build();
        let spec = PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 0,
                index: 0,
            },
            io_len: 1,
            claims: Vec::new(),
        };
        let io = [F128::ONE];
        let purpose = poseidon2b_hash_byte_slices(b"MERKLE-SIDECAR-TEST-PURPOSE", &[b"honest"]);
        let vk = MerkleRegionVk::new(purpose, w_log, slices, block_log, families.clone())
            .expect("canonical Walk-B VK");
        let bridged =
            MerkleRegionVk::from_fixed(purpose, w_log, slices, block_log, families, vk.fixed())
                .expect("exact production fixed bridge");
        assert_eq!(vk, bridged);
        assert_eq!(vk.transcript_digest(), bridged.transcript_digest());
        let plan = MerkleRegionProverPlan::new(&vk, &s0, &s_out).unwrap();

        let mut prover_challenger = FsLaneChallenger::new(DOMAIN);
        let (field_proof, sidecar, commitment, _) = prove_field_with_public_io_and_post_commit(
            &r1cs,
            &z,
            &params(r1cs.m),
            &spec,
            &io,
            &mut prover_challenger,
            |z, _commitment, challenger| plan.prove(z, challenger).expect("honest sidecar"),
        );

        let encoded = bincode::serialize(&sidecar).expect("serialize Walk-B sidecar");
        assert_eq!(encoded.len(), sidecar.byte_len());
        let decoded: MerkleRegionSidecarProof =
            bincode::deserialize(&encoded).expect("deserialize Walk-B sidecar");
        assert_eq!(decoded, sidecar);

        let verify = |candidate_vk: &MerkleRegionVk, candidate_proof: &MerkleRegionSidecarProof| {
            let mut challenger = FsLaneChallenger::new(DOMAIN);
            verify_field_with_public_io_and_post_commit(
                &r1cs,
                &commitment,
                &field_proof,
                &spec,
                &io,
                candidate_proof,
                &mut challenger,
                |proof, challenger| {
                    verify_merkle_region_sidecar(candidate_vk, r1cs.m, proof, challenger)
                        .map_err(|_| VerifyError::Auxiliary)
                },
            )
        };

        assert!(verify(&vk, &decoded).is_ok());

        // The proof opened an auxiliary batch and bound its VK before outer
        // zerocheck; accepting it through the standard verifier would be a
        // downgrade path.
        let mut standard_challenger = FsLaneChallenger::new(DOMAIN);
        assert!(
            verify_field_with_public_io(
                &r1cs,
                &commitment,
                &field_proof,
                &spec,
                &io,
                &mut standard_challenger,
            )
            .is_err(),
            "sidecar-bearing proof accepted by standard verifier"
        );

        let mut bad_proof = decoded.clone();
        bad_proof.authority.zero.rounds[0][0] += F128::ONE;
        assert!(verify(&vk, &bad_proof).is_err(), "proof mutation");

        let mut bad_walk = decoded.clone();
        bad_walk.authority.walk.layers[0].round_coeffs[0][0] += F128::ONE;
        assert!(verify(&vk, &bad_walk).is_err(), "walk mutation");

        let mut bad_substitution = decoded.clone();
        bad_substitution.authority.substitution.rounds[0][0] += F128::ONE;
        assert!(
            verify(&vk, &bad_substitution).is_err(),
            "substitution mutation"
        );

        let mut missing_shift = decoded.clone();
        assert!(!missing_shift.authority.shifts.is_empty());
        missing_shift.authority.shifts.pop();
        assert!(
            verify(&vk, &missing_shift).is_err(),
            "shift-length mutation"
        );

        let mut bad_version = decoded.clone();
        bad_version.version ^= 1;
        assert!(verify(&vk, &bad_version).is_err(), "version mutation");

        let mut bad_vk = vk.clone();
        bad_vk.layout_digest[0] ^= 1;
        assert!(verify(&bad_vk, &decoded).is_err(), "VK mutation");

        let mut bad_fixed = vk.clone();
        bad_fixed.fixed[0].table[0] += F128::ONE;
        assert!(verify(&bad_fixed, &decoded).is_err(), "fixed mutation");

        let mut bad_slices = vk.clone();
        bad_slices.slices.swap(0, 1);
        assert!(
            verify(&bad_slices, &decoded).is_err(),
            "exact-slice mutation"
        );
    }

    #[test]
    fn merkle_sidecar_rejects_shift2_at_w_log_one_and_precommit_kernel() {
        let slices: [WitnessSlice; MERKLE_REGION_COMMITTED_COLUMNS] =
            std::array::from_fn(|column| WitnessSlice {
                log2_len: 1,
                index: column,
            });
        assert!(
            MerkleRegionVk::new(
                [0x77; 32],
                1,
                slices,
                1,
                vec![MerkleRegionFamily::TwoPermutation {
                    offset: 0,
                    depth: 1,
                    n_paths: 1,
                    iv: [F128::ZERO; 2],
                }],
            )
            .is_err(),
            "shift-2 family accepted at w_log=1"
        );

        let oversized_slices: [WitnessSlice; MERKLE_REGION_COMMITTED_COLUMNS] =
            std::array::from_fn(|column| WitnessSlice {
                log2_len: 60,
                index: column,
            });
        assert!(
            MerkleRegionVk::new(
                [0x78; 32],
                60,
                oversized_slices,
                60,
                vec![MerkleRegionFamily::FeedForward {
                    offset: 0,
                    depth: 1,
                    n_paths: 1,
                    iv: [F128::ZERO; 2],
                }],
            )
            .is_err(),
            "oversized fixed-pattern log reached allocation"
        );

        let unordered_slices: [WitnessSlice; MERKLE_REGION_COMMITTED_COLUMNS] =
            std::array::from_fn(|column| WitnessSlice {
                log2_len: 3,
                index: column,
            });
        assert!(
            MerkleRegionVk::new(
                [0x79; 32],
                3,
                unordered_slices,
                3,
                vec![
                    MerkleRegionFamily::FeedForward {
                        offset: 4,
                        depth: 1,
                        n_paths: 1,
                        iv: [F128::ZERO; 2],
                    },
                    MerkleRegionFamily::FeedForward {
                        offset: 0,
                        depth: 1,
                        n_paths: 1,
                        iv: [F128::ONE; 2],
                    },
                ],
            )
            .is_err(),
            "unordered family descriptors admitted a second VK encoding"
        );

        // Old ordering: rho is known before a commitment to C0, so a nonzero
        // two-entry delta can be selected in its MLE kernel.
        let mut old_prover = FsLaneChallenger::new(b"merkle-precommit-kernel-v0");
        let beta = old_prover.sample_f128();
        let rho = old_prover.sample_f128_vec(1);
        let delta = [rho[0], F128::ONE + rho[0]];
        let eval = delta
            .iter()
            .zip(build_eq_table(&rho))
            .fold(F128::ZERO, |sum, (value, weight)| sum + *value * weight);
        assert_eq!(eval, F128::ZERO);
        assert!(delta.iter().any(|value| *value != F128::ZERO));

        let zero = [F128::ZERO; 2];
        let mut committed_owned: [Vec<F128>; MERKLE_REGION_COMMITTED_COLUMNS] =
            std::array::from_fn(|_| zero.to_vec());
        committed_owned[0] = delta.to_vec();
        let committed: Vec<&[F128]> = committed_owned.iter().map(Vec::as_slice).collect();
        let internal_owned: [Vec<F128>; 4] = std::array::from_fn(|_| zero.to_vec());
        let internal: Vec<&[F128]> = internal_owned.iter().map(Vec::as_slice).collect();
        let terms = carry_selection_terms(&[0, 1, 2, 3], beta);
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

        let mut old_verifier = FsLaneChallenger::new(b"merkle-precommit-kernel-v0");
        let old_beta = old_verifier.sample_f128();
        let old_rho = old_verifier.sample_f128_vec(1);
        assert_eq!(old_beta, beta);
        assert_eq!(old_rho, rho);
        assert!(
            verify_column_relation(
                1,
                F128::ZERO,
                &old_rho,
                &carry_selection_terms(&[0, 1, 2, 3], old_beta),
                &[],
                &old_proof,
                &mut old_verifier,
            )
            .is_ok(),
            "old precommit ordering did not reproduce the kernel"
        );

        let mut postcommit = FsLaneChallenger::new(b"merkle-precommit-kernel-v0");
        postcommit.observe_bytes(b"outer-field-witness-root");
        let post_beta = postcommit.sample_f128();
        let post_rho = postcommit.sample_f128_vec(1);
        let post_eval = delta
            .iter()
            .zip(build_eq_table(&post_rho))
            .fold(F128::ZERO, |sum, (value, weight)| sum + *value * weight);
        assert_ne!(post_eval, F128::ZERO);
        assert!(
            verify_column_relation(
                1,
                F128::ZERO,
                &post_rho,
                &carry_selection_terms(&[0, 1, 2, 3], post_beta),
                &[],
                &old_proof,
                &mut postcommit,
            )
            .is_err(),
            "postcommit transcript accepted the fixed-rho kernel proof"
        );
    }
}
