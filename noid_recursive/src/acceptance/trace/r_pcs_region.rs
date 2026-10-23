// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! HistoryStep parent PCS hashing discharged through the mandatory LinkRegion
//! sidecar ([`super::self_verify::PcsWalkObligations`] consumer).
//!
//! The predecessor replay records every PCS leaf sponge and
//! Merkle path as an obligation instead of replaying it inline (~90% of
//! the replay). This module hosts those obligations on two shared walks:
//!
//! - **walk L-A (leaves)** — one combined duplex union: each (proof,
//!   query) is a tile whose sub-channels are that query's leaf hashes,
//!   compiled as absorb-only schedules with the length-bound `IVCPCSF_`
//!   capacity IV (every [R] PCS leaf is even-lane, fixed no-pad mode).
//!   A leaf's digest is the C0/C1 carry cells at its sub-channel's last
//!   real slot; its absorbed lanes pin to the A-lane cells (the same
//!   proof wires the fold algebra consumes — Stage-2 cell pins).
//! - **walk L-B (paths)** — one ff-Merkle union with the `IVCPCSN_`
//!   capacity IV (the 1-permutation feed-forward node of the proof-core
//!   PCS): one max-depth carrier per tree position, with (proof role, query)
//!   on the path-block axis.  The actual authentication path is a causal
//!   prefix of its carrier. Entry binding: fresh digest wires pin to BOTH
//!   the walk L-A digest cells and `CR(start)`; direction cells pin to the
//!   transcript-bound query-position bits; `CR(actual_depth)`, proven by the
//!   carrier's chain relation, pins directly to the FS-observed root wire
//!   (commitment root / post-row-batch commit / epoch commits — all absorbed
//!   before the query draw, the capsule's authentication-root rule). The
//!   remaining suffix is relation-valid padding and has no semantic role.
//!
//! HistoryStep allocates both walks before the predecessor `[R]` replay,
//! add only the semantic cell pins in phase 2, and prove both relation
//! authorities after the enclosing Field commitment through
//! [`crate::region_sidecar::LinkRegionProverPlan`]. No opening-claim IO tail
//! and no B-to-A transcript recording is part of that path.
//!
//! Tree-structure invariant: every ladder shape yields the same leaf
//! signature — `[2^log_batch_size, 2^a0, 2^a0, 2^a0]` lanes (the
//! trailing sub-arity-`a0` fold layers live in the plaintext tail, never
//! behind a commitment) — asserted at assembly, so one sub-channel
//! schedule serves every tile.

use std::collections::BTreeMap;

use noid_ivc_core::deep_chain::ff_merkle::{
    build_ff_merkle_path_columns, FfMerklePathFamily, FfMerklePathWitness,
};
use noid_ivc_core::deep_chain::schedule::{compile_duplex, TranscriptOp};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{
    DeferredConstraintSlot, FieldR1csBuilder, FsChannelUnionRecorder, LayoutRecordedChannel,
    LinExpr,
};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::proof::pcs_params_statement_bytes;
use noid_ivc_core::public_io::WitnessSlice;
use noid_poseidon2b::native::permutation::STATE_SIZE;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

use crate::region_sidecar::{
    CombinedDuplexRegionDescriptor, CombinedDuplexRegionVk, CombinedDuplexSubChannelDescriptor,
    LinkRegionProverInput, LinkRegionProverPlan, LinkRegionSidecarVk, MerkleRegionFamily,
    MerkleRegionVk, RecordingDuplexRegionVk, RegionSidecarError, RegionWalkEndpoints,
    MAX_COMBINED_DUPLEX_DATA_LANES,
};

use noid_ivc_core::deep_chain::schedule::DuplexLayout;
use noid_ivc_core::field_circuit::RecordedChannel as FsRecordedChannel;

use super::region_source_binding::{
    alloc_boolean_column_slice_values_only, alloc_column_slice_values_only,
    build_combined_duplex_union, build_recording_only_duplex_union, duplex_data_positions,
    pack_recording_only_blocks, slot_cell, DuplexUnion, RecordingSpec, SubChannel,
};
use super::self_verify::{
    flat_digest_lanes, pcs_leaf_iv_flat, pcs_node_iv_flat, PcsWalkObligations,
};
use super::{mul, pin_eq, with_pin_gate};

const DOMAIN_LA: &[u8] = b"r-pcs-leaf-union-v0";
const DOMAIN_LB: &[u8] = b"r-pcs-merkle-union-v0";
const LINK_R_PCS_LEAF_SIDECAR_PURPOSE_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/LINK-R-PCS-LEAF-A/V1";
const LINK_R_PCS_PATH_SIDECAR_PURPOSE_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/LINK-R-PCS-PATH-B/V1";

/// Canonical role identifier for link-local `[R]` leaf Walk L-A.
pub fn link_r_pcs_leaf_sidecar_purpose() -> [u8; 32] {
    poseidon2b_hash_byte_slices(LINK_R_PCS_LEAF_SIDECAR_PURPOSE_DOMAIN, &[DOMAIN_LA])
}

/// Canonical role identifier for link-local `[R]` path Walk L-B.
pub fn link_r_pcs_path_sidecar_purpose() -> [u8; 32] {
    poseidon2b_hash_byte_slices(LINK_R_PCS_PATH_SIDECAR_PURPOSE_DOMAIN, &[DOMAIN_LB])
}

const LINK_RECORDINGS_REC_PURPOSE_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/HISTORY-STEP-RECORDINGS/V1";
/// Canonical role identifier for HistoryStep's recordings vertical (walk
/// L-C): two possible predecessor Block-child transcripts followed by two
/// possible `[R]_prev` transcripts. Exactly one block in each bank is live.
pub fn link_recordings_purpose() -> [u8; 32] {
    poseidon2b_hash_byte_slices(
        LINK_RECORDINGS_REC_PURPOSE_DOMAIN,
        &[
            crate::region_sidecar::BLOCK_SIDECAR_CHILD_DOMAIN,
            crate::acceptance::history_step::HISTORY_STEP_PROOF_DOMAIN,
        ],
    )
}

/// Walk L-B committed column layout (the wallet walk-B convention):
/// `C0..C3` at 0..4, `CR0..CR1` at 4..6, `SIB0..SIB1` at 6..8, `D` at 8.
const N_COMMITTED_B: usize = 9;

/// One verified proof's PCS side, as the assembly consumes it.
pub struct RPcsProof<'a> {
    pub native: &'a pcs::C1BaseFoldProof,
    pub params: &'a PcsParams,
    /// The initial codeword commitment root (flat lanes) — tree 0's root;
    /// the later trees' roots live in the proof itself.
    pub commitment_root: [F128; 2],
}

/// One authenticated tree of a proof: its leaf lane count and path depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TreeInfo {
    lanes: usize,
    depth: usize,
}

/// Canonical PCS carrier shared by the two possible HistoryStep parent tiers.
/// One authenticated predecessor occupies the tile/path axis. Its tier chooses
/// witness data from `groups` but never changes verifier topology.
#[derive(Clone, Debug)]
pub(crate) struct HistoryStepPcsCarrierGeometry {
    group_params: Vec<PcsParams>,
    groups: Vec<Vec<TreeInfo>>,
    n_queries: usize,
    proof_roles: usize,
}

impl HistoryStepPcsCarrierGeometry {
    fn subchannel_count(&self) -> usize {
        self.groups.iter().map(Vec::len).max().unwrap_or(0)
    }

    /// Exact L-A leaf schedule at each tree position. A smaller tier may omit a
    /// trailing committed FRI tree, in which case its tile carries a
    /// relation-valid ghost on that position; an existing tree may never
    /// change the lane count / leaf IV selected by the universal descriptor.
    fn leaf_lanes(&self) -> Result<Vec<usize>, RegionSidecarError> {
        let positions = self.subchannel_count();
        if positions < 2 {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let mut lanes = Vec::with_capacity(positions);
        for position in 0..positions {
            let mut present = self
                .groups
                .iter()
                .filter_map(|group| group.get(position))
                .map(|tree| tree.lanes);
            let first = present
                .next()
                .ok_or(RegionSidecarError::UnsupportedVkShape)?;
            if first < 2
                || first % 2 != 0
                || first > MAX_COMBINED_DUPLEX_DATA_LANES
                || present.any(|candidate| candidate != first)
            {
                return Err(RegionSidecarError::UnsupportedVkShape);
            }
            lanes.push(first);
        }
        Ok(lanes)
    }

    /// L-B's causal carrier depth at each tree position. A shorter live path
    /// exposes its root in `CR(actual_depth)`. A path which fills the carrier
    /// exposes the same value through the final feed-forward node expression.
    fn path_carrier_depths(&self) -> Result<Vec<usize>, RegionSidecarError> {
        let positions = self.subchannel_count();
        let mut depths = Vec::with_capacity(positions);
        for position in 0..positions {
            let max_actual = self
                .groups
                .iter()
                .filter_map(|group| group.get(position))
                .map(|tree| tree.depth)
                .max()
                .ok_or(RegionSidecarError::UnsupportedVkShape)?;
            if max_actual == 0 {
                return Err(RegionSidecarError::UnsupportedVkShape);
            }
            depths.push(max_actual);
        }
        Ok(depths)
    }
}

/// Two-role universal carrier for HistoryStep recursion.
///
/// L-A and L-B carry the selected predecessor through a max-shape topology.
/// L-C commits one Block-child transcript and one enclosing `[R]_prev`
/// transcript. Its fixed key contains both parent layouts, while the
/// authenticated selector binds the committed pair and the shared PCS
/// carrier to exactly one verifier arm.
#[derive(Clone, Debug)]
pub(crate) struct HistoryStepParentGeometry {
    carrier: HistoryStepPcsCarrierGeometry,
    child_layouts: Vec<DuplexLayout>,
    r_prev_layouts: Vec<DuplexLayout>,
    selected_recording_blocks: Vec<Vec<(DuplexLayout, usize)>>,
    rec_w_log: usize,
}

impl HistoryStepParentGeometry {
    fn from_parts(
        parent_params: &[PcsParams],
        child_layouts: Vec<DuplexLayout>,
        r_prev_layouts: Vec<DuplexLayout>,
    ) -> Result<Self, RegionSidecarError> {
        if parent_params.is_empty()
            || child_layouts.len() != parent_params.len()
            || r_prev_layouts.len() != parent_params.len()
            || child_layouts.iter().any(|layout| layout.slots.is_empty())
            || r_prev_layouts.iter().any(|layout| layout.slots.is_empty())
        {
            return Err(RegionSidecarError::BadVk);
        }
        let first = parent_params.first().ok_or(RegionSidecarError::BadVk)?;
        let n_queries = pcs::checked_fri_configuration(first.log_dim(), first.log_inv_rate)
            .map_err(|_| RegionSidecarError::UnsupportedVkShape)?
            .query_count;
        for params in parent_params {
            let config = pcs::checked_fri_configuration(params.log_dim(), params.log_inv_rate)
                .map_err(|_| RegionSidecarError::UnsupportedVkShape)?;
            if config.query_count != n_queries {
                return Err(RegionSidecarError::UnsupportedVkShape);
            }
        }
        let groups = parent_params
            .iter()
            .map(checked_tree_structure)
            .collect::<Result<Vec<_>, _>>()?;
        if groups.iter().any(|group| group.len() < 2) {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let carrier = HistoryStepPcsCarrierGeometry {
            group_params: parent_params.to_vec(),
            groups,
            n_queries,
            proof_roles: 1,
        };
        carrier.leaf_lanes()?;
        carrier.path_carrier_depths()?;
        if !(1..=3).contains(&child_layouts.len()) {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let mut arm_blocks = Vec::with_capacity(child_layouts.len());
        let mut common_w_log = None;
        let mut common_offsets = None;
        for arm in 0..child_layouts.len() {
            let layouts = [&child_layouts[arm], &r_prev_layouts[arm]];
            let (offsets, w_log) = pack_recording_only_blocks(&layouts);
            if common_w_log.is_some_and(|expected| expected != w_log)
                || common_offsets
                    .as_ref()
                    .is_some_and(|expected: &Vec<usize>| expected != &offsets)
            {
                return Err(RegionSidecarError::UnsupportedVkShape);
            }
            common_w_log = Some(w_log);
            common_offsets = Some(offsets.clone());
            arm_blocks.push(
                layouts
                    .into_iter()
                    .cloned()
                    .zip(offsets)
                    .collect::<Vec<_>>(),
            );
        }
        let selected_recording_blocks = arm_blocks;
        let rec_w_log = common_w_log.ok_or(RegionSidecarError::BadVk)?;
        Ok(Self {
            carrier,
            child_layouts,
            r_prev_layouts,
            selected_recording_blocks,
            rec_w_log,
        })
    }

    pub(crate) fn new(
        parent_params: &[PcsParams],
        child_layouts: Vec<DuplexLayout>,
        r_prev_layouts: Vec<DuplexLayout>,
    ) -> Result<Self, RegionSidecarError> {
        let tier_count = noid_chain::consensus::params::BLOCK_PAGE_CLASS_TIERS.len();
        if parent_params.len() != tier_count
            || child_layouts.len() != tier_count
            || r_prev_layouts.len() != tier_count
        {
            return Err(RegionSidecarError::BadVk);
        }
        Self::from_parts(parent_params, child_layouts, r_prev_layouts)
    }

    pub(crate) fn three_classes(
        parent_params: &[PcsParams],
        child_layouts: Vec<DuplexLayout>,
        r_prev_layouts: Vec<DuplexLayout>,
    ) -> Result<Self, RegionSidecarError> {
        if parent_params.len() != 3 || child_layouts.len() != 3 || r_prev_layouts.len() != 3 {
            return Err(RegionSidecarError::BadVk);
        }
        Self::from_parts(parent_params, child_layouts, r_prev_layouts)
    }

    pub(crate) fn tier_count(&self) -> usize {
        self.child_layouts.len()
    }

    /// The v2 parent has one proof and one matrix lane. Legacy callers still
    /// use `new`, which requires the original two-class bank.
    pub(crate) fn single(
        parent_params: &PcsParams,
        child_layout: DuplexLayout,
        r_prev_layout: DuplexLayout,
    ) -> Result<Self, RegionSidecarError> {
        Self::from_parts(
            std::slice::from_ref(parent_params),
            vec![child_layout],
            vec![r_prev_layout],
        )
    }

    pub(crate) fn child_layout(&self, slot: usize) -> Option<&DuplexLayout> {
        self.child_layouts.get(slot)
    }

    pub(crate) fn r_prev_layout(&self, slot: usize) -> Option<&DuplexLayout> {
        self.r_prev_layouts.get(slot)
    }

    #[cfg(test)]
    pub(crate) fn selected_recording_blocks(&self) -> &[Vec<(DuplexLayout, usize)>] {
        &self.selected_recording_blocks
    }

    pub(crate) fn canonical_vk(
        &self,
        spec: &noid_ivc_core::public_io::PublicIoSpec,
    ) -> Result<LinkRegionSidecarVk, RegionSidecarError> {
        let leaf_w_log = crate::region_sidecar::combined_duplex_protocol_w_log(
            &combined_leaf_descriptor(&self.carrier)?,
        )?;
        let (_, path_w_log) = link_path_geometry(&self.carrier)?;
        let (leaf, path, rec, selector) =
            canonical_link_walk_slices(spec, leaf_w_log, path_w_log, self.rec_w_log);
        self.vk_from_slices(leaf, path, rec, selector)
    }

    fn recording_union(
        &self,
        children: &[LayoutRecordedChannel],
        r_prev: &[LayoutRecordedChannel],
        active_slot: usize,
    ) -> Result<DuplexUnion, RegionSidecarError> {
        if children.len() != self.tier_count()
            || r_prev.len() != self.tier_count()
            || active_slot >= self.tier_count()
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        for (child, expected) in children.iter().zip(self.child_layouts.iter()) {
            if &child.layout != expected || child.data_flat.len() != expected.n_data {
                return Err(RegionSidecarError::UnsupportedVkShape);
            }
        }
        if r_prev
            .iter()
            .zip(self.r_prev_layouts.iter())
            .any(|(recording, layout)| {
                &recording.layout != layout || recording.data_flat.len() != layout.n_data
            })
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let specs = [
            (
                &children[active_slot].layout,
                children[active_slot].data_flat.as_slice(),
            ),
            (
                &r_prev[active_slot].layout,
                r_prev[active_slot].data_flat.as_slice(),
            ),
        ]
        .into_iter()
        .map(|(layout, data)| RecordingSpec {
            layout: layout.clone(),
            iv_flat: FsChannelUnionRecorder::capacity_iv_flat_c1(),
            data,
        })
        .collect::<Vec<_>>();
        Ok(build_recording_only_duplex_union(&specs))
    }

    fn vk_from_slices(
        &self,
        leaf_slices: [WitnessSlice; 6],
        path_slices: [WitnessSlice; N_COMMITTED_B],
        rec_slices: [WitnessSlice; 6],
        selector_slice: WitnessSlice,
    ) -> Result<LinkRegionSidecarVk, RegionSidecarError> {
        let leaf = CombinedDuplexRegionVk::new(
            link_r_pcs_leaf_sidecar_purpose(),
            combined_leaf_descriptor(&self.carrier)?,
            leaf_slices,
        )?;
        let path_geometry = dense_path_geometry(&self.carrier)?;
        let families = path_geometry
            .carrier_depths
            .iter()
            .copied()
            .zip(path_geometry.family_offsets.iter().copied())
            .zip(path_geometry.family_path_counts.iter().copied())
            .map(
                |((depth, offset), n_paths)| MerkleRegionFamily::FeedForwardStrided {
                    offset,
                    depth,
                    n_paths,
                    stride: depth,
                    iv: pcs_node_iv_flat(),
                },
            )
            .collect();
        let path = MerkleRegionVk::new(
            link_r_pcs_path_sidecar_purpose(),
            path_geometry.w_log,
            path_slices,
            path_geometry.w_log,
            families,
        )?;
        let rec = self.recording_vk(rec_slices, selector_slice)?;
        LinkRegionSidecarVk::new(leaf, path, rec)
    }

    fn recording_vk(
        &self,
        slices: [WitnessSlice; 6],
        selector: WitnessSlice,
    ) -> Result<RecordingDuplexRegionVk, RegionSidecarError> {
        match self.selected_recording_blocks.as_slice() {
            [single] => RecordingDuplexRegionVk::new_fixed(
                link_recordings_purpose(),
                self.rec_w_log,
                slices,
                single.clone(),
            ),
            [first, second] => RecordingDuplexRegionVk::new_selected(
                link_recordings_purpose(),
                self.rec_w_log,
                slices,
                selector,
                [first.clone(), second.clone()],
            ),
            [first, second, third] => RecordingDuplexRegionVk::new_selected(
                link_recordings_purpose(),
                self.rec_w_log,
                slices,
                selector,
                [first.clone(), second.clone(), third.clone()],
            ),
            _ => Err(RegionSidecarError::BadVk),
        }
    }
}

/// The per-proof tree ladder, mirroring `basefold_verify_trace`'s shape
/// math: the initial codeword tree, the post-row-batch tree, then one
/// tree per FRI epoch commitment.
fn checked_tree_structure(params: &PcsParams) -> Result<Vec<TreeInfo>, RegionSidecarError> {
    if !(1..=5).contains(&params.log_inv_rate) {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let log_msg_len = params
        .m
        .checked_sub(pcs::LOG_PACKING)
        .ok_or(RegionSidecarError::UnsupportedVkShape)?;
    let log_batch_size = params.log_batch_size;
    let log_dim = log_msg_len
        .checked_sub(log_batch_size)
        .ok_or(RegionSidecarError::UnsupportedVkShape)?;
    let k_code = log_dim
        .checked_add(params.log_inv_rate)
        .ok_or(RegionSidecarError::BadVk)?;
    // Query-position sampling accepts at most 64 bits, while every concrete
    // vector/domain below also needs `2^log` to fit in `usize`.
    if log_batch_size >= usize::BITS as usize
        || k_code == 0
        || k_code > 64
        || k_code >= usize::BITS as usize
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let arities = pcs::compute_fri_arities(log_dim);
    let (num_fri_commits, _) = pcs::fri_commit_layout(k_code, &arities);
    let arity_0 = arities.first().copied().unwrap_or(0);
    let initial_lanes = 1usize << log_batch_size;
    if initial_lanes > MAX_COMBINED_DUPLEX_DATA_LANES {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let mut trees = vec![TreeInfo {
        lanes: initial_lanes,
        depth: k_code,
    }];
    if !arities.is_empty() {
        trees.push(TreeInfo {
            lanes: 2usize << arity_0,
            depth: k_code
                .checked_sub(arity_0)
                .ok_or(RegionSidecarError::BadVk)?,
        });
        let mut cum = arity_0;
        for i in 0..num_fri_commits {
            let next = *arities.get(i + 1).ok_or(RegionSidecarError::BadVk)?;
            let depth = k_code
                .checked_sub(cum)
                .and_then(|remaining| remaining.checked_sub(next))
                .ok_or(RegionSidecarError::BadVk)?;
            trees.push(TreeInfo {
                lanes: 2usize << next,
                depth,
            });
            cum = cum.checked_add(next).ok_or(RegionSidecarError::BadVk)?;
        }
    }
    if trees.iter().any(|tree| tree.depth == 0) {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    Ok(trees)
}

/// The native leaf lanes of tree `t` for query `q`.
fn native_leaf_lanes(q: &pcs::C1QueryOpening, t: usize) -> Vec<F128> {
    match t {
        0 => q.initial_leaf.clone(),
        1 => q
            .post_row_batch_leaf
            .iter()
            .flat_map(|value| [value.lo, value.hi])
            .collect(),
        _ => q.epoch_leaves[t - 2]
            .iter()
            .flat_map(|value| [value.lo, value.hi])
            .collect(),
    }
}

/// The native sibling digests of tree `t` for query `q`, bottom-up flat.
fn native_path(q: &pcs::C1QueryOpening, t: usize) -> Vec<[F128; 2]> {
    let path = match t {
        0 => &q.initial_path,
        1 => &q.post_row_batch_path,
        _ => &q.epoch_paths[t - 2],
    };
    path.iter().map(flat_digest_lanes).collect()
}

/// The native root lanes of tree `t` (tree 0's root is the commitment,
/// supplied by the caller).
fn native_root(p: &RPcsProof<'_>, t: usize) -> [F128; 2] {
    match t {
        0 => p.commitment_root,
        1 => flat_digest_lanes(&p.native.post_row_batch_commit.root),
        _ => flat_digest_lanes(&p.native.round_commitments[t - 2].root),
    }
}

/// The direction-bit offset of tree `t`'s path within the query-position
/// bits (mirror of the replay's `&bits[..]` slices).
fn dir_bit_offset(trees: &[TreeInfo], t: usize, k_code: usize) -> usize {
    // depth = k_code - offset for every tree.
    k_code - trees[t].depth
}

/// Native leaf digest: `merkle::hash_leaf` over the flat lane bytes.
fn native_leaf_digest(lanes: &[F128]) -> [F128; 2] {
    let mut bytes = Vec::with_capacity(lanes.len() * 16);
    for l in lanes {
        let v = (l.lo as u128) | ((l.hi as u128) << 64);
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    flat_digest_lanes(&noid_ivc_core::merkle::hash_leaf(&bytes))
}

/// HistoryStep parent walk assembly. Its L-A union is the exact
/// recording-free output of [`build_combined_duplex_union`], while L-B remains
/// an independent sibling vertical.
struct RecordingFreeLinkAssembly {
    u_a: DuplexUnion,
    leaf_descriptor: CombinedDuplexRegionDescriptor,
    /// Tree ladders for every selectable verifier arm.
    all_trees: Vec<Vec<TreeInfo>>,
    /// Universal leaf lane count indexed by tree position.
    leaf_lanes: Vec<usize>,
    /// Global-within-tile `(slot, A-lane)` data cells per tree-position
    /// subchannel.
    leaf_data_positions: Vec<Vec<(usize, usize)>>,
    s_log: usize,
    n_queries: usize,
    cb: Vec<Vec<F128>>,
    s0b: [Vec<F128>; STATE_SIZE],
    soutb: [Vec<F128>; STATE_SIZE],
    path_families: Vec<MerkleRegionFamily>,
    /// L-B max-depth carrier offset indexed by tree position.
    leg_offsets: Vec<usize>,
    carrier_depths: Vec<usize>,
    block_log_b: usize,
    w_log_b: usize,
}

fn combined_leaf_descriptor(
    geometry: &HistoryStepPcsCarrierGeometry,
) -> Result<CombinedDuplexRegionDescriptor, RegionSidecarError> {
    let subchannels = geometry
        .leaf_lanes()?
        .into_iter()
        .map(|lanes| {
            CombinedDuplexSubChannelDescriptor::new(
                vec![TranscriptOp::Absorb(vec![None; lanes])],
                pcs_leaf_iv_flat(lanes),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    // HistoryStep has exactly one predecessor proof/query role.
    let live_tiles = geometry
        .proof_roles
        .checked_mul(geometry.n_queries)
        .ok_or(RegionSidecarError::BadVk)?;
    let padded_tiles = live_tiles
        .max(1)
        .checked_next_power_of_two()
        .ok_or(RegionSidecarError::BadVk)?;
    let tx_tile_log = padded_tiles.trailing_zeros() as usize;
    CombinedDuplexRegionDescriptor::new(tx_tile_log, subchannels)
}

struct DensePathGeometry {
    carrier_depths: Vec<usize>,
    family_offsets: Vec<usize>,
    family_path_counts: Vec<usize>,
    n_paths: usize,
    active_slots: usize,
    w_log: usize,
}

/// Family-major packing of the universal link walk L-B. Every path keeps its
/// exact causal node order, while dyadic padding is paid only once by the
/// complete shared column rather than once per query.
fn dense_path_geometry(
    geometry: &HistoryStepPcsCarrierGeometry,
) -> Result<DensePathGeometry, RegionSidecarError> {
    let carrier_depths = geometry.path_carrier_depths()?;
    let n_paths = geometry
        .proof_roles
        .checked_mul(geometry.n_queries)
        .ok_or(RegionSidecarError::BadVk)?;
    if n_paths == 0 {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let live_slots = carrier_depths.iter().try_fold(0usize, |sum, depth| {
        sum.checked_add(
            n_paths
                .checked_mul(*depth)
                .ok_or(RegionSidecarError::BadVk)?,
        )
        .ok_or(RegionSidecarError::BadVk)
    })?;
    let cells = live_slots
        .checked_next_power_of_two()
        .ok_or(RegionSidecarError::BadVk)?;

    // Every slot must belong to a relation family: an uncovered dyadic tail
    // has no ghost-carry substitution term. Fill that tail with the minimum
    // number of ordinary, unpinned paths over the existing carrier depths.
    let padding = cells - live_slots;
    let mut best = vec![usize::MAX; padding + 1];
    let mut previous = vec![None; padding + 1];
    best[0] = 0;
    for total in 1..=padding {
        for (family, depth) in carrier_depths.iter().copied().enumerate() {
            if total >= depth && best[total - depth] != usize::MAX {
                let candidate = best[total - depth] + 1;
                if candidate < best[total] {
                    best[total] = candidate;
                    previous[total] = Some(family);
                }
            }
        }
    }
    if best[padding] == usize::MAX {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let mut extra_paths = vec![0usize; carrier_depths.len()];
    let mut remaining = padding;
    while remaining != 0 {
        let family = previous[remaining].ok_or(RegionSidecarError::BadVk)?;
        extra_paths[family] += 1;
        remaining -= carrier_depths[family];
    }
    let family_path_counts = extra_paths
        .into_iter()
        .map(|extra| n_paths.checked_add(extra).ok_or(RegionSidecarError::BadVk))
        .collect::<Result<Vec<_>, _>>()?;

    let mut active_slots = 0usize;
    let mut family_offsets = Vec::with_capacity(carrier_depths.len());
    for (&depth, &path_count) in carrier_depths.iter().zip(&family_path_counts) {
        family_offsets.push(active_slots);
        active_slots = active_slots
            .checked_add(
                path_count
                    .checked_mul(depth)
                    .ok_or(RegionSidecarError::BadVk)?,
            )
            .ok_or(RegionSidecarError::BadVk)?;
    }
    if active_slots != cells {
        return Err(RegionSidecarError::BadVk);
    }
    Ok(DensePathGeometry {
        carrier_depths,
        family_offsets,
        family_path_counts,
        n_paths,
        active_slots,
        w_log: cells.trailing_zeros() as usize,
    })
}

/// Path carrier packing of the universal link walk L-B: `(block_log, w_log)`.
fn link_path_geometry(
    geometry: &HistoryStepPcsCarrierGeometry,
) -> Result<(usize, usize), RegionSidecarError> {
    let dense = dense_path_geometry(geometry)?;
    Ok((dense.w_log, dense.w_log))
}

/// The canonical walk-column [`WitnessSlice`] table of every HistoryStep class:
/// columns are allocated right after the public-IO block in the exact
/// minimum-span order for the production domains: leaves, paths, recordings.
/// Each family remains aligned to its own width.
/// Mirrors `alloc_column_slice` exactly.
pub(crate) fn canonical_link_walk_slices(
    spec: &noid_ivc_core::public_io::PublicIoSpec,
    leaf_w_log: usize,
    path_w_log: usize,
    rec_w_log: usize,
) -> (
    [WitnessSlice; 6],
    [WitnessSlice; N_COMMITTED_B],
    [WitnessSlice; 6],
    WitnessSlice,
) {
    fn family<const N: usize>(cursor: &mut usize, w_log: usize) -> [WitnessSlice; N] {
        let len = 1usize << w_log;
        *cursor = cursor.next_multiple_of(len);
        let base = *cursor / len;
        *cursor += N * len;
        std::array::from_fn(|column| WitnessSlice {
            log2_len: w_log,
            index: base + column,
        })
    }
    let mut cursor = spec.io_slice.start() + (1usize << spec.io_slice.log2_len);
    let leaf = family(&mut cursor, leaf_w_log);
    let path = family(&mut cursor, path_w_log);
    let rec = family(&mut cursor, rec_w_log);
    let selector = family::<1>(&mut cursor, 0)[0];
    (leaf, path, rec, selector)
}

fn build_recording_free_link_assembly(
    proofs: &[RPcsProof<'_>],
    geometry: &HistoryStepPcsCarrierGeometry,
    active_groups: &[usize],
) -> Result<RecordingFreeLinkAssembly, RegionSidecarError> {
    if proofs.is_empty()
        || proofs.len() != active_groups.len()
        || proofs.len() != geometry.proof_roles
        || proofs.len() > 2
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    // The active group is the predecessor's output tier; universal carrier
    // topology stays unchanged by that selection.
    if active_groups
        .iter()
        .any(|group| *group >= geometry.groups.len())
        || (proofs.len() == 2 && (active_groups[0] != 0 || active_groups[1] == 0))
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let trees = proofs
        .iter()
        .map(|proof| checked_tree_structure(proof.params))
        .collect::<Result<Vec<_>, _>>()?;
    let n_queries = geometry.n_queries;
    if proofs
        .iter()
        .any(|proof| proof.native.queries.len() != n_queries)
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    for (proof_index, actual) in trees.iter().enumerate() {
        let active_group = active_groups[proof_index];
        if actual != &geometry.groups[active_group]
            || pcs_params_statement_bytes(proofs[proof_index].params)
                != pcs_params_statement_bytes(&geometry.group_params[active_group])
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
    }
    let universal_leaf_lanes = geometry.leaf_lanes()?;
    let leaf_descriptor = combined_leaf_descriptor(geometry)?;
    let subs = leaf_descriptor
        .subchannels()
        .iter()
        .map(|descriptor| SubChannel {
            layout: compile_duplex(descriptor.schedule()),
            iv_flat: descriptor.iv_flat(),
        })
        .collect::<Vec<_>>();
    let s = subs
        .iter()
        .map(|subchannel| subchannel.layout.slots.len())
        .max()
        .unwrap_or(1)
        .max(1)
        .next_power_of_two();
    let s_log = s.trailing_zeros() as usize;

    let leaf_data_positions = subs
        .iter()
        .enumerate()
        .map(|(subchannel, sub)| {
            duplex_data_positions(&sub.layout)
                .into_iter()
                .map(|(slot, lane)| (subchannel * s + slot, lane))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let tile_capacity = proofs
        .len()
        .checked_mul(n_queries)
        .ok_or(RegionSidecarError::BadVk)?;
    let mut tiles = Vec::with_capacity(tile_capacity);
    let mut digests = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let mut per_proof = Vec::with_capacity(n_queries);
        for query in &proof.native.queries {
            let mut tile = subs
                .iter()
                .map(|sub| vec![F128::ZERO; sub.layout.n_data])
                .collect::<Vec<_>>();
            let proof_index = digests.len();
            let mut query_digests = Vec::with_capacity(subs.len());
            for tree in 0..subs.len() {
                let lanes = if let Some(actual) = trees[proof_index].get(tree) {
                    let lanes = native_leaf_lanes(query, tree);
                    if lanes.len() != actual.lanes {
                        return Err(RegionSidecarError::UnsupportedVkShape);
                    }
                    lanes
                } else {
                    vec![F128::ZERO; universal_leaf_lanes[tree]]
                };
                query_digests.push(native_leaf_digest(&lanes));
                tile[tree] = lanes;
            }
            tiles.push(tile);
            per_proof.push(query_digests);
        }
        digests.push(per_proof);
    }
    let u_a = build_combined_duplex_union(&subs, &tiles);
    if !u_a.rec_blocks.is_empty() || !u_a.rec_refs.is_empty() || !u_a.rec_challenges.is_empty() {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }

    let iv_node = pcs_node_iv_flat();
    let dense_path = dense_path_geometry(geometry)?;
    if dense_path.n_paths != proofs.len() * n_queries {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let carrier_depths = dense_path.carrier_depths;
    let leg_offsets = dense_path.family_offsets;
    let family_path_counts = dense_path.family_path_counts;
    let live_blocks_b = dense_path.n_paths;
    let block_log_b = dense_path.w_log;
    let w_log_b = dense_path.w_log;
    let pb = 1usize << w_log_b;

    let mut cb = (0..N_COMMITTED_B)
        .map(|_| vec![F128::ZERO; pb])
        .collect::<Vec<_>>();
    let mut s0b: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; pb]);
    let mut soutb: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; pb]);

    let mut path_families = Vec::new();
    for (tree_index, &carrier_depth) in carrier_depths.iter().enumerate() {
        let family_path_count = family_path_counts[tree_index];
        let family = FfMerklePathFamily {
            depth: carrier_depth,
            n_paths: family_path_count,
        };
        let source_stride = family.stride();
        path_families.push(MerkleRegionFamily::FeedForwardStrided {
            offset: leg_offsets[tree_index],
            depth: carrier_depth,
            n_paths: family_path_count,
            stride: carrier_depth,
            iv: iv_node,
        });

        let mut actual_trees = Vec::with_capacity(family_path_count);
        let mut witnesses = Vec::with_capacity(family_path_count);
        for block_index in 0..family_path_count {
            let (actual, witness) = if block_index < live_blocks_b {
                let proof_index = block_index / n_queries;
                let query_index = block_index % n_queries;
                let query = &proofs[proof_index].native.queries[query_index];
                let actual = trees[proof_index].get(tree_index).copied();
                let witness = if let Some(tree) = actual {
                    let bit_offset = dir_bit_offset(
                        &trees[proof_index],
                        tree_index,
                        trees[proof_index][0].depth,
                    );
                    let mut siblings = native_path(query, tree_index);
                    siblings.resize(carrier_depth, [F128::ZERO; 2]);
                    let mut directions = (0..tree.depth)
                        .map(|level| (query.position >> (bit_offset + level)) & 1 == 1)
                        .collect::<Vec<_>>();
                    directions.resize(carrier_depth, false);
                    FfMerklePathWitness {
                        entry: digests[proof_index][query_index][tree_index],
                        siblings,
                        directions,
                    }
                } else {
                    FfMerklePathWitness {
                        entry: digests[proof_index][query_index][tree_index],
                        siblings: vec![[F128::ZERO; 2]; carrier_depth],
                        directions: vec![false; carrier_depth],
                    }
                };
                (actual.map(|tree| (proof_index, tree)), witness)
            } else {
                (
                    None,
                    FfMerklePathWitness {
                        entry: [F128::ZERO; 2],
                        siblings: vec![[F128::ZERO; 2]; carrier_depth],
                        directions: vec![false; carrier_depth],
                    },
                )
            };
            actual_trees.push(actual);
            witnesses.push(witness);
        }
        let source_slots = family_path_count
            .checked_mul(source_stride)
            .ok_or(RegionSidecarError::BadVk)?
            .checked_next_power_of_two()
            .ok_or(RegionSidecarError::BadVk)?;
        let columns = build_ff_merkle_path_columns(
            &family,
            iv_node,
            &witnesses,
            source_slots.trailing_zeros() as usize,
        );
        for (block_index, actual) in actual_trees.into_iter().enumerate() {
            let source = block_index * source_stride;
            let destination = leg_offsets[tree_index] + block_index * carrier_depth;
            if let Some((proof_index, tree)) = actual {
                let root = if tree.depth < carrier_depth {
                    [
                        columns.cr[0][source + tree.depth],
                        columns.cr[1][source + tree.depth],
                    ]
                } else {
                    columns.roots[block_index]
                };
                assert_eq!(
                    root,
                    native_root(&proofs[proof_index], tree_index),
                    "ff carrier prefix root != committed root (proof {proof_index}, tree {tree_index}, block {block_index})"
                );
            }
            for level in 0..carrier_depth {
                let from = source + level;
                let to = destination + level;
                for lane in 0..2 {
                    cb[4 + lane][to] = columns.cr[lane][from];
                    cb[6 + lane][to] = columns.sib[lane][from];
                }
                cb[8][to] = columns.d[from];
                for lane in 0..STATE_SIZE {
                    cb[lane][to] = columns.c[lane][from];
                    s0b[lane][to] = columns.s0[lane][from];
                    soutb[lane][to] = columns.s_out[lane][from];
                }
            }
        }
    }

    if dense_path.active_slots != pb {
        return Err(RegionSidecarError::BadVk);
    }

    let per_tile = 1usize << u_a.block_log;
    for (proof_index, per_proof) in digests.iter().enumerate() {
        for (query_index, query_digests) in per_proof.iter().enumerate() {
            let tile_offset = (proof_index * n_queries + query_index) * per_tile;
            for (tree_index, digest) in query_digests.iter().enumerate() {
                let digest_slot =
                    tile_offset + tree_index * s + universal_leaf_lanes[tree_index] / 2 - 1;
                assert_eq!(
                    [u_a.committed[2][digest_slot], u_a.committed[3][digest_slot]],
                    *digest,
                    "leaf digest cell mismatch (proof {proof_index}, query {query_index}, tree {tree_index})"
                );
            }
        }
    }

    Ok(RecordingFreeLinkAssembly {
        u_a,
        leaf_descriptor,
        all_trees: geometry.groups.clone(),
        leaf_lanes: universal_leaf_lanes,
        leaf_data_positions,
        s_log,
        n_queries,
        cb,
        s0b,
        soutb,
        path_families,
        leg_offsets,
        carrier_depths,
        block_log_b,
        w_log_b,
    })
}

/// Self-recursive HistoryStep columns over the universal two-arm parent
/// geometry. Walk L-C carries one selected nested Block-child transcript and
/// one selected enclosing `[R]_prev` chain.
pub(crate) struct HistoryStepParentColumns {
    asm: RecordingFreeLinkAssembly,
    slices_a: [WitnessSlice; 6],
    slices_b: [WitnessSlice; N_COMMITTED_B],
    slices_rec: [WitnessSlice; 6],
    recording_constraint_slots: BTreeMap<(usize, usize), DeferredConstraintSlot>,
    selector_slice: WitnessSlice,
    u_rec: DuplexUnion,
    child_scratches: Vec<LayoutRecordedChannel>,
    r_prev_scratches: Vec<LayoutRecordedChannel>,
    active_slot: usize,
    vk: LinkRegionSidecarVk,
}

impl HistoryStepParentColumns {
    pub(crate) fn align_shared_replay_hints(
        &mut self,
        builder: &FieldR1csBuilder,
        children: &[FsRecordedChannel],
        parents: &[FsRecordedChannel],
    ) -> Result<(), RegionSidecarError> {
        if children.len() != 3
            || parents.len() != 3
            || self.child_scratches.len() != 3
            || self.r_prev_scratches.len() != 3
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        for arm in [1, 2] {
            if arm == self.active_slot {
                continue;
            }
            for (scratch, replay) in [
                (&mut self.child_scratches[arm], &children[arm]),
                (&mut self.r_prev_scratches[arm], &parents[arm]),
            ] {
                let layout = compile_duplex(&replay.ops);
                if layout != scratch.layout
                    || layout.n_data != replay.data_flat.len()
                    || layout.n_data != replay.data_wires.len()
                    || layout.challenges.len() != replay.challenge_wires.len()
                    || replay.perms != scratch.perms
                {
                    return Err(RegionSidecarError::UnsupportedVkShape);
                }
                *scratch = LayoutRecordedChannel {
                    layout,
                    data_flat: replay.data_flat.clone(),
                    challenges: replay
                        .challenge_wires
                        .iter()
                        .map(|value| Some(value.eval(builder.values())))
                        .collect(),
                    post_state: replay.post_state,
                    perms: replay.perms,
                };
            }
        }
        Ok(())
    }
}

fn allocate_selected_recording_columns(
    b: &mut FieldR1csBuilder,
    columns: &[Vec<F128>; 6],
    w_log: usize,
    arms: &[Vec<(DuplexLayout, usize)>],
) -> (
    [WitnessSlice; 6],
    BTreeMap<(usize, usize), DeferredConstraintSlot>,
) {
    let block = 1usize << w_log;
    assert!(columns.iter().all(|column| column.len() == block));
    let mut selected_cells: [std::collections::BTreeSet<usize>; 6] =
        std::array::from_fn(|_| std::collections::BTreeSet::new());
    for arm in arms {
        for (layout, base) in arm {
            for &(slot, lane) in &layout.challenges {
                selected_cells[2 + lane].insert(base + slot);
            }
            for (slot, lane) in duplex_data_positions(layout) {
                selected_cells[lane].insert(base + slot);
            }
        }
    }

    let mut slices = Vec::with_capacity(6);
    let mut slots = BTreeMap::new();
    for column in 0..6 {
        while b.num_wires() % block != 0 {
            b.alloc_f128(F128::ZERO);
        }
        let index = b.num_wires() / block;
        for (offset, &value) in columns[column].iter().enumerate() {
            if selected_cells[column].contains(&offset) {
                let (_, slot) = b.alloc_deferred_constraint_f128(value);
                assert!(slots.insert((column, offset), slot).is_none());
            } else {
                b.alloc_f128(value);
            }
        }
        slices.push(WitnessSlice {
            log2_len: w_log,
            index,
        });
    }
    (
        slices.try_into().expect("six recording column slices"),
        slots,
    )
}

pub(crate) fn prepare_history_step_parent_columns(
    b: &mut FieldR1csBuilder,
    proofs: &[RPcsProof<'_>],
    active_slot: usize,
    geometry: &HistoryStepParentGeometry,
    child_recordings: Vec<LayoutRecordedChannel>,
    r_prev_recordings: Vec<LayoutRecordedChannel>,
) -> Result<HistoryStepParentColumns, RegionSidecarError> {
    if proofs.len() != geometry.tier_count() || active_slot >= geometry.tier_count() {
        return Err(RegionSidecarError::BadVk);
    }
    let asm = build_recording_free_link_assembly(
        std::slice::from_ref(&proofs[active_slot]),
        &geometry.carrier,
        &[active_slot],
    )?;
    let u_rec = geometry.recording_union(&child_recordings, &r_prev_recordings, active_slot)?;
    let slices_a = std::array::from_fn(|column| {
        alloc_column_slice_values_only(b, &asm.u_a.committed[column], asm.u_a.w_log)
    });
    let slices_b = std::array::from_fn(|column| {
        if column == 8 {
            alloc_boolean_column_slice_values_only(b, &asm.cb[column], asm.w_log_b)
        } else {
            alloc_column_slice_values_only(b, &asm.cb[column], asm.w_log_b)
        }
    });
    let (slices_rec, recording_constraint_slots) = allocate_selected_recording_columns(
        b,
        &u_rec.committed,
        u_rec.w_log,
        &geometry.selected_recording_blocks,
    );
    let selector_slice = if geometry.selected_recording_blocks.len() == 3 {
        alloc_column_slice_values_only(
            b,
            &[noid_ivc_core::field_circuit::f128_from_u128(
                active_slot as u128,
            )],
            0,
        )
    } else {
        alloc_boolean_column_slice_values_only(
            b,
            &[if active_slot == 1 {
                F128::ONE
            } else {
                F128::ZERO
            }],
            0,
        )
    };

    let leaf_vk = CombinedDuplexRegionVk::from_union(
        link_r_pcs_leaf_sidecar_purpose(),
        asm.leaf_descriptor.clone(),
        slices_a,
        &asm.u_a,
    )?;
    let path_vk = MerkleRegionVk::new(
        link_r_pcs_path_sidecar_purpose(),
        asm.w_log_b,
        slices_b,
        asm.block_log_b,
        asm.path_families.clone(),
    )?;
    let rec_vk = geometry.recording_vk(slices_rec, selector_slice)?;
    if u_rec.w_log != geometry.rec_w_log
        || u_rec.rec_blocks != geometry.selected_recording_blocks[active_slot]
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let vk = LinkRegionSidecarVk::new(leaf_vk, path_vk, rec_vk)?;
    if vk != geometry.vk_from_slices(slices_a, slices_b, slices_rec, selector_slice)? {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    Ok(HistoryStepParentColumns {
        asm,
        slices_a,
        slices_b,
        slices_rec,
        recording_constraint_slots,
        selector_slice,
        u_rec,
        child_scratches: child_recordings,
        r_prev_scratches: r_prev_recordings,
        active_slot,
        vk,
    })
}

/// Production predecessor-recursion preparation for the three HistoryStep
/// parent sidecar verticals.
pub(crate) struct HistoryStepParentRegionPreparation {
    vk: LinkRegionSidecarVk,
    input: LinkRegionProverInput,
}

impl HistoryStepParentRegionPreparation {
    pub(crate) fn vk(&self) -> &LinkRegionSidecarVk {
        &self.vk
    }

    pub(crate) fn certified_c1_prover_plan(
        &self,
    ) -> Result<LinkRegionProverPlan<'_>, RegionSidecarError> {
        LinkRegionProverPlan::new_certified_c1(&self.vk, &self.input)
    }
}

/// Validate one recorded replay and return every semantic source wire keyed by
/// its physical recording-column cell. The caller combines both parent arms
/// before emitting constraints, so selecting a different honest parent never
/// changes matrix topology.
fn recording_block_bindings(
    b: &FieldR1csBuilder,
    what: &str,
    scratch: &LayoutRecordedChannel,
    recorded: &FsRecordedChannel,
    expected_block: &(DuplexLayout, usize),
) -> BTreeMap<(usize, usize), LinExpr> {
    assert_eq!(
        compile_duplex(&recorded.ops),
        scratch.layout,
        "{what} recording schedule drift"
    );
    assert_eq!(
        recorded.data_flat, scratch.data_flat,
        "{what} recording data drift"
    );
    assert_eq!(
        recorded.post_state, scratch.post_state,
        "{what} recording post-state drift"
    );
    assert_eq!(
        recorded.perms, scratch.perms,
        "{what} permutation-count drift"
    );
    let (rec_layout, rec_offset) = expected_block;
    assert_eq!(
        recorded.challenge_wires.len(),
        rec_layout.challenges.len(),
        "{what} recording challenge count"
    );
    assert_eq!(
        recorded.data_wires.len(),
        rec_layout.n_data,
        "{what} recording data count"
    );
    let mut bindings = BTreeMap::new();
    for (k, &(slot, lane)) in rec_layout.challenges.iter().enumerate() {
        if let Some(native) = scratch.challenges[k] {
            assert_eq!(
                recorded.challenge_wires[k].eval(b.values()),
                native,
                "{what} native/trace challenge {k} drift"
            );
        }
        assert!(
            bindings
                .insert(
                    (2 + lane, rec_offset + slot),
                    recorded.challenge_wires[k].clone(),
                )
                .is_none(),
            "{what} duplicate recording challenge cell"
        );
    }
    for (k, &(slot, lane)) in duplex_data_positions(rec_layout).iter().enumerate() {
        assert!(
            bindings
                .insert((lane, rec_offset + slot), recorded.data_wires[k].clone(),)
                .is_none(),
            "{what} duplicate recording data cell"
        );
    }
    bindings
}

/// Bind one recording role shared by the two possible parent classes. Every
/// selected source uses one product row, while the committed cell's reserved
/// tautology row is replaced by the final equality. This emits the same
/// topology for either parent without paying a second pin row per cell.
#[allow(clippy::too_many_arguments)]
fn pin_selected_recording_role(
    b: &mut FieldR1csBuilder,
    what: &str,
    scratches: &[LayoutRecordedChannel],
    recordings: &[FsRecordedChannel],
    rec_vk: &RecordingDuplexRegionVk,
    arm_selectors: &[LinExpr],
    active_slot: usize,
    role: usize,
    u_rec: &DuplexUnion,
    slices_rec: &[WitnessSlice; 6],
    union_block: usize,
    constraint_slots: &mut BTreeMap<(usize, usize), DeferredConstraintSlot>,
) -> Result<(), RegionSidecarError> {
    let arms = scratches.len();
    if !(1..=3).contains(&arms)
        || recordings.len() != arms
        || arm_selectors.len() != arms
        || active_slot >= arms
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }

    let mut selected_bindings: BTreeMap<(usize, usize), [Option<LinExpr>; 3]> = BTreeMap::new();
    for arm in 0..arms {
        let block = rec_vk
            .selected_block(arm, role)
            .ok_or(RegionSidecarError::UnsupportedVkShape)?;
        let bindings = recording_block_bindings(b, what, &scratches[arm], &recordings[arm], block);
        if arm == active_slot {
            assert_eq!(
                u_rec.rec_blocks[union_block], *block,
                "{what} selected recording geometry"
            );
            assert_eq!(
                recordings[arm].challenge_wires.len(),
                u_rec.rec_challenges[union_block].len(),
                "{what} selected recording challenge count"
            );
            for (k, wire) in recordings[arm].challenge_wires.iter().enumerate() {
                assert_eq!(
                    wire.eval(b.values()),
                    u_rec.rec_challenges[union_block][k],
                    "{what} recording challenge {k} lockstep"
                );
            }
        }
        for (cell, expression) in bindings {
            assert!(
                selected_bindings.entry(cell).or_default()[arm]
                    .replace(expression)
                    .is_none(),
                "{what} duplicate arm binding"
            );
        }
    }

    for ((column, offset), sources) in selected_bindings {
        let cell = slot_cell(&slices_rec[column], offset);
        let constraint_slot = constraint_slots
            .remove(&(column, offset))
            .ok_or(RegionSidecarError::UnsupportedVkShape)?;
        let one = b.one();
        if arms == 3 {
            let mut expression = cell.clone();
            for (selector, source) in arm_selectors.iter().zip(&sources) {
                if let Some(source) = source {
                    expression = expression.add(&mul(b, selector, &source.add(&cell)));
                }
            }
            b.seal_deferred_constraint(constraint_slot, &expression, &one)
                .map_err(|_| RegionSidecarError::InvalidProof)?;
            continue;
        }
        match sources {
            [Some(arm0), Some(arm1), None] => {
                let product = mul(b, &arm_selectors[1], &arm0.add(&arm1));
                b.seal_deferred_constraint(constraint_slot, &arm0.add(&product), &one)
                    .map_err(|_| RegionSidecarError::InvalidProof)?;
            }
            [Some(source), None, None] if arms == 1 => {
                b.seal_deferred_constraint(constraint_slot, &source, &one)
                    .map_err(|_| RegionSidecarError::InvalidProof)?;
            }
            [Some(source), None, None] => {
                let product = mul(b, &arm_selectors[0], &source.add(&cell));
                b.seal_deferred_constraint(constraint_slot, &cell.add(&product), &one)
                    .map_err(|_| RegionSidecarError::InvalidProof)?;
            }
            [None, Some(source), None] => {
                let product = mul(b, &arm_selectors[1], &source.add(&cell));
                b.seal_deferred_constraint(constraint_slot, &cell.add(&product), &one)
                    .map_err(|_| RegionSidecarError::InvalidProof)?;
            }
            _ => unreachable!("recording binding without a source"),
        }
    }
    Ok(())
}

fn checked_pcs_binding_groups(
    b: &mut FieldR1csBuilder,
    trees: &[Vec<TreeInfo>],
    obligations: &[PcsWalkObligations],
    selectors: &[LinExpr],
) -> Result<Vec<(usize, LinExpr)>, RegionSidecarError> {
    if trees.len() != selectors.len() || obligations.len() != selectors.len() {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let mut groups: Vec<(usize, LinExpr)> = Vec::new();
    for (arm, selector) in selectors.iter().enumerate() {
        let non_boolean = mul(b, selector, &selector.add_const(F128::ONE));
        pin_eq(b, &non_boolean, &LinExpr::zero());
        for other in &selectors[..arm] {
            let both = mul(b, selector, other);
            pin_eq(b, &both, &LinExpr::zero());
        }
        if let Some((_, combined)) = groups.iter_mut().find(|(prior, _)| {
            trees[*prior] == trees[arm] && obligations[*prior] == obligations[arm]
        }) {
            *combined = combined.add(selector);
        } else {
            groups.push((arm, selector.clone()));
        }
    }
    Ok(groups)
}

/// Self-recursive twin of [`finalize_r_pcs_history_step_region`]. Besides the
/// predecessor PCS obligations it conditionally binds both possible parent
/// recording sources to one selected child and one selected `[R]_prev` block.
pub(crate) fn finalize_history_step_parent_region(
    b: &mut FieldR1csBuilder,
    columns: HistoryStepParentColumns,
    obligations: &[PcsWalkObligations],
    arm_selectors: &[LinExpr],
    recorded_children: &[FsRecordedChannel],
    recorded_r_prev: &[FsRecordedChannel],
) -> Result<HistoryStepParentRegionPreparation, RegionSidecarError> {
    finalize_history_step_parent_region_inner(
        b,
        columns,
        obligations,
        arm_selectors,
        recorded_children,
        recorded_r_prev,
        false,
    )
}

pub(crate) fn finalize_shared_history_step_parent_region(
    b: &mut FieldR1csBuilder,
    columns: HistoryStepParentColumns,
    obligations: &[PcsWalkObligations],
    arm_selectors: &[LinExpr],
    recorded_children: &[FsRecordedChannel],
    recorded_r_prev: &[FsRecordedChannel],
) -> Result<HistoryStepParentRegionPreparation, RegionSidecarError> {
    finalize_history_step_parent_region_inner(
        b,
        columns,
        obligations,
        arm_selectors,
        recorded_children,
        recorded_r_prev,
        true,
    )
}

fn finalize_history_step_parent_region_inner(
    b: &mut FieldR1csBuilder,
    columns: HistoryStepParentColumns,
    obligations: &[PcsWalkObligations],
    arm_selectors: &[LinExpr],
    recorded_children: &[FsRecordedChannel],
    recorded_r_prev: &[FsRecordedChannel],
    coalesce: bool,
) -> Result<HistoryStepParentRegionPreparation, RegionSidecarError> {
    let HistoryStepParentColumns {
        asm,
        slices_a,
        slices_b,
        slices_rec,
        mut recording_constraint_slots,
        selector_slice,
        u_rec,
        child_scratches,
        r_prev_scratches,
        active_slot,
        vk,
    } = columns;
    if recorded_children.len() != child_scratches.len()
        || recorded_r_prev.len() != r_prev_scratches.len()
        || obligations.len() != asm.all_trees.len()
        || arm_selectors.len() != asm.all_trees.len()
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    if active_slot >= arm_selectors.len() || !(1..=3).contains(&arm_selectors.len()) {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    if arm_selectors.len() == 1 {
        pin_eq(b, &slot_cell(&selector_slice, 0), &LinExpr::zero());
        pin_eq(b, &arm_selectors[0], &LinExpr::constant(F128::ONE));
    } else if arm_selectors.len() == 2 {
        pin_eq(b, &slot_cell(&selector_slice, 0), &arm_selectors[1]);
    } else {
        let code = arm_selectors[1]
            .add(&arm_selectors[2].scale(noid_ivc_core::field_circuit::f128_from_u128(2)));
        pin_eq(b, &slot_cell(&selector_slice, 0), &code);
    }

    let per_tile = 1usize << asm.u_a.block_log;
    let subchannel_slots = 1usize << asm.s_log;

    // L-A and L-B carry one shared predecessor. Their digest/entry join is
    // unconditional; the authenticated class selector below chooses which
    // verifier arm supplies the leaves, directions and roots.
    for query_index in 0..asm.n_queries {
        let tile_offset = query_index * per_tile;
        for tree_index in 0..asm.carrier_depths.len() {
            let digest_slot =
                tile_offset + tree_index * subchannel_slots + asm.leaf_lanes[tree_index] / 2 - 1;
            let carrier_depth = asm.carrier_depths[tree_index];
            let leg_slot = asm.leg_offsets[tree_index] + query_index * carrier_depth;
            for lane in 0..2 {
                pin_eq(
                    b,
                    &slot_cell(&slices_a[2 + lane], digest_slot),
                    &slot_cell(&slices_b[4 + lane], leg_slot),
                );
            }
        }
    }

    let binding_groups = if coalesce {
        checked_pcs_binding_groups(b, &asm.all_trees, obligations, arm_selectors)?
    } else {
        arm_selectors.iter().cloned().enumerate().collect()
    };
    if coalesce {
        eprintln!(
            "[shared-pcs-bindings] arms={} groups={}",
            arm_selectors.len(),
            binding_groups.len()
        );
    }
    for (arm, selector) in binding_groups {
        let trees = &asm.all_trees[arm];
        let obligations = &obligations[arm];
        let n_trees = trees.len();
        assert_eq!(
            obligations.leaves.len(),
            asm.n_queries * n_trees,
            "HistoryStep parent leaf obligation count"
        );
        assert_eq!(
            obligations.paths.len(),
            obligations.leaves.len(),
            "HistoryStep parent path/leaf pairing"
        );
        with_pin_gate(&selector, || {
            for query_index in 0..asm.n_queries {
                let tile_offset = query_index * per_tile;
                for tree_index in 0..n_trees {
                    let obligation_index = query_index * n_trees + tree_index;
                    let leaf = &obligations.leaves[obligation_index];
                    let positions = &asm.leaf_data_positions[tree_index];
                    assert_eq!(
                        leaf.lanes.len(),
                        positions.len(),
                        "HistoryStep parent leaf lanes"
                    );
                    for (wire, &(slot, lane)) in leaf.lanes.iter().zip(positions) {
                        pin_eq(b, wire, &slot_cell(&slices_a[lane], tile_offset + slot));
                    }

                    let obligation = &obligations.paths[obligation_index];
                    assert_eq!(
                        obligation.leaf, obligation_index,
                        "HistoryStep parent leaf/path pairing in arm {arm}"
                    );
                    let tree = trees[tree_index];
                    assert_eq!(obligation.dir_bits.len(), tree.depth);
                    let carrier_depth = asm.carrier_depths[tree_index];
                    let leg_slot = asm.leg_offsets[tree_index] + query_index * carrier_depth;
                    for (level, bit) in obligation.dir_bits.iter().enumerate() {
                        pin_eq(b, bit, &slot_cell(&slices_b[8], leg_slot + level));
                    }
                    for lane in 0..2 {
                        let root = if tree.depth < carrier_depth {
                            slot_cell(&slices_b[4 + lane], leg_slot + tree.depth)
                        } else {
                            let last = leg_slot + tree.depth - 1;
                            let carried = slot_cell(&slices_b[4 + lane], last);
                            let sibling = slot_cell(&slices_b[6 + lane], last);
                            let direction = slot_cell(&slices_b[8], last);
                            let selected_delta = mul(b, &direction, &carried.add(&sibling));
                            slot_cell(&slices_b[lane], last)
                                .add(&carried)
                                .add(&selected_delta)
                        };
                        pin_eq(b, &root, &obligation.root[lane]);
                    }
                }
            }
        });
    }
    pin_selected_recording_role(
        b,
        "walk L-C HistoryStep parent Block child",
        &child_scratches,
        recorded_children,
        vk.rec_c(),
        arm_selectors,
        active_slot,
        0,
        &u_rec,
        &slices_rec,
        0,
        &mut recording_constraint_slots,
    )?;
    pin_selected_recording_role(
        b,
        "walk L-C HistoryStep [R]_prev",
        &r_prev_scratches,
        recorded_r_prev,
        vk.rec_c(),
        arm_selectors,
        active_slot,
        1,
        &u_rec,
        &slices_rec,
        1,
        &mut recording_constraint_slots,
    )?;
    if !recording_constraint_slots.is_empty() {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }

    let input = LinkRegionProverInput::new(
        &vk,
        RegionWalkEndpoints::new(asm.u_a.s0, asm.u_a.s_out),
        RegionWalkEndpoints::new(asm.s0b, asm.soutb),
        RegionWalkEndpoints::new(u_rec.s0, u_rec.s_out),
    )?;
    Ok(HistoryStepParentRegionPreparation { vk, input })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acceptance::history_step_bank::HISTORY_STEP_FRI_QUERIES;
    use noid_ivc_core::field::F256;
    use noid_ivc_core::field_circuit::{ExtExpr, FsChannelOps};
    use noid_ivc_core::pcs::LOG_PACKING;
    use noid_ivc_core::public_io::PublicIoSpec;

    fn c1_recording(seed: u64) -> LayoutRecordedChannel {
        let mut builder = FieldR1csBuilder::new();
        let value = F256::new(
            F128::new(seed, seed.rotate_left(17)),
            F128::new(seed ^ 0xA5A5, seed.rotate_left(41)),
        );
        let expression = ExtExpr::new(
            LinExpr::from_wire(builder.alloc_f128(value.lo)),
            LinExpr::from_wire(builder.alloc_f128(value.hi)),
        );
        let mut recorder = FsChannelUnionRecorder::new_c1(b"history-recording-c1-iv-test");
        recorder.observe_f256(&mut builder, &expression);
        let _ = recorder.sample_f256(&mut builder);
        recorder.observe_f128(&mut builder, &expression.lo);
        let _ = recorder.sample_f256(&mut builder);
        let recording = recorder.finish();
        LayoutRecordedChannel {
            layout: compile_duplex(&recording.ops),
            data_flat: recording.data_flat,
            challenges: recording
                .challenge_wires
                .iter()
                .map(|challenge| Some(challenge.eval(builder.values())))
                .collect(),
            post_state: recording.post_state,
            perms: recording.perms,
        }
    }

    #[test]
    fn single_parent_geometry_has_one_fixed_recording_recipe() {
        let params = PcsParams {
            m: 24 + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        };
        let recording = c1_recording(7);
        let single = HistoryStepParentGeometry::single(
            &params,
            recording.layout.clone(),
            recording.layout.clone(),
        )
        .unwrap();
        let legacy = HistoryStepParentGeometry::new(
            &[params.clone(), params],
            vec![recording.layout.clone(); 2],
            vec![recording.layout.clone(); 2],
        )
        .unwrap();
        assert_eq!(single.tier_count(), 1);
        assert_eq!(single.carrier.groups.len(), 1);
        let spec = PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 8,
                index: 1,
            },
            io_len: 132,
            claims: Vec::new(),
        };
        let single_vk = single.canonical_vk(&spec).unwrap();
        let legacy_vk = legacy.canonical_vk(&spec).unwrap();
        assert_ne!(single_vk.transcript_digest(), legacy_vk.transcript_digest());
        assert!(single_vk.rec_c().selected_block(1, 0).is_none());
        for role in 0..2 {
            assert_eq!(
                single_vk.rec_c().selected_block(0, role),
                Some(&single.selected_recording_blocks()[0][role])
            );
        }
        let union = single
            .recording_union(
                std::slice::from_ref(&recording),
                std::slice::from_ref(&recording),
                0,
            )
            .unwrap();
        assert_eq!(union.rec_blocks, single.selected_recording_blocks()[0]);
        assert!(single
            .recording_union(
                std::slice::from_ref(&recording),
                std::slice::from_ref(&recording),
                1
            )
            .is_err());
    }

    #[test]
    fn history_step_parent_geometry_has_two_tiers_and_two_selected_roles() {
        let params = [23usize, 24].map(|m| PcsParams {
            m: m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        });
        let layout = compile_duplex(&[
            TranscriptOp::Absorb(vec![None, Some(7), None]),
            TranscriptOp::Squeeze(2),
        ]);
        let geometry =
            HistoryStepParentGeometry::new(&params, vec![layout.clone(); 2], vec![layout; 2])
                .expect("two-tier HistoryStep geometry");
        assert_eq!(geometry.carrier.proof_roles, 1);
        assert_eq!(geometry.carrier.groups.len(), 2);
        assert_eq!(geometry.carrier.n_queries, HISTORY_STEP_FRI_QUERIES);
        assert_eq!(geometry.selected_recording_blocks()[0].len(), 2);
        assert_eq!(geometry.selected_recording_blocks()[1].len(), 2);
        let dense = dense_path_geometry(&geometry.carrier).expect("dense path geometry");
        assert_eq!(dense.carrier_depths, [21, 17, 13, 9]);
        assert_eq!(dense.n_paths, HISTORY_STEP_FRI_QUERIES);
        assert_eq!(dense.family_path_counts, [141, 134, 133, 136]);
        assert_eq!(dense.active_slots, 1usize << 13);

        let spec = PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 10,
                index: 1,
            },
            io_len: 900,
            claims: Vec::new(),
        };
        let vk = geometry
            .canonical_vk(&spec)
            .expect("canonical HistoryStep parent sidecar VK");
        assert_eq!(vk.leaf_a().w_log(), 14);
        assert_eq!(vk.path_b().w_log(), 13);
        assert_eq!(vk.path_b().block_log(), 13);
    }

    #[test]
    fn history_recording_union_replays_c1_capacity_iv_exactly() {
        let recordings = [
            c1_recording(1),
            c1_recording(2),
            c1_recording(3),
            c1_recording(4),
        ];
        let params = [23usize, 24].map(|m| PcsParams {
            m: m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        });
        let geometry = HistoryStepParentGeometry::new(
            &params,
            recordings[..2]
                .iter()
                .map(|recording| recording.layout.clone())
                .collect(),
            recordings[2..]
                .iter()
                .map(|recording| recording.layout.clone())
                .collect(),
        )
        .expect("two-arm C1 recording geometry");
        for active in 0..2 {
            let union = geometry
                .recording_union(&recordings[..2], &recordings[2..], active)
                .expect("selected C1 recordings-only union");
            for (union_role, recording_index) in [active, active + 2].into_iter().enumerate() {
                assert_eq!(
                    union.rec_challenges[union_role],
                    recordings[recording_index]
                        .challenges
                        .iter()
                        .map(|challenge| challenge.expect("ordinary wide sample"))
                        .collect::<Vec<_>>(),
                    "recording arm {active} role {union_role} used a non-C1 capacity IV"
                );
            }
        }
    }
}
