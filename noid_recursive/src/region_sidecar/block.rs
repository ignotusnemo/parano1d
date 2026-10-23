// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block component of the mandatory joint C1 HistoryStep authority.
//!
//! The six children are the complete block-region authority. None is
//! optional: wallet/meta Walk-A, wallet/meta Walk-B, owner-auth C' and the
//! main FRICHANL C walk. Every child carries its own prefix and suffix
//! relation authority with the deep-chain walk deliberately absent. The six
//! Block instances join the three Link instances in one mandatory
//! nine-instance ragged walk on Block's derived child channel. Terminal PCS
//! claims are verifier output and never appear in the serialized proof.

use noid_fri_binius::zk_capsule_pcs::{
    ZK_CAPSULE_PCS_MID_PATH_DEPTH, ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
};
use noid_ivc_core::challenger::Challenger;
use noid_ivc_core::deep_chain::c1::C1LaneClaimGroup;
use noid_ivc_core::deep_chain::capsule_leaf::raw_flat_lane;
use noid_ivc_core::deep_chain::schedule::{
    duplex_family_refs, duplex_fixed_patterns, flat_of_tower_u128,
};
use noid_ivc_core::deep_chain::source_tree::compress_iv_flat;
use noid_ivc_core::field::{F128, F256};
use noid_ivc_core::field_circuit::FsChannelOps;
use noid_ivc_core::pcs::{C1QuirkyDirectClaim, PcsParams};
use noid_ivc_core::public_io::{PublicIoSpec, WitnessSlice};
use noid_poseidon2b::native::domain::{
    capacity_iv, capacity_iv_flat, TAG_CAPSNODE, TAG_EXSTNOD, TAG_KSCH256,
};
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

use crate::acceptance::block_slots::SelectedBlockAssemblyFinalizationSeal;
use crate::acceptance::trace::deep_chain::C1LaneClaimGroupTrace;
use crate::acceptance::trace::region_source_binding::{
    auth_pcs_meta_a_sidecar_purpose, auth_pcs_meta_b_sidecar_purpose,
};
use crate::acceptance::trace::self_verify::{
    C1QuirkyDirectClaimTrace, FieldPostCommitTraceContext,
};
use crate::acceptance::trace::FieldR1csBuilder;
use crate::acceptance::zk_auth_capsule_schedule::{
    zk_auth_region_sidecar_purpose_for_version, ZkAuthCapsuleDuplexSchedules,
    ZK_AUTH_MAIN_TILE_LOG, ZK_AUTH_OWNER_TILE_LOG,
};

use super::bounded_decode::{
    duplex_shape_for_vk, merkle_shape_for_vk, DeferredFixedProofShape, DeferredMerkleProofShape,
};
use super::walk_a::walk_a_bounded_shape;
use super::{
    verify_c1_duplex_region_walk_deferred_prefix,
    verify_c1_duplex_region_walk_deferred_prefix_trace,
    verify_c1_merkle_region_walk_deferred_prefix,
    verify_c1_merkle_region_walk_deferred_prefix_trace,
    verify_c1_walk_a_region_walk_deferred_prefix,
    verify_c1_walk_a_region_walk_deferred_prefix_trace, C1DuplexRegionWalkDeferredProof,
    C1MerkleRegionWalkDeferredProof, C1WalkARegionWalkDeferredProof, DuplexRegionProverPlan,
    DuplexRegionVk, MerkleRegionProverPlan, MerkleRegionVk, RegionSidecarError,
    WalkARegionProverPlan, WalkARegionVk,
};

pub const BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION: u8 = 6;

/// Compact retained portion of a selected Block sidecar VK.
///
/// Every schedule, purpose, family descriptor, fixed table and walk geometry
/// is canonical for the tier and is regenerated on load.  Only the outer
/// witness locations vary with the frozen matrix layout and therefore need to
/// be persisted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedZkBlockRegionVkSlices {
    pub wallet_a: [WitnessSlice; super::WALK_A_WALLET_COMMITTED_COLUMNS],
    pub meta_a: [WitnessSlice; super::WALK_A_META_COMMITTED_COLUMNS],
    pub wallet_b: [WitnessSlice; super::MERKLE_REGION_COMMITTED_COLUMNS],
    pub meta_b: [WitnessSlice; super::MERKLE_REGION_COMMITTED_COLUMNS],
    pub owner_c: [WitnessSlice; super::DUPLEX_REGION_COMMITTED_COLUMNS],
    pub main_c: [WitnessSlice; super::DUPLEX_REGION_COMMITTED_COLUMNS],
}

/// Exact selected authorization geometry for one canonical block class.
///
/// The two entries below are protocol certificates, not estimates. Keeping
/// them explicit prevents B25 from silently inheriting B255's 256
/// authorization tiles and RAM footprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedZkBlockGeometry {
    pub authorization_version: noid_tx::OwnerAuthorizationVersion,
    pub tier: usize,
    pub auth_tiles: usize,
    pub tx_log: usize,
    pub owner_w_log: usize,
    pub main_w_log: usize,
    pub wallet_a_w_log: usize,
    pub wallet_b_w_log: usize,
    pub exact_state_region_log: usize,
    pub spine_cap_log: usize,
    pub meta_a_w_log: usize,
    pub meta_b_w_log: usize,
    pub meta_b_block_log: usize,
    pub touched_capacity: usize,
    pub segment_capacity: usize,
    pub paired_caps_per_block: [usize; 2],
    pub paired_bases: [usize; 2],
    pub tx_root_base: usize,
    pub tx_root_paths_per_block: usize,
    pub wallet_overflow_bases: [usize; 2],
}

pub(crate) const fn selected_zk_block_geometry(tier: usize) -> Option<SelectedZkBlockGeometry> {
    let geometry = match tier {
        25 => SelectedZkBlockGeometry {
            authorization_version: noid_tx::OwnerAuthorizationVersion::V4,
            tier: 25,
            auth_tiles: 32,
            tx_log: 5,
            owner_w_log: 12,
            main_w_log: 13,
            wallet_a_w_log: 16,
            wallet_b_w_log: 15,
            exact_state_region_log: 10,
            spine_cap_log: 0,
            meta_a_w_log: 12,
            meta_b_w_log: 16,
            meta_b_block_log: 11,
            touched_capacity: 251,
            segment_capacity: 251,
            paired_caps_per_block: [8, 8],
            paired_bases: [0, 512],
            tx_root_base: 1_024,
            tx_root_paths_per_block: 8,
            wallet_overflow_bases: [1_152, 1_162],
        },
        255 => SelectedZkBlockGeometry {
            authorization_version: noid_tx::OwnerAuthorizationVersion::V4,
            tier: 255,
            auth_tiles: 256,
            tx_log: 8,
            owner_w_log: 15,
            main_w_log: 16,
            wallet_a_w_log: 19,
            wallet_b_w_log: 18,
            exact_state_region_log: 13,
            spine_cap_log: 0,
            meta_a_w_log: 15,
            meta_b_w_log: 17,
            meta_b_block_log: 9,
            touched_capacity: 1_531,
            segment_capacity: 256,
            paired_caps_per_block: [6, 1],
            paired_bases: [0, 384],
            tx_root_base: 448,
            tx_root_paths_per_block: 1,
            wallet_overflow_bases: [464, 474],
        },
        63 | 64 | 96 | 112 | 120 | 127 | 128 | 176 | 192 | 206 | 207 | 209 | 210 | 211 | 223 => {
            let inputs = if tier * 8 > 1_020 { 1_020 } else { tier * 8 };
            return Some(candidate_block_geometry(tier, inputs));
        }
        _ => return None,
    };
    Some(geometry)
}

/// Isolated candidate geometry. These capacities are not legacy consensus
/// classes. Include the coinbase when sizing the shared body/authentication
/// tile axis, so a power-of-two user capacity cannot overrun that axis.
pub(crate) const fn selected_zk_block_geometry_with_inputs(
    tier: usize,
    inputs: usize,
) -> Option<SelectedZkBlockGeometry> {
    if matches!(
        tier,
        63 | 96 | 112 | 120 | 127 | 128 | 176 | 192 | 206 | 207 | 209 | 210 | 211 | 223 | 255
    ) && matches!(inputs, 256 | 384 | 472 | 480 | 504)
    {
        return Some(candidate_block_geometry(tier, inputs));
    }
    match selected_zk_block_geometry(tier) {
        Some(geometry) if inputs == geometry.touched_capacity - 2 * tier - 1 => Some(geometry),
        _ => None,
    }
}

pub(crate) fn object_block_geometries() -> impl Iterator<Item = SelectedZkBlockGeometry> {
    [
        25, 63, 64, 96, 112, 120, 127, 128, 176, 192, 206, 207, 209, 210, 211, 223, 255,
    ]
    .into_iter()
    .filter_map(selected_zk_block_geometry)
    .chain(
        [
            63, 96, 112, 120, 127, 128, 176, 192, 206, 207, 209, 210, 211, 223, 255,
        ]
        .into_iter()
        .flat_map(|tier| {
            [256, 384, 472, 480, 504]
                .into_iter()
                .filter_map(move |inputs| selected_zk_block_geometry_with_inputs(tier, inputs))
        }),
    )
}

const fn candidate_block_geometry(tier: usize, inputs: usize) -> SelectedZkBlockGeometry {
    let auth_tiles = (tier + 1).next_power_of_two();
    let tx_log = auth_tiles.trailing_zeros() as usize;
    let touched = inputs + 2 * tier + 1;
    let segments = if touched > 256 { 256 } else { touched };
    let exact_slots = (4 * touched).next_power_of_two();
    let metadata_half = (exact_slots
        + 2 * auth_tiles * noid_ivc_core::deep_chain::capsule_leaf::CAPSULE_LEAF_STRIDE)
        .next_power_of_two();
    let spine_slots = auth_tiles * 64;
    let meta_half = if metadata_half > spine_slots {
        metadata_half
    } else {
        spine_slots
    };
    let caps = [touched.div_ceil(auth_tiles), segments.div_ceil(auth_tiles)];
    let paired_bases = [0, caps[0] * 64];
    let tx_root_base = (caps[0] + caps[1]) * 64;
    let tx_paths = 256usize.div_ceil(auth_tiles);
    let overflow = tx_root_base + 16 * tx_paths;
    let block_log = (overflow + ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH + ZK_CAPSULE_PCS_MID_PATH_DEPTH)
        .next_power_of_two()
        .trailing_zeros() as usize;
    SelectedZkBlockGeometry {
        authorization_version: noid_tx::OwnerAuthorizationVersion::V4,
        tier,
        auth_tiles,
        tx_log,
        owner_w_log: tx_log + 7,
        main_w_log: tx_log + 8,
        wallet_a_w_log: tx_log + 11,
        wallet_b_w_log: tx_log + 10,
        exact_state_region_log: exact_slots.trailing_zeros() as usize,
        spine_cap_log: 0,
        meta_a_w_log: 1 + meta_half.trailing_zeros() as usize,
        meta_b_w_log: tx_log + block_log,
        meta_b_block_log: block_log,
        touched_capacity: touched,
        segment_capacity: segments,
        paired_caps_per_block: caps,
        paired_bases,
        tx_root_base,
        tx_root_paths_per_block: tx_paths,
        wallet_overflow_bases: [overflow, overflow + ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH],
    }
}

pub(crate) fn selected_zk_block_geometry_for_auth_tiles(
    auth_tiles: usize,
) -> Option<SelectedZkBlockGeometry> {
    [25, 63, 127, 255]
        .into_iter()
        .filter_map(selected_zk_block_geometry)
        .find(|geometry| geometry.auth_tiles == auth_tiles)
}

const SELECTED_ZK_AUTH_QUERY_LOG: usize = 6;

const BLOCK_REGION_SELECTED_ZK_VK_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/BLOCK-ZK-AUTH-VK/V6";
const BLOCK_SELECTED_ZK_POST_COMMIT_CLASS_DIGEST_DOMAIN: &[u8] =
    b"NOID/REGION-SIDECAR/BLOCK-ZK-AUTH-POST-COMMIT-CLASS/V6";
const BLOCK_REGION_SELECTED_ZK_TRANSCRIPT_LABEL: &[u8] = b"history-region-sidecar-block-zk-auth-v6";

/// Outer-channel label preceding the child-transcript seed draw.
pub(crate) const BLOCK_SIDECAR_RECORDED_LABEL: &[u8] = b"history-block-sidecar-recorded-v2";
/// Fresh Fiat-Shamir domain of the block-sidecar CHILD transcript.  The
/// child chain starts from this domain, absorbs one outer-sampled seed (so
/// its challenges are causally post-commit), replays the complete V5 block
/// sidecar verification, and squeezes a two-lane terminal digest that the
/// outer channel re-absorbs before its first zerocheck challenge.
pub(crate) const BLOCK_SIDECAR_CHILD_DOMAIN: &[u8] = b"history-block-sidecar-child-c1-v2";

/// Canonical verification key for all six production block-region verticals.
///
/// Private fields make partial block keys unrepresentable outside this module.
/// The constructor accepts already validated child keys and freezes their role
/// and order into one digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRegionSidecarVk {
    wallet_a: WalkARegionVk,
    meta_a: WalkARegionVk,
    wallet_b: MerkleRegionVk,
    meta_b: MerkleRegionVk,
    owner_c: DuplexRegionVk,
    main_c: DuplexRegionVk,
    transcript_digest: [u8; 32],
}

impl BlockRegionSidecarVk {
    pub(crate) fn authorization_version(
        &self,
    ) -> Result<noid_tx::OwnerAuthorizationVersion, RegionSidecarError> {
        for version in [
            noid_tx::OwnerAuthorizationVersion::V3,
            noid_tx::OwnerAuthorizationVersion::V4,
        ] {
            if self.owner_c.purpose()
                == &zk_auth_region_sidecar_purpose_for_version(b"owner", version)
            {
                return Ok(version);
            }
        }
        Err(RegionSidecarError::UnsupportedVkShape)
    }
    /// Rebuild a selected VK from its compact registry carrier.  This is a
    /// checked constructor, not a raw-field deserializer: all omitted data is
    /// regenerated from the canonical tier certificate, and the final
    /// six-child role validator compares the resulting duplex schedules and
    /// Merkle families byte-for-byte with production geometry.
    pub(crate) fn from_selected_registry_slices(
        tier: usize,
        slices: SelectedZkBlockRegionVkSlices,
    ) -> Result<Self, RegionSidecarError> {
        // Research profiles can share all dimensions with a legacy class.
        // Only the two released tiers may use the legacy registry constructor.
        if !matches!(tier, 25 | 255) {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let mut geometry =
            selected_zk_block_geometry(tier).ok_or(RegionSidecarError::UnsupportedVkShape)?;
        geometry.authorization_version = noid_tx::OwnerAuthorizationVersion::V3;
        Self::from_profile_registry_slices(geometry, slices, false)
    }

    pub(crate) fn from_object_registry_slices(
        geometry: SelectedZkBlockGeometry,
        slices: SelectedZkBlockRegionVkSlices,
    ) -> Result<Self, RegionSidecarError> {
        Self::from_profile_registry_slices(geometry, slices, true)
    }

    fn from_profile_registry_slices(
        geometry: SelectedZkBlockGeometry,
        slices: SelectedZkBlockRegionVkSlices,
        objects: bool,
    ) -> Result<Self, RegionSidecarError> {
        let authorization_version = geometry.authorization_version;
        let wallet_a = WalkARegionVk::new_wallet(
            zk_auth_region_sidecar_purpose_for_version(b"wallet-a", authorization_version),
            geometry.tx_log,
            SELECTED_ZK_AUTH_QUERY_LOG,
            slices.wallet_a,
        )?;
        let meta_constructor = if objects {
            WalkARegionVk::new_object_meta
        } else {
            WalkARegionVk::new_meta
        };
        let meta_a = meta_constructor(
            auth_pcs_meta_a_sidecar_purpose(),
            geometry.tx_log,
            Some(geometry.exact_state_region_log),
            Some(geometry.spine_cap_log),
            slices.meta_a,
        )?;
        let capsule_iv = capacity_iv_flat(TAG_CAPSNODE).map(raw_flat_lane);
        let wallet_b = MerkleRegionVk::new(
            zk_auth_region_sidecar_purpose_for_version(b"wallet-b", authorization_version),
            geometry.wallet_b_w_log,
            slices.wallet_b,
            10,
            vec![
                super::MerkleRegionFamily::FeedForwardStrided {
                    offset: 0,
                    depth: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
                    n_paths: 64,
                    stride: 16,
                    iv: capsule_iv,
                },
                super::MerkleRegionFamily::FeedForwardStrided {
                    offset: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
                    depth: ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                    n_paths: 64,
                    stride: 16,
                    iv: capsule_iv,
                },
            ],
        )?;
        let exact_state_iv = capacity_iv_flat(TAG_EXSTNOD).map(raw_flat_lane);
        let meta_b = MerkleRegionVk::new(
            auth_pcs_meta_b_sidecar_purpose(),
            geometry.meta_b_w_log,
            slices.meta_b,
            geometry.meta_b_block_log,
            vec![
                super::MerkleRegionFamily::PairedUpdate {
                    offset: geometry.paired_bases[0],
                    n_updates: geometry.paired_caps_per_block[0],
                    iv: exact_state_iv,
                },
                super::MerkleRegionFamily::PairedUpdate {
                    offset: geometry.paired_bases[1],
                    n_updates: geometry.paired_caps_per_block[1],
                    iv: exact_state_iv,
                },
                super::MerkleRegionFamily::TwoPermutation {
                    offset: geometry.tx_root_base,
                    depth: 8,
                    n_paths: geometry.tx_root_paths_per_block,
                    iv: compress_iv_flat(),
                },
                super::MerkleRegionFamily::FeedForwardStrided {
                    offset: geometry.wallet_overflow_bases[0],
                    depth: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
                    n_paths: 1,
                    stride: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH + ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                    iv: capsule_iv,
                },
                super::MerkleRegionFamily::FeedForwardStrided {
                    offset: geometry.wallet_overflow_bases[1],
                    depth: ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                    n_paths: 1,
                    stride: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH + ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                    iv: capsule_iv,
                },
            ],
        )?;
        let schedules = ZkAuthCapsuleDuplexSchedules::for_version(authorization_version);
        let [iv_hi, iv_lo] = capacity_iv(TAG_KSCH256);
        let iv = [flat_of_tower_u128(iv_hi.0), flat_of_tower_u128(iv_lo.0)];
        let owner_layout = schedules.owner_sidecar_layout();
        let owner_c = DuplexRegionVk::new(
            zk_auth_region_sidecar_purpose_for_version(b"owner", authorization_version),
            geometry.owner_w_log,
            slices.owner_c,
            duplex_fixed_patterns(&owner_layout, iv, ZK_AUTH_OWNER_TILE_LOG),
            duplex_family_refs(0, 0),
            &owner_layout,
        )?;
        let main_layout = schedules.main_sidecar_layout();
        let main_c = DuplexRegionVk::new(
            zk_auth_region_sidecar_purpose_for_version(b"main", authorization_version),
            geometry.main_w_log,
            slices.main_c,
            duplex_fixed_patterns(&main_layout, iv, ZK_AUTH_MAIN_TILE_LOG),
            duplex_family_refs(0, 0),
            &main_layout,
        )?;
        Self::new_selected_zk(wallet_a, meta_a, wallet_b, meta_b, owner_c, main_c)
    }

    pub(crate) fn selected_registry_slices(
        &self,
    ) -> Result<SelectedZkBlockRegionVkSlices, RegionSidecarError> {
        self.validate_selected_zk_roles()?;
        Ok(SelectedZkBlockRegionVkSlices {
            wallet_a: self
                .wallet_a
                .slices()
                .try_into()
                .map_err(|_| RegionSidecarError::UnsupportedVkShape)?,
            meta_a: self
                .meta_a
                .slices()
                .try_into()
                .map_err(|_| RegionSidecarError::UnsupportedVkShape)?,
            wallet_b: *self.wallet_b.slices(),
            meta_b: *self.meta_b.slices(),
            owner_c: *self.owner_c.slices(),
            main_c: *self.main_c.slices(),
        })
    }

    /// Construct the selected ZK-authorization six-child key.
    ///
    /// This is a VK shape certificate only.  It is deliberately not a
    /// committed-region capability: the only path to a selected mandatory
    /// preparation additionally consumes the all-class-tiles binding typestate.
    pub(crate) fn new_selected_zk(
        wallet_a: WalkARegionVk,
        meta_a: WalkARegionVk,
        wallet_b: MerkleRegionVk,
        meta_b: MerkleRegionVk,
        owner_c: DuplexRegionVk,
        main_c: DuplexRegionVk,
    ) -> Result<Self, RegionSidecarError> {
        let transcript_digest = block_region_sidecar_vk_digest(
            &wallet_a, &meta_a, &wallet_b, &meta_b, &owner_c, &main_c,
        );
        let vk = Self {
            wallet_a,
            meta_a,
            wallet_b,
            meta_b,
            owner_c,
            main_c,
            transcript_digest,
        };
        vk.validate_selected_zk_roles()?;
        Ok(vk)
    }

    pub fn wallet_a(&self) -> &WalkARegionVk {
        &self.wallet_a
    }

    pub fn meta_a(&self) -> &WalkARegionVk {
        &self.meta_a
    }

    pub fn supports_objects(&self) -> bool {
        matches!(
            self.meta_a.descriptor(),
            super::WalkARegionDescriptor::ObjectMeta { .. }
        )
    }

    pub fn wallet_b(&self) -> &MerkleRegionVk {
        &self.wallet_b
    }

    pub fn meta_b(&self) -> &MerkleRegionVk {
        &self.meta_b
    }

    pub fn owner_c(&self) -> &DuplexRegionVk {
        &self.owner_c
    }

    pub fn main_c(&self) -> &DuplexRegionVk {
        &self.main_c
    }

    pub fn version(&self) -> u8 {
        BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION
    }

    /// Digest of the complete ordered block sidecar VK.  This digest is a
    /// component of the enclosing block class digest; the exact child keys
    /// are also absorbed here before any child proof message is sampled.
    pub fn transcript_digest(&self) -> [u8; 32] {
        self.transcript_digest
    }

    fn transcript_label(&self) -> &'static [u8] {
        BLOCK_REGION_SELECTED_ZK_TRANSCRIPT_LABEL
    }

    /// Exact two-class selected certificate over all six child roles,
    /// layouts, domains and slices. Success does not by itself authorize
    /// proving: the Block builder must still bind every class tile and consume
    /// the resulting private typestate before a selected preparation can
    /// exist.
    pub(crate) fn validate_selected_zk_roles(&self) -> Result<(), RegionSidecarError> {
        use super::{MerkleRegionFamily, WalkARegionDescriptor};
        let authorization_version = self.authorization_version()?;

        let tx_log = match self.wallet_a.descriptor() {
            WalkARegionDescriptor::Wallet {
                tx_log,
                nq_log: SELECTED_ZK_AUTH_QUERY_LOG,
            } => tx_log,
            _ => return Err(RegionSidecarError::UnsupportedVkShape),
        };
        let geometry = object_block_geometries()
            .filter(|geometry| self.supports_objects() || [25, 255].contains(&geometry.tier))
            .find(|geometry| {
                geometry.tx_log == tx_log
                    && matches!(self.meta_b.families().first(),
                        Some(MerkleRegionFamily::PairedUpdate { n_updates, .. })
                        if *n_updates == geometry.paired_caps_per_block[0])
                    && matches!(self.meta_b.families().get(1),
                        Some(MerkleRegionFamily::PairedUpdate { n_updates, .. })
                        if *n_updates == geometry.paired_caps_per_block[1])
            })
            .ok_or(RegionSidecarError::UnsupportedVkShape)?;
        let expected_meta = if self.supports_objects() {
            WalkARegionDescriptor::ObjectMeta {
                tx_log: geometry.tx_log,
                exact_state_region_log: Some(geometry.exact_state_region_log),
                spine_cap_log: Some(geometry.spine_cap_log),
            }
        } else {
            WalkARegionDescriptor::Meta {
                tx_log: geometry.tx_log,
                exact_state_region_log: Some(geometry.exact_state_region_log),
                spine_cap_log: Some(geometry.spine_cap_log),
            }
        };

        if self.wallet_a.purpose()
            != &zk_auth_region_sidecar_purpose_for_version(b"wallet-a", authorization_version)
            || self.meta_a.purpose() != &auth_pcs_meta_a_sidecar_purpose()
            || self.wallet_b.purpose()
                != &zk_auth_region_sidecar_purpose_for_version(b"wallet-b", authorization_version)
            || self.meta_b.purpose() != &auth_pcs_meta_b_sidecar_purpose()
            || self.owner_c.purpose()
                != &zk_auth_region_sidecar_purpose_for_version(b"owner", authorization_version)
            || self.main_c.purpose()
                != &zk_auth_region_sidecar_purpose_for_version(b"main", authorization_version)
            || self.wallet_a.descriptor()
                != (WalkARegionDescriptor::Wallet {
                    tx_log: geometry.tx_log,
                    nq_log: SELECTED_ZK_AUTH_QUERY_LOG,
                })
            || self.wallet_a.w_log() != geometry.wallet_a_w_log
            || self.meta_a.descriptor() != expected_meta
            || self.meta_a.w_log() != geometry.meta_a_w_log
            || self.wallet_b.w_log() != geometry.wallet_b_w_log
            || self.wallet_b.block_log() != 10
            || self.meta_b.w_log() != geometry.meta_b_w_log
            || self.meta_b.block_log() != geometry.meta_b_block_log
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }

        let capsule_iv = capacity_iv_flat(TAG_CAPSNODE).map(raw_flat_lane);
        let expected_wallet_b = [
            MerkleRegionFamily::FeedForwardStrided {
                offset: 0,
                depth: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
                n_paths: 64,
                stride: 16,
                iv: capsule_iv,
            },
            MerkleRegionFamily::FeedForwardStrided {
                offset: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
                depth: ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                n_paths: 64,
                stride: 16,
                iv: capsule_iv,
            },
        ];
        if self.wallet_b.families() != expected_wallet_b {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }

        let exact_state_iv = capacity_iv_flat(TAG_EXSTNOD).map(raw_flat_lane);
        let expected_meta_b = [
            MerkleRegionFamily::PairedUpdate {
                offset: geometry.paired_bases[0],
                n_updates: geometry.paired_caps_per_block[0],
                iv: exact_state_iv,
            },
            MerkleRegionFamily::PairedUpdate {
                offset: geometry.paired_bases[1],
                n_updates: geometry.paired_caps_per_block[1],
                iv: exact_state_iv,
            },
            MerkleRegionFamily::TwoPermutation {
                offset: geometry.tx_root_base,
                depth: 8,
                n_paths: geometry.tx_root_paths_per_block,
                iv: compress_iv_flat(),
            },
            MerkleRegionFamily::FeedForwardStrided {
                offset: geometry.wallet_overflow_bases[0],
                depth: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
                n_paths: 1,
                stride: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH + ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                iv: capsule_iv,
            },
            MerkleRegionFamily::FeedForwardStrided {
                offset: geometry.wallet_overflow_bases[1],
                depth: ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                n_paths: 1,
                stride: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH + ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                iv: capsule_iv,
            },
        ];
        if self.meta_b.families() != expected_meta_b {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }

        let schedules = ZkAuthCapsuleDuplexSchedules::for_version(authorization_version);
        if !selected_duplex_vk_matches(
            self.owner_c(),
            &schedules.owner_sidecar_layout(),
            zk_auth_region_sidecar_purpose_for_version(b"owner", authorization_version),
            geometry.owner_w_log,
            ZK_AUTH_OWNER_TILE_LOG,
        ) || !selected_duplex_vk_matches(
            self.main_c(),
            &schedules.main_sidecar_layout(),
            zk_auth_region_sidecar_purpose_for_version(b"main", authorization_version),
            geometry.main_w_log,
            ZK_AUTH_MAIN_TILE_LOG,
        ) {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }

        let slices = self
            .wallet_a
            .slices()
            .iter()
            .chain(self.meta_a.slices())
            .chain(self.wallet_b.slices())
            .chain(self.meta_b.slices())
            .chain(self.owner_c.slices())
            .chain(self.main_c.slices())
            .collect::<Vec<_>>();
        for (index, left) in slices.iter().enumerate() {
            let left_start = left.start();
            let left_end = left_start
                .checked_add(left.len())
                .ok_or(RegionSidecarError::BadSlice)?;
            for right in &slices[index + 1..] {
                let right_start = right.start();
                let right_end = right_start
                    .checked_add(right.len())
                    .ok_or(RegionSidecarError::BadSlice)?;
                if left_start < right_end && right_start < left_end {
                    return Err(RegionSidecarError::BadSlice);
                }
            }
        }
        Ok(())
    }
}

fn block_region_sidecar_vk_digest(
    wallet_a: &WalkARegionVk,
    meta_a: &WalkARegionVk,
    wallet_b: &MerkleRegionVk,
    meta_b: &MerkleRegionVk,
    owner_c: &DuplexRegionVk,
    main_c: &DuplexRegionVk,
) -> [u8; 32] {
    let child = [
        wallet_a.transcript_digest(),
        meta_a.transcript_digest(),
        wallet_b.transcript_digest(),
        meta_b.transcript_digest(),
        owner_c.transcript_digest(),
        main_c.transcript_digest(),
    ];
    let version = [BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION];
    poseidon2b_hash_byte_slices(
        BLOCK_REGION_SELECTED_ZK_VK_DIGEST_DOMAIN,
        &[
            &version,
            b"wallet-a",
            &child[0],
            b"meta-a",
            &child[1],
            b"wallet-b",
            &child[2],
            b"meta-b",
            &child[3],
            b"owner-c",
            &child[4],
            b"main-c",
            &child[5],
        ],
    )
}

fn selected_duplex_vk_matches(
    vk: &DuplexRegionVk,
    layout: &noid_ivc_core::deep_chain::schedule::DuplexLayout,
    purpose: [u8; 32],
    w_log: usize,
    tile_log: usize,
) -> bool {
    let [iv_hi, iv_lo] = capacity_iv(TAG_KSCH256);
    let iv = [flat_of_tower_u128(iv_hi.0), flat_of_tower_u128(iv_lo.0)];
    vk.purpose() == &purpose
        && vk.w_log() == w_log
        && vk.refs() == duplex_family_refs(0, 0)
        && vk.fixed() == duplex_fixed_patterns(layout, iv, tile_log)
        && vk.layout_digest() == &super::duplex_compiled_layout_digest(layout, w_log)
}

/// Stable post-commit class identity bound by the enclosing Field typestate
/// API.  It covers the matrix content, exact public-IO spec, PCS parameters,
/// and all six sidecar verification keys.  A proof from any ordinary Field
/// class or from a differently sliced region class therefore enters a
/// different transcript before the first sidecar challenge.
pub fn block_post_commit_class_digest(
    matrix_digest: &[u8; 32],
    spec: &PublicIoSpec,
    pcs_params: &PcsParams,
    sidecar_vk: &BlockRegionSidecarVk,
) -> [u8; 32] {
    block_post_commit_class_digest_from_vk_digest(
        matrix_digest,
        spec,
        pcs_params,
        sidecar_vk.transcript_digest(),
    )
}

fn block_post_commit_class_digest_from_vk_digest(
    matrix_digest: &[u8; 32],
    spec: &PublicIoSpec,
    pcs_params: &PcsParams,
    sidecar_vk_digest: [u8; 32],
) -> [u8; 32] {
    let mut spec_bytes = Vec::new();
    push_u64(&mut spec_bytes, spec.io_slice.log2_len);
    push_u64(&mut spec_bytes, spec.io_slice.index);
    push_u64(&mut spec_bytes, spec.io_len);
    push_u64(&mut spec_bytes, spec.claims.len());
    for claim in &spec.claims {
        push_u64(&mut spec_bytes, claim.slice.log2_len);
        push_u64(&mut spec_bytes, claim.slice.index);
        push_u64(&mut spec_bytes, claim.point.start);
        push_u64(&mut spec_bytes, claim.point.end);
        push_u64(&mut spec_bytes, claim.value);
    }

    let mut pcs_bytes = Vec::new();
    push_u64(&mut pcs_bytes, pcs_params.m);
    push_u64(&mut pcs_bytes, pcs_params.log_inv_rate);
    push_u64(&mut pcs_bytes, pcs_params.log_batch_size);
    let profile = pcs_params.profile.as_str().as_bytes();
    push_u64(&mut pcs_bytes, profile.len());
    pcs_bytes.extend_from_slice(profile);

    let version = [BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION];
    poseidon2b_hash_byte_slices(
        BLOCK_SELECTED_ZK_POST_COMMIT_CLASS_DIGEST_DOMAIN,
        &[
            &version,
            b"block-zk-auth",
            matrix_digest,
            &spec_bytes,
            &pcs_bytes,
            &sidecar_vk_digest,
        ],
    )
}

/// Owned layer-0/layer-66 columns for one post-commit walk.  The committed
/// columns are deliberately absent: every child plan reads them from the
/// enclosing witness through its exact VK slices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionWalkEndpoints {
    s0: [Vec<F128>; 4],
    s_out: [Vec<F128>; 4],
}

impl RegionWalkEndpoints {
    pub fn new(s0: [Vec<F128>; 4], s_out: [Vec<F128>; 4]) -> Self {
        Self { s0, s_out }
    }

    pub(crate) fn s0(&self) -> &[Vec<F128>; 4] {
        &self.s0
    }

    pub(crate) fn s_out(&self) -> &[Vec<F128>; 4] {
        &self.s_out
    }
}

/// Prover-only inputs for the six mandatory block verticals.
///
/// Construction validates every endpoint length against the corresponding
/// child key, so a class cannot reach proving with a missing or cross-wired
/// family.
pub struct BlockRegionProverInput {
    wallet_a: RegionWalkEndpoints,
    meta_a: RegionWalkEndpoints,
    wallet_b: RegionWalkEndpoints,
    meta_b: RegionWalkEndpoints,
    owner_c: RegionWalkEndpoints,
    main_c: RegionWalkEndpoints,
}

impl BlockRegionProverInput {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_selected_zk(
        vk: &BlockRegionSidecarVk,
        wallet_a: RegionWalkEndpoints,
        meta_a: RegionWalkEndpoints,
        wallet_b: RegionWalkEndpoints,
        meta_b: RegionWalkEndpoints,
        owner_c: RegionWalkEndpoints,
        main_c: RegionWalkEndpoints,
    ) -> Result<Self, RegionSidecarError> {
        let input = Self {
            wallet_a,
            meta_a,
            wallet_b,
            meta_b,
            owner_c,
            main_c,
        };
        input.validate_selected_zk(vk)?;
        Ok(input)
    }

    fn validate_selected_zk(&self, vk: &BlockRegionSidecarVk) -> Result<(), RegionSidecarError> {
        vk.validate_selected_zk_roles()?;
        self.validate_children(vk)
    }

    fn validate_children(&self, vk: &BlockRegionSidecarVk) -> Result<(), RegionSidecarError> {
        WalkARegionProverPlan::new(vk.wallet_a(), self.wallet_a.s0(), self.wallet_a.s_out())?;
        WalkARegionProverPlan::new(vk.meta_a(), self.meta_a.s0(), self.meta_a.s_out())?;
        MerkleRegionProverPlan::new(vk.wallet_b(), self.wallet_b.s0(), self.wallet_b.s_out())?;
        MerkleRegionProverPlan::new(vk.meta_b(), self.meta_b.s0(), self.meta_b.s_out())?;
        DuplexRegionProverPlan::new(vk.owner_c(), self.owner_c.s0(), self.owner_c.s_out())?;
        DuplexRegionProverPlan::new(vk.main_c(), self.main_c.s0(), self.main_c.s_out())?;
        Ok(())
    }

    fn validate_children_certified_c1(
        &self,
        vk: &BlockRegionSidecarVk,
    ) -> Result<(), RegionSidecarError> {
        WalkARegionProverPlan::new_certified_c1(
            vk.wallet_a(),
            self.wallet_a.s0(),
            self.wallet_a.s_out(),
        )?;
        WalkARegionProverPlan::new_certified_c1(
            vk.meta_a(),
            self.meta_a.s0(),
            self.meta_a.s_out(),
        )?;
        MerkleRegionProverPlan::new_certified_c1(
            vk.wallet_b(),
            self.wallet_b.s0(),
            self.wallet_b.s_out(),
        )?;
        MerkleRegionProverPlan::new_certified_c1(
            vk.meta_b(),
            self.meta_b.s0(),
            self.meta_b.s_out(),
        )?;
        DuplexRegionProverPlan::new_certified_c1(
            vk.owner_c(),
            self.owner_c.s0(),
            self.owner_c.s_out(),
        )?;
        DuplexRegionProverPlan::new_certified_c1(
            vk.main_c(),
            self.main_c.s0(),
            self.main_c.s_out(),
        )?;
        Ok(())
    }
}

/// Borrowed proving plan.  It has no challenger constructor; callers must run
/// it inside the enclosing Field proof's post-commit context.
pub struct BlockRegionProverPlan<'a> {
    vk: &'a BlockRegionSidecarVk,
    input: &'a BlockRegionProverInput,
}

pub(crate) struct C1BlockRegionProverWalkContinuation<'a, 'z> {
    wallet_a: super::C1WalkARegionProverWalkContinuation<'a, 'z>,
    meta_a: super::C1WalkARegionProverWalkContinuation<'a, 'z>,
    wallet_b: super::C1MerkleRegionProverWalkContinuation<'a, 'z>,
    meta_b: super::C1MerkleRegionProverWalkContinuation<'a, 'z>,
    owner_c: super::C1DuplexRegionProverWalkContinuation<'a, 'z>,
    main_c: super::C1DuplexRegionProverWalkContinuation<'a, 'z>,
}

impl C1BlockRegionProverWalkContinuation<'_, '_> {
    pub(crate) fn groups(&self) -> [C1LaneClaimGroup; 6] {
        [
            self.wallet_a.group().clone(),
            self.meta_a.group().clone(),
            self.wallet_b.group().clone(),
            self.meta_b.group().clone(),
            self.owner_c.group().clone(),
            self.main_c.group().clone(),
        ]
    }

    pub(crate) fn states(&self) -> [&[Vec<F128>; 4]; 6] {
        [
            self.wallet_a.s0(),
            self.meta_a.s0(),
            self.wallet_b.s0(),
            self.meta_b.s0(),
            self.owner_c.s0(),
            self.main_c.s0(),
        ]
    }

    pub(crate) fn finish<Ch: Challenger>(
        self,
        terminals: &[C1LaneClaimGroup; 6],
        challenger: &mut Ch,
    ) -> Result<(C1BlockRegionWalkDeferredProof, Vec<C1QuirkyDirectClaim>), RegionSidecarError>
    {
        let (wallet_a, mut claims) = self.wallet_a.finish(&terminals[0], challenger)?;
        let (meta_a, child_claims) = self.meta_a.finish(&terminals[1], challenger)?;
        claims.extend(child_claims);
        let (wallet_b, child_claims) = self.wallet_b.finish(&terminals[2], challenger)?;
        claims.extend(child_claims);
        let (meta_b, child_claims) = self.meta_b.finish(&terminals[3], challenger)?;
        claims.extend(child_claims);
        let (owner_c, child_claims) = self.owner_c.finish(&terminals[4], challenger)?;
        claims.extend(child_claims);
        let (main_c, child_claims) = self.main_c.finish(&terminals[5], challenger)?;
        claims.extend(child_claims);
        Ok((
            C1BlockRegionWalkDeferredProof {
                wallet_a,
                meta_a,
                wallet_b,
                meta_b,
                owner_c,
                main_c,
            },
            claims,
        ))
    }
}

pub(crate) struct C1BlockRegionVerifierWalkContinuation<'a> {
    wallet_a: super::C1WalkARegionVerifierWalkContinuation<'a>,
    meta_a: super::C1WalkARegionVerifierWalkContinuation<'a>,
    wallet_b: super::C1MerkleRegionVerifierWalkContinuation<'a>,
    meta_b: super::C1MerkleRegionVerifierWalkContinuation<'a>,
    owner_c: super::C1DuplexRegionVerifierWalkContinuation<'a>,
    main_c: super::C1DuplexRegionVerifierWalkContinuation<'a>,
}

impl C1BlockRegionVerifierWalkContinuation<'_> {
    pub(crate) fn groups(&self) -> [C1LaneClaimGroup; 6] {
        [
            self.wallet_a.group().clone(),
            self.meta_a.group().clone(),
            self.wallet_b.group().clone(),
            self.meta_b.group().clone(),
            self.owner_c.group().clone(),
            self.main_c.group().clone(),
        ]
    }

    pub(crate) fn finish<Ch: Challenger>(
        self,
        terminals: &[C1LaneClaimGroup; 6],
        challenger: &mut Ch,
    ) -> Result<Vec<C1QuirkyDirectClaim>, RegionSidecarError> {
        let mut claims = self.wallet_a.finish(&terminals[0], challenger)?;
        claims.extend(self.meta_a.finish(&terminals[1], challenger)?);
        claims.extend(self.wallet_b.finish(&terminals[2], challenger)?);
        claims.extend(self.meta_b.finish(&terminals[3], challenger)?);
        claims.extend(self.owner_c.finish(&terminals[4], challenger)?);
        claims.extend(self.main_c.finish(&terminals[5], challenger)?);
        Ok(claims)
    }
}

/// Owning handoff from block-trace assembly to the causally post-commit
/// prover.  Keeping the VK and its validated endpoint input together avoids
/// cross-class wiring when a built block is queued for proving.
pub struct BlockRegionPreparation {
    vk: BlockRegionSidecarVk,
    input: BlockRegionProverInput,
}

/// Unbound selected preparation state.  It owns the exact six-child key and
/// native endpoints, but cannot enter the prover until the Block matrix has
/// constrained every one of its 256 authorization tiles.
pub(crate) struct SelectedZkBlockRegionDraft {
    vk: BlockRegionSidecarVk,
    input: BlockRegionProverInput,
}

impl SelectedZkBlockRegionDraft {
    pub(crate) fn new(
        vk: BlockRegionSidecarVk,
        input: BlockRegionProverInput,
    ) -> Result<Self, RegionSidecarError> {
        vk.validate_selected_zk_roles()?;
        input.validate_selected_zk(&vk)?;
        Ok(Self { vk, input })
    }

    pub(crate) fn vk(&self) -> &BlockRegionSidecarVk {
        &self.vk
    }

    fn into_parts(self) -> (BlockRegionSidecarVk, BlockRegionProverInput) {
        (self.vk, self.input)
    }
}

impl BlockRegionPreparation {
    /// Selected-ZK finalization is sealed by the owning Block assembly. The
    /// seal's field is private to that module, so no draft/VK-only caller can
    /// construct it or obtain a preparation before the same owner has bound
    /// all tiles and retained the builder through final `build()`.
    pub(crate) fn from_selected_zk_owned_assembly(
        draft: SelectedZkBlockRegionDraft,
        _seal: SelectedBlockAssemblyFinalizationSeal,
        total_vars: usize,
    ) -> Result<Self, RegionSidecarError> {
        let (vk, input) = draft.into_parts();
        vk.validate_selected_zk_roles()?;
        input.validate_selected_zk(&vk)?;
        // All 44 selected slices — including unchanged Meta-A/B, which the
        // authorization candidate does not read — must live inside the matrix
        // that the owner just built. Reject availability drift atomically at
        // finish rather than deferring it to a prover-plan failure.
        let _ = block_c1_proof_shapes(&vk, total_vars)?;
        Ok(Self { vk, input })
    }

    pub fn vk(&self) -> &BlockRegionSidecarVk {
        &self.vk
    }

    pub fn prover_input(&self) -> &BlockRegionProverInput {
        &self.input
    }

    pub fn prover_plan(&self) -> Result<BlockRegionProverPlan<'_>, RegionSidecarError> {
        BlockRegionProverPlan::new_selected_zk(&self.vk, &self.input)
    }

    pub(crate) fn certified_c1_prover_plan(
        &self,
    ) -> Result<BlockRegionProverPlan<'_>, RegionSidecarError> {
        BlockRegionProverPlan::new_certified_c1(&self.vk, &self.input)
    }

    pub fn into_parts(self) -> (BlockRegionSidecarVk, BlockRegionProverInput) {
        (self.vk, self.input)
    }
}

impl<'a> BlockRegionProverPlan<'a> {
    fn new_selected_zk(
        vk: &'a BlockRegionSidecarVk,
        input: &'a BlockRegionProverInput,
    ) -> Result<Self, RegionSidecarError> {
        input.validate_selected_zk(vk)?;
        Ok(Self { vk, input })
    }

    fn new_certified_c1(
        vk: &'a BlockRegionSidecarVk,
        input: &'a BlockRegionProverInput,
    ) -> Result<Self, RegionSidecarError> {
        input.validate_children_certified_c1(vk)?;
        Ok(Self { vk, input })
    }

    pub(crate) fn prove_c1_walk_deferred_prefix<'z, Ch: Challenger>(
        &self,
        z: &'z [F128],
        challenger: &mut Ch,
    ) -> Result<C1BlockRegionProverWalkContinuation<'a, 'z>, RegionSidecarError> {
        bind_block_vk(challenger, self.vk);
        let wallet_a_plan = WalkARegionProverPlan::new_certified_c1(
            self.vk.wallet_a(),
            self.input.wallet_a.s0(),
            self.input.wallet_a.s_out(),
        )?;
        let meta_a_plan = WalkARegionProverPlan::new_certified_c1(
            self.vk.meta_a(),
            self.input.meta_a.s0(),
            self.input.meta_a.s_out(),
        )?;
        let wallet_b_plan = MerkleRegionProverPlan::new_certified_c1(
            self.vk.wallet_b(),
            self.input.wallet_b.s0(),
            self.input.wallet_b.s_out(),
        )?;
        let meta_b_plan = MerkleRegionProverPlan::new_certified_c1(
            self.vk.meta_b(),
            self.input.meta_b.s0(),
            self.input.meta_b.s_out(),
        )?;
        let owner_c_plan = DuplexRegionProverPlan::new_certified_c1(
            self.vk.owner_c(),
            self.input.owner_c.s0(),
            self.input.owner_c.s_out(),
        )?;
        let main_c_plan = DuplexRegionProverPlan::new_certified_c1(
            self.vk.main_c(),
            self.input.main_c.s0(),
            self.input.main_c.s_out(),
        )?;
        Ok(C1BlockRegionProverWalkContinuation {
            wallet_a: wallet_a_plan.prove_c1_walk_deferred_prefix(z, challenger)?,
            meta_a: meta_a_plan.prove_c1_walk_deferred_prefix(z, challenger)?,
            wallet_b: wallet_b_plan.prove_c1_walk_deferred_prefix(z, challenger)?,
            meta_b: meta_b_plan.prove_c1_walk_deferred_prefix(z, challenger)?,
            owner_c: owner_c_plan.prove_c1_walk_deferred_prefix(z, challenger)?,
            main_c: main_c_plan.prove_c1_walk_deferred_prefix(z, challenger)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct C1BlockRegionWalkDeferredProof {
    wallet_a: C1WalkARegionWalkDeferredProof,
    meta_a: C1WalkARegionWalkDeferredProof,
    wallet_b: C1MerkleRegionWalkDeferredProof,
    meta_b: C1MerkleRegionWalkDeferredProof,
    owner_c: C1DuplexRegionWalkDeferredProof,
    main_c: C1DuplexRegionWalkDeferredProof,
}

impl C1BlockRegionWalkDeferredProof {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        wallet_a: C1WalkARegionWalkDeferredProof,
        meta_a: C1WalkARegionWalkDeferredProof,
        wallet_b: C1MerkleRegionWalkDeferredProof,
        meta_b: C1MerkleRegionWalkDeferredProof,
        owner_c: C1DuplexRegionWalkDeferredProof,
        main_c: C1DuplexRegionWalkDeferredProof,
    ) -> Self {
        Self {
            wallet_a,
            meta_a,
            wallet_b,
            meta_b,
            owner_c,
            main_c,
        }
    }

    pub(crate) fn parts(
        &self,
    ) -> (
        &C1WalkARegionWalkDeferredProof,
        &C1WalkARegionWalkDeferredProof,
        &C1MerkleRegionWalkDeferredProof,
        &C1MerkleRegionWalkDeferredProof,
        &C1DuplexRegionWalkDeferredProof,
        &C1DuplexRegionWalkDeferredProof,
    ) {
        (
            &self.wallet_a,
            &self.meta_a,
            &self.wallet_b,
            &self.meta_b,
            &self.owner_c,
            &self.main_c,
        )
    }
}

pub(crate) fn verify_c1_block_region_walk_deferred_prefix<'a, Ch: Challenger>(
    vk: &'a BlockRegionSidecarVk,
    total_vars: usize,
    proof: &'a C1BlockRegionWalkDeferredProof,
    challenger: &mut Ch,
) -> Result<C1BlockRegionVerifierWalkContinuation<'a>, RegionSidecarError> {
    let timing = std::env::var_os("NOIDH_C1_VERIFY_TIMING").is_some();
    let total_started = std::time::Instant::now();
    vk.validate_selected_zk_roles()?;
    let validate_micros = total_started.elapsed().as_micros();
    bind_block_vk(challenger, vk);
    let bind_micros = total_started.elapsed().as_micros() - validate_micros;

    let wallet_a_started = std::time::Instant::now();
    let wallet_a = verify_c1_walk_a_region_walk_deferred_prefix(
        vk.wallet_a(),
        total_vars,
        &proof.wallet_a,
        challenger,
    )?;
    let wallet_a_micros = wallet_a_started.elapsed().as_micros();
    let meta_a_started = std::time::Instant::now();
    let meta_a = verify_c1_walk_a_region_walk_deferred_prefix(
        vk.meta_a(),
        total_vars,
        &proof.meta_a,
        challenger,
    )?;
    let meta_a_micros = meta_a_started.elapsed().as_micros();
    let wallet_b_started = std::time::Instant::now();
    let wallet_b = verify_c1_merkle_region_walk_deferred_prefix(
        vk.wallet_b(),
        total_vars,
        &proof.wallet_b,
        challenger,
    )?;
    let wallet_b_micros = wallet_b_started.elapsed().as_micros();
    let meta_b_started = std::time::Instant::now();
    let meta_b = verify_c1_merkle_region_walk_deferred_prefix(
        vk.meta_b(),
        total_vars,
        &proof.meta_b,
        challenger,
    )?;
    let meta_b_micros = meta_b_started.elapsed().as_micros();
    let owner_c_started = std::time::Instant::now();
    let owner_c = verify_c1_duplex_region_walk_deferred_prefix(
        vk.owner_c(),
        total_vars,
        &proof.owner_c,
        challenger,
    )?;
    let owner_c_micros = owner_c_started.elapsed().as_micros();
    let main_c_started = std::time::Instant::now();
    let main_c = verify_c1_duplex_region_walk_deferred_prefix(
        vk.main_c(),
        total_vars,
        &proof.main_c,
        challenger,
    )?;
    let main_c_micros = main_c_started.elapsed().as_micros();

    if timing {
        eprintln!(
            "[block-c1 prefix] validate_us={validate_micros} bind_us={bind_micros} wallet_a_us={wallet_a_micros} meta_a_us={meta_a_micros} wallet_b_us={wallet_b_micros} meta_b_us={meta_b_micros} owner_c_us={owner_c_micros} main_c_us={main_c_micros} total_us={}",
            total_started.elapsed().as_micros(),
        );
    }
    Ok(C1BlockRegionVerifierWalkContinuation {
        wallet_a,
        meta_a,
        wallet_b,
        meta_b,
        owner_c,
        main_c,
    })
}

pub(crate) struct C1BlockRegionTraceWalkContinuation<'a> {
    wallet_a: super::C1WalkARegionTraceWalkContinuation<'a>,
    meta_a: super::C1WalkARegionTraceWalkContinuation<'a>,
    wallet_b: super::C1MerkleRegionTraceWalkContinuation<'a>,
    meta_b: super::C1MerkleRegionTraceWalkContinuation<'a>,
    owner_c: super::C1DuplexRegionTraceWalkContinuation<'a>,
    main_c: super::C1DuplexRegionTraceWalkContinuation<'a>,
}

impl C1BlockRegionTraceWalkContinuation<'_> {
    pub(crate) fn groups(&self) -> [C1LaneClaimGroupTrace; 6] {
        [
            self.wallet_a.walk_group(),
            self.meta_a.walk_group(),
            self.wallet_b.walk_group(),
            self.meta_b.walk_group(),
            self.owner_c.walk_group(),
            self.main_c.walk_group(),
        ]
    }

    pub(crate) fn finish<C: FsChannelOps>(
        self,
        b: &mut FieldR1csBuilder,
        context: &mut FieldPostCommitTraceContext<'_, C>,
        terminals: &[C1LaneClaimGroupTrace; 6],
    ) -> Result<Vec<C1QuirkyDirectClaimTrace>, RegionSidecarError> {
        let mut claims = self.wallet_a.finish(b, context, &terminals[0])?;
        claims.extend(self.meta_a.finish(b, context, &terminals[1])?);
        claims.extend(self.wallet_b.finish(b, context, &terminals[2])?);
        claims.extend(self.meta_b.finish(b, context, &terminals[3])?);
        claims.extend(self.owner_c.finish(b, context, &terminals[4])?);
        claims.extend(self.main_c.finish(b, context, &terminals[5])?);
        Ok(claims)
    }
}

pub(crate) fn verify_c1_block_region_walk_deferred_prefix_trace<'a, C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    context: &mut FieldPostCommitTraceContext<'_, C>,
    vk: &'a BlockRegionSidecarVk,
    proof: &'a C1BlockRegionWalkDeferredProof,
) -> Result<C1BlockRegionTraceWalkContinuation<'a>, RegionSidecarError> {
    vk.validate_selected_zk_roles()?;
    context.observe_label(b, vk.transcript_label());
    crate::acceptance::trace::self_verify::observe_pinned_digest(
        b,
        context,
        &vk.transcript_digest(),
    );
    let wallet_a = verify_c1_walk_a_region_walk_deferred_prefix_trace(
        b,
        context,
        vk.wallet_a(),
        &proof.wallet_a,
    )?;
    let meta_a =
        verify_c1_walk_a_region_walk_deferred_prefix_trace(b, context, vk.meta_a(), &proof.meta_a)?;
    let wallet_b = verify_c1_merkle_region_walk_deferred_prefix_trace(
        b,
        context,
        vk.wallet_b(),
        &proof.wallet_b,
    )?;
    let meta_b =
        verify_c1_merkle_region_walk_deferred_prefix_trace(b, context, vk.meta_b(), &proof.meta_b)?;
    let owner_c = verify_c1_duplex_region_walk_deferred_prefix_trace(
        b,
        context,
        vk.owner_c(),
        &proof.owner_c,
    )?;
    let main_c =
        verify_c1_duplex_region_walk_deferred_prefix_trace(b, context, vk.main_c(), &proof.main_c)?;
    Ok(C1BlockRegionTraceWalkContinuation {
        wallet_a,
        meta_a,
        wallet_b,
        meta_b,
        owner_c,
        main_c,
    })
}

pub(super) struct BlockC1ProofShapes {
    pub(super) wallet_a: DeferredFixedProofShape,
    pub(super) meta_a: DeferredFixedProofShape,
    pub(super) wallet_b: DeferredMerkleProofShape,
    pub(super) meta_b: DeferredMerkleProofShape,
    pub(super) owner_c: DeferredFixedProofShape,
    pub(super) main_c: DeferredFixedProofShape,
}

pub(super) fn block_c1_proof_shapes(
    vk: &BlockRegionSidecarVk,
    total_vars: usize,
) -> Result<BlockC1ProofShapes, RegionSidecarError> {
    Ok(BlockC1ProofShapes {
        wallet_a: walk_a_bounded_shape(vk.wallet_a(), total_vars)?.walk_deferred(),
        meta_a: walk_a_bounded_shape(vk.meta_a(), total_vars)?.walk_deferred(),
        wallet_b: merkle_shape_for_vk(vk.wallet_b(), total_vars)?.walk_deferred(),
        meta_b: merkle_shape_for_vk(vk.meta_b(), total_vars)?.walk_deferred(),
        owner_c: duplex_shape_for_vk(vk.owner_c(), total_vars)?.walk_deferred(),
        main_c: duplex_shape_for_vk(vk.main_c(), total_vars)?.walk_deferred(),
    })
}

pub(crate) fn shape_only_c1_block_region_walk_deferred_proof(
    vk: &BlockRegionSidecarVk,
    total_vars: usize,
) -> Result<C1BlockRegionWalkDeferredProof, RegionSidecarError> {
    use noid_ivc_core::deep_chain::relations::c1::{C1ColumnRelationProof, C1ShiftDischargeProof};

    use crate::acceptance::trace::region_source_binding_c1::{
        C1DuplexUnionWalkDeferredProof, C1MerkleUnionWalkDeferredProof,
        C1WalkAUnionWalkDeferredProof,
    };

    let relation = |rounds: usize, values: usize| C1ColumnRelationProof {
        rounds: vec![[F256::ZERO; noid_ivc_core::deep_chain::relations::RELATION_DEGREE]; rounds],
        final_values: vec![F256::ZERO; values],
    };
    let shifts = |count: usize, w_log: usize| -> Vec<C1ShiftDischargeProof> {
        (0..count)
            .map(|_| C1ShiftDischargeProof {
                rounds: vec![[F256::ZERO; 2]; w_log],
                final_value: F256::ZERO,
            })
            .collect()
    };
    let fixed_child = |shape: &super::bounded_decode::DeferredFixedProofShape| {
        (
            relation(shape.w_log, shape.selection_values),
            relation(shape.w_log, shape.substitution_values),
            shifts(shape.shifts, shape.w_log),
            match shape.tail {
                super::bounded_decode::ProofTailShape::None
                | super::bounded_decode::ProofTailShape::RelationOption(None) => None,
                super::bounded_decode::ProofTailShape::RelationOption(Some(spine)) => {
                    Some(relation(spine.rounds, spine.values))
                }
            },
        )
    };
    let BlockC1ProofShapes {
        wallet_a: wallet_a_shape,
        meta_a: meta_a_shape,
        wallet_b: wallet_b_shape,
        meta_b: meta_b_shape,
        owner_c: owner_c_shape,
        main_c: main_c_shape,
    } = block_c1_proof_shapes(vk, total_vars)?;
    let walk_a = |shape: &super::bounded_decode::DeferredFixedProofShape| {
        let (selection, substitution, shifts, spine_exposure) = fixed_child(shape);
        C1WalkARegionWalkDeferredProof::new(C1WalkAUnionWalkDeferredProof {
            selection,
            substitution,
            shifts,
            spine_exposure,
        })
    };
    let merkle = |shape: &super::bounded_decode::DeferredMerkleProofShape| {
        C1MerkleRegionWalkDeferredProof::new(C1MerkleUnionWalkDeferredProof {
            zero: relation(shape.w_log, shape.zero_values),
            zero_shifts: shifts(shape.zero_shifts, shape.w_log),
            selection: relation(shape.w_log, shape.selection_values),
            substitution: relation(shape.w_log, shape.substitution_values),
            shifts: shifts(shape.shifts, shape.w_log),
        })
    };
    let duplex = |shape: &super::bounded_decode::DeferredFixedProofShape| {
        C1DuplexRegionWalkDeferredProof::new(C1DuplexUnionWalkDeferredProof {
            selection: relation(shape.w_log, shape.selection_values),
            substitution: relation(shape.w_log, shape.substitution_values),
            shifts: shifts(shape.shifts, shape.w_log),
        })
    };
    Ok(C1BlockRegionWalkDeferredProof {
        wallet_a: walk_a(&wallet_a_shape),
        meta_a: walk_a(&meta_a_shape),
        wallet_b: merkle(&wallet_b_shape),
        meta_b: merkle(&meta_b_shape),
        owner_c: duplex(&owner_c_shape),
        main_c: duplex(&main_c_shape),
    })
}

fn bind_block_vk<Ch: Challenger>(challenger: &mut Ch, vk: &BlockRegionSidecarVk) {
    challenger.observe_label(vk.transcript_label());
    challenger.observe_bytes(&vk.transcript_digest());
}

fn push_u64(bytes: &mut Vec<u8>, value: usize) {
    let value = u64::try_from(value).expect("block sidecar class index exceeds u64");
    bytes.extend_from_slice(&value.to_le_bytes());
}
