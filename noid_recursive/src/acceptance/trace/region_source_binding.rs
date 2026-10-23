// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared committed-region machinery for the selected ZK Block relation.
//!
//! The production allocator closes the fixed six-child selected geometry:
//! authorization wallet-A/wallet-B/main/owner regions plus exact-state,
//! transaction-root and body-spine Meta-A/Meta-B carriers. The generic walk
//! protocols below reconstruct their terminal openings from verifier-pinned
//! layouts; prover-controlled region descriptors are never accepted.

use noid_fri_binius::zk_capsule_pcs::{
    ZK_CAPSULE_PCS_MID_PATH_DEPTH, ZK_CAPSULE_PCS_QUERY_COUNT as SELECTED_ZK_QUERY_COUNT,
    ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
};
use noid_poseidon2b::native::domain::{capacity_iv, DomainTag, TAG_CAPSNODE, TAG_EXSTNOD};
#[cfg(test)]
use noid_poseidon2b::native::domain::{TAG_FRICHANL, TAG_KSCH256, TAG_KSCHANNL};
use noid_poseidon2b::native::permutation::STATE_SIZE;

use noid_ivc_core::challenger::Challenger;
#[cfg(test)]
use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::deep_chain::capsule_leaf::CAPSULE_LEAF_STRIDE;
#[cfg(test)]
use noid_ivc_core::deep_chain::ff_merkle::{
    build_ff_merkle_path_columns, ff_merkle_fixed_patterns, FfMerklePathFamily, FfMerklePathWitness,
};
use noid_ivc_core::deep_chain::ff_merkle::{
    ff_merkle_chain_terms, ff_merkle_substitution_terms, FfMerkleFamilyRefs,
};
use noid_ivc_core::deep_chain::leaf_hash::{
    build_sponge_leaf_columns, slot_leaf_pad_flat, sponge_leaf_substitution_terms, SpongeLeafRefs,
    SPONGE_LEAF_DIGEST_SLOT, SPONGE_LEAF_SLOTS,
};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, prove_shift_discharge_pow2,
    verify_column_relation, verify_shift_discharge, verify_shift_discharge_pow2, ColRef,
    ColumnRelationProof, FixedPattern, RelationColumns, RelationError, RelationTerm,
    ShiftDischargeProof,
};
use noid_ivc_core::deep_chain::schedule::{
    build_duplex_columns, build_merkle_path_columns, carry_selection_terms, duplex_family_refs,
    duplex_fixed_patterns, duplex_substitution_terms, flat_of_tower_u128, merkle_booleanity_terms,
    merkle_substitution_terms, DuplexFamilyRefs, DuplexLayout, DuplexSlot, LaneSource,
    MerkleFamilyRefs, MerklePathColumns, MerklePathFamily, MerklePathWitness,
};
#[cfg(test)]
use noid_ivc_core::deep_chain::schedule::{compile_duplex, merkle_fixed_patterns};
use noid_ivc_core::deep_chain::source_tree::{
    compress_iv_flat, mds_weights_pub, source_tree_substitution_terms, SourceTreeRefs,
};
use noid_ivc_core::deep_chain::spine::{
    build_spine_instance_columns, build_spine_instance_columns_with_contract,
    spine_tree_exposure_terms, spine_tree_internal_child_pattern, SpineContractInstanceFlat,
    SpineInstanceFlat, SPINE_CONTRACT_CODE_BASE, SPINE_CONTRACT_NEW_OBJECT_BASE,
    SPINE_CONTRACT_OLD_OBJECT_BASE, SPINE_CONTRACT_POLICY_BASE, SPINE_TREE_KID_LEAF_BASE,
    SPINE_TREE_LEAVES, SPINE_TREE_SLOTS, SPINE_V2_WRAP_SLOTS, SPINE_WRAP_SLOT, SPINE_WRAP_SLOTS,
};
use noid_ivc_core::deep_chain::{
    prove_deep_chain_walk, verify_deep_chain_walk, DeepChainWalkProof, LaneClaimGroup, WalkError,
};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr, Wire};
#[cfg(test)]
use noid_ivc_core::field_circuit::{
    FsChannelOps, FsChannelTrace, FsChannelUnionRecorder, RecordedChannel,
};
use noid_ivc_core::public_io::WitnessSlice;

use super::deep_chain::RelationTermTrace;
#[cfg(test)]
use super::deep_chain::{
    verify_column_relation_trace, verify_deep_chain_walk_trace, verify_shift_discharge_trace,
    ColumnRelationProofTrace, DeepChainWalkProofTrace, LaneClaimGroupTrace,
    ShiftDischargeProofTrace,
};
use super::exact_state::{ExactStatePairedRegionData, ExactStateRegionData};
#[cfg(test)]
use super::fri_pcs::mle_evaluate_small_trace;
#[cfg(test)]
use super::paired_merkle_update::paired_merkle_update_fixed_patterns;
use super::paired_merkle_update::{
    build_paired_merkle_update_columns, paired_merkle_update_consistency_terms,
    paired_merkle_update_refs, paired_merkle_update_substitution_terms, paired_update_root_offsets,
    PairedMerkleUpdateRefs, PAIRED_UPDATE_DEPTH, PAIRED_UPDATE_SLOTS_PER_LEVEL,
    PAIRED_UPDATE_STRIDE,
};
use super::{mul, pin_eq};
#[cfg(test)]
use crate::acceptance::zk_auth_capsule_schedule::{
    selected_zk_auth_main_sidecar_purpose, selected_zk_auth_owner_sidecar_purpose,
    selected_zk_auth_wallet_a_sidecar_purpose, selected_zk_auth_wallet_b_sidecar_purpose,
};

// FS domains for the region walks (self-contained sub-protocols; the soundness
// of the discharge lives in the committed-column opening claims the caller
// threads through the outer PCS, not in these transcripts).  Wallet capsule
// leaves and block metadata intentionally use independent transcripts: their
// very different natural domains must never force one another to round up.
const DOMAIN_A_WALLET: &[u8] = b"source-binding-wallet-leaf-union";
const DOMAIN_A_META: &[u8] = b"source-binding-block-meta-union";
const DOMAIN_B_WALLET: &[u8] = b"source-binding-wallet-merkle-union";
const DOMAIN_B_META: &[u8] = b"source-binding-block-meta-merkle-union";
const DOMAIN_C: &[u8] = b"source-binding-full-duplex-union";
#[cfg(test)]
const DOMAIN_D: &[u8] = b"source-binding-recording-only-host";

// Meta committed column order (all length P):
//   KID0=0, KID1=1, IN0=2, IN1=3, C0=4..C3=7.
// The source-tree CODE lanes RIDE the IN columns: CODE cells live only in
// source-tree slots ([tx_off, +st_slots) and the ghosted spine trees), IN
// cells only in leaf/es/spine-tile slots — disjoint by layout, and every
// relation term reading either is gated by its family's fixed pattern.
const KID0: usize = 0;
const IN0: usize = 2;
const C0: usize = 4;
const N_META_COMMITTED: usize = 8;

/// One block-tiled walk domain. `bases[i]` is the start of leg `i` inside a
/// block; the block and full walk are independently rounded to powers of two.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TiledWalkLayout {
    bases: Vec<usize>,
    live_per_block: usize,
    block_log: usize,
    block_slots: usize,
    w_log: usize,
    slots: usize,
}

/// Raw block-metadata half of the authorization PCS region assembly.
///
/// This draft deliberately knows nothing about wallet obligations or native
/// capsule proofs.  It owns the canonical Meta-A/Meta-B geometry, filled
/// columns and endpoints, exact cell-pin intents, and the ordered Meta-B
/// family descriptors.  The enclosing assembler still owns physical column
/// allocation and the legacy/selected finalization policy.
struct AuthPcsMetaRegionDraft {
    has_meta: bool,
    has_both_a_families: bool,
    es_region_slots: usize,
    spine_cap: usize,
    meta_w_log: usize,
    meta_b: Option<TiledWalkLayout>,
    paired_caps_per_block: Option<[usize; 2]>,
    paired_bases: Option<[usize; 2]>,
    leg_depths: Vec<usize>,
    leg_caps: Vec<usize>,
    meta_b_families: Vec<crate::region_sidecar::MerkleRegionFamily>,
    meta_cols: Vec<Vec<F128>>,
    meta_s0: [Vec<F128>; STATE_SIZE],
    meta_s_out: [Vec<F128>; STATE_SIZE],
    cb_meta_b: Vec<Vec<F128>>,
    s0_meta_b: [Vec<F128>; STATE_SIZE],
    sout_meta_b: [Vec<F128>; STATE_SIZE],
    cell_pins_meta: Vec<(usize, usize, LinExpr)>,
    cell_pins_meta_b: Vec<(usize, usize, LinExpr)>,
    acc_committed_roots: Vec<Vec<[F128; 2]>>,
    acc_recomputed_roots: Vec<Vec<[F128; 2]>>,
    acc_entry_wires: Vec<Vec<[LinExpr; 2]>>,
    acc_root_wires: Vec<Vec<[LinExpr; 2]>>,
    acc_path_slots: Vec<Vec<usize>>,
}

/// Lay out non-empty, disjoint leg slot ranges in one K-tiled walk.
fn tiled_walk_layout(k: usize, leg_slots: &[usize]) -> TiledWalkLayout {
    assert!(k.is_power_of_two(), "walk tile count must be dyadic");
    assert!(!leg_slots.is_empty(), "walk needs at least one leg");
    assert!(leg_slots.iter().all(|&n| n > 0), "empty walk leg");
    let mut bases = Vec::with_capacity(leg_slots.len());
    let mut live_per_block = 0usize;
    for &slots in leg_slots {
        bases.push(live_per_block);
        live_per_block = live_per_block
            .checked_add(slots)
            .expect("walk block geometry overflow");
    }
    let block_slots = live_per_block.next_power_of_two();
    let block_log = block_slots.trailing_zeros() as usize;
    let slots = k
        .checked_mul(block_slots)
        .expect("walk domain geometry overflow");
    debug_assert!(slots.is_power_of_two());
    TiledWalkLayout {
        bases,
        live_per_block,
        block_log,
        block_slots,
        w_log: slots.trailing_zeros() as usize,
        slots,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// One discharged committed-column opening claim, carrying both the trace-wire
/// (point, value) and the concrete native (point, value) the caller folds into
/// the link's public IO envelope. `slice` is the committed [`WitnessSlice`]
/// allocated in the builder for this claim's column.
pub struct RegionPcsClaim {
    pub slice: WitnessSlice,
    /// Trace-wire point coordinates.
    pub point: Vec<LinExpr>,
    /// Trace-wire opened value.
    pub value: LinExpr,
    /// Native point (for the caller's IO envelope).
    pub native_point: Vec<F128>,
    /// Native opened value (for the caller's IO envelope).
    pub native_value: F128,
}

/// Fixed-capacity cells exposed by one local depth-16 paired update.
#[derive(Clone)]
pub struct PairedLocalExactStateCells {
    pub old_entry: [LinExpr; 2],
    pub new_entry: [LinExpr; 2],
    pub old_root: [LinExpr; 2],
    pub new_root: [LinExpr; 2],
    /// One old-even direction cell per level. The committed four-slot copy
    /// chain is enforced by the post-commit Merkle relation.
    pub directions: [LinExpr; PAIRED_UPDATE_DEPTH],
}

/// Fixed-capacity cells exposed by one upper paired update. All sixteen root
/// depths are carried; the later consumer, not this region, selects the
/// header-bound active upper depth.
#[derive(Clone)]
pub struct PairedUpperExactStateCells {
    pub old_entry: [LinExpr; 2],
    pub new_entry: [LinExpr; 2],
    pub old_roots: [[LinExpr; 2]; PAIRED_UPDATE_DEPTH],
    pub new_roots: [[LinExpr; 2]; PAIRED_UPDATE_DEPTH],
    pub directions: [LinExpr; PAIRED_UPDATE_DEPTH],
}

/// Block-slots handoff for the paired exact-state carrier. Vector lengths are
/// the class capacities, not the live update counts.
#[derive(Clone)]
pub struct PairedExactStateCells {
    pub local: Vec<PairedLocalExactStateCells>,
    pub upper: Vec<PairedUpperExactStateCells>,
}

const AUTH_PCS_REGION_SIDECAR_PURPOSE_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/AUTH-PCS-PRODUCTION/V1";

fn auth_pcs_region_sidecar_purpose(role: &[u8], walk_domain: &[u8]) -> [u8; 32] {
    noid_poseidon2b::native::poseidon2b_hash_byte_slices(
        AUTH_PCS_REGION_SIDECAR_PURPOSE_DOMAIN,
        &[role, walk_domain],
    )
}

/// Canonical role purpose for the wallet capsule-leaf Walk-A vertical.
pub fn auth_pcs_wallet_a_sidecar_purpose() -> [u8; 32] {
    auth_pcs_region_sidecar_purpose(b"wallet-a", DOMAIN_A_WALLET)
}

/// Canonical role purpose for the exact-state/body-spine Walk-A vertical.
pub fn auth_pcs_meta_a_sidecar_purpose() -> [u8; 32] {
    auth_pcs_region_sidecar_purpose(b"meta-a", DOMAIN_A_META)
}

/// Canonical role purpose for the wallet capsule-path Walk-B vertical.
pub fn auth_pcs_wallet_b_sidecar_purpose() -> [u8; 32] {
    auth_pcs_region_sidecar_purpose(b"wallet-b", DOMAIN_B_WALLET)
}

/// Canonical role purpose for the exact-state/tx-root Walk-B vertical.
pub fn auth_pcs_meta_b_sidecar_purpose() -> [u8; 32] {
    auth_pcs_region_sidecar_purpose(b"meta-b", DOMAIN_B_META)
}

/// Canonical role purpose for the recording-free main FRICHANL Walk-C.
pub fn auth_pcs_main_c_sidecar_purpose() -> [u8; 32] {
    auth_pcs_region_sidecar_purpose(b"main-c", DOMAIN_C)
}

// Selected-ZK column counts shared by both canonical geometries. Domain
// logs and class capacities come from the exact geometry certificate in
// `region_sidecar::block`; lower tiers never allocate B255-sized columns.
const SELECTED_ZK_REGION_QUERY_LOG: usize = 6;
const SELECTED_ZK_REGION_CORE_QUERY_COUNT: usize = 1 << SELECTED_ZK_REGION_QUERY_LOG;
const SELECTED_ZK_REGION_WALLET_A_COLUMNS: usize = 6;
const SELECTED_ZK_REGION_WALLET_B_COLUMNS: usize = 9;
const SELECTED_ZK_REGION_META_B_COLUMNS: usize = 9;
const SELECTED_ZK_REGION_MAIN_COLUMNS: usize = 6;
const SELECTED_ZK_REGION_META_A_COLUMNS: usize = 8;
const SELECTED_ZK_REGION_OWNER_COLUMNS: usize = 6;
const SELECTED_ZK_REGION_COMMITTED_COLUMNS: usize = 44;

// B255 snapshot spellings retained only by the exact regression tests below.
#[cfg(test)]
const SELECTED_ZK_REGION_TX_LOG: usize = 8;
#[cfg(test)]
const SELECTED_ZK_REGION_WALLET_A_LOG: usize = 19;
#[cfg(test)]
const SELECTED_ZK_REGION_WALLET_B_LOG: usize = 18;
#[cfg(test)]
const SELECTED_ZK_REGION_META_B_LOG: usize = 17;
#[cfg(test)]
const SELECTED_ZK_REGION_MAIN_LOG: usize = 16;
#[cfg(test)]
const SELECTED_ZK_REGION_META_A_LOG: usize = 15;
#[cfg(test)]
const SELECTED_ZK_REGION_OWNER_LOG: usize = 15;
#[cfg(test)]
const SELECTED_ZK_REGION_COMMITTED_CELLS: usize = 7_536_640;

const _: () = assert!(SELECTED_ZK_QUERY_COUNT == SELECTED_ZK_REGION_CORE_QUERY_COUNT + 1);
const _: () = assert!(
    SELECTED_ZK_REGION_WALLET_A_COLUMNS
        + SELECTED_ZK_REGION_WALLET_B_COLUMNS
        + SELECTED_ZK_REGION_META_B_COLUMNS
        + SELECTED_ZK_REGION_MAIN_COLUMNS
        + SELECTED_ZK_REGION_META_A_COLUMNS
        + SELECTED_ZK_REGION_OWNER_COLUMNS
        == SELECTED_ZK_REGION_COMMITTED_COLUMNS
);

/// Allocation-free input failures for the private selected common
/// allocator. Every variant is returned before the builder is touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SelectedZkAuthPcsRegionAllocationError {
    AuthorizationShape,
    ExactStateShape,
    TxRootShape,
    SpineShape,
}

/// Opaque result of the one selected authorization+Meta allocation boundary.
/// It is not a preparation and carries no finalization token. The owning Block
/// assembly may borrow the draft to bind all class authorization tiles, then
/// consume this value to recover the draft and paired exact-state handoff.
pub(super) struct SelectedZkAuthPcsRegionAllocation {
    draft: crate::region_sidecar::SelectedZkBlockRegionDraft,
    paired: PairedExactStateCells,
}

impl SelectedZkAuthPcsRegionAllocation {
    pub(super) fn draft(&self) -> &crate::region_sidecar::SelectedZkBlockRegionDraft {
        &self.draft
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        crate::region_sidecar::SelectedZkBlockRegionDraft,
        PairedExactStateCells,
    ) {
        (self.draft, self.paired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SelectedZkRegionFamily {
    Main,
    Owner,
    WalletB,
    WalletA,
    MetaA,
    MetaB,
}

impl SelectedZkRegionFamily {
    const ALL: [Self; 6] = [
        Self::Main,
        Self::Owner,
        Self::WalletB,
        Self::WalletA,
        Self::MetaA,
        Self::MetaB,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    fn dimensions(
        self,
        geometry: crate::region_sidecar::SelectedZkBlockGeometry,
    ) -> (usize, usize) {
        match self {
            Self::Main => (geometry.main_w_log, SELECTED_ZK_REGION_MAIN_COLUMNS),
            Self::Owner => (geometry.owner_w_log, SELECTED_ZK_REGION_OWNER_COLUMNS),
            Self::WalletB => (geometry.wallet_b_w_log, SELECTED_ZK_REGION_WALLET_B_COLUMNS),
            Self::WalletA => (geometry.wallet_a_w_log, SELECTED_ZK_REGION_WALLET_A_COLUMNS),
            Self::MetaA => (geometry.meta_a_w_log, SELECTED_ZK_REGION_META_A_COLUMNS),
            Self::MetaB => (geometry.meta_b_w_log, SELECTED_ZK_REGION_META_B_COLUMNS),
        }
    }
}

fn next_selected_family_permutation(order: &mut [SelectedZkRegionFamily; 6]) -> bool {
    let Some(pivot) = (0..order.len() - 1)
        .rev()
        .find(|&index| order[index] < order[index + 1])
    else {
        return false;
    };
    let successor = (pivot + 1..order.len())
        .rev()
        .find(|&index| order[pivot] < order[index])
        .expect("permutation pivot has a successor");
    order.swap(pivot, successor);
    order[pivot + 1..].reverse();
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedZkRegionAllocationLedger {
    before: usize,
    order: [SelectedZkRegionFamily; 6],
    main: usize,
    owner: usize,
    wallet_b: usize,
    wallet_a: usize,
    meta_a: usize,
    meta_b: usize,
    after: usize,
}

impl SelectedZkRegionAllocationLedger {
    fn new(before: usize, geometry: crate::region_sidecar::SelectedZkBlockGeometry) -> Self {
        let mut candidate = SelectedZkRegionFamily::ALL;
        let mut best_order = candidate;
        let mut best_starts = [0usize; 6];
        let mut best_after = usize::MAX;
        loop {
            let mut cursor = before;
            let mut starts = [0usize; 6];
            for family in candidate {
                let (w_log, columns) = family.dimensions(geometry);
                let width = 1usize
                    .checked_shl(w_log as u32)
                    .expect("selected family width overflow");
                cursor = cursor
                    .checked_next_multiple_of(width)
                    .expect("selected family alignment overflow");
                starts[family.index()] = cursor;
                cursor = cursor
                    .checked_add(
                        columns
                            .checked_mul(width)
                            .expect("selected family column span overflow"),
                    )
                    .expect("selected family allocation overflow");
            }
            if cursor < best_after {
                best_order = candidate;
                best_starts = starts;
                best_after = cursor;
            }
            if !next_selected_family_permutation(&mut candidate) {
                break;
            }
        }
        Self {
            before,
            order: best_order,
            main: best_starts[SelectedZkRegionFamily::Main.index()],
            owner: best_starts[SelectedZkRegionFamily::Owner.index()],
            wallet_b: best_starts[SelectedZkRegionFamily::WalletB.index()],
            wallet_a: best_starts[SelectedZkRegionFamily::WalletA.index()],
            meta_a: best_starts[SelectedZkRegionFamily::MetaA.index()],
            meta_b: best_starts[SelectedZkRegionFamily::MetaB.index()],
            after: best_after,
        }
    }
}

fn append_meta_b_statement_pins(
    pins: &mut Vec<(usize, usize, LinExpr)>,
    leg_depths: &[usize],
    entry_wires: &[Vec<[LinExpr; 2]>],
    root_wires: &[Vec<[LinExpr; 2]>],
    committed_roots: &[Vec<[F128; 2]>],
    recomputed_roots: &[Vec<[F128; 2]>],
    path_slots: &[Vec<usize>],
) {
    for family in 0..leg_depths.len() {
        let n_paths = path_slots[family].len();
        assert_eq!(entry_wires[family].len(), n_paths, "meta-B entry count");
        assert_eq!(root_wires[family].len(), n_paths, "meta-B root count");
        assert_eq!(
            committed_roots[family].len(),
            n_paths,
            "meta-B committed-root count"
        );
        assert_eq!(
            recomputed_roots[family].len(),
            n_paths,
            "meta-B recomputed-root count"
        );
        let root_slot_local = 2 * (leg_depths[family] - 1) + 1;
        for path in 0..n_paths {
            let entry_slot = path_slots[family][path];
            for lane in 0..2 {
                pins.push((
                    4 + lane,
                    entry_slot,
                    entry_wires[family][path][lane].clone(),
                ));
                assert_eq!(
                    recomputed_roots[family][path][lane], committed_roots[family][path][lane],
                    "meta-B recomputed/committed root mismatch"
                );
                pins.push((
                    lane,
                    entry_slot + root_slot_local,
                    root_wires[family][path][lane].clone(),
                ));
            }
        }
    }
}

fn pin_stage2_cells(
    b: &mut FieldR1csBuilder,
    slices: &[WitnessSlice],
    pins: &[(usize, usize, LinExpr)],
) {
    for (column, slot, wire) in pins {
        pin_eq(b, wire, &slot_cell(&slices[*column], *slot));
    }
}

#[cfg(test)]
#[derive(Clone)]
struct WalletFfRootPin {
    base_slot: usize,
    depth: usize,
    root_wires: [LinExpr; 2],
}

#[cfg(test)]
impl WalletFfRootPin {
    fn new(base_slot: usize, depth: usize, root_wires: [LinExpr; 2]) -> Self {
        assert!(depth > 0, "ff-Merkle root pin needs a non-empty path");
        Self {
            base_slot,
            depth,
            root_wires,
        }
    }
}

/// Pin the public root of each wallet-B feed-forward path. Non-power-of-two
/// depths use the CR root-copy cell constrained by `NODENS`. At an exact
/// power-of-two depth there is no spare stride slot, so reconstruct the final
/// feed-forward digest from committed cells already constrained by the node
/// substitution and CR-chain relations:
///
/// `root_i = C_i + CR_i + D * (CR_i + SIB_i)`.
#[cfg(test)]
fn pin_wallet_b_roots(
    b: &mut FieldR1csBuilder,
    slices: &[WitnessSlice],
    root_pins: &[WalletFfRootPin],
) {
    for pin in root_pins {
        let stride = pin.depth.next_power_of_two();
        for lane in 0..2 {
            let root = if pin.depth < stride {
                slot_cell(&slices[4 + lane], pin.base_slot + pin.depth)
            } else {
                let last = pin.base_slot + pin.depth - 1;
                let cr = slot_cell(&slices[4 + lane], last);
                let sib = slot_cell(&slices[6 + lane], last);
                let direction = slot_cell(&slices[8], last);
                let selected_delta = mul(b, &direction, &cr.add(&sib));
                slot_cell(&slices[lane], last).add(&cr).add(&selected_delta)
            };
            pin_eq(b, &root, &pin.root_wires[lane]);
        }
    }
}

// ===========================================================================
/// One feed-forward wallet leg's union wiring: column/pattern indices only
/// (entries, directions and roots bind through cell pins in the caller).
#[cfg(test)]
pub(crate) struct FfLegSpec {
    pub(crate) refs: FfMerkleFamilyRefs,
    pub(crate) region: usize,
}

/// The tx-root region handoff: every transaction body-hash Merkle path to the
/// underlying universal 256-leaf tree root `M`, as ONE walk-B TAG_COMPRESS
/// leg. Entries are the SPINE tx-hash wires (the leaf closure); `root_w` is
/// `M` (the root closure), not the header `tx_root`. The block slot separately
/// binds `TAG_TXROOT(M, tx_count)` to the header. Direction bits are the
/// CONSTANT leaf-index bits and the last real path's right-hand siblings are
/// the zero-subtree padding constants — both become const cell pins on the
/// committed D/SIB cells.
pub struct TxRootRegionData {
    /// Universal transaction-tree depth; fixed to `TX_TREE_DEPTH == 8`.
    pub depth: usize,
    /// Underlying universal-tree root `M` wires — every path's expected root.
    pub root_w: [LinExpr; 2],
    pub root_flat: [F128; 2],
    /// One path per transaction, in tx order (path `j`'s leaf position is `j`).
    pub paths: Vec<TxRootPathRegion>,
    /// Zero-subtree digest lanes per level (`Z_0 = zero leaf`,
    /// `Z_{l+1} = compress(Z_l, Z_l)`) — the padding-rim constants.
    pub rim_flat: Vec<[F128; 2]>,
}

/// One tx-root path's region handoff. The direction bits are NOT carried:
/// they are the leaf-index bits of the path's position in
/// [`TxRootRegionData::paths`], const-pinned in the leg fill.
pub struct TxRootPathRegion {
    /// The spine tx-hash wires — the walk-B entry (shared-wire leaf closure).
    pub entry_w: [LinExpr; 2],
    pub entry_flat: [F128; 2],
    /// Sibling digests, flat lanes, `[..depth]`.
    pub siblings: Vec<[F128; 2]>,
}

/// Final 31-permutation Tx8x2 spine handoff.  One instance per block
/// transaction (coinbase included), in transaction order.
pub struct SpineRegionData {
    pub instances: Vec<SpineInstanceRegion>,
    pub objects: bool,
}

/// One transaction's spine handoff: all sixteen canonical raw body leaves,
/// plus the tx-body hash pair consumed by the tx-root and owner-auth paths.
pub struct SpineInstanceRegion {
    pub flat: SpineInstanceFlat,
    pub leaves_w: [[LinExpr; 2]; SPINE_TREE_LEAVES],
    pub tx_hash_w: [LinExpr; 2],
    pub tx_hash_flat: [F128; 2],
    pub contract: Option<SpineContractRegion>,
}

/// Contract commitment values and exact HistoryStep aliases for one body.
pub struct SpineContractRegion {
    pub live: LinExpr,
    pub terminal: LinExpr,
    pub flat: SpineContractInstanceFlat,
    pub program_w: [[LinExpr; 2]; noid_ivc_core::deep_chain::spine::SPINE_CONTRACT_PROGRAM_STEPS],
    pub current_w: LinExpr,
    pub next_w: LinExpr,
    pub controller_w: [LinExpr; 2],
    pub refund_authority_w: [LinExpr; 2],
    pub code_digest_w: [LinExpr; 2],
    pub policy_digest_w: [LinExpr; 2],
    pub contexts_w: [LinExpr; noid_tx::experimental_object::BODY_CONTEXT_FIELDS],
    pub deadline_w: LinExpr,
    pub claim_recipient_w: [LinExpr; 2],
    pub refund_recipient_w: [LinExpr; 2],
    pub rules_w: [LinExpr; 4],
    pub old_object_root_w: [LinExpr; 2],
    pub new_object_root_w: [LinExpr; 2],
}

/// Assemble the complete raw Meta-A/Meta-B draft without observing wallet
/// obligations or native capsule proofs.  This is intentionally called at the
/// old metadata-fill point in the enclosing monolith, so the spine bridge-wire
/// allocation order remains byte-for-byte/matrix-for-matrix unchanged.
fn build_auth_pcs_meta_region_draft(
    b: &mut FieldR1csBuilder,
    k: usize,
    es: Option<&ExactStateRegionData>,
    txr: Option<&TxRootRegionData>,
    spine: Option<&SpineRegionData>,
    wallet_overflow: Option<&super::zk_authorization_region::SelectedZkAuthorizationOverflow>,
) -> AuthPcsMetaRegionDraft {
    assert!(k.is_power_of_two(), "meta region tile count must be dyadic");
    let objects = spine.is_some_and(|spine| spine.objects);
    let wrap_slots = if objects {
        SPINE_V2_WRAP_SLOTS
    } else {
        SPINE_WRAP_SLOTS
    };

    // Meta-A geometry: EXSTSLT and the body spine occupy separate aligned
    // dyadic regions when both are present.
    let es_region_slots = es.map_or(0, |e| {
        assert!(!e.leaves.is_empty(), "exact-state handoff without leaves");
        (e.leaves.len() * SPONGE_LEAF_SLOTS).next_power_of_two()
    });
    let spine_cap = spine.map_or(0, |s| {
        assert!(!s.instances.is_empty(), "spine handoff without instances");
        s.instances.len().div_ceil(k)
    });
    assert!(
        spine_cap == 0 || spine_cap.is_power_of_two(),
        "spine per-block capacity must be a power of two (got {spine_cap})"
    );
    let spine_tree_base = 0usize;
    let spine_wrap_base = spine_cap * SPINE_TREE_SLOTS;
    let spine_per_tx = if spine_cap > 0 {
        (spine_cap * (SPINE_TREE_SLOTS + wrap_slots)).next_power_of_two()
    } else {
        0
    };
    let spine_region_slots = k * spine_per_tx;
    let has_meta = es.is_some() || spine.is_some();
    let has_both_a_families = es.is_some() && spine.is_some();
    let overflow_a_slots = wallet_overflow.map_or(0, |_| k * 2 * CAPSULE_LEAF_STRIDE);
    let first_region_live = es_region_slots + overflow_a_slots;
    let first_region_slots = if first_region_live == 0 {
        0
    } else {
        first_region_live.next_power_of_two()
    };
    let meta_half = first_region_slots.max(spine_region_slots);
    let meta_p = if has_both_a_families {
        2 * meta_half
    } else {
        meta_half.max(1)
    };
    let meta_w_log = meta_p.trailing_zeros() as usize;
    let es_meta_base = 0usize;
    let spine_meta_base = if has_both_a_families { meta_half } else { 0 };

    // Meta-B geometry: paired exact-state families first, followed by the
    // transaction-root path family.
    let paired_es = es.map(|e| &e.paired);
    let mut leg_depths = Vec::new();
    let mut leg_caps = Vec::new();
    let mut leg_ivs = Vec::new();
    let mut txr_leg = None;
    if let Some(t) = txr {
        assert!(!t.paths.is_empty(), "tx-root region handoff without paths");
        txr_leg = Some(leg_depths.len());
        leg_depths.push(t.depth);
        leg_caps.push(t.paths.len().div_ceil(k));
        leg_ivs.push(compress_iv_flat());
    }
    let n_legs = leg_depths.len();
    let paired_caps_per_block = paired_es.map(|paired| {
        assert!(
            paired.touched_capacity > 0,
            "paired local capacity is empty"
        );
        assert!(
            paired.segment_capacity > 0,
            "paired upper capacity is empty"
        );
        [
            paired.touched_capacity.div_ceil(k),
            paired.segment_capacity.div_ceil(k),
        ]
    });
    let mut meta_slot_families: Vec<usize> = paired_caps_per_block
        .map(|caps| caps.map(|cap| cap * PAIRED_UPDATE_STRIDE).to_vec())
        .unwrap_or_default();
    let paired_family_count = meta_slot_families.len();
    meta_slot_families
        .extend((0..n_legs).map(|f| leg_caps[f] * (2 * leg_depths[f]).next_power_of_two()));
    if wallet_overflow.is_some() {
        meta_slot_families.extend([
            ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
            ZK_CAPSULE_PCS_MID_PATH_DEPTH,
        ]);
    }
    let meta_b =
        (!meta_slot_families.is_empty()).then(|| tiled_walk_layout(k, &meta_slot_families));
    let paired_bases: Option<[usize; 2]> = paired_caps_per_block.map(|_| {
        meta_b.as_ref().expect("paired carrier needs meta-B").bases[..paired_family_count]
            .try_into()
            .expect("local and upper paired bases")
    });
    let meta_bases = meta_b.as_ref().map_or_else(Vec::new, |layout| {
        layout.bases[paired_family_count..paired_family_count + n_legs].to_vec()
    });
    let overflow_b_bases: Option<[usize; 2]> = wallet_overflow.map(|_| {
        meta_b.as_ref().expect("wallet overflow needs Meta-B").bases
            [paired_family_count + n_legs..paired_family_count + n_legs + 2]
            .try_into()
            .expect("two Wallet overflow families")
    });
    let mut meta_b_families = Vec::with_capacity(
        paired_family_count + n_legs + usize::from(wallet_overflow.is_some()) * 2,
    );
    if let (Some(caps), Some(bases)) = (paired_caps_per_block, paired_bases) {
        let iv = iv_flat_of_tag(TAG_EXSTNOD);
        for family in 0..2 {
            meta_b_families.push(crate::region_sidecar::MerkleRegionFamily::PairedUpdate {
                offset: bases[family],
                n_updates: caps[family],
                iv,
            });
        }
    }
    for family in 0..n_legs {
        meta_b_families.push(crate::region_sidecar::MerkleRegionFamily::TwoPermutation {
            offset: meta_bases[family],
            depth: leg_depths[family],
            n_paths: leg_caps[family],
            iv: leg_ivs[family],
        });
    }
    if let Some(bases) = overflow_b_bases {
        let iv = iv_flat_of_tag(TAG_CAPSNODE);
        for (base, depth) in bases.into_iter().zip([
            ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
            ZK_CAPSULE_PCS_MID_PATH_DEPTH,
        ]) {
            meta_b_families.push(
                crate::region_sidecar::MerkleRegionFamily::FeedForwardStrided {
                    offset: base,
                    depth,
                    n_paths: 1,
                    stride: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH + ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                    iv,
                },
            );
        }
    }

    // Canonical ghost initialization for both metadata walks.
    let mut meta_cols: Vec<Vec<F128>> = (0..N_META_COMMITTED)
        .map(|_| vec![F128::ZERO; meta_p])
        .collect();
    let mut meta_s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; meta_p]);
    let mut meta_s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; meta_p]);
    let (ghost_s0, ghost_out) =
        noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..meta_p {
        for j in 0..STATE_SIZE {
            meta_s0[j][slot] = ghost_s0[j];
            meta_s_out[j][slot] = ghost_out[j];
            meta_cols[C0 + j][slot] = ghost_out[j];
        }
    }

    let meta_b_slots = meta_b.as_ref().map_or(0, |layout| layout.slots);
    let mut cb_meta_b: Vec<Vec<F128>> = (0..9).map(|_| vec![F128::ZERO; meta_b_slots]).collect();
    let mut s0_meta_b: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; meta_b_slots]);
    let mut sout_meta_b: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; meta_b_slots]);
    let (ghost_b_s0, ghost_b_out) =
        noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..meta_b_slots {
        for j in 0..STATE_SIZE {
            s0_meta_b[j][slot] = ghost_b_s0[j];
            sout_meta_b[j][slot] = ghost_b_out[j];
            cb_meta_b[j][slot] = ghost_b_out[j];
        }
    }

    if let Some(overflow) = wallet_overflow {
        let overflow_a = &overflow.wallet_a;
        let overflow_b = &overflow.wallet_b;
        let overflow_a_family_slots = k * CAPSULE_LEAF_STRIDE;
        let expected_overflow_a_len = 2 * overflow_a_family_slots;
        let overflow_b_depths = [
            ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
            ZK_CAPSULE_PCS_MID_PATH_DEPTH,
        ];
        let overflow_b_offsets = [0, ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH];
        let overflow_b_stride = overflow_b_depths.into_iter().sum::<usize>();
        let expected_overflow_b_len = k * overflow_b_stride;
        assert!(overflow_a
            .committed()
            .iter()
            .all(|column| column.len() == expected_overflow_a_len));
        assert!(overflow_a
            .s0()
            .iter()
            .chain(overflow_a.s_out())
            .all(|column| column.len() == expected_overflow_a_len));
        assert!(overflow_b
            .committed()
            .iter()
            .all(|column| column.len() == expected_overflow_b_len));
        assert!(overflow_b
            .s0()
            .iter()
            .chain(overflow_b.s_out())
            .all(|column| column.len() == expected_overflow_b_len));

        // Staging is tx-major. Meta-A is family-major so each family occupies
        // one aligned dyadic region immediately after Exact State.
        for tx in 0..k {
            for family in 0..2 {
                let source = tx * 2 * CAPSULE_LEAF_STRIDE + family * CAPSULE_LEAF_STRIDE;
                let destination =
                    es_region_slots + family * overflow_a_family_slots + tx * CAPSULE_LEAF_STRIDE;
                for lane in 0..2 {
                    meta_cols[IN0 + lane][destination..destination + CAPSULE_LEAF_STRIDE]
                        .copy_from_slice(
                            &overflow_a.committed()[lane][source..source + CAPSULE_LEAF_STRIDE],
                        );
                }
                for lane in 0..STATE_SIZE {
                    meta_cols[C0 + lane][destination..destination + CAPSULE_LEAF_STRIDE]
                        .copy_from_slice(
                            &overflow_a.committed()[2 + lane][source..source + CAPSULE_LEAF_STRIDE],
                        );
                    meta_s0[lane][destination..destination + CAPSULE_LEAF_STRIDE].copy_from_slice(
                        &overflow_a.s0()[lane][source..source + CAPSULE_LEAF_STRIDE],
                    );
                    meta_s_out[lane][destination..destination + CAPSULE_LEAF_STRIDE]
                        .copy_from_slice(
                            &overflow_a.s_out()[lane][source..source + CAPSULE_LEAF_STRIDE],
                        );
                }
            }
        }

        // Meta-B remains tx-blocked. Preserve the source/mid path split from
        // the staging walk: ten source levels followed by six mid levels.
        let bases = overflow_b_bases.expect("wallet overflow Meta-B bases");
        let layout = meta_b.as_ref().expect("wallet overflow Meta-B layout");
        for tx in 0..k {
            for family in 0..2 {
                let depth = overflow_b_depths[family];
                let source = tx * overflow_b_stride + overflow_b_offsets[family];
                let destination = tx * layout.block_slots + bases[family];
                for column in 0..9 {
                    cb_meta_b[column][destination..destination + depth]
                        .copy_from_slice(&overflow_b.committed()[column][source..source + depth]);
                }
                for lane in 0..STATE_SIZE {
                    s0_meta_b[lane][destination..destination + depth]
                        .copy_from_slice(&overflow_b.s0()[lane][source..source + depth]);
                    sout_meta_b[lane][destination..destination + depth]
                        .copy_from_slice(&overflow_b.s_out()[lane][source..source + depth]);
                }
            }
        }
    }

    let mut cell_pins_meta = Vec::new();
    let mut cell_pins_meta_b = Vec::new();
    let mut acc_committed_roots = vec![Vec::new(); n_legs];
    let mut acc_recomputed_roots = vec![Vec::new(); n_legs];
    let mut acc_entry_wires = vec![Vec::new(); n_legs];
    let mut acc_root_wires = vec![Vec::new(); n_legs];
    let mut acc_path_slots = vec![Vec::new(); n_legs];

    // Paired exact-state families.
    if let Some(paired) = paired_es {
        let packed = paired.packed_updates();
        assert_eq!(
            packed.updates.len(),
            paired.touched_capacity + paired.segment_capacity,
            "paired packed capacity"
        );
        assert_eq!(
            packed.active_slots,
            packed.updates.len() * PAIRED_UPDATE_STRIDE,
            "paired packed active slots"
        );
        let (local_updates, upper_updates) = packed.updates.split_at(paired.touched_capacity);
        let partitions = [local_updates, upper_updates];
        let caps = paired_caps_per_block.expect("paired per-block capacities");
        let bases = paired_bases.expect("paired meta-B bases");
        let layout = meta_b.as_ref().expect("paired carrier needs meta-B");
        let iv = iv_flat_of_tag(TAG_EXSTNOD);
        for blk in 0..k {
            for family in 0..2 {
                let cap = caps[family];
                let lo = (blk * cap).min(partitions[family].len());
                let hi = ((blk + 1) * cap).min(partitions[family].len());
                let family_slots = cap * PAIRED_UPDATE_STRIDE;
                let family_w_log = family_slots.next_power_of_two().trailing_zeros() as usize;
                let columns = build_paired_merkle_update_columns(
                    &partitions[family][lo..hi],
                    iv,
                    family_w_log,
                );
                place_paired_merkle_updates(
                    &mut cb_meta_b,
                    &mut s0_meta_b,
                    &mut sout_meta_b,
                    &columns,
                    blk * layout.block_slots + bases[family],
                    family_slots,
                );
            }
        }
    }

    // Exact-state Meta-A leaves. Its state transition is carried exclusively
    // by the paired local/upper Meta-B families above.
    if let Some(e) = es {
        let pad_flat = slot_leaf_pad_flat();
        let leaf_data: Vec<(F128, F128, F128)> = e
            .leaves
            .iter()
            .map(|l| (l.packed_value_flat, l.owner_hi_flat, l.owner_lo_flat))
            .collect();
        let es_w_log = es_region_slots.trailing_zeros() as usize;
        let (tc, tile_digests) = build_sponge_leaf_columns(&leaf_data, es_w_log);
        let base = es_meta_base;
        for j in 0..2 {
            meta_cols[IN0 + j][base..base + es_region_slots].copy_from_slice(&tc.in_[j]);
        }
        for j in 0..STATE_SIZE {
            meta_cols[C0 + j][base..base + es_region_slots].copy_from_slice(&tc.c[j]);
            meta_s0[j][base..base + es_region_slots].copy_from_slice(&tc.s0[j]);
            meta_s_out[j][base..base + es_region_slots].copy_from_slice(&tc.s_out[j]);
        }
        for (g, leaf) in e.leaves.iter().enumerate() {
            assert_eq!(
                tile_digests[g], leaf.expected_leaf_flat,
                "es sponge tile digest != the statement's expected leaf"
            );
            let off = base + g * SPONGE_LEAF_SLOTS;
            cell_pins_meta.push((IN0, off, leaf.packed_value_w.clone()));
            cell_pins_meta.push((IN0 + 1, off, leaf.owner_hi_w.clone()));
            cell_pins_meta.push((IN0, off + 1, leaf.owner_lo_w.clone()));
            cell_pins_meta.push((IN0 + 1, off + 1, LinExpr::constant(pad_flat)));
            let dslot = off + SPONGE_LEAF_DIGEST_SLOT;
            cell_pins_meta.push((C0, dslot, leaf.expected_leaf_w[0].clone()));
            cell_pins_meta.push((C0 + 1, dslot, leaf.expected_leaf_w[1].clone()));
        }
    }

    // Tx-root Meta-B family, including exact direction and padding-rim pins.
    if let Some(t) = txr {
        let txr_leg = txr_leg.expect("tx-root leg index");
        let cap = leg_caps[txr_leg];
        let stride = (2 * t.depth).next_power_of_two();
        let n_paths = t.paths.len();
        assert!(
            t.rim_flat.is_empty() || t.rim_flat.len() == t.depth,
            "one rim constant per level (or none at tier capacity)"
        );
        for blk in 0..k {
            let lo = (blk * cap).min(n_paths);
            let hi = ((blk + 1) * cap).min(n_paths);
            let real: Vec<EsPathReal> = (lo..hi)
                .map(|j| {
                    let p = &t.paths[j];
                    assert_eq!(p.siblings.len(), t.depth, "tx-root path depth");
                    EsPathReal {
                        entry_flat: p.entry_flat,
                        entry_w: p.entry_w.clone(),
                        siblings: p.siblings.clone(),
                        directions: (0..t.depth).map(|level| (j >> level) & 1 == 1).collect(),
                        root_flat: t.root_flat,
                        root_w: t.root_w.clone(),
                    }
                })
                .collect();
            let region_base = blk
                * meta_b
                    .as_ref()
                    .expect("tx-root leg needs meta-B")
                    .block_slots
                + meta_bases[txr_leg];
            fill_es_merkle_leg(
                &mut cb_meta_b,
                &mut s0_meta_b,
                &mut sout_meta_b,
                &mut acc_entry_wires[txr_leg],
                &mut acc_root_wires[txr_leg],
                &mut acc_committed_roots[txr_leg],
                &mut acc_path_slots[txr_leg],
                &mut acc_recomputed_roots[txr_leg],
                t.depth,
                cap,
                leg_ivs[txr_leg],
                4,
                region_base,
                &real,
            );
            for (i, j) in (lo..hi).enumerate() {
                let base = region_base + i * stride;
                for level in 0..t.depth {
                    let bit = (j >> level) & 1 == 1;
                    cell_pins_meta_b.push((
                        8,
                        base + 2 * level,
                        LinExpr::constant(if bit { F128::ONE } else { F128::ZERO }),
                    ));
                }
                if !t.rim_flat.is_empty() && j == n_paths - 1 {
                    for level in 0..t.depth {
                        if (j >> level) & 1 == 0 {
                            for lane in 0..2 {
                                cell_pins_meta_b.push((
                                    6 + lane,
                                    base + 2 * level,
                                    LinExpr::constant(t.rim_flat[level][lane]),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Tx-body spine Meta-A family.  This is the only raw-meta step that
    // allocates builder wires; its position relative to the monolith is fixed.
    if let Some(sp) = spine {
        let n_inst = sp.instances.len();
        for blk in 0..k {
            for i in 0..spine_cap {
                let g = blk * spine_cap + i;
                let inst_flat = sp
                    .instances
                    .get(g)
                    .map(|inst| inst.flat.clone())
                    .unwrap_or_else(SpineInstanceFlat::ghost);
                let contract = sp
                    .instances
                    .get(g)
                    .and_then(|instance| instance.contract.as_ref());
                let icols = if objects {
                    build_spine_instance_columns_with_contract(
                        &inst_flat,
                        contract.map(|contract| &contract.flat),
                    )
                } else {
                    assert!(contract.is_none(), "legacy spine has no object opening");
                    build_spine_instance_columns(&inst_flat)
                };
                let tree_abs =
                    spine_meta_base + blk * spine_per_tx + spine_tree_base + i * SPINE_TREE_SLOTS;
                let wrap_abs =
                    spine_meta_base + blk * spine_per_tx + spine_wrap_base + i * wrap_slots;
                for j in 0..STATE_SIZE {
                    meta_cols[C0 + j][tree_abs..tree_abs + SPINE_TREE_SLOTS]
                        .copy_from_slice(&icols.tree_c[j]);
                    meta_s0[j][tree_abs..tree_abs + SPINE_TREE_SLOTS]
                        .copy_from_slice(&icols.tree_s0[j]);
                    meta_s_out[j][tree_abs..tree_abs + SPINE_TREE_SLOTS]
                        .copy_from_slice(&icols.tree_s_out[j]);
                    meta_cols[C0 + j][wrap_abs..wrap_abs + wrap_slots]
                        .copy_from_slice(&icols.wrap_c[j]);
                    meta_s0[j][wrap_abs..wrap_abs + wrap_slots].copy_from_slice(&icols.wrap_s0[j]);
                    meta_s_out[j][wrap_abs..wrap_abs + wrap_slots]
                        .copy_from_slice(&icols.wrap_s_out[j]);
                }
                for lane in 0..2 {
                    meta_cols[KID0 + lane][tree_abs..tree_abs + SPINE_TREE_SLOTS]
                        .copy_from_slice(&icols.tree_kid[lane]);
                    meta_cols[IN0 + lane][wrap_abs..wrap_abs + wrap_slots]
                        .copy_from_slice(&icols.wrap_in[lane]);
                }
                if let Some(contract) = contract {
                    for step in 0..contract.program_w.len() {
                        for lane in 0..2 {
                            cell_pins_meta.push((
                                IN0 + lane,
                                wrap_abs + SPINE_CONTRACT_CODE_BASE + step,
                                contract.program_w[step][lane].clone(),
                            ));
                        }
                    }
                    for lane in 0..2 {
                        cell_pins_meta.push((
                            C0 + lane,
                            wrap_abs + SPINE_CONTRACT_CODE_BASE + contract.program_w.len() - 1,
                            contract.code_digest_w[lane].clone(),
                        ));
                        cell_pins_meta.push((
                            IN0 + lane,
                            wrap_abs + SPINE_CONTRACT_POLICY_BASE,
                            contract.code_digest_w[lane].clone(),
                        ));
                        cell_pins_meta.push((
                            C0 + lane,
                            wrap_abs + SPINE_CONTRACT_POLICY_BASE + 7,
                            contract.policy_digest_w[lane].clone(),
                        ));
                        for object_base in [
                            SPINE_CONTRACT_OLD_OBJECT_BASE,
                            SPINE_CONTRACT_NEW_OBJECT_BASE,
                        ] {
                            cell_pins_meta.push((
                                IN0 + lane,
                                wrap_abs + object_base,
                                contract.policy_digest_w[lane].clone(),
                            ));
                        }
                    }
                    for (slot, values) in [
                        (
                            SPINE_CONTRACT_POLICY_BASE + 1,
                            [contract.deadline_w.clone(), contract.controller_w[0].clone()],
                        ),
                        (
                            SPINE_CONTRACT_POLICY_BASE + 2,
                            [
                                contract.controller_w[1].clone(),
                                contract.refund_authority_w[0].clone(),
                            ],
                        ),
                        (
                            SPINE_CONTRACT_POLICY_BASE + 3,
                            [
                                contract.refund_authority_w[1].clone(),
                                contract.claim_recipient_w[0].clone(),
                            ],
                        ),
                        (
                            SPINE_CONTRACT_POLICY_BASE + 4,
                            [
                                contract.claim_recipient_w[1].clone(),
                                contract.refund_recipient_w[0].clone(),
                            ],
                        ),
                        (
                            SPINE_CONTRACT_POLICY_BASE + 5,
                            [
                                contract.refund_recipient_w[1].clone(),
                                LinExpr::constant(
                                    noid_ivc_core::deep_chain::spine::spine_contract_object_version_flat(),
                                ),
                            ],
                        ),
                        (
                            SPINE_CONTRACT_POLICY_BASE + 6,
                            [contract.rules_w[0].clone(), contract.rules_w[1].clone()],
                        ),
                        (
                            SPINE_CONTRACT_POLICY_BASE + 7,
                            [contract.rules_w[2].clone(), contract.rules_w[3].clone()],
                        ),
                        (
                            SPINE_CONTRACT_OLD_OBJECT_BASE + 1,
                            [contract.current_w.clone(), LinExpr::zero()],
                        ),
                        (
                            SPINE_CONTRACT_NEW_OBJECT_BASE + 1,
                            [contract.next_w.clone(), LinExpr::zero()],
                        ),
                    ] {
                        for lane in 0..2 {
                            cell_pins_meta.push((
                                IN0 + lane,
                                wrap_abs + slot,
                                values[lane].clone(),
                            ));
                        }
                    }
                    for lane in 0..2 {
                        cell_pins_meta.push((
                            C0 + lane,
                            wrap_abs + SPINE_CONTRACT_OLD_OBJECT_BASE + 1,
                            contract.old_object_root_w[lane].clone(),
                        ));
                        cell_pins_meta.push((
                            C0 + lane,
                            wrap_abs + SPINE_CONTRACT_NEW_OBJECT_BASE + 1,
                            contract.new_object_root_w[lane].clone(),
                        ));
                    }
                }
                if g >= n_inst {
                    continue;
                }
                let inst = &sp.instances[g];
                assert_eq!(
                    icols.tx_hash, inst.tx_hash_flat,
                    "spine instance {g}: region tx-body hash != the statement wires"
                );
                for (leaf, wpair) in inst.leaves_w.iter().enumerate() {
                    let kslot = tree_abs + SPINE_TREE_KID_LEAF_BASE + leaf;
                    cell_pins_meta.push((KID0, kslot, wpair[0].clone()));
                    cell_pins_meta.push((KID0 + 1, kslot, wpair[1].clone()));
                }
                for lane in 0..2 {
                    let w = LinExpr::from_wire(b.alloc_f128(icols.root[lane]));
                    cell_pins_meta.push((C0 + lane, tree_abs + 3, w.clone()));
                    cell_pins_meta.push((IN0 + lane, wrap_abs + SPINE_WRAP_SLOT, w));
                }
                for lane in 0..2 {
                    cell_pins_meta.push((
                        C0 + lane,
                        wrap_abs + SPINE_WRAP_SLOT,
                        inst.tx_hash_w[lane].clone(),
                    ));
                }
            }
        }
    }

    AuthPcsMetaRegionDraft {
        has_meta,
        has_both_a_families,
        es_region_slots,
        spine_cap,
        meta_w_log,
        meta_b,
        paired_caps_per_block,
        paired_bases,
        leg_depths,
        leg_caps,
        meta_b_families,
        meta_cols,
        meta_s0,
        meta_s_out,
        cb_meta_b,
        s0_meta_b,
        sout_meta_b,
        cell_pins_meta,
        cell_pins_meta_b,
        acc_committed_roots,
        acc_recomputed_roots,
        acc_entry_wires,
        acc_root_wires,
        acc_path_slots,
    }
}

/// Resolve the paired exact-state portion of a raw metadata draft after its
/// Meta-B columns have received physical witness slices.  Keeping this here
/// makes the exact copy/overhang pins and the typed handoff part of the same
/// metadata-only construction boundary as the raw columns.
fn bind_auth_pcs_meta_paired_handoff(
    meta_b_slices: &[WitnessSlice],
    meta_b: Option<&TiledWalkLayout>,
    paired_bases: Option<[usize; 2]>,
    paired_caps_per_block: Option<[usize; 2]>,
    paired: Option<&ExactStatePairedRegionData>,
) -> Option<PairedExactStateCells> {
    paired.map(|paired| {
        let layout = meta_b.expect("paired carrier needs meta-B slices");
        let bases = paired_bases.expect("paired family bases");
        let caps = paired_caps_per_block.expect("paired family capacities");
        paired_exact_state_cells(meta_b_slices, layout, bases, caps, paired)
    })
}

fn preflight_selected_zk_authorization_draft(
    authorization: &super::zk_authorization_region::SelectedZkAuthorizationRegionDraft,
) -> Result<crate::region_sidecar::SelectedZkBlockGeometry, SelectedZkAuthPcsRegionAllocationError>
{
    let mut geometry = crate::region_sidecar::selected_zk_block_geometry_for_auth_tiles(
        authorization.owner().challenges.len(),
    )
    .ok_or(SelectedZkAuthPcsRegionAllocationError::AuthorizationShape)?;
    geometry.authorization_version = authorization.version();
    let exact_duplex = |union: &DuplexUnion, w_log: usize, block_log: usize| {
        let len = 1usize << w_log;
        union.w_log == w_log
            && union.block_log == block_log
            && union.committed.iter().all(|column| column.len() == len)
            && union.s0.iter().all(|column| column.len() == len)
            && union.s_out.iter().all(|column| column.len() == len)
            && union.challenges.len() == geometry.auth_tiles
            && union.rec_blocks.is_empty()
            && union.rec_refs.is_empty()
            && union.rec_challenges.is_empty()
    };
    let exact_raw_walk = |committed: &[Vec<F128>],
                          s0: &[Vec<F128>; STATE_SIZE],
                          s_out: &[Vec<F128>; STATE_SIZE],
                          columns: usize,
                          w_log: usize| {
        let len = 1usize << w_log;
        committed.len() == columns
            && committed.iter().all(|column| column.len() == len)
            && s0.iter().all(|column| column.len() == len)
            && s_out.iter().all(|column| column.len() == len)
    };

    let wallet_a = authorization.wallet_a();
    let wallet_b = authorization.wallet_b();
    let overflow_a = &authorization.overflow().wallet_a;
    let overflow_b = &authorization.overflow().wallet_b;
    let valid = authorization.changed_committed_columns() == 27
        && authorization.committed_cells()
            == SELECTED_ZK_REGION_WALLET_A_COLUMNS * (1 << geometry.wallet_a_w_log)
                + SELECTED_ZK_REGION_WALLET_B_COLUMNS * (1 << geometry.wallet_b_w_log)
                + SELECTED_ZK_REGION_OWNER_COLUMNS * (1 << geometry.owner_w_log)
                + SELECTED_ZK_REGION_MAIN_COLUMNS * (1 << geometry.main_w_log)
        && exact_duplex(authorization.owner(), geometry.owner_w_log, 7)
        && exact_duplex(authorization.main(), geometry.main_w_log, 8)
        && exact_raw_walk(
            wallet_a.committed(),
            wallet_a.s0(),
            wallet_a.s_out(),
            SELECTED_ZK_REGION_WALLET_A_COLUMNS,
            geometry.wallet_a_w_log,
        )
        && exact_raw_walk(
            wallet_b.committed(),
            wallet_b.s0(),
            wallet_b.s_out(),
            SELECTED_ZK_REGION_WALLET_B_COLUMNS,
            geometry.wallet_b_w_log,
        )
        && exact_raw_walk(
            overflow_a.committed(),
            overflow_a.s0(),
            overflow_a.s_out(),
            SELECTED_ZK_REGION_WALLET_A_COLUMNS,
            geometry.tx_log + 5,
        )
        && exact_raw_walk(
            overflow_b.committed(),
            overflow_b.s0(),
            overflow_b.s_out(),
            SELECTED_ZK_REGION_WALLET_B_COLUMNS,
            geometry.tx_log + 4,
        )
        && wallet_b.committed()[8]
            .iter()
            .all(|&value| value == F128::ZERO || value == F128::ONE)
        && overflow_b.committed()[8]
            .iter()
            .all(|&value| value == F128::ZERO || value == F128::ONE);
    if valid {
        Ok(geometry)
    } else {
        Err(SelectedZkAuthPcsRegionAllocationError::AuthorizationShape)
    }
}

fn preflight_selected_zk_meta_inputs(
    es: &ExactStateRegionData,
    txr: &TxRootRegionData,
    spine: &SpineRegionData,
    geometry: crate::region_sidecar::SelectedZkBlockGeometry,
) -> Result<(), SelectedZkAuthPcsRegionAllocationError> {
    let paired = &es.paired;
    if es.leaves.len() != 2 * geometry.touched_capacity
        || paired.touched_capacity != geometry.touched_capacity
        || paired.segment_capacity != geometry.segment_capacity
        || paired.local_updates.len() != paired.local_update_count
        || paired.upper_updates.len() != paired.upper_update_count
        || paired.local_update_count > paired.touched_capacity
        || paired.upper_update_count > paired.segment_capacity
        || !(8..=PAIRED_UPDATE_DEPTH).contains(&paired.active_upper_depth)
    {
        return Err(SelectedZkAuthPcsRegionAllocationError::ExactStateShape);
    }
    if txr.depth != 8
        || txr.paths.len() != 1 << noid_chain::tx_tree::TX_TREE_DEPTH
        || txr
            .paths
            .iter()
            .any(|path| path.siblings.len() != txr.depth)
        || !(txr.rim_flat.is_empty() || txr.rim_flat.len() == txr.depth)
    {
        return Err(SelectedZkAuthPcsRegionAllocationError::TxRootShape);
    }
    if spine.instances.len() != geometry.tier + 1 {
        return Err(SelectedZkAuthPcsRegionAllocationError::SpineShape);
    }
    Ok(())
}

fn alloc_selected_column_slice(
    b: &mut FieldR1csBuilder,
    column: &[F128],
    w_log: usize,
) -> WitnessSlice {
    let len = 1usize << w_log;
    assert_eq!(column.len(), len, "selected committed column length");
    while b.num_wires() % len != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let index = b.num_wires() / len;
    for &value in column {
        b.alloc_f128(value);
    }
    WitnessSlice {
        log2_len: w_log,
        index,
    }
}

fn alloc_selected_boolean_column_slice(
    b: &mut FieldR1csBuilder,
    column: &[F128],
    w_log: usize,
) -> WitnessSlice {
    let len = 1usize << w_log;
    assert_eq!(column.len(), len, "selected boolean column length");
    while b.num_wires() % len != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let index = b.num_wires() / len;
    for (slot, &value) in column.iter().enumerate() {
        assert!(
            value == F128::ZERO || value == F128::ONE,
            "selected boolean column slot {slot}"
        );
        b.alloc_bool(value == F128::ONE);
    }
    WitnessSlice {
        log2_len: w_log,
        index,
    }
}

fn alloc_selected_columns<const N: usize>(
    b: &mut FieldR1csBuilder,
    columns: &[Vec<F128>],
    w_log: usize,
    boolean_column: Option<usize>,
) -> [WitnessSlice; N] {
    assert_eq!(columns.len(), N, "selected committed column count");
    std::array::from_fn(|column| {
        if boolean_column == Some(column) {
            alloc_selected_boolean_column_slice(b, &columns[column], w_log)
        } else {
            alloc_selected_column_slice(b, &columns[column], w_log)
        }
    })
}

/// Allocate and close one exact selected-class authorization+Meta region.
///
/// This is the sole common six-child allocator. It consumes the verified raw
/// authorization draft and accepts only the canonical production Meta inputs.
/// All input-shape rejection happens before the builder is touched. The raw
/// Meta draft is constructed, allocated, statement-pinned and converted into
/// its paired handoff entirely inside this function; no partially closed Meta
/// value can escape. The result is still only a draft owned by the private
/// Block assembly, never a post-commit preparation or finalization token.
pub(super) fn allocate_selected_zk_auth_pcs_region(
    b: &mut FieldR1csBuilder,
    authorization: super::zk_authorization_region::SelectedZkAuthorizationRegionDraft,
    es: &ExactStateRegionData,
    txr: &TxRootRegionData,
    spine: &SpineRegionData,
    geometry: crate::region_sidecar::SelectedZkBlockGeometry,
) -> Result<SelectedZkAuthPcsRegionAllocation, SelectedZkAuthPcsRegionAllocationError> {
    let authorization_geometry = preflight_selected_zk_authorization_draft(&authorization)?;
    if spine.instances.len() != geometry.tier + 1 {
        return Err(SelectedZkAuthPcsRegionAllocationError::SpineShape);
    }
    if geometry.auth_tiles != authorization_geometry.auth_tiles
        || geometry.authorization_version != authorization_geometry.authorization_version
    {
        return Err(SelectedZkAuthPcsRegionAllocationError::AuthorizationShape);
    }
    preflight_selected_zk_meta_inputs(es, txr, spine, geometry)?;

    let (owner, main, wallet_a, wallet_b, overflow) = authorization.into_parts();
    let (wallet_a_columns, wallet_a_s0, wallet_a_s_out) = wallet_a.into_parts();
    let (wallet_b_columns, wallet_b_s0, wallet_b_s_out) = wallet_b.into_parts();

    let AuthPcsMetaRegionDraft {
        has_meta,
        has_both_a_families,
        es_region_slots,
        spine_cap,
        meta_w_log,
        meta_b,
        paired_caps_per_block,
        paired_bases,
        leg_depths,
        leg_caps,
        meta_b_families,
        meta_cols,
        meta_s0,
        meta_s_out,
        cb_meta_b,
        s0_meta_b,
        sout_meta_b,
        cell_pins_meta,
        mut cell_pins_meta_b,
        acc_committed_roots,
        acc_recomputed_roots,
        acc_entry_wires,
        acc_root_wires,
        acc_path_slots,
        ..
    } = build_auth_pcs_meta_region_draft(
        b,
        geometry.auth_tiles,
        Some(es),
        Some(txr),
        Some(spine),
        Some(&overflow),
    );
    let meta_b_layout = meta_b
        .as_ref()
        .expect("selected paired Meta input must construct Meta-B");
    assert!(has_meta && has_both_a_families, "selected Meta-A families");
    assert_eq!(
        es_region_slots,
        1 << geometry.exact_state_region_log,
        "selected exact-state region"
    );
    assert_eq!(
        spine_cap,
        1 << geometry.spine_cap_log,
        "selected spine capacity per tile"
    );
    assert_eq!(meta_w_log, geometry.meta_a_w_log);
    assert_eq!(meta_b_layout.w_log, geometry.meta_b_w_log);
    assert_eq!(meta_b_layout.block_log, geometry.meta_b_block_log);
    assert_eq!(paired_caps_per_block, Some(geometry.paired_caps_per_block));
    assert_eq!(paired_bases, Some(geometry.paired_bases));
    assert_eq!(leg_depths, vec![8]);
    assert_eq!(leg_caps, vec![geometry.tx_root_paths_per_block]);
    assert_eq!(meta_cols.len(), SELECTED_ZK_REGION_META_A_COLUMNS);
    assert_eq!(cb_meta_b.len(), SELECTED_ZK_REGION_META_B_COLUMNS);
    assert!(cb_meta_b[8]
        .iter()
        .all(|&value| value == F128::ZERO || value == F128::ONE));

    append_meta_b_statement_pins(
        &mut cell_pins_meta_b,
        &leg_depths,
        &acc_entry_wires,
        &acc_root_wires,
        &acc_committed_roots,
        &acc_recomputed_roots,
        &acc_path_slots,
    );

    // One canonical allocation ordered to minimize alignment loss at the
    // production HistoryStep boundary. The six family domains and their
    // committed contents are unchanged.
    let allocation_ledger = SelectedZkRegionAllocationLedger::new(b.num_wires(), geometry);
    if std::env::var_os("NOID_ROW_LEDGER").is_some() {
        eprintln!("[ledger] selected-region allocation {allocation_ledger:?}");
    }
    let mut main_slices = None;
    let mut owner_slices = None;
    let mut wallet_b_slices = None;
    let mut wallet_a_slices = None;
    let mut meta_a_slices = None;
    let mut meta_b_slices = None;
    for family in allocation_ledger.order {
        match family {
            SelectedZkRegionFamily::Main => {
                main_slices = Some(alloc_selected_columns::<SELECTED_ZK_REGION_MAIN_COLUMNS>(
                    b,
                    &main.committed,
                    geometry.main_w_log,
                    None,
                ));
            }
            SelectedZkRegionFamily::Owner => {
                owner_slices = Some(alloc_selected_columns::<SELECTED_ZK_REGION_OWNER_COLUMNS>(
                    b,
                    &owner.committed,
                    geometry.owner_w_log,
                    None,
                ));
            }
            SelectedZkRegionFamily::WalletB => {
                wallet_b_slices = Some(
                    alloc_selected_columns::<SELECTED_ZK_REGION_WALLET_B_COLUMNS>(
                        b,
                        &wallet_b_columns,
                        geometry.wallet_b_w_log,
                        Some(8),
                    ),
                );
            }
            SelectedZkRegionFamily::WalletA => {
                wallet_a_slices = Some(
                    alloc_selected_columns::<SELECTED_ZK_REGION_WALLET_A_COLUMNS>(
                        b,
                        &wallet_a_columns,
                        geometry.wallet_a_w_log,
                        None,
                    ),
                );
            }
            SelectedZkRegionFamily::MetaA => {
                meta_a_slices = Some(alloc_selected_columns::<SELECTED_ZK_REGION_META_A_COLUMNS>(
                    b,
                    &meta_cols,
                    geometry.meta_a_w_log,
                    None,
                ));
            }
            SelectedZkRegionFamily::MetaB => {
                meta_b_slices = Some(alloc_selected_columns::<SELECTED_ZK_REGION_META_B_COLUMNS>(
                    b,
                    &cb_meta_b,
                    geometry.meta_b_w_log,
                    Some(8),
                ));
            }
        }
    }
    let main_slices = main_slices.expect("selected Main family allocation");
    let owner_slices = owner_slices.expect("selected Owner family allocation");
    let wallet_b_slices = wallet_b_slices.expect("selected wallet-B family allocation");
    let wallet_a_slices = wallet_a_slices.expect("selected wallet-A family allocation");
    let meta_a_slices = meta_a_slices.expect("selected Meta-A family allocation");
    let meta_b_slices = meta_b_slices.expect("selected Meta-B family allocation");
    drop(wallet_b_columns);
    drop(wallet_a_columns);
    drop(meta_cols);
    drop(cb_meta_b);
    let owner_vk = crate::region_sidecar::DuplexRegionVk::from_union(
        crate::acceptance::zk_auth_capsule_schedule::zk_auth_region_sidecar_purpose_for_version(
            b"owner",
            geometry.authorization_version,
        ),
        owner_slices,
        &owner,
    )
    .expect("preflighted selected Owner VK drift");
    let main_vk = crate::region_sidecar::DuplexRegionVk::from_union(
        crate::acceptance::zk_auth_capsule_schedule::zk_auth_region_sidecar_purpose_for_version(
            b"main",
            geometry.authorization_version,
        ),
        main_slices,
        &main,
    )
    .expect("preflighted selected Main VK drift");
    let DuplexUnion {
        committed: owner_committed,
        s0: owner_s0,
        s_out: owner_s_out,
        ..
    } = owner;
    drop(owner_committed);
    let DuplexUnion {
        committed: main_committed,
        s0: main_s0,
        s_out: main_s_out,
        ..
    } = main;
    drop(main_committed);
    assert_eq!(main_slices[0].start(), allocation_ledger.main);
    assert_eq!(owner_slices[0].start(), allocation_ledger.owner);
    assert_eq!(wallet_b_slices[0].start(), allocation_ledger.wallet_b);
    assert_eq!(wallet_a_slices[0].start(), allocation_ledger.wallet_a);
    assert_eq!(meta_a_slices[0].start(), allocation_ledger.meta_a);
    assert_eq!(meta_b_slices[0].start(), allocation_ledger.meta_b);
    assert_eq!(b.num_wires(), allocation_ledger.after);

    // Export only the class-bounded paired prefix, then bind the Meta-A/B
    // statement cells. Ceil-tiling overhang is internal committed witness and
    // cannot reach the typed handoff.
    let before_paired_closure = b.num_wires();
    let paired = bind_auth_pcs_meta_paired_handoff(
        &meta_b_slices,
        Some(meta_b_layout),
        paired_bases,
        paired_caps_per_block,
        Some(&es.paired),
    )
    .expect("selected paired Meta preflight made the handoff mandatory");
    assert_eq!(
        b.num_wires() - before_paired_closure,
        0,
        "selected paired handoff must allocate no rows"
    );
    let before_statement_pins = b.num_wires();
    let before_reused_pins = b.reused_linear_pins();
    let before_constant_pins = b.boolean_pin_observation().constant_assertions_removed;
    pin_stage2_cells(b, &meta_a_slices, &cell_pins_meta);
    pin_stage2_cells(b, &meta_b_slices, &cell_pins_meta_b);
    assert_eq!(
        b.num_wires() - before_statement_pins + b.reused_linear_pins() - before_reused_pins
            + b.boolean_pin_observation().constant_assertions_removed
            - before_constant_pins,
        cell_pins_meta.len() + cell_pins_meta_b.len(),
        "selected Meta statement-pin ledger"
    );

    let wallet_a_vk = crate::region_sidecar::WalkARegionVk::new_wallet(
        crate::acceptance::zk_auth_capsule_schedule::zk_auth_region_sidecar_purpose_for_version(
            b"wallet-a",
            geometry.authorization_version,
        ),
        geometry.tx_log,
        SELECTED_ZK_REGION_QUERY_LOG,
        wallet_a_slices,
    )
    .expect("preflighted selected wallet-A VK drift");
    let capsule_iv = iv_flat_of_tag(TAG_CAPSNODE);
    let wallet_b_vk = crate::region_sidecar::MerkleRegionVk::new(
        crate::acceptance::zk_auth_capsule_schedule::zk_auth_region_sidecar_purpose_for_version(
            b"wallet-b",
            geometry.authorization_version,
        ),
        geometry.wallet_b_w_log,
        wallet_b_slices,
        10,
        vec![
            crate::region_sidecar::MerkleRegionFamily::FeedForwardStrided {
                offset: 0,
                depth: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
                n_paths: SELECTED_ZK_REGION_CORE_QUERY_COUNT,
                stride: 16,
                iv: capsule_iv,
            },
            crate::region_sidecar::MerkleRegionFamily::FeedForwardStrided {
                offset: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
                depth: ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                n_paths: SELECTED_ZK_REGION_CORE_QUERY_COUNT,
                stride: 16,
                iv: capsule_iv,
            },
        ],
    )
    .expect("preflighted selected wallet-B VK drift");
    let meta_constructor = if spine.objects {
        crate::region_sidecar::WalkARegionVk::new_object_meta
    } else {
        crate::region_sidecar::WalkARegionVk::new_meta
    };
    let meta_a_vk = meta_constructor(
        auth_pcs_meta_a_sidecar_purpose(),
        geometry.tx_log,
        Some(geometry.exact_state_region_log),
        Some(geometry.spine_cap_log),
        meta_a_slices,
    )
    .expect("preflighted selected Meta-A VK drift");
    let meta_b_vk = crate::region_sidecar::MerkleRegionVk::new(
        auth_pcs_meta_b_sidecar_purpose(),
        geometry.meta_b_w_log,
        meta_b_slices,
        geometry.meta_b_block_log,
        meta_b_families,
    )
    .expect("preflighted selected Meta-B VK drift");
    let vk = crate::region_sidecar::BlockRegionSidecarVk::new_selected_zk(
        wallet_a_vk,
        meta_a_vk,
        wallet_b_vk,
        meta_b_vk,
        owner_vk,
        main_vk,
    )
    .expect("preflighted selected block VK drift");
    let input = crate::region_sidecar::BlockRegionProverInput::new_selected_zk(
        &vk,
        crate::region_sidecar::RegionWalkEndpoints::new(wallet_a_s0, wallet_a_s_out),
        crate::region_sidecar::RegionWalkEndpoints::new(meta_s0, meta_s_out),
        crate::region_sidecar::RegionWalkEndpoints::new(wallet_b_s0, wallet_b_s_out),
        crate::region_sidecar::RegionWalkEndpoints::new(s0_meta_b, sout_meta_b),
        crate::region_sidecar::RegionWalkEndpoints::new(owner_s0, owner_s_out),
        crate::region_sidecar::RegionWalkEndpoints::new(main_s0, main_s_out),
    )
    .expect("preflighted selected prover input drift");
    let draft = crate::region_sidecar::SelectedZkBlockRegionDraft::new(vk, input)
        .expect("preflighted selected draft drift");
    Ok(SelectedZkAuthPcsRegionAllocation { draft, paired })
}

#[cfg(test)]
mod selected_zk_common_allocator_tests {
    use noid_ivc_core::deep_chain::schedule::{duplex_family_refs, duplex_fixed_patterns};

    use super::*;

    fn family_slices<const N: usize>(start: usize, w_log: usize) -> [WitnessSlice; N] {
        let len = 1usize << w_log;
        assert_eq!(start % len, 0);
        let first = start / len;
        std::array::from_fn(|column| WitnessSlice {
            log2_len: w_log,
            index: first + column,
        })
    }

    #[test]
    fn selected_b255_column_ledger_minimizes_alignment_exactly() {
        let geometry = crate::region_sidecar::selected_zk_block_geometry(255).unwrap();
        let ledger = SelectedZkRegionAllocationLedger::new(966_647, geometry);
        assert_eq!(ledger.before, 966_647);
        assert_eq!(ledger.main, 983_040);
        assert_eq!(ledger.owner, 1_376_256);
        assert_eq!(ledger.wallet_b, 1_572_864);
        assert_eq!(ledger.wallet_a, 4_194_304);
        assert_eq!(ledger.meta_a, 3_932_160);
        assert_eq!(ledger.meta_b, 7_340_032);
        assert_eq!(ledger.after, 8_519_680);
        assert_eq!(
            ledger.after - ledger.before - SELECTED_ZK_REGION_COMMITTED_CELLS,
            16_393
        );

        let mut ranges = Vec::new();
        let mut cursor = ledger.before;
        for family in ledger.order {
            let (w_log, columns) = family.dimensions(geometry);
            let start = match family {
                SelectedZkRegionFamily::Main => ledger.main,
                SelectedZkRegionFamily::Owner => ledger.owner,
                SelectedZkRegionFamily::WalletB => ledger.wallet_b,
                SelectedZkRegionFamily::WalletA => ledger.wallet_a,
                SelectedZkRegionFamily::MetaA => ledger.meta_a,
                SelectedZkRegionFamily::MetaB => ledger.meta_b,
            };
            let len = 1usize << w_log;
            cursor = cursor.checked_next_multiple_of(len).unwrap();
            assert_eq!(start, cursor, "optimal family alignment");
            for column in 0..columns {
                ranges.push(start + column * len..start + (column + 1) * len);
            }
            cursor += columns * len;
        }
        assert_eq!(ranges.len(), SELECTED_ZK_REGION_COMMITTED_COLUMNS);
        assert_eq!(cursor, ledger.after);
        assert!(
            ledger.after < 1 << 24,
            "selected slices fit the B255 witness"
        );
        for (index, left) in ranges.iter().enumerate() {
            for right in &ranges[index + 1..] {
                assert!(left.end <= right.start || right.end <= left.start);
            }
        }
    }

    #[test]
    fn selected_lower_classes_keep_their_own_committed_domains() {
        for (tier, expected_cells, expected_span, class_m) in [
            (25usize, 1_384_448usize, 1_384_448usize, 22usize),
            (255, 7_536_640, 7_536_640, 24),
        ] {
            let geometry = crate::region_sidecar::selected_zk_block_geometry(tier).unwrap();
            let ledger = SelectedZkRegionAllocationLedger::new(0, geometry);
            let committed_cells = SELECTED_ZK_REGION_WALLET_A_COLUMNS
                * (1 << geometry.wallet_a_w_log)
                + SELECTED_ZK_REGION_WALLET_B_COLUMNS * (1 << geometry.wallet_b_w_log)
                + SELECTED_ZK_REGION_META_B_COLUMNS * (1 << geometry.meta_b_w_log)
                + SELECTED_ZK_REGION_MAIN_COLUMNS * (1 << geometry.main_w_log)
                + SELECTED_ZK_REGION_META_A_COLUMNS * (1 << geometry.meta_a_w_log)
                + SELECTED_ZK_REGION_OWNER_COLUMNS * (1 << geometry.owner_w_log);
            assert_eq!(committed_cells, expected_cells, "B{tier} committed cells");
            assert_eq!(ledger.after, expected_span, "B{tier} allocation span");
            assert!(ledger.after < 1usize << class_m, "B{tier} class domain");
        }
    }

    #[test]
    fn candidate_allocations_form_complete_object_registry_certificates() {
        use crate::region_sidecar::{BlockRegionSidecarVk, SelectedZkBlockRegionVkSlices};
        for g in crate::region_sidecar::object_block_geometries() {
            let tier = g.tier;
            let ledger = SelectedZkRegionAllocationLedger::new(966_647, g);
            let slices = SelectedZkBlockRegionVkSlices {
                wallet_a: family_slices(ledger.wallet_a, g.wallet_a_w_log),
                wallet_b: family_slices(ledger.wallet_b, g.wallet_b_w_log),
                meta_a: family_slices(ledger.meta_a, g.meta_a_w_log),
                meta_b: family_slices(ledger.meta_b, g.meta_b_w_log),
                owner_c: family_slices(ledger.owner, g.owner_w_log),
                main_c: family_slices(ledger.main, g.main_w_log),
            };
            let vk = BlockRegionSidecarVk::from_object_registry_slices(g, slices).unwrap();
            assert!(vk.supports_objects());
            assert_eq!(vk.meta_a().w_log(), g.meta_a_w_log);
            // A registry with the same dimensions but missing an overflow
            // region cannot silently stand in for the candidate certificate.
            let mut bad = vk.selected_registry_slices().unwrap();
            bad.meta_a[0].log2_len -= 1;
            assert!(BlockRegionSidecarVk::from_object_registry_slices(g, bad).is_err());
            let recipe = vk.selected_registry_slices().unwrap();
            let rebuilt = BlockRegionSidecarVk::from_object_registry_slices(g, recipe).unwrap();
            assert_eq!(rebuilt, vk);
            if ![25, 255].contains(&tier) {
                assert!(BlockRegionSidecarVk::from_selected_registry_slices(
                    tier,
                    vk.selected_registry_slices().unwrap()
                )
                .is_err());
            }
        }
    }

    #[test]
    fn selected_b255_planned_slices_form_the_exact_v5_certificate() {
        let geometry = crate::region_sidecar::selected_zk_block_geometry(255).unwrap();
        let ledger = SelectedZkRegionAllocationLedger::new(966_647, geometry);
        let wallet_a = crate::region_sidecar::WalkARegionVk::new_wallet(
            selected_zk_auth_wallet_a_sidecar_purpose(),
            SELECTED_ZK_REGION_TX_LOG,
            SELECTED_ZK_REGION_QUERY_LOG,
            family_slices(ledger.wallet_a, SELECTED_ZK_REGION_WALLET_A_LOG),
        )
        .unwrap();
        let meta_a = crate::region_sidecar::WalkARegionVk::new_meta(
            auth_pcs_meta_a_sidecar_purpose(),
            SELECTED_ZK_REGION_TX_LOG,
            Some(13),
            Some(0),
            family_slices(ledger.meta_a, SELECTED_ZK_REGION_META_A_LOG),
        )
        .unwrap();
        let capsule_iv = iv_flat_of_tag(TAG_CAPSNODE);
        let wallet_b = crate::region_sidecar::MerkleRegionVk::new(
            selected_zk_auth_wallet_b_sidecar_purpose(),
            SELECTED_ZK_REGION_WALLET_B_LOG,
            family_slices(ledger.wallet_b, SELECTED_ZK_REGION_WALLET_B_LOG),
            10,
            vec![
                crate::region_sidecar::MerkleRegionFamily::FeedForwardStrided {
                    offset: 0,
                    depth: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
                    n_paths: SELECTED_ZK_REGION_CORE_QUERY_COUNT,
                    stride: 16,
                    iv: capsule_iv,
                },
                crate::region_sidecar::MerkleRegionFamily::FeedForwardStrided {
                    offset: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
                    depth: ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                    n_paths: SELECTED_ZK_REGION_CORE_QUERY_COUNT,
                    stride: 16,
                    iv: capsule_iv,
                },
            ],
        )
        .unwrap();
        let exact_state_iv = iv_flat_of_tag(TAG_EXSTNOD);
        let meta_b = crate::region_sidecar::MerkleRegionVk::new(
            auth_pcs_meta_b_sidecar_purpose(),
            SELECTED_ZK_REGION_META_B_LOG,
            family_slices(ledger.meta_b, SELECTED_ZK_REGION_META_B_LOG),
            9,
            vec![
                crate::region_sidecar::MerkleRegionFamily::PairedUpdate {
                    offset: 0,
                    n_updates: 6,
                    iv: exact_state_iv,
                },
                crate::region_sidecar::MerkleRegionFamily::PairedUpdate {
                    offset: 384,
                    n_updates: 1,
                    iv: exact_state_iv,
                },
                crate::region_sidecar::MerkleRegionFamily::TwoPermutation {
                    offset: 448,
                    depth: 8,
                    n_paths: 1,
                    iv: compress_iv_flat(),
                },
                crate::region_sidecar::MerkleRegionFamily::FeedForwardStrided {
                    offset: 464,
                    depth: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
                    n_paths: 1,
                    stride: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH + ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                    iv: capsule_iv,
                },
                crate::region_sidecar::MerkleRegionFamily::FeedForwardStrided {
                    offset: 474,
                    depth: ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                    n_paths: 1,
                    stride: ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH + ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                    iv: capsule_iv,
                },
            ],
        )
        .unwrap();
        let schedules =
            crate::acceptance::zk_auth_capsule_schedule::ZkAuthCapsuleDuplexSchedules::selected();
        let channel_iv = iv_flat_of_tag(TAG_KSCH256);
        let owner_layout = schedules.owner_sidecar_layout();
        let owner = crate::region_sidecar::DuplexRegionVk::new(
            selected_zk_auth_owner_sidecar_purpose(),
            SELECTED_ZK_REGION_OWNER_LOG,
            family_slices(ledger.owner, SELECTED_ZK_REGION_OWNER_LOG),
            duplex_fixed_patterns(&owner_layout, channel_iv, 7),
            duplex_family_refs(0, 0),
            &owner_layout,
        )
        .unwrap();
        let main_layout = schedules.main_sidecar_layout();
        let main = crate::region_sidecar::DuplexRegionVk::new(
            selected_zk_auth_main_sidecar_purpose(),
            SELECTED_ZK_REGION_MAIN_LOG,
            family_slices(ledger.main, SELECTED_ZK_REGION_MAIN_LOG),
            duplex_fixed_patterns(&main_layout, channel_iv, 8),
            duplex_family_refs(0, 0),
            &main_layout,
        )
        .unwrap();
        let vk = crate::region_sidecar::BlockRegionSidecarVk::new_selected_zk(
            wallet_a, meta_a, wallet_b, meta_b, owner, main,
        )
        .unwrap();
        vk.validate_selected_zk_roles().unwrap();
        assert_eq!(
            vk.version(),
            crate::region_sidecar::BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION
        );
        assert_eq!(vk.wallet_a().slices()[0].start(), ledger.wallet_a);
        assert_eq!(vk.wallet_b().slices()[0].start(), ledger.wallet_b);
        assert_eq!(vk.meta_b().slices()[0].start(), ledger.meta_b);
        assert_eq!(vk.main_c().slices()[0].start(), ledger.main);
        assert_eq!(vk.meta_a().slices()[0].start(), ledger.meta_a);
        assert_eq!(vk.owner_c().slices()[0].start(), ledger.owner);
    }

    #[test]
    fn meta_statement_entry_and_root_pins_reject_mutations() {
        let depth = 2usize;
        let root_slot = 2 * (depth - 1) + 1;
        let entry = [F128::new(5, 0), F128::new(7, 0)];
        let root = [F128::new(11, 0), F128::new(13, 0)];
        let mut columns = vec![vec![F128::ZERO; 16]; 9];
        for lane in 0..2 {
            columns[4 + lane][0] = entry[lane];
            columns[lane][root_slot] = root[lane];
        }
        let mut b = FieldR1csBuilder::new();
        let slices = columns
            .iter()
            .map(|column| alloc_column_slice(&mut b, column, 4).0)
            .collect::<Vec<_>>();
        let mut pins = Vec::new();
        append_meta_b_statement_pins(
            &mut pins,
            &[depth],
            &[vec![entry.map(LinExpr::constant)]],
            &[vec![root.map(LinExpr::constant)]],
            &[vec![root]],
            &[vec![root]],
            &[vec![0]],
        );
        assert_eq!(pins.len(), 4);
        pin_stage2_cells(&mut b, &slices, &pins);
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));

        let mut bad_entry = witness.clone();
        bad_entry[slices[4].start()] += F128::ONE;
        assert!(!r1cs.satisfies(&bad_entry));
        let mut bad_root = witness;
        bad_root[slices[0].start() + root_slot] += F128::ONE;
        assert!(!r1cs.satisfies(&bad_root));
    }
}

/// The flat-basis capacity IV of a consensus domain tag (mirror of the
/// TAG_FRICHANL conversion at the walk-C setup: `[φ(iv_hi), φ(iv_lo)]`).
fn iv_flat_of_tag(tag: DomainTag) -> [F128; 2] {
    let iv = capacity_iv(tag);
    [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
}

/// One real exact-state path of a walk-B leg chunk: the flat witness data
/// plus the statement wires the leg pins bind (entry = the paired slot-leaf
/// digest wires; root = the expected-root statement wires).
struct EsPathReal {
    entry_flat: [F128; 2],
    entry_w: [LinExpr; 2],
    siblings: Vec<[F128; 2]>,
    directions: Vec<bool>,
    root_flat: [F128; 2],
    root_w: [LinExpr; 2],
}

/// Fill ONE tx block's chunk of an exact-state walk-B Merkle leg: the real
/// paths (entries/roots = statement wires) then canonical ghost paths (entry
/// `[0,0]`, zero siblings, all-left — the recomputed root is a deterministic
/// constant of `(depth, iv)`) up to the leg's per-block capacity. Extends the
/// per-leg accumulators in path order so `discharge_merkle_union`'s generic
/// entry/root pin loop covers real and ghost paths alike.
#[allow(clippy::too_many_arguments)]
fn fill_es_merkle_leg(
    cb: &mut [Vec<F128>],
    s0b: &mut [Vec<F128>; STATE_SIZE],
    soutb: &mut [Vec<F128>; STATE_SIZE],
    acc_entry_wires: &mut Vec<[LinExpr; 2]>,
    acc_root_wires: &mut Vec<[LinExpr; 2]>,
    acc_committed_roots: &mut Vec<[F128; 2]>,
    acc_path_slots: &mut Vec<usize>,
    acc_recomputed_roots: &mut Vec<[F128; 2]>,
    depth: usize,
    cap: usize,
    iv_flat: [F128; 2],
    col_base: usize,
    region_base: usize,
    real: &[EsPathReal],
) {
    assert!(
        real.len() <= cap,
        "es leg chunk exceeds the per-block capacity"
    );
    let stride = (2 * depth).next_power_of_two();
    let mut witnesses = Vec::with_capacity(cap);
    for p in real {
        assert_eq!(p.siblings.len(), depth);
        assert_eq!(p.directions.len(), depth);
        witnesses.push(MerklePathWitness {
            entry: p.entry_flat,
            siblings: p.siblings.clone(),
            directions: p.directions.clone(),
        });
    }
    for _ in real.len()..cap {
        witnesses.push(MerklePathWitness {
            entry: [F128::ZERO; 2],
            siblings: vec![[F128::ZERO; 2]; depth],
            directions: vec![false; depth],
        });
    }
    let family = MerklePathFamily {
        depth,
        n_paths: cap,
    };
    let fam_wlog = (cap * stride).next_power_of_two().trailing_zeros() as usize;
    let mcols = build_merkle_path_columns(&family, iv_flat, &witnesses, fam_wlog);
    place_merkle(cb, s0b, soutb, &mcols, col_base, region_base, cap * stride);
    for (i, p) in real.iter().enumerate() {
        assert_eq!(
            mcols.roots[i], p.root_flat,
            "es path recomputed root != the expected-root statement"
        );
        acc_entry_wires.push(p.entry_w.clone());
        acc_root_wires.push(p.root_w.clone());
        acc_committed_roots.push(p.root_flat);
        acc_path_slots.push(region_base + i * stride);
    }
    for i in real.len()..cap {
        let r = mcols.roots[i];
        acc_entry_wires.push([LinExpr::zero(), LinExpr::zero()]);
        acc_root_wires.push([LinExpr::constant(r[0]), LinExpr::constant(r[1])]);
        acc_committed_roots.push(r);
        acc_path_slots.push(region_base + i * stride);
    }
    acc_recomputed_roots.extend(mcols.roots.iter().copied());
}

#[cfg(test)]
pub(crate) fn alloc_column_slice(
    b: &mut FieldR1csBuilder,
    col: &[F128],
    log2_len: usize,
) -> (WitnessSlice, Vec<LinExpr>) {
    let block = 1usize << log2_len;
    while b.num_wires() % block != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let index = b.num_wires() / block;
    let wires: Vec<LinExpr> = col
        .iter()
        .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
        .collect();
    for _ in col.len()..block {
        b.alloc_f128(F128::ZERO);
    }
    (WitnessSlice { log2_len, index }, wires)
}

/// Allocate the exact same committed-column geometry as the test-only legacy
/// allocator when the caller needs only its [`WitnessSlice`].
///
/// Constructing the discarded `Vec<LinExpr>` is not free: every
/// [`LinExpr::from_wire`] owns a one-term heap allocation.  Production Link
/// assembly allocates more than a million committed cells and retains only
/// their slices, so that compatibility return value used to create and free
/// more than a million tiny allocations.  This twin deliberately mirrors the
/// alignment, value allocation, padding, and wire order of the original
/// helper without materializing expressions that cannot be observed.
pub(crate) fn alloc_column_slice_values_only(
    b: &mut FieldR1csBuilder,
    col: &[F128],
    log2_len: usize,
) -> WitnessSlice {
    let block = 1usize << log2_len;
    while b.num_wires() % block != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let index = b.num_wires() / block;
    for &value in col {
        b.alloc_f128(value);
    }
    for _ in col.len()..block {
        b.alloc_f128(F128::ZERO);
    }
    WitnessSlice { log2_len, index }
}

/// Allocate one committed column as exact boolean R1CS rows while preserving
/// the same contiguous [`WitnessSlice`] geometry as [`alloc_column_slice`].
/// This is used by wallet-B's D column: live directions and packed-query tail
/// carriers are boolean by protocol, and their booleanity must not depend on a
/// pre-commit Fiat–Shamir relation challenge.
#[cfg(test)]
pub(crate) fn alloc_boolean_column_slice(
    b: &mut FieldR1csBuilder,
    col: &[F128],
    log2_len: usize,
) -> (WitnessSlice, Vec<LinExpr>) {
    let block = 1usize << log2_len;
    while b.num_wires() % block != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let index = b.num_wires() / block;
    let wires = col
        .iter()
        .enumerate()
        .map(|(slot, &value)| {
            assert!(
                value == F128::ZERO || value == F128::ONE,
                "boolean column slot {slot}"
            );
            LinExpr::from_wire(b.alloc_bool(value == F128::ONE))
        })
        .collect::<Vec<_>>();
    for _ in col.len()..block {
        b.alloc_bool(false);
    }
    (WitnessSlice { log2_len, index }, wires)
}

/// Values-only twin of the test-only legacy boolean allocator. It preserves
/// the boolean rows, validation, alignment and wire numbering while avoiding
/// a discarded one-allocation-per-cell `Vec<LinExpr>`.
pub(crate) fn alloc_boolean_column_slice_values_only(
    b: &mut FieldR1csBuilder,
    col: &[F128],
    log2_len: usize,
) -> WitnessSlice {
    let block = 1usize << log2_len;
    while b.num_wires() % block != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let index = b.num_wires() / block;
    for (slot, &value) in col.iter().enumerate() {
        assert!(
            value == F128::ZERO || value == F128::ONE,
            "boolean column slot {slot}"
        );
        b.alloc_bool(value == F128::ONE);
    }
    for _ in col.len()..block {
        b.alloc_bool(false);
    }
    WitnessSlice { log2_len, index }
}

#[cfg(test)]
mod column_slice_values_only_tests {
    use super::*;

    #[test]
    fn values_only_allocators_match_legacy_slices_wires_rows_and_values() {
        let column = [
            F128::new(3, 5),
            F128::new(7, 11),
            F128::ZERO,
            F128::new(13, 17),
            F128::new(19, 23),
        ];
        let boolean = [F128::ONE, F128::ZERO, F128::ONE];
        let mut legacy = FieldR1csBuilder::new();
        let mut values_only = FieldR1csBuilder::new();

        // Force non-trivial alignment before the first slice.  The second
        // slice then proves that padding leaves the next wire identical too.
        for value in [F128::new(29, 31), F128::new(37, 41)] {
            legacy.alloc_f128(value);
            values_only.alloc_f128(value);
        }

        let (legacy_column, column_wires) = alloc_column_slice(&mut legacy, &column, 3);
        let fast_column = alloc_column_slice_values_only(&mut values_only, &column, 3);
        assert_eq!(fast_column, legacy_column);
        assert_eq!(fast_column.start(), legacy_column.start());
        assert_eq!(fast_column.len(), legacy_column.len());
        assert_eq!(legacy.values(), values_only.values());
        assert_eq!(legacy.num_wires(), values_only.num_wires());
        for (offset, expression) in column_wires.iter().enumerate() {
            assert_eq!(
                expression,
                &LinExpr::from_wire(noid_ivc_core::field_circuit::Wire(
                    (legacy_column.start() + offset) as u32,
                ))
            );
        }

        let (legacy_boolean, boolean_wires) = alloc_boolean_column_slice(&mut legacy, &boolean, 3);
        let fast_boolean = alloc_boolean_column_slice_values_only(&mut values_only, &boolean, 3);
        assert_eq!(fast_boolean, legacy_boolean);
        assert_eq!(fast_boolean.start(), legacy_boolean.start());
        assert_eq!(fast_boolean.len(), legacy_boolean.len());
        assert_eq!(legacy.values(), values_only.values());
        assert_eq!(legacy.num_wires(), values_only.num_wires());
        for (offset, expression) in boolean_wires.iter().enumerate() {
            assert_eq!(
                expression,
                &LinExpr::from_wire(noid_ivc_core::field_circuit::Wire(
                    (legacy_boolean.start() + offset) as u32,
                ))
            );
        }

        let (legacy_relation, legacy_witness) = legacy.build();
        let (fast_relation, fast_witness) = values_only.build();
        assert_eq!(fast_witness, legacy_witness);
        assert_eq!(fast_relation.useful_rows, legacy_relation.useful_rows);
        assert_eq!(
            fast_relation.structural_statement_digest(),
            legacy_relation.structural_statement_digest()
        );
    }
}

/// The boolean point selecting slot `s` in `w_log` coordinates.
#[cfg(test)]
pub(crate) fn slot_point(s: usize, w_log: usize) -> (Vec<LinExpr>, Vec<F128>) {
    let lin = (0..w_log)
        .map(|bb| {
            LinExpr::constant(if (s >> bb) & 1 == 1 {
                F128::ONE
            } else {
                F128::ZERO
            })
        })
        .collect();
    let nat = (0..w_log)
        .map(|bb| {
            if (s >> bb) & 1 == 1 {
                F128::ONE
            } else {
                F128::ZERO
            }
        })
        .collect();
    (lin, nat)
}

/// The committed cell at `slot` of `slice`, as a raw wire read. Bound by the
/// column's walk opening (Stage 2: pin an algebra wire to a cell instead of
/// emitting a per-cell opening claim — an R1CS row, not a link-IO lane).
pub(crate) fn slot_cell(slice: &WitnessSlice, slot: usize) -> LinExpr {
    LinExpr::from_wire(Wire((slice.start() + slot) as u32))
}

fn paired_update_base(
    layout: &TiledWalkLayout,
    family_base: usize,
    cap_per_block: usize,
    ordinal: usize,
) -> usize {
    let block = ordinal / cap_per_block;
    let within = ordinal % cap_per_block;
    let base = block * layout.block_slots + family_base + within * PAIRED_UPDATE_STRIDE;
    assert!(
        base + PAIRED_UPDATE_STRIDE <= layout.slots,
        "paired cell outside meta-B"
    );
    base
}

/// Test-only exact reference for the paired consistency relation. Production
/// discharges these equalities against the committed columns in the
/// post-commit Merkle sidecar.
#[cfg(test)]
fn pin_paired_consistency_cells(
    b: &mut FieldR1csBuilder,
    slices: &[WitnessSlice],
    layout: &TiledWalkLayout,
    family_bases: [usize; 2],
    caps_per_block: [usize; 2],
) {
    assert_eq!(slices.len(), 9, "paired meta-B slice count");
    let blocks = layout.slots / layout.block_slots;
    for block in 0..blocks {
        for family in 0..2 {
            for update in 0..caps_per_block[family] {
                let base = block * layout.block_slots
                    + family_bases[family]
                    + update * PAIRED_UPDATE_STRIDE;
                for level in 0..PAIRED_UPDATE_DEPTH {
                    let old_even = base + level * PAIRED_UPDATE_SLOTS_PER_LEVEL;
                    for col in [6usize, 7, 8] {
                        for offset in 1..PAIRED_UPDATE_SLOTS_PER_LEVEL {
                            pin_eq(
                                b,
                                &slot_cell(&slices[col], old_even + offset - 1),
                                &slot_cell(&slices[col], old_even + offset),
                            );
                        }
                    }
                    for lane in 0..2 {
                        // new-odd E carries this level's old-odd C.
                        pin_eq(
                            b,
                            &slot_cell(&slices[4 + lane], old_even + 3),
                            &slot_cell(&slices[lane], old_even + 1),
                        );
                        if level > 0 {
                            // next old-odd E carries the previous new-odd C.
                            pin_eq(
                                b,
                                &slot_cell(&slices[4 + lane], old_even + 1),
                                &slot_cell(&slices[lane], old_even - 1),
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Test-only reference that binds the ceil-tiling suffix of each paired family
/// to the native builder's canonical ghost update. Production leaves this
/// non-exported committed suffix internal to the sound paired-walk relation.
///
/// One overhang update costs exactly `9 * PAIRED_UPDATE_STRIDE = 576` rows.
#[cfg(test)]
fn pin_paired_overhang_ghost_cells(
    b: &mut FieldR1csBuilder,
    slices: &[WitnessSlice],
    layout: &TiledWalkLayout,
    family_bases: [usize; 2],
    caps_per_block: [usize; 2],
    class_capacities: [usize; 2],
    iv_flat: [F128; 2],
) {
    assert_eq!(slices.len(), 9, "paired meta-B slice count");
    let blocks = layout.slots / layout.block_slots;
    let ghost = build_paired_merkle_update_columns(&[], iv_flat, 6);
    let ghost_committed = ghost.committed_columns();
    assert_eq!(ghost_committed.len(), slices.len(), "paired ghost columns");

    for family in 0..2 {
        assert_eq!(
            caps_per_block[family],
            class_capacities[family].div_ceil(blocks),
            "paired ceil-tiling capacity"
        );
        let tiled_capacity = blocks * caps_per_block[family];
        for ordinal in class_capacities[family]..tiled_capacity {
            let base = paired_update_base(
                layout,
                family_bases[family],
                caps_per_block[family],
                ordinal,
            );
            for (column, values) in ghost_committed.iter().enumerate() {
                for offset in 0..PAIRED_UPDATE_STRIDE {
                    pin_eq(
                        b,
                        &slot_cell(&slices[column], base + offset),
                        &LinExpr::constant(values[offset]),
                    );
                }
            }
        }
    }
}

fn paired_exact_state_cells(
    slices: &[WitnessSlice],
    layout: &TiledWalkLayout,
    family_bases: [usize; 2],
    caps_per_block: [usize; 2],
    paired: &ExactStatePairedRegionData,
) -> PairedExactStateCells {
    assert_eq!(slices.len(), 9, "paired meta-B slice count");
    let entries = |base: usize| {
        (
            std::array::from_fn(|lane| slot_cell(&slices[4 + lane], base)),
            std::array::from_fn(|lane| slot_cell(&slices[4 + lane], base + 2)),
        )
    };
    let directions = |base: usize| {
        std::array::from_fn(|level| {
            slot_cell(&slices[8], base + level * PAIRED_UPDATE_SLOTS_PER_LEVEL)
        })
    };
    let roots_at = |base: usize, depth: usize| {
        let [old, new] = paired_update_root_offsets(depth);
        (
            std::array::from_fn(|lane| slot_cell(&slices[lane], base + old)),
            std::array::from_fn(|lane| slot_cell(&slices[lane], base + new)),
        )
    };

    let local = (0..paired.touched_capacity)
        .map(|ordinal| {
            let base = paired_update_base(layout, family_bases[0], caps_per_block[0], ordinal);
            let (old_entry, new_entry) = entries(base);
            let (old_root, new_root) = roots_at(base, PAIRED_UPDATE_DEPTH);
            PairedLocalExactStateCells {
                old_entry,
                new_entry,
                old_root,
                new_root,
                directions: directions(base),
            }
        })
        .collect();
    let upper = (0..paired.segment_capacity)
        .map(|ordinal| {
            let base = paired_update_base(layout, family_bases[1], caps_per_block[1], ordinal);
            let (old_entry, new_entry) = entries(base);
            let root_pairs: [([LinExpr; 2], [LinExpr; 2]); PAIRED_UPDATE_DEPTH] =
                std::array::from_fn(|level| roots_at(base, level + 1));
            PairedUpperExactStateCells {
                old_entry,
                new_entry,
                old_roots: std::array::from_fn(|level| root_pairs[level].0.clone()),
                new_roots: std::array::from_fn(|level| root_pairs[level].1.clone()),
                directions: directions(base),
            }
        })
        .collect();
    PairedExactStateCells { local, upper }
}

/// Rebuild a per-family stride-period pattern as a META-period table by
/// repeating its stride table `n_tiles` times starting at `base`, zero
/// elsewhere; `low_log = meta_p_log` localizes it to `[base, base + n·stride)`.
/// A COMMON-PERIOD pattern for the multi-tx tiling: place `stride_table`
/// `n_tiles` times at `offset` within ONE per-tx block of `2^block_log` slots,
/// `low_log = block_log`. Because the pattern is periodic over the tx block, it
/// fires in every tx for free and its MLE cost is `O(2^block_log)` (flat in the
/// tx count) — NOT the `O(2^w_log)` of a full-domain [`localize`].
pub(crate) fn common_period_pattern(
    stride_table: &[F128],
    offset: usize,
    n_tiles: usize,
    block_log: usize,
) -> FixedPattern {
    let block = 1usize << block_log;
    let stride = stride_table.len();
    let mut t = vec![F128::ZERO; block];
    for q in 0..n_tiles {
        let off = offset + q * stride;
        t[off..off + stride].copy_from_slice(stride_table);
    }
    FixedPattern::new(block_log, t)
}

/// A common-period selector: `1` over `[offset, offset + len)` within a per-tx
/// block of `2^block_log` slots, `low_log = block_log` (a region selector that
/// fires in every tx).
pub(crate) fn common_period_ones(offset: usize, len: usize, block_log: usize) -> FixedPattern {
    let block = 1usize << block_log;
    let mut t = vec![F128::ZERO; block];
    for s in offset..offset + len {
        t[s] = F128::ONE;
    }
    FixedPattern::new(block_log, t)
}

/// High index bits selecting one aligned dyadic sub-region of a walk domain.
/// Bits are returned LSB-first, starting immediately above the region-local
/// coordinates. An empty vector means the region is the whole domain.
pub(crate) fn dyadic_region_bits(base: usize, slots: usize, w_log: usize) -> Vec<bool> {
    assert!(slots.is_power_of_two(), "dyadic region size");
    let region_log = slots.trailing_zeros() as usize;
    assert!(region_log <= w_log, "region exceeds walk domain");
    assert_eq!(base % slots, 0, "dyadic region alignment");
    assert!(
        base + slots <= 1usize << w_log,
        "region outside walk domain"
    );
    (region_log..w_log)
        .map(|bit| (base >> bit) & 1 == 1)
        .collect()
}

/// Restrict a periodic fixed pattern to one aligned dyadic sub-region.  When
/// the region spans the whole walk no gate is necessary (and `FixedPattern`
/// intentionally rejects an empty high gate).
pub(crate) fn pattern_in_dyadic_region(
    pattern: FixedPattern,
    base: usize,
    slots: usize,
    w_log: usize,
) -> FixedPattern {
    let bits = dyadic_region_bits(base, slots, w_log);
    if bits.is_empty() {
        assert_eq!(base, 0, "whole-domain region starts at zero");
        pattern
    } else {
        pattern.gated(slots.trailing_zeros() as usize, bits)
    }
}

#[cfg(test)]
mod split_walk_a_layout_tests {
    use super::*;

    #[test]
    fn meta_region_draft_spine_only_matches_direct_raw_columns() {
        let flat = SpineInstanceFlat::ghost();
        let direct = build_spine_instance_columns(&flat);
        let spine = SpineRegionData {
            objects: false,
            instances: vec![SpineInstanceRegion {
                leaves_w: flat.leaves.clone().map(|pair| pair.map(LinExpr::constant)),
                tx_hash_w: direct.tx_hash.map(LinExpr::constant),
                tx_hash_flat: direct.tx_hash,
                flat,
                contract: None,
            }],
        };
        let mut b = FieldR1csBuilder::new();
        let before = b.num_wires();
        let draft = build_auth_pcs_meta_region_draft(&mut b, 1, None, None, Some(&spine), None);

        assert!(draft.has_meta);
        assert!(!draft.has_both_a_families);
        assert_eq!(draft.spine_cap, 1);
        assert_eq!(draft.meta_cols[0].len(), 64, "spine-only region slots");
        assert_eq!(draft.meta_w_log, 6);
        assert!(draft.meta_b.is_none());
        assert!(draft.meta_b_families.is_empty());
        assert_eq!(b.num_wires() - before, 2, "two spine root bridge wires");
        assert_eq!(
            draft.cell_pins_meta.len(),
            38,
            "32 KID + 4 root + 2 digest pins"
        );

        for lane in 0..2 {
            assert_eq!(
                &draft.meta_cols[KID0 + lane][..SPINE_TREE_SLOTS],
                direct.tree_kid[lane].as_slice()
            );
            let spine_wrap_base = SPINE_TREE_SLOTS;
            assert_eq!(
                &draft.meta_cols[IN0 + lane][spine_wrap_base..spine_wrap_base + SPINE_WRAP_SLOTS],
                direct.wrap_in[lane].as_slice()
            );
        }
        for lane in 0..STATE_SIZE {
            assert_eq!(
                &draft.meta_cols[C0 + lane][..SPINE_TREE_SLOTS],
                direct.tree_c[lane].as_slice()
            );
            assert_eq!(
                &draft.meta_s0[lane][..SPINE_TREE_SLOTS],
                direct.tree_s0[lane].as_slice()
            );
            assert_eq!(
                &draft.meta_s_out[lane][..SPINE_TREE_SLOTS],
                direct.tree_s_out[lane].as_slice()
            );
        }
    }

    fn production_split_b(k: usize) -> (TiledWalkLayout, TiledWalkLayout, TiledWalkLayout) {
        // Owner-auth capsule: nq=64, source/mid depths 5/6, both stride 8.
        let wallet_slots: [usize; 2] = [64 * 8, 64 * 8];
        // Current legacy B255 meta carrier: 12 depth-16 exact-state paths and
        // one depth-8 universal tx-root path per authorization tile.
        let meta_slots: [usize; 2] = [
            12 * (2usize * 16).next_power_of_two(),
            (2usize * 8).next_power_of_two(),
        ];
        let wallet = tiled_walk_layout(k, &wallet_slots);
        let meta = tiled_walk_layout(k, &meta_slots);
        let combined = tiled_walk_layout(
            k,
            &[
                wallet_slots[0],
                wallet_slots[1],
                meta_slots[0],
                meta_slots[1],
            ],
        );
        (wallet, meta, combined)
    }

    #[test]
    fn split_walk_b_layout_and_k1_k2_matrix() {
        let (w1, m1, old1) = production_split_b(1);
        let (w2, m2, old2) = production_split_b(2);

        assert_eq!(w1.bases, vec![0, 512]);
        assert_eq!(
            (w1.live_per_block, w1.block_slots, w1.w_log),
            (1024, 1024, 10)
        );
        assert_eq!(m1.bases, vec![0, 384]);
        assert_eq!((m1.live_per_block, m1.block_slots, m1.w_log), (400, 512, 9));
        assert_eq!(
            (old1.live_per_block, old1.block_slots, old1.w_log),
            (1424, 2048, 11)
        );

        // K changes only the high tile axis: bases, block logs, and therefore
        // every common-period relation matrix stay identical; each walk gains
        // exactly one high variable/domain bit.
        assert_eq!(w2.bases, w1.bases);
        assert_eq!(m2.bases, m1.bases);
        assert_eq!(w2.block_log, w1.block_log);
        assert_eq!(m2.block_log, m1.block_log);
        assert_eq!(w2.w_log, w1.w_log + 1);
        assert_eq!(m2.w_log, m1.w_log + 1);
        assert_eq!(old2.w_log, old1.w_log + 1);
        assert_eq!(w2.slots, 2 * w1.slots);
        assert_eq!(m2.slots, 2 * m1.slots);

        let wallet_matrix_k1 = common_period_ones(0, 512, w1.block_log);
        let wallet_matrix_k2 = common_period_ones(0, 512, w2.block_log);
        let meta_matrix_k1 = common_period_ones(384, 16, m1.block_log);
        let meta_matrix_k2 = common_period_ones(384, 16, m2.block_log);
        assert_eq!(wallet_matrix_k1, wallet_matrix_k2, "wallet-B matrix period");
        assert_eq!(meta_matrix_k1, meta_matrix_k2, "meta-B matrix period");

        const COLS: usize = 9;
        assert_eq!(
            COLS * (old1.slots - w1.slots - m1.slots),
            4_608,
            "K=1 raw split saving"
        );
        assert_eq!(
            COLS * (old2.slots - w2.slots - m2.slots),
            9_216,
            "K=2 raw split saving"
        );
    }

    #[test]
    fn split_walk_b_b255_raw_saving_is_1_179_648_rows() {
        let (wallet, meta, old) = production_split_b(256);
        assert_eq!(wallet.slots, 262_144);
        assert_eq!(meta.slots, 131_072);
        assert_eq!(old.slots, 524_288);
        assert_eq!(9 * (old.slots - wallet.slots - meta.slots), 1_179_648);
    }

    #[test]
    fn ff_d_committed_slice_is_exact_boolean_at_no_extra_row_cost() {
        let column = (0..8)
            .map(|slot| if slot & 1 == 1 { F128::ONE } else { F128::ZERO })
            .collect::<Vec<_>>();
        let mut b = FieldR1csBuilder::new();
        let before = b.num_wires();
        let (slice, wires) = alloc_boolean_column_slice(&mut b, &column, 3);
        assert_eq!(wires.len(), column.len());
        assert_eq!(
            b.num_wires() - before,
            15,
            "seven alignment rows plus the same eight committed cells"
        );
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
        let mut bad = witness;
        bad[slice.start()] = F128::new(2, 0);
        assert!(
            !r1cs.satisfies(&bad),
            "non-boolean committed D cell survived exact allocation row"
        );
    }

    #[test]
    fn wallet_ff_root_pin_uses_composite_only_at_power_of_two_depth() {
        let iv = iv_flat_of_tag(noid_poseidon2b::native::domain::TAG_CAPSNODE);
        let build = |depth: usize| {
            build_ff_merkle_path_columns(
                &FfMerklePathFamily { depth, n_paths: 1 },
                iv,
                &[FfMerklePathWitness {
                    entry: [F128::new(5, 7), F128::new(11, 13)],
                    siblings: (0..depth)
                        .map(|level| {
                            [
                                F128::new(17 + level as u64, 19 + level as u64),
                                F128::new(23 + level as u64, 29 + level as u64),
                            ]
                        })
                        .collect(),
                    directions: (0..depth).map(|level| level & 1 == 1).collect(),
                }],
                3,
            )
        };
        let allocate =
            |b: &mut FieldR1csBuilder,
             cols: &noid_ivc_core::deep_chain::ff_merkle::FfMerklePathColumns| {
                let mut slices = Vec::with_capacity(9);
                for column in cols.c.iter() {
                    slices.push(alloc_column_slice(b, column, 3).0);
                }
                for column in cols.cr.iter() {
                    slices.push(alloc_column_slice(b, column, 3).0);
                }
                for column in cols.sib.iter() {
                    slices.push(alloc_column_slice(b, column, 3).0);
                }
                slices.push(alloc_boolean_column_slice(b, &cols.d, 3).0);
                slices
            };

        // Depth five retains the chain-constrained root-copy cell: only the
        // two equality pins are new at the statement boundary.
        let short = build(5);
        let mut short_builder = FieldR1csBuilder::new();
        let short_slices = allocate(&mut short_builder, &short);
        let before_short = short_builder.num_wires();
        pin_wallet_b_roots(
            &mut short_builder,
            &short_slices,
            &[WalletFfRootPin::new(
                0,
                5,
                short.roots[0].map(LinExpr::constant),
            )],
        );
        assert_eq!(short_builder.num_wires() - before_short, 2);
        let (short_r1cs, short_witness) = short_builder.build();
        assert!(short_r1cs.satisfies(&short_witness));

        // Depth eight has no tail. Two products plus the same two public-root
        // equalities are exactly the four rows charged per path.
        let full = build(8);
        let mut full_builder = FieldR1csBuilder::new();
        let full_slices = allocate(&mut full_builder, &full);
        let before_full = full_builder.num_wires();
        pin_wallet_b_roots(
            &mut full_builder,
            &full_slices,
            &[WalletFfRootPin::new(
                0,
                8,
                full.roots[0].map(LinExpr::constant),
            )],
        );
        assert_eq!(full_builder.num_wires() - before_full, 4);
        let (full_r1cs, full_witness) = full_builder.build();
        assert!(full_r1cs.satisfies(&full_witness));
    }

    fn paired_meta_layout(
        k: usize,
        touched_capacity: usize,
        segment_capacity: usize,
        tx_root_slots: usize,
    ) -> TiledWalkLayout {
        tiled_walk_layout(
            k,
            &[
                touched_capacity.div_ceil(k) * PAIRED_UPDATE_STRIDE,
                segment_capacity.div_ceil(k) * PAIRED_UPDATE_STRIDE,
                tx_root_slots,
            ],
        )
    }

    #[test]
    fn paired_meta_b_shape_k1_k2_and_b255_m17() {
        // Same per-tile class matrix: doubling both fixed capacities and K
        // adds one high tile coordinate and leaves every low pattern intact.
        let k1 = paired_meta_layout(1, 6, 1, 16);
        let k2 = paired_meta_layout(2, 12, 2, 16);
        assert_eq!(k1.bases, vec![0, 384, 448]);
        assert_eq!(k2.bases, k1.bases);
        assert_eq!(k1.block_slots, 512);
        assert_eq!(k2.block_slots, 512);
        assert_eq!(k2.w_log, k1.w_log + 1);
        assert_eq!(k2.slots, 2 * k1.slots);

        let b255 = paired_meta_layout(256, 1_531, 256, 16);
        assert_eq!(b255.bases, vec![0, 384, 448]);
        assert_eq!(b255.live_per_block, 464);
        assert_eq!(b255.block_slots, 512);
        assert_eq!(b255.slots, 131_072);
        assert_eq!(b255.w_log, 17, "B255 paired meta-B is m17");
        assert_eq!(9 * b255.slots, 1_179_648, "exactly nine meta-B columns");
        let b255_overhang_updates =
            256 * 1_531usize.div_ceil(256) - 1_531 + 256 * 256usize.div_ceil(256) - 256;
        assert_eq!(b255_overhang_updates, 5);
        assert_eq!(
            9 * PAIRED_UPDATE_STRIDE * b255_overhang_updates,
            2_880,
            "B255 paired overhang exact-cell rows"
        );
    }

    fn paired_witness(seed: u64) -> super::super::paired_merkle_update::PairedMerkleUpdateWitness {
        let lane = |offset: u64| F128::new(seed + offset, seed.rotate_left(17) ^ offset);
        super::super::paired_merkle_update::PairedMerkleUpdateWitness {
            old_entry: [lane(1), lane(2)],
            new_entry: [lane(3), lane(4)],
            siblings: std::array::from_fn(|level| {
                [lane(10 + 2 * level as u64), lane(11 + 2 * level as u64)]
            }),
            directions: std::array::from_fn(|level| (seed as usize + level) & 1 == 1),
        }
    }

    #[test]
    fn merkle_postcommit_protocol_matches_legacy_paired_meta_b() {
        let w_log = 6;
        let iv = iv_flat_of_tag(TAG_EXSTNOD);
        let columns = build_paired_merkle_update_columns(&[paired_witness(0x51de)], iv, w_log);
        let committed_owned = vec![
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
        let committed: Vec<&[F128]> = committed_owned.iter().map(Vec::as_slice).collect();
        let mut fixed = paired_merkle_update_fixed_patterns(iv);
        fixed.push(common_period_ones(0, PAIRED_UPDATE_STRIDE, w_log));
        let paired = [PairedMerkleSpec {
            refs: paired_merkle_update_refs(0, 0),
            region: 11,
        }];
        let domain = b"walk-b-postcommit-legacy-parity";
        let legacy = run_merkle_union_native_with_paired(
            &committed,
            &columns.s0,
            &columns.s_out,
            &fixed,
            &[0, 1, 2, 3],
            &[],
            &[],
            &paired,
            w_log,
            domain,
        );

        let families = [MerkleProtocolFamily::paired_update(0)];
        let mut prover = FsLaneChallenger::new(domain);
        let (proof, claims) = prove_merkle_union_with_challenger(
            w_log,
            &fixed,
            &[0, 1, 2, 3],
            &families,
            &committed,
            &columns.s0,
            &columns.s_out,
            &mut prover,
        );
        let mut verifier = FsLaneChallenger::new(domain);
        let replay = verify_merkle_union_with_challenger(
            w_log,
            &fixed,
            &[0, 1, 2, 3],
            &families,
            &proof,
            &mut verifier,
        )
        .expect("postcommit Walk-B replay");

        assert_eq!(claims, replay);
        assert_eq!(proof.zero, legacy.zero_proof);
        assert_eq!(proof.selection, legacy.sel_proof);
        assert_eq!(proof.walk, legacy.walk_proof);
        assert_eq!(proof.substitution, legacy.sub_proof);
        assert_eq!(
            proof.zero_shifts,
            legacy
                .zero_shifts
                .iter()
                .map(|(_, _, shift)| shift.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            proof.shifts,
            legacy
                .shifts
                .iter()
                .map(|(_, _, shift)| shift.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            claims
                .iter()
                .map(|claim| (claim.column, claim.point.clone(), claim.value))
                .collect::<Vec<_>>(),
            legacy.pending
        );
    }

    #[test]
    fn merkle_postcommit_rejects_each_paired_consistency_mutation() {
        let w_log = 6;
        let iv = iv_flat_of_tag(TAG_EXSTNOD);
        let columns = build_paired_merkle_update_columns(&[paired_witness(0x51de)], iv, w_log);
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
        let mut fixed = paired_merkle_update_fixed_patterns(iv);
        fixed.push(common_period_ones(0, PAIRED_UPDATE_STRIDE, w_log));
        let families = [MerkleProtocolFamily::paired_update(0)];

        for (column, slot, domain, label) in [
            (
                4usize,
                3usize,
                b"paired-bad-e-bridge".as_slice(),
                "E bridge",
            ),
            (6, 2, b"paired-bad-sibling-copy".as_slice(), "sibling copy"),
            (
                8,
                2,
                b"paired-bad-direction-copy".as_slice(),
                "direction copy",
            ),
        ] {
            let mut malformed = committed.clone();
            malformed[column][slot] += F128::ONE;
            let malformed_refs = malformed.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let proof = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut prover = FsLaneChallenger::new(domain);
                prove_merkle_union_with_challenger(
                    w_log,
                    &fixed,
                    &[0, 1, 2, 3],
                    &families,
                    &malformed_refs,
                    &columns.s0,
                    &columns.s_out,
                    &mut prover,
                )
                .0
            })) {
                Ok(proof) => proof,
                Err(payload) => {
                    let message = payload
                        .downcast_ref::<String>()
                        .map(String::as_str)
                        .or_else(|| payload.downcast_ref::<&'static str>().copied())
                        .unwrap_or_default();
                    if message.contains("relation prover-side round mismatch") {
                        // Debug builds reject a dishonest witness before it can
                        // produce an invalid proof. Release builds exercise the
                        // verifier-side Zero rejection below.
                        continue;
                    }
                    std::panic::resume_unwind(payload);
                }
            };
            let mut verifier = FsLaneChallenger::new(domain);
            assert!(
                matches!(
                    verify_merkle_union_with_challenger(
                        w_log,
                        &fixed,
                        &[0, 1, 2, 3],
                        &families,
                        &proof,
                        &mut verifier,
                    ),
                    Err(MerkleUnionVerifyError::Zero(_))
                ),
                "{label} mutation escaped the post-commit zero relation"
            );
        }
    }

    #[test]
    fn merkle_postcommit_protocol_matches_mixed_production_meta_b_order() {
        let w_log = 8;
        let block_log = 8;
        let domain = b"walk-b-postcommit-mixed-meta-parity";
        let paired_iv = iv_flat_of_tag(TAG_EXSTNOD);
        let merkle_iv = iv_flat_of_tag(TAG_EXSTNOD);
        let (ghost_s0, ghost_out) =
            noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
        let mut committed_owned: Vec<Vec<F128>> =
            (0..9).map(|_| vec![F128::ZERO; 1usize << w_log]).collect();
        let mut s0: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![F128::ZERO; 1usize << w_log]);
        let mut s_out: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![F128::ZERO; 1usize << w_log]);
        for slot in 0..1usize << w_log {
            for lane in 0..STATE_SIZE {
                committed_owned[lane][slot] = ghost_out[lane];
                s0[lane][slot] = ghost_s0[lane];
                s_out[lane][slot] = ghost_out[lane];
            }
        }

        for (family, offset) in [paired_witness(0x6100), paired_witness(0x7200)]
            .into_iter()
            .zip([0usize, PAIRED_UPDATE_STRIDE])
        {
            let columns = build_paired_merkle_update_columns(&[family], paired_iv, 6);
            place_paired_merkle_updates(
                &mut committed_owned,
                &mut s0,
                &mut s_out,
                &columns,
                offset,
                PAIRED_UPDATE_STRIDE,
            );
        }

        let merkle_family = MerklePathFamily {
            depth: 2,
            n_paths: 1,
        };
        let merkle_columns = build_merkle_path_columns(
            &merkle_family,
            merkle_iv,
            &[MerklePathWitness {
                entry: [F128::new(7, 11), F128::new(13, 17)],
                siblings: vec![
                    [F128::new(19, 23), F128::new(29, 31)],
                    [F128::new(37, 41), F128::new(43, 47)],
                ],
                directions: vec![false, true],
            }],
            2,
        );
        place_merkle(
            &mut committed_owned,
            &mut s0,
            &mut s_out,
            &merkle_columns,
            4,
            2 * PAIRED_UPDATE_STRIDE,
            merkle_family.n_slots(),
        );

        let mut fixed = Vec::new();
        let mut paired_specs = Vec::new();
        for offset in [0usize, PAIRED_UPDATE_STRIDE] {
            let fixed_base = fixed.len();
            for pattern in paired_merkle_update_fixed_patterns(paired_iv) {
                fixed.push(common_period_pattern(&pattern.table, offset, 1, block_log));
            }
            fixed.push(common_period_ones(offset, PAIRED_UPDATE_STRIDE, block_log));
            paired_specs.push(PairedMerkleSpec {
                refs: paired_merkle_update_refs(0, fixed_base),
                region: fixed_base + 11,
            });
        }
        let merkle_fixed_base = fixed.len();
        for pattern in merkle_fixed_patterns(&merkle_family, merkle_iv) {
            fixed.push(common_period_pattern(
                &pattern.table,
                2 * PAIRED_UPDATE_STRIDE,
                merkle_family.n_paths,
                block_log,
            ));
        }
        fixed.push(common_period_ones(
            2 * PAIRED_UPDATE_STRIDE,
            merkle_family.n_slots(),
            block_log,
        ));
        let legs = [MerkleLeg {
            family: merkle_family,
            refs: union_merkle_refs(merkle_fixed_base),
            region: merkle_fixed_base + 8,
            committed_roots: Vec::new(),
            entry_wires: Vec::new(),
            root_wires: Vec::new(),
            path_slots: Vec::new(),
            recomputed_roots: Vec::new(),
        }];
        let committed: Vec<&[F128]> = committed_owned.iter().map(Vec::as_slice).collect();
        let legacy = run_merkle_union_native_with_paired(
            &committed,
            &s0,
            &s_out,
            &fixed,
            &[0, 1, 2, 3],
            &[],
            &legs,
            &paired_specs,
            w_log,
            domain,
        );

        let families = [
            MerkleProtocolFamily::paired_update(0),
            MerkleProtocolFamily::paired_update(12),
            MerkleProtocolFamily::two_permutation(merkle_fixed_base),
        ];
        let mut prover = FsLaneChallenger::new(domain);
        let (proof, claims) = prove_merkle_union_with_challenger(
            w_log,
            &fixed,
            &[0, 1, 2, 3],
            &families,
            &committed,
            &s0,
            &s_out,
            &mut prover,
        );
        let prover_next = prover.sample_f128();
        let mut verifier = FsLaneChallenger::new(domain);
        let replay = verify_merkle_union_with_challenger(
            w_log,
            &fixed,
            &[0, 1, 2, 3],
            &families,
            &proof,
            &mut verifier,
        )
        .expect("mixed meta-B replay");
        let verifier_next = verifier.sample_f128();

        assert_eq!(claims, replay);
        assert_eq!(prover_next, verifier_next, "postcommit transcript lockstep");
        assert_eq!(proof.zero, legacy.zero_proof);
        assert_eq!(proof.selection, legacy.sel_proof);
        assert_eq!(proof.walk, legacy.walk_proof);
        assert_eq!(proof.substitution, legacy.sub_proof);
        assert_eq!(
            proof.zero_shifts,
            legacy
                .zero_shifts
                .iter()
                .map(|(_, _, shift)| shift.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            proof.shifts,
            legacy
                .shifts
                .iter()
                .map(|(_, _, shift)| shift.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            claims
                .iter()
                .map(|claim| (claim.column, claim.point.clone(), claim.value))
                .collect::<Vec<_>>(),
            legacy.pending
        );
    }

    #[test]
    fn merkle_postcommit_protocol_matches_legacy_wallet_ff_b() {
        let w_log = 2;
        let domain = b"walk-b-postcommit-wallet-ff-parity";
        let iv = iv_flat_of_tag(noid_poseidon2b::native::domain::TAG_CAPSNODE);
        let family = FfMerklePathFamily {
            depth: 3,
            n_paths: 1,
        };
        let columns = build_ff_merkle_path_columns(
            &family,
            iv,
            &[FfMerklePathWitness {
                entry: [F128::new(5, 7), F128::new(11, 13)],
                siblings: vec![
                    [F128::new(17, 19), F128::new(23, 29)],
                    [F128::new(31, 37), F128::new(41, 43)],
                    [F128::new(47, 53), F128::new(59, 61)],
                ],
                directions: vec![false, true, false],
            }],
            w_log,
        );
        let committed_owned = vec![
            columns.c[0].clone(),
            columns.c[1].clone(),
            columns.c[2].clone(),
            columns.c[3].clone(),
            columns.cr[0].clone(),
            columns.cr[1].clone(),
            columns.sib[0].clone(),
            columns.sib[1].clone(),
            columns.d.clone(),
        ];
        let committed: Vec<&[F128]> = committed_owned.iter().map(Vec::as_slice).collect();
        let mut fixed = ff_merkle_fixed_patterns(&family, iv);
        fixed.push(common_period_ones(0, family.n_slots(), w_log));
        let ff = [FfLegSpec {
            refs: FfMerkleFamilyRefs {
                cr: [4, 5],
                sib: [6, 7],
                d: 8,
                c: [0, 1, 2, 3],
                node: 0,
                nodens: 1,
                start: 2,
                iv: [3, 4],
            },
            region: 5,
        }];
        let legacy = run_merkle_union_native(
            &committed,
            &columns.s0,
            &columns.s_out,
            &fixed,
            &[0, 1, 2, 3],
            &ff,
            &[],
            w_log,
            domain,
        );

        let families = [MerkleProtocolFamily::feed_forward(0)];
        let mut prover = FsLaneChallenger::new(domain);
        let (proof, claims) = prove_merkle_union_with_challenger(
            w_log,
            &fixed,
            &[0, 1, 2, 3],
            &families,
            &committed,
            &columns.s0,
            &columns.s_out,
            &mut prover,
        );
        let mut verifier = FsLaneChallenger::new(domain);
        let replay = verify_merkle_union_with_challenger(
            w_log,
            &fixed,
            &[0, 1, 2, 3],
            &families,
            &proof,
            &mut verifier,
        )
        .expect("wallet ff-B replay");

        assert_eq!(claims, replay);
        assert_eq!(proof.zero, legacy.zero_proof);
        assert_eq!(proof.selection, legacy.sel_proof);
        assert_eq!(proof.walk, legacy.walk_proof);
        assert_eq!(proof.substitution, legacy.sub_proof);
        assert_eq!(
            proof.zero_shifts,
            legacy
                .zero_shifts
                .iter()
                .map(|(_, _, shift)| shift.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            proof.shifts,
            legacy
                .shifts
                .iter()
                .map(|(_, _, shift)| shift.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            claims
                .iter()
                .map(|claim| (claim.column, claim.point.clone(), claim.value))
                .collect::<Vec<_>>(),
            legacy.pending
        );
    }

    #[test]
    fn paired_k2_reference_pins_cover_overhang_and_handoff_stops_at_capacity() {
        let k = 2usize;
        let class_capacities = [3usize, 1usize];
        let caps_per_block = [2usize, 1usize];
        let family_slots = caps_per_block.map(|cap| cap * PAIRED_UPDATE_STRIDE);
        let layout = tiled_walk_layout(k, &family_slots);
        assert_eq!(layout.bases, vec![0, 2 * PAIRED_UPDATE_STRIDE]);
        assert_eq!(layout.block_slots, 4 * PAIRED_UPDATE_STRIDE);

        let local_updates: Vec<_> = (0..class_capacities[0])
            .map(|i| paired_witness(0x3100 + i as u64))
            .collect();
        let upper_updates: Vec<_> = (0..class_capacities[1])
            .map(|i| paired_witness(0x4100 + i as u64))
            .collect();
        let partitions = [local_updates.as_slice(), upper_updates.as_slice()];
        let iv = iv_flat_of_tag(TAG_EXSTNOD);
        let mut cb: Vec<Vec<F128>> = (0..9).map(|_| vec![F128::ZERO; layout.slots]).collect();
        let mut s0: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![F128::ZERO; layout.slots]);
        let mut sout: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![F128::ZERO; layout.slots]);
        for block in 0..k {
            for family in 0..2 {
                let cap = caps_per_block[family];
                let lo = (block * cap).min(partitions[family].len());
                let hi = ((block + 1) * cap).min(partitions[family].len());
                let slots = cap * PAIRED_UPDATE_STRIDE;
                let columns = build_paired_merkle_update_columns(
                    &partitions[family][lo..hi],
                    iv,
                    slots.trailing_zeros() as usize,
                );
                place_paired_merkle_updates(
                    &mut cb,
                    &mut s0,
                    &mut sout,
                    &columns,
                    block * layout.block_slots + layout.bases[family],
                    slots,
                );
            }
        }

        let mut b = FieldR1csBuilder::new();
        let slices: Vec<WitnessSlice> = cb
            .iter()
            .map(|column| alloc_column_slice(&mut b, column, layout.w_log).0)
            .collect();
        let before_copies = b.num_wires();
        pin_paired_consistency_cells(
            &mut b,
            &slices,
            &layout,
            [layout.bases[0], layout.bases[1]],
            caps_per_block,
        );
        assert_eq!(
            b.num_wires() - before_copies,
            206 * 6,
            "exact copies cover all four local/upper tiles"
        );
        let before_ghosts = b.num_wires();
        pin_paired_overhang_ghost_cells(
            &mut b,
            &slices,
            &layout,
            [layout.bases[0], layout.bases[1]],
            caps_per_block,
            class_capacities,
            iv,
        );
        assert_eq!(
            b.num_wires() - before_ghosts,
            2 * 9 * PAIRED_UPDATE_STRIDE,
            "one local plus one upper overhang, 576 rows each"
        );

        let paired = ExactStatePairedRegionData {
            local_updates,
            upper_updates,
            local_update_count: class_capacities[0],
            upper_update_count: class_capacities[1],
            touched_capacity: class_capacities[0],
            segment_capacity: class_capacities[1],
            active_upper_depth: 16,
        };
        let handoff = paired_exact_state_cells(
            &slices,
            &layout,
            [layout.bases[0], layout.bases[1]],
            caps_per_block,
            &paired,
        );
        assert_eq!(handoff.local.len(), class_capacities[0]);
        assert_eq!(handoff.upper.len(), class_capacities[1]);
        for (ordinal, cells) in handoff.local.iter().enumerate() {
            let base = paired_update_base(&layout, layout.bases[0], caps_per_block[0], ordinal);
            let [old_root, new_root] = paired_update_root_offsets(PAIRED_UPDATE_DEPTH);
            for lane in 0..2 {
                assert_eq!(cells.old_entry[lane], slot_cell(&slices[4 + lane], base));
                assert_eq!(
                    cells.new_entry[lane],
                    slot_cell(&slices[4 + lane], base + 2)
                );
                assert_eq!(
                    cells.old_root[lane],
                    slot_cell(&slices[lane], base + old_root)
                );
                assert_eq!(
                    cells.new_root[lane],
                    slot_cell(&slices[lane], base + new_root)
                );
            }
            for level in 0..PAIRED_UPDATE_DEPTH {
                assert_eq!(
                    cells.directions[level],
                    slot_cell(&slices[8], base + level * PAIRED_UPDATE_SLOTS_PER_LEVEL,)
                );
            }
        }
        for (ordinal, cells) in handoff.upper.iter().enumerate() {
            let base = paired_update_base(&layout, layout.bases[1], caps_per_block[1], ordinal);
            for lane in 0..2 {
                assert_eq!(cells.old_entry[lane], slot_cell(&slices[4 + lane], base));
                assert_eq!(
                    cells.new_entry[lane],
                    slot_cell(&slices[4 + lane], base + 2)
                );
            }
            for level in 0..PAIRED_UPDATE_DEPTH {
                let [old_root, new_root] = paired_update_root_offsets(level + 1);
                for lane in 0..2 {
                    assert_eq!(
                        cells.old_roots[level][lane],
                        slot_cell(&slices[lane], base + old_root)
                    );
                    assert_eq!(
                        cells.new_roots[level][lane],
                        slot_cell(&slices[lane], base + new_root)
                    );
                }
                assert_eq!(
                    cells.directions[level],
                    slot_cell(&slices[8], base + level * PAIRED_UPDATE_SLOTS_PER_LEVEL,)
                );
            }
        }

        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));

        // The last real local update is the exact prefix boundary: changing
        // its unconstrained entry is allowed by these copy/ghost pins, proving
        // the overhang range starts at (and not before) class capacity.
        let last_live = paired_update_base(
            &layout,
            layout.bases[0],
            caps_per_block[0],
            class_capacities[0] - 1,
        );
        let mut changed_live_boundary = witness.clone();
        changed_live_boundary[slices[4].start() + last_live] += F128::ONE;
        assert!(
            r1cs.satisfies(&changed_live_boundary),
            "last live update was accidentally ghost-pinned"
        );

        let local_ghost = paired_update_base(
            &layout,
            layout.bases[0],
            caps_per_block[0],
            class_capacities[0],
        );
        // Preserve the SIB/D copy chain while mutating those columns, so every
        // rejection below comes specifically from the canonical-ghost pins.
        for column in 0..9 {
            let mut bad = witness.clone();
            if column < 6 {
                bad[slices[column].start() + local_ghost] += F128::ONE;
            } else {
                for offset in 0..PAIRED_UPDATE_SLOTS_PER_LEVEL {
                    bad[slices[column].start() + local_ghost + offset] += F128::ONE;
                }
            }
            assert!(
                !r1cs.satisfies(&bad),
                "local overhang mutation accepted in committed column {column}"
            );
        }

        let upper_ghost = paired_update_base(
            &layout,
            layout.bases[1],
            caps_per_block[1],
            class_capacities[1],
        );
        let mut bad_upper = witness.clone();
        bad_upper[slices[4].start() + upper_ghost] += F128::ONE;
        assert!(
            !r1cs.satisfies(&bad_upper),
            "upper overhang mutation accepted"
        );

        // Mutating one interior D cell exercises the exact copy-chain reference
        // at the K-tile boundary.
        let mut bad_d_copy = witness;
        bad_d_copy[slices[8].start() + last_live + 2] += F128::ONE;
        assert!(
            !r1cs.satisfies(&bad_d_copy),
            "paired D copy mutation accepted"
        );
    }

    #[test]
    fn paired_handoff_roots_depth8_depth16_and_copy_negative() {
        let local_update = paired_witness(0x1100);
        let upper_update = paired_witness(0x2200);
        let paired = ExactStatePairedRegionData {
            local_updates: vec![local_update.clone()],
            upper_updates: vec![upper_update.clone()],
            local_update_count: 1,
            upper_update_count: 1,
            touched_capacity: 1,
            segment_capacity: 1,
            active_upper_depth: 8,
        };
        let layout = tiled_walk_layout(1, &[PAIRED_UPDATE_STRIDE, PAIRED_UPDATE_STRIDE]);
        assert_eq!(layout.bases, vec![0, PAIRED_UPDATE_STRIDE]);
        let iv = iv_flat_of_tag(TAG_EXSTNOD);
        let local_cols = build_paired_merkle_update_columns(&[local_update], iv, 6);
        let upper_cols = build_paired_merkle_update_columns(&[upper_update], iv, 6);
        let mut cb: Vec<Vec<F128>> = (0..9).map(|_| vec![F128::ZERO; layout.slots]).collect();
        let mut s0: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![F128::ZERO; layout.slots]);
        let mut sout: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![F128::ZERO; layout.slots]);
        place_paired_merkle_updates(
            &mut cb,
            &mut s0,
            &mut sout,
            &local_cols,
            layout.bases[0],
            PAIRED_UPDATE_STRIDE,
        );
        place_paired_merkle_updates(
            &mut cb,
            &mut s0,
            &mut sout,
            &upper_cols,
            layout.bases[1],
            PAIRED_UPDATE_STRIDE,
        );

        let mut fixed = Vec::new();
        let mut specs = Vec::new();
        for family in 0..2 {
            let fixed_base = fixed.len();
            for pattern in paired_merkle_update_fixed_patterns(iv) {
                fixed.push(common_period_pattern(
                    &pattern.table,
                    layout.bases[family],
                    1,
                    layout.block_log,
                ));
            }
            fixed.push(common_period_ones(
                layout.bases[family],
                PAIRED_UPDATE_STRIDE,
                layout.block_log,
            ));
            specs.push(PairedMerkleSpec {
                refs: paired_merkle_update_refs(0, fixed_base),
                region: fixed_base + 11,
            });
        }
        let committed: Vec<&[F128]> = cb.iter().map(Vec::as_slice).collect();
        let native = run_merkle_union_native_with_paired(
            &committed,
            &s0,
            &sout,
            &fixed,
            &[0, 1, 2, 3],
            &[],
            &[],
            &specs,
            layout.w_log,
            b"paired-meta-native-test",
        );
        assert!(!native.pending.is_empty(), "paired native union claims");

        let mut b = FieldR1csBuilder::new();
        let slices: Vec<WitnessSlice> = cb
            .iter()
            .map(|column| alloc_column_slice(&mut b, column, layout.w_log).0)
            .collect();
        let mut channel = FsChannelTrace::new(&mut b, b"paired-meta-native-test");
        let (claims, leg_pins) = discharge_merkle_union_with_paired(
            &mut b,
            &mut channel,
            &fixed,
            &[0, 1, 2, 3],
            &[],
            &[],
            &specs,
            layout.w_log,
            &native,
        );
        assert!(!claims.is_empty(), "paired trace union claims");
        assert!(leg_pins.is_empty(), "paired family has no legacy leg pins");
        let before = b.num_wires();
        pin_paired_consistency_cells(&mut b, &slices, &layout, [0, 64], [1, 1]);
        assert_eq!(b.num_wires() - before, 412, "206 exact rows per update");
        let handoff = paired_exact_state_cells(&slices, &layout, [0, 64], [1, 1], &paired);
        assert_eq!(handoff.local.len(), 1);
        assert_eq!(handoff.upper.len(), 1);

        let local16 = local_cols.update_roots_at_depth(0, 16);
        let upper8 = upper_cols.update_roots_at_depth(0, 8);
        let upper16 = upper_cols.update_roots_at_depth(0, 16);
        for lane in 0..2 {
            assert_eq!(
                handoff.local[0].old_root[lane].eval(b.values()),
                local16.0[lane]
            );
            assert_eq!(
                handoff.local[0].new_root[lane].eval(b.values()),
                local16.1[lane]
            );
            assert_eq!(
                handoff.upper[0].old_roots[7][lane].eval(b.values()),
                upper8.0[lane]
            );
            assert_eq!(
                handoff.upper[0].new_roots[7][lane].eval(b.values()),
                upper8.1[lane]
            );
            assert_eq!(
                handoff.upper[0].old_roots[15][lane].eval(b.values()),
                upper16.0[lane]
            );
            assert_eq!(
                handoff.upper[0].new_roots[15][lane].eval(b.values()),
                upper16.1[lane]
            );
        }

        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
        let mut bad = witness.clone();
        // Upper update level 0: mutate new-even SIB0, which must equal the
        // old-even SIB0 exactly (no Fiat-Shamir mixing).
        bad[slices[6].start() + PAIRED_UPDATE_STRIDE + 2] += F128::ONE;
        assert!(!r1cs.satisfies(&bad), "paired SIB copy mutation accepted");
        let mut bad_bridge = witness;
        bad_bridge[slices[4].start() + 3] += F128::ONE;
        assert!(
            !r1cs.satisfies(&bad_bridge),
            "paired E bridge mutation accepted"
        );
    }

    #[test]
    fn b255_meta_gates_select_disjoint_dyadic_regions() {
        let w_log = 15usize;
        let es = pattern_in_dyadic_region(FixedPattern::new(0, vec![F128::ONE]), 0, 8192, w_log)
            .materialize(1usize << w_log);
        let spine = pattern_in_dyadic_region(
            FixedPattern::new(6, vec![F128::ONE; 64]),
            16384,
            16384,
            w_log,
        )
        .materialize(1usize << w_log);

        assert!(es[..8192].iter().all(|&v| v == F128::ONE));
        assert!(es[8192..].iter().all(|&v| v == F128::ZERO));
        assert!(spine[..16384].iter().all(|&v| v == F128::ZERO));
        assert!(spine[16384..].iter().all(|&v| v == F128::ONE));
    }

    #[test]
    fn b255_spine_exposure_repoint_includes_meta_region_bit() {
        let spec = SpineUnionSpec {
            tree_refs: SourceTreeRefs {
                code: [2, 3],
                kid: [0, 1],
                c: [4, 5, 6, 7],
                even_int: 0,
                odd_int: 1,
                leafodd: 2,
                iv: [3, 4],
            },
            wrap_refs: SpongeLeafRefs {
                in_: [2, 3],
                c: [4, 5, 6, 7],
                odd: 6,
                iv: [7, 8],
            },
            wrap_region: 5,
            kid_meta: [0, 1],
            c_meta: [4, 5],
            cap_log: 0,
            tx_log: 8,
            tree_base: 0,
            block_log_a: 6,
            walk_high_bits: vec![F128::ONE],
        };
        let expo_point: Vec<F128> = (0..spec.expo_wlog())
            .map(|i| F128 {
                lo: (i + 2) as u64,
                hi: 0,
            })
            .collect();
        let kid = spec.repoint_kid(&expo_point);
        let c = spec.repoint_c(&expo_point);

        assert_eq!(kid.len(), 15);
        assert_eq!(c.len(), 15);
        assert_eq!(kid[4], F128::ZERO, "KID low-half coordinate");
        assert_eq!(c[0], F128::ONE, "C odd-window coordinate");
        assert_eq!(kid[5], F128::ZERO, "tree half of compact tx block");
        assert_eq!(c[5], F128::ZERO, "tree half of compact tx block");
        assert_eq!(kid[14], F128::ONE, "upper block-meta region");
        assert_eq!(c[14], F128::ONE, "upper block-meta region");
    }
}

fn flat_mds_entry(e: usize, j: usize) -> F128 {
    noid_ivc_core::deep_chain::flat_mds(true)[e][j]
}

/// `arr[idx]` selected by the witness bits of `idx` (LSB first).
///
/// A highest-variable multilinear fold computes the same
/// `Σ_c eq(bits, c)·arr[c]` value in `N - 1` multiplications.  Building the
/// equality tensor and multiplying every table cell separately costs
/// `2N - 1`; the direct fold also retains class-fixed matrix columns because
/// every level reads both halves before applying its witness bit.
/// `arr.len()` must equal `2^bits.len()`.
#[cfg(test)]
fn select_by_bits(b: &mut FieldR1csBuilder, bits: &[LinExpr], arr: &[LinExpr]) -> LinExpr {
    debug_assert_eq!(arr.len(), 1usize << bits.len(), "select_by_bits arity");
    mle_evaluate_small_trace(b, arr, bits)
}

#[cfg(test)]
mod fold_selection_tests {
    use super::*;

    #[test]
    fn direct_bit_selection_is_exact_and_uses_n_minus_one_rows() {
        let values = (0..8)
            .map(|i| F128 {
                lo: 0xA500 + i,
                hi: 0x5A00 ^ i,
            })
            .collect::<Vec<_>>();
        for index in 0..values.len() {
            let mut b = FieldR1csBuilder::new();
            let table = values
                .iter()
                .map(|&value| LinExpr::from_wire(b.alloc_f128(value)))
                .collect::<Vec<_>>();
            let bits = (0..3)
                .map(|bit| LinExpr::from_wire(b.alloc_bool((index >> bit) & 1 == 1)))
                .collect::<Vec<_>>();
            let before = b.num_wires();
            let selected = select_by_bits(&mut b, &bits, &table);
            assert_eq!(b.num_wires() - before, values.len() - 1);
            assert_eq!(selected.eval(b.values()), values[index]);
            pin_eq(&mut b, &selected, &LinExpr::constant(values[index]));
            let (r1cs, witness) = b.build();
            assert!(r1cs.satisfies(&witness));
        }
    }
}

/// Trace α-power MDS weights `m[j] = Σ_e α^{e+1}·flat(MDS[e][j])`.
pub(crate) fn mds_alpha_weights(
    b: &mut FieldR1csBuilder,
    alpha: &LinExpr,
) -> (Vec<LinExpr>, Vec<LinExpr>) {
    let mut ap = Vec::with_capacity(STATE_SIZE);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..STATE_SIZE {
        acc = mul(b, &acc, alpha);
        ap.push(acc.clone());
    }
    let m = (0..STATE_SIZE)
        .map(|j| {
            let mut a = LinExpr::zero();
            for e in 0..STATE_SIZE {
                a = a.add(&ap[e].scale(flat_mds_entry(e, j)));
            }
            a
        })
        .collect();
    (m, ap)
}

// ---------------------------------------------------------------------------
// Internal claim record (global column index; resolved to a WitnessSlice at the
// end into a RegionPcsClaim).
// ---------------------------------------------------------------------------
#[cfg(test)]
pub(crate) struct Claim {
    pub(crate) slice: usize,
    pub(crate) point: Vec<LinExpr>,
    pub(crate) value: LinExpr,
    pub(crate) native_point: Vec<F128>,
    pub(crate) native_value: F128,
}

// ===========================================================================
// WALK A — the leaf-union native/trace DAG.
// ===========================================================================
/// The spine families' union wiring: the tree rides the source-tree term
/// shape (own patterns, zero LEAFODD), the one-slot wrap the region-gated
/// sponge shape, and the gated tiled exposure re-points into walk A through
/// the class-constant layout below.
#[derive(Clone, Debug)]
pub(crate) struct SpineUnionSpec {
    pub(crate) tree_refs: SourceTreeRefs,
    pub(crate) wrap_refs: SpongeLeafRefs,
    pub(crate) wrap_region: usize,
    /// Walk-A columns the 4 exposure claims re-point into.
    pub(crate) kid_meta: [usize; 2],
    pub(crate) c_meta: [usize; 2],
    /// `log2` of the per-block instance capacity / the tx count.
    pub(crate) cap_log: usize,
    pub(crate) tx_log: usize,
    /// In-block offset of instance 0's tree (a multiple of
    /// `SPINE_TREE_SLOTS << cap_log`).
    pub(crate) tree_base: usize,
    pub(crate) block_log_a: usize,
    /// Constant coordinates above the compact spine region, selecting its
    /// aligned slot inside the larger block-meta walk.
    pub(crate) walk_high_bits: Vec<F128>,
}

impl SpineUnionSpec {
    pub(crate) fn local_log(&self) -> usize {
        (SPINE_TREE_SLOTS / 2).trailing_zeros() as usize
    }
    pub(crate) fn expo_wlog(&self) -> usize {
        self.local_log() + self.cap_log + self.tx_log
    }
    /// The constant high in-block bits selecting the spine-tree run:
    /// `tree_base >> (log2(SPINE_TREE_SLOTS) + cap_log)`, emitted LSB-first
    /// up to `block_log_a`.
    pub(crate) fn base_bits(&self) -> Vec<F128> {
        let start = self.local_log() + 1 + self.cap_log;
        assert_eq!(
            self.tree_base % (1usize << start),
            0,
            "spine tree base alignment"
        );
        let s = self.tree_base >> start;
        (start..self.block_log_a)
            .map(|bit| {
                if (s >> (bit - start)) & 1 == 1 {
                    F128::ONE
                } else {
                    F128::ZERO
                }
            })
            .collect()
    }
    /// Re-point a KID claim: `[rho_local, 0, rho_i, base bits, rho_tx]`.
    pub(crate) fn repoint_kid(&self, expo_point: &[F128]) -> Vec<F128> {
        let (rho_local, rest) = expo_point.split_at(self.local_log());
        let (rho_i, rho_tx) = rest.split_at(self.cap_log);
        let mut pt = rho_local.to_vec();
        pt.push(F128::ZERO);
        pt.extend_from_slice(rho_i);
        pt.extend(self.base_bits());
        pt.extend_from_slice(rho_tx);
        pt.extend_from_slice(&self.walk_high_bits);
        pt
    }
    /// Re-point a C window claim: `[1, rho_local, rho_i, base bits, rho_tx]`.
    pub(crate) fn repoint_c(&self, expo_point: &[F128]) -> Vec<F128> {
        let (rho_local, rest) = expo_point.split_at(self.local_log());
        let (rho_i, rho_tx) = rest.split_at(self.cap_log);
        let mut pt = vec![F128::ONE];
        pt.extend_from_slice(rho_local);
        pt.extend_from_slice(rho_i);
        pt.extend(self.base_bits());
        pt.extend_from_slice(rho_tx);
        pt.extend_from_slice(&self.walk_high_bits);
        pt
    }
    /// The internal-child gate over the tiled exposure domain.
    pub(crate) fn gate_pattern(&self) -> FixedPattern {
        spine_tree_internal_child_pattern()
    }
}

#[cfg(test)]
pub(crate) struct UnionNative {
    pub(crate) sel_proof: ColumnRelationProof,
    pub(crate) walk_proof: DeepChainWalkProof,
    pub(crate) sub_proof: ColumnRelationProof,
    pub(crate) shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pub(crate) pending: Vec<(usize, Vec<F128>, F128)>,
    /// ONE gated tiled exposure over all spine trees + its 4 re-pointed
    /// claims (present iff the spine families ride this union).
    pub(crate) spine_expo_proof: Option<ColumnRelationProof>,
    pub(crate) spine_expo_pending: Vec<(usize, Vec<F128>, F128)>,
}

/// Serializable proof authority for one Walk-A union.  Terminal opening
/// descriptors and shift metadata are intentionally absent: both are derived
/// from the verification-key relation structure during replay.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct WalkAUnionProof {
    pub(crate) selection: ColumnRelationProof,
    pub(crate) walk: DeepChainWalkProof,
    pub(crate) substitution: ColumnRelationProof,
    pub(crate) shifts: Vec<ShiftDischargeProof>,
    pub(crate) spine_exposure: Option<ColumnRelationProof>,
}

/// Serializable Walk-A authority with the deep-chain walk deliberately
/// deferred to its enclosing protocol.  This is the proof object used when
/// several prefix claims are reduced by a caller-owned walk; unlike
/// [`WalkAUnionProof`], it contains no dummy or ignored walk field.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct WalkAUnionWalkDeferredProof {
    pub(crate) selection: ColumnRelationProof,
    pub(crate) substitution: ColumnRelationProof,
    pub(crate) shifts: Vec<ShiftDischargeProof>,
    pub(crate) spine_exposure: Option<ColumnRelationProof>,
}

/// Borrowed view of an embedded standalone Walk-A authority.
#[derive(Clone, Copy)]
pub(crate) struct WalkAUnionWalkDeferredProofRef<'a> {
    pub(crate) selection: &'a ColumnRelationProof,
    pub(crate) substitution: &'a ColumnRelationProof,
    pub(crate) shifts: &'a [ShiftDischargeProof],
    pub(crate) spine_exposure: Option<&'a ColumnRelationProof>,
}

impl WalkAUnionProof {
    pub(crate) fn walk_deferred(&self) -> WalkAUnionWalkDeferredProofRef<'_> {
        WalkAUnionWalkDeferredProofRef {
            selection: &self.selection,
            substitution: &self.substitution,
            shifts: &self.shifts,
            spine_exposure: self.spine_exposure.as_ref(),
        }
    }
}

/// Prover typestate after Walk-A's selection prefix and before the caller's
/// deep-chain walk.  The selection claims are retained privately so the
/// suffix cannot accidentally omit them from the terminal PCS claim set.
pub(crate) struct WalkAUnionProverWalkPrefix {
    selection: ColumnRelationProof,
    pending: Vec<WalkAColumnClaim>,
    walk_group: LaneClaimGroup,
}

impl WalkAUnionProverWalkPrefix {
    pub(crate) fn walk_group(&self) -> &LaneClaimGroup {
        &self.walk_group
    }
}

/// Verifier typestate at the same transcript boundary as
/// [`WalkAUnionProverWalkPrefix`].
pub(crate) struct WalkAUnionVerifierWalkPrefix<'a> {
    proof: WalkAUnionWalkDeferredProofRef<'a>,
    pending: Vec<WalkAColumnClaim>,
    walk_group: LaneClaimGroup,
}

impl WalkAUnionVerifierWalkPrefix<'_> {
    pub(crate) fn walk_group(&self) -> &LaneClaimGroup {
        &self.walk_group
    }
}

/// Verifier-derived terminal opening on a Walk-A committed column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WalkAColumnClaim {
    pub(crate) column: usize,
    pub(crate) point: Vec<F128>,
    pub(crate) value: F128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WalkAUnionVerifyError {
    Shape,
    Selection(RelationError),
    Walk(WalkError),
    Substitution(RelationError),
    Shift(RelationError),
    SpineExposure(RelationError),
}

/// Gate a sponge-shaped family's plain IN reads with its region-ones
/// pattern (native side). The ODD/CARRY-gated carries and the IV patterns
/// carry their own localized gates.
fn gated_sponge_native_terms(
    sr: &SpongeLeafRefs,
    region: usize,
    alpha: F128,
    terms: &mut Vec<RelationTerm>,
) {
    let mut t = sponge_leaf_substitution_terms(sr, alpha);
    for term in t.iter_mut() {
        if !term.factors.iter().any(|f| matches!(f, ColRef::Fixed(_))) {
            term.factors.insert(0, ColRef::Fixed(region));
        }
    }
    terms.extend(t);
}

/// One transcript suffix relocated into Wallet-A. `region` selects every live
/// suffix permutation, `carry` selects all but the first, and `first` selects
/// only the first. The immediately preceding carrier slot stores prefix
/// capacity lanes in A0/A1 while the first live A0/A1 cells contain prefix
/// rate lanes plus that slot's dynamic absorb value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SplitDuplexTailRefs {
    pub(crate) a: [usize; 2],
    pub(crate) c: [usize; STATE_SIZE],
    pub(crate) region: usize,
    pub(crate) carry: usize,
    pub(crate) first: usize,
    pub(crate) consts: [usize; 2],
}

fn split_duplex_tail_native_terms(refs: &SplitDuplexTailRefs, alpha: F128) -> Vec<RelationTerm> {
    let m = mds_weights_pub(alpha);
    let mut terms = Vec::with_capacity(14);
    for lane in 0..2 {
        terms.push(RelationTerm {
            coeff: m[lane],
            factors: vec![ColRef::Fixed(refs.region), ColRef::Committed(refs.a[lane])],
        });
        terms.push(RelationTerm {
            coeff: m[lane],
            factors: vec![ColRef::Fixed(refs.consts[lane])],
        });
        terms.push(RelationTerm {
            coeff: m[lane],
            factors: vec![
                ColRef::Fixed(refs.carry),
                ColRef::CommittedShift(refs.c[lane]),
            ],
        });
    }
    for lane in 2..STATE_SIZE {
        terms.push(RelationTerm {
            coeff: m[lane],
            factors: vec![
                ColRef::Fixed(refs.first),
                ColRef::CommittedShift(refs.a[lane - 2]),
            ],
        });
        terms.push(RelationTerm {
            coeff: m[lane],
            factors: vec![
                ColRef::Fixed(refs.carry),
                ColRef::CommittedShift(refs.c[lane]),
            ],
        });
    }
    terms
}

fn union_native_terms(
    leaf_refs: &[(SpongeLeafRefs, usize)],
    split_tails: &[SplitDuplexTailRefs],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    alpha: F128,
) -> Vec<RelationTerm> {
    let mut terms = Vec::new();
    // The capsule-leaf tile families ride the region-gated sponge shape
    // (CARRY as the duplex selector). Their committed refs coincide, so the
    // claimed-ref set (and claim count) stays family-count independent.
    for (sr, region) in leaf_refs {
        gated_sponge_native_terms(sr, *region, alpha, &mut terms);
    }
    for refs in split_tails {
        terms.extend(split_duplex_tail_native_terms(refs, alpha));
    }
    // Exact-state sponge family: same shape, its own patterns.
    if let Some((sr, region)) = es_sponge {
        gated_sponge_native_terms(sr, *region, alpha, &mut terms);
    }
    // Spine families: the tree is the SOURCE-TREE shape on shared CODE/KID/C
    // columns (LEAFODD ≡ 0); the TAG_TX8X2 wrap is a one-slot sponge shape.
    if let Some(sp) = spine {
        terms.extend(source_tree_substitution_terms(&sp.tree_refs, alpha));
        gated_sponge_native_terms(&sp.wrap_refs, sp.wrap_region, alpha, &mut terms);
    }
    terms
}

/// Prove Walk-A's transcript prefix through carry selection, stopping before
/// any deep-chain walk messages are observed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_walk_a_union_walk_prefix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    meta_c: &[usize; STATE_SIZE],
    committed: &[&[F128]],
    s_out: &[Vec<F128>; STATE_SIZE],
    challenger: &mut Ch,
) -> WalkAUnionProverWalkPrefix {
    let w = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == w));
    assert!(s_out.iter().all(|column| column.len() == w));

    let mut pending = Vec::new();
    let beta = challenger.sample_f128();
    let selection_terms = carry_selection_terms(meta_c, beta);
    let rho = challenger.sample_f128_vec(w_log);
    let internal: Vec<&[F128]> = s_out.iter().map(Vec::as_slice).collect();
    let (selection, selection_point, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &selection_terms,
        &RelationColumns {
            committed,
            internal: &internal,
            fixed,
        },
        challenger,
    );
    let mut output_values = [F128::ZERO; STATE_SIZE];
    for (reference, value) in claimed_refs(&selection_terms)
        .iter()
        .zip(selection.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(WalkAColumnClaim {
                column: *column,
                point: selection_point.clone(),
                value: *value,
            }),
            ColRef::Internal(lane) => output_values[*lane] = *value,
            _ => unreachable!("Walk-A selection claim kind"),
        }
    }

    WalkAUnionProverWalkPrefix {
        selection,
        pending,
        walk_group: LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    }
}

/// Finish Walk-A after a caller-owned deep-chain walk has reduced the prefix
/// group to `terminal`.  The returned authority contains only the prefix and
/// suffix messages; the caller owns serialization of the walk itself.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_walk_a_union_walk_suffix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    leaf_refs: &[(SpongeLeafRefs, usize)],
    split_tails: &[SplitDuplexTailRefs],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    committed: &[&[F128]],
    spine_expo_cols: Option<&[&[F128]; 4]>,
    prefix: WalkAUnionProverWalkPrefix,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
) -> (WalkAUnionWalkDeferredProof, Vec<WalkAColumnClaim>) {
    assert_eq!(
        spine.is_some(),
        spine_expo_cols.is_some(),
        "spine exposure columns"
    );
    let w = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == w));
    let WalkAUnionProverWalkPrefix {
        selection,
        mut pending,
        walk_group: _,
    } = prefix;

    let alpha = challenger.sample_f128();
    let substitution_terms = union_native_terms(leaf_refs, split_tails, es_sponge, spine, alpha);
    let mut target = F128::ZERO;
    let mut alpha_power = F128::ONE;
    for value in terminal.values {
        alpha_power = alpha_power * alpha;
        target += alpha_power * value;
    }
    let (substitution, substitution_point, _) = prove_column_relation(
        target,
        &terminal.point,
        &substitution_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        challenger,
    );

    let mut shifts = Vec::new();
    for (reference, value) in claimed_refs(&substitution_terms)
        .iter()
        .zip(substitution.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(WalkAColumnClaim {
                column: *column,
                point: substitution_point.clone(),
                value: *value,
            }),
            ColRef::CommittedShift(column) | ColRef::CommittedShift2(column) => {
                let shift_log = usize::from(matches!(reference, ColRef::CommittedShift2(_)));
                let (shift, point) = prove_shift_discharge_pow2(
                    committed[*column],
                    &substitution_point,
                    *value,
                    shift_log,
                    challenger,
                );
                pending.push(WalkAColumnClaim {
                    column: *column,
                    point,
                    value: shift.final_value,
                });
                shifts.push(shift);
            }
            _ => unreachable!("Walk-A substitution claim kind"),
        }
    }

    let spine_exposure = if let (Some(spec), Some(columns)) = (spine, spine_expo_cols) {
        let gamma = challenger.sample_f128();
        let terms = spine_tree_exposure_terms([0, 1], [2, 3], 0, gamma);
        let fixed = vec![spec.gate_pattern()];
        let rho = challenger.sample_f128_vec(spec.expo_wlog());
        let (proof, point, _) = prove_column_relation(
            F128::ZERO,
            &rho,
            &terms,
            &RelationColumns {
                committed: columns,
                internal: &[],
                fixed: &fixed,
            },
            challenger,
        );
        for (reference, value) in claimed_refs(&terms).iter().zip(proof.final_values.iter()) {
            match reference {
                ColRef::Committed(local_column) => pending.push(WalkAColumnClaim {
                    column: spec.kid_meta[*local_column],
                    point: spec.repoint_kid(&point),
                    value: *value,
                }),
                ColRef::Window { col, .. } => pending.push(WalkAColumnClaim {
                    column: spec.c_meta[*col - 2],
                    point: spec.repoint_c(&point),
                    value: *value,
                }),
                _ => unreachable!("Walk-A spine exposure claim kind"),
            }
        }
        Some(proof)
    } else {
        None
    };

    (
        WalkAUnionWalkDeferredProof {
            selection,
            substitution,
            shifts,
            spine_exposure,
        },
        pending,
    )
}

/// Verify Walk-A's selection prefix and expose exactly one caller-owned walk
/// group.  No walk proof is accepted by this phase.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_walk_a_union_walk_prefix_with_challenger<'a, Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    meta_c: &[usize; STATE_SIZE],
    proof: WalkAUnionWalkDeferredProofRef<'a>,
    challenger: &mut Ch,
) -> Result<WalkAUnionVerifierWalkPrefix<'a>, WalkAUnionVerifyError> {
    let mut pending = Vec::new();
    let beta = challenger.sample_f128();
    let selection_terms = carry_selection_terms(meta_c, beta);
    let rho = challenger.sample_f128_vec(w_log);
    let selection_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho,
        &selection_terms,
        fixed,
        proof.selection,
        challenger,
    )
    .map_err(WalkAUnionVerifyError::Selection)?;
    let mut output_values = [F128::ZERO; STATE_SIZE];
    for (reference, value) in claimed_refs(&selection_terms)
        .iter()
        .zip(proof.selection.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(WalkAColumnClaim {
                column: *column,
                point: selection_point.clone(),
                value: *value,
            }),
            ColRef::Internal(lane) if *lane < STATE_SIZE => output_values[*lane] = *value,
            _ => return Err(WalkAUnionVerifyError::Shape),
        }
    }

    Ok(WalkAUnionVerifierWalkPrefix {
        proof,
        pending,
        walk_group: LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    })
}

/// Verify the Walk-A suffix against the terminal claim returned by the
/// caller-owned walk and reconstruct every committed-column opening.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_walk_a_union_walk_suffix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    leaf_refs: &[(SpongeLeafRefs, usize)],
    split_tails: &[SplitDuplexTailRefs],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    prefix: WalkAUnionVerifierWalkPrefix<'_>,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
) -> Result<Vec<WalkAColumnClaim>, WalkAUnionVerifyError> {
    let WalkAUnionVerifierWalkPrefix {
        proof,
        mut pending,
        walk_group: _,
    } = prefix;
    let alpha = challenger.sample_f128();
    let substitution_terms = union_native_terms(leaf_refs, split_tails, es_sponge, spine, alpha);
    let mut target = F128::ZERO;
    let mut alpha_power = F128::ONE;
    for value in terminal.values {
        alpha_power = alpha_power * alpha;
        target += alpha_power * value;
    }
    let substitution_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &substitution_terms,
        fixed,
        proof.substitution,
        challenger,
    )
    .map_err(WalkAUnionVerifyError::Substitution)?;

    let mut shift_cursor = 0usize;
    for (reference, value) in claimed_refs(&substitution_terms)
        .iter()
        .zip(proof.substitution.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(WalkAColumnClaim {
                column: *column,
                point: substitution_point.clone(),
                value: *value,
            }),
            ColRef::CommittedShift(column) | ColRef::CommittedShift2(column) => {
                let shift = proof
                    .shifts
                    .get(shift_cursor)
                    .ok_or(WalkAUnionVerifyError::Shape)?;
                shift_cursor += 1;
                let shift_log = usize::from(matches!(reference, ColRef::CommittedShift2(_)));
                let point = verify_shift_discharge_pow2(
                    w_log,
                    &substitution_point,
                    *value,
                    shift_log,
                    shift,
                    challenger,
                )
                .map_err(WalkAUnionVerifyError::Shift)?;
                pending.push(WalkAColumnClaim {
                    column: *column,
                    point,
                    value: shift.final_value,
                });
            }
            _ => return Err(WalkAUnionVerifyError::Shape),
        }
    }
    if shift_cursor != proof.shifts.len() {
        return Err(WalkAUnionVerifyError::Shape);
    }

    match (spine, proof.spine_exposure) {
        (None, None) => {}
        (Some(spec), Some(exposure)) => {
            let gamma = challenger.sample_f128();
            let terms = spine_tree_exposure_terms([0, 1], [2, 3], 0, gamma);
            let fixed = vec![spec.gate_pattern()];
            let rho = challenger.sample_f128_vec(spec.expo_wlog());
            let point = verify_column_relation(
                spec.expo_wlog(),
                F128::ZERO,
                &rho,
                &terms,
                &fixed,
                exposure,
                challenger,
            )
            .map_err(WalkAUnionVerifyError::SpineExposure)?;
            for (reference, value) in claimed_refs(&terms)
                .iter()
                .zip(exposure.final_values.iter())
            {
                match reference {
                    ColRef::Committed(local_column) if *local_column < 2 => {
                        pending.push(WalkAColumnClaim {
                            column: spec.kid_meta[*local_column],
                            point: spec.repoint_kid(&point),
                            value: *value,
                        });
                    }
                    ColRef::Window {
                        col,
                        stride_log: 1,
                        offset: 1,
                    } if (2..4).contains(col) => pending.push(WalkAColumnClaim {
                        column: spec.c_meta[*col - 2],
                        point: spec.repoint_c(&point),
                        value: *value,
                    }),
                    _ => return Err(WalkAUnionVerifyError::Shape),
                }
            }
        }
        _ => return Err(WalkAUnionVerifyError::Shape),
    }
    Ok(pending)
}

/// Prover half of the Walk-A protocol over an already-bound transcript.
///
/// The caller owns domain separation and MUST invoke this only after the
/// enclosing witness commitment has been absorbed.  No challenger is
/// constructed here.  The returned terminal claims are transient and are not
/// part of [`WalkAUnionProof`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_walk_a_union_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    meta_c: &[usize; STATE_SIZE],
    leaf_refs: &[(SpongeLeafRefs, usize)],
    split_tails: &[SplitDuplexTailRefs],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    spine_expo_cols: Option<&[&[F128]; 4]>,
    challenger: &mut Ch,
) -> (WalkAUnionProof, Vec<WalkAColumnClaim>) {
    let w = 1usize << w_log;
    assert!(s0.iter().all(|column| column.len() == w));
    let prefix = prove_walk_a_union_walk_prefix_with_challenger(
        w_log, fixed, meta_c, committed, s_out, challenger,
    );
    let groups = [prefix.walk_group().clone()];
    let (walk, terminal) = prove_deep_chain_walk(s0, &groups, challenger);
    let (deferred, pending) = prove_walk_a_union_walk_suffix_with_challenger(
        w_log,
        fixed,
        leaf_refs,
        split_tails,
        es_sponge,
        spine,
        committed,
        spine_expo_cols,
        prefix,
        &terminal,
        challenger,
    );
    (
        WalkAUnionProof {
            selection: deferred.selection,
            walk,
            substitution: deferred.substitution,
            shifts: deferred.shifts,
            spine_exposure: deferred.spine_exposure,
        },
        pending,
    )
}

/// Verifier half of [`prove_walk_a_union_with_challenger`].  Every terminal
/// PCS descriptor is reconstructed from the fixed relation structure and the
/// verified endpoints; the proof supplies no column, point, or shift metadata.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_walk_a_union_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    meta_c: &[usize; STATE_SIZE],
    leaf_refs: &[(SpongeLeafRefs, usize)],
    split_tails: &[SplitDuplexTailRefs],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    proof: &WalkAUnionProof,
    challenger: &mut Ch,
) -> Result<Vec<WalkAColumnClaim>, WalkAUnionVerifyError> {
    let deferred = proof.walk_deferred();
    let prefix = verify_walk_a_union_walk_prefix_with_challenger(
        w_log, fixed, meta_c, deferred, challenger,
    )?;
    let groups = [prefix.walk_group().clone()];
    let terminal = verify_deep_chain_walk(w_log, &groups, &proof.walk, challenger)
        .map_err(WalkAUnionVerifyError::Walk)?;
    verify_walk_a_union_walk_suffix_with_challenger(
        w_log,
        fixed,
        leaf_refs,
        split_tails,
        es_sponge,
        spine,
        prefix,
        &terminal,
        challenger,
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn run_union_native(
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    fixed: &[FixedPattern],
    meta_c: &[usize; STATE_SIZE],
    leaf_refs: &[(SpongeLeafRefs, usize)],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
    spine_expo_cols: Option<&[&[F128]; 4]>,
    w_log: usize,
    domain: &[u8],
) -> UnionNative {
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let (proof, prover_claims) = prove_walk_a_union_with_challenger(
        w_log,
        fixed,
        meta_c,
        leaf_refs,
        &[],
        es_sponge,
        spine,
        committed,
        s0,
        s_out,
        spine_expo_cols,
        &mut ch_p,
    );
    let verifier_claims = verify_walk_a_union_with_challenger(
        w_log,
        fixed,
        meta_c,
        leaf_refs,
        &[],
        es_sponge,
        spine,
        &proof,
        &mut ch_v,
    )
    .expect("native Walk-A union");
    assert_eq!(prover_claims, verifier_claims, "Walk-A terminal claims");
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "native lockstep");

    let exposure_count = if spine.is_some() { 4 } else { 0 };
    let main_count = prover_claims
        .len()
        .checked_sub(exposure_count)
        .expect("Walk-A exposure claim count");
    let pending = prover_claims[..main_count]
        .iter()
        .map(|claim| (claim.column, claim.point.clone(), claim.value))
        .collect();
    let spine_expo_pending = prover_claims[main_count..]
        .iter()
        .map(|claim| (claim.column, claim.point.clone(), claim.value))
        .collect();

    let shift_layout: Vec<(usize, usize)> = claimed_refs(&union_native_terms(
        leaf_refs,
        &[],
        es_sponge,
        spine,
        F128::ONE,
    ))
    .into_iter()
    .filter_map(|reference| match reference {
        ColRef::CommittedShift(column) => Some((0, column)),
        ColRef::CommittedShift2(column) => Some((1, column)),
        _ => None,
    })
    .collect();
    assert_eq!(shift_layout.len(), proof.shifts.len());
    let shifts = shift_layout
        .into_iter()
        .zip(proof.shifts.iter().cloned())
        .map(|((shift_log, column), shift)| (shift_log, column, shift))
        .collect();

    UnionNative {
        sel_proof: proof.selection,
        walk_proof: proof.walk,
        sub_proof: proof.substitution,
        shifts,
        pending,
        spine_expo_proof: proof.spine_exposure,
        spine_expo_pending,
    }
}

/// One source-tree-shaped trace term block (the spine tree rides this shape
/// with its own pattern indices).
fn tree_trace_terms(m: &[LinExpr], st_refs: &SourceTreeRefs, terms: &mut Vec<RelationTermTrace>) {
    for i in 0..2 {
        let kid = ColRef::Committed(st_refs.kid[i]);
        let c_sh = ColRef::CommittedShift(st_refs.c[i]);
        let code = ColRef::Committed(st_refs.code[i]);
        for factors in [
            vec![ColRef::Fixed(st_refs.even_int), kid],
            vec![ColRef::Fixed(st_refs.odd_int), kid],
            vec![ColRef::Fixed(st_refs.odd_int), c_sh],
            vec![ColRef::Fixed(st_refs.leafodd), code],
        ] {
            terms.push(RelationTermTrace {
                coeff: m[i].clone(),
                factors,
            });
        }
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(st_refs.iv[j - 2])],
        });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![
                ColRef::Fixed(st_refs.odd_int),
                ColRef::CommittedShift(st_refs.c[j]),
            ],
        });
    }
}

/// One region-gated sponge-shaped trace term block (the capsule-leaf tile
/// families, the exact-state sponge tiles and the one-slot spine wrap all
/// ride this shape).
fn gated_sponge_trace_terms(
    m: &[LinExpr],
    sr: &SpongeLeafRefs,
    region: usize,
    terms: &mut Vec<RelationTermTrace>,
) {
    for i in 0..2 {
        terms.push(RelationTermTrace {
            coeff: m[i].clone(),
            factors: vec![ColRef::Fixed(region), ColRef::Committed(sr.in_[i])],
        });
        terms.push(RelationTermTrace {
            coeff: m[i].clone(),
            factors: vec![ColRef::Fixed(sr.odd), ColRef::CommittedShift(sr.c[i])],
        });
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(sr.iv[j - 2])],
        });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(sr.odd), ColRef::CommittedShift(sr.c[j])],
        });
    }
}

/// Trace twin of `union_native_terms` with α-power MDS coefficients.
pub(crate) fn union_trace_terms(
    m: &[LinExpr],
    leaf_refs: &[(SpongeLeafRefs, usize)],
    split_tails: &[SplitDuplexTailRefs],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
) -> Vec<RelationTermTrace> {
    let mut terms = Vec::new();
    for (sr, region) in leaf_refs {
        gated_sponge_trace_terms(m, sr, *region, &mut terms);
    }
    for refs in split_tails {
        for lane in 0..2 {
            terms.push(RelationTermTrace {
                coeff: m[lane].clone(),
                factors: vec![ColRef::Fixed(refs.region), ColRef::Committed(refs.a[lane])],
            });
            terms.push(RelationTermTrace {
                coeff: m[lane].clone(),
                factors: vec![ColRef::Fixed(refs.consts[lane])],
            });
            terms.push(RelationTermTrace {
                coeff: m[lane].clone(),
                factors: vec![
                    ColRef::Fixed(refs.carry),
                    ColRef::CommittedShift(refs.c[lane]),
                ],
            });
        }
        for lane in 2..STATE_SIZE {
            terms.push(RelationTermTrace {
                coeff: m[lane].clone(),
                factors: vec![
                    ColRef::Fixed(refs.first),
                    ColRef::CommittedShift(refs.a[lane - 2]),
                ],
            });
            terms.push(RelationTermTrace {
                coeff: m[lane].clone(),
                factors: vec![
                    ColRef::Fixed(refs.carry),
                    ColRef::CommittedShift(refs.c[lane]),
                ],
            });
        }
    }
    if let Some((sr, region)) = es_sponge {
        gated_sponge_trace_terms(m, sr, *region, &mut terms);
    }
    if let Some(sp) = spine {
        tree_trace_terms(m, &sp.tree_refs, &mut terms);
        gated_sponge_trace_terms(m, &sp.wrap_refs, sp.wrap_region, &mut terms);
    }
    terms
}

pub(crate) fn union_ref_terms(
    leaf_refs: &[(SpongeLeafRefs, usize)],
    split_tails: &[SplitDuplexTailRefs],
    es_sponge: Option<&(SpongeLeafRefs, usize)>,
    spine: Option<&SpineUnionSpec>,
) -> Vec<RelationTerm> {
    union_native_terms(leaf_refs, split_tails, es_sponge, spine, F128::ONE)
}

// ===========================================================================
// WALK B — the merkle-union.
// ===========================================================================
fn union_merkle_refs(fixed_base: usize) -> MerkleFamilyRefs {
    MerkleFamilyRefs {
        e: [4, 5],
        sib: [6, 7],
        d: 8,
        c: std::array::from_fn(|i| i),
        even: fixed_base,
        evenns: fixed_base + 1,
        evenstart: fixed_base + 2,
        odd: fixed_base + 3,
        oddns: fixed_base + 4,
        oddstart: fixed_base + 5,
        iv: [fixed_base + 6, fixed_base + 7],
    }
}

/// One Merkle-authentication leg placed in the shared walk-B meta domain.
#[cfg(test)]
pub(crate) struct MerkleLeg {
    family: MerklePathFamily,
    refs: MerkleFamilyRefs,
    region: usize,
    committed_roots: Vec<[F128; 2]>,
    entry_wires: Vec<[LinExpr; 2]>,
    /// TRANSCRIPT-BINDING: the FS-observed root wire per path (== the wire
    /// absorbed into the channel BEFORE the query draw). The walk-recomputed root
    /// cell is `pin_eq`'d to this wire, so the authenticated root is the
    /// transcript-seeded root — a prover cannot authenticate against a root chosen
    /// after the query positions are known.
    root_wires: Vec<[LinExpr; 2]>,
    /// The slot base of each path in the shared walk-B domain. Single tx: just
    /// `meta_base + path*stride`; the plural discharge tiles paths across tx
    /// blocks (`tx*per_tx_block_B + meta_base + q*stride`), so the entry/root
    /// claim slots read from here rather than a contiguous `meta_base + p*stride`.
    path_slots: Vec<usize>,
    /// The chain-replay-recomputed root per path (from `build_merkle_path_columns`),
    /// asserted == `committed_roots` (native consistency of the path replay).
    /// Accumulated across txs in the plural discharge.
    recomputed_roots: Vec<[F128; 2]>,
}

/// One fixed-capacity paired-update family (local or upper) sharing meta-B's
/// nine committed columns. `region` gates the otherwise-unconditional ghost
/// carry base in the substitution relation.
#[derive(Clone, Copy)]
#[cfg(test)]
struct PairedMerkleSpec {
    refs: PairedMerkleUpdateRefs,
    region: usize,
}

/// The existing union zero-check: every 2-perm leg's direction booleanity,
/// plus every ff leg's two CR-chain lanes weighted by λ and λ². Feed-forward
/// D booleanity is deliberately NOT mixed into this relation: wallet-B's D
/// committed slice is allocated as exact boolean R1CS rows.
#[cfg(test)]
fn union_zero_terms(
    legs: &[MerkleLeg],
    ff_specs: &[FfLegSpec],
    paired_specs: &[PairedMerkleSpec],
    lambda: F128,
) -> Vec<RelationTerm> {
    let mut t = Vec::new();
    for leg in legs {
        t.extend(merkle_booleanity_terms(&leg.refs));
    }
    for spec in ff_specs {
        t.extend(ff_merkle_chain_terms(&spec.refs, lambda));
    }
    for spec in paired_specs {
        t.extend(paired_merkle_update_consistency_terms(&spec.refs, lambda));
    }
    t
}

#[cfg(test)]
fn union_zero_terms_trace(
    b: &mut FieldR1csBuilder,
    legs: &[MerkleLeg],
    ff_specs: &[FfLegSpec],
    paired_specs: &[PairedMerkleSpec],
    lambda: &LinExpr,
) -> Vec<RelationTermTrace> {
    let mut t: Vec<RelationTermTrace> = Vec::new();
    for leg in legs {
        for term in merkle_booleanity_terms(&leg.refs) {
            t.push(RelationTermTrace {
                coeff: LinExpr::constant(term.coeff),
                factors: term.factors.clone(),
            });
        }
    }
    // λ-power lane weights (the trace mirror of `ff_merkle_chain_terms`).
    let lp1 = lambda.clone();
    let lp2 = mul(b, lambda, lambda);
    for spec in ff_specs {
        let refs = &spec.refs;
        for (i, w) in [lp1.clone(), lp2.clone()].into_iter().enumerate() {
            let nodens = ColRef::Fixed(refs.nodens);
            let cr = ColRef::Committed(refs.cr[i]);
            let cr_sh = ColRef::CommittedShift(refs.cr[i]);
            let sib_sh = ColRef::CommittedShift(refs.sib[i]);
            let d_sh = ColRef::CommittedShift(refs.d);
            let c_sh = ColRef::CommittedShift(refs.c[i]);
            for factors in [
                vec![nodens, cr],
                vec![nodens, c_sh],
                vec![nodens, cr_sh],
                vec![nodens, d_sh, cr_sh],
                vec![nodens, d_sh, sib_sh],
            ] {
                t.push(RelationTermTrace {
                    coeff: w.clone(),
                    factors,
                });
            }
        }
    }
    let mut paired_weights = vec![LinExpr::constant(F128::ONE)];
    for _ in 1..6 {
        let next = mul(b, paired_weights.last().expect("paired weight"), lambda);
        paired_weights.push(next);
    }
    for spec in paired_specs {
        let refs = &spec.refs;
        let equations = [
            (
                vec![
                    ColRef::Fixed(refs.old_even),
                    ColRef::Committed(refs.d),
                    ColRef::Committed(refs.d),
                ],
                vec![ColRef::Fixed(refs.old_even), ColRef::Committed(refs.d)],
            ),
            (
                vec![ColRef::Fixed(refs.bridge), ColRef::Committed(refs.e[0])],
                vec![
                    ColRef::Fixed(refs.bridge),
                    ColRef::CommittedShift2(refs.c[0]),
                ],
            ),
            (
                vec![ColRef::Fixed(refs.bridge), ColRef::Committed(refs.e[1])],
                vec![
                    ColRef::Fixed(refs.bridge),
                    ColRef::CommittedShift2(refs.c[1]),
                ],
            ),
            (
                vec![
                    ColRef::Fixed(refs.copy_step),
                    ColRef::Committed(refs.sib[0]),
                ],
                vec![
                    ColRef::Fixed(refs.copy_step),
                    ColRef::CommittedShift(refs.sib[0]),
                ],
            ),
            (
                vec![
                    ColRef::Fixed(refs.copy_step),
                    ColRef::Committed(refs.sib[1]),
                ],
                vec![
                    ColRef::Fixed(refs.copy_step),
                    ColRef::CommittedShift(refs.sib[1]),
                ],
            ),
            (
                vec![ColRef::Fixed(refs.copy_step), ColRef::Committed(refs.d)],
                vec![
                    ColRef::Fixed(refs.copy_step),
                    ColRef::CommittedShift(refs.d),
                ],
            ),
        ];
        for (weight, (left, right)) in paired_weights.iter().zip(equations) {
            for factors in [left, right] {
                t.push(RelationTermTrace {
                    coeff: weight.clone(),
                    factors,
                });
            }
        }
    }
    t
}

#[cfg(test)]
fn union_sub_terms_native(
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    paired_specs: &[PairedMerkleSpec],
    alpha: F128,
) -> Vec<RelationTerm> {
    let m = mds_weights_pub(alpha);
    let mut terms = Vec::new();
    // ff legs: the region-gated ghost-carry base (every lane), then the
    // NODE-gated wiring (which cancels the base at node slots and feeds the
    // CR/SIB mix — see `ff_merkle_substitution_terms`).
    for spec in ff_specs {
        for j in 0..STATE_SIZE {
            terms.push(RelationTerm {
                coeff: m[j],
                factors: vec![
                    ColRef::Fixed(spec.region),
                    ColRef::CommittedShift(spec.refs.c[j]),
                ],
            });
        }
        terms.extend(ff_merkle_substitution_terms(&spec.refs, alpha));
    }
    for leg in legs {
        let mut t = merkle_substitution_terms(&leg.refs, alpha);
        for term in t.iter_mut() {
            if !term.factors.iter().any(|f| matches!(f, ColRef::Fixed(_))) {
                term.factors.insert(0, ColRef::Fixed(leg.region));
            }
        }
        terms.extend(t);
    }
    for spec in paired_specs {
        let mut paired = paired_merkle_update_substitution_terms(&spec.refs, alpha);
        for term in &mut paired {
            if !term
                .factors
                .iter()
                .any(|factor| matches!(factor, ColRef::Fixed(_)))
            {
                term.factors.insert(0, ColRef::Fixed(spec.region));
            }
        }
        terms.extend(paired);
    }
    terms
}

/// Trace-coefficient twin of `paired_merkle_update_substitution_terms`.
/// SIB/D copies and E bridges belong to the post-commit consistency relation,
/// so the substitution relation intentionally does not duplicate them.
#[cfg(test)]
fn paired_substitution_terms_trace(
    m: &[LinExpr],
    spec: &PairedMerkleSpec,
) -> Vec<RelationTermTrace> {
    assert_eq!(m.len(), STATE_SIZE, "paired MDS weight count");
    let refs = &spec.refs;
    let mut terms = Vec::new();
    let mut push = |coeff: LinExpr, mut factors: Vec<ColRef>| {
        if !factors
            .iter()
            .any(|factor| matches!(factor, ColRef::Fixed(_)))
        {
            factors.insert(0, ColRef::Fixed(spec.region));
        }
        terms.push(RelationTermTrace { coeff, factors });
    };

    for lane in 0..2 {
        let c_shift = ColRef::CommittedShift(refs.c[lane]);
        let e = ColRef::Committed(refs.e[lane]);
        let e_shift = ColRef::CommittedShift(refs.e[lane]);
        let e_shift2 = ColRef::CommittedShift2(refs.e[lane]);
        let sib = ColRef::Committed(refs.sib[lane]);
        let sib_shift = ColRef::CommittedShift(refs.sib[lane]);
        let d = ColRef::Committed(refs.d);
        let d_shift = ColRef::CommittedShift(refs.d);
        for factors in [
            vec![c_shift],
            vec![ColRef::Fixed(refs.even), c_shift],
            vec![ColRef::Fixed(refs.even_start), e],
            vec![ColRef::Fixed(refs.even_start), d, e],
            vec![ColRef::Fixed(refs.even_nonstart), e_shift],
            vec![ColRef::Fixed(refs.even_nonstart), d, e_shift],
            vec![ColRef::Fixed(refs.even), d, sib],
            vec![ColRef::Fixed(refs.odd), sib_shift],
            vec![ColRef::Fixed(refs.odd), d_shift, sib_shift],
            vec![ColRef::Fixed(refs.odd_start), d_shift, e_shift],
            vec![ColRef::Fixed(refs.odd_nonstart), d_shift, e_shift2],
        ] {
            push(m[lane].clone(), factors);
        }
    }
    for lane in 2..STATE_SIZE {
        let c_shift = ColRef::CommittedShift(refs.c[lane]);
        for factors in [
            vec![c_shift],
            vec![ColRef::Fixed(refs.even), c_shift],
            vec![ColRef::Fixed(refs.iv[lane - 2])],
        ] {
            push(m[lane].clone(), factors);
        }
    }
    terms
}

#[cfg(test)]
fn union_sub_terms_trace(
    b: &mut FieldR1csBuilder,
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    paired_specs: &[PairedMerkleSpec],
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let (m, ap) = mds_alpha_weights(b, alpha);
    let mut terms: Vec<RelationTermTrace> = Vec::new();

    for spec in ff_specs {
        let refs = &spec.refs;
        for j in 0..STATE_SIZE {
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![
                    ColRef::Fixed(spec.region),
                    ColRef::CommittedShift(refs.c[j]),
                ],
            });
        }
        let node = ColRef::Fixed(refs.node);
        for i in 0..2 {
            let cr = ColRef::Committed(refs.cr[i]);
            let sib = ColRef::Committed(refs.sib[i]);
            let d = ColRef::Committed(refs.d);
            let c_sh = ColRef::CommittedShift(refs.c[i]);
            for factors in [
                vec![node, c_sh],
                vec![node, cr],
                vec![node, d, cr],
                vec![node, d, sib],
            ] {
                terms.push(RelationTermTrace {
                    coeff: m[i].clone(),
                    factors,
                });
            }
            let j = 2 + i;
            let c_sh_j = ColRef::CommittedShift(refs.c[j]);
            for factors in [
                vec![node, c_sh_j],
                vec![node, sib],
                vec![node, d, cr],
                vec![node, d, sib],
                vec![ColRef::Fixed(refs.iv[i])],
            ] {
                terms.push(RelationTermTrace {
                    coeff: m[j].clone(),
                    factors,
                });
            }
        }
    }
    for leg in legs {
        let refs = &leg.refs;
        let region = ColRef::Fixed(leg.region);
        for i in 0..2 {
            let c_sh = ColRef::CommittedShift(refs.c[i]);
            let c_sh2 = ColRef::CommittedShift2(refs.c[i]);
            let sib = ColRef::Committed(refs.sib[i]);
            let sib_sh = ColRef::CommittedShift(refs.sib[i]);
            let e_col = ColRef::Committed(refs.e[i]);
            let e_sh = ColRef::CommittedShift(refs.e[i]);
            let d_col = ColRef::Committed(refs.d);
            let d_sh = ColRef::CommittedShift(refs.d);
            for factors in [
                vec![region, c_sh],
                vec![ColRef::Fixed(refs.evenstart), c_sh],
                vec![ColRef::Fixed(refs.evenns), d_col, c_sh],
                vec![ColRef::Fixed(refs.even), d_col, sib],
                vec![ColRef::Fixed(refs.evenstart), e_col],
                vec![ColRef::Fixed(refs.evenstart), d_col, e_col],
                vec![ColRef::Fixed(refs.odd), sib_sh],
                vec![ColRef::Fixed(refs.odd), d_sh, sib_sh],
                vec![ColRef::Fixed(refs.oddns), d_sh, c_sh2],
                vec![ColRef::Fixed(refs.oddstart), d_sh, e_sh],
            ] {
                terms.push(RelationTermTrace {
                    coeff: m[i].clone(),
                    factors,
                });
            }
        }
        for j in 2..STATE_SIZE {
            let c_sh = ColRef::CommittedShift(refs.c[j]);
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![region, c_sh],
            });
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(refs.even), c_sh],
            });
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(refs.iv[j - 2])],
            });
        }
    }
    for spec in paired_specs {
        terms.extend(paired_substitution_terms_trace(&m, spec));
    }
    (terms, ap)
}

#[cfg(test)]
pub(crate) struct MerkleUnionNative {
    pub(crate) zero_proof: ColumnRelationProof,
    pub(crate) zero_shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pub(crate) sel_proof: ColumnRelationProof,
    pub(crate) walk_proof: DeepChainWalkProof,
    pub(crate) sub_proof: ColumnRelationProof,
    pub(crate) shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pub(crate) pending: Vec<(usize, Vec<F128>, F128)>,
}

/// Canonical relation family inside the shared nine-column Walk-B table.
///
/// The committed-column map is fixed for every variant:
/// `C0..C3,E0,E1,SIB0,SIB1,D`.  Only fixed-pattern indices vary.  A region
/// sidecar constructs these values from its ordered family list; they are not
/// serialized as prover authority.
#[derive(Clone, Copy, Debug)]
pub(crate) enum MerkleProtocolFamily {
    FeedForward {
        refs: FfMerkleFamilyRefs,
        region: usize,
    },
    TwoPermutation {
        refs: MerkleFamilyRefs,
        region: usize,
    },
    PairedUpdate {
        refs: PairedMerkleUpdateRefs,
        region: usize,
    },
}

impl MerkleProtocolFamily {
    pub(crate) fn feed_forward(fixed_base: usize) -> Self {
        Self::FeedForward {
            refs: FfMerkleFamilyRefs {
                cr: [4, 5],
                sib: [6, 7],
                d: 8,
                c: std::array::from_fn(|lane| lane),
                node: fixed_base,
                nodens: fixed_base + 1,
                start: fixed_base + 2,
                iv: [fixed_base + 3, fixed_base + 4],
            },
            region: fixed_base + 5,
        }
    }

    pub(crate) fn two_permutation(fixed_base: usize) -> Self {
        Self::TwoPermutation {
            refs: union_merkle_refs(fixed_base),
            region: fixed_base + 8,
        }
    }

    pub(crate) fn paired_update(fixed_base: usize) -> Self {
        Self::PairedUpdate {
            refs: paired_merkle_update_refs(0, fixed_base),
            region: fixed_base + 11,
        }
    }
}

/// Serializable Walk-B proof authority.  In particular this type contains no
/// `pending` opening list: terminal column descriptors are reconstructed from
/// the verifier's fixed family list while replaying the proof.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct MerkleUnionProof {
    pub(crate) zero: ColumnRelationProof,
    pub(crate) zero_shifts: Vec<ShiftDischargeProof>,
    pub(crate) selection: ColumnRelationProof,
    pub(crate) walk: DeepChainWalkProof,
    pub(crate) substitution: ColumnRelationProof,
    pub(crate) shifts: Vec<ShiftDischargeProof>,
}

/// Serializable Walk-B authority whose deep-chain walk is owned by an
/// enclosing protocol.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct MerkleUnionWalkDeferredProof {
    pub(crate) zero: ColumnRelationProof,
    pub(crate) zero_shifts: Vec<ShiftDischargeProof>,
    pub(crate) selection: ColumnRelationProof,
    pub(crate) substitution: ColumnRelationProof,
    pub(crate) shifts: Vec<ShiftDischargeProof>,
}

#[derive(Clone, Copy)]
pub(crate) struct MerkleUnionWalkDeferredProofRef<'a> {
    pub(crate) zero: &'a ColumnRelationProof,
    pub(crate) zero_shifts: &'a [ShiftDischargeProof],
    pub(crate) selection: &'a ColumnRelationProof,
    pub(crate) substitution: &'a ColumnRelationProof,
    pub(crate) shifts: &'a [ShiftDischargeProof],
}

impl MerkleUnionProof {
    pub(crate) fn walk_deferred(&self) -> MerkleUnionWalkDeferredProofRef<'_> {
        MerkleUnionWalkDeferredProofRef {
            zero: &self.zero,
            zero_shifts: &self.zero_shifts,
            selection: &self.selection,
            substitution: &self.substitution,
            shifts: &self.shifts,
        }
    }
}

pub(crate) struct MerkleUnionProverWalkPrefix {
    zero: ColumnRelationProof,
    zero_shifts: Vec<ShiftDischargeProof>,
    selection: ColumnRelationProof,
    pending: Vec<MerkleColumnClaim>,
    walk_group: LaneClaimGroup,
}

impl MerkleUnionProverWalkPrefix {
    pub(crate) fn walk_group(&self) -> &LaneClaimGroup {
        &self.walk_group
    }
}

pub(crate) struct MerkleUnionVerifierWalkPrefix<'a> {
    proof: MerkleUnionWalkDeferredProofRef<'a>,
    pending: Vec<MerkleColumnClaim>,
    walk_group: LaneClaimGroup,
}

impl MerkleUnionVerifierWalkPrefix<'_> {
    pub(crate) fn walk_group(&self) -> &LaneClaimGroup {
        &self.walk_group
    }
}

/// One verifier-derived terminal claim on a shared Walk-B column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MerkleColumnClaim {
    pub(crate) column: usize,
    pub(crate) point: Vec<F128>,
    pub(crate) value: F128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MerkleUnionVerifyError {
    Shape,
    Zero(RelationError),
    Selection(RelationError),
    Walk(WalkError),
    Substitution(RelationError),
    Shift(RelationError),
}

pub(crate) fn merkle_protocol_zero_terms(
    families: &[MerkleProtocolFamily],
    lambda: F128,
) -> Vec<RelationTerm> {
    let mut terms = Vec::new();
    // Transcript compatibility is category-ordered, independently of the
    // physical fixed-pattern group order.
    for family in families {
        if let MerkleProtocolFamily::TwoPermutation { refs, .. } = family {
            terms.extend(merkle_booleanity_terms(refs));
        }
    }
    for family in families {
        if let MerkleProtocolFamily::FeedForward { refs, .. } = family {
            terms.extend(ff_merkle_chain_terms(refs, lambda));
        }
    }
    for family in families {
        if let MerkleProtocolFamily::PairedUpdate { refs, .. } = family {
            terms.extend(paired_merkle_update_consistency_terms(refs, lambda));
        }
    }
    terms
}

pub(crate) fn merkle_protocol_substitution_terms(
    families: &[MerkleProtocolFamily],
    alpha: F128,
) -> Vec<RelationTerm> {
    let m = mds_weights_pub(alpha);
    let mut terms = Vec::new();
    for family in families {
        if let MerkleProtocolFamily::FeedForward { refs, region } = family {
            for lane in 0..STATE_SIZE {
                terms.push(RelationTerm {
                    coeff: m[lane],
                    factors: vec![ColRef::Fixed(*region), ColRef::CommittedShift(refs.c[lane])],
                });
            }
            terms.extend(ff_merkle_substitution_terms(refs, alpha));
        }
    }
    for family in families {
        if let MerkleProtocolFamily::TwoPermutation { refs, region } = family {
            let mut family_terms = merkle_substitution_terms(refs, alpha);
            for term in &mut family_terms {
                if !term
                    .factors
                    .iter()
                    .any(|factor| matches!(factor, ColRef::Fixed(_)))
                {
                    term.factors.insert(0, ColRef::Fixed(*region));
                }
            }
            terms.extend(family_terms);
        }
    }
    for family in families {
        if let MerkleProtocolFamily::PairedUpdate { refs, region } = family {
            let mut family_terms = paired_merkle_update_substitution_terms(refs, alpha);
            for term in &mut family_terms {
                if !term
                    .factors
                    .iter()
                    .any(|factor| matches!(factor, ColRef::Fixed(_)))
                {
                    term.factors.insert(0, ColRef::Fixed(*region));
                }
            }
            terms.extend(family_terms);
        }
    }
    terms
}

fn prove_merkle_claim_pass<Ch: Challenger>(
    committed: &[&[F128]],
    references: &[ColRef],
    values: &[F128],
    point: &[F128],
    challenger: &mut Ch,
) -> (
    [F128; STATE_SIZE],
    Vec<MerkleColumnClaim>,
    Vec<ShiftDischargeProof>,
) {
    assert_eq!(references.len(), values.len(), "Walk-B claim shape");
    let mut internal = [F128::ZERO; STATE_SIZE];
    let mut pending = Vec::new();
    let mut shifts = Vec::new();
    for (reference, value) in references.iter().zip(values) {
        match reference {
            ColRef::Committed(column) => pending.push(MerkleColumnClaim {
                column: *column,
                point: point.to_vec(),
                value: *value,
            }),
            ColRef::Internal(lane) => internal[*lane] = *value,
            ColRef::CommittedShift(column) => {
                let (shift, shifted_point) =
                    prove_shift_discharge(committed[*column], point, *value, challenger);
                pending.push(MerkleColumnClaim {
                    column: *column,
                    point: shifted_point,
                    value: shift.final_value,
                });
                shifts.push(shift);
            }
            ColRef::CommittedShift2(column) => {
                let (shift, shifted_point) =
                    prove_shift_discharge_pow2(committed[*column], point, *value, 1, challenger);
                pending.push(MerkleColumnClaim {
                    column: *column,
                    point: shifted_point,
                    value: shift.final_value,
                });
                shifts.push(shift);
            }
            _ => unreachable!("Walk-B terminal claim kind"),
        }
    }
    (internal, pending, shifts)
}

fn verify_merkle_claim_pass<Ch: Challenger>(
    w_log: usize,
    references: &[ColRef],
    values: &[F128],
    point: &[F128],
    proof_shifts: &[ShiftDischargeProof],
    challenger: &mut Ch,
) -> Result<([F128; STATE_SIZE], Vec<MerkleColumnClaim>), MerkleUnionVerifyError> {
    if references.len() != values.len() {
        return Err(MerkleUnionVerifyError::Shape);
    }
    let mut internal = [F128::ZERO; STATE_SIZE];
    let mut pending = Vec::new();
    let mut shift_cursor = 0usize;
    for (reference, value) in references.iter().zip(values) {
        match reference {
            ColRef::Committed(column) => pending.push(MerkleColumnClaim {
                column: *column,
                point: point.to_vec(),
                value: *value,
            }),
            ColRef::Internal(lane) if *lane < STATE_SIZE => internal[*lane] = *value,
            ColRef::CommittedShift(column) | ColRef::CommittedShift2(column) => {
                let shift = proof_shifts
                    .get(shift_cursor)
                    .ok_or(MerkleUnionVerifyError::Shape)?;
                shift_cursor += 1;
                let shift_log = usize::from(matches!(reference, ColRef::CommittedShift2(_)));
                let shifted_point = if shift_log == 0 {
                    verify_shift_discharge(w_log, point, *value, shift, challenger)
                } else {
                    verify_shift_discharge_pow2(w_log, point, *value, 1, shift, challenger)
                }
                .map_err(MerkleUnionVerifyError::Shift)?;
                pending.push(MerkleColumnClaim {
                    column: *column,
                    point: shifted_point,
                    value: shift.final_value,
                });
            }
            _ => return Err(MerkleUnionVerifyError::Shape),
        }
    }
    if shift_cursor != proof_shifts.len() {
        return Err(MerkleUnionVerifyError::Shape);
    }
    Ok((internal, pending))
}

/// Prove Walk-B's zero and carry-selection prefix, stopping immediately
/// before the deep-chain walk.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_merkle_union_walk_prefix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    families: &[MerkleProtocolFamily],
    committed: &[&[F128]],
    s_out: &[Vec<F128>; STATE_SIZE],
    challenger: &mut Ch,
) -> MerkleUnionProverWalkPrefix {
    let w = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == w));
    assert!(s_out.iter().all(|column| column.len() == w));

    let lambda = challenger.sample_f128();
    let zero_terms = merkle_protocol_zero_terms(families, lambda);
    let zero_rho = challenger.sample_f128_vec(w_log);
    let (zero, zero_point, _) = prove_column_relation(
        F128::ZERO,
        &zero_rho,
        &zero_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        challenger,
    );
    let (_, mut pending, zero_shifts) = prove_merkle_claim_pass(
        committed,
        &claimed_refs(&zero_terms),
        &zero.final_values,
        &zero_point,
        challenger,
    );

    let beta = challenger.sample_f128();
    let selection_terms = carry_selection_terms(cb_c, beta);
    let selection_rho = challenger.sample_f128_vec(w_log);
    let internal_columns: Vec<&[F128]> = s_out.iter().map(Vec::as_slice).collect();
    let (selection, selection_point, _) = prove_column_relation(
        F128::ZERO,
        &selection_rho,
        &selection_terms,
        &RelationColumns {
            committed,
            internal: &internal_columns,
            fixed,
        },
        challenger,
    );
    let (output_values, selection_pending, selection_shifts) = prove_merkle_claim_pass(
        committed,
        &claimed_refs(&selection_terms),
        &selection.final_values,
        &selection_point,
        challenger,
    );
    assert!(selection_shifts.is_empty(), "Walk-B selection shifts");
    pending.extend(selection_pending);

    MerkleUnionProverWalkPrefix {
        zero,
        zero_shifts,
        selection,
        pending,
        walk_group: LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    }
}

/// Finish Walk-B after a caller-owned walk and return a proof authority which
/// contains no embedded walk.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_merkle_union_walk_suffix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    families: &[MerkleProtocolFamily],
    committed: &[&[F128]],
    prefix: MerkleUnionProverWalkPrefix,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
) -> (MerkleUnionWalkDeferredProof, Vec<MerkleColumnClaim>) {
    let w = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == w));
    let MerkleUnionProverWalkPrefix {
        zero,
        zero_shifts,
        selection,
        mut pending,
        walk_group: _,
    } = prefix;

    let alpha = challenger.sample_f128();
    let substitution_terms = merkle_protocol_substitution_terms(families, alpha);
    let mut target = F128::ZERO;
    let mut alpha_power = F128::ONE;
    for value in terminal.values {
        alpha_power = alpha_power * alpha;
        target += alpha_power * value;
    }
    let (substitution, substitution_point, _) = prove_column_relation(
        target,
        &terminal.point,
        &substitution_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        challenger,
    );
    let (_, substitution_pending, shifts) = prove_merkle_claim_pass(
        committed,
        &claimed_refs(&substitution_terms),
        &substitution.final_values,
        &substitution_point,
        challenger,
    );
    pending.extend(substitution_pending);

    (
        MerkleUnionWalkDeferredProof {
            zero,
            zero_shifts,
            selection,
            substitution,
            shifts,
        },
        pending,
    )
}

/// Verify Walk-B through carry selection and expose its caller-owned walk
/// group without accepting any walk proof in this phase.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_merkle_union_walk_prefix_with_challenger<'a, Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    families: &[MerkleProtocolFamily],
    proof: MerkleUnionWalkDeferredProofRef<'a>,
    challenger: &mut Ch,
) -> Result<MerkleUnionVerifierWalkPrefix<'a>, MerkleUnionVerifyError> {
    let lambda = challenger.sample_f128();
    let zero_terms = merkle_protocol_zero_terms(families, lambda);
    let zero_rho = challenger.sample_f128_vec(w_log);
    let zero_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &zero_rho,
        &zero_terms,
        fixed,
        proof.zero,
        challenger,
    )
    .map_err(MerkleUnionVerifyError::Zero)?;
    let (_, mut pending) = verify_merkle_claim_pass(
        w_log,
        &claimed_refs(&zero_terms),
        &proof.zero.final_values,
        &zero_point,
        proof.zero_shifts,
        challenger,
    )?;

    let beta = challenger.sample_f128();
    let selection_terms = carry_selection_terms(cb_c, beta);
    let selection_rho = challenger.sample_f128_vec(w_log);
    let selection_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &selection_rho,
        &selection_terms,
        fixed,
        proof.selection,
        challenger,
    )
    .map_err(MerkleUnionVerifyError::Selection)?;
    let (output_values, selection_pending) = verify_merkle_claim_pass(
        w_log,
        &claimed_refs(&selection_terms),
        &proof.selection.final_values,
        &selection_point,
        &[],
        challenger,
    )?;
    pending.extend(selection_pending);

    Ok(MerkleUnionVerifierWalkPrefix {
        proof,
        pending,
        walk_group: LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    })
}

/// Verify the Walk-B substitution suffix against an externally verified walk
/// terminal and reconstruct the terminal PCS claims.
pub(crate) fn verify_merkle_union_walk_suffix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    families: &[MerkleProtocolFamily],
    prefix: MerkleUnionVerifierWalkPrefix<'_>,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
) -> Result<Vec<MerkleColumnClaim>, MerkleUnionVerifyError> {
    let MerkleUnionVerifierWalkPrefix {
        proof,
        mut pending,
        walk_group: _,
    } = prefix;
    let alpha = challenger.sample_f128();
    let substitution_terms = merkle_protocol_substitution_terms(families, alpha);
    let mut target = F128::ZERO;
    let mut alpha_power = F128::ONE;
    for value in terminal.values {
        alpha_power = alpha_power * alpha;
        target += alpha_power * value;
    }
    let substitution_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &substitution_terms,
        fixed,
        proof.substitution,
        challenger,
    )
    .map_err(MerkleUnionVerifyError::Substitution)?;
    let (_, substitution_pending) = verify_merkle_claim_pass(
        w_log,
        &claimed_refs(&substitution_terms),
        &proof.substitution.final_values,
        &substitution_point,
        proof.shifts,
        challenger,
    )?;
    pending.extend(substitution_pending);
    Ok(pending)
}

/// Prove the complete Walk-B union on a challenger already bound to the outer
/// witness commitment and statement.  This function intentionally has no
/// challenger-constructing shortcut.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_merkle_union_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    families: &[MerkleProtocolFamily],
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    challenger: &mut Ch,
) -> (MerkleUnionProof, Vec<MerkleColumnClaim>) {
    let w = 1usize << w_log;
    assert!(s0.iter().all(|column| column.len() == w));
    let prefix = prove_merkle_union_walk_prefix_with_challenger(
        w_log, fixed, cb_c, families, committed, s_out, challenger,
    );
    let groups = [prefix.walk_group().clone()];
    let (walk, terminal) = prove_deep_chain_walk(s0, &groups, challenger);
    let (deferred, pending) = prove_merkle_union_walk_suffix_with_challenger(
        w_log, fixed, families, committed, prefix, &terminal, challenger,
    );
    (
        MerkleUnionProof {
            zero: deferred.zero,
            zero_shifts: deferred.zero_shifts,
            selection: deferred.selection,
            walk,
            substitution: deferred.substitution,
            shifts: deferred.shifts,
        },
        pending,
    )
}

/// Verify [`prove_merkle_union_with_challenger`] and reconstruct all terminal
/// committed-column claims from the fixed family layout.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_merkle_union_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    families: &[MerkleProtocolFamily],
    proof: &MerkleUnionProof,
    challenger: &mut Ch,
) -> Result<Vec<MerkleColumnClaim>, MerkleUnionVerifyError> {
    let deferred = proof.walk_deferred();
    let prefix = verify_merkle_union_walk_prefix_with_challenger(
        w_log, fixed, cb_c, families, deferred, challenger,
    )?;
    let groups = [prefix.walk_group().clone()];
    let terminal = verify_deep_chain_walk(w_log, &groups, &proof.walk, challenger)
        .map_err(MerkleUnionVerifyError::Walk)?;
    verify_merkle_union_walk_suffix_with_challenger(
        w_log, fixed, families, prefix, &terminal, challenger,
    )
}

/// Place a prefix of paired-update columns into the shared nine-column meta-B
/// layout `C0..C3,E0,E1,SIB0,SIB1,D`.
fn place_paired_merkle_updates(
    cb: &mut [Vec<F128>],
    s0b: &mut [Vec<F128>; STATE_SIZE],
    soutb: &mut [Vec<F128>; STATE_SIZE],
    cols: &super::paired_merkle_update::PairedMerkleUpdateColumns,
    base: usize,
    n_slots: usize,
) {
    let range = base..base + n_slots;
    for lane in 0..STATE_SIZE {
        cb[lane][range.clone()].copy_from_slice(&cols.c[lane][..n_slots]);
        s0b[lane][range.clone()].copy_from_slice(&cols.s0[lane][..n_slots]);
        soutb[lane][range.clone()].copy_from_slice(&cols.s_out[lane][..n_slots]);
    }
    for lane in 0..2 {
        cb[4 + lane][range.clone()].copy_from_slice(&cols.e[lane][..n_slots]);
        cb[6 + lane][range.clone()].copy_from_slice(&cols.sib[lane][..n_slots]);
    }
    cb[8][range].copy_from_slice(&cols.d[..n_slots]);
}

fn place_merkle(
    cb: &mut [Vec<F128>],
    s0b: &mut [Vec<F128>; STATE_SIZE],
    soutb: &mut [Vec<F128>; STATE_SIZE],
    cols: &MerklePathColumns,
    col_base: usize,
    meta_base: usize,
    n_slots: usize,
) {
    let rng = meta_base..meta_base + n_slots;
    for j in 0..2 {
        cb[col_base + j][rng.clone()].copy_from_slice(&cols.e[j][0..n_slots]);
        cb[col_base + 2 + j][rng.clone()].copy_from_slice(&cols.sib[j][0..n_slots]);
    }
    cb[col_base + 4][rng.clone()].copy_from_slice(&cols.d[0..n_slots]);
    for j in 0..STATE_SIZE {
        cb[j][rng.clone()].copy_from_slice(&cols.c[j][0..n_slots]);
        s0b[j][rng.clone()].copy_from_slice(&cols.s0[j][0..n_slots]);
        soutb[j][rng.clone()].copy_from_slice(&cols.s_out[j][0..n_slots]);
    }
}

/// Discharge one committed/shift claim set (native side): push Committed
/// claims to `pending`, run shift discharges into `shifts`.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn native_claim_pass(
    committed: &[&[F128]],
    w_log: usize,
    refs: &[ColRef],
    values: &[F128],
    point: &[F128],
    ch_p: &mut FsLaneChallenger,
    ch_v: &mut FsLaneChallenger,
    pending: &mut Vec<(usize, Vec<F128>, F128)>,
    shifts: &mut Vec<(usize, usize, ShiftDischargeProof)>,
) -> [F128; STATE_SIZE] {
    let mut internal = [F128::ZERO; STATE_SIZE];
    for (r, v) in refs.iter().zip(values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, point.to_vec(), *v)),
            ColRef::Internal(j) => internal[*j] = *v,
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], point, *v, ch_p);
                let pt = verify_shift_discharge(w_log, point, *v, &pr, ch_v).expect("shift");
                pending.push((*c, pt, pr.final_value));
                shifts.push((0usize, *c, pr));
            }
            ColRef::CommittedShift2(c) => {
                let (pr, _) = prove_shift_discharge_pow2(committed[*c], point, *v, 1, ch_p);
                let pt =
                    verify_shift_discharge_pow2(w_log, point, *v, 1, &pr, ch_v).expect("shift2");
                pending.push((*c, pt, pr.final_value));
                shifts.push((1usize, *c, pr));
            }
            _ => unreachable!(),
        }
    }
    internal
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn run_merkle_union_native(
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    w_log: usize,
    domain: &[u8],
) -> MerkleUnionNative {
    run_merkle_union_native_with_paired(
        committed,
        s0,
        s_out,
        fixed,
        cb_c,
        ff_specs,
        legs,
        &[],
        w_log,
        domain,
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn run_merkle_union_native_with_paired(
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    paired_specs: &[PairedMerkleSpec],
    w_log: usize,
    domain: &[u8],
) -> MerkleUnionNative {
    let internal: Vec<&[F128]> = s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();
    let mut zero_shifts = Vec::new();

    // Zero-check: 2-perm booleanity + λ-weighted ff CR-chain.
    let lambda = ch_p.sample_f128();
    assert_eq!(lambda, ch_v.sample_f128());
    let zero_terms = union_zero_terms(legs, ff_specs, paired_specs, lambda);
    let rho_b = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (zero_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho_b,
        &zero_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        &mut ch_p,
    );
    let zero_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho_b,
        &zero_terms,
        fixed,
        &zero_proof,
        &mut ch_v,
    )
    .expect("native merkle-union zero-check");
    native_claim_pass(
        committed,
        w_log,
        &claimed_refs(&zero_terms),
        &zero_proof.final_values,
        &zero_point,
        &mut ch_p,
        &mut ch_v,
        &mut pending,
        &mut zero_shifts,
    );

    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(cb_c, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &sel_terms,
        &RelationColumns {
            committed,
            internal: &internal,
            fixed,
        },
        &mut ch_p,
    );
    let sel_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho,
        &sel_terms,
        fixed,
        &sel_proof,
        &mut ch_v,
    )
    .expect("native merkle-union selection");
    let mut sel_shifts = Vec::new();
    let gv = native_claim_pass(
        committed,
        w_log,
        &claimed_refs(&sel_terms),
        &sel_proof.final_values,
        &sel_point,
        &mut ch_p,
        &mut ch_v,
        &mut pending,
        &mut sel_shifts,
    );
    assert!(sel_shifts.is_empty(), "carry selection claims no shifts");

    let groups = vec![LaneClaimGroup {
        point: sel_point,
        values: gv,
    }];
    let (walk_proof, _) = prove_deep_chain_walk(s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native merkle walk");

    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = union_sub_terms_native(ff_specs, legs, paired_specs, alpha);
    let mut target = F128::ZERO;
    let mut p = F128::ONE;
    for e in 0..STATE_SIZE {
        p = p * alpha;
        target += p * terminal.values[e];
    }
    let (sub_proof, _, _) = prove_column_relation(
        target,
        &terminal.point,
        &sub_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        &mut ch_p,
    );
    let sub_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &sub_terms,
        fixed,
        &sub_proof,
        &mut ch_v,
    )
    .expect("native merkle-union substitution");
    let mut shifts = Vec::new();
    native_claim_pass(
        committed,
        w_log,
        &claimed_refs(&sub_terms),
        &sub_proof.final_values,
        &sub_point,
        &mut ch_p,
        &mut ch_v,
        &mut pending,
        &mut shifts,
    );
    assert_eq!(
        ch_p.sample_f128(),
        ch_v.sample_f128(),
        "native merkle-union lockstep"
    );
    MerkleUnionNative {
        zero_proof,
        zero_shifts,
        sel_proof,
        walk_proof,
        sub_proof,
        shifts,
        pending,
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn discharge_merkle_union_with_paired(
    b: &mut FieldR1csBuilder,
    mut ch: &mut impl FsChannelOps,
    fixed: &[FixedPattern],
    cb_c: &[usize; STATE_SIZE],
    ff_specs: &[FfLegSpec],
    legs: &[MerkleLeg],
    paired_specs: &[PairedMerkleSpec],
    w_log: usize,
    native: &MerkleUnionNative,
) -> (Vec<Claim>, Vec<(usize, usize, LinExpr)>) {
    let mut out: Vec<Claim> = Vec::new();
    // Stage 2: the per-cell reads/pins (leg entries, leg roots) resolve to
    // pin_eq of the wire to the committed cell -- R1CS rows, not link-IO
    // claims. Every column is opened by this walk's zero-check / selection /
    // substitution (random point), so the cells are bound.
    let mut cell_pins: Vec<(usize, usize, LinExpr)> = Vec::new();
    let np = &native.pending;
    let mut cur = 0usize;
    let zero = LinExpr::zero();

    // Trace-side claim pass mirroring `native_claim_pass`.
    macro_rules! trace_claim_pass {
        ($refs:expr, $values:expr, $point:expr, $shifts:expr, $shift_cursor:ident, $gv:expr) => {
            for (r, v) in $refs.iter().zip($values.iter()) {
                match r {
                    ColRef::Committed(_) => {
                        let (col, npt, nval) = &np[cur];
                        cur += 1;
                        out.push(Claim {
                            slice: *col,
                            point: $point.clone(),
                            value: v.clone(),
                            native_point: npt.clone(),
                            native_value: *nval,
                        });
                    }
                    ColRef::Internal(j) => $gv[*j] = v.clone(),
                    ColRef::CommittedShift(_) | ColRef::CommittedShift2(_) => {
                        let (shift_log, _col, ns) = &$shifts[$shift_cursor];
                        $shift_cursor += 1;
                        let se = ShiftDischargeProofTrace::alloc(b, ns, w_log);
                        let pt = verify_shift_discharge_trace(
                            b, &mut ch, w_log, &$point, v, *shift_log, &se,
                        );
                        let (col, npt, nval) = &np[cur];
                        cur += 1;
                        out.push(Claim {
                            slice: *col,
                            point: pt,
                            value: se.final_value.clone(),
                            native_point: npt.clone(),
                            native_value: *nval,
                        });
                    }
                    _ => unreachable!(),
                }
            }
        };
    }

    // Zero-check: 2-perm booleanity + λ-weighted ff CR-chain (see
    // `union_zero_terms` for the λ soundness argument).
    let lambda = ch.sample_f128(b);
    let zero_ref = union_zero_terms(legs, ff_specs, paired_specs, F128::ONE);
    let n_zero = claimed_refs(&zero_ref).len();
    let rho_b = ch.sample_f128_vec(b, w_log);
    let zero_e = ColumnRelationProofTrace::alloc(b, &native.zero_proof, w_log, n_zero);
    let zero_terms_e = union_zero_terms_trace(b, legs, ff_specs, paired_specs, &lambda);
    let zero_point = verify_column_relation_trace(
        b,
        &mut ch,
        w_log,
        &zero,
        &rho_b,
        &zero_terms_e,
        fixed,
        &zero_e,
    );
    let mut zero_shift_cursor = 0usize;
    let mut unused_gv: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    trace_claim_pass!(
        claimed_refs(&zero_ref),
        zero_e.final_values,
        zero_point,
        native.zero_shifts,
        zero_shift_cursor,
        unused_gv
    );
    assert_eq!(
        zero_shift_cursor,
        native.zero_shifts.len(),
        "zero-check shifts consumed"
    );

    let beta = ch.sample_f128(b);
    let mut bp = LinExpr::constant(F128::ONE);
    let mut sel_terms: Vec<RelationTermTrace> = Vec::new();
    for j in 0..STATE_SIZE {
        bp = mul(b, &bp, &beta);
        sel_terms.push(RelationTermTrace {
            coeff: bp.clone(),
            factors: vec![ColRef::Committed(cb_c[j])],
        });
        sel_terms.push(RelationTermTrace {
            coeff: bp.clone(),
            factors: vec![ColRef::Internal(j)],
        });
    }
    let rho = ch.sample_f128_vec(b, w_log);
    let sel_e = ColumnRelationProofTrace::alloc(b, &native.sel_proof, w_log, 2 * STATE_SIZE);
    let sel_point =
        verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho, &sel_terms, fixed, &sel_e);
    let sel_claimed = claimed_refs(&carry_selection_terms(cb_c, F128::ONE));
    let mut gv: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    let mut sel_shift_cursor = 0usize;
    let no_shifts: Vec<(usize, usize, ShiftDischargeProof)> = Vec::new();
    trace_claim_pass!(
        sel_claimed,
        sel_e.final_values,
        sel_point,
        no_shifts,
        sel_shift_cursor,
        gv
    );
    assert_eq!(sel_shift_cursor, 0, "carry selection claims no shifts");

    let groups_e = vec![LaneClaimGroupTrace {
        point: sel_point,
        values: gv,
    }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    let alpha = ch.sample_f128(b);
    let (sub_terms, ap) = union_sub_terms_trace(b, ff_specs, legs, paired_specs, &alpha);
    let ref_terms = union_sub_terms_native(ff_specs, legs, paired_specs, F128::ONE);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e = ColumnRelationProofTrace::alloc(
        b,
        &native.sub_proof,
        w_log,
        claimed_refs(&ref_terms).len(),
    );
    let sub_point = verify_column_relation_trace(
        b,
        &mut ch,
        w_log,
        &target,
        &terminal.point,
        &sub_terms,
        fixed,
        &sub_e,
    );
    let mut shift_cursor = 0usize;
    let mut unused_gv2: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    trace_claim_pass!(
        claimed_refs(&ref_terms),
        sub_e.final_values,
        sub_point,
        native.shifts,
        shift_cursor,
        unused_gv2
    );
    assert_eq!(
        shift_cursor,
        native.shifts.len(),
        "merkle-union shifts consumed"
    );
    assert_eq!(cur, np.len(), "merkle-union pending lockstep");

    // Per-leg entry pins (E == shared leaf digest wire) + recomputed-root pins
    // (C0/C1 at the root slot == the FS-OBSERVED root wire) -- both pin_eq, no
    // IO claims (flat in tx count). The ff legs' entry/direction/root pins are
    // collected by the caller (their root is a composite LinExpr).
    for leg in legs {
        let root_slot_local = 2 * (leg.family.depth - 1) + 1;
        for path in 0..leg.path_slots.len() {
            let entry_wire = leg.entry_wires[path].clone();
            let entry_slot = leg.path_slots[path];
            for lane in 0..2 {
                cell_pins.push((leg.refs.e[lane], entry_slot, entry_wire[lane].clone()));
            }
            // TRANSCRIPT-BINDING (flat): the recomputed-root column cell at
            // `root_slot` is `pin_eq`'d to the FS-OBSERVED root wire
            // (absorbed into the channel BEFORE the query draw). The C column
            // is opened at a random point by the Merkle walk, so the cell is
            // bound; the pin is an R1CS ROW, not an IO claim.
            let root_slot = leg.path_slots[path] + root_slot_local;
            for lane in 0..2 {
                assert_eq!(
                    leg.recomputed_roots[path][lane],
                    leg.committed_roots[path][lane]
                );
                cell_pins.push((
                    leg.refs.c[lane],
                    root_slot,
                    leg.root_wires[path][lane].clone(),
                ));
            }
        }
    }

    (out, cell_pins)
}

// ===========================================================================
// Duplex-channel union shared by the selected recursive region protocols.
//
// Each transcript channel is one Poseidon2b permutation chain. Channels with a
// common period tile one domain and share carry-selection, deep-chain and
// substitution discharges. Squeezed challenges are bound to committed carry
// cells and absorbed data are bound to the caller's proof wires.
//
// Columns (all length P): A0=0, A1=1, C0=2..C3=5.
//
// `stage1_duplex_union_tests` gates the generic mechanism in isolation.
// ===========================================================================
#[derive(Clone)]
pub(crate) struct DuplexUnion {
    pub(crate) committed: [Vec<F128>; 6],
    pub(crate) s0: [Vec<F128>; STATE_SIZE],
    pub(crate) s_out: [Vec<F128>; STATE_SIZE],
    pub(crate) fixed: Vec<FixedPattern>,
    pub(crate) refs: DuplexFamilyRefs,
    pub(crate) layout: DuplexLayout,
    pub(crate) w_log: usize,
    pub(crate) block_log: usize,
    /// One squeezed-challenge stream per real tx (schedule order).
    pub(crate) challenges: Vec<Vec<F128>>,
    /// REGION-2 recording blocks (caller order): each recorded discharge
    /// transcript's compiled layout and its dyadic domain offset. Empty for
    /// a single-region union.
    pub(crate) rec_blocks: Vec<(DuplexLayout, usize)>,
    /// Per-recording gated pattern-set refs (same committed columns,
    /// pattern indices after the region-1 set).
    pub(crate) rec_refs: Vec<DuplexFamilyRefs>,
    /// Per-recording squeezed challenges (native, schedule order).
    pub(crate) rec_challenges: Vec<Vec<F128>>,
}

/// Tile `data.len()` transactions' duplex channels into ONE walk-C domain at a
/// common per-tx block period. `data[t]` is tx `t`'s absorbed-data stream (flat,
/// length `layout.n_data`). The tile count is padded to a power of two with
/// CANONICAL GHOST channel blocks (IV-seeded, zero-data channels) — NOT
/// `perm([0;4])` ghost slots: the duplex substitution's leading carry term is
/// ungated, so every block must be a valid IV-seeded chain (the START pattern
/// cancels the cross-block carry in char 2, re-seeding each block).
#[cfg(test)]
pub(crate) fn build_duplex_union(
    layout: &DuplexLayout,
    iv_flat: [F128; 2],
    data: &[Vec<F128>],
) -> DuplexUnion {
    let per_tx = layout.slots.len().next_power_of_two();
    let block_log = per_tx.trailing_zeros() as usize;
    let k = data.len();
    let w_log = (k.max(1) * per_tx).next_power_of_two().trailing_zeros() as usize;
    let p = 1usize << w_log;
    let n_blocks = p / per_tx;

    let mut committed: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut challenges = Vec::with_capacity(k);
    let zero_data = vec![F128::ZERO; layout.n_data];

    for blk in 0..n_blocks {
        let d = data.get(blk).unwrap_or(&zero_data);
        let cols = build_duplex_columns(layout, iv_flat, d, block_log);
        let off = blk * per_tx;
        for j in 0..2 {
            committed[j][off..off + per_tx].copy_from_slice(&cols.a[j]);
        }
        for j in 0..STATE_SIZE {
            committed[2 + j][off..off + per_tx].copy_from_slice(&cols.c[j]);
            s0[j][off..off + per_tx].copy_from_slice(&cols.s0[j]);
            s_out[j][off..off + per_tx].copy_from_slice(&cols.s_out[j]);
        }
        if blk < k {
            challenges.push(cols.challenges);
        }
    }
    let fixed = duplex_fixed_patterns(layout, iv_flat, block_log);
    let refs = duplex_family_refs(0, 0);
    DuplexUnion {
        committed,
        s0,
        s_out,
        fixed,
        refs,
        layout: layout.clone(),
        w_log,
        block_log,
        challenges,
        rec_blocks: Vec::new(),
        rec_refs: Vec::new(),
        rec_challenges: Vec::new(),
    }
}

/// A recorded LANECHAL discharge transcript riding walk C as a REGION-2
/// block: its compiled schedule, capacity IV and absorbed witness data
/// (flat). Recordings are per-BLOCK objects (one per walk discharge), so
/// region 2 is transaction-count FLAT.
pub(crate) struct RecordingSpec<'a> {
    pub(crate) layout: DuplexLayout,
    pub(crate) iv_flat: [F128; 2],
    pub(crate) data: &'a [F128],
}

/// Two-region walk-C domain. REGION 1 (`[0, 2^r1_log)`) tiles the K
/// transactions' channels at the per-tx block period exactly like
/// [`build_duplex_union`] (real blocks + canonical zero-data ghost
/// channels); REGION 2 appends each RECORDED walk-discharge transcript
/// ONCE as its own dyadic sub-block, packed in descending size order (so
/// every offset is self-aligned to its block size). The slots between and
/// after the regions are pure carry-chain ghosts.
///
/// Pattern discipline: every set's START/ABS/CONST patterns carry a
/// [`FixedPattern::gated`] hi-gate pinning its dyadic region, so no set's
/// constants fire in another's slots (regions of DIFFERENT periods share
/// one walk soundly). The substitution's leading carry term stays ungated:
/// every slot is a valid chain permutation — schedule slots, in-block
/// ghost tails, the inter-region gap and the domain tail all carry the
/// previous state forward, and each block start re-seeds its capacity IV
/// through its own gated START/const patterns (char-2: `(1+START)·C`
/// cancels the incoming carry).
#[cfg(test)]
pub(crate) fn build_duplex_union_with_recordings(
    layout: &DuplexLayout,
    iv_flat: [F128; 2],
    data: &[Vec<F128>],
    recordings: &[RecordingSpec<'_>],
) -> DuplexUnion {
    assert!(
        !recordings.is_empty(),
        "recording-free unions use build_duplex_union"
    );
    let per_tx = layout.slots.len().next_power_of_two();
    let block_log = per_tx.trailing_zeros() as usize;
    let k = data.len();
    let r1_len = (k.max(1) * per_tx).next_power_of_two();
    let r1_log = r1_len.trailing_zeros() as usize;

    let packing = pack_recordings(r1_len, recordings);
    let offsets = &packing.offsets;
    let w_log = packing.w_log;
    let p = 1usize << w_log;

    let mut committed: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut challenges = Vec::with_capacity(k);
    let zero_data = vec![F128::ZERO; layout.n_data];

    // Region 1: real channel blocks + zero-data ghost channels to the
    // region boundary (each block IV-re-seeded by the gated START).
    for blk in 0..r1_len / per_tx {
        let d = data.get(blk).unwrap_or(&zero_data);
        let cols = build_duplex_columns(layout, iv_flat, d, block_log);
        let off = blk * per_tx;
        for j in 0..2 {
            committed[j][off..off + per_tx].copy_from_slice(&cols.a[j]);
        }
        for j in 0..STATE_SIZE {
            committed[2 + j][off..off + per_tx].copy_from_slice(&cols.c[j]);
            s0[j][off..off + per_tx].copy_from_slice(&cols.s0[j]);
            s_out[j][off..off + per_tx].copy_from_slice(&cols.s_out[j]);
        }
        if blk < k {
            challenges.push(cols.challenges);
        }
    }

    let rec_challenges = fill_recording_region(
        &mut committed,
        &mut s0,
        &mut s_out,
        r1_len,
        &packing,
        recordings,
    );

    // Gated pattern sets: region 1 pinned to its dyadic prefix, each
    // recording to its own block. Both region boundaries are strictly
    // below the domain top (region 2 is non-empty), so no gate is empty.
    let mut fixed: Vec<FixedPattern> = duplex_fixed_patterns(layout, iv_flat, block_log)
        .into_iter()
        .map(|pat| pat.gated(r1_log, rec_hi_bits(0, r1_log, w_log)))
        .collect();
    let rec_refs = gate_recording_patterns(&mut fixed, &packing, recordings);

    DuplexUnion {
        committed,
        s0,
        s_out,
        fixed,
        refs: duplex_family_refs(0, 0),
        layout: layout.clone(),
        w_log,
        block_log,
        challenges,
        rec_blocks: recordings
            .iter()
            .enumerate()
            .map(|(r, rec)| (rec.layout.clone(), offsets[r]))
            .collect(),
        rec_refs,
        rec_challenges,
    }
}

/// Canonical dyadic packing of a recordings-only union: blocks packed from
/// offset ZERO in descending size order (self-aligned), offsets returned in
/// CALLER order plus the covering domain log.  Shared by the column builder
/// and the slices-only verification-key constructor so both derive one
/// identical geometry.
pub(crate) fn pack_recording_only_blocks(layouts: &[&DuplexLayout]) -> (Vec<usize>, usize) {
    assert!(!layouts.is_empty(), "at least one recording block");
    let sizes: Vec<usize> = layouts
        .iter()
        .map(|layout| layout.slots.len().max(1).next_power_of_two())
        .collect();
    let mut order: Vec<usize> = (0..layouts.len()).collect();
    order.sort_by_key(|&rec| std::cmp::Reverse(sizes[rec]));
    let mut offsets = vec![0usize; layouts.len()];
    let mut cursor = 0usize;
    for &rec in &order {
        debug_assert_eq!(cursor % sizes[rec], 0, "dyadic packing alignment");
        offsets[rec] = cursor;
        cursor += sizes[rec];
    }
    let w_log = cursor.next_power_of_two().trailing_zeros() as usize;
    (offsets, w_log)
}

/// Recordings-ONLY duplex union: no region-1 channel tiles, just each
/// recorded transcript as its own gated dyadic block, packed from offset
/// zero in descending size order (every offset stays self-aligned).  Slots
/// between and after the blocks are pure carry-chain ghosts; every block
/// start re-seeds its capacity IV through its own gated START/const
/// patterns (char-2 cancellation of the incoming carry, including the
/// cyclic wrap into slot 0).  Set 0 (the first recording in CALLER order)
/// provides the primary `refs`; the remaining sets ride `rec_refs` exactly
/// like the region-2 blocks of the legacy mixed recordings builder.
pub(crate) fn build_recording_only_duplex_union(recordings: &[RecordingSpec<'_>]) -> DuplexUnion {
    assert!(!recordings.is_empty(), "at least one recording block");
    let layouts: Vec<&DuplexLayout> = recordings.iter().map(|rec| &rec.layout).collect();
    let (offsets, w_log) = pack_recording_only_blocks(&layouts);
    let sizes: Vec<usize> = recordings
        .iter()
        .map(|rec| rec.layout.slots.len().max(1).next_power_of_two())
        .collect();
    let mut order: Vec<usize> = (0..recordings.len()).collect();
    order.sort_by_key(|&rec| std::cmp::Reverse(sizes[rec]));
    let p = 1usize << w_log;
    for (&size, &offset) in sizes.iter().zip(&offsets) {
        assert!(
            size < p || (recordings.len() == 1 && offset == 0),
            "recording block gate must not be empty"
        );
    }

    let mut committed: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut rec_challenges: Vec<Vec<F128>> = vec![Vec::new(); recordings.len()];
    let mut carry = [F128::ZERO; STATE_SIZE];
    let mut filled = 0usize;
    let fill_carry = |committed: &mut [Vec<F128>; 6],
                      s0: &mut [Vec<F128>; STATE_SIZE],
                      s_out: &mut [Vec<F128>; STATE_SIZE],
                      carry: &mut [F128; STATE_SIZE],
                      from: usize,
                      to: usize| {
        for slot in from..to {
            let (g0, gout) = noid_ivc_core::deep_chain::source_tree::run_perm(*carry);
            for lane in 0..STATE_SIZE {
                s0[lane][slot] = g0[lane];
                s_out[lane][slot] = gout[lane];
                committed[2 + lane][slot] = gout[lane];
            }
            *carry = gout;
        }
    };
    for &rec_index in &order {
        fill_carry(
            &mut committed,
            &mut s0,
            &mut s_out,
            &mut carry,
            filled,
            offsets[rec_index],
        );
        let rec = &recordings[rec_index];
        let size = sizes[rec_index];
        let s_log = size.trailing_zeros() as usize;
        let cols = build_duplex_columns(&rec.layout, rec.iv_flat, rec.data, s_log);
        let offset = offsets[rec_index];
        for lane in 0..2 {
            committed[lane][offset..offset + size].copy_from_slice(&cols.a[lane]);
        }
        for lane in 0..STATE_SIZE {
            committed[2 + lane][offset..offset + size].copy_from_slice(&cols.c[lane]);
            s0[lane][offset..offset + size].copy_from_slice(&cols.s0[lane]);
            s_out[lane][offset..offset + size].copy_from_slice(&cols.s_out[lane]);
        }
        rec_challenges[rec_index] = cols.challenges;
        carry = std::array::from_fn(|lane| committed[2 + lane][offset + size - 1]);
        filled = offset + size;
    }
    fill_carry(&mut committed, &mut s0, &mut s_out, &mut carry, filled, p);

    let mut fixed: Vec<FixedPattern> = Vec::new();
    let mut set_refs = Vec::with_capacity(recordings.len());
    for (rec_index, rec) in recordings.iter().enumerate() {
        let s_log = sizes[rec_index].trailing_zeros() as usize;
        let base = fixed.len();
        for pattern in duplex_fixed_patterns(&rec.layout, rec.iv_flat, s_log) {
            // A single block spanning the whole domain needs no gate (an
            // empty hi-gate is the ungated pattern).
            if s_log == w_log {
                fixed.push(pattern);
            } else {
                fixed.push(pattern.gated(s_log, rec_hi_bits(offsets[rec_index], s_log, w_log)));
            }
        }
        set_refs.push(duplex_family_refs(0, base));
    }
    let refs = set_refs[0];
    let rec_refs = set_refs[1..].to_vec();
    let primary_challenges = rec_challenges[0].clone();
    DuplexUnion {
        committed,
        s0,
        s_out,
        fixed,
        refs,
        layout: recordings[0].layout.clone(),
        w_log,
        block_log: sizes[0].trailing_zeros() as usize,
        challenges: vec![primary_challenges],
        rec_blocks: recordings
            .iter()
            .enumerate()
            .map(|(rec_index, rec)| (rec.layout.clone(), offsets[rec_index]))
            .collect(),
        rec_refs,
        rec_challenges,
    }
}

/// Descending-size dyadic packing of recording blocks after a region-1
/// prefix of `r1_len` slots: each recording gets a self-aligned dyadic
/// block, `w_log` covers everything.
#[cfg(test)]
pub(crate) struct RecordingPacking {
    pub(crate) order: Vec<usize>,
    pub(crate) sizes: Vec<usize>,
    pub(crate) offsets: Vec<usize>,
    pub(crate) w_log: usize,
}

#[cfg(test)]
pub(crate) fn pack_recordings(r1_len: usize, recordings: &[RecordingSpec<'_>]) -> RecordingPacking {
    let sizes: Vec<usize> = recordings
        .iter()
        .map(|r| r.layout.slots.len().max(1).next_power_of_two())
        .collect();
    let s_max = *sizes.iter().max().expect("non-empty recordings");
    let mut order: Vec<usize> = (0..recordings.len()).collect();
    order.sort_by_key(|&r| std::cmp::Reverse(sizes[r]));
    let r2_base = r1_len.max(s_max);
    let mut offsets = vec![0usize; recordings.len()];
    let mut cur = r2_base;
    for &r in &order {
        debug_assert_eq!(cur % sizes[r], 0, "dyadic packing alignment");
        offsets[r] = cur;
        cur += sizes[r];
    }
    let w_log = cur.next_power_of_two().trailing_zeros() as usize;
    RecordingPacking {
        order,
        sizes,
        offsets,
        w_log,
    }
}

/// High-coordinate gate bits of the dyadic block at `off` (block log
/// `from`) inside a `w_log` domain.
pub(crate) fn rec_hi_bits(off: usize, from: usize, w_log: usize) -> Vec<bool> {
    (from..w_log).map(|c| (off >> c) & 1 == 1).collect()
}

/// Fill the recording blocks + the carry-ghost gap/tail slots of a
/// recording-bearing union domain (columns pre-sized to `2^packing.w_log`;
/// region 1 already filled up to `r1_len`). Returns each recording's
/// squeezed challenges.
#[cfg(test)]
pub(crate) fn fill_recording_region(
    committed: &mut [Vec<F128>; 6],
    s0: &mut [Vec<F128>; STATE_SIZE],
    s_out: &mut [Vec<F128>; STATE_SIZE],
    r1_len: usize,
    packing: &RecordingPacking,
    recordings: &[RecordingSpec<'_>],
) -> Vec<Vec<F128>> {
    let p = 1usize << packing.w_log;
    let mut rec_challenges: Vec<Vec<F128>> = vec![Vec::new(); recordings.len()];
    let mut carry: [F128; STATE_SIZE] = std::array::from_fn(|j| committed[2 + j][r1_len - 1]);
    let mut cursor = r1_len;
    let fill_carry = |committed: &mut [Vec<F128>; 6],
                      s0: &mut [Vec<F128>; STATE_SIZE],
                      s_out: &mut [Vec<F128>; STATE_SIZE],
                      carry: &mut [F128; STATE_SIZE],
                      from: usize,
                      to: usize| {
        for slot in from..to {
            let (g0, gout) = noid_ivc_core::deep_chain::source_tree::run_perm(*carry);
            for j in 0..STATE_SIZE {
                s0[j][slot] = g0[j];
                s_out[j][slot] = gout[j];
                committed[2 + j][slot] = gout[j];
            }
            *carry = gout;
        }
    };
    for &r in &packing.order {
        fill_carry(committed, s0, s_out, &mut carry, cursor, packing.offsets[r]);
        let rec = &recordings[r];
        let sz = packing.sizes[r];
        let s_log = sz.trailing_zeros() as usize;
        let cols = build_duplex_columns(&rec.layout, rec.iv_flat, rec.data, s_log);
        let off = packing.offsets[r];
        for j in 0..2 {
            committed[j][off..off + sz].copy_from_slice(&cols.a[j]);
        }
        for j in 0..STATE_SIZE {
            committed[2 + j][off..off + sz].copy_from_slice(&cols.c[j]);
            s0[j][off..off + sz].copy_from_slice(&cols.s0[j]);
            s_out[j][off..off + sz].copy_from_slice(&cols.s_out[j]);
        }
        rec_challenges[r] = cols.challenges;
        carry = std::array::from_fn(|j| committed[2 + j][off + sz - 1]);
        cursor = off + sz;
    }
    fill_carry(committed, s0, s_out, &mut carry, cursor, p);
    rec_challenges
}

/// Append each recording's gated 7-pattern set to `fixed` and return the
/// per-recording family refs (pattern indices after the existing sets).
#[cfg(test)]
pub(crate) fn gate_recording_patterns(
    fixed: &mut Vec<FixedPattern>,
    packing: &RecordingPacking,
    recordings: &[RecordingSpec<'_>],
) -> Vec<DuplexFamilyRefs> {
    let mut rec_refs = Vec::with_capacity(recordings.len());
    for (r, rec) in recordings.iter().enumerate() {
        let s_log = packing.sizes[r].trailing_zeros() as usize;
        let base = fixed.len();
        for pat in duplex_fixed_patterns(&rec.layout, rec.iv_flat, s_log) {
            fixed.push(pat.gated(s_log, rec_hi_bits(packing.offsets[r], s_log, packing.w_log)));
        }
        rec_refs.push(duplex_family_refs(0, base));
    }
    rec_refs
}

/// Substitution terms over a MULTI-REGION duplex domain: the ungated
/// leading carry once (`Σ_j m_j·C_j(w−1)` — every slot of every region and
/// ghost gap is a chain permutation), then each pattern set's gated
/// START/ABS/CONST wiring. The claimed refs stay the six A/C columns —
/// identical discharge plumbing to the single-set terms.
fn duplex_mds_weights(alpha: F128) -> [F128; STATE_SIZE] {
    let flat = |v: u128| flat_of_tower_u128(v);
    let mut alphas = [F128::ZERO; STATE_SIZE];
    let mut pw = F128::ONE;
    for a in alphas.iter_mut() {
        pw = pw * alpha;
        *a = pw;
    }
    std::array::from_fn(|j| {
        let mut acc = F128::ZERO;
        for e in 0..STATE_SIZE {
            acc += alphas[e] * flat(noid_poseidon2b::native::permutation::MDS_FULL[e][j]);
        }
        acc
    })
}

fn append_duplex_pattern_terms(
    terms: &mut Vec<RelationTerm>,
    refs: &DuplexFamilyRefs,
    weights: &[F128; STATE_SIZE],
) {
    for j in 0..STATE_SIZE {
        terms.push(RelationTerm {
            coeff: weights[j],
            factors: vec![ColRef::Fixed(refs.start), ColRef::CommittedShift(refs.c[j])],
        });
        if j < 2 {
            terms.push(RelationTerm {
                coeff: weights[j],
                factors: vec![ColRef::Fixed(refs.abs[j]), ColRef::Committed(refs.a[j])],
            });
        }
        terms.push(RelationTerm {
            coeff: weights[j],
            factors: vec![ColRef::Fixed(refs.consts[j])],
        });
    }
}

fn duplex_substitution_terms_multi(sets: &[DuplexFamilyRefs], alpha: F128) -> Vec<RelationTerm> {
    let m = duplex_mds_weights(alpha);
    let mut terms = Vec::new();
    for j in 0..STATE_SIZE {
        terms.push(RelationTerm {
            coeff: m[j],
            factors: vec![ColRef::CommittedShift(sets[0].c[j])],
        });
    }
    for refs in sets {
        append_duplex_pattern_terms(&mut terms, refs, &m);
    }
    terms
}

/// Selector-aware recording wiring. `sets` is ordered as
/// `(arm-0 base, arm-0/arm-1 delta)` for each recording chunk. Over the
/// characteristic-two base field, `base + selector * delta` is exactly the
/// selected fixed schedule while retaining one proof shape for both arms.
pub(crate) fn duplex_substitution_terms_selected(
    sets: &[DuplexFamilyRefs],
    selector: F128,
    alpha: F128,
) -> Vec<RelationTerm> {
    assert!(!sets.is_empty() && sets.len() % 2 == 0);
    let m = duplex_mds_weights(alpha);
    let selected_m = m.map(|weight| weight * selector);
    let mut terms = Vec::new();
    for j in 0..STATE_SIZE {
        terms.push(RelationTerm {
            coeff: m[j],
            factors: vec![ColRef::CommittedShift(sets[0].c[j])],
        });
    }
    for pair in sets.chunks_exact(2) {
        append_duplex_pattern_terms(&mut terms, &pair[0], &m);
        append_duplex_pattern_terms(&mut terms, &pair[1], &selected_m);
    }
    terms
}

/// Ref-set twin of the test-only native-union adapter for callers that hold a
/// verification key instead of an assembled union.
pub(crate) fn duplex_substitution_terms_sets(
    refs: &DuplexFamilyRefs,
    rec_refs: &[DuplexFamilyRefs],
    alpha: F128,
) -> Vec<RelationTerm> {
    if rec_refs.is_empty() {
        duplex_substitution_terms(refs, alpha)
    } else {
        let mut sets = vec![*refs];
        sets.extend_from_slice(rec_refs);
        duplex_substitution_terms_multi(&sets, alpha)
    }
}

/// The union's substitution terms: single-set unions keep the original
/// [`duplex_substitution_terms`] wiring byte-for-byte; recording-bearing
/// unions use the multi-set form.
#[cfg(test)]
pub(crate) fn duplex_union_sub_terms(u: &DuplexUnion, alpha: F128) -> Vec<RelationTerm> {
    if u.rec_refs.is_empty() {
        duplex_substitution_terms(&u.refs, alpha)
    } else {
        let mut sets = vec![u.refs];
        sets.extend(u.rec_refs.iter().copied());
        duplex_substitution_terms_multi(&sets, alpha)
    }
}

#[cfg(test)]
pub(crate) struct DuplexUnionNative {
    pub(crate) sel_proof: ColumnRelationProof,
    pub(crate) walk_proof: DeepChainWalkProof,
    pub(crate) sub_proof: ColumnRelationProof,
    pub(crate) shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pub(crate) pending: Vec<(usize, Vec<F128>, F128)>,
}

/// Serializable proof authority for one duplex-union sidecar.  Terminal PCS
/// descriptors are deliberately absent: their column, point and value are
/// reconstructed while replaying this proof against the verification key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DuplexUnionProof {
    pub(crate) selection: ColumnRelationProof,
    pub(crate) walk: DeepChainWalkProof,
    pub(crate) substitution: ColumnRelationProof,
    pub(crate) shifts: Vec<ShiftDischargeProof>,
}

/// Serializable duplex authority with its deep-chain walk deferred to an
/// enclosing protocol.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DuplexUnionWalkDeferredProof {
    pub(crate) selection: ColumnRelationProof,
    pub(crate) substitution: ColumnRelationProof,
    pub(crate) shifts: Vec<ShiftDischargeProof>,
}

#[derive(Clone, Copy)]
pub(crate) struct DuplexUnionWalkDeferredProofRef<'a> {
    pub(crate) selection: &'a ColumnRelationProof,
    pub(crate) substitution: &'a ColumnRelationProof,
    pub(crate) shifts: &'a [ShiftDischargeProof],
}

impl DuplexUnionProof {
    pub(crate) fn walk_deferred(&self) -> DuplexUnionWalkDeferredProofRef<'_> {
        DuplexUnionWalkDeferredProofRef {
            selection: &self.selection,
            substitution: &self.substitution,
            shifts: &self.shifts,
        }
    }
}

pub(crate) struct DuplexUnionProverWalkPrefix {
    selection: ColumnRelationProof,
    pending: Vec<DuplexColumnClaim>,
    walk_group: LaneClaimGroup,
}

impl DuplexUnionProverWalkPrefix {
    pub(crate) fn walk_group(&self) -> &LaneClaimGroup {
        &self.walk_group
    }
}

pub(crate) struct DuplexUnionVerifierWalkPrefix<'a> {
    proof: DuplexUnionWalkDeferredProofRef<'a>,
    pending: Vec<DuplexColumnClaim>,
    walk_group: LaneClaimGroup,
}

impl DuplexUnionVerifierWalkPrefix<'_> {
    pub(crate) fn walk_group(&self) -> &LaneClaimGroup {
        &self.walk_group
    }
}

/// A terminal opening on one of the six duplex committed columns.  This is a
/// transient replay result, never serialized into [`DuplexUnionProof`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DuplexColumnClaim {
    pub(crate) column: usize,
    pub(crate) point: Vec<F128>,
    pub(crate) value: F128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DuplexUnionVerifyError {
    Shape,
    Selection(RelationError),
    Walk(WalkError),
    Substitution(RelationError),
    Shift(RelationError),
}

fn duplex_terms_from_refs(
    refs: &DuplexFamilyRefs,
    rec_refs: &[DuplexFamilyRefs],
    alpha: F128,
) -> Vec<RelationTerm> {
    if rec_refs.is_empty() {
        duplex_substitution_terms(refs, alpha)
    } else {
        let mut sets = vec![*refs];
        sets.extend_from_slice(rec_refs);
        duplex_substitution_terms_multi(&sets, alpha)
    }
}

/// Prove the duplex carry-selection prefix and stop before the deep-chain
/// walk.  The caller receives one exact walk group and cannot obtain a
/// deferred authority until it supplies the walk terminal to the suffix.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_duplex_union_walk_prefix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    committed: &[&[F128]],
    s_out: &[Vec<F128>; STATE_SIZE],
    challenger: &mut Ch,
) -> DuplexUnionProverWalkPrefix {
    let w = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == w));
    assert!(s_out.iter().all(|column| column.len() == w));

    let mut pending = Vec::new();
    let beta = challenger.sample_f128();
    let selection_terms = carry_selection_terms(&refs.c, beta);
    let rho = challenger.sample_f128_vec(w_log);
    let internal: Vec<&[F128]> = s_out.iter().map(Vec::as_slice).collect();
    let (selection, selection_point, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &selection_terms,
        &RelationColumns {
            committed,
            internal: &internal,
            fixed,
        },
        challenger,
    );
    let mut output_values = [F128::ZERO; STATE_SIZE];
    for (reference, value) in claimed_refs(&selection_terms)
        .iter()
        .zip(selection.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(DuplexColumnClaim {
                column: *column,
                point: selection_point.clone(),
                value: *value,
            }),
            ColRef::Internal(lane) => output_values[*lane] = *value,
            _ => unreachable!("duplex selection claim kind"),
        }
    }

    DuplexUnionProverWalkPrefix {
        selection,
        pending,
        walk_group: LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    }
}

/// Finish the duplex substitution and shift discharges after a caller-owned
/// walk has produced `terminal`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_duplex_union_walk_suffix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    rec_refs: &[DuplexFamilyRefs],
    committed: &[&[F128]],
    prefix: DuplexUnionProverWalkPrefix,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
) -> (DuplexUnionWalkDeferredProof, Vec<DuplexColumnClaim>) {
    prove_duplex_union_walk_suffix_with_term_builder(
        w_log,
        fixed,
        committed,
        prefix,
        terminal,
        challenger,
        |alpha| duplex_terms_from_refs(refs, rec_refs, alpha),
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_duplex_union_walk_suffix_with_term_builder<Ch, BuildTerms>(
    w_log: usize,
    fixed: &[FixedPattern],
    committed: &[&[F128]],
    prefix: DuplexUnionProverWalkPrefix,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
    build_terms: BuildTerms,
) -> (DuplexUnionWalkDeferredProof, Vec<DuplexColumnClaim>)
where
    Ch: Challenger,
    BuildTerms: FnOnce(F128) -> Vec<RelationTerm>,
{
    let w = 1usize << w_log;
    assert!(committed.iter().all(|column| column.len() == w));
    let DuplexUnionProverWalkPrefix {
        selection,
        mut pending,
        walk_group: _,
    } = prefix;

    let alpha = challenger.sample_f128();
    let substitution_terms = build_terms(alpha);
    let mut target = F128::ZERO;
    let mut alpha_power = F128::ONE;
    for value in terminal.values {
        alpha_power = alpha_power * alpha;
        target += alpha_power * value;
    }
    let (substitution, substitution_point, _) = prove_column_relation(
        target,
        &terminal.point,
        &substitution_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        challenger,
    );

    let mut shifts = Vec::new();
    for (reference, value) in claimed_refs(&substitution_terms)
        .iter()
        .zip(substitution.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(DuplexColumnClaim {
                column: *column,
                point: substitution_point.clone(),
                value: *value,
            }),
            ColRef::CommittedShift(column) => {
                let (shift, point) = prove_shift_discharge(
                    committed[*column],
                    &substitution_point,
                    *value,
                    challenger,
                );
                pending.push(DuplexColumnClaim {
                    column: *column,
                    point,
                    value: shift.final_value,
                });
                shifts.push(shift);
            }
            _ => unreachable!("duplex substitution claim kind"),
        }
    }

    (
        DuplexUnionWalkDeferredProof {
            selection,
            substitution,
            shifts,
        },
        pending,
    )
}

/// Verify the duplex selection prefix and expose its exact caller-owned walk
/// group.
pub(crate) fn verify_duplex_union_walk_prefix_with_challenger<'a, Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    proof: DuplexUnionWalkDeferredProofRef<'a>,
    challenger: &mut Ch,
) -> Result<DuplexUnionVerifierWalkPrefix<'a>, DuplexUnionVerifyError> {
    let mut pending = Vec::new();
    let beta = challenger.sample_f128();
    let selection_terms = carry_selection_terms(&refs.c, beta);
    let rho = challenger.sample_f128_vec(w_log);
    let selection_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho,
        &selection_terms,
        fixed,
        proof.selection,
        challenger,
    )
    .map_err(DuplexUnionVerifyError::Selection)?;
    let mut output_values = [F128::ZERO; STATE_SIZE];
    for (reference, value) in claimed_refs(&selection_terms)
        .iter()
        .zip(proof.selection.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(DuplexColumnClaim {
                column: *column,
                point: selection_point.clone(),
                value: *value,
            }),
            ColRef::Internal(lane) if *lane < STATE_SIZE => output_values[*lane] = *value,
            _ => return Err(DuplexUnionVerifyError::Shape),
        }
    }

    Ok(DuplexUnionVerifierWalkPrefix {
        proof,
        pending,
        walk_group: LaneClaimGroup {
            point: selection_point,
            values: output_values,
        },
    })
}

/// Verify the duplex suffix against an externally verified walk terminal.
pub(crate) fn verify_duplex_union_walk_suffix_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    rec_refs: &[DuplexFamilyRefs],
    prefix: DuplexUnionVerifierWalkPrefix<'_>,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
) -> Result<Vec<DuplexColumnClaim>, DuplexUnionVerifyError> {
    verify_duplex_union_walk_suffix_with_term_builder(
        w_log,
        fixed,
        prefix,
        terminal,
        challenger,
        |alpha| duplex_terms_from_refs(refs, rec_refs, alpha),
    )
}

fn verify_duplex_union_walk_suffix_with_term_builder<Ch, BuildTerms>(
    w_log: usize,
    fixed: &[FixedPattern],
    prefix: DuplexUnionVerifierWalkPrefix<'_>,
    terminal: &LaneClaimGroup,
    challenger: &mut Ch,
    build_terms: BuildTerms,
) -> Result<Vec<DuplexColumnClaim>, DuplexUnionVerifyError>
where
    Ch: Challenger,
    BuildTerms: FnOnce(F128) -> Vec<RelationTerm>,
{
    let DuplexUnionVerifierWalkPrefix {
        proof,
        mut pending,
        walk_group: _,
    } = prefix;
    let alpha = challenger.sample_f128();
    let substitution_terms = build_terms(alpha);
    let mut target = F128::ZERO;
    let mut alpha_power = F128::ONE;
    for value in terminal.values {
        alpha_power = alpha_power * alpha;
        target += alpha_power * value;
    }
    let substitution_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &substitution_terms,
        fixed,
        proof.substitution,
        challenger,
    )
    .map_err(DuplexUnionVerifyError::Substitution)?;

    let mut shift_cursor = 0usize;
    for (reference, value) in claimed_refs(&substitution_terms)
        .iter()
        .zip(proof.substitution.final_values.iter())
    {
        match reference {
            ColRef::Committed(column) => pending.push(DuplexColumnClaim {
                column: *column,
                point: substitution_point.clone(),
                value: *value,
            }),
            ColRef::CommittedShift(column) => {
                let shift = proof
                    .shifts
                    .get(shift_cursor)
                    .ok_or(DuplexUnionVerifyError::Shape)?;
                shift_cursor += 1;
                let point =
                    verify_shift_discharge(w_log, &substitution_point, *value, shift, challenger)
                        .map_err(DuplexUnionVerifyError::Shift)?;
                pending.push(DuplexColumnClaim {
                    column: *column,
                    point,
                    value: shift.final_value,
                });
            }
            _ => return Err(DuplexUnionVerifyError::Shape),
        }
    }
    if shift_cursor != proof.shifts.len() {
        return Err(DuplexUnionVerifyError::Shape);
    }
    Ok(pending)
}

/// Prover half of the duplex-union protocol over an already-bound transcript.
///
/// The caller owns transcript domain separation and, for a region sidecar,
/// MUST call this only after the outer witness commitment has been absorbed.
/// No challenger is constructed here: all challenges are drawn from the exact
/// challenger passed by the outer FieldR1cs prover.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_duplex_union_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    rec_refs: &[DuplexFamilyRefs],
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    challenger: &mut Ch,
) -> (DuplexUnionProof, Vec<DuplexColumnClaim>) {
    let w = 1usize << w_log;
    assert!(s0.iter().all(|column| column.len() == w));
    let prefix = prove_duplex_union_walk_prefix_with_challenger(
        w_log, fixed, refs, committed, s_out, challenger,
    );
    let groups = [prefix.walk_group().clone()];
    let (walk, terminal) = prove_deep_chain_walk(s0, &groups, challenger);
    let (deferred, pending) = prove_duplex_union_walk_suffix_with_challenger(
        w_log, fixed, refs, rec_refs, committed, prefix, &terminal, challenger,
    );
    (
        DuplexUnionProof {
            selection: deferred.selection,
            walk,
            substitution: deferred.substitution,
            shifts: deferred.shifts,
        },
        pending,
    )
}

/// Verifier half of [`prove_duplex_union_with_challenger`].  Every returned
/// terminal descriptor is derived from the proof replay and the caller's
/// fixed refs; no prover-supplied pending-claim list is consumed.
pub(crate) fn verify_duplex_union_with_challenger<Ch: Challenger>(
    w_log: usize,
    fixed: &[FixedPattern],
    refs: &DuplexFamilyRefs,
    rec_refs: &[DuplexFamilyRefs],
    proof: &DuplexUnionProof,
    challenger: &mut Ch,
) -> Result<Vec<DuplexColumnClaim>, DuplexUnionVerifyError> {
    let deferred = proof.walk_deferred();
    let prefix =
        verify_duplex_union_walk_prefix_with_challenger(w_log, fixed, refs, deferred, challenger)?;
    let groups = [prefix.walk_group().clone()];
    let terminal = verify_deep_chain_walk(w_log, &groups, &proof.walk, challenger)
        .map_err(DuplexUnionVerifyError::Walk)?;
    verify_duplex_union_walk_suffix_with_challenger(
        w_log, fixed, refs, rec_refs, prefix, &terminal, challenger,
    )
}

/// Native discharge of the whole channel union in ONE walk (mirror of
/// `run_leaf_union_native` with the duplex family's terms).
#[cfg(test)]
pub(crate) fn run_duplex_union_native(u: &DuplexUnion, domain: &[u8]) -> DuplexUnionNative {
    let committed: Vec<&[F128]> = u.committed.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let (proof, prover_claims) = prove_duplex_union_with_challenger(
        u.w_log,
        &u.fixed,
        &u.refs,
        &u.rec_refs,
        &committed,
        &u.s0,
        &u.s_out,
        &mut ch_p,
    );
    let verifier_claims = verify_duplex_union_with_challenger(
        u.w_log,
        &u.fixed,
        &u.refs,
        &u.rec_refs,
        &proof,
        &mut ch_v,
    )
    .expect("native duplex union");
    assert_eq!(prover_claims, verifier_claims, "duplex terminal claims");
    assert_eq!(
        ch_p.sample_f128(),
        ch_v.sample_f128(),
        "native duplex-union lockstep"
    );

    let shift_columns: Vec<usize> = claimed_refs(&duplex_union_sub_terms(u, F128::ONE))
        .iter()
        .filter_map(|reference| match reference {
            ColRef::CommittedShift(column) => Some(*column),
            _ => None,
        })
        .collect();
    assert_eq!(shift_columns.len(), proof.shifts.len());
    let shifts = shift_columns
        .into_iter()
        .zip(proof.shifts.iter().cloned())
        .map(|(column, shift)| (0usize, column, shift))
        .collect();
    let pending = prover_claims
        .into_iter()
        .map(|claim| (claim.column, claim.point, claim.value))
        .collect();
    DuplexUnionNative {
        sel_proof: proof.selection,
        walk_proof: proof.walk,
        sub_proof: proof.substitution,
        shifts,
        pending,
    }
}

/// Trace twin of `duplex_substitution_terms`: the α-batched walk-terminal wiring
/// `Σ_j m_j·[C_j(w−1) + START·C_j(w−1) + ABS_j·A_j + CONST_j]` (rate-lane absorbs
/// on j ∈ {0,1}), with `m_j = Σ_e α^{e+1}·flat(MDS[e][j])` built in-trace.
pub(crate) fn duplex_sub_terms_trace(
    b: &mut FieldR1csBuilder,
    refs: &DuplexFamilyRefs,
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let (m, ap) = mds_alpha_weights(b, alpha);
    let mut terms = Vec::new();
    for j in 0..STATE_SIZE {
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::CommittedShift(refs.c[j])],
        });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(refs.start), ColRef::CommittedShift(refs.c[j])],
        });
        if j < 2 {
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(refs.abs[j]), ColRef::Committed(refs.a[j])],
            });
        }
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(refs.consts[j])],
        });
    }
    (terms, ap)
}

#[cfg(test)]
fn duplex_sub_terms_trace_multi(
    b: &mut FieldR1csBuilder,
    sets: &[DuplexFamilyRefs],
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let (m, ap) = mds_alpha_weights(b, alpha);
    let mut terms = Vec::new();
    for j in 0..STATE_SIZE {
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::CommittedShift(sets[0].c[j])],
        });
    }
    for refs in sets {
        for j in 0..STATE_SIZE {
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(refs.start), ColRef::CommittedShift(refs.c[j])],
            });
            if j < 2 {
                terms.push(RelationTermTrace {
                    coeff: m[j].clone(),
                    factors: vec![ColRef::Fixed(refs.abs[j]), ColRef::Committed(refs.a[j])],
                });
            }
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(refs.consts[j])],
            });
        }
    }
    (terms, ap)
}

/// Discharge the shared channel union in-trace (mirror of `discharge_leaf_union`
/// for the duplex family). Column claims are offset by `base` in the caller's
/// global slice table. Returns the pending terminal claims on the A/C columns.
/// The caller supplies the discharge transcript channel: an inline
/// [`FsChannelTrace`] (walk C itself — a walk cannot host its own transcript),
/// or an [`FsChannelUnionRecorder`] whose recording rides another union.
#[cfg(test)]
pub(crate) fn discharge_duplex_union(
    b: &mut FieldR1csBuilder,
    mut ch: &mut impl FsChannelOps,
    u: &DuplexUnion,
    native: &DuplexUnionNative,
    base: usize,
) -> Vec<Claim> {
    let refs = &u.refs;
    let fixed = &u.fixed;
    let w_log = u.w_log;
    let mut out: Vec<Claim> = Vec::new();
    let np = &native.pending;
    let mut np_cursor = 0usize;
    let zero = LinExpr::zero();

    let beta = ch.sample_f128(b);
    let mut bp = LinExpr::constant(F128::ONE);
    let mut sel_e_terms = Vec::new();
    for j in 0..STATE_SIZE {
        bp = mul(b, &bp, &beta);
        sel_e_terms.push(RelationTermTrace {
            coeff: bp.clone(),
            factors: vec![ColRef::Committed(refs.c[j])],
        });
        sel_e_terms.push(RelationTermTrace {
            coeff: bp.clone(),
            factors: vec![ColRef::Internal(j)],
        });
    }
    let rho = ch.sample_f128_vec(b, w_log);
    let sel_e = ColumnRelationProofTrace::alloc(b, &native.sel_proof, w_log, 2 * STATE_SIZE);
    let sel_point =
        verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho, &sel_e_terms, fixed, &sel_e);
    let sel_claimed = claimed_refs(&carry_selection_terms(&refs.c, F128::ONE));
    let mut gv: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    for (r, v) in sel_claimed.iter().zip(sel_e.final_values.iter()) {
        match r {
            ColRef::Committed(c) => {
                let (_, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: base + *c,
                    point: sel_point.clone(),
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            ColRef::Internal(j) => gv[*j] = v.clone(),
            _ => unreachable!(),
        }
    }
    let groups_e = vec![LaneClaimGroupTrace {
        point: sel_point,
        values: gv,
    }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    let alpha = ch.sample_f128(b);
    let sub_native = duplex_union_sub_terms(u, F128::ONE);
    let (sub_e_terms, ap) = if u.rec_refs.is_empty() {
        duplex_sub_terms_trace(b, refs, &alpha)
    } else {
        let mut sets = vec![*refs];
        sets.extend(u.rec_refs.iter().copied());
        duplex_sub_terms_trace_multi(b, &sets, &alpha)
    };
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e = ColumnRelationProofTrace::alloc(
        b,
        &native.sub_proof,
        w_log,
        claimed_refs(&sub_native).len(),
    );
    let sub_point = verify_column_relation_trace(
        b,
        &mut ch,
        w_log,
        &target,
        &terminal.point,
        &sub_e_terms,
        fixed,
        &sub_e,
    );
    let mut shift_cursor = 0usize;
    for (r, v) in claimed_refs(&sub_native)
        .iter()
        .zip(sub_e.final_values.iter())
    {
        match r {
            ColRef::Committed(c) => {
                let (_, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: base + *c,
                    point: sub_point.clone(),
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            ColRef::CommittedShift(_) => {
                let (sl, col, ns) = &native.shifts[shift_cursor];
                shift_cursor += 1;
                let se = ShiftDischargeProofTrace::alloc(b, ns, w_log);
                let pt = verify_shift_discharge_trace(b, &mut ch, w_log, &sub_point, v, *sl, &se);
                let (_, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: base + *col,
                    point: pt,
                    value: se.final_value.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(np_cursor, np.len(), "duplex-union pending lockstep");
    out
}

/// Bind tx `t`'s already-allocated squeezed-challenge wires to the walk-C carry
/// cells: one opening claim per challenge on carry column `C_lane` at the
/// challenge's slot (the digest-read pattern). Because the C columns are opened
/// by the walk (proving they ARE the chain output) and each claim opens `C_lane`
/// at the exact slot, the bound wire is forced to the correct squeezed challenge
/// — the prover cannot use a different value. The plural uses this to bind the
/// in-loop challenge wires the per-tx algebra consumed.
#[cfg(test)]
pub(crate) fn bind_duplex_challenges(
    u: &DuplexUnion,
    t: usize,
    base: usize,
    chal_wires: &[LinExpr],
    out: &mut Vec<Claim>,
) {
    let per_tx = 1usize << u.block_log;
    assert_eq!(
        chal_wires.len(),
        u.layout.challenges.len(),
        "challenge wire count"
    );
    for (k, &(slot, lane)) in u.layout.challenges.iter().enumerate() {
        let gslot = t * per_tx + slot;
        let (pt_lin, pt_nat) = slot_point(gslot, u.w_log);
        out.push(Claim {
            slice: base + u.refs.c[lane],
            point: pt_lin,
            value: chal_wires[k].clone(),
            native_point: pt_nat,
            native_value: u.challenges[t][k],
        });
    }
}

/// Read tx `t`'s squeezed challenges into FRESH wires (allocate + bind). Used by
/// the isolated gate; the plural binds its own in-loop wires directly.
#[cfg(test)]
fn read_duplex_challenges(
    b: &mut FieldR1csBuilder,
    u: &DuplexUnion,
    t: usize,
    base: usize,
    out: &mut Vec<Claim>,
) -> Vec<LinExpr> {
    let wires: Vec<LinExpr> = (0..u.layout.challenges.len())
        .map(|k| LinExpr::from_wire(b.alloc_f128(u.challenges[t][k])))
        .collect();
    bind_duplex_challenges(u, t, base, &wires, out);
    wires
}

/// The `(slot, lane)` where each data lane `k` is absorbed, read off the compiled
/// layout — a class constant used to place each tx's absorb-binding claims.
pub(crate) fn duplex_data_positions(layout: &DuplexLayout) -> Vec<(usize, usize)> {
    let mut pos = vec![(0usize, 0usize); layout.n_data];
    for (slot, ds) in layout.slots.iter().enumerate() {
        for (lane, src) in ds.lanes.iter().enumerate() {
            if let Some(LaneSource::Data(k)) = src {
                pos[*k] = (slot, lane);
            }
        }
    }
    pos
}

// ===========================================================================
// HETEROGENEOUS walk-C union: N DIFFERENT duplex channels per tx, ONE walk.
//
// The homogeneous `build_duplex_union` tiles K copies of ONE channel schedule.
// This variant tiles K transactions each carrying N DIFFERENT channels (distinct
// IVs, distinct op layouts) into ONE data-parallel walk. It is the memory
// optimization that lets the owner-auth KSCHANNL channel and the wallet-PCS
// FRICHANL channel share ONE walk-C (~1.1M rows) instead of two: the substitution
// wiring `raw_j(w) = (1+START(w))·C_j(w−1) + ABS_j(w)·A_j(w) + CONST_j(w)` is
// UNIFORM across the whole slot domain, so as long as the fixed patterns place
// each channel's START / IV / absorb-selector / rate-constant lanes at the right
// slots, ONE `duplex_substitution_terms` relation discharges every channel of
// every tx — and `run_duplex_union_native` / `discharge_duplex_union` (which read
// only the 6 committed columns, the 7 fixed patterns, the refs and s0/s_out, and
// NEVER the layout) work UNCHANGED on the combined [`DuplexUnion`].
//
// Layout — common-S sub-block tiling: sub-channel `i` occupies the power-of-two
// sub-block `[i·S, (i+1)·S)` of every per-tx block, where
// `S = next_pow2(max_i subs[i].slots.len())`; the per-tx period is `N·S` (N padded
// to a power of two with canonical IV-seeded ghost sub-channels). Sub-block `i` of
// tx `t` sits at global offset `t·N·S + i·S`.
//
// Carry reset (THE correctness crux): the combined START pattern has a `1` at
// EVERY sub-channel's slot 0 (`i·S` for all i), so the substitution's
// `(1+START)·C_j(w−1)` term zeroes there — each sub-channel re-seeds its OWN IV and
// does NOT inherit the previous sub-channel's final carry. That is exactly what
// makes the N channels within one tiled block independent (proven by
// `combined_duplex_union_tests::combined_correctness_vs_separate`).
// ===========================================================================

/// One heterogeneous sub-channel of a combined walk-C union: its compiled duplex
/// schedule and its capacity IV. Different sub-channels may have DIFFERENT
/// schedules AND DIFFERENT IVs (e.g. FRICHANL vs KSCHANNL), yet still share ONE
/// data-parallel walk.
#[derive(Clone)]
pub(crate) struct SubChannel {
    pub(crate) layout: DuplexLayout,
    pub(crate) iv_flat: [F128; 2],
}

/// The 7 duplex fixed patterns (`start, abs0, abs1, const0..const3`) over the
/// combined per-tx period `N·S`, with sub-channel `i` placed at offset `i·S`.
/// Mirrors `duplex_fixed_patterns` per sub-block: `start[i·S]=1` (the carry reset),
/// the capacity IV on `const2/const3` at `i·S`, and each real slot's absorb
/// selectors / rate constants at `i·S + sl`. Ghost sub-block slots (past a sub's
/// real length) carry START=0 and no constants — they just continue the chain, and
/// `build_duplex_columns` fills the matching continuing-chain tail per sub-block.
pub(crate) fn combined_duplex_fixed_patterns(
    subs: &[SubChannel],
    s_log: usize,
) -> Vec<FixedPattern> {
    let s = 1usize << s_log;
    let per_tx = subs.len() * s;
    let block_log = per_tx.trailing_zeros() as usize;
    let mut start = vec![F128::ZERO; per_tx];
    let mut abs: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; per_tx]);
    let mut consts: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; per_tx]);
    for (i, sub) in subs.iter().enumerate() {
        let off = i * s;
        assert!(
            sub.layout.slots.len() <= s,
            "sub schedule exceeds the common S"
        );
        // Carry reset + IV seed at this sub-channel's slot 0.
        start[off] = F128::ONE;
        consts[2][off] = sub.iv_flat[0];
        consts[3][off] = sub.iv_flat[1];
        for (sl, ds) in sub.layout.slots.iter().enumerate() {
            for (j, lane) in ds.lanes.iter().enumerate() {
                match lane {
                    Some(LaneSource::Data(_)) => abs[j][off + sl] = F128::ONE,
                    Some(LaneSource::Const(cv)) => consts[j][off + sl] = flat_of_tower_u128(*cv),
                    None => {}
                }
            }
        }
    }
    let mut out = Vec::with_capacity(3 + STATE_SIZE);
    out.push(FixedPattern::new(block_log, start));
    for pat in abs {
        out.push(FixedPattern::new(block_log, pat));
    }
    for pat in consts {
        out.push(FixedPattern::new(block_log, pat));
    }
    out
}

/// The combined [`DuplexLayout`] over the per-tx period `N·S`: each sub-channel's
/// slots placed at offset `i·S` with Data lane indices RENUMBERED to the flattened
/// `[sub0 data ++ sub1 data ++ ...]` global stream, and challenges concatenated in
/// sub order with slots shifted by `i·S` (matching the per-tx challenge stream). By
/// construction, reading data positions from this layout yields the flattened
/// sub-channel streams in order.
pub(crate) fn combined_duplex_layout(subs: &[SubChannel], s_log: usize) -> DuplexLayout {
    let s = 1usize << s_log;
    let per_tx = subs.len() * s;
    let mut slots = vec![
        DuplexSlot {
            lanes: [None, None]
        };
        per_tx
    ];
    let mut challenges = Vec::new();
    let mut data_off = 0usize;
    for (i, sub) in subs.iter().enumerate() {
        let off = i * s;
        for (sl, ds) in sub.layout.slots.iter().enumerate() {
            let lanes = std::array::from_fn(|lane| match ds.lanes[lane] {
                Some(LaneSource::Data(k)) => Some(LaneSource::Data(data_off + k)),
                other => other,
            });
            slots[off + sl] = DuplexSlot { lanes };
        }
        for &(slot, lane) in &sub.layout.challenges {
            challenges.push((off + slot, lane));
        }
        data_off += sub.layout.n_data;
    }
    DuplexLayout {
        slots,
        challenges,
        n_data: data_off,
    }
}

/// Tile `data.len()` transactions, each carrying `subs.len()` DIFFERENT duplex
/// sub-channels, into ONE walk-C domain. `data[t][i]` is sub-channel `i`'s
/// absorbed-data stream for tx `t` (flat, length `subs[i].layout.n_data`).
///
/// The result is a drop-in [`DuplexUnion`]: `run_duplex_union_native` and
/// `discharge_duplex_union` are AGNOSTIC to how many sub-channels a block holds
/// (they walk the 6 committed columns and open each at ONE random point), so ONE
/// carry-selection + ONE walk + ONE substitution discharges every sub-channel of
/// every tx. The per-tx challenge stream `challenges[t]` is the sub-channels'
/// squeezed challenges CONCATENATED in sub order.
///
/// Padding: `N` is padded to a power of two with canonical IV-seeded ghost
/// sub-channels (empty schedules → pure IV chains, no absorbs, no challenges); `K`
/// is padded to a power of two with ghost TILES (zero-data channel blocks). Both
/// pads are valid chains re-seeded by the START pattern — never `perm([0;4])` ghost
/// slots (the duplex substitution's leading carry term is ungated, so every block
/// must be a genuine IV-seeded chain).
pub(crate) fn build_combined_duplex_union(
    subs: &[SubChannel],
    data: &[Vec<Vec<F128>>],
) -> DuplexUnion {
    assert!(!subs.is_empty(), "need at least one sub-channel");
    let n_real = subs.len();
    let n = n_real.next_power_of_two();
    // Common S = smallest power-of-two slot capacity across all sub-channels.
    let s = subs
        .iter()
        .map(|c| c.layout.slots.len())
        .max()
        .unwrap()
        .max(1)
        .next_power_of_two();
    let s_log = s.trailing_zeros() as usize;
    let per_tx = n * s;
    let block_log = per_tx.trailing_zeros() as usize;
    let k = data.len();
    let w_log = (k.max(1) * per_tx).next_power_of_two().trailing_zeros() as usize;
    let p = 1usize << w_log;
    let n_tx_blocks = p / per_tx;

    // Validate the caller's data shape against the real sub-channels.
    for (t, row) in data.iter().enumerate() {
        assert_eq!(
            row.len(),
            n_real,
            "data row {t} width must equal the sub-channel count"
        );
        for (i, stream) in row.iter().enumerate() {
            assert_eq!(stream.len(), subs[i].layout.n_data, "data[{t}][{i}] length");
        }
    }

    // Pad N up to a power of two with canonical ghost sub-channels (an empty
    // schedule seeds a pure zero-IV chain in its S-block — no absorbs, no
    // challenges). For the N=2 wallet use this is a no-op.
    let ghost = SubChannel {
        layout: DuplexLayout {
            slots: Vec::new(),
            challenges: Vec::new(),
            n_data: 0,
        },
        iv_flat: [F128::ZERO, F128::ZERO],
    };
    let subs_padded: Vec<SubChannel> = (0..n)
        .map(|i| {
            if i < n_real {
                subs[i].clone()
            } else {
                ghost.clone()
            }
        })
        .collect();

    let mut committed: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut challenges: Vec<Vec<F128>> = Vec::with_capacity(k);

    for blk in 0..n_tx_blocks {
        let mut tx_challenges: Vec<F128> = Vec::new();
        for (i, sub) in subs_padded.iter().enumerate() {
            let zero_data = vec![F128::ZERO; sub.layout.n_data];
            let d: &[F128] = if blk < k && i < n_real {
                &data[blk][i]
            } else {
                &zero_data
            };
            // Each sub-block is an S-slot homogeneous block: slot 0 is
            // IV-seeded, later slots carry, and the tail past the real schedule is
            // the continuing chain fill — copied wholesale into the tiled domain.
            let cols = build_duplex_columns(&sub.layout, sub.iv_flat, d, s_log);
            let off = blk * per_tx + i * s;
            for j in 0..2 {
                committed[j][off..off + s].copy_from_slice(&cols.a[j]);
            }
            for j in 0..STATE_SIZE {
                committed[2 + j][off..off + s].copy_from_slice(&cols.c[j]);
                s0[j][off..off + s].copy_from_slice(&cols.s0[j]);
                s_out[j][off..off + s].copy_from_slice(&cols.s_out[j]);
            }
            if blk < k {
                tx_challenges.extend_from_slice(&cols.challenges);
            }
        }
        if blk < k {
            challenges.push(tx_challenges);
        }
    }

    let fixed = combined_duplex_fixed_patterns(&subs_padded, s_log);
    let layout = combined_duplex_layout(&subs_padded, s_log);
    let refs = duplex_family_refs(0, 0);
    DuplexUnion {
        committed,
        s0,
        s_out,
        fixed,
        refs,
        layout,
        w_log,
        block_log,
        challenges,
        rec_blocks: Vec::new(),
        rec_refs: Vec::new(),
        rec_challenges: Vec::new(),
    }
}

/// [`build_combined_duplex_union`] with REGION-2 recording blocks — the
/// heterogeneous-sub-channel analogue of
/// the legacy mixed recordings builder. Region 1 tiles the K txs'
/// combined sub-channel blocks (its pattern set hi-gated to the region-1
/// dyadic prefix); each recorded discharge transcript rides its own
/// self-aligned dyadic block after it; gaps and the tail are pure carry
/// ghosts. Same pattern/substitution discipline as the homogeneous
/// recordings builder — `run_duplex_union_native` / `discharge_duplex_union`
/// consume the result unchanged.
#[cfg(test)]
pub(crate) fn build_combined_duplex_union_with_recordings(
    subs: &[SubChannel],
    data: &[Vec<Vec<F128>>],
    recordings: &[RecordingSpec<'_>],
) -> DuplexUnion {
    assert!(
        !recordings.is_empty(),
        "recording-free combined unions use build_combined_duplex_union"
    );
    assert!(!subs.is_empty(), "need at least one sub-channel");
    let n_real = subs.len();
    let n = n_real.next_power_of_two();
    let s = subs
        .iter()
        .map(|c| c.layout.slots.len())
        .max()
        .unwrap()
        .max(1)
        .next_power_of_two();
    let s_log = s.trailing_zeros() as usize;
    let per_tx = n * s;
    let block_log = per_tx.trailing_zeros() as usize;
    let k = data.len();
    let r1_len = (k.max(1) * per_tx).next_power_of_two();
    let r1_log = r1_len.trailing_zeros() as usize;

    let packing = pack_recordings(r1_len, recordings);
    let w_log = packing.w_log;
    let p = 1usize << w_log;

    for (t, row) in data.iter().enumerate() {
        assert_eq!(
            row.len(),
            n_real,
            "data row {t} width must equal the sub-channel count"
        );
        for (i, stream) in row.iter().enumerate() {
            assert_eq!(stream.len(), subs[i].layout.n_data, "data[{t}][{i}] length");
        }
    }
    let ghost = SubChannel {
        layout: DuplexLayout {
            slots: Vec::new(),
            challenges: Vec::new(),
            n_data: 0,
        },
        iv_flat: [F128::ZERO, F128::ZERO],
    };
    let subs_padded: Vec<SubChannel> = (0..n)
        .map(|i| {
            if i < n_real {
                subs[i].clone()
            } else {
                ghost.clone()
            }
        })
        .collect();

    let mut committed: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut challenges: Vec<Vec<F128>> = Vec::with_capacity(k);

    // Region 1: the combined tiling (real tx blocks + zero-data ghost
    // tiles up to the region boundary).
    for blk in 0..r1_len / per_tx {
        let mut tx_challenges: Vec<F128> = Vec::new();
        for (i, sub) in subs_padded.iter().enumerate() {
            let zero_data = vec![F128::ZERO; sub.layout.n_data];
            let d: &[F128] = if blk < k && i < n_real {
                &data[blk][i]
            } else {
                &zero_data
            };
            let cols = build_duplex_columns(&sub.layout, sub.iv_flat, d, s_log);
            let off = blk * per_tx + i * s;
            for j in 0..2 {
                committed[j][off..off + s].copy_from_slice(&cols.a[j]);
            }
            for j in 0..STATE_SIZE {
                committed[2 + j][off..off + s].copy_from_slice(&cols.c[j]);
                s0[j][off..off + s].copy_from_slice(&cols.s0[j]);
                s_out[j][off..off + s].copy_from_slice(&cols.s_out[j]);
            }
            if blk < k {
                tx_challenges.extend_from_slice(&cols.challenges);
            }
        }
        if blk < k {
            challenges.push(tx_challenges);
        }
    }

    let rec_challenges = fill_recording_region(
        &mut committed,
        &mut s0,
        &mut s_out,
        r1_len,
        &packing,
        recordings,
    );

    let mut fixed: Vec<FixedPattern> = combined_duplex_fixed_patterns(&subs_padded, s_log)
        .into_iter()
        .map(|pat| pat.gated(r1_log, rec_hi_bits(0, r1_log, w_log)))
        .collect();
    let rec_refs = gate_recording_patterns(&mut fixed, &packing, recordings);

    DuplexUnion {
        committed,
        s0,
        s_out,
        fixed,
        refs: duplex_family_refs(0, 0),
        layout: combined_duplex_layout(&subs_padded, s_log),
        w_log,
        block_log,
        challenges,
        rec_blocks: recordings
            .iter()
            .enumerate()
            .map(|(r, rec)| (rec.layout.clone(), packing.offsets[r]))
            .collect(),
        rec_refs,
        rec_challenges,
    }
}

#[cfg(test)]
mod stage1_duplex_union_tests {
    use super::*;
    use noid_ivc_core::deep_chain::schedule::{compile_duplex, TranscriptOp};
    use noid_poseidon2b::native::domain::{capacity_iv, TAG_FRICHANL};

    fn iv_flat() -> [F128; 2] {
        let iv = capacity_iv(TAG_FRICHANL);
        [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
    }

    /// A representative channel schedule exercising every duplex feature: a
    /// three-lane absorb (a full slot + a pending lane), a constant-lane absorb,
    /// a two-challenge squeeze (read + pending + the eager permutation), an
    /// absorb-after-squeeze reset, and a pad-flush squeeze.
    fn channel_ops() -> Vec<TranscriptOp> {
        const TAG: u128 = 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10;
        vec![
            TranscriptOp::Absorb(vec![None, None, None]),
            TranscriptOp::Absorb(vec![Some(TAG)]),
            TranscriptOp::Squeeze(2),
            TranscriptOp::Absorb(vec![None, None]),
            TranscriptOp::Absorb(vec![None]),
            TranscriptOp::Squeeze(3),
        ]
    }

    fn tx_data(layout: &DuplexLayout, seed: u64) -> Vec<F128> {
        let mut r = seed;
        (0..layout.n_data)
            .map(|_| {
                r = r.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(0x1234_5);
                F128 {
                    lo: r,
                    hi: r.rotate_left(29) ^ 0xA5A5,
                }
            })
            .collect()
    }

    /// The channel union discharges K txs' duplex chains in ONE walk: native
    /// verify (inside `run_duplex_union_native`) + trace satisfiability + the
    /// per-tx challenge wires (read from the carry cells) carry exactly the
    /// native squeezed challenges. Distinct tx data ⇒ distinct challenges, all
    /// recovered from the ONE tiled walk.
    #[test]
    fn duplex_union_native_and_trace() {
        let layout = compile_duplex(&channel_ops());
        let data: Vec<Vec<F128>> = (0..2)
            .map(|t| tx_data(&layout, 0xABCD_0000 + t as u64))
            .collect();
        let u = build_duplex_union(&layout, iv_flat(), &data);
        assert_ne!(
            u.challenges[0], u.challenges[1],
            "per-tx channels squeeze distinct challenges"
        );
        let native = run_duplex_union_native(&u, b"duplex-union-unit");

        let mut b = FieldR1csBuilder::new();
        for col in u.committed.iter() {
            alloc_column_slice(&mut b, col, u.w_log);
        }
        let mut ch = FsChannelTrace::new(&mut b, b"duplex-union-unit");
        let mut claims = discharge_duplex_union(&mut b, &mut ch, &u, &native, 0);
        let ch0 = read_duplex_challenges(&mut b, &u, 0, 0, &mut claims);
        let ch1 = read_duplex_challenges(&mut b, &u, 1, 0, &mut claims);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "duplex-union trace unsatisfiable");
        for (k, w) in ch0.iter().enumerate() {
            assert_eq!(w.eval(&z), u.challenges[0][k], "tx0 challenge wire");
        }
        for (k, w) in ch1.iter().enumerate() {
            assert_eq!(w.eval(&z), u.challenges[1][k], "tx1 challenge wire");
        }
        assert!(!claims.is_empty());
    }

    /// Production C->D construction invariant without paying D's 2.1M-row
    /// inline twin in this unit: two independent recorder passes over the same
    /// C native proof are byte/value identical, and the recording becomes ONE
    /// ordinary D channel block (never the two-region builder's extra half).
    /// Every recorded data/challenge value occupies its exact D A/C cell.
    #[test]
    fn c_to_recording_only_d_scratch_is_exact_and_single_block() {
        let layout = compile_duplex(&channel_ops());
        let data: Vec<Vec<F128>> = (0..2)
            .map(|t| tx_data(&layout, 0xD1E7_0000 + t as u64))
            .collect();
        let u_c = build_duplex_union(&layout, iv_flat(), &data);
        let native_c = run_duplex_union_native(&u_c, DOMAIN_C);

        let record = || {
            let mut b = FieldR1csBuilder::new_witness_only();
            let mut ch = FsChannelUnionRecorder::new(DOMAIN_C);
            let claims = discharge_duplex_union(&mut b, &mut ch, &u_c, &native_c, 0);
            let rec = ch.finish();
            let challenges: Vec<F128> = rec
                .challenge_wires
                .iter()
                .map(|w| w.eval(b.values()))
                .collect();
            (rec, challenges, claims.len())
        };
        let (scratch, scratch_challenges, scratch_claims) = record();
        let (real, real_challenges, real_claims) = record();
        assert_eq!(real.ops, scratch.ops, "C recorder schedule parity");
        assert_eq!(real.data_flat, scratch.data_flat, "C recorder data parity");
        assert_eq!(
            real.post_state, scratch.post_state,
            "C recorder state parity"
        );
        assert_eq!(real.perms, scratch.perms, "C recorder permutation parity");
        assert_eq!(real_challenges, scratch_challenges, "C challenge parity");
        assert_eq!(real_claims, scratch_claims, "C claim-count parity");

        let d_layout = compile_duplex(&scratch.ops);
        let d_slots = d_layout.slots.len().max(1).next_power_of_two();
        let u_d = build_duplex_union(
            &d_layout,
            FsChannelUnionRecorder::capacity_iv_flat(),
            std::slice::from_ref(&scratch.data_flat),
        );
        assert_eq!(u_d.committed.len(), 6, "D committed column count");
        assert_eq!(u_d.committed[0].len(), d_slots, "one D schedule block");
        assert!(u_d.rec_blocks.is_empty(), "D must not grow a region-2 half");
        assert_eq!(u_d.challenges.len(), 1, "one hosted C transcript");
        assert_eq!(u_d.challenges[0], scratch_challenges, "D challenge cells");
        for (kk, &(slot, lane)) in duplex_data_positions(&d_layout).iter().enumerate() {
            assert_eq!(
                u_d.committed[u_d.refs.a[lane]][slot], scratch.data_flat[kk],
                "D data cell {kk}"
            );
        }
        for (kk, &(slot, lane)) in d_layout.challenges.iter().enumerate() {
            assert_eq!(
                u_d.committed[u_d.refs.c[lane]][slot], scratch_challenges[kk],
                "D challenge cell {kk}"
            );
        }
        let native_d = run_duplex_union_native(&u_d, DOMAIN_D);
        assert_eq!(native_d.pending.len(), scratch_claims, "D claim shape");
    }

    /// The production handoff uses exact cell equalities, not a known linear
    /// mix. Honest C recording wires satisfy them; mixing D columns built from
    /// another recording, or flipping either a hosted data/challenge cell,
    /// breaks the relation.
    #[test]
    fn c_to_d_exact_pins_reject_component_mix_and_cell_mutations() {
        fn record(b: &mut FieldR1csBuilder, seed: u64) -> RecordedChannel {
            let wires: Vec<LinExpr> = (0..12)
                .map(|i| {
                    LinExpr::from_wire(b.alloc_f128(F128 {
                        lo: seed.wrapping_add(i as u64),
                        hi: seed.rotate_left(23) ^ (17 * i as u64),
                    }))
                })
                .collect();
            let mut ch = FsChannelUnionRecorder::new(b"c-to-d-pin-source");
            ch.observe_label(b, b"hosted-C-proof");
            ch.observe_f128_slice(b, &wires);
            let _ = ch.sample_f128(b);
            ch.observe_f128(b, &wires[3]);
            let _ = ch.sample_f128_vec(b, 3);
            ch.finish()
        }

        let build = |host_seed: u64, wire_seed: u64| {
            let host = {
                let mut scratch = FieldR1csBuilder::new_witness_only();
                record(&mut scratch, host_seed)
            };
            let layout = compile_duplex(&host.ops);
            let u_d = build_duplex_union(
                &layout,
                FsChannelUnionRecorder::capacity_iv_flat(),
                std::slice::from_ref(&host.data_flat),
            );
            let mut b = FieldR1csBuilder::new();
            let real = record(&mut b, wire_seed);
            assert_eq!(real.ops, host.ops, "class-fixed recording schedule");
            let slices: Vec<WitnessSlice> = u_d
                .committed
                .iter()
                .map(|col| alloc_column_slice(&mut b, col, u_d.w_log).0)
                .collect();
            for (kk, &(slot, lane)) in layout.challenges.iter().enumerate() {
                pin_eq(
                    &mut b,
                    &real.challenge_wires[kk],
                    &slot_cell(&slices[u_d.refs.c[lane]], slot),
                );
            }
            let data_positions = duplex_data_positions(&layout);
            for (kk, &(slot, lane)) in data_positions.iter().enumerate() {
                pin_eq(
                    &mut b,
                    &real.data_wires[kk],
                    &slot_cell(&slices[u_d.refs.a[lane]], slot),
                );
            }
            let first_data = {
                let (slot, lane) = data_positions[0];
                slices[u_d.refs.a[lane]].start() + slot
            };
            let first_challenge = {
                let (slot, lane) = layout.challenges[0];
                slices[u_d.refs.c[lane]].start() + slot
            };
            let (r1cs, witness) = b.build();
            (r1cs, witness, first_data, first_challenge)
        };

        let (r1cs, honest, data_cell, challenge_cell) = build(0xC001, 0xC001);
        assert!(r1cs.satisfies(&honest), "honest C->D pins");
        for cell in [data_cell, challenge_cell] {
            let mut bad = honest.clone();
            bad[cell] += F128::ONE;
            assert!(!r1cs.satisfies(&bad), "mutated hosted D cell {cell}");
        }

        let (mixed_r1cs, mixed, _, _) = build(0xC001, 0xC002);
        assert!(
            !mixed_r1cs.satisfies(&mixed),
            "C proof wires mixed with another D recording"
        );
    }

    /// TWO-REGION union: region 1 tiles K=2 channel blocks, region 2 hosts two
    /// RECORDED LANECHAL transcripts of different sizes (descending-size dyadic
    /// packing, per-set gated patterns). Honest: satisfiable, every opening
    /// claim true against the committed columns natively, claim count equal to
    /// the single-region discharge (recordings add pins, not claims), and the
    /// build's recording challenges equal the recorder's. Negatives: corrupting
    /// a recording's absorbed-data stream (fed to the union build) breaks the
    /// data-cell pins — the twin's proof wires no longer match the walk-proven
    /// chain — and corrupting an early lane also drags every downstream
    /// challenge pin along; both must be unsatisfiable.
    #[test]
    fn duplex_union_two_region_recording_binding() {
        use noid_ivc_core::lincheck::build_eq_table;

        let layout = compile_duplex(&channel_ops());
        let data: Vec<Vec<F128>> = (0..2)
            .map(|t| tx_data(&layout, 0xBEEF_0000 + t as u64))
            .collect();

        // Two synthetic recorded transcripts of DIFFERENT lengths (the second
        // exercises `sample_f128_vec` and lands in a smaller dyadic block).
        let record = |b: &mut FieldR1csBuilder, domain: &[u8], n_wires: usize, vec_draw: bool| {
            let wires: Vec<LinExpr> = (0..n_wires)
                .map(|i| {
                    let v = F128 {
                        lo: 0x1111 * (i as u64 + 1),
                        hi: 0x77 ^ i as u64,
                    };
                    LinExpr::from_wire(b.alloc_f128(v))
                })
                .collect();
            let mut rec = FsChannelUnionRecorder::new(domain);
            rec.observe_label(b, b"two-region-unit");
            rec.observe_f128_slice(b, &wires);
            let _c1 = rec.sample_f128(b);
            rec.observe_f128(b, &wires[0]);
            if vec_draw {
                let _cv = rec.sample_f128_vec(b, 3);
            }
            rec.observe_f128_slice(b, &wires[..n_wires / 2]);
            let _c2 = rec.sample_f128(b);
            // Trailing absorbs AFTER the last squeeze: corrupting these
            // lanes breaks ONLY their data pins (no downstream
            // challenge). The tail deliberately ends at ODD lane parity
            // (2-lane observe + 3-lane slice = 5 lanes): the last data
            // lane sits alone in a trailing partial-absorb slot, which
            // `compile_duplex` must flush — the real walk discharges end
            // this way, and an unflushed lane would be unpinnable.
            rec.observe_f128(b, &wires[1]);
            rec.observe_f128_slice(b, &wires[..2]);
            rec.finish()
        };

        let run = |corrupt: Option<(usize, usize)>| -> bool {
            let mut b = FieldR1csBuilder::new();
            let rec_a = record(&mut b, b"two-region-rec-a", 24, false);
            let rec_b = record(&mut b, b"two-region-rec-b", 6, true);
            let recs = [&rec_a, &rec_b];
            let mut rec_data: Vec<Vec<F128>> = recs.iter().map(|r| r.data_flat.clone()).collect();
            if let Some((r, lane)) = corrupt {
                rec_data[r][lane] += F128::ONE;
            }
            let rec_iv = FsChannelUnionRecorder::capacity_iv_flat();
            let rec_specs: Vec<RecordingSpec> = recs
                .iter()
                .zip(rec_data.iter())
                .map(|(rc, d)| RecordingSpec {
                    layout: compile_duplex(&rc.ops),
                    iv_flat: rec_iv,
                    data: d,
                })
                .collect();
            let u = build_duplex_union_with_recordings(&layout, iv_flat(), &data, &rec_specs);
            let native = run_duplex_union_native(&u, b"two-region-unit");

            let slices: Vec<WitnessSlice> = u
                .committed
                .iter()
                .map(|c| alloc_column_slice(&mut b, c, u.w_log).0)
                .collect();
            let mut ch = FsChannelTrace::new(&mut b, b"two-region-unit");
            let claims = discharge_duplex_union(&mut b, &mut ch, &u, &native, 0);
            // Region-1 challenge pins (the per-tx algebra path) + the
            // recording pins (the plural's region-2 discipline).
            let per_tx = 1usize << u.block_log;
            for tx in 0..2 {
                for (kk, &(slot, lane)) in u.layout.challenges.iter().enumerate() {
                    let w = LinExpr::from_wire(b.alloc_f128(u.challenges[tx][kk]));
                    pin_eq(
                        &mut b,
                        &w,
                        &slot_cell(&slices[u.refs.c[lane]], tx * per_tx + slot),
                    );
                }
            }
            for (r, rc) in recs.iter().enumerate() {
                let (rec_layout, off) = &u.rec_blocks[r];
                assert_eq!(rc.challenge_wires.len(), rec_layout.challenges.len());
                assert_eq!(rc.data_wires.len(), rec_layout.n_data);
                for (kk, &(slot, lane)) in rec_layout.challenges.iter().enumerate() {
                    pin_eq(
                        &mut b,
                        &rc.challenge_wires[kk],
                        &slot_cell(&slices[u.refs.c[lane]], off + slot),
                    );
                }
                for (kk, &(slot, lane)) in duplex_data_positions(rec_layout).iter().enumerate() {
                    pin_eq(
                        &mut b,
                        &rc.data_wires[kk],
                        &slot_cell(&slices[u.refs.a[lane]], off + slot),
                    );
                }
            }

            if corrupt.is_none() {
                // Structure: dyadic packing puts the LARGER recording first
                // and both blocks after region 1; claim count matches the
                // single-region discharge (flatness — recordings are pins).
                let (la, oa) = &u.rec_blocks[0];
                let (lb, ob) = &u.rec_blocks[1];
                let sz = |l: &DuplexLayout| l.slots.len().next_power_of_two();
                assert!(sz(la) >= sz(lb), "recording sizes");
                assert!(
                    *oa >= 2 * per_tx && *ob == oa + sz(la),
                    "descending packing"
                );
                let u1 = build_duplex_union(&layout, iv_flat(), &data);
                let n1 = run_duplex_union_native(&u1, b"two-region-unit");
                let mut b1 = FieldR1csBuilder::new();
                for col in u1.committed.iter() {
                    alloc_column_slice(&mut b1, col, u1.w_log);
                }
                let mut ch1 = FsChannelTrace::new(&mut b1, b"two-region-unit");
                let c1 = discharge_duplex_union(&mut b1, &mut ch1, &u1, &n1, 0);
                assert_eq!(
                    claims.len(),
                    c1.len(),
                    "recording-bearing union claim flatness"
                );
                // Recorder challenges match the union build's chain.
                for (r, rc) in recs.iter().enumerate() {
                    assert_eq!(
                        u.rec_challenges[r].len(),
                        rc.challenge_wires.len(),
                        "recording {r} challenge stream"
                    );
                }
                // Every opening claim is true against the committed columns.
                for c in &claims {
                    let eq = build_eq_table(&c.native_point);
                    let mut acc = F128::ZERO;
                    for (v, e) in u.committed[c.slice].iter().zip(eq.iter()) {
                        acc += *v * *e;
                    }
                    assert_eq!(acc, c.native_value, "claim false on column {}", c.slice);
                }
            }
            let (r1cs, z) = b.build();
            r1cs.satisfies(&z)
        };

        assert!(run(None), "honest two-region union unsatisfiable");
        // rec_a data lanes: 24 (slice) + 1 + 12 (slice) + 1 + 2 (tail) = 40;
        // lane 39 is the odd trailing lane living in the flushed partial slot.
        assert!(
            !run(Some((0, 39))),
            "corrupted trailing recording data slipped through the data pin"
        );
        assert!(
            !run(Some((1, 0))),
            "corrupted early lane slipped through the challenge/data pins"
        );
    }

    /// The channel union discharged through the REAL outer PCS: the 6 committed
    /// columns live as witness slices, the whole claim DAG (selection → walk →
    /// substitution → carry shifts) is replayed in-trace, and every terminal +
    /// every squeezed-challenge read becomes an opening claim against the
    /// committed witness. Flipping the committed carry cell that a challenge is
    /// read from makes exactly that opening claim false — the BaseFold layer
    /// rejects, proving the squeezed challenge is bound to the walk-proven
    /// carry cell (not a value the prover is free to choose).
    #[test]
    fn duplex_union_slot_end_to_end() {
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec};
        use noid_ivc_core::verifier::verify_field_with_public_io;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;

        const OUTER: &[u8] = b"duplex-union-slot-outer";
        let layout = compile_duplex(&channel_ops());
        let k = 2usize;
        let data: Vec<Vec<F128>> = (0..k)
            .map(|t| tx_data(&layout, 0xC0FE_0000 + t as u64))
            .collect();
        let u = build_duplex_union(&layout, iv_flat(), &data);
        let native = run_duplex_union_native(&u, b"duplex-union-slot");
        let w_log = u.w_log;

        let mut b = FieldR1csBuilder::new();
        let slices: Vec<WitnessSlice> = u
            .committed
            .iter()
            .map(|c| alloc_column_slice(&mut b, c, w_log).0)
            .collect();
        let mut ch = FsChannelTrace::new(&mut b, b"duplex-union-slot");
        let mut claims = discharge_duplex_union(&mut b, &mut ch, &u, &native, 0);
        for t in 0..k {
            let _ = read_duplex_challenges(&mut b, &u, t, 0, &mut claims);
        }

        let lanes_per_claim = w_log + 1;
        let io_len = claims.len() * lanes_per_claim;
        let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
        let mut io_values = Vec::with_capacity(io_len);
        for c in &claims {
            assert_eq!(c.native_point.len(), w_log, "claim point arity");
            io_values.extend_from_slice(&c.native_point);
            io_values.push(c.native_value);
        }
        let (io_slice, io_wires) = alloc_column_slice(&mut b, &io_values, io_log);
        for (ci, c) in claims.iter().enumerate() {
            let base = ci * lanes_per_claim;
            for (k, p) in c.point.iter().enumerate() {
                pin_eq(&mut b, p, &io_wires[base + k]);
            }
            pin_eq(&mut b, &c.value, &io_wires[base + w_log]);
        }
        let spec = PublicIoSpec {
            io_slice,
            io_len,
            claims: claims
                .iter()
                .enumerate()
                .map(|(ci, c)| IoClaimSpec {
                    slice: slices[c.slice],
                    point: ci * lanes_per_claim..ci * lanes_per_claim + w_log,
                    value: ci * lanes_per_claim + w_log,
                })
                .collect(),
        };

        let (r1cs, z) = b.build();
        assert!(
            r1cs.satisfies(&z),
            "honest duplex-union trace unsatisfiable"
        );
        let params = PcsParams {
            m: r1cs.m + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let mut ch_p = FsLaneChallenger::new(OUTER);
        let (proof, commitment, _) =
            prove_field_with_public_io(&r1cs, &z, &params, &spec, &io_values, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(OUTER);
        verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io_values, &mut ch_v)
            .expect("the duplex-union slot proof verifies");
        eprintln!(
            "[duplex-union-slot] K={}, rows={} (m={}), opening claims={}",
            k,
            z.len(),
            r1cs.m,
            spec.claims.len()
        );

        // Money negative: flip the committed carry cell that tx 0's first
        // squeezed challenge is read from. The trace stays satisfiable (columns
        // are free wires) but that challenge's opening claim is now false.
        let (chal_slot, chal_lane) = u.layout.challenges[0];
        let col = slices[u.refs.c[chal_lane]];
        let mut bad_z = z.clone();
        bad_z[col.start() + chal_slot] += F128::ONE;
        assert!(r1cs.satisfies(&bad_z), "committed columns are free wires");
        let mut ch_p = FsLaneChallenger::new(OUTER);
        let (bad_proof, bad_commitment, _) =
            prove_field_with_public_io(&r1cs, &bad_z, &params, &spec, &io_values, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(OUTER);
        assert!(
            verify_field_with_public_io(
                &r1cs,
                &bad_commitment,
                &bad_proof,
                &spec,
                &io_values,
                &mut ch_v
            )
            .is_err(),
            "flipping a challenge's carry cell must break its opening claim"
        );
    }

    /// [G] step 4 Stage 2 SOUNDNESS: a RAW-READ committed cell is bound by its
    /// column's single walk opening — no per-cell opening claim needed. This is
    /// the invariant the Stage-2 claim collapse rests on: the walk selection
    /// opens each carry column at ONE random point (Schwartz–Zippel binds every
    /// cell), so the per-tx challenge/absorb reads can drop their per-cell claims
    /// and read the committed cell directly. Here we discharge ONLY the walk
    /// (no `read_duplex_challenges`), raw-read a squeezed challenge straight out
    /// of its carry cell, and show: honest verifies + the raw-read carries the
    /// native challenge value; flipping that carry cell leaves the trace
    /// satisfiable (the cell is unconstrained by the trace — no per-cell claim)
    /// yet breaks the column's selection opening → the PCS rejects. So the
    /// raw-read value is provably the correct squeezed challenge.
    #[test]
    fn duplex_union_raw_read_binding() {
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec};
        use noid_ivc_core::verifier::verify_field_with_public_io;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;

        const OUTER: &[u8] = b"duplex-raw-read-outer";
        let layout = compile_duplex(&channel_ops());
        let data: Vec<Vec<F128>> = (0..2)
            .map(|t| tx_data(&layout, 0x5EED_0000 + t as u64))
            .collect();
        let u = build_duplex_union(&layout, iv_flat(), &data);
        let native = run_duplex_union_native(&u, b"duplex-raw-read");
        let w_log = u.w_log;

        let mut b = FieldR1csBuilder::new();
        let slices: Vec<WitnessSlice> = u
            .committed
            .iter()
            .map(|c| alloc_column_slice(&mut b, c, w_log).0)
            .collect();
        // Discharge ONLY the walk (selection -> walk -> substitution -> shifts).
        // NO per-cell challenge reads: the Stage-2 pattern raw-reads instead.
        let mut ch = FsChannelTrace::new(&mut b, b"duplex-raw-read");
        let claims = discharge_duplex_union(&mut b, &mut ch, &u, &native, 0);

        // RAW-READ tx 0's first squeezed challenge straight out of its carry cell
        // (no fresh wire, no per-cell claim): the cell wire IS the challenge.
        let (chal_slot, chal_lane) = u.layout.challenges[0];
        let c_col = slices[u.refs.c[chal_lane]];
        let chal = LinExpr::from_wire(noid_ivc_core::field_circuit::Wire(
            (c_col.start() + chal_slot) as u32,
        ));

        // Wire the walk claims into the PCS (uniform w_log-arity points).
        let lanes_per = w_log + 1;
        let io_len = claims.len() * lanes_per;
        let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
        let mut io_values = Vec::with_capacity(io_len);
        for c in &claims {
            io_values.extend_from_slice(&c.native_point);
            io_values.push(c.native_value);
        }
        let (io_slice, io_wires) = alloc_column_slice(&mut b, &io_values, io_log);
        for (ci, c) in claims.iter().enumerate() {
            let base = ci * lanes_per;
            for (kk, p) in c.point.iter().enumerate() {
                pin_eq(&mut b, p, &io_wires[base + kk]);
            }
            pin_eq(&mut b, &c.value, &io_wires[base + w_log]);
        }
        let spec = PublicIoSpec {
            io_slice,
            io_len,
            claims: claims
                .iter()
                .enumerate()
                .map(|(ci, c)| IoClaimSpec {
                    slice: slices[c.slice],
                    point: ci * lanes_per..ci * lanes_per + w_log,
                    value: ci * lanes_per + w_log,
                })
                .collect(),
        };

        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest raw-read trace unsatisfiable");
        // The raw-read cell carries exactly the native squeezed challenge.
        assert_eq!(
            chal.eval(&z),
            u.challenges[0][0],
            "raw-read == native challenge"
        );
        let params = PcsParams {
            m: r1cs.m + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let mut ch_p = FsLaneChallenger::new(OUTER);
        let (proof, commitment, _) =
            prove_field_with_public_io(&r1cs, &z, &params, &spec, &io_values, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(OUTER);
        verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io_values, &mut ch_v)
            .expect("honest raw-read proof verifies");

        // Flip the raw-read carry cell: the trace stays satisfiable (no per-cell
        // claim constrains it) but the column's selection opening is now false.
        let mut bad_z = z.clone();
        bad_z[c_col.start() + chal_slot] += F128::ONE;
        assert!(
            r1cs.satisfies(&bad_z),
            "the raw-read cell is unconstrained by the trace"
        );
        let mut ch_p = FsLaneChallenger::new(OUTER);
        let (bad_proof, bad_commitment, _) =
            prove_field_with_public_io(&r1cs, &bad_z, &params, &spec, &io_values, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(OUTER);
        assert!(
            verify_field_with_public_io(
                &r1cs,
                &bad_commitment,
                &bad_proof,
                &spec,
                &io_values,
                &mut ch_v
            )
            .is_err(),
            "flipping a raw-read carry cell must break the column's walk opening"
        );
    }

    /// Transaction-count independence: doubling K raises the tiled domain by one
    /// bit, so the ONE channel walk gains exactly one sumcheck round —
    /// logarithmic, not the K-fold of K inline channel replays.
    #[test]
    fn duplex_union_walk_is_flat() {
        let layout = compile_duplex(&channel_ops());
        let rounds = |k: usize| {
            let data: Vec<Vec<F128>> = (0..k)
                .map(|t| tx_data(&layout, 0xF1A7_0000 + t as u64))
                .collect();
            let u = build_duplex_union(&layout, iv_flat(), &data);
            run_duplex_union_native(&u, b"flat").walk_proof.layers[0]
                .round_coeffs
                .len()
        };
        let r1 = rounds(1);
        assert_eq!(rounds(2), r1 + 1, "K:1->2 adds one walk round");
        assert_eq!(rounds(4), r1 + 2, "K:1->4 adds two walk rounds");
        assert_eq!(rounds(8), r1 + 3, "K:1->8 adds three walk rounds");
    }
}

/// [G] step 4 — the HETEROGENEOUS duplex-union walk C: K txs, each carrying N
/// DIFFERENT Poseidon2b channels (different IVs, different op layouts), tiled into
/// ONE data-parallel walk and discharged ONCE. This is the memory optimization
/// that lets the owner-auth KSCHANNL and the wallet-PCS FRICHANL channels share
/// ONE walk-C instead of two.
#[cfg(test)]
mod combined_duplex_union_tests {
    use super::*;
    use noid_ivc_core::deep_chain::schedule::TranscriptOp;
    use noid_poseidon2b::native::domain::DomainTag;

    fn iv_flat(tag: DomainTag) -> [F128; 2] {
        let iv = capacity_iv(tag);
        [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
    }

    /// Channel 0 (FRICHANL-shaped): 7 slots, 6 data lanes, 5 squeezed challenges —
    /// a three-lane absorb, a constant-lane absorb, a two-challenge squeeze, an
    /// absorb-after-squeeze reset, and a pad-flush squeeze.
    fn channel0_ops() -> Vec<TranscriptOp> {
        const TAG: u128 = 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10;
        vec![
            TranscriptOp::Absorb(vec![None, None, None]),
            TranscriptOp::Absorb(vec![Some(TAG)]),
            TranscriptOp::Squeeze(2),
            TranscriptOp::Absorb(vec![None, None]),
            TranscriptOp::Absorb(vec![None]),
            TranscriptOp::Squeeze(3),
        ]
    }

    /// Channel 1 (KSCHANNL-shaped, deliberately DIFFERENT counts): 4 slots, 3 data
    /// lanes, 3 challenges — a two-lane absorb, a one-challenge squeeze, then an
    /// absorb + pad-flush two-challenge squeeze.
    fn channel1_ops() -> Vec<TranscriptOp> {
        vec![
            TranscriptOp::Absorb(vec![None, None]),
            TranscriptOp::Squeeze(1),
            TranscriptOp::Absorb(vec![None]),
            TranscriptOp::Squeeze(2),
        ]
    }

    /// Channel 2 (a THIRD distinct shape, for the N=3→4 ghost-sub padding test): 3
    /// slots, 4 data lanes, 2 challenges.
    fn channel2_ops() -> Vec<TranscriptOp> {
        vec![
            TranscriptOp::Absorb(vec![None, None, None, None]),
            TranscriptOp::Squeeze(2),
        ]
    }

    fn tx_data(layout: &DuplexLayout, seed: u64) -> Vec<F128> {
        let mut r = seed;
        (0..layout.n_data)
            .map(|_| {
                r = r.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(0x1234_5);
                F128 {
                    lo: r,
                    hi: r.rotate_left(29) ^ 0xA5A5,
                }
            })
            .collect()
    }

    fn s_log_of(subs: &[SubChannel]) -> usize {
        subs.iter()
            .map(|c| c.layout.slots.len())
            .max()
            .unwrap()
            .max(1)
            .next_power_of_two()
            .trailing_zeros() as usize
    }

    /// CORRECTNESS vs SEPARATE (the carry-reset proof): building two DIFFERENT
    /// channels into ONE combined union yields, per tx, EXACTLY the challenges each
    /// channel squeezes when tiled alone. That is only possible if each
    /// sub-channel re-seeds its own IV at `i·S` (START=1 there) and does NOT inherit
    /// the previous sub-channel's final carry — i.e. zero cross-channel bleed. Also
    /// checks the data-position map agrees with the combined layout and the
    /// heterogeneous native walk discharges.
    #[test]
    fn combined_correctness_vs_separate() {
        let ch0 = compile_duplex(&channel0_ops());
        let ch1 = compile_duplex(&channel1_ops());
        assert_eq!(
            (ch0.slots.len(), ch0.n_data, ch0.challenges.len()),
            (7, 6, 5)
        );
        assert_eq!(
            (ch1.slots.len(), ch1.n_data, ch1.challenges.len()),
            (4, 3, 3)
        );
        let iv0 = iv_flat(TAG_FRICHANL);
        let iv1 = iv_flat(TAG_KSCHANNL);
        assert_ne!(iv0, iv1, "the two channels must carry different IVs");
        let subs = vec![
            SubChannel {
                layout: ch0.clone(),
                iv_flat: iv0,
            },
            SubChannel {
                layout: ch1.clone(),
                iv_flat: iv1,
            },
        ];
        let k = 2usize;
        let data: Vec<Vec<Vec<F128>>> = (0..k)
            .map(|t| {
                vec![
                    tx_data(&ch0, 0x1000 + t as u64),
                    tx_data(&ch1, 0x2000 + t as u64),
                ]
            })
            .collect();
        let u = build_combined_duplex_union(&subs, &data);

        // Homogeneous unions for each channel ALONE (same per-tx data streams).
        let data0: Vec<Vec<F128>> = (0..k).map(|t| tx_data(&ch0, 0x1000 + t as u64)).collect();
        let data1: Vec<Vec<F128>> = (0..k).map(|t| tx_data(&ch1, 0x2000 + t as u64)).collect();
        let h0 = build_duplex_union(&ch0, iv0, &data0);
        let h1 = build_duplex_union(&ch1, iv1, &data1);

        let (n0, n1) = (ch0.challenges.len(), ch1.challenges.len());
        assert_eq!(u.challenges.len(), k);
        for t in 0..k {
            assert_eq!(
                u.challenges[t].len(),
                n0 + n1,
                "concatenated challenge count"
            );
            assert_eq!(
                &u.challenges[t][0..n0],
                h0.challenges[t].as_slice(),
                "channel 0 squeezes exactly its standalone challenges (no cross-channel bleed)"
            );
            assert_eq!(
                &u.challenges[t][n0..n0 + n1],
                h1.challenges[t].as_slice(),
                "channel 1 squeezes exactly its standalone challenges (no cross-channel bleed)"
            );
        }
        assert_ne!(
            u.challenges[0], u.challenges[1],
            "distinct tx data ⇒ distinct challenges"
        );

        // Data indices are renumbered into one flattened stream.
        assert_eq!(
            duplex_data_positions(&u.layout).len(),
            ch0.n_data + ch1.n_data,
            "one position per real data lane"
        );

        // The heterogeneous walk discharges natively (soundness of the shared DAG).
        let _ = run_duplex_union_native(&u, b"combined-correctness");
    }

    /// GHOST padding: N=3 (padded to 4 with a canonical IV-seeded ghost sub-channel)
    /// AND K=3 (padded to 4 tx-blocks with zero-data ghost tiles) still recovers
    /// each real channel's standalone challenges and discharges natively — the pads
    /// are valid chains, re-seeded by START, not `perm([0;4])` ghost slots.
    #[test]
    fn combined_ghost_padding() {
        let ch0 = compile_duplex(&channel0_ops());
        let ch1 = compile_duplex(&channel1_ops());
        let ch2 = compile_duplex(&channel2_ops());
        let iv0 = iv_flat(TAG_FRICHANL);
        let iv1 = iv_flat(TAG_KSCHANNL);
        let iv2 = [
            flat_of_tower_u128(0xA5A5_5A5A_1234_5678_9ABC_DEF0_0F1E_2D3C),
            flat_of_tower_u128(0x5A5A_A5A5_8765_4321_0FED_CBA9_C3D2_E1F0),
        ];
        let subs = vec![
            SubChannel {
                layout: ch0.clone(),
                iv_flat: iv0,
            },
            SubChannel {
                layout: ch1.clone(),
                iv_flat: iv1,
            },
            SubChannel {
                layout: ch2.clone(),
                iv_flat: iv2,
            },
        ];
        let k = 3usize; // K=3 -> padded to 4 tx-blocks (ghost tile).
        let data: Vec<Vec<Vec<F128>>> = (0..k)
            .map(|t| {
                vec![
                    tx_data(&ch0, 0x11 + t as u64),
                    tx_data(&ch1, 0x22 + t as u64),
                    tx_data(&ch2, 0x33 + t as u64),
                ]
            })
            .collect();
        let u = build_combined_duplex_union(&subs, &data);

        // N padded to 4 → per-tx period = 4·S.
        let s = 1usize << s_log_of(&subs);
        assert_eq!(1usize << u.block_log, 4 * s, "N padded to a power of two");

        let mk = |layout: &DuplexLayout, iv: [F128; 2], base: u64| {
            let d: Vec<Vec<F128>> = (0..k).map(|t| tx_data(layout, base + t as u64)).collect();
            build_duplex_union(layout, iv, &d)
        };
        let h0 = mk(&ch0, iv0, 0x11);
        let h1 = mk(&ch1, iv1, 0x22);
        let h2 = mk(&ch2, iv2, 0x33);
        let (n0, n1, n2) = (
            ch0.challenges.len(),
            ch1.challenges.len(),
            ch2.challenges.len(),
        );
        assert_eq!(
            u.challenges.len(),
            k,
            "K real tx challenge streams (ghost tile excluded)"
        );
        for t in 0..k {
            assert_eq!(u.challenges[t].len(), n0 + n1 + n2);
            assert_eq!(&u.challenges[t][0..n0], h0.challenges[t].as_slice());
            assert_eq!(&u.challenges[t][n0..n0 + n1], h1.challenges[t].as_slice());
            assert_eq!(
                &u.challenges[t][n0 + n1..n0 + n1 + n2],
                h2.challenges[t].as_slice()
            );
        }
        // The padded (ghost sub + ghost tile) domain still discharges natively.
        let _ = run_duplex_union_native(&u, b"combined-ghost");
    }

    /// The carry reset is LOAD-BEARING (the correctness crux, verified — not just
    /// reasoned). First, structurally: START=1 lands EXACTLY at each sub-channel's
    /// boundary `i·S` and the capacity IV is seeded on the const2/const3 lanes there.
    /// Then, behaviourally: removing the START=1 at the SECOND sub-channel's boundary
    /// makes the heterogeneous discharge NO LONGER verify — the substitution wiring
    /// `(1+START)·C(w−1)` then reads the previous channel's final carry instead of
    /// the IV reset the columns actually used, so the terminal claim is false and
    /// `run_duplex_union_native`'s internal verify panics.
    #[test]
    fn carry_reset_is_load_bearing() {
        let ch0 = compile_duplex(&channel0_ops());
        let ch1 = compile_duplex(&channel1_ops());
        let iv0 = iv_flat(TAG_FRICHANL);
        let iv1 = iv_flat(TAG_KSCHANNL);
        let subs = vec![
            SubChannel {
                layout: ch0.clone(),
                iv_flat: iv0,
            },
            SubChannel {
                layout: ch1.clone(),
                iv_flat: iv1,
            },
        ];
        let data: Vec<Vec<Vec<F128>>> = (0..2)
            .map(|t| {
                vec![
                    tx_data(&ch0, 0x900 + t as u64),
                    tx_data(&ch1, 0xA00 + t as u64),
                ]
            })
            .collect();
        let u = build_combined_duplex_union(&subs, &data);
        let s = 1usize << s_log_of(&subs);

        // Structural: START is ONE exactly at the two sub-channel boundaries {0, S}.
        let start = &u.fixed[u.refs.start];
        let ones: Vec<usize> = start
            .table
            .iter()
            .enumerate()
            .filter(|(_, v)| **v == F128::ONE)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            ones,
            vec![0, s],
            "START resets each sub-channel's carry at i·S"
        );
        // Structural: each boundary seeds its OWN channel's capacity IV.
        assert_eq!(u.fixed[u.refs.consts[2]].table[0], iv0[0]);
        assert_eq!(u.fixed[u.refs.consts[3]].table[0], iv0[1]);
        assert_eq!(u.fixed[u.refs.consts[2]].table[s], iv1[0]);
        assert_eq!(u.fixed[u.refs.consts[3]].table[s], iv1[1]);

        // Honest discharge verifies.
        let _ = run_duplex_union_native(&u, b"carry-reset");

        // Behavioural: remove the reset at sub-channel 1's boundary → the shared
        // discharge must fail (substitution terminal is now false).
        let mut bad = build_combined_duplex_union(&subs, &data);
        bad.fixed[bad.refs.start].table[s] = F128::ZERO;
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // silence the expected panic log
        let broke = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = run_duplex_union_native(&bad, b"carry-reset");
        }));
        std::panic::set_hook(prev);
        assert!(
            broke.is_err(),
            "removing the carry reset must break the heterogeneous discharge"
        );
    }

    /// ONE discharge binds BOTH channels through the REAL outer PCS. The 6 committed
    /// columns live as witness slices; ONE selection → walk → substitution → shift
    /// discharge opens every A/C column at ONE random point; each tx's squeezed
    /// challenges are read from the carry cells as opening claims. Honest verifies;
    /// flipping a channel-0 carry cell breaks that column's opening (reject), and so
    /// does flipping a channel-1 carry cell — BOTH bound by the ONE walk.
    #[test]
    fn combined_one_discharge_binds_both() {
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec};
        use noid_ivc_core::verifier::verify_field_with_public_io;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;

        const DOM: &[u8] = b"combined-duplex-binds-both";
        const OUTER: &[u8] = b"combined-duplex-binds-both-outer";
        let ch0 = compile_duplex(&channel0_ops());
        let ch1 = compile_duplex(&channel1_ops());
        let iv0 = iv_flat(TAG_FRICHANL);
        let iv1 = iv_flat(TAG_KSCHANNL);
        let subs = vec![
            SubChannel {
                layout: ch0.clone(),
                iv_flat: iv0,
            },
            SubChannel {
                layout: ch1.clone(),
                iv_flat: iv1,
            },
        ];
        let k = 2usize;
        let data: Vec<Vec<Vec<F128>>> = (0..k)
            .map(|t| {
                vec![
                    tx_data(&ch0, 0xC0FE_0000 + t as u64),
                    tx_data(&ch1, 0xBEEF_0000 + t as u64),
                ]
            })
            .collect();
        let u = build_combined_duplex_union(&subs, &data);
        let native = run_duplex_union_native(&u, DOM);
        let w_log = u.w_log;

        // Build the trace: 6 committed columns as slices, ONE union discharge, and
        // each tx's challenges read from the carry cells.
        let mut b = FieldR1csBuilder::new();
        let slices: Vec<WitnessSlice> = u
            .committed
            .iter()
            .map(|c| alloc_column_slice(&mut b, c, w_log).0)
            .collect();
        let mut ch = FsChannelTrace::new(&mut b, DOM);
        let mut claims = discharge_duplex_union(&mut b, &mut ch, &u, &native, 0);
        for t in 0..k {
            let _ = read_duplex_challenges(&mut b, &u, t, 0, &mut claims);
        }

        // Wire every claim into the outer PCS public IO (uniform w_log-arity points).
        let lanes_per = w_log + 1;
        let io_len = claims.len() * lanes_per;
        let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
        let mut io_values = Vec::with_capacity(io_len);
        for c in &claims {
            assert_eq!(c.native_point.len(), w_log, "claim point arity");
            io_values.extend_from_slice(&c.native_point);
            io_values.push(c.native_value);
        }
        let (io_slice, io_wires) = alloc_column_slice(&mut b, &io_values, io_log);
        for (ci, c) in claims.iter().enumerate() {
            let base = ci * lanes_per;
            for (kk, p) in c.point.iter().enumerate() {
                pin_eq(&mut b, p, &io_wires[base + kk]);
            }
            pin_eq(&mut b, &c.value, &io_wires[base + w_log]);
        }
        let spec = PublicIoSpec {
            io_slice,
            io_len,
            claims: claims
                .iter()
                .enumerate()
                .map(|(ci, c)| IoClaimSpec {
                    slice: slices[c.slice],
                    point: ci * lanes_per..ci * lanes_per + w_log,
                    value: ci * lanes_per + w_log,
                })
                .collect(),
        };

        let (r1cs, z) = b.build();
        assert!(
            r1cs.satisfies(&z),
            "honest combined-union trace unsatisfiable"
        );
        assert!(z.len() < (1usize << 21), "wire-count guard");
        let params = PcsParams {
            m: r1cs.m + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let mut ch_p = FsLaneChallenger::new(OUTER);
        let (proof, commitment, _) =
            prove_field_with_public_io(&r1cs, &z, &params, &spec, &io_values, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(OUTER);
        verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io_values, &mut ch_v)
            .expect("honest combined-union proof verifies");
        eprintln!(
            "[combined-duplex] N=2 K={k} rows={} (m={}) claims={} — ONE walk binds both channels",
            z.len(),
            r1cs.m,
            spec.claims.len()
        );

        // The two channels' challenge slots (channel 0 first, channel 1 after) —
        // both in tx 0's tiled block.
        let (n0, _n1) = (ch0.challenges.len(), ch1.challenges.len());
        let reject_flip = |slot_lane: (usize, usize), label: &str| {
            let (slot, lane) = slot_lane;
            let col = slices[u.refs.c[lane]];
            let mut bad_z = z.clone();
            bad_z[col.start() + slot] += F128::ONE;
            assert!(
                r1cs.satisfies(&bad_z),
                "committed columns are free wires ({label})"
            );
            let mut ch_p = FsLaneChallenger::new(OUTER);
            let (bad_proof, bad_commitment, _) =
                prove_field_with_public_io(&r1cs, &bad_z, &params, &spec, &io_values, &mut ch_p);
            let mut ch_v = FsLaneChallenger::new(OUTER);
            assert!(
                verify_field_with_public_io(
                    &r1cs,
                    &bad_commitment,
                    &bad_proof,
                    &spec,
                    &io_values,
                    &mut ch_v
                )
                .is_err(),
                "flipping a {label} carry cell must break its opening claim"
            );
        };
        // NEGATIVE A: a channel-0 carry cell (its first squeezed challenge slot).
        reject_flip(u.layout.challenges[0], "channel-0");
        // NEGATIVE B: a channel-1 carry cell (its first squeezed challenge slot,
        // in the i=1 sub-block).
        reject_flip(u.layout.challenges[n0], "channel-1");
    }

    /// FLATNESS: doubling K raises the tiled domain by one bit, so the ONE shared
    /// walk gains exactly ONE sumcheck round — not a second walk. Prints the K=1 vs
    /// K=2 full-trace wire counts (they grow only by the per-tx tiles + one round).
    #[test]
    fn combined_walk_is_flat() {
        let ch0 = compile_duplex(&channel0_ops());
        let ch1 = compile_duplex(&channel1_ops());
        let iv0 = iv_flat(TAG_FRICHANL);
        let iv1 = iv_flat(TAG_KSCHANNL);
        let subs = vec![
            SubChannel {
                layout: ch0.clone(),
                iv_flat: iv0,
            },
            SubChannel {
                layout: ch1.clone(),
                iv_flat: iv1,
            },
        ];

        // Walk rounds (layer 0 sumcheck rounds) grow by exactly one per K-doubling.
        let walk_rounds = |k: usize| {
            let data: Vec<Vec<Vec<F128>>> = (0..k)
                .map(|t| {
                    vec![
                        tx_data(&ch0, 0xF00D + t as u64),
                        tx_data(&ch1, 0xBA5E + t as u64),
                    ]
                })
                .collect();
            let u = build_combined_duplex_union(&subs, &data);
            run_duplex_union_native(&u, b"combined-flat")
                .walk_proof
                .layers[0]
                .round_coeffs
                .len()
        };
        let r1 = walk_rounds(1);
        assert_eq!(
            walk_rounds(2),
            r1 + 1,
            "K:1->2 adds exactly one shared-walk round"
        );
        assert_eq!(
            walk_rounds(4),
            r1 + 2,
            "K:1->4 adds exactly two shared-walk rounds"
        );

        // Full-trace RAW wire counts (discharge + per-tx challenge reads), taken
        // BEFORE `build()` rounds up to a power of two — the padded `z.len()` would
        // hide the sub-linear growth (both K land in the same 2^m block).
        let trace_wires = |k: usize| -> usize {
            let data: Vec<Vec<Vec<F128>>> = (0..k)
                .map(|t| {
                    vec![
                        tx_data(&ch0, 0xF00D + t as u64),
                        tx_data(&ch1, 0xBA5E + t as u64),
                    ]
                })
                .collect();
            let u = build_combined_duplex_union(&subs, &data);
            let native = run_duplex_union_native(&u, b"combined-flat");
            let mut b = FieldR1csBuilder::new();
            for c in u.committed.iter() {
                alloc_column_slice(&mut b, c, u.w_log);
            }
            let mut ch = FsChannelTrace::new(&mut b, b"combined-flat");
            let mut claims = discharge_duplex_union(&mut b, &mut ch, &u, &native, 0);
            for t in 0..k {
                let _ = read_duplex_challenges(&mut b, &u, t, 0, &mut claims);
            }
            b.num_wires()
        };
        let w1 = trace_wires(1);
        let w2 = trace_wires(2);
        eprintln!(
            "[combined-duplex-flat] raw wires K=1: {w1}, K=2: {w2} (Δ={}) — shared walk, NOT a second walk (Δ ≪ w1)",
            w2 - w1
        );
        assert!(
            w2 < 2 * w1,
            "K=2 must NOT be a second walk (sub-linear wire growth)"
        );
        assert!(
            w2 - w1 < w1 / 2,
            "K-doubling grows the trace by ≪ a full walk"
        );
    }
}

pub(crate) fn recording_choice_weights(arms: usize, selector: F128) -> Vec<F128> {
    if arms == 2 {
        return vec![F128::ONE, selector];
    }
    assert_eq!(arms, 3);
    let nodes = [
        F128::ZERO,
        F128::ONE,
        noid_ivc_core::field_circuit::f128_from_u128(2),
    ];
    nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            nodes
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .fold(F128::ONE, |value, (_, other)| {
                    value * (selector + *other) * (*node + *other).inv()
                })
        })
        .collect()
}

pub(crate) fn duplex_substitution_terms_selected_n(
    sets: &[DuplexFamilyRefs],
    arms: usize,
    selector: F128,
    alpha: F128,
) -> Vec<RelationTerm> {
    if arms == 2 {
        return duplex_substitution_terms_selected(sets, selector, alpha);
    }
    assert_eq!(arms, 3);
    assert!(!sets.is_empty() && sets.len() % arms == 0);
    let m = duplex_mds_weights(alpha);
    let choices = recording_choice_weights(arms, selector);
    let mut terms = (0..STATE_SIZE)
        .map(|j| RelationTerm {
            coeff: m[j],
            factors: vec![ColRef::CommittedShift(sets[0].c[j])],
        })
        .collect::<Vec<_>>();
    for group in sets.chunks_exact(arms) {
        for (choice, set) in choices.iter().zip(group) {
            append_duplex_pattern_terms(&mut terms, set, &m.map(|weight| weight * *choice));
        }
    }
    terms
}
