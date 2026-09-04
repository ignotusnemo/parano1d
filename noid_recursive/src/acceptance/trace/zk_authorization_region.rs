// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(dead_code)]

//! Raw selected authorization-region reconstruction for the canonical ladder.
//!
//! This module reconstructs the four authorization children changed by the ZK
//! capsule: Owner/Main duplex, Wallet-A capsule leaves and Wallet-B FF paths.
//! Its only proof input is the opaque policy-verified batch owned by the
//! selected Block assembly. It accepts no independent statements, applies no
//! second proof-reuse policy, and reuses the batch's one ghost entry by
//! reference for every dead/PAD slot.
//!
//! The result is deliberately pre-allocation data: raw columns, native walk
//! endpoints and duplex layouts only. It cannot allocate a `WitnessSlice`,
//! construct a region VK, mint a preparation, or switch production LinkBlock.
//! A future common allocator must join it with canonical Meta data while the
//! same private selected assembly still owns the Block builder.

use std::collections::BTreeMap;

use noid_core::{Block128, Block256};
#[cfg(test)]
use noid_fri::hasher::CryptographicHasher;
use noid_fri_binius::capsule::{
    capsule_leaf_hash_mixed, capsule_leaf_hash_wide, CapsuleNodeHasher,
};
use noid_fri_binius::interleaved_commit::{
    expand_source_batched_merkle_proof_to_cap, IndependentSourceMerklePath,
    SourceBatchedMerkleProof, SourceHash,
};
use noid_fri_binius::zk_capsule_algebra::{
    map_source_query_leaf, ZkCapsuleAlgebraError, JOINT_SOURCE_LEAF_SYMBOLS, MID_STANDARD_FOLDS,
};
use noid_fri_binius::zk_capsule_pcs::{
    ZK_CAPSULE_PCS_MID_CAP_DEPTH, ZK_CAPSULE_PCS_MID_PATH_DEPTH, ZK_CAPSULE_PCS_MID_TREE_DEPTH,
    ZK_CAPSULE_PCS_QUERY_COUNT, ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH, ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
    ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH,
};
use noid_gkr::zk_authorization::{
    zk_auth_capsule_owner_dynamic_data, zk_authorization_main_dynamic_data, ZkAuthorizationError,
    ZK_AUTH_MAIN_TILE_LOG, ZK_AUTH_OWNER_TILE_LOG,
};
use noid_ivc_core::deep_chain::capsule_leaf::{
    build_c1_capsule_leaf_columns, raw_flat_lane, C1CapsuleLeafData, C1CapsuleLeafKind,
    C1_CAPSULE_LEAF_STRIDE, C1_CAPSULE_MID_SLOTS, C1_CAPSULE_SOURCE_SLOTS,
};
#[cfg(test)]
use noid_ivc_core::deep_chain::capsule_leaf::{
    C1_CAPSULE_MID_DIGEST_SLOT, C1_CAPSULE_SOURCE_DIGEST_SLOT,
};
use noid_ivc_core::deep_chain::ff_merkle::{
    build_ff_merkle_path_columns, FfMerklePathFamily, FfMerklePathWitness,
};
use noid_ivc_core::deep_chain::schedule::{
    build_duplex_columns, duplex_family_refs, duplex_fixed_patterns, flat_of_tower_u128,
    DuplexLayout,
};
use noid_ivc_core::deep_chain::source_tree::run_perm;
use noid_ivc_core::field::{F128, F256};
use noid_poseidon2b::native::domain::{capacity_iv, capacity_iv_flat, TAG_CAPSNODE, TAG_KSCH256};

use super::region_source_binding::DuplexUnion;
use super::zk_authorization_candidate::SelectedZkAuthorizationProofBatch;
use crate::acceptance::zk_auth_capsule_schedule::{
    ZkAuthCapsuleDuplexSchedules, ZK_AUTH_MAIN_TAIL_SLOTS, ZK_AUTH_OWNER_TAIL_SLOTS,
    ZK_AUTH_WALLET_A_MAIN_BRIDGE_SLOT, ZK_AUTH_WALLET_A_MAIN_DATA_SLOT,
    ZK_AUTH_WALLET_A_MAIN_TAIL_BASE, ZK_AUTH_WALLET_A_MID_BASE, ZK_AUTH_WALLET_A_OWNER_BRIDGE_SLOT,
    ZK_AUTH_WALLET_A_OWNER_DATA_SLOT, ZK_AUTH_WALLET_A_OWNER_TAIL_BASE,
    ZK_AUTH_WALLET_A_SOURCE_BASE, ZK_AUTH_WALLET_A_TILE_LOG,
};

const WALLET_A_TILE_LOG: usize = ZK_AUTH_WALLET_A_TILE_LOG;
const WALLET_B_TILE_LOG: usize = 10;
const WALLET_CORE_QUERY_COUNT: usize = 64;
const WALLET_OVERFLOW_QUERY: usize = WALLET_CORE_QUERY_COUNT;
const WALLET_A_SOURCE_SLOTS: usize = WALLET_CORE_QUERY_COUNT * C1_CAPSULE_SOURCE_SLOTS;
const WALLET_A_MID_SLOTS: usize = WALLET_CORE_QUERY_COUNT * C1_CAPSULE_MID_SLOTS;
const WALLET_B_SOURCE_PATH_OFFSET: usize = 0;
const WALLET_B_MID_PATH_OFFSET: usize = ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH;
const WALLET_B_PATH_STRIDE: usize =
    ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH + ZK_CAPSULE_PCS_MID_PATH_DEPTH;
const WALLET_OVERFLOW_A_SLOTS_PER_TX: usize = 2 * C1_CAPSULE_LEAF_STRIDE;
const WALLET_OVERFLOW_B_SLOTS_PER_TX: usize = WALLET_B_PATH_STRIDE;
const SELECTED_CHANGED_COMMITTED_COLUMNS: usize = 6 + 6 + 6 + 9;

const _: () = assert!(ZK_CAPSULE_PCS_QUERY_COUNT == 65);
const _: () = assert!(WALLET_OVERFLOW_QUERY + 1 == ZK_CAPSULE_PCS_QUERY_COUNT);
const _: () = assert!(WALLET_A_SOURCE_SLOTS == 768);
const _: () = assert!(WALLET_A_MID_SLOTS == 1024);
const _: () = assert!(ZK_AUTH_WALLET_A_MID_BASE == WALLET_A_SOURCE_SLOTS);
const _: () = assert!(ZK_AUTH_WALLET_A_OWNER_BRIDGE_SLOT == 1792);
const _: () =
    assert!(ZK_AUTH_WALLET_A_MAIN_TAIL_BASE + ZK_AUTH_MAIN_TAIL_SLOTS <= 1 << WALLET_A_TILE_LOG);
const _: () = assert!(WALLET_B_PATH_STRIDE == 16);
const _: () = assert!(WALLET_CORE_QUERY_COUNT * WALLET_B_PATH_STRIDE == 1 << WALLET_B_TILE_LOG);
const _: () = assert!(SELECTED_CHANGED_COMMITTED_COLUMNS == 27);

#[derive(Debug)]
pub(super) enum SelectedZkAuthorizationRegionError {
    VerifiedProjection {
        index: usize,
        source: ZkAuthorizationError,
    },
    QueryMapping {
        tx: usize,
        query: usize,
        source: ZkCapsuleAlgebraError,
    },
    PathExpansion {
        tx: usize,
        family: &'static str,
        source: String,
    },
    MissingExpandedPath {
        tx: usize,
        family: &'static str,
        leaf: usize,
    },
    LeafDigestMismatch {
        tx: usize,
        family: &'static str,
        query: usize,
    },
    PathRootMismatch {
        tx: usize,
        family: &'static str,
        query: usize,
    },
    TranscriptMismatch {
        tx: usize,
        family: &'static str,
    },
    Geometry(&'static str),
}

pub(super) struct SelectedZkAuthorizationRawWalk<const N: usize> {
    committed: [Vec<F128>; N],
    s0: [Vec<F128>; 4],
    s_out: [Vec<F128>; 4],
}

struct SplitDuplexTail {
    committed: [Vec<F128>; 6],
    s0: [Vec<F128>; 4],
    s_out: [Vec<F128>; 4],
    prefix_state: [Vec<F128>; 4],
    slots_per_tx: usize,
}

struct SplitDuplexBuild {
    prefix: DuplexUnion,
    tail: SplitDuplexTail,
}

fn build_split_duplex_union(
    full_layout: &DuplexLayout,
    prefix_layout: DuplexLayout,
    iv_flat: [F128; 2],
    data: &[Vec<F128>],
) -> SplitDuplexBuild {
    let prefix_slots = prefix_layout.slots.len();
    assert!(
        prefix_slots.is_power_of_two(),
        "duplex prefix must be dyadic"
    );
    assert!(
        prefix_slots < full_layout.slots.len(),
        "split duplex requires a live suffix"
    );
    assert!(
        !data.is_empty() && data.len().is_power_of_two(),
        "canonical duplex tile count"
    );
    assert!(data.iter().all(|stream| stream.len() == full_layout.n_data));

    let tail_slots = full_layout.slots.len() - prefix_slots;
    let w = data.len() * prefix_slots;
    let w_log = w.trailing_zeros() as usize;
    let block_log = prefix_slots.trailing_zeros() as usize;
    let full_log = full_layout.slots.len().next_power_of_two().trailing_zeros() as usize;
    let mut committed: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s0: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s_out: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut tail_committed: [Vec<F128>; 6] =
        std::array::from_fn(|_| vec![F128::ZERO; data.len() * tail_slots]);
    let mut tail_s0: [Vec<F128>; 4] =
        std::array::from_fn(|_| vec![F128::ZERO; data.len() * tail_slots]);
    let mut tail_s_out: [Vec<F128>; 4] =
        std::array::from_fn(|_| vec![F128::ZERO; data.len() * tail_slots]);
    let mut prefix_state: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; data.len()]);
    let mut challenges = Vec::with_capacity(data.len());

    for (tx, stream) in data.iter().enumerate() {
        let columns = build_duplex_columns(full_layout, iv_flat, stream, full_log);
        let prefix_base = tx * prefix_slots;
        let tail_base = tx * tail_slots;
        for lane in 0..2 {
            committed[lane][prefix_base..prefix_base + prefix_slots]
                .copy_from_slice(&columns.a[lane][..prefix_slots]);
            tail_committed[lane][tail_base..tail_base + tail_slots]
                .copy_from_slice(&columns.a[lane][prefix_slots..full_layout.slots.len()]);
        }
        for lane in 0..4 {
            committed[2 + lane][prefix_base..prefix_base + prefix_slots]
                .copy_from_slice(&columns.c[lane][..prefix_slots]);
            s0[lane][prefix_base..prefix_base + prefix_slots]
                .copy_from_slice(&columns.s0[lane][..prefix_slots]);
            s_out[lane][prefix_base..prefix_base + prefix_slots]
                .copy_from_slice(&columns.s_out[lane][..prefix_slots]);
            tail_committed[2 + lane][tail_base..tail_base + tail_slots]
                .copy_from_slice(&columns.c[lane][prefix_slots..full_layout.slots.len()]);
            tail_s0[lane][tail_base..tail_base + tail_slots]
                .copy_from_slice(&columns.s0[lane][prefix_slots..full_layout.slots.len()]);
            tail_s_out[lane][tail_base..tail_base + tail_slots]
                .copy_from_slice(&columns.s_out[lane][prefix_slots..full_layout.slots.len()]);
            prefix_state[lane][tx] = columns.c[lane][prefix_slots - 1];
        }
        challenges.push(columns.challenges);
    }

    SplitDuplexBuild {
        prefix: DuplexUnion {
            committed,
            s0,
            s_out,
            fixed: duplex_fixed_patterns(&prefix_layout, iv_flat, block_log),
            refs: duplex_family_refs(0, 0),
            layout: prefix_layout,
            w_log,
            block_log,
            challenges,
            rec_blocks: Vec::new(),
            rec_refs: Vec::new(),
            rec_challenges: Vec::new(),
        },
        tail: SplitDuplexTail {
            committed: tail_committed,
            s0: tail_s0,
            s_out: tail_s_out,
            prefix_state,
            slots_per_tx: tail_slots,
        },
    }
}

/// The single query beyond the legacy dyadic Wallet-A/Wallet-B tiles.
/// These staging columns are merged into the authenticated Meta-A/Meta-B
/// regions by the common six-child allocator; they are never allocated as a
/// seventh sidecar.
pub(super) struct SelectedZkAuthorizationOverflow {
    pub(super) wallet_a: SelectedZkAuthorizationRawWalk<6>,
    pub(super) wallet_b: SelectedZkAuthorizationRawWalk<9>,
}

impl<const N: usize> SelectedZkAuthorizationRawWalk<N> {
    pub(super) fn committed(&self) -> &[Vec<F128>; N] {
        &self.committed
    }

    pub(super) fn s0(&self) -> &[Vec<F128>; 4] {
        &self.s0
    }

    pub(super) fn s_out(&self) -> &[Vec<F128>; 4] {
        &self.s_out
    }

    /// Zero-copy handoff reserved for the future common six-child allocator.
    pub(super) fn into_parts(self) -> ([Vec<F128>; N], [Vec<F128>; 4], [Vec<F128>; 4]) {
        (self.committed, self.s0, self.s_out)
    }
}

/// Exact pre-allocation data for the four selected authorization children.
/// Fields and construction stay inside `acceptance::trace`; no sidecar key or
/// builder handle can be obtained from this value.
pub(super) struct SelectedZkAuthorizationRegionDraft {
    owner: DuplexUnion,
    main: DuplexUnion,
    wallet_a: SelectedZkAuthorizationRawWalk<6>,
    wallet_b: SelectedZkAuthorizationRawWalk<9>,
    overflow: SelectedZkAuthorizationOverflow,
}

impl SelectedZkAuthorizationRegionDraft {
    pub(super) fn owner(&self) -> &DuplexUnion {
        &self.owner
    }

    pub(super) fn main(&self) -> &DuplexUnion {
        &self.main
    }

    pub(super) fn wallet_a(&self) -> &SelectedZkAuthorizationRawWalk<6> {
        &self.wallet_a
    }

    pub(super) fn wallet_b(&self) -> &SelectedZkAuthorizationRawWalk<9> {
        &self.wallet_b
    }

    pub(super) fn overflow(&self) -> &SelectedZkAuthorizationOverflow {
        &self.overflow
    }

    pub(super) fn changed_committed_columns(&self) -> usize {
        self.owner.committed.len()
            + self.main.committed.len()
            + self.wallet_a.committed.len()
            + self.wallet_b.committed.len()
    }

    pub(super) fn committed_cells(&self) -> usize {
        self.owner
            .committed
            .iter()
            .chain(self.main.committed.iter())
            .chain(self.wallet_a.committed.iter())
            .chain(self.wallet_b.committed.iter())
            .map(Vec::len)
            .sum()
    }

    /// Zero-copy handoff reserved for the future common authorization+Meta
    /// allocator. Keeping the fields private prevents piecemeal replacement.
    pub(super) fn into_parts(
        self,
    ) -> (
        DuplexUnion,
        DuplexUnion,
        SelectedZkAuthorizationRawWalk<6>,
        SelectedZkAuthorizationRawWalk<9>,
        SelectedZkAuthorizationOverflow,
    ) {
        (
            self.owner,
            self.main,
            self.wallet_a,
            self.wallet_b,
            self.overflow,
        )
    }
}

/// Reconstruct every selected authorization tile of one canonical class from
/// the sole policy-verified batch. Native proof verification and duplicate
/// policy have already completed before this boundary.
pub(super) fn build_selected_zk_authorization_region_draft(
    batch: &SelectedZkAuthorizationProofBatch,
) -> Result<SelectedZkAuthorizationRegionDraft, SelectedZkAuthorizationRegionError> {
    let geometry = crate::region_sidecar::selected_zk_block_geometry_for_auth_tiles(batch.len())
        .ok_or(SelectedZkAuthorizationRegionError::Geometry(
            "selected authorization batch is not a canonical class",
        ))?;
    let schedules = ZkAuthCapsuleDuplexSchedules::selected();
    let owner_layout = schedules.owner_layout();
    let main_layout = schedules.main_layout();
    let owner_sidecar_layout = schedules.owner_sidecar_layout();
    let main_sidecar_layout = schedules.main_sidecar_layout();
    let iv = ksch256_iv_flat();

    let mut owner_streams = Vec::with_capacity(geometry.auth_tiles);
    let mut main_streams = Vec::with_capacity(geometry.auth_tiles);
    let mut ghost_streams: Option<(Vec<F128>, Vec<F128>)> = None;
    for tx in 0..batch.len() {
        let entry = batch.entry_for_slot(tx);
        if std::ptr::eq(entry, batch.ghost_entry()) {
            if ghost_streams.is_none() {
                ghost_streams = Some(build_dynamic_streams(tx, entry)?);
            }
            let (owner, main) = ghost_streams
                .as_ref()
                .expect("ghost streams were initialized");
            owner_streams.push(owner.clone());
            main_streams.push(main.clone());
        } else {
            let (owner, main) = build_dynamic_streams(tx, entry)?;
            owner_streams.push(owner);
            main_streams.push(main);
        }
    }

    let owner_split =
        build_split_duplex_union(&owner_layout, owner_sidecar_layout, iv, &owner_streams);
    let main_split = build_split_duplex_union(&main_layout, main_sidecar_layout, iv, &main_streams);
    let owner_union = owner_split.prefix;
    let main_union = main_split.prefix;
    // The unions own their reconstructed columns; the per-tile absorbed-data
    // streams are no longer needed while the much larger Wallet columns are
    // materialized below.
    drop(owner_streams);
    drop(main_streams);
    drop(ghost_streams);
    if owner_union.w_log != geometry.owner_w_log || owner_union.block_log != ZK_AUTH_OWNER_TILE_LOG
    {
        return Err(SelectedZkAuthorizationRegionError::Geometry(
            "selected Owner union has the wrong canonical class geometry",
        ));
    }
    if main_union.w_log != geometry.main_w_log || main_union.block_log != ZK_AUTH_MAIN_TILE_LOG {
        return Err(SelectedZkAuthorizationRegionError::Geometry(
            "selected Main union has the wrong canonical class geometry",
        ));
    }
    for tx in 0..batch.len() {
        let verified = batch.entry_for_slot(tx).verified();
        let expected_owner = verified.owner.transcript_challenges().map(F256::from_tower);
        let actual_owner = owner_union.challenges[tx]
            .chunks_exact(2)
            .map(|lanes| F256::from_raw_challenge_lanes(lanes[0], lanes[1]))
            .collect::<Vec<_>>();
        if actual_owner.as_slice() != expected_owner.as_slice() {
            return Err(SelectedZkAuthorizationRegionError::TranscriptMismatch {
                tx,
                family: "Owner",
            });
        }
        let expected_main_algebraic = verified.main_algebraic_challenges().map(F256::from_tower);
        let algebraic_raw_lanes = 2 * expected_main_algebraic.len();
        let actual_main_algebraic = main_union.challenges[tx][..algebraic_raw_lanes]
            .chunks_exact(2)
            .map(|lanes| F256::from_raw_challenge_lanes(lanes[0], lanes[1]))
            .collect::<Vec<_>>();
        let expected_main_base = std::iter::once(phi(verified.grind))
            .chain(verified.query_seeds.iter().copied().map(phi))
            .collect::<Vec<_>>();
        if actual_main_algebraic.as_slice() != expected_main_algebraic.as_slice()
            || main_union.challenges[tx][algebraic_raw_lanes..] != expected_main_base
        {
            return Err(SelectedZkAuthorizationRegionError::TranscriptMismatch {
                tx,
                family: "Main",
            });
        }
    }

    let wallet = build_wallet_columns(
        batch,
        geometry.wallet_a_w_log,
        geometry.wallet_b_w_log,
        &owner_split.tail,
        &main_split.tail,
    )?;

    Ok(SelectedZkAuthorizationRegionDraft {
        owner: owner_union,
        main: main_union,
        wallet_a: wallet.wallet_a,
        wallet_b: wallet.wallet_b,
        overflow: wallet.overflow,
    })
}

fn build_dynamic_streams(
    tx: usize,
    entry: &super::zk_authorization_candidate::SelectedZkAuthorizationVerifiedEntry,
) -> Result<(Vec<F128>, Vec<F128>), SelectedZkAuthorizationRegionError> {
    let proof = entry.proof();
    let source_cap = proof.source_commitment.transcript_lanes().map_err(|_| {
        SelectedZkAuthorizationRegionError::Geometry("verified source cap shape drift")
    })?;
    let owner = zk_auth_capsule_owner_dynamic_data(entry.statement(), &source_cap, &proof.owner)
        .into_iter()
        .map(phi)
        .collect();
    let main = zk_authorization_main_dynamic_data(&entry.verified().owner, proof)
        .map_err(
            |source| SelectedZkAuthorizationRegionError::VerifiedProjection { index: tx, source },
        )?
        .into_iter()
        .map(phi)
        .collect();
    Ok((owner, main))
}

fn ksch256_iv_flat() -> [F128; 2] {
    let [hi, lo] = capacity_iv(TAG_KSCH256);
    [flat_of_tower_u128(hi.0), flat_of_tower_u128(lo.0)]
}

fn phi(value: Block128) -> F128 {
    flat_of_tower_u128(value.0)
}

fn raw_digest_lanes(digest: &SourceHash) -> [F128; 2] {
    [
        raw_flat_lane(u128::from_le_bytes(digest[..16].try_into().unwrap())),
        raw_flat_lane(u128::from_le_bytes(digest[16..].try_into().unwrap())),
    ]
}

#[allow(clippy::too_many_arguments)]
fn place_ff_dense(
    committed: &mut [Vec<F128>; 9],
    s0: &mut [Vec<F128>; 4],
    s_out: &mut [Vec<F128>; 4],
    columns: &noid_ivc_core::deep_chain::ff_merkle::FfMerklePathColumns,
    n_paths: usize,
    depth: usize,
    destination_base: usize,
    destination_stride: usize,
    destination_offset: usize,
) {
    let source_stride = depth.next_power_of_two();
    for path in 0..n_paths {
        let source = path * source_stride;
        let destination = destination_base + path * destination_stride + destination_offset;
        for level in 0..depth {
            let from = source + level;
            let to = destination + level;
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
}

#[allow(clippy::too_many_arguments)]
fn place_split_duplex_tail(
    tx: usize,
    tail: &SplitDuplexTail,
    bridge_slot: usize,
    tail_base: usize,
    data_slot: usize,
    committed: &mut [Vec<F128>; 6],
    s0: &mut [Vec<F128>; 4],
    s_out: &mut [Vec<F128>; 4],
) {
    let destination_base = (tx << WALLET_A_TILE_LOG) + tail_base;
    let source_base = tx * tail.slots_per_tx;
    committed[0][(tx << WALLET_A_TILE_LOG) + bridge_slot] = tail.prefix_state[2][tx];
    committed[1][(tx << WALLET_A_TILE_LOG) + bridge_slot] = tail.prefix_state[3][tx];
    for lane in 0..2 {
        committed[lane][destination_base..destination_base + tail.slots_per_tx]
            .copy_from_slice(&tail.committed[lane][source_base..source_base + tail.slots_per_tx]);
        committed[lane][(tx << WALLET_A_TILE_LOG) + data_slot] = tail.committed[lane][source_base];
        committed[lane][destination_base] += tail.prefix_state[lane][tx];
    }
    for lane in 0..4 {
        committed[2 + lane][destination_base..destination_base + tail.slots_per_tx]
            .copy_from_slice(
                &tail.committed[2 + lane][source_base..source_base + tail.slots_per_tx],
            );
        s0[lane][destination_base..destination_base + tail.slots_per_tx]
            .copy_from_slice(&tail.s0[lane][source_base..source_base + tail.slots_per_tx]);
        s_out[lane][destination_base..destination_base + tail.slots_per_tx]
            .copy_from_slice(&tail.s_out[lane][source_base..source_base + tail.slots_per_tx]);
    }
}

struct WalletColumns {
    wallet_a: SelectedZkAuthorizationRawWalk<6>,
    wallet_b: SelectedZkAuthorizationRawWalk<9>,
    overflow: SelectedZkAuthorizationOverflow,
}

fn build_wallet_columns(
    batch: &SelectedZkAuthorizationProofBatch,
    wallet_a_w_log: usize,
    wallet_b_w_log: usize,
    owner_tail: &SplitDuplexTail,
    main_tail: &SplitDuplexTail,
) -> Result<WalletColumns, SelectedZkAuthorizationRegionError> {
    let expected = crate::region_sidecar::selected_zk_block_geometry_for_auth_tiles(batch.len())
        .ok_or(SelectedZkAuthorizationRegionError::Geometry(
            "wallet assembly requires a canonical authorization class",
        ))?;
    if wallet_a_w_log != expected.wallet_a_w_log || wallet_b_w_log != expected.wallet_b_w_log {
        return Err(SelectedZkAuthorizationRegionError::Geometry(
            "wallet assembly class geometry drift",
        ));
    }
    let wallet_a_len = 1 << wallet_a_w_log;
    let mut wallet_a: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; wallet_a_len]);
    let mut wallet_a_s0: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; wallet_a_len]);
    let mut wallet_a_s_out: [Vec<F128>; 4] =
        std::array::from_fn(|_| vec![F128::ZERO; wallet_a_len]);
    let (ghost_s0, ghost_out) = run_perm([F128::ZERO; 4]);
    for lane in 0..4 {
        wallet_a[2 + lane].fill(ghost_out[lane]);
        wallet_a_s0[lane].fill(ghost_s0[lane]);
        wallet_a_s_out[lane].fill(ghost_out[lane]);
    }
    let mut wallet_b: [Vec<F128>; 9] =
        std::array::from_fn(|_| vec![F128::ZERO; 1 << wallet_b_w_log]);
    let mut wallet_b_s0: [Vec<F128>; 4] =
        std::array::from_fn(|_| vec![F128::ZERO; 1 << wallet_b_w_log]);
    let mut wallet_b_s_out: [Vec<F128>; 4] =
        std::array::from_fn(|_| vec![F128::ZERO; 1 << wallet_b_w_log]);
    let overflow_a_len = batch.len() * WALLET_OVERFLOW_A_SLOTS_PER_TX;
    let overflow_b_len = batch.len() * WALLET_OVERFLOW_B_SLOTS_PER_TX;
    debug_assert!(overflow_a_len.is_power_of_two());
    debug_assert!(overflow_b_len.is_power_of_two());
    let mut overflow_a: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; overflow_a_len]);
    let mut overflow_a_s0: [Vec<F128>; 4] =
        std::array::from_fn(|_| vec![F128::ZERO; overflow_a_len]);
    let mut overflow_a_s_out: [Vec<F128>; 4] =
        std::array::from_fn(|_| vec![F128::ZERO; overflow_a_len]);
    let mut overflow_b: [Vec<F128>; 9] = std::array::from_fn(|_| vec![F128::ZERO; overflow_b_len]);
    let mut overflow_b_s0: [Vec<F128>; 4] =
        std::array::from_fn(|_| vec![F128::ZERO; overflow_b_len]);
    let mut overflow_b_s_out: [Vec<F128>; 4] =
        std::array::from_fn(|_| vec![F128::ZERO; overflow_b_len]);

    if owner_tail.slots_per_tx != ZK_AUTH_OWNER_TAIL_SLOTS
        || main_tail.slots_per_tx != ZK_AUTH_MAIN_TAIL_SLOTS
    {
        return Err(SelectedZkAuthorizationRegionError::Geometry(
            "split transcript tail shape drift",
        ));
    }
    for tx in 0..batch.len() {
        place_split_duplex_tail(
            tx,
            owner_tail,
            ZK_AUTH_WALLET_A_OWNER_BRIDGE_SLOT,
            ZK_AUTH_WALLET_A_OWNER_TAIL_BASE,
            ZK_AUTH_WALLET_A_OWNER_DATA_SLOT,
            &mut wallet_a,
            &mut wallet_a_s0,
            &mut wallet_a_s_out,
        );
        place_split_duplex_tail(
            tx,
            main_tail,
            ZK_AUTH_WALLET_A_MAIN_BRIDGE_SLOT,
            ZK_AUTH_WALLET_A_MAIN_TAIL_BASE,
            ZK_AUTH_WALLET_A_MAIN_DATA_SLOT,
            &mut wallet_a,
            &mut wallet_a_s0,
            &mut wallet_a_s_out,
        );
    }

    let mut first_ghost_tile = None;
    for tx in 0..batch.len() {
        let entry = batch.entry_for_slot(tx);
        if std::ptr::eq(entry, batch.ghost_entry()) {
            if let Some(source_tx) = first_ghost_tile {
                copy_wallet_tile(
                    source_tx,
                    tx,
                    &mut wallet_a,
                    &mut wallet_a_s0,
                    &mut wallet_a_s_out,
                    &mut wallet_b,
                    &mut wallet_b_s0,
                    &mut wallet_b_s_out,
                    &mut overflow_a,
                    &mut overflow_a_s0,
                    &mut overflow_a_s_out,
                    &mut overflow_b,
                    &mut overflow_b_s0,
                    &mut overflow_b_s_out,
                );
                continue;
            }
            first_ghost_tile = Some(tx);
        }
        let proof = entry.proof();
        fill_wallet_opening(
            tx,
            &entry.verified().queries,
            &proof.opening.source_joint_symbols,
            &proof.opening.source_batch,
            &proof.source_commitment.cap.hashes,
            &proof.opening.mid_symbols,
            &proof.opening.mid_batch,
            &proof.mid_commitment.cap.hashes,
            &mut wallet_a,
            &mut wallet_a_s0,
            &mut wallet_a_s_out,
            &mut wallet_b,
            &mut wallet_b_s0,
            &mut wallet_b_s_out,
            &mut overflow_a,
            &mut overflow_a_s0,
            &mut overflow_a_s_out,
            &mut overflow_b,
            &mut overflow_b_s0,
            &mut overflow_b_s_out,
        )?;
    }
    Ok(WalletColumns {
        wallet_a: SelectedZkAuthorizationRawWalk {
            committed: wallet_a,
            s0: wallet_a_s0,
            s_out: wallet_a_s_out,
        },
        wallet_b: SelectedZkAuthorizationRawWalk {
            committed: wallet_b,
            s0: wallet_b_s0,
            s_out: wallet_b_s_out,
        },
        overflow: SelectedZkAuthorizationOverflow {
            wallet_a: SelectedZkAuthorizationRawWalk {
                committed: overflow_a,
                s0: overflow_a_s0,
                s_out: overflow_a_s_out,
            },
            wallet_b: SelectedZkAuthorizationRawWalk {
                committed: overflow_b,
                s0: overflow_b_s0,
                s_out: overflow_b_s_out,
            },
        },
    })
}

fn copy_tile<const N: usize>(
    columns: &mut [Vec<F128>; N],
    source_base: usize,
    destination_base: usize,
    tile_slots: usize,
) {
    let source = source_base..source_base + tile_slots;
    for column in columns {
        column.copy_within(source.clone(), destination_base);
    }
}

#[allow(clippy::too_many_arguments)]
fn copy_wallet_tile(
    source_tx: usize,
    destination_tx: usize,
    wallet_a: &mut [Vec<F128>; 6],
    wallet_a_s0: &mut [Vec<F128>; 4],
    wallet_a_s_out: &mut [Vec<F128>; 4],
    wallet_b: &mut [Vec<F128>; 9],
    wallet_b_s0: &mut [Vec<F128>; 4],
    wallet_b_s_out: &mut [Vec<F128>; 4],
    overflow_a: &mut [Vec<F128>; 6],
    overflow_a_s0: &mut [Vec<F128>; 4],
    overflow_a_s_out: &mut [Vec<F128>; 4],
    overflow_b: &mut [Vec<F128>; 9],
    overflow_b_s0: &mut [Vec<F128>; 4],
    overflow_b_s_out: &mut [Vec<F128>; 4],
) {
    let wallet_a_source = source_tx << WALLET_A_TILE_LOG;
    let wallet_a_destination = destination_tx << WALLET_A_TILE_LOG;
    let wallet_a_slots = 1 << WALLET_A_TILE_LOG;
    copy_tile(
        wallet_a,
        wallet_a_source,
        wallet_a_destination,
        wallet_a_slots,
    );
    copy_tile(
        wallet_a_s0,
        wallet_a_source,
        wallet_a_destination,
        wallet_a_slots,
    );
    copy_tile(
        wallet_a_s_out,
        wallet_a_source,
        wallet_a_destination,
        wallet_a_slots,
    );

    let wallet_b_source = source_tx << WALLET_B_TILE_LOG;
    let wallet_b_destination = destination_tx << WALLET_B_TILE_LOG;
    let wallet_b_slots = 1 << WALLET_B_TILE_LOG;
    copy_tile(
        wallet_b,
        wallet_b_source,
        wallet_b_destination,
        wallet_b_slots,
    );
    copy_tile(
        wallet_b_s0,
        wallet_b_source,
        wallet_b_destination,
        wallet_b_slots,
    );
    copy_tile(
        wallet_b_s_out,
        wallet_b_source,
        wallet_b_destination,
        wallet_b_slots,
    );

    let overflow_a_source = source_tx * WALLET_OVERFLOW_A_SLOTS_PER_TX;
    let overflow_a_destination = destination_tx * WALLET_OVERFLOW_A_SLOTS_PER_TX;
    copy_tile(
        overflow_a,
        overflow_a_source,
        overflow_a_destination,
        WALLET_OVERFLOW_A_SLOTS_PER_TX,
    );
    copy_tile(
        overflow_a_s0,
        overflow_a_source,
        overflow_a_destination,
        WALLET_OVERFLOW_A_SLOTS_PER_TX,
    );
    copy_tile(
        overflow_a_s_out,
        overflow_a_source,
        overflow_a_destination,
        WALLET_OVERFLOW_A_SLOTS_PER_TX,
    );

    let overflow_b_source = source_tx * WALLET_OVERFLOW_B_SLOTS_PER_TX;
    let overflow_b_destination = destination_tx * WALLET_OVERFLOW_B_SLOTS_PER_TX;
    copy_tile(
        overflow_b,
        overflow_b_source,
        overflow_b_destination,
        WALLET_OVERFLOW_B_SLOTS_PER_TX,
    );
    copy_tile(
        overflow_b_s0,
        overflow_b_source,
        overflow_b_destination,
        WALLET_OVERFLOW_B_SLOTS_PER_TX,
    );
    copy_tile(
        overflow_b_s_out,
        overflow_b_source,
        overflow_b_destination,
        WALLET_OVERFLOW_B_SLOTS_PER_TX,
    );
}

#[allow(clippy::too_many_arguments)]
fn fill_wallet_opening(
    tx: usize,
    queries: &[usize; ZK_CAPSULE_PCS_QUERY_COUNT],
    source_symbols: &[Block128],
    source_batch: &SourceBatchedMerkleProof,
    source_cap: &[SourceHash],
    mid_symbols: &[Block256],
    mid_batch: &SourceBatchedMerkleProof,
    mid_cap: &[SourceHash],
    wallet_a: &mut [Vec<F128>; 6],
    wallet_a_s0: &mut [Vec<F128>; 4],
    wallet_a_s_out: &mut [Vec<F128>; 4],
    wallet_b: &mut [Vec<F128>; 9],
    wallet_b_s0: &mut [Vec<F128>; 4],
    wallet_b_s_out: &mut [Vec<F128>; 4],
    overflow_a: &mut [Vec<F128>; 6],
    overflow_a_s0: &mut [Vec<F128>; 4],
    overflow_a_s_out: &mut [Vec<F128>; 4],
    overflow_b: &mut [Vec<F128>; 9],
    overflow_b_s0: &mut [Vec<F128>; 4],
    overflow_b_s_out: &mut [Vec<F128>; 4],
) -> Result<(), SelectedZkAuthorizationRegionError> {
    if source_symbols.len() != ZK_CAPSULE_PCS_QUERY_COUNT * JOINT_SOURCE_LEAF_SYMBOLS
        || mid_symbols.len() != ZK_CAPSULE_PCS_QUERY_COUNT * (1 << MID_STANDARD_FOLDS)
        || source_cap.len() != 1 << ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH
        || mid_cap.len() != 1 << ZK_CAPSULE_PCS_MID_CAP_DEPTH
    {
        return Err(SelectedZkAuthorizationRegionError::Geometry(
            "verified wallet opening shape drift",
        ));
    }

    let mappings = queries
        .iter()
        .enumerate()
        .map(|(query, &index)| {
            map_source_query_leaf(index).map_err(|source| {
                SelectedZkAuthorizationRegionError::QueryMapping { tx, query, source }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let source_indices = mappings
        .iter()
        .map(|mapping| mapping.source_leaf_index)
        .collect::<Vec<_>>();
    let mid_indices = mappings
        .iter()
        .map(|mapping| mapping.mid_leaf_index)
        .collect::<Vec<_>>();

    let source_hashes = source_indices
        .iter()
        .enumerate()
        .map(|(query, _)| {
            let start = query * JOINT_SOURCE_LEAF_SYMBOLS;
            capsule_leaf_hash_mixed(&source_symbols[start..start + JOINT_SOURCE_LEAF_SYMBOLS])
        })
        .collect::<Vec<_>>();
    let mid_hashes = mid_indices
        .iter()
        .enumerate()
        .map(|(query, _)| {
            let start = query * (1 << MID_STANDARD_FOLDS);
            capsule_leaf_hash_wide(&mid_symbols[start..start + (1 << MID_STANDARD_FOLDS)])
        })
        .collect::<Vec<_>>();

    let source_paths = expand_paths(
        tx,
        "source",
        source_batch,
        ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH,
        ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH,
        &source_indices,
        &source_hashes,
    )?;
    let mid_paths = expand_paths(
        tx,
        "mid",
        mid_batch,
        ZK_CAPSULE_PCS_MID_TREE_DEPTH,
        ZK_CAPSULE_PCS_MID_CAP_DEPTH,
        &mid_indices,
        &mid_hashes,
    )?;

    let wallet_a_base = tx << WALLET_A_TILE_LOG;
    let wallet_b_base = tx << WALLET_B_TILE_LOG;
    let source_tiles = source_symbols
        .chunks_exact(JOINT_SOURCE_LEAF_SYMBOLS)
        .map(|symbols| C1CapsuleLeafData {
            lanes: symbols.iter().copied().map(phi).collect(),
        })
        .collect::<Vec<_>>();
    let mid_tiles = mid_symbols
        .chunks_exact(1 << MID_STANDARD_FOLDS)
        .map(|symbols| C1CapsuleLeafData {
            lanes: symbols
                .iter()
                .flat_map(|symbol| [phi(symbol.lo), phi(symbol.hi)])
                .collect(),
        })
        .collect::<Vec<_>>();

    let mut family_digests: [Vec<[F128; 2]>; 2] = [Vec::new(), Vec::new()];
    for (family, (kind, tiles)) in [
        (C1CapsuleLeafKind::MixedSource, source_tiles.as_slice()),
        (C1CapsuleLeafKind::WideMid, mid_tiles.as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        let (columns, mut digests) =
            build_c1_capsule_leaf_columns(&tiles[..WALLET_CORE_QUERY_COUNT], kind, 10);
        let active_slots = kind.active_slots();
        let family_base = wallet_a_base
            + if family == 0 {
                ZK_AUTH_WALLET_A_SOURCE_BASE
            } else {
                ZK_AUTH_WALLET_A_MID_BASE
            };
        for query in 0..WALLET_CORE_QUERY_COUNT {
            let source = query * C1_CAPSULE_LEAF_STRIDE;
            let destination = family_base + query * active_slots;
            for lane in 0..2 {
                wallet_a[lane][destination..destination + active_slots]
                    .copy_from_slice(&columns.in_[lane][source..source + active_slots]);
            }
            for lane in 0..4 {
                wallet_a[2 + lane][destination..destination + active_slots]
                    .copy_from_slice(&columns.c[lane][source..source + active_slots]);
                wallet_a_s0[lane][destination..destination + active_slots]
                    .copy_from_slice(&columns.s0[lane][source..source + active_slots]);
                wallet_a_s_out[lane][destination..destination + active_slots]
                    .copy_from_slice(&columns.s_out[lane][source..source + active_slots]);
            }
        }

        let (overflow_columns, overflow_digests) =
            build_c1_capsule_leaf_columns(&tiles[WALLET_OVERFLOW_QUERY..], kind, 4);
        let overflow_base = tx * WALLET_OVERFLOW_A_SLOTS_PER_TX + family * C1_CAPSULE_LEAF_STRIDE;
        for lane in 0..2 {
            overflow_a[lane][overflow_base..overflow_base + C1_CAPSULE_LEAF_STRIDE]
                .copy_from_slice(&overflow_columns.in_[lane]);
        }
        for lane in 0..4 {
            overflow_a[2 + lane][overflow_base..overflow_base + C1_CAPSULE_LEAF_STRIDE]
                .copy_from_slice(&overflow_columns.c[lane]);
            overflow_a_s0[lane][overflow_base..overflow_base + C1_CAPSULE_LEAF_STRIDE]
                .copy_from_slice(&overflow_columns.s0[lane]);
            overflow_a_s_out[lane][overflow_base..overflow_base + C1_CAPSULE_LEAF_STRIDE]
                .copy_from_slice(&overflow_columns.s_out[lane]);
        }
        digests.extend(overflow_digests);
        for query in 0..ZK_CAPSULE_PCS_QUERY_COUNT {
            let native = raw_digest_lanes(if family == 0 {
                &source_hashes[query]
            } else {
                &mid_hashes[query]
            });
            if digests[query] != native {
                return Err(SelectedZkAuthorizationRegionError::LeafDigestMismatch {
                    tx,
                    family: if family == 0 { "source" } else { "mid" },
                    query,
                });
            }
        }
        family_digests[family] = digests;
    }

    let capsule_iv = capacity_iv_flat(TAG_CAPSNODE).map(raw_flat_lane);
    for family in 0..2 {
        let path_depth = if family == 0 {
            ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH
        } else {
            ZK_CAPSULE_PCS_MID_PATH_DEPTH
        };
        let path_offset = if family == 0 {
            WALLET_B_SOURCE_PATH_OFFSET
        } else {
            WALLET_B_MID_PATH_OFFSET
        };
        let (indices, paths, cap) = if family == 0 {
            (&source_indices, &source_paths, source_cap)
        } else {
            (&mid_indices, &mid_paths, mid_cap)
        };
        let witnesses = indices
            .iter()
            .enumerate()
            .map(|(query, &leaf)| {
                let path = paths.get(&leaf).ok_or(
                    SelectedZkAuthorizationRegionError::MissingExpandedPath {
                        tx,
                        family: if family == 0 { "source" } else { "mid" },
                        leaf,
                    },
                )?;
                Ok(FfMerklePathWitness {
                    entry: family_digests[family][query],
                    siblings: path.siblings.iter().map(raw_digest_lanes).collect(),
                    directions: path.directions.clone(),
                })
            })
            .collect::<Result<Vec<_>, SelectedZkAuthorizationRegionError>>()?;
        let columns = build_ff_merkle_path_columns(
            &FfMerklePathFamily {
                depth: path_depth,
                n_paths: WALLET_CORE_QUERY_COUNT,
            },
            capsule_iv,
            &witnesses[..WALLET_CORE_QUERY_COUNT],
            (WALLET_CORE_QUERY_COUNT * path_depth.next_power_of_two()).trailing_zeros() as usize,
        );
        place_ff_dense(
            wallet_b,
            wallet_b_s0,
            wallet_b_s_out,
            &columns,
            WALLET_CORE_QUERY_COUNT,
            path_depth,
            wallet_b_base,
            WALLET_B_PATH_STRIDE,
            path_offset,
        );
        let overflow_columns = build_ff_merkle_path_columns(
            &FfMerklePathFamily {
                depth: path_depth,
                n_paths: 1,
            },
            capsule_iv,
            &witnesses[WALLET_OVERFLOW_QUERY..],
            path_depth.next_power_of_two().trailing_zeros() as usize,
        );
        place_ff_dense(
            overflow_b,
            overflow_b_s0,
            overflow_b_s_out,
            &overflow_columns,
            1,
            path_depth,
            tx * WALLET_OVERFLOW_B_SLOTS_PER_TX,
            WALLET_B_PATH_STRIDE,
            path_offset,
        );
        for (query, mapping) in mappings.iter().enumerate() {
            let cap_index = if family == 0 {
                mapping.source_cap_index
            } else {
                mapping.mid_cap_index
            };
            let root = if query < WALLET_CORE_QUERY_COUNT {
                columns.roots[query]
            } else {
                overflow_columns.roots[query - WALLET_CORE_QUERY_COUNT]
            };
            if root != raw_digest_lanes(&cap[cap_index]) {
                return Err(SelectedZkAuthorizationRegionError::PathRootMismatch {
                    tx,
                    family: if family == 0 { "source" } else { "mid" },
                    query,
                });
            }
        }
    }
    Ok(())
}

fn expand_paths(
    tx: usize,
    family: &'static str,
    batch: &SourceBatchedMerkleProof,
    depth: usize,
    cap_depth: usize,
    indices: &[usize],
    hashes: &[SourceHash],
) -> Result<BTreeMap<usize, IndependentSourceMerklePath>, SelectedZkAuthorizationRegionError> {
    let paths = expand_source_batched_merkle_proof_to_cap(
        batch,
        depth,
        cap_depth,
        indices,
        hashes,
        &CapsuleNodeHasher,
    )
    .map_err(|source| SelectedZkAuthorizationRegionError::PathExpansion {
        tx,
        family,
        source,
    })?;
    Ok(paths
        .into_iter()
        .map(|path| (path.leaf_index, path))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(seed: u64) -> SourceHash {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&seed.to_le_bytes());
        out[8..16].copy_from_slice(&seed.rotate_left(17).to_le_bytes());
        out[16..24].copy_from_slice(&seed.rotate_left(31).to_le_bytes());
        out[24..].copy_from_slice(&seed.rotate_left(47).to_le_bytes());
        out
    }

    fn cap_for_leftmost_leaf(
        leaf: SourceHash,
        siblings: &[SourceHash],
        width: usize,
    ) -> Vec<SourceHash> {
        let mut node = leaf;
        for sibling in siblings {
            node = CapsuleNodeHasher.compress(&node, sibling);
        }
        let mut cap = (0..width)
            .map(|index| hash(10_000 + index as u64))
            .collect::<Vec<_>>();
        cap[0] = node;
        cap
    }

    #[test]
    fn selected_two_class_authorization_geometry_is_exact() {
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        assert_eq!(
            schedules.owner_layout().slots.len().next_power_of_two(),
            1 << 8
        );
        assert_eq!(
            schedules.main_layout().slots.len().next_power_of_two(),
            1 << 9
        );
        assert_eq!(schedules.owner_sidecar_layout().slots.len(), 1 << 7);
        assert_eq!(schedules.main_sidecar_layout().slots.len(), 1 << 8);
        for tier in [25usize, 255] {
            let geometry = crate::region_sidecar::selected_zk_block_geometry(tier).unwrap();
            assert_eq!(geometry.auth_tiles << 7, 1 << geometry.owner_w_log);
            assert_eq!(geometry.auth_tiles << 8, 1 << geometry.main_w_log);
            assert_eq!(geometry.auth_tiles << 11, 1 << geometry.wallet_a_w_log);
            assert_eq!(geometry.auth_tiles << 10, 1 << geometry.wallet_b_w_log);
            assert_eq!(
                geometry.wallet_overflow_bases[1],
                geometry.wallet_overflow_bases[0] + ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
                "B{tier} overflow Meta-B must preserve the packed 10+6 path split",
            );
            assert!(
                geometry.wallet_overflow_bases[1] + ZK_CAPSULE_PCS_MID_PATH_DEPTH
                    <= 1 << geometry.meta_b_block_log,
                "B{tier} overflow Meta-B paths exceed the per-transaction block",
            );
        }
        assert_eq!(SELECTED_CHANGED_COMMITTED_COLUMNS, 27);
    }

    #[test]
    fn raw_reconstructor_has_no_independent_proof_or_allocation_surface() {
        let source = include_str!("zk_authorization_region.rs");
        let production = source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production raw-region source");
        assert!(!production.contains("verify_zk_authorization("));
        assert!(!production.contains("Vec<ZkAuthorizationProof>"));
        assert!(!production.contains("Vec<ZkAuthCapsuleOwnerStatement>"));
        assert!(!production.contains("use super::FieldR1csBuilder"));
        assert!(!production.contains("-> WitnessSlice"));
        assert!(!production.contains("RegionVk::"));
        assert!(!production.contains("BlockRegionPreparation::"));
        assert!(production.contains("batch.entry_for_slot(tx)"));
    }

    #[test]
    fn deterministic_one_tile_c1_digests_and_balanced_cap_roots_match() {
        let queries = [0usize; ZK_CAPSULE_PCS_QUERY_COUNT];
        let source_leaf = (0..JOINT_SOURCE_LEAF_SYMBOLS)
            .map(|index| Block128::from(0x5100 + index as u128))
            .collect::<Vec<_>>();
        let mid_leaf = (0..1 << MID_STANDARD_FOLDS)
            .map(|index| {
                Block256::new(
                    Block128::from(0xA100 + index as u128),
                    Block128::from(0xB200 + index as u128),
                )
            })
            .collect::<Vec<_>>();
        let source_symbols = source_leaf
            .iter()
            .copied()
            .cycle()
            .take(ZK_CAPSULE_PCS_QUERY_COUNT * JOINT_SOURCE_LEAF_SYMBOLS)
            .collect::<Vec<_>>();
        let mid_symbols = mid_leaf
            .iter()
            .copied()
            .cycle()
            .take(ZK_CAPSULE_PCS_QUERY_COUNT * (1 << MID_STANDARD_FOLDS))
            .collect::<Vec<_>>();
        let source_hash = capsule_leaf_hash_mixed(&source_leaf);
        let mid_hash = capsule_leaf_hash_wide(&mid_leaf);
        let source_siblings = (0..ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH)
            .map(|level| hash(100 + level as u64))
            .collect::<Vec<_>>();
        let mid_siblings = (0..ZK_CAPSULE_PCS_MID_PATH_DEPTH)
            .map(|level| hash(200 + level as u64))
            .collect::<Vec<_>>();
        let source_cap = cap_for_leftmost_leaf(
            source_hash,
            &source_siblings,
            1 << ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH,
        );
        let mid_cap =
            cap_for_leftmost_leaf(mid_hash, &mid_siblings, 1 << ZK_CAPSULE_PCS_MID_CAP_DEPTH);

        let mut wallet_a: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 11]);
        let mut wallet_a_s0: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 11]);
        let mut wallet_a_s_out: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 11]);
        let mut wallet_b: [Vec<F128>; 9] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 10]);
        let mut wallet_b_s0: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 10]);
        let mut wallet_b_s_out: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 10]);
        let mut overflow_a: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 5]);
        let mut overflow_a_s0: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 5]);
        let mut overflow_a_s_out: [Vec<F128>; 4] =
            std::array::from_fn(|_| vec![F128::ZERO; 1 << 5]);
        let mut overflow_b: [Vec<F128>; 9] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 4]);
        let mut overflow_b_s0: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 4]);
        let mut overflow_b_s_out: [Vec<F128>; 4] =
            std::array::from_fn(|_| vec![F128::ZERO; 1 << 4]);
        fill_wallet_opening(
            0,
            &queries,
            &source_symbols,
            &SourceBatchedMerkleProof {
                siblings: source_siblings,
            },
            &source_cap,
            &mid_symbols,
            &SourceBatchedMerkleProof {
                siblings: mid_siblings,
            },
            &mid_cap,
            &mut wallet_a,
            &mut wallet_a_s0,
            &mut wallet_a_s_out,
            &mut wallet_b,
            &mut wallet_b_s0,
            &mut wallet_b_s_out,
            &mut overflow_a,
            &mut overflow_a_s0,
            &mut overflow_a_s_out,
            &mut overflow_b,
            &mut overflow_b_s0,
            &mut overflow_b_s_out,
        )
        .expect("deterministic one-tile selected wallet columns");

        assert_eq!(
            [
                wallet_a[2][C1_CAPSULE_SOURCE_DIGEST_SLOT],
                wallet_a[3][C1_CAPSULE_SOURCE_DIGEST_SLOT],
            ],
            raw_digest_lanes(&source_hash)
        );
        assert_eq!(
            [
                wallet_a[2][ZK_AUTH_WALLET_A_MID_BASE + C1_CAPSULE_MID_DIGEST_SLOT],
                wallet_a[3][ZK_AUTH_WALLET_A_MID_BASE + C1_CAPSULE_MID_DIGEST_SLOT],
            ],
            raw_digest_lanes(&mid_hash)
        );
        assert_eq!(wallet_b[8][..WALLET_B_PATH_STRIDE], [F128::ZERO; 16]);
        assert_eq!(
            [
                overflow_a[2][C1_CAPSULE_SOURCE_DIGEST_SLOT],
                overflow_a[3][C1_CAPSULE_SOURCE_DIGEST_SLOT],
            ],
            raw_digest_lanes(&source_hash)
        );
        assert_eq!(
            [
                overflow_a[2][C1_CAPSULE_LEAF_STRIDE + C1_CAPSULE_MID_DIGEST_SLOT],
                overflow_a[3][C1_CAPSULE_LEAF_STRIDE + C1_CAPSULE_MID_DIGEST_SLOT],
            ],
            raw_digest_lanes(&mid_hash)
        );
        assert_eq!(overflow_b[8][..WALLET_B_PATH_STRIDE], [F128::ZERO; 16]);
    }
}
