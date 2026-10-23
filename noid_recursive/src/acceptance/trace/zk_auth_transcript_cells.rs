// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Zero-row cell view of the selected tiled Owner/Main authorization
//! transcripts.
//!
//! The two duplex walks already commit their absorb (`A0/A1`) and carry
//! (`C0..C3`) columns.  Authorization algebra must consume those exact cells:
//! copying a transcript field into a fresh witness wire would both spend a row
//! and create a second value that has to be pinned.  This module instead maps
//! every dynamic field and every challenge through the compiled
//! [`DuplexLayout`] and returns raw one-wire [`LinExpr`] aliases.
//!
//! Owner tiles have stride `2^7`; Main tiles have stride `2^8`.  Larger column
//! domains are unions of an equal number of transaction tiles.  The view
//! validates that geometry, all twelve committed slices, and the complete
//! selected layouts before it exposes a cell.

use noid_ivc_core::deep_chain::schedule::{DuplexLayout, LaneSource};
use noid_ivc_core::public_io::WitnessSlice;
use noid_tx::OwnerAuthorizationVersion;

use super::region_source_binding::slot_cell;
use super::{ExtExpr, FieldR1csBuilder, LinExpr};
use crate::acceptance::zk_auth_capsule_schedule::{
    ZkAuthCapsuleDuplexSchedules, ZK_AUTH_BETA_FIELDS, ZK_AUTH_BRIDGE_LANES,
    ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES, ZK_AUTH_MAIN_COMPILED_SLOTS, ZK_AUTH_MAIN_DYNAMIC_LANES,
    ZK_AUTH_MAIN_MID_CAP_DATA_START, ZK_AUTH_MAIN_NONCE_DATA_INDEX,
    ZK_AUTH_MAIN_PHASE_A_DATA_START, ZK_AUTH_MAIN_PHASE_B_VALUE_DATA_INDEX,
    ZK_AUTH_MAIN_RAW_CHALLENGE_LANES, ZK_AUTH_MAIN_SIGMA_DATA_INDEX, ZK_AUTH_MAIN_SQUEEZES,
    ZK_AUTH_MAIN_TAIL_DATA_START, ZK_AUTH_MAIN_TILE_LOG, ZK_AUTH_MAIN_UPPER_DATA_START,
    ZK_AUTH_MID_CAP_LANES, ZK_AUTH_MLECHECK_ROUND_FIELDS, ZK_AUTH_MLECHECK_VARS,
    ZK_AUTH_OWNER_COMPILED_SLOTS, ZK_AUTH_OWNER_DYNAMIC_LANES,
    ZK_AUTH_OWNER_PUBLIC_STATEMENT_FIELDS, ZK_AUTH_OWNER_RAW_CHALLENGE_LANES,
    ZK_AUTH_OWNER_SQUEEZES, ZK_AUTH_OWNER_TILE_LOG, ZK_AUTH_PHASE_A_ROUND_FIELDS,
    ZK_AUTH_QUERY_SEEDS, ZK_AUTH_SOURCE_CAP_HASHES, ZK_AUTH_SOURCE_CAP_LANES, ZK_AUTH_TAIL_FIELDS,
    ZK_AUTH_TERMINAL_FIELDS, ZK_AUTH_UPPER_FIELDS, ZK_AUTH_WALLET_A_MAIN_DATA_SLOT,
    ZK_AUTH_WALLET_A_MAIN_TAIL_BASE, ZK_AUTH_WALLET_A_OWNER_DATA_SLOT,
    ZK_AUTH_WALLET_A_OWNER_TAIL_BASE, ZK_AUTH_WALLET_A_TILE_LOG,
};

pub const ZK_AUTH_OWNER_PUBLIC_STATEMENT_DATA_START: usize = 0;
pub const ZK_AUTH_OWNER_SOURCE_CAP_DATA_START: usize = 4;
pub const ZK_AUTH_OWNER_MASK_MU_DATA_INDEX: usize = 20;
pub const ZK_AUTH_OWNER_ROUND_DATA_START: usize = 22;
pub const ZK_AUTH_OWNER_MASK_FINAL_DATA_INDEX: usize = 242;
pub const ZK_AUTH_OWNER_OPERAND_CLAIMS_DATA_START: usize = 244;
pub const ZK_AUTH_OWNER_OPERAND_CLAIMS: usize = 5;

pub const ZK_AUTH_OWNER_RHO_CHALLENGE_START: usize = 0;
pub const ZK_AUTH_OWNER_LAMBDA_CHALLENGE_INDEX: usize = 11;
pub const ZK_AUTH_OWNER_ROUND_CHALLENGE_START: usize = 12;
pub const ZK_AUTH_OWNER_ETA_CHALLENGE_INDEX: usize = 23;

pub const ZK_AUTH_MAIN_GAMMA_CHALLENGE_INDEX: usize = 0;
pub const ZK_AUTH_MAIN_PHASE_A_CHALLENGE_START: usize = 1;
pub const ZK_AUTH_MAIN_BETA_CHALLENGE_START: usize = 12;
pub const ZK_AUTH_MAIN_GRIND_CHALLENGE_INDEX: usize = 20;
pub const ZK_AUTH_MAIN_QUERY_SEED_CHALLENGE_START: usize = 21;
pub const ZK_AUTH_MAIN_GRIND_RAW_CHALLENGE_INDEX: usize = 2 * ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES;
pub const ZK_AUTH_MAIN_QUERY_SEED_RAW_CHALLENGE_START: usize =
    ZK_AUTH_MAIN_GRIND_RAW_CHALLENGE_INDEX + 1;

const _: () = assert!(ZK_AUTH_OWNER_PUBLIC_STATEMENT_DATA_START == 0);
const _: () = assert!(ZK_AUTH_OWNER_SOURCE_CAP_DATA_START == 4);
const _: () = assert!(ZK_AUTH_OWNER_SOURCE_CAP_DATA_START + ZK_AUTH_SOURCE_CAP_LANES == 20);
const _: () = assert!(ZK_AUTH_OWNER_MASK_MU_DATA_INDEX == 20);
const _: () = assert!(ZK_AUTH_OWNER_ROUND_DATA_START == 22);
const _: () = assert!(
    ZK_AUTH_OWNER_ROUND_DATA_START + 2 * ZK_AUTH_MLECHECK_VARS * ZK_AUTH_MLECHECK_ROUND_FIELDS
        == ZK_AUTH_OWNER_MASK_FINAL_DATA_INDEX
);
const _: () =
    assert!(ZK_AUTH_OWNER_MASK_FINAL_DATA_INDEX + 2 == ZK_AUTH_OWNER_OPERAND_CLAIMS_DATA_START);
const _: () = assert!(
    ZK_AUTH_OWNER_OPERAND_CLAIMS_DATA_START + 2 * ZK_AUTH_OWNER_OPERAND_CLAIMS
        == ZK_AUTH_OWNER_DYNAMIC_LANES
);
const _: () = assert!(ZK_AUTH_OWNER_OPERAND_CLAIMS + 1 == ZK_AUTH_TERMINAL_FIELDS);
const _: () = assert!(ZK_AUTH_OWNER_RHO_CHALLENGE_START == 0);
const _: () = assert!(ZK_AUTH_OWNER_LAMBDA_CHALLENGE_INDEX == ZK_AUTH_MLECHECK_VARS);
const _: () =
    assert!(ZK_AUTH_OWNER_ROUND_CHALLENGE_START == ZK_AUTH_OWNER_LAMBDA_CHALLENGE_INDEX + 1);
const _: () = assert!(
    ZK_AUTH_OWNER_ROUND_CHALLENGE_START + ZK_AUTH_MLECHECK_VARS
        == ZK_AUTH_OWNER_ETA_CHALLENGE_INDEX
);
const _: () = assert!(ZK_AUTH_OWNER_ETA_CHALLENGE_INDEX + 1 == ZK_AUTH_OWNER_SQUEEZES);

const _: () = assert!(ZK_AUTH_MAIN_SIGMA_DATA_INDEX == ZK_AUTH_BRIDGE_LANES);
const _: () = assert!(ZK_AUTH_MAIN_PHASE_A_DATA_START == 6);
const _: () = assert!(
    ZK_AUTH_MAIN_PHASE_A_DATA_START + 2 * ZK_AUTH_MLECHECK_VARS * ZK_AUTH_PHASE_A_ROUND_FIELDS
        == ZK_AUTH_MAIN_PHASE_B_VALUE_DATA_INDEX
);
const _: () = assert!(ZK_AUTH_MAIN_PHASE_B_VALUE_DATA_INDEX + 2 == ZK_AUTH_MAIN_UPPER_DATA_START);
const _: () = assert!(
    ZK_AUTH_MAIN_UPPER_DATA_START + 2 * ZK_AUTH_UPPER_FIELDS == ZK_AUTH_MAIN_MID_CAP_DATA_START
);
const _: () = assert!(
    ZK_AUTH_MAIN_MID_CAP_DATA_START + ZK_AUTH_MID_CAP_LANES == ZK_AUTH_MAIN_TAIL_DATA_START
);
const _: () = assert!(
    ZK_AUTH_MAIN_TAIL_DATA_START + 2 * ZK_AUTH_TAIL_FIELDS == ZK_AUTH_MAIN_NONCE_DATA_INDEX
);
const _: () = assert!(ZK_AUTH_MAIN_NONCE_DATA_INDEX + 1 == ZK_AUTH_MAIN_DYNAMIC_LANES);
const _: () = assert!(ZK_AUTH_MAIN_GAMMA_CHALLENGE_INDEX == 0);
const _: () = assert!(ZK_AUTH_MAIN_PHASE_A_CHALLENGE_START == 1);
const _: () = assert!(
    ZK_AUTH_MAIN_PHASE_A_CHALLENGE_START + ZK_AUTH_MLECHECK_VARS
        == ZK_AUTH_MAIN_BETA_CHALLENGE_START
);
const _: () = assert!(
    ZK_AUTH_MAIN_BETA_CHALLENGE_START + ZK_AUTH_BETA_FIELDS == ZK_AUTH_MAIN_GRIND_CHALLENGE_INDEX
);
const _: () =
    assert!(ZK_AUTH_MAIN_GRIND_CHALLENGE_INDEX + 1 == ZK_AUTH_MAIN_QUERY_SEED_CHALLENGE_START);
const _: () =
    assert!(ZK_AUTH_MAIN_QUERY_SEED_CHALLENGE_START + ZK_AUTH_QUERY_SEEDS == ZK_AUTH_MAIN_SQUEEZES);
const _: () = assert!(ZK_AUTH_MAIN_GRIND_RAW_CHALLENGE_INDEX == 40);
const _: () = assert!(ZK_AUTH_MAIN_QUERY_SEED_RAW_CHALLENGE_START == 41);
const _: () = assert!(
    ZK_AUTH_MAIN_QUERY_SEED_RAW_CHALLENGE_START + ZK_AUTH_QUERY_SEEDS
        == ZK_AUTH_MAIN_RAW_CHALLENGE_LANES
);

/// Dynamic Owner absorb cells and squeezed challenges for one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZkAuthOwnerTranscriptCells {
    pub public_statement: [LinExpr; ZK_AUTH_OWNER_PUBLIC_STATEMENT_FIELDS],
    /// Hash-major, lane-interleaved: `source_cap[2 * cap_index + digest_lane]`.
    pub source_cap: [LinExpr; ZK_AUTH_SOURCE_CAP_LANES],
    pub mask_mu: ExtExpr,
    pub round_coefficients: [[ExtExpr; ZK_AUTH_MLECHECK_ROUND_FIELDS]; ZK_AUTH_MLECHECK_VARS],
    pub mask_final: ExtExpr,
    /// Padded `state_inc(r)` followed by padded lane operands 0 through 3.
    pub operand_claims: [ExtExpr; ZK_AUTH_OWNER_OPERAND_CLAIMS],
    pub rho: [ExtExpr; ZK_AUTH_MLECHECK_VARS],
    pub lambda: ExtExpr,
    /// Owner MLE-check challenges in transcript HIGH-to-LOW round order.
    pub round_challenges: [ExtExpr; ZK_AUTH_MLECHECK_VARS],
    pub eta: ExtExpr,
}

impl ZkAuthOwnerTranscriptCells {
    /// Phase-B's `[digest_lane][cap_index]` view of the same source-cap cells.
    pub(crate) fn source_cap_by_digest_lane(&self) -> [[LinExpr; ZK_AUTH_SOURCE_CAP_HASHES]; 2] {
        std::array::from_fn(|lane| {
            std::array::from_fn(|node| self.source_cap[2 * node + lane].clone())
        })
    }
}

/// Dynamic Main absorb cells and squeezed challenges for one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZkAuthMainTranscriptCells {
    /// Derived Owner closing state, absorbed as Main data lanes 0 through 3.
    pub bridge: [LinExpr; ZK_AUTH_BRIDGE_LANES],
    pub sigma: ExtExpr,
    pub phase_a_round_coefficients:
        [[ExtExpr; ZK_AUTH_PHASE_A_ROUND_FIELDS]; ZK_AUTH_MLECHECK_VARS],
    pub phase_b_value: ExtExpr,
    pub upper: [ExtExpr; ZK_AUTH_UPPER_FIELDS],
    /// Hash-major, lane-interleaved: `mid_cap[2 * cap_index + digest_lane]`.
    pub mid_cap: [LinExpr; ZK_AUTH_MID_CAP_LANES],
    pub tail: [ExtExpr; ZK_AUTH_TAIL_FIELDS],
    pub nonce: LinExpr,
    pub gamma: ExtExpr,
    /// Phase-A challenges in transcript HIGH-to-LOW round order.
    pub phase_a_challenges: [ExtExpr; ZK_AUTH_MLECHECK_VARS],
    pub beta: [ExtExpr; ZK_AUTH_BETA_FIELDS],
    pub grind: LinExpr,
    pub query_seeds: [LinExpr; ZK_AUTH_QUERY_SEEDS],
}

impl ZkAuthMainTranscriptCells {
    /// Phase-B's `[digest_lane][cap_index]` view of the same mid-cap cells.
    pub(crate) fn mid_cap_by_digest_lane(&self) -> [[LinExpr; ZK_AUTH_MID_CAP_LANES / 2]; 2] {
        std::array::from_fn(|lane| {
            std::array::from_fn(|node| self.mid_cap[2 * node + lane].clone())
        })
    }
}

/// Alias-only view of both disconnected transcript tiles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZkAuthTranscriptCells {
    pub version: OwnerAuthorizationVersion,
    pub owner: ZkAuthOwnerTranscriptCells,
    pub main: ZkAuthMainTranscriptCells,
}

fn assert_layout_eq(actual: &DuplexLayout, selected: &DuplexLayout, name: &str) {
    assert_eq!(actual.n_data, selected.n_data, "{name} data-count drift");
    assert_eq!(
        actual.challenges, selected.challenges,
        "{name} challenge placement drift"
    );
    assert_eq!(
        actual.slots.len(),
        selected.slots.len(),
        "{name} slot-count drift"
    );
    for (slot, (actual, selected)) in actual.slots.iter().zip(&selected.slots).enumerate() {
        assert_eq!(
            actual.lanes, selected.lanes,
            "{name} absorb placement drift at slot {slot}"
        );
    }
}

fn assert_selected_layouts(owner: &DuplexLayout, main: &DuplexLayout) -> OwnerAuthorizationVersion {
    let version = match owner.slots.first().and_then(|slot| slot.lanes[1]) {
        Some(LaneSource::Const(3)) => OwnerAuthorizationVersion::V3,
        Some(LaneSource::Const(4)) => OwnerAuthorizationVersion::V4,
        _ => panic!("unsupported Owner transcript profile"),
    };
    let selected = ZkAuthCapsuleDuplexSchedules::for_version(version);
    let selected_owner = selected.owner_layout();
    let selected_main = selected.main_layout();
    assert_layout_eq(owner, &selected_owner, "Owner");
    assert_layout_eq(main, &selected_main, "Main");
    assert_eq!(owner.n_data, ZK_AUTH_OWNER_DYNAMIC_LANES);
    assert_eq!(main.n_data, ZK_AUTH_MAIN_DYNAMIC_LANES);
    assert_eq!(owner.challenges.len(), ZK_AUTH_OWNER_RAW_CHALLENGE_LANES);
    assert_eq!(main.challenges.len(), ZK_AUTH_MAIN_RAW_CHALLENGE_LANES);
    assert_eq!(owner.slots.len(), ZK_AUTH_OWNER_COMPILED_SLOTS);
    assert_eq!(main.slots.len(), ZK_AUTH_MAIN_COMPILED_SLOTS);
    version
}

fn checked_range(slice: &WitnessSlice) -> std::ops::Range<usize> {
    let start = slice.start();
    let end = start
        .checked_add(slice.len())
        .expect("duplex witness slice range overflow");
    assert!(
        end <= u32::MAX as usize,
        "duplex witness slice exceeds LinExpr wire address space"
    );
    start..end
}

fn assert_pairwise_disjoint(slices: &[WitnessSlice]) {
    for (index, left) in slices.iter().enumerate() {
        let left = checked_range(left);
        for right in &slices[index + 1..] {
            let right = checked_range(right);
            assert!(
                left.end <= right.start || right.end <= left.start,
                "Owner/Main duplex columns must occupy disjoint witness slices"
            );
        }
    }
}

fn validate_column_slices(
    owner_a: &[WitnessSlice; 2],
    owner_c: &[WitnessSlice; 4],
    main_a: &[WitnessSlice; 2],
    main_c: &[WitnessSlice; 4],
) -> usize {
    let owner = owner_a
        .iter()
        .chain(owner_c.iter())
        .copied()
        .collect::<Vec<_>>();
    let main = main_a
        .iter()
        .chain(main_c.iter())
        .copied()
        .collect::<Vec<_>>();
    assert!(
        owner
            .iter()
            .all(|slice| slice.log2_len >= ZK_AUTH_OWNER_TILE_LOG),
        "Owner columns must contain at least one selected m7 tile"
    );
    assert!(
        main.iter()
            .all(|slice| slice.log2_len >= ZK_AUTH_MAIN_TILE_LOG),
        "Main columns must contain at least one selected m8 tile"
    );
    assert!(
        owner
            .iter()
            .all(|slice| slice.log2_len == owner[0].log2_len),
        "Owner A/C columns must share one tiled domain"
    );
    assert!(
        main.iter().all(|slice| slice.log2_len == main[0].log2_len),
        "Main A/C columns must share one tiled domain"
    );

    let owner_tiles = 1usize << (owner[0].log2_len - ZK_AUTH_OWNER_TILE_LOG);
    let main_tiles = 1usize << (main[0].log2_len - ZK_AUTH_MAIN_TILE_LOG);
    assert_eq!(
        owner_tiles, main_tiles,
        "Owner and Main duplex unions must have equal tile counts"
    );

    let all = owner.into_iter().chain(main).collect::<Vec<_>>();
    assert_pairwise_disjoint(&all);
    owner_tiles
}

/// Return data-index -> `(slot, A lane)` from the compiled schedule.
///
/// This deliberately rejects duplicates and holes instead of allowing a
/// default physical cell to stand in for a malformed layout.
fn data_positions(layout: &DuplexLayout) -> Vec<(usize, usize)> {
    let mut positions = vec![None; layout.n_data];
    for (slot, descriptor) in layout.slots.iter().enumerate() {
        for (lane, source) in descriptor.lanes.iter().enumerate() {
            if let Some(LaneSource::Data(index)) = source {
                assert!(*index < positions.len(), "duplex data index out of range");
                assert!(
                    positions[*index].replace((slot, lane)).is_none(),
                    "duplicate duplex data index {index}"
                );
            }
        }
    }
    positions
        .into_iter()
        .enumerate()
        .map(|(index, position)| {
            position.unwrap_or_else(|| panic!("missing duplex data index {index}"))
        })
        .collect()
}

fn split_data_aliases(
    layout: &DuplexLayout,
    prefix_columns: &[WitnessSlice; 2],
    wallet_columns: &[WitnessSlice; 6],
    tile_index: usize,
    prefix_log: usize,
    tail_base: usize,
    first_data_slot: usize,
) -> Vec<LinExpr> {
    let prefix_slots = 1usize << prefix_log;
    let prefix_base = tile_index << prefix_log;
    let wallet_base = tile_index << ZK_AUTH_WALLET_A_TILE_LOG;
    data_positions(layout)
        .into_iter()
        .map(|(slot, lane)| {
            if slot < prefix_slots {
                slot_cell(&prefix_columns[lane], prefix_base + slot)
            } else if slot == prefix_slots {
                slot_cell(&wallet_columns[lane], wallet_base + first_data_slot)
            } else {
                slot_cell(
                    &wallet_columns[lane],
                    wallet_base + tail_base + slot - prefix_slots,
                )
            }
        })
        .collect()
}

fn split_challenge_aliases(
    layout: &DuplexLayout,
    prefix_columns: &[WitnessSlice; 4],
    wallet_columns: &[WitnessSlice; 6],
    tile_index: usize,
    prefix_log: usize,
    tail_base: usize,
) -> Vec<LinExpr> {
    let prefix_slots = 1usize << prefix_log;
    let prefix_base = tile_index << prefix_log;
    let wallet_base = tile_index << ZK_AUTH_WALLET_A_TILE_LOG;
    layout
        .challenges
        .iter()
        .map(|&(slot, lane)| {
            assert!(lane < 4 && slot < layout.slots.len());
            if slot < prefix_slots {
                slot_cell(&prefix_columns[lane], prefix_base + slot)
            } else {
                slot_cell(
                    &wallet_columns[2 + lane],
                    wallet_base + tail_base + slot - prefix_slots,
                )
            }
        })
        .collect()
}

fn wide_data(data: &[LinExpr], start: usize) -> ExtExpr {
    ExtExpr::new(data[start].clone(), data[start + 1].clone())
}

fn wide_challenge(
    b: &mut FieldR1csBuilder,
    raw_challenges: &[LinExpr],
    logical_index: usize,
) -> ExtExpr {
    let raw_start = 2 * logical_index;
    b.c1_challenge_from_raw(
        raw_challenges[raw_start].clone(),
        raw_challenges[raw_start + 1].clone(),
    )
}

/// Read-only one-wire aliases for a selected transcript tile before the C1
/// challenge map is materialized.  Keeping this view separate lets the block
/// assembler preflight every tile atomically without appending sampler rows.
pub(crate) struct ZkAuthRawTranscriptTile {
    pub version: OwnerAuthorizationVersion,
    pub owner_data: Vec<LinExpr>,
    pub owner_challenges: Vec<LinExpr>,
    pub main_data: Vec<LinExpr>,
    pub main_challenges: Vec<LinExpr>,
}

/// Split-layout counterpart used by the selected C1 profile. Owner/Main keep
/// their original dyadic prefix domains while the two authenticated suffixes
/// occupy Wallet-A. Every dynamic transcript field remains a one-wire alias;
/// the first suffix data block is retained in its dedicated carrier slot.
#[allow(clippy::too_many_arguments)]
pub(crate) fn view_zk_auth_raw_split_transcript_tile(
    owner_layout: &DuplexLayout,
    owner_a: &[WitnessSlice; 2],
    owner_c: &[WitnessSlice; 4],
    main_layout: &DuplexLayout,
    main_a: &[WitnessSlice; 2],
    main_c: &[WitnessSlice; 4],
    wallet_a: &[WitnessSlice; 6],
    tile_index: usize,
) -> ZkAuthRawTranscriptTile {
    let version = assert_selected_layouts(owner_layout, main_layout);
    let tile_count = validate_column_slices(owner_a, owner_c, main_a, main_c);
    assert!(wallet_a.iter().all(|slice| {
        slice.log2_len >= ZK_AUTH_WALLET_A_TILE_LOG && slice.log2_len == wallet_a[0].log2_len
    }));
    assert_eq!(
        tile_count,
        1usize << (wallet_a[0].log2_len - ZK_AUTH_WALLET_A_TILE_LOG)
    );
    assert!(
        tile_index < tile_count,
        "split transcript tile index out of range"
    );
    ZkAuthRawTranscriptTile {
        version,
        owner_data: split_data_aliases(
            owner_layout,
            owner_a,
            wallet_a,
            tile_index,
            ZK_AUTH_OWNER_TILE_LOG,
            ZK_AUTH_WALLET_A_OWNER_TAIL_BASE,
            ZK_AUTH_WALLET_A_OWNER_DATA_SLOT,
        ),
        owner_challenges: split_challenge_aliases(
            owner_layout,
            owner_c,
            wallet_a,
            tile_index,
            ZK_AUTH_OWNER_TILE_LOG,
            ZK_AUTH_WALLET_A_OWNER_TAIL_BASE,
        ),
        main_data: split_data_aliases(
            main_layout,
            main_a,
            wallet_a,
            tile_index,
            ZK_AUTH_MAIN_TILE_LOG,
            ZK_AUTH_WALLET_A_MAIN_TAIL_BASE,
            ZK_AUTH_WALLET_A_MAIN_DATA_SLOT,
        ),
        main_challenges: split_challenge_aliases(
            main_layout,
            main_c,
            wallet_a,
            tile_index,
            ZK_AUTH_MAIN_TILE_LOG,
            ZK_AUTH_WALLET_A_MAIN_TAIL_BASE,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn view_zk_auth_split_transcript_tile(
    b: &mut FieldR1csBuilder,
    owner_layout: &DuplexLayout,
    owner_a: &[WitnessSlice; 2],
    owner_c: &[WitnessSlice; 4],
    main_layout: &DuplexLayout,
    main_a: &[WitnessSlice; 2],
    main_c: &[WitnessSlice; 4],
    wallet_a: &[WitnessSlice; 6],
    tile_index: usize,
) -> ZkAuthTranscriptCells {
    let raw = view_zk_auth_raw_split_transcript_tile(
        owner_layout,
        owner_a,
        owner_c,
        main_layout,
        main_a,
        main_c,
        wallet_a,
        tile_index,
    );
    transcript_cells_from_raw(b, raw)
}

fn transcript_cells_from_raw(
    b: &mut FieldR1csBuilder,
    raw: ZkAuthRawTranscriptTile,
) -> ZkAuthTranscriptCells {
    let owner_data = raw.owner_data;
    let owner_challenges = raw.owner_challenges;
    let main_data = raw.main_data;
    let main_challenges = raw.main_challenges;

    let owner = ZkAuthOwnerTranscriptCells {
        public_statement: std::array::from_fn(|index| {
            owner_data[ZK_AUTH_OWNER_PUBLIC_STATEMENT_DATA_START + index].clone()
        }),
        source_cap: std::array::from_fn(|index| {
            owner_data[ZK_AUTH_OWNER_SOURCE_CAP_DATA_START + index].clone()
        }),
        mask_mu: wide_data(&owner_data, ZK_AUTH_OWNER_MASK_MU_DATA_INDEX),
        round_coefficients: std::array::from_fn(|round| {
            std::array::from_fn(|coefficient| {
                wide_data(
                    &owner_data,
                    ZK_AUTH_OWNER_ROUND_DATA_START
                        + 2 * (round * ZK_AUTH_MLECHECK_ROUND_FIELDS + coefficient),
                )
            })
        }),
        mask_final: wide_data(&owner_data, ZK_AUTH_OWNER_MASK_FINAL_DATA_INDEX),
        operand_claims: std::array::from_fn(|index| {
            wide_data(
                &owner_data,
                ZK_AUTH_OWNER_OPERAND_CLAIMS_DATA_START + 2 * index,
            )
        }),
        rho: std::array::from_fn(|index| {
            wide_challenge(
                b,
                &owner_challenges,
                ZK_AUTH_OWNER_RHO_CHALLENGE_START + index,
            )
        }),
        lambda: wide_challenge(b, &owner_challenges, ZK_AUTH_OWNER_LAMBDA_CHALLENGE_INDEX),
        round_challenges: std::array::from_fn(|round| {
            wide_challenge(
                b,
                &owner_challenges,
                ZK_AUTH_OWNER_ROUND_CHALLENGE_START + round,
            )
        }),
        eta: wide_challenge(b, &owner_challenges, ZK_AUTH_OWNER_ETA_CHALLENGE_INDEX),
    };

    let main = ZkAuthMainTranscriptCells {
        bridge: std::array::from_fn(|index| main_data[index].clone()),
        sigma: wide_data(&main_data, ZK_AUTH_MAIN_SIGMA_DATA_INDEX),
        phase_a_round_coefficients: std::array::from_fn(|round| {
            std::array::from_fn(|coefficient| {
                wide_data(
                    &main_data,
                    ZK_AUTH_MAIN_PHASE_A_DATA_START
                        + 2 * (round * ZK_AUTH_PHASE_A_ROUND_FIELDS + coefficient),
                )
            })
        }),
        phase_b_value: wide_data(&main_data, ZK_AUTH_MAIN_PHASE_B_VALUE_DATA_INDEX),
        upper: std::array::from_fn(|index| {
            wide_data(&main_data, ZK_AUTH_MAIN_UPPER_DATA_START + 2 * index)
        }),
        mid_cap: std::array::from_fn(|index| {
            main_data[ZK_AUTH_MAIN_MID_CAP_DATA_START + index].clone()
        }),
        tail: std::array::from_fn(|index| {
            wide_data(&main_data, ZK_AUTH_MAIN_TAIL_DATA_START + 2 * index)
        }),
        nonce: main_data[ZK_AUTH_MAIN_NONCE_DATA_INDEX].clone(),
        gamma: wide_challenge(b, &main_challenges, ZK_AUTH_MAIN_GAMMA_CHALLENGE_INDEX),
        phase_a_challenges: std::array::from_fn(|round| {
            wide_challenge(
                b,
                &main_challenges,
                ZK_AUTH_MAIN_PHASE_A_CHALLENGE_START + round,
            )
        }),
        beta: std::array::from_fn(|index| {
            wide_challenge(
                b,
                &main_challenges,
                ZK_AUTH_MAIN_BETA_CHALLENGE_START + index,
            )
        }),
        grind: main_challenges[ZK_AUTH_MAIN_GRIND_RAW_CHALLENGE_INDEX].clone(),
        query_seeds: std::array::from_fn(|index| {
            main_challenges[ZK_AUTH_MAIN_QUERY_SEED_RAW_CHALLENGE_START + index].clone()
        }),
    };

    ZkAuthTranscriptCells {
        version: raw.version,
        owner,
        main,
    }
}

#[cfg(test)]
mod tests {
    use noid_ivc_core::deep_chain::schedule::{build_duplex_columns, flat_of_tower_u128};
    use noid_ivc_core::field::{F128, F256};
    use noid_ivc_core::field_circuit::FieldR1csBuilder;
    use noid_poseidon2b::native::domain::{capacity_iv, TAG_KSCH256};

    use super::super::region_source_binding::alloc_column_slice;
    use super::*;

    fn sample(seed: u128, index: usize) -> F128 {
        flat_of_tower_u128(
            seed.wrapping_add(
                0x9E37_79B9_7F4A_7C15_6C8E_9CF5_7093_2BD5u128.wrapping_mul(index as u128 + 1),
            )
            .rotate_left(((19 * index + 7) % 127) as u32),
        )
    }

    fn stream(layout: &DuplexLayout, seed: u128) -> Vec<F128> {
        (0..layout.n_data)
            .map(|index| sample(seed, index))
            .collect()
    }

    fn iv_flat() -> [F128; 2] {
        let [hi, lo] = capacity_iv(TAG_KSCH256);
        [flat_of_tower_u128(hi.0), flat_of_tower_u128(lo.0)]
    }

    fn flatten_owner_data(cells: &ZkAuthOwnerTranscriptCells) -> Vec<LinExpr> {
        let mut out = Vec::with_capacity(ZK_AUTH_OWNER_DYNAMIC_LANES);
        out.extend(cells.public_statement.iter().cloned());
        out.extend(cells.source_cap.iter().cloned());
        out.extend([cells.mask_mu.lo.clone(), cells.mask_mu.hi.clone()]);
        for round in &cells.round_coefficients {
            for coefficient in round {
                out.extend([coefficient.lo.clone(), coefficient.hi.clone()]);
            }
        }
        out.extend([cells.mask_final.lo.clone(), cells.mask_final.hi.clone()]);
        for claim in &cells.operand_claims {
            out.extend([claim.lo.clone(), claim.hi.clone()]);
        }
        out
    }

    fn owner_wide_challenges(cells: &ZkAuthOwnerTranscriptCells) -> Vec<ExtExpr> {
        let mut out = Vec::with_capacity(ZK_AUTH_OWNER_SQUEEZES);
        out.extend(cells.rho.iter().cloned());
        out.push(cells.lambda.clone());
        out.extend(cells.round_challenges.iter().cloned());
        out.push(cells.eta.clone());
        out
    }

    fn flatten_main_data(cells: &ZkAuthMainTranscriptCells) -> Vec<LinExpr> {
        let mut out = Vec::with_capacity(ZK_AUTH_MAIN_DYNAMIC_LANES);
        out.extend(cells.bridge.iter().cloned());
        out.extend([cells.sigma.lo.clone(), cells.sigma.hi.clone()]);
        for round in &cells.phase_a_round_coefficients {
            for coefficient in round {
                out.extend([coefficient.lo.clone(), coefficient.hi.clone()]);
            }
        }
        out.extend([
            cells.phase_b_value.lo.clone(),
            cells.phase_b_value.hi.clone(),
        ]);
        for value in &cells.upper {
            out.extend([value.lo.clone(), value.hi.clone()]);
        }
        out.extend(cells.mid_cap.iter().cloned());
        for value in &cells.tail {
            out.extend([value.lo.clone(), value.hi.clone()]);
        }
        out.push(cells.nonce.clone());
        out
    }

    fn main_wide_challenges(cells: &ZkAuthMainTranscriptCells) -> Vec<ExtExpr> {
        let mut out = Vec::with_capacity(ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES);
        out.push(cells.gamma.clone());
        out.extend(cells.phase_a_challenges.iter().cloned());
        out.extend(cells.beta.iter().cloned());
        out
    }

    fn assert_alias(expr: &LinExpr, wire: usize, expected: F128, values: &[F128]) {
        assert_eq!(expr.terms, vec![(wire as u32, F128::ONE)]);
        assert_eq!(expr.constant, F128::ZERO);
        assert_eq!(expr.eval(values), expected);
    }

    fn split_data_wire(
        positions: &[(usize, usize)],
        index: usize,
        prefix: &[WitnessSlice; 2],
        wallet: &[WitnessSlice; 6],
        tile: usize,
        prefix_log: usize,
        tail_base: usize,
        data_slot: usize,
    ) -> usize {
        let (slot, lane) = positions[index];
        let prefix_slots = 1usize << prefix_log;
        if slot < prefix_slots {
            prefix[lane].start() + (tile << prefix_log) + slot
        } else if slot == prefix_slots {
            wallet[lane].start() + (tile << ZK_AUTH_WALLET_A_TILE_LOG) + data_slot
        } else {
            wallet[lane].start() + (tile << ZK_AUTH_WALLET_A_TILE_LOG) + tail_base + slot
                - prefix_slots
        }
    }

    fn split_challenge_wire(
        layout: &DuplexLayout,
        raw_index: usize,
        prefix: &[WitnessSlice; 4],
        wallet: &[WitnessSlice; 6],
        tile: usize,
        prefix_log: usize,
        tail_base: usize,
    ) -> usize {
        let (slot, lane) = layout.challenges[raw_index];
        let prefix_slots = 1usize << prefix_log;
        if slot < prefix_slots {
            prefix[lane].start() + (tile << prefix_log) + slot
        } else {
            wallet[2 + lane].start() + (tile << ZK_AUTH_WALLET_A_TILE_LOG) + tail_base + slot
                - prefix_slots
        }
    }

    struct BuiltFixture {
        builder: FieldR1csBuilder,
        owner_layout: DuplexLayout,
        main_layout: DuplexLayout,
        owner_a: [WitnessSlice; 2],
        owner_c: [WitnessSlice; 4],
        main_a: [WitnessSlice; 2],
        main_c: [WitnessSlice; 4],
        wallet_a: [WitnessSlice; 6],
        owner_data: Vec<Vec<F128>>,
        owner_challenges: Vec<Vec<F128>>,
        main_data: Vec<Vec<F128>>,
        main_challenges: Vec<Vec<F128>>,
    }

    fn build_fixture(tile_count: usize, salt: u128) -> BuiltFixture {
        assert!(tile_count.is_power_of_two());
        let tile_log = tile_count.trailing_zeros() as usize;
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        let owner_layout = schedules.owner_layout();
        let main_layout = schedules.main_layout();

        let mut owner_data = Vec::with_capacity(tile_count);
        let mut owner_challenges = Vec::with_capacity(tile_count);
        let mut main_data = Vec::with_capacity(tile_count);
        let mut main_challenges = Vec::with_capacity(tile_count);
        let mut owner_columns_a: [Vec<F128>; 2] = std::array::from_fn(|_| Vec::new());
        let mut owner_columns_c: [Vec<F128>; 4] = std::array::from_fn(|_| Vec::new());
        let mut main_columns_a: [Vec<F128>; 2] = std::array::from_fn(|_| Vec::new());
        let mut main_columns_c: [Vec<F128>; 4] = std::array::from_fn(|_| Vec::new());
        let mut wallet_columns: [Vec<F128>; 6] =
            std::array::from_fn(|_| vec![F128::ZERO; tile_count << ZK_AUTH_WALLET_A_TILE_LOG]);

        for tile in 0..tile_count {
            let owner_stream = stream(&owner_layout, salt ^ (tile as u128 + 1) * 0x101);
            let owner = build_duplex_columns(
                &owner_layout,
                iv_flat(),
                &owner_stream,
                owner_layout
                    .slots
                    .len()
                    .next_power_of_two()
                    .trailing_zeros() as usize,
            );
            let mut main_stream = stream(&main_layout, salt ^ (tile as u128 + 1) * 0x10001);
            for lane in 0..ZK_AUTH_BRIDGE_LANES {
                main_stream[lane] = owner.c[lane][owner_layout.slots.len() - 1];
            }
            let main = build_duplex_columns(
                &main_layout,
                iv_flat(),
                &main_stream,
                main_layout.slots.len().next_power_of_two().trailing_zeros() as usize,
            );

            for lane in 0..2 {
                owner_columns_a[lane]
                    .extend_from_slice(&owner.a[lane][..1 << ZK_AUTH_OWNER_TILE_LOG]);
                main_columns_a[lane].extend_from_slice(&main.a[lane][..1 << ZK_AUTH_MAIN_TILE_LOG]);
            }
            for lane in 0..4 {
                owner_columns_c[lane]
                    .extend_from_slice(&owner.c[lane][..1 << ZK_AUTH_OWNER_TILE_LOG]);
                main_columns_c[lane].extend_from_slice(&main.c[lane][..1 << ZK_AUTH_MAIN_TILE_LOG]);
            }
            let wallet_base = tile << ZK_AUTH_WALLET_A_TILE_LOG;
            for (columns, prefix_log, tail_base, data_slot, bridge_slot, full_slots) in [
                (
                    &owner,
                    ZK_AUTH_OWNER_TILE_LOG,
                    ZK_AUTH_WALLET_A_OWNER_TAIL_BASE,
                    ZK_AUTH_WALLET_A_OWNER_DATA_SLOT,
                    crate::acceptance::zk_auth_capsule_schedule::ZK_AUTH_WALLET_A_OWNER_BRIDGE_SLOT,
                    owner_layout.slots.len(),
                ),
                (
                    &main,
                    ZK_AUTH_MAIN_TILE_LOG,
                    ZK_AUTH_WALLET_A_MAIN_TAIL_BASE,
                    ZK_AUTH_WALLET_A_MAIN_DATA_SLOT,
                    crate::acceptance::zk_auth_capsule_schedule::ZK_AUTH_WALLET_A_MAIN_BRIDGE_SLOT,
                    main_layout.slots.len(),
                ),
            ] {
                let prefix_slots = 1usize << prefix_log;
                let tail_slots = full_slots - prefix_slots;
                wallet_columns[0][wallet_base + bridge_slot] = columns.c[2][prefix_slots - 1];
                wallet_columns[1][wallet_base + bridge_slot] = columns.c[3][prefix_slots - 1];
                for lane in 0..2 {
                    wallet_columns[lane][wallet_base + data_slot] = columns.a[lane][prefix_slots];
                    wallet_columns[lane]
                        [wallet_base + tail_base..wallet_base + tail_base + tail_slots]
                        .copy_from_slice(&columns.a[lane][prefix_slots..prefix_slots + tail_slots]);
                    wallet_columns[lane][wallet_base + tail_base] +=
                        columns.c[lane][prefix_slots - 1];
                }
                for lane in 0..4 {
                    wallet_columns[2 + lane]
                        [wallet_base + tail_base..wallet_base + tail_base + tail_slots]
                        .copy_from_slice(&columns.c[lane][prefix_slots..prefix_slots + tail_slots]);
                }
            }
            owner_data.push(owner_stream);
            owner_challenges.push(owner.challenges);
            main_data.push(main_stream);
            main_challenges.push(main.challenges);
        }

        let mut builder = FieldR1csBuilder::new();
        let owner_log = ZK_AUTH_OWNER_TILE_LOG + tile_log;
        let main_log = ZK_AUTH_MAIN_TILE_LOG + tile_log;
        let owner_a = std::array::from_fn(|lane| {
            alloc_column_slice(&mut builder, &owner_columns_a[lane], owner_log).0
        });
        let owner_c = std::array::from_fn(|lane| {
            alloc_column_slice(&mut builder, &owner_columns_c[lane], owner_log).0
        });
        let main_a = std::array::from_fn(|lane| {
            alloc_column_slice(&mut builder, &main_columns_a[lane], main_log).0
        });
        let main_c = std::array::from_fn(|lane| {
            alloc_column_slice(&mut builder, &main_columns_c[lane], main_log).0
        });
        let wallet_a = std::array::from_fn(|lane| {
            alloc_column_slice(
                &mut builder,
                &wallet_columns[lane],
                ZK_AUTH_WALLET_A_TILE_LOG + tile_log,
            )
            .0
        });

        BuiltFixture {
            builder,
            owner_layout,
            main_layout,
            owner_a,
            owner_c,
            main_a,
            main_c,
            wallet_a,
            owner_data,
            owner_challenges,
            main_data,
            main_challenges,
        }
    }

    fn assert_complete_mapping(fixture: &BuiltFixture, tile: usize, cells: &ZkAuthTranscriptCells) {
        let values = fixture.builder.values();
        let owner_positions = data_positions(&fixture.owner_layout);
        let main_positions = data_positions(&fixture.main_layout);

        let owner_data = flatten_owner_data(&cells.owner);
        let owner_challenges = owner_wide_challenges(&cells.owner);
        let main_data = flatten_main_data(&cells.main);
        let main_challenges = main_wide_challenges(&cells.main);
        assert_eq!(owner_data.len(), ZK_AUTH_OWNER_DYNAMIC_LANES);
        assert_eq!(owner_challenges.len(), ZK_AUTH_OWNER_SQUEEZES);
        assert_eq!(main_data.len(), ZK_AUTH_MAIN_DYNAMIC_LANES);
        assert_eq!(main_challenges.len(), ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES);

        for (index, expr) in owner_data.iter().enumerate() {
            assert_alias(
                expr,
                split_data_wire(
                    &owner_positions,
                    index,
                    &fixture.owner_a,
                    &fixture.wallet_a,
                    tile,
                    ZK_AUTH_OWNER_TILE_LOG,
                    ZK_AUTH_WALLET_A_OWNER_TAIL_BASE,
                    ZK_AUTH_WALLET_A_OWNER_DATA_SLOT,
                ),
                fixture.owner_data[tile][index],
                values,
            );
        }
        for (index, expr) in owner_challenges.iter().enumerate() {
            let raw_index = 2 * index;
            assert_alias(
                &expr.lo,
                split_challenge_wire(
                    &fixture.owner_layout,
                    raw_index,
                    &fixture.owner_c,
                    &fixture.wallet_a,
                    tile,
                    ZK_AUTH_OWNER_TILE_LOG,
                    ZK_AUTH_WALLET_A_OWNER_TAIL_BASE,
                ),
                fixture.owner_challenges[tile][raw_index],
                values,
            );
            assert_eq!(
                expr.eval(values),
                F256::from_raw_challenge_lanes(
                    fixture.owner_challenges[tile][raw_index],
                    fixture.owner_challenges[tile][raw_index + 1],
                )
            );
        }
        for (index, expr) in main_data.iter().enumerate() {
            assert_alias(
                expr,
                split_data_wire(
                    &main_positions,
                    index,
                    &fixture.main_a,
                    &fixture.wallet_a,
                    tile,
                    ZK_AUTH_MAIN_TILE_LOG,
                    ZK_AUTH_WALLET_A_MAIN_TAIL_BASE,
                    ZK_AUTH_WALLET_A_MAIN_DATA_SLOT,
                ),
                fixture.main_data[tile][index],
                values,
            );
        }
        for (index, expr) in main_challenges.iter().enumerate() {
            let raw_index = 2 * index;
            assert_alias(
                &expr.lo,
                split_challenge_wire(
                    &fixture.main_layout,
                    raw_index,
                    &fixture.main_c,
                    &fixture.wallet_a,
                    tile,
                    ZK_AUTH_MAIN_TILE_LOG,
                    ZK_AUTH_WALLET_A_MAIN_TAIL_BASE,
                ),
                fixture.main_challenges[tile][raw_index],
                values,
            );
            assert_eq!(
                expr.eval(values),
                F256::from_raw_challenge_lanes(
                    fixture.main_challenges[tile][raw_index],
                    fixture.main_challenges[tile][raw_index + 1],
                )
            );
        }
        for (raw_index, expr) in
            std::iter::once((ZK_AUTH_MAIN_GRIND_RAW_CHALLENGE_INDEX, &cells.main.grind)).chain(
                cells
                    .main
                    .query_seeds
                    .iter()
                    .enumerate()
                    .map(|(index, expr)| {
                        (ZK_AUTH_MAIN_QUERY_SEED_RAW_CHALLENGE_START + index, expr)
                    }),
            )
        {
            assert_alias(
                expr,
                split_challenge_wire(
                    &fixture.main_layout,
                    raw_index,
                    &fixture.main_c,
                    &fixture.wallet_a,
                    tile,
                    ZK_AUTH_MAIN_TILE_LOG,
                    ZK_AUTH_WALLET_A_MAIN_TAIL_BASE,
                ),
                fixture.main_challenges[tile][raw_index],
                values,
            );
        }
    }

    #[test]
    fn k1_real_duplex_columns_map_every_cell_with_exact_c1_sampler_rows() {
        let mut fixture = build_fixture(1, 0xA11C_E001);
        let before = fixture.builder.num_wires();
        let cells = view_zk_auth_split_transcript_tile(
            &mut fixture.builder,
            &fixture.owner_layout,
            &fixture.owner_a,
            &fixture.owner_c,
            &fixture.main_layout,
            &fixture.main_a,
            &fixture.main_c,
            &fixture.wallet_a,
            0,
        );
        assert_eq!(
            fixture.builder.num_wires() - before,
            ZK_AUTH_OWNER_SQUEEZES + ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES
        );
        assert_complete_mapping(&fixture, 0, &cells);

        let source_by_lane = cells.owner.source_cap_by_digest_lane();
        for lane in 0..2 {
            for node in 0..ZK_AUTH_SOURCE_CAP_HASHES {
                assert_eq!(
                    source_by_lane[lane][node],
                    cells.owner.source_cap[2 * node + lane]
                );
            }
        }
        let mid_by_lane = cells.main.mid_cap_by_digest_lane();
        for lane in 0..2 {
            for node in 0..ZK_AUTH_MID_CAP_LANES / 2 {
                assert_eq!(mid_by_lane[lane][node], cells.main.mid_cap[2 * node + lane]);
            }
        }
        for bridge in &cells.main.bridge {
            assert_ne!(bridge, &cells.main.sigma.lo, "sigma aliases a bridge cell");
            assert_ne!(bridge, &cells.main.sigma.hi, "sigma aliases a bridge cell");
        }
    }

    #[test]
    fn k2_real_duplex_columns_preserve_tile_isolation() {
        let mut fixture = build_fixture(2, 0x715E_1A7E);
        let before = fixture.builder.num_wires();
        let tile0 = view_zk_auth_split_transcript_tile(
            &mut fixture.builder,
            &fixture.owner_layout,
            &fixture.owner_a,
            &fixture.owner_c,
            &fixture.main_layout,
            &fixture.main_a,
            &fixture.main_c,
            &fixture.wallet_a,
            0,
        );
        let tile1 = view_zk_auth_split_transcript_tile(
            &mut fixture.builder,
            &fixture.owner_layout,
            &fixture.owner_a,
            &fixture.owner_c,
            &fixture.main_layout,
            &fixture.main_a,
            &fixture.main_c,
            &fixture.wallet_a,
            1,
        );
        assert_eq!(
            fixture.builder.num_wires() - before,
            2 * (ZK_AUTH_OWNER_SQUEEZES + ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES)
        );
        assert_complete_mapping(&fixture, 0, &tile0);
        assert_complete_mapping(&fixture, 1, &tile1);

        for (left, right) in flatten_owner_data(&tile0.owner)
            .iter()
            .zip(flatten_owner_data(&tile1.owner))
        {
            assert_ne!(left, &right, "Owner tile aliases overlap");
        }
        for (left, right) in main_wide_challenges(&tile0.main)
            .iter()
            .zip(main_wide_challenges(&tile1.main))
        {
            assert_ne!(left, &right, "Main tile aliases overlap");
        }
    }

    fn built_matrix(salt: u128) -> noid_ivc_core::field_r1cs::FieldR1cs {
        let mut fixture = build_fixture(1, salt);
        let before = fixture.builder.num_wires();
        let _ = view_zk_auth_split_transcript_tile(
            &mut fixture.builder,
            &fixture.owner_layout,
            &fixture.owner_a,
            &fixture.owner_c,
            &fixture.main_layout,
            &fixture.main_a,
            &fixture.main_c,
            &fixture.wallet_a,
            0,
        );
        assert_eq!(
            fixture.builder.num_wires() - before,
            ZK_AUTH_OWNER_SQUEEZES + ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES
        );
        fixture.builder.build().0
    }

    #[test]
    fn alias_view_is_matrix_and_witness_value_invariant() {
        let left = built_matrix(0x1111_2222);
        let right = built_matrix(0xAAAA_BBBB);
        assert_eq!(left.useful_rows, right.useful_rows);
        assert_eq!(left.a_0, right.a_0);
        assert_eq!(left.b_0, right.b_0);
        assert_eq!(
            left.structural_statement_digest(),
            right.structural_statement_digest()
        );
    }

    #[test]
    fn selected_schedule_drift_is_rejected_before_mapping() {
        let mut fixture = build_fixture(1, 0x5C4E_DA1F);
        let mut owner = fixture.owner_layout.clone();
        owner.challenges[0].0 += 1;
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            view_zk_auth_split_transcript_tile(
                &mut fixture.builder,
                &owner,
                &fixture.owner_a,
                &fixture.owner_c,
                &fixture.main_layout,
                &fixture.main_a,
                &fixture.main_c,
                &fixture.wallet_a,
                0,
            )
        }));
        assert!(
            rejected.is_err(),
            "Owner challenge-placement drift survived"
        );

        let mut main = fixture.main_layout.clone();
        main.slots[0].lanes[1] = Some(LaneSource::Data(1));
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            view_zk_auth_split_transcript_tile(
                &mut fixture.builder,
                &fixture.owner_layout,
                &fixture.owner_a,
                &fixture.owner_c,
                &main,
                &fixture.main_a,
                &fixture.main_c,
                &fixture.wallet_a,
                0,
            )
        }));
        assert!(rejected.is_err(), "Main absorb-placement drift survived");
    }
}
