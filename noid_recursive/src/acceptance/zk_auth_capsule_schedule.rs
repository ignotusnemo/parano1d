// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Production duplex schedules for the selected ZK authorization capsule.
//!
//! The selected construction keeps the existing two channel families. The
//! Owner schedule fits m7 and Main remains m8. Owner binds the public
//! statement, joint affine source commitment, ZK MLE-check, and all post-claim
//! scalars. It then closes on one fixed full absorb block. All four resulting
//! sponge-state lanes are shared wires into the Main channel before `sigma`
//! and `gamma`; they are never serialized.
//! This executable schedule/bridge contract is consumed by the selected-class
//! recursive assembly.

use noid_ivc_core::deep_chain::capsule_leaf::{C1_CAPSULE_MID_SLOTS, C1_CAPSULE_SOURCE_SLOTS};
use noid_ivc_core::deep_chain::schedule::{compile_duplex, DuplexLayout, LaneSource, TranscriptOp};
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;
use noid_tx::OwnerAuthorizationVersion;

pub use noid_gkr::zk_authorization::{
    affine_blend_gamma_is_admissible, ZK_AUTH_BETA_FIELDS, ZK_AUTH_BRIDGE_LANES, ZK_AUTH_GRIND_TAG,
    ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES, ZK_AUTH_MAIN_BRIDGE_DATA_START, ZK_AUTH_MAIN_COMPILED_SLOTS,
    ZK_AUTH_MAIN_CONSTANT_LANES, ZK_AUTH_MAIN_DYNAMIC_LANES, ZK_AUTH_MAIN_FROM_OWNER_TAG,
    ZK_AUTH_MAIN_MID_CAP_DATA_START, ZK_AUTH_MAIN_NONCE_DATA_INDEX,
    ZK_AUTH_MAIN_PHASE_A_DATA_START, ZK_AUTH_MAIN_PHASE_B_VALUE_DATA_INDEX,
    ZK_AUTH_MAIN_RAW_CHALLENGE_LANES, ZK_AUTH_MAIN_SIGMA_DATA_INDEX, ZK_AUTH_MAIN_SQUEEZES,
    ZK_AUTH_MAIN_TAIL_DATA_START, ZK_AUTH_MAIN_TILE_LOG, ZK_AUTH_MAIN_UPPER_DATA_START,
    ZK_AUTH_MID_CAP_LANES, ZK_AUTH_MID_CAP_TAG, ZK_AUTH_MLECHECK_ROUND_FIELDS,
    ZK_AUTH_MLECHECK_VARS, ZK_AUTH_OWNER_BRIDGE_SLOT, ZK_AUTH_OWNER_COMPILED_SLOTS,
    ZK_AUTH_OWNER_CONSTANT_LANES, ZK_AUTH_OWNER_CONSTRUCTION_VERSION, ZK_AUTH_OWNER_DYNAMIC_LANES,
    ZK_AUTH_OWNER_PREFIX_CONSTANTS, ZK_AUTH_OWNER_PROTOCOL_TAG,
    ZK_AUTH_OWNER_PUBLIC_STATEMENT_FIELDS, ZK_AUTH_OWNER_RAW_CHALLENGE_LANES,
    ZK_AUTH_OWNER_SQUEEZES, ZK_AUTH_OWNER_TILE_LOG, ZK_AUTH_OWNER_TO_MAIN_CLOSE_TAG,
    ZK_AUTH_PHASE_A_ROUND_FIELDS, ZK_AUTH_PHASE_B_TAG, ZK_AUTH_QUERY_SEEDS,
    ZK_AUTH_REJECTED_SINGLE_CHANNEL_SLOTS, ZK_AUTH_SOURCE_CAP_HASHES, ZK_AUTH_SOURCE_CAP_LANES,
    ZK_AUTH_TAIL_FIELDS, ZK_AUTH_TAIL_TAG, ZK_AUTH_TERMINAL_FIELDS, ZK_AUTH_UPPER_FIELDS,
};

const _: () =
    assert!(ZK_AUTH_MLECHECK_VARS == noid_gkr::zk_auth_capsule::ZK_AUTH_CAPSULE_BANK_VARS);
const _: () =
    assert!(ZK_AUTH_MLECHECK_ROUND_FIELDS == noid_gkr::zk_mlecheck::ZK_MLECHECK_ROUND_PROOF_COEFFS);
const _: () = assert!(ZK_AUTH_UPPER_FIELDS == 1 << 8);
const _: () = assert!(ZK_AUTH_QUERY_SEEDS * 128 >= 65 * 13);
const _: () = assert!(1 << ZK_AUTH_OWNER_TILE_LOG == 128);
const _: () = assert!(1 << ZK_AUTH_MAIN_TILE_LOG == 256);

/// The first 64 query leaves stay in Wallet-A. Source leaves are packed at
/// their exact 12-slot schedule while mid leaves retain their exact 16 slots.
/// The remaining 256 slots carry the two transcript suffixes without changing
/// either selected outer matrix.
pub const ZK_AUTH_WALLET_CORE_QUERY_COUNT: usize = 64;
pub const ZK_AUTH_WALLET_A_TILE_LOG: usize = 11;
pub const ZK_AUTH_WALLET_A_SOURCE_BASE: usize = 0;
pub const ZK_AUTH_WALLET_A_SOURCE_SLOTS: usize =
    ZK_AUTH_WALLET_CORE_QUERY_COUNT * C1_CAPSULE_SOURCE_SLOTS;
pub const ZK_AUTH_WALLET_A_MID_BASE: usize = ZK_AUTH_WALLET_A_SOURCE_SLOTS;
pub const ZK_AUTH_WALLET_A_MID_SLOTS: usize =
    ZK_AUTH_WALLET_CORE_QUERY_COUNT * C1_CAPSULE_MID_SLOTS;
pub const ZK_AUTH_WALLET_A_TRANSCRIPT_BASE: usize =
    ZK_AUTH_WALLET_A_MID_BASE + ZK_AUTH_WALLET_A_MID_SLOTS;

pub const ZK_AUTH_OWNER_PREFIX_SLOTS: usize = 1 << ZK_AUTH_OWNER_TILE_LOG;
pub const ZK_AUTH_MAIN_PREFIX_SLOTS: usize = 1 << ZK_AUTH_MAIN_TILE_LOG;
pub const ZK_AUTH_OWNER_TAIL_SLOTS: usize =
    ZK_AUTH_OWNER_COMPILED_SLOTS - ZK_AUTH_OWNER_PREFIX_SLOTS;
pub const ZK_AUTH_MAIN_TAIL_SLOTS: usize = ZK_AUTH_MAIN_COMPILED_SLOTS - ZK_AUTH_MAIN_PREFIX_SLOTS;

/// Each split suffix receives one non-permutation carrier slot immediately
/// before its first live permutation. The carrier stores the two capacity
/// lanes of the preceding prefix state; the first suffix A cells store the
/// two rate lanes plus that slot's absorb contribution.
pub const ZK_AUTH_WALLET_A_OWNER_BRIDGE_SLOT: usize = ZK_AUTH_WALLET_A_TRANSCRIPT_BASE;
pub const ZK_AUTH_WALLET_A_OWNER_TAIL_BASE: usize = ZK_AUTH_WALLET_A_OWNER_BRIDGE_SLOT + 1;
pub const ZK_AUTH_WALLET_A_MAIN_BRIDGE_SLOT: usize =
    ZK_AUTH_WALLET_A_OWNER_TAIL_BASE + ZK_AUTH_OWNER_TAIL_SLOTS;
pub const ZK_AUTH_WALLET_A_MAIN_TAIL_BASE: usize = ZK_AUTH_WALLET_A_MAIN_BRIDGE_SLOT + 1;
pub const ZK_AUTH_WALLET_A_OWNER_DATA_SLOT: usize =
    ZK_AUTH_WALLET_A_MAIN_TAIL_BASE + ZK_AUTH_MAIN_TAIL_SLOTS;
pub const ZK_AUTH_WALLET_A_MAIN_DATA_SLOT: usize = ZK_AUTH_WALLET_A_OWNER_DATA_SLOT + 1;
pub const ZK_AUTH_WALLET_A_LIVE_SLOTS: usize = ZK_AUTH_WALLET_A_MAIN_DATA_SLOT + 1;

const _: () = assert!(C1_CAPSULE_SOURCE_SLOTS == 12);
const _: () = assert!(C1_CAPSULE_MID_SLOTS == 16);
const _: () = assert!(ZK_AUTH_WALLET_A_SOURCE_SLOTS == 768);
const _: () = assert!(ZK_AUTH_WALLET_A_MID_SLOTS == 1024);
const _: () = assert!(ZK_AUTH_WALLET_A_TRANSCRIPT_BASE == 1792);
const _: () = assert!(ZK_AUTH_OWNER_TAIL_SLOTS == 29);
const _: () = assert!(ZK_AUTH_MAIN_TAIL_SLOTS == 79);
const _: () = assert!(ZK_AUTH_WALLET_A_OWNER_DATA_SLOT == 1902);
const _: () = assert!(ZK_AUTH_WALLET_A_MAIN_DATA_SLOT == 1903);
const _: () = assert!(ZK_AUTH_WALLET_A_LIVE_SLOTS == 1904);
const _: () = assert!(ZK_AUTH_WALLET_A_LIVE_SLOTS <= 1 << ZK_AUTH_WALLET_A_TILE_LOG);

/// Construction identity of the selected post-commit Owner/Main region pair.
///
/// This is deliberately the padded-terminal Owner construction version, not
/// the legacy C-prime/FRICHANL sidecar identity.  The child VK separately
/// binds the exact compiled layout, fixed patterns, slices and full domain.
pub const ZK_AUTH_REGION_SIDECAR_CONSTRUCTION_VERSION: u8 =
    ZK_AUTH_OWNER_CONSTRUCTION_VERSION as u8;

const ZK_AUTH_REGION_SIDECAR_PURPOSE_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/ZK-AUTH-SPLIT/V4";

fn selected_zk_auth_region_sidecar_purpose(role: &[u8]) -> [u8; 32] {
    zk_auth_region_sidecar_purpose_for_version(role, OwnerAuthorizationVersion::V4)
}

pub(crate) fn zk_auth_region_sidecar_purpose_for_version(
    role: &[u8],
    construction: OwnerAuthorizationVersion,
) -> [u8; 32] {
    let version = [construction as u8];
    let domain: &[u8] = match construction {
        OwnerAuthorizationVersion::V3 => b"NOID/REGION-SIDECAR/ZK-AUTH-SPLIT/V3",
        OwnerAuthorizationVersion::V4 => ZK_AUTH_REGION_SIDECAR_PURPOSE_DOMAIN,
    };
    poseidon2b_hash_byte_slices(domain, &[&version, b"KSCH256_", role])
}

/// Canonical purpose of the selected padded-terminal Owner duplex child.
pub fn selected_zk_auth_owner_sidecar_purpose() -> [u8; 32] {
    selected_zk_auth_region_sidecar_purpose(b"owner")
}

/// Canonical purpose of the selected Phase-A/Phase-B Main duplex child.
pub fn selected_zk_auth_main_sidecar_purpose() -> [u8; 32] {
    selected_zk_auth_region_sidecar_purpose(b"main")
}

/// Canonical purpose of the selected source/mid capsule-leaf Walk-A child.
pub fn selected_zk_auth_wallet_a_sidecar_purpose() -> [u8; 32] {
    selected_zk_auth_region_sidecar_purpose(b"wallet-a")
}

/// Canonical purpose of the selected depth-eight source/mid Walk-B child.
pub fn selected_zk_auth_wallet_b_sidecar_purpose() -> [u8; 32] {
    selected_zk_auth_region_sidecar_purpose(b"wallet-b")
}

#[derive(Clone, Debug)]
pub struct ZkAuthCapsuleDuplexSchedules {
    pub owner_ops: Vec<TranscriptOp>,
    pub main_ops: Vec<TranscriptOp>,
}

impl ZkAuthCapsuleDuplexSchedules {
    pub fn selected() -> Self {
        Self::for_version(OwnerAuthorizationVersion::V4)
    }

    pub fn for_version(version: OwnerAuthorizationVersion) -> Self {
        Self {
            owner_ops: owner_ops_for_version(true, version),
            main_ops: main_ops(true),
        }
    }

    pub fn owner_layout(&self) -> DuplexLayout {
        compile_duplex(&self.owner_ops)
    }

    pub fn main_layout(&self) -> DuplexLayout {
        compile_duplex(&self.main_ops)
    }

    pub fn owner_sidecar_layout(&self) -> DuplexLayout {
        prefix_layout(&self.owner_layout(), ZK_AUTH_OWNER_PREFIX_SLOTS)
    }

    pub fn main_sidecar_layout(&self) -> DuplexLayout {
        prefix_layout(&self.main_layout(), ZK_AUTH_MAIN_PREFIX_SLOTS)
    }
}

/// Canonical physical prefix authenticated by the original Owner/Main child.
/// Data indices in a compiled transcript are monotone, hence every prefix has
/// a contiguous `0..n_data` data stream.
fn prefix_layout(layout: &DuplexLayout, slots: usize) -> DuplexLayout {
    assert!(
        slots <= layout.slots.len(),
        "duplex prefix exceeds schedule"
    );
    let prefix_slots = layout.slots[..slots].to_vec();
    let n_data = prefix_slots
        .iter()
        .flat_map(|slot| slot.lanes)
        .filter_map(|lane| match lane {
            Some(LaneSource::Data(index)) => Some(index + 1),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    assert!(prefix_slots
        .iter()
        .flat_map(|slot| slot.lanes)
        .all(|lane| !matches!(lane, Some(LaneSource::Data(index)) if index >= n_data)));
    DuplexLayout {
        slots: prefix_slots,
        challenges: layout
            .challenges
            .iter()
            .copied()
            .filter(|(slot, _)| *slot < slots)
            .collect(),
        n_data,
    }
}

fn data_lanes(count: usize) -> Vec<Option<u128>> {
    vec![None; count]
}

fn squeeze_wide(count: usize) -> TranscriptOp {
    TranscriptOp::Squeeze(2 * count)
}

/// Owner schedule. `close_for_bridge=false` is used only to screen and reject
/// the one-channel alternative.
#[cfg(test)]
fn owner_ops(close_for_bridge: bool) -> Vec<TranscriptOp> {
    owner_ops_for_version(close_for_bridge, OwnerAuthorizationVersion::V4)
}

fn owner_ops_for_version(
    close_for_bridge: bool,
    version: OwnerAuthorizationVersion,
) -> Vec<TranscriptOp> {
    let mut ops = Vec::new();
    let mut prefix: Vec<Option<u128>> =
        noid_gkr::zk_authorization::zk_auth_owner_prefix_constants(version)
            .into_iter()
            .map(Some)
            .collect();
    prefix.extend(data_lanes(
        ZK_AUTH_OWNER_PUBLIC_STATEMENT_FIELDS + ZK_AUTH_SOURCE_CAP_LANES,
    ));
    ops.push(TranscriptOp::Absorb(prefix));
    ops.push(squeeze_wide(ZK_AUTH_MLECHECK_VARS));

    // mu = g_MLE(rho), then the characteristic-two-safe batching challenge.
    ops.push(TranscriptOp::Absorb(data_lanes(2)));
    ops.push(squeeze_wide(1));

    // Eleven high-to-low ZK MLE-check rounds.
    for _ in 0..ZK_AUTH_MLECHECK_VARS {
        ops.push(TranscriptOp::Absorb(data_lanes(
            2 * ZK_AUTH_MLECHECK_ROUND_FIELDS,
        )));
        ops.push(squeeze_wide(1));
    }

    // g(r), padded state_inc(r), and four padded lane operands must all be
    // absorbed before eta selects the transparent post-claim relation t.
    ops.push(TranscriptOp::Absorb(data_lanes(
        2 * ZK_AUTH_TERMINAL_FIELDS,
    )));
    ops.push(squeeze_wide(1));

    if close_for_bridge {
        // A full fixed block forces one final permutation. Its C0..C3 output is
        // the exact Owner->Main bridge.
        ops.push(TranscriptOp::Absorb(vec![
            Some(ZK_AUTH_OWNER_TO_MAIN_CLOSE_TAG),
            Some(0),
        ]));
    }
    ops
}

/// Main schedule. With `include_bridge=false`, only sigma is absorbed in the
/// prefix; this is the rejected single-channel screen.
fn main_ops(include_bridge: bool) -> Vec<TranscriptOp> {
    let mut ops = Vec::new();
    let mut prefix = vec![Some(ZK_AUTH_MAIN_FROM_OWNER_TAG)];
    prefix.extend(data_lanes(if include_bridge {
        ZK_AUTH_BRIDGE_LANES + 2 // bridge + wide sigma
    } else {
        2 // wide sigma only; prior channel state would be implicit
    }));
    ops.push(TranscriptOp::Absorb(prefix));
    ops.push(squeeze_wide(1)); // gamma

    for _ in 0..ZK_AUTH_MLECHECK_VARS {
        ops.push(TranscriptOp::Absorb(data_lanes(
            2 * ZK_AUTH_PHASE_A_ROUND_FIELDS,
        )));
        ops.push(squeeze_wide(1));
    }

    let mut phase_b = vec![Some(ZK_AUTH_PHASE_B_TAG)];
    phase_b.extend(data_lanes(2 * (1 + ZK_AUTH_UPPER_FIELDS))); // wide v + upper[256]
    ops.push(TranscriptOp::Absorb(phase_b));
    // Commit/challenge order is part of FRI soundness.  Only the three
    // source-layer folds may be sampled from the source/upper commitment.
    // Sampling the mid challenges before committing the mid codeword would
    // let a prover adapt one cell per leaf to a chosen tail.
    ops.push(squeeze_wide(3)); // beta0..beta2

    let mut mid = vec![Some(ZK_AUTH_MID_CAP_TAG)];
    mid.extend(data_lanes(ZK_AUTH_MID_CAP_LANES));
    ops.push(TranscriptOp::Absorb(mid));
    ops.push(squeeze_wide(4)); // beta3..beta6

    let mut tail = vec![Some(ZK_AUTH_TAIL_TAG)];
    tail.extend(data_lanes(2 * ZK_AUTH_TAIL_FIELDS));
    ops.push(TranscriptOp::Absorb(tail));
    // The tail is the committed next layer for the final local fold.  beta7
    // must therefore be sampled only after all sixteen tail cells are bound.
    ops.push(squeeze_wide(1)); // beta7

    ops.push(TranscriptOp::Absorb(vec![
        Some(ZK_AUTH_GRIND_TAG),
        None, // nonce
    ]));
    ops.push(TranscriptOp::Squeeze(1)); // checked grind output
    ops.push(TranscriptOp::Squeeze(ZK_AUTH_QUERY_SEEDS));
    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::{Block128, TowerField};
    use noid_gkr::evaluate_permutation;
    use noid_gkr::zk_auth_capsule::{ZkAuthCapsuleStateTable, ZK_AUTH_CAPSULE_STATE_LEN};
    use noid_gkr::zk_authorization::{
        prove_zk_authorization_from_state_table, verify_zk_authorization,
        zk_auth_capsule_owner_dynamic_data, zk_authorization_main_dynamic_data,
        ZkAuthCapsuleOwnerStatement,
    };
    use noid_ivc_core::deep_chain::schedule::{
        build_duplex_columns, flat_of_tower_u128, LaneSource,
    };
    use noid_ivc_core::field::{F128, F256};
    use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRFIX, TAG_KSCH256};

    fn counts(ops: &[TranscriptOp]) -> (usize, usize, usize) {
        ops.iter().fold((0, 0, 0), |mut counts, op| {
            match op {
                TranscriptOp::Absorb(lanes) => {
                    for lane in lanes {
                        if lane.is_some() {
                            counts.1 += 1;
                        } else {
                            counts.0 += 1;
                        }
                    }
                }
                TranscriptOp::Squeeze(n) => counts.2 += n,
            }
            counts
        })
    }

    fn data_slot(layout: &DuplexLayout, data_index: usize) -> usize {
        layout
            .slots
            .iter()
            .enumerate()
            .find_map(|(slot, descriptor)| {
                descriptor
                    .lanes
                    .iter()
                    .any(|source| *source == Some(LaneSource::Data(data_index)))
                    .then_some(slot)
            })
            .unwrap_or_else(|| panic!("missing Main data index {data_index}"))
    }

    fn owner_test_elem(index: usize, domain: u128, salt: u128) -> Block128 {
        Block128::from(
            domain
                .wrapping_mul(index as u128 + 1)
                .rotate_left(((17 * index + 5) % 127) as u32)
                ^ salt.rotate_left(((11 * index + 3) % 127) as u32)
                ^ (index as u128 + 7).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        )
    }

    fn ksch256_iv_flat() -> [F128; 2] {
        let iv = capacity_iv(TAG_KSCH256);
        [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
    }

    #[test]
    fn selected_split_schedules_compile_exactly_inside_m7_and_m8() {
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        let owner = schedules.owner_layout();
        let main = schedules.main_layout();

        assert_eq!(
            counts(&schedules.owner_ops),
            (
                ZK_AUTH_OWNER_DYNAMIC_LANES,
                ZK_AUTH_OWNER_CONSTANT_LANES,
                ZK_AUTH_OWNER_RAW_CHALLENGE_LANES,
            )
        );
        assert_eq!(
            counts(&schedules.main_ops),
            (
                ZK_AUTH_MAIN_DYNAMIC_LANES,
                ZK_AUTH_MAIN_CONSTANT_LANES,
                ZK_AUTH_MAIN_RAW_CHALLENGE_LANES,
            )
        );
        assert_eq!(owner.n_data, ZK_AUTH_OWNER_DYNAMIC_LANES);
        assert_eq!(main.n_data, ZK_AUTH_MAIN_DYNAMIC_LANES);
        assert_eq!(owner.slots.len(), ZK_AUTH_OWNER_COMPILED_SLOTS);
        assert_eq!(main.slots.len(), ZK_AUTH_MAIN_COMPILED_SLOTS);
        assert_eq!(owner.slots.len().next_power_of_two(), 256);
        assert_eq!(main.slots.len().next_power_of_two(), 512);
    }

    #[test]
    fn padded_terminal_operands_are_bound_to_construction_version_four() {
        assert_eq!(ZK_AUTH_OWNER_CONSTRUCTION_VERSION, 4);
        assert_eq!(ZK_AUTH_OWNER_PREFIX_CONSTANTS[1], 4);
        assert_eq!(ZK_AUTH_REGION_SIDECAR_CONSTRUCTION_VERSION, 4);
        let purposes = [
            selected_zk_auth_wallet_a_sidecar_purpose(),
            selected_zk_auth_wallet_b_sidecar_purpose(),
            selected_zk_auth_owner_sidecar_purpose(),
            selected_zk_auth_main_sidecar_purpose(),
        ];
        for (index, left) in purposes.iter().enumerate() {
            assert!(purposes[index + 1..].iter().all(|right| left != right));
        }
    }

    #[test]
    fn bridge_is_owner_final_c_and_main_first_four_data_lanes() {
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        let owner = schedules.owner_layout();
        let main = schedules.main_layout();

        assert_eq!(ZK_AUTH_OWNER_BRIDGE_SLOT, owner.slots.len() - 1);
        assert_eq!(
            owner.slots[ZK_AUTH_OWNER_BRIDGE_SLOT].lanes,
            [
                Some(LaneSource::Const(ZK_AUTH_OWNER_TO_MAIN_CLOSE_TAG)),
                Some(LaneSource::Const(0)),
            ]
        );
        assert_eq!(
            main.slots[0].lanes,
            [
                Some(LaneSource::Const(ZK_AUTH_MAIN_FROM_OWNER_TAG)),
                Some(LaneSource::Data(0)),
            ]
        );
        assert_eq!(
            main.slots[1].lanes,
            [Some(LaneSource::Data(1)), Some(LaneSource::Data(2))]
        );
        assert_eq!(
            main.slots[2].lanes,
            [Some(LaneSource::Data(3)), Some(LaneSource::Data(4))]
        );
        assert_eq!(main.challenges[0], (3, 0));
        assert_eq!(ZK_AUTH_MAIN_SIGMA_DATA_INDEX, 4);
    }

    #[test]
    fn canonical_full_transcripts_match_compiled_layouts_and_bridge() {
        let salt = 0xA11C_E002;
        let iv = capacity_iv(TAG_ADDRFIX);
        let secret = [
            owner_test_elem(1, 0x5EC2_E7, salt),
            owner_test_elem(2, 0x5EC2_E7, salt),
        ];
        let permutation = evaluate_permutation([secret[0], secret[1], iv[0], iv[1]]);
        let address = [permutation.final_state()[0], permutation.final_state()[1]];
        let state = ZkAuthCapsuleStateTable::from_permutation_witness(&permutation)
            .expect("valid Poseidon state table");
        assert_eq!(state.len(), ZK_AUTH_CAPSULE_STATE_LEN);
        let statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [
                owner_test_elem(3, 0x7A_B0D1, salt),
                owner_test_elem(4, 0x7A_B0D1, salt),
            ],
            address,
        };
        let proof = prove_zk_authorization_from_state_table(&state, statement)
            .expect("complete authorization proof");
        let verified =
            verify_zk_authorization(statement, &proof).expect("complete authorization replay");
        let source_cap = proof
            .source_commitment
            .transcript_lanes()
            .expect("source cap shape");

        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        let owner_layout = schedules.owner_layout();
        let owner_data = zk_auth_capsule_owner_dynamic_data(statement, &source_cap, &proof.owner);
        let owner_flat_data: Vec<F128> = owner_data
            .iter()
            .map(|value| flat_of_tower_u128(value.0))
            .collect();
        let owner_columns = build_duplex_columns(
            &owner_layout,
            ksch256_iv_flat(),
            &owner_flat_data,
            owner_layout
                .slots
                .len()
                .next_power_of_two()
                .trailing_zeros() as usize,
        );

        assert_eq!(owner_data.len(), ZK_AUTH_OWNER_DYNAMIC_LANES);
        assert_eq!(owner_layout.slots.len(), ZK_AUTH_OWNER_COMPILED_SLOTS);
        let owner_challenges = verified.owner.transcript_challenges();
        assert_eq!(owner_columns.challenges.len(), 2 * owner_challenges.len());
        for (index, (&tower, raw)) in owner_challenges
            .iter()
            .zip(owner_columns.challenges.chunks_exact(2))
            .enumerate()
        {
            assert_eq!(
                F256::from_tower(tower),
                F256::from_raw_challenge_lanes(raw[0], raw[1]),
                "Owner native/compiled challenge {index}"
            );
        }
        for lane in 0..ZK_AUTH_BRIDGE_LANES {
            assert_eq!(
                flat_of_tower_u128(verified.owner.bridge[lane].0),
                owner_columns.c[lane][ZK_AUTH_OWNER_BRIDGE_SLOT],
                "Owner close bridge lane C{lane}"
            );
        }

        let main_layout = schedules.main_layout();
        let main_data =
            zk_authorization_main_dynamic_data(&verified.owner, &proof).expect("Main data stream");
        assert_eq!(&main_data[..ZK_AUTH_BRIDGE_LANES], &verified.owner.bridge);
        let main_flat_data: Vec<F128> = main_data
            .iter()
            .map(|value| flat_of_tower_u128(value.0))
            .collect();
        let main_columns = build_duplex_columns(
            &main_layout,
            ksch256_iv_flat(),
            &main_flat_data,
            main_layout.slots.len().next_power_of_two().trailing_zeros() as usize,
        );
        let main_algebraic = verified.main_algebraic_challenges();
        assert_eq!(main_data.len(), ZK_AUTH_MAIN_DYNAMIC_LANES);
        assert_eq!(main_layout.slots.len(), ZK_AUTH_MAIN_COMPILED_SLOTS);
        assert_eq!(
            main_columns.challenges.len(),
            ZK_AUTH_MAIN_RAW_CHALLENGE_LANES
        );
        for (index, (&tower, raw)) in main_algebraic
            .iter()
            .zip(main_columns.challenges[..2 * ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES].chunks_exact(2))
            .enumerate()
        {
            assert_eq!(
                F256::from_tower(tower),
                F256::from_raw_challenge_lanes(raw[0], raw[1]),
                "Main native/compiled algebraic challenge {index}"
            );
        }
        let base_challenges = std::iter::once(verified.grind)
            .chain(verified.query_seeds)
            .collect::<Vec<_>>();
        for (index, (&tower, &flat)) in base_challenges
            .iter()
            .zip(&main_columns.challenges[2 * ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES..])
            .enumerate()
        {
            assert_eq!(
                flat_of_tower_u128(tower.0),
                flat,
                "Main base challenge {index}"
            );
        }
    }

    #[test]
    fn main_data_offsets_and_proof_carried_count_are_exact() {
        assert_eq!(ZK_AUTH_MAIN_PHASE_A_DATA_START, 6);
        assert_eq!(ZK_AUTH_MAIN_PHASE_B_VALUE_DATA_INDEX, 6 + 11 * 4);
        assert_eq!(ZK_AUTH_MAIN_UPPER_DATA_START, 52);
        assert_eq!(ZK_AUTH_MAIN_MID_CAP_DATA_START, 52 + 512);
        assert_eq!(ZK_AUTH_MAIN_TAIL_DATA_START, 564 + 16);
        assert_eq!(ZK_AUTH_MAIN_NONCE_DATA_INDEX, 580 + 32);
        assert_eq!(
            ZK_AUTH_MAIN_NONCE_DATA_INDEX + 1,
            ZK_AUTH_MAIN_DYNAMIC_LANES
        );
        assert_eq!(
            ZK_AUTH_MAIN_DYNAMIC_LANES - ZK_AUTH_BRIDGE_LANES,
            609,
            "bridge lanes are derived and not serialized"
        );
    }

    #[test]
    fn every_phase_b_layer_is_committed_before_its_fold_challenges() {
        let main = ZkAuthCapsuleDuplexSchedules::selected().main_layout();
        let beta_start = 1 + ZK_AUTH_MLECHECK_VARS;
        let beta_raw_start = 2 * beta_start;
        let grind_index = 2 * ZK_AUTH_MAIN_ALGEBRAIC_SQUEEZES;

        let beta0_slot = main.challenges[beta_raw_start].0;
        let beta2_slot = main.challenges[beta_raw_start + 2 * 2].0;
        let beta3_slot = main.challenges[beta_raw_start + 2 * 3].0;
        let beta6_slot = main.challenges[beta_raw_start + 2 * 6].0;
        let beta7_slot = main.challenges[beta_raw_start + 2 * 7].0;

        assert!(
            data_slot(
                &main,
                ZK_AUTH_MAIN_UPPER_DATA_START + ZK_AUTH_UPPER_FIELDS - 1
            ) <= beta0_slot
        );
        assert!(beta2_slot < data_slot(&main, ZK_AUTH_MAIN_MID_CAP_DATA_START));
        assert!(
            data_slot(
                &main,
                ZK_AUTH_MAIN_MID_CAP_DATA_START + ZK_AUTH_MID_CAP_LANES - 1
            ) <= beta3_slot
        );
        assert!(beta6_slot < data_slot(&main, ZK_AUTH_MAIN_TAIL_DATA_START));
        assert!(
            data_slot(
                &main,
                ZK_AUTH_MAIN_TAIL_DATA_START + ZK_AUTH_TAIL_FIELDS - 1
            ) <= beta7_slot
        );
        assert!(beta7_slot < data_slot(&main, ZK_AUTH_MAIN_NONCE_DATA_INDEX));
        assert!(data_slot(&main, ZK_AUTH_MAIN_NONCE_DATA_INDEX) <= main.challenges[grind_index].0);
    }

    #[test]
    fn one_channel_alternative_crosses_to_m9_and_is_rejected() {
        let mut combined = owner_ops(false);
        combined.extend(main_ops(false));
        let layout = compile_duplex(&combined);
        assert_eq!(layout.n_data, 863);
        assert_eq!(layout.slots.len(), ZK_AUTH_REJECTED_SINGLE_CHANNEL_SLOTS);
        assert_eq!(layout.slots.len().next_power_of_two(), 512);
    }

    #[test]
    fn affine_blend_rejects_both_erasing_endpoints() {
        assert!(!affine_blend_gamma_is_admissible(noid_core::Block256::ZERO));
        assert!(!affine_blend_gamma_is_admissible(noid_core::Block256::ONE));
        assert!(affine_blend_gamma_is_admissible(noid_core::Block256::new(
            Block128::from(2u128),
            Block128::ONE,
        )));
    }
}
