// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Header chain validation.
//!
//! Validates a candidate block header against its parent and the expected
//! ASERT difficulty target. Pure, I/O-free — the caller provides all data.
//!
//! Reference: Reth `crates/consensus/consensus/src/lib.rs` for structure.

use crate::block_header::BlockHeader;
use crate::consensus::{
    difficulty::next_target,
    expected_child_log_slots,
    params::{CONSENSUS_FINALITY_DEPTH, EPOCH_LENGTH},
    pow::{block_id, validate_pow},
    timestamps::{validate_future_drift, validate_median_time_past},
    ConsensusError,
};

/// Validate a candidate block header against its parent and recent timestamps.
///
/// Checks (in order):
/// 1. `prev_block_hash` == semantic Poseidon2b block id of the parent
/// 2. `height` == parent.height + 1
/// 3. `difficulty_target` == ASERT-computed target
/// 4. Timestamp rules (MTP + future drift)
/// 5. Poseidon2b PoW satisfies difficulty_target
/// 6. `log_slots` equals the exact hard-finalized expansion result
///
/// Detached validation witness presence is checked by the block acceptance
/// path, not by semantic header validation.
///
/// `prev_timestamps`: timestamps of the last ≤11 ancestors, oldest-first.
/// `finalized_active_counts`: the complete hard-finalized expansion window,
/// oldest-first, or empty while the chain is too short to provide it.
/// `local_time`: current wall-clock seconds (for future drift check).
/// `anchor_*`: epoch anchor values for ASERT.
pub fn validate_header(
    header: &BlockHeader,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    finalized_active_counts: &[u64],
    local_time: u64,
    anchor_height: u64,
    anchor_timestamp: u64,
    anchor_target: &[u8; 32],
) -> Result<(), ConsensusError> {
    validate_header_inner(
        header,
        parent,
        block_id(parent),
        prev_timestamps,
        finalized_active_counts,
        Some(local_time),
        anchor_height,
        anchor_timestamp,
        anchor_target,
        true,
        None,
    )
}

/// Validate every header rule of a node-owned template except proof of work.
///
/// The relation and terminal are nonce-free, so a miner finishes and proves
/// the complete HistoryStep before PoW; the winning nonce is then checked by
/// exactly one native `validate_pow` at seal time. This variant exists only
/// for that pre-PoW template path — every acceptance path keeps the full
/// PoW-checking validators.
pub fn validate_header_template(
    header: &BlockHeader,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    finalized_active_counts: &[u64],
    local_time: u64,
    anchor_height: u64,
    anchor_timestamp: u64,
    anchor_target: &[u8; 32],
) -> Result<(), ConsensusError> {
    validate_header_inner(
        header,
        parent,
        block_id(parent),
        prev_timestamps,
        finalized_active_counts,
        Some(local_time),
        anchor_height,
        anchor_timestamp,
        anchor_target,
        false,
        None,
    )
}

/// Validate deterministic header consensus rules that can be proven for
/// historical recursive checkpoints.
///
/// This excludes only the local wall-clock future-drift admission policy.
pub fn validate_header_timeless(
    header: &BlockHeader,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    finalized_active_counts: &[u64],
    anchor_height: u64,
    anchor_timestamp: u64,
    anchor_target: &[u8; 32],
) -> Result<(), ConsensusError> {
    validate_header_inner(
        header,
        parent,
        block_id(parent),
        prev_timestamps,
        finalized_active_counts,
        None,
        anchor_height,
        anchor_timestamp,
        anchor_target,
        true,
        None,
    )
}

/// Validate deterministic historical header rules using an already computed
/// semantic block id for the exact `parent` value.
///
/// This is consensus-equivalent to [`validate_header_timeless`]. It exists for
/// bounded sequential validation, where the current header id becomes the
/// next header's parent id and hashing the same parent again is unnecessary.
/// The caller must derive `parent_id` from the supplied `parent` or obtain it
/// from an authenticated canonical boundary.
#[allow(clippy::too_many_arguments)]
pub fn validate_header_timeless_prehashed_parent(
    header: &BlockHeader,
    parent: &BlockHeader,
    parent_id: [u8; 32],
    prev_timestamps: &[u64],
    finalized_active_counts: &[u64],
    anchor_height: u64,
    anchor_timestamp: u64,
    anchor_target: &[u8; 32],
) -> Result<(), ConsensusError> {
    validate_header_inner(
        header,
        parent,
        parent_id,
        prev_timestamps,
        finalized_active_counts,
        None,
        anchor_height,
        anchor_timestamp,
        anchor_target,
        true,
        None,
    )
}

/// Entry point with explicit height-selected timing for isolated profiles.
#[allow(clippy::too_many_arguments)]
pub fn validate_header_with_schedule(
    header: &BlockHeader,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    finalized_active_counts: &[u64],
    local_time: Option<u64>,
    anchor_height: u64,
    anchor_timestamp: u64,
    anchor_target: &[u8; 32],
    check_pow: bool,
    schedule: super::forks::ForkSchedule,
) -> Result<(), ConsensusError> {
    validate_header_inner(
        header,
        parent,
        block_id(parent),
        prev_timestamps,
        finalized_active_counts,
        local_time,
        anchor_height,
        anchor_timestamp,
        anchor_target,
        check_pow,
        Some(schedule),
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_header_inner(
    header: &BlockHeader,
    parent: &BlockHeader,
    expected_parent_hash: [u8; 32],
    prev_timestamps: &[u64],
    finalized_active_counts: &[u64],
    local_time: Option<u64>,
    anchor_height: u64,
    anchor_timestamp: u64,
    anchor_target: &[u8; 32],
    check_pow: bool,
    schedule: Option<super::forks::ForkSchedule>,
) -> Result<(), ConsensusError> {
    // 1. Parent hash linkage.
    if header.prev_block_hash != expected_parent_hash {
        return Err(ConsensusError::BadParentHash);
    }

    // 2. Height.
    if header.height != parent.height + 1 {
        return Err(ConsensusError::BadHeight);
    }

    // 3. Difficulty target matches ASERT expectation.
    let expected_target = match schedule {
        Some(schedule) => super::difficulty::next_target_with_schedule(
            anchor_height,
            anchor_timestamp,
            anchor_target,
            header.height,
            parent.timestamp,
            header.timestamp,
            schedule,
        ),
        None => next_target(
            anchor_height,
            anchor_timestamp,
            anchor_target,
            header.height,
            parent.timestamp,
            header.timestamp,
        ),
    };
    if header.difficulty_target != expected_target {
        return Err(ConsensusError::BadDifficultyTarget);
    }

    // 4. Timestamp rules.
    validate_median_time_past(header.timestamp, prev_timestamps)
        .map_err(|_| ConsensusError::BadTimestamp)?;
    if let Some(local_time) = local_time {
        // The normal future-drift allowance must not let the first mainnet
        // child enter local consensus before the fixed genesis time. This is
        // an admission-time rule only; timeless historical verification is
        // unchanged once the network has launched.
        if parent.height == 0 && local_time < parent.timestamp {
            return Err(ConsensusError::BadTimestamp);
        }
        validate_future_drift(header.timestamp, local_time)
            .map_err(|_| ConsensusError::BadTimestamp)?;
    }

    // 5. Poseidon2b PoW over semantic header fields. Skipped only on the
    //    miner's nonce-free template path; the winning nonce is validated at
    //    seal time.
    if check_pow {
        validate_pow(header)?;
    }

    // 6. Exact slot-space expansion.
    let expected_log_slots =
        expected_child_log_slots(parent.height, parent.log_slots, finalized_active_counts);
    if header.log_slots != expected_log_slots {
        return Err(ConsensusError::BadLogSlotsExpansion);
    }

    Ok(())
}

/// Determine the ASERT anchor for a given chain tip.
///
/// The anchor is the block at the most recent epoch boundary:
/// `anchor_height = largest H ≤ current_height where H % EPOCH_LENGTH == 0`.
/// The v2 interval starts from its actual predecessor until the next regular
/// epoch boundary, avoiding a difficulty discontinuity from the old interval.
pub fn asert_anchor_height(current_height: u64) -> u64 {
    asert_anchor_height_with_schedule(current_height, super::forks::ACTIVE_SCHEDULE)
}

pub fn asert_anchor_height_with_schedule(
    current_height: u64,
    schedule: super::forks::ForkSchedule,
) -> u64 {
    let regular = (current_height / EPOCH_LENGTH) * EPOCH_LENGTH;
    match schedule.v2() {
        Some(at) if current_height >= at.height() - 1 => regular.max(at.height() - 1),
        _ => regular,
    }
}

/// Returns `true` if a block at `height` is considered final (cannot be reorged).
pub fn is_final(block_height: u64, tip_height: u64) -> bool {
    tip_height >= block_height + CONSENSUS_FINALITY_DEPTH
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::params::BLOCK_TIME;
    use noid_poseidon2b::primitives::Address;
    // Any hash satisfies this target — nonce=0 always works, no search needed.
    const TEST_TARGET: [u8; 32] = [0xFF; 32];

    fn make_header(height: u64, timestamp: u64, parent: Option<&BlockHeader>) -> BlockHeader {
        let prev_hash = parent.map(block_id).unwrap_or([0u8; 32]);
        BlockHeader {
            prev_block_hash: prev_hash,
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            timestamp,
            height,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    fn mine(header: &mut BlockHeader) {
        // TEST_TARGET: nonce=0 trivially satisfies any target of [0xFF;32].
        // search_pow(header, 0, 1) would always return Some(0).
        header.nonce = 0;
    }

    #[test]
    fn valid_header_accepts() {
        let genesis = make_header(0, 1_000_000, None);
        let mut h1 = make_header(1, 1_000_000 + BLOCK_TIME, Some(&genesis));
        mine(&mut h1);
        let prev_ts = vec![genesis.timestamp];
        let result = validate_header(
            &h1,
            &genesis,
            &prev_ts,
            &[],
            h1.timestamp + 1,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        assert!(result.is_ok(), "valid header should accept: {:?}", result);
    }

    #[test]
    fn timeless_header_excludes_local_future_drift_policy() {
        let genesis = make_header(0, 1_000_000, None);
        let mut h1 = make_header(1, 1_000_000 + BLOCK_TIME, Some(&genesis));
        mine(&mut h1);
        let prev_ts = vec![genesis.timestamp];

        assert_eq!(
            validate_header(
                &h1,
                &genesis,
                &prev_ts,
                &[],
                1,
                0,
                genesis.timestamp,
                &genesis.difficulty_target,
            ),
            Err(ConsensusError::BadTimestamp)
        );
        assert!(validate_header_timeless(
            &h1,
            &genesis,
            &prev_ts,
            &[],
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        )
        .is_ok());
    }

    #[test]
    fn first_child_unlocks_exactly_at_genesis_time() {
        let genesis = make_header(0, 1_000_000, None);
        let mut h1 = make_header(1, genesis.timestamp + BLOCK_TIME, Some(&genesis));
        mine(&mut h1);
        let previous = [genesis.timestamp];

        assert_eq!(
            validate_header(
                &h1,
                &genesis,
                &previous,
                &[],
                genesis.timestamp - 1,
                0,
                genesis.timestamp,
                &genesis.difficulty_target,
            ),
            Err(ConsensusError::BadTimestamp)
        );
        assert!(validate_header(
            &h1,
            &genesis,
            &previous,
            &[],
            genesis.timestamp,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        )
        .is_ok());
        assert!(validate_header_timeless(
            &h1,
            &genesis,
            &previous,
            &[],
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        )
        .is_ok());
    }

    #[test]
    fn wrong_parent_hash_rejects() {
        let genesis = make_header(0, 1_000_000, None);
        let mut h1 = make_header(1, 1_000_000 + BLOCK_TIME, Some(&genesis));
        mine(&mut h1);
        h1.prev_block_hash = [0xAB; 32]; // tamper
        let result = validate_header(
            &h1,
            &genesis,
            &[genesis.timestamp],
            &[],
            h1.timestamp + 1,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        assert_eq!(result, Err(ConsensusError::BadParentHash));
    }

    #[test]
    fn prehashed_parent_validation_matches_standard_validation() {
        let genesis = make_header(0, 1_000_000, None);
        let mut h1 = make_header(1, 1_000_000 + BLOCK_TIME, Some(&genesis));
        mine(&mut h1);
        let parent_id = block_id(&genesis);
        let standard = validate_header_timeless(
            &h1,
            &genesis,
            &[genesis.timestamp],
            &[],
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        let prehashed = validate_header_timeless_prehashed_parent(
            &h1,
            &genesis,
            parent_id,
            &[genesis.timestamp],
            &[],
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        assert_eq!(prehashed, standard);

        assert_eq!(
            validate_header_timeless_prehashed_parent(
                &h1,
                &genesis,
                [0xAB; 32],
                &[genesis.timestamp],
                &[],
                0,
                genesis.timestamp,
                &genesis.difficulty_target,
            ),
            Err(ConsensusError::BadParentHash)
        );
    }

    #[test]
    fn v2_validates_siblings_with_one_parent_derived_target() {
        use crate::consensus::forks::{ForkSchedule, V2Activation};

        let schedule = ForkSchedule::new(Some(5), V2Activation::new(10, 30)).unwrap();
        let parent = make_header(9, 1_000, None);
        let previous = [900, 910, 920, 930, 940, 950, 960, 970, 980, 990, 1_000];
        let expected = super::super::difficulty::next_target_with_schedule(
            9,
            parent.timestamp,
            &parent.difficulty_target,
            10,
            parent.timestamp,
            980,
            schedule,
        );
        for timestamp in [980, 1_010] {
            let mut child = make_header(10, timestamp, Some(&parent));
            child.difficulty_target = expected;
            assert!(validate_header_with_schedule(
                &child,
                &parent,
                &previous,
                &[],
                Some(1_010),
                9,
                parent.timestamp,
                &parent.difficulty_target,
                false,
                schedule,
            )
            .is_ok());
        }
    }

    #[test]
    fn wrong_height_rejects() {
        let genesis = make_header(0, 1_000_000, None);
        let mut h1 = make_header(2, 1_000_000 + BLOCK_TIME, Some(&genesis)); // height=2 wrong
        h1.prev_block_hash = block_id(&genesis);
        mine(&mut h1);
        let result = validate_header(
            &h1,
            &genesis,
            &[genesis.timestamp],
            &[],
            h1.timestamp + 1,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        assert_eq!(result, Err(ConsensusError::BadHeight));
    }

    #[test]
    fn decreasing_log_slots_rejects() {
        let genesis = make_header(0, 1_000_000, None);
        let mut h1 = make_header(1, 1_000_000 + BLOCK_TIME, Some(&genesis));
        h1.log_slots = 23; // less than genesis 24
        mine(&mut h1);
        let result = validate_header(
            &h1,
            &genesis,
            &[genesis.timestamp],
            &[],
            h1.timestamp + 1,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        assert_eq!(result, Err(ConsensusError::BadLogSlotsExpansion));
    }

    #[test]
    fn asert_anchor_height_examples() {
        assert_eq!(asert_anchor_height(0), 0);
        assert_eq!(asert_anchor_height(5), 0);
        assert_eq!(asert_anchor_height(6), 6);
        assert_eq!(
            asert_anchor_height(11),
            if super::super::params::ISOLATED_V2_FORK_TESTNET {
                9
            } else {
                6
            }
        );
        assert_eq!(asert_anchor_height(12), 12);
        assert_eq!(asert_anchor_height(100), 96);
    }

    #[test]
    fn v2_anchors_to_its_predecessor_until_the_next_epoch() {
        use crate::consensus::forks::{ForkSchedule, V2Activation};
        for h in [10, 12, 13, 219_177] {
            let schedule = ForkSchedule::new(Some(5), V2Activation::new(h, 30)).unwrap();
            let anchor = |tip| asert_anchor_height_with_schedule(tip, schedule);
            assert_eq!(anchor(h - 2), (h - 2) / 6 * 6);
            assert_eq!(anchor(h - 1), h - 1);
            for tip in h..h + 6 {
                let regular = tip / 6 * 6;
                assert_eq!(anchor(tip), regular.max(h - 1));
            }
            assert_eq!(anchor(h - 2), (h - 2) / 6 * 6);
        }
    }

    #[test]
    fn finality_check() {
        assert!(is_final(0, 18));
        assert!(!is_final(0, 17));
        assert!(is_final(100, 118));
    }
}
