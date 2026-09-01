// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! All consensus constants.

/// Target inter-block interval in seconds.
///
/// ASERT adjusts PoW difficulty so all hardware converges to this target.
/// Bounded below by `prove_block_time` on the miner's hardware; PoW is
/// ordering-only, not security-critical.
pub const BLOCK_TIME: u64 = 20;

/// Number of blocks per ASERT epoch.
pub const EPOCH_LENGTH: u64 = 6;

/// ASERT halflife in seconds = EPOCH_LENGTH × BLOCK_TIME.
pub const HALFLIFE: u64 = EPOCH_LENGTH * BLOCK_TIME; // 120s at BLOCK_TIME=20

/// First block height governed by the complete v2 consensus rules.
///
/// `None` keeps every v2 rule disabled. The release activation height is set
/// once for the complete upgrade; individual v2 changes must not introduce
/// independent activation clocks.
pub const V2_ACTIVATION_HEIGHT: Option<u64> = None;

/// Whether one candidate block height is governed by the v2 consensus rules.
#[inline]
pub const fn v2_active(height: u64) -> bool {
    v2_active_with(height, V2_ACTIVATION_HEIGHT)
}

#[inline]
pub(crate) const fn v2_active_with(height: u64, activation_height: Option<u64>) -> bool {
    matches!(activation_height, Some(activation_height) if height >= activation_height)
}

/// Maximum seconds a block timestamp may exceed local wall clock.
pub const MAX_FUTURE_DRIFT: u64 = 120;

/// Number of previous blocks used for median-time-past.
pub const MEDIAN_TIME_BLOCKS: usize = 11;

// ---------------------------------------------------------------------------
// Block limits
// ---------------------------------------------------------------------------

/// Maximum fixed bodies decoded in one block, including system records.
///
/// This is a hard decoder/DoS cap. The consensus throughput budget is the
/// semantic block budget below: one mandatory coinbase plus 255 effective
/// page positions. A scheduled development payout consumes one of those
/// positions, leaving at most 254 physical user pages in that block.
pub const BLOCK_MAX_TXS: usize = 256;

/// Fixed input capacity of every transaction body.
pub const MAX_INPUTS: usize = 8;

/// Fixed output capacity of every transaction body.
pub const MAX_OUTPUTS: usize = 2;

/// Maximum physical non-coinbase PagedSpend pages accepted by consensus.
pub const BLOCK_MAX_USER_PAGES: usize = BLOCK_MAX_TXS - 1;

/// Maximum live user inputs accepted in one block.
pub const BLOCK_MAX_LIVE_INPUTS: usize = 1_020;

/// Maximum live user outputs accepted in one block.
pub const BLOCK_MAX_USER_OUTPUTS: usize = 510;

/// Maximum bitmap-live user action capacity accepted by consensus.
pub const BLOCK_MAX_USER_ACTIONS: usize = BLOCK_MAX_LIVE_INPUTS + BLOCK_MAX_USER_OUTPUTS;

/// Maximum accepted live action count across system and user bodies.
pub const BLOCK_MAX_ACTIONS: usize = BLOCK_MAX_USER_ACTIONS + 1;

/// Maximum number of distinct dense state segments a block may make resident.
/// This is an availability/DoS bound and is checked before segment preload.
pub const BLOCK_MAX_DISTINCT_SEGMENTS: usize = 256;

// ---------------------------------------------------------------------------
// HistoryStep classes
// ---------------------------------------------------------------------------

/// The two launch proof classes, indexed by effective page positions.
/// Physical user pages count one each and a live development payout counts
/// one; the primary coinbase is excluded. Counts through 25 use B25 and
/// 26 through 255 use B255. Logical groups/capsules never select the class.
pub const BLOCK_PAGE_CLASS_TIERS: [usize; 2] = [25, 255];

/// Smallest tier in `tiers` holding `count`, or None past the top tier.
#[inline]
fn class_tier_for(tiers: &[usize], count: usize) -> Option<usize> {
    tiers.iter().copied().find(|&tier| tier >= count)
}

/// Proof class tier for a block's effective page-position count.
#[inline]
pub fn block_page_class_tier(page_count: usize) -> Option<usize> {
    class_tier_for(&BLOCK_PAGE_CLASS_TIERS, page_count)
}

/// Live-input (spend) capacity of a proof class: what the class's per-input
/// proof structures are padded to. Capped by the semantic
/// block budget, which admits the tier mix only up to the global
/// live-input maximum.
#[inline]
pub fn block_class_spend_capacity(user_tier: usize) -> usize {
    (user_tier * MAX_INPUTS).min(BLOCK_MAX_LIVE_INPUTS)
}

/// Live user-output capacity of one proof class.
#[inline]
pub fn block_class_output_capacity(user_tier: usize) -> usize {
    (user_tier * MAX_OUTPUTS).min(BLOCK_MAX_USER_OUTPUTS)
}

/// Maximum exact-state touched surface across system and user bodies.
#[inline]
pub fn block_class_touched_capacity(user_tier: usize) -> usize {
    block_class_spend_capacity(user_tier) + block_class_output_capacity(user_tier) + 1
}

/// Spend capacity of the proof class holding a block with the given physical
/// page count, or None past the tier table.
#[inline]
pub fn block_class_spend_capacity_for_page_count(page_count: usize) -> Option<usize> {
    block_page_class_tier(page_count).map(block_class_spend_capacity)
}

/// Number of blocks for the transaction replay-protection epoch.
///
/// This is a separate protocol clock from ASERT's short difficulty epoch.
pub const TX_EPOCH_BLOCKS: u64 = 144;

const _: () = assert!(
    TX_EPOCH_BLOCKS == noid_tx::TX_EPOCH_BLOCKS,
    "noid_chain TX_EPOCH_BLOCKS must equal noid_tx"
);

// ---------------------------------------------------------------------------
// Finality
// ---------------------------------------------------------------------------

/// Consensus hard-finality depth.
///
/// Reorgs that would change the finalized prefix are rejected by fork choice.
/// This depth is fixed by the public-network consensus profile.
pub const CONSENSUS_FINALITY_DEPTH: u64 = 18;

/// Undo-log retention depth for local shallow reorg recovery and incremental
/// finalized-state snapshot generation.
///
/// This is intentionally separate from consensus finality. Retention may be
/// tuned for operational needs; it must not silently define finality.
/// Two finality windows let the snapshot publisher advance from its preceding
/// finalized generation without rescanning the complete live state.
pub const UNDO_RETENTION_DEPTH: u64 = CONSENSUS_FINALITY_DEPTH * 2;

/// Authenticated recent-suffix depth for normal catch-up and reorganization.
///
/// This remains equal to consensus finality. Local nodes may retain additional
/// complete bundles for serving through `RETAINED_BLOCK_SERVING_DEPTH`, but a
/// cold snapshot still authenticates and applies only this suffix. Undo
/// metadata has its own operational window; headers remain permanent.
pub const RECENT_BLOCK_RETENTION_DEPTH: u64 = CONSENSUS_FINALITY_DEPTH;

/// Local full-block serving window for bounded fork recovery.
///
/// This is deliberately not a finality or snapshot parameter.  Nodes still
/// authenticate and apply the same 18-block compact suffix, while retaining a
/// bounded set of older complete bundles for peers recovering a non-final
/// fork.  In the worst automatically recoverable case the receiver may need
/// `CONSENSUS_FINALITY_DEPTH` replacement blocks below its tip plus
/// `RECENT_BLOCK_RETENTION_DEPTH` blocks above it before the remote snapshot
/// boundary is itself ahead.  Six further blocks cover movement while the
/// oldest bundles are requested.  None of these additional bundles are part
/// of cold snapshot sync.
pub const RETAINED_BLOCK_SERVING_DEPTH: u64 =
    CONSENSUS_FINALITY_DEPTH + RECENT_BLOCK_RETENTION_DEPTH + 6;

/// Number of hard-finalized block headers used for the state-expansion trigger.
///
/// Expansion requires a strict majority of this complete window to be at or
/// above 75% occupancy. With the current even window, a 9/9 tie does not
/// expand; at least 10 of 18 finalized headers must meet the threshold.
pub const EXPANSION_WINDOW: u64 = CONSENSUS_FINALITY_DEPTH;

/// Oldest parent-relative header depth needed to validate state expansion.
///
/// For parent height `H`, the finalized window ends at
/// `H - CONSENSUS_FINALITY_DEPTH` and contains `EXPANSION_WINDOW` headers, so
/// its oldest member is `H - EXPANSION_HEADER_LOOKBACK`.
pub const EXPANSION_HEADER_LOOKBACK: u64 = CONSENSUS_FINALITY_DEPTH + EXPANSION_WINDOW - 1;

const _: () = assert!(EXPANSION_WINDOW > 0, "expansion window must be non-zero");

// ---------------------------------------------------------------------------
// Slot state
// ---------------------------------------------------------------------------

/// Initial `log_slots` at genesis: 2^24 = 16,777,216 slots.
pub const LOG_SLOTS_GENESIS: u32 = 24;

/// Maximum `log_slots`: 2^32 = 4,294,967,296 slots.
pub const LOG_SLOTS_MAX: u32 = 32;

/// Each segment holds 2^LOG_SEGMENT_SIZE slots.
pub const LOG_SEGMENT_SIZE: u32 = 16;

const _: () = assert!(
    LOG_SEGMENT_SIZE as usize == crate::fri_state::LOG_SEGMENT_SIZE,
    "consensus and state segment geometry must match"
);

/// Fraction of current capacity that triggers expansion (numerator/denominator).
/// When `active_slot_count * EXPAND_DENOM >= 2^log_slots * EXPAND_NUM`, expand.
pub const EXPAND_NUM: u64 = 3; // 75 %
pub const EXPAND_DENOM: u64 = 4;

// ---------------------------------------------------------------------------
// PoW
// ---------------------------------------------------------------------------

/// Genesis difficulty target = 2^238.
///
/// Calibrated to roughly the same wall-clock genesis solve time as the previous
/// difficulty floor, using production Poseidon2b PoW on the current 12-core laptop:
///   measured parallel Poseidon2b PoW ≈ 186 KH/s
///   avg_nonces = 2^(256-238) = 2^18 = 262,144
///   time = 262K / 186K ≈ 1.4s
///
/// LE 256-bit layout: byte 29 = 0x40 (bit 238 = bit 6 of byte 29).
/// Bytes 30-31 = 0x00 so the target value equals 2^238.
///
/// This is the minimum allowed difficulty floor. ASERT may only move harder.
/// Halved difficulty (2^237 -> 2^238 target, owner decision 2026-07-13) so
/// young-network block discovery is twice as fast; ASERT converges to
/// BLOCK_TIME either way.
pub const GENESIS_TARGET: [u8; 32] = {
    let mut t = [0u8; 32];
    t[29] = 0x40; // bit 6 of byte 29 -> 2^(8*29+6) = 2^238
    t
};

/// Minimum allowed target (maximum difficulty). Theoretical floor.
pub const MIN_TARGET: [u8; 32] = {
    let mut t = [0u8; 32];
    t[0] = 1;
    t
};

/// Maximum allowed target (minimum difficulty = trivially satisfied).
pub const MAX_TARGET: [u8; 32] = [0xFF; 32];

// ---------------------------------------------------------------------------
// DA retention
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

/// Precision: 1 NOID = 1_000_000 μNOID (microNOID).
pub const MICRONOID_PER_NOID: u64 = 1_000_000;

/// Starting block reward at zero occupancy: 50 NOID.
pub const BASE_REWARD_MICRONOID: u64 = 50 * MICRONOID_PER_NOID;

/// Reward floor: 1 NOID forever.
pub const FLOOR_REWARD_MICRONOID: u64 = MICRONOID_PER_NOID;

// ---------------------------------------------------------------------------
// Height-tagged coinbase creation ids
// ---------------------------------------------------------------------------

/// High-bit tag marking a coinbase mint's `creation_id`.
///
/// Coinbase outputs store `creation_id = COINBASE_CREATION_TAG | mint_height`.
/// Normal mints use the monotone `alloc_counter` namespace, which consensus
/// keeps strictly below `2^63` (allocation fails closed at the namespace
/// boundary), so the two id spaces can never collide. Exactly one live
/// coinbase output exists per block (canonical coinbase bitmap), so tagged
/// ids stay unique per chain history.
pub const COINBASE_CREATION_TAG: u64 = 1 << 63;

/// True when a `creation_id` names a coinbase mint.
#[inline]
pub const fn is_coinbase_creation_id(creation_id: u64) -> bool {
    creation_id & COINBASE_CREATION_TAG != 0
}

/// The tagged `creation_id` of the unique coinbase output minted at `height`.
#[inline]
pub const fn coinbase_creation_id(height: u64) -> u64 {
    COINBASE_CREATION_TAG | height
}

/// Mint height encoded in a tagged coinbase `creation_id`.
#[inline]
pub const fn coinbase_creation_height(creation_id: u64) -> u64 {
    creation_id & !COINBASE_CREATION_TAG
}

/// Whether a live slot's creation id can exist at one authenticated chain
/// boundary. User outputs are bounded by the monotone allocator; coinbase
/// outputs occupy the disjoint tagged namespace and are bounded by mint
/// height instead.
pub const fn creation_id_within_boundary(
    creation_id: u64,
    alloc_counter: u64,
    height: u64,
) -> bool {
    if is_coinbase_creation_id(creation_id) {
        coinbase_creation_height(creation_id) <= height
    } else {
        creation_id <= alloc_counter
    }
}

// ---------------------------------------------------------------------------
// Slot allocator PRNG
// ---------------------------------------------------------------------------
// splitmix64 constants are embedded in noid_chain::consensus::allocator.
// No separate params needed — the algorithm uses fixed Weyl/mixing constants.

// ---------------------------------------------------------------------------
// Fee policy
// ---------------------------------------------------------------------------

/// Base minimum fee in μNOID per non-coinbase transaction.
pub const MIN_FEE_BASE: u64 = 5_000; // 0.005 NOID

/// Small anti-DoS fee charged per live input verified by a transaction.
///
/// Inputs do not grow chain state, so this intentionally stays much lower than
/// the output fee. It keeps very large-input transactions from becoming free
/// relay/prover spam without penalising useful state-shrinking transactions.
pub const FEE_PER_INPUT: u64 = 100; // 0.0001 NOID per input

/// Fee charged per live output created by a transaction.
///
/// Outputs are the main user-visible driver of fee because they create UTXOs and
/// may increase state pressure. The 1-input/2-output low-pressure send remains
/// at the historical 9_000 μNOID baseline together with state-growth burn.
pub const FEE_PER_OUTPUT: u64 = 700; // 0.0007 NOID per output

/// Base fee charged per net-new live UTXO slot at low occupancy.
/// This state-growth component is burned by consensus.
pub const STATE_GROWTH_FEE_BASE: u64 = 2_500; // 0.0025 NOID per net-new slot

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_block_caps_are_exact() {
        assert_eq!(BLOCK_MAX_TXS, 256);
        assert_eq!(BLOCK_MAX_USER_PAGES, 255);
        assert_eq!(MAX_INPUTS, 8);
        assert_eq!(MAX_OUTPUTS, 2);
        assert_eq!(BLOCK_MAX_LIVE_INPUTS, 1_020);
        assert_eq!(BLOCK_MAX_USER_OUTPUTS, 510);
        assert_eq!(BLOCK_MAX_USER_ACTIONS, 1_530);
        assert_eq!(BLOCK_MAX_ACTIONS, 1_531);
    }

    #[test]
    fn history_step_page_classes_are_exact() {
        assert_eq!(BLOCK_PAGE_CLASS_TIERS, [25, 255]);
        assert_eq!(block_page_class_tier(0), Some(25));
        assert_eq!(block_page_class_tier(25), Some(25));
        assert_eq!(block_page_class_tier(26), Some(255));
        assert_eq!(block_page_class_tier(255), Some(255));
        assert_eq!(block_page_class_tier(256), None);
        assert_eq!(block_class_spend_capacity(255), BLOCK_MAX_LIVE_INPUTS);
        assert_eq!(block_class_output_capacity(255), BLOCK_MAX_USER_OUTPUTS);
        assert_eq!(block_class_touched_capacity(255), 1_531);
    }

    #[test]
    fn creation_id_boundary_uses_disjoint_user_and_coinbase_bounds() {
        assert!(creation_id_within_boundary(9, 9, 7));
        assert!(!creation_id_within_boundary(10, 9, 7));
        assert!(creation_id_within_boundary(coinbase_creation_id(7), 0, 7));
        assert!(!creation_id_within_boundary(
            coinbase_creation_id(8),
            u64::MAX,
            7,
        ));
    }

    #[test]
    fn transaction_epoch_is_not_asert_epoch() {
        assert_eq!(TX_EPOCH_BLOCKS, 144);
        assert_ne!(TX_EPOCH_BLOCKS, EPOCH_LENGTH);
    }
}
