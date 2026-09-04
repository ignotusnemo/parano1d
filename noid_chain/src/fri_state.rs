// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Column-oriented raw-state helper for UTXO slots.
//!
//! The chain state is a vector of `2^log_slots` UTXO slots. Each slot is
//! a `SlotValue { value, owner_hi, owner_lo }` tuple. Production block
//! validation uses the exact Poseidon2b sparse-Merkle UTXO root. This module
//! remains the raw segment storage utility used by the node, wallet scanner,
//! and snapshot serializer.
//!
//! State transitions are **linear**: spending `slot_i` is `slot_i ← 0`,
//! minting into `slot_j` is `slot_j ← new`. `apply_delta` applies a batch
//! of such updates in place and returns the new root.

use std::borrow::Cow;

use noid_core::{Block128, TowerField};
use noid_tx::{pack_amount_creation_id, unpack_amount_creation_id};

/// Segment size used by `SegmentedFriState`.
/// Each segment independently holds and commits `2^LOG_SEGMENT_SIZE` slots.
/// When `log_slots <= LOG_SEGMENT_SIZE` (tests), the state is monolithic
/// (one segment whose size is `2^log_slots`).
pub const LOG_SEGMENT_SIZE: usize = 16;
use noid_fri_binius::interleaved_commit_cap;
use noid_poseidon2b::native::compress;
use noid_poseidon2b::native::compression::Poseidon2bSponge;

/// Genesis `log_slots` for the public network: 16 777 216 slots at block 0. Not a
/// proof-wide constant: accepted blocks bind the header-declared `log_slots`
/// (see `noid_tx::public::PublicInputs::log_slots` and `MAX_LOG_SLOTS`),
/// which may grow to at most `32` via the expansion trigger.
/// This value is used only as the seed depth when instantiating a
/// fresh `ChainState` without an existing header. Tests override with
/// smaller values through [`FriState::new_empty`].
pub const STATE_LOG_SLOTS: usize = 24;

/// Per-slot payload: `(pack(amount, creation_id), owner)` where `owner` is
/// 256 bits split into two 128-bit halves.  The packed value keeps the raw
/// storage layout at three field elements while binding a slot incarnation to
/// every live UTXO. All-zeros means "slot empty / spent".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SlotValue {
    pub value: Block128,
    pub owner_hi: Block128,
    pub owner_lo: Block128,
}

impl SlotValue {
    pub const EMPTY: Self = Self {
        value: Block128(0),
        owner_hi: Block128(0),
        owner_lo: Block128(0),
    };

    #[inline]
    pub fn is_empty(&self) -> bool {
        *self == Self::EMPTY
    }

    /// Construct a live slot from its typed components without exposing the
    /// packed field layout to callers.
    #[inline]
    pub const fn from_parts(
        amount: u64,
        creation_id: u64,
        owner_hi: Block128,
        owner_lo: Block128,
    ) -> Self {
        Self {
            value: pack_amount_creation_id(amount, creation_id),
            owner_hi,
            owner_lo,
        }
    }

    /// Construct a live slot from typed value parts and the two owner fields.
    #[inline]
    pub const fn with_owner_fields(amount: u64, creation_id: u64, owner: [Block128; 2]) -> Self {
        Self::from_parts(amount, creation_id, owner[0], owner[1])
    }

    /// Monetary amount stored in the low 64 bits of the packed value lane.
    #[inline]
    pub const fn amount(&self) -> u64 {
        unpack_amount_creation_id(self.value).0
    }

    /// Monotone UTXO incarnation stored in the high 64 bits.
    #[inline]
    pub const fn creation_id(&self) -> u64 {
        unpack_amount_creation_id(self.value).1
    }
}

/// 32-byte state root.
pub type StateRoot = [u8; 32];

/// Errors returned by raw State updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    SlotOutOfRange,
}

/// Column-oriented UTXO state helper.
#[derive(Debug, Clone)]
pub struct FriState {
    log_slots: usize,
    values: Vec<Block128>,
    owners_hi: Vec<Block128>,
    owners_lo: Vec<Block128>,
    /// Cached root. Invalidated (set to `None`) on every mutation.
    cached_root: Option<StateRoot>,
}

impl FriState {
    /// Empty state vector with `2^log_slots` zero slots.
    ///
    /// Mainnet: `log_slots = STATE_LOG_SLOTS`. Tests should pick a small
    /// value (e.g. 4) to keep memory bounded.
    pub fn new_empty(log_slots: usize) -> Self {
        assert!(log_slots >= 1, "FriState needs at least one slot");
        let n = 1usize << log_slots;
        Self {
            log_slots,
            values: vec![Block128::ZERO; n],
            owners_hi: vec![Block128::ZERO; n],
            owners_lo: vec![Block128::ZERO; n],
            cached_root: None,
        }
    }

    #[inline]
    pub fn log_slots(&self) -> usize {
        self.log_slots
    }

    #[inline]
    pub fn num_slots(&self) -> u64 {
        1u64 << self.log_slots
    }

    /// Read the slot at `idx`. Returns `SlotValue::EMPTY` for any
    /// in-range index that has never been written.
    pub fn slot(&self, idx: u32) -> SlotValue {
        let i = idx as usize;
        assert!(i < self.values.len(), "slot index out of range");
        SlotValue {
            value: self.values[i],
            owner_hi: self.owners_hi[i],
            owner_lo: self.owners_lo[i],
        }
    }

    /// Apply a batch of `(index, new_value)` updates in place and
    /// return the post-update state root. Later entries in `deltas`
    /// override earlier ones at the same index.
    pub fn apply_delta(&mut self, deltas: &[(u32, SlotValue)]) -> Result<StateRoot, StateError> {
        for (idx, _) in deltas {
            if (*idx as u64) >= self.num_slots() {
                return Err(StateError::SlotOutOfRange);
            }
        }
        for (idx, v) in deltas {
            let i = *idx as usize;
            self.values[i] = v.value;
            self.owners_hi[i] = v.owner_hi;
            self.owners_lo[i] = v.owner_lo;
        }
        self.cached_root = None;
        Ok(self.root())
    }

    /// Write one slot and return the new root.
    pub fn set_slot(&mut self, idx: u32, v: SlotValue) -> Result<StateRoot, StateError> {
        self.apply_delta(&[(idx, v)])
    }

    /// Compute (or return cached) state root.
    ///
    /// Uses the established interleaved cap format over the three columns,
    /// then reduces the cap to a single 32-byte root. This matches
    /// `SegmentedFriState` raw segment storage; production block validity uses
    /// exact sparse-Merkle transition proofs.
    pub fn root(&mut self) -> StateRoot {
        if let Some(r) = self.cached_root {
            return r;
        }
        let r = compute_segment_root(
            self.log_slots,
            &self.values,
            &self.owners_hi,
            &self.owners_lo,
        );
        self.cached_root = Some(r);
        r
    }

    /// Consume `self` and return the three raw columns. Useful for the
    /// Prover-side witness builder that needs the whole evaluation vector.
    pub fn into_columns(self) -> (Vec<Block128>, Vec<Block128>, Vec<Block128>) {
        (self.values, self.owners_hi, self.owners_lo)
    }

    /// Borrow the three columns without taking ownership.
    pub fn columns(&self) -> (&[Block128], &[Block128], &[Block128]) {
        (&self.values, &self.owners_hi, &self.owners_lo)
    }
}

// ---------------------------------------------------------------------------
// Raw segment commitment
// ---------------------------------------------------------------------------

/// Minimum log2(n) for the interleaved cap to be data-sensitive
/// (cap_size = 2^MERKLE_CAP_DEPTH = 32 requires n >= 32).
const MIN_COMMIT_LOG: usize = noid_fri_binius::MERKLE_CAP_DEPTH;

fn pad_column_borrowed(col: &[Block128], commit_n: usize) -> Cow<'_, [Block128]> {
    if col.len() < commit_n {
        let mut padded = col.to_vec();
        padded.resize(commit_n, Block128::ZERO);
        Cow::Owned(padded)
    } else {
        Cow::Borrowed(col)
    }
}

/// Compute the established raw segment commitment from three column vectors.
///
/// `seg_root = cap_to_seg_root(interleaved_commit_cap(padded_cols))` where
/// padding to `2^max(eff_log, MIN_COMMIT_LOG)` ensures the cap captures all data.
/// For production (`eff_log=16`): no padding needed. For small test segments
/// (`eff_log < 5`): zero-padded to 32 elements before commitment.
pub fn compute_segment_root(
    eff_log: usize,
    values: &[Block128],
    owners_hi: &[Block128],
    owners_lo: &[Block128],
) -> StateRoot {
    let commit_log = eff_log.max(MIN_COMMIT_LOG);
    let commit_n = 1usize << commit_log;
    // Pad to commit_n if needed (zero-extends, preserves MLE on lower hypercube).
    // Production segments already have commit_n rows, so borrow them to avoid
    // copying three full 2^16 columns before every root computation.
    let v = pad_column_borrowed(values, commit_n);
    let h = pad_column_borrowed(owners_hi, commit_n);
    let l = pad_column_borrowed(owners_lo, commit_n);
    let ntt = noid_core::AdditiveNTT::<Block128>::new(commit_log + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let cols: [&[Block128]; 3] = [v.as_ref(), h.as_ref(), l.as_ref()];
    let cap = interleaved_commit_cap(&cols, &ntt, &hasher);
    cap_to_seg_root_with_depth(&cap, eff_log)
}

/// Reduce an interleaved cap to a single 32-byte state root via pairwise
/// Poseidon2b compression, then mix in `eff_log` for domain separation across
/// segment sizes.
///
/// Caps contain the 32 segment hashes plus the encoded-source cap retained by
/// the historical commitment format. Odd layers are padded with a deterministic
/// domain-separated leaf instead of silently dropping the final hash.
///
/// Including `eff_log` ensures states with different `log_slots` produce
/// distinct roots even when all data is zero.
pub fn cap_to_seg_root(cap: &noid_fri_binius::MerkleCap) -> StateRoot {
    let mut layer: Vec<[u8; 32]> = cap.hashes.clone();
    assert!(!layer.is_empty(), "state cap must not be empty");
    let mut level = 0u64;
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(state_cap_odd_pad(level, layer.len()));
        }
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks_exact(2) {
            next.push(compress(&chunk[0], &chunk[1]));
        }
        layer = next;
        level += 1;
    }
    layer[0]
}

fn state_cap_odd_pad(level: u64, layer_len: usize) -> [u8; 32] {
    let mut pad = [0u8; 32];
    pad[..8].copy_from_slice(&level.to_le_bytes());
    pad[8..16].copy_from_slice(&(layer_len as u64).to_le_bytes());
    pad[16..].copy_from_slice(b"NOID_STATE_PAD_v");
    pad
}

/// Like `cap_to_seg_root` but mixes in the ORIGINAL `eff_log` so that
/// empty segments of different depths produce distinct roots.
///
/// Use this everywhere a segment root is computed or verified.
pub fn cap_to_seg_root_with_depth(cap: &noid_fri_binius::MerkleCap, eff_log: usize) -> StateRoot {
    let base = cap_to_seg_root(cap);
    // Mix eff_log into the root via one Poseidon2b compression.
    let mut depth = [0u8; 32];
    depth[..8].copy_from_slice(&(eff_log as u64).to_le_bytes());
    compress(&base, &depth)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(seed: u128) -> SlotValue {
        SlotValue {
            value: Block128::from(seed),
            owner_hi: Block128::from(seed.wrapping_mul(3) + 1),
            owner_lo: Block128::from(seed.wrapping_mul(7) + 2),
        }
    }

    #[test]
    fn empty_state_root_is_deterministic() {
        let mut a = FriState::new_empty(4);
        let mut b = FriState::new_empty(4);
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn empty_roots_differ_by_depth() {
        let mut a = FriState::new_empty(4);
        let mut b = FriState::new_empty(5);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn writing_a_slot_changes_the_root() {
        let mut state = FriState::new_empty(4);
        let r0 = state.root();
        state.set_slot(3, sv(42)).unwrap();
        let r1 = state.root();
        assert_ne!(r0, r1);
    }

    #[test]
    fn delta_is_idempotent_on_zero_write() {
        let mut state = FriState::new_empty(4);
        let r0 = state.root();
        state.apply_delta(&[(2, SlotValue::EMPTY)]).unwrap();
        assert_eq!(state.root(), r0);
    }

    #[test]
    fn spending_then_rewriting_restores_root() {
        let mut state = FriState::new_empty(4);
        let seed = sv(9);
        let r0 = state.root();
        state.set_slot(1, seed).unwrap();
        let r1 = state.root();
        state.set_slot(1, SlotValue::EMPTY).unwrap();
        assert_eq!(state.root(), r0);
        state.set_slot(1, seed).unwrap();
        assert_eq!(state.root(), r1);
    }

    #[test]
    fn batch_delta_equals_sequential() {
        let deltas = [(0u32, sv(1)), (5, sv(2)), (10, sv(3))];
        let mut batched = FriState::new_empty(4);
        batched.apply_delta(&deltas).unwrap();

        let mut seq = FriState::new_empty(4);
        for (i, v) in deltas {
            seq.set_slot(i, v).unwrap();
        }
        assert_eq!(batched.root(), seq.root());
    }

    #[test]
    fn out_of_range_errors() {
        let mut state = FriState::new_empty(2); // 4 slots
        assert_eq!(
            state.apply_delta(&[(4, sv(1))]),
            Err(StateError::SlotOutOfRange)
        );
    }

    #[test]
    fn slot_reads_back_what_was_written() {
        let mut state = FriState::new_empty(3);
        let v = sv(777);
        state.set_slot(6, v).unwrap();
        assert_eq!(state.slot(6), v);
        assert_eq!(state.slot(0), SlotValue::EMPTY);
    }
}
