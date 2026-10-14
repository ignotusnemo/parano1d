// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! Batch Poseidon2b permutation using packed arithmetic.
//!
//! Processes P independent permutations simultaneously by:
//! 1. Loading P state vectors into packed representation
//! 2. Applying linear operations (round constants, MDS) in packed form
//! 3. Applying S-box per lane (squarings are packed, muls are per-lane)

// Many loops in this module iterate by explicit index because they touch
// multiple parallel buffers (state/input/round-constants/MDS rows) or use
// the index arithmetically. Rewriting them as iterator chains hurts
// readability without changing generated code.
#![allow(clippy::needless_range_loop)]

use crate::native::compression::Poseidon2bSponge;
use crate::native::domain::{capacity_iv, capacity_iv_flat, DomainTag, TAG_COMPRESS};
use crate::native::permutation::{
    F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};
use noid_core::hardware::{flat_to_tower_u128, tower_to_flat_u128};
use noid_core::packed::{PackedBlock128, PACKED_LANES};
use noid_core::Block128;
use std::sync::OnceLock;

/// Number of independent Block128 lanes used by the packed Poseidon2b kernels
/// in this build.
pub const POSEIDON2B_BATCH_LANES: usize = PACKED_LANES;

/// Padding constants for Poseidon2b sponge finalization.
const PAD0: u128 = u128::from_le_bytes([0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
const PAD1: u128 = u128::from_le_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);

/// Hash pairs of field elements using packed permutations.
///
/// When `PACKED_LANES > 1` and the input is large enough, processes
/// multiple hashes simultaneously. Falls back to scalar hashing for
/// small inputs or scalar builds.
pub fn hash_pair_batch(a: &[Block128], b: &[Block128]) -> Vec<[u8; 32]> {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    let mut out = vec![[0u8; 32]; n];

    let scalar = |i: usize| scalar_hash_pair(a[i], b[i]);

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            out[i] = scalar(i);
        }
        return out;
    }

    let chunks = n / PACKED_LANES;

    for chunk in 0..chunks {
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let off = chunk * PACKED_LANES;

        for lane in 0..PACKED_LANES {
            states[0] = states[0].set_lane(lane, a[off + lane]);
            states[1] = states[1].set_lane(lane, b[off + lane]);
        }

        // Fixed-width compression: one permutation on [a, b, 0, 0].
        packed_poseidon2b_permute(&mut states);

        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        out[i] = scalar(i);
    }

    out
}

/// Hash adjacent pairs of field elements from a single interleaved slice.
///
/// `pairs` has even length: `[a0, b0, a1, b1, ...]`. Output `out[i]` is the
/// `hash_pair(a_i, b_i)` digest. Skips the two-Vec split that
/// `hash_pair_batch` callers would otherwise have to do on an interleaved
/// input.
pub fn hash_pair_batch_interleaved_into(pairs: &[Block128], out: &mut [[u8; 32]]) {
    assert_eq!(
        pairs.len() & 1,
        0,
        "hash_pair_batch_interleaved expects even length"
    );
    let n = pairs.len() / 2;
    assert_eq!(out.len(), n, "output length must match pair count");

    let scalar = |i: usize, out: &mut [[u8; 32]]| {
        out[i] = scalar_hash_pair(pairs[2 * i], pairs[2 * i + 1]);
    };

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            scalar(i, out);
        }
        return;
    }

    let chunks = n / PACKED_LANES;

    for chunk in 0..chunks {
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let off = chunk * PACKED_LANES;

        for lane in 0..PACKED_LANES {
            states[0] = states[0].set_lane(lane, pairs[2 * (off + lane)]);
            states[1] = states[1].set_lane(lane, pairs[2 * (off + lane) + 1]);
        }

        // Fixed-width compression: one permutation on [a, b, 0, 0].
        packed_poseidon2b_permute(&mut states);

        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        scalar(i, out);
    }
}

/// Scalar fixed-width `(Block128, Block128) → [u8; 32]` compression.
/// Matches `CryptographicHasher::hash_pair` — one Poseidon2b permutation.
fn scalar_hash_pair(a: Block128, b: Block128) -> [u8; 32] {
    use crate::native::permutation::Poseidon2bPermutation;
    use noid_core::{CanonicalSerialize, TowerField};
    let mut state = [a, b, Block128::ZERO, Block128::ZERO];
    Poseidon2bPermutation.permute_mut(&mut state);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&state[0].to_bytes());
    out[16..].copy_from_slice(&state[1].to_bytes());
    out
}

/// Hash concatenations of 32-byte digests using packed permutations.
///
/// Matches the exact scalar output of `Poseidon2bSponge::hash_concatenation`.
pub fn hash_concatenation_batch(a: &[[u8; 32]], b: &[[u8; 32]]) -> Vec<[u8; 32]> {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    let mut out = vec![[0u8; 32]; n];

    let scalar = |i: usize| {
        let mut sponge = Poseidon2bSponge::new();
        sponge.update(&a[i]);
        sponge.update(&b[i]);
        sponge.finalize()
    };

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            out[i] = scalar(i);
        }
        return out;
    }

    let chunks = n / PACKED_LANES;

    for chunk in 0..chunks {
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let off = chunk * PACKED_LANES;

        // Load a into rate (states start at zero, so set = XOR)
        for lane in 0..PACKED_LANES {
            let a0 = Block128::from(u128::from_le_bytes(
                a[off + lane][0..16].try_into().unwrap(),
            ));
            let a1 = Block128::from(u128::from_le_bytes(
                a[off + lane][16..32].try_into().unwrap(),
            ));
            states[0] = states[0].set_lane(lane, a0);
            states[1] = states[1].set_lane(lane, a1);
        }

        // update(a) -> permute
        packed_poseidon2b_permute(&mut states);

        // XOR b into rate
        let mut pb0 = PackedBlock128::ZERO;
        let mut pb1 = PackedBlock128::ZERO;
        for lane in 0..PACKED_LANES {
            let b0 = Block128::from(u128::from_le_bytes(
                b[off + lane][0..16].try_into().unwrap(),
            ));
            let b1 = Block128::from(u128::from_le_bytes(
                b[off + lane][16..32].try_into().unwrap(),
            ));
            pb0 = pb0.set_lane(lane, b0);
            pb1 = pb1.set_lane(lane, b1);
        }
        states[0] = states[0].xor(pb0);
        states[1] = states[1].xor(pb1);

        packed_poseidon2b_permute(&mut states);

        // finalize padding
        states[0] = states[0].xor(PackedBlock128::broadcast(Block128::from(PAD0)));
        states[1] = states[1].xor(PackedBlock128::broadcast(Block128::from(PAD1)));
        packed_poseidon2b_permute(&mut states);

        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        out[i] = scalar(i);
    }

    out
}

/// Hash interleaved pairs of 32-byte digests using packed permutations.
///
/// `pairs` must have even length and contain `[a0, b0, a1, b1, ...]`.
/// Matches the exact scalar output of `Poseidon2bSponge::hash_concatenation`.
pub fn hash_concatenation_batch_interleaved(pairs: &[[u8; 32]]) -> Vec<[u8; 32]> {
    assert_eq!(
        pairs.len() & 1,
        0,
        "Interleaved pairs must have even length"
    );
    let n = pairs.len() / 2;
    let mut out = vec![[0u8; 32]; n];

    let scalar = |i: usize| {
        let mut sponge = Poseidon2bSponge::new();
        sponge.update(&pairs[2 * i]);
        sponge.update(&pairs[2 * i + 1]);
        sponge.finalize()
    };

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            out[i] = scalar(i);
        }
        return out;
    }

    let chunks = n / PACKED_LANES;

    for chunk in 0..chunks {
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let off = chunk * PACKED_LANES;

        // Load a into rate (states start at zero)
        for lane in 0..PACKED_LANES {
            let a0 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane)][0..16].try_into().unwrap(),
            ));
            let a1 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane)][16..32].try_into().unwrap(),
            ));
            states[0] = states[0].set_lane(lane, a0);
            states[1] = states[1].set_lane(lane, a1);
        }

        packed_poseidon2b_permute(&mut states);

        // XOR b into rate
        let mut pb0 = PackedBlock128::ZERO;
        let mut pb1 = PackedBlock128::ZERO;
        for lane in 0..PACKED_LANES {
            let b0 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane) + 1][0..16].try_into().unwrap(),
            ));
            let b1 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane) + 1][16..32].try_into().unwrap(),
            ));
            pb0 = pb0.set_lane(lane, b0);
            pb1 = pb1.set_lane(lane, b1);
        }
        states[0] = states[0].xor(pb0);
        states[1] = states[1].xor(pb1);

        packed_poseidon2b_permute(&mut states);

        // finalize padding
        states[0] = states[0].xor(PackedBlock128::broadcast(Block128::from(PAD0)));
        states[1] = states[1].xor(PackedBlock128::broadcast(Block128::from(PAD1)));
        packed_poseidon2b_permute(&mut states);

        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        out[i] = scalar(i);
    }

    out
}

/// Batched 2-to-1 compression of interleaved 32-byte digest pairs.
///
/// Matches `native::compress` exactly: two Poseidon2b permutations per
/// pair with capacity IV = `COMPRESS` absorbed before `a`, then `b` XORed
/// into the rate between permutations (CRYPTO.md §5.1).
pub fn compress_batch_interleaved_into(pairs: &[[u8; 32]], out: &mut [[u8; 32]]) {
    compress_batch_interleaved_with_tag_into(TAG_COMPRESS, pairs, out);
}

/// Batched 2-to-1 compression of interleaved 32-byte digest pairs under a
/// caller-selected capacity tag.
///
/// Matches `native::compress_with_tag(tag, left, right)` exactly.
pub fn compress_batch_interleaved_with_tag_into(
    tag: DomainTag,
    pairs: &[[u8; 32]],
    out: &mut [[u8; 32]],
) {
    assert_eq!(
        pairs.len() & 1,
        0,
        "Interleaved pairs must have even length"
    );
    let n = pairs.len() / 2;
    assert_eq!(out.len(), n, "Output length must match pair count");

    let scalar = |i: usize, out: &mut [[u8; 32]]| {
        out[i] = crate::native::compress_with_tag(tag, &pairs[2 * i], &pairs[2 * i + 1]);
    };

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            scalar(i, out);
        }
        return;
    }

    let [iv_hi, iv_lo] = capacity_iv(tag);
    let chunks = n / PACKED_LANES;

    for chunk in 0..chunks {
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let off = chunk * PACKED_LANES;

        // state = [a0, a1, IV_hi, IV_lo]
        states[2] = PackedBlock128::broadcast(iv_hi);
        states[3] = PackedBlock128::broadcast(iv_lo);
        for lane in 0..PACKED_LANES {
            let a0 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane)][0..16].try_into().unwrap(),
            ));
            let a1 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane)][16..32].try_into().unwrap(),
            ));
            states[0] = states[0].set_lane(lane, a0);
            states[1] = states[1].set_lane(lane, a1);
        }

        packed_poseidon2b_permute(&mut states);

        // XOR b into rate.
        let mut pb0 = PackedBlock128::ZERO;
        let mut pb1 = PackedBlock128::ZERO;
        for lane in 0..PACKED_LANES {
            let b0 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane) + 1][0..16].try_into().unwrap(),
            ));
            let b1 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane) + 1][16..32].try_into().unwrap(),
            ));
            pb0 = pb0.set_lane(lane, b0);
            pb1 = pb1.set_lane(lane, b1);
        }
        states[0] = states[0].xor(pb0);
        states[1] = states[1].xor(pb1);

        packed_poseidon2b_permute(&mut states);

        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        scalar(i, out);
    }
}

/// Like `hash_concatenation_batch_interleaved` but writes into a caller-provided
/// output slice. Skips the Vec allocation per layer.
pub fn hash_concatenation_batch_interleaved_into(pairs: &[[u8; 32]], out: &mut [[u8; 32]]) {
    assert_eq!(
        pairs.len() & 1,
        0,
        "Interleaved pairs must have even length"
    );
    let n = pairs.len() / 2;
    assert_eq!(out.len(), n, "Output length must match pair count");

    let scalar = |i: usize, out: &mut [[u8; 32]]| {
        let mut sponge = Poseidon2bSponge::new();
        sponge.update(&pairs[2 * i]);
        sponge.update(&pairs[2 * i + 1]);
        out[i] = sponge.finalize();
    };

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            scalar(i, out);
        }
        return;
    }

    let chunks = n / PACKED_LANES;

    for chunk in 0..chunks {
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let off = chunk * PACKED_LANES;

        for lane in 0..PACKED_LANES {
            let a0 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane)][0..16].try_into().unwrap(),
            ));
            let a1 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane)][16..32].try_into().unwrap(),
            ));
            states[0] = states[0].set_lane(lane, a0);
            states[1] = states[1].set_lane(lane, a1);
        }

        packed_poseidon2b_permute(&mut states);

        let mut pb0 = PackedBlock128::ZERO;
        let mut pb1 = PackedBlock128::ZERO;
        for lane in 0..PACKED_LANES {
            let b0 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane) + 1][0..16].try_into().unwrap(),
            ));
            let b1 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane) + 1][16..32].try_into().unwrap(),
            ));
            pb0 = pb0.set_lane(lane, b0);
            pb1 = pb1.set_lane(lane, b1);
        }
        states[0] = states[0].xor(pb0);
        states[1] = states[1].xor(pb1);

        packed_poseidon2b_permute(&mut states);

        states[0] = states[0].xor(PackedBlock128::broadcast(Block128::from(PAD0)));
        states[1] = states[1].xor(PackedBlock128::broadcast(Block128::from(PAD1)));
        packed_poseidon2b_permute(&mut states);

        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        scalar(i, out);
    }
}

/// Precomputed flat-basis round constants and MDS matrices.
///
/// XOR is identical in tower and flat bases (both linear over GF(2)), and
/// scalar multiplication in flat basis is just CLMUL. Converting the
/// Poseidon2b constants once at program start lets the batch permutation
/// stay in flat basis for the entire schedule.
struct FlatTables {
    rc: [[u128; N_ROUNDS]; STATE_SIZE],
    mds_full: [[u128; STATE_SIZE]; STATE_SIZE],
    mds_partial: [[u128; STATE_SIZE]; STATE_SIZE],
    // Sparsity masks: `is_one[i][j] = true` when MDS[i][j] == tower 0x1.
    // In that case multiplication is the identity and the CLMUL can be
    // replaced with a bare XOR of the input.
    mds_full_is_one: [[bool; STATE_SIZE]; STATE_SIZE],
    mds_partial_is_one: [[bool; STATE_SIZE]; STATE_SIZE],
}

/// Flat-basis constants shared by register-domain ISA kernels.
pub(crate) struct KernelTables {
    pub rc: [[u128; N_ROUNDS]; STATE_SIZE],
    pub mds_full_two: u128,
    pub mds_full_four: u128,
    pub mds_partial_diag: [u128; STATE_SIZE],
}

fn flat_tables() -> &'static FlatTables {
    static TABLES: OnceLock<FlatTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut rc = [[0u128; N_ROUNDS]; STATE_SIZE];
        for i in 0..STATE_SIZE {
            for r in 0..N_ROUNDS {
                rc[i][r] = tower_to_flat_u128(ROUND_CONSTANTS[i][r]);
            }
        }
        let mut mds_full = [[0u128; STATE_SIZE]; STATE_SIZE];
        let mut mds_partial = [[0u128; STATE_SIZE]; STATE_SIZE];
        let mut mds_full_is_one = [[false; STATE_SIZE]; STATE_SIZE];
        let mut mds_partial_is_one = [[false; STATE_SIZE]; STATE_SIZE];
        for i in 0..STATE_SIZE {
            for j in 0..STATE_SIZE {
                mds_full[i][j] = tower_to_flat_u128(MDS_FULL[i][j]);
                mds_partial[i][j] = tower_to_flat_u128(MDS_PARTIAL[i][j]);
                mds_full_is_one[i][j] = MDS_FULL[i][j] == 1;
                mds_partial_is_one[i][j] = MDS_PARTIAL[i][j] == 1;
            }
        }
        FlatTables {
            rc,
            mds_full,
            mds_partial,
            mds_full_is_one,
            mds_partial_is_one,
        }
    })
}

/// Runtime gate for the register-domain AVX2+VPCLMULQDQ kernels. In a build
/// where both features are statically enabled this folds to `true` at
/// compile time; a runtime-dispatched source build probes once at first use
/// (Alder/Raptor-Lake class cores and every AVX-512 part pass). New ISA
/// tiers (AVX-512, aarch64 PMULL) plug their kernels into the same dispatch
/// points.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn avx2_vpclmul_runtime() -> bool {
    #[cfg(all(target_feature = "avx2", target_feature = "vpclmulqdq"))]
    return true;
    #[cfg(not(all(target_feature = "avx2", target_feature = "vpclmulqdq")))]
    noid_core::cpu::avx2_vpclmul_available()
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn avx512_vpclmul_runtime() -> bool {
    #[cfg(all(
        target_feature = "avx512f",
        target_feature = "avx512bw",
        target_feature = "vpclmulqdq"
    ))]
    return true;
    #[cfg(not(all(
        target_feature = "avx512f",
        target_feature = "avx512bw",
        target_feature = "vpclmulqdq"
    )))]
    noid_core::cpu::avx512_vpclmul_available()
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub(crate) fn pmull_runtime() -> bool {
    #[cfg(target_feature = "aes")]
    return true;
    #[cfg(not(target_feature = "aes"))]
    noid_core::cpu::pmull_available()
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn kernel_tables() -> &'static KernelTables {
    static TABLES: OnceLock<KernelTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        assert_eq!(
            MDS_FULL,
            [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]],
            "register-domain full MDS specialization drifted from protocol constants"
        );
        let t = flat_tables();
        let mut mds_partial_diag = [0u128; STATE_SIZE];
        for i in 0..STATE_SIZE {
            mds_partial_diag[i] = t.mds_partial[i][i];
            for j in 0..STATE_SIZE {
                // The register-domain kernel folds the off-diagonal entries
                // into one shared XOR sum — valid only while they are all 1.
                assert!(
                    i == j || t.mds_partial_is_one[i][j],
                    "partial MDS off-diagonal must be 1"
                );
            }
        }
        KernelTables {
            rc: t.rc,
            mds_full_two: tower_to_flat_u128(2),
            mds_full_four: tower_to_flat_u128(4),
            mds_partial_diag,
        }
    })
}

/// Apply PackedBlock128 Poseidon2b permutation to P states simultaneously.
///
/// Runs the entire schedule in flat basis: a single tower→flat pass at the
/// start and flat→tower pass at the end replaces what was previously 3
/// basis conversions per CLMUL (hundreds per permutation).
pub fn packed_poseidon2b_permute(states: &mut [PackedBlock128; STATE_SIZE]) {
    // Convert state to flat basis once.
    for i in 0..STATE_SIZE {
        states[i] = states[i].to_flat();
    }
    packed_poseidon2b_permute_flat(states);
    // Convert back to tower basis.
    for i in 0..STATE_SIZE {
        states[i] = states[i].to_tower();
    }
}

/// Number of independent packed state groups the wide batch kernels keep in
/// flight. One permutation is a serial multiply chain (S-box then MDS every
/// round), so a single group leaves the CLMUL unit mostly idle waiting on
/// latency; interleaving independent hashes converts the batch from
/// latency-bound to throughput-bound. 4 groups × PACKED_LANES lanes saturate
/// the carry-less-multiply port without spilling the working set.
const PERM_INTERLEAVE: usize = 4;

/// Apply the flat-basis packed permutation to several INDEPENDENT packed
/// state groups in lockstep — each round phase runs across all groups before
/// the next phase starts, so the out-of-order core overlaps the groups'
/// multiply chains. Bit-identical per group to
/// [`packed_poseidon2b_permute_flat`].
pub fn packed_poseidon2b_permute_flat_many(states: &mut [[PackedBlock128; STATE_SIZE]]) {
    #[cfg(target_arch = "x86_64")]
    if states.len() >= 2 && avx512_vpclmul_runtime() {
        // SAFETY: gated on runtime AVX-512BW+VPCLMULQDQ detection.
        return unsafe { crate::batch_avx512::permute_flat_groups(states, kernel_tables()) };
    }
    #[cfg(target_arch = "x86_64")]
    if avx2_vpclmul_runtime() {
        // SAFETY: gated on runtime AVX2+VPCLMULQDQ detection.
        return unsafe { crate::batch_avx2::permute_flat_groups(states, kernel_tables()) };
    }
    #[cfg(target_arch = "aarch64")]
    if pmull_runtime() {
        // SAFETY: gated on runtime/static PMULL detection.
        return unsafe { crate::batch_aarch64::permute_flat_groups(states, kernel_tables()) };
    }
    #[allow(unreachable_code)]
    {
        let tables = flat_tables();

        for s in states.iter_mut() {
            packed_apply_mds_full_flat(s, tables);
        }

        for r in 0..N_ROUNDS {
            let is_full = !((F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&r));

            if is_full {
                for s in states.iter_mut() {
                    for i in 0..STATE_SIZE {
                        s[i] = s[i].xor(PackedBlock128::broadcast(Block128::from(tables.rc[i][r])));
                        s[i] = packed_sbox_x7_flat(s[i]);
                    }
                }
                for s in states.iter_mut() {
                    packed_apply_mds_full_flat(s, tables);
                }
            } else {
                let rc_flat = tables.rc[0][r];
                for s in states.iter_mut() {
                    s[0] = s[0].xor(PackedBlock128::broadcast(Block128::from(rc_flat)));
                    s[0] = packed_sbox_x7_flat(s[0]);
                }
                for s in states.iter_mut() {
                    packed_apply_mds_partial_flat(s, tables);
                }
            }
        }
    }
}

/// Packed permutation acting on states whose lanes already carry **flat
/// (GCM) basis** bit patterns — the batched twin of
/// `native::permutation::permute_flat_u128`, with no boundary conversion.
pub fn packed_poseidon2b_permute_flat(states: &mut [PackedBlock128; STATE_SIZE]) {
    #[cfg(target_arch = "x86_64")]
    if avx2_vpclmul_runtime() {
        // SAFETY: gated on runtime AVX2+VPCLMULQDQ detection.
        return unsafe { crate::batch_avx2::permute_flat_one(states, kernel_tables()) };
    }
    #[cfg(target_arch = "aarch64")]
    if pmull_runtime() {
        // SAFETY: gated on runtime/static PMULL detection.
        return unsafe { crate::batch_aarch64::permute_flat_one(states, kernel_tables()) };
    }
    #[allow(unreachable_code)]
    let tables = flat_tables();

    // Initial MDS_FULL multiplication (flat basis).
    packed_apply_mds_full_flat(states, tables);

    for r in 0..N_ROUNDS {
        let is_full = !((F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&r));

        // 1. Add round constants (linear — XOR works in flat basis).
        if is_full {
            for i in 0..STATE_SIZE {
                let rc_flat = tables.rc[i][r];
                states[i] = states[i].xor(PackedBlock128::broadcast(Block128::from(rc_flat)));
            }
        } else {
            let rc_flat = tables.rc[0][r];
            states[0] = states[0].xor(PackedBlock128::broadcast(Block128::from(rc_flat)));
        }

        // 2. Apply S-box x → x^7 in flat basis (no round trips).
        let active_count = if is_full { STATE_SIZE } else { 1 };
        for i in 0..active_count {
            states[i] = packed_sbox_x7_flat(states[i]);
        }

        // 3. Apply MDS (flat basis).
        if is_full {
            packed_apply_mds_full_flat(states, tables);
        } else {
            packed_apply_mds_partial_flat(states, tables);
        }
    }
}

/// Prepared fixed-length field-element sponge whose only varying field is a
/// consecutive `u128` nonce.
///
/// Fixed fields are converted to the flat basis once at construction and are
/// copied into scratch only when the batch reaches a new maximum size. Later
/// calls patch only the nonce words. The existing no-pad leaf kernels then
/// keep several independent sponge chains in registers: eight nonces per AVX2
/// chunk, sixteen per AVX-512 chunk, and four per AArch64 PMULL chunk. Results
/// are mapped back to the canonical tower basis, so this is byte-identical to
/// `Poseidon2bSponge::with_iv` followed by `absorb_pair` for every field pair
/// and `finalize_no_pad`.
pub struct FixedFieldNonceBatch {
    iv: [u128; 2],
    flat_template: Box<[u8]>,
    nonce_offset: usize,
    flat_leaves: Vec<u8>,
}

impl FixedFieldNonceBatch {
    pub fn new(tag: DomainTag, fields: &[Block128], nonce_field_index: usize) -> Self {
        assert!(
            !fields.is_empty() && fields.len().is_multiple_of(2),
            "fixed-field sponge requires a nonempty even field count"
        );
        assert!(
            nonce_field_index < fields.len(),
            "nonce field index is outside the fixed-field sponge"
        );

        let leaf_size = fields
            .len()
            .checked_mul(16)
            .expect("fixed-field sponge byte length must fit usize");
        let mut flat_template = Vec::with_capacity(leaf_size);
        for field in fields {
            flat_template.extend_from_slice(&tower_to_flat_u128(field.to_u128()).to_le_bytes());
        }
        Self {
            iv: capacity_iv_flat(tag),
            flat_template: flat_template.into_boxed_slice(),
            nonce_offset: nonce_field_index * 16,
            flat_leaves: Vec::new(),
        }
    }

    pub fn hash_into(&mut self, start_nonce: u128, out: &mut [[u8; 32]]) {
        if out.is_empty() {
            return;
        }

        let leaf_size = self.flat_template.len();
        let data_len = leaf_size
            .checked_mul(out.len())
            .expect("fixed-field sponge batch length must fit usize");
        let previous_len = self.flat_leaves.len();
        if previous_len < data_len {
            self.flat_leaves.resize(data_len, 0);
            for leaf in self.flat_leaves[previous_len..data_len].chunks_exact_mut(leaf_size) {
                leaf.copy_from_slice(&self.flat_template);
            }
        }

        let active_leaves = &mut self.flat_leaves[..data_len];
        for (index, leaf) in active_leaves.chunks_exact_mut(leaf_size).enumerate() {
            let nonce = start_nonce.saturating_add(index as u128);
            let nonce_flat = tower_to_flat_u128(nonce).to_le_bytes();
            leaf[self.nonce_offset..self.nonce_offset + 16].copy_from_slice(&nonce_flat);
        }

        leaf_sponge_flat_batch_with_iv_into(self.iv, false, active_leaves, leaf_size, out);

        for digest in out {
            let flat_hi = u128::from_le_bytes(digest[..16].try_into().unwrap());
            let flat_lo = u128::from_le_bytes(digest[16..].try_into().unwrap());
            digest[..16].copy_from_slice(&flat_to_tower_u128(flat_hi).to_le_bytes());
            digest[16..].copy_from_slice(&flat_to_tower_u128(flat_lo).to_le_bytes());
        }
    }
}

/// Batched flat-basis 1-permutation feed-forward compression of interleaved
/// 32-byte digest pairs. Matches
/// `native::compress_flat_feed_forward_with_tag(tag, left, right)` exactly.
pub fn compress_flat_ff_batch_interleaved_with_tag_into(
    tag: DomainTag,
    pairs: &[[u8; 32]],
    out: &mut [[u8; 32]],
) {
    assert_eq!(
        pairs.len() & 1,
        0,
        "Interleaved pairs must have even length"
    );
    let n = pairs.len() / 2;
    assert_eq!(out.len(), n, "Output length must match pair count");

    let scalar = |i: usize, out: &mut [[u8; 32]]| {
        out[i] = crate::native::compression::compress_flat_feed_forward_with_tag(
            tag,
            &pairs[2 * i],
            &pairs[2 * i + 1],
        );
    };

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            scalar(i, out);
        }
        return;
    }

    let [iv_hi, iv_lo] = crate::native::domain::capacity_iv_flat(tag);
    let chunks = n / PACKED_LANES;

    // Load one packed group: state = [a0, a1, b0 ^ IV_hi, b1 ^ IV_lo] (all
    // lanes flat bit patterns; Block128 is used as a plain 128-bit container
    // here). Returns the (a0, a1) lanes for the feed-forward.
    let load_group = |off: usize,
                      states: &mut [PackedBlock128; STATE_SIZE]|
     -> (PackedBlock128, PackedBlock128) {
        let mut a0s = PackedBlock128::ZERO;
        let mut a1s = PackedBlock128::ZERO;
        *states = [PackedBlock128::ZERO; STATE_SIZE];
        for lane in 0..PACKED_LANES {
            let a = &pairs[2 * (off + lane)];
            let b = &pairs[2 * (off + lane) + 1];
            let a0 = u128::from_le_bytes(a[0..16].try_into().unwrap());
            let a1 = u128::from_le_bytes(a[16..32].try_into().unwrap());
            let b0 = u128::from_le_bytes(b[0..16].try_into().unwrap());
            let b1 = u128::from_le_bytes(b[16..32].try_into().unwrap());
            a0s = a0s.set_lane(lane, Block128::from(a0));
            a1s = a1s.set_lane(lane, Block128::from(a1));
            states[0] = states[0].set_lane(lane, Block128::from(a0));
            states[1] = states[1].set_lane(lane, Block128::from(a1));
            states[2] = states[2].set_lane(lane, Block128::from(b0 ^ iv_hi));
            states[3] = states[3].set_lane(lane, Block128::from(b1 ^ iv_lo));
        }
        (a0s, a1s)
    };

    // Feed-forward of the left input on the truncated lanes, then store.
    let store_group = |off: usize,
                       states: &[PackedBlock128; STATE_SIZE],
                       ff: (PackedBlock128, PackedBlock128),
                       out: &mut [[u8; 32]]| {
        let s0 = states[0].xor(ff.0);
        let s1 = states[1].xor(ff.1);
        for lane in 0..PACKED_LANES {
            out[off + lane][..16].copy_from_slice(&s0.get_lane(lane).to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.get_lane(lane).to_u128().to_le_bytes());
        }
    };

    // Wide pass: PERM_INTERLEAVE independent groups per permutation call so
    // the multiply chains of one hash overlap another's.
    let wide_chunks = chunks / PERM_INTERLEAVE;
    for wchunk in 0..wide_chunks {
        let base = wchunk * PERM_INTERLEAVE * PACKED_LANES;
        let mut states = [[PackedBlock128::ZERO; STATE_SIZE]; PERM_INTERLEAVE];
        let mut ffs = [(PackedBlock128::ZERO, PackedBlock128::ZERO); PERM_INTERLEAVE];
        for g in 0..PERM_INTERLEAVE {
            ffs[g] = load_group(base + g * PACKED_LANES, &mut states[g]);
        }
        packed_poseidon2b_permute_flat_many(&mut states);
        for g in 0..PERM_INTERLEAVE {
            store_group(base + g * PACKED_LANES, &states[g], ffs[g], out);
        }
    }

    // Remaining full groups, one at a time.
    for chunk in wide_chunks * PERM_INTERLEAVE..chunks {
        let off = chunk * PACKED_LANES;
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let ff = load_group(off, &mut states);
        packed_poseidon2b_permute_flat(&mut states);
        store_group(off, &states, ff, out);
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        scalar(i, out);
    }
}

/// Batched flat-basis leaf-sponge hash of equal-length leaves stored
/// contiguously in `data` (`data.len() = leaf_size · out.len()`). Matches
/// `Poseidon2bFlatSponge::with_tag(tag)` + `update(leaf)` + `finalize()`
/// exactly, running `PACKED_LANES` leaf sponges in lockstep — the absorb
/// schedule is identical across leaves because all leaves share one length.
pub fn leaf_sponge_flat_batch_with_tag_into(
    tag: DomainTag,
    data: &[u8],
    leaf_size: usize,
    out: &mut [[u8; 32]],
) {
    leaf_sponge_flat_batch_with_iv_into(
        crate::native::domain::capacity_iv_flat(tag),
        true,
        data,
        leaf_size,
        out,
    );
}

/// [`leaf_sponge_flat_batch_with_tag_into`] on explicit flat capacity-IV
/// words, optionally in the **no-pad fixed-length** mode (`pad = false`,
/// requires `leaf_size % 32 == 0`): the final permutation of the padded
/// duplex is dropped, matching `Poseidon2bFlatSponge::with_iv_flat` +
/// `update` + `finalize_no_pad`. The caller owns the domain-separation
/// argument for the IV (a distinct tag, fixed length bound in).
pub fn leaf_sponge_flat_batch_with_iv_into(
    iv: [u128; 2],
    pad: bool,
    data: &[u8],
    leaf_size: usize,
    out: &mut [[u8; 32]],
) {
    assert!(leaf_size > 0, "leaf_size must be nonzero");
    assert!(
        pad || leaf_size % 32 == 0,
        "no-pad mode requires whole rate blocks"
    );
    let expected_data_len = leaf_size
        .checked_mul(out.len())
        .expect("leaf_size × leaf count must fit usize");
    assert_eq!(
        data.len(),
        expected_data_len,
        "data length must be leaf_size × leaf count"
    );

    let scalar = |i: usize, out: &mut [[u8; 32]]| {
        let mut sponge = crate::native::Poseidon2bFlatSponge::with_iv_flat(iv);
        sponge.update(&data[i * leaf_size..(i + 1) * leaf_size]);
        out[i] = if pad {
            sponge.finalize()
        } else {
            sponge.finalize_no_pad()
        };
    };

    let n = out.len();
    #[cfg(target_arch = "x86_64")]
    if !pad
        && leaf_size.is_multiple_of(32)
        && n.is_multiple_of(PERM_INTERLEAVE * 4)
        && avx512_vpclmul_runtime()
    {
        // SAFETY: runtime ISA gate and the public shape checks above satisfy
        // the sixteen-leaf AVX-512 kernel contract.
        unsafe {
            crate::batch_avx512::leaf_sponge_flat_no_pad_into(
                iv,
                data,
                leaf_size,
                out,
                kernel_tables(),
            );
        }
        return;
    }
    #[cfg(target_arch = "aarch64")]
    if !pad && n.is_multiple_of(PERM_INTERLEAVE) && pmull_runtime() {
        // SAFETY: runtime/static PMULL gate and the public shape checks above
        // satisfy the specialized kernel contract.
        unsafe {
            crate::batch_aarch64::leaf_sponge_flat_no_pad_into(
                iv,
                data,
                leaf_size,
                out,
                kernel_tables(),
            );
        }
        return;
    }
    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            scalar(i, out);
        }
        return;
    }

    // Production PCS leaves are fixed-length and block-aligned. Keep the
    // complete multi-block sponge chains resident in AVX2 registers instead
    // of crossing the packed-permutation load/store boundary after every
    // block. Eight leaves are exactly four two-lane state groups, the same
    // interleave width as the register-domain permutation kernel.
    #[cfg(target_arch = "x86_64")]
    if !pad
        && leaf_size.is_multiple_of(32)
        && n.is_multiple_of(PERM_INTERLEAVE * PACKED_LANES)
        && avx2_vpclmul_runtime()
    {
        // SAFETY: the runtime ISA gate and public preconditions above prove
        // the specialized kernel's alignment-independent slice contract.
        unsafe {
            crate::batch_avx2::leaf_sponge_flat_no_pad_into(
                iv,
                data,
                leaf_size,
                out,
                kernel_tables(),
            );
        }
        return;
    }

    let [iv_hi, iv_lo] = iv;
    let full_blocks = leaf_size / 32;
    let rem = leaf_size % 32;
    let chunks = n / PACKED_LANES;

    // Absorb the b-th 32-byte block of every lane in one group (leaves start
    // at leaf index `off`).
    let absorb_block = |off: usize, b: usize, states: &mut [PackedBlock128; STATE_SIZE]| {
        let mut w0 = PackedBlock128::ZERO;
        let mut w1 = PackedBlock128::ZERO;
        for lane in 0..PACKED_LANES {
            let base = (off + lane) * leaf_size + b * 32;
            w0 = w0.set_lane(
                lane,
                Block128::from(u128::from_le_bytes(
                    data[base..base + 16].try_into().unwrap(),
                )),
            );
            w1 = w1.set_lane(
                lane,
                Block128::from(u128::from_le_bytes(
                    data[base + 16..base + 32].try_into().unwrap(),
                )),
            );
        }
        states[0] = states[0].xor(w0);
        states[1] = states[1].xor(w1);
    };

    // Absorb the 0x80…01-padded tail block (padded mode only): a pure pad
    // block when the leaf is block-aligned, else the leftover bytes with the
    // pad markers OR'd into the zero-filled remainder. The no-pad mode ends
    // block-aligned and squeezes as-is.
    let absorb_tail = |off: usize, states: &mut [PackedBlock128; STATE_SIZE]| {
        if rem == 0 {
            states[0] = states[0].xor(PackedBlock128::broadcast(Block128::from(PAD0)));
            states[1] = states[1].xor(PackedBlock128::broadcast(Block128::from(PAD1)));
        } else {
            let mut w0 = PackedBlock128::ZERO;
            let mut w1 = PackedBlock128::ZERO;
            for lane in 0..PACKED_LANES {
                let mut tail = [0u8; 32];
                let base = (off + lane) * leaf_size + full_blocks * 32;
                tail[..rem].copy_from_slice(&data[base..base + rem]);
                tail[rem] |= 0x80;
                tail[31] |= 0x01;
                w0 = w0.set_lane(
                    lane,
                    Block128::from(u128::from_le_bytes(tail[..16].try_into().unwrap())),
                );
                w1 = w1.set_lane(
                    lane,
                    Block128::from(u128::from_le_bytes(tail[16..].try_into().unwrap())),
                );
            }
            states[0] = states[0].xor(w0);
            states[1] = states[1].xor(w1);
        }
    };

    let store_group = |off: usize, states: &[PackedBlock128; STATE_SIZE], out: &mut [[u8; 32]]| {
        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    };

    let fresh_states = || {
        [
            PackedBlock128::ZERO,
            PackedBlock128::ZERO,
            PackedBlock128::broadcast(Block128::from(iv_hi)),
            PackedBlock128::broadcast(Block128::from(iv_lo)),
        ]
    };

    // Wide pass: PERM_INTERLEAVE independent groups advance through the
    // absorb schedule in lockstep, so every permutation call carries
    // PERM_INTERLEAVE × PACKED_LANES independent sponges.
    let wide_chunks = chunks / PERM_INTERLEAVE;
    for wchunk in 0..wide_chunks {
        let base = wchunk * PERM_INTERLEAVE * PACKED_LANES;
        let mut states = [fresh_states(); PERM_INTERLEAVE];

        for b in 0..full_blocks {
            for g in 0..PERM_INTERLEAVE {
                absorb_block(base + g * PACKED_LANES, b, &mut states[g]);
            }
            packed_poseidon2b_permute_flat_many(&mut states);
        }
        if pad {
            for g in 0..PERM_INTERLEAVE {
                absorb_tail(base + g * PACKED_LANES, &mut states[g]);
            }
            packed_poseidon2b_permute_flat_many(&mut states);
        }
        for g in 0..PERM_INTERLEAVE {
            store_group(base + g * PACKED_LANES, &states[g], out);
        }
    }

    // Remaining full groups, one at a time.
    for chunk in wide_chunks * PERM_INTERLEAVE..chunks {
        let off = chunk * PACKED_LANES;
        let mut states = fresh_states();
        for b in 0..full_blocks {
            absorb_block(off, b, &mut states);
            packed_poseidon2b_permute_flat(&mut states);
        }
        if pad {
            absorb_tail(off, &mut states);
            packed_poseidon2b_permute_flat(&mut states);
        }
        store_group(off, &states, out);
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        scalar(i, out);
    }
}

/// Packed S-box x → x^7 entirely in flat basis.
///
/// x^2, x^4 use `flat_square` (CLMUL-free bit spread + reduction); the
/// two multiplications use raw CLMUL with no basis conversion.
#[inline(always)]
fn packed_sbox_x7_flat(x: PackedBlock128) -> PackedBlock128 {
    let x2 = x.flat_square();
    let x4 = x2.flat_square();
    let x6 = x.flat_mul(x2);
    x6.flat_mul(x4)
}

#[inline(always)]
fn packed_apply_mds_full_flat(state: &mut [PackedBlock128; STATE_SIZE], tables: &FlatTables) {
    let input = *state;
    for i in 0..STATE_SIZE {
        let mut out = PackedBlock128::ZERO;
        for j in 0..STATE_SIZE {
            // Skip CLMUL when the MDS entry is 1 (identity); XOR the lane
            // directly. On GF(2^128) over flat basis, `a * 1 = a`.
            if tables.mds_full_is_one[i][j] {
                out = out.xor(input[j]);
            } else {
                out = out.xor(input[j].flat_scalar_mul(tables.mds_full[i][j]));
            }
        }
        state[i] = out;
    }
}

#[inline(always)]
fn packed_apply_mds_partial_flat(state: &mut [PackedBlock128; STATE_SIZE], tables: &FlatTables) {
    let input = *state;
    for i in 0..STATE_SIZE {
        let mut out = PackedBlock128::ZERO;
        for j in 0..STATE_SIZE {
            if tables.mds_partial_is_one[i][j] {
                out = out.xor(input[j]);
            } else {
                out = out.xor(input[j].flat_scalar_mul(tables.mds_partial[i][j]));
            }
        }
        state[i] = out;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::CryptographicHasher;
    use crate::native::compression::Poseidon2bSponge;
    use noid_core::TowerField;
    use rand::Rng;

    #[test]
    fn test_hash_pair_batch_matches_scalar() {
        let mut rng = rand::thread_rng();
        let n = 256;
        let a: Vec<Block128> = (0..n).map(|_| Block128::from(rng.gen::<u128>())).collect();
        let b: Vec<Block128> = (0..n).map(|_| Block128::from(rng.gen::<u128>())).collect();

        let sponge = Poseidon2bSponge::new();
        let expected: Vec<[u8; 32]> = (0..n).map(|i| sponge.hash_pair(&a[i], &b[i])).collect();

        let got = hash_pair_batch(&a, &b);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_hash_concatenation_batch_matches_scalar() {
        let mut rng = rand::thread_rng();
        let n = 256;
        let a: Vec<[u8; 32]> = (0..n).map(|_| rng.gen()).collect();
        let b: Vec<[u8; 32]> = (0..n).map(|_| rng.gen()).collect();

        let sponge = Poseidon2bSponge::new();
        let expected: Vec<[u8; 32]> = (0..n)
            .map(|i| sponge.hash_concatenation(&a[i], &b[i]))
            .collect();

        let got = hash_concatenation_batch(&a, &b);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_hash_pair_batch_small_input() {
        let sponge = Poseidon2bSponge::new();
        let a = vec![Block128::ONE, Block128::ZERO];
        let b = vec![Block128::ZERO, Block128::ONE];
        let expected = vec![
            sponge.hash_pair(&Block128::ONE, &Block128::ZERO),
            sponge.hash_pair(&Block128::ZERO, &Block128::ONE),
        ];
        let got = hash_pair_batch(&a, &b);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_hash_concatenation_batch_small_input() {
        let sponge = Poseidon2bSponge::new();
        let a = vec![[1u8; 32], [2u8; 32]];
        let b = vec![[3u8; 32], [4u8; 32]];
        let expected = vec![
            sponge.hash_concatenation(&a[0], &b[0]),
            sponge.hash_concatenation(&a[1], &b[1]),
        ];
        let got = hash_concatenation_batch(&a, &b);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_hash_concatenation_batch_interleaved_matches_scalar() {
        let mut rng = rand::thread_rng();
        let n = 256;
        let a: Vec<[u8; 32]> = (0..n).map(|_| rng.gen()).collect();
        let b: Vec<[u8; 32]> = (0..n).map(|_| rng.gen()).collect();

        let sponge = Poseidon2bSponge::new();
        let expected: Vec<[u8; 32]> = (0..n)
            .map(|i| sponge.hash_concatenation(&a[i], &b[i]))
            .collect();

        let mut interleaved = Vec::with_capacity(n * 2);
        for i in 0..n {
            interleaved.push(a[i]);
            interleaved.push(b[i]);
        }
        let got = hash_concatenation_batch_interleaved(&interleaved);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_hash_concatenation_batch_interleaved_small_input() {
        let sponge = Poseidon2bSponge::new();
        let interleaved = vec![[1u8; 32], [3u8; 32], [2u8; 32], [4u8; 32]];
        let expected = vec![
            sponge.hash_concatenation(&interleaved[0], &interleaved[1]),
            sponge.hash_concatenation(&interleaved[2], &interleaved[3]),
        ];
        let got = hash_concatenation_batch_interleaved(&interleaved);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_compress_batch_interleaved_with_tag_matches_scalar() {
        use crate::native::DomainTag;

        let mut rng = rand::thread_rng();
        let tag = DomainTag::new(b"BTCHTST_");
        let n = 257;
        let mut interleaved = Vec::with_capacity(n * 2);
        for _ in 0..(n * 2) {
            interleaved.push(rng.gen::<[u8; 32]>());
        }

        let mut got = vec![[0u8; 32]; n];
        compress_batch_interleaved_with_tag_into(tag, &interleaved, &mut got);
        let expected: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                crate::native::compress_with_tag(tag, &interleaved[2 * i], &interleaved[2 * i + 1])
            })
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn test_compress_flat_ff_batch_matches_scalar() {
        use crate::native::DomainTag;

        let mut rng = rand::thread_rng();
        let tag = DomainTag::new(b"FFTBTST_");
        // 257 exercises both the packed chunks and the scalar remainder.
        let n = 257;
        let mut interleaved = Vec::with_capacity(n * 2);
        for _ in 0..(n * 2) {
            interleaved.push(rng.gen::<[u8; 32]>());
        }

        let mut got = vec![[0u8; 32]; n];
        compress_flat_ff_batch_interleaved_with_tag_into(tag, &interleaved, &mut got);
        let expected: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                crate::native::compress_flat_feed_forward_with_tag(
                    tag,
                    &interleaved[2 * i],
                    &interleaved[2 * i + 1],
                )
            })
            .collect();
        assert_eq!(got, expected);
    }

    /// Batched leaf sponge vs the scalar `Poseidon2bFlatSponge` oracle across
    /// leaf sizes hitting every tail shape: block-aligned, 16-byte-aligned,
    /// rem ∈ {1, 15, 31} (31 makes both pad markers share one byte), and a
    /// leaf count exercising packed chunks plus a scalar remainder.
    #[test]
    fn test_leaf_sponge_flat_batch_matches_scalar() {
        use crate::native::{DomainTag, Poseidon2bFlatSponge};

        let mut rng = rand::thread_rng();
        let tag = DomainTag::new(b"LEAFTST_");
        for &(n, leaf_size) in &[
            (257usize, 64usize),
            (64, 512),
            (33, 48),
            (17, 33),
            (9, 31),
            (16, 63),
            (8, 1),
            (3, 16), // below PACKED_LANES on typical builds → scalar fallback
        ] {
            let mut data = vec![0u8; n * leaf_size];
            rng.fill(&mut data[..]);

            let mut got = vec![[0u8; 32]; n];
            leaf_sponge_flat_batch_with_tag_into(tag, &data, leaf_size, &mut got);

            let expected: Vec<[u8; 32]> = (0..n)
                .map(|i| {
                    let mut sponge = Poseidon2bFlatSponge::with_tag(tag);
                    sponge.update(&data[i * leaf_size..(i + 1) * leaf_size]);
                    sponge.finalize()
                })
                .collect();
            assert_eq!(got, expected, "n={n} leaf_size={leaf_size}");
        }
    }

    /// No-pad fixed-length mode vs the scalar `finalize_no_pad` oracle on a
    /// caller-supplied (length-bound) IV, across block-aligned sizes and a
    /// scalar remainder.
    #[test]
    fn test_leaf_sponge_flat_batch_no_pad_matches_scalar() {
        use crate::native::domain::{capacity_iv_flat, DomainTag};
        use crate::native::Poseidon2bFlatSponge;

        let mut rng = rand::thread_rng();
        let tag = DomainTag::new(b"LEAFFIX_");
        for &(n, leaf_size) in &[(257usize, 64usize), (64, 512), (9, 32), (3, 32)] {
            let [hi, lo] = capacity_iv_flat(tag);
            let iv = [hi ^ leaf_size as u128, lo];
            let mut data = vec![0u8; n * leaf_size];
            rng.fill(&mut data[..]);

            let mut got = vec![[0u8; 32]; n];
            leaf_sponge_flat_batch_with_iv_into(iv, false, &data, leaf_size, &mut got);

            let expected: Vec<[u8; 32]> = (0..n)
                .map(|i| {
                    let mut sponge = Poseidon2bFlatSponge::with_iv_flat(iv);
                    sponge.update(&data[i * leaf_size..(i + 1) * leaf_size]);
                    sponge.finalize_no_pad()
                })
                .collect();
            assert_eq!(got, expected, "n={n} leaf_size={leaf_size}");
        }
    }

    #[test]
    fn fixed_field_nonce_batch_matches_tower_sponge() {
        use crate::native::domain::DomainTag;

        let tag = DomainTag::new(b"NONCETST");
        let nonce_index = 10usize;
        let start_nonce = 0x0123_4567_89ab_cdefu128;
        let fields: [Block128; 16] =
            std::array::from_fn(|index| Block128::from((index as u128 + 1) * 0x0101_0101));

        let mut prepared = FixedFieldNonceBatch::new(tag, &fields, nonce_index);
        for count in [257usize, 1, 16, 3, 8] {
            let mut got = vec![[0u8; 32]; count];
            prepared.hash_into(start_nonce, &mut got);

            let expected: Vec<[u8; 32]> = (0..count)
                .map(|index| {
                    let mut scalar_fields = fields;
                    scalar_fields[nonce_index] =
                        Block128::from(start_nonce.saturating_add(index as u128));
                    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(tag));
                    for pair in scalar_fields.chunks_exact(2) {
                        sponge.absorb_pair(pair[0], pair[1]);
                    }
                    sponge.finalize_no_pad()
                })
                .collect();
            assert_eq!(got, expected, "count={count}");
        }
    }

    #[test]
    #[should_panic(expected = "leaf_size × leaf count must fit usize")]
    fn leaf_sponge_batch_rejects_length_product_overflow_before_unsafe_dispatch() {
        let mut out = [[0u8; 32]; 2];
        leaf_sponge_flat_batch_with_iv_into(
            [0u128; 2],
            false,
            &[],
            1usize << (usize::BITS - 1),
            &mut out,
        );
    }
}
