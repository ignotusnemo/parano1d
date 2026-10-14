// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! Register-domain Poseidon2b kernel for AArch64 PMULL.
//!
//! NEON vectors are 128 bits wide, exactly one field element.  The kernel
//! therefore interleaves four independent permutations in registers instead
//! of changing the logical packed layout.  All carry-less products stay
//! behind one `aes`/PMULL target-feature boundary for the complete schedule.

#![cfg(target_arch = "aarch64")]

use crate::batch::KernelTables;
use crate::native::permutation::{F_ROUNDS, N_ROUNDS, P_ROUNDS, STATE_SIZE};
use noid_core::hardware::clmul_gcm_pmull;
use noid_core::packed::PackedBlock128;
use noid_core::Block128;

#[inline]
#[target_feature(enable = "aes")]
unsafe fn mul(a: u128, b: u128) -> u128 {
    // SAFETY: inherited PMULL target feature.
    unsafe { clmul_gcm_pmull(a, b) }
}

#[inline]
#[target_feature(enable = "aes")]
unsafe fn sbox_x7(x: u128) -> u128 {
    unsafe {
        let x2 = mul(x, x);
        let x4 = mul(x2, x2);
        let x6 = mul(x, x2);
        mul(x6, x4)
    }
}

#[inline]
#[target_feature(enable = "aes")]
unsafe fn mds_full(s: &mut [u128; STATE_SIZE], t: &KernelTables) {
    unsafe {
        let [a, b, c, d] = *s;
        let a4 = mul(a, t.mds_full_four);
        let b2 = mul(b, t.mds_full_two);
        let b4 = mul(b, t.mds_full_four);
        let c4 = mul(c, t.mds_full_four);
        let d2 = mul(d, t.mds_full_two);
        let d4 = mul(d, t.mds_full_four);

        s[0] = (a4 ^ a) ^ (b4 ^ b2) ^ (b ^ c) ^ (d2 ^ d);
        s[1] = a4 ^ (b4 ^ b2) ^ c ^ d;
        s[2] = a ^ (b2 ^ b) ^ (c4 ^ c) ^ (d4 ^ d2 ^ d);
        s[3] = a ^ b ^ c4 ^ d4 ^ d2;
    }
}

#[inline]
#[target_feature(enable = "aes")]
unsafe fn mds_partial(s: &mut [u128; STATE_SIZE], t: &KernelTables) {
    let sum = s[0] ^ s[1] ^ s[2] ^ s[3];
    for i in 0..STATE_SIZE {
        // SAFETY: inherited PMULL target feature.
        let diagonal = unsafe { mul(s[i], t.mds_partial_diag[i]) };
        s[i] ^= diagonal ^ sum;
    }
}

#[inline]
#[target_feature(enable = "aes")]
unsafe fn permute_groups<const G: usize>(states: &mut [[u128; STATE_SIZE]; G], t: &KernelTables) {
    unsafe {
        for state in states.iter_mut() {
            mds_full(state, t);
        }
        for r in 0..N_ROUNDS {
            let full = !((F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&r));
            if full {
                for state in states.iter_mut() {
                    for (i, word) in state.iter_mut().enumerate() {
                        *word = sbox_x7(*word ^ t.rc[i][r]);
                    }
                }
                for state in states.iter_mut() {
                    mds_full(state, t);
                }
            } else {
                for state in states.iter_mut() {
                    state[0] = sbox_x7(state[0] ^ t.rc[0][r]);
                }
                for state in states.iter_mut() {
                    mds_partial(state, t);
                }
            }
        }
    }
}

#[inline]
fn load_group(state: &[PackedBlock128; STATE_SIZE]) -> [u128; STATE_SIZE] {
    std::array::from_fn(|i| state[i].get_lane(0).to_u128())
}

#[inline]
fn store_group(words: [u128; STATE_SIZE], state: &mut [PackedBlock128; STATE_SIZE]) {
    for i in 0..STATE_SIZE {
        state[i] = state[i].set_lane(0, Block128::from(words[i]));
    }
}

#[target_feature(enable = "aes")]
pub(crate) unsafe fn permute_flat_groups(
    states: &mut [[PackedBlock128; STATE_SIZE]],
    tables: &KernelTables,
) {
    const GROUPS: usize = 4;
    unsafe {
        let mut chunks = states.chunks_exact_mut(GROUPS);
        for chunk in &mut chunks {
            let mut words: [[u128; STATE_SIZE]; GROUPS] =
                std::array::from_fn(|i| load_group(&chunk[i]));
            permute_groups(&mut words, tables);
            for i in 0..GROUPS {
                store_group(words[i], &mut chunk[i]);
            }
        }
        for state in chunks.into_remainder() {
            let mut words = [load_group(state)];
            permute_groups(&mut words, tables);
            store_group(words[0], state);
        }
    }
}

#[target_feature(enable = "aes")]
pub(crate) unsafe fn permute_flat_one(
    state: &mut [PackedBlock128; STATE_SIZE],
    tables: &KernelTables,
) {
    unsafe {
        let mut words = [load_group(state)];
        permute_groups(&mut words, tables);
        store_group(words[0], state);
    }
}

#[target_feature(enable = "aes")]
pub(crate) unsafe fn permute_flat_single_u128(
    state: &mut [u128; STATE_SIZE],
    tables: &KernelTables,
) {
    unsafe {
        let mut words = [*state];
        permute_groups(&mut words, tables);
        *state = words[0];
    }
}

#[target_feature(enable = "aes")]
pub(crate) unsafe fn leaf_sponge_flat_no_pad_into(
    iv: [u128; 2],
    data: &[u8],
    leaf_size: usize,
    out: &mut [[u8; 32]],
    tables: &KernelTables,
) {
    const GROUPS: usize = 4;
    debug_assert!(leaf_size > 0 && leaf_size.is_multiple_of(32));
    debug_assert_eq!(data.len(), leaf_size * out.len());
    debug_assert!(out.len().is_multiple_of(GROUPS));

    unsafe {
        for leaf_base in (0..out.len()).step_by(GROUPS) {
            let mut states = [[0, 0, iv[0], iv[1]]; GROUPS];
            for block in (0..leaf_size).step_by(32) {
                for (group, state) in states.iter_mut().enumerate() {
                    let base = (leaf_base + group) * leaf_size + block;
                    state[0] ^= u128::from_le_bytes(data[base..base + 16].try_into().unwrap());
                    state[1] ^= u128::from_le_bytes(data[base + 16..base + 32].try_into().unwrap());
                }
                permute_groups(&mut states, tables);
            }
            for (group, state) in states.iter().enumerate() {
                out[leaf_base + group][..16].copy_from_slice(&state[0].to_le_bytes());
                out[leaf_base + group][16..].copy_from_slice(&state[1].to_le_bytes());
            }
        }
    }
}
