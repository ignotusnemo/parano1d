// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `CryptographicHasher` implementation backed by Poseidon2b.

use crate::compression::Poseidon2bSponge;
use crate::hasher::{CryptographicHasher, HashOutput};
use crate::native::permutation::Poseidon2bPermutation;
use noid_core::{Block128, CanonicalSerialize, TowerField};

impl CryptographicHasher for Poseidon2bSponge {
    // Fixed-width encoding: one permutation of `[a, b, 0, 0]`, followed
    // by serialization of the first two field elements as a 32-byte digest.
    // Generic FRI helpers and raw-state source commitments use this layout.
    // Authorization capsules hash leaves with dedicated tagged sponges.
    fn hash_pair(&self, a: &Block128, b: &Block128) -> HashOutput {
        let mut state = [*a, *b, Block128::ZERO, Block128::ZERO];
        Poseidon2bPermutation.permute_mut(&mut state);
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&state[0].to_bytes());
        out[16..].copy_from_slice(&state[1].to_bytes());
        out
    }

    fn hash_field(&self, _elem: &Block128) -> HashOutput {
        let mut sponge = Poseidon2bSponge::new();
        sponge.absorb(*_elem);
        sponge.finalize()
    }

    fn hash_concatenation(&self, a: &HashOutput, b: &HashOutput) -> HashOutput {
        let mut sponge = Poseidon2bSponge::new();
        sponge.update(a);
        sponge.update(b);
        sponge.finalize()
    }

    fn compress(&self, a: &HashOutput, b: &HashOutput) -> HashOutput {
        crate::native::compress(a, b)
    }

    fn batch_hash_pair(&self, pairs: &[Block128], out: &mut [HashOutput]) {
        crate::batch::hash_pair_batch_interleaved_into(pairs, out);
    }

    fn batch_compress(&self, pairs: &[HashOutput], out: &mut [HashOutput]) {
        crate::batch::compress_batch_interleaved_into(pairs, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::TowerField;

    #[test]
    fn test_hasher_pair() {
        let sponge = Poseidon2bSponge::new();
        let h1 = sponge.hash_pair(&Block128::ONE, &Block128::ZERO);
        let h2 = sponge.hash_pair(&Block128::ONE, &Block128::ZERO);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hasher_concatenation() {
        let sponge = Poseidon2bSponge::new();
        let a = [1u8; 32];
        let b = [2u8; 32];
        let h1 = sponge.hash_concatenation(&a, &b);
        let h2 = sponge.hash_concatenation(&a, &b);
        assert_eq!(h1, h2);
    }
}
