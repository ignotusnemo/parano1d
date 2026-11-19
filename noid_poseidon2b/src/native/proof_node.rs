// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Versioned flat-basis Merkle compression for proof commitments.
//!
//! The version belongs to the authenticated proof profile. Address derivation,
//! exact-state hashing and historical profiles keep their existing definitions.

use super::{
    capacity_iv_flat, compress_flat_feed_forward_with_tag, DomainTag, Poseidon2bFlatSponge,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofNodeHashVersion {
    #[default]
    FeedForward = 0,
    FixedCapacity = 1,
}

impl ProofNodeHashVersion {
    pub const fn permutations_per_node(self) -> usize {
        match self {
            Self::FeedForward => 1,
            Self::FixedCapacity => 2,
        }
    }

    /// Fixed-width 64-byte input, interpreted as four flat-basis field lanes.
    /// The fixed-capacity mode absorbs the left and right halves in successive
    /// rate blocks. Its caller must authenticate the mode as part of the profile.
    #[inline]
    pub fn compress(self, tag: DomainTag, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        match self {
            Self::FeedForward => compress_flat_feed_forward_with_tag(tag, left, right),
            Self::FixedCapacity => {
                let mut sponge = Poseidon2bFlatSponge::with_tag(tag);
                sponge.update(left);
                sponge.update(right);
                sponge.finalize_no_pad()
            }
        }
    }

    /// Batched equivalent of [`Self::compress`], including scalar tails.
    pub fn batch_compress(self, tag: DomainTag, pairs: &[[u8; 32]], out: &mut [[u8; 32]]) {
        assert_eq!(pairs.len(), 2 * out.len(), "proof-node pair count");
        match self {
            Self::FeedForward => {
                crate::batch::compress_flat_ff_batch_interleaved_with_tag_into(tag, pairs, out)
            }
            Self::FixedCapacity if !out.is_empty() => {
                crate::batch::leaf_sponge_flat_batch_with_iv_into(
                    capacity_iv_flat(tag),
                    false,
                    pairs.as_flattened(),
                    64,
                    out,
                );
            }
            Self::FixedCapacity => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::domain::TAG_CAPSNODE;
    use super::*;
    use noid_core::hardware::{flat_to_tower_u128, tower_to_flat_u128};

    fn digest(text: &str) -> [u8; 32] {
        hex::decode(text).unwrap().try_into().unwrap()
    }

    #[test]
    fn reproduced_feed_forward_collision_separates_under_fixed_capacity() {
        let left_a = digest("50b69c6c8383747a09aa97c1c2c686518945e8a5932c40b733ff8d098aef8aaa");
        let left_b = digest("392ffcde45295696135190d31588849f7a3426ac737814acbc7283f68767043c");
        let iv = capacity_iv_flat(TAG_CAPSNODE);
        let mut right = [0u8; 32];
        right[..16].copy_from_slice(&iv[0].to_le_bytes());
        right[16..].copy_from_slice(&iv[1].to_le_bytes());
        assert_ne!(left_a, left_b);
        assert_eq!(
            ProofNodeHashVersion::FeedForward.compress(TAG_CAPSNODE, &left_a, &right),
            ProofNodeHashVersion::FeedForward.compress(TAG_CAPSNODE, &left_b, &right),
        );
        assert_ne!(
            ProofNodeHashVersion::FixedCapacity.compress(TAG_CAPSNODE, &left_a, &right),
            ProofNodeHashVersion::FixedCapacity.compress(TAG_CAPSNODE, &left_b, &right),
        );
    }

    #[test]
    fn fixed_capacity_batch_matches_scalar_across_kernel_and_tail_sizes() {
        let tag = TAG_CAPSNODE;
        for count in [0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 65] {
            let pairs: Vec<_> = (0..2 * count)
                .map(|index| {
                    std::array::from_fn(|byte| {
                        ((index * 37 + byte * 19 + index * byte) & 255) as u8
                    })
                })
                .collect();
            for version in [
                ProofNodeHashVersion::FeedForward,
                ProofNodeHashVersion::FixedCapacity,
            ] {
                let mut out = vec![[0u8; 32]; count];
                version.batch_compress(tag, &pairs, &mut out);
                for (index, hash) in out.iter().enumerate() {
                    assert_eq!(
                        *hash,
                        version.compress(tag, &pairs[2 * index], &pairs[2 * index + 1])
                    );
                }
            }
        }
    }

    #[test]
    fn fixed_capacity_matches_existing_tower_sponge_after_basis_conversion() {
        let left = std::array::from_fn(|index| (3 * index + 1) as u8);
        let right = std::array::from_fn(|index| (5 * index + 7) as u8);
        let map_digest = |digest: [u8; 32], map: fn(u128) -> u128| {
            let mut out = [0u8; 32];
            for lane in 0..2 {
                let value =
                    u128::from_le_bytes(digest[16 * lane..16 * lane + 16].try_into().unwrap());
                out[16 * lane..16 * lane + 16].copy_from_slice(&map(value).to_le_bytes());
            }
            out
        };
        let tower_left = map_digest(left, flat_to_tower_u128);
        let tower_right = map_digest(right, flat_to_tower_u128);
        let tower_hash = super::super::compress_with_tag(TAG_CAPSNODE, &tower_left, &tower_right);
        assert_eq!(
            ProofNodeHashVersion::FixedCapacity.compress(TAG_CAPSNODE, &left, &right),
            map_digest(tower_hash, tower_to_flat_u128),
        );
    }
}
