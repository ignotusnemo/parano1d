// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Versioned proof-node paths using the existing feed-forward and sponge walks.

use super::ff_merkle::{FfMerklePathFamily, build_ff_merkle_path_columns};
use super::schedule::{
    MerklePathColumns, MerklePathFamily, MerklePathWitness, build_merkle_path_columns,
};
use crate::field::F128;
use noid_poseidon2b::native::ProofNodeHashVersion;

#[derive(Clone, Copy, Debug)]
pub struct ProofNodePathFamily {
    pub depth: usize,
    pub n_paths: usize,
    pub hash_version: ProofNodeHashVersion,
}

impl ProofNodePathFamily {
    pub fn stride(self) -> usize {
        (self.depth * self.hash_version.permutations_per_node()).next_power_of_two()
    }

    /// Slot containing the final permutation output of one node.
    pub fn output_slot(self, path: usize, node: usize) -> usize {
        path * self.stride() + (node + 1) * self.hash_version.permutations_per_node() - 1
    }
}

/// The first two columns carry CR in the historical walk and E in the
/// fixed-capacity walk. Their binding is selected by the authenticated family.
pub fn build_proof_node_path_columns(
    family: ProofNodePathFamily,
    iv: [F128; 2],
    paths: &[MerklePathWitness],
    w_log: usize,
) -> MerklePathColumns {
    match family.hash_version {
        ProofNodeHashVersion::FeedForward => {
            let columns = build_ff_merkle_path_columns(
                &FfMerklePathFamily {
                    depth: family.depth,
                    n_paths: family.n_paths,
                },
                iv,
                paths,
                w_log,
            );
            MerklePathColumns {
                e: columns.cr,
                sib: columns.sib,
                d: columns.d,
                c: columns.c,
                s0: columns.s0,
                s_out: columns.s_out,
                roots: columns.roots,
            }
        }
        ProofNodeHashVersion::FixedCapacity => build_merkle_path_columns(
            &MerklePathFamily {
                depth: family.depth,
                n_paths: family.n_paths,
            },
            iv,
            paths,
            w_log,
        ),
    }
}
