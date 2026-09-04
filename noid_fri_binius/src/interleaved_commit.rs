// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Interleaved column commitments and Merkle helpers.
//!
//! All columns are bound into a single compact cap (2^5 = 32 hashes). The
//! cap and source-binding Merkle nodes use the caller's field-friendly hasher.

use noid_core::{AdditiveNTT, Block128};
use noid_fri::code::{Code, LOG_RATE, RATE};
use noid_fri::hasher::{CryptographicHasher, HashOutput};
use rayon::prelude::*;

use crate::MERKLE_CAP_DEPTH;

/// Top levels of the commitment kept as a compact binding.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MerkleCap {
    pub hashes: Vec<HashOutput>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CommitmentHashBackend {
    Arithmetic = 1,
}

pub type SourceHash = [u8; 32];

const SOURCE_HASH_BYTES: usize = 32;
const SOURCE_MERKLE_CHUNK_LOG: usize = 8;
const SOURCE_MERKLE_CHUNK_LEAVES: usize = 1 << SOURCE_MERKLE_CHUNK_LOG;
const SOURCE_MERKLE_FULL_TREE_MAX_DEPTH: usize = 18;
const SOURCE_CAP_DEPTH: usize = MERKLE_CAP_DEPTH;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SourceBatchedMerkleProof {
    pub siblings: Vec<SourceHash>,
}

/// One source query's independent Merkle path, expanded from a deduplicated
/// batched proof. Siblings are ordered bottom to top.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndependentSourceMerklePath {
    pub leaf_index: usize,
    pub leaf_hash: SourceHash,
    /// One sibling digest per level between the leaf and the selected cap.
    pub siblings: Vec<SourceHash>,
    /// `directions[d]` is true when the path node is the right child.
    pub directions: Vec<bool>,
}

/// One canonical missing-sibling position in a batched path to a Merkle cap.
/// `depth_from_root == depth` denotes the leaf layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceMerkleSiblingPosition {
    pub depth_from_root: usize,
    pub index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceHashMerkleTree {
    nodes: Vec<SourceHash>,
    layer_offsets: Vec<usize>,
    layer_lens: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceMerkleTree {
    Full(SourceHashMerkleTree),
    Chunked {
        full_depth: usize,
        chunk_log: usize,
        upper_tree: SourceHashMerkleTree,
    },
}

impl SourceMerkleTree {
    pub(crate) fn new(
        encoded_cols: &[Vec<Block128>],
        log_rows: usize,
        n_cols: usize,
        backend: CommitmentHashBackend,
        hasher: &dyn CryptographicHasher,
    ) -> Self {
        let full_depth = source_tree_depth(log_rows);
        if full_depth <= SOURCE_MERKLE_FULL_TREE_MAX_DEPTH {
            return Self::Full(SourceHashMerkleTree::new(
                build_source_leaf_hashes(encoded_cols, log_rows, n_cols, backend, hasher),
                backend,
                hasher,
            ));
        }

        let chunk_log = SOURCE_MERKLE_CHUNK_LOG.min(full_depth);
        let upper_depth = full_depth - chunk_log;
        let chunk_count = 1usize << upper_depth;
        let chunk_roots: Vec<SourceHash> = (0..chunk_count)
            .into_par_iter()
            .with_min_len(16)
            .map(|chunk_idx| {
                build_source_chunk_root(
                    encoded_cols,
                    log_rows,
                    n_cols,
                    chunk_log,
                    chunk_idx,
                    backend,
                    hasher,
                )
            })
            .collect();
        Self::Chunked {
            full_depth,
            chunk_log,
            upper_tree: SourceHashMerkleTree::new(chunk_roots, backend, hasher),
        }
    }

    pub(crate) fn get_cap(&self, cap_depth: usize) -> Vec<SourceHash> {
        match self {
            Self::Full(tree) => tree.get_layer_at_depth(cap_depth),
            Self::Chunked {
                full_depth,
                chunk_log,
                upper_tree,
            } => {
                let upper_depth = full_depth - chunk_log;
                assert!(
                    cap_depth <= upper_depth,
                    "source cap must stay inside chunked upper tree"
                );
                upper_tree.get_layer_at_depth(cap_depth)
            }
        }
    }
}

impl SourceHashMerkleTree {
    pub(crate) fn new(
        leaf_hashes: Vec<SourceHash>,
        backend: CommitmentHashBackend,
        hasher: &dyn CryptographicHasher,
    ) -> Self {
        let n = leaf_hashes.len();
        assert!(
            n.is_power_of_two(),
            "source Merkle leaves must be a power of two"
        );
        let tree_depth = n.trailing_zeros() as usize;
        let total = 2 * n - 1;
        let mut nodes = leaf_hashes;
        nodes.reserve_exact(total - n);
        nodes.resize(total, [0u8; SOURCE_HASH_BYTES]);

        let mut level_start = 0usize;
        let mut level_len = n;
        while level_len > 1 {
            let next_start = level_start + level_len;
            let next_len = level_len / 2;
            let (prefix, suffix) = nodes.split_at_mut(next_start);
            let current = &prefix[level_start..level_start + level_len];
            let next = &mut suffix[..next_len];
            if next_len >= 1024 {
                next.par_iter_mut().enumerate().for_each(|(i, out)| {
                    *out = source_compress(backend, &current[2 * i], &current[2 * i + 1], hasher);
                });
            } else {
                for i in 0..next_len {
                    next[i] =
                        source_compress(backend, &current[2 * i], &current[2 * i + 1], hasher);
                }
            }
            level_start = next_start;
            level_len = next_len;
        }

        let mut layer_offsets = Vec::with_capacity(tree_depth + 1);
        let mut layer_lens = Vec::with_capacity(tree_depth + 1);
        let mut bottom_up_offsets = Vec::with_capacity(tree_depth + 1);
        let mut bottom_up_lens = Vec::with_capacity(tree_depth + 1);
        let mut off = 0usize;
        let mut len = n;
        loop {
            bottom_up_offsets.push(off);
            bottom_up_lens.push(len);
            if len == 1 {
                break;
            }
            off += len;
            len /= 2;
        }
        for i in (0..bottom_up_offsets.len()).rev() {
            layer_offsets.push(bottom_up_offsets[i]);
            layer_lens.push(bottom_up_lens[i]);
        }

        Self {
            nodes,
            layer_offsets,
            layer_lens,
        }
    }

    pub(crate) fn get_node_at_depth(&self, depth: usize, index: usize) -> SourceHash {
        assert!(depth < self.layer_offsets.len());
        assert!(index < self.layer_lens[depth]);
        self.nodes[self.layer_offsets[depth] + index]
    }

    pub(crate) fn get_layer_at_depth(&self, depth: usize) -> Vec<SourceHash> {
        assert!(depth < self.layer_offsets.len());
        let offset = self.layer_offsets[depth];
        let len = self.layer_lens[depth];
        self.nodes[offset..offset + len].to_vec()
    }
}

pub(crate) fn source_hash_to_output(h: SourceHash) -> HashOutput {
    h
}

pub(crate) fn source_compress(
    _backend: CommitmentHashBackend,
    left: &SourceHash,
    right: &SourceHash,
    hasher: &dyn CryptographicHasher,
) -> SourceHash {
    hasher.compress(left, right)
}

/// Canonical sibling schedule shared by native builders, recursive geometry,
/// and security-model differentials.
pub fn canonical_source_batched_merkle_sibling_positions(
    depth: usize,
    cap_depth: usize,
    leaf_indices: &[usize],
) -> Result<Vec<SourceMerkleSiblingPosition>, String> {
    if cap_depth > depth {
        return Err("source cap depth exceeds tree depth".into());
    }
    let leaf_bound = 1usize
        .checked_shl(depth as u32)
        .ok_or_else(|| "source tree depth exceeds usize".to_string())?;
    if let Some(&index) = leaf_indices.iter().find(|&&index| index >= leaf_bound) {
        return Err(format!("source leaf index {index} out of range"));
    }

    let mut positions = Vec::new();
    let mut known = sorted_unique_usize(leaf_indices);
    for d in 0..(depth - cap_depth) {
        let parents = sorted_unique_parents(&known);
        let mut next = Vec::with_capacity(parents.len());
        for &parent in &parents {
            let left_child = parent * 2;
            let right_child = parent * 2 + 1;
            let left_known = known.binary_search(&left_child).is_ok();
            let right_known = known.binary_search(&right_child).is_ok();
            if left_known && right_known {
            } else if left_known {
                positions.push(SourceMerkleSiblingPosition {
                    depth_from_root: depth - d,
                    index: right_child,
                });
            } else if right_known {
                positions.push(SourceMerkleSiblingPosition {
                    depth_from_root: depth - d,
                    index: left_child,
                });
            }
            if left_known || right_known {
                next.push(parent);
            }
        }
        known = next;
    }
    Ok(positions)
}

fn build_source_batched_merkle_proof_with_getter_to_cap<F>(
    depth: usize,
    cap_depth: usize,
    leaf_indices: &[usize],
    mut get_node_at_depth: F,
) -> SourceBatchedMerkleProof
where
    F: FnMut(usize, usize) -> SourceHash,
{
    let positions =
        canonical_source_batched_merkle_sibling_positions(depth, cap_depth, leaf_indices)
            .expect("internal source Merkle opening shape");
    let siblings = positions
        .into_iter()
        .map(|position| get_node_at_depth(position.depth_from_root, position.index))
        .collect();
    SourceBatchedMerkleProof { siblings }
}

pub(crate) fn build_source_batched_merkle_proof_to_cap(
    tree: &SourceHashMerkleTree,
    leaf_indices: &[usize],
    depth: usize,
    cap_depth: usize,
    backend: CommitmentHashBackend,
    hasher: &dyn CryptographicHasher,
) -> SourceBatchedMerkleProof {
    let _ = (backend, hasher);
    build_source_batched_merkle_proof_with_getter_to_cap(
        depth,
        cap_depth,
        leaf_indices,
        |node_depth, node_index| tree.get_node_at_depth(node_depth, node_index),
    )
}

pub(crate) fn verify_source_batched_merkle_proof_to_cap(
    cap_nodes: &[SourceHash],
    cap_depth: usize,
    batch: &SourceBatchedMerkleProof,
    depth: usize,
    leaf_indices: &[usize],
    leaf_hashes: &[SourceHash],
    backend: CommitmentHashBackend,
    hasher: &dyn CryptographicHasher,
) -> Result<(), String> {
    if cap_depth > depth {
        return Err("source cap depth exceeds tree depth".into());
    }
    if cap_nodes.len() != (1usize << cap_depth) {
        return Err("source cap width mismatch".into());
    }
    if leaf_indices.len() != leaf_hashes.len() {
        return Err("source leaf index/hash count mismatch".into());
    }
    let (mut known_indices, mut known_hashes) =
        sorted_unique_source_leaf_hashes(leaf_indices, leaf_hashes)
            .map_err(|idx| format!("inconsistent source leaf hashes for index {idx}"))?;

    let mut sib_cursor = 0usize;
    for d in 0..(depth - cap_depth) {
        let mut next_indices = Vec::new();
        let mut next_hashes = Vec::new();
        let mut cursor = 0usize;
        while cursor < known_indices.len() {
            let parent = known_indices[cursor] >> 1;
            let left_child = parent * 2;
            let right_child = left_child + 1;
            let mut left = None;
            let mut right = None;
            while cursor < known_indices.len() && (known_indices[cursor] >> 1) == parent {
                let idx = known_indices[cursor];
                if idx == left_child {
                    left = Some(known_hashes[cursor]);
                } else if idx == right_child {
                    right = Some(known_hashes[cursor]);
                } else {
                    return Err(format!("source bad child index {idx} at layer {d}"));
                }
                cursor += 1;
            }
            let parent_hash = match (left, right) {
                (Some(l), Some(r)) => source_compress(backend, &l, &r, hasher),
                (Some(l), None) => {
                    if sib_cursor >= batch.siblings.len() {
                        return Err(format!("insufficient source siblings at layer {d}"));
                    }
                    let r = batch.siblings[sib_cursor];
                    sib_cursor += 1;
                    source_compress(backend, &l, &r, hasher)
                }
                (None, Some(r)) => {
                    if sib_cursor >= batch.siblings.len() {
                        return Err(format!("insufficient source siblings at layer {d}"));
                    }
                    let l = batch.siblings[sib_cursor];
                    sib_cursor += 1;
                    source_compress(backend, &l, &r, hasher)
                }
                (None, None) => return Err(format!("source orphan parent at layer {d}")),
            };
            next_indices.push(parent);
            next_hashes.push(parent_hash);
        }
        known_indices = next_indices;
        known_hashes = next_hashes;
    }
    for (idx, hash) in known_indices.iter().zip(known_hashes.iter()) {
        if *idx >= cap_nodes.len() {
            return Err("source cap node index out of range".into());
        }
        if hash != &cap_nodes[*idx] {
            return Err("source batched Merkle cap mismatch".into());
        }
    }
    if sib_cursor != batch.siblings.len() {
        return Err(format!(
            "unused source siblings: consumed {sib_cursor}, total {}",
            batch.siblings.len()
        ));
    }
    Ok(())
}

/// Expand a source-tree batched proof into one independent path per distinct
/// leaf. The reconstruction exactly follows the canonical batched sibling
/// schedule used by the native verifier. Each returned path stops at the
/// selected cap depth, where its endpoint is checked by the recursive proof.
pub fn expand_source_batched_merkle_proof_to_cap(
    batch: &SourceBatchedMerkleProof,
    depth: usize,
    cap_depth: usize,
    leaf_indices: &[usize],
    leaf_hashes: &[SourceHash],
    hasher: &dyn CryptographicHasher,
) -> Result<Vec<IndependentSourceMerklePath>, String> {
    use std::collections::HashMap;

    if cap_depth > depth {
        return Err("source cap depth exceeds tree depth".into());
    }
    if leaf_indices.len() != leaf_hashes.len() {
        return Err("source leaf index/hash count mismatch".into());
    }
    let leaf_bound = 1usize
        .checked_shl(depth as u32)
        .ok_or_else(|| "source tree depth exceeds usize".to_string())?;
    if let Some(&index) = leaf_indices.iter().find(|&&index| index >= leaf_bound) {
        return Err(format!("source leaf index {index} out of range"));
    }

    let walk_depth = depth - cap_depth;
    let (mut known_indices, mut known_hashes) =
        sorted_unique_source_leaf_hashes(leaf_indices, leaf_hashes)
            .map_err(|idx| format!("inconsistent source leaf hashes for index {idx}"))?;

    // Retain every touched node so each deduplicated query can recover its own
    // fixed-shape path after the batched proof has been reconstructed.
    let mut levels: Vec<HashMap<usize, SourceHash>> = Vec::with_capacity(walk_depth + 1);
    levels.push(
        known_indices
            .iter()
            .copied()
            .zip(known_hashes.iter().copied())
            .collect(),
    );

    let mut sibling_cursor = 0usize;
    for layer in 0..walk_depth {
        let mut this_level = std::mem::take(&mut levels[layer]);
        let mut next_indices = Vec::new();
        let mut next_hashes = Vec::new();
        let mut cursor = 0usize;
        while cursor < known_indices.len() {
            let parent = known_indices[cursor] >> 1;
            let left_child = parent * 2;
            let right_child = left_child + 1;
            let mut left = None;
            let mut right = None;
            while cursor < known_indices.len() && (known_indices[cursor] >> 1) == parent {
                let index = known_indices[cursor];
                if index == left_child {
                    left = Some(known_hashes[cursor]);
                } else if index == right_child {
                    right = Some(known_hashes[cursor]);
                } else {
                    return Err(format!("source bad child index {index} at layer {layer}"));
                }
                cursor += 1;
            }

            let parent_hash =
                match (left, right) {
                    (Some(left), Some(right)) => hasher.compress(&left, &right),
                    (Some(left), None) => {
                        let right = *batch.siblings.get(sibling_cursor).ok_or_else(|| {
                            format!("insufficient source siblings at layer {layer}")
                        })?;
                        sibling_cursor += 1;
                        this_level.insert(right_child, right);
                        hasher.compress(&left, &right)
                    }
                    (None, Some(right)) => {
                        let left = *batch.siblings.get(sibling_cursor).ok_or_else(|| {
                            format!("insufficient source siblings at layer {layer}")
                        })?;
                        sibling_cursor += 1;
                        this_level.insert(left_child, left);
                        hasher.compress(&left, &right)
                    }
                    (None, None) => {
                        return Err(format!(
                            "source orphan parent at layer {layer} index {parent}"
                        ));
                    }
                };
            next_indices.push(parent);
            next_hashes.push(parent_hash);
        }

        levels[layer] = this_level;
        levels.push(
            next_indices
                .iter()
                .copied()
                .zip(next_hashes.iter().copied())
                .collect(),
        );
        known_indices = next_indices;
        known_hashes = next_hashes;
    }

    if sibling_cursor != batch.siblings.len() {
        return Err(format!(
            "unused source siblings: consumed {sibling_cursor}, total {}",
            batch.siblings.len()
        ));
    }

    let (leaf_indices, leaf_hashes) =
        sorted_unique_source_leaf_hashes(leaf_indices, leaf_hashes)
            .map_err(|idx| format!("inconsistent source leaf hashes for index {idx}"))?;
    let mut paths = Vec::with_capacity(leaf_indices.len());
    for (leaf_index, leaf_hash) in leaf_indices.into_iter().zip(leaf_hashes) {
        let mut siblings = Vec::with_capacity(walk_depth);
        let mut directions = Vec::with_capacity(walk_depth);
        let mut node = leaf_index;
        for layer in 0..walk_depth {
            let sibling_index = node ^ 1;
            let sibling = *levels[layer].get(&sibling_index).ok_or_else(|| {
                format!("missing source sibling {sibling_index} at layer {layer}")
            })?;
            siblings.push(sibling);
            directions.push(node & 1 == 1);
            node >>= 1;
        }
        paths.push(IndependentSourceMerklePath {
            leaf_index,
            leaf_hash,
            siblings,
            directions,
        });
    }
    Ok(paths)
}

fn sorted_unique_usize(values: &[usize]) -> Vec<usize> {
    let mut out = values.to_vec();
    out.sort_unstable();
    out.dedup();
    out
}

fn sorted_unique_parents(values: &[usize]) -> Vec<usize> {
    let mut out = Vec::with_capacity(values.len());
    let mut last = None;
    for &value in values {
        let parent = value >> 1;
        if last != Some(parent) {
            out.push(parent);
            last = Some(parent);
        }
    }
    out
}

fn sorted_unique_source_leaf_hashes(
    leaf_indices: &[usize],
    leaf_hashes: &[SourceHash],
) -> Result<(Vec<usize>, Vec<SourceHash>), usize> {
    let mut pairs: Vec<(usize, SourceHash)> = leaf_indices
        .iter()
        .copied()
        .zip(leaf_hashes.iter().copied())
        .collect();
    pairs.sort_unstable_by_key(|(idx, _)| *idx);

    let mut indices = Vec::with_capacity(pairs.len());
    let mut hashes = Vec::with_capacity(pairs.len());
    for (idx, hash) in pairs {
        if indices.last().copied() == Some(idx) {
            if hashes.last().copied() != Some(hash) {
                return Err(idx);
            }
        } else {
            indices.push(idx);
            hashes.push(hash);
        }
    }
    Ok((indices, hashes))
}

/// Commit raw interleaved columns into the historical State-segment cap.
///
/// The encoded-source cap remains part of this commitment so existing State
/// roots keep exactly the same byte representation after removal of the old
/// local opening API.
pub fn interleaved_commit_cap(
    cols: &[&[Block128]],
    ntt: &AdditiveNTT<Block128>,
    hasher: &dyn CryptographicHasher,
) -> MerkleCap {
    let backend = CommitmentHashBackend::Arithmetic;
    assert!(!cols.is_empty());
    let n = cols[0].len();
    assert!(n.is_power_of_two());
    let log_rows = n.trailing_zeros() as usize;
    let n_cols = cols.len();

    for col in cols.iter() {
        assert_eq!(col.len(), n, "All columns must have the same length");
    }

    let cap_size = 1usize << MERKLE_CAP_DEPTH;
    let rows_per_segment = n / cap_size;

    let cap_hashes: Vec<HashOutput> = (0..cap_size)
        .into_par_iter()
        .map(|seg| {
            interleaved_cap_segment_hash(
                backend,
                cols,
                seg,
                rows_per_segment,
                n_cols,
                log_rows,
                hasher,
            )
        })
        .collect();

    let encoded_cols: Vec<Vec<Block128>> = cols
        .par_iter()
        .map(|col| Code::new_parallel(col, ntt).encoding)
        .collect();
    let source_tree = SourceMerkleTree::new(&encoded_cols, log_rows, n_cols, backend, hasher);
    let source_cap = source_tree.get_cap(source_cap_depth(log_rows));

    let mut cap_hashes = cap_hashes;
    cap_hashes.extend(source_cap.into_iter().map(source_hash_to_output));
    MerkleCap { hashes: cap_hashes }
}

fn interleaved_cap_segment_hash(
    _backend: CommitmentHashBackend,
    cols: &[&[Block128]],
    seg: usize,
    rows_per_segment: usize,
    n_cols: usize,
    log_rows: usize,
    hasher: &dyn CryptographicHasher,
) -> HashOutput {
    let start = seg * rows_per_segment;
    let end = start + rows_per_segment;
    const CAP_DOMAIN: u128 = 0xF21B_1DCA_0000_0001u128;
    let mut acc = hasher.hash_pair(
        &Block128::from(CAP_DOMAIN),
        &Block128::from(log_rows as u128),
    );
    let meta = hasher.hash_pair(
        &Block128::from(seg as u128),
        &Block128::from(n_cols as u128),
    );
    acc = hasher.compress(&acc, &meta);
    for row in start..end {
        for col in cols.iter() {
            let elem = hasher.hash_field(&col[row]);
            acc = hasher.compress(&acc, &elem);
        }
    }
    acc
}

pub(crate) fn source_leaf_count(log_rows: usize) -> usize {
    1usize << (log_rows + LOG_RATE - 1)
}

pub fn source_tree_depth(log_rows: usize) -> usize {
    log_rows + LOG_RATE - 1
}

pub fn source_cap_depth(log_rows: usize) -> usize {
    SOURCE_CAP_DEPTH.min(source_tree_depth(log_rows))
}

pub fn source_leaf_hash(
    _backend: CommitmentHashBackend,
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    symbols: &[Block128],
    hasher: &dyn CryptographicHasher,
) -> SourceHash {
    assert_eq!(symbols.len(), n_cols * 2);
    source_leaf_hash_arithmetic(log_rows, n_cols, leaf_index, symbols, hasher)
}

/// Domain tag for encoded-source leaf hashes.
///
/// Public so the in-circuit trace twin can replay this definition;
/// change both together.
pub const SOURCE_LEAF_DOMAIN: u128 = 0xF21B_1D50_0000_0001u128;

fn source_leaf_hash_arithmetic(
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    symbols: &[Block128],
    hasher: &dyn CryptographicHasher,
) -> SourceHash {
    let mut acc = hasher.hash_pair(
        &Block128::from(SOURCE_LEAF_DOMAIN),
        &Block128::from(log_rows as u128),
    );
    let meta = hasher.hash_pair(
        &Block128::from(n_cols as u128),
        &Block128::from(leaf_index as u128),
    );
    acc = hasher.compress(&acc, &meta);
    let mut pair_hashes = vec![[0u8; 32]; symbols.len() / 2];
    hasher.batch_hash_pair(symbols, &mut pair_hashes);
    for pair_hash in pair_hashes {
        acc = hasher.compress(&acc, &pair_hash);
    }
    acc
}

pub fn source_leaf_positions(log_rows: usize, leaf_index: usize) -> (usize, usize) {
    assert!(log_rows > 0);
    let half = 1usize << (log_rows - 1);
    let local_mask = half - 1;
    let local = leaf_index & local_mask;
    let coset = leaf_index >> (log_rows - 1);
    let base = coset * (1usize << log_rows) + local;
    (base, base + half)
}

fn build_source_leaf_hashes(
    encoded_cols: &[Vec<Block128>],
    log_rows: usize,
    n_cols: usize,
    backend: CommitmentHashBackend,
    hasher: &dyn CryptographicHasher,
) -> Vec<SourceHash> {
    assert_source_encoded_shape(encoded_cols, log_rows, n_cols);
    let leaf_count = source_leaf_count(log_rows);
    (0..leaf_count)
        .into_par_iter()
        .map(|leaf_index| {
            source_leaf_hash_from_encoded_cols_at(
                encoded_cols,
                log_rows,
                n_cols,
                leaf_index,
                backend,
                hasher,
            )
        })
        .collect()
}

fn build_source_chunk_root(
    encoded_cols: &[Vec<Block128>],
    log_rows: usize,
    n_cols: usize,
    chunk_log: usize,
    chunk_idx: usize,
    backend: CommitmentHashBackend,
    hasher: &dyn CryptographicHasher,
) -> SourceHash {
    assert_source_encoded_shape(encoded_cols, log_rows, n_cols);
    let chunk_leaf_count = 1usize << chunk_log;
    let first_leaf = chunk_idx * chunk_leaf_count;
    if chunk_log == SOURCE_MERKLE_CHUNK_LOG {
        let mut layer = [[0u8; SOURCE_HASH_BYTES]; SOURCE_MERKLE_CHUNK_LEAVES];
        for (local, leaf) in layer.iter_mut().take(chunk_leaf_count).enumerate() {
            *leaf = source_leaf_hash_from_encoded_cols_at(
                encoded_cols,
                log_rows,
                n_cols,
                first_leaf + local,
                backend,
                hasher,
            );
        }
        let mut len = chunk_leaf_count;
        while len > 1 {
            for i in 0..(len / 2) {
                layer[i] = source_compress(backend, &layer[2 * i], &layer[2 * i + 1], hasher);
            }
            len /= 2;
        }
        return layer[0];
    }

    let mut layer: Vec<SourceHash> = (0..chunk_leaf_count)
        .map(|local| {
            source_leaf_hash_from_encoded_cols_at(
                encoded_cols,
                log_rows,
                n_cols,
                first_leaf + local,
                backend,
                hasher,
            )
        })
        .collect();
    let mut len = chunk_leaf_count;
    while len > 1 {
        for i in 0..(len / 2) {
            layer[i] = source_compress(backend, &layer[2 * i], &layer[2 * i + 1], hasher);
        }
        len /= 2;
    }
    layer[0]
}

fn source_leaf_hash_from_encoded_cols_at(
    encoded_cols: &[Vec<Block128>],
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    backend: CommitmentHashBackend,
    hasher: &dyn CryptographicHasher,
) -> SourceHash {
    let (pos0, pos1) = source_leaf_positions(log_rows, leaf_index);
    source_leaf_hash_from_encoded_cols(
        log_rows,
        n_cols,
        leaf_index,
        encoded_cols,
        pos0,
        pos1,
        backend,
        hasher,
    )
}

fn assert_source_encoded_shape(encoded_cols: &[Vec<Block128>], log_rows: usize, n_cols: usize) {
    assert_eq!(encoded_cols.len(), n_cols);
    let code_len = (1usize << log_rows) * RATE;
    for col in encoded_cols {
        assert_eq!(col.len(), code_len);
    }
}

fn source_leaf_hash_from_encoded_cols(
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    encoded_cols: &[Vec<Block128>],
    pos0: usize,
    pos1: usize,
    backend: CommitmentHashBackend,
    hasher: &dyn CryptographicHasher,
) -> SourceHash {
    let _ = backend;
    let mut symbols = Vec::with_capacity(n_cols * 2);
    for col in encoded_cols {
        symbols.push(col[pos0]);
        symbols.push(col[pos1]);
    }
    source_leaf_hash_arithmetic(log_rows, n_cols, leaf_index, &symbols, hasher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::native::compression::Poseidon2bSponge;

    #[test]
    fn batched_source_proof_expands_to_independent_cap_paths() {
        let hasher = Poseidon2bSponge::new();
        let depth = 5;
        let cap_depth = 2;
        let leaves: Vec<SourceHash> = (0..(1usize << depth))
            .map(|index| hasher.hash_field(&Block128::from(index as u128 + 1)))
            .collect();
        let tree =
            SourceHashMerkleTree::new(leaves.clone(), CommitmentHashBackend::Arithmetic, &hasher);
        let indices = [18usize, 1, 7, 1];
        let hashes = indices.map(|index| leaves[index]);
        let proof = build_source_batched_merkle_proof_to_cap(
            &tree,
            &indices,
            depth,
            cap_depth,
            CommitmentHashBackend::Arithmetic,
            &hasher,
        );

        let paths = expand_source_batched_merkle_proof_to_cap(
            &proof, depth, cap_depth, &indices, &hashes, &hasher,
        )
        .expect("expand source proof");
        assert_eq!(paths.len(), 3);

        let cap = tree.get_layer_at_depth(cap_depth);
        for path in paths {
            let mut node = path.leaf_hash;
            for (sibling, is_right) in path.siblings.iter().zip(&path.directions) {
                node = if *is_right {
                    hasher.compress(sibling, &node)
                } else {
                    hasher.compress(&node, sibling)
                };
            }
            let cap_index = path.leaf_index >> (depth - cap_depth);
            assert_eq!(node, cap[cap_index]);
        }
    }
}
