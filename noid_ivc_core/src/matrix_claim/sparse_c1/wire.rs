// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2026 Paranoid Zero.

//! Bounded canonical transport for preprocessed sparse evaluations. Every
//! vector length comes from a separately pinned key, never from proof bytes.
//! Key decoding authenticates public preprocessing, not a chain checkpoint.

use super::*;
use crate::pcs::basefold::{C1QueryOpening, C1RoundMessage};
use crate::pcs::{compute_fri_arities, default_fri_queries, fri_commit_layout, RoundCommitment};

const KEY_MAGIC: &[u8; 8] = b"N1SPKEY1";
const PROOF_MAGIC: &[u8; 8] = b"N1SPEVL1";
const SHARED_PROOF_MAGIC: &[u8; 8] = b"N1SPEVL2";
pub const SPARSE_EVALUATION_KEY_BYTES: usize = 8 + 5 * 8 + 32 + STATIC_COLUMNS * 32;
pub const MAX_SPARSE_EVALUATION_PROOF_BYTES: usize = 64 * 1024 * 1024;

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(count).ok_or(Error::Wire)?;
        let bytes = self.bytes.get(self.at..end).ok_or(Error::Wire)?;
        self.at = end;
        Ok(bytes)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn size(&mut self) -> Result<usize, Error> {
        usize::try_from(self.u64()?).map_err(|_| Error::Wire)
    }
    fn hash(&mut self) -> Result<[u8; 32], Error> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn f128(&mut self) -> Result<F128, Error> {
        Ok(F128::new(self.u64()?, self.u64()?))
    }
    fn f256(&mut self) -> Result<F256, Error> {
        Ok(F256::from_le_bytes(self.take(32)?.try_into().unwrap()))
    }
    fn wide(&mut self, n: usize) -> Result<Vec<F256>, Error> {
        // Preflight the full byte span before allocating even a fixed vector.
        if self.bytes.len() - self.at < n.checked_mul(32).ok_or(Error::Wire)? {
            return Err(Error::Wire);
        }
        (0..n).map(|_| self.f256()).collect()
    }
    fn hashes(&mut self, n: usize) -> Result<Vec<[u8; 32]>, Error> {
        if self.bytes.len() - self.at < n.checked_mul(32).ok_or(Error::Wire)? {
            return Err(Error::Wire);
        }
        (0..n).map(|_| self.hash()).collect()
    }
    fn end(&self) -> Result<(), Error> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Wire)
        }
    }
}

fn wide(out: &mut Vec<u8>, values: &[F256], expected: usize) -> Result<(), Error> {
    if values.len() != expected {
        return Err(Error::Wire);
    }
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
    Ok(())
}
fn hashes(out: &mut Vec<u8>, values: &[[u8; 32]], expected: usize) -> Result<(), Error> {
    if values.len() != expected {
        return Err(Error::Wire);
    }
    for value in values {
        out.extend_from_slice(value);
    }
    Ok(())
}

impl SparseMatrixEvaluationKey {
    pub fn to_bytes(&self) -> [u8; SPARSE_EVALUATION_KEY_BYTES] {
        let mut out = Vec::with_capacity(SPARSE_EVALUATION_KEY_BYTES);
        out.extend_from_slice(KEY_MAGIC);
        for value in [
            self.shape.m,
            self.shape.k_log,
            self.shape.k_skip,
            self.shape.const_pin.map_or(0, |pin| pin + 1),
            self.geometry.entries,
        ] {
            out.extend_from_slice(&(value as u64).to_le_bytes());
        }
        out.extend_from_slice(&self.matrix_digest);
        for root in &self.roots {
            out.extend_from_slice(root);
        }
        out.try_into().expect("fixed sparse key encoding")
    }

    /// The pin must come from an independently authenticated release manifest.
    /// Taking it from the same untrusted payload does not authenticate rows.
    pub fn from_bytes_pinned(bytes: &[u8], expected_key: [u8; 32]) -> Result<Self, Error> {
        if bytes.len() != SPARSE_EVALUATION_KEY_BYTES || !bytes.starts_with(KEY_MAGIC) {
            return Err(Error::Wire);
        }
        let mut reader = Reader { bytes, at: 8 };
        let m = reader.size()?;
        let k_log = reader.size()?;
        let k_skip = reader.size()?;
        let const_pin = reader.size()?.checked_sub(1);
        let shape = FieldShape {
            m,
            k_log,
            k_skip,
            const_pin,
        };
        preprocess::check_shape(shape)?;
        let geometry = SparseEvaluationGeometry::new(k_log, reader.size()?)?;
        let matrix_digest = reader.hash()?;
        let roots = reader
            .hashes(STATIC_COLUMNS)?
            .try_into()
            .map_err(|_| Error::Wire)?;
        reader.end()?;
        let key = Self {
            shape,
            matrix_digest,
            geometry,
            roots,
        };
        if key.digest() != expected_key {
            return Err(Error::MatrixIdentity);
        }
        Ok(key)
    }
}

fn put_cubic(out: &mut Vec<u8>, proof: &CubicProof, log: usize) -> Result<(), Error> {
    if proof.rounds.len() != log {
        return Err(Error::Wire);
    }
    for round in &proof.rounds {
        wide(out, round, 3)?;
    }
    wide(out, &proof.values, 3)
}
fn get_cubic(reader: &mut Reader<'_>, log: usize) -> Result<CubicProof, Error> {
    Ok(CubicProof {
        rounds: (0..log)
            .map(|_| Ok([reader.f256()?, reader.f256()?, reader.f256()?]))
            .collect::<Result<_, Error>>()?,
        values: [reader.f256()?, reader.f256()?, reader.f256()?],
    })
}
fn tree_log(key: &SparseMatrixEvaluationKey, side: usize, kind: usize) -> usize {
    if kind == READ || kind == WRITE {
        key.geometry.entry_log()
    } else {
        key.shape.k_log + usize::from(side == ROW)
    }
}
fn put_reduction(
    out: &mut Vec<u8>,
    key: &SparseMatrixEvaluationKey,
    reduction: &Reduction,
) -> Result<(), Error> {
    hashes(out, &reduction.dynamic_roots, 4)?;
    put_cubic(out, &reduction.inner_product, key.geometry.entry_log())?;
    for (side, lookup) in reduction.lookups.iter().enumerate() {
        wide(out, &lookup.products, 4)?;
        for (kind, tree) in lookup.trees.iter().enumerate() {
            let log = tree_log(key, side, kind);
            if tree.layers.len() != log {
                return Err(Error::Wire);
            }
            for (j, layer) in tree.layers.iter().enumerate() {
                put_cubic(out, layer, j)?;
            }
        }
    }
    Ok(())
}
fn get_reduction(
    reader: &mut Reader<'_>,
    key: &SparseMatrixEvaluationKey,
) -> Result<Reduction, Error> {
    let dynamic_roots = reader.hashes(4)?.try_into().map_err(|_| Error::Wire)?;
    let inner_product = get_cubic(reader, key.geometry.entry_log())?;
    let mut lookups = Vec::with_capacity(2);
    for side in 0..2 {
        let products = reader.wide(4)?.try_into().map_err(|_| Error::Wire)?;
        let mut trees = Vec::with_capacity(4);
        for kind in 0..4 {
            let layers = (0..tree_log(key, side, kind))
                .map(|j| get_cubic(reader, j))
                .collect::<Result<_, Error>>()?;
            trees.push(ProductProof { layers });
        }
        lookups.push(LookupProof {
            products,
            trees: trees.try_into().map_err(|_| Error::Wire)?,
        });
    }
    Ok(Reduction {
        dynamic_roots,
        inner_product,
        lookups: lookups.try_into().map_err(|_| Error::Wire)?,
    })
}

// Full Merkle paths are fixed length here. The existing terminal's shared-path
// codec is independent; changing this transport does not change a PCS proof.
struct PcsShape {
    rounds: usize,
    commits: usize,
    codeword: usize,
    tail: usize,
    queries: usize,
    initial_leaf: usize,
    initial_path: usize,
    row_leaf: usize,
    row_path: usize,
    epochs: Vec<(usize, usize)>,
}
impl PcsShape {
    fn new(log: usize) -> Self {
        let params = params(log);
        let message_log = params.m - pcs::LOG_PACKING;
        let log_dim = params.log_dim();
        let k_code = params.k_code();
        let arities = compute_fri_arities(log_dim);
        let (commits, tail) = fri_commit_layout(k_code, &arities);
        let first = arities[0];
        let mut consumed = first;
        let epochs = arities
            .iter()
            .skip(1)
            .take(commits)
            .map(|arity| {
                consumed += arity;
                (1usize << arity, k_code - consumed)
            })
            .collect();
        Self {
            rounds: message_log,
            commits,
            codeword: 1 << params.log_inv_rate,
            tail: tail.map_or(0, |(length, _)| length),
            queries: default_fri_queries(log_dim, params.log_inv_rate),
            initial_leaf: 1 << params.log_batch_size,
            initial_path: k_code,
            row_leaf: 1 << first,
            row_path: k_code - first,
            epochs,
        }
    }
    fn bytes_without_paths(&self) -> usize {
        self.bytes()
            - self.queries
                * 32
                * (self.initial_path
                    + self.row_path
                    + self.epochs.iter().map(|(_, path)| path).sum::<usize>())
    }
    fn bytes(&self) -> usize {
        let query = 8
            + 16 * self.initial_leaf
            + 32 * (self.initial_path + self.row_leaf + self.row_path)
            + self
                .epochs
                .iter()
                .map(|(leaf, path)| 32 * (leaf + path))
                .sum::<usize>();
        64 * self.rounds
            + 32 * (1 + self.commits + 2 + self.codeword + self.tail)
            + 8
            + self.queries * query
    }
}
fn put_pcs(
    out: &mut Vec<u8>,
    shape: &PcsShape,
    proof: &C1BaseFoldProof,
    shared: bool,
) -> Result<(), Error> {
    if proof.round_messages.len() != shape.rounds
        || proof.round_commitments.len() != shape.commits
        || proof.queries.len() != shape.queries
    {
        return Err(Error::Wire);
    }
    for round in &proof.round_messages {
        wide(out, &[round.u_0, round.u_2], 2)?;
    }
    out.extend_from_slice(&proof.post_row_batch_commit.root);
    for commitment in &proof.round_commitments {
        out.extend_from_slice(&commitment.root);
    }
    wide(out, &[proof.final_a, proof.final_b], 2)?;
    wide(out, &proof.final_codeword, shape.codeword)?;
    wide(out, &proof.plaintext_tail, shape.tail)?;
    out.extend_from_slice(&proof.pow_nonce.to_le_bytes());
    for query in &proof.queries {
        if query.position >= 1usize << shape.initial_path
            || query.initial_leaf.len() != shape.initial_leaf
            || query.epoch_leaves.len() != shape.epochs.len()
            || query.epoch_paths.len() != shape.epochs.len()
        {
            return Err(Error::Wire);
        }
        out.extend_from_slice(&(query.position as u64).to_le_bytes());
        for value in &query.initial_leaf {
            out.extend_from_slice(&value.lo.to_le_bytes());
            out.extend_from_slice(&value.hi.to_le_bytes());
        }
        if !shared {
            hashes(out, &query.initial_path, shape.initial_path)?;
        }
        wide(out, &query.post_row_batch_leaf, shape.row_leaf)?;
        if !shared {
            hashes(out, &query.post_row_batch_path, shape.row_path)?;
        }
        for (j, &(leaf, path)) in shape.epochs.iter().enumerate() {
            wide(out, &query.epoch_leaves[j], leaf)?;
            if !shared {
                hashes(out, &query.epoch_paths[j], path)?;
            }
        }
    }
    if shared {
        put_shared_paths(out, shape, &proof.queries)?;
    }
    Ok(())
}
fn get_pcs(
    reader: &mut Reader<'_>,
    shape: &PcsShape,
    shared: bool,
) -> Result<C1BaseFoldProof, Error> {
    // All allocation sizes are independently derived from the pinned key.
    if reader.bytes.len() - reader.at
        < if shared {
            shape.bytes_without_paths()
        } else {
            shape.bytes()
        }
    {
        return Err(Error::Wire);
    }
    let round_messages = (0..shape.rounds)
        .map(|_| {
            Ok(C1RoundMessage {
                u_0: reader.f256()?,
                u_2: reader.f256()?,
            })
        })
        .collect::<Result<_, Error>>()?;
    let post_row_batch_commit = RoundCommitment {
        root: reader.hash()?,
    };
    let round_commitments = (0..shape.commits)
        .map(|_| {
            Ok(RoundCommitment {
                root: reader.hash()?,
            })
        })
        .collect::<Result<_, Error>>()?;
    let final_a = reader.f256()?;
    let final_b = reader.f256()?;
    let final_codeword = reader.wide(shape.codeword)?;
    let plaintext_tail = reader.wide(shape.tail)?;
    let pow_nonce = reader.u64()?;
    let mut queries = Vec::with_capacity(shape.queries);
    for _ in 0..shape.queries {
        let position = reader.size()?;
        if position >= 1usize << shape.initial_path {
            return Err(Error::Wire);
        }
        let initial_leaf = (0..shape.initial_leaf)
            .map(|_| reader.f128())
            .collect::<Result<_, _>>()?;
        let initial_path = reader.hashes(if shared { 0 } else { shape.initial_path })?;
        let post_row_batch_leaf = reader.wide(shape.row_leaf)?;
        let post_row_batch_path = reader.hashes(if shared { 0 } else { shape.row_path })?;
        let mut epoch_leaves = Vec::with_capacity(shape.epochs.len());
        let mut epoch_paths = Vec::with_capacity(shape.epochs.len());
        for &(leaf, path) in &shape.epochs {
            epoch_leaves.push(reader.wide(leaf)?);
            epoch_paths.push(reader.hashes(if shared { 0 } else { path })?);
        }
        queries.push(C1QueryOpening {
            position,
            initial_leaf,
            initial_path,
            post_row_batch_leaf,
            post_row_batch_path,
            epoch_leaves,
            epoch_paths,
        });
    }
    if shared {
        get_shared_paths(reader, shape, &mut queries)?;
    }
    Ok(C1BaseFoldProof {
        round_messages,
        post_row_batch_commit,
        round_commitments,
        final_a,
        final_b,
        final_codeword,
        plaintext_tail,
        pow_nonce,
        queries,
    })
}

impl SparseMatrixEvaluationProof {
    /// Canonical bytes are bound to a particular key, retirement request and
    /// evaluation claim. Encoding validates shape and the algebraic reduction;
    /// the receiving verifier must still authenticate all PCS openings.
    pub fn to_bytes(
        &self,
        key: &SparseMatrixEvaluationKey,
        context: [u8; 32],
        claim: &C1MatrixAccClaim,
    ) -> Result<Vec<u8>, Error> {
        self.encode(key, context, claim, false)
    }

    /// Canonical dictionaries restore the original full Merkle paths. The
    /// cryptographic verifier, transcript and query schedule are unchanged.
    pub fn to_shared_bytes(
        &self,
        key: &SparseMatrixEvaluationKey,
        context: [u8; 32],
        claim: &C1MatrixAccClaim,
    ) -> Result<Vec<u8>, Error> {
        self.encode(key, context, claim, true)
    }

    fn encode(
        &self,
        key: &SparseMatrixEvaluationKey,
        context: [u8; 32],
        claim: &C1MatrixAccClaim,
        shared: bool,
    ) -> Result<Vec<u8>, Error> {
        let (plan, _) = reduce(key, context, claim, &self.reduction)?;
        plan.check(&self.values)?;
        let mut out = Vec::new();
        out.extend_from_slice(if shared {
            SHARED_PROOF_MAGIC
        } else {
            PROOF_MAGIC
        });
        out.extend_from_slice(&key.digest());
        out.extend_from_slice(&context);
        wide(&mut out, &claim.point, 2 * key.shape.k_log + 1)?;
        wide(&mut out, &[claim.value], 1)?;
        put_reduction(&mut out, key, &self.reduction)?;
        for column in 0..ALL_COLUMNS {
            wide(&mut out, &self.values[column], plan.points[column].len())?;
            put_pcs(
                &mut out,
                &PcsShape::new(key.column_log(column)),
                &self.openings[column],
                shared,
            )?;
            if out.len() > MAX_SPARSE_EVALUATION_PROOF_BYTES {
                return Err(Error::Wire);
            }
        }
        Ok(out)
    }

    /// Bounded framing and reduction checks do not establish PCS validity.
    /// Pass the result to the independently pinned key's `verify` method.
    pub fn from_bytes(
        key: &SparseMatrixEvaluationKey,
        context: [u8; 32],
        claim: &C1MatrixAccClaim,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        claim_shape(key, claim)?;
        let shared = bytes.starts_with(SHARED_PROOF_MAGIC);
        if bytes.len() > MAX_SPARSE_EVALUATION_PROOF_BYTES
            || !(shared || bytes.starts_with(PROOF_MAGIC))
        {
            return Err(Error::Wire);
        }
        let mut reader = Reader { bytes, at: 8 };
        if reader.hash()? != key.digest() || reader.hash()? != context {
            return Err(Error::Wire);
        }
        for &value in &claim.point {
            if reader.f256()? != value {
                return Err(Error::Claim);
            }
        }
        if reader.f256()? != claim.value {
            return Err(Error::Claim);
        }
        let reduction = get_reduction(&mut reader, key)?;
        let (plan, _) = reduce(key, context, claim, &reduction)?;
        let remaining: usize = (0..ALL_COLUMNS)
            .map(|col| {
                let shape = PcsShape::new(key.column_log(col));
                32 * plan.points[col].len()
                    + if shared {
                        shape.bytes_without_paths()
                    } else {
                        shape.bytes()
                    }
            })
            .sum();
        if (!shared && bytes.len() - reader.at != remaining)
            || (shared && bytes.len() - reader.at < remaining)
        {
            return Err(Error::Wire);
        }
        let mut values = Vec::with_capacity(ALL_COLUMNS);
        let mut openings = Vec::with_capacity(ALL_COLUMNS);
        for column in 0..ALL_COLUMNS {
            values.push(reader.wide(plan.points[column].len())?);
            openings.push(get_pcs(
                &mut reader,
                &PcsShape::new(key.column_log(column)),
                shared,
            )?);
        }
        reader.end()?;
        let values = values.try_into().map_err(|_| Error::Wire)?;
        plan.check(&values)?;
        Ok(Self {
            reduction,
            values,
            openings: openings.try_into().map_err(|_| Error::Wire)?,
        })
    }
}

fn tree_depths(shape: &PcsShape) -> impl Iterator<Item = usize> + '_ {
    [shape.initial_path, shape.row_path]
        .into_iter()
        .chain(shape.epochs.iter().map(|(_, d)| *d))
}
fn query_path(query: &C1QueryOpening, tree: usize) -> &[[u8; 32]] {
    match tree {
        0 => &query.initial_path,
        1 => &query.post_row_batch_path,
        _ => &query.epoch_paths[tree - 2],
    }
}
fn put_shared_paths(
    out: &mut Vec<u8>,
    shape: &PcsShape,
    queries: &[C1QueryOpening],
) -> Result<(), Error> {
    use std::collections::BTreeMap;
    for (tree, depth) in tree_depths(shape).enumerate() {
        let shift = shape.initial_path - depth;
        let mut nodes = BTreeMap::new();
        for query in queries {
            let path = query_path(query, tree);
            if path.len() != depth {
                return Err(Error::Wire);
            }
            let position = query.position >> shift;
            for (level, hash) in path.iter().enumerate() {
                let key = (level, (position >> level) ^ 1);
                if nodes.insert(key, *hash).is_some_and(|old| old != *hash) {
                    return Err(Error::Wire);
                }
            }
        }
        for hash in nodes.values() {
            out.extend_from_slice(hash);
        }
    }
    Ok(())
}
fn get_shared_paths(
    reader: &mut Reader<'_>,
    shape: &PcsShape,
    queries: &mut [C1QueryOpening],
) -> Result<(), Error> {
    use std::collections::{BTreeMap, BTreeSet};
    for (tree, depth) in tree_depths(shape).enumerate() {
        let shift = shape.initial_path - depth;
        let order: BTreeSet<_> = queries
            .iter()
            .flat_map(|query| {
                let position = query.position >> shift;
                (0..depth).map(move |level| (level, (position >> level) ^ 1))
            })
            .collect();
        // Preflight the whole dictionary before allocating reconstructed paths.
        if reader.bytes.len() - reader.at < order.len().checked_mul(32).ok_or(Error::Wire)? {
            return Err(Error::Wire);
        }
        let mut nodes = BTreeMap::new();
        for key in order {
            nodes.insert(key, reader.hash()?);
        }
        for query in queries.iter_mut() {
            let position = query.position >> shift;
            let path = (0..depth)
                .map(|level| nodes[&(level, (position >> level) ^ 1)])
                .collect();
            match tree {
                0 => query.initial_path = path,
                1 => query.post_row_batch_path = path,
                _ => query.epoch_paths[tree - 2] = path,
            }
        }
    }
    Ok(())
}
