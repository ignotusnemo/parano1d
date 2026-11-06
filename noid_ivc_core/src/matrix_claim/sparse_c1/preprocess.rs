// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::field_r1cs::{CompactFieldR1cs, FieldR1cs, FieldR1csArtifactMatrix};
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

/// Explicit admission policy for this experimental, sequential prover. The
/// byte figure is a planning allowance, not a bound on process RSS: caller
/// matrices, allocator overhead and the shared scratch pool are additional.
#[derive(Clone, Copy, Debug)]
pub struct SparseEvaluationBudget {
    pub max_padded_entries: usize,
    pub max_planned_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SparseEvaluationGeometry {
    pub k_log: usize,
    pub entries: usize,
    pub padded_entries: usize,
    pub row_addresses: usize,
    pub column_addresses: usize,
    pub planned_bytes: u64,
}

impl SparseEvaluationGeometry {
    pub fn new(k_log: usize, entries: usize) -> Result<Self, Error> {
        // The fixed transcript encoding uses u32 addresses/tags. The tag's
        // high bit distinguishes every write from the initial zero tag.
        if !(1..=30).contains(&k_log) || entries > 1usize << 30 {
            return Err(Error::Shape);
        }
        let padded_entries = entries.max(2).next_power_of_two();
        let column_addresses = 1usize << k_log;
        let row_addresses = 2 * column_addresses;
        // Sequential commitments/openings, two wide lookup vectors and one
        // product tree at a time. This deliberately leaves room for BaseFold
        // transients; it is not a production memory measurement.
        let planned_bytes =
            448 * padded_entries as u64 + 128 * (row_addresses + column_addresses) as u64;
        Ok(Self {
            k_log,
            entries,
            padded_entries,
            row_addresses,
            column_addresses,
            planned_bytes,
        })
    }

    pub fn admit(self, budget: SparseEvaluationBudget) -> Result<Self, Error> {
        if self.padded_entries > budget.max_padded_entries
            || self.planned_bytes > budget.max_planned_bytes
        {
            return Err(Error::Budget);
        }
        Ok(self)
    }

    pub(super) fn entry_log(self) -> usize {
        self.padded_entries.trailing_zeros() as usize
    }
}

/// Public preprocessing result. Roots are constructed from authenticated rows
/// or decoded against an independently pinned key digest. Attaching an old
/// matrix hash to arbitrary roots does not authenticate those roots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMatrixEvaluationKey {
    pub(super) shape: FieldShape,
    pub(super) matrix_digest: [u8; 32],
    pub(super) geometry: SparseEvaluationGeometry,
    pub(super) roots: [[u8; 32]; STATIC_COLUMNS],
}

impl SparseMatrixEvaluationKey {
    pub const fn shape(&self) -> FieldShape {
        self.shape
    }
    pub const fn matrix_digest(&self) -> [u8; 32] {
        self.matrix_digest
    }
    pub const fn geometry(&self) -> SparseEvaluationGeometry {
        self.geometry
    }

    /// Source-linked PCS inventory for this key's seven static and four
    /// dynamic columns. This is parameter inspection, not proof verification.
    pub fn opening_parameters(&self) -> impl ExactSizeIterator<Item = PcsParams> + '_ {
        (0..ALL_COLUMNS).map(|column| params(self.column_log(column)))
    }

    /// Number of prover-selected commitments that precede reduction challenges.
    /// The other opening columns belong to the authenticated preprocessing key.
    pub const fn dynamic_commitment_count(&self) -> usize {
        ALL_COLUMNS - STATIC_COLUMNS
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        for item in [
            self.shape.m,
            self.shape.k_log,
            self.shape.k_skip,
            self.shape.const_pin.map_or(0, |pin| pin + 1),
            self.geometry.entries,
        ] {
            bytes.extend_from_slice(&(item as u64).to_le_bytes());
        }
        bytes.extend_from_slice(&self.matrix_digest);
        for root in self.roots {
            bytes.extend_from_slice(&root);
        }
        poseidon2b_hash_byte_slices(b"NOID/SPARSE-MATRIX-KEY/C1/V1", &[&bytes])
    }

    pub(super) fn column_log(&self, column: usize) -> usize {
        match column {
            FINAL_ROW => self.shape.k_log + 1,
            FINAL_COL => self.shape.k_log,
            _ => self.geometry.entry_log(),
        }
    }
}

/// Prover-only canonical sparse entries and immutable memory-chain metadata.
/// Neither this data nor any old matrix is needed by `verify`.
pub struct SparseMatrixProver {
    pub(super) key: SparseMatrixEvaluationKey,
    // row, column, previous row tag, previous column tag.
    pub(super) indices: Vec<[u32; 4]>,
    pub(super) coefficients: Vec<F128>,
    pub(super) final_tags: [Vec<u32>; 2],
}

pub(super) fn check_shape(shape: FieldShape) -> Result<(), Error> {
    if !(1..=30).contains(&shape.k_log)
        || shape.m < shape.k_log
        || shape.m > 30
        || shape.k_skip > shape.k_log
        || shape.const_pin.is_some_and(|pin| pin >= 1usize << shape.m)
    {
        return Err(Error::Shape);
    }
    Ok(())
}

impl SparseMatrixProver {
    pub fn from_resident(
        matrix: &FieldR1cs,
        expected_digest: [u8; 32],
        budget: SparseEvaluationBudget,
    ) -> Result<Self, Error> {
        let shape = FieldShape::of(matrix);
        check_shape(shape)?;
        let count = matrix
            .a_0
            .nnz()
            .checked_add(matrix.b_0.nnz())
            .ok_or(Error::Shape)?;
        let geometry = SparseEvaluationGeometry::new(shape.k_log, count)?.admit(budget)?;
        let width = geometry.column_addresses;
        // A FieldR1cs is a local Rust value, but reject malformed arrays here
        // instead of indexing them while authenticating/preprocessing.
        for side in [&matrix.a_0, &matrix.b_0] {
            if side.num_rows != width
                || side.num_cols != width
                || side.row_offsets.len() != width + 1
                || side.row_offsets.first() != Some(&0)
                || side.row_offsets.last() != Some(&side.nnz())
                || side.row_offsets.windows(2).any(|pair| pair[0] > pair[1])
                || side.col_indices.iter().any(|&col| col as usize >= width)
                || side.col_indices.len() != side.nnz()
                || side
                    .value_indices
                    .iter()
                    .any(|&index| index as usize >= side.value_table.len())
            {
                return Err(Error::Shape);
            }
        }
        if matrix.structural_statement_digest() != expected_digest {
            return Err(Error::MatrixIdentity);
        }
        let mut prover = Self::empty(shape, expected_digest, geometry);
        for (side, rows) in [&matrix.a_0, &matrix.b_0].into_iter().enumerate() {
            for row in 0..width {
                for (col, value) in rows.row(row) {
                    prover.push(row + side * width, col, value);
                }
            }
        }
        prover.complete()
    }

    pub fn from_compact(
        matrix: &CompactFieldR1cs,
        expected_digest: [u8; 32],
        budget: SparseEvaluationBudget,
    ) -> Result<Self, Error> {
        let shape = matrix.shape();
        check_shape(shape)?;
        if matrix.statement_digest() != expected_digest {
            return Err(Error::MatrixIdentity);
        }
        // No CSR expansion. CompactFieldR1cs already authenticated immutable
        // row bytes; the counting pass permits admission before table allocation.
        let visit = |callback: &mut dyn FnMut(usize, u32, F128)| {
            for (side_index, side) in [FieldR1csArtifactMatrix::A, FieldR1csArtifactMatrix::B]
                .into_iter()
                .enumerate()
            {
                for group in 0..matrix.matrix_group_count(side) {
                    assert!(
                        matrix.for_each_matrix_group_entry(side, group, |row, col, value| {
                            callback(row + (side_index << shape.k_log), col, value);
                        })
                    );
                }
            }
        };
        let mut count = 0usize;
        visit(&mut |_, _, _| {
            count += 1;
        });
        let geometry = SparseEvaluationGeometry::new(shape.k_log, count)?.admit(budget)?;
        let mut prover = Self::empty(shape, expected_digest, geometry);
        visit(&mut |row, col, value| prover.push(row, col, value));
        prover.complete()
    }

    fn empty(
        shape: FieldShape,
        matrix_digest: [u8; 32],
        geometry: SparseEvaluationGeometry,
    ) -> Self {
        Self {
            key: SparseMatrixEvaluationKey {
                shape,
                matrix_digest,
                geometry,
                roots: [[0; 32]; STATIC_COLUMNS],
            },
            indices: Vec::with_capacity(geometry.padded_entries),
            coefficients: Vec::with_capacity(geometry.padded_entries),
            final_tags: [
                vec![0; geometry.row_addresses],
                vec![0; geometry.column_addresses],
            ],
        }
    }

    fn push(&mut self, row: usize, col: u32, value: F128) {
        let tag = (self.key.geometry.padded_entries + self.indices.len()) as u32;
        self.indices.push([
            row as u32,
            col,
            self.final_tags[0][row],
            self.final_tags[1][col as usize],
        ]);
        self.coefficients.push(value);
        self.final_tags[0][row] = tag;
        self.final_tags[1][col as usize] = tag;
    }

    fn complete(mut self) -> Result<Self, Error> {
        if self.indices.len() != self.key.geometry.entries {
            return Err(Error::Shape);
        }
        // Padding is part of both authenticated access chains, even though
        // its zero coefficient contributes nothing to the matrix evaluation.
        while self.indices.len() < self.key.geometry.padded_entries {
            self.push(0, 0, F128::ZERO);
        }
        for column in 0..STATIC_COLUMNS {
            let mut table = self.static_column(column);
            pad_column(&mut table);
            let (commitment, data) = pcs::commit(&table, &params(self.key.column_log(column)));
            self.key.roots[column] = commitment.root;
            drop(data);
            // A larger entry column must not remain in the idle pool while
            // preprocessing the smaller row/column audit domains.
            crate::scratch::clear();
        }
        Ok(self)
    }

    pub fn key(&self) -> &SparseMatrixEvaluationKey {
        &self.key
    }

    pub(super) fn static_column(&self, column: usize) -> Vec<F128> {
        match column {
            ROW | COL => self
                .indices
                .iter()
                .map(|entry| raw(entry[column]))
                .collect(),
            VALUE => self.coefficients.clone(),
            READ_ROW | READ_COL => self
                .indices
                .iter()
                .map(|entry| raw(entry[column - 1]))
                .collect(),
            FINAL_ROW | FINAL_COL => self.final_tags[column - FINAL_ROW]
                .iter()
                .map(|&tag| raw(tag))
                .collect(),
            _ => unreachable!("static column"),
        }
    }
}

pub(super) fn raw(value: u32) -> F128 {
    F128::new(u64::from(value), 0)
}

// raw(index) is linear in the binary index bits. The write tag has one
// additional high bit, so it is never zero and never relies on field + 1.
pub(super) fn index_mle(point: &[F256]) -> F256 {
    point.iter().enumerate().fold(F256::ZERO, |out, (bit, &r)| {
        out + r.scale_base(raw(1 << bit))
    })
}

pub(super) fn write_tag_mle(point: &[F256]) -> F256 {
    index_mle(point) + F256::from_base(raw(1 << point.len()))
}
