//! Block-diagonal R1CS over F_{2^128} — the substrate of the recursive
//! acceptance proof.
//!
//! Generalizes [`crate::r1cs::BlockR1cs`] from a boolean witness to
//! `z ∈ F_{2^128}^{2^m}`: the relation is `(A·z) ⊙ (B·z) = C·z` with the
//! Hadamard product now a genuine field multiplication per constraint row.
//! The sparse base matrices carry F128 coefficients, so linear layers
//! (Poseidon2b MDS, round constants via the constant wire) cost zero extra
//! constraints.
//!
//! Conventions shared with the boolean path:
//! - `C = I` (circuit R1CS): every witness element is constrained as
//!   `z_i = (A·z)_i · (B·z)_i`, and the zerocheck's c-claim is directly a
//!   z-claim. `C` is not materialized.
//! - Block-diagonal structure: `A = I_{2^(m−k_log)} ⊗ A_0` with `A_0` a
//!   `k × k` sparse matrix, `k = 2^k_log`.
//! - `k_skip` is the univariate-skip dimension of the field zerocheck
//!   ([`crate::zerocheck::field`]) and the lincheck quirky-point layout.
//! - `const_pin` drives the lincheck constant-wire pin (the committed
//!   constant-one column), closing the all-zero-witness gap — see
//!   `docs/const-wire-pin.md`.

use crate::field::{F128, F256};
use crate::lincheck::LincheckCircuit;
use std::borrow::Cow;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};

/// Scale an extension value by a public matrix coefficient.
#[inline(always)]
pub(crate) fn scale_matrix_coefficient_c1(value: F256, coefficient: F128) -> F256 {
    if coefficient == F128::ONE {
        value
    } else {
        value.scale_base(coefficient)
    }
}

/// Interns F128 coefficients into a dedup'd table + `u32` indices, preserving
/// first-seen order (deterministic for a fixed construction sequence).
#[derive(Default)]
pub(crate) struct ValueInterner {
    table: Vec<F128>,
    map: std::collections::HashMap<u128, u32>,
}

impl ValueInterner {
    #[inline]
    pub(crate) fn intern(&mut self, v: F128) -> u32 {
        let key = ((v.hi as u128) << 64) | v.lo as u128;
        *self.map.entry(key).or_insert_with(|| {
            let idx = self.table.len() as u32;
            self.table.push(v);
            idx
        })
    }
    pub(crate) fn into_table(self) -> Vec<F128> {
        self.table
    }
}

/// Sparse matrix over F_{2^128} in **dictionary-encoded CSR** form. Row `r`'s
/// nonzero columns are `col_indices[row_offsets[r]..row_offsets[r + 1]]`; each
/// nonzero's coefficient is `value_table[value_indices[i]]` at the matching
/// position. Absent columns are zero. Per-row entry order is preserved from
/// construction — both [`FieldR1cs::statement_digest`] and the lincheck column
/// fold depend on it. Coefficients must be nonzero (a zero coefficient is
/// representable but wasteful and forbidden by convention).
///
/// The matrix is a **protocol constant**, so its coefficients are a small fixed
/// set — a few hundred distinct values (MDS entries, round constants,
/// additive-NTT twiddles) heavily repeated across millions of nonzeros. Storing
/// a `u32` index (4 B) into a tiny table instead of a 16 B `F128` per nonzero
/// roughly halves the matrix vs the plain-CSR `Vec<F128>` (12 B saved per
/// nonzero) — which itself already halved the former `Vec<Vec<(u32, F128)>>`
/// (32 B/nonzero + a 24 B `Vec` header per row). The matrix is the single
/// largest resident prover buffer at block-bearing (2^23–2^24) sizes.
#[derive(Clone, Debug)]
pub struct SparseFieldMatrix {
    pub num_rows: usize,
    pub num_cols: usize,
    /// Column index of each nonzero, grouped by row per `row_offsets`.
    pub col_indices: Vec<u32>,
    /// Coefficient-table index of each nonzero, parallel to `col_indices`.
    pub value_indices: Vec<u32>,
    /// Distinct coefficient values; `value_table[value_indices[i]]` is the
    /// coefficient of nonzero `i`.
    pub value_table: Vec<F128>,
    /// Row boundaries: length `num_rows + 1`, monotone non-decreasing,
    /// `row_offsets[0] == 0` and `row_offsets[num_rows] == col_indices.len()`.
    pub row_offsets: Vec<usize>,
}

/// Compared by DECODED content: two matrices are equal iff their columns,
/// offsets and per-nonzero coefficient VALUES match — independent of the
/// interning order of `value_table` (the drift-check gates rely on this).
impl PartialEq for SparseFieldMatrix {
    fn eq(&self, other: &Self) -> bool {
        self.num_rows == other.num_rows
            && self.num_cols == other.num_cols
            && self.row_offsets == other.row_offsets
            && self.col_indices == other.col_indices
            && self.value_indices.len() == other.value_indices.len()
            && self
                .value_indices
                .iter()
                .zip(&other.value_indices)
                .all(|(&a, &b)| self.value_table[a as usize] == other.value_table[b as usize])
    }
}

impl SparseFieldMatrix {
    /// Build from a row-major `(column, coefficient)` list — the natural
    /// builder output. Interns coefficients into the value table as it flattens
    /// (each inner `Vec` frees as consumed), preserving per-row entry order.
    pub fn from_rows(num_cols: usize, rows: Vec<Vec<(u32, F128)>>) -> Self {
        let num_rows = rows.len();
        let nnz: usize = rows.iter().map(|r| r.len()).sum();
        let mut col_indices = Vec::with_capacity(nnz);
        let mut value_indices = Vec::with_capacity(nnz);
        let mut row_offsets = Vec::with_capacity(num_rows + 1);
        let mut interner = ValueInterner::default();
        row_offsets.push(0);
        for row in rows {
            for (c, v) in row {
                col_indices.push(c);
                value_indices.push(interner.intern(v));
            }
            row_offsets.push(col_indices.len());
        }
        Self {
            num_rows,
            num_cols,
            col_indices,
            value_indices,
            value_table: interner.into_table(),
            row_offsets,
        }
    }

    /// Assemble directly from dictionary-encoded arrays (the builder's output).
    pub fn from_dict(
        num_cols: usize,
        col_indices: Vec<u32>,
        value_indices: Vec<u32>,
        value_table: Vec<F128>,
        row_offsets: Vec<usize>,
    ) -> Self {
        Self {
            num_rows: row_offsets.len() - 1,
            num_cols,
            col_indices,
            value_indices,
            value_table,
            row_offsets,
        }
    }

    /// Identity matrix of side `k`.
    pub fn identity(k: usize) -> Self {
        Self {
            num_rows: k,
            num_cols: k,
            col_indices: (0..k as u32).collect(),
            value_indices: vec![0u32; k],
            value_table: vec![F128::ONE],
            row_offsets: (0..=k).collect(),
        }
    }

    /// All-zero matrix of side `k`.
    pub fn zero(k: usize) -> Self {
        Self {
            num_rows: k,
            num_cols: k,
            col_indices: Vec::new(),
            value_indices: Vec::new(),
            value_table: Vec::new(),
            row_offsets: vec![0usize; k + 1],
        }
    }

    pub fn nnz(&self) -> usize {
        self.value_indices.len()
    }

    /// Number of distinct coefficient values (the dictionary size).
    pub fn distinct_values(&self) -> usize {
        self.value_table.len()
    }

    /// Entry-index range `[start, end)` of row `r`.
    #[inline]
    pub fn row_range(&self, r: usize) -> std::ops::Range<usize> {
        self.row_offsets[r]..self.row_offsets[r + 1]
    }

    /// Column indices of row `r`.
    #[inline]
    pub fn row_cols(&self, r: usize) -> &[u32] {
        &self.col_indices[self.row_range(r)]
    }

    /// Number of nonzero entries in row `r`.
    #[inline]
    pub fn row_len(&self, r: usize) -> usize {
        self.row_offsets[r + 1] - self.row_offsets[r]
    }

    /// `(column, coefficient)` pairs of row `r`, in stored order (coefficients
    /// decoded through the value table). This is the primary accessor — the
    /// dictionary encoding is transparent to callers.
    #[inline]
    pub fn row(&self, r: usize) -> impl Iterator<Item = (u32, F128)> + '_ {
        let range = self.row_range(r);
        let table = &self.value_table;
        self.col_indices[range.clone()].iter().copied().zip(
            self.value_indices[range]
                .iter()
                .map(move |&vi| table[vi as usize]),
        )
    }
}

/// Block-diagonal R1CS instance with an F128 witness.
///
/// Total witness length `N = 2^m` **field elements** (not bits). The
/// constraint hypercube also has `2^m` points — one deg-2 constraint per
/// witness element under the `C = I` convention.
#[derive(Debug)]
pub struct FieldR1cs {
    /// log2 of the witness length in F128 elements (= log2 constraint count).
    pub m: usize,
    /// log2 of the base-matrix side `k`.
    pub k_log: usize,
    /// Univariate-skip dimension (`k_skip ≤ k_log`); the protocol standard is
    /// [`crate::zerocheck::K_SKIP`] = 6.
    pub k_skip: usize,
    /// Rows `[0, useful_rows)` of each block carry real witness data; rows
    /// `[useful_rows, 2^k_log)` are zero padding with empty matrix rows.
    /// Default `1 << k_log` (no padding).
    pub useful_rows: usize,
    pub a_0: SparseFieldMatrix,
    pub b_0: SparseFieldMatrix,
    /// Column of a constant-one wire pinned across all blocks, or `None`.
    /// See [`LincheckCircuit::const_pin_col`].
    pub const_pin: Option<usize>,
    /// Lazily-cached statement digest (see [`Self::statement_digest`]).
    #[doc(hidden)]
    pub digest_cache: std::sync::OnceLock<[u8; 32]>,
    /// Lazily-cached CSC lincheck circuit (see [`Self::csc_lincheck_circuit`]).
    #[doc(hidden)]
    pub csc_cache: std::sync::OnceLock<FieldCscCircuit>,
}

impl Clone for FieldR1cs {
    fn clone(&self) -> Self {
        Self {
            m: self.m,
            k_log: self.k_log,
            k_skip: self.k_skip,
            useful_rows: self.useful_rows,
            a_0: self.a_0.clone(),
            b_0: self.b_0.clone(),
            const_pin: self.const_pin,
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical matrix artifact codec
// ---------------------------------------------------------------------------

/// Magic prefix of the canonical on-disk [`FieldR1cs`] artifact.
pub const FIELD_R1CS_ARTIFACT_MAGIC: [u8; 8] = *b"NOIDR1CS";
/// First canonical artifact version. All integers, including field limbs, are
/// encoded little-endian.
pub const FIELD_R1CS_ARTIFACT_VERSION: u16 = 2;

/// Magic prefix of the relocatable startup-packed image emitted by
/// [`CompactFieldR1cs::encode_startup_packed_image`].
///
/// This is deliberately a different format from the canonical artifact. The
/// canonical artifact is the release authority and remains the source of the
/// statement digest; this image is only a build-produced runtime layout.
pub const FIELD_R1CS_PACKED_IMAGE_MAGIC: [u8; 8] = *b"NOIDPKD\0";
/// First startup-packed image version. All scalar and array elements are
/// encoded little-endian and the image contains no native pointers.
pub const FIELD_R1CS_PACKED_IMAGE_VERSION: u16 = 1;

/// Opaque metadata emitted only after the canonical-pack preflight has
/// structurally authenticated one exact embedded matrix leaf.
///
/// This is not a portable proof or a filesystem trust record.  It is a
/// capability for the executable-embedded path: the release build stages the
/// approved bytes into `OUT_DIR` and emits this metadata beside the matching
/// `include_bytes!`. Runtime code may then repeat the cheap canonical
/// header/index checks without repeating the multi-second structural Poseidon
/// scan already completed by pack preflight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildAuthenticatedFieldR1csSeal {
    shape: crate::proof::FieldShape,
    statement_digest: [u8; 32],
    canonical_bytes: usize,
}

impl BuildAuthenticatedFieldR1csSeal {
    /// Construct metadata accepted by the pack-preflight authority.
    ///
    /// Ordinary runtime/file loaders must never derive these fields from the
    /// bytes they are about to open.  They must use [`CompactFieldR1cs::open`]
    /// instead.  This constructor is public solely because generated Rust in
    /// the final node crate materializes the build result.
    ///
    /// # Safety
    ///
    /// Pack preflight must first run [`CompactFieldR1cs::open`]
    /// successfully over the exact canonical bytes embedded beside this
    /// value, with exactly `shape` and `statement_digest`, and bind
    /// `canonical_bytes` to that complete immutable payload. Forging this
    /// capability would let proving code trust an unrelated relation identity.
    #[doc(hidden)]
    pub const unsafe fn from_release_build(
        shape: crate::proof::FieldShape,
        statement_digest: [u8; 32],
        canonical_bytes: usize,
    ) -> Self {
        Self {
            shape,
            statement_digest,
            canonical_bytes,
        }
    }

    pub const fn shape(self) -> crate::proof::FieldShape {
        self.shape
    }

    pub const fn statement_digest(self) -> [u8; 32] {
        self.statement_digest
    }

    pub const fn canonical_bytes(self) -> usize {
        self.canonical_bytes
    }
}

/// Rows per planar row group. Equal to [`DIGEST_SPAN_ROWS`] so the bounded
/// streaming scanner walks exactly one group per digest span.
const ARTIFACT_GROUP_ROWS: usize = DIGEST_SPAN_ROWS;

// The complete fixed header is deliberately 128 bytes:
// magic/version/header-size/total-size, the FieldR1cs parameters, then two
// five-u64 matrix descriptors (rows, columns, nnz, values, offsets).
const FIELD_R1CS_ARTIFACT_HEADER_BYTES: usize = 128;
const FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES: usize = 64 * 1024;

/// Identifies one base matrix in a malformed artifact error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldR1csArtifactMatrix {
    A,
    B,
}

/// Fail-closed error returned by the canonical matrix artifact codec.
#[derive(Debug)]
pub enum FieldR1csArtifactError {
    Io(io::Error),
    Truncated {
        offset: u64,
        needed: usize,
    },
    TrailingBytes,
    InvalidMagic,
    UnsupportedVersion {
        actual: u16,
    },
    InvalidHeaderLength {
        actual: u16,
    },
    InvalidShape(&'static str),
    ShapeMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    MatrixDimensions {
        matrix: FieldR1csArtifactMatrix,
        expected: u64,
        rows: u64,
        cols: u64,
    },
    MatrixLengthMismatch {
        matrix: FieldR1csArtifactMatrix,
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    CountOutOfRange {
        matrix: FieldR1csArtifactMatrix,
        field: &'static str,
        actual: u64,
        maximum: u64,
    },
    LengthArithmetic,
    TotalLengthMismatch {
        declared: u64,
        computed: u64,
    },
    TooLarge {
        actual: u64,
        max: usize,
    },
    Allocation {
        matrix: FieldR1csArtifactMatrix,
        field: &'static str,
    },
    InvalidRowOffset {
        matrix: FieldR1csArtifactMatrix,
        index: usize,
        previous: usize,
        actual: u64,
        nnz: usize,
    },
    InvalidColumn {
        matrix: FieldR1csArtifactMatrix,
        index: usize,
        actual: u32,
        num_cols: usize,
    },
    InvalidValueIndex {
        matrix: FieldR1csArtifactMatrix,
        index: usize,
        actual: u32,
        value_count: usize,
    },
    NonCanonicalValueCount {
        matrix: FieldR1csArtifactMatrix,
        values: u64,
        nnz: u64,
    },
    NonCanonicalValueIndexOrder {
        matrix: FieldR1csArtifactMatrix,
        index: usize,
        expected_next: usize,
        actual: u32,
    },
    UnusedCoefficient {
        matrix: FieldR1csArtifactMatrix,
        index: usize,
    },
    ZeroCoefficient {
        matrix: FieldR1csArtifactMatrix,
        index: usize,
    },
    DuplicateCoefficient {
        matrix: FieldR1csArtifactMatrix,
        first: usize,
        duplicate: usize,
    },
    StructuralDigestMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    BackingLengthMismatch {
        expected: u64,
        actual: u64,
    },
    BackingFileChanged,
    StreamingDictionaryTooLarge {
        matrix: FieldR1csArtifactMatrix,
        actual: u64,
        maximum: u64,
    },
    /// A planar varint stream is malformed: truncated inside one encoding,
    /// non-minimal (a shorter encoding of the same value exists), or wider
    /// than the target type. The artifact has exactly one canonical byte
    /// encoding; anything else is rejected, never re-normalized.
    InvalidVarint {
        matrix: FieldR1csArtifactMatrix,
        stream: &'static str,
        index: usize,
        reason: &'static str,
    },
    /// One row-group header declares sub-stream byte lengths that do not fit
    /// the remaining section budget or do not match the decoded content.
    GroupLength {
        matrix: FieldR1csArtifactMatrix,
        group: usize,
        declared: u64,
        budget: u64,
    },
    MatrixClaimShape(&'static str),
    MatrixEvaluatorAlreadyConsumed,
}

impl fmt::Display for FieldR1csArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "FieldR1cs artifact I/O: {error}"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for FieldR1csArtifactError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for FieldR1csArtifactError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug)]
struct ArtifactMatrixCounts {
    rows: u64,
    cols: u64,
    nnz: u64,
    values: u64,
    /// Exact encoded byte length of this matrix's planar section (dictionary
    /// plus all row groups). Occupies the header slot that format v1 used for
    /// the row-offset count.
    section_bytes: u64,
}

impl ArtifactMatrixCounts {
    /// Largest legal planar section for these counts: the dictionary, one
    /// 16-byte group header per row group, and worst-case varint widths
    /// (5 bytes per row count, 5 per first column, 5 per in-row delta, 5 per
    /// value index). Any declared `section_bytes` above this is rejected
    /// before allocation.
    fn max_section_bytes(self) -> Result<u64, FieldR1csArtifactError> {
        let groups = self.rows.div_ceil(ARTIFACT_GROUP_ROWS as u64);
        self.values
            .checked_mul(16)
            .and_then(|bytes| groups.checked_mul(16).and_then(|n| bytes.checked_add(n)))
            .and_then(|bytes| self.rows.checked_mul(10).and_then(|n| bytes.checked_add(n)))
            .and_then(|bytes| self.nnz.checked_mul(10).and_then(|n| bytes.checked_add(n)))
            .ok_or(FieldR1csArtifactError::LengthArithmetic)
    }

    /// Smallest legal planar section: the dictionary and one 16-byte header
    /// plus at least one count byte per row for every group.
    fn min_section_bytes(self) -> Result<u64, FieldR1csArtifactError> {
        let groups = self.rows.div_ceil(ARTIFACT_GROUP_ROWS as u64);
        self.values
            .checked_mul(16)
            .and_then(|bytes| groups.checked_mul(16).and_then(|n| bytes.checked_add(n)))
            .and_then(|bytes| bytes.checked_add(self.rows))
            .ok_or(FieldR1csArtifactError::LengthArithmetic)
    }

    fn validate_section_bytes(
        self,
        side: FieldR1csArtifactMatrix,
    ) -> Result<(), FieldR1csArtifactError> {
        let minimum = self.min_section_bytes()?;
        let maximum = self.max_section_bytes()?;
        if self.section_bytes < minimum || self.section_bytes > maximum {
            return Err(FieldR1csArtifactError::MatrixLengthMismatch {
                matrix: side,
                field: "section_bytes",
                expected: maximum,
                actual: self.section_bytes,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct ArtifactHeader {
    total_bytes: u64,
    m: u32,
    k_log: u32,
    k_skip: u32,
    useful_rows: u64,
    const_pin_plus_one: u64,
    matrices: [ArtifactMatrixCounts; 2],
}

/// Small canonical coefficient dictionary prepared for one matrix while its
/// existing CSR arrays stay in place. Builder-produced matrices may share a
/// superset dictionary between A and B; the artifact never persists that
/// non-canonical representation.
struct CanonicalArtifactDictionary {
    by_value: std::collections::HashMap<u128, u32>,
    values: Vec<F128>,
}

impl ArtifactHeader {
    fn computed_bytes(self) -> Result<u64, FieldR1csArtifactError> {
        self.matrices
            .iter()
            .try_fold(FIELD_R1CS_ARTIFACT_HEADER_BYTES as u64, |total, matrix| {
                total
                    .checked_add(matrix.section_bytes)
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)
            })
    }
}

const fn zigzag_encode(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

const fn zigzag_decode(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

const fn varint_len(value: u64) -> u64 {
    if value == 0 {
        1
    } else {
        (70 - value.leading_zeros() as u64) / 7
    }
}

fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

/// Minimal-form LEB128 decoder over one in-memory sub-stream. Every value has
/// exactly one accepted encoding: a truncated, over-wide, or padded
/// (`0x80 0x00`-style) encoding is rejected, so byte equality and value
/// equality coincide for the whole stream.
struct SliceVarints<'a> {
    bytes: &'a [u8],
    at: usize,
    matrix: FieldR1csArtifactMatrix,
    stream: &'static str,
    decoded: usize,
}

impl<'a> SliceVarints<'a> {
    fn new(bytes: &'a [u8], matrix: FieldR1csArtifactMatrix, stream: &'static str) -> Self {
        Self {
            bytes,
            at: 0,
            matrix,
            stream,
            decoded: 0,
        }
    }

    fn invalid(&self, reason: &'static str) -> FieldR1csArtifactError {
        FieldR1csArtifactError::InvalidVarint {
            matrix: self.matrix,
            stream: self.stream,
            index: self.decoded,
            reason,
        }
    }

    fn next(&mut self) -> Result<u64, FieldR1csArtifactError> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = *self
                .bytes
                .get(self.at)
                .ok_or_else(|| self.invalid("truncated"))?;
            self.at += 1;
            let payload = (byte & 0x7f) as u64;
            if shift == 63 && payload > 1 {
                return Err(self.invalid("overflow"));
            }
            value |= payload << shift;
            if byte & 0x80 == 0 {
                if payload == 0 && shift != 0 {
                    return Err(self.invalid("non-minimal"));
                }
                self.decoded += 1;
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                return Err(self.invalid("overflow"));
            }
        }
    }

    fn finish(self) -> Result<(), FieldR1csArtifactError> {
        if self.at != self.bytes.len() {
            return Err(self.invalid("trailing bytes"));
        }
        Ok(())
    }
}

fn artifact_matrix_name(index: usize) -> FieldR1csArtifactMatrix {
    if index == 0 {
        FieldR1csArtifactMatrix::A
    } else {
        FieldR1csArtifactMatrix::B
    }
}

fn checked_u64(value: usize) -> Result<u64, FieldR1csArtifactError> {
    u64::try_from(value).map_err(|_| FieldR1csArtifactError::LengthArithmetic)
}

fn validate_artifact_shape(
    m: usize,
    k_log: usize,
    k_skip: usize,
    useful_rows: usize,
    const_pin: Option<usize>,
) -> Result<usize, FieldR1csArtifactError> {
    if k_skip > k_log {
        return Err(FieldR1csArtifactError::InvalidShape("k_skip > k_log"));
    }
    if k_log > m {
        return Err(FieldR1csArtifactError::InvalidShape("k_log > m"));
    }
    if m >= usize::BITS as usize {
        return Err(FieldR1csArtifactError::InvalidShape(
            "m is outside the usize power-of-two domain",
        ));
    }
    let k = 1usize
        .checked_shl(
            u32::try_from(k_log)
                .map_err(|_| FieldR1csArtifactError::InvalidShape("k_log is too large"))?,
        )
        .ok_or(FieldR1csArtifactError::InvalidShape(
            "k_log is outside the usize power-of-two domain",
        ))?;
    if useful_rows > k {
        return Err(FieldR1csArtifactError::InvalidShape("useful_rows > k"));
    }
    if const_pin.is_some_and(|column| column >= k) {
        return Err(FieldR1csArtifactError::InvalidShape(
            "const_pin is outside the base matrix",
        ));
    }
    Ok(k)
}

fn validate_sparse_artifact_matrix(
    matrix: &SparseFieldMatrix,
    side: FieldR1csArtifactMatrix,
    k: usize,
) -> Result<(ArtifactMatrixCounts, CanonicalArtifactDictionary), FieldR1csArtifactError> {
    let expected = checked_u64(k)?;
    if matrix.num_rows != k || matrix.num_cols != k {
        return Err(FieldR1csArtifactError::MatrixDimensions {
            matrix: side,
            expected,
            rows: checked_u64(matrix.num_rows)?,
            cols: checked_u64(matrix.num_cols)?,
        });
    }
    let nnz = matrix.col_indices.len();
    if matrix.value_indices.len() != nnz {
        return Err(FieldR1csArtifactError::MatrixLengthMismatch {
            matrix: side,
            field: "value_indices",
            expected: checked_u64(nnz)?,
            actual: checked_u64(matrix.value_indices.len())?,
        });
    }
    let expected_offsets = k
        .checked_add(1)
        .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
    if matrix.row_offsets.len() != expected_offsets {
        return Err(FieldR1csArtifactError::MatrixLengthMismatch {
            matrix: side,
            field: "row_offsets",
            expected: checked_u64(expected_offsets)?,
            actual: checked_u64(matrix.row_offsets.len())?,
        });
    }
    if checked_u64(nnz)? > u32::MAX as u64 {
        return Err(FieldR1csArtifactError::CountOutOfRange {
            matrix: side,
            field: "nnz",
            actual: checked_u64(nnz)?,
            maximum: u32::MAX as u64,
        });
    }
    if checked_u64(matrix.value_table.len())? > u32::MAX as u64 {
        return Err(FieldR1csArtifactError::CountOutOfRange {
            matrix: side,
            field: "values",
            actual: checked_u64(matrix.value_table.len())?,
            maximum: u32::MAX as u64,
        });
    }

    let mut previous = 0usize;
    for (index, &actual) in matrix.row_offsets.iter().enumerate() {
        if (index == 0 && actual != 0) || actual < previous || actual > nnz {
            return Err(FieldR1csArtifactError::InvalidRowOffset {
                matrix: side,
                index,
                previous,
                actual: checked_u64(actual)?,
                nnz,
            });
        }
        previous = actual;
    }
    if previous != nnz {
        return Err(FieldR1csArtifactError::InvalidRowOffset {
            matrix: side,
            index: matrix.row_offsets.len() - 1,
            previous,
            actual: checked_u64(previous)?,
            nnz,
        });
    }
    for (index, &column) in matrix.col_indices.iter().enumerate() {
        if column as usize >= matrix.num_cols {
            return Err(FieldR1csArtifactError::InvalidColumn {
                matrix: side,
                index,
                actual: column,
                num_cols: matrix.num_cols,
            });
        }
    }
    for (index, &value_index) in matrix.value_indices.iter().enumerate() {
        if value_index as usize >= matrix.value_table.len() {
            return Err(FieldR1csArtifactError::InvalidValueIndex {
                matrix: side,
                index,
                actual: value_index,
                value_count: matrix.value_table.len(),
            });
        }
    }
    for (index, &value) in matrix.value_table.iter().enumerate() {
        if value == F128::ZERO {
            return Err(FieldR1csArtifactError::ZeroCoefficient {
                matrix: side,
                index,
            });
        }
    }

    // Re-intern by decoded coefficient in first-use order. This is bounded by
    // the small protocol coefficient alphabet and does not copy either CSR
    // index array.
    let mut dictionary = CanonicalArtifactDictionary {
        by_value: std::collections::HashMap::new(),
        values: Vec::new(),
    };
    for &source_index in &matrix.value_indices {
        let value = matrix.value_table[source_index as usize];
        let key = ((value.hi as u128) << 64) | value.lo as u128;
        if !dictionary.by_value.contains_key(&key) {
            dictionary
                .by_value
                .try_reserve(1)
                .map_err(|_| FieldR1csArtifactError::Allocation {
                    matrix: side,
                    field: "canonical coefficient map",
                })?;
            dictionary
                .values
                .try_reserve(1)
                .map_err(|_| FieldR1csArtifactError::Allocation {
                    matrix: side,
                    field: "canonical coefficient table",
                })?;
            let actual = checked_u64(dictionary.values.len())?;
            let canonical_index = u32::try_from(dictionary.values.len()).map_err(|_| {
                FieldR1csArtifactError::CountOutOfRange {
                    matrix: side,
                    field: "canonical values",
                    actual,
                    maximum: u32::MAX as u64,
                }
            })?;
            dictionary.by_value.insert(key, canonical_index);
            dictionary.values.push(value);
        }
    }

    Ok((
        ArtifactMatrixCounts {
            rows: expected,
            cols: expected,
            nnz: checked_u64(nnz)?,
            values: checked_u64(dictionary.values.len())?,
            // Filled by the writer once the planar pre-pass has sized the
            // section exactly.
            section_bytes: 0,
        },
        dictionary,
    ))
}

/// One planar row group prepared for writing: the four sub-streams of
/// [`ARTIFACT_GROUP_ROWS`] consecutive rows.
struct PlanarGroupBuffers {
    counts: Vec<u8>,
    firsts: Vec<u8>,
    deltas: Vec<u8>,
    values: Vec<u8>,
}

impl PlanarGroupBuffers {
    fn new() -> Self {
        Self {
            counts: Vec::new(),
            firsts: Vec::new(),
            deltas: Vec::new(),
            values: Vec::new(),
        }
    }

    fn clear(&mut self) {
        self.counts.clear();
        self.firsts.clear();
        self.deltas.clear();
        self.values.clear();
    }
}

/// Walk one matrix in planar group order, invoking `group` for every
/// completed row group. `PlanarRowCursor` carries the cross-group first-column
/// predictor so encoded artifacts are identical whether the walk is sized
/// (pre-pass) or written (emit pass).
struct PlanarRowCursor {
    previous_first: i64,
}

impl PlanarRowCursor {
    fn new() -> Self {
        Self { previous_first: 0 }
    }
}

fn canonical_value_index(
    matrix: &SparseFieldMatrix,
    dictionary: &CanonicalArtifactDictionary,
    entry: usize,
) -> u64 {
    let value = matrix.value_table[matrix.value_indices[entry] as usize];
    let key = ((value.hi as u128) << 64) | value.lo as u128;
    u64::from(
        dictionary
            .by_value
            .get(&key)
            .copied()
            .expect("validated coefficient was installed in canonical dictionary"),
    )
}

/// Exact planar section length for one matrix: dictionary bytes plus, per
/// group, the 16-byte header and the four sub-stream varint lengths.
fn planar_section_bytes(
    matrix: &SparseFieldMatrix,
    dictionary: &CanonicalArtifactDictionary,
) -> Result<u64, FieldR1csArtifactError> {
    let mut total = checked_u64(dictionary.values.len())?
        .checked_mul(16)
        .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
    let mut cursor = PlanarRowCursor::new();
    for group_first in (0..matrix.num_rows).step_by(ARTIFACT_GROUP_ROWS) {
        let group_rows = (matrix.num_rows - group_first).min(ARTIFACT_GROUP_ROWS);
        let mut group_bytes = 16u64;
        for row in group_first..group_first + group_rows {
            let start = matrix.row_offsets[row];
            let end = matrix.row_offsets[row + 1];
            group_bytes = group_bytes
                .checked_add(varint_len((end - start) as u64))
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            if start == end {
                continue;
            }
            let first = matrix.col_indices[start] as i64;
            group_bytes = group_bytes
                .checked_add(varint_len(zigzag_encode(first - cursor.previous_first)))
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            cursor.previous_first = first;
            let mut previous = first;
            for entry in start + 1..end {
                let column = matrix.col_indices[entry] as i64;
                group_bytes = group_bytes
                    .checked_add(varint_len(zigzag_encode(column - previous)))
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
                previous = column;
            }
            for entry in start..end {
                group_bytes = group_bytes
                    .checked_add(varint_len(canonical_value_index(matrix, dictionary, entry)))
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            }
        }
        total = total
            .checked_add(group_bytes)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
    }
    Ok(total)
}

/// Emit one matrix's planar section. Byte-for-byte the length promised by
/// [`planar_section_bytes`]: same cursor, same varint forms.
fn write_planar_section<W: Write + ?Sized>(
    writer: &mut W,
    matrix: &SparseFieldMatrix,
    dictionary: &CanonicalArtifactDictionary,
) -> Result<(), FieldR1csArtifactError> {
    write_f128_slice(writer, &dictionary.values)?;
    let mut cursor = PlanarRowCursor::new();
    let mut buffers = PlanarGroupBuffers::new();
    for group_first in (0..matrix.num_rows).step_by(ARTIFACT_GROUP_ROWS) {
        let group_rows = (matrix.num_rows - group_first).min(ARTIFACT_GROUP_ROWS);
        buffers.clear();
        for row in group_first..group_first + group_rows {
            let start = matrix.row_offsets[row];
            let end = matrix.row_offsets[row + 1];
            push_varint(&mut buffers.counts, (end - start) as u64);
            if start == end {
                continue;
            }
            let first = matrix.col_indices[start] as i64;
            push_varint(
                &mut buffers.firsts,
                zigzag_encode(first - cursor.previous_first),
            );
            cursor.previous_first = first;
            let mut previous = first;
            for entry in start + 1..end {
                let column = matrix.col_indices[entry] as i64;
                push_varint(&mut buffers.deltas, zigzag_encode(column - previous));
                previous = column;
            }
            for entry in start..end {
                push_varint(
                    &mut buffers.values,
                    canonical_value_index(matrix, dictionary, entry),
                );
            }
        }
        let mut header = [0u8; 16];
        for (slot, stream) in [
            &buffers.counts,
            &buffers.firsts,
            &buffers.deltas,
            &buffers.values,
        ]
        .iter()
        .enumerate()
        {
            let length = u32::try_from(stream.len())
                .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
            header[slot * 4..slot * 4 + 4].copy_from_slice(&length.to_le_bytes());
        }
        writer.write_all(&header)?;
        writer.write_all(&buffers.counts)?;
        writer.write_all(&buffers.firsts)?;
        writer.write_all(&buffers.deltas)?;
        writer.write_all(&buffers.values)?;
    }
    Ok(())
}

fn validate_unique_nonzero_coefficients(
    value_table: &[F128],
    matrix: FieldR1csArtifactMatrix,
) -> Result<(), FieldR1csArtifactError> {
    // A u32 permutation costs 4 bytes per 16-byte coefficient, substantially
    // less peak memory than a HashSet while preserving O(v log v) rejection
    // for a maliciously large declared dictionary.
    let mut order = Vec::new();
    order
        .try_reserve_exact(value_table.len())
        .map_err(|_| FieldR1csArtifactError::Allocation {
            matrix,
            field: "coefficient uniqueness order",
        })?;
    for (index, &value) in value_table.iter().enumerate() {
        if value == F128::ZERO {
            return Err(FieldR1csArtifactError::ZeroCoefficient { matrix, index });
        }
        order.push(
            u32::try_from(index).map_err(|_| FieldR1csArtifactError::CountOutOfRange {
                matrix,
                field: "values",
                actual: index as u64,
                maximum: u32::MAX as u64,
            })?,
        );
    }
    order.sort_unstable_by_key(|&index| {
        let value = value_table[index as usize];
        ((value.hi as u128) << 64) | value.lo as u128
    });
    for pair in order.windows(2) {
        let first = pair[0] as usize;
        let duplicate = pair[1] as usize;
        if value_table[first] == value_table[duplicate] {
            return Err(FieldR1csArtifactError::DuplicateCoefficient {
                matrix,
                first,
                duplicate,
            });
        }
    }
    Ok(())
}

fn write_f128_slice<W: Write + ?Sized>(
    writer: &mut W,
    values: &[F128],
) -> Result<(), FieldR1csArtifactError> {
    let mut scratch = [0u8; FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES];
    for chunk in values.chunks(FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES / 16) {
        for (bytes, value) in scratch.chunks_exact_mut(16).zip(chunk) {
            bytes[..8].copy_from_slice(&value.lo.to_le_bytes());
            bytes[8..].copy_from_slice(&value.hi.to_le_bytes());
        }
        writer.write_all(&scratch[..chunk.len() * 16])?;
    }
    Ok(())
}

fn read_exact_artifact<R: Read + ?Sized>(
    reader: &mut R,
    bytes: &mut [u8],
    offset: &mut u64,
) -> Result<(), FieldR1csArtifactError> {
    match reader.read_exact(bytes) {
        Ok(()) => {
            *offset = offset
                .checked_add(bytes.len() as u64)
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(FieldR1csArtifactError::Truncated {
                offset: *offset,
                needed: bytes.len(),
            })
        }
        Err(error) => Err(FieldR1csArtifactError::Io(error)),
    }
}

fn reserve_artifact_vec<T>(
    length: usize,
    matrix: FieldR1csArtifactMatrix,
    field: &'static str,
) -> Result<Vec<T>, FieldR1csArtifactError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| FieldR1csArtifactError::Allocation { matrix, field })?;
    Ok(values)
}

/// Read the byte lengths of the four planar sub-streams from one 16-byte row
/// group header and charge them against the matrix section budget.
fn read_group_header<R: Read + ?Sized>(
    reader: &mut R,
    offset: &mut u64,
    matrix: FieldR1csArtifactMatrix,
    group: usize,
    remaining_section: &mut u64,
) -> Result<[usize; 4], FieldR1csArtifactError> {
    let mut header = [0u8; 16];
    read_exact_artifact(reader, &mut header, offset)?;
    decode_group_header(&header, matrix, group, remaining_section)
}

fn decode_group_header(
    header: &[u8; 16],
    matrix: FieldR1csArtifactMatrix,
    group: usize,
    remaining_section: &mut u64,
) -> Result<[usize; 4], FieldR1csArtifactError> {
    let mut lengths = [0usize; 4];
    let mut payload = 0u64;
    for (slot, length) in lengths.iter_mut().enumerate() {
        let raw = u32::from_le_bytes(
            header[slot * 4..slot * 4 + 4]
                .try_into()
                .expect("group header length"),
        );
        *length = usize::try_from(raw).map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        payload += u64::from(raw);
    }
    let declared = payload
        .checked_add(16)
        .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
    *remaining_section =
        remaining_section
            .checked_sub(declared)
            .ok_or(FieldR1csArtifactError::GroupLength {
                matrix,
                group,
                declared,
                budget: *remaining_section,
            })?;
    Ok(lengths)
}

/// Decode one matrix from its planar section: dictionary first, then row
/// groups of [`ARTIFACT_GROUP_ROWS`] rows. Enforces the single canonical
/// encoding (minimal varints, exact sub-stream consumption, exact section
/// budget) and the same semantic invariants as format v1: row totals equal
/// `nnz`, columns inside the base matrix, first-use dictionary order, and a
/// nonzero unique coefficient table.
fn read_planar_matrix<R: Read + ?Sized>(
    reader: &mut R,
    offset: &mut u64,
    counts: ArtifactMatrixCounts,
    side: FieldR1csArtifactMatrix,
    expected_k: usize,
) -> Result<SparseFieldMatrix, FieldR1csArtifactError> {
    let nnz = usize::try_from(counts.nnz).map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
    let value_count =
        usize::try_from(counts.values).map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;

    let value_table = read_f128_vec(reader, offset, value_count, side)?;
    validate_unique_nonzero_coefficients(&value_table, side)?;
    let mut remaining_section = counts
        .section_bytes
        .checked_sub(
            checked_u64(value_count)?
                .checked_mul(16)
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?,
        )
        .ok_or(FieldR1csArtifactError::LengthArithmetic)?;

    let mut row_offsets = reserve_artifact_vec(
        expected_k
            .checked_add(1)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?,
        side,
        "row_offsets",
    )?;
    row_offsets.push(0usize);
    let mut col_indices: Vec<u32> = reserve_artifact_vec(nnz, side, "col_indices")?;
    let mut value_indices: Vec<u32> = reserve_artifact_vec(nnz, side, "value_indices")?;

    let mut payload: Vec<u8> = Vec::new();
    let mut previous_first = 0i64;
    let mut next_value_index = 0usize;
    for group_first in (0..expected_k).step_by(ARTIFACT_GROUP_ROWS) {
        let group = group_first / ARTIFACT_GROUP_ROWS;
        let group_rows = (expected_k - group_first).min(ARTIFACT_GROUP_ROWS);
        let lengths = read_group_header(reader, offset, side, group, &mut remaining_section)?;
        let payload_len = lengths.iter().sum::<usize>();
        if payload.len() < payload_len {
            payload
                .try_reserve_exact(payload_len - payload.len())
                .map_err(|_| FieldR1csArtifactError::Allocation {
                    matrix: side,
                    field: "planar group payload",
                })?;
            payload.resize(payload_len, 0);
        }
        read_exact_artifact(reader, &mut payload[..payload_len], offset)?;
        let (counts_bytes, rest) = payload[..payload_len].split_at(lengths[0]);
        let (firsts_bytes, rest) = rest.split_at(lengths[1]);
        let (deltas_bytes, values_bytes) = rest.split_at(lengths[2]);
        let mut counts_stream = SliceVarints::new(counts_bytes, side, "counts");
        let mut firsts_stream = SliceVarints::new(firsts_bytes, side, "firsts");
        let mut deltas_stream = SliceVarints::new(deltas_bytes, side, "deltas");
        let mut values_stream = SliceVarints::new(values_bytes, side, "values");

        for local_row in 0..group_rows {
            let row = group_first + local_row;
            let previous_entries = col_indices.len();
            let count = counts_stream.next()?;
            let count = usize::try_from(count)
                .ok()
                .filter(|count| nnz - previous_entries >= *count)
                .ok_or(FieldR1csArtifactError::InvalidRowOffset {
                    matrix: side,
                    index: row,
                    previous: previous_entries,
                    actual: count.saturating_add(previous_entries as u64),
                    nnz,
                })?;
            if count > 0 {
                let mut column = previous_first
                    .checked_add(zigzag_decode(firsts_stream.next()?))
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
                previous_first = column;
                for entry in 0..count {
                    if entry > 0 {
                        column = column
                            .checked_add(zigzag_decode(deltas_stream.next()?))
                            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
                    }
                    if column < 0 || column >= expected_k as i64 {
                        return Err(FieldR1csArtifactError::InvalidColumn {
                            matrix: side,
                            index: col_indices.len(),
                            actual: column.clamp(0, u32::MAX as i64) as u32,
                            num_cols: expected_k,
                        });
                    }
                    col_indices.push(column as u32);
                }
                for _ in 0..count {
                    let raw = values_stream.next()?;
                    let value_index = usize::try_from(raw)
                        .ok()
                        .filter(|index| *index < value_count)
                        .ok_or(FieldR1csArtifactError::InvalidValueIndex {
                            matrix: side,
                            index: value_indices.len(),
                            actual: raw.min(u32::MAX as u64) as u32,
                            value_count,
                        })?;
                    if value_index > next_value_index {
                        return Err(FieldR1csArtifactError::NonCanonicalValueIndexOrder {
                            matrix: side,
                            index: value_indices.len(),
                            expected_next: next_value_index,
                            actual: value_index as u32,
                        });
                    }
                    if value_index == next_value_index {
                        next_value_index += 1;
                    }
                    value_indices.push(value_index as u32);
                }
            }
            row_offsets.push(col_indices.len());
        }
        counts_stream.finish()?;
        firsts_stream.finish()?;
        deltas_stream.finish()?;
        values_stream.finish()?;
    }
    if remaining_section != 0 {
        return Err(FieldR1csArtifactError::MatrixLengthMismatch {
            matrix: side,
            field: "section_bytes",
            expected: counts.section_bytes,
            actual: counts.section_bytes - remaining_section,
        });
    }
    if col_indices.len() != nnz {
        return Err(FieldR1csArtifactError::InvalidRowOffset {
            matrix: side,
            index: expected_k,
            previous: col_indices.len(),
            actual: col_indices.len() as u64,
            nnz,
        });
    }
    if next_value_index != value_count {
        return Err(FieldR1csArtifactError::UnusedCoefficient {
            matrix: side,
            index: next_value_index,
        });
    }
    Ok(SparseFieldMatrix {
        num_rows: expected_k,
        num_cols: expected_k,
        col_indices,
        value_indices,
        value_table,
        row_offsets,
    })
}

fn read_f128_vec<R: Read + ?Sized>(
    reader: &mut R,
    offset: &mut u64,
    length: usize,
    matrix: FieldR1csArtifactMatrix,
) -> Result<Vec<F128>, FieldR1csArtifactError> {
    let mut values = reserve_artifact_vec(length, matrix, "value_table")?;
    let mut scratch = [0u8; FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES];
    while values.len() < length {
        let count = (length - values.len()).min(FIELD_R1CS_ARTIFACT_IO_CHUNK_BYTES / 16);
        read_exact_artifact(reader, &mut scratch[..count * 16], offset)?;
        for bytes in scratch[..count * 16].chunks_exact(16) {
            let value = F128 {
                lo: u64::from_le_bytes(bytes[..8].try_into().expect("low limb")),
                hi: u64::from_le_bytes(bytes[8..].try_into().expect("high limb")),
            };
            if value == F128::ZERO {
                return Err(FieldR1csArtifactError::ZeroCoefficient {
                    matrix,
                    index: values.len(),
                });
            }
            values.push(value);
        }
    }
    Ok(values)
}

fn push_header_u16(
    header: &mut [u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES],
    at: &mut usize,
    value: u16,
) {
    header[*at..*at + 2].copy_from_slice(&value.to_le_bytes());
    *at += 2;
}

fn push_header_u32(
    header: &mut [u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES],
    at: &mut usize,
    value: u32,
) {
    header[*at..*at + 4].copy_from_slice(&value.to_le_bytes());
    *at += 4;
}

fn push_header_u64(
    header: &mut [u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES],
    at: &mut usize,
    value: u64,
) {
    header[*at..*at + 8].copy_from_slice(&value.to_le_bytes());
    *at += 8;
}

fn take_header_u16(header: &[u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES], at: &mut usize) -> u16 {
    let value = u16::from_le_bytes(header[*at..*at + 2].try_into().expect("header u16"));
    *at += 2;
    value
}

fn take_header_u32(header: &[u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES], at: &mut usize) -> u32 {
    let value = u32::from_le_bytes(header[*at..*at + 4].try_into().expect("header u32"));
    *at += 4;
    value
}

fn take_header_u64(header: &[u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES], at: &mut usize) -> u64 {
    let value = u64::from_le_bytes(header[*at..*at + 8].try_into().expect("header u64"));
    *at += 8;
    value
}

impl FieldR1cs {
    /// Stream this canonical matrix artifact to `writer` without constructing
    /// a second serialized matrix in memory.
    ///
    /// The writer is expected to be buffered by the caller when it is a raw
    /// file. This method itself uses only one fixed 64-KiB conversion buffer.
    pub fn write_artifact<W: Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<(), FieldR1csArtifactError> {
        let k = validate_artifact_shape(
            self.m,
            self.k_log,
            self.k_skip,
            self.useful_rows,
            self.const_pin,
        )?;
        let (mut a_counts, a_dictionary) =
            validate_sparse_artifact_matrix(&self.a_0, FieldR1csArtifactMatrix::A, k)?;
        let (mut b_counts, b_dictionary) =
            validate_sparse_artifact_matrix(&self.b_0, FieldR1csArtifactMatrix::B, k)?;
        a_counts.section_bytes = planar_section_bytes(&self.a_0, &a_dictionary)?;
        b_counts.section_bytes = planar_section_bytes(&self.b_0, &b_dictionary)?;
        let matrices = [a_counts, b_counts];
        let m = u32::try_from(self.m)
            .map_err(|_| FieldR1csArtifactError::InvalidShape("m does not fit u32"))?;
        let k_log = u32::try_from(self.k_log)
            .map_err(|_| FieldR1csArtifactError::InvalidShape("k_log does not fit u32"))?;
        let k_skip = u32::try_from(self.k_skip)
            .map_err(|_| FieldR1csArtifactError::InvalidShape("k_skip does not fit u32"))?;
        let const_pin_plus_one = match self.const_pin {
            None => 0,
            Some(column) => checked_u64(
                column
                    .checked_add(1)
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)?,
            )?,
        };
        let mut artifact = ArtifactHeader {
            total_bytes: 0,
            m,
            k_log,
            k_skip,
            useful_rows: checked_u64(self.useful_rows)?,
            const_pin_plus_one,
            matrices,
        };
        artifact.total_bytes = artifact.computed_bytes()?;

        let mut header = [0u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES];
        header[..FIELD_R1CS_ARTIFACT_MAGIC.len()].copy_from_slice(&FIELD_R1CS_ARTIFACT_MAGIC);
        let mut at = FIELD_R1CS_ARTIFACT_MAGIC.len();
        push_header_u16(&mut header, &mut at, FIELD_R1CS_ARTIFACT_VERSION);
        push_header_u16(
            &mut header,
            &mut at,
            FIELD_R1CS_ARTIFACT_HEADER_BYTES as u16,
        );
        push_header_u64(&mut header, &mut at, artifact.total_bytes);
        push_header_u32(&mut header, &mut at, artifact.m);
        push_header_u32(&mut header, &mut at, artifact.k_log);
        push_header_u32(&mut header, &mut at, artifact.k_skip);
        push_header_u64(&mut header, &mut at, artifact.useful_rows);
        push_header_u64(&mut header, &mut at, artifact.const_pin_plus_one);
        for matrix in artifact.matrices {
            push_header_u64(&mut header, &mut at, matrix.rows);
            push_header_u64(&mut header, &mut at, matrix.cols);
            push_header_u64(&mut header, &mut at, matrix.nnz);
            push_header_u64(&mut header, &mut at, matrix.values);
            push_header_u64(&mut header, &mut at, matrix.section_bytes);
        }
        debug_assert_eq!(at, FIELD_R1CS_ARTIFACT_HEADER_BYTES);
        writer.write_all(&header)?;

        for (matrix, dictionary) in [(&self.a_0, &a_dictionary), (&self.b_0, &b_dictionary)] {
            write_planar_section(writer, matrix, dictionary)?;
        }
        Ok(())
    }

    /// Load one canonical matrix artifact under local shape and structural
    /// digest authority.
    ///
    /// Both descriptors and the complete byte arithmetic are checked against
    /// `max_bytes` before the first matrix vector is allocated. The returned
    /// object has empty digest and CSC caches; in particular the externally
    /// supplied digest is never installed into the seedable digest cache.
    pub fn read_artifact<R: Read + ?Sized>(
        reader: &mut R,
        expected_shape: crate::proof::FieldShape,
        expected_structural_digest: [u8; 32],
        max_bytes: usize,
    ) -> Result<Self, FieldR1csArtifactError> {
        let r1cs = Self::read_artifact_undigested(reader, expected_shape, max_bytes)?;
        let actual_digest = r1cs.structural_statement_digest();
        if actual_digest != expected_structural_digest {
            return Err(FieldR1csArtifactError::StructuralDigestMismatch {
                expected: expected_structural_digest,
                actual: actual_digest,
            });
        }
        Ok(r1cs)
    }

    /// Parse and canonically validate an artifact without asserting a
    /// protocol statement identity. This is intended for diagnostics which
    /// compute/report the structural digest after decoding; acceptance paths
    /// must use [`Self::read_artifact`] or [`CompactFieldR1cs::open`].
    /// Unlike the former established-digest fast path, this never seeds the
    /// digest cache from caller-controlled bytes.
    pub fn read_artifact_unbound<R: Read + ?Sized>(
        reader: &mut R,
        expected_shape: crate::proof::FieldShape,
        max_bytes: usize,
    ) -> Result<Self, FieldR1csArtifactError> {
        Self::read_artifact_undigested(reader, expected_shape, max_bytes)
    }

    /// Crate-private decode of canonical bytes whose structural identity was
    /// already established by an opaque core value. Currently the sole caller
    /// is [`CompactFieldR1cs::decode_resident_authenticated`], whose canonical
    /// artifact was fully scanned by [`CompactFieldR1cs::open`] before any
    /// byte-proven zero suffix was trimmed. Keeping this private prevents
    /// filesystem metadata or a caller-seeded digest from becoming an
    /// authentication capability.
    pub(crate) fn read_artifact_with_established_digest<R: Read + ?Sized>(
        reader: &mut R,
        expected_shape: crate::proof::FieldShape,
        established_digest: [u8; 32],
        max_bytes: usize,
    ) -> Result<Self, FieldR1csArtifactError> {
        let r1cs = Self::read_artifact_undigested(reader, expected_shape, max_bytes)?;
        r1cs.seed_statement_digest(established_digest);
        Ok(r1cs)
    }

    fn read_artifact_undigested<R: Read + ?Sized>(
        reader: &mut R,
        expected_shape: crate::proof::FieldShape,
        max_bytes: usize,
    ) -> Result<Self, FieldR1csArtifactError> {
        if max_bytes < FIELD_R1CS_ARTIFACT_HEADER_BYTES {
            return Err(FieldR1csArtifactError::TooLarge {
                actual: FIELD_R1CS_ARTIFACT_HEADER_BYTES as u64,
                max: max_bytes,
            });
        }
        let expected_k = validate_artifact_shape(
            expected_shape.m,
            expected_shape.k_log,
            expected_shape.k_skip,
            0,
            expected_shape.const_pin,
        )?;
        let expected_k_u64 = checked_u64(expected_k)?;

        let mut offset = 0u64;
        let mut header_bytes = [0u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES];
        read_exact_artifact(reader, &mut header_bytes, &mut offset)?;
        if header_bytes[..FIELD_R1CS_ARTIFACT_MAGIC.len()] != FIELD_R1CS_ARTIFACT_MAGIC {
            return Err(FieldR1csArtifactError::InvalidMagic);
        }
        let mut at = FIELD_R1CS_ARTIFACT_MAGIC.len();
        let version = take_header_u16(&header_bytes, &mut at);
        if version != FIELD_R1CS_ARTIFACT_VERSION {
            return Err(FieldR1csArtifactError::UnsupportedVersion { actual: version });
        }
        let header_length = take_header_u16(&header_bytes, &mut at);
        if header_length as usize != FIELD_R1CS_ARTIFACT_HEADER_BYTES {
            return Err(FieldR1csArtifactError::InvalidHeaderLength {
                actual: header_length,
            });
        }
        let total_bytes = take_header_u64(&header_bytes, &mut at);
        let m = take_header_u32(&header_bytes, &mut at);
        let k_log = take_header_u32(&header_bytes, &mut at);
        let k_skip = take_header_u32(&header_bytes, &mut at);
        let useful_rows = take_header_u64(&header_bytes, &mut at);
        let const_pin_plus_one = take_header_u64(&header_bytes, &mut at);
        let mut matrices = [ArtifactMatrixCounts {
            rows: 0,
            cols: 0,
            nnz: 0,
            values: 0,
            section_bytes: 0,
        }; 2];
        for matrix in &mut matrices {
            matrix.rows = take_header_u64(&header_bytes, &mut at);
            matrix.cols = take_header_u64(&header_bytes, &mut at);
            matrix.nnz = take_header_u64(&header_bytes, &mut at);
            matrix.values = take_header_u64(&header_bytes, &mut at);
            matrix.section_bytes = take_header_u64(&header_bytes, &mut at);
        }
        debug_assert_eq!(at, FIELD_R1CS_ARTIFACT_HEADER_BYTES);
        let artifact = ArtifactHeader {
            total_bytes,
            m,
            k_log,
            k_skip,
            useful_rows,
            const_pin_plus_one,
            matrices,
        };

        let compare_shape = |field: &'static str,
                             expected: usize,
                             actual: u64|
         -> Result<(), FieldR1csArtifactError> {
            let expected = checked_u64(expected)?;
            if actual != expected {
                return Err(FieldR1csArtifactError::ShapeMismatch {
                    field,
                    expected,
                    actual,
                });
            }
            Ok(())
        };
        compare_shape("m", expected_shape.m, u64::from(artifact.m))?;
        compare_shape("k_log", expected_shape.k_log, u64::from(artifact.k_log))?;
        compare_shape("k_skip", expected_shape.k_skip, u64::from(artifact.k_skip))?;
        let expected_pin_plus_one = match expected_shape.const_pin {
            None => 0,
            Some(column) => checked_u64(
                column
                    .checked_add(1)
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)?,
            )?,
        };
        if artifact.const_pin_plus_one != expected_pin_plus_one {
            return Err(FieldR1csArtifactError::ShapeMismatch {
                field: "const_pin",
                expected: expected_pin_plus_one,
                actual: artifact.const_pin_plus_one,
            });
        }
        let useful_rows = usize::try_from(artifact.useful_rows)
            .map_err(|_| FieldR1csArtifactError::InvalidShape("useful_rows does not fit usize"))?;
        validate_artifact_shape(
            expected_shape.m,
            expected_shape.k_log,
            expected_shape.k_skip,
            useful_rows,
            expected_shape.const_pin,
        )?;

        for (index, matrix) in artifact.matrices.iter().copied().enumerate() {
            let side = artifact_matrix_name(index);
            if matrix.rows != expected_k_u64 || matrix.cols != expected_k_u64 {
                return Err(FieldR1csArtifactError::MatrixDimensions {
                    matrix: side,
                    expected: expected_k_u64,
                    rows: matrix.rows,
                    cols: matrix.cols,
                });
            }
            for (field, count) in [("nnz", matrix.nnz), ("values", matrix.values)] {
                if count > u32::MAX as u64 {
                    return Err(FieldR1csArtifactError::CountOutOfRange {
                        matrix: side,
                        field,
                        actual: count,
                        maximum: u32::MAX as u64,
                    });
                }
            }
            if matrix.values > matrix.nnz || (matrix.nnz != 0 && matrix.values == 0) {
                return Err(FieldR1csArtifactError::NonCanonicalValueCount {
                    matrix: side,
                    values: matrix.values,
                    nnz: matrix.nnz,
                });
            }
            matrix.validate_section_bytes(side)?;
        }

        let computed_bytes = artifact.computed_bytes()?;
        if artifact.total_bytes != computed_bytes {
            return Err(FieldR1csArtifactError::TotalLengthMismatch {
                declared: artifact.total_bytes,
                computed: computed_bytes,
            });
        }
        let max_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
        if computed_bytes > max_u64 {
            return Err(FieldR1csArtifactError::TooLarge {
                actual: computed_bytes,
                max: max_bytes,
            });
        }

        let mut decoded = Vec::with_capacity(2);
        for (index, counts) in artifact.matrices.iter().copied().enumerate() {
            let side = artifact_matrix_name(index);
            decoded.push(read_planar_matrix(
                reader,
                &mut offset,
                counts,
                side,
                expected_k,
            )?);
        }
        debug_assert_eq!(offset, computed_bytes);

        let mut trailing = [0u8; 1];
        loop {
            match reader.read(&mut trailing) {
                Ok(0) => break,
                Ok(_) => return Err(FieldR1csArtifactError::TrailingBytes),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(FieldR1csArtifactError::Io(error)),
            }
        }

        let b_0 = decoded.pop().expect("two matrices decoded");
        let a_0 = decoded.pop().expect("two matrices decoded");
        Ok(Self {
            m: expected_shape.m,
            k_log: expected_shape.k_log,
            k_skip: expected_shape.k_skip,
            useful_rows,
            a_0,
            b_0,
            const_pin: expected_shape.const_pin,
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        })
    }

    pub fn n_outer(&self) -> usize {
        1usize << self.n_log()
    }
    pub fn n_log(&self) -> usize {
        self.m - self.k_log
    }
    pub fn k(&self) -> usize {
        1usize << self.k_log
    }
    /// Total witness length in F128 elements.
    pub fn n(&self) -> usize {
        1usize << self.m
    }

    /// Structural validation: matrix shapes, `k_skip ≤ k_log ≤ m`,
    /// `useful_rows ≤ k`, `const_pin < k`.
    pub fn validate_shape(&self) {
        let k = self.k();
        assert!(self.k_skip <= self.k_log, "k_skip > k_log");
        assert!(self.k_log <= self.m, "k_log > m");
        assert!(self.useful_rows <= k, "useful_rows > k");
        assert_eq!(self.a_0.num_rows, k);
        assert_eq!(self.a_0.num_cols, k);
        assert_eq!(self.b_0.num_rows, k);
        assert_eq!(self.b_0.num_cols, k);
        if let Some(col) = self.const_pin {
            assert!(col < k, "const_pin out of range");
        }
    }

    /// `a = (I ⊗ A_0) · z` over F128.
    pub fn apply_a(&self, z: &[F128]) -> Vec<F128> {
        apply_block_diag_field(&self.a_0, z, self.k_log)
    }

    /// `b = (I ⊗ B_0) · z` over F128.
    pub fn apply_b(&self, z: &[F128]) -> Vec<F128> {
        apply_block_diag_field(&self.b_0, z, self.k_log)
    }

    /// Check `(A·z) ⊙ (B·z) = z` per element (`C = I`).
    pub fn satisfies(&self, z: &[F128]) -> bool {
        assert_eq!(z.len(), self.n());
        let a = self.apply_a(z);
        let b = self.apply_b(z);
        a.iter()
            .zip(b.iter())
            .zip(z.iter())
            .all(|((ai, bi), zi)| *ai * *bi == *zi)
    }

    /// Build a [`FlipBattery`] over this instance and an honest witness —
    /// the fast path for wire-flip mutation gates (`O(column degree)` per
    /// flip instead of a full [`Self::satisfies`] pass).
    pub fn flip_battery(&self, z: &[F128]) -> FlipBattery<'_> {
        FlipBattery::new(self, z)
    }

    /// Poseidon2b hash of the instance (parameters + coefficient matrices).
    /// Binds the Fiat-Shamir transcript to the statement being proved.
    ///
    /// Two-level chunked construction: matrix rows are serialized in fixed
    /// [`DIGEST_SPAN_ROWS`]-row spans, each span hashed independently (in
    /// parallel — a big instance serializes to hundreds of MB, which a single
    /// sequential sponge would take tens of seconds to absorb, and this way
    /// the full serialization is never materialized at once), and the top
    /// hash absorbs the header fields plus the span digests in order. The
    /// encoding stays injective: the header fixes both matrices' row counts
    /// (hence the span count), every row is length-prefixed inside its span,
    /// and span digests are fixed-width.
    ///
    /// For production verifier-trace shapes the matrix is a protocol
    /// constant, so this value is a per-shape-class constant: compute it
    /// once and install it on fresh instances with
    /// [`Self::seed_statement_digest`] instead of re-hashing per instance.
    pub fn statement_digest(&self) -> [u8; 32] {
        *self
            .digest_cache
            .get_or_init(|| self.structural_statement_digest())
    }

    /// Recompute the statement digest directly from the matrix structure,
    /// deliberately ignoring [`Self::digest_cache`].
    ///
    /// Ordinary proof construction uses [`Self::statement_digest`] so a
    /// locally established class constant can be seeded cheaply. Trust
    /// boundaries that accept a matrix supplied by another component must use
    /// this method instead: otherwise that component could seed the expected
    /// digest onto different matrix contents and bypass the local structural
    /// identity check.
    pub fn structural_statement_digest(&self) -> [u8; 32] {
        let mut top = Vec::new();
        push_u64(&mut top, self.m as u64);
        push_u64(&mut top, self.k_log as u64);
        push_u64(&mut top, self.k_skip as u64);
        push_u64(&mut top, self.useful_rows as u64);
        // Encode the pin unambiguously: 0 = None, 1 + col = Some(col).
        push_u64(&mut top, self.const_pin.map(|c| 1 + c as u64).unwrap_or(0));
        for m_0 in [&self.a_0, &self.b_0] {
            push_u64(&mut top, m_0.num_rows as u64);
            push_u64(&mut top, m_0.num_cols as u64);
            for digest in matrix_span_digests(m_0) {
                top.extend_from_slice(&digest);
            }
        }
        noid_poseidon2b::native::poseidon2b_hash_byte_slices(b"NOID/IVC/FIELD-R1CS-STMT", &[&top])
    }

    /// Install a precomputed statement digest — the per-shape-class protocol
    /// constant — skipping the content hash entirely.
    ///
    /// This is safe only after the caller has already established that the
    /// matrix contents have this identity (for example by reproducing a frozen
    /// class relation). A verifier receiving a matrix from another component
    /// must compare [`Self::structural_statement_digest`] instead of trusting
    /// this seedable cache. Panics if a different digest is already cached.
    pub fn seed_statement_digest(&self, digest: [u8; 32]) {
        if self.digest_cache.set(digest).is_err() {
            assert_eq!(
                *self.digest_cache.get().expect("cache is set"),
                digest,
                "seed_statement_digest: a different digest is already cached"
            );
        }
    }

    /// CSC-transposed `LincheckCircuit` over `(a_0, b_0)` with F128
    /// coefficients. Built lazily on first access and cached.
    pub fn csc_lincheck_circuit(&self) -> &FieldCscCircuit {
        self.csc_cache.get_or_init(|| {
            FieldCscCircuit::from_matrices(&self.a_0, &self.b_0).with_const_pin(self.const_pin)
        })
    }

    /// Release the lazily materialized CSC transpose while retaining the
    /// canonical CSR statement.  Long-lived class registries and streaming
    /// deciders call this after a proof phase so one verification cache per
    /// frozen class does not remain resident between prover jobs.
    ///
    /// The cache is purely derived data and is rebuilt on the next
    /// [`Self::csc_lincheck_circuit`] access. Returns whether a cache was
    /// present.
    pub fn release_csc_cache(&mut self) -> bool {
        self.csc_cache.take().is_some()
    }
}

// ---------------------------------------------------------------------------
// Bounded-memory seekable artifact evaluator
// ---------------------------------------------------------------------------

/// Maximum coefficient dictionary retained by the streaming verifier for one
/// base matrix. Production verifier circuits use only a few hundred distinct
/// constants; this protocol-policy cap keeps a hostile but otherwise valid
/// artifact from turning its dictionary into a second multi-gigabyte matrix.
pub const STREAMING_FIELD_R1CS_MAX_DICTIONARY_VALUES: usize = 1 << 16;

const STREAMING_FIELD_R1CS_ENTRY_CHUNK: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
struct SeekableArtifactMatrixLayout {
    side: FieldR1csArtifactMatrix,
    counts: ArtifactMatrixCounts,
    /// Coefficient dictionary position (section start).
    values_at: u64,
    /// First row-group header position (immediately after the dictionary).
    groups_at: u64,
    /// One past the last section byte.
    section_end: u64,
}

/// A canonical `FieldR1cs` artifact that remains on a seekable backing store.
///
/// Construction performs a complete canonical scan and authenticates the
/// structural statement digest without allocating CSR arrays. Every later
/// claim evaluation scans and authenticates the exact rows again, protecting
/// callers against same-length mutation after preflight. Retained memory is
/// bounded by four fixed 64-KiB varint stream windows, one 2048-entry
/// row-count window, the factorized equality tables, and one capped
/// coefficient dictionary — independent of any group lengths a hostile
/// artifact declares.
pub struct SeekableFieldR1csArtifact<R> {
    reader: R,
    shape: crate::proof::FieldShape,
    useful_rows: usize,
    total_bytes: u64,
    header_bytes: [u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES],
    layouts: [SeekableArtifactMatrixLayout; 2],
    expected_structural_digest: [u8; 32],
}

impl<R: Read + Seek> SeekableFieldR1csArtifact<R> {
    /// Open, preflight, fully validate, and structurally authenticate a
    /// canonical artifact without materializing either sparse matrix.
    pub fn open(
        reader: R,
        expected_shape: crate::proof::FieldShape,
        expected_structural_digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Self, FieldR1csArtifactError> {
        let mut artifact = Self::preflight_header(
            reader,
            expected_shape,
            expected_structural_digest,
            max_bytes,
        )?;
        artifact.scan_authenticated(None, None)?;
        Ok(artifact)
    }

    fn preflight_header(
        mut reader: R,
        expected_shape: crate::proof::FieldShape,
        expected_structural_digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Self, FieldR1csArtifactError> {
        let actual_bytes = reader.seek(SeekFrom::End(0))?;
        if actual_bytes > max_bytes {
            return Err(FieldR1csArtifactError::TooLarge {
                actual: actual_bytes,
                max: usize::try_from(max_bytes).unwrap_or(usize::MAX),
            });
        }
        if actual_bytes < FIELD_R1CS_ARTIFACT_HEADER_BYTES as u64 {
            return Err(FieldR1csArtifactError::Truncated {
                offset: actual_bytes,
                needed: FIELD_R1CS_ARTIFACT_HEADER_BYTES,
            });
        }

        reader.seek(SeekFrom::Start(0))?;
        let mut offset = 0u64;
        let mut header_bytes = [0u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES];
        read_exact_artifact(&mut reader, &mut header_bytes, &mut offset)?;
        if header_bytes[..FIELD_R1CS_ARTIFACT_MAGIC.len()] != FIELD_R1CS_ARTIFACT_MAGIC {
            return Err(FieldR1csArtifactError::InvalidMagic);
        }
        let mut at = FIELD_R1CS_ARTIFACT_MAGIC.len();
        let version = take_header_u16(&header_bytes, &mut at);
        if version != FIELD_R1CS_ARTIFACT_VERSION {
            return Err(FieldR1csArtifactError::UnsupportedVersion { actual: version });
        }
        let header_length = take_header_u16(&header_bytes, &mut at);
        if header_length as usize != FIELD_R1CS_ARTIFACT_HEADER_BYTES {
            return Err(FieldR1csArtifactError::InvalidHeaderLength {
                actual: header_length,
            });
        }
        let total_bytes = take_header_u64(&header_bytes, &mut at);
        let m = take_header_u32(&header_bytes, &mut at);
        let k_log = take_header_u32(&header_bytes, &mut at);
        let k_skip = take_header_u32(&header_bytes, &mut at);
        let useful_rows_raw = take_header_u64(&header_bytes, &mut at);
        let const_pin_plus_one = take_header_u64(&header_bytes, &mut at);
        let mut matrices = [ArtifactMatrixCounts {
            rows: 0,
            cols: 0,
            nnz: 0,
            values: 0,
            section_bytes: 0,
        }; 2];
        for matrix in &mut matrices {
            matrix.rows = take_header_u64(&header_bytes, &mut at);
            matrix.cols = take_header_u64(&header_bytes, &mut at);
            matrix.nnz = take_header_u64(&header_bytes, &mut at);
            matrix.values = take_header_u64(&header_bytes, &mut at);
            matrix.section_bytes = take_header_u64(&header_bytes, &mut at);
        }
        debug_assert_eq!(at, FIELD_R1CS_ARTIFACT_HEADER_BYTES);

        let expected_k = validate_artifact_shape(
            expected_shape.m,
            expected_shape.k_log,
            expected_shape.k_skip,
            0,
            expected_shape.const_pin,
        )?;
        let expected_k_u64 = checked_u64(expected_k)?;
        for (field, expected, actual) in [
            ("m", expected_shape.m as u64, u64::from(m)),
            ("k_log", expected_shape.k_log as u64, u64::from(k_log)),
            ("k_skip", expected_shape.k_skip as u64, u64::from(k_skip)),
        ] {
            if expected != actual {
                return Err(FieldR1csArtifactError::ShapeMismatch {
                    field,
                    expected,
                    actual,
                });
            }
        }
        let expected_pin_plus_one = expected_shape
            .const_pin
            .map(|column| (column as u64) + 1)
            .unwrap_or(0);
        if const_pin_plus_one != expected_pin_plus_one {
            return Err(FieldR1csArtifactError::ShapeMismatch {
                field: "const_pin",
                expected: expected_pin_plus_one,
                actual: const_pin_plus_one,
            });
        }
        let useful_rows = usize::try_from(useful_rows_raw)
            .map_err(|_| FieldR1csArtifactError::InvalidShape("useful_rows does not fit usize"))?;
        validate_artifact_shape(
            expected_shape.m,
            expected_shape.k_log,
            expected_shape.k_skip,
            useful_rows,
            expected_shape.const_pin,
        )?;

        for (index, counts) in matrices.iter().copied().enumerate() {
            let side = artifact_matrix_name(index);
            if counts.rows != expected_k_u64 || counts.cols != expected_k_u64 {
                return Err(FieldR1csArtifactError::MatrixDimensions {
                    matrix: side,
                    expected: expected_k_u64,
                    rows: counts.rows,
                    cols: counts.cols,
                });
            }
            if counts.nnz > u32::MAX as u64 {
                return Err(FieldR1csArtifactError::CountOutOfRange {
                    matrix: side,
                    field: "nnz",
                    actual: counts.nnz,
                    maximum: u32::MAX as u64,
                });
            }
            if counts.values > u32::MAX as u64 {
                return Err(FieldR1csArtifactError::CountOutOfRange {
                    matrix: side,
                    field: "values",
                    actual: counts.values,
                    maximum: u32::MAX as u64,
                });
            }
            if counts.values > counts.nnz || (counts.nnz != 0 && counts.values == 0) {
                return Err(FieldR1csArtifactError::NonCanonicalValueCount {
                    matrix: side,
                    values: counts.values,
                    nnz: counts.nnz,
                });
            }
            if counts.values > STREAMING_FIELD_R1CS_MAX_DICTIONARY_VALUES as u64 {
                return Err(FieldR1csArtifactError::StreamingDictionaryTooLarge {
                    matrix: side,
                    actual: counts.values,
                    maximum: STREAMING_FIELD_R1CS_MAX_DICTIONARY_VALUES as u64,
                });
            }
            counts.validate_section_bytes(side)?;
        }

        let artifact = ArtifactHeader {
            total_bytes,
            m,
            k_log,
            k_skip,
            useful_rows: useful_rows_raw,
            const_pin_plus_one,
            matrices,
        };
        let computed_bytes = artifact.computed_bytes()?;
        if total_bytes != computed_bytes {
            return Err(FieldR1csArtifactError::TotalLengthMismatch {
                declared: total_bytes,
                computed: computed_bytes,
            });
        }
        if actual_bytes != total_bytes {
            return Err(FieldR1csArtifactError::BackingLengthMismatch {
                expected: total_bytes,
                actual: actual_bytes,
            });
        }

        let mut cursor = FIELD_R1CS_ARTIFACT_HEADER_BYTES as u64;
        let mut layouts = [SeekableArtifactMatrixLayout {
            side: FieldR1csArtifactMatrix::A,
            counts: matrices[0],
            values_at: 0,
            groups_at: 0,
            section_end: 0,
        }; 2];
        for (index, counts) in matrices.iter().copied().enumerate() {
            let values_at = cursor;
            let groups_at = values_at
                .checked_add(
                    counts
                        .values
                        .checked_mul(16)
                        .ok_or(FieldR1csArtifactError::LengthArithmetic)?,
                )
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            let section_end = values_at
                .checked_add(counts.section_bytes)
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            if groups_at > section_end {
                return Err(FieldR1csArtifactError::MatrixLengthMismatch {
                    matrix: artifact_matrix_name(index),
                    field: "section_bytes",
                    expected: groups_at - values_at,
                    actual: counts.section_bytes,
                });
            }
            cursor = section_end;
            layouts[index] = SeekableArtifactMatrixLayout {
                side: artifact_matrix_name(index),
                counts,
                values_at,
                groups_at,
                section_end,
            };
        }
        debug_assert_eq!(cursor, total_bytes);

        Ok(Self {
            reader,
            shape: expected_shape,
            useful_rows,
            total_bytes,
            header_bytes,
            layouts,
            expected_structural_digest,
        })
    }

    pub fn reader(&self) -> &R {
        &self.reader
    }

    /// Mutable backing access is provided for file-metadata adapters and
    /// tests. Any byte mutation is still rejected by the next authenticated
    /// evaluation because header, length, canonical rows, and digest are
    /// rechecked together.
    pub fn reader_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    pub const fn useful_rows(&self) -> usize {
        self.useful_rows
    }

    fn read_at(&mut self, at: u64, bytes: &mut [u8]) -> Result<(), FieldR1csArtifactError> {
        self.reader.seek(SeekFrom::Start(at))?;
        let mut offset = at;
        read_exact_artifact(&mut self.reader, bytes, &mut offset)
    }

    fn ensure_backing_identity(&mut self) -> Result<(), FieldR1csArtifactError> {
        let actual = self.reader.seek(SeekFrom::End(0))?;
        if actual != self.total_bytes {
            return Err(FieldR1csArtifactError::BackingLengthMismatch {
                expected: self.total_bytes,
                actual,
            });
        }
        let mut current = [0u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES];
        self.read_at(0, &mut current)?;
        if current != self.header_bytes {
            return Err(FieldR1csArtifactError::BackingFileChanged);
        }
        Ok(())
    }

    fn load_dictionary(
        &mut self,
        layout: SeekableArtifactMatrixLayout,
    ) -> Result<Vec<F128>, FieldR1csArtifactError> {
        let count = usize::try_from(layout.counts.values)
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        let byte_len = count
            .checked_mul(16)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(byte_len)
            .map_err(|_| FieldR1csArtifactError::Allocation {
                matrix: layout.side,
                field: "streaming coefficient bytes",
            })?;
        bytes.resize(byte_len, 0);
        self.read_at(layout.values_at, &mut bytes)?;

        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| FieldR1csArtifactError::Allocation {
                matrix: layout.side,
                field: "streaming coefficient table",
            })?;
        for (index, chunk) in bytes.chunks_exact(16).enumerate() {
            let value = F128 {
                lo: u64::from_le_bytes(chunk[..8].try_into().expect("low limb")),
                hi: u64::from_le_bytes(chunk[8..].try_into().expect("high limb")),
            };
            if value == F128::ZERO {
                return Err(FieldR1csArtifactError::ZeroCoefficient {
                    matrix: layout.side,
                    index,
                });
            }
            values.push(value);
        }
        drop(bytes);
        validate_unique_nonzero_coefficients(&values, layout.side)?;
        Ok(values)
    }

    fn scan_authenticated(
        &mut self,
        fresh: Option<&crate::matrix_claim::FreshLincheckClaim>,
        accumulated: Option<&crate::matrix_claim::MatrixAccClaim>,
    ) -> Result<crate::matrix_claim::AuthenticatedMatrixClaimEvaluations, FieldR1csArtifactError>
    {
        self.ensure_backing_identity()?;
        validate_streaming_claim_shapes(self.shape, fresh, accumulated)?;

        let fresh_weights = fresh.map(|claim| StreamingFreshWeights::new(self.shape, claim));
        let accumulated_weights =
            accumulated.map(|claim| StreamingAccumulatedWeights::new(self.shape, claim));
        let spans = (1usize << self.shape.k_log).div_ceil(DIGEST_SPAN_ROWS);
        let top_payload_len = 5u64
            .checked_mul(8)
            .and_then(|n| n.checked_add(2 * 16))
            .and_then(|n| n.checked_add((2 * spans * 32) as u64))
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        let mut top = StreamingOnePieceByteHash::new(b"NOID/IVC/FIELD-R1CS-STMT", top_payload_len);
        for value in [
            self.shape.m as u64,
            self.shape.k_log as u64,
            self.shape.k_skip as u64,
            self.useful_rows as u64,
            self.shape
                .const_pin
                .map(|column| 1 + column as u64)
                .unwrap_or(0),
        ] {
            top.update(&value.to_le_bytes());
        }

        let mut fresh_total = F128::ZERO;
        let mut accumulated_total = F128::ZERO;
        for matrix_index in 0..2 {
            let layout = self.layouts[matrix_index];
            let dictionary = self.load_dictionary(layout)?;
            top.update(&layout.counts.rows.to_le_bytes());
            top.update(&layout.counts.cols.to_le_bytes());
            let (fresh_matrix, accumulated_matrix) = self.scan_matrix_rows(
                layout,
                &dictionary,
                fresh_weights.as_ref(),
                accumulated_weights.as_ref(),
                &mut top,
            )?;
            if let Some(weights) = fresh_weights.as_ref() {
                fresh_total += fresh_matrix * weights.side_weight(matrix_index);
            }
            if let Some(weights) = accumulated_weights.as_ref() {
                accumulated_total += accumulated_matrix * weights.side_weight(matrix_index);
            }
        }
        let structural_digest = top.finalize();
        self.ensure_backing_identity()?;
        if structural_digest != self.expected_structural_digest {
            return Err(FieldR1csArtifactError::StructuralDigestMismatch {
                expected: self.expected_structural_digest,
                actual: structural_digest,
            });
        }
        Ok(
            crate::matrix_claim::AuthenticatedMatrixClaimEvaluations::new(
                structural_digest,
                fresh,
                accumulated,
                fresh.map(|_| fresh_total),
                accumulated.map(|_| accumulated_total),
            ),
        )
    }

    fn scan_matrix_rows(
        &mut self,
        layout: SeekableArtifactMatrixLayout,
        dictionary: &[F128],
        fresh: Option<&StreamingFreshWeights<'_>>,
        accumulated: Option<&StreamingAccumulatedWeights>,
        top: &mut StreamingOnePieceByteHash,
    ) -> Result<(F128, F128), FieldR1csArtifactError> {
        let num_rows = usize::try_from(layout.counts.rows)
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        let nnz = usize::try_from(layout.counts.nnz)
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        let mut next_dictionary_index = 0usize;
        let mut entries_committed = 0usize;
        let mut previous_first = 0i64;
        let mut fresh_matrix = F128::ZERO;
        let mut accumulated_matrix = F128::ZERO;
        let mut remaining_section = layout.section_end - layout.groups_at;
        let mut group_cursor = layout.groups_at;
        let mut row_counts: Vec<usize> = Vec::with_capacity(ARTIFACT_GROUP_ROWS);
        let mut streams = PlanarStreamCursors::new(layout.side);

        for span_index in 0..num_rows.div_ceil(ARTIFACT_GROUP_ROWS) {
            let first_row = span_index * ARTIFACT_GROUP_ROWS;
            let rows = (num_rows - first_row).min(ARTIFACT_GROUP_ROWS);
            let mut header = [0u8; 16];
            self.read_at(group_cursor, &mut header)?;
            let lengths =
                decode_group_header(&header, layout.side, span_index, &mut remaining_section)?;
            let payload_at = group_cursor
                .checked_add(16)
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            let group_end = streams.reset(payload_at, &lengths)?;

            // Row-count pass: sizes this span's rows so the span hash can be
            // seeded with the exact format-v1 payload length (8 bytes per
            // row plus 24 per entry) before any entry is visited.
            row_counts.clear();
            let mut running = entries_committed;
            for local in 0..rows {
                let raw = streams.counts.next(self)?;
                let count = usize::try_from(raw)
                    .ok()
                    .filter(|count| nnz - running >= *count)
                    .ok_or(FieldR1csArtifactError::InvalidRowOffset {
                        matrix: layout.side,
                        index: first_row + local,
                        previous: running,
                        actual: raw.saturating_add(running as u64),
                        nnz,
                    })?;
                running += count;
                row_counts.push(count);
            }
            let span_entries = running - entries_committed;
            let span_payload_len = (rows as u64)
                .checked_mul(8)
                .and_then(|n| {
                    (span_entries as u64)
                        .checked_mul(24)
                        .and_then(|e| n.checked_add(e))
                })
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            let mut span =
                StreamingOnePieceByteHash::new(b"NOID/IVC/FIELD-R1CS-SPAN", span_payload_len);

            let mut absolute_entry = entries_committed;
            let mut fresh_row = F128::ZERO;
            let mut accumulated_row = F128::ZERO;
            for local in 0..rows {
                let count = row_counts[local];
                span.update(&(count as u64).to_le_bytes());
                if count == 0 {
                    continue;
                }
                let mut column = previous_first
                    .checked_add(zigzag_decode(streams.firsts.next(self)?))
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
                previous_first = column;
                for entry in 0..count {
                    if entry > 0 {
                        column = column
                            .checked_add(zigzag_decode(streams.deltas.next(self)?))
                            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
                    }
                    if column < 0 || column >= num_rows as i64 {
                        return Err(FieldR1csArtifactError::InvalidColumn {
                            matrix: layout.side,
                            index: absolute_entry,
                            actual: column.clamp(0, u32::MAX as i64) as u32,
                            num_cols: num_rows,
                        });
                    }
                    let raw = streams.values.next(self)?;
                    let value_at = usize::try_from(raw)
                        .ok()
                        .filter(|index| *index < dictionary.len())
                        .ok_or(FieldR1csArtifactError::InvalidValueIndex {
                            matrix: layout.side,
                            index: absolute_entry,
                            actual: raw.min(u32::MAX as u64) as u32,
                            value_count: dictionary.len(),
                        })?;
                    if value_at > next_dictionary_index {
                        return Err(FieldR1csArtifactError::NonCanonicalValueIndexOrder {
                            matrix: layout.side,
                            index: absolute_entry,
                            expected_next: next_dictionary_index,
                            actual: value_at as u32,
                        });
                    }
                    if value_at == next_dictionary_index {
                        next_dictionary_index += 1;
                    }
                    let coefficient = dictionary[value_at];
                    span.update(&(column as u64).to_le_bytes());
                    span.update(&coefficient.lo.to_le_bytes());
                    span.update(&coefficient.hi.to_le_bytes());
                    if let Some(weights) = fresh {
                        fresh_row += coefficient * weights.column_weight(column as usize);
                    }
                    if let Some(weights) = accumulated {
                        accumulated_row += coefficient * weights.column_weight(column as usize);
                    }
                    absolute_entry += 1;
                }
                streaming_finish_row(
                    first_row + local,
                    &mut fresh_row,
                    &mut accumulated_row,
                    &mut fresh_matrix,
                    &mut accumulated_matrix,
                    fresh,
                    accumulated,
                );
            }
            streams.finish_group(self.total_bytes)?;
            entries_committed = running;
            top.update(&span.finalize());
            group_cursor = group_end;
        }
        if remaining_section != 0 {
            return Err(FieldR1csArtifactError::MatrixLengthMismatch {
                matrix: layout.side,
                field: "section_bytes",
                expected: layout.counts.section_bytes,
                actual: layout.counts.section_bytes - remaining_section,
            });
        }
        if entries_committed != nnz {
            return Err(FieldR1csArtifactError::InvalidRowOffset {
                matrix: layout.side,
                index: num_rows,
                previous: entries_committed,
                actual: entries_committed as u64,
                nnz,
            });
        }
        if next_dictionary_index != dictionary.len() {
            return Err(FieldR1csArtifactError::UnusedCoefficient {
                matrix: layout.side,
                index: next_dictionary_index,
            });
        }
        Ok((fresh_matrix, accumulated_matrix))
    }
}

// ---------------------------------------------------------------------------
// Authenticated immutable compact artifact
// ---------------------------------------------------------------------------

/// One byte range inside an authenticated planar row group.
#[derive(Clone, Copy, Debug)]
struct CompactByteRange {
    start: usize,
    end: usize,
}

impl CompactByteRange {
    #[inline]
    fn slice<'a>(self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[self.start..self.end]
    }
}

/// Random-access metadata for one canonical 2048-row planar group.
///
/// The canonical artifact delta-codes the first nonzero column against the
/// previous nonempty row, including across group boundaries.  Retaining that
/// one seed makes every group independently decodable and therefore safe to
/// scan in parallel.  The four streams themselves remain zero-copy borrows of
/// the immutable artifact bytes.
#[derive(Clone, Debug)]
struct CompactPlanarGroup {
    first_row: usize,
    rows: usize,
    entries: usize,
    previous_first: i64,
    streams: [CompactByteRange; 4],
}

#[derive(Debug)]
struct CompactSparseFieldMatrix {
    side: FieldR1csArtifactMatrix,
    num_rows: usize,
    num_cols: usize,
    nnz: usize,
    value_table: Vec<F128>,
    /// Number of groups in the canonical matrix. `groups` may omit a
    /// completely empty canonical suffix after authentication.
    total_groups: usize,
    rows: CompactMatrixRows,
}

/// Hot row storage selected only after the canonical artifact has been fully
/// authenticated. `Planar` preserves the compact varint view used by ordinary
/// callers of [`CompactFieldR1cs::open`]. `Packed` is the production startup
/// representation: it trades a bounded amount of RAM for fixed-width,
/// branch-light scans and releases the canonical/trimmed artifact backing.
#[derive(Debug)]
enum CompactMatrixRows {
    Planar(Vec<CompactPlanarGroup>),
    Packed(PackedSparseFieldRows),
}

/// Dictionary CSR specialized for immutable authenticated protocol matrices.
///
/// A full `usize`/`u32` CSR row-offset and coefficient-index pair costs 12
/// bytes per row/nonzero on 64-bit targets. Release matrices satisfy tighter
/// authenticated bounds, so the hot representation stores:
///
/// - one `u8` count for each row through the last nonempty row, with `255`
///   denoting an exact count stored in the rare-overflow stream;
/// - one `u32` entry base and one `u32` overflow base per 2048-row group,
///   each with a sentinel, so groups remain independently scannable;
/// - `u32` columns and `u16` canonical coefficient indices.
///
/// A zero row suffix is implicit. Entry order and coefficient dictionary order
/// are copied from the already-authenticated canonical streams, so this is a
/// storage transform only: statement digest, row semantics, and transcript are
/// unchanged.
#[derive(Debug)]
struct PackedSparseFieldRows {
    row_counts: Box<[u8]>,
    overflow_counts: Box<[u16]>,
    group_offsets: Box<[u32]>,
    group_overflow_offsets: Box<[u32]>,
    columns: Box<[u32]>,
    value_indices: Box<[u16]>,
}

const PACKED_ROW_COUNT_OVERFLOW_SENTINEL: u8 = u8::MAX;

// Fixed framing followed by two fixed descriptors and their variable arrays:
//
//   magic/version/header bytes/total bytes/canonical bytes/useful rows/count
//   exact 128-byte canonical artifact header
//   descriptor A, descriptor B
//   arrays A, arrays B
//
// The framing is byte-oriented rather than `repr(C)`, so an image is
// relocatable across addresses and independent of Rust struct padding.
const FIELD_R1CS_PACKED_IMAGE_HEADER_BYTES: usize = 168;
const FIELD_R1CS_PACKED_IMAGE_MATRIX_DESCRIPTOR_BYTES: usize = 11 * 8;
const FIELD_R1CS_PACKED_IMAGE_MATRIX_COUNT: u32 = 2;

#[derive(Clone, Copy, Debug)]
struct PackedImageMatrixDescriptor {
    num_rows: usize,
    num_cols: usize,
    nnz: usize,
    total_groups: usize,
    value_table: usize,
    row_counts: usize,
    overflow_counts: usize,
    group_offsets: usize,
    group_overflow_offsets: usize,
    columns: usize,
    value_indices: usize,
}

impl PackedImageMatrixDescriptor {
    fn from_packed(matrix: &CompactSparseFieldMatrix, rows: &PackedSparseFieldRows) -> Self {
        Self {
            num_rows: matrix.num_rows,
            num_cols: matrix.num_cols,
            nnz: matrix.nnz,
            total_groups: matrix.total_groups,
            value_table: matrix.value_table.len(),
            row_counts: rows.row_counts.len(),
            overflow_counts: rows.overflow_counts.len(),
            group_offsets: rows.group_offsets.len(),
            group_overflow_offsets: rows.group_overflow_offsets.len(),
            columns: rows.columns.len(),
            value_indices: rows.value_indices.len(),
        }
    }

    fn encoded_payload_bytes(self) -> Result<usize, FieldR1csArtifactError> {
        self.value_table
            .checked_mul(16)
            .and_then(|total| total.checked_add(self.row_counts))
            .and_then(|total| {
                self.overflow_counts
                    .checked_mul(2)
                    .and_then(|bytes| total.checked_add(bytes))
            })
            .and_then(|total| {
                self.group_offsets
                    .checked_mul(4)
                    .and_then(|bytes| total.checked_add(bytes))
            })
            .and_then(|total| {
                self.group_overflow_offsets
                    .checked_mul(4)
                    .and_then(|bytes| total.checked_add(bytes))
            })
            .and_then(|total| {
                self.columns
                    .checked_mul(4)
                    .and_then(|bytes| total.checked_add(bytes))
            })
            .and_then(|total| {
                self.value_indices
                    .checked_mul(2)
                    .and_then(|bytes| total.checked_add(bytes))
            })
            .ok_or(FieldR1csArtifactError::LengthArithmetic)
    }

    fn write(self, out: &mut Vec<u8>) -> Result<(), FieldR1csArtifactError> {
        for value in [
            self.num_rows,
            self.num_cols,
            self.nnz,
            self.total_groups,
            self.value_table,
            self.row_counts,
            self.overflow_counts,
            self.group_offsets,
            self.group_overflow_offsets,
            self.columns,
            self.value_indices,
        ] {
            out.extend_from_slice(&checked_u64(value)?.to_le_bytes());
        }
        Ok(())
    }

    fn read(cursor: &mut PackedImageCursor<'_>) -> Result<Self, FieldR1csArtifactError> {
        let mut next = || {
            usize::try_from(cursor.take_u64()?)
                .map_err(|_| FieldR1csArtifactError::LengthArithmetic)
        };
        Ok(Self {
            num_rows: next()?,
            num_cols: next()?,
            nnz: next()?,
            total_groups: next()?,
            value_table: next()?,
            row_counts: next()?,
            overflow_counts: next()?,
            group_offsets: next()?,
            group_overflow_offsets: next()?,
            columns: next()?,
            value_indices: next()?,
        })
    }
}

struct PackedImageCursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> PackedImageCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, needed: usize) -> Result<&'a [u8], FieldR1csArtifactError> {
        let end = self
            .at
            .checked_add(needed)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        let bytes = self
            .bytes
            .get(self.at..end)
            .ok_or(FieldR1csArtifactError::Truncated {
                offset: u64::try_from(self.at).unwrap_or(u64::MAX),
                needed,
            })?;
        self.at = end;
        Ok(bytes)
    }

    fn take_u16(&mut self) -> Result<u16, FieldR1csArtifactError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn take_u32(&mut self) -> Result<u32, FieldR1csArtifactError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn take_u64(&mut self) -> Result<u64, FieldR1csArtifactError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn finish(self) -> Result<(), FieldR1csArtifactError> {
        if self.at != self.bytes.len() {
            return Err(FieldR1csArtifactError::TrailingBytes);
        }
        Ok(())
    }
}

fn packed_image_allocation(
    side: FieldR1csArtifactMatrix,
    field: &'static str,
) -> FieldR1csArtifactError {
    FieldR1csArtifactError::Allocation {
        matrix: side,
        field,
    }
}

fn packed_image_u8_array(
    cursor: &mut PackedImageCursor<'_>,
    count: usize,
    side: FieldR1csArtifactMatrix,
    field: &'static str,
) -> Result<Box<[u8]>, FieldR1csArtifactError> {
    let bytes = cursor.take(count)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| packed_image_allocation(side, field))?;
    values.extend_from_slice(bytes);
    Ok(values.into_boxed_slice())
}

fn packed_image_u16_array(
    cursor: &mut PackedImageCursor<'_>,
    count: usize,
    side: FieldR1csArtifactMatrix,
    field: &'static str,
) -> Result<Box<[u16]>, FieldR1csArtifactError> {
    let byte_len = count
        .checked_mul(2)
        .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
    let bytes = cursor.take(byte_len)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| packed_image_allocation(side, field))?;
    values.extend(
        bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])),
    );
    Ok(values.into_boxed_slice())
}

fn packed_image_u32_array(
    cursor: &mut PackedImageCursor<'_>,
    count: usize,
    side: FieldR1csArtifactMatrix,
    field: &'static str,
) -> Result<Box<[u32]>, FieldR1csArtifactError> {
    let byte_len = count
        .checked_mul(4)
        .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
    let bytes = cursor.take(byte_len)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| packed_image_allocation(side, field))?;
    values.extend(
        bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])),
    );
    Ok(values.into_boxed_slice())
}

fn packed_image_f128_array(
    cursor: &mut PackedImageCursor<'_>,
    count: usize,
    side: FieldR1csArtifactMatrix,
) -> Result<Vec<F128>, FieldR1csArtifactError> {
    let byte_len = count
        .checked_mul(16)
        .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
    let bytes = cursor.take(byte_len)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| packed_image_allocation(side, "packed image coefficient table"))?;
    for chunk in bytes.chunks_exact(16) {
        values.push(F128 {
            lo: u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]),
            hi: u64::from_le_bytes([
                chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14],
                chunk[15],
            ]),
        });
    }
    Ok(values)
}

fn read_packed_image_matrix(
    cursor: &mut PackedImageCursor<'_>,
    descriptor: PackedImageMatrixDescriptor,
    side: FieldR1csArtifactMatrix,
) -> Result<CompactSparseFieldMatrix, FieldR1csArtifactError> {
    // The release build already established every semantic and packed-layout
    // invariant. Runtime does only bounded framing, endian conversion and
    // owned copies. In particular this must not call
    // `validate_authenticated_layout` or inspect column/value-index meaning.
    let value_table = packed_image_f128_array(cursor, descriptor.value_table, side)?;
    let row_counts = packed_image_u8_array(
        cursor,
        descriptor.row_counts,
        side,
        "packed image row counts",
    )?;
    let overflow_counts = packed_image_u16_array(
        cursor,
        descriptor.overflow_counts,
        side,
        "packed image overflow counts",
    )?;
    let group_offsets = packed_image_u32_array(
        cursor,
        descriptor.group_offsets,
        side,
        "packed image group offsets",
    )?;
    let group_overflow_offsets = packed_image_u32_array(
        cursor,
        descriptor.group_overflow_offsets,
        side,
        "packed image group overflow offsets",
    )?;
    let columns = packed_image_u32_array(cursor, descriptor.columns, side, "packed image columns")?;
    let value_indices = packed_image_u16_array(
        cursor,
        descriptor.value_indices,
        side,
        "packed image coefficient indices",
    )?;

    Ok(CompactSparseFieldMatrix {
        side,
        num_rows: descriptor.num_rows,
        num_cols: descriptor.num_cols,
        nnz: descriptor.nnz,
        value_table,
        total_groups: descriptor.total_groups,
        rows: CompactMatrixRows::Packed(PackedSparseFieldRows {
            row_counts,
            overflow_counts,
            group_offsets,
            group_overflow_offsets,
            columns,
            value_indices,
        }),
    })
}

impl PackedSparseFieldRows {
    fn from_authenticated_planar(
        matrix: &CompactSparseFieldMatrix,
        bytes: &[u8],
    ) -> Result<Self, FieldR1csArtifactError> {
        let CompactMatrixRows::Planar(groups) = &matrix.rows else {
            return Err(FieldR1csArtifactError::InvalidShape(
                "matrix rows are already startup-packed",
            ));
        };
        if matrix.value_table.len() > usize::from(u16::MAX) + 1 {
            return Err(FieldR1csArtifactError::CountOutOfRange {
                matrix: matrix.side,
                field: "packed coefficient dictionary",
                actual: checked_u64(matrix.value_table.len())?,
                maximum: u64::from(u16::MAX) + 1,
            });
        }

        let retained_rows = groups
            .len()
            .checked_mul(ARTIFACT_GROUP_ROWS)
            .map(|rows| rows.min(matrix.num_rows))
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        let mut row_counts = Vec::<u8>::new();
        row_counts.try_reserve_exact(retained_rows).map_err(|_| {
            FieldR1csArtifactError::Allocation {
                matrix: matrix.side,
                field: "packed row counts",
            }
        })?;
        row_counts.resize(retained_rows, 0);
        // Every overflow row owns at least 255 entries, so this authenticated
        // upper bound prevents a hidden reallocation (and remains tiny for
        // the release relations, whose rows are overwhelmingly short).
        let mut overflow_counts = Vec::<u16>::new();
        overflow_counts
            .try_reserve_exact(matrix.nnz / usize::from(PACKED_ROW_COUNT_OVERFLOW_SENTINEL))
            .map_err(|_| FieldR1csArtifactError::Allocation {
                matrix: matrix.side,
                field: "packed overflow row counts",
            })?;
        let mut group_offsets = Vec::<u32>::new();
        group_offsets
            .try_reserve_exact(groups.len().saturating_add(1))
            .map_err(|_| FieldR1csArtifactError::Allocation {
                matrix: matrix.side,
                field: "packed group offsets",
            })?;
        let mut group_overflow_offsets = Vec::<u32>::new();
        group_overflow_offsets
            .try_reserve_exact(groups.len().saturating_add(1))
            .map_err(|_| FieldR1csArtifactError::Allocation {
                matrix: matrix.side,
                field: "packed group overflow offsets",
            })?;
        let mut columns = Vec::<u32>::new();
        columns
            .try_reserve_exact(matrix.nnz)
            .map_err(|_| FieldR1csArtifactError::Allocation {
                matrix: matrix.side,
                field: "packed columns",
            })?;
        let mut value_indices = Vec::<u16>::new();
        value_indices.try_reserve_exact(matrix.nnz).map_err(|_| {
            FieldR1csArtifactError::Allocation {
                matrix: matrix.side,
                field: "packed coefficient indices",
            }
        })?;

        for group_index in 0..groups.len() {
            group_offsets.push(u32::try_from(columns.len()).map_err(|_| {
                FieldR1csArtifactError::CountOutOfRange {
                    matrix: matrix.side,
                    field: "packed group entry offset",
                    actual: columns.len() as u64,
                    maximum: u64::from(u32::MAX),
                }
            })?);
            group_overflow_offsets.push(u32::try_from(overflow_counts.len()).map_err(|_| {
                FieldR1csArtifactError::CountOutOfRange {
                    matrix: matrix.side,
                    field: "packed group overflow offset",
                    actual: overflow_counts.len() as u64,
                    maximum: u64::from(u32::MAX),
                }
            })?);
            let mut overflowing_row = None;
            let mut active_overflow_row = None;
            let visited = matrix.for_each_group_index_entry(
                Some(bytes),
                group_index,
                |row, column, value_index| {
                    let count = row_counts
                        .get_mut(row)
                        .expect("authenticated retained row is indexed");
                    if *count < PACKED_ROW_COUNT_OVERFLOW_SENTINEL - 1 {
                        *count += 1;
                    } else if *count == PACKED_ROW_COUNT_OVERFLOW_SENTINEL - 1 {
                        *count = PACKED_ROW_COUNT_OVERFLOW_SENTINEL;
                        overflow_counts.push(u16::from(PACKED_ROW_COUNT_OVERFLOW_SENTINEL));
                        active_overflow_row = Some(row);
                    } else {
                        debug_assert_eq!(active_overflow_row, Some(row));
                        let exact = overflow_counts
                            .last_mut()
                            .expect("overflow sentinel owns an exact count");
                        if let Some(next) = exact.checked_add(1) {
                            *exact = next;
                        } else {
                            overflowing_row.get_or_insert(row);
                        }
                    }
                    columns.push(column);
                    value_indices.push(
                        u16::try_from(value_index)
                            .expect("authenticated packed coefficient index fits u16"),
                    );
                },
            );
            debug_assert!(visited);
            if overflowing_row.is_some() {
                return Err(FieldR1csArtifactError::CountOutOfRange {
                    matrix: matrix.side,
                    field: "packed nonzeros per row",
                    actual: u64::from(u16::MAX) + 1,
                    maximum: u64::from(u16::MAX),
                });
            }
        }
        group_offsets.push(u32::try_from(columns.len()).map_err(|_| {
            FieldR1csArtifactError::CountOutOfRange {
                matrix: matrix.side,
                field: "packed group entry offset",
                actual: columns.len() as u64,
                maximum: u64::from(u32::MAX),
            }
        })?);
        group_overflow_offsets.push(u32::try_from(overflow_counts.len()).map_err(|_| {
            FieldR1csArtifactError::CountOutOfRange {
                matrix: matrix.side,
                field: "packed group overflow offset",
                actual: overflow_counts.len() as u64,
                maximum: u64::from(u32::MAX),
            }
        })?);
        if columns.len() != matrix.nnz || value_indices.len() != matrix.nnz {
            return Err(FieldR1csArtifactError::MatrixLengthMismatch {
                matrix: matrix.side,
                field: "packed nnz",
                expected: checked_u64(matrix.nnz)?,
                actual: checked_u64(columns.len())?,
            });
        }

        // Only the exact row suffix after the last nonzero is implicit. Keep
        // the group sentinel matching the retained group that owns that row.
        while row_counts.last() == Some(&0) {
            row_counts.pop();
        }
        let retained_groups = row_counts.len().div_ceil(ARTIFACT_GROUP_ROWS);
        group_offsets.truncate(retained_groups.saturating_add(1));
        group_overflow_offsets.truncate(retained_groups.saturating_add(1));
        if group_offsets.is_empty() {
            group_offsets.push(0);
        }
        if group_overflow_offsets.is_empty() {
            group_overflow_offsets.push(0);
        }
        debug_assert_eq!(group_offsets.last().copied(), Some(matrix.nnz as u32));
        debug_assert_eq!(
            group_overflow_offsets.last().copied(),
            Some(overflow_counts.len() as u32),
        );

        let packed = Self {
            row_counts: row_counts.into_boxed_slice(),
            overflow_counts: overflow_counts.into_boxed_slice(),
            group_offsets: group_offsets.into_boxed_slice(),
            group_overflow_offsets: group_overflow_offsets.into_boxed_slice(),
            columns: columns.into_boxed_slice(),
            value_indices: value_indices.into_boxed_slice(),
        };
        packed.validate_authenticated_layout(matrix.side)?;
        Ok(packed)
    }

    /// Re-check the derived fixed-width index before releasing the canonical
    /// backing. This is deliberately construction-only: hot proving scans can
    /// then trust private immutable arrays without repeating bounds work.
    fn validate_authenticated_layout(
        &self,
        side: FieldR1csArtifactMatrix,
    ) -> Result<(), FieldR1csArtifactError> {
        if self.group_offsets.len() != self.group_overflow_offsets.len()
            || self.row_counts.len().div_ceil(ARTIFACT_GROUP_ROWS) != self.group_count()
        {
            return Err(FieldR1csArtifactError::InvalidShape(
                "packed group index cardinality",
            ));
        }
        let mut total_entries = 0usize;
        let mut total_overflows = 0usize;
        for group_index in 0..self.group_count() {
            let first_row = group_index
                .checked_mul(ARTIFACT_GROUP_ROWS)
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            let row_end = first_row
                .checked_add(ARTIFACT_GROUP_ROWS)
                .map(|end| end.min(self.row_counts.len()))
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            let entry_start = self.group_offsets[group_index] as usize;
            let entry_end = self.group_offsets[group_index + 1] as usize;
            let overflow_start = self.group_overflow_offsets[group_index] as usize;
            let overflow_end = self.group_overflow_offsets[group_index + 1] as usize;
            if entry_start != total_entries
                || entry_end < entry_start
                || entry_end > self.columns.len()
                || overflow_start != total_overflows
                || overflow_end < overflow_start
                || overflow_end > self.overflow_counts.len()
            {
                return Err(FieldR1csArtifactError::InvalidShape(
                    "packed group index bounds",
                ));
            }

            let mut overflow = overflow_start;
            let mut decoded_entries = 0usize;
            for &encoded in &self.row_counts[first_row..row_end] {
                let count = if encoded == PACKED_ROW_COUNT_OVERFLOW_SENTINEL {
                    if overflow >= overflow_end {
                        return Err(FieldR1csArtifactError::MatrixLengthMismatch {
                            matrix: side,
                            field: "packed overflow row counts",
                            expected: overflow_end.saturating_sub(overflow_start) as u64,
                            actual: overflow.saturating_sub(overflow_start).saturating_add(1)
                                as u64,
                        });
                    }
                    let exact = self.overflow_counts.get(overflow).copied().ok_or(
                        FieldR1csArtifactError::MatrixLengthMismatch {
                            matrix: side,
                            field: "packed overflow row counts",
                            expected: overflow_end as u64,
                            actual: overflow as u64,
                        },
                    )?;
                    if exact < u16::from(PACKED_ROW_COUNT_OVERFLOW_SENTINEL) {
                        return Err(FieldR1csArtifactError::InvalidShape(
                            "packed overflow count below sentinel",
                        ));
                    }
                    overflow += 1;
                    usize::from(exact)
                } else {
                    usize::from(encoded)
                };
                decoded_entries = decoded_entries
                    .checked_add(count)
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            }
            let decoded_end = entry_start
                .checked_add(decoded_entries)
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            if overflow != overflow_end || decoded_end != entry_end {
                return Err(FieldR1csArtifactError::MatrixLengthMismatch {
                    matrix: side,
                    field: "packed group entries",
                    expected: entry_end.saturating_sub(entry_start) as u64,
                    actual: decoded_entries as u64,
                });
            }
            total_entries = entry_end;
            total_overflows = overflow_end;
        }
        if total_entries != self.columns.len()
            || self.columns.len() != self.value_indices.len()
            || total_overflows != self.overflow_counts.len()
        {
            return Err(FieldR1csArtifactError::InvalidShape(
                "packed terminal sentinel bounds",
            ));
        }
        Ok(())
    }

    #[inline]
    fn group_count(&self) -> usize {
        self.group_offsets.len().saturating_sub(1)
    }

    #[inline]
    fn for_each_group_index_entry(
        &self,
        group_index: usize,
        mut visit: impl FnMut(usize, u32, usize),
    ) -> bool {
        if group_index >= self.group_count() {
            return false;
        }
        let first_row = group_index * ARTIFACT_GROUP_ROWS;
        let rows = (self.row_counts.len() - first_row).min(ARTIFACT_GROUP_ROWS);
        let mut entry = self.group_offsets[group_index] as usize;
        let group_end = self.group_offsets[group_index + 1] as usize;
        let mut overflow = self.group_overflow_offsets[group_index] as usize;
        let overflow_end = self.group_overflow_offsets[group_index + 1] as usize;
        for (local_row, &encoded) in self.row_counts[first_row..first_row + rows]
            .iter()
            .enumerate()
        {
            let count = if encoded == PACKED_ROW_COUNT_OVERFLOW_SENTINEL {
                let exact = self.overflow_counts[overflow];
                overflow += 1;
                usize::from(exact)
            } else {
                usize::from(encoded)
            };
            for _ in 0..count {
                visit(
                    first_row + local_row,
                    self.columns[entry],
                    usize::from(self.value_indices[entry]),
                );
                entry += 1;
            }
        }
        debug_assert_eq!(entry, group_end);
        debug_assert_eq!(overflow, overflow_end);
        true
    }

    fn heap_payload_len(&self) -> usize {
        self.row_counts
            .len()
            .saturating_mul(std::mem::size_of::<u8>())
            .saturating_add(
                self.overflow_counts
                    .len()
                    .saturating_mul(std::mem::size_of::<u16>()),
            )
            .saturating_add(
                self.group_offsets
                    .len()
                    .saturating_mul(std::mem::size_of::<u32>()),
            )
            .saturating_add(
                self.group_overflow_offsets
                    .len()
                    .saturating_mul(std::mem::size_of::<u32>()),
            )
            .saturating_add(
                self.columns
                    .len()
                    .saturating_mul(std::mem::size_of::<u32>()),
            )
            .saturating_add(
                self.value_indices
                    .len()
                    .saturating_mul(std::mem::size_of::<u16>()),
            )
    }

    /// Re-emit the canonical planar section from the fixed-width rows. The
    /// source artifact was canonical and value indices retain that exact
    /// first-use dictionary order, so this produces the original bytes (it is
    /// a compatibility path, never a production proving path).
    fn write_canonical_section<W: Write + ?Sized>(
        &self,
        writer: &mut W,
        side: FieldR1csArtifactMatrix,
        num_rows: usize,
        value_table: &[F128],
    ) -> Result<(), FieldR1csArtifactError> {
        write_f128_slice(writer, value_table)?;
        let mut cursor = PlanarRowCursor::new();
        let mut buffers = PlanarGroupBuffers::new();
        let mut entry = 0usize;
        for group_first in (0..num_rows).step_by(ARTIFACT_GROUP_ROWS) {
            let group_index = group_first / ARTIFACT_GROUP_ROWS;
            let group_rows = (num_rows - group_first).min(ARTIFACT_GROUP_ROWS);
            let retained_group = group_index < self.group_count();
            let mut overflow = if retained_group {
                self.group_overflow_offsets[group_index] as usize
            } else {
                self.overflow_counts.len()
            };
            let overflow_end = if retained_group {
                self.group_overflow_offsets[group_index + 1] as usize
            } else {
                self.overflow_counts.len()
            };
            buffers.clear();
            for row in group_first..group_first + group_rows {
                let encoded = self.row_counts.get(row).copied().unwrap_or(0);
                let count = if encoded == PACKED_ROW_COUNT_OVERFLOW_SENTINEL {
                    let exact = self.overflow_counts.get(overflow).copied().ok_or(
                        FieldR1csArtifactError::MatrixLengthMismatch {
                            matrix: side,
                            field: "packed overflow row counts",
                            expected: overflow_end as u64,
                            actual: overflow as u64,
                        },
                    )?;
                    overflow += 1;
                    usize::from(exact)
                } else {
                    usize::from(encoded)
                };
                let end = entry
                    .checked_add(count)
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
                push_varint(&mut buffers.counts, count as u64);
                if count == 0 {
                    continue;
                }
                let first = self.columns[entry] as i64;
                push_varint(
                    &mut buffers.firsts,
                    zigzag_encode(first - cursor.previous_first),
                );
                cursor.previous_first = first;
                let mut previous = first;
                for &column in &self.columns[entry + 1..end] {
                    let column = i64::from(column);
                    push_varint(&mut buffers.deltas, zigzag_encode(column - previous));
                    previous = column;
                }
                for &value_index in &self.value_indices[entry..end] {
                    push_varint(&mut buffers.values, u64::from(value_index));
                }
                entry = end;
            }
            debug_assert_eq!(overflow, overflow_end);
            let mut header = [0u8; 16];
            for (slot, stream) in [
                &buffers.counts,
                &buffers.firsts,
                &buffers.deltas,
                &buffers.values,
            ]
            .iter()
            .enumerate()
            {
                let length = u32::try_from(stream.len())
                    .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
                header[slot * 4..slot * 4 + 4].copy_from_slice(&length.to_le_bytes());
            }
            writer.write_all(&header)?;
            writer.write_all(&buffers.counts)?;
            writer.write_all(&buffers.firsts)?;
            writer.write_all(&buffers.deltas)?;
            writer.write_all(&buffers.values)?;
        }
        debug_assert_eq!(entry, self.columns.len());
        Ok(())
    }

    fn decode_resident(
        &self,
        num_rows: usize,
        num_cols: usize,
        value_table: &[F128],
    ) -> SparseFieldMatrix {
        let mut row_offsets = Vec::with_capacity(num_rows.saturating_add(1));
        row_offsets.push(0);
        let mut running = 0usize;
        for group_first in (0..num_rows).step_by(ARTIFACT_GROUP_ROWS) {
            let group_index = group_first / ARTIFACT_GROUP_ROWS;
            let group_rows = (num_rows - group_first).min(ARTIFACT_GROUP_ROWS);
            let retained_group = group_index < self.group_count();
            let mut overflow = if retained_group {
                self.group_overflow_offsets[group_index] as usize
            } else {
                self.overflow_counts.len()
            };
            let overflow_end = if retained_group {
                self.group_overflow_offsets[group_index + 1] as usize
            } else {
                self.overflow_counts.len()
            };
            for row in group_first..group_first + group_rows {
                let encoded = self.row_counts.get(row).copied().unwrap_or(0);
                let count = if encoded == PACKED_ROW_COUNT_OVERFLOW_SENTINEL {
                    let exact = self.overflow_counts[overflow];
                    overflow += 1;
                    usize::from(exact)
                } else {
                    usize::from(encoded)
                };
                running = running
                    .checked_add(count)
                    .expect("authenticated packed row counts fit resident CSR");
                row_offsets.push(running);
            }
            debug_assert_eq!(overflow, overflow_end);
        }
        debug_assert_eq!(running, self.columns.len());
        SparseFieldMatrix {
            num_rows,
            num_cols,
            col_indices: self.columns.to_vec(),
            value_indices: self
                .value_indices
                .iter()
                .map(|&index| u32::from(index))
                .collect(),
            value_table: value_table.to_vec(),
            row_offsets,
        }
    }
}

impl CompactSparseFieldMatrix {
    #[inline]
    fn retained_group_count(&self) -> usize {
        match &self.rows {
            CompactMatrixRows::Planar(groups) => groups.len(),
            CompactMatrixRows::Packed(rows) => rows.group_count(),
        }
    }

    #[inline]
    fn is_packed(&self) -> bool {
        matches!(&self.rows, CompactMatrixRows::Packed(_))
    }

    fn heap_payload_len(&self) -> usize {
        let dictionary = self
            .value_table
            .capacity()
            .saturating_mul(std::mem::size_of::<F128>());
        dictionary.saturating_add(match &self.rows {
            CompactMatrixRows::Planar(groups) => groups
                .capacity()
                .saturating_mul(std::mem::size_of::<CompactPlanarGroup>()),
            CompactMatrixRows::Packed(rows) => rows.heap_payload_len(),
        })
    }

    /// Visit the nonzero entries of one row group in canonical row-major
    /// order.  Construction has already performed the complete canonical scan
    /// and structural authentication over the same immutable boxed bytes, so
    /// hot scans need no repeated bounds/canonicality checks or CSR decode.
    #[inline]
    fn for_each_group_entry(
        &self,
        bytes: Option<&[u8]>,
        group_index: usize,
        visit: impl FnMut(usize, u32, F128),
    ) -> bool {
        self.for_each_group_entry_with_dictionary(bytes, group_index, &self.value_table, visit)
    }

    /// The same authenticated group walk with a caller-prepared coefficient
    /// dictionary. The index stream and its canonical bounds were fixed by
    /// `open`; requiring the exact dictionary length makes this useful for a
    /// tiny `alpha * coefficient` table without changing row interpretation.
    #[inline]
    fn for_each_group_entry_with_dictionary(
        &self,
        bytes: Option<&[u8]>,
        group_index: usize,
        dictionary: &[F128],
        mut visit: impl FnMut(usize, u32, F128),
    ) -> bool {
        assert_eq!(dictionary.len(), self.value_table.len());
        self.for_each_group_index_entry(bytes, group_index, |row, column, value_index| {
            visit(row, column, dictionary[value_index]);
        })
    }

    /// Visit raw canonical coefficient indices. This is the one-time bridge
    /// from authenticated planar streams into the packed SoA and also avoids
    /// a reverse coefficient lookup while preserving first-use order exactly.
    #[inline]
    fn for_each_group_index_entry(
        &self,
        bytes: Option<&[u8]>,
        group_index: usize,
        mut visit: impl FnMut(usize, u32, usize),
    ) -> bool {
        let groups = match &self.rows {
            CompactMatrixRows::Planar(groups) => groups,
            CompactMatrixRows::Packed(rows) => {
                return if group_index < rows.group_count() {
                    rows.for_each_group_index_entry(group_index, visit)
                } else {
                    group_index < self.total_groups
                };
            }
        };
        let Some(group) = groups.get(group_index) else {
            // A post-authentication compact view is allowed to discard only
            // the canonical all-zero suffix. Those logical groups still
            // exist and visiting them succeeds with no entries.
            return group_index < self.total_groups;
        };
        if group.entries == 0 {
            return true;
        }
        let bytes = bytes.expect("planar compact matrix retains authenticated bytes");
        let mut counts = SliceVarints::new(group.streams[0].slice(bytes), self.side, "counts");
        let mut firsts = SliceVarints::new(group.streams[1].slice(bytes), self.side, "firsts");
        let mut deltas = SliceVarints::new(group.streams[2].slice(bytes), self.side, "deltas");
        let mut values = SliceVarints::new(group.streams[3].slice(bytes), self.side, "values");
        let mut previous_first = group.previous_first;
        let mut visited = 0usize;

        for local_row in 0..group.rows {
            let count = counts.next().expect("authenticated compact count stream") as usize;
            if count == 0 {
                continue;
            }
            let mut column = previous_first
                + zigzag_decode(
                    firsts
                        .next()
                        .expect("authenticated compact first-column stream"),
                );
            previous_first = column;
            for entry in 0..count {
                if entry > 0 {
                    column += zigzag_decode(
                        deltas
                            .next()
                            .expect("authenticated compact column-delta stream"),
                    );
                }
                let value_index = values
                    .next()
                    .expect("authenticated compact coefficient stream")
                    as usize;
                visit(group.first_row + local_row, column as u32, value_index);
                visited += 1;
            }
        }
        debug_assert_eq!(visited, group.entries);
        debug_assert!(counts.finish().is_ok());
        debug_assert!(firsts.finish().is_ok());
        debug_assert!(deltas.finish().is_ok());
        debug_assert!(values.finish().is_ok());
        true
    }
}

#[derive(Clone, Copy, Debug)]
struct CompactArtifactMatrixTrim {
    /// Exact prefix retained from the canonical matrix section: dictionary
    /// plus every group through the last nonempty group.
    retained_section_bytes: usize,
    canonical_section_bytes: usize,
    retained_groups: usize,
    rows: usize,
}

#[derive(Clone, Copy, Debug)]
struct CompactArtifactTrimLayout {
    canonical_bytes: usize,
    matrices: [CompactArtifactMatrixTrim; 2],
}

impl CompactArtifactTrimLayout {
    fn rebuild(self, compact: &[u8]) -> Box<[u8]> {
        let mut canonical = Vec::with_capacity(self.canonical_bytes);
        canonical.extend_from_slice(
            compact
                .get(..FIELD_R1CS_ARTIFACT_HEADER_BYTES)
                .expect("authenticated compact artifact header"),
        );
        let mut compact_at = FIELD_R1CS_ARTIFACT_HEADER_BYTES;
        let mut canonical_sections = 0usize;
        for matrix in self.matrices {
            let retained_end = compact_at
                .checked_add(matrix.retained_section_bytes)
                .expect("authenticated compact section length");
            canonical.extend_from_slice(
                compact
                    .get(compact_at..retained_end)
                    .expect("authenticated compact section prefix"),
            );
            compact_at = retained_end;

            let total_groups = matrix.rows.div_ceil(ARTIFACT_GROUP_ROWS);
            for group in matrix.retained_groups..total_groups {
                let first_row = group * ARTIFACT_GROUP_ROWS;
                let rows = (matrix.rows - first_row).min(ARTIFACT_GROUP_ROWS);
                append_canonical_zero_group(&mut canonical, rows);
            }
            canonical_sections = canonical_sections
                .checked_add(matrix.canonical_section_bytes)
                .expect("authenticated canonical section length");
            debug_assert_eq!(
                canonical.len(),
                FIELD_R1CS_ARTIFACT_HEADER_BYTES + canonical_sections,
            );
        }
        assert_eq!(compact_at, compact.len());
        assert_eq!(canonical.len(), self.canonical_bytes);
        canonical.into_boxed_slice()
    }
}

fn append_canonical_zero_group(bytes: &mut Vec<u8>, rows: usize) {
    let count_bytes = u32::try_from(rows).expect("artifact group rows fit u32");
    bytes.extend_from_slice(&count_bytes.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 12]);
    bytes.resize(bytes.len() + rows, 0);
}

#[derive(Debug)]
struct TrimmedCompactArtifactBacking {
    bytes: Box<[u8]>,
    layout: CompactArtifactTrimLayout,
}

#[derive(Debug)]
struct PackedArtifactBacking {
    /// Exact authenticated header. The fixed header carries the canonical
    /// section lengths, shape, and total byte count; packed rows can therefore
    /// re-emit a byte-identical compatibility artifact without retaining its
    /// original planar payload.
    header: [u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES],
    canonical_bytes: usize,
}

#[derive(Debug)]
enum CompactArtifactBacking {
    Canonical(Box<[u8]>),
    Trimmed(TrimmedCompactArtifactBacking),
    Packed(PackedArtifactBacking),
}

impl CompactArtifactBacking {
    fn planar_hot_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Canonical(bytes) => Some(bytes),
            Self::Trimmed(backing) => Some(&backing.bytes),
            Self::Packed(_) => None,
        }
    }

    fn canonical_len(&self) -> usize {
        match self {
            Self::Canonical(bytes) => bytes.len(),
            Self::Trimmed(backing) => backing.layout.canonical_bytes,
            Self::Packed(backing) => backing.canonical_bytes,
        }
    }

    fn resident_artifact_len(&self) -> usize {
        match self {
            Self::Canonical(bytes) => bytes.len(),
            Self::Trimmed(backing) => backing.bytes.len(),
            Self::Packed(_) => 0,
        }
    }

    fn heap_payload_len(&self) -> usize {
        match self {
            Self::Canonical(bytes) => bytes.len(),
            Self::Trimmed(backing) => backing.bytes.len(),
            Self::Packed(_) => 0,
        }
    }
}

/// An authenticated `FieldR1cs` with compact-planar and startup-packed hot
/// layouts, both exposed through the same immutable API.
///
/// `open` performs the same complete canonical scan and structural digest
/// authentication as [`SeekableFieldR1csArtifact::open`]. After that scan, an
/// exactly canonical all-zero suffix may be removed from each matrix's hot
/// backing; every retained byte remains immutable and every omitted group is
/// byte-proven to contain no entries. Later matrix scans therefore reuse the
/// established digest and walk independent 2048-row groups directly from the
/// compact bytes. Only the two small coefficient dictionaries, one group
/// index, and a reconstruction recipe are materialized.
///
/// [`Self::open_packed`] performs that same authentication, then copies the
/// canonical row order into a fixed-width SoA and releases the planar payload.
/// This type is intended for frozen protocol matrices embedded in the node.
/// Neither layout changes canonical byte encoding or the proof statement.
pub struct CompactFieldR1cs {
    backing: CompactArtifactBacking,
    shape: crate::proof::FieldShape,
    useful_rows: usize,
    statement_digest: [u8; 32],
    matrices: [CompactSparseFieldMatrix; 2],
    build_authenticated: bool,
}

impl fmt::Debug for CompactFieldR1cs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompactFieldR1cs")
            .field("shape", &self.shape)
            .field("useful_rows", &self.useful_rows)
            .field("storage", &self.storage_name())
            .field("artifact_bytes", &self.backing.canonical_len())
            .field(
                "resident_artifact_bytes",
                &self.backing.resident_artifact_len(),
            )
            .field(
                "resident_heap_payload_bytes",
                &self.resident_heap_payload_len(),
            )
            .field("a_nnz", &self.matrices[0].nnz)
            .field("b_nnz", &self.matrices[1].nnz)
            .finish()
    }
}

impl CompactFieldR1cs {
    /// Authenticate an immutable canonical artifact and build its small
    /// parallel group index without ever materializing CSR arrays.
    pub fn open(
        bytes: Box<[u8]>,
        expected_shape: crate::proof::FieldShape,
        expected_structural_digest: [u8; 32],
    ) -> Result<Self, FieldR1csArtifactError> {
        let max_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let mut authenticated = SeekableFieldR1csArtifact::open(
            std::io::Cursor::new(bytes.as_ref()),
            expected_shape,
            expected_structural_digest,
            max_bytes,
        )?;
        let useful_rows = authenticated.useful_rows;
        let layouts = authenticated.layouts;
        let a = build_compact_matrix_index(&bytes, &mut authenticated, layouts[0])?;
        let b = build_compact_matrix_index(&bytes, &mut authenticated, layouts[1])?;
        drop(authenticated);
        let (backing, matrices) = trim_authenticated_compact_padding(bytes, layouts, [a, b])?;
        Ok(Self {
            backing,
            shape: expected_shape,
            useful_rows,
            statement_digest: expected_structural_digest,
            matrices,
            build_authenticated: false,
        })
    }

    /// Open canonical bytes authenticated semantically by pack preflight.
    ///
    /// The seal and bytes must be the paired immutable values emitted by the
    /// pack-preflight authority. This path still checks exact length, canonical
    /// header arithmetic, shape, dictionaries, planar group boundaries, row
    /// counts, and first-column streams before constructing the opaque
    /// relation.  It deliberately omits only the structural Poseidon pass:
    /// that expensive pass minted the seal over the exact approved leaf before
    /// rustc embedded it. There is no filesystem or caller-derived fallback.
    /// # Safety
    ///
    /// `bytes` must be the exact immutable canonical payload paired with
    /// `seal` by pack preflight which successfully ran [`Self::open`] over
    /// that pair. This is an executable-internal materialization primitive;
    /// safe runtime/file APIs must use [`Self::open`].
    pub unsafe fn open_build_authenticated(
        bytes: Box<[u8]>,
        seal: BuildAuthenticatedFieldR1csSeal,
    ) -> Result<Self, FieldR1csArtifactError> {
        let actual_bytes = bytes.len();
        if actual_bytes != seal.canonical_bytes {
            return Err(FieldR1csArtifactError::BackingLengthMismatch {
                expected: checked_u64(seal.canonical_bytes)?,
                actual: checked_u64(actual_bytes)?,
            });
        }
        let max_bytes = checked_u64(actual_bytes)?;
        let mut preflight = SeekableFieldR1csArtifact::preflight_header(
            std::io::Cursor::new(bytes.as_ref()),
            seal.shape,
            seal.statement_digest,
            max_bytes,
        )?;
        let useful_rows = preflight.useful_rows;
        let layouts = preflight.layouts;
        let a = build_compact_matrix_index(&bytes, &mut preflight, layouts[0])?;
        let b = build_compact_matrix_index(&bytes, &mut preflight, layouts[1])?;
        drop(preflight);
        let (backing, matrices) = trim_authenticated_compact_padding(bytes, layouts, [a, b])?;
        Ok(Self {
            backing,
            shape: seal.shape,
            useful_rows,
            statement_digest: seal.statement_digest,
            matrices,
            build_authenticated: true,
        })
    }

    /// Authenticate the complete canonical artifact, transform its immutable
    /// rows into the startup-packed SoA, then release the planar byte backing.
    /// This is the production embedded-bank constructor. It performs no
    /// filesystem access and changes no protocol identity or transcript.
    pub fn open_packed(
        bytes: Box<[u8]>,
        expected_shape: crate::proof::FieldShape,
        expected_structural_digest: [u8; 32],
    ) -> Result<Self, FieldR1csArtifactError> {
        Self::open(bytes, expected_shape, expected_structural_digest)?.into_startup_packed()
    }

    /// Convert an already authenticated compact relation into the production
    /// startup layout. Safe callers cannot invoke this on unauthenticated rows
    /// because the opaque relation is minted only by [`Self::open`].
    pub fn into_startup_packed(mut self) -> Result<Self, FieldR1csArtifactError> {
        if self.is_packed() {
            return Ok(self);
        }
        let bytes = self
            .backing
            .planar_hot_bytes()
            .expect("non-packed relation has planar authenticated backing");
        let header: [u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES] = bytes
            .get(..FIELD_R1CS_ARTIFACT_HEADER_BYTES)
            .and_then(|header| header.try_into().ok())
            .expect("authenticated artifact retains its exact header");
        let canonical_bytes = self.backing.canonical_len();
        let a = PackedSparseFieldRows::from_authenticated_planar(&self.matrices[0], bytes)?;
        let b = PackedSparseFieldRows::from_authenticated_planar(&self.matrices[1], bytes)?;
        self.matrices[0].rows = CompactMatrixRows::Packed(a);
        self.matrices[1].rows = CompactMatrixRows::Packed(b);
        self.matrices[0].value_table.shrink_to_fit();
        self.matrices[1].value_table.shrink_to_fit();
        self.backing = CompactArtifactBacking::Packed(PackedArtifactBacking {
            header,
            canonical_bytes,
        });
        Ok(self)
    }

    /// Serialize this authenticated startup-packed relation into a versioned,
    /// relocatable build image.
    ///
    /// The image contains the exact canonical header and canonical byte
    /// length for compatibility export, plus both matrices' already-derived
    /// fixed-width runtime arrays. It contains no pointers and is independent
    /// of Rust struct layout. A trusted release build should call
    /// [`Self::open`] followed by [`Self::into_startup_packed`], encode the
    /// result once, and embed the returned bytes beside the matching
    /// [`BuildAuthenticatedFieldR1csSeal`].
    pub fn encode_startup_packed_image(&self) -> Result<Box<[u8]>, FieldR1csArtifactError> {
        let CompactArtifactBacking::Packed(backing) = &self.backing else {
            return Err(FieldR1csArtifactError::InvalidShape(
                "startup-packed image requires packed matrix storage",
            ));
        };
        let packed_rows = self
            .matrices
            .iter()
            .map(|matrix| match &matrix.rows {
                CompactMatrixRows::Packed(rows) => Ok(rows),
                CompactMatrixRows::Planar(_) => Err(FieldR1csArtifactError::InvalidShape(
                    "startup-packed image has planar matrix rows",
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let descriptors = [
            PackedImageMatrixDescriptor::from_packed(&self.matrices[0], packed_rows[0]),
            PackedImageMatrixDescriptor::from_packed(&self.matrices[1], packed_rows[1]),
        ];
        let payload_bytes = descriptors.iter().try_fold(0usize, |total, descriptor| {
            total
                .checked_add(descriptor.encoded_payload_bytes()?)
                .ok_or(FieldR1csArtifactError::LengthArithmetic)
        })?;
        let total_bytes = FIELD_R1CS_PACKED_IMAGE_HEADER_BYTES
            .checked_add(
                FIELD_R1CS_PACKED_IMAGE_MATRIX_DESCRIPTOR_BYTES
                    .checked_mul(FIELD_R1CS_PACKED_IMAGE_MATRIX_COUNT as usize)
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)?,
            )
            .and_then(|bytes| bytes.checked_add(payload_bytes))
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;

        let mut image = Vec::new();
        image.try_reserve_exact(total_bytes).map_err(|_| {
            packed_image_allocation(FieldR1csArtifactMatrix::A, "startup-packed image")
        })?;
        image.extend_from_slice(&FIELD_R1CS_PACKED_IMAGE_MAGIC);
        image.extend_from_slice(&FIELD_R1CS_PACKED_IMAGE_VERSION.to_le_bytes());
        image.extend_from_slice(
            &u16::try_from(FIELD_R1CS_PACKED_IMAGE_HEADER_BYTES)
                .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?
                .to_le_bytes(),
        );
        image.extend_from_slice(&checked_u64(total_bytes)?.to_le_bytes());
        image.extend_from_slice(&checked_u64(backing.canonical_bytes)?.to_le_bytes());
        image.extend_from_slice(&checked_u64(self.useful_rows)?.to_le_bytes());
        image.extend_from_slice(&FIELD_R1CS_PACKED_IMAGE_MATRIX_COUNT.to_le_bytes());
        image.extend_from_slice(&backing.header);
        if image.len() != FIELD_R1CS_PACKED_IMAGE_HEADER_BYTES {
            return Err(FieldR1csArtifactError::LengthArithmetic);
        }
        for descriptor in descriptors {
            descriptor.write(&mut image)?;
        }
        for (matrix, rows) in self.matrices.iter().zip(packed_rows) {
            for value in &matrix.value_table {
                image.extend_from_slice(&value.lo.to_le_bytes());
                image.extend_from_slice(&value.hi.to_le_bytes());
            }
            image.extend_from_slice(&rows.row_counts);
            for value in &rows.overflow_counts {
                image.extend_from_slice(&value.to_le_bytes());
            }
            for value in &rows.group_offsets {
                image.extend_from_slice(&value.to_le_bytes());
            }
            for value in &rows.group_overflow_offsets {
                image.extend_from_slice(&value.to_le_bytes());
            }
            for value in &rows.columns {
                image.extend_from_slice(&value.to_le_bytes());
            }
            for value in &rows.value_indices {
                image.extend_from_slice(&value.to_le_bytes());
            }
        }
        if image.len() != total_bytes {
            return Err(FieldR1csArtifactError::TotalLengthMismatch {
                declared: checked_u64(total_bytes)?,
                computed: checked_u64(image.len())?,
            });
        }
        Ok(image.into_boxed_slice())
    }

    /// Materialize the runtime-ready fixed-width relation emitted by a trusted
    /// release build.
    ///
    /// Runtime performs only bounded framing, little-endian copies and exact
    /// image-length checks. It does **not** parse canonical rows, recompute a
    /// structural digest, run Poseidon, or revalidate the packed layout. Those
    /// operations belong to the release build that minted `seal` and emitted
    /// `image` with [`Self::encode_startup_packed_image`].
    ///
    /// # Safety
    ///
    /// Malformed or truncated framing may be passed and is returned as an
    /// error. Any image that passes those bounded framing checks must be the
    /// exact immutable output of [`Self::encode_startup_packed_image`] for the
    /// exact relation previously authenticated by [`Self::open`] under
    /// `seal.shape()` and `seal.statement_digest()`, with
    /// `seal.canonical_bytes()` bound to that relation's complete canonical
    /// artifact. Passing merely well-framed but different bytes violates the
    /// private packed-array invariants relied on by branch-light proving
    /// scans. Safe runtime/file loaders must use [`Self::open`] or
    /// [`Self::open_packed`].
    pub unsafe fn open_build_authenticated_packed_image(
        image: &[u8],
        seal: BuildAuthenticatedFieldR1csSeal,
    ) -> Result<Self, FieldR1csArtifactError> {
        let mut cursor = PackedImageCursor::new(image);
        if cursor.take(FIELD_R1CS_PACKED_IMAGE_MAGIC.len())? != FIELD_R1CS_PACKED_IMAGE_MAGIC {
            return Err(FieldR1csArtifactError::InvalidMagic);
        }
        let version = cursor.take_u16()?;
        if version != FIELD_R1CS_PACKED_IMAGE_VERSION {
            return Err(FieldR1csArtifactError::UnsupportedVersion { actual: version });
        }
        let header_bytes = cursor.take_u16()?;
        if usize::from(header_bytes) != FIELD_R1CS_PACKED_IMAGE_HEADER_BYTES {
            return Err(FieldR1csArtifactError::InvalidHeaderLength {
                actual: header_bytes,
            });
        }
        let declared_total_bytes = cursor.take_u64()?;
        let actual_total_bytes = checked_u64(image.len())?;
        if declared_total_bytes != actual_total_bytes {
            return Err(FieldR1csArtifactError::TotalLengthMismatch {
                declared: declared_total_bytes,
                computed: actual_total_bytes,
            });
        }
        let canonical_bytes = usize::try_from(cursor.take_u64()?)
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        if canonical_bytes != seal.canonical_bytes {
            return Err(FieldR1csArtifactError::BackingLengthMismatch {
                expected: checked_u64(seal.canonical_bytes)?,
                actual: checked_u64(canonical_bytes)?,
            });
        }
        let useful_rows = usize::try_from(cursor.take_u64()?)
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        if cursor.take_u32()? != FIELD_R1CS_PACKED_IMAGE_MATRIX_COUNT {
            return Err(FieldR1csArtifactError::InvalidShape(
                "startup-packed image matrix count",
            ));
        }
        let header: [u8; FIELD_R1CS_ARTIFACT_HEADER_BYTES] = cursor
            .take(FIELD_R1CS_ARTIFACT_HEADER_BYTES)?
            .try_into()
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        let descriptors = [
            PackedImageMatrixDescriptor::read(&mut cursor)?,
            PackedImageMatrixDescriptor::read(&mut cursor)?,
        ];
        let matrices = [
            read_packed_image_matrix(&mut cursor, descriptors[0], FieldR1csArtifactMatrix::A)?,
            read_packed_image_matrix(&mut cursor, descriptors[1], FieldR1csArtifactMatrix::B)?,
        ];
        cursor.finish()?;

        Ok(Self {
            backing: CompactArtifactBacking::Packed(PackedArtifactBacking {
                header,
                canonical_bytes,
            }),
            shape: seal.shape,
            useful_rows,
            statement_digest: seal.statement_digest,
            matrices,
            build_authenticated: true,
        })
    }

    pub const fn shape(&self) -> crate::proof::FieldShape {
        self.shape
    }

    pub const fn useful_rows(&self) -> usize {
        self.useful_rows
    }

    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    pub fn encoded_len(&self) -> usize {
        self.backing.canonical_len()
    }

    /// Stable diagnostic label used by live timing logs.
    pub fn storage_name(&self) -> &'static str {
        if matches!(&self.backing, CompactArtifactBacking::Packed(_)) {
            "packed"
        } else {
            "compact-planar"
        }
    }

    /// Authentication path used to mint this opaque relation.  Both values
    /// represent the same canonical protocol statement; the label exists for
    /// startup telemetry and release-path regression gates.
    pub const fn authentication_name(&self) -> &'static str {
        if self.build_authenticated {
            "release-build-sealed"
        } else {
            "runtime-structural-scan"
        }
    }

    pub fn is_packed(&self) -> bool {
        let packed = matches!(&self.backing, CompactArtifactBacking::Packed(_));
        debug_assert_eq!(
            packed,
            self.matrices
                .iter()
                .all(CompactSparseFieldMatrix::is_packed),
        );
        packed
    }

    /// Bytes retained for the authenticated planar backing used by proving.
    /// This excludes the small coefficient tables/group metadata and any
    /// lazily reconstructed compatibility copy returned by
    /// [`Self::artifact_bytes`].
    pub fn resident_artifact_len(&self) -> usize {
        self.backing.resident_artifact_len()
    }

    /// Exact heap payload owned by this relation (allocator metadata and the
    /// small inline struct headers are intentionally excluded). Unlike a
    /// fixed cache surcharge, this accounts for dictionaries, group metadata,
    /// packed arrays, retained artifact bytes, and any lazily requested
    /// compatibility artifact.
    pub fn resident_heap_payload_len(&self) -> usize {
        self.backing.heap_payload_len().saturating_add(
            self.matrices
                .iter()
                .map(CompactSparseFieldMatrix::heap_payload_len)
                .sum::<usize>(),
        )
    }

    /// The exact authenticated canonical artifact represented by this view.
    ///
    /// Trimmed and packed layouts reconstruct an owned byte-identical export
    /// for the caller. They never retain that diagnostic copy inside the hot
    /// relation, so requesting an export cannot silently and permanently grow
    /// the production matrix cache.
    pub fn artifact_bytes(&self) -> Cow<'_, [u8]> {
        match &self.backing {
            CompactArtifactBacking::Canonical(bytes) => Cow::Borrowed(bytes),
            CompactArtifactBacking::Trimmed(backing) => {
                Cow::Owned(backing.layout.rebuild(&backing.bytes).into_vec())
            }
            CompactArtifactBacking::Packed(backing) => {
                let mut canonical = Vec::with_capacity(backing.canonical_bytes);
                canonical.extend_from_slice(&backing.header);
                for matrix in &self.matrices {
                    let CompactMatrixRows::Packed(rows) = &matrix.rows else {
                        unreachable!("packed backing owns only packed matrix rows")
                    };
                    rows.write_canonical_section(
                        &mut canonical,
                        matrix.side,
                        matrix.num_rows,
                        &matrix.value_table,
                    )
                    .expect("authenticated packed rows re-encode canonically");
                }
                assert_eq!(canonical.len(), backing.canonical_bytes);
                Cow::Owned(canonical)
            }
        }
    }

    /// Materialize the mature CSR representation from these exact immutable
    /// bytes without repeating the structural span hash. `open` already
    /// authenticated the complete canonical artifact against
    /// `statement_digest`; safe callers cannot construct this capability from
    /// unverified bytes or replace its boxed backing afterwards.
    pub fn decode_resident_authenticated(&self) -> Result<FieldR1cs, FieldR1csArtifactError> {
        let decode = |bytes: &[u8]| {
            let mut reader = std::io::Cursor::new(bytes);
            FieldR1cs::read_artifact_with_established_digest(
                &mut reader,
                self.shape,
                self.statement_digest,
                self.encoded_len(),
            )
        };
        match &self.backing {
            CompactArtifactBacking::Canonical(bytes) => decode(bytes),
            CompactArtifactBacking::Trimmed(backing) => {
                // This compatibility path already allocates a resident CSR.
                // Rebuild canonical bytes only for the duration of the decode
                // instead of permanently defeating the compact bank's trim.
                let canonical = backing.layout.rebuild(&backing.bytes);
                decode(&canonical)
            }
            CompactArtifactBacking::Packed(_) => {
                let decode_matrix = |matrix: &CompactSparseFieldMatrix| {
                    let CompactMatrixRows::Packed(rows) = &matrix.rows else {
                        unreachable!("packed backing owns only packed matrix rows")
                    };
                    rows.decode_resident(matrix.num_rows, matrix.num_cols, &matrix.value_table)
                };
                let resident = FieldR1cs {
                    m: self.shape.m,
                    k_log: self.shape.k_log,
                    k_skip: self.shape.k_skip,
                    useful_rows: self.useful_rows,
                    a_0: decode_matrix(&self.matrices[0]),
                    b_0: decode_matrix(&self.matrices[1]),
                    const_pin: self.shape.const_pin,
                    digest_cache: std::sync::OnceLock::new(),
                    csc_cache: std::sync::OnceLock::new(),
                };
                resident.seed_statement_digest(self.statement_digest);
                Ok(resident)
            }
        }
    }

    pub fn n(&self) -> usize {
        1usize << self.shape.m
    }

    pub fn k(&self) -> usize {
        1usize << self.shape.k_log
    }

    /// `a = (I ⊗ A_0) · z` directly from the compact planar bytes.
    pub fn apply_a(&self, z: &[F128]) -> Vec<F128> {
        apply_block_diag_compact(
            &self.matrices[0],
            self.backing.planar_hot_bytes(),
            z,
            self.shape.k_log,
        )
    }

    /// `b = (I ⊗ B_0) · z` directly from the compact planar bytes.
    pub fn apply_b(&self, z: &[F128]) -> Vec<F128> {
        apply_block_diag_compact(
            &self.matrices[1],
            self.backing.planar_hot_bytes(),
            z,
            self.shape.k_log,
        )
    }

    pub(crate) fn matrix_group_count(&self, side: FieldR1csArtifactMatrix) -> usize {
        match side {
            FieldR1csArtifactMatrix::A => self.matrices[0].retained_group_count(),
            FieldR1csArtifactMatrix::B => self.matrices[1].retained_group_count(),
        }
    }

    /// Visit one authenticated planar group. Returns `false` for an invalid
    /// group instead of exposing an unchecked index into the compact backing.
    /// The matrix side is an enum, so callers cannot manufacture an invalid
    /// A/B selector either.
    pub(crate) fn for_each_matrix_group_entry(
        &self,
        side: FieldR1csArtifactMatrix,
        group: usize,
        visit: impl FnMut(usize, u32, F128),
    ) -> bool {
        let matrix = match side {
            FieldR1csArtifactMatrix::A => &self.matrices[0],
            FieldR1csArtifactMatrix::B => &self.matrices[1],
        };
        matrix.for_each_group_entry(self.backing.planar_hot_bytes(), group, visit)
    }

    /// Compute `H(c) = sum_y eq_rho[y] * M_hat[y,c]` for the stacked
    /// `M_hat = [A; B]` matrix directly from authenticated compact groups.
    ///
    /// Independent row-group chunks scatter into private dense combs and are
    /// reduced after the scan. This avoids both the former two-task A/B split
    /// and the later global atomic accumulator: the latter made millions of
    /// cache-line-contended RMWs in the matrix-claim hot path. A and B are
    /// deliberately scanned into the same chunk comb, so their scratch never
    /// overlaps as two independent width-`k` result sets.
    pub(crate) fn stacked_weighted_column_image<F>(&self, row_weight: &F) -> Vec<F128>
    where
        F: Fn(usize) -> F128 + Sync,
    {
        let k = self.k();
        let a = &self.matrices[0];
        let b = &self.matrices[1];
        let bytes = self.backing.planar_hot_bytes();

        if rayon::current_num_threads() == 1 {
            let mut h = vec![F128::ZERO; k];
            for (matrix, offset) in [(a, 0usize), (b, k)] {
                for group in 0..matrix.retained_group_count() {
                    let mut cached_row = usize::MAX;
                    let mut weight = F128::ZERO;
                    let visited =
                        matrix.for_each_group_entry(bytes, group, |row, column, coefficient| {
                            if row != cached_row {
                                cached_row = row;
                                weight = row_weight(offset + row);
                            }
                            if weight != F128::ZERO {
                                h[column as usize] += coefficient * weight;
                            }
                        });
                    debug_assert!(visited);
                }
            }
            return h;
        }

        debug_assert_eq!(a.total_groups, b.total_groups);
        let group_count = a.retained_group_count().max(b.retained_group_count());
        parallel_compact_group_fold(k, group_count, |groups, comb| {
            for group in groups {
                for (matrix, offset) in [(a, 0usize), (b, k)] {
                    let mut cached_row = usize::MAX;
                    let mut weight = F128::ZERO;
                    let visited =
                        matrix.for_each_group_entry(bytes, group, |row, column, coefficient| {
                            if row != cached_row {
                                cached_row = row;
                                weight = row_weight(offset + row);
                            }
                            if weight != F128::ZERO {
                                comb[column as usize] += coefficient * weight;
                            }
                        });
                    debug_assert!(visited);
                }
            }
        })
    }
}

mod field_prover_relation_sealed {
    pub trait Sealed {}
}

/// One immutable relation accepted by the field prover.
///
/// The trait is sealed: the only implementations are [`FieldR1cs`] and the
/// fully authenticated [`CompactFieldR1cs`].  In particular, a caller cannot
/// provide unrelated `apply_a`/`apply_b` and lincheck row sources while
/// claiming a frozen statement digest.  Both implementations expose exactly
/// the same statement, witness transform and lincheck column fold; only their
/// storage representation differs.
pub trait FieldProverRelation:
    field_prover_relation_sealed::Sealed + LincheckCircuit + Sync
{
    fn field_shape(&self) -> crate::proof::FieldShape;
    fn useful_rows(&self) -> usize;
    fn field_statement_digest(&self) -> [u8; 32];
    fn apply_a_relation(&self, witness: &[F128]) -> Vec<F128>;
    fn apply_b_relation(&self, witness: &[F128]) -> Vec<F128>;
}

impl field_prover_relation_sealed::Sealed for FieldR1cs {}

impl FieldProverRelation for FieldR1cs {
    fn field_shape(&self) -> crate::proof::FieldShape {
        crate::proof::FieldShape::of(self)
    }

    fn useful_rows(&self) -> usize {
        self.useful_rows
    }

    fn field_statement_digest(&self) -> [u8; 32] {
        self.statement_digest()
    }

    fn apply_a_relation(&self, witness: &[F128]) -> Vec<F128> {
        self.apply_a(witness)
    }

    fn apply_b_relation(&self, witness: &[F128]) -> Vec<F128> {
        self.apply_b(witness)
    }
}

impl field_prover_relation_sealed::Sealed for CompactFieldR1cs {}

impl FieldProverRelation for CompactFieldR1cs {
    fn field_shape(&self) -> crate::proof::FieldShape {
        self.shape
    }

    fn useful_rows(&self) -> usize {
        self.useful_rows
    }

    fn field_statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    fn apply_a_relation(&self, witness: &[F128]) -> Vec<F128> {
        self.apply_a(witness)
    }

    fn apply_b_relation(&self, witness: &[F128]) -> Vec<F128> {
        self.apply_b(witness)
    }
}

fn build_compact_matrix_index<R: Read + Seek>(
    bytes: &[u8],
    authenticated: &mut SeekableFieldR1csArtifact<R>,
    layout: SeekableArtifactMatrixLayout,
) -> Result<CompactSparseFieldMatrix, FieldR1csArtifactError> {
    let num_rows = usize::try_from(layout.counts.rows)
        .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
    let num_cols = usize::try_from(layout.counts.cols)
        .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
    let nnz =
        usize::try_from(layout.counts.nnz).map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
    let value_table = authenticated.load_dictionary(layout)?;
    let mut cursor =
        usize::try_from(layout.groups_at).map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
    let section_end = usize::try_from(layout.section_end)
        .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
    let mut previous_first = 0i64;
    let mut total_entries = 0usize;
    let mut groups = Vec::with_capacity(num_rows.div_ceil(ARTIFACT_GROUP_ROWS));

    for first_row in (0..num_rows).step_by(ARTIFACT_GROUP_ROWS) {
        let rows = (num_rows - first_row).min(ARTIFACT_GROUP_ROWS);
        let header_end = cursor
            .checked_add(16)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        let header: &[u8; 16] = bytes
            .get(cursor..header_end)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(FieldR1csArtifactError::Truncated {
                offset: cursor as u64,
                needed: 16,
            })?;
        let mut lengths = [0usize; 4];
        for (slot, length) in lengths.iter_mut().enumerate() {
            *length = u32::from_le_bytes(
                header[slot * 4..slot * 4 + 4]
                    .try_into()
                    .expect("group length"),
            ) as usize;
        }
        let mut stream_at = header_end;
        let mut streams = [CompactByteRange { start: 0, end: 0 }; 4];
        for (slot, length) in lengths.into_iter().enumerate() {
            let end = stream_at
                .checked_add(length)
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            if end > section_end || bytes.get(stream_at..end).is_none() {
                return Err(FieldR1csArtifactError::Truncated {
                    offset: stream_at as u64,
                    needed: length,
                });
            }
            streams[slot] = CompactByteRange {
                start: stream_at,
                end,
            };
            stream_at = end;
        }

        let seed = previous_first;
        let mut counts = SliceVarints::new(streams[0].slice(bytes), layout.side, "counts");
        let mut firsts = SliceVarints::new(streams[1].slice(bytes), layout.side, "firsts");
        let mut entries = 0usize;
        for _ in 0..rows {
            let count = usize::try_from(counts.next()?)
                .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
            entries = entries
                .checked_add(count)
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            if count > 0 {
                previous_first = previous_first
                    .checked_add(zigzag_decode(firsts.next()?))
                    .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            }
        }
        counts.finish()?;
        firsts.finish()?;
        total_entries = total_entries
            .checked_add(entries)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        groups.push(CompactPlanarGroup {
            first_row,
            rows,
            entries,
            previous_first: seed,
            streams,
        });
        cursor = stream_at;
    }
    if cursor != section_end {
        return Err(FieldR1csArtifactError::MatrixLengthMismatch {
            matrix: layout.side,
            field: "compact section bytes",
            expected: layout.counts.section_bytes,
            actual: (cursor as u64).saturating_sub(layout.values_at),
        });
    }
    if total_entries != nnz {
        return Err(FieldR1csArtifactError::MatrixLengthMismatch {
            matrix: layout.side,
            field: "compact nnz",
            expected: layout.counts.nnz,
            actual: total_entries as u64,
        });
    }
    Ok(CompactSparseFieldMatrix {
        side: layout.side,
        num_rows,
        num_cols,
        nnz,
        value_table,
        total_groups: groups.len(),
        rows: CompactMatrixRows::Planar(groups),
    })
}

fn compact_group_is_canonical_zero(group: &CompactPlanarGroup, bytes: &[u8]) -> bool {
    if group.entries != 0 {
        return false;
    }
    let [counts, firsts, deltas, values] = group.streams;
    let Some(header_start) = counts.start.checked_sub(16) else {
        return false;
    };
    let Some(header) = bytes.get(header_start..counts.start) else {
        return false;
    };
    let Ok(count_bytes) = u32::try_from(group.rows) else {
        return false;
    };
    header.starts_with(&count_bytes.to_le_bytes())
        && header
            .get(4..)
            .is_some_and(|tail| tail.iter().all(|&byte| byte == 0))
        && counts.end - counts.start == group.rows
        && counts.slice(bytes).iter().all(|&byte| byte == 0)
        && firsts.start == firsts.end
        && deltas.start == deltas.end
        && values.start == values.end
        && counts.end == firsts.start
        && firsts.end == deltas.start
        && deltas.end == values.start
}

fn rebase_compact_groups(
    matrix: &mut CompactSparseFieldMatrix,
    old_section_start: usize,
    new_section_start: usize,
    retained_groups: usize,
) -> Result<(), FieldR1csArtifactError> {
    let CompactMatrixRows::Planar(groups) = &mut matrix.rows else {
        return Err(FieldR1csArtifactError::InvalidShape(
            "cannot rebase startup-packed matrix groups",
        ));
    };
    groups.truncate(retained_groups);
    groups.shrink_to_fit();
    for group in groups {
        for range in &mut group.streams {
            range.start = range
                .start
                .checked_sub(old_section_start)
                .and_then(|offset| new_section_start.checked_add(offset))
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            range.end = range
                .end
                .checked_sub(old_section_start)
                .and_then(|offset| new_section_start.checked_add(offset))
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        }
    }
    Ok(())
}

/// Drop only a byte-proven canonical all-zero suffix after the complete
/// artifact scan and structural-digest authentication have succeeded. The
/// retained group streams are copied verbatim and rebased; no matrix entry,
/// row number, coefficient, statement field, or transcript input changes.
fn trim_authenticated_compact_padding(
    bytes: Box<[u8]>,
    layouts: [SeekableArtifactMatrixLayout; 2],
    mut matrices: [CompactSparseFieldMatrix; 2],
) -> Result<(CompactArtifactBacking, [CompactSparseFieldMatrix; 2]), FieldR1csArtifactError> {
    let canonical_bytes = bytes.len();
    let mut trims = [CompactArtifactMatrixTrim {
        retained_section_bytes: 0,
        canonical_section_bytes: 0,
        retained_groups: 0,
        rows: 0,
    }; 2];
    let mut retained_total = FIELD_R1CS_ARTIFACT_HEADER_BYTES;

    for index in 0..2 {
        let matrix = &matrices[index];
        let layout = layouts[index];
        let CompactMatrixRows::Planar(groups) = &matrix.rows else {
            return Err(FieldR1csArtifactError::InvalidShape(
                "cannot trim startup-packed matrix groups",
            ));
        };
        let retained_groups = groups
            .iter()
            .rposition(|group| group.entries != 0)
            .map_or(0, |last| last + 1);
        if !groups[retained_groups..]
            .iter()
            .all(|group| compact_group_is_canonical_zero(group, &bytes))
        {
            return Err(FieldR1csArtifactError::InvalidShape(
                "authenticated empty compact group is not canonical zero encoding",
            ));
        }

        let section_start = usize::try_from(layout.values_at)
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        let retained_end = if retained_groups == 0 {
            usize::try_from(layout.groups_at)
                .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?
        } else {
            groups[retained_groups - 1].streams[3].end
        };
        let retained_section_bytes = retained_end
            .checked_sub(section_start)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        let canonical_section_bytes = usize::try_from(layout.counts.section_bytes)
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        let removed_section_bytes = canonical_section_bytes
            .checked_sub(retained_section_bytes)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        let rebuilt_zero_bytes = groups[retained_groups..]
            .iter()
            .try_fold(0usize, |bytes, group| bytes.checked_add(16 + group.rows))
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        if removed_section_bytes != rebuilt_zero_bytes {
            return Err(FieldR1csArtifactError::MatrixLengthMismatch {
                matrix: layout.side,
                field: "canonical zero suffix bytes",
                expected: removed_section_bytes as u64,
                actual: rebuilt_zero_bytes as u64,
            });
        }
        retained_total = retained_total
            .checked_add(retained_section_bytes)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        trims[index] = CompactArtifactMatrixTrim {
            retained_section_bytes,
            canonical_section_bytes,
            retained_groups,
            rows: matrix.num_rows,
        };
    }

    if retained_total == canonical_bytes {
        return Ok((CompactArtifactBacking::Canonical(bytes), matrices));
    }

    // Reuse the authenticated allocation. Only B's retained prefix may need
    // one overlapping memmove across A's discarded suffix; no second
    // artifact-sized allocation is created during startup.
    let mut compact = bytes.into_vec();
    let mut new_section_start = FIELD_R1CS_ARTIFACT_HEADER_BYTES;
    for index in 0..2 {
        let old_section_start = usize::try_from(layouts[index].values_at)
            .map_err(|_| FieldR1csArtifactError::LengthArithmetic)?;
        let old_section_end = old_section_start
            .checked_add(trims[index].retained_section_bytes)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
        if old_section_start != new_section_start {
            compact.copy_within(old_section_start..old_section_end, new_section_start);
        }
        rebase_compact_groups(
            &mut matrices[index],
            old_section_start,
            new_section_start,
            trims[index].retained_groups,
        )?;
        new_section_start = new_section_start
            .checked_add(trims[index].retained_section_bytes)
            .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
    }
    compact.truncate(retained_total);
    compact.shrink_to_fit();
    assert_eq!(compact.len(), retained_total);

    Ok((
        CompactArtifactBacking::Trimmed(TrimmedCompactArtifactBacking {
            bytes: compact.into_boxed_slice(),
            layout: CompactArtifactTrimLayout {
                canonical_bytes,
                matrices: trims,
            },
        }),
        matrices,
    ))
}

/// Header/layout-only typestate for one terminal claim evaluation.
///
/// Construction validates the exact backing length, frozen shape, count
/// arithmetic, dictionary cap, and section boundaries, but deliberately does
/// not authenticate payload rows. The only operation that can produce an
/// authenticated result consumes its one-shot evaluation right and performs
/// canonical validation, structural hashing, and all requested claim
/// evaluations in the same full payload pass.
pub struct PreflightSeekableFieldR1csArtifact<R> {
    artifact: SeekableFieldR1csArtifact<R>,
    consumed: bool,
}

impl<R: Read + Seek> PreflightSeekableFieldR1csArtifact<R> {
    pub fn open(
        reader: R,
        expected_shape: crate::proof::FieldShape,
        expected_structural_digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Self, FieldR1csArtifactError> {
        Ok(Self {
            artifact: SeekableFieldR1csArtifact::preflight_header(
                reader,
                expected_shape,
                expected_structural_digest,
                max_bytes,
            )?,
            consumed: false,
        })
    }

    pub fn reader(&self) -> &R {
        self.artifact.reader()
    }
}

impl<R: Read + Seek> crate::matrix_claim::MatrixClaimEvaluator
    for PreflightSeekableFieldR1csArtifact<R>
{
    fn field_shape(&self) -> crate::proof::FieldShape {
        self.artifact.shape
    }

    fn evaluate_matrix_claims(
        &mut self,
        fresh: Option<&crate::matrix_claim::FreshLincheckClaim>,
        accumulated: Option<&crate::matrix_claim::MatrixAccClaim>,
    ) -> Result<crate::matrix_claim::AuthenticatedMatrixClaimEvaluations, FieldR1csArtifactError>
    {
        if self.consumed {
            return Err(FieldR1csArtifactError::MatrixEvaluatorAlreadyConsumed);
        }
        self.consumed = true;
        self.artifact.scan_authenticated(fresh, accumulated)
    }
}

impl<R: Read + Seek> crate::matrix_claim::MatrixClaimEvaluator for SeekableFieldR1csArtifact<R> {
    fn field_shape(&self) -> crate::proof::FieldShape {
        self.shape
    }

    fn evaluate_matrix_claims(
        &mut self,
        fresh: Option<&crate::matrix_claim::FreshLincheckClaim>,
        accumulated: Option<&crate::matrix_claim::MatrixAccClaim>,
    ) -> Result<crate::matrix_claim::AuthenticatedMatrixClaimEvaluations, FieldR1csArtifactError>
    {
        self.scan_authenticated(fresh, accumulated)
    }
}

fn validate_streaming_claim_shapes(
    shape: crate::proof::FieldShape,
    fresh: Option<&crate::matrix_claim::FreshLincheckClaim>,
    accumulated: Option<&crate::matrix_claim::MatrixAccClaim>,
) -> Result<(), FieldR1csArtifactError> {
    if let Some(claim) = fresh {
        let rest = shape.k_log - shape.k_skip;
        if claim.x_inner_rest.len() != rest || claim.r_inner_rest.len() != rest {
            return Err(FieldR1csArtifactError::MatrixClaimShape(
                "fresh inner-rest width",
            ));
        }
        if claim.z_partial.len() != 1usize << shape.k_skip {
            return Err(FieldR1csArtifactError::MatrixClaimShape(
                "fresh partial window",
            ));
        }
    }
    if accumulated.is_some_and(|claim| claim.point.len() != 2 * shape.k_log + 1) {
        return Err(FieldR1csArtifactError::MatrixClaimShape(
            "accumulated point width",
        ));
    }
    Ok(())
}

struct StreamingFactoredEqTable {
    low: Vec<F128>,
    high: Vec<F128>,
    low_bits: usize,
    low_mask: usize,
}

impl StreamingFactoredEqTable {
    fn new(point: &[F128]) -> Self {
        let low_bits = point.len() / 2;
        Self {
            low: crate::lincheck::build_eq_table(&point[..low_bits]),
            high: crate::lincheck::build_eq_table(&point[low_bits..]),
            low_bits,
            low_mask: (1usize << low_bits) - 1,
        }
    }

    #[inline(always)]
    fn value(&self, index: usize) -> F128 {
        self.low[index & self.low_mask] * self.high[index >> self.low_bits]
    }
}

struct StreamingFreshWeights<'a> {
    claim: &'a crate::matrix_claim::FreshLincheckClaim,
    k_skip: usize,
    mask: usize,
    lambda: Vec<F128>,
    row_rest: StreamingFactoredEqTable,
    col_rest: StreamingFactoredEqTable,
}

impl<'a> StreamingFreshWeights<'a> {
    fn new(
        shape: crate::proof::FieldShape,
        claim: &'a crate::matrix_claim::FreshLincheckClaim,
    ) -> Self {
        Self {
            claim,
            k_skip: shape.k_skip,
            mask: (1usize << shape.k_skip) - 1,
            lambda: crate::zerocheck::multilinear::lagrange_weights_naive(
                shape.k_skip,
                claim.z_skip,
            ),
            row_rest: StreamingFactoredEqTable::new(&claim.x_inner_rest),
            col_rest: StreamingFactoredEqTable::new(&claim.r_inner_rest),
        }
    }

    fn side_weight(&self, index: usize) -> F128 {
        if index == 0 {
            self.claim.alpha
        } else {
            F128::ONE
        }
    }

    fn row_weight(&self, row: usize) -> F128 {
        self.lambda[row & self.mask] * self.row_rest.value(row >> self.k_skip)
    }

    fn column_weight(&self, column: usize) -> F128 {
        self.claim.z_partial[column & self.mask] * self.col_rest.value(column >> self.k_skip)
    }
}

struct StreamingAccumulatedWeights {
    stack: F128,
    row: StreamingFactoredEqTable,
    column: StreamingFactoredEqTable,
}

impl StreamingAccumulatedWeights {
    fn new(shape: crate::proof::FieldShape, claim: &crate::matrix_claim::MatrixAccClaim) -> Self {
        let (row, column) = claim.point.split_at(shape.k_log + 1);
        Self {
            stack: row[shape.k_log],
            row: StreamingFactoredEqTable::new(&row[..shape.k_log]),
            column: StreamingFactoredEqTable::new(column),
        }
    }

    fn side_weight(&self, index: usize) -> F128 {
        if index == 0 {
            F128::ONE + self.stack
        } else {
            self.stack
        }
    }

    fn row_weight(&self, row: usize) -> F128 {
        self.row.value(row)
    }

    fn column_weight(&self, column: usize) -> F128 {
        self.column.value(column)
    }
}

const STREAMING_VARINT_WINDOW_BYTES: usize = 64 * 1024;

/// One bounded cursor over a contiguous varint sub-stream of the backing
/// store: a fixed 64-KiB window refilled through `read_at`, so scanner
/// memory stays constant no matter what group lengths an artifact declares.
/// Decoding enforces the same single canonical form as [`SliceVarints`].
struct ChunkedVarints {
    matrix: FieldR1csArtifactMatrix,
    stream: &'static str,
    /// Next backing-store byte to fetch.
    file_next: u64,
    /// One past the last byte of the current sub-stream.
    end: u64,
    window: Vec<u8>,
    buffered: usize,
    consumed: usize,
    decoded: usize,
}

impl ChunkedVarints {
    fn new(matrix: FieldR1csArtifactMatrix, stream: &'static str) -> Self {
        Self {
            matrix,
            stream,
            file_next: 0,
            end: 0,
            window: vec![0u8; STREAMING_VARINT_WINDOW_BYTES],
            buffered: 0,
            consumed: 0,
            decoded: 0,
        }
    }

    fn reset(&mut self, start: u64, end: u64) {
        self.file_next = start;
        self.end = end;
        self.buffered = 0;
        self.consumed = 0;
        self.decoded = 0;
    }

    fn invalid(&self, reason: &'static str) -> FieldR1csArtifactError {
        FieldR1csArtifactError::InvalidVarint {
            matrix: self.matrix,
            stream: self.stream,
            index: self.decoded,
            reason,
        }
    }

    fn exhausted(&self) -> bool {
        self.consumed == self.buffered && self.file_next == self.end
    }

    fn next_byte<R: Read + Seek>(
        &mut self,
        artifact: &mut SeekableFieldR1csArtifact<R>,
    ) -> Result<u8, FieldR1csArtifactError> {
        if self.consumed == self.buffered {
            let want = usize::try_from(self.end - self.file_next)
                .unwrap_or(usize::MAX)
                .min(STREAMING_VARINT_WINDOW_BYTES);
            if want == 0 {
                return Err(self.invalid("truncated"));
            }
            let at = self.file_next;
            artifact.read_at(at, &mut self.window[..want])?;
            self.file_next += want as u64;
            self.buffered = want;
            self.consumed = 0;
        }
        let byte = self.window[self.consumed];
        self.consumed += 1;
        Ok(byte)
    }

    fn next<R: Read + Seek>(
        &mut self,
        artifact: &mut SeekableFieldR1csArtifact<R>,
    ) -> Result<u64, FieldR1csArtifactError> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.next_byte(artifact)?;
            let payload = (byte & 0x7f) as u64;
            if shift == 63 && payload > 1 {
                return Err(self.invalid("overflow"));
            }
            value |= payload << shift;
            if byte & 0x80 == 0 {
                if payload == 0 && shift != 0 {
                    return Err(self.invalid("non-minimal"));
                }
                self.decoded += 1;
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                return Err(self.invalid("overflow"));
            }
        }
    }
}

/// The four planar sub-stream cursors of one row group.
struct PlanarStreamCursors {
    counts: ChunkedVarints,
    firsts: ChunkedVarints,
    deltas: ChunkedVarints,
    values: ChunkedVarints,
}

impl PlanarStreamCursors {
    fn new(matrix: FieldR1csArtifactMatrix) -> Self {
        Self {
            counts: ChunkedVarints::new(matrix, "counts"),
            firsts: ChunkedVarints::new(matrix, "firsts"),
            deltas: ChunkedVarints::new(matrix, "deltas"),
            values: ChunkedVarints::new(matrix, "values"),
        }
    }

    /// Aim the four cursors at one group payload starting at `payload_at`
    /// with the given sub-stream byte lengths; returns one past the group's
    /// last byte.
    fn reset(
        &mut self,
        payload_at: u64,
        lengths: &[usize; 4],
    ) -> Result<u64, FieldR1csArtifactError> {
        let mut cursor = payload_at;
        for (stream, length) in [
            &mut self.counts,
            &mut self.firsts,
            &mut self.deltas,
            &mut self.values,
        ]
        .into_iter()
        .zip(lengths)
        {
            let end = cursor
                .checked_add(checked_u64(*length)?)
                .ok_or(FieldR1csArtifactError::LengthArithmetic)?;
            stream.reset(cursor, end);
            cursor = end;
        }
        Ok(cursor)
    }

    /// Every cursor must land exactly on its sub-stream end: leftover bytes
    /// mean the group header over-declared and the encoding is not canonical.
    fn finish_group(&self, _total_bytes: u64) -> Result<(), FieldR1csArtifactError> {
        for stream in [&self.counts, &self.firsts, &self.deltas, &self.values] {
            if !stream.exhausted() {
                return Err(stream.invalid("trailing bytes"));
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn streaming_finish_row(
    row: usize,
    fresh_row: &mut F128,
    accumulated_row: &mut F128,
    fresh_matrix: &mut F128,
    accumulated_matrix: &mut F128,
    fresh: Option<&StreamingFreshWeights<'_>>,
    accumulated: Option<&StreamingAccumulatedWeights>,
) {
    if let Some(weights) = fresh {
        *fresh_matrix += *fresh_row * weights.row_weight(row);
        *fresh_row = F128::ZERO;
    }
    if let Some(weights) = accumulated {
        *accumulated_matrix += *accumulated_row * weights.row_weight(row);
        *accumulated_row = F128::ZERO;
    }
}

struct StreamingOnePieceByteHash(noid_poseidon2b::native::Poseidon2bSponge);

impl StreamingOnePieceByteHash {
    fn new(domain: &[u8], payload_len: u64) -> Self {
        let mut sponge = noid_poseidon2b::native::Poseidon2bSponge::with_iv(
            noid_poseidon2b::native::capacity_iv(noid_poseidon2b::native::TAG_BYTEHASH),
        );
        sponge.update(&(domain.len() as u64).to_le_bytes());
        sponge.update(domain);
        sponge.update(&1u64.to_le_bytes());
        sponge.update(&payload_len.to_le_bytes());
        Self(sponge)
    }

    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    fn finalize(self) -> [u8; 32] {
        self.0.finalize()
    }
}

/// Rows per statement-digest span. Small enough that per-span buffers stay
/// cache-friendly (a ~20-nnz/row span is ~1 MB), large enough that span
/// digests are negligible against the span payloads.
const DIGEST_SPAN_ROWS: usize = 2048;

/// Independent Poseidon2b digests of a coefficient matrix's rows in
/// [`DIGEST_SPAN_ROWS`]-row spans (parallel), each span serialized as
/// length-prefixed rows of `(column, coeff.lo, coeff.hi)` u64 triples.
fn matrix_span_digests(m: &SparseFieldMatrix) -> Vec<[u8; 32]> {
    use rayon::prelude::*;
    let n_spans = m.num_rows.div_ceil(DIGEST_SPAN_ROWS);
    (0..n_spans)
        .into_par_iter()
        .map(|s| {
            let r0 = s * DIGEST_SPAN_ROWS;
            let r1 = ((s + 1) * DIGEST_SPAN_ROWS).min(m.num_rows);
            let payload: usize = (r0..r1).map(|r| 8 + 24 * m.row_len(r)).sum();
            let mut bytes = Vec::with_capacity(payload);
            for r in r0..r1 {
                push_u64(&mut bytes, m.row_len(r) as u64);
                for (col, coeff) in m.row(r) {
                    push_u64(&mut bytes, col as u64);
                    push_u64(&mut bytes, coeff.lo);
                    push_u64(&mut bytes, coeff.hi);
                }
            }
            noid_poseidon2b::native::poseidon2b_hash_byte_slices(
                b"NOID/IVC/FIELD-R1CS-SPAN",
                &[&bytes],
            )
        })
        .collect()
}

#[inline]
fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Block-diagonal `(I ⊗ M_0) · z` over F128.
///
/// Parallel over the Kronecker blocks AND, within each block, over row chunks.
/// Block-only parallelism (one task per `k`-sized block) starves when there
/// are few large blocks: the recursion link commits ONE block of `2^k_log`
/// rows, so a block-parallel loop is a single serial task walking millions of
/// rows (measured ~6.5 s at `k_log = 24`). Nesting a row-chunk `par_chunks_mut`
/// restores full core utilization there and is a no-op for the many-small-block
/// regime (a block shorter than `ROW_CHUNK` yields one inner chunk). The
/// per-row work and its accumulation order are unchanged, so the output is
/// bit-identical to the serial form.
pub fn apply_block_diag_field(m_0: &SparseFieldMatrix, z: &[F128], k_log: usize) -> Vec<F128> {
    use rayon::prelude::*;

    let k = 1usize << k_log;
    assert_eq!(m_0.num_rows, k);
    assert_eq!(m_0.num_cols, k);
    assert_eq!(z.len() % k, 0);

    const ROW_CHUNK: usize = 4096;
    let mut out = vec![F128::ZERO; z.len()];
    out.par_chunks_mut(k)
        .zip(z.par_chunks(k))
        .for_each(|(out_block, z_block)| {
            out_block
                .par_chunks_mut(ROW_CHUNK)
                .enumerate()
                .for_each(|(ci, out_rows)| {
                    let r0 = ci * ROW_CHUNK;
                    for (j, o) in out_rows.iter_mut().enumerate() {
                        let mut acc = F128::ZERO;
                        for (c, coeff) in m_0.row(r0 + j) {
                            acc += coeff * z_block[c as usize];
                        }
                        *o = acc;
                    }
                });
        });
    out
}

/// Compact-planar twin of [`apply_block_diag_field`].  The group index makes
/// the canonical artifact's delta streams independently decodable; each Rayon
/// task writes one disjoint 2048-row output slice and reads the immutable byte
/// backing without locks or CSR materialization.
fn apply_block_diag_compact(
    m_0: &CompactSparseFieldMatrix,
    bytes: Option<&[u8]>,
    z: &[F128],
    k_log: usize,
) -> Vec<F128> {
    use rayon::prelude::*;

    let k = 1usize << k_log;
    assert_eq!(m_0.num_rows, k);
    assert_eq!(m_0.num_cols, k);
    assert_eq!(z.len() % k, 0);

    let mut out = vec![F128::ZERO; z.len()];
    out.par_chunks_mut(k)
        .zip(z.par_chunks(k))
        .for_each(|(out_block, z_block)| {
            out_block
                .par_chunks_mut(ARTIFACT_GROUP_ROWS)
                .enumerate()
                .for_each(|(group_index, out_rows)| {
                    let first_row = group_index * ARTIFACT_GROUP_ROWS;
                    m_0.for_each_group_entry(bytes, group_index, |row, column, coefficient| {
                        out_rows[row - first_row] += coefficient * z_block[column as usize];
                    });
                });
        });
    out
}

// ---------------------------------------------------------------------------
// FlipBattery: incremental single-wire mutation checks
// ---------------------------------------------------------------------------

/// Incremental wire-flip mutation checker: precomputes `Az`, `Bz` and
/// per-column row lists once, then answers "does the trace still satisfy
/// after `z[w] += 1`?" in `O(deg_A(w) + deg_B(w))` — a single-wire flip
/// only perturbs the rows whose A/B row reads that wire (block-diagonal
/// relation, `C = I`, so the flipped wire's own row is the only RHS
/// change). Semantically identical to cloning the witness, flipping, and
/// running the full [`FieldR1cs::satisfies`]; mutation batteries at
/// verifier-trace scale (`2^20+` rows × 10⁴+ targets) are infeasible
/// with full passes and instant with this.
pub struct FlipBattery<'a> {
    r1cs: &'a FieldR1cs,
    z: Vec<F128>,
    az: Vec<F128>,
    bz: Vec<F128>,
    /// Per inner column: the block-local rows reading it, with coefficients.
    cols_a: Vec<Vec<(u32, F128)>>,
    cols_b: Vec<Vec<(u32, F128)>>,
}

impl<'a> FlipBattery<'a> {
    pub fn new(r1cs: &'a FieldR1cs, z: &[F128]) -> Self {
        assert_eq!(z.len(), r1cs.n());
        let az = r1cs.apply_a(z);
        let bz = r1cs.apply_b(z);
        assert!(
            az.iter()
                .zip(bz.iter())
                .zip(z.iter())
                .all(|((a, b), zi)| *a * *b == *zi),
            "FlipBattery requires an honest witness"
        );
        let transpose = |m: &SparseFieldMatrix| {
            let mut cols: Vec<Vec<(u32, F128)>> = vec![Vec::new(); m.num_cols];
            for r in 0..m.num_rows {
                for (c, coeff) in m.row(r) {
                    cols[c as usize].push((r as u32, coeff));
                }
            }
            cols
        };
        Self {
            r1cs,
            z: z.to_vec(),
            az,
            bz,
            cols_a: transpose(&r1cs.a_0),
            cols_b: transpose(&r1cs.b_0),
        }
    }

    /// Whether the trace still satisfies after flipping `z[w] += 1`
    /// (leaves the battery state unchanged).
    pub fn survives_flip(&mut self, w: usize) -> bool {
        let k_log = self.r1cs.k_log;
        let base = (w >> k_log) << k_log;
        let i = w & ((1usize << k_log) - 1);

        // Apply the delta (char 2: Δz = 1 ⇒ Δ(Az)[r] = A[r][i]).
        self.z[w] += F128::ONE;
        for &(r, coeff) in &self.cols_a[i] {
            self.az[base + r as usize] += coeff;
        }
        for &(r, coeff) in &self.cols_b[i] {
            self.bz[base + r as usize] += coeff;
        }

        // Check the affected rows (both column lists plus the wire's own
        // row); duplicates re-check harmlessly.
        let mut ok = {
            let r = w;
            self.az[r] * self.bz[r] == self.z[r]
        };
        if ok {
            for &(r, _) in &self.cols_a[i] {
                let r = base + r as usize;
                if self.az[r] * self.bz[r] != self.z[r] {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            for &(r, _) in &self.cols_b[i] {
                let r = base + r as usize;
                if self.az[r] * self.bz[r] != self.z[r] {
                    ok = false;
                    break;
                }
            }
        }

        // Revert (char 2: adding the same deltas again).
        self.z[w] += F128::ONE;
        for &(r, coeff) in &self.cols_a[i] {
            self.az[base + r as usize] += coeff;
        }
        for &(r, coeff) in &self.cols_b[i] {
            self.bz[base + r as usize] += coeff;
        }
        ok
    }

    /// Run the battery over a wire range, returning the survivors.
    pub fn survivors(&mut self, range: std::ops::Range<usize>) -> Vec<usize> {
        range.filter(|&w| self.survives_flip(w)).collect()
    }

    /// Whether `w` is a pin-row helper: the free wire `pin_f128`
    /// materializes so its row can constrain an expression SUM. Such a
    /// wire appears with coefficient one in its own A row (where it
    /// cancels against the `C = I` right-hand side in char 2), that row's
    /// B side is the constant-one wire, and nothing else reads it —
    /// flipping it is satisfiability-neutral BY CONSTRUCTION, so mutation
    /// batteries exclude exactly this shape.
    pub fn is_pin_helper(&self, w: usize) -> bool {
        let i = w & ((1usize << self.r1cs.k_log) - 1);
        self.cols_b[i].is_empty()
            && self.cols_a[i].len() == 1
            && self.cols_a[i][0] == (i as u32, F128::ONE)
            && self.r1cs.b_0.row_cols(i) == [0u32]
            && self.r1cs.b_0.row(i).next().map(|(_, v)| v) == Some(F128::ONE)
    }

    /// [`Self::survivors`] minus the pin-helper class — the standard gate
    /// for assembled traces where pin rows interleave with allocations.
    pub fn survivors_excluding_pin_helpers(&mut self, range: std::ops::Range<usize>) -> Vec<usize> {
        range
            .filter(|&w| !self.is_pin_helper(w) && self.survives_flip(w))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// FieldCscCircuit: coefficient-carrying LincheckCircuit
// ---------------------------------------------------------------------------

/// Column-major (CSC) [`LincheckCircuit`] over a pair of F128-coefficient
/// matrices: vs the binary-matrix fold, the eq-weighted column
/// marginal gains one field multiplication per nonzero,
///
///   `comb[c] = α · Σ_{(r,κ) ∈ colA(c)} κ · eq_inner[r]
///            +     Σ_{(r,κ) ∈ colB(c)} κ · eq_inner[r]`
///
/// replacing the boolean path's XOR accumulation. Everything else in the
/// lincheck (sumcheck rounds, univariate skip, transcript) is untouched.
#[derive(Clone)]
pub struct FieldCscCircuit {
    n_cols: usize,
    a_col_ptr: Vec<u32>,
    a_rows: Vec<u32>,
    a_coeffs: Vec<F128>,
    b_col_ptr: Vec<u32>,
    b_rows: Vec<u32>,
    b_coeffs: Vec<F128>,
    const_pin: Option<usize>,
}

impl std::fmt::Debug for FieldCscCircuit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldCscCircuit")
            .field("n_cols", &self.n_cols)
            .field("nnz_a", &self.a_rows.len())
            .field("nnz_b", &self.b_rows.len())
            .finish()
    }
}

/// Flatten one coefficient matrix into CSC arrays.
fn field_csc_from_rows(m: &SparseFieldMatrix) -> (Vec<u32>, Vec<u32>, Vec<F128>) {
    assert!(m.num_rows <= u32::MAX as usize);
    assert!(m.num_cols <= u32::MAX as usize);
    let mut col_ptr = vec![0u32; m.num_cols + 1];
    for &c in &m.col_indices {
        col_ptr[c as usize + 1] += 1;
    }
    for c in 0..m.num_cols {
        col_ptr[c + 1] += col_ptr[c];
    }
    let mut next = col_ptr.clone();
    let nnz = *col_ptr.last().unwrap() as usize;
    let mut rows_flat = vec![0u32; nnz];
    let mut coeffs_flat = vec![F128::ZERO; nnz];
    for r in 0..m.num_rows {
        for (c, coeff) in m.row(r) {
            let c = c as usize;
            let slot = next[c] as usize;
            rows_flat[slot] = r as u32;
            coeffs_flat[slot] = coeff;
            next[c] += 1;
        }
    }
    (col_ptr, rows_flat, coeffs_flat)
}

impl FieldCscCircuit {
    pub fn from_matrices(a_0: &SparseFieldMatrix, b_0: &SparseFieldMatrix) -> Self {
        assert_eq!(a_0.num_rows, b_0.num_rows);
        assert_eq!(a_0.num_cols, b_0.num_cols);
        let (a_col_ptr, a_rows, a_coeffs) = field_csc_from_rows(a_0);
        let (b_col_ptr, b_rows, b_coeffs) = field_csc_from_rows(b_0);
        Self {
            n_cols: a_0.num_cols,
            a_col_ptr,
            a_rows,
            a_coeffs,
            b_col_ptr,
            b_rows,
            b_coeffs,
            const_pin: None,
        }
    }

    /// Set the constant-wire pin column (see `docs/const-wire-pin.md`).
    pub fn with_const_pin(mut self, const_pin: Option<usize>) -> Self {
        self.const_pin = const_pin;
        self
    }
}

/// Same rayon-dispatch threshold as the boolean `CscCircuit`.
const FIELD_FOLD_PAR_THRESHOLD: usize = 1usize << 12;

/// Peak-memory budget for compact/resident fold per-chunk partial combs. Each
/// parallel chunk holds one width-`n_cols` F128 comb; at the m=24 block-bearing
/// class `n_cols = 2^24` (256 MB/comb), so one comb per worker was a multi-GB
/// transient (the largest at that scale). The chunk count is capped so the live
/// combs stay under this budget while retaining as many independent row
/// chunks as the available workers and supported width permit. Small
/// instances have small combs, so the cap only binds at large `m`.
const FOLD_COMB_BUDGET_BYTES: usize = 1usize << 30;

fn compact_fold_chunk_count_for_threads(
    n_cols: usize,
    group_count: usize,
    threads: usize,
) -> usize {
    compact_fold_chunk_count_for_element(n_cols, group_count, threads, std::mem::size_of::<F128>())
}

fn compact_fold_chunk_count_for_element(
    n_cols: usize,
    group_count: usize,
    threads: usize,
    element_bytes: usize,
) -> usize {
    if group_count == 0 {
        return 0;
    }
    let comb_bytes = n_cols.saturating_mul(element_bytes);
    let budget_chunks = (FOLD_COMB_BUDGET_BYTES / comb_bytes.max(1)).max(1);
    let target_chunks = threads.max(1).min(budget_chunks).min(group_count).max(1);
    let groups_per_chunk = group_count.div_ceil(target_chunks);
    group_count.div_ceil(groups_per_chunk)
}

fn compact_c1_fold_chunk_count_for_threads(
    n_cols: usize,
    group_count: usize,
    threads: usize,
) -> usize {
    compact_fold_chunk_count_for_element(n_cols, group_count, threads, std::mem::size_of::<F256>())
}

/// Scatter authenticated row groups into bounded private dense combs and
/// reduce them without an identity allocation.
///
/// `reduce_with` always reuses one of its two input `Vec`s, so the output is
/// already included in the `chunk_count * n_cols * sizeof(F128)` bound.  In
/// particular, the m22 embedded relation uses 64 MiB per comb: an 11-worker
/// proof pool owns at most 704 MiB of fold combs, not a separate A result plus
/// a second set of B partials.  The caller must therefore scan both A and B
/// inside `fold_chunk` when both contribute to the same result.
fn parallel_compact_group_fold<F>(n_cols: usize, group_count: usize, fold_chunk: F) -> Vec<F128>
where
    F: Fn(std::ops::Range<usize>, &mut [F128]) + Sync,
{
    use rayon::prelude::*;

    if group_count == 0 {
        return vec![F128::ZERO; n_cols];
    }

    let chunk_count =
        compact_fold_chunk_count_for_threads(n_cols, group_count, rayon::current_num_threads());
    let comb_bytes = n_cols.saturating_mul(std::mem::size_of::<F128>());
    debug_assert!(
        chunk_count.saturating_mul(comb_bytes) <= FOLD_COMB_BUDGET_BYTES
            || (chunk_count == 1 && comb_bytes > FOLD_COMB_BUDGET_BYTES),
        "private fold combs must obey the fixed scratch budget",
    );
    let groups_per_chunk = group_count.div_ceil(chunk_count);

    (0..chunk_count)
        .into_par_iter()
        .map(|chunk| {
            let first = chunk * groups_per_chunk;
            let end = ((chunk + 1) * groups_per_chunk).min(group_count);
            let mut comb = vec![F128::ZERO; n_cols];
            fold_chunk(first..end, &mut comb);
            comb
        })
        .reduce_with(|mut accumulator, partial| {
            for (left, right) in accumulator.iter_mut().zip(partial) {
                *left += right;
            }
            accumulator
        })
        .expect("non-empty compact group range has one fold chunk")
}

/// C1 counterpart of [`parallel_compact_group_fold`]. A width-`n_cols`
/// extension-field comb is twice as large, so the same fixed scratch budget
/// admits at most two private combs at the B255 width instead of four base
/// field combs. Both matrix sides must be scanned into each private comb.
pub(crate) fn parallel_compact_group_fold_c1<F>(
    n_cols: usize,
    group_count: usize,
    fold_chunk: F,
) -> Vec<F256>
where
    F: Fn(std::ops::Range<usize>, &mut [F256]) + Sync,
{
    use rayon::prelude::*;

    if group_count == 0 {
        return vec![F256::ZERO; n_cols];
    }

    let chunk_count =
        compact_c1_fold_chunk_count_for_threads(n_cols, group_count, rayon::current_num_threads());
    let comb_bytes = n_cols.saturating_mul(std::mem::size_of::<F256>());
    debug_assert!(
        chunk_count.saturating_mul(comb_bytes) <= FOLD_COMB_BUDGET_BYTES
            || (chunk_count == 1 && comb_bytes > FOLD_COMB_BUDGET_BYTES),
        "private C1 fold combs must obey the fixed scratch budget",
    );
    let groups_per_chunk = group_count.div_ceil(chunk_count);

    (0..chunk_count)
        .into_par_iter()
        .map(|chunk| {
            let first = chunk * groups_per_chunk;
            let end = ((chunk + 1) * groups_per_chunk).min(group_count);
            let mut comb = vec![F256::ZERO; n_cols];
            fold_chunk(first..end, &mut comb);
            comb
        })
        .reduce_with(|mut accumulator, partial| {
            for (left, right) in accumulator.iter_mut().zip(partial) {
                *left += right;
            }
            accumulator
        })
        .expect("non-empty compact group range has one C1 fold chunk")
}

impl LincheckCircuit for FieldCscCircuit {
    fn n_cols(&self) -> usize {
        self.n_cols
    }
    fn const_pin_col(&self) -> Option<usize> {
        self.const_pin
    }
    fn fold_alpha_batched(&self, alpha: F128, eq_inner: &[F128]) -> Vec<F128> {
        use rayon::prelude::*;
        assert_eq!(eq_inner.len(), self.n_cols);
        let one_col = |c: usize| {
            let mut sa = F128::ZERO;
            let (lo, hi) = (self.a_col_ptr[c] as usize, self.a_col_ptr[c + 1] as usize);
            for (r, coeff) in self.a_rows[lo..hi].iter().zip(&self.a_coeffs[lo..hi]) {
                sa += *coeff * eq_inner[*r as usize];
            }
            let mut sb = F128::ZERO;
            let (lo, hi) = (self.b_col_ptr[c] as usize, self.b_col_ptr[c + 1] as usize);
            for (r, coeff) in self.b_rows[lo..hi].iter().zip(&self.b_coeffs[lo..hi]) {
                sb += *coeff * eq_inner[*r as usize];
            }
            alpha * sa + sb
        };
        if self.n_cols < FIELD_FOLD_PAR_THRESHOLD {
            return (0..self.n_cols).map(one_col).collect();
        }
        let mut out = vec![F128::ZERO; self.n_cols];
        out.par_iter_mut()
            .enumerate()
            .for_each(|(c, slot)| *slot = one_col(c));
        out
    }
}

/// Borrowing, **row-major** [`LincheckCircuit`] over a pair of
/// F128-coefficient matrices `(a_0, b_0)`.
///
/// It folds directly off the row-major [`SparseFieldMatrix`] storage the
/// caller already owns, so — unlike [`FieldCscCircuit`] — it allocates **no**
/// transposed CSC copy. During a prover or verifier lincheck window only ONE
/// matrix representation (the un-droppable row-major `a_0`/`b_0`) stays
/// resident, roughly halving constraint-matrix RAM.
///
/// `fold_alpha_batched` is **value-identical** to
/// [`FieldCscCircuit::fold_alpha_batched`]: it computes the same
///
///   `comb[c] = α · Σ_{r} A_0[r,c]·eq[r] + Σ_{r} B_0[r,c]·eq[r]`
///
/// by scattering `α·coeff·eq[r]` (matrix A) and `coeff·eq[r]` (matrix B) into
/// `comb[c]`. GF(2^128) addition is exact, associative and commutative, so the
/// scatter/accumulation order is irrelevant to the result (the
/// `csc_fold_matches_direct` test asserts this scatter form equals the CSC
/// fold bit-for-bit). Identical `comb_vec` ⇒ identical Fiat-Shamir transcript
/// ⇒ byte-identical proof.
pub struct FieldRowCircuit<'a> {
    a_0: &'a SparseFieldMatrix,
    b_0: &'a SparseFieldMatrix,
    const_pin: Option<usize>,
}

impl<'a> FieldRowCircuit<'a> {
    pub fn new(
        a_0: &'a SparseFieldMatrix,
        b_0: &'a SparseFieldMatrix,
        const_pin: Option<usize>,
    ) -> Self {
        debug_assert_eq!(a_0.num_rows, b_0.num_rows);
        debug_assert_eq!(a_0.num_cols, b_0.num_cols);
        Self {
            a_0,
            b_0,
            const_pin,
        }
    }

    /// Fold both matrix sides into one C1 comb. The row weight is computed
    /// once, multiplied by `alpha` once, then each F128 matrix coefficient is
    /// applied with the two-product [`F256::scale_base`] path.
    fn fold_alpha_batched_c1_with_row_weight<W>(&self, alpha: F256, row_weight: W) -> Vec<F256>
    where
        W: Fn(usize) -> F256 + Sync,
    {
        use rayon::prelude::*;

        let n = self.a_0.num_cols;
        debug_assert_eq!(self.a_0.num_rows, self.b_0.num_rows);
        let row_count = self.a_0.num_rows;
        let nnz = self.a_0.nnz() + self.b_0.nnz();
        let threads = rayon::current_num_threads().max(1);

        let fold_rows = |rows: std::ops::Range<usize>, comb: &mut [F256]| {
            for row in rows {
                let weight = row_weight(row);
                let alpha_weight = alpha * weight;
                for (column, coefficient) in self.a_0.row(row) {
                    comb[column as usize] += scale_matrix_coefficient_c1(alpha_weight, coefficient);
                }
                for (column, coefficient) in self.b_0.row(row) {
                    comb[column as usize] += scale_matrix_coefficient_c1(weight, coefficient);
                }
            }
        };

        if nnz < FIELD_FOLD_PAR_THRESHOLD || threads == 1 || row_count == 0 {
            let mut comb = vec![F256::ZERO; n];
            fold_rows(0..row_count, &mut comb);
            return comb;
        }

        let chunk_count = compact_c1_fold_chunk_count_for_threads(n, row_count, threads).max(1);
        let rows_per_chunk = row_count.div_ceil(chunk_count);
        (0..chunk_count)
            .into_par_iter()
            .map(|chunk| {
                let first = chunk * rows_per_chunk;
                let end = ((chunk + 1) * rows_per_chunk).min(row_count);
                let mut comb = vec![F256::ZERO; n];
                fold_rows(first..end, &mut comb);
                comb
            })
            .reduce_with(|mut accumulator, partial| {
                for (left, right) in accumulator.iter_mut().zip(partial) {
                    *left += right;
                }
                accumulator
            })
            .expect("non-empty row range has one C1 fold chunk")
    }
}

impl LincheckCircuit for FieldRowCircuit<'_> {
    fn n_cols(&self) -> usize {
        self.a_0.num_cols
    }
    fn const_pin_col(&self) -> Option<usize> {
        self.const_pin
    }
    fn fold_alpha_batched(&self, alpha: F128, eq_inner: &[F128]) -> Vec<F128> {
        use rayon::prelude::*;
        let n = self.a_0.num_cols;
        assert_eq!(eq_inner.len(), n);

        let nnz = self.a_0.nnz() + self.b_0.nnz();
        let threads = rayon::current_num_threads().max(1);

        // Serial scatter for small instances and for the deliberately
        // single-threaded production verifier: one output comb,
        // `comb[c] += weight·coeff·eq[r]` over both matrices' rows (weight α
        // for A, 1 for B). Besides avoiding parallel overhead, the verifier
        // therefore never holds separate width-n A and B partial combs.
        if nnz < FIELD_FOLD_PAR_THRESHOLD || threads == 1 {
            let mut comb = vec![F128::ZERO; n];
            for r in 0..self.a_0.num_rows {
                let er = eq_inner[r];
                for (c, coeff) in self.a_0.row(r) {
                    comb[c as usize] += alpha * coeff * er;
                }
            }
            for r in 0..self.b_0.num_rows {
                let er = eq_inner[r];
                for (c, coeff) in self.b_0.row(r) {
                    comb[c as usize] += coeff * er;
                }
            }
            return comb;
        }

        // Parallel scatter: split the rows into row-chunks, each producing a
        // private width-`n` partial comb, reduced with field addition (char-2,
        // associative ⇒ value-identical to any other order).
        //
        // Chunk count = `threads` (ONE contiguous chunk per worker), NOT a
        // multiple of it: each partial comb is `n = n_cols` F128 (256 MB at
        // the m=24 block-bearing class), so `4 * threads` chunks made the fold
        // a multi-GB transient — VmHWM showed a +266 MB spike at m=19
        // (n_cols = 8 MB), i.e. ~8.5 GB at m=24 (n_cols = 256 MB), the single
        // largest prover transient and invisible to lap-boundary RSS. One
        // chunk per worker caps the live combs at ~`threads` (uniform row
        // density load-balances the equal ranges), trading a little
        // work-steal slack for the memory. Preserves the CSC fold's
        // column-parallelism without materializing a transpose.
        // Cap the chunk count so the live per-chunk combs fit the memory budget
        // (see FOLD_COMB_BUDGET_BYTES): one comb per worker was ~threads * n_cols
        // F128, and `reduce`'s per-segment identity seed doubled that. Bound the
        // chunks by the budget and use `reduce_with` (no identity comb — it
        // folds the map outputs directly, the first as seed).
        let comb_bytes = n * std::mem::size_of::<F128>();
        let max_chunks = (FOLD_COMB_BUDGET_BYTES / comb_bytes.max(1)).max(1);
        let fold_matrix = |m: &SparseFieldMatrix, weight: F128| -> Vec<F128> {
            let target_chunks = threads.min(max_chunks).max(1);
            let chunk = m.num_rows.div_ceil(target_chunks).max(256);
            let n_chunks = m.num_rows.div_ceil(chunk);
            (0..n_chunks)
                .into_par_iter()
                .map(|ci| {
                    let r0 = ci * chunk;
                    let r1 = ((ci + 1) * chunk).min(m.num_rows);
                    let mut comb = vec![F128::ZERO; n];
                    for r in r0..r1 {
                        let er = eq_inner[r];
                        for (c, coeff) in m.row(r) {
                            comb[c as usize] += weight * coeff * er;
                        }
                    }
                    comb
                })
                .reduce_with(|mut acc, part| {
                    for (x, y) in acc.iter_mut().zip(part) {
                        *x += y;
                    }
                    acc
                })
                .unwrap_or_else(|| vec![F128::ZERO; n])
        };

        let mut comb = fold_matrix(self.a_0, alpha);
        let b_comb = fold_matrix(self.b_0, F128::ONE);
        for (x, y) in comb.iter_mut().zip(b_comb) {
            *x += y;
        }
        comb
    }

    fn fold_alpha_batched_c1(&self, alpha: F256, eq_inner: &[F256]) -> Vec<F256> {
        assert_eq!(eq_inner.len(), self.a_0.num_cols);
        self.fold_alpha_batched_c1_with_row_weight(alpha, |row| eq_inner[row])
    }

    fn fold_alpha_batched_quirky_c1(
        &self,
        alpha: F256,
        z_skip: F256,
        x_inner_rest: &[F256],
        k_skip: usize,
    ) -> Vec<F256> {
        let skip_size = 1usize << k_skip;
        let skip = crate::zerocheck::field_c1::lagrange_weights(k_skip, z_skip, 0);
        let rest = crate::zerocheck::field_c1::build_eq_table(x_inner_rest);
        assert_eq!(skip_size.saturating_mul(rest.len()), self.a_0.num_cols);
        self.fold_alpha_batched_c1_with_row_weight(alpha, |row| {
            skip[row & (skip_size - 1)] * rest[row >> k_skip]
        })
    }
}

impl LincheckCircuit for FieldR1cs {
    fn n_cols(&self) -> usize {
        self.a_0.num_cols
    }

    fn const_pin_col(&self) -> Option<usize> {
        self.const_pin
    }

    fn fold_alpha_batched(&self, alpha: F128, eq_inner: &[F128]) -> Vec<F128> {
        FieldRowCircuit::new(&self.a_0, &self.b_0, self.const_pin)
            .fold_alpha_batched(alpha, eq_inner)
    }

    fn fold_alpha_batched_c1(&self, alpha: F256, eq_inner: &[F256]) -> Vec<F256> {
        FieldRowCircuit::new(&self.a_0, &self.b_0, self.const_pin)
            .fold_alpha_batched_c1(alpha, eq_inner)
    }

    fn fold_alpha_batched_quirky_c1(
        &self,
        alpha: F256,
        z_skip: F256,
        x_inner_rest: &[F256],
        k_skip: usize,
    ) -> Vec<F256> {
        FieldRowCircuit::new(&self.a_0, &self.b_0, self.const_pin).fold_alpha_batched_quirky_c1(
            alpha,
            z_skip,
            x_inner_rest,
            k_skip,
        )
    }
}

impl CompactFieldR1cs {
    /// Fold an arbitrary C1 row-weight oracle over the authenticated compact
    /// relation without materializing a width-k equality table. Each 2048-row
    /// tile holds its weights and alpha-scaled weights once and scans A and B
    /// into the same bounded private comb.
    fn fold_alpha_batched_c1_with_row_weight<W>(&self, alpha: F256, row_weight: W) -> Vec<F256>
    where
        W: Fn(usize) -> F256 + Sync,
    {
        let n = self.k();
        let a = &self.matrices[0];
        let b = &self.matrices[1];
        let bytes = self.backing.planar_hot_bytes();
        debug_assert_eq!(a.total_groups, b.total_groups);
        let group_count = a.retained_group_count().max(b.retained_group_count());

        let fill_group_weights =
            |group: usize,
             weights: &mut [F256; ARTIFACT_GROUP_ROWS],
             alpha_weights: &mut [F256; ARTIFACT_GROUP_ROWS]| {
                let first_row = group * ARTIFACT_GROUP_ROWS;
                let rows = n.saturating_sub(first_row).min(ARTIFACT_GROUP_ROWS);
                for local_row in 0..rows {
                    let weight = row_weight(first_row + local_row);
                    weights[local_row] = weight;
                    alpha_weights[local_row] = alpha * weight;
                }
                first_row
            };

        let fold_groups = |groups: std::ops::Range<usize>, comb: &mut [F256]| {
            let mut weights = [F256::ZERO; ARTIFACT_GROUP_ROWS];
            let mut alpha_weights = [F256::ZERO; ARTIFACT_GROUP_ROWS];
            for group in groups {
                let first_row = fill_group_weights(group, &mut weights, &mut alpha_weights);
                let visited = a.for_each_group_entry(bytes, group, |row, column, coefficient| {
                    comb[column as usize] +=
                        scale_matrix_coefficient_c1(alpha_weights[row - first_row], coefficient);
                });
                debug_assert!(visited);
                let visited = b.for_each_group_entry(bytes, group, |row, column, coefficient| {
                    comb[column as usize] +=
                        scale_matrix_coefficient_c1(weights[row - first_row], coefficient);
                });
                debug_assert!(visited);
            }
        };

        let nnz = a.nnz + b.nnz;
        if nnz < FIELD_FOLD_PAR_THRESHOLD || rayon::current_num_threads() == 1 {
            let mut comb = vec![F256::ZERO; n];
            fold_groups(0..group_count, &mut comb);
            return comb;
        }
        parallel_compact_group_fold_c1(n, group_count, fold_groups)
    }
}

impl LincheckCircuit for CompactFieldR1cs {
    fn n_cols(&self) -> usize {
        self.k()
    }

    fn const_pin_col(&self) -> Option<usize> {
        self.shape.const_pin
    }

    fn fold_alpha_batched(&self, alpha: F128, eq_inner: &[F128]) -> Vec<F128> {
        let n = self.k();
        assert_eq!(eq_inner.len(), n);
        let a = &self.matrices[0];
        let b = &self.matrices[1];
        let bytes = self.backing.planar_hot_bytes();
        let nnz = a.nnz + b.nnz;
        let alpha_a = a
            .value_table
            .iter()
            .map(|&coefficient| alpha * coefficient)
            .collect::<Vec<_>>();

        // Keep the deterministic single-thread path allocation-minimal.  It
        // is also the production verifier path, where Rayon is deliberately
        // configured with one worker.
        if nnz < FIELD_FOLD_PAR_THRESHOLD || rayon::current_num_threads() == 1 {
            let mut comb = vec![F128::ZERO; n];
            for group in 0..a.retained_group_count() {
                let visited = a.for_each_group_entry_with_dictionary(
                    bytes,
                    group,
                    &alpha_a,
                    |row, column, alpha_coeff| {
                        comb[column as usize] += alpha_coeff * eq_inner[row];
                    },
                );
                debug_assert!(visited);
            }
            for group in 0..b.retained_group_count() {
                let visited = b.for_each_group_entry(bytes, group, |row, column, coeff| {
                    comb[column as usize] += coeff * eq_inner[row];
                });
                debug_assert!(visited);
            }
            return comb;
        }

        // Scatter bounded row-group chunks into private width-n combs. Each
        // chunk scans A and B into the same allocation, then `reduce_with`
        // reuses those allocations. Characteristic-two addition is exact,
        // associative and commutative, so this is value/transcript-identical
        // to both the serial row scan and the removed atomic scatter.
        debug_assert_eq!(a.total_groups, b.total_groups);
        let group_count = a.retained_group_count().max(b.retained_group_count());
        parallel_compact_group_fold(n, group_count, |groups, comb| {
            for group in groups {
                let visited = a.for_each_group_entry_with_dictionary(
                    bytes,
                    group,
                    &alpha_a,
                    |row, column, alpha_coeff| {
                        comb[column as usize] += alpha_coeff * eq_inner[row];
                    },
                );
                debug_assert!(visited);
                let visited = b.for_each_group_entry(bytes, group, |row, column, coeff| {
                    comb[column as usize] += coeff * eq_inner[row];
                });
                debug_assert!(visited);
            }
        })
    }

    fn fold_alpha_batched_quirky(
        &self,
        alpha: F128,
        z_skip: F128,
        x_inner_rest: &[F128],
        k_skip: usize,
    ) -> Vec<F128> {
        let n = self.k();
        let ell_skip = 1usize << k_skip;
        let lambda_skip = crate::zerocheck::multilinear::lagrange_weights_naive(k_skip, z_skip);
        let eq_rest = crate::lincheck::build_eq_table(x_inner_rest);
        assert_eq!(ell_skip.saturating_mul(eq_rest.len()), n);

        let a = &self.matrices[0];
        let b = &self.matrices[1];
        let bytes = self.backing.planar_hot_bytes();
        let alpha_a = a
            .value_table
            .iter()
            .map(|&coefficient| alpha * coefficient)
            .collect::<Vec<_>>();
        assert_eq!(a.total_groups, b.total_groups);
        let group_count = a.retained_group_count().max(b.retained_group_count());

        // Each canonical group has exactly 2048 consecutive rows. Materialize
        // only that group's outer-product weights (32 KiB), then reuse them
        // for both A and B before the task returns. Across the Rayon pool this
        // is O(threads * 2048), not the former width-k 64-MiB eq table. The
        // number and order-independent values of field multiplications are
        // unchanged: every row weight is still lambda_skip[i] * eq_rest[j].
        let fill_group_weights = |group: usize, weights: &mut [F128; ARTIFACT_GROUP_ROWS]| {
            let first_row = group * ARTIFACT_GROUP_ROWS;
            let rows = (n - first_row).min(ARTIFACT_GROUP_ROWS);
            for (local_row, slot) in weights[..rows].iter_mut().enumerate() {
                let row = first_row + local_row;
                *slot = lambda_skip[row & (ell_skip - 1)] * eq_rest[row >> k_skip];
            }
            (first_row, rows)
        };

        let nnz = a.nnz + b.nnz;
        if nnz < FIELD_FOLD_PAR_THRESHOLD || rayon::current_num_threads() == 1 {
            let mut comb = vec![F128::ZERO; n];
            for group in 0..group_count {
                let mut weights = [F128::ZERO; ARTIFACT_GROUP_ROWS];
                let (first_row, _) = fill_group_weights(group, &mut weights);
                let visited = a.for_each_group_entry_with_dictionary(
                    bytes,
                    group,
                    &alpha_a,
                    |row, column, alpha_coeff| {
                        comb[column as usize] += alpha_coeff * weights[row - first_row];
                    },
                );
                debug_assert!(visited);
                let visited = b.for_each_group_entry(bytes, group, |row, column, coeff| {
                    comb[column as usize] += coeff * weights[row - first_row];
                });
                debug_assert!(visited);
            }
            return comb;
        }

        parallel_compact_group_fold(n, group_count, |groups, comb| {
            // One 32-KiB weight tile per chunk is reused for every group in
            // that chunk and for both matrix sides.
            let mut weights = [F128::ZERO; ARTIFACT_GROUP_ROWS];
            for group in groups {
                let (first_row, _) = fill_group_weights(group, &mut weights);
                let visited = a.for_each_group_entry_with_dictionary(
                    bytes,
                    group,
                    &alpha_a,
                    |row, column, alpha_coeff| {
                        comb[column as usize] += alpha_coeff * weights[row - first_row];
                    },
                );
                debug_assert!(visited);
                let visited = b.for_each_group_entry(bytes, group, |row, column, coeff| {
                    comb[column as usize] += coeff * weights[row - first_row];
                });
                debug_assert!(visited);
            }
        })
    }

    fn fold_alpha_batched_c1(&self, alpha: F256, eq_inner: &[F256]) -> Vec<F256> {
        assert_eq!(eq_inner.len(), self.k());
        self.fold_alpha_batched_c1_with_row_weight(alpha, |row| eq_inner[row])
    }

    fn fold_alpha_batched_quirky_c1(
        &self,
        alpha: F256,
        z_skip: F256,
        x_inner_rest: &[F256],
        k_skip: usize,
    ) -> Vec<F256> {
        let n = self.k();
        let skip_size = 1usize << k_skip;
        let skip = crate::zerocheck::field_c1::lagrange_weights(k_skip, z_skip, 0);
        let rest = crate::zerocheck::field_c1::build_eq_table(x_inner_rest);
        assert_eq!(skip_size.saturating_mul(rest.len()), n);
        self.fold_alpha_batched_c1_with_row_weight(alpha, |row| {
            skip[row & (skip_size - 1)] * rest[row >> k_skip]
        })
    }
}

// ---------------------------------------------------------------------------
// Synthetic instances (tests + the substrate throughput bench)
// ---------------------------------------------------------------------------

/// Deterministic synthetic satisfiable instance + witness — test/bench
/// fixture (a stand-in for builder-produced gadget traces).
///
/// Shape mimics a verifier-replay trace: column 0 of every block is the
/// constant-one wire (`const_pin = Some(0)`, row-0 constraint `z_0² = z_0`
/// with the honest witness at 1), every later row is a multiplication of two
/// coefficient-weighted combinations of earlier wires (strictly
/// lower-triangular support, 1–4 nonzeros per matrix row — the density of
/// Poseidon2b round chains under option A). The witness is derived alongside,
/// so `satisfies` holds by construction.
pub fn synthetic_satisfiable(m: usize, k_log: usize, seed: u64) -> (FieldR1cs, Vec<F128>) {
    synthetic_satisfiable_inner(m, k_log, seed, None)
}

/// Like [`synthetic_satisfiable`], but coefficients are drawn from a fixed
/// pool of `dictionary_len` distinct nonzero values. Production verifier
/// matrices carry only a few hundred distinct constants and the streaming
/// artifact evaluator enforces that profile
/// ([`STREAMING_FIELD_R1CS_MAX_DICTIONARY_VALUES`]); artifact/decider
/// rooflines must match it or they reject at preflight.
pub fn synthetic_satisfiable_bounded_dictionary(
    m: usize,
    k_log: usize,
    seed: u64,
    dictionary_len: usize,
) -> (FieldR1cs, Vec<F128>) {
    assert!(dictionary_len >= 1);
    synthetic_satisfiable_inner(m, k_log, seed, Some(dictionary_len))
}

fn synthetic_satisfiable_inner(
    m: usize,
    k_log: usize,
    seed: u64,
    dictionary_len: Option<usize>,
) -> (FieldR1cs, Vec<F128>) {
    let k = 1usize << k_log;
    assert!(k_log >= 1 && k_log <= m);
    let mut state = seed;
    let mut next_u64 = move || {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    };
    let mut next_f128_nonzero: Box<dyn FnMut() -> F128> = match dictionary_len {
        None => Box::new(move || {
            loop {
                let v = F128 {
                    lo: next_u64(),
                    hi: next_u64(),
                };
                if v != F128::ZERO {
                    return v;
                }
            }
        }),
        Some(len) => {
            let mut pool = Vec::with_capacity(len);
            while pool.len() < len {
                let v = F128 {
                    lo: next_u64(),
                    hi: next_u64(),
                };
                if v != F128::ZERO && !pool.contains(&v) {
                    pool.push(v);
                }
            }
            Box::new(move || pool[(next_u64() as usize) % pool.len()])
        }
    };
    let mut next_f128_nonzero = &mut *next_f128_nonzero;

    let gen_matrix =
        |rng: &mut dyn FnMut() -> u64, coeff: &mut dyn FnMut() -> F128| -> SparseFieldMatrix {
            SparseFieldMatrix::from_rows(
                k,
                (0..k)
                    .map(|r| {
                        if r == 0 {
                            // Constant-wire row: z_0 · z_0 = z_0.
                            return vec![(0u32, F128::ONE)];
                        }
                        let n_nonzero = 1 + (rng() % 4) as usize;
                        (0..n_nonzero)
                            .map(|_| ((rng() as usize % r) as u32, coeff()))
                            .collect()
                    })
                    .collect(),
            )
        };
    let mut rng_a = {
        let mut s = seed ^ 0xA;
        move || {
            s = s.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
    };
    let a_0 = gen_matrix(&mut rng_a, &mut next_f128_nonzero);
    let mut rng_b = {
        let mut s = seed ^ 0xB;
        move || {
            s = s.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
    };
    let b_0 = gen_matrix(&mut rng_b, &mut next_f128_nonzero);

    let n = 1usize << m;
    let mut z = vec![F128::ZERO; n];
    let n_outer = n / k;
    for blk in 0..n_outer {
        let base = blk * k;
        z[base] = F128::ONE; // the constant wire
        for r in 1..k {
            let dot = |m: &SparseFieldMatrix| {
                let mut acc = F128::ZERO;
                for (c, coeff) in m.row(r) {
                    acc += coeff * z[base + c as usize];
                }
                acc
            };
            z[base + r] = dot(&a_0) * dot(&b_0);
        }
    }

    let r1cs = FieldR1cs {
        m,
        k_log,
        k_skip: crate::zerocheck::K_SKIP.min(k_log),
        useful_rows: k,
        a_0,
        b_0,
        const_pin: Some(0),
        digest_cache: std::sync::OnceLock::new(),
        csc_cache: std::sync::OnceLock::new(),
    };
    debug_assert!(r1cs.satisfies(&z));
    (r1cs, z)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lincheck::build_eq_table;
    use crate::proof::FieldShape;
    use std::io::{Cursor, Read, Seek, SeekFrom};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct CountingCursor {
        inner: Cursor<Vec<u8>>,
        bytes_read: Arc<AtomicUsize>,
    }

    impl Read for CountingCursor {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let read = self.inner.read(bytes)?;
            self.bytes_read.fetch_add(read, Ordering::Relaxed);
            Ok(read)
        }
    }

    impl Seek for CountingCursor {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        fn f128(&mut self) -> F128 {
            F128 {
                lo: self.next_u64(),
                hi: self.next_u64(),
            }
        }

        fn f256(&mut self) -> F256 {
            F256::new(self.f128(), self.f128())
        }
    }

    /// Retains only the legacy F128 fold so the trait defaults provide an
    /// independent four-pass oracle for optimized C1 implementations.
    struct LegacyC1FoldOracle<'a, T: LincheckCircuit + ?Sized>(&'a T);

    impl<T: LincheckCircuit + ?Sized> LincheckCircuit for LegacyC1FoldOracle<'_, T> {
        fn n_cols(&self) -> usize {
            self.0.n_cols()
        }

        fn fold_alpha_batched(&self, alpha: F128, eq_inner: &[F128]) -> Vec<F128> {
            self.0.fold_alpha_batched(alpha, eq_inner)
        }

        fn const_pin_col(&self) -> Option<usize> {
            self.0.const_pin_col()
        }
    }

    fn random_satisfiable(m: usize, k_log: usize, seed: u64) -> (FieldR1cs, Vec<F128>) {
        synthetic_satisfiable(m, k_log, seed)
    }

    fn artifact_fixture(seed: u64) -> (FieldR1cs, FieldShape, [u8; 32], Vec<u8>) {
        let (r1cs, _) = random_satisfiable(8, 4, seed);
        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut bytes = Vec::new();
        r1cs.write_artifact(&mut bytes).unwrap();
        (r1cs, shape, digest, bytes)
    }

    /// Test-only model of the removed production atomic scatter. It is kept
    /// deliberately simple (one atomic XOR per contribution) so parity tests
    /// bind the private-comb result to both the old scheduling-independent
    /// behavior and an independently accumulated resident-row definition.
    fn atomic_compact_column_image<F>(
        relation: &CompactFieldR1cs,
        alpha: F128,
        row_weight: &F,
    ) -> Vec<F128>
    where
        F: Fn(usize, usize) -> F128 + Sync,
    {
        use rayon::prelude::*;
        use std::sync::atomic::AtomicU64;

        struct Cell {
            lo: AtomicU64,
            hi: AtomicU64,
        }

        let n = relation.k();
        let cells = (0..n)
            .map(|_| Cell {
                lo: AtomicU64::new(0),
                hi: AtomicU64::new(0),
            })
            .collect::<Vec<_>>();
        let a = &relation.matrices[0];
        let b = &relation.matrices[1];
        let bytes = relation.backing.planar_hot_bytes();
        let group_count = a.retained_group_count().max(b.retained_group_count());
        (0..group_count).into_par_iter().for_each(|group| {
            for (side, matrix, scale) in [(0usize, a, alpha), (1usize, b, F128::ONE)] {
                let visited =
                    matrix.for_each_group_entry(bytes, group, |row, column, coefficient| {
                        let contribution = scale * coefficient * row_weight(side, row);
                        cells[column as usize]
                            .lo
                            .fetch_xor(contribution.lo, Ordering::Relaxed);
                        cells[column as usize]
                            .hi
                            .fetch_xor(contribution.hi, Ordering::Relaxed);
                    });
                debug_assert!(visited);
            }
        });
        cells
            .into_iter()
            .map(|cell| F128::new(cell.lo.into_inner(), cell.hi.into_inner()))
            .collect()
    }

    fn direct_resident_column_image<F>(
        relation: &FieldR1cs,
        alpha: F128,
        row_weight: &F,
    ) -> Vec<F128>
    where
        F: Fn(usize, usize) -> F128,
    {
        let mut comb = vec![F128::ZERO; relation.k()];
        for (side, matrix, scale) in [
            (0usize, &relation.a_0, alpha),
            (1usize, &relation.b_0, F128::ONE),
        ] {
            for row in 0..matrix.num_rows {
                let weight = row_weight(side, row);
                for (column, coefficient) in matrix.row(row) {
                    comb[column as usize] += scale * coefficient * weight;
                }
            }
        }
        comb
    }

    fn odd_retained_group_fixture() -> FieldR1cs {
        let k_log = 13;
        let k = 1usize << k_log;
        let live_rows = 3 * ARTIFACT_GROUP_ROWS;
        let mut a_rows = vec![Vec::new(); k];
        let mut b_rows = vec![Vec::new(); k];
        for row in 0..live_rows {
            a_rows[row].push((((row * 37 + 19) & (k - 1)) as u32, F128::new(3, 5)));
            b_rows[row].push((((row * 53 + 7) & (k - 1)) as u32, F128::new(11, 13)));
            if row & 3 == 0 {
                a_rows[row].push((((row * 97 + 1) & (k - 1)) as u32, F128::new(17, 23)));
            }
        }
        FieldR1cs {
            m: k_log,
            k_log,
            k_skip: 6,
            useful_rows: live_rows,
            a_0: SparseFieldMatrix::from_rows(k, a_rows),
            b_0: SparseFieldMatrix::from_rows(k, b_rows),
            const_pin: Some(0),
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        }
    }

    fn decode_fixture(
        bytes: &[u8],
        shape: FieldShape,
        digest: [u8; 32],
    ) -> Result<FieldR1cs, FieldR1csArtifactError> {
        FieldR1cs::read_artifact(&mut Cursor::new(bytes), shape, digest, bytes.len())
    }

    fn header_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    fn set_header_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// A-section navigation for format-v2 byte surgery: the dictionary
    /// position plus the four sub-stream ranges of matrix A's first row
    /// group (the only group for the small `artifact_fixture` shapes).
    fn a_planar_streams(bytes: &[u8]) -> (usize, [(usize, usize); 4]) {
        let a_values = header_u64(bytes, 72) as usize;
        let dictionary_at = FIELD_R1CS_ARTIFACT_HEADER_BYTES;
        let group_at = dictionary_at + a_values * 16;
        let mut ranges = [(0usize, 0usize); 4];
        let mut cursor = group_at + 16;
        for (slot, range) in ranges.iter_mut().enumerate() {
            let length = u32::from_le_bytes(
                bytes[group_at + slot * 4..group_at + slot * 4 + 4]
                    .try_into()
                    .unwrap(),
            ) as usize;
            *range = (cursor, cursor + length);
            cursor += length;
        }
        (dictionary_at, ranges)
    }

    /// Swap canonical dictionary references 0 and 1 inside matrix A's values
    /// sub-stream. The fixture dictionaries are far below 128 entries, so
    /// every reference is one varint byte and the swap is length-preserving.
    fn swap_a_value_references(bytes: &mut [u8]) {
        let (_, ranges) = a_planar_streams(bytes);
        for byte in &mut bytes[ranges[3].0..ranges[3].1] {
            assert!(*byte < 0x80, "fixture value references must be one byte");
            *byte = match *byte {
                0 => 1,
                1 => 0,
                other => other,
            };
        }
    }

    #[test]
    fn field_r1cs_artifact_roundtrip_has_empty_derived_caches() {
        let (expected, shape, digest, bytes) = artifact_fixture(0xA271_FAC7);
        assert_eq!(
            header_u64(&bytes, 12) as usize,
            bytes.len(),
            "fixed header must bind the exact artifact length",
        );

        let decoded = decode_fixture(&bytes, shape, digest).unwrap();
        assert_eq!(decoded.m, expected.m);
        assert_eq!(decoded.k_log, expected.k_log);
        assert_eq!(decoded.k_skip, expected.k_skip);
        assert_eq!(decoded.useful_rows, expected.useful_rows);
        assert_eq!(decoded.const_pin, expected.const_pin);
        assert_eq!(decoded.a_0, expected.a_0);
        assert_eq!(decoded.b_0, expected.b_0);
        assert!(decoded.digest_cache.get().is_none());
        assert!(decoded.csc_cache.get().is_none());
        assert_eq!(decoded.structural_statement_digest(), digest);
    }

    #[test]
    fn compact_artifact_apply_matches_resident_csr() {
        let (r1cs, shape, digest, bytes) = artifact_fixture(0xC04A_C7A1);
        let compact = CompactFieldR1cs::open(bytes.into_boxed_slice(), shape, digest)
            .expect("canonical artifact opens as an authenticated compact view");
        assert_eq!(compact.shape(), shape);
        assert_eq!(compact.useful_rows(), r1cs.useful_rows);
        assert_eq!(compact.statement_digest(), digest);

        let mut rng = Rng::new(0xA991_1E55);
        let z = (0..r1cs.n()).map(|_| rng.f128()).collect::<Vec<_>>();
        assert_eq!(compact.apply_a(&z), r1cs.apply_a(&z));
        assert_eq!(compact.apply_b(&z), r1cs.apply_b(&z));
    }

    #[test]
    fn release_build_sealed_open_is_byte_and_relation_identical() {
        let (r1cs, shape, digest, bytes) = artifact_fixture(0xB017_D5EA);
        let fully_scanned =
            CompactFieldR1cs::open(bytes.clone().into_boxed_slice(), shape, digest).unwrap();
        let seal = unsafe {
            BuildAuthenticatedFieldR1csSeal::from_release_build(shape, digest, bytes.len())
        };
        let sealed = unsafe {
            CompactFieldR1cs::open_build_authenticated(bytes.clone().into_boxed_slice(), seal)
        }
        .unwrap();

        assert_eq!(sealed.authentication_name(), "release-build-sealed");
        assert_eq!(
            fully_scanned.authentication_name(),
            "runtime-structural-scan"
        );
        assert_eq!(sealed.shape(), fully_scanned.shape());
        assert_eq!(sealed.useful_rows(), fully_scanned.useful_rows());
        assert_eq!(sealed.statement_digest(), fully_scanned.statement_digest());
        assert_eq!(sealed.artifact_bytes().as_ref(), bytes);

        let mut rng = Rng::new(0x5EA1_ED01);
        let z = (0..r1cs.n()).map(|_| rng.f128()).collect::<Vec<_>>();
        assert_eq!(sealed.apply_a(&z), fully_scanned.apply_a(&z));
        assert_eq!(sealed.apply_b(&z), fully_scanned.apply_b(&z));

        let sealed_packed = sealed.into_startup_packed().unwrap();
        let scanned_packed = fully_scanned.into_startup_packed().unwrap();
        assert_eq!(
            sealed_packed.artifact_bytes(),
            scanned_packed.artifact_bytes()
        );
        assert_eq!(
            sealed_packed.resident_heap_payload_len(),
            scanned_packed.resident_heap_payload_len()
        );
    }

    #[test]
    fn release_build_seal_binds_exact_canonical_length_and_shape() {
        let (_, shape, digest, bytes) = artifact_fixture(0xB017_1EAD);
        let short_seal = unsafe {
            BuildAuthenticatedFieldR1csSeal::from_release_build(shape, digest, bytes.len() - 1)
        };
        assert!(matches!(
            unsafe {
                CompactFieldR1cs::open_build_authenticated(
                    bytes.clone().into_boxed_slice(),
                    short_seal,
                )
            },
            Err(FieldR1csArtifactError::BackingLengthMismatch { .. })
        ));

        let mut wrong_shape = shape;
        wrong_shape.k_skip -= 1;
        let wrong_shape_seal = unsafe {
            BuildAuthenticatedFieldR1csSeal::from_release_build(wrong_shape, digest, bytes.len())
        };
        assert!(matches!(
            unsafe {
                CompactFieldR1cs::open_build_authenticated(
                    bytes.into_boxed_slice(),
                    wrong_shape_seal,
                )
            },
            Err(FieldR1csArtifactError::ShapeMismatch { .. })
        ));
    }

    #[test]
    fn compact_artifact_trims_only_authenticated_zero_suffix_and_rebuilds_exact_bytes() {
        let k_log = 13;
        let k = 1usize << k_log;
        let mut a_rows = vec![Vec::new(); k];
        let mut b_rows = vec![Vec::new(); k];
        a_rows[0].push((0, F128::ONE));
        // Keep B's second group live. This makes the retained A/B group
        // counts asymmetric and exercises the shared quirky-fold loop.
        b_rows[ARTIFACT_GROUP_ROWS].push((1, F128::new(7, 11)));
        let r1cs = FieldR1cs {
            m: k_log,
            k_log,
            k_skip: 6,
            useful_rows: ARTIFACT_GROUP_ROWS + 1,
            a_0: SparseFieldMatrix::from_rows(k, a_rows),
            b_0: SparseFieldMatrix::from_rows(k, b_rows),
            const_pin: Some(0),
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        };
        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut canonical = Vec::new();
        r1cs.write_artifact(&mut canonical).unwrap();
        let canonical_len = canonical.len();
        let compact =
            CompactFieldR1cs::open(canonical.clone().into_boxed_slice(), shape, digest).unwrap();

        // A drops three suffix groups and B drops two. Every full 2048-row
        // zero group is exactly a 16-byte lengths header plus 2048 canonical
        // zero count varints.
        assert_eq!(
            compact.resident_artifact_len() + 5 * (16 + ARTIFACT_GROUP_ROWS),
            canonical_len,
        );
        assert_eq!(compact.encoded_len(), canonical_len);
        assert_eq!(compact.statement_digest(), digest);

        let mut omitted_entries = 0usize;
        assert!(
            compact.for_each_matrix_group_entry(FieldR1csArtifactMatrix::A, 1, |_, _, _| {
                omitted_entries += 1
            },)
        );
        assert_eq!(omitted_entries, 0);
        assert!(!compact.for_each_matrix_group_entry(FieldR1csArtifactMatrix::A, 4, |_, _, _| {},));

        let mut rng = Rng::new(0x7A11_C04A);
        let z = (0..k).map(|_| rng.f128()).collect::<Vec<_>>();
        assert_eq!(compact.apply_a(&z), r1cs.apply_a(&z));
        assert_eq!(compact.apply_b(&z), r1cs.apply_b(&z));
        let point = (0..k_log).map(|_| rng.f128()).collect::<Vec<_>>();
        let alpha = rng.f128();
        let eq = build_eq_table(&point);
        assert_eq!(
            compact.fold_alpha_batched(alpha, &eq),
            r1cs.fold_alpha_batched(alpha, &eq),
        );
        assert_eq!(
            compact.fold_alpha_batched_quirky(alpha, point[0], &point[1..], 1),
            r1cs.fold_alpha_batched_quirky(alpha, point[0], &point[1..], 1),
        );

        assert_eq!(compact.artifact_bytes(), canonical);
        let decoded = compact.decode_resident_authenticated().unwrap();
        assert_eq!(decoded.a_0, r1cs.a_0);
        assert_eq!(decoded.b_0, r1cs.b_0);
        assert_eq!(decoded.structural_statement_digest(), digest);
    }

    #[test]
    fn startup_packed_artifact_releases_planar_bytes_and_preserves_exact_authority() {
        let (r1cs, shape, digest, canonical) = artifact_fixture(0x50A0_B8A8);
        let packed =
            CompactFieldR1cs::open_packed(canonical.clone().into_boxed_slice(), shape, digest)
                .unwrap();
        assert!(packed.is_packed());
        assert_eq!(packed.storage_name(), "packed");
        assert_eq!(packed.resident_artifact_len(), 0);
        assert_eq!(packed.encoded_len(), canonical.len());
        assert_eq!(packed.statement_digest(), digest);

        let exact_packed_payload = packed
            .matrices
            .iter()
            .map(|matrix| {
                let CompactMatrixRows::Packed(rows) = &matrix.rows else {
                    panic!("startup-packed relation retained planar rows")
                };
                matrix.value_table.capacity() * std::mem::size_of::<F128>()
                    + rows.row_counts.len() * std::mem::size_of::<u8>()
                    + rows.overflow_counts.len() * std::mem::size_of::<u16>()
                    + rows.group_offsets.len() * std::mem::size_of::<u32>()
                    + rows.group_overflow_offsets.len() * std::mem::size_of::<u32>()
                    + rows.columns.len() * std::mem::size_of::<u32>()
                    + rows.value_indices.len() * std::mem::size_of::<u16>()
            })
            .sum::<usize>();
        assert_eq!(packed.resident_heap_payload_len(), exact_packed_payload);

        let mut rng = Rng::new(0xB8A8_50A0);
        let z = (0..r1cs.n()).map(|_| rng.f128()).collect::<Vec<_>>();
        assert_eq!(packed.apply_a(&z), r1cs.apply_a(&z));
        assert_eq!(packed.apply_b(&z), r1cs.apply_b(&z));
        let point = (0..shape.k_log).map(|_| rng.f128()).collect::<Vec<_>>();
        let eq = build_eq_table(&point);
        let alpha = rng.f128();
        assert_eq!(
            packed.fold_alpha_batched(alpha, &eq),
            r1cs.fold_alpha_batched(alpha, &eq)
        );
        assert_eq!(
            packed.fold_alpha_batched_quirky(alpha, point[0], &point[1..], 1),
            r1cs.fold_alpha_batched_quirky(alpha, point[0], &point[1..], 1),
        );

        // Compatibility export is exact but remains caller-owned: a
        // diagnostic request cannot permanently grow the hot relation.
        assert_eq!(packed.artifact_bytes(), canonical);
        assert_eq!(packed.resident_heap_payload_len(), exact_packed_payload);
        let decoded = packed.decode_resident_authenticated().unwrap();
        assert_eq!(decoded.a_0, r1cs.a_0);
        assert_eq!(decoded.b_0, r1cs.b_0);
        assert_eq!(decoded.statement_digest(), digest);
    }

    #[test]
    fn build_packed_image_is_runtime_relation_and_matrix_claim_identical() {
        use crate::matrix_claim::{FreshLincheckClaim, MatrixAccClaim};

        let (r1cs, shape, digest, canonical) = artifact_fixture(0xB017_1A6E);
        let packed =
            CompactFieldR1cs::open_packed(canonical.clone().into_boxed_slice(), shape, digest)
                .unwrap();
        let image = packed.encode_startup_packed_image().unwrap();
        assert_eq!(&image[..8], &FIELD_R1CS_PACKED_IMAGE_MAGIC);
        assert_eq!(
            u16::from_le_bytes(image[8..10].try_into().unwrap()),
            FIELD_R1CS_PACKED_IMAGE_VERSION,
        );
        let seal = unsafe {
            BuildAuthenticatedFieldR1csSeal::from_release_build(shape, digest, canonical.len())
        };
        let decoded =
            unsafe { CompactFieldR1cs::open_build_authenticated_packed_image(&image, seal) }
                .unwrap();

        assert_eq!(decoded.shape(), packed.shape());
        assert_eq!(decoded.statement_digest(), packed.statement_digest());
        assert_eq!(decoded.useful_rows(), packed.useful_rows());
        assert_eq!(decoded.storage_name(), "packed");
        assert!(decoded.is_packed());
        assert_eq!(decoded.authentication_name(), "release-build-sealed");
        assert_eq!(decoded.encoded_len(), canonical.len());
        assert_eq!(decoded.artifact_bytes().as_ref(), canonical);
        assert_eq!(decoded.encode_startup_packed_image().unwrap(), image);

        let mut rng = Rng::new(0x1A6E_C1A1);
        let z = (0..r1cs.n()).map(|_| rng.f128()).collect::<Vec<_>>();
        assert_eq!(decoded.apply_a(&z), packed.apply_a(&z));
        assert_eq!(decoded.apply_b(&z), packed.apply_b(&z));

        let rest = shape.k_log - shape.k_skip;
        let fresh = FreshLincheckClaim {
            alpha: rng.f128(),
            z_skip: rng.f128(),
            x_inner_rest: (0..rest).map(|_| rng.f128()).collect(),
            r_inner_rest: (0..rest).map(|_| rng.f128()).collect(),
            z_partial: (0..1usize << shape.k_skip).map(|_| rng.f128()).collect(),
            value: rng.f128(),
        };
        let accumulated = MatrixAccClaim {
            point: (0..2 * shape.k_log + 1).map(|_| rng.f128()).collect(),
            value: rng.f128(),
        };
        let expected = packed
            .evaluate_matrix_claims_authenticated(Some(&fresh), Some(&accumulated))
            .unwrap();
        let actual = decoded
            .evaluate_matrix_claims_authenticated(Some(&fresh), Some(&accumulated))
            .unwrap();
        assert_eq!(actual, expected);
        assert!(actual.is_bound_to(Some(&fresh), Some(&accumulated)));
    }

    #[test]
    fn build_packed_image_malformed_or_truncated_framing_never_panics() {
        let (_, shape, digest, canonical) = artifact_fixture(0xB017_BAD0);
        let packed =
            CompactFieldR1cs::open_packed(canonical.clone().into_boxed_slice(), shape, digest)
                .unwrap();
        let image = packed.encode_startup_packed_image().unwrap();
        let seal = unsafe {
            BuildAuthenticatedFieldR1csSeal::from_release_build(shape, digest, canonical.len())
        };

        let cuts = [
            0usize,
            1,
            8,
            12,
            FIELD_R1CS_PACKED_IMAGE_HEADER_BYTES - 1,
            FIELD_R1CS_PACKED_IMAGE_HEADER_BYTES,
            FIELD_R1CS_PACKED_IMAGE_HEADER_BYTES
                + 2 * FIELD_R1CS_PACKED_IMAGE_MATRIX_DESCRIPTOR_BYTES
                - 1,
            image.len() - 1,
        ];
        for cut in cuts {
            let mut truncated = image[..cut].to_vec();
            // Once the total-length slot itself is present, bind it to the
            // shortened slice so parsing proceeds to the actual missing
            // header/descriptor/payload boundary instead of stopping early.
            if cut >= 20 {
                truncated[12..20].copy_from_slice(&(cut as u64).to_le_bytes());
            }
            let result = std::panic::catch_unwind(|| unsafe {
                CompactFieldR1cs::open_build_authenticated_packed_image(&truncated, seal)
            });
            assert!(result.is_ok(), "decoder panicked for prefix length {cut}");
            assert!(
                result.unwrap().is_err(),
                "decoder accepted truncated prefix length {cut}"
            );
        }

        // The first matrix's coefficient-count descriptor is framing, not a
        // trusted native allocation request. Overflow must be reported before
        // any copy or allocation and must not panic.
        let mut malformed = image.to_vec();
        let first_value_count = FIELD_R1CS_PACKED_IMAGE_HEADER_BYTES + 4 * 8;
        malformed[first_value_count..first_value_count + 8]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        let result = std::panic::catch_unwind(|| unsafe {
            CompactFieldR1cs::open_build_authenticated_packed_image(&malformed, seal)
        });
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            Err(FieldR1csArtifactError::LengthArithmetic)
        ));
    }

    fn packed_overflow_row_fixture(last_count: usize) -> FieldR1cs {
        let k_log = 12;
        let k = 1usize << k_log;
        let mut rows = vec![Vec::new(); k];
        for (row, count) in [
            (0usize, 254usize),
            (1, 255),
            (2, 256),
            (ARTIFACT_GROUP_ROWS, last_count),
        ] {
            rows[row] = (0..count)
                // Deliberately non-monotone with repeats: exact per-row order
                // is transcript-visible and must survive the storage change.
                .map(|entry| {
                    (
                        ((entry.wrapping_mul(37) + row.wrapping_mul(101)) % k) as u32,
                        F128::ONE,
                    )
                })
                .collect();
        }
        FieldR1cs {
            m: k_log,
            k_log,
            k_skip: 6,
            useful_rows: ARTIFACT_GROUP_ROWS + 1,
            a_0: SparseFieldMatrix::from_rows(k, rows),
            b_0: SparseFieldMatrix::zero(k),
            const_pin: None,
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn startup_packed_u8_counts_preserve_overflow_rows_groups_and_zero_suffix() {
        let r1cs = packed_overflow_row_fixture(usize::from(u16::MAX));
        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut canonical = Vec::new();
        r1cs.write_artifact(&mut canonical).unwrap();
        let packed =
            CompactFieldR1cs::open_packed(canonical.clone().into_boxed_slice(), shape, digest)
                .unwrap();
        let CompactMatrixRows::Packed(a_rows) = &packed.matrices[0].rows else {
            panic!("A must use startup-packed rows")
        };
        let CompactMatrixRows::Packed(b_rows) = &packed.matrices[1].rows else {
            panic!("B must use startup-packed rows")
        };

        assert_eq!(a_rows.row_counts.len(), ARTIFACT_GROUP_ROWS + 1);
        assert_eq!(a_rows.row_counts[0], 254);
        assert_eq!(a_rows.row_counts[1], PACKED_ROW_COUNT_OVERFLOW_SENTINEL);
        assert_eq!(a_rows.row_counts[2], PACKED_ROW_COUNT_OVERFLOW_SENTINEL);
        assert_eq!(
            a_rows.row_counts[ARTIFACT_GROUP_ROWS],
            PACKED_ROW_COUNT_OVERFLOW_SENTINEL,
        );
        assert_eq!(&*a_rows.overflow_counts, &[255, 256, u16::MAX]);
        assert_eq!(&*a_rows.group_overflow_offsets, &[0, 2, 3]);
        assert_eq!(&*a_rows.group_offsets, &[0, 765, 66_300]);
        assert_eq!(a_rows.group_count(), 2);
        assert_eq!(a_rows.heap_payload_len(), 399_879);
        assert!(b_rows.row_counts.is_empty());
        assert!(b_rows.overflow_counts.is_empty());
        assert_eq!(&*b_rows.group_offsets, &[0]);
        assert_eq!(&*b_rows.group_overflow_offsets, &[0]);
        assert_eq!(b_rows.heap_payload_len(), 8);

        let mut visited = [0usize; 2];
        // Scan out of order to prove each group uses its own overflow base.
        for group in [1usize, 0] {
            assert!(a_rows.for_each_group_index_entry(group, |row, _, _| {
                assert_eq!(row / ARTIFACT_GROUP_ROWS, group);
                visited[group] += 1;
            }));
        }
        assert_eq!(visited, [765, usize::from(u16::MAX)]);
        assert!(!a_rows.for_each_group_index_entry(2, |_, _, _| {}));

        // Both the lazy compatibility bytes and the mature CSR decode remain
        // exact, including the implicit 2047-row canonical zero suffix.
        assert_eq!(packed.artifact_bytes(), canonical);
        let decoded = packed.decode_resident_authenticated().unwrap();
        assert_eq!(decoded.a_0, r1cs.a_0);
        assert_eq!(decoded.b_0, r1cs.b_0);
        assert_eq!(decoded.statement_digest(), digest);

        let mut rng = Rng::new(0xA11C_0F10);
        let z = (0..r1cs.n()).map(|_| rng.f128()).collect::<Vec<_>>();
        assert_eq!(packed.apply_a(&z), r1cs.apply_a(&z));
        assert_eq!(packed.apply_b(&z), r1cs.apply_b(&z));
        let point = (0..shape.k_log).map(|_| rng.f128()).collect::<Vec<_>>();
        let eq = build_eq_table(&point);
        let alpha = rng.f128();
        assert_eq!(
            packed.fold_alpha_batched(alpha, &eq),
            r1cs.fold_alpha_batched(alpha, &eq),
        );
        assert_eq!(
            packed.fold_alpha_batched_quirky(alpha, point[0], &point[1..], 1),
            r1cs.fold_alpha_batched_quirky(alpha, point[0], &point[1..], 1),
        );
    }

    #[test]
    fn startup_packed_rejects_a_row_above_exact_u16_overflow_capacity() {
        let r1cs = packed_overflow_row_fixture(usize::from(u16::MAX) + 1);
        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut canonical = Vec::new();
        r1cs.write_artifact(&mut canonical).unwrap();
        assert!(matches!(
            CompactFieldR1cs::open_packed(canonical.into_boxed_slice(), shape, digest),
            Err(FieldR1csArtifactError::CountOutOfRange {
                matrix: FieldR1csArtifactMatrix::A,
                field: "packed nonzeros per row",
                actual: 65_536,
                maximum: 65_535,
            })
        ));
    }

    #[test]
    fn compact_artifact_indexes_cross_group_deltas_and_rejects_substitution() {
        let (r1cs, z) = random_satisfiable(12, 12, 0xC205_5EED);
        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut bytes = Vec::new();
        r1cs.write_artifact(&mut bytes).unwrap();
        let compact =
            CompactFieldR1cs::open(bytes.clone().into_boxed_slice(), shape, digest).unwrap();
        let packed =
            CompactFieldR1cs::open_packed(bytes.into_boxed_slice(), shape, digest).unwrap();
        assert!(compact.matrices[0].retained_group_count() > 1);
        assert_eq!(compact.apply_a(&z), r1cs.apply_a(&z));
        assert_eq!(compact.apply_b(&z), r1cs.apply_b(&z));
        assert_eq!(packed.apply_a(&z), r1cs.apply_a(&z));
        assert_eq!(packed.apply_b(&z), r1cs.apply_b(&z));

        let (_, expected_shape, expected_digest, _) = artifact_fixture(0xA271_FAC7);
        let (_other, other_shape, _other_digest, substituted) = artifact_fixture(0xBAD5_71E0);
        assert_eq!(other_shape, expected_shape);
        assert!(matches!(
            CompactFieldR1cs::open(substituted.into_boxed_slice(), other_shape, expected_digest,),
            Err(FieldR1csArtifactError::StructuralDigestMismatch { .. })
        ));
    }

    #[test]
    fn compact_private_comb_budget_is_exact_at_m22_for_eleven_workers() {
        let m22_cols = 1usize << 22;
        let m22_groups = m22_cols / ARTIFACT_GROUP_ROWS;
        let comb_bytes = m22_cols * std::mem::size_of::<F128>();
        assert_eq!(comb_bytes, 64usize << 20);
        let chunks = compact_fold_chunk_count_for_threads(m22_cols, m22_groups, 11);
        assert_eq!(chunks, 11);
        assert_eq!(chunks * comb_bytes, 704usize << 20);
        assert!(chunks * comb_bytes <= FOLD_COMB_BUDGET_BYTES);

        // At the wider classes the fixed 1-GiB cap, rather than the worker
        // count, is the binding constraint.
        assert_eq!(
            compact_fold_chunk_count_for_threads(1usize << 23, 1usize << 12, 11),
            8,
        );
        assert_eq!(
            compact_fold_chunk_count_for_threads(1usize << 24, 1usize << 13, 11),
            4,
        );

        // C1 combs carry two F128 coordinates. The same budget therefore
        // permits half as many private accumulators at every large width and
        // exactly two at the production B255 width.
        assert_eq!(
            compact_c1_fold_chunk_count_for_threads(1usize << 22, 1usize << 11, 11),
            8,
        );
        assert_eq!(
            compact_c1_fold_chunk_count_for_threads(1usize << 23, 1usize << 12, 11),
            4,
        );
        assert_eq!(
            compact_c1_fold_chunk_count_for_threads(1usize << 24, 1usize << 13, 11),
            2,
        );
    }

    #[test]
    fn compact_private_comb_odd_groups_match_atomic_resident_and_direct() {
        let r1cs = odd_retained_group_fixture();
        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut bytes = Vec::new();
        r1cs.write_artifact(&mut bytes).unwrap();
        let compact =
            CompactFieldR1cs::open(bytes.clone().into_boxed_slice(), shape, digest).unwrap();
        let packed =
            CompactFieldR1cs::open_packed(bytes.into_boxed_slice(), shape, digest).unwrap();
        for relation in [&compact, &packed] {
            assert_eq!(relation.matrices[0].retained_group_count(), 3);
            assert_eq!(relation.matrices[1].retained_group_count(), 3);
            assert_eq!(relation.matrices[0].total_groups, 4);
            assert_eq!(relation.matrices[1].total_groups, 4);
        }

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let mut rng = Rng::new(0x0DD0_C04A_F01D);
        let alpha = rng.f128();
        let point = (0..shape.k_log).map(|_| rng.f128()).collect::<Vec<_>>();
        let eq_inner = build_eq_table(&point);
        let lincheck_weight = |_: usize, row: usize| eq_inner[row];
        let direct = direct_resident_column_image(&r1cs, alpha, &lincheck_weight);
        let resident = pool.install(|| r1cs.fold_alpha_batched(alpha, &eq_inner));
        assert_eq!(resident, direct);
        for (name, relation) in [("planar", &compact), ("packed", &packed)] {
            let private = pool.install(|| relation.fold_alpha_batched(alpha, &eq_inner));
            let atomic =
                pool.install(|| atomic_compact_column_image(relation, alpha, &lincheck_weight));
            assert_eq!(private, direct, "{name} private standard fold drift");
            assert_eq!(atomic, direct, "{name} atomic standard reference drift");
        }

        let z_skip = rng.f128();
        let x_inner_rest = (0..shape.k_log - shape.k_skip)
            .map(|_| rng.f128())
            .collect::<Vec<_>>();
        let quirky_eq = crate::lincheck::build_quirky_eq_table(z_skip, &x_inner_rest, shape.k_skip);
        let quirky_weight = |_: usize, row: usize| quirky_eq[row];
        let quirky_direct = direct_resident_column_image(&r1cs, alpha, &quirky_weight);
        let quirky_resident = pool
            .install(|| r1cs.fold_alpha_batched_quirky(alpha, z_skip, &x_inner_rest, shape.k_skip));
        assert_eq!(quirky_resident, quirky_direct);
        for (name, relation) in [("planar", &compact), ("packed", &packed)] {
            let private = pool.install(|| {
                relation.fold_alpha_batched_quirky(alpha, z_skip, &x_inner_rest, shape.k_skip)
            });
            let atomic =
                pool.install(|| atomic_compact_column_image(relation, alpha, &quirky_weight));
            assert_eq!(private, quirky_direct, "{name} private quirky fold drift");
            assert_eq!(
                atomic, quirky_direct,
                "{name} atomic quirky reference drift"
            );
        }

        let k = r1cs.k();
        let eq_rho = (0..2 * k).map(|_| rng.f128()).collect::<Vec<_>>();
        let stacked_weight = |side: usize, row: usize| eq_rho[side * k + row];
        let stacked_direct = direct_resident_column_image(&r1cs, F128::ONE, &stacked_weight);
        for (name, relation) in [("planar", &compact), ("packed", &packed)] {
            let private =
                pool.install(|| relation.stacked_weighted_column_image(&|index| eq_rho[index]));
            let atomic =
                pool.install(|| atomic_compact_column_image(relation, F128::ONE, &stacked_weight));
            assert_eq!(private, stacked_direct, "{name} private stacked fold drift");
            assert_eq!(
                atomic, stacked_direct,
                "{name} atomic stacked reference drift"
            );
        }
    }

    #[test]
    fn compact_lincheck_fold_matches_resident_in_serial_and_parallel() {
        let (r1cs, _) = random_satisfiable(12, 12, 0xC011_F01D);
        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut bytes = Vec::new();
        r1cs.write_artifact(&mut bytes).unwrap();
        let compact =
            CompactFieldR1cs::open(bytes.clone().into_boxed_slice(), shape, digest).unwrap();
        let packed =
            CompactFieldR1cs::open_packed(bytes.into_boxed_slice(), shape, digest).unwrap();

        let mut rng = Rng::new(0xF01D_C04A);
        let point = (0..shape.k_log).map(|_| rng.f128()).collect::<Vec<_>>();
        let eq_inner = build_eq_table(&point);
        let alpha = rng.f128();
        let expected = r1cs.fold_alpha_batched(alpha, &eq_inner);

        for threads in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let actual = pool.install(|| compact.fold_alpha_batched(alpha, &eq_inner));
            assert_eq!(
                actual, expected,
                "compact fold drift with {threads} threads"
            );
            let actual = pool.install(|| packed.fold_alpha_batched(alpha, &eq_inner));
            assert_eq!(actual, expected, "packed fold drift with {threads} threads");
        }
    }

    #[test]
    fn compact_stacked_column_image_matches_resident_in_serial_and_parallel() {
        let (r1cs, _) = random_satisfiable(12, 12, 0xC011_57AC);
        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut bytes = Vec::new();
        r1cs.write_artifact(&mut bytes).unwrap();
        let compact =
            CompactFieldR1cs::open(bytes.clone().into_boxed_slice(), shape, digest).unwrap();
        let packed =
            CompactFieldR1cs::open_packed(bytes.into_boxed_slice(), shape, digest).unwrap();

        let k = r1cs.k();
        let mut rng = Rng::new(0x57AC_C04A);
        let eq_rho = (0..2 * k).map(|_| rng.f128()).collect::<Vec<_>>();
        let mut expected = vec![F128::ZERO; k];
        for (matrix, offset) in [(&r1cs.a_0, 0usize), (&r1cs.b_0, k)] {
            for row in 0..matrix.num_rows {
                let weight = eq_rho[offset + row];
                for (column, coefficient) in matrix.row(row) {
                    expected[column as usize] += coefficient * weight;
                }
            }
        }

        for threads in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let actual =
                pool.install(|| compact.stacked_weighted_column_image(&|index| eq_rho[index]));
            assert_eq!(
                actual, expected,
                "compact stacked column image drift with {threads} threads"
            );
            let actual =
                pool.install(|| packed.stacked_weighted_column_image(&|index| eq_rho[index]));
            assert_eq!(
                actual, expected,
                "packed stacked column image drift with {threads} threads"
            );
        }
    }

    #[test]
    fn compact_factorized_quirky_fold_matches_dense_table_in_serial_and_parallel() {
        let (r1cs, _) = random_satisfiable(12, 12, 0xC011_FAC7);
        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut bytes = Vec::new();
        r1cs.write_artifact(&mut bytes).unwrap();
        let compact =
            CompactFieldR1cs::open(bytes.clone().into_boxed_slice(), shape, digest).unwrap();
        let packed =
            CompactFieldR1cs::open_packed(bytes.into_boxed_slice(), shape, digest).unwrap();

        let mut rng = Rng::new(0xFACA_DE22);
        let z_skip = rng.f128();
        let x_inner_rest = (0..shape.k_log - shape.k_skip)
            .map(|_| rng.f128())
            .collect::<Vec<_>>();
        let alpha = rng.f128();
        let dense = crate::lincheck::build_quirky_eq_table(z_skip, &x_inner_rest, shape.k_skip);
        let expected = r1cs.fold_alpha_batched(alpha, &dense);

        for threads in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let actual = pool.install(|| {
                compact.fold_alpha_batched_quirky(alpha, z_skip, &x_inner_rest, shape.k_skip)
            });
            assert_eq!(
                actual, expected,
                "factorized compact quirky fold drift with {threads} threads"
            );
            let actual = pool.install(|| {
                packed.fold_alpha_batched_quirky(alpha, z_skip, &x_inner_rest, shape.k_skip)
            });
            assert_eq!(
                actual, expected,
                "factorized packed quirky fold drift with {threads} threads"
            );
        }
    }

    #[test]
    fn seekable_artifact_evaluations_match_in_memory_without_csr_decode() {
        use crate::matrix_claim::{
            FreshLincheckClaim, MatrixAccClaim, MatrixClaimEvaluator, fresh_claim_value,
            stacked_matrix_mle_eval,
        };

        let (r1cs, shape, digest, bytes) = artifact_fixture(0x51EA_4AB1);
        let rest = shape.k_log - shape.k_skip;
        let mut rng = Rng::new(0xE0A1_5A7E);
        let fresh = FreshLincheckClaim {
            alpha: rng.f128(),
            z_skip: rng.f128(),
            x_inner_rest: (0..rest).map(|_| rng.f128()).collect(),
            r_inner_rest: (0..rest).map(|_| rng.f128()).collect(),
            z_partial: (0..1usize << shape.k_skip).map(|_| rng.f128()).collect(),
            value: F128::ZERO,
        };
        let accumulated = MatrixAccClaim {
            point: (0..2 * shape.k_log + 1).map(|_| rng.f128()).collect(),
            value: F128::ZERO,
        };
        let expected_fresh = fresh_claim_value(&r1cs, &fresh);
        let expected_accumulated = stacked_matrix_mle_eval(&r1cs, &accumulated);

        let mut view = SeekableFieldR1csArtifact::open(
            Cursor::new(bytes.clone()),
            shape,
            digest,
            bytes.len() as u64,
        )
        .unwrap();
        let evaluated = view
            .evaluate_matrix_claims(Some(&fresh), Some(&accumulated))
            .unwrap();
        assert_eq!(evaluated.structural_digest(), digest);
        assert_eq!(evaluated.fresh_value(), Some(expected_fresh));
        assert_eq!(evaluated.accumulated_value(), Some(expected_accumulated));
        assert_eq!(view.useful_rows(), r1cs.useful_rows);
    }

    #[test]
    fn terminal_preflight_reads_payload_exactly_once() {
        use crate::matrix_claim::{MatrixAccClaim, MatrixClaimEvaluator};

        let (_r1cs, shape, digest, bytes) = artifact_fixture(0x0A11_CE55);
        // The fixture has fewer than DIGEST_SPAN_ROWS rows, so neither
        // matrix rereads an overlapping span-boundary offset.
        assert!((1usize << shape.k_log) < DIGEST_SPAN_ROWS);
        let bytes_read = Arc::new(AtomicUsize::new(0));
        let reader = CountingCursor {
            inner: Cursor::new(bytes.clone()),
            bytes_read: Arc::clone(&bytes_read),
        };
        let mut preflight =
            PreflightSeekableFieldR1csArtifact::open(reader, shape, digest, bytes.len() as u64)
                .unwrap();
        assert_eq!(
            bytes_read.load(Ordering::Relaxed),
            FIELD_R1CS_ARTIFACT_HEADER_BYTES,
            "header preflight must not scan the payload",
        );

        let claim = MatrixAccClaim {
            point: vec![F128::ZERO; 2 * shape.k_log + 1],
            value: F128::ZERO,
        };
        preflight
            .evaluate_matrix_claims(None, Some(&claim))
            .unwrap();
        let payload = bytes.len() - FIELD_R1CS_ARTIFACT_HEADER_BYTES;
        assert_eq!(
            bytes_read.load(Ordering::Relaxed),
            3 * FIELD_R1CS_ARTIFACT_HEADER_BYTES + payload,
            "one header preflight, two identity-header reads, and exactly one payload pass",
        );
        assert!(matches!(
            preflight.evaluate_matrix_claims(None, Some(&claim)),
            Err(FieldR1csArtifactError::MatrixEvaluatorAlreadyConsumed)
        ));
    }

    #[test]
    fn seekable_artifact_matches_across_digest_spans_and_entry_chunks() {
        use crate::matrix_claim::{
            FreshLincheckClaim, MatrixAccClaim, MatrixClaimEvaluator, fresh_claim_value,
            stacked_matrix_mle_eval,
        };

        let k_log = 12usize;
        let k = 1usize << k_log;
        let mut a_rows = vec![Vec::new(); k];
        // Row 7 ends exactly at an entry-chunk boundary; row 8 begins the
        // next chunk. The last/first rows around DIGEST_SPAN_ROWS exercise
        // the independent span boundary, including adjacent empty padding.
        a_rows[7] = (0..STREAMING_FIELD_R1CS_ENTRY_CHUNK)
            .map(|index| ((index % k) as u32, F128::ONE))
            .collect();
        a_rows[8].push((17, F128::new(3, 7)));
        a_rows[DIGEST_SPAN_ROWS - 1].push((18, F128::new(4, 8)));
        a_rows[DIGEST_SPAN_ROWS].push((19, F128::new(5, 9)));
        let r1cs = FieldR1cs {
            m: k_log,
            k_log,
            k_skip: 6,
            useful_rows: DIGEST_SPAN_ROWS + 1,
            a_0: SparseFieldMatrix::from_rows(k, a_rows),
            b_0: SparseFieldMatrix::zero(k),
            const_pin: Some(0),
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        };
        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut bytes = Vec::new();
        r1cs.write_artifact(&mut bytes).unwrap();
        let mut rng = Rng::new(0x5A4E_C2055);
        let fresh = FreshLincheckClaim {
            alpha: rng.f128(),
            z_skip: rng.f128(),
            x_inner_rest: (0..k_log - 6).map(|_| rng.f128()).collect(),
            r_inner_rest: (0..k_log - 6).map(|_| rng.f128()).collect(),
            z_partial: (0..64).map(|_| rng.f128()).collect(),
            value: F128::ZERO,
        };
        let accumulated = MatrixAccClaim {
            point: (0..2 * k_log + 1).map(|_| rng.f128()).collect(),
            value: F128::ZERO,
        };
        let mut view = SeekableFieldR1csArtifact::open(
            Cursor::new(bytes.clone()),
            shape,
            digest,
            bytes.len() as u64,
        )
        .unwrap();
        let evaluated = view
            .evaluate_matrix_claims(Some(&fresh), Some(&accumulated))
            .unwrap();
        assert_eq!(
            evaluated.fresh_value(),
            Some(fresh_claim_value(&r1cs, &fresh))
        );
        assert_eq!(
            evaluated.accumulated_value(),
            Some(stacked_matrix_mle_eval(&r1cs, &accumulated))
        );
    }

    #[test]
    fn seekable_artifact_reauthenticates_same_length_mutation() {
        use crate::matrix_claim::MatrixClaimEvaluator;

        let (_r1cs, shape, digest, bytes) = artifact_fixture(0x5A4E_1E67);
        let mut view = SeekableFieldR1csArtifact::open(
            Cursor::new(bytes.clone()),
            shape,
            digest,
            bytes.len() as u64,
        )
        .unwrap();
        // Same-length mutation of the first row-count varint after a fully
        // authenticated open: the next evaluation must re-derive everything
        // and fail closed (row accounting, stream exhaustion, or digest).
        let (_, ranges) = a_planar_streams(&bytes);
        view.reader_mut().get_mut()[ranges[0].0] ^= 1;
        assert!(view.evaluate_matrix_claims(None, None).is_err());
    }

    #[test]
    fn terminal_preflight_defers_but_never_skips_payload_rejection() {
        use crate::matrix_claim::MatrixClaimEvaluator;

        let (_r1cs, shape, digest, mut bytes) = artifact_fixture(0xDEFE_22ED);
        // Corrupt matrix A's payload only: force a continuation bit onto the
        // first row-count varint. Header and layout arithmetic stay valid,
        // so preflight must succeed and evaluation must reject.
        let (_, ranges) = a_planar_streams(&bytes);
        bytes[ranges[0].0] = 0xFF;

        let mut preflight = PreflightSeekableFieldR1csArtifact::open(
            Cursor::new(bytes.clone()),
            shape,
            digest,
            bytes.len() as u64,
        )
        .expect("header/layout preflight deliberately does not authenticate payload rows");
        assert!(preflight.evaluate_matrix_claims(None, None).is_err());
    }

    #[test]
    fn seekable_artifact_fails_closed_on_length_and_header_changes() {
        use crate::matrix_claim::MatrixClaimEvaluator;

        let (_r1cs, shape, digest, bytes) = artifact_fixture(0x7A11_1E5E);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            SeekableFieldR1csArtifact::open(
                Cursor::new(trailing.clone()),
                shape,
                digest,
                trailing.len() as u64,
            ),
            Err(FieldR1csArtifactError::BackingLengthMismatch { .. })
        ));
        let truncated = &bytes[..bytes.len() - 1];
        assert!(
            SeekableFieldR1csArtifact::open(
                Cursor::new(truncated),
                shape,
                digest,
                bytes.len() as u64,
            )
            .is_err()
        );

        let mut view = SeekableFieldR1csArtifact::open(
            Cursor::new(bytes.clone()),
            shape,
            digest,
            bytes.len() as u64,
        )
        .unwrap();
        view.reader_mut().get_mut()[20] ^= 1;
        assert!(matches!(
            view.evaluate_matrix_claims(None, None),
            Err(FieldR1csArtifactError::BackingFileChanged)
        ));
    }

    #[test]
    fn seekable_artifact_rejects_noncanonical_sparse_sections() {
        let (_r1cs, shape, digest, bytes) = artifact_fixture(0xBAD5_EC71);
        let a_nnz = header_u64(&bytes, 64) as usize;
        let a_values = header_u64(&bytes, 72) as usize;
        assert!(a_nnz > 0 && a_nnz < 127 && a_values >= 2);
        let (dictionary_at, ranges) = a_planar_streams(&bytes);
        let group_at = dictionary_at + a_values * 16;

        let reject = |candidate: Vec<u8>| match SeekableFieldR1csArtifact::open(
            Cursor::new(candidate.clone()),
            shape,
            digest,
            candidate.len() as u64,
        ) {
            Ok(_) => panic!("malformed seekable artifact must fail closed"),
            Err(error) => error,
        };

        // Row counts that overrun nnz are rejected by row accounting.
        let mut bad_count = bytes.clone();
        bad_count[ranges[0].0] = 0x7F;
        assert!(matches!(
            reject(bad_count),
            FieldR1csArtifactError::InvalidRowOffset { .. }
        ));

        // A negative reconstructed column (zigzag -64) leaves the base
        // matrix.
        let mut bad_column = bytes.clone();
        bad_column[ranges[1].0] = 0x7F;
        assert!(matches!(
            reject(bad_column),
            FieldR1csArtifactError::InvalidColumn { .. }
        ));

        // A dictionary reference past the declared table.
        let mut bad_index = bytes.clone();
        bad_index[ranges[3].0] = 0x7F;
        assert!(matches!(
            reject(bad_index),
            FieldR1csArtifactError::InvalidValueIndex { .. }
        ));

        // Semantically identical dictionary reordering is not the canonical
        // first-use encoding.
        let mut skipped_first = bytes.clone();
        swap_a_value_references(&mut skipped_first);
        let first: [u8; 16] = skipped_first[dictionary_at..dictionary_at + 16]
            .try_into()
            .unwrap();
        let second: [u8; 16] = skipped_first[dictionary_at + 16..dictionary_at + 32]
            .try_into()
            .unwrap();
        skipped_first[dictionary_at..dictionary_at + 16].copy_from_slice(&second);
        skipped_first[dictionary_at + 16..dictionary_at + 32].copy_from_slice(&first);
        assert!(matches!(
            reject(skipped_first),
            FieldR1csArtifactError::NonCanonicalValueIndexOrder { .. }
        ));

        // Group headers must consume the section budget exactly: shifting a
        // byte from firsts to counts keeps the payload length but breaks
        // canonical stream consumption.
        let mut shifted_streams = bytes.clone();
        let counts_len =
            u32::from_le_bytes(shifted_streams[group_at..group_at + 4].try_into().unwrap());
        let firsts_len = u32::from_le_bytes(
            shifted_streams[group_at + 4..group_at + 8]
                .try_into()
                .unwrap(),
        );
        assert!(firsts_len > 0);
        shifted_streams[group_at..group_at + 4].copy_from_slice(&(counts_len + 1).to_le_bytes());
        shifted_streams[group_at + 4..group_at + 8]
            .copy_from_slice(&(firsts_len - 1).to_le_bytes());
        let _ = reject(shifted_streams);

        // An inflated section length no longer matches the declared total.
        let mut inflated_section = bytes.clone();
        set_header_u64(&mut inflated_section, 80, header_u64(&bytes, 80) + 16);
        assert!(matches!(
            reject(inflated_section),
            FieldR1csArtifactError::TotalLengthMismatch { .. }
        ));

        let mut zero = bytes.clone();
        zero[dictionary_at..dictionary_at + 16].fill(0);
        assert!(matches!(
            reject(zero),
            FieldR1csArtifactError::ZeroCoefficient { .. }
        ));

        let mut duplicate = bytes;
        let first = duplicate[dictionary_at..dictionary_at + 16].to_vec();
        duplicate[dictionary_at + 16..dictionary_at + 32].copy_from_slice(&first);
        assert!(matches!(
            reject(duplicate),
            FieldR1csArtifactError::DuplicateCoefficient { .. }
        ));
    }

    #[test]
    fn seekable_artifact_scratch_is_protocol_bounded() {
        assert!(STREAMING_FIELD_R1CS_ENTRY_CHUNK * 8 <= 512 * 1024);
        assert!(STREAMING_FIELD_R1CS_MAX_DICTIONARY_VALUES * 16 <= 1024 * 1024);
        let source = include_str!("field_r1cs.rs");
        let implementation = source
            .split("pub struct SeekableFieldR1csArtifact")
            .nth(1)
            .expect("streaming artifact view")
            .split("struct CompactSparseFieldMatrix")
            .next()
            .expect("streaming implementation boundary");
        assert!(!implementation.contains("read_artifact(&mut"));
        assert!(!implementation.contains("SparseFieldMatrix {"));
    }

    #[test]
    fn field_r1cs_artifact_writer_canonicalizes_shared_dictionary() {
        let (honest, shape, digest, canonical_bytes) = artifact_fixture(0xCA10_D1C7);
        let mut shared = honest.clone();

        // Model the builder's shared A/B dictionary: reorder all A entries,
        // remap the references so decoded rows stay identical, then retain an
        // unused duplicate entry from the shared superset.
        let value_count = shared.a_0.value_table.len();
        assert!(value_count > 2);
        shared.a_0.value_table.rotate_left(1);
        for value_index in &mut shared.a_0.value_indices {
            *value_index = (*value_index + value_count as u32 - 1) % value_count as u32;
        }
        shared.a_0.value_table.push(shared.a_0.value_table[0]);
        assert_eq!(shared.a_0, honest.a_0);
        assert_eq!(shared.structural_statement_digest(), digest);

        let mut canonicalized = Vec::new();
        shared.write_artifact(&mut canonicalized).unwrap();
        assert_eq!(
            canonicalized, canonical_bytes,
            "writer must emit first-use per-matrix dictionaries, independent of builder interning",
        );
        let decoded = decode_fixture(&canonicalized, shape, digest).unwrap();
        assert_eq!(decoded.a_0, honest.a_0);
        assert_eq!(decoded.b_0, honest.b_0);
    }

    #[test]
    fn field_r1cs_artifact_reader_rejects_semantic_dictionary_reordering() {
        let (honest, shape, digest, mut bytes) = artifact_fixture(0x57A1_C7D1);
        let a_values = header_u64(&bytes, 72) as usize;
        assert!(a_values >= 2);
        let (values_start, _) = a_planar_streams(&bytes);

        // Swap dictionary entries 0/1 and all of their references. The
        // decoded coefficient in every row is unchanged, but the first used
        // artifact index is now 1 rather than canonical index 0.
        swap_a_value_references(&mut bytes);
        let first: [u8; 16] = bytes[values_start..values_start + 16].try_into().unwrap();
        let second: [u8; 16] = bytes[values_start + 16..values_start + 32]
            .try_into()
            .unwrap();
        bytes[values_start..values_start + 16].copy_from_slice(&second);
        bytes[values_start + 16..values_start + 32].copy_from_slice(&first);

        assert!(matches!(
            decode_fixture(&bytes, shape, digest),
            Err(FieldR1csArtifactError::NonCanonicalValueIndexOrder {
                matrix: FieldR1csArtifactMatrix::A,
                expected_next: 0,
                actual: 1,
                ..
            })
        ));
        // Keep the semantic equivalence premise explicit and independent of
        // the decoder under test.
        let mut equivalent = honest.clone();
        equivalent.a_0.value_table.swap(0, 1);
        for index in &mut equivalent.a_0.value_indices {
            *index = match *index {
                0 => 1,
                1 => 0,
                other => other,
            };
        }
        assert_eq!(equivalent.structural_statement_digest(), digest);
    }

    #[test]
    fn field_r1cs_artifact_rejects_seeded_content_substitution() {
        let (honest, shape, expected_digest, _) = artifact_fixture(0x0D16_5E57);
        let mut substituted = honest.clone();
        let entry = substituted.a_0.row_offsets[1];
        substituted.a_0.col_indices[entry] =
            (substituted.a_0.col_indices[entry] + 1) % substituted.a_0.num_cols as u32;
        assert_ne!(substituted.structural_statement_digest(), expected_digest,);
        substituted.seed_statement_digest(expected_digest);

        let mut bytes = Vec::new();
        substituted.write_artifact(&mut bytes).unwrap();
        assert!(matches!(
            decode_fixture(&bytes, shape, expected_digest),
            Err(FieldR1csArtifactError::StructuralDigestMismatch { .. })
        ));
    }

    struct CountingReader<'a> {
        inner: Cursor<&'a [u8]>,
        bytes_read: usize,
    }

    impl Read for CountingReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let read = self.inner.read(buffer)?;
            self.bytes_read += read;
            Ok(read)
        }
    }

    #[test]
    fn field_r1cs_artifact_rejects_forged_huge_counts_before_payload() {
        let (_, shape, digest, mut bytes) = artifact_fixture(0xC0A1_7001);
        // A.nnz is the third u64 of the first descriptor.
        set_header_u64(&mut bytes, 64, u64::MAX);
        let max_bytes = bytes.len();
        let mut reader = CountingReader {
            inner: Cursor::new(bytes.as_slice()),
            bytes_read: 0,
        };
        assert!(matches!(
            FieldR1cs::read_artifact(&mut reader, shape, digest, max_bytes),
            Err(FieldR1csArtifactError::CountOutOfRange {
                matrix: FieldR1csArtifactMatrix::A,
                field: "nnz",
                ..
            })
        ));
        assert_eq!(
            reader.bytes_read, FIELD_R1CS_ARTIFACT_HEADER_BYTES,
            "untrusted vector counts must fail before payload reads or allocations",
        );
    }

    #[test]
    fn field_r1cs_artifact_rejects_bad_dimensions_and_offsets() {
        let (_, shape, digest, bytes) = artifact_fixture(0xBAD0_FF5E7);

        let mut bad_dimensions = bytes.clone();
        set_header_u64(&mut bad_dimensions, 48, (1u64 << shape.k_log) - 1);
        assert!(matches!(
            decode_fixture(&bad_dimensions, shape, digest),
            Err(FieldR1csArtifactError::MatrixDimensions {
                matrix: FieldR1csArtifactMatrix::A,
                ..
            })
        ));

        let a_nnz = header_u64(&bytes, 64) as usize;
        assert!(a_nnz < 127);
        let mut bad_first_count = bytes;
        let (_, ranges) = a_planar_streams(&bad_first_count);
        bad_first_count[ranges[0].0] = 0x7F;
        assert!(matches!(
            decode_fixture(&bad_first_count, shape, digest),
            Err(FieldR1csArtifactError::InvalidRowOffset {
                matrix: FieldR1csArtifactMatrix::A,
                index: 0,
                ..
            })
        ));
    }

    #[test]
    fn field_r1cs_artifact_rejects_bad_indices_and_zero_coefficients() {
        let (_, shape, digest, bytes) = artifact_fixture(0xBAD1_D1CE5);
        let a_values = header_u64(&bytes, 72) as usize;
        assert!(a_values >= 2 && a_values < 127);
        let (values_start, ranges) = a_planar_streams(&bytes);

        // Zigzag 0x7F is -64: the reconstructed first column leaves the base
        // matrix from below.
        let mut bad_column = bytes.clone();
        bad_column[ranges[1].0] = 0x7F;
        assert!(matches!(
            decode_fixture(&bad_column, shape, digest),
            Err(FieldR1csArtifactError::InvalidColumn {
                matrix: FieldR1csArtifactMatrix::A,
                ..
            })
        ));

        // Reference 127 is past every fixture dictionary.
        let mut bad_value_index = bytes.clone();
        bad_value_index[ranges[3].0] = 0x7F;
        assert!(matches!(
            decode_fixture(&bad_value_index, shape, digest),
            Err(FieldR1csArtifactError::InvalidValueIndex {
                matrix: FieldR1csArtifactMatrix::A,
                ..
            })
        ));

        let mut zero_coefficient = bytes;
        let mut duplicate_coefficient = zero_coefficient.clone();
        duplicate_coefficient[values_start + 16..values_start + 32]
            .copy_from_slice(&zero_coefficient[values_start..values_start + 16]);
        assert!(matches!(
            decode_fixture(&duplicate_coefficient, shape, digest),
            Err(FieldR1csArtifactError::DuplicateCoefficient {
                matrix: FieldR1csArtifactMatrix::A,
                ..
            })
        ));

        zero_coefficient[values_start..values_start + 16].fill(0);
        assert!(matches!(
            decode_fixture(&zero_coefficient, shape, digest),
            Err(FieldR1csArtifactError::ZeroCoefficient {
                matrix: FieldR1csArtifactMatrix::A,
                index: 0,
            })
        ));
    }

    #[test]
    fn field_r1cs_artifact_rejects_trailing_and_truncated_bytes() {
        let (_, shape, digest, bytes) = artifact_fixture(0x7A11_1A7E);

        let mut trailing = bytes.clone();
        trailing.push(0xA5);
        assert!(matches!(
            decode_fixture(&trailing, shape, digest),
            Err(FieldR1csArtifactError::TrailingBytes)
        ));

        let truncated = &bytes[..bytes.len() - 1];
        assert!(matches!(
            FieldR1cs::read_artifact(&mut Cursor::new(truncated), shape, digest, bytes.len(),),
            Err(FieldR1csArtifactError::Truncated { .. })
        ));
    }

    #[test]
    fn random_instances_satisfy() {
        for &(m, k_log, seed) in &[(8usize, 4usize, 1u64), (10, 6, 2), (12, 8, 3)] {
            let (r1cs, z) = random_satisfiable(m, k_log, seed);
            r1cs.validate_shape();
            assert!(r1cs.satisfies(&z), "m={m} k_log={k_log}");

            // Corrupt one element → unsatisfied. Index 1 is a constrained row
            // (row 0 is the free-input row where any corruption also breaks
            // the z_0 = 0 constraint, but 1 exercises the multiplicative row).
            let mut bad = z.clone();
            bad[1] += F128::ONE;
            assert!(!r1cs.satisfies(&bad), "corruption accepted m={m}");
        }
    }

    #[test]
    fn identity_a_b_forces_idempotents() {
        // A_0 = B_0 = I ⇒ constraint z_i² = z_i ⇒ z_i ∈ {0, 1} (the only
        // idempotents of a field). Field semantics differ from GF(2) bitwise:
        // an arbitrary F128 element does NOT satisfy it.
        let k_log = 3;
        let m = 5;
        let r1cs = FieldR1cs {
            m,
            k_log,
            k_skip: 3,
            useful_rows: 1 << k_log,
            a_0: SparseFieldMatrix::identity(1 << k_log),
            b_0: SparseFieldMatrix::identity(1 << k_log),
            const_pin: None,
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        };
        let mut z = vec![F128::ZERO; 1 << m];
        z[3] = F128::ONE;
        assert!(r1cs.satisfies(&z));
        z[5] = F128 { lo: 2, hi: 0 };
        assert!(!r1cs.satisfies(&z), "non-idempotent element accepted");
    }

    #[test]
    fn csc_cache_can_be_released_and_rebuilt() {
        let (mut r1cs, _) = random_satisfiable(10, 6, 0xC5C);
        assert!(!r1cs.release_csc_cache(), "fresh instance has no CSC");
        let first_shape = {
            let csc = r1cs.csc_lincheck_circuit();
            (csc.n_cols, csc.a_rows.len(), csc.b_rows.len())
        };
        assert!(r1cs.release_csc_cache(), "materialized CSC was released");
        assert!(!r1cs.release_csc_cache(), "release is idempotent");
        let rebuilt = r1cs.csc_lincheck_circuit();
        assert_eq!(
            (rebuilt.n_cols, rebuilt.a_rows.len(), rebuilt.b_rows.len()),
            first_shape,
            "rebuilt CSC shape drifted",
        );
    }

    /// FieldCscCircuit::fold_alpha_batched matches the direct definition
    /// `comb[c] = α·Σ_r A_0[r,c]·eq[r] + Σ_r B_0[r,c]·eq[r]`.
    #[test]
    fn csc_fold_matches_direct() {
        let (r1cs, _) = random_satisfiable(10, 6, 77);
        let k = r1cs.k();
        let mut rng = Rng::new(999);
        let point: Vec<F128> = (0..r1cs.k_log).map(|_| rng.f128()).collect();
        let eq_inner = build_eq_table(&point);
        assert_eq!(eq_inner.len(), k);
        let alpha = rng.f128();

        let circuit = r1cs.csc_lincheck_circuit();
        let got = circuit.fold_alpha_batched(alpha, &eq_inner);

        let mut expected = vec![F128::ZERO; k];
        for r in 0..r1cs.a_0.num_rows {
            for (c, coeff) in r1cs.a_0.row(r) {
                expected[c as usize] += alpha * coeff * eq_inner[r];
            }
        }
        for r in 0..r1cs.b_0.num_rows {
            for (c, coeff) in r1cs.b_0.row(r) {
                expected[c as usize] += coeff * eq_inner[r];
            }
        }
        assert_eq!(got, expected);

        let row = FieldRowCircuit::new(&r1cs.a_0, &r1cs.b_0, r1cs.const_pin);
        let row_got = row.fold_alpha_batched(alpha, &eq_inner);
        assert_eq!(row_got, got, "row-major fold drifted from CSC fold");
    }

    /// The borrowing row fold is value-identical to the legacy CSC gather in
    /// both its one-comb verifier path and its parallel prover path.
    #[test]
    fn row_fold_matches_csc_in_serial_and_parallel_pools() {
        let (r1cs, _) = random_satisfiable(13, 12, 0xA11C_E551);
        let mut rng = Rng::new(0xF01D_E001);
        let point: Vec<F128> = (0..r1cs.k_log).map(|_| rng.f128()).collect();
        let eq_inner = build_eq_table(&point);
        let alpha = rng.f128();
        let csc =
            FieldCscCircuit::from_matrices(&r1cs.a_0, &r1cs.b_0).with_const_pin(r1cs.const_pin);
        let expected = csc.fold_alpha_batched(alpha, &eq_inner);
        let row = FieldRowCircuit::new(&r1cs.a_0, &r1cs.b_0, r1cs.const_pin);

        let serial = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("one-thread test pool")
            .install(|| row.fold_alpha_batched(alpha, &eq_inner));
        let parallel = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("two-thread test pool")
            .install(|| row.fold_alpha_batched(alpha, &eq_inner));

        assert_eq!(serial, expected, "single-comb verifier fold drifted");
        assert_eq!(parallel, expected, "parallel row fold drifted");
    }

    #[test]
    fn c1_single_scan_folds_match_four_pass_oracle_for_every_hot_layout() {
        let (r1cs, _) = random_satisfiable(13, 12, 0xC1_51_6E5C);
        let row = FieldRowCircuit::new(&r1cs.a_0, &r1cs.b_0, r1cs.const_pin);
        let mut rng = Rng::new(0xC1_F01D_0A11);
        let alpha = rng.f256();
        let z_skip = rng.f256();
        let inner_rest = (0..r1cs.k_log - r1cs.k_skip)
            .map(|_| rng.f256())
            .collect::<Vec<_>>();
        let dense_point = (0..r1cs.k_log).map(|_| rng.f256()).collect::<Vec<_>>();
        let dense_eq = crate::zerocheck::field_c1::build_eq_table(&dense_point);

        let row_oracle = LegacyC1FoldOracle(&row);
        let expected_quirky =
            row_oracle.fold_alpha_batched_quirky_c1(alpha, z_skip, &inner_rest, r1cs.k_skip);
        let expected_dense = row_oracle.fold_alpha_batched_c1(alpha, &dense_eq);

        for threads in [1, 2] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("C1 fold test pool");
            let (quirky, dense) = pool.install(|| {
                (
                    row.fold_alpha_batched_quirky_c1(alpha, z_skip, &inner_rest, r1cs.k_skip),
                    row.fold_alpha_batched_c1(alpha, &dense_eq),
                )
            });
            assert_eq!(quirky, expected_quirky, "resident quirky C1 fold drifted");
            assert_eq!(dense, expected_dense, "resident dense C1 fold drifted");
        }

        let shape = FieldShape::of(&r1cs);
        let digest = r1cs.structural_statement_digest();
        let mut bytes = Vec::new();
        r1cs.write_artifact(&mut bytes).unwrap();
        let compact =
            CompactFieldR1cs::open(bytes.clone().into_boxed_slice(), shape, digest).unwrap();
        let packed =
            CompactFieldR1cs::open_packed(bytes.into_boxed_slice(), shape, digest).unwrap();
        for (name, relation) in [("compact", &compact), ("packed", &packed)] {
            for threads in [1, 2] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .expect("compact C1 fold test pool");
                let (quirky, dense) = pool.install(|| {
                    (
                        relation.fold_alpha_batched_quirky_c1(
                            alpha,
                            z_skip,
                            &inner_rest,
                            r1cs.k_skip,
                        ),
                        relation.fold_alpha_batched_c1(alpha, &dense_eq),
                    )
                });
                assert_eq!(quirky, expected_quirky, "{name} quirky C1 fold drifted");
                assert_eq!(dense, expected_dense, "{name} dense C1 fold drifted");
            }
        }
    }

    /// A proof produced against either circuit representation is byte-for-byte
    /// identical and the shared verifier accepts it with the same terminal
    /// claim. This pins the transcript/acceptance semantics while production
    /// verification switches from retained CSC to borrowing CSR.
    #[test]
    fn row_and_csc_lincheck_transcripts_and_acceptance_match() {
        use crate::challenger::FsChallenger;
        use crate::lincheck::{QuirkyPoint, prove_field, verify};

        let (r1cs, z) = random_satisfiable(10, 7, 0x7E57_C5C0);
        let mut rng = Rng::new(0x7A4A_5C71);
        let x_ab = QuirkyPoint {
            z_skip: rng.f128(),
            x_inner_rest: (0..r1cs.k_log - r1cs.k_skip).map(|_| rng.f128()).collect(),
            x_outer: (0..r1cs.m - r1cs.k_log).map(|_| rng.f128()).collect(),
        };
        let row = FieldRowCircuit::new(&r1cs.a_0, &r1cs.b_0, r1cs.const_pin);
        let csc =
            FieldCscCircuit::from_matrices(&r1cs.a_0, &r1cs.b_0).with_const_pin(r1cs.const_pin);

        let mut ch_row = FsChallenger::new(b"field-row-csc-parity-v0");
        let (proof_row, claim_row) = prove_field(
            &z,
            r1cs.m,
            r1cs.k_log,
            r1cs.k_skip,
            r1cs.useful_rows,
            &row,
            &x_ab,
            &mut ch_row,
        );
        let mut ch_csc = FsChallenger::new(b"field-row-csc-parity-v0");
        let (proof_csc, claim_csc) = prove_field(
            &z,
            r1cs.m,
            r1cs.k_log,
            r1cs.k_skip,
            r1cs.useful_rows,
            &csc,
            &x_ab,
            &mut ch_csc,
        );
        assert_eq!(proof_row, proof_csc, "lincheck proof/transcript drifted");
        assert_eq!(claim_row, claim_csc, "prover terminal claim drifted");

        let a = apply_block_diag_field(&r1cs.a_0, &z, r1cs.k_log);
        let b = apply_block_diag_field(&r1cs.b_0, &z, r1cs.k_log);
        let eval = |values: &[F128]| {
            let skip =
                crate::zerocheck::multilinear::lagrange_weights_naive(r1cs.k_skip, x_ab.z_skip);
            let rest = build_eq_table(&x_ab.x_inner_rest);
            let outer = build_eq_table(&x_ab.x_outer);
            let inner_mask = (1usize << r1cs.k_log) - 1;
            let skip_mask = (1usize << r1cs.k_skip) - 1;
            values
                .iter()
                .enumerate()
                .fold(F128::ZERO, |acc, (i, value)| {
                    let inner = i & inner_mask;
                    acc + *value
                        * skip[inner & skip_mask]
                        * rest[inner >> r1cs.k_skip]
                        * outer[i >> r1cs.k_log]
                })
        };
        let (v_a, v_b) = (eval(&a), eval(&b));

        let mut ch_verify_row = FsChallenger::new(b"field-row-csc-parity-v0");
        let accepted_row = verify(
            r1cs.m,
            r1cs.k_log,
            r1cs.k_skip,
            &row,
            &x_ab,
            v_a,
            v_b,
            &proof_row,
            &mut ch_verify_row,
        )
        .expect("borrowing row verifier rejected the parity proof");
        let mut ch_verify_csc = FsChallenger::new(b"field-row-csc-parity-v0");
        let accepted_csc = verify(
            r1cs.m,
            r1cs.k_log,
            r1cs.k_skip,
            &csc,
            &x_ab,
            v_a,
            v_b,
            &proof_row,
            &mut ch_verify_csc,
        )
        .expect("legacy CSC verifier rejected the parity proof");

        assert_eq!(accepted_row, claim_row);
        assert_eq!(accepted_row, accepted_csc, "verifier acceptance drifted");
        assert!(
            r1cs.csc_cache.get().is_none(),
            "row verification populated the retained CSC cache",
        );
    }

    #[test]
    fn statement_digest_distinguishes_instances() {
        let (r1cs_a, _) = random_satisfiable(8, 4, 10);
        let (r1cs_b, _) = random_satisfiable(8, 4, 11);
        assert_ne!(r1cs_a.statement_digest(), r1cs_b.statement_digest());

        // Coefficient change flips the digest (perturb a table entry — every
        // nonzero mapping to it decodes to the new value; `clone` resets the
        // digest cache, so it is re-hashed).
        let mut r1cs_c = r1cs_a.clone();
        *r1cs_c
            .a_0
            .value_table
            .first_mut()
            .expect("matrix has at least one distinct value") += F128::ONE;
        assert_ne!(r1cs_a.statement_digest(), r1cs_c.statement_digest());

        // Same content → same digest (cache-independent).
        let r1cs_d = r1cs_a.clone();
        assert_eq!(r1cs_a.statement_digest(), r1cs_d.statement_digest());
    }

    /// The chunked digest is sensitive to content in EVERY span, not just the
    /// first: k = 2^12 rows = two spans of `DIGEST_SPAN_ROWS`.
    #[test]
    fn statement_digest_covers_all_spans() {
        let (r1cs, _) = random_satisfiable(12, 12, 5);
        assert!(r1cs.k() > DIGEST_SPAN_ROWS, "instance must span ≥2 chunks");
        let base = r1cs.statement_digest();

        for &row in &[1usize, DIGEST_SPAN_ROWS - 1, DIGEST_SPAN_ROWS, r1cs.k() - 1] {
            let mut mutated = r1cs.clone();
            assert!(mutated.b_0.row_len(row) > 0, "synthetic rows are nonempty");
            // Perturb exactly this one nonzero: point it at a fresh table entry
            // holding (old value + 1), leaving all other nonzeros untouched.
            let entry = mutated.b_0.row_offsets[row];
            let old = mutated.b_0.value_table[mutated.b_0.value_indices[entry] as usize];
            let new_idx = mutated.b_0.value_table.len() as u32;
            mutated.b_0.value_table.push(old + F128::ONE);
            mutated.b_0.value_indices[entry] = new_idx;
            assert_ne!(
                base,
                mutated.statement_digest(),
                "coefficient change in row {row} must flip the digest"
            );
        }
    }

    #[test]
    fn seed_statement_digest_installs_constant() {
        let (r1cs, _) = random_satisfiable(8, 4, 21);
        let true_digest = r1cs.statement_digest();

        // Seeding a fresh instance short-circuits the content hash.
        let fresh = r1cs.clone();
        fresh.seed_statement_digest(true_digest);
        assert_eq!(fresh.statement_digest(), true_digest);

        // Seeding the already-computed digest again is a no-op.
        fresh.seed_statement_digest(true_digest);

        // A seeded digest wins even if it is not the content hash. Callers at
        // a matrix trust boundary must use structural_statement_digest().
        let mislabeled = r1cs.clone();
        mislabeled.seed_statement_digest([0xAB; 32]);
        assert_eq!(mislabeled.statement_digest(), [0xAB; 32]);
        assert_eq!(
            mislabeled.structural_statement_digest(),
            true_digest,
            "cache-independent digest must recover the matrix's real identity",
        );
    }

    #[test]
    fn structural_statement_digest_rejects_seeded_content_substitution() {
        let (honest, _) = random_satisfiable(8, 4, 0x51A7_E001);
        let expected = honest.structural_statement_digest();
        let mut substituted = honest.clone();
        let entry = substituted.a_0.row_offsets[0];
        let old = substituted.a_0.value_table[substituted.a_0.value_indices[entry] as usize];
        let replacement = substituted.a_0.value_table.len() as u32;
        substituted.a_0.value_table.push(old + F128::ONE);
        substituted.a_0.value_indices[entry] = replacement;
        substituted.seed_statement_digest(expected);

        assert_eq!(
            substituted.statement_digest(),
            expected,
            "the ordinary class cache is intentionally seedable",
        );
        assert_ne!(
            substituted.structural_statement_digest(),
            expected,
            "a trust-boundary digest must ignore the seeded cache",
        );
    }

    #[test]
    #[should_panic(expected = "different digest is already cached")]
    fn seed_statement_digest_rejects_conflict() {
        let (r1cs, _) = random_satisfiable(8, 4, 22);
        let _ = r1cs.statement_digest();
        r1cs.seed_statement_digest([0xCD; 32]);
    }

    /// FlipBattery answers exactly what a full clone-flip-satisfies pass
    /// answers, for EVERY wire of several instances (multi-block shapes
    /// included), and leaves its state intact between queries.
    #[test]
    fn flip_battery_matches_full_satisfies() {
        for (m, k_log, seed) in [(6usize, 6usize, 1u64), (8, 5, 2), (7, 7, 3)] {
            let (r1cs, z) = random_satisfiable(m, k_log, seed);
            assert!(r1cs.satisfies(&z));
            let mut battery = r1cs.flip_battery(&z);
            for w in 0..z.len() {
                let mut bad = z.clone();
                bad[w] += F128::ONE;
                let full = r1cs.satisfies(&bad);
                assert_eq!(
                    battery.survives_flip(w),
                    full,
                    "m={m} k_log={k_log} wire {w}"
                );
            }
            // State intact: a second pass agrees with itself.
            for w in (0..z.len()).step_by(7) {
                let mut bad = z.clone();
                bad[w] += F128::ONE;
                assert_eq!(battery.survives_flip(w), r1cs.satisfies(&bad));
            }
        }
    }

    #[test]
    fn apply_block_diag_field_blocks_independent() {
        let (r1cs, z) = random_satisfiable(9, 5, 42);
        let k = r1cs.k();
        let a_full = r1cs.apply_a(&z);
        // Per-block manual apply must match.
        for blk in 0..r1cs.n_outer() {
            let base = blk * k;
            for r in 0..r1cs.a_0.num_rows {
                let mut acc = F128::ZERO;
                for (c, coeff) in r1cs.a_0.row(r) {
                    acc += coeff * z[base + c as usize];
                }
                assert_eq!(a_full[base + r], acc, "blk={blk} r={r}");
            }
        }
    }
}
