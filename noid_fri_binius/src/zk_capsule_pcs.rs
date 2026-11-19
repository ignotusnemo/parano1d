// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Transcript-free selected PCS for the witness-hiding authorization capsule.
//!
//! This module commits one fixed 2048-cell bank and one independently fresh
//! 2048-cell companion with the selected rate-1/32 affine LCH code.  It then
//! exposes typed prover stages matching the only sound transcript order:
//!
//! 1. commit the joint source cap before any masking challenge;
//! 2. bind the transparent Phase-A relation and the already-proved Owner bank
//!    claim, expose only `sigma = <C,t>`, then sample `gamma`;
//! 3. derive every Phase-A challenge adaptively after its round message, link
//!    its terminal value through the public `upper[256]`, and only then admit
//!    the state to Phase B;
//! 4. after `beta[0..3]`, commit the mid cap before `beta[3..7]`;
//! 5. after `beta[3..7]`, reveal `tail[16]` before `beta[7]` and queries;
//! 6. only then open the fixed 65 transcript-derived 13-bit queries.
//!
//! There is deliberately no transcript in this file and no reuse of the
//! active capsule's rejected all-beta-before-mid ordering.  The caller owns
//! challenge sampling, the `beta[7]` upper/tail link, and grinding.  The sole
//! production source-commit entry point accepts only the 512-cell state and
//! draws the bank's PCS coins, Libra mask, remaining padding, and the complete
//! companion internally from a caller-supplied cryptographic RNG.
//!
//! Source leaves are fixed-shape fold-normal joint cells over 8192 leaves
//! with an eight-hash cap.  Three
//! LOW-to-HIGH affine folds land in one of the 16 cells of the corresponding
//! 512-leaf mid tree, whose cap also has eight hashes.  Four more folds land in the
//! locally re-encoded `Code(tail16)`.

use noid_core::hardware::{flat_to_tower_u128, tower_to_flat_u128};
use noid_core::{Block128, Block256, TowerField};
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::capsule::{capsule_leaf_hash_mixed, capsule_leaf_hash_wide, VersionedCapsuleNodeHasher};
use crate::interleaved_commit::{
    build_source_batched_merkle_proof_to_cap, verify_source_batched_merkle_proof_to_cap,
    CommitmentHashBackend, MerkleCap, SourceBatchedMerkleProof, SourceHash, SourceHashMerkleTree,
};
use crate::zk_affine_code::{
    AffineHighPaddingRankCertificate, ZkAffineCodeError, ZkAffineLchCode, AFFINE_CODE_LEN,
    AFFINE_CODE_LOG_RATE, AFFINE_CODE_MESSAGE_LEN, AFFINE_CODE_MESSAGE_LOG,
    AFFINE_RANK_RANDOM_BLOCK_LEN, AFFINE_STATE_LEN,
};
use crate::zk_capsule::ZK_AUTH_CAPSULE_GEOMETRY;
use crate::zk_capsule_algebra::{
    build_fold_normal_joint_source_leaf, build_fold_normal_mid_leaf,
    certify_source_query_hiding_rank, contract_high3_for_each_low8, evaluate_upper_at_low8,
    fold_normal_joint_source_leaf, fold_normal_mid_leaf, fold_normal_mid_raw_member,
    map_source_query_leaf, ZkCapsuleAlgebraError, JOINT_SOURCE_LEAF_SYMBOLS, MID_STANDARD_FOLDS,
    PHASE_B_HIGH_VARS, PHASE_B_LOW_VARS, SOURCE_QUERY_BITS, SOURCE_STANDARD_FOLDS, TAIL_SYMBOLS,
    UPPER_SYMBOLS,
};
use crate::zk_phase_a::{
    phase_a_relation_claims, phase_a_virtual_oracle, prove_phase_a_adaptive, ZkPhaseAError,
    ZkPhaseAProverOutput, ZkPhaseARoundProof, PHASE_A_VARS,
};
use noid_poseidon2b::native::ProofNodeHashVersion;

pub const ZK_CAPSULE_PCS_QUERY_COUNT: usize = 65;
pub const ZK_CAPSULE_PCS_SOURCE_LEAF_COUNT: usize = 8_192;
pub const ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH: usize = 13;
pub const ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH: usize = 3;
pub const ZK_CAPSULE_PCS_SOURCE_CAP_HASHES: usize = 1 << ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH;
pub const ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH: usize =
    ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH - ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH;
/// Effective joint source log: bank log 11 plus the bank/companion line bit.
pub const ZK_CAPSULE_PCS_SOURCE_LEAF_HASH_LOG: usize = AFFINE_CODE_MESSAGE_LOG + 1;

pub const ZK_CAPSULE_PCS_MID_CODE_LEN: usize = 8_192;
pub const ZK_CAPSULE_PCS_MID_LEAF_COUNT: usize = 512;
pub const ZK_CAPSULE_PCS_MID_TREE_DEPTH: usize = 9;
pub const ZK_CAPSULE_PCS_MID_CAP_DEPTH: usize = 3;
pub const ZK_CAPSULE_PCS_MID_CAP_HASHES: usize = 1 << ZK_CAPSULE_PCS_MID_CAP_DEPTH;
pub const ZK_CAPSULE_PCS_MID_PATH_DEPTH: usize =
    ZK_CAPSULE_PCS_MID_TREE_DEPTH - ZK_CAPSULE_PCS_MID_CAP_DEPTH;
pub const ZK_CAPSULE_PCS_MID_LEAF_HASH_LOG: usize = AFFINE_CODE_MESSAGE_LOG - SOURCE_STANDARD_FOLDS;

pub const ZK_CAPSULE_PCS_SOURCE_SYMBOLS: usize =
    ZK_CAPSULE_PCS_QUERY_COUNT * JOINT_SOURCE_LEAF_SYMBOLS;
pub const ZK_CAPSULE_PCS_MID_SYMBOLS: usize =
    ZK_CAPSULE_PCS_QUERY_COUNT * (1 << MID_STANDARD_FOLDS);
/// Exact maxima for a canonical batched proof of 65 leaves in the eight
/// capped source subtrees and their induced mid leaves.  The source maximum
/// is `453`; the mid maximum is `193`.  The test below certifies both maxima
/// by dynamic programming and exhibits one query set attaining them together.
pub const ZK_CAPSULE_PCS_WORST_SOURCE_SIBLINGS: usize = 453;
pub const ZK_CAPSULE_PCS_WORST_MID_SIBLINGS: usize = 193;
pub const ZK_CAPSULE_PCS_WORST_OPENING_BYTES: usize = ZK_CAPSULE_PCS_SOURCE_SYMBOLS * 16
    + ZK_CAPSULE_PCS_MID_SYMBOLS * 32
    + (ZK_CAPSULE_PCS_WORST_SOURCE_SIBLINGS + ZK_CAPSULE_PCS_WORST_MID_SIBLINGS) * 32;
pub const ZK_CAPSULE_PCS_SOURCE_COMMITMENT_BYTES: usize = ZK_CAPSULE_PCS_SOURCE_CAP_HASHES * 32;
pub const ZK_CAPSULE_PCS_MID_COMMITMENT_BYTES: usize = ZK_CAPSULE_PCS_MID_CAP_HASHES * 32;
pub const ZK_CAPSULE_PCS_TAIL_BYTES: usize = TAIL_SYMBOLS * 32;
pub const ZK_CAPSULE_PCS_WORST_TOTAL_BYTES: usize = ZK_CAPSULE_PCS_SOURCE_COMMITMENT_BYTES
    + ZK_CAPSULE_PCS_MID_COMMITMENT_BYTES
    + ZK_CAPSULE_PCS_TAIL_BYTES
    + ZK_CAPSULE_PCS_WORST_OPENING_BYTES;

const _: () = assert!(AFFINE_CODE_LOG_RATE == 5);
const _: () = assert!(SOURCE_QUERY_BITS == 13);
const _: () = assert!(SOURCE_STANDARD_FOLDS == 3);
const _: () = assert!(MID_STANDARD_FOLDS == 4);
const _: () = assert!(TAIL_SYMBOLS == 16);
const _: () = assert!(ZK_CAPSULE_PCS_SOURCE_LEAF_COUNT == 1 << SOURCE_QUERY_BITS);
const _: () = assert!(ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH == SOURCE_QUERY_BITS);
const _: () = assert!(
    ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH
        == AFFINE_CODE_LOG_RATE + ZK_CAPSULE_PCS_SOURCE_LEAF_HASH_LOG - 4
);
const _: () = assert!(ZK_CAPSULE_PCS_SOURCE_LEAF_COUNT == 1 << ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH);
const _: () = assert!(ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH == 10);
const _: () = assert!(ZK_CAPSULE_PCS_MID_PATH_DEPTH == 6);
const _: () = assert!(ZK_CAPSULE_PCS_MID_CODE_LEN == AFFINE_CODE_LEN >> SOURCE_STANDARD_FOLDS);
const _: () = assert!(
    ZK_CAPSULE_PCS_MID_LEAF_COUNT * (1 << MID_STANDARD_FOLDS) == ZK_CAPSULE_PCS_MID_CODE_LEN
);
const _: () = assert!(ZK_CAPSULE_PCS_MID_LEAF_COUNT == 1 << ZK_CAPSULE_PCS_MID_TREE_DEPTH);
const _: () = assert!(
    ZK_CAPSULE_PCS_MID_TREE_DEPTH == AFFINE_CODE_LOG_RATE + ZK_CAPSULE_PCS_MID_LEAF_HASH_LOG - 4
);
const _: () = assert!(ZK_CAPSULE_PCS_QUERY_COUNT == ZK_AUTH_CAPSULE_GEOMETRY.query_count);
const _: () = assert!(ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH == ZK_AUTH_CAPSULE_GEOMETRY.source_cap_depth);
const _: () = assert!(ZK_CAPSULE_PCS_MID_CAP_DEPTH == ZK_AUTH_CAPSULE_GEOMETRY.mid_cap_depth);
const _: () = assert!(ZK_CAPSULE_PCS_WORST_OPENING_BYTES == 78_912);
const _: () = assert!(ZK_CAPSULE_PCS_WORST_TOTAL_BYTES == 79_936);

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ZkCapsulePcsSourceCommitment {
    pub cap: MerkleCap,
}

impl ZkCapsulePcsSourceCommitment {
    pub fn byte_len(&self) -> usize {
        self.cap.hashes.len() * 32
    }

    /// Flatten the eight flat-basis hashes into 16 tower-basis transcript
    /// lanes absorbed by Owner, hash-major and low-half first.
    pub fn transcript_lanes(
        &self,
    ) -> Result<[Block128; 2 * ZK_CAPSULE_PCS_SOURCE_CAP_HASHES], ZkCapsulePcsError> {
        if self.cap.hashes.len() != ZK_CAPSULE_PCS_SOURCE_CAP_HASHES {
            return Err(ZkCapsulePcsError::SourceCapCount {
                expected: ZK_CAPSULE_PCS_SOURCE_CAP_HASHES,
                actual: self.cap.hashes.len(),
            });
        }
        Ok(std::array::from_fn(|lane| {
            flat_digest_to_tower_lanes(&self.cap.hashes[lane / 2])[lane & 1]
        }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ZkCapsulePcsMidCommitment {
    pub cap: MerkleCap,
}

impl ZkCapsulePcsMidCommitment {
    pub fn byte_len(&self) -> usize {
        self.cap.hashes.len() * 32
    }

    pub fn transcript_lanes(
        &self,
    ) -> Result<[Block128; 2 * ZK_CAPSULE_PCS_MID_CAP_HASHES], ZkCapsulePcsError> {
        if self.cap.hashes.len() != ZK_CAPSULE_PCS_MID_CAP_HASHES {
            return Err(ZkCapsulePcsError::MidCapCount {
                expected: ZK_CAPSULE_PCS_MID_CAP_HASHES,
                actual: self.cap.hashes.len(),
            });
        }
        Ok(std::array::from_fn(|lane| {
            flat_digest_to_tower_lanes(&self.cap.hashes[lane / 2])[lane & 1]
        }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ZkCapsulePcsTailReveal {
    pub coefficients: [Block256; TAIL_SYMBOLS],
}

impl ZkCapsulePcsTailReveal {
    pub const fn byte_len(&self) -> usize {
        ZK_CAPSULE_PCS_TAIL_BYTES
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ZkCapsulePcsOpening {
    /// Query-major adjacent `[B0,C0,...,B7,C7]` leaves.
    pub source_joint_symbols: Vec<Block128>,
    pub source_batch: SourceBatchedMerkleProof,
    /// Query-major contiguous 16-cell mid leaves.
    pub mid_symbols: Vec<Block256>,
    pub mid_batch: SourceBatchedMerkleProof,
}

impl ZkCapsulePcsOpening {
    pub fn byte_len(&self) -> usize {
        self.source_joint_symbols.len() * 16
            + self.mid_symbols.len() * 32
            + (self.source_batch.siblings.len() + self.mid_batch.siblings.len()) * 32
    }
}

struct VersionedProofTree {
    tree: SourceHashMerkleTree,
    hash_version: ProofNodeHashVersion,
}

impl std::ops::Deref for VersionedProofTree {
    type Target = SourceHashMerkleTree;
    fn deref(&self) -> &Self::Target {
        &self.tree
    }
}

/// Opaque fresh source state. Production has no direct bank accessor and must
/// consume this value through [`zk_capsule_pcs_bind_owner`].
///
/// ```compile_fail
/// use noid_fri_binius::ZkCapsulePcsSourceProverState;
///
/// fn cannot_reopen_bank(source: &ZkCapsulePcsSourceProverState) {
///     let _ = source.bank();
/// }
/// ```
pub struct ZkCapsulePcsSourceProverState {
    bank: Zeroizing<Vec<Block128>>,
    companion: Zeroizing<Vec<Block256>>,
    bank_codeword: Zeroizing<Vec<Block128>>,
    companion_codeword: Zeroizing<Vec<Block256>>,
    source_tree: VersionedProofTree,
}

impl ZkCapsulePcsSourceProverState {
    /// Raw bank inspection is confined to local randomness/path tests.
    /// Production can access the bank only inside the consuming Owner handoff.
    #[cfg(test)]
    fn bank_for_test(&self) -> &[Block128] {
        &self.bank
    }
}

/// Source commitment state after the one-shot Owner prover handoff. It
/// exposes neither bank nor companion and can advance only by being consumed
/// into the Phase-A relation binding.
pub struct ZkCapsulePcsOwnerBoundProverState {
    bank: Zeroizing<Vec<Block128>>,
    companion: Zeroizing<Vec<Block256>>,
    bank_codeword: Zeroizing<Vec<Block128>>,
    companion_codeword: Zeroizing<Vec<Block256>>,
    source_tree: VersionedProofTree,
}

/// The sole scalar released while binding the transparent Phase-A relation.
/// The Owner bank claim is checked, not duplicated in this hand-off.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ZkCapsulePcsPhaseABinding {
    pub companion_claim: Block256,
}

/// Source commitment state after the transparent relation and Owner bank
/// claim have been bound, but before `gamma` exists.
pub struct ZkCapsulePcsPhaseABoundProverState {
    bank: Zeroizing<Vec<Block128>>,
    companion: Zeroizing<Vec<Block256>>,
    relation: Zeroizing<Vec<Block256>>,
    bank_codeword: Zeroizing<Vec<Block128>>,
    companion_codeword: Zeroizing<Vec<Block256>>,
    source_tree: VersionedProofTree,
}

/// State after the adaptive Phase-A sumcheck. Raw bank and companion messages
/// have already been zeroized; exactly one materialization of `U_gamma`
/// remains for the Phase-B link and low folds.
pub struct ZkCapsulePcsPhaseACompleteProverState {
    virtual_oracle: Zeroizing<Vec<Block256>>,
    gamma: Block256,
    terminal_point: [Block256; PHASE_A_VARS],
    terminal_oracle_value: Block256,
    bank_codeword: Zeroizing<Vec<Block128>>,
    companion_codeword: Zeroizing<Vec<Block256>>,
    source_tree: VersionedProofTree,
}

/// The public Phase-B table linked to the exact Phase-A terminal value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkCapsulePcsPhaseBLink {
    pub upper: [Block256; UPPER_SYMBOLS],
}

/// The only production state admitted to the mid-commit transition.
pub struct ZkCapsulePcsPhaseBReadyProverState {
    virtual_oracle: Zeroizing<Vec<Block256>>,
    gamma: Block256,
    bank_codeword: Zeroizing<Vec<Block128>>,
    companion_codeword: Zeroizing<Vec<Block256>>,
    source_tree: VersionedProofTree,
}

pub struct ZkCapsulePcsMidProverState {
    mid_message: Zeroizing<Vec<Block256>>,
    mid_codeword: Zeroizing<Vec<Block256>>,
    mid_tree: VersionedProofTree,
    bank_codeword: Zeroizing<Vec<Block128>>,
    companion_codeword: Zeroizing<Vec<Block256>>,
    source_tree: VersionedProofTree,
}

pub struct ZkCapsulePcsTailProverState {
    pub tail: ZkCapsulePcsTailReveal,
    mid_codeword: Zeroizing<Vec<Block256>>,
    mid_tree: VersionedProofTree,
    bank_codeword: Zeroizing<Vec<Block128>>,
    companion_codeword: Zeroizing<Vec<Block256>>,
    source_tree: VersionedProofTree,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkCapsulePcsVerified {
    pub source_hiding_rank: AffineHighPaddingRankCertificate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkCapsulePcsError {
    StateLength {
        expected: usize,
        actual: usize,
    },
    BankLength {
        expected: usize,
        actual: usize,
    },
    CompanionLength {
        expected: usize,
        actual: usize,
    },
    QueryCount {
        expected: usize,
        actual: usize,
    },
    QueryOutOfRange {
        query_index: usize,
        value: usize,
    },
    SourceCapCount {
        expected: usize,
        actual: usize,
    },
    MidCapCount {
        expected: usize,
        actual: usize,
    },
    SourceSymbolCount {
        expected: usize,
        actual: usize,
    },
    MidSymbolCount {
        expected: usize,
        actual: usize,
    },
    GammaEndpoint,
    OwnerBankClaimMismatch {
        expected: Block256,
        actual: Block256,
    },
    PhaseATerminalMismatch {
        expected: Block256,
        actual: Block256,
    },
    QueryMapping {
        query_index: usize,
    },
    SourceToMidMismatch {
        query_index: usize,
    },
    MidToTailMismatch {
        query_index: usize,
    },
    HidingRankMismatch {
        expected: usize,
        actual: usize,
    },
    SourceMerkle(String),
    MidMerkle(String),
    AffineCode(ZkAffineCodeError),
    Algebra(ZkCapsuleAlgebraError),
    PhaseA(ZkPhaseAError),
}

impl From<ZkAffineCodeError> for ZkCapsulePcsError {
    fn from(value: ZkAffineCodeError) -> Self {
        Self::AffineCode(value)
    }
}

impl From<ZkCapsuleAlgebraError> for ZkCapsulePcsError {
    fn from(value: ZkCapsuleAlgebraError) -> Self {
        Self::Algebra(value)
    }
}

impl From<ZkPhaseAError> for ZkCapsulePcsError {
    fn from(value: ZkPhaseAError) -> Self {
        Self::PhaseA(value)
    }
}

/// Convert one flat tree digest into the exact two tower-field transcript
/// lanes that represent the same field elements.
pub fn flat_digest_to_tower_lanes(digest: &SourceHash) -> [Block128; 2] {
    std::array::from_fn(|lane| {
        let start = lane * 16;
        let flat = u128::from_le_bytes(digest[start..start + 16].try_into().unwrap());
        Block128::from(flat_to_tower_u128(flat))
    })
}

/// Inverse of [`flat_digest_to_tower_lanes`].
pub fn tower_lanes_to_flat_digest(lanes: [Block128; 2]) -> SourceHash {
    let mut digest = [0u8; 32];
    for (lane, value) in lanes.into_iter().enumerate() {
        let start = lane * 16;
        digest[start..start + 16].copy_from_slice(&tower_to_flat_u128(value.0).to_le_bytes());
    }
    digest
}

fn require_gamma(gamma: Block256) -> Result<(), ZkCapsulePcsError> {
    if gamma == Block256::ZERO || gamma == Block256::ONE {
        Err(ZkCapsulePcsError::GammaEndpoint)
    } else {
        Ok(())
    }
}

/// Bind the lowest variable while erasing every discarded cell before the
/// vector length shrinks. This avoids leaving folded witness material in the
/// initialized-but-out-of-length portion of a retained allocation.
fn fold_lowest_zeroizing(values: &mut Zeroizing<Vec<Block256>>, challenge: Block256) {
    debug_assert!(values.len().is_power_of_two() && values.len() >= 2);
    let folded_len = values.len() / 2;
    for index in 0..folded_len {
        let at_zero = values[2 * index];
        let at_one = values[2 * index + 1];
        values[index] = at_zero + challenge * (at_zero + at_one);
    }
    for value in &mut values[folded_len..] {
        value.zeroize();
    }
    values.truncate(folded_len);
}

fn preflight_messages(bank: &[Block128], companion: &[Block256]) -> Result<(), ZkCapsulePcsError> {
    if bank.len() != AFFINE_CODE_MESSAGE_LEN {
        return Err(ZkCapsulePcsError::BankLength {
            expected: AFFINE_CODE_MESSAGE_LEN,
            actual: bank.len(),
        });
    }
    if companion.len() != AFFINE_CODE_MESSAGE_LEN {
        return Err(ZkCapsulePcsError::CompanionLength {
            expected: AFFINE_CODE_MESSAGE_LEN,
            actual: companion.len(),
        });
    }
    Ok(())
}

fn preflight_queries(queries: &[usize]) -> Result<(), ZkCapsulePcsError> {
    if queries.len() != ZK_CAPSULE_PCS_QUERY_COUNT {
        return Err(ZkCapsulePcsError::QueryCount {
            expected: ZK_CAPSULE_PCS_QUERY_COUNT,
            actual: queries.len(),
        });
    }
    for (query_index, &value) in queries.iter().enumerate() {
        if value >= ZK_CAPSULE_PCS_SOURCE_LEAF_COUNT {
            return Err(ZkCapsulePcsError::QueryOutOfRange { query_index, value });
        }
    }
    Ok(())
}

fn build_source_tree(
    bank_codeword: &[Block128],
    companion_codeword: &[Block256],
    hash_version: ProofNodeHashVersion,
) -> VersionedProofTree {
    let code = ZkAffineLchCode::selected().expect("selected affine code is valid");
    let leaf_hashes = (0..ZK_CAPSULE_PCS_SOURCE_LEAF_COUNT)
        .into_par_iter()
        .with_min_len(64)
        .map(|leaf| {
            let joint =
                build_fold_normal_joint_source_leaf(&code, bank_codeword, companion_codeword, leaf)
                    .expect("fixed selected source codeword shape");
            capsule_leaf_hash_mixed(&joint)
        })
        .collect();
    VersionedProofTree {
        tree: SourceHashMerkleTree::new(
            leaf_hashes,
            CommitmentHashBackend::Arithmetic,
            &VersionedCapsuleNodeHasher(hash_version),
        ),
        hash_version,
    }
}

fn build_mid_tree(
    mid_codeword: &[Block256],
    hash_version: ProofNodeHashVersion,
) -> VersionedProofTree {
    let code = ZkAffineLchCode::selected().expect("selected affine code is valid");
    let leaf_hashes = (0..ZK_CAPSULE_PCS_MID_LEAF_COUNT)
        .into_par_iter()
        .with_min_len(32)
        .map(|leaf| {
            let leaf = build_fold_normal_mid_leaf(&code, mid_codeword, leaf)
                .expect("fixed selected mid codeword shape");
            capsule_leaf_hash_wide(&leaf)
        })
        .collect();
    VersionedProofTree {
        tree: SourceHashMerkleTree::new(
            leaf_hashes,
            CommitmentHashBackend::Arithmetic,
            &VersionedCapsuleNodeHasher(hash_version),
        ),
        hash_version,
    }
}

fn commit_prepared_messages(
    bank: Zeroizing<Vec<Block128>>,
    companion: Zeroizing<Vec<Block256>>,
    hash_version: ProofNodeHashVersion,
) -> Result<(ZkCapsulePcsSourceCommitment, ZkCapsulePcsSourceProverState), ZkCapsulePcsError> {
    preflight_messages(&bank, &companion)?;
    let code = ZkAffineLchCode::selected()?;
    let bank_codeword = Zeroizing::new(code.encode(&bank)?);
    let companion_codeword = Zeroizing::new(code.encode_extension_after_low_folds(&companion, 0)?);
    let source_tree = build_source_tree(&bank_codeword, &companion_codeword, hash_version);
    let commitment = ZkCapsulePcsSourceCommitment {
        cap: MerkleCap {
            hashes: source_tree.get_layer_at_depth(ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH),
        },
    };
    Ok((
        commitment,
        ZkCapsulePcsSourceProverState {
            bank,
            companion,
            bank_codeword,
            companion_codeword,
            source_tree,
        },
    ))
}

#[inline]
fn draw_fresh_field(rng: &mut (impl CryptoRng + RngCore + ?Sized)) -> Block128 {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    let value = Block128::from(u128::from_le_bytes(bytes));
    bytes.zeroize();
    value
}

#[inline]
fn draw_fresh_wide_field(rng: &mut (impl CryptoRng + RngCore + ?Sized)) -> Block256 {
    Block256::new(draw_fresh_field(rng), draw_fresh_field(rng))
}

/// Commit one authorization state with attempt-local witness-hiding entropy.
///
/// Only the exact 512-cell AuthGKR state is accepted from the caller.  Bank
/// cells `512..2048` and every cell of the independent 2048-cell companion
/// are drawn here before the source cap is built.  The returned typestate is
/// non-cloneable and every later prover transition consumes it; retrying thus
/// requires another call and another complete set of RNG draws.
pub fn zk_capsule_pcs_commit_fresh(
    state: &[Block128],
    rng: &mut (impl CryptoRng + RngCore + ?Sized),
) -> Result<(ZkCapsulePcsSourceCommitment, ZkCapsulePcsSourceProverState), ZkCapsulePcsError> {
    zk_capsule_pcs_commit_fresh_with_hash(state, rng, ProofNodeHashVersion::FeedForward)
}

/// Commit with the node mode selected by the authenticated authorization version.
pub fn zk_capsule_pcs_commit_fresh_with_hash(
    state: &[Block128],
    rng: &mut (impl CryptoRng + RngCore + ?Sized),
    hash_version: ProofNodeHashVersion,
) -> Result<(ZkCapsulePcsSourceCommitment, ZkCapsulePcsSourceProverState), ZkCapsulePcsError> {
    if state.len() != AFFINE_STATE_LEN {
        return Err(ZkCapsulePcsError::StateLength {
            expected: AFFINE_STATE_LEN,
            actual: state.len(),
        });
    }

    let mut bank = Zeroizing::new(Vec::with_capacity(AFFINE_CODE_MESSAGE_LEN));
    bank.extend_from_slice(state);
    bank.extend((AFFINE_STATE_LEN..AFFINE_CODE_MESSAGE_LEN).map(|_| draw_fresh_field(rng)));
    let companion = Zeroizing::new(
        (0..AFFINE_CODE_MESSAGE_LEN)
            .map(|_| draw_fresh_wide_field(rng))
            .collect(),
    );
    commit_prepared_messages(bank, companion, hash_version)
}

/// Deterministic raw-message entry point retained only for algebra/path unit
/// fixtures.  Production builds expose only [`zk_capsule_pcs_commit_fresh`].
#[cfg(test)]
fn zk_capsule_pcs_commit_for_test(
    bank: Vec<Block128>,
    companion: Vec<Block256>,
) -> Result<(ZkCapsulePcsSourceCommitment, ZkCapsulePcsSourceProverState), ZkCapsulePcsError> {
    commit_prepared_messages(
        Zeroizing::new(bank),
        Zeroizing::new(companion),
        ProofNodeHashVersion::FeedForward,
    )
}

/// Execute the Owner prover exactly once while this function owns the source
/// state, then seal the attempt into an opaque Owner-bound typestate.
///
/// The callback is `FnOnce` and the raw bank borrow cannot escape through the
/// returned typestate. If it returns an error, the complete source attempt is
/// dropped and all field-vector material is zeroized; retrying requires a new
/// fresh commitment.
pub fn zk_capsule_pcs_bind_owner<T, E>(
    source: ZkCapsulePcsSourceProverState,
    prove_owner_once: impl FnOnce(&[Block128]) -> Result<T, E>,
) -> Result<(T, ZkCapsulePcsOwnerBoundProverState), E> {
    let owner_output = prove_owner_once(&source.bank)?;
    let ZkCapsulePcsSourceProverState {
        bank,
        companion,
        bank_codeword,
        companion_codeword,
        source_tree,
    } = source;
    Ok((
        owner_output,
        ZkCapsulePcsOwnerBoundProverState {
            bank,
            companion,
            bank_codeword,
            companion_codeword,
            source_tree,
        },
    ))
}

/// Consume the one-shot Owner-bound state and bind the transparent Phase-A
/// relation to the bank claim established by that Owner invocation.
///
/// On mismatch the Owner-bound state is consumed and all attempt-local
/// messages are dropped. The only scalar released on success is the companion
/// contraction `sigma`; the checked Owner claim is not duplicated.
///
/// ```compile_fail
/// use noid_core::Block128;
/// use noid_fri_binius::{zk_capsule_pcs_bind_phase_a, ZkCapsulePcsSourceProverState};
///
/// fn cannot_skip_owner(source: ZkCapsulePcsSourceProverState, relation: &[Block128]) {
///     let _ = zk_capsule_pcs_bind_phase_a(source, relation, Block128::from(0u128));
/// }
/// ```
pub fn zk_capsule_pcs_bind_phase_a(
    owner_bound: ZkCapsulePcsOwnerBoundProverState,
    relation: &[Block256],
    expected_owner_bank_claim: Block256,
) -> Result<
    (
        ZkCapsulePcsPhaseABinding,
        ZkCapsulePcsPhaseABoundProverState,
    ),
    ZkCapsulePcsError,
> {
    let claims = phase_a_relation_claims(&owner_bound.bank, &owner_bound.companion, relation)?;
    if claims.bank != expected_owner_bank_claim {
        return Err(ZkCapsulePcsError::OwnerBankClaimMismatch {
            expected: expected_owner_bank_claim,
            actual: claims.bank,
        });
    }

    let ZkCapsulePcsOwnerBoundProverState {
        bank,
        companion,
        bank_codeword,
        companion_codeword,
        source_tree,
    } = owner_bound;
    Ok((
        ZkCapsulePcsPhaseABinding {
            companion_claim: claims.companion,
        },
        ZkCapsulePcsPhaseABoundProverState {
            bank,
            companion,
            relation: Zeroizing::new(relation.to_vec()),
            bank_codeword,
            companion_codeword,
            source_tree,
        },
    ))
}

/// Consume the bound state and build Phase A while deriving each challenge
/// only after its corresponding two-field round message exists.
///
/// `gamma` is admitted only after the caller has received and transcript-bound
/// `sigma`. The returned complete state contains one `U_gamma` materialization;
/// the raw bank, companion, and relation messages are zeroized on return.
pub fn zk_capsule_pcs_prove_phase_a(
    bound: ZkCapsulePcsPhaseABoundProverState,
    gamma: Block256,
    challenge_after_round: impl FnMut(usize, ZkPhaseARoundProof<Block256>) -> Block256,
) -> Result<
    (
        ZkPhaseAProverOutput<Block256>,
        ZkCapsulePcsPhaseACompleteProverState,
    ),
    ZkCapsulePcsError,
> {
    require_gamma(gamma)?;
    let output = prove_phase_a_adaptive(
        &bound.bank,
        &bound.companion,
        &bound.relation,
        gamma,
        challenge_after_round,
    )?;
    let virtual_oracle = Zeroizing::new(phase_a_virtual_oracle(
        &bound.bank,
        &bound.companion,
        gamma,
    )?);
    let complete = ZkCapsulePcsPhaseACompleteProverState {
        virtual_oracle,
        gamma,
        terminal_point: output.terminal_point,
        terminal_oracle_value: output.terminal_oracle_value,
        bank_codeword: bound.bank_codeword,
        companion_codeword: bound.companion_codeword,
        source_tree: bound.source_tree,
    };
    Ok((output, complete))
}

/// Link the exact Phase-A terminal value to the public `upper[256]` table and
/// admit the consumed state to Phase B.
pub fn zk_capsule_pcs_link_phase_b(
    complete: ZkCapsulePcsPhaseACompleteProverState,
    linked_terminal_value: Block256,
) -> Result<(ZkCapsulePcsPhaseBLink, ZkCapsulePcsPhaseBReadyProverState), ZkCapsulePcsError> {
    let low_point: [Block256; PHASE_B_LOW_VARS] =
        std::array::from_fn(|index| complete.terminal_point[index]);
    let high_point: [Block256; PHASE_B_HIGH_VARS] =
        std::array::from_fn(|index| complete.terminal_point[PHASE_B_LOW_VARS + index]);
    let oracle: &[Block256; AFFINE_CODE_MESSAGE_LEN] = complete
        .virtual_oracle
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| unreachable!("Phase A preserves the 2048-cell virtual oracle"));
    let upper = contract_high3_for_each_low8(oracle, &high_point);
    let expected = evaluate_upper_at_low8(&upper, &low_point);
    if linked_terminal_value != complete.terminal_oracle_value || linked_terminal_value != expected
    {
        return Err(ZkCapsulePcsError::PhaseATerminalMismatch {
            expected,
            actual: linked_terminal_value,
        });
    }

    Ok((
        ZkCapsulePcsPhaseBLink { upper },
        ZkCapsulePcsPhaseBReadyProverState {
            virtual_oracle: complete.virtual_oracle,
            gamma: complete.gamma,
            bank_codeword: complete.bank_codeword,
            companion_codeword: complete.companion_codeword,
            source_tree: complete.source_tree,
        },
    ))
}

/// Build and commit the mid codeword after `beta[0..3]` has been derived from
/// the already-linked Phase-B `upper[256]` table.
///
/// Production accepts only [`ZkCapsulePcsPhaseBReadyProverState`]; neither a
/// raw source state nor a caller-supplied `gamma` can enter this transition.
///
/// ```compile_fail
/// use noid_core::Block128;
/// use noid_fri_binius::{zk_capsule_pcs_commit_mid, ZkCapsulePcsSourceProverState};
///
/// fn cannot_skip_phase_a(source: ZkCapsulePcsSourceProverState) {
///     let _ = zk_capsule_pcs_commit_mid(source, [Block128::from(0u128); 3]);
/// }
/// ```
pub fn zk_capsule_pcs_commit_mid(
    ready: ZkCapsulePcsPhaseBReadyProverState,
    beta_source: [Block256; SOURCE_STANDARD_FOLDS],
) -> Result<(ZkCapsulePcsMidCommitment, ZkCapsulePcsMidProverState), ZkCapsulePcsError> {
    require_gamma(ready.gamma)?;
    let code = ZkAffineLchCode::selected()?;
    let ZkCapsulePcsPhaseBReadyProverState {
        mut virtual_oracle,
        gamma: _,
        bank_codeword,
        companion_codeword,
        source_tree,
    } = ready;
    for challenge in beta_source {
        fold_lowest_zeroizing(&mut virtual_oracle, challenge);
    }
    let mid_codeword = Zeroizing::new(
        code.encode_extension_after_low_folds(&virtual_oracle, SOURCE_STANDARD_FOLDS)?,
    );
    let mid_tree = build_mid_tree(&mid_codeword, source_tree.hash_version);
    let commitment = ZkCapsulePcsMidCommitment {
        cap: MerkleCap {
            hashes: mid_tree.get_layer_at_depth(ZK_CAPSULE_PCS_MID_CAP_DEPTH),
        },
    };
    Ok((
        commitment,
        ZkCapsulePcsMidProverState {
            mid_message: virtual_oracle,
            mid_codeword,
            mid_tree,
            bank_codeword,
            companion_codeword,
            source_tree,
        },
    ))
}

/// Test-only bridge for low-level path and tamper fixtures. Production has no
/// source-to-mid transition: it must complete and link Phase A first.
#[cfg(test)]
fn zk_capsule_pcs_commit_mid_for_test(
    source: ZkCapsulePcsSourceProverState,
    gamma: Block256,
    beta_source: [Block256; SOURCE_STANDARD_FOLDS],
) -> Result<(ZkCapsulePcsMidCommitment, ZkCapsulePcsMidProverState), ZkCapsulePcsError> {
    require_gamma(gamma)?;
    let virtual_oracle = Zeroizing::new(phase_a_virtual_oracle(
        &source.bank,
        &source.companion,
        gamma,
    )?);
    let ready = ZkCapsulePcsPhaseBReadyProverState {
        virtual_oracle,
        gamma,
        bank_codeword: source.bank_codeword,
        companion_codeword: source.companion_codeword,
        source_tree: source.source_tree,
    };
    zk_capsule_pcs_commit_mid(ready, beta_source)
}

/// Consume the mid prover state and reveal the common 16-coefficient tail
/// after `beta[3..7]`.  The returned state retains only what query opening
/// still needs.
pub fn zk_capsule_pcs_reveal_tail(
    mut mid: ZkCapsulePcsMidProverState,
    beta_mid: [Block256; MID_STANDARD_FOLDS],
) -> Result<ZkCapsulePcsTailProverState, ZkCapsulePcsError> {
    for challenge in beta_mid {
        fold_lowest_zeroizing(&mut mid.mid_message, challenge);
    }
    let coefficients: [Block256; TAIL_SYMBOLS] = mid
        .mid_message
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| unreachable!("seven low folds leave tail16"));
    Ok(ZkCapsulePcsTailProverState {
        tail: ZkCapsulePcsTailReveal { coefficients },
        mid_codeword: mid.mid_codeword,
        mid_tree: mid.mid_tree,
        bank_codeword: mid.bank_codeword,
        companion_codeword: mid.companion_codeword,
        source_tree: mid.source_tree,
    })
}

/// Open exactly 65 already transcript-derived source-leaf queries. Repeated
/// queries retain query-major symbol slots while the canonical multiproofs
/// deduplicate authenticated leaves.
pub fn zk_capsule_pcs_open(
    tail_state: ZkCapsulePcsTailProverState,
    queries: &[usize],
) -> Result<ZkCapsulePcsOpening, ZkCapsulePcsError> {
    preflight_queries(queries)?;
    let code = ZkAffineLchCode::selected()?;
    let mut source_joint_symbols = Vec::with_capacity(ZK_CAPSULE_PCS_SOURCE_SYMBOLS);
    let mut mid_symbols = Vec::with_capacity(ZK_CAPSULE_PCS_MID_SYMBOLS);
    let mut source_leaves = Vec::with_capacity(ZK_CAPSULE_PCS_QUERY_COUNT);
    let mut mid_leaves = Vec::with_capacity(ZK_CAPSULE_PCS_QUERY_COUNT);

    for &query in queries {
        let mapping = map_source_query_leaf(query)?;
        source_leaves.push(mapping.source_leaf_index);
        source_joint_symbols.extend_from_slice(&build_fold_normal_joint_source_leaf(
            &code,
            &tail_state.bank_codeword,
            &tail_state.companion_codeword,
            mapping.source_leaf_index,
        )?);
        mid_leaves.push(mapping.mid_leaf_index);
        mid_symbols.extend_from_slice(&build_fold_normal_mid_leaf(
            &code,
            &tail_state.mid_codeword,
            mapping.mid_leaf_index,
        )?);
    }

    let source_batch = build_source_batched_merkle_proof_to_cap(
        &tail_state.source_tree,
        &source_leaves,
        ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH,
        ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH,
        CommitmentHashBackend::Arithmetic,
        &VersionedCapsuleNodeHasher(tail_state.source_tree.hash_version),
    );
    let mid_batch = build_source_batched_merkle_proof_to_cap(
        &tail_state.mid_tree,
        &mid_leaves,
        ZK_CAPSULE_PCS_MID_TREE_DEPTH,
        ZK_CAPSULE_PCS_MID_CAP_DEPTH,
        CommitmentHashBackend::Arithmetic,
        &VersionedCapsuleNodeHasher(tail_state.source_tree.hash_version),
    );
    Ok(ZkCapsulePcsOpening {
        source_joint_symbols,
        source_batch,
        mid_symbols,
        mid_batch,
    })
}

/// Verify the selected algebraic opening.  Challenge derivation and the
/// `beta[7]` upper/tail link remain outside this transcript-free PCS layer.
pub fn zk_capsule_pcs_verify(
    source_commitment: &ZkCapsulePcsSourceCommitment,
    mid_commitment: &ZkCapsulePcsMidCommitment,
    tail: &ZkCapsulePcsTailReveal,
    gamma: Block256,
    beta_source: [Block256; SOURCE_STANDARD_FOLDS],
    beta_mid: [Block256; MID_STANDARD_FOLDS],
    queries: &[usize],
    opening: &ZkCapsulePcsOpening,
) -> Result<ZkCapsulePcsVerified, ZkCapsulePcsError> {
    zk_capsule_pcs_verify_with_hash(
        source_commitment,
        mid_commitment,
        tail,
        gamma,
        beta_source,
        beta_mid,
        queries,
        opening,
        ProofNodeHashVersion::FeedForward,
    )
}

/// Verify under a trusted profile. A proof cannot select or downgrade its mode.
pub fn zk_capsule_pcs_verify_with_hash(
    source_commitment: &ZkCapsulePcsSourceCommitment,
    mid_commitment: &ZkCapsulePcsMidCommitment,
    tail: &ZkCapsulePcsTailReveal,
    gamma: Block256,
    beta_source: [Block256; SOURCE_STANDARD_FOLDS],
    beta_mid: [Block256; MID_STANDARD_FOLDS],
    queries: &[usize],
    opening: &ZkCapsulePcsOpening,
    hash_version: ProofNodeHashVersion,
) -> Result<ZkCapsulePcsVerified, ZkCapsulePcsError> {
    require_gamma(gamma)?;
    preflight_queries(queries)?;
    if source_commitment.cap.hashes.len() != ZK_CAPSULE_PCS_SOURCE_CAP_HASHES {
        return Err(ZkCapsulePcsError::SourceCapCount {
            expected: ZK_CAPSULE_PCS_SOURCE_CAP_HASHES,
            actual: source_commitment.cap.hashes.len(),
        });
    }
    if mid_commitment.cap.hashes.len() != ZK_CAPSULE_PCS_MID_CAP_HASHES {
        return Err(ZkCapsulePcsError::MidCapCount {
            expected: ZK_CAPSULE_PCS_MID_CAP_HASHES,
            actual: mid_commitment.cap.hashes.len(),
        });
    }
    if opening.source_joint_symbols.len() != ZK_CAPSULE_PCS_SOURCE_SYMBOLS {
        return Err(ZkCapsulePcsError::SourceSymbolCount {
            expected: ZK_CAPSULE_PCS_SOURCE_SYMBOLS,
            actual: opening.source_joint_symbols.len(),
        });
    }
    if opening.mid_symbols.len() != ZK_CAPSULE_PCS_MID_SYMBOLS {
        return Err(ZkCapsulePcsError::MidSymbolCount {
            expected: ZK_CAPSULE_PCS_MID_SYMBOLS,
            actual: opening.mid_symbols.len(),
        });
    }

    let code = ZkAffineLchCode::selected()?;
    let source_hiding_rank = certify_source_query_hiding_rank(&code, queries)?;
    let distinct_leaves = queries
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let expected_rank = distinct_leaves.len() * (1 << SOURCE_STANDARD_FOLDS);
    if source_hiding_rank.certified_rank != expected_rank
        || source_hiding_rank.distinct_query_count != expected_rank
        || source_hiding_rank.independent_coeff_len != AFFINE_RANK_RANDOM_BLOCK_LEN
    {
        return Err(ZkCapsulePcsError::HidingRankMismatch {
            expected: expected_rank,
            actual: source_hiding_rank.certified_rank,
        });
    }

    let tail_codeword = code.encode_extension_after_low_folds(
        &tail.coefficients,
        SOURCE_STANDARD_FOLDS + MID_STANDARD_FOLDS,
    )?;
    let mut source_leaves = Vec::with_capacity(ZK_CAPSULE_PCS_QUERY_COUNT);
    let mut source_hashes = Vec::with_capacity(ZK_CAPSULE_PCS_QUERY_COUNT);
    let mut mid_leaves = Vec::with_capacity(ZK_CAPSULE_PCS_QUERY_COUNT);
    let mut mid_hashes = Vec::with_capacity(ZK_CAPSULE_PCS_QUERY_COUNT);

    for (query_index, &query) in queries.iter().enumerate() {
        let mapping = map_source_query_leaf(query)?;
        if mapping.source_tree_roundtrip() != query
            || mapping.source_from_mid_roundtrip() != query
            || mapping.mid_tree_roundtrip() != mapping.mid_leaf_index
        {
            return Err(ZkCapsulePcsError::QueryMapping { query_index });
        }
        let source_start = query_index * JOINT_SOURCE_LEAF_SYMBOLS;
        let source_leaf: &[Block128; JOINT_SOURCE_LEAF_SYMBOLS] = opening.source_joint_symbols
            [source_start..source_start + JOINT_SOURCE_LEAF_SYMBOLS]
            .try_into()
            .expect("source shape preflighted");
        source_leaves.push(mapping.source_leaf_index);
        source_hashes.push(capsule_leaf_hash_mixed(source_leaf));
        let source_folded = fold_normal_joint_source_leaf(source_leaf, gamma, &beta_source);

        let mid_start = query_index * (1 << MID_STANDARD_FOLDS);
        let mid_leaf: &[Block256; 1 << MID_STANDARD_FOLDS] = opening.mid_symbols
            [mid_start..mid_start + (1 << MID_STANDARD_FOLDS)]
            .try_into()
            .expect("mid shape preflighted");
        if fold_normal_mid_raw_member(
            &code,
            mid_leaf,
            mapping.mid_leaf_index,
            mapping.mid_member_index,
        )? != source_folded
        {
            return Err(ZkCapsulePcsError::SourceToMidMismatch { query_index });
        }
        mid_leaves.push(mapping.mid_leaf_index);
        mid_hashes.push(capsule_leaf_hash_wide(mid_leaf));
        let mid_folded = fold_normal_mid_leaf(mid_leaf, &beta_mid);
        if tail_codeword[mapping.mid_leaf_index] != mid_folded {
            return Err(ZkCapsulePcsError::MidToTailMismatch { query_index });
        }
    }

    verify_source_batched_merkle_proof_to_cap(
        &source_commitment.cap.hashes,
        ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH,
        &opening.source_batch,
        ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH,
        &source_leaves,
        &source_hashes,
        CommitmentHashBackend::Arithmetic,
        &VersionedCapsuleNodeHasher(hash_version),
    )
    .map_err(ZkCapsulePcsError::SourceMerkle)?;
    verify_source_batched_merkle_proof_to_cap(
        &mid_commitment.cap.hashes,
        ZK_CAPSULE_PCS_MID_CAP_DEPTH,
        &opening.mid_batch,
        ZK_CAPSULE_PCS_MID_TREE_DEPTH,
        &mid_leaves,
        &mid_hashes,
        CommitmentHashBackend::Arithmetic,
        &VersionedCapsuleNodeHasher(hash_version),
    )
    .map_err(ZkCapsulePcsError::MidMerkle)?;

    Ok(ZkCapsulePcsVerified { source_hiding_rank })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::CapsuleNodeHasher;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    fn elem(index: usize, domain: u128, salt: u128) -> Block128 {
        Block128::from(
            domain
                .wrapping_mul(index as u128 + 1)
                .rotate_left(((19 * index + 7) % 127) as u32)
                ^ salt.rotate_left(((13 * index + 3) % 127) as u32)
                ^ (index as u128 + 11).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        )
    }

    fn message(domain: u128, salt: u128) -> Vec<Block128> {
        (0..AFFINE_CODE_MESSAGE_LEN)
            .map(|index| elem(index, domain, salt))
            .collect()
    }

    fn wide(index: usize, domain: u128, salt: u128) -> Block256 {
        Block256::new(
            elem(index, domain, salt),
            elem(index + 10_000, domain ^ 0xC1_0256, salt.rotate_left(17)),
        )
    }

    fn bank_claim(bank: &[Block128], relation: &[Block256]) -> Block256 {
        bank.iter()
            .zip(relation)
            .fold(Block256::ZERO, |sum, (&bank, &weight)| {
                sum + Block256::from(bank) * weight
            })
    }

    fn exact_max_batched_siblings(tree_depth: usize, cap_count: usize, queries: usize) -> usize {
        let mut tree = vec![vec![0usize; 2]; tree_depth + 1];
        for depth in 1..=tree_depth {
            let half = 1usize << (depth - 1);
            let mut current = vec![0usize; 2 * half + 1];
            for selected in 1..=2 * half {
                let mut best = 0;
                let left_min = selected.saturating_sub(half);
                let left_max = selected.min(half);
                for left in left_min..=left_max {
                    let right = selected - left;
                    let exposed_sibling = usize::from((left == 0) != (right == 0));
                    best =
                        best.max(tree[depth - 1][left] + tree[depth - 1][right] + exposed_sibling);
                }
                current[selected] = best;
            }
            tree[depth] = current;
        }

        let unreachable = usize::MAX;
        let mut forest = vec![unreachable; queries + 1];
        forest[0] = 0;
        for _ in 0..cap_count {
            let previous = forest;
            forest = vec![unreachable; queries + 1];
            for selected in 0..=queries {
                let in_tree_max = selected.min(1usize << tree_depth);
                forest[selected] = (0..=in_tree_max)
                    .filter_map(|in_tree| {
                        let prior = previous[selected - in_tree];
                        (prior != unreachable).then(|| prior + tree[tree_depth][in_tree])
                    })
                    .max()
                    .unwrap_or(unreachable);
            }
        }
        forest[queries]
    }

    fn worst_queries() -> Vec<usize> {
        let mut queries = Vec::with_capacity(ZK_CAPSULE_PCS_QUERY_COUNT);
        for cap in 0..ZK_CAPSULE_PCS_SOURCE_CAP_HASHES {
            let base = cap << ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH;
            for mid_leaf_within_cap in (0..64).step_by(8) {
                queries.push(base | (mid_leaf_within_cap << MID_STANDARD_FOLDS));
            }
        }
        queries.push(4 << MID_STANDARD_FOLDS);
        assert_eq!(queries.len(), ZK_CAPSULE_PCS_QUERY_COUNT);
        queries
    }

    struct Fixture {
        source_commitment: ZkCapsulePcsSourceCommitment,
        mid_commitment: ZkCapsulePcsMidCommitment,
        tail: ZkCapsulePcsTailReveal,
        gamma: Block256,
        beta_source: [Block256; SOURCE_STANDARD_FOLDS],
        beta_mid: [Block256; MID_STANDARD_FOLDS],
        queries: Vec<usize>,
        opening: ZkCapsulePcsOpening,
    }

    fn fixture(salt: u128, queries: Vec<usize>) -> Fixture {
        let bank = message(0xB4A9, salt ^ 0x11);
        let companion = (0..AFFINE_CODE_MESSAGE_LEN)
            .map(|index| wide(index, 0xC09A, salt ^ 0x22))
            .collect();
        let mut gamma = wide(19, 0x6A77A, salt ^ 0x33);
        if gamma == Block256::ZERO || gamma == Block256::ONE {
            gamma += Block256::from(2u128);
        }
        let beta_source = std::array::from_fn(|round| wide(round + 41, 0xBE7A_03, salt ^ 0x44));
        let beta_mid = std::array::from_fn(|round| wide(round + 61, 0xBE7A_47, salt ^ 0x55));
        let (source_commitment, source_state) =
            zk_capsule_pcs_commit_for_test(bank, companion).expect("source commit");
        let (mid_commitment, mid_state) =
            zk_capsule_pcs_commit_mid_for_test(source_state, gamma, beta_source)
                .expect("mid commit");
        let tail_state = zk_capsule_pcs_reveal_tail(mid_state, beta_mid).expect("tail reveal");
        let tail = tail_state.tail.clone();
        let opening = zk_capsule_pcs_open(tail_state, &queries).expect("query opening");
        Fixture {
            source_commitment,
            mid_commitment,
            tail,
            gamma,
            beta_source,
            beta_mid,
            queries,
            opening,
        }
    }

    fn verify(fixture: &Fixture) -> Result<ZkCapsulePcsVerified, ZkCapsulePcsError> {
        zk_capsule_pcs_verify(
            &fixture.source_commitment,
            &fixture.mid_commitment,
            &fixture.tail,
            fixture.gamma,
            fixture.beta_source,
            fixture.beta_mid,
            &fixture.queries,
            &fixture.opening,
        )
    }

    #[test]
    fn fresh_commit_requires_exact_state_without_consuming_entropy() {
        let state = message(0x57A7E, 0x11);
        let mut rng = StdRng::seed_from_u64(0xA11C_E101);
        let mut untouched = rng.clone();
        assert!(matches!(
            zk_capsule_pcs_commit_fresh(&state[..AFFINE_STATE_LEN - 1], &mut rng),
            Err(ZkCapsulePcsError::StateLength {
                expected: AFFINE_STATE_LEN,
                actual,
            }) if actual == AFFINE_STATE_LEN - 1
        ));
        assert!(matches!(
            zk_capsule_pcs_commit_fresh(&state[..AFFINE_STATE_LEN + 1], &mut rng),
            Err(ZkCapsulePcsError::StateLength {
                expected: AFFINE_STATE_LEN,
                actual,
            }) if actual == AFFINE_STATE_LEN + 1
        ));
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }

    #[test]
    fn sequential_fresh_attempts_randomize_every_private_region() {
        let full = message(0x57A7E, 0x22);
        let state = &full[..AFFINE_STATE_LEN];
        let mut rng = StdRng::seed_from_u64(0xA11C_E102);
        let (first_commitment, first) =
            zk_capsule_pcs_commit_fresh(state, &mut rng).expect("first fresh commit");
        let (second_commitment, second) =
            zk_capsule_pcs_commit_fresh(state, &mut rng).expect("second fresh commit");

        assert_eq!(&first.bank_for_test()[..AFFINE_STATE_LEN], state);
        assert_eq!(&second.bank_for_test()[..AFFINE_STATE_LEN], state);
        for range in [
            crate::zk_affine_code::AFFINE_LIBRA_MASK_START
                ..crate::zk_affine_code::AFFINE_FRESH_PADDING_START,
            crate::zk_affine_code::AFFINE_FRESH_PADDING_START
                ..crate::zk_affine_code::AFFINE_PCS_COINS_START,
            crate::zk_affine_code::AFFINE_PCS_COINS_START..AFFINE_CODE_MESSAGE_LEN,
        ] {
            assert_ne!(
                &first.bank_for_test()[range.clone()],
                &second.bank_for_test()[range]
            );
        }
        assert_ne!(&*first.companion, &*second.companion);
        assert_ne!(first_commitment, second_commitment);
    }

    #[test]
    fn consumed_attempt_retry_builds_a_new_source_commitment() {
        let full = message(0x57A7E, 0x33);
        let state = &full[..AFFINE_STATE_LEN];
        let mut rng = StdRng::seed_from_u64(0xA11C_E103);
        let (abandoned_commitment, abandoned) =
            zk_capsule_pcs_commit_fresh(state, &mut rng).expect("abandoned fresh commit");

        assert!(matches!(
            zk_capsule_pcs_commit_mid_for_test(
                abandoned,
                Block256::ZERO,
                [Block256::ZERO; SOURCE_STANDARD_FOLDS],
            ),
            Err(ZkCapsulePcsError::GammaEndpoint)
        ));

        let (retry_commitment, retry) =
            zk_capsule_pcs_commit_fresh(state, &mut rng).expect("retry fresh commit");
        assert_ne!(abandoned_commitment, retry_commitment);
        assert_eq!(&retry.bank_for_test()[..AFFINE_STATE_LEN], state);
    }

    #[test]
    fn owner_callback_failure_consumes_attempt_and_retry_is_fresh() {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct OwnerFailure;

        let full = message(0x57A7E, 0x34);
        let state = &full[..AFFINE_STATE_LEN];
        let mut rng = StdRng::seed_from_u64(0xA11C_E107);
        let (failed_commitment, failed_source) =
            zk_capsule_pcs_commit_fresh(state, &mut rng).expect("failed attempt source");
        let failed_calls = std::cell::Cell::new(0usize);
        let failed: Result<((), ZkCapsulePcsOwnerBoundProverState), OwnerFailure> =
            zk_capsule_pcs_bind_owner(failed_source, |_bank| {
                failed_calls.set(failed_calls.get() + 1);
                Err(OwnerFailure)
            });
        assert!(matches!(failed, Err(OwnerFailure)));
        assert_eq!(failed_calls.get(), 1);

        let (retry_commitment, retry_source) =
            zk_capsule_pcs_commit_fresh(state, &mut rng).expect("fresh retry source");
        assert_ne!(failed_commitment, retry_commitment);
        let retry_calls = std::cell::Cell::new(0usize);
        let (_, _owner_bound) = zk_capsule_pcs_bind_owner(retry_source, |bank| {
            retry_calls.set(retry_calls.get() + 1);
            assert_eq!(&bank[..AFFINE_STATE_LEN], state);
            Ok::<_, OwnerFailure>(())
        })
        .expect("retry Owner handoff");
        assert_eq!(retry_calls.get(), 1);
    }

    #[test]
    fn honest_production_typestate_runs_phase_a_link_and_mid_in_order() {
        let full = message(0x57A7E, 0x44);
        let state = &full[..AFFINE_STATE_LEN];
        let relation: [Block256; AFFINE_CODE_MESSAGE_LEN] =
            std::array::from_fn(|index| wide(index, 0x7E1A_710, 0xA11C_E104));
        let mut rng = StdRng::seed_from_u64(0xA11C_E104);
        let (source_commitment, source) =
            zk_capsule_pcs_commit_fresh(state, &mut rng).expect("fresh source");
        let owner_callback_count = std::cell::Cell::new(0usize);
        let (owner_bank_claim, owner_bound) = zk_capsule_pcs_bind_owner(source, |bank| {
            owner_callback_count.set(owner_callback_count.get() + 1);
            Ok::<_, ()>(bank_claim(bank, &relation))
        })
        .expect("one-shot Owner handoff");
        assert_eq!(owner_callback_count.get(), 1);
        let (binding, bound) =
            zk_capsule_pcs_bind_phase_a(owner_bound, &relation, owner_bank_claim)
                .expect("bind Phase A");

        let mut gamma = wide(17, 0x6A77A, 0xA11C_E104);
        if gamma == Block256::ZERO || gamma == Block256::ONE {
            gamma += Block256::from(2u128);
        }
        let challenges: [Block256; PHASE_A_VARS] =
            std::array::from_fn(|round| wide(round + 31, 0xC4A1_1E6E, 0xA11C_E104));
        let mut observed = Vec::new();
        let (phase_a, complete) =
            zk_capsule_pcs_prove_phase_a(bound, gamma, |round, round_proof| {
                assert_eq!(round, observed.len());
                observed.push(round_proof);
                challenges[round]
            })
            .expect("adaptive Phase A");
        assert_eq!(observed.as_slice(), phase_a.proof.rounds.as_slice());
        assert_eq!(binding.companion_claim, phase_a.relation_claims.companion);
        assert_eq!(owner_bank_claim, phase_a.relation_claims.bank);

        let terminal = phase_a.terminal_oracle_value;
        let terminal_point = phase_a.terminal_point;
        let (phase_b_link, ready) =
            zk_capsule_pcs_link_phase_b(complete, terminal).expect("link Phase B");
        let low: [Block256; PHASE_B_LOW_VARS] = std::array::from_fn(|index| terminal_point[index]);
        assert_eq!(evaluate_upper_at_low8(&phase_b_link.upper, &low), terminal);

        let beta_source = std::array::from_fn(|round| wide(round + 41, 0xBE7A_03, 0xA11C_E104));
        let beta_mid = std::array::from_fn(|round| wide(round + 61, 0xBE7A_47, 0xA11C_E104));
        let (mid_commitment, mid) =
            zk_capsule_pcs_commit_mid(ready, beta_source).expect("typed mid commit");
        let tail_state = zk_capsule_pcs_reveal_tail(mid, beta_mid).expect("tail reveal");
        let tail = tail_state.tail.clone();
        let queries = worst_queries();
        let opening = zk_capsule_pcs_open(tail_state, &queries).expect("query opening");
        zk_capsule_pcs_verify(
            &source_commitment,
            &mid_commitment,
            &tail,
            gamma,
            beta_source,
            beta_mid,
            &queries,
            &opening,
        )
        .expect("typed PCS verifies");

        let _only_phase_b_ready: fn(
            ZkCapsulePcsPhaseBReadyProverState,
            [Block256; SOURCE_STANDARD_FOLDS],
        ) -> Result<
            (ZkCapsulePcsMidCommitment, ZkCapsulePcsMidProverState),
            ZkCapsulePcsError,
        > = zk_capsule_pcs_commit_mid;
    }

    #[test]
    fn owner_bank_claim_mismatch_consumes_the_attempt_atomically() {
        let full = message(0x57A7E, 0x55);
        let state = &full[..AFFINE_STATE_LEN];
        let relation: [Block256; AFFINE_CODE_MESSAGE_LEN] =
            std::array::from_fn(|index| wide(index, 0x7E1A_710, 0xA11C_E105));
        let mut rng = StdRng::seed_from_u64(0xA11C_E105);
        let (failed_commitment, source) =
            zk_capsule_pcs_commit_fresh(state, &mut rng).expect("failed attempt source");
        let (actual, owner_bound) =
            zk_capsule_pcs_bind_owner(source, |bank| Ok::<_, ()>(bank_claim(bank, &relation)))
                .expect("one-shot Owner handoff");
        let expected = actual + Block256::ONE;
        assert!(matches!(
            zk_capsule_pcs_bind_phase_a(owner_bound, &relation, expected),
            Err(ZkCapsulePcsError::OwnerBankClaimMismatch {
                expected: error_expected,
                actual: error_actual,
            }) if error_expected == expected && error_actual == actual
        ));

        let (retry_commitment, retry) =
            zk_capsule_pcs_commit_fresh(state, &mut rng).expect("fresh retry source");
        assert_ne!(failed_commitment, retry_commitment);
        assert_eq!(&retry.bank_for_test()[..AFFINE_STATE_LEN], state);
    }

    #[test]
    fn phase_b_link_rejects_a_terminal_value_not_produced_by_phase_a() {
        let full = message(0x57A7E, 0x66);
        let state = &full[..AFFINE_STATE_LEN];
        let relation: [Block256; AFFINE_CODE_MESSAGE_LEN] =
            std::array::from_fn(|index| wide(index, 0x7E1A_710, 0xA11C_E106));
        let mut rng = StdRng::seed_from_u64(0xA11C_E106);
        let (_, source) = zk_capsule_pcs_commit_fresh(state, &mut rng).expect("fresh source");
        let (owner_bank_claim, owner_bound) =
            zk_capsule_pcs_bind_owner(source, |bank| Ok::<_, ()>(bank_claim(bank, &relation)))
                .expect("one-shot Owner handoff");
        let (_, bound) = zk_capsule_pcs_bind_phase_a(owner_bound, &relation, owner_bank_claim)
            .expect("bind Phase A");
        let mut gamma = wide(17, 0x6A77A, 0xA11C_E106);
        if gamma == Block256::ZERO || gamma == Block256::ONE {
            gamma += Block256::from(2u128);
        }
        let challenges: [Block256; PHASE_A_VARS] =
            std::array::from_fn(|round| wide(round + 31, 0xC4A1_1E6E, 0xA11C_E106));
        let (phase_a, complete) =
            zk_capsule_pcs_prove_phase_a(bound, gamma, |round, _| challenges[round])
                .expect("adaptive Phase A");
        let bad_terminal = phase_a.terminal_oracle_value + Block256::ONE;
        assert!(matches!(
            zk_capsule_pcs_link_phase_b(complete, bad_terminal),
            Err(ZkCapsulePcsError::PhaseATerminalMismatch { expected, actual })
                if expected == phase_a.terminal_oracle_value && actual == bad_terminal
        ));
    }

    #[test]
    fn selected_pcs_honest_opening_and_digest_lane_roundtrip() {
        let fixture = fixture(0xA11C_E001, worst_queries());
        let verified = verify(&fixture).expect("honest selected PCS opening");
        assert_eq!(verified.source_hiding_rank.certified_rank, 520);
        assert_eq!(verified.source_hiding_rank.distinct_query_count, 520);
        assert_eq!(
            fixture.source_commitment.transcript_lanes().unwrap().len(),
            16
        );
        assert_eq!(fixture.mid_commitment.transcript_lanes().unwrap().len(), 16);

        for digest in fixture
            .source_commitment
            .cap
            .hashes
            .iter()
            .chain(&fixture.mid_commitment.cap.hashes)
        {
            assert_eq!(
                tower_lanes_to_flat_digest(flat_digest_to_tower_lanes(digest)),
                *digest
            );
        }
    }

    #[test]
    fn canonical_batched_proofs_hit_exact_worst_counts_and_bytes() {
        assert_eq!(
            exact_max_batched_siblings(
                ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
                ZK_CAPSULE_PCS_SOURCE_CAP_HASHES,
                ZK_CAPSULE_PCS_QUERY_COUNT,
            ),
            ZK_CAPSULE_PCS_WORST_SOURCE_SIBLINGS,
        );
        assert_eq!(
            exact_max_batched_siblings(
                ZK_CAPSULE_PCS_MID_PATH_DEPTH,
                ZK_CAPSULE_PCS_MID_CAP_HASHES,
                ZK_CAPSULE_PCS_QUERY_COUNT,
            ),
            ZK_CAPSULE_PCS_WORST_MID_SIBLINGS,
        );
        let fixture = fixture(0xA11C_E002, worst_queries());
        assert_eq!(fixture.opening.source_batch.siblings.len(), 453);
        assert_eq!(fixture.opening.mid_batch.siblings.len(), 193);
        assert_eq!(fixture.opening.source_joint_symbols.len(), 1_560);
        assert_eq!(fixture.opening.mid_symbols.len(), 1_040);
        assert_eq!(
            fixture.opening.byte_len(),
            ZK_CAPSULE_PCS_WORST_OPENING_BYTES
        );
        assert_eq!(fixture.source_commitment.byte_len(), 256);
        assert_eq!(fixture.mid_commitment.byte_len(), 256);
        assert_eq!(fixture.tail.byte_len(), 512);
        assert_eq!(
            fixture.opening.byte_len()
                + fixture.source_commitment.byte_len()
                + fixture.mid_commitment.byte_len()
                + fixture.tail.byte_len(),
            ZK_CAPSULE_PCS_WORST_TOTAL_BYTES
        );
        verify(&fixture).expect("worst-pattern proof verifies");
    }

    #[test]
    fn repeated_queries_are_deduplicated_only_in_paths_and_rank() {
        let queries = vec![0x12A5; ZK_CAPSULE_PCS_QUERY_COUNT];
        let fixture = fixture(0xA11C_E003, queries);
        assert_eq!(fixture.opening.source_batch.siblings.len(), 10);
        assert_eq!(fixture.opening.mid_batch.siblings.len(), 6);
        assert_eq!(fixture.opening.source_joint_symbols.len(), 1_560);
        assert_eq!(fixture.opening.mid_symbols.len(), 1_040);
        let verified = verify(&fixture).expect("repeated-query proof verifies");
        assert_eq!(verified.source_hiding_rank.distinct_query_count, 8);
        assert_eq!(verified.source_hiding_rank.certified_rank, 8);

        let mut inconsistent = fixture.opening.clone();
        inconsistent.source_joint_symbols[JOINT_SOURCE_LEAF_SYMBOLS] += Block128::ONE;
        assert!(zk_capsule_pcs_verify(
            &fixture.source_commitment,
            &fixture.mid_commitment,
            &fixture.tail,
            fixture.gamma,
            fixture.beta_source,
            fixture.beta_mid,
            &fixture.queries,
            &inconsistent,
        )
        .is_err());
    }

    #[test]
    fn every_commitment_algebra_and_path_family_tamper_rejects() {
        let fixture = fixture(0xA11C_E004, worst_queries());
        assert!(verify(&fixture).is_ok());

        let check = |source: &ZkCapsulePcsSourceCommitment,
                     mid: &ZkCapsulePcsMidCommitment,
                     tail: &ZkCapsulePcsTailReveal,
                     gamma: Block256,
                     beta_source: [Block256; SOURCE_STANDARD_FOLDS],
                     beta_mid: [Block256; MID_STANDARD_FOLDS],
                     queries: &[usize],
                     opening: &ZkCapsulePcsOpening,
                     name: &str| {
            assert!(
                zk_capsule_pcs_verify(
                    source,
                    mid,
                    tail,
                    gamma,
                    beta_source,
                    beta_mid,
                    queries,
                    opening,
                )
                .is_err(),
                "accepted {name} tamper"
            );
        };

        let mut source = fixture.source_commitment.clone();
        source.cap.hashes[7][0] ^= 1;
        check(
            &source,
            &fixture.mid_commitment,
            &fixture.tail,
            fixture.gamma,
            fixture.beta_source,
            fixture.beta_mid,
            &fixture.queries,
            &fixture.opening,
            "source cap",
        );

        let mut mid = fixture.mid_commitment.clone();
        mid.cap.hashes[1][3] ^= 1;
        check(
            &fixture.source_commitment,
            &mid,
            &fixture.tail,
            fixture.gamma,
            fixture.beta_source,
            fixture.beta_mid,
            &fixture.queries,
            &fixture.opening,
            "mid cap",
        );

        let mut tail = fixture.tail.clone();
        tail.coefficients[9] += Block256::ONE;
        check(
            &fixture.source_commitment,
            &fixture.mid_commitment,
            &tail,
            fixture.gamma,
            fixture.beta_source,
            fixture.beta_mid,
            &fixture.queries,
            &fixture.opening,
            "tail",
        );

        let mut opening = fixture.opening.clone();
        opening.source_joint_symbols[13] += Block128::ONE;
        check(
            &fixture.source_commitment,
            &fixture.mid_commitment,
            &fixture.tail,
            fixture.gamma,
            fixture.beta_source,
            fixture.beta_mid,
            &fixture.queries,
            &opening,
            "source symbols",
        );

        let mut opening = fixture.opening.clone();
        opening.mid_symbols[11] += Block256::ONE;
        check(
            &fixture.source_commitment,
            &fixture.mid_commitment,
            &fixture.tail,
            fixture.gamma,
            fixture.beta_source,
            fixture.beta_mid,
            &fixture.queries,
            &opening,
            "mid symbols",
        );

        let mut opening = fixture.opening.clone();
        opening.source_batch.siblings[17][5] ^= 1;
        check(
            &fixture.source_commitment,
            &fixture.mid_commitment,
            &fixture.tail,
            fixture.gamma,
            fixture.beta_source,
            fixture.beta_mid,
            &fixture.queries,
            &opening,
            "source sibling",
        );

        let mut opening = fixture.opening.clone();
        opening.mid_batch.siblings[17][5] ^= 1;
        check(
            &fixture.source_commitment,
            &fixture.mid_commitment,
            &fixture.tail,
            fixture.gamma,
            fixture.beta_source,
            fixture.beta_mid,
            &fixture.queries,
            &opening,
            "mid sibling",
        );

        let mut beta_source = fixture.beta_source;
        beta_source[1] += Block256::ONE;
        check(
            &fixture.source_commitment,
            &fixture.mid_commitment,
            &fixture.tail,
            fixture.gamma,
            beta_source,
            fixture.beta_mid,
            &fixture.queries,
            &fixture.opening,
            "source beta",
        );

        let mut beta_mid = fixture.beta_mid;
        beta_mid[2] += Block256::ONE;
        check(
            &fixture.source_commitment,
            &fixture.mid_commitment,
            &fixture.tail,
            fixture.gamma,
            fixture.beta_source,
            beta_mid,
            &fixture.queries,
            &fixture.opening,
            "mid beta",
        );

        check(
            &fixture.source_commitment,
            &fixture.mid_commitment,
            &fixture.tail,
            Block256::ZERO,
            fixture.beta_source,
            fixture.beta_mid,
            &fixture.queries,
            &fixture.opening,
            "gamma endpoint",
        );

        let mut queries = fixture.queries.clone();
        queries.swap(0, 1);
        check(
            &fixture.source_commitment,
            &fixture.mid_commitment,
            &fixture.tail,
            fixture.gamma,
            fixture.beta_source,
            fixture.beta_mid,
            &queries,
            &fixture.opening,
            "query order",
        );
    }

    #[test]
    fn malformed_shapes_and_noncanonical_extra_siblings_reject() {
        let fixture = fixture(0xA11C_E005, worst_queries());

        let mut source_commitment = fixture.source_commitment.clone();
        source_commitment.cap.hashes.pop();
        assert!(matches!(
            zk_capsule_pcs_verify(
                &source_commitment,
                &fixture.mid_commitment,
                &fixture.tail,
                fixture.gamma,
                fixture.beta_source,
                fixture.beta_mid,
                &fixture.queries,
                &fixture.opening,
            ),
            Err(ZkCapsulePcsError::SourceCapCount { .. })
        ));

        let mut mid_commitment = fixture.mid_commitment.clone();
        mid_commitment.cap.hashes.pop();
        assert!(matches!(
            zk_capsule_pcs_verify(
                &fixture.source_commitment,
                &mid_commitment,
                &fixture.tail,
                fixture.gamma,
                fixture.beta_source,
                fixture.beta_mid,
                &fixture.queries,
                &fixture.opening,
            ),
            Err(ZkCapsulePcsError::MidCapCount { .. })
        ));

        let mut opening = fixture.opening.clone();
        opening.source_joint_symbols.pop();
        assert!(matches!(
            zk_capsule_pcs_verify(
                &fixture.source_commitment,
                &fixture.mid_commitment,
                &fixture.tail,
                fixture.gamma,
                fixture.beta_source,
                fixture.beta_mid,
                &fixture.queries,
                &opening,
            ),
            Err(ZkCapsulePcsError::SourceSymbolCount { .. })
        ));

        let mut opening = fixture.opening.clone();
        opening.mid_symbols.pop();
        assert!(matches!(
            zk_capsule_pcs_verify(
                &fixture.source_commitment,
                &fixture.mid_commitment,
                &fixture.tail,
                fixture.gamma,
                fixture.beta_source,
                fixture.beta_mid,
                &fixture.queries,
                &opening,
            ),
            Err(ZkCapsulePcsError::MidSymbolCount { .. })
        ));

        let mut opening = fixture.opening.clone();
        opening.source_batch.siblings.push([0u8; 32]);
        assert!(matches!(
            zk_capsule_pcs_verify(
                &fixture.source_commitment,
                &fixture.mid_commitment,
                &fixture.tail,
                fixture.gamma,
                fixture.beta_source,
                fixture.beta_mid,
                &fixture.queries,
                &opening,
            ),
            Err(ZkCapsulePcsError::SourceMerkle(_))
        ));

        let mut opening = fixture.opening.clone();
        opening.mid_batch.siblings.push([0u8; 32]);
        assert!(matches!(
            zk_capsule_pcs_verify(
                &fixture.source_commitment,
                &fixture.mid_commitment,
                &fixture.tail,
                fixture.gamma,
                fixture.beta_source,
                fixture.beta_mid,
                &fixture.queries,
                &opening,
            ),
            Err(ZkCapsulePcsError::MidMerkle(_))
        ));

        assert!(matches!(
            zk_capsule_pcs_verify(
                &fixture.source_commitment,
                &fixture.mid_commitment,
                &fixture.tail,
                fixture.gamma,
                fixture.beta_source,
                fixture.beta_mid,
                &fixture.queries[..63],
                &fixture.opening,
            ),
            Err(ZkCapsulePcsError::QueryCount { .. })
        ));

        let mut queries = fixture.queries.clone();
        queries[0] = ZK_CAPSULE_PCS_SOURCE_LEAF_COUNT;
        assert!(matches!(
            zk_capsule_pcs_verify(
                &fixture.source_commitment,
                &fixture.mid_commitment,
                &fixture.tail,
                fixture.gamma,
                fixture.beta_source,
                fixture.beta_mid,
                &queries,
                &fixture.opening,
            ),
            Err(ZkCapsulePcsError::QueryOutOfRange { .. })
        ));
    }
}
