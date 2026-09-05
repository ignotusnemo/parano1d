// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Executable boundary for the selected authorization base IOP's restoration
//! and round-by-round-knowledge argument.
//!
//! This module intentionally stops before the missing theorems.  It fixes the
//! exact logical source/mid oracle shapes, checks a caller-supplied affine-code
//! candidate by re-encoding it and measuring its exact distance, verifies the
//! `B,C -> U_gamma -> mid -> tail` restoration chain, and validates the
//! lineage of state-restoration forks.  It does **not** implement an affine
//! decoder, decide membership in a doomed set, interpolate forks, or assign a
//! numeric RBR error.  The intended list decoder is an external
//! randomized/Las-Vegas PPT extractor operation, not verifier or sync work;
//! its existence, running time, and list completeness remain theorem inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use noid_core::{Block128, TowerField};
use noid_fri_binius::zk_affine_code::{ZkAffineCodeError, ZkAffineLchCode};
use noid_fri_binius::zk_capsule::ZK_AUTH_CAPSULE_GEOMETRY;
use noid_fri_binius::zk_capsule_algebra::{
    JOINT_SOURCE_BANK_SYMBOLS, JOINT_SOURCE_LOGICAL_SYMBOLS, MID_STANDARD_FOLDS,
    SOURCE_STANDARD_FOLDS, TAIL_SYMBOLS,
};
use noid_fri_binius::zk_phase_a::{phase_a_virtual_oracle, ZkPhaseAError};
use noid_poseidon2b::native::permutation::{MDS_FULL, STATE_SIZE};
use noid_poseidon2b::primitives::{derive_address, SpendSecret};
use zeroize::Zeroizing;

use crate::zk_auth_capsule::{
    fold_lowest_variable_in_place, state_cell_index, validate_auth_main_relation,
    validate_sparse_boundary, ZkAuthCapsuleBankView, ZkAuthCapsuleError, ZK_AUTH_CAPSULE_BANK_LEN,
    ZK_AUTH_CAPSULE_STATE_LEN,
};
use crate::zk_auth_qrom::{
    conditional_zk_auth_pcs_proximity_ledger, selected_zk_auth_johnson_list_size_ledger,
    zk_auth_affine_rs_layers, zk_auth_iop_moves, zk_auth_rbr_move_profiles, ZkAuthAffineRsLayer,
    ZkAuthIopMove, ZK_AUTH_AFFINE_PROXIMITY_FOLD_ROUNDS, ZK_AUTH_BASE_MID_ORACLE_FIELDS,
    ZK_AUTH_BASE_SOURCE_ORACLE_FIELDS, ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS,
    ZK_AUTH_SELECTED_PCS_PROXIMITY_PARAMETERS, ZK_AUTH_TOTAL_VERIFIER_MOVES,
};
use crate::zk_authorization::ZkAuthCapsuleOwnerStatement;

/// Exact rational restoration radius selected by the finite-length ledger.
/// A supplied candidate is admitted only when
/// `1984 * distance < 949 * codeword_len`.
pub const ZK_AUTH_RESTORATION_RADIUS_NUMERATOR: u128 = 949;
pub const ZK_AUTH_RESTORATION_RADIUS_DENOMINATOR: u128 = 1_984;
/// Conditional Johnson list-decoding radius.  It is deliberately separate
/// from the unique-restoration radius above.
pub const ZK_AUTH_JOHNSON_LIST_RADIUS_NUMERATOR: u128 =
    ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS.radius_numerator;
pub const ZK_AUTH_JOHNSON_LIST_RADIUS_DENOMINATOR: u128 =
    ZK_AUTH_SELECTED_JOHNSON_PCS_PARAMETERS.radius_denominator;
pub const ZK_AUTH_JOHNSON_MAX_CANDIDATES: usize =
    selected_zk_auth_johnson_list_size_ledger().global_max_candidate_list_size;
pub const ZK_AUTH_JOHNSON_MAX_RESTORATION_TRIPLES: usize = ZK_AUTH_JOHNSON_MAX_CANDIDATES
    * ZK_AUTH_JOHNSON_MAX_CANDIDATES
    * ZK_AUTH_JOHNSON_MAX_CANDIDATES;

const ZK_AUTH_RBR_RS_LAYERS: [ZkAuthAffineRsLayer; ZK_AUTH_AFFINE_PROXIMITY_FOLD_ROUNDS + 1] =
    zk_auth_affine_rs_layers();

pub const ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS: usize = ZK_AUTH_RBR_RS_LAYERS[0].code_len;
pub const ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS: usize = ZK_AUTH_RBR_RS_LAYERS[0].message_len;
pub const ZK_AUTH_RBR_JOINT_SOURCE_FIELDS: usize = ZK_AUTH_BASE_SOURCE_ORACLE_FIELDS;
pub const ZK_AUTH_RBR_SOURCE_LEAVES: usize =
    ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS / JOINT_SOURCE_BANK_SYMBOLS;
pub const ZK_AUTH_RBR_MID_CODEWORD_FIELDS: usize = ZK_AUTH_BASE_MID_ORACLE_FIELDS;
pub const ZK_AUTH_RBR_MID_MESSAGE_FIELDS: usize =
    ZK_AUTH_RBR_RS_LAYERS[SOURCE_STANDARD_FOLDS].message_len;
pub const ZK_AUTH_RBR_TAIL_FIELDS: usize =
    ZK_AUTH_RBR_RS_LAYERS[ZK_AUTH_AFFINE_PROXIMITY_FOLD_ROUNDS].message_len;

/// Largest integral distance satisfying the strict selected-radius predicate.
pub const fn zk_auth_max_restoration_errors(codeword_len: usize) -> usize {
    if codeword_len == 0 {
        0
    } else {
        ((ZK_AUTH_RESTORATION_RADIUS_NUMERATOR * codeword_len as u128 - 1)
            / ZK_AUTH_RESTORATION_RADIUS_DENOMINATOR) as usize
    }
}

pub const ZK_AUTH_RBR_SOURCE_MAX_RESTORATION_ERRORS: usize =
    zk_auth_max_restoration_errors(ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS);
pub const ZK_AUTH_RBR_MID_MAX_RESTORATION_ERRORS: usize =
    zk_auth_max_restoration_errors(ZK_AUTH_RBR_MID_CODEWORD_FIELDS);

const _: () =
    assert!(ZK_AUTH_CAPSULE_GEOMETRY.source_leaf_symbols == 2 * JOINT_SOURCE_BANK_SYMBOLS);
const _: () = assert!(
    ZK_AUTH_RBR_SOURCE_LEAVES * ZK_AUTH_CAPSULE_GEOMETRY.source_leaf_symbols
        == ZK_AUTH_RBR_JOINT_SOURCE_FIELDS
);
const _: () = assert!(
    ZK_AUTH_RBR_MID_CODEWORD_FIELDS == ZK_AUTH_RBR_RS_LAYERS[SOURCE_STANDARD_FOLDS].code_len
);
const _: () = assert!(ZK_AUTH_RBR_MID_MESSAGE_FIELDS == 256);
const _: () = assert!(ZK_AUTH_RBR_TAIL_FIELDS == 16);
const _: () = assert!(ZK_AUTH_RBR_SOURCE_MAX_RESTORATION_ERRORS == 31_347);
const _: () = assert!(ZK_AUTH_RBR_MID_MAX_RESTORATION_ERRORS == 3_918);
const _: () = assert!(
    2 * ZK_AUTH_RESTORATION_RADIUS_NUMERATOR * 32 < 31 * ZK_AUTH_RESTORATION_RADIUS_DENOMINATOR
);
const _: () = assert!(ZK_AUTH_JOHNSON_LIST_RADIUS_NUMERATOR == 4);
const _: () = assert!(ZK_AUTH_JOHNSON_LIST_RADIUS_DENOMINATOR == 5);
const _: () = assert!(ZK_AUTH_JOHNSON_MAX_CANDIDATES == 17);
const _: () = assert!(ZK_AUTH_JOHNSON_MAX_RESTORATION_TRIPLES == 4_913);
const _: () = assert!(
    ZK_AUTH_JOHNSON_LIST_RADIUS_NUMERATOR * ZK_AUTH_RESTORATION_RADIUS_DENOMINATOR
        > ZK_AUTH_RESTORATION_RADIUS_NUMERATOR * ZK_AUTH_JOHNSON_LIST_RADIUS_DENOMINATOR
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthRbrRestorationDomainManifest {
    pub source_message_fields: usize,
    pub source_codeword_fields_per_oracle: usize,
    pub joint_source_fields: usize,
    pub source_leaf_fields: usize,
    pub source_leaves: usize,
    pub source_folds: usize,
    pub mid_message_fields: usize,
    pub mid_codeword_fields: usize,
    pub mid_folds: usize,
    pub tail_fields: usize,
    pub radius_numerator: u128,
    pub radius_denominator: u128,
}

pub const ZK_AUTH_RBR_RESTORATION_DOMAIN: ZkAuthRbrRestorationDomainManifest =
    ZkAuthRbrRestorationDomainManifest {
        source_message_fields: ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS,
        source_codeword_fields_per_oracle: ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS,
        joint_source_fields: ZK_AUTH_RBR_JOINT_SOURCE_FIELDS,
        source_leaf_fields: JOINT_SOURCE_LOGICAL_SYMBOLS,
        source_leaves: ZK_AUTH_RBR_SOURCE_LEAVES,
        source_folds: SOURCE_STANDARD_FOLDS,
        mid_message_fields: ZK_AUTH_RBR_MID_MESSAGE_FIELDS,
        mid_codeword_fields: ZK_AUTH_RBR_MID_CODEWORD_FIELDS,
        mid_folds: MID_STANDARD_FOLDS,
        tail_fields: ZK_AUTH_RBR_TAIL_FIELDS,
        radius_numerator: ZK_AUTH_RESTORATION_RADIUS_NUMERATOR,
        radius_denominator: ZK_AUTH_RESTORATION_RADIUS_DENOMINATOR,
    };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthRbrBoundaryEvidence {
    Executable,
    ExternalProofRequired,
}

/// Mathematical shape of the source-relative knowledge doomed set.
///
/// For a nonempty prefix `p` with fixed source bank oracle `S_B`, the intended
/// predicate is
///
/// `D_K(x,p) = !K_x(S_B) && D_relative(x,p)`.
///
/// `K_x` is executable once a close candidate has been supplied and checked;
/// construction and propagation of `D_relative` remain theorem obligations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthSourceRelativeDoomedRule {
    EmptyPrefixAlwaysDoomed,
    NonemptyNoRestoredWitnessAndRelativeDoomed,
}

/// This is a boundary manifest, not a security certificate.  In particular,
/// `numeric_rbr_bits` must remain `None` until the decoder, grouped agreement,
/// doomed-state propagation, and whole-composition extractor are proved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthSourceRelativeKnowledgeBoundaryManifest {
    pub verifier_moves: usize,
    pub empty_rule: ZkAuthSourceRelativeDoomedRule,
    pub nonempty_rule: ZkAuthSourceRelativeDoomedRule,
    pub supplied_candidate_check: ZkAuthRbrBoundaryEvidence,
    pub authorization_witness_check: ZkAuthRbrBoundaryEvidence,
    pub exact_restoration_chain: ZkAuthRbrBoundaryEvidence,
    pub affine_minimum_distance_and_unique_radius: ZkAuthRbrBoundaryEvidence,
    pub polynomial_time_unique_decoder: ZkAuthRbrBoundaryEvidence,
    pub johnson_polynomial_time_list_decoder: ZkAuthRbrBoundaryEvidence,
    pub bounded_list_candidate_selection: ZkAuthRbrBoundaryEvidence,
    pub bounded_supplied_list_restoration_check: ZkAuthRbrBoundaryEvidence,
    pub grouped_common_agreement: ZkAuthRbrBoundaryEvidence,
    pub relative_doomed_propagation: ZkAuthRbrBoundaryEvidence,
    pub whole_composition_rbr_knowledge: ZkAuthRbrBoundaryEvidence,
    pub sr_typed_message_replay: ZkAuthRbrBoundaryEvidence,
    pub sr_child_prefix_replay: ZkAuthRbrBoundaryEvidence,
    pub numeric_rbr_bits: Option<u32>,
    pub rbr_extractor_accepts_forks: bool,
    pub fork_interpolation_is_used: bool,
}

pub const ZK_AUTH_SOURCE_RELATIVE_KNOWLEDGE_BOUNDARY:
    ZkAuthSourceRelativeKnowledgeBoundaryManifest = ZkAuthSourceRelativeKnowledgeBoundaryManifest {
    verifier_moves: ZK_AUTH_TOTAL_VERIFIER_MOVES,
    empty_rule: ZkAuthSourceRelativeDoomedRule::EmptyPrefixAlwaysDoomed,
    nonempty_rule: ZkAuthSourceRelativeDoomedRule::NonemptyNoRestoredWitnessAndRelativeDoomed,
    supplied_candidate_check: ZkAuthRbrBoundaryEvidence::Executable,
    authorization_witness_check: ZkAuthRbrBoundaryEvidence::Executable,
    exact_restoration_chain: ZkAuthRbrBoundaryEvidence::Executable,
    affine_minimum_distance_and_unique_radius: ZkAuthRbrBoundaryEvidence::ExternalProofRequired,
    polynomial_time_unique_decoder: ZkAuthRbrBoundaryEvidence::ExternalProofRequired,
    johnson_polynomial_time_list_decoder: ZkAuthRbrBoundaryEvidence::ExternalProofRequired,
    bounded_list_candidate_selection: ZkAuthRbrBoundaryEvidence::ExternalProofRequired,
    bounded_supplied_list_restoration_check: ZkAuthRbrBoundaryEvidence::Executable,
    grouped_common_agreement: ZkAuthRbrBoundaryEvidence::ExternalProofRequired,
    relative_doomed_propagation: ZkAuthRbrBoundaryEvidence::ExternalProofRequired,
    whole_composition_rbr_knowledge: ZkAuthRbrBoundaryEvidence::ExternalProofRequired,
    sr_typed_message_replay: ZkAuthRbrBoundaryEvidence::ExternalProofRequired,
    sr_child_prefix_replay: ZkAuthRbrBoundaryEvidence::ExternalProofRequired,
    numeric_rbr_bits: None,
    rbr_extractor_accepts_forks: false,
    fork_interpolation_is_used: false,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthAffineRestorationDomain {
    SourceBank,
    SourceCompanion,
    Mid,
}

impl ZkAuthAffineRestorationDomain {
    const fn folds_done(self) -> usize {
        match self {
            Self::SourceBank | Self::SourceCompanion => 0,
            Self::Mid => SOURCE_STANDARD_FOLDS,
        }
    }

    const fn message_fields(self) -> usize {
        match self {
            Self::SourceBank | Self::SourceCompanion => ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS,
            Self::Mid => ZK_AUTH_RBR_MID_MESSAGE_FIELDS,
        }
    }

    const fn codeword_fields(self) -> usize {
        match self {
            Self::SourceBank | Self::SourceCompanion => ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS,
            Self::Mid => ZK_AUTH_RBR_MID_CODEWORD_FIELDS,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkAuthRbrError {
    JointSourceFieldCount {
        expected: usize,
        actual: usize,
    },
    SourceCodewordFieldCount {
        expected: usize,
        actual: usize,
    },
    MidCodewordFieldCount {
        expected: usize,
        actual: usize,
    },
    CandidateMessageFieldCount {
        expected: usize,
        actual: usize,
    },
    CandidateOutsideRestorationRadius {
        distance: usize,
        maximum: usize,
        codeword_len: usize,
    },
    CandidateDomain {
        expected: ZkAuthAffineRestorationDomain,
        actual: ZkAuthAffineRestorationDomain,
    },
    SourceToMidRestorationMismatch {
        index: usize,
    },
    MidToTailRestorationMismatch {
        index: usize,
    },
    EmptySuppliedCandidateList,
    SuppliedCandidateListTooLong {
        maximum: usize,
        actual: usize,
    },
    NoValidSuppliedCandidate,
    EmptySuppliedRestorationCandidateList {
        domain: ZkAuthAffineRestorationDomain,
    },
    SuppliedRestorationCandidateListTooLong {
        domain: ZkAuthAffineRestorationDomain,
        maximum: usize,
        actual: usize,
    },
    NoConsistentSuppliedRestorationTriple,
    ExtractedAddressMismatch,
    AffineCode(ZkAffineCodeError),
    PhaseA(ZkPhaseAError),
    AuthCapsule(ZkAuthCapsuleError),
}

impl From<ZkAffineCodeError> for ZkAuthRbrError {
    fn from(value: ZkAffineCodeError) -> Self {
        Self::AffineCode(value)
    }
}

impl From<ZkPhaseAError> for ZkAuthRbrError {
    fn from(value: ZkPhaseAError) -> Self {
        Self::PhaseA(value)
    }
}

impl From<ZkAuthCapsuleError> for ZkAuthRbrError {
    fn from(value: ZkAuthCapsuleError) -> Self {
        Self::AuthCapsule(value)
    }
}

/// Canonical logical first oracle of the base IOP.  The Merkle wrapper uses
/// interleaved leaves, but restoration always reasons about these two separate
/// length-65,536 words.
///
/// This value may contain encodings of secret witness material.  It therefore
/// has no `Clone`, `Debug`, or serde implementation and zeroizes both words on
/// drop.
pub struct ZkAuthLogicalSourceOracle {
    bank_codeword: Zeroizing<Vec<Block128>>,
    companion_codeword: Zeroizing<Vec<Block128>>,
}

impl ZkAuthLogicalSourceOracle {
    pub fn checked(
        bank_codeword: Vec<Block128>,
        companion_codeword: Vec<Block128>,
    ) -> Result<Self, ZkAuthRbrError> {
        let bank_codeword = Zeroizing::new(bank_codeword);
        let companion_codeword = Zeroizing::new(companion_codeword);
        if bank_codeword.len() != ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS {
            return Err(ZkAuthRbrError::SourceCodewordFieldCount {
                expected: ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS,
                actual: bank_codeword.len(),
            });
        }
        if companion_codeword.len() != ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS {
            return Err(ZkAuthRbrError::SourceCodewordFieldCount {
                expected: ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS,
                actual: companion_codeword.len(),
            });
        }
        Ok(Self {
            bank_codeword,
            companion_codeword,
        })
    }

    /// Deinterleave canonical leaves
    /// `[B0,C0,...,B7,C7]` in increasing leaf/position order.
    pub fn from_interleaved_fields(fields: &[Block128]) -> Result<Self, ZkAuthRbrError> {
        if fields.len() != ZK_AUTH_RBR_JOINT_SOURCE_FIELDS {
            return Err(ZkAuthRbrError::JointSourceFieldCount {
                expected: ZK_AUTH_RBR_JOINT_SOURCE_FIELDS,
                actual: fields.len(),
            });
        }
        let mut bank = Vec::with_capacity(ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS);
        let mut companion = Vec::with_capacity(ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS);
        for leaf in fields.chunks_exact(JOINT_SOURCE_LOGICAL_SYMBOLS) {
            for pair in leaf.chunks_exact(2) {
                bank.push(pair[0]);
                companion.push(pair[1]);
            }
        }
        debug_assert_eq!(bank.len(), ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS);
        debug_assert_eq!(companion.len(), ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS);
        Self::checked(bank, companion)
    }

    /// Check, but do not discover, a caller-supplied bank message candidate.
    pub fn check_supplied_bank_candidate(
        &self,
        supplied_message: Vec<Block128>,
    ) -> Result<ZkAuthCheckedAffineCandidate, ZkAuthRbrError> {
        ZkAuthCheckedAffineCandidate::check(
            ZkAuthAffineRestorationDomain::SourceBank,
            &self.bank_codeword,
            supplied_message,
        )
    }

    /// Check, but do not discover, a caller-supplied companion candidate.
    pub fn check_supplied_companion_candidate(
        &self,
        supplied_message: Vec<Block128>,
    ) -> Result<ZkAuthCheckedAffineCandidate, ZkAuthRbrError> {
        ZkAuthCheckedAffineCandidate::check(
            ZkAuthAffineRestorationDomain::SourceCompanion,
            &self.companion_codeword,
            supplied_message,
        )
    }
}

/// Canonical logical 8,192-field mid oracle.  It may still contain a linear
/// image of witness material and is consequently zeroized and non-cloneable.
pub struct ZkAuthLogicalMidOracle {
    codeword: Zeroizing<Vec<Block128>>,
}

impl ZkAuthLogicalMidOracle {
    pub fn checked(codeword: Vec<Block128>) -> Result<Self, ZkAuthRbrError> {
        let codeword = Zeroizing::new(codeword);
        if codeword.len() != ZK_AUTH_RBR_MID_CODEWORD_FIELDS {
            return Err(ZkAuthRbrError::MidCodewordFieldCount {
                expected: ZK_AUTH_RBR_MID_CODEWORD_FIELDS,
                actual: codeword.len(),
            });
        }
        Ok(Self { codeword })
    }

    pub fn check_supplied_candidate(
        &self,
        supplied_message: Vec<Block128>,
    ) -> Result<ZkAuthCheckedAffineCandidate, ZkAuthRbrError> {
        ZkAuthCheckedAffineCandidate::check(
            ZkAuthAffineRestorationDomain::Mid,
            &self.codeword,
            supplied_message,
        )
    }
}

/// A re-encoding-and-distance check for a message supplied by an external
/// decoder or theorem harness.
///
/// Construction of this value is not decoding: the caller supplies the whole
/// candidate message.  This type proves only that its re-encoding is within
/// the selected strict radius of the observed word.  Unique decoding and the
/// code-distance theorem remain external obligations.
pub struct ZkAuthCheckedAffineCandidate {
    domain: ZkAuthAffineRestorationDomain,
    message: Zeroizing<Vec<Block128>>,
    hamming_distance: usize,
}

fn reencoded_affine_hamming_distance(
    code: &ZkAffineLchCode,
    domain: ZkAuthAffineRestorationDomain,
    observed_codeword: &[Block128],
    supplied_message: &[Block128],
) -> Result<usize, ZkAuthRbrError> {
    if observed_codeword.len() != domain.codeword_fields() {
        return Err(match domain {
            ZkAuthAffineRestorationDomain::SourceBank
            | ZkAuthAffineRestorationDomain::SourceCompanion => {
                ZkAuthRbrError::SourceCodewordFieldCount {
                    expected: domain.codeword_fields(),
                    actual: observed_codeword.len(),
                }
            }
            ZkAuthAffineRestorationDomain::Mid => ZkAuthRbrError::MidCodewordFieldCount {
                expected: domain.codeword_fields(),
                actual: observed_codeword.len(),
            },
        });
    }
    if supplied_message.len() != domain.message_fields() {
        return Err(ZkAuthRbrError::CandidateMessageFieldCount {
            expected: domain.message_fields(),
            actual: supplied_message.len(),
        });
    }

    let encoded =
        Zeroizing::new(code.encode_after_low_folds(supplied_message, domain.folds_done())?);
    debug_assert_eq!(encoded.len(), observed_codeword.len());
    Ok(encoded
        .iter()
        .zip(observed_codeword)
        .filter(|(expected, observed)| expected != observed)
        .count())
}

impl ZkAuthCheckedAffineCandidate {
    fn check(
        domain: ZkAuthAffineRestorationDomain,
        observed_codeword: &[Block128],
        supplied_message: Vec<Block128>,
    ) -> Result<Self, ZkAuthRbrError> {
        let supplied_message = Zeroizing::new(supplied_message);
        let code = ZkAffineLchCode::selected()?;
        let hamming_distance =
            reencoded_affine_hamming_distance(&code, domain, observed_codeword, &supplied_message)?;
        let within_radius = ZK_AUTH_RESTORATION_RADIUS_DENOMINATOR * (hamming_distance as u128)
            < ZK_AUTH_RESTORATION_RADIUS_NUMERATOR * observed_codeword.len() as u128;
        if !within_radius {
            return Err(ZkAuthRbrError::CandidateOutsideRestorationRadius {
                distance: hamming_distance,
                maximum: zk_auth_max_restoration_errors(observed_codeword.len()),
                codeword_len: observed_codeword.len(),
            });
        }
        Ok(Self {
            domain,
            message: supplied_message,
            hamming_distance,
        })
    }

    pub const fn domain(&self) -> ZkAuthAffineRestorationDomain {
        self.domain
    }

    pub const fn hamming_distance(&self) -> usize {
        self.hamming_distance
    }

    pub fn message_fields(&self) -> usize {
        self.message.len()
    }

    /// Rebind this detached candidate to the actual logical oracle supplied by
    /// the transcript consumer.  A candidate minted against another oracle is
    /// unusable unless its message independently satisfies the same strict
    /// radius check against this word too.
    fn recheck_against(
        &self,
        expected_domain: ZkAuthAffineRestorationDomain,
        observed_codeword: &[Block128],
    ) -> Result<usize, ZkAuthRbrError> {
        self.require_domain(expected_domain)?;
        let code = ZkAffineLchCode::selected()?;
        let distance = reencoded_affine_hamming_distance(
            &code,
            expected_domain,
            observed_codeword,
            &self.message,
        )?;
        if ZK_AUTH_RESTORATION_RADIUS_DENOMINATOR * distance as u128
            >= ZK_AUTH_RESTORATION_RADIUS_NUMERATOR * observed_codeword.len() as u128
        {
            return Err(ZkAuthRbrError::CandidateOutsideRestorationRadius {
                distance,
                maximum: zk_auth_max_restoration_errors(observed_codeword.len()),
                codeword_len: observed_codeword.len(),
            });
        }
        Ok(distance)
    }

    fn require_domain(
        &self,
        expected: ZkAuthAffineRestorationDomain,
    ) -> Result<(), ZkAuthRbrError> {
        if self.domain == expected {
            Ok(())
        } else {
            Err(ZkAuthRbrError::CandidateDomain {
                expected,
                actual: self.domain,
            })
        }
    }
}

/// Secret extracted from a checked bank candidate after the complete native
/// trace and boundary relation have been revalidated.
///
/// ```compile_fail
/// use noid_gkr::zk_auth_rbr::ZkAuthKnowledgeWitness;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ZkAuthKnowledgeWitness>();
/// ```
///
/// ```compile_fail
/// use noid_gkr::zk_auth_rbr::ZkAuthKnowledgeWitness;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<ZkAuthKnowledgeWitness>();
/// ```
///
/// ```compile_fail
/// use noid_gkr::zk_auth_rbr::ZkAuthKnowledgeWitness;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<ZkAuthKnowledgeWitness>();
/// ```
pub struct ZkAuthKnowledgeWitness {
    secret: Zeroizing<[Block128; 2]>,
}

impl ZkAuthKnowledgeWitness {
    /// Re-evaluate the public address without exposing either secret limb.
    pub fn matches_statement(&self, statement: ZkAuthCapsuleOwnerStatement) -> bool {
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes[..16].copy_from_slice(&self.secret[0].0.to_le_bytes());
        bytes[16..].copy_from_slice(&self.secret[1].0.to_le_bytes());
        let spend_secret = SpendSecret::from_bytes(*bytes);
        derive_address(&spend_secret).as_fields() == statement.address
    }
}

fn mds_full_inverse() -> &'static [[Block128; STATE_SIZE]; STATE_SIZE] {
    static INVERSE: OnceLock<[[Block128; STATE_SIZE]; STATE_SIZE]> = OnceLock::new();
    INVERSE.get_or_init(|| {
        let mut augmented = [[Block128::ZERO; STATE_SIZE * 2]; STATE_SIZE];
        for row in 0..STATE_SIZE {
            for column in 0..STATE_SIZE {
                augmented[row][column] = Block128::from(MDS_FULL[row][column]);
            }
            augmented[row][STATE_SIZE + row] = Block128::ONE;
        }
        for column in 0..STATE_SIZE {
            let pivot = (column..STATE_SIZE)
                .find(|&row| augmented[row][column] != Block128::ZERO)
                .expect("selected Poseidon MDS matrix is invertible");
            if pivot != column {
                augmented.swap(pivot, column);
            }
            let inverse = augmented[column][column].invert();
            for entry in &mut augmented[column] {
                *entry *= inverse;
            }
            for row in 0..STATE_SIZE {
                if row == column {
                    continue;
                }
                let factor = augmented[row][column];
                let pivot_row = augmented[column];
                for (entry, &pivot_entry) in augmented[row].iter_mut().zip(&pivot_row) {
                    *entry += factor * pivot_entry;
                }
            }
        }
        std::array::from_fn(|row| std::array::from_fn(|column| augmented[row][STATE_SIZE + column]))
    })
}

fn extract_witness_from_bank_message(
    statement: ZkAuthCapsuleOwnerStatement,
    bank_message: &[Block128],
) -> Result<ZkAuthKnowledgeWitness, ZkAuthRbrError> {
    let view = ZkAuthCapsuleBankView::checked(bank_message)?;
    validate_auth_main_relation(view)?;
    validate_sparse_boundary(view, statement.boundary())?;

    let row_zero = Zeroizing::new(std::array::from_fn::<Block128, STATE_SIZE, _>(|lane| {
        bank_message[state_cell_index(0, lane).expect("selected row-zero lane")]
    }));
    let inverse = mds_full_inverse();
    let pre_mds = Zeroizing::new(std::array::from_fn::<Block128, STATE_SIZE, _>(|lane| {
        (0..STATE_SIZE).fold(Block128::ZERO, |sum, post_lane| {
            sum + inverse[lane][post_lane] * row_zero[post_lane]
        })
    }));
    let witness = ZkAuthKnowledgeWitness {
        secret: Zeroizing::new([pre_mds[0], pre_mds[1]]),
    };
    if !witness.matches_statement(statement) {
        return Err(ZkAuthRbrError::ExtractedAddressMismatch);
    }
    Ok(witness)
}

/// Rebind a supplied unique-radius candidate to the actual logical source
/// oracle, validate its complete authorization trace, and extract the two
/// pre-initial-MDS secret limbs.  The candidate check is not a decoder and this
/// function does not change that status.
pub fn extract_zk_auth_knowledge_witness_from_supplied_candidate(
    statement: ZkAuthCapsuleOwnerStatement,
    source: &ZkAuthLogicalSourceOracle,
    bank: &ZkAuthCheckedAffineCandidate,
) -> Result<ZkAuthKnowledgeWitness, ZkAuthRbrError> {
    let _ = bank.recheck_against(
        ZkAuthAffineRestorationDomain::SourceBank,
        &source.bank_codeword,
    )?;
    extract_witness_from_bank_message(statement, &bank.message)
}

/// Straight-line selection over a caller-supplied Johnson decoder list.
///
/// Every candidate is re-encoded and checked against the actual fixed source
/// bank oracle at the separate `4/5` Johnson radius, then subjected to the
/// full Auth trace/address predicate.  The first valid secret witness is
/// returned opaquely. The supplied list is capped by the executable
/// Guruswami--Sudan dimension ledger at seventeen candidates. This function
/// does not produce the list or prove that a decoder's output is exhaustive;
/// those properties
/// remain explicit manifest obligations above.  It deliberately does not call
/// or relax the unique-radius candidate constructor.  In the intended model,
/// the randomized/Las-Vegas PPT decoder runs externally as extractor work, not
/// in the verifier or node-sync path.
pub fn scan_supplied_johnson_bank_candidate_list(
    statement: ZkAuthCapsuleOwnerStatement,
    source: &ZkAuthLogicalSourceOracle,
    supplied_candidates: Vec<Vec<Block128>>,
) -> Result<ZkAuthKnowledgeWitness, ZkAuthRbrError> {
    // Wrap every allocation before any early return so an accepted first
    // candidate cannot leave later decoder outputs unwiped.
    let supplied_candidates = supplied_candidates
        .into_iter()
        .map(Zeroizing::new)
        .collect::<Vec<_>>();
    if supplied_candidates.is_empty() {
        return Err(ZkAuthRbrError::EmptySuppliedCandidateList);
    }
    if supplied_candidates.len() > ZK_AUTH_JOHNSON_MAX_CANDIDATES {
        return Err(ZkAuthRbrError::SuppliedCandidateListTooLong {
            maximum: ZK_AUTH_JOHNSON_MAX_CANDIDATES,
            actual: supplied_candidates.len(),
        });
    }
    let code = ZkAffineLchCode::selected()?;
    for supplied in supplied_candidates {
        let distance = reencoded_affine_hamming_distance(
            &code,
            ZkAuthAffineRestorationDomain::SourceBank,
            &source.bank_codeword,
            &supplied,
        )?;
        if ZK_AUTH_JOHNSON_LIST_RADIUS_DENOMINATOR * distance as u128
            > ZK_AUTH_JOHNSON_LIST_RADIUS_NUMERATOR * ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS as u128
        {
            continue;
        }
        if let Ok(witness) = extract_witness_from_bank_message(statement, &supplied) {
            return Ok(witness);
        }
    }
    Err(ZkAuthRbrError::NoValidSuppliedCandidate)
}

struct ZkAuthJohnsonBoundCandidate {
    supplied_index: usize,
    message: Zeroizing<Vec<Block128>>,
    hamming_distance: usize,
}

fn bind_supplied_johnson_candidates(
    code: &ZkAffineLchCode,
    domain: ZkAuthAffineRestorationDomain,
    observed_codeword: &[Block128],
    supplied_candidates: Vec<Zeroizing<Vec<Block128>>>,
) -> Result<Vec<ZkAuthJohnsonBoundCandidate>, ZkAuthRbrError> {
    let mut bound = Vec::with_capacity(supplied_candidates.len());
    for (supplied_index, message) in supplied_candidates.into_iter().enumerate() {
        let hamming_distance =
            reencoded_affine_hamming_distance(code, domain, observed_codeword, &message)?;
        let within_johnson_radius = ZK_AUTH_JOHNSON_LIST_RADIUS_DENOMINATOR
            * hamming_distance as u128
            <= ZK_AUTH_JOHNSON_LIST_RADIUS_NUMERATOR * observed_codeword.len() as u128;
        if within_johnson_radius {
            bound.push(ZkAuthJohnsonBoundCandidate {
                supplied_index,
                message,
                hamming_distance,
            });
        }
    }
    Ok(bound)
}

fn check_supplied_restoration_list_size(
    domain: ZkAuthAffineRestorationDomain,
    actual: usize,
) -> Result<(), ZkAuthRbrError> {
    if actual == 0 {
        return Err(ZkAuthRbrError::EmptySuppliedRestorationCandidateList { domain });
    }
    if actual > ZK_AUTH_JOHNSON_MAX_CANDIDATES {
        return Err(ZkAuthRbrError::SuppliedRestorationCandidateListTooLong {
            domain,
            maximum: ZK_AUTH_JOHNSON_MAX_CANDIDATES,
            actual,
        });
    }
    Ok(())
}

/// Public, non-secret facts about the first accepted caller-supplied triple.
/// Candidate messages and the extracted secret are intentionally absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthJohnsonRestorationEvidence {
    bank_candidate_index: usize,
    companion_candidate_index: usize,
    mid_candidate_index: usize,
    bank_distance: usize,
    companion_distance: usize,
    mid_distance: usize,
    triples_examined: usize,
}

impl ZkAuthJohnsonRestorationEvidence {
    pub const fn bank_candidate_index(self) -> usize {
        self.bank_candidate_index
    }

    pub const fn companion_candidate_index(self) -> usize {
        self.companion_candidate_index
    }

    pub const fn mid_candidate_index(self) -> usize {
        self.mid_candidate_index
    }

    pub const fn bank_distance(self) -> usize {
        self.bank_distance
    }

    pub const fn companion_distance(self) -> usize {
        self.companion_distance
    }

    pub const fn mid_distance(self) -> usize {
        self.mid_distance
    }

    pub const fn triples_examined(self) -> usize {
        self.triples_examined
    }
}

/// Opaque result of bounded supplied-list restoration.  It deliberately has
/// no `Clone`, `Debug`, or serde implementation because it owns the extracted
/// secret witness.
pub struct ZkAuthJohnsonRestorationSelection {
    witness: ZkAuthKnowledgeWitness,
    evidence: ZkAuthJohnsonRestorationEvidence,
}

impl ZkAuthJohnsonRestorationSelection {
    pub fn matches_statement(&self, statement: ZkAuthCapsuleOwnerStatement) -> bool {
        self.witness.matches_statement(statement)
    }

    pub const fn evidence(&self) -> ZkAuthJohnsonRestorationEvidence {
        self.evidence
    }
}

/// Check three bounded caller-supplied Johnson candidate lists against the
/// actual source-bank, source-companion, and mid oracles.
///
/// Every list is first put under zeroizing ownership, before any shape or cap
/// error can return.  Every candidate is then independently re-encoded and
/// rebound to its actual oracle at the inclusive `4/5` radius. The surviving
/// lists contain at most seventeen candidates each, so lexicographic selection
/// examines at most 4,913 triples. A triple is accepted only if its bank passes
/// the complete Auth/address check and its exact
/// `B,C -> U_gamma -> fold3 -> mid -> fold4 -> tail` chain closes.
///
/// This is neither a decoder nor a completeness/common-agreement argument.
/// Those obligations remain external in the boundary manifest.  The intended
/// randomized/Las-Vegas PPT decoder is extractor-side work and is not part of
/// verification or node synchronization.
#[allow(clippy::too_many_arguments)] // Keep every fixed transcript object explicit at this gate.
pub fn scan_supplied_johnson_restoration_candidate_lists(
    statement: ZkAuthCapsuleOwnerStatement,
    source: &ZkAuthLogicalSourceOracle,
    mid_oracle: &ZkAuthLogicalMidOracle,
    supplied_bank_candidates: Vec<Vec<Block128>>,
    supplied_companion_candidates: Vec<Vec<Block128>>,
    supplied_mid_candidates: Vec<Vec<Block128>>,
    gamma: Block128,
    beta_source: [Block128; SOURCE_STANDARD_FOLDS],
    beta_mid: [Block128; MID_STANDARD_FOLDS],
    tail: &[Block128; TAIL_SYMBOLS],
) -> Result<ZkAuthJohnsonRestorationSelection, ZkAuthRbrError> {
    // These three conversions must precede every fallible operation and every
    // early return: even a cap error on B must wipe supplied C/mid messages.
    let supplied_bank_candidates = supplied_bank_candidates
        .into_iter()
        .map(Zeroizing::new)
        .collect::<Vec<_>>();
    let supplied_companion_candidates = supplied_companion_candidates
        .into_iter()
        .map(Zeroizing::new)
        .collect::<Vec<_>>();
    let supplied_mid_candidates = supplied_mid_candidates
        .into_iter()
        .map(Zeroizing::new)
        .collect::<Vec<_>>();

    check_supplied_restoration_list_size(
        ZkAuthAffineRestorationDomain::SourceBank,
        supplied_bank_candidates.len(),
    )?;
    check_supplied_restoration_list_size(
        ZkAuthAffineRestorationDomain::SourceCompanion,
        supplied_companion_candidates.len(),
    )?;
    check_supplied_restoration_list_size(
        ZkAuthAffineRestorationDomain::Mid,
        supplied_mid_candidates.len(),
    )?;

    let code = ZkAffineLchCode::selected()?;
    let bank_candidates = bind_supplied_johnson_candidates(
        &code,
        ZkAuthAffineRestorationDomain::SourceBank,
        &source.bank_codeword,
        supplied_bank_candidates,
    )?;
    let companion_candidates = bind_supplied_johnson_candidates(
        &code,
        ZkAuthAffineRestorationDomain::SourceCompanion,
        &source.companion_codeword,
        supplied_companion_candidates,
    )?;
    let mid_candidates = bind_supplied_johnson_candidates(
        &code,
        ZkAuthAffineRestorationDomain::Mid,
        &mid_oracle.codeword,
        supplied_mid_candidates,
    )?;

    let mut triples_examined = 0usize;
    for bank in &bank_candidates {
        let mut witness = extract_witness_from_bank_message(statement, &bank.message).ok();
        for companion in &companion_candidates {
            for mid in &mid_candidates {
                triples_examined += 1;
                debug_assert!(triples_examined <= ZK_AUTH_JOHNSON_MAX_RESTORATION_TRIPLES);
                if witness.is_none() {
                    continue;
                }
                match check_exact_restoration_messages(
                    &bank.message,
                    &companion.message,
                    gamma,
                    &beta_source,
                    &mid.message,
                    &beta_mid,
                    tail,
                ) {
                    Ok(()) => {
                        return Ok(ZkAuthJohnsonRestorationSelection {
                            witness: witness.take().expect("checked present witness"),
                            evidence: ZkAuthJohnsonRestorationEvidence {
                                bank_candidate_index: bank.supplied_index,
                                companion_candidate_index: companion.supplied_index,
                                mid_candidate_index: mid.supplied_index,
                                bank_distance: bank.hamming_distance,
                                companion_distance: companion.hamming_distance,
                                mid_distance: mid.hamming_distance,
                                triples_examined,
                            },
                        });
                    }
                    Err(ZkAuthRbrError::SourceToMidRestorationMismatch { .. })
                    | Err(ZkAuthRbrError::MidToTailRestorationMismatch { .. }) => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }

    Err(ZkAuthRbrError::NoConsistentSuppliedRestorationTriple)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthExactRestorationEvidence {
    bank_distance: usize,
    companion_distance: usize,
    mid_distance: usize,
    virtual_message_fields: usize,
    mid_message_fields: usize,
    tail_fields: usize,
}

impl ZkAuthExactRestorationEvidence {
    pub const fn bank_distance(self) -> usize {
        self.bank_distance
    }

    pub const fn companion_distance(self) -> usize {
        self.companion_distance
    }

    pub const fn mid_distance(self) -> usize {
        self.mid_distance
    }

    pub const fn virtual_message_fields(self) -> usize {
        self.virtual_message_fields
    }

    pub const fn mid_message_fields(self) -> usize {
        self.mid_message_fields
    }

    pub const fn tail_fields(self) -> usize {
        self.tail_fields
    }
}

fn check_exact_restoration_messages(
    bank_message: &[Block128],
    companion_message: &[Block128],
    gamma: Block128,
    beta_source: &[Block128; SOURCE_STANDARD_FOLDS],
    mid_message: &[Block128],
    beta_mid: &[Block128; MID_STANDARD_FOLDS],
    tail: &[Block128; TAIL_SYMBOLS],
) -> Result<(), ZkAuthRbrError> {
    let mut expected_mid = Zeroizing::new(phase_a_virtual_oracle(
        bank_message,
        companion_message,
        gamma,
    )?);
    for &challenge in beta_source {
        fold_lowest_variable_in_place(&mut expected_mid, challenge)?;
    }
    if let Some(index) = expected_mid
        .iter()
        .zip(mid_message)
        .position(|(expected, actual)| expected != actual)
    {
        return Err(ZkAuthRbrError::SourceToMidRestorationMismatch { index });
    }

    let mut expected_tail = Zeroizing::new(mid_message.to_vec());
    for &challenge in beta_mid {
        fold_lowest_variable_in_place(&mut expected_tail, challenge)?;
    }
    if let Some(index) = expected_tail
        .iter()
        .zip(tail)
        .position(|(expected, actual)| expected != actual)
    {
        return Err(ZkAuthRbrError::MidToTailRestorationMismatch { index });
    }
    Ok(())
}

/// Check the exact candidate chain after candidates have been supplied by an
/// external decoder/harness.  No proximity or common-agreement probability is
/// inferred from success or failure here.
#[allow(clippy::too_many_arguments)] // Keep every fixed transcript object explicit at this gate.
pub fn check_zk_auth_exact_restoration_chain(
    source: &ZkAuthLogicalSourceOracle,
    bank: &ZkAuthCheckedAffineCandidate,
    companion: &ZkAuthCheckedAffineCandidate,
    gamma: Block128,
    beta_source: [Block128; SOURCE_STANDARD_FOLDS],
    mid_oracle: &ZkAuthLogicalMidOracle,
    mid: &ZkAuthCheckedAffineCandidate,
    beta_mid: [Block128; MID_STANDARD_FOLDS],
    tail: &[Block128; TAIL_SYMBOLS],
) -> Result<ZkAuthExactRestorationEvidence, ZkAuthRbrError> {
    let bank_distance = bank.recheck_against(
        ZkAuthAffineRestorationDomain::SourceBank,
        &source.bank_codeword,
    )?;
    let companion_distance = companion.recheck_against(
        ZkAuthAffineRestorationDomain::SourceCompanion,
        &source.companion_codeword,
    )?;
    let mid_distance =
        mid.recheck_against(ZkAuthAffineRestorationDomain::Mid, &mid_oracle.codeword)?;

    check_exact_restoration_messages(
        &bank.message,
        &companion.message,
        gamma,
        &beta_source,
        &mid.message,
        &beta_mid,
        tail,
    )?;

    Ok(ZkAuthExactRestorationEvidence {
        bank_distance,
        companion_distance,
        mid_distance,
        virtual_message_fields: ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS,
        mid_message_fields: ZK_AUTH_RBR_MID_MESSAGE_FIELDS,
        tail_fields: ZK_AUTH_RBR_TAIL_FIELDS,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ZkAuthSrCheckpointId(u64);

impl ZkAuthSrCheckpointId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One state-restoration branch after a fixed prover message and one public
/// coin move.  Fixed message bytes are retained, compared directly (never by
/// an unproved digest), and zeroized on drop.
pub struct ZkAuthSrForkBranch {
    parent: ZkAuthSrCheckpointId,
    move_index: usize,
    fixed_message: Zeroizing<Vec<u8>>,
    challenge: Vec<Block128>,
    child: ZkAuthSrCheckpointId,
}

impl ZkAuthSrForkBranch {
    pub fn new(
        parent: ZkAuthSrCheckpointId,
        move_index: usize,
        fixed_message: Vec<u8>,
        challenge: Vec<Block128>,
        child: ZkAuthSrCheckpointId,
    ) -> Self {
        Self {
            parent,
            move_index,
            fixed_message: Zeroizing::new(fixed_message),
            challenge,
            child,
        }
    }

    pub const fn parent(&self) -> ZkAuthSrCheckpointId {
        self.parent
    }

    pub const fn child(&self) -> ZkAuthSrCheckpointId {
        self.child
    }

    pub const fn move_index(&self) -> usize {
        self.move_index
    }
}

pub struct ZkAuthSrFork {
    branches: Vec<ZkAuthSrForkBranch>,
}

impl ZkAuthSrFork {
    pub fn new(branches: Vec<ZkAuthSrForkBranch>) -> Self {
        Self { branches }
    }

    pub fn branch_count(&self) -> usize {
        self.branches.len()
    }
}

/// Topologically ordered state-restoration fork collection.  This is only a
/// structural input to a future straight-line SR adapter; it contains no
/// accepting-tree or interpolation extractor.
pub struct ZkAuthSrForkTrace {
    root: ZkAuthSrCheckpointId,
    forks: Vec<ZkAuthSrFork>,
}

impl ZkAuthSrForkTrace {
    pub fn new(root: ZkAuthSrCheckpointId) -> Self {
        Self {
            root,
            forks: Vec::new(),
        }
    }

    pub fn push_fork(&mut self, fork: ZkAuthSrFork) {
        self.forks.push(fork);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkAuthSrForkError {
    TooFewBranches {
        actual: usize,
    },
    MoveIndexOutOfRange {
        move_index: usize,
    },
    InternalMoveManifestMismatch {
        move_index: usize,
    },
    UnknownParent {
        parent: ZkAuthSrCheckpointId,
    },
    ParentAlreadyExpanded {
        parent: ZkAuthSrCheckpointId,
    },
    MoveDoesNotFollowParent {
        parent: ZkAuthSrCheckpointId,
        expected: usize,
        actual: usize,
    },
    ParentMismatch,
    MoveMismatch,
    EmptyFixedMessage,
    FixedMessageMismatch,
    ChallengeFieldCount {
        branch: usize,
        expected: usize,
        actual: usize,
    },
    InadmissibleChallenge {
        branch: usize,
        move_index: usize,
    },
    DuplicateChallenge,
    SelfLoop {
        checkpoint: ZkAuthSrCheckpointId,
    },
    DuplicateCheckpoint {
        checkpoint: ZkAuthSrCheckpointId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Opaque summary of lineage checks only.  It is not an accepting SR
/// transcript, a state-transition certificate, or an extractor capability.
pub struct ZkAuthValidatedSrForkTrace {
    forks: usize,
    branches: usize,
    checkpoints: usize,
    deepest_completed_move: usize,
    fork_interpolation_performed: bool,
}

impl ZkAuthValidatedSrForkTrace {
    pub const fn forks(self) -> usize {
        self.forks
    }

    pub const fn branches(self) -> usize {
        self.branches
    }

    pub const fn checkpoints(self) -> usize {
        self.checkpoints
    }

    pub const fn deepest_completed_move(self) -> usize {
        self.deepest_completed_move
    }

    pub const fn fork_interpolation_performed(self) -> bool {
        self.fork_interpolation_performed
    }
}

/// Validate fork lineage and exact precoin identity.  The canonical move list
/// and challenge widths come from `zk_auth_qrom`; this module does not maintain
/// a second 30-entry schedule.  Fixed-message bytes remain opaque and child
/// prefix replay remains an external obligation recorded in the manifest, so
/// this result must not be consumed as full SR evidence.
pub fn validate_zk_auth_sr_fork_trace(
    trace: &ZkAuthSrForkTrace,
) -> Result<ZkAuthValidatedSrForkTrace, ZkAuthSrForkError> {
    let moves = zk_auth_iop_moves();
    let profiles = zk_auth_rbr_move_profiles();
    let mut checkpoints = BTreeMap::new();
    checkpoints.insert(trace.root, 0usize);
    let mut expanded_parents = BTreeSet::new();
    let mut total_branches = 0usize;
    let mut deepest_completed_move = 0usize;

    for fork in &trace.forks {
        if fork.branches.len() < 2 {
            return Err(ZkAuthSrForkError::TooFewBranches {
                actual: fork.branches.len(),
            });
        }
        let first = &fork.branches[0];
        let Some(&move_) = moves.get(first.move_index) else {
            return Err(ZkAuthSrForkError::MoveIndexOutOfRange {
                move_index: first.move_index,
            });
        };
        if profiles.get(first.move_index).map(|profile| profile.move_) != Some(move_) {
            return Err(ZkAuthSrForkError::InternalMoveManifestMismatch {
                move_index: first.move_index,
            });
        }
        let Some(&expected_move_index) = checkpoints.get(&first.parent) else {
            return Err(ZkAuthSrForkError::UnknownParent {
                parent: first.parent,
            });
        };
        if first.move_index != expected_move_index {
            return Err(ZkAuthSrForkError::MoveDoesNotFollowParent {
                parent: first.parent,
                expected: expected_move_index,
                actual: first.move_index,
            });
        }
        if !expanded_parents.insert(first.parent) {
            return Err(ZkAuthSrForkError::ParentAlreadyExpanded {
                parent: first.parent,
            });
        }
        if first.fixed_message.is_empty() {
            return Err(ZkAuthSrForkError::EmptyFixedMessage);
        }

        for (branch_index, branch) in fork.branches.iter().enumerate() {
            if branch.parent != first.parent {
                return Err(ZkAuthSrForkError::ParentMismatch);
            }
            if branch.move_index != first.move_index {
                return Err(ZkAuthSrForkError::MoveMismatch);
            }
            if branch.fixed_message.as_slice() != first.fixed_message.as_slice() {
                return Err(ZkAuthSrForkError::FixedMessageMismatch);
            }
            if branch.challenge.len() != move_.challenge_fields() {
                return Err(ZkAuthSrForkError::ChallengeFieldCount {
                    branch: branch_index,
                    expected: move_.challenge_fields(),
                    actual: branch.challenge.len(),
                });
            }
            let challenge_is_admissible = match move_ {
                ZkAuthIopMove::OwnerLambda | ZkAuthIopMove::OwnerEta => {
                    branch.challenge[0] != Block128::ZERO
                }
                ZkAuthIopMove::MainGamma => {
                    branch.challenge[0] != Block128::ZERO && branch.challenge[0] != Block128::ONE
                }
                _ => true,
            };
            if !challenge_is_admissible {
                return Err(ZkAuthSrForkError::InadmissibleChallenge {
                    branch: branch_index,
                    move_index: first.move_index,
                });
            }
            if branch.child == branch.parent {
                return Err(ZkAuthSrForkError::SelfLoop {
                    checkpoint: branch.child,
                });
            }
            for previous in &fork.branches[..branch_index] {
                if previous.challenge == branch.challenge {
                    return Err(ZkAuthSrForkError::DuplicateChallenge);
                }
            }
        }

        let mut children = BTreeSet::new();
        for branch in &fork.branches {
            if checkpoints.contains_key(&branch.child) || !children.insert(branch.child) {
                return Err(ZkAuthSrForkError::DuplicateCheckpoint {
                    checkpoint: branch.child,
                });
            }
        }
        for child in children {
            checkpoints.insert(child, first.move_index + 1);
        }
        total_branches += fork.branches.len();
        deepest_completed_move = deepest_completed_move.max(first.move_index + 1);
    }

    Ok(ZkAuthValidatedSrForkTrace {
        forks: trace.forks.len(),
        branches: total_branches,
        checkpoints: checkpoints.len(),
        deepest_completed_move,
        fork_interpolation_performed: false,
    })
}

/// Recheck that this module's rational radius remains the one derived by the
/// selected finite-length ledger.  This is executable arithmetic only; it does
/// not upgrade the conditional ledger into an RBR theorem.
pub fn zk_auth_rbr_radius_matches_selected_ledger() -> bool {
    conditional_zk_auth_pcs_proximity_ledger(ZK_AUTH_SELECTED_PCS_PROXIMITY_PARAMETERS)
        .map(|ledger| {
            ledger.conservative_gap_numerator == ZK_AUTH_RESTORATION_RADIUS_NUMERATOR
                && ledger.conservative_gap_denominator == ZK_AUTH_RESTORATION_RADIUS_DENOMINATOR
        })
        .unwrap_or(false)
}

const _: () = assert!(ZK_AUTH_CAPSULE_BANK_LEN == ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS);
const _: () = assert!(ZK_AUTH_CAPSULE_STATE_LEN == 512);
const _: () = assert!(ZK_AUTH_TOTAL_VERIFIER_MOVES == 30);
const _: () = assert!(!ZK_AUTH_SOURCE_RELATIVE_KNOWLEDGE_BOUNDARY.rbr_extractor_accepts_forks);
const _: () = assert!(!ZK_AUTH_SOURCE_RELATIVE_KNOWLEDGE_BOUNDARY.fork_interpolation_is_used);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::evaluate_permutation;
    use crate::zk_auth_capsule::ZkAuthCapsuleStateTable;
    use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRFIX};

    fn elem(index: usize, domain: u128) -> Block128 {
        Block128::from(
            domain
                .wrapping_mul(index as u128 + 1)
                .rotate_left(((17 * index + 5) % 127) as u32)
                ^ (index as u128 + 9).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        )
    }

    fn message(len: usize, domain: u128) -> Vec<Block128> {
        (0..len).map(|index| elem(index, domain)).collect()
    }

    fn interleave_source(bank: &[Block128], companion: &[Block128]) -> Vec<Block128> {
        assert_eq!(bank.len(), ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS);
        assert_eq!(companion.len(), ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS);
        let mut fields = Vec::with_capacity(ZK_AUTH_RBR_JOINT_SOURCE_FIELDS);
        for (bank_leaf, companion_leaf) in bank
            .chunks_exact(JOINT_SOURCE_BANK_SYMBOLS)
            .zip(companion.chunks_exact(JOINT_SOURCE_BANK_SYMBOLS))
        {
            for (&bank, &companion) in bank_leaf.iter().zip(companion_leaf) {
                fields.push(bank);
                fields.push(companion);
            }
        }
        fields
    }

    fn fold_message(values: &[Block128], challenges: &[Block128]) -> Vec<Block128> {
        let mut folded = values.to_vec();
        for &challenge in challenges {
            fold_lowest_variable_in_place(&mut folded, challenge).expect("valid power-of-two fold");
        }
        folded
    }

    #[test]
    fn manifest_has_no_decoder_theorem_numeric_error_or_fork_extractor() {
        assert!(zk_auth_rbr_radius_matches_selected_ledger());
        assert_eq!(
            ZK_AUTH_SOURCE_RELATIVE_KNOWLEDGE_BOUNDARY.verifier_moves,
            30
        );
        assert_eq!(
            ZK_AUTH_SOURCE_RELATIVE_KNOWLEDGE_BOUNDARY.affine_minimum_distance_and_unique_radius,
            ZkAuthRbrBoundaryEvidence::ExternalProofRequired
        );
        assert_eq!(
            ZK_AUTH_SOURCE_RELATIVE_KNOWLEDGE_BOUNDARY.polynomial_time_unique_decoder,
            ZkAuthRbrBoundaryEvidence::ExternalProofRequired
        );
        assert_eq!(
            ZK_AUTH_SOURCE_RELATIVE_KNOWLEDGE_BOUNDARY.johnson_polynomial_time_list_decoder,
            ZkAuthRbrBoundaryEvidence::ExternalProofRequired
        );
        assert_eq!(
            ZK_AUTH_SOURCE_RELATIVE_KNOWLEDGE_BOUNDARY.bounded_list_candidate_selection,
            ZkAuthRbrBoundaryEvidence::ExternalProofRequired
        );
        assert_eq!(
            ZK_AUTH_SOURCE_RELATIVE_KNOWLEDGE_BOUNDARY.bounded_supplied_list_restoration_check,
            ZkAuthRbrBoundaryEvidence::Executable
        );
        assert_eq!(
            ZK_AUTH_SOURCE_RELATIVE_KNOWLEDGE_BOUNDARY.sr_typed_message_replay,
            ZkAuthRbrBoundaryEvidence::ExternalProofRequired
        );
        assert_eq!(
            ZK_AUTH_SOURCE_RELATIVE_KNOWLEDGE_BOUNDARY.sr_child_prefix_replay,
            ZkAuthRbrBoundaryEvidence::ExternalProofRequired
        );
        assert_eq!(
            ZK_AUTH_SOURCE_RELATIVE_KNOWLEDGE_BOUNDARY.grouped_common_agreement,
            ZkAuthRbrBoundaryEvidence::ExternalProofRequired
        );
        assert_eq!(
            ZK_AUTH_SOURCE_RELATIVE_KNOWLEDGE_BOUNDARY.numeric_rbr_bits,
            None
        );
        assert_eq!(zk_auth_iop_moves().len(), 30);
    }

    #[test]
    fn canonical_source_deinterleave_checks_supplied_candidates_without_decoding() {
        let code = ZkAffineLchCode::selected().expect("selected code");
        let bank_message = message(ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS, 0xB4A9);
        let companion_message = message(ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS, 0xC011);
        let bank_codeword = code.encode(&bank_message).expect("bank encoding");
        let companion_codeword = code.encode(&companion_message).expect("companion encoding");
        let interleaved = interleave_source(&bank_codeword, &companion_codeword);
        let source = ZkAuthLogicalSourceOracle::from_interleaved_fields(&interleaved)
            .expect("canonical source shape");
        let bank = source
            .check_supplied_bank_candidate(bank_message)
            .expect("supplied bank candidate");
        let companion = source
            .check_supplied_companion_candidate(companion_message)
            .expect("supplied companion candidate");
        assert_eq!(bank.domain(), ZkAuthAffineRestorationDomain::SourceBank);
        assert_eq!(
            companion.domain(),
            ZkAuthAffineRestorationDomain::SourceCompanion
        );
        assert_eq!(bank.hamming_distance(), 0);
        assert_eq!(companion.hamming_distance(), 0);
    }

    #[test]
    fn supplied_candidate_must_be_strictly_inside_selected_radius() {
        let code = ZkAffineLchCode::selected().expect("selected code");
        let mid_message = message(ZK_AUTH_RBR_MID_MESSAGE_FIELDS, 0xA11D);
        let mut mid_codeword = code
            .encode_after_low_folds(&mid_message, SOURCE_STANDARD_FOLDS)
            .expect("mid encoding");
        for (index, value) in mid_codeword
            .iter_mut()
            .take(ZK_AUTH_RBR_MID_MAX_RESTORATION_ERRORS + 1)
            .enumerate()
        {
            *value += elem(index, 0xBAD0) + Block128::ONE;
        }
        let mid = ZkAuthLogicalMidOracle::checked(mid_codeword).expect("mid shape");
        assert!(matches!(
            mid.check_supplied_candidate(mid_message),
            Err(ZkAuthRbrError::CandidateOutsideRestorationRadius {
                distance,
                maximum: ZK_AUTH_RBR_MID_MAX_RESTORATION_ERRORS,
                codeword_len: ZK_AUTH_RBR_MID_CODEWORD_FIELDS,
            }) if distance == ZK_AUTH_RBR_MID_MAX_RESTORATION_ERRORS + 1
        ));
    }

    #[test]
    fn exact_source_virtual_mid_tail_restoration_chain_closes() {
        let code = ZkAffineLchCode::selected().expect("selected code");
        let bank_message = message(ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS, 0xB001);
        let companion_message = message(ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS, 0xC002);
        let bank_codeword = code.encode(&bank_message).expect("bank encoding");
        let companion_codeword = code.encode(&companion_message).expect("companion encoding");
        let source = ZkAuthLogicalSourceOracle::checked(bank_codeword, companion_codeword)
            .expect("source shape");
        let bank = source
            .check_supplied_bank_candidate(bank_message.clone())
            .expect("bank candidate");
        let companion = source
            .check_supplied_companion_candidate(companion_message.clone())
            .expect("companion candidate");

        let gamma = elem(1, 0x6A11) + Block128::from(2u128);
        assert_ne!(gamma, Block128::ZERO);
        assert_ne!(gamma, Block128::ONE);
        let beta_source = std::array::from_fn(|index| elem(index + 7, 0xBE70));
        let beta_mid = std::array::from_fn(|index| elem(index + 17, 0xBE71));
        let virtual_oracle =
            phase_a_virtual_oracle(&bank_message, &companion_message, gamma).expect("virtual");
        let mid_message = fold_message(&virtual_oracle, &beta_source);
        let mid_codeword = code
            .encode_after_low_folds(&mid_message, SOURCE_STANDARD_FOLDS)
            .expect("mid encoding");
        let mid_oracle = ZkAuthLogicalMidOracle::checked(mid_codeword).expect("mid shape");
        let mid = mid_oracle
            .check_supplied_candidate(mid_message.clone())
            .expect("mid candidate");
        let tail_vec = fold_message(&mid_message, &beta_mid);
        let tail: [Block128; TAIL_SYMBOLS] = tail_vec.try_into().expect("tail16");

        let evidence = check_zk_auth_exact_restoration_chain(
            &source,
            &bank,
            &companion,
            gamma,
            beta_source,
            &mid_oracle,
            &mid,
            beta_mid,
            &tail,
        )
        .expect("exact restoration chain");
        assert_eq!(
            evidence.virtual_message_fields(),
            ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS
        );
        assert_eq!(
            evidence.mid_message_fields(),
            ZK_AUTH_RBR_MID_MESSAGE_FIELDS
        );
        assert_eq!(evidence.tail_fields(), TAIL_SYMBOLS);

        let unrelated_bank_message = message(ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS, 0xDEAD);
        let unrelated_source = ZkAuthLogicalSourceOracle::checked(
            code.encode(&unrelated_bank_message)
                .expect("unrelated bank encoding"),
            code.encode(&companion_message)
                .expect("unrelated companion encoding"),
        )
        .expect("unrelated source shape");
        let unrelated_bank = unrelated_source
            .check_supplied_bank_candidate(unrelated_bank_message)
            .expect("unrelated bank candidate");
        assert!(matches!(
            check_zk_auth_exact_restoration_chain(
                &source,
                &unrelated_bank,
                &companion,
                gamma,
                beta_source,
                &mid_oracle,
                &mid,
                beta_mid,
                &tail,
            ),
            Err(ZkAuthRbrError::CandidateOutsideRestorationRadius { .. })
        ));

        let mut changed_mid_message = mid_message.clone();
        changed_mid_message[5] += Block128::ONE;
        let changed_mid_oracle = ZkAuthLogicalMidOracle::checked(
            code.encode_after_low_folds(&changed_mid_message, SOURCE_STANDARD_FOLDS)
                .expect("changed mid encoding"),
        )
        .expect("changed mid shape");
        let changed_mid = changed_mid_oracle
            .check_supplied_candidate(changed_mid_message)
            .expect("changed mid candidate");
        assert_eq!(
            check_zk_auth_exact_restoration_chain(
                &source,
                &bank,
                &companion,
                gamma,
                beta_source,
                &changed_mid_oracle,
                &changed_mid,
                beta_mid,
                &tail,
            ),
            Err(ZkAuthRbrError::SourceToMidRestorationMismatch { index: 5 })
        );

        let mut bad_tail = tail;
        bad_tail[9] += Block128::ONE;
        assert_eq!(
            check_zk_auth_exact_restoration_chain(
                &source,
                &bank,
                &companion,
                gamma,
                beta_source,
                &mid_oracle,
                &mid,
                beta_mid,
                &bad_tail,
            ),
            Err(ZkAuthRbrError::MidToTailRestorationMismatch { index: 9 })
        );
    }

    #[test]
    fn checked_bank_extracts_nonserializable_secret_witness() {
        let iv = capacity_iv(TAG_ADDRFIX);
        let secret = [elem(1, 0x5EC2E7), elem(2, 0x5EC2E7)];
        let permutation = evaluate_permutation([secret[0], secret[1], iv[0], iv[1]]);
        let address = [permutation.final_state()[0], permutation.final_state()[1]];
        let state =
            ZkAuthCapsuleStateTable::from_permutation_witness(&permutation).expect("state table");
        let mut bank_message = message(ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS, 0xA771);
        bank_message[..ZK_AUTH_CAPSULE_STATE_LEN].copy_from_slice(state.cells());
        let companion_message = message(ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS, 0xC099);
        let code = ZkAffineLchCode::selected().expect("selected code");
        let source = ZkAuthLogicalSourceOracle::checked(
            code.encode(&bank_message).expect("bank encoding"),
            code.encode(&companion_message).expect("companion encoding"),
        )
        .expect("source shape");
        let bank = source
            .check_supplied_bank_candidate(bank_message.clone())
            .expect("bank candidate");
        let statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [elem(4, 0x7AB0), elem(5, 0x7AB0)],
            address,
        };
        let witness =
            extract_zk_auth_knowledge_witness_from_supplied_candidate(statement, &source, &bank)
                .expect("knowledge witness");
        assert!(witness.matches_statement(statement));

        let changed = ZkAuthCapsuleOwnerStatement {
            address: [address[0] + Block128::ONE, address[1]],
            ..statement
        };
        assert!(
            extract_zk_auth_knowledge_witness_from_supplied_candidate(changed, &source, &bank)
                .is_err()
        );

        let mut johnson_bank_word = code.encode(&bank_message).expect("Johnson bank encoding");
        for (index, value) in johnson_bank_word
            .iter_mut()
            .take(ZK_AUTH_RBR_SOURCE_MAX_RESTORATION_ERRORS + 1)
            .enumerate()
        {
            *value += Block128::from(index as u128 + 1);
        }
        let johnson_source = ZkAuthLogicalSourceOracle::checked(
            johnson_bank_word,
            code.encode(&companion_message)
                .expect("Johnson companion encoding"),
        )
        .expect("Johnson source shape");
        assert!(matches!(
            johnson_source.check_supplied_bank_candidate(bank_message.clone()),
            Err(ZkAuthRbrError::CandidateOutsideRestorationRadius { .. })
        ));
        assert!(matches!(
            extract_zk_auth_knowledge_witness_from_supplied_candidate(
                statement,
                &johnson_source,
                &bank,
            ),
            Err(ZkAuthRbrError::CandidateOutsideRestorationRadius { .. })
        ));
        let mut invalid_candidate = bank_message.clone();
        invalid_candidate[0] += Block128::ONE;
        assert!(matches!(
            scan_supplied_johnson_bank_candidate_list(
                statement,
                &johnson_source,
                vec![bank_message.clone(); ZK_AUTH_JOHNSON_MAX_CANDIDATES + 1],
            ),
            Err(ZkAuthRbrError::SuppliedCandidateListTooLong {
                maximum: ZK_AUTH_JOHNSON_MAX_CANDIDATES,
                actual: 18,
            })
        ));
        let johnson_witness = scan_supplied_johnson_bank_candidate_list(
            statement,
            &johnson_source,
            vec![invalid_candidate, bank_message],
        )
        .expect("straight-line Johnson candidate selection");
        assert!(johnson_witness.matches_statement(statement));
    }

    fn mix_codewords_at_differences(
        base: &[Block128],
        alternate: &[Block128],
        replacements: usize,
    ) -> Vec<Block128> {
        assert_eq!(base.len(), alternate.len());
        assert!(
            base.iter()
                .zip(alternate)
                .filter(|(left, right)| left != right)
                .count()
                >= replacements
        );
        let mut mixed = base.to_vec();
        let mut replaced = 0usize;
        for (index, (&base_value, &alternate_value)) in base.iter().zip(alternate).enumerate() {
            if replaced == replacements {
                break;
            }
            if base_value != alternate_value {
                mixed[index] = alternate_value;
                replaced += 1;
            }
        }
        assert_eq!(replaced, replacements);
        mixed
    }

    struct JohnsonRestorationFixture {
        statement: ZkAuthCapsuleOwnerStatement,
        source: ZkAuthLogicalSourceOracle,
        mid_oracle: ZkAuthLogicalMidOracle,
        bank_message: Vec<Block128>,
        invalid_bank_message: Vec<Block128>,
        companion_message: Vec<Block128>,
        wrong_companion_message: Vec<Block128>,
        mid_message: Vec<Block128>,
        wrong_mid_message: Vec<Block128>,
        gamma: Block128,
        beta_source: [Block128; SOURCE_STANDARD_FOLDS],
        beta_mid: [Block128; MID_STANDARD_FOLDS],
        tail: [Block128; TAIL_SYMBOLS],
    }

    fn johnson_restoration_fixture() -> JohnsonRestorationFixture {
        const SOURCE_REPLACEMENTS: usize = 32_000;
        const MID_REPLACEMENTS: usize = 4_000;

        let iv = capacity_iv(TAG_ADDRFIX);
        let secret = [elem(31, 0xA17E), elem(32, 0xA17E)];
        let permutation = evaluate_permutation([secret[0], secret[1], iv[0], iv[1]]);
        let address = [permutation.final_state()[0], permutation.final_state()[1]];
        let state =
            ZkAuthCapsuleStateTable::from_permutation_witness(&permutation).expect("state table");
        let mut bank_message = message(ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS, 0xB417);
        bank_message[..ZK_AUTH_CAPSULE_STATE_LEN].copy_from_slice(state.cells());
        let mut invalid_bank_message = bank_message.clone();
        invalid_bank_message[0] += Block128::ONE;

        let companion_message = message(ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS, 0xC417);
        let wrong_companion_message = message(ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS, 0xC0FFEE);
        let gamma = elem(41, 0x6A17) + Block128::from(2u128);
        assert_ne!(gamma, Block128::ZERO);
        assert_ne!(gamma, Block128::ONE);
        let beta_source: [Block128; SOURCE_STANDARD_FOLDS] =
            std::array::from_fn(|index| elem(index + 51, 0xBEA0));
        let beta_mid: [Block128; MID_STANDARD_FOLDS] =
            std::array::from_fn(|index| elem(index + 61, 0xBEA1));

        let virtual_oracle =
            phase_a_virtual_oracle(&bank_message, &companion_message, gamma).expect("virtual");
        let mid_message = fold_message(&virtual_oracle, &beta_source);
        let wrong_virtual_oracle =
            phase_a_virtual_oracle(&bank_message, &wrong_companion_message, gamma)
                .expect("wrong virtual");
        let wrong_mid_message = fold_message(&wrong_virtual_oracle, &beta_source);
        assert_ne!(mid_message, wrong_mid_message);
        let tail: [Block128; TAIL_SYMBOLS] = fold_message(&mid_message, &beta_mid)
            .try_into()
            .expect("tail16");

        let code = ZkAffineLchCode::selected().expect("selected code");
        let bank_encoding = code.encode(&bank_message).expect("bank encoding");
        let invalid_bank_encoding = code
            .encode(&invalid_bank_message)
            .expect("invalid bank encoding");
        let companion_encoding = code.encode(&companion_message).expect("companion encoding");
        let wrong_companion_encoding = code
            .encode(&wrong_companion_message)
            .expect("wrong companion encoding");
        let mid_encoding = code
            .encode_after_low_folds(&mid_message, SOURCE_STANDARD_FOLDS)
            .expect("mid encoding");
        let wrong_mid_encoding = code
            .encode_after_low_folds(&wrong_mid_message, SOURCE_STANDARD_FOLDS)
            .expect("wrong mid encoding");

        let source = ZkAuthLogicalSourceOracle::checked(
            mix_codewords_at_differences(
                &bank_encoding,
                &invalid_bank_encoding,
                SOURCE_REPLACEMENTS,
            ),
            mix_codewords_at_differences(
                &companion_encoding,
                &wrong_companion_encoding,
                SOURCE_REPLACEMENTS,
            ),
        )
        .expect("mixed source shape");
        let mid_oracle = ZkAuthLogicalMidOracle::checked(mix_codewords_at_differences(
            &mid_encoding,
            &wrong_mid_encoding,
            MID_REPLACEMENTS,
        ))
        .expect("mixed mid shape");
        let statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [elem(71, 0x7AB0), elem(72, 0x7AB0)],
            address,
        };
        assert!(extract_witness_from_bank_message(statement, &invalid_bank_message).is_err());

        JohnsonRestorationFixture {
            statement,
            source,
            mid_oracle,
            bank_message,
            invalid_bank_message,
            companion_message,
            wrong_companion_message,
            mid_message,
            wrong_mid_message,
            gamma,
            beta_source,
            beta_mid,
            tail,
        }
    }

    #[test]
    fn supplied_johnson_lists_select_first_exact_auth_valid_triple() {
        let fixture = johnson_restoration_fixture();
        assert_eq!(ZK_AUTH_JOHNSON_MAX_CANDIDATES, 17);
        assert_eq!(ZK_AUTH_JOHNSON_MAX_RESTORATION_TRIPLES, 4_913);
        assert!(matches!(
            fixture
                .source
                .check_supplied_bank_candidate(fixture.bank_message.clone()),
            Err(ZkAuthRbrError::CandidateOutsideRestorationRadius { .. })
        ));
        assert!(matches!(
            fixture
                .source
                .check_supplied_companion_candidate(fixture.companion_message.clone()),
            Err(ZkAuthRbrError::CandidateOutsideRestorationRadius { .. })
        ));
        assert!(matches!(
            fixture
                .mid_oracle
                .check_supplied_candidate(fixture.mid_message.clone()),
            Err(ZkAuthRbrError::CandidateOutsideRestorationRadius { .. })
        ));

        let selection = scan_supplied_johnson_restoration_candidate_lists(
            fixture.statement,
            &fixture.source,
            &fixture.mid_oracle,
            vec![
                fixture.invalid_bank_message.clone(),
                fixture.bank_message.clone(),
            ],
            vec![
                fixture.wrong_companion_message.clone(),
                fixture.companion_message.clone(),
            ],
            vec![
                fixture.wrong_mid_message.clone(),
                fixture.mid_message.clone(),
            ],
            fixture.gamma,
            fixture.beta_source,
            fixture.beta_mid,
            &fixture.tail,
        )
        .expect("first consistent Johnson triple");
        assert!(selection.matches_statement(fixture.statement));
        let evidence = selection.evidence();
        assert_eq!(evidence.bank_candidate_index(), 1);
        assert_eq!(evidence.companion_candidate_index(), 1);
        assert_eq!(evidence.mid_candidate_index(), 1);
        assert_eq!(evidence.bank_distance(), 32_000);
        assert_eq!(evidence.companion_distance(), 32_000);
        assert_eq!(evidence.mid_distance(), 4_000);
        assert_eq!(evidence.triples_examined(), 8);
        assert!(evidence.triples_examined() <= ZK_AUTH_JOHNSON_MAX_RESTORATION_TRIPLES);
    }

    #[test]
    fn supplied_johnson_bank_radius_uses_the_exact_inclusive_integer_boundary() {
        let fixture = johnson_restoration_fixture();
        let code = ZkAffineLchCode::selected().unwrap();
        let mut bank_word = code.encode(&fixture.bank_message).unwrap();
        let maximum_distance = bank_word.len() * 4 / 5;
        for value in bank_word.iter_mut().take(maximum_distance) {
            *value += Block128::ONE;
        }
        let companion_word = code.encode(&fixture.companion_message).unwrap();
        let source =
            ZkAuthLogicalSourceOracle::checked(bank_word.clone(), companion_word.clone()).unwrap();
        assert!(scan_supplied_johnson_bank_candidate_list(
            fixture.statement,
            &source,
            vec![fixture.bank_message.clone()],
        )
        .unwrap()
        .matches_statement(fixture.statement));

        bank_word[maximum_distance] += Block128::ONE;
        let outside = ZkAuthLogicalSourceOracle::checked(bank_word, companion_word).unwrap();
        assert!(matches!(
            scan_supplied_johnson_bank_candidate_list(
                fixture.statement,
                &outside,
                vec![fixture.bank_message],
            ),
            Err(ZkAuthRbrError::NoValidSuppliedCandidate)
        ));
    }

    #[test]
    fn supplied_johnson_lists_reject_tail_statement_and_cross_chain_tampering() {
        let fixture = johnson_restoration_fixture();
        let mut bad_tail = fixture.tail;
        bad_tail[3] += Block128::ONE;
        assert!(matches!(
            scan_supplied_johnson_restoration_candidate_lists(
                fixture.statement,
                &fixture.source,
                &fixture.mid_oracle,
                vec![fixture.bank_message.clone()],
                vec![fixture.companion_message.clone()],
                vec![fixture.mid_message.clone()],
                fixture.gamma,
                fixture.beta_source,
                fixture.beta_mid,
                &bad_tail,
            ),
            Err(ZkAuthRbrError::NoConsistentSuppliedRestorationTriple)
        ));

        let changed_statement = ZkAuthCapsuleOwnerStatement {
            address: [
                fixture.statement.address[0] + Block128::ONE,
                fixture.statement.address[1],
            ],
            ..fixture.statement
        };
        assert!(matches!(
            scan_supplied_johnson_restoration_candidate_lists(
                changed_statement,
                &fixture.source,
                &fixture.mid_oracle,
                vec![fixture.bank_message.clone()],
                vec![fixture.companion_message.clone()],
                vec![fixture.mid_message.clone()],
                fixture.gamma,
                fixture.beta_source,
                fixture.beta_mid,
                &fixture.tail,
            ),
            Err(ZkAuthRbrError::NoConsistentSuppliedRestorationTriple)
        ));

        assert!(matches!(
            scan_supplied_johnson_restoration_candidate_lists(
                fixture.statement,
                &fixture.source,
                &fixture.mid_oracle,
                vec![fixture.bank_message.clone()],
                vec![fixture.wrong_companion_message.clone()],
                vec![fixture.mid_message.clone()],
                fixture.gamma,
                fixture.beta_source,
                fixture.beta_mid,
                &fixture.tail,
            ),
            Err(ZkAuthRbrError::NoConsistentSuppliedRestorationTriple)
        ));
    }

    #[test]
    fn supplied_johnson_restoration_caps_every_candidate_list_at_seventeen() {
        let source = ZkAuthLogicalSourceOracle::checked(
            vec![Block128::ZERO; ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS],
            vec![Block128::ZERO; ZK_AUTH_RBR_SOURCE_CODEWORD_FIELDS],
        )
        .expect("source shape");
        let mid_oracle =
            ZkAuthLogicalMidOracle::checked(vec![Block128::ZERO; ZK_AUTH_RBR_MID_CODEWORD_FIELDS])
                .expect("mid shape");
        let source_candidate = vec![Block128::ZERO; ZK_AUTH_RBR_SOURCE_MESSAGE_FIELDS];
        let mid_candidate = vec![Block128::ZERO; ZK_AUTH_RBR_MID_MESSAGE_FIELDS];
        let statement = ZkAuthCapsuleOwnerStatement {
            tx_body_hash: [Block128::ZERO; 2],
            address: [Block128::ZERO; 2],
        };
        let gamma = Block128::from(2u128);
        let beta_source = [Block128::ZERO; SOURCE_STANDARD_FOLDS];
        let beta_mid = [Block128::ZERO; MID_STANDARD_FOLDS];
        let tail = [Block128::ZERO; TAIL_SYMBOLS];

        assert!(matches!(
            scan_supplied_johnson_restoration_candidate_lists(
                statement,
                &source,
                &mid_oracle,
                vec![source_candidate.clone(); ZK_AUTH_JOHNSON_MAX_CANDIDATES + 1],
                vec![source_candidate.clone()],
                vec![mid_candidate.clone()],
                gamma,
                beta_source,
                beta_mid,
                &tail,
            ),
            Err(ZkAuthRbrError::SuppliedRestorationCandidateListTooLong {
                domain: ZkAuthAffineRestorationDomain::SourceBank,
                maximum: ZK_AUTH_JOHNSON_MAX_CANDIDATES,
                actual: 18,
            })
        ));
        assert!(matches!(
            scan_supplied_johnson_restoration_candidate_lists(
                statement,
                &source,
                &mid_oracle,
                vec![source_candidate.clone()],
                vec![source_candidate.clone(); ZK_AUTH_JOHNSON_MAX_CANDIDATES + 1],
                vec![mid_candidate.clone()],
                gamma,
                beta_source,
                beta_mid,
                &tail,
            ),
            Err(ZkAuthRbrError::SuppliedRestorationCandidateListTooLong {
                domain: ZkAuthAffineRestorationDomain::SourceCompanion,
                maximum: ZK_AUTH_JOHNSON_MAX_CANDIDATES,
                actual: 18,
            })
        ));
        assert!(matches!(
            scan_supplied_johnson_restoration_candidate_lists(
                statement,
                &source,
                &mid_oracle,
                vec![source_candidate.clone()],
                vec![source_candidate],
                vec![mid_candidate; ZK_AUTH_JOHNSON_MAX_CANDIDATES + 1],
                gamma,
                beta_source,
                beta_mid,
                &tail,
            ),
            Err(ZkAuthRbrError::SuppliedRestorationCandidateListTooLong {
                domain: ZkAuthAffineRestorationDomain::Mid,
                maximum: ZK_AUTH_JOHNSON_MAX_CANDIDATES,
                actual: 18,
            })
        ));
    }

    fn branch(
        parent: u64,
        move_index: usize,
        message: &[u8],
        challenge_seed: u128,
        child: u64,
    ) -> ZkAuthSrForkBranch {
        let width = zk_auth_iop_moves()[move_index].challenge_fields();
        ZkAuthSrForkBranch::new(
            ZkAuthSrCheckpointId::new(parent),
            move_index,
            message.to_vec(),
            (0..width)
                .map(|index| elem(index, challenge_seed))
                .collect(),
            ZkAuthSrCheckpointId::new(child),
        )
    }

    #[test]
    fn sr_forks_require_canonical_lineage_and_identical_precoin_message() {
        let root = ZkAuthSrCheckpointId::new(0);
        let mut trace = ZkAuthSrForkTrace::new(root);
        trace.push_fork(ZkAuthSrFork::new(vec![
            branch(0, 0, b"fixed source oracle", 0xA0, 1),
            branch(0, 0, b"fixed source oracle", 0xB0, 2),
        ]));
        trace.push_fork(ZkAuthSrFork::new(vec![
            branch(1, 1, b"fixed mask evaluation", 0xA1, 3),
            branch(1, 1, b"fixed mask evaluation", 0xB1, 4),
        ]));
        let validated = validate_zk_auth_sr_fork_trace(&trace).expect("valid lineage");
        assert_eq!(validated.forks(), 2);
        assert_eq!(validated.branches(), 4);
        assert_eq!(validated.checkpoints(), 5);
        assert_eq!(validated.deepest_completed_move(), 2);
        assert!(!validated.fork_interpolation_performed());

        let mut changed_message = ZkAuthSrForkTrace::new(root);
        changed_message.push_fork(ZkAuthSrFork::new(vec![
            branch(0, 0, b"source A", 0xA2, 10),
            branch(0, 0, b"source B", 0xB2, 11),
        ]));
        assert_eq!(
            validate_zk_auth_sr_fork_trace(&changed_message),
            Err(ZkAuthSrForkError::FixedMessageMismatch)
        );

        let mut changed_parent = ZkAuthSrForkTrace::new(root);
        changed_parent.push_fork(ZkAuthSrFork::new(vec![
            branch(0, 0, b"same source", 0xA4, 14),
            branch(99, 0, b"same source", 0xB4, 15),
        ]));
        assert_eq!(
            validate_zk_auth_sr_fork_trace(&changed_parent),
            Err(ZkAuthSrForkError::ParentMismatch)
        );

        let mut repeated_parent = ZkAuthSrForkTrace::new(root);
        repeated_parent.push_fork(ZkAuthSrFork::new(vec![
            branch(0, 0, b"first source", 0xA5, 16),
            branch(0, 0, b"first source", 0xB5, 17),
        ]));
        repeated_parent.push_fork(ZkAuthSrFork::new(vec![
            branch(0, 0, b"second source", 0xA6, 18),
            branch(0, 0, b"second source", 0xB6, 19),
        ]));
        assert_eq!(
            validate_zk_auth_sr_fork_trace(&repeated_parent),
            Err(ZkAuthSrForkError::ParentAlreadyExpanded { parent: root })
        );

        let mut endpoint_coin = ZkAuthSrForkTrace::new(root);
        endpoint_coin.push_fork(ZkAuthSrFork::new(vec![
            branch(0, 0, b"source", 0xA7, 20),
            branch(0, 0, b"source", 0xB7, 21),
        ]));
        endpoint_coin.push_fork(ZkAuthSrFork::new(vec![
            ZkAuthSrForkBranch::new(
                ZkAuthSrCheckpointId::new(20),
                1,
                b"mask evaluation".to_vec(),
                vec![Block128::ZERO],
                ZkAuthSrCheckpointId::new(22),
            ),
            ZkAuthSrForkBranch::new(
                ZkAuthSrCheckpointId::new(20),
                1,
                b"mask evaluation".to_vec(),
                vec![Block128::from(2u128)],
                ZkAuthSrCheckpointId::new(23),
            ),
        ]));
        assert_eq!(
            validate_zk_auth_sr_fork_trace(&endpoint_coin),
            Err(ZkAuthSrForkError::InadmissibleChallenge {
                branch: 0,
                move_index: 1,
            })
        );

        let mut skipped_move = ZkAuthSrForkTrace::new(root);
        skipped_move.push_fork(ZkAuthSrFork::new(vec![
            branch(0, 1, b"wrong next move", 0xA3, 12),
            branch(0, 1, b"wrong next move", 0xB3, 13),
        ]));
        assert_eq!(
            validate_zk_auth_sr_fork_trace(&skipped_move),
            Err(ZkAuthSrForkError::MoveDoesNotFollowParent {
                parent: root,
                expected: 0,
                actual: 1,
            })
        );
    }
}
