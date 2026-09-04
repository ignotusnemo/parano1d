// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Binary-field commitments and production authorization-capsule PCS
//! components.
//!
//! Wallet authorization uses the capsule proof system and its source-linked
//! soundness ledger. Raw State segments retain their established interleaved
//! cap format for root compatibility, while exact sparse-Merkle proofs
//! authorize production State transitions.

pub mod capsule;
pub mod encode_kernel;
pub mod interleaved_commit;
pub mod zk_affine_code;
pub mod zk_capsule;
pub mod zk_capsule_algebra;
pub mod zk_capsule_pcs;
pub mod zk_phase_a;

pub use capsule::{
    absorb_capsule_commitment, capsule_commit, capsule_open, capsule_queries_from_seeds,
    capsule_query_bit_location, capsule_query_seed_count, capsule_verify, CapsuleCommitment,
    CapsuleOpeningProof, CapsuleProverState, CAPSULE_CAP_DEPTH, CAPSULE_GRIND_BITS,
    CAPSULE_LOG_RATE, CAPSULE_NUM_QUERIES, CAPSULE_QUERY_SEED_BITS, CAPSULE_TAU, CAPSULE_WIDE_LOG,
};
pub use interleaved_commit::{
    expand_source_batched_merkle_proof_to_cap, interleaved_commit_cap, CommitmentHashBackend,
    IndependentSourceMerklePath, MerkleCap,
};
pub use zk_capsule::{
    ZkCapsuleGeometry, ZkCapsuleGeometryError, ZkCapsuleParameters,
    QUERY_BITS_REQUIRING_AUX_CARRIER, ZK_AUTH_CAPSULE_GEOMETRY, ZK_AUTH_CAPSULE_PARAMETERS,
};
pub use zk_capsule_algebra::{
    build_joint_source_leaf, build_mid_leaf, certify_source_query_hiding_rank,
    contract_high3_for_each_low8, encode_tail16, eq_high_zero,
    evaluate_fundamental_slice_embedding, evaluate_upper_at_low8, fold_bank_low8,
    fold_joint_source_leaf, fundamental_slice_alignment_point,
    fundamental_slice_relation_embedding, interleave_joint_source_leaf, joint_source_line_fold,
    map_source_query_leaf, mid_standard_fold4, source_leaf_from_query_bits, source_query_bits,
    source_standard_fold3, tail16_local_fold, ZkCapsuleAlgebraError, ZkCapsuleQueryMapping,
};
pub use zk_capsule_pcs::{
    flat_digest_to_tower_lanes, tower_lanes_to_flat_digest, zk_capsule_pcs_bind_owner,
    zk_capsule_pcs_bind_phase_a, zk_capsule_pcs_commit_fresh, zk_capsule_pcs_commit_mid,
    zk_capsule_pcs_link_phase_b, zk_capsule_pcs_open, zk_capsule_pcs_prove_phase_a,
    zk_capsule_pcs_reveal_tail, zk_capsule_pcs_verify, ZkCapsulePcsError,
    ZkCapsulePcsMidCommitment, ZkCapsulePcsMidProverState, ZkCapsulePcsOpening,
    ZkCapsulePcsOwnerBoundProverState, ZkCapsulePcsPhaseABinding,
    ZkCapsulePcsPhaseABoundProverState, ZkCapsulePcsPhaseACompleteProverState,
    ZkCapsulePcsPhaseBLink, ZkCapsulePcsPhaseBReadyProverState, ZkCapsulePcsSourceCommitment,
    ZkCapsulePcsSourceProverState, ZkCapsulePcsTailProverState, ZkCapsulePcsTailReveal,
    ZkCapsulePcsVerified,
};
pub use zk_phase_a::{
    phase_a_initial_claim, phase_a_relation_claims, phase_a_terminal_point, phase_a_virtual_oracle,
    prove_phase_a, prove_phase_a_adaptive, prove_phase_a_from_virtual_oracle_adaptive,
    verify_phase_a, ZkPhaseAError, ZkPhaseAProof, ZkPhaseAProverOutput, ZkPhaseARelationClaims,
    ZkPhaseARoundProof, ZkPhaseAVerifierOutput, PHASE_A_ROUND_DEGREE,
};

/// Top levels of Merkle tree stored in the cap commitment.
/// 2^5 = 32 hash nodes at cap level.
pub const MERKLE_CAP_DEPTH: usize = 5;
