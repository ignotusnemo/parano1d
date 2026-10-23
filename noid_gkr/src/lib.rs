// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Proof components for the Paranoid transaction system.
//!
//! This crate provides:
//!
//! - **Selected ZK authorization**: a witness-hiding AuthGKR/Binary BaseFold
//!   proof of the transaction's single input owner.
//! - **Poseidon2b spine components**: reusable Kill-Shot proofs for fixed
//!   permutation batches such as tx-body hashing, accepted-claim hashing,
//!   state-root hashing, and chain accumulation.
//! - **Merkle GKR**: proves batches of Poseidon2b Merkle paths through the
//!   same Kill-Shot permutation relation.
//!
//! The pre-ZK owner-auth proof and its standalone capsule PCS were removed
//! from the production API. These compile-fail gates prevent either surface
//! from being restored accidentally:
//!
//! ```compile_fail
//! use noid_gkr::{prove_owner_auth_killshot, OwnerAuthProofKillShot};
//! ```
//!
//! ```compile_fail
//! use noid_gkr::auth_pcs::AuthMleOpeningProof;
//! ```
//!
//! ```compile_fail
//! let _ = noid_gkr::ghost_tx::ghost_authorization();
//! ```

pub mod accepted_claim_killshot;
pub mod authorization_profile;
pub mod batch_eval;
pub mod block_spine;
pub mod circuit;
pub mod fixed_field_hash_killshot;
pub mod ghost_tx;
pub mod header_hash_killshot;
pub mod history_claim_killshot;
pub mod layers;
pub mod merkle_batch_killshot;
pub mod merkle_circuit;
pub mod merkle_oracle;
pub mod mle_layout;
pub mod oracle;
mod owner_auth;
pub mod spine_killshot;
pub mod spine_mle;
pub mod spine_shift;
pub mod spine_statement;
pub mod spine_sumcheck;
pub mod spine_unified;
pub mod state_leaf_killshot;
pub mod tx_body_layout;
pub mod wallet_authorization;
pub mod zk_auth_capsule;
pub mod zk_auth_hiding;
pub mod zk_auth_qrom;
pub mod zk_auth_rbr;
pub mod zk_authorization;
pub mod zk_authorization_wire;
pub mod zk_mlecheck;

pub use accepted_claim_killshot::{
    discharge_accepted_claim_hash_reductions_native, prove_accepted_claim_hash_killshot,
    verify_accepted_claim_hash_killshot, AcceptedClaimHashInputs, AcceptedClaimHashProofKillShot,
    AcceptedClaimHashReductions, ACCEPTED_CLAIM_FIELDS,
};
pub use batch_eval::{
    prove_batch_eval, prove_multi_batch_eval, verify_batch_eval, verify_multi_batch_eval,
    BatchEvalProof, BatchEvalReduction, BatchEvalRound, EvalClaim, MultiBatchEvalProof,
};
pub use block_spine::{
    discharge_block_spine_batch_reductions_from_slot_state_ins_native,
    discharge_block_spine_reductions_native, evaluate_block_spine_columns_from_slot_state_ins,
    prove_block_spine_killshot, verify_block_spine_killshot, BlockSpineKillShotProof,
    BlockSpineMle, BlockSpineProof, BlockSpineReductions, BlockSpineShiftProof,
    BlockSpineShiftReduction, BlockSpineUnifiedProof, BlockSpineUnifiedReduction,
    BLOCK_SPINE_ROUND_DEGREE, BLOCK_SPINE_SHIFT_DEGREE,
};
pub use circuit::{SlotDescriptor, SpineCircuit, SpineInputs};
pub use fixed_field_hash_killshot::{
    discharge_fixed_field_hash_reductions_native, prove_fixed_field_hash_killshot,
    verify_fixed_field_hash_killshot, FixedFieldHashInputs, FixedFieldHashParams,
    FixedFieldHashProofKillShot, FixedFieldHashReductions, FIXED_FIELD_HASH_PIN_LANES,
};
pub use header_hash_killshot::{
    discharge_header_hash_reductions_native, discharge_header_hash_reductions_native_padded,
    prove_header_hash_killshot, prove_header_hash_killshot_padded, verify_header_hash_killshot,
    verify_header_hash_killshot_padded, HeaderHashInputs, HeaderHashProofKillShot,
    HeaderHashReductions, HEADER_HASH_FIELDS,
};
pub use history_claim_killshot::{
    discharge_history_claim_hash_reductions_native, prove_history_claim_hash_killshot,
    verify_history_claim_hash_killshot, HistoryClaimHashInputs, HistoryClaimHashProofKillShot,
    HistoryClaimHashReductions, HISTORY_CLAIM_FIELDS,
};
pub use layers::{evaluate_permutation, round_kind, PermLayerWitness, RoundKind};
pub use merkle_batch_killshot::{
    discharge_batched_merkle_reductions_native, prove_batched_merkle_killshot,
    verify_batched_merkle_killshot, BatchedMerkleKillShotReductions, BatchedMerkleProofKillShot,
};
pub use merkle_circuit::{
    MerkleCircuit, MerklePathInputs, MerkleSlotDescriptor, MerkleSlotRole, MAX_MERKLE_DEPTH,
    N_MERKLE_SLOTS, N_PERMS_PER_COMPRESS,
};
pub use merkle_oracle::{compute_merkle_root, evaluate_merkle, MerkleSlotState, MerkleWitness};
pub use mle_layout::{pack_column, PermColumn, PermMle, N_PERM_CELLS, N_PERM_VARS};
pub use oracle::{evaluate_spine, SpineWitness};
pub use owner_auth::{
    owner_auth_public_from_body, owner_auth_public_from_statement, OwnerAuthLayout,
    OwnerAuthPublicInputs, OwnerAuthStatementError, OWNER_AUTH_NUM_VARS,
};
pub use spine_killshot::{
    build_unified_from_inputs, build_unified_from_states, discharge_reductions_native,
    prove_spine_killshot, prove_spine_killshot_with_states, verify_spine_killshot,
    SpineKillShotReductions, SpineProofKillShot,
};
pub use spine_mle::{
    build_unified_mle, sigma_at, SpineUnifiedMle, N_SPINE_ELEM_VARS, N_SPINE_ROUND_VARS,
    N_SPINE_SLOT_VARS, N_SPINE_UNIFIED_CELLS, N_SPINE_UNIFIED_VARS,
};
pub use spine_shift::{
    build_mds_lane_table, build_mu_table, build_rc_table, build_sigma_table, build_u_table,
    dec_round_index, elem_of, inc_round_index, mds_coeff, mu_evaluate, pack_index, permute_by_dec,
    project_lane, rc_evaluate, round_of, sigma_evaluate, slot_of,
};
pub use spine_shift::{
    build_mds_lane_table_for_live_slots, build_mu_table_for_live_slots,
    build_rc_table_for_live_slots, build_sigma_table_for_live_slots, build_u_table_for_live_slots,
};
pub use spine_statement::spine_inputs_from_body;
pub use spine_sumcheck::{
    build_boundary_mle, compute_tx_body_hash, discharge_boundary_native, reconstruct_slot_states,
    N_BOUNDARY_CELLS, N_BOUNDARY_VARS, N_SLOT_VARS, N_SPINE_SLOTS, N_SPINE_SLOTS_PADDED,
};
pub use spine_unified::{
    prove_spine_shift, prove_spine_unified, prove_spine_unified_for_live_slots, verify_spine_shift,
    verify_spine_unified, verify_spine_unified_for_live_slots, SpineKillShotProof, SpineShiftProof,
    SpineShiftReduction, SpineUnifiedProof, SpineUnifiedReduction, N_UNIFIED_WITNESS_CLAIMS,
    SPINE_SHIFT_ROUND_DEGREE, SPINE_UNIFIED_ROUND_DEGREE,
};
pub use state_leaf_killshot::{
    discharge_batched_slot_leaf_reductions_native, prove_batched_slot_leaf_killshot,
    verify_batched_slot_leaf_killshot, BatchedSlotLeafProofKillShot, BatchedSlotLeafReductions,
    SlotLeafInputs,
};
pub use tx_body_layout::{
    build_instance_layout, InstanceMeta, InstanceRole, TXBODY_N_TREE_LEAVES, TXBODY_TREE_DEPTH,
};
pub use wallet_authorization::{
    authorization_proof_wire_bytes, canonical_authorization_statement_from_body,
    prove_native_asset_authorization, prove_paged_spend_authorization,
    prove_v2_contract_controller_authorization, prove_wallet_authorization,
    validate_authorization_statement, verify_authorization_statement_proof,
    verify_native_asset_authorization, verify_paged_spend_authorization,
    verify_paged_spend_authorization_proof, verify_wallet_authorization,
    verify_wallet_authorization_proof, AuthorizationDecodeError, AuthorizationEncodeError,
    CanonicalAuthorizationStatement, OwnerAuthWitness, ProveAuthorizationError,
    VerifiedAuthorization, VerifiedAuthorizationBatch, VerifyAuthorizationError,
    WalletAuthorizationBundle, MAX_AUTHORIZATION_BUNDLE_BYTES, MAX_AUTHORIZATION_LIVE_INPUTS,
};
pub use zk_auth_hiding::{
    certify_zk_auth_companion_change_of_variables,
    certify_zk_auth_conditioned_companion_hyperplane, certify_zk_auth_joint_hiding_rank,
    ZkAuthCompanionChangeOfVariablesCertificate, ZkAuthConditionedCompanionHyperplaneCertificate,
    ZkAuthHidingRankError, ZkAuthJointHidingRankCertificate, ZkAuthRandomBlock,
    ZK_AUTH_COMPANION_CHANGE_DIMENSION, ZK_AUTH_COMPANION_CHANGE_RANK,
    ZK_AUTH_COMPANION_HYPERPLANE_DIMENSION, ZK_AUTH_FRESH_BANK_SUFFIX_CELLS,
    ZK_AUTH_FRESH_COMPANION_CELLS, ZK_AUTH_LIBRA_RANDOM_BLOCK, ZK_AUTH_SOURCE_COIN_RANDOM_BLOCK,
    ZK_AUTH_TERMINAL_OPERAND_PAD_RANDOM_BLOCK, ZK_AUTH_TOTAL_FRESH_CELLS,
};
pub use zk_authorization_wire::{
    ZkAuthorizationWireDecodeError, ZkAuthorizationWireEncodeError, ZK_AUTHORIZATION_MAX_WIRE_BYTES,
};

#[cfg(test)]
mod production_auth_hard_cut_tests {
    use std::path::Path;

    #[test]
    fn retired_owner_auth_sources_and_default_exports_stay_absent() {
        let retired_proof = concat!("OwnerAuthProof", "KillShot");
        let retired_prover = concat!("prove_owner_auth_", "killshot");
        let retired_ghost = concat!("pub fn ghost_", "authorization(");
        let owner_source = include_str!("owner_auth.rs");
        let ghost_source = include_str!("ghost_tx.rs");
        assert!(!owner_source.contains(retired_proof));
        assert!(!owner_source.contains(retired_prover));
        assert!(!ghost_source.contains(retired_ghost));

        let default_code: String = include_str!("lib.rs")
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect();
        assert!(!default_code.contains(retired_proof));
        assert!(!default_code.contains(retired_prover));
        assert!(!default_code.contains(concat!("pub mod auth_", "pcs")));

        let retired_pcs = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/auth_pcs.rs");
        assert!(
            !retired_pcs.exists(),
            "retired standalone owner-auth PCS source was restored"
        );
    }

    #[test]
    fn selected_wallet_secret_surface_stays_opaque_and_errors_stay_redacted() {
        let wallet = include_str!("wallet_authorization.rs");
        let ghost = include_str!("ghost_tx.rs");

        assert!(wallet.contains("spend_secret: SpendSecret"));
        assert!(!wallet.contains("pub spend_secret: SpendSecret"));
        assert!(!wallet.contains("pub fn spend_secret("));
        let prove_error = wallet
            .split("pub enum ProveAuthorizationError")
            .nth(1)
            .expect("prover error declaration")
            .split("impl From<PublicLogicError> for ProveAuthorizationError")
            .next()
            .expect("prover error declaration boundary");
        assert!(!prove_error.contains("Proof(String)"));
        assert!(!wallet.contains("ProveAuthorizationError::Proof(format!"));
        assert_eq!(
            wallet.matches("with_exposed_prover_fields").count(),
            1,
            "only the reviewed wallet-to-GKR closure may expose secret limbs"
        );

        // The ghost authority is a public padding constant, not wallet
        // material. Keep this exclusion explicit rather than weakening the
        // live-secret gates above.
        assert!(ghost.contains("DELIBERATELY PUBLIC"));
        assert!(ghost.contains("PARANOID-GHOST-TX-SPEND-SECRET.0"));

        let authorization = include_str!("zk_authorization.rs");
        let state = include_str!("zk_auth_capsule.rs");
        assert!(!authorization.contains("pub fn prove_zk_authorization_from_state("));
        assert!(authorization.contains("pub fn prove_zk_authorization_from_state_table("));
        let state_owner = state
            .split("impl ZkAuthCapsuleStateTable")
            .nth(1)
            .expect("state owner implementation")
            .split("/// Natural low-to-high state address")
            .next()
            .expect("state owner implementation boundary");
        assert!(!state_owner.contains("pub fn cells(&self)"));
        assert!(state_owner.contains("pub(crate) fn cells(&self)"));
    }

    #[test]
    fn secret_bearing_zk_owners_are_noncloneable_nonformattable_and_nonserializable() {
        static_assertions::assert_not_impl_any!(
            crate::OwnerAuthWitness:
                Copy, Clone, std::fmt::Debug, serde::Serialize, serde::de::DeserializeOwned
        );
        static_assertions::assert_not_impl_any!(
            crate::zk_auth_capsule::ZkAuthCapsuleStateTable:
                Copy, Clone, std::fmt::Debug, serde::Serialize, serde::de::DeserializeOwned
        );
        static_assertions::assert_not_impl_any!(
            crate::layers::PermLayerWitness:
                Copy, Clone, std::fmt::Debug, serde::Serialize, serde::de::DeserializeOwned
        );
    }
}
