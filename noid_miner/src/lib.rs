// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! # noid_miner — Block Production Engine
//!
//! Implements atomic PoW + HistoryStep block production.
//!
//! ## Pipeline
//!
//! ```text
//!  ┌────────────────────────────────────────────────────────────┐
//!  │                   Block Production Loop                    │
//!  │                                                            │
//!  │  1. Build template + complete nonce-free HistoryStep       │
//!  │  2. Search PoW with every process CPU                      │
//!  │  3. Seal the nonce into the prepared terminal              │
//!  │  4. Atomically commit and broadcast AcceptedBlockBundle   │
//!  └────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Security property
//!
//! `state_root` (derived from all txs + miner_address via coinbase output) is
//! in the fixed Poseidon2b PoW header schedule. An external miner CANNOT change
//! the coinbase or any other semantic field; the miner only returns a nonce.

pub mod block_production;
mod cpu_budget;
pub mod history_protocol;
pub mod history_step_artifacts;
pub mod miner;
pub mod pow;
pub mod proof_capacity;
pub mod template;
pub mod v21_artifacts;
pub mod v2_artifacts;

pub use block_production::{CommittedBlock, MiningProofClass, PreparedBlockAttempt, ProvedBlock};
pub use cpu_budget::{
    configure_process_cpu_budget, configure_process_cpu_budget_with_threads,
    configured_process_cpu_budget, install_history_step_phase_cpu, install_inbound_verifier_cpu,
    install_pow_phase_cpu, install_wallet_proof_cpu, install_wallet_verifier_cpu,
    plan_process_cpu_budget, plan_process_cpu_budget_with_threads, ProcessCpuBudgetError,
    ProcessCpuBudgetMode, ProcessCpuBudgetPlan,
};
pub use history_protocol::HistoryProtocolRuntime;
pub use history_step_artifacts::{
    decode_history_step_runtime_metadata_pinned, encode_history_step_runtime_metadata,
    history_step_matrix_file_name, history_step_runtime_image_file_name,
    EmbeddedHistoryStepMatrixError, EmbeddedHistoryStepMatrixLeaf, EmbeddedHistoryStepMatrixSource,
    HistoryStepRuntimeMetadata, HistoryStepRuntimeMetadataError, HISTORY_STEP_PACK_LEAF_COUNT,
    HISTORY_STEP_PACK_VERSION_DIRECTORY, HISTORY_STEP_RUNTIME_METADATA_DIGEST_DOMAIN,
    HISTORY_STEP_RUNTIME_METADATA_FILE, HISTORY_STEP_RUNTIME_METADATA_MAX_BYTES,
    HISTORY_STEP_RUNTIME_METADATA_VERSION,
};
pub use miner::{BlockAppliedHook, BlockMiner, MinerConfig, MinerEvent};
pub use pow::{search_pow_parallel, PowSolution};
pub use proof_capacity::AdaptiveProofCapacity;
pub use template::{BlockTemplate, TemplateBuilder, TemplateRefreshTrigger};
