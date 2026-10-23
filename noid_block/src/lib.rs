// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native preparation for the one proof-carrying block protocol.
//!
//! A miner assembles every nonce-independent HistoryStep witness row once,
//! searches only the nonce, then appends the exact sealed-header suffix and
//! proves that one block. There is no detached block proof, auth sidecar,
//! certificate, history claim, or durable intermediate proof format.

mod history_step_witness;

pub use history_step_witness::{
    build_history_step_components_with_financial_context,
    build_history_step_components_with_native_data,
    build_history_step_components_with_native_openings, prepare_history_step_input_witness,
    prepare_history_step_witness, prepare_v2_research_history_step_input_witness,
    HistoryStepPreparationContext, HistoryStepWitnessError, PreparedHistoryStepInputWitness,
    PreparedHistoryStepWitness,
};

pub mod candidate_history;
pub mod contract_receipt;
pub mod native_trade;
