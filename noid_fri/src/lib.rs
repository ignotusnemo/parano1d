// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! FRI Protocol: Fast Reed-Solomon IOP of Proximity.

pub mod batch;
pub mod channel;
pub mod code;
pub mod hasher;
pub mod merkle;
pub mod prover;
pub mod verifier;

pub use channel::{Channel, NUM_QUERIES, TAU};
pub use hasher::*;
pub use prover::{EvalProof, FriCommitment, Univariate};
pub use verifier::compute_eq_table;
