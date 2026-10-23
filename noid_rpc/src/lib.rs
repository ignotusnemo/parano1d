// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! # noid_rpc — JSON-RPC Server for Paranoid Full Node

pub mod api;
pub mod client_types;
pub mod native_types;
pub mod object_receipts;
pub mod object_types;
pub mod server;
pub mod types;
pub mod wallet_ops;
pub mod wallet_submit;

pub use server::{start_rpc_server, ExternalMiningAttemptInvalidator};
pub use wallet_ops::WalletOps;
pub use wallet_submit::WalletOperationGate;
