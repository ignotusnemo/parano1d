// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! # noid_mempool — Async Mempool for the Paranoid Full Node
//!
//! This crate wraps the synchronous `noid_chain::Mempool` in an async
//! (`tokio`-based) interface that drives the full node's transaction pipeline:
//!
//! ```text
//!  wallet
//!    │  PagedSpendIntent (pages + selected-ZK authorization bytes)
//!    ▼
//!  AsyncMempool::submit()
//!    ├─ stateless body-hash and size checks
//!    ├─ cheap pre-filter under lock:
//!    │  fee floor, consensus, anchor, slot conflicts/state
//!    ├─ authorization verification outside lock (`spawn_blocking`, semaphore-bounded)
//!    └─ final admission under lock: re-run cheap checks against current view
//!         │
//!         ▼ admitted only after proof verification
//!    broadcast MempoolEvent::TxAdmitted
//!         │
//!         ├──► P2P: gossip to peers
//!         ├──► RPC WebSocket: notify subscribed wallets
//!         └──► Block builder: wake up if 100+ new txs
//!
//!  Cached proof reuse: admitted entries keep verified selected-ZK bytes for block assembly
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! use noid_mempool::{AsyncMempool, ChainView, MempoolConfig};
//! use noid_chain::storage::MdbxChainContext;
//!
//! async fn example(
//!     ctx: &MdbxChainContext,
//!     pinned_v2_budgets: [noid_chain::mempool::BlockSelectionBudget; 2],
//! ) {
//!     let view = ChainView::from_mdbx(ctx);
//!     let config = MempoolConfig::default().with_v2_block_budgets(pinned_v2_budgets);
//!     let mp = AsyncMempool::new(view, config);
//!
//!     // Subscribe to events (P2P, RPC, block builder).
//!     let mut rx = mp.subscribe();
//!
//!     // Submit a transaction from a wallet.
//!     // let hash = mp.submit(intent, intent_bytes).await?;
//! }
//! ```

pub mod config;
mod contracts;
pub mod error;
pub mod event;
pub mod floor;
pub mod pool;
pub mod view;

// ---------------------------------------------------------------------------
// Public re-exports
// ---------------------------------------------------------------------------

pub use config::MempoolConfig;
pub use contracts::DecodedMempoolIntent;
pub use error::SubmitError;
pub use event::{EvictReason, MempoolEvent};
pub use floor::FeeFloor;
pub use pool::{
    AsyncMempool, AuthorizationVerificationExecutor, AuthorizationVerificationTask,
    MempoolEntryDetails, MempoolEntryMetadata, MempoolMetadataSnapshot, MempoolUsageSnapshot,
    SelectedMempoolEntry, V2MempoolSelection,
};
pub use view::ChainView;

// Re-export `MempoolEntry` from noid_chain for block builder convenience.
pub use noid_chain::mempool::MempoolEntry;
