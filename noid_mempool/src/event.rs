// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Mempool events broadcast to P2P, RPC subscribers, and the block builder.

use std::sync::Arc;

use noid_poseidon2b::primitives::TxBodyHash;

/// An event emitted by the mempool and broadcast to all subscribers.
///
/// Subscribers include:
/// - **P2P relay**: gossips `TxAdmitted` to peers
/// - **RPC WebSocket**: forwards events to subscribed wallets
/// - **Block builder** (`noid_miner`): watches `TxAdmitted` to refresh templates
#[derive(Debug, Clone)]
pub enum MempoolEvent {
    /// A new transaction was admitted (passed all native checks).
    /// Payload: canonical ordinary or contract intent bytes (for P2P gossip).
    TxAdmitted {
        hash: TxBodyHash,
        fee: u64,
        /// The exact admitted envelope, including any contract opening.
        intent_bytes: Arc<[u8]>,
    },

    /// A transaction was evicted (epoch changed or pool pressure).
    TxEvicted {
        hash: TxBodyHash,
        reason: EvictReason,
    },

    /// A transaction was confirmed in a block and removed from the pool.
    TxConfirmed { hash: TxBodyHash, block_height: u64 },

    /// Wallet authorization cached for a transaction (background proving cache).
    /// The block assembler can now use the cached proof.
    TxAuthorizationVerified { hash: TxBodyHash },
}

/// Why a transaction was evicted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvictReason {
    TradePolicyExpired,
    AuthorizationProfileChanged,
    NativeContextChanged,
    /// Candidate-height rules no longer allow this intent in any proof class.
    BlockCapacityChanged,
    /// A reorg moved the candidate block back before contract activation.
    ContractForkInactive,
    /// The candidate height changed a contract's result or authorized key.
    /// The wallet must rebuild and reauthorize the call against the new view.
    ContractContextChanged,
    /// The canonical transaction epoch anchor advanced at a boundary.
    EpochAnchorChanged,
    /// The fee is below the current parent-State consensus minimum.
    /// A later increase of the node-local relay floor does not cause eviction.
    ConsensusFeeIncreased,
    /// Pool over capacity; low-fee tx was dropped.
    CapacityPressure,
    /// The transaction's claimed input slot was spent by a confirmed block.
    InputConsumed,
    /// One of the transaction's chosen output slots was filled by a confirmed block.
    /// The wallet should rebuild/re-prove with fresh slot hints.
    OutputSlotOccupied,
}
