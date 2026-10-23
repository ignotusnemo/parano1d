// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! WalletOps trait — interface between RPC layer and wallet implementation.
//!
//! Implemented by `WalletHandle` in `noid_node/src/wallet/mod.rs`.
//! `RpcHandler` holds `Arc<dyn WalletOps + Send + Sync>`.

use std::collections::HashSet;

use noid_chain::block::Block;
use noid_chain::storage::VerifiedOwnerSnapshot;

mod native;
pub use native::{
    WalletNativeClaims, WalletNativeContext, WalletNativeIntent, WalletNativeProofRequest,
    WalletNativeReservation, WalletNativeSubmission,
};

use crate::types::{
    WalletAddressInfo, WalletBalance, WalletConsolidationPlan, WalletHistoryEntry,
    WalletScanResult, WalletSendPlan, WalletStatus, WalletUtxoInfo, WalletUtxoSnapshot,
};

/// Deterministic send-planning failure. Keeping the input-limit case typed
/// prevents the RPC layer from scraping human-readable wallet errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WalletSendPlanError {
    #[error("InsufficientFunds: need {needed_micronoid} μNOID, have {available_micronoid} μNOID spendable")]
    InsufficientFunds {
        needed_micronoid: u64,
        available_micronoid: u64,
    },

    #[error("InputLimitExceeded: canonical payments support at most {max_inputs} inputs")]
    InputLimitExceeded { max_inputs: usize },

    #[error("{0}")]
    Other(String),
}

/// Immutable activation/reload intent captured under the wallet lock.
/// Commit rejects it if either wallet index changed before installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletActivationPreview {
    pub expected_active_index: u32,
    pub expected_next_index: u32,
    pub target_index: u32,
    pub owner: [u8; 32],
}

/// Immutable contiguous address-discovery intent captured under the wallet
/// lock. Candidates are derived from the one master secret but remain inactive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletAddressDiscoveryPreview {
    pub expected_active_index: u32,
    pub expected_next_index: u32,
    pub candidates: Vec<(u32, [u8; 32])>,
}

/// Internal bounded view used to build the public mined-block RPC page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletMinedBlockRecord {
    pub coinbase_txid: [u8; 32],
    pub block_hash: Option<[u8; 32]>,
    pub height: u64,
    pub timestamp: u64,
    pub reward_micronoid: u64,
    pub payout_address: String,
    pub payout_key_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletMinedBlockSlice {
    pub total: usize,
    pub blocks: Vec<WalletMinedBlockRecord>,
}

/// Internal receipt record before JSON pagination metadata is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletReceiptRecord {
    pub txid: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub amount_micronoid: u64,
    pub fee_micronoid: u64,
    pub peer_address: Option<String>,
    pub own_address: Option<String>,
    pub own_key_index: Option<u32>,
    pub input_count: usize,
    pub output_count: usize,
    pub receipt_bytes: usize,
    pub trade: Option<crate::types::ReceiptTradeInfo>,
    pub native: Option<crate::types::ReceiptNativeInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletReceiptSlice {
    pub total: usize,
    pub receipts: Vec<WalletReceiptRecord>,
}

pub struct WalletReceiptQueryIndex {
    pub revision: String,
    pub ids: Vec<[u8; 32]>,
}

pub struct WalletObjectOpeningPage {
    pub openings: Vec<noid_tx::experimental_object::ObjectOpening>,
    pub next_root: Option<[u8; 32]>,
}

/// Compact retained call with its Merkle inclusion checked locally. No
/// recursive terminal is loaded to enumerate these records.
pub struct WalletObjectReceiptRecord {
    pub opening: noid_tx::experimental_object::ObjectOpening,
    pub page: noid_tx::TxPage,
    pub header: noid_chain::BlockHeader,
}

pub struct WalletObjectReceiptPage {
    pub receipts: Vec<WalletObjectReceiptRecord>,
    pub next_cursor: Option<String>,
}

pub trait WalletOps: Send + Sync {
    fn reserve_native_submission(
        &self,
        _submission: &WalletNativeSubmission,
    ) -> Result<u128, String> {
        Err("native wallet reservations unavailable".into())
    }

    fn rollback_native_submission(&self, _txid: [u8; 32], _lease: u128) {}

    fn native_pending_submissions(&self) -> Vec<WalletNativeReservation> {
        Vec::new()
    }

    fn remember_native_submission(
        &self,
        _submission: &WalletNativeSubmission,
        _preview: &crate::native_types::NativeWalletPreview,
    ) -> Result<(), String> {
        Err("native wallet activity unavailable".into())
    }

    fn native_activity(&self) -> Result<Vec<crate::native_types::NativeWalletActivity>, String> {
        Ok(Vec::new())
    }

    fn forget_native_activity(&self, _txid: [u8; 32]) -> Result<(), String> {
        Err("native wallet activity unavailable".into())
    }

    /// Authorize a reviewed native operation with the active local account.
    fn build_native_authorization(
        &self,
        _request: WalletNativeProofRequest,
        _store: noid_chain::storage::MdbxStore,
    ) -> Result<WalletNativeSubmission, String> {
        Err("native wallet authoring unavailable".into())
    }

    /// Prove with the locally selected policy authority. No key material is
    /// accepted from RPC or returned by this boundary.
    fn build_object_call(
        &self,
        _opening: noid_tx::experimental_object::ObjectOpening,
        _page: noid_tx::TxPage,
        _height: u64,
    ) -> Result<Vec<u8>, String> {
        Err("object wallet unavailable".into())
    }
    fn remember_object_opening(
        &self,
        _opening: &noid_tx::experimental_object::ObjectOpening,
    ) -> Result<(), String> {
        Err("object wallet unavailable".into())
    }
    fn load_object_opening(
        &self,
        _root: [u8; 32],
    ) -> Result<noid_tx::experimental_object::ObjectOpening, String> {
        Err("object opening unavailable".into())
    }
    /// Local public terms with identical program and rules but different
    /// counters. Presence in this catalog never implies a confirmed balance.
    fn related_object_openings(
        &self,
        _opening: &noid_tx::experimental_object::ObjectOpening,
        _after: Option<[u8; 32]>,
        _limit: usize,
    ) -> Result<WalletObjectOpeningPage, String> {
        Err("object catalog unavailable".into())
    }
    fn remember_object_receipt(&self, _txid: [u8; 32], _bytes: &[u8]) -> Result<(), String> {
        Err("object wallet unavailable".into())
    }
    fn load_object_receipt(&self, _txid: [u8; 32]) -> Result<Vec<u8>, String> {
        Err("object receipt unavailable".into())
    }
    fn object_receipts(
        &self,
        _opening: &noid_tx::experimental_object::ObjectOpening,
        _after: Option<&str>,
        _limit: usize,
    ) -> Result<WalletObjectReceiptPage, String> {
        Err("object receipt catalog unavailable".into())
    }

    /// Overall wallet status (exists, address, balance).
    fn status(&self) -> WalletStatus;

    /// Derive the address at `index`. Returns None if wallet is not loaded.
    fn get_address(&self, index: u32) -> Option<String>;

    /// Current confirmed balance.
    fn get_balance(&self) -> WalletBalance;

    /// All known UTXOs.
    fn list_utxos(&self) -> Vec<WalletUtxoInfo>;

    /// Read a vector only when the caller's revision is stale. Implementations
    /// without revision tracking remain compatible by always returning data.
    fn utxo_snapshot(&self, _known_revision: Option<&str>) -> WalletUtxoSnapshot {
        WalletUtxoSnapshot {
            revision: None,
            utxos: Some(self.list_utxos()),
        }
    }

    /// Transaction history (most recent last).
    fn history(&self) -> Vec<WalletHistoryEntry>;

    /// Newest-first bounded slice of durable different-address receipts.
    fn receipts(&self, offset: usize, limit: usize) -> Result<WalletReceiptSlice, String>;

    fn filtered_receipts(
        &self,
        offset: usize,
        limit: usize,
        filter: crate::types::ReceiptFilter,
    ) -> Result<WalletReceiptSlice, String> {
        if filter == crate::types::ReceiptFilter::All {
            self.receipts(offset, limit)
        } else {
            Err("receipt filtering is unavailable".into())
        }
    }

    fn receipt_query_index(&self) -> Result<WalletReceiptQueryIndex, String> {
        Err("receipt queries are unavailable".into())
    }

    fn receipt_query_bytes(&self, _revision: &str, _id: &[u8; 32]) -> Result<Vec<u8>, String> {
        Err("receipt queries are unavailable".into())
    }

    fn receipt_query_records(
        &self,
        _revision: &str,
        _ids: &[[u8; 32]],
    ) -> Result<Vec<WalletReceiptRecord>, String> {
        Err("receipt queries are unavailable".into())
    }

    /// Newest-first bounded slice of every coinbase paid to any local address.
    fn mined_blocks(&self, offset: usize, limit: usize) -> WalletMinedBlockSlice;

    /// Preview a reload of the current active address without mutation.
    fn preview_active_reload(&self) -> Result<WalletActivationPreview, String>;

    /// Preview switching to an already-generated address without mutation.
    fn preview_address_switch(&self, index: u32) -> Result<WalletActivationPreview, String>;

    /// Atomically derive and persist the next inactive address without
    /// changing the active owner or its loaded UTXO snapshot.
    fn create_next_address(&self) -> Result<WalletAddressInfo, String>;

    /// Derive at most `max_additional` sequential inactive addresses without
    /// changing the address book or loading their balances.
    fn preview_address_discovery(
        &self,
        max_additional: u32,
    ) -> Result<WalletAddressDiscoveryPreview, String>;

    /// Persist the contiguous funded prefix found from a discovery preview.
    /// The active address and its loaded UTXO snapshot remain unchanged.
    fn commit_address_discovery(
        &self,
        expected_active_index: u32,
        expected_next_index: u32,
        discovered_next_index: u32,
    ) -> Result<Vec<WalletAddressInfo>, String>;

    /// Atomically validate a preview, persist its indices, and install the
    /// exact durable owner snapshot while holding one wallet lock.
    fn commit_activation_snapshot(
        &self,
        preview: WalletActivationPreview,
        snapshot: VerifiedOwnerSnapshot,
        reserved_input_slots: &HashSet<u32>,
        reserved_output_slots: &HashSet<u32>,
    ) -> Result<(WalletAddressInfo, WalletScanResult), String>;

    /// Apply one accepted block to the active-address cache and wallet
    /// artifacts. The caller invokes this while it still holds the chain write
    /// guard, establishing the global `chain -> wallet` lock order.
    fn on_accepted_block(&self, block: &Block) -> Result<(), String>;

    fn retain_object_receipts(
        &self,
        _store: &noid_chain::storage::MdbxStore,
        _block: &Block,
    ) -> Result<(), String> {
        Ok(())
    }

    /// Deterministically plan one ordinary canonical payment transaction using
    /// at most eight active-owner UTXOs.
    ///
    /// `explicit_fee_micronoid = Some(fee)` applies that exact fee and rejects
    /// it if below the deterministic minimum for the resulting I/O. `None`
    /// computes the automatic relay fee from the actual input/output counts.
    fn plan_send(
        &self,
        amount_micronoid: u64,
        explicit_fee_micronoid: Option<u64>,
        active_slot_count: u64,
        log_slots: u32,
        relay_floor: u64,
    ) -> Result<WalletSendPlan, WalletSendPlanError>;

    /// Build, prove, and serialize a send transaction.
    ///
    /// Returns raw `PagedSpendIntent` bytes plus selected input slot indices. Building
    /// is side-effect free: the async coordinator installs the complete pending
    /// reservation only after `spawn_blocking` returns.
    ///
    /// This is CPU-heavy (~0.3–3 s): caller must invoke in `spawn_blocking`.
    ///
    /// # Parameters
    /// - `to_address`: recipient 32-byte address
    /// - `amount_micronoid`: payment amount in μNOID
    /// - `fee_micronoid`: transaction fee in μNOID
    /// - `epoch_anchor`: exact transaction-epoch anchor for the next block
    /// - `slot_hints`: one or two empty slot indices for outputs
    /// - `log_slots`: current chain `log_slots` (from `tip_header().log_slots`)
    fn build_send(
        &self,
        to_address: [u8; 32],
        amount_micronoid: u64,
        fee_micronoid: u64,
        epoch_anchor: [u8; 32],
        slot_hints: Vec<u32>,
        log_slots: u32,
        candidate_height: u64,
    ) -> Result<(Vec<u8>, Vec<u32>), String>;

    /// Plan one active-wallet consolidation from the smallest available UTXOs.
    ///
    /// The returned slot list is an immutable build boundary: block rewards or
    /// unrelated wallet refreshes cannot silently change which UTXOs the user
    /// approved while the proof is being prepared.
    fn plan_consolidation(
        &self,
        max_inputs: usize,
        active_slot_count: u64,
        log_slots: u32,
        relay_floor: u64,
    ) -> Result<WalletConsolidationPlan, WalletSendPlanError>;

    /// Build, prove, and serialize the exact consolidation approved above.
    ///
    /// Every selected input must still be live, active-owner, and unreserved.
    /// The transaction creates exactly one output back to the active address.
    fn build_consolidation(
        &self,
        selected_input_slots: Vec<u32>,
        output_value_micronoid: u64,
        fee_micronoid: u64,
        epoch_anchor: [u8; 32],
        slot_hints: Vec<u32>,
        log_slots: u32,
        candidate_height: u64,
    ) -> Result<(Vec<u8>, Vec<u32>), String>;

    /// Export a receipt for a past transaction as hex-encoded bytes.
    /// Returns `Err` if the tx is unknown or receipt was not generated
    /// (block already pruned when it was confirmed).
    fn export_receipt(&self, txhash_hex: &str) -> Result<String, String>;

    /// Atomically reserve every wallet-side artifact immediately before async
    /// mempool admission. The caller wraps this reservation in an owned rollback
    /// guard, so task cancellation cannot strand inputs, outputs, or history.
    fn reserve_pending_submission(
        &self,
        txid: [u8; 32],
        input_slots: &[u32],
        output_slots: &[u32],
        amount_micronoid: u64,
        peer_address: [u8; 32],
    ) -> Result<(), String>;

    /// Roll back the exact reservation installed above. Safe to call from Drop.
    fn rollback_pending_submission(
        &self,
        txid: [u8; 32],
        input_slots: &[u32],
        output_slots: &[u32],
    );

    /// The ACTIVE address (key index + bech32m): every send spends this
    /// address's UTXOs only and change returns to it (one owner per transaction
    /// is a consensus rule).
    fn active_address(&self) -> Option<(u32, String)>;

    /// List locally generated address metadata. No inactive address is
    /// scanned and no per-address balances are synthesized.
    fn list_addresses(&self) -> Vec<WalletAddressInfo>;

    /// Sum of values of UTXOs currently being spent by pending txs.
    fn pending_outbound(&self) -> u64;
}
