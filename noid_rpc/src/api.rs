// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.
//! JSON-RPC trait definition (generated server + client traits via proc macro).

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

use crate::types::{
    AddressInfo, BlockDetailsInfo, BlockHeaderInfo, BlockTemplateResponse, ChainInfo, FeeEstimate,
    MempoolInfo, MempoolStats, MiningInfo, NodeStatus, ReceiptVerifyResult, RecentTransactionsPage,
    SlotInfo, StateInfo, StateMapInfo, TxInfo, WalletAddressInfo, WalletBalance,
    WalletConsolidationPlan, WalletConsolidationResult, WalletHistoryEntry, WalletMinedBlocksPage,
    WalletReceiptsPage, WalletScanResult, WalletSendPlan, WalletSendResult, WalletStatus,
    WalletUtxoInfo, WalletUtxoSnapshot,
};

#[rpc(server, namespace = "paranoid")]
pub trait ParanoidApi {
    // =========================================================================
    // Chain
    // =========================================================================

    /// Current tip height.
    #[method(name = "blockCount")]
    async fn block_count(&self) -> RpcResult<u64>;

    /// Chain tip summary: height, hash, difficulty, active UTXOs.
    #[method(name = "getChainInfo")]
    async fn get_chain_info(&self) -> RpcResult<ChainInfo>;

    /// H_BLOCK hash of the block at `height` (hex, no 0x prefix).
    /// Stored forever. Returns null if height > tip.
    #[method(name = "getBlockHash")]
    async fn get_block_hash(&self, height: u64) -> RpcResult<Option<String>>;

    /// Decoded block header at `height`. All fields as typed values.
    /// Stored forever.
    #[method(name = "getBlockHeader")]
    async fn get_block_header(&self, height: u64) -> RpcResult<Option<BlockHeaderInfo>>;

    /// Decoded permanent block header by H_BLOCK hash.
    #[method(name = "getBlockHeaderByHash")]
    async fn get_block_header_by_hash(&self, hash: String) -> RpcResult<Option<BlockHeaderInfo>>;

    /// Raw 212-byte block header hex at `height` (for developers).
    #[method(name = "getHeaderByHeight")]
    async fn get_header_by_height(&self, height: u64) -> RpcResult<Option<String>>;

    /// Raw 212-byte block header hex by H_BLOCK hash.
    #[method(name = "getHeaderByHash")]
    async fn get_header_by_hash(&self, hash: String) -> RpcResult<Option<String>>;

    /// Current finalized HistoryStep terminal, when locally available.
    #[method(name = "getHistoryStepTerminal")]
    async fn get_history_step_terminal(&self) -> RpcResult<Option<String>>;

    /// UTXO slot contents by index.
    #[method(name = "getSlot")]
    async fn get_slot(&self, slot_index: u32) -> RpcResult<SlotInfo>;

    /// All live UTXO slots owned by `address` (bech32m).
    /// Uses the persistent owner index — O(1) lookup.
    #[method(name = "getSlotsByOwner")]
    async fn get_slots_by_owner(&self, address: String) -> RpcResult<Vec<SlotInfo>>;

    /// Total live UTXO count.
    #[method(name = "getActiveSlotCount")]
    async fn get_active_slot_count(&self) -> RpcResult<u64>;

    /// Full state dimensions: capacity, fill %, bytes on disk, expansion headroom.
    #[method(name = "getStateInfo")]
    async fn get_state_info(&self) -> RpcResult<StateInfo>;

    /// Bounded 16×16 occupancy atlas of the current live state.
    #[method(name = "getStateMap")]
    async fn get_state_map(&self) -> RpcResult<StateMapInfo>;

    /// Confirmed transaction info by derived txid. Uses the permanent tx index.
    /// Returns null if hash is unknown (not yet confirmed or never submitted).
    #[method(name = "getTx")]
    async fn get_tx(&self, txhash: String) -> RpcResult<Option<TxInfo>>;

    /// Full block (header + transactions) at `height`, as hex.
    /// Only retained recent blocks are served; older block bodies are pruned.
    #[method(name = "getBlock")]
    async fn get_block(&self, height: u64) -> RpcResult<Option<String>>;

    /// Permanent header plus full body detail when the block remains retained.
    #[method(name = "getBlockDetails")]
    async fn get_block_details(&self, height: u64) -> RpcResult<Option<BlockDetailsInfo>>;

    /// Compact paginated logical transactions from the retained body window.
    /// Supplying an address filters the bounded scan to transitions involving
    /// that owner and adds exact sent/received aggregates for that address.
    #[method(name = "getRecentTransactions")]
    async fn get_recent_transactions(
        &self,
        page: u32,
        page_size: u32,
        address: Option<String>,
    ) -> RpcResult<RecentTransactionsPage>;

    // =========================================================================
    // Network / mining
    // =========================================================================

    /// Mining and network state: difficulty, block reward, HistoryStep height.
    #[method(name = "getMiningInfo")]
    async fn get_mining_info(&self) -> RpcResult<MiningInfo>;

    /// Number of currently connected P2P peers.
    #[method(name = "getPeerCount")]
    async fn get_peer_count(&self) -> RpcResult<usize>;

    /// Daemon sync, mining, CPU backend and worker-pool status.
    #[method(name = "getNodeStatus")]
    async fn get_node_status(&self) -> RpcResult<NodeStatus>;

    /// Estimated minimum fee in μNOID for a transaction with `n_outputs` outputs.
    /// Simple u64 method: assumes one live input.
    #[method(name = "estimateFee")]
    async fn estimate_fee(&self, n_outputs: u32) -> RpcResult<u64>;

    /// Detailed fee estimate for explicit live input/output counts.
    #[method(name = "estimateFeeDetailed")]
    async fn estimate_fee_detailed(&self, n_inputs: u32, n_outputs: u32) -> RpcResult<FeeEstimate>;

    // =========================================================================
    // Utilities
    // =========================================================================

    /// Validate and normalise an address (bech32m).
    /// Returns the canonical bech32m form on success.
    #[method(name = "validateAddress")]
    async fn validate_address(&self, address: String) -> RpcResult<AddressInfo>;

    /// Candidate empty slot indices for transaction outputs.
    ///
    /// Uses node-local entropy in addition to the tip state so concurrent callers
    /// are unlikely to receive identical hints.
    #[method(name = "getSlotHints")]
    async fn get_slot_hints(&self, count: u32) -> RpcResult<Vec<u32>>;

    /// Candidate empty slot indices salted by wallet/request entropy.
    ///
    /// `salt_hex` can be any caller-chosen bytes encoded as hex (for example a
    /// wallet address plus a random nonce). Different salts on the same tip produce
    /// different hint streams across nodes without creating global reservations.
    #[method(name = "getSlotHintsSalted")]
    async fn get_slot_hints_salted(&self, count: u32, salt_hex: String) -> RpcResult<Vec<u32>>;

    /// Current epoch anchor hash (use as `epoch_anchor` when building transactions).
    #[method(name = "getEpochAnchor")]
    async fn get_epoch_anchor(&self) -> RpcResult<String>;

    /// Submit a raw `PagedSpendIntent` (pages + WalletAuthorizationBundle) to the mempool.
    #[method(name = "submitTxIntent")]
    async fn submit_tx_intent(&self, hex: String) -> RpcResult<String>;

    // =========================================================================
    // Mempool
    // =========================================================================

    /// Full mempool state: count, fee floor, list of pending transactions.
    #[method(name = "getMempoolInfo")]
    async fn get_mempool_info(&self) -> RpcResult<MempoolInfo>;

    /// Pending transaction count (lighter than getMempoolInfo).
    #[method(name = "getMempoolSize")]
    async fn get_mempool_size(&self) -> RpcResult<usize>;

    /// Constant-size transaction-count and retained-byte pressure summary.
    #[method(name = "getMempoolStats")]
    async fn get_mempool_stats(&self) -> RpcResult<MempoolStats>;

    /// Single pending transaction by hash. Returns null if not in mempool.
    #[method(name = "getMempoolEntry")]
    async fn get_mempool_entry(
        &self,
        txhash: String,
    ) -> RpcResult<Option<crate::types::MempoolTxInfo>>;

    // =========================================================================
    // Receipt
    // =========================================================================

    /// Verify a Merkle payment receipt against the canonical chain.
    #[method(name = "verifyReceipt")]
    async fn verify_receipt(&self, receipt_hex: String) -> RpcResult<ReceiptVerifyResult>;

    // =========================================================================
    // Mining (external miner API)
    // =========================================================================

    /// Get a PoW block template for an external miner.
    #[method(name = "getBlockTemplate")]
    async fn get_block_template(&self, miner_address: String) -> RpcResult<BlockTemplateResponse>;

    /// Submit only a nonce for a single-use, node-owned prepared template.
    /// `nonce_hex` is exactly 16 little-endian bytes encoded as 32 lowercase hex chars.
    #[method(name = "submitBlock")]
    async fn submit_block(&self, template_id: String, nonce_hex: String) -> RpcResult<String>;

    // =========================================================================
    // Node control
    // =========================================================================

    /// Gracefully stop the Parano1d daemon.
    #[method(name = "stop")]
    async fn stop(&self) -> RpcResult<String>;

    // =========================================================================
    // Wallet RPC methods (noid_walletXxx namespace preserved via method name)
    // =========================================================================

    /// Get wallet status: address, balance, UTXO count.
    #[method(name = "walletStatus")]
    async fn wallet_status(&self) -> RpcResult<WalletStatus>;

    /// Get the address at key index `index`.
    #[method(name = "walletGetAddress")]
    async fn wallet_get_address(&self, index: u32) -> RpcResult<String>;

    /// Get balance breakdown.
    #[method(name = "walletGetBalance")]
    async fn wallet_get_balance(&self) -> RpcResult<WalletBalance>;

    /// List all confirmed UTXOs.
    #[method(name = "walletListUtxos")]
    async fn wallet_list_utxos(&self) -> RpcResult<Vec<WalletUtxoInfo>>;

    /// Conditional full UTXO snapshot for local polling clients.
    #[method(name = "walletUtxoSnapshot")]
    async fn wallet_utxo_snapshot(
        &self,
        known_revision: Option<String>,
    ) -> RpcResult<WalletUtxoSnapshot>;

    /// Transaction history (most recent last).
    #[method(name = "walletHistory")]
    async fn wallet_history(&self) -> RpcResult<Vec<WalletHistoryEntry>>;

    /// Newest-first durable receipts for payments to a different address.
    #[method(name = "walletReceipts")]
    async fn wallet_receipts(&self, page: u32, page_size: u32) -> RpcResult<WalletReceiptsPage>;

    /// Newest-first paginated blocks whose coinbase belongs to this wallet.
    #[method(name = "walletMinedBlocks")]
    async fn wallet_mined_blocks(
        &self,
        page: u32,
        page_size: u32,
    ) -> RpcResult<WalletMinedBlocksPage>;

    /// Reload the active address from the exact verified durable owner index.
    #[method(name = "walletScan")]
    async fn wallet_scan(&self) -> RpcResult<WalletScanResult>;

    /// Discover the contiguous funded address prefix after master-secret
    /// import. The first empty address stops discovery.
    #[method(name = "walletDiscoverAddresses")]
    async fn wallet_discover_addresses(
        &self,
        max_additional: u32,
    ) -> RpcResult<Vec<WalletAddressInfo>>;

    /// Dry-run wallet send planning without proving or submitting.
    /// `fee_micronoid = 0` computes the automatic fee.
    #[method(name = "walletPlanSend")]
    async fn wallet_plan_send(
        &self,
        to_address: String,
        amount_micronoid: u64,
        fee_micronoid: u64,
    ) -> RpcResult<WalletSendPlan>;

    /// Send NOID to a recipient address.
    /// `to_address`: recipient bech32m address.
    /// `amount_micronoid`: amount in μNOID.
    /// `fee_micronoid`: exact fee (0 = automatic fee).
    #[method(name = "walletSend")]
    async fn wallet_send(
        &self,
        to_address: String,
        amount_micronoid: u64,
        fee_micronoid: u64,
    ) -> RpcResult<WalletSendResult>;

    /// Exact live quote for merging up to 64 of the active wallet's smallest
    /// spendable UTXOs into one output.
    #[method(name = "walletPlanConsolidation")]
    async fn wallet_plan_consolidation(&self) -> RpcResult<WalletConsolidationPlan>;

    /// Build, prove, and submit the exact active-wallet consolidation.
    #[method(name = "walletConsolidate")]
    async fn wallet_consolidate(
        &self,
        selected_input_slots: Vec<u32>,
        expected_fee_micronoid: u64,
        expected_output_value_micronoid: u64,
    ) -> RpcResult<WalletConsolidationResult>;

    /// Export a receipt for a confirmed transaction (hex-encoded bytes).
    #[method(name = "walletExportReceipt")]
    async fn wallet_export_receipt(&self, txhash_hex: String) -> RpcResult<String>;

    /// Generate the next inactive address. The active owner, loaded UTXOs,
    /// and mining payout remain unchanged until walletSetActiveAddress.
    #[method(name = "walletNextAddress")]
    async fn wallet_next_address(&self) -> RpcResult<WalletAddressInfo>;

    /// List locally generated address metadata and mark the active address.
    #[method(name = "walletListAddresses")]
    async fn wallet_list_addresses(&self) -> RpcResult<Vec<WalletAddressInfo>>;

    /// The ACTIVE address (key index + bech32m). Sends spend this address's
    /// UTXOs only (one owner per transaction is a consensus rule) and change
    /// returns to it.
    #[method(name = "walletActiveAddress")]
    async fn wallet_active_address(&self) -> RpcResult<WalletAddressInfo>;

    /// Switch the ACTIVE address to an already-generated key index and load
    /// that address's current UTXOs. The choice persists across restarts.
    #[method(name = "walletSetActiveAddress")]
    async fn wallet_set_active_address(&self, index: u32) -> RpcResult<WalletAddressInfo>;
}
