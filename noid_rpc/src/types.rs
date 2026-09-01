// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.
//! JSON response types for the Paranoid RPC API.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Chain types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    pub height: u64,
    pub best_hash: String,
    pub difficulty_target: String,
    pub active_slot_count: u64,
    pub log_slots: u32,
    /// Exact sum of all live UTXO values, encoded as a decimal string so the
    /// JSON boundary never loses precision.
    pub circulating_supply_micronoid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotInfo {
    pub slot_index: u32,
    pub value: u64,
    /// Alloc-counter incarnation assigned when this UTXO was minted.
    pub creation_id: u64,
    pub owner: String,
    pub empty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptVerifyResult {
    pub merkle_valid: bool,
    pub canonical: bool,
    pub confirmed: bool,
    pub error: Option<String>,
    /// Payment data reconstructed from the receipt and authenticated by its
    /// Merkle path. Present only when `merkle_valid` is true; `canonical`
    /// separately says whether the claimed root is on this node's chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated_summary: Option<ReceiptSummaryInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptSummaryInfo {
    pub txid: String,
    pub claimed_height: u64,
    pub confirmed_unix: u64,
    pub tx_index: u16,
    pub tx_count: u16,
    pub fee_micronoid: u64,
    pub inputs: Vec<ReceiptInputInfo>,
    pub outputs: Vec<ReceiptOutputInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptInputInfo {
    pub slot_index: u32,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptOutputInfo {
    pub slot_index: u32,
    pub amount_micronoid: u64,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTemplateResponse {
    /// Opaque, single-use identifier for the node-owned prepared template.
    /// The external miner cannot use it to mutate the block body or witnesses.
    pub template_id: String,
    /// Fixed 16-field Poseidon2b PoW input as hex, with the nonce field zeroed.
    /// Each field is serialized as 16 little-endian bytes. Patch field 10
    /// with the LE u128 nonce. A valid nonce satisfies:
    /// `Poseidon2b(POWHDR__, patched_fields) < difficulty_target`.
    pub pow_fields_hex: String,
    /// Field index to replace with the canonical 16-byte little-endian nonce.
    pub nonce_field_index: usize,
    /// Difficulty target as 64-char little-endian hex.
    pub difficulty_target_hex: String,
    pub height: u64,
    /// Strict server-side lifetime of this template after this response is built.
    pub expires_in_seconds: u64,
    /// Total transaction count including coinbase.
    pub n_txs: usize,
    /// Live input counts per user transaction in canonical block order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tx_input_counts: Vec<usize>,
    /// Live output counts per user transaction in canonical block order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tx_output_counts: Vec<usize>,
    /// Coinbase output value in μNOID.
    pub coinbase_value_micronoid: u64,
    /// Sum of user fees claimable by the miner after burned state-growth fees.
    pub claimable_fees_micronoid: u64,
}

// ---------------------------------------------------------------------------
// Wallet types
// ---------------------------------------------------------------------------

/// Local derivation metadata for one generated wallet address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAddressInfo {
    /// Bech32m address string.
    pub address: String,
    /// Derivation index (0 = default on first load/import).
    pub key_index: u32,
    /// Whether this is the wallet's ACTIVE address (sends spend from it;
    /// one owner per transaction is a consensus rule).
    pub is_active: bool,
}

/// Overall wallet status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletStatus {
    /// Whether a wallet file exists.
    pub exists: bool,
    /// The ACTIVE address as bech32m, or empty string (sends spend from
    /// this address only — one owner per transaction).
    pub address: String,
    /// The active address's key index.
    pub active_index: u32,
    /// Confirmed balance of the ACTIVE address in μNOID.
    pub balance_micronoid: u64,
    /// Active-address balance in NOID (6 decimal places).
    pub balance_noid: f64,
    /// Number of confirmed UTXOs at the active address.
    pub utxo_count: usize,
    /// Number of derived addresses.
    pub address_count: u32,
}

/// Balance breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalance {
    /// Confirmed balance of the ACTIVE address (the spendable pool under
    /// the one-owner-per-tx rule).
    pub balance_micronoid: u64,
    pub balance_noid: f64,
    /// Number of confirmed UTXOs at the active address.
    pub utxo_count: usize,
    /// Confirmed UTXOs being spent by pending (mempool) txs.
    /// These are locked and cannot be spent again until confirmed or evicted.
    pub pending_outbound_micronoid: u64,
    /// Pending external outputs addressed to the ACTIVE address. Change from
    /// this same address is deliberately excluded.
    #[serde(default)]
    pub pending_incoming_micronoid: u64,
    /// Spendable = active balance - pending_outbound.
    pub spendable_micronoid: u64,
    pub spendable_noid: f64,
}

/// Info about a single UTXO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletUtxoInfo {
    pub slot_index: u32,
    pub value_micronoid: u64,
    /// Alloc-counter incarnation committed alongside the amount.
    pub creation_id: u64,
    pub value_noid: f64,
    pub address: String,
    pub key_index: u32,
    pub confirmed_height: u64,
    /// True while a pending mempool transaction reserves this input.
    #[serde(default)]
    pub reserved: bool,
}

/// A historical transaction entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletHistoryEntry {
    pub tx_hash: String,
    pub height: u64,
    pub direction: String, // "sent" or "received"
    /// True only for the canonical coinbase at logical transaction zero.
    #[serde(default)]
    pub is_coinbase: bool,
    pub amount_micronoid: u64,
    pub amount_noid: f64,
    pub peer_address: Option<String>,
    pub timestamp: u64,
    /// Which of our own addresses was involved (received-to or sent-from address).
    pub own_address: Option<String>,
    /// Key index of the own address.
    pub own_key_index: Option<u32>,
}

/// One durable receipt for a payment whose recipient differs from its source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletReceiptInfo {
    pub txid: String,
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
}

/// Newest-first bounded page over durable payment receipts in the local
/// wallet. Same-owner consolidations do not produce receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletReceiptsPage {
    pub page: u32,
    pub page_size: u32,
    pub total: usize,
    pub total_pages: u32,
    pub receipts: Vec<WalletReceiptInfo>,
}

/// One block mined by this local wallet and its current canonical status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMinedBlockInfo {
    pub height: u64,
    pub block_hash: String,
    pub coinbase_txid: String,
    pub timestamp: u64,
    pub reward_micronoid: u64,
    pub reward_noid: f64,
    pub payout_address: String,
    pub payout_key_index: u32,
    /// True only while the exact locally mined block remains canonical.
    pub canonical: bool,
    /// Tip-inclusive confirmation count on the current canonical chain.
    pub confirmations: u64,
    /// Exact truth from retained storage, not an inferred height comparison.
    pub full_block_available: bool,
}

/// Bounded newest-first page of blocks mined by this local wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMinedBlocksPage {
    pub page: u32,
    pub page_size: u32,
    pub total: usize,
    pub total_pages: u32,
    pub blocks: Vec<WalletMinedBlockInfo>,
}

/// Result of reloading the active owner from one verified durable snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletScanResult {
    pub found_utxos: usize,
    pub balance_micronoid: u64,
    pub balance_noid: f64,
    pub active_index: u32,
    pub snapshot_height: u64,
    pub snapshot_tip_hash: String,
    pub snapshot_state_root: String,
}

/// Detailed deterministic fee calculation exposed over RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeBreakdownInfo {
    /// Fixed per-transaction anti-DoS component.
    pub base: u64,
    /// Small anti-DoS/prover-work component for live inputs.
    pub input: u64,
    /// Output component for created live UTXOs.
    pub output: u64,
    /// Aggregate input + output component.
    pub io: u64,
    /// Burned state-growth component for net-new live slots.
    pub state_growth: u64,
    /// Consensus-required minimum before relay floor.
    pub required_total: u64,
    /// Current relay/mempool floor applied by this node.
    pub relay_floor: u64,
    /// Required amount accepted by this node: max(required_total, relay_floor).
    pub relay_total: u64,
    /// Actual fee this estimate/transaction pays. For estimates this equals
    /// `relay_total`; for no-change wallet transactions it can be higher and
    /// the excess is a miner tip.
    pub paid_total: u64,
    /// Portion burned by consensus.
    pub burned: u64,
    /// Miner-claimable portion at `paid_total`.
    pub miner_claimable: u64,
}

/// Fee estimate for explicit live input/output counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub n_inputs: usize,
    pub n_outputs: usize,
    pub net_new_slots: u64,
    pub active_slot_count: u64,
    pub log_slots: u32,
    pub fee_micronoid: u64,
    pub breakdown: FeeBreakdownInfo,
}

/// Dry-run plan for one ordinary Tx8x2 payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSendPlan {
    pub amount_micronoid: u64,
    pub fee_micronoid: u64,
    pub total_spend_micronoid: u64,
    pub input_count: usize,
    pub output_count: usize,
    pub change_micronoid: u64,
    pub fee_breakdown: FeeBreakdownInfo,
}

/// Stable JSON-RPC code for a payment that exceeds the canonical input limit.
pub const WALLET_INPUT_LIMIT_EXCEEDED_CODE: i32 = -32011;
/// Stable JSON-RPC message for a payment that exceeds the canonical input limit.
pub const WALLET_INPUT_LIMIT_EXCEEDED_MESSAGE: &str = "InputLimitExceeded";

/// JSON-RPC error data when no legal payment can be formed within the fixed
/// transaction input bound.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInputLimitExceeded {
    pub max_inputs: usize,
}

/// One successfully admitted ordinary payment transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSendResult {
    pub txid: String,
    pub amount_micronoid: u64,
    pub fee_micronoid: u64,
    pub input_count: usize,
    pub output_count: usize,
}

/// Maximum number of active-owner UTXOs merged by one GUI consolidation.
///
/// The protocol supports larger paged spends, but keeping the wallet action at
/// 64 inputs bounds interactive proving latency, remains comfortably inside
/// B25 page capacity and leaves additional UTXOs for a later consolidation.
pub const WALLET_CONSOLIDATION_INPUT_LIMIT: usize = 64;

/// Exact live consolidation quote produced from the active wallet snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConsolidationPlan {
    pub input_value_micronoid: u64,
    pub fee_micronoid: u64,
    pub output_value_micronoid: u64,
    pub balance_before_micronoid: u64,
    pub balance_after_micronoid: u64,
    pub input_count: usize,
    pub untouched_count: usize,
    pub remaining_count: usize,
    pub freed_slots: usize,
    pub selected_input_slots: Vec<u32>,
    pub fee_breakdown: FeeBreakdownInfo,
}

/// One successfully admitted active-wallet consolidation transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConsolidationResult {
    pub txid: String,
    pub input_value_micronoid: u64,
    pub fee_micronoid: u64,
    pub output_value_micronoid: u64,
    pub input_count: usize,
    pub output_count: usize,
    pub freed_slots: usize,
}

/// Decoded block header (structured, not raw bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderInfo {
    pub height: u64,
    /// H_BLOCK hash of this header (64-char hex).
    pub hash: String,
    /// H_BLOCK hash of the parent header.
    pub prev_hash: String,
    /// Poseidon2b Merkle root of UTXO state after this block.
    pub state_root: String,
    /// Poseidon2b Merkle root of transactions in this block.
    pub tx_root: String,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    /// Coinbase recipient address (bech32m).
    pub miner: String,
    /// Fixed-width hexadecimal encoding of the little-endian u128 PoW nonce.
    pub nonce_hex: String,
    /// Poseidon2b PoW difficulty target (64-char hex, LE).
    pub difficulty_target: String,
    /// log₂ of total UTXO slot space capacity.
    pub log_slots: u32,
    /// Live UTXO count after this block.
    pub active_slot_count: u64,
    /// Monotonic PRNG seed for coinbase slot allocation.
    pub alloc_counter: u64,
}

/// One logical transaction summary decoded from a retained full block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTransactionInfo {
    pub position: u16,
    pub txid: String,
    pub page_count: u16,
    pub live_inputs: u16,
    pub live_outputs: u16,
    pub fee_micronoid: u64,
    pub coinbase: bool,
    /// Deterministic batched payout of the two development-reward shares.
    #[serde(default)]
    pub development_payout: bool,
    /// Shared anti-replay anchor carried by every physical page.
    pub epoch_anchor: String,
    /// One owner shared by every live input. Coinbase has no input owner.
    pub input_owner: Option<String>,
    /// Decimal u128 strings preserve exact aggregate values in JSON.
    pub input_sum_micronoid: String,
    pub output_sum_micronoid: String,
    /// Hash of every physical Tx8x2 page composing this logical transaction.
    pub page_hashes: Vec<String>,
    pub inputs: Vec<BlockTransactionInputInfo>,
    pub outputs: Vec<BlockTransactionOutputInfo>,
}

/// One live input inside a retained logical transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTransactionInputInfo {
    pub page: u16,
    pub lane: u8,
    pub slot_index: u32,
    pub amount_micronoid: u64,
    pub creation_id: u64,
}

/// One live output inside a retained logical transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTransactionOutputInfo {
    pub page: u16,
    pub lane: u8,
    pub slot_index: u32,
    pub amount_micronoid: u64,
    pub owner: String,
    /// Incarnation assigned when this output was applied to the state.
    pub creation_id: u64,
}

/// Body-dependent detail available only while the node retains the full block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetainedBlockInfo {
    pub proof_class: String,
    /// Coinbase, optional development payout, and logical PagedSpend groups.
    pub logical_transactions: u16,
    pub user_pages: u16,
    pub live_inputs: u16,
    /// Includes all system-mint outputs.
    pub live_outputs: u16,
    pub reward_micronoid: u64,
    pub reward_noid: f64,
    /// Decimal u128 string; a complete block can aggregate more than u64.
    pub total_fees_micronoid: String,
    pub block_bytes: u64,
    pub history_step_bytes: u64,
    pub bundle_bytes: u64,
    pub transactions: Vec<BlockTransactionInfo>,
}

/// Permanent canonical header plus optional data from the retained body window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDetailsInfo {
    pub header: BlockHeaderInfo,
    pub retained: Option<RetainedBlockInfo>,
}

/// Compact logical-transaction row from the consensus-retained body window.
/// Full inputs, outputs and page hashes remain lazy and are returned only by
/// `getBlockDetails` after the user opens one row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentTransactionInfo {
    pub height: u64,
    pub block_hash: String,
    pub timestamp: u64,
    pub position: u16,
    pub txid: String,
    pub page_count: u16,
    pub live_inputs: u16,
    pub live_outputs: u16,
    pub fee_micronoid: u64,
    pub coinbase: bool,
    /// Deterministic batched payout of the two development-reward shares.
    #[serde(default)]
    pub development_payout: bool,
    pub input_owner: Option<String>,
    /// Decimal u128 strings preserve exact aggregates in JSON.
    pub input_sum_micronoid: String,
    pub output_sum_micronoid: String,
    /// Present only when the request filters by an address.
    pub address_spent_micronoid: Option<String>,
    /// Present only when the request filters by an address.
    pub address_received_micronoid: Option<String>,
}

/// One bounded page over logical transactions in retained full blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentTransactionsPage {
    pub page: u32,
    pub page_size: u32,
    pub total: usize,
    pub total_pages: u32,
    pub tip_height: u64,
    pub retained_from_height: u64,
    pub address: Option<String>,
    pub transactions: Vec<RecentTransactionInfo>,
}

/// Transaction location info (from the permanent tx index).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInfo {
    /// Canonical logical transaction id (64-char hex).
    pub tx_hash: String,
    /// Block height where this tx was confirmed.
    pub height: u64,
    /// H_BLOCK of the confirming block.
    pub block_hash: String,
    /// Zero-based position in the logical tx tree (coinbase is position zero).
    pub tx_position: u32,
}

/// Mining / network status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningInfo {
    /// Current tip height.
    pub height: u64,
    /// Number of leading zero bits in the current difficulty target.
    pub difficulty_bits: u32,
    /// Difficulty target as 64-char hex (LE 256-bit).
    pub difficulty_target: String,
    /// Block reward for the next block in μNOID.
    pub block_reward_micronoid: u64,
    /// Block reward in NOID.
    pub block_reward_noid: f64,
    /// Number of live UTXOs (determines reward via occupancy formula).
    pub active_slot_count: u64,
}

/// Coarse initial synchronization stage for operator interfaces.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeSyncStage {
    #[default]
    Headers,
    State,
    Tip,
}

/// Runtime status of the daemon which serves this RPC endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    /// Whether the node has established a current canonical chain view.
    pub synced: bool,
    /// Coarse initial synchronization stage. Once `synced` is true, callers
    /// should present the node as synchronized regardless of this value.
    pub sync_stage: NodeSyncStage,
    /// Whether this process owns the built-in miner.
    pub mining: bool,
    /// Whether block production may safely extend the current synchronized tip.
    pub mining_ready: bool,
    /// Compatible peers which have confirmed or advanced the canonical tip.
    pub mining_confirmed_peers: usize,
    /// Confirmed peers required for ordinary block production (currently one).
    pub mining_required_peers: usize,
    /// Explicit isolated/genesis mode bypasses the peer quorum.
    pub isolated_mining: bool,
    /// Runtime-selected CPU implementation.
    pub backend: String,
    /// Logical CPUs visible to the process.
    pub available_threads: usize,
    /// Workers in the single shared proof/mining pool.
    pub worker_threads: usize,
    /// The P2P reactor has published a heartbeat within its bounded window.
    pub p2p_healthy: bool,
    /// Age of the latest lock-free P2P heartbeat.
    pub p2p_heartbeat_age_ms: u64,
    /// Raw established peer identities visible to the swarm.
    pub p2p_connected_peers: usize,
    /// Profile-authenticated peers safe for exact-object dispatch.
    pub p2p_dispatchable_peers: usize,
    /// Active Circuit Relay v2 reservations held by this node.
    pub p2p_relay_reservations: usize,
    /// Reserved control/header queue pressure, independent from bulk data.
    pub p2p_control_queue: usize,
    pub p2p_header_queue: usize,
    /// Combined bulk command/event queue pressure.
    pub p2p_data_queue: usize,
    /// Correlated outbound requests awaiting a terminal event.
    pub p2p_pending_requests: usize,
}

/// Current UTXO state dimensions and fill metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateInfo {
    /// log₂ of total slot capacity. Capacity = 2^log_slots.
    pub log_slots: u32,
    /// Total slot space capacity (2^log_slots).
    pub capacity: u64,
    /// Live (non-zero) UTXOs.
    pub active_slots: u64,
    /// Fill percentage (active / capacity × 100), rounded to 2 decimal places.
    pub fill_pct: f64,
    /// Slots remaining before current occupancy reaches the 75% sample
    /// threshold. Negative means the current header is above that threshold;
    /// expansion still requires the consensus finalized-window majority.
    pub slots_until_expand: i64,
    /// Expansion trigger threshold in percent (always 75).
    pub expand_trigger_pct: u8,
    /// Maximum allowed log_slots (slot space cannot grow beyond 2^log_slots_max).
    pub log_slots_max: u32,
    /// Exact canonical sparse bytes in the current-state segment table.
    /// Virtual-zero segments consume no bytes; MDBX page/index overhead is
    /// deliberately excluded.
    pub state_bytes: u64,
    /// Human-readable resident/encoded/current-domain/protocol-limit breakdown.
    /// Encoded bytes exclude MDBX page and owner-index overhead, which depend
    /// on the storage engine and workload.
    pub state_size_human: String,
}

/// Bounded occupancy map of the live state for operator and wallet UIs.
///
/// The map has at most 256 buckets. At the launch `m24` state each bucket is
/// one physical segment; after state expansion adjacent segments are folded
/// into the same stable 16×16 atlas cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMapInfo {
    pub log_slots: u32,
    pub bucket_capacity: u64,
    pub live_counts: Vec<u64>,
}

/// Result of `validateAddress`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    /// Whether the address is valid.
    pub valid: bool,
    /// Canonical bech32m form (`o1…`).
    pub bech32: Option<String>,
    /// Raw 32-byte payload as hex.
    pub hex: Option<String>,
    /// Error message if invalid.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Convert μNOID to NOID with 6 decimal places.
#[inline]
pub fn micronoid_to_noid(micronoid: u64) -> f64 {
    micronoid as f64 / 1_000_000.0
}

// ---------------------------------------------------------------------------
// Mempool types
// ---------------------------------------------------------------------------

/// Information about a single pending transaction in the mempool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolTxInfo {
    /// Canonical logical transaction id (hex).
    pub tx_hash: String,
    /// Fee in μNOID.
    pub fee_micronoid: u64,
    /// Fee rate using weighted resource units (`inputs + outputs + 4 × net_new_slots`).
    pub fee_rate: u64,
    /// Number of live inputs.
    pub n_inputs: usize,
    /// Number of live outputs.
    pub n_outputs: usize,
    /// Number of physical Tx8x2 pages in this indivisible logical transaction.
    pub page_count: usize,
    /// Smallest block proof class capable of including the complete intent.
    pub minimum_proof_class: String,
    /// True while this pending intent requires a B255-qualified producer.
    pub requires_b255_miner: bool,
    /// Chain height at admission.
    pub admitted_height: u64,
    /// Whether a wallet authorization bundle is cached.
    pub has_authorization: bool,
}

/// Summary of the current mempool state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolInfo {
    /// Number of pending transactions.
    pub size: usize,
    /// Current dynamic fee floor in μNOID.
    pub fee_floor: u64,
    /// All pending transactions.
    pub txs: Vec<MempoolTxInfo>,
}

/// Constant-size mempool pressure summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolStats {
    pub size: usize,
    pub capacity: usize,
    pub intent_bytes: u64,
    pub max_intent_bytes: u64,
    pub fee_floor: u64,
}

#[cfg(test)]
mod tests {
    use super::NodeSyncStage;

    #[test]
    fn node_sync_stage_has_stable_wire_names() {
        assert_eq!(
            serde_json::to_string(&NodeSyncStage::Headers).unwrap(),
            "\"headers\""
        );
        assert_eq!(
            serde_json::to_string(&NodeSyncStage::State).unwrap(),
            "\"state\""
        );
        assert_eq!(
            serde_json::to_string(&NodeSyncStage::Tip).unwrap(),
            "\"tip\""
        );
    }
}
