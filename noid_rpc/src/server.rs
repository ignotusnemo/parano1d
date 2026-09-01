// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! JSON-RPC server implementation.
//!
//! All JSON-RPC methods are implemented. See API.md for the full method reference.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jsonrpsee::core::async_trait;
use jsonrpsee::core::RpcResult;
use jsonrpsee::server::middleware::rpc::{RpcServiceBuilder, RpcServiceT};
use jsonrpsee::server::{serve_with_graceful_shutdown, stop_channel, MethodResponse, Server};
use jsonrpsee::types::{ErrorObject, Request};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use zeroize::Zeroize;

use noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH;
use noid_chain::consensus::pow::{
    block_id, pow_header_fields, validate_pow, POW_NONCE_FIELD_INDEX,
};
use noid_chain::consensus::wire_limits::{
    hex_chars_for_bytes, MAX_RPC_RECEIPT_BYTES, MAX_RPC_SALT_BYTES, MAX_TX_INTENT_BYTES_GLOBAL,
};
use noid_chain::storage::MdbxChainContext;
use noid_mempool::AsyncMempool;
use noid_miner::template::{TemplateBuilder, TemplateChainSnapshot};
use noid_miner::{AdaptiveProofCapacity, PreparedBlockAttempt};

use crate::api::ParanoidApiServer;
use crate::types::{
    AddressInfo, BlockDetailsInfo, BlockHeaderInfo, BlockTemplateResponse, BlockTransactionInfo,
    BlockTransactionInputInfo, BlockTransactionOutputInfo, ChainInfo, FeeBreakdownInfo,
    FeeEstimate, MempoolInfo, MempoolStats, MempoolTxInfo, MiningInfo, NodeStatus, NodeSyncStage,
    ReceiptInputInfo, ReceiptOutputInfo, ReceiptSummaryInfo, ReceiptVerifyResult,
    RecentTransactionInfo, RecentTransactionsPage, RetainedBlockInfo, SlotInfo, StateInfo,
    StateMapInfo, TxInfo, WalletAddressInfo, WalletBalance, WalletConsolidationPlan,
    WalletConsolidationResult, WalletHistoryEntry, WalletInputLimitExceeded, WalletMinedBlockInfo,
    WalletMinedBlocksPage, WalletReceiptInfo, WalletReceiptsPage, WalletScanResult, WalletSendPlan,
    WalletSendResult, WalletStatus, WalletUtxoInfo, WALLET_CONSOLIDATION_INPUT_LIMIT,
    WALLET_INPUT_LIMIT_EXCEEDED_CODE, WALLET_INPUT_LIMIT_EXCEEDED_MESSAGE,
};
use crate::wallet_ops::{WalletActivationPreview, WalletOps, WalletSendPlanError};
use crate::wallet_submit::{
    collect_empty_slot_hints, next_user_epoch_anchor, PendingAdmissionGuard, WalletOperationGate,
};

/// External workers receive only a short-lived capability for immutable
/// node-owned material.  The server retains exactly one attempt across its
/// preparation, PoW, proof and commit lifecycle.
const EXTERNAL_MINING_TEMPLATE_TTL: Duration = Duration::from_secs(30);

/// Large enough for the maximum canonical transaction intent encoded as JSON
/// hex, while rejecting jsonrpsee's otherwise unnecessary 10 MiB default.
const RPC_MAX_REQUEST_BODY_BYTES: u32 = 1024 * 1024;

type ExternalMiningTemplateId = [u8; 16];

fn rpc_err(msg: impl Into<String>) -> ErrorObject<'static> {
    ErrorObject::owned(-32000, msg.into(), None::<()>)
}

fn mined_record_is_canonical(
    recorded_block_hash: Option<[u8; 32]>,
    recorded_timestamp: u64,
    recorded_payout_address: &str,
    canonical_header: &noid_chain::block_header::BlockHeader,
) -> bool {
    recorded_block_hash.map_or_else(
        || {
            recorded_timestamp == canonical_header.timestamp
                && recorded_payout_address == canonical_header.miner_address.to_bech32()
        },
        |mined_hash| mined_hash == block_id(canonical_header),
    )
}

fn discover_contiguous_funded_prefix<E>(
    expected_next_index: u32,
    candidates: &[(u32, [u8; 32])],
    mut is_funded: impl FnMut(&[u8; 32]) -> Result<bool, E>,
) -> Result<u32, E> {
    let mut discovered_next_index = expected_next_index;
    for (index, owner) in candidates {
        if !is_funded(owner)? {
            break;
        }
        discovered_next_index = index.saturating_add(1);
    }
    Ok(discovered_next_index)
}

fn block_header_info(header: &noid_chain::BlockHeader) -> BlockHeaderInfo {
    use noid_poseidon2b::primitives::Address;

    BlockHeaderInfo {
        height: header.height,
        hash: hex::encode(block_id(header)),
        prev_hash: hex::encode(header.prev_block_hash),
        state_root: hex::encode(header.state_root),
        tx_root: hex::encode(header.tx_root),
        timestamp: header.timestamp,
        miner: Address(header.miner_address.0).to_bech32(),
        nonce_hex: hex::encode(header.nonce.to_le_bytes()),
        difficulty_target: hex::encode(header.difficulty_target),
        log_slots: header.log_slots,
        active_slot_count: header.active_slot_count,
        alloc_counter: header.alloc_counter,
    }
}

fn retained_transaction_summaries(
    header: &noid_chain::BlockHeader,
    bundle_bytes: &[u8],
    address: Option<&noid_poseidon2b::primitives::Address>,
) -> Result<Vec<RecentTransactionInfo>, String> {
    let bundle = noid_chain::AcceptedBlockBundle::decode(bundle_bytes)
        .map_err(|error| format!("decode retained block bundle: {error}"))?;
    let block = noid_chain::Block::from_bytes(bundle.block_bytes())
        .map_err(|error| format!("decode retained block: {error:?}"))?;
    if block.header != *header {
        return Err("retained block header does not match canonical header".into());
    }
    let stream = noid_chain::validate_block_page_stream(&block.transactions)
        .map_err(|error| format!("decode retained transaction stream: {error}"))?;
    let logical_txids = noid_chain::try_compute_logical_txids(&block.transactions)
        .map_err(|error| format!("derive retained transaction ids: {error}"))?;
    let coinbase = block
        .transactions
        .first()
        .ok_or_else(|| "retained block is missing coinbase".to_string())?;
    let block_hash = hex::encode(block_id(header));

    let coinbase_output_sum = coinbase
        .body
        .live_outputs()
        .map(|(_, output)| u128::from(output.amount))
        .sum::<u128>();
    let coinbase_received = address.map(|owner| {
        coinbase
            .body
            .live_outputs()
            .filter(|(_, output)| &output.owner == owner)
            .map(|(_, output)| u128::from(output.amount))
            .sum::<u128>()
    });
    let coinbase_outputs = u16::try_from(coinbase.body.live_outputs().count())
        .map_err(|_| "coinbase output count does not fit u16".to_string())?;
    let mut transactions = Vec::with_capacity(logical_txids.len());
    if coinbase_received.is_none_or(|received| received > 0) {
        transactions.push(RecentTransactionInfo {
            height: header.height,
            block_hash: block_hash.clone(),
            timestamp: header.timestamp,
            position: 0,
            txid: hex::encode(
                logical_txids
                    .first()
                    .ok_or_else(|| "retained block has no logical coinbase id".to_string())?
                    .0,
            ),
            page_count: 1,
            live_inputs: 0,
            live_outputs: coinbase_outputs,
            fee_micronoid: 0,
            coinbase: true,
            development_payout: false,
            input_owner: None,
            input_sum_micronoid: "0".into(),
            output_sum_micronoid: coinbase_output_sum.to_string(),
            address_spent_micronoid: address.map(|_| "0".into()),
            address_received_micronoid: coinbase_received.map(|value| value.to_string()),
        });
    }

    if stream.has_development_payout {
        let payout = &block.transactions[1];
        let payout_output_sum = payout
            .body
            .live_outputs()
            .map(|(_, output)| u128::from(output.amount))
            .sum::<u128>();
        let payout_received = address.map(|owner| {
            payout
                .body
                .live_outputs()
                .filter(|(_, output)| &output.owner == owner)
                .map(|(_, output)| u128::from(output.amount))
                .sum::<u128>()
        });
        if payout_received.is_none_or(|received| received > 0) {
            transactions.push(RecentTransactionInfo {
                height: header.height,
                block_hash: block_hash.clone(),
                timestamp: header.timestamp,
                position: 1,
                txid: hex::encode(logical_txids[1].0),
                page_count: 1,
                live_inputs: 0,
                live_outputs: 2,
                fee_micronoid: 0,
                coinbase: true,
                development_payout: true,
                input_owner: None,
                input_sum_micronoid: "0".into(),
                output_sum_micronoid: payout_output_sum.to_string(),
                address_spent_micronoid: address.map(|_| "0".into()),
                address_received_micronoid: payout_received.map(|value| value.to_string()),
            });
        }
    }

    for (index, group) in stream.groups.iter().enumerate() {
        let (address_spent, address_received) = if let Some(owner) = address {
            let spent = if &group.spend.input_owner == owner {
                group.spend.input_sum
            } else {
                0
            };
            let start = stream.user_body_start(usize::from(group.start_page));
            let end = start
                .checked_add(usize::from(group.page_count))
                .ok_or_else(|| "retained transaction page range overflow".to_string())?;
            let pages = block
                .transactions
                .get(start..end)
                .ok_or_else(|| "retained transaction page range is unavailable".to_string())?;
            let received = pages
                .iter()
                .flat_map(|page| page.body.live_outputs())
                .filter(|(_, output)| &output.owner == owner)
                .map(|(_, output)| u128::from(output.amount))
                .sum::<u128>();
            if spent == 0 && received == 0 {
                continue;
            }
            (Some(spent.to_string()), Some(received.to_string()))
        } else {
            (None, None)
        };

        transactions.push(RecentTransactionInfo {
            height: header.height,
            block_hash: block_hash.clone(),
            timestamp: header.timestamp,
            position: u16::try_from(stream.user_logical_index(index))
                .map_err(|_| "logical transaction position does not fit u16".to_string())?,
            txid: hex::encode(group.spend.logical_txid.0),
            page_count: group.page_count,
            live_inputs: group.spend.live_inputs,
            live_outputs: group.spend.live_outputs,
            fee_micronoid: group.spend.fee,
            coinbase: false,
            development_payout: false,
            input_owner: Some(group.spend.input_owner.to_bech32()),
            input_sum_micronoid: group.spend.input_sum.to_string(),
            output_sum_micronoid: group.spend.output_sum.to_string(),
            address_spent_micronoid: address_spent,
            address_received_micronoid: address_received,
        });
    }
    Ok(transactions)
}

fn wallet_plan_error(error: WalletSendPlanError) -> ErrorObject<'static> {
    match error {
        WalletSendPlanError::InputLimitExceeded { max_inputs } => ErrorObject::owned(
            WALLET_INPUT_LIMIT_EXCEEDED_CODE,
            WALLET_INPUT_LIMIT_EXCEEDED_MESSAGE,
            Some(WalletInputLimitExceeded { max_inputs }),
        ),
        other => rpc_err(other.to_string()),
    }
}

/// Read a canonical slot without treating an MDBX-evicted segment as virtual
/// zero. `SegmentedFriState::slot` intentionally cannot distinguish those at
/// the read call site, so RPC reads hydrate the one needed segment from the
/// durable store. The cache amortizes owner-index responses with many UTXOs in
/// the same segment.
fn read_canonical_slot(
    chain: &MdbxChainContext,
    slot_index: u32,
    segment_cache: &mut HashMap<u16, noid_chain::segmented_state::SegmentColumns>,
) -> Result<noid_chain::fri_state::SlotValue, String> {
    use noid_chain::fri_state::SlotValue;

    let state = &chain.state.state;
    if u64::from(slot_index) >= state.num_slots() {
        return Err(format!("slot {slot_index} is out of range"));
    }
    let segment_log = state.effective_log_segment_size();
    let segment_id = (slot_index >> segment_log) as u16;
    if !state.is_evicted(segment_id) {
        return Ok(state.slot(slot_index));
    }

    if !segment_cache.contains_key(&segment_id) {
        let Some((stored_log, columns)) = chain
            .store
            .get_segment(segment_id)
            .map_err(|error| error.to_string())?
        else {
            return Err(format!(
                "evicted segment {segment_id} is missing from durable state"
            ));
        };
        if usize::from(stored_log) != segment_log {
            return Err(format!(
                "segment {segment_id} depth mismatch: stored {stored_log}, expected {segment_log}"
            ));
        }
        segment_cache.insert(segment_id, columns);
    }

    let local_mask = (1u32 << segment_log) - 1;
    let local_index = (slot_index & local_mask) as usize;
    let columns = &segment_cache[&segment_id];
    if local_index >= columns.values.len()
        || local_index >= columns.owners_hi.len()
        || local_index >= columns.owners_lo.len()
    {
        return Err(format!(
            "segment {segment_id} is too short for local slot {local_index}"
        ));
    }
    Ok(SlotValue {
        value: columns.values[local_index],
        owner_hi: columns.owners_hi[local_index],
        owner_lo: columns.owners_lo[local_index],
    })
}

fn history_step_terminal_bytes(ctx: &MdbxChainContext) -> Result<Option<Vec<u8>>, String> {
    let finalized = ctx.finalized_checkpoint();
    if finalized.height == 0 {
        return Ok(None);
    }
    ctx.store
        .get_history_step_terminal_at(finalized.height, finalized.hash)
        .map_err(|error| {
            format!(
                "HistoryStep terminal read h={} failed: {error}",
                finalized.height
            )
        })
}

#[inline]
fn trim_hex_prefix(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

fn encode_pow_fields_hex(header: &noid_chain::BlockHeader) -> String {
    let fields = pow_header_fields(header);
    let mut bytes = Vec::with_capacity(fields.len() * 16);
    for field in fields {
        bytes.extend_from_slice(&field.to_u128().to_le_bytes());
    }
    hex::encode(bytes)
}

fn ensure_hex_max_chars(
    name: &str,
    hex_str: &str,
    max_bytes: usize,
) -> Result<(), ErrorObject<'static>> {
    let hex_str = trim_hex_prefix(hex_str);
    let max_chars = hex_chars_for_bytes(max_bytes);
    if hex_str.len() > max_chars {
        return Err(rpc_err(format!(
            "{name} too large: {} hex chars (max {max_chars}, {max_bytes} bytes)",
            hex_str.len()
        )));
    }
    Ok(())
}

fn decode_bounded_hex(
    name: &str,
    hex_str: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, ErrorObject<'static>> {
    ensure_hex_max_chars(name, hex_str, max_bytes)?;
    hex::decode(trim_hex_prefix(hex_str)).map_err(|e| rpc_err(format!("{name} hex decode: {e}")))
}

fn decode_32_byte_hex(name: &str, hex_str: &str) -> Result<[u8; 32], ErrorObject<'static>> {
    let hex_str = trim_hex_prefix(hex_str);
    if hex_str.len() != 64 {
        return Err(rpc_err(format!("invalid {name}: expected 64-char hex")));
    }
    hex::decode(hex_str)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| rpc_err(format!("invalid {name}: expected 32-byte hex")))
}

fn decode_canonical_fixed_hex<const N: usize>(
    name: &str,
    encoded: &str,
) -> Result<[u8; N], ErrorObject<'static>> {
    if encoded.len() != N.saturating_mul(2) {
        return Err(rpc_err(format!(
            "invalid {name}: expected exactly {} lowercase hex chars",
            N.saturating_mul(2)
        )));
    }
    let decoded = hex::decode(encoded)
        .map_err(|error| rpc_err(format!("invalid {name}: canonical hex decode: {error}")))?;
    if hex::encode(&decoded) != encoded {
        return Err(rpc_err(format!(
            "invalid {name}: expected canonical lowercase hex without a prefix"
        )));
    }
    decoded
        .try_into()
        .map_err(|_| rpc_err(format!("invalid {name}: expected exactly {} bytes", N)))
}

fn decode_external_template_id(
    encoded: &str,
) -> Result<ExternalMiningTemplateId, ErrorObject<'static>> {
    decode_canonical_fixed_hex("template_id", encoded)
}

fn decode_external_nonce_hex(encoded: &str) -> Result<u128, ErrorObject<'static>> {
    let bytes = decode_canonical_fixed_hex::<16>("nonce_hex", encoded)?;
    Ok(u128::from_le_bytes(bytes))
}

#[inline]
fn node_entropy_nonce() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[inline]
fn mix_slot_hint_seed(tip_seed: u64, salt: u64) -> u64 {
    let mut s = tip_seed ^ salt ^ 0x9E37_79B9_7F4A_7C15;
    noid_chain::consensus::allocator::splitmix64(&mut s)
}

fn fee_breakdown_info(
    breakdown: noid_chain::consensus::FeeBreakdown,
    relay_floor: u64,
    paid_total: u64,
) -> FeeBreakdownInfo {
    let relay_total = breakdown.required_total.max(relay_floor);
    let paid_total = paid_total.max(relay_total);
    FeeBreakdownInfo {
        base: breakdown.base,
        input: breakdown.input,
        output: breakdown.output,
        io: breakdown.io,
        state_growth: breakdown.state_growth,
        required_total: breakdown.required_total,
        relay_floor,
        relay_total,
        paid_total,
        burned: breakdown.burned,
        miner_claimable: paid_total.saturating_sub(breakdown.burned),
    }
}

fn mempool_tx_info(entry: noid_mempool::MempoolEntryMetadata) -> MempoolTxInfo {
    use noid_chain::consensus::paged_spend::BlockProofClass;

    let page_count = usize::from(entry.page_count);
    let proof_class = BlockProofClass::for_page_count(page_count)
        .expect("admitted PagedSpend always fits a consensus proof class");
    let requires_b255_miner = matches!(proof_class, BlockProofClass::B255);
    MempoolTxInfo {
        tx_hash: hex::encode(entry.tx_hash.0),
        fee_micronoid: entry.fee_micronoid,
        fee_rate: entry.fee_rate,
        n_inputs: usize::from(entry.n_inputs),
        n_outputs: usize::from(entry.n_outputs),
        page_count,
        minimum_proof_class: if requires_b255_miner { "B255" } else { "B25" }.to_owned(),
        requires_b255_miner,
        admitted_height: entry.admitted_height,
        has_authorization: entry.has_authorization,
    }
}

fn validate_tx_counts(n_inputs: usize, n_outputs: usize) -> Result<(), ErrorObject<'static>> {
    if (1..=noid_tx::MAX_PAGED_SPEND_INPUTS).contains(&n_inputs)
        && (1..=noid_tx::MAX_PAGED_SPEND_OUTPUTS).contains(&n_outputs)
    {
        Ok(())
    } else {
        Err(rpc_err(format!(
            "canonical PagedSpend supports 1..={} inputs and 1..={} outputs, got {n_inputs} and {n_outputs}",
            noid_tx::MAX_PAGED_SPEND_INPUTS,
            noid_tx::MAX_PAGED_SPEND_OUTPUTS,
        )))
    }
}

fn seed_from_salt_hex(salt_hex: &str) -> Result<u64, ErrorObject<'static>> {
    let bytes = decode_bounded_hex("salt", salt_hex, MAX_RPC_SALT_BYTES)?;
    let mut acc = 0xD6E8_FD9D_AA28_4A7Bu64;
    for chunk in bytes.chunks(8) {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        acc ^= u64::from_le_bytes(word);
        acc = noid_chain::consensus::allocator::splitmix64(&mut acc);
    }
    Ok(acc)
}

struct CachedExternalMiningTemplate<T> {
    prepared: T,
    template_id: ExternalMiningTemplateId,
    parent_height: u64,
    parent_id: [u8; 32],
    expires_at: Instant,
}

enum ExternalMiningAttemptState<T> {
    Idle,
    Preparing {
        template_id: ExternalMiningTemplateId,
        invalidated: bool,
    },
    Ready(CachedExternalMiningTemplate<T>),
    Proving {
        template_id: ExternalMiningTemplateId,
    },
}

/// The external miner owns one attempt, not a cache of independent proofs.
/// The generic payload keeps the lifecycle testable without constructing a
/// cryptographic witness in unit tests.
struct ExternalMiningAttemptSlot<T> {
    state: ExternalMiningAttemptState<T>,
    namespace: u64,
    next_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExternalMiningConsumeError {
    Unavailable,
    Stale,
}

impl<T> ExternalMiningAttemptSlot<T> {
    fn new(namespace: u64) -> Self {
        Self {
            state: ExternalMiningAttemptState::Idle,
            namespace,
            next_sequence: 0,
        }
    }

    fn purge_expired(&mut self, now: Instant) {
        let expired = matches!(
            &self.state,
            ExternalMiningAttemptState::Ready(cached) if cached.expires_at <= now
        );
        if expired {
            self.state = ExternalMiningAttemptState::Idle;
        }
    }

    fn reserve_preparation(&mut self, now: Instant) -> Result<ExternalMiningTemplateId, String> {
        self.purge_expired(now);
        if !matches!(self.state, ExternalMiningAttemptState::Idle) {
            return Err("external mining attempt is already active".to_string());
        }
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let mut template_id = [0u8; 16];
        template_id[..8].copy_from_slice(&self.namespace.to_le_bytes());
        template_id[8..].copy_from_slice(&self.next_sequence.to_le_bytes());
        self.state = ExternalMiningAttemptState::Preparing {
            template_id,
            invalidated: false,
        };
        Ok(template_id)
    }

    fn cancel_preparation(&mut self, template_id: ExternalMiningTemplateId) {
        if matches!(
            &self.state,
            ExternalMiningAttemptState::Preparing {
                template_id: active,
                ..
            } if *active == template_id
        ) {
            self.state = ExternalMiningAttemptState::Idle;
        }
    }

    fn install_ready(
        &mut self,
        template_id: ExternalMiningTemplateId,
        prepared: T,
        parent_height: u64,
        parent_id: [u8; 32],
        expires_at: Instant,
    ) -> Result<(), String> {
        let installable = matches!(
            &self.state,
            ExternalMiningAttemptState::Preparing {
                template_id: active,
                invalidated: false,
            } if *active == template_id
        );
        if !installable {
            self.cancel_preparation(template_id);
            return Err("external mining preparation was invalidated".to_string());
        }
        self.state = ExternalMiningAttemptState::Ready(CachedExternalMiningTemplate {
            prepared,
            template_id,
            parent_height,
            parent_id,
            expires_at,
        });
        Ok(())
    }

    fn expire_ready(&mut self, template_id: ExternalMiningTemplateId, now: Instant) {
        if matches!(
            &self.state,
            ExternalMiningAttemptState::Ready(cached)
                if cached.template_id == template_id && cached.expires_at <= now
        ) {
            self.state = ExternalMiningAttemptState::Idle;
        }
    }

    fn begin_proving(
        &mut self,
        template_id: ExternalMiningTemplateId,
        now: Instant,
        tip_height: u64,
        tip_id: [u8; 32],
    ) -> Result<T, ExternalMiningConsumeError> {
        self.purge_expired(now);
        let previous = std::mem::replace(&mut self.state, ExternalMiningAttemptState::Idle);
        match previous {
            ExternalMiningAttemptState::Ready(cached)
                if cached.template_id == template_id
                    && cached.parent_height == tip_height
                    && cached.parent_id == tip_id =>
            {
                self.state = ExternalMiningAttemptState::Proving { template_id };
                Ok(cached.prepared)
            }
            ExternalMiningAttemptState::Ready(cached) if cached.template_id == template_id => {
                Err(ExternalMiningConsumeError::Stale)
            }
            other => {
                self.state = other;
                Err(ExternalMiningConsumeError::Unavailable)
            }
        }
    }

    fn finish_proving(&mut self, template_id: ExternalMiningTemplateId) {
        if matches!(
            &self.state,
            ExternalMiningAttemptState::Proving {
                template_id: active,
                ..
            } if *active == template_id
        ) {
            self.state = ExternalMiningAttemptState::Idle;
        }
    }

    fn invalidate_except(&mut self, tip_height: u64, tip_id: [u8; 32]) {
        match &mut self.state {
            ExternalMiningAttemptState::Idle => {}
            ExternalMiningAttemptState::Preparing { invalidated, .. } => {
                // The parent may have been captured immediately before this
                // canonical advance. Keep the owner occupied until its running
                // preparation returns, but never publish that result.
                *invalidated = true;
            }
            ExternalMiningAttemptState::Ready(cached) => {
                if cached.parent_height != tip_height || cached.parent_id != tip_id {
                    self.state = ExternalMiningAttemptState::Idle;
                }
            }
            // Proving cannot be synchronously cancelled. Keep the slot occupied
            // until its owner exits; atomic commit rejects a replaced parent.
            ExternalMiningAttemptState::Proving { .. } => {}
        }
    }
}

/// A small node-facing handle which immediately drops a ready attempt when a
/// P2P block, reorg or snapshot replaces its parent. Running preparation/proof
/// owners remain occupied until their cancellation-safe lease is dropped.
#[derive(Clone)]
pub struct ExternalMiningAttemptInvalidator {
    inner: Arc<Mutex<ExternalMiningAttemptSlot<PreparedBlockAttempt>>>,
}

impl Default for ExternalMiningAttemptInvalidator {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalMiningAttemptInvalidator {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ExternalMiningAttemptSlot::new(
                node_entropy_nonce(),
            ))),
        }
    }

    pub fn invalidate_for_tip(&self, tip_height: u64, tip_id: [u8; 32]) {
        match self.inner.lock() {
            Ok(mut slot) => slot.invalidate_except(tip_height, tip_id),
            Err(_) => tracing::error!("external mining attempt slot lock poisoned"),
        }
    }

    fn reserve_preparation(&self, now: Instant) -> Result<ExternalMiningPreparationLease, String> {
        let template_id = self
            .inner
            .lock()
            .map_err(|_| "external mining attempt slot lock poisoned".to_string())?
            .reserve_preparation(now)?;
        Ok(ExternalMiningPreparationLease {
            attempts: self.clone(),
            template_id,
            armed: true,
        })
    }

    fn begin_proving(
        &self,
        template_id: ExternalMiningTemplateId,
        now: Instant,
        tip_height: u64,
        tip_id: [u8; 32],
    ) -> Result<ExternalMiningProvingAttempt, ExternalMiningConsumeError> {
        let prepared = self
            .inner
            .lock()
            .map_err(|_| ExternalMiningConsumeError::Unavailable)?
            .begin_proving(template_id, now, tip_height, tip_id)?;
        Ok(ExternalMiningProvingAttempt {
            prepared,
            lease: ExternalMiningProvingLease {
                attempts: self.clone(),
                template_id,
            },
        })
    }
}

struct ExternalMiningPreparationLease {
    attempts: ExternalMiningAttemptInvalidator,
    template_id: ExternalMiningTemplateId,
    armed: bool,
}

impl ExternalMiningPreparationLease {
    const fn template_id(&self) -> ExternalMiningTemplateId {
        self.template_id
    }

    fn install_ready(
        mut self,
        prepared: PreparedBlockAttempt,
        parent_height: u64,
        parent_id: [u8; 32],
        now: Instant,
    ) -> Result<(), String> {
        let expires_at = now
            .checked_add(EXTERNAL_MINING_TEMPLATE_TTL)
            .ok_or_else(|| "external template expiry overflow".to_string())?;
        let retained_bytes = prepared.retained_bytes();
        self.attempts
            .inner
            .lock()
            .map_err(|_| "external mining attempt slot lock poisoned".to_string())?
            .install_ready(
                self.template_id,
                prepared,
                parent_height,
                parent_id,
                expires_at,
            )?;
        self.armed = false;
        tracing::debug!(
            template_id = %hex::encode(self.template_id),
            retained_bytes,
            "external mining attempt staged"
        );

        let attempts = self.attempts.clone();
        let template_id = self.template_id;
        tokio::spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(expires_at)).await;
            match attempts.inner.lock() {
                Ok(mut slot) => slot.expire_ready(template_id, Instant::now()),
                Err(_) => tracing::error!("external mining attempt slot lock poisoned"),
            }
        });
        Ok(())
    }
}

impl Drop for ExternalMiningPreparationLease {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        match self.attempts.inner.lock() {
            Ok(mut slot) => slot.cancel_preparation(self.template_id),
            Err(_) => tracing::error!("external mining attempt slot lock poisoned"),
        }
    }
}

struct ExternalMiningProvingAttempt {
    prepared: PreparedBlockAttempt,
    lease: ExternalMiningProvingLease,
}

struct ExternalMiningProvingLease {
    attempts: ExternalMiningAttemptInvalidator,
    template_id: ExternalMiningTemplateId,
}

impl Drop for ExternalMiningProvingLease {
    fn drop(&mut self) {
        match self.attempts.inner.lock() {
            Ok(mut slot) => slot.finish_proving(self.template_id),
            Err(_) => tracing::error!("external mining attempt slot lock poisoned"),
        }
    }
}

// ---------------------------------------------------------------------------
// RpcHandler
// ---------------------------------------------------------------------------

/// The JSON-RPC handler.
///
/// Holds shared references to the chain context, mempool, and wallet.
/// All state access goes through `Arc<RwLock<MdbxChainContext>>`.
#[derive(Clone)]
pub struct RpcHandler {
    pub chain: Arc<RwLock<MdbxChainContext>>,
    pub mempool: AsyncMempool,
    /// Shared mempool state with a local-only CPU executor for wallet
    /// authorization verification. P2P and public submitTx keep the ordinary
    /// inbound executor and cannot acquire wallet priority over PoW.
    wallet_submission_mempool: AsyncMempool,
    pub wallet: Arc<dyn WalletOps + Send + Sync>,
    /// Serializes stateful wallet RPC operations from snapshot/reload through
    /// proving and mempool admission. The wallet's short synchronous mutex is
    /// intentionally not held during proving.
    pub wallet_operation_gate: Arc<tokio::sync::Mutex<()>>,
    /// Channel to the P2P layer for queries (peer count, etc.).
    pub p2p_cmd: noid_p2p::NetworkCommandSender,
    /// Lock-free reactor heartbeat and queue snapshot. Status RPC remains
    /// responsive even while the chain writer owns its commit lock.
    pub p2p_health: tokio::sync::watch::Receiver<noid_p2p::P2PHealthSnapshot>,
    /// Exact canonical-tip notification consumed by networking readiness.
    /// A locally committed RPC block must revoke the previous parent's nonce
    /// authorization synchronously rather than waiting for a polling tick.
    pub canonical_tip_changes: tokio::sync::watch::Sender<noid_p2p::object_protocol::ChainPoint>,
    /// The same durable readiness watch consumed by the internal miner.
    pub initial_sync_ready: tokio::sync::watch::Receiver<bool>,
    /// Coarse read-only initial synchronization stage for operator clients.
    pub initial_sync_stage: tokio::sync::watch::Receiver<NodeSyncStage>,
    /// Live mining gate and its authenticated-peer count.
    pub mining_network_ready: tokio::sync::watch::Receiver<bool>,
    pub mining_confirmed_peers: tokio::sync::watch::Receiver<usize>,
    pub mining_required_peers: usize,
    pub isolated_mining: bool,
    /// Immutable process role and CPU plan selected at startup.
    pub internal_mining_enabled: bool,
    pub cpu_backend: String,
    pub available_threads: usize,
    pub worker_threads: usize,
    /// One-shot sender: firing this triggers graceful daemon shutdown
    /// (same effect as Ctrl-C). Wrapped in Mutex so the RPC handler can
    /// take ownership on first call.
    pub stop_tx: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    /// Whether getBlockTemplate/submitBlock are enabled for external PoW workers.
    /// This is true only for nodes explicitly started with `--mode extminer`.
    pub mining_api_enabled: bool,
    /// Explicit configured payout. `None` means resolve the wallet's current
    /// active address for every newly built template.
    pub mining_payout_address: Option<noid_poseidon2b::primitives::Address>,
    /// When true (requires mining_key to be set), external miners may specify
    /// any valid address as `miner_address` in getBlockTemplate and receive
    /// block rewards directly. The node operator earns via off-chain service fees.
    pub allow_custom_coinbase: bool,
    /// Pinned self-recursive HistoryStep runtime shared with local mining and
    /// inbound bundle verification.
    pub history_step_runtime:
        Option<Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>>,
    /// Process-wide prepared ghost authorization reused by every block attempt.
    pub history_step_ghost: Option<
        Arc<noid_recursive::acceptance::history_step::PreparedHistoryStepGhostAuthorization>,
    >,
    /// Every handler clone shares the same one-attempt lifecycle owner.
    external_mining_attempts: ExternalMiningAttemptInvalidator,
    /// Wakes the internal miner when a dynamic wallet payout changes.
    mining_template_changes: tokio::sync::broadcast::Sender<()>,
    /// Node-side proof capacity for external PoW templates. External workers
    /// do not choose the B25/B255 class.
    external_mining_capacity: Arc<Mutex<AdaptiveProofCapacity>>,
}

#[derive(Clone)]
enum WalletSubmissionBuild {
    Payment,
    Consolidation { selected_input_slots: Vec<u32> },
}

#[derive(Clone)]
struct WalletSubmissionRequest {
    to_address: [u8; 32],
    amount_micronoid: u64,
    fee_micronoid: u64,
    expected_input_count: usize,
    expected_output_count: usize,
    pending_history_amount_micronoid: u64,
    build: WalletSubmissionBuild,
    failure_label: &'static str,
}

impl RpcHandler {
    fn require_mining_network(&self) -> RpcResult<()> {
        if *self.mining_network_ready.borrow() {
            Ok(())
        } else {
            Err(rpc_err("mining is waiting for network synchronization"))
        }
    }

    fn resolved_mining_payout(&self) -> RpcResult<noid_poseidon2b::primitives::Address> {
        if let Some(address) = self.mining_payout_address {
            return Ok(address);
        }
        let (_, address) = self
            .wallet
            .active_address()
            .ok_or_else(|| rpc_err("wallet not initialized"))?;
        parse_address_param(&address)
    }

    async fn install_wallet_activation(
        &self,
        preview: WalletActivationPreview,
    ) -> RpcResult<(WalletAddressInfo, WalletScanResult)> {
        let (reserved_inputs, reserved_outputs) = self.mempool.reserved_slots().await;
        let chain = self.chain.read().await;
        let snapshot = chain
            .store
            .get_verified_utxos_by_owner(&preview.owner)
            .map_err(|error| rpc_err(error.to_string()))?;
        // Keep the chain read guard alive through the wallet commit. A block
        // writer cannot advance the durable tip between lookup and install.
        let result = self
            .wallet
            .commit_activation_snapshot(preview, snapshot, &reserved_inputs, &reserved_outputs)
            .map_err(rpc_err);
        drop(chain);
        result
    }

    async fn reload_active_wallet(&self) -> RpcResult<WalletScanResult> {
        let preview = self.wallet.preview_active_reload().map_err(rpc_err)?;
        let (_address, scan) = self.install_wallet_activation(preview).await?;
        Ok(scan)
    }

    async fn submit_wallet_transaction(
        &self,
        request: WalletSubmissionRequest,
    ) -> RpcResult<WalletSendResult> {
        let WalletSubmissionRequest {
            to_address,
            amount_micronoid,
            fee_micronoid,
            expected_input_count,
            expected_output_count,
            pending_history_amount_micronoid,
            build,
            failure_label,
        } = request;
        let call_nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        let mut last_error = String::new();
        for attempt in 0..3u32 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
            let reserved_outputs = self.mempool.reserved_output_slots().await;
            let selection = {
                let chain = self.chain.read().await;
                let tip = chain.tip_header();
                let unique_seed = u64::from_le_bytes(tip.state_root[..8].try_into().unwrap())
                    .wrapping_add(
                        call_nonce
                            .wrapping_add(attempt as u64)
                            .wrapping_mul(0x9e37_79b9_7f4a_7c15),
                    );
                next_user_epoch_anchor(&chain).and_then(|epoch_anchor| {
                    collect_empty_slot_hints(
                        &chain,
                        &reserved_outputs,
                        unique_seed,
                        noid_tx::TX_OUTPUTS,
                    )
                    .map(|slot_hints| (epoch_anchor, tip.log_slots, slot_hints))
                })
            };
            let (epoch_anchor, log_slots, slot_hints) = match selection {
                Ok(selection) => selection,
                Err(error) => {
                    last_error = error;
                    break;
                }
            };
            if slot_hints.len() < expected_output_count {
                last_error = "not enough empty output slots available".to_string();
                break;
            }

            let wallet = Arc::clone(&self.wallet);
            let build_attempt = build.clone();
            let (intent_bytes, input_slots) = match tokio::task::spawn_blocking(move || {
                noid_miner::install_wallet_proof_cpu(|| match build_attempt {
                    WalletSubmissionBuild::Payment => wallet.build_send(
                        to_address,
                        amount_micronoid,
                        fee_micronoid,
                        epoch_anchor,
                        slot_hints,
                        log_slots,
                    ),
                    WalletSubmissionBuild::Consolidation {
                        selected_input_slots,
                    } => wallet.build_consolidation(
                        selected_input_slots,
                        amount_micronoid,
                        fee_micronoid,
                        epoch_anchor,
                        slot_hints,
                        log_slots,
                    ),
                })
                .map_err(|error| format!("wallet proof CPU admission failed: {error}"))
                .and_then(|result| result)
            })
            .await
            {
                Ok(Ok(parts)) => parts,
                Ok(Err(error)) => {
                    last_error = error;
                    break;
                }
                Err(error) => {
                    last_error = format!("wallet proof task: {error}");
                    break;
                }
            };

            let intent = match noid_tx::PagedSpendIntent::from_bytes(&intent_bytes) {
                Ok(intent) => intent,
                Err(error) => {
                    last_error = format!("intent decode: {error:?}");
                    break;
                }
            };
            let facts = noid_tx::validate_paged_spend(&intent.pages)
                .map_err(|error| rpc_err(format!("wallet PagedSpend: {error}")))?;
            let input_count = usize::from(facts.live_inputs);
            let output_count = usize::from(facts.live_outputs);
            let actual_fee = facts.fee;
            let failed_txid = facts.logical_txid.0;
            let output_slots: Vec<u32> = intent
                .pages
                .iter()
                .flat_map(|page| page.body.live_outputs())
                .map(|(_, output)| output.slot_index)
                .collect();
            if actual_fee != fee_micronoid
                || input_count != expected_input_count
                || output_count != expected_output_count
            {
                last_error = format!(
                    "wallet builder diverged from plan: expected fee/counts {fee_micronoid}/{expected_input_count}/{expected_output_count}, got {actual_fee}/{input_count}/{output_count}"
                );
                break;
            }

            let reservation = match PendingAdmissionGuard::reserve(
                Arc::clone(&self.wallet),
                failed_txid,
                input_slots,
                output_slots,
                pending_history_amount_micronoid,
                to_address,
            ) {
                Ok(reservation) => reservation,
                Err(error) => {
                    last_error = error;
                    break;
                }
            };
            match self
                .wallet_submission_mempool
                .submit(intent, intent_bytes)
                .await
            {
                Ok(txid) => {
                    reservation.commit();
                    if attempt > 0 {
                        tracing::info!(
                            attempt,
                            failure_label,
                            "wallet submission succeeded after retry"
                        );
                    }
                    return Ok(WalletSendResult {
                        txid: hex::encode(txid.0),
                        amount_micronoid,
                        fee_micronoid: actual_fee,
                        input_count,
                        output_count,
                    });
                }
                Err(error) => {
                    drop(reservation);
                    last_error = error.to_string();
                }
            }
        }

        Err(rpc_err(format!(
            "{failure_label} failed after 3 attempts: {last_error}"
        )))
    }

    async fn collect_slot_hints(&self, count: u32, salt_seed: u64) -> RpcResult<Vec<u32>> {
        let count = (count as usize).min(256);
        if count == 0 {
            return Ok(Vec::new());
        }

        let reserved = self.mempool.reserved_output_slots().await;
        let chain = self.chain.read().await;
        let tip = chain.tip_header();
        let tip_seed = u64::from_le_bytes(tip.state_root[..8].try_into().unwrap());
        let seed = mix_slot_hint_seed(tip_seed, salt_seed);

        collect_empty_slot_hints(&chain, &reserved, seed, count).map_err(rpc_err)
    }

    /// Owned preparation coordinator. `getBlockTemplate` runs this in its own
    /// Tokio task, so disconnecting the RPC client cannot drop the one-attempt
    /// lease while a detached blocking/Rayon job still owns the template.
    async fn prepare_external_mining_attempt(
        self,
        requested: Option<noid_poseidon2b::primitives::Address>,
        preparation: ExternalMiningPreparationLease,
    ) -> RpcResult<BlockTemplateResponse> {
        self.require_mining_network()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let builder = TemplateBuilder::new(self.mempool.clone());
        // Snapshot/reorg installation holds the same gate while it replaces
        // chain, mempool and wallet views. Capture the exact parent+payout
        // boundary under that gate, then release it before witness preparation.
        let wallet_operation = self.wallet_operation_gate.lock().await;
        let (snapshot, addr) = {
            let mut ctx = self.chain.write().await;
            let operator_payout = self.resolved_mining_payout()?;
            let addr = match requested {
                None => operator_payout,
                Some(requested) if self.allow_custom_coinbase => requested,
                Some(requested) if requested.0 == operator_payout.0 => requested,
                Some(_) => {
                    return Err(rpc_err(
                        "miner_address must match the node's configured payout address. \
                         Use empty string \"\" to use the node's address, or start the \
                         node with --allow-custom-coinbase (requires --mining-key) to \
                         allow miners to specify their own payout address.",
                    ));
                }
            };
            let snapshot = TemplateChainSnapshot::from_context(&mut ctx)
                .map_err(|e| rpc_err(format!("template snapshot: {e:?}")))?;
            (snapshot, addr)
        };
        drop(wallet_operation);
        let max_effective_pages = self
            .external_mining_capacity
            .lock()
            .map_err(|_| rpc_err("external mining capacity lock poisoned"))?
            .page_limit();
        let tmpl = builder
            .build_from_snapshot_with_limit(snapshot, addr, now, max_effective_pages)
            .await
            .ok_or_else(|| rpc_err("template build failed"))?;

        let height = tmpl.inner.height;
        let n_txs = tmpl.inner.n_txs();
        let tx_input_counts: Vec<usize> = tmpl
            .inner
            .txs
            .iter()
            .map(|tx| tx.body.live_input_count())
            .collect();
        let tx_output_counts: Vec<usize> = tmpl
            .inner
            .txs
            .iter()
            .map(|tx| tx.body.live_output_count())
            .collect();
        let coinbase_value_micronoid: u64 = tmpl
            .inner
            .coinbase
            .body
            .live_outputs()
            .map(|(_, output)| output.amount)
            .fold(0u64, |acc, value| acc.saturating_add(value));
        let claimable_fees_micronoid = tmpl
            .inner
            .txs
            .iter()
            .map(|tx| {
                noid_chain::consensus::claimable_fee_for_tx_body(
                    &tx.body,
                    tmpl.parent.active_slot_count,
                    tmpl.parent.log_slots,
                )
            })
            .fold(0u64, |acc, fee| acc.saturating_add(fee));
        let pow_header = tmpl.header_for_pow(0);
        let pow_fields_hex = encode_pow_fields_hex(&pow_header);
        let diff_target = pow_header.difficulty_target;

        // Build and prove the complete nonce-independent HistoryStep before
        // exposing the capability. The worker's only remaining job is PoW.
        let runtime = self
            .history_step_runtime
            .as_ref()
            .cloned()
            .ok_or_else(|| rpc_err("HistoryStep runtime is unavailable"))?;
        let ghost = self
            .history_step_ghost
            .as_ref()
            .cloned()
            .ok_or_else(|| rpc_err("HistoryStep producer authorization is unavailable"))?;
        let (prepared, prepare_elapsed) = tokio::task::spawn_blocking(move || {
            let started = Instant::now();
            let result = noid_miner::install_history_step_phase_cpu(|| {
                PreparedBlockAttempt::prepare(tmpl, &runtime, &ghost, now)
            })
            .map_err(|error| format!("HistoryStep CPU admission failed: {error}"))
            .and_then(|result| result);
            (result, started.elapsed())
        })
        .await
        .map_err(|error| rpc_err(format!("HistoryStep preparation task failed: {error}")))?;
        let prepared = prepared
            .map_err(|error| rpc_err(format!("HistoryStep preparation failed: {error}")))?;
        self.require_mining_network()?;

        let proof_class = prepared.proof_class();
        let user_pages = prepared.user_page_count();
        let (previous_page_limit, next_page_limit, b25_prepare_ms_ewma, b255_prepare_ms_ewma) = {
            let mut capacity = self
                .external_mining_capacity
                .lock()
                .map_err(|_| rpc_err("external mining capacity lock poisoned"))?;
            let previous = capacity.page_limit();
            capacity.observe_preparation(proof_class, prepare_elapsed);
            (
                previous,
                capacity.page_limit(),
                capacity.prepare_ms_ewma(noid_chain::consensus::paged_spend::BlockProofClass::B25),
                capacity.prepare_ms_ewma(noid_chain::consensus::paged_spend::BlockProofClass::B255),
            )
        };
        tracing::info!(
            mining = "external",
            user_pages,
            ?proof_class,
            max_effective_pages,
            previous_page_limit,
            next_page_limit,
            history_step_ms = prepare_elapsed.as_millis(),
            b25_prepare_ms_ewma,
            b255_prepare_ms_ewma,
            "external mining template proved"
        );

        let parent_height = prepared.expected_parent_height();
        let parent_id = prepared.expected_parent_id();
        {
            let chain = self.chain.read().await;
            let tip = chain.tip_header();
            if tip.height != parent_height || block_id(tip) != parent_id {
                return Err(rpc_err(
                    "chain tip changed while preparing external mining template",
                ));
            }
        }

        let template_id = preparation.template_id();
        preparation
            .install_ready(prepared, parent_height, parent_id, Instant::now())
            .map_err(|error| rpc_err(format!("install external mining attempt: {error}")))?;
        Ok(BlockTemplateResponse {
            template_id: hex::encode(template_id),
            pow_fields_hex,
            nonce_field_index: POW_NONCE_FIELD_INDEX,
            difficulty_target_hex: hex::encode(diff_target),
            height,
            expires_in_seconds: EXTERNAL_MINING_TEMPLATE_TTL.as_secs(),
            n_txs,
            tx_input_counts,
            tx_output_counts,
            coinbase_value_micronoid,
            claimable_fees_micronoid,
        })
    }

    /// Seal the sole miner-controlled value into an immutable node-owned
    /// template, check the exact parent and PoW, then finalize it through the
    /// node-owned consensus path.
    async fn finalize_node_owned_template_after_nonce(
        &self,
        prepared: PreparedBlockAttempt,
        nonce: u128,
        nonce_submitted_at: Instant,
    ) -> RpcResult<String> {
        self.require_mining_network()?;
        // Consume happened before this check, so a stale or losing template
        // cannot be retried. Atomic apply repeats the parent checks under the
        // chain write lock and closes the race with a peer block.
        {
            let chain = self.chain.read().await;
            let tip = chain.tip_header();
            if tip.height != prepared.expected_parent_height()
                || block_id(tip) != prepared.expected_parent_id()
            {
                return Err(rpc_err("stale external mining template parent"));
            }
        }

        validate_pow(&prepared.pow_header(nonce))
            .map_err(|error| rpc_err(format!("proof of work: {error}")))?;

        let seal_started = Instant::now();
        let runtime = self
            .history_step_runtime
            .as_ref()
            .cloned()
            .ok_or_else(|| rpc_err("HistoryStep runtime is unavailable"))?;
        let proved = tokio::task::spawn_blocking(move || {
            noid_miner::install_history_step_phase_cpu(|| prepared.prove(&runtime, nonce))
                .map_err(|error| format!("HistoryStep CPU admission failed: {error}"))?
        })
        .await
        .map_err(|error| rpc_err(format!("HistoryStep task failed: {error}")))?
        .map_err(|error| rpc_err(format!("HistoryStep prove failed: {error}")))?;
        self.require_mining_network()?;
        let seal_ms = seal_started.elapsed().as_millis();
        // Serialize canonical commit + wallet delta + mempool view replacement.
        let wallet_operation = self.wallet_operation_gate.lock().await;
        let chain = Arc::clone(&self.chain);
        let wallet = Arc::clone(&self.wallet);
        let canonical_tip_changes = self.canonical_tip_changes.clone();
        let (committed, new_view) = tokio::task::spawn_blocking(move || {
            let mut ctx = chain.blocking_write();
            let committed = proved
                .commit(&mut ctx)
                .map_err(|error| format!("consensus: {error}"))?;
            if let Err(error) = wallet.on_accepted_block(committed.block()) {
                tracing::error!(
                    height = committed.block().header.height,
                    %error,
                    "committed RPC block but wallet update failed"
                );
            }
            let view = noid_mempool::ChainView::from_mdbx(&ctx);
            canonical_tip_changes.send_replace(noid_p2p::object_protocol::ChainPoint::new(
                committed.block().header.height,
                block_id(&committed.block().header),
            ));
            Ok::<_, String>((committed, view))
        })
        .await
        .map_err(|error| rpc_err(format!("block commit task failed: {error}")))?
        .map_err(rpc_err)?;

        let block = committed.block();
        let height = block.header.height;
        let hash = block_id(&block.header);
        let confirmed = noid_chain::try_compute_logical_txids(&block.transactions)
            .expect("locally committed block has a canonical logical tx stream");
        let n_txs = confirmed.len();
        self.mempool
            .on_new_block(&confirmed, height, new_view)
            .await;
        drop(wallet_operation);

        tracing::info!(
            height,
            hash = %hex::encode(hash),
            txs = n_txs,
            mining = "external",
            seal_ms,
            nonce_to_commit_ms = nonce_submitted_at.elapsed().as_millis(),
            "block accepted"
        );

        let (_block, bundle) = committed.into_parts();
        let mut command = noid_p2p::NetworkCommand::AnnounceBlock { bundle };
        loop {
            match self.p2p_cmd.try_send(command) {
                Ok(()) => break,
                Err(tokio::sync::mpsc::error::TrySendError::Full(returned)) => {
                    command = returned;
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    tracing::error!(
                        height,
                        "P2P command lanes closed before RPC-submitted block announcement"
                    );
                    break;
                }
            }
        }

        Ok(hex::encode(hash))
    }
}

#[async_trait]
impl ParanoidApiServer for RpcHandler {
    // -----------------------------------------------------------------------
    // Chain state (always available)
    // -----------------------------------------------------------------------

    async fn block_count(&self) -> RpcResult<u64> {
        let chain = self.chain.read().await;
        Ok(chain.tip_height())
    }

    async fn get_chain_info(&self) -> RpcResult<ChainInfo> {
        let chain = self.chain.read().await;
        let tip = chain.tip_header();
        Ok(ChainInfo {
            height: chain.tip_height(),
            best_hash: hex::encode(chain.tip_hash()),
            difficulty_target: hex::encode(tip.difficulty_target),
            active_slot_count: tip.active_slot_count,
            log_slots: tip.log_slots,
            circulating_supply_micronoid: chain.state.circulating_supply_micronoid.to_string(),
        })
    }

    async fn get_header_by_height(&self, height: u64) -> RpcResult<Option<String>> {
        let chain = self.chain.read().await;
        match chain.get_header_from_store(height) {
            Ok(Some(hdr)) => {
                let mut buf = Vec::new();
                hdr.encode(&mut buf);
                Ok(Some(hex::encode(buf)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    async fn get_header_by_hash(&self, hash: String) -> RpcResult<Option<String>> {
        let hash_bytes = decode_32_byte_hex("hash", &hash)?;
        let chain = self.chain.read().await;
        match chain.store.get_header_by_hash(&hash_bytes) {
            Ok(Some(hdr)) => {
                let mut buf = Vec::new();
                hdr.encode(&mut buf);
                Ok(Some(hex::encode(buf)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    async fn get_history_step_terminal(&self) -> RpcResult<Option<String>> {
        let chain = self.chain.read().await;
        history_step_terminal_bytes(&chain)
            .map(|bytes| bytes.map(hex::encode))
            .map_err(rpc_err)
    }

    async fn get_slot(&self, slot_index: u32) -> RpcResult<SlotInfo> {
        let chain = self.chain.read().await;
        let tip = chain.tip_header();
        let log_slots = tip.log_slots;
        if (slot_index as u64) >= (1u64 << log_slots) {
            return Err(rpc_err(format!(
                "slot {slot_index} out of range (log_slots={log_slots})"
            )));
        }
        use noid_chain::fri_state::SlotValue;
        let sv = read_canonical_slot(&chain, slot_index, &mut HashMap::new()).map_err(rpc_err)?;
        // Decode both packed limbs independently so the response always reflects
        // the actual FRI state. Never suppress them based on `empty` — that would
        // hide a malformed all-zero-owner/non-zero-value state.
        let value = sv.amount();
        let creation_id = sv.creation_id();
        let empty = sv == SlotValue::EMPTY;
        let owner_bytes = {
            let mut b = [0u8; 32];
            b[..16].copy_from_slice(&sv.owner_hi.0.to_le_bytes());
            b[16..].copy_from_slice(&sv.owner_lo.0.to_le_bytes());
            b
        };
        use noid_poseidon2b::primitives::Address;
        let owner = if empty {
            String::new()
        } else {
            Address(owner_bytes).to_bech32()
        };
        Ok(SlotInfo {
            slot_index,
            value,
            creation_id,
            owner,
            empty,
        })
    }

    async fn get_active_slot_count(&self) -> RpcResult<u64> {
        let chain = self.chain.read().await;
        Ok(chain.state.active_slot_count)
    }

    async fn get_state_info(&self) -> RpcResult<StateInfo> {
        use noid_chain::consensus::params::{EXPAND_DENOM, EXPAND_NUM, LOG_SLOTS_MAX};
        use noid_chain::fri_state::LOG_SEGMENT_SIZE;
        let chain = self.chain.read().await;
        let tip = chain.tip_header();
        let log_slots = tip.log_slots;
        let active = tip.active_slot_count;

        let capacity = 1u64.checked_shl(log_slots).unwrap_or(u64::MAX);

        // Total number of segments = 2^(log_slots - LOG_SEGMENT_SIZE)
        // At genesis (log_slots=24, LOG_SEGMENT_SIZE=16): 256 segments.
        let num_segments = if log_slots as usize > LOG_SEGMENT_SIZE {
            1usize << (log_slots as usize - LOG_SEGMENT_SIZE)
        } else {
            1
        };

        // Populated = segments with at least one live UTXO. Fully-empty touched
        // segments are dematerialised and excluded from RAM, disk, and snapshots.
        let materialized_in_ram = chain.state.state.materialized_segment_ids().count();
        // Per-materialized-segment RAM size:
        //   3 columns (values, owners_hi, owners_lo)
        //   × 2^LOG_SEGMENT_SIZE slots
        //   × 16 bytes per Block128
        // = 3 × 65536 × 16 = 3,145,728 bytes = 3 MB
        let seg_size_bytes: u64 = 3 * (1u64 << LOG_SEGMENT_SIZE) * 16;

        // RAM is still materialized densely while a segment is hot. Durable
        // state and snapshots use canonical sparse records instead.
        let state_bytes_ram = (materialized_in_ram as u64).saturating_mul(seg_size_bytes);
        let state_bytes_disk = chain
            .store
            .encoded_state_bytes()
            .map_err(|error| rpc_err(error.to_string()))?;
        // Theoretical maxima are deliberately reported separately.  The
        // current slot domain grows at the consensus expansion boundary, so
        // its fully-materialised size is not the lifetime protocol ceiling.
        let max_encoded_segment_bytes =
            noid_chain::storage::max_encoded_segment_len_for_eff_log(LOG_SEGMENT_SIZE as u8)
                .unwrap_or(usize::MAX) as u64;
        let state_bytes_current_domain_max =
            (num_segments as u64).saturating_mul(max_encoded_segment_bytes);
        let protocol_num_segments = if LOG_SLOTS_MAX as usize > LOG_SEGMENT_SIZE {
            1u64 << (LOG_SLOTS_MAX as usize - LOG_SEGMENT_SIZE)
        } else {
            1
        };
        let state_bytes_protocol_max =
            protocol_num_segments.saturating_mul(max_encoded_segment_bytes);

        let fill_pct = if capacity > 0 {
            (active as f64 / capacity as f64 * 10000.0).round() / 100.0
        } else {
            0.0
        };

        let trigger_slots = capacity
            .saturating_mul(EXPAND_NUM)
            .checked_div(EXPAND_DENOM)
            .unwrap_or(0);
        let slots_until_expand = trigger_slots as i64 - active as i64;

        Ok(StateInfo {
            log_slots,
            capacity,
            active_slots: active,
            fill_pct,
            slots_until_expand,
            expand_trigger_pct: (EXPAND_NUM * 100 / EXPAND_DENOM) as u8,
            log_slots_max: LOG_SLOTS_MAX,
            // Real current size (non-zero segments only)
            state_bytes: state_bytes_disk,
            state_size_human: format!(
                "{} materialized RAM  /  {} encoded state  /  {} encoded at 2^{}  /  {} encoded protocol max",
                human_bytes(state_bytes_ram),
                human_bytes(state_bytes_disk),
                human_bytes(state_bytes_current_domain_max),
                log_slots,
                human_bytes(state_bytes_protocol_max),
            ),
        })
    }

    async fn get_state_map(&self) -> RpcResult<StateMapInfo> {
        use noid_chain::fri_state::LOG_SEGMENT_SIZE;

        const MAX_BUCKETS: usize = 256;
        let chain = self.chain.read().await;
        let log_slots = chain.tip_header().log_slots;
        let num_segments = if log_slots as usize > LOG_SEGMENT_SIZE {
            1usize << (log_slots as usize - LOG_SEGMENT_SIZE)
        } else {
            1
        };
        let bucket_count = num_segments.clamp(1, MAX_BUCKETS);
        let capacity = 1u64.checked_shl(log_slots).unwrap_or(u64::MAX);
        let bucket_capacity = capacity / bucket_count as u64;
        let mut live_counts = vec![0u64; bucket_count];
        for segment_id in 0..num_segments {
            let bucket = segment_id.saturating_mul(bucket_count) / num_segments;
            live_counts[bucket] = live_counts[bucket].saturating_add(u64::from(
                chain.state.state.segment_live_count(segment_id as u16),
            ));
        }
        Ok(StateMapInfo {
            log_slots,
            bucket_capacity,
            live_counts,
        })
    }

    // -----------------------------------------------------------------------
    // New chain methods
    // -----------------------------------------------------------------------

    async fn get_block_hash(&self, height: u64) -> RpcResult<Option<String>> {
        let chain = self.chain.read().await;
        match chain.get_header_from_store(height) {
            Ok(Some(hdr)) => Ok(Some(hex::encode(block_id(&hdr)))),
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    async fn get_block_header(&self, height: u64) -> RpcResult<Option<BlockHeaderInfo>> {
        let chain = self.chain.read().await;
        match chain.get_header_from_store(height) {
            Ok(Some(header)) => Ok(Some(block_header_info(&header))),
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    async fn get_block_header_by_hash(&self, hash: String) -> RpcResult<Option<BlockHeaderInfo>> {
        let hash_bytes = decode_32_byte_hex("hash", &hash)?;
        let chain = self.chain.read().await;
        match chain.store.get_header_by_hash(&hash_bytes) {
            Ok(Some(header)) => Ok(Some(block_header_info(&header))),
            Ok(None) => Ok(None),
            Err(error) => Err(rpc_err(error.to_string())),
        }
    }

    async fn get_slots_by_owner(&self, address: String) -> RpcResult<Vec<SlotInfo>> {
        use noid_poseidon2b::primitives::Address;
        let addr =
            Address::parse(&address).map_err(|e| rpc_err(format!("invalid address: {e}")))?;
        let chain = self.chain.read().await;
        let snapshot = chain
            .store
            .get_verified_utxos_by_owner(&addr.0)
            .map_err(|e| rpc_err(e.to_string()))?;
        Ok(snapshot
            .utxos
            .into_iter()
            .map(|utxo| SlotInfo {
                slot_index: utxo.slot_index,
                value: utxo.amount,
                creation_id: utxo.creation_id,
                owner: address.clone(),
                empty: false,
            })
            .collect())
    }

    async fn get_tx(&self, txhash: String) -> RpcResult<Option<TxInfo>> {
        let hash_bytes = decode_32_byte_hex("txhash", &txhash)?;
        let chain = self.chain.read().await;
        match chain.store.get_tx_index(&hash_bytes) {
            Ok(Some((height, tx_position))) => {
                let block_hash = chain
                    .get_header_from_store(height)
                    .ok()
                    .flatten()
                    .map(|h| hex::encode(block_id(&h)))
                    .unwrap_or_default();
                Ok(Some(TxInfo {
                    tx_hash: txhash,
                    height,
                    block_hash,
                    tx_position,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    async fn get_block(&self, height: u64) -> RpcResult<Option<String>> {
        let chain = self.chain.read().await;
        match chain.store.get_recent_block(height) {
            Ok(Some(bytes)) => Ok(Some(hex::encode(bytes))),
            Ok(None) => Ok(None),
            Err(e) => Err(rpc_err(e.to_string())),
        }
    }

    async fn get_block_details(&self, height: u64) -> RpcResult<Option<BlockDetailsInfo>> {
        let (header, retained_bytes) = {
            let chain = self.chain.read().await;
            let Some(header) = chain
                .get_header_from_store(height)
                .map_err(|error| rpc_err(error.to_string()))?
            else {
                return Ok(None);
            };
            let retained = chain
                .store
                .get_recent_accepted_block_bundle_bounded(height)
                .map_err(|error| rpc_err(error.to_string()))?;
            (header, retained)
        };
        let header_info = block_header_info(&header);
        let Some(bundle_bytes) = retained_bytes else {
            return Ok(Some(BlockDetailsInfo {
                header: header_info,
                retained: None,
            }));
        };

        let bundle = noid_chain::AcceptedBlockBundle::decode(&bundle_bytes)
            .map_err(|error| rpc_err(format!("decode retained block bundle: {error}")))?;
        let block = noid_chain::Block::from_bytes(bundle.block_bytes())
            .map_err(|error| rpc_err(format!("decode retained block: {error:?}")))?;
        if block.header != header {
            return Err(rpc_err(
                "retained block header does not match canonical header",
            ));
        }
        let stream = noid_chain::validate_block_page_stream(&block.transactions)
            .map_err(|error| rpc_err(format!("decode retained transaction stream: {error}")))?;
        let logical_txids = noid_chain::try_compute_logical_txids(&block.transactions)
            .map_err(|error| rpc_err(format!("derive retained transaction ids: {error}")))?;
        let coinbase = block
            .transactions
            .first()
            .ok_or_else(|| rpc_err("retained block is missing coinbase"))?;
        let reward_micronoid = coinbase
            .body
            .live_outputs()
            .map(|(_, output)| output.amount)
            .fold(0u64, u64::saturating_add);
        let coinbase_outputs = u16::try_from(coinbase.body.live_outputs().count())
            .map_err(|_| rpc_err("coinbase output count does not fit u16"))?;
        let development_outputs = if stream.has_development_payout {
            u16::try_from(block.transactions[1].body.live_outputs().count())
                .map_err(|_| rpc_err("development payout output count does not fit u16"))?
        } else {
            0
        };
        let minted_outputs = u64::from(stream.live_outputs)
            .checked_add(u64::from(coinbase_outputs))
            .and_then(|count| count.checked_add(u64::from(development_outputs)))
            .ok_or_else(|| rpc_err("retained block output count overflow"))?;
        let mut alloc_cursor = header
            .alloc_counter
            .checked_sub(minted_outputs)
            .ok_or_else(|| rpc_err("retained block allocator counter underflow"))?;

        let mut transactions = Vec::with_capacity(logical_txids.len());
        let mut coinbase_output_details = Vec::with_capacity(usize::from(coinbase_outputs));
        for (lane, output) in coinbase.body.live_outputs() {
            alloc_cursor = alloc_cursor
                .checked_add(1)
                .ok_or_else(|| rpc_err("retained block allocator counter overflow"))?;
            coinbase_output_details.push(BlockTransactionOutputInfo {
                page: 0,
                lane: lane as u8,
                slot_index: output.slot_index,
                amount_micronoid: output.amount,
                owner: output.owner.to_bech32(),
                creation_id: noid_chain::consensus::params::coinbase_creation_id(header.height),
            });
        }
        let coinbase_txid = hex::encode(logical_txids[0].0);
        transactions.push(BlockTransactionInfo {
            position: 0,
            txid: coinbase_txid.clone(),
            page_count: 1,
            live_inputs: 0,
            live_outputs: coinbase_outputs,
            fee_micronoid: 0,
            coinbase: true,
            development_payout: false,
            epoch_anchor: hex::encode(coinbase.body.epoch_anchor),
            input_owner: None,
            input_sum_micronoid: "0".into(),
            output_sum_micronoid: reward_micronoid.to_string(),
            page_hashes: vec![coinbase_txid],
            inputs: Vec::new(),
            outputs: coinbase_output_details,
        });

        if stream.has_development_payout {
            let payout = &block.transactions[1];
            let mut payout_outputs = Vec::with_capacity(usize::from(development_outputs));
            let mut payout_output_sum = 0u128;
            for (lane, output) in payout.body.live_outputs() {
                alloc_cursor = alloc_cursor
                    .checked_add(1)
                    .ok_or_else(|| rpc_err("retained block allocator counter overflow"))?;
                payout_output_sum = payout_output_sum
                    .checked_add(u128::from(output.amount))
                    .ok_or_else(|| rpc_err("development payout sum overflow"))?;
                payout_outputs.push(BlockTransactionOutputInfo {
                    page: 0,
                    lane: lane as u8,
                    slot_index: output.slot_index,
                    amount_micronoid: output.amount,
                    owner: output.owner.to_bech32(),
                    creation_id: alloc_cursor,
                });
            }
            let payout_txid = hex::encode(logical_txids[1].0);
            transactions.push(BlockTransactionInfo {
                position: 1,
                txid: payout_txid.clone(),
                page_count: 1,
                live_inputs: 0,
                live_outputs: development_outputs,
                fee_micronoid: 0,
                coinbase: true,
                development_payout: true,
                epoch_anchor: hex::encode(payout.body.epoch_anchor),
                input_owner: None,
                input_sum_micronoid: "0".into(),
                output_sum_micronoid: payout_output_sum.to_string(),
                page_hashes: vec![payout_txid],
                inputs: Vec::new(),
                outputs: payout_outputs,
            });
        }

        for (index, group) in stream.groups.iter().enumerate() {
            let start = stream.user_body_start(usize::from(group.start_page));
            let end = start
                .checked_add(usize::from(group.page_count))
                .ok_or_else(|| rpc_err("retained transaction page range overflow"))?;
            let pages = block
                .transactions
                .get(start..end)
                .ok_or_else(|| rpc_err("retained transaction page range is unavailable"))?;

            let mut inputs = Vec::with_capacity(usize::from(group.spend.live_inputs));
            let mut outputs = Vec::with_capacity(usize::from(group.spend.live_outputs));
            let mut page_hashes = Vec::with_capacity(pages.len());
            for (page_index, page) in pages.iter().enumerate() {
                page_hashes.push(hex::encode(page.txid().0));
                for (lane, input) in page.body.live_inputs() {
                    inputs.push(BlockTransactionInputInfo {
                        page: page_index as u16,
                        lane: lane as u8,
                        slot_index: input.slot_index,
                        amount_micronoid: input.amount,
                        creation_id: input.creation_id,
                    });
                }
                for (lane, output) in page.body.live_outputs() {
                    alloc_cursor = alloc_cursor
                        .checked_add(1)
                        .ok_or_else(|| rpc_err("retained block allocator counter overflow"))?;
                    outputs.push(BlockTransactionOutputInfo {
                        page: page_index as u16,
                        lane: lane as u8,
                        slot_index: output.slot_index,
                        amount_micronoid: output.amount,
                        owner: output.owner.to_bech32(),
                        creation_id: alloc_cursor,
                    });
                }
            }

            transactions.push(BlockTransactionInfo {
                position: stream.user_logical_index(index) as u16,
                txid: hex::encode(group.spend.logical_txid.0),
                page_count: group.page_count,
                live_inputs: group.spend.live_inputs,
                live_outputs: group.spend.live_outputs,
                fee_micronoid: group.spend.fee,
                coinbase: false,
                development_payout: false,
                epoch_anchor: hex::encode(group.spend.epoch_anchor),
                input_owner: Some(group.spend.input_owner.to_bech32()),
                input_sum_micronoid: group.spend.input_sum.to_string(),
                output_sum_micronoid: group.spend.output_sum.to_string(),
                page_hashes,
                inputs,
                outputs,
            });
        }
        if alloc_cursor != header.alloc_counter {
            return Err(rpc_err(
                "retained transaction outputs do not match the header allocator counter",
            ));
        }
        let total_fees_micronoid = stream
            .groups
            .iter()
            .map(|group| u128::from(group.spend.fee))
            .sum::<u128>()
            .to_string();
        let proof_class = match stream.proof_class {
            noid_chain::consensus::BlockProofClass::B25 => "B25 / m22",
            noid_chain::consensus::BlockProofClass::B255 => "B255 / m24",
        }
        .to_string();
        let retained = RetainedBlockInfo {
            proof_class,
            logical_transactions: logical_txids.len() as u16,
            user_pages: stream.page_count,
            live_inputs: stream.live_inputs,
            live_outputs: stream
                .live_outputs
                .saturating_add(coinbase_outputs)
                .saturating_add(development_outputs),
            reward_micronoid,
            reward_noid: crate::types::micronoid_to_noid(reward_micronoid),
            total_fees_micronoid,
            block_bytes: bundle.block_bytes().len() as u64,
            history_step_bytes: bundle.history_step_terminal_bytes().len() as u64,
            bundle_bytes: bundle_bytes.len() as u64,
            transactions,
        };
        Ok(Some(BlockDetailsInfo {
            header: header_info,
            retained: Some(retained),
        }))
    }

    async fn get_recent_transactions(
        &self,
        page: u32,
        page_size: u32,
        address: Option<String>,
    ) -> RpcResult<RecentTransactionsPage> {
        use noid_poseidon2b::primitives::Address;

        const MAX_PAGE_SIZE: u32 = 32;
        let page_size = page_size.clamp(1, MAX_PAGE_SIZE);
        let filter = address
            .as_deref()
            .map(Address::parse)
            .transpose()
            .map_err(|error| rpc_err(format!("invalid address: {error}")))?;
        let canonical_address = filter.as_ref().map(Address::to_bech32);

        let (tip_height, retained_from_height, retained) = {
            let chain = self.chain.read().await;
            let tip_height = chain.tip_height();
            let retained_from_height = if tip_height == 0 {
                0
            } else {
                tip_height
                    .saturating_sub(RECENT_BLOCK_RETENTION_DEPTH.saturating_sub(1))
                    .max(1)
            };
            let mut retained = Vec::new();
            for height in (retained_from_height..=tip_height).rev() {
                let Some(header) = chain
                    .get_header_from_store(height)
                    .map_err(|error| rpc_err(error.to_string()))?
                else {
                    return Err(rpc_err(format!("canonical header {height} is unavailable")));
                };
                if let Some(bundle) = chain
                    .store
                    .get_recent_accepted_block_bundle_bounded(height)
                    .map_err(|error| rpc_err(error.to_string()))?
                {
                    retained.push((header, bundle));
                }
            }
            (tip_height, retained_from_height, retained)
        };

        let mut transactions = Vec::new();
        for (header, bundle) in retained {
            transactions.extend(
                retained_transaction_summaries(&header, &bundle, filter.as_ref())
                    .map_err(rpc_err)?,
            );
        }

        let total = transactions.len();
        let total_pages = if total == 0 {
            0
        } else {
            u32::try_from(total.div_ceil(page_size as usize)).unwrap_or(u32::MAX)
        };
        let page = if total_pages == 0 {
            1
        } else {
            page.max(1).min(total_pages)
        };
        let offset = (page.saturating_sub(1) as usize).saturating_mul(page_size as usize);
        let transactions = transactions
            .into_iter()
            .skip(offset)
            .take(page_size as usize)
            .collect();

        Ok(RecentTransactionsPage {
            page,
            page_size,
            total,
            total_pages,
            tip_height,
            retained_from_height,
            address: canonical_address,
            transactions,
        })
    }

    // -----------------------------------------------------------------------
    // Mining / network info
    // -----------------------------------------------------------------------

    async fn get_mining_info(&self) -> RpcResult<MiningInfo> {
        use noid_chain::consensus::emission::block_reward;
        let chain = self.chain.read().await;
        let tip = chain.tip_header();
        let height = chain.tip_height();
        let diff = tip.difficulty_target;
        let diff_bits = noid_chain::consensus::target_leading_zero_bits(&diff);
        let reward = block_reward(tip.log_slots);
        Ok(MiningInfo {
            height,
            difficulty_bits: diff_bits,
            difficulty_target: hex::encode(diff),
            block_reward_micronoid: reward,
            block_reward_noid: reward as f64 / 1_000_000.0,
            active_slot_count: tip.active_slot_count,
        })
    }

    async fn get_peer_count(&self) -> RpcResult<usize> {
        let count = noid_p2p::P2PNetwork::peer_count_via(&self.p2p_cmd).await;
        Ok(count)
    }

    async fn get_node_status(&self) -> RpcResult<NodeStatus> {
        let p2p = self.p2p_health.borrow().clone();
        let heartbeat_age = p2p.updated_at.elapsed();
        Ok(NodeStatus {
            synced: *self.initial_sync_ready.borrow(),
            sync_stage: *self.initial_sync_stage.borrow(),
            mining: self.internal_mining_enabled,
            mining_ready: *self.mining_network_ready.borrow(),
            mining_confirmed_peers: *self.mining_confirmed_peers.borrow(),
            mining_required_peers: self.mining_required_peers,
            isolated_mining: self.isolated_mining,
            backend: self.cpu_backend.clone(),
            available_threads: self.available_threads,
            worker_threads: self.worker_threads,
            p2p_healthy: p2p.sequence > 0 && heartbeat_age <= std::time::Duration::from_secs(30),
            p2p_heartbeat_age_ms: heartbeat_age.as_millis().min(u128::from(u64::MAX)) as u64,
            p2p_connected_peers: p2p.connected_peers,
            p2p_dispatchable_peers: p2p.dispatchable_peers,
            p2p_relay_reservations: p2p.relay_reservations,
            p2p_control_queue: p2p.control_queue,
            p2p_header_queue: p2p.header_queue,
            p2p_data_queue: p2p.data_queue,
            p2p_pending_requests: p2p.pending_requests,
        })
    }

    async fn estimate_fee(&self, n_outputs: u32) -> RpcResult<u64> {
        let (active_slot_count, log_slots) = self.mempool.fee_context().await;
        let floor = self.mempool.fee_floor().await;
        Ok(
            noid_chain::consensus::fee_breakdown(1, n_outputs as u64, active_slot_count, log_slots)
                .required_total
                .max(floor),
        )
    }

    async fn estimate_fee_detailed(&self, n_inputs: u32, n_outputs: u32) -> RpcResult<FeeEstimate> {
        let n_inputs = n_inputs as usize;
        let n_outputs = n_outputs as usize;
        validate_tx_counts(n_inputs, n_outputs)?;
        let (active_slot_count, log_slots) = self.mempool.fee_context().await;
        let floor = self.mempool.fee_floor().await;
        let breakdown = noid_chain::consensus::fee_breakdown(
            n_inputs as u64,
            n_outputs as u64,
            active_slot_count,
            log_slots,
        );
        let relay_total = breakdown.required_total.max(floor);
        let info = fee_breakdown_info(breakdown, floor, relay_total);
        Ok(FeeEstimate {
            n_inputs,
            n_outputs,
            net_new_slots: (n_outputs as u64).saturating_sub(n_inputs as u64),
            active_slot_count,
            log_slots,
            fee_micronoid: info.relay_total,
            breakdown: info,
        })
    }

    async fn validate_address(&self, address: String) -> RpcResult<AddressInfo> {
        use noid_poseidon2b::primitives::Address;
        match Address::parse(&address) {
            Ok(addr) => Ok(AddressInfo {
                valid: true,
                bech32: Some(addr.to_bech32()),
                hex: Some(hex::encode(addr.0)),
                error: None,
            }),
            Err(e) => Ok(AddressInfo {
                valid: false,
                bech32: None,
                hex: None,
                error: Some(e.to_string()),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Wallet support
    // -----------------------------------------------------------------------

    async fn get_slot_hints(&self, count: u32) -> RpcResult<Vec<u32>> {
        self.collect_slot_hints(count, node_entropy_nonce()).await
    }

    async fn get_slot_hints_salted(&self, count: u32, salt_hex: String) -> RpcResult<Vec<u32>> {
        self.collect_slot_hints(count, seed_from_salt_hex(&salt_hex)?)
            .await
    }

    async fn get_epoch_anchor(&self) -> RpcResult<String> {
        let chain = self.chain.read().await;
        Ok(hex::encode(
            next_user_epoch_anchor(&chain).map_err(rpc_err)?,
        ))
    }

    async fn submit_tx_intent(&self, hex_str: String) -> RpcResult<String> {
        let bytes = decode_bounded_hex("tx intent", &hex_str, MAX_TX_INTENT_BYTES_GLOBAL)?;
        let intent = noid_tx::PagedSpendIntent::from_bytes(&bytes)
            .map_err(|e| rpc_err(format!("decode: {e:?}")))?;
        let hash = self
            .mempool
            .submit(intent, bytes)
            .await
            .map_err(|e| rpc_err(e.to_string()))?;
        Ok(hex::encode(hash.0))
    }

    async fn get_mempool_size(&self) -> RpcResult<usize> {
        Ok(self.mempool.len().await)
    }

    async fn get_mempool_entry(&self, txhash: String) -> RpcResult<Option<MempoolTxInfo>> {
        let hash_bytes = decode_32_byte_hex("txhash", &txhash)?;
        let hash = noid_poseidon2b::primitives::TxBodyHash(hash_bytes);
        let found = self.mempool.get_entry_metadata(&hash).await;
        Ok(found.map(mempool_tx_info))
    }

    // -----------------------------------------------------------------------
    // Receipt verification
    // -----------------------------------------------------------------------

    async fn verify_receipt(&self, receipt_hex: String) -> RpcResult<ReceiptVerifyResult> {
        use noid_chain::consensus::receipt::{verify_against_header, verify_merkle_inclusion};

        let bytes = decode_bounded_hex("receipt", &receipt_hex, MAX_RPC_RECEIPT_BYTES)?;

        let receipt = noid_chain::consensus::receipt::ParanoidReceipt::from_bytes(&bytes)
            .map_err(|e| rpc_err(format!("decode receipt: {e:?}")))?;

        // Verify Merkle inclusion (offline, math only).
        let merkle_valid = verify_merkle_inclusion(&receipt);

        // Verify against canonical chain (look up header by height).
        let chain = self.chain.read().await;
        let canonical = match chain.get_header_from_store(receipt.claimed_height) {
            Ok(Some(hdr)) => Some(verify_against_header(&receipt, &hdr)),
            Ok(None) => None,
            Err(_) => None,
        };

        let confirmed = merkle_valid && canonical == Some(true);
        let authenticated_summary = merkle_valid.then(|| ReceiptSummaryInfo {
            txid: hex::encode(receipt.summary.logical_txid),
            claimed_height: receipt.claimed_height,
            confirmed_unix: receipt.summary.confirmed_unix,
            tx_index: receipt.tx_index,
            tx_count: receipt.tx_count,
            fee_micronoid: receipt.summary.fee_micronoid,
            inputs: receipt
                .summary
                .inputs
                .iter()
                .map(|(slot_index, owner)| ReceiptInputInfo {
                    slot_index: *slot_index,
                    owner: owner.to_bech32(),
                })
                .collect(),
            outputs: receipt
                .summary
                .outputs
                .iter()
                .map(|(slot_index, amount_micronoid, owner)| ReceiptOutputInfo {
                    slot_index: *slot_index,
                    amount_micronoid: *amount_micronoid,
                    owner: owner.to_bech32(),
                })
                .collect(),
        });

        Ok(ReceiptVerifyResult {
            merkle_valid,
            canonical: canonical.unwrap_or(false),
            confirmed,
            error: if !confirmed && canonical.is_none() {
                Some(format!(
                    "header at height {} not found",
                    receipt.claimed_height
                ))
            } else {
                None
            },
            authenticated_summary,
        })
    }

    // -----------------------------------------------------------------------
    // Mining — Block Template API
    // -----------------------------------------------------------------------

    /// Get a block template for external miners (or internal use).
    ///
    /// Returns the fixed Poseidon2b PoW field schedule as hex.
    /// The external miner brute-forces `nonce` such that:
    ///   `Poseidon2b(POWHDR__, patched_fields) < difficulty_target`
    ///
    /// Every semantic field, including the coinbase address, is fixed inside
    /// the node-owned prepared attempt. The worker can return only a nonce.
    async fn get_block_template(&self, miner_address: String) -> RpcResult<BlockTemplateResponse> {
        if !self.mining_api_enabled {
            return Err(rpc_err(
                "external mining API is disabled; start this node with --mode extminer",
            ));
        }
        self.require_mining_network()?;

        let requested = if miner_address.is_empty() {
            None
        } else {
            Some(parse_address_param(&miner_address)?)
        };
        let preparation = self
            .external_mining_attempts
            .reserve_preparation(Instant::now())
            .map_err(rpc_err)?;
        let handler = self.clone();
        // The task, not the request future, owns the lease. Dropping a client
        // connection detaches this coordinator but cannot admit a second
        // attempt while its blocking preparation is still running.
        tokio::spawn(async move {
            handler
                .prepare_external_mining_attempt(requested, preparation)
                .await
        })
        .await
        .map_err(|error| rpc_err(format!("external mining coordinator failed: {error}")))?
    }

    /// Consume one node-owned template and submit its canonical LE nonce.
    async fn submit_block(&self, template_id: String, nonce_hex: String) -> RpcResult<String> {
        let nonce_submitted_at = Instant::now();
        if !self.mining_api_enabled {
            return Err(rpc_err(
                "external mining API is disabled; start this node with --mode extminer",
            ));
        }
        self.require_mining_network()?;

        let template_id = decode_external_template_id(&template_id)?;
        let nonce = decode_external_nonce_hex(&nonce_hex)?;
        let (tip_height, tip_id) = {
            let chain = self.chain.read().await;
            let tip = chain.tip_header();
            (tip.height, block_id(tip))
        };
        let proving = self
            .external_mining_attempts
            .begin_proving(template_id, Instant::now(), tip_height, tip_id)
            .map_err(|error| match error {
                ExternalMiningConsumeError::Unavailable => {
                    rpc_err("external mining template is unknown, expired, consumed, or busy")
                }
                ExternalMiningConsumeError::Stale => {
                    rpc_err("stale external mining template parent")
                }
            })?;
        let handler = self.clone();
        // Keep the Proving marker in an owned task. If the RPC client
        // disconnects, proof/commit continues to own the sole slot and its
        // lease releases it on every return or panic path.
        tokio::spawn(async move {
            let ExternalMiningProvingAttempt { prepared, lease } = proving;
            let _lease = lease;
            handler
                .finalize_node_owned_template_after_nonce(prepared, nonce, nonce_submitted_at)
                .await
        })
        .await
        .map_err(|error| rpc_err(format!("external proving coordinator failed: {error}")))?
    }

    // -----------------------------------------------------------------------
    // Wallet RPC methods
    // -----------------------------------------------------------------------

    async fn wallet_status(&self) -> RpcResult<WalletStatus> {
        Ok(self.wallet.status())
    }

    async fn wallet_get_address(&self, index: u32) -> RpcResult<String> {
        self.wallet
            .get_address(index)
            .ok_or_else(|| rpc_err("wallet not initialized"))
    }

    async fn wallet_get_balance(&self) -> RpcResult<WalletBalance> {
        let mut balance = self.wallet.get_balance();
        if let Some((_, address)) = self.wallet.active_address() {
            let owner = noid_poseidon2b::primitives::Address::parse(&address)
                .map_err(|error| rpc_err(format!("active wallet address: {error}")))?;
            balance.pending_incoming_micronoid =
                self.mempool.pending_incoming_for_owner(&owner).await;
        }
        Ok(balance)
    }

    async fn wallet_list_utxos(&self) -> RpcResult<Vec<WalletUtxoInfo>> {
        Ok(self.wallet.list_utxos())
    }

    async fn wallet_history(&self) -> RpcResult<Vec<WalletHistoryEntry>> {
        Ok(self.wallet.history())
    }

    async fn wallet_receipts(&self, page: u32, page_size: u32) -> RpcResult<WalletReceiptsPage> {
        const MAX_PAGE_SIZE: u32 = 50;
        if page == 0 {
            return Err(rpc_err("page must be at least 1"));
        }
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(rpc_err(format!("page_size must be in 1..={MAX_PAGE_SIZE}")));
        }
        let offset = usize::try_from(page.saturating_sub(1))
            .ok()
            .and_then(|page| page.checked_mul(page_size as usize))
            .ok_or_else(|| rpc_err("receipt page offset overflow"))?;
        let slice = self
            .wallet
            .receipts(offset, page_size as usize)
            .map_err(rpc_err)?;
        let total_pages = if slice.total == 0 {
            0
        } else {
            u32::try_from(slice.total.div_ceil(page_size as usize))
                .map_err(|_| rpc_err("receipt page count overflow"))?
        };
        let receipts = slice
            .receipts
            .into_iter()
            .map(|receipt| WalletReceiptInfo {
                txid: hex::encode(receipt.txid),
                height: receipt.height,
                timestamp: receipt.timestamp,
                amount_micronoid: receipt.amount_micronoid,
                fee_micronoid: receipt.fee_micronoid,
                peer_address: receipt.peer_address,
                own_address: receipt.own_address,
                own_key_index: receipt.own_key_index,
                input_count: receipt.input_count,
                output_count: receipt.output_count,
                receipt_bytes: receipt.receipt_bytes,
            })
            .collect();

        Ok(WalletReceiptsPage {
            page,
            page_size,
            total: slice.total,
            total_pages,
            receipts,
        })
    }

    async fn wallet_mined_blocks(
        &self,
        page: u32,
        page_size: u32,
    ) -> RpcResult<WalletMinedBlocksPage> {
        const MAX_PAGE_SIZE: u32 = 50;
        if page == 0 {
            return Err(rpc_err("page must be at least 1"));
        }
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(rpc_err(format!("page_size must be in 1..={MAX_PAGE_SIZE}")));
        }
        let offset = usize::try_from(page.saturating_sub(1))
            .ok()
            .and_then(|page| page.checked_mul(page_size as usize))
            .ok_or_else(|| rpc_err("mined-block page offset overflow"))?;
        let slice = self.wallet.mined_blocks(offset, page_size as usize);
        let total_pages = if slice.total == 0 {
            0
        } else {
            u32::try_from(slice.total.div_ceil(page_size as usize))
                .map_err(|_| rpc_err("mined-block page count overflow"))?
        };

        let chain = self.chain.read().await;
        let tip = chain.tip_height();
        let mut blocks = Vec::with_capacity(slice.blocks.len());
        for record in slice.blocks {
            let header = chain
                .get_header_from_store(record.height)
                .map_err(|error| rpc_err(error.to_string()))?;
            // New history records bind the exact mined header. For legacy
            // records, a timestamp or payout mismatch is still definitive
            // evidence that another block won at this height; matching legacy
            // metadata is the best migration-safe identity available. A
            // missing canonical height is also definitive non-canonical state.
            let canonical = header.as_ref().is_some_and(|header| {
                mined_record_is_canonical(
                    record.block_hash,
                    record.timestamp,
                    &record.payout_address,
                    header,
                )
            });
            let displayed_hash = record
                .block_hash
                .or_else(|| header.as_ref().filter(|_| canonical).map(block_id));
            let full_block_available = canonical
                && chain
                    .store
                    .get_recent_block(record.height)
                    .map_err(|error| rpc_err(error.to_string()))?
                    .is_some();
            blocks.push(WalletMinedBlockInfo {
                height: record.height,
                block_hash: displayed_hash.map(hex::encode).unwrap_or_default(),
                coinbase_txid: hex::encode(record.coinbase_txid),
                timestamp: record.timestamp,
                reward_micronoid: record.reward_micronoid,
                reward_noid: crate::types::micronoid_to_noid(record.reward_micronoid),
                payout_address: record.payout_address,
                payout_key_index: record.payout_key_index,
                canonical,
                confirmations: canonical
                    .then(|| tip.saturating_sub(record.height).saturating_add(1))
                    .unwrap_or(0),
                full_block_available,
            });
        }

        Ok(WalletMinedBlocksPage {
            page,
            page_size,
            total: slice.total,
            total_pages,
            blocks,
        })
    }

    async fn wallet_scan(&self) -> RpcResult<WalletScanResult> {
        let _wallet_operation = self.wallet_operation_gate.lock().await;
        if !self.wallet.status().exists {
            return Err(rpc_err("wallet not initialized"));
        }
        self.reload_active_wallet().await
    }

    async fn wallet_discover_addresses(
        &self,
        max_additional: u32,
    ) -> RpcResult<Vec<WalletAddressInfo>> {
        const MAX_IMPORT_DISCOVERY_ADDRESSES: u32 = 20;
        if max_additional == 0 || max_additional > MAX_IMPORT_DISCOVERY_ADDRESSES {
            return Err(rpc_err(format!(
                "max_additional must be in 1..={MAX_IMPORT_DISCOVERY_ADDRESSES}"
            )));
        }

        let mut readiness = self.initial_sync_ready.clone();
        if !*readiness.borrow() {
            tokio::time::timeout(std::time::Duration::from_secs(180), async {
                while !*readiness.borrow() {
                    readiness
                        .changed()
                        .await
                        .map_err(|_| rpc_err("node stopped before state synchronization"))?;
                }
                Ok::<(), ErrorObject<'static>>(())
            })
            .await
            .map_err(|_| rpc_err("state synchronization timed out during address discovery"))??;
        }

        // Discovery is a read-mostly preview/commit operation. Keep sends and
        // balance work available while the owner index is queried. The commit
        // rejects a stale active/next index or newly pending wallet activity.
        let preview = self
            .wallet
            .preview_address_discovery(max_additional)
            .map_err(rpc_err)?;
        let chain = self.chain.read().await;
        let discovered_next_index = discover_contiguous_funded_prefix(
            preview.expected_next_index,
            &preview.candidates,
            |owner| {
                chain
                    .store
                    .has_verified_utxo_by_owner(owner)
                    .map_err(|error| rpc_err(error.to_string()))
            },
        )?;
        drop(chain);
        let addresses = self
            .wallet
            .commit_address_discovery(
                preview.expected_active_index,
                preview.expected_next_index,
                discovered_next_index,
            )
            .map_err(rpc_err)?;
        Ok(addresses)
    }

    async fn wallet_plan_send(
        &self,
        to_address: String,
        amount_micronoid: u64,
        fee_micronoid: u64,
    ) -> RpcResult<WalletSendPlan> {
        let _wallet_operation = self.wallet_operation_gate.lock().await;
        self.reload_active_wallet().await?;
        let _to_address = parse_address_param(&to_address)?.0;
        let (active_slot_count, log_slots) = self.mempool.fee_context().await;
        let floor = self.mempool.fee_floor().await;
        self.wallet
            .plan_send(
                amount_micronoid,
                if fee_micronoid == 0 {
                    None
                } else {
                    Some(fee_micronoid)
                },
                active_slot_count,
                log_slots,
                floor,
            )
            .map_err(wallet_plan_error)
    }

    async fn wallet_send(
        &self,
        to_address: String,
        amount_micronoid: u64,
        fee_micronoid: u64,
    ) -> RpcResult<WalletSendResult> {
        let _wallet_operation = self.wallet_operation_gate.lock().await;
        self.reload_active_wallet().await?;
        let to_address = parse_address_param(&to_address)?.0;

        let (fee_active_slot_count, fee_log_slots) = self.mempool.fee_context().await;
        let fee_floor = self.mempool.fee_floor().await;
        let plan = self
            .wallet
            .plan_send(
                amount_micronoid,
                (fee_micronoid != 0).then_some(fee_micronoid),
                fee_active_slot_count,
                fee_log_slots,
                fee_floor,
            )
            .map_err(wallet_plan_error)?;
        tracing::info!(
            amount_micronoid,
            fee_micronoid = plan.fee_micronoid,
            input_count = plan.input_count,
            output_count = plan.output_count,
            "wallet_send deterministic plan ready"
        );

        self.submit_wallet_transaction(WalletSubmissionRequest {
            to_address,
            amount_micronoid,
            fee_micronoid: plan.fee_micronoid,
            expected_input_count: plan.input_count,
            expected_output_count: plan.output_count,
            pending_history_amount_micronoid: amount_micronoid,
            build: WalletSubmissionBuild::Payment,
            failure_label: "wallet send",
        })
        .await
    }

    async fn wallet_plan_consolidation(&self) -> RpcResult<WalletConsolidationPlan> {
        let _wallet_operation = self.wallet_operation_gate.lock().await;
        self.reload_active_wallet().await?;
        let (active_slot_count, log_slots) = self.mempool.fee_context().await;
        let relay_floor = self.mempool.fee_floor().await;
        self.wallet
            .plan_consolidation(
                WALLET_CONSOLIDATION_INPUT_LIMIT,
                active_slot_count,
                log_slots,
                relay_floor,
            )
            .map_err(wallet_plan_error)
    }

    async fn wallet_consolidate(
        &self,
        selected_input_slots: Vec<u32>,
        expected_fee_micronoid: u64,
        expected_output_value_micronoid: u64,
    ) -> RpcResult<WalletConsolidationResult> {
        let _wallet_operation = self.wallet_operation_gate.lock().await;
        self.reload_active_wallet().await?;
        let (_, active_address) = self
            .wallet
            .active_address()
            .ok_or_else(|| rpc_err("wallet not initialized"))?;
        let active_address = parse_address_param(&active_address)?.0;
        let (active_slot_count, log_slots) = self.mempool.fee_context().await;
        let relay_floor = self.mempool.fee_floor().await;
        let plan = self
            .wallet
            .plan_consolidation(
                WALLET_CONSOLIDATION_INPUT_LIMIT,
                active_slot_count,
                log_slots,
                relay_floor,
            )
            .map_err(wallet_plan_error)?;
        if selected_input_slots != plan.selected_input_slots
            || expected_fee_micronoid != plan.fee_micronoid
            || expected_output_value_micronoid != plan.output_value_micronoid
        {
            return Err(rpc_err(
                "consolidation quote changed; request a new live quote before submitting",
            ));
        }
        tracing::info!(
            input_count = plan.input_count,
            input_value_micronoid = plan.input_value_micronoid,
            fee_micronoid = plan.fee_micronoid,
            output_value_micronoid = plan.output_value_micronoid,
            untouched_count = plan.untouched_count,
            "wallet_consolidate deterministic plan ready"
        );

        let submitted = self
            .submit_wallet_transaction(WalletSubmissionRequest {
                to_address: active_address,
                amount_micronoid: plan.output_value_micronoid,
                fee_micronoid: plan.fee_micronoid,
                expected_input_count: plan.input_count,
                expected_output_count: 1,
                pending_history_amount_micronoid: plan.fee_micronoid,
                build: WalletSubmissionBuild::Consolidation {
                    selected_input_slots: plan.selected_input_slots.clone(),
                },
                failure_label: "wallet consolidation",
            })
            .await?;
        Ok(WalletConsolidationResult {
            txid: submitted.txid,
            input_value_micronoid: plan.input_value_micronoid,
            fee_micronoid: submitted.fee_micronoid,
            output_value_micronoid: submitted.amount_micronoid,
            input_count: submitted.input_count,
            output_count: submitted.output_count,
            freed_slots: plan.freed_slots,
        })
    }

    async fn wallet_export_receipt(&self, txhash_hex: String) -> RpcResult<String> {
        self.wallet.export_receipt(&txhash_hex).map_err(rpc_err)
    }

    async fn wallet_next_address(&self) -> RpcResult<WalletAddressInfo> {
        let _wallet_operation = self.wallet_operation_gate.lock().await;
        self.wallet.create_next_address().map_err(rpc_err)
    }

    async fn wallet_list_addresses(&self) -> RpcResult<Vec<WalletAddressInfo>> {
        Ok(self.wallet.list_addresses())
    }

    async fn wallet_active_address(&self) -> RpcResult<WalletAddressInfo> {
        let (key_index, address) = self
            .wallet
            .active_address()
            .ok_or_else(|| rpc_err("wallet not initialized"))?;
        Ok(WalletAddressInfo {
            address,
            key_index,
            is_active: true,
        })
    }

    async fn wallet_set_active_address(&self, index: u32) -> RpcResult<WalletAddressInfo> {
        let _wallet_operation = self.wallet_operation_gate.lock().await;
        self.reload_active_wallet().await?;
        if self
            .wallet
            .active_address()
            .is_some_and(|(active_index, _)| active_index == index)
        {
            return self.wallet_active_address().await;
        }
        let preview = self.wallet.preview_address_switch(index).map_err(rpc_err)?;
        let (activated, _scan) = self.install_wallet_activation(preview).await?;
        if self.mining_payout_address.is_none() {
            let _ = self.mining_template_changes.send(());
        }
        Ok(activated)
    }

    // -----------------------------------------------------------------------
    // Node control
    // -----------------------------------------------------------------------

    async fn stop(&self) -> RpcResult<String> {
        // Take the sender (one-shot: subsequent calls are no-ops).
        let taken = self.stop_tx.lock().await.take();
        match taken {
            Some(tx) => {
                tracing::info!("RPC stop command received — initiating graceful shutdown");
                let _ = tx.send(());
                Ok("stopping".to_string())
            }
            None => Ok("already stopping".to_string()),
        }
    }

    // -----------------------------------------------------------------------
    // Mempool inspection
    // -----------------------------------------------------------------------

    async fn get_mempool_info(&self) -> RpcResult<MempoolInfo> {
        let snapshot = self.mempool.metadata_snapshot().await;

        let txs: Vec<MempoolTxInfo> = snapshot
            .entries
            .iter()
            .copied()
            .map(mempool_tx_info)
            .collect();

        Ok(MempoolInfo {
            size: txs.len(),
            fee_floor: snapshot.fee_floor,
            txs,
        })
    }

    async fn get_mempool_stats(&self) -> RpcResult<MempoolStats> {
        let usage = self.mempool.usage_snapshot().await;
        Ok(MempoolStats {
            size: usage.size,
            capacity: usage.capacity,
            intent_bytes: usage.intent_bytes as u64,
            max_intent_bytes: usage.max_intent_bytes as u64,
            fee_floor: usage.fee_floor,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn human_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Parse a required address parameter from canonical bech32m (`o1…`).
/// Optional mining payout selection handles its empty sentinel before calling
/// this function; wallet recipients and active addresses must never be empty.
fn parse_address_param(s: &str) -> RpcResult<noid_poseidon2b::primitives::Address> {
    if s.is_empty() {
        return Err(rpc_err("address must not be empty"));
    }
    noid_poseidon2b::primitives::Address::parse(s)
        .map_err(|e| rpc_err(format!("invalid address: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mined_block_identity_marks_exact_and_legacy_reorganizations() {
        let header = noid_chain::consensus::genesis_header();
        let payout = header.miner_address.to_bech32();
        let exact_hash = block_id(&header);

        assert!(mined_record_is_canonical(
            Some(exact_hash),
            header.timestamp,
            &payout,
            &header,
        ));
        let mut displaced_hash = exact_hash;
        displaced_hash[0] ^= 1;
        assert!(!mined_record_is_canonical(
            Some(displaced_hash),
            header.timestamp,
            &payout,
            &header,
        ));

        // Old history files have no block hash. Matching immutable metadata
        // keeps their canonical display, while either mismatch is sufficient
        // to mark a displaced local block without inventing confirmations.
        assert!(mined_record_is_canonical(
            None,
            header.timestamp,
            &payout,
            &header,
        ));
        assert!(!mined_record_is_canonical(
            None,
            header.timestamp.saturating_add(1),
            &payout,
            &header,
        ));
        assert!(!mined_record_is_canonical(
            None,
            header.timestamp,
            &noid_poseidon2b::primitives::Address([1; 32]).to_bech32(),
            &header,
        ));
    }

    #[test]
    fn imported_address_discovery_stops_at_the_first_empty_owner() {
        let candidates = (1u32..=5)
            .map(|index| (index, [index as u8; 32]))
            .collect::<Vec<_>>();
        let mut queried = Vec::new();
        let next_index = discover_contiguous_funded_prefix(1, &candidates, |owner| {
            queried.push(owner[0]);
            Ok::<bool, ()>(owner[0] < 3)
        })
        .unwrap();

        assert_eq!(next_index, 3);
        assert_eq!(queried, vec![1, 2, 3]);
    }

    #[test]
    fn imported_address_discovery_can_add_exactly_twenty_funded_addresses() {
        let candidates = (1u32..=20)
            .map(|index| (index, [index as u8; 32]))
            .collect::<Vec<_>>();
        let mut queries = 0usize;
        let next_index = discover_contiguous_funded_prefix(1, &candidates, |_| {
            queries += 1;
            Ok::<bool, ()>(true)
        })
        .unwrap();

        assert_eq!(queries, 20);
        assert_eq!(next_index, 21);
    }

    #[test]
    fn external_mining_slot_owns_exactly_one_attempt() {
        let now = Instant::now();
        let mut slot = ExternalMiningAttemptSlot::new(7);
        let template_id = slot.reserve_preparation(now).unwrap();
        assert!(slot.reserve_preparation(now).is_err());
        slot.install_ready(
            template_id,
            "prepared",
            11,
            [3u8; 32],
            now + Duration::from_secs(30),
        )
        .unwrap();

        let mut unknown = template_id;
        unknown[15] ^= 1;
        assert_eq!(
            slot.begin_proving(unknown, now, 11, [3u8; 32]),
            Err(ExternalMiningConsumeError::Unavailable)
        );
        assert_eq!(
            slot.begin_proving(template_id, now, 11, [3u8; 32]),
            Ok("prepared")
        );
        assert!(slot.reserve_preparation(now).is_err());
        slot.finish_proving(template_id);
        assert!(slot.reserve_preparation(now).is_ok());
    }

    #[test]
    fn external_mining_slot_drops_expired_and_stale_ready_attempts() {
        let now = Instant::now();
        let mut slot = ExternalMiningAttemptSlot::new(9);
        let expired = slot.reserve_preparation(now).unwrap();
        slot.install_ready(expired, (), 4, [1u8; 32], now).unwrap();
        assert!(slot.reserve_preparation(now).is_ok());

        let active = match &slot.state {
            ExternalMiningAttemptState::Preparing { template_id, .. } => *template_id,
            _ => panic!("fresh reservation must be preparing"),
        };
        slot.install_ready(active, (), 5, [2u8; 32], now + Duration::from_secs(30))
            .unwrap();
        slot.invalidate_except(6, [4u8; 32]);
        assert_eq!(
            slot.begin_proving(active, now, 6, [4u8; 32]),
            Err(ExternalMiningConsumeError::Unavailable)
        );
        assert!(slot.reserve_preparation(now).is_ok());
    }

    #[test]
    fn canonical_advance_invalidates_preparing_but_keeps_proving_occupied() {
        let now = Instant::now();
        let mut slot = ExternalMiningAttemptSlot::new(11);
        let preparing = slot.reserve_preparation(now).unwrap();
        slot.invalidate_except(8, [8u8; 32]);
        assert!(slot
            .install_ready(preparing, (), 7, [7u8; 32], now + Duration::from_secs(30),)
            .is_err());
        let proving = slot.reserve_preparation(now).unwrap();
        slot.install_ready(proving, (), 8, [8u8; 32], now + Duration::from_secs(30))
            .unwrap();
        slot.begin_proving(proving, now, 8, [8u8; 32]).unwrap();
        slot.invalidate_except(9, [9u8; 32]);
        assert!(slot.reserve_preparation(now).is_err());
        slot.finish_proving(proving);
        assert!(slot.reserve_preparation(now).is_ok());
    }

    #[test]
    fn preparation_lease_drop_releases_only_its_own_token() {
        let attempts = ExternalMiningAttemptInvalidator::new();
        let first = attempts.reserve_preparation(Instant::now()).unwrap();
        assert!(attempts.reserve_preparation(Instant::now()).is_err());
        drop(first);
        let second = attempts.reserve_preparation(Instant::now()).unwrap();
        let second_id = second.template_id();
        let mut stale_id = second_id;
        stale_id[15] ^= 1;
        attempts.inner.lock().unwrap().cancel_preparation(stale_id);
        assert!(attempts.reserve_preparation(Instant::now()).is_err());
        drop(second);
        assert!(attempts.reserve_preparation(Instant::now()).is_ok());
    }

    #[test]
    fn proving_lease_drop_releases_the_occupied_slot() {
        let attempts = ExternalMiningAttemptInvalidator::new();
        let mut preparation = attempts.reserve_preparation(Instant::now()).unwrap();
        let template_id = preparation.template_id();
        attempts.inner.lock().unwrap().state = ExternalMiningAttemptState::Proving { template_id };
        preparation.armed = false;
        drop(preparation);

        let proving = ExternalMiningProvingLease {
            attempts: attempts.clone(),
            template_id,
        };
        assert!(attempts.reserve_preparation(Instant::now()).is_err());
        drop(proving);
        assert!(attempts.reserve_preparation(Instant::now()).is_ok());
    }

    #[test]
    fn transaction_count_validation_matches_paged_spend() {
        assert!(validate_tx_counts(1, 1).is_ok());
        assert!(validate_tx_counts(
            noid_tx::MAX_PAGED_SPEND_INPUTS,
            noid_tx::MAX_PAGED_SPEND_OUTPUTS,
        )
        .is_ok());
        assert!(validate_tx_counts(0, 1).is_err());
        assert!(validate_tx_counts(noid_tx::MAX_PAGED_SPEND_INPUTS + 1, 1).is_err());
        assert!(validate_tx_counts(1, noid_tx::MAX_PAGED_SPEND_OUTPUTS + 1).is_err());
    }

    #[test]
    fn mempool_status_exposes_the_exact_b25_b255_boundary() {
        let metadata = |page_count| noid_mempool::MempoolEntryMetadata {
            tx_hash: noid_poseidon2b::primitives::TxBodyHash([page_count as u8; 32]),
            fee_micronoid: 7,
            fee_rate: 3,
            n_inputs: 1,
            n_outputs: 1,
            page_count,
            admitted_height: 11,
            has_authorization: true,
        };

        let b25 = mempool_tx_info(metadata(25));
        assert_eq!(b25.page_count, 25);
        assert_eq!(b25.minimum_proof_class, "B25");
        assert!(!b25.requires_b255_miner);

        let b255 = mempool_tx_info(metadata(26));
        assert_eq!(b255.page_count, 26);
        assert_eq!(b255.minimum_proof_class, "B255");
        assert!(b255.requires_b255_miner);
    }

    #[test]
    fn input_limit_error_exposes_only_the_canonical_limit() {
        let error = wallet_plan_error(WalletSendPlanError::InputLimitExceeded { max_inputs: 8 });

        assert_eq!(error.code(), WALLET_INPUT_LIMIT_EXCEEDED_CODE);
        assert_eq!(error.message(), WALLET_INPUT_LIMIT_EXCEEDED_MESSAGE);
        let data: WalletInputLimitExceeded = serde_json::from_str(
            error
                .data()
                .expect("input-limit error has structured data")
                .get(),
        )
        .expect("input-limit error data decodes");
        assert_eq!(data.max_inputs, 8);
        let value = serde_json::to_value(data).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 1);
    }

    #[test]
    fn block_template_response_serializes_canonical_counts() {
        let response = BlockTemplateResponse {
            template_id: "00112233445566778899aabbccddeeff".into(),
            pow_fields_hex: "00".into(),
            nonce_field_index: POW_NONCE_FIELD_INDEX,
            difficulty_target_hex: "ff".into(),
            height: 7,
            expires_in_seconds: 30,
            n_txs: 3,
            tx_input_counts: vec![2, 5],
            tx_output_counts: vec![2, 1],
            coinbase_value_micronoid: 50,
            claimable_fees_micronoid: 9,
        };

        let json = serde_json::to_value(response).expect("serialize template response");
        assert_eq!(json["tx_input_counts"][1], 5);
        assert_eq!(json["template_id"], "00112233445566778899aabbccddeeff");
        assert_eq!(json["nonce_field_index"], POW_NONCE_FIELD_INDEX);
        assert_eq!(json["expires_in_seconds"], 30);
        assert_eq!(json.as_object().unwrap().len(), 11);
    }

    #[test]
    fn external_nonce_is_exact_canonical_little_endian_u128() {
        let bytes = [
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45,
            0x23, 0x01,
        ];
        let encoded = hex::encode(bytes);
        assert_eq!(
            decode_external_nonce_hex(&encoded).unwrap(),
            0x0123_4567_89ab_cdef_0123_4567_89ab_cdef
        );
        assert!(decode_external_nonce_hex(&encoded.to_uppercase()).is_err());
        assert!(decode_external_nonce_hex(&format!("0x{encoded}")).is_err());
        assert!(decode_external_nonce_hex(&encoded[..30]).is_err());
    }

    #[test]
    fn required_address_parameters_reject_the_empty_mining_sentinel() {
        let error = parse_address_param("").unwrap_err();
        assert_eq!(error.message(), "address must not be empty");

        let address = noid_poseidon2b::primitives::Address([0x42; 32]);
        assert_eq!(parse_address_param(&address.to_bech32()).unwrap(), address);
    }
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

/// Start the JSON-RPC server and return a handle.
///
/// The server runs until `handle.stop()` is called or it is dropped.
/// Start the RPC server and return (handle, stop_rx).
/// `stop_rx` fires when `paranoid_stop` is called via RPC.
#[allow(clippy::too_many_arguments)]
pub async fn start_rpc_server(
    listen: SocketAddr,
    chain: Arc<RwLock<MdbxChainContext>>,
    mempool: AsyncMempool,
    wallet: Arc<dyn WalletOps + Send + Sync>,
    wallet_operation_gate: WalletOperationGate,
    p2p_cmd: noid_p2p::NetworkCommandSender,
    p2p_health: tokio::sync::watch::Receiver<noid_p2p::P2PHealthSnapshot>,
    canonical_tip_changes: tokio::sync::watch::Sender<noid_p2p::object_protocol::ChainPoint>,
    initial_sync_ready: tokio::sync::watch::Receiver<bool>,
    initial_sync_stage: tokio::sync::watch::Receiver<NodeSyncStage>,
    mining_network_ready: tokio::sync::watch::Receiver<bool>,
    mining_confirmed_peers: tokio::sync::watch::Receiver<usize>,
    mining_required_peers: usize,
    isolated_mining: bool,
    internal_mining_enabled: bool,
    cpu_backend: String,
    available_threads: usize,
    worker_threads: usize,
    history_step_runtime: Option<Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>>,
    history_step_ghost: Option<
        Arc<noid_recursive::acceptance::history_step::PreparedHistoryStepGhostAuthorization>,
    >,
    external_mining_attempts: ExternalMiningAttemptInvalidator,
    mining_template_changes: tokio::sync::broadcast::Sender<()>,
    mining_api_enabled: bool,
    mining_payout_address: Option<noid_poseidon2b::primitives::Address>,
    mut mining_key: Option<String>,
    mut operator_key: Option<String>,
    allow_custom_coinbase: bool,
) -> anyhow::Result<(
    jsonrpsee::server::ServerHandle,
    tokio::sync::oneshot::Receiver<()>,
)> {
    if !listen.ip().is_loopback() && mining_key.is_none() && operator_key.is_none() {
        anyhow::bail!("non-loopback RPC listener {listen} requires bearer authentication");
    }
    if mining_key.is_some() && mining_key == operator_key {
        anyhow::bail!("mining key and operator key must be different");
    }

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let stop_tx = Arc::new(tokio::sync::Mutex::new(Some(stop_tx)));
    let wallet_submission_mempool =
        mempool
            .clone()
            .with_authorization_verification_executor(Arc::new(
                |task: noid_mempool::AuthorizationVerificationTask| {
                    noid_miner::install_wallet_verifier_cpu(task).map_err(|error| {
                        format!("wallet verification CPU admission failed: {error}")
                    })?
                },
            ));
    let handler = RpcHandler {
        chain,
        mempool,
        wallet_submission_mempool,
        wallet,
        wallet_operation_gate,
        p2p_cmd,
        p2p_health,
        canonical_tip_changes,
        initial_sync_ready,
        initial_sync_stage,
        mining_network_ready,
        mining_confirmed_peers,
        mining_required_peers,
        isolated_mining,
        internal_mining_enabled,
        cpu_backend,
        available_threads,
        worker_threads,
        stop_tx,
        mining_api_enabled,
        mining_payout_address,
        allow_custom_coinbase,
        history_step_runtime,
        history_step_ghost,
        external_mining_attempts,
        mining_template_changes,
        external_mining_capacity: Arc::new(Mutex::new(AdaptiveProofCapacity::default())),
    };

    // Browser-originated requests are rejected before JSON-RPC dispatch so an
    // arbitrary website cannot reach a wallet through its loopback listener.
    // Only fixed digests are retained for constant-time Bearer verification;
    // successful Authorization headers are removed before jsonrpsee can trace
    // the request. The RPC middleware then fails closed around the exact access
    // scope attached by the HTTP middleware.
    let expected_mining_bearer = mining_key.as_deref().map(BearerDigest::from_token);
    let expected_operator_bearer = operator_key.as_deref().map(BearerDigest::from_token);
    if let Some(key) = mining_key.as_mut() {
        key.zeroize();
    }
    if let Some(key) = operator_key.as_mut() {
        key.zeroize();
    }
    let rpc_middleware =
        RpcServiceBuilder::new().layer_fn(|inner| CredentialScopeService { inner });
    let service_builder = Server::builder()
        .http_only()
        .max_request_body_size(RPC_MAX_REQUEST_BODY_BYTES)
        .set_http_middleware(tower::ServiceBuilder::new().layer(BearerAuthLayer {
            mining: expected_mining_bearer,
            operator: expected_operator_bearer,
        }))
        .set_rpc_middleware(rpc_middleware)
        .to_service_builder();
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| anyhow::anyhow!("build RPC server: {e}"))?;
    let methods: jsonrpsee::server::Methods = handler.into_rpc().into();
    let (stop_handle, handle) = stop_channel();
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => Some(accepted),
                _ = stop_handle.clone().shutdown() => None,
            };
            let Some(accepted) = accepted else {
                break;
            };
            let (socket, peer_addr) = match accepted {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::debug!(%error, "RPC listener failed to accept connection");
                    continue;
                }
            };
            if let Err(error) = socket.set_nodelay(true) {
                tracing::debug!(%peer_addr, %error, "RPC connection rejected because TCP_NODELAY could not be set");
                continue;
            }

            let service = service_builder
                .clone()
                .build(methods.clone(), stop_handle.clone());
            let service = PeerAddressService {
                inner: service,
                peer_addr,
            };
            let connection_stop = stop_handle.clone();
            tokio::spawn(async move {
                if let Err(error) =
                    serve_with_graceful_shutdown(socket, service, connection_stop.shutdown()).await
                {
                    tracing::debug!(%peer_addr, %error, "RPC connection ended with an error");
                }
            });
        }
    });
    tracing::debug!(%listen, "RPC server started");
    Ok((handle, stop_rx))
}

// ---------------------------------------------------------------------------
// Simple Bearer-token HTTP middleware
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct TcpPeerAddr(SocketAddr);

#[derive(Clone)]
struct PeerAddressService<S> {
    inner: S,
    peer_addr: SocketAddr,
}

impl<S, B> tower::Service<http::Request<B>> for PeerAddressService<S>
where
    S: tower::Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        request.extensions_mut().insert(TcpPeerAddr(self.peer_addr));
        self.inner.call(request)
    }
}

fn peer_ip_is_loopback(addr: SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.is_loopback(),
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    }
}

#[derive(Clone)]
struct BearerDigest([u8; 32]);

impl BearerDigest {
    fn from_token(token: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"Bearer ");
        hasher.update(token.as_bytes());
        Self(*hasher.finalize().as_bytes())
    }

    fn matches_header(&self, value: &http::HeaderValue) -> bool {
        let candidate = blake3::hash(value.as_bytes());
        bool::from(self.0.ct_eq(candidate.as_bytes()))
    }
}

#[derive(Clone)]
struct BearerAuthLayer {
    /// Remote native clients require one configured credential. Originless
    /// loopback clients without an Authorization header receive local access.
    mining: Option<BearerDigest>,
    operator: Option<BearerDigest>,
}

impl<S> tower::Layer<S> for BearerAuthLayer {
    type Service = BearerAuthService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        BearerAuthService {
            inner,
            mining: self.mining.clone(),
            operator: self.operator.clone(),
        }
    }
}

#[derive(Clone)]
struct BearerAuthService<S> {
    inner: S,
    mining: Option<BearerDigest>,
    operator: Option<BearerDigest>,
}

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

impl<S, B> tower::Service<http::Request<B>> for BearerAuthService<S>
where
    S: tower::Service<http::Request<B>, Response = http::Response<jsonrpsee::server::HttpBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = http::Response<jsonrpsee::server::HttpBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        // A browser can reach a loopback TCP listener from an unrelated web
        // origin. Reject every browser-originated HTTP and WebSocket request;
        // the official GUI, CLI and miner are native clients without Origin.
        if req.headers().contains_key(http::header::ORIGIN) {
            return Box::pin(async {
                Ok(http::Response::builder()
                    .status(http::StatusCode::FORBIDDEN)
                    .body(jsonrpsee::server::HttpBody::empty())
                    .expect("static 403 response"))
            });
        }

        // Consume this header even when authentication is disabled. jsonrpsee
        // traces the complete inner request at TRACE level, so no credential or
        // unrelated proxy secret may cross this middleware boundary.
        let authorization_count = req
            .headers()
            .get_all(http::header::AUTHORIZATION)
            .iter()
            .count();
        let authorization = req.headers_mut().remove(http::header::AUTHORIZATION);

        // A supplied credential always selects its exact role, including on
        // loopback. This keeps a local TLS proxy or miner scoped when it
        // forwards Authorization. Invalid and duplicate credentials fail
        // before the local no-credential path is considered.
        if (self.mining.is_some() || self.operator.is_some()) && authorization_count != 0 {
            let access = (authorization_count == 1)
                .then_some(authorization.as_ref())
                .flatten()
                .and_then(|authorization| {
                    if self
                        .mining
                        .as_ref()
                        .is_some_and(|expected| expected.matches_header(authorization))
                    {
                        Some(RpcAccess::Mining)
                    } else if self
                        .operator
                        .as_ref()
                        .is_some_and(|expected| expected.matches_header(authorization))
                    {
                        Some(RpcAccess::Operator)
                    } else {
                        None
                    }
                });

            if let Some(access) = access {
                req.extensions_mut().insert(access);
                let fut = self.inner.call(req);
                return Box::pin(fut);
            }
            return unauthorized_response();
        }

        // Only the peer address captured from TcpListener::accept can grant
        // owner access. HTTP headers are deliberately irrelevant here.
        let loopback = req
            .extensions()
            .get::<TcpPeerAddr>()
            .is_some_and(|peer| peer_ip_is_loopback(peer.0));
        if loopback {
            req.extensions_mut().insert(RpcAccess::Local);
            let fut = self.inner.call(req);
            return Box::pin(fut);
        }

        unauthorized_response()
    }
}

fn unauthorized_response<E>(
) -> Pin<Box<dyn Future<Output = Result<http::Response<jsonrpsee::server::HttpBody>, E>> + Send>> {
    Box::pin(async {
        Ok(http::Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .header(
                http::header::WWW_AUTHENTICATE,
                "Bearer realm=\"paranoid-rpc\"",
            )
            .body(jsonrpsee::server::HttpBody::empty())
            .expect("static 401 response"))
    })
}

/// Marker propagated from the HTTP request into each JSON-RPC request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RpcAccess {
    Local,
    Mining,
    Operator,
}

#[derive(Clone)]
struct CredentialScopeService<S> {
    inner: S,
}

fn mining_credential_method_allowed(method: &str) -> bool {
    matches!(method, "paranoid_getBlockTemplate" | "paranoid_submitBlock")
}

fn operator_credential_method_allowed(method: &str) -> bool {
    matches!(
        method,
        "paranoid_walletMinedBlocks"
            | "paranoid_walletGetBalance"
            | "paranoid_walletStatus"
            | "paranoid_walletPlanSend"
            | "paranoid_walletSend"
            | "paranoid_walletPlanConsolidation"
            | "paranoid_walletConsolidate"
            | "paranoid_walletReceipts"
            | "paranoid_walletExportReceipt"
            | "paranoid_getTx"
            | "paranoid_getMempoolEntry"
            | "paranoid_verifyReceipt"
            | "paranoid_submitTxIntent"
            | "paranoid_validateAddress"
            | "paranoid_getChainInfo"
            | "paranoid_estimateFee"
            | "paranoid_estimateFeeDetailed"
    )
}

impl<'a, S> RpcServiceT<'a> for CredentialScopeService<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'static,
    S::Future: Send + 'a,
{
    type Future = Pin<Box<dyn Future<Output = MethodResponse> + Send + 'a>>;

    fn call(&self, request: Request<'a>) -> Self::Future {
        let denial = match request.extensions().get::<RpcAccess>() {
            Some(RpcAccess::Local) => None,
            Some(RpcAccess::Mining) if !mining_credential_method_allowed(request.method_name()) => {
                Some((
                    -32001,
                    "mining credential is restricted to getBlockTemplate and submitBlock",
                ))
            }
            Some(RpcAccess::Operator)
                if !operator_credential_method_allowed(request.method_name()) =>
            {
                Some((
                    -32002,
                    "operator credential is restricted to the accounting and payout allowlist",
                ))
            }
            Some(RpcAccess::Mining | RpcAccess::Operator) => None,
            None => Some((
                -32003,
                "RPC request is missing an authenticated access scope",
            )),
        };
        if let Some((code, message)) = denial {
            let id = request.id();
            return Box::pin(async move {
                MethodResponse::error(id, ErrorObject::owned(code, message, None::<()>))
            });
        }

        let future = self.inner.call(request);
        Box::pin(future)
    }
}

#[cfg(test)]
mod access_control_tests {
    use std::convert::Infallible;
    use std::future::{ready, Ready};
    use std::net::SocketAddr;
    use std::task::{Context, Poll};

    use jsonrpsee::core::server::ResponsePayload;
    use jsonrpsee::types::Id;
    use jsonrpsee::RpcModule;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use tower::{Layer, Service, ServiceExt};

    #[derive(Clone)]
    struct OkService;

    impl<B> Service<http::Request<B>> for OkService {
        type Response = http::Response<jsonrpsee::server::HttpBody>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: http::Request<B>) -> Self::Future {
            ready(Ok(http::Response::builder()
                .status(http::StatusCode::OK)
                .body(jsonrpsee::server::HttpBody::empty())
                .expect("static test response")))
        }
    }

    #[derive(Clone)]
    struct AccessProbeService {
        expected: RpcAccess,
    }

    impl<B> Service<http::Request<B>> for AccessProbeService {
        type Response = http::Response<jsonrpsee::server::HttpBody>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<B>) -> Self::Future {
            let status = if request.extensions().get::<RpcAccess>() == Some(&self.expected)
                && !request.headers().contains_key(http::header::AUTHORIZATION)
            {
                http::StatusCode::OK
            } else {
                http::StatusCode::INTERNAL_SERVER_ERROR
            };
            ready(Ok(http::Response::builder()
                .status(status)
                .body(jsonrpsee::server::HttpBody::empty())
                .expect("static test response")))
        }
    }

    #[derive(Clone)]
    struct RpcOkService;

    impl<'a> RpcServiceT<'a> for RpcOkService {
        type Future = Ready<MethodResponse>;

        fn call(&self, request: Request<'a>) -> Self::Future {
            ready(MethodResponse::response(
                request.id(),
                ResponsePayload::success("ok"),
                usize::MAX,
            ))
        }
    }

    fn rpc_request(method: &'static str, access: Option<RpcAccess>) -> Request<'static> {
        let mut request = Request::new(method.into(), None, Id::Number(1));
        if let Some(access) = access {
            request.extensions_mut().insert(access);
        }
        request
    }

    fn from_peer<B>(mut request: http::Request<B>, peer: &str) -> http::Request<B> {
        request
            .extensions_mut()
            .insert(TcpPeerAddr(peer.parse().unwrap()));
        request
    }

    async fn send_http_request(addr: SocketAddr, request: String) -> String {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    async fn post_rpc_body(addr: SocketAddr, body: &str, token: &str) -> String {
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        send_http_request(addr, request).await
    }

    async fn post_rpc(addr: SocketAddr, method: &str, token: &str) -> String {
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":[]}}"#);
        post_rpc_body(addr, &body, token).await
    }

    async fn post_rpc_without_authorization(addr: SocketAddr, method: &str) -> String {
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":[]}}"#);
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        send_http_request(addr, request).await
    }

    async fn start_access_test_server(
        peer_override: Option<SocketAddr>,
    ) -> (SocketAddr, jsonrpsee::server::ServerHandle) {
        let rpc_middleware =
            RpcServiceBuilder::new().layer_fn(|inner| CredentialScopeService { inner });
        let service_builder = Server::builder()
            .http_only()
            .max_request_body_size(RPC_MAX_REQUEST_BODY_BYTES)
            .set_http_middleware(tower::ServiceBuilder::new().layer(BearerAuthLayer {
                mining: Some(BearerDigest::from_token("mining-integration-token")),
                operator: Some(BearerDigest::from_token("operator-integration-token")),
            }))
            .set_rpc_middleware(rpc_middleware)
            .to_service_builder();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut module = RpcModule::new(());
        module
            .register_method("paranoid_getBlockTemplate", |_, _, _| "template")
            .unwrap();
        module
            .register_method("paranoid_walletStatus", |_, _, _| "status")
            .unwrap();
        module
            .register_method("paranoid_walletSend", |_, _, _| "sent")
            .unwrap();
        module
            .register_method("paranoid_walletHistory", |_, _, _| "history")
            .unwrap();
        let methods: jsonrpsee::server::Methods = module.into();
        let (stop_handle, server_handle) = stop_channel();
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    accepted = listener.accept() => Some(accepted),
                    _ = stop_handle.clone().shutdown() => None,
                };
                let Some(Ok((socket, accepted_peer))) = accepted else {
                    break;
                };
                let service = service_builder
                    .clone()
                    .build(methods.clone(), stop_handle.clone());
                let service = PeerAddressService {
                    inner: service,
                    peer_addr: peer_override.unwrap_or(accepted_peer),
                };
                let connection_stop = stop_handle.clone();
                tokio::spawn(async move {
                    serve_with_graceful_shutdown(socket, service, connection_stop.shutdown())
                        .await
                        .unwrap();
                });
            }
        });
        (addr, server_handle)
    }

    async fn websocket_upgrade_status(addr: SocketAddr, token: &str) -> String {
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = [0u8; 4096];
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut response))
            .await
            .expect("HTTP-only server must answer a WebSocket upgrade")
            .unwrap();
        String::from_utf8_lossy(&response[..read]).into_owned()
    }

    #[tokio::test]
    async fn browser_origin_is_rejected_before_rpc_dispatch() {
        let service = BearerAuthLayer {
            mining: None,
            operator: Some(BearerDigest::from_token("operator-token")),
        }
        .layer(OkService);
        let request = http::Request::builder()
            .header(http::header::ORIGIN, "https://attacker.example")
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::AUTHORIZATION, "Bearer operator-token")
            .body(())
            .unwrap();
        let request = from_peer(request, "127.0.0.1:12345");

        let response = service.oneshot(request).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn native_originless_client_remains_available_without_a_key() {
        let service = BearerAuthLayer {
            mining: None,
            operator: None,
        }
        .layer(AccessProbeService {
            expected: RpcAccess::Local,
        });
        let request = http::Request::builder()
            .header(
                http::header::AUTHORIZATION,
                "Bearer must-not-reach-inner-service",
            )
            .body(())
            .unwrap();
        let request = from_peer(request, "127.0.0.1:12345");

        let response = service.oneshot(request).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn bearer_auth_remains_required_when_configured() {
        let layer = BearerAuthLayer {
            mining: Some(BearerDigest::from_token("correct-token")),
            operator: None,
        };

        let unauthorized = layer
            .clone()
            .layer(OkService)
            .oneshot(from_peer(
                http::Request::builder().body(()).unwrap(),
                "192.0.2.10:12345",
            ))
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), http::StatusCode::UNAUTHORIZED);

        let authorized_request = http::Request::builder()
            .header(http::header::AUTHORIZATION, "Bearer correct-token")
            .body(())
            .unwrap();
        let authorized = layer
            .layer(OkService)
            .oneshot(from_peer(authorized_request, "192.0.2.10:12345"))
            .await
            .unwrap();
        assert_eq!(authorized.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn each_valid_bearer_marks_the_connection_with_exactly_one_role() {
        let service = BearerAuthLayer {
            mining: Some(BearerDigest::from_token("mining-token")),
            operator: Some(BearerDigest::from_token("operator-token")),
        }
        .layer(AccessProbeService {
            expected: RpcAccess::Mining,
        });
        let request = http::Request::builder()
            .header(http::header::AUTHORIZATION, "Bearer mining-token")
            .body(())
            .unwrap();
        let response = service
            .oneshot(from_peer(request, "192.0.2.10:12345"))
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);

        let service = BearerAuthLayer {
            mining: Some(BearerDigest::from_token("mining-token")),
            operator: Some(BearerDigest::from_token("operator-token")),
        }
        .layer(AccessProbeService {
            expected: RpcAccess::Operator,
        });
        let request = http::Request::builder()
            .header(http::header::AUTHORIZATION, "Bearer operator-token")
            .body(())
            .unwrap();
        let response = service
            .oneshot(from_peer(request, "192.0.2.10:12345"))
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn loopback_without_authorization_receives_local_access_with_keys_configured() {
        for peer in ["127.0.0.1:12345", "[::1]:12345", "[::ffff:127.0.0.1]:12345"] {
            let service = BearerAuthLayer {
                mining: Some(BearerDigest::from_token("mining-token")),
                operator: Some(BearerDigest::from_token("operator-token")),
            }
            .layer(AccessProbeService {
                expected: RpcAccess::Local,
            });
            let request = from_peer(http::Request::builder().body(()).unwrap(), peer);
            let response = service.oneshot(request).await.unwrap();
            assert_eq!(response.status(), http::StatusCode::OK, "{peer}");
        }
    }

    #[tokio::test]
    async fn supplied_authorization_is_validated_even_on_loopback() {
        let layer = BearerAuthLayer {
            mining: None,
            operator: Some(BearerDigest::from_token("operator-token")),
        };
        let invalid = http::Request::builder()
            .header(http::header::AUTHORIZATION, "Bearer wrong-token")
            .body(())
            .unwrap();
        let response = layer
            .clone()
            .layer(OkService)
            .oneshot(from_peer(invalid, "127.0.0.1:12345"))
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);

        let valid = http::Request::builder()
            .header(http::header::AUTHORIZATION, "Bearer operator-token")
            .body(())
            .unwrap();
        let response = layer
            .clone()
            .layer(AccessProbeService {
                expected: RpcAccess::Operator,
            })
            .oneshot(from_peer(valid, "127.0.0.1:12345"))
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);

        let mut duplicate = http::Request::builder().body(()).unwrap();
        duplicate.headers_mut().append(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer operator-token"),
        );
        duplicate.headers_mut().append(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer operator-token"),
        );
        let response = layer
            .layer(OkService)
            .oneshot(from_peer(duplicate, "127.0.0.1:12345"))
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn headers_cannot_spoof_a_loopback_peer() {
        let service = BearerAuthLayer {
            mining: None,
            operator: None,
        }
        .layer(OkService);
        let request = http::Request::builder()
            .header(http::header::HOST, "127.0.0.1:9601")
            .header("forwarded", "for=127.0.0.1")
            .header("x-forwarded-for", "127.0.0.1")
            .body(())
            .unwrap();
        let response = service
            .oneshot(from_peer(request, "192.0.2.10:12345"))
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_tcp_peer_address_fails_closed() {
        let service = BearerAuthLayer {
            mining: None,
            operator: None,
        }
        .layer(OkService);
        let response = service
            .oneshot(http::Request::builder().body(()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mining_credential_is_limited_to_external_mining_methods() {
        let service = CredentialScopeService {
            inner: RpcOkService,
        };

        for method in ["paranoid_getBlockTemplate", "paranoid_submitBlock"] {
            let response = service
                .call(rpc_request(method, Some(RpcAccess::Mining)))
                .await;
            assert!(response.is_success(), "{method} must remain available");
        }

        for method in [
            "paranoid_walletSend",
            "paranoid_walletStatus",
            "paranoid_stop",
            "paranoid_getChainInfo",
        ] {
            let response = service
                .call(rpc_request(method, Some(RpcAccess::Mining)))
                .await;
            assert_eq!(response.as_error_code(), Some(-32001), "{method}");
        }
    }

    #[tokio::test]
    async fn operator_credential_is_limited_to_accounting_and_payout_methods() {
        let service = CredentialScopeService {
            inner: RpcOkService,
        };

        for method in [
            "paranoid_walletMinedBlocks",
            "paranoid_walletGetBalance",
            "paranoid_walletStatus",
            "paranoid_walletPlanSend",
            "paranoid_walletSend",
            "paranoid_walletPlanConsolidation",
            "paranoid_walletConsolidate",
            "paranoid_walletReceipts",
            "paranoid_walletExportReceipt",
            "paranoid_getTx",
            "paranoid_getMempoolEntry",
            "paranoid_verifyReceipt",
            "paranoid_submitTxIntent",
            "paranoid_validateAddress",
            "paranoid_getChainInfo",
            "paranoid_estimateFee",
            "paranoid_estimateFeeDetailed",
        ] {
            let response = service
                .call(rpc_request(method, Some(RpcAccess::Operator)))
                .await;
            assert!(response.is_success(), "{method} must remain available");
        }

        for method in [
            "paranoid_getBlockTemplate",
            "paranoid_submitBlock",
            "paranoid_stop",
            "paranoid_walletListUtxos",
            "paranoid_walletHistory",
            "paranoid_walletScan",
            "paranoid_walletNextAddress",
            "paranoid_walletSetActiveAddress",
            "paranoid_getNodeStatus",
        ] {
            let response = service
                .call(rpc_request(method, Some(RpcAccess::Operator)))
                .await;
            assert_eq!(response.as_error_code(), Some(-32002), "{method}");
        }
    }

    #[tokio::test]
    async fn ordinary_loopback_rpc_is_not_restricted_without_a_credential() {
        let service = CredentialScopeService {
            inner: RpcOkService,
        };
        let response = service
            .call(rpc_request("paranoid_walletSend", Some(RpcAccess::Local)))
            .await;
        assert!(response.is_success());
    }

    #[tokio::test]
    async fn missing_access_scope_fails_closed() {
        let service = CredentialScopeService {
            inner: RpcOkService,
        };
        let response = service.call(rpc_request("paranoid_walletSend", None)).await;
        assert_eq!(response.as_error_code(), Some(-32003));
    }

    #[tokio::test]
    async fn live_server_keeps_mining_and_operator_scopes_disjoint() {
        let (addr, handle) =
            start_access_test_server(Some("192.0.2.10:12345".parse().unwrap())).await;

        let mining = post_rpc(
            addr,
            "paranoid_getBlockTemplate",
            "mining-integration-token",
        )
        .await;
        assert!(mining.starts_with("HTTP/1.1 200"), "{mining}");
        assert!(mining.contains(r#""result":"template""#), "{mining}");

        let mining_wallet = post_rpc(addr, "paranoid_walletSend", "mining-integration-token").await;
        assert!(mining_wallet.starts_with("HTTP/1.1 200"), "{mining_wallet}");
        assert!(
            mining_wallet.contains(r#""code":-32001"#),
            "{mining_wallet}"
        );
        assert!(
            !mining_wallet.contains(r#""result":"sent""#),
            "{mining_wallet}"
        );

        let operator_wallet =
            post_rpc(addr, "paranoid_walletSend", "operator-integration-token").await;
        assert!(
            operator_wallet.starts_with("HTTP/1.1 200"),
            "{operator_wallet}"
        );
        assert!(
            operator_wallet.contains(r#""result":"sent""#),
            "{operator_wallet}"
        );

        let operator_mining = post_rpc(
            addr,
            "paranoid_getBlockTemplate",
            "operator-integration-token",
        )
        .await;
        assert!(
            operator_mining.starts_with("HTTP/1.1 200"),
            "{operator_mining}"
        );
        assert!(
            operator_mining.contains(r#""code":-32002"#),
            "{operator_mining}"
        );
        assert!(
            !operator_mining.contains(r#""result":"template""#),
            "{operator_mining}"
        );

        let operator_status =
            post_rpc(addr, "paranoid_walletStatus", "operator-integration-token").await;
        assert!(
            operator_status.contains(r#""result":"status""#),
            "{operator_status}"
        );

        let operator_other_wallet =
            post_rpc(addr, "paranoid_walletHistory", "operator-integration-token").await;
        assert!(
            operator_other_wallet.contains(r#""code":-32002"#),
            "{operator_other_wallet}"
        );

        let wrong = post_rpc(addr, "paranoid_walletSend", "wrong-token").await;
        assert!(wrong.starts_with("HTTP/1.1 401"), "{wrong}");
        assert!(!wrong.contains(r#""result":"sent""#), "{wrong}");

        let batch = post_rpc_body(
            addr,
            r#"[{"jsonrpc":"2.0","id":1,"method":"paranoid_walletStatus","params":[]},{"jsonrpc":"2.0","id":2,"method":"paranoid_walletHistory","params":[]}]"#,
            "operator-integration-token",
        )
        .await;
        assert!(batch.contains(r#""result":"status""#), "{batch}");
        assert!(batch.contains(r#""code":-32002"#), "{batch}");
        assert!(!batch.contains(r#""result":"history""#), "{batch}");

        let upgrade = websocket_upgrade_status(addr, "operator-integration-token").await;
        assert!(!upgrade.starts_with("HTTP/1.1 101"), "{upgrade}");

        handle.stop().unwrap();
        handle.stopped().await;
    }

    #[tokio::test]
    async fn live_server_grants_local_scope_from_accepted_loopback_peer() {
        let (addr, handle) = start_access_test_server(None).await;

        let wallet = post_rpc_without_authorization(addr, "paranoid_walletSend").await;
        assert!(wallet.starts_with("HTTP/1.1 200"), "{wallet}");
        assert!(wallet.contains(r#""result":"sent""#), "{wallet}");

        let history = post_rpc_without_authorization(addr, "paranoid_walletHistory").await;
        assert!(history.contains(r#""result":"history""#), "{history}");

        handle.stop().unwrap();
        handle.stopped().await;
    }
}
