// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Built-in wallet for the `parano1d` daemon.
//!
//! The wallet lives inside the daemon process. The master secret is generated
//! once and stored by the keystore; the active address's `SpendSecret` is
//! derived locally just in time for proving. Secret material is:
//! 1. Kept in the wallet keystore (plaintext mode currently has no password)
//! 2. Loaded/derived only inside the daemon
//! 3. Moved into one zeroizing `OwnerAuthWitness` per transaction
//! 4. Zeroized when its owner object is dropped
//! 5. **NEVER transmitted over the network** — not in RPC responses,
//!    not in P2P messages, not in `PagedSpendIntent`
//!
//! Transaction flow (all inside the daemon):
//! ```text
//! wallet send(to, amount, fee) →
//!   1. select UTXOs from utxos map
//!   2. get slot hints from local chain state (empty slots for outputs)
//!   3. builder::build_and_prove_tx(...)
//!      a. derive txid from the canonical body
//!      b. prove_tx(body, one_owner_witness) → WalletAuthorizationBundle
//!      c. assemble PagedSpendIntent bytes
//!   4. submit to own mempool
//! ```

pub mod builder;
pub mod keystore;
pub mod prover;
pub mod scanner;
pub mod state;

pub use state::{SharedWallet, WalletState};

#[cfg(test)]
use state::MAX_WALLET_ADDRESSES;

#[cfg(test)]
mod secret_surface_source_tests {
    #[test]
    fn wallet_secret_capabilities_stay_module_private_and_unlogged() {
        static_assertions::assert_not_impl_any!(
            super::state::WalletState:
                Copy, Clone, std::fmt::Debug, serde::Serialize, serde::de::DeserializeOwned
        );
        static_assertions::assert_not_impl_any!(
            super::builder::TxBuildData:
                Copy, Clone, std::fmt::Debug, serde::Serialize, serde::de::DeserializeOwned
        );

        let keystore = include_str!("keystore.rs");
        let state = include_str!("state.rs");
        let builder = include_str!("builder.rs");
        let prover = include_str!("prover.rs");

        assert!(keystore.contains("pub(super) struct MasterSecret("));
        assert!(!keystore.contains("pub struct MasterSecret("));
        assert!(state.contains("pub(super) fn spend_secret_for("));
        assert!(!state.contains("pub fn spend_secret_for("));

        for source in [keystore, state, builder, prover] {
            for line in source.lines().filter(|line| line.contains("tracing::")) {
                assert!(
                    !line.contains("secret") && !line.contains("witness"),
                    "wallet logging statement mentions secret material: {line}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// WalletHandle — implements WalletOps for RPC layer
// ---------------------------------------------------------------------------

use std::sync::Arc;

use noid_chain::storage::VerifiedOwnerSnapshot;
use noid_rpc::types::{
    micronoid_to_noid, FeeBreakdownInfo, WalletAddressInfo, WalletBalance, WalletConsolidationPlan,
    WalletHistoryEntry, WalletScanResult, WalletSendPlan, WalletStatus, WalletUtxoInfo,
    WALLET_CONSOLIDATION_INPUT_LIMIT,
};
use noid_rpc::wallet_ops::{
    WalletActivationPreview, WalletAddressDiscoveryPreview, WalletMinedBlockRecord,
    WalletMinedBlockSlice, WalletReceiptRecord, WalletReceiptSlice, WalletSendPlanError,
};
use noid_rpc::WalletOps;
use noid_tx::MAX_PAGED_SPEND_INPUTS;

/// Thread-safe handle to the in-process wallet.
///
/// Implements `WalletOps` so `RpcHandler` can call wallet methods without
/// depending on noid_node types.
pub struct WalletHandle {
    pub inner: SharedWallet,
}

impl WalletHandle {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(inner: SharedWallet) -> Arc<dyn WalletOps + Send + Sync> {
        Arc::new(Self { inner })
    }
}

/// Apply one already-committed block while the caller still holds the chain
/// write guard. This is the only incremental active-wallet update path; keeping
/// the lock order `chain -> wallet` prevents account activation from installing
/// a newer snapshot and then receiving an older block delta.
pub fn update_for_accepted_block(
    wallet: &SharedWallet,
    block: &noid_chain::block::Block,
) -> Result<(), String> {
    let mut guard = wallet
        .lock()
        .map_err(|_| "wallet state lock is poisoned".to_string())?;
    let Some(wallet) = guard.as_mut() else {
        return Ok(());
    };

    let history_count_before = wallet.history.len();
    let receipt_count_before = wallet.receipts.len();
    let active_address = wallet.active_address();
    let active_index = wallet.active_index;
    scanner::update_active_wallet_from_block(
        &mut wallet.utxos,
        &mut wallet.history,
        &mut wallet.receipts,
        active_address,
        active_index,
        &mut wallet.pending_input_slots,
        block,
    )?;
    wallet.active_snapshot = Some(state::ActiveWalletSnapshot {
        height: block.header.height,
        tip_hash: noid_chain::consensus::pow::block_id(&block.header),
        state_root: block.header.state_root,
        log_slots: block.header.log_slots,
        active_slot_count: block.header.active_slot_count,
        alloc_counter: block.header.alloc_counter,
    });

    let mut history_changed = wallet.history.len() != history_count_before;
    let confirmed_block_hash = noid_chain::block_id(&block.header);
    for txid in noid_chain::try_compute_logical_txids(&block.transactions)
        .map_err(|error| format!("accepted block logical txids: {error}"))?
    {
        history_changed |=
            wallet.confirm_pending_tx(&txid.0, block.header.height, confirmed_block_hash);
    }
    for tx in &block.transactions {
        let output_slots: Vec<u32> = tx
            .body
            .live_outputs()
            .map(|(_, output)| output)
            .map(|output| output.slot_index)
            .collect();
        wallet.remove_pending_outputs(&output_slots);
    }
    wallet.history_dirty |= history_changed;
    wallet.receipts_dirty |= wallet.receipts.len() != receipt_count_before;
    if wallet.history_dirty {
        wallet.save_history()?;
    }
    if wallet.receipts_dirty {
        wallet.save_receipts()?;
    }
    Ok(())
}

fn recover_outgoing_receipts_from_block(
    wallet: &mut WalletState,
    owned_addresses: &std::collections::HashSet<[u8; 32]>,
    sent_history: &std::collections::HashSet<[u8; 32]>,
    block: &noid_chain::block::Block,
) -> (usize, bool) {
    let stream = noid_chain::validate_block_page_stream(&block.transactions)
        .expect("retained accepted block has a canonical PagedSpend stream");
    let tx_hashes = noid_chain::try_compute_logical_txids(&block.transactions)
        .expect("retained accepted block has canonical logical txids")
        .into_iter()
        .map(|txid| txid.0)
        .collect::<Vec<_>>();
    let mut recovered = 0usize;
    let mut history_changed = false;
    for (group_index, group) in stream.groups.iter().enumerate() {
        let tx_index = stream.user_logical_index(group_index);
        let tx_hash = group.spend.logical_txid.0;
        let start = stream.user_body_start(usize::from(group.start_page));
        let end = stream.user_body_start(group.end_page_exclusive());
        let pages = &block.transactions[start..end];
        let has_distinct_recipient = pages
            .iter()
            .flat_map(|page| page.body.live_outputs().map(|(_, output)| output))
            .any(|output| output.owner != group.spend.input_owner);
        let outgoing = sent_history.contains(&tx_hash)
            || pages.iter().any(|page| {
                page.body.live_inputs().next().is_some()
                    && owned_addresses.contains(&page.body.input_owner.0)
            });
        if !outgoing || !has_distinct_recipient {
            continue;
        }
        if let std::collections::hash_map::Entry::Vacant(entry) = wallet.receipts.entry(tx_hash) {
            entry.insert(
                noid_chain::consensus::receipt::generate_receipt(
                    &block.header,
                    pages,
                    tx_index,
                    &tx_hashes,
                )
                .to_bytes(),
            );
            recovered += 1;
        }
        for history in wallet.history.iter_mut().filter(|entry| {
            entry.tx_hash == tx_hash
                && entry.direction == state::TxDirection::Sent
                && entry.height == 0
        }) {
            history.height = block.header.height;
            history_changed = true;
        }
    }
    (recovered, history_changed)
}

/// Reconcile the durable receipt cache with permanent canonical headers and
/// recover any receipt lost in the crash window between chain commit and the
/// wallet-side fsync. Recovery reads only the consensus-retained body window.
pub fn reconcile_receipts_at_startup(
    wallet: &mut WalletState,
    chain: &noid_chain::storage::MdbxChainContext,
) -> Result<(usize, usize), String> {
    use noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH;
    use noid_chain::consensus::receipt::{
        verify_against_header, verify_merkle_inclusion, ParanoidReceipt,
    };

    let mut removed = 0usize;
    let receipt_keys = wallet.receipts.keys().copied().collect::<Vec<_>>();
    for tx_hash in receipt_keys {
        let receipt = wallet
            .receipts
            .get(&tx_hash)
            .and_then(|bytes| ParanoidReceipt::from_bytes(bytes).ok());
        let valid = match receipt {
            Some(receipt)
                if receipt.summary.logical_txid == tx_hash
                    && verify_merkle_inclusion(&receipt)
                    && receipt
                        .summary
                        .inputs
                        .first()
                        .is_some_and(|(_, input_owner)| {
                            receipt
                                .summary
                                .outputs
                                .iter()
                                .any(|(_, _, owner)| owner != input_owner)
                        }) =>
            {
                match chain
                    .store
                    .get_header(receipt.claimed_height)
                    .map_err(|error| format!("load canonical receipt header: {error}"))?
                {
                    Some(header) => verify_against_header(&receipt, &header),
                    // A chain-data purge preserves wallet artifacts. During the
                    // following snapshot bootstrap, the receipt's permanent
                    // header may not have arrived yet; absence is not evidence
                    // that the receipt belongs to an orphaned block.
                    None => true,
                }
            }
            _ => false,
        };
        if !valid {
            wallet.receipts.remove(&tx_hash);
            removed += 1;
        }
    }

    // This set is used only to recover an outgoing transaction whose durable
    // history write was lost. Receipt eligibility itself is strictly
    // source-owner based and never scans wallet addresses.
    let owned_addresses = (0..wallet.next_index)
        .map(|index| wallet.address_at(index).0)
        .collect::<std::collections::HashSet<_>>();
    let sent_history = wallet
        .history
        .iter()
        .filter(|entry| entry.direction == state::TxDirection::Sent)
        .map(|entry| entry.tx_hash)
        .collect::<std::collections::HashSet<_>>();
    let tip = chain.tip_height();
    let first = tip
        .saturating_sub(RECENT_BLOCK_RETENTION_DEPTH.saturating_sub(1))
        .max(1);
    let mut recovered = 0usize;
    let mut history_changed = false;
    if first <= tip {
        for height in first..=tip {
            let Some(bundle_bytes) = chain
                .store
                .get_recent_accepted_block_bundle_bounded(height)
                .map_err(|error| format!("load retained accepted block {height}: {error}"))?
            else {
                continue;
            };
            let bundle = noid_chain::AcceptedBlockBundle::decode(&bundle_bytes)
                .map_err(|error| format!("decode retained accepted block {height}: {error}"))?;
            let block = noid_chain::block::Block::from_bytes(bundle.block_bytes())
                .map_err(|error| format!("decode retained block body {height}: {error:?}"))?;
            let (block_recovered, block_history_changed) = recover_outgoing_receipts_from_block(
                wallet,
                &owned_addresses,
                &sent_history,
                &block,
            );
            recovered += block_recovered;
            history_changed |= block_history_changed;
        }
    }

    if history_changed {
        wallet.history_dirty = true;
        wallet.save_history()?;
    }
    if removed != 0 || recovered != 0 {
        wallet.receipts_dirty = true;
        wallet.save_receipts()?;
    }
    Ok((removed, recovered))
}

/// Install the one exact post-reorg active-owner snapshot, then derive only
/// history/receipt artifacts from replacement block bodies. No replacement
/// block is ever replayed onto the old-branch UTXO cache.
#[allow(clippy::too_many_arguments)]
pub fn install_reorg_snapshot_and_artifacts(
    wallet: &SharedWallet,
    expected_active_index: u32,
    expected_next_index: u32,
    owner: [u8; 32],
    snapshot: VerifiedOwnerSnapshot,
    reserved_input_slots: &std::collections::HashSet<u32>,
    reserved_output_slots: &std::collections::HashSet<u32>,
    reclaimed_tx_hashes: &[noid_poseidon2b::primitives::TxBodyHash],
    replacement_blocks: &[&noid_chain::block::Block],
) -> Result<(), String> {
    let mut guard = wallet
        .lock()
        .map_err(|_| "wallet state lock is poisoned".to_string())?;
    let Some(wallet) = guard.as_mut() else {
        return Ok(());
    };

    wallet.commit_verified_activation(
        expected_active_index,
        expected_next_index,
        expected_active_index,
        owner,
        snapshot,
        reserved_input_slots,
        reserved_output_slots,
    )?;

    let reclaimed: std::collections::HashSet<[u8; 32]> =
        reclaimed_tx_hashes.iter().map(|hash| hash.0).collect();
    // Receipts commit to the orphaned block header and transaction position.
    // Remove every reclaimed receipt before replay; a transaction that also
    // appears on the replacement branch gets a fresh canonical receipt below.
    for tx_hash in &reclaimed {
        wallet.receipts.remove(tx_hash);
    }
    let replacement: std::collections::HashSet<[u8; 32]> = replacement_blocks
        .iter()
        .flat_map(|block| {
            noid_chain::try_compute_logical_txids(&block.transactions)
                .expect("committed replacement block has a canonical logical tx stream")
        })
        .map(|txid| txid.0)
        .collect();
    wallet.history.retain_mut(|entry| {
        if !reclaimed.contains(&entry.tx_hash) {
            return true;
        }
        // A locally mined block remains part of the wallet's mining record
        // after it loses a reorganization. Its exact block hash lets RPC and
        // GUI report ORPHANED without pretending the reward is spendable.
        if entry.is_coinbase {
            return true;
        }
        if replacement.contains(&entry.tx_hash) && entry.direction == state::TxDirection::Sent {
            // Preserve the local source-account tag so the replacement-chain
            // confirmation can produce a receipt at its new height.
            entry.height = 0;
            return true;
        }
        false
    });

    let active_address = wallet.active_address();
    let active_index = wallet.active_index;
    for block in replacement_blocks {
        scanner::update_wallet_artifacts_from_block(
            &mut wallet.history,
            &mut wallet.receipts,
            active_address,
            active_index,
            block,
        );
        let confirmed_block_hash = noid_chain::block_id(&block.header);
        for txid in noid_chain::try_compute_logical_txids(&block.transactions)
            .expect("committed replacement block has canonical logical txids")
        {
            let _ = wallet.confirm_pending_tx(&txid.0, block.header.height, confirmed_block_hash);
        }
        for transaction in &block.transactions {
            let output_slots: Vec<u32> = transaction
                .body
                .live_outputs()
                .map(|(_, output)| output)
                .map(|output| output.slot_index)
                .collect();
            wallet.remove_pending_outputs(&output_slots);
        }
    }
    wallet.history_dirty = true;
    wallet.receipts_dirty = true;
    wallet.save_history()?;
    // Persist even the empty map: otherwise removing the last orphan-bound
    // receipt in RAM would leave its old file to resurrect after restart.
    wallet.save_receipts()?;
    Ok(())
}

/// Fail closed if an exact owner snapshot cannot be installed after a chain
/// replacement. A later verified reload restores the cache.
pub fn invalidate_active_cache(wallet: &SharedWallet) {
    let Ok(mut guard) = wallet.lock() else {
        return;
    };
    if let Some(wallet) = guard.as_mut() {
        wallet.utxos.clear();
        wallet.pending_input_slots.clear();
        wallet.active_snapshot = None;
    }
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

impl WalletOps for WalletHandle {
    fn status(&self) -> WalletStatus {
        let guard = self.inner.lock().unwrap();
        match &*guard {
            None => WalletStatus {
                exists: false,
                address: String::new(),
                active_index: 0,
                balance_micronoid: 0,
                balance_noid: 0.0,
                utxo_count: 0,
                address_count: 0,
            },
            Some(w) => {
                let balance = w.balance();
                WalletStatus {
                    exists: true,
                    address: w.active_address().to_bech32(),
                    active_index: w.active_index,
                    balance_micronoid: balance,
                    balance_noid: micronoid_to_noid(balance),
                    utxo_count: w.utxos.len(),
                    address_count: w.next_index,
                }
            }
        }
    }

    fn get_address(&self, index: u32) -> Option<String> {
        let guard = self.inner.lock().unwrap();
        guard
            .as_ref()
            .and_then(|w| (index < w.next_index).then(|| w.address_at(index).to_bech32()))
    }

    fn get_balance(&self) -> WalletBalance {
        let guard = self.inner.lock().unwrap();
        match &*guard {
            None => WalletBalance {
                balance_micronoid: 0,
                balance_noid: 0.0,
                utxo_count: 0,
                pending_outbound_micronoid: 0,
                pending_incoming_micronoid: 0,
                spendable_micronoid: 0,
                spendable_noid: 0.0,
            },
            Some(w) => {
                let total = w.balance();
                let pending_out: u64 = w
                    .pending_input_slots
                    .iter()
                    .filter_map(|&s| w.utxos.get(&s))
                    .filter(|u| u.key_index == w.active_index)
                    .map(|u| u.value)
                    .sum();
                let spendable = total.saturating_sub(pending_out);
                WalletBalance {
                    balance_micronoid: total,
                    balance_noid: micronoid_to_noid(total),
                    utxo_count: w.utxos.len(),
                    pending_outbound_micronoid: pending_out,
                    pending_incoming_micronoid: 0,
                    spendable_micronoid: spendable,
                    spendable_noid: micronoid_to_noid(spendable),
                }
            }
        }
    }

    fn list_utxos(&self) -> Vec<WalletUtxoInfo> {
        let guard = self.inner.lock().unwrap();
        match &*guard {
            None => vec![],
            Some(w) => w
                .utxos
                .values()
                .map(|u| WalletUtxoInfo {
                    slot_index: u.slot_index,
                    value_micronoid: u.value,
                    creation_id: u.creation_id,
                    value_noid: micronoid_to_noid(u.value),
                    address: u.address.to_bech32(),
                    key_index: u.key_index,
                    confirmed_height: u.confirmed_height,
                    reserved: w.pending_input_slots.contains(&u.slot_index),
                })
                .collect(),
        }
    }

    fn history(&self) -> Vec<WalletHistoryEntry> {
        let guard = self.inner.lock().unwrap();
        match &*guard {
            None => vec![],
            Some(w) => w
                .history
                .iter()
                .filter(|entry| entry.own_key_index == Some(w.active_index))
                .map(|h| WalletHistoryEntry {
                    tx_hash: hex::encode(h.tx_hash),
                    height: h.height,
                    direction: match h.direction {
                        state::TxDirection::Sent => "sent".into(),
                        state::TxDirection::Received => "received".into(),
                    },
                    is_coinbase: h.is_coinbase,
                    amount_micronoid: h.amount_micronoid,
                    amount_noid: micronoid_to_noid(h.amount_micronoid),
                    peer_address: h
                        .peer_address
                        .map(|a| noid_poseidon2b::primitives::Address(a).to_bech32()),
                    timestamp: h.timestamp,
                    own_address: h.own_address.clone(),
                    own_key_index: h.own_key_index,
                })
                .collect(),
        }
    }

    fn receipts(&self, offset: usize, limit: usize) -> Result<WalletReceiptSlice, String> {
        use noid_chain::consensus::receipt::ParanoidReceipt;

        let guard = self.inner.lock().unwrap();
        let wallet = guard
            .as_ref()
            .ok_or_else(|| "wallet not initialized".to_string())?;
        let mut receipts = Vec::with_capacity(wallet.receipts.len());
        for (txid, bytes) in &wallet.receipts {
            let receipt = ParanoidReceipt::from_bytes(bytes).map_err(|error| {
                format!("decode durable receipt {}: {error}", hex::encode(txid))
            })?;
            if receipt.summary.logical_txid != *txid {
                return Err(format!(
                    "durable receipt key does not match authenticated txid {}",
                    hex::encode(txid)
                ));
            }
            let sent = wallet.history.iter().find(|entry| {
                entry.tx_hash == *txid && entry.direction == state::TxDirection::Sent
            });
            let input_owner = receipt.summary.inputs.first().map(|(_, owner)| *owner);
            let recipient_outputs = receipt
                .summary
                .outputs
                .iter()
                .filter(|(_, _, owner)| Some(*owner) != input_owner)
                .collect::<Vec<_>>();
            if recipient_outputs.is_empty() {
                continue;
            }
            let derived_amount = recipient_outputs
                .iter()
                .map(|(_, amount, _)| *amount)
                .fold(0u64, u64::saturating_add);
            let derived_peer =
                (recipient_outputs.len() == 1).then(|| recipient_outputs[0].2.to_bech32());

            receipts.push(WalletReceiptRecord {
                txid: *txid,
                height: receipt.claimed_height,
                timestamp: receipt.summary.confirmed_unix,
                amount_micronoid: sent.map_or(derived_amount, |entry| entry.amount_micronoid),
                fee_micronoid: receipt.summary.fee_micronoid,
                peer_address: sent
                    .and_then(|entry| entry.peer_address)
                    .map(|owner| noid_poseidon2b::primitives::Address(owner).to_bech32())
                    .or(derived_peer),
                own_address: sent
                    .and_then(|entry| entry.own_address.clone())
                    .or_else(|| input_owner.map(|owner| owner.to_bech32())),
                own_key_index: sent.and_then(|entry| entry.own_key_index),
                input_count: receipt.summary.inputs.len(),
                output_count: receipt.summary.outputs.len(),
                receipt_bytes: bytes.len(),
            });
        }
        receipts.sort_unstable_by(|left, right| {
            right
                .height
                .cmp(&left.height)
                .then_with(|| right.timestamp.cmp(&left.timestamp))
                .then_with(|| right.txid.cmp(&left.txid))
        });
        let total = receipts.len();
        let receipts = receipts.into_iter().skip(offset).take(limit).collect();
        Ok(WalletReceiptSlice { total, receipts })
    }

    fn mined_blocks(&self, offset: usize, limit: usize) -> WalletMinedBlockSlice {
        let guard = self.inner.lock().unwrap();
        let Some(wallet) = &*guard else {
            return WalletMinedBlockSlice {
                total: 0,
                blocks: Vec::new(),
            };
        };

        let total = wallet
            .history
            .iter()
            .filter(|entry| entry.is_coinbase && entry.height != 0)
            .count();
        let blocks = wallet
            .history
            .iter()
            .rev()
            .filter(|entry| entry.is_coinbase && entry.height != 0)
            .skip(offset)
            .take(limit)
            .filter_map(|entry| {
                Some(WalletMinedBlockRecord {
                    coinbase_txid: entry.tx_hash,
                    block_hash: entry.block_hash,
                    height: entry.height,
                    timestamp: entry.timestamp,
                    reward_micronoid: entry.amount_micronoid,
                    payout_address: entry.own_address.clone()?,
                    payout_key_index: entry.own_key_index?,
                })
            })
            .collect();
        WalletMinedBlockSlice { total, blocks }
    }

    fn preview_active_reload(&self) -> Result<WalletActivationPreview, String> {
        let guard = self.inner.lock().unwrap();
        let w = guard
            .as_ref()
            .ok_or_else(|| "wallet not initialized".to_string())?;
        let owner = w.active_address();
        Ok(WalletActivationPreview {
            expected_active_index: w.active_index,
            expected_next_index: w.next_index,
            target_index: w.active_index,
            owner: owner.0,
        })
    }

    fn preview_address_switch(&self, index: u32) -> Result<WalletActivationPreview, String> {
        let guard = self.inner.lock().unwrap();
        let w = guard
            .as_ref()
            .ok_or_else(|| "wallet not initialized".to_string())?;
        let owner = w.preview_generated_index(index).map_err(str::to_string)?;
        Ok(WalletActivationPreview {
            expected_active_index: w.active_index,
            expected_next_index: w.next_index,
            target_index: index,
            owner: owner.0,
        })
    }

    fn create_next_address(&self) -> Result<WalletAddressInfo, String> {
        let mut guard = self.inner.lock().unwrap();
        let w = guard
            .as_mut()
            .ok_or_else(|| "wallet not initialized".to_string())?;
        let (key_index, address) = w.create_next_inactive_address()?;
        Ok(WalletAddressInfo {
            address: address.to_bech32(),
            key_index,
            is_active: false,
        })
    }

    fn preview_address_discovery(
        &self,
        max_additional: u32,
    ) -> Result<WalletAddressDiscoveryPreview, String> {
        let guard = self.inner.lock().unwrap();
        let w = guard
            .as_ref()
            .ok_or_else(|| "wallet not initialized".to_string())?;
        if w.has_pending_activity() {
            return Err("cannot discover addresses while a wallet transaction is pending".into());
        }
        let end = w
            .next_index
            .saturating_add(max_additional)
            .min(state::MAX_WALLET_ADDRESSES);
        let candidates = (w.next_index..end)
            .map(|index| (index, w.address_at(index).0))
            .collect();
        Ok(WalletAddressDiscoveryPreview {
            expected_active_index: w.active_index,
            expected_next_index: w.next_index,
            candidates,
        })
    }

    fn commit_address_discovery(
        &self,
        expected_active_index: u32,
        expected_next_index: u32,
        discovered_next_index: u32,
    ) -> Result<Vec<WalletAddressInfo>, String> {
        let mut guard = self.inner.lock().unwrap();
        let w = guard
            .as_mut()
            .ok_or_else(|| "wallet not initialized".to_string())?;
        w.commit_discovered_next_index(
            expected_active_index,
            expected_next_index,
            discovered_next_index,
        )?;
        Ok((0..w.next_index)
            .map(|index| WalletAddressInfo {
                address: w.address_at(index).to_bech32(),
                key_index: index,
                is_active: index == w.active_index,
            })
            .collect())
    }

    fn commit_activation_snapshot(
        &self,
        preview: WalletActivationPreview,
        snapshot: VerifiedOwnerSnapshot,
        reserved_input_slots: &std::collections::HashSet<u32>,
        reserved_output_slots: &std::collections::HashSet<u32>,
    ) -> Result<(WalletAddressInfo, WalletScanResult), String> {
        let found = snapshot.utxos.len();
        let balance = snapshot
            .utxos
            .iter()
            .map(|utxo| utxo.amount)
            .fold(0u64, u64::saturating_add);
        let snapshot_height = snapshot.height;
        let snapshot_tip_hash = hex::encode(snapshot.tip_hash);
        let snapshot_state_root = hex::encode(snapshot.state_root);
        let mut guard = self.inner.lock().unwrap();
        let w = guard
            .as_mut()
            .ok_or_else(|| "wallet not initialized".to_string())?;
        w.commit_verified_activation(
            preview.expected_active_index,
            preview.expected_next_index,
            preview.target_index,
            preview.owner,
            snapshot,
            reserved_input_slots,
            reserved_output_slots,
        )?;

        let address_info = WalletAddressInfo {
            address: w.active_address().to_bech32(),
            key_index: preview.target_index,
            is_active: true,
        };
        let scan_result = WalletScanResult {
            found_utxos: found,
            balance_micronoid: balance,
            balance_noid: micronoid_to_noid(balance),
            active_index: w.active_index,
            snapshot_height,
            snapshot_tip_hash,
            snapshot_state_root,
        };
        Ok((address_info, scan_result))
    }

    fn on_accepted_block(&self, block: &noid_chain::block::Block) -> Result<(), String> {
        update_for_accepted_block(&self.inner, block)
    }

    fn plan_send(
        &self,
        amount_micronoid: u64,
        explicit_fee_micronoid: Option<u64>,
        active_slot_count: u64,
        log_slots: u32,
        relay_floor: u64,
    ) -> Result<WalletSendPlan, WalletSendPlanError> {
        if amount_micronoid == 0 {
            return Err(WalletSendPlanError::Other(
                "amount cannot be zero".to_string(),
            ));
        }

        let guard = self.inner.lock().unwrap();
        let wallet = guard
            .as_ref()
            .ok_or_else(|| WalletSendPlanError::Other("wallet not initialized".to_string()))?;
        let mut available: Vec<&state::WalletUtxo> = wallet
            .utxos
            .values()
            .filter(|utxo| utxo.key_index == wallet.active_index)
            .filter(|utxo| !wallet.pending_input_slots.contains(&utxo.slot_index))
            .collect();
        available.sort_by_key(|utxo| {
            (
                std::cmp::Reverse(utxo.value),
                utxo.slot_index >> noid_chain::consensus::params::LOG_SEGMENT_SIZE,
                utxo.slot_index,
            )
        });
        let spendable = available
            .iter()
            .map(|utxo| utxo.value)
            .try_fold(0u64, u64::checked_add)
            .ok_or_else(|| {
                WalletSendPlanError::Other("wallet balance arithmetic overflow".to_string())
            })?;

        // Reject an impossible balance before shape selection using the
        // cheapest legal transaction as the lower bound. The exact fee is
        // still computed below from the selected transaction's real I/O.
        let one_input_one_output =
            noid_chain::consensus::fee_breakdown(1, 1, active_slot_count, log_slots);
        let one_input_one_output_minimum = one_input_one_output.required_total.max(relay_floor);
        if let Some(fee) = explicit_fee_micronoid {
            if fee < one_input_one_output_minimum {
                return Err(WalletSendPlanError::Other(format!(
                    "fee too low for transaction with 1 input and 1 output: required {one_input_one_output_minimum} μNOID, got {fee} μNOID"
                )));
            }
        }
        let minimum_fee = explicit_fee_micronoid.unwrap_or(one_input_one_output_minimum);
        let minimum_total = amount_micronoid.checked_add(minimum_fee).ok_or_else(|| {
            WalletSendPlanError::Other("payment amount plus fee overflows u64".to_string())
        })?;
        if spendable < minimum_total {
            return Err(WalletSendPlanError::InsufficientFunds {
                needed_micronoid: minimum_total,
                available_micronoid: spendable,
            });
        }

        let mut selected_value = 0u64;
        let mut planned = explicit_fee_micronoid.and_then(|fee| {
            available
                .iter()
                .find(|utxo| utxo.value == minimum_total)
                .map(|_| (1, fee, 1, 0, one_input_one_output))
        });
        for input_count in 1..=MAX_PAGED_SPEND_INPUTS {
            if planned.is_some() {
                break;
            }
            let Some(utxo) = available.get(input_count - 1) else {
                break;
            };
            selected_value = selected_value.checked_add(utxo.value).ok_or_else(|| {
                WalletSendPlanError::Other("wallet balance arithmetic overflow".to_string())
            })?;

            if let Some(fee) = explicit_fee_micronoid {
                if selected_value < minimum_total {
                    continue;
                }
                let change = selected_value - minimum_total;
                let output_count = 1 + usize::from(change > 0);
                let breakdown = noid_chain::consensus::fee_breakdown(
                    input_count as u64,
                    output_count as u64,
                    active_slot_count,
                    log_slots,
                );
                let minimum = breakdown.required_total.max(relay_floor);
                if fee < minimum {
                    return Err(WalletSendPlanError::Other(format!(
                        "fee too low for transaction with {input_count} input(s) and {output_count} output(s): required {minimum} μNOID, got {fee} μNOID"
                    )));
                }
                planned = Some((input_count, fee, output_count, change, breakdown));
                break;
            }

            let one_output_breakdown = noid_chain::consensus::fee_breakdown(
                input_count as u64,
                1,
                active_slot_count,
                log_slots,
            );
            let one_output_fee = one_output_breakdown.required_total.max(relay_floor);
            if selected_value > amount_micronoid {
                let two_output_breakdown = noid_chain::consensus::fee_breakdown(
                    input_count as u64,
                    2,
                    active_slot_count,
                    log_slots,
                );
                let two_output_fee = two_output_breakdown.required_total.max(relay_floor);
                let two_output_need =
                    amount_micronoid
                        .checked_add(two_output_fee)
                        .ok_or_else(|| {
                            WalletSendPlanError::Other(
                                "payment amount plus fee overflows u64".to_string(),
                            )
                        })?;
                if selected_value > two_output_need {
                    planned = Some((
                        input_count,
                        two_output_fee,
                        2,
                        selected_value - two_output_need,
                        two_output_breakdown,
                    ));
                    break;
                }
            }
            if selected_value >= amount_micronoid {
                let no_change_fee = selected_value - amount_micronoid;
                if no_change_fee >= one_output_fee {
                    planned = Some((input_count, no_change_fee, 1, 0, one_output_breakdown));
                    break;
                }
            }
        }

        let Some((_, fee_micronoid, _, _, _)) = planned else {
            if available.len() > MAX_PAGED_SPEND_INPUTS {
                return Err(WalletSendPlanError::InputLimitExceeded {
                    max_inputs: MAX_PAGED_SPEND_INPUTS,
                });
            }
            return Err(WalletSendPlanError::InsufficientFunds {
                needed_micronoid: minimum_total,
                available_micronoid: spendable,
            });
        };
        // Re-run the shared exact-single-before-greedy selector with the final
        // fee. This is cheap and guarantees that dry-run counts cannot diverge
        // from the builder's selected shape.
        let Some((selected, change_micronoid)) =
            wallet.select_utxos(amount_micronoid, fee_micronoid)
        else {
            if available.len() > MAX_PAGED_SPEND_INPUTS {
                return Err(WalletSendPlanError::InputLimitExceeded {
                    max_inputs: MAX_PAGED_SPEND_INPUTS,
                });
            }
            return Err(WalletSendPlanError::InsufficientFunds {
                needed_micronoid: amount_micronoid.saturating_add(fee_micronoid),
                available_micronoid: spendable,
            });
        };
        let input_count = selected.len();
        let output_count = 1 + usize::from(change_micronoid > 0);
        let breakdown = noid_chain::consensus::fee_breakdown(
            input_count as u64,
            output_count as u64,
            active_slot_count,
            log_slots,
        );
        let minimum = breakdown.required_total.max(relay_floor);
        if fee_micronoid < minimum {
            return Err(WalletSendPlanError::Other(format!(
                "fee too low for selected transaction with {input_count} input(s) and {output_count} output(s): required {minimum} μNOID, got {fee_micronoid} μNOID"
            )));
        }
        let total_spend_micronoid =
            amount_micronoid.checked_add(fee_micronoid).ok_or_else(|| {
                WalletSendPlanError::Other("payment amount plus fee overflows u64".to_string())
            })?;
        Ok(WalletSendPlan {
            amount_micronoid,
            fee_micronoid,
            total_spend_micronoid,
            input_count,
            output_count,
            change_micronoid,
            fee_breakdown: fee_breakdown_info(breakdown, relay_floor, fee_micronoid),
        })
    }
    fn build_send(
        &self,
        to_address: [u8; 32],
        amount_micronoid: u64,
        fee_micronoid: u64,
        epoch_anchor: [u8; 32],
        slot_hints: Vec<u32>,
        log_slots: u32,
    ) -> Result<(Vec<u8>, Vec<u32>), String> {
        // Extract build data from wallet (brief lock).
        // Snapshot pending_output_slots (avoid output reuse). Input slots are
        // returned to the coordinator for reserve-before-admit handling.
        let (build_data, input_slots) = {
            let guard = self.inner.lock().unwrap();
            let w = guard
                .as_ref()
                .ok_or_else(|| "wallet not initialized".to_string())?;
            let pending_outputs = w.pending_output_slots.clone();
            let data = builder::extract_build_data(
                w,
                amount_micronoid,
                fee_micronoid,
                epoch_anchor,
                slot_hints,
                log_slots,
                &pending_outputs,
            )
            .map_err(|e| e.to_string())?;
            // Capture input slots BEFORE build_data is moved into the prover.
            let inputs: Vec<u32> = data.selected_utxos.iter().map(|u| u.slot_index).collect();
            (data, inputs)
        };

        // Prove outside the lock (CPU-heavy, ~0.3–3 s).
        let (_txid, intent_bytes) =
            builder::build_and_prove_tx(to_address, amount_micronoid, fee_micronoid, build_data)
                .map_err(|e| e.to_string())?;

        Ok((intent_bytes, input_slots))
    }

    fn plan_consolidation(
        &self,
        max_inputs: usize,
        active_slot_count: u64,
        log_slots: u32,
        relay_floor: u64,
    ) -> Result<WalletConsolidationPlan, WalletSendPlanError> {
        if !(2..=WALLET_CONSOLIDATION_INPUT_LIMIT).contains(&max_inputs) {
            return Err(WalletSendPlanError::Other(format!(
                "consolidation input limit must be within 2..={WALLET_CONSOLIDATION_INPUT_LIMIT}"
            )));
        }

        let guard = self.inner.lock().unwrap();
        let wallet = guard
            .as_ref()
            .ok_or_else(|| WalletSendPlanError::Other("wallet not initialized".to_string()))?;
        if !wallet.pending_input_slots.is_empty() || !wallet.pending_output_slots.is_empty() {
            return Err(WalletSendPlanError::Other(
                "wallet has a pending transaction".to_string(),
            ));
        }

        let mut available: Vec<&state::WalletUtxo> = wallet
            .utxos
            .values()
            .filter(|utxo| utxo.key_index == wallet.active_index)
            .collect();
        available.sort_by_key(|utxo| {
            (
                utxo.value,
                utxo.slot_index >> noid_chain::consensus::params::LOG_SEGMENT_SIZE,
                utxo.slot_index,
            )
        });
        if available.len() < 2 {
            return Err(WalletSendPlanError::Other(
                "consolidation requires at least two spendable UTXOs".to_string(),
            ));
        }

        let balance_before_micronoid = available
            .iter()
            .map(|utxo| utxo.value)
            .try_fold(0u64, u64::checked_add)
            .ok_or_else(|| {
                WalletSendPlanError::Other("wallet balance arithmetic overflow".to_string())
            })?;
        let input_count = available.len().min(max_inputs);
        let selected = &available[..input_count];
        let input_value_micronoid = selected
            .iter()
            .map(|utxo| utxo.value)
            .try_fold(0u64, u64::checked_add)
            .ok_or_else(|| {
                WalletSendPlanError::Other("wallet balance arithmetic overflow".to_string())
            })?;
        let breakdown = noid_chain::consensus::fee_breakdown(
            input_count as u64,
            1,
            active_slot_count,
            log_slots,
        );
        let fee_micronoid = breakdown.required_total.max(relay_floor);
        let Some(output_value_micronoid) = input_value_micronoid.checked_sub(fee_micronoid) else {
            return Err(WalletSendPlanError::InsufficientFunds {
                needed_micronoid: fee_micronoid.saturating_add(1),
                available_micronoid: input_value_micronoid,
            });
        };
        if output_value_micronoid == 0 {
            return Err(WalletSendPlanError::InsufficientFunds {
                needed_micronoid: fee_micronoid.saturating_add(1),
                available_micronoid: input_value_micronoid,
            });
        }

        let untouched_count = available.len() - input_count;
        Ok(WalletConsolidationPlan {
            input_value_micronoid,
            fee_micronoid,
            output_value_micronoid,
            balance_before_micronoid,
            balance_after_micronoid: balance_before_micronoid - fee_micronoid,
            input_count,
            untouched_count,
            remaining_count: untouched_count + 1,
            freed_slots: input_count - 1,
            selected_input_slots: selected.iter().map(|utxo| utxo.slot_index).collect(),
            fee_breakdown: fee_breakdown_info(breakdown, relay_floor, fee_micronoid),
        })
    }

    fn build_consolidation(
        &self,
        selected_input_slots: Vec<u32>,
        output_value_micronoid: u64,
        fee_micronoid: u64,
        epoch_anchor: [u8; 32],
        slot_hints: Vec<u32>,
        _log_slots: u32,
    ) -> Result<(Vec<u8>, Vec<u32>), String> {
        let (build_data, active_address) = {
            let guard = self.inner.lock().unwrap();
            let wallet = guard
                .as_ref()
                .ok_or_else(|| "wallet not initialized".to_string())?;
            let pending_outputs = wallet.pending_output_slots.clone();
            let data = builder::extract_consolidation_build_data(
                wallet,
                &selected_input_slots,
                output_value_micronoid,
                fee_micronoid,
                epoch_anchor,
                slot_hints,
                &pending_outputs,
            )
            .map_err(|error| error.to_string())?;
            (data, wallet.active_address().0)
        };

        let (_txid, intent_bytes) = builder::build_and_prove_tx(
            active_address,
            output_value_micronoid,
            fee_micronoid,
            build_data,
        )
        .map_err(|error| error.to_string())?;
        Ok((intent_bytes, selected_input_slots))
    }

    fn reserve_pending_submission(
        &self,
        txid: [u8; 32],
        input_slots: &[u32],
        output_slots: &[u32],
        amount_micronoid: u64,
        peer_address: [u8; 32],
    ) -> Result<(), String> {
        let mut guard = self.inner.lock().unwrap();
        let wallet = guard
            .as_mut()
            .ok_or_else(|| "wallet not initialized".to_string())?;
        wallet.add_pending_inputs(input_slots);
        wallet.add_pending_outputs(output_slots);
        wallet.record_pending_send(txid, amount_micronoid, peer_address)?;
        Ok(())
    }

    fn rollback_pending_submission(
        &self,
        txid: [u8; 32],
        input_slots: &[u32],
        output_slots: &[u32],
    ) {
        let mut guard = self.inner.lock().unwrap();
        if let Some(wallet) = guard.as_mut() {
            wallet.remove_pending_inputs(input_slots);
            wallet.remove_pending_outputs(output_slots);
            if let Err(error) = wallet.remove_pending_send(&txid) {
                tracing::error!(%error, "failed to durably roll back pending wallet send");
            }
        }
    }

    fn active_address(&self) -> Option<(u32, String)> {
        let guard = self.inner.lock().unwrap();
        guard
            .as_ref()
            .map(|w| (w.active_index, w.active_address().to_bech32()))
    }

    fn list_addresses(&self) -> Vec<WalletAddressInfo> {
        let guard = self.inner.lock().unwrap();
        let w = match &*guard {
            None => return vec![],
            Some(w) => w,
        };

        (0..w.next_index)
            .map(|idx| {
                let addr = w.address_at(idx);
                WalletAddressInfo {
                    address: addr.to_bech32(),
                    key_index: idx,
                    is_active: idx == w.active_index,
                }
            })
            .collect()
    }

    fn pending_outbound(&self) -> u64 {
        let guard = self.inner.lock().unwrap();
        match &*guard {
            None => 0,
            Some(w) => w
                .pending_input_slots
                .iter()
                .filter_map(|&s| w.utxos.get(&s))
                .filter(|u| u.key_index == w.active_index)
                .map(|u| u.value)
                .sum(),
        }
    }

    fn export_receipt(&self, txhash_hex: &str) -> Result<String, String> {
        let tx_hash: [u8; 32] = hex::decode(txhash_hex)
            .map_err(|e| format!("invalid hex: {e}"))?
            .try_into()
            .map_err(|_| "tx_hash must be 32 bytes".to_string())?;

        let guard = self.inner.lock().unwrap();
        let w = guard
            .as_ref()
            .ok_or_else(|| "wallet not initialized".to_string())?;

        match w.get_receipt(&tx_hash) {
            Some(bytes) => {
                let receipt = noid_chain::consensus::receipt::ParanoidReceipt::from_bytes(bytes)
                    .map_err(|error| format!("decode durable receipt: {error}"))?;
                let has_recipient =
                    receipt
                        .summary
                        .inputs
                        .first()
                        .is_some_and(|(_, input_owner)| {
                            receipt
                                .summary
                                .outputs
                                .iter()
                                .any(|(_, _, owner)| owner != input_owner)
                        });
                if !has_recipient {
                    return Err(
                        "same-owner consolidations do not create payment receipts".to_string()
                    );
                }
                Ok(hex::encode(bytes))
            }
            None => {
                let is_same_owner_consolidation = w.history.iter().any(|entry| {
                    entry.tx_hash == tx_hash
                        && entry.direction == state::TxDirection::Sent
                        && entry.peer_address.is_some_and(|peer| {
                            entry.own_address.as_deref().is_some_and(|own| {
                                noid_poseidon2b::primitives::Address(peer).to_bech32() == own
                            })
                        })
                });
                if is_same_owner_consolidation {
                    Err("same-owner consolidations do not create payment receipts".to_string())
                } else {
                    Err(format!(
                        "no receipt for {txhash_hex} — block already pruned or tx not found"
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    fn handle_with_utxos(values: &[u64]) -> (TempDir, WalletHandle) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wallet.key");
        let mut wallet = WalletState::create_or_load(path).unwrap();
        for (i, value) in values.iter().copied().enumerate() {
            let slot_index = i as u32;
            wallet.utxos.insert(
                slot_index,
                state::WalletUtxo {
                    slot_index,
                    value,
                    creation_id: slot_index as u64 + 1,
                    // One owner per tx: fixture UTXOs live on the ACTIVE
                    // (index-0) address.
                    address: wallet.address_at(0),
                    key_index: 0,
                    confirmed_height: 1,
                },
            );
        }
        let handle = WalletHandle {
            inner: Arc::new(Mutex::new(Some(wallet))),
        };
        (dir, handle)
    }

    fn empty_snapshot(owner: [u8; 32]) -> VerifiedOwnerSnapshot {
        VerifiedOwnerSnapshot {
            owner,
            height: 2,
            tip_hash: [0x11; 32],
            state_root: [0x22; 32],
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
            utxos: vec![],
        }
    }

    fn valid_outgoing_receipt(
        owner: noid_poseidon2b::primitives::Address,
        height: u64,
    ) -> ([u8; 32], Vec<u8>) {
        use noid_chain::block_header::BlockHeader;
        use noid_chain::consensus::receipt::generate_receipt;
        use noid_poseidon2b::primitives::Address;
        use noid_tx::{
            PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT, TX_INPUTS, TX_OUTPUTS, Transaction, TxBody,
            TxInput, TxOutput, output_bitmap_bit,
        };

        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 7,
            amount: 50,
            creation_id: 3,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 9,
            amount: 40,
            owner: Address([0xA5; 32]),
        };
        let transaction = Transaction::new(TxBody {
            epoch_anchor: [0x11; 32],
            fee: 10,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0) | PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        });
        let coinbase = Transaction::new(TxBody {
            epoch_anchor: [0; 32],
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: [TxOutput::dummy(); TX_OUTPUTS],
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        });
        let transactions = vec![coinbase, transaction];
        let logical_txids = noid_chain::try_compute_logical_txids(&transactions).unwrap();
        let logical_hashes = logical_txids.iter().map(|txid| txid.0).collect::<Vec<_>>();
        let header = BlockHeader {
            prev_block_hash: [0; 32],
            state_root: [0; 32],
            tx_root: noid_chain::consensus::receipt::tx_root(&logical_hashes),
            timestamp: 123 + height,
            height,
            miner_address: Address([0x77; 32]),
            nonce: 0,
            difficulty_target: [0xFF; 32],
            log_slots: 24,
            active_slot_count: 1,
            alloc_counter: 1,
        };
        let receipt = generate_receipt(&header, &transactions[1..], 1, &logical_hashes);
        (logical_hashes[1], receipt.to_bytes())
    }

    #[test]
    fn startup_reconciliation_keeps_valid_receipt_until_header_arrives() {
        let wallet_dir = TempDir::new().unwrap();
        let chain_dir = TempDir::new().unwrap();
        let wallet_path = wallet_dir.path().join("wallet.key");
        let mut wallet = WalletState::create_or_load(wallet_path.clone()).unwrap();
        let (tx_hash, receipt) = valid_outgoing_receipt(wallet.active_address(), 7);
        wallet.receipts.insert(tx_hash, receipt.clone());
        wallet.save_receipts().unwrap();

        let chain =
            noid_chain::storage::MdbxChainContext::open_or_create(chain_dir.path()).unwrap();
        assert_eq!(chain.tip_height(), 0);
        assert_eq!(
            reconcile_receipts_at_startup(&mut wallet, &chain).unwrap(),
            (0, 0)
        );
        assert_eq!(wallet.receipts.get(&tx_hash), Some(&receipt));
        drop(wallet);

        let reloaded = WalletState::create_or_load(wallet_path).unwrap();
        assert_eq!(reloaded.receipts.get(&tx_hash), Some(&receipt));
    }

    #[test]
    fn startup_reconciliation_removes_receipt_contradicted_by_known_header() {
        let wallet_dir = TempDir::new().unwrap();
        let chain_dir = TempDir::new().unwrap();
        let wallet_path = wallet_dir.path().join("wallet.key");
        let mut wallet = WalletState::create_or_load(wallet_path.clone()).unwrap();
        let (tx_hash, receipt) = valid_outgoing_receipt(wallet.active_address(), 0);
        wallet.receipts.insert(tx_hash, receipt);
        wallet.save_receipts().unwrap();

        let chain =
            noid_chain::storage::MdbxChainContext::open_or_create(chain_dir.path()).unwrap();
        assert_eq!(
            reconcile_receipts_at_startup(&mut wallet, &chain).unwrap(),
            (1, 0)
        );
        assert!(!wallet.receipts.contains_key(&tx_hash));
        drop(wallet);

        let reloaded = WalletState::create_or_load(wallet_path).unwrap();
        assert!(!reloaded.receipts.contains_key(&tx_hash));
    }

    #[test]
    fn retained_body_rebuilds_missing_outgoing_receipt_without_history_marker() {
        use noid_chain::block_header::BlockHeader;
        use noid_chain::consensus::receipt::{
            verify_against_header, verify_merkle_inclusion, ParanoidReceipt,
        };
        use noid_poseidon2b::primitives::Address;
        use noid_tx::{
            output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, PAGED_SPEND_END_BIT,
            PAGED_SPEND_START_BIT, TX_INPUTS, TX_OUTPUTS,
        };

        let (dir, handle) = handle_with_utxos(&[]);
        let mut guard = handle.inner.lock().unwrap();
        let wallet = guard.as_mut().unwrap();
        let owner = wallet.active_address();
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 7,
            amount: 50,
            creation_id: 3,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 9,
            amount: 40,
            owner: Address([0xA5; 32]),
        };
        let transaction = Transaction::new(TxBody {
            epoch_anchor: [0x11; 32],
            fee: 10,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0) | PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        });
        let coinbase = Transaction::new(TxBody {
            epoch_anchor: [0; 32],
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: [TxOutput::dummy(); TX_OUTPUTS],
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        });
        let transactions = vec![coinbase, transaction];
        let header = BlockHeader {
            prev_block_hash: [0; 32],
            state_root: [0; 32],
            tx_root: noid_chain::block::compute_tx_root(&transactions),
            timestamp: 123,
            height: 7,
            miner_address: Address([0x77; 32]),
            nonce: 0,
            difficulty_target: [0xFF; 32],
            log_slots: 24,
            active_slot_count: 1,
            alloc_counter: 1,
        };
        let block = noid_chain::block::Block {
            header,
            transactions,
        };
        let owned = std::collections::HashSet::from([owner.0]);
        let (recovered, history_changed) = recover_outgoing_receipts_from_block(
            wallet,
            &owned,
            &std::collections::HashSet::new(),
            &block,
        );
        assert_eq!(recovered, 1);
        assert!(!history_changed);
        let tx_hash = noid_chain::try_compute_logical_txids(&block.transactions).unwrap()[1].0;
        let receipt = ParanoidReceipt::from_bytes(&wallet.receipts[&tx_hash]).unwrap();
        assert!(verify_merkle_inclusion(&receipt));
        assert!(verify_against_header(&receipt, &block.header));

        let (recovered_again, _) = recover_outgoing_receipts_from_block(
            wallet,
            &owned,
            &std::collections::HashSet::new(),
            &block,
        );
        assert_eq!(recovered_again, 0);
        drop(guard);
        drop(dir);
    }

    #[test]
    fn planner_accepts_a_payment_that_needs_multiple_pages() {
        let (_dir, handle) = handle_with_utxos(&[10_000; 20]);
        let plan = handle
            .plan_send(150_000, Some(10_000), 0, 24, 0)
            .expect("16-input PagedSpend plan");
        assert_eq!(plan.input_count, 16);
        assert_eq!(plan.output_count, 1);
        let guard = handle.inner.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        assert!(wallet.pending_input_slots.is_empty());
        assert!(wallet.pending_output_slots.is_empty());
        assert!(wallet.history.is_empty());
    }

    #[test]
    fn automatic_fee_path_selects_more_than_one_physical_page() {
        let (_dir, handle) = handle_with_utxos(&[1_000; 20]);
        let plan = handle
            .plan_send(10_000, None, 0, 24, 0)
            .expect("automatic multi-page plan");
        assert!(plan.input_count > noid_tx::TX_INPUTS);
        assert!(plan.input_count <= MAX_PAGED_SPEND_INPUTS);
    }

    #[test]
    fn planner_reports_the_real_paged_spend_input_limit() {
        let values = vec![10_000; MAX_PAGED_SPEND_INPUTS + 1];
        let (_dir, handle) = handle_with_utxos(&values);
        let error = handle
            .plan_send(10_110_000, Some(100_000), 0, 24, 0)
            .unwrap_err();
        assert_eq!(
            error,
            WalletSendPlanError::InputLimitExceeded {
                max_inputs: MAX_PAGED_SPEND_INPUTS,
            }
        );
    }

    #[test]
    fn consolidation_below_limit_merges_every_spendable_utxo() {
        let values: Vec<u64> = (0..63).map(|index| 100_000 + index * 1_000).collect();
        let expected_balance: u64 = values.iter().sum();
        let (_dir, handle) = handle_with_utxos(&values);
        let plan = handle
            .plan_consolidation(WALLET_CONSOLIDATION_INPUT_LIMIT, 0, 24, 0)
            .unwrap();

        assert_eq!(plan.input_count, 63);
        assert_eq!(plan.untouched_count, 0);
        assert_eq!(plan.remaining_count, 1);
        assert_eq!(plan.freed_slots, 62);
        assert_eq!(plan.selected_input_slots, (0..63).collect::<Vec<_>>());
        assert_eq!(plan.input_value_micronoid, expected_balance);
        assert_eq!(
            plan.output_value_micronoid + plan.fee_micronoid,
            expected_balance
        );
        assert_eq!(
            plan.balance_after_micronoid,
            expected_balance - plan.fee_micronoid
        );
    }

    #[test]
    fn consolidation_above_limit_selects_exactly_the_64_smallest_utxos() {
        let values: Vec<u64> = (0..65)
            .map(|index| 100_000 + (64 - index) * 1_000)
            .collect();
        let expected_selected_slots: Vec<u32> = (1..65).rev().collect();
        let expected_input_value: u64 = expected_selected_slots
            .iter()
            .map(|slot| values[*slot as usize])
            .sum();
        let expected_balance: u64 = values.iter().sum();
        let (_dir, handle) = handle_with_utxos(&values);
        let plan = handle
            .plan_consolidation(WALLET_CONSOLIDATION_INPUT_LIMIT, 0, 24, 0)
            .unwrap();

        assert_eq!(plan.input_count, WALLET_CONSOLIDATION_INPUT_LIMIT);
        assert_eq!(plan.untouched_count, 1);
        assert_eq!(plan.remaining_count, 2);
        assert_eq!(plan.freed_slots, 63);
        assert_eq!(plan.selected_input_slots, expected_selected_slots);
        assert_eq!(plan.input_value_micronoid, expected_input_value);
        assert_eq!(plan.balance_before_micronoid, expected_balance);
        assert_eq!(
            plan.balance_after_micronoid,
            expected_balance - plan.fee_micronoid
        );
    }

    #[test]
    fn explicit_fee_below_one_by_one_minimum_is_rejected_before_selection() {
        let (_dir, handle) = handle_with_utxos(&[1_000; 20]);
        let error = handle.plan_send(10_000, Some(1), 0, 24, 0).unwrap_err();
        assert_eq!(
            error,
            WalletSendPlanError::Other(
                "fee too low for transaction with 1 input and 1 output: required 5800 μNOID, got 1 μNOID"
                    .to_string()
            )
        );
    }

    #[test]
    fn explicit_fee_prefers_exact_single_before_greedy_change() {
        let (_dir, handle) = handle_with_utxos(&[100_000, 95_800]);
        let plan = handle.plan_send(90_000, Some(5_800), 0, 24, 0).unwrap();
        assert_eq!(plan.input_count, 1);
        assert_eq!(plan.output_count, 1);
        assert_eq!(plan.change_micronoid, 0);
        assert_eq!(plan.fee_micronoid, 5_800);

        let guard = handle.inner.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        let (selected, change) = wallet.select_utxos(90_000, 5_800).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, 95_800);
        assert_eq!(change, 0);
    }

    #[test]
    fn building_is_side_effect_free_until_pending_reservation_is_installed() {
        let (_dir, handle) = handle_with_utxos(&[100_000]);
        let (intent_bytes, input_slots) = handle
            .build_send(
                [0xA7; 32],
                50_000,
                9_000,
                [0x11; 32],
                vec![10_000, 10_001],
                24,
            )
            .expect("build ordinary send");
        let intent =
            noid_tx::PagedSpendIntent::from_bytes(&intent_bytes).expect("decode built intent");
        let txid = intent.logical_txid().0;
        let output_slots: Vec<u32> = intent
            .pages
            .iter()
            .flat_map(|page| page.body.live_outputs())
            .map(|(_, output)| output.slot_index)
            .collect();

        {
            let guard = handle.inner.lock().unwrap();
            let wallet = guard.as_ref().unwrap();
            assert!(wallet.pending_input_slots.is_empty());
            assert!(wallet.pending_output_slots.is_empty());
            assert!(wallet.history.is_empty());
        }

        handle
            .reserve_pending_submission(txid, &input_slots, &output_slots, 50_000, [0xA7; 32])
            .expect("install pending reservation");
        {
            let guard = handle.inner.lock().unwrap();
            let wallet = guard.as_ref().unwrap();
            assert_eq!(wallet.pending_input_slots.len(), input_slots.len());
            assert_eq!(wallet.pending_output_slots.len(), output_slots.len());
            assert_eq!(wallet.history.len(), 1);
            assert_eq!(wallet.history[0].tx_hash, txid);
        }

        handle.rollback_pending_submission(txid, &input_slots, &output_slots);
        let guard = handle.inner.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        assert!(wallet.pending_input_slots.is_empty());
        assert!(wallet.pending_output_slots.is_empty());
        assert!(wallet.history.is_empty());
    }

    #[test]
    fn planner_excludes_pending_inputs_from_spendable_balance() {
        let (_dir, handle) = handle_with_utxos(&[10_000, 1_000, 1_000, 1_000, 1_000]);
        {
            let mut guard = handle.inner.lock().unwrap();
            guard.as_mut().unwrap().pending_input_slots.insert(0);
        }
        let err = handle.plan_send(9_000, Some(6_000), 0, 24, 0).unwrap_err();
        assert_eq!(
            err,
            WalletSendPlanError::InsufficientFunds {
                needed_micronoid: 15_000,
                available_micronoid: 4_000,
            }
        );
    }

    #[test]
    fn status_and_pending_balance_cover_cached_active_utxos_only() {
        let (_dir, handle) = handle_with_utxos(&[2_000, 2_000]);
        {
            let mut guard = handle.inner.lock().unwrap();
            let wallet = guard.as_mut().unwrap();
            wallet.pending_input_slots.insert(0);
        }

        assert!(handle.plan_send(3_000, None, 0, 24, 0).is_err());
        let balance = handle.get_balance();
        assert_eq!(balance.balance_micronoid, 4_000);
        assert_eq!(balance.pending_outbound_micronoid, 2_000);
        assert_eq!(balance.spendable_micronoid, 2_000);
        assert_eq!(handle.status().utxo_count, 2);
    }

    #[test]
    fn export_receipt_identifies_same_owner_consolidation_without_cached_receipt() {
        let (_dir, handle) = handle_with_utxos(&[2_000, 2_000]);
        let tx_hash = [0xA5; 32];
        {
            let mut guard = handle.inner.lock().unwrap();
            let wallet = guard.as_mut().unwrap();
            let active = wallet.active_address();
            wallet.history.push(state::TxHistoryEntry {
                tx_hash,
                block_hash: None,
                height: 7,
                direction: state::TxDirection::Sent,
                is_coinbase: false,
                amount_micronoid: 100,
                peer_address: Some(active.0),
                timestamp: 8,
                own_address: Some(active.to_bech32()),
                own_key_index: Some(wallet.active_index),
            });
        }

        assert_eq!(
            handle.export_receipt(&hex::encode(tx_hash)).unwrap_err(),
            "same-owner consolidations do not create payment receipts"
        );
    }

    #[test]
    fn rpc_history_exposes_only_the_active_account() {
        let (_dir, handle) = handle_with_utxos(&[1_000]);
        {
            let mut guard = handle.inner.lock().unwrap();
            let wallet = guard.as_mut().unwrap();
            wallet.record_pending_send([1; 32], 10, [2; 32]).unwrap();
            wallet.history.push(state::TxHistoryEntry {
                tx_hash: [3; 32],
                block_hash: None,
                height: 7,
                direction: state::TxDirection::Received,
                is_coinbase: false,
                amount_micronoid: 20,
                peer_address: None,
                timestamp: 8,
                own_address: Some(wallet.address_at(1).to_bech32()),
                own_key_index: Some(1),
            });
        }

        let history = handle.history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].own_key_index, Some(0));
    }

    #[test]
    fn mined_block_slice_spans_addresses_and_is_newest_first() {
        let (_dir, handle) = handle_with_utxos(&[1_000]);
        {
            let mut guard = handle.inner.lock().unwrap();
            let wallet = guard.as_mut().unwrap();
            for (height, key_index, is_coinbase) in [(3, 0, true), (5, 1, false), (7, 2, true)] {
                wallet.history.push(state::TxHistoryEntry {
                    tx_hash: [height as u8; 32],
                    block_hash: None,
                    height,
                    direction: state::TxDirection::Received,
                    is_coinbase,
                    amount_micronoid: height * 1_000,
                    peer_address: None,
                    timestamp: height + 100,
                    own_address: Some(wallet.address_at(key_index).to_bech32()),
                    own_key_index: Some(key_index),
                });
            }
        }

        let newest = handle.mined_blocks(0, 1);
        assert_eq!(newest.total, 2);
        assert_eq!(newest.blocks.len(), 1);
        assert_eq!(newest.blocks[0].height, 7);
        assert_eq!(newest.blocks[0].payout_key_index, 2);

        let older = handle.mined_blocks(1, 1);
        assert_eq!(older.total, 2);
        assert_eq!(older.blocks[0].height, 3);
        assert_eq!(older.blocks[0].payout_key_index, 0);
    }

    #[test]
    fn rpc_wallet_handle_rejects_max_active_index_without_mutation() {
        let (_dir, handle) = handle_with_utxos(&[1_000]);
        let error = handle
            .preview_address_switch(MAX_WALLET_ADDRESSES)
            .unwrap_err();
        assert!(error.contains("has not been generated"));
        let (index, _) = handle.active_address().unwrap();
        assert_eq!(index, 0);
    }

    #[test]
    fn address_derivation_stops_at_shared_wallet_cap() {
        let (_dir, handle) = handle_with_utxos(&[1_000]);
        {
            let mut guard = handle.inner.lock().unwrap();
            guard.as_mut().unwrap().next_index = MAX_WALLET_ADDRESSES;
        }

        assert!(handle.create_next_address().is_err());
        assert!(handle.get_address(MAX_WALLET_ADDRESSES).is_none());
    }

    #[test]
    fn discovery_derives_twenty_addresses_without_loading_inactive_balances() {
        let (_dir, handle) = handle_with_utxos(&[1_000, 2_000]);
        let balance_before = handle.get_balance();
        let slots_before = handle
            .list_utxos()
            .into_iter()
            .map(|utxo| utxo.slot_index)
            .collect::<Vec<_>>();

        let preview = handle.preview_address_discovery(20).unwrap();
        assert_eq!(preview.candidates.len(), 20);
        assert_eq!(preview.candidates.first().unwrap().0, 1);
        assert_eq!(preview.candidates.last().unwrap().0, 20);
        let addresses = handle
            .commit_address_discovery(
                preview.expected_active_index,
                preview.expected_next_index,
                21,
            )
            .unwrap();

        assert_eq!(addresses.len(), 21);
        assert_eq!(
            addresses.iter().filter(|address| address.is_active).count(),
            1
        );
        assert!(addresses[0].is_active);
        let balance_after = handle.get_balance();
        assert_eq!(
            balance_after.balance_micronoid,
            balance_before.balance_micronoid
        );
        assert_eq!(balance_after.utxo_count, balance_before.utxo_count);
        assert_eq!(
            handle
                .list_utxos()
                .into_iter()
                .map(|utxo| utxo.slot_index)
                .collect::<Vec<_>>(),
            slots_before
        );
    }

    #[test]
    fn address_list_keeps_new_address_inactive() {
        let (_dir, handle) = handle_with_utxos(&[1_000]);
        let balance_before = handle.get_balance();
        let slots_before = handle
            .list_utxos()
            .into_iter()
            .map(|utxo| (utxo.slot_index, utxo.value_micronoid, utxo.creation_id))
            .collect::<Vec<_>>();
        let generated = handle.create_next_address().unwrap();
        assert_eq!(generated.key_index, 1);
        assert!(!generated.is_active);

        let addresses = handle.list_addresses();
        assert_eq!(addresses.len(), 2);
        assert!(addresses[0].is_active);
        assert!(!addresses[1].is_active);
        let balance_after = handle.get_balance();
        assert_eq!(
            (
                balance_after.balance_micronoid,
                balance_after.utxo_count,
                balance_after.spendable_micronoid,
            ),
            (
                balance_before.balance_micronoid,
                balance_before.utxo_count,
                balance_before.spendable_micronoid,
            )
        );
        assert_eq!(
            handle
                .list_utxos()
                .into_iter()
                .map(|utxo| (utxo.slot_index, utxo.value_micronoid, utxo.creation_id))
                .collect::<Vec<_>>(),
            slots_before
        );
    }

    #[test]
    fn reorg_installs_exact_snapshot_instead_of_replaying_on_old_cache() {
        let (_dir, handle) = handle_with_utxos(&[111, 222]);
        let owner = handle
            .inner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .active_address();
        let snapshot = VerifiedOwnerSnapshot {
            owner: owner.0,
            height: 10,
            tip_hash: [0x44; 32],
            state_root: [0x55; 32],
            log_slots: 24,
            active_slot_count: 1,
            alloc_counter: 8,
            utxos: vec![noid_chain::storage::VerifiedOwnerUtxo {
                slot_index: 99,
                amount: 777,
                creation_id: 8,
            }],
        };

        install_reorg_snapshot_and_artifacts(
            &handle.inner,
            0,
            1,
            owner.0,
            snapshot,
            &std::collections::HashSet::new(),
            &std::collections::HashSet::new(),
            &[],
            &[],
        )
        .unwrap();

        let guard = handle.inner.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        assert_eq!(wallet.utxos.len(), 1);
        assert_eq!(wallet.utxos[&99].value, 777);
        assert!(!wallet.utxos.contains_key(&0));
        assert!(!wallet.utxos.contains_key(&1));
        assert_eq!(wallet.active_snapshot.as_ref().unwrap().height, 10);
    }

    #[test]
    fn reorg_removes_receipts_bound_to_orphaned_blocks() {
        let (dir, handle) = handle_with_utxos(&[111]);
        let orphan_hash = [0x66; 32];
        let owner = {
            let mut guard = handle.inner.lock().unwrap();
            let wallet = guard.as_mut().unwrap();
            wallet.receipts.insert(orphan_hash, vec![1, 2, 3]);
            wallet.save_receipts().unwrap();
            wallet.history.push(state::TxHistoryEntry {
                tx_hash: orphan_hash,
                block_hash: None,
                height: 9,
                direction: state::TxDirection::Sent,
                is_coinbase: false,
                amount_micronoid: 7,
                peer_address: None,
                timestamp: 8,
                own_address: Some(wallet.active_address().to_bech32()),
                own_key_index: Some(wallet.active_index),
            });
            wallet.active_address()
        };

        install_reorg_snapshot_and_artifacts(
            &handle.inner,
            0,
            1,
            owner.0,
            empty_snapshot(owner.0),
            &std::collections::HashSet::new(),
            &std::collections::HashSet::new(),
            &[noid_poseidon2b::primitives::TxBodyHash(orphan_hash)],
            &[],
        )
        .unwrap();

        let guard = handle.inner.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        assert!(!wallet.receipts.contains_key(&orphan_hash));
        assert!(wallet
            .history
            .iter()
            .all(|entry| entry.tx_hash != orphan_hash));
        drop(guard);

        let reloaded = state::WalletState::create_or_load(dir.path().join("wallet.key")).unwrap();
        assert!(
            !reloaded.receipts.contains_key(&orphan_hash),
            "orphan receipt must not return after restart"
        );
    }

    #[test]
    fn reorg_confirms_pending_send_by_logical_transaction_id() {
        use noid_chain::block_header::BlockHeader;
        use noid_poseidon2b::primitives::Address;
        use noid_tx::{
            output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, PAGED_SPEND_END_BIT,
            PAGED_SPEND_START_BIT, TX_INPUTS, TX_OUTPUTS,
        };

        let (dir, handle) = handle_with_utxos(&[]);
        let owner = handle
            .inner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .active_address();
        let recipient = Address([0xA5; 32]);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 7,
            amount: 50,
            creation_id: 3,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 9,
            amount: 40,
            owner: recipient,
        };
        let payment = Transaction::new(TxBody {
            epoch_anchor: [0x11; 32],
            fee: 10,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0) | PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        });
        let physical_txid = payment.txid().0;
        let coinbase = Transaction::new(TxBody {
            epoch_anchor: [0; 32],
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: [TxOutput::dummy(); TX_OUTPUTS],
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        });
        let transactions = vec![coinbase, payment];
        let logical_txid = noid_chain::try_compute_logical_txids(&transactions).unwrap()[1].0;
        assert_ne!(logical_txid, physical_txid);
        let header = BlockHeader {
            prev_block_hash: [0; 32],
            state_root: [0; 32],
            tx_root: noid_chain::compute_tx_root(&transactions),
            timestamp: 123,
            height: 7,
            miner_address: Address([0x77; 32]),
            nonce: 0,
            difficulty_target: [0xFF; 32],
            log_slots: 24,
            active_slot_count: 1,
            alloc_counter: 1,
        };
        let block = noid_chain::Block {
            header,
            transactions,
        };
        let confirmed_block_hash = noid_chain::block_id(&block.header);
        {
            let mut guard = handle.inner.lock().unwrap();
            guard
                .as_mut()
                .unwrap()
                .record_pending_send(logical_txid, 40, recipient.0)
                .unwrap();
        }

        install_reorg_snapshot_and_artifacts(
            &handle.inner,
            0,
            1,
            owner.0,
            empty_snapshot(owner.0),
            &std::collections::HashSet::new(),
            &std::collections::HashSet::new(),
            &[noid_poseidon2b::primitives::TxBodyHash(logical_txid)],
            &[&block],
        )
        .unwrap();

        let guard = handle.inner.lock().unwrap();
        let entry = guard
            .as_ref()
            .unwrap()
            .history
            .iter()
            .find(|entry| entry.tx_hash == logical_txid)
            .expect("replacement-chain send remains in wallet history");
        assert_eq!(entry.height, 7);
        assert_eq!(entry.block_hash, Some(confirmed_block_hash));
        drop(guard);

        let reloaded = state::WalletState::create_or_load(dir.path().join("wallet.key")).unwrap();
        assert!(reloaded.history.iter().any(|entry| {
            entry.tx_hash == logical_txid
                && entry.height == 7
                && entry.block_hash == Some(confirmed_block_hash)
        }));
    }

    #[test]
    fn reorg_preserves_displaced_coinbase_as_mining_history() {
        let (dir, handle) = handle_with_utxos(&[111]);
        let coinbase_txid = [0x67; 32];
        let displaced_block_hash = [0x68; 32];
        let owner = {
            let mut guard = handle.inner.lock().unwrap();
            let wallet = guard.as_mut().unwrap();
            let owner = wallet.active_address();
            wallet.history.push(state::TxHistoryEntry {
                tx_hash: coinbase_txid,
                block_hash: Some(displaced_block_hash),
                height: 9,
                direction: state::TxDirection::Received,
                is_coinbase: true,
                amount_micronoid: 45_000_000,
                peer_address: None,
                timestamp: 8,
                own_address: Some(owner.to_bech32()),
                own_key_index: Some(wallet.active_index),
            });
            owner
        };

        install_reorg_snapshot_and_artifacts(
            &handle.inner,
            0,
            1,
            owner.0,
            empty_snapshot(owner.0),
            &std::collections::HashSet::new(),
            &std::collections::HashSet::new(),
            &[noid_poseidon2b::primitives::TxBodyHash(coinbase_txid)],
            &[],
        )
        .unwrap();

        let guard = handle.inner.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        let entry = wallet
            .history
            .iter()
            .find(|entry| entry.tx_hash == coinbase_txid)
            .expect("displaced coinbase must remain visible");
        assert!(entry.is_coinbase);
        assert_eq!(entry.block_hash, Some(displaced_block_hash));
        drop(guard);

        let reloaded = state::WalletState::create_or_load(dir.path().join("wallet.key")).unwrap();
        assert!(reloaded.history.iter().any(|entry| {
            entry.tx_hash == coinbase_txid
                && entry.block_hash == Some(displaced_block_hash)
                && entry.is_coinbase
        }));
    }

    #[test]
    fn rejected_incremental_update_does_not_advance_snapshot_or_cache() {
        let (_dir, handle) = handle_with_utxos(&[111]);
        let owner = handle
            .inner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .active_address();
        let baseline = state::ActiveWalletSnapshot {
            height: 3,
            tip_hash: [0x31; 32],
            state_root: [0x32; 32],
            log_slots: 24,
            active_slot_count: 1,
            alloc_counter: 1,
        };
        handle
            .inner
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .active_snapshot = Some(baseline.clone());

        let mut outputs = [noid_tx::TxOutput::dummy(); noid_tx::TX_OUTPUTS];
        outputs[0] = noid_tx::TxOutput {
            slot_index: 9,
            amount: 50,
            owner,
        };
        let body = noid_tx::TxBody {
            epoch_anchor: [0; 32],
            fee: 0,
            input_owner: noid_poseidon2b::primitives::Address([0; 32]),
            inputs: [noid_tx::TxInput::dummy(); noid_tx::TX_INPUTS],
            outputs,
            validity_bitmap: noid_tx::output_bitmap_bit(0),
            is_coinbase: true,
        };
        let malformed = noid_chain::block::Block {
            header: noid_chain::BlockHeader {
                prev_block_hash: baseline.tip_hash,
                state_root: [0x41; 32],
                tx_root: [0x42; 32],
                timestamp: 4,
                height: 4,
                miner_address: owner,
                nonce: 0,
                difficulty_target: [0xFF; 32],
                log_slots: 24,
                active_slot_count: 2,
                // One live mint with a zero post-counter is impossible.
                alloc_counter: 0,
            },
            transactions: vec![noid_tx::Transaction::new(body)],
        };

        assert!(update_for_accepted_block(&handle.inner, &malformed).is_err());
        let guard = handle.inner.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        assert_eq!(wallet.active_snapshot.as_ref(), Some(&baseline));
        assert_eq!(wallet.utxos.len(), 1);
        assert_eq!(wallet.utxos[&0].value, 111);
        assert!(!wallet.utxos.contains_key(&9));
    }

    #[test]
    fn canonical_send_selects_up_to_eight_inputs() {
        let (_dir, handle) = handle_with_utxos(&[50_000_000; 8]);
        let amount = 200_000_001;
        let fee = 18_500;
        let plan = handle.plan_send(amount, Some(fee), 0, 24, 0).unwrap();
        assert_eq!(plan.amount_micronoid, amount);
        assert_eq!(plan.input_count, 5);

        let guard = handle.inner.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        let (selected, change) = wallet.select_utxos(amount, fee).expect("select UTXOs");
        assert_eq!(selected.len(), 5);
        assert_eq!(change, 49_981_499);
    }

    #[test]
    fn plan_keeps_small_payment_fee_at_baseline() {
        let (_dir, handle) = handle_with_utxos(&[100_000]);
        let plan = handle.plan_send(50_000, None, 0, 24, 0).unwrap();
        assert_eq!(plan.fee_micronoid, 9_000);
        assert_eq!(plan.input_count, 1);
        assert_eq!(plan.output_count, 2);
        assert_eq!(plan.fee_breakdown.burned, 2_500);
    }

    #[test]
    fn plan_handles_no_change_boundary_without_oscillation() {
        let (_dir, handle) = handle_with_utxos(&[100_000]);
        let plan = handle.plan_send(91_000, None, 0, 24, 0).unwrap();
        assert_eq!(plan.fee_micronoid, 9_000);
        assert_eq!(plan.output_count, 1);
        assert_eq!(plan.change_micronoid, 0);
        assert_eq!(plan.fee_breakdown.paid_total, 9_000);
        assert_eq!(plan.fee_breakdown.relay_total, 5_800);
    }

    #[test]
    fn plan_charges_actual_io_for_five_input_send() {
        let (_dir, handle) = handle_with_utxos(&[50_000_000; 8]);
        let plan = handle.plan_send(200_000_001, None, 0, 24, 0).unwrap();
        assert_eq!(plan.input_count, 5);
        assert_eq!(plan.output_count, 2);
        assert_eq!(plan.fee_micronoid, 6_900);
        assert_eq!(plan.fee_breakdown.state_growth, 0);
    }
}
