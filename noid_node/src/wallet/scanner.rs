// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Incremental active-address wallet updates from accepted blocks.
//!
//! # Architecture
//!
//! Blocks are pruned after application, so this hook consumes accepted block
//! bodies while they are available. It never discovers inactive accounts.
//!
//! ## Incremental update (new block)
//!
//! O(block_size): check outputs for the one active address, remove spent inputs.
//! Startup, explicit reload, snapshot install, and reorg recovery use the
//! durable verified owner index instead of traversing state here.

use std::collections::HashMap;

use super::state::{TxDirection, TxHistoryEntry, WalletUtxo};
use noid_chain::block::Block;
use noid_chain::consensus::receipt::generate_receipt;

// ---------------------------------------------------------------------------
// Incremental block update
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreationIdDerivationError {
    InvalidSystemLayout,
    MintCountOverflow,
    HeaderCounterUnderflow { alloc_counter: u64, live_mints: u64 },
    CounterOverflow,
    FinalCounterMismatch { expected: u64, actual: u64 },
}

impl std::fmt::Display for CreationIdDerivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSystemLayout => write!(f, "invalid system transaction layout"),
            Self::MintCountOverflow => write!(f, "live output count exceeds u64"),
            Self::HeaderCounterUnderflow {
                alloc_counter,
                live_mints,
            } => write!(
                f,
                "header alloc_counter {alloc_counter} is below live mint count {live_mints}"
            ),
            Self::CounterOverflow => write!(f, "creation_id counter overflow"),
            Self::FinalCounterMismatch { expected, actual } => write!(
                f,
                "derived final alloc_counter {actual} does not match header {expected}"
            ),
        }
    }
}

/// Reconstruct each output's consensus creation id from the post-block
/// allocator counter. IDs follow `block.transactions` and output order exactly.
/// The helper independently validates the primary coinbase and optional
/// development-payout positions so malformed data cannot acquire a
/// wallet-only interpretation different from consensus.
///
/// `TxOutput` intentionally carries no caller-chosen creation id. The wallet
/// therefore derives the parent counter as `header.alloc_counter - live_mints`
/// and advances it with checked arithmetic. The returned matrix is aligned
/// with `block.transactions[tx].body.outputs[output]`; dummy outputs map to
/// `None`.
fn derive_output_creation_ids(
    block: &Block,
) -> Result<Vec<Vec<Option<u64>>>, CreationIdDerivationError> {
    noid_chain::validate_block_page_stream(&block.transactions)
        .map_err(|_| CreationIdDerivationError::InvalidSystemLayout)?;

    let live_mints = block
        .transactions
        .iter()
        .flat_map(|tx| tx.body.live_outputs())
        .try_fold(0u64, |count, _| count.checked_add(1))
        .ok_or(CreationIdDerivationError::MintCountOverflow)?;
    let mut counter = block.header.alloc_counter.checked_sub(live_mints).ok_or(
        CreationIdDerivationError::HeaderCounterUnderflow {
            alloc_counter: block.header.alloc_counter,
            live_mints,
        },
    )?;

    let mut ids: Vec<Vec<Option<u64>>> = block
        .transactions
        .iter()
        .map(|tx| vec![None; tx.body.outputs.len()])
        .collect();

    for (tx_index, tx) in block.transactions.iter().enumerate() {
        for (output_index, _output) in tx.body.outputs.iter().enumerate() {
            if !tx.body.output_is_live(output_index) {
                continue;
            }
            // Every mint (including coinbase) consumes one allocator
            // increment, but the coinbase's unique live output STORES the
            // height-tagged coinbase creation id.
            counter = counter
                .checked_add(1)
                .ok_or(CreationIdDerivationError::CounterOverflow)?;
            ids[tx_index][output_index] = Some(if tx.body.is_primary_coinbase_shape() {
                noid_chain::consensus::params::coinbase_creation_id(block.header.height)
            } else {
                counter
            });
        }
    }

    if counter != block.header.alloc_counter {
        return Err(CreationIdDerivationError::FinalCounterMismatch {
            expected: block.header.alloc_counter,
            actual: counter,
        });
    }
    Ok(ids)
}

/// Record history and receipts from an accepted block without touching the
/// active UTXO cache. Reorg recovery uses this after installing one exact
/// post-reorg owner snapshot; replaying replacement deltas onto the old branch
/// cache would make balance and sent-value inference transiently incorrect.
pub fn update_wallet_artifacts_from_block(
    history: &mut Vec<TxHistoryEntry>,
    receipts: &mut super::persistence::ReceiptMap,
    active_address: noid_poseidon2b::primitives::Address,
    active_index: u32,
    block: &Block,
) {
    let block_hash = noid_chain::block_id(&block.header);
    let stream = noid_chain::validate_block_page_stream(&block.transactions)
        .expect("accepted block has a canonical PagedSpend stream");
    let block_tx_hashes: Vec<[u8; 32]> = noid_chain::try_compute_logical_txids(&block.transactions)
        .expect("accepted block has canonical logical txids")
        .into_iter()
        .map(|txid| txid.0)
        .collect();
    let pending_hashes: std::collections::HashSet<[u8; 32]> = history
        .iter()
        .filter(|entry| entry.height == 0 && entry.direction == TxDirection::Sent)
        .map(|entry| entry.tx_hash)
        .collect();
    let existing_confirmed: std::collections::HashSet<[u8; 32]> = history
        .iter()
        .filter(|entry| entry.height != 0)
        .map(|entry| entry.tx_hash)
        .collect();

    for system_index in 0..stream.user_start_index {
        let system = &block.transactions[system_index];
        let system_hash = block_tx_hashes[system_index];
        if existing_confirmed.contains(&system_hash) {
            continue;
        }
        let received = system
            .body
            .live_outputs()
            .map(|(_, output)| output)
            .filter(|output| output.owner == active_address)
            .map(|output| output.amount)
            .fold(0u64, u64::saturating_add);
        if received > 0 {
            history.push(TxHistoryEntry {
                tx_hash: system_hash,
                block_hash: Some(block_hash),
                height: block.header.height,
                direction: TxDirection::Received,
                is_coinbase: system_index == 0,
                amount_micronoid: received,
                peer_address: None,
                timestamp: block.header.timestamp,
                own_address: Some(active_address.to_bech32()),
                own_key_index: Some(active_index),
            });
        }
    }

    for (group_index, group) in stream.groups.iter().enumerate() {
        let tx_index = stream.user_logical_index(group_index);
        let tx_hash = group.spend.logical_txid.0;
        let start = stream.user_body_start(usize::from(group.start_page));
        let end = stream.user_body_start(group.end_page_exclusive());
        let pages = &block.transactions[start..end];
        let pending_send = pending_hashes.contains(&tx_hash);
        let has_distinct_recipient = pages
            .iter()
            .flat_map(|page| page.body.live_outputs().map(|(_, output)| output))
            .any(|output| output.owner != group.spend.input_owner);

        if pending_send && has_distinct_recipient {
            let receipt = generate_receipt(&block.header, pages, tx_index, &block_tx_hashes);
            receipts.insert(tx_hash, receipt.to_bytes());
            continue;
        } else if pending_send {
            continue;
        }

        if existing_confirmed.contains(&tx_hash) {
            continue;
        }
        let received = pages
            .iter()
            .flat_map(|page| page.body.live_outputs().map(|(_, output)| output))
            .filter(|output| output.owner == active_address)
            .map(|output| output.amount)
            .fold(0u64, u64::saturating_add);
        if received == 0 {
            continue;
        }
        history.push(TxHistoryEntry {
            tx_hash,
            block_hash: Some(block_hash),
            height: block.header.height,
            direction: TxDirection::Received,
            is_coinbase: false,
            amount_micronoid: received,
            peer_address: None,
            timestamp: block.header.timestamp,
            own_address: Some(active_address.to_bech32()),
            own_key_index: Some(active_index),
        });
    }
}

/// Update wallet state based on a newly confirmed block.
///
/// Must be called BEFORE block pruning (while transactions are still available).
/// O(block_size).
///
/// Updates:
/// - Removes spent UTXOs (inputs consumed by this block)
/// - Adds new UTXOs (outputs addressed to this wallet)
/// - Appends to tx history
/// - Generates receipts only when a payment leaves its input owner
/// - Clears confirmed input slots from `pending_input_slots`
pub fn update_active_wallet_from_block(
    utxos: &mut HashMap<u32, WalletUtxo>,
    history: &mut Vec<TxHistoryEntry>,
    receipts: &mut super::persistence::ReceiptMap,
    active_address: noid_poseidon2b::primitives::Address,
    active_index: u32,
    pending_input_slots: &mut std::collections::HashSet<u32>,
    block: &Block,
) -> Result<(), String> {
    let height = block.header.height;
    let timestamp = block.header.timestamp;
    let block_hash = noid_chain::block_id(&block.header);

    // Derive the complete map before mutating wallet state. Consensus-valid
    // blocks always satisfy this relation; rejecting the update here avoids
    // inventing or wrapping an incarnation if corrupt/unvalidated data reaches
    // the product hook.
    let output_creation_ids = derive_output_creation_ids(block).map_err(|error| {
        format!(
            "wallet block h={height} has invalid creation-id sequence at alloc_counter {}: {error}",
            block.header.alloc_counter
        )
    })?;

    let stream = noid_chain::validate_block_page_stream(&block.transactions).map_err(|error| {
        format!("wallet block h={height} has invalid PagedSpend stream: {error}")
    })?;
    let block_tx_hashes: Vec<[u8; 32]> = noid_chain::try_compute_logical_txids(&block.transactions)
        .map_err(|error| format!("wallet block h={height} has invalid txids: {error}"))?
        .into_iter()
        .map(|txid| txid.0)
        .collect();

    // Build once before the loop: O(history) instead of O(history × txs).
    let pending_hashes: std::collections::HashSet<[u8; 32]> = history
        .iter()
        .filter(|e| e.height == 0)
        .map(|e| e.tx_hash)
        .collect();

    // Primary coinbase and the optional development payout occupy the
    // logical prefix in the same order as their physical bodies.
    for system_index in 0..stream.user_start_index {
        let system = &block.transactions[system_index];
        let system_hash = block_tx_hashes[system_index];
        for (output_index, output) in system.body.outputs.iter().enumerate() {
            if !system.body.output_is_live(output_index) {
                continue;
            }
            let Some(creation_id) = output_creation_ids[system_index][output_index] else {
                return Err(format!(
                    "wallet block h={height} is missing creation id for live system output {system_index}:{output_index}"
                ));
            };
            if output.owner == active_address {
                utxos.insert(
                    output.slot_index,
                    WalletUtxo {
                        slot_index: output.slot_index,
                        value: output.amount,
                        creation_id,
                        address: output.owner,
                        key_index: active_index,
                        confirmed_height: height,
                    },
                );
                history.push(TxHistoryEntry {
                    tx_hash: system_hash,
                    block_hash: Some(block_hash),
                    height,
                    direction: TxDirection::Received,
                    is_coinbase: system_index == 0,
                    amount_micronoid: output.amount,
                    peer_address: None,
                    timestamp,
                    own_address: Some(output.owner.to_bech32()),
                    own_key_index: Some(active_index),
                });
            }
        }
    }

    for (group_index, group) in stream.groups.iter().enumerate() {
        let logical_index = stream.user_logical_index(group_index);
        let tx_hash = group.spend.logical_txid.0;
        let start = stream.user_body_start(usize::from(group.start_page));
        let end = stream.user_body_start(group.end_page_exclusive());
        let pages = &block.transactions[start..end];
        let has_distinct_recipient = pages
            .iter()
            .flat_map(|page| page.body.live_outputs().map(|(_, output)| output))
            .any(|output| output.owner != group.spend.input_owner);
        // Track value flow for this transaction
        let mut sent_from_wallet: u64 = 0;
        let mut received_by_wallet: u64 = 0;
        let mut sent_own_address: Option<String> = None;
        let mut sent_own_key_index: Option<u32> = None;
        let mut recv_own_address: Option<String> = None;
        let mut recv_own_key_index: Option<u32> = None;

        for (page_offset, page) in pages.iter().enumerate() {
            let physical_index = start + page_offset;
            // Inputs: remove spent UTXOs and clear pending reservations.
            for (_, input) in page.body.live_inputs() {
                pending_input_slots.remove(&input.slot_index);
                if let Some(spent) = utxos.remove(&input.slot_index) {
                    sent_from_wallet = sent_from_wallet.saturating_add(spent.value);
                    if sent_own_address.is_none() {
                        sent_own_address = Some(spent.address.to_bech32());
                        sent_own_key_index = Some(spent.key_index);
                    }
                }
            }

            // Outputs: add new UTXOs owned by this wallet.
            for (output_index, output) in page.body.outputs.iter().enumerate() {
                if !page.body.output_is_live(output_index) {
                    continue;
                }
                let Some(creation_id) = output_creation_ids[physical_index][output_index] else {
                    return Err(format!(
                        "wallet block h={height} is missing creation id for live user output {physical_index}:{output_index}"
                    ));
                };
                if output.owner == active_address {
                    utxos.insert(
                        output.slot_index,
                        WalletUtxo {
                            slot_index: output.slot_index,
                            value: output.amount,
                            creation_id,
                            address: output.owner,
                            key_index: active_index,
                            confirmed_height: height,
                        },
                    );
                    received_by_wallet = received_by_wallet.saturating_add(output.amount);
                    if recv_own_address.is_none() {
                        recv_own_address = Some(output.owner.to_bech32());
                        recv_own_key_index = Some(active_index);
                    }
                }
            }
        }

        // Record history entry.
        // Skip if this tx_hash is already in history as a pending (height=0) entry
        // from record_pending_send — confirm_pending_tx will update the height.
        let already_pending = pending_hashes.contains(&tx_hash);

        if !already_pending {
            if sent_from_wallet > 0 {
                let net_sent = sent_from_wallet.saturating_sub(received_by_wallet);
                history.push(TxHistoryEntry {
                    tx_hash,
                    block_hash: Some(block_hash),
                    height,
                    direction: TxDirection::Sent,
                    is_coinbase: false,
                    amount_micronoid: net_sent,
                    peer_address: None,
                    timestamp,
                    own_address: sent_own_address,
                    own_key_index: sent_own_key_index,
                });
            } else if received_by_wallet > 0 {
                history.push(TxHistoryEntry {
                    tx_hash,
                    block_hash: Some(block_hash),
                    height,
                    direction: TxDirection::Received,
                    is_coinbase: false,
                    amount_micronoid: received_by_wallet,
                    peer_address: None,
                    timestamp,
                    own_address: recv_own_address,
                    own_key_index: recv_own_key_index,
                });
            }
        }

        // A locally pending send remains ours even if the user switched away
        // from its source address before confirmation. In that case its input
        // is intentionally absent from the active-address cache, so the durable
        // pending history tag is the ownership signal for receipt generation.
        // Incoming-only transactions still need no receipt.
        if has_distinct_recipient && (sent_from_wallet > 0 || already_pending) {
            let receipt = generate_receipt(&block.header, pages, logical_index, &block_tx_hashes);
            receipts.insert(tx_hash, receipt.to_bytes());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::block_header::BlockHeader;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, PAGED_SPEND_END_BIT,
        PAGED_SPEND_START_BIT, TX_INPUTS, TX_OUTPUTS,
    };

    fn transaction(is_coinbase: bool, slot_index: u32, owner: Address) -> Transaction {
        let amount = u64::from(slot_index) + 100;
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        if !is_coinbase {
            inputs[0] = TxInput {
                slot_index: slot_index + 1_000,
                amount,
                creation_id: 1,
            };
        }
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index,
            amount,
            owner,
        };
        Transaction::new(TxBody {
            epoch_anchor: if is_coinbase { [0; 32] } else { [1; 32] },
            fee: 0,
            input_owner: if is_coinbase {
                Address([0; 32])
            } else {
                Address([0xEE; 32])
            },
            inputs,
            outputs,
            validity_bitmap: output_bitmap_bit(0)
                | u16::from(!is_coinbase)
                | if is_coinbase {
                    0
                } else {
                    PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT
                },
            is_coinbase,
        })
    }

    fn development_payout(slot_index: u32) -> Transaction {
        Transaction::new(TxBody {
            epoch_anchor: [0; 32],
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: [
                TxOutput {
                    slot_index,
                    amount: 500,
                    owner: noid_chain::consensus::O1_NETWORK_FUND_ADDRESS,
                },
                TxOutput {
                    slot_index: slot_index + 1,
                    amount: 500,
                    owner: noid_chain::consensus::PARANO1D_LAB_ADDRESS,
                },
            ],
            validity_bitmap: output_bitmap_bit(0) | output_bitmap_bit(1),
            is_coinbase: true,
        })
    }

    fn block(transactions: Vec<Transaction>, alloc_counter: u64) -> Block {
        let tx_root = noid_chain::try_compute_tx_root(&transactions).unwrap_or([0; 32]);
        Block {
            header: BlockHeader {
                prev_block_hash: [0; 32],
                state_root: [0; 32],
                tx_root,
                timestamp: 123,
                height: 7,
                miner_address: Address([0x77; 32]),
                nonce: 0,
                difficulty_target: [0xFF; 32],
                log_slots: 24,
                active_slot_count: transactions.len() as u64,
                alloc_counter,
            },
            transactions,
        }
    }

    fn logical_txid(transaction: &Transaction) -> [u8; 32] {
        noid_tx::validate_paged_spend(&[noid_tx::TxPage {
            body: transaction.body.clone(),
        }])
        .unwrap()
        .logical_txid
        .0
    }

    #[test]
    fn incremental_scan_assigns_coinbase_then_user_creation_ids() {
        let owner = Address([0xA1; 32]);
        let block = block(
            vec![transaction(true, 10, owner), transaction(false, 20, owner)],
            102,
        );
        let mut utxos = HashMap::new();
        let mut history = vec![];
        let mut receipts = super::super::persistence::ReceiptMap::default();
        let mut pending_inputs = std::collections::HashSet::new();

        update_active_wallet_from_block(
            &mut utxos,
            &mut history,
            &mut receipts,
            owner,
            3,
            &mut pending_inputs,
            &block,
        )
        .unwrap();

        assert_eq!(
            utxos[&10].creation_id,
            noid_chain::consensus::params::coinbase_creation_id(7),
            "coinbase stores the height-tagged creation id"
        );
        assert_eq!(
            utxos[&20].creation_id, 102,
            "user output follows the allocator (coinbase still burned id 101)"
        );
        assert_eq!(history.len(), 2);
        assert!(history[0].is_coinbase);
        assert!(!history[1].is_coinbase);
        let expected_block_hash = noid_chain::block_id(&block.header);
        assert!(history
            .iter()
            .all(|entry| entry.block_hash == Some(expected_block_hash)));
    }

    #[test]
    fn incremental_scan_assigns_normal_ids_to_development_payout_outputs() {
        let owner = noid_chain::consensus::O1_NETWORK_FUND_ADDRESS;
        let block = block(
            vec![
                transaction(true, 10, owner),
                development_payout(30),
                transaction(false, 20, owner),
            ],
            104,
        );
        let ids = derive_output_creation_ids(&block).unwrap();
        assert_eq!(
            ids[0][0],
            Some(noid_chain::consensus::params::coinbase_creation_id(7))
        );
        assert_eq!(ids[1][0], Some(102));
        assert_eq!(ids[1][1], Some(103));
        assert_eq!(ids[2][0], Some(104));

        let mut utxos = HashMap::new();
        let mut history = vec![];
        let mut receipts = super::super::persistence::ReceiptMap::default();
        let mut pending_inputs = std::collections::HashSet::new();
        update_active_wallet_from_block(
            &mut utxos,
            &mut history,
            &mut receipts,
            owner,
            3,
            &mut pending_inputs,
            &block,
        )
        .unwrap();

        assert_eq!(utxos[&30].creation_id, 102);
        assert_eq!(utxos[&20].creation_id, 104);
        assert_eq!(history.len(), 3);
        assert!(history[0].is_coinbase);
        assert!(!history[1].is_coinbase);
        assert!(!history[2].is_coinbase);
    }

    #[test]
    fn incremental_scan_rejects_noncanonical_coinbase_layout() {
        let owner = Address([0xA3; 32]);
        let late = block(
            vec![transaction(false, 20, owner), transaction(true, 10, owner)],
            102,
        );
        assert_eq!(
            derive_output_creation_ids(&late),
            Err(CreationIdDerivationError::InvalidSystemLayout)
        );

        let duplicate = block(
            vec![transaction(true, 10, owner), transaction(true, 11, owner)],
            102,
        );
        assert_eq!(
            derive_output_creation_ids(&duplicate),
            Err(CreationIdDerivationError::InvalidSystemLayout)
        );
    }

    #[test]
    fn incremental_scan_rejects_counter_underflow_before_mutation() {
        let owner = Address([0xA2; 32]);
        let block = block(
            vec![transaction(true, 10, owner), transaction(false, 20, owner)],
            1,
        );
        let mut utxos = HashMap::new();
        let mut history = vec![];
        let mut receipts = super::super::persistence::ReceiptMap::default();
        let mut pending_inputs = std::collections::HashSet::new();

        assert!(update_active_wallet_from_block(
            &mut utxos,
            &mut history,
            &mut receipts,
            owner,
            0,
            &mut pending_inputs,
            &block,
        )
        .is_err());

        assert!(utxos.is_empty());
        assert!(history.is_empty());
    }

    #[test]
    fn incremental_update_ignores_inactive_owner_outputs() {
        let active = Address([0xA4; 32]);
        let inactive = Address([0xA5; 32]);
        let block = block(vec![transaction(true, 10, inactive)], 1);
        let mut utxos = HashMap::new();
        let mut history = vec![];
        let mut receipts = super::super::persistence::ReceiptMap::default();
        let mut pending_inputs = std::collections::HashSet::new();

        update_active_wallet_from_block(
            &mut utxos,
            &mut history,
            &mut receipts,
            active,
            0,
            &mut pending_inputs,
            &block,
        )
        .unwrap();

        assert!(utxos.is_empty());
        assert!(history.is_empty());
    }

    #[test]
    fn pending_send_gets_receipt_after_source_account_becomes_inactive() {
        let active = Address([0xA6; 32]);
        let inactive_source = Address([0xA7; 32]);
        let coinbase = transaction(true, 10, Address([0xCC; 32]));
        let outgoing = transaction(false, 20, Address([0xBB; 32]));
        let outgoing_hash = logical_txid(&outgoing);
        let block = block(vec![coinbase, outgoing], 2);
        let mut utxos = HashMap::new();
        let mut history = vec![TxHistoryEntry {
            tx_hash: outgoing_hash,
            block_hash: None,
            height: 0,
            direction: TxDirection::Sent,
            is_coinbase: false,
            amount_micronoid: 123,
            peer_address: Some([0xBB; 32]),
            timestamp: 1,
            own_address: Some(inactive_source.to_bech32()),
            own_key_index: Some(9),
        }];
        let mut receipts = super::super::persistence::ReceiptMap::default();
        let mut pending_inputs = std::collections::HashSet::new();

        update_active_wallet_from_block(
            &mut utxos,
            &mut history,
            &mut receipts,
            active,
            0,
            &mut pending_inputs,
            &block,
        )
        .unwrap();

        assert!(receipts.contains_key(&outgoing_hash));
        assert_eq!(history.len(), 1, "pending history must not be duplicated");
        assert_eq!(history[0].own_key_index, Some(9));
    }

    #[test]
    fn pending_same_owner_send_does_not_get_receipt() {
        let source = Address([0xEE; 32]);
        let coinbase = transaction(true, 10, Address([0xCC; 32]));
        let outgoing = transaction(false, 20, source);
        let outgoing_hash = logical_txid(&outgoing);
        let block = block(vec![coinbase, outgoing], 2);
        let mut utxos = HashMap::new();
        let mut history = vec![TxHistoryEntry {
            tx_hash: outgoing_hash,
            block_hash: None,
            height: 0,
            direction: TxDirection::Sent,
            is_coinbase: false,
            amount_micronoid: 123,
            peer_address: Some(source.0),
            timestamp: 1,
            own_address: Some(source.to_bech32()),
            own_key_index: Some(9),
        }];
        let mut receipts = super::super::persistence::ReceiptMap::default();
        let mut pending_inputs = std::collections::HashSet::new();

        update_active_wallet_from_block(
            &mut utxos,
            &mut history,
            &mut receipts,
            source,
            0,
            &mut pending_inputs,
            &block,
        )
        .unwrap();

        assert!(!receipts.contains_key(&outgoing_hash));
        assert_eq!(history.len(), 1, "pending history must still be confirmed");
    }

    #[test]
    fn pending_send_to_an_inactive_wallet_address_still_gets_receipt() {
        let source = Address([0xEE; 32]);
        let inactive_wallet_recipient = Address([0xBB; 32]);
        let coinbase = transaction(true, 10, Address([0xCC; 32]));
        let outgoing = transaction(false, 20, inactive_wallet_recipient);
        let outgoing_hash = logical_txid(&outgoing);
        let block = block(vec![coinbase, outgoing], 2);
        let mut utxos = HashMap::new();
        let mut history = vec![TxHistoryEntry {
            tx_hash: outgoing_hash,
            block_hash: None,
            height: 0,
            direction: TxDirection::Sent,
            is_coinbase: false,
            amount_micronoid: 123,
            peer_address: Some(inactive_wallet_recipient.0),
            timestamp: 1,
            own_address: Some(source.to_bech32()),
            own_key_index: Some(9),
        }];
        let mut receipts = super::super::persistence::ReceiptMap::default();
        let mut pending_inputs = std::collections::HashSet::new();

        update_active_wallet_from_block(
            &mut utxos,
            &mut history,
            &mut receipts,
            source,
            0,
            &mut pending_inputs,
            &block,
        )
        .unwrap();

        assert!(receipts.contains_key(&outgoing_hash));
    }

    #[test]
    fn reorg_artifact_replay_does_not_need_or_mutate_utxo_cache() {
        let active = Address([0xD1; 32]);
        let inactive_source = Address([0xD2; 32]);
        let coinbase = transaction(true, 10, Address([0xCC; 32]));
        let outgoing = transaction(false, 20, Address([0xBB; 32]));
        let outgoing_hash = logical_txid(&outgoing);
        let block = block(vec![coinbase, outgoing], 2);
        let mut history = vec![TxHistoryEntry {
            tx_hash: outgoing_hash,
            block_hash: None,
            height: 0,
            direction: TxDirection::Sent,
            is_coinbase: false,
            amount_micronoid: 123,
            peer_address: Some([0xBB; 32]),
            timestamp: 1,
            own_address: Some(inactive_source.to_bech32()),
            own_key_index: Some(9),
        }];
        let mut receipts = super::super::persistence::ReceiptMap::default();

        update_wallet_artifacts_from_block(&mut history, &mut receipts, active, 0, &block);

        assert!(receipts.contains_key(&outgoing_hash));
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].own_key_index, Some(9));
    }
}
