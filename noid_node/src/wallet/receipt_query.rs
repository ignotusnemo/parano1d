// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use noid_chain::consensus::receipt::{
    native_receipt_details, trade_receipt_details, ParanoidReceipt,
};

pub(super) fn records(
    wallet: &mut WalletState,
    selected: Vec<(u64, u64, [u8; 32], u8)>,
) -> Result<Vec<WalletReceiptRecord>, String> {
    if selected.iter().any(|entry| entry.3 != 0) {
        wallet.refresh_receipt_accounts();
    }
    let mut sent_by_txid = std::collections::HashMap::new();
    for entry in &wallet.history {
        if entry.direction == state::TxDirection::Sent
            && wallet.receipts.contains_key(&entry.tx_hash)
        {
            sent_by_txid.entry(entry.tx_hash).or_insert(entry);
        }
    }
    let mut receipts = Vec::with_capacity(selected.len());
    for (_, _, id, native) in selected {
        let bytes = wallet
            .receipts
            .get(&id)
            .ok_or("durable receipt disappeared")?;
        let receipt = ParanoidReceipt::from_bytes(bytes).map_err(|e| e.to_string())?;
        if native == 2 {
            let details =
                native_receipt_details(&receipt).ok_or("invalid native action receipt")?;
            let participants = details.participants();
            let own = wallet
                .receipt_accounts
                .get(&details.authority.0)
                .map(|index| (details.authority, *index))
                .or_else(|| {
                    participants
                        .iter()
                        .filter_map(|owner| {
                            wallet
                                .receipt_accounts
                                .get(&owner.0)
                                .map(|index| (*owner, *index))
                        })
                        .min_by_key(|entry| entry.1)
                });
            let own = own.ok_or("native receipt has no wallet participant")?;
            let spent: u128 = details
                .inputs
                .iter()
                .filter(|claim| claim.opening.is_none() && claim.root == own.0)
                .map(|claim| u128::from(claim.input.amount))
                .sum();
            let received: u128 = details
                .outputs
                .iter()
                .filter(|claim| claim.opening.is_none() && claim.output.owner == own.0)
                .map(|claim| u128::from(claim.output.amount))
                .sum();
            let amount = u64::try_from(spent.abs_diff(received))
                .map_err(|_| "native receipt amount overflow")?;
            receipts.push(WalletReceiptRecord {
                txid: id,
                height: receipt.claimed_height,
                timestamp: receipt.summary.confirmed_unix,
                amount_micronoid: amount,
                fee_micronoid: receipt.summary.fee_micronoid,
                peer_address: None,
                own_address: Some(own.0.to_bech32()),
                own_key_index: Some(own.1),
                input_count: details.inputs.len(),
                output_count: details.outputs.len(),
                receipt_bytes: bytes.len(),
                trade: None,
                native: Some(details.into()),
            });
            continue;
        }
        if native == 1 {
            let trade = trade_receipt_details(&receipt).ok_or("invalid native policy receipt")?;
            let own = wallet
                .receipt_accounts
                .get(&trade.owner.0)
                .map(|index| (trade.owner, *index))
                .or_else(|| {
                    wallet
                        .receipt_accounts
                        .get(&trade.recipient.0)
                        .map(|index| (trade.recipient, *index))
                });
            let received_only = own.is_some_and(|(address, _)| address != trade.owner);
            let noid_amount = match trade.side {
                noid_tx::native_assets::launch::LaunchSide::Buy if received_only => 0,
                noid_tx::native_assets::launch::LaunchSide::Buy => trade.spent_input,
                noid_tx::native_assets::launch::LaunchSide::Sell => trade.output,
            };
            receipts.push(WalletReceiptRecord {
                txid: id,
                height: receipt.claimed_height,
                timestamp: receipt.summary.confirmed_unix,
                amount_micronoid: noid_amount,
                fee_micronoid: receipt.summary.fee_micronoid,
                peer_address: Some(trade.recipient.to_bech32()),
                own_address: Some(own.map_or(trade.owner, |v| v.0).to_bech32()),
                own_key_index: own.map(|v| v.1),
                input_count: receipt.summary.inputs.len(),
                output_count: receipt.summary.outputs.len(),
                receipt_bytes: bytes.len(),
                trade: Some(trade.into()),
                native: None,
            });
            continue;
        }
        let sent = sent_by_txid.get(&id).copied();
        let input_owner = receipt.summary.inputs.first().map(|(_, owner)| *owner);
        let outputs: Vec<_> = receipt
            .summary
            .outputs
            .iter()
            .filter(|(_, _, owner)| Some(*owner) != input_owner)
            .collect();
        let amount = outputs
            .iter()
            .map(|(_, amount, _)| *amount)
            .fold(0u64, u64::saturating_add);
        let peer = (outputs.len() == 1).then(|| outputs[0].2.to_bech32());
        receipts.push(WalletReceiptRecord {
            txid: id,
            height: receipt.claimed_height,
            timestamp: receipt.summary.confirmed_unix,
            amount_micronoid: sent.map_or(amount, |entry| entry.amount_micronoid),
            fee_micronoid: receipt.summary.fee_micronoid,
            peer_address: sent
                .and_then(|entry| entry.peer_address)
                .map(|owner| noid_poseidon2b::primitives::Address(owner).to_bech32())
                .or(peer),
            own_address: sent
                .and_then(|entry| entry.own_address.clone())
                .or_else(|| input_owner.map(|owner| owner.to_bech32())),
            own_key_index: sent.and_then(|entry| entry.own_key_index),
            input_count: receipt.summary.inputs.len(),
            output_count: receipt.summary.outputs.len(),
            receipt_bytes: bytes.len(),
            trade: None,
            native: None,
        });
    }
    Ok(receipts)
}
