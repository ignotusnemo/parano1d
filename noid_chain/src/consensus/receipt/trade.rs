// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Individual policy receipts bound to their canonical execution group.

use noid_poseidon2b::primitives::{Address, TxBodyHash};
use noid_tx::{
    native_assets::{
        financial::FinancialOperation,
        launch::LaunchSide,
        trade::{
            batch::TradeBatch,
            execution::{quote_charge, TradeExecution, TradeFeeQuotes, TradeOutputSlots},
            sequencing::{TradeBoundary, TradeOutcome},
            TradePayout,
        },
        transition::NativeOperation,
        wire::{decode_native_pages, encode_native_pages, NativeIntent},
        AssetId,
    },
    Transaction, TxPage,
};

use super::{ParanoidReceipt, TxSummary, RECEIPT_CONSTRUCTION_MARKER};
use crate::{
    block_header::BlockHeader, consensus::wire_limits::MAX_RPC_RECEIPT_BYTES,
    state::native_assets::market::liquidity::MarketFeeContext, wire::BLOCK_HEADER_WIRE_SIZE,
};

pub(super) const MAGIC: &[u8; 4] = b"NTR1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeReceiptDetails {
    pub authorization_id: TxBodyHash,
    pub group_id: TxBodyHash,
    pub asset: AssetId,
    pub owner: Address,
    pub recipient: Address,
    pub side: LaunchSide,
    pub gross_input: u64,
    pub spent_input: u64,
    pub output: u64,
    pub minimum_output: u64,
    pub fee_limit: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub market_fee: u64,
    pub network_fee: u64,
    pub execution_index: usize,
    pub payouts: Vec<TradePayout>,
}

pub(super) struct CheckedTradeReceipt {
    pub header: BlockHeader,
    pub leaf: TxBodyHash,
    pub summary: TxSummary,
    pub details: TradeReceiptDetails,
}

pub fn generate_trade_receipt(
    header: &BlockHeader,
    parent: &BlockHeader,
    pages: &[Transaction],
    tx_index: usize,
    block_tx_hashes: &[[u8; 32]],
    batch: &TradeBatch,
    policy_index: usize,
) -> Result<ParanoidReceipt, String> {
    if !(1..=crate::tx_tree::TX_TREE_LEAVES).contains(&block_tx_hashes.len())
        || tx_index >= block_tx_hashes.len()
    {
        return Err("trade receipt group position".into());
    }
    let mut encoded = MAGIC.to_vec();
    encoded.extend_from_slice(
        &u16::try_from(policy_index)
            .map_err(|_| "trade receipt policy index")?
            .to_le_bytes(),
    );
    encoded.extend_from_slice(&[0; 2]);
    encoded.extend_from_slice(&header.to_bytes());
    encoded.extend_from_slice(&parent.to_bytes());
    let pages: Vec<_> = pages
        .iter()
        .map(|tx| TxPage {
            body: tx.body.clone(),
        })
        .collect();
    encode_native_pages(&pages, &mut encoded).map_err(|e| e.to_string())?;
    let batch_bytes = batch.to_bytes().map_err(|e| e.to_string())?;
    encoded.extend_from_slice(
        &u32::try_from(batch_bytes.len())
            .map_err(|_| "trade receipt batch length")?
            .to_le_bytes(),
    );
    encoded.extend_from_slice(&batch_bytes);
    let checked = check_payload(&encoded)?;
    if block_tx_hashes.get(tx_index) != Some(&checked.leaf.0)
        || crate::tx_tree::root_from_hashes(block_tx_hashes) != header.tx_root
    {
        return Err("trade receipt group position".into());
    }
    let receipt = ParanoidReceipt {
        construction_marker: RECEIPT_CONSTRUCTION_MARKER,
        paged_spend: encoded,
        tx_index: u16::try_from(tx_index).map_err(|_| "trade receipt index")?,
        tx_count: u16::try_from(block_tx_hashes.len()).map_err(|_| "trade receipt count")?,
        merkle_path: crate::tx_tree::path_from_hashes(block_tx_hashes, tx_index),
        claimed_root: header.tx_root,
        claimed_height: header.height,
        summary: checked.summary,
    };
    if receipt.to_bytes().len() > MAX_RPC_RECEIPT_BYTES {
        return Err("trade receipt byte limit".into());
    }
    Ok(receipt)
}

pub fn trade_receipt_details(receipt: &ParanoidReceipt) -> Option<TradeReceiptDetails> {
    Some(check_receipt(receipt)?.details)
}

/// Resolve an individual policy through the group's committed trade set.
pub fn trade_receipt_for_policy(
    payload: &crate::block::payload::BlockBodyPayload,
    parent: &BlockHeader,
    authorization_id: &[u8; 32],
) -> Result<Option<ParanoidReceipt>, String> {
    let mut selected = None;
    for batch in payload.trade_batches() {
        for (index, policy) in batch.policies().iter().enumerate() {
            if policy.authorization_id().map_err(|e| e.to_string())?.0 == *authorization_id {
                if selected.replace((batch, index)).is_some() {
                    return Err("trade receipt duplicate policy".into());
                }
            }
        }
    }
    let Some((batch, policy_index)) = selected else {
        return Ok(None);
    };
    let block = payload.block();
    let commitment = batch.root().map_err(|e| e.to_string())?;
    let stream = crate::block::native_assets::validate_scheduled_block_page_stream(
        &block.transactions,
        block.header.height,
    )
    .map_err(|e| e.to_string())?;
    let (index, group) = stream
        .groups()
        .enumerate()
        .find(|(_, group)| {
            matches!(
                group.kind,
                crate::block::native_assets::ScheduledSpendKind::Native(facts)
                    if facts.operation == NativeOperation::Financial(
                        FinancialOperation::ExecuteTrades { commitment }
                    )
            )
        })
        .ok_or("trade receipt group missing")?;
    let hashes: Vec<_> = stream
        .logical_txids(&block.transactions)
        .into_iter()
        .map(|id| id.0)
        .collect();
    generate_trade_receipt(
        &block.header,
        parent,
        &block.transactions[group.body_start..group.body_start + group.page_count],
        stream.user_start_index() + index,
        &hashes,
        batch,
        policy_index,
    )
    .map(Some)
}

pub(super) fn check_receipt(receipt: &ParanoidReceipt) -> Option<CheckedTradeReceipt> {
    if receipt.construction_marker != RECEIPT_CONSTRUCTION_MARKER {
        return None;
    }
    let checked = check_payload(&receipt.paged_spend).ok()?;
    if receipt.claimed_height != checked.header.height
        || receipt.claimed_root != checked.header.tx_root
        || receipt.summary != checked.summary
        || !crate::tx_tree::verify_path(
            checked.leaf.0,
            &receipt.merkle_path,
            usize::from(receipt.tx_index),
            usize::from(receipt.tx_count),
            receipt.claimed_root,
        )
    {
        return None;
    }
    Some(checked)
}

pub(super) fn claimed_header(bytes: &[u8]) -> Result<BlockHeader, String> {
    if !bytes.starts_with(MAGIC) || bytes.len() > MAX_RPC_RECEIPT_BYTES {
        return Err("trade receipt framing".into());
    }
    let mut cursor = bytes.get(8..).ok_or("trade receipt truncated")?;
    BlockHeader::from_bytes(&take::<BLOCK_HEADER_WIRE_SIZE>(&mut cursor)?)
        .map_err(|e| format!("trade receipt header: {e:?}"))
}

pub(super) fn check_payload(bytes: &[u8]) -> Result<CheckedTradeReceipt, String> {
    if !bytes.starts_with(MAGIC) || bytes.len() > MAX_RPC_RECEIPT_BYTES {
        return Err("trade receipt framing".into());
    }
    let mut cursor = &bytes[MAGIC.len()..];
    let policy_index = usize::from(u16::from_le_bytes(take::<2>(&mut cursor)?));
    if take::<2>(&mut cursor)? != [0; 2] {
        return Err("trade receipt reserved bytes".into());
    }
    let header = BlockHeader::from_bytes(&take::<BLOCK_HEADER_WIRE_SIZE>(&mut cursor)?)
        .map_err(|e| format!("trade receipt header: {e:?}"))?;
    let parent = BlockHeader::from_bytes(&take::<BLOCK_HEADER_WIRE_SIZE>(&mut cursor)?)
        .map_err(|e| format!("trade receipt parent: {e:?}"))?;
    if parent.height.checked_add(1) != Some(header.height)
        || crate::block_id(&parent) != header.prev_block_hash
        || !crate::consensus::params::v2_1_active(header.height)
    {
        return Err("trade receipt boundary".into());
    }
    let (pages, facts) = decode_native_pages(&mut cursor).map_err(|e| e.to_string())?;
    let size = u32::from_le_bytes(take::<4>(&mut cursor)?) as usize;
    if cursor.len() != size || facts.chain != crate::state::native_assets::native_chain_id() {
        return Err("trade receipt batch framing".into());
    }
    let batch = TradeBatch::from_bytes(cursor).map_err(|e| e.to_string())?;
    let policy = batch
        .policies()
        .get(policy_index)
        .ok_or("trade receipt policy index")?;
    let boundary = TradeBoundary {
        chain: facts.chain,
        epoch_anchor: facts.epoch_anchor,
        parent_id: header.prev_block_hash,
        height: header.height,
    };
    let fee_context = MarketFeeContext::from_parent(&parent);
    let mut fees = Vec::with_capacity(batch.policies().len());
    for intent in batch.policies() {
        let mut quotes = [0; 3];
        for (index, quote) in quotes.iter_mut().enumerate() {
            *quote = fee_context
                .required(intent.funding.len() + 1, index + 2)
                .map_err(|e| e.to_string())?;
        }
        fees.push(TradeFeeQuotes(quotes));
    }
    let plan = batch.checked(boundary).map_err(|e| e.to_string())?;
    let mut outcomes: Vec<Option<TradeOutcome>> = vec![None; batch.policies().len()];
    for fill in plan.fills() {
        outcomes[fill.source_index] = Some(fill.outcome);
    }
    let outputs: Vec<_> = pages[1..]
        .iter()
        .flat_map(|page| page.body.live_outputs().map(|(_, output)| *output))
        .collect();
    let mut offset = 0usize;
    let mut payout_slots = Vec::with_capacity(batch.policies().len());
    for (index, intent) in batch.policies().iter().enumerate() {
        let charge = quote_charge(
            intent,
            boundary,
            outcomes[index].ok_or("trade receipt missing fill")?,
            fees[index],
        )
        .map_err(|e| e.to_string())?;
        let end = offset
            .checked_add(charge.payouts.len())
            .ok_or("trade receipt payout count")?;
        let claims = outputs
            .get(offset..end)
            .ok_or("trade receipt payout count")?;
        payout_slots.push(claims.iter().map(|output| output.slot_index).collect());
        offset = end;
    }
    if outputs.len() != offset + 1 {
        return Err("trade receipt market successor".into());
    }
    let execution = TradeExecution::new(
        &batch,
        boundary,
        &fees,
        &TradeOutputSlots {
            payouts: payout_slots,
            market: outputs[offset].slot_index,
        },
    )
    .map_err(|e| e.to_string())?;
    let expected =
        NativeIntent::from_trade_execution(&execution, |_| None).map_err(|e| e.to_string())?;
    if expected.pages != pages {
        return Err("trade receipt execution pages".into());
    }
    let charge = &execution.charges()[policy_index];
    let begin: usize = execution.charges()[..policy_index]
        .iter()
        .map(|charge| charge.payouts.len())
        .sum();
    let payout_claims = &execution.outputs()[begin..begin + charge.payouts.len()];
    let summary = TxSummary {
        logical_txid: charge.authorization_id.0,
        inputs: policy
            .funding
            .iter()
            .map(|claim| (claim.input.slot_index, claim.root))
            .collect(),
        outputs: payout_claims
            .iter()
            .map(|claim| {
                (
                    claim.output.slot_index,
                    claim.output.amount,
                    claim.output.owner,
                )
            })
            .collect(),
        fee_micronoid: charge.fee,
        confirmed_height: header.height,
        confirmed_unix: header.timestamp,
    };
    let execution_index = plan
        .fills()
        .iter()
        .position(|fill| fill.source_index == policy_index)
        .ok_or("trade receipt execution index")?;
    let outcome = outcomes[policy_index].ok_or("trade receipt missing fill")?;
    let details = TradeReceiptDetails {
        authorization_id: charge.authorization_id,
        group_id: facts.logical_txid,
        asset: policy.policy.asset,
        owner: policy.policy.owner,
        recipient: policy.policy.recipient,
        side: policy.policy.side,
        gross_input: policy.policy.gross_input,
        spent_input: outcome.spent_input,
        output: outcome.output,
        minimum_output: policy.policy.minimum_output,
        fee_limit: policy.policy.fee_limit,
        valid_from: policy.policy.valid_from,
        valid_until: policy.policy.valid_until,
        market_fee: outcome.market_fee,
        network_fee: charge.fee,
        execution_index,
        payouts: charge.payouts.clone(),
    };
    let leaf = facts.logical_txid;
    Ok(CheckedTradeReceipt {
        header,
        leaf,
        summary,
        details,
    })
}

fn take<const N: usize>(cursor: &mut &[u8]) -> Result<[u8; N], String> {
    if cursor.len() < N {
        return Err("trade receipt truncated".into());
    }
    let value = cursor[..N]
        .try_into()
        .map_err(|_| "trade receipt truncated")?;
    *cursor = &cursor[N..];
    Ok(value)
}
