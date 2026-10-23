// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Retained canonical transaction projection shared by Scope queries.

use std::collections::{BTreeMap, BTreeSet};

use noid_chain::{
    block::{
        native_assets::{
            validate_scheduled_block_page_stream, ScheduledBlockPageStream, ScheduledSpendKind,
        },
        payload::BlockBodyPayload,
    },
    consensus::{
        paged_spend::BlockProofClass,
        receipt::{NativeReceiptDetails, TradeReceiptDetails},
    },
    state::native_assets::market::liquidity::MarketFeeContext,
    BlockHeader,
};
use noid_poseidon2b::primitives::Address;
use noid_tx::{
    native_assets::{
        financial::FinancialOperation,
        native_creation_id,
        trade::{execution::TradeFeeQuotes, sequencing::TradeBoundary},
        transition::{NativeInputClaim, NativeOperation, NativeOutputClaim},
        wire::NativeIntent,
    },
    TxPage,
};

use crate::types::{
    BlockTradeInfo, BlockTransactionInfo, BlockTransactionInputInfo, BlockTransactionOutputInfo,
    RecentTransactionInfo,
};

pub(super) struct Projection {
    pub transactions: Vec<ProjectedTransaction>,
    pub proof_class: BlockProofClass,
    pub user_pages: u16,
    pub live_inputs: u16,
    pub live_outputs: u16,
    pub reward_micronoid: u64,
    pub block_bytes: u64,
}

pub(super) struct ProjectedTransaction {
    pub details: BlockTransactionInfo,
    participants: BTreeSet<[u8; 32]>,
}

impl Projection {
    pub fn summaries(
        self,
        header: &BlockHeader,
        address: Option<&Address>,
    ) -> Vec<RecentTransactionInfo> {
        let block_hash = hex::encode(super::block_id(header));
        self.transactions
            .into_iter()
            .filter_map(|projected| {
                if address.is_some_and(|owner| !projected.participants.contains(&owner.0)) {
                    return None;
                }
                let tx = projected.details;
                let spent = address.map(|owner| {
                    tx.inputs
                        .iter()
                        .filter(|input| !input.native && input.owner == owner.to_bech32())
                        .map(|input| u128::from(input.amount_micronoid))
                        .sum::<u128>()
                        .to_string()
                });
                let received = address.map(|owner| {
                    tx.outputs
                        .iter()
                        .filter(|output| !output.native && output.owner == owner.to_bech32())
                        .map(|output| u128::from(output.amount_micronoid))
                        .sum::<u128>()
                        .to_string()
                });
                Some(RecentTransactionInfo {
                    height: header.height,
                    block_hash: block_hash.clone(),
                    timestamp: header.timestamp,
                    position: tx.position,
                    txid: tx.txid,
                    page_count: tx.page_count,
                    live_inputs: tx.live_inputs,
                    live_outputs: tx.live_outputs,
                    fee_micronoid: tx.fee_micronoid,
                    coinbase: tx.coinbase,
                    development_payout: tx.development_payout,
                    contract: tx.contract,
                    native_operation: tx.native.map(|native| native.operation),
                    trade_count: tx.trades.len(),
                    input_owner: tx.input_owner,
                    input_sum_micronoid: tx.input_sum_micronoid,
                    output_sum_micronoid: tx.output_sum_micronoid,
                    address_spent_micronoid: spent,
                    address_received_micronoid: received,
                })
            })
            .collect()
    }
}

pub(super) fn decode(
    header: &BlockHeader,
    parent: Option<&BlockHeader>,
    bytes: &[u8],
) -> Result<Projection, String> {
    let payload = BlockBodyPayload::decode(bytes)
        .map_err(|error| format!("decode retained body payload: {error}"))?;
    let block = payload.block();
    if block.header != *header {
        return Err("retained block header does not match canonical header".into());
    }
    let stream = validate_scheduled_block_page_stream(&block.transactions, header.height)
        .map_err(|error| error.to_string())?;
    let logical_ids = stream.logical_txids(&block.transactions);
    let hashes: Vec<_> = logical_ids.iter().map(|id| id.0).collect();
    if noid_chain::tx_tree::root_from_hashes(&hashes) != header.tx_root {
        return Err("retained logical transaction root does not match canonical header".into());
    }
    let proof_class = match &stream {
        ScheduledBlockPageStream::Ordinary(facts) => facts.proof_class,
        ScheduledBlockPageStream::Native(facts) => facts.proof_class,
    };
    let output_count = block
        .transactions
        .iter()
        .map(|tx| tx.body.live_outputs().count())
        .sum::<usize>();
    let mut allocator = header
        .alloc_counter
        .checked_sub(output_count as u64)
        .ok_or("retained block allocator counter underflow")?;
    let openings: BTreeMap<_, _> = payload
        .native_openings()
        .iter()
        .map(|opening| (opening.root().0, *opening))
        .collect();
    let mut batches = BTreeMap::new();
    for batch in payload.trade_batches() {
        batches.insert(batch.root().map_err(|error| error.to_string())?.0, batch);
    }
    let system = (0..stream.user_start_index()).map(|index| (index, 1, None));
    let users = stream
        .groups()
        .map(|group| (group.body_start, group.page_count, Some(group)));
    let mut transactions = Vec::with_capacity(logical_ids.len());
    for (position, (start, count, group)) in system.chain(users).enumerate() {
        let pages = &block.transactions[start..start + count];
        let native = match group.map(|group| group.kind) {
            Some(ScheduledSpendKind::Native(facts)) => Some(facts),
            _ => None,
        };
        let mut participants = BTreeSet::new();
        let mut native_info = None;
        let mut trades = Vec::new();
        if let Some(facts) = native {
            let intent = NativeIntent::from_pages_with_openings(
                pages
                    .iter()
                    .map(|tx| TxPage {
                        body: tx.body.clone(),
                    })
                    .collect(),
                |root| openings.get(&root.0).copied(),
            )
            .map_err(|error| error.to_string())?;
            let details = NativeReceiptDetails {
                operation: facts.operation,
                authority: facts.authority,
                inputs: pages
                    .iter()
                    .skip(1)
                    .flat_map(|page| {
                        page.body
                            .live_inputs()
                            .map(|(_, input)| (*input, page.body.input_owner))
                    })
                    .zip(&intent.input_openings)
                    .map(|((input, root), opening)| NativeInputClaim {
                        input,
                        root,
                        opening: *opening,
                    })
                    .collect(),
                outputs: pages
                    .iter()
                    .skip(1)
                    .flat_map(|page| page.body.live_outputs().map(|(_, output)| *output))
                    .zip(&intent.output_openings)
                    .map(|(output, opening)| NativeOutputClaim {
                        output,
                        opening: *opening,
                    })
                    .collect(),
                dependencies: intent.dependencies.clone(),
            };
            participants.extend(details.participants().iter().map(|owner| owner.0));
            native_info = Some(details.into());
            if let NativeOperation::Financial(FinancialOperation::ExecuteTrades { commitment }) =
                facts.operation
            {
                let parent = parent.ok_or("retained trade parent unavailable")?;
                if parent.height.checked_add(1) != Some(header.height)
                    || super::block_id(parent) != header.prev_block_hash
                {
                    return Err("retained trade parent does not match canonical header".into());
                }
                let batch = batches
                    .remove(&commitment.0)
                    .ok_or("retained trade batch unavailable")?;
                let context = MarketFeeContext::from_parent(parent);
                let fees = batch
                    .policies()
                    .iter()
                    .map(|policy| {
                        let mut fees = [0; 3];
                        for (index, fee) in fees.iter_mut().enumerate() {
                            *fee = context
                                .required(policy.funding.len() + 1, index + 2)
                                .map_err(|error| error.to_string())?;
                        }
                        Ok(TradeFeeQuotes(fees))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let execution = intent
                    .checked_trade(
                        TradeBoundary {
                            chain: facts.chain,
                            epoch_anchor: facts.epoch_anchor,
                            parent_id: header.prev_block_hash,
                            height: header.height,
                        },
                        batch,
                        &fees,
                    )
                    .map_err(|error| error.to_string())?;
                for (execution_index, fill) in execution.plan().fills().iter().enumerate() {
                    let policy = &batch.policies()[fill.source_index].policy;
                    let charge = &execution.charges()[fill.source_index];
                    participants.extend([policy.owner.0, policy.recipient.0]);
                    let details = TradeReceiptDetails {
                        authorization_id: charge.authorization_id,
                        group_id: facts.logical_txid,
                        asset: policy.asset,
                        owner: policy.owner,
                        recipient: policy.recipient,
                        side: policy.side,
                        gross_input: policy.gross_input,
                        spent_input: fill.outcome.spent_input,
                        output: fill.outcome.output,
                        minimum_output: policy.minimum_output,
                        fee_limit: policy.fee_limit,
                        valid_from: policy.valid_from,
                        valid_until: policy.valid_until,
                        market_fee: fill.outcome.market_fee,
                        network_fee: charge.fee,
                        execution_index,
                        payouts: charge.payouts.clone(),
                    };
                    trades.push(BlockTradeInfo {
                        authorization_id: hex::encode(charge.authorization_id.0),
                        network_fee_micronoid: charge.fee,
                        trade: details.into(),
                    });
                }
            }
        }
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        for (page_index, page) in pages.iter().enumerate() {
            for (lane, input) in page.body.live_inputs() {
                let is_native = native.is_some_and(|facts| facts.input_is_native(inputs.len()));
                if !is_native {
                    participants.insert(page.body.input_owner.0);
                }
                inputs.push(BlockTransactionInputInfo {
                    page: page_index as u16,
                    lane: lane as u8,
                    slot_index: input.slot_index,
                    amount_micronoid: input.amount,
                    creation_id: input.creation_id,
                    owner: page.body.input_owner.to_bech32(),
                    native: is_native,
                });
            }
            for (lane, output) in page.body.live_outputs() {
                allocator = allocator
                    .checked_add(1)
                    .ok_or("retained block allocator counter overflow")?;
                let is_native = native.is_some_and(|facts| facts.output_is_native(outputs.len()));
                let creation_id = if position == 0 {
                    noid_chain::consensus::params::coinbase_creation_id(header.height)
                } else if is_native {
                    native_creation_id(allocator).map_err(|error| error.to_string())?
                } else {
                    allocator
                };
                if !is_native {
                    participants.insert(output.owner.0);
                }
                outputs.push(BlockTransactionOutputInfo {
                    page: page_index as u16,
                    lane: lane as u8,
                    slot_index: output.slot_index,
                    amount_micronoid: output.amount,
                    owner: output.owner.to_bech32(),
                    creation_id,
                    native: is_native,
                });
            }
        }
        transactions.push(ProjectedTransaction {
            details: BlockTransactionInfo {
                position: position as u16,
                txid: hex::encode(logical_ids[position].0),
                page_count: count as u16,
                live_inputs: inputs.len() as u16,
                live_outputs: outputs.len() as u16,
                fee_micronoid: group.map_or(0, |group| group.fee()),
                coinbase: group.is_none(),
                development_payout: position == 1 && group.is_none(),
                contract: if native.is_none() {
                    super::contract_transaction_kind(pages[0].body.validity_bitmap)
                } else {
                    None
                },
                native: native_info,
                trades,
                epoch_anchor: hex::encode(
                    native.map_or(pages[0].body.epoch_anchor, |facts| facts.epoch_anchor),
                ),
                input_owner: group.map(|group| group.authority().to_bech32()),
                input_sum_micronoid: inputs
                    .iter()
                    .map(|input| u128::from(input.amount_micronoid))
                    .sum::<u128>()
                    .to_string(),
                output_sum_micronoid: outputs
                    .iter()
                    .map(|output| u128::from(output.amount_micronoid))
                    .sum::<u128>()
                    .to_string(),
                page_hashes: pages
                    .iter()
                    .map(|page| hex::encode(page.txid().0))
                    .collect(),
                inputs,
                outputs,
            },
            participants,
        });
    }
    if allocator != header.alloc_counter || !batches.is_empty() {
        return Err("retained transaction output or trade accounting mismatch".into());
    }
    let reward_micronoid = transactions[0]
        .details
        .outputs
        .iter()
        .try_fold(0u64, |sum, output| sum.checked_add(output.amount_micronoid))
        .ok_or("retained block reward overflow")?;
    Ok(Projection {
        transactions,
        proof_class,
        user_pages: stream.page_count() as u16,
        live_inputs: stream.live_inputs() as u16,
        live_outputs: output_count as u16,
        reward_micronoid,
        block_bytes: block
            .canonical_wire_len()
            .map_err(|error| format!("retained block bytes: {error:?}"))?
            as u64,
    })
}
