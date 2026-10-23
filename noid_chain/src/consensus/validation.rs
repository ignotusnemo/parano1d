// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Consensus checks shared by proof-native validation and in-memory utilities.
//!
//! Live full nodes use `validate_block_checks` as the cheap native first stage,
//! verify the block's fused recursive `HistoryStep`, then materialize and commit
//! the exact public state transition atomically. `validate_block_consensus` is
//! the sequential interpreter path for RAM tests and utilities.
//!
//! # Invariants checked here (SPEC §16)
//!
//!  ✅  Header chain (prev_hash, height, difficulty, timestamp, PoW)     [P.6]
//!  ✅  Mandatory canonical coinbase (exactly one, first, fixed bitmap)  [P.7 partial]
//!  ✅  Coinbase value ≤ block_reward(log_slots) + Σ claimable fees      [P.7 full]
//!  ✅  Per-tx: fixed canonical body and anchor structure                 [P.8]
//!  ✅  Cross-tx slot conflicts                                           [P.8]
//!  ✅  Decoder tx cap and semantic block budget                          [P.9]
//!  ✅  Sequential state transition (`validate_block_consensus` only)       [P.9]
//!
//! # Invariants checked by the production proof layer
//!
//!  ✅  Wallet authorization proof verifies for every user transaction
//!  ✅  Exact public transaction predicate verifies for every user transaction
//!  ✅  Exact authenticated state transition verifies state updates
//!  ✅  The sealed semantic header and recursive parent bind the complete step
//! Exact user epoch-anchor equality is checked by the owning chain context
//! before this state-free validation boundary.

use std::collections::BTreeSet;

use crate::block::native_assets::{
    validate_scheduled_block_page_stream, NativeBlockError, ScheduledBlockPageStream,
    ScheduledSpendKind,
};
use crate::block::{apply_block, Block, BlockPageStreamError};
use crate::block_header::BlockHeader;
use crate::consensus::{
    checks::{validate_block_slot_conflicts, validate_tx_consensus},
    emission::max_coinbase_value_from_claimable_fee_sum,
    fees::fee_breakdown,
    header::{validate_header, validate_header_template, validate_header_timeless},
    params::{
        BLOCK_MAX_ACTIONS, BLOCK_MAX_DISTINCT_SEGMENTS, BLOCK_MAX_LIVE_INPUTS, BLOCK_MAX_TXS,
        BLOCK_MAX_USER_OUTPUTS, BLOCK_MAX_USER_PAGES, LOG_SEGMENT_SIZE,
    },
    ConsensusError,
};
use crate::state::ChainState;

/// Parameters needed for header chain validation.
#[derive(Debug, Clone)]
pub struct AnchorInfo {
    /// Height of the ASERT anchor block.
    pub anchor_height: u64,
    /// Timestamp of the ASERT anchor block.
    pub anchor_timestamp: u64,
    /// Difficulty target at the ASERT anchor block.
    pub anchor_target: [u8; 32],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockResourcePreflight {
    pub user_page_count: usize,
    pub logical_tx_count: usize,
    pub live_input_count: usize,
    /// All live outputs, including coinbase.
    pub output_count: usize,
    /// Live inputs plus all live outputs, including coinbase.
    pub action_count: usize,
    pub touched_slot_count: usize,
    pub distinct_segment_count: usize,
    /// Missing digest nodes in the canonical structural multiproof frontier at
    /// this block's declared state depth.
    pub state_frontier_node_count: usize,
}

fn resource_limit(
    limit: &'static str,
    actual: usize,
    max: usize,
) -> Result<BlockResourcePreflight, ConsensusError> {
    Err(ConsensusError::BlockResourceLimitExceeded { limit, actual, max })
}

fn page_stream_consensus_error(error: BlockPageStreamError) -> ConsensusError {
    use crate::consensus::paged_spend::PagedSpendStreamError;
    match error {
        BlockPageStreamError::MissingCoinbase => ConsensusError::MissingCoinbase,
        BlockPageStreamError::CoinbaseNotFirst => ConsensusError::CoinbaseNotFirst,
        BlockPageStreamError::MultipleCoinbase => ConsensusError::MultipleCoinbase,
        BlockPageStreamError::PagedSpend(PagedSpendStreamError::BlockPageLimit {
            actual,
            capacity,
        }) => ConsensusError::BlockResourceLimitExceeded {
            limit: "user_pages",
            actual,
            max: capacity,
        },
        BlockPageStreamError::PagedSpend(PagedSpendStreamError::TooManyGroups {
            actual,
            capacity,
        }) => ConsensusError::BlockResourceLimitExceeded {
            limit: "logical_txs",
            actual,
            max: capacity,
        },
        BlockPageStreamError::PagedSpend(PagedSpendStreamError::BlockInputLimit {
            actual,
            capacity,
        }) => ConsensusError::BlockResourceLimitExceeded {
            limit: "live_inputs",
            actual,
            max: capacity,
        },
        BlockPageStreamError::PagedSpend(PagedSpendStreamError::BlockOutputLimit {
            actual,
            capacity,
        }) => ConsensusError::BlockResourceLimitExceeded {
            limit: "user_outputs",
            actual,
            max: capacity,
        },
        BlockPageStreamError::PagedSpend(
            PagedSpendStreamError::DuplicateInputSlot { .. }
            | PagedSpendStreamError::DuplicateOutputSlot { .. }
            | PagedSpendStreamError::InputOutputSlotOverlap { .. },
        ) => ConsensusError::SlotConflict,
        other => ConsensusError::InvalidPagedSpend(other.to_string()),
    }
}

fn checked_block_stream(block: &Block) -> Result<ScheduledBlockPageStream, ConsensusError> {
    if block.transactions.len() > BLOCK_MAX_TXS {
        return Err(ConsensusError::TooManyTxs);
    }
    if !(1..=32).contains(&block.header.log_slots) {
        return Err(ConsensusError::ShapeMismatch(
            "block log_slots is outside the u32 slot domain".into(),
        ));
    }
    validate_scheduled_block_page_stream(&block.transactions, block.header.height).map_err(
        |error| match error {
            NativeBlockError::System(error) => page_stream_consensus_error(error),
            NativeBlockError::SlotConflict => ConsensusError::SlotConflict,
            error => ConsensusError::InvalidPagedSpend(error.to_string()),
        },
    )
}

/// Count and bound the complete raw block resource surface before any
/// segment-sized work, proof decode, or state clone.
///
/// The fixed arrays bound each body before allocation. Live selectors drive
/// the consensus block caps and touched-slot/segment union.
pub fn validate_block_resource_preflight(
    block: &Block,
) -> Result<BlockResourcePreflight, ConsensusError> {
    let stream = checked_block_stream(block)?;
    validate_block_resources_with_stream(block, &stream)
}

fn validate_block_resources_with_stream(
    block: &Block,
    stream: &ScheduledBlockPageStream,
) -> Result<BlockResourcePreflight, ConsensusError> {
    if block.transactions.len() > BLOCK_MAX_TXS {
        return Err(ConsensusError::TooManyTxs);
    }
    if !(1..=32).contains(&block.header.log_slots) {
        return Err(ConsensusError::ShapeMismatch(
            "block log_slots is outside the u32 slot domain".into(),
        ));
    }
    let slot_domain = 1u64 << block.header.log_slots;

    let user_page_count = stream.page_count();
    let logical_tx_count = stream.logical_count();
    if user_page_count > BLOCK_MAX_USER_PAGES {
        return resource_limit("user_pages", user_page_count, BLOCK_MAX_USER_PAGES);
    }

    let mut live_input_count = 0usize;
    let mut output_count = 0usize;
    let mut touched_slots = BTreeSet::new();
    let mut segments = BTreeSet::new();
    for tx in &block.transactions {
        for (_, input) in tx.body.live_inputs() {
            if u64::from(input.slot_index) >= slot_domain {
                return Err(ConsensusError::ShapeMismatch(
                    "live input slot is outside block log_slots".into(),
                ));
            }
            live_input_count += 1;
            touched_slots.insert(input.slot_index);
            segments.insert(input.slot_index >> LOG_SEGMENT_SIZE);
        }
        for (_, output) in tx.body.live_outputs() {
            if u64::from(output.slot_index) >= slot_domain {
                return Err(ConsensusError::ShapeMismatch(
                    "live output slot is outside block log_slots".into(),
                ));
            }
            output_count += 1;
            touched_slots.insert(output.slot_index);
            segments.insert(output.slot_index >> LOG_SEGMENT_SIZE);
        }
        if segments.len() > BLOCK_MAX_DISTINCT_SEGMENTS {
            return resource_limit(
                "distinct_segments",
                segments.len(),
                BLOCK_MAX_DISTINCT_SEGMENTS,
            );
        }
    }

    if live_input_count > BLOCK_MAX_LIVE_INPUTS {
        return resource_limit("live_inputs", live_input_count, BLOCK_MAX_LIVE_INPUTS);
    }
    if output_count > BLOCK_MAX_USER_OUTPUTS + 1 {
        return resource_limit("outputs", output_count, BLOCK_MAX_USER_OUTPUTS + 1);
    }
    let action_count = live_input_count + output_count;
    if action_count > BLOCK_MAX_ACTIONS {
        return resource_limit("actions", action_count, BLOCK_MAX_ACTIONS);
    }

    let touched_indices: Vec<_> = touched_slots.iter().copied().collect();
    let state_frontier_node_count = if touched_indices.is_empty() {
        0
    } else {
        crate::sparse_merkle::expected_sibling_count(&touched_indices, block.header.log_slots)
            .expect("preflight already produced sorted in-range unique slots")
    };

    Ok(BlockResourcePreflight {
        user_page_count,
        logical_tx_count,
        live_input_count,
        output_count,
        action_count,
        touched_slot_count: touched_slots.len(),
        distinct_segment_count: segments.len(),
        state_frontier_node_count,
    })
}

fn validate_fee_policy_and_claimable_fee_sum(
    parent: &BlockHeader,
    stream: &ScheduledBlockPageStream,
) -> Result<u128, ConsensusError> {
    let mut claimable_fee_sum = 0u128;
    for group in stream.groups() {
        let actual = group.fee();
        let zero_fee = matches!(
            group.kind,
            ScheduledSpendKind::Native(facts)
                if matches!(
                    facts.operation,
                    noid_tx::native_assets::transition::NativeOperation::Financial(operation)
                        if operation.has_zero_fee()
                )
        );
        if zero_fee {
            if actual != 0 {
                return Err(ConsensusError::ShapeMismatch(
                    "native maintenance fee must be zero".into(),
                ));
            }
            continue;
        }
        let breakdown = fee_breakdown(
            group.live_inputs() as u64,
            group.live_outputs() as u64,
            parent.active_slot_count,
            parent.log_slots,
        );
        let required = breakdown.required_total;
        if actual < required {
            return Err(ConsensusError::BelowMinFee { required, actual });
        }
        claimable_fee_sum = claimable_fee_sum
            .checked_add(u128::from(actual.saturating_sub(breakdown.burned)))
            .ok_or_else(|| ConsensusError::ShapeMismatch("claimable fee sum overflow".into()))?;
    }
    Ok(claimable_fee_sum)
}

/// Validate the complete mandatory system-mint contract for a non-genesis block.
///
/// This is the single cheap, state-free predicate shared by every accepted
/// block entry point. Genesis is deliberately outside this contract and is
/// required to have an empty transaction list by `apply_genesis_block`.
pub fn validate_mandatory_coinbase(
    block: &Block,
    parent: &BlockHeader,
) -> Result<(), ConsensusError> {
    validate_mandatory_coinbase_with_schedule(block, parent, super::forks::ACTIVE_SCHEDULE)
}

pub fn validate_mandatory_coinbase_with_schedule(
    block: &Block,
    parent: &BlockHeader,
    schedule: super::forks::ForkSchedule,
) -> Result<(), ConsensusError> {
    let stream = checked_block_stream(block)?;
    validate_mandatory_coinbase_with_stream(block, parent, schedule, &stream)
}

fn validate_mandatory_coinbase_with_stream(
    block: &Block,
    parent: &BlockHeader,
    schedule: super::forks::ForkSchedule,
    stream: &ScheduledBlockPageStream,
) -> Result<(), ConsensusError> {
    let expected_anchor = crate::consensus::pow::block_id(parent);

    let coinbase = &block.transactions[0];
    // This one shared predicate owns fee/input/output counts and canonical
    // dead-entry encoding. Keeping it here (rather than relying on the later
    // per-transaction loop) makes the complete coinbase contract one atomic
    // cheap preflight.
    noid_tx::validate_body_semantics_no_hash(&coinbase.body)
        .map_err(|error| ConsensusError::ShapeMismatch(format!("coinbase semantics: {error}")))?;

    if coinbase.body.epoch_anchor != expected_anchor {
        return Err(ConsensusError::BadCoinbaseAnchor);
    }
    let output = &coinbase.body.outputs[0];
    if output.owner != block.header.miner_address {
        return Err(ConsensusError::BadCoinbaseOwner);
    }

    let allocation =
        crate::consensus::development_allocation::development_allocation_with_schedule(
            block.header.height,
            block.header.log_slots,
            schedule,
        )
        .map_err(|_| ConsensusError::BadDevelopmentPayout)?;

    match (allocation.payout_each, stream.has_development_payout()) {
        (Some(_), false) => return Err(ConsensusError::MissingDevelopmentPayout),
        (None, true) => return Err(ConsensusError::UnexpectedDevelopmentPayout),
        (None, false) => {}
        (Some(expected_amount), true) => {
            let payout = &block.transactions[1];
            noid_tx::validate_body_semantics_no_hash(&payout.body).map_err(|_| {
                ConsensusError::ShapeMismatch(
                    "development payout has non-canonical body semantics".into(),
                )
            })?;
            if payout.body.epoch_anchor != expected_anchor {
                return Err(ConsensusError::BadDevelopmentPayout);
            }
            let first = &payout.body.outputs[0];
            let second = &payout.body.outputs[1];
            if first.owner != crate::consensus::development_allocation::O1_NETWORK_FUND_ADDRESS
                || second.owner != crate::consensus::development_allocation::PARANO1D_LAB_ADDRESS
                || first.amount != expected_amount
                || second.amount != expected_amount
            {
                return Err(ConsensusError::BadDevelopmentPayout);
            }
        }
    }

    Ok(())
}

/// Run all native consensus checks WITHOUT applying the state transition.
///
/// Use this as the first step of the full-proof-native validation path:
///   1. `validate_block_checks()` — header + tx checks (no MDBX reads)
///   2. exact block transition verification
///   3. commit the verifier-sealed slot updates and counters atomically
///
/// Note: does NOT check `state_root` (that's done by minimal proof verification).
/// Does NOT check `active_slot_count` / `alloc_counter` (done by the exact
/// transition verifier).
pub fn validate_block_checks(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    finalized_active_counts: &[u64],
    local_time: u64,
    anchor: &AnchorInfo,
) -> Result<(), ConsensusError> {
    validate_block_checks_inner(
        block,
        parent,
        prev_timestamps,
        finalized_active_counts,
        anchor,
        Some(local_time),
        true,
        None,
    )
}

/// Run deterministic block consensus checks without local wall-clock policy.
///
/// This is the deterministic boundary for historical history proofs. Live node
/// admission must continue to use [`validate_block_checks`] so far-future
/// timestamps are filtered before relay/acceptance.
/// Run every block consensus check of a node-owned template except proof of
/// work (see `validate_header_template`).
pub fn validate_block_checks_template(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    finalized_active_counts: &[u64],
    local_time: u64,
    anchor: &AnchorInfo,
) -> Result<(), ConsensusError> {
    validate_block_checks_inner(
        block,
        parent,
        prev_timestamps,
        finalized_active_counts,
        anchor,
        Some(local_time),
        false,
        None,
    )
}

pub fn validate_block_checks_timeless(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    finalized_active_counts: &[u64],
    anchor: &AnchorInfo,
) -> Result<(), ConsensusError> {
    validate_block_checks_inner(
        block,
        parent,
        prev_timestamps,
        finalized_active_counts,
        anchor,
        None,
        true,
        None,
    )
}

/// Explicit candidate schedule; this does not select it for the network.
#[allow(clippy::too_many_arguments)]
pub fn validate_block_checks_with_schedule(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    finalized_active_counts: &[u64],
    local_time: Option<u64>,
    anchor: &AnchorInfo,
    check_pow: bool,
    schedule: super::forks::ForkSchedule,
) -> Result<(), ConsensusError> {
    validate_block_checks_inner(
        block,
        parent,
        prev_timestamps,
        finalized_active_counts,
        anchor,
        local_time,
        check_pow,
        Some(schedule),
    )
}

fn validate_block_checks_inner(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    finalized_active_counts: &[u64],
    anchor: &AnchorInfo,
    local_time: Option<u64>,
    check_pow: bool,
    schedule: Option<super::forks::ForkSchedule>,
) -> Result<(), ConsensusError> {
    // Bound the raw semantic surface before any O(n) consensus scan.  This is
    // also the first line of defence for direct in-memory callers that did not
    // arrive through the bounded wire decoder.
    let stream = checked_block_stream(block)?;
    validate_block_resources_with_stream(block, &stream)?;
    if let Some(schedule) = schedule {
        super::header::validate_header_with_schedule(
            &block.header,
            parent,
            prev_timestamps,
            finalized_active_counts,
            local_time,
            anchor.anchor_height,
            anchor.anchor_timestamp,
            &anchor.anchor_target,
            check_pow,
            schedule,
        )?;
    } else {
        match (local_time, check_pow) {
            (Some(local_time), true) => validate_header(
                &block.header,
                parent,
                prev_timestamps,
                finalized_active_counts,
                local_time,
                anchor.anchor_height,
                anchor.anchor_timestamp,
                &anchor.anchor_target,
            )?,
            (Some(local_time), false) => validate_header_template(
                &block.header,
                parent,
                prev_timestamps,
                finalized_active_counts,
                local_time,
                anchor.anchor_height,
                anchor.anchor_timestamp,
                &anchor.anchor_target,
            )?,
            (None, _) => validate_header_timeless(
                &block.header,
                parent,
                prev_timestamps,
                finalized_active_counts,
                anchor.anchor_height,
                anchor.anchor_timestamp,
                &anchor.anchor_target,
            )?,
        }
    }
    validate_mandatory_coinbase_with_stream(
        block,
        parent,
        schedule.unwrap_or(super::forks::ACTIVE_SCHEDULE),
        &stream,
    )?;
    validate_block_slot_conflicts(&block.transactions)?;
    validate_tx_consensus(&block.transactions[0])?;
    let claimable_fee_sum = validate_fee_policy_and_claimable_fee_sum(parent, &stream)?;
    if let Some(cb) = block.transactions.first() {
        if cb.body.is_coinbase {
            let cb_value = cb
                .body
                .live_outputs()
                .next()
                .expect("mandatory coinbase has output zero live")
                .1
                .amount;
            let max_allowed =
                super::emission::max_coinbase_value_from_claimable_fee_sum_with_schedule(
                    block.header.height,
                    block.header.log_slots,
                    claimable_fee_sum,
                    schedule.unwrap_or(super::forks::ACTIVE_SCHEDULE),
                )
                .map_err(|_| ConsensusError::BadDevelopmentPayout)?;
            if u128::from(cb_value) > max_allowed {
                return Err(ConsensusError::InflatedCoinbase);
            }
        }
    }
    Ok(())
}

/// Validate through the sequential interpreter and apply it to `state`.
///
/// This is not the live full-node production path. It is used by the in-memory
/// context and tests/utilities that intentionally recompute the transition
/// directly. Production validation uses:
/// `validate_block_checks` + exact transition verification + sealed commit.
///
/// On success, `state` is updated. On failure, `state` is left unchanged.
pub fn validate_block_consensus(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    finalized_active_counts: &[u64],
    local_time: u64,
    anchor: &AnchorInfo,
    state: &mut ChainState,
) -> Result<[u8; 32], ConsensusError> {
    // --- Header checks (P.6) ---
    validate_header(
        &block.header,
        parent,
        prev_timestamps,
        finalized_active_counts,
        local_time,
        anchor.anchor_height,
        anchor.anchor_timestamp,
        &anchor.anchor_target,
    )?;

    // --- Bounded canonical resource preflight ---
    let stream = checked_block_stream(block)?;
    validate_block_resources_with_stream(block, &stream)?;

    validate_mandatory_coinbase_with_stream(block, parent, super::forks::ACTIVE_SCHEDULE, &stream)?;

    // --- Cross-tx slot conflict check (P.8, §16 invariants 4-5) ---
    validate_block_slot_conflicts(&block.transactions)?;

    // Coinbase retains the fixed-body predicate. User pages were checked as
    // complete groups above; validating them independently would reject the
    // START/END bits and group-wide balance by construction.
    validate_tx_consensus(&block.transactions[0])?;

    let claimable_fee_sum = validate_fee_policy_and_claimable_fee_sum(parent, &stream)?;

    // --- Coinbase amount validation (P.7) ---
    // Sum fees directly from &Transaction references — no TxBody cloning.
    if let Some(cb) = block.transactions.first() {
        if cb.body.is_coinbase {
            let cb_value = cb
                .body
                .live_outputs()
                .next()
                .expect("mandatory coinbase has output zero live")
                .1
                .amount;

            let max_allowed = max_coinbase_value_from_claimable_fee_sum(
                block.header.height,
                block.header.log_slots,
                claimable_fee_sum,
            );
            if u128::from(cb_value) > max_allowed {
                return Err(ConsensusError::InflatedCoinbase);
            }
        }
    }

    // --- Sequential state transition (apply_block handles state_root, active counts, etc.) ---
    // apply_block returns Err(BlockApplyError) on mismatch; map to ConsensusError.
    apply_block(state, block).map_err(|e| {
        use crate::block::BlockApplyError;
        match e {
            BlockApplyError::TooManyTransactions => ConsensusError::TooManyTxs,
            BlockApplyError::InvalidTxBody => {
                ConsensusError::ShapeMismatch("invalid fixed transaction body".to_string())
            }
            BlockApplyError::InvalidPagedSpend => {
                ConsensusError::InvalidPagedSpend("invalid block page stream".to_string())
            }
            BlockApplyError::HeaderStateRootMismatch => ConsensusError::BadStateRoot,
            BlockApplyError::HeaderTxRootMismatch => ConsensusError::BadTxRoot,
            _ => ConsensusError::ShapeMismatch(format!("{:?}", e)),
        }
    })?;

    Ok(block.header.state_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::params::GENESIS_TARGET;
    use crate::consensus::pow::block_id;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, PAGED_SPEND_END_BIT,
        PAGED_SPEND_START_BIT, TX_INPUTS, TX_OUTPUTS,
    };

    fn header(height: u64) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            timestamp: height,
            height,
            miner_address: Address([9u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    fn coinbase(parent: &BlockHeader) -> Transaction {
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 15_000_000,
            amount: 1,
            owner: Address([9u8; 32]),
        };
        Transaction::new(TxBody {
            epoch_anchor: block_id(parent),
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        })
    }

    fn development_payout(parent: &BlockHeader, amount: u64) -> Transaction {
        Transaction::new(TxBody {
            epoch_anchor: block_id(parent),
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: [
                TxOutput {
                    slot_index: 15_000_001,
                    amount,
                    owner: crate::consensus::development_allocation::O1_NETWORK_FUND_ADDRESS,
                },
                TxOutput {
                    slot_index: 15_000_002,
                    amount,
                    owner: crate::consensus::development_allocation::PARANO1D_LAB_ADDRESS,
                },
            ],
            validity_bitmap: output_bitmap_bit(0) | output_bitmap_bit(1),
            is_coinbase: true,
        })
    }

    fn user(index: usize, live_inputs: usize, live_outputs: usize) -> Transaction {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        for (i, input) in inputs.iter_mut().take(live_inputs).enumerate() {
            *input = TxInput {
                slot_index: (index * 16 + i) as u32,
                amount: 2,
                creation_id: 1,
            };
        }
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        for (i, output) in outputs.iter_mut().take(live_outputs).enumerate() {
            *output = TxOutput {
                slot_index: (8_000_000 + index * 2 + i) as u32,
                amount: 1,
                owner: Address([2u8; 32]),
            };
        }
        let input_sum = (live_inputs as u64) * 2;
        let output_sum = live_outputs as u64;
        let input_bits = if live_inputs == 0 {
            0
        } else {
            (1u16 << live_inputs) - 1
        };
        let output_bits = (0..live_outputs).fold(0u16, |bits, i| bits | output_bitmap_bit(i));
        Transaction::new(TxBody {
            epoch_anchor: [7u8; 32],
            fee: input_sum - output_sum,
            input_owner: Address([1u8; 32]),
            inputs,
            outputs,
            validity_bitmap: input_bits | output_bits | PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        })
    }

    #[test]
    fn max_real_block_surface_is_exact() {
        let parent = header(0);
        let mut transactions = vec![coinbase(&parent)];
        transactions.extend((0..255).map(|i| user(i, 4, 2)));
        let block = Block {
            header: header(1),
            transactions,
        };
        let counts = validate_block_resource_preflight(&block).unwrap();
        assert_eq!(counts.user_page_count, 255);
        assert_eq!(counts.logical_tx_count, 255);
        assert_eq!(counts.live_input_count, 1_020);
        assert_eq!(counts.output_count, 511);
        assert_eq!(counts.action_count, 1_531);
        assert_eq!(counts.touched_slot_count, 1_531);
    }

    #[test]
    fn decoder_and_live_caps_reject_overflow() {
        let parent = header(0);
        let mut transactions = vec![coinbase(&parent)];
        transactions.extend((0..256).map(|i| user(i, 1, 1)));
        let block = Block {
            header: header(1),
            transactions,
        };
        assert_eq!(
            validate_block_resource_preflight(&block),
            Err(ConsensusError::TooManyTxs)
        );

        let mut transactions = vec![coinbase(&parent)];
        transactions.extend((0..128).map(|i| user(i, 8, 1)));
        let block = Block {
            header: header(1),
            transactions,
        };
        assert!(matches!(
            validate_block_resource_preflight(&block),
            Err(ConsensusError::BlockResourceLimitExceeded {
                limit: "live_inputs",
                ..
            })
        ));
    }

    #[test]
    fn mandatory_coinbase_is_one_exact_fixed_body() {
        let parent = header(0);
        let mut block = Block {
            header: header(1),
            transactions: vec![coinbase(&parent)],
        };
        assert_eq!(validate_mandatory_coinbase(&block, &parent), Ok(()));

        block.transactions[0].body.input_owner = Address([1u8; 32]);
        assert!(matches!(
            validate_mandatory_coinbase(&block, &parent),
            Err(ConsensusError::ShapeMismatch(_))
        ));
    }

    #[test]
    fn scheduled_development_payout_is_mandatory_and_exact() {
        use crate::consensus::development_allocation::{
            development_allocation_at_height, development_share_each,
        };
        use crate::consensus::emission::block_reward_at_height;

        let period = if crate::consensus::params::ISOLATED_V2_FORK_TESTNET {
            2880
        } else {
            4320
        };
        let due = if crate::consensus::params::ISOLATED_V2_FORK_TESTNET {
            10 + period - 1
        } else {
            period
        };
        let parent = header(due - 1);
        let share = development_share_each(block_reward_at_height(due, parent.log_slots)).unwrap();
        let allocation = development_allocation_at_height(due, parent.log_slots).unwrap();
        let amount = allocation.payout_each.unwrap();
        let block = Block {
            header: header(due),
            transactions: vec![coinbase(&parent), development_payout(&parent, amount)],
        };
        assert_eq!(amount, share * period);
        assert_eq!(validate_mandatory_coinbase(&block, &parent), Ok(()));

        let mut missing = block.clone();
        missing.transactions.pop();
        assert_eq!(
            validate_mandatory_coinbase(&missing, &parent),
            Err(ConsensusError::MissingDevelopmentPayout)
        );

        let mut wrong_amount = block.clone();
        wrong_amount.transactions[1].body.outputs[0].amount += 1;
        assert_eq!(
            validate_mandatory_coinbase(&wrong_amount, &parent),
            Err(ConsensusError::BadDevelopmentPayout)
        );

        let mut wrong_recipient = block.clone();
        wrong_recipient.transactions[1].body.outputs.swap(0, 1);
        assert_eq!(
            validate_mandatory_coinbase(&wrong_recipient, &parent),
            Err(ConsensusError::BadDevelopmentPayout)
        );
    }

    #[test]
    fn unscheduled_development_payout_is_rejected() {
        let parent = header(0);
        let block = Block {
            header: header(1),
            transactions: vec![coinbase(&parent), development_payout(&parent, 1)],
        };
        assert_eq!(
            validate_mandatory_coinbase(&block, &parent),
            Err(ConsensusError::UnexpectedDevelopmentPayout)
        );
    }

    #[test]
    fn explicit_fork_schedule_binds_the_coinbase_ceiling_and_system_records() {
        use crate::consensus::development_allocation::{
            development_allocation_end_height_with_schedule, development_allocation_with_schedule,
        };
        use crate::consensus::forks::{ForkSchedule, V2Activation};
        // This intentionally differs from the network schedule so a hidden
        // use of ACTIVE_SCHEDULE cannot pass the explicit validation path.
        let h = 4320;
        let schedule = ForkSchedule::new(Some(5), V2Activation::new(h, 30)).unwrap();
        let end = development_allocation_end_height_with_schedule(schedule);
        let mut heights = vec![h - 1, h, h + 2878, h + 2879, end, end + 1];
        for epoch in 1..super::super::emission::V2_REWARDS_MICRONOID.len() {
            let threshold = h + epoch as u64 * super::super::emission::V2_REWARD_INTERVAL_BLOCKS;
            heights.extend([threshold - 1, threshold, threshold + 1, threshold + 2879]);
        }
        for height in heights {
            for level in 24..=32 {
                let mut parent = header(height - 1);
                parent.log_slots = level;
                let allocation =
                    development_allocation_with_schedule(height, level, schedule).unwrap();
                let mut child = header(height);
                child.log_slots = level;
                child.prev_block_hash = block_id(&parent);
                child.timestamp = parent.timestamp + schedule.block_time(height);
                let anchor = AnchorInfo {
                    anchor_height: parent.height,
                    anchor_timestamp: parent.timestamp,
                    anchor_target: parent.difficulty_target,
                };
                let mut body = coinbase(&parent).body;
                body.outputs[0].amount = allocation.miner_subsidy;
                let mut transactions = vec![Transaction::new(body)];
                if let Some(amount) = allocation.payout_each {
                    transactions.push(development_payout(&parent, amount));
                }
                let block = Block {
                    header: child,
                    transactions,
                };
                let check = |block: &Block| {
                    validate_block_checks_with_schedule(
                        block,
                        &parent,
                        &[parent.timestamp],
                        &[],
                        None,
                        &anchor,
                        false,
                        schedule,
                    )
                };
                assert_eq!(check(&block), Ok(()), "height={height}, level={level}");
                let mut inflated = block.clone();
                let mut body = inflated.transactions[0].body.clone();
                body.outputs[0].amount += 1;
                inflated.transactions[0] = Transaction::new(body);
                assert_eq!(check(&inflated), Err(ConsensusError::InflatedCoinbase));

                let mut wrong_records = block;
                if allocation.payout_due {
                    wrong_records.transactions.pop();
                    assert_eq!(
                        check(&wrong_records),
                        Err(ConsensusError::MissingDevelopmentPayout)
                    );
                } else {
                    wrong_records
                        .transactions
                        .push(development_payout(&parent, 1));
                    assert_eq!(
                        check(&wrong_records),
                        Err(ConsensusError::UnexpectedDevelopmentPayout)
                    );
                }
            }
        }
    }
}
