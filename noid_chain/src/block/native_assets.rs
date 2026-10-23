// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Height-bound native groups and exact accepted-block materialization.

use std::collections::{BTreeMap, BTreeSet};

pub mod financial;
use financial::{FinancialBlockError, FinancialBlockTracker, FinancialHeaderWindow};
use noid_tx::native_assets::transition::NativeOperation;

use crate::state::native_assets::trade::{prepare_trade_batch_from_claims, TradeStateError};
use noid_poseidon2b::primitives::{Address, Digest, TxBodyHash};
use noid_tx::native_assets::transition::{NativeContext, NativeInputClaim, NativeOutputClaim};
use noid_tx::native_assets::wire::{
    is_native_header, validate_native_pages, NativePageFacts, NativeWireError,
};
use noid_tx::native_assets::{
    financial::FinancialOperation,
    trade::{batch::TradeBatch, sequencing::TradeBoundary},
    NativeOpening,
};
use noid_tx::{validate_paged_spend, PagedSpendError, PagedSpendFacts, Transaction, TxPage};

use super::{Block, BlockApplyError, BlockPageStreamError, BLOCK_MAX_TXS};
use crate::consensus::paged_spend::BlockProofClass;
use crate::state::native_assets::{
    apply_checked_native_deferred_root, apply_native_deferred_root, native_chain_id,
    NativeApplyError, NativeConsumedOpening, NativeCreatedOpening,
};
use crate::state::{apply_tx_checked_deferred_root, ApplyError, ChainState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockSpendKind {
    Ordinary(PagedSpendFacts),
    Native(NativePageFacts),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSpendGroup {
    pub body_start: usize,
    pub page_count: usize,
    pub kind: BlockSpendKind,
}

impl BlockSpendGroup {
    pub fn logical_txid(&self) -> TxBodyHash {
        match &self.kind {
            BlockSpendKind::Ordinary(facts) => facts.logical_txid,
            BlockSpendKind::Native(facts) => facts.logical_txid,
        }
    }

    pub fn live_inputs(&self) -> usize {
        match &self.kind {
            BlockSpendKind::Ordinary(facts) => usize::from(facts.live_inputs),
            BlockSpendKind::Native(facts) => facts.live_inputs,
        }
    }

    pub fn live_outputs(&self) -> usize {
        match &self.kind {
            BlockSpendKind::Ordinary(facts) => usize::from(facts.live_outputs),
            BlockSpendKind::Native(facts) => facts.live_outputs,
        }
    }

    pub fn fee(&self) -> u64 {
        match &self.kind {
            BlockSpendKind::Ordinary(facts) => facts.fee,
            BlockSpendKind::Native(facts) => facts.fee,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeBlockStreamFacts {
    pub proof_class: BlockProofClass,
    pub groups: Vec<BlockSpendGroup>,
    pub page_count: usize,
    pub live_inputs: usize,
    pub live_outputs: usize,
    pub user_start_index: usize,
}

/// Height-selected layout shared by resource, fee and candidate validation.
/// Earlier ordinary streams retain their original parser and exact facts.
pub enum ScheduledBlockPageStream {
    Ordinary(super::BlockPageStreamFacts),
    Native(NativeBlockStreamFacts),
}

#[derive(Clone, Copy)]
pub enum ScheduledSpendKind<'a> {
    Ordinary(&'a PagedSpendFacts),
    Native(&'a NativePageFacts),
}

#[derive(Clone, Copy)]
pub struct ScheduledSpendGroup<'a> {
    pub body_start: usize,
    pub page_count: usize,
    pub kind: ScheduledSpendKind<'a>,
}

impl ScheduledSpendGroup<'_> {
    pub fn live_inputs(self) -> usize {
        match self.kind {
            ScheduledSpendKind::Ordinary(facts) => usize::from(facts.live_inputs),
            ScheduledSpendKind::Native(facts) => facts.live_inputs,
        }
    }
    pub fn live_outputs(self) -> usize {
        match self.kind {
            ScheduledSpendKind::Ordinary(facts) => usize::from(facts.live_outputs),
            ScheduledSpendKind::Native(facts) => facts.live_outputs,
        }
    }
    pub fn fee(self) -> u64 {
        match self.kind {
            ScheduledSpendKind::Ordinary(facts) => facts.fee,
            ScheduledSpendKind::Native(facts) => facts.fee,
        }
    }
    pub fn logical_txid(self) -> TxBodyHash {
        match self.kind {
            ScheduledSpendKind::Ordinary(facts) => facts.logical_txid,
            ScheduledSpendKind::Native(facts) => facts.logical_txid,
        }
    }
    pub fn authority(self) -> Address {
        match self.kind {
            ScheduledSpendKind::Ordinary(facts) => facts.input_owner,
            ScheduledSpendKind::Native(facts) => facts.authority,
        }
    }
}

impl ScheduledBlockPageStream {
    pub fn page_count(&self) -> usize {
        match self {
            Self::Ordinary(facts) => usize::from(facts.page_count),
            Self::Native(facts) => facts.page_count,
        }
    }
    pub fn user_start_index(&self) -> usize {
        match self {
            Self::Ordinary(facts) => facts.user_start_index,
            Self::Native(facts) => facts.user_start_index,
        }
    }
    pub fn has_development_payout(&self) -> bool {
        self.user_start_index() == 2
    }
    pub fn effective_page_count(&self) -> usize {
        self.page_count() + usize::from(self.has_development_payout())
    }
    pub fn logical_count(&self) -> usize {
        match self {
            Self::Ordinary(facts) => facts.groups.len(),
            Self::Native(facts) => facts.groups.len(),
        }
    }
    pub fn live_inputs(&self) -> usize {
        match self {
            Self::Ordinary(facts) => usize::from(facts.live_inputs),
            Self::Native(facts) => facts.live_inputs,
        }
    }
    pub fn logical_txids(&self, transactions: &[Transaction]) -> Vec<TxBodyHash> {
        transactions[..self.user_start_index()]
            .iter()
            .map(Transaction::txid)
            .chain(self.groups().map(ScheduledSpendGroup::logical_txid))
            .collect()
    }
    pub fn required_native_opening_roots(&self, transactions: &[Transaction]) -> Vec<Address> {
        match self {
            Self::Ordinary(_) => Vec::new(),
            Self::Native(facts) => opening_roots(transactions, facts),
        }
    }

    pub fn required_native_operand_roots(&self) -> Vec<Address> {
        self.groups()
            .filter_map(|group| match group.kind {
                ScheduledSpendKind::Native(facts) => Some(facts.operation),
                ScheduledSpendKind::Ordinary(_) => None,
            })
            .flat_map(noid_tx::native_assets::wire::operand_roots)
            .collect()
    }

    pub fn groups(&self) -> impl Iterator<Item = ScheduledSpendGroup<'_>> {
        let (ordinary, native) = match self {
            Self::Ordinary(facts) => (Some(facts), None),
            Self::Native(facts) => (None, Some(facts)),
        };
        ordinary
            .into_iter()
            .flat_map(|stream| {
                stream.groups.iter().map(move |group| ScheduledSpendGroup {
                    body_start: stream.user_start_index + usize::from(group.start_page),
                    page_count: usize::from(group.page_count),
                    kind: ScheduledSpendKind::Ordinary(&group.spend),
                })
            })
            .chain(native.into_iter().flat_map(|stream| {
                stream.groups.iter().map(|group| ScheduledSpendGroup {
                    body_start: group.body_start,
                    page_count: group.page_count,
                    kind: match &group.kind {
                        BlockSpendKind::Ordinary(facts) => ScheduledSpendKind::Ordinary(facts),
                        BlockSpendKind::Native(facts) => ScheduledSpendKind::Native(facts),
                    },
                })
            }))
    }
}

pub fn validate_scheduled_block_page_stream(
    transactions: &[Transaction],
    height: u64,
) -> Result<ScheduledBlockPageStream, NativeBlockError> {
    let native_flags = noid_tx::native_assets::wire::NATIVE_PAGE_BIT
        | noid_tx::native_assets::wire::NATIVE_HEADER_BIT;
    let stream = if transactions
        .iter()
        .any(|tx| tx.body.validity_bitmap & native_flags != 0)
    {
        ScheduledBlockPageStream::Native(validate_block_page_stream_at(transactions, height)?)
    } else {
        ScheduledBlockPageStream::Ordinary(
            super::validate_block_page_stream(transactions).map_err(NativeBlockError::System)?,
        )
    };
    if crate::consensus::params::v2_1_active(height) {
        for group in stream.groups() {
            let mut ordinal = 0;
            let native = match group.kind {
                ScheduledSpendKind::Native(facts) => Some(facts),
                ScheduledSpendKind::Ordinary(_) => None,
            };
            let data_start = group.body_start + usize::from(native.is_some());
            for tx in &transactions[data_start..group.body_start + group.page_count] {
                for (_, input) in tx.body.live_inputs() {
                    let tagged = input.creation_id & noid_tx::native_assets::NATIVE_CREATION_TAG
                        != 0
                        && input.creation_id & (1 << 63) == 0;
                    let expected = native.is_some_and(|facts| facts.input_is_native(ordinal));
                    if tagged != expected
                        || expected
                            && noid_tx::native_assets::native_sequence(input.creation_id).is_err()
                    {
                        return Err(NativeBlockError::Provenance);
                    }
                    ordinal += 1;
                }
            }
        }
    }
    Ok(stream)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeBlockError {
    System(BlockPageStreamError),
    Ordinary(PagedSpendError),
    Native(NativeWireError),
    Inactive,
    ChainContext,
    UnterminatedGroup,
    ResourceLimit,
    SlotConflict,
    Provenance,
    MissingOpening(Address),
    Apply(BlockApplyError),
    NativeApply(NativeApplyError),
    Financial(FinancialBlockError),
    Trade(TradeStateError),
    Payload(super::payload::BlockBodyPayloadError),
}

impl core::fmt::Display for NativeBlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "native block: {self:?}")
    }
}
impl std::error::Error for NativeBlockError {}

/// Parse complete ordinary/native groups under the shared height schedule.
/// Metadata headers count as physical pages and carry no State actions.
pub fn validate_block_page_stream_at(
    txs: &[Transaction],
    height: u64,
) -> Result<NativeBlockStreamFacts, NativeBlockError> {
    if txs.len() > BLOCK_MAX_TXS {
        return Err(NativeBlockError::ResourceLimit);
    }
    let has_development = txs
        .get(1)
        .is_some_and(|tx| tx.body.is_development_payout_shape());
    let user_start_index = 1 + usize::from(has_development);
    let system = txs.get(..user_start_index).unwrap_or(txs);
    super::validate_block_page_stream(system).map_err(NativeBlockError::System)?;
    if txs[user_start_index..].iter().any(|tx| tx.body.is_coinbase) {
        return Err(NativeBlockError::System(
            BlockPageStreamError::MultipleCoinbase,
        ));
    }
    parse_user_groups(txs, height, user_start_index, usize::from(has_development))
}

/// Parse selected user groups before the fee-dependent system mints exist.
pub fn validate_user_page_stream_at(
    transactions: &[Transaction],
    height: u64,
) -> Result<NativeBlockStreamFacts, NativeBlockError> {
    if transactions.iter().any(|tx| tx.body.is_coinbase) {
        return Err(NativeBlockError::System(
            BlockPageStreamError::MultipleCoinbase,
        ));
    }
    parse_user_groups(transactions, height, 0, 0)
}

fn parse_user_groups(
    txs: &[Transaction],
    height: u64,
    user_start_index: usize,
    system_records: usize,
) -> Result<NativeBlockStreamFacts, NativeBlockError> {
    if txs.len() > BLOCK_MAX_TXS || user_start_index > txs.len() {
        return Err(NativeBlockError::ResourceLimit);
    }
    let page_count = txs.len() - user_start_index;
    let proof_class = BlockProofClass::for_page_count(page_count + system_records)
        .ok_or(NativeBlockError::ResourceLimit)?;
    let mut groups = Vec::new();
    let mut live_inputs = 0usize;
    let mut live_outputs = 0usize;
    let mut cursor = user_start_index;
    while cursor < txs.len() {
        let native = is_native_header(&txs[cursor].body);
        if native && !crate::consensus::params::v2_1_active(height) {
            return Err(NativeBlockError::Inactive);
        }
        let relative_end = txs[cursor..]
            .iter()
            .position(|tx| tx.body.validity_bitmap & noid_tx::PAGED_SPEND_END_BIT != 0)
            .ok_or(NativeBlockError::UnterminatedGroup)?;
        let end = cursor + relative_end + 1;
        let pages: Vec<_> = txs[cursor..end]
            .iter()
            .map(|tx| TxPage {
                body: tx.body.clone(),
            })
            .collect();
        let kind = if native {
            let facts = validate_native_pages(&pages).map_err(NativeBlockError::Native)?;
            if facts.chain != native_chain_id() {
                return Err(NativeBlockError::ChainContext);
            }
            BlockSpendKind::Native(facts)
        } else {
            BlockSpendKind::Ordinary(
                validate_paged_spend(&pages).map_err(NativeBlockError::Ordinary)?,
            )
        };
        let group = BlockSpendGroup {
            body_start: cursor,
            page_count: pages.len(),
            kind,
        };
        live_inputs += group.live_inputs();
        live_outputs += group.live_outputs();
        groups.push(group);
        cursor = end;
    }
    if groups.len() > proof_class.live_authorization_capacity()
        || live_inputs > proof_class.input_capacity()
        || live_outputs > proof_class.output_capacity()
    {
        return Err(NativeBlockError::ResourceLimit);
    }
    crate::consensus::checks::validate_block_slot_conflicts(txs)
        .map_err(|_| NativeBlockError::SlotConflict)?;
    Ok(NativeBlockStreamFacts {
        proof_class,
        groups,
        page_count,
        live_inputs,
        live_outputs,
        user_start_index,
    })
}

pub fn try_compute_logical_txids_at(
    txs: &[Transaction],
    height: u64,
) -> Result<Vec<TxBodyHash>, NativeBlockError> {
    if txs.is_empty() {
        return Ok(Vec::new());
    }
    let stream = validate_scheduled_block_page_stream(txs, height)?;
    Ok(stream.logical_txids(txs))
}

fn logical_txids(txs: &[Transaction], stream: &NativeBlockStreamFacts) -> Vec<TxBodyHash> {
    txs[..stream.user_start_index]
        .iter()
        .map(Transaction::txid)
        .chain(stream.groups.iter().map(BlockSpendGroup::logical_txid))
        .collect()
}

pub fn try_compute_tx_root_at(
    txs: &[Transaction],
    height: u64,
) -> Result<Digest, NativeBlockError> {
    let hashes: Vec<_> = try_compute_logical_txids_at(txs, height)?
        .into_iter()
        .map(|hash| hash.0)
        .collect();
    Ok(crate::tx_tree::root_from_hashes(&hashes))
}

/// Exact content keys needed to interpret this body's native live actions.
/// Each key is committed by the body's input root or output owner field.
pub fn required_native_opening_roots(block: &Block) -> Result<Vec<Address>, NativeBlockError> {
    let stream = validate_scheduled_block_page_stream(&block.transactions, block.header.height)?;
    Ok(stream.required_native_opening_roots(&block.transactions))
}

fn opening_roots(txs: &[Transaction], stream: &NativeBlockStreamFacts) -> Vec<Address> {
    let mut roots = BTreeSet::new();
    for group in &stream.groups {
        let BlockSpendKind::Native(facts) = &group.kind else {
            continue;
        };
        let data = &txs[group.body_start + 1..group.body_start + group.page_count];
        let mut input_index = 0;
        let mut output_index = 0;
        for tx in data {
            for _ in tx.body.live_inputs() {
                if facts.input_is_native(input_index) {
                    roots.insert(tx.body.input_owner.0);
                }
                input_index += 1;
            }
            for (_, output) in tx.body.live_outputs() {
                if facts.output_is_native(output_index) {
                    roots.insert(output.owner.0);
                }
                output_index += 1;
            }
        }
    }
    roots.into_iter().map(Address).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeBlockStateTransition {
    pub new_state_root: Digest,
    pub created_openings: Vec<NativeCreatedOpening>,
    pub consumed_openings: Vec<NativeConsumedOpening>,
}

/// Build the canonical exact-State witness for a local native candidate.
/// The original parent remains immutable; the common materializer checks
/// the complete typed transition, allocator, transaction root and child State.
pub fn build_native_block_action_surface(
    parent: &ChainState,
    block: &Block,
    opening: impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<crate::state_delta::ExactActionSurface, NativeBlockError> {
    build_native_block_action_surface_in_context(parent, block, None, &[], opening)
}

pub fn build_native_block_action_surface_with_financial_context(
    parent: &ChainState,
    block: &Block,
    financial: &FinancialHeaderWindow,
    opening: impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<crate::state_delta::ExactActionSurface, NativeBlockError> {
    build_native_block_action_surface_in_context(parent, block, Some(financial), &[], opening)
}

pub fn build_native_block_action_surface_with_native_data(
    parent: &ChainState,
    block: &Block,
    financial: &FinancialHeaderWindow,
    batches: &[TradeBatch],
    opening: impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<crate::state_delta::ExactActionSurface, NativeBlockError> {
    build_native_block_action_surface_in_context(parent, block, Some(financial), batches, opening)
}

fn build_native_block_action_surface_in_context(
    parent: &ChainState,
    block: &Block,
    financial: Option<&FinancialHeaderWindow>,
    batches: &[TradeBatch],
    opening: impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<crate::state_delta::ExactActionSurface, NativeBlockError> {
    use crate::state_delta::{
        exact_action_surface_from_surface, StateDeltaAction, StateDeltaActionKind,
        StateDeltaActionSurface,
    };
    let old_depth = parent.state.log_slots();
    if block.header.log_slots as usize != old_depth
        && block.header.log_slots as usize != old_depth + 1
    {
        return Err(NativeBlockError::ResourceLimit);
    }
    let (child, _) = prepare_native_block_state(parent, block, financial, batches, opening)?;
    let mut surface = StateDeltaActionSurface {
        actions: Vec::new(),
        spends: 0,
        mints: 0,
    };
    let old_domain = parent.state.num_slots();
    for (tx_index, transaction) in block.transactions.iter().enumerate() {
        for (op_index, input) in transaction.body.live_inputs() {
            surface.actions.push(StateDeltaAction {
                tx_index: tx_index as u32,
                op_index: op_index as u8,
                slot_index: input.slot_index,
                pre: if u64::from(input.slot_index) < old_domain {
                    parent.state.slot(input.slot_index)
                } else {
                    crate::SlotValue::EMPTY
                },
                post: child.state.slot(input.slot_index),
                kind: StateDeltaActionKind::Spend,
            });
            surface.spends += 1;
        }
        for (op_index, output) in transaction.body.live_outputs() {
            surface.actions.push(StateDeltaAction {
                tx_index: tx_index as u32,
                op_index: op_index as u8,
                slot_index: output.slot_index,
                pre: if u64::from(output.slot_index) < old_domain {
                    parent.state.slot(output.slot_index)
                } else {
                    crate::SlotValue::EMPTY
                },
                post: child.state.slot(output.slot_index),
                kind: StateDeltaActionKind::Mint,
            });
            surface.mints += 1;
        }
    }
    Ok(exact_action_surface_from_surface(surface))
}

/// Materialize a block after its full recursive terminal has been verified.
/// Resolve mandatory live openings by their authenticated content keys. All
/// slot updates and header comparisons succeed before the caller's State changes.
pub fn materialize_accepted_block_state_with_native_openings(
    state: &mut ChainState,
    block: &Block,
    opening: impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<NativeBlockStateTransition, NativeBlockError> {
    let (snapshot, transition) = prepare_native_block_state(state, block, None, &[], opening)?;
    *state = snapshot;
    Ok(transition)
}

/// Materialize checked financial groups with their canonical parent context.
pub fn materialize_accepted_block_state_with_financial_context(
    state: &mut ChainState,
    block: &Block,
    financial: &FinancialHeaderWindow,
    opening: impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<NativeBlockStateTransition, NativeBlockError> {
    let (snapshot, transition) =
        prepare_native_block_state(state, block, Some(financial), &[], opening)?;
    *state = snapshot;
    Ok(transition)
}

pub fn materialize_accepted_block_state_with_native_data(
    state: &mut ChainState,
    block: &Block,
    financial: &FinancialHeaderWindow,
    batches: &[TradeBatch],
    opening: impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<NativeBlockStateTransition, NativeBlockError> {
    let (snapshot, transition) =
        prepare_native_block_state(state, block, Some(financial), batches, opening)?;
    *state = snapshot;
    Ok(transition)
}

fn prepare_native_block_state(
    state: &ChainState,
    block: &Block,
    financial: Option<&FinancialHeaderWindow>,
    batches: &[TradeBatch],
    mut opening: impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<(ChainState, NativeBlockStateTransition), NativeBlockError> {
    if !(1..=32).contains(&block.header.log_slots) {
        return Err(NativeBlockError::ResourceLimit);
    }
    let stream = validate_block_page_stream_at(&block.transactions, block.header.height)?;
    let has_financial = stream.groups.iter().any(|g| matches!(
        &g.kind, BlockSpendKind::Native(facts) if matches!(facts.operation, NativeOperation::Financial(_))
    ));
    if let Some(financial) = financial {
        financial
            .check_parent(state, &block.header)
            .map_err(NativeBlockError::Financial)?;
    } else if has_financial {
        return Err(NativeBlockError::Financial(FinancialBlockError::Context));
    }
    let mut tracker = FinancialBlockTracker::default();
    let mut snapshot = state.clone();
    while block.header.log_slots as usize > snapshot.state.log_slots() {
        snapshot.expand_one();
    }
    for tx in &block.transactions[..stream.user_start_index] {
        tx.body
            .validate_canonical()
            .map_err(|_| NativeBlockError::Apply(BlockApplyError::InvalidTxBody))?;
        apply_tx_checked_deferred_root(&mut snapshot, &tx.body, Some(block.header.height))
            .map_err(|e| NativeBlockError::Apply(BlockApplyError::Tx(e)))?;
    }
    let operands: Vec<_> = stream
        .groups
        .iter()
        .filter_map(|group| match &group.kind {
            BlockSpendKind::Native(facts) => Some(facts.operation),
            BlockSpendKind::Ordinary(_) => None,
        })
        .flat_map(noid_tx::native_assets::wire::operand_roots)
        .collect();
    let closure = noid_tx::native_assets::closure::resolve_native_closure(
        &opening_roots(&block.transactions, &stream),
        &operands,
        super::payload::MAX_BLOCK_NATIVE_OPENINGS,
        &mut opening,
    )
    .map_err(|error| match error {
        noid_tx::native_assets::closure::NativeClosureError::Missing(root) => {
            NativeBlockError::MissingOpening(root)
        }
        _ => NativeBlockError::Native(NativeWireError::Dependencies(error)),
    })?;
    let payloads: BTreeMap<_, _> = closure.into_iter().map(|o| (o.root().0, o)).collect();
    let batches = super::payload::canonical_trade_batches(block, &payloads, batches.to_vec())
        .map_err(NativeBlockError::Payload)?;
    let batches: BTreeMap<_, _> = batches
        .into_iter()
        .map(|batch| (batch.root().expect("validated trade batch").0, batch))
        .collect();
    let mut created_openings = Vec::new();
    let mut consumed_openings = Vec::new();
    for group in &stream.groups {
        let operation = match &group.kind {
            BlockSpendKind::Native(facts) => match facts.operation {
                NativeOperation::Financial(op) => Some(op),
                _ => None,
            },
            _ => None,
        };
        let registrations = tracker
            .begin_group(operation)
            .map_err(NativeBlockError::Financial)?;
        let transactions =
            &block.transactions[group.body_start..group.body_start + group.page_count];
        match &group.kind {
            BlockSpendKind::Ordinary(_) => {
                for tx in transactions {
                    apply_tx_checked_deferred_root(
                        &mut snapshot,
                        &tx.body,
                        Some(block.header.height),
                    )
                    .map_err(|e| NativeBlockError::Apply(BlockApplyError::Tx(e)))?;
                }
            }
            BlockSpendKind::Native(facts) => {
                let data = &transactions[1..];
                let inputs: Vec<_> = data
                    .iter()
                    .flat_map(|tx| {
                        tx.body
                            .live_inputs()
                            .map(|(_, input)| (*input, tx.body.input_owner))
                    })
                    .enumerate()
                    .map(|(i, (input, root))| NativeInputClaim {
                        input,
                        root,
                        opening: facts.input_is_native(i).then(|| payloads[&root.0]),
                    })
                    .collect();
                let outputs: Vec<_> = data
                    .iter()
                    .flat_map(|tx| tx.body.live_outputs().map(|(_, output)| *output))
                    .enumerate()
                    .map(|(i, output)| NativeOutputClaim {
                        output,
                        opening: facts.output_is_native(i).then(|| payloads[&output.owner.0]),
                    })
                    .collect();
                let context = NativeContext {
                    chain: facts.chain,
                    height: block.header.height,
                    authority: facts.authority,
                    fee: facts.fee,
                };
                let effects = if let Some(operation) = operation {
                    let financial = financial
                        .ok_or(NativeBlockError::Financial(FinancialBlockError::Context))?;
                    let transition = if let FinancialOperation::ExecuteTrades { commitment } =
                        operation
                    {
                        let batch = batches.get(&commitment.0).ok_or(NativeBlockError::Payload(
                            super::payload::BlockBodyPayloadError::Trade,
                        ))?;
                        let boundary = TradeBoundary {
                            chain: facts.chain,
                            epoch_anchor: facts.epoch_anchor,
                            parent_id: block.header.prev_block_hash,
                            height: block.header.height,
                        };
                        let prepared = prepare_trade_batch_from_claims(
                            state,
                            boundary,
                            block.header.log_slots,
                            batch,
                            &inputs,
                            &outputs,
                        )
                        .map_err(NativeBlockError::Trade)?;
                        if prepared.fee() != context.fee
                            || prepared.commitment() != commitment
                            || prepared
                                .auxiliary()
                                .iter()
                                .any(|o| payloads.get(&o.root().0) != Some(o))
                        {
                            return Err(NativeBlockError::Financial(FinancialBlockError::Context));
                        }
                        prepared.execution().facts().clone()
                    } else if operation.requires_owner() {
                        financial
                            .check_owner(state, &context, operation, &inputs, &outputs, |r| {
                                payloads.get(&r.0).copied()
                            })
                            .map_err(NativeBlockError::Financial)?
                    } else {
                        let checked = financial
                            .check_public(
                                state,
                                &context,
                                operation,
                                &inputs,
                                &outputs,
                                &registrations,
                                |r| payloads.get(&r.0).copied(),
                            )
                            .map_err(NativeBlockError::Financial)?;
                        if checked
                            .auxiliary
                            .iter()
                            .any(|o| payloads.get(&o.root().0) != Some(o))
                        {
                            return Err(NativeBlockError::Financial(FinancialBlockError::Context));
                        }
                        checked.transition
                    };
                    apply_checked_native_deferred_root(
                        &mut snapshot,
                        &context,
                        &inputs,
                        &outputs,
                        transition,
                    )
                } else {
                    apply_native_deferred_root(
                        &mut snapshot,
                        &context,
                        facts.operation,
                        &inputs,
                        &outputs,
                    )
                }
                .map_err(NativeBlockError::NativeApply)?;
                if let Some(op) = operation.filter(|op| op.requires_owner()) {
                    tracker
                        .owner_outputs(op, &effects.created_openings)
                        .map_err(NativeBlockError::Financial)?;
                }
                created_openings.extend(effects.created_openings);
                consumed_openings.extend(effects.consumed_openings);
            }
        }
    }
    tracker.finish().map_err(NativeBlockError::Financial)?;
    let new_state_root = snapshot.try_state_root().map_err(|_| {
        NativeBlockError::Apply(BlockApplyError::Tx(ApplyError::ExactStateUnavailable))
    })?;
    let header = &block.header;
    let tx_hashes: Vec<_> = logical_txids(&block.transactions, &stream)
        .into_iter()
        .map(|hash| hash.0)
        .collect();
    let error = if new_state_root != header.state_root {
        Some(BlockApplyError::HeaderStateRootMismatch)
    } else if snapshot.active_slot_count != header.active_slot_count {
        Some(BlockApplyError::HeaderActiveSlotCountMismatch)
    } else if snapshot.alloc_counter != header.alloc_counter {
        Some(BlockApplyError::HeaderAllocCounterMismatch)
    } else if snapshot.state.log_slots() != header.log_slots as usize {
        Some(BlockApplyError::HeaderLogSlotsMismatch)
    } else if crate::tx_tree::root_from_hashes(&tx_hashes) != header.tx_root {
        Some(BlockApplyError::HeaderTxRootMismatch)
    } else {
        None
    };
    if let Some(error) = error {
        return Err(NativeBlockError::Apply(error));
    }
    let transition = NativeBlockStateTransition {
        new_state_root,
        created_openings,
        consumed_openings,
    };
    Ok((snapshot, transition))
}
