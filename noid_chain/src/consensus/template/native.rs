// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Checked native groups and the complete selected block payload.

use std::collections::{BTreeMap, BTreeSet};

use noid_poseidon2b::primitives::Address;
use noid_tx::native_assets::{
    closure::resolve_native_closure,
    financial::FinancialOperation,
    trade::{batch::TradeBatch, sequencing::TradeBoundary},
    transition::{NativeContext, NativeInputClaim, NativeOperation, NativeOutputClaim},
    wire::{NativeIntent, NativeSpendFacts},
    NativeOpening,
};

use crate::block::native_assets::{
    financial::FinancialHeaderWindow, validate_scheduled_block_page_stream, BlockSpendGroup,
    BlockSpendKind, ScheduledSpendKind,
};
use crate::block::payload::{
    BlockBodyPayload, MAX_BLOCK_NATIVE_OPENINGS, MAX_BLOCK_TRADE_POLICIES,
};
use crate::state::native_assets::{native_chain_id, trade::prepare_trade_batch_from_intent};
use crate::{Block, BlockHeader, ChainState};

use super::TemplateBuildError;

type Batches = BTreeMap<[u8; 32], TradeBatch>;

fn error(error: impl core::fmt::Display) -> TemplateBuildError {
    TemplateBuildError::StateApplyError(error.to_string())
}

pub(super) fn candidate_batches(
    groups: &[BlockSpendGroup],
    batches: &[TradeBatch],
) -> Result<Batches, TemplateBuildError> {
    let expected = groups
        .iter()
        .filter_map(|group| match &group.kind {
            BlockSpendKind::Native(facts) => match facts.operation {
                NativeOperation::Financial(FinancialOperation::ExecuteTrades { commitment }) => {
                    Some(commitment.0)
                }
                _ => None,
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let unique = expected.iter().copied().collect::<BTreeSet<_>>();
    if expected.len() != unique.len()
        || batches.len() != expected.len()
        || batches.len() > MAX_BLOCK_TRADE_POLICIES
    {
        return Err(error("candidate trade batch set"));
    }
    let mut keyed = Batches::new();
    let mut count = 0usize;
    for batch in batches {
        count = count
            .checked_add(batch.policies().len())
            .filter(|&n| n <= MAX_BLOCK_TRADE_POLICIES)
            .ok_or_else(|| error("candidate trade policy limit"))?;
        let root = batch.root().map_err(error)?.0;
        if !unique.contains(&root) || keyed.insert(root, batch.clone()).is_some() {
            return Err(error("candidate trade batch set"));
        }
    }
    Ok(keyed)
}

/// Typed execution is checked against the immutable parent once. Selection
/// and final replay use these exact claims with the common raw allocator.
pub(super) fn checked_candidate(
    parent: &BlockHeader,
    state: &ChainState,
    child_log_slots: u32,
    intent: &NativeIntent,
    batches: &Batches,
) -> Result<NativeSpendFacts, TemplateBuildError> {
    let pages = intent.validate_structure().map_err(error)?;
    let height = parent
        .height
        .checked_add(1)
        .ok_or_else(|| error("candidate height exhausted"))?;
    if pages.chain != native_chain_id() {
        return Err(error("native candidate chain"));
    }
    let NativeOperation::Financial(operation) = pages.operation else {
        return intent.checked(native_chain_id(), height).map_err(error);
    };
    if !matches!(operation.code(), 48 | 64 | 65 | 66 | 80) {
        return Err(error("financial operation outside the template profile"));
    }
    let context = NativeContext {
        chain: pages.chain,
        height,
        authority: pages.authority,
        fee: pages.fee,
    };
    let inputs = intent
        .pages
        .iter()
        .skip(1)
        .flat_map(|page| {
            page.body
                .live_inputs()
                .map(|(_, i)| (*i, page.body.input_owner))
        })
        .zip(&intent.input_openings)
        .map(|((input, root), opening)| NativeInputClaim {
            input,
            root,
            opening: *opening,
        })
        .collect::<Vec<_>>();
    let outputs = intent
        .pages
        .iter()
        .skip(1)
        .flat_map(|page| page.body.live_outputs().map(|(_, o)| *o))
        .zip(&intent.output_openings)
        .map(|(output, opening)| NativeOutputClaim {
            output,
            opening: *opening,
        })
        .collect::<Vec<_>>();
    let transition = if let FinancialOperation::ExecuteTrades { commitment } = operation {
        let batch = batches
            .get(&commitment.0)
            .ok_or_else(|| error("candidate trade batch missing"))?;
        let prepared = prepare_trade_batch_from_intent(
            state,
            TradeBoundary {
                chain: pages.chain,
                epoch_anchor: pages.epoch_anchor,
                parent_id: crate::block_id(parent),
                height,
            },
            child_log_slots,
            batch,
            intent,
        )
        .map_err(error)?;
        if prepared
            .auxiliary()
            .iter()
            .any(|opening| intent.opening(opening.root()) != Some(*opening))
        {
            return Err(error("candidate trade dependencies"));
        }
        prepared.execution().facts().clone()
    } else {
        FinancialHeaderWindow::new(*parent, &[])
            .map_err(error)?
            .check_owner(state, &context, operation, &inputs, &outputs, |root| {
                intent.opening(root)
            })
            .map_err(error)?
    };
    Ok(NativeSpendFacts {
        pages,
        context,
        inputs,
        outputs,
        transition,
    })
}

pub(super) fn selected_data(
    block: &Block,
    openings: &[NativeOpening],
    batches: &[TradeBatch],
) -> Result<(Vec<NativeOpening>, Vec<TradeBatch>), TemplateBuildError> {
    let stream = validate_scheduled_block_page_stream(&block.transactions, block.header.height)
        .map_err(error)?;
    let keyed: BTreeMap<_, _> = openings.iter().map(|o| (o.root().0, *o)).collect();
    let closure = resolve_native_closure(
        &stream.required_native_opening_roots(&block.transactions),
        &stream.required_native_operand_roots(),
        MAX_BLOCK_NATIVE_OPENINGS,
        |root: Address| keyed.get(&root.0).copied(),
    )
    .map_err(error)?;
    let mut selected = Vec::new();
    for group in stream.groups() {
        let ScheduledSpendKind::Native(facts) = group.kind else {
            continue;
        };
        if let NativeOperation::Financial(FinancialOperation::ExecuteTrades { commitment }) =
            facts.operation
        {
            let batch = batches
                .iter()
                .find(|batch| batch.root().ok().map(|root| root.0) == Some(commitment.0))
                .ok_or_else(|| error("selected trade batch missing"))?;
            selected.push(batch.clone());
        }
    }
    let body =
        BlockBodyPayload::new_with_native_data(block.clone(), closure, selected).map_err(error)?;
    Ok((
        body.native_openings().to_vec(),
        body.trade_batches().to_vec(),
    ))
}
