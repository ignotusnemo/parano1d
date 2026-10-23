// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Scheduled v2 witness preparation using a class's pinned resource limits.
//! Production mining and capacity qualification share this exact path; the
//! embedded bank, rather than a local default, supplies the configuration.

use noid_chain::block::native_assets::{
    validate_scheduled_block_page_stream, ScheduledBlockPageStream, ScheduledSpendKind,
};
use noid_chain::{consensus::ConsensusError, Block};
use noid_gkr::zk_authorization::ZkAuthorizationProof;
use noid_recursive::{
    acceptance::history_step::{prepare_candidate_authorizations, v2::V2Config},
    HistoryStepBlockInput, PreparedHistoryStepGhostAuthorization, V2ContractComponentInput,
};
use noid_tx::{experimental_object::ObjectOpening, TxPage, PAGED_SPEND_V2_CONTRACT_MASK};

use crate::{HistoryStepPreparationContext, HistoryStepWitnessError};

/// Validate the schedule, body, exact State boundary, object openings and
/// capsules before producing a witness. Only PoW is deferred to nonce sealing.
pub fn prepare_candidate_input<const PAGES: usize>(
    block: &Block,
    context: HistoryStepPreparationContext<'_>,
    proofs: Vec<ZkAuthorizationProof>,
    ghost: &PreparedHistoryStepGhostAuthorization,
    openings: &[ObjectOpening],
    config: V2Config,
) -> Result<HistoryStepBlockInput<PAGES>, HistoryStepWitnessError> {
    prepare_candidate_input_with_native_openings(
        block,
        context,
        proofs,
        ghost,
        openings,
        &[],
        config,
    )
}

/// Complete candidate preparation with root-bound native object preimages.
pub fn prepare_candidate_input_with_native_openings<const PAGES: usize>(
    block: &Block,
    context: HistoryStepPreparationContext<'_>,
    proofs: Vec<ZkAuthorizationProof>,
    ghost: &PreparedHistoryStepGhostAuthorization,
    openings: &[ObjectOpening],
    native_openings: &[noid_tx::native_assets::NativeOpening],
    config: V2Config,
) -> Result<HistoryStepBlockInput<PAGES>, HistoryStepWitnessError> {
    prepare_candidate_input_with_financial_context(
        block,
        context,
        proofs,
        ghost,
        openings,
        native_openings,
        &[],
        config,
    )
}

pub fn prepare_candidate_input_with_financial_context<const PAGES: usize>(
    block: &Block,
    context: HistoryStepPreparationContext<'_>,
    proofs: Vec<ZkAuthorizationProof>,
    ghost: &PreparedHistoryStepGhostAuthorization,
    openings: &[ObjectOpening],
    native_openings: &[noid_tx::native_assets::NativeOpening],
    ancestors: &[noid_chain::BlockHeader],
    config: V2Config,
) -> Result<HistoryStepBlockInput<PAGES>, HistoryStepWitnessError> {
    prepare_candidate_input_with_native_data(
        block,
        context,
        proofs,
        ghost,
        openings,
        native_openings,
        ancestors,
        &[],
        config,
    )
}

pub fn prepare_candidate_input_with_native_data<const PAGES: usize>(
    block: &Block,
    context: HistoryStepPreparationContext<'_>,
    proofs: Vec<ZkAuthorizationProof>,
    ghost: &PreparedHistoryStepGhostAuthorization,
    openings: &[ObjectOpening],
    native_openings: &[noid_tx::native_assets::NativeOpening],
    ancestors: &[noid_chain::BlockHeader],
    batches: &[noid_tx::native_assets::trade::batch::TradeBatch],
    config: V2Config,
) -> Result<HistoryStepBlockInput<PAGES>, HistoryStepWitnessError> {
    if ancestors.len() > 3 || config.native_financial_config().is_none() && !ancestors.is_empty() {
        return Err(HistoryStepWitnessError::V2ContractShape);
    }
    if PAGES != config.pages()
        || block.header.height < config.activation_height()
        || openings.len() > config.contract_slots()
    {
        return Err(HistoryStepWitnessError::V2ContractShape);
    }
    context
        .start_accumulator
        .validate_local_header_boundary(context.parent_header, context.tx_epoch_anchor_header)
        .map_err(HistoryStepWitnessError::StartBoundary)?;
    super::history_step_witness::validate_parent_state_boundary(
        context.parent_header,
        context.parent_state,
    )?;
    noid_chain::consensus::validation::validate_block_checks_with_schedule(
        block,
        context.parent_header,
        context.previous_timestamps,
        context.finalized_active_counts,
        Some(context.local_time),
        context.asert_anchor,
        false,
        config.schedule(),
    )?;
    let parent_id = noid_chain::hash_block_header(context.parent_header);
    let epoch = if context
        .start_accumulator
        .height
        .is_multiple_of(noid_chain::consensus::params::TX_EPOCH_BLOCKS)
    {
        parent_id
    } else {
        context.start_accumulator.epoch_anchor_id
    };
    noid_chain::consensus::validate_block_epoch_anchors(block, epoch, parent_id)?;
    let stream = validate_scheduled_block_page_stream(&block.transactions, block.header.height)
        .map_err(HistoryStepWitnessError::NativeBlock)?;
    let hashes = stream
        .logical_txids(&block.transactions)
        .into_iter()
        .map(|id| id.0)
        .collect::<Vec<_>>();
    if noid_chain::tx_tree::root_from_hashes(&hashes) != block.header.tx_root {
        return Err(HistoryStepWitnessError::TransactionRootMismatch);
    }
    validate_scheduled_candidate_resources(&stream, config)?;
    let native_capacity = config.native_action_capacity().unwrap_or(0);
    if native_openings.len() > 2 * native_capacity
        || stream
            .required_native_opening_roots(&block.transactions)
            .len()
            > native_capacity
    {
        return Err(ConsensusError::ShapeMismatch("native object preimage limit".into()).into());
    }
    noid_chain::block::payload::canonical_opening_map(block, native_openings.to_vec()).map_err(
        |error| match error {
            noid_chain::block::payload::BlockBodyPayloadError::MissingOpening(root) => {
                HistoryStepWitnessError::NativeBlock(
                    noid_chain::block::native_assets::NativeBlockError::MissingOpening(root),
                )
            }
            other => ConsensusError::ShapeMismatch(other.to_string()).into(),
        },
    )?;
    let base = stream.user_start_index();
    let mut contracts = Vec::with_capacity(openings.len());
    let mut opening_iter = openings.iter();
    for (index, transaction) in block.transactions.iter().enumerate() {
        if transaction.body.validity_bitmap & PAGED_SPEND_V2_CONTRACT_MASK != 0 {
            if index < base
                || index - base >= config.contract_slots()
                || config.native_sequential_config().is_none() && index - base != contracts.len()
            {
                return Err(HistoryStepWitnessError::V2ContractShape);
            }
            let opening = opening_iter
                .next()
                .ok_or(HistoryStepWitnessError::V2ContractShape)?;
            let checked = opening
                .check_call(
                    &TxPage {
                        body: transaction.body.clone(),
                    },
                    block.header.height,
                )
                .map_err(|e| ConsensusError::ShapeMismatch(e.to_string()))?;
            contracts.push(V2ContractComponentInput {
                body_index: index,
                live: true,
                program: opening.program,
                current: opening.state,
                contexts: checked.contexts,
                next: checked.next,
                controller: opening.claim_authority.as_fields(),
                refund_authority: opening.recovery_authority.as_fields(),
                terminal: checked.terminal,
                deadline: opening.deadline,
                claim_recipient: opening.claim_recipient.as_fields(),
                refund_recipient: opening.recovery_recipient.as_fields(),
                rules: opening.rules,
            });
        }
    }
    if opening_iter.next().is_some() || contracts.len() != openings.len() {
        return Err(HistoryStepWitnessError::V2ContractShape);
    }
    let mut components = if config.native_financial_config().is_some() {
        let financial = noid_chain::block::native_assets::financial::FinancialHeaderWindow::new(
            *context.parent_header,
            ancestors,
        )
        .map_err(|error| {
            HistoryStepWitnessError::NativeBlock(
                noid_chain::block::native_assets::NativeBlockError::Financial(error),
            )
        })?;
        super::history_step_witness::build_history_step_components_with_native_data(
            block,
            context.parent_state,
            native_openings,
            &financial,
            batches,
        )?
    } else {
        if !batches.is_empty() {
            return Err(HistoryStepWitnessError::V2ContractShape);
        }
        super::history_step_witness::build_history_step_components_with_native_openings(
            block,
            context.parent_state,
            native_openings,
        )?
    };
    for contract in &contracts {
        let group = stream
            .groups()
            .find(|group| {
                contract.body_index >= group.body_start
                    && contract.body_index < group.body_start + group.page_count
            })
            .ok_or(HistoryStepWitnessError::V2ContractShape)?;
        if !matches!(group.kind, ScheduledSpendKind::Ordinary(_)) {
            return Err(HistoryStepWitnessError::V2ContractShape);
        }
        let hash = group.logical_txid().as_fields();
        let mut matches = components
            .authorization_inputs
            .iter_mut()
            .filter(|a| a.tx_body_hash == hash);
        let authorization = matches
            .next()
            .ok_or(HistoryStepWitnessError::V2ContractShape)?;
        if matches.next().is_some() {
            return Err(HistoryStepWitnessError::V2ContractShape);
        }
        authorization.public = noid_gkr::OwnerAuthPublicInputs::new(
            authorization.tx_body_hash,
            if block.header.height < contract.deadline {
                contract.controller
            } else {
                contract.refund_authority
            },
        );
    }
    components.v2_contract_inputs = contracts;
    let authorizations = prepare_candidate_authorizations(
        config,
        components.effective_page_count(),
        &components.authorization_inputs,
        proofs,
        ghost,
    )?;
    let end = context
        .start_accumulator
        .advance(context.parent_header, &block.header)
        .map_err(HistoryStepWitnessError::AccumulatorAdvance)?;
    HistoryStepBlockInput::try_new_candidate(
        config,
        context.start_accumulator,
        &end,
        components,
        authorizations,
        &block.header,
        context.parent_header,
    )
    .map_err(HistoryStepWitnessError::RecursiveInput)
}

fn validate_scheduled_candidate_resources(
    stream: &ScheduledBlockPageStream,
    config: V2Config,
) -> Result<(), ConsensusError> {
    if let ScheduledBlockPageStream::Ordinary(facts) = stream {
        return validate_candidate_resources(facts, config);
    }
    validate_candidate_counts(stream.effective_page_count(), stream.live_inputs(), config)?;
    let mut headers = 0;
    let mut records = 0;
    let mut settlement_inputs = 0;
    for group in stream.groups() {
        if let ScheduledSpendKind::Native(facts) = group.kind {
            if config.native_sequential_config().is_some() {
                if let noid_tx::native_assets::transition::NativeOperation::Financial(operation) =
                    facts.operation
                {
                    if !matches!(operation.code(), 48 | 64 | 65 | 66 | 80) {
                        return Err(ConsensusError::ShapeMismatch(
                            "native operation is outside the selected class".into(),
                        ));
                    }
                }
            }
            headers += 1;
            if let Some(financial) = config.native_financial_config() {
                use noid_recursive::acceptance::trace::native_assets::financial_kernel::FinancialKernelPhase;
                let is_settlement = matches!(
                    facts.operation,
                    noid_tx::native_assets::transition::NativeOperation::Financial(
                        noid_tx::native_assets::financial::FinancialOperation::SettlePool
                            | noid_tx::native_assets::financial::FinancialOperation::SettleLaunch
                            | noid_tx::native_assets::financial::FinancialOperation::SettleListing
                    )
                );
                if (financial.phase == FinancialKernelPhase::Admission && is_settlement)
                    || (financial.phase == FinancialKernelPhase::Settlement && !is_settlement)
                {
                    return Err(ConsensusError::BlockResourceLimitExceeded {
                        limit: "financial_operation_family",
                        actual: 1,
                        max: 0,
                    });
                }
                records += facts.live_inputs + facts.live_outputs;
                if matches!(
                    facts.operation,
                    noid_tx::native_assets::transition::NativeOperation::Financial(
                        noid_tx::native_assets::financial::FinancialOperation::SettlePool
                            | noid_tx::native_assets::financial::FinancialOperation::SettleLaunch
                    )
                ) {
                    settlement_inputs += facts.live_inputs;
                }
                if 2 * settlement_inputs > financial.kernel.settlement_action_capacity {
                    return Err(ConsensusError::BlockResourceLimitExceeded {
                        limit: "financial_settlement_actions",
                        actual: 2 * settlement_inputs,
                        max: financial.kernel.settlement_action_capacity,
                    });
                }
                continue;
            }
            if matches!(
                facts.operation,
                noid_tx::native_assets::transition::NativeOperation::Financial(_)
            ) {
                return Err(ConsensusError::BlockResourceLimitExceeded {
                    limit: "financial_headers",
                    actual: 1,
                    max: 0,
                });
            }
            records += (0..facts.live_inputs)
                .filter(|&i| facts.input_is_native(i))
                .count();
            records += (0..facts.live_outputs)
                .filter(|&i| facts.output_is_native(i))
                .count();
            if matches!(
                facts.operation,
                noid_tx::native_assets::transition::NativeOperation::CreateToken { .. }
                    | noid_tx::native_assets::transition::NativeOperation::CreateCollection { .. }
            ) {
                records += 1;
            }
        }
    }
    let header_limit = config.native_header_capacity().unwrap_or(0);
    let record_limit = config.native_action_capacity().unwrap_or(0);
    for (limit, actual, max) in [
        ("native_headers", headers, header_limit),
        ("native_records", records, record_limit),
    ] {
        if actual > max {
            return Err(ConsensusError::BlockResourceLimitExceeded { limit, actual, max });
        }
    }
    Ok(())
}

fn validate_candidate_resources(
    stream: &noid_chain::BlockPageStreamFacts,
    config: V2Config,
) -> Result<(), ConsensusError> {
    validate_candidate_counts(
        stream.effective_page_count(),
        usize::from(stream.live_inputs),
        config,
    )
}

fn validate_candidate_counts(
    pages: usize,
    inputs: usize,
    config: V2Config,
) -> Result<(), ConsensusError> {
    use noid_chain::consensus::paged_spend::PagedSpendStreamError;
    let error = if pages > config.pages() {
        Some(PagedSpendStreamError::BlockPageLimit {
            actual: pages,
            capacity: config.pages(),
        })
    } else if inputs > config.max_live_inputs() {
        Some(PagedSpendStreamError::BlockInputLimit {
            actual: inputs,
            capacity: config.max_live_inputs(),
        })
    } else {
        None
    };
    match error {
        Some(error) => Err(ConsensusError::InvalidPagedSpend(error.to_string())),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::{
        forks::{ForkSchedule, V2Activation},
        paged_spend::BlockProofClass,
    };

    #[test]
    fn candidate_budget_rejects_extra_inputs_even_with_spare_touched_slots() {
        let schedule = ForkSchedule::new(Some(5), V2Activation::new(10, 30)).unwrap();
        let config = V2Config::with_input_budget(23, 96, 384, schedule).unwrap();
        let mut stream = noid_chain::BlockPageStreamFacts {
            proof_class: BlockProofClass::B255,
            groups: Vec::new(),
            page_count: 96,
            logical_count: 96,
            live_inputs: 384,
            live_outputs: 96,
            has_development_payout: false,
            user_start_index: 1,
        };
        assert!(validate_candidate_resources(&stream, config).is_ok());
        stream.live_inputs = 385;
        assert!(usize::from(stream.live_inputs + stream.live_outputs) + 1 < 577);
        assert!(validate_candidate_resources(&stream, config).is_err());
        // The original candidate and old B255 allowance remain unchanged.
        assert!(
            validate_candidate_resources(&stream, V2Config::new(23, 96, schedule).unwrap()).is_ok()
        );
        assert_eq!(BlockProofClass::B255.input_capacity(), 1020);
        stream.live_inputs = 96;
        stream.has_development_payout = true;
        assert!(validate_candidate_resources(&stream, config).is_err());
    }
}
