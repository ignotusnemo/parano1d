// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Staged native-financial transitions over one complete authenticated body.

use noid_tx::native_assets::NativeOpening;

use super::super::action_surface::ActionSurfaceTrace;
use super::super::paged_spend::NativePageContextTrace;
use super::super::{mul, pin_eq, FieldR1csBuilder, LinExpr};
use super::financial_actions::FinancialActionTrace;
use super::financial_admission::bind_financial_registration_rounds;
use super::financial_base_projection::bind_financial_base_operations;
use super::financial_clearing_witness::financial_clearing_witness;
use super::financial_control_rows::{bind_financial_control_rows, FinancialControlRowTrace};
use super::financial_definitions::{bind_financial_definitions, FinancialDefinitionsTrace};
use super::financial_global_clearing::{
    bind_financial_global_clearing, FinancialSettlementClearingTrace,
};
use super::financial_global_effects::{
    bind_financial_effect_requests, bind_financial_global_market_effects_from_requests,
};
use super::financial_global_launch_effects::bind_financial_global_launch_effects_from_requests;
use super::financial_launch_effects_shared::FinancialLaunchEffectsTrace;
use super::financial_launch_outputs::{
    bind_financial_launch_effect_outputs, bind_financial_launch_output_control,
};
use super::financial_listing_purchase::bind_financial_listing_purchase;
use super::financial_listing_settlement::FinancialListingSeedTrace;
use super::financial_market_effects_shared::{
    bind_financial_market_effect_outputs, FinancialMarketEffectsTrace,
};
use super::financial_reads::{bind_financial_parent_reads, FinancialParentReadTrace};
use super::financial_registration::{
    bind_financial_registration_requests, bind_financial_registration_suffix,
    FinancialRegistrationsTrace,
};
use super::financial_registration_budgets::bind_financial_registration_budgets;
use super::financial_registration_controls::bind_financial_registered_controls;
use super::financial_settlement_sets::{
    bind_financial_settlement_sets_for_headers, FinancialSettlementSetTrace,
};
use super::financial_single_public::bind_financial_single_public;
use super::financial_values::{bind_financial_carrier_values, FinancialCarrierValuesTrace};
use super::header::FinancialNativeHeaderTrace;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FinancialKernelPhase {
    Complete = 0,
    Admission = 1,
    Settlement = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinancialKernelConfig {
    pub definition_capacity: usize,
    pub control_capacity: usize,
    pub registered_control_capacity: usize,
    pub settlement_action_capacity: usize,
}

pub struct FinancialKernelBody<'a> {
    pub actions: &'a [FinancialActionTrace],
    pub headers: &'a [FinancialNativeHeaderTrace],
    pub surfaces: &'a [ActionSurfaceTrace],
    pub pages: &'a [NativePageContextTrace],
}

pub struct FinancialKernelBoundary<'a> {
    pub height: &'a LinExpr,
    pub parent_id: &'a [LinExpr; 2],
    pub parent_alloc_counter: &'a LinExpr,
}

pub struct FinancialPreparedTrace {
    pub reads: Vec<FinancialParentReadTrace>,
    pub definitions: FinancialDefinitionsTrace,
    pub values: Vec<FinancialCarrierValuesTrace>,
    pub controls: Vec<FinancialControlRowTrace>,
    pub registrations: FinancialRegistrationsTrace,
}

pub struct FinancialExecutionTrace {
    pub sets: Vec<FinancialSettlementSetTrace>,
    pub clearing: Vec<FinancialSettlementClearingTrace>,
    pub markets: Vec<FinancialMarketEffectsTrace>,
    pub launches: Vec<FinancialLaunchEffectsTrace>,
}

/// The immutable class selects its operation family before witness allocation.
pub fn bind_financial_phase_headers(
    b: &mut FieldR1csBuilder,
    phase: FinancialKernelPhase,
    headers: &[FinancialNativeHeaderTrace],
) {
    use super::super::pin_zero;
    use super::financial_operation::FINANCIAL_OPERATION_CODES;
    for header in headers {
        let trade = &header.metadata.financial[FINANCIAL_OPERATION_CODES
            .iter()
            .position(|&code| code == 80)
            .unwrap()];
        pin_zero(b, trade);
        let settlements = [39, 51, 71].into_iter().fold(LinExpr::zero(), |sum, code| {
            let index = FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&value| value == code)
                .unwrap();
            sum.add(&header.metadata.financial[index])
        });
        match phase {
            FinancialKernelPhase::Complete => {}
            FinancialKernelPhase::Admission => pin_zero(b, &settlements),
            FinancialKernelPhase::Settlement => pin_eq(b, &header.header.live, &settlements),
        }
    }
}

/// Native sequential profiles expose the fixed launch/token/NFT operation set.
pub fn bind_financial_sequential_headers(
    b: &mut FieldR1csBuilder,
    headers: &[FinancialNativeHeaderTrace],
) {
    use super::financial_operation::FINANCIAL_OPERATION_CODES;
    for header in headers {
        let mut allowed = [2usize, 3, 5, 6, 7, 8]
            .into_iter()
            .fold(LinExpr::zero(), |sum, code| {
                sum.add(&header.metadata.base[code])
            });
        for code in [48, 64, 65, 66, 80] {
            let index = FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&value| value == code)
                .unwrap();
            allowed = allowed.add(&header.metadata.financial[index]);
        }
        pin_eq(b, &header.header.live, &allowed);
    }
}

pub fn bind_financial_sequential_preparation(
    b: &mut FieldR1csBuilder,
    config: FinancialKernelConfig,
    body: &FinancialKernelBody<'_>,
    boundary: &FinancialKernelBoundary<'_>,
    auxiliary: &[NativeOpening],
) -> FinancialPreparedTrace {
    let mut ledger = b.num_wires();
    let reads =
        bind_financial_parent_reads(b, body.actions, body.headers, boundary.parent_alloc_counter);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "native: immutable parent reads");
    let definitions = bind_financial_definitions(
        b,
        body.actions,
        body.headers,
        &reads,
        config.definition_capacity,
        auxiliary,
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "native: definition commitments");
    let values = body
        .actions
        .iter()
        .map(|action| bind_financial_carrier_values(b, &action.opening))
        .collect::<Vec<_>>();
    crate::acceptance::row_ledger_mark(b, &mut ledger, "native: carrier values");
    bind_financial_base_operations(b, body.headers, body.actions, &values, boundary.height);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "native: base operations");
    FinancialPreparedTrace {
        reads,
        definitions,
        values,
        controls: Vec::new(),
        registrations: FinancialRegistrationsTrace {
            requests: Vec::new(),
            family_counts: std::array::from_fn(|_| LinExpr::zero()),
        },
    }
}

pub fn bind_financial_sequential_owner_operations(
    b: &mut FieldR1csBuilder,
    body: &FinancialKernelBody<'_>,
    prepared: &FinancialPreparedTrace,
    boundary: &FinancialKernelBoundary<'_>,
    fees: &[LinExpr],
) {
    assert_eq!(body.headers.len(), fees.len());
    for (header, required) in body.headers.iter().zip(fees) {
        let selected = [48, 64, 65, 66]
            .into_iter()
            .fold(LinExpr::zero(), |sum, code| {
                let index = super::financial_operation::FINANCIAL_OPERATION_CODES
                    .iter()
                    .position(|&value| value == code)
                    .expect("finite owner operation");
                sum.add(&header.metadata.financial[index])
            });
        let difference = mul(b, &selected, &header.header.fee.add(required));
        super::super::pin_zero(b, &difference);
    }

    super::financial_launch_genesis::bind_financial_launch_genesis(
        b,
        body.actions,
        &prepared.definitions,
        body.headers,
    );
    super::financial_nft_funding::bind_financial_nft_funding(
        b,
        body.actions,
        &prepared.definitions,
        body.headers,
        boundary.height,
    );
    super::financial_listing_purchase::bind_financial_listing_purchase(
        b,
        body.actions,
        &prepared.definitions,
        body.headers,
        boundary.height,
    );
    super::financial_listing_returns::bind_financial_listing_returns(
        b,
        body.actions,
        &prepared.values,
        &prepared.definitions,
        body.headers,
        boundary.height,
        fees,
    );
}

/// Frozen-set execution reuses exact typed carriers, definitions and control
/// arithmetic. Its class admits only pool, launch and listing settlements.
pub fn bind_financial_settlement_preparation(
    b: &mut FieldR1csBuilder,
    config: FinancialKernelConfig,
    body: &FinancialKernelBody<'_>,
    boundary: &FinancialKernelBoundary<'_>,
    auxiliary: &[NativeOpening],
) -> FinancialPreparedTrace {
    let reads =
        bind_financial_parent_reads(b, body.actions, body.headers, boundary.parent_alloc_counter);
    let definitions = bind_financial_definitions(
        b,
        body.actions,
        body.headers,
        &reads,
        config.definition_capacity,
        auxiliary,
    );
    let values = body
        .actions
        .iter()
        .map(|action| bind_financial_carrier_values(b, &action.opening))
        .collect();
    let controls =
        bind_financial_control_rows(b, body.actions, &definitions, config.control_capacity);
    FinancialPreparedTrace {
        reads,
        definitions,
        values,
        controls,
        registrations: FinancialRegistrationsTrace {
            requests: Vec::new(),
            family_counts: std::array::from_fn(|_| LinExpr::zero()),
        },
    }
}

/// The body supplies exact packed allocator actions and hash-bound headers.
/// The boundary uses the same canonical height, parent id and allocation
/// counter as State and authorization. Auxiliary definitions are complete.
pub fn bind_financial_preparation(
    b: &mut FieldR1csBuilder,
    config: FinancialKernelConfig,
    body: &FinancialKernelBody<'_>,
    boundary: &FinancialKernelBoundary<'_>,
    auxiliary: &[NativeOpening],
) -> FinancialPreparedTrace {
    let actions = body.actions;
    let headers = body.headers;
    let parent = boundary.parent_alloc_counter;
    let height = boundary.height;
    let reads = bind_financial_parent_reads(b, actions, headers, parent);
    let definitions = bind_financial_definitions(
        b,
        actions,
        headers,
        &reads,
        config.definition_capacity,
        auxiliary,
    );
    let values = actions
        .iter()
        .map(|a| bind_financial_carrier_values(b, &a.opening))
        .collect::<Vec<_>>();
    bind_financial_base_operations(b, headers, actions, &values, height);
    let controls = bind_financial_control_rows(b, actions, &definitions, config.control_capacity);
    let registrations = bind_financial_registration_requests(b, actions, headers, parent);
    bind_financial_registration_suffix(b, body.surfaces, body.pages, headers, &registrations);
    let rounds = bind_financial_registration_rounds(
        b,
        actions,
        &values,
        headers,
        &reads,
        &definitions,
        &registrations,
        height,
        boundary.parent_id,
        parent,
    );
    let registered = bind_financial_registered_controls(
        b,
        actions,
        &definitions,
        headers,
        &rounds,
        &registrations,
        height,
        parent,
        config.registered_control_capacity,
    );
    bind_financial_registration_budgets(b, actions, &registrations, &registered, headers.len());
    bind_financial_single_public(b, actions, &values, &definitions, headers, height);
    FinancialPreparedTrace {
        reads,
        definitions,
        values,
        controls,
        registrations,
    }
}

/// Canonical block fee arithmetic supplies one required fee per exact header.
pub fn bind_financial_owner_operations(
    b: &mut FieldR1csBuilder,
    body: &FinancialKernelBody<'_>,
    prepared: &FinancialPreparedTrace,
    boundary: &FinancialKernelBoundary<'_>,
    fees: &[LinExpr],
) {
    use super::financial_launch_genesis::bind_financial_launch_genesis;
    use super::financial_listing_returns::bind_financial_listing_returns;
    use super::financial_market_owner::bind_financial_market_owner;
    use super::financial_nft_funding::bind_financial_nft_funding;
    use super::financial_owner_requests::bind_financial_owner_requests;
    use super::financial_swap_claims::bind_financial_swap_claims;
    use super::financial_timeout_refunds::bind_financial_timeout_refunds;
    let actions = body.actions;
    let headers = body.headers;
    let definitions = &prepared.definitions;
    let height = boundary.height;
    assert_eq!(headers.len(), fees.len());
    bind_financial_swap_claims(b, actions, headers, fees);
    bind_financial_listing_returns(
        b,
        actions,
        &prepared.values,
        definitions,
        headers,
        height,
        fees,
    );
    bind_financial_listing_purchase(b, actions, definitions, headers, height);
    bind_financial_nft_funding(b, actions, definitions, headers, height);
    bind_financial_market_owner(b, actions, definitions, headers, height);
    bind_financial_timeout_refunds(b, actions, definitions, headers, height);
    bind_financial_owner_requests(
        b,
        actions,
        definitions,
        headers,
        &prepared.reads,
        height,
        boundary.parent_alloc_counter,
    );
    bind_financial_launch_genesis(b, actions, definitions, headers);
}

/// Complete frozen sets, exact allocation and physical successors share one
/// action table. Compact headers retain their exact required and paid fees.
pub fn bind_financial_settlements(
    b: &mut FieldR1csBuilder,
    config: FinancialKernelConfig,
    body: &FinancialKernelBody<'_>,
    prepared: &FinancialPreparedTrace,
    height: &LinExpr,
    fees: &[LinExpr],
    _listing_seeds: &[FinancialListingSeedTrace],
) -> FinancialExecutionTrace {
    assert_eq!(body.headers.len(), fees.len());
    assert!(config.settlement_action_capacity <= body.actions.len());
    let selected = super::financial_settlement_headers::bind_financial_settlement_headers(
        b,
        body.headers,
        fees,
        config.settlement_action_capacity,
    );
    let fees = &selected.required_fees;
    let sets = bind_financial_settlement_sets_for_headers(
        b,
        body.actions,
        &prepared.definitions,
        &selected.headers,
        height,
    );
    let witness = financial_clearing_witness(b, &sets, body.actions);
    let clearing =
        bind_financial_global_clearing(b, &sets, config.settlement_action_capacity, &witness);
    let prices = clearing.iter().map(|x| x.price.clone()).collect::<Vec<_>>();
    let quantities = clearing
        .iter()
        .map(|x| x.effective.clone())
        .collect::<Vec<_>>();
    let requests = bind_financial_effect_requests(
        b,
        &sets,
        &prices,
        &quantities,
        config.settlement_action_capacity,
    );
    let markets =
        bind_financial_global_market_effects_from_requests(b, &sets, &prices, fees, &requests);
    let controls = sets
        .iter()
        .map(|set| bind_financial_launch_output_control(b, set, &prepared.controls))
        .collect::<Vec<_>>();
    let launches =
        bind_financial_global_launch_effects_from_requests(b, &sets, fees, &controls, &requests);
    for (index, set) in sets.iter().enumerate() {
        bind_financial_market_effect_outputs(b, set, &markets[index], body.actions);
        bind_financial_launch_effect_outputs(b, set, &launches[index], body.actions);
        let expected = mul(b, &set.family[0], &fees[index]).add(&launches[index].total_fee);
        let actual = mul(b, &set.live, &selected.fees[index]);
        pin_eq(b, &actual, &expected);
    }
    FinancialExecutionTrace {
        sets,
        clearing,
        markets,
        launches,
    }
}
