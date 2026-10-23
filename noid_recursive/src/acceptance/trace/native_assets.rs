// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-shape native-opening commitments and canonical field framing.

pub mod actions;
pub mod arithmetic;
pub mod financial_actions;
pub mod financial_active_clearing_route;
pub mod financial_admission;
pub mod financial_allocation_budget;
pub mod financial_base_projection;
pub mod financial_bootstrap_root;
pub mod financial_budget_scan;
pub mod financial_cash_payouts;
pub mod financial_clearing_classification;
pub mod financial_clearing_summaries;
pub mod financial_clearing_witness;
pub mod financial_control_rows;
pub mod financial_controls;
pub mod financial_definitions;
pub mod financial_global_allocation;
pub mod financial_global_clearing;
pub mod financial_global_effects;
pub mod financial_global_launch_effects;
pub mod financial_header_window;
pub mod financial_inventory_scan;
pub mod financial_kernel;
pub mod financial_launch_context;
pub mod financial_launch_effects;
pub mod financial_launch_effects_shared;
pub mod financial_launch_execution;
pub mod financial_launch_genesis;
pub mod financial_launch_outputs;
pub mod financial_liquidity_claims;
pub mod financial_liquidity_step;
pub mod financial_listing_purchase;
pub mod financial_listing_returns;
pub mod financial_listing_settlement;
pub mod financial_market_context;
pub mod financial_market_effects_shared;
pub mod financial_market_owner;
pub mod financial_nft_funding;
pub mod financial_nft_offers;
pub mod financial_nft_refunds;
pub mod financial_opening;
pub mod financial_operation;
pub mod financial_owner_requests;
pub mod financial_pool_genesis;
pub mod financial_queue;
pub mod financial_ratio;
pub mod financial_reads;
pub mod financial_registration;
pub mod financial_registration_budgets;
pub mod financial_registration_controls;
pub mod financial_settlement_headers;
pub mod financial_settlement_sets;
pub mod financial_single_public;
pub mod financial_slot;
pub mod financial_swap_claims;
pub mod financial_swap_execution;
pub mod financial_timeout_refunds;
pub mod financial_values;
pub mod fungible;
pub mod genesis;
pub mod header;
pub mod kernel;
pub mod nft;
pub mod sequential_trade;
pub mod validation;

use noid_core::Block128;
use noid_poseidon2b::native::capacity_iv;
use noid_tx::native_assets::{
    NativeKind, COMPACT_NATIVE_OPENING_FIELDS as MAX_NATIVE_OPENING_FIELDS,
};

use super::{
    flat_of, mul, pin_zero, poseidon2b_permute, range_check_bits, FieldR1csBuilder, LinExpr, F128,
};

pub struct NativeOpeningRootTrace {
    /// Index zero is inactive; indices one through five select NativeKind.
    pub selectors: [LinExpr; 6],
    pub root: [LinExpr; 2],
}

/// Hash the five base native kinds with one matrix shape. The enclosing operation
/// binds these fields to its typed quantities, authority and exact State slot.
/// Kind zero frames an inactive position with zero fields and a zero root.
pub fn native_opening_root_trace(
    b: &mut FieldR1csBuilder,
    kind: &LinExpr,
    fields: &[LinExpr; MAX_NATIVE_OPENING_FIELDS],
) -> NativeOpeningRootTrace {
    const _: () = assert!(MAX_NATIVE_OPENING_FIELDS == 8);
    let bits = range_check_bits(b, kind, 3);
    let mut tensor = vec![LinExpr::constant(F128::ONE)];
    for bit in bits {
        let bit = LinExpr::from_wire(bit);
        let mut next = vec![LinExpr::zero(); tensor.len() * 2];
        for (index, value) in tensor.into_iter().enumerate() {
            let one = mul(b, &value, &bit);
            next[index] = value.add(&one);
            let half = next.len() / 2;
            next[index + half] = one;
        }
        tensor = next;
    }
    pin_zero(b, &tensor[6].add(&tensor[7]));
    let selectors: [LinExpr; 6] = std::array::from_fn(|i| tensor[i].clone());

    // Every kind uses a fixed canonical tail. An inactive position has all
    // fields zero, while six-field carriers also zero the unused final pair.
    for field in &fields[..5] {
        let unused = mul(b, &selectors[0], field);
        pin_zero(b, &unused);
    }
    let unused_five = selectors[0].add(&selectors[2]);
    let unused_five = mul(b, &unused_five, &fields[5]);
    pin_zero(b, &unused_five);
    let unused_six = selectors[0].add(&selectors[2]).add(&selectors[3]);
    let unused_six = mul(b, &unused_six, &fields[6]);
    pin_zero(b, &unused_six);
    pin_zero(b, &fields[7]);

    let mut iv = [LinExpr::zero(), LinExpr::zero()];
    for (index, selector) in selectors.iter().enumerate().skip(1) {
        let kind = NativeKind::from_u16(index as u16).expect("fixed native kind");
        let constants = capacity_iv(kind.tag());
        for lane in 0..2 {
            iv[lane] = iv[lane].add(&selector.scale(flat_of(constants[lane])));
        }
    }
    let mut state = [
        LinExpr::zero(),
        LinExpr::zero(),
        iv[0].clone(),
        iv[1].clone(),
    ];
    let mut short_root = [LinExpr::zero(), LinExpr::zero()];
    for (index, pair) in fields.chunks_exact(2).enumerate() {
        state[0] = state[0].add(&pair[0]);
        state[1] = state[1].add(&pair[1]);
        state = poseidon2b_permute(b, state);
        if index == 2 {
            short_root = [state[0].clone(), state[1].clone()];
        }
    }
    let short = selectors[2].add(&selectors[3]);
    let long = selectors[1].add(&selectors[4]).add(&selectors[5]);
    let root = std::array::from_fn(|lane| {
        let a = mul(b, &short, &short_root[lane]);
        let c = mul(b, &long, &state[lane]);
        a.add(&c)
    });
    NativeOpeningRootTrace { selectors, root }
}

/// A stable field-order helper for callers allocating opening witnesses.
pub fn native_opening_fields(
    b: &mut FieldR1csBuilder,
    fields: [Block128; MAX_NATIVE_OPENING_FIELDS],
) -> [LinExpr; MAX_NATIVE_OPENING_FIELDS] {
    fields.map(|field| super::alloc_block(b, field))
}
