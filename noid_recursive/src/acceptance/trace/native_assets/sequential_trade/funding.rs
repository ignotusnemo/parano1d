// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact policy funding streams, provenance and principal-anchor selection.

use super::super::super::{
    mul, pin_eq, pin_zero, poseidon2b_permute, FieldR1csBuilder, LinExpr, F128,
};
use super::super::arithmetic::{bits, checked_add, checked_subtract, extend, less_than, pack};
use super::super::validation::{is_zero, require_nonzero};
use super::policy::{gated_equal, packed, TradePolicyContextTrace, TradePolicyTrace};
use super::{boolean, hash_fields, hash_state, number, select};
use noid_poseidon2b::native::DomainTag;
use noid_tx::MAX_PAGED_SPEND_INPUTS;

const TOTAL_BITS: usize = 74;

pub struct TradeFundingInputTrace {
    pub live: LinExpr,
    pub slot: LinExpr,
    pub amount: LinExpr,
    pub creation_id: LinExpr,
    pub root: [LinExpr; 2],
    pub native: LinExpr,
    pub token_asset: [LinExpr; 2],
    pub token_owner: [LinExpr; 2],
    pub token_units: LinExpr,
    pub unlock_height: LinExpr,
}

#[derive(Clone)]
pub struct TradeFundingStateTrace {
    sponge: [LinExpr; 4],
    declared_count: LinExpr,
    count: Vec<LinExpr>,
    noid: Vec<LinExpr>,
    tokens: Vec<LinExpr>,
    previous_live: LinExpr,
    previous_slot: LinExpr,
    anchor_quantity: LinExpr,
    anchor_creation_id: LinExpr,
    anchor_slot: LinExpr,
}

#[derive(Clone)]
pub struct TradeFundingResultTrace {
    pub authorization_id: [LinExpr; 2],
    pub count: LinExpr,
    pub noid: Vec<LinExpr>,
    pub tokens: Vec<LinExpr>,
    pub anchor_quantity: LinExpr,
    pub anchor_creation_id: LinExpr,
    pub anchor_slot: LinExpr,
}

impl TradeFundingStateTrace {
    pub(crate) fn select(
        b: &mut FieldR1csBuilder,
        when: &LinExpr,
        when_zero: &Self,
        when_one: &Self,
    ) -> Self {
        let mut pick = |a: &LinExpr, c: &LinExpr| select(b, when, a, c);
        Self {
            sponge: std::array::from_fn(|i| pick(&when_zero.sponge[i], &when_one.sponge[i])),
            declared_count: pick(&when_zero.declared_count, &when_one.declared_count),
            count: when_zero
                .count
                .iter()
                .zip(&when_one.count)
                .map(|(a, c)| pick(a, c))
                .collect(),
            noid: when_zero
                .noid
                .iter()
                .zip(&when_one.noid)
                .map(|(a, c)| pick(a, c))
                .collect(),
            tokens: when_zero
                .tokens
                .iter()
                .zip(&when_one.tokens)
                .map(|(a, c)| pick(a, c))
                .collect(),
            previous_live: pick(&when_zero.previous_live, &when_one.previous_live),
            previous_slot: pick(&when_zero.previous_slot, &when_one.previous_slot),
            anchor_quantity: pick(&when_zero.anchor_quantity, &when_one.anchor_quantity),
            anchor_creation_id: pick(&when_zero.anchor_creation_id, &when_one.anchor_creation_id),
            anchor_slot: pick(&when_zero.anchor_slot, &when_one.anchor_slot),
        }
    }

    pub(crate) fn weighted_sum(b: &mut FieldR1csBuilder, terms: &[(&LinExpr, &Self)]) -> Self {
        let zero = Self::zero();
        let mut sum = zero.clone();
        for (when, state) in terms {
            let selected = Self::select(b, when, &zero, state);
            for i in 0..4 {
                sum.sponge[i] = sum.sponge[i].add(&selected.sponge[i]);
            }
            sum.declared_count = sum.declared_count.add(&selected.declared_count);
            for (a, c) in sum.count.iter_mut().zip(&selected.count) {
                *a = a.add(c);
            }
            for (a, c) in sum.noid.iter_mut().zip(&selected.noid) {
                *a = a.add(c);
            }
            for (a, c) in sum.tokens.iter_mut().zip(&selected.tokens) {
                *a = a.add(c);
            }
            sum.previous_live = sum.previous_live.add(&selected.previous_live);
            sum.previous_slot = sum.previous_slot.add(&selected.previous_slot);
            sum.anchor_quantity = sum.anchor_quantity.add(&selected.anchor_quantity);
            sum.anchor_creation_id = sum.anchor_creation_id.add(&selected.anchor_creation_id);
            sum.anchor_slot = sum.anchor_slot.add(&selected.anchor_slot);
        }
        sum
    }

    pub(crate) fn zero() -> Self {
        Self {
            sponge: std::array::from_fn(|_| LinExpr::zero()),
            declared_count: LinExpr::zero(),
            count: vec![LinExpr::zero(); 11],
            noid: vec![LinExpr::zero(); TOTAL_BITS],
            tokens: vec![LinExpr::zero(); TOTAL_BITS],
            previous_live: LinExpr::zero(),
            previous_slot: LinExpr::zero(),
            anchor_quantity: LinExpr::zero(),
            anchor_creation_id: LinExpr::zero(),
            anchor_slot: LinExpr::zero(),
        }
    }
}

/// Finish exactly one complete canonical policy boundary. Intermediate source
/// rows retain their running state without applying final budget predicates.
pub fn finish_trade_funding_at(
    b: &mut FieldR1csBuilder,
    when: &LinExpr,
    policy: &TradePolicyTrace,
    state: &TradeFundingStateTrace,
) -> TradeFundingResultTrace {
    boolean(b, when);
    let invalid = mul(b, when, &policy.input.live.add_const(F128::ONE));
    pin_zero(b, &invalid);
    let mut masked = policy.clone();
    masked.input.live = when.clone();
    masked.input.sell = mul(b, when, &policy.input.sell);
    masked.input.gross_input = mul(b, when, &policy.input.gross_input);
    masked.input.fee_limit = mul(b, when, &policy.input.fee_limit);
    let state = TradeFundingStateTrace::select(b, when, &TradeFundingStateTrace::zero(), state);
    finish_trade_funding(b, &masked, state)
}

pub fn begin_trade_funding(
    b: &mut FieldR1csBuilder,
    policy: &TradePolicyTrace,
    declared_count: &LinExpr,
) -> TradeFundingStateTrace {
    let live = &policy.input.live;
    let count = bits(b, declared_count, 11);
    let bound = bits(b, &number(MAX_PAGED_SPEND_INPUTS as u128 + 1), 11);
    let in_range = less_than(b, &count, &bound);
    let invalid = mul(b, live, &in_range.add_const(F128::ONE));
    pin_zero(b, &invalid);
    require_nonzero(b, declared_count, live);
    let padding = mul(b, &live.add_const(F128::ONE), declared_count);
    pin_zero(b, &padding);
    let sponge = hash_state(
        b,
        DomainTag::new(b"TRINT_21"),
        &[
            policy.root[0].clone(),
            policy.root[1].clone(),
            declared_count.clone(),
            live.clone(),
        ],
    );
    TradeFundingStateTrace {
        sponge,
        declared_count: declared_count.clone(),
        count: vec![LinExpr::zero(); 11],
        noid: vec![LinExpr::zero(); TOTAL_BITS],
        tokens: vec![LinExpr::zero(); TOTAL_BITS],
        previous_live: live.clone(),
        previous_slot: LinExpr::zero(),
        anchor_quantity: LinExpr::zero(),
        anchor_creation_id: LinExpr::zero(),
        anchor_slot: LinExpr::zero(),
    }
}

/// Each row is the next exact raw input of the selected policy. The enclosing
/// body relation binds this projection to its authenticated input action table.
pub fn append_trade_funding(
    b: &mut FieldR1csBuilder,
    context: &TradePolicyContextTrace,
    policy: &TradePolicyTrace,
    state: &TradeFundingStateTrace,
    row: &TradeFundingInputTrace,
) -> TradeFundingStateTrace {
    boolean(b, &row.live);
    boolean(b, &row.native);
    let hole = mul(b, &row.live, &state.previous_live.add_const(F128::ONE));
    pin_zero(b, &hole);
    for field in [
        &row.slot,
        &row.amount,
        &row.creation_id,
        &row.native,
        &row.token_units,
        &row.unlock_height,
    ]
    .into_iter()
    .chain(&row.root)
    .chain(&row.token_asset)
    .chain(&row.token_owner)
    {
        let padding = mul(b, &row.live.add_const(F128::ONE), field);
        pin_zero(b, &padding);
    }
    let slot_bits = bits(b, &row.slot, 32);
    let amount_bits = bits(b, &row.amount, 64);
    let creation = bits(b, &row.creation_id, 64);
    let units_bits = bits(b, &row.token_units, 64);
    let unlock = bits(b, &row.unlock_height, 64);
    let native = mul(b, &creation[62], &creation[63].add_const(F128::ONE));
    pin_eq(b, &native, &row.native);
    let ordinary = row.live.add(&row.native);
    require_nonzero(b, &row.creation_id, &row.live);
    require_nonzero(b, &row.amount, &ordinary);
    let invalid = mul(b, &row.native, &row.amount);
    pin_zero(b, &invalid);
    let invalid = mul(b, &row.native, &policy.input.sell.add_const(F128::ONE));
    pin_zero(b, &invalid);
    for field in row
        .token_asset
        .iter()
        .chain(&row.token_owner)
        .chain([&row.token_units, &row.unlock_height])
    {
        let unused = mul(b, &row.native.add_const(F128::ONE), field);
        pin_zero(b, &unused);
    }
    for lane in 0..2 {
        gated_equal(b, &ordinary, &row.root[lane], &policy.input.owner[lane]);
        gated_equal(
            b,
            &row.native,
            &row.token_asset[lane],
            &policy.input.asset[lane],
        );
        gated_equal(
            b,
            &row.native,
            &row.token_owner[lane],
            &policy.input.owner[lane],
        );
    }
    require_nonzero(b, &row.token_units, &row.native);
    let height_bits = bits(b, &context.height, 64);
    let before_unlock = less_than(b, &height_bits, &unlock);
    let invalid = mul(b, &row.native, &before_unlock);
    pin_zero(b, &invalid);
    let opening_fields = [
        row.token_asset[0].clone(),
        row.token_asset[1].clone(),
        row.token_owner[0].clone(),
        row.token_owner[1].clone(),
        packed(&row.token_units, &row.unlock_height),
        LinExpr::zero(),
    ];
    let token_root = hash_fields(b, DomainTag::new(b"NATBAL21"), &opening_fields);
    for lane in 0..2 {
        gated_equal(b, &row.native, &row.root[lane], &token_root[lane]);
    }

    let counter = bits(b, &context.parent_alloc_counter, 62);
    let sequence = &creation[..62];
    require_nonzero(b, &pack(sequence), &row.native);
    let beyond_counter = less_than(b, &counter, sequence);
    let counted = mul(b, &row.live, &creation[63].add_const(F128::ONE));
    let invalid = mul(b, &counted, &beyond_counter);
    pin_zero(b, &invalid);
    let one = bits(b, &number(1), 64);
    let parent_height = checked_subtract(b, &height_bits, &one);
    let coinbase_height = extend(&creation[..63], 64);
    let beyond_parent = less_than(b, &parent_height, &coinbase_height);
    let invalid = mul(b, &creation[63], &beyond_parent);
    pin_zero(b, &invalid);

    let previous_slot = bits(b, &state.previous_slot, 32);
    let has_previous = is_zero(b, &pack(&state.count)).add_const(F128::ONE);
    let ordered = less_than(b, &previous_slot, &slot_bits);
    let compare = mul(b, &row.live, &has_previous);
    let invalid = mul(b, &compare, &ordered.add_const(F128::ONE));
    pin_zero(b, &invalid);
    let mut increment = vec![LinExpr::zero(); 11];
    increment[0] = row.live.clone();
    let count = checked_add(b, &state.count, &increment);
    let noid = checked_add(b, &state.noid, &extend(&amount_bits, TOTAL_BITS));
    let tokens = checked_add(b, &state.tokens, &extend(&units_bits, TOTAL_BITS));

    let buy = policy.input.live.add(&policy.input.sell);
    let principal = mul(b, &buy, &ordinary).add(&mul(b, &policy.input.sell, &row.native));
    let quantity = row.amount.add(&row.token_units);
    let quantity_bits = bits(b, &quantity, 64);
    let old_quantity = bits(b, &state.anchor_quantity, 64);
    let old_creation = bits(b, &state.anchor_creation_id, 64);
    let old_slot = bits(b, &state.anchor_slot, 32);
    let larger_quantity = less_than(b, &old_quantity, &quantity_bits);
    let equal_quantity = is_zero(b, &state.anchor_quantity.add(&quantity));
    let smaller_creation = less_than(b, &creation, &old_creation);
    let equal_creation = is_zero(b, &state.anchor_creation_id.add(&row.creation_id));
    let smaller_slot = less_than(b, &slot_bits, &old_slot);
    let tie = smaller_creation.add(&mul(b, &equal_creation, &smaller_slot));
    let preferred = larger_quantity.add(&mul(b, &equal_quantity, &tie));
    let replace = mul(b, &principal, &preferred);

    let fields = [
        row.slot.clone(),
        packed(&row.amount, &row.creation_id),
        row.root[0].clone(),
        row.root[1].clone(),
    ];
    let mut next_sponge = state.sponge.clone();
    for pair in fields.chunks_exact(2) {
        next_sponge[0] = next_sponge[0].add(&pair[0]);
        next_sponge[1] = next_sponge[1].add(&pair[1]);
        next_sponge = poseidon2b_permute(b, next_sponge);
    }
    let sponge =
        std::array::from_fn(|lane| select(b, &row.live, &state.sponge[lane], &next_sponge[lane]));
    TradeFundingStateTrace {
        sponge,
        declared_count: state.declared_count.clone(),
        count,
        noid,
        tokens,
        previous_live: row.live.clone(),
        previous_slot: select(b, &row.live, &state.previous_slot, &row.slot),
        anchor_quantity: select(b, &replace, &state.anchor_quantity, &quantity),
        anchor_creation_id: select(b, &replace, &state.anchor_creation_id, &row.creation_id),
        anchor_slot: select(b, &replace, &state.anchor_slot, &row.slot),
    }
}

pub fn finish_trade_funding(
    b: &mut FieldR1csBuilder,
    policy: &TradePolicyTrace,
    state: TradeFundingStateTrace,
) -> TradeFundingResultTrace {
    let live = &policy.input.live;
    pin_eq(b, &pack(&state.count), &state.declared_count);
    let noid_principal = mul(
        b,
        &policy.input.sell.add_const(F128::ONE),
        &policy.input.gross_input,
    );
    let principal = bits(b, &noid_principal, TOTAL_BITS);
    let fee = bits(b, &policy.input.fee_limit, TOTAL_BITS);
    let required_noid = checked_add(b, &principal, &fee);
    let too_little_noid = less_than(b, &state.noid, &required_noid);
    pin_zero(b, &too_little_noid);
    let token_principal = mul(b, &policy.input.sell, &policy.input.gross_input);
    let token_principal = bits(b, &token_principal, TOTAL_BITS);
    let too_little_tokens = less_than(b, &state.tokens, &token_principal);
    pin_zero(b, &too_little_tokens);
    require_nonzero(b, &state.anchor_quantity, live);
    TradeFundingResultTrace {
        authorization_id: [
            mul(b, live, &state.sponge[0]),
            mul(b, live, &state.sponge[1]),
        ],
        count: pack(&state.count),
        noid: state.noid,
        tokens: state.tokens,
        anchor_quantity: state.anchor_quantity,
        anchor_creation_id: state.anchor_creation_id,
        anchor_slot: state.anchor_slot,
    }
}
