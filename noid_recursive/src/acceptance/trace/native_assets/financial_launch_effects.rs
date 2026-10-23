// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact launch cash, claims, rounding and permanent-liquidity graduation.

use super::super::{
    alloc_block, const_block, flat_const, mul, pin_eq, pin_zero, poseidon2b_permute,
    FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, extend, less_than, multiply, pack};
use super::financial_bootstrap_root::bind_bootstrap_share_root;
use super::financial_control_rows::FinancialControlRowTrace;
use super::financial_ratio::bind_financial_ratio;
use super::financial_settlement_sets::FinancialSettlementSetTrace;
use super::validation::{is_zero, require_nonzero};
use noid_core::{hardware::flat_to_tower_u128, Block128};
use noid_poseidon2b::native::capacity_iv;
use noid_tx::native_assets::{
    market::{
        clearing::MAX_SETTLEMENT_FEE_PER_REQUEST, queue::MAX_ROUND_REQUESTS, MARKET_PROFILE,
        MARKET_REQUEST_FEE_CREDIT,
    },
    NativeKind,
};

pub struct FinancialLaunchEffectsTrace {
    pub live: LinExpr,
    pub graduated: LinExpr,
    pub control: [LinExpr; 12],
    pub claims: Vec<[LinExpr; 12]>,
    pub market_definition: [LinExpr; 8],
    pub market_definition_root: [LinExpr; 2],
    pub total_fee: LinExpr,
    pub rounding_fee: LinExpr,
    pub rounding_credit: LinExpr,
    pub costs: Vec<LinExpr>,
    pub proceeds: Vec<LinExpr>,
}
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn number(n: u128) -> LinExpr {
    LinExpr::constant(flat_const(n))
}
fn constant(n: u128, width: usize) -> Vec<LinExpr> {
    (0..width).map(|i| number((n >> i) & 1)).collect()
}
fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}
fn a(b: &mut FieldR1csBuilder, x: u128) -> LinExpr {
    alloc_block(b, Block128(x))
}
fn eq_when(b: &mut FieldR1csBuilder, f: &LinExpr, x: &LinExpr, y: &LinExpr) {
    let bad = mul(b, f, &x.add(y));
    pin_zero(b, &bad);
}
fn add_value(b: &mut FieldR1csBuilder, total: &mut Vec<LinExpr>, x: &LinExpr) {
    let value = bits(b, x, 64);
    *total = checked_add(b, total, &extend(&value, total.len()));
}
fn root(b: &mut FieldR1csBuilder, fields: &[LinExpr; 8], live: &LinExpr) -> [LinExpr; 2] {
    let tag = capacity_iv(NativeKind::MarketDefinition.tag());
    let mut state = [
        LinExpr::zero(),
        LinExpr::zero(),
        const_block(tag[0]),
        const_block(tag[1]),
    ];
    for pair in fields.chunks_exact(2) {
        state[0] = state[0].add(&pair[0]);
        state[1] = state[1].add(&pair[1]);
        state = poseidon2b_permute(b, state);
    }
    std::array::from_fn(|i| mul(b, live, &state[i]))
}

/// One exact complete frozen launch set supplies admission and source order.
/// The shared control table binds the same physical output's typed fields,
/// curve-cash or pool-product arithmetic, coordinates and commitment root.
/// Complete clearing supplies every final quantity and the common price.
pub fn bind_financial_launch_effects(
    b: &mut FieldR1csBuilder,
    set: &FinancialSettlementSetTrace,
    price: &[LinExpr; 2],
    quantities: &[LinExpr],
    protocol_fee: &LinExpr,
    output: &FinancialControlRowTrace,
) -> FinancialLaunchEffectsTrace {
    assert_eq!(set.requests.len(), MAX_ROUND_REQUESTS);
    assert_eq!(quantities.len(), MAX_ROUND_REQUESTS);
    assert_eq!(output.arithmetic.remainder.len(), 126);
    let live = &set.family[1];
    let count = mul(b, live, &set.count);
    let fee = mul(b, live, protocol_fee);
    let supply_word = mul(b, live, &set.definition[4]);
    let supply = split_packed_input_value(b, &supply_word);
    let supply = supply.amount.value;
    let supply_bits = bits(b, &supply, 64);
    require_nonzero(b, &supply, live);
    let sv = tower(b, &supply);
    let sale = a(b, sv / 5 * 3);
    bits(b, &sale, 64);
    let _ = bind_financial_ratio(
        b,
        live,
        &LinExpr::zero(),
        &supply,
        &number(3),
        &number(5),
        &sale,
        64,
    );
    let sale_bits = bits(b, &sale, 64);
    let dex = pack(&checked_subtract(b, &supply_bits, &sale_bits));
    let before = split_packed_input_value(b, &set.frozen[2]);
    let before_inventory = mul(b, live, &before.amount.value);
    let before_cash = mul(b, live, &before.creation_id.value);
    let before_inventory_bits = bits(b, &before_inventory, 68);
    let mut buys = vec![LinExpr::zero(); 68];
    let mut sells = vec![LinExpr::zero(); 68];
    let mut costs = Vec::with_capacity(MAX_ROUND_REQUESTS);
    let mut proceeds = Vec::with_capacity(MAX_ROUND_REQUESTS);
    let mut buy_cost = vec![LinExpr::zero(); 68];
    let mut sell_proceeds = vec![LinExpr::zero(); 68];
    let mut refunds = Vec::with_capacity(MAX_ROUND_REQUESTS);
    let mut outputs = Vec::with_capacity(MAX_ROUND_REQUESTS);
    let mut members = Vec::with_capacity(MAX_ROUND_REQUESTS);
    let mut buy_flags = Vec::with_capacity(MAX_ROUND_REQUESTS);
    let mut sell_flags = Vec::with_capacity(MAX_ROUND_REQUESTS);
    for (i, r) in set.requests.iter().enumerate() {
        let member = mul(b, live, &r.kinds[4]);
        let time = split_packed_input_value(b, &r.fields[9]);
        let sell = mul(b, &member, &time.creation_id.value);
        let buy = member.add(&sell);
        let terms = split_packed_input_value(b, &r.fields[8]);
        let requested = mul(b, &member, &terms.amount.value);
        let limit = mul(b, &member, &terms.creation_id.value);
        let q = mul(b, &member, &quantities[i]);
        let outside = mul(b, &member.add_const(F128::ONE), &quantities[i]);
        pin_zero(b, &outside);
        let qb = bits(b, &q, 63);
        let request_bits = bits(b, &requested, 63);
        let over = less_than(b, &request_bits, &qb);
        pin_zero(b, &over);
        require_nonzero(b, &requested, &member);
        let numerator = mul(b, &member, &price[0]);
        let denominator = mul(b, &member, &price[1]);
        let qv = tower(b, &q);
        let nv = tower(b, &numerator);
        let dv = tower(b, &denominator);
        let paying = tower(b, &buy) != 0;
        let amount = a(
            b,
            if dv == 0 {
                0
            } else if paying {
                qv.saturating_mul(nv).div_ceil(dv)
            } else {
                qv.saturating_mul(nv) / dv
            },
        );
        let amount_bits = bits(b, &amount, 63);
        let _ = bind_financial_ratio(b, &member, &buy, &q, &numerator, &denominator, &amount, 64);
        let rv = tower(b, &requested);
        let lv = tower(b, &limit);
        let bound = a(
            b,
            if rv == 0 {
                0
            } else if paying {
                lv.saturating_mul(qv).div_ceil(rv)
            } else {
                lv.saturating_mul(qv) / rv
            },
        );
        let bound_bits = bits(b, &bound, 63);
        let _ = bind_financial_ratio(b, &member, &buy, &limit, &q, &requested, &bound, 64);
        let low = less_than(b, &amount_bits, &bound_bits);
        let high = less_than(b, &bound_bits, &amount_bits);
        let bad = mul(b, &sell, &low).add(&mul(b, &buy, &high));
        pin_zero(b, &bad);
        let budget = bits(b, &limit, 63);
        let over = less_than(b, &budget, &amount_bits);
        let bad = mul(b, &buy, &over);
        pin_zero(b, &bad);
        let positive = is_zero(b, &q).add_const(F128::ONE);
        let empty = is_zero(b, &amount);
        let bad = mul(b, &sell, &positive);
        let bad = mul(b, &bad, &empty);
        pin_zero(b, &bad);
        let cost = mul(b, &buy, &amount);
        let received = mul(b, &sell, &amount);
        add_value(b, &mut buy_cost, &cost);
        add_value(b, &mut sell_proceeds, &received);
        let bought = mul(b, &buy, &q);
        let sold = mul(b, &sell, &q);
        add_value(b, &mut buys, &bought);
        add_value(b, &mut sells, &sold);
        let principal = mul(b, &buy, &limit).add(&mul(b, &sell, &requested));
        let spent = cost.add(&sold);
        let principal = bits(b, &principal, 64);
        let spent = bits(b, &spent, 64);
        refunds.push(pack(&checked_subtract(b, &principal, &spent)));
        outputs.push(bought.add(&received));
        members.push(member);
        buy_flags.push(buy);
        sell_flags.push(sell);
        costs.push(cost);
        proceeds.push(received);
    }
    let inventory = checked_add(b, &before_inventory_bits, &sells);
    let inventory = checked_subtract(b, &inventory, &buys);
    let inventory = pack(&inventory);
    let inventory_bits = bits(b, &inventory, 63);
    let sold = pack(&checked_subtract(
        b,
        &supply_bits,
        &extend(&inventory_bits, 64),
    ));
    let sale_bits = bits(b, &sale, 64);
    let sold_bits = bits(b, &sold, 64);
    let over = less_than(b, &sale_bits, &sold_bits);
    pin_zero(b, &over);
    let graduated = is_zero(b, &sold.add(&sale));
    let graduated = mul(b, live, &graduated);
    let continuing = live.add(&graduated);
    eq_when(b, live, &output.live, &number(1));
    eq_when(b, live, &output.header_page, &set.header_page);
    eq_when(b, live, &output.is_output, &number(1));
    eq_when(b, live, &output.ordinal, &LinExpr::zero());
    eq_when(b, live, &output.arithmetic.pool, &graduated);
    eq_when(b, live, &output.arithmetic.launch, &continuing);
    let post = split_packed_input_value(b, &output.fields[2]);
    let cash =
        mul(b, &continuing, &post.creation_id.value).add(&mul(b, &graduated, &post.amount.value));
    bits(b, &cash, 63);
    let graduation_cash = a(b, if sv == 0 { 0 } else { sv / 250 });
    bits(b, &graduation_cash, 63);
    let _ = bind_financial_ratio(
        b,
        &graduated,
        &LinExpr::zero(),
        &supply,
        &number(1),
        &number(250),
        &graduation_cash,
        64,
    );
    eq_when(b, &graduated, &cash, &graduation_cash);
    let shares = split_packed_input_value(b, &output.fields[3]);
    let shares = mul(b, &graduated, &shares.amount.value);
    let share_bits = bits(b, &shares, 63);
    bind_bootstrap_share_root(b, &graduated, &share_bits, &output.arithmetic.remainder);
    let temporal = split_packed_input_value(b, &set.frozen[3]);
    let generation = mul(b, &continuing, &temporal.amount.value);
    let generation = bits(b, &generation, 64);
    let generation = checked_add(b, &generation, &extend(&[continuing.clone()], 64));
    let mut definition: [LinExpr; 8] = std::array::from_fn(|_| LinExpr::zero());
    for j in 0..2 {
        definition[j] = mul(b, &graduated, &set.definition[2 + j]);
        definition[4 + j] = mul(b, &graduated, &set.definition[j]);
    }
    definition[6] = graduated.scale(flat_const(u128::from(MARKET_PROFILE)));
    let definition_root = root(b, &definition, &graduated);
    let mut control: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
    for j in 0..2 {
        control[j] = mul(b, &continuing, &set.frozen[j]).add(&definition_root[j]);
    }
    let pool_cash = mul(b, &graduated, &cash);
    let launch_inventory = mul(b, &continuing, &inventory);
    let dex_inventory = mul(b, &graduated, &dex);
    control[2] = launch_inventory.add(&pool_cash).add(
        &mul(b, &continuing, &cash)
            .add(&dex_inventory)
            .scale(flat_const(1u128 << 64)),
    );
    control[3] = pack(&generation)
        .add(&shares)
        .add(&shares.scale(flat_const(1u128 << 64)));
    control[7] = graduated.scale(flat_const(1u128 << 88));
    for j in 0..12 {
        eq_when(b, live, &output.fields[j], &control[j]);
    }
    let mut incoming = bits(b, &before_cash, 68);
    incoming = checked_add(b, &incoming, &buy_cost);
    let cash_bits = bits(b, &cash, 68);
    let outgoing = checked_add(b, &cash_bits, &sell_proceeds);
    let iv = tower(b, &pack(&incoming));
    let ov = tower(b, &pack(&outgoing));
    let rounding_fee = a(b, iv.saturating_sub(ov));
    let rounding_credit = a(b, ov.saturating_sub(iv));
    let rf = bits(b, &rounding_fee, 5);
    bits(b, &rounding_credit, 1);
    let both = mul(b, &rounding_fee, &rounding_credit);
    pin_zero(b, &both);
    let count_bits = bits(b, &count, 5);
    let limit = checked_add(b, &extend(&count_bits, 6), &extend(&[live.clone()], 6));
    let over = less_than(b, &limit, &extend(&rf, 6));
    pin_zero(b, &over);
    let mut balanced_in = incoming;
    add_value(b, &mut balanced_in, &rounding_credit);
    let mut balanced_out = outgoing;
    add_value(b, &mut balanced_out, &rounding_fee);
    pin_eq(b, &pack(&balanced_in), &pack(&balanced_out));
    let fee_bits = bits(b, &fee, 64);
    let total_fee = pack(&checked_add(b, &fee_bits, &extend(&rf, 64)));
    let cv = tower(b, &count);
    let fv = tower(b, &fee);
    let quotient = a(b, if cv == 0 { 0 } else { fv / cv });
    let remainder = a(b, if cv == 0 { 0 } else { fv % cv });
    let qbits = bits(b, &quotient, 16);
    let rbits = bits(b, &remainder, 5);
    let valid = less_than(b, &rbits, &count_bits);
    eq_when(b, live, &valid, &number(1));
    let product = multiply(b, &qbits, &extend(&count_bits, 16));
    let actual_fee = checked_add(b, &product, &extend(&rbits, 32));
    pin_eq(b, &pack(&actual_fee), &fee);
    let maximum = multiply(
        b,
        &extend(&count_bits, 16),
        &constant(u128::from(MAX_SETTLEMENT_FEE_PER_REQUEST), 16),
    );
    let over = less_than(b, &maximum, &actual_fee);
    pin_zero(b, &over);
    let mut claims = Vec::with_capacity(MAX_ROUND_REQUESTS);
    for (i, r) in set.requests.iter().enumerate() {
        let member = &members[i];
        let buy = &buy_flags[i];
        let sell = &sell_flags[i];
        let extra = less_than(b, &constant(i as u128, 5), &rbits);
        let mut charge = checked_add(b, &extend(&qbits, 64), &extend(&[extra], 64));
        if i == 0 {
            let credit = bits(b, &rounding_credit, 64);
            charge = checked_add(b, &charge, &credit);
        }
        let credit = pack(&checked_subtract(
            b,
            &constant(u128::from(MARKET_REQUEST_FEE_CREDIT), 64),
            &charge,
        ));
        let credit = mul(b, member, &credit);
        let mut claim: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        for j in 0..2 {
            claim[j] = mul(b, member, &r.key[j]);
            claim[2 + j] = mul(b, sell, &set.definition[j]);
            claim[4 + j] = mul(b, buy, &set.definition[j]);
            claim[6 + j] = mul(b, member, &r.fields[4 + j]);
            claim[8 + j] = mul(b, member, &r.fields[6 + j]);
        }
        claim[10] = refunds[i].add(&outputs[i].scale(flat_const(1u128 << 64)));
        claim[11] = credit;
        claims.push(claim);
    }
    FinancialLaunchEffectsTrace {
        live: live.clone(),
        graduated,
        control,
        claims,
        market_definition: definition,
        market_definition_root: definition_root,
        total_fee,
        rounding_fee,
        rounding_credit,
        costs,
        proceeds,
    }
}
