// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! First eligible fee quotation and canonical merged user payouts.

use super::super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::super::arithmetic::{bits, checked_add, checked_subtract, extend, less_than, pack};
use super::super::validation::is_zero;
use super::fees::TradeFeeQuoteTrace;
use super::funding::TradeFundingResultTrace;
use super::policy::TradePolicyTrace;
use super::{digest_bytes_bits, number, select};

const TOTAL_BITS: usize = 74;

#[derive(Clone)]
pub struct TradePayoutRowTrace {
    pub live: LinExpr,
    pub token: LinExpr,
    pub owner: [LinExpr; 2],
    pub units: LinExpr,
}
pub struct TradePayoutsTrace {
    pub fee: LinExpr,
    pub quote_count: LinExpr,
    pub output_count: LinExpr,
    pub payouts: [TradePayoutRowTrace; 3],
}
struct Candidate {
    eligible: LinExpr,
    payouts: [TradePayoutRowTrace; 3],
}

fn row(
    b: &mut FieldR1csBuilder,
    amount: &[LinExpr],
    token: &LinExpr,
    owner: &[LinExpr; 2],
) -> TradePayoutRowTrace {
    let units = pack(amount);
    let live = is_zero(b, &units).add_const(F128::ONE);
    TradePayoutRowTrace {
        token: mul(b, &live, token),
        owner: owner.clone().map(|lane| mul(b, &live, &lane)),
        units,
        live,
    }
}
fn selected_row(
    b: &mut FieldR1csBuilder,
    flag: &LinExpr,
    a: &TradePayoutRowTrace,
    c: &TradePayoutRowTrace,
) -> TradePayoutRowTrace {
    TradePayoutRowTrace {
        live: select(b, flag, &a.live, &c.live),
        token: select(b, flag, &a.token, &c.token),
        owner: std::array::from_fn(|lane| select(b, flag, &a.owner[lane], &c.owner[lane])),
        units: select(b, flag, &a.units, &c.units),
    }
}
fn order_bits(b: &mut FieldR1csBuilder, row: &TradePayoutRowTrace) -> Vec<LinExpr> {
    let mut key = digest_bytes_bits(b, &row.owner);
    key.push(row.token.clone());
    key.push(row.live.add_const(F128::ONE));
    key
}
fn sorted(
    b: &mut FieldR1csBuilder,
    mut rows: [TradePayoutRowTrace; 3],
) -> [TradePayoutRowTrace; 3] {
    for (first, second) in [(0, 1), (1, 2), (0, 1)] {
        let left = order_bits(b, &rows[first]);
        let right = order_bits(b, &rows[second]);
        let swap = less_than(b, &right, &left);
        let a = selected_row(b, &swap, &rows[first], &rows[second]);
        let c = selected_row(b, &swap, &rows[second], &rows[first]);
        rows[first] = a;
        rows[second] = c;
    }
    rows
}
fn candidate(
    b: &mut FieldR1csBuilder,
    policy: &TradePolicyTrace,
    funding: &TradeFundingResultTrace,
    spent: &LinExpr,
    output: &LinExpr,
    fee: &LinExpr,
    budget: usize,
) -> Candidate {
    let fee_bits = bits(b, fee, 32);
    let limit_bits = bits(b, &policy.input.fee_limit, 63);
    let exceeds = less_than(b, &limit_bits, &extend(&fee_bits, 63));
    let active = mul(b, &policy.input.live, &exceeds.add_const(F128::ONE));
    let buy = policy.input.live.add(&policy.input.sell);
    let noid = funding
        .noid
        .iter()
        .map(|bit| mul(b, &active, bit))
        .collect::<Vec<_>>();
    let tokens = funding
        .tokens
        .iter()
        .map(|bit| mul(b, &active, bit))
        .collect::<Vec<_>>();
    let principal = mul(b, &active, spent);
    let noid_principal = mul(b, &buy, &principal);
    let token_principal = mul(b, &policy.input.sell, &principal);
    let selected_fee = mul(b, &active, fee);
    let noid_spent = bits(b, &noid_principal, TOTAL_BITS);
    let token_spent = bits(b, &token_principal, TOTAL_BITS);
    let fee_bits = bits(b, &selected_fee, TOTAL_BITS);
    let paid = checked_add(b, &noid_spent, &fee_bits);
    let noid_refund = checked_subtract(b, &noid, &paid);
    let token_refund = checked_subtract(b, &tokens, &token_spent);
    let equal0 = is_zero(b, &policy.input.owner[0].add(&policy.input.recipient[0]));
    let equal1 = is_zero(b, &policy.input.owner[1].add(&policy.input.recipient[1]));
    let same_owner = mul(b, &equal0, &equal1);
    let received = mul(b, &active, output);
    let noid_merge = mul(b, &same_owner, &policy.input.sell);
    let token_merge = mul(b, &same_owner, &buy);
    let noid_output = mul(b, &noid_merge, &received);
    let token_output = mul(b, &token_merge, &received);
    let noid_output_bits = bits(b, &noid_output, TOTAL_BITS);
    let token_output_bits = bits(b, &token_output, TOTAL_BITS);
    let owner_noid = checked_add(b, &noid_refund, &noid_output_bits);
    let owner_tokens = checked_add(b, &token_refund, &token_output_bits);
    let recipient = mul(b, &same_owner.add_const(F128::ONE), &received);
    let recipient_bits = bits(b, &recipient, TOTAL_BITS);
    let mut fits = LinExpr::constant(F128::ONE);
    for amount in [&owner_noid, &owner_tokens, &recipient_bits] {
        let in_range = is_zero(b, &pack(&amount[64..]));
        fits = mul(b, &fits, &in_range);
    }
    let rows = [
        row(b, &owner_noid, &LinExpr::zero(), &policy.input.owner),
        row(b, &owner_tokens, &number(1), &policy.input.owner),
        row(b, &recipient_bits, &buy, &policy.input.recipient),
    ];
    let rows = sorted(b, rows);
    let mut count = vec![LinExpr::zero(); 3];
    for row in &rows {
        let mut one = vec![LinExpr::zero(); 3];
        one[0] = row.live.clone();
        count = checked_add(b, &count, &one);
    }
    let budget_bits = bits(b, &number(budget as u128), 3);
    let too_many = less_than(b, &budget_bits, &count);
    let fits_count = mul(b, &fits, &too_many.add_const(F128::ONE));
    Candidate {
        eligible: mul(b, &active, &fits_count),
        payouts: rows,
    }
}

/// Funding totals and quote fields come from the exact selected policy and
/// execution traces. Three fixed candidates establish the smallest admissible
/// fee, merge equal beneficiaries and retain native byte-order payout keys.
pub fn bind_trade_payouts(
    b: &mut FieldR1csBuilder,
    policy: &TradePolicyTrace,
    funding: &TradeFundingResultTrace,
    spent_input: &LinExpr,
    output: &LinExpr,
    fees: &TradeFeeQuoteTrace,
) -> TradePayoutsTrace {
    assert_eq!(funding.noid.len(), TOTAL_BITS);
    assert_eq!(funding.tokens.len(), TOTAL_BITS);
    let spent_bits = bits(b, spent_input, 63);
    let output_bits = bits(b, output, 63);
    let gross_bits = bits(b, &policy.input.gross_input, 63);
    let minimum_bits = bits(b, &policy.input.minimum_output, 63);
    let too_much = less_than(b, &gross_bits, &spent_bits);
    let too_little = less_than(b, &output_bits, &minimum_bits);
    pin_zero(b, &too_much);
    pin_zero(b, &too_little);
    for field in [spent_input, output] {
        let padding = mul(b, &policy.input.live.add_const(F128::ONE), field);
        pin_zero(b, &padding);
    }
    let blank = TradePayoutRowTrace {
        live: LinExpr::zero(),
        token: LinExpr::zero(),
        owner: [LinExpr::zero(), LinExpr::zero()],
        units: LinExpr::zero(),
    };
    let mut payouts = std::array::from_fn(|_| blank.clone());
    let mut fee = LinExpr::zero();
    let mut quote_count = LinExpr::zero();
    let mut found = LinExpr::zero();
    for (index, quote) in fees.quotes().iter().enumerate() {
        let candidate = candidate(b, policy, funding, spent_input, output, quote, index + 1);
        let chosen = mul(b, &candidate.eligible, &found.add_const(F128::ONE));
        found = found.add(&chosen);
        fee = fee.add(&mul(b, &chosen, quote));
        quote_count =
            quote_count.add(&chosen.scale(super::super::super::flat_const(index as u128 + 1)));
        for (actual, candidate) in payouts.iter_mut().zip(&candidate.payouts) {
            actual.live = actual.live.add(&mul(b, &chosen, &candidate.live));
            actual.token = actual.token.add(&mul(b, &chosen, &candidate.token));
            actual.units = actual.units.add(&mul(b, &chosen, &candidate.units));
            for lane in 0..2 {
                actual.owner[lane] =
                    actual.owner[lane].add(&mul(b, &chosen, &candidate.owner[lane]));
            }
        }
    }
    pin_eq(b, &found, &policy.input.live);
    let mut count = vec![LinExpr::zero(); 3];
    for payout in &payouts {
        bits(b, &payout.units, 64);
        let mut one = vec![LinExpr::zero(); 3];
        one[0] = payout.live.clone();
        count = checked_add(b, &count, &one);
    }
    TradePayoutsTrace {
        fee,
        quote_count,
        output_count: pack(&count),
        payouts,
    }
}
