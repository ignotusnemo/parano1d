// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native request identities and complete grouped admission budgets.

use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr};
use super::actions::route_sorted;
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_subtract, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_budget_scan::{
    bind_financial_budget_scan, FinancialBudgetRowTrace, FinancialBudgetStepTrace,
};
use super::financial_registration::FinancialRegistrationsTrace;
use super::financial_registration_controls::FinancialRegisteredControlTrace;
use super::validation::is_zero;
use noid_tx::native_assets::{
    market::{queue::MAX_ROUND_REQUESTS, MARKET_QUANTITY_MAX},
    nft_market::NFT_FEE_CREDIT,
};

pub struct FinancialRegistrationBudgetsTrace {
    pub rows: Vec<FinancialBudgetRowTrace>,
    pub steps: Vec<FinancialBudgetStepTrace>,
}
fn bits(b: &mut FieldR1csBuilder, v: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, v, n)
}
fn pair_equal(b: &mut FieldR1csBuilder, a: &[LinExpr; 2], c: &[LinExpr; 2]) -> LinExpr {
    let first = is_zero(b, &a[0].add(&c[0]));
    let second = is_zero(b, &a[1].add(&c[1]));
    mul(b, &first, &second)
}
fn require_pair(b: &mut FieldR1csBuilder, when: &LinExpr, a: &[LinExpr; 2], c: &[LinExpr; 2]) {
    for i in 0..2 {
        let bad = mul(b, when, &a[i].add(&c[i]));
        pin_zero(b, &bad);
    }
}
fn compact(
    b: &mut FieldR1csBuilder,
    mut rows: Vec<Vec<LinExpr>>,
    limit: usize,
) -> Vec<Vec<LinExpr>> {
    let capacity = rows.len().max(limit).max(1).next_power_of_two();
    rows.resize_with(capacity, || vec![LinExpr::zero(); 16]);
    let rows = route_sorted(b, rows, 16, |_, _| Vec::new());
    for row in &rows[limit..] {
        pin_zero(b, &row[0]);
    }
    rows.into_iter().take(limit).collect()
}
/// All controls and members come from the complete registered-control relation.
/// The caller supplies the already constrained native header capacity and all
/// canonical carrier rules. Complete requests are compacted before quantity
/// decoding; no live source can be omitted. LP deposit side flags reuse the
/// shared definition link after their exact pool identities agree.
pub fn bind_financial_registration_budgets(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    registrations: &FinancialRegistrationsTrace,
    controls: &[FinancialRegisteredControlTrace],
    header_capacity: usize,
) -> FinancialRegistrationBudgetsTrace {
    assert_eq!(actions.len(), registrations.requests.len());
    assert!(!controls.is_empty());
    assert!(header_capacity >= 2);
    let request_capacity = (header_capacity - 1).min(3 * MAX_ROUND_REQUESTS);
    let mut rows = Vec::with_capacity(controls.len() + request_capacity);
    let mut supplies = Vec::new();
    let mut asks = Vec::new();
    for (index, control) in controls.iter().enumerate() {
        assert_eq!(control.members.len(), actions.len());
        let pool = &control.family[0];
        let launch = &control.family[1];
        let listing = &control.family[2];
        let state = mul(b, &pool.add(launch), &control.fields[2]);
        let state = split_packed_input_value(b, &state);
        pin_zero(b, &LinExpr::from_wire(state.amount.bits[63]));
        pin_zero(b, &LinExpr::from_wire(state.creation_id.bits[63]));
        let share_word = mul(b, pool, &control.fields[3]);
        let shares = split_packed_input_value(b, &share_word);
        pin_zero(b, &LinExpr::from_wire(shares.amount.bits[63]));
        pin_zero(b, &LinExpr::from_wire(shares.creation_id.bits[63]));
        let total = shares.amount.bits[..63]
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let locked = shares.creation_id.bits[..63]
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let available = pack(&checked_subtract(b, &total, &locked));
        let supply_word = mul(b, launch, &control.definition[4]);
        let supply = split_packed_input_value(b, &supply_word);
        pin_zero(b, &LinExpr::from_wire(supply.amount.bits[63]));
        let supply_bits = supply.amount.bits[..63]
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let inventory = state.amount.bits[..63]
            .iter()
            .map(|&v| mul(b, launch, &LinExpr::from_wire(v)))
            .collect::<Vec<_>>();
        let sold = pack(&checked_subtract(b, &supply_bits, &inventory));
        supplies.push(supply.amount.value);
        let ask_word = mul(b, listing, &control.definition[7]);
        let ask = split_packed_input_value(b, &ask_word);
        pin_zero(b, &LinExpr::from_wire(ask.amount.bits[63]));
        asks.push(ask.amount.value);
        let first = mul(b, pool, &state.amount.value)
            .add(&mul(b, launch, &state.creation_id.value))
            .add(&listing.scale(flat_const(u128::from(NFT_FEE_CREDIT))));
        let second = mul(b, pool, &state.creation_id.value);
        let second_limit = pool
            .scale(flat_const(u128::from(MARKET_QUANTITY_MAX)))
            .add(&sold);
        rows.push(FinancialBudgetRowTrace {
            live: control.live.clone(),
            control_index: control.live.scale(flat_const(index as u128 + 1)),
            request: LinExpr::zero(),
            request_index: LinExpr::zero(),
            amounts: [first, second, LinExpr::zero()],
            limits: [second_limit, available],
        });
    }
    let source = registrations
        .requests
        .iter()
        .zip(actions)
        .enumerate()
        .map(|(index, (request, action))| {
            let group = controls
                .iter()
                .enumerate()
                .fold(LinExpr::zero(), |sum, (j, c)| {
                    sum.add(&c.members[index].scale(flat_const(j as u128 + 1)))
                });
            let mut row = vec![
                request.live.clone(),
                group,
                mul(b, &request.live, &action.operation),
            ];
            row.extend(request.fields.iter().cloned());
            row.push(mul(b, &request.live, &action.opening.amount));
            assert_eq!(row.len(), 16);
            row
        })
        .collect();
    let requests = compact(b, source, request_capacity);
    for (index, row) in requests.iter().enumerate() {
        let live = &row[0];
        let mut found = LinExpr::zero();
        let mut definition: [LinExpr; 8] = std::array::from_fn(|_| LinExpr::zero());
        let mut id = [LinExpr::zero(), LinExpr::zero()];
        let mut supply = LinExpr::zero();
        let mut ask = LinExpr::zero();
        for (j, control) in controls.iter().enumerate() {
            let same = is_zero(b, &row[1].add_const(flat_const(j as u128 + 1)));
            let selected = mul(b, &same, &control.live);
            let selected = mul(b, &selected, live);
            found = found.add(&selected);
            for k in 0..8 {
                definition[k] = definition[k].add(&mul(b, &selected, &control.definition[k]));
            }
            for k in 0..2 {
                id[k] = id[k].add(&mul(b, &selected, &control.fields[k]));
            }
            supply = supply.add(&mul(b, &selected, &supplies[j]));
            ask = ask.add(&mul(b, &selected, &asks[j]));
        }
        pin_eq(b, &found, live);
        let flags = [33, 34, 35, 36, 49, 65].map(|code| {
            let same = is_zero(b, &row[2].add_const(flat_const(code)));
            mul(b, live, &same)
        });
        let total = flags.iter().fold(LinExpr::zero(), |sum, x| sum.add(x));
        pin_eq(b, &total, live);
        let [swap, deposit, withdraw, burn, launch, nft] = flags;
        let fields = &row[3..15];
        let input = [fields[2].clone(), fields[3].clone()];
        let output = [fields[4].clone(), fields[5].clone()];
        let base = [definition[2].clone(), definition[3].clone()];
        let quote = [definition[4].clone(), definition[5].clone()];
        let base_input = pair_equal(b, &input, &base);
        let base_input = mul(b, &swap, &base_input);
        let quote_input = pair_equal(b, &input, &quote);
        let quote_input = mul(b, &swap, &quote_input);
        pin_eq(b, &base_input.add(&quote_input), &swap);
        require_pair(b, &base_input, &output, &quote);
        require_pair(b, &quote_input, &output, &base);
        let lp = deposit.add(&withdraw).add(&burn);
        require_pair(b, &lp, &[fields[0].clone(), fields[1].clone()], &id);
        require_pair(
            b,
            &launch,
            &input,
            &[definition[0].clone(), definition[1].clone()],
        );
        require_pair(b, &nft, &[fields[0].clone(), fields[1].clone()], &id);
        let mut primary = mul(b, &swap, &fields[10]);
        primary = primary.add(&mul(b, &lp, &fields[6]));
        primary = primary.add(&mul(b, &launch.add(&nft), &fields[8]));
        let primary = split_packed_input_value(b, &primary);
        pin_zero(b, &LinExpr::from_wire(primary.amount.bits[63]));
        let narrow_high = mul(
            b,
            &swap.add(&deposit).add(&launch),
            &LinExpr::from_wire(primary.creation_id.bits[63]),
        );
        pin_zero(b, &narrow_high);
        let quantity = primary.amount.bits[..63]
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let high = primary.creation_id.bits[..63]
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let supply = bits(b, &supply, 63);
        let too_many = less_than(b, &supply, &quantity);
        let too_many = mul(b, &launch, &too_many);
        pin_zero(b, &too_many);
        let ask = bits(b, &ask, 63);
        let too_small = less_than(b, &quantity, &ask);
        let too_small = mul(b, &nft, &too_small);
        pin_zero(b, &too_small);
        let side = mul(b, &launch, &fields[9]);
        let side = bits(b, &side, 65);
        let sell = side[64].clone();
        let buy = launch.add(&sell);
        let nft_value = mul(b, &nft, &row[15]);
        let nft_value = bits(b, &nft_value, 63);
        let first = (0..63)
            .map(|i| {
                let value = mul(b, &base_input.add(&deposit), &quantity[i]);
                value.add(&mul(b, &buy, &high[i])).add(&nft_value[i])
            })
            .collect::<Vec<_>>();
        let second = (0..63)
            .map(|i| mul(b, &quote_input.add(&sell), &quantity[i]).add(&mul(b, &deposit, &high[i])))
            .collect::<Vec<_>>();
        let third = (0..63)
            .map(|i| mul(b, &withdraw.add(&burn), &quantity[i]))
            .collect::<Vec<_>>();
        rows.push(FinancialBudgetRowTrace {
            live: live.clone(),
            control_index: row[1].clone(),
            request: live.clone(),
            request_index: live.scale(flat_const(index as u128 + 1)),
            amounts: [pack(&first), pack(&second), pack(&third)],
            limits: [LinExpr::zero(), LinExpr::zero()],
        });
    }
    let steps = bind_financial_budget_scan(b, &rows, controls.len(), request_capacity);
    FinancialRegistrationBudgetsTrace { rows, steps }
}
