// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Cumulative curve cash, maximal buys and same-step market graduation.

use super::super::super::{mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::super::arithmetic::{
    bits, checked_add, checked_subtract, extend, less_than, multiply, pack,
};
use super::super::validation::{is_zero, require_nonzero};
use super::market::{bind_sequential_market_candidate, SequentialMarketInputTrace};
use super::{bind_quotient, bind_same, boolean, number, select, value, witness};
use noid_tx::native_assets::{
    launch::{LAUNCH_MAX_SUPPLY, LAUNCH_MIN_SUPPLY},
    TOKEN_UNITS,
};

pub struct SequentialTradeInputTrace {
    pub live: LinExpr,
    pub curve: LinExpr,
    pub sell: LinExpr,
    pub supply: LinExpr,
    pub base_reserve: LinExpr,
    pub quote_reserve: LinExpr,
    pub gross_input: LinExpr,
    pub minimum_output: LinExpr,
}

pub struct SequentialTradeStepTrace {
    pub spent_input: LinExpr,
    pub output: LinExpr,
    pub market_fee: LinExpr,
    pub curve_spent: LinExpr,
    pub curve_output: LinExpr,
    pub after_curve: LinExpr,
    pub after_base: LinExpr,
    pub after_quote: LinExpr,
    pub graduated: LinExpr,
}

pub(super) struct CheckedCurveState {
    active: LinExpr,
    supply: LinExpr,
    cap: LinExpr,
    inventory: LinExpr,
    sold: LinExpr,
    cash: LinExpr,
    three_supply: LinExpr,
    denominator: LinExpr,
}

impl CheckedCurveState {
    fn fields(&self) -> [&LinExpr; 8] {
        [
            &self.active,
            &self.supply,
            &self.cap,
            &self.inventory,
            &self.sold,
            &self.cash,
            &self.three_supply,
            &self.denominator,
        ]
    }

    fn from_fields(fields: [LinExpr; 8]) -> Self {
        let [active, supply, cap, inventory, sold, cash, three_supply, denominator] = fields;
        Self {
            active,
            supply,
            cap,
            inventory,
            sold,
            cash,
            three_supply,
            denominator,
        }
    }

    pub(super) fn zero() -> Self {
        Self::from_fields(std::array::from_fn(|_| LinExpr::zero()))
    }

    pub(super) fn select(
        b: &mut FieldR1csBuilder,
        flag: &LinExpr,
        when_zero: &Self,
        when_one: &Self,
    ) -> Self {
        boolean(b, flag);
        let zero = when_zero.fields();
        let one = when_one.fields();
        Self::from_fields(std::array::from_fn(|index| {
            let value = select(b, flag, zero[index], one[index]);
            LinExpr::from_wire(b.materialize(&value))
        }))
    }

    /// Establish the cumulative cash relation at the exact initial market State.
    pub(super) fn initial(
        b: &mut FieldR1csBuilder,
        live: &LinExpr,
        curve: &LinExpr,
        supply: &LinExpr,
        base: &LinExpr,
        quote: &LinExpr,
    ) -> Self {
        boolean(b, live);
        boolean(b, curve);
        let active = mul(b, live, curve);
        let supply = mul(b, &active, supply);
        let supply_bits = bits(b, &supply, 54);
        let minimum_supply = bits(b, &number(u128::from(LAUNCH_MIN_SUPPLY)), 54);
        let maximum_supply = bits(b, &number(u128::from(LAUNCH_MAX_SUPPLY) + 1), 54);
        let too_small = less_than(b, &supply_bits, &minimum_supply);
        let too_large = less_than(b, &supply_bits, &maximum_supply).add_const(F128::ONE);
        let invalid = mul(b, &active, &too_small.add(&too_large));
        pin_zero(b, &invalid);
        let sv = value(b, &supply);
        let whole = witness(b, sv / u128::from(TOKEN_UNITS));
        let whole_bits = bits(b, &whole, 54);
        let whole_units = scaled(b, &whole_bits, u128::from(TOKEN_UNITS), 108);
        bind_same(b, &whole_units, &extend(&supply_bits, 108));
        let cap = witness(b, sv / 5 * 3);
        let cap_bits = bits(b, &cap, 54);
        let five_cap = scaled(b, &cap_bits, 5, 108);
        let three_supply = scaled(b, &supply_bits, 3, 108);
        bind_same(b, &five_cap, &three_supply);
        let inventory = mul(b, &active, quote);
        let inventory_bits = bits(b, &inventory, 54);
        let sold_bits = checked_subtract(b, &supply_bits, &inventory_bits);
        let sold = pack(&sold_bits);
        let before_cap = less_than(b, &sold_bits, &cap_bits);
        let invalid = mul(b, &active, &before_cap.add_const(F128::ONE));
        pin_zero(b, &invalid);
        let cash = mul(b, &active, base);
        let three_supply = scaled(b, &supply_bits, 3, 64);
        let denominator = scaled(b, &supply_bits, 900, 63);
        bind_cash(b, &active, &three_supply, &denominator, &sold_bits, &cash);
        Self::from_fields(
            [
                active,
                supply,
                cap,
                inventory,
                sold,
                cash,
                pack(&three_supply),
                pack(&denominator),
            ]
            .map(|field| LinExpr::from_wire(b.materialize(&field))),
        )
    }

    fn successor(
        b: &mut FieldR1csBuilder,
        old: &Self,
        active: &LinExpr,
        sold: &LinExpr,
        cash: &LinExpr,
        inventory: &LinExpr,
    ) -> Self {
        let fields = [
            active.clone(),
            mul(b, active, &old.supply),
            mul(b, active, &old.cap),
            mul(b, active, inventory),
            mul(b, active, sold),
            mul(b, active, cash),
            mul(b, active, &old.three_supply),
            mul(b, active, &old.denominator),
        ];
        Self::from_fields(fields.map(|field| LinExpr::from_wire(b.materialize(&field))))
    }
}

pub(super) fn scaled(
    b: &mut FieldR1csBuilder,
    value: &[LinExpr],
    factor: u128,
    width: usize,
) -> Vec<LinExpr> {
    let factor = bits(b, &number(factor), value.len());
    let product = multiply(b, value, &factor);
    assert!(width <= product.len());
    for high in &product[width..] {
        pin_zero(b, high);
    }
    product[..width].to_vec()
}

fn cash_value(supply: u128, sold: u128) -> u128 {
    if supply == 0 || supply > u128::from(LAUNCH_MAX_SUPPLY) || sold > supply {
        return 0;
    }
    (3 * supply * sold + 5 * sold * sold).div_ceil(900 * supply)
}

/// Bind C(s) = ceil((3*S*s + 5*s*s)/(900*S)) with full product widths.
fn bind_cash(
    b: &mut FieldR1csBuilder,
    active: &LinExpr,
    three_supply: &[LinExpr],
    denominator: &[LinExpr],
    sold: &[LinExpr],
    cash: &LinExpr,
) -> Vec<LinExpr> {
    let five_q = scaled(b, sold, 5, 64);
    let sum = checked_add(b, three_supply, &five_q);
    let numerator = multiply(b, &sum, &extend(sold, 64));
    let cash = bits(b, cash, 63);
    bind_quotient(b, active, &numerator, denominator, &cash, true);
    numerator
}

fn next_sold_value(supply: u128, sold: u128, gross: u128, sell: bool) -> u128 {
    if supply == 0
        || supply > u128::from(LAUNCH_MAX_SUPPLY)
        || sold >= supply / 5 * 3
        || gross > (1u128 << 63) - 1
    {
        return 0;
    }
    if sell {
        return sold.saturating_sub(gross);
    }
    let cap = supply / 5 * 3;
    let limit = cash_value(supply, sold) + gross;
    let (mut low, mut high) = (sold, cap);
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if cash_value(supply, middle) <= limit {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    low
}

/// The enclosing native relation binds identity, authorization, exact input
/// openings and final State. This predicate fixes every integer quote field.
pub fn bind_sequential_trade_step(
    b: &mut FieldR1csBuilder,
    input: &SequentialTradeInputTrace,
) -> SequentialTradeStepTrace {
    let initial = CheckedCurveState::initial(
        b,
        &input.live,
        &input.curve,
        &input.supply,
        &input.base_reserve,
        &input.quote_reserve,
    );
    bind_sequential_trade_step_with_curve(b, input, &initial).0
}

pub(super) fn bind_sequential_trade_step_with_curve(
    b: &mut FieldR1csBuilder,
    input: &SequentialTradeInputTrace,
    initial: &CheckedCurveState,
) -> (SequentialTradeStepTrace, CheckedCurveState) {
    for flag in [&input.live, &input.curve, &input.sell] {
        boolean(b, flag);
    }
    let curve = mul(b, &input.live, &input.curve);
    let market = input.live.add(&curve);
    let sell = mul(b, &curve, &input.sell);
    let buy = curve.add(&sell);
    let gross = mul(b, &input.live, &input.gross_input);
    let gross_bits = bits(b, &gross, 63);
    require_nonzero(b, &gross, &input.live);
    let minimum = mul(b, &input.live, &input.minimum_output);
    let minimum_bits = bits(b, &minimum, 63);
    require_nonzero(b, &minimum, &input.live);

    let supply = mul(b, &curve, &input.supply);
    let inventory = mul(b, &curve, &input.quote_reserve);
    let old_cash = mul(b, &curve, &input.base_reserve);
    pin_eq(b, &curve, &initial.active);
    pin_eq(b, &supply, &initial.supply);
    pin_eq(b, &inventory, &initial.inventory);
    pin_eq(b, &old_cash, &initial.cash);
    let supply_bits = bits(b, &initial.supply, 54);
    let cap = &initial.cap;
    let cap_bits = bits(b, cap, 54);
    let sold = &initial.sold;
    let sold_bits = bits(b, sold, 54);
    let old_cash_bits = bits(b, &old_cash, 63);
    let three_supply = bits(b, &initial.three_supply, 64);
    let denominator = bits(b, &initial.denominator, 63);
    let sv = value(b, &initial.supply);

    let next_sold = witness(
        b,
        next_sold_value(
            sv,
            value(b, &sold),
            value(b, &gross),
            value(b, &input.sell) != 0,
        ),
    );
    let next_sold_bits = bits(b, &next_sold, 54);
    let above_cap = less_than(b, &cap_bits, &next_sold_bits);
    pin_zero(b, &above_cap);
    let mut increasing = Vec::with_capacity(54);
    let mut decreasing = Vec::with_capacity(54);
    for (before, after) in sold_bits.iter().zip(&next_sold_bits) {
        increasing.push(select(b, &input.sell, after, before));
        decreasing.push(select(b, &input.sell, before, after));
    }
    let quantity_bits = checked_subtract(b, &increasing, &decreasing);
    let quantity = pack(&quantity_bits);
    require_nonzero(b, &quantity, &curve);
    let sell_quantity = mul(b, &sell, &quantity.add(&gross));
    pin_zero(b, &sell_quantity);
    let next_cash = witness(b, cash_value(sv, value(b, &next_sold)));
    let inactive_cash = mul(b, &curve.add_const(F128::ONE), &next_cash);
    pin_zero(b, &inactive_cash);
    let next_cash_bits = bits(b, &next_cash, 63);
    let next_numerator = bind_cash(
        b,
        &curve,
        &three_supply,
        &denominator,
        &next_sold_bits,
        &next_cash,
    );
    let mut larger = Vec::with_capacity(63);
    let mut smaller = Vec::with_capacity(63);
    for (before, after) in old_cash_bits.iter().zip(&next_cash_bits) {
        larger.push(select(b, &input.sell, after, before));
        smaller.push(select(b, &input.sell, before, after));
    }
    let cash_difference = pack(&checked_subtract(b, &larger, &smaller));
    let curve_spent = select(b, &input.sell, &cash_difference, &quantity);
    let curve_output = select(b, &input.sell, &quantity, &cash_difference);
    let at_cap = is_zero(b, &next_sold.add(&cap));
    let graduated = mul(b, &curve, &at_cap);
    let invalid = mul(b, &graduated, &input.sell);
    pin_zero(b, &invalid);

    let buy_old_cash = mul(b, &buy, &old_cash);
    let buy_gross = mul(b, &buy, &gross);
    let buy_cash_bits = bits(b, &buy_old_cash, 64);
    let buy_gross_bits = bits(b, &buy_gross, 64);
    let budget = checked_add(b, &buy_cash_bits, &buy_gross_bits);
    let buy_next_cash = mul(b, &buy, &next_cash);
    let buy_next_cash_bits = bits(b, &buy_next_cash, 64);
    checked_subtract(b, &budget, &buy_next_cash_bits);
    let noncap_buy = buy.add(&graduated);
    // N(q + 1) = N(q) + 3*S + 10*q + 5. For a positive denominator,
    // B < ceil(N(q + 1)/D) is exactly B*D < N(q + 1).
    let ten_next = scaled(b, &next_sold_bits, 10, 64);
    let delta = checked_add(b, &three_supply, &ten_next);
    let five = bits(b, &number(5), 64);
    let delta = checked_add(b, &delta, &five);
    let next_unit_numerator = checked_add(b, &next_numerator, &extend(&delta, 128));
    let budget_numerator = multiply(b, &budget, &extend(&denominator, 64));
    let maximal = less_than(b, &budget_numerator, &next_unit_numerator);
    let invalid = mul(b, &noncap_buy, &maximal.add_const(F128::ONE));
    pin_zero(b, &invalid);

    let curve_spent_bits = bits(b, &curve_spent, 63);
    let remaining = pack(&checked_subtract(b, &gross_bits, &curve_spent_bits));
    let next_inventory = pack(&checked_subtract(b, &supply_bits, &next_sold_bits));
    let market_base = mul(b, &market, &input.base_reserve).add(&mul(b, &graduated, &next_cash));
    let market_quote =
        mul(b, &market, &input.quote_reserve).add(&mul(b, &graduated, &next_inventory));
    let market_sell = mul(b, &market, &input.sell);
    let market_input = SequentialMarketInputTrace {
        live: market.add(&graduated),
        sell: market_sell,
        base_reserve: market_base,
        quote_reserve: market_quote,
        gross_input: remaining,
        minimum_output: LinExpr::zero(),
    };
    let market_step = bind_sequential_market_candidate(b, &market_input);
    let invalid = mul(b, &market, &market_step.executed.add_const(F128::ONE));
    pin_zero(b, &invalid);
    let market_spent_bits = bits(b, &market_step.spent_input, 63);
    let spent_input = pack(&checked_add(b, &curve_spent_bits, &market_spent_bits));
    let curve_output_bits = bits(b, &curve_output, 63);
    let market_output_bits = bits(b, &market_step.output, 63);
    let output_bits = checked_add(b, &curve_output_bits, &market_output_bits);
    let too_small = less_than(b, &output_bits, &minimum_bits);
    pin_zero(b, &too_small);
    let after_curve = curve.add(&graduated);
    let after_base = mul(b, &after_curve, &next_cash).add(&market_step.after_base);
    let after_quote = mul(b, &after_curve, &next_inventory).add(&market_step.after_quote);
    bits(b, &after_base, 63);
    bits(b, &after_quote, 63);
    let successor = CheckedCurveState::successor(
        b,
        initial,
        &after_curve,
        &next_sold,
        &next_cash,
        &next_inventory,
    );
    let step = SequentialTradeStepTrace {
        spent_input,
        output: pack(&output_bits),
        market_fee: market_step.fee,
        curve_spent,
        curve_output,
        after_curve,
        after_base,
        after_quote,
        graduated,
    };
    (step, successor)
}
