// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact launch control selection and complete ordered physical outputs.

use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::financial_actions::FinancialActionTrace;
use super::financial_control_rows::FinancialControlRowTrace;
use super::financial_controls::FinancialControlArithmeticTrace;
use super::financial_launch_effects_shared::FinancialLaunchEffectsTrace;
use super::financial_settlement_sets::FinancialSettlementSetTrace;
use super::validation::is_zero;
use noid_tx::native_assets::{market::queue::MAX_ROUND_REQUESTS, NativeKind};
fn eq_when(b: &mut FieldR1csBuilder, flag: &LinExpr, x: &LinExpr, y: &LinExpr) {
    let bad = mul(b, flag, &x.add(y));
    pin_zero(b, &bad);
}
/// Select the sole ordinal-zero output from the same complete shared control
/// table. Its coordinates, fields, root and integer remainder stay together.
pub fn bind_financial_launch_output_control(
    b: &mut FieldR1csBuilder,
    set: &FinancialSettlementSetTrace,
    controls: &[FinancialControlRowTrace],
) -> FinancialControlRowTrace {
    let live = &set.family[1];
    let mut found = LinExpr::zero();
    let mut group = LinExpr::zero();
    let mut fields: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
    let mut root = [LinExpr::zero(), LinExpr::zero()];
    let mut pool = LinExpr::zero();
    let mut launch = LinExpr::zero();
    let mut remainder = vec![LinExpr::zero(); 126];
    let mut sold_units = vec![LinExpr::zero(); 64];
    for c in controls {
        assert_eq!(c.arithmetic.remainder.len(), 126);
        assert_eq!(c.arithmetic.sold_units.len(), 64);
        let same = is_zero(b, &set.header_page.add(&c.header_page));
        let ordinal = is_zero(b, &c.ordinal);
        let selected = mul(b, live, &same);
        let selected = mul(b, &selected, &ordinal);
        let selected = mul(b, &selected, &c.live);
        let selected = mul(b, &selected, &c.is_output);
        let repeated = mul(b, &found, &selected);
        pin_zero(b, &repeated);
        found = found.add(&selected);
        group = group.add(&mul(b, &selected, &c.header_page));
        pool = pool.add(&mul(b, &selected, &c.arithmetic.pool));
        launch = launch.add(&mul(b, &selected, &c.arithmetic.launch));
        for j in 0..12 {
            fields[j] = fields[j].add(&mul(b, &selected, &c.fields[j]));
        }
        for j in 0..2 {
            root[j] = root[j].add(&mul(b, &selected, &c.root[j]));
        }
        for j in 0..126 {
            remainder[j] = remainder[j].add(&mul(b, &selected, &c.arithmetic.remainder[j]));
        }
        for j in 0..64 {
            sold_units[j] = sold_units[j].add(&mul(b, &selected, &c.arithmetic.sold_units[j]));
        }
    }
    pin_eq(b, &found, live);
    FinancialControlRowTrace {
        live: found.clone(),
        header_page: group,
        is_output: found,
        ordinal: LinExpr::zero(),
        root,
        fields,
        arithmetic: FinancialControlArithmeticTrace {
            pool,
            launch,
            remainder,
            sold_units,
        },
    }
}
/// Every physical output in this settlement is the exact ordinal-zero control
/// or one funded-key-ordered swap claim. No extra or repeated output is valid.
pub fn bind_financial_launch_effect_outputs(
    b: &mut FieldR1csBuilder,
    set: &FinancialSettlementSetTrace,
    effects: &FinancialLaunchEffectsTrace,
    actions: &[FinancialActionTrace],
) {
    let mut found = vec![LinExpr::zero(); MAX_ROUND_REQUESTS + 1];
    for a in actions {
        let same = is_zero(b, &a.header_page.add(&set.header_page));
        let selected = mul(b, &same, &a.live);
        let selected = mul(b, &selected, &a.is_output);
        let selected = mul(b, &selected, &effects.live);
        eq_when(b, &selected, &a.native, &LinExpr::constant(F128::ONE));
        let mut permitted = LinExpr::zero();
        for i in 0..=MAX_ROUND_REQUESTS {
            let ordinal = is_zero(b, &a.ordinal.add_const(flat_const(i as u128)));
            let hit = mul(b, &selected, &ordinal);
            let member = if i == 0 {
                effects.live.clone()
            } else {
                mul(b, &effects.live, &set.requests[i - 1].live)
            };
            eq_when(b, &hit, &member, &LinExpr::constant(F128::ONE));
            let repeated = mul(b, &found[i], &hit);
            pin_zero(b, &repeated);
            found[i] = found[i].add(&hit);
            permitted = permitted.add(&hit);
            let fields = if i == 0 {
                &effects.control
            } else {
                &effects.claims[i - 1]
            };
            for j in 0..12 {
                eq_when(b, &hit, &a.opening.fields[j], &fields[j]);
            }
            let kind = if i == 0 {
                let continuing = effects.live.add(&effects.graduated);
                mul(
                    b,
                    &continuing,
                    a.opening.commitment.selector(NativeKind::LaunchState),
                )
                .add(&mul(
                    b,
                    &effects.graduated,
                    a.opening.commitment.selector(NativeKind::MarketPool),
                ))
            } else {
                a.opening
                    .commitment
                    .selector(NativeKind::MarketClaim)
                    .clone()
            };
            eq_when(b, &hit, &kind, &LinExpr::constant(F128::ONE));
        }
        pin_eq(b, &permitted, &selected);
    }
    pin_eq(b, &found[0], &effects.live);
    for i in 0..MAX_ROUND_REQUESTS {
        let expected = mul(b, &effects.live, &set.requests[i].live);
        pin_eq(b, &found[i + 1], &expected);
    }
}
