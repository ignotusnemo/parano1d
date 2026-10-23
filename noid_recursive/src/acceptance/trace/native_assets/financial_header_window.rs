// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical recent-header context for registered financial rounds.

use noid_chain::BlockHeader;
use noid_tx::native_assets::NativeKind;

use crate::acceptance::block_slots::ParentSealTrace;

use super::super::{
    integer_add_no_overflow, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::range_check_bits;
use super::arithmetic::split_packed_input_value;
use super::financial_actions::FinancialActionTrace;
use super::financial_listing_settlement::FinancialListingSeedTrace;
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;

struct FinancialCanonicalHeaderTrace {
    live: LinExpr,
    seal: ParentSealTrace,
    registration_height: LinExpr,
}

pub struct FinancialHeaderWindowTrace {
    headers: Vec<FinancialCanonicalHeaderTrace>,
}

fn equal_when(b: &mut FieldR1csBuilder, live: &LinExpr, left: &LinExpr, right: &LinExpr) {
    let changed = mul(b, live, &left.add(right));
    pin_zero(b, &changed);
}

fn unique(b: &mut FieldR1csBuilder, seen: &LinExpr, selected: &LinExpr) -> LinExpr {
    let duplicate = mul(b, seen, selected);
    pin_zero(b, &duplicate);
    seen.add(selected)
}

impl FinancialHeaderWindowTrace {
    /// The first header is the same canonical parent as the enclosing State
    /// transition. Every live predecessor hashes to its child's exact link.
    pub fn bind(
        b: &mut FieldR1csBuilder,
        parent: &BlockHeader,
        ancestors: &[BlockHeader],
        parent_id: &[LinExpr; 2],
        parent_height: &LinExpr,
        parent_counter: &LinExpr,
    ) -> Self {
        assert!(ancestors.len() <= 3);
        let one = LinExpr::constant(F128::ONE);
        let mut headers: Vec<FinancialCanonicalHeaderTrace> = Vec::with_capacity(4);
        for index in 0..4 {
            let native = if index == 0 {
                parent
            } else {
                ancestors.get(index - 1).unwrap_or(parent)
            };
            let live = if index == 0 {
                one.clone()
            } else {
                LinExpr::from_wire(b.alloc_bool(index <= ancestors.len()))
            };
            let seal = ParentSealTrace::alloc(b, native);
            let registration_height = integer_add_no_overflow(b, &seal.height, &one, 64);
            let counter = range_check_bits(b, &seal.alloc_counter, 64);
            for high in &counter[62..] {
                let invalid = mul(b, &live, &LinExpr::from_wire(*high));
                pin_zero(b, &invalid);
            }
            if index == 0 {
                for lane in 0..2 {
                    pin_eq(b, &seal.block_id[lane], &parent_id[lane]);
                }
                pin_eq(b, &seal.height, parent_height);
                pin_eq(b, &seal.alloc_counter, parent_counter);
            } else {
                let previous = &headers[index - 1];
                let hole = mul(b, &live, &previous.live.add_const(F128::ONE));
                pin_zero(b, &hole);
                for lane in 0..2 {
                    equal_when(
                        b,
                        &live,
                        &seal.block_id[lane],
                        &previous.seal.previous_block_id[lane],
                    );
                }
                equal_when(b, &live, &registration_height, &previous.seal.height);
            }
            headers.push(FinancialCanonicalHeaderTrace {
                live,
                seal,
                registration_height,
            });
        }
        Self { headers }
    }

    /// Select the unique canonical parent of one registered round.
    pub fn seed_for_round(
        &self,
        b: &mut FieldR1csBuilder,
        live: &LinExpr,
        registered: &LinExpr,
    ) -> FinancialListingSeedTrace {
        let boolean = mul(b, live, &live.add_const(F128::ONE));
        pin_zero(b, &boolean);
        let mut found = LinExpr::zero();
        let mut parent_id = [LinExpr::zero(), LinExpr::zero()];
        let mut parent_counter = LinExpr::zero();
        for source in &self.headers {
            let same = is_zero(b, &source.registration_height.add(registered));
            let selected = mul(b, live, &source.live);
            let selected = mul(b, &selected, &same);
            found = unique(b, &found, &selected);
            for lane in 0..2 {
                parent_id[lane] =
                    parent_id[lane].add(&mul(b, &selected, &source.seal.block_id[lane]));
            }
            parent_counter = parent_counter.add(&mul(b, &selected, &source.seal.alloc_counter));
        }
        pin_eq(b, &found, live);
        FinancialListingSeedTrace {
            parent_id,
            parent_counter,
        }
    }

    /// Complete listing inputs select exactly one registered height and its
    /// authenticated parent id/counter. Other operations receive zero seeds.
    pub fn listing_seeds(
        &self,
        b: &mut FieldR1csBuilder,
        actions: &[FinancialActionTrace],
        headers: &[FinancialNativeHeaderTrace],
    ) -> Vec<FinancialListingSeedTrace> {
        let code = FINANCIAL_OPERATION_CODES
            .iter()
            .position(|&c| c == 71)
            .unwrap();
        headers
            .iter()
            .map(|header| {
                let live = &header.metadata.financial[code];
                let mut seen = LinExpr::zero();
                let mut registered = LinExpr::zero();
                for action in actions {
                    let group = is_zero(b, &action.header_page.add(&header.header.header_page));
                    let selected = mul(b, &group, &action.live);
                    let selected = mul(b, &selected, live);
                    let selected = mul(b, &selected, &action.is_output.add_const(F128::ONE));
                    let selected = mul(
                        b,
                        &selected,
                        action.opening.commitment.selector(NativeKind::NftListing),
                    );
                    seen = unique(b, &seen, &selected);
                    let time = split_packed_input_value(b, &action.opening.fields[7]);
                    registered = registered.add(&mul(b, &selected, &time.amount.value));
                }
                pin_eq(b, &seen, live);
                self.seed_for_round(b, live, &registered)
            })
            .collect()
    }
}
