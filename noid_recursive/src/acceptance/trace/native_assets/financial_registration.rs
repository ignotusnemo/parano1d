// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact funded request extraction and final registration order.

use super::super::action_surface::ActionSurfaceTrace;
use super::super::paged_spend::NativePageContextTrace;
use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::arithmetic::range_check_bits;
use super::arithmetic::{checked_add, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_queue::funded_request_key_trace;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_tx::native_assets::{market::queue::MAX_ROUND_REQUESTS, NativeKind};

pub struct FinancialRegistrationRequestTrace {
    pub live: LinExpr,
    pub family: [LinExpr; 3],
    pub header_page: LinExpr,
    pub slot: LinExpr,
    pub creation_id: LinExpr,
    pub root: [LinExpr; 2],
    pub key: [LinExpr; 2],
    pub parent_slot: LinExpr,
    pub parent_creation_id: LinExpr,
    pub parent_root: [LinExpr; 2],
    pub fields: [LinExpr; 12],
}
pub struct FinancialRegistrationsTrace {
    pub requests: Vec<FinancialRegistrationRequestTrace>,
    pub family_counts: [LinExpr; 3],
}
fn increment(b: &mut FieldR1csBuilder, bits: &[LinExpr], flag: &LinExpr) -> Vec<LinExpr> {
    let mut delta = vec![LinExpr::zero(); bits.len()];
    delta[0] = flag.clone();
    checked_add(b, bits, &delta)
}
fn gated_eq(b: &mut FieldR1csBuilder, when: &LinExpr, actual: &LinExpr, expected: &LinExpr) {
    let invalid = mul(b, when, &actual.add(expected));
    pin_zero(b, &invalid);
}
/// Each registered market or launch request has one allocator-bound output.
/// The enclosing relation supplies complete hash-bound actions and exact
/// immutable-parent reads. This table retains every selected request.
pub fn bind_financial_registration_requests(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    headers: &[FinancialNativeHeaderTrace],
    parent_counter: &LinExpr,
) -> FinancialRegistrationsTrace {
    let counter = range_check_bits(b, parent_counter, 62)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let count_width = (actions.len() + 1)
        .next_power_of_two()
        .trailing_zeros()
        .max(1) as usize;
    let mut header_counts = vec![vec![LinExpr::zero(); count_width]; headers.len()];
    let mut family_counts: [Vec<LinExpr>; 3] = std::array::from_fn(|_| vec![LinExpr::zero(); 5]);
    let registration_actions = actions
        .iter()
        .map(|a| {
            [38, 50, 70].iter().fold(LinExpr::zero(), |sum, &code| {
                let code = is_zero(b, &a.operation.add_const(flat_const(code)));
                sum.add(&mul(b, &code, &a.live))
            })
        })
        .collect::<Vec<_>>();
    let mut requests = Vec::with_capacity(actions.len());
    for action in actions {
        let selectors = [
            (NativeKind::MarketRequest, 33),
            (NativeKind::MarketLiquidityDeposit, 34),
            (NativeKind::MarketLiquidityWithdrawal, 35),
            (NativeKind::MarketLiquidityBurn, 36),
            (NativeKind::LaunchRequest, 49),
            (NativeKind::NftPurchase, 65),
        ]
        .map(|(kind, code)| {
            let selected = mul(
                b,
                action.opening.commitment.selector(kind),
                &action.is_output,
            );
            gated_eq(
                b,
                &selected,
                &action.operation,
                &LinExpr::constant(flat_const(code)),
            );
            selected
        });
        let family = [
            selectors[..4]
                .iter()
                .fold(LinExpr::zero(), |sum, x| sum.add(x)),
            selectors[4].clone(),
            selectors[5].clone(),
        ];
        let live = family.iter().fold(LinExpr::zero(), |sum, x| sum.add(x));
        for i in 0..3 {
            family_counts[i] = increment(b, &family_counts[i], &family[i]);
        }
        let sequence = action.opening.creation_id.bits[..62]
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let after_parent = less_than(b, &counter, &sequence);
        gated_eq(b, &live, &after_parent, &LinExpr::constant(F128::ONE));
        let mut parent_slot = LinExpr::zero();
        let mut parent_creation_id = LinExpr::zero();
        let mut parent_root = [LinExpr::zero(), LinExpr::zero()];
        let mut found = vec![
            LinExpr::zero();
            (headers.len() + 1)
                .next_power_of_two()
                .trailing_zeros()
                .max(1) as usize
        ];
        for (index, header) in headers.iter().enumerate() {
            let same = is_zero(b, &action.header_page.add(&header.header.header_page));
            let selected = mul(b, &same, &header.metadata.registration_required);
            let selected = mul(b, &selected, &live);
            found = increment(b, &found, &selected);
            header_counts[index] = increment(b, &header_counts[index], &selected);
            parent_slot = parent_slot.add(&mul(b, &selected, &header.metadata.read_slot));
            parent_creation_id =
                parent_creation_id.add(&mul(b, &selected, &header.metadata.read_creation_id));
            for lane in 0..2 {
                parent_root[lane] =
                    parent_root[lane].add(&mul(b, &selected, &header.metadata.read_root[lane]));
            }
        }
        pin_eq(b, &pack(&found), &live);
        for (other, registration) in actions.iter().zip(&registration_actions) {
            let same_slot = is_zero(b, &action.slot.add(&other.slot));
            let invalid = mul(b, &same_slot, registration);
            let invalid = mul(b, &invalid, &live);
            pin_zero(b, &invalid);
        }
        let slot = mul(b, &live, &action.slot);
        let creation_id = mul(b, &live, &action.opening.creation_id.value);
        let root = std::array::from_fn(|i| mul(b, &live, &action.root[i]));
        let key =
            funded_request_key_trace(b, &root, &slot, &creation_id).map(|v| mul(b, &live, &v));
        requests.push(FinancialRegistrationRequestTrace {
            live: live.clone(),
            family,
            header_page: mul(b, &live, &action.header_page),
            slot,
            creation_id,
            root,
            key,
            parent_slot,
            parent_creation_id,
            parent_root,
            fields: std::array::from_fn(|i| mul(b, &live, &action.opening.fields[i])),
        });
    }
    for (count, header) in header_counts.iter().zip(headers) {
        pin_eq(b, &pack(count), &header.metadata.registration_required);
    }
    let family_counts = family_counts.map(|bits| {
        let maximum = (0..5)
            .map(|i| LinExpr::constant(flat_const(((MAX_ROUND_REQUESTS as u128) >> i) & 1)))
            .collect::<Vec<_>>();
        let too_many = less_than(b, &maximum, &bits);
        pin_zero(b, &too_many);
        pack(&bits)
    });
    FinancialRegistrationsTrace {
        requests,
        family_counts,
    }
}
/// Scan all physical groups, including ordinary payments and ABI 3 calls.
/// Every nonempty family occurs once in a strictly ascending final suffix.
pub fn bind_financial_registration_suffix(
    b: &mut FieldR1csBuilder,
    surfaces: &[ActionSurfaceTrace],
    pages: &[NativePageContextTrace],
    headers: &[FinancialNativeHeaderTrace],
    registrations: &FinancialRegistrationsTrace,
) {
    assert_eq!(surfaces.len(), pages.len());
    let mut seen: [LinExpr; 3] = std::array::from_fn(|_| LinExpr::zero());
    let mut seen_any = LinExpr::zero();
    for (surface, page) in surfaces.iter().zip(pages) {
        let family = [38, 50, 70].map(|code| {
            let op = is_zero(b, &page.operation.add_const(flat_const(code)));
            mul(b, &op, &surface.native_header)
        });
        let registration = family.iter().fold(LinExpr::zero(), |sum, x| sum.add(x));
        let starts = mul(b, &surface.tx_live, &surface.start);
        let following = mul(b, &starts, &seen_any);
        gated_eq(b, &following, &registration, &LinExpr::constant(F128::ONE));
        for current in 0..3 {
            for previous in current..3 {
                let invalid = mul(b, &family[current], &seen[previous]);
                pin_zero(b, &invalid);
            }
        }
        for i in 0..3 {
            seen[i] = seen[i].add(&family[i]);
        }
        seen_any = seen_any.add(&mul(b, &registration, &seen_any.add_const(F128::ONE)));
    }
    for i in 0..3 {
        let empty = is_zero(b, &registrations.family_counts[i]);
        pin_eq(b, &seen[i], &empty.add_const(F128::ONE));
    }
    for header in headers {
        let registration = [38, 50, 70].iter().fold(LinExpr::zero(), |sum, &code| {
            let op = is_zero(b, &header.header.operation.add_const(flat_const(code)));
            sum.add(&mul(b, &op, &header.header.live))
        });
        gated_eq(
            b,
            &registration,
            &header.header.input_count,
            &header.header.output_count,
        );
    }
}
