// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete registered queues and immutable frozen control successors.

use super::super::{flat_const, mul, pin_eq, pin_zero, FieldR1csBuilder, LinExpr, F128};
use super::actions::route_sorted as route;
use super::arithmetic::{checked_add, less_than, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_definitions::FinancialDefinitionsTrace;
use super::financial_queue::bind_financial_queue;
use super::financial_registration::FinancialRegistrationsTrace;
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_core::hardware::flat_to_tower_u128;
use noid_tx::native_assets::{market::queue::MAX_ROUND_REQUESTS, NativeKind};

pub struct FinancialRegisteredControlTrace {
    pub live: LinExpr,
    pub family: [LinExpr; 3],
    pub header_page: LinExpr,
    pub slot: LinExpr,
    pub creation_id: LinExpr,
    pub root: [LinExpr; 2],
    pub fields: [LinExpr; 12],
    pub definition: [LinExpr; 8],
    pub base_is_noid: LinExpr,
    pub round: [LinExpr; 2],
    pub members: Vec<LinExpr>,
    pub request_count: LinExpr,
    pub queue_root: [LinExpr; 2],
}
fn tower(b: &FieldR1csBuilder, value: &LinExpr) -> u128 {
    let f = value.eval(b.values());
    flat_to_tower_u128(u128::from(f.lo) | (u128::from(f.hi) << 64))
}
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn digest_order(b: &mut FieldR1csBuilder, root: &[LinExpr; 2]) -> Vec<LinExpr> {
    let raw = root
        .iter()
        .flat_map(|v| bits(b, v, 128))
        .collect::<Vec<_>>();
    (0..32)
        .rev()
        .flat_map(|byte| raw[byte * 8..byte * 8 + 8].iter().cloned())
        .collect()
}
fn increment(b: &mut FieldR1csBuilder, x: &[LinExpr], flag: &LinExpr) -> Vec<LinExpr> {
    let mut delta = vec![LinExpr::zero(); x.len()];
    delta[0] = flag.clone();
    checked_add(b, x, &delta)
}
fn family_match(b: &mut FieldR1csBuilder, a: &[LinExpr; 3], c: &[LinExpr; 3]) -> LinExpr {
    (0..3).fold(LinExpr::zero(), |sum, i| sum.add(&mul(b, &a[i], &c[i])))
}
fn shifted(b: &mut FieldR1csBuilder, x: &LinExpr, width: usize, shift: usize) -> LinExpr {
    bits(b, x, width)
        .iter()
        .enumerate()
        .fold(LinExpr::zero(), |sum, (i, v)| {
            sum.add(&v.scale(flat_const(1u128 << (shift + i))))
        })
}

/// The caller supplies complete actions, validated definitions and admission
/// rounds from exact immutable-parent Owner reads. Every request belongs to
/// exactly one consumed control and every frozen successor commits its full
/// funded set. Typed aggregate admission budgets compose on the returned rows.
pub fn bind_financial_registered_controls(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialNativeHeaderTrace],
    rounds: &[[LinExpr; 2]],
    registrations: &FinancialRegistrationsTrace,
    height: &LinExpr,
    parent_counter: &LinExpr,
    capacity: usize,
) -> Vec<FinancialRegisteredControlTrace> {
    assert_eq!(actions.len(), definitions.actions.len());
    assert_eq!(headers.len(), rounds.len());
    assert!(capacity > 0 && capacity <= actions.len().max(1).next_power_of_two());
    let source = actions
        .iter()
        .map(|a| {
            let family = [
                (38, NativeKind::MarketPool),
                (50, NativeKind::LaunchState),
                (70, NativeKind::NftListing),
            ]
            .map(|(code, kind)| {
                let op = is_zero(b, &a.operation.add_const(flat_const(code)));
                mul(b, &op, a.opening.commitment.selector(kind))
            });
            let control = family.iter().fold(LinExpr::zero(), |sum, x| sum.add(x));
            let mut registration = LinExpr::zero();
            for code in [38, 50, 70] {
                let op = is_zero(b, &a.operation.add_const(flat_const(code)));
                registration = registration.add(&mul(b, &op, &a.live));
            }
            pin_eq(b, &registration, &control);
            family
        })
        .collect::<Vec<_>>();
    // Public group inputs and outputs occupy distinct slots within each family.
    for i in 0..actions.len() {
        for j in i + 1..actions.len() {
            let family = family_match(b, &source[i], &source[j]);
            let same = is_zero(b, &actions[i].slot.add(&actions[j].slot));
            let bad = mul(b, &family, &same);
            pin_zero(b, &bad);
        }
    }
    let candidates = actions
        .iter()
        .zip(&source)
        .zip(&definitions.actions)
        .map(|((a, family), definition)| {
            let live = family.iter().fold(LinExpr::zero(), |sum, x| sum.add(x));
            let live = mul(b, &live, &a.is_output.add_const(F128::ONE));
            let mut row = vec![live.clone()];
            row.extend(family.iter().map(|x| mul(b, &live, x)));
            row.extend(
                [
                    &a.header_page,
                    &a.ordinal,
                    &a.slot,
                    &a.opening.creation_id.value,
                ]
                .map(|x| mul(b, &live, x)),
            );
            row.extend(a.root.iter().map(|x| mul(b, &live, x)));
            row.extend(a.opening.fields.iter().map(|x| mul(b, &live, x)));
            row.extend(definition.fields.iter().map(|x| mul(b, &live, x)));
            row.push(mul(b, &live, &definition.base_is_noid));
            assert_eq!(row.len(), 31);
            row
        })
        .collect::<Vec<_>>();
    let rows = route(b, candidates, 31, |b, row| {
        vec![
            tower(b, &row[2]) + 2 * tower(b, &row[3]),
            tower(b, &row[10]).swap_bytes(),
            tower(b, &row[11]).swap_bytes(),
        ]
    });
    for row in &rows[capacity..] {
        pin_zero(b, &row[0]);
    }
    let counter = bits(b, parent_counter, 62);
    let height_bits = bits(b, height, 64);
    let delta = (0..64)
        .map(|i| LinExpr::constant(flat_const(u128::from(i == 2))))
        .collect::<Vec<_>>();
    let timeout = pack(&checked_add(b, &height_bits, &delta));
    let height_high = shifted(b, height, 64, 64);
    let width = (capacity + 1).next_power_of_two().trailing_zeros().max(1) as usize;
    let mut coverage = vec![vec![LinExpr::zero(); width]; registrations.requests.len()];
    let mut result = Vec::new();
    let mut previous: Option<(LinExpr, [LinExpr; 3], Vec<LinExpr>, Vec<LinExpr>)> = None;
    for row in rows.iter().take(capacity) {
        let live = row[0].clone();
        let family: [LinExpr; 3] = std::array::from_fn(|i| row[1 + i].clone());
        let fields: [LinExpr; 12] = std::array::from_fn(|i| row[10 + i].clone());
        let id = [fields[0].clone(), fields[1].clone()];
        let mut order = digest_order(b, &id);
        order.extend([family[1].clone(), family[2].clone()]);
        let cid = bits(b, &row[7], 64);
        pin_eq(b, &cid[62], &live);
        pin_zero(b, &cid[63]);
        let future = less_than(b, &counter, &cid[..62]);
        pin_zero(b, &future);
        let mut round = [LinExpr::zero(), LinExpr::zero()];
        let mut found = LinExpr::zero();
        for (header, value) in headers.iter().zip(rounds) {
            let same_slot = is_zero(b, &row[6].add(&header.metadata.read_slot));
            let same_cid = is_zero(b, &row[7].add(&header.metadata.read_creation_id));
            let same_root0 = is_zero(b, &row[8].add(&header.metadata.read_root[0]));
            let same_root1 = is_zero(b, &row[9].add(&header.metadata.read_root[1]));
            let mut selected = mul(b, &same_slot, &same_cid);
            selected = mul(b, &selected, &same_root0);
            selected = mul(b, &selected, &same_root1);
            selected = mul(b, &selected, &header.metadata.read_required);
            selected = mul(b, &selected, &live);
            selected = mul(b, &selected, &found.add_const(F128::ONE));
            found = found.add(&selected);
            for lane in 0..2 {
                round[lane] = round[lane].add(&mul(b, &selected, &value[lane]));
            }
        }
        pin_eq(b, &found, &live);
        let mut members = Vec::new();
        let mut candidates: Vec<Vec<LinExpr>> = registrations
            .requests
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let mut selected = family_match(b, &family, &r.family);
                for (a, c) in [
                    (&row[6], &r.parent_slot),
                    (&row[7], &r.parent_creation_id),
                    (&row[8], &r.parent_root[0]),
                    (&row[9], &r.parent_root[1]),
                ] {
                    let same = is_zero(b, &a.add(c));
                    selected = mul(b, &selected, &same);
                }
                coverage[i] = increment(b, &coverage[i], &selected);
                members.push(selected.clone());
                vec![
                    selected.clone(),
                    mul(b, &selected, &r.key[0]),
                    mul(b, &selected, &r.key[1]),
                ]
            })
            .collect();
        candidates.resize_with(
            candidates.len().max(MAX_ROUND_REQUESTS).next_power_of_two(),
            || vec![LinExpr::zero(); 3],
        );
        let queue_rows = route(b, candidates, 3, |b, row| {
            vec![
                tower(b, &row[1]).swap_bytes(),
                tower(b, &row[2]).swap_bytes(),
            ]
        });
        for r in &queue_rows[MAX_ROUND_REQUESTS..] {
            pin_zero(b, &r[0]);
        }
        let keys = std::array::from_fn(|i| [queue_rows[i][1].clone(), queue_rows[i][2].clone()]);
        let selected = std::array::from_fn(|i| queue_rows[i][0].clone());
        let queue = bind_financial_queue(b, &live, &round, &keys, &selected);
        let mut output: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        let mut ordinal = LinExpr::zero();
        let mut count = vec![
            LinExpr::zero();
            (actions.len() + 1)
                .next_power_of_two()
                .trailing_zeros()
                .max(1) as usize
        ];
        for (a, other) in actions.iter().zip(&source) {
            let mut selected = family_match(b, &family, other);
            selected = mul(b, &selected, &a.is_output);
            for lane in 0..2 {
                let same = is_zero(b, &id[lane].add(&a.opening.fields[lane]));
                selected = mul(b, &selected, &same);
            }
            count = increment(b, &count, &selected);
            ordinal = ordinal.add(&mul(b, &selected, &a.ordinal));
            for i in 0..12 {
                output[i] = output[i].add(&mul(b, &selected, &a.opening.fields[i]));
            }
        }
        pin_eq(b, &pack(&count), &live);
        let ordinal_bits = bits(b, &ordinal, 9);
        if let Some((was_live, was_family, old_order, old_ordinal)) = previous {
            let hole = mul(b, &live, &was_live.add_const(F128::ONE));
            pin_zero(b, &hole);
            let strict = less_than(b, &old_order, &order);
            let unordered = mul(b, &live, &strict.add_const(F128::ONE));
            pin_zero(b, &unordered);
            let same = family_match(b, &family, &was_family);
            let canonical = less_than(b, &old_ordinal, &ordinal_bits);
            let bad = mul(b, &same, &canonical.add_const(F128::ONE));
            pin_zero(b, &bad);
        }
        previous = Some((live.clone(), family.clone(), order, ordinal_bits));
        let ordinary = family[0].add(&family[1]);
        let count_high = shifted(b, &queue.count, 5, 64);
        let phase = live.scale(flat_const(1u128 << 80));
        let mut meta = mul(b, &ordinary, &timeout).add(&count_high).add(&phase);
        let nft_height = mul(b, &family[2], height);
        meta = meta.add(&nft_height);
        let mut expected = fields.clone();
        expected[3] = fields[3].add(&mul(b, &family[1], &height_high));
        expected[4] = mul(b, &ordinary, &queue.root[0]).add(&mul(b, &family[2], &fields[4]));
        expected[5] = mul(b, &ordinary, &queue.root[1]).add(&mul(b, &family[2], &queue.root[0]));
        expected[6] = mul(b, &family[0], &fields[6].add(&height_high))
            .add(&mul(b, &family[1], &meta))
            .add(&mul(b, &family[2], &queue.root[1]));
        expected[7] =
            mul(b, &family[0].add(&family[2]), &meta).add(&row[30].scale(flat_const(1u128 << 88)));
        for i in 0..12 {
            pin_eq(b, &output[i], &expected[i]);
        }
        result.push(FinancialRegisteredControlTrace {
            live,
            family,
            header_page: row[4].clone(),
            slot: row[6].clone(),
            creation_id: row[7].clone(),
            root: [row[8].clone(), row[9].clone()],
            fields,
            definition: std::array::from_fn(|i| row[22 + i].clone()),
            base_is_noid: row[30].clone(),
            round,
            members,
            request_count: queue.count,
            queue_root: queue.root,
        });
    }
    for (count, r) in coverage.iter().zip(&registrations.requests) {
        pin_eq(b, &pack(count), &r.live);
    }
    result
}
