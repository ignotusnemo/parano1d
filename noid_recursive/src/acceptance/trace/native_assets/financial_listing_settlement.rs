// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete listing rounds, deterministic delivery and beneficiary payouts.

use super::super::permutation_network::route_permutation_network;
use super::super::{
    alloc_block, flat_const, flat_of, mul, pin_eq, pin_zero, poseidon2b_permute, FieldR1csBuilder,
    LinExpr, F128,
};
use super::arithmetic::split_packed_input_value;
use super::arithmetic::{checked_add, checked_subtract, extend, less_than, multiply, pack};
use super::financial_actions::FinancialActionTrace;
use super::financial_cash_payouts::{
    bind_financial_cash_payouts, FinancialCashContributionTrace, FinancialCashOutputTrace,
};
use super::financial_definitions::{FinancialDefinitionsTrace, SelectedFinancialDefinitionTrace};
use super::financial_inventory_scan::{bind_financial_inventory_scan, FinancialInventoryRowTrace};
use super::financial_operation::FINANCIAL_OPERATION_CODES;
use super::financial_queue::{
    bind_financial_queue, bind_financial_round, funded_request_key_trace,
};
use super::header::FinancialNativeHeaderTrace;
use super::validation::is_zero;
use noid_core::{hardware::flat_to_tower_u128, Block128};
use noid_poseidon2b::native::{capacity_iv, DomainTag};
use noid_tx::native_assets::{
    market::queue::MAX_ROUND_REQUESTS,
    nft_market::{NFT_FEE_CREDIT, NFT_MAX_SETTLEMENT_FEE_PER_REQUEST},
    NativeKind,
};

pub struct FinancialListingSeedTrace {
    pub parent_id: [LinExpr; 2],
    pub parent_counter: LinExpr,
}
fn bits(b: &mut FieldR1csBuilder, x: &LinExpr, n: usize) -> Vec<LinExpr> {
    super::arithmetic::bits(b, x, n)
}
fn constant(x: u128, n: usize) -> Vec<LinExpr> {
    (0..n)
        .map(|i| LinExpr::constant(flat_const((x >> i) & 1)))
        .collect()
}
fn eq_when(b: &mut FieldR1csBuilder, flag: &LinExpr, a: &LinExpr, c: &LinExpr) {
    let bad = mul(b, flag, &a.add(c));
    pin_zero(b, &bad);
}
fn unique(b: &mut FieldR1csBuilder, seen: &LinExpr, flag: &LinExpr) -> LinExpr {
    let bad = mul(b, seen, flag);
    pin_zero(b, &bad);
    seen.add(flag)
}
fn tower(b: &FieldR1csBuilder, x: &LinExpr) -> u128 {
    let x = x.eval(b.values());
    flat_to_tower_u128(u128::from(x.lo) | (u128::from(x.hi) << 64))
}
fn digest_bits(b: &mut FieldR1csBuilder, x: &[LinExpr; 2]) -> Vec<LinExpr> {
    let raw = [bits(b, &x[0], 128), bits(b, &x[1], 128)].concat();
    (0..32)
        .rev()
        .flat_map(|byte| raw[8 * byte..8 * byte + 8].iter().cloned())
        .collect()
}
fn hash(b: &mut FieldR1csBuilder, tag: DomainTag, fields: &[LinExpr]) -> [LinExpr; 2] {
    assert!(fields.len().is_multiple_of(2));
    let iv = capacity_iv(tag);
    let mut s = [
        LinExpr::zero(),
        LinExpr::zero(),
        LinExpr::constant(flat_of(iv[0])),
        LinExpr::constant(flat_of(iv[1])),
    ];
    for x in fields.chunks_exact(2) {
        s[0] = s[0].add(&x[0]);
        s[1] = s[1].add(&x[1]);
        s = poseidon2b_permute(b, s);
    }
    [s[0].clone(), s[1].clone()]
}
fn request_rows(b: &mut FieldR1csBuilder, mut rows: Vec<Vec<LinExpr>>) -> Vec<Vec<LinExpr>> {
    rows.resize_with(
        rows.len().max(MAX_ROUND_REQUESTS).next_power_of_two(),
        || vec![LinExpr::zero(); 17],
    );
    let mut order = (0..rows.len()).collect::<Vec<_>>();
    order.sort_by_key(|&i| {
        (
            tower(b, &rows[i][0]) == 0,
            tower(b, &rows[i][1]).swap_bytes(),
            tower(b, &rows[i][2]).swap_bytes(),
            i,
        )
    });
    let mut p = vec![0; rows.len()];
    for (target, source) in order.into_iter().enumerate() {
        p[source] = target;
    }
    let rows = route_permutation_network(b, rows, &p);
    for row in &rows[MAX_ROUND_REQUESTS..] {
        pin_zero(b, &row[0]);
    }
    rows.into_iter().take(MAX_ROUND_REQUESTS).collect()
}

/// The enclosing relation binds complete physical actions, validated openings,
/// definitions, carrier values, State incarnations, canonical height and fees.
/// Each supplied seed is authenticated against the historical parent header
/// and allocation counter at the listing control's registration height.
pub fn bind_financial_listing_settlement(
    b: &mut FieldR1csBuilder,
    actions: &[FinancialActionTrace],
    definitions: &FinancialDefinitionsTrace,
    headers: &[FinancialNativeHeaderTrace],
    seeds: &[FinancialListingSeedTrace],
    height: &LinExpr,
) {
    assert_eq!(headers.len(), definitions.headers.len());
    assert_eq!(actions.len(), definitions.actions.len());
    assert_eq!(headers.len(), seeds.len());
    let current = bits(b, height, 64);
    let mut contributions = Vec::new();
    let mut cash_outputs = Vec::new();
    let mut inventory = Vec::with_capacity(actions.len());
    let flags = headers
        .iter()
        .map(|h| {
            h.metadata.financial[FINANCIAL_OPERATION_CODES
                .iter()
                .position(|&x| x == 71)
                .unwrap()]
            .clone()
        })
        .collect::<Vec<_>>();
    let keys = actions
        .iter()
        .map(|a| funded_request_key_trace(b, &a.root, &a.slot, &a.opening.creation_id.value))
        .collect::<Vec<_>>();
    for a in actions {
        let mut selected = LinExpr::zero();
        for (h, f) in headers.iter().zip(&flags) {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let f = mul(b, &same, f);
            selected = selected.add(&f);
        }
        let live = mul(b, &selected, &a.live);
        let ordinary = mul(b, &live, &a.native.add_const(F128::ONE));
        let ordinary = mul(b, &ordinary, &a.is_output);
        let ordinary_value = split_packed_input_value(b, &a.packed_value);
        cash_outputs.push(FinancialCashOutputTrace {
            live: ordinary.clone(),
            group: mul(b, &ordinary, &a.header_page),
            owner: std::array::from_fn(|j| mul(b, &ordinary, &a.root[j])),
            amount: mul(b, &ordinary, &ordinary_value.amount.value),
            ordinal: mul(b, &ordinary, &a.ordinal),
        });
        inventory.push(FinancialInventoryRowTrace {
            live: live.clone(),
            group: mul(b, &live, &a.header_page),
            slot: mul(b, &live, &a.slot),
            amounts: std::array::from_fn(|_| LinExpr::zero()),
            singleton: LinExpr::zero(),
            payload: std::array::from_fn(|_| LinExpr::zero()),
        });
    }
    let _ = bind_financial_inventory_scan(b, &inventory, headers.len());
    for (index, h) in headers.iter().enumerate() {
        let live = &flags[index];
        let mut d = SelectedFinancialDefinitionTrace {
            market: LinExpr::zero(),
            launch: LinExpr::zero(),
            listing: LinExpr::zero(),
            root: std::array::from_fn(|_| LinExpr::zero()),
            fields: std::array::from_fn(|_| LinExpr::zero()),
            base_is_noid: LinExpr::zero(),
        };
        let mut control: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        let mut seen = LinExpr::zero();
        let mut items = LinExpr::zero();
        let mut item_fields: [LinExpr; 12] = std::array::from_fn(|_| LinExpr::zero());
        let mut candidates = Vec::with_capacity(actions.len());
        for ((a, key), definition) in actions.iter().zip(&keys).zip(&definitions.actions) {
            let same = is_zero(b, &a.header_page.add(&h.header.header_page));
            let group = mul(b, &same, &a.live);
            let group = mul(b, &group, live);
            let input = mul(b, &group, &a.is_output.add_const(F128::ONE));
            let output = mul(b, &group, &a.is_output);
            let listing = mul(
                b,
                &input,
                a.opening.commitment.selector(NativeKind::NftListing),
            );
            let request = mul(
                b,
                &input,
                a.opening.commitment.selector(NativeKind::NftPurchase),
            );
            pin_eq(b, &input, &listing.add(&request));
            eq_when(b, &input, &a.native, &LinExpr::constant(F128::ONE));
            seen = unique(b, &seen, &listing);
            eq_when(
                b,
                &listing,
                &definition.listing,
                &LinExpr::constant(F128::ONE),
            );
            d.listing = d.listing.add(&mul(b, &listing, &definition.listing));
            for j in 0..8 {
                d.fields[j] = d.fields[j].add(&mul(b, &listing, &definition.fields[j]));
            }
            for j in 0..2 {
                d.root[j] = d.root[j].add(&mul(b, &listing, &definition.root[j]));
            }
            let item = mul(
                b,
                &output,
                a.opening.commitment.selector(NativeKind::NftItem),
            );
            let native_output = mul(b, &output, &a.native);
            pin_eq(b, &native_output, &item);
            items = unique(b, &items, &item);
            for j in 0..12 {
                control[j] = control[j].add(&mul(b, &listing, &a.opening.fields[j]));
                item_fields[j] = item_fields[j].add(&mul(b, &item, &a.opening.fields[j]));
            }
            let ordinal = mul(b, &item, &a.ordinal);
            let ordinal = bits(b, &ordinal, 12);
            let mut one = vec![LinExpr::zero(); 12];
            one[0] = item.clone();
            let count = checked_add(b, &ordinal, &one);
            eq_when(b, &item, &pack(&count), &h.header.output_count);
            let mut row = vec![request.clone()];
            row.extend(key.iter().map(|v| mul(b, &request, v)));
            row.extend(a.root.iter().map(|v| mul(b, &request, v)));
            row.extend(a.opening.fields.iter().map(|v| mul(b, &request, v)));
            candidates.push(row);
        }
        pin_eq(b, &seen, live);
        pin_eq(b, &items, live);
        pin_eq(b, &d.listing, live);
        for j in 0..2 {
            eq_when(b, live, &control[j], &d.root[j]);
            eq_when(b, live, &control[2 + j], &d.fields[j]);
        }
        let identity = split_packed_input_value(b, &control[4]);
        let serial = split_packed_input_value(b, &d.fields[6]);
        eq_when(b, live, &identity.amount.value, &serial.amount.value);
        let exhausted = is_zero(
            b,
            &identity
                .creation_id
                .value
                .add_const(flat_const(u128::from(u64::MAX))),
        );
        let bad = mul(b, live, &exhausted);
        pin_zero(b, &bad);
        let meta = bits(b, &control[7], 128);
        let registered = pack(&meta[..64]);
        let count = pack(&meta[64..80]);
        let phase = pack(&meta[80..]);
        eq_when(b, live, &phase, &LinExpr::constant(F128::ONE));
        let active_height = mul(b, live, &registered);
        let start = bits(b, &active_height, 64);
        let mut four = vec![LinExpr::zero(); 64];
        four[2] = live.clone();
        let timeout = checked_add(b, &start, &four);
        let after = less_than(b, &start, &current);
        eq_when(b, live, &after, &LinExpr::constant(F128::ONE));
        let before = less_than(b, &current, &timeout);
        eq_when(b, live, &before, &LinExpr::constant(F128::ONE));
        let price = split_packed_input_value(b, &d.fields[7]);
        let ask = mul(b, live, &price.amount.value);
        let expiry = price
            .creation_id
            .bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>();
        let before = less_than(b, &current, &expiry);
        eq_when(b, live, &before, &LinExpr::constant(F128::ONE));
        let mut one = vec![LinExpr::zero(); 64];
        one[0] = live.clone();
        let following = checked_add(b, &start, &one);
        let before = less_than(b, &following, &expiry);
        eq_when(b, live, &before, &LinExpr::constant(F128::ONE));
        let mut idle = control.clone();
        idle[5] = LinExpr::zero();
        idle[6] = LinExpr::zero();
        idle[7] = LinExpr::zero();
        let idle_root = hash(b, NativeKind::NftListing.tag(), &idle[..8]);
        let parent_id = std::array::from_fn(|j| mul(b, live, &seeds[index].parent_id[j]));
        let parent_counter = mul(b, live, &seeds[index].parent_counter);
        let round = bind_financial_round(
            b,
            &[LinExpr::zero(), LinExpr::zero(), live.clone()],
            &[control[0].clone(), control[1].clone()],
            &idle_root,
            &active_height,
            &parent_id,
            &parent_counter,
        );
        let rows = request_rows(b, candidates);
        let members = std::array::from_fn(|i| rows[i][0].clone());
        let keys = std::array::from_fn(|i| [rows[i][1].clone(), rows[i][2].clone()]);
        let queue = bind_financial_queue(b, live, &round, &keys, &members);
        eq_when(b, live, &queue.count, &count);
        for j in 0..2 {
            eq_when(b, live, &queue.root[j], &control[5 + j]);
        }
        let mut one = vec![LinExpr::zero(); 16];
        one[0] = live.clone();
        let count_bits = bits(b, &queue.count, 16);
        let expected_inputs = checked_add(b, &count_bits, &one);
        eq_when(b, live, &h.header.input_count, &pack(&expected_inputs));
        let mut best = vec![LinExpr::zero(); 768];
        let mut found = LinExpr::zero();
        let mut winner_index = LinExpr::zero();
        let mut recipient = [LinExpr::zero(), LinExpr::zero()];
        let mut incoming = vec![LinExpr::zero(); 68];
        incoming[0] = LinExpr::zero();
        for (i, row) in rows.iter().enumerate() {
            let member = &row[0];
            let f = &row[5..17];
            for j in 0..2 {
                eq_when(b, member, &f[j], &control[j]);
                eq_when(b, member, &f[2 + j], &round[j]);
            }
            let amount = split_packed_input_value(b, &f[8]);
            eq_when(b, member, &amount.creation_id.value, &registered);
            let budget = bits(b, &amount.amount.value, 64);
            let ask_selected = mul(b, member, &ask);
            let ask_bits = bits(b, &ask_selected, 64);
            let low = less_than(b, &budget, &ask_bits);
            let bad = mul(b, member, &low);
            pin_zero(b, &bad);
            let priority = hash(
                b,
                DomainTag::new(b"NMPRIOR1"),
                &[f[2].clone(), f[3].clone(), f[4].clone(), f[5].clone()],
            );
            let mut order = digest_bits(b, &[row[1].clone(), row[2].clone()]);
            order.extend(digest_bits(b, &[row[3].clone(), row[4].clone()]));
            order.extend(digest_bits(b, &priority));
            let less = less_than(b, &order, &best);
            let choose = mul(b, &found, &less).add(&found.add_const(F128::ONE));
            let choose = mul(b, member, &choose);
            for j in 0..768 {
                best[j] = best[j].add(&mul(b, &choose, &best[j].add(&order[j])));
            }
            winner_index = winner_index.add(&mul(
                b,
                &choose,
                &winner_index.add_const(flat_const(i as u128)),
            ));
            for j in 0..2 {
                recipient[j] = recipient[j].add(&mul(b, &choose, &recipient[j].add(&f[6 + j])));
            }
            found = found.add(&mul(b, member, &found.add_const(F128::ONE)));
            let credit = constant(u128::from(NFT_FEE_CREDIT), 68)
                .iter()
                .map(|x| mul(b, member, x))
                .collect::<Vec<_>>();
            let value = checked_add(b, &extend(&budget, 68), &credit);
            incoming = checked_add(b, &incoming, &value);
        }
        pin_eq(b, &found, live);
        let initial = constant(u128::from(NFT_FEE_CREDIT), 68)
            .iter()
            .map(|x| mul(b, live, x))
            .collect::<Vec<_>>();
        incoming = checked_add(b, &incoming, &initial);
        bits(b, &pack(&incoming), 63);
        let n = tower(b, &queue.count);
        let fee = tower(b, &h.header.fee);
        let quotient = alloc_block(b, Block128(if n == 0 { 0 } else { fee / n }));
        let remainder = alloc_block(b, Block128(if n == 0 { 0 } else { fee % n }));
        let qb = bits(b, &quotient, 16);
        let rb = bits(b, &remainder, 16);
        let nb = bits(b, &queue.count, 16);
        let rlow = less_than(b, &rb, &nb);
        eq_when(b, live, &rlow, &LinExpr::constant(F128::ONE));
        let product = multiply(b, &qb, &nb);
        let fee_bits = checked_add(b, &product, &extend(&rb, 32));
        eq_when(b, live, &pack(&fee_bits), &h.header.fee);
        let limit = multiply(
            b,
            &nb,
            &constant(u128::from(NFT_MAX_SETTLEMENT_FEE_PER_REQUEST), 16),
        );
        let over = less_than(b, &limit, &fee_bits);
        let bad = mul(b, live, &over);
        pin_zero(b, &bad);
        for (i, row) in rows.iter().enumerate() {
            let member = &row[0];
            let f = &row[5..17];
            let budget = split_packed_input_value(b, &f[8]);
            let winner = is_zero(b, &winner_index.add_const(flat_const(i as u128)));
            let winner = mul(b, member, &winner);
            let spent = mul(b, &winner, &ask);
            let budget = bits(b, &budget.amount.value, 64);
            let spent = bits(b, &spent, 64);
            let refund = checked_subtract(b, &budget, &spent);
            let credit = constant(u128::from(NFT_FEE_CREDIT), 64)
                .iter()
                .map(|x| mul(b, member, x))
                .collect::<Vec<_>>();
            let refund = checked_add(b, &refund, &credit);
            let extra = less_than(b, &constant(i as u128, 16), &rb);
            let extra = mul(b, member, &extra);
            let charge = qb.iter().map(|x| mul(b, member, x)).collect::<Vec<_>>();
            let mut extra_bits = vec![LinExpr::zero(); 64];
            extra_bits[0] = extra;
            let charge = checked_add(b, &extend(&charge, 64), &extra_bits);
            let refund = checked_subtract(b, &refund, &charge);
            contributions.push(FinancialCashContributionTrace {
                live: member.clone(),
                group: mul(b, member, &h.header.header_page),
                owner: [f[4].clone(), f[5].clone()],
                amount: pack(&refund),
            });
        }
        let ask_bits = bits(b, &ask, 64);
        let seller_credit = constant(u128::from(NFT_FEE_CREDIT), 64)
            .iter()
            .map(|x| mul(b, live, x))
            .collect::<Vec<_>>();
        let seller = checked_add(b, &ask_bits, &seller_credit);
        contributions.push(FinancialCashContributionTrace {
            live: live.clone(),
            group: mul(b, live, &h.header.header_page),
            owner: std::array::from_fn(|j| mul(b, live, &d.fields[2 + j])),
            amount: pack(&seller),
        });
        let expected: [LinExpr; 12] = std::array::from_fn(|j| match j {
            0 | 1 => mul(b, live, &d.fields[j]),
            2 | 3 => recipient[j - 2].clone(),
            4 | 5 => mul(b, live, &d.fields[j]),
            6 => mul(b, live, &serial.amount.value),
            _ => LinExpr::zero(),
        });
        for j in 0..12 {
            pin_eq(b, &item_fields[j], &expected[j]);
        }
    }
    bind_financial_cash_payouts(b, &contributions, &cash_outputs);
}
