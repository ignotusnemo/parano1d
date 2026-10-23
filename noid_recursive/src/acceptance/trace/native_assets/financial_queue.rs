// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Count-bound complete-set queue and native round commitments.

use super::super::accepted_claim_batch::compress_with_tag_trace;
use super::super::{
    flat_const, flat_of, mul, pin_zero, poseidon2b_permute, FieldR1csBuilder, LinExpr, F128,
};
use super::arithmetic::range_check_bits;
use super::arithmetic::{checked_add, less_than, pack};
use super::validation::{is_zero, require_nonzero};
use noid_poseidon2b::native::{capacity_iv, DomainTag};
use noid_tx::native_assets::market::queue::MAX_ROUND_REQUESTS;

fn digest_bits(b: &mut FieldR1csBuilder, value: &[LinExpr; 2]) -> Vec<LinExpr> {
    let raw = value
        .iter()
        .flat_map(|v| {
            range_check_bits(b, v, 128)
                .into_iter()
                .map(LinExpr::from_wire)
        })
        .collect::<Vec<_>>();
    (0..32)
        .rev()
        .flat_map(|byte| raw[8 * byte..8 * byte + 8].iter().cloned())
        .collect()
}
fn nonzero_pair(b: &mut FieldR1csBuilder, value: &[LinExpr; 2], when: &LinExpr) {
    let x = is_zero(b, &value[0]);
    let y = is_zero(b, &value[1]);
    let zero = mul(b, &x, &y);
    let bad = mul(b, when, &zero);
    pin_zero(b, &bad);
}
fn hash_fields(b: &mut FieldR1csBuilder, tag: DomainTag, fields: &[LinExpr]) -> [LinExpr; 2] {
    assert!(fields.len().is_multiple_of(2));
    let iv = capacity_iv(tag);
    let mut state = [
        LinExpr::zero(),
        LinExpr::zero(),
        LinExpr::constant(flat_of(iv[0])),
        LinExpr::constant(flat_of(iv[1])),
    ];
    for pair in fields.chunks_exact(2) {
        state[0] = state[0].add(&pair[0]);
        state[1] = state[1].add(&pair[1]);
        state = poseidon2b_permute(b, state);
    }
    [state[0].clone(), state[1].clone()]
}
pub fn funded_request_key_trace(
    b: &mut FieldR1csBuilder,
    root: &[LinExpr; 2],
    slot: &LinExpr,
    incarnation: &LinExpr,
) -> [LinExpr; 2] {
    compress_with_tag_trace(
        b,
        DomainTag::new(b"MKREQID1"),
        root,
        &[slot.clone(), incarnation.clone()],
    )
}

pub struct FinancialQueueTrace {
    pub count: LinExpr,
    pub root: [LinExpr; 2],
}
/// Keys are a strict byte-sorted live prefix with canonical zero padding.
/// The caller binds the complete routed funding/settlement request set.
pub fn bind_financial_queue(
    b: &mut FieldR1csBuilder,
    live: &LinExpr,
    round: &[LinExpr; 2],
    keys: &[[LinExpr; 2]; MAX_ROUND_REQUESTS],
    members: &[LinExpr; MAX_ROUND_REQUESTS],
) -> FinancialQueueTrace {
    let bad = mul(b, live, &live.add_const(F128::ONE));
    pin_zero(b, &bad);
    nonzero_pair(b, round, live);
    for lane in round {
        let inactive = mul(b, &live.add_const(F128::ONE), lane);
        pin_zero(b, &inactive);
    }
    let width = (MAX_ROUND_REQUESTS + 1)
        .next_power_of_two()
        .trailing_zeros() as usize;
    let mut count = vec![LinExpr::zero(); width];
    let mut previous_live = LinExpr::constant(F128::ONE);
    let mut previous_key: Option<Vec<LinExpr>> = None;
    for (key, member) in keys.iter().zip(members) {
        let bad = mul(b, member, &member.add_const(F128::ONE));
        pin_zero(b, &bad);
        let outside = mul(b, member, &live.add_const(F128::ONE));
        pin_zero(b, &outside);
        let hole = mul(b, member, &previous_live.add_const(F128::ONE));
        pin_zero(b, &hole);
        previous_live = member.clone();
        for lane in key {
            let padding = mul(b, &member.add_const(F128::ONE), lane);
            pin_zero(b, &padding);
        }
        let order = digest_bits(b, key);
        if let Some(old) = previous_key {
            let strict = less_than(b, &old, &order);
            let bad = mul(b, member, &strict.add_const(F128::ONE));
            pin_zero(b, &bad);
        }
        previous_key = Some(order);
        let mut delta = vec![LinExpr::zero(); width];
        delta[0] = member.clone();
        count = checked_add(b, &count, &delta);
    }
    let count = pack(&count);
    require_nonzero(b, &count, live);
    let mut layer = keys.to_vec();
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|pair| compress_with_tag_trace(b, DomainTag::new(b"MKQNOD21"), &pair[0], &pair[1]))
            .collect();
    }
    let root = hash_fields(
        b,
        DomainTag::new(b"MKQROOT1"),
        &[
            layer[0][0].clone(),
            layer[0][1].clone(),
            round[0].clone(),
            round[1].clone(),
            count.clone(),
            LinExpr::zero(),
        ],
    );
    let root = [mul(b, live, &root[0]), mul(b, live, &root[1])];
    FinancialQueueTrace { count, root }
}

/// The NFT round commits the canonical nonce-inclusive parent id and counter;
/// pool and launch rounds commit the actual idle control root and height.
pub fn bind_financial_round(
    b: &mut FieldR1csBuilder,
    family: &[LinExpr; 3],
    id: &[LinExpr; 2],
    control_root: &[LinExpr; 2],
    height: &LinExpr,
    parent_id: &[LinExpr; 2],
    parent_counter: &LinExpr,
) -> [LinExpr; 2] {
    for bit in family {
        let bad = mul(b, bit, &bit.add_const(F128::ONE));
        pin_zero(b, &bad);
    }
    for first in 0..3 {
        for second in first + 1..3 {
            let overlap = mul(b, &family[first], &family[second]);
            pin_zero(b, &overlap);
        }
    }
    let active = family.iter().fold(LinExpr::zero(), |sum, x| sum.add(x));
    let height_bits = range_check_bits(b, height, 64);
    let parent_bits = range_check_bits(b, parent_counter, 64);
    let height_value = pack(
        &height_bits
            .iter()
            .copied()
            .map(LinExpr::from_wire)
            .collect::<Vec<_>>(),
    );
    require_nonzero(b, &height_value, &active);
    let current = height_bits
        .iter()
        .copied()
        .map(|wire| mul(b, &active, &LinExpr::from_wire(wire)))
        .collect::<Vec<_>>();
    let delta = (0..64)
        .map(|i| {
            if i == 2 {
                active.clone()
            } else {
                LinExpr::zero()
            }
        })
        .collect::<Vec<_>>();
    let _timeout = checked_add(b, &current, &delta);
    nonzero_pair(b, parent_id, &family[2]);
    for bit in &parent_bits[62..] {
        let invalid = mul(b, &family[2], &LinExpr::from_wire(*bit));
        pin_zero(b, &invalid);
    }
    let packed_parent = parent_bits
        .iter()
        .enumerate()
        .fold(LinExpr::zero(), |sum, (i, &bit)| {
            sum.add(&LinExpr::from_wire(bit).scale(flat_const(1u128 << (64 + i))))
        });
    let packed = height_value.add(&packed_parent);
    let mut iv = [LinExpr::zero(), LinExpr::zero()];
    for (selected, tag) in family.iter().zip([
        DomainTag::new(b"MKROUND1"),
        DomainTag::new(b"LNROUND1"),
        DomainTag::new(b"NMROUND1"),
    ]) {
        let v = capacity_iv(tag);
        for lane in 0..2 {
            iv[lane] = iv[lane].add(&selected.scale(flat_of(v[lane])));
        }
    }
    let mut state = [
        mul(b, &active, &id[0]),
        mul(b, &active, &id[1]),
        iv[0].clone(),
        iv[1].clone(),
    ];
    state = poseidon2b_permute(b, state);
    for lane in 0..2 {
        state[lane] = state[lane].add(&mul(b, &active, &control_root[lane]));
    }
    state = poseidon2b_permute(b, state);
    let ordinary = family[0].add(&family[1]);
    state[0] = state[0].add(&mul(b, &ordinary, height));
    for lane in 0..2 {
        state[lane] = state[lane].add(&mul(b, &family[2], &parent_id[lane]));
    }
    state = poseidon2b_permute(b, state);
    let short = [state[0].clone(), state[1].clone()];
    state[0] = state[0].add(&mul(b, &family[2], &packed));
    state = poseidon2b_permute(b, state);
    std::array::from_fn(|lane| {
        let a = mul(b, &ordinary, &short[lane]);
        a.add(&mul(b, &family[2], &state[lane]))
    })
}
