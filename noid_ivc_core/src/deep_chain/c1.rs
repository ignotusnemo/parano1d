//! Genuine extension-field ragged Poseidon walk for the C1 sidecar profile.
//!
//! Poseidon2b columns are still committed over `GF(2^128)`. The Boolean layer
//! states therefore remain base-field data. Claims, sumcheck messages, fold
//! challenges, folded tables, and terminal evaluations live in `GF(2^256)`.
//! This is one extension-field protocol, not two projected base-field runs.

use crate::challenger::Challenger;
use crate::field::{F128, F256};
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use super::{
    flat_mds, flat_round_constant, is_full_round, mul_pair,
    sbox7_affine_coeffs as base_sbox7_affine_coeffs, RaggedDescendingLayerStates, WalkError,
    WALK_DEGREE,
};

const C1_RAGGED_WALK_DOMAIN: &[u8] = b"history-deep-chain-ragged-multi-walk-c1-v1";

/// Four extension-field evaluations of one Poseidon state at one point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C1LaneClaimGroup {
    pub point: Vec<F256>,
    pub values: [F256; STATE_SIZE],
}

/// One layer of the genuine C1 ragged walk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct C1MultiWalkLayerProof {
    /// Compressed degree-eight coefficients `[c_0, c_2, ..., c_8]`.
    pub round_coeffs: Vec<[F256; WALK_DEGREE]>,
    /// Four next-layer values in canonical child order.
    pub next_values: Vec<[F256; STATE_SIZE]>,
}

/// One aggregate extension-field walk over differently sized children.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct C1MultiDeepChainWalkProof {
    pub layers: Vec<C1MultiWalkLayerProof>,
}

#[inline]
fn base_constant(value: usize) -> F256 {
    F256::from_base(F128::new(value as u64, 0))
}

/// Two independent quadratic-extension products. This small abstraction
/// exposes pairing opportunities to callers while retaining the faster fused
/// scalar reduction selected by the production laptop measurements.
#[inline]
fn mul_f256_pair(left_0: F256, right_0: F256, left_1: F256, right_1: F256) -> [F256; 2] {
    [left_0 * right_0, left_1 * right_1]
}

#[inline]
fn square_f256_pair(left: F256, right: F256) -> [F256; 2] {
    let square_base = |value: F128| {
        let flat = (value.lo as u128) | ((value.hi as u128) << 64);
        let square = noid_core::hardware::square_flat_u128(flat);
        F128::new(square as u64, (square >> 64) as u64)
    };
    let low_0 = square_base(left.lo);
    let low_1 = square_base(right.lo);
    let high_0 = square_base(left.hi);
    let high_1 = square_base(right.hi);
    let [tau_0, tau_1] = mul_pair(high_0, F256::EXTENSION_TAU, high_1, F256::EXTENSION_TAU);
    [
        F256::new(low_0 + tau_0, high_0),
        F256::new(low_1 + tau_1, high_1),
    ]
}

#[inline]
fn scale_base(value: F256, scalar: F128) -> F256 {
    let [lo, hi] = mul_pair(value.lo, scalar, value.hi, scalar);
    F256::new(lo, hi)
}

#[inline]
fn sbox7(value: F256) -> F256 {
    let square = value.square();
    let fourth = square.square();
    value * square * fourth
}

#[inline]
fn sbox7_affine_coeffs(a: F256, b: F256) -> [F256; WALK_DEGREE] {
    let [a2, b2] = square_f256_pair(a, b);
    let [a4, b4] = square_f256_pair(a2, b2);
    let [a4a2, b4b2] = mul_f256_pair(a4, a2, b4, b2);
    let [a4b2, b4a2] = mul_f256_pair(a4, b2, b4, a2);
    let [c0, c1] = mul_f256_pair(a4a2, a, a4a2, b);
    let [c2, c3] = mul_f256_pair(a4b2, a, a4b2, b);
    let [c4, c5] = mul_f256_pair(b4a2, a, b4a2, b);
    let [c6, c7] = mul_f256_pair(b4b2, a, b4b2, b);
    [c0, c1, c2, c3, c4, c5, c6, c7]
}

#[inline]
fn layer_terms(round: usize, values: &[F256; STATE_SIZE]) -> [F256; STATE_SIZE] {
    if is_full_round(round) {
        std::array::from_fn(|lane| {
            sbox7(values[lane] + F256::from_base(flat_round_constant(lane, round)))
        })
    } else {
        let mut terms = *values;
        terms[0] = sbox7(values[0] + F256::from_base(flat_round_constant(0, round)));
        terms
    }
}

fn lane_weight_table(alpha: F256, groups: usize) -> Vec<[F256; STATE_SIZE]> {
    let mut power = F256::ONE;
    (0..groups)
        .map(|_| {
            std::array::from_fn(|_| {
                power *= alpha;
                power
            })
        })
        .collect()
}

fn column_weights(round: usize, lane_weights: &[F256; STATE_SIZE]) -> [F256; STATE_SIZE] {
    let mds = flat_mds(is_full_round(round));
    std::array::from_fn(|column| {
        (0..STATE_SIZE).fold(F256::ZERO, |sum, lane| {
            sum + scale_base(lane_weights[lane], mds[lane][column])
        })
    })
}

fn build_eq_table(point: &[F256]) -> Vec<F256> {
    let mut table = Vec::with_capacity(1usize << point.len());
    table.push(F256::ONE);
    for (coordinate, &challenge) in point.iter().enumerate() {
        let length = 1usize << coordinate;
        table.resize(2 * length, F256::ZERO);
        for index in 0..length {
            let value = table[index];
            let high = value * challenge;
            table[index] = value + high;
            table[index + length] = high;
        }
    }
    table
}

fn eq_eval(left: &[F256], right: &[F256]) -> F256 {
    debug_assert_eq!(left.len(), right.len());
    left.iter()
        .zip(right)
        .fold(F256::ONE, |product, (&left, &right)| {
            // xy + (1 + x)(1 + y) = 1 + x + y in characteristic two.
            product * (F256::ONE + left + right)
        })
}

fn absorb_groups<C: Challenger>(channel: &mut C, w_logs: &[usize], groups: &[C1LaneClaimGroup]) {
    debug_assert_eq!(w_logs.len(), groups.len());
    channel.observe_label(C1_RAGGED_WALK_DOMAIN);
    channel.observe_f256(base_constant(groups.len()));
    for (&w_log, group) in w_logs.iter().zip(groups) {
        channel.observe_f256(base_constant(w_log));
        channel.observe_f256(F256::ONE);
        channel.observe_f256_slice(&group.point);
        channel.observe_f256_slice(&group.values);
    }
}

fn reconstruct(wire: &[F256; WALK_DEGREE], claim: F256) -> [F256; WALK_DEGREE + 1] {
    let mut linear = claim;
    for &coefficient in &wire[1..] {
        linear += coefficient;
    }
    let mut full = [F256::ZERO; WALK_DEGREE + 1];
    full[0] = wire[0];
    full[1] = linear;
    full[2..].copy_from_slice(&wire[1..]);
    full
}

fn compress(full: &[F256; WALK_DEGREE + 1]) -> [F256; WALK_DEGREE] {
    let mut wire = [F256::ZERO; WALK_DEGREE];
    wire[0] = full[0];
    wire[1..].copy_from_slice(&full[2..]);
    wire
}

#[inline]
fn horner(coefficients: &[F256; WALK_DEGREE + 1], point: F256) -> F256 {
    let mut value = coefficients[WALK_DEGREE];
    for degree in (0..WALK_DEGREE).rev() {
        value = value * point + coefficients[degree];
    }
    value
}

#[inline]
fn wide_relation_coefficients(
    round: usize,
    columns: &[F256; STATE_SIZE],
    state_base: &[F256; STATE_SIZE],
    state_delta: &[F256; STATE_SIZE],
) -> [F256; WALK_DEGREE] {
    if state_delta.iter().all(|value| value.is_zero()) {
        let terms = layer_terms(round, state_base);
        let [product_0, product_1] = mul_f256_pair(columns[0], terms[0], columns[1], terms[1]);
        let [product_2, product_3] = mul_f256_pair(columns[2], terms[2], columns[3], terms[3]);
        let mut relation = [F256::ZERO; WALK_DEGREE];
        relation[0] = product_0 + product_1 + product_2 + product_3;
        return relation;
    }
    let full_round = is_full_round(round);
    let mut relation = [F256::ZERO; WALK_DEGREE];
    for lane in 0..STATE_SIZE {
        let column = columns[lane];
        if column.is_zero() {
            continue;
        }
        if full_round || lane == 0 {
            let coefficients = sbox7_affine_coeffs(
                state_base[lane] + F256::from_base(flat_round_constant(lane, round)),
                state_delta[lane],
            );
            for degree in (0..WALK_DEGREE).step_by(2) {
                let [low, high] = mul_f256_pair(
                    column,
                    coefficients[degree],
                    column,
                    coefficients[degree + 1],
                );
                relation[degree] += low;
                relation[degree + 1] += high;
            }
        } else {
            let [constant, linear] =
                mul_f256_pair(column, state_base[lane], column, state_delta[lane]);
            relation[0] += constant;
            relation[1] += linear;
        }
    }
    relation
}

#[inline]
fn weighted_wide_relation_coefficients(
    round: usize,
    equality: F256,
    columns: &[F256; STATE_SIZE],
    state_base: &[F256; STATE_SIZE],
    state_delta: &[F256; STATE_SIZE],
) -> [F256; WALK_DEGREE] {
    let mut relation = [F256::ZERO; WALK_DEGREE];
    if state_delta.iter().all(|value| value.is_zero()) {
        let terms = layer_terms(round, state_base);
        let [product_0, product_1] = mul_f256_pair(columns[0], terms[0], columns[1], terms[1]);
        let [product_2, product_3] = mul_f256_pair(columns[2], terms[2], columns[3], terms[3]);
        relation[0] = equality * (product_0 + product_1 + product_2 + product_3);
        return relation;
    }
    if is_full_round(round) {
        let [weighted_0, weighted_1] = mul_f256_pair(equality, columns[0], equality, columns[1]);
        let [weighted_2, weighted_3] = mul_f256_pair(equality, columns[2], equality, columns[3]);
        let weighted_columns = [weighted_0, weighted_1, weighted_2, weighted_3];
        for lane in 0..STATE_SIZE {
            let coefficients = sbox7_affine_coeffs(
                state_base[lane] + F256::from_base(flat_round_constant(lane, round)),
                state_delta[lane],
            );
            for degree in (0..WALK_DEGREE).step_by(2) {
                let [low, high] = mul_f256_pair(
                    weighted_columns[lane],
                    coefficients[degree],
                    weighted_columns[lane],
                    coefficients[degree + 1],
                );
                relation[degree] += low;
                relation[degree + 1] += high;
            }
        }
    } else {
        let weighted_sbox = equality * columns[0];
        let coefficients = sbox7_affine_coeffs(
            state_base[0] + F256::from_base(flat_round_constant(0, round)),
            state_delta[0],
        );
        for degree in (0..WALK_DEGREE).step_by(2) {
            let [low, high] = mul_f256_pair(
                weighted_sbox,
                coefficients[degree],
                weighted_sbox,
                coefficients[degree + 1],
            );
            relation[degree] += low;
            relation[degree + 1] += high;
        }
        let mut passthrough_base = F256::ZERO;
        let mut passthrough_delta = F256::ZERO;
        for lane in 1..STATE_SIZE {
            let [base, delta] = mul_f256_pair(
                columns[lane],
                state_base[lane],
                columns[lane],
                state_delta[lane],
            );
            passthrough_base += base;
            passthrough_delta += delta;
        }
        let [base, delta] = mul_f256_pair(equality, passthrough_base, equality, passthrough_delta);
        relation[0] += base;
        relation[1] += delta;
    }
    relation
}

#[inline]
fn base_relation_coefficients(
    round: usize,
    columns: &[F256; STATE_SIZE],
    state_base: &[F128; STATE_SIZE],
    state_delta: &[F128; STATE_SIZE],
) -> [F256; WALK_DEGREE] {
    let full_round = is_full_round(round);
    let mut relation = [F256::ZERO; WALK_DEGREE];
    for lane in 0..STATE_SIZE {
        let column = columns[lane];
        if column.is_zero() {
            continue;
        }
        if full_round || lane == 0 {
            let coefficients = base_sbox7_affine_coeffs(
                state_base[lane] + flat_round_constant(lane, round),
                state_delta[lane],
            );
            for degree in 0..WALK_DEGREE {
                relation[degree] += scale_base(column, coefficients[degree]);
            }
        } else {
            relation[0] += scale_base(column, state_base[lane]);
            relation[1] += scale_base(column, state_delta[lane]);
        }
    }
    relation
}

#[inline]
fn weighted_base_relation_coefficients(
    round: usize,
    equality: F256,
    columns: &[F256; STATE_SIZE],
    state_base: &[F128; STATE_SIZE],
    state_delta: &[F128; STATE_SIZE],
) -> [F256; WALK_DEGREE] {
    let mut relation = [F256::ZERO; WALK_DEGREE];
    if state_delta.iter().all(|value| value.is_zero()) {
        let full_round = is_full_round(round);
        let terms = std::array::from_fn::<_, STATE_SIZE, _>(|lane| {
            if full_round || lane == 0 {
                super::sbox7(state_base[lane] + flat_round_constant(lane, round))
            } else {
                state_base[lane]
            }
        });
        let value = (0..STATE_SIZE).fold(F256::ZERO, |sum, lane| {
            sum + scale_base(columns[lane], terms[lane])
        });
        relation[0] = equality * value;
        return relation;
    }
    if is_full_round(round) {
        let [weighted_0, weighted_1] = mul_f256_pair(equality, columns[0], equality, columns[1]);
        let [weighted_2, weighted_3] = mul_f256_pair(equality, columns[2], equality, columns[3]);
        let weighted_columns = [weighted_0, weighted_1, weighted_2, weighted_3];
        for lane in 0..STATE_SIZE {
            let coefficients = base_sbox7_affine_coeffs(
                state_base[lane] + flat_round_constant(lane, round),
                state_delta[lane],
            );
            for degree in 0..WALK_DEGREE {
                relation[degree] += scale_base(weighted_columns[lane], coefficients[degree]);
            }
        }
    } else {
        let weighted_sbox = equality * columns[0];
        let coefficients = base_sbox7_affine_coeffs(
            state_base[0] + flat_round_constant(0, round),
            state_delta[0],
        );
        for degree in 0..WALK_DEGREE {
            relation[degree] += scale_base(weighted_sbox, coefficients[degree]);
        }
        let mut passthrough_base = F256::ZERO;
        let mut passthrough_delta = F256::ZERO;
        for lane in 1..STATE_SIZE {
            passthrough_base += scale_base(columns[lane], state_base[lane]);
            passthrough_delta += scale_base(columns[lane], state_delta[lane]);
        }
        let [base, delta] = mul_f256_pair(equality, passthrough_base, equality, passthrough_delta);
        relation[0] += base;
        relation[1] += delta;
    }
    relation
}

const CONSTANT_PAIR_CHUNK: usize = 128;

fn first_base_round_contribution(
    round: usize,
    point_coordinate: F256,
    tail_eq: &[F256],
    columns: &[F256; STATE_SIZE],
    states: &[[F128; STATE_SIZE]],
) -> [F256; WALK_DEGREE + 1] {
    debug_assert_eq!(states.len(), 2 * tail_eq.len());
    let relation_sum = tail_eq
        .par_chunks(CONSTANT_PAIR_CHUNK)
        .enumerate()
        .map(|(chunk, equality)| {
            let start = 2 * chunk * CONSTANT_PAIR_CHUNK;
            let states = &states[start..start + 2 * equality.len()];
            if states[1..].iter().all(|state| state == &states[0]) {
                let weight = equality.iter().copied().fold(F256::ZERO, |sum, x| sum + x);
                return base_relation_coefficients(
                    round,
                    columns,
                    &states[0],
                    &[F128::ZERO; STATE_SIZE],
                )
                .map(|coefficient| {
                    if coefficient.is_zero() {
                        F256::ZERO
                    } else {
                        weight * coefficient
                    }
                });
            }
            let mut accumulator = [F256::ZERO; WALK_DEGREE];
            for (pair, &weight) in equality.iter().enumerate() {
                let state_base = states[2 * pair];
                let state_next = states[2 * pair + 1];
                let state_delta = std::array::from_fn(|lane| state_base[lane] + state_next[lane]);
                let relation = weighted_base_relation_coefficients(
                    round,
                    weight,
                    columns,
                    &state_base,
                    &state_delta,
                );
                for degree in 0..WALK_DEGREE {
                    accumulator[degree] += relation[degree];
                }
            }
            accumulator
        })
        .reduce(
            || [F256::ZERO; WALK_DEGREE],
            |mut left, right| {
                for (left, right) in left.iter_mut().zip(right) {
                    *left += right;
                }
                left
            },
        );
    convolve_equality_factor(relation_sum, F256::ONE + point_coordinate)
}

#[inline]
fn convolve_equality_factor(
    relation_sum: [F256; WALK_DEGREE],
    zero_factor: F256,
) -> [F256; WALK_DEGREE + 1] {
    let mut contribution = [F256::ZERO; WALK_DEGREE + 1];
    for degree in (0..WALK_DEGREE).step_by(2) {
        let relation_low = relation_sum[degree];
        let relation_high = relation_sum[degree + 1];
        if relation_low.is_zero() && relation_high.is_zero() {
            continue;
        }
        let (low, high) = if relation_high.is_zero() {
            (zero_factor * relation_low, F256::ZERO)
        } else if relation_low.is_zero() {
            (F256::ZERO, zero_factor * relation_high)
        } else {
            let [low, high] = mul_f256_pair(zero_factor, relation_low, zero_factor, relation_high);
            (low, high)
        };
        contribution[degree] += low;
        contribution[degree + 1] += relation_low + high;
        contribution[degree + 2] += relation_high;
    }
    contribution
}

fn exhausted_base_round_contribution(
    round: usize,
    eq: F256,
    columns: &[F256; STATE_SIZE],
    state: &[F128; STATE_SIZE],
) -> [F256; WALK_DEGREE + 1] {
    let relation = base_relation_coefficients(round, columns, state, &[F128::ZERO; STATE_SIZE]);
    let mut contribution = [F256::ZERO; WALK_DEGREE + 1];
    for degree in (0..WALK_DEGREE).step_by(2) {
        let [low, high] = mul_f256_pair(eq, relation[degree], eq, relation[degree + 1]);
        contribution[degree] += low;
        contribution[degree + 1] += low + high;
        contribution[degree + 2] += high;
    }
    contribution
}

#[inline]
fn scale_contribution(
    contribution: [F256; WALK_DEGREE + 1],
    scalar: F256,
) -> [F256; WALK_DEGREE + 1] {
    if scalar == F256::ONE {
        contribution
    } else {
        contribution.map(|coefficient| {
            if coefficient.is_zero() {
                F256::ZERO
            } else {
                coefficient * scalar
            }
        })
    }
}

fn round_contribution(
    round: usize,
    point_coordinate: Option<F256>,
    eq: &[F256],
    columns: &[F256; STATE_SIZE],
    states: &[[F256; STATE_SIZE]],
) -> [F256; WALK_DEGREE + 1] {
    let relation_sum = if point_coordinate.is_some() {
        eq.par_chunks(2 * CONSTANT_PAIR_CHUNK)
            .enumerate()
            .map(|(chunk, equality)| {
                let start = 2 * chunk * CONSTANT_PAIR_CHUNK;
                let states = &states[start..start + equality.len()];
                if states[1..].iter().all(|state| state == &states[0]) {
                    let weight = equality.iter().copied().fold(F256::ZERO, |sum, x| sum + x);
                    return wide_relation_coefficients(
                        round,
                        columns,
                        &states[0],
                        &[F256::ZERO; STATE_SIZE],
                    )
                    .map(|coefficient| {
                        if coefficient.is_zero() {
                            F256::ZERO
                        } else {
                            weight * coefficient
                        }
                    });
                }
                let mut accumulator = [F256::ZERO; WALK_DEGREE];
                for pair in 0..equality.len() / 2 {
                    let weight = equality[2 * pair] + equality[2 * pair + 1];
                    let state_base = states[2 * pair];
                    let state_next = states[2 * pair + 1];
                    let state_delta =
                        std::array::from_fn(|lane| state_base[lane] + state_next[lane]);
                    let relation = weighted_wide_relation_coefficients(
                        round,
                        weight,
                        columns,
                        &state_base,
                        &state_delta,
                    );
                    for degree in 0..WALK_DEGREE {
                        accumulator[degree] += relation[degree];
                    }
                }
                accumulator
            })
            .reduce(
                || [F256::ZERO; WALK_DEGREE],
                |mut left, right| {
                    for (left, right) in left.iter_mut().zip(right) {
                        *left += right;
                    }
                    left
                },
            )
    } else {
        debug_assert_eq!(eq.len(), 1);
        debug_assert_eq!(states.len(), 1);
        let relation =
            wide_relation_coefficients(round, columns, &states[0], &[F256::ZERO; STATE_SIZE]);
        std::array::from_fn(|degree| eq[0] * relation[degree])
    };
    let zero_factor = point_coordinate.map_or(F256::ONE, |point| F256::ONE + point);
    convolve_equality_factor(relation_sum, zero_factor)
}

fn fold_scalars(table: &mut Vec<F256>, scratch: &mut Vec<F256>, challenge: F256) {
    let half = table.len() / 2;
    scratch.clear();
    scratch.resize(half, F256::ZERO);
    scratch
        .par_chunks_mut(2)
        .enumerate()
        .for_each(|(chunk, output)| {
            let first = 2 * chunk;
            let first_low = table[2 * first];
            let first_delta = first_low + table[2 * first + 1];
            if output.len() == 2 {
                let second = first + 1;
                let second_low = table[2 * second];
                let second_delta = second_low + table[2 * second + 1];
                let [first_product, second_product] =
                    mul_f256_pair(challenge, first_delta, challenge, second_delta);
                output[0] = first_low + first_product;
                output[1] = second_low + second_product;
            } else {
                output[0] = first_low + challenge * first_delta;
            }
        });
    std::mem::swap(table, scratch);
}

fn fold_states(
    table: &mut Vec<[F256; STATE_SIZE]>,
    scratch: &mut Vec<[F256; STATE_SIZE]>,
    challenge: F256,
) {
    let half = table.len() / 2;
    scratch.clear();
    scratch.par_extend((0..half).into_par_iter().map(|pair| {
        let low = table[2 * pair];
        let high = table[2 * pair + 1];
        let [product_0, product_1] =
            mul_f256_pair(challenge, low[0] + high[0], challenge, low[1] + high[1]);
        let [product_2, product_3] =
            mul_f256_pair(challenge, low[2] + high[2], challenge, low[3] + high[3]);
        [
            low[0] + product_0,
            low[1] + product_1,
            low[2] + product_2,
            low[3] + product_3,
        ]
    }));
    std::mem::swap(table, scratch);
}

fn fold_base_states(
    table: &[[F128; STATE_SIZE]],
    output: &mut Vec<[F256; STATE_SIZE]>,
    challenge: F256,
) {
    let half = table.len() / 2;
    output.clear();
    output.par_extend((0..half).into_par_iter().map(|pair| {
        let low = table[2 * pair];
        let high = table[2 * pair + 1];
        std::array::from_fn(|lane| {
            F256::from_base(low[lane]) + scale_base(challenge, low[lane] + high[lane])
        })
    }));
}

/// Prove one genuine C1 ragged walk with exactly one output group per child.
///
/// The single-group restriction is the production Link/Block shape. It keeps
/// the equality polynomial factored and avoids four dense E columns.
pub fn prove_ragged_deep_chain_walk<C: Challenger>(
    base_states: &[&[Vec<F128>; STATE_SIZE]],
    output_groups: &[C1LaneClaimGroup],
    channel: &mut C,
) -> (C1MultiDeepChainWalkProof, Vec<C1LaneClaimGroup>) {
    assert!(!base_states.is_empty(), "at least one C1 walk child");
    assert_eq!(base_states.len(), output_groups.len());
    let w_logs = base_states
        .iter()
        .map(|states| {
            let width = states[0].len();
            assert!(width.is_power_of_two());
            assert!(states.iter().all(|column| column.len() == width));
            width.trailing_zeros() as usize
        })
        .collect::<Vec<_>>();
    assert!(output_groups
        .iter()
        .zip(&w_logs)
        .all(|(group, &w_log)| group.point.len() == w_log));
    let max_w_log = *w_logs.iter().max().expect("one C1 walk child");

    let timing = std::env::var_os("NOIDH_C1_DEEP_CHAIN_TIMING").is_some();
    let total_started = std::time::Instant::now();
    let state_started = std::time::Instant::now();
    let mut layer_states = base_states
        .par_iter()
        .map(|&states| RaggedDescendingLayerStates::new(states))
        .collect::<Vec<_>>();
    let state_init = state_started.elapsed();

    absorb_groups(channel, &w_logs, output_groups);
    let mut groups = output_groups.to_vec();
    let mut layers = Vec::with_capacity(N_ROUNDS);
    let mut setup_elapsed = std::time::Duration::ZERO;
    let mut state_fetch_elapsed = std::time::Duration::ZERO;
    let mut sumcheck_elapsed = std::time::Duration::ZERO;
    let mut first_contribution_elapsed = std::time::Duration::ZERO;
    let mut wide_contribution_elapsed = std::time::Duration::ZERO;
    let mut fold_elapsed = std::time::Duration::ZERO;
    let mut finish_elapsed = std::time::Duration::ZERO;

    for layer in (1..=N_ROUNDS).rev() {
        let setup_started = std::time::Instant::now();
        let round = layer - 1;
        let alpha = channel.sample_f256();
        let weights = lane_weight_table(alpha, groups.len());
        let columns = weights
            .iter()
            .map(|weights| column_weights(round, weights))
            .collect::<Vec<_>>();
        let mut claim = groups
            .iter()
            .zip(&weights)
            .fold(F256::ZERO, |sum, (group, weights)| {
                sum + (0..STATE_SIZE).fold(F256::ZERO, |inner, lane| {
                    inner + weights[lane] * group.values[lane]
                })
            });
        // Keep the first equality coordinate factored out. The tail table is
        // half the former size, and after the first challenge its missing
        // factor is one scalar shared by every row and every later round.
        let mut equality = groups
            .iter()
            .map(|group| {
                if group.point.is_empty() {
                    vec![F256::ONE]
                } else {
                    build_eq_table(&group.point[1..])
                }
            })
            .collect::<Vec<_>>();
        let mut equality_prefix = vec![F256::ONE; groups.len()];
        setup_elapsed += setup_started.elapsed();

        let state_fetch_started = std::time::Instant::now();
        let base_layer_states = layer_states
            .par_iter_mut()
            .map(|server| server.state(round))
            .collect::<Vec<_>>();
        state_fetch_elapsed += state_fetch_started.elapsed();

        let mut states = (0..groups.len()).map(|_| Vec::new()).collect::<Vec<_>>();
        let mut equality_scratch = (0..groups.len()).map(|_| Vec::new()).collect::<Vec<_>>();
        let mut state_scratch = (0..groups.len()).map(|_| Vec::new()).collect::<Vec<_>>();
        let mut round_coeffs = Vec::with_capacity(max_w_log);
        let mut point = Vec::with_capacity(max_w_log);
        let sumcheck_started = std::time::Instant::now();
        for coordinate in 0..max_w_log {
            let contribution_started = std::time::Instant::now();
            let contributions = (0..groups.len())
                .into_par_iter()
                .map(|child| {
                    if coordinate == 0 {
                        if w_logs[child] > 0 {
                            first_base_round_contribution(
                                round,
                                groups[child].point[0],
                                &equality[child],
                                &columns[child],
                                &base_layer_states[child],
                            )
                        } else {
                            exhausted_base_round_contribution(
                                round,
                                equality[child][0],
                                &columns[child],
                                &base_layer_states[child][0],
                            )
                        }
                    } else {
                        scale_contribution(
                            round_contribution(
                                round,
                                (coordinate < w_logs[child])
                                    .then(|| groups[child].point[coordinate]),
                                &equality[child],
                                &columns[child],
                                &states[child],
                            ),
                            equality_prefix[child],
                        )
                    }
                })
                .collect::<Vec<_>>();
            if coordinate == 0 {
                first_contribution_elapsed += contribution_started.elapsed();
            } else {
                wide_contribution_elapsed += contribution_started.elapsed();
            }
            let mut full = [F256::ZERO; WALK_DEGREE + 1];
            for contribution in contributions {
                for (coefficient, contribution) in full.iter_mut().zip(contribution) {
                    *coefficient += contribution;
                }
            }
            debug_assert_eq!(full[0] + horner(&full, F256::ONE), claim);
            let wire = compress(&full);
            channel.observe_f256_slice(&wire);
            let challenge = channel.sample_f256();
            claim = horner(&full, challenge);
            point.push(challenge);
            round_coeffs.push(wire);
            let fold_started = std::time::Instant::now();
            if coordinate == 0 {
                equality
                    .par_iter_mut()
                    .zip(base_layer_states.par_iter())
                    .zip(states.par_iter_mut())
                    .zip(equality_prefix.par_iter_mut())
                    .zip(groups.par_iter())
                    .zip(w_logs.par_iter())
                    .for_each(
                        |(((((equality, base_states), states), prefix), group), &w_log)| {
                            if w_log > 0 {
                                fold_base_states(base_states, states, challenge);
                                *prefix = F256::ONE + group.point[0] + challenge;
                            } else {
                                equality[0] *= F256::ONE + challenge;
                                states.push(base_states[0].map(F256::from_base));
                            }
                        },
                    );
            } else {
                equality
                    .par_iter_mut()
                    .zip(states.par_iter_mut())
                    .zip(equality_scratch.par_iter_mut())
                    .zip(state_scratch.par_iter_mut())
                    .zip(w_logs.par_iter())
                    .for_each(
                        |((((equality, states), equality_scratch), state_scratch), &w_log)| {
                            if coordinate < w_log {
                                rayon::join(
                                    || fold_scalars(equality, equality_scratch, challenge),
                                    || fold_states(states, state_scratch, challenge),
                                );
                            } else {
                                equality[0] *= F256::ONE + challenge;
                            }
                        },
                    );
            }
            fold_elapsed += fold_started.elapsed();
        }
        sumcheck_elapsed += sumcheck_started.elapsed();

        let finish_started = std::time::Instant::now();
        let next_values = states.iter().map(|states| states[0]).collect::<Vec<_>>();
        channel.observe_f256_slice(
            &next_values
                .iter()
                .flat_map(|values| values.iter().copied())
                .collect::<Vec<_>>(),
        );
        let mut expected = F256::ZERO;
        for child in 0..groups.len() {
            let terms = layer_terms(round, &next_values[child]);
            let mut high_gate = F256::ONE;
            for &coordinate in &point[w_logs[child]..] {
                high_gate *= F256::ONE + coordinate;
            }
            let aligned_eq = eq_eval(&groups[child].point, &point[..w_logs[child]]) * high_gate;
            let dot = (0..STATE_SIZE).fold(F256::ZERO, |sum, lane| {
                sum + columns[child][lane] * terms[lane]
            });
            expected += aligned_eq * dot;
        }
        debug_assert_eq!(expected, claim, "C1 walk layer {layer}");
        layers.push(C1MultiWalkLayerProof {
            round_coeffs,
            next_values: next_values.clone(),
        });
        groups = next_values
            .into_iter()
            .enumerate()
            .map(|(child, values)| C1LaneClaimGroup {
                point: point[..w_logs[child]].to_vec(),
                values,
            })
            .collect();
        finish_elapsed += finish_started.elapsed();
    }

    if timing {
        eprintln!(
            "NOIDH C1 deep-chain-ragged widths={w_logs:?} state_init_ms={} setup_ms={} state_fetch_ms={} sumcheck_ms={} first_contribution_ms={} wide_contribution_ms={} fold_ms={} finish_ms={} total_ms={}",
            state_init.as_millis(),
            setup_elapsed.as_millis(),
            state_fetch_elapsed.as_millis(),
            sumcheck_elapsed.as_millis(),
            first_contribution_elapsed.as_millis(),
            wide_contribution_elapsed.as_millis(),
            fold_elapsed.as_millis(),
            finish_elapsed.as_millis(),
            total_started.elapsed().as_millis(),
        );
    }
    (C1MultiDeepChainWalkProof { layers }, groups)
}

/// Verify the genuine C1 single-group ragged walk.
pub fn verify_ragged_deep_chain_walk<C: Challenger>(
    w_logs: &[usize],
    output_groups: &[C1LaneClaimGroup],
    proof: &C1MultiDeepChainWalkProof,
    channel: &mut C,
) -> Result<Vec<C1LaneClaimGroup>, WalkError> {
    if w_logs.is_empty()
        || w_logs.len() != output_groups.len()
        || output_groups
            .iter()
            .zip(w_logs)
            .any(|(group, &w_log)| group.point.len() != w_log)
    {
        return Err(WalkError::Shape);
    }
    let max_w_log = *w_logs.iter().max().ok_or(WalkError::Shape)?;
    if proof.layers.len() != N_ROUNDS
        || proof.layers.iter().any(|layer| {
            layer.round_coeffs.len() != max_w_log || layer.next_values.len() != output_groups.len()
        })
    {
        return Err(WalkError::Shape);
    }

    absorb_groups(channel, w_logs, output_groups);
    let mut groups = output_groups.to_vec();
    for (layer_index, layer_proof) in proof.layers.iter().enumerate() {
        let layer = N_ROUNDS - layer_index;
        let round = layer - 1;
        let alpha = channel.sample_f256();
        let weights = lane_weight_table(alpha, groups.len());
        let columns = weights
            .iter()
            .map(|weights| column_weights(round, weights))
            .collect::<Vec<_>>();
        let mut claim = groups
            .iter()
            .zip(&weights)
            .fold(F256::ZERO, |sum, (group, weights)| {
                sum + (0..STATE_SIZE).fold(F256::ZERO, |inner, lane| {
                    inner + weights[lane] * group.values[lane]
                })
            });
        let mut point = Vec::with_capacity(max_w_log);
        for wire in &layer_proof.round_coeffs {
            channel.observe_f256_slice(wire);
            let full = reconstruct(wire, claim);
            let challenge = channel.sample_f256();
            claim = horner(&full, challenge);
            point.push(challenge);
        }
        channel.observe_f256_slice(
            &layer_proof
                .next_values
                .iter()
                .flat_map(|values| values.iter().copied())
                .collect::<Vec<_>>(),
        );

        let mut expected = F256::ZERO;
        for child in 0..groups.len() {
            let terms = layer_terms(round, &layer_proof.next_values[child]);
            let mut high_gate = F256::ONE;
            for &coordinate in &point[w_logs[child]..] {
                high_gate *= F256::ONE + coordinate;
            }
            let aligned_eq = eq_eval(&groups[child].point, &point[..w_logs[child]]) * high_gate;
            let dot = (0..STATE_SIZE).fold(F256::ZERO, |sum, lane| {
                sum + columns[child][lane] * terms[lane]
            });
            expected += aligned_eq * dot;
        }
        if expected != claim {
            return Err(WalkError::LayerMismatch(layer));
        }
        groups = layer_proof
            .next_values
            .iter()
            .enumerate()
            .map(|(child, &values)| C1LaneClaimGroup {
                point: point[..w_logs[child]].to_vec(),
                values,
            })
            .collect();
    }
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::FsLaneChallenger;
    use crate::deep_chain::apply_round;

    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut value = self.0;
            value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            value ^ (value >> 31)
        }

        fn f128(&mut self) -> F128 {
            F128::new(self.next_u64(), self.next_u64())
        }

        fn f256(&mut self) -> F256 {
            F256::new(self.f128(), self.f128())
        }
    }

    fn random_columns(w_log: usize, seed: u64) -> [Vec<F128>; STATE_SIZE] {
        let mut rng = Rng(seed);
        std::array::from_fn(|_| (0..1usize << w_log).map(|_| rng.f128()).collect())
    }

    fn output_columns(input: &[Vec<F128>; STATE_SIZE]) -> [Vec<F128>; STATE_SIZE] {
        let width = input[0].len();
        let rows = (0..width)
            .into_par_iter()
            .map(|index| {
                let mut state = std::array::from_fn(|lane| input[lane][index]);
                for round in 0..N_ROUNDS {
                    state = apply_round(round, state);
                }
                state
            })
            .collect::<Vec<_>>();
        std::array::from_fn(|lane| rows.iter().map(|row| row[lane]).collect())
    }

    fn evaluate_base_column(column: &[F128], point: &[F256]) -> F256 {
        build_eq_table(point)
            .into_iter()
            .zip(column)
            .fold(F256::ZERO, |sum, (weight, &value)| {
                sum + weight.scale_base(value)
            })
    }

    fn honest_fixture(w_logs: &[usize]) -> (Vec<[Vec<F128>; STATE_SIZE]>, Vec<C1LaneClaimGroup>) {
        let inputs = w_logs
            .iter()
            .enumerate()
            .map(|(child, &w_log)| random_columns(w_log, 0xC100_0000 + child as u64))
            .collect::<Vec<_>>();
        let mut rng = Rng(0xC1_F1_57);
        let groups = inputs
            .iter()
            .zip(w_logs)
            .map(|(input, &w_log)| {
                let output = output_columns(input);
                let point = (0..w_log).map(|_| rng.f256()).collect::<Vec<_>>();
                let values =
                    std::array::from_fn(|lane| evaluate_base_column(&output[lane], &point));
                C1LaneClaimGroup { point, values }
            })
            .collect();
        (inputs, groups)
    }

    #[test]
    fn genuine_c1_ragged_walk_roundtrip_and_mutations() {
        let w_logs = [2usize, 4, 3];
        let (inputs, groups) = honest_fixture(&w_logs);
        let references = inputs.iter().collect::<Vec<_>>();
        let mut prover = FsLaneChallenger::new_c1(b"genuine-c1-ragged-walk-test");
        let (proof, prover_terminals) =
            prove_ragged_deep_chain_walk(&references, &groups, &mut prover);
        let mut verifier = FsLaneChallenger::new_c1(b"genuine-c1-ragged-walk-test");
        let verifier_terminals =
            verify_ragged_deep_chain_walk(&w_logs, &groups, &proof, &mut verifier).unwrap();
        assert_eq!(prover_terminals, verifier_terminals);
        for (terminal, input) in verifier_terminals.iter().zip(&inputs) {
            for lane in 0..STATE_SIZE {
                assert_eq!(
                    evaluate_base_column(&input[lane], &terminal.point),
                    terminal.values[lane]
                );
            }
        }

        let mut bad = proof.clone();
        bad.layers[N_ROUNDS / 2].round_coeffs[1][3] += F256::ONE;
        let mut verifier = FsLaneChallenger::new_c1(b"genuine-c1-ragged-walk-test");
        assert!(verify_ragged_deep_chain_walk(&w_logs, &groups, &bad, &mut verifier).is_err());
    }

    /// Isolated production-width benchmark. Claims are intentionally arbitrary:
    /// this measures the prover kernel, while the small test above verifies
    /// the complete authenticated relation.
    #[test]
    #[ignore = "production-width C1 performance benchmark"]
    fn genuine_c1_joint_b25_sidecar_micro_profile() {
        let w_logs = [14usize, 15, 17, 16, 12, 15, 16, 12, 13];
        let inputs = w_logs
            .iter()
            .enumerate()
            .map(|(child, &w_log)| random_columns(w_log, 0xC1_2500 + child as u64))
            .collect::<Vec<_>>();
        let references = inputs.iter().collect::<Vec<_>>();
        let mut rng = Rng(0xC1_25FF);
        let groups = w_logs
            .iter()
            .map(|&w_log| C1LaneClaimGroup {
                point: (0..w_log).map(|_| rng.f256()).collect(),
                values: std::array::from_fn(|_| rng.f256()),
            })
            .collect::<Vec<_>>();
        let started = std::time::Instant::now();
        let mut channel = FsLaneChallenger::new_c1(b"genuine-c1-joint-b25-sidecar-micro");
        let (proof, terminals) = prove_ragged_deep_chain_walk(&references, &groups, &mut channel);
        eprintln!(
            "NOIDH genuine-C1 joint-B25-sidecar elapsed_ms={} layers={} terminals={}",
            started.elapsed().as_millis(),
            proof.layers.len(),
            terminals.len(),
        );
        assert_eq!(proof.layers.len(), N_ROUNDS);
        assert_eq!(terminals.len(), w_logs.len());
    }
}
