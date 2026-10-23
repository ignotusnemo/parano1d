// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete-set limit classification and bounded integer pro-rata execution.

use super::{clearing::ClearingRate, queue::RegisteredBatch, MarketDefinition, MarketError};
use core::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClearingStep {
    pub price: ClearingRate,
    pub active_mask: u16,
    pub dust_mask: u16,
    /// 0 is base, 1 is quote, and 2 denotes no marginal side.
    pub partial_side: u8,
    pub fraction_numerator: u128,
    pub fraction_denominator: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitSolution {
    pub price: ClearingRate,
    pub effective: Vec<u64>,
    pub steps: Vec<ClearingStep>,
}

#[derive(Clone, Copy)]
struct Order {
    side: usize,
    capacity: u64,
    limit: ClearingRate,
}

pub fn solve(
    definition: MarketDefinition,
    batch: &RegisteredBatch,
) -> Result<LimitSolution, MarketError> {
    batch.before().check_definition(definition)?;
    let orders: Vec<_> = batch
        .requests()
        .iter()
        .map(|r| {
            let capacity = r.request.effective_input()?;
            let side = usize::from(r.request.input_asset != definition.base);
            let limit = if side == 0 {
                ClearingRate {
                    numerator: r.request.minimum_output,
                    denominator: capacity,
                }
            } else {
                ClearingRate {
                    numerator: capacity,
                    denominator: r.request.minimum_output,
                }
            };
            Ok(Order {
                side,
                capacity,
                limit,
            })
        })
        .collect::<Result<_, MarketError>>()?;
    let mut active_mask = ((1u32 << orders.len()) - 1) as u16;
    let mut steps = Vec::with_capacity(orders.len() + 1);
    for _ in 0..=orders.len() {
        let mut step = continuous_step(batch, &orders, active_mask)?;
        let marginal_total = orders
            .iter()
            .enumerate()
            .filter(|(index, order)| {
                active_mask & (1 << index) != 0
                    && order.side as u8 == step.partial_side
                    && classify(**order, step.price) == 2
            })
            .try_fold(0u64, |sum, (_, order)| add(sum, order.capacity))?;
        let partial_total = floor_ratio(
            step.fraction_numerator,
            marginal_total,
            step.fraction_denominator,
        )?;
        let mut prefix = 0u64;
        let mut allocated = 0u64;
        let mut effective = vec![0; orders.len()];
        for (index, order) in orders.iter().enumerate() {
            if active_mask & (1 << index) == 0 {
                continue;
            }
            let classification = classify(*order, step.price);
            let positive_target = match classification {
                0 => false,
                1 => {
                    effective[index] = order.capacity;
                    true
                }
                _ if order.side as u8 != step.partial_side => {
                    effective[index] = order.capacity;
                    true
                }
                _ => {
                    prefix = add(prefix, order.capacity)?;
                    let cumulative = u64::try_from(
                        u128::from(partial_total) * u128::from(prefix) / u128::from(marginal_total),
                    )
                    .map_err(|_| MarketError::Arithmetic)?;
                    effective[index] = cumulative
                        .checked_sub(allocated)
                        .ok_or(MarketError::Arithmetic)?;
                    allocated = cumulative;
                    step.fraction_numerator != 0
                }
            };
            let output = payout(effective[index], order.side, step.price)?;
            if positive_target && (effective[index] == 0 || output == 0) {
                step.dust_mask |= 1 << index;
            }
        }
        if prefix != marginal_total || allocated != partial_total {
            return Err(MarketError::Conservation);
        }
        steps.push(step);
        if step.dust_mask == 0 {
            return Ok(LimitSolution {
                price: step.price,
                effective,
                steps,
            });
        }
        active_mask &= !step.dust_mask;
    }
    Err(MarketError::Clearing)
}

fn continuous_step(
    batch: &RegisteredBatch,
    orders: &[Order],
    active_mask: u16,
) -> Result<ClearingStep, MarketError> {
    let mut boundaries: Vec<_> = orders
        .iter()
        .enumerate()
        .filter(|(i, _)| active_mask & (1 << i) != 0)
        .map(|(_, o)| o.limit)
        .collect();
    boundaries.sort_by(|a, b| compare(*a, *b));
    boundaries.dedup_by(|a, b| compare(*a, *b) == Ordering::Equal);
    let before = batch.before();
    let mut candidate = None;
    for interval in 0..=boundaries.len() {
        let low = interval.checked_sub(1).map(|i| boundaries[i]);
        let high = boundaries.get(interval).copied();
        let mut full = [0u64; 2];
        for (index, order) in orders.iter().enumerate() {
            if active_mask & (1 << index) == 0 {
                continue;
            }
            let included = if order.side == 0 {
                low.is_some_and(|p| compare(order.limit, p) != Ordering::Greater)
            } else {
                high.is_some_and(|p| compare(order.limit, p) != Ordering::Less)
            };
            if included {
                full[order.side] = add(full[order.side], order.capacity)?;
            }
        }
        let price = ClearingRate {
            numerator: twice_plus(before.quote_reserve, full[1])?,
            denominator: twice_plus(before.base_reserve, full[0])?,
        };
        if low.is_none_or(|p| compare(price, p) == Ordering::Greater)
            && high.is_none_or(|p| compare(price, p) == Ordering::Less)
        {
            install(
                &mut candidate,
                ClearingStep {
                    price,
                    active_mask,
                    dust_mask: 0,
                    partial_side: 2,
                    fraction_numerator: 0,
                    fraction_denominator: 1,
                },
            )?;
        }
    }
    for price in boundaries {
        let mut full = [0u64; 2];
        let mut marginal = [0u64; 2];
        for (index, order) in orders.iter().enumerate() {
            if active_mask & (1 << index) == 0 {
                continue;
            }
            match classify(*order, price) {
                1 => full[order.side] = add(full[order.side], order.capacity)?,
                2 => marginal[order.side] = add(marginal[order.side], order.capacity)?,
                _ => (),
            }
        }
        let n = u128::from(price.numerator);
        let d = u128::from(price.denominator);
        let left = n * u128::from(twice_plus(before.base_reserve, full[0])?);
        let right = d * u128::from(twice_plus(before.quote_reserve, full[1])?);
        let left_max = n * u128::from(twice_plus(before.base_reserve, add(full[0], marginal[0])?)?);
        let right_max = d * u128::from(twice_plus(
            before.quote_reserve,
            add(full[1], marginal[1])?,
        )?);
        if right_max < left || right > left_max {
            continue;
        }
        let (partial_side, numerator, denominator) = if right_max <= left_max {
            (0, right_max - left, 2 * n * u128::from(marginal[0]))
        } else {
            (1, left_max - right, 2 * d * u128::from(marginal[1]))
        };
        let (partial_side, numerator, denominator) = if denominator == 0 {
            if numerator != 0 {
                return Err(MarketError::Clearing);
            }
            (2, 0, 1)
        } else {
            (partial_side, numerator, denominator)
        };
        if numerator > denominator {
            return Err(MarketError::Clearing);
        }
        install(
            &mut candidate,
            ClearingStep {
                price,
                active_mask,
                dust_mask: 0,
                partial_side,
                fraction_numerator: numerator,
                fraction_denominator: denominator,
            },
        )?;
    }
    candidate.ok_or(MarketError::Clearing)
}

fn install(candidate: &mut Option<ClearingStep>, step: ClearingStep) -> Result<(), MarketError> {
    if candidate.replace(step).is_some() {
        return Err(MarketError::Clearing);
    }
    Ok(())
}

fn classify(order: Order, price: ClearingRate) -> u8 {
    match compare(price, order.limit) {
        Ordering::Equal => 2,
        Ordering::Greater if order.side == 0 => 1,
        Ordering::Less if order.side == 1 => 1,
        _ => 0,
    }
}

fn compare(a: ClearingRate, b: ClearingRate) -> Ordering {
    (u128::from(a.numerator) * u128::from(b.denominator))
        .cmp(&(u128::from(b.numerator) * u128::from(a.denominator)))
}

fn twice_plus(reserve: u64, input: u64) -> Result<u64, MarketError> {
    input
        .checked_mul(2)
        .and_then(|n| n.checked_add(reserve))
        .ok_or(MarketError::Arithmetic)
}
fn add(a: u64, b: u64) -> Result<u64, MarketError> {
    a.checked_add(b).ok_or(MarketError::Arithmetic)
}

pub(crate) fn payout(effective: u64, side: usize, price: ClearingRate) -> Result<u64, MarketError> {
    let (n, d) = if side == 0 {
        (price.numerator, price.denominator)
    } else {
        (price.denominator, price.numerator)
    };
    if d == 0 {
        return Err(MarketError::Arithmetic);
    }
    u64::try_from(u128::from(effective) * u128::from(n) / u128::from(d))
        .map_err(|_| MarketError::Arithmetic)
}

/// Exact floor(a*b/d) for 0 <= a <= d and a 64-bit b. Three limbs
/// retain the full product while the quotient search remains bounded.
pub(crate) fn floor_ratio(a: u128, b: u64, d: u128) -> Result<u64, MarketError> {
    if d == 0 || a > d {
        return Err(MarketError::Arithmetic);
    }
    let target = wide_product(a, b);
    let mut low = 0u64;
    let mut high = b;
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if wide_product(d, middle) <= target {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    Ok(low)
}

/// Most significant limb first, allowing an ordinary lexicographic comparison.
fn wide_product(a: u128, b: u64) -> [u64; 3] {
    let lo = u128::from(a as u64) * u128::from(b);
    let hi = (a >> 64) * u128::from(b) + (lo >> 64);
    [(hi >> 64) as u64, hi as u64, lo as u64]
}
