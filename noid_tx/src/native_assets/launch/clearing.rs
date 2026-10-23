// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Uniform complete-set curve execution, bounded allocation and graduation.

use super::{queue::LaunchRegisteredBatch, *};
use core::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchStep {
    pub price: LaunchPrice,
    pub active_mask: u16,
    pub dust_mask: u16,
    /// Buy is zero, sell is one, and two denotes no partial group.
    pub partial_side: u8,
    pub fraction_numerator: u128,
    pub fraction_denominator: u128,
    pub at_cap: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSolution {
    pub price: LaunchPrice,
    pub quantities: Vec<u64>,
    pub steps: Vec<LaunchStep>,
}

#[derive(Clone, Copy)]
struct Order {
    side: LaunchSide,
    quantity: u64,
    limit: LaunchPrice,
}

pub fn solve(
    definition: LaunchDefinition,
    batch: &LaunchRegisteredBatch,
) -> Result<LaunchSolution, LaunchError> {
    batch.before().check_definition(definition)?;
    let orders: Vec<_> = batch
        .requests()
        .iter()
        .map(|r| Order {
            side: r.request.side,
            quantity: r.request.quantity,
            limit: LaunchPrice {
                numerator: r.request.noid_limit,
                denominator: r.request.quantity,
            },
        })
        .collect();
    let mut active_mask = ((1u32 << orders.len()) - 1) as u16;
    let mut steps = Vec::with_capacity(orders.len() + 1);
    for _ in 0..=orders.len() {
        let mut step = continuous_step(definition, batch, &orders, active_mask)?;
        let mut marginal_total = 0u64;
        for (i, order) in orders.iter().enumerate() {
            if active_mask & (1 << i) != 0 && is_partial(*order, step) {
                marginal_total = add(marginal_total, order.quantity)?;
            }
        }
        let partial_total = if step.partial_side < 2 {
            super::super::market::limits::floor_ratio(
                step.fraction_numerator,
                marginal_total,
                step.fraction_denominator,
            )
            .map_err(|_| LaunchError::Arithmetic)?
        } else {
            0
        };
        let mut prefix = 0u64;
        let mut allocated = 0u64;
        let mut quantities = vec![0; orders.len()];
        for (i, order) in orders.iter().enumerate() {
            if active_mask & (1 << i) == 0 || classify(*order, step.price) == 0 {
                continue;
            }
            let positive_target;
            let quantity;
            if is_partial(*order, step) {
                prefix = add(prefix, order.quantity)?;
                let cumulative = u64::try_from(
                    u128::from(partial_total) * u128::from(prefix) / u128::from(marginal_total),
                )
                .map_err(|_| LaunchError::Arithmetic)?;
                quantity = cumulative
                    .checked_sub(allocated)
                    .ok_or(LaunchError::Arithmetic)?;
                allocated = cumulative;
                positive_target = step.fraction_numerator != 0;
            } else {
                quantity = order.quantity;
                positive_target = true;
            }
            if quantity > order.quantity {
                return Err(LaunchError::Conservation);
            }
            if positive_target
                && (quantity == 0
                    || (order.side == LaunchSide::Sell && step.price.proceeds(quantity)? == 0))
            {
                step.dust_mask |= 1 << i;
            }
            quantities[i] = quantity;
        }
        if allocated != partial_total || prefix != marginal_total {
            return Err(LaunchError::Conservation);
        }
        steps.push(step);
        if step.dust_mask == 0 {
            let sold = sold_after(definition, batch, &quantities)?;
            if sold > definition.sale_units() {
                return Err(LaunchError::Clearing);
            }
            return Ok(LaunchSolution {
                price: step.price,
                quantities,
                steps,
            });
        }
        active_mask &= !step.dust_mask;
    }
    Err(LaunchError::Clearing)
}

fn continuous_step(
    definition: LaunchDefinition,
    batch: &LaunchRegisteredBatch,
    orders: &[Order],
    active_mask: u16,
) -> Result<LaunchStep, LaunchError> {
    let sold = definition.initial_supply - batch.before().inventory_units;
    let remaining = definition.sale_units() - sold;
    let cap_price = definition.average_price(sold, definition.sale_units())?;
    let mut cap_buys = 0u64;
    let mut cap_sells = 0u64;
    for (i, order) in orders.iter().enumerate() {
        if active_mask & (1 << i) != 0 && classify(*order, cap_price) != 0 {
            if order.side == LaunchSide::Buy {
                cap_buys = add(cap_buys, order.quantity)?;
            } else {
                cap_sells = add(cap_sells, order.quantity)?;
            }
        }
    }
    let needed = add(cap_sells, remaining)?;
    if cap_buys >= needed && cap_buys != 0 {
        return Ok(LaunchStep {
            price: cap_price,
            active_mask,
            dust_mask: 0,
            partial_side: LaunchSide::Buy as u8,
            fraction_numerator: u128::from(needed),
            fraction_denominator: u128::from(cap_buys),
            at_cap: true,
        });
    }
    let mut boundaries: Vec<_> = orders
        .iter()
        .enumerate()
        .filter(|(i, _)| active_mask & (1 << i) != 0)
        .map(|(_, o)| o.limit)
        .collect();
    boundaries.sort_by(|a, b| compare(*a, *b));
    boundaries.dedup_by(|a, b| compare(*a, *b) == Ordering::Equal);
    let center = i128::from(3 * definition.initial_supply + 10 * sold);
    let denominator = 900 * definition.initial_supply;
    let mut candidate = None;
    for interval in 0..=boundaries.len() {
        let low = interval.checked_sub(1).map(|i| boundaries[i]);
        let high = boundaries.get(interval).copied();
        let mut full = [0u64; 2];
        for (i, order) in orders.iter().enumerate() {
            if active_mask & (1 << i) == 0 {
                continue;
            }
            let included = if order.side == LaunchSide::Buy {
                high.is_some_and(|p| compare(order.limit, p) != Ordering::Less)
            } else {
                low.is_some_and(|p| compare(order.limit, p) != Ordering::Greater)
            };
            if included {
                full[order.side as usize] = add(full[order.side as usize], order.quantity)?;
            }
        }
        let delta = i128::from(full[0]) - i128::from(full[1]);
        if delta < -i128::from(sold) || delta >= i128::from(remaining) {
            continue;
        }
        let numerator = u64::try_from(center + 5 * delta).map_err(|_| LaunchError::Arithmetic)?;
        let price = LaunchPrice {
            numerator,
            denominator,
        };
        if low.is_none_or(|p| compare(price, p) == Ordering::Greater)
            && high.is_none_or(|p| compare(price, p) == Ordering::Less)
        {
            install(
                &mut candidate,
                LaunchStep {
                    price,
                    active_mask,
                    dust_mask: 0,
                    partial_side: 2,
                    fraction_numerator: 0,
                    fraction_denominator: 1,
                    at_cap: false,
                },
            )?;
        }
    }
    for price in boundaries {
        if price.numerator == 0 {
            continue;
        }
        let n = i128::from(price.numerator);
        let d = i128::from(price.denominator);
        let target_numerator = i128::from(denominator) * n - center * d;
        let target_denominator = 5 * d;
        if target_numerator < -i128::from(sold) * target_denominator
            || target_numerator >= i128::from(remaining) * target_denominator
        {
            continue;
        }
        let mut full = [0u64; 2];
        let mut marginal = [0u64; 2];
        for (i, order) in orders.iter().enumerate() {
            if active_mask & (1 << i) == 0 {
                continue;
            }
            let side = order.side as usize;
            match classify(*order, price) {
                1 => full[side] = add(full[side], order.quantity)?,
                2 => marginal[side] = add(marginal[side], order.quantity)?,
                _ => (),
            }
        }
        let target =
            target_numerator - (i128::from(full[0]) - i128::from(full[1])) * target_denominator;
        let max_buy = i128::from(marginal[0]) * target_denominator;
        let max_sell = i128::from(marginal[1]) * target_denominator;
        if target < -max_sell || target > max_buy {
            continue;
        }
        let (partial_side, numerator, denominator) = if max_buy <= max_sell + target {
            (1, max_buy - target, max_sell)
        } else {
            (0, max_sell + target, max_buy)
        };
        let (partial_side, numerator, denominator) = if denominator == 0 {
            if numerator != 0 {
                return Err(LaunchError::Clearing);
            }
            (2, 0, 1)
        } else {
            (partial_side, numerator, denominator)
        };
        if numerator < 0 || numerator > denominator {
            return Err(LaunchError::Clearing);
        }
        install(
            &mut candidate,
            LaunchStep {
                price,
                active_mask,
                dust_mask: 0,
                partial_side,
                fraction_numerator: numerator as u128,
                fraction_denominator: denominator as u128,
                at_cap: false,
            },
        )?;
    }
    candidate.ok_or(LaunchError::Clearing)
}

fn is_partial(order: Order, step: LaunchStep) -> bool {
    let classification = classify(order, step.price);
    order.side as u8 == step.partial_side
        && if step.at_cap {
            classification != 0
        } else {
            classification == 2
        }
}
fn classify(order: Order, price: LaunchPrice) -> u8 {
    match compare(price, order.limit) {
        Ordering::Equal => 2,
        Ordering::Less if order.side == LaunchSide::Buy => 1,
        Ordering::Greater if order.side == LaunchSide::Sell => 1,
        _ => 0,
    }
}
pub fn compare(a: LaunchPrice, b: LaunchPrice) -> Ordering {
    (u128::from(a.numerator) * u128::from(b.denominator))
        .cmp(&(u128::from(b.numerator) * u128::from(a.denominator)))
}
fn add(a: u64, b: u64) -> Result<u64, LaunchError> {
    a.checked_add(b).ok_or(LaunchError::Arithmetic)
}
fn install(candidate: &mut Option<LaunchStep>, step: LaunchStep) -> Result<(), LaunchError> {
    if candidate.replace(step).is_some() {
        Err(LaunchError::Clearing)
    } else {
        Ok(())
    }
}
fn sold_after(
    definition: LaunchDefinition,
    batch: &LaunchRegisteredBatch,
    quantities: &[u64],
) -> Result<u64, LaunchError> {
    let mut sold = i128::from(definition.initial_supply - batch.before().inventory_units);
    for (r, &amount) in batch.requests().iter().zip(quantities) {
        if r.request.side == LaunchSide::Buy {
            sold += i128::from(amount)
        } else {
            sold -= i128::from(amount)
        }
    }
    u64::try_from(sold).map_err(|_| LaunchError::Conservation)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchOutcome {
    Continue(LaunchState),
    Graduate(PoolState),
}
impl LaunchOutcome {
    pub fn root(self) -> Address {
        match self {
            Self::Continue(s) => s.root(),
            Self::Graduate(p) => p.root(),
        }
    }
    pub fn noid_value(self) -> u64 {
        match self {
            Self::Continue(s) => s.market_noid,
            Self::Graduate(p) => p.noid_value(),
        }
    }
    pub fn inventory_units(self) -> u64 {
        match self {
            Self::Continue(s) => s.inventory_units,
            Self::Graduate(p) => p.quote_reserve,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchExecution {
    pub filled_quantity: u64,
    pub noid_cost: u64,
    pub noid_proceeds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSettlement {
    outcome: LaunchOutcome,
    solution: LaunchSolution,
    execution: Vec<LaunchExecution>,
    claims: Vec<SwapClaim>,
    protocol_fee: u64,
    rounding_fee: u64,
    rounding_credit: u64,
}
impl LaunchSettlement {
    pub fn calculate(
        definition: LaunchDefinition,
        batch: &LaunchRegisteredBatch,
        height: u64,
        protocol_fee: u64,
    ) -> Result<Self, LaunchError> {
        batch.settlement_allowed(height)?;
        let count = batch.requests().len() as u64;
        if protocol_fee > count * super::super::market::clearing::MAX_SETTLEMENT_FEE_PER_REQUEST {
            return Err(LaunchError::Fee);
        }
        let solution = solve(definition, batch)?;
        let sold = sold_after(definition, batch, &solution.quantities)?;
        let cash = definition.curve_cash(sold)?;
        let mut raw_cash = i128::from(batch.before().market_noid);
        let mut execution = Vec::with_capacity(count as usize);
        for (r, &filled) in batch.requests().iter().zip(&solution.quantities) {
            let mut e = LaunchExecution {
                filled_quantity: filled,
                noid_cost: 0,
                noid_proceeds: 0,
            };
            let minimum = u64::try_from(
                u128::from(r.request.noid_limit) * u128::from(filled)
                    / u128::from(r.request.quantity),
            )
            .map_err(|_| LaunchError::Arithmetic)?;
            if r.request.side == LaunchSide::Buy {
                e.noid_cost = solution.price.cost(filled)?;
                let maximum = u64::try_from(
                    (u128::from(r.request.noid_limit) * u128::from(filled))
                        .div_ceil(u128::from(r.request.quantity)),
                )
                .map_err(|_| LaunchError::Arithmetic)?;
                if e.noid_cost > maximum || e.noid_cost > r.request.noid_limit {
                    return Err(LaunchError::Conservation);
                }
                raw_cash += i128::from(e.noid_cost);
            } else {
                e.noid_proceeds = solution.price.proceeds(filled)?;
                if e.noid_proceeds < minimum || (filled != 0 && e.noid_proceeds == 0) {
                    return Err(LaunchError::Conservation);
                }
                raw_cash -= i128::from(e.noid_proceeds);
            }
            execution.push(e);
        }
        let rounding = raw_cash - i128::from(cash);
        if rounding < -1 || rounding > i128::from(count + 1) {
            return Err(LaunchError::Conservation);
        }
        let rounding_fee = rounding.max(0) as u64;
        let rounding_credit = (-rounding).max(0) as u64;
        let outcome = if sold == definition.sale_units() {
            LaunchOutcome::Graduate(definition.graduation_pool()?)
        } else {
            let state = LaunchState {
                inventory_units: definition.initial_supply - sold,
                market_noid: cash,
                generation: batch
                    .before()
                    .generation
                    .checked_add(1)
                    .ok_or(LaunchError::Arithmetic)?,
                ..batch.before().idle_view()
            };
            state.check_definition(definition)?;
            LaunchOutcome::Continue(state)
        };
        let mut incoming_noid = u128::from(batch.before().market_noid);
        let mut outgoing_noid =
            u128::from(outcome.noid_value()) + u128::from(protocol_fee + rounding_fee);
        let mut incoming_units = u128::from(batch.before().inventory_units);
        let mut outgoing_units = u128::from(outcome.inventory_units());
        let mut claims = Vec::with_capacity(count as usize);
        for (i, (r, e)) in batch.requests().iter().zip(&execution).enumerate() {
            let charged = protocol_fee / count
                + u64::from((i as u64) < protocol_fee % count)
                + if i == 0 { rounding_credit } else { 0 };
            let credit = MARKET_REQUEST_FEE_CREDIT
                .checked_sub(charged)
                .ok_or(LaunchError::Fee)?;
            let buy = r.request.side == LaunchSide::Buy;
            let c = SwapClaim {
                request: r.key(),
                input_asset: if buy { NOID_ASSET } else { definition.asset },
                output_asset: if buy { definition.asset } else { NOID_ASSET },
                refund_owner: r.request.owner,
                recipient: r.request.recipient,
                refund_units: if buy {
                    r.request.noid_limit - e.noid_cost
                } else {
                    r.request.quantity - e.filled_quantity
                },
                output_units: if buy {
                    e.filled_quantity
                } else {
                    e.noid_proceeds
                },
                fee_credit: credit,
            };
            c.validate().map_err(|_| LaunchError::Conservation)?;
            incoming_noid += u128::from(r.request.noid_value()?);
            outgoing_noid += u128::from(c.noid_value().map_err(|_| LaunchError::Conservation)?);
            if buy {
                outgoing_units += u128::from(c.output_units)
            } else {
                incoming_units += u128::from(r.request.quantity);
                outgoing_units += u128::from(c.refund_units)
            }
            claims.push(c);
        }
        if incoming_noid != outgoing_noid || incoming_units != outgoing_units {
            return Err(LaunchError::Conservation);
        }
        Ok(Self {
            outcome,
            solution,
            execution,
            claims,
            protocol_fee,
            rounding_fee,
            rounding_credit,
        })
    }
    pub fn outcome(&self) -> LaunchOutcome {
        self.outcome
    }
    pub fn solution(&self) -> &LaunchSolution {
        &self.solution
    }
    pub fn execution(&self) -> &[LaunchExecution] {
        &self.execution
    }
    pub fn claims(&self) -> &[SwapClaim] {
        &self.claims
    }
    pub fn fee(&self) -> u64 {
        self.protocol_fee + self.rounding_fee
    }
    pub fn protocol_fee(&self) -> u64 {
        self.protocol_fee
    }
    pub fn rounding_fee(&self) -> u64 {
        self.rounding_fee
    }
    pub fn rounding_credit(&self) -> u64 {
        self.rounding_credit
    }
}
