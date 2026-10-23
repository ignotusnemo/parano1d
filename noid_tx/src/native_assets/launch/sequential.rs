// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Sequential curve trades and automatic same-asset market graduation.

use super::{LaunchDefinition, LaunchError, LaunchSide, LaunchState};
use crate::native_assets::market::{
    sequential::{quote_exact_input, MAX_SEQUENTIAL_TRADES},
    MarketError, PoolPhase, PoolState, MARKET_QUANTITY_MAX, NOID_ASSET,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TradeState {
    Curve(LaunchState),
    Market(PoolState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TradeError {
    Launch(LaunchError),
    Market(MarketError),
    Minimum,
}

impl From<LaunchError> for TradeError {
    fn from(value: LaunchError) -> Self {
        Self::Launch(value)
    }
}

impl From<MarketError> for TradeError {
    fn from(value: MarketError) -> Self {
        Self::Market(value)
    }
}

impl core::fmt::Display for TradeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "sequential launch: {self:?}")
    }
}

impl std::error::Error for TradeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TradeQuote {
    side: LaunchSide,
    gross_input: u64,
    spent_input: u64,
    output: u64,
    market_fee: u64,
    curve_spent: u64,
    curve_output: u64,
    after: TradeState,
}

impl TradeQuote {
    pub fn side(self) -> LaunchSide {
        self.side
    }

    pub fn gross_input(self) -> u64 {
        self.gross_input
    }

    pub fn spent_input(self) -> u64 {
        self.spent_input
    }

    pub fn refund_input(self) -> u64 {
        self.gross_input - self.spent_input
    }

    pub fn output(self) -> u64 {
        self.output
    }

    pub fn market_fee(self) -> u64 {
        self.market_fee
    }

    pub fn curve_spent(self) -> u64 {
        self.curve_spent
    }

    pub fn curve_output(self) -> u64 {
        self.curve_output
    }

    pub fn after(self) -> TradeState {
        self.after
    }
}

fn bounded(value: u64) -> Result<(), LaunchError> {
    if value == 0 || value > MARKET_QUANTITY_MAX {
        Err(LaunchError::Quantity)
    } else {
        Ok(())
    }
}

fn market_quote(
    definition: LaunchDefinition,
    before: PoolState,
    side: LaunchSide,
    gross_input: u64,
    minimum_output: u64,
) -> Result<TradeQuote, TradeError> {
    let input_asset = match side {
        LaunchSide::Buy => NOID_ASSET,
        LaunchSide::Sell => definition.asset,
    };
    let quote = quote_exact_input(
        definition.market_definition(),
        before,
        input_asset,
        gross_input,
        minimum_output,
    )?;
    Ok(TradeQuote {
        side,
        gross_input,
        spent_input: gross_input,
        output: quote.output(),
        market_fee: quote.fee(),
        curve_spent: 0,
        curve_output: 0,
        after: TradeState::Market(quote.after()),
    })
}

pub fn quote_curve_exact_input(
    definition: LaunchDefinition,
    before: LaunchState,
    side: LaunchSide,
    gross_input: u64,
    minimum_output: u64,
) -> Result<TradeQuote, TradeError> {
    before.check_definition(definition)?;
    if before.phase != PoolPhase::Idle {
        return Err(LaunchError::Phase.into());
    }
    bounded(gross_input)?;
    bounded(minimum_output)?;
    let sold = definition.initial_supply - before.inventory_units;
    let (next_sold, curve_spent, curve_output) = match side {
        LaunchSide::Buy => {
            let mut low = 0;
            let mut high = definition.sale_units() - sold;
            let cash_limit = u128::from(before.market_noid) + u128::from(gross_input);
            while low < high {
                let middle = low + (high - low).div_ceil(2);
                if u128::from(definition.curve_cash(sold + middle)?) <= cash_limit {
                    low = middle;
                } else {
                    high = middle - 1;
                }
            }
            if low == 0 {
                return Err(LaunchError::Quantity.into());
            }
            let next_sold = sold + low;
            let spent = definition
                .curve_cash(next_sold)?
                .checked_sub(before.market_noid)
                .ok_or(LaunchError::Conservation)?;
            (next_sold, spent, low)
        }
        LaunchSide::Sell => {
            let next_sold = sold.checked_sub(gross_input).ok_or(LaunchError::Quantity)?;
            let output = before
                .market_noid
                .checked_sub(definition.curve_cash(next_sold)?)
                .ok_or(LaunchError::Conservation)?;
            (next_sold, gross_input, output)
        }
    };
    let next_cash = definition.curve_cash(next_sold)?;
    let mut after = if next_sold == definition.sale_units() {
        let pool = definition.graduation_pool()?;
        if pool.base_reserve != next_cash {
            return Err(LaunchError::Conservation.into());
        }
        TradeState::Market(pool)
    } else {
        let next = LaunchState {
            inventory_units: definition.initial_supply - next_sold,
            market_noid: next_cash,
            ..before
        };
        next.check_definition(definition)?;
        TradeState::Curve(next)
    };
    let mut spent_input = curve_spent;
    let mut output = curve_output;
    let mut market_fee = 0;
    if side == LaunchSide::Buy {
        let remaining = gross_input
            .checked_sub(curve_spent)
            .ok_or(LaunchError::Conservation)?;
        if let TradeState::Market(pool) = after {
            if remaining != 0 {
                match market_quote(definition, pool, side, remaining, 1) {
                    Ok(quote) => {
                        spent_input = spent_input
                            .checked_add(quote.spent_input())
                            .ok_or(LaunchError::Arithmetic)?;
                        output = output
                            .checked_add(quote.output())
                            .ok_or(LaunchError::Arithmetic)?;
                        market_fee = quote.market_fee();
                        after = quote.after();
                    }
                    Err(TradeError::Market(MarketError::Quantity | MarketError::Minimum)) => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
    if output < minimum_output {
        return Err(TradeError::Minimum);
    }
    Ok(TradeQuote {
        side,
        gross_input,
        spent_input,
        output,
        market_fee,
        curve_spent,
        curve_output,
        after,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequentialLaunch {
    definition: LaunchDefinition,
    before: LaunchState,
    current: TradeState,
    steps: Vec<TradeQuote>,
}

impl SequentialLaunch {
    pub fn new(definition: LaunchDefinition, before: LaunchState) -> Result<Self, TradeError> {
        before.check_definition(definition)?;
        if before.phase != PoolPhase::Idle || before.generation == u64::MAX {
            return Err(LaunchError::Phase.into());
        }
        Ok(Self {
            definition,
            before,
            current: TradeState::Curve(before),
            steps: Vec::new(),
        })
    }

    pub fn current(&self) -> TradeState {
        self.current
    }

    pub fn steps(&self) -> &[TradeQuote] {
        &self.steps
    }

    pub fn apply(
        &mut self,
        side: LaunchSide,
        gross_input: u64,
        minimum_output: u64,
    ) -> Result<TradeQuote, TradeError> {
        if self.steps.len() == MAX_SEQUENTIAL_TRADES {
            return Err(LaunchError::Capacity.into());
        }
        let quote = match self.current {
            TradeState::Curve(state) => {
                quote_curve_exact_input(self.definition, state, side, gross_input, minimum_output)?
            }
            TradeState::Market(pool) => {
                market_quote(self.definition, pool, side, gross_input, minimum_output)?
            }
        };
        self.current = quote.after();
        self.steps.push(quote);
        Ok(quote)
    }

    pub fn finish(self) -> Result<LaunchExecution, TradeError> {
        if self.steps.is_empty() {
            return Err(LaunchError::Capacity.into());
        }
        let after = match self.current {
            TradeState::Curve(mut state) => {
                state.generation = state
                    .generation
                    .checked_add(1)
                    .ok_or(LaunchError::Arithmetic)?;
                state.check_definition(self.definition)?;
                TradeState::Curve(state)
            }
            TradeState::Market(pool) => {
                pool.check_definition(self.definition.market_definition())?;
                TradeState::Market(pool)
            }
        };
        Ok(LaunchExecution {
            before: self.before,
            after,
            steps: self.steps,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchExecution {
    before: LaunchState,
    after: TradeState,
    steps: Vec<TradeQuote>,
}

impl LaunchExecution {
    pub fn before(&self) -> LaunchState {
        self.before
    }

    pub fn after(&self) -> TradeState {
        self.after
    }

    pub fn steps(&self) -> &[TradeQuote] {
        &self.steps
    }
}
