// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact integer swap steps within one market State transition.

use super::{
    quantity, MarketDefinition, MarketError, PoolPhase, PoolState, MARKET_FEE_BPS,
    MARKET_QUANTITY_MAX,
};
use crate::native_assets::AssetId;

pub const MAX_SEQUENTIAL_TRADES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapQuote {
    input_asset: AssetId,
    output_asset: AssetId,
    gross_input: u64,
    effective_input: u64,
    output: u64,
    after: PoolState,
}

impl SwapQuote {
    pub fn input_asset(self) -> AssetId {
        self.input_asset
    }

    pub fn output_asset(self) -> AssetId {
        self.output_asset
    }

    pub fn gross_input(self) -> u64 {
        self.gross_input
    }

    pub fn effective_input(self) -> u64 {
        self.effective_input
    }

    pub fn fee(self) -> u64 {
        self.gross_input - self.effective_input
    }

    pub fn output(self) -> u64 {
        self.output
    }

    pub fn after(self) -> PoolState {
        self.after
    }
}

pub fn quote_exact_input(
    definition: MarketDefinition,
    before: PoolState,
    input_asset: AssetId,
    gross_input: u64,
    minimum_output: u64,
) -> Result<SwapQuote, MarketError> {
    before.check_definition(definition)?;
    if before.phase != PoolPhase::Idle
        || !definition.base_is_noid()
        || before.locked_shares != before.total_shares
    {
        return Err(MarketError::Phase);
    }
    quantity(gross_input)?;
    quantity(minimum_output)?;
    let base_input = if input_asset == definition.base {
        true
    } else if input_asset == definition.quote {
        false
    } else {
        return Err(MarketError::Pool);
    };
    let fee = (u128::from(gross_input) * u128::from(MARKET_FEE_BPS)).div_ceil(10_000);
    let effective_input = gross_input
        .checked_sub(u64::try_from(fee).map_err(|_| MarketError::Arithmetic)?)
        .filter(|&n| n != 0)
        .ok_or(MarketError::Quantity)?;
    let (input_reserve, output_reserve) = if base_input {
        (before.base_reserve, before.quote_reserve)
    } else {
        (before.quote_reserve, before.base_reserve)
    };
    let after_input = input_reserve
        .checked_add(gross_input)
        .filter(|&n| n <= MARKET_QUANTITY_MAX)
        .ok_or(MarketError::Capacity)?;
    let output = u64::try_from(
        u128::from(output_reserve) * u128::from(effective_input)
            / (u128::from(input_reserve) + u128::from(effective_input)),
    )
    .map_err(|_| MarketError::Arithmetic)?;
    if output < minimum_output {
        return Err(MarketError::Minimum);
    }
    let after_output = output_reserve
        .checked_sub(output)
        .filter(|&n| n != 0)
        .ok_or(MarketError::Conservation)?;
    let mut after = before;
    if base_input {
        after.base_reserve = after_input;
        after.quote_reserve = after_output;
    } else {
        after.quote_reserve = after_input;
        after.base_reserve = after_output;
    }
    after.check_definition(definition)?;
    if u128::from(after.base_reserve) * u128::from(after.quote_reserve)
        < u128::from(before.base_reserve) * u128::from(before.quote_reserve)
    {
        return Err(MarketError::Conservation);
    }
    Ok(SwapQuote {
        input_asset,
        output_asset: if base_input {
            definition.quote
        } else {
            definition.base
        },
        gross_input,
        effective_input,
        output,
        after,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequentialMarket {
    definition: MarketDefinition,
    before: PoolState,
    current: PoolState,
    steps: Vec<SwapQuote>,
}

impl SequentialMarket {
    pub fn new(definition: MarketDefinition, before: PoolState) -> Result<Self, MarketError> {
        before.check_definition(definition)?;
        if before.phase != PoolPhase::Idle
            || before.generation == u64::MAX
            || !definition.base_is_noid()
            || before.locked_shares != before.total_shares
        {
            return Err(MarketError::Phase);
        }
        Ok(Self {
            definition,
            before,
            current: before,
            steps: Vec::new(),
        })
    }

    pub fn current(&self) -> PoolState {
        self.current
    }

    pub fn steps(&self) -> &[SwapQuote] {
        &self.steps
    }

    pub fn apply(
        &mut self,
        input_asset: AssetId,
        gross_input: u64,
        minimum_output: u64,
    ) -> Result<SwapQuote, MarketError> {
        if self.steps.len() == MAX_SEQUENTIAL_TRADES {
            return Err(MarketError::Capacity);
        }
        let quote = quote_exact_input(
            self.definition,
            self.current,
            input_asset,
            gross_input,
            minimum_output,
        )?;
        self.current = quote.after();
        self.steps.push(quote);
        Ok(quote)
    }

    /// Advance the persisted generation once for the complete logical group.
    pub fn finish(self) -> Result<MarketExecution, MarketError> {
        if self.steps.is_empty() {
            return Err(MarketError::Capacity);
        }
        let mut after = self.current;
        after.generation = after
            .generation
            .checked_add(1)
            .ok_or(MarketError::Generation)?;
        after.check_definition(self.definition)?;
        Ok(MarketExecution {
            before: self.before,
            after,
            steps: self.steps,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketExecution {
    before: PoolState,
    after: PoolState,
    steps: Vec<SwapQuote>,
}

impl MarketExecution {
    pub fn before(&self) -> PoolState {
        self.before
    }

    pub fn after(&self) -> PoolState {
        self.after
    }

    pub fn steps(&self) -> &[SwapQuote] {
        &self.steps
    }
}
