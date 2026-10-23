// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Funded liquidity rights and common-reference share accounting.

use super::{
    owner, quantity, MarketDefinition, MarketError, PoolId, PoolPhase, PoolState,
    MARKET_QUANTITY_MAX, MARKET_REQUEST_FEE_CREDIT, MARKET_SETTLEMENT_WINDOW,
};
use crate::native_assets::{NativeOpening, TokenBalance};
use noid_poseidon2b::primitives::{Address, Digest};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiquidityDeposit {
    pub pool: PoolId,
    pub round: Digest,
    pub owner: Address,
    pub max_base: u64,
    pub max_quote: u64,
    pub minimum_shares: u64,
    pub registered_height: u64,
    pub base_is_noid: bool,
}

impl LiquidityDeposit {
    pub fn validate(self) -> Result<(), MarketError> {
        identity(self.pool, self.round, self.owner, self.registered_height)?;
        quantity(self.max_base)?;
        quantity(self.max_quote)?;
        quantity(self.minimum_shares)?;
        self.noid_value()?;
        Ok(())
    }
    pub fn noid_value(self) -> Result<u64, MarketError> {
        MARKET_REQUEST_FEE_CREDIT
            .checked_add(if self.base_is_noid { self.max_base } else { 0 })
            .ok_or(MarketError::Arithmetic)
    }
    pub fn check_definition(self, definition: MarketDefinition) -> Result<(), MarketError> {
        self.validate()?;
        definition.validate()?;
        if self.pool != definition.id() || self.base_is_noid != definition.base_is_noid() {
            return Err(MarketError::Pool);
        }
        Ok(())
    }
    pub fn check_round(
        self,
        definition: MarketDefinition,
        pool: PoolState,
        height: u64,
    ) -> Result<(), MarketError> {
        self.check_definition(definition)?;
        pool.check_definition(definition)?;
        if self.pool != pool.pool
            || self.round != pool.round_id(height)?
            || self.registered_height != height
        {
            return Err(MarketError::Generation);
        }
        Ok(())
    }
    pub fn refundable_at(self, height: u64) -> Result<bool, MarketError> {
        self.validate()?;
        Ok(height >= expiry(self.registered_height)?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiquidityWithdrawal {
    pub pool: PoolId,
    pub round: Digest,
    pub owner: Address,
    pub shares: u64,
    pub registered_height: u64,
    pub minimum_base: u64,
    pub minimum_quote: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiquidityBurn {
    pub pool: PoolId,
    pub round: Digest,
    pub owner: Address,
    pub shares: u64,
    pub registered_height: u64,
}

impl LiquidityBurn {
    pub fn validate(self) -> Result<(), MarketError> {
        identity(self.pool, self.round, self.owner, self.registered_height)?;
        quantity(self.shares)
    }
    pub fn noid_value(self) -> u64 {
        MARKET_REQUEST_FEE_CREDIT
    }
    pub fn check_definition(self, definition: MarketDefinition) -> Result<(), MarketError> {
        self.validate()?;
        definition.validate()?;
        if self.pool != definition.id() {
            return Err(MarketError::Pool);
        }
        Ok(())
    }
    pub fn check_round(
        self,
        definition: MarketDefinition,
        pool: PoolState,
        height: u64,
    ) -> Result<(), MarketError> {
        self.check_definition(definition)?;
        pool.check_definition(definition)?;
        if self.pool != pool.pool
            || self.round != pool.round_id(height)?
            || self.registered_height != height
        {
            return Err(MarketError::Generation);
        }
        Ok(())
    }
    pub fn refundable_at(self, height: u64) -> Result<bool, MarketError> {
        self.validate()?;
        Ok(height >= expiry(self.registered_height)?)
    }
}

impl LiquidityWithdrawal {
    pub fn validate(self) -> Result<(), MarketError> {
        identity(self.pool, self.round, self.owner, self.registered_height)?;
        quantity(self.shares)?;
        if self.minimum_base > MARKET_QUANTITY_MAX || self.minimum_quote > MARKET_QUANTITY_MAX {
            return Err(MarketError::Quantity);
        }
        Ok(())
    }
    pub fn noid_value(self) -> u64 {
        MARKET_REQUEST_FEE_CREDIT
    }
    pub fn check_definition(self, definition: MarketDefinition) -> Result<(), MarketError> {
        self.validate()?;
        definition.validate()?;
        if self.pool != definition.id() {
            return Err(MarketError::Pool);
        }
        Ok(())
    }
    pub fn check_round(
        self,
        definition: MarketDefinition,
        pool: PoolState,
        height: u64,
    ) -> Result<(), MarketError> {
        self.check_definition(definition)?;
        pool.check_definition(definition)?;
        if self.pool != pool.pool
            || self.round != pool.round_id(height)?
            || self.registered_height != height
        {
            return Err(MarketError::Generation);
        }
        Ok(())
    }
    pub fn refundable_at(self, height: u64) -> Result<bool, MarketError> {
        self.validate()?;
        Ok(height >= expiry(self.registered_height)?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiquidityClaim {
    pub request: Digest,
    pub pool: PoolId,
    pub owner: Address,
    pub base_units: u64,
    pub quote_units: u64,
    pub shares: u64,
    pub fee_credit: u64,
    pub base_is_noid: bool,
}

impl LiquidityClaim {
    pub fn validate(self) -> Result<(), MarketError> {
        if self.request == [0; 32] || self.pool.0 == [0; 32] {
            return Err(MarketError::Identifier);
        }
        owner(self.owner)?;
        if self.base_units > MARKET_QUANTITY_MAX
            || self.quote_units > MARKET_QUANTITY_MAX
            || self.shares > MARKET_QUANTITY_MAX
            || self.fee_credit > MARKET_REQUEST_FEE_CREDIT
            || (self.base_units == 0
                && self.quote_units == 0
                && self.shares == 0
                && self.fee_credit == 0)
        {
            return Err(MarketError::Quantity);
        }
        self.noid_value()?;
        Ok(())
    }
    pub fn noid_value(self) -> Result<u64, MarketError> {
        self.fee_credit
            .checked_add(if self.base_is_noid {
                self.base_units
            } else {
                0
            })
            .ok_or(MarketError::Arithmetic)
    }
    pub fn check_definition(self, definition: MarketDefinition) -> Result<(), MarketError> {
        self.validate()?;
        definition.validate()?;
        if self.pool != definition.id() || self.base_is_noid != definition.base_is_noid() {
            return Err(MarketError::Pool);
        }
        Ok(())
    }

    /// Canonical beneficiary outputs, with fee credit kept separate from shares.
    pub fn payouts(
        self,
        definition: MarketDefinition,
        fee: u64,
    ) -> Result<Vec<(u64, Address, Option<NativeOpening>)>, MarketError> {
        self.check_definition(definition)?;
        if fee >= self.fee_credit {
            return Err(MarketError::Fee);
        }
        let mut values = BTreeMap::new();
        for (asset, amount) in [
            (definition.base, self.base_units),
            (definition.quote, self.quote_units),
            (super::NOID_ASSET, self.fee_credit - fee),
        ] {
            if amount != 0 {
                let entry = values.entry(asset).or_insert(0u64);
                *entry = entry.checked_add(amount).ok_or(MarketError::Arithmetic)?;
            }
        }
        let mut result = Vec::with_capacity(4);
        for (asset, amount) in values {
            if asset == super::NOID_ASSET {
                result.push((amount, self.owner, None));
            } else {
                let opening = NativeOpening::TokenBalance(TokenBalance {
                    asset,
                    owner: self.owner,
                    units: amount,
                    unlock_height: 0,
                });
                opening.validate().map_err(|_| MarketError::Funding)?;
                result.push((0, opening.root(), Some(opening)));
            }
        }
        if self.shares != 0 {
            let opening =
                NativeOpening::Market(super::MarketOpening::Liquidity(super::LiquidityPosition {
                    pool: self.pool,
                    owner: self.owner,
                    shares: self.shares,
                    unlock_height: 0,
                }));
            opening.validate().map_err(|_| MarketError::Funding)?;
            result.push((0, opening.root(), Some(opening)));
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiquidityChange {
    Deposit {
        max_base: u64,
        max_quote: u64,
        minimum_shares: u64,
    },
    Withdraw {
        shares: u64,
        minimum_base: u64,
        minimum_quote: u64,
    },
    Burn {
        shares: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LiquidityExecution {
    pub used_base: u64,
    pub used_quote: u64,
    pub paid_base: u64,
    pub paid_quote: u64,
    pub minted_shares: u64,
    pub burned_shares: u64,
    pub returned_shares: u64,
    pub locked_shares: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquiditySettlement {
    after: PoolState,
    execution: Vec<LiquidityExecution>,
}

impl LiquiditySettlement {
    /// All changes use the same post-swap reserves and pre-liquidity shares.
    pub fn calculate(
        reference: PoolState,
        changes: &[LiquidityChange],
    ) -> Result<Self, MarketError> {
        reference.validate()?;
        if reference.phase != PoolPhase::Idle {
            return Err(MarketError::Phase);
        }
        if changes.len() > super::queue::MAX_ROUND_REQUESTS {
            return Err(MarketError::Capacity);
        }
        let mut maximum = [
            u128::from(reference.base_reserve),
            u128::from(reference.quote_reserve),
        ];
        let mut withdrawal_shares = 0u128;
        for &change in changes {
            match change {
                LiquidityChange::Deposit {
                    max_base,
                    max_quote,
                    minimum_shares,
                } => {
                    quantity(max_base)?;
                    quantity(max_quote)?;
                    quantity(minimum_shares)?;
                    maximum[0] += u128::from(max_base);
                    maximum[1] += u128::from(max_quote);
                }
                LiquidityChange::Withdraw {
                    shares,
                    minimum_base,
                    minimum_quote,
                } => {
                    quantity(shares)?;
                    if minimum_base > MARKET_QUANTITY_MAX || minimum_quote > MARKET_QUANTITY_MAX {
                        return Err(MarketError::Quantity);
                    }
                    withdrawal_shares += u128::from(shares);
                }
                LiquidityChange::Burn { shares } => {
                    quantity(shares)?;
                    withdrawal_shares += u128::from(shares);
                }
            }
        }
        if maximum.iter().any(|&n| n > u128::from(MARKET_QUANTITY_MAX))
            || withdrawal_shares > u128::from(reference.total_shares - reference.locked_shares)
        {
            return Err(MarketError::Capacity);
        }
        let (x, y, l) = (
            u128::from(reference.base_reserve),
            u128::from(reference.quote_reserve),
            u128::from(reference.total_shares),
        );
        let mut used = [0u128; 2];
        let mut paid = [0u128; 2];
        let mut minted = 0u128;
        let mut burned = 0u128;
        let mut locked = 0u128;
        let mut execution = Vec::with_capacity(changes.len());
        for &change in changes {
            let mut result = LiquidityExecution::default();
            match change {
                LiquidityChange::Deposit {
                    max_base,
                    max_quote,
                    minimum_shares,
                } => {
                    let shares = (u128::from(max_base) * l / x).min(u128::from(max_quote) * l / y);
                    if shares >= u128::from(minimum_shares) {
                        result.minted_shares = to_quantity(shares)?;
                        result.used_base = to_quantity((shares * x).div_ceil(l))?;
                        result.used_quote = to_quantity((shares * y).div_ceil(l))?;
                        if result.used_base > max_base || result.used_quote > max_quote {
                            return Err(MarketError::Conservation);
                        }
                    }
                }
                LiquidityChange::Withdraw {
                    shares,
                    minimum_base,
                    minimum_quote,
                } => {
                    let base = u128::from(shares) * x / l;
                    let quote = u128::from(shares) * y / l;
                    if base >= u128::from(minimum_base)
                        && quote >= u128::from(minimum_quote)
                        && (base != 0 || quote != 0)
                    {
                        result.burned_shares = shares;
                        result.paid_base = to_quantity(base)?;
                        result.paid_quote = to_quantity(quote)?;
                    } else {
                        result.returned_shares = shares;
                    }
                }
                LiquidityChange::Burn { shares } => {
                    result.locked_shares = shares;
                }
            }
            used[0] += u128::from(result.used_base);
            used[1] += u128::from(result.used_quote);
            paid[0] += u128::from(result.paid_base);
            paid[1] += u128::from(result.paid_quote);
            minted += u128::from(result.minted_shares);
            burned += u128::from(result.burned_shares);
            locked += u128::from(result.locked_shares);
            execution.push(result);
        }
        let mut after = reference;
        after.base_reserve = to_quantity(
            (x + used[0])
                .checked_sub(paid[0])
                .ok_or(MarketError::Conservation)?,
        )?;
        after.quote_reserve = to_quantity(
            (y + used[1])
                .checked_sub(paid[1])
                .ok_or(MarketError::Conservation)?,
        )?;
        after.total_shares = to_quantity(
            (l + minted)
                .checked_sub(burned)
                .ok_or(MarketError::Conservation)?,
        )?;
        after.locked_shares = to_quantity(u128::from(reference.locked_shares) + locked)?;
        after.validate()?;
        if u128::from(after.base_reserve) * l < x * u128::from(after.total_shares)
            || u128::from(after.quote_reserve) * l < y * u128::from(after.total_shares)
        {
            return Err(MarketError::Conservation);
        }
        Ok(Self { after, execution })
    }
    pub fn after(&self) -> PoolState {
        self.after
    }
    pub fn execution(&self) -> &[LiquidityExecution] {
        &self.execution
    }
}

fn identity(pool: PoolId, round: Digest, who: Address, height: u64) -> Result<(), MarketError> {
    if pool.0 == [0; 32] || round == [0; 32] {
        return Err(MarketError::Identifier);
    }
    owner(who)?;
    expiry(height)?;
    Ok(())
}
fn expiry(height: u64) -> Result<u64, MarketError> {
    if height == 0 {
        return Err(MarketError::Height);
    }
    height
        .checked_add(MARKET_SETTLEMENT_WINDOW)
        .ok_or(MarketError::Arithmetic)
}
fn to_quantity(n: u128) -> Result<u64, MarketError> {
    if n > u128::from(MARKET_QUANTITY_MAX) {
        return Err(MarketError::Arithmetic);
    }
    Ok(n as u64)
}
