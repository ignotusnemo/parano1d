// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Checked complete-set clearing, partial execution and exact escrow claims.

use super::{
    queue::RegisteredBatch, MarketDefinition, MarketError, PoolState, SwapClaim,
    MARKET_QUANTITY_MAX, MARKET_REQUEST_FEE_CREDIT,
};

pub const MAX_SETTLEMENT_FEE_PER_REQUEST: u64 = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClearingRate {
    pub numerator: u64,
    pub denominator: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchSettlement {
    after: PoolState,
    rate: ClearingRate,
    claims: Vec<SwapClaim>,
    fee: u64,
    execution: Vec<SwapExecution>,
    steps: Vec<super::limits::ClearingStep>,
}

impl BatchSettlement {
    pub fn calculate(
        definition: MarketDefinition,
        batch: &RegisteredBatch,
        height: u64,
        fee: u64,
    ) -> Result<Self, MarketError> {
        batch.settlement_allowed(height)?;
        batch.before().check_definition(definition)?;
        let count = batch.requests().len() as u64;
        if fee > count * MAX_SETTLEMENT_FEE_PER_REQUEST {
            return Err(MarketError::Fee);
        }
        let solution = super::limits::solve(definition, batch)?;
        let before = batch.before();
        let numerator = solution.price.numerator;
        let denominator = solution.price.denominator;
        let mut gross = [0u64; 2];
        let mut paid = [0u64; 2];
        let mut claims = Vec::with_capacity(count as usize);
        let mut execution = Vec::with_capacity(count as usize);
        for (index, entry) in batch.requests().iter().enumerate() {
            let r = entry.request;
            let side = usize::from(r.input_asset != definition.base);
            let effective = solution.effective[index];
            let capacity = r.effective_input()?;
            let spent = if effective == 0 {
                0
            } else if effective == capacity {
                r.gross_input
            } else {
                u64::try_from(
                    (u128::from(effective) * 10_000)
                        .div_ceil(u128::from(10_000 - super::MARKET_FEE_BPS)),
                )
                .map_err(|_| MarketError::Arithmetic)?
            };
            if spent > r.gross_input {
                return Err(MarketError::Conservation);
            }
            let output = super::limits::payout(effective, side, solution.price)?;
            let minimum = u64::try_from(
                u128::from(r.minimum_output) * u128::from(effective) / u128::from(capacity),
            )
            .map_err(|_| MarketError::Arithmetic)?;
            if output < minimum || (spent != 0 && output == 0) {
                return Err(MarketError::Minimum);
            }
            gross[side] = gross[side]
                .checked_add(spent)
                .ok_or(MarketError::Arithmetic)?;
            paid[1 - side] = paid[1 - side]
                .checked_add(output)
                .ok_or(MarketError::Arithmetic)?;
            let charged = fee / count + u64::from((index as u64) < fee % count);
            let refund = r.gross_input - spent;
            let claim = SwapClaim {
                request: entry.key(),
                input_asset: r.input_asset,
                output_asset: r.output_asset,
                refund_owner: r.owner,
                recipient: r.recipient,
                refund_units: refund,
                output_units: output,
                fee_credit: MARKET_REQUEST_FEE_CREDIT
                    .checked_sub(charged)
                    .ok_or(MarketError::Fee)?,
            };
            claim.validate()?;
            claims.push(claim);
            execution.push(SwapExecution {
                effective_input: effective,
                spent_input: spent,
                refund_input: refund,
                output,
            });
        }
        let mut after = before.idle_view();
        after.generation = after
            .generation
            .checked_add(1)
            .ok_or(MarketError::Arithmetic)?;
        after.base_reserve = before
            .base_reserve
            .checked_add(gross[0])
            .and_then(|n| n.checked_sub(paid[0]))
            .filter(|n| *n <= MARKET_QUANTITY_MAX)
            .ok_or(MarketError::Arithmetic)?;
        after.quote_reserve = before
            .quote_reserve
            .checked_add(gross[1])
            .and_then(|n| n.checked_sub(paid[1]))
            .filter(|n| *n <= MARKET_QUANTITY_MAX)
            .ok_or(MarketError::Arithmetic)?;
        after.validate()?;
        if u128::from(after.base_reserve) * u128::from(after.quote_reserve)
            < u128::from(before.base_reserve) * u128::from(before.quote_reserve)
        {
            return Err(MarketError::Conservation);
        }
        let incoming =
            batch
                .requests()
                .iter()
                .try_fold(u128::from(before.noid_value()), |sum, r| {
                    r.request.noid_value().and_then(|n| {
                        sum.checked_add(u128::from(n))
                            .ok_or(MarketError::Arithmetic)
                    })
                })?;
        let outgoing = claims.iter().try_fold(
            u128::from(after.noid_value()) + u128::from(fee),
            |sum, c| {
                c.noid_value().and_then(|n| {
                    sum.checked_add(u128::from(n))
                        .ok_or(MarketError::Arithmetic)
                })
            },
        )?;
        if incoming != outgoing {
            return Err(MarketError::Conservation);
        }
        Ok(Self {
            after,
            rate: ClearingRate {
                numerator,
                denominator,
            },
            claims,
            fee,
            execution,
            steps: solution.steps,
        })
    }
    pub fn after(&self) -> PoolState {
        self.after
    }
    pub fn rate(&self) -> ClearingRate {
        self.rate
    }
    pub fn claims(&self) -> &[SwapClaim] {
        &self.claims
    }
    pub fn fee(&self) -> u64 {
        self.fee
    }
    pub fn execution(&self) -> &[SwapExecution] {
        &self.execution
    }
    pub fn steps(&self) -> &[super::limits::ClearingStep] {
        &self.steps
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapExecution {
    pub effective_input: u64,
    pub spent_input: u64,
    pub refund_input: u64,
    pub output: u64,
}

/// Full execution convenience wrapper using the same complete-set engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullBatchSettlement(BatchSettlement);
impl FullBatchSettlement {
    pub fn calculate(
        definition: MarketDefinition,
        batch: &RegisteredBatch,
        height: u64,
        fee: u64,
    ) -> Result<Self, MarketError> {
        let result = BatchSettlement::calculate(definition, batch, height, fee)?;
        if result.execution.iter().any(|e| e.refund_input != 0) {
            return Err(MarketError::Minimum);
        }
        Ok(Self(result))
    }
    pub fn after(&self) -> PoolState {
        self.0.after()
    }
    pub fn rate(&self) -> ClearingRate {
        self.0.rate()
    }
    pub fn claims(&self) -> &[SwapClaim] {
        self.0.claims()
    }
    pub fn fee(&self) -> u64 {
        self.0.fee()
    }
}
