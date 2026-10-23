// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete swap and liquidity settlement for one authenticated round.

use super::{
    clearing::{BatchSettlement, ClearingRate, MAX_SETTLEMENT_FEE_PER_REQUEST},
    liquidity::{LiquidityChange, LiquidityClaim, LiquidityExecution, LiquiditySettlement},
    queue::{FundedRequestRef, MarketRequestRef, MixedRegisteredBatch},
    request::{MarketRequest, RequestValue},
    MarketDefinition, MarketError, MarketOpening, PoolState, SwapClaim, MARKET_REQUEST_FEE_CREDIT,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixedBatchSettlement {
    after: PoolState,
    rate: ClearingRate,
    claims: Vec<MarketOpening>,
    fee: u64,
    swaps: Option<BatchSettlement>,
    liquidity: Vec<(usize, LiquidityExecution)>,
}

impl MixedBatchSettlement {
    pub fn calculate(
        definition: MarketDefinition,
        batch: &MixedRegisteredBatch,
        height: u64,
        fee: u64,
    ) -> Result<Self, MarketError> {
        batch.settlement_allowed(height)?;
        batch.before().check_definition(definition)?;
        let count = batch.requests().len() as u64;
        if count == 0 || fee > count * MAX_SETTLEMENT_FEE_PER_REQUEST {
            return Err(MarketError::Fee);
        }
        let charged: Vec<_> = (0..count)
            .map(|i| fee / count + u64::from(i < fee % count))
            .collect();
        let projection = batch.swap_projection();
        let swap_fee = batch
            .requests()
            .iter()
            .enumerate()
            .filter_map(|(i, r)| matches!(r.request, MarketRequest::Swap(_)).then_some(charged[i]))
            .sum();
        let swaps = if projection.requests().is_empty() {
            None
        } else {
            Some(BatchSettlement::calculate(
                definition,
                &projection,
                height,
                swap_fee,
            )?)
        };
        let (reference, rate) = if let Some(s) = &swaps {
            (s.after(), s.rate())
        } else {
            let mut next = batch.before().idle_view();
            next.generation = next
                .generation
                .checked_add(1)
                .ok_or(MarketError::Arithmetic)?;
            next.validate()?;
            (
                next,
                ClearingRate {
                    numerator: next.quote_reserve,
                    denominator: next.base_reserve,
                },
            )
        };
        let mut indexes = Vec::new();
        let mut changes = Vec::new();
        for (i, r) in batch.requests().iter().enumerate() {
            match r.request {
                MarketRequest::Deposit(d) => {
                    indexes.push(i);
                    changes.push(LiquidityChange::Deposit {
                        max_base: d.max_base,
                        max_quote: d.max_quote,
                        minimum_shares: d.minimum_shares,
                    });
                }
                MarketRequest::Withdraw(w) => {
                    indexes.push(i);
                    changes.push(LiquidityChange::Withdraw {
                        shares: w.shares,
                        minimum_base: w.minimum_base,
                        minimum_quote: w.minimum_quote,
                    });
                }
                MarketRequest::Burn(b) => {
                    indexes.push(i);
                    changes.push(LiquidityChange::Burn { shares: b.shares });
                }
                _ => (),
            }
        }
        let lp = LiquiditySettlement::calculate(reference, &changes)?;
        let liquidity: Vec<_> = indexes
            .iter()
            .copied()
            .zip(lp.execution().iter().copied())
            .collect();
        let mut li = 0;
        let mut si = 0;
        let mut claims = Vec::with_capacity(count as usize);
        for (i, r) in batch.requests().iter().enumerate() {
            let credit = MARKET_REQUEST_FEE_CREDIT - charged[i];
            let claim = match r.request {
                MarketRequest::Swap(_) => {
                    let c = swaps.as_ref().ok_or(MarketError::Conservation)?.claims()[si];
                    si += 1;
                    if c.request != r.key() || c.fee_credit != credit {
                        return Err(MarketError::Conservation);
                    }
                    MarketOpening::Claim(c)
                }
                MarketRequest::Deposit(d) => {
                    let result = lp.execution()[li];
                    li += 1;
                    MarketOpening::LiquidityClaim(LiquidityClaim {
                        request: r.key(),
                        pool: d.pool,
                        owner: d.owner,
                        base_units: d.max_base - result.used_base,
                        quote_units: d.max_quote - result.used_quote,
                        shares: result.minted_shares,
                        fee_credit: credit,
                        base_is_noid: definition.base_is_noid(),
                    })
                }
                MarketRequest::Withdraw(w) => {
                    let result = lp.execution()[li];
                    li += 1;
                    MarketOpening::LiquidityClaim(LiquidityClaim {
                        request: r.key(),
                        pool: w.pool,
                        owner: w.owner,
                        base_units: result.paid_base,
                        quote_units: result.paid_quote,
                        shares: result.returned_shares,
                        fee_credit: credit,
                        base_is_noid: definition.base_is_noid(),
                    })
                }
                MarketRequest::Burn(b) => {
                    let result = lp.execution()[li];
                    li += 1;
                    if result.locked_shares != b.shares {
                        return Err(MarketError::Conservation);
                    }
                    MarketOpening::LiquidityClaim(LiquidityClaim {
                        request: r.key(),
                        pool: b.pool,
                        owner: b.owner,
                        base_units: 0,
                        quote_units: 0,
                        shares: 0,
                        fee_credit: credit,
                        base_is_noid: definition.base_is_noid(),
                    })
                }
            };
            claim.validate()?;
            claims.push(claim);
        }
        let after = lp.after();
        let mut incoming = [
            u128::from(batch.before().base_reserve),
            u128::from(batch.before().quote_reserve),
        ];
        let mut outgoing = [
            u128::from(after.base_reserve),
            u128::from(after.quote_reserve),
        ];
        let mut incoming_noid = u128::from(batch.before().noid_value());
        let mut outgoing_noid = u128::from(after.noid_value()) + u128::from(fee);
        let mut requested_shares = 0u128;
        let mut returned_or_minted_shares = 0u128;
        for (r, c) in batch.requests().iter().zip(&claims) {
            let principal = r.request.principal(definition)?;
            for side in 0..2 {
                incoming[side] += u128::from(principal[side]);
            }
            incoming_noid += u128::from(r.request.noid_value()?);
            outgoing_noid += u128::from(c.noid_value()?);
            requested_shares += u128::from(r.request.consumed_lp_shares());
            match *c {
                MarketOpening::Claim(c) => {
                    if c.input_asset == definition.base {
                        outgoing[0] += u128::from(c.refund_units);
                        outgoing[1] += u128::from(c.output_units);
                    } else {
                        outgoing[1] += u128::from(c.refund_units);
                        outgoing[0] += u128::from(c.output_units);
                    }
                }
                MarketOpening::LiquidityClaim(c) => {
                    c.check_definition(definition)?;
                    outgoing[0] += u128::from(c.base_units);
                    outgoing[1] += u128::from(c.quote_units);
                    returned_or_minted_shares += u128::from(c.shares);
                }
                _ => return Err(MarketError::Conservation),
            }
        }
        if incoming != outgoing
            || incoming_noid != outgoing_noid
            || u128::from(batch.before().total_shares - batch.before().locked_shares)
                + returned_or_minted_shares
                != u128::from(after.total_shares - after.locked_shares) + requested_shares
            || u128::from(after.locked_shares)
                != u128::from(batch.before().locked_shares)
                    + liquidity
                        .iter()
                        .map(|(_, e)| u128::from(e.locked_shares))
                        .sum::<u128>()
        {
            return Err(MarketError::Conservation);
        }
        Ok(Self {
            after,
            rate,
            claims,
            fee,
            swaps,
            liquidity,
        })
    }
    pub fn after(&self) -> PoolState {
        self.after
    }
    pub fn rate(&self) -> ClearingRate {
        self.rate
    }
    pub fn claims(&self) -> &[MarketOpening] {
        &self.claims
    }
    pub fn fee(&self) -> u64 {
        self.fee
    }
    pub fn swaps(&self) -> Option<&BatchSettlement> {
        self.swaps.as_ref()
    }
    pub fn liquidity(&self) -> &[(usize, LiquidityExecution)] {
        &self.liquidity
    }
}

pub fn timeout_claim(
    definition: MarketDefinition,
    r: MarketRequestRef,
    height: u64,
    charged: u64,
) -> Result<MarketOpening, MarketError> {
    r.validate()?;
    if charged > MAX_SETTLEMENT_FEE_PER_REQUEST {
        return Err(MarketError::Fee);
    }
    if !r.request.refundable_at(height)? {
        return Err(MarketError::Phase);
    }
    let credit = MARKET_REQUEST_FEE_CREDIT - charged;
    let claim = match r.request {
        MarketRequest::Swap(request) => MarketOpening::Claim(SwapClaim::timeout_refund(
            FundedRequestRef {
                slot_index: r.slot_index,
                creation_id: r.creation_id,
                request,
            },
            height,
            charged,
        )?),
        MarketRequest::Deposit(d) => {
            d.check_definition(definition)?;
            MarketOpening::LiquidityClaim(LiquidityClaim {
                request: r.key(),
                pool: d.pool,
                owner: d.owner,
                base_units: d.max_base,
                quote_units: d.max_quote,
                shares: 0,
                fee_credit: credit,
                base_is_noid: definition.base_is_noid(),
            })
        }
        MarketRequest::Withdraw(w) => {
            w.check_definition(definition)?;
            MarketOpening::LiquidityClaim(LiquidityClaim {
                request: r.key(),
                pool: w.pool,
                owner: w.owner,
                base_units: 0,
                quote_units: 0,
                shares: w.shares,
                fee_credit: credit,
                base_is_noid: definition.base_is_noid(),
            })
        }
        MarketRequest::Burn(b) => {
            b.check_definition(definition)?;
            MarketOpening::LiquidityClaim(LiquidityClaim {
                request: r.key(),
                pool: b.pool,
                owner: b.owner,
                base_units: 0,
                quote_units: 0,
                shares: b.shares,
                fee_credit: credit,
                base_is_noid: definition.base_is_noid(),
            })
        }
    };
    claim.validate()?;
    Ok(claim)
}
