// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical price-directed execution of one selected trade set.

use std::collections::BTreeSet;

use noid_poseidon2b::primitives::{Digest, TxBodyHash};

use super::{TradeError, TradeIntent};
use crate::native_assets::{
    launch::{
        sequential::{SequentialLaunch, TradeError as LaunchTradeError, TradeState},
        LaunchDefinition, LaunchError, LaunchSide, LaunchState,
    },
    market::{
        sequential::{SequentialMarket, MAX_SEQUENTIAL_TRADES},
        MarketDefinition, MarketError, PoolState, NOID_ASSET,
    },
    AssetId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TradeBoundary {
    pub chain: Digest,
    pub epoch_anchor: Digest,
    pub parent_id: Digest,
    pub height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketStart {
    Curve {
        definition: LaunchDefinition,
        state: LaunchState,
    },
    Market {
        definition: MarketDefinition,
        state: PoolState,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequencingError {
    Bounds,
    Asset,
    DuplicateFunding,
    Policy(TradeError),
    Market(MarketError),
    Launch(LaunchTradeError),
}

impl From<TradeError> for SequencingError {
    fn from(value: TradeError) -> Self {
        Self::Policy(value)
    }
}
impl From<MarketError> for SequencingError {
    fn from(value: MarketError) -> Self {
        Self::Market(value)
    }
}
impl From<LaunchTradeError> for SequencingError {
    fn from(value: LaunchTradeError) -> Self {
        Self::Launch(value)
    }
}

impl core::fmt::Display for SequencingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "trade sequence: {self:?}")
    }
}
impl std::error::Error for SequencingError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TradeOutcome {
    pub side: LaunchSide,
    pub gross_input: u64,
    pub spent_input: u64,
    pub output: u64,
    pub market_fee: u64,
    pub curve_spent: u64,
    pub curve_output: u64,
    pub after: TradeState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequencedFill {
    pub source_index: usize,
    pub authorization_id: TxBodyHash,
    pub outcome: TradeOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencingPlan {
    fills: Vec<SequencedFill>,
    unfilled: Vec<usize>,
    after: Option<TradeState>,
}

impl SequencingPlan {
    pub fn fills(&self) -> &[SequencedFill] {
        &self.fills
    }
    pub fn unfilled(&self) -> &[usize] {
        &self.unfilled
    }
    pub fn after(&self) -> Option<TradeState> {
        self.after
    }

    pub fn execute(
        start: MarketStart,
        boundary: TradeBoundary,
        intents: &[TradeIntent],
    ) -> Result<Self, SequencingError> {
        if intents.is_empty() || intents.len() > MAX_SEQUENTIAL_TRADES {
            return Err(SequencingError::Bounds);
        }
        let mut engine = Engine::new(start)?;
        let asset = engine.asset();
        let initial_price = engine.price()?;
        let mut slots = BTreeSet::new();
        let mut priorities = Vec::with_capacity(intents.len());
        for intent in intents {
            intent.checked(boundary.chain, boundary.epoch_anchor, boundary.height)?;
            if intent.policy.asset != asset {
                return Err(SequencingError::Asset);
            }
            for funding in &intent.funding {
                if !slots.insert(funding.input.slot_index) {
                    return Err(SequencingError::DuplicateFunding);
                }
            }
            priorities.push(intent.funding_priority(boundary.parent_id)?);
        }
        let mut remaining: Vec<_> = (0..intents.len()).collect();
        remaining.sort_unstable_by_key(|&index| priorities[index]);
        let mut fills = Vec::new();
        let mut unfilled = Vec::new();
        while !remaining.is_empty() {
            let current_price = engine.price()?;
            let preferred = if current_price.at_most(initial_price) {
                LaunchSide::Buy
            } else {
                LaunchSide::Sell
            };
            let position = remaining
                .iter()
                .position(|&i| intents[i].policy.side == preferred)
                .unwrap_or(0);
            let index = remaining.remove(position);
            let policy = intents[index].policy;
            match engine.apply(policy.side, policy.gross_input, policy.minimum_output) {
                Ok(outcome) => fills.push(SequencedFill {
                    source_index: index,
                    authorization_id: intents[index].authorization_id()?,
                    outcome,
                }),
                Err(error) if declinable(error) => unfilled.push(index),
                Err(error) => return Err(error),
            }
        }
        let after = if fills.is_empty() {
            None
        } else {
            Some(engine.finish()?)
        };
        Ok(Self {
            fills,
            unfilled,
            after,
        })
    }
}

fn declinable(error: SequencingError) -> bool {
    matches!(
        error,
        SequencingError::Market(
            MarketError::Minimum | MarketError::Quantity | MarketError::Capacity
        ) | SequencingError::Launch(LaunchTradeError::Minimum)
            | SequencingError::Launch(LaunchTradeError::Market(
                MarketError::Minimum | MarketError::Quantity | MarketError::Capacity
            ))
            | SequencingError::Launch(LaunchTradeError::Launch(
                LaunchError::Quantity | LaunchError::Capacity
            ))
    )
}

#[derive(Debug, Clone, Copy)]
struct Price {
    numerator: u64,
    denominator: u64,
}
impl Price {
    fn at_most(self, other: Self) -> bool {
        u128::from(self.numerator) * u128::from(other.denominator)
            <= u128::from(other.numerator) * u128::from(self.denominator)
    }
}

enum Engine {
    Curve {
        definition: LaunchDefinition,
        group: SequentialLaunch,
    },
    Market {
        definition: MarketDefinition,
        group: SequentialMarket,
    },
}

impl Engine {
    fn new(start: MarketStart) -> Result<Self, SequencingError> {
        Ok(match start {
            MarketStart::Curve { definition, state } => Self::Curve {
                definition,
                group: SequentialLaunch::new(definition, state)?,
            },
            MarketStart::Market { definition, state } => Self::Market {
                definition,
                group: SequentialMarket::new(definition, state)?,
            },
        })
    }

    fn asset(&self) -> AssetId {
        match self {
            Self::Curve { definition, .. } => definition.asset,
            Self::Market { definition, .. } => definition.quote,
        }
    }

    fn price(&self) -> Result<Price, SequencingError> {
        let pool = match self {
            Self::Curve { definition, group } => match group.current() {
                TradeState::Curve(state) => {
                    let price = definition
                        .marginal_price(definition.initial_supply - state.inventory_units)
                        .map_err(|error| {
                            SequencingError::Launch(LaunchTradeError::Launch(error))
                        })?;
                    return Ok(Price {
                        numerator: price.numerator,
                        denominator: price.denominator,
                    });
                }
                TradeState::Market(pool) => pool,
            },
            Self::Market { group, .. } => group.current(),
        };
        Ok(Price {
            numerator: pool.base_reserve,
            denominator: pool.quote_reserve,
        })
    }

    fn apply(
        &mut self,
        side: LaunchSide,
        gross_input: u64,
        minimum_output: u64,
    ) -> Result<TradeOutcome, SequencingError> {
        match self {
            Self::Curve { group, .. } => {
                let quote = group.apply(side, gross_input, minimum_output)?;
                Ok(TradeOutcome {
                    side,
                    gross_input,
                    spent_input: quote.spent_input(),
                    output: quote.output(),
                    market_fee: quote.market_fee(),
                    curve_spent: quote.curve_spent(),
                    curve_output: quote.curve_output(),
                    after: quote.after(),
                })
            }
            Self::Market { definition, group } => {
                let asset = match side {
                    LaunchSide::Buy => NOID_ASSET,
                    LaunchSide::Sell => definition.quote,
                };
                let quote = group.apply(asset, gross_input, minimum_output)?;
                Ok(TradeOutcome {
                    side,
                    gross_input,
                    spent_input: quote.gross_input(),
                    output: quote.output(),
                    market_fee: quote.fee(),
                    curve_spent: 0,
                    curve_output: 0,
                    after: TradeState::Market(quote.after()),
                })
            }
        }
    }

    fn finish(self) -> Result<TradeState, SequencingError> {
        Ok(match self {
            Self::Curve { group, .. } => group.finish()?.after(),
            Self::Market { group, .. } => TradeState::Market(group.finish()?.after()),
        })
    }
}
