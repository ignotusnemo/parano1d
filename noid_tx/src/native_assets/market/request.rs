// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Typed members of one funded market round.

use super::{
    LiquidityBurn, LiquidityDeposit, LiquidityWithdrawal, MarketDefinition, MarketError,
    MarketOpening, PoolState, SwapRequest,
};
use noid_poseidon2b::primitives::{Address, Digest};

mod sealed {
    pub trait Sealed {}
}

pub trait RequestValue: sealed::Sealed + Copy + Eq + core::fmt::Debug {
    fn validate(self) -> Result<(), MarketError>;
    fn root(self) -> Address;
    fn round(self) -> Digest;
    fn check_round(
        self,
        definition: MarketDefinition,
        pool: PoolState,
        height: u64,
    ) -> Result<(), MarketError>;
    fn principal(self, definition: MarketDefinition) -> Result<[u64; 2], MarketError>;
    fn consumed_lp_shares(self) -> u64;
    fn noid_value(self) -> Result<u64, MarketError>;
}

impl sealed::Sealed for SwapRequest {}
impl RequestValue for SwapRequest {
    fn validate(self) -> Result<(), MarketError> {
        SwapRequest::validate(self)
    }
    fn root(self) -> Address {
        SwapRequest::root(self)
    }
    fn round(self) -> Digest {
        self.round
    }
    fn check_round(self, d: MarketDefinition, p: PoolState, h: u64) -> Result<(), MarketError> {
        SwapRequest::check_round(self, d, p, h)
    }
    fn principal(self, d: MarketDefinition) -> Result<[u64; 2], MarketError> {
        if self.input_asset == d.base && self.output_asset == d.quote {
            Ok([self.gross_input, 0])
        } else if self.input_asset == d.quote && self.output_asset == d.base {
            Ok([0, self.gross_input])
        } else {
            Err(MarketError::Pool)
        }
    }
    fn consumed_lp_shares(self) -> u64 {
        0
    }
    fn noid_value(self) -> Result<u64, MarketError> {
        SwapRequest::noid_value(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketRequest {
    Swap(SwapRequest),
    Deposit(LiquidityDeposit),
    Withdraw(LiquidityWithdrawal),
    Burn(LiquidityBurn),
}
impl From<SwapRequest> for MarketRequest {
    fn from(v: SwapRequest) -> Self {
        Self::Swap(v)
    }
}
impl From<LiquidityDeposit> for MarketRequest {
    fn from(v: LiquidityDeposit) -> Self {
        Self::Deposit(v)
    }
}
impl From<LiquidityWithdrawal> for MarketRequest {
    fn from(v: LiquidityWithdrawal) -> Self {
        Self::Withdraw(v)
    }
}
impl From<LiquidityBurn> for MarketRequest {
    fn from(v: LiquidityBurn) -> Self {
        Self::Burn(v)
    }
}
impl sealed::Sealed for MarketRequest {}

impl MarketRequest {
    pub fn opening(self) -> MarketOpening {
        match self {
            Self::Swap(v) => MarketOpening::Request(v),
            Self::Deposit(v) => MarketOpening::LiquidityDeposit(v),
            Self::Withdraw(v) => MarketOpening::LiquidityWithdrawal(v),
            Self::Burn(v) => MarketOpening::LiquidityBurn(v),
        }
    }
    pub fn owner(self) -> Address {
        match self {
            Self::Swap(v) => v.owner,
            Self::Deposit(v) => v.owner,
            Self::Withdraw(v) => v.owner,
            Self::Burn(v) => v.owner,
        }
    }
    pub fn refundable_at(self, height: u64) -> Result<bool, MarketError> {
        match self {
            Self::Swap(v) => v.refundable_at(height),
            Self::Deposit(v) => v.refundable_at(height),
            Self::Withdraw(v) => v.refundable_at(height),
            Self::Burn(v) => v.refundable_at(height),
        }
    }
}

impl RequestValue for MarketRequest {
    fn validate(self) -> Result<(), MarketError> {
        self.opening().validate()
    }
    fn root(self) -> Address {
        self.opening().root()
    }
    fn round(self) -> Digest {
        match self {
            Self::Swap(v) => v.round,
            Self::Deposit(v) => v.round,
            Self::Withdraw(v) => v.round,
            Self::Burn(v) => v.round,
        }
    }
    fn check_round(self, d: MarketDefinition, p: PoolState, h: u64) -> Result<(), MarketError> {
        match self {
            Self::Swap(v) => v.check_round(d, p, h),
            Self::Deposit(v) => v.check_round(d, p, h),
            Self::Withdraw(v) => v.check_round(d, p, h),
            Self::Burn(v) => v.check_round(d, p, h),
        }
    }
    fn principal(self, d: MarketDefinition) -> Result<[u64; 2], MarketError> {
        match self {
            Self::Swap(v) => v.principal(d),
            Self::Deposit(v) => {
                v.check_definition(d)?;
                Ok([v.max_base, v.max_quote])
            }
            Self::Withdraw(v) => {
                v.check_definition(d)?;
                Ok([0, 0])
            }
            Self::Burn(v) => {
                v.check_definition(d)?;
                Ok([0, 0])
            }
        }
    }
    fn consumed_lp_shares(self) -> u64 {
        match self {
            Self::Withdraw(v) => v.shares,
            Self::Burn(v) => v.shares,
            _ => 0,
        }
    }
    fn noid_value(self) -> Result<u64, MarketError> {
        self.opening().noid_value()
    }
}
