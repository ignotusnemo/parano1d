// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Finite financial operations and their canonical header operands.

pub mod owner;
pub mod public;

use super::{native_sequence, NATIVE_SEQUENCE_MAX};
use crate::TxOutput;
use noid_poseidon2b::primitives::Address;

/// Automatic registration and timeout maintenance carry no transaction fee.
pub const ZERO_FEE_OPERATION_CODES: [u16; 4] = [38, 41, 50, 53];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeParentRef {
    pub slot_index: u32,
    pub creation_id: u64,
    pub root: Address,
}
impl NativeParentRef {
    pub fn validate(self) -> Result<(), FinancialOperationError> {
        if self.root == Address([0; 32]) || native_sequence(self.creation_id).is_err() {
            return Err(FinancialOperationError::Parent);
        }
        Ok(())
    }
    pub fn check_boundary(self, parent_alloc_counter: u64) -> Result<(), FinancialOperationError> {
        self.validate()?;
        if parent_alloc_counter > NATIVE_SEQUENCE_MAX
            || native_sequence(self.creation_id).map_err(|_| FinancialOperationError::Parent)?
                > parent_alloc_counter
        {
            return Err(FinancialOperationError::Parent);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinancialOperation {
    BootstrapPool {
        funding_input: u16,
        definition: Address,
    },
    Swap {
        parent: NativeParentRef,
    },
    DepositLiquidity {
        parent: NativeParentRef,
    },
    WithdrawLiquidity {
        parent: NativeParentRef,
    },
    BurnLiquidity {
        parent: NativeParentRef,
    },
    TransferLiquidity {
        definition: Address,
    },
    RegisterPools,
    SettlePool,
    RefundMarket {
        definition: Address,
    },
    ResetPool,
    ClaimLiquidity {
        definition: Address,
    },
    ClaimSwap,
    CreateLaunch {
        funding_input: u16,
        definition: Address,
    },
    LaunchRequest {
        parent: NativeParentRef,
    },
    RegisterLaunches,
    SettleLaunch,
    RefundLaunch,
    ResetLaunch,
    CreateListing {
        definition: Address,
    },
    Purchase {
        parent: NativeParentRef,
    },
    CancelListing,
    CreateOffer {
        funding_input: u16,
    },
    AcceptOffer,
    CancelOffer,
    RegisterListings,
    SettleListing,
    ResetListing,
    RecoverListing,
    RefundPurchase,
    RefundOffer,
    ExecuteTrades {
        commitment: Address,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinancialOperationError {
    Code,
    Operand,
    Parent,
    Funding,
}
impl core::fmt::Display for FinancialOperationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "financial operation: {self:?}")
    }
}
impl std::error::Error for FinancialOperationError {}

impl FinancialOperation {
    pub fn has_zero_fee(self) -> bool {
        ZERO_FEE_OPERATION_CODES.contains(&self.code())
    }

    pub fn requires_owner(self) -> bool {
        matches!(
            self,
            Self::BootstrapPool { .. }
                | Self::Swap { .. }
                | Self::DepositLiquidity { .. }
                | Self::WithdrawLiquidity { .. }
                | Self::BurnLiquidity { .. }
                | Self::TransferLiquidity { .. }
                | Self::CreateLaunch { .. }
                | Self::LaunchRequest { .. }
                | Self::CreateListing { .. }
                | Self::Purchase { .. }
                | Self::CancelListing
                | Self::CreateOffer { .. }
                | Self::AcceptOffer
                | Self::CancelOffer
        )
    }
    pub fn parent(self) -> Option<NativeParentRef> {
        match self {
            Self::Swap { parent }
            | Self::DepositLiquidity { parent }
            | Self::WithdrawLiquidity { parent }
            | Self::BurnLiquidity { parent }
            | Self::LaunchRequest { parent }
            | Self::Purchase { parent } => Some(parent),
            _ => None,
        }
    }
    pub fn definition(self) -> Option<Address> {
        match self {
            Self::BootstrapPool { definition, .. }
            | Self::TransferLiquidity { definition }
            | Self::RefundMarket { definition }
            | Self::ClaimLiquidity { definition }
            | Self::CreateLaunch { definition, .. }
            | Self::CreateListing { definition } => Some(definition),
            _ => None,
        }
    }
    pub fn funding_input(self) -> Option<u16> {
        match self {
            Self::BootstrapPool { funding_input, .. }
            | Self::CreateLaunch { funding_input, .. }
            | Self::CreateOffer { funding_input } => Some(funding_input),
            _ => None,
        }
    }
    pub fn with_funding_input(self, funding_input: u16) -> Result<Self, FinancialOperationError> {
        Ok(match self {
            Self::BootstrapPool { definition, .. } => Self::BootstrapPool {
                definition,
                funding_input,
            },
            Self::CreateLaunch { definition, .. } => Self::CreateLaunch {
                definition,
                funding_input,
            },
            Self::CreateOffer { .. } => Self::CreateOffer { funding_input },
            _ => return Err(FinancialOperationError::Funding),
        })
    }
    pub fn code(self) -> u16 {
        match self {
            Self::BootstrapPool { .. } => 32,
            Self::Swap { .. } => 33,
            Self::DepositLiquidity { .. } => 34,
            Self::WithdrawLiquidity { .. } => 35,
            Self::BurnLiquidity { .. } => 36,
            Self::TransferLiquidity { .. } => 37,
            Self::RegisterPools => 38,
            Self::SettlePool => 39,
            Self::RefundMarket { .. } => 40,
            Self::ResetPool => 41,
            Self::ClaimLiquidity { .. } => 42,
            Self::ClaimSwap => 43,
            Self::CreateLaunch { .. } => 48,
            Self::LaunchRequest { .. } => 49,
            Self::RegisterLaunches => 50,
            Self::SettleLaunch => 51,
            Self::RefundLaunch => 52,
            Self::ResetLaunch => 53,
            Self::CreateListing { .. } => 64,
            Self::Purchase { .. } => 65,
            Self::CancelListing => 66,
            Self::CreateOffer { .. } => 67,
            Self::AcceptOffer => 68,
            Self::CancelOffer => 69,
            Self::RegisterListings => 70,
            Self::SettleListing => 71,
            Self::ResetListing => 72,
            Self::RecoverListing => 73,
            Self::RefundPurchase => 74,
            Self::RefundOffer => 75,
            Self::ExecuteTrades { .. } => 80,
        }
    }
    pub fn operand(self) -> Result<TxOutput, FinancialOperationError> {
        if !super::profile::operation_enabled(self.code()) {
            return Err(FinancialOperationError::Code);
        }
        if let Self::ExecuteTrades { commitment } = self {
            if commitment == Address([0; 32]) {
                return Err(FinancialOperationError::Operand);
            }
            return Ok(TxOutput {
                slot_index: 0,
                amount: 0,
                owner: commitment,
            });
        }
        if self
            .funding_input()
            .is_some_and(|i| usize::from(i) >= crate::MAX_PAGED_SPEND_INPUTS)
        {
            return Err(FinancialOperationError::Funding);
        }
        let value = if let Some(p) = self.parent() {
            p.validate()?;
            TxOutput {
                slot_index: p.slot_index,
                amount: p.creation_id,
                owner: p.root,
            }
        } else {
            let owner = self.definition().unwrap_or(Address([0; 32]));
            if self.definition().is_some() && owner == Address([0; 32]) {
                return Err(FinancialOperationError::Operand);
            }
            TxOutput {
                slot_index: 0,
                amount: u64::from(self.funding_input().unwrap_or(0)),
                owner,
            }
        };
        Ok(value)
    }
    pub fn decode(code: u16, operand: TxOutput) -> Result<Self, FinancialOperationError> {
        let parent = NativeParentRef {
            slot_index: operand.slot_index,
            creation_id: operand.amount,
            root: operand.owner,
        };
        let funding_input = u16::try_from(operand.amount).unwrap_or(u16::MAX);
        let definition = operand.owner;
        let value = match code {
            32 => Self::BootstrapPool {
                funding_input,
                definition,
            },
            33 => Self::Swap { parent },
            34 => Self::DepositLiquidity { parent },
            35 => Self::WithdrawLiquidity { parent },
            36 => Self::BurnLiquidity { parent },
            37 => Self::TransferLiquidity { definition },
            38 => Self::RegisterPools,
            39 => Self::SettlePool,
            40 => Self::RefundMarket { definition },
            41 => Self::ResetPool,
            42 => Self::ClaimLiquidity { definition },
            43 => Self::ClaimSwap,
            48 => Self::CreateLaunch {
                funding_input,
                definition,
            },
            49 => Self::LaunchRequest { parent },
            50 => Self::RegisterLaunches,
            51 => Self::SettleLaunch,
            52 => Self::RefundLaunch,
            53 => Self::ResetLaunch,
            64 => Self::CreateListing { definition },
            65 => Self::Purchase { parent },
            66 => Self::CancelListing,
            67 => Self::CreateOffer { funding_input },
            68 => Self::AcceptOffer,
            69 => Self::CancelOffer,
            70 => Self::RegisterListings,
            71 => Self::SettleListing,
            72 => Self::ResetListing,
            73 => Self::RecoverListing,
            74 => Self::RefundPurchase,
            75 => Self::RefundOffer,
            80 => Self::ExecuteTrades {
                commitment: operand.owner,
            },
            _ => return Err(FinancialOperationError::Code),
        };
        if value.operand()? != operand {
            return Err(FinancialOperationError::Operand);
        }
        Ok(value)
    }
}
