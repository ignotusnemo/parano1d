// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical financial contexts and complete block registration extraction.

use crate::state::native_assets::{market::liquidity::MarketFeeContext, NativeCreatedOpening};
use crate::{BlockHeader, ChainState, SlotValue};
use noid_poseidon2b::primitives::Address;
use noid_tx::native_assets::{
    financial::{
        owner::{check_financial_owner, FinancialOwnerError},
        public::{
            check_financial_public, FinancialPublicContext, FinancialPublicError,
            FinancialPublicFacts, FinancialRegistration,
        },
        FinancialOperation, NativeParentRef,
    },
    launch::{queue::LaunchRequestRef, LaunchOpening},
    market::{
        queue::{MarketRequestRef, MAX_ROUND_REQUESTS},
        request::MarketRequest,
        MarketOpening,
    },
    nft_market::{queue::FundedPurchaseRef, NftMarketOpening, NftRoundContext},
    transition::{NativeContext, NativeInputClaim, NativeOutputClaim, NativeTransitionFacts},
    NativeOpening, NATIVE_SEQUENCE_MAX,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinancialBlockError {
    Context,
    Read,
    Fee,
    Registration,
    Order,
    Owner(FinancialOwnerError),
    Public(FinancialPublicError),
}
impl core::fmt::Display for FinancialBlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "financial block: {self:?}")
    }
}
impl std::error::Error for FinancialBlockError {}

/// Recent verified canonical headers, newest first. Their nonce-including ids
/// bind admission and the original NFT registration context to the parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinancialHeaderWindow {
    headers: Vec<BlockHeader>,
}
impl FinancialHeaderWindow {
    pub fn new(
        parent: BlockHeader,
        ancestors: &[BlockHeader],
    ) -> Result<Self, FinancialBlockError> {
        if ancestors.len() > 3 {
            return Err(FinancialBlockError::Context);
        }
        let headers: Vec<_> = std::iter::once(parent)
            .chain(ancestors.iter().copied())
            .collect();
        for h in &headers {
            if !(1..=32).contains(&h.log_slots)
                || h.active_slot_count > 1u64 << h.log_slots
                || h.alloc_counter > NATIVE_SEQUENCE_MAX
            {
                return Err(FinancialBlockError::Context);
            }
        }
        for pair in headers.windows(2) {
            if pair[1].height.checked_add(1) != Some(pair[0].height)
                || crate::block_id(&pair[1]) != pair[0].prev_block_hash
            {
                return Err(FinancialBlockError::Context);
            }
        }
        Ok(Self { headers })
    }
    pub fn parent(&self) -> &BlockHeader {
        &self.headers[0]
    }
    pub fn headers(&self) -> &[BlockHeader] {
        &self.headers
    }
    pub fn round_at(&self, height: u64) -> Result<NftRoundContext, FinancialBlockError> {
        let parent = self
            .headers
            .iter()
            .find(|h| h.height.checked_add(1) == Some(height))
            .ok_or(FinancialBlockError::Context)?;
        NftRoundContext::new(height, crate::block_id(parent), parent.alloc_counter)
            .map_err(|_| FinancialBlockError::Context)
    }
    pub(crate) fn check_parent(
        &self,
        state: &ChainState,
        child: &BlockHeader,
    ) -> Result<NftRoundContext, FinancialBlockError> {
        let p = self.parent();
        if p.height.checked_add(1) != Some(child.height)
            || crate::block_id(p) != child.prev_block_hash
            || state.alloc_counter != p.alloc_counter
            || state.active_slot_count != p.active_slot_count
            || state.state.log_slots() != p.log_slots as usize
        {
            return Err(FinancialBlockError::Context);
        }
        let mut exact = state.clone();
        if exact
            .try_state_root()
            .map_err(|_| FinancialBlockError::Context)?
            != p.state_root
        {
            return Err(FinancialBlockError::Context);
        }
        self.round_at(child.height)
    }
    fn check_read(
        &self,
        state: &ChainState,
        parent: NativeParentRef,
        opening: NativeOpening,
    ) -> Result<(), FinancialBlockError> {
        parent
            .check_boundary(self.parent().alloc_counter)
            .map_err(|_| FinancialBlockError::Read)?;
        if opening.root() != parent.root
            || opening.validate().is_err()
            || u64::from(parent.slot_index) >= state.num_slots()
            || state
                .state
                .is_evicted((parent.slot_index >> state.state.effective_log_segment_size()) as u16)
        {
            return Err(FinancialBlockError::Read);
        }
        let expected = SlotValue::with_owner_fields(
            opening.amount_micronoid(),
            parent.creation_id,
            parent.root.as_fields(),
        );
        if state.state.slot(parent.slot_index) != expected {
            return Err(FinancialBlockError::Read);
        }
        Ok(())
    }
    pub(crate) fn check_owner(
        &self,
        parent_state: &ChainState,
        context: &NativeContext,
        operation: FinancialOperation,
        inputs: &[NativeInputClaim],
        outputs: &[NativeOutputClaim],
        mut resolve: impl FnMut(Address) -> Option<NativeOpening>,
    ) -> Result<NativeTransitionFacts, FinancialBlockError> {
        let fee = MarketFeeContext::from_parent(self.parent())
            .required(inputs.len(), outputs.len())
            .map_err(|_| FinancialBlockError::Fee)?;
        if context.fee != fee {
            return Err(FinancialBlockError::Fee);
        }
        if let Some(parent) = operation.parent() {
            self.check_read(
                parent_state,
                parent,
                resolve(parent.root).ok_or(FinancialBlockError::Read)?,
            )?;
        }
        check_financial_owner(
            context,
            self.round_at(context.height)?,
            operation,
            inputs,
            outputs,
            resolve,
        )
        .map_err(FinancialBlockError::Owner)
    }
    pub(crate) fn check_public(
        &self,
        parent_state: &ChainState,
        context: &NativeContext,
        operation: FinancialOperation,
        inputs: &[NativeInputClaim],
        outputs: &[NativeOutputClaim],
        registrations: &[FinancialRegistration],
        resolve: impl FnMut(Address) -> Option<NativeOpening>,
    ) -> Result<FinancialPublicFacts, FinancialBlockError> {
        if is_registration(operation) {
            for c in inputs {
                let reference = NativeParentRef {
                    slot_index: c.input.slot_index,
                    creation_id: c.input.creation_id,
                    root: c.root,
                };
                self.check_read(
                    parent_state,
                    reference,
                    c.opening.ok_or(FinancialBlockError::Read)?,
                )?;
            }
        }
        let required_fee = MarketFeeContext::from_parent(self.parent())
            .required(inputs.len(), outputs.len())
            .map_err(|_| FinancialBlockError::Fee)?;
        let listing_round = if operation == FinancialOperation::SettleListing {
            let height = inputs
                .iter()
                .find_map(|c| match c.opening {
                    Some(NativeOpening::NftMarket(NftMarketOpening::Listing(s))) => {
                        Some(s.registered_height)
                    }
                    _ => None,
                })
                .ok_or(FinancialBlockError::Context)?;
            Some(self.round_at(height)?)
        } else {
            None
        };
        let public = FinancialPublicContext {
            round: self.round_at(context.height)?,
            required_fee,
            listing_round,
            registrations,
        };
        check_financial_public(context, operation, inputs, outputs, &public, resolve)
            .map_err(FinancialBlockError::Public)
    }
}

pub(crate) fn is_registration(operation: FinancialOperation) -> bool {
    matches!(
        operation,
        FinancialOperation::RegisterPools
            | FinancialOperation::RegisterLaunches
            | FinancialOperation::RegisterListings
    )
}

#[derive(Default)]
pub(crate) struct FinancialBlockTracker {
    pending: BTreeMap<u16, Vec<FinancialRegistration>>,
    last_registration: Option<u16>,
}
impl FinancialBlockTracker {
    /// Registration groups form an ascending family suffix after all funding.
    pub(crate) fn begin_group(
        &mut self,
        operation: Option<FinancialOperation>,
    ) -> Result<Vec<FinancialRegistration>, FinancialBlockError> {
        if let Some(op) = operation.filter(|&op| is_registration(op)) {
            let code = op.code();
            if self
                .last_registration
                .is_some_and(|previous| code <= previous)
            {
                return Err(FinancialBlockError::Order);
            }
            self.last_registration = Some(code);
            self.pending
                .remove(&code)
                .filter(|r| !r.is_empty())
                .ok_or(FinancialBlockError::Registration)
        } else if self.last_registration.is_some() {
            Err(FinancialBlockError::Order)
        } else {
            Ok(Vec::new())
        }
    }
    pub(crate) fn owner_outputs(
        &mut self,
        operation: FinancialOperation,
        outputs: &[NativeCreatedOpening],
    ) -> Result<(), FinancialBlockError> {
        if matches!(operation, FinancialOperation::Purchase { .. }) {
            return Ok(());
        }
        let Some(parent) = operation.parent() else {
            return Ok(());
        };
        let mut added = 0;
        for &out in outputs {
            let slot_index = out.slot_index;
            let creation_id = out.creation_id;
            use FinancialOperation::*;
            let registration = match (operation, out.opening) {
                (Swap { .. }, NativeOpening::Market(MarketOpening::Request(r))) => {
                    Some(FinancialRegistration::Market {
                        parent,
                        request: MarketRequestRef {
                            slot_index,
                            creation_id,
                            request: MarketRequest::Swap(r),
                        },
                    })
                }
                (
                    DepositLiquidity { .. },
                    NativeOpening::Market(MarketOpening::LiquidityDeposit(r)),
                ) => Some(FinancialRegistration::Market {
                    parent,
                    request: MarketRequestRef {
                        slot_index,
                        creation_id,
                        request: MarketRequest::Deposit(r),
                    },
                }),
                (
                    WithdrawLiquidity { .. },
                    NativeOpening::Market(MarketOpening::LiquidityWithdrawal(r)),
                ) => Some(FinancialRegistration::Market {
                    parent,
                    request: MarketRequestRef {
                        slot_index,
                        creation_id,
                        request: MarketRequest::Withdraw(r),
                    },
                }),
                (BurnLiquidity { .. }, NativeOpening::Market(MarketOpening::LiquidityBurn(r))) => {
                    Some(FinancialRegistration::Market {
                        parent,
                        request: MarketRequestRef {
                            slot_index,
                            creation_id,
                            request: MarketRequest::Burn(r),
                        },
                    })
                }
                (LaunchRequest { .. }, NativeOpening::Launch(LaunchOpening::Request(request))) => {
                    Some(FinancialRegistration::Launch {
                        parent,
                        request: LaunchRequestRef {
                            slot_index,
                            creation_id,
                            request,
                        },
                    })
                }
                (
                    Purchase { .. },
                    NativeOpening::NftMarket(NftMarketOpening::Purchase(request)),
                ) => Some(FinancialRegistration::Listing {
                    parent,
                    request: FundedPurchaseRef {
                        slot_index,
                        creation_id,
                        request,
                    },
                }),
                _ => None,
            };
            if let Some(r) = registration {
                let list = self
                    .pending
                    .entry(r.registration_operation().code())
                    .or_default();
                if list.len() >= MAX_ROUND_REQUESTS {
                    return Err(FinancialBlockError::Registration);
                }
                list.push(r);
                added += 1;
            }
        }
        if added != 1 {
            return Err(FinancialBlockError::Registration);
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<(), FinancialBlockError> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(FinancialBlockError::Registration)
        }
    }
}
