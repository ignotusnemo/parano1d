// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Owner-authorized funding and movement of native market rights.

use super::{MarketDefinition, MarketError, MarketOpening, PoolState, NOID_ASSET};
use crate::native_assets::{
    native_sequence,
    transition::{NativeContext, NativeInputClaim, NativeOutputClaim},
    GenesisAnchor, NativeOpening, NATIVE_CREATION_TAG,
};
use noid_poseidon2b::primitives::Address;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketOwnerOperation {
    Bootstrap {
        funding_input: u16,
        base: u64,
        quote: u64,
    },
    Swap,
    Deposit,
    Withdraw,
    Burn,
    Transfer,
}

pub fn check_owned_market_operation(
    context: &NativeContext,
    definition: MarketDefinition,
    parent: Option<PoolState>,
    operation: MarketOwnerOperation,
    inputs: &[NativeInputClaim],
    outputs: &[NativeOutputClaim],
) -> Result<(), MarketError> {
    definition.validate()?;
    if context.chain == [0; 32] || context.authority == Address([0; 32]) {
        return Err(MarketError::Owner);
    }
    if inputs.is_empty()
        || inputs.len() > crate::MAX_PAGED_SPEND_INPUTS
        || outputs.is_empty()
        || outputs.len() > crate::MAX_PAGED_SPEND_OUTPUTS
    {
        return Err(MarketError::Capacity);
    }
    let mut slots = BTreeSet::new();
    let mut noid_in = 0u128;
    let mut noid_out = u128::from(context.fee);
    let mut token_in = BTreeMap::new();
    let mut token_out = BTreeMap::new();
    let mut lp_in = 0u128;
    let mut lp_out = 0u128;
    for claim in inputs {
        if !slots.insert(claim.input.slot_index) {
            return Err(MarketError::Duplicate);
        }
        if let Some(opening) = claim.opening {
            opening
                .check_input(&claim.input, claim.root, context.height)
                .map_err(|_| MarketError::Funding)?;
            match opening {
                NativeOpening::TokenBalance(b)
                    if b.owner == context.authority
                        && matches!(
                            operation,
                            MarketOwnerOperation::Bootstrap { .. }
                                | MarketOwnerOperation::Deposit
                                | MarketOwnerOperation::Swap
                        ) =>
                {
                    if b.asset != definition.base && b.asset != definition.quote {
                        return Err(MarketError::Pool);
                    }
                    *token_in.entry(b.asset).or_insert(0u128) += u128::from(b.units);
                }
                NativeOpening::Market(MarketOpening::Liquidity(p))
                    if p.owner == context.authority
                        && p.pool == definition.id()
                        && context.height >= p.unlock_height
                        && matches!(
                            operation,
                            MarketOwnerOperation::Withdraw
                                | MarketOwnerOperation::Burn
                                | MarketOwnerOperation::Transfer
                        ) =>
                {
                    lp_in += u128::from(p.shares);
                }
                _ => return Err(MarketError::Owner),
            }
        } else {
            let id = claim.input.creation_id;
            if id == 0
                || native_sequence(id).is_ok()
                || (id >= NATIVE_CREATION_TAG && id & (1 << 63) == 0)
                || claim.root != context.authority
            {
                return Err(MarketError::Funding);
            }
        }
        noid_in += u128::from(claim.input.amount);
    }
    let mut swap = None;
    let mut deposit = None;
    let mut withdrawal = None;
    let mut burn = None;
    let mut pool = None;
    for claim in outputs {
        if !slots.insert(claim.output.slot_index) {
            return Err(MarketError::Duplicate);
        }
        if let Some(opening) = claim.opening {
            opening
                .check_output(&claim.output)
                .map_err(|_| MarketError::Funding)?;
            match opening {
                NativeOpening::TokenBalance(b)
                    if b.owner == context.authority
                        && matches!(
                            operation,
                            MarketOwnerOperation::Bootstrap { .. }
                                | MarketOwnerOperation::Deposit
                                | MarketOwnerOperation::Swap
                        ) =>
                {
                    if b.asset != definition.base && b.asset != definition.quote {
                        return Err(MarketError::Pool);
                    }
                    *token_out.entry(b.asset).or_insert(0u128) += u128::from(b.units);
                }
                NativeOpening::Market(MarketOpening::Liquidity(p))
                    if p.pool == definition.id()
                        && (matches!(operation, MarketOwnerOperation::Transfer)
                            || p.owner == context.authority) =>
                {
                    lp_out += u128::from(p.shares);
                }
                NativeOpening::Market(MarketOpening::Pool(p))
                    if matches!(operation, MarketOwnerOperation::Bootstrap { .. })
                        && pool.is_none() =>
                {
                    pool = Some(p);
                }
                NativeOpening::Market(MarketOpening::Request(r))
                    if matches!(operation, MarketOwnerOperation::Swap)
                        && swap.is_none()
                        && r.owner == context.authority =>
                {
                    swap = Some(r);
                }
                NativeOpening::Market(MarketOpening::LiquidityDeposit(d))
                    if matches!(operation, MarketOwnerOperation::Deposit)
                        && deposit.is_none()
                        && d.owner == context.authority =>
                {
                    deposit = Some(d);
                }
                NativeOpening::Market(MarketOpening::LiquidityWithdrawal(w))
                    if matches!(operation, MarketOwnerOperation::Withdraw)
                        && withdrawal.is_none()
                        && w.owner == context.authority =>
                {
                    withdrawal = Some(w);
                }
                NativeOpening::Market(MarketOpening::LiquidityBurn(b))
                    if matches!(operation, MarketOwnerOperation::Burn)
                        && burn.is_none()
                        && b.owner == context.authority =>
                {
                    burn = Some(b);
                }
                _ => return Err(MarketError::Funding),
            }
        } else if claim.output.owner != context.authority || claim.output.amount == 0 {
            return Err(MarketError::Owner);
        }
        noid_out += u128::from(claim.output.amount);
    }
    let principal = match operation {
        MarketOwnerOperation::Bootstrap {
            funding_input,
            base,
            quote,
        } => {
            if parent.is_some() {
                return Err(MarketError::Pool);
            }
            let funding = inputs
                .get(usize::from(funding_input))
                .ok_or(MarketError::Anchor)?;
            if funding.opening.is_some() {
                return Err(MarketError::Anchor);
            }
            let expected = MarketDefinition::from_genesis(
                &GenesisAnchor {
                    chain: context.chain,
                    owner: context.authority,
                    input: funding.input,
                },
                definition.base,
                definition.quote,
            )?;
            if expected != definition {
                return Err(MarketError::Anchor);
            }
            let initial = PoolState::bootstrap(definition, base, quote)?;
            if pool != Some(initial)
                || lp_in != 0
                || lp_out != u128::from(initial.total_shares - initial.locked_shares)
            {
                return Err(MarketError::Conservation);
            }
            [base, quote]
        }
        MarketOwnerOperation::Swap => {
            let swap = swap.ok_or(MarketError::Funding)?;
            swap.check_round(definition, parent.ok_or(MarketError::Pool)?, context.height)?;
            if lp_in != 0 || lp_out != 0 {
                return Err(MarketError::Conservation);
            }
            if swap.input_asset == definition.base {
                [swap.gross_input, 0]
            } else {
                [0, swap.gross_input]
            }
        }
        MarketOwnerOperation::Deposit => {
            let deposit = deposit.ok_or(MarketError::Funding)?;
            deposit.check_round(definition, parent.ok_or(MarketError::Pool)?, context.height)?;
            if lp_in != 0 || lp_out != 0 {
                return Err(MarketError::Conservation);
            }
            [deposit.max_base, deposit.max_quote]
        }
        MarketOwnerOperation::Withdraw => {
            let withdrawal = withdrawal.ok_or(MarketError::Funding)?;
            withdrawal.check_round(definition, parent.ok_or(MarketError::Pool)?, context.height)?;
            if lp_out + u128::from(withdrawal.shares) != lp_in {
                return Err(MarketError::Conservation);
            }
            [0, 0]
        }
        MarketOwnerOperation::Burn => {
            let burn = burn.ok_or(MarketError::Funding)?;
            burn.check_round(definition, parent.ok_or(MarketError::Pool)?, context.height)?;
            if lp_out + u128::from(burn.shares) != lp_in {
                return Err(MarketError::Conservation);
            }
            [0, 0]
        }
        MarketOwnerOperation::Transfer => {
            if parent.is_some() || lp_in == 0 || lp_in != lp_out {
                return Err(MarketError::Conservation);
            }
            [0, 0]
        }
    };
    for (asset, amount) in [
        (definition.base, principal[0]),
        (definition.quote, principal[1]),
    ] {
        if asset != NOID_ASSET && amount != 0 {
            *token_out.entry(asset).or_insert(0) += u128::from(amount);
        }
    }
    if noid_in != noid_out || token_in != token_out {
        return Err(MarketError::Conservation);
    }
    Ok(())
}
