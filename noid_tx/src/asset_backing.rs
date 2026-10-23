// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact integer backing calculations for native fungible assets.

pub const MIN_BACKING_MICRONOID_PER_TOKEN: u64 = 1_000;
pub const MAX_TOKEN_DECIMALS: u8 = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenDenomination {
    decimals: u8,
    units_per_token: u64,
}

impl TokenDenomination {
    pub fn new(decimals: u8) -> Result<Self, BackingError> {
        if decimals > MAX_TOKEN_DECIMALS {
            return Err(BackingError::UnsupportedPrecision);
        }
        Ok(Self {
            decimals,
            units_per_token: 10u64.pow(u32::from(decimals)),
        })
    }

    pub const fn decimals(self) -> u8 {
        self.decimals
    }

    pub const fn units_per_token(self) -> u64 {
        self.units_per_token
    }

    pub fn minimum_backing(self, supply_units: u64) -> Result<u64, BackingError> {
        ceil_ratio(
            u128::from(MIN_BACKING_MICRONOID_PER_TOKEN) * u128::from(supply_units),
            u128::from(self.units_per_token),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackingState {
    denomination: TokenDenomination,
    reserve_micronoid: u64,
    supply_units: u64,
    issuance_closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuanceQuote {
    pub deposit_micronoid: u64,
    pub next: BackingState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedemptionQuote {
    pub payout_micronoid: u64,
    pub next: BackingState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackingError {
    UnsupportedPrecision,
    BelowMinimum,
    EmptySupplyHasReserve,
    NoOutstandingSupply,
    ZeroAmount,
    ExcessRedemption,
    SupplyAlreadyIssued,
    ReserveOverflow,
}

impl BackingState {
    pub fn new(
        denomination: TokenDenomination,
        reserve_micronoid: u64,
        supply_units: u64,
    ) -> Result<Self, BackingError> {
        if supply_units == 0 {
            if reserve_micronoid != 0 {
                return Err(BackingError::EmptySupplyHasReserve);
            }
        } else if u128::from(reserve_micronoid) * u128::from(denomination.units_per_token)
            < u128::from(MIN_BACKING_MICRONOID_PER_TOKEN) * u128::from(supply_units)
        {
            return Err(BackingError::BelowMinimum);
        }
        Ok(Self {
            denomination,
            reserve_micronoid,
            supply_units,
            issuance_closed: supply_units != 0,
        })
    }

    pub const fn denomination(self) -> TokenDenomination {
        self.denomination
    }

    pub const fn reserve_micronoid(self) -> u64 {
        self.reserve_micronoid
    }

    pub const fn supply_units(self) -> u64 {
        self.supply_units
    }

    pub fn quote_initial_issuance(self, minted_units: u64) -> Result<IssuanceQuote, BackingError> {
        if minted_units == 0 {
            return Err(BackingError::ZeroAmount);
        }
        if self.issuance_closed {
            return Err(BackingError::SupplyAlreadyIssued);
        }
        let deposit_micronoid = self.denomination.minimum_backing(minted_units)?;
        Ok(IssuanceQuote {
            deposit_micronoid,
            next: Self::new(self.denomination, deposit_micronoid, minted_units)?,
        })
    }

    pub fn quote_redemption(self, burned_units: u64) -> Result<RedemptionQuote, BackingError> {
        if burned_units == 0 {
            return Err(BackingError::ZeroAmount);
        }
        if burned_units > self.supply_units {
            return Err(BackingError::ExcessRedemption);
        }
        let payout_micronoid = (u128::from(self.reserve_micronoid) * u128::from(burned_units)
            / u128::from(self.supply_units)) as u64;
        let mut next = Self::new(
            self.denomination,
            self.reserve_micronoid - payout_micronoid,
            self.supply_units - burned_units,
        )?;
        next.issuance_closed = self.issuance_closed;
        Ok(RedemptionQuote {
            payout_micronoid,
            next,
        })
    }

    pub fn quote_top_up(self, contribution_micronoid: u64) -> Result<Self, BackingError> {
        if contribution_micronoid == 0 {
            return Err(BackingError::ZeroAmount);
        }
        if self.supply_units == 0 {
            return Err(BackingError::NoOutstandingSupply);
        }
        let next_reserve = self
            .reserve_micronoid
            .checked_add(contribution_micronoid)
            .ok_or(BackingError::ReserveOverflow)?;
        Self::new(self.denomination, next_reserve, self.supply_units)
    }
}

fn ceil_ratio(numerator: u128, denominator: u128) -> Result<u64, BackingError> {
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    u64::try_from(quotient + u128::from(remainder != 0)).map_err(|_| BackingError::ReserveOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_is_per_whole_token_at_every_supported_precision() {
        for decimals in 0..=MAX_TOKEN_DECIMALS {
            let denomination = TokenDenomination::new(decimals).unwrap();
            assert_eq!(denomination.decimals(), decimals);
            assert_eq!(
                denomination.minimum_backing(denomination.units_per_token()),
                Ok(1_000)
            );
            assert_eq!(denomination.minimum_backing(0), Ok(0));
        }
        assert_eq!(
            TokenDenomination::new(19),
            Err(BackingError::UnsupportedPrecision)
        );
    }

    #[test]
    fn a_million_whole_tokens_require_a_thousand_noid() {
        let denomination = TokenDenomination::new(6).unwrap();
        let empty = BackingState::new(denomination, 0, 0).unwrap();
        let quote = empty.quote_initial_issuance(1_000_000_000_000).unwrap();
        assert_eq!(quote.deposit_micronoid, 1_000_000_000);
        assert_eq!(quote.next.supply_units(), 1_000_000_000_000);
        assert_eq!(
            BackingState::new(denomination, 999_999_999, 1_000_000_000_000),
            Err(BackingError::BelowMinimum)
        );
    }

    #[test]
    fn fractional_units_require_real_integer_backing() {
        let denomination = TokenDenomination::new(6).unwrap();
        assert_eq!(denomination.minimum_backing(1), Ok(1));
        let state = BackingState::new(denomination, 1, 1).unwrap();
        assert_eq!(
            state.quote_initial_issuance(1),
            Err(BackingError::SupplyAlreadyIssued)
        );
    }

    #[test]
    fn issued_supply_cannot_be_increased() {
        let denomination = TokenDenomination::new(3).unwrap();
        let state = BackingState::new(denomination, 10, 3).unwrap();
        assert_eq!(
            state.quote_initial_issuance(1),
            Err(BackingError::SupplyAlreadyIssued)
        );
        let topped_up = state.quote_top_up(5).unwrap();
        assert_eq!(topped_up.reserve_micronoid(), 15);
        assert_eq!(topped_up.supply_units(), 3);
        assert_eq!(
            topped_up.quote_initial_issuance(1),
            Err(BackingError::SupplyAlreadyIssued)
        );
    }

    #[test]
    fn redemption_preserves_residue_for_the_remaining_units() {
        let denomination = TokenDenomination::new(3).unwrap();
        let state = BackingState::new(denomination, 10, 3).unwrap();
        let first = state.quote_redemption(1).unwrap();
        assert_eq!(first.payout_micronoid, 3);
        assert_eq!(first.next.reserve_micronoid(), 7);
        let last = first.next.quote_redemption(2).unwrap();
        assert_eq!(last.payout_micronoid, 7);
        assert_eq!(last.next.reserve_micronoid(), 0);
        assert_eq!(last.next.supply_units(), 0);
        assert_eq!(
            last.next.quote_initial_issuance(3),
            Err(BackingError::SupplyAlreadyIssued)
        );
    }

    #[test]
    fn final_redemption_empties_a_maximum_sized_reserve() {
        let denomination = TokenDenomination::new(3).unwrap();
        let state = BackingState::new(denomination, u64::MAX, u64::MAX).unwrap();
        let quote = state.quote_redemption(u64::MAX).unwrap();
        assert_eq!(quote.payout_micronoid, u64::MAX);
        assert_eq!(quote.next.reserve_micronoid(), 0);
        assert_eq!(quote.next.supply_units(), 0);
        assert_eq!(
            quote.next.quote_initial_issuance(1),
            Err(BackingError::SupplyAlreadyIssued)
        );
    }

    #[test]
    fn empty_zero_excess_and_overflow_cases_are_explicit() {
        let denomination = TokenDenomination::new(3).unwrap();
        let empty = BackingState::new(denomination, 0, 0).unwrap();
        assert_eq!(
            BackingState::new(denomination, 1, 0),
            Err(BackingError::EmptySupplyHasReserve)
        );
        assert_eq!(
            empty.quote_initial_issuance(0),
            Err(BackingError::ZeroAmount)
        );
        assert_eq!(empty.quote_redemption(0), Err(BackingError::ZeroAmount));
        assert_eq!(
            empty.quote_redemption(1),
            Err(BackingError::ExcessRedemption)
        );
        assert_eq!(
            empty.quote_top_up(1),
            Err(BackingError::NoOutstandingSupply)
        );
        let maximum = BackingState::new(denomination, u64::MAX, u64::MAX).unwrap();
        assert_eq!(
            maximum.quote_initial_issuance(1),
            Err(BackingError::SupplyAlreadyIssued)
        );
        assert_eq!(maximum.quote_top_up(1), Err(BackingError::ReserveOverflow));
        let expensive = BackingState::new(denomination, u64::MAX, 1).unwrap();
        assert_eq!(
            expensive.quote_initial_issuance(1),
            Err(BackingError::SupplyAlreadyIssued)
        );
        assert_eq!(
            TokenDenomination::new(0).unwrap().minimum_backing(u64::MAX),
            Err(BackingError::ReserveOverflow)
        );
    }

    #[test]
    fn quoted_transitions_preserve_backing_and_exact_amounts() {
        for decimals in [0, 3, 6, 12, 18] {
            let denomination = TokenDenomination::new(decimals).unwrap();
            for supply in [1, 2, 3, 7, 31, 257, 65_537] {
                let minimum = denomination.minimum_backing(supply).unwrap();
                for extra in [0, 1, 13, 1_000_000] {
                    let state = BackingState::new(denomination, minimum + extra, supply).unwrap();
                    for minted in [1, 2, 17, 131] {
                        assert_eq!(
                            state.quote_initial_issuance(minted),
                            Err(BackingError::SupplyAlreadyIssued)
                        );
                        let initial = BackingState::new(denomination, 0, 0)
                            .unwrap()
                            .quote_initial_issuance(minted)
                            .unwrap();
                        let paid = u128::from(initial.deposit_micronoid);
                        let scale = u128::from(denomination.units_per_token());
                        let required =
                            u128::from(MIN_BACKING_MICRONOID_PER_TOKEN) * u128::from(minted);
                        assert!(paid * scale >= required);
                        assert!((paid - 1) * scale < required);
                    }
                    for burned in [1, supply.div_ceil(2), supply] {
                        let quote = state.quote_redemption(burned).unwrap();
                        assert_eq!(
                            state.reserve_micronoid(),
                            quote.next.reserve_micronoid() + quote.payout_micronoid
                        );
                        assert_eq!(supply, quote.next.supply_units() + burned);
                        if quote.next.supply_units() > 0 {
                            assert!(
                                u128::from(quote.next.reserve_micronoid()) * u128::from(supply)
                                    >= u128::from(state.reserve_micronoid())
                                        * u128::from(quote.next.supply_units())
                            );
                        }
                    }
                }
            }
        }
    }
}
