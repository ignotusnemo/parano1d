// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical market rights and complete registration batches.

pub mod clearing;
pub mod limits;
pub mod liquidity;
pub mod mixed;
pub mod owner;
pub mod queue;
pub mod request;
pub mod sequential;

pub use liquidity::{LiquidityBurn, LiquidityClaim, LiquidityDeposit, LiquidityWithdrawal};

use noid_core::Block128;
use noid_poseidon2b::{
    native::{capacity_iv, DomainTag, Poseidon2bSponge},
    primitives::{Address, Digest},
};

use super::{
    AssetId, GenesisAnchor, NATIVE_OPENING_HEADER_BYTES, NATIVE_OPENING_MAGIC,
    NATIVE_OPENING_VERSION,
};

pub const MARKET_PROFILE: u64 = 1;
pub const MARKET_FEE_BPS: u64 = 30;
pub const MARKET_REQUEST_FEE_CREDIT: u64 = 100_000;
pub const MARKET_SETTLEMENT_WINDOW: u64 = 4;
pub const MARKET_MIN_LOCKED_SHARES: u64 = 1_000;
pub const MARKET_QUANTITY_MAX: u64 = (1 << 63) - 1;
pub const MARKET_FIELDS: usize = 12;
pub const MAX_MARKET_OPENING_BYTES: usize = NATIVE_OPENING_HEADER_BYTES + 16 * MARKET_FIELDS;
pub const NOID_ASSET: AssetId = AssetId([0; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoolId(pub Digest);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketError {
    Encoding,
    Kind,
    Padding,
    Identifier,
    Owner,
    Quantity,
    Profile,
    Anchor,
    Pool,
    Phase,
    Height,
    Generation,
    Queue,
    Duplicate,
    Funding,
    Capacity,
    Arithmetic,
    Minimum,
    Conservation,
    Fee,
    Clearing,
}

impl core::fmt::Display for MarketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "native market: {self:?}")
    }
}
impl std::error::Error for MarketError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarketDefinition {
    pub genesis: Digest,
    pub base: AssetId,
    pub quote: AssetId,
    pub profile: u64,
}

impl MarketDefinition {
    pub fn from_genesis(
        anchor: &GenesisAnchor,
        first: AssetId,
        second: AssetId,
    ) -> Result<Self, MarketError> {
        anchor.validate().map_err(|_| MarketError::Anchor)?;
        if first == second {
            return Err(MarketError::Identifier);
        }
        let (base, quote) = if first < second {
            (first, second)
        } else {
            (second, first)
        };
        let mut fields = Vec::with_capacity(10);
        fields.extend_from_slice(&Address(anchor.chain).as_fields());
        fields.extend_from_slice(&anchor.owner.as_fields());
        fields.push(crate::pack_amount_creation_id(
            anchor.input.amount,
            anchor.input.creation_id,
        ));
        fields.push(Block128(u128::from(anchor.input.slot_index)));
        fields.extend_from_slice(&base.as_fields());
        fields.extend_from_slice(&quote.as_fields());
        let value = Self {
            genesis: hash_fields(DomainTag::new(b"MKSEED21"), &fields),
            base,
            quote,
            profile: MARKET_PROFILE,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), MarketError> {
        if self.genesis == [0; 32] || self.base >= self.quote {
            return Err(MarketError::Identifier);
        }
        if self.profile != MARKET_PROFILE {
            return Err(MarketError::Profile);
        }
        Ok(())
    }
    pub fn id(self) -> PoolId {
        PoolId(MarketOpening::Definition(self).root().0)
    }
    pub fn base_is_noid(self) -> bool {
        self.base == NOID_ASSET
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PoolPhase {
    Idle = 0,
    Frozen = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundPhase {
    Open,
    Registered,
    Settlement,
    Refund,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolState {
    pub pool: PoolId,
    pub base_reserve: u64,
    pub quote_reserve: u64,
    pub total_shares: u64,
    pub locked_shares: u64,
    pub queue_root: Digest,
    pub generation: u64,
    pub registered_height: u64,
    pub timeout_height: u64,
    pub request_count: u16,
    pub phase: PoolPhase,
    pub base_is_noid: bool,
}

impl PoolState {
    pub fn bootstrap(
        definition: MarketDefinition,
        base: u64,
        quote: u64,
    ) -> Result<Self, MarketError> {
        definition.validate()?;
        quantity(base)?;
        quantity(quote)?;
        let total_shares = integer_sqrt(u128::from(base) * u128::from(quote));
        if total_shares <= MARKET_MIN_LOCKED_SHARES {
            return Err(MarketError::Quantity);
        }
        let value = Self {
            pool: definition.id(),
            base_reserve: base,
            quote_reserve: quote,
            total_shares,
            locked_shares: MARKET_MIN_LOCKED_SHARES,
            queue_root: [0; 32],
            generation: 0,
            registered_height: 0,
            timeout_height: 0,
            request_count: 0,
            phase: PoolPhase::Idle,
            base_is_noid: definition.base_is_noid(),
        };
        value.validate()?;
        Ok(value)
    }
    /// Create permanent bootstrap liquidity without an owner withdrawal right.
    pub fn bootstrap_permanent(
        definition: MarketDefinition,
        base: u64,
        quote: u64,
    ) -> Result<Self, MarketError> {
        let mut value = Self::bootstrap(definition, base, quote)?;
        value.locked_shares = value.total_shares;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), MarketError> {
        if self.pool.0 == [0; 32] {
            return Err(MarketError::Identifier);
        }
        quantity(self.base_reserve)?;
        quantity(self.quote_reserve)?;
        quantity(self.total_shares)?;
        if u128::from(self.total_shares) * u128::from(self.total_shares)
            > u128::from(self.base_reserve) * u128::from(self.quote_reserve)
        {
            return Err(MarketError::Pool);
        }
        if self.locked_shares < MARKET_MIN_LOCKED_SHARES || self.locked_shares > self.total_shares {
            return Err(MarketError::Pool);
        }
        match self.phase {
            PoolPhase::Idle
                if self.queue_root != [0; 32]
                    || self.request_count != 0
                    || self.registered_height != 0
                    || self.timeout_height != 0 =>
            {
                return Err(MarketError::Phase)
            }
            PoolPhase::Frozen
                if self.queue_root == [0; 32]
                    || self.request_count == 0
                    || usize::from(self.request_count) > queue::MAX_ROUND_REQUESTS
                    || self.registered_height == 0
                    || self.registered_height.checked_add(MARKET_SETTLEMENT_WINDOW)
                        != Some(self.timeout_height) =>
            {
                return Err(MarketError::Phase)
            }
            _ => {}
        }
        Ok(())
    }
    pub fn check_definition(self, definition: MarketDefinition) -> Result<(), MarketError> {
        self.validate()?;
        definition.validate()?;
        if self.pool != definition.id() || self.base_is_noid != definition.base_is_noid() {
            return Err(MarketError::Pool);
        }
        Ok(())
    }
    pub fn root(self) -> Address {
        MarketOpening::Pool(self).root()
    }
    pub fn noid_value(self) -> u64 {
        if self.base_is_noid {
            self.base_reserve
        } else {
            0
        }
    }
    pub fn phase_at(self, height: u64) -> Result<RoundPhase, MarketError> {
        self.validate()?;
        match self.phase {
            PoolPhase::Idle => Ok(RoundPhase::Open),
            PoolPhase::Frozen if height < self.registered_height => Err(MarketError::Height),
            PoolPhase::Frozen if height == self.registered_height => Ok(RoundPhase::Registered),
            PoolPhase::Frozen if height < self.timeout_height => Ok(RoundPhase::Settlement),
            PoolPhase::Frozen => Ok(RoundPhase::Refund),
        }
    }
    pub fn idle_view(mut self) -> Self {
        self.queue_root = [0; 32];
        self.registered_height = 0;
        self.timeout_height = 0;
        self.request_count = 0;
        self.phase = PoolPhase::Idle;
        self
    }
    pub fn round_id(self, height: u64) -> Result<Digest, MarketError> {
        self.validate()?;
        if self.phase != PoolPhase::Idle
            || self.generation == u64::MAX
            || height == 0
            || height.checked_add(MARKET_SETTLEMENT_WINDOW).is_none()
        {
            return Err(MarketError::Phase);
        }
        let root = self.root();
        let mut fields = Vec::with_capacity(6);
        fields.extend_from_slice(&Address(self.pool.0).as_fields());
        fields.extend_from_slice(&root.as_fields());
        fields.push(Block128(u128::from(height)));
        fields.push(Block128(0));
        Ok(hash_fields(DomainTag::new(b"MKROUND1"), &fields))
    }
    pub fn frozen_round_id(self) -> Result<Digest, MarketError> {
        self.validate()?;
        if self.phase != PoolPhase::Frozen {
            return Err(MarketError::Phase);
        }
        self.idle_view().round_id(self.registered_height)
    }
    pub fn reset_after_timeout(self, height: u64) -> Result<Self, MarketError> {
        if self.phase_at(height)? != RoundPhase::Refund {
            return Err(MarketError::Phase);
        }
        let mut next = self.idle_view();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(MarketError::Arithmetic)?;
        next.validate()?;
        Ok(next)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapRequest {
    pub round: Digest,
    pub input_asset: AssetId,
    pub output_asset: AssetId,
    pub owner: Address,
    pub recipient: Address,
    pub gross_input: u64,
    /// Output floor for the full effective capacity. Partial execution scales
    /// this floor by its actual effective input, rounding down once.
    pub minimum_output: u64,
    pub registered_height: u64,
    pub profile: u64,
}

impl SwapRequest {
    pub fn validate(self) -> Result<(), MarketError> {
        if self.round == [0; 32] || self.input_asset == self.output_asset {
            return Err(MarketError::Identifier);
        }
        owner(self.owner)?;
        owner(self.recipient)?;
        quantity(self.gross_input)?;
        quantity(self.minimum_output)?;
        if self.profile != MARKET_PROFILE {
            return Err(MarketError::Profile);
        }
        self.timeout_height()?;
        self.noid_value()?;
        if self.effective_input()? == 0 {
            return Err(MarketError::Quantity);
        }
        Ok(())
    }
    pub fn root(self) -> Address {
        MarketOpening::Request(self).root()
    }
    pub fn noid_value(self) -> Result<u64, MarketError> {
        MARKET_REQUEST_FEE_CREDIT
            .checked_add(if self.input_asset == NOID_ASSET {
                self.gross_input
            } else {
                0
            })
            .ok_or(MarketError::Arithmetic)
    }
    pub fn timeout_height(self) -> Result<u64, MarketError> {
        if self.registered_height == 0 {
            return Err(MarketError::Height);
        }
        self.registered_height
            .checked_add(MARKET_SETTLEMENT_WINDOW)
            .ok_or(MarketError::Arithmetic)
    }
    pub fn effective_input(self) -> Result<u64, MarketError> {
        let fee = (u128::from(self.gross_input) * u128::from(MARKET_FEE_BPS)).div_ceil(10_000);
        self.gross_input
            .checked_sub(u64::try_from(fee).map_err(|_| MarketError::Arithmetic)?)
            .ok_or(MarketError::Arithmetic)
    }
    pub fn check_round(
        self,
        definition: MarketDefinition,
        pool: PoolState,
        height: u64,
    ) -> Result<(), MarketError> {
        self.validate()?;
        pool.check_definition(definition)?;
        if self.profile != definition.profile
            || self.registered_height != height
            || self.round != pool.round_id(height)?
        {
            return Err(MarketError::Generation);
        }
        if !((self.input_asset == definition.base && self.output_asset == definition.quote)
            || (self.input_asset == definition.quote && self.output_asset == definition.base))
        {
            return Err(MarketError::Pool);
        }
        Ok(())
    }
    pub fn refundable_at(self, height: u64) -> Result<bool, MarketError> {
        self.validate()?;
        Ok(height >= self.timeout_height()?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapClaim {
    pub request: Digest,
    pub input_asset: AssetId,
    pub output_asset: AssetId,
    pub refund_owner: Address,
    pub recipient: Address,
    pub refund_units: u64,
    pub output_units: u64,
    pub fee_credit: u64,
}
impl SwapClaim {
    pub fn timeout_refund(
        funded: queue::FundedRequestRef,
        height: u64,
        charged_fee: u64,
    ) -> Result<Self, MarketError> {
        funded.validate()?;
        if !funded.request.refundable_at(height)? {
            return Err(MarketError::Phase);
        }
        if charged_fee > clearing::MAX_SETTLEMENT_FEE_PER_REQUEST {
            return Err(MarketError::Fee);
        }
        let request = funded.request;
        let value = Self {
            request: funded.key(),
            input_asset: request.input_asset,
            output_asset: request.output_asset,
            refund_owner: request.owner,
            recipient: request.recipient,
            refund_units: request.gross_input,
            output_units: 0,
            fee_credit: MARKET_REQUEST_FEE_CREDIT - charged_fee,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(self) -> Result<(), MarketError> {
        if self.request == [0; 32] || self.input_asset == self.output_asset {
            return Err(MarketError::Identifier);
        }
        owner(self.refund_owner)?;
        owner(self.recipient)?;
        if self.refund_units > MARKET_QUANTITY_MAX
            || self.output_units > MARKET_QUANTITY_MAX
            || (self.refund_units == 0 && self.output_units == 0)
            || self.fee_credit > MARKET_REQUEST_FEE_CREDIT
        {
            return Err(MarketError::Quantity);
        }
        self.noid_value()?;
        Ok(())
    }
    pub fn noid_value(self) -> Result<u64, MarketError> {
        self.fee_credit
            .checked_add(if self.input_asset == NOID_ASSET {
                self.refund_units
            } else if self.output_asset == NOID_ASSET {
                self.output_units
            } else {
                0
            })
            .ok_or(MarketError::Arithmetic)
    }
    pub fn root(self) -> Address {
        MarketOpening::Claim(self).root()
    }

    /// Release each asset to its committed recipient. Fee credit belongs to
    /// the refund owner and pays only the supplied protocol fee.
    pub fn payouts(self, fee: u64) -> Result<Vec<MarketPayout>, MarketError> {
        self.validate()?;
        if fee >= self.fee_credit {
            return Err(MarketError::Fee);
        }
        let mut payouts = std::collections::BTreeMap::<(AssetId, Digest), u64>::new();
        for (asset, owner, amount) in [
            (self.input_asset, self.refund_owner, self.refund_units),
            (self.output_asset, self.recipient, self.output_units),
            (NOID_ASSET, self.refund_owner, self.fee_credit - fee),
        ] {
            if amount != 0 {
                let value = payouts.entry((asset, owner.0)).or_default();
                *value = value.checked_add(amount).ok_or(MarketError::Arithmetic)?;
            }
        }
        Ok(payouts
            .into_iter()
            .map(|((asset, owner), units)| MarketPayout {
                asset,
                owner: Address(owner),
                units,
            })
            .collect())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarketPayout {
    pub asset: AssetId,
    pub owner: Address,
    pub units: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiquidityPosition {
    pub pool: PoolId,
    pub owner: Address,
    pub shares: u64,
    pub unlock_height: u64,
}
impl LiquidityPosition {
    pub fn validate(self) -> Result<(), MarketError> {
        if self.pool.0 == [0; 32] {
            return Err(MarketError::Identifier);
        }
        owner(self.owner)?;
        quantity(self.shares)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MarketKind {
    Definition = 32,
    Pool = 33,
    Request = 34,
    Claim = 35,
    Liquidity = 36,
    LiquidityDeposit = 37,
    LiquidityWithdrawal = 38,
    LiquidityClaim = 39,
    LiquidityBurn = 40,
}
impl MarketKind {
    pub const fn field_count(self) -> usize {
        match self {
            Self::Definition
            | Self::Pool
            | Self::LiquidityDeposit
            | Self::LiquidityWithdrawal
            | Self::LiquidityClaim
            | Self::LiquidityBurn => 8,
            Self::Request | Self::Claim => 12,
            Self::Liquidity => 6,
        }
    }
    pub const fn tag(self) -> DomainTag {
        DomainTag::new(match self {
            Self::Definition => b"MKDEF_21",
            Self::Pool => b"MKPOOL21",
            Self::Request => b"MKREQ_21",
            Self::Claim => b"MKCLM_21",
            Self::Liquidity => b"MKLP__21",
            Self::LiquidityDeposit => b"MKLPIN21",
            Self::LiquidityWithdrawal => b"MKLPOU21",
            Self::LiquidityClaim => b"MKLPCM21",
            Self::LiquidityBurn => b"MKLPBN21",
        })
    }
    fn decode(n: u16) -> Result<Self, MarketError> {
        match n {
            32 => Ok(Self::Definition),
            33 => Ok(Self::Pool),
            34 => Ok(Self::Request),
            35 => Ok(Self::Claim),
            36 => Ok(Self::Liquidity),
            37 => Ok(Self::LiquidityDeposit),
            38 => Ok(Self::LiquidityWithdrawal),
            39 => Ok(Self::LiquidityClaim),
            40 => Ok(Self::LiquidityBurn),
            _ => Err(MarketError::Kind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketOpening {
    Definition(MarketDefinition),
    Pool(PoolState),
    Request(SwapRequest),
    Claim(SwapClaim),
    Liquidity(LiquidityPosition),
    LiquidityDeposit(LiquidityDeposit),
    LiquidityWithdrawal(LiquidityWithdrawal),
    LiquidityClaim(LiquidityClaim),
    LiquidityBurn(LiquidityBurn),
}
impl MarketOpening {
    pub const fn kind(self) -> MarketKind {
        match self {
            Self::Definition(_) => MarketKind::Definition,
            Self::Pool(_) => MarketKind::Pool,
            Self::Request(_) => MarketKind::Request,
            Self::Claim(_) => MarketKind::Claim,
            Self::Liquidity(_) => MarketKind::Liquidity,
            Self::LiquidityDeposit(_) => MarketKind::LiquidityDeposit,
            Self::LiquidityWithdrawal(_) => MarketKind::LiquidityWithdrawal,
            Self::LiquidityClaim(_) => MarketKind::LiquidityClaim,
            Self::LiquidityBurn(_) => MarketKind::LiquidityBurn,
        }
    }
    pub fn noid_value(self) -> Result<u64, MarketError> {
        match self {
            Self::Pool(p) => Ok(p.noid_value()),
            Self::Request(r) => r.noid_value(),
            Self::Claim(c) => c.noid_value(),
            Self::LiquidityDeposit(d) => d.noid_value(),
            Self::LiquidityWithdrawal(w) => Ok(w.noid_value()),
            Self::LiquidityClaim(c) => c.noid_value(),
            Self::LiquidityBurn(b) => Ok(b.noid_value()),
            Self::Definition(_) | Self::Liquidity(_) => Ok(0),
        }
    }

    pub fn validate(self) -> Result<(), MarketError> {
        match self {
            Self::Definition(v) => v.validate(),
            Self::Pool(v) => v.validate(),
            Self::Request(v) => v.validate(),
            Self::Claim(v) => v.validate(),
            Self::Liquidity(v) => v.validate(),
            Self::LiquidityDeposit(v) => v.validate(),
            Self::LiquidityWithdrawal(v) => v.validate(),
            Self::LiquidityClaim(v) => v.validate(),
            Self::LiquidityBurn(v) => v.validate(),
        }
    }
    pub fn fields(self) -> [Block128; MARKET_FIELDS] {
        let mut f = [Block128(0); MARKET_FIELDS];
        match self {
            Self::Definition(d) => {
                put_digest(&mut f, 0, d.genesis);
                put_digest(&mut f, 2, d.base.0);
                put_digest(&mut f, 4, d.quote.0);
                f[6] = Block128(u128::from(d.profile));
            }
            Self::Pool(p) => {
                put_digest(&mut f, 0, p.pool.0);
                f[2] = pack(p.base_reserve, p.quote_reserve);
                f[3] = pack(p.total_shares, p.locked_shares);
                put_digest(&mut f, 4, p.queue_root);
                f[6] = pack(p.generation, p.registered_height);
                f[7] = Block128(
                    u128::from(p.timeout_height)
                        | ((p.request_count as u128) << 64)
                        | ((p.phase as u128) << 80)
                        | ((p.base_is_noid as u128) << 88),
                );
            }
            Self::Request(r) => {
                put_digest(&mut f, 0, r.round);
                put_digest(&mut f, 2, r.input_asset.0);
                put_digest(&mut f, 4, r.output_asset.0);
                put_digest(&mut f, 6, r.owner.0);
                put_digest(&mut f, 8, r.recipient.0);
                f[10] = pack(r.gross_input, r.minimum_output);
                f[11] = pack(r.registered_height, r.profile);
            }
            Self::Claim(c) => {
                put_digest(&mut f, 0, c.request);
                put_digest(&mut f, 2, c.input_asset.0);
                put_digest(&mut f, 4, c.output_asset.0);
                put_digest(&mut f, 6, c.refund_owner.0);
                put_digest(&mut f, 8, c.recipient.0);
                f[10] = pack(c.refund_units, c.output_units);
                f[11] = Block128(u128::from(c.fee_credit));
            }
            Self::LiquidityDeposit(d) => {
                put_digest(&mut f, 0, d.pool.0);
                put_digest(&mut f, 2, d.round);
                put_digest(&mut f, 4, d.owner.0);
                f[6] = pack(d.max_base, d.max_quote);
                f[7] = pack(
                    d.minimum_shares | ((d.base_is_noid as u64) << 63),
                    d.registered_height,
                );
            }
            Self::LiquidityWithdrawal(w) => {
                put_digest(&mut f, 0, w.pool.0);
                put_digest(&mut f, 2, w.round);
                put_digest(&mut f, 4, w.owner.0);
                f[6] = pack(w.shares, w.registered_height);
                f[7] = pack(w.minimum_base, w.minimum_quote);
            }
            Self::LiquidityClaim(c) => {
                put_digest(&mut f, 0, c.request);
                put_digest(&mut f, 2, c.pool.0);
                put_digest(&mut f, 4, c.owner.0);
                f[6] = pack(c.base_units, c.quote_units);
                f[7] = pack(c.shares, c.fee_credit | ((c.base_is_noid as u64) << 63));
            }
            Self::LiquidityBurn(b) => {
                put_digest(&mut f, 0, b.pool.0);
                put_digest(&mut f, 2, b.round);
                put_digest(&mut f, 4, b.owner.0);
                f[6] = pack(b.shares, b.registered_height);
            }
            Self::Liquidity(p) => {
                put_digest(&mut f, 0, p.pool.0);
                put_digest(&mut f, 2, p.owner.0);
                f[4] = pack(p.shares, p.unlock_height);
            }
        }
        f
    }
    pub fn root(self) -> Address {
        Address(hash_fields(
            self.kind().tag(),
            &self.fields()[..self.kind().field_count()],
        ))
    }
    pub fn to_bytes(self) -> Result<Vec<u8>, MarketError> {
        self.validate()?;
        let mut b =
            Vec::with_capacity(NATIVE_OPENING_HEADER_BYTES + 16 * self.kind().field_count());
        b.extend_from_slice(NATIVE_OPENING_MAGIC);
        b.extend_from_slice(&NATIVE_OPENING_VERSION.to_le_bytes());
        b.extend_from_slice(&(self.kind() as u16).to_le_bytes());
        for f in &self.fields()[..self.kind().field_count()] {
            b.extend_from_slice(&f.0.to_le_bytes())
        }
        Ok(b)
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, MarketError> {
        if b.len() < NATIVE_OPENING_HEADER_BYTES
            || b.len() > MAX_MARKET_OPENING_BYTES
            || &b[..8] != NATIVE_OPENING_MAGIC
            || u16::from_le_bytes(b[8..10].try_into().unwrap()) != NATIVE_OPENING_VERSION
        {
            return Err(MarketError::Encoding);
        }
        let k = MarketKind::decode(u16::from_le_bytes(b[10..12].try_into().unwrap()))?;
        if b.len() != 12 + 16 * k.field_count() {
            return Err(MarketError::Encoding);
        }
        let mut f = [Block128(0); MARKET_FIELDS];
        for (i, raw) in b[12..].chunks_exact(16).enumerate() {
            f[i] = Block128(u128::from_le_bytes(raw.try_into().unwrap()))
        }
        Self::from_fields(k, &f[..k.field_count()])
    }

    pub fn from_fields(k: MarketKind, fields: &[Block128]) -> Result<Self, MarketError> {
        if fields.len() != k.field_count() {
            return Err(MarketError::Encoding);
        }
        let mut f = [Block128(0); MARKET_FIELDS];
        f[..fields.len()].copy_from_slice(fields);
        let v = match k {
            MarketKind::Definition => Self::Definition(MarketDefinition {
                genesis: digest(&f, 0),
                base: AssetId(digest(&f, 2)),
                quote: AssetId(digest(&f, 4)),
                profile: f[6].0 as u64,
            }),
            MarketKind::Pool => Self::Pool(PoolState {
                pool: PoolId(digest(&f, 0)),
                base_reserve: lo(f[2]),
                quote_reserve: hi(f[2]),
                total_shares: lo(f[3]),
                locked_shares: hi(f[3]),
                queue_root: digest(&f, 4),
                generation: lo(f[6]),
                registered_height: hi(f[6]),
                timeout_height: lo(f[7]),
                request_count: (f[7].0 >> 64) as u16,
                phase: match (f[7].0 >> 80) & 255 {
                    0 => PoolPhase::Idle,
                    1 => PoolPhase::Frozen,
                    _ => return Err(MarketError::Phase),
                },
                base_is_noid: (f[7].0 >> 88) & 1 != 0,
            }),
            MarketKind::Request => Self::Request(SwapRequest {
                round: digest(&f, 0),
                input_asset: AssetId(digest(&f, 2)),
                output_asset: AssetId(digest(&f, 4)),
                owner: Address(digest(&f, 6)),
                recipient: Address(digest(&f, 8)),
                gross_input: lo(f[10]),
                minimum_output: hi(f[10]),
                registered_height: lo(f[11]),
                profile: hi(f[11]),
            }),
            MarketKind::Claim => Self::Claim(SwapClaim {
                request: digest(&f, 0),
                input_asset: AssetId(digest(&f, 2)),
                output_asset: AssetId(digest(&f, 4)),
                refund_owner: Address(digest(&f, 6)),
                recipient: Address(digest(&f, 8)),
                refund_units: lo(f[10]),
                output_units: hi(f[10]),
                fee_credit: lo(f[11]),
            }),
            MarketKind::LiquidityDeposit => Self::LiquidityDeposit(LiquidityDeposit {
                pool: PoolId(digest(&f, 0)),
                round: digest(&f, 2),
                owner: Address(digest(&f, 4)),
                max_base: lo(f[6]),
                max_quote: hi(f[6]),
                minimum_shares: lo(f[7]) & MARKET_QUANTITY_MAX,
                base_is_noid: lo(f[7]) >> 63 != 0,
                registered_height: hi(f[7]),
            }),
            MarketKind::LiquidityWithdrawal => Self::LiquidityWithdrawal(LiquidityWithdrawal {
                pool: PoolId(digest(&f, 0)),
                round: digest(&f, 2),
                owner: Address(digest(&f, 4)),
                shares: lo(f[6]),
                registered_height: hi(f[6]),
                minimum_base: lo(f[7]),
                minimum_quote: hi(f[7]),
            }),
            MarketKind::LiquidityClaim => Self::LiquidityClaim(LiquidityClaim {
                request: digest(&f, 0),
                pool: PoolId(digest(&f, 2)),
                owner: Address(digest(&f, 4)),
                base_units: lo(f[6]),
                quote_units: hi(f[6]),
                shares: lo(f[7]),
                fee_credit: hi(f[7]) & MARKET_QUANTITY_MAX,
                base_is_noid: hi(f[7]) >> 63 != 0,
            }),
            MarketKind::LiquidityBurn => Self::LiquidityBurn(LiquidityBurn {
                pool: PoolId(digest(&f, 0)),
                round: digest(&f, 2),
                owner: Address(digest(&f, 4)),
                shares: lo(f[6]),
                registered_height: hi(f[6]),
            }),
            MarketKind::Liquidity => Self::Liquidity(LiquidityPosition {
                pool: PoolId(digest(&f, 0)),
                owner: Address(digest(&f, 2)),
                shares: lo(f[4]),
                unlock_height: hi(f[4]),
            }),
        };
        v.validate()?;
        if v.fields() != f {
            return Err(MarketError::Padding);
        }
        Ok(v)
    }
}

fn quantity(n: u64) -> Result<(), MarketError> {
    if n == 0 || n > MARKET_QUANTITY_MAX {
        Err(MarketError::Quantity)
    } else {
        Ok(())
    }
}
fn owner(a: Address) -> Result<(), MarketError> {
    if a == Address([0; 32]) {
        Err(MarketError::Owner)
    } else {
        Ok(())
    }
}
fn pack(a: u64, b: u64) -> Block128 {
    Block128(u128::from(a) | (u128::from(b) << 64))
}
fn lo(a: Block128) -> u64 {
    a.0 as u64
}
fn hi(a: Block128) -> u64 {
    (a.0 >> 64) as u64
}
fn put_digest(f: &mut [Block128], offset: usize, d: Digest) {
    f[offset..offset + 2].copy_from_slice(&Address(d).as_fields())
}
fn digest(f: &[Block128], i: usize) -> Digest {
    let mut d = [0; 32];
    d[..16].copy_from_slice(&f[i].0.to_le_bytes());
    d[16..].copy_from_slice(&f[i + 1].0.to_le_bytes());
    d
}
pub(crate) fn hash_fields(tag: DomainTag, fields: &[Block128]) -> Digest {
    assert_eq!(fields.len() % 2, 0, "market hash field pairs");
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(tag));
    for p in fields.chunks_exact(2) {
        sponge.absorb_pair(p[0], p[1])
    }
    sponge.finalize_no_pad()
}
fn integer_sqrt(n: u128) -> u64 {
    let mut lo = 0u128;
    let mut hi = 1u128 << 64;
    while lo + 1 < hi {
        let m = (lo + hi) / 2;
        if m * m <= n {
            lo = m
        } else {
            hi = m
        }
    }
    lo as u64
}
