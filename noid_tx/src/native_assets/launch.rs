// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-supply launch custody, curve accounting and exact round identities.

pub mod clearing;
pub mod owner;
pub mod queue;
pub mod sequential;

use super::{
    market::{
        MarketDefinition, PoolPhase, PoolState, RoundPhase, SwapClaim, MARKET_PROFILE,
        MARKET_QUANTITY_MAX, MARKET_REQUEST_FEE_CREDIT, MARKET_SETTLEMENT_WINDOW, NOID_ASSET,
    },
    native_sequence, AssetId, FungibleDefinition, GenesisAnchor, IssuanceRoute, NativeOpening,
    NATIVE_OPENING_HEADER_BYTES, NATIVE_OPENING_MAGIC, NATIVE_OPENING_VERSION, TOKEN_UNITS,
};
use noid_core::Block128;
use noid_poseidon2b::{
    native::{capacity_iv, DomainTag, Poseidon2bSponge},
    primitives::{Address, Digest},
};

pub const LAUNCH_PROFILE: u64 = 1;
pub const LAUNCH_MIN_WHOLE_TOKENS: u64 = 100_000;
pub const LAUNCH_MIN_SUPPLY: u64 = LAUNCH_MIN_WHOLE_TOKENS * TOKEN_UNITS;
pub const LAUNCH_MAX_SUPPLY: u64 = MARKET_QUANTITY_MAX / 900;

pub fn launch_supply_from_whole(tokens: u64) -> Result<u64, LaunchError> {
    let units = tokens
        .checked_mul(TOKEN_UNITS)
        .ok_or(LaunchError::Arithmetic)?;
    validate_supply_units(units)?;
    Ok(units)
}

pub(super) fn validate_supply_units(units: u64) -> Result<(), LaunchError> {
    if !(LAUNCH_MIN_SUPPLY..=LAUNCH_MAX_SUPPLY).contains(&units) || units % TOKEN_UNITS != 0 {
        return Err(LaunchError::Quantity);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaunchId(pub Digest);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchError {
    Encoding,
    Kind,
    Padding,
    Identity,
    Definition,
    Quantity,
    Arithmetic,
    Height,
    Phase,
    Round,
    Funding,
    Fee,
    Queue,
    Capacity,
    Duplicate,
    Clearing,
    Conservation,
}
impl core::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "launch: {self:?}")
    }
}
impl std::error::Error for LaunchError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchPrice {
    /// NOID base units per token base unit are numerator / denominator.
    pub numerator: u64,
    pub denominator: u64,
}
impl LaunchPrice {
    pub fn cost(self, units: u64) -> Result<u64, LaunchError> {
        if self.denominator == 0 {
            return Err(LaunchError::Arithmetic);
        }
        u64::try_from(
            (u128::from(units) * u128::from(self.numerator)).div_ceil(u128::from(self.denominator)),
        )
        .map_err(|_| LaunchError::Arithmetic)
    }
    pub fn proceeds(self, units: u64) -> Result<u64, LaunchError> {
        if self.denominator == 0 {
            return Err(LaunchError::Arithmetic);
        }
        u64::try_from(u128::from(units) * u128::from(self.numerator) / u128::from(self.denominator))
            .map_err(|_| LaunchError::Arithmetic)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchDefinition {
    pub asset: AssetId,
    pub market_genesis: Digest,
    pub initial_supply: u64,
    pub definition_root: Address,
    pub profile: u64,
}
impl LaunchDefinition {
    pub fn from_genesis(
        anchor: &GenesisAnchor,
        token: FungibleDefinition,
    ) -> Result<Self, LaunchError> {
        let expected = FungibleDefinition::from_genesis(
            anchor,
            token.initial_supply,
            IssuanceRoute::Launchpad,
            token.metadata,
        )
        .map_err(|_| LaunchError::Definition)?;
        if token != expected {
            return Err(LaunchError::Definition);
        }
        let market = MarketDefinition::from_genesis(anchor, NOID_ASSET, token.asset)
            .map_err(|_| LaunchError::Definition)?;
        let value = Self {
            asset: token.asset,
            market_genesis: market.genesis,
            initial_supply: token.initial_supply,
            definition_root: NativeOpening::FungibleDefinition(token).root(),
            profile: LAUNCH_PROFILE,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(self) -> Result<(), LaunchError> {
        if self.asset.0 == [0; 32]
            || self.market_genesis == [0; 32]
            || self.definition_root == Address([0; 32])
            || self.profile != LAUNCH_PROFILE
        {
            return Err(LaunchError::Definition);
        }
        validate_supply_units(self.initial_supply)
    }
    pub fn id(self) -> LaunchId {
        LaunchId(LaunchOpening::Definition(self).root().0)
    }
    pub fn market_definition(self) -> MarketDefinition {
        MarketDefinition {
            genesis: self.market_genesis,
            base: NOID_ASSET,
            quote: self.asset,
            profile: MARKET_PROFILE,
        }
    }
    pub fn sale_units(self) -> u64 {
        self.initial_supply / 5 * 3
    }
    pub fn dex_units(self) -> u64 {
        self.initial_supply - self.sale_units()
    }
    pub fn graduation_cash(self) -> u64 {
        self.initial_supply / 250
    }
    pub fn graduation_pool(self) -> Result<PoolState, LaunchError> {
        self.validate()?;
        PoolState::bootstrap_permanent(
            self.market_definition(),
            self.graduation_cash(),
            self.dex_units(),
        )
        .map_err(|_| LaunchError::Definition)
    }
    pub fn curve_cash(self, sold_units: u64) -> Result<u64, LaunchError> {
        self.validate()?;
        curve_cash_for_supply(self.initial_supply, sold_units)
    }
    pub fn after_initial_purchase(self, units: u64) -> Result<sequential::TradeState, LaunchError> {
        let cash = self.curve_cash(units)?;
        if units == self.sale_units() {
            return self.graduation_pool().map(sequential::TradeState::Market);
        }
        let state = LaunchState {
            inventory_units: self.initial_supply - units,
            market_noid: cash,
            ..LaunchState::initial(self)?
        };
        state.check_definition(self)?;
        Ok(sequential::TradeState::Curve(state))
    }
    pub fn average_price(
        self,
        before_sold: u64,
        after_sold: u64,
    ) -> Result<LaunchPrice, LaunchError> {
        self.validate()?;
        if before_sold > self.sale_units() || after_sold > self.sale_units() {
            return Err(LaunchError::Quantity);
        }
        Ok(LaunchPrice {
            numerator: 3 * self.initial_supply + 5 * (before_sold + after_sold),
            denominator: 900 * self.initial_supply,
        })
    }
    pub fn marginal_price(self, sold_units: u64) -> Result<LaunchPrice, LaunchError> {
        self.average_price(sold_units, sold_units)
    }
}

pub fn curve_cash_for_supply(initial_supply: u64, sold_units: u64) -> Result<u64, LaunchError> {
    validate_supply_units(initial_supply)?;
    if sold_units > initial_supply / 5 * 3 {
        return Err(LaunchError::Quantity);
    }
    let s = u128::from(initial_supply);
    let q = u128::from(sold_units);
    u64::try_from((3 * s * q + 5 * q * q).div_ceil(900 * s)).map_err(|_| LaunchError::Arithmetic)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchState {
    pub launch: LaunchId,
    pub inventory_units: u64,
    pub market_noid: u64,
    pub generation: u64,
    pub queue_root: Digest,
    pub registered_height: u64,
    pub timeout_height: u64,
    pub request_count: u16,
    pub phase: PoolPhase,
}
impl LaunchState {
    pub fn initial(definition: LaunchDefinition) -> Result<Self, LaunchError> {
        definition.validate()?;
        Ok(Self {
            launch: definition.id(),
            inventory_units: definition.initial_supply,
            market_noid: 0,
            generation: 0,
            queue_root: [0; 32],
            registered_height: 0,
            timeout_height: 0,
            request_count: 0,
            phase: PoolPhase::Idle,
        })
    }
    pub fn validate(self) -> Result<(), LaunchError> {
        if self.launch.0 == [0; 32]
            || self.inventory_units == 0
            || self.inventory_units > LAUNCH_MAX_SUPPLY
            || self.market_noid > MARKET_QUANTITY_MAX
        {
            return Err(LaunchError::Quantity);
        }
        match self.phase {
            PoolPhase::Idle
                if self.queue_root != [0; 32]
                    || self.registered_height != 0
                    || self.timeout_height != 0
                    || self.request_count != 0 =>
            {
                return Err(LaunchError::Phase)
            }
            PoolPhase::Frozen
                if self.queue_root == [0; 32]
                    || self.registered_height == 0
                    || self.registered_height.checked_add(MARKET_SETTLEMENT_WINDOW)
                        != Some(self.timeout_height)
                    || self.request_count == 0
                    || usize::from(self.request_count)
                        > super::market::queue::MAX_ROUND_REQUESTS =>
            {
                return Err(LaunchError::Phase)
            }
            _ => {}
        }
        Ok(())
    }
    pub fn check_definition(self, d: LaunchDefinition) -> Result<(), LaunchError> {
        self.validate()?;
        d.validate()?;
        if self.launch != d.id()
            || self.inventory_units > d.initial_supply
            || self.inventory_units <= d.dex_units()
            || self.market_noid != d.curve_cash(d.initial_supply - self.inventory_units)?
        {
            return Err(LaunchError::Definition);
        }
        Ok(())
    }
    pub fn root(self) -> Address {
        LaunchOpening::State(self).root()
    }
    pub fn round_id(self, height: u64) -> Result<Digest, LaunchError> {
        self.validate()?;
        if self.phase != PoolPhase::Idle || self.generation == u64::MAX {
            return Err(LaunchError::Phase);
        }
        expiry(height)?;
        let id = Address(self.launch.0).as_fields();
        let root = self.root().as_fields();
        Ok(hash(
            DomainTag::new(b"LNROUND1"),
            &[
                id[0],
                id[1],
                root[0],
                root[1],
                Block128(u128::from(height)),
                Block128(0),
            ],
        ))
    }
    pub fn idle_view(mut self) -> Self {
        self.queue_root = [0; 32];
        self.registered_height = 0;
        self.timeout_height = 0;
        self.request_count = 0;
        self.phase = PoolPhase::Idle;
        self
    }
    pub fn phase_at(self, height: u64) -> Result<RoundPhase, LaunchError> {
        self.validate()?;
        match self.phase {
            PoolPhase::Idle => Ok(RoundPhase::Open),
            PoolPhase::Frozen if height < self.registered_height => Err(LaunchError::Height),
            PoolPhase::Frozen if height == self.registered_height => Ok(RoundPhase::Registered),
            PoolPhase::Frozen if height < self.timeout_height => Ok(RoundPhase::Settlement),
            PoolPhase::Frozen => Ok(RoundPhase::Refund),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LaunchSide {
    Buy = 0,
    Sell = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchRequest {
    pub round: Digest,
    pub asset: AssetId,
    pub owner: Address,
    pub recipient: Address,
    pub quantity: u64,
    /// Maximum NOID cost for a buy, minimum NOID proceeds for a sell.
    pub noid_limit: u64,
    pub registered_height: u64,
    pub side: LaunchSide,
    pub profile: u64,
}
impl LaunchRequest {
    pub fn validate(self) -> Result<(), LaunchError> {
        if self.round == [0; 32]
            || self.asset.0 == [0; 32]
            || self.owner == Address([0; 32])
            || self.recipient == Address([0; 32])
            || self.profile != LAUNCH_PROFILE
        {
            return Err(LaunchError::Identity);
        }
        if self.quantity == 0
            || self.quantity > LAUNCH_MAX_SUPPLY
            || self.noid_limit > MARKET_QUANTITY_MAX
            || (self.side == LaunchSide::Buy && self.noid_limit == 0)
        {
            return Err(LaunchError::Quantity);
        }
        expiry(self.registered_height)?;
        self.noid_value()?;
        Ok(())
    }
    pub fn noid_value(self) -> Result<u64, LaunchError> {
        MARKET_REQUEST_FEE_CREDIT
            .checked_add(if self.side == LaunchSide::Buy {
                self.noid_limit
            } else {
                0
            })
            .ok_or(LaunchError::Arithmetic)
    }
    pub fn root(self) -> Address {
        LaunchOpening::Request(self).root()
    }
    pub fn check_round(
        self,
        definition: LaunchDefinition,
        before: LaunchState,
        height: u64,
    ) -> Result<(), LaunchError> {
        self.validate()?;
        before.check_definition(definition)?;
        if self.asset != definition.asset
            || self.quantity > definition.initial_supply
            || self.round != before.round_id(height)?
            || self.registered_height != height
        {
            return Err(LaunchError::Round);
        }
        Ok(())
    }
    pub fn timeout_claim(
        self,
        key: Digest,
        height: u64,
        fee: u64,
    ) -> Result<SwapClaim, LaunchError> {
        self.validate()?;
        if height < expiry(self.registered_height)? {
            return Err(LaunchError::Phase);
        }
        if fee > super::market::clearing::MAX_SETTLEMENT_FEE_PER_REQUEST {
            return Err(LaunchError::Fee);
        }
        let buy = self.side == LaunchSide::Buy;
        let claim = SwapClaim {
            request: key,
            input_asset: if buy { NOID_ASSET } else { self.asset },
            output_asset: if buy { self.asset } else { NOID_ASSET },
            refund_owner: self.owner,
            recipient: self.recipient,
            refund_units: if buy { self.noid_limit } else { self.quantity },
            output_units: 0,
            fee_credit: MARKET_REQUEST_FEE_CREDIT - fee,
        };
        claim.validate().map_err(|_| LaunchError::Funding)?;
        Ok(claim)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum LaunchKind {
    Definition = 48,
    State = 49,
    Request = 50,
}
impl LaunchKind {
    pub const fn field_count(self) -> usize {
        match self {
            Self::Definition | Self::State => 8,
            Self::Request => 12,
        }
    }
    pub const fn tag(self) -> DomainTag {
        DomainTag::new(match self {
            Self::Definition => b"LNDEF_21",
            Self::State => b"LNSTAT21",
            Self::Request => b"LNREQ_21",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchOpening {
    Definition(LaunchDefinition),
    State(LaunchState),
    Request(LaunchRequest),
}
impl LaunchOpening {
    pub const fn kind(self) -> LaunchKind {
        match self {
            Self::Definition(_) => LaunchKind::Definition,
            Self::State(_) => LaunchKind::State,
            Self::Request(_) => LaunchKind::Request,
        }
    }
    pub fn validate(self) -> Result<(), LaunchError> {
        match self {
            Self::Definition(d) => d.validate(),
            Self::State(s) => s.validate(),
            Self::Request(r) => r.validate(),
        }
    }
    pub fn noid_value(self) -> Result<u64, LaunchError> {
        self.validate()?;
        match self {
            Self::Definition(_) => Ok(0),
            Self::State(s) => Ok(s.market_noid),
            Self::Request(r) => r.noid_value(),
        }
    }
    pub fn fields(self) -> [Block128; 12] {
        let mut f = [Block128(0); 12];
        match self {
            Self::Definition(d) => {
                put(&mut f, 0, d.asset.0);
                put(&mut f, 2, d.market_genesis);
                f[4] = pack(d.initial_supply, d.profile);
                put(&mut f, 5, d.definition_root.0);
            }
            Self::State(s) => {
                put(&mut f, 0, s.launch.0);
                f[2] = pack(s.inventory_units, s.market_noid);
                f[3] = pack(s.generation, s.registered_height);
                put(&mut f, 4, s.queue_root);
                f[6] = Block128(
                    u128::from(s.timeout_height)
                        | (u128::from(s.request_count) << 64)
                        | ((s.phase as u128) << 80),
                );
            }
            Self::Request(r) => {
                put(&mut f, 0, r.round);
                put(&mut f, 2, r.asset.0);
                put(&mut f, 4, r.owner.0);
                put(&mut f, 6, r.recipient.0);
                f[8] = pack(r.quantity, r.noid_limit);
                f[9] = pack(r.registered_height, r.side as u64);
                f[10] = Block128(u128::from(r.profile));
            }
        }
        f
    }
    pub fn root(self) -> Address {
        Address(hash(
            self.kind().tag(),
            &self.fields()[..self.kind().field_count()],
        ))
    }
    pub fn to_bytes(self) -> Result<Vec<u8>, LaunchError> {
        self.validate()?;
        let mut bytes =
            Vec::with_capacity(NATIVE_OPENING_HEADER_BYTES + 16 * self.kind().field_count());
        bytes.extend_from_slice(NATIVE_OPENING_MAGIC);
        bytes.extend_from_slice(&NATIVE_OPENING_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(self.kind() as u16).to_le_bytes());
        for field in &self.fields()[..self.kind().field_count()] {
            bytes.extend_from_slice(&field.0.to_le_bytes());
        }
        Ok(bytes)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LaunchError> {
        if bytes.len() < NATIVE_OPENING_HEADER_BYTES
            || &bytes[..8] != NATIVE_OPENING_MAGIC
            || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != NATIVE_OPENING_VERSION
        {
            return Err(LaunchError::Encoding);
        }
        let kind = match u16::from_le_bytes(bytes[10..12].try_into().unwrap()) {
            48 => LaunchKind::Definition,
            49 => LaunchKind::State,
            50 => LaunchKind::Request,
            _ => return Err(LaunchError::Kind),
        };
        if bytes.len() != NATIVE_OPENING_HEADER_BYTES + 16 * kind.field_count() {
            return Err(LaunchError::Encoding);
        }
        let mut f = [Block128(0); 12];
        for (i, raw) in bytes[12..].chunks_exact(16).enumerate() {
            f[i] = Block128(u128::from_le_bytes(raw.try_into().unwrap()));
        }
        Self::from_fields(kind, &f[..kind.field_count()])
    }
    pub fn from_fields(kind: LaunchKind, f: &[Block128]) -> Result<Self, LaunchError> {
        if f.len() != kind.field_count() {
            return Err(LaunchError::Encoding);
        }
        let value = match kind {
            LaunchKind::Definition => Self::Definition(LaunchDefinition {
                asset: AssetId(digest(&f, 0)),
                market_genesis: digest(&f, 2),
                initial_supply: f[4].0 as u64,
                profile: (f[4].0 >> 64) as u64,
                definition_root: Address(digest(&f, 5)),
            }),
            LaunchKind::State => Self::State(LaunchState {
                launch: LaunchId(digest(&f, 0)),
                inventory_units: f[2].0 as u64,
                market_noid: (f[2].0 >> 64) as u64,
                generation: f[3].0 as u64,
                registered_height: (f[3].0 >> 64) as u64,
                queue_root: digest(&f, 4),
                timeout_height: f[6].0 as u64,
                request_count: (f[6].0 >> 64) as u16,
                phase: match (f[6].0 >> 80) & 255 {
                    0 => PoolPhase::Idle,
                    1 => PoolPhase::Frozen,
                    _ => return Err(LaunchError::Phase),
                },
            }),
            LaunchKind::Request => Self::Request(LaunchRequest {
                round: digest(&f, 0),
                asset: AssetId(digest(&f, 2)),
                owner: Address(digest(&f, 4)),
                recipient: Address(digest(&f, 6)),
                quantity: f[8].0 as u64,
                noid_limit: (f[8].0 >> 64) as u64,
                registered_height: f[9].0 as u64,
                profile: f[10].0 as u64,
                side: match f[9].0 >> 64 {
                    0 => LaunchSide::Buy,
                    1 => LaunchSide::Sell,
                    _ => return Err(LaunchError::Kind),
                },
            }),
        };
        value.validate()?;
        if value.fields()[..kind.field_count()] != *f {
            return Err(LaunchError::Padding);
        }
        Ok(value)
    }
}

fn expiry(height: u64) -> Result<u64, LaunchError> {
    if height == 0 {
        return Err(LaunchError::Height);
    }
    height
        .checked_add(MARKET_SETTLEMENT_WINDOW)
        .ok_or(LaunchError::Height)
}
fn hash(tag: DomainTag, fields: &[Block128]) -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(tag));
    for pair in fields.chunks_exact(2) {
        sponge.absorb_pair(pair[0], pair[1]);
    }
    sponge.finalize_no_pad()
}
fn pack(low: u64, high: u64) -> Block128 {
    Block128(u128::from(low) | (u128::from(high) << 64))
}
fn put(fields: &mut [Block128], at: usize, digest: Digest) {
    fields[at..at + 2].copy_from_slice(&Address(digest).as_fields());
}
fn digest(fields: &[Block128], at: usize) -> Digest {
    let mut value = [0; 32];
    value[..16].copy_from_slice(&fields[at].0.to_le_bytes());
    value[16..].copy_from_slice(&fields[at + 1].0.to_le_bytes());
    value
}

pub fn validate_funded_request(
    creation_id: u64,
    request: LaunchRequest,
) -> Result<(), LaunchError> {
    native_sequence(creation_id).map_err(|_| LaunchError::Funding)?;
    request.validate()
}
