// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded native asset openings and their exact State-slot bindings.

pub mod closure;
pub mod financial;
pub mod launch;
pub mod market;
pub mod nft_market;
pub mod profile;
pub mod transition;
pub mod trade;
pub mod wire;

use noid_core::Block128;
use noid_poseidon2b::native::{capacity_iv, DomainTag, Poseidon2bSponge};
use noid_poseidon2b::primitives::{Address, Digest};

use crate::asset_backing::{BackingError, BackingState, TokenDenomination};
use crate::{pack_amount_creation_id, TxInput, TxOutput};

pub const TOKEN_DECIMALS: u8 = 6;
pub const TOKEN_UNITS: u64 = 10u64.pow(TOKEN_DECIMALS as u32);
pub const NATIVE_CREATION_TAG: u64 = 1 << 62;
pub const NATIVE_SEQUENCE_MAX: u64 = NATIVE_CREATION_TAG - 1;
const COINBASE_CREATION_TAG: u64 = 1 << 63;
const CREATION_TAG_MASK: u64 = NATIVE_CREATION_TAG | COINBASE_CREATION_TAG;

pub const NATIVE_OPENING_VERSION: u16 = 1;
pub const NATIVE_OPENING_MAGIC: &[u8; 8] = b"NOIDAS21";
pub const NATIVE_OPENING_HEADER_BYTES: usize = 12;
pub const COMPACT_NATIVE_OPENING_FIELDS: usize = 8;
pub const MAX_NATIVE_OPENING_FIELDS: usize = 12;
pub const MAX_NATIVE_OPENING_BYTES: usize =
    NATIVE_OPENING_HEADER_BYTES + 16 * MAX_NATIVE_OPENING_FIELDS;

const TAG_GENESIS: DomainTag = DomainTag::new(b"NATID_21");
const TAG_NFT_ID: DomainTag = DomainTag::new(b"NATNFTID");

macro_rules! identifier {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub Digest);

        impl $name {
            pub fn as_fields(self) -> [Block128; 2] {
                Address(self.0).as_fields()
            }
        }
    };
}

identifier!(AssetId);
identifier!(CollectionId);
identifier!(NftId);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NativeKind {
    FungibleDefinition = 1,
    TokenBalance = 2,
    TokenReserve = 3,
    NftCollection = 4,
    NftItem = 5,
    MarketDefinition = 32,
    MarketPool = 33,
    MarketRequest = 34,
    MarketClaim = 35,
    MarketLiquidity = 36,
    MarketLiquidityDeposit = 37,
    MarketLiquidityWithdrawal = 38,
    MarketLiquidityClaim = 39,
    MarketLiquidityBurn = 40,
    LaunchDefinition = 48,
    LaunchState = 49,
    LaunchRequest = 50,
    NftListingDefinition = 64,
    NftListing = 65,
    NftPurchase = 66,
    NftOffer = 67,
}

impl NativeKind {
    pub const ALL: [Self; 21] = [
        Self::FungibleDefinition,
        Self::TokenBalance,
        Self::TokenReserve,
        Self::NftCollection,
        Self::NftItem,
        Self::MarketDefinition,
        Self::MarketPool,
        Self::MarketRequest,
        Self::MarketClaim,
        Self::MarketLiquidity,
        Self::MarketLiquidityDeposit,
        Self::MarketLiquidityWithdrawal,
        Self::MarketLiquidityClaim,
        Self::MarketLiquidityBurn,
        Self::LaunchDefinition,
        Self::LaunchState,
        Self::LaunchRequest,
        Self::NftListingDefinition,
        Self::NftListing,
        Self::NftPurchase,
        Self::NftOffer,
    ];

    pub const fn field_count(self) -> usize {
        match self {
            Self::TokenBalance | Self::TokenReserve | Self::MarketLiquidity => 6,
            Self::FungibleDefinition
            | Self::NftCollection
            | Self::NftItem
            | Self::MarketDefinition
            | Self::MarketPool
            | Self::MarketLiquidityDeposit
            | Self::MarketLiquidityWithdrawal
            | Self::MarketLiquidityClaim
            | Self::MarketLiquidityBurn
            | Self::LaunchDefinition
            | Self::LaunchState
            | Self::NftListingDefinition
            | Self::NftListing
            | Self::NftOffer => 8,
            Self::MarketRequest | Self::MarketClaim | Self::LaunchRequest | Self::NftPurchase => 12,
        }
    }

    pub const fn tag(self) -> DomainTag {
        match self {
            Self::FungibleDefinition => DomainTag::new(b"NATDEF21"),
            Self::TokenBalance => DomainTag::new(b"NATBAL21"),
            Self::TokenReserve => DomainTag::new(b"NATRES21"),
            Self::NftCollection => DomainTag::new(b"NATCOL21"),
            Self::NftItem => DomainTag::new(b"NATNFT21"),
            Self::MarketDefinition => market::MarketKind::Definition.tag(),
            Self::MarketPool => market::MarketKind::Pool.tag(),
            Self::MarketRequest => market::MarketKind::Request.tag(),
            Self::MarketClaim => market::MarketKind::Claim.tag(),
            Self::MarketLiquidity => market::MarketKind::Liquidity.tag(),
            Self::MarketLiquidityDeposit => market::MarketKind::LiquidityDeposit.tag(),
            Self::MarketLiquidityWithdrawal => market::MarketKind::LiquidityWithdrawal.tag(),
            Self::MarketLiquidityClaim => market::MarketKind::LiquidityClaim.tag(),
            Self::MarketLiquidityBurn => market::MarketKind::LiquidityBurn.tag(),
            Self::LaunchDefinition => launch::LaunchKind::Definition.tag(),
            Self::LaunchState => launch::LaunchKind::State.tag(),
            Self::LaunchRequest => launch::LaunchKind::Request.tag(),
            Self::NftListingDefinition => nft_market::NftMarketKind::Definition.tag(),
            Self::NftListing => nft_market::NftMarketKind::Listing.tag(),
            Self::NftPurchase => nft_market::NftMarketKind::Purchase.tag(),
            Self::NftOffer => nft_market::NftMarketKind::Offer.tag(),
        }
    }

    pub const fn market_kind(self) -> Option<market::MarketKind> {
        match self {
            Self::MarketDefinition => Some(market::MarketKind::Definition),
            Self::MarketPool => Some(market::MarketKind::Pool),
            Self::MarketRequest => Some(market::MarketKind::Request),
            Self::MarketClaim => Some(market::MarketKind::Claim),
            Self::MarketLiquidity => Some(market::MarketKind::Liquidity),
            Self::MarketLiquidityDeposit => Some(market::MarketKind::LiquidityDeposit),
            Self::MarketLiquidityWithdrawal => Some(market::MarketKind::LiquidityWithdrawal),
            Self::MarketLiquidityClaim => Some(market::MarketKind::LiquidityClaim),
            Self::MarketLiquidityBurn => Some(market::MarketKind::LiquidityBurn),
            _ => None,
        }
    }

    pub fn from_u16(kind: u16) -> Result<Self, NativeAssetError> {
        match kind {
            1 => Ok(Self::FungibleDefinition),
            2 => Ok(Self::TokenBalance),
            3 => Ok(Self::TokenReserve),
            4 => Ok(Self::NftCollection),
            5 => Ok(Self::NftItem),
            32 => Ok(Self::MarketDefinition),
            33 => Ok(Self::MarketPool),
            34 => Ok(Self::MarketRequest),
            35 => Ok(Self::MarketClaim),
            36 => Ok(Self::MarketLiquidity),
            37 => Ok(Self::MarketLiquidityDeposit),
            38 => Ok(Self::MarketLiquidityWithdrawal),
            39 => Ok(Self::MarketLiquidityClaim),
            40 => Ok(Self::MarketLiquidityBurn),
            48 => Ok(Self::LaunchDefinition),
            49 => Ok(Self::LaunchState),
            50 => Ok(Self::LaunchRequest),
            64 => Ok(Self::NftListingDefinition),
            65 => Ok(Self::NftListing),
            66 => Ok(Self::NftPurchase),
            67 => Ok(Self::NftOffer),
            _ => Err(NativeAssetError::Kind),
        }
    }

    pub const fn launch_kind(self) -> Option<launch::LaunchKind> {
        match self {
            Self::LaunchDefinition => Some(launch::LaunchKind::Definition),
            Self::LaunchState => Some(launch::LaunchKind::State),
            Self::LaunchRequest => Some(launch::LaunchKind::Request),
            _ => None,
        }
    }
    pub const fn nft_market_kind(self) -> Option<nft_market::NftMarketKind> {
        match self {
            Self::NftListingDefinition => Some(nft_market::NftMarketKind::Definition),
            Self::NftListing => Some(nft_market::NftMarketKind::Listing),
            Self::NftPurchase => Some(nft_market::NftMarketKind::Purchase),
            Self::NftOffer => Some(nft_market::NftMarketKind::Offer),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum IssuanceRoute {
    Standalone = 0,
    Launchpad = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAssetError {
    Encoding,
    Version,
    Kind,
    Padding,
    Identifier,
    Owner,
    Quantity,
    Supply,
    Provenance,
    Anchor,
    SlotBinding,
    Timelock,
    Definition,
    Backing(BackingError),
    Market(market::MarketError),
    Launch(launch::LaunchError),
    NftMarket(nft_market::NftMarketError),
}

impl core::fmt::Display for NativeAssetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "native asset: {self:?}")
    }
}

impl std::error::Error for NativeAssetError {}

impl From<BackingError> for NativeAssetError {
    fn from(value: BackingError) -> Self {
        Self::Backing(value)
    }
}

pub fn native_creation_id(sequence: u64) -> Result<u64, NativeAssetError> {
    if sequence == 0 || sequence > NATIVE_SEQUENCE_MAX {
        return Err(NativeAssetError::Provenance);
    }
    Ok(NATIVE_CREATION_TAG | sequence)
}

pub fn native_sequence(creation_id: u64) -> Result<u64, NativeAssetError> {
    let sequence = creation_id & NATIVE_SEQUENCE_MAX;
    if creation_id & CREATION_TAG_MASK != NATIVE_CREATION_TAG || sequence == 0 {
        return Err(NativeAssetError::Provenance);
    }
    Ok(sequence)
}

/// Genesis identity uses an exact consumed funding incarnation. Its enclosing
/// transition authenticates this input, the chain and the funding authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisAnchor {
    pub chain: Digest,
    pub owner: Address,
    pub input: TxInput,
}

impl GenesisAnchor {
    pub fn validate(&self) -> Result<(), NativeAssetError> {
        let ordinary = self.input.creation_id < NATIVE_CREATION_TAG;
        let coinbase = self.input.creation_id & COINBASE_CREATION_TAG != 0;
        if self.chain == [0; 32]
            || self.owner == Address([0; 32])
            || self.input.amount == 0
            || self.input.creation_id == 0
            || !(ordinary || coinbase)
        {
            return Err(NativeAssetError::Anchor);
        }
        Ok(())
    }

    fn derive(&self, kind: NativeKind, specification: [Block128; 6]) -> Digest {
        let chain = Address(self.chain).as_fields();
        let owner = self.owner.as_fields();
        let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_GENESIS));
        for pair in [
            chain,
            owner,
            [
                pack_amount_creation_id(self.input.amount, self.input.creation_id),
                Block128(u128::from(self.input.slot_index) | ((kind as u128) << 32)),
            ],
        ] {
            sponge.absorb_pair(pair[0], pair[1]);
        }
        for pair in specification.chunks_exact(2) {
            sponge.absorb_pair(pair[0], pair[1]);
        }
        sponge.finalize_no_pad()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FungibleDefinition {
    pub asset: AssetId,
    pub issuer: Address,
    pub initial_supply: u64,
    pub route: IssuanceRoute,
    pub metadata: Digest,
}

impl FungibleDefinition {
    pub fn from_genesis(
        anchor: &GenesisAnchor,
        initial_supply: u64,
        route: IssuanceRoute,
        metadata: Digest,
    ) -> Result<Self, NativeAssetError> {
        anchor.validate()?;
        if initial_supply == 0 {
            return Err(NativeAssetError::Supply);
        }
        let issuer = anchor.owner.as_fields();
        let data = Address(metadata).as_fields();
        let asset = AssetId(anchor.derive(
            NativeKind::FungibleDefinition,
            [
                issuer[0],
                issuer[1],
                pack_amount_creation_id(initial_supply, route as u64),
                data[0],
                data[1],
                Block128(0),
            ],
        ));
        let definition = Self {
            asset,
            issuer: anchor.owner,
            initial_supply,
            route,
            metadata,
        };
        NativeOpening::FungibleDefinition(definition).validate()?;
        Ok(definition)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBalance {
    pub asset: AssetId,
    pub owner: Address,
    pub units: u64,
    pub unlock_height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenReserve {
    pub asset: AssetId,
    pub reserve_micronoid: u64,
    pub outstanding_units: u64,
    pub initial_supply: u64,
    pub definition_root: Address,
}

impl TokenReserve {
    pub fn from_definition(
        definition: &FungibleDefinition,
        reserve_micronoid: u64,
    ) -> Result<Self, NativeAssetError> {
        let opening = NativeOpening::FungibleDefinition(*definition);
        opening.validate()?;
        let reserve = Self {
            asset: definition.asset,
            reserve_micronoid,
            outstanding_units: definition.initial_supply,
            initial_supply: definition.initial_supply,
            definition_root: opening.root(),
        };
        reserve.backing()?;
        Ok(reserve)
    }

    pub fn check_definition(
        &self,
        definition: &FungibleDefinition,
    ) -> Result<(), NativeAssetError> {
        let opening = NativeOpening::FungibleDefinition(*definition);
        opening.validate()?;
        if self.asset != definition.asset
            || self.initial_supply != definition.initial_supply
            || self.definition_root != opening.root()
        {
            return Err(NativeAssetError::Definition);
        }
        self.backing()?;
        Ok(())
    }

    pub fn backing(&self) -> Result<BackingState, NativeAssetError> {
        require_identifier(self.asset.0)?;
        if self.initial_supply == 0 || self.outstanding_units > self.initial_supply {
            return Err(NativeAssetError::Supply);
        }
        if self.definition_root == Address([0; 32]) {
            return Err(NativeAssetError::Definition);
        }
        Ok(BackingState::new(
            TokenDenomination::new(TOKEN_DECIMALS)?,
            self.reserve_micronoid,
            self.outstanding_units,
        )?)
    }

    pub fn redeem(&self, burned_units: u64) -> Result<(Self, u64), NativeAssetError> {
        let quote = self.backing()?.quote_redemption(burned_units)?;
        Ok((
            Self {
                reserve_micronoid: quote.next.reserve_micronoid(),
                outstanding_units: quote.next.supply_units(),
                ..*self
            },
            quote.payout_micronoid,
        ))
    }

    pub fn top_up(&self, contribution_micronoid: u64) -> Result<Self, NativeAssetError> {
        let next = self.backing()?.quote_top_up(contribution_micronoid)?;
        Ok(Self {
            reserve_micronoid: next.reserve_micronoid(),
            ..*self
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftCollection {
    pub collection: CollectionId,
    pub creator: Address,
    pub maximum_items: u64,
    pub issued_items: u64,
    pub metadata: Digest,
}

impl NftCollection {
    pub fn from_genesis(
        anchor: &GenesisAnchor,
        maximum_items: u64,
        metadata: Digest,
    ) -> Result<Self, NativeAssetError> {
        anchor.validate()?;
        if maximum_items == 0 {
            return Err(NativeAssetError::Supply);
        }
        let creator = anchor.owner.as_fields();
        let data = Address(metadata).as_fields();
        let collection = CollectionId(anchor.derive(
            NativeKind::NftCollection,
            [
                creator[0],
                creator[1],
                Block128(u128::from(maximum_items)),
                data[0],
                data[1],
                Block128(0),
            ],
        ));
        let collection = Self {
            collection,
            creator: anchor.owner,
            maximum_items,
            issued_items: 0,
            metadata,
        };
        NativeOpening::NftCollection(collection).validate()?;
        Ok(collection)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftItem {
    pub collection: CollectionId,
    pub owner: Address,
    pub metadata: Digest,
    pub serial: u64,
    pub unlock_height: u64,
}

impl NftItem {
    pub fn id(&self) -> NftId {
        let collection = self.collection.as_fields();
        let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_NFT_ID));
        sponge.absorb_pair(collection[0], collection[1]);
        sponge.absorb_pair(Block128(u128::from(self.serial)), Block128(0));
        NftId(sponge.finalize_no_pad())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeOpening {
    FungibleDefinition(FungibleDefinition),
    TokenBalance(TokenBalance),
    TokenReserve(TokenReserve),
    NftCollection(NftCollection),
    NftItem(NftItem),
    Market(market::MarketOpening),
    Launch(launch::LaunchOpening),
    NftMarket(nft_market::NftMarketOpening),
}

impl NativeOpening {
    pub const fn kind(&self) -> NativeKind {
        match self {
            Self::FungibleDefinition(_) => NativeKind::FungibleDefinition,
            Self::TokenBalance(_) => NativeKind::TokenBalance,
            Self::TokenReserve(_) => NativeKind::TokenReserve,
            Self::NftCollection(_) => NativeKind::NftCollection,
            Self::NftItem(_) => NativeKind::NftItem,
            Self::Market(m) => match m.kind() {
                market::MarketKind::Definition => NativeKind::MarketDefinition,
                market::MarketKind::Pool => NativeKind::MarketPool,
                market::MarketKind::Request => NativeKind::MarketRequest,
                market::MarketKind::Claim => NativeKind::MarketClaim,
                market::MarketKind::Liquidity => NativeKind::MarketLiquidity,
                market::MarketKind::LiquidityDeposit => NativeKind::MarketLiquidityDeposit,
                market::MarketKind::LiquidityWithdrawal => NativeKind::MarketLiquidityWithdrawal,
                market::MarketKind::LiquidityClaim => NativeKind::MarketLiquidityClaim,
                market::MarketKind::LiquidityBurn => NativeKind::MarketLiquidityBurn,
            },
            Self::Launch(l) => match l.kind() {
                launch::LaunchKind::Definition => NativeKind::LaunchDefinition,
                launch::LaunchKind::State => NativeKind::LaunchState,
                launch::LaunchKind::Request => NativeKind::LaunchRequest,
            },
            Self::NftMarket(n) => match n.kind() {
                nft_market::NftMarketKind::Definition => NativeKind::NftListingDefinition,
                nft_market::NftMarketKind::Listing => NativeKind::NftListing,
                nft_market::NftMarketKind::Purchase => NativeKind::NftPurchase,
                nft_market::NftMarketKind::Offer => NativeKind::NftOffer,
            },
        }
    }

    pub fn validate(&self) -> Result<(), NativeAssetError> {
        if !profile::kind_enabled(self.kind()) {
            return Err(NativeAssetError::Kind);
        }
        match self {
            Self::FungibleDefinition(d) => {
                require_identifier(d.asset.0)?;
                require_owner(d.issuer)?;
                if d.initial_supply == 0 {
                    return Err(NativeAssetError::Supply);
                }
                if d.route != IssuanceRoute::Launchpad
                    || launch::validate_supply_units(d.initial_supply).is_err()
                {
                    return Err(NativeAssetError::Supply);
                }
            }
            Self::TokenBalance(b) => {
                require_identifier(b.asset.0)?;
                require_owner(b.owner)?;
                if b.units == 0 {
                    return Err(NativeAssetError::Quantity);
                }
            }
            Self::TokenReserve(r) => {
                r.backing()?;
            }
            Self::NftCollection(c) => {
                require_identifier(c.collection.0)?;
                require_owner(c.creator)?;
                if c.maximum_items == 0 || c.issued_items > c.maximum_items {
                    return Err(NativeAssetError::Supply);
                }
            }
            Self::NftItem(n) => {
                require_identifier(n.collection.0)?;
                require_owner(n.owner)?;
                if n.serial == 0 {
                    return Err(NativeAssetError::Quantity);
                }
            }
            Self::Market(m) => {
                m.validate().map_err(NativeAssetError::Market)?;
                match m {
                    market::MarketOpening::Definition(d) if !d.base_is_noid() => {
                        return Err(NativeAssetError::Kind);
                    }
                    market::MarketOpening::Pool(p) if p.total_shares != p.locked_shares => {
                        return Err(NativeAssetError::Kind);
                    }
                    _ => {}
                }
            }
            Self::Launch(l) => l.validate().map_err(NativeAssetError::Launch)?,
            Self::NftMarket(n) => n.validate().map_err(NativeAssetError::NftMarket)?,
        }
        Ok(())
    }

    /// The raw amount lane always measures NOID, including for token carriers.
    pub fn amount_micronoid(&self) -> u64 {
        match self {
            Self::TokenReserve(r) => r.reserve_micronoid,
            Self::Market(m) => m.noid_value().unwrap_or(u64::MAX),
            Self::Launch(l) => l.noid_value().unwrap_or(u64::MAX),
            Self::NftMarket(n) => n.noid_value().unwrap_or(u64::MAX),
            _ => 0,
        }
    }

    pub const fn unlock_height(&self) -> u64 {
        match self {
            Self::TokenBalance(b) => b.unlock_height,
            Self::NftItem(n) => n.unlock_height,
            Self::Market(market::MarketOpening::Liquidity(p)) => p.unlock_height,
            _ => 0,
        }
    }

    pub fn fields(&self) -> [Block128; MAX_NATIVE_OPENING_FIELDS] {
        let compact = match self {
            Self::FungibleDefinition(d) => {
                let asset = d.asset.as_fields();
                let issuer = d.issuer.as_fields();
                let metadata = Address(d.metadata).as_fields();
                [
                    asset[0],
                    asset[1],
                    issuer[0],
                    issuer[1],
                    pack_amount_creation_id(d.initial_supply, d.route as u64),
                    metadata[0],
                    metadata[1],
                    Block128(0),
                ]
            }
            Self::TokenBalance(b) => {
                let asset = b.asset.as_fields();
                let owner = b.owner.as_fields();
                [
                    asset[0],
                    asset[1],
                    owner[0],
                    owner[1],
                    pack_amount_creation_id(b.units, b.unlock_height),
                    Block128(0),
                    Block128(0),
                    Block128(0),
                ]
            }
            Self::TokenReserve(r) => {
                let asset = r.asset.as_fields();
                let definition = r.definition_root.as_fields();
                [
                    asset[0],
                    asset[1],
                    pack_amount_creation_id(r.reserve_micronoid, r.outstanding_units),
                    Block128(u128::from(r.initial_supply)),
                    definition[0],
                    definition[1],
                    Block128(0),
                    Block128(0),
                ]
            }
            Self::NftCollection(c) => {
                let collection = c.collection.as_fields();
                let creator = c.creator.as_fields();
                let metadata = Address(c.metadata).as_fields();
                [
                    collection[0],
                    collection[1],
                    creator[0],
                    creator[1],
                    pack_amount_creation_id(c.maximum_items, c.issued_items),
                    metadata[0],
                    metadata[1],
                    Block128(0),
                ]
            }
            Self::NftItem(n) => {
                let collection = n.collection.as_fields();
                let owner = n.owner.as_fields();
                let metadata = Address(n.metadata).as_fields();
                [
                    collection[0],
                    collection[1],
                    owner[0],
                    owner[1],
                    metadata[0],
                    metadata[1],
                    pack_amount_creation_id(n.serial, n.unlock_height),
                    Block128(0),
                ]
            }
            Self::Market(m) => return m.fields(),
            Self::Launch(l) => return l.fields(),
            Self::NftMarket(n) => return n.fields(),
        };
        let mut fields = [Block128(0); MAX_NATIVE_OPENING_FIELDS];
        fields[..COMPACT_NATIVE_OPENING_FIELDS].copy_from_slice(&compact);
        fields
    }

    pub fn compact_fields(&self) -> Option<[Block128; COMPACT_NATIVE_OPENING_FIELDS]> {
        if matches!(self, Self::Market(_) | Self::Launch(_) | Self::NftMarket(_)) {
            return None;
        }
        Some(
            self.fields()[..COMPACT_NATIVE_OPENING_FIELDS]
                .try_into()
                .unwrap(),
        )
    }

    pub const fn is_auxiliary(&self) -> bool {
        matches!(
            self,
            Self::Market(market::MarketOpening::Definition(_))
                | Self::Launch(launch::LaunchOpening::Definition(_))
                | Self::NftMarket(nft_market::NftMarketOpening::Definition(_))
        )
    }

    pub const fn allows_duplicate_carriers(&self) -> bool {
        matches!(
            self,
            Self::TokenBalance(_)
                | Self::Launch(launch::LaunchOpening::Request(_))
                | Self::NftMarket(nft_market::NftMarketOpening::Purchase(_))
                | Self::Market(
                    market::MarketOpening::Request(_)
                        | market::MarketOpening::Liquidity(_)
                        | market::MarketOpening::LiquidityDeposit(_)
                        | market::MarketOpening::LiquidityWithdrawal(_)
                        | market::MarketOpening::LiquidityBurn(_)
                )
        )
    }

    pub fn dependency_root(&self) -> Option<Address> {
        match self {
            Self::Launch(launch::LaunchOpening::State(s)) => Some(Address(s.launch.0)),
            Self::NftMarket(nft_market::NftMarketOpening::Listing(s)) => Some(Address(s.listing.0)),
            Self::Market(market::MarketOpening::Pool(p)) => Some(Address(p.pool.0)),
            Self::Market(market::MarketOpening::Liquidity(p)) => Some(Address(p.pool.0)),
            Self::Market(market::MarketOpening::LiquidityDeposit(p)) => Some(Address(p.pool.0)),
            Self::Market(market::MarketOpening::LiquidityWithdrawal(p)) => Some(Address(p.pool.0)),
            Self::Market(market::MarketOpening::LiquidityClaim(p)) => Some(Address(p.pool.0)),
            Self::Market(market::MarketOpening::LiquidityBurn(p)) => Some(Address(p.pool.0)),
            _ => None,
        }
    }

    pub fn check_dependency(&self, dependency: Option<Self>) -> Result<(), NativeAssetError> {
        match (self.dependency_root(), dependency) {
            (None, None) => Ok(()),
            (Some(root), Some(Self::NftMarket(nft_market::NftMarketOpening::Definition(d)))) => {
                if d.id().0 != root.0 {
                    return Err(NativeAssetError::Definition);
                }
                let Self::NftMarket(nft_market::NftMarketOpening::Listing(s)) = self else {
                    return Err(NativeAssetError::Definition);
                };
                s.check_definition(d).map_err(NativeAssetError::NftMarket)
            }
            (Some(root), Some(Self::Launch(launch::LaunchOpening::Definition(d)))) => {
                if d.id().0 != root.0 {
                    return Err(NativeAssetError::Definition);
                }
                let Self::Launch(launch::LaunchOpening::State(s)) = self else {
                    return Err(NativeAssetError::Definition);
                };
                s.check_definition(d).map_err(NativeAssetError::Launch)
            }
            (Some(root), Some(Self::Market(market::MarketOpening::Definition(d)))) => {
                d.validate().map_err(NativeAssetError::Market)?;
                if d.id().0 != root.0 {
                    return Err(NativeAssetError::Definition);
                }
                match self {
                    Self::Market(market::MarketOpening::Pool(p)) => p.check_definition(d),
                    Self::Market(market::MarketOpening::LiquidityDeposit(p)) => {
                        p.check_definition(d)
                    }
                    Self::Market(market::MarketOpening::LiquidityWithdrawal(p)) => {
                        p.check_definition(d)
                    }
                    Self::Market(market::MarketOpening::LiquidityClaim(p)) => p.check_definition(d),
                    Self::Market(market::MarketOpening::LiquidityBurn(p)) => p.check_definition(d),
                    Self::Market(market::MarketOpening::Liquidity(_)) => Ok(()),
                    _ => Err(market::MarketError::Pool),
                }
                .map_err(NativeAssetError::Market)?;
                Ok(())
            }
            _ => Err(NativeAssetError::Definition),
        }
    }

    pub fn owners(&self) -> Vec<Address> {
        let (first, second) = match self {
            Self::FungibleDefinition(d) => (Some(d.issuer), None),
            Self::TokenBalance(b) => (Some(b.owner), None),
            Self::NftCollection(c) => (Some(c.creator), None),
            Self::NftItem(n) => (Some(n.owner), None),
            Self::Launch(launch::LaunchOpening::Request(r)) => (Some(r.owner), None),
            Self::NftMarket(nft_market::NftMarketOpening::Purchase(r)) => (Some(r.payer), None),
            Self::NftMarket(nft_market::NftMarketOpening::Offer(o)) => (Some(o.payer), None),
            Self::Market(market::MarketOpening::Request(r)) => (Some(r.owner), None),
            Self::Market(market::MarketOpening::Liquidity(p)) => (Some(p.owner), None),
            Self::Market(market::MarketOpening::LiquidityDeposit(p)) => (Some(p.owner), None),
            Self::Market(market::MarketOpening::LiquidityWithdrawal(p)) => (Some(p.owner), None),
            Self::Market(market::MarketOpening::LiquidityClaim(p)) => (Some(p.owner), None),
            Self::Market(market::MarketOpening::LiquidityBurn(p)) => (Some(p.owner), None),
            Self::Market(market::MarketOpening::Claim(c)) => (
                (c.refund_units != 0 || c.fee_credit != 0).then_some(c.refund_owner),
                (c.output_units != 0).then_some(c.recipient),
            ),
            _ => (None, None),
        };
        let mut owners: Vec<_> = first.into_iter().collect();
        if let Some(owner) = second {
            if !owners.contains(&owner) {
                owners.push(owner);
            }
        }
        owners
    }

    pub fn owners_with_dependency(
        &self,
        dependency: Option<Self>,
    ) -> Result<Vec<Address>, NativeAssetError> {
        self.check_dependency(dependency)?;
        if let Self::NftMarket(nft_market::NftMarketOpening::Listing(_)) = self {
            let Some(Self::NftMarket(nft_market::NftMarketOpening::Definition(d))) = dependency
            else {
                return Err(NativeAssetError::Definition);
            };
            return Ok(vec![d.seller]);
        }
        Ok(self.owners())
    }

    pub fn root(&self) -> Address {
        let fields = self.fields();
        let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(self.kind().tag()));
        for pair in fields[..self.kind().field_count()].chunks_exact(2) {
            sponge.absorb_pair(pair[0], pair[1]);
        }
        Address(sponge.finalize_no_pad())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, NativeAssetError> {
        self.validate()?;
        let count = self.kind().field_count();
        let mut bytes = Vec::with_capacity(NATIVE_OPENING_HEADER_BYTES + 16 * count);
        bytes.extend_from_slice(NATIVE_OPENING_MAGIC);
        bytes.extend_from_slice(&NATIVE_OPENING_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(self.kind() as u16).to_le_bytes());
        for field in &self.fields()[..count] {
            bytes.extend_from_slice(&field.0.to_le_bytes());
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NativeAssetError> {
        if bytes.len() < NATIVE_OPENING_HEADER_BYTES
            || bytes.len() > MAX_NATIVE_OPENING_BYTES
            || &bytes[..8] != NATIVE_OPENING_MAGIC
        {
            return Err(NativeAssetError::Encoding);
        }
        if u16::from_le_bytes([bytes[8], bytes[9]]) != NATIVE_OPENING_VERSION {
            return Err(NativeAssetError::Version);
        }
        let kind = NativeKind::from_u16(u16::from_le_bytes([bytes[10], bytes[11]]))?;
        let count = kind.field_count();
        if bytes.len() != NATIVE_OPENING_HEADER_BYTES + 16 * count {
            return Err(NativeAssetError::Encoding);
        }
        let mut fields = [Block128(0); MAX_NATIVE_OPENING_FIELDS];
        for (field, chunk) in fields.iter_mut().zip(bytes[12..].chunks_exact(16)) {
            *field = Block128(u128::from_le_bytes(
                chunk.try_into().map_err(|_| NativeAssetError::Encoding)?,
            ));
        }
        Self::from_fields(kind, &fields[..count])
    }

    pub fn from_fields(kind: NativeKind, f: &[Block128]) -> Result<Self, NativeAssetError> {
        if !profile::kind_enabled(kind) {
            return Err(NativeAssetError::Kind);
        }
        if f.len() != kind.field_count() {
            return Err(NativeAssetError::Encoding);
        }
        if let Some(market_kind) = kind.market_kind() {
            let opening = market::MarketOpening::from_fields(market_kind, f)
                .map(Self::Market)
                .map_err(NativeAssetError::Market)?;
            opening.validate()?;
            return Ok(opening);
        }
        if let Some(launch_kind) = kind.launch_kind() {
            return launch::LaunchOpening::from_fields(launch_kind, f)
                .map(Self::Launch)
                .map_err(NativeAssetError::Launch);
        }
        if let Some(nft_kind) = kind.nft_market_kind() {
            return nft_market::NftMarketOpening::from_fields(nft_kind, f)
                .map(Self::NftMarket)
                .map_err(NativeAssetError::NftMarket);
        }
        let opening = match kind {
            NativeKind::FungibleDefinition => {
                require_zero(f[7])?;
                let route = match (f[4].0 >> 64) as u64 {
                    0 => IssuanceRoute::Standalone,
                    1 => IssuanceRoute::Launchpad,
                    _ => return Err(NativeAssetError::Encoding),
                };
                Self::FungibleDefinition(FungibleDefinition {
                    asset: AssetId(fields_digest(f[0], f[1])),
                    issuer: Address(fields_digest(f[2], f[3])),
                    initial_supply: f[4].0 as u64,
                    route,
                    metadata: fields_digest(f[5], f[6]),
                })
            }
            NativeKind::TokenBalance => {
                require_zero(f[5])?;
                Self::TokenBalance(TokenBalance {
                    asset: AssetId(fields_digest(f[0], f[1])),
                    owner: Address(fields_digest(f[2], f[3])),
                    units: f[4].0 as u64,
                    unlock_height: (f[4].0 >> 64) as u64,
                })
            }
            NativeKind::TokenReserve => {
                if f[3].0 > u128::from(u64::MAX) {
                    return Err(NativeAssetError::Encoding);
                }
                Self::TokenReserve(TokenReserve {
                    asset: AssetId(fields_digest(f[0], f[1])),
                    reserve_micronoid: f[2].0 as u64,
                    outstanding_units: (f[2].0 >> 64) as u64,
                    initial_supply: f[3].0 as u64,
                    definition_root: Address(fields_digest(f[4], f[5])),
                })
            }
            NativeKind::NftCollection => {
                require_zero(f[7])?;
                Self::NftCollection(NftCollection {
                    collection: CollectionId(fields_digest(f[0], f[1])),
                    creator: Address(fields_digest(f[2], f[3])),
                    maximum_items: f[4].0 as u64,
                    issued_items: (f[4].0 >> 64) as u64,
                    metadata: fields_digest(f[5], f[6]),
                })
            }
            NativeKind::NftItem => {
                require_zero(f[7])?;
                Self::NftItem(NftItem {
                    collection: CollectionId(fields_digest(f[0], f[1])),
                    owner: Address(fields_digest(f[2], f[3])),
                    metadata: fields_digest(f[4], f[5]),
                    serial: f[6].0 as u64,
                    unlock_height: (f[6].0 >> 64) as u64,
                })
            }
            _ => return Err(NativeAssetError::Kind),
        };
        opening.validate()?;
        Ok(opening)
    }

    /// Bind an opening to the consumed raw claim. The enclosing transition
    /// authenticates this exact slot and incarnation against State.
    pub fn check_input(
        &self,
        input: &TxInput,
        input_root: Address,
        height: u64,
    ) -> Result<(), NativeAssetError> {
        self.check_input_binding(input, input_root)?;
        if height < self.unlock_height() {
            return Err(NativeAssetError::Timelock);
        }
        Ok(())
    }

    pub fn check_input_binding(
        &self,
        input: &TxInput,
        input_root: Address,
    ) -> Result<(), NativeAssetError> {
        self.validate()?;
        native_sequence(input.creation_id)?;
        if input.amount != self.amount_micronoid() || input_root != self.root() {
            return Err(NativeAssetError::SlotBinding);
        }
        Ok(())
    }

    pub fn check_output(&self, output: &TxOutput) -> Result<(), NativeAssetError> {
        self.validate()?;
        if output.amount != self.amount_micronoid() || output.owner != self.root() {
            return Err(NativeAssetError::SlotBinding);
        }
        Ok(())
    }
}

fn require_identifier(id: Digest) -> Result<(), NativeAssetError> {
    if id == [0; 32] {
        return Err(NativeAssetError::Identifier);
    }
    Ok(())
}

fn require_owner(owner: Address) -> Result<(), NativeAssetError> {
    if owner == Address([0; 32]) {
        return Err(NativeAssetError::Owner);
    }
    Ok(())
}

fn require_zero(field: Block128) -> Result<(), NativeAssetError> {
    if field != Block128(0) {
        return Err(NativeAssetError::Padding);
    }
    Ok(())
}

fn fields_digest(a: Block128, b: Block128) -> Digest {
    let mut digest = [0; 32];
    digest[..16].copy_from_slice(&a.0.to_le_bytes());
    digest[16..].copy_from_slice(&b.0.to_le_bytes());
    digest
}
