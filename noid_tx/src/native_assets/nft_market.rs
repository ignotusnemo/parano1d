// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Funded NFT listings, purchase rounds and single-fill collection offers.

pub mod owner;
pub mod queue;
pub mod settlement;

use super::{
    market::{
        PoolPhase, RoundPhase, MARKET_QUANTITY_MAX, MARKET_REQUEST_FEE_CREDIT,
        MARKET_SETTLEMENT_WINDOW,
    },
    native_sequence, CollectionId, NativeOpening, NftItem, NATIVE_CREATION_TAG,
    NATIVE_OPENING_HEADER_BYTES, NATIVE_OPENING_MAGIC, NATIVE_OPENING_VERSION, NATIVE_SEQUENCE_MAX,
};
use noid_core::Block128;
use noid_poseidon2b::{
    native::{capacity_iv, DomainTag, Poseidon2bSponge},
    primitives::{Address, Digest},
};

pub const NFT_MARKET_PROFILE: u64 = 1;
pub const NFT_FEE_CREDIT: u64 = MARKET_REQUEST_FEE_CREDIT;
pub const NFT_MAX_SETTLEMENT_FEE_PER_REQUEST: u64 = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListingId(pub Digest);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftMarketError {
    Encoding,
    Kind,
    Padding,
    Identity,
    Height,
    Price,
    Incarnation,
    Owner,
    Definition,
    Phase,
    Queue,
    Duplicate,
    Funding,
    Fee,
    Conservation,
    Capacity,
    Expired,
}
impl core::fmt::Display for NftMarketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NFT market: {self:?}")
    }
}
impl std::error::Error for NftMarketError {}

/// Canonical parent inputs shared by every purchase in one admission block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftRoundContext {
    height: u64,
    parent_block_id: Digest,
    parent_alloc_counter: u64,
}
impl NftRoundContext {
    pub fn new(
        height: u64,
        parent_block_id: Digest,
        parent_alloc_counter: u64,
    ) -> Result<Self, NftMarketError> {
        let value = Self {
            height,
            parent_block_id,
            parent_alloc_counter,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(self) -> Result<(), NftMarketError> {
        timeout_height(self.height)?;
        if self.height == 0
            || self.parent_block_id == [0; 32]
            || self.parent_alloc_counter > NATIVE_SEQUENCE_MAX
        {
            return Err(NftMarketError::Height);
        }
        Ok(())
    }
    pub const fn height(self) -> u64 {
        self.height
    }
    pub const fn parent_block_id(self) -> Digest {
        self.parent_block_id
    }
    pub const fn parent_alloc_counter(self) -> u64 {
        self.parent_alloc_counter
    }
    fn input_at(input: &crate::TxInput, counter: u64, height: u64) -> bool {
        if input.amount == 0 || input.creation_id == 0 {
            return false;
        }
        if input.creation_id & (1 << 63) != 0 {
            return input.creation_id & !(1 << 63) <= height;
        }
        input.creation_id < NATIVE_CREATION_TAG && input.creation_id <= counter
    }
    pub fn contains_current_input(self, input: &crate::TxInput) -> bool {
        Self::input_at(input, self.parent_alloc_counter, self.height - 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListingDefinition {
    pub collection: CollectionId,
    pub seller: Address,
    pub metadata: Digest,
    pub serial: u64,
    pub source_creation_id: u64,
    pub ask: u64,
    pub expiry_height: u64,
}
impl ListingDefinition {
    pub fn from_item(
        item: NftItem,
        creation_id: u64,
        ask: u64,
        expiry_height: u64,
        height: u64,
    ) -> Result<Self, NftMarketError> {
        NativeOpening::NftItem(item)
            .validate()
            .map_err(|_| NftMarketError::Definition)?;
        if height < item.unlock_height || height.checked_add(1).is_none_or(|h| h >= expiry_height) {
            return Err(NftMarketError::Height);
        }
        let d = Self {
            collection: item.collection,
            seller: item.owner,
            metadata: item.metadata,
            serial: item.serial,
            source_creation_id: creation_id,
            ask,
            expiry_height,
        };
        d.validate()?;
        Ok(d)
    }
    pub fn validate(self) -> Result<(), NftMarketError> {
        if self.collection.0 == [0; 32] || self.seller == Address([0; 32]) || self.serial == 0 {
            return Err(NftMarketError::Identity);
        }
        native_sequence(self.source_creation_id).map_err(|_| NftMarketError::Incarnation)?;
        if self.ask == 0
            || self.ask > MARKET_QUANTITY_MAX - 2 * NFT_FEE_CREDIT
            || self.expiry_height == 0
        {
            return Err(NftMarketError::Price);
        }
        Ok(())
    }
    pub fn id(self) -> ListingId {
        ListingId(NftMarketOpening::Definition(self).root().0)
    }
    pub fn item(self, owner: Address) -> Result<NftItem, NftMarketError> {
        self.validate()?;
        let item = NftItem {
            collection: self.collection,
            owner,
            metadata: self.metadata,
            serial: self.serial,
            unlock_height: 0,
        };
        NativeOpening::NftItem(item)
            .validate()
            .map_err(|_| NftMarketError::Owner)?;
        Ok(item)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListingState {
    pub listing: ListingId,
    pub collection: CollectionId,
    pub serial: u64,
    pub generation: u64,
    pub queue_root: Digest,
    pub registered_height: u64,
    pub request_count: u16,
    pub phase: PoolPhase,
}
impl ListingState {
    pub fn initial(d: ListingDefinition) -> Result<Self, NftMarketError> {
        d.validate()?;
        Ok(Self {
            listing: d.id(),
            collection: d.collection,
            serial: d.serial,
            generation: 0,
            queue_root: [0; 32],
            registered_height: 0,
            request_count: 0,
            phase: PoolPhase::Idle,
        })
    }
    pub fn validate(self) -> Result<(), NftMarketError> {
        if self.listing.0 == [0; 32] || self.collection.0 == [0; 32] || self.serial == 0 {
            return Err(NftMarketError::Identity);
        }
        match self.phase {
            PoolPhase::Idle
                if self.queue_root != [0; 32]
                    || self.registered_height != 0
                    || self.request_count != 0 =>
            {
                return Err(NftMarketError::Phase)
            }
            PoolPhase::Frozen
                if self.queue_root == [0; 32]
                    || self.registered_height == 0
                    || self.request_count == 0
                    || usize::from(self.request_count)
                        > super::market::queue::MAX_ROUND_REQUESTS =>
            {
                return Err(NftMarketError::Phase)
            }
            _ => (),
        }
        if self.phase == PoolPhase::Frozen {
            timeout_height(self.registered_height)?;
        }
        Ok(())
    }
    pub fn check_definition(self, d: ListingDefinition) -> Result<(), NftMarketError> {
        self.validate()?;
        d.validate()?;
        if self.listing != d.id()
            || self.collection != d.collection
            || self.serial != d.serial
            || (self.phase == PoolPhase::Frozen
                && self
                    .registered_height
                    .checked_add(1)
                    .is_none_or(|h| h >= d.expiry_height))
        {
            return Err(NftMarketError::Definition);
        }
        Ok(())
    }
    pub fn root(self) -> Address {
        NftMarketOpening::Listing(self).root()
    }
    pub fn round_id(self, context: NftRoundContext) -> Result<Digest, NftMarketError> {
        self.validate()?;
        context.validate()?;
        if self.phase != PoolPhase::Idle || self.generation == u64::MAX {
            return Err(NftMarketError::Phase);
        }
        let a = Address(self.listing.0).as_fields();
        let b = self.root().as_fields();
        let seed = Address(context.parent_block_id()).as_fields();
        Ok(hash(
            DomainTag::new(b"NMROUND1"),
            &[
                a[0],
                a[1],
                b[0],
                b[1],
                seed[0],
                seed[1],
                pack(context.height(), context.parent_alloc_counter()),
                Block128(0),
            ],
        ))
    }
    pub fn idle_view(mut self) -> Self {
        self.queue_root = [0; 32];
        self.registered_height = 0;
        self.request_count = 0;
        self.phase = PoolPhase::Idle;
        self
    }
    pub fn phase_at(self, height: u64) -> Result<RoundPhase, NftMarketError> {
        self.validate()?;
        match self.phase {
            PoolPhase::Idle => Ok(RoundPhase::Open),
            PoolPhase::Frozen if height < self.registered_height => Err(NftMarketError::Height),
            PoolPhase::Frozen if height == self.registered_height => Ok(RoundPhase::Registered),
            PoolPhase::Frozen if height < timeout_height(self.registered_height)? => {
                Ok(RoundPhase::Settlement)
            }
            PoolPhase::Frozen => Ok(RoundPhase::Refund),
        }
    }
    pub fn expired_recovery(self, d: ListingDefinition, height: u64) -> Result<(), NftMarketError> {
        self.check_definition(d)?;
        if height < d.expiry_height
            || (self.phase == PoolPhase::Frozen && self.phase_at(height)? != RoundPhase::Refund)
        {
            return Err(NftMarketError::Phase);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurchaseRequest {
    pub listing: ListingId,
    pub round: Digest,
    pub payer: Address,
    pub recipient: Address,
    pub budget: u64,
    pub registered_height: u64,
    pub profile: u64,
}
impl PurchaseRequest {
    pub fn validate(self) -> Result<(), NftMarketError> {
        if self.listing.0 == [0; 32]
            || self.round == [0; 32]
            || self.payer == Address([0; 32])
            || self.recipient == Address([0; 32])
            || self.profile != NFT_MARKET_PROFILE
        {
            return Err(NftMarketError::Identity);
        }
        if self.budget == 0 || self.budget > MARKET_QUANTITY_MAX - 2 * NFT_FEE_CREDIT {
            return Err(NftMarketError::Price);
        }
        timeout_height(self.registered_height)?;
        Ok(())
    }
    pub fn noid_value(self) -> Result<u64, NftMarketError> {
        self.budget
            .checked_add(NFT_FEE_CREDIT)
            .ok_or(NftMarketError::Funding)
    }
    pub fn root(self) -> Address {
        NftMarketOpening::Purchase(self).root()
    }
    pub fn check_round(
        self,
        d: ListingDefinition,
        parent: ListingState,
        context: NftRoundContext,
    ) -> Result<(), NftMarketError> {
        self.validate()?;
        context.validate()?;
        parent.check_definition(d)?;
        let height = context.height();
        if height.checked_add(1).is_none_or(|h| h >= d.expiry_height) {
            return Err(NftMarketError::Expired);
        }
        if self.listing != d.id()
            || self.round != parent.round_id(context)?
            || self.registered_height != height
            || self.budget < d.ask
        {
            return Err(NftMarketError::Funding);
        }
        Ok(())
    }
    /// Payer priority is independent of recipient, budget and carrier placement.
    pub fn payer_priority(self) -> Digest {
        let a = Address(self.round).as_fields();
        let b = self.payer.as_fields();
        hash(DomainTag::new(b"NMPRIOR1"), &[a[0], a[1], b[0], b[1]])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftOffer {
    pub collection: CollectionId,
    pub payer: Address,
    pub recipient: Address,
    /// Zero selects any one item from the collection.
    pub serial: u64,
    pub expiry_height: u64,
    pub price: u64,
    pub funding_creation_id: u64,
}
impl NftOffer {
    pub fn validate(self) -> Result<(), NftMarketError> {
        if self.collection.0 == [0; 32]
            || self.payer == Address([0; 32])
            || self.recipient == Address([0; 32])
            || self.funding_creation_id == 0
            || self.expiry_height == 0
        {
            return Err(NftMarketError::Identity);
        }
        if self.price == 0 || self.price > MARKET_QUANTITY_MAX - NFT_FEE_CREDIT {
            return Err(NftMarketError::Price);
        }
        Ok(())
    }
    pub fn noid_value(self) -> Result<u64, NftMarketError> {
        self.price
            .checked_add(NFT_FEE_CREDIT)
            .ok_or(NftMarketError::Funding)
    }
    pub fn root(self) -> Address {
        NftMarketOpening::Offer(self).root()
    }
    pub fn check_item(self, item: NftItem, height: u64) -> Result<(), NftMarketError> {
        self.validate()?;
        NativeOpening::NftItem(item)
            .validate()
            .map_err(|_| NftMarketError::Definition)?;
        if height >= self.expiry_height || height < item.unlock_height {
            return Err(NftMarketError::Expired);
        }
        if self.collection != item.collection || (self.serial != 0 && self.serial != item.serial) {
            return Err(NftMarketError::Definition);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NftMarketKind {
    Definition = 64,
    Listing = 65,
    Purchase = 66,
    Offer = 67,
}
impl NftMarketKind {
    pub const fn field_count(self) -> usize {
        match self {
            Self::Purchase => 12,
            _ => 8,
        }
    }
    pub const fn tag(self) -> DomainTag {
        DomainTag::new(match self {
            Self::Definition => b"NMDEF_21",
            Self::Listing => b"NMLIST21",
            Self::Purchase => b"NMBUY_21",
            Self::Offer => b"NMOFF_21",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftMarketOpening {
    Definition(ListingDefinition),
    Listing(ListingState),
    Purchase(PurchaseRequest),
    Offer(NftOffer),
}
impl NftMarketOpening {
    pub const fn kind(self) -> NftMarketKind {
        match self {
            Self::Definition(_) => NftMarketKind::Definition,
            Self::Listing(_) => NftMarketKind::Listing,
            Self::Purchase(_) => NftMarketKind::Purchase,
            Self::Offer(_) => NftMarketKind::Offer,
        }
    }
    pub fn validate(self) -> Result<(), NftMarketError> {
        match self {
            Self::Definition(d) => d.validate(),
            Self::Listing(s) => s.validate(),
            Self::Purchase(r) => r.validate(),
            Self::Offer(o) => o.validate(),
        }
    }
    pub fn noid_value(self) -> Result<u64, NftMarketError> {
        self.validate()?;
        match self {
            Self::Definition(_) => Ok(0),
            Self::Listing(_) => Ok(NFT_FEE_CREDIT),
            Self::Purchase(r) => r.noid_value(),
            Self::Offer(o) => o.noid_value(),
        }
    }
    pub fn fields(self) -> [Block128; 12] {
        let mut f = [Block128(0); 12];
        match self {
            Self::Definition(d) => {
                put(&mut f, 0, d.collection.0);
                put(&mut f, 2, d.seller.0);
                put(&mut f, 4, d.metadata);
                f[6] = pack(d.serial, d.source_creation_id);
                f[7] = pack(d.ask, d.expiry_height);
            }
            Self::Listing(s) => {
                put(&mut f, 0, s.listing.0);
                put(&mut f, 2, s.collection.0);
                f[4] = pack(s.serial, s.generation);
                put(&mut f, 5, s.queue_root);
                f[7] = Block128(
                    u128::from(s.registered_height)
                        | (u128::from(s.request_count) << 64)
                        | ((s.phase as u128) << 80),
                );
            }
            Self::Purchase(r) => {
                put(&mut f, 0, r.listing.0);
                put(&mut f, 2, r.round);
                put(&mut f, 4, r.payer.0);
                put(&mut f, 6, r.recipient.0);
                f[8] = pack(r.budget, r.registered_height);
                f[9] = Block128(u128::from(r.profile));
            }
            Self::Offer(o) => {
                put(&mut f, 0, o.collection.0);
                put(&mut f, 2, o.payer.0);
                put(&mut f, 4, o.recipient.0);
                f[6] = pack(o.serial, o.expiry_height);
                f[7] = pack(o.price, o.funding_creation_id);
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
    pub fn to_bytes(self) -> Result<Vec<u8>, NftMarketError> {
        self.validate()?;
        let mut b =
            Vec::with_capacity(NATIVE_OPENING_HEADER_BYTES + 16 * self.kind().field_count());
        b.extend_from_slice(NATIVE_OPENING_MAGIC);
        b.extend_from_slice(&NATIVE_OPENING_VERSION.to_le_bytes());
        b.extend_from_slice(&(self.kind() as u16).to_le_bytes());
        for x in &self.fields()[..self.kind().field_count()] {
            b.extend_from_slice(&x.0.to_le_bytes());
        }
        Ok(b)
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, NftMarketError> {
        if b.len() < NATIVE_OPENING_HEADER_BYTES
            || &b[..8] != NATIVE_OPENING_MAGIC
            || u16::from_le_bytes(b[8..10].try_into().unwrap()) != NATIVE_OPENING_VERSION
        {
            return Err(NftMarketError::Encoding);
        }
        let k = match u16::from_le_bytes(b[10..12].try_into().unwrap()) {
            64 => NftMarketKind::Definition,
            65 => NftMarketKind::Listing,
            66 => NftMarketKind::Purchase,
            67 => NftMarketKind::Offer,
            _ => return Err(NftMarketError::Kind),
        };
        if b.len() != NATIVE_OPENING_HEADER_BYTES + 16 * k.field_count() {
            return Err(NftMarketError::Encoding);
        }
        let f: Vec<_> = b[12..]
            .chunks_exact(16)
            .map(|x| Block128(u128::from_le_bytes(x.try_into().unwrap())))
            .collect();
        Self::from_fields(k, &f)
    }
    pub fn from_fields(k: NftMarketKind, f: &[Block128]) -> Result<Self, NftMarketError> {
        if f.len() != k.field_count() {
            return Err(NftMarketError::Encoding);
        }
        let value = match k {
            NftMarketKind::Definition => Self::Definition(ListingDefinition {
                collection: CollectionId(digest(f, 0)),
                seller: Address(digest(f, 2)),
                metadata: digest(f, 4),
                serial: f[6].0 as u64,
                source_creation_id: (f[6].0 >> 64) as u64,
                ask: f[7].0 as u64,
                expiry_height: (f[7].0 >> 64) as u64,
            }),
            NftMarketKind::Listing => Self::Listing(ListingState {
                listing: ListingId(digest(f, 0)),
                collection: CollectionId(digest(f, 2)),
                serial: f[4].0 as u64,
                generation: (f[4].0 >> 64) as u64,
                queue_root: digest(f, 5),
                registered_height: f[7].0 as u64,
                request_count: (f[7].0 >> 64) as u16,
                phase: match (f[7].0 >> 80) & 255 {
                    0 => PoolPhase::Idle,
                    1 => PoolPhase::Frozen,
                    _ => return Err(NftMarketError::Phase),
                },
            }),
            NftMarketKind::Purchase => Self::Purchase(PurchaseRequest {
                listing: ListingId(digest(f, 0)),
                round: digest(f, 2),
                payer: Address(digest(f, 4)),
                recipient: Address(digest(f, 6)),
                budget: f[8].0 as u64,
                registered_height: (f[8].0 >> 64) as u64,
                profile: f[9].0 as u64,
            }),
            NftMarketKind::Offer => Self::Offer(NftOffer {
                collection: CollectionId(digest(f, 0)),
                payer: Address(digest(f, 2)),
                recipient: Address(digest(f, 4)),
                serial: f[6].0 as u64,
                expiry_height: (f[6].0 >> 64) as u64,
                price: f[7].0 as u64,
                funding_creation_id: (f[7].0 >> 64) as u64,
            }),
        };
        value.validate()?;
        if value.fields()[..k.field_count()] != *f {
            return Err(NftMarketError::Padding);
        }
        Ok(value)
    }
}

pub fn timeout_height(height: u64) -> Result<u64, NftMarketError> {
    if height == 0 {
        return Err(NftMarketError::Height);
    }
    height
        .checked_add(MARKET_SETTLEMENT_WINDOW)
        .ok_or(NftMarketError::Height)
}
fn hash(tag: DomainTag, fields: &[Block128]) -> Digest {
    let mut s = Poseidon2bSponge::with_iv(capacity_iv(tag));
    for p in fields.chunks_exact(2) {
        s.absorb_pair(p[0], p[1]);
    }
    s.finalize_no_pad()
}
fn pack(a: u64, b: u64) -> Block128 {
    Block128(u128::from(a) | (u128::from(b) << 64))
}
fn put(f: &mut [Block128], at: usize, v: Digest) {
    f[at..at + 2].copy_from_slice(&Address(v).as_fields());
}
fn digest(f: &[Block128], at: usize) -> Digest {
    let mut d = [0; 32];
    d[..16].copy_from_slice(&f[at].0.to_le_bytes());
    d[16..].copy_from_slice(&f[at + 1].0.to_le_bytes());
    d
}
