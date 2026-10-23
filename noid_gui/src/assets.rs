// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use crate::model::Section;
pub mod activity;
pub mod catalog;
pub mod chart;
pub mod live;
pub mod media;
pub mod nft_batch;
pub mod nft_gallery;
pub mod nft_sales;
pub mod operations;
pub mod trading;

pub const DISCOVERY_PAGE_SIZE: usize = 12;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Currency {
    #[default]
    Noid,
    Token([u8; 32]),
}

impl std::fmt::Display for Currency {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Noid => formatter.write_str("NOID"),
            Self::Token(id) => write!(formatter, "TOKEN {}", live::short_id(id)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Holdings,
    Launchpad,
    Dex,
    Trade,
    CreateToken,
    TokenReview,
    OrderReview,
    TokenSend,
    Burn,
    Collection,
    Marketplace,
    Listings,
    NftDetail,
    CreateNft,
    NftMarketCollection,
    NftCollectionDetail,
    CreateNftCollection,
    MintNfts,
    NftSend,
    NftList,
    NftListPicker,
    NftBuy,
    NftBurn,
    NftCancel,
}

impl Page {
    pub fn is_dialog(self) -> bool {
        matches!(
            self,
            Self::TokenSend
                | Self::Burn
                | Self::NftSend
                | Self::NftList
                | Self::NftListPicker
                | Self::NftBuy
                | Self::NftBurn
                | Self::NftCancel
        )
    }

    pub fn is_nft(self) -> bool {
        matches!(
            self,
            Self::Collection
                | Self::Marketplace
                | Self::Listings
                | Self::NftDetail
                | Self::CreateNft
                | Self::NftMarketCollection
                | Self::NftCollectionDetail
                | Self::CreateNftCollection
                | Self::MintNfts
                | Self::NftSend
                | Self::NftList
                | Self::NftListPicker
                | Self::NftBuy
                | Self::NftBurn
                | Self::NftCancel
        )
    }
}

#[derive(Debug, Clone)]
pub enum Action {
    Open(Page),
    Name(String),
    Ticker(String),
    Supply(String),
    InitialBuy(String),
    Amount(String),
    Limit(String),
    Recipient(String),
    Search(String),
    NftSearch(bool, String),
    NftFilter(bool, nft_gallery::Filter),
    ChooseNftToList,
    OfferNft([u8; 32], u64),
    RemoveNftListing([u8; 32], u64),
    NftSaleSearch(String),
    NftSalePage(usize),
    SelectMarketCollection([u8; 32]),
    MarketNftPage(usize),
    MarketSearch(String),
    Discovery(catalog::Discovery),
    DiscoveryPage(usize),
    CatalogScroll(f32),
    Description(String),
    Website(String),
    OpenWebsite(String),
    Sell(bool),
    SelectToken(String),
    InspectToken(String),
    UseToken(String, Page),
    SelectNft { index: usize, owned: bool },
    NftName(String),
    SelectLiveToken([u8; 32]),
    UseLiveToken([u8; 32], Page),
    SelectLiveNft([u8; 32], u64),
    RefreshLive,
    ReviewLive,
    ConfirmLive,
    ResetLive,
    CloseTradeStatus,
    Currency(Currency),
    SelectMainOutput(u32),
    NativePage(usize),
    ChooseImage,
    RemoveImage,
    SelectMarket([u8; 32]),
    SelectListing([u8; 32], u64),
    RefreshCatalog(bool),
    ResumeNft([u8; 32]),
    SelectNftCollection([u8; 32]),
    MintCollection([u8; 32]),
    ChooseNftImages,
    NftBatchName(usize, String),
    RemoveNftImage(usize),
    RefreshNftCollections,
    NftPage(usize),
    ChartSpan(u64),
}

#[derive(Debug)]
pub struct State {
    pub live: live::State,
    pub operation: operations::State,
    pub media: media::Draft,
    pub library: media::library::Library,
    pub chart: chart::State,
    pub external_data: bool,
    pub markets: catalog::State,
    pub listings: catalog::State,
    pub nft_collections: catalog::State,
    pub nft_group: Option<[u8; 32]>,
    pub nft_group_listed_only: bool,
    pub nft_owned_browse: nft_gallery::Browse,
    pub nft_market_browse: nft_gallery::Browse,
    pub nft_listed_browse: nft_gallery::Browse,
    pub nft_sale_browse: nft_gallery::Browse,
    pub nft_action_home: Page,
    pub nft_notice: Option<String>,
    pub nft_batch: nft_batch::Draft,
    pub nft_group_page: usize,
    pub nft_market_group_page: usize,
    pub trade_notice: Option<String>,
    pub currency: Currency,
    pub native_output: Option<u32>,
    pub native_segment: Option<u8>,
    pub native_page: usize,
    pub token_page: Page,
    pub nft_page: Page,
    pub name: String,
    pub ticker: String,
    pub supply: String,
    pub initial_buy: String,
    pub amount: String,
    pub limit: String,
    pub recipient: String,
    pub search: String,
    pub launchpad: catalog::Browse,
    pub dex: catalog::Browse,
    pub token_home: Page,
    pub description: String,
    pub website: String,
    pub sell: bool,
    pub selected_token: String,
    pub selected_nft: usize,
    pub nft_owned: bool,
    pub nft_home: Page,
    pub nft_name: String,
    pub nft_collection: Option<[u8; 32]>,
}

impl State {
    pub fn new(preview: bool) -> Self {
        let mut state = Self {
            live: live::State::default(),
            operation: operations::State::default(),
            media: media::Draft::default(),
            library: media::library::Library::default(),
            chart: chart::State::default(),
            external_data: false,
            markets: catalog::State::new(catalog::Kind::Markets),
            listings: catalog::State::new(catalog::Kind::NftListings),
            nft_collections: catalog::State::new(catalog::Kind::Collections),
            nft_group: None,
            nft_group_listed_only: false,
            nft_owned_browse: Default::default(),
            nft_market_browse: Default::default(),
            nft_listed_browse: Default::default(),
            nft_sale_browse: Default::default(),
            nft_action_home: Page::NftDetail,
            nft_notice: None,
            nft_batch: nft_batch::Draft::default(),
            nft_group_page: 0,
            nft_market_group_page: 0,
            trade_notice: None,
            currency: Currency::Noid,
            native_output: None,
            native_segment: None,
            native_page: 0,
            token_page: Page::Holdings,
            nft_page: Page::Collection,
            name: if preview {
                "Orbit".into()
            } else {
                String::new()
            },
            ticker: if preview { "ORB".into() } else { String::new() },
            supply: if preview {
                "1000000".into()
            } else {
                "100000".into()
            },
            initial_buy: String::new(),
            amount: if preview { "200".into() } else { String::new() },
            limit: if preview {
                "0.025000".into()
            } else {
                String::new()
            },
            recipient: String::new(),
            search: String::new(),
            launchpad: catalog::Browse::default(),
            dex: catalog::Browse {
                filter: catalog::Discovery::Liquidity,
                ..Default::default()
            },
            token_home: Page::Holdings,
            description: String::new(),
            website: String::new(),
            sell: false,
            selected_token: "ORB".into(),
            selected_nft: 0,
            nft_owned: true,
            nft_home: Page::Collection,
            nft_name: if preview {
                "Contours #005".into()
            } else {
                String::new()
            },
            nft_collection: None,
        };
        if preview {
            let page = match std::env::var("NOID_GUI_PREVIEW_SCREEN").as_deref() {
                Ok("launchpad") => Page::Launchpad,
                Ok("dex") => Page::Dex,
                Ok("trade") => Page::Trade,
                Ok("create-token") => Page::CreateToken,
                Ok("token-review") => Page::TokenReview,
                Ok("order-review") => Page::OrderReview,
                Ok("token-send") => Page::TokenSend,
                Ok("burn") => Page::Burn,
                Ok("nfts") => Page::Collection,
                Ok("marketplace") => Page::Marketplace,
                Ok("listings") => Page::Listings,
                Ok("nft-detail") => Page::NftDetail,
                Ok("create-nft") => Page::CreateNft,
                Ok("nft-send") => Page::NftSend,
                Ok("nft-list") => Page::NftList,
                Ok("nft-buy") => Page::NftBuy,
                _ => Page::Holdings,
            };
            state.open(page);
            if page == Page::NftBuy {
                state.nft_owned = false;
                state.nft_home = Page::Marketplace;
            }
        }
        state
    }

    pub fn initial_section(&self, preview: bool) -> Section {
        if !preview || std::env::var("NOID_GUI_PREVIEW_SCREEN").map_or(true, |v| v == "main") {
            Section::Present
        } else if self.nft_page != Page::Collection
            || std::env::var("NOID_GUI_PREVIEW_SCREEN").as_deref() == Ok("nfts")
        {
            Section::Nfts
        } else {
            Section::Tokens
        }
    }

    fn open(&mut self, page: Page) {
        if page != Page::Trade {
            self.chart.deactivate();
        }
        self.nft_notice = None;
        self.trade_notice = None;
        if matches!(
            page,
            Page::NftSend | Page::NftList | Page::NftBurn | Page::NftCancel
        ) && page != self.nft_page
        {
            self.nft_action_home = self.nft_page;
        }
        let previous_token_page = self.token_page;
        if matches!(page, Page::Trade | Page::CreateToken)
            && matches!(
                self.token_page,
                Page::Holdings | Page::Launchpad | Page::Dex
            )
        {
            self.token_home = self.token_page;
        }
        let was_dialog = if page.is_nft() {
            self.nft_page
        } else {
            self.token_page
        }
        .is_dialog();
        self.media.cancel_loading();
        self.nft_batch.cancel_loading();
        if matches!(
            page,
            Page::CreateToken | Page::CreateNft | Page::CreateNftCollection
        ) {
            self.media.clear();
        }
        if matches!(page, Page::CreateNft | Page::CreateNftCollection) {
            self.nft_collection = None;
            self.nft_name.clear();
            self.description.clear();
            self.website.clear();
        }
        if page == Page::MintNfts {
            self.nft_batch.clear();
            if let Some(manifest) = self.nft_group.and_then(|id| self.collection_manifest(&id)) {
                let description = manifest.description.clone();
                let website = manifest.website.clone().unwrap_or_default();
                self.description = description;
                self.website = website;
            } else {
                self.description.clear();
                self.website.clear();
            }
        }
        if self.live.key.is_some()
            && matches!(
                page,
                Page::Trade
                    | Page::TokenSend
                    | Page::Burn
                    | Page::NftSend
                    | Page::NftList
                    | Page::NftBurn
                    | Page::NftCancel
                    | Page::NftBuy
            )
        {
            self.amount.clear();
            self.limit.clear();
            self.recipient.clear();
            if page == Page::Trade {
                self.sell = false;
            }
        }
        if page.is_nft() {
            if matches!(page, Page::Collection | Page::Marketplace | Page::Listings) {
                self.nft_home = page;
            }
            self.nft_page = page;
        } else {
            self.token_page = page;
        }
        if !page.is_dialog()
            && !was_dialog
            && page != Page::Trade
            && previous_token_page != Page::Trade
        {
            self.search.clear();
        }
    }

    pub fn update(&mut self, action: Action) {
        if matches!(
            action,
            Action::Amount(_) | Action::Limit(_) | Action::Sell(_)
        ) {
            self.trade_notice = None;
        }
        if !matches!(
            action,
            Action::Search(_)
                | Action::MarketSearch(_)
                | Action::CatalogScroll(_)
                | Action::SelectMainOutput(_)
                | Action::NativePage(_)
                | Action::ReviewLive
                | Action::ConfirmLive
                | Action::ChartSpan(_)
        ) {
            self.operation.edit();
        }
        match action {
            Action::ChartSpan(span) => self.chart.span = if span == 480 { 480 } else { 120 },
            Action::CloseTradeStatus => self.close_trade_status(),
            Action::Open(page) => self.open(page),
            Action::Name(value) => self.name = value,
            Action::Ticker(value) => self.ticker = value,
            Action::Supply(value) => self.supply = value,
            Action::InitialBuy(value) => self.initial_buy = value,
            Action::Amount(value) => self.amount = value,
            Action::Limit(value) => self.limit = value,
            Action::Recipient(value) => self.recipient = value,
            Action::NftSearch(market, value) => {
                let b = self.nft_browse_mut(market);
                b.search = value;
                b.page = 0;
                self.nft_group_page = 0;
                self.nft_market_group_page = 0;
            }
            Action::NftFilter(market, filter) => {
                let b = self.nft_browse_mut(market);
                b.filter = filter;
                b.page = 0;
            }
            Action::MarketNftPage(page) => {
                if self.nft_page == Page::NftMarketCollection {
                    self.nft_market_group_page = page;
                } else {
                    self.nft_market_browse.page = page;
                }
            }
            Action::SelectMarketCollection(id) => {
                self.nft_group = Some(id);
                self.nft_market_group_page = 0;
                self.open(Page::NftMarketCollection);
            }
            Action::ChooseNftToList => {
                self.nft_home = self.nft_background_page();
                self.nft_sale_browse = Default::default();
                self.open(Page::NftListPicker);
            }
            Action::OfferNft(id, serial) => {
                if self.can_list_nft(id, serial) {
                    self.live.selected_nft = Some((id, serial));
                    self.open(Page::NftList);
                }
            }
            Action::RemoveNftListing(id, serial) => self.remove_nft_listing(id, serial),
            Action::NftSaleSearch(value) => {
                self.nft_sale_browse.search = value;
                self.nft_sale_browse.page = 0;
            }
            Action::NftSalePage(page) => self.nft_sale_browse.page = page,
            Action::Search(value) => {
                self.search = value;
            }
            Action::MarketSearch(value) => {
                let browser = self.market_browser_mut();
                browser.search = value;
                browser.page = 0;
                browser.scroll = 0.0;
            }
            Action::Discovery(value) => {
                if self.token_page == Page::Dex && value == catalog::Discovery::Graduated {
                    return;
                }
                let browser = self.market_browser_mut();
                browser.filter = value;
                browser.page = 0;
                browser.scroll = 0.0;
            }
            Action::DiscoveryPage(value) => {
                let last = self
                    .discovery_markets()
                    .len()
                    .div_ceil(DISCOVERY_PAGE_SIZE)
                    .saturating_sub(1);
                let browser = self.market_browser_mut();
                browser.page = value.min(last);
                browser.scroll = 0.0;
            }
            Action::CatalogScroll(value) => {
                if matches!(self.token_page, Page::Launchpad | Page::Dex) && value.is_finite() {
                    self.market_browser_mut().scroll = value.clamp(0.0, 1.0);
                }
            }
            Action::Description(value) => self.description = value,
            Action::Website(value) => self.website = value,
            Action::OpenWebsite(_) => {}
            Action::Sell(value) => {
                self.sell = value;
                if self.live.key.is_some() {
                    self.amount.clear();
                    self.limit.clear();
                    return;
                }
                self.limit = match self.selected_token.as_str() {
                    "MOSS" => {
                        if value {
                            "0.006000"
                        } else {
                            "0.006400"
                        }
                    }
                    "EMBER" => {
                        if value {
                            "0.018000"
                        } else {
                            "0.019000"
                        }
                    }
                    _ => {
                        if value {
                            "0.024000"
                        } else {
                            "0.025000"
                        }
                    }
                }
                .into();
            }
            Action::InspectToken(value) => self.selected_token = value,
            Action::SelectToken(value) => {
                self.selected_token = value;
                self.open(Page::TokenSend);
            }
            Action::UseToken(value, page) => {
                self.selected_token = value;
                if page == Page::Trade {
                    self.limit = match self.selected_token.as_str() {
                        "MOSS" => "0.006400",
                        "EMBER" => "0.019000",
                        _ => "0.025000",
                    }
                    .into();
                    self.sell = false;
                }
                self.open(page);
            }
            Action::SelectNft { index, owned } => {
                self.selected_nft = index;
                self.nft_owned = owned;
                self.open(Page::NftDetail);
            }
            Action::NftName(value) => self.nft_name = value,
            Action::SelectLiveToken(id) => self.live.selected_asset = Some(id),
            Action::UseLiveToken(id, page) => {
                if (self.live.tokens.contains_key(&id)
                    || page == Page::Trade && self.markets.markets.contains_key(&id))
                    && matches!(page, Page::TokenSend | Page::Burn | Page::Trade)
                {
                    self.live.selected_asset = Some(id);
                    self.open(page);
                }
            }
            Action::SelectLiveNft(collection, serial) => {
                if matches!(
                    self.nft_page,
                    Page::NftCollectionDetail
                        | Page::NftMarketCollection
                        | Page::Marketplace
                        | Page::Listings
                        | Page::Collection
                ) {
                    self.nft_home = self.nft_page;
                }
                self.live.selected_nft = Some((collection, serial));
                self.open(Page::NftDetail);
            }
            Action::RefreshLive => self.live.retry(),
            Action::ReviewLive | Action::ConfirmLive | Action::ResetLive => {}
            Action::Currency(currency) => {
                if let Currency::Token(id) = currency {
                    if !self.live.has_snapshot()
                        || !self.live.tokens.get(&id).is_some_and(|t| t.units > 0)
                    {
                        return;
                    }
                    self.live.selected_asset = Some(id);
                    self.open(Page::TokenSend);
                }
                self.currency = currency;
                self.native_output = None;
                self.native_segment = None;
                self.native_page = 0;
                self.amount.clear();
                self.recipient.clear();
            }
            Action::SelectMainOutput(slot) => {
                if self
                    .main_token()
                    .is_some_and(|token| token.carriers.iter().any(|output| output.slot == slot))
                {
                    self.native_output = Some(slot);
                }
            }
            Action::NativePage(page) => self.native_page = page,
            Action::ChooseImage => {}
            Action::ChooseNftImages => {}
            Action::RefreshNftCollections => self.nft_collections.retry(),
            Action::NftPage(index) => {
                if self.nft_page == Page::NftCollectionDetail {
                    self.nft_group_page = index;
                } else {
                    self.nft_browse_mut(false).page = index;
                }
            }
            Action::SelectNftCollection(id) => {
                if self.live.collections.contains_key(&id)
                    || self.nft_collections.collections.contains_key(&id)
                    || self.live.nfts.values().any(|item| item.collection == id)
                {
                    self.nft_group_listed_only = self.nft_page == Page::Listings;
                    self.nft_group = Some(id);
                    self.nft_group_page = 0;
                    self.open(Page::NftCollectionDetail);
                }
            }
            Action::MintCollection(id) => {
                self.nft_group_listed_only = false;
                if self.live.collections.get(&id).is_some_and(|collection| {
                    !collection.reserved && collection.issued < collection.maximum
                }) {
                    self.nft_group = Some(id);
                    self.open(Page::MintNfts);
                }
            }
            Action::NftBatchName(index, name) => {
                if let Some(item) = self.nft_batch.items.get_mut(index) {
                    item.name = Some(name);
                }
            }
            Action::RemoveNftImage(index) => {
                if index < self.nft_batch.items.len() {
                    self.nft_batch.items.remove(index);
                }
            }
            Action::RemoveImage => self.media.clear(),
            Action::SelectMarket(asset) => {
                if !self.markets.markets.contains_key(&asset) {
                    return;
                }
                let changed = self.live.selected_asset != Some(asset);
                self.live.selected_asset = Some(asset);
                if self.token_page != Page::Trade {
                    self.open(Page::Trade);
                } else if changed {
                    self.amount.clear();
                    self.limit.clear();
                    self.sell = false;
                }
            }
            Action::SelectListing(collection, serial) => {
                self.nft_home = if self.nft_page == Page::NftMarketCollection {
                    Page::NftMarketCollection
                } else {
                    Page::Marketplace
                };
                if self
                    .live
                    .nfts
                    .get(&(collection, serial))
                    .is_some_and(|item| item.listing.is_some())
                {
                    self.live.selected_nft = Some((collection, serial));
                    self.open(Page::NftDetail);
                    return;
                }
                self.listings.selected_listing = Some((collection, serial));
                self.open(Page::NftBuy);
            }
            Action::RefreshCatalog(nft) => {
                if nft {
                    self.listings.retry();
                } else {
                    self.markets.retry();
                }
            }
            Action::ResumeNft(collection) => {
                if self
                    .live
                    .collections
                    .get(&collection)
                    .is_some_and(live::Collection::unfinished_nft)
                {
                    self.open(Page::CreateNft);
                    self.nft_collection = Some(collection);
                }
            }
        }
    }

    pub fn token_matches(&self, id: &[u8; 32], search: &str) -> bool {
        hex::encode(id).contains(search)
            || self
                .markets
                .markets
                .get(id)
                .and_then(|market| self.library.manifest(&market.metadata))
                .filter(|manifest| manifest.kind == media::Kind::Token)
                .is_some_and(|manifest| {
                    format!(
                        "{} {}",
                        manifest.name,
                        manifest.symbol.as_deref().unwrap_or_default()
                    )
                    .to_lowercase()
                    .contains(search)
                })
    }

    pub fn discovery_markets(&self) -> Vec<&catalog::Market> {
        use catalog::{Discovery, Phase};
        let browser = self.market_browser();
        let search = browser.search.trim().to_lowercase();
        let dex = self.token_page == Page::Dex;
        let mut markets: Vec<_> = self
            .markets
            .markets
            .values()
            .filter(|market| {
                let phase = if dex || browser.filter == Discovery::Graduated {
                    Phase::Dex
                } else {
                    Phase::Curve
                };
                market.phase == phase && self.token_matches(&market.id, &search)
            })
            .collect();
        markets.sort_by(|a, b| {
            let price = (u128::from(b.price_numerator) * u128::from(a.price_denominator))
                .cmp(&(u128::from(a.price_numerator) * u128::from(b.price_denominator)));
            match browser.filter {
                Discovery::Gainers => price,
                Discovery::Liquidity => b.noid.cmp(&a.noid),
                _ => std::cmp::Ordering::Equal,
            }
            .then_with(|| b.created_order.cmp(&a.created_order))
            .then_with(|| a.id.cmp(&b.id))
        });
        markets
    }

    pub fn discovery_page_markets(&self) -> Vec<&catalog::Market> {
        let markets = self.discovery_markets();
        let pages = markets.len().div_ceil(DISCOVERY_PAGE_SIZE).max(1);
        markets
            .into_iter()
            .skip(self.market_browser().page.min(pages - 1) * DISCOVERY_PAGE_SIZE)
            .take(DISCOVERY_PAGE_SIZE)
            .collect()
    }

    pub fn market_browser(&self) -> &catalog::Browse {
        if self.token_page == Page::Dex {
            &self.dex
        } else {
            &self.launchpad
        }
    }

    fn market_browser_mut(&mut self) -> &mut catalog::Browse {
        if self.token_page == Page::Dex {
            &mut self.dex
        } else {
            &mut self.launchpad
        }
    }

    pub fn token_tab(&self) -> Page {
        match self.token_page {
            Page::Trade | Page::OrderReview => {
                match self
                    .live
                    .selected_asset
                    .and_then(|id| self.markets.markets.get(&id))
                {
                    Some(market) if market.phase == catalog::Phase::Curve => Page::Launchpad,
                    Some(_) => Page::Dex,
                    None if self.token_home == Page::Launchpad => Page::Launchpad,
                    None => Page::Dex,
                }
            }
            Page::TokenReview => Page::CreateToken,
            Page::TokenSend | Page::Burn => Page::Holdings,
            page => page,
        }
    }

    pub fn main_token(&self) -> Option<&live::Token> {
        match self.currency {
            Currency::Noid => None,
            Currency::Token(id) => self.live.tokens.get(&id),
        }
    }

    pub fn maximum_token_amount(&self) -> Option<String> {
        if !self.live.has_snapshot()
            || self.operation.submitting()
            || !matches!(self.token_page, Page::TokenSend | Page::Burn)
                && !(self.token_page == Page::Trade && self.sell)
        {
            return None;
        }
        let units = self.live.spendable_units(self.live.operation_asset()?);
        (units > 0).then(|| live::units(units))
    }

    pub fn navigate(&mut self, section: Section) {
        if self.operation.submitting() {
            return;
        }
        self.operation.edit();
        self.chart.deactivate();
        self.media.cancel_loading();
        self.nft_batch.cancel_loading();
        self.amount.clear();
        self.limit.clear();
        self.recipient.clear();
        match section {
            Section::Tokens => self.token_page = Page::Holdings,
            Section::Nfts => {
                self.nft_page = Page::Collection;
                self.nft_home = Page::Collection;
            }
            _ => {}
        }
    }

    pub fn account_changed(&mut self) {
        self.chart.deactivate();
        self.trade_notice = None;
        self.media.clear();
        self.nft_collection = None;
        self.nft_group = None;
        self.nft_group_listed_only = false;
        self.nft_owned_browse = Default::default();
        self.nft_market_browse = Default::default();
        self.nft_listed_browse = Default::default();
        self.nft_sale_browse = Default::default();
        self.nft_action_home = Page::NftDetail;
        self.nft_notice = None;
        self.nft_batch.clear();
        self.nft_group_page = 0;
        self.nft_market_group_page = 0;
        self.nft_name.clear();
        self.listings.selected_listing = None;
        self.currency = Currency::Noid;
        self.native_output = None;
        self.native_segment = None;
        self.native_page = 0;
        self.live.selected_asset = None;
        self.live.selected_nft = None;
        self.navigate(Section::Tokens);
        self.navigate(Section::Nfts);
    }

    pub fn native_operations_enabled(&self) -> bool {
        self.live
            .protocol
            .as_ref()
            .is_some_and(|protocol| protocol.active_at_next_block && protocol.runtime_available)
    }

    pub fn native_request(&self, nft: bool) -> Result<operations::Request, String> {
        use operations::{parse_amount, Request};
        let key = self
            .live
            .key
            .as_ref()
            .ok_or("The wallet address is not loaded.")?;
        if !self.live.complete || self.live.error.is_some() {
            return Err("Wait for confirmed holdings to finish loading.".into());
        }
        if !self.native_operations_enabled() {
            return Err("Native operations are not active on this node.".into());
        }
        let recipient = || {
            let value = self.recipient.trim();
            if value.is_empty() {
                Err("Enter a recipient address.".to_owned())
            } else {
                Ok(value.to_owned())
            }
        };
        if !nft {
            if self.token_page == Page::CreateToken {
                let supply = self.supply.replace([',', ' '], "");
                let whole = supply
                    .parse::<u64>()
                    .map_err(|_| "Enter a whole number of tokens.")?;
                noid_tx::native_assets::launch::launch_supply_from_whole(whole)
                    .map_err(|_| "Choose a fixed supply of at least 100,000 tokens within the native supply limit.")?;
                let initial_buy_units = self.initial_purchase()?.0;
                if initial_buy_units.is_some() && !self.supports_initial_purchase() {
                    return Err(
                        "The connected node does not support an initial creator purchase.".into(),
                    );
                }
                return Ok(Request::CreateToken {
                    whole_tokens: whole.to_string(),
                    initial_buy_units,
                    metadata_hash: self
                        .creation_media()?
                        .ok_or("Add the token details.")?
                        .hash()?,
                });
            }
            let asset = self.live.operation_asset().ok_or("Select a token.")?;
            let asset_id = hex::encode(asset);
            let units = parse_amount(&self.amount)?;
            return match self.token_page {
                Page::TokenSend => Ok(Request::TransferToken {
                    asset_id,
                    units,
                    recipient: recipient()?,
                }),
                Page::Burn => Ok(Request::BurnToken { asset_id, units }),
                Page::Trade => Ok(Request::Trade {
                    asset_id,
                    buy: !self.sell,
                    gross_input: units,
                    minimum_output: if self.limit.trim().is_empty() {
                        None
                    } else {
                        Some(parse_amount(&self.limit)?)
                    },
                    slippage_bps: Some(trading::DEFAULT_SLIPPAGE_BPS),
                    valid_until: None,
                }),
                _ => Err("Choose a token operation.".into()),
            };
        }
        if self.nft_page == Page::CreateNftCollection {
            return Ok(Request::CreateCollection {
                maximum_items: u64::MAX.to_string(),
                metadata_hash: self.collection_creation_media()?.hash()?,
            });
        }
        if self.nft_page == Page::MintNfts {
            let id = self.nft_group.ok_or("Choose a collection.")?;
            self.mintable_collection(&id)?;
            return Ok(Request::MintNfts {
                collection_id: hex::encode(id),
                metadata_hashes: self
                    .nft_batch_media()?
                    .iter()
                    .map(|bundle| bundle.hash())
                    .collect::<Result<_, _>>()?,
            });
        }
        if self.nft_page == Page::CreateNft {
            let metadata_hash = self.nft_creation_media()?.hash()?;
            return match self.nft_collection {
                None => Ok(Request::CreateCollection {
                    maximum_items: "1".into(),
                    metadata_hash,
                }),
                Some(id) => {
                    let collection = self
                        .live
                        .collections
                        .get(&id)
                        .ok_or("The prepared NFT is not at this address.")?;
                    if !collection.unfinished_nft() {
                        return Err(
                            "This NFT is already created or has a pending operation.".into()
                        );
                    }
                    if metadata_hash != hex::encode(collection.metadata) {
                        return Err("The NFT details differ from its prepared identity. Restore the saved details before continuing.".into());
                    }
                    Ok(Request::MintNft {
                        collection_id: hex::encode(id),
                        metadata_hash,
                    })
                }
            };
        }
        if self.nft_page == Page::NftBuy {
            if !self.listings.complete
                || self.listings.error.is_some()
                || self.listings.key.as_ref() != Some(key)
            {
                return Err("Wait for the NFT market to finish loading.".into());
            }
            let listing = self
                .listings
                .selected_listing
                .and_then(|id| self.listings.listings.get(&id))
                .ok_or("Select a listed NFT.")?;
            if !listing.ready || listing.reserved {
                return Err("This NFT already has a pending operation.".into());
            }
            if key
                .height
                .checked_add(1)
                .is_none_or(|height| height >= listing.expiry)
            {
                return Err("This NFT listing has expired.".into());
            }
            return Ok(Request::BuyNft {
                collection_id: hex::encode(listing.collection),
                serial: listing.serial.to_string(),
                maximum_ask_micronoid: listing.ask.to_string(),
            });
        }
        let identity = self.live.selected_nft.ok_or("Select an NFT.")?;
        let item = self
            .live
            .nfts
            .get(&identity)
            .ok_or("The selected NFT is no longer at this address.")?;
        if item.reserved {
            return Err("This NFT already has a pending operation.".into());
        }
        if item.unlock_height > key.height.saturating_add(1) {
            return Err(format!(
                "This NFT is locked until block {}.",
                item.unlock_height
            ));
        }
        let collection_id = hex::encode(identity.0);
        let serial = identity.1.to_string();
        if !matches!(self.nft_page, Page::NftCancel) && item.listing.is_some() {
            return Err("Cancel the listing before sending or burning this NFT.".into());
        }
        match self.nft_page {
            Page::NftSend => Ok(Request::TransferNft {
                collection_id,
                serial,
                recipient: recipient()?,
            }),
            Page::NftBurn => Ok(Request::BurnNft {
                collection_id,
                serial,
            }),
            Page::NftList => Ok(Request::ListNft {
                collection_id,
                serial,
                ask_micronoid: parse_amount(&self.amount)?,
                expiry_height: key
                    .height
                    .checked_add(2881)
                    .ok_or("Block height exceeds its limit.")?,
            }),
            Page::NftCancel if item.listing.is_some() => Ok(Request::CancelListing {
                collection_id,
                serial,
            }),
            _ => Err("Choose an NFT operation.".into()),
        }
    }

    pub fn initial_purchase(&self) -> Result<(Option<String>, u64), String> {
        let supply = self
            .supply
            .replace([',', ' '], "")
            .parse::<u64>()
            .map_err(|_| "Enter a whole number of tokens.")?;
        let supply = noid_tx::native_assets::launch::launch_supply_from_whole(supply)
            .map_err(|e| e.to_string())?;
        let units = operations::parse_optional_amount(&self.initial_buy)?;
        let quantity = units
            .as_deref()
            .map(|v| v.parse::<u64>())
            .transpose()
            .map_err(|_| "Initial purchase exceeds its limit.")?
            .unwrap_or(0);
        let cost = noid_tx::native_assets::launch::curve_cash_for_supply(supply, quantity)
            .map_err(|_| {
                "The initial purchase can use up to the 60% curve allocation.".to_string()
            })?;
        Ok((units, cost))
    }

    pub fn supports_initial_purchase(&self) -> bool {
        self.live
            .protocol
            .as_ref()
            .is_some_and(|protocol| protocol.initial_creator_purchase)
    }

    pub fn creation_media(&self) -> Result<Option<media::Bundle>, String> {
        if self.token_page != Page::CreateToken {
            return Ok(None);
        }
        if self.media.loading {
            return Err("Wait for the image to finish loading.".into());
        }
        media::Bundle::new(
            media::Kind::Token,
            &self.name,
            Some(&self.ticker),
            &self.description,
            self.media.image.clone(),
        )?
        .with_website(&self.website)
        .map(Some)
    }

    pub fn nft_creation_media(&self) -> Result<media::Bundle, String> {
        if self.media.loading {
            return Err("Wait for the NFT details to finish loading.".into());
        }
        media::Bundle::new(
            media::Kind::Nft,
            &self.nft_name,
            None,
            &self.description,
            self.media.image.clone(),
        )?
        .with_website(&self.website)
    }

    pub fn restore_nft_media(
        &mut self,
        collection: [u8; 32],
        bundle: media::Bundle,
    ) -> Result<(), String> {
        let current = self
            .live
            .collections
            .get(&collection)
            .ok_or("The prepared NFT is not at this address.")?;
        if !current.unfinished_nft()
            || bundle.manifest().kind != media::Kind::Nft
            || bundle.hash()? != hex::encode(current.metadata)
            || self.nft_page != Page::CreateNft
            || self.nft_collection != Some(collection)
        {
            return Err(
                "The prepared NFT or its details changed. Refresh before continuing.".into(),
            );
        }
        self.nft_name = bundle.manifest().name.clone();
        self.description = bundle.manifest().description.clone();
        self.website = bundle.manifest().website.clone().unwrap_or_default();
        self.media.image = bundle.image();
        Ok(())
    }

    /// Continue only after the exact prepared identity appears in current State.
    pub fn reconcile_nft_creation(&mut self) -> bool {
        use operations::{Phase, Request};
        if self.nft_page != Page::CreateNft
            || !self.live.complete
            || self.live.error.is_some()
            || self.operation.phase != Phase::Submitted
        {
            return false;
        }
        let Some(key) = &self.live.key else {
            return false;
        };
        let Some(context) = &self.operation.context else {
            return false;
        };
        if context.owner != key.owner || context.key_index != key.key_index {
            return false;
        }
        let Some(preview) = &self.operation.preview else {
            return false;
        };
        let Some(id) = preview
            .collection_id
            .as_ref()
            .and_then(|id| hex::decode(id).ok())
            .and_then(|id| id.try_into().ok())
        else {
            return false;
        };
        match &preview.request {
            Request::CreateCollection {
                maximum_items,
                metadata_hash,
            } if maximum_items == "1" => {
                if self.live.collections.get(&id).is_none_or(|collection| {
                    !collection.unfinished_nft()
                        || hex::encode(collection.metadata) != *metadata_hash
                }) || self
                    .nft_creation_media()
                    .and_then(|bundle| bundle.hash())
                    .as_ref()
                    != Ok(metadata_hash)
                {
                    return false;
                }
                self.nft_collection = Some(id);
                self.operation.edit();
                true
            }
            Request::MintNft { metadata_hash, .. } => {
                let Some(serial) = preview
                    .serial
                    .as_ref()
                    .and_then(|serial| serial.parse::<u64>().ok())
                else {
                    return false;
                };
                if self
                    .live
                    .nfts
                    .get(&(id, serial))
                    .is_some_and(|item| hex::encode(item.metadata) == *metadata_hash)
                {
                    self.live.selected_nft = Some((id, serial));
                    self.nft_page = Page::NftDetail;
                    self.nft_home = Page::Collection;
                }
                false
            }
            _ => false,
        }
    }

    pub fn minimum_backing(&self) -> Option<u64> {
        let supply = self.supply.replace([',', ' '], "").parse::<u64>().ok()?;
        let units = noid_tx::native_assets::launch::launch_supply_from_whole(supply).ok()?;
        noid_tx::asset_backing::TokenDenomination::new(noid_tx::native_assets::TOKEN_DECIMALS)
            .ok()?
            .minimum_backing(units)
            .ok()
    }

    pub fn back_page(&self, nft: bool) -> Option<Page> {
        if nft {
            match self.nft_page {
                Page::NftCollectionDetail => Some(if self.nft_group_listed_only {
                    Page::Listings
                } else {
                    Page::Collection
                }),
                Page::CreateNftCollection => Some(Page::CreateNft),
                Page::NftMarketCollection => Some(Page::Marketplace),
                Page::MintNfts => Some(Page::NftCollectionDetail),
                Page::NftDetail | Page::CreateNft => Some(self.nft_home),
                Page::NftBuy => Some(self.nft_home),
                Page::NftListPicker => Some(self.nft_home),
                Page::NftSend | Page::NftList | Page::NftBurn | Page::NftCancel => {
                    Some(self.nft_action_home)
                }
                _ => None,
            }
        } else {
            match self.token_page {
                Page::TokenReview => Some(Page::CreateToken),
                Page::CreateToken | Page::Trade => Some(self.token_home),
                Page::OrderReview => Some(Page::Trade),
                Page::TokenSend | Page::Burn => Some(Page::Holdings),
                _ => None,
            }
        }
    }
}
