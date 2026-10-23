// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::assets::nft_gallery::{Card, Filter};
use iced::widget::column;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Owned,
    Market,
    Listings,
    ForSale,
}

fn page(app: &App, market: bool, group: bool) -> usize {
    if group {
        if market {
            app.assets.nft_market_group_page
        } else {
            app.assets.nft_group_page
        }
    } else {
        app.assets.nft_browse(market).page
    }
}
fn go_page(market: bool, index: usize) -> Message {
    Message::Asset(if market {
        Action::MarketNftPage(index)
    } else {
        Action::NftPage(index)
    })
}
pub(super) fn controls(app: &App, market: bool, group: bool, count: usize) -> El<'_> {
    let state = &app.assets;
    let browse = state.nft_browse(market);
    let pages = count.div_ceil(12).max(1);
    let index = page(app, market, group).min(pages - 1);
    let mut previous = button(text("← PREV").size(12))
        .padding([8, 10])
        .style(|_, s| theme::button(ButtonKind::Secondary, s));
    let mut next = button(text("NEXT →").size(12))
        .padding([8, 10])
        .style(|_, s| theme::button(ButtonKind::Secondary, s));
    if index > 0 {
        previous = previous.on_press(go_page(market, index - 1));
    }
    if index + 1 < pages {
        next = next.on_press(go_page(market, index + 1));
    }
    let search = row![
        text_input("Search NFT, collection name or ID", &browse.search)
            .padding([10, 12])
            .size(13)
            .style(theme::text_input)
            .on_input(move |v| Message::Asset(Action::NftSearch(market, v))),
        previous,
        label(&format!("{} / {pages}", index + 1)),
        next
    ]
    .spacing(8)
    .align_y(Alignment::Center);
    let mut body = column![search].spacing(10);
    if !group {
        let mut filters = Row::new().spacing(8);
        for (name, filter) in [
            ("ALL", Filter::All),
            ("COLLECTIONS", Filter::Collections),
            ("SINGLE NFTS", Filter::Singles),
        ] {
            let active = browse.filter == filter;
            filters = filters.push(
                button(text(name).size(12))
                    .padding([8, 12])
                    .style(move |_, s| {
                        theme::button(
                            if active {
                                ButtonKind::CommandActive
                            } else {
                                ButtonKind::Command
                            },
                            s,
                        )
                    })
                    .on_press(Message::Asset(Action::NftFilter(market, filter))),
            );
        }
        body = body.push(filters);
    }
    body.into()
}
fn artwork(state: &State, card: &Card) -> El<'static> {
    let image = state
        .library
        .get(&card.metadata)
        .and_then(|b| b.image())
        .or_else(|| {
            card.fallback
                .and_then(|m| state.library.get(&m))
                .and_then(|b| b.image())
        })
        .filter(|_| state.external_data);
    match image {
        Some(image) => iced::widget::image(image.handle())
            .width(90)
            .height(90)
            .content_fit(iced::ContentFit::Contain)
            .into(),
        None => container(mark(
            if card.serial.is_some() { "N" } else { "C" },
            theme::PROOF,
        ))
        .width(90)
        .height(90)
        .center(90)
        .style(theme::surface)
        .into(),
    }
}
pub(super) fn grid<'a>(
    app: &'a App,
    market: bool,
    group: bool,
    cards: &[Card],
    compact: bool,
) -> El<'a> {
    let mode = if market {
        Mode::Market
    } else if app.assets.nft_background_page() == Page::Listings
        || group && app.assets.nft_group_listed_only
    {
        Mode::Listings
    } else {
        Mode::Owned
    };
    card_grid(app, mode, group, cards, compact)
}

fn card_grid<'a>(app: &'a App, mode: Mode, group: bool, cards: &[Card], compact: bool) -> El<'a> {
    let market = mode == Mode::Market;
    let mut grid = Column::new().spacing(12);
    let columns = if compact { 2 } else { 3 };
    let pages = cards.len().div_ceil(12).max(1);
    let index = if mode == Mode::ForSale {
        app.assets.nft_sale_browse.page
    } else {
        page(app, market, group)
    }
    .min(pages - 1);
    let visible = cards.iter().skip(index * 12).take(12).collect::<Vec<_>>();
    for chunk in visible.chunks(columns) {
        let mut row = Row::new().spacing(12);
        for card in chunk {
            let identity = match card.serial {
                Some(serial) => format!(
                    "{} · #{serial}",
                    crate::assets::live::short_id(&card.collection)
                ),
                None => crate::assets::live::short_id(&card.collection),
            };
            let bottom = if card.prepared {
                "PREPARED · COMPLETE NFT →".into()
            } else if mode == Mode::ForSale {
                "LIST FOR SALE →".into()
            } else if market || mode == Mode::Listings {
                match card.ask {
                    Some(ask) => format!(
                        "{}{} NOID",
                        if card.serial.is_none() { "FROM " } else { "" },
                        crate::model::format_micronoid(ask)
                    ),
                    None => "PENDING".into(),
                }
            } else if card.serial.is_some() {
                if card.ask.is_some() {
                    "LISTED".into()
                } else {
                    "OWNED".into()
                }
            } else {
                format!(
                    "{} NFTS{}",
                    card.count,
                    if card.creator { " · CREATOR" } else { "" }
                )
            };
            let mut body = column![
                row![
                    artwork(&app.assets, card),
                    column![value(card.title.clone()), label(&identity)]
                        .spacing(5)
                        .width(Length::Fill)
                ]
                .spacing(12)
                .align_y(Alignment::Center),
                text(bottom)
                    .size(13)
                    .color(if market { GREEN } else { CYAN })
            ]
            .spacing(12);
            if market && card.serial.is_none() {
                body = body.push(label(&format!("{} LISTED NFTS", card.count)));
            }
            let action = if mode == Mode::ForSale {
                Action::OfferNft(card.collection, card.serial.unwrap_or_default())
            } else if card.prepared {
                Action::ResumeNft(card.collection)
            } else if market {
                match card.serial {
                    Some(serial) => Action::SelectListing(card.collection, serial),
                    None => Action::SelectMarketCollection(card.collection),
                }
            } else {
                match card.serial {
                    Some(serial) => Action::SelectLiveNft(card.collection, serial),
                    None => Action::SelectNftCollection(card.collection),
                }
            };
            if mode == Mode::Listings {
                if let Some(serial) = card.serial {
                    if let Some((_, expiry)) = app
                        .assets
                        .live
                        .nfts
                        .get(&(card.collection, serial))
                        .and_then(|item| item.listing)
                    {
                        let height = app
                            .assets
                            .live
                            .display_key()
                            .map_or(0, |key| key.height.saturating_add(1));
                        body = body.push(label(&format!(
                            "{} · BLOCK {expiry}",
                            if height >= expiry {
                                "EXPIRED"
                            } else {
                                "EXPIRES"
                            }
                        )));
                    }
                    let details = button(body)
                        .padding(0)
                        .width(Length::Fill)
                        .style(|_, _| iced::widget::button::Style {
                            text_color: theme::TEXT,
                            ..Default::default()
                        })
                        .on_press(Message::Asset(Action::SelectLiveNft(
                            card.collection,
                            serial,
                        )));
                    let mut remove = button(text("REMOVE LISTING").size(12))
                        .padding([8, 12])
                        .style(|_, s| theme::button(ButtonKind::Secondary, s));
                    if !app.wallet_action_in_flight() && !card.pending && app.assets.live.complete {
                        remove = remove.on_press(Message::Asset(Action::RemoveNftListing(
                            card.collection,
                            serial,
                        )));
                    }
                    let content = column![details, remove].spacing(12);
                    let surface = container(content)
                        .padding(14)
                        .width(Length::Fill)
                        .style(|_| {
                            let style = theme::market_card(iced::widget::button::Status::Active);
                            container::Style {
                                background: style.background,
                                border: style.border,
                                shadow: style.shadow,
                                text_color: Some(style.text_color),
                                snap: true,
                            }
                        });
                    row = row.push(surface.width(Length::FillPortion(1)));
                    continue;
                }
            }
            let mut button = button(body)
                .width(Length::Fill)
                .padding(14)
                .style(|_, s| theme::market_card(s));
            if !app.wallet_action_in_flight()
                && (!card.pending || card.serial.is_none())
                && (mode != Mode::ForSale
                    || card
                        .serial
                        .is_some_and(|serial| app.assets.can_list_nft(card.collection, serial)))
            {
                button = button.on_press(Message::Asset(action));
            }
            row = row.push(container(button).width(Length::FillPortion(1)));
        }
        for _ in chunk.len()..columns {
            row = row.push(Space::new().width(Length::FillPortion(1)));
        }
        grid = grid.push(row);
    }
    if cards.is_empty() {
        let searching = if mode == Mode::ForSale {
            !app.assets.nft_sale_browse.search.trim().is_empty()
        } else {
            !app.assets.nft_browse(market).search.trim().is_empty()
                || !group && app.assets.nft_browse(market).filter != Filter::All
        };
        grid = grid.push(
            container(hint(if searching {
                "No NFTs match these filters."
            } else if group {
                "No NFTs to display in this collection."
            } else if mode == Mode::Listings {
                "Your listed NFTs appear here. Choose List NFT to offer one for sale."
            } else if mode == Mode::ForSale {
                "Available NFTs appear here after confirmation. Open My NFTs to view your items and pending sales."
            } else if market {
                "Listings appear here when NFTs are offered for sale."
            } else {
                "Your NFTs and collections appear here. Create an NFT or collection to get started."
            }))
            .padding(18)
            .style(theme::surface),
        );
    }
    grid.into()
}
pub(super) fn view(app: &App, market: bool, group: Option<[u8; 32]>, listed_only: bool) -> El<'_> {
    responsive(move |size| {
        let state = &app.assets;
        let cards = state.nft_cards(market, group, listed_only);
        let mut header = Row::new().spacing(12).align_y(Alignment::Center);
        header = header
            .push(
                column![
                    text(group.map_or_else(
                        || if market {
                            "MARKETPLACE".into()
                        } else if listed_only {
                            "MY LISTINGS".into()
                        } else {
                            "MY NFTS".into()
                        },
                        |id| state.collection_name(&id)
                    ))
                    .size(22),
                    label(if listed_only {
                        "Your sales, prices and expiry. Remove a listing to offer it again at a new price."
                    } else if market {
                        "NFTs listed for sale, grouped by collection."
                    } else {
                        "Your NFTs, grouped by collection."
                    })
                ]
                .spacing(6),
            )
            .push(space());
        if market || listed_only {
            header = header.push(control("LIST NFT", Action::ChooseNftToList, true));
        } else {
            header = header.push(go("CREATE NFT", Page::CreateNft, true));
        }
        let mut body = column![
            header,
            controls(app, market, group.is_some(), cards.len()),
            grid(app, market, group.is_some(), &cards, size.width < 880.0)
        ]
        .spacing(14);
        if let Some(notice) = &state.nft_notice {
            body = column![text(notice).size(13).color(GREEN), body].spacing(14);
        }
        if market && group.is_some() {
            body = column![go("← MARKETPLACE", Page::Marketplace, false), body].spacing(14);
        }
        if market {
            body = body.push(super::discovery::status(
                &state.listings,
                true,
                state.native_operations_enabled(),
            ));
        } else {
            body = column![live_heading(app), body].spacing(14);
            if let Some(error) = &state.live.error {
                body = body.push(text(error).size(12).color(theme::DANGER));
            }
            body = body.push(
                row![space(), control("REFRESH", Action::RefreshLive, false)]
                    .align_y(Alignment::Center),
            );
        }
        body.into()
    })
    .into()
}

pub(super) fn picker(app: &App) -> El<'_> {
    let state = &app.assets;
    let cards = state.nft_sale_cards();
    let browse = &state.nft_sale_browse;
    let pages = cards.len().div_ceil(12).max(1);
    let index = browse.page.min(pages - 1);
    let mut previous = button(text("← PREV").size(12))
        .padding([8, 10])
        .style(|_, s| theme::button(ButtonKind::Secondary, s));
    let mut next = button(text("NEXT →").size(12))
        .padding([8, 10])
        .style(|_, s| theme::button(ButtonKind::Secondary, s));
    if index > 0 {
        previous = previous.on_press(Message::Asset(Action::NftSalePage(index - 1)));
    }
    if index + 1 < pages {
        next = next.on_press(Message::Asset(Action::NftSalePage(index + 1)));
    }
    column![
        hint("Choose an NFT from this address. Set its NOID price, then review and confirm the sale."),
        text_input("Search your NFTs or collections", &browse.search).padding([10, 12]).size(13).style(theme::text_input)
            .on_input(|value| Message::Asset(Action::NftSaleSearch(value))),
        row![label(&format!("{} AVAILABLE", cards.len())), space(), previous, label(&format!("{} / {pages}", index+1)), next].spacing(8).align_y(Alignment::Center),
        card_grid(app, Mode::ForSale, false, &cards, true),
        control("MY NFTS", Action::Open(Page::Collection), false),
    ].spacing(12).into()
}
