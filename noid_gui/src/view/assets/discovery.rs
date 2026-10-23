// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::assets::catalog::{Phase, State as Catalog};
use iced::widget::column;

pub(super) fn status(catalog: &Catalog, nft: bool, active: bool) -> El<'static> {
    let note = if let Some(error) = &catalog.error {
        error.clone()
    } else if catalog.complete || !active {
        "Current State · verified by your local node".into()
    } else if catalog.has_snapshot() {
        "Updating current State…".into()
    } else {
        "Loading current State…".into()
    };
    row![
        text(note).size(12).color(if catalog.error.is_some() {
            theme::DANGER
        } else {
            DIM
        }),
        space(),
        control("REFRESH", Action::RefreshCatalog(nft), false)
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into()
}

pub(super) fn markets(app: &App, compact: bool) -> El<'_> {
    let state = &app.assets;
    if matches!(state.token_page, Page::Launchpad | Page::Dex) {
        return catalogue(app, compact);
    }
    let back = state.back_page(false).unwrap_or(Page::Dex);
    let caption = match back {
        Page::Launchpad => "← BACK TO LAUNCHPAD",
        Page::Dex => "← BACK TO DEX",
        _ => "← BACK TO MY TOKENS",
    };
    let mut back_button = button(text(caption).size(13))
        .padding([8, 12])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if !app.wallet_action_in_flight() {
        back_button = back_button.on_press(Message::Asset(Action::Open(back)));
    }
    let market = state
        .live
        .selected_asset
        .and_then(|id| state.markets.markets.get(&id));
    let Some(market) = market else {
        return column![
            back_button,
            tagged(
                "MARKET",
                CYAN,
                column![
                    hint("This market is unavailable in the current State."),
                    status(&state.markets, false, state.native_operations_enabled()),
                ]
                .spacing(12)
            ),
        ]
        .spacing(GAP)
        .into();
    };
    let heading = row![
        back_button,
        space(),
        text(if market.phase == Phase::Curve {
            "LAUNCHPAD · BONDING CURVE"
        } else {
            "DEX · PERMANENT LIQUIDITY"
        })
        .size(12)
        .color(GREEN),
    ]
    .spacing(12)
    .align_y(Alignment::Center);
    let overview = column![chart::view(app, market), token_information(app, market)]
        .spacing(GAP)
        .into();
    column![
        heading,
        split(overview, operations::view(app, false), compact)
    ]
    .spacing(GAP)
    .into()
}

fn catalogue(app: &App, compact: bool) -> El<'_> {
    use crate::assets::catalog::Discovery;
    let state = &app.assets;
    let launchpad = state.token_page == Page::Launchpad;
    let browser = state.market_browser();
    let markets = state.discovery_markets();
    let pages = markets
        .len()
        .div_ceil(crate::assets::DISCOVERY_PAGE_SIZE)
        .max(1);
    let page = browser.page.min(pages - 1);
    let choices = if launchpad {
        [
            ("NEW", Discovery::New),
            ("TOP GAINERS", Discovery::Gainers),
            ("GRADUATED", Discovery::Graduated),
        ]
    } else {
        [
            ("LIQUIDITY", Discovery::Liquidity),
            ("TOP GAINERS", Discovery::Gainers),
            ("NEWEST", Discovery::New),
        ]
    };
    let mut filters = Row::new().spacing(6);
    for (caption, filter) in choices {
        filters = filters.push(control(
            caption,
            Action::Discovery(filter),
            browser.filter == filter,
        ));
    }
    let mut previous = button(text("← PREV").size(12))
        .padding([7, 10])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    let mut next = button(text("NEXT →").size(12))
        .padding([7, 10])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if page > 0 {
        previous = previous.on_press(Message::Asset(Action::DiscoveryPage(page - 1)));
    }
    if page + 1 < pages {
        next = next.on_press(Message::Asset(Action::DiscoveryPage(page + 1)));
    }
    let pager = row![previous, label(&format!("{} / {pages}", page + 1)), next]
        .spacing(8)
        .align_y(Alignment::Center);
    let mut grid = Column::new().spacing(12);
    let visible = state.discovery_page_markets();
    let columns = if compact { 2 } else { 3 };
    for group in visible.chunks(columns) {
        let mut cards = Row::new().spacing(12);
        for market in group {
            let price = market.price_numerator as f64 / market.price_denominator as f64;
            let gain = (price * 300.0 - 1.0) * 100.0;
            let curve = market.phase == Phase::Curve;
            let mut content = column![
                native_token_identity_sized(state, &market.id, 72),
                row![
                    text(format!("{price:.8} NOID")).size(13),
                    space(),
                    text(format!("{gain:+.2}%")).size(12).color(if gain >= 0.0 {
                        GREEN
                    } else {
                        theme::DANGER
                    })
                ],
            ]
            .spacing(11);
            if curve {
                let progress = market.sold_units as f32 / market.sale_units.max(1) as f32;
                content = content
                    .push(
                        iced::widget::progress_bar(0.0..=1.0, progress)
                            .girth(4)
                            .style(|_| iced::widget::progress_bar::Style {
                                background: theme::SURFACE_HIGH.into(),
                                bar: GREEN.into(),
                                border: Border::default().rounded(3),
                            }),
                    )
                    .push(row![
                        label("BONDING CURVE"),
                        space(),
                        label(&format!("{:.1}% TO DEX", progress * 100.0))
                    ]);
            } else {
                content = content
                    .push(row![
                        label("POOL / NOID"),
                        space(),
                        text(crate::model::format_micronoid(market.noid)).size(12)
                    ])
                    .push(row![
                        label(if launchpad {
                            "GRADUATED"
                        } else {
                            "PERMANENT LIQUIDITY"
                        }),
                        space(),
                        label(if launchpad {
                            "OPEN ON DEX →"
                        } else if market.reserved {
                            "PENDING"
                        } else {
                            "DEX"
                        })
                    ]);
            }
            let mut card = button(content)
                .padding(14)
                .width(Length::Fill)
                .style(|_, status| theme::market_card(status));
            if !app.wallet_action_in_flight() {
                card = card.on_press(Message::Asset(Action::SelectMarket(market.id)));
            }
            cards = cards.push(container(card).width(Length::FillPortion(1)));
        }
        for _ in group.len()..columns {
            cards = cards.push(Space::new().width(Length::FillPortion(1)));
        }
        grid = grid.push(cards);
    }
    if visible.is_empty() {
        grid = grid.push(tagged(
            if launchpad { "LAUNCHPAD" } else { "DEX" },
            CYAN,
            hint(if !state.markets.has_snapshot() && state.native_operations_enabled() {
                "Loading tokens…"
            } else if launchpad {
                "No matching tokens. Try another filter or create a token."
            } else {
                "No matching pools. Tokens enter the DEX when they graduate from Launchpad."
            }),
        ));
    }
    let mut heading = row![
        column![text(if launchpad { "LAUNCHPAD" } else { "DEX" }).size(20),
            label(if launchpad { "Discover tokens on the bonding curve." } else { "Trade tokens in permanent NOID pools." })].spacing(5),
        space(),
    ].align_y(Alignment::Center);
    if launchpad {
        heading = heading.push(go("CREATE TOKEN", Page::CreateToken, true));
    }
    column![
        heading,
        row![filters, space(), pager].spacing(12).align_y(Alignment::Center),
        text_input("Search name, ticker or asset ID", &browser.search).padding([10, 12]).size(13)
            .on_input(|value| Message::Asset(Action::MarketSearch(value))).style(theme::text_input),
        label(&format!("{} TOKENS", markets.len())),
        grid,
        hint("Price change compares current spot with the standard curve starting price. Newest sorts by token creation; liquidity uses the pool's NOID reserve."),
        status(&state.markets, false, state.native_operations_enabled()),
    ].spacing(14).into()
}
