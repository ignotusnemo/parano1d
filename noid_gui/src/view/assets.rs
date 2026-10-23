// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::widget::{
    button, canvas, column, container, responsive, row, scrollable, text_input, Column, Row, Space,
};
use iced::{Alignment, Border, Color, Element, Length, Padding, Point, Rectangle, Renderer, Theme};

use crate::app::{App, BackendState, Message, ASSETS_SCROLL_ID};
use crate::assets::{Action, Page, State};
use crate::i18n::text;
use crate::theme::{self, ButtonKind};

type El<'a> = Element<'a, Message>;
const GREEN: Color = theme::ACCENT;
const CYAN: Color = theme::CYAN;
const GOLD: Color = theme::ADVISORY;
const LINE: Color = theme::LINE;
const DIM: Color = theme::DIM;
const GAP: u32 = 10;
const INSET: u16 = 12;
mod chart;
mod collections;
mod discovery;
mod nft_gallery;
mod operations;

pub(super) fn currency_picker(app: &App) -> El<'static> {
    operations::currency_picker(app)
}

pub(super) fn main_send(app: &App, _compact: bool) -> El<'_> {
    operations::view(app, false)
}

pub(super) fn overlays(app: &App, compact: bool) -> Vec<El<'_>> {
    let nft = app.section == crate::model::Section::Nfts;
    let page = if nft {
        app.assets.nft_page
    } else {
        app.assets.token_page
    };
    if app.action.is_none()
        && app.backend_state != BackendState::Mock
        && matches!(
            app.section,
            crate::model::Section::Tokens | crate::model::Section::Nfts
        )
        && page.is_dialog()
    {
        vec![operations::dialog(app, compact, nft)]
    } else {
        Vec::new()
    }
}

pub fn tokens(app: &App, _compact: bool) -> El<'_> {
    let state = &app.assets;
    if app.backend_state != BackendState::Mock {
        return live_tokens(app);
    }
    responsive(move |size| {
        let compact = size.width < 880.0;
        let body = match state.token_page {
            Page::Holdings => holdings(state, compact),
            Page::Launchpad => launchpad(compact),
            Page::Dex => trade(state, compact),
            Page::Trade => trade(state, compact),
            Page::CreateToken => create_token(state, compact),
            Page::TokenReview => token_review(state),
            Page::OrderReview => order_review(state),
            Page::TokenSend => token_send(state),
            Page::Burn => burn(state),
            _ => holdings(state, compact),
        };
        workspace(false, state, body)
    })
    .into()
}

pub fn nfts(app: &App, _compact: bool) -> El<'_> {
    let state = &app.assets;
    if app.backend_state != BackendState::Mock {
        return live_nfts(app);
    }
    responsive(move |size| {
        let compact = size.width < 880.0;
        let body = match state.nft_page {
            Page::Collection => collection(false, size.width < 1040.0),
            Page::Marketplace => collection(true, size.width < 1040.0),
            Page::Listings => listings(),
            Page::NftDetail => nft_detail(state, compact),
            Page::CreateNft => create_nft(state, compact),
            Page::NftSend | Page::NftList | Page::NftBuy => nft_action(state, compact),
            _ => collection(false, size.width < 1040.0),
        };
        workspace(true, state, body)
    })
    .into()
}

fn live_notice(app: &App, nft: bool) -> Option<El<'_>> {
    let live = &app.assets.live;
    if let Some(error) = live.error.as_ref().filter(|_| !live.has_snapshot()) {
        return Some(workspace(
            nft,
            &app.assets,
            tagged(
                "NATIVE HOLDINGS",
                theme::ADVISORY,
                column![
                    text(error).size(13).color(theme::MUTED),
                    control("REFRESH", Action::RefreshLive, false),
                ]
                .spacing(12),
            )
            .into(),
        ));
    }
    if live.protocol.is_none() {
        return Some(workspace(
            nft,
            &app.assets,
            tagged(
                "NATIVE HOLDINGS",
                CYAN,
                column![
                    value("Loading confirmed holdings…"),
                    label("Your local node verifies the current State."),
                ]
                .spacing(8),
            )
            .into(),
        ));
    }
    None
}

fn live_tokens(app: &App) -> El<'_> {
    if let Some(notice) = live_notice(app, false) {
        return notice;
    }
    responsive(move|size|{
        let state=&app.assets;
        let live=&state.live;
        if matches!(state.token_page,Page::Launchpad|Page::Dex|Page::Trade){return workspace(false,state,discovery::markets(app,size.width<880.0));}
        if state.token_page == Page::CreateToken {
            return workspace(false,state,operations::view(app,false));
        }
        if !matches!(state.token_page, Page::Holdings | Page::TokenSend | Page::Burn) {
            return workspace(false,state,tagged("NATIVE TOKENS",CYAN,column![
                value("Your confirmed tokens are available in My Tokens."),
                go("MY TOKENS",Page::Holdings,false),
            ].spacing(12)).into());
        }
        let mut rows=Column::new().spacing(0);
        let selected=live.selected_asset.and_then(|id|live.tokens.get(&id)).or_else(||live.tokens.values().next());
        let search=state.search.to_lowercase();
        let mut shown=0;
        for token in live.tokens.values().filter(|t|native_token_matches(state,&t.id,&search)) {
            let active=selected.is_some_and(|s|s.id==token.id);
            let amount=format!("{}{}",if live.has_snapshot(){""}else{"≥ "},crate::assets::live::units(token.units));
            rows=rows.push(button(row![
                container(native_token_identity(state,&token.id)).width(Length::FillPortion(4)),
                text(amount).size(14).width(Length::FillPortion(3)),
                label(if token.issued_here{"CREATED"}else{"OWNED"}).width(Length::FillPortion(2)),
            ].align_y(Alignment::Center)).on_press(Message::Asset(Action::SelectLiveToken(token.id))).padding([9,9]).width(Length::Fill).style(move|_,status|theme::utxo_row(shown%2==1,active,status)));
            shown+=1;
        }
        if shown==0 {rows=rows.push(container(label(if live.complete{"No tokens at this address."}else{"Loading token outputs…"})).padding([18,9]));}
        let table=panel("MY TOKENS",CYAN,label(&format!("SHOWN [{shown}]")).into(),column![
            container(text_input("Search name, ticker or asset ID",&state.search).size(13).padding(8).on_input(|value|Message::Asset(Action::Search(value))).style(theme::text_input)).padding(9),
            container(row![label("TOKEN").width(Length::FillPortion(4)),label("BALANCE").width(Length::FillPortion(3)),label("RIGHT").width(Length::FillPortion(2))]).padding([7,9]).style(theme::utxo_table_header),
            rows,
            container(row![label(if live.complete{"CONFIRMED HOLDINGS"}else if live.has_snapshot(){"UPDATING HOLDINGS"}else{"LOADING · BALANCES ARE PARTIAL"}),space(),control("REFRESH",Action::RefreshLive,false)]).padding([8,9]).align_y(Alignment::Center),
        ].spacing(0).into(),false);
        let detail:El<'_>=if let Some(token)=selected {
            let id=hex::encode(token.id);
            let displayed_id=format!("{}\n{}",&id[..32],&id[32..]);
            tagged("ASSET DETAILS",theme::PROOF,column![
                native_token_identity(state,&token.id),label("ASSET ID"),row![value(displayed_id),super::copy_value_button(&id,app.copied_value.as_deref()==Some(&id))].spacing(6).align_y(Alignment::Center),
                line(),label(if live.has_snapshot(){"YOUR BALANCE"}else{"LOADED BALANCE"}),text(crate::assets::live::units(token.units)).size(24),
                pair("LOCKED",crate::assets::live::units(token.locked_units)),pair("STATE OUTPUTS",token.outputs),
                row![control("SEND",Action::UseLiveToken(token.id,Page::TokenSend),false),control("BURN & REDEEM",Action::UseLiveToken(token.id,Page::Burn),false)].spacing(6),
                control("TRADE",Action::UseLiveToken(token.id,Page::Trade),true),
                hint("The asset ID identifies this token. Your wallet checks names and images against State."),
            ].spacing(10)).into()
        }else{tagged("ASSET DETAILS",theme::PROOF,hint("Select a token to view its confirmed holdings.")).into()};
        let heading=live_heading(app);
        workspace(false,state,column![heading,split(table.into(),detail,size.width<880.0)].spacing(GAP).into())
    }).into()
}

fn live_heading(app: &App) -> El<'static> {
    let live = &app.assets.live;
    let address = app.snapshot.active_address();
    container(
        row![
            column![
                value(format!("[{}] {}", address.key_index, address.label)),
                label(&format!(
                    "STATE HEIGHT {}",
                    live.display_key().map_or(0, |key| key.height)
                ))
            ]
            .spacing(4),
            space(),
            label(&format!(
                "OUTPUTS [{}]{}",
                live.loaded_outputs,
                if live.complete {
                    " · CONFIRMED"
                } else if live.has_snapshot() {
                    " · UPDATING"
                } else {
                    " · LOADING"
                }
            )),
        ]
        .align_y(Alignment::Center),
    )
    .padding([10, 12])
    .style(theme::surface)
    .into()
}

fn live_nfts(app: &App) -> El<'_> {
    if let Some(notice) = live_notice(app, true) {
        return notice;
    }
    let state = &app.assets;
    let live = &state.live;
    let page = state.nft_background_page();
    if matches!(page, Page::Marketplace | Page::NftMarketCollection) {
        let group = if page == Page::NftMarketCollection {
            state.nft_group
        } else {
            None
        };
        return workspace(true, state, nft_gallery::view(app, true, group, false));
    }
    if matches!(page, Page::Collection | Page::Listings) {
        return workspace(
            true,
            state,
            nft_gallery::view(app, false, None, page == Page::Listings),
        );
    }
    if page == Page::NftCollectionDetail {
        return workspace(true, state, collections::view(app));
    }
    if matches!(
        page,
        Page::CreateNft | Page::CreateNftCollection | Page::MintNfts
    ) {
        return workspace(true, state, operations::view(app, true));
    }
    if !page.is_dialog() && !matches!(page, Page::Collection | Page::Listings | Page::NftDetail) {
        return workspace(
            true,
            state,
            tagged(
                "NFT",
                theme::PROOF,
                column![
                    value("Your confirmed items are available in My NFTs."),
                    go("MY NFTS", Page::Collection, false)
                ]
                .spacing(12),
            )
            .into(),
        );
    }
    let mut content = column![
        go(
            match state.nft_home {
                Page::Listings => "← MY LISTINGS",
                Page::NftCollectionDetail => "← COLLECTION",
                Page::Marketplace => "← MARKETPLACE",
                Page::NftMarketCollection => "← COLLECTION",
                _ => "← MY NFTS",
            },
            state.nft_home,
            false,
        ),
        live_heading(app),
    ]
    .spacing(GAP);
    if let Some(nft) = live.selected_nft.and_then(|id| live.nfts.get(&id)) {
        let draft = state.nft_creation_media().ok();
        let draft = draft.as_ref().filter(|bundle| {
            bundle.hash().ok().as_deref() == Some(hex::encode(nft.metadata).as_str())
        });
        if let Some(manifest) = state
            .library
            .manifest(&nft.metadata)
            .or_else(|| draft.map(|bundle| bundle.manifest()))
            .filter(|manifest| manifest.kind == crate::assets::media::Kind::Nft)
        {
            let image = state
                .library
                .get(&nft.metadata)
                .or(draft)
                .and_then(|bundle| bundle.image())
                .filter(|_| state.external_data);
            let artwork: El<'static> = match image {
                Some(image) => iced::widget::image(image.handle())
                    .width(180)
                    .height(180)
                    .content_fit(iced::ContentFit::Contain)
                    .into(),
                None => container(mark("NFT", theme::PROOF))
                    .width(180)
                    .height(180)
                    .center(180)
                    .style(theme::surface)
                    .into(),
            };
            content = content.push(tagged(
                "NFT",
                theme::PROOF,
                row![
                    artwork,
                    column![
                        value(manifest.name.clone()),
                        label(&manifest.description),
                        project_website(manifest)
                    ]
                    .spacing(8),
                ]
                .spacing(12),
            ));
        }
        let collection = hex::encode(nft.collection);
        if state
            .nft_collections
            .collections
            .get(&nft.collection)
            .is_some_and(|group| group.maximum > 1)
            || state
                .live
                .collections
                .get(&nft.collection)
                .is_some_and(|group| group.maximum > 1)
        {
            content = content.push(control(
                &format!("COLLECTION · {} →", state.collection_name(&nft.collection)),
                Action::SelectNftCollection(nft.collection),
                false,
            ));
        }
        let actions: El<'_> = if let Some((ask, expiry)) = nft.listing {
            column![
                pair("ASK / NOID", crate::model::format_micronoid(ask)),
                pair("EXPIRES AT BLOCK", expiry),
                go("REMOVE LISTING", Page::NftCancel, false)
            ]
            .spacing(8)
            .into()
        } else {
            row![
                go("SEND", Page::NftSend, false),
                go("LIST FOR SALE", Page::NftList, true),
                go("BURN", Page::NftBurn, false)
            ]
            .spacing(6)
            .into()
        };
        content = content.push(tagged(
            "NFT DETAILS",
            CYAN,
            column![
                pair("COLLECTION", crate::assets::live::short_id(&nft.collection)),
                pair("SERIAL", nft.serial),
                pair("UNLOCK HEIGHT", nft.unlock_height),
                pair("METADATA", crate::assets::live::short_id(&nft.metadata)),
                row![
                    label("COLLECTION ID"),
                    space(),
                    super::copy_value_button(
                        &collection,
                        app.copied_value.as_deref() == Some(&collection)
                    )
                ]
                .align_y(Alignment::Center),
                actions,
            ]
            .spacing(9),
        ));
    }
    workspace(true, state, content.into())
}

fn workspace<'a>(nft: bool, state: &State, body: El<'a>) -> El<'a> {
    let entries: &[(&str, Page)] = if nft {
        &[
            ("MY NFTS", Page::Collection),
            ("MARKETPLACE", Page::Marketplace),
            ("MY LISTINGS", Page::Listings),
            ("CREATE", Page::CreateNft),
        ]
    } else {
        &[
            ("MY TOKENS", Page::Holdings),
            ("LAUNCHPAD", Page::Launchpad),
            ("DEX", Page::Dex),
            ("CREATE", Page::CreateToken),
        ]
    };
    let active = if nft {
        state.nft_tab()
    } else {
        state.token_tab()
    };
    let mut tabs = Row::new().spacing(5).align_y(Alignment::Center);
    for &(label, target) in entries {
        tabs = tabs.push(
            button(text(label).size(13))
                .padding([8, 12])
                .on_press(Message::Asset(Action::Open(target)))
                .style(move |_, status| {
                    theme::button(
                        if active == target {
                            ButtonKind::CommandActive
                        } else {
                            ButtonKind::Command
                        },
                        status,
                    )
                }),
        );
    }
    let mut scroller = scrollable(
        container(body)
            .width(Length::Fill)
            .padding(Padding::ZERO.right(10)),
    )
    .id(ASSETS_SCROLL_ID)
    .style(theme::scrollable)
    .height(Length::Fill);
    if !nft && matches!(state.token_page, Page::Launchpad | Page::Dex) {
        scroller = scroller.on_scroll(|viewport| {
            Message::Asset(Action::CatalogScroll(viewport.relative_offset().y))
        });
    }
    container(column![tabs, scroller].spacing(GAP))
        .padding(Padding::new(12.0).top(10))
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
}

fn panel<'a>(
    title: &str,
    color: Color,
    aside: El<'a>,
    body: El<'a>,
    inset: bool,
) -> iced::widget::Container<'a, Message> {
    let title = container(text(title).size(13).color(theme::INK))
        .padding([5, 9])
        .style(move |_| container::Style {
            background: Some(color.into()),
            border: Border {
                radius: 4.into(),
                ..Default::default()
            },
            snap: true,
            ..Default::default()
        });
    let heading = container(
        row![
            title,
            space(),
            container(aside).padding(Padding::ZERO.right(9))
        ]
        .align_y(Alignment::Center),
    )
    .style(theme::surface_alt);
    container(
        column![
            heading,
            container(body)
                .width(Length::Fill)
                .padding(if inset { INSET } else { 0 })
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface)
}

fn tagged<'a>(
    title: &str,
    color: Color,
    body: impl Into<El<'a>>,
) -> iced::widget::Container<'a, Message> {
    panel(title, color, Space::new().into(), body.into(), true)
}

fn label(s: &str) -> iced::widget::Text<'static> {
    text(s).size(12).color(DIM)
}
fn value(s: impl ToString) -> iced::widget::Text<'static> {
    text(s)
        .size(13)
        .color(theme::TEXT)
        .wrapping(iced::widget::text::Wrapping::Glyph)
}
fn space() -> Space {
    Space::new().width(Length::Fill)
}
fn line<'a>() -> El<'a> {
    container(Space::new().width(Length::Fill).height(1))
        .style(theme::divider)
        .into()
}
fn control<'a>(label: &str, action: Action, primary: bool) -> iced::widget::Button<'a, Message> {
    button(text(label).size(13))
        .padding([8, 12])
        .on_press(Message::Asset(action))
        .style(move |_, status| {
            theme::button(
                if primary {
                    ButtonKind::Primary
                } else {
                    ButtonKind::Secondary
                },
                status,
            )
        })
}
fn go<'a>(label: &str, page: Page, primary: bool) -> iced::widget::Button<'a, Message> {
    control(label, Action::Open(page), primary)
}
fn choice<'a>(label: &str, action: Action, active: bool) -> El<'a> {
    button(
        text(label)
            .size(13)
            .width(Length::Fill)
            .align_x(Alignment::Center),
    )
    .padding([8, 12])
    .width(Length::Fill)
    .on_press(Message::Asset(action))
    .style(move |_, status| {
        theme::button(
            if active {
                ButtonKind::CommandActive
            } else {
                ButtonKind::Command
            },
            status,
        )
    })
    .into()
}
fn pair(label_text: &str, amount: impl ToString) -> El<'static> {
    row![
        label(label_text),
        value(amount).width(Length::Fill).align_x(Alignment::End)
    ]
    .spacing(12)
    .align_y(Alignment::Center)
    .into()
}
fn stat(label_text: &str, amount: &str, color: Color) -> El<'static> {
    column![label(label_text), text(amount).size(20).color(color)]
        .spacing(5)
        .width(Length::Fill)
        .into()
}
fn field<'a>(
    label_text: &str,
    placeholder: &str,
    current: &'a str,
    input: fn(String) -> Action,
) -> El<'a> {
    column![
        label(label_text),
        text_input(placeholder, current)
            .size(13)
            .padding([9, 10])
            .on_input(move |v| Message::Asset(input(v)))
            .style(theme::text_input)
    ]
    .spacing(5)
    .width(Length::Fill)
    .into()
}
fn hint(s: &str) -> El<'static> {
    text(s)
        .size(12)
        .color(theme::MUTED)
        .width(Length::Fill)
        .into()
}
fn split<'a>(left: El<'a>, right: El<'a>, compact: bool) -> El<'a> {
    if compact {
        column![left, right].spacing(GAP).into()
    } else {
        row![
            container(left).width(Length::FillPortion(13)),
            container(right).width(Length::FillPortion(8))
        ]
        .spacing(GAP)
        .align_y(Alignment::Start)
        .into()
    }
}
fn focused<'a>(body: El<'a>) -> El<'a> {
    container(container(body).max_width(680))
        .width(Length::Fill)
        .align_x(Alignment::Center)
        .into()
}
fn review_actions(label_text: &str, back: Page) -> El<'static> {
    column![
        line(),
        row![
            go("← BACK", back, false),
            space(),
            button(text(label_text).size(13))
                .padding([8, 16])
                .style(|_, status| theme::button(ButtonKind::Primary, status)),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        label("Preview · No transaction is broadcast.")
    ]
    .spacing(10)
    .into()
}
fn mark(ticker: &str, color: Color) -> El<'static> {
    container(
        text(ticker.chars().next().unwrap_or('?'))
            .size(16)
            .color(color),
    )
    .center_x(Length::Fixed(32.0))
    .center_y(Length::Fixed(32.0))
    .style(move |_| container::Style {
        background: Some(Color { a: 0.10, ..color }.into()),
        border: Border {
            color: Color { a: 0.4, ..color },
            width: 1.0,
            radius: 5.into(),
        },
        snap: true,
        ..Default::default()
    })
    .into()
}
fn token_identity(ticker: &str, name: &str, color: Color) -> El<'static> {
    row![
        mark(ticker, color),
        column![value(name), label(ticker)].spacing(3)
    ]
    .spacing(9)
    .align_y(Alignment::Center)
    .into()
}

fn native_token_label(state: &State, id: &[u8; 32]) -> String {
    let short = crate::assets::live::short_id(id);
    state
        .markets
        .markets
        .get(id)
        .and_then(|market| state.library.manifest(&market.metadata))
        .filter(|manifest| manifest.kind == crate::assets::media::Kind::Token)
        .and_then(|manifest| manifest.symbol.as_ref())
        .map_or_else(
            || format!("UNKNOWN · {short}"),
            |symbol| format!("{symbol} · {short}"),
        )
}

fn native_token_matches(state: &State, id: &[u8; 32], search: &str) -> bool {
    state.token_matches(id, search)
}

fn native_token_identity(state: &State, id: &[u8; 32]) -> El<'static> {
    native_token_identity_sized(state, id, 32)
}

fn project_website(manifest: &crate::assets::media::Manifest) -> El<'static> {
    if let Some(url) = &manifest.website {
        control(
            &format!("{} ↗", url),
            Action::OpenWebsite(url.clone()),
            false,
        )
        .into()
    } else {
        Space::new().into()
    }
}

fn token_information(app: &App, market: &crate::assets::catalog::Market) -> El<'static> {
    let mut body = column![
        native_token_identity(&app.assets, &market.id),
        pair("ASSET ID", crate::assets::live::short_id(&market.id)),
        pair(
            "FIXED SUPPLY",
            crate::assets::live::units(market.initial_supply.into())
        ),
        pair(
            "HOLDER BACKING / NOID",
            crate::model::format_micronoid(market.backing)
        ),
    ]
    .spacing(9);
    if let Some(manifest) = app
        .assets
        .library
        .manifest(&market.metadata)
        .filter(|manifest| manifest.kind == crate::assets::media::Kind::Token)
    {
        if !manifest.description.is_empty() {
            body = body.push(hint(&manifest.description));
        }
        body = body.push(project_website(manifest));
    }
    tagged("TOKEN INFORMATION", CYAN, body).into()
}

fn native_token_identity_sized(state: &State, id: &[u8; 32], size: u32) -> El<'static> {
    let manifest = state
        .markets
        .markets
        .get(id)
        .and_then(|market| state.library.manifest(&market.metadata))
        .filter(|manifest| manifest.kind == crate::assets::media::Kind::Token);
    let bundle = state
        .markets
        .markets
        .get(id)
        .and_then(|market| state.library.get(&market.metadata))
        .filter(|bundle| bundle.manifest().kind == crate::assets::media::Kind::Token);
    let icon: El<'static> = match bundle
        .and_then(|bundle| bundle.image())
        .filter(|_| state.external_data)
    {
        Some(image) => iced::widget::image(image.handle())
            .width(size)
            .height(size)
            .content_fit(iced::ContentFit::Contain)
            .into(),
        None => container(mark("?", CYAN))
            .center_x(size)
            .center_y(size)
            .style(theme::surface)
            .into(),
    };
    row![
        icon,
        column![
            value(manifest.map_or_else(
                || crate::assets::live::short_id(id),
                |manifest| manifest.name.clone()
            )),
            label(&native_token_label(state, id)),
        ]
        .spacing(3)
    ]
    .spacing(9)
    .align_y(Alignment::Center)
    .into()
}

fn native_nft_identity(
    state: &State,
    metadata: &[u8; 32],
    collection: &[u8; 32],
    serial: u64,
) -> El<'static> {
    let bundle = state
        .library
        .get(metadata)
        .filter(|bundle| bundle.manifest().kind == crate::assets::media::Kind::Nft);
    let icon: El<'static> = match bundle
        .and_then(|bundle| bundle.image())
        .filter(|_| state.external_data)
    {
        Some(image) => iced::widget::image(image.handle())
            .width(40)
            .height(40)
            .content_fit(iced::ContentFit::Contain)
            .into(),
        None => mark("NFT", theme::PROOF),
    };
    row![
        icon,
        column![
            value(state.nft_item_name(metadata, serial)),
            label(&format!(
                "{} · #{serial}",
                crate::assets::live::short_id(collection)
            )),
        ]
        .spacing(3)
    ]
    .spacing(9)
    .align_y(Alignment::Center)
    .into()
}
fn token_info(
    ticker: &str,
) -> (
    &'static str,
    Color,
    &'static str,
    &'static str,
    &'static str,
) {
    match ticker {
        "ORB" => ("Orbit", CYAN, "24 800.000000", "0.024800", "7fa2…8c91"),
        "MOSS" => ("Moss", GREEN, "8 400.000000", "0.006200", "2d14…e365"),
        "EMBER" => ("Ember", GOLD, "0.000000", "0.018400", "5f82…a4d0"),
        _ => ("Unreviewed asset", DIM, "500.000000", "—", "c028…1b49"),
    }
}

fn holdings(state: &State, compact: bool) -> El<'_> {
    let header = container(
        row![
            label("ASSET").width(Length::FillPortion(3)),
            label("BALANCE").width(Length::FillPortion(3)),
            label("PRICE / NOID").width(Length::FillPortion(2)),
        ]
        .align_y(Alignment::Center),
    )
    .padding([7, 9])
    .style(theme::utxo_table_header);
    let mut rows = Column::new().spacing(0);
    let mut count = 0;
    for (index, ticker) in ["ORB", "MOSS", "?"].into_iter().enumerate() {
        let (name, color, balance, price, asset_id) = token_info(ticker);
        if !format!("{name} {ticker} {asset_id}")
            .to_lowercase()
            .contains(&state.search.to_lowercase())
        {
            continue;
        }
        count += 1;
        let selected = state.selected_token == ticker;
        rows = rows.push(
            button(
                row![
                    container(token_identity(ticker, name, color)).width(Length::FillPortion(3)),
                    text(balance).size(14).width(Length::FillPortion(3)),
                    text(price)
                        .size(14)
                        .color(if price == "—" { DIM } else { theme::TEXT })
                        .width(Length::FillPortion(2)),
                ]
                .align_y(Alignment::Center),
            )
            .on_press(Message::Asset(Action::InspectToken(ticker.into())))
            .width(Length::Fill)
            .padding([8, 9])
            .style(move |_, status| theme::utxo_row(index % 2 == 1, selected, status)),
        );
    }
    if count == 0 {
        rows = rows.push(container(label("No matching tokens.")).padding([18, 9]));
    }
    let table = panel(
        "MY TOKENS",
        CYAN,
        label("[0] Main · 3 assets").into(),
        column![
            container(
                text_input("Search name or asset ID", &state.search)
                    .size(13)
                    .padding(8)
                    .on_input(|s| Message::Asset(Action::Search(s)))
                    .style(theme::text_input)
            )
            .padding([9, 9]),
            header,
            rows,
            container(row![
                label("SELECT AN ASSET TO VIEW ITS RIGHTS"),
                space(),
                label(&format!("SHOWN [{count}]"))
            ])
            .padding([8, 9]),
        ]
        .spacing(0)
        .into(),
        false,
    );
    let ticker = &state.selected_token;
    let (name, color, balance, price, asset_id) = token_info(ticker);
    let mut trade = button(text("TRADE").size(13))
        .padding([8, 12])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if price != "—" {
        trade = trade.on_press(Message::Asset(Action::UseToken(
            ticker.clone(),
            Page::Trade,
        )));
    }
    let detail = tagged("ASSET DETAILS", theme::PROOF, column![
        token_identity(ticker, name, color), line(),
        label("YOUR BALANCE"), text(format!("{balance} {ticker}")).size(22).color(theme::TEXT),
        pair("ASSET ID", asset_id), pair("PRICE / NOID", price),
        pair("BACKING / TOKEN", "0.001 NOID"),
        pair("TOTAL SUPPLY", "1 000 000"),
        line(),
        row![control("SEND", Action::SelectToken(ticker.clone()), true), trade,
            control("BURN", Action::UseToken(ticker.clone(), Page::Burn), false)]
            .spacing(6).align_y(Alignment::Center),
        hint("Burn tokens to redeem their NOID backing. This reserve stays separate from trading liquidity."),
    ].spacing(10));
    column![
        container(
            row![
                stat("OWNED ASSETS", "3 tokens", CYAN),
                stat("MINIMUM BACKING / TOKEN", "0.001 NOID", GREEN),
                space(),
                go("CREATE TOKEN", Page::CreateToken, true)
            ]
            .spacing(20)
            .align_y(Alignment::Center)
        )
        .padding([10, 12])
        .style(theme::surface),
        split(table.into(), detail.into(), compact),
    ]
    .spacing(GAP)
    .into()
}

fn launchpad(compact: bool) -> El<'static> {
    let mut cards = Vec::new();
    for (ticker, name, progress, raised, price, color) in [
        ("ORB", "Orbit", 62.0, "12 400", "0.024800", CYAN),
        ("MOSS", "Moss", 38.0, "7 600", "0.006200", GREEN),
        ("EMBER", "Ember", 81.0, "16 200", "0.018400", GOLD),
    ] {
        cards.push(
            tagged(
                name,
                color,
                column![
                    token_identity(ticker, name, color),
                    line(),
                    pair("RAISED / NOID", format!("{raised} / 20 000")),
                    iced::widget::progress_bar(0.0..=100.0, progress)
                        .girth(4)
                        .style(move |_| iced::widget::progress_bar::Style {
                            background: theme::SURFACE_ALT.into(),
                            bar: color.into(),
                            border: Border::default(),
                        }),
                    pair("LAUNCH PROGRESS", format!("{progress:.0}%")),
                    pair("FIXED SUPPLY", "1 000 000"),
                    pair("BACKING / TOKEN", "0.001 NOID"),
                    line(),
                    row![
                        column![label("PRICE / NOID"), value(price)].spacing(4),
                        space(),
                        control(
                            "OPEN →",
                            Action::UseToken(ticker.into(), Page::Trade),
                            false
                        )
                    ]
                    .align_y(Alignment::Center),
                ]
                .spacing(10),
            )
            .into(),
        );
    }
    let cards: El<'static> = if compact {
        Column::with_children(cards).spacing(GAP).into()
    } else {
        Row::with_children(cards).spacing(GAP).into()
    };
    column![
        row![label("TOKEN LAUNCHES"), space(), go("LAUNCH A TOKEN", Page::CreateToken, true)]
            .align_y(Alignment::Center),
        cards,
        container(hint("Fixed supply. Holder backing is funded at creation. Graduation opens a permanent native pool with the same asset ID."))
            .padding([10, 12]).style(theme::surface),
    ].spacing(GAP).into()
}

fn trade(state: &State, compact: bool) -> El<'_> {
    let ticker = &state.selected_token;
    let (name, color, _, price_text, _) = token_info(ticker);
    if price_text == "—" {
        return tagged(
            "NO ACTIVE MARKET",
            CYAN,
            column![
                hint("This asset has no active trading pool."),
                go("BACK TO TOKENS", Page::Holdings, false),
            ]
            .spacing(12),
        )
        .into();
    }
    let price = crate::app::parse_noid_amount(price_text).unwrap_or(0);
    let ready = [&state.amount, &state.limit]
        .iter()
        .all(|input| crate::app::parse_noid_amount(input).is_ok_and(|value| value > 0));
    let review = go("REVIEW SWAP →", Page::OrderReview, true)
        .on_press_maybe(ready.then_some(Message::Asset(Action::Open(Page::OrderReview))));
    let estimate = crate::app::parse_noid_amount(&state.amount)
        .ok()
        .and_then(|amount| {
            let units = if state.sell {
                u128::from(amount) * u128::from(price) / 1_000_000
            } else {
                u128::from(amount) * 1_000_000 / u128::from(price)
            };
            u64::try_from(units).ok()
        })
        .map(crate::model::format_micronoid)
        .unwrap_or_else(|| "—".into());
    let chart = panel(
        &format!("{ticker} / NOID"),
        CYAN,
        label("BATCH MARKET").into(),
        column![
            row![
                token_identity(ticker, name, color),
                space(),
                column![
                    label("PRICE / NOID"),
                    text(price_text).size(22).color(GREEN),
                ]
                .spacing(4)
                .align_x(Alignment::End)
            ]
            .align_y(Alignment::Center),
            canvas(PriceChart(price)).width(Length::Fill).height(230),
            line(),
            row![
                pair("24H VOLUME", "84 208 NOID"),
                pair("LIQUIDITY", "126 400 NOID")
            ]
            .spacing(20),
        ]
        .spacing(10)
        .into(),
        true,
    );
    let order = tagged(
        "SWAP",
        GREEN,
        column![
            row![
                choice(&format!("BUY {ticker}"), Action::Sell(false), !state.sell),
                choice(&format!("SELL {ticker}"), Action::Sell(true), state.sell)
            ]
            .spacing(5),
            field(
                &format!("YOU PAY · {}", if state.sell { ticker } else { "NOID" }),
                "0.00",
                &state.amount,
                Action::Amount
            ),
            pair(
                "AVAILABLE",
                if state.sell {
                    format!("{} {ticker}", token_info(ticker).2)
                } else {
                    "100 000 NOID".into()
                }
            ),
            field(
                &format!(
                    "{} PRICE · NOID / {ticker}",
                    if state.sell { "MINIMUM" } else { "MAXIMUM" }
                ),
                "Price per token",
                &state.limit,
                Action::Limit
            ),
            line(),
            label(&format!(
                "ESTIMATED RECEIVED · {}",
                if state.sell { "NOID" } else { ticker }
            )),
            text(estimate).size(24).color(theme::TEXT),
            pair("SETTLEMENT", "Next batch"),
            row![space(), review].align_y(Alignment::Center),
        ]
        .spacing(10),
    );
    let orders = panel(
        "MY ORDERS",
        theme::PROOF,
        label("1 QUEUED").into(),
        column![
            container(row![
                label("SIDE").width(Length::Fill),
                label("AMOUNT").width(Length::Fill),
                label("LIMIT / NOID").width(Length::Fill),
                label("STATUS").width(Length::Fill)
            ])
            .padding([7, 9])
            .style(theme::scope_table_header),
            container(row![
                text("BUY ORB").size(13).color(GREEN).width(Length::Fill),
                value("2 000 ORB").width(Length::Fill),
                value("0.025000").width(Length::Fill),
                text("QUEUED").size(13).color(CYAN).width(Length::Fill)
            ])
            .padding([9, 9])
            .style(theme::table_row(false)),
        ]
        .spacing(0)
        .into(),
        false,
    );
    column![
        split(chart.into(), order.into(), compact),
        orders,
        hint("Your price limit applies to the batch. The receipt records the fill and any refund.")
    ]
    .spacing(GAP)
    .into()
}

fn create_token(state: &State, compact: bool) -> El<'_> {
    let ready = !state.name.trim().is_empty()
        && !state.ticker.trim().is_empty()
        && state.minimum_backing().is_some();
    let review = go("REVIEW TOKEN →", Page::TokenReview, true)
        .on_press_maybe(ready.then_some(Message::Asset(Action::Open(Page::TokenReview))));
    let media: El<'_> = column![
        label("LOGO"),
        row![
            mark(&state.ticker, CYAN),
            column![
                value("PNG / WebP"),
                label("Reviewed media · Parano1d storage")
            ]
            .spacing(4),
            space(),
            button(text("CHOOSE IMAGE").size(12))
                .padding([7, 10])
                .style(|_, status| theme::button(ButtonKind::Secondary, status))
        ]
        .spacing(9)
        .align_y(Alignment::Center)
    ]
    .spacing(5)
    .into();
    let form = tagged(
        "CREATE TOKEN",
        CYAN,
        column![
            pair("CREATION", "Launchpad"),
            field("TOKEN NAME", "Name", &state.name, Action::Name),
            row![
                field("TICKER", "TICKER", &state.ticker, Action::Ticker),
                field(
                    "TOTAL SUPPLY · MINIMUM 100 000",
                    "1000000",
                    &state.supply,
                    Action::Supply
                )
            ]
            .spacing(10),
            media,
            field(
                "DESCRIPTION · OPTIONAL",
                "A short description",
                &state.description,
                Action::Description
            ),
            line(),
            row![space(), review].align_y(Alignment::Center),
        ]
        .spacing(12),
    );
    let backing = state
        .minimum_backing()
        .map(|v| format!("{} NOID", crate::model::format_micronoid(v)))
        .unwrap_or_else(|| "Enter at least 100 000 whole tokens".into());
    let summary = tagged(
        "HOLDER RIGHTS",
        theme::PROOF,
        column![
            pair("SUPPLY", "Fixed at creation"),
            pair("ADDITIONAL MINTING", "Disabled"),
            pair("BACKING / TOKEN", "0.001 NOID"),
            line(),
            label("BACKING LOCKED AT CREATION"),
            text(backing).size(22).color(GREEN),
            hint("You fund the complete holder reserve when the tokens are created."),
            line(),
            hint(
                "Burning tokens pays their NOID backing. The creator cannot withdraw this reserve."
            ),
            hint("The same asset moves from the launch curve to its permanent DEX pool."),
        ]
        .spacing(10),
    );
    split(form.into(), summary.into(), compact)
}

fn token_review(state: &State) -> El<'_> {
    let backing = state
        .minimum_backing()
        .map(crate::model::format_micronoid)
        .unwrap_or_else(|| "—".into());
    focused(
        tagged(
            "REVIEW TOKEN",
            GREEN,
            column![
                token_identity(&state.ticker, &state.name, CYAN),
                line(),
                pair("CREATION", "Launchpad"),
                pair("TOTAL SUPPLY", &state.supply),
                pair("RESERVE AT CREATION / NOID", backing),
                pair("ADDITIONAL MINTING", "Disabled"),
                hint("The name and supply are fixed at creation. Check them before continuing."),
                review_actions("CREATE TOKEN", Page::CreateToken),
            ]
            .spacing(12),
        )
        .into(),
    )
}

fn order_review(state: &State) -> El<'_> {
    let ticker = &state.selected_token;
    let (name, color, _, _, _) = token_info(ticker);
    focused(
        tagged(
            "REVIEW SWAP",
            GREEN,
            column![
                token_identity(ticker, name, color),
                line(),
                pair(
                    "SIDE",
                    format!("{} {ticker}", if state.sell { "Sell" } else { "Buy" })
                ),
                pair(
                    "YOU PAY",
                    format!(
                        "{} {}",
                        state.amount,
                        if state.sell { ticker } else { "NOID" }
                    )
                ),
                pair(
                    if state.sell {
                        "MINIMUM PRICE / NOID"
                    } else {
                        "MAXIMUM PRICE / NOID"
                    },
                    &state.limit
                ),
                pair("SETTLEMENT", "Next eligible batch"),
                pair("UNFILLED FUNDS", "Returned to your address"),
                review_actions("PLACE ORDER", Page::Trade),
            ]
            .spacing(12),
        )
        .into(),
    )
}

fn token_send(state: &State) -> El<'_> {
    let (name, color, balance, _, _) = token_info(&state.selected_token);
    focused(
        tagged(
            "SEND TOKEN",
            CYAN,
            column![
                token_identity(&state.selected_token, name, color),
                line(),
                pair("AVAILABLE", format!("{balance} {}", state.selected_token)),
                field("RECIPIENT", "o1…", &state.recipient, Action::Recipient),
                field(
                    &format!("AMOUNT · {}", state.selected_token),
                    "0.00",
                    &state.amount,
                    Action::Amount
                ),
                pair("NETWORK FEE", "Paid in NOID"),
                review_actions("SEND TOKEN", Page::Holdings),
            ]
            .spacing(12),
        )
        .into(),
    )
}

fn burn(state: &State) -> El<'_> {
    let (name, color, balance, _, _) = token_info(&state.selected_token);
    let payout = crate::app::parse_noid_amount(&state.amount)
        .ok()
        .map(|amount| crate::model::format_micronoid(amount / 1_000))
        .unwrap_or_else(|| "—".into());
    focused(tagged("BURN TOKENS", GREEN, column![
        token_identity(&state.selected_token, name, color), line(),
        pair("AVAILABLE", format!("{balance} {}", state.selected_token)),
        field(&format!("TOKENS TO BURN · {}", state.selected_token), "0.00", &state.amount, Action::Amount),
        pair("BACKING / TOKEN", "0.001 NOID"),
        label("YOU RECEIVE · NOID"), text(payout).size(24).color(GREEN),
        hint("The tokens are burned and the corresponding NOID backing is paid to your address in the same transaction."),
        review_actions("BURN TOKENS", Page::Holdings),
    ].spacing(12)).into())
}

fn collection(market: bool, compact: bool) -> El<'static> {
    let mut items: Vec<El<'static>> = Vec::new();
    for index in 0..4 {
        let card = container(
            column![
                container(
                    canvas(Artwork(index))
                        .width(Length::Fill)
                        .height(if compact { 200 } else { 160 })
                )
                .padding(5)
                .style(theme::photo_frame),
                container(
                    column![
                        value(format!("Contours #{:03}", index + 1)),
                        label("Contours · Reviewed media"),
                        line(),
                        row![
                            column![
                                label(if market { "PRICE / NOID" } else { "OWNER" }),
                                value(if market { "120.000000" } else { "[0] Main" })
                            ]
                            .spacing(4),
                            space(),
                            control(
                                "OPEN →",
                                Action::SelectNft {
                                    index,
                                    owned: !market
                                },
                                false
                            )
                        ]
                        .align_y(Alignment::Center),
                    ]
                    .spacing(8)
                )
                .padding([9, 10]),
            ]
            .spacing(0),
        )
        .width(Length::Fill)
        .style(theme::surface_alt);
        items.push(card.into());
    }
    let mut items = items.into_iter();
    let mut gallery = Column::new().spacing(GAP);
    while let Some(first) = items.next() {
        let mut row = Row::new().spacing(GAP).push(first);
        for _ in 1..if compact { 2 } else { 4 } {
            if let Some(item) = items.next() {
                row = row.push(item);
            }
        }
        gallery = gallery.push(row);
    }
    let gallery = panel(
        if market { "MARKETPLACE" } else { "MY NFTS" },
        theme::PROOF,
        label(if market {
            "CONTOURS · 4 LISTINGS"
        } else {
            "CONTOURS · 4 ITEMS"
        })
        .into(),
        gallery.into(),
        true,
    );
    column![
        row![label(if market { "BROWSE NATIVE NFTS" } else { "[0] Main" }), space(),
            go("CREATE NFT", Page::CreateNft, true)].align_y(Alignment::Center),
        gallery,
        if market {
            panel("RECENT SALES", CYAN, label("PAID IN NOID").into(), column![
                container(row![label("ITEM").width(Length::Fill), label("SALE PRICE / NOID").width(Length::Fill)])
                    .padding([7, 9]).style(theme::scope_table_header),
                container(row![value("Contours #021").width(Length::Fill), value("112.000000").width(Length::Fill)])
                    .padding([8, 9]).style(theme::table_row(false)),
                container(row![value("Contours #018").width(Length::Fill), value("96.000000").width(Length::Fill)])
                    .padding([8, 9]).style(theme::table_row(true)),
            ].spacing(0).into(), false).into()
        } else {
            hint("Select an item to send it or list it for sale. Ownership and payments are verified by your node.")
        },
    ].spacing(GAP).into()
}

fn nft_art(index: usize, height: u32) -> El<'static> {
    container(canvas(Artwork(index)).width(Length::Fill).height(height))
        .padding(6)
        .style(theme::photo_frame)
        .into()
}

fn nft_detail(state: &State, compact: bool) -> El<'static> {
    let name = format!("Contours #{:03}", state.selected_nft + 1);
    let actions: El<'static> = if state.nft_owned {
        row![
            space(),
            go("SEND", Page::NftSend, false),
            go("LIST FOR SALE", Page::NftList, true)
        ]
        .spacing(8)
        .align_y(Alignment::Center)
        .into()
    } else {
        row![
            column![
                label("PRICE / NOID"),
                text("120.000000").size(22).color(GREEN)
            ]
            .spacing(4),
            space(),
            go("BUY NFT", Page::NftBuy, true)
        ]
        .align_y(Alignment::Center)
        .into()
    };
    column![
        row![
            go("← BACK", state.nft_home, false),
            space(),
            label("CONTOURS")
        ]
        .align_y(Alignment::Center),
        split(
            tagged(
                &name.to_uppercase(),
                theme::PROOF,
                nft_art(state.selected_nft, 300)
            )
            .into(),
            tagged(
                "ITEM DETAILS",
                CYAN,
                column![
                    text(name).size(22).color(theme::TEXT),
                    label("Contours · Native NFT"),
                    line(),
                    pair("ITEM ID", "9b73…0c42"),
                    pair(
                        "OWNER",
                        if state.nft_owned {
                            "[0] Main"
                        } else {
                            "Seller"
                        }
                    ),
                    pair("MEDIA", "Reviewed · Hash committed"),
                    pair(
                        "STATUS",
                        if state.nft_owned {
                            "Not listed"
                        } else {
                            "Listed for sale"
                        }
                    ),
                    line(),
                    actions,
                    hint("Payment and ownership transfer together."),
                ]
                .spacing(12)
            )
            .into(),
            compact
        ),
    ]
    .spacing(GAP)
    .into()
}

fn listings() -> El<'static> {
    let header = || {
        container(row![
            label("ITEM").width(Length::FillPortion(3)),
            label("PRICE / NOID").width(Length::FillPortion(2)),
            label("STATUS").width(Length::FillPortion(3)),
            Space::new().width(98)
        ])
        .padding([7, 9])
        .style(theme::scope_table_header)
    };
    column![panel(
        "MY LISTINGS",
        theme::PROOF,
        label("1 ACTIVE").into(),
        column![
            header(),
            container(
                row![
                    value("Contours #002").width(Length::FillPortion(3)),
                    value("150.000000").width(Length::FillPortion(2)),
                    label("Listed · Until #240 000").width(Length::FillPortion(3)),
                    control(
                        "VIEW →",
                        Action::SelectNft {
                            index: 1,
                            owned: true
                        },
                        false
                    )
                    .width(98)
                ]
                .align_y(Alignment::Center)
            )
            .padding([8, 9])
            .style(theme::table_row(false)),
        ]
        .spacing(0)
        .into(),
        false
    ),]
    .spacing(GAP)
    .into()
}

fn create_nft(state: &State, compact: bool) -> El<'_> {
    split(
        tagged(
            "CREATE NFT",
            theme::PROOF,
            column![
                field("NAME", "NFT name", &state.nft_name, Action::NftName),
                field(
                    "DESCRIPTION · OPTIONAL",
                    "A short description",
                    &state.description,
                    Action::Description
                ),
                row![
                    label("IMAGE"),
                    space(),
                    button(text("CHOOSE IMAGE").size(12))
                        .padding([7, 10])
                        .style(|_, status| theme::button(ButtonKind::Secondary, status))
                ]
                .align_y(Alignment::Center),
                nft_art(0, 190),
                label("PNG / WebP · Parano1d storage"),
                review_actions("CREATE NFT", state.nft_home),
            ]
            .spacing(12),
        )
        .into(),
        tagged(
            "OWNERSHIP & MEDIA",
            CYAN,
            column![
        pair("INITIAL OWNER", "[0] Main"), pair("ASSET", "Unique native NFT"),
        pair("MEDIA", "Hash committed"), line(),
        hint("The image is reviewed before the wallet displays it. A copy is kept for recovery."),
        hint("The network verifies ownership. Sending or selling transfers the same native item."),
    ]
            .spacing(12),
        )
        .into(),
        compact,
    )
}

fn nft_action(state: &State, compact: bool) -> El<'_> {
    let page = state.nft_page;
    let (title, action) = match page {
        Page::NftSend => ("SEND NFT", "SEND NFT"),
        Page::NftList => ("LIST FOR SALE", "CREATE LISTING"),
        _ => ("BUY NFT", "BUY NFT"),
    };
    let input = match page {
        Page::NftSend => field("RECIPIENT", "o1…", &state.recipient, Action::Recipient),
        Page::NftList => field("SALE PRICE · NOID", "0.00", &state.amount, Action::Amount),
        _ => column![
            label("YOU PAY · NOID"),
            text("120.000000").size(24).color(GREEN)
        ]
        .spacing(5)
        .into(),
    };
    let name = format!("Contours #{:03}", state.selected_nft + 1);
    split(tagged(&name.to_uppercase(), theme::PROOF, nft_art(state.selected_nft, 280)).into(),
        tagged(title, CYAN, column![value(name), line(), input,
            pair("NETWORK FEE", "Paid in NOID"),
            hint(match page {
                Page::NftSend => "Ownership moves to the recipient address.",
                Page::NftList => "The item is reserved for sale. Payment and ownership transfer together.",
                _ => "The listing must remain available. Payment and ownership transfer together.",
            }),
            review_actions(action, Page::NftDetail),
        ].spacing(12)).into(), compact)
}

struct Artwork(usize);
struct PriceChart(u64);
impl canvas::Program<Message> for Artwork {
    type State = ();
    fn draw(
        &self,
        _: &(),
        renderer: &Renderer,
        _: &Theme,
        bounds: Rectangle,
        _: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        frame.fill_rectangle(Point::ORIGIN, bounds.size(), Color::from_rgb8(11, 17, 27));
        let color = [GREEN, Color::from_rgb8(159, 141, 235), GOLD, CYAN][self.0 % 4];
        let scale = bounds.width.min(bounds.height) / 500.;
        let center = Point::new(bounds.width * 0.5, bounds.height * 0.48);
        for i in 0..27 {
            let path = canvas::Path::new(|b| {
                for j in 0..161 {
                    let a = std::f32::consts::TAU * j as f32 / 160.;
                    let r = (70.
                        + i as f32 * 4.
                        + (a * 3. + self.0 as f32).sin() * 12.
                        + (a * 5. + i as f32 * 0.08).cos() * 6.)
                        * scale;
                    let p = Point::new(center.x + a.cos() * r, center.y + a.sin() * r * 0.82);
                    if j == 0 {
                        b.move_to(p)
                    } else {
                        b.line_to(p)
                    }
                }
            });
            frame.stroke(
                &path,
                canvas::Stroke::default().with_width(0.8).with_color(Color {
                    a: 0.3 + i as f32 * 0.02,
                    ..color
                }),
            );
        }
        frame.fill_text(canvas::Text {
            content: "CONTOURS".into(),
            position: Point::new(18., 18.),
            color,
            size: 9.into(),
            font: theme::TECH_FONT,
            ..Default::default()
        });
        vec![frame.into_geometry()]
    }
}
impl canvas::Program<Message> for PriceChart {
    type State = ();
    fn draw(
        &self,
        _: &(),
        renderer: &Renderer,
        _: &Theme,
        bounds: Rectangle,
        _: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut f = canvas::Frame::new(renderer, bounds.size());
        let w = bounds.width - 65.;
        let h = bounds.height - 32.;
        let current_y = 112. / 216. * h;
        for i in 0..5 {
            let y = 20. + i as f32 * (h - 20.) / 4.;
            f.stroke(
                &canvas::Path::line(Point::new(0., y), Point::new(w, y)),
                canvas::Stroke::default().with_width(0.7).with_color(LINE),
            );
            if (y - current_y).abs() > 14.0 {
                f.fill_text(canvas::Text {
                    content: format!(
                        "{:.4}",
                        self.0 as f64 / 1_000_000.0 * (1.0 + f64::from((current_y - y) / h) * 0.65)
                    ),
                    position: Point::new(w + 10., y - 5.),
                    size: 9.into(),
                    color: DIM,
                    font: theme::TECH_FONT,
                    ..Default::default()
                });
            }
        }
        let mut seed = 8201u32;
        let mut rnd = || {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            seed as f32 / u32::MAX as f32
        };
        let mut prices = Vec::new();
        let mut price = 135.;
        for _ in 0..52 {
            let open = price;
            price = (price + (rnd() - 0.53) * 32. - 1.).clamp(45., 170.);
            prices.push((open, price));
        }
        let last = price;
        for (i, (o, c)) in prices.into_iter().enumerate() {
            let open = (112. + (o - last) * 0.65) / 216. * h;
            let close = (112. + (c - last) * 0.65) / 216. * h;
            let x = 8. + i as f32 * (w - 12.) / 52.;
            let col = if close < open {
                GREEN
            } else {
                Color::from_rgb8(221, 113, 129)
            };
            f.stroke(
                &canvas::Path::line(
                    Point::new(x + 2., open.min(close) - 5.),
                    Point::new(x + 2., open.max(close) + 7.),
                ),
                canvas::Stroke::default().with_width(1.).with_color(col),
            );
            f.fill_rectangle(
                Point::new(x, open.min(close)),
                iced::Size::new(4., (close - open).abs().max(2.)),
                col,
            );
        }
        let y = 112. / 216. * h;
        f.stroke(
            &canvas::Path::line(Point::new(0., y), Point::new(w, y)),
            canvas::Stroke::default()
                .with_width(0.7)
                .with_color(Color { a: 0.5, ..GREEN }),
        );
        f.fill_rectangle(
            Point::new(w + 5., y - 8.),
            iced::Size::new(59., 18.),
            Color::from_rgb8(25, 49, 37),
        );
        f.fill_text(canvas::Text {
            content: format!("{:.5}", self.0 as f64 / 1_000_000.0),
            position: Point::new(w + 8., y - 5.),
            size: 9.into(),
            color: GREEN,
            font: theme::TECH_FONT,
            ..Default::default()
        });
        for (i, label) in ["09:00", "12:00", "15:00", "18:00"].iter().enumerate() {
            f.fill_text(canvas::Text {
                content: (*label).into(),
                position: Point::new(8. + i as f32 * (w - 45.) / 3., h + 10.),
                size: 9.into(),
                color: DIM,
                font: theme::TECH_FONT,
                ..Default::default()
            });
        }
        vec![f.into_geometry()]
    }
}
