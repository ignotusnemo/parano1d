// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::assets::operations::{integer, Phase, Preview, Request};
use crate::assets::Currency;
use iced::widget::{column, pick_list};

#[derive(Debug, Clone, PartialEq, Eq)]
struct CurrencyChoice(Currency, String);
impl std::fmt::Display for CurrencyChoice {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.1)
    }
}

pub(super) fn currency_picker(app: &App) -> El<'static> {
    let selected = app.assets.currency;
    let choice = |currency| {
        CurrencyChoice(
            currency,
            match currency {
                Currency::Noid => "NOID".into(),
                Currency::Token(id) => native_token_label(&app.assets, &id),
            },
        )
    };
    if app.wallet_action_in_flight() {
        return container(
            row![
                text(choice(selected).to_string())
                    .size(13)
                    .font(theme::TECH_FONT),
                Space::new().width(Length::Fill),
                text("⌄").size(16).font(theme::SYMBOL_FONT),
            ]
            .align_y(Alignment::Center),
        )
        .padding([0, 12])
        .height(35)
        .align_y(Alignment::Center)
        .width(224)
        .style(|_| theme::asset_picker_locked())
        .into();
    }
    let mut choices = vec![Currency::Noid];
    if app.assets.live.has_snapshot() {
        choices.extend(
            app.assets
                .live
                .tokens
                .values()
                .filter(|token| token.units > 0)
                .map(|token| Currency::Token(token.id)),
        );
    }
    if !choices.contains(&selected) {
        choices.push(selected);
    }
    let menu_height = (choices.len() as f32 * 34.9).min(240.0);
    let choices: Vec<_> = choices.into_iter().map(choice).collect();
    let selected = choice(selected);
    let picker = pick_list(choices, Some(selected), |currency: CurrencyChoice| {
        Message::Asset(Action::Currency(currency.0))
    })
    .text_size(13)
    .text_line_height(1.3)
    .font(theme::TECH_FONT)
    .padding([9, 12])
    .width(224)
    .menu_height(menu_height)
    .handle(pick_list::Handle::Dynamic {
        closed: pick_list::Icon {
            font: theme::SYMBOL_FONT,
            code_point: '⌄',
            size: Some(16.into()),
            line_height: iced::widget::text::LineHeight::Relative(1.0),
            shaping: iced::widget::text::Shaping::Basic,
        },
        open: pick_list::Icon {
            font: theme::SYMBOL_FONT,
            code_point: '⌃',
            size: Some(16.into()),
            line_height: iced::widget::text::LineHeight::Relative(1.0),
            shaping: iced::widget::text::Shaping::Basic,
        },
    })
    .style(|_, status| theme::asset_picker(status))
    .menu_style(|_| theme::asset_picker_menu());

    container(picker)
        .style(|_| theme::asset_picker_frame())
        .into()
}

fn amount(value: &str) -> String {
    integer(value)
        .map(crate::assets::live::units)
        .unwrap_or_else(|_| "Unavailable".into())
}

fn identifier(value: &str) -> iced::widget::Text<'static> {
    text(value)
        .size(12)
        .width(Length::Fill)
        .wrapping(iced::widget::text::Wrapping::Glyph)
}

fn field<'a>(
    caption: &str,
    placeholder: &str,
    value: &'a str,
    action: fn(String) -> Action,
    locked: bool,
) -> El<'a> {
    let mut input = text_input(placeholder, value)
        .size(14)
        .padding([10, 12])
        .style(theme::text_input);
    if !locked {
        input = input.on_input(move |value| Message::Asset(action(value)));
    }
    column![label(caption), input].spacing(6).into()
}

fn title(state: &State, page: Page) -> &'static str {
    match page {
        Page::CreateToken => "CREATE TOKEN",
        Page::CreateNft => "CREATE NFT",
        Page::CreateNftCollection => "CREATE COLLECTION",
        Page::MintNfts => "ADD NFTS",
        Page::TokenSend => "SEND TOKENS",
        Page::Burn => "BURN & REDEEM",
        Page::Trade => {
            if state.sell {
                "SELL TOKENS"
            } else {
                "BUY TOKENS"
            }
        }
        Page::NftSend => "SEND NFT",
        Page::NftBuy => "BUY NFT",
        Page::NftList => "LIST NFT",
        Page::NftBurn => "BURN NFT",
        Page::NftCancel => "REMOVE LISTING",
        Page::NftListPicker => "LIST NFT",
        _ => "NATIVE OPERATION",
    }
}

pub(super) fn dialog(app: &App, compact: bool, nft: bool) -> El<'_> {
    let state = &app.assets;
    let page = if nft {
        state.nft_page
    } else {
        state.token_page
    };
    let address = app.snapshot.active_address();
    let back = state.back_page(nft).unwrap_or(if nft {
        Page::Collection
    } else {
        Page::Holdings
    });
    super::super::present::action_dialog(
        app,
        format!(
            "{} · [{}] {}",
            title(state, page),
            address.key_index,
            address.label
        ),
        view(app, nft),
        Message::Asset(Action::Open(back)),
        compact,
        state.operation.submitting(),
    )
}

pub(super) fn view(app: &App, nft: bool) -> El<'_> {
    let state = &app.assets;
    let operation = &state.operation;
    let page = if nft {
        state.nft_page
    } else {
        state.token_page
    };
    let locked =
        operation.submitting() || page == Page::Trade && operation.phase == Phase::Submitted;
    if page == Page::NftListPicker {
        return super::nft_gallery::picker(app);
    }
    let title = title(state, page);
    let mut form = Column::new().spacing(12);
    if page == Page::Trade {
        if let Some(notice) = &state.trade_notice {
            form = form.push(tagged("TRADE STATUS", GREEN, hint(notice)));
        }
    }
    if matches!(page, Page::CreateNft | Page::CreateNftCollection) {
        form = form.push(
            row![
                control(
                    "SINGLE NFT",
                    Action::Open(Page::CreateNft),
                    page == Page::CreateNft
                ),
                control(
                    "COLLECTION",
                    Action::Open(Page::CreateNftCollection),
                    page == Page::CreateNftCollection
                ),
            ]
            .spacing(6),
        );
    }
    if page == Page::CreateToken {
        form = form
            .push(
                row![
                    field("NAME", "Token name", &state.name, Action::Name, locked),
                    field("TICKER", "ABC", &state.ticker, Action::Ticker, locked),
                ]
                .spacing(10),
            )
            .push(field(
                "FIXED SUPPLY",
                "100000",
                &state.supply,
                Action::Supply,
                locked,
            ))
            .push(field(
                "DESCRIPTION · OPTIONAL",
                "What is this token for?",
                &state.description,
                Action::Description,
                locked,
            ))
            .push(field(
                "PROJECT WEBSITE · OPTIONAL",
                "https://",
                &state.website,
                Action::Website,
                locked,
            ));
        form = form.push(creation_image(state, locked, false));
        if state.supports_initial_purchase() {
            form = form.push(field(
                "INITIAL BUY / TOKENS · OPTIONAL",
                "0",
                &state.initial_buy,
                Action::InitialBuy,
                locked,
            ));
        }
        if let Some(reserve) = state.minimum_backing() {
            form = form.push(pair(
                "NOID BACKING DEPOSIT",
                crate::model::format_micronoid(reserve),
            ));
        }
        if state.supports_initial_purchase() {
            match state.initial_purchase() {
                Ok((_, cost)) => {
                    form = form.push(pair(
                        "INITIAL BUY COST / NOID",
                        crate::model::format_micronoid(cost),
                    ));
                    form = form.push(hint("Creation and your first purchase complete together. Public trading starts from the resulting curve position."));
                }
                Err(error) if !state.initial_buy.trim().is_empty() => {
                    form = form.push(text(error).size(12).color(theme::DANGER));
                }
                _ => {}
            }
        }
        form = form.push(hint("At least 100,000 tokens. Fixed supply, six decimal places and at least 0.001 NOID backing per whole token. The reserve belongs to token holders. Additional issuance is disabled."));
    } else if page == Page::CreateNftCollection {
        let fixed = locked || operation.phase == Phase::Submitted;
        form = form
            .push(field("COLLECTION NAME", "Collection name", &state.nft_name, Action::NftName, fixed))
            .push(field("DESCRIPTION · OPTIONAL", "About this collection", &state.description, Action::Description, fixed))
            .push(field("PROJECT WEBSITE · OPTIONAL", "https://", &state.website, Action::Website, fixed))
            .push(creation_image(state, fixed, false))
            .push(hint("Create the collection once, then add NFTs now or later. Only its creator can mint into it. Each NFT has its own name, image and serial."));
    } else if page == Page::MintNfts {
        form = form.push(super::collections::mint_form(
            app,
            locked || operation.phase == Phase::Submitted,
        ));
    } else if page == Page::CreateNft {
        let fixed = locked || state.nft_collection.is_some() || operation.phase == Phase::Submitted;
        let prepared = state.nft_collection.is_some();
        form = form
            .push(row![
                text(if prepared { "1 · PREPARED" } else { "1 · PREPARE" }).size(14)
                    .color(if prepared { GREEN } else { CYAN }),
                text("→").size(14).color(DIM),
                text("2 · MINT NFT").size(14).color(if prepared { CYAN } else { DIM }),
            ].spacing(12).align_y(Alignment::Center))
            .push(hint(if prepared {
                "Step 1 confirmed. Review and confirm step 2 to mint your NFT."
            } else {
                "Creating one NFT takes two transactions: prepare, then mint. Each step needs confirmation and has its own network fee."
            }))
            .push(field("NAME", "NFT name", &state.nft_name, Action::NftName, fixed))
            .push(field("DESCRIPTION · OPTIONAL", "A short description", &state.description, Action::Description, fixed))
            .push(field("PROJECT WEBSITE · OPTIONAL", "https://", &state.website, Action::Website, fixed))
            .push(creation_image(state, fixed, true));
        if let Some(id) = state.nft_collection {
            form = form.push(pair("COLLECTION", crate::assets::live::short_id(&id)));
        }
    } else if page == Page::NftBuy {
        if let Some(listing) = state
            .listings
            .selected_listing
            .and_then(|id| state.listings.listings.get(&id))
        {
            form = form
                .push(native_nft_identity(
                    state,
                    &listing.metadata,
                    &listing.collection,
                    listing.serial,
                ))
                .push(pair(
                    "NFT",
                    format!(
                        "{} · #{}",
                        crate::assets::live::short_id(&listing.collection),
                        listing.serial
                    ),
                ))
                .push(pair(
                    "ASK / NOID",
                    crate::model::format_micronoid(listing.ask),
                ))
                .push(pair("SELLER", listing.seller.clone()))
                .push(pair("EXPIRES AT BLOCK", listing.expiry))
                .push(hint(
                    "Payment and NFT ownership change together in one transaction.",
                ));
            if let Some(manifest) = state
                .library
                .manifest(&listing.metadata)
                .filter(|manifest| manifest.kind == crate::assets::media::Kind::Nft)
            {
                if let Some(image) = state
                    .library
                    .get(&listing.metadata)
                    .and_then(|bundle| bundle.image())
                    .filter(|_| state.external_data)
                {
                    form = form.push(
                        iced::widget::image(image.handle())
                            .width(180)
                            .height(180)
                            .content_fit(iced::ContentFit::Contain),
                    );
                }
                if !manifest.description.is_empty() {
                    form = form.push(hint(&manifest.description));
                }
                form = form.push(project_website(manifest));
            }
        }
    } else if nft {
        if let Some((collection, serial)) = state.live.selected_nft {
            if let Some(item) = state.live.nfts.get(&(collection, serial)) {
                form = form.push(native_nft_identity(
                    state,
                    &item.metadata,
                    &collection,
                    serial,
                ));
            }
            form = form.push(pair(
                "NFT",
                format!("{} · #{serial}", crate::assets::live::short_id(&collection)),
            ));
        }
    } else if let Some(asset) = state.live.operation_asset() {
        form = form
            .push(pair("ASSET", native_token_label(state, &asset)))
            .push(pair(
                "AVAILABLE",
                crate::assets::live::units(state.live.spendable_units(asset)),
            ));
    }
    if page == Page::Trade {
        let id = state.live.operation_asset();
        if let Some(market) = id.and_then(|id| state.markets.markets.get(&id)) {
            form = form
                .push(pair(
                    "MARKET",
                    if market.phase == crate::assets::catalog::Phase::Curve {
                        "LAUNCHPAD"
                    } else {
                        "DEX"
                    },
                ))
                .push(pair(
                    "HOLDER BACKING / NOID",
                    crate::model::format_micronoid(market.backing),
                ));
            if market.phase == crate::assets::catalog::Phase::Curve {
                form = form
                    .push(pair(
                        "CURVE SOLD / TOKENS",
                        crate::assets::live::units(u128::from(market.sold_units)),
                    ))
                    .push(pair(
                        "GRADUATION / TOKENS",
                        crate::assets::live::units(u128::from(market.sale_units)),
                    ));
            }
        }
    }
    if page == Page::Trade {
        let mut buy = button(text("BUY").size(13))
            .padding([8, 14])
            .style(move |_, status| {
                theme::button(
                    if !state.sell {
                        ButtonKind::CommandActive
                    } else {
                        ButtonKind::Command
                    },
                    status,
                )
            });
        let mut sell = button(text("SELL").size(13))
            .padding([8, 14])
            .style(move |_, status| {
                theme::button(
                    if state.sell {
                        ButtonKind::CommandActive
                    } else {
                        ButtonKind::Command
                    },
                    status,
                )
            });
        if !locked {
            buy = buy.on_press(Message::Asset(Action::Sell(false)));
            sell = sell.on_press(Message::Asset(Action::Sell(true)));
        }
        form = form.push(row![buy, sell].spacing(6));
    }
    if matches!(page, Page::TokenSend | Page::NftSend) {
        form = form.push(field(
            "RECIPIENT",
            "Paste an o1 address",
            &state.recipient,
            Action::Recipient,
            locked,
        ));
    }
    if matches!(
        page,
        Page::TokenSend | Page::Burn | Page::Trade | Page::NftList
    ) {
        let caption = match page {
            Page::NftList => "ASK / NOID",
            Page::Trade if !state.sell => "SPEND / NOID",
            _ => "AMOUNT / TOKENS",
        };
        if matches!(page, Page::TokenSend | Page::Burn) || page == Page::Trade && state.sell {
            let mut input = text_input("0.000000", &state.amount)
                .size(14)
                .padding([10, 12])
                .style(theme::text_input);
            let mut max = button(text("MAX").size(12))
                .padding([10, 14])
                .style(|_, status| theme::button(ButtonKind::Secondary, status));
            if !locked {
                input = input.on_input(|value| Message::Asset(Action::Amount(value)));
                if let Some(amount) = state.maximum_token_amount() {
                    max = max.on_press(Message::Asset(Action::Amount(amount)));
                }
            }
            form = form.push(
                column![
                    label(caption),
                    row![input, max].spacing(8).align_y(Alignment::Center)
                ]
                .spacing(6),
            );
        } else {
            form = form.push(field(
                caption,
                "0.000000",
                &state.amount,
                Action::Amount,
                locked,
            ));
        }
    }
    match page {
        Page::Trade => {
            form = form.push(field(if state.sell { "MINIMUM RECEIVE / NOID" } else { "MINIMUM RECEIVE / TOKENS" },
                "AUTO · 10% price tolerance",&state.limit,Action::Limit,locked))
                .push(hint("The review shows the current quote and the minimum you authorize. Each preceding trade changes the price. Your order is included only if its minimum can be met."));
        }
        Page::Burn => {
            form = form.push(hint("The tokens are destroyed and their share of NOID backing is returned to you in the same transaction. Review the payout after the network fee."));
        }
        Page::NftBurn => {
            form = form.push(hint(
                "Burning permanently destroys this NFT. Its serial cannot be issued again.",
            ));
        }
        Page::NftList => {
            form = form.push(hint("The listing lasts about one day at the target block rate. You can cancel it while it remains unsold. The review includes the refundable listing credit."));
        }
        Page::NftCancel => {
            form = form.push(hint("Cancel the unsold listing and return the NFT and remaining listing credit to this address."));
        }
        _ => {}
    }
    if let Some(error) = &operation.error {
        form = form.push(text(error).size(13).color(theme::DANGER));
    }
    if let Some(submission) = &operation.submission {
        let mut submitted = column![
            value("Accepted by your local node."),
            label("TRANSACTION ID"),
            identifier(&submission.txid),
            super::super::copy_value_button(
                &submission.txid,
                app.copied_value.as_deref() == Some(&submission.txid)
            ),
        ]
        .spacing(8);
        let submitted_title = if page == Page::CreateNft {
            submitted = submitted.push(hint(if state.nft_collection.is_some() {
                "Step 2 sent. Your NFT will appear in My NFTs after this transaction confirms."
            } else {
                "Step 1 sent. Wait for confirmation, then confirm step 2 to mint your NFT. You can resume from Prepared NFTs in My NFTs."
            }));
            if state.nft_collection.is_some() {
                "STEP 2 / 2 · MINT SUBMITTED"
            } else {
                "STEP 1 / 2 · PREPARATION SUBMITTED"
            }
        } else if page == Page::CreateNftCollection {
            submitted = submitted.push(hint("Waiting for the collection to confirm. Its page will open when it is ready for adding NFTs."));
            "COLLECTION SUBMITTED"
        } else if page == Page::MintNfts {
            submitted = submitted.push(hint("Waiting for confirmation. All NFTs in this batch appear together after the transaction confirms."));
            "NFT BATCH SUBMITTED"
        } else if page == Page::Trade {
            submitted = submitted.push(hint("Waiting for a block to confirm your order. This panel closes automatically after your balances update. You can close it now and follow the order in Receipts."));
            if let Some(height) = operation.preview.as_ref().and_then(|p| p.valid_until) {
                submitted = submitted.push(pair("VALID THROUGH BLOCK", height));
            }
            submitted = submitted.push(control("CLOSE", Action::CloseTradeStatus, false));
            "WAITING FOR CONFIRMATION"
        } else if matches!(page, Page::NftList | Page::NftCancel) {
            submitted = submitted.push(hint(if page == Page::NftList {
                "Waiting for confirmation. Your sale will appear in My Listings and Marketplace."
            } else {
                "Waiting for confirmation. The NFT will return to My NFTs and can be listed again."
            }));
            "WAITING FOR CONFIRMATION"
        } else {
            submitted = submitted.push(control("NEW OPERATION", Action::ResetLive, false));
            "SUBMITTED"
        };
        form = form.push(tagged(submitted_title, GREEN, submitted));
    } else if let Some(preview) = &operation.preview {
        form = form.push(review(preview));
        let mut confirm = button(
            text(if locked {
                "BUILDING PROOF…"
            } else if page == Page::CreateNft {
                if state.nft_collection.is_some() {
                    "CONFIRM MINT · STEP 2 / 2"
                } else {
                    "CONFIRM PREPARATION · STEP 1 / 2"
                }
            } else {
                "CONFIRM & SEND"
            })
            .size(13),
        )
        .padding([10, 16])
        .style(|_, status| theme::button(ButtonKind::Primary, status));
        if operation.phase == Phase::Ready && state.native_operations_enabled() {
            confirm = confirm.on_press(Message::Asset(Action::ConfirmLive));
        }
        form = form.push(confirm);
    } else {
        let mut review = button(
            text(if operation.phase == Phase::Previewing {
                "CALCULATING…"
            } else if page == Page::CreateNft {
                if state.nft_collection.is_some() {
                    "REVIEW MINT · STEP 2 / 2"
                } else {
                    "REVIEW PREPARATION · STEP 1 / 2"
                }
            } else {
                "REVIEW"
            })
            .size(13),
        )
        .padding([10, 16])
        .style(|_, status| theme::button(ButtonKind::Primary, status));
        if operation.phase != Phase::Previewing
            && state.live.complete
            && state.native_operations_enabled()
            && !state.media.loading
        {
            review = review.on_press(Message::Asset(Action::ReviewLive));
        }
        form = form.push(review);
    }
    let back = state.back_page(nft).unwrap_or(if nft {
        Page::Collection
    } else {
        Page::Holdings
    });
    let mut cancel = button(text("BACK").size(13))
        .padding([8, 12])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if !locked {
        cancel = cancel.on_press(Message::Asset(Action::Open(back)));
    }
    if !nft && app.action == Some(crate::app::Action::Send) {
        return column![currency_picker(app), form].spacing(GAP).into();
    }
    if page.is_dialog() {
        return form.into();
    }
    if page == Page::Trade {
        return column![live_heading(app), tagged(title, CYAN, form)]
            .spacing(GAP)
            .into();
    }
    column![
        live_heading(app),
        tagged(title, if nft { theme::PROOF } else { CYAN }, form),
        cancel
    ]
    .spacing(GAP)
    .into()
}

fn review(preview: &Preview) -> El<'_> {
    let mut details = column![
        value(preview.request.title()),
        label("FROM"),
        identifier(&preview.owner)
    ]
    .spacing(9);
    match &preview.request {
        Request::TransferToken {
            units, recipient, ..
        } => {
            details = details
                .push(pair("TOKENS", amount(units)))
                .push(label("TO"))
                .push(identifier(recipient));
        }
        Request::BurnToken { units, .. } => {
            details = details.push(pair("BURN", amount(units)));
        }
        Request::Trade {
            buy, gross_input, ..
        } => {
            details = details.push(pair(
                if *buy {
                    "SPEND UP TO / NOID"
                } else {
                    "SELL UP TO / TOKENS"
                },
                amount(gross_input),
            ));
            if let Some(pending) = &preview.pending_quote {
                if let Some(output) = &pending.confirmed_output {
                    details = details.push(pair(
                        if *buy {
                            "CURRENT STATE / TOKENS"
                        } else {
                            "CURRENT STATE / NOID"
                        },
                        amount(output),
                    ));
                }
                details = details.push(pair("PENDING TRADES", pending.pending_policies));
                if let Some(position) = pending.position {
                    details = details.push(pair("POSITION IN THIS MARKET", position + 1));
                } else {
                    details=details.push(hint("This order is waiting for capacity or its price bound in the current local candidate."));
                }
                details=details.push(hint("The estimate includes locally known pending trades in a native block candidate. The block's selected trades determine the final price. Your minimum and fee limit remain fixed."));
            }
            if let Some(quote) = &preview.quoted_output {
                details = details.push(pair(
                    if *buy {
                        "EXPECTED TOKENS"
                    } else {
                        "EXPECTED NOID"
                    },
                    amount(quote),
                ));
            }
            if let Some(minimum) = &preview.minimum_output {
                details = details.push(pair(
                    if *buy {
                        "MINIMUM TOKENS"
                    } else {
                        "MINIMUM NOID"
                    },
                    amount(minimum),
                ));
            }
            if let Some(until) = preview.valid_until {
                details = details.push(pair("VALID THROUGH BLOCK", until));
            }
        }
        Request::TransferNft { recipient, .. } => {
            details = details.push(label("TO")).push(identifier(recipient));
        }
        Request::ListNft {
            ask_micronoid,
            expiry_height,
            ..
        } => {
            details = details
                .push(pair("ASK / NOID", amount(ask_micronoid)))
                .push(pair("EXPIRES AT BLOCK", expiry_height));
        }
        Request::BuyNft {
            maximum_ask_micronoid,
            ..
        } => {
            details = details.push(pair("MAXIMUM ASK / NOID", amount(maximum_ask_micronoid)));
        }
        Request::CreateToken {
            whole_tokens,
            metadata_hash,
            initial_buy_units,
        } => {
            details = details
                .push(pair("FIXED SUPPLY", whole_tokens))
                .push(label("METADATA HASH"))
                .push(text(metadata_hash.clone()).size(11));
            if let Some(reserve) = &preview.reserve_deposit_micronoid {
                details = details.push(pair("BACKING DEPOSIT / NOID", amount(reserve)));
            }
            if let Some(units) = initial_buy_units {
                details = details.push(pair("INITIAL BUY / TOKENS", amount(units)));
            }
            if let Some(cost) = &preview.initial_buy_cost_micronoid {
                details = details.push(pair("INITIAL BUY COST / NOID", amount(cost)));
            }
        }
        Request::CreateCollection {
            maximum_items,
            metadata_hash,
        } => {
            details = details
                .push(if maximum_items == &u64::MAX.to_string() {
                    pair("ISSUANCE", "The creator can add NFTs later")
                } else {
                    pair("MAXIMUM ITEMS", maximum_items)
                })
                .push(label("METADATA HASH"))
                .push(text(metadata_hash.clone()).size(11));
            if let Some(id) = &preview.collection_id {
                details = details
                    .push(label("COLLECTION ID"))
                    .push(text(id.clone()).size(11));
            }
        }
        Request::MintNft {
            collection_id,
            metadata_hash,
        } => {
            details = details
                .push(label("COLLECTION ID"))
                .push(text(collection_id.clone()).size(11))
                .push(pair(
                    "SERIAL",
                    preview.serial.as_deref().unwrap_or("Unavailable"),
                ))
                .push(label("METADATA HASH"))
                .push(text(metadata_hash.clone()).size(11));
        }
        Request::MintNfts {
            collection_id,
            metadata_hashes,
        } => {
            details = details
                .push(pair("NFTS IN THIS BATCH", metadata_hashes.len()))
                .push(pair(
                    "SERIALS",
                    format!(
                        "#{} – #{}",
                        preview.serial.as_deref().unwrap_or("?"),
                        preview.last_serial.as_deref().unwrap_or("?")
                    ),
                ))
                .push(label("COLLECTION ID"))
                .push(text(collection_id.clone()).size(11));
        }
        _ => {}
    }
    if let Some(value) = &preview.redemption_micronoid {
        details = details.push(pair("BACKING RETURNED / NOID", amount(value)));
    }
    let trade = matches!(preview.request, Request::Trade { .. });
    details = details.push(line()).push(pair(
        if trade {
            "ESTIMATED NETWORK FEE / NOID"
        } else {
            "NETWORK FEE / NOID"
        },
        amount(&preview.fee_micronoid),
    ));
    if let Some(limit) = &preview.fee_limit_micronoid {
        details = details.push(pair("MAXIMUM NETWORK FEE / NOID", amount(limit)));
    }
    if integer(&preview.noid_debit_micronoid).is_ok_and(|n| n > 0) {
        details = details.push(pair(
            if trade {
                "ESTIMATED NOID DEBIT"
            } else {
                "TOTAL NOID DEBIT"
            },
            amount(&preview.noid_debit_micronoid),
        ));
    }
    if integer(&preview.noid_credit_micronoid).is_ok_and(|n| n > 0) {
        details = details.push(pair(
            if trade {
                "ESTIMATED NET NOID"
            } else {
                "NET NOID RETURNED"
            },
            amount(&preview.noid_credit_micronoid),
        ));
    }
    tagged("REVIEW", GREEN, details).into()
}

fn creation_image(state: &State, locked: bool, nft: bool) -> El<'_> {
    let mut content = Column::new().spacing(8);
    let mut choose = button(
        text(if state.media.loading {
            "PREPARING IMAGE…"
        } else {
            if state.nft_page == Page::CreateNftCollection {
                "CHOOSE COVER"
            } else if nft {
                "CHOOSE IMAGE"
            } else {
                "CHOOSE LOGO"
            }
        })
        .size(13),
    )
    .padding([8, 12])
    .style(|_, status| theme::button(ButtonKind::Command, status));
    if !locked && !state.media.loading {
        choose = choose.on_press(Message::Asset(Action::ChooseImage));
    }
    let mut media = column![
        choose,
        hint(if nft {
            "PNG, JPEG or WebP · up to 4 MB"
        } else {
            "Optional · PNG, JPEG or WebP · up to 4 MB"
        })
    ]
    .spacing(7);
    if let Some(image) = &state.media.image {
        let mut remove = button(text("REMOVE").size(12))
            .padding([6, 10])
            .style(|_, status| theme::button(ButtonKind::Command, status));
        if !locked {
            remove = remove.on_press(Message::Asset(Action::RemoveImage));
        }
        media = media.push(remove);
        content = content.push(
            row![
                container(
                    iced::widget::image(image.handle())
                        .width(if nft { 180 } else { 80 })
                        .height(if nft { 180 } else { 80 })
                        .content_fit(iced::ContentFit::Contain)
                )
                .padding(8)
                .style(theme::surface),
                media,
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        );
    } else {
        content = content.push(media);
    }
    if let Some(error) = &state.media.error {
        content = content.push(text(error).size(13).color(theme::DANGER));
    }
    if state.library.publication_pending > 0 {
        content = content.push(hint(
            state
                .library
                .publication_error
                .as_deref()
                .unwrap_or("Media publication is waiting for confirmation."),
        ));
    }
    content.into()
}
