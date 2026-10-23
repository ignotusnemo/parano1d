// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::assets::{live, operations::Phase};
use iced::widget::column;

fn cover(state: &State, metadata: &[u8; 32], size: u32) -> El<'static> {
    match state
        .library
        .get(metadata)
        .filter(|bundle| bundle.manifest().kind == crate::assets::media::Kind::Collection)
        .and_then(|bundle| bundle.image())
        .filter(|_| state.external_data)
    {
        Some(image) => iced::widget::image(image.handle())
            .width(size)
            .height(size)
            .content_fit(iced::ContentFit::Contain)
            .into(),
        None => container(mark("C", theme::PROOF))
            .width(size)
            .height(size)
            .center(size)
            .into(),
    }
}

pub(super) fn view(app: &App) -> El<'_> {
    detail(app)
}

fn detail(app: &App) -> El<'_> {
    let state = &app.assets;
    let Some(id) = state.nft_group else {
        return column![
            go("← MY NFTS", Page::Collection, false),
            hint("Choose a collection.")
        ]
        .spacing(GAP)
        .into();
    };
    let owned = state.live.collections.get(&id);
    let public = state.nft_collections.collections.get(&id);
    let metadata = state.collection_metadata(&id);
    let issued = owned
        .map(|group| group.issued)
        .or_else(|| public.map(|group| group.issued));
    let manifest = state.collection_manifest(&id);
    let mut info = column![
        text(state.collection_name(&id)).size(24),
        label("COLLECTION ID"),
        row![
            value(hex::encode(id)),
            super::super::copy_value_button(
                &hex::encode(id),
                app.copied_value.as_deref() == Some(hex::encode(id).as_str())
            )
        ]
        .spacing(6)
    ]
    .spacing(10);
    if let Some(issued) = issued {
        info = info.push(pair("NFTS ISSUED", issued));
    }
    if let Some(group) = public {
        info = info.push(label("CREATOR")).push(value(&group.creator));
    }
    if let Some(manifest) = manifest {
        if !manifest.description.is_empty() {
            info = info.push(value(&manifest.description));
        }
        if let Some(url) = &manifest.website {
            info = info.push(control(
                "PROJECT WEBSITE ↗",
                Action::OpenWebsite(url.clone()),
                false,
            ));
        }
    }
    let mut actions=column![hint("Only the creator can add NFTs. Each issued NFT keeps its own identity, image and ownership.")].spacing(10);
    if owned.is_some_and(|group| !group.reserved && group.issued < group.maximum) {
        actions = actions.push(control("ADD NFTS", Action::MintCollection(id), true));
    } else if owned.is_some_and(|group| group.reserved) {
        actions = actions.push(hint("A collection operation is waiting for confirmation."));
    }
    let header = tagged(
        "COLLECTION",
        theme::PROOF,
        column![
            row![cover(state, &metadata.unwrap_or_default(), 140), info].spacing(16),
            actions
        ]
        .spacing(14),
    );
    let cards = state.nft_cards(false, Some(id), state.nft_group_listed_only);
    let gallery = responsive(move |size| {
        let cards = state.nft_cards(false, Some(id), state.nft_group_listed_only);
        super::nft_gallery::grid(app, false, true, &cards, size.width < 880.0)
    });
    column![
        go(
            if state.nft_group_listed_only {
                "← MY LISTINGS"
            } else {
                "← MY NFTS"
            },
            if state.nft_group_listed_only {
                Page::Listings
            } else {
                Page::Collection
            },
            false
        ),
        header,
        super::nft_gallery::controls(app, false, true, cards.len()),
        gallery
    ]
    .spacing(14)
    .into()
}

pub(super) fn mint_form(app: &App, locked: bool) -> El<'_> {
    let state = &app.assets;
    let Some(id) = state.nft_group else {
        return hint("Choose a collection.");
    };
    let mut choose = button(
        text(if state.nft_batch.loading {
            "PREPARING IMAGES…"
        } else {
            "ADD IMAGES"
        })
        .size(13),
    )
    .padding([9, 14])
    .style(|_, status| theme::button(ButtonKind::Command, status));
    if !locked && !state.nft_batch.loading && state.nft_batch.items.len() < state.nft_batch_limit()
    {
        choose = choose.on_press(Message::Asset(Action::ChooseNftImages));
    }
    let mut items = Column::new().spacing(8);
    for (index, item) in state.nft_batch.items.iter().enumerate() {
        let mut name = text_input("NFT name", &state.nft_batch_name(index))
            .padding([10, 12])
            .size(14)
            .style(theme::text_input);
        let mut remove = button(text("REMOVE").size(12))
            .padding([7, 10])
            .style(|_, status| theme::button(ButtonKind::Secondary, status));
        if !locked && !state.nft_batch.loading {
            name = name.on_input(move |name| Message::Asset(Action::NftBatchName(index, name)));
            remove = remove.on_press(Message::Asset(Action::RemoveNftImage(index)));
        }
        items = items.push(
            container(
                row![
                    iced::widget::image(item.image.handle())
                        .width(64)
                        .height(64)
                        .content_fit(iced::ContentFit::Contain),
                    column![
                        label(&format!(
                            "NFT #{}",
                            state.nft_batch_serial(index).unwrap_or(0)
                        )),
                        name
                    ]
                    .spacing(5)
                    .width(Length::Fill),
                    remove
                ]
                .spacing(12)
                .align_y(Alignment::Center),
            )
            .padding(10)
            .style(theme::surface),
        );
    }
    let mut description = text_input("Optional description for this batch", &state.description)
        .padding([10, 12])
        .size(14)
        .style(theme::text_input);
    let mut website = text_input("https://", &state.website)
        .padding([10, 12])
        .size(14)
        .style(theme::text_input);
    if !locked {
        description = description.on_input(|value| Message::Asset(Action::Description(value)));
        website = website.on_input(|value| Message::Asset(Action::Website(value)));
    }
    let mut form=column![text(state.collection_name(&id)).size(20),label(&format!("{} · {} NFTS IN THIS BATCH",live::short_id(&id),state.nft_batch.items.len())),
        hint(&format!("Choose up to {} images for one transaction. You can add more batches to this collection later. PNG, JPEG or WebP, up to 4 MB per image.",state.nft_batch_limit())),choose,
        label("DESCRIPTION FOR THIS BATCH · OPTIONAL"),description,label("PROJECT WEBSITE · OPTIONAL"),website,items].spacing(12);
    if let Some(error) = &state.nft_batch.error {
        form = form.push(text(error).size(13).color(theme::DANGER));
    }
    if state.operation.phase == Phase::Previewing {
        form = form.push(hint("Checking the batch and network fee…"));
    }
    form.into()
}
