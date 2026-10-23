// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::assets::{live::TokenOutput, Action as AssetAction};
use iced::widget::column;

pub(super) fn token_metric(
    caption: &str,
    value: String,
    color: iced::Color,
    label_size: f32,
    value_size: f32,
) -> Element<'static, Message> {
    column![
        text(caption).size(label_size).color(theme::DIM),
        text(value).size(value_size).color(color)
    ]
    .spacing(6)
    .into()
}

fn segment(app: &App, slot: u32) -> u8 {
    let domains = 1usize
        .checked_shl(app.snapshot.network.log_slots.saturating_sub(16))
        .unwrap_or(256)
        .max(1);
    let buckets = app.snapshot.segments.len().clamp(1, 256);
    ((slot as usize >> 16).saturating_mul(buckets) / domains).min(buckets - 1) as u8
}

fn status(app: &App, output: &TokenOutput) -> (&'static str, iced::Color) {
    if output.reserved {
        ("RESERVED", theme::WARNING)
    } else if output.unlock_height > app.snapshot.network.height.saturating_add(1) {
        ("LOCKED", theme::ADVISORY)
    } else {
        ("AVAILABLE", theme::ACCENT)
    }
}

pub(super) fn token_outputs(app: &App) -> container::Container<'_, Message> {
    let token = app.assets.main_token();
    let mut outputs = token
        .map(|token| {
            token
                .carriers
                .iter()
                .filter(|output| {
                    app.assets
                        .native_segment
                        .is_none_or(|filter| segment(app, output.slot) == filter)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    outputs.sort_by_key(|output| output.slot);
    let pages = outputs.len().div_ceil(UTXO_PAGE_SIZE).max(1);
    let page = app.assets.native_page.min(pages - 1);
    let mut rows = column![].spacing(0);
    for (index, output) in outputs
        .iter()
        .skip(page * UTXO_PAGE_SIZE)
        .take(UTXO_PAGE_SIZE)
        .enumerate()
    {
        let (state, color) = status(app, output);
        let selected = app.assets.native_output == Some(output.slot);
        rows = rows.push(
            button(
                row![
                    table_cell(output.slot.to_string(), 3, theme::CYAN),
                    table_cell(
                        crate::assets::live::units(u128::from(output.units)),
                        8,
                        theme::TEXT
                    ),
                    table_cell(
                        format!("#{}", output.creation_id & ((1u64 << 62) - 1)),
                        5,
                        theme::MUTED
                    ),
                    table_cell(
                        if output.unlock_height == 0 {
                            "—".into()
                        } else {
                            output.unlock_height.to_string()
                        },
                        3,
                        theme::PROOF
                    ),
                    table_cell(state.into(), 6, color),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            )
            .on_press(Message::Asset(AssetAction::SelectMainOutput(output.slot)))
            .padding([8, 9])
            .width(Length::Fill)
            .style(move |_, status| theme::utxo_row(index % 2 == 1, selected, status)),
        );
    }
    if outputs.is_empty() {
        rows = rows.push(
            container(
                text(if app.assets.live.complete {
                    "No token outputs in this view."
                } else {
                    "Loading confirmed token outputs…"
                })
                .size(13)
                .color(theme::DIM),
            )
            .padding(12),
        );
    }
    let mut previous = button(text("← PREV").size(12))
        .padding([5, 8])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    let mut next = button(text("NEXT →").size(12))
        .padding([5, 8])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if page > 0 {
        previous = previous.on_press(Message::Asset(AssetAction::NativePage(page - 1)));
    }
    if page + 1 < pages {
        next = next.on_press(Message::Asset(AssetAction::NativePage(page + 1)));
    }
    let filter: Element<'_, Message> = if let Some(value) = app.assets.native_segment {
        button(text(format!("SEGMENT {value:03} · SHOW ALL")).size(12))
            .padding([4, 8])
            .on_press(Message::SelectSegment(value))
            .style(|_, status| theme::button(ButtonKind::Secondary, status))
            .into()
    } else {
        text(format!("{} OUTPUTS", outputs.len())).size(13).into()
    };
    container(
        column![
            container(
                row![
                    container(text("MY TOKEN OUTPUTS").size(13))
                        .padding([6, 9])
                        .style(theme::title_bar_cyan),
                    iced::widget::Space::new().width(Length::Fill),
                    container(filter).padding(Padding::ZERO.right(9))
                ]
                .align_y(Alignment::Center)
            )
            .style(theme::surface_alt),
            table_columns("SLOT", "TOKENS", "STATE ID", "UNLOCK", "STATUS"),
            scrollable(rows)
                .height(Length::Fill)
                .style(theme::scrollable),
            container(
                row![
                    text(if app.assets.live.complete {
                        "CONFIRMED STATE"
                    } else {
                        "LOADING"
                    })
                    .size(12)
                    .color(theme::CYAN),
                    iced::widget::Space::new().width(Length::Fill),
                    previous,
                    text(format!("PAGE {} / {pages}", page + 1)).size(12),
                    next
                ]
                .spacing(7)
                .align_y(Alignment::Center)
            )
            .padding([7, 9]),
        ]
        .spacing(0),
    )
    .style(theme::surface)
    .width(Length::Fill)
}

pub(super) fn token_state(app: &App) -> container::Container<'_, Message> {
    let outputs = app
        .assets
        .main_token()
        .map(|token| token.carriers.as_slice())
        .unwrap_or_default();
    let utxos = outputs
        .iter()
        .map(|output| UtxoSnapshot {
            slot_index: output.slot,
            value_micronoid: output.units,
            creation_id: output.creation_id,
            segment: segment(app, output.slot),
            reserved: output.reserved,
        })
        .collect::<Vec<_>>();
    let mut segments = app.snapshot.segments.clone();
    for bucket in &mut segments {
        bucket.owned = false;
    }
    for utxo in &utxos {
        if let Some(bucket) = segments.get_mut(utxo.segment as usize) {
            bucket.owned = true;
        }
    }
    let selected = outputs
        .iter()
        .find(|output| Some(output.slot) == app.assets.native_output);
    let field = iced::widget::canvas(StateField::new(
        &segments,
        &utxos,
        selected.map(|output| segment(app, output.slot)),
        app.assets.native_segment,
    ))
    .width(Length::Fill)
    .height(Length::Fill);
    let selection: Element<'_, Message> = if let Some(output) = selected {
        let (state, color) = status(app, output);
        column![
            row![
                text("SELECTED TOKEN OUTPUT").size(13).color(theme::PROOF),
                iced::widget::Space::new().width(Length::Fill),
                text(state).size(13).color(color)
            ]
            .align_y(Alignment::Center),
            row![
                state_detail("SLOT", output.slot.to_string(), theme::CYAN),
                iced::widget::Space::new().width(Length::Fill),
                text(format!(
                    "{} TOKENS",
                    crate::assets::live::units(u128::from(output.units))
                ))
                .size(15)
            ]
            .spacing(8),
        ]
        .spacing(7)
        .into()
    } else {
        text("SELECT A TOKEN OUTPUT OR MAGENTA SEGMENT")
            .size(12)
            .color(theme::CYAN)
            .into()
    };
    container(
        column![
            container(
                row![
                    container(text("LIVE STATE").size(13))
                        .padding([6, 9])
                        .style(theme::title_bar_proof),
                    iced::widget::Space::new().width(Length::Fill),
                    text(format!(
                        "[{}] ROOT [{}]",
                        if app.snapshot.network.terminal_verified {
                            "VERIFIED"
                        } else {
                            "UNVERIFIED"
                        },
                        short_digest(&app.snapshot.network.state_root)
                    ))
                    .size(12)
                    .color(theme::PROOF)
                ]
                .align_y(Alignment::Center)
            )
            .style(theme::surface_alt),
            container(field).padding(7).height(Length::Fill),
            container(
                column![
                    selection,
                    row![
                        legend_item(theme::CYAN, "STATE DENSITY"),
                        legend_item(theme::PROOF, "MY TOKEN OUTPUTS")
                    ]
                    .spacing(12)
                ]
                .spacing(9)
            )
            .padding([9, 10]),
        ]
        .spacing(0),
    )
    .style(theme::surface)
    .width(Length::Fill)
}
