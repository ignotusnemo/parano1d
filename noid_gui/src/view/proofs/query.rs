// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::model::receipt_query::{Action, Operation, Order, Verification};
use iced::widget::{column, pick_list, Row};

fn button_action(label: &str, action: Action, active: bool) -> Element<'static, Message> {
    button(text(label.to_owned()).size(12))
        .on_press(Message::ReceiptQuery(action))
        .padding([7, 12])
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

pub(super) fn header<'a>(app: &'a App, families: Row<'a, Message>) -> Element<'a, Message> {
    row![
        families,
        Space::new().width(Length::Fill),
        button_action(
            "FILTERS",
            Action::Toggle,
            app.receipt_query.open || !app.receipt_query.applied.is_default()
        ),
        pick_list(Order::ALL, Some(app.receipt_query.order), |order| {
            Message::ReceiptQuery(Action::Order(order))
        })
        .text_size(12)
        .padding([7, 11])
        .width(164)
        .style(|_, status| theme::asset_picker(status))
        .menu_style(|_| theme::asset_picker_menu())
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into()
}

pub(super) fn view(app: &App, compact: bool) -> Element<'_, Message> {
    let state = &app.receipt_query;
    let asset = column![
        text("ASSET OR COLLECTION ID").size(10).color(theme::DIM),
        text_input("64 hex characters · optional", &state.asset)
            .on_input(|s| Message::ReceiptQuery(Action::Asset(s)))
            .on_submit(Message::ReceiptQuery(Action::Apply))
            .padding([8, 10])
            .size(12)
            .style(theme::text_input)
    ]
    .spacing(5)
    .width(Length::FillPortion(3));
    let operation = column![
        text("OPERATION").size(10).color(theme::DIM),
        pick_list(Operation::ALL, Some(state.operation), |value| {
            Message::ReceiptQuery(Action::Operation(value))
        })
        .text_size(12)
        .padding([8, 10])
        .width(Length::Fill)
        .style(|_, status| theme::asset_picker(status))
        .menu_style(|_| theme::asset_picker_menu())
    ]
    .spacing(5)
    .width(Length::FillPortion(2));
    let dates = row![
        column![
            text("FROM · UTC").size(10).color(theme::DIM),
            text_input("YYYY-MM-DD", &state.from)
                .on_input(|s| Message::ReceiptQuery(Action::From(s)))
                .on_submit(Message::ReceiptQuery(Action::Apply))
                .padding([8, 10])
                .size(12)
                .style(theme::text_input)
        ]
        .spacing(5)
        .width(Length::Fill),
        column![
            text("THROUGH · UTC").size(10).color(theme::DIM),
            text_input("YYYY-MM-DD", &state.through)
                .on_input(|s| Message::ReceiptQuery(Action::Through(s)))
                .on_submit(Message::ReceiptQuery(Action::Apply))
                .padding([8, 10])
                .size(12)
                .style(theme::text_input)
        ]
        .spacing(5)
        .width(Length::Fill)
    ]
    .spacing(9)
    .width(Length::FillPortion(3));
    let status = column![
        text("VERIFICATION").size(10).color(theme::DIM),
        pick_list(Verification::ALL, Some(state.verification), |value| {
            Message::ReceiptQuery(Action::Verification(value))
        })
        .text_size(12)
        .padding([8, 10])
        .width(Length::Fill)
        .style(|_, status| theme::asset_picker(status))
        .menu_style(|_| theme::asset_picker_menu())
    ]
    .spacing(5)
    .width(Length::FillPortion(2));
    let mut content = column![
        row![asset, operation].spacing(10),
        row![dates, status].spacing(10)
    ]
    .spacing(10);
    if let Some(error) = &state.error {
        content = content.push(text(error).size(12).color(theme::DANGER));
    }
    let note = if compact {
        "Filter and sort the complete saved history."
    } else {
        "Filters and sorting apply to the complete saved history before pagination."
    };
    content = content.push(
        row![
            text(note).size(11).color(theme::DIM),
            Space::new().width(Length::Fill),
            button_action("CLEAR", Action::Clear, false),
            button_action("APPLY", Action::Apply, true)
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    );
    container(content)
        .padding(12)
        .width(Length::Fill)
        .style(theme::surface)
        .into()
}
