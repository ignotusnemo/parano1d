// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use std::time::{SystemTime, UNIX_EPOCH};

use iced::widget::{button, column, container, row, scrollable, Space};
use iced::{Alignment, Element, Length, Padding};

use crate::app::{App, Message};
use crate::i18n::{text, text_input};
use crate::model::{
    format_creation_origin, format_micronoid, grouped, ExplorerAddressSnapshot,
    ExplorerBlockSnapshot, ExplorerSearchResultSnapshot, ExplorerSlotSnapshot,
    RecentTransactionSnapshot, RecentTransactionsSnapshot, EXPLORER_SLOT_PAGE_SIZE,
};
use crate::theme::{self, ButtonKind};

use super::copy_value_button;

pub fn view(app: &App, compact: bool) -> Element<'_, Message> {
    let search = search_bar(app, compact);
    let body = match &app.explorer_result {
        Some(result) => search_result(app, result, compact),
        None => explorer_home(app, compact),
    };

    let mut content = column![search].spacing(10);
    if let Some(error) = &app.explorer_error {
        content = content.push(
            container(
                row![
                    text("SEARCH").size(13).color(theme::DANGER),
                    text(error).size(13).color(theme::MUTED),
                ]
                .spacing(12)
                .align_y(Alignment::Center),
            )
            .width(Length::Fill)
            .padding([9, 12])
            .style(theme::surface),
        );
    }
    content = content.push(body);

    container(
        scrollable(container(content).padding(Padding::ZERO.right(10))).style(theme::scrollable),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .padding(12)
    .into()
}

fn search_bar(app: &App, compact: bool) -> Element<'_, Message> {
    let query = text_input(
        "ADDRESS · BLOCK HEIGHT/HASH · TXID · SLOT:<NUMBER>",
        &app.explorer_query,
    )
    .on_input(Message::ExplorerQueryChanged)
    .on_submit(Message::SubmitExplorerSearch)
    .size(14)
    .padding([11, 13])
    .width(Length::Fill)
    .style(theme::scope_search_input);

    let label = if app.explorer_searching {
        "SEARCHING…"
    } else {
        "SEARCH"
    };
    let mut submit = button(text(label).size(13))
        .padding([9, 14])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if !app.explorer_searching {
        submit = submit.on_press(Message::SubmitExplorerSearch);
    }
    let clear = button(text("CLEAR").size(13))
        .on_press(Message::ClearExplorerSearch)
        .padding([9, 12])
        .style(|_, status| theme::button(ButtonKind::Ghost, status));
    let mut refresh = button(text(if app.explorer_loading {
        "REFRESHING…"
    } else {
        "REFRESH"
    }))
    .padding([9, 12])
    .style(|_, status| theme::button(ButtonKind::Ghost, status));
    if !app.explorer_loading {
        refresh = refresh.on_press(Message::RefreshExplorer);
    }

    let controls: Element<'_, Message> = if compact {
        column![
            query,
            row![submit, clear, Space::new().width(Length::Fill), refresh]
                .spacing(7)
                .align_y(Alignment::Center),
        ]
        .spacing(7)
        .into()
    } else {
        row![query, submit, clear, refresh]
            .spacing(7)
            .align_y(Alignment::Center)
            .into()
    };

    let retention_note: Element<'_, Message> =
        text("Search live state. Full block data is retained for 18 blocks; receipts prove older payments.")
            .size(13)
            .color(theme::MUTED)
            .wrapping(iced::widget::text::Wrapping::None)
            .into();

    container(column![controls, retention_note].spacing(8))
        .width(Length::Fill)
        .padding(10)
        .style(theme::surface)
        .into()
}

fn explorer_home(app: &App, compact: bool) -> Element<'_, Message> {
    if app.explorer_loading && app.explorer.blocks.is_empty() {
        return container(
            column![
                text("READING CANONICAL STATE").size(13).color(theme::CYAN),
                text("Headers, retained transactions and live state remain node-verified.")
                    .size(13)
                    .color(theme::DIM),
            ]
            .spacing(6)
            .align_x(Alignment::Center),
        )
        .width(Length::Fill)
        .height(Length::Fixed(240.0))
        .align_x(Alignment::Center)
        .align_y(Alignment::Center)
        .style(theme::surface)
        .into();
    }

    let retained = &app.explorer.recent_transactions;
    let metrics: Element<'_, Message> = if compact {
        column![
            row![
                metric("TIP", grouped(app.explorer.tip_height), theme::CYAN),
                metric(
                    "LIVE UTXOS",
                    grouped(app.snapshot.network.active_slots),
                    theme::ACCENT,
                ),
            ]
            .spacing(7),
            row![
                metric(
                    "STATE LVL",
                    format!("m{}", app.snapshot.network.log_slots),
                    theme::PROOF,
                ),
                metric(
                    "FULL DATA",
                    format!(
                        "#{}–#{}",
                        retained.retained_from_height, retained.tip_height
                    ),
                    theme::TEXT,
                ),
            ]
            .spacing(7),
        ]
        .spacing(7)
        .into()
    } else {
        row![
            metric("TIP", grouped(app.explorer.tip_height), theme::CYAN),
            metric(
                "LIVE UTXOS",
                grouped(app.snapshot.network.active_slots),
                theme::ACCENT,
            ),
            metric(
                "STATE LVL",
                format!("m{}", app.snapshot.network.log_slots),
                theme::PROOF,
            ),
            metric(
                "FULL DATA",
                format!(
                    "#{}–#{}",
                    retained.retained_from_height, retained.tip_height
                ),
                theme::TEXT,
            ),
        ]
        .spacing(7)
        .into()
    };

    column![
        metrics,
        blocks_panel(app, compact),
        recent_transactions_panel(app, retained, compact, false),
    ]
    .spacing(10)
    .into()
}

fn blocks_panel(app: &App, compact: bool) -> Element<'_, Message> {
    let title = row![
        text("CANONICAL BLOCKS").size(13).color(theme::CYAN),
        text(format!("[0…{}]", grouped(app.explorer.tip_height)))
            .size(13)
            .color(theme::MUTED),
        Space::new().width(Length::Fill),
        legend("FULL", theme::ACCENT),
        legend("HEADER", theme::DIM),
    ]
    .spacing(9)
    .align_y(Alignment::Center);

    let rows: Element<'_, Message> = if app.explorer.blocks.is_empty() {
        empty_state("NO CANONICAL HEADERS AVAILABLE")
    } else if compact {
        let mut list = column![].spacing(5);
        for block in &app.explorer.blocks {
            list = list.push(compact_block(app, block));
        }
        list.into()
    } else {
        let header = container(
            row![
                table_cell("HEIGHT", 2, theme::MUTED),
                table_cell("AGE", 2, theme::MUTED),
                table_cell("BLOCK", 6, theme::MUTED),
                table_cell("STATE", 2, theme::MUTED),
                table_cell("AVAILABLE", 3, theme::MUTED),
                text("OPEN")
                    .size(13)
                    .color(theme::MUTED)
                    .width(Length::Fixed(88.0)),
            ]
            .spacing(7)
            .align_y(Alignment::Center),
        )
        .padding([7, 9])
        .style(theme::scope_table_header);
        let mut list = column![header].spacing(0);
        for (index, block) in app.explorer.blocks.iter().enumerate() {
            list = list.push(block_row(app, block, index % 2 == 1));
        }
        list.into()
    };

    container(
        column![
            container(title).padding([7, 10]),
            rows,
            container(pagination(
                app.explorer_block_page,
                app.explorer.block_total_pages,
                Message::PreviousExplorerBlockPage,
                Message::NextExplorerBlockPage,
            ))
            .padding([8, 10]),
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface)
    .into()
}

fn block_row<'a>(
    app: &'a App,
    block: &'a ExplorerBlockSnapshot,
    alternate: bool,
) -> Element<'a, Message> {
    let available = if block.full_block_available {
        (
            format!("FULL · {} conf", block.confirmations),
            theme::ACCENT,
        )
    } else {
        (format!("HEADER · {} conf", block.confirmations), theme::DIM)
    };
    let mut open = button(text(if block.full_block_available {
        "DETAILS"
    } else {
        "HEADER"
    }))
    .width(Length::Fixed(88.0))
    .padding([6, 8])
    .style(|_, status| theme::button(ButtonKind::Ghost, status));
    if !app.block_details_loading {
        open = open.on_press(Message::OpenBlockDetails(block.header.height));
    }

    container(
        row![
            table_cell(block.header.height.to_string(), 2, theme::CYAN),
            table_cell(format_age(block.header.timestamp), 2, theme::MUTED),
            digest_cell(app, &block.header.hash, 6, theme::MUTED),
            table_cell(format!("m{}", block.header.log_slots), 2, theme::PROOF),
            table_cell(available.0, 3, available.1),
            open,
        ]
        .spacing(7)
        .align_y(Alignment::Center),
    )
    .padding([6, 9])
    .style(theme::table_row(alternate))
    .into()
}

fn compact_block<'a>(app: &'a App, block: &'a ExplorerBlockSnapshot) -> Element<'a, Message> {
    let available = if block.full_block_available {
        ("FULL BLOCK", theme::ACCENT)
    } else {
        ("HEADER", theme::DIM)
    };
    let mut open = button(text(if block.full_block_available {
        "DETAILS →"
    } else {
        "HEADER →"
    }))
    .padding([6, 8])
    .style(|_, status| theme::button(ButtonKind::Ghost, status));
    if !app.block_details_loading {
        open = open.on_press(Message::OpenBlockDetails(block.header.height));
    }
    container(
        column![
            row![
                text(format!("BLOCK #{}", block.header.height))
                    .size(13)
                    .color(theme::CYAN),
                text(format_age(block.header.timestamp))
                    .size(13)
                    .color(theme::MUTED),
                Space::new().width(Length::Fill),
                text(available.0).size(12).color(available.1),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            row![
                text(short_digest(&block.header.hash))
                    .size(13)
                    .color(theme::MUTED),
                copy_value_button(
                    &block.header.hash,
                    app.copied_value.as_deref() == Some(block.header.hash.as_str()),
                ),
                Space::new().width(Length::Fill),
                text(format!(
                    "m{} · {} conf",
                    block.header.log_slots, block.confirmations
                ))
                .size(12)
                .color(theme::DIM),
                open,
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        ]
        .spacing(6),
    )
    .width(Length::Fill)
    .padding([8, 10])
    .style(theme::surface_alt)
    .into()
}

fn recent_transactions_panel<'a>(
    app: &'a App,
    recent: &'a RecentTransactionsSnapshot,
    compact: bool,
    address_mode: bool,
) -> Element<'a, Message> {
    let title_label = if address_mode {
        "RECENT ADDRESS ACTIVITY"
    } else {
        "RECENT TRANSACTIONS"
    };
    let retained_label = format!(
        "FULL DATA #{}–#{}",
        recent.retained_from_height, recent.tip_height
    );
    let title: Element<'_, Message> = if compact {
        column![
            row![
                text(title_label).size(13).color(theme::PROOF),
                text(format!("[{}]", recent.total))
                    .size(13)
                    .color(theme::MUTED),
            ]
            .spacing(9),
            text(retained_label).size(12).color(theme::DIM),
        ]
        .spacing(3)
        .into()
    } else {
        row![
            text(title_label).size(13).color(theme::PROOF),
            text(format!("[{}]", recent.total))
                .size(13)
                .color(theme::MUTED),
            Space::new().width(Length::Fill),
            text(retained_label).size(12).color(theme::DIM),
        ]
        .spacing(9)
        .align_y(Alignment::Center)
        .into()
    };

    let rows: Element<'a, Message> = if recent.transactions.is_empty() {
        empty_state(if address_mode {
            "NO ACTIVITY FOR THIS ADDRESS IN THE RETAINED WINDOW"
        } else {
            "NO TRANSACTIONS IN THE RETAINED WINDOW"
        })
    } else if compact {
        let mut list = column![].spacing(5);
        for transaction in &recent.transactions {
            list = list.push(compact_transaction(app, transaction, address_mode));
        }
        list.into()
    } else {
        let header = container(
            row![
                table_cell("BLOCK", 2, theme::MUTED),
                table_cell("TYPE", 2, theme::MUTED),
                table_cell("TXID", 7, theme::MUTED),
                table_cell(if address_mode { "SPENT" } else { "IN" }, 2, theme::MUTED),
                table_cell(
                    if address_mode { "RECEIVED" } else { "OUT" },
                    2,
                    theme::MUTED,
                ),
                table_cell("FEE / NOID", 3, theme::MUTED),
                text("OPEN")
                    .size(13)
                    .color(theme::MUTED)
                    .width(Length::Fixed(78.0)),
            ]
            .spacing(7)
            .align_y(Alignment::Center),
        )
        .padding([7, 9])
        .style(theme::scope_table_header);
        let mut list = column![header].spacing(0);
        for (index, transaction) in recent.transactions.iter().enumerate() {
            list = list.push(transaction_row(
                app,
                transaction,
                index % 2 == 1,
                address_mode,
            ));
        }
        list.into()
    };

    container(
        column![
            container(title).padding([7, 10]),
            rows,
            container(
                column![
                    pagination(
                        recent.page,
                        recent.total_pages,
                        Message::PreviousExplorerTransactionPage,
                        Message::NextExplorerTransactionPage,
                    ),
                    text("After 18 blocks, a payment receipt carries the proof; the transaction body is not retained.")
                        .size(12)
                        .color(theme::DIM),
                ]
                .spacing(6),
            )
            .padding([8, 10]),
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface)
    .into()
}

fn transaction_row<'a>(
    app: &'a App,
    transaction: &'a RecentTransactionSnapshot,
    alternate: bool,
    address_mode: bool,
) -> Element<'a, Message> {
    let kind = if transaction.development_payout {
        ("DEVELOPMENT", theme::PROOF)
    } else if transaction.coinbase {
        ("COINBASE", theme::ACCENT)
    } else {
        ("TRANSFER", theme::TEXT)
    };
    let spent = if address_mode {
        transaction
            .address_spent_micronoid
            .as_deref()
            .map(format_micronoid_string)
            .unwrap_or_else(|| "0.000000".into())
    } else {
        transaction.live_inputs.to_string()
    };
    let received = if address_mode {
        transaction
            .address_received_micronoid
            .as_deref()
            .map(format_micronoid_string)
            .unwrap_or_else(|| "0.000000".into())
    } else {
        transaction.live_outputs.to_string()
    };
    let open = button(text("DETAILS").size(12))
        .width(Length::Fixed(78.0))
        .padding([6, 8])
        .on_press(Message::OpenLocatedTransaction(
            transaction.height,
            transaction.position,
        ))
        .style(|_, status| theme::button(ButtonKind::Ghost, status));

    container(
        row![
            table_cell(format!("#{}", transaction.height), 2, theme::CYAN),
            table_cell(kind.0, 2, kind.1),
            digest_cell(app, &transaction.txid, 7, theme::MUTED),
            table_cell(
                spent,
                2,
                if address_mode {
                    theme::WARNING
                } else {
                    theme::TEXT
                }
            ),
            table_cell(
                received,
                2,
                if address_mode {
                    theme::ACCENT
                } else {
                    theme::TEXT
                }
            ),
            table_cell(
                format_micronoid(transaction.fee_micronoid),
                3,
                theme::WARNING,
            ),
            open,
        ]
        .spacing(7)
        .align_y(Alignment::Center),
    )
    .padding([6, 9])
    .style(theme::table_row(alternate))
    .into()
}

fn compact_transaction<'a>(
    app: &'a App,
    transaction: &'a RecentTransactionSnapshot,
    address_mode: bool,
) -> Element<'a, Message> {
    let kind = if transaction.development_payout {
        ("DEVELOPMENT", theme::PROOF)
    } else if transaction.coinbase {
        ("COINBASE", theme::ACCENT)
    } else {
        ("TRANSFER", theme::TEXT)
    };
    let flow = if address_mode {
        format!(
            "−{} ①  +{} ①",
            transaction
                .address_spent_micronoid
                .as_deref()
                .map(format_micronoid_string)
                .unwrap_or_else(|| "0.000000".into()),
            transaction
                .address_received_micronoid
                .as_deref()
                .map(format_micronoid_string)
                .unwrap_or_else(|| "0.000000".into()),
        )
    } else {
        format!(
            "{} in · {} out · fee {} NOID",
            transaction.live_inputs,
            transaction.live_outputs,
            format_micronoid(transaction.fee_micronoid)
        )
    };
    container(
        column![
            row![
                text(format!("#{}", transaction.height))
                    .size(13)
                    .color(theme::CYAN),
                text(kind.0).size(12).color(kind.1),
                Space::new().width(Length::Fill),
                text(format_age(transaction.timestamp))
                    .size(12)
                    .color(theme::DIM),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
            row![
                text(short_digest(&transaction.txid))
                    .size(13)
                    .color(theme::MUTED),
                copy_value_button(
                    &transaction.txid,
                    app.copied_value.as_deref() == Some(transaction.txid.as_str()),
                ),
                Space::new().width(Length::Fill),
                button(text("DETAILS").size(12))
                    .on_press(Message::OpenLocatedTransaction(
                        transaction.height,
                        transaction.position,
                    ))
                    .padding([5, 8])
                    .style(|_, status| theme::button(ButtonKind::Ghost, status)),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
            text(flow).size(12).color(theme::DIM),
        ]
        .spacing(5),
    )
    .width(Length::Fill)
    .padding([8, 10])
    .style(theme::surface_alt)
    .into()
}

fn search_result<'a>(
    app: &'a App,
    result: &'a ExplorerSearchResultSnapshot,
    compact: bool,
) -> Element<'a, Message> {
    match result {
        ExplorerSearchResultSnapshot::Address(address) => address_result(app, address, compact),
        ExplorerSearchResultSnapshot::Slot(slot) => slot_result(app, slot, compact),
    }
}

fn address_result<'a>(
    app: &'a App,
    address: &'a ExplorerAddressSnapshot,
    compact: bool,
) -> Element<'a, Message> {
    let total_slot_pages = address.slots.len().div_ceil(EXPLORER_SLOT_PAGE_SIZE).max(1);
    let slot_page = app.explorer_slot_page.min(total_slot_pages);
    let start = (slot_page - 1) * EXPLORER_SLOT_PAGE_SIZE;
    let end = (start + EXPLORER_SLOT_PAGE_SIZE).min(address.slots.len());
    let visible_slots = address.slots.get(start..end).unwrap_or_default();

    let title = result_title("ADDRESS / LIVE STATE", "OWNER INDEX");
    let address_line = column![
        text("ADDRESS").size(12).color(theme::DIM),
        row![
            text_input("", &address.address)
                .on_input(|_| Message::Noop)
                .size(14)
                .padding([7, 9])
                .width(Length::Fill)
                .style(theme::text_input),
            copy_value_button(
                &address.address,
                app.copied_value.as_deref() == Some(address.address.as_str()),
            ),
        ]
        .spacing(7),
    ]
    .spacing(4);
    let balance = metric(
        "BALANCE",
        format!("{} ①", format_u128_micronoid(address.balance_micronoid)),
        theme::ACCENT,
    );
    let live_slots = metric(
        "LIVE SLOTS",
        grouped_usize(address.slots.len()),
        theme::CYAN,
    );
    let recent_tx = metric(
        "RECENT TX",
        address.recent_transactions.total.to_string(),
        theme::PROOF,
    );
    let metrics: Element<'_, Message> = if compact {
        column![balance, row![live_slots, recent_tx].spacing(7)]
            .spacing(7)
            .into()
    } else {
        row![balance, live_slots, recent_tx].spacing(7).into()
    };

    let slots = address_slots(app, visible_slots, slot_page, total_slot_pages, compact);
    column![
        container(
            column![
                title,
                address_line,
                text("Current live outputs come directly from the proved state—not from replayed history.")
                    .size(12)
                    .color(theme::DIM),
                metrics,
            ]
            .spacing(10),
        )
            .width(Length::Fill)
            .padding(12)
            .style(theme::surface),
        slots,
        recent_transactions_panel(app, &address.recent_transactions, compact, true),
    ]
    .spacing(10)
    .into()
}

fn address_slots<'a>(
    _app: &'a App,
    slots: &'a [ExplorerSlotSnapshot],
    page: usize,
    total_pages: usize,
    compact: bool,
) -> Element<'a, Message> {
    let title = row![
        text("LIVE OUTPUTS").size(13).color(theme::ACCENT),
        Space::new().width(Length::Fill),
        text("CURRENT STATE ONLY").size(12).color(theme::DIM),
    ]
    .align_y(Alignment::Center);
    let rows: Element<'_, Message> = if slots.is_empty() {
        empty_state("THIS ADDRESS HAS NO LIVE OUTPUTS")
    } else if compact {
        let mut list = column![].spacing(4);
        for slot in slots {
            list = list.push(
                container(
                    row![
                        column![
                            text(format!("SLOT {}", grouped(u64::from(slot.slot_index))))
                                .size(13)
                                .color(theme::CYAN),
                            text(format!(
                                "ORIGIN {}",
                                format_creation_origin(slot.creation_id)
                            ))
                            .size(12)
                            .color(theme::DIM),
                        ]
                        .spacing(3),
                        Space::new().width(Length::Fill),
                        text(format!(
                            "{} ①",
                            crate::model::format_micronoid(slot.value_micronoid)
                        ))
                        .size(13)
                        .color(theme::ACCENT),
                    ]
                    .align_y(Alignment::Center),
                )
                .padding([8, 10])
                .style(theme::surface_alt),
            );
        }
        list.into()
    } else {
        let header = container(
            row![
                table_cell("SLOT", 3, theme::MUTED),
                table_cell("VALUE / NOID", 4, theme::MUTED),
                table_cell("ORIGIN", 4, theme::MUTED),
                table_cell("STATE", 2, theme::MUTED),
            ]
            .spacing(8),
        )
        .padding([7, 9])
        .style(theme::scope_table_header);
        let mut list = column![header].spacing(0);
        for (index, slot) in slots.iter().enumerate() {
            list = list.push(
                container(
                    row![
                        table_cell(grouped(u64::from(slot.slot_index)), 3, theme::CYAN),
                        table_cell(
                            crate::model::format_micronoid(slot.value_micronoid),
                            4,
                            theme::ACCENT,
                        ),
                        table_cell(format_creation_origin(slot.creation_id), 4, theme::MUTED),
                        table_cell("LIVE", 2, theme::ACCENT),
                    ]
                    .spacing(8),
                )
                .padding([6, 9])
                .style(theme::table_row(index % 2 == 1)),
            );
        }
        list.into()
    };

    container(
        column![
            container(title).padding([7, 10]),
            rows,
            container(pagination_usize(
                page,
                total_pages,
                Message::PreviousExplorerSlotPage,
                Message::NextExplorerSlotPage,
            ))
            .padding([8, 10]),
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface)
    .into()
}

fn slot_result<'a>(
    app: &'a App,
    slot: &'a ExplorerSlotSnapshot,
    compact: bool,
) -> Element<'a, Message> {
    let state = if slot.empty {
        ("EMPTY", theme::DIM)
    } else {
        ("LIVE", theme::ACCENT)
    };
    let owner: Element<'_, Message> = if slot.empty {
        text("No owner in the current state.")
            .size(13)
            .color(theme::DIM)
            .into()
    } else {
        column![
            text("OWNER").size(12).color(theme::DIM),
            row![
                text_input("", &slot.owner)
                    .on_input(|_| Message::Noop)
                    .size(14)
                    .padding([7, 9])
                    .width(Length::Fill)
                    .style(theme::text_input),
                copy_value_button(
                    &slot.owner,
                    app.copied_value.as_deref() == Some(slot.owner.as_str()),
                ),
            ]
            .spacing(7),
        ]
        .spacing(4)
        .into()
    };

    let slot_metric = metric("SLOT", grouped(u64::from(slot.slot_index)), theme::CYAN);
    let value_metric = metric(
        "VALUE",
        format!("{} ①", crate::model::format_micronoid(slot.value_micronoid)),
        state.1,
    );
    let creation_metric = metric(
        "ORIGIN",
        format_creation_origin(slot.creation_id),
        theme::PROOF,
    );
    let metrics: Element<'_, Message> = if compact {
        column![slot_metric, row![value_metric, creation_metric].spacing(7)]
            .spacing(7)
            .into()
    } else {
        row![slot_metric, value_metric, creation_metric]
            .spacing(7)
            .into()
    };

    container(column![result_title("STATE SLOT", state.0), metrics, owner].spacing(12))
        .width(Length::Fill)
        .padding(12)
        .style(theme::surface)
        .into()
}

fn result_title(title: &'static str, status: &'static str) -> Element<'static, Message> {
    row![
        container(text(title).size(13))
            .padding([6, 9])
            .style(theme::title_bar_proof),
        Space::new().width(Length::Fill),
        text(status).size(12).color(theme::DIM),
        button(text("ESC CLEAR").size(13))
            .on_press(Message::ClearExplorerSearch)
            .padding([6, 9])
            .style(|_, button_status| theme::button(ButtonKind::Ghost, button_status)),
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into()
}

fn metric(label: &'static str, value: String, color: iced::Color) -> Element<'static, Message> {
    container(
        column![
            text(label).size(12).color(theme::DIM),
            text(value).size(15).color(color),
        ]
        .spacing(3),
    )
    .width(Length::FillPortion(1))
    .padding([8, 10])
    .style(theme::surface_alt)
    .into()
}

fn table_cell(
    value: impl Into<String>,
    portion: u16,
    color: iced::Color,
) -> Element<'static, Message> {
    text(value.into())
        .size(13)
        .color(color)
        .width(Length::FillPortion(portion))
        .into()
}

fn digest_cell<'a>(
    app: &'a App,
    digest: &'a str,
    portion: u16,
    color: iced::Color,
) -> Element<'a, Message> {
    row![
        text(short_digest(digest)).size(13).color(color),
        copy_value_button(digest, app.copied_value.as_deref() == Some(digest)),
        Space::new().width(Length::Fill),
    ]
    .spacing(3)
    .align_y(Alignment::Center)
    .width(Length::FillPortion(portion))
    .into()
}

fn pagination(
    page: u32,
    total_pages: u32,
    previous_message: Message,
    next_message: Message,
) -> Element<'static, Message> {
    let total_pages = total_pages.max(1);
    let page = page.max(1).min(total_pages);
    let mut previous = button(text("← PREV").size(13))
        .padding([7, 11])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if page > 1 {
        previous = previous.on_press(previous_message);
    }
    let mut next = button(text("NEXT →").size(13))
        .padding([7, 11])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if page < total_pages {
        next = next.on_press(next_message);
    }
    row![
        previous,
        text(format!("PAGE {page} / {total_pages}"))
            .size(13)
            .color(theme::MUTED),
        next,
    ]
    .spacing(10)
    .align_y(Alignment::Center)
    .into()
}

fn pagination_usize(
    page: usize,
    total_pages: usize,
    previous_message: Message,
    next_message: Message,
) -> Element<'static, Message> {
    pagination(
        u32::try_from(page).unwrap_or(u32::MAX),
        u32::try_from(total_pages).unwrap_or(u32::MAX),
        previous_message,
        next_message,
    )
}

fn legend(label: &'static str, color: iced::Color) -> Element<'static, Message> {
    row![
        container(Space::new())
            .width(7)
            .height(7)
            .style(theme::status_dot(color)),
        text(label).size(12).color(theme::DIM),
    ]
    .spacing(5)
    .align_y(Alignment::Center)
    .into()
}

fn empty_state(label: &'static str) -> Element<'static, Message> {
    container(text(label).size(13).color(theme::DIM))
        .width(Length::Fill)
        .height(Length::Fixed(72.0))
        .align_x(Alignment::Center)
        .align_y(Alignment::Center)
        .into()
}

fn short_digest(digest: &str) -> String {
    if digest.len() <= 20 {
        return digest.to_owned();
    }
    format!("{}…{}", &digest[..11], &digest[digest.len() - 7..])
}

fn format_age(timestamp: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(timestamp);
    let age = now.saturating_sub(timestamp);
    if age < 60 {
        format!("{age}s ago")
    } else if age < 3_600 {
        format!("{}m ago", age / 60)
    } else if age < 86_400 {
        format!("{}h ago", age / 3_600)
    } else {
        format!("{}d ago", age / 86_400)
    }
}

fn format_u128_micronoid(value: u128) -> String {
    let whole = value / 1_000_000;
    let fractional = value % 1_000_000;
    format!("{whole}.{fractional:06}")
}

fn format_micronoid_string(value: &str) -> String {
    value
        .parse::<u128>()
        .map(format_u128_micronoid)
        .unwrap_or_else(|_| value.to_owned())
}

fn grouped_usize(value: usize) -> String {
    u64::try_from(value)
        .map(grouped)
        .unwrap_or_else(|_| value.to_string())
}
