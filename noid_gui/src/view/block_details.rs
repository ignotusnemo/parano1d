// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::widget::{button, column, container, row, scrollable};
use iced::{Alignment, Element, Length, Padding};

use crate::app::{App, Message, BLOCK_DETAILS_SCROLL_ID, TRANSACTION_DETAILS_SCROLL_ID};
use crate::i18n::{text, text_input};
use crate::model::{format_creation_origin, BlockDetailsSnapshot, BlockTransactionSnapshot};
use crate::theme::{self, ButtonKind};

use super::copy_value_button;

pub(super) fn overlays(app: &App, compact: bool) -> Vec<Element<'_, Message>> {
    app.block_details
        .as_ref()
        .map(|details| {
            let transaction = app.block_transaction_position.and_then(|position| {
                details.retained.as_ref().and_then(|retained| {
                    retained
                        .transactions
                        .iter()
                        .find(|transaction| transaction.position == position)
                })
            });
            let mut layers = vec![block_details(app, details, compact)];
            if let Some(transaction) = transaction {
                layers.push(transaction_details(app, details, transaction, compact));
            }
            layers
        })
        .unwrap_or_default()
}

fn block_details<'a>(
    app: &'a App,
    details: &'a BlockDetailsSnapshot,
    compact: bool,
) -> Element<'a, Message> {
    let header = &details.header;
    let availability = if details.retained.is_some() {
        ("FULL BLOCK · RETAINED", theme::ACCENT)
    } else {
        ("HEADER · BODY NOT RETAINED", theme::DIM)
    };
    let title = row![
        text(format!("BLOCK #{}", header.height)).size(13),
        text(format!("[{}]", availability.0))
            .size(13)
            .color(availability.1),
        iced::widget::Space::new().width(Length::Fill),
        button(text("ESC CLOSE").size(13))
            .on_press(Message::CloseBlockDetails)
            .padding([6, 9])
            .style(|_, status| theme::button(ButtonKind::Ghost, status)),
    ]
    .spacing(10)
    .align_y(Alignment::Center);

    let header_grid: Element<'_, Message> = if compact {
        column![
            copyable_detail_line(app, "HASH", header.hash.clone(), theme::CYAN),
            copyable_detail_line(app, "PARENT", header.prev_hash.clone(), theme::MUTED),
            copyable_detail_line(app, "STATE ROOT", header.state_root.clone(), theme::ACCENT),
            copyable_detail_line(app, "TX ROOT", header.tx_root.clone(), theme::PROOF),
            copyable_detail_line(app, "MINER", header.miner.clone(), theme::TEXT),
            copyable_detail_line(app, "NONCE", header.nonce_hex.clone(), theme::WARNING),
        ]
        .spacing(5)
        .into()
    } else {
        row![
            column![
                copyable_detail_line(app, "HASH", header.hash.clone(), theme::CYAN),
                copyable_detail_line(app, "PARENT", header.prev_hash.clone(), theme::MUTED),
                copyable_detail_line(app, "MINER", header.miner.clone(), theme::TEXT),
            ]
            .spacing(5)
            .width(Length::Fill),
            column![
                copyable_detail_line(app, "STATE ROOT", header.state_root.clone(), theme::ACCENT),
                copyable_detail_line(app, "TX ROOT", header.tx_root.clone(), theme::PROOF),
                copyable_detail_line(app, "NONCE", header.nonce_hex.clone(), theme::WARNING),
            ]
            .spacing(5)
            .width(Length::Fill),
        ]
        .spacing(18)
        .into()
    };

    let consensus = row![
        metric("TIME", header.timestamp.to_string(), theme::TEXT),
        metric("STATE LVL", format!("m{}", header.log_slots), theme::CYAN),
        metric(
            "LIVE SLOTS",
            header.active_slot_count.to_string(),
            theme::ACCENT,
        ),
        metric("ALLOC", header.alloc_counter.to_string(), theme::PROOF),
    ]
    .spacing(8);

    let body: Element<'_, Message> = if let Some(retained) = &details.retained {
        let summary = row![
            metric("PROOF", retained.proof_class.clone(), theme::PROOF),
            metric(
                "TRANSACTIONS",
                retained.logical_transactions.to_string(),
                theme::CYAN,
            ),
            metric("USER PAGES", retained.user_pages.to_string(), theme::TEXT),
            metric("INPUTS", retained.live_inputs.to_string(), theme::TEXT),
            metric("OUTPUTS", retained.live_outputs.to_string(), theme::TEXT),
            metric(
                "REWARD",
                format!(
                    "{} ①",
                    crate::model::format_micronoid(retained.reward_micronoid)
                ),
                theme::ACCENT,
            ),
        ]
        .spacing(8);
        let sizes = row![
            detail("BLOCK", format_bytes(retained.block_bytes)),
            detail("HISTORYSTEP", format_bytes(retained.history_step_bytes)),
            detail("BUNDLE", format_bytes(retained.bundle_bytes)),
            detail("FEES", format!("{} μNOID", retained.total_fees_micronoid)),
        ]
        .spacing(18);
        let tx_header = container(
            row![
                table_cell("POS".into(), 2, theme::INK),
                table_cell("TYPE".into(), 3, theme::INK),
                table_cell("TXID".into(), 8, theme::INK),
                table_cell("PAGES".into(), 2, theme::INK),
                table_cell("IN".into(), 2, theme::INK),
                table_cell("OUT".into(), 2, theme::INK),
                table_cell("FEE / μNOID".into(), 4, theme::INK),
                text("OPEN")
                    .size(13)
                    .color(theme::INK)
                    .width(Length::Fixed(52.0)),
            ]
            .spacing(6),
        )
        .padding([6, 8])
        .style(theme::table_header);
        let mut tx_rows = column![].spacing(0);
        for (index, transaction) in retained.transactions.iter().enumerate() {
            tx_rows = tx_rows.push(
                button(
                    row![
                        table_cell(transaction.position.to_string(), 2, theme::CYAN),
                        table_cell(
                            transaction.label(),
                            3,
                            if transaction.development_payout {
                                theme::PROOF
                            } else if transaction.coinbase {
                                theme::ACCENT
                            } else {
                                theme::TEXT
                            },
                        ),
                        table_cell(short_digest(&transaction.txid), 8, theme::MUTED),
                        table_cell(transaction.page_count.to_string(), 2, theme::TEXT),
                        table_cell(transaction.live_inputs.to_string(), 2, theme::TEXT),
                        table_cell(transaction.live_outputs.to_string(), 2, theme::TEXT),
                        table_cell(transaction.fee_micronoid.to_string(), 4, theme::WARNING),
                        text("VIEW")
                            .size(12)
                            .color(theme::CYAN)
                            .width(Length::Fixed(52.0)),
                    ]
                    .spacing(6),
                )
                .width(Length::Fill)
                .padding([6, 8])
                .on_press(Message::OpenBlockTransaction(transaction.position))
                .style(move |_, status| theme::transaction_row(index % 2 == 1, status)),
            );
        }
        column![
            summary,
            sizes,
            text("LOGICAL TRANSACTIONS").size(13).color(theme::DIM),
            tx_header,
            scrollable(tx_rows)
                .height(Length::Fixed(210.0))
                .style(theme::scrollable),
        ]
        .spacing(9)
        .into()
    } else {
        container(
            column![
                text("HEADER ONLY").size(13).color(theme::DIM),
                text("The canonical header remains available. Full block data is retained for 18 blocks; payment receipts prove older transactions.")
                .size(13)
                .color(theme::MUTED),
                copyable_detail_line(
                    app,
                    "DIFFICULTY TARGET",
                    header.difficulty_target.clone(),
                    theme::WARNING,
                ),
            ]
            .spacing(8),
        )
        .width(Length::Fill)
        .padding(14)
        .style(theme::surface_alt)
        .into()
    };

    let card = container(
        column![
            container(title)
                .padding([7, 10])
                .style(theme::title_bar_proof),
            scrollable(
                column![header_grid, consensus, divider(), body]
                    .spacing(12)
                    .padding(Padding {
                        top: 14.0,
                        right: 28.0,
                        bottom: 14.0,
                        left: 14.0,
                    })
            )
            .id(BLOCK_DETAILS_SCROLL_ID)
            .style(theme::scrollable),
        ]
        .spacing(0),
    )
    .width(if compact {
        Length::Fill
    } else {
        Length::Fixed(1040.0)
    })
    .height(Length::Fill)
    .style(theme::surface_alt);

    container(card)
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(Alignment::Center)
        .align_y(Alignment::Center)
        .padding(Padding::from(if compact { [8, 12] } else { [20, 24] }))
        .style(theme::overlay)
        .into()
}

fn transaction_details<'a>(
    app: &'a App,
    details: &'a BlockDetailsSnapshot,
    transaction: &'a BlockTransactionSnapshot,
    compact: bool,
) -> Element<'a, Message> {
    let kind = transaction.label();
    let title = row![
        text(format!("{kind} TRANSACTION")).size(13),
        text(format!(
            "[BLOCK #{} · POSITION {}]",
            details.header.height, transaction.position
        ))
        .size(13)
        .color(theme::CYAN),
        iced::widget::Space::new().width(Length::Fill),
        button(text("← ESC BACK TO BLOCK").size(11))
            .on_press(Message::CloseBlockTransaction)
            .padding([6, 9])
            .style(|_, status| theme::button(ButtonKind::Ghost, status)),
    ]
    .spacing(10)
    .align_y(Alignment::Center);

    let txid = column![
        text("LOGICAL TRANSACTION ID").size(12).color(theme::DIM),
        row![
            text_input("", &transaction.txid)
                .on_input(|_| Message::Noop)
                .size(14)
                .padding([7, 9])
                .width(Length::Fill)
                .style(theme::text_input),
            copy_value_button(
                &transaction.txid,
                app.copied_value.as_deref() == Some(transaction.txid.as_str()),
            ),
        ]
        .spacing(8),
    ]
    .spacing(4);

    let binding: Element<'_, Message> = if compact {
        column![
            copyable_detail_line(app, "BLOCK HASH", details.header.hash.clone(), theme::CYAN),
            copyable_detail_line(
                app,
                "EPOCH ANCHOR",
                transaction.epoch_anchor.clone(),
                theme::PROOF,
            ),
        ]
        .spacing(6)
        .into()
    } else {
        row![
            copyable_detail_line(app, "BLOCK HASH", details.header.hash.clone(), theme::CYAN),
            copyable_detail_line(
                app,
                "EPOCH ANCHOR",
                transaction.epoch_anchor.clone(),
                theme::PROOF,
            ),
        ]
        .spacing(18)
        .into()
    };

    let metrics = row![
        metric(
            "TYPE",
            kind.into(),
            if transaction.development_payout {
                theme::PROOF
            } else if transaction.coinbase {
                theme::ACCENT
            } else {
                theme::TEXT
            }
        ),
        metric("PAGES", transaction.page_count.to_string(), theme::PROOF),
        metric("INPUTS", transaction.live_inputs.to_string(), theme::CYAN),
        metric("OUTPUTS", transaction.live_outputs.to_string(), theme::CYAN),
        metric(
            "FEE",
            format!(
                "{} ①",
                crate::model::format_micronoid(transaction.fee_micronoid)
            ),
            if transaction.fee_micronoid == 0 {
                theme::DIM
            } else {
                theme::WARNING
            },
        ),
    ]
    .spacing(8);

    let flow = if transaction.development_payout {
        column![
            text("REWARD SHARE").size(12).color(theme::DIM),
            text("Block-reward shares paid to O(1) Network Fund and ParanO(1)d Lab. This protocol payout has no spend inputs.")
                .size(13)
                .color(theme::PROOF),
        ]
        .spacing(4)
    } else if transaction.coinbase {
        column![
            text("BLOCK REWARD").size(12).color(theme::DIM),
            text(format!(
                "{} ① paid to the block miner. Coinbase has no spend inputs.",
                format_micronoid_string(&transaction.output_sum_micronoid)
            ))
            .size(13)
            .color(theme::ACCENT),
        ]
        .spacing(4)
    } else {
        column![
            copyable_detail_line(
                app,
                if transaction.native.is_some() {
                    "AUTHORITY"
                } else {
                    "INPUT OWNER"
                },
                transaction.input_owner.clone().unwrap_or_default(),
                theme::PROOF,
            ),
            row![
                detail(
                    "INPUT TOTAL",
                    format!(
                        "{} ①",
                        format_micronoid_string(&transaction.input_sum_micronoid)
                    ),
                ),
                detail(
                    "OUTPUT TOTAL",
                    format!(
                        "{} ①",
                        format_micronoid_string(&transaction.output_sum_micronoid)
                    ),
                ),
                detail(
                    "FEE",
                    format!(
                        "{} ①",
                        crate::model::format_micronoid(transaction.fee_micronoid)
                    ),
                ),
            ]
            .spacing(18),
        ]
        .spacing(7)
    };

    let io: Element<'_, Message> = if compact {
        column![
            transaction_inputs(transaction),
            transaction_outputs(app, transaction),
        ]
        .spacing(10)
        .into()
    } else {
        row![
            transaction_inputs(transaction).width(Length::Fill),
            transaction_outputs(app, transaction).width(Length::Fill),
        ]
        .spacing(10)
        .into()
    };

    let mut effects = column![].spacing(10);
    if transaction.trades.is_empty() {
        if let Some(native) = &transaction.native {
            effects = effects.push(super::proofs::native::view(app, native));
        }
    }
    for trade in &transaction.trades {
        effects = effects
            .push(copyable_detail_line(
                app,
                "AUTHORIZATION ID",
                trade.authorization_id.clone(),
                theme::CYAN,
            ))
            .push(
                text(format!(
                    "NETWORK FEE {} NOID",
                    crate::model::format_micronoid(trade.network_fee_micronoid)
                ))
                .size(12)
                .color(theme::DIM),
            )
            .push(super::proofs::authenticated_trade(
                app,
                &trade.trade,
                compact,
            ));
    }
    let hashes = transaction_page_hashes(app, transaction);
    let card = container(
        column![
            container(title)
                .padding([7, 10])
                .style(theme::title_bar_proof),
            scrollable(
                column![txid, binding, metrics, flow, effects, divider(), io, hashes]
                    .spacing(12)
                    .padding(Padding {
                        top: 14.0,
                        right: 28.0,
                        bottom: 14.0,
                        left: 14.0,
                    }),
            )
            .id(TRANSACTION_DETAILS_SCROLL_ID)
            .style(theme::scrollable),
        ]
        .spacing(0),
    )
    .width(if compact {
        Length::Fill
    } else {
        Length::Fixed(1040.0)
    })
    .height(Length::Fill)
    .style(theme::surface_alt);

    container(card)
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(Alignment::Center)
        .align_y(Alignment::Center)
        .padding(Padding::from(if compact { [8, 12] } else { [20, 24] }))
        .style(theme::overlay)
        .into()
}

fn transaction_inputs(
    transaction: &BlockTransactionSnapshot,
) -> iced::widget::Container<'_, Message> {
    if transaction.inputs.is_empty() {
        return container(
            column![
                container(
                    row![
                        text("INPUT UTXOS").size(13).color(theme::CYAN),
                        text("[0]").size(12).color(theme::MUTED),
                    ]
                    .spacing(7),
                )
                .padding([7, 9]),
                container(
                    text("NO INPUTS · BLOCK REWARD PAYOUT")
                        .size(13)
                        .color(theme::DIM)
                )
                .width(Length::Fill)
                .align_x(Alignment::Center)
                .padding([9, 8]),
            ]
            .spacing(0),
        )
        .style(theme::surface);
    }

    let header = container(
        row![
            table_cell("REF".into(), 2, theme::INK),
            table_cell("SLOT".into(), 3, theme::INK),
            table_cell("ORIGIN".into(), 4, theme::INK),
            table_cell("AMOUNT / NOID".into(), 5, theme::INK),
        ]
        .spacing(6),
    )
    .padding([6, 8])
    .style(theme::table_header);
    let mut rows = column![].spacing(0);
    for (index, input) in transaction.inputs.iter().enumerate() {
        rows = rows.push(
            container(
                row![
                    table_cell(
                        format!(
                            "P{}:I{}{}",
                            input.page,
                            input.lane,
                            if input.native { "*" } else { "" }
                        ),
                        2,
                        theme::CYAN
                    ),
                    table_cell(input.slot_index.to_string(), 3, theme::TEXT),
                    table_cell(format_creation_origin(input.creation_id), 4, theme::MUTED),
                    table_cell(
                        crate::model::format_micronoid(input.amount_micronoid),
                        5,
                        theme::TEXT,
                    ),
                ]
                .spacing(6),
            )
            .padding([6, 8])
            .style(theme::table_row(index % 2 == 1)),
        );
    }
    container(
        column![
            container(
                row![
                    text("INPUT UTXOS").size(13).color(theme::CYAN),
                    text(format!("[{}]", transaction.inputs.len()))
                        .size(12)
                        .color(theme::MUTED),
                ]
                .spacing(7),
            )
            .padding([7, 9]),
            header,
            rows,
        ]
        .spacing(0),
    )
    .style(theme::surface)
}

fn transaction_outputs<'a>(
    app: &'a App,
    transaction: &'a BlockTransactionSnapshot,
) -> iced::widget::Container<'a, Message> {
    let mut rows = column![].spacing(0);
    for (index, output) in transaction.outputs.iter().enumerate() {
        let change = transaction
            .input_owner
            .as_ref()
            .is_some_and(|owner| owner == &output.owner);
        rows = rows.push(
            container(
                column![
                    row![
                        detail("REF", format!("P{}:O{}", output.page, output.lane)),
                        detail("SLOT", output.slot_index.to_string()),
                        iced::widget::Space::new().width(Length::Fill),
                        text(format!(
                            "{} NOID{}",
                            crate::model::format_micronoid(output.amount_micronoid),
                            if output.native {
                                " · NATIVE RECORD"
                            } else if change {
                                " · CHANGE"
                            } else {
                                ""
                            }
                        ))
                        .size(13)
                        .color(if change {
                            theme::MUTED
                        } else {
                            theme::ACCENT
                        }),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                    detail("ORIGIN", format_creation_origin(output.creation_id)),
                    copyable_detail_line(
                        app,
                        if output.native {
                            "CONTENT ROOT"
                        } else {
                            "OWNER"
                        },
                        output.owner.clone(),
                        theme::PROOF
                    ),
                ]
                .spacing(5),
            )
            .padding([7, 9])
            .style(theme::table_row(index % 2 == 1)),
        );
    }
    container(
        column![
            container(
                row![
                    text("OUTPUT UTXOS").size(13).color(theme::CYAN),
                    text(format!("[{}]", transaction.outputs.len()))
                        .size(12)
                        .color(theme::MUTED),
                ]
                .spacing(7),
            )
            .padding([7, 9]),
            rows,
        ]
        .spacing(0),
    )
    .style(theme::surface)
}

fn transaction_page_hashes<'a>(
    app: &'a App,
    transaction: &'a BlockTransactionSnapshot,
) -> iced::widget::Container<'a, Message> {
    let header = container(
        row![
            text("PAGE")
                .size(13)
                .color(theme::INK)
                .width(Length::FillPortion(2)),
            text("TX8x2 BODY HASH")
                .size(13)
                .color(theme::INK)
                .width(Length::FillPortion(12)),
        ]
        .spacing(8),
    )
    .padding([6, 8])
    .style(theme::table_header);
    let mut rows = column![].spacing(0);
    for (index, hash) in transaction.page_hashes.iter().enumerate() {
        rows = rows.push(
            container(
                row![
                    text(index.to_string())
                        .size(13)
                        .color(theme::CYAN)
                        .width(Length::FillPortion(2)),
                    row![
                        text(hash)
                            .size(10)
                            .font(theme::TECH_FONT)
                            .color(theme::MUTED)
                            .wrapping(iced::widget::text::Wrapping::None)
                            .width(Length::Fill),
                        copy_value_button(
                            hash,
                            app.copied_value.as_deref() == Some(hash.as_str()),
                        ),
                    ]
                    .spacing(5)
                    .align_y(Alignment::Center)
                    .width(Length::FillPortion(12)),
                ]
                .spacing(8),
            )
            .padding([6, 8])
            .style(theme::table_row(index % 2 == 1)),
        );
    }
    container(
        column![
            container(
                row![
                    text("PHYSICAL TX8x2 PAGES").size(13).color(theme::CYAN),
                    text(format!("[{}]", transaction.page_hashes.len()))
                        .size(12)
                        .color(theme::MUTED),
                ]
                .spacing(7),
            )
            .padding([7, 9]),
            header,
            rows,
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface)
}

fn format_micronoid_string(value: &str) -> String {
    let Ok(value) = value.parse::<u128>() else {
        return value.to_owned();
    };
    let whole = value / 1_000_000;
    let fractional = value % 1_000_000;
    format!("{whole}.{fractional:06}")
}

fn table_cell(value: String, portion: u16, color: iced::Color) -> Element<'static, Message> {
    text(value)
        .size(13)
        .color(color)
        .wrapping(iced::widget::text::Wrapping::None)
        .width(Length::FillPortion(portion))
        .into()
}

fn metric(
    label: &'static str,
    value: String,
    color: iced::Color,
) -> iced::widget::Container<'static, Message> {
    container(
        column![
            text(label).size(12).color(theme::DIM),
            text(value).size(13).color(color),
        ]
        .spacing(3),
    )
    .width(Length::FillPortion(1))
    .padding([8, 10])
    .style(theme::surface_alt)
}

fn copyable_detail_line(
    app: &App,
    label: &'static str,
    value: String,
    color: iced::Color,
) -> Element<'static, Message> {
    let copied = app.copied_value.as_deref() == Some(value.as_str());
    column![
        text(label).size(12).color(theme::DIM),
        row![
            text(value.clone())
                .size(10)
                .font(theme::TECH_FONT)
                .color(color)
                .wrapping(iced::widget::text::Wrapping::None)
                .width(Length::Fill),
            copy_value_button(&value, copied),
        ]
        .spacing(5)
        .align_y(Alignment::Center),
    ]
    .width(Length::Fill)
    .spacing(2)
    .into()
}

fn detail(label: &'static str, value: String) -> Element<'static, Message> {
    row![
        text(label).size(12).color(theme::DIM),
        text(format!("[{value}]")).size(13).color(theme::CYAN),
    ]
    .spacing(6)
    .align_y(Alignment::Center)
    .into()
}

fn divider() -> Element<'static, Message> {
    container(iced::widget::Space::new())
        .width(Length::Fill)
        .height(1)
        .style(theme::divider)
        .into()
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn short_digest(digest: &str) -> String {
    if digest.len() <= 24 {
        digest.to_string()
    } else {
        format!("{}…{}", &digest[..13], &digest[digest.len() - 9..])
    }
}
