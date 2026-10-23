// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use std::time::{SystemTime, UNIX_EPOCH};

use iced::widget::{button, column, container, row, scrollable, text_editor, Space};
use iced::{Alignment, Element, Length, Padding};

use crate::app::{App, Message};
use crate::i18n::{text, text_input, translate};
use crate::model::{
    format_micronoid, grouped, ProofsTab, ReceiptFilter, ReceiptSnapshot, ReceiptSummarySnapshot,
    ReceiptTradeSnapshot, ReceiptVerificationSnapshot,
};
use crate::theme::{self, ButtonKind};

use super::copy_value_button;

pub(super) mod native;
mod query;

pub fn view(app: &App, compact: bool) -> Element<'_, Message> {
    let tabs = proof_tabs(app);
    let body = match app.proofs_tab {
        ProofsTab::Mine => my_proofs(app, compact),
        ProofsTab::Verify => verify_proof(app, compact),
    };
    let mut content = column![tabs].spacing(10);
    if app.proofs_tab == ProofsTab::Mine {
        let mut filters = row![].spacing(5);
        for filter in ReceiptFilter::ALL {
            let active = app.receipt_filter == filter;
            filters = filters.push(
                button(text(filter.to_string()).size(12))
                    .on_press(Message::SetReceiptFilter(filter))
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
                    }),
            );
        }
        content = content.push(query::header(app, filters));
        if app.receipt_query.open {
            content = content.push(query::view(app, compact));
        }
    }
    if let Some(error) = &app.receipt_error {
        content = content.push(error_panel(error));
    }
    if app.proofs_tab == ProofsTab::Mine {
        if let Some(error) = &app.native_pending_error {
            content = content.push(error_panel(error));
        }
        if let Some(pending) = recent_submissions(app) {
            content = content.push(pending);
        }
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

fn recent_submissions(app: &App) -> Option<Element<'_, Message>> {
    use crate::assets::activity::Status;
    let records: Vec<_> = app
        .native_pending
        .iter()
        .filter(|record| {
            record.includes(app.receipt_filter) && record.includes_query(&app.receipt_query.applied)
        })
        .collect();
    if records.is_empty() {
        return None;
    }
    let mut rows = column![].spacing(6);
    let pages = u32::try_from(records.len().div_ceil(5)).unwrap_or(u32::MAX);
    let page = app.native_pending_page.min(pages).max(1);
    for record in records.iter().skip((page as usize - 1) * 5).take(5) {
        let (status, color) = match record.status {
            Status::Pending => ("IN QUEUE".to_owned(), theme::WARNING),
            Status::Unconfirmed => ("UNCONFIRMED".to_owned(), theme::MUTED),
            Status::Confirmed => (
                format!(
                    "CONFIRMED / BLOCK {}",
                    grouped(record.confirmation_height.unwrap_or(0))
                ),
                theme::ACCENT,
            ),
        };
        let subject = record
            .preview
            .as_ref()
            .and_then(|p| p.asset_id.as_ref().or(p.collection_id.as_ref()))
            .map(|id| format!(" · {}", short_digest(id)))
            .unwrap_or_default();
        let age = record.submitted_unix.map(format_age).unwrap_or_default();
        let mut line = row![
            column![
                text(format!("{}{subject}", record.title())).size(13),
                text(format!(
                    "{} · ADDRESS {} · {age}",
                    short_digest(&record.txid),
                    record.key_index
                ))
                .size(12)
                .color(theme::DIM),
            ]
            .spacing(3)
            .width(Length::Fill),
            text(status).size(12).color(color),
            copy_value_button(
                &record.txid,
                app.copied_value.as_deref() == Some(&record.txid)
            ),
        ]
        .spacing(12)
        .align_y(Alignment::Center);
        if record.status == Status::Unconfirmed {
            let mut dismiss = button(text("DISMISS").size(12))
                .padding([6, 9])
                .style(|_, state| theme::button(ButtonKind::Ghost, state));
            if app.native_pending_dismissal.is_none() {
                dismiss = dismiss.on_press(Message::DismissNativePending(record.txid.clone()));
            }
            line = line.push(dismiss);
        }
        rows = rows.push(container(line).padding([8, 10]).style(theme::surface_alt));
    }
    let mut content = column![
        text(format!("RECENT SUBMISSIONS · {}", records.len()))
            .size(13)
            .color(theme::CYAN),
        scrollable(rows)
            .height(Length::Fixed((records.len() as f32 * 63.0).min(240.0)))
            .style(theme::scrollable),
    ]
    .spacing(8);
    if pages > 1 {
        content = content.push(pagination(
            page,
            pages,
            Message::PreviousNativePendingPage,
            Message::NextNativePendingPage,
        ));
    }
    if records
        .iter()
        .any(|record| record.status == Status::Unconfirmed)
    {
        content = content.push(text("Unconfirmed submissions are outside this node's queue and may still confirm. Dismiss removes the local entry.")
            .size(12).color(theme::DIM));
    }
    Some(
        container(content)
            .padding([10, 14])
            .width(Length::Fill)
            .style(theme::surface)
            .into(),
    )
}

fn proof_tabs(app: &App) -> Element<'_, Message> {
    row![
        tab_button(
            "MY RECEIPTS",
            ProofsTab::Mine,
            app.proofs_tab == ProofsTab::Mine,
        ),
        tab_button(
            "VERIFY",
            ProofsTab::Verify,
            app.proofs_tab == ProofsTab::Verify,
        ),
    ]
    .spacing(5)
    .align_y(Alignment::Center)
    .into()
}

fn tab_button(label: &'static str, tab: ProofsTab, active: bool) -> Element<'static, Message> {
    button(text(label).size(13))
        .on_press(Message::SetProofsTab(tab))
        .padding([8, 13])
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

fn my_proofs(app: &App, compact: bool) -> Element<'_, Message> {
    if app.receipts_loading && app.receipts.receipts.is_empty() {
        return loading_panel("READING RECEIPTS");
    }

    let filtered =
        app.receipt_filter != ReceiptFilter::All || !app.receipt_query.applied.is_default();
    let receipt_count = container(
        column![
            text(grouped_usize(app.receipts.total))
                .size(22)
                .color(theme::TEXT),
            text(if filtered {
                "MATCHING RECEIPTS"
            } else {
                "SAVED RECEIPTS"
            })
            .size(12)
            .color(theme::DIM),
        ]
        .spacing(2)
        .align_x(Alignment::End),
    )
    .width(Length::Fixed(88.0))
    .align_x(Alignment::End);
    let introduction = container(
        row![
            column![
                text("THE BLOCK BODY MAY EXPIRE. THE RECEIPT DOES NOT.")
                    .size(13)
                    .color(theme::PROOF),
                text("Saved locally at confirmation, a receipt authenticates the transaction and its inclusion in a canonical block. Key import on another device does not restore receipts.")
                    .size(13)
                    .color(theme::MUTED),
            ]
            .spacing(5)
            .width(Length::Fill),
            receipt_count,
        ]
        .spacing(16)
        .align_y(Alignment::Center),
    )
    .width(Length::Fill)
    .padding([10, 14])
    .style(theme::surface);

    if app.receipts.receipts.is_empty() {
        return column![
            introduction,
            container(
                column![
                    text(if filtered {
                        "NO MATCHING RECEIPTS"
                    } else {
                        "NO SAVED RECEIPTS YET"
                    })
                        .size(13)
                        .color(theme::MUTED),
                    text(if filtered {
                        "Change the filters to see other saved receipts."
                    } else {
                        "Payment receipts and native asset activity are saved automatically at confirmation."
                    })
                        .size(13)
                        .color(theme::DIM),
                ]
                .spacing(6)
                .align_x(Alignment::Center),
            )
            .width(Length::Fill)
            .height(Length::Fixed(180.0))
            .align_x(Alignment::Center)
            .align_y(Alignment::Center)
            .style(theme::surface),
        ]
        .spacing(10)
        .into();
    }

    let list = receipt_list(app);
    let detail = local_receipt_detail(app, compact);
    let workspace: Element<'_, Message> = if compact {
        column![list, detail].spacing(10).into()
    } else {
        row![
            container(list).width(Length::FillPortion(5)),
            container(detail).width(Length::FillPortion(7)),
        ]
        .spacing(10)
        .align_y(Alignment::Start)
        .into()
    };

    column![introduction, workspace].spacing(10).into()
}

fn receipt_list(app: &App) -> Element<'_, Message> {
    let mut refresh = button(text(if app.receipts_loading {
        "REFRESHING…"
    } else {
        "REFRESH"
    }))
    .padding([6, 9])
    .style(|_, status| theme::button(ButtonKind::Ghost, status));
    if !app.receipts_loading {
        refresh = refresh.on_press(Message::RefreshReceipts);
    }
    let title = row![
        text("SAVED ACTIVITY").size(13).color(theme::CYAN),
        Space::new().width(Length::Fill),
        refresh,
    ]
    .align_y(Alignment::Center);

    let mut rows = column![].spacing(0);
    for (index, receipt) in app.receipts.receipts.iter().enumerate() {
        rows = rows.push(receipt_row(
            receipt,
            index % 2 == 1,
            app.selected_receipt_txid.as_deref() == Some(receipt.txid.as_str()),
        ));
    }

    container(
        column![
            container(title).padding([6, 9]),
            rows,
            container(pagination(
                app.receipt_page,
                app.receipts.total_pages,
                Message::PreviousReceiptPage,
                Message::NextReceiptPage,
            ))
            .padding([8, 9]),
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface)
    .into()
}

fn receipt_row(
    receipt: &ReceiptSnapshot,
    alternate: bool,
    selected: bool,
) -> Element<'static, Message> {
    let peer = receipt
        .native
        .as_ref()
        .and_then(|value| value.subject())
        .map(|id| format!("ASSET {}", short_digest(id)))
        .unwrap_or_else(|| {
            receipt
                .peer_address
                .as_deref()
                .map(short_address)
                .map(|peer| format!("TO {peer}"))
                .unwrap_or_else(|| "MULTIPLE OUTPUTS".into())
        });
    let txid = receipt.txid.clone();
    let amount = if let Some(trade) = &receipt.trade {
        let asset = if trade.side == "buy" { "TOKEN" } else { "NOID" };
        let role = if receipt.own_address.as_deref() == Some(trade.owner.as_str()) {
            trade.side.to_uppercase()
        } else {
            "RECEIVED".into()
        };
        let value = trade
            .output_units
            .parse::<u64>()
            .map(format_micronoid)
            .unwrap_or_else(|_| "invalid amount".into());
        format!("{role} {value} {asset}")
    } else if let Some(native) = &receipt.native {
        native.label()
    } else {
        format!("{} ①", format_micronoid(receipt.amount_micronoid))
    };
    button(
        column![
            row![
                text(amount).size(13).color(theme::ACCENT),
                Space::new().width(Length::Fill),
                text(format!("BLOCK #{}", grouped(receipt.height)))
                    .size(12)
                    .color(theme::CYAN),
            ]
            .align_y(Alignment::Center),
            row![
                text(peer).size(12).color(theme::PROOF),
                Space::new().width(Length::Fill),
                text(format_age(receipt.timestamp))
                    .size(12)
                    .color(theme::DIM),
            ]
            .align_y(Alignment::Center),
            row![
                text(short_digest(&receipt.txid))
                    .size(12)
                    .color(theme::MUTED),
                Space::new().width(Length::Fill),
                text(format!(
                    "KEY #{} · I/O {}/{} · {}",
                    receipt
                        .own_key_index
                        .map_or_else(|| "?".into(), |index| index.to_string()),
                    receipt.input_count,
                    receipt.output_count,
                    format_bytes(receipt.receipt_bytes),
                ))
                .size(12)
                .color(theme::DIM),
            ]
            .align_y(Alignment::Center),
        ]
        .spacing(5),
    )
    .on_press(Message::SelectReceipt(txid))
    .width(Length::Fill)
    .padding([9, 10])
    .style(move |_, status| theme::utxo_row(alternate, selected, status))
    .into()
}

fn local_receipt_detail(app: &App, compact: bool) -> Element<'_, Message> {
    if app.receipt_detail_loading {
        return loading_panel("VERIFYING SELECTED RECEIPT");
    }
    let Some(detail) = &app.receipt_detail else {
        return container(text("SELECT A RECEIPT").size(13).color(theme::DIM))
            .width(Length::Fill)
            .height(Length::Fixed(180.0))
            .align_x(Alignment::Center)
            .align_y(Alignment::Center)
            .style(theme::surface)
            .into();
    };

    let copied = app.copied_value.as_deref() == Some(detail.receipt_hex.as_str());
    let copy = button(text(if copied { "COPIED" } else { "COPY RECEIPT" }).size(13))
        .on_press(Message::CopyValue(detail.receipt_hex.clone()))
        .padding([7, 11])
        .style(|_, status| theme::button(ButtonKind::Primary, status));
    let header = row![
        text("SELECTED RECEIPT").size(13).color(theme::PROOF),
        Space::new().width(Length::Fill),
        text(format!("{} BYTES", detail.receipt_hex.len() / 2))
            .size(12)
            .color(theme::DIM),
        copy,
    ]
    .spacing(8)
    .align_y(Alignment::Center);

    container(
        column![
            container(header).padding([7, 9]),
            verification_result(app, &detail.verification, compact),
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface)
    .into()
}

fn verify_proof(app: &App, compact: bool) -> Element<'_, Message> {
    let input = text_editor(&app.receipt_editor)
        .placeholder(translate("Paste receipt hex"))
        .on_action(Message::EditReceipt)
        .size(14)
        .padding([9, 11])
        .height(if compact { 92 } else { 108 })
        .wrapping(iced::widget::text::Wrapping::Glyph)
        .style(theme::text_editor);
    let paste = button(text("PASTE").size(13))
        .on_press(Message::PasteReceipt)
        .padding([10, 13])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    let mut verify = button(text(if app.receipt_verifying {
        "VERIFYING…"
    } else {
        "VERIFY"
    }))
    .padding([10, 14])
    .style(|_, status| theme::button(ButtonKind::Primary, status));
    if !app.receipt_verifying {
        verify = verify.on_press(Message::VerifyReceipt);
    }
    let clear = button(text("CLEAR").size(13))
        .on_press(Message::ClearReceiptVerifier)
        .padding([10, 12])
        .style(|_, status| theme::button(ButtonKind::Ghost, status));

    let controls: Element<'_, Message> = column![
        input,
        row![paste, verify, clear]
            .spacing(7)
            .align_y(Alignment::Center),
    ]
    .spacing(7)
    .into();
    let entry = container(
        column![
            row![
                text("VERIFY A RECEIPT").size(13).color(theme::PROOF),
                Space::new().width(Length::Fill),
                text("WHITESPACE IS IGNORED")
                    .size(12)
                    .color(theme::DIM),
            ]
            .align_y(Alignment::Center),
            controls,
            text("Verification checks the receipt against the network's canonical headers. The receipt stays local.")
                .size(12)
                .color(theme::MUTED),
        ]
        .spacing(8),
    )
    .width(Length::Fill)
    .padding(12)
    .style(theme::surface);

    let result: Element<'_, Message> = if app.receipt_verifying {
        loading_panel("CHECKING RECEIPT AND CANONICAL HEADER")
    } else if let Some(verification) = &app.receipt_verification {
        container(verification_result(app, verification, compact))
            .width(Length::Fill)
            .style(theme::surface)
            .into()
    } else {
        container(
            column![
                text("PASTE · VERIFY · KNOW")
                    .size(13)
                    .color(theme::CYAN),
                text("The result authenticates the transaction, outputs, fee, block position and canonical-chain membership.")
                    .size(13)
                    .color(theme::DIM),
            ]
            .spacing(6)
            .align_x(Alignment::Center),
        )
        .width(Length::Fill)
        .height(Length::Fixed(170.0))
        .align_x(Alignment::Center)
        .align_y(Alignment::Center)
        .style(theme::surface)
        .into()
    };

    column![entry, result].spacing(10).into()
}

fn verification_result<'a>(
    app: &'a App,
    verification: &'a ReceiptVerificationSnapshot,
    compact: bool,
) -> Element<'a, Message> {
    let (verdict, verdict_color) = if verification.confirmed {
        ("VALID · CANONICAL", theme::ACCENT)
    } else if verification.merkle_valid {
        ("RECEIPT VALID · NOT CANONICAL", theme::WARNING)
    } else {
        ("INVALID RECEIPT", theme::DANGER)
    };
    let status = container(
        row![
            container(Space::new())
                .width(8)
                .height(8)
                .style(theme::status_dot(verdict_color)),
            text(verdict).size(13).color(verdict_color),
            Space::new().width(Length::Fill),
            proof_check("MERKLE", verification.merkle_valid),
            proof_check("CANONICAL", verification.canonical),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    )
    .padding([10, 11])
    .style(theme::surface_alt);

    let mut content = column![status].spacing(9);
    if let Some(error) = &verification.error {
        content = content.push(text(error).size(13).color(theme::DANGER));
    }
    if let Some(summary) = &verification.authenticated_summary {
        content = content.push(authenticated_payment(app, summary, compact));
    } else {
        content = content.push(
            container(
                text("No payment fields are trusted because the Merkle proof did not verify.")
                    .size(13)
                    .color(theme::DIM),
            )
            .padding([12, 4]),
        );
    }
    container(content).width(Length::Fill).padding(10).into()
}

fn authenticated_payment<'a>(
    app: &'a App,
    summary: &'a ReceiptSummarySnapshot,
    compact: bool,
) -> Element<'a, Message> {
    let txid = copyable_line(app, "TRANSACTION", &summary.txid, theme::CYAN);
    let metrics: Element<'_, Message> = if compact {
        column![
            row![
                metric(
                    "BLOCK",
                    format!("#{}", grouped(summary.claimed_height)),
                    theme::CYAN
                ),
                metric(
                    "POSITION",
                    format!("{} / {}", summary.tx_index + 1, summary.tx_count),
                    theme::PROOF,
                ),
            ]
            .spacing(7),
            row![
                metric(
                    "FEE / NOID",
                    format_micronoid(summary.fee_micronoid),
                    theme::WARNING,
                ),
                metric(
                    "CONFIRMED",
                    format_age(summary.confirmed_unix),
                    theme::ACCENT,
                ),
            ]
            .spacing(7),
        ]
        .spacing(7)
        .into()
    } else {
        row![
            metric(
                "BLOCK",
                format!("#{}", grouped(summary.claimed_height)),
                theme::CYAN
            ),
            metric(
                "POSITION",
                format!("{} / {}", summary.tx_index + 1, summary.tx_count),
                theme::PROOF,
            ),
            metric(
                "FEE / NOID",
                format_micronoid(summary.fee_micronoid),
                theme::WARNING,
            ),
            metric(
                "CONFIRMED",
                format_age(summary.confirmed_unix),
                theme::ACCENT,
            ),
        ]
        .spacing(7)
        .into()
    };

    let title = if summary.native.is_some() {
        "AUTHENTICATED NATIVE ACTION"
    } else if summary.trade.is_some() {
        "AUTHENTICATED TRADE"
    } else {
        "AUTHENTICATED PAYMENT"
    };
    let mut content = column![
        row![
            text(title).size(13).color(theme::PROOF),
            Space::new().width(Length::Fill),
            text(format!("UNIX {}", summary.confirmed_unix))
                .size(12)
                .color(theme::DIM),
        ]
        .align_y(Alignment::Center),
        txid,
        metrics,
    ]
    .spacing(9);
    if let Some(trade) = &summary.trade {
        content = content.push(authenticated_trade(app, trade, compact));
    } else if let Some(native) = &summary.native {
        content = content.push(native::view(app, native));
    } else {
        content = content
            .push(receipt_inputs(app, summary))
            .push(receipt_outputs(app, summary));
    }
    content.into()
}

pub(super) fn authenticated_trade<'a>(
    app: &'a App,
    trade: &'a ReceiptTradeSnapshot,
    compact: bool,
) -> Element<'a, Message> {
    let buying = trade.side == "buy";
    let (input_asset, output_asset) = if buying {
        ("NOID", "TOKEN")
    } else {
        ("TOKEN", "NOID")
    };
    let units = |value: &str| {
        value
            .parse::<u64>()
            .map(format_micronoid)
            .unwrap_or_else(|_| "invalid amount".into())
    };
    let spent = metric(
        "TRADE INPUT",
        format!("{} {input_asset}", units(&trade.spent_input_units)),
        theme::CYAN,
    );
    let received = metric(
        "RECEIVED",
        format!("{} {output_asset}", units(&trade.output_units)),
        theme::ACCENT,
    );
    let amounts: Element<'_, Message> = if compact {
        column![spent, received].spacing(7).into()
    } else {
        row![spent, received].spacing(7).into()
    };
    let mut content = column![
        row![
            text(if buying { "BUY" } else { "SELL" })
                .size(13)
                .color(theme::ACCENT),
            Space::new().width(Length::Fill),
            text(format!("ORDER {}", trade.execution_index + 1))
                .size(12)
                .color(theme::DIM),
        ]
        .align_y(Alignment::Center),
        copyable_line(app, "ASSET", &trade.asset_id, theme::CYAN),
        amounts,
        text(format!(
            "MINIMUM {} {output_asset}  ·  POOL FEE {} {input_asset}",
            units(&trade.minimum_output_units),
            units(&trade.market_fee_units),
        ))
        .size(12)
        .color(theme::DIM),
        copyable_line(app, "OWNER", &trade.owner, theme::DIM),
        copyable_line(app, "RECIPIENT", &trade.recipient, theme::DIM),
        text("PAYOUTS AND CHANGE").size(12).color(theme::PROOF),
    ]
    .spacing(9);
    for payout in &trade.payouts {
        let asset = if payout.asset_id == "00".repeat(32) {
            "NOID"
        } else {
            "TOKEN"
        };
        content = content.push(
            container(
                column![
                    text(format!("{} {asset}", units(&payout.units)))
                        .size(14)
                        .color(theme::ACCENT),
                    copyable_line(app, "TO", &payout.owner, theme::DIM),
                ]
                .spacing(6),
            )
            .padding(10)
            .width(Length::Fill)
            .style(theme::surface_alt),
        );
    }
    content.into()
}

fn receipt_inputs<'a>(app: &'a App, summary: &'a ReceiptSummarySnapshot) -> Element<'a, Message> {
    let mut rows = column![].spacing(0);
    for (index, input) in summary.inputs.iter().enumerate() {
        rows = rows.push(
            container(
                row![
                    text(format!("SLOT {}", grouped(u64::from(input.slot_index))))
                        .size(12)
                        .color(theme::CYAN),
                    text(short_address(&input.owner))
                        .size(12)
                        .color(theme::MUTED),
                    copy_value_button(
                        &input.owner,
                        app.copied_value.as_deref() == Some(input.owner.as_str()),
                    ),
                    Space::new().width(Length::Fill),
                ]
                .spacing(5)
                .align_y(Alignment::Center),
            )
            .padding([6, 8])
            .style(theme::table_row(index % 2 == 1)),
        );
    }
    container(
        column![
            container(
                row![
                    text("INPUT OWNERSHIP").size(12).color(theme::CYAN),
                    text(format!("[{}]", summary.inputs.len()))
                        .size(12)
                        .color(theme::DIM),
                ]
                .spacing(6),
            )
            .padding([6, 8]),
            rows,
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface_alt)
    .into()
}

fn receipt_outputs<'a>(app: &'a App, summary: &'a ReceiptSummarySnapshot) -> Element<'a, Message> {
    let input_owner = summary.inputs.first().map(|input| input.owner.as_str());
    let mut rows = column![].spacing(0);
    for (index, output) in summary.outputs.iter().enumerate() {
        let change = input_owner == Some(output.owner.as_str());
        rows = rows.push(
            container(
                column![
                    row![
                        text(format!("SLOT {}", grouped(u64::from(output.slot_index))))
                            .size(12)
                            .color(theme::CYAN),
                        Space::new().width(Length::Fill),
                        text(format!(
                            "{} ①{}",
                            format_micronoid(output.amount_micronoid),
                            if change { " · CHANGE" } else { "" }
                        ))
                        .size(13)
                        .color(if change {
                            theme::MUTED
                        } else {
                            theme::ACCENT
                        }),
                    ]
                    .align_y(Alignment::Center),
                    row![
                        text(short_address(&output.owner))
                            .size(12)
                            .color(theme::PROOF),
                        copy_value_button(
                            &output.owner,
                            app.copied_value.as_deref() == Some(output.owner.as_str()),
                        ),
                        Space::new().width(Length::Fill),
                    ]
                    .spacing(5)
                    .align_y(Alignment::Center),
                ]
                .spacing(4),
            )
            .padding([7, 8])
            .style(theme::table_row(index % 2 == 1)),
        );
    }
    container(
        column![
            container(
                row![
                    text("AUTHENTICATED OUTPUTS").size(12).color(theme::CYAN),
                    text(format!("[{}]", summary.outputs.len()))
                        .size(12)
                        .color(theme::DIM),
                ]
                .spacing(6),
            )
            .padding([6, 8]),
            rows,
        ]
        .spacing(0),
    )
    .width(Length::Fill)
    .style(theme::surface_alt)
    .into()
}

fn copyable_line<'a>(
    app: &'a App,
    label: &'static str,
    value: &'a str,
    color: iced::Color,
) -> Element<'a, Message> {
    column![
        text(label).size(12).color(theme::DIM),
        row![
            text_input("", value)
                .on_input(|_| Message::Noop)
                .size(14)
                .padding([7, 9])
                .width(Length::Fill)
                .style(theme::text_input),
            copy_value_button(value, app.copied_value.as_deref() == Some(value)),
        ]
        .spacing(5)
        .align_y(Alignment::Center),
        container(Space::new()).height(1).style(move |_| {
            container::Style::default().background(iced::Background::Color(color))
        }),
    ]
    .spacing(3)
    .into()
}

fn proof_check(label: &'static str, valid: bool) -> Element<'static, Message> {
    text(format!("{label} [{}]", if valid { "OK" } else { "NO" }))
        .size(12)
        .color(if valid { theme::ACCENT } else { theme::DANGER })
        .into()
}

fn metric(label: &'static str, value: String, color: iced::Color) -> Element<'static, Message> {
    container(
        column![
            text(label).size(12).color(theme::DIM),
            text(value).size(13).color(color),
        ]
        .spacing(3),
    )
    .width(Length::FillPortion(1))
    .padding([7, 9])
    .style(theme::surface_alt)
    .into()
}

fn loading_panel(label: &'static str) -> Element<'static, Message> {
    container(text(label).size(13).color(theme::CYAN))
        .width(Length::Fill)
        .height(Length::Fixed(170.0))
        .align_x(Alignment::Center)
        .align_y(Alignment::Center)
        .style(theme::surface)
        .into()
}

fn error_panel(error: &str) -> Element<'_, Message> {
    container(
        row![
            text("RECEIPT ERROR").size(13).color(theme::DANGER),
            text(error).size(13).color(theme::MUTED),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
    )
    .width(Length::Fill)
    .padding([9, 11])
    .style(theme::surface)
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
    let mut previous = button(text("← PREV").size(12))
        .padding([6, 9])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if page > 1 {
        previous = previous.on_press(previous_message);
    }
    let mut next = button(text("NEXT →").size(12))
        .padding([6, 9])
        .style(|_, status| theme::button(ButtonKind::Secondary, status));
    if page < total_pages {
        next = next.on_press(next_message);
    }
    row![
        previous,
        text(format!("PAGE {page} / {total_pages}"))
            .size(12)
            .color(theme::MUTED),
        next,
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into()
}

fn short_digest(value: &str) -> String {
    if value.len() <= 20 {
        return value.into();
    }
    format!("{}…{}", &value[..11], &value[value.len() - 7..])
}

fn short_address(value: &str) -> String {
    if value.len() <= 24 {
        return value.into();
    }
    format!("{}…{}", &value[..13], &value[value.len() - 7..])
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

fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    }
}

fn grouped_usize(value: usize) -> String {
    u64::try_from(value)
        .map(grouped)
        .unwrap_or_else(|_| value.to_string())
}
