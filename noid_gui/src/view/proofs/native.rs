// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use iced::{
    widget::{column, container},
    Element, Length,
};

use crate::{
    app::{App, Message},
    i18n::text,
    model::{format_micronoid, format_native_units, ReceiptNativeSnapshot},
    theme,
};

use super::copyable_line;

pub(in crate::view) fn view<'a>(
    app: &'a App,
    receipt: &'a ReceiptNativeSnapshot,
) -> Element<'a, Message> {
    let mut content = column![
        text(receipt.label()).size(15).color(theme::ACCENT),
        copyable_line(app, "AUTHORIZED BY", &receipt.authority, theme::DIM),
    ]
    .spacing(9);
    if receipt.operation == "burn_token" {
        if let Some((before, after)) = receipt
            .reserves
            .iter()
            .filter(|value| !value.after)
            .find_map(|before| {
                receipt
                    .reserves
                    .iter()
                    .find(|after| after.after && after.asset_id == before.asset_id)
                    .map(|after| (before, after))
            })
        {
            if let Some(amount) = before
                .amount_micronoid
                .parse::<u128>()
                .ok()
                .zip(after.amount_micronoid.parse::<u128>().ok())
                .and_then(|(before, after)| before.checked_sub(after))
            {
                content = content.push(
                    text(format!(
                        "REDEEMED {} NOID",
                        format_native_units(&amount.to_string())
                    ))
                    .size(14)
                    .color(theme::CYAN),
                );
            }
        }
    }
    for created in &receipt.created {
        let supply = if created.kind == "token" {
            format!(
                "FIXED SUPPLY {} TOKEN",
                format_native_units(&created.supply_or_maximum)
            )
        } else {
            format!("MAXIMUM {} ITEMS", created.supply_or_maximum)
        };
        content = content
            .push(copyable_line(app, "CREATED", &created.id, theme::CYAN))
            .push(text(supply).size(13).color(theme::ACCENT))
            .push(copyable_line(
                app,
                "METADATA",
                &created.metadata_hash,
                theme::DIM,
            ));
    }
    for (after, token) in receipt
        .token_inputs
        .iter()
        .map(|item| (false, item))
        .chain(receipt.token_outputs.iter().map(|item| (true, item)))
    {
        let mut details = column![
            text(format!(
                "{} {} TOKEN",
                if after { "OUTPUT" } else { "INPUT" },
                format_native_units(&token.units)
            ))
            .size(14)
            .color(theme::ACCENT),
            copyable_line(app, "ASSET", &token.asset_id, theme::CYAN),
            copyable_line(app, "OWNER", &token.owner, theme::DIM),
        ]
        .spacing(6);
        if token.unlock_height != 0 {
            details = details.push(
                text(format!("UNLOCK BLOCK #{}", token.unlock_height))
                    .size(12)
                    .color(theme::WARNING),
            );
        }
        content = content.push(
            container(details)
                .padding(10)
                .width(Length::Fill)
                .style(theme::surface_alt),
        );
    }
    for (after, item) in receipt
        .nft_inputs
        .iter()
        .map(|item| (false, item))
        .chain(receipt.nft_outputs.iter().map(|item| (true, item)))
    {
        let mut details = column![
            text(format!(
                "{} NFT #{}{}",
                if after { "OUTPUT" } else { "INPUT" },
                item.serial,
                if item.listed { " · LISTED" } else { "" }
            ))
            .size(14)
            .color(theme::ACCENT),
            copyable_line(app, "COLLECTION", &item.collection_id, theme::CYAN),
            copyable_line(app, "OWNER", &item.owner, theme::DIM),
            copyable_line(app, "METADATA", &item.metadata_hash, theme::DIM),
        ]
        .spacing(6);
        if let (Some(ask), Some(expiry)) = (item.ask_micronoid, item.expiry_height) {
            details = details.push(
                text(format!(
                    "ASK {} NOID · EXPIRES AT BLOCK #{expiry}",
                    format_micronoid(ask)
                ))
                .size(12)
                .color(theme::WARNING),
            );
        }
        if item.unlock_height != 0 {
            details = details.push(
                text(format!("UNLOCK BLOCK #{}", item.unlock_height))
                    .size(12)
                    .color(theme::WARNING),
            );
        }
        content = content.push(
            container(details)
                .padding(10)
                .width(Length::Fill)
                .style(theme::surface_alt),
        );
    }
    for reserve in &receipt.reserves {
        content = content.push(
            column![
                text(format!(
                    "RESERVE {} · {} NOID · {} TOKEN OUTSTANDING",
                    if reserve.after { "AFTER" } else { "BEFORE" },
                    format_native_units(&reserve.amount_micronoid),
                    format_native_units(&reserve.outstanding_units)
                ))
                .size(12)
                .color(theme::CYAN),
                copyable_line(app, "ASSET", &reserve.asset_id, theme::DIM),
            ]
            .spacing(6),
        );
    }
    for (after, value) in receipt
        .noid_inputs
        .iter()
        .map(|value| (false, value))
        .chain(receipt.noid_outputs.iter().map(|value| (true, value)))
    {
        content = content.push(
            column![
                text(format!(
                    "NOID {} {}",
                    if after { "OUTPUT" } else { "INPUT" },
                    format_native_units(&value.amount_micronoid)
                ))
                .size(12)
                .color(theme::MUTED),
                copyable_line(
                    app,
                    if after { "TO" } else { "FROM" },
                    &value.owner,
                    theme::DIM
                ),
            ]
            .spacing(5),
        );
    }
    content.into()
}
