// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::{activity, operations, Page, State};

pub const DEFAULT_SLIPPAGE_BPS: u16 = 1_000;

impl State {
    pub fn submitted_trade(&self) -> Option<&operations::Submission> {
        (self.token_page == Page::Trade
            && self.operation.phase == operations::Phase::Submitted
            && matches!(
                self.operation.request,
                Some(operations::Request::Trade { .. })
            ))
        .then_some(self.operation.submission.as_ref())
        .flatten()
    }

    pub fn close_trade_status(&mut self) {
        if self.operation.submitting() {
            return;
        }
        self.operation.edit();
        self.amount.clear();
        self.limit.clear();
        self.trade_notice = None;
    }

    pub fn reconcile_trade(&mut self, records: &[activity::Pending]) -> bool {
        let Some(submission) = self.submitted_trade() else {
            return false;
        };
        let Some(preview) = &self.operation.preview else {
            return false;
        };
        let Some(key) = self.live.key.as_ref().filter(|key| {
            self.live.complete
                && self.live.error.is_none()
                && key.owner == preview.owner
                && key.key_index == preview.key_index
        }) else {
            return false;
        };
        let Some(record) = records.iter().find(|record| {
            record.txid == submission.txid
                && record.owner == preview.owner
                && record.key_index == preview.key_index
                && record.validate().is_ok()
                && record.preview.as_ref().is_some_and(|saved| {
                    saved.plan_id == preview.plan_id
                        && saved.txid == preview.txid
                        && saved.request == preview.request
                })
        }) else {
            return false;
        };
        let notice = match (record.status, record.confirmation_height) {
            (activity::Status::Confirmed, Some(height)) if key.height >= height => {
                format!("Trade confirmed in block {height}. Balances updated.")
            }
            (activity::Status::Unconfirmed, None)
                if preview
                    .valid_until
                    .is_some_and(|height| key.height > height) =>
            {
                "Order expired. Its record is available in Receipts.".into()
            }
            _ => return false,
        };
        self.close_trade_status();
        self.trade_notice = Some(notice);
        true
    }
}
