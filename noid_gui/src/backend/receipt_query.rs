// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use crate::model::receipt_query::Query;

#[derive(Deserialize)]
struct QueriedPage {
    page: u32,
    page_size: u32,
    query: Query,
    total: usize,
    total_pages: u32,
    receipts: Vec<RpcWalletReceipt>,
}

impl Backend {
    pub async fn queried_receipts_snapshot(
        &self,
        page: u32,
        query: Query,
    ) -> Result<ReceiptsSnapshot, String> {
        if query.is_default() {
            return self.receipts_snapshot(page, query.filter).await;
        }
        if self.is_mock() {
            return Err("Connect to a v2.1.0 node to filter the complete receipt history.".into());
        }
        let response = self
            .rpc_with_timeout::<QueriedPage>(
                "walletQueryReceipts",
                json!([page, RECEIPT_PAGE_SIZE, query]),
                Duration::from_secs(60),
            )
            .await
            .map_err(|error| {
                if error.ends_with("(-32601)") {
                    "Receipt filters require a v2.1.0 node.".to_owned()
                } else {
                    error
                }
            })?;
        let offset = usize::try_from(page.saturating_sub(1))
            .ok()
            .and_then(|page| page.checked_mul(RECEIPT_PAGE_SIZE as usize))
            .ok_or("Receipt page offset is too large.")?;
        let expected = response
            .total
            .saturating_sub(offset)
            .min(RECEIPT_PAGE_SIZE as usize);
        if response.page != page
            || response.page_size != RECEIPT_PAGE_SIZE
            || response.query != query
            || response.receipts.len() != expected
            || response.total_pages as usize != response.total.div_ceil(RECEIPT_PAGE_SIZE as usize)
        {
            return Err("Receipt results differ from the requested filters.".into());
        }
        Ok(ReceiptsSnapshot {
            page: response.page,
            filter: query.filter,
            total: response.total,
            total_pages: response.total_pages,
            receipts: response
                .receipts
                .into_iter()
                .map(RpcWalletReceipt::into_snapshot)
                .collect(),
        })
    }
}
