// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Mempool configuration.

use noid_chain::consensus::wire_limits::{MAX_MEMPOOL_BYTES, MAX_MEMPOOL_TXS};
use noid_chain::mempool::{BlockSelectionBudget, NativeResourceUsage};

use crate::SubmitError;

#[cfg(test)]
pub(crate) fn test_config() -> MempoolConfig {
    MempoolConfig::default().with_v2_block_budgets([63, 206].map(|pages| BlockSelectionBudget {
        pages,
        live_inputs: 504,
        contract_calls: 63,
        native_headers: 0,
        native_records: 0,
        owner_authorizations: pages,
        financial: None,
    }))
}

/// Configuration for the async mempool.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of admitted transactions.
    pub capacity: usize,

    /// Maximum serialized PagedSpendIntent bytes retained in RAM.
    pub max_total_intent_bytes: usize,

    /// Number of recent admitted-tx fees used to compute the dynamic fee floor.
    /// Floor = max(MIN_FEE_BASE, median(last N fees) × 0.9).
    /// From v1.1 it is applied only while the 80%/50% pressure latch is active.
    pub fee_floor_window: usize,

    /// Number of concurrent authorization verification workers (`spawn_blocking` slots).
    /// 0 = no concurrency limit; authorization verification is still required.
    /// Recommended: number of physical cores.
    pub auth_verify_workers: usize,

    /// Full class budgets supplied by the authenticated v2 bank, before the
    /// candidate height's additional system-page reservation. Missing budgets
    /// keep legacy admission available but cannot authorize v2 admission.
    pub v2_block_budgets: Option<[BlockSelectionBudget; 2]>,
    pub v21_native_budget: Option<BlockSelectionBudget>,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            capacity: MAX_MEMPOOL_TXS,
            max_total_intent_bytes: MAX_MEMPOOL_BYTES,
            fee_floor_window: 50,
            auth_verify_workers: 4,
            v2_block_budgets: None,
            v21_native_budget: None,
        }
    }
}

impl MempoolConfig {
    pub fn with_v2_block_budgets(mut self, budgets: [BlockSelectionBudget; 2]) -> Self {
        self.v2_block_budgets = Some(budgets);
        self
    }

    pub fn with_v21_native_budget(mut self, budget: BlockSelectionBudget) -> Self {
        self.v21_native_budget = Some(budget);
        self
    }

    /// A whole intent must fit one pinned class. Taking page and input maxima
    /// independently could admit a spend that fits neither class.
    pub(crate) fn check_resources(
        &self,
        height: u64,
        pages: usize,
        inputs: usize,
        calls: usize,
    ) -> Result<(), SubmitError> {
        self.check_native_resources(
            height,
            pages,
            inputs,
            calls,
            NativeResourceUsage::ordinary(),
        )
    }

    pub(crate) fn check_native_resources(
        &self,
        height: u64,
        pages: usize,
        inputs: usize,
        calls: usize,
        native: NativeResourceUsage,
    ) -> Result<(), SubmitError> {
        if !noid_chain::consensus::params::v2_active(height) {
            return Ok(());
        }
        let budgets = self
            .v2_block_budgets
            .ok_or(SubmitError::V2LimitsUnavailable)?;
        let reserved = usize::from(
            noid_chain::consensus::development_allocation::development_payout_due_at_height(height),
        );
        let max_inputs = budgets
            .into_iter()
            .chain(
                self.v21_native_budget
                    .filter(|_| noid_chain::consensus::params::v2_1_active(height)),
            )
            .filter(|budget| {
                pages <= budget.pages.saturating_sub(reserved)
                    && calls <= budget.contract_calls
                    && budget.fits_native(native)
            })
            .map(|budget| budget.live_inputs)
            .max()
            .ok_or(SubmitError::NoProofClass {
                pages,
                inputs,
                calls,
            })?;
        let max_inputs = max_inputs.min(noid_tx::MAX_PAGED_SPEND_INPUTS);
        if inputs > max_inputs {
            return Err(SubmitError::InputLimitExceeded {
                actual: inputs,
                max_inputs,
            });
        }
        Ok(())
    }

    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    pub fn with_max_total_intent_bytes(mut self, bytes: usize) -> Self {
        self.max_total_intent_bytes = bytes;
        self
    }

    pub fn with_auth_verify_workers(mut self, n: usize) -> Self {
        self.auth_verify_workers = n;
        self
    }
}
