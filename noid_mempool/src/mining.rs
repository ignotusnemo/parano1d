// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Parent-bound policy snapshots and complete template selections.

use super::*;
use noid_chain::mempool::{BlockSelectionBudget, BlockSelectionReservation};
use noid_tx::native_assets::trade::TradeIntent;

pub struct TradeMiningSnapshot {
    pub intents: Vec<Arc<TradeIntent>>,
    pub pending_outputs: HashSet<u32>,
}

pub struct V2MiningReservation {
    pub remaining: BlockSelectionBudget,
    pub occupied: BlockSelectionReservation,
    pub claimable_fees: u128,
    pub trade_ids: Vec<TxBodyHash>,
}

impl V2MiningReservation {
    pub fn empty(budget: BlockSelectionBudget) -> Self {
        Self {
            remaining: budget,
            occupied: BlockSelectionReservation::default(),
            claimable_fees: 0,
            trade_ids: Vec::new(),
        }
    }
}

pub struct PrefilledV2MempoolSelection {
    pub selection: V2MempoolSelection,
    pub trade_authorizations: Vec<(TxBodyHash, Vec<u8>)>,
}

pub struct MiningCandidateSelection {
    pub candidate_index: usize,
    pub entries: Vec<SelectedMempoolEntry>,
    pub pending_outputs: HashSet<u32>,
    pub trade_authorizations: Vec<(TxBodyHash, Vec<u8>)>,
}

fn require_parent(
    st: &MempoolState,
    parent_height: u64,
    parent_hash: [u8; 32],
    epoch_anchor: [u8; 32],
) -> Result<u64, SubmitError> {
    if st.view.tip_height != parent_height
        || st.view.tip_hash != parent_hash
        || st.view.user_epoch_anchor_id != epoch_anchor
    {
        return Err(SubmitError::MalformedIntent(
            "mempool parent changed during template selection".into(),
        ));
    }
    parent_height
        .checked_add(1)
        .ok_or_else(|| SubmitError::Internal("height exhausted".into()))
}

impl AsyncMempool {
    /// Clone semantic references while retained capsules stay in the pool.
    pub async fn trade_mining_snapshot(
        &self,
        parent_height: u64,
        parent_hash: [u8; 32],
        epoch_anchor: [u8; 32],
    ) -> Result<TradeMiningSnapshot, SubmitError> {
        let st = self.state.lock().await;
        let height = require_parent(&st, parent_height, parent_hash, epoch_anchor)?;
        let intents = st
            .pool
            .iter()
            .filter_map(|(_, entry)| {
                let intent = entry.trade_intent()?;
                intent
                    .policy
                    .check_context(
                        noid_chain::state::native_assets::native_chain_id(),
                        epoch_anchor,
                        height,
                    )
                    .ok()?;
                entry.cached_authorization()?;
                entry.shared_trade_intent()
            })
            .collect();
        Ok(TradeMiningSnapshot {
            intents,
            pending_outputs: st.admitted_output_slots.clone(),
        })
    }

    /// Compare complete class revenues before copying the winning capsules.
    pub async fn select_for_v2_mining_prefilled(
        &self,
        parent_height: u64,
        parent_hash: [u8; 32],
        epoch_anchor: [u8; 32],
        small: V2MiningReservation,
        large: Option<V2MiningReservation>,
    ) -> Result<PrefilledV2MempoolSelection, SubmitError> {
        let candidates = std::iter::once(small).chain(large).collect();
        let selected = self
            .select_for_mining_candidates(parent_height, parent_hash, epoch_anchor, candidates)
            .await?;
        Ok(PrefilledV2MempoolSelection {
            selection: V2MempoolSelection {
                large_class: selected.candidate_index == 1,
                entries: selected.entries,
                pending_outputs: selected.pending_outputs,
            },
            trade_authorizations: selected.trade_authorizations,
        })
    }

    /// Compare all offered class budgets under one parent-bound pool lock.
    /// Equal revenue preserves candidate order; only the winner's capsules
    /// cross the lock boundary.
    pub async fn select_for_mining_candidates(
        &self,
        parent_height: u64,
        parent_hash: [u8; 32],
        epoch_anchor: [u8; 32],
        candidates: Vec<V2MiningReservation>,
    ) -> Result<MiningCandidateSelection, SubmitError> {
        if !(1..=3).contains(&candidates.len()) {
            return Err(SubmitError::MalformedIntent(
                "mining class candidate count".into(),
            ));
        }
        let st = self.state.lock().await;
        let height = require_parent(&st, parent_height, parent_hash, epoch_anchor)?;
        if !noid_chain::consensus::params::v2_active(height) {
            return Err(SubmitError::MalformedIntent(
                "v2 is not active at the candidate height".into(),
            ));
        }
        for reservation in &candidates {
            let mut unique = HashSet::new();
            for id in &reservation.trade_ids {
                let entry = st.pool.get(id).ok_or_else(|| {
                    SubmitError::MalformedIntent("selected trade left the mempool".into())
                })?;
                let intent = entry.trade_intent().ok_or_else(|| {
                    SubmitError::MalformedIntent("selected entry is not a trade".into())
                })?;
                if !unique.insert(*id) || entry.cached_authorization().is_none() {
                    return Err(SubmitError::MalformedIntent(
                        "selected trade authorization set".into(),
                    ));
                }
                intent
                    .policy
                    .check_context(
                        noid_chain::state::native_assets::native_chain_id(),
                        epoch_anchor,
                        height,
                    )
                    .map_err(|error| SubmitError::MalformedIntent(error.to_string()))?;
            }
        }
        let choose = |reservation: &V2MiningReservation| {
            st.pool.select_for_block_with_reservations(
                reservation.remaining,
                &epoch_anchor,
                &reservation.occupied,
            )
        };
        let revenue = |entries: &[&MempoolEntry], reservation: &V2MiningReservation| {
            entries
                .iter()
                .try_fold(reservation.claimable_fees, |total, entry| {
                    let burned = fee_breakdown(
                        u64::from(entry.spend.live_inputs),
                        u64::from(entry.spend.live_outputs),
                        st.view.active_slot_count,
                        st.view.log_slots(),
                    )
                    .burned;
                    total.checked_add(u128::from(entry.spend.fee.saturating_sub(burned)))
                })
                .ok_or_else(|| SubmitError::MalformedIntent("mining candidate fee overflow".into()))
        };
        let mut candidate_index = 0;
        let mut selected = choose(&candidates[0]);
        let mut best_revenue = revenue(&selected, &candidates[0])?;
        for (index, candidate) in candidates.iter().enumerate().skip(1) {
            let alternative = choose(candidate);
            let alternative_revenue = revenue(&alternative, candidate)?;
            if alternative_revenue > best_revenue {
                selected = alternative;
                candidate_index = index;
                best_revenue = alternative_revenue;
            }
        }
        let reservation = &candidates[candidate_index];
        let entries = selected
            .into_iter()
            .map(|entry| SelectedMempoolEntry {
                pages: entry.pages.clone(),
                logical_txid: entry.spend.logical_txid,
                cached_authorization: entry.cached_authorization().map(<[u8]>::to_vec),
                contract_opening: entry.contract_opening(),
                native_intent: entry.native_intent(),
            })
            .collect();
        let trade_authorizations = reservation
            .trade_ids
            .iter()
            .map(|id| {
                (
                    *id,
                    st.pool
                        .get(id)
                        .and_then(MempoolEntry::cached_authorization)
                        .expect("selected retained trade was checked above")
                        .to_vec(),
                )
            })
            .collect();
        let mut pending_outputs = st.admitted_output_slots.clone();
        pending_outputs.extend(&reservation.occupied.outputs);
        Ok(MiningCandidateSelection {
            candidate_index,
            entries,
            pending_outputs,
            trade_authorizations,
        })
    }
}
