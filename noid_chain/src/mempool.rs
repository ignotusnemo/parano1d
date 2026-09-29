// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! In-memory mempool for admitted transactions.
//!
//! `Mempool` is a pure data structure with no I/O, no async, no networking.
//! `AsyncMempool` in `noid_mempool` wraps this in async admission/eviction tasks and connects it to the
//! P2P layer and the block template builder.
//!
//! # Design
//!
//! Admission and authorization run in `noid_mempool`; this module only owns
//! deterministic storage, ordering and eviction of already admitted entries.
//!
//! When a block is confirmed: `on_block_confirmed()` removes confirmed txs
//! and returns reverted txs (from reorged blocks) to the pool.
//!
//! On an epoch boundary or reorg, `evict_wrong_anchor` removes every intent
//! that does not bind the chain's one current transaction-epoch anchor.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use noid_poseidon2b::primitives::{Address, Digest, TxBodyHash};
use noid_tx::{
    paged_spend_authorization_wire_offset, validate_paged_spend, PagedSpendFacts, TxPage,
};

use crate::consensus::params::BLOCK_MAX_TXS;

// ---------------------------------------------------------------------------
// Fee-priority key for BTreeMap index
// ---------------------------------------------------------------------------

/// Ordering key for the fee-priority BTreeMap index.
///
/// BTreeMap iterates in ascending key order, so we use descending fee_rate
/// (via `u64::MAX - fee_rate`) and ascending logical txid as tie-break.
/// This gives us the highest-fee tx at the front of iteration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FeeKey {
    /// `u64::MAX - fee_rate`: sorts higher fee_rate to lower BTreeMap key.
    neg_fee_rate: u64,
    /// Ascending logical txid: deterministic tie-break.
    hash: [u8; 32],
}

impl FeeKey {
    fn new(fee_rate: u64, hash: TxBodyHash) -> Self {
        Self {
            neg_fee_rate: u64::MAX - fee_rate,
            hash: hash.0,
        }
    }
}

// ---------------------------------------------------------------------------
// MempoolEntry
// ---------------------------------------------------------------------------

/// One indivisible logical PagedSpend admitted to the mempool.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    /// Ordered physical pages. The detached authorization remains borrowed
    /// from `intent_bytes` and is not duplicated here.
    pub pages: Vec<TxPage>,
    /// Canonical aggregate facts, including the logical txid.
    pub spend: PagedSpendFacts,
    /// Chain height at the time of admission.
    pub admitted_height: u64,
    /// Fee per weighted resource unit.
    ///
    /// The weight is `inputs + outputs + 4 × net_new_slots`, so transactions
    /// that grow live state are deprioritised versus state-shrinking
    /// transactions at similar fees.
    pub fee_rate: u64,

    /// Length of the versioned `WalletAuthorizationBundle` suffix inside
    /// `intent_bytes`. Zero means no retained authorization. Keeping only the
    /// range metadata avoids retaining the same proof in a second allocation.
    cached_authorization_len: u32,

    /// Canonical ordinary or contract intent bytes as submitted by the wallet.
    /// Stored so the P2P mempool-sync protocol can re-serve existing TXs to
    /// newly connected peers (gossipsub deduplication prevents re-gossiping;
    /// a dedicated request-response exchange is the only reliable mechanism).
    pub intent_bytes: Arc<[u8]>,
}

impl MempoolEntry {
    /// Compute fee rate from group-wide live resources.
    pub fn compute_fee_rate(spend: &PagedSpendFacts) -> u64 {
        let n_inputs = u64::from(spend.live_inputs);
        let n_outputs = u64::from(spend.live_outputs);
        let net_new_slots = n_outputs.saturating_sub(n_inputs);
        let weight = n_inputs
            .saturating_add(n_outputs)
            .saturating_add(net_new_slots.saturating_mul(4))
            .max(1);
        spend.fee / weight
    }

    /// Create a new entry.
    ///
    /// `current_height` — chain tip at admission time.
    pub fn new(pages: Vec<TxPage>, current_height: u64) -> Result<Self, noid_tx::PagedSpendError> {
        let spend = validate_paged_spend(&pages)?;
        let fee_rate = Self::compute_fee_rate(&spend);
        Ok(Self {
            pages,
            spend,
            admitted_height: current_height,
            fee_rate,
            cached_authorization_len: 0,
            intent_bytes: Arc::from([]), // populated by AsyncMempool::submit
        })
    }

    /// Borrow the retained authorization directly from the immutable intent.
    pub fn cached_authorization(&self) -> Option<&[u8]> {
        let len = usize::try_from(self.cached_authorization_len).ok()?;
        if len == 0 {
            return None;
        }
        let start = paged_spend_authorization_wire_offset(self.pages.len())
            .ok()?
            .checked_add(self.contract_prefix_bytes())?;
        let end = start.checked_add(len)?;
        self.intent_bytes.get(start..end)
    }

    fn contract_prefix_bytes(&self) -> usize {
        if self
            .intent_bytes
            .starts_with(noid_tx::experimental_object::INTENT_MAGIC)
        {
            noid_tx::experimental_object::INTENT_PREFIX_BYTES
        } else {
            0
        }
    }

    /// Borrow the canonical public opening from an admitted contract envelope.
    /// The authorization payload is never copied with it.
    pub fn contract_opening_bytes(
        &self,
    ) -> Option<&[u8; noid_tx::experimental_object::OPENING_BYTES]> {
        use noid_tx::experimental_object::INTENT_MAGIC;

        let end = self.contract_prefix_bytes();
        self.intent_bytes
            .get(INTENT_MAGIC.len()..end)?
            .try_into()
            .ok()
    }

    /// Decode only the bounded opening from an already admitted envelope.
    /// The detached authorization remains borrowed from the retained bytes.
    pub fn contract_opening(&self) -> Option<noid_tx::experimental_object::ObjectOpening> {
        noid_tx::experimental_object::ObjectOpening::from_bytes(self.contract_opening_bytes()?).ok()
    }
}

/// User resources available in one proof class, excluding the system record.
/// A producer derives this budget from its pinned bank. This is selection
/// policy only; the block proof independently enforces every resource limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockSelectionBudget {
    pub pages: usize,
    pub live_inputs: usize,
    pub contract_calls: usize,
}

impl BlockSelectionBudget {
    fn pages_only(pages: usize) -> Self {
        Self {
            pages,
            live_inputs: usize::MAX,
            contract_calls: usize::MAX,
        }
    }
}

// ---------------------------------------------------------------------------
// MempoolError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolError {
    /// Transaction already in the pool.
    AlreadyAdmitted,
    /// Input slot conflict with an already-admitted transaction.
    InputConflict { conflicting_hash: TxBodyHash },
    /// Output slot conflict with an already-admitted transaction.
    OutputConflict { conflicting_hash: TxBodyHash },
    /// Pool is at capacity.
    Full,
}

// ---------------------------------------------------------------------------
// Mempool
// ---------------------------------------------------------------------------

/// In-memory mempool: a conflict-free set of admitted transactions.
///
/// Invariants maintained:
/// - No two live actions share any physical slot.
/// - `fee_index` is always in sync with `entries`.
///
/// # Block selection performance
///
/// `fee_index: BTreeMap<FeeKey, TxBodyHash>` gives O(max_txs) iteration for
/// `select_for_block` instead of O(N log N) sort over all entries.
/// At N=8192, BTreeMap is ~8192x faster for a 1-tx block, and equivalent for
/// a 1024-tx full block (both O(N)). In both cases no allocation occurs.
pub struct Mempool {
    /// Admitted entries, indexed by logical txid.
    entries: HashMap<TxBodyHash, MempoolEntry>,
    /// Fee-priority index: sorted by (desc fee_rate, asc logical txid).
    /// Always in sync with `entries`: insert on `admit`, remove on `remove`.
    fee_index: BTreeMap<FeeKey, TxBodyHash>,
    /// Input slot -> logical txid of the group that spends it.
    spent_inputs: HashMap<u32, TxBodyHash>,
    /// Output slot -> logical txid of the group that mints it.
    minted_outputs: HashMap<u32, TxBodyHash>,
    /// Pending value sent to each external owner. Change back to the input
    /// owner is excluded, so wallet UIs do not mislabel change as incoming.
    incoming_value_by_owner: HashMap<Address, u64>,
    /// Maximum number of entries.
    capacity: usize,
}

impl Mempool {
    /// Create a new empty mempool with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity.min(4096)),
            fee_index: BTreeMap::new(),
            spent_inputs: HashMap::new(),
            minted_outputs: HashMap::new(),
            incoming_value_by_owner: HashMap::new(),
            capacity,
        }
    }

    /// Default capacity = BLOCK_MAX_TXS * 8 (8 blocks worth of txs).
    pub fn with_default_capacity() -> Self {
        Self::new(BLOCK_MAX_TXS * 8)
    }

    /// Number of transactions currently in the pool.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the pool contains no transactions.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// True if the pool contains a transaction with the given hash.
    pub fn contains(&self, hash: &TxBodyHash) -> bool {
        self.entries.contains_key(hash)
    }

    /// Get an entry by logical txid. O(1) HashMap lookup.
    pub fn get(&self, hash: &TxBodyHash) -> Option<&MempoolEntry> {
        self.entries.get(hash)
    }

    /// Attempt to add one complete PagedSpend group to the pool.
    ///
    /// The caller is responsible for native admission checks. This function
    /// only checks pool-internal constraints
    /// (capacity, duplicates, slot conflicts with already-admitted txs).
    ///
    pub fn admit(&mut self, pages: Vec<TxPage>, current_height: u64) -> Result<(), MempoolError> {
        if self.entries.len() >= self.capacity {
            return Err(MempoolError::Full);
        }
        let entry = MempoolEntry::new(pages, current_height)
            .expect("AsyncMempool admits only natively validated PagedSpend groups");
        let hash = entry.spend.logical_txid;
        if self.entries.contains_key(&hash) {
            return Err(MempoolError::AlreadyAdmitted);
        }

        // Check input slot conflicts.
        for page in &entry.pages {
            for (_, inp) in page.body.live_inputs() {
                if let Some(&existing) = self
                    .spent_inputs
                    .get(&inp.slot_index)
                    .or_else(|| self.minted_outputs.get(&inp.slot_index))
                {
                    return Err(MempoolError::InputConflict {
                        conflicting_hash: existing,
                    });
                }
            }
        }
        // Check output slot conflicts.
        for page in &entry.pages {
            for (_, out) in page.body.live_outputs() {
                if let Some(&existing) = self
                    .minted_outputs
                    .get(&out.slot_index)
                    .or_else(|| self.spent_inputs.get(&out.slot_index))
                {
                    return Err(MempoolError::OutputConflict {
                        conflicting_hash: existing,
                    });
                }
            }
        }

        // All checks passed — insert.
        let fee_key = FeeKey::new(entry.fee_rate, hash);
        for page in &entry.pages {
            for (_, inp) in page.body.live_inputs() {
                self.spent_inputs.insert(inp.slot_index, hash);
            }
            for (_, out) in page.body.live_outputs() {
                self.minted_outputs.insert(out.slot_index, hash);
                if out.owner != entry.spend.input_owner {
                    self.incoming_value_by_owner
                        .entry(out.owner)
                        .and_modify(|value| *value = value.saturating_add(out.amount))
                        .or_insert(out.amount);
                }
            }
        }
        self.fee_index.insert(fee_key, hash);
        self.entries.insert(hash, entry);
        Ok(())
    }

    /// Remove a transaction by hash. Returns the removed entry, or `None`.
    pub fn remove(&mut self, hash: &TxBodyHash) -> Option<MempoolEntry> {
        let entry = self.entries.remove(hash)?;
        // Remove from fee_index using the same key that was inserted.
        self.fee_index.remove(&FeeKey::new(entry.fee_rate, *hash));
        for page in &entry.pages {
            for (_, inp) in page.body.live_inputs() {
                self.spent_inputs.remove(&inp.slot_index);
            }
            for (_, out) in page.body.live_outputs() {
                self.minted_outputs.remove(&out.slot_index);
                if out.owner != entry.spend.input_owner {
                    let remove_owner = self
                        .incoming_value_by_owner
                        .get_mut(&out.owner)
                        .is_some_and(|value| {
                            *value = value.saturating_sub(out.amount);
                            *value == 0
                        });
                    if remove_owner {
                        self.incoming_value_by_owner.remove(&out.owner);
                    }
                }
            }
        }
        Some(entry)
    }

    /// Evict every user intent not bound to the chain's current exact anchor.
    pub fn evict_wrong_anchor(&mut self, current_anchor: &Digest) -> Vec<TxBodyHash> {
        let expired: Vec<TxBodyHash> = self
            .entries
            .iter()
            .filter(|(_, entry)| &entry.spend.epoch_anchor != current_anchor)
            .map(|(&h, _)| h)
            .collect();
        for hash in &expired {
            self.remove(hash);
        }
        expired
    }

    /// Fee-pack complete groups into at most `max_pages` physical pages.
    ///
    /// Returns entries in descending fee_rate order (highest fees first),
    /// with ascending logical txid as a deterministic tie-break.
    ///
    /// Does NOT include coinbase (caller adds it separately).
    /// Does NOT resolve cross-tx slot conflicts — the caller must call
    /// `resolve_slot_conflicts()` on the result.
    ///
    /// # Performance
    ///
    /// O(max_txs × log N) using the `fee_index` BTreeMap instead of
    /// the previous O(N log N) sort-all. At N=8192 and max_txs=1023:
    /// ~1023 BTreeMap lookups (~10K operations) vs ~107K comparisons.
    pub fn select_for_block(&self, max_pages: usize) -> Vec<&MempoolEntry> {
        self.select_for_block_matching(BlockSelectionBudget::pages_only(max_pages), |_| true)
    }

    /// Anchor-filter before page packing so stale high-fee groups cannot
    /// consume the local B25/B255 page budget and starve valid groups.
    pub fn select_for_block_at_anchor(
        &self,
        max_pages: usize,
        epoch_anchor: &Digest,
    ) -> Vec<&MempoolEntry> {
        self.select_for_block_matching(BlockSelectionBudget::pages_only(max_pages), |entry| {
            &entry.spend.epoch_anchor == epoch_anchor
        })
    }

    /// Filter all three resources before cloning or packing an indivisible
    /// group. Exhausted call/input capacity must not consume remaining pages.
    pub fn select_for_block_with_budget(
        &self,
        budget: BlockSelectionBudget,
        epoch_anchor: &Digest,
    ) -> Vec<&MempoolEntry> {
        self.select_for_block_matching(budget, |entry| &entry.spend.epoch_anchor == epoch_anchor)
    }

    fn select_for_block_matching(
        &self,
        budget: BlockSelectionBudget,
        keep: impl Fn(&MempoolEntry) -> bool,
    ) -> Vec<&MempoolEntry> {
        let mut remaining_pages = budget
            .pages
            .min(crate::consensus::params::BLOCK_MAX_USER_PAGES);
        let mut remaining_inputs = budget.live_inputs;
        let mut remaining_calls = budget.contract_calls;
        let mut selected = Vec::new();
        if remaining_pages == 0 || remaining_inputs == 0 {
            return selected;
        }
        for hash in self.fee_index.values() {
            let Some(entry) = self.entries.get(hash) else {
                continue;
            };
            if !keep(entry) {
                continue;
            }
            let inputs = usize::from(entry.spend.live_inputs);
            let calls = entry
                .pages
                .iter()
                .filter(|page| page.body.validity_bitmap & noid_tx::PAGED_SPEND_CONTRACT_BIT != 0)
                .count();
            if entry.pages.len() > remaining_pages
                || inputs > remaining_inputs
                || calls > remaining_calls
            {
                continue;
            }
            remaining_pages -= entry.pages.len();
            remaining_inputs -= inputs;
            remaining_calls -= calls;
            selected.push(entry);
            if remaining_pages == 0 {
                break;
            }
        }
        selected
    }

    /// Update the pool after a block is confirmed or after a reorg.
    ///
    /// - `confirmed`: logical txids that were included in the confirmed block.
    ///   These are removed from the pool (already applied to state).
    ///
    /// - `reverted`: logical txids from reorged blocks that should be returned
    ///   to the pool (their state changes were undone). The caller is responsible
    ///   for re-validating these txs against the new chain state before re-admitting.
    ///   This function only removes confirmed; reverted txs must be re-admitted via `admit()`.
    ///
    /// Returns the number of transactions removed.
    pub fn on_block_confirmed(&mut self, confirmed: &[TxBodyHash]) -> usize {
        let mut removed = 0;
        for hash in confirmed {
            if self.remove(hash).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Iterate over all entries (no guaranteed order).
    pub fn iter(&self) -> impl Iterator<Item = (&TxBodyHash, &MempoolEntry)> {
        self.entries.iter()
    }

    /// Store canonical raw PagedSpendIntent bytes for mempool-sync serving and retain
    /// only the authorization suffix length. The proof itself is borrowed from
    /// this one immutable allocation by miners and the block fast path.
    pub fn set_intent_bytes(&mut self, hash: &TxBodyHash, bytes: impl Into<Arc<[u8]>>) {
        if let Some(entry) = self.entries.get_mut(hash) {
            entry.intent_bytes = bytes.into();
            let offset = paged_spend_authorization_wire_offset(entry.pages.len())
                .ok()
                .and_then(|offset| offset.checked_add(entry.contract_prefix_bytes()));
            entry.cached_authorization_len = offset
                .and_then(|offset| entry.intent_bytes.len().checked_sub(offset))
                .and_then(|len| u32::try_from(len).ok())
                .unwrap_or(0);
        }
    }

    /// Clone a bounded prefix of retained intents for one mempool-sync reply.
    ///
    /// Bounds are enforced before cloning each payload.  In particular this
    /// never constructs a full-pool `Vec<Vec<u8>>` only to truncate it at the
    /// network boundary.
    pub fn intent_bytes_prefix(
        &self,
        max_txs: usize,
        max_total_bytes: usize,
        max_tx_bytes: usize,
    ) -> Vec<Vec<u8>> {
        self.intent_bytes_missing(&[], max_txs, max_total_bytes, max_tx_bytes)
    }

    /// Serve only missing logical transactions, with exactly the same payload
    /// bounds as a legacy prefix. `known` is sorted and unique at the wire
    /// boundary. No proof payload is cloned for an excluded transaction.
    pub fn intent_bytes_missing(
        &self,
        known: &[[u8; 32]],
        max_txs: usize,
        max_total_bytes: usize,
        max_tx_bytes: usize,
    ) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(max_txs.min(self.entries.len()));
        let mut total_bytes = 0usize;

        for (txid, entry) in &self.entries {
            if out.len() == max_txs {
                break;
            }
            if known.binary_search(txid.as_bytes()).is_ok() {
                continue;
            }
            let bytes = entry.intent_bytes.as_ref();
            if bytes.is_empty() || bytes.len() > max_tx_bytes {
                continue;
            }
            let Some(next_total) = total_bytes.checked_add(bytes.len()) else {
                break;
            };
            if next_total > max_total_bytes {
                break;
            }
            out.push(bytes.to_vec());
            total_bytes = next_total;
        }
        out
    }

    /// Total serialized PagedSpendIntent bytes retained by this mempool.
    pub fn total_intent_bytes(&self) -> usize {
        self.entries.values().map(|e| e.intent_bytes.len()).sum()
    }

    /// Total fees available in the pool (useful for coinbase computation).
    pub fn total_fees(&self) -> u64 {
        self.entries
            .values()
            .map(|entry| entry.spend.fee)
            .fold(0u64, |a, f| a.saturating_add(f))
    }

    /// Pending external value addressed to `owner`, excluding change produced
    /// by spends from the same owner. O(1), maintained on admission/removal.
    pub fn pending_incoming_for_owner(&self, owner: &Address) -> u64 {
        self.incoming_value_by_owner
            .get(owner)
            .copied()
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, TxBody, TxInput, TxOutput, PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT,
        TX_INPUTS, TX_OUTPUTS,
    };

    fn tx(input_slot: u32, output_slot: u32, fee: u64, seed: u8, anchor: Digest) -> Vec<TxPage> {
        tx_to(input_slot, output_slot, fee, seed, seed, anchor)
    }

    fn tx_to(
        input_slot: u32,
        output_slot: u32,
        fee: u64,
        input_seed: u8,
        output_seed: u8,
        anchor: Digest,
    ) -> Vec<TxPage> {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: input_slot,
            amount: 100 + fee,
            creation_id: 1,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: output_slot,
            amount: 100,
            owner: Address([output_seed; 32]),
        };
        vec![TxPage::new(TxBody {
            epoch_anchor: anchor,
            fee,
            input_owner: Address([input_seed; 32]),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0) | PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        })
        .unwrap()]
    }

    fn paged_tx(page_count: usize, slot_base: u32, fee: u64, seed: u8) -> Vec<TxPage> {
        (0..page_count)
            .map(|page_index| {
                let mut inputs = [TxInput::dummy(); TX_INPUTS];
                for (slot, input) in inputs.iter_mut().enumerate() {
                    *input = TxInput {
                        slot_index: slot_base + 10 * page_index as u32 + slot as u32,
                        amount: 25 + u64::from(page_index == 0 && slot == 0) * fee,
                        creation_id: 1,
                    };
                }
                let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
                for (slot, output) in outputs.iter_mut().enumerate() {
                    *output = TxOutput {
                        slot_index: slot_base + 10 * page_index as u32 + 8 + slot as u32,
                        amount: 100,
                        owner: Address([seed; 32]),
                    };
                }
                let mut validity_bitmap = 0x00ff | output_bitmap_bit(0) | output_bitmap_bit(1);
                if page_index == 0 {
                    validity_bitmap |= PAGED_SPEND_START_BIT;
                }
                if page_index + 1 == page_count {
                    validity_bitmap |= PAGED_SPEND_END_BIT;
                }
                TxPage::new(TxBody {
                    epoch_anchor: [9u8; 32],
                    fee: if page_index == 0 { fee } else { 0 },
                    input_owner: Address([seed; 32]),
                    inputs,
                    outputs,
                    validity_bitmap,
                    is_coinbase: false,
                })
                .unwrap()
            })
            .collect()
    }

    fn id(pages: &[TxPage]) -> TxBodyHash {
        validate_paged_spend(pages).unwrap().logical_txid
    }

    #[test]
    fn derived_txid_keys_and_duplicate_admission() {
        let mut pool = Mempool::new(4);
        let tx = tx(1, 2, 10, 1, [9u8; 32]);
        let hash = id(&tx);
        pool.admit(tx.clone(), 3).unwrap();
        assert!(pool.contains(&hash));
        assert_eq!(pool.admit(tx, 3), Err(MempoolError::AlreadyAdmitted));
        assert_eq!(pool.remove(&hash).unwrap().spend.logical_txid, hash);
    }

    #[test]
    fn pending_incoming_index_excludes_change_and_tracks_removal() {
        let mut pool = Mempool::new(4);
        let recipient = Address([9; 32]);
        let first = tx_to(1, 2, 10, 1, 9, [7; 32]);
        let first_id = id(&first);
        let second = tx_to(3, 4, 10, 2, 9, [7; 32]);
        pool.admit(first, 3).unwrap();
        pool.admit(second, 3).unwrap();

        assert_eq!(pool.pending_incoming_for_owner(&recipient), 200);
        assert_eq!(pool.pending_incoming_for_owner(&Address([1; 32])), 0);
        pool.remove(&first_id).unwrap();
        assert_eq!(pool.pending_incoming_for_owner(&recipient), 100);
    }

    #[test]
    fn pending_set_is_fully_disjoint() {
        let mut pool = Mempool::new(8);
        pool.admit(tx(1, 2, 10, 1, [9u8; 32]), 3).unwrap();

        assert!(matches!(
            pool.admit(tx(1, 3, 10, 2, [9u8; 32]), 3),
            Err(MempoolError::InputConflict { .. })
        ));
        assert!(matches!(
            pool.admit(tx(4, 2, 10, 3, [9u8; 32]), 3),
            Err(MempoolError::OutputConflict { .. })
        ));
        assert!(matches!(
            pool.admit(tx(2, 5, 10, 4, [9u8; 32]), 3),
            Err(MempoolError::InputConflict { .. })
        ));
        assert!(matches!(
            pool.admit(tx(6, 1, 10, 5, [9u8; 32]), 3),
            Err(MempoolError::OutputConflict { .. })
        ));
    }

    #[test]
    fn epoch_switch_evicts_by_exact_anchor() {
        let mut pool = Mempool::new(8);
        let old = tx(1, 2, 10, 1, [7u8; 32]);
        let old_hash = id(&old);
        pool.admit(old, 3).unwrap();
        pool.admit(tx(3, 4, 10, 2, [8u8; 32]), 3).unwrap();

        let evicted = pool.evict_wrong_anchor(&[8u8; 32]);
        assert_eq!(evicted, vec![old_hash]);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn fee_index_selects_highest_rate_first_and_capacity_holds() {
        let mut pool = Mempool::new(2);
        let low = tx(1, 2, 1, 1, [9u8; 32]);
        let high = tx(3, 4, 100, 2, [9u8; 32]);
        let high_id = id(&high);
        pool.admit(low, 0).unwrap();
        pool.admit(high.clone(), 0).unwrap();
        assert_eq!(pool.select_for_block(1)[0].spend.logical_txid, high_id);
        assert_eq!(
            pool.admit(tx(5, 6, 10, 3, [9u8; 32]), 0),
            Err(MempoolError::Full)
        );
    }

    #[test]
    fn resource_budgets_pack_calls_and_payments_without_assuming_nested_classes() {
        let mut pool = Mempool::new(400);
        for slot in 0..340 {
            let mut pages = tx(
                slot * 2,
                slot * 2 + 1,
                if slot < 70 { 1_000 } else { 1 },
                1,
                [9; 32],
            );
            if slot < 70 {
                pages[0].body.validity_bitmap |= noid_tx::PAGED_SPEND_CONTRACT_BIT;
            }
            pool.admit(pages, 0).unwrap();
        }
        // These are example independent budgets, not a release selection.
        for (budget, expected_pages, expected_calls) in [
            (
                BlockSelectionBudget {
                    pages: 63,
                    live_inputs: 504,
                    contract_calls: 63,
                },
                63,
                63,
            ),
            (
                BlockSelectionBudget {
                    pages: 255,
                    live_inputs: 1_020,
                    contract_calls: 26,
                },
                255,
                26,
            ),
            (
                BlockSelectionBudget {
                    pages: 63,
                    live_inputs: 10,
                    contract_calls: 4,
                },
                10,
                4,
            ),
            (
                BlockSelectionBudget {
                    pages: 63,
                    live_inputs: 504,
                    contract_calls: 0,
                },
                63,
                0,
            ),
            (
                BlockSelectionBudget {
                    pages: 0,
                    live_inputs: 504,
                    contract_calls: 63,
                },
                0,
                0,
            ),
            (
                BlockSelectionBudget {
                    pages: 63,
                    live_inputs: 0,
                    contract_calls: 63,
                },
                0,
                0,
            ),
        ] {
            let selected = pool.select_for_block_with_budget(budget, &[9; 32]);
            assert_eq!(selected.len(), expected_pages);
            assert_eq!(
                selected
                    .iter()
                    .filter(|entry| entry.spend.fee == 1_000)
                    .count(),
                expected_calls
            );
            assert!(pool
                .select_for_block_with_budget(budget, &[8; 32])
                .is_empty());
        }
        assert_eq!(
            pool.len(),
            340,
            "template selection never removes pending entries"
        );
    }

    #[test]
    fn input_budget_skips_whole_groups_and_does_not_slice_a_spend() {
        let mut pool = Mempool::new(4);
        let large = paged_tx(2, 1_000, 32_000, 7);
        let large_id = id(&large);
        let small = tx(1, 2, 1, 8, [9; 32]);
        let small_id = id(&small);
        pool.admit(large, 0).unwrap();
        pool.admit(small, 0).unwrap();
        for (inputs, expected) in [
            (15, vec![small_id]),
            (16, vec![large_id]),
            (17, vec![large_id, small_id]),
        ] {
            let selected = pool.select_for_block_with_budget(
                BlockSelectionBudget {
                    pages: 255,
                    live_inputs: inputs,
                    contract_calls: 255,
                },
                &[9; 32],
            );
            assert_eq!(
                selected
                    .iter()
                    .map(|e| e.spend.logical_txid)
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn contract_authorization_borrows_the_exact_envelope_suffix() {
        use noid_tx::experimental_object::{applications, ObjectIntent, INTENT_PREFIX_BYTES};
        let opening = applications::refundable_payment(Address([1; 32]), Address([2; 32]), 10, 100);
        let page = opening
            .build_call(
                TxInput {
                    slot_index: 1,
                    amount: 1_000,
                    creation_id: 1,
                },
                2,
                10,
                [9; 32],
                9,
                true,
            )
            .unwrap();
        let intent = ObjectIntent {
            opening: opening.clone(),
            spend: noid_tx::PagedSpendIntent::new(vec![page], vec![0xa5; 64]).unwrap(),
        };
        let txid = intent.spend.logical_txid();
        let mut pool = Mempool::new(4);
        pool.admit(intent.spend.pages.clone(), 8).unwrap();
        pool.set_intent_bytes(&txid, intent.to_bytes().unwrap());
        let entry = pool.get(&txid).unwrap();
        assert_eq!(entry.contract_opening(), Some(opening));
        let authorization = entry.cached_authorization().unwrap();
        assert_eq!(authorization, &[0xa5; 64]);
        let offset = INTENT_PREFIX_BYTES + paged_spend_authorization_wire_offset(1).unwrap();
        assert_eq!(
            authorization.as_ptr(),
            entry.intent_bytes[offset..].as_ptr()
        );
    }

    #[test]
    fn b25_skips_b255_only_group_without_slicing_or_waiting() {
        let mut pool = Mempool::new(4);
        let large = paged_tx(26, 1_000, 26_000, 7);
        let large_id = id(&large);
        let small = tx(1, 2, 1, 8, [9u8; 32]);
        let small_id = id(&small);
        pool.admit(large, 0).unwrap();
        pool.admit(small, 0).unwrap();

        let b25 = pool.select_for_block(25);
        assert_eq!(b25.len(), 1);
        assert_eq!(b25[0].spend.logical_txid, small_id);
        assert_eq!(b25[0].pages.len(), 1);

        let b255 = pool.select_for_block(255);
        assert_eq!(b255.len(), 2);
        assert_eq!(b255[0].spend.logical_txid, large_id);
        assert_eq!(b255[0].pages.len(), 26);
        assert_eq!(
            b255.iter().map(|entry| entry.pages.len()).sum::<usize>(),
            27
        );
    }

    #[test]
    fn large_groups_keep_normal_fee_order_without_reserved_space() {
        let mut pool = Mempool::new(260);
        let large = paged_tx(30, 10_000, 30_000, 7);
        let large_id = id(&large);
        pool.admit(large, 0).unwrap();
        for slot in 0..230 {
            pool.admit(tx(slot * 2, slot * 2 + 1, 1_000, 8, [9; 32]), 0)
                .unwrap();
        }
        let tail = tx(2_000, 2_001, 1, 9, [9; 32]);
        let tail_id = id(&tail);
        pool.admit(tail, 0).unwrap();

        // Higher-fee small groups consume 230 positions first. The large group
        // does not fit the remaining 25, but a later small group still does.
        let selected = pool.select_for_block_at_anchor(255, &[9; 32]);
        assert_eq!(selected.len(), 231);
        assert!(selected
            .iter()
            .all(|entry| entry.spend.logical_txid != large_id));
        assert_eq!(selected.last().unwrap().spend.logical_txid, tail_id);
        assert!(pool.contains(&large_id));

        // Once it fits, the large group enters in ordinary fee order, whole.
        let first_id = selected[0].spend.logical_txid;
        drop(selected);
        pool.remove(&first_id);
        for entry in pool.select_for_block_at_anchor(4, &[9; 32]) {
            assert_ne!(entry.spend.logical_txid, large_id);
        }
        let remove: Vec<_> = pool
            .select_for_block(4)
            .iter()
            .map(|entry| entry.spend.logical_txid)
            .collect();
        for hash in remove {
            pool.remove(&hash);
        }
        let selected = pool.select_for_block_at_anchor(255, &[9; 32]);
        assert_eq!(
            selected
                .iter()
                .map(|entry| entry.pages.len())
                .sum::<usize>(),
            255
        );
        assert_eq!(selected.last().unwrap().spend.logical_txid, large_id);
        assert_eq!(selected.last().unwrap().pages.len(), 30);
    }

    #[test]
    fn mempool_sync_clones_only_within_requested_byte_and_count_bounds() {
        let mut pool = Mempool::new(4);
        let a = tx(1, 2, 10, 1, [9u8; 32]);
        let b = tx(3, 4, 10, 2, [9u8; 32]);
        let c = tx(5, 6, 10, 3, [9u8; 32]);
        let ids = [id(&a), id(&b), id(&c)];
        pool.admit(a, 0).unwrap();
        pool.admit(b, 0).unwrap();
        pool.admit(c, 0).unwrap();
        for id in ids {
            pool.set_intent_bytes(&id, vec![0xA5; 4]);
        }

        let by_count = pool.intent_bytes_prefix(2, usize::MAX, usize::MAX);
        assert_eq!(by_count.len(), 2);
        assert_eq!(by_count.iter().map(Vec::len).sum::<usize>(), 8);

        let by_bytes = pool.intent_bytes_prefix(4, 7, usize::MAX);
        assert_eq!(by_bytes.len(), 1);
        assert_eq!(by_bytes[0].len(), 4);

        let per_tx_rejected = pool.intent_bytes_prefix(4, usize::MAX, 3);
        assert!(per_tx_rejected.is_empty());
    }

    #[test]
    fn missing_sync_drains_overlapping_pages_without_changing_caps() {
        use std::collections::BTreeSet;
        for count in [129, 256, 1024] {
            let mut pool = Mempool::new(count);
            for i in 0..count as u32 {
                let transaction = tx(2 * i + 1, 2 * i + 2, 10, i.wrapping_add(1) as u8, [9u8; 32]);
                let txid = id(&transaction);
                pool.admit(transaction, 0).unwrap();
                pool.set_intent_bytes(&txid, txid.0.to_vec());
            }
            let mut known = BTreeSet::new();
            // Include entries learned from a second peer before requesting
            // more from the first. Exclusion must not depend on map order.
            for txid in pool.entries.keys().take(count / 3) {
                known.insert(txid.0);
            }
            for _ in 0..count {
                let ids: Vec<_> = known.iter().copied().collect();
                let page = pool.intent_bytes_missing(&ids, 128, 128 * 32, 32);
                assert!(page.len() <= 128);
                if page.is_empty() {
                    break;
                }
                for bytes in page {
                    assert!(known.insert(bytes.try_into().unwrap()));
                }
            }
            assert_eq!(known.len(), count);
            assert!(pool
                .intent_bytes_missing(
                    &known.into_iter().collect::<Vec<_>>(),
                    128,
                    16 * 1024 * 1024,
                    32,
                )
                .is_empty());
        }
    }

    #[test]
    fn cached_authorization_is_a_borrowed_intent_suffix() {
        let mut pool = Mempool::new(1);
        let transaction = tx(1, 2, 10, 1, [9u8; 32]);
        let id = id(&transaction);
        pool.admit(transaction, 0).unwrap();
        let offset = paged_spend_authorization_wire_offset(1).unwrap();
        let mut intent = vec![0u8; offset];
        intent.extend_from_slice(&[0xA5; 64]);
        pool.set_intent_bytes(&id, intent);

        let entry = pool.get(&id).unwrap();
        let authorization = entry.cached_authorization().unwrap();
        assert_eq!(authorization, &[0xA5; 64]);
        assert_eq!(
            authorization.as_ptr(),
            entry.intent_bytes[offset..].as_ptr()
        );
    }
}
