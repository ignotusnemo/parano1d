// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! ParanoidReceipt — unforgeable proof of transaction inclusion.
//!
//! Reference for Merkle inclusion proof structure:
//!   Bitcoin Core `src/merkle.cpp` (transaction inclusion proofs).
//!   Grin `core/src/core/transaction.rs` (output Merkle paths).
//!
//! # Verification algorithm
//!
//! **Merkle inclusion** (offline): Poseidon2b COMPRESS binary tree.
//!   Must match `noid_chain::block::compute_tx_root` exactly.
//!   Poseidon2b is used because `tx_root` feeds the HistoryStep transition and
//!   must stay in the arithmetic consensus hash domain.
//! **Header lookup** (online): `getHeaderByHeight(claimed_height)` → check `tx_root`.
//! **Canonical-chain check** (online): compare the claimed root and timestamp
//! against the permanently retained header at `claimed_height`.

use crate::block_header::BlockHeader;
use crate::tx_tree;
use noid_poseidon2b::primitives::Address;
use noid_tx::{validate_paged_spend, PagedSpendIntent, Transaction, TxPage};

mod native;
mod trade;
pub use native::{native_receipt_details, native_receipt_for_group, NativeReceiptDetails};
pub use trade::{
    generate_trade_receipt, trade_receipt_details, trade_receipt_for_policy, TradeReceiptDetails,
};

const RECEIPT_CONSTRUCTION_MARKER: u8 = 0x02;
const NATIVE_RECEIPT_PAGES_MAGIC: &[u8; 4] = b"NPR1";

/// Compact summary of a transaction (public on-chain data only).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TxSummary {
    pub logical_txid: [u8; 32],
    pub inputs: Vec<(u32, Address)>,
    pub outputs: Vec<(u32, u64, Address)>,
    pub fee_micronoid: u64,
    pub confirmed_height: u64,
    pub confirmed_unix: u64,
}

/// Cryptographic proof that a transaction is in the canonical chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParanoidReceipt {
    /// Fixed construction marker. This is not a negotiable protocol version.
    pub construction_marker: u8,
    /// Canonical PagedSpend intent encoding with an empty authorization field.
    /// Its complete ordered page list derives the logical transaction leaf.
    pub paged_spend: Vec<u8>,
    /// Logical position in the universal namespace. Directions derive from it.
    pub tx_index: u16,
    /// Real logical count, including coinbase and any development payout.
    pub tx_count: u16,
    /// Sibling hashes along the Merkle path (leaf → root), always depth 8.
    pub merkle_path: [[u8; 32]; tx_tree::TX_TREE_DEPTH],
    pub claimed_root: [u8; 32],
    pub claimed_height: u64,
    pub summary: TxSummary,
}

impl ParanoidReceipt {
    /// Payload family used for typed wallet activity.
    pub fn is_trade(&self) -> bool {
        self.paged_spend.starts_with(trade::MAGIC)
    }

    pub fn is_native(&self) -> bool {
        self.paged_spend.starts_with(native::MAGIC)
    }

    /// Serialize to compact bincode bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("ParanoidReceipt serialize")
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptVerifyResult {
    pub merkle_valid: bool,
    pub canonical: Option<bool>,
    pub confirmed: bool,
}

impl ReceiptVerifyResult {
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }
}

/// Generate a receipt for a confirmed transaction.
pub fn generate_receipt(
    header: &BlockHeader,
    pages: &[Transaction],
    tx_index: usize,
    block_tx_hashes: &[[u8; 32]],
) -> ParanoidReceipt {
    let pages: Vec<_> = pages
        .iter()
        .map(|transaction| TxPage {
            body: transaction.body.clone(),
        })
        .collect();
    let native = pages
        .first()
        .is_some_and(|page| noid_tx::native_assets::wire::is_native_header(&page.body));
    let (encoded, logical_txid) = if native {
        let mut bytes = NATIVE_RECEIPT_PAGES_MAGIC.to_vec();
        let facts = noid_tx::native_assets::wire::encode_native_pages(&pages, &mut bytes)
            .expect("receipt source is one canonical native group");
        (bytes, facts.logical_txid.0)
    } else {
        let intent = PagedSpendIntent::new(pages.clone(), Vec::new())
            .expect("receipt source is one canonical PagedSpend group");
        (
            intent
                .to_bytes()
                .expect("canonical receipt PagedSpend encoding"),
            intent.logical_txid().0,
        )
    };
    assert_eq!(block_tx_hashes.get(tx_index), Some(&logical_txid));
    let merkle_path = tx_tree::path_from_hashes(block_tx_hashes, tx_index);
    let summary = summary_from_pages(&pages, header.height, header.timestamp);
    ParanoidReceipt {
        construction_marker: RECEIPT_CONSTRUCTION_MARKER,
        paged_spend: encoded,
        tx_index: tx_index as u16,
        tx_count: block_tx_hashes.len() as u16,
        merkle_path,
        claimed_root: header.tx_root,
        claimed_height: header.height,
        summary,
    }
}

/// Derive every payment-relevant summary field from the authenticated group.
pub fn summary_from_pages(
    pages: &[TxPage],
    confirmed_height: u64,
    confirmed_unix: u64,
) -> TxSummary {
    let (logical_txid, fee) = if pages
        .first()
        .is_some_and(|page| noid_tx::native_assets::wire::is_native_header(&page.body))
    {
        let facts = noid_tx::native_assets::wire::validate_native_pages(pages)
            .expect("summary source is canonical native pages");
        (facts.logical_txid.0, facts.fee)
    } else {
        let facts = validate_paged_spend(pages).expect("summary source is canonical PagedSpend");
        (facts.logical_txid.0, facts.fee)
    };
    TxSummary {
        logical_txid,
        inputs: pages
            .iter()
            .flat_map(|page| {
                page.body
                    .live_inputs()
                    .map(|(_, input)| (input.slot_index, page.body.input_owner))
            })
            .collect(),
        outputs: pages
            .iter()
            .flat_map(|page| {
                page.body
                    .live_outputs()
                    .map(|(_, output)| (output.slot_index, output.amount, output.owner))
            })
            .collect(),
        fee_micronoid: fee,
        confirmed_height,
        confirmed_unix,
    }
}

/// Verify Merkle inclusion (offline). Returns true iff tx is in claimed_root.
///
/// Also checks summary_hash so an attacker cannot forge payment data
/// (amounts, addresses) while keeping the Merkle proof valid.
///
/// Uses Poseidon2b COMPRESS to match `compute_tx_root` in `noid_chain::block`.
pub fn verify_merkle_inclusion(receipt: &ParanoidReceipt) -> bool {
    if receipt.construction_marker != RECEIPT_CONSTRUCTION_MARKER {
        return false;
    }
    if receipt.paged_spend.starts_with(trade::MAGIC) {
        return trade::check_receipt(receipt).is_some();
    }
    if receipt.is_native() {
        return native::check_receipt(receipt).is_some();
    }
    let (pages, logical_txid) = if receipt.paged_spend.starts_with(NATIVE_RECEIPT_PAGES_MAGIC) {
        if !crate::consensus::params::v2_1_active(receipt.claimed_height) {
            return false;
        }
        let mut bytes = &receipt.paged_spend[NATIVE_RECEIPT_PAGES_MAGIC.len()..];
        let Ok((pages, facts)) = noid_tx::native_assets::wire::decode_native_pages(&mut bytes)
        else {
            return false;
        };
        if !bytes.is_empty() || facts.chain != crate::state::native_assets::native_chain_id() {
            return false;
        }
        (pages, facts.logical_txid.0)
    } else {
        let Ok(intent) = PagedSpendIntent::from_bytes(&receipt.paged_spend) else {
            return false;
        };
        if !intent.authorization_bytes.is_empty() {
            return false;
        }
        let logical_txid = intent.logical_txid().0;
        (intent.pages, logical_txid)
    };
    let expected_summary = summary_from_pages(
        &pages,
        receipt.claimed_height,
        receipt.summary.confirmed_unix,
    );
    if receipt.summary != expected_summary {
        return false;
    }

    // Fixed-depth Merkle path plus the header's real-count wrapper.
    tx_tree::verify_path(
        logical_txid,
        &receipt.merkle_path,
        usize::from(receipt.tx_index),
        usize::from(receipt.tx_count),
        receipt.claimed_root,
    )
}

/// Verify receipt against a canonical header (online step).
pub fn verify_against_header(receipt: &ParanoidReceipt, canonical_header: &BlockHeader) -> bool {
    canonical_header.height == receipt.claimed_height
        && canonical_header.tx_root == receipt.claimed_root
        && canonical_header.timestamp == receipt.summary.confirmed_unix
        && (!receipt.paged_spend.starts_with(trade::MAGIC)
            || trade::claimed_header(&receipt.paged_spend)
                .is_ok_and(|header| header == *canonical_header))
        && (!receipt.is_native()
            || native::claimed_header(&receipt.paged_spend)
                .is_ok_and(|header| header == *canonical_header))
}

/// Compute the tx_root from a list of canonical logical leaf hashes.
/// Mirrors `compute_tx_root` in `noid_chain::block`.
pub fn tx_root(tx_hashes: &[[u8; 32]]) -> [u8; 32] {
    tx_tree::root_from_hashes(tx_hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::params::GENESIS_TARGET;
    use noid_tx::{
        output_bitmap_bit, TxBody, TxInput, TxOutput, PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT,
        TX_INPUTS, TX_OUTPUTS,
    };

    fn one_page(index: u16) -> Transaction {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: u32::from(index) + 1,
            amount: u64::from(index) + 10,
            creation_id: 1,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: u32::from(index) + 1_000,
            amount: u64::from(index) + 9,
            owner: Address([2u8; 32]),
        };
        let mut anchor = [0u8; 32];
        anchor[..2].copy_from_slice(&index.to_le_bytes());
        anchor[2] = 1;
        Transaction::new(TxBody {
            epoch_anchor: anchor,
            fee: 1,
            input_owner: Address([1u8; 32]),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0) | PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        })
    }

    fn two_page_group() -> Vec<Transaction> {
        let mut first_inputs = [TxInput::dummy(); TX_INPUTS];
        for (index, input) in first_inputs.iter_mut().enumerate() {
            *input = TxInput {
                slot_index: index as u32 + 1,
                amount: 10,
                creation_id: index as u64 + 1,
            };
        }
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 1_000,
            amount: 89,
            owner: Address([2u8; 32]),
        };
        let first = Transaction::new(TxBody {
            epoch_anchor: [7u8; 32],
            fee: 1,
            input_owner: Address([1u8; 32]),
            inputs: first_inputs,
            outputs,
            validity_bitmap: ((1u16 << TX_INPUTS) - 1)
                | output_bitmap_bit(0)
                | PAGED_SPEND_START_BIT,
            is_coinbase: false,
        });
        let mut final_inputs = [TxInput::dummy(); TX_INPUTS];
        final_inputs[0] = TxInput {
            slot_index: 9,
            amount: 10,
            creation_id: 9,
        };
        let last = Transaction::new(TxBody {
            epoch_anchor: [7u8; 32],
            fee: 0,
            input_owner: Address([1u8; 32]),
            inputs: final_inputs,
            outputs: [TxOutput::dummy(); TX_OUTPUTS],
            validity_bitmap: 1 | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        });
        vec![first, last]
    }

    fn header(height: u64, root: [u8; 32]) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: [0u8; 32],
            tx_root: root,
            timestamp: 1_700_000_000,
            height,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    #[test]
    fn all_255_user_positions_have_authenticated_fixed_paths() {
        let groups: Vec<_> = (0..255).map(one_page).collect();
        let hashes: Vec<_> = std::iter::once([0xCB; 32])
            .chain(groups.iter().map(|transaction| {
                validate_paged_spend(&[TxPage {
                    body: transaction.body.clone(),
                }])
                .unwrap()
                .logical_txid
                .0
            }))
            .collect();
        let header = header(10, tx_root(&hashes));
        for (index, transaction) in groups.iter().enumerate() {
            let receipt = generate_receipt(
                &header,
                std::slice::from_ref(transaction),
                index + 1,
                &hashes,
            );
            assert_eq!(receipt.merkle_path.len(), 8);
            assert!(verify_merkle_inclusion(&receipt), "index {index}");
            assert!(verify_against_header(&receipt, &header));
            assert_eq!(
                ParanoidReceipt::from_bytes(&receipt.to_bytes())
                    .unwrap()
                    .paged_spend,
                receipt.paged_spend
            );
        }
    }

    #[test]
    fn multipage_summary_count_index_and_header_tamper_fail() {
        let group = two_page_group();
        let pages: Vec<_> = group
            .iter()
            .map(|transaction| TxPage {
                body: transaction.body.clone(),
            })
            .collect();
        let logical_txid = validate_paged_spend(&pages).unwrap().logical_txid.0;
        let hashes = [[0xCB; 32], logical_txid];
        let header = header(5, tx_root(&hashes));
        let receipt = generate_receipt(&header, &group, 1, &hashes);
        assert_eq!(receipt.summary.inputs.len(), 9);
        assert_eq!(receipt.summary.outputs.len(), 1);
        assert!(verify_merkle_inclusion(&receipt));

        let mut bad = receipt.clone();
        bad.paged_spend[80] ^= 1;
        assert!(!verify_merkle_inclusion(&bad));

        let mut bad = receipt.clone();
        bad.summary.outputs[0].1 += 1;
        assert!(!verify_merkle_inclusion(&bad));

        let mut bad = receipt.clone();
        bad.tx_count = 1;
        assert!(!verify_merkle_inclusion(&bad));

        let mut bad = receipt.clone();
        bad.tx_index = 2;
        assert!(!verify_merkle_inclusion(&bad));

        let mut other_header = header;
        other_header.timestamp += 1;
        assert!(!verify_against_header(&receipt, &other_header));
    }

    #[test]
    fn real_count_is_bound_even_with_zero_suffix() {
        let hashes = [[1u8; 32], [2u8; 32]];
        assert_ne!(tx_root(&hashes[..1]), tx_root(&hashes));
        assert_eq!(tx_root(&[]), [0u8; 32]);
    }
}
