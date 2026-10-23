// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Holder-retained transition receipt. Verification needs the selected-chain
//! header, the pinned v2 bank and its authenticated fork origin.
//! It never treats a self-declared header or object opening as chain validity.

use noid_chain::{Block, BlockHeader};
use noid_tx::{
    experimental_object::{CheckedTransition, ObjectOpening, OPENING_BYTES},
    TxPage,
};

const MAGIC: &[u8; 8] = b"O1OBJRC4";
const DESCENDANT_MAGIC: &[u8; 8] = b"O1OBJRC5";
const HEADER_BYTES: usize = noid_chain::wire::BLOCK_HEADER_WIRE_SIZE;
const PATH_BYTES: usize = 32 * noid_chain::tx_tree::TX_TREE_DEPTH;
pub const FIXED_BYTES: usize =
    8 + OPENING_BYTES + noid_tx::TX_BODY_WIRE_SIZE + 2 * HEADER_BYTES + 2 + 2 + PATH_BYTES + 4;
/// A receiver may accept several bodies under one later recursive terminal.
/// The holder retains their short, hash-linked ancestry alongside that proof.
pub const MAX_RECEIPT_DESCENDANTS: usize =
    noid_chain::consensus::params::RETAINED_BLOCK_SERVING_DEPTH as usize;
pub const MAX_RECEIPT_BYTES: usize = FIXED_BYTES
    + 2
    + MAX_RECEIPT_DESCENDANTS * HEADER_BYTES
    + noid_chain::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES;

#[derive(Clone, Debug)]
pub struct ObjectTransitionReceipt {
    pub opening: ObjectOpening,
    pub page: TxPage,
    pub header: BlockHeader,
    pub epoch_anchor_header: BlockHeader,
    pub tx_index: u16,
    pub tx_count: u16,
    pub path: [[u8; 32]; noid_chain::tx_tree::TX_TREE_DEPTH],
    /// Empty when the terminal proves the call block itself. Otherwise these
    /// sealed headers link the call block to the terminal's later boundary.
    pub descendants: Vec<BlockHeader>,
    pub terminal: Vec<u8>,
}

impl ObjectTransitionReceipt {
    pub fn from_block(
        block: &Block,
        logical_user_index: usize,
        opening: ObjectOpening,
        epoch_anchor_header: BlockHeader,
        terminal: Vec<u8>,
    ) -> Result<Self, String> {
        let stream = noid_chain::block::native_assets::validate_scheduled_block_page_stream(
            &block.transactions,
            block.header.height,
        )
        .map_err(|e| e.to_string())?;
        let group = stream
            .groups()
            .nth(logical_user_index)
            .ok_or("receipt group index")?;
        if group.page_count != 1 {
            return Err("receipt requires a single contract-prefix page".into());
        }
        // Every preceding contract is a one-page group; checked adapter binds
        // this partition again when building the proof.
        let page = TxPage {
            body: block.transactions[group.body_start].body.clone(),
        };
        let ids: Vec<_> = noid_chain::block::native_assets::try_compute_logical_txids_at(
            &block.transactions,
            block.header.height,
        )
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|id| id.0)
        .collect();
        let tx_index = stream.user_start_index() + logical_user_index;
        let receipt = Self {
            opening,
            page,
            header: block.header,
            epoch_anchor_header,
            tx_index: u16::try_from(tx_index).map_err(|_| "receipt index overflow")?,
            tx_count: u16::try_from(ids.len()).map_err(|_| "receipt count overflow")?,
            path: noid_chain::tx_tree::path_from_hashes(&ids, tx_index),
            descendants: Vec::new(),
            terminal,
        };
        receipt.check_inclusion()?;
        receipt.check_size()?;
        Ok(receipt)
    }

    fn check_size(&self) -> Result<(), String> {
        if self.terminal.is_empty()
            || self.terminal.len()
                > noid_chain::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES
        {
            return Err("receipt terminal length".into());
        }
        self.proof_header()?;
        Ok(())
    }

    pub fn proof_header(&self) -> Result<&BlockHeader, String> {
        if self.descendants.len() > MAX_RECEIPT_DESCENDANTS {
            return Err("receipt ancestry length".into());
        }
        let mut parent = &self.header;
        for child in &self.descendants {
            if parent.height.checked_add(1) != Some(child.height)
                || child.prev_block_hash != noid_chain::block_id(parent)
            {
                return Err("receipt ancestry does not link to the call block".into());
            }
            noid_chain::consensus::pow::validate_pow(child)
                .map_err(|e| format!("receipt descendant proof of work: {e:?}"))?;
            parent = child;
        }
        Ok(parent)
    }

    fn check_inclusion(&self) -> Result<CheckedTransition, String> {
        if !noid_chain::consensus::params::v2_active(self.header.height) {
            return Err("contract receipt predates v2 activation".into());
        }
        let checked = self
            .opening
            .check_call(&self.page, self.header.height)
            .map_err(|e| e.to_string())?;
        let id = noid_tx::hash_paged_spend(std::slice::from_ref(&self.page))
            .map_err(|e| e.to_string())?;
        if !noid_chain::tx_tree::verify_path(
            id.0,
            &self.path,
            usize::from(self.tx_index),
            usize::from(self.tx_count),
            self.header.tx_root,
        ) {
            return Err("receipt transaction inclusion".into());
        }
        Ok(checked)
    }

    /// Verify a scheduled v2 transition after its original block body has
    /// been discarded. The authenticated fork origin is required alongside
    /// the selected new runtime; receipt metadata cannot supply that authority.
    pub fn verify_v2(
        &self,
        runtime: &noid_recursive::acceptance::history_step::v2::banked::Runtime,
        origin: &noid_recursive::acceptance::history_step::v2::banked::VerifiedOrigin,
        canonical_header: &BlockHeader,
    ) -> Result<CheckedTransition, String> {
        use noid_recursive::acceptance::history_step::v2::banked as v2;
        self.check_size()?;
        if &self.header != canonical_header {
            return Err("receipt is not on the selected chain".into());
        }
        let checked = self.check_inclusion()?;
        let terminal = v2::decode_terminal(runtime, &self.terminal).map_err(|e| e.to_string())?;
        let proof_header = self.proof_header()?;
        let accepted = v2::verify_terminal(
            runtime,
            origin,
            &terminal,
            proof_header,
            &self.epoch_anchor_header,
        )
        .map_err(|e| e.to_string())?;
        if accepted.accumulator().state_root != proof_header.state_root {
            return Err("receipt State boundary".into());
        }
        Ok(checked)
    }

    pub fn verify_with_terminal(
        &self,
        canonical_header: &BlockHeader,
        verify: impl FnOnce(&[u8], &BlockHeader, &BlockHeader) -> Result<(), String>,
    ) -> Result<CheckedTransition, String> {
        self.check_size()?;
        if &self.header != canonical_header {
            return Err("receipt is not on the selected chain".into());
        }
        let checked = self.check_inclusion()?;
        verify(
            &self.terminal,
            self.proof_header()?,
            &self.epoch_anchor_header,
        )?;
        Ok(checked)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        self.check_size()?;
        self.check_inclusion()?;
        let extended = !self.descendants.is_empty();
        let mut bytes = Vec::with_capacity(
            FIXED_BYTES
                + self.terminal.len()
                + self.descendants.len() * HEADER_BYTES
                + usize::from(extended) * 2,
        );
        bytes.extend_from_slice(if extended { DESCENDANT_MAGIC } else { MAGIC });
        bytes.extend_from_slice(&self.opening.to_bytes().map_err(|e| e.to_string())?);
        bytes.extend_from_slice(&self.page.to_bytes().map_err(|e| e.to_string())?);
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.epoch_anchor_header.to_bytes());
        bytes.extend_from_slice(&self.tx_index.to_le_bytes());
        bytes.extend_from_slice(&self.tx_count.to_le_bytes());
        for sibling in self.path {
            bytes.extend_from_slice(&sibling);
        }
        if extended {
            bytes.extend_from_slice(&(self.descendants.len() as u16).to_le_bytes());
            for header in &self.descendants {
                bytes.extend_from_slice(&header.to_bytes());
            }
        }
        bytes.extend_from_slice(&(self.terminal.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.terminal);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() <= FIXED_BYTES
            || bytes.len() > MAX_RECEIPT_BYTES
            || (!bytes.starts_with(MAGIC) && !bytes.starts_with(DESCENDANT_MAGIC))
        {
            return Err("receipt encoding length or marker".into());
        }
        let count = if bytes.starts_with(DESCENDANT_MAGIC) {
            let count =
                u16::from_le_bytes(bytes[FIXED_BYTES - 4..FIXED_BYTES - 2].try_into().unwrap())
                    as usize;
            if count == 0 || count > MAX_RECEIPT_DESCENDANTS {
                return Err("receipt ancestry length".into());
            }
            count
        } else {
            0
        };
        let prefix = FIXED_BYTES
            + if count == 0 {
                0
            } else {
                2 + count * HEADER_BYTES
            };
        if bytes.len() <= prefix {
            return Err("receipt ancestry truncated".into());
        }
        let len = u32::from_le_bytes(bytes[prefix - 4..prefix].try_into().unwrap()) as usize;
        if len != bytes.len() - prefix
            || len > noid_chain::consensus::wire_limits::MAX_HISTORY_STEP_TERMINAL_TRANSPORT_BYTES
        {
            return Err("receipt terminal framing".into());
        }
        let mut at = 8;
        let mut take = |count: usize| {
            let out = &bytes[at..at + count];
            at += count;
            out
        };
        let opening = ObjectOpening::from_bytes(take(OPENING_BYTES)).map_err(|e| e.to_string())?;
        let page =
            TxPage::from_bytes(take(noid_tx::TX_BODY_WIRE_SIZE)).map_err(|e| e.to_string())?;
        let header = BlockHeader::from_bytes(take(HEADER_BYTES))
            .map_err(|e| format!("receipt header: {e:?}"))?;
        let epoch_anchor_header = BlockHeader::from_bytes(take(HEADER_BYTES))
            .map_err(|e| format!("receipt anchor: {e:?}"))?;
        let tx_index = u16::from_le_bytes(take(2).try_into().unwrap());
        let tx_count = u16::from_le_bytes(take(2).try_into().unwrap());
        let path = std::array::from_fn(|_| take(32).try_into().unwrap());
        let descendants = if count == 0 {
            Vec::new()
        } else {
            take(2);
            (0..count)
                .map(|_| {
                    BlockHeader::from_bytes(take(HEADER_BYTES))
                        .map_err(|e| format!("receipt descendant: {e:?}"))
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        let receipt = Self {
            opening,
            page,
            header,
            epoch_anchor_header,
            tx_index,
            tx_count,
            path,
            descendants,
            terminal: bytes[prefix..].to_vec(),
        };
        receipt.check_size()?;
        receipt.check_inclusion()?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{experimental_object::applications, Transaction, TxBody, TxInput, TxOutput};

    // Framing/inclusion fixture only. Its deliberately invalid terminal must
    // never be mistaken for proof authority; real verification is separate.
    fn fixture() -> ObjectTransitionReceipt {
        let height = noid_chain::consensus::params::V2_ACTIVATION_HEIGHT.unwrap();
        let owner = Address([7; 32]);
        let opening = applications::timelocked_vault(owner, 0, 5);
        let mut coinbase = TxBody {
            epoch_anchor: [0; 32],
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); noid_tx::TX_INPUTS],
            outputs: [TxOutput::dummy(); noid_tx::TX_OUTPUTS],
            validity_bitmap: noid_tx::output_bitmap_bit(0),
            is_coinbase: true,
        };
        coinbase.outputs[0] = TxOutput {
            slot_index: 0,
            amount: 16_000_000,
            owner,
        };
        let mut transactions = vec![Transaction::new(coinbase)];
        for index in 0..63 {
            let call = opening
                .build_call(
                    TxInput {
                        slot_index: index + 1,
                        amount: 1001,
                        creation_id: u64::from(index) + 1,
                    },
                    index + 100,
                    1,
                    [0; 32],
                    height,
                    true,
                )
                .unwrap();
            transactions.push(Transaction::new(call.body));
        }
        let epoch = noid_chain::consensus::genesis_header();
        let mut header = epoch;
        header.height = height;
        header.difficulty_target = [0xff; 32];
        header.tx_root = noid_chain::block::compute_tx_root(&transactions);
        let block = Block {
            header,
            transactions,
        };
        ObjectTransitionReceipt::from_block(&block, 62, opening, epoch, b"not-a-proof".to_vec())
            .unwrap()
    }

    #[test]
    fn last_full_small_call_has_a_bounded_round_trip_after_position_sixteen() {
        let receipt = fixture();
        assert_eq!(receipt.tx_index, 63);
        assert_eq!(receipt.tx_count, 64);
        let bytes = receipt.to_bytes().unwrap();
        let decoded = ObjectTransitionReceipt::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), bytes);
        assert!(decoded.check_inclusion().unwrap().terminal);
        for length in [0, 7, FIXED_BYTES - 1, FIXED_BYTES, bytes.len() - 1] {
            assert!(ObjectTransitionReceipt::from_bytes(&bytes[..length]).is_err());
        }
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(ObjectTransitionReceipt::from_bytes(&extended).is_err());
        let mut old = bytes;
        old[7] = b'2';
        assert!(ObjectTransitionReceipt::from_bytes(&old).is_err());
    }

    #[test]
    fn receipt_binds_the_opening_body_position_and_merkle_path() {
        let original = fixture();
        for mutation in 0..6 {
            let mut bad = original.clone();
            match mutation {
                0 => bad.opening.state.0 ^= 1,
                1 => bad.page.body.fee += 1,
                2 => bad.tx_index = 0,
                3 => bad.tx_count = 63,
                4 => bad.path[0][0] ^= 1,
                5 => {
                    bad.header.height =
                        noid_chain::consensus::params::V2_ACTIVATION_HEIGHT.unwrap() - 1
                }
                _ => unreachable!(),
            }
            assert!(bad.to_bytes().is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn receipt_descendants_are_bounded_and_hash_linked_to_the_proof_boundary() {
        let mut receipt = fixture();
        let mut parent = receipt.header;
        for _ in 0..2 {
            let mut child = parent;
            child.height += 1;
            child.prev_block_hash = noid_chain::block_id(&parent);
            receipt.descendants.push(child);
            parent = child;
        }
        let bytes = receipt.to_bytes().unwrap();
        let decoded = ObjectTransitionReceipt::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.proof_header().unwrap(), &parent);
        assert_eq!(decoded.to_bytes().unwrap(), bytes);
        let mut bad = receipt.clone();
        bad.descendants[0].prev_block_hash[0] ^= 1;
        assert!(bad.to_bytes().is_err());
        let mut bad = receipt.clone();
        bad.descendants[1].height += 1;
        assert!(bad.to_bytes().is_err());
        receipt.descendants = vec![parent; MAX_RECEIPT_DESCENDANTS + 1];
        assert!(receipt.to_bytes().is_err());
    }
}
