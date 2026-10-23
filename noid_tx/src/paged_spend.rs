// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical multi-page transaction primitive.
//!
//! A [`TxPage`] has exactly the existing 323-byte Tx8x2 body encoding. Bits
//! 10 and 11 delimit one atomic logical transaction. The research v2 carrier
//! reserves bits 12 and 13 for contract and terminal-object selection without
//! changing the fixed 323-byte Tx8x2 encoding. Page-local validation
//! checks representation invariants; group-wide validation checks density,
//! balance, ownership and the logical transaction id.

use std::collections::HashSet;

use noid_core::Block128;
use noid_poseidon2b::native::{capacity_iv, DomainTag, Poseidon2bSponge};
use noid_poseidon2b::primitives::{Address, Digest, TxBodyHash};

use crate::{
    TxBody, TxInput, TxOutput, WireError, TX_BODY_WIRE_SIZE, TX_INPUTS, TX_OUTPUTS,
    TX_VALIDITY_MASK,
};

const TAG_PAGED_SPEND: DomainTag = DomainTag::new(b"PAGEDTX_");

pub const PAGED_SPEND_VERSION: u16 = 1;
pub const MAX_TX_AUTHORIZATION_BYTES: usize = 256 * 1024;
pub const PAGED_SPEND_START_BIT: u16 = 1 << 10;
pub const PAGED_SPEND_END_BIT: u16 = 1 << 11;
/// Research-v2 proof-native object call. This is hash-bound by the existing
/// validity-bitmap leaf and deliberately remains outside the v1 standalone
/// `TxBody` canonical mask.
pub const PAGED_SPEND_CONTRACT_BIT: u16 = 1 << 12;
/// Selects a terminal object transition. Meaningful only together with
/// [`PAGED_SPEND_CONTRACT_BIT`].
pub const PAGED_SPEND_TERMINAL_BIT: u16 = 1 << 13;
pub const PAGED_SPEND_MARKER_MASK: u16 = PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT;
pub const PAGED_SPEND_V2_CONTRACT_MASK: u16 = PAGED_SPEND_CONTRACT_BIT | PAGED_SPEND_TERMINAL_BIT;
pub const PAGED_SPEND_VALIDITY_MASK: u16 =
    TX_VALIDITY_MASK | PAGED_SPEND_MARKER_MASK | PAGED_SPEND_V2_CONTRACT_MASK;

pub const MAX_PAGED_SPEND_PAGES: usize = 128;
pub const MAX_PAGED_SPEND_INPUTS: usize = 1_020;
pub const MAX_PAGED_SPEND_OUTPUTS: usize = MAX_PAGED_SPEND_PAGES * TX_OUTPUTS;

pub const PAGED_SPEND_INTENT_MARKER: u8 = 0xA3;
pub const PAGED_SPEND_INTENT_FIXED_OVERHEAD: usize = 1 + 2 + 4;
pub const MAX_PAGED_SPEND_INTENT_BYTES: usize = PAGED_SPEND_INTENT_FIXED_OVERHEAD
    + MAX_PAGED_SPEND_PAGES * TX_BODY_WIRE_SIZE
    + MAX_TX_AUTHORIZATION_BYTES;

const _: () = assert!(MAX_PAGED_SPEND_INPUTS <= MAX_PAGED_SPEND_PAGES * TX_INPUTS);
const _: () = assert!(MAX_PAGED_SPEND_OUTPUTS == 256);
const _: () = assert!(MAX_PAGED_SPEND_PAGES <= u16::MAX as usize);
const _: () = assert!(MAX_PAGED_SPEND_INTENT_BYTES == 303_495);

/// One physical Tx8x2 page. The body is public for direct action/exact-state
/// reuse, but every boundary revalidates it because callers may mutate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxPage {
    pub body: TxBody,
}

impl TxPage {
    pub fn new(body: TxBody) -> Result<Self, PagedSpendError> {
        validate_page_shape(&body, 0)?;
        Ok(Self { body })
    }

    #[inline]
    pub fn is_start(&self) -> bool {
        self.body.validity_bitmap & PAGED_SPEND_START_BIT != 0
    }

    #[inline]
    pub fn is_end(&self) -> bool {
        self.body.validity_bitmap & PAGED_SPEND_END_BIT != 0
    }

    #[inline]
    pub fn page_hash(&self) -> TxBodyHash {
        self.body.txid()
    }

    pub fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), PagedSpendError> {
        validate_page_shape(&self.body, 0)?;
        encode_page_body(&self.body, bytes);
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<[u8; TX_BODY_WIRE_SIZE], PagedSpendError> {
        let mut bytes = Vec::with_capacity(TX_BODY_WIRE_SIZE);
        self.encode(&mut bytes)?;
        Ok(bytes
            .try_into()
            .unwrap_or_else(|_| unreachable!("TxPage retains the fixed Tx8x2 wire")))
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, PagedSpendError> {
        let body = decode_page_body(src)?;
        Self::new(body)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PagedSpendError> {
        if bytes.len() != TX_BODY_WIRE_SIZE {
            return Err(PagedSpendError::Wire(if bytes.len() < TX_BODY_WIRE_SIZE {
                WireError::Truncated
            } else {
                WireError::TrailingBytes
            }));
        }
        let mut src = bytes;
        let page = Self::decode(&mut src)?;
        debug_assert!(src.is_empty());
        Ok(page)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagedSpendFacts {
    pub logical_txid: TxBodyHash,
    pub input_owner: Address,
    pub epoch_anchor: Digest,
    pub fee: u64,
    pub live_inputs: u16,
    pub live_outputs: u16,
    pub input_sum: u128,
    pub output_sum: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalPagedSpendAuth {
    pub logical_txid: TxBodyHash,
    pub input_owner: Address,
}

/// One indivisible mempool/relay object with exactly one detached capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagedSpendIntent {
    pub pages: Vec<TxPage>,
    pub authorization_bytes: Vec<u8>,
}

impl PagedSpendIntent {
    pub fn new(pages: Vec<TxPage>, authorization_bytes: Vec<u8>) -> Result<Self, PagedSpendError> {
        validate_paged_spend(&pages)?;
        if authorization_bytes.len() > MAX_TX_AUTHORIZATION_BYTES {
            return Err(PagedSpendError::AuthorizationTooLarge {
                actual: authorization_bytes.len(),
            });
        }
        Ok(Self {
            pages,
            authorization_bytes,
        })
    }

    #[inline]
    pub fn logical_txid(&self) -> TxBodyHash {
        hash_paged_spend_unchecked(&self.pages)
    }

    /// Byte offset of the detached authorization payload in the canonical
    /// encoded intent. Mempool storage uses this to borrow the proof from the
    /// one retained wire allocation instead of keeping a second copy.
    pub fn authorization_wire_offset(&self) -> Result<usize, PagedSpendError> {
        paged_spend_authorization_wire_offset(self.pages.len())
    }

    pub fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), PagedSpendError> {
        validate_paged_spend(&self.pages)?;
        if self.authorization_bytes.len() > MAX_TX_AUTHORIZATION_BYTES {
            return Err(PagedSpendError::AuthorizationTooLarge {
                actual: self.authorization_bytes.len(),
            });
        }
        bytes.push(PAGED_SPEND_INTENT_MARKER);
        bytes.extend_from_slice(&(self.pages.len() as u16).to_le_bytes());
        for page in &self.pages {
            page.encode(bytes)?;
        }
        let authorization_len = u32::try_from(self.authorization_bytes.len())
            .map_err(|_| PagedSpendError::Wire(WireError::LengthOverflow))?;
        bytes.extend_from_slice(&authorization_len.to_le_bytes());
        bytes.extend_from_slice(&self.authorization_bytes);
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, PagedSpendError> {
        let mut bytes = Vec::with_capacity(
            PAGED_SPEND_INTENT_FIXED_OVERHEAD
                + self.pages.len() * TX_BODY_WIRE_SIZE
                + self.authorization_bytes.len(),
        );
        self.encode(&mut bytes)?;
        Ok(bytes)
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, PagedSpendError> {
        let marker = take(src, 1)?[0];
        if marker != PAGED_SPEND_INTENT_MARKER {
            return Err(PagedSpendError::Wire(WireError::BadMarker));
        }
        let page_count = take_u16(src)? as usize;
        validate_page_count(page_count)?;
        let required_page_bytes = page_count
            .checked_mul(TX_BODY_WIRE_SIZE)
            .ok_or(PagedSpendError::Wire(WireError::LengthOverflow))?;
        if src.len() < required_page_bytes {
            return Err(PagedSpendError::Wire(WireError::Truncated));
        }
        let mut pages = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            pages.push(TxPage::decode(src)?);
        }
        let authorization_len = take_u32(src)? as usize;
        if authorization_len > MAX_TX_AUTHORIZATION_BYTES {
            return Err(PagedSpendError::AuthorizationTooLarge {
                actual: authorization_len,
            });
        }
        let authorization_bytes = take(src, authorization_len)?.to_vec();
        Self::new(pages, authorization_bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PagedSpendError> {
        if bytes.len() > MAX_PAGED_SPEND_INTENT_BYTES {
            return Err(PagedSpendError::IntentTooLarge {
                actual: bytes.len(),
            });
        }
        let mut src = bytes;
        let intent = Self::decode(&mut src)?;
        if !src.is_empty() {
            return Err(PagedSpendError::Wire(WireError::TrailingBytes));
        }
        Ok(intent)
    }
}

/// Canonical byte offset of the authorization payload for `page_count`
/// physical pages: marker + count + pages + authorization length.
pub fn paged_spend_authorization_wire_offset(page_count: usize) -> Result<usize, PagedSpendError> {
    validate_page_count(page_count)?;
    page_count
        .checked_mul(TX_BODY_WIRE_SIZE)
        .and_then(|page_bytes| (1usize + 2).checked_add(page_bytes))
        .and_then(|prefix| prefix.checked_add(4))
        .ok_or(PagedSpendError::Wire(WireError::LengthOverflow))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PagedSpendError {
    Wire(WireError),
    PageCount {
        actual: usize,
    },
    ReservedBitmapBits {
        page: usize,
        bitmap: u16,
    },
    CoinbasePage {
        page: usize,
    },
    DeadInputNotZero {
        page: usize,
        slot: usize,
    },
    DeadOutputNotZero {
        page: usize,
        slot: usize,
    },
    MissingStart,
    UnexpectedStart {
        page: usize,
    },
    MissingEnd,
    UnexpectedEnd {
        page: usize,
    },
    OwnerMismatch {
        page: usize,
    },
    EpochMismatch {
        page: usize,
    },
    ContinuationFee {
        page: usize,
    },
    SparseInputs {
        page: usize,
        slot: usize,
    },
    SparseOutputs {
        page: usize,
        slot: usize,
    },
    NoLiveInputs,
    TooManyInputs {
        actual: usize,
    },
    TooManyOutputs {
        actual: usize,
    },
    NonMinimalPageCount {
        actual: usize,
        required: usize,
    },
    DuplicateInputSlot {
        slot: u32,
    },
    DuplicateOutputSlot {
        slot: u32,
    },
    InputOutputSlotOverlap {
        slot: u32,
    },
    InputSumOverflow,
    OutputSumOverflow,
    OutputPlusFeeOverflow,
    BalanceMismatch {
        input_sum: u128,
        output_sum: u128,
        fee: u64,
    },
    AuthorizationTooLarge {
        actual: usize,
    },
    IntentTooLarge {
        actual: usize,
    },
}

impl std::fmt::Display for PagedSpendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for PagedSpendError {}

impl From<WireError> for PagedSpendError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

pub fn hash_paged_spend(pages: &[TxPage]) -> Result<TxBodyHash, PagedSpendError> {
    validate_paged_spend(pages)?;
    Ok(hash_paged_spend_unchecked(pages))
}

pub(crate) fn hash_paged_spend_unchecked(pages: &[TxPage]) -> TxBodyHash {
    debug_assert!(!pages.is_empty() && pages.len() <= MAX_PAGED_SPEND_PAGES);
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_PAGED_SPEND));
    sponge.absorb_pair(
        Block128::from(PAGED_SPEND_VERSION as u128),
        Block128::from(pages.len() as u128),
    );
    for page in pages {
        let [low, high] = page.page_hash().as_fields();
        sponge.absorb_pair(low, high);
    }
    TxBodyHash(sponge.finalize())
}

pub fn canonical_paged_spend_auth(
    pages: &[TxPage],
) -> Result<CanonicalPagedSpendAuth, PagedSpendError> {
    let facts = validate_paged_spend(pages)?;
    Ok(CanonicalPagedSpendAuth {
        logical_txid: facts.logical_txid,
        input_owner: facts.input_owner,
    })
}

pub fn validate_paged_spend(pages: &[TxPage]) -> Result<PagedSpendFacts, PagedSpendError> {
    validate_page_count(pages.len())?;
    for (page_index, page) in pages.iter().enumerate() {
        validate_page_shape(&page.body, page_index)?;
    }
    if !pages[0].is_start() {
        return Err(PagedSpendError::MissingStart);
    }
    if !pages[pages.len() - 1].is_end() {
        return Err(PagedSpendError::MissingEnd);
    }
    for (page_index, page) in pages.iter().enumerate() {
        if page_index != 0 && page.is_start() {
            return Err(PagedSpendError::UnexpectedStart { page: page_index });
        }
        if page_index + 1 != pages.len() && page.is_end() {
            return Err(PagedSpendError::UnexpectedEnd { page: page_index });
        }
        if page.body.input_owner != pages[0].body.input_owner {
            return Err(PagedSpendError::OwnerMismatch { page: page_index });
        }
        if page.body.epoch_anchor != pages[0].body.epoch_anchor {
            return Err(PagedSpendError::EpochMismatch { page: page_index });
        }
        if page_index != 0 && page.body.fee != 0 {
            return Err(PagedSpendError::ContinuationFee { page: page_index });
        }
    }

    let mut input_slots = HashSet::with_capacity(MAX_PAGED_SPEND_INPUTS);
    let mut output_slots = HashSet::with_capacity(MAX_PAGED_SPEND_OUTPUTS);
    let mut live_inputs = 0usize;
    let mut live_outputs = 0usize;
    let mut input_sum = 0u128;
    let mut output_sum = 0u128;
    let mut input_gap = false;
    let mut output_gap = false;

    for (page_index, page) in pages.iter().enumerate() {
        for (slot, input) in page.body.inputs.iter().enumerate() {
            if page.body.input_is_live(slot) {
                if input_gap {
                    return Err(PagedSpendError::SparseInputs {
                        page: page_index,
                        slot,
                    });
                }
                live_inputs += 1;
                if live_inputs > MAX_PAGED_SPEND_INPUTS {
                    return Err(PagedSpendError::TooManyInputs {
                        actual: live_inputs,
                    });
                }
                if !input_slots.insert(input.slot_index) {
                    return Err(PagedSpendError::DuplicateInputSlot {
                        slot: input.slot_index,
                    });
                }
                input_sum = input_sum
                    .checked_add(input.amount as u128)
                    .ok_or(PagedSpendError::InputSumOverflow)?;
            } else {
                input_gap = true;
            }
        }
        for (slot, output) in page.body.outputs.iter().enumerate() {
            if page.body.output_is_live(slot) {
                if output_gap {
                    return Err(PagedSpendError::SparseOutputs {
                        page: page_index,
                        slot,
                    });
                }
                live_outputs += 1;
                if live_outputs > MAX_PAGED_SPEND_OUTPUTS {
                    return Err(PagedSpendError::TooManyOutputs {
                        actual: live_outputs,
                    });
                }
                if !output_slots.insert(output.slot_index) {
                    return Err(PagedSpendError::DuplicateOutputSlot {
                        slot: output.slot_index,
                    });
                }
                output_sum = output_sum
                    .checked_add(output.amount as u128)
                    .ok_or(PagedSpendError::OutputSumOverflow)?;
            } else {
                output_gap = true;
            }
        }
    }

    if live_inputs == 0 {
        return Err(PagedSpendError::NoLiveInputs);
    }
    if let Some(slot) = input_slots.intersection(&output_slots).next() {
        return Err(PagedSpendError::InputOutputSlotOverlap { slot: *slot });
    }
    let required_pages = 1usize
        .max(live_inputs.div_ceil(TX_INPUTS))
        .max(live_outputs.div_ceil(TX_OUTPUTS));
    if pages.len() != required_pages {
        return Err(PagedSpendError::NonMinimalPageCount {
            actual: pages.len(),
            required: required_pages,
        });
    }
    let fee = pages[0].body.fee;
    let expected = output_sum
        .checked_add(fee as u128)
        .ok_or(PagedSpendError::OutputPlusFeeOverflow)?;
    if input_sum != expected {
        return Err(PagedSpendError::BalanceMismatch {
            input_sum,
            output_sum,
            fee,
        });
    }

    Ok(PagedSpendFacts {
        logical_txid: hash_paged_spend_unchecked(pages),
        input_owner: pages[0].body.input_owner,
        epoch_anchor: pages[0].body.epoch_anchor,
        fee,
        live_inputs: live_inputs as u16,
        live_outputs: live_outputs as u16,
        input_sum,
        output_sum,
    })
}

fn validate_page_count(count: usize) -> Result<(), PagedSpendError> {
    if !(1..=MAX_PAGED_SPEND_PAGES).contains(&count) {
        return Err(PagedSpendError::PageCount { actual: count });
    }
    Ok(())
}

fn validate_page_shape(body: &TxBody, page: usize) -> Result<(), PagedSpendError> {
    if body.validity_bitmap & !PAGED_SPEND_VALIDITY_MASK != 0 {
        return Err(PagedSpendError::ReservedBitmapBits {
            page,
            bitmap: body.validity_bitmap,
        });
    }
    if body.is_coinbase {
        return Err(PagedSpendError::CoinbasePage { page });
    }
    for (slot, input) in body.inputs.iter().enumerate() {
        if !body.input_is_live(slot) && *input != TxInput::dummy() {
            return Err(PagedSpendError::DeadInputNotZero { page, slot });
        }
    }
    for (slot, output) in body.outputs.iter().enumerate() {
        if !body.output_is_live(slot) && *output != TxOutput::dummy() {
            return Err(PagedSpendError::DeadOutputNotZero { page, slot });
        }
    }
    Ok(())
}

pub(crate) fn encode_page_body(body: &TxBody, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&body.epoch_anchor);
    bytes.extend_from_slice(&body.fee.to_le_bytes());
    bytes.extend_from_slice(&body.input_owner.0);
    for input in &body.inputs {
        input.encode(bytes);
    }
    for output in &body.outputs {
        output.encode(bytes);
    }
    bytes.extend_from_slice(&body.validity_bitmap.to_le_bytes());
    bytes.push(body.is_coinbase as u8);
}

pub(crate) fn decode_page_body(src: &mut &[u8]) -> Result<TxBody, PagedSpendError> {
    let epoch_anchor = take(src, 32)?.try_into().unwrap();
    let fee = u64::from_le_bytes(take(src, 8)?.try_into().unwrap());
    let input_owner = Address(take(src, 32)?.try_into().unwrap());
    let mut inputs = [TxInput::dummy(); TX_INPUTS];
    for input in &mut inputs {
        *input = TxInput::decode(src)?;
    }
    let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
    for output in &mut outputs {
        *output = TxOutput::decode(src)?;
    }
    let validity_bitmap = take_u16(src)?;
    let is_coinbase = match take(src, 1)?[0] {
        0 => false,
        1 => true,
        _ => return Err(PagedSpendError::Wire(WireError::InvalidBool)),
    };
    Ok(TxBody {
        epoch_anchor,
        fee,
        input_owner,
        inputs,
        outputs,
        validity_bitmap,
        is_coinbase,
    })
}

fn take<'a>(src: &mut &'a [u8], len: usize) -> Result<&'a [u8], PagedSpendError> {
    if src.len() < len {
        return Err(PagedSpendError::Wire(WireError::Truncated));
    }
    let (head, tail) = src.split_at(len);
    *src = tail;
    Ok(head)
}

fn take_u16(src: &mut &[u8]) -> Result<u16, PagedSpendError> {
    Ok(u16::from_le_bytes(take(src, 2)?.try_into().unwrap()))
}

fn take_u32(src: &mut &[u8]) -> Result<u32, PagedSpendError> {
    Ok(u32::from_le_bytes(take(src, 4)?.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output_bitmap_bit;

    fn owner() -> Address {
        Address([0x42; 32])
    }

    fn pages(input_count: usize, output_count: usize, fee: u64) -> Vec<TxPage> {
        let page_count = 1usize
            .max(input_count.div_ceil(TX_INPUTS))
            .max(output_count.div_ceil(TX_OUTPUTS));
        const INPUT_AMOUNT: u64 = 100_000;
        let output_total = input_count as u64 * INPUT_AMOUNT - fee;
        (0..page_count)
            .map(|page_index| {
                let mut inputs = [TxInput::dummy(); TX_INPUTS];
                let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
                let mut bitmap = 0u16;
                for (slot, input) in inputs.iter_mut().enumerate() {
                    let index = page_index * TX_INPUTS + slot;
                    if index < input_count {
                        *input = TxInput {
                            slot_index: index as u32 + 1,
                            amount: INPUT_AMOUNT,
                            creation_id: index as u64 + 50,
                        };
                        bitmap |= 1 << slot;
                    }
                }
                for (slot, output) in outputs.iter_mut().enumerate() {
                    let index = page_index * TX_OUTPUTS + slot;
                    if index < output_count {
                        *output = TxOutput {
                            slot_index: 10_000 + index as u32,
                            amount: if index + 1 == output_count {
                                output_total - (output_count as u64 - 1)
                            } else {
                                1
                            },
                            owner: owner(),
                        };
                        bitmap |= output_bitmap_bit(slot);
                    }
                }
                if page_index == 0 {
                    bitmap |= PAGED_SPEND_START_BIT;
                }
                if page_index + 1 == page_count {
                    bitmap |= PAGED_SPEND_END_BIT;
                }
                TxPage::new(TxBody {
                    epoch_anchor: [9u8; 32],
                    fee: if page_index == 0 { fee } else { 0 },
                    input_owner: owner(),
                    inputs,
                    outputs,
                    validity_bitmap: bitmap,
                    is_coinbase: false,
                })
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn one_page_vector_and_intent_roundtrip_are_frozen() {
        let pages = pages(1, 1, 3);
        let facts = validate_paged_spend(&pages).unwrap();
        assert_eq!(facts.live_inputs, 1);
        assert_eq!(facts.live_outputs, 1);
        assert_eq!(facts.input_sum, 100_000);
        assert_eq!(facts.output_sum, 99_997);
        assert_eq!(
            facts.logical_txid.0,
            [
                144, 52, 42, 186, 154, 94, 96, 45, 163, 83, 87, 77, 200, 176, 104, 60, 207, 115,
                158, 254, 28, 206, 83, 209, 198, 238, 59, 242, 133, 203, 62, 33,
            ]
        );

        let intent = PagedSpendIntent::new(pages, vec![1, 2, 3]).unwrap();
        let bytes = intent.to_bytes().unwrap();
        assert_eq!(PagedSpendIntent::from_bytes(&bytes), Ok(intent));
    }

    #[test]
    fn hundred_and_1020_inputs_are_one_logical_transaction() {
        let hundred = pages(100, 1, 15_700);
        assert_eq!(hundred.len(), 13);
        assert_eq!(validate_paged_spend(&hundred).unwrap().live_inputs, 100);

        let maximum = pages(1_020, 1, 5_000);
        let facts = validate_paged_spend(&maximum).unwrap();
        assert_eq!(maximum.len(), 128);
        assert_eq!(facts.live_inputs, 1_020);
        assert_eq!(
            facts.logical_txid.0,
            [
                45, 143, 66, 164, 239, 252, 242, 233, 221, 159, 123, 187, 161, 13, 1, 61, 153, 164,
                221, 118, 174, 187, 6, 222, 23, 120, 245, 210, 243, 96, 115, 252,
            ]
        );
        let statement = canonical_paged_spend_auth(&maximum).unwrap();
        assert_eq!(statement.logical_txid, facts.logical_txid);
        assert_eq!(statement.input_owner, owner());
    }

    #[test]
    fn group_boundaries_owner_epoch_fee_and_balance_reject() {
        let mut missing_start = pages(9, 1, 3);
        missing_start[0].body.validity_bitmap &= !PAGED_SPEND_START_BIT;
        assert_eq!(
            validate_paged_spend(&missing_start),
            Err(PagedSpendError::MissingStart)
        );

        let mut early_end = pages(9, 1, 3);
        early_end[0].body.validity_bitmap |= PAGED_SPEND_END_BIT;
        assert_eq!(
            validate_paged_spend(&early_end),
            Err(PagedSpendError::UnexpectedEnd { page: 0 })
        );

        let mut changed = pages(9, 1, 3);
        changed[1].body.input_owner = Address([7u8; 32]);
        assert_eq!(
            validate_paged_spend(&changed),
            Err(PagedSpendError::OwnerMismatch { page: 1 })
        );

        let mut continuation_fee = pages(9, 1, 3);
        continuation_fee[1].body.fee = 1;
        assert_eq!(
            validate_paged_spend(&continuation_fee),
            Err(PagedSpendError::ContinuationFee { page: 1 })
        );

        let mut unbalanced = pages(9, 1, 3);
        unbalanced[0].body.outputs[0].amount += 1;
        assert!(matches!(
            validate_paged_spend(&unbalanced),
            Err(PagedSpendError::BalanceMismatch { .. })
        ));
    }

    #[test]
    fn wire_is_bounded_before_allocation() {
        let intent = PagedSpendIntent::new(pages(1, 1, 3), vec![5; 20]).unwrap();
        let encoded = intent.to_bytes().unwrap();

        let mut wrong_marker = encoded.clone();
        wrong_marker[0] ^= 1;
        assert_eq!(
            PagedSpendIntent::from_bytes(&wrong_marker),
            Err(PagedSpendError::Wire(WireError::BadMarker))
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            PagedSpendIntent::from_bytes(&trailing),
            Err(PagedSpendError::Wire(WireError::TrailingBytes))
        );
        assert_eq!(
            PagedSpendIntent::from_bytes(&encoded[..encoded.len() - 1]),
            Err(PagedSpendError::Wire(WireError::Truncated))
        );

        let mut oversized_auth = encoded;
        let authorization_len_offset = 1 + 2 + TX_BODY_WIRE_SIZE;
        oversized_auth[authorization_len_offset..authorization_len_offset + 4]
            .copy_from_slice(&((MAX_TX_AUTHORIZATION_BYTES as u32) + 1).to_le_bytes());
        assert_eq!(
            PagedSpendIntent::from_bytes(&oversized_auth),
            Err(PagedSpendError::AuthorizationTooLarge {
                actual: MAX_TX_AUTHORIZATION_BYTES + 1,
            })
        );
    }
}
