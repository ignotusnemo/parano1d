// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical native-operation pages, live openings and detached authorization.

use std::collections::BTreeSet;

use noid_poseidon2b::primitives::{Address, Digest, TxBodyHash};

use super::closure::{canonical_native_closure, resolve_native_closure, NativeClosureError};
use super::financial::{
    owner::{check_financial_owner, FinancialOwnerError},
    public::{check_financial_public, FinancialPublicContext, FinancialPublicError},
    FinancialOperation, FinancialOperationError,
};
use super::nft_market::NftRoundContext;
use super::transition::{
    check_native_transition, NativeContext, NativeInputClaim, NativeOperation, NativeOutputClaim,
    NativeTransitionError, NativeTransitionFacts,
};
use super::{AssetId, NativeAssetError, NativeOpening, MAX_NATIVE_OPENING_BYTES};
use crate::paged_spend::{decode_page_body, encode_page_body, hash_paged_spend_unchecked};
use crate::{
    output_bitmap_bit, CanonicalOwnerAuth, PagedSpendError, TxBody, TxInput, TxOutput, TxPage,
    MAX_PAGED_SPEND_INPUTS, MAX_PAGED_SPEND_OUTPUTS, MAX_PAGED_SPEND_PAGES,
    MAX_TX_AUTHORIZATION_BYTES, PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT, TX_BODY_WIRE_SIZE,
    TX_INPUTS, TX_OUTPUTS, TX_VALIDITY_MASK,
};

pub const NATIVE_PAGE_BIT: u16 = 1 << 14;
pub const NATIVE_HEADER_BIT: u16 = 1 << 15;
pub const NATIVE_SPEND_VERSION: u16 = 1;
pub const NATIVE_INTENT_MAGIC: &[u8; 8] = b"NOIDNT21";
pub const NATIVE_INTENT_PREFIX_BYTES: usize = 16;
const INPUT_MASK_BITS: usize = 1024;
const MASK_BYTES: usize = 160;
pub const MAX_NATIVE_INTENT_DEPENDENCIES: usize =
    MAX_PAGED_SPEND_INPUTS + MAX_PAGED_SPEND_OUTPUTS + 2;
pub const MAX_NATIVE_INTENT_BYTES: usize = NATIVE_INTENT_PREFIX_BYTES
    + MAX_PAGED_SPEND_PAGES * TX_BODY_WIRE_SIZE
    + (MAX_PAGED_SPEND_INPUTS + MAX_PAGED_SPEND_OUTPUTS) * (2 + MAX_NATIVE_OPENING_BYTES)
    + 2
    + MAX_NATIVE_INTENT_DEPENDENCIES * (2 + MAX_NATIVE_OPENING_BYTES)
    + MAX_TX_AUTHORIZATION_BYTES;

const _: () = assert!(INPUT_MASK_BITS >= MAX_PAGED_SPEND_INPUTS);
const _: () = assert!(INPUT_MASK_BITS + MAX_PAGED_SPEND_OUTPUTS == MASK_BYTES * 8);
const _: () = assert!(TX_INPUTS * 20 == MASK_BYTES);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeWireError {
    Encoding,
    Version,
    Bounds,
    Header,
    Operation,
    Context,
    PageShape,
    InputLayout,
    OutputLayout,
    OpeningCount,
    OpeningMask,
    Authorization,
    Dependencies(NativeClosureError),
    FinancialOperand(FinancialOperationError),
    FinancialOwner(FinancialOwnerError),
    FinancialPublic(FinancialPublicError),
    Trade(super::trade::execution::TradeExecutionError),
    Page(PagedSpendError),
    Opening(NativeAssetError),
    Semantic(NativeTransitionError),
}

impl core::fmt::Display for NativeWireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "native intent: {self:?}")
    }
}
impl std::error::Error for NativeWireError {}
impl From<NativeAssetError> for NativeWireError {
    fn from(e: NativeAssetError) -> Self {
        Self::Opening(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePageFacts {
    pub chain: Digest,
    pub authority: Address,
    pub epoch_anchor: Digest,
    pub fee: u64,
    pub operation: NativeOperation,
    pub logical_txid: TxBodyHash,
    pub live_inputs: usize,
    pub live_outputs: usize,
    mask: [u8; MASK_BYTES],
}

impl NativePageFacts {
    pub fn input_is_native(&self, index: usize) -> bool {
        index < self.live_inputs && mask_bit(&self.mask, index)
    }

    pub fn output_is_native(&self, index: usize) -> bool {
        index < self.live_outputs && mask_bit(&self.mask, INPUT_MASK_BITS + index)
    }

    pub fn canonical_auth(&self) -> CanonicalOwnerAuth {
        CanonicalOwnerAuth {
            tx_body_hash: self.logical_txid,
            input_owner: self.authority,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSpendFacts {
    pub pages: NativePageFacts,
    pub context: NativeContext,
    pub inputs: Vec<NativeInputClaim>,
    pub outputs: Vec<NativeOutputClaim>,
    pub transition: NativeTransitionFacts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeIntent {
    pub pages: Vec<TxPage>,
    pub input_openings: Vec<Option<NativeOpening>>,
    pub output_openings: Vec<Option<NativeOpening>>,
    pub dependencies: Vec<NativeOpening>,
    pub authorization_bytes: Vec<u8>,
}

impl NativeIntent {
    /// Resolve every typed live action from its committed content key.
    pub fn from_pages_with_openings(
        pages: Vec<TxPage>,
        mut opening: impl FnMut(Address) -> Option<NativeOpening>,
    ) -> Result<Self, NativeWireError> {
        let facts = validate_native_pages(&pages)?;
        let input_openings = pages
            .iter()
            .skip(1)
            .flat_map(|page| page.body.live_inputs().map(|_| page.body.input_owner))
            .enumerate()
            .map(|(index, root)| {
                if facts.input_is_native(index) {
                    opening(root).map(Some).ok_or(NativeWireError::OpeningCount)
                } else {
                    Ok(None)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let output_openings = pages
            .iter()
            .skip(1)
            .flat_map(|page| page.body.live_outputs().map(|(_, output)| output.owner))
            .enumerate()
            .map(|(index, root)| {
                if facts.output_is_native(index) {
                    opening(root).map(Some).ok_or(NativeWireError::OpeningCount)
                } else {
                    Ok(None)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let dependencies =
            resolve_dependencies(&facts, &input_openings, &output_openings, &mut opening)?;
        let intent = Self {
            pages,
            input_openings,
            output_openings,
            dependencies,
            authorization_bytes: Vec::new(),
        };
        intent.validate_structure()?;
        Ok(intent)
    }

    /// Resource and fee accounting shared with ordinary indivisible spends.
    pub fn resource_facts(&self) -> Result<crate::PagedSpendFacts, NativeWireError> {
        let facts = self.validate_structure()?;
        Ok(crate::PagedSpendFacts {
            logical_txid: facts.logical_txid,
            input_owner: facts.authority,
            epoch_anchor: facts.epoch_anchor,
            fee: facts.fee,
            live_inputs: facts.live_inputs as u16,
            live_outputs: facts.live_outputs as u16,
            input_sum: self
                .pages
                .iter()
                .flat_map(|page| page.body.live_inputs())
                .map(|(_, input)| u128::from(input.amount))
                .sum(),
            output_sum: self
                .pages
                .iter()
                .flat_map(|page| page.body.live_outputs())
                .map(|(_, output)| u128::from(output.amount))
                .sum(),
        })
    }

    /// Group equal input roots for compact pages and retain the selected
    /// output order. A genesis funding ordinal follows its exact input.
    pub fn from_claims(
        context: &NativeContext,
        epoch_anchor: Digest,
        operation: NativeOperation,
        inputs: Vec<NativeInputClaim>,
        outputs: Vec<NativeOutputClaim>,
    ) -> Result<Self, NativeWireError> {
        let intent = Self::build_from_claims(context, epoch_anchor, operation, inputs, outputs)?;
        intent.checked(context.chain, context.height)?;
        Ok(intent)
    }

    pub fn from_financial_claims(
        context: &NativeContext,
        epoch_anchor: Digest,
        operation: FinancialOperation,
        round: NftRoundContext,
        inputs: Vec<NativeInputClaim>,
        outputs: Vec<NativeOutputClaim>,
        mut resolve: impl FnMut(Address) -> Option<NativeOpening>,
    ) -> Result<Self, NativeWireError> {
        if context.height != round.height() {
            return Err(NativeWireError::Context);
        }
        let mut intent = Self::build_from_claims(
            context,
            epoch_anchor,
            NativeOperation::Financial(operation),
            inputs,
            outputs,
        )?;
        let facts = validate_native_pages(&intent.pages)?;
        intent.dependencies = resolve_dependencies(
            &facts,
            &intent.input_openings,
            &intent.output_openings,
            &mut resolve,
        )?;
        intent.checked_financial_owner(context.chain, round)?;
        Ok(intent)
    }

    pub fn from_public_financial_claims(
        context: &NativeContext,
        epoch_anchor: Digest,
        operation: FinancialOperation,
        public: &FinancialPublicContext<'_>,
        inputs: Vec<NativeInputClaim>,
        outputs: Vec<NativeOutputClaim>,
        mut resolve: impl FnMut(Address) -> Option<NativeOpening>,
    ) -> Result<Self, NativeWireError> {
        if context.height != public.round.height() {
            return Err(NativeWireError::Context);
        }
        let mut intent = Self::build_from_claims(
            context,
            epoch_anchor,
            NativeOperation::Financial(operation),
            inputs,
            outputs,
        )?;
        let facts = validate_native_pages(&intent.pages)?;
        intent.dependencies = resolve_dependencies(
            &facts,
            &intent.input_openings,
            &intent.output_openings,
            &mut resolve,
        )?;
        intent.checked_financial_public(context.chain, public)?;
        Ok(intent)
    }

    pub fn from_trade_execution(
        execution: &super::trade::execution::TradeExecution,
        mut resolve: impl FnMut(Address) -> Option<NativeOpening>,
    ) -> Result<Self, NativeWireError> {
        let boundary = execution.boundary();
        let context = NativeContext {
            chain: boundary.chain,
            height: boundary.height,
            authority: Address([0; 32]),
            fee: execution.fee(),
        };
        let mut intent = Self::build_claims_layout(
            &context,
            boundary.epoch_anchor,
            NativeOperation::Financial(FinancialOperation::ExecuteTrades {
                commitment: execution.commitment(),
            }),
            execution.inputs().to_vec(),
            execution.outputs().to_vec(),
            false,
        )?;
        let facts = validate_native_pages(&intent.pages)?;
        let auxiliary = execution
            .auxiliary()
            .iter()
            .map(|o| (o.root().0, *o))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut resolve = |root: Address| auxiliary.get(&root.0).copied().or_else(|| resolve(root));
        intent.dependencies = resolve_dependencies(
            &facts,
            &intent.input_openings,
            &intent.output_openings,
            &mut resolve,
        )?;
        intent.validate_structure()?;
        Ok(intent)
    }

    pub fn checked_trade(
        &self,
        boundary: super::trade::sequencing::TradeBoundary,
        batch: &super::trade::batch::TradeBatch,
        fees: &[super::trade::execution::TradeFeeQuotes],
    ) -> Result<super::trade::execution::TradeExecution, NativeWireError> {
        let facts = self.validate_structure()?;
        let commitment = batch
            .root()
            .map_err(|error| NativeWireError::Trade(error.into()))?;
        if facts.chain != boundary.chain
            || facts.epoch_anchor != boundary.epoch_anchor
            || facts.operation
                != NativeOperation::Financial(FinancialOperation::ExecuteTrades { commitment })
        {
            return Err(NativeWireError::Context);
        }
        let (inputs, outputs) = self.claims();
        let execution = super::trade::execution::TradeExecution::from_claims(
            batch, boundary, fees, &inputs, &outputs,
        )
        .map_err(NativeWireError::Trade)?;
        if facts.fee != execution.fee() {
            return Err(NativeWireError::Context);
        }
        Ok(execution)
    }

    fn build_from_claims(
        context: &NativeContext,
        epoch_anchor: Digest,
        operation: NativeOperation,
        inputs: Vec<NativeInputClaim>,
        outputs: Vec<NativeOutputClaim>,
    ) -> Result<Self, NativeWireError> {
        Self::build_claims_layout(context, epoch_anchor, operation, inputs, outputs, true)
    }

    fn build_claims_layout(
        context: &NativeContext,
        epoch_anchor: Digest,
        operation: NativeOperation,
        mut inputs: Vec<NativeInputClaim>,
        outputs: Vec<NativeOutputClaim>,
        sort_inputs: bool,
    ) -> Result<Self, NativeWireError> {
        if inputs.is_empty()
            || inputs.len() > MAX_PAGED_SPEND_INPUTS
            || outputs.len() > MAX_PAGED_SPEND_OUTPUTS
        {
            return Err(NativeWireError::Bounds);
        }
        let funding_slot = operation
            .funding_input()
            .map(|index| {
                inputs
                    .get(usize::from(index))
                    .map(|c| c.input.slot_index)
                    .ok_or(NativeWireError::Operation)
            })
            .transpose()?;
        if sort_inputs {
            inputs.sort_by_key(|c| (c.root.0, c.input.slot_index));
        }
        let operation = if let Some(slot) = funding_slot {
            let funding_input = inputs
                .iter()
                .position(|c| c.input.slot_index == slot)
                .ok_or(NativeWireError::Operation)? as u16;
            operation
                .with_funding_input(funding_input)
                .map_err(NativeWireError::Semantic)?
        } else {
            operation
        };
        let mut data: Vec<TxPage> = Vec::new();
        for claim in &inputs {
            let new_page = data.last().is_none_or(|page| {
                page.body.input_owner != claim.root || page.body.live_input_count() == TX_INPUTS
            });
            if new_page {
                if data.len() + 1 >= MAX_PAGED_SPEND_PAGES {
                    return Err(NativeWireError::Bounds);
                }
                let mut page = empty_page(epoch_anchor);
                page.body.input_owner = claim.root;
                data.push(page);
            }
            let page = data.last_mut().ok_or(NativeWireError::InputLayout)?;
            let index = page.body.live_input_count();
            page.body.inputs[index] = claim.input;
            page.body.validity_bitmap |= 1 << index;
        }
        for (index, claim) in outputs.iter().enumerate() {
            let page = index / TX_OUTPUTS;
            if page >= data.len() {
                if data.len() + 1 >= MAX_PAGED_SPEND_PAGES {
                    return Err(NativeWireError::Bounds);
                }
                data.push(empty_page(epoch_anchor));
            }
            let output = index % TX_OUTPUTS;
            data[page].body.outputs[output] = claim.output;
            data[page].body.validity_bitmap |= output_bitmap_bit(output);
        }
        data.last_mut()
            .ok_or(NativeWireError::InputLayout)?
            .body
            .validity_bitmap |= PAGED_SPEND_END_BIT;
        let mut mask = [0; MASK_BYTES];
        for (i, claim) in inputs.iter().enumerate() {
            set_mask_bit(&mut mask, i, claim.opening.is_some());
        }
        for (i, claim) in outputs.iter().enumerate() {
            set_mask_bit(&mut mask, INPUT_MASK_BITS + i, claim.opening.is_some());
        }
        let (code, operand) = encode_operation(operation)?;
        let header = TxPage {
            body: TxBody {
                epoch_anchor,
                fee: context.fee,
                input_owner: context.authority,
                inputs: encode_mask(mask),
                outputs: [
                    TxOutput {
                        slot_index: u32::from(NATIVE_SPEND_VERSION),
                        amount: u64::from(code),
                        owner: Address(context.chain),
                    },
                    operand,
                ],
                validity_bitmap: NATIVE_PAGE_BIT | NATIVE_HEADER_BIT | PAGED_SPEND_START_BIT,
                is_coinbase: false,
            },
        };
        let mut pages = Vec::with_capacity(data.len() + 1);
        pages.push(header);
        pages.extend(data);
        let intent = Self {
            pages,
            input_openings: inputs.iter().map(|c| c.opening).collect(),
            output_openings: outputs.iter().map(|c| c.opening).collect(),
            dependencies: Vec::new(),
            authorization_bytes: Vec::new(),
        };
        validate_native_pages(&intent.pages)?;
        Ok(intent)
    }

    pub fn validate_structure(&self) -> Result<NativePageFacts, NativeWireError> {
        if self.authorization_bytes.len() > MAX_TX_AUTHORIZATION_BYTES {
            return Err(NativeWireError::Bounds);
        }
        let facts = validate_native_pages(&self.pages)?;
        if self.input_openings.len() != facts.live_inputs
            || self.output_openings.len() != facts.live_outputs
        {
            return Err(NativeWireError::OpeningCount);
        }
        for (index, (input, root)) in self
            .pages
            .iter()
            .skip(1)
            .flat_map(|p| p.body.live_inputs().map(|(_, i)| (i, p.body.input_owner)))
            .enumerate()
        {
            let opening = &self.input_openings[index];
            if opening.is_some() != facts.input_is_native(index) {
                return Err(NativeWireError::OpeningMask);
            }
            if let Some(opening) = opening {
                opening.check_input_binding(input, root)?;
            }
        }
        for (index, output) in self
            .pages
            .iter()
            .skip(1)
            .flat_map(|p| p.body.live_outputs().map(|(_, o)| o))
            .enumerate()
        {
            let opening = &self.output_openings[index];
            if opening.is_some() != facts.output_is_native(index) {
                return Err(NativeWireError::OpeningMask);
            }
            if let Some(opening) = opening {
                opening.check_output(output)?;
            }
        }
        if matches!(facts.operation, NativeOperation::Financial(_)) {
            if !facts.operation.requires_owner() && !self.authorization_bytes.is_empty() {
                return Err(NativeWireError::Authorization);
            }
            let carriers = primary_openings(&self.input_openings, &self.output_openings);
            let roots: Vec<_> = carriers.iter().map(NativeOpening::root).collect();
            let operands = operand_roots(facts.operation);
            let mut supplied = carriers.clone();
            supplied.extend_from_slice(&self.dependencies);
            let closure = canonical_native_closure(
                &roots,
                &operands,
                &supplied,
                MAX_PAGED_SPEND_INPUTS + MAX_PAGED_SPEND_OUTPUTS + MAX_NATIVE_INTENT_DEPENDENCIES,
            )
            .map_err(NativeWireError::Dependencies)?;
            let keys: BTreeSet<_> = carriers.iter().map(|o| o.root().0).collect();
            let expected: Vec<_> = closure
                .into_iter()
                .filter(|o| !keys.contains(&o.root().0))
                .collect();
            if expected != self.dependencies {
                return Err(NativeWireError::OpeningCount);
            }
        } else if !self.dependencies.is_empty() {
            return Err(NativeWireError::OpeningCount);
        }
        Ok(facts)
    }

    pub fn checked(
        &self,
        expected_chain: Digest,
        height: u64,
    ) -> Result<NativeSpendFacts, NativeWireError> {
        let pages = self.validate_structure()?;
        if pages.chain != expected_chain {
            return Err(NativeWireError::Context);
        }
        let context = NativeContext {
            chain: pages.chain,
            height,
            authority: pages.authority,
            fee: pages.fee,
        };
        let (inputs, outputs) = self.claims();
        let transition = check_native_transition(&context, pages.operation, &inputs, &outputs)
            .map_err(NativeWireError::Semantic)?;
        Ok(NativeSpendFacts {
            pages,
            context,
            inputs,
            outputs,
            transition,
        })
    }

    pub fn checked_financial_owner(
        &self,
        expected_chain: Digest,
        round: NftRoundContext,
    ) -> Result<NativeSpendFacts, NativeWireError> {
        let pages = self.validate_structure()?;
        if pages.chain != expected_chain {
            return Err(NativeWireError::Context);
        }
        let NativeOperation::Financial(operation) = pages.operation else {
            return Err(NativeWireError::Operation);
        };
        let context = NativeContext {
            chain: pages.chain,
            height: round.height(),
            authority: pages.authority,
            fee: pages.fee,
        };
        let (inputs, outputs) = self.claims();
        let transition =
            check_financial_owner(&context, round, operation, &inputs, &outputs, |root| {
                self.opening(root)
            })
            .map_err(NativeWireError::FinancialOwner)?;
        Ok(NativeSpendFacts {
            pages,
            context,
            inputs,
            outputs,
            transition,
        })
    }

    pub fn checked_financial_public(
        &self,
        expected_chain: Digest,
        public: &FinancialPublicContext<'_>,
    ) -> Result<(NativeSpendFacts, Vec<NativeOpening>), NativeWireError> {
        let pages = self.validate_structure()?;
        if pages.chain != expected_chain {
            return Err(NativeWireError::Context);
        }
        let NativeOperation::Financial(operation) = pages.operation else {
            return Err(NativeWireError::Operation);
        };
        let context = NativeContext {
            chain: pages.chain,
            height: public.round.height(),
            authority: pages.authority,
            fee: pages.fee,
        };
        let (inputs, outputs) = self.claims();
        let facts =
            check_financial_public(&context, operation, &inputs, &outputs, public, |root| {
                self.opening(root)
            })
            .map_err(NativeWireError::FinancialPublic)?;
        Ok((
            NativeSpendFacts {
                pages,
                context,
                inputs,
                outputs,
                transition: facts.transition,
            },
            facts.auxiliary,
        ))
    }

    pub fn opening(&self, root: Address) -> Option<NativeOpening> {
        self.input_openings
            .iter()
            .chain(&self.output_openings)
            .flatten()
            .chain(&self.dependencies)
            .find(|o| o.root() == root)
            .copied()
    }

    fn claims(&self) -> (Vec<NativeInputClaim>, Vec<NativeOutputClaim>) {
        let inputs: Vec<_> = self
            .pages
            .iter()
            .skip(1)
            .flat_map(|p| p.body.live_inputs().map(|(_, i)| (*i, p.body.input_owner)))
            .zip(&self.input_openings)
            .map(|((input, root), &opening)| NativeInputClaim {
                input,
                root,
                opening,
            })
            .collect();
        let outputs: Vec<_> = self
            .pages
            .iter()
            .skip(1)
            .flat_map(|p| p.body.live_outputs().map(|(_, o)| *o))
            .zip(&self.output_openings)
            .map(|(output, &opening)| NativeOutputClaim { output, opening })
            .collect();
        (inputs, outputs)
    }

    pub fn logical_txid(&self) -> Result<TxBodyHash, NativeWireError> {
        Ok(self.validate_structure()?.logical_txid)
    }

    pub fn authorization_wire_offset(&self) -> Result<usize, NativeWireError> {
        let facts = self.validate_structure()?;
        let dependencies = if matches!(facts.operation, NativeOperation::Financial(_)) {
            2 + self
                .dependencies
                .iter()
                .map(|o| 2 + 12 + 16 * o.kind().field_count())
                .sum::<usize>()
        } else {
            0
        };
        Ok(NATIVE_INTENT_PREFIX_BYTES
            + dependencies
            + self.pages.len() * TX_BODY_WIRE_SIZE
            + self
                .input_openings
                .iter()
                .chain(&self.output_openings)
                .map(|opening| 2 + opening.map_or(0, |o| 12 + 16 * o.kind().field_count()))
                .sum::<usize>())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, NativeWireError> {
        let offset = self.authorization_wire_offset()?;
        let mut bytes = Vec::with_capacity(offset + self.authorization_bytes.len());
        bytes.extend_from_slice(NATIVE_INTENT_MAGIC);
        bytes.extend_from_slice(&NATIVE_SPEND_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(self.pages.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.authorization_bytes.len() as u32).to_le_bytes());
        for page in &self.pages {
            encode_page_body(&page.body, &mut bytes);
        }
        for opening in self.input_openings.iter().chain(&self.output_openings) {
            if let Some(opening) = opening {
                let opening = opening.to_bytes()?;
                bytes.extend_from_slice(&(opening.len() as u16).to_le_bytes());
                bytes.extend_from_slice(&opening);
            } else {
                bytes.extend_from_slice(&0u16.to_le_bytes());
            }
        }
        if self.pages[0].body.outputs[0].amount >= 32 {
            bytes.extend_from_slice(&(self.dependencies.len() as u16).to_le_bytes());
            for opening in &self.dependencies {
                let raw = opening.to_bytes()?;
                bytes.extend_from_slice(&(raw.len() as u16).to_le_bytes());
                bytes.extend_from_slice(&raw);
            }
        }
        debug_assert_eq!(bytes.len(), offset);
        bytes.extend_from_slice(&self.authorization_bytes);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NativeWireError> {
        if bytes.len() < NATIVE_INTENT_PREFIX_BYTES
            || bytes.len() > MAX_NATIVE_INTENT_BYTES
            || &bytes[..8] != NATIVE_INTENT_MAGIC
        {
            return Err(NativeWireError::Encoding);
        }
        let mut src = &bytes[8..];
        if read_u16(&mut src)? != NATIVE_SPEND_VERSION {
            return Err(NativeWireError::Version);
        }
        let page_count = usize::from(read_u16(&mut src)?);
        let auth_count = u32::from_le_bytes(take(&mut src, 4)?.try_into().unwrap()) as usize;
        if !(2..=MAX_PAGED_SPEND_PAGES).contains(&page_count)
            || auth_count > MAX_TX_AUTHORIZATION_BYTES
            || src.len() < page_count * TX_BODY_WIRE_SIZE + auth_count
        {
            return Err(NativeWireError::Bounds);
        }
        let mut pages = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            pages.push(TxPage {
                body: decode_page_body(&mut src).map_err(NativeWireError::Page)?,
            });
        }
        let facts = validate_native_pages(&pages)?;
        let input_openings = read_openings(&mut src, facts.live_inputs)?;
        let output_openings = read_openings(&mut src, facts.live_outputs)?;
        let dependencies = if matches!(facts.operation, NativeOperation::Financial(_)) {
            let count = usize::from(read_u16(&mut src)?);
            if count > MAX_NATIVE_INTENT_DEPENDENCIES {
                return Err(NativeWireError::Bounds);
            }
            read_openings(&mut src, count)?
                .into_iter()
                .map(|o| o.ok_or(NativeWireError::OpeningCount))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        if src.len() != auth_count {
            return Err(NativeWireError::Encoding);
        }
        let intent = Self {
            pages,
            input_openings,
            output_openings,
            dependencies,
            authorization_bytes: src.to_vec(),
        };
        intent.validate_structure()?;
        Ok(intent)
    }
}

pub fn is_native_header(body: &TxBody) -> bool {
    body.validity_bitmap & (NATIVE_PAGE_BIT | NATIVE_HEADER_BIT)
        == NATIVE_PAGE_BIT | NATIVE_HEADER_BIT
}

/// Encode one complete native group in the fixed block-record format.
pub fn encode_native_pages(
    pages: &[TxPage],
    bytes: &mut Vec<u8>,
) -> Result<NativePageFacts, NativeWireError> {
    let facts = validate_native_pages(pages)?;
    for page in pages {
        encode_page_body(&page.body, bytes);
    }
    Ok(facts)
}

/// Decode exactly one bounded group, leaving the caller's cursor unchanged
/// unless its complete framing is canonical.
pub fn decode_native_pages(
    src: &mut &[u8],
) -> Result<(Vec<TxPage>, NativePageFacts), NativeWireError> {
    let mut cursor = *src;
    let mut pages = Vec::new();
    loop {
        if pages.len() == MAX_PAGED_SPEND_PAGES {
            return Err(NativeWireError::Bounds);
        }
        let body = decode_page_body(&mut cursor).map_err(NativeWireError::Page)?;
        let end = body.validity_bitmap & PAGED_SPEND_END_BIT != 0;
        pages.push(TxPage { body });
        if end {
            break;
        }
    }
    let facts = validate_native_pages(&pages)?;
    *src = cursor;
    Ok((pages, facts))
}

/// Validate page framing independently of the detached opening/proof bytes.
/// The logical id therefore remains derivable from the retained body format.
pub fn validate_native_pages(pages: &[TxPage]) -> Result<NativePageFacts, NativeWireError> {
    if !(2..=MAX_PAGED_SPEND_PAGES).contains(&pages.len()) {
        return Err(NativeWireError::Bounds);
    }
    let header = &pages[0].body;
    if header.is_coinbase
        || header.validity_bitmap != NATIVE_PAGE_BIT | NATIVE_HEADER_BIT | PAGED_SPEND_START_BIT
        || header.outputs[0].slot_index != u32::from(NATIVE_SPEND_VERSION)
        || header.outputs[0].owner == Address([0; 32])
    {
        return Err(NativeWireError::Header);
    }
    let code = u16::try_from(header.outputs[0].amount).map_err(|_| NativeWireError::Operation)?;
    let operation = decode_operation(code, header.outputs[1])?;
    if operation.requires_owner() == (header.input_owner == Address([0; 32])) {
        return Err(NativeWireError::Header);
    }
    let mask = decode_mask(&header.inputs);
    let mut input_slots = BTreeSet::new();
    let mut output_slots = BTreeSet::new();
    let mut input_tail = false;
    let mut output_tail = false;
    for (index, page) in pages.iter().enumerate().skip(1) {
        let body = &page.body;
        let end = if index + 1 == pages.len() {
            PAGED_SPEND_END_BIT
        } else {
            0
        };
        if body.is_coinbase
            || body.epoch_anchor != header.epoch_anchor
            || body.fee != 0
            || body.validity_bitmap & !TX_VALIDITY_MASK != NATIVE_PAGE_BIT | end
        {
            return Err(NativeWireError::PageShape);
        }
        let n_input = body.live_input_count();
        let n_output = body.live_output_count();
        if n_input == 0 && n_output == 0 {
            return Err(NativeWireError::PageShape);
        }
        if (n_input != 0 && input_tail) || (body.input_owner == Address([0; 32])) != (n_input == 0)
        {
            return Err(NativeWireError::InputLayout);
        }
        input_tail |= n_input == 0;
        if body.validity_bitmap & 0xff != ((1u16 << n_input) - 1) {
            return Err(NativeWireError::InputLayout);
        }
        let expected_output = ((1u16 << n_output) - 1) << TX_INPUTS;
        if (n_output != 0 && output_tail)
            || body.validity_bitmap & (3 << TX_INPUTS) != expected_output
        {
            return Err(NativeWireError::OutputLayout);
        }
        output_tail |= n_output < TX_OUTPUTS;
        for (i, input) in body.inputs.iter().enumerate() {
            if body.input_is_live(i) {
                if !input_slots.insert(input.slot_index) {
                    return Err(NativeWireError::InputLayout);
                }
            } else if *input != TxInput::dummy() {
                return Err(NativeWireError::PageShape);
            }
        }
        for (i, output) in body.outputs.iter().enumerate() {
            if body.output_is_live(i) {
                if !output_slots.insert(output.slot_index) {
                    return Err(NativeWireError::OutputLayout);
                }
            } else if *output != TxOutput::dummy() {
                return Err(NativeWireError::PageShape);
            }
        }
    }
    if input_slots.is_empty()
        || input_slots.len() > MAX_PAGED_SPEND_INPUTS
        || output_slots.len() > MAX_PAGED_SPEND_OUTPUTS
        || input_slots.intersection(&output_slots).next().is_some()
    {
        return Err(NativeWireError::Bounds);
    }
    if operation
        .funding_input()
        .is_some_and(|i| usize::from(i) >= input_slots.len())
    {
        return Err(NativeWireError::Operation);
    }
    if (input_slots.len()..INPUT_MASK_BITS).any(|i| mask_bit(&mask, i))
        || (output_slots.len()..MAX_PAGED_SPEND_OUTPUTS)
            .any(|i| mask_bit(&mask, INPUT_MASK_BITS + i))
    {
        return Err(NativeWireError::OpeningMask);
    }
    Ok(NativePageFacts {
        chain: header.outputs[0].owner.0,
        authority: header.input_owner,
        epoch_anchor: header.epoch_anchor,
        fee: header.fee,
        operation,
        logical_txid: hash_paged_spend_unchecked(pages),
        live_inputs: input_slots.len(),
        live_outputs: output_slots.len(),
        mask,
    })
}

fn empty_page(epoch_anchor: Digest) -> TxPage {
    TxPage {
        body: TxBody {
            epoch_anchor,
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: [TxOutput::dummy(); TX_OUTPUTS],
            validity_bitmap: NATIVE_PAGE_BIT,
            is_coinbase: false,
        },
    }
}

fn encode_operation(operation: NativeOperation) -> Result<(u16, TxOutput), NativeWireError> {
    if !operation.enabled() {
        return Err(NativeWireError::Operation);
    }
    let (code, argument, asset) = match operation {
        NativeOperation::CreateToken { funding_input } => (1, funding_input, [0; 32]),
        NativeOperation::TransferToken { asset } => (2, 0, asset.0),
        NativeOperation::RedeemToken { asset } => (3, 0, asset.0),
        NativeOperation::TopUpReserve { asset } => (4, 0, asset.0),
        NativeOperation::CreateCollection { funding_input } => (5, funding_input, [0; 32]),
        NativeOperation::MintNft => (6, 0, [0; 32]),
        NativeOperation::TransferNft => (7, 0, [0; 32]),
        NativeOperation::BurnNft => (8, 0, [0; 32]),
        NativeOperation::Financial(operation) => {
            return Ok((
                operation.code(),
                operation
                    .operand()
                    .map_err(NativeWireError::FinancialOperand)?,
            ))
        }
    };
    Ok((
        code,
        TxOutput {
            slot_index: 0,
            amount: u64::from(argument),
            owner: Address(asset),
        },
    ))
}

fn decode_operation(code: u16, operand: TxOutput) -> Result<NativeOperation, NativeWireError> {
    if !super::profile::operation_enabled(code) {
        return Err(NativeWireError::Operation);
    }
    if code >= 32 {
        return FinancialOperation::decode(code, operand)
            .map(NativeOperation::Financial)
            .map_err(NativeWireError::FinancialOperand);
    }
    if operand.slot_index != 0 {
        return Err(NativeWireError::Operation);
    }
    let argument = u16::try_from(operand.amount).map_err(|_| NativeWireError::Operation)?;
    let asset = operand.owner.0;
    let zero_asset = asset == [0; 32];
    match code {
        1 if zero_asset => Ok(NativeOperation::CreateToken {
            funding_input: argument,
        }),
        2 if argument == 0 && !zero_asset => Ok(NativeOperation::TransferToken {
            asset: AssetId(asset),
        }),
        3 if argument == 0 && !zero_asset => Ok(NativeOperation::RedeemToken {
            asset: AssetId(asset),
        }),
        4 if argument == 0 && !zero_asset => Ok(NativeOperation::TopUpReserve {
            asset: AssetId(asset),
        }),
        5 if zero_asset => Ok(NativeOperation::CreateCollection {
            funding_input: argument,
        }),
        6 if argument == 0 && zero_asset => Ok(NativeOperation::MintNft),
        7 if argument == 0 && zero_asset => Ok(NativeOperation::TransferNft),
        8 if argument == 0 && zero_asset => Ok(NativeOperation::BurnNft),
        _ => Err(NativeWireError::Operation),
    }
}

fn primary_openings(
    inputs: &[Option<NativeOpening>],
    outputs: &[Option<NativeOpening>],
) -> Vec<NativeOpening> {
    inputs.iter().chain(outputs).flatten().copied().collect()
}

pub fn operand_roots(operation: NativeOperation) -> Vec<Address> {
    match operation {
        NativeOperation::Financial(op) => op
            .parent()
            .map(|p| p.root)
            .or(op.definition())
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn resolve_dependencies(
    facts: &NativePageFacts,
    inputs: &[Option<NativeOpening>],
    outputs: &[Option<NativeOpening>],
    resolve: &mut impl FnMut(Address) -> Option<NativeOpening>,
) -> Result<Vec<NativeOpening>, NativeWireError> {
    if !matches!(facts.operation, NativeOperation::Financial(_)) {
        return Ok(Vec::new());
    }
    let primary = primary_openings(inputs, outputs);
    let keyed: std::collections::BTreeMap<_, _> =
        primary.iter().map(|o| (o.root().0, *o)).collect();
    let roots: Vec<_> = keyed.keys().copied().map(Address).collect();
    let closure = resolve_native_closure(
        &roots,
        &operand_roots(facts.operation),
        MAX_PAGED_SPEND_INPUTS + MAX_PAGED_SPEND_OUTPUTS + MAX_NATIVE_INTENT_DEPENDENCIES,
        |r| keyed.get(&r.0).copied().or_else(|| resolve(r)),
    )
    .map_err(NativeWireError::Dependencies)?;
    let dependencies: Vec<_> = closure
        .into_iter()
        .filter(|o| !keyed.contains_key(&o.root().0))
        .collect();
    if dependencies.len() > MAX_NATIVE_INTENT_DEPENDENCIES {
        return Err(NativeWireError::Bounds);
    }
    Ok(dependencies)
}

fn mask_bit(mask: &[u8; MASK_BYTES], bit: usize) -> bool {
    mask[bit / 8] & (1 << (bit % 8)) != 0
}

fn set_mask_bit(mask: &mut [u8; MASK_BYTES], bit: usize, value: bool) {
    if value {
        mask[bit / 8] |= 1 << (bit % 8);
    }
}

fn encode_mask(mask: [u8; MASK_BYTES]) -> [TxInput; TX_INPUTS] {
    std::array::from_fn(|i| {
        let bytes = &mask[i * 20..(i + 1) * 20];
        TxInput {
            slot_index: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            amount: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            creation_id: u64::from_le_bytes(bytes[12..].try_into().unwrap()),
        }
    })
}

fn decode_mask(inputs: &[TxInput; TX_INPUTS]) -> [u8; MASK_BYTES] {
    let mut mask = [0; MASK_BYTES];
    for (i, input) in inputs.iter().enumerate() {
        let bytes = &mut mask[i * 20..(i + 1) * 20];
        bytes[..4].copy_from_slice(&input.slot_index.to_le_bytes());
        bytes[4..12].copy_from_slice(&input.amount.to_le_bytes());
        bytes[12..].copy_from_slice(&input.creation_id.to_le_bytes());
    }
    mask
}

fn read_openings(
    src: &mut &[u8],
    count: usize,
) -> Result<Vec<Option<NativeOpening>>, NativeWireError> {
    let mut openings = Vec::with_capacity(count);
    for _ in 0..count {
        let len = usize::from(read_u16(src)?);
        if len > MAX_NATIVE_OPENING_BYTES {
            return Err(NativeWireError::Bounds);
        }
        openings.push(if len == 0 {
            None
        } else {
            Some(NativeOpening::from_bytes(take(src, len)?)?)
        });
    }
    Ok(openings)
}

fn take<'a>(src: &mut &'a [u8], count: usize) -> Result<&'a [u8], NativeWireError> {
    if src.len() < count {
        return Err(NativeWireError::Encoding);
    }
    let (bytes, tail) = src.split_at(count);
    *src = tail;
    Ok(bytes)
}

fn read_u16(src: &mut &[u8]) -> Result<u16, NativeWireError> {
    Ok(u16::from_le_bytes(take(src, 2)?.try_into().unwrap()))
}
