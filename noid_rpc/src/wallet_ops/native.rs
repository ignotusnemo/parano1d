// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Reviewed native operations bound to one local account and canonical parent.

use noid_chain::{consensus::params, BlockHeader};
use noid_poseidon2b::primitives::Address;
use noid_tx::native_assets::{
    nft_market::NftRoundContext,
    trade::TradeIntent,
    transition::{NativeInputClaim, NativeOperation},
    wire::NativeIntent,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletNativeContext {
    pub key_index: u32,
    pub owner: Address,
    pub parent: BlockHeader,
    pub epoch_anchor: [u8; 32],
}

impl WalletNativeContext {
    pub fn candidate_height(&self) -> Result<u64, String> {
        let height = self
            .parent
            .height
            .checked_add(1)
            .ok_or("height exhausted")?;
        if !params::v2_1_active(height) {
            return Err("native operations are not active at the candidate height".into());
        }
        Ok(height)
    }

    pub fn round(&self) -> Result<NftRoundContext, String> {
        NftRoundContext::new(
            self.candidate_height()?,
            noid_chain::block_id(&self.parent),
            self.parent.alloc_counter,
        )
        .map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletNativeIntent {
    Operation(NativeIntent),
    Trade(TradeIntent),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletNativeProofRequest {
    pub context: WalletNativeContext,
    pub intent: WalletNativeIntent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletNativeClaims {
    pub txid: [u8; 32],
    pub inputs: Vec<NativeInputClaim>,
    pub output_slots: Vec<u32>,
}

impl WalletNativeProofRequest {
    pub fn checked_claims(&self) -> Result<WalletNativeClaims, String> {
        let height = self.context.candidate_height()?;
        let chain = noid_chain::state::native_assets::native_chain_id();
        let (txid, inputs, output_slots) = match &self.intent {
            WalletNativeIntent::Operation(intent) => {
                if !intent.authorization_bytes.is_empty() {
                    return Err("native wallet request already carries authorization".into());
                }
                let pages = intent.validate_structure().map_err(|e| e.to_string())?;
                if pages.authority != self.context.owner
                    || pages.epoch_anchor != self.context.epoch_anchor
                    || !pages.operation.enabled()
                    || !pages.operation.requires_owner()
                {
                    return Err(
                        "native operation does not match the reviewed wallet context".into(),
                    );
                }
                let facts = if matches!(pages.operation, NativeOperation::Financial(_)) {
                    intent.checked_financial_owner(chain, self.context.round()?)
                } else {
                    intent.checked(chain, height)
                }
                .map_err(|e| e.to_string())?;
                (
                    facts.pages.logical_txid.0,
                    facts.inputs,
                    facts
                        .outputs
                        .iter()
                        .map(|o| o.output.slot_index)
                        .collect::<Vec<_>>(),
                )
            }
            WalletNativeIntent::Trade(intent) => {
                if intent.policy.owner != self.context.owner {
                    return Err("trade authority does not match the reviewed wallet account".into());
                }
                intent
                    .checked(chain, self.context.epoch_anchor, height)
                    .map_err(|e| e.to_string())?;
                (
                    intent.authorization_id().map_err(|e| e.to_string())?.0,
                    intent.funding.clone(),
                    Vec::new(),
                )
            }
        };
        let mut slots = std::collections::BTreeSet::new();
        if inputs.is_empty() || inputs.iter().any(|i| !slots.insert(i.input.slot_index)) {
            return Err("native wallet inputs must be nonempty and distinct".into());
        }
        let mut slots = std::collections::BTreeSet::new();
        if output_slots.iter().any(|slot| !slots.insert(*slot)) {
            return Err("native wallet output slots must be distinct".into());
        }
        Ok(WalletNativeClaims {
            txid,
            inputs,
            output_slots,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletNativeSubmission {
    pub context: WalletNativeContext,
    pub txid: [u8; 32],
    pub intent_bytes: Vec<u8>,
    pub input_slots: Vec<u32>,
    pub output_slots: Vec<u32>,
}

impl WalletNativeSubmission {
    pub fn checked_claims(&self) -> Result<WalletNativeClaims, String> {
        let intent = if self
            .intent_bytes
            .starts_with(noid_tx::native_assets::wire::NATIVE_INTENT_MAGIC)
        {
            let mut intent =
                NativeIntent::from_bytes(&self.intent_bytes).map_err(|e| e.to_string())?;
            if intent.authorization_bytes.is_empty() {
                return Err("native submission requires authorization".into());
            }
            intent.authorization_bytes.clear();
            WalletNativeIntent::Operation(intent)
        } else {
            let intent = noid_tx::native_assets::trade::wire::TradeOwnerIntent::from_bytes(
                &self.intent_bytes,
            )
            .map_err(|e| e.to_string())?;
            if intent.authorization_bytes.is_empty() {
                return Err("native submission requires authorization".into());
            }
            WalletNativeIntent::Trade(intent.intent)
        };
        let claims = WalletNativeProofRequest {
            context: self.context.clone(),
            intent,
        }
        .checked_claims()?;
        if claims.txid != self.txid
            || claims
                .inputs
                .iter()
                .map(|i| i.input.slot_index)
                .collect::<Vec<_>>()
                != self.input_slots
            || claims.output_slots != self.output_slots
        {
            return Err("native submission footprint changed".into());
        }
        Ok(claims)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletNativeReservation {
    pub lease: u128,
    pub txid: [u8; 32],
    pub owner: Address,
    pub key_index: u32,
    pub parent_height: u64,
    pub input_slots: Vec<u32>,
    pub output_slots: Vec<u32>,
}
