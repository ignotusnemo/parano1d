// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded contract admission syntax and candidate-height checks. These checks
//! do not replace the contract execution enforced by the block proof.

use noid_chain::consensus::wire_limits::MAX_TX_INTENT_BYTES_GLOBAL;
use noid_poseidon2b::primitives::TxBodyHash;
use noid_tx::{
    experimental_object::{CheckedTransition, ObjectIntent, ObjectOpening, INTENT_MAGIC},
    PagedSpendIntent, TxPage,
};

use crate::SubmitError;

/// Decoding establishes syntax only. The pool must bind these fields to the
/// retained bytes and check State, height and authorization before admission.
pub enum DecodedMempoolIntent {
    Paged {
        intent: PagedSpendIntent,
        opening: Option<ObjectOpening>,
    },
    Native(noid_tx::native_assets::wire::NativeIntent),
    Trade(noid_tx::native_assets::trade::wire::TradeOwnerIntent),
}

impl DecodedMempoolIntent {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SubmitError> {
        if bytes.len() > MAX_TX_INTENT_BYTES_GLOBAL {
            return Err(SubmitError::IntentTooLarge {
                actual: bytes.len(),
                max: MAX_TX_INTENT_BYTES_GLOBAL,
            });
        }
        if bytes.starts_with(noid_tx::native_assets::trade::wire::TRADE_OWNER_INTENT_MAGIC) {
            noid_tx::native_assets::trade::wire::TradeOwnerIntent::from_bytes(bytes)
                .map(Self::Trade)
                .map_err(|error| SubmitError::MalformedIntent(error.to_string()))
        } else if bytes.starts_with(noid_tx::native_assets::wire::NATIVE_INTENT_MAGIC) {
            noid_tx::native_assets::wire::NativeIntent::from_bytes(bytes)
                .map(Self::Native)
                .map_err(|error| SubmitError::MalformedIntent(error.to_string()))
        } else if bytes.starts_with(INTENT_MAGIC) {
            let object = ObjectIntent::from_bytes(bytes)
                .map_err(|e| SubmitError::MalformedIntent(e.to_string()))?;
            Ok(Self::Paged {
                intent: object.spend,
                opening: Some(object.opening),
            })
        } else {
            let intent = PagedSpendIntent::from_bytes(bytes)
                .map_err(|e| SubmitError::MalformedIntent(e.to_string()))?;
            Ok(Self::Paged {
                intent,
                opening: None,
            })
        }
    }

    pub fn logical_txid(&self) -> TxBodyHash {
        match self {
            Self::Paged { intent, .. } => intent.logical_txid(),
            Self::Native(intent) => intent.logical_txid().expect("decoded native syntax"),
            Self::Trade(envelope) => envelope
                .intent
                .authorization_id()
                .expect("decoded trade syntax"),
        }
    }
}

pub(crate) fn check_candidate_call(
    opening: &ObjectOpening,
    pages: &[TxPage],
    height: u64,
) -> Result<CheckedTransition, SubmitError> {
    if !noid_chain::consensus::params::v2_active(height) {
        return Err(SubmitError::MalformedIntent(
            "contracts are not active at the candidate height".into(),
        ));
    }
    let [page] = pages else {
        return Err(SubmitError::MalformedIntent(
            "a contract call must contain exactly one page".into(),
        ));
    };
    opening
        .check_call(page, height)
        .map_err(|e| SubmitError::MalformedIntent(e.to_string()))
}

pub(crate) fn eviction_reason(
    entry: &noid_chain::mempool::MempoolEntry,
    candidate_height: Option<u64>,
) -> Option<crate::EvictReason> {
    let opening = entry.contract_opening()?;
    let Some(height) =
        candidate_height.filter(|height| noid_chain::consensus::params::v2_active(*height))
    else {
        return Some(crate::EvictReason::ContractForkInactive);
    };
    match check_candidate_call(&opening, &entry.pages, height) {
        Ok(checked)
            if entry
                .admitted_height
                .checked_add(1)
                .is_some_and(|admitted| checked.authority == opening.authority_at(admitted)) =>
        {
            None
        }
        _ => Some(crate::EvictReason::ContractContextChanged),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::experimental_object::{applications, INTENT_PREFIX_BYTES, MAX_INTENT_BYTES};

    fn object_intent(height: u64) -> ObjectIntent {
        let opening =
            applications::refundable_payment(Address([1; 32]), Address([2; 32]), height + 10, 100);
        let page = opening
            .build_call(
                noid_tx::TxInput {
                    slot_index: 1,
                    amount: 10_000,
                    creation_id: 1,
                },
                2,
                10,
                [3; 32],
                height,
                true,
            )
            .unwrap();
        ObjectIntent {
            opening,
            spend: PagedSpendIntent::new(vec![page], vec![7; 16]).unwrap(),
        }
    }

    #[test]
    fn object_bound_fits_the_unchanged_global_transport_cap() {
        assert_eq!(MAX_INTENT_BYTES, 263_181);
        assert_eq!(MAX_TX_INTENT_BYTES_GLOBAL, 303_495);
        assert!(MAX_INTENT_BYTES < MAX_TX_INTENT_BYTES_GLOBAL);
    }

    #[test]
    fn one_decoder_keeps_the_opening_and_exact_logical_transaction() {
        let object = object_intent(10);
        let encoded = object.to_bytes().unwrap();
        let decoded = DecodedMempoolIntent::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.logical_txid(), object.spend.logical_txid());
        let DecodedMempoolIntent::Paged { intent, opening } = decoded else {
            panic!("paged contract")
        };
        assert_eq!(opening.as_ref(), Some(&object.opening));
        assert_eq!(intent.to_bytes().unwrap(), encoded[INTENT_PREFIX_BYTES..]);
        let ordinary = object.spend.to_bytes().unwrap();
        let decoded = DecodedMempoolIntent::from_bytes(&ordinary).unwrap();
        let DecodedMempoolIntent::Paged { intent, opening } = decoded else {
            panic!("ordinary spend")
        };
        assert!(opening.is_none());
        assert_eq!(intent.to_bytes().unwrap(), ordinary);
        for length in [
            0,
            7,
            INTENT_PREFIX_BYTES - 1,
            INTENT_PREFIX_BYTES,
            encoded.len() - 1,
        ] {
            assert!(DecodedMempoolIntent::from_bytes(&encoded[..length]).is_err());
        }
        let mut extra_page = encoded.clone();
        extra_page[INTENT_PREFIX_BYTES + 1..INTENT_PREFIX_BYTES + 3]
            .copy_from_slice(&2u16.to_le_bytes());
        assert!(DecodedMempoolIntent::from_bytes(&extra_page).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(DecodedMempoolIntent::from_bytes(&trailing).is_err());
    }

    #[test]
    fn calls_follow_candidate_activation_and_recovery_height_in_both_directions() {
        let height = noid_chain::consensus::params::V2_ACTIVATION_HEIGHT.unwrap_or(10);
        let object = object_intent(height);
        if noid_chain::consensus::params::V2_ACTIVATION_HEIGHT.is_none() {
            assert!(check_candidate_call(&object.opening, &object.spend.pages, height).is_err());
            return;
        }
        assert!(check_candidate_call(&object.opening, &object.spend.pages, height - 1).is_err());
        assert!(check_candidate_call(&object.opening, &object.spend.pages, height).is_ok());
        assert!(check_candidate_call(&object.opening, &object.spend.pages, height + 10).is_err());
        assert!(check_candidate_call(&object.opening, &object.spend.pages, height).is_ok());
        assert!(check_candidate_call(&object.opening, &[], height).is_err());
    }
}
