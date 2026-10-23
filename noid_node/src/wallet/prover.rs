// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Transaction proving inside the daemon.
//!
//! This is the ONLY place where the wallet's one-secret `OwnerAuthWitness` is
//! consumed by the authorization pipeline. It never leaves this function: it
//! is moved into the prover and zeroized on drop. Field-limb temporaries are
//! wallet-local proof workspace and are not serialized.
//!
//! # What this produces
//!
//! `WalletAuthorizationBundle` — the wallet's owner-batched auth proof artifact
//! submitted to the local mempool via `submitTxIntent`. The bundle is
//! forwarded from the mempool to the block prover inside the daemon.
//! Secret-bearing Poseidon state remains wallet-local; the bundle carries one
//! self-contained witness-hiding selected authorization capsule.
//!
//! # SpendSecret handling
//!
//! The witness is taken by value and zeroized when this function returns. No
//! reference escapes. No copy is serialized or stored on disk after this
//! function completes.

use noid_gkr::{OwnerAuthWitness, WalletAuthorizationBundle};
use noid_tx::TxPage;

/// Error from transaction proving.
#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    #[error("wallet authorization failed: {0}")]
    Authorization(String),
}

/// Prove wallet authorization for a transaction inside the daemon.
///
/// This produces only the selected witness-hiding authorization bundle. Public
/// transaction arithmetic is checked exactly before proving, and the canonical
/// block prover rebuilds the public AIR from `TxBody` at inclusion time.
#[cfg(test)]
pub fn prove_tx(
    pages: &[TxPage],
    witness: OwnerAuthWitness,
) -> Result<WalletAuthorizationBundle, ProveError> {
    prove_tx_for_version(pages, witness, noid_tx::OwnerAuthorizationVersion::V4)
}

pub fn prove_tx_for_version(
    pages: &[TxPage],
    witness: OwnerAuthWitness,
    version: noid_tx::OwnerAuthorizationVersion,
) -> Result<WalletAuthorizationBundle, ProveError> {
    noid_gkr::wallet_authorization::prove_paged_spend_authorization_for_version(
        pages, witness, version,
    )
    .map_err(|e| ProveError::Authorization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{derive_address, Address, SpendSecret};
    use noid_tx::{
        output_bitmap_bit, TxBody, TxInput, TxOutput, PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT,
        TX_INPUTS, TX_OUTPUTS,
    };

    fn secret_bytes(seed: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed.wrapping_mul(37).wrapping_add(i as u8).wrapping_add(3);
        }
        bytes
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn pages(spend_secret: &SpendSecret, input_count: usize) -> Vec<TxPage> {
        let owner = derive_address(spend_secret);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        let mut total = 0u64;
        for i in 0..input_count {
            inputs[i] = TxInput {
                slot_index: 1_000 + i as u32,
                amount: 10_000 + i as u64,
                creation_id: 100 + i as u64,
            };
            total += inputs[i].amount;
        }
        let fee = 123u64;
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 50_000,
            amount: total - fee,
            owner: Address([0xB1; 32]),
        };
        vec![TxPage::new(TxBody {
            epoch_anchor: [0x52; 32],
            fee,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: ((1u16 << input_count) - 1)
                | output_bitmap_bit(0)
                | PAGED_SPEND_START_BIT
                | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        })
        .unwrap()]
    }

    #[test]
    fn wallet_bundle_does_not_serialize_spend_secret_bytes() {
        let raw_secret = secret_bytes(11);
        let spend_secret = SpendSecret::from_bytes(raw_secret);
        let pages = pages(&spend_secret, 1);

        let bundle =
            prove_tx(&pages, OwnerAuthWitness::new(spend_secret)).expect("prove transaction");
        let bytes = bundle.to_bytes().expect("serialize wallet authorization");

        assert!(
            !contains_subslice(&bytes, &raw_secret),
            "wallet bundle must not contain raw spend_secret bytes"
        );
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only eight-input proof regression")]
    fn eight_input_wallet_bundle_does_not_serialize_spend_secret_bytes() {
        let raw_secret = secret_bytes(21);
        let spend_secret = SpendSecret::from_bytes(raw_secret);
        let pages = pages(&spend_secret, TX_INPUTS);

        let bundle = prove_tx(&pages, OwnerAuthWitness::new(spend_secret))
            .expect("prove eight-input transaction");
        let bytes = bundle.to_bytes().expect("serialize wallet authorization");

        assert!(
            !contains_subslice(&bytes, &raw_secret),
            "eight-input wallet bundle must not contain raw spend_secret bytes"
        );
    }
}
