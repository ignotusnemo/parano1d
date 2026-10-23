// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Transparent transaction layer for Paranoid.
//!
//! Defines the on-wire shape of a transaction — inputs, outputs, body
//! roots, auth tags — and the canonical body hash that binds all of it.
//! Paranoid is a transparent UTXO chain: values and owner addresses are
//! on-chain, spends are authorized by signatureless owner proofs.

pub mod asset_backing;
pub mod authorization_version;
pub mod body_hash;
pub mod claims;
pub mod experimental_object;
pub mod native_assets;
pub mod owner_auth;
pub mod paged_spend;
pub mod public_logic;
pub mod types;
pub mod wire;

pub use authorization_version::OwnerAuthorizationVersion;
pub use body_hash::hash_tx_body;
pub use claims::compute_claims_commitment;
pub use owner_auth::{canonical_owner_auth, CanonicalOwnerAuth, OwnerAuthError};
pub use paged_spend::{
    canonical_paged_spend_auth, hash_paged_spend, paged_spend_authorization_wire_offset,
    validate_paged_spend, CanonicalPagedSpendAuth, PagedSpendError, PagedSpendFacts,
    PagedSpendIntent, TxPage, MAX_PAGED_SPEND_INPUTS, MAX_PAGED_SPEND_INTENT_BYTES,
    MAX_PAGED_SPEND_OUTPUTS, MAX_PAGED_SPEND_PAGES, MAX_TX_AUTHORIZATION_BYTES,
    PAGED_SPEND_CONTRACT_BIT, PAGED_SPEND_END_BIT, PAGED_SPEND_INTENT_FIXED_OVERHEAD,
    PAGED_SPEND_INTENT_MARKER, PAGED_SPEND_MARKER_MASK, PAGED_SPEND_START_BIT,
    PAGED_SPEND_TERMINAL_BIT, PAGED_SPEND_V2_CONTRACT_MASK, PAGED_SPEND_VALIDITY_MASK,
    PAGED_SPEND_VERSION,
};
pub use public_logic::{
    validate_body_semantics_no_hash, validate_public_tx_logic, PublicLogicError, PublicLogicFacts,
};
pub use types::{
    output_bitmap_bit, pack_amount_creation_id, unpack_amount_creation_id, Transaction, TxBody,
    TxInput, TxOutput, TX_ACTIONS, TX_EPOCH_BLOCKS, TX_INPUTS, TX_OUTPUTS, TX_VALIDITY_MASK,
};
pub use wire::{
    WireError, TRANSACTION_WIRE_SIZE, TX_BODY_WIRE_SIZE, TX_INPUT_WIRE_SIZE, TX_OUTPUT_WIRE_SIZE,
};
